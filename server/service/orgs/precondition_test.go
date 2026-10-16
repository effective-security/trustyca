package orgs

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// Test_preconditionFailed covers the public contract of a refusal the
// state of the org causes: HTTP 409 with the message, gRPC
// FailedPrecondition. The pinned porto maps FailedPrecondition alone to
// HTTP 500 and hides the message.
func Test_preconditionFailed(t *testing.T) {
	t.Parallel()

	err := preconditionFailed(context.Background(), "org has %d owners", 1)
	assert.Equal(t, http.StatusConflict, err.HTTPStatus)
	assert.Equal(t, httperror.CodeConflict, err.Code)
	assert.EqualError(t, err, "conflict: org has 1 owners")

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Equal(t, "org has 1 owners", st.Message())

	w := httptest.NewRecorder()
	marshal.WriteJSON(w, httptest.NewRequest(http.MethodPost, "/", nil), err)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.JSONEq(t, `{"code":"conflict","message":"org has 1 owners"}`, w.Body.String())
}

// TestService_RegisterProject_PreconditionContract refuses to register a
// project in a deleted org through the REST handler and through gRPC
func TestService_RegisterProject_PreconditionContract(t *testing.T) {
	t.Parallel()

	deletedOrg := func(t *testing.T) (*Service, context.Context) {
		ctrl := gomock.NewController(t)
		db := mocktrustycadb.NewMockOrgsDb(ctrl)
		// the HTTP handler adds the correlation ID to the request's context
		db.EXPECT().GetOrg(gomock.Any(), uint64(1)).
			Return(&model.Org{ID: xdb.NewID(1), Status: pb.ItemStatus_Inactive}, nil)
		svc := &Service{db: db, authorizer: newFakeAuthorizer(orgGrant(42, pb.Role_Admin))}
		return svc, testCtx("42", "1")
	}

	t.Run("http", func(t *testing.T) {
		t.Parallel()
		svc, ctx := deletedOrg(t)

		r := httptest.NewRequestWithContext(ctx, http.MethodPost, pb.Orgs_RegisterProject_FullMethodName,
			strings.NewReader(`{"Name":"Test"}`))
		w := httptest.NewRecorder()
		svc.OrgsHTTPHandler()(w, r, nil)
		assert.Equal(t, http.StatusConflict, w.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, "conflict", body["code"])
		assert.Equal(t, "org is deleted", body["message"])
	})

	t.Run("grpc", func(t *testing.T) {
		t.Parallel()
		svc, ctx := deletedOrg(t)

		// the server sees the caller's context, as the auth interceptor
		// makes it
		lis := bufconn.Listen(1 << 20)
		srv := grpc.NewServer(grpc.UnaryInterceptor(
			func(_ context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				return handler(ctx, req)
			}))
		pb.RegisterOrgsServer(srv, svc)
		go func() { _ = srv.Serve(lis) }()
		t.Cleanup(srv.Stop)

		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, err = pb.NewOrgsClient(conn).RegisterProject(context.Background(), &pb.RegisterProjectRequest{Name: "Test"})
		st, ok := status.FromError(err)
		require.True(t, ok, "%v", err)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Equal(t, "org is deleted", st.Message())
		// a Go client converting it keeps the message, and reports a 500:
		// this fails once porto maps FailedPrecondition to 409
		converted := httperror.NewFromPb(err)
		assert.Equal(t, "org is deleted", converted.Message)
		assert.Equal(t, http.StatusBadRequest, converted.HTTPStatus, "porto maps FailedPrecondition to 400")
	})
}
