package ca

import (
	"net/http"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/server/service/internal/caapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestForwardedError covers the errors of a remote backend: a precondition
// refusal is HTTP 409 conflict again, every other error is kept
func TestForwardedError(t *testing.T) {
	t.Parallel()
	assert.NoError(t, forwardedError(nil))

	plain := errors.New("plain")
	assert.Same(t, plain, forwardedError(plain))

	// a refusal as the gRPC client of a remote backend returns it
	remote := httperror.NewFromPb(caapi.PreconditionFailed(t.Context(), "issuer is not pending").GRPCStatus().Err())
	require.Equal(t, codes.FailedPrecondition, remote.RPCStatus)
	err := forwardedError(remote)
	var e *httperror.Error
	require.True(t, errors.As(err, &e))
	assert.Equal(t, http.StatusConflict, e.HTTPStatus)
	assert.Equal(t, httperror.CodeConflict, e.Code)
	assert.Equal(t, codes.FailedPrecondition, e.RPCStatus)
	assert.Equal(t, "issuer is not pending", e.Message)

	notFound := httperror.NewFromPb(status.Error(codes.NotFound, "issuer not found"))
	err = forwardedError(notFound)
	require.True(t, errors.As(err, &e))
	assert.Equal(t, http.StatusNotFound, e.HTTPStatus)
	assert.Equal(t, httperror.CodeNotFound, e.Code)
}

// TestService_ProfileWithoutBackend covers a CA service whose process runs
// no backend: it manages the profiles in the DB, and the issuer registry of
// a remote backend keeps a resolution it cached until its TTL
func TestService_ProfileWithoutBackend(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc, _ := tca.noCA()
	ctx := testCtx("42", "1")

	// the remote backend resolved the profile before the change
	_, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testProfile})
	require.NoError(t, err)

	storeProfile(tca, nil)
	res, err := svc.RegisterProfile(ctx, &pb.RegisterProfileRequest{
		Profile: peerProfileDef("server", testIssuerLabel, "24h"),
	})
	require.NoError(t, err)
	assert.Equal(t, "server", res.Label)

	tca.cadb.EXPECT().DeleteProfile(gomock.Any(), uint64(1), tca.peer.ID.UInt64()).DoAndReturn(tca.rows.deleteProfile)
	_, err = svc.DeleteProfile(ctx, &pb.DeleteProfileRequest{ID: tca.peer.ID.String()})
	require.NoError(t, err)
	_, err = tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testProfile})
	assert.NoError(t, err, "the remote registry learns of the deletion after its TTL")
}
