package ca

import (
	"context"
	"net"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/mocks/mockclient"
	"github.com/effective-security/trustyca/privpb"
	privmockpb "github.com/effective-security/trustyca/privpb/mockpb"
	privproxypb "github.com/effective-security/trustyca/privpb/proxypb"
	"github.com/effective-security/trustyca/server/service/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// forwardedContextHeader is the gRPC metadata the caller's context travels
// in to a remote backend
const forwardedContextHeader = "x-trustyca-context"

// userCtx returns the context the WFE builds for a user token of the org;
// an empty org selects none
func userCtx(orgID string) context.Context {
	claims := map[string]any{
		"sub":   "42",
		"email": "user@example.com",
	}
	if orgID != "" {
		claims[authctx.ClaimOrg] = orgID
	}
	uid := identity.NewIdentity("user", "42", orgID, claims, "tok", "Bearer", identity.MethodJWT)
	return authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(uid, "/wfe"))
}

// recordingBackend serves the mock backend over an in-memory gRPC
// connection and records every request it receives with its metadata
type recordingBackend struct {
	mock privmockpb.MockBackendServer

	mu   sync.Mutex
	reqs []proto.Message
	mds  []metadata.MD
}

// last returns the last request and its metadata
func (b *recordingBackend) last() (proto.Message, metadata.MD) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.reqs) == 0 {
		return nil, nil
	}
	return b.reqs[len(b.reqs)-1], b.mds[len(b.mds)-1]
}

// client returns the backend client of the recording server
func (b *recordingBackend) client(t *testing.T) privpb.BackendServer {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			b.mu.Lock()
			b.reqs = append(b.reqs, proto.Clone(req.(proto.Message)))
			b.mds = append(b.mds, md)
			b.mu.Unlock()
			return handler(ctx, req)
		}))
	privpb.RegisterBackendServer(srv, &b.mock)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return privproxypb.NewBackendClient(conn, nil)
}

// methodPairs returns every method of pb.CA with the privpb.Backend method
// of the same name
func methodPairs(t *testing.T) map[string][2]protoreflect.MethodDescriptor {
	t.Helper()
	ca := pb.File_ca_proto.Services().ByName("CA")
	backend := privpb.File_backend_proto.Services().ByName("Backend")
	require.NotNil(t, ca)
	require.NotNil(t, backend)
	pairs := map[string][2]protoreflect.MethodDescriptor{}
	for i := range ca.Methods().Len() {
		m := ca.Methods().Get(i)
		bm := backend.Methods().ByName(m.Name())
		require.NotNil(t, bm, "privpb.Backend has %s", m.Name())
		pairs[string(m.Name())] = [2]protoreflect.MethodDescriptor{m, bm}
	}
	assert.Equal(t, backend.Methods().Len(), ca.Methods().Len(), "every method of privpb.Backend is a method of pb.CA")
	return pairs
}

// populate sets every field of the message to a value that is not the
// default, so that a field the conversion drops shows
func populate(m protoreflect.Message) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		switch {
		case fd.IsMap():
			m.Mutable(fd).Map().Set(protoreflect.ValueOfString("k").MapKey(), protoreflect.ValueOfString("v"))
		case fd.IsList():
			list := m.Mutable(fd).List()
			if fd.Kind() == protoreflect.MessageKind {
				list.Append(protoreflect.ValueOfMessage(list.NewElement().Message()))
			} else {
				list.Append(scalar(fd))
			}
		case fd.Kind() == protoreflect.MessageKind:
			m.Mutable(fd)
		default:
			m.Set(fd, scalar(fd))
		}
	}
}

// scalar returns a value of the field that is not the default
func scalar(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		return protoreflect.ValueOfEnum(1)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(7)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(7)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(7)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(7)
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte("bytes-" + string(fd.Name())))
	default:
		return protoreflect.ValueOfString("value-" + string(fd.Name()))
	}
}

// newMessage returns a new message of the type
func newMessage(t *testing.T, md protoreflect.MessageDescriptor) proto.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
	require.NoError(t, err)
	return mt.New().Interface()
}

// call calls the method of the service with the context and the request
func call(svc *Service, method string, ctx context.Context, req proto.Message) (any, error) {
	out := reflect.ValueOf(svc).MethodByName(method).Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(req)})
	err, _ := reflect.TypeAssert[error](out[1])
	return out[0].Interface(), err
}

// TestRequests_Counterparts checks that the request of every privpb.Backend
// method is the request of the pb.CA method of the same name with OrgID:
// the public request reserves field 1 and has no OrgID, and every other
// field has the name, number, kind and type of its counterpart, which the
// conversion of the CA service relies on. SignOCSP takes the same message,
// since it carries no tenant.
func TestRequests_Counterparts(t *testing.T) {
	t.Parallel()
	for name, pair := range methodPairs(t) {
		in, pin := pair[0].Input(), pair[1].Input()
		assert.Equal(t, pair[0].Output().FullName(), pair[1].Output().FullName(), "%s returns the same response", name)
		if name == "SignOCSP" {
			assert.Equal(t, in.FullName(), pin.FullName(), "SignOCSP takes the public request")
			continue
		}
		assert.Equal(t, protoreflect.Name(in.Name()), pin.Name(), "%s: the copy keeps the name", name)
		assert.Nil(t, in.Fields().ByName(orgIDField), "%s: the public request has no OrgID", name)
		assert.True(t, in.ReservedRanges().Has(1), "%s: the public request reserves field 1", name)
		assert.True(t, in.ReservedNames().Has(orgIDField), "%s: the public request reserves OrgID", name)
		org := pin.Fields().ByName(orgIDField)
		require.NotNil(t, org, "%s: the copy has OrgID", name)
		assert.Equal(t, protoreflect.FieldNumber(1), org.Number(), name)
		assert.Equal(t, protoreflect.StringKind, org.Kind(), name)
		assert.Equal(t, in.Fields().Len()+1, pin.Fields().Len(), "%s: the copy adds OrgID only", name)
		for i := range in.Fields().Len() {
			fd := in.Fields().Get(i)
			pfd := pin.Fields().ByNumber(fd.Number())
			require.NotNil(t, pfd, "%s.%s", name, fd.Name())
			assert.Equal(t, fd.Name(), pfd.Name(), "%s field %d", name, fd.Number())
			assert.Equal(t, fd.Kind(), pfd.Kind(), "%s.%s", name, fd.Name())
			assert.Equal(t, fd.Cardinality(), pfd.Cardinality(), "%s.%s", name, fd.Name())
			assert.Equal(t, fd.IsMap(), pfd.IsMap(), "%s.%s", name, fd.Name())
			assert.Equal(t, fd.JSONName(), pfd.JSONName(), "%s.%s", name, fd.Name())
			switch {
			case fd.IsMap():
				// a map entry is a type of its message: compare its key and value
				assert.Equal(t, fd.MapKey().Kind(), pfd.MapKey().Kind(), "%s.%s key", name, fd.Name())
				assert.Equal(t, fd.MapValue().Kind(), pfd.MapValue().Kind(), "%s.%s value", name, fd.Name())
			case fd.Message() != nil:
				assert.Equal(t, fd.Message().FullName(), pfd.Message().FullName(), "%s.%s", name, fd.Name())
			}
			if fd.Enum() != nil {
				assert.Equal(t, fd.Enum().FullName(), pfd.Enum().FullName(), "%s.%s", name, fd.Name())
			}
		}
	}
}

// TestService_Forward calls every method of the CA service with a request
// whose every field is set, over a remote backend: the backend receives the
// privpb counterpart with the same fields and the org of the caller's
// token, the caller's context travels in the metadata, and the response of
// the backend is returned
func TestService_Forward(t *testing.T) {
	t.Parallel()
	rec := &recordingBackend{}
	svc := New(shared.NewStaticBackendLocator(rec.client(t)))
	ctx := userCtx("1001")

	for name, pair := range methodPairs(t) {
		req := newMessage(t, pair[0].Input())
		populate(req.ProtoReflect())
		res := newMessage(t, pair[0].Output())
		rec.mock.SetResponse(res)

		got, err := call(svc, name, ctx, req)
		require.NoError(t, err, name)
		assert.True(t, proto.Equal(res, got.(proto.Message)), "%s returns the response of the backend", name)

		sent, md := rec.last()
		require.NotNil(t, sent, name)
		assert.Equal(t, pair[1].Input().FullName(), sent.ProtoReflect().Descriptor().FullName(), name)
		assert.NotEmpty(t, md.Get(forwardedContextHeader), "%s: the caller's context travels", name)
		if name == "SignOCSP" {
			assert.True(t, proto.Equal(req, sent), "SignOCSP sends the request as is")
			continue
		}
		pm := sent.ProtoReflect()
		org := pm.Descriptor().Fields().ByName(orgIDField)
		assert.Equal(t, "1001", pm.Get(org).String(), "%s: the org of the token", name)
		pm.Clear(org)
		want, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
		require.NoError(t, err)
		have, err := proto.MarshalOptions{Deterministic: true}.Marshal(sent)
		require.NoError(t, err)
		assert.Equal(t, want, have, "%s: the copy has the fields of the request", name)
	}

	// an error of the backend is returned, a precondition refusal as 409
	rec.mock.Err = status.Error(codes.FailedPrecondition, "issuer is not pending")
	_, err := svc.ActivateIssuer(ctx, &pb.ActivateIssuerRequest{ID: "1"})
	var herr *httperror.Error
	require.True(t, errors.As(err, &herr), err)
	assert.Equal(t, http.StatusConflict, herr.HTTPStatus)
	assert.Equal(t, httperror.CodeConflict, herr.Code)
	assert.Equal(t, "issuer is not pending", herr.Message)
	rec.mock.Err = status.Error(codes.NotFound, "issuer not found")
	_, err = svc.GetIssuer(ctx, &pb.GetIssuerRequest{ID: "1"})
	assert.EqualError(t, err, "not_found: issuer not found")
}

// localBackend is the backend of the process: it records the requests it
// is called with, nil included
type localBackend struct {
	privpb.UnimplementedBackendServer
	issuerReqs []*privpb.GetIssuerRequest
}

func (b *localBackend) GetIssuer(_ context.Context, req *privpb.GetIssuerRequest) (*pb.Issuer, error) {
	b.issuerReqs = append(b.issuerReqs, req)
	return &pb.Issuer{ID: "5"}, nil
}

// TestService_Forward_Org covers the org of the forwarded request: always
// the org of the token, never one the caller encodes in the reserved field
// 1 of the public request, and empty without one; a nil request reaches the
// backend as nil, which refuses it
func TestService_Forward_Org(t *testing.T) {
	t.Parallel()
	be := &localBackend{}
	svc := New(shared.NewStaticBackendLocator(be))

	// a caller that encodes an org in field 1
	smuggled := &pb.GetIssuerRequest{ID: "5"}
	unknown := protowire.AppendTag(nil, 1, protowire.BytesType)
	unknown = protowire.AppendString(unknown, "2002")
	smuggled.ProtoReflect().SetUnknown(unknown)
	res, err := svc.GetIssuer(userCtx("1001"), smuggled)
	require.NoError(t, err)
	assert.Equal(t, "5", res.ID)
	require.Len(t, be.issuerReqs, 1)
	assert.Equal(t, "1001", be.issuerReqs[0].OrgID)
	assert.Equal(t, "5", be.issuerReqs[0].ID)
	assert.Empty(t, be.issuerReqs[0].ProtoReflect().GetUnknown(), "unknown fields are not forwarded")

	_, err = svc.GetIssuer(userCtx(""), smuggled)
	require.NoError(t, err)
	require.Len(t, be.issuerReqs, 2)
	assert.Empty(t, be.issuerReqs[1].OrgID, "a token without an org forwards none")

	_, err = svc.GetIssuer(userCtx("1001"), nil)
	require.NoError(t, err)
	require.Len(t, be.issuerReqs, 3)
	assert.Nil(t, be.issuerReqs[2])
}

// TestService_NoBackend covers a service without a backend, and one whose
// backend cannot be reached: every method is Unavailable
func TestService_NoBackend(t *testing.T) {
	t.Parallel()
	ctx := userCtx("1001")
	svc := New(nil)
	_, err := svc.GetIssuer(ctx, &pb.GetIssuerRequest{ID: "1"})
	assert.EqualError(t, err, "unavailable: CA is not configured")
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: []byte("der")})
	assert.EqualError(t, err, "unavailable: CA is not configured")

	ctrl := gomock.NewController(t)
	factory := mockclient.NewMockFactory(ctrl)
	factory.EXPECT().BackendClient(gomock.Any(), gomock.Any()).Return(nil, nil, errors.New("backend down")).Times(2)
	svc = New(shared.NewBackendLocator(nil, factory, "ca", "backend"))
	_, err = svc.ListProfiles(ctx, &pb.ListProfilesRequest{})
	assert.EqualError(t, err, "unavailable: CA is not available")
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: []byte("der")})
	assert.EqualError(t, err, "unavailable: CA is not available")
	svc.Close()
}

// TestForwardedError covers the errors of a remote backend: a precondition
// refusal is HTTP 409 conflict again, every other error is kept
func TestForwardedError(t *testing.T) {
	t.Parallel()
	assert.NoError(t, forwardedError(nil))

	plain := errors.New("plain")
	assert.Same(t, plain, forwardedError(plain))

	// a refusal as the gRPC client of a remote backend returns it
	remote := httperror.NewFromPb(status.Error(codes.FailedPrecondition, "issuer is not pending"))
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
