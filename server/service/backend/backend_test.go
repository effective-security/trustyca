package backend_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/service/backend"
	"github.com/effective-security/trustyca/server/service/shared"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// the CA service of a process finds the backend through discovery by
// client.LocalBackend, which the backend must implement
var (
	_ shared.LocalBackend  = (*backend.Service)(nil)
	_ privpb.BackendServer = (*backend.Service)(nil)
)

// TestService_NoRegistry covers the service without an issuer registry:
// every method is Unavailable, and there is no profile to invalidate. The
// methods themselves are tested through the CA service that forwards to
// them (server/service/ca).
func TestService_NoRegistry(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() {
		backend.Factory(nil)
	})
	ctrl := gomock.NewController(t)
	svc := backend.New(mocktrustycadb.NewMockCaDb(ctrl), mocktrustycadb.NewMockOrgsDb(ctrl), nil, nil)
	assert.Equal(t, backend.ServiceName, svc.Name())
	assert.True(t, svc.IsReady())
	svc.InvalidateProfile(xdb.NewID(1), xdb.NewID(0), "server")

	ctx := t.Context()
	const unavailable = "unavailable: CA is not configured"
	_, err := svc.RegisterIssuer(ctx, &pb.RegisterIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.ImportIssuer(ctx, &pb.ImportIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.ActivateIssuer(ctx, &pb.ActivateIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.UpdateIssuer(ctx, &pb.UpdateIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: []byte("csr"), Profile: "server"})
	assert.EqualError(t, err, unavailable)
	_, err = svc.PublishCrls(ctx, &pb.PublishCrlsRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: []byte("der")})
	assert.EqualError(t, err, unavailable)
	svc.Close()
}
