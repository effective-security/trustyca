package backend_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/service/backend"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// the CA service and the AIA of a process find the backend through
// discovery by privpb.BackendServer
var _ privpb.BackendServer = (*backend.Service)(nil)

// TestService_NoRegistry covers the service without an issuer registry:
// every method that uses a key or the registry is Unavailable
func TestService_NoRegistry(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() {
		backend.Factory(nil)
	})
	ctrl := gomock.NewController(t)
	svc := backend.New(mocktrustycadb.NewMockCaDb(ctrl), mocktrustycadb.NewMockOrgsDb(ctrl), nil, nil)
	assert.Equal(t, backend.ServiceName, svc.Name())
	assert.True(t, svc.IsReady())

	ctx := t.Context()
	const unavailable = "unavailable: CA is not configured"
	_, err := svc.RegisterIssuer(ctx, &privpb.RegisterIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.ImportIssuer(ctx, &privpb.ImportIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.ActivateIssuer(ctx, &privpb.ActivateIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: []byte("csr"), Profile: "server"})
	assert.EqualError(t, err, unavailable)
	_, err = svc.PublishCrls(ctx, &privpb.PublishCrlsRequest{})
	assert.EqualError(t, err, unavailable)
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: []byte("der")})
	assert.EqualError(t, err, unavailable)
	svc.Close()
}
