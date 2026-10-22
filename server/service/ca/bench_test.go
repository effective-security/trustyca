package ca

import (
	"context"
	"crypto"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ocsp"
)

// BenchmarkService_SignCertificate measures a warm SignCertificate: the
// tenant checks, the resolution of the issuer from memory, the signature
// and the conversion of the record, with the DB registration mocked
func BenchmarkService_SignCertificate(b *testing.B) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	tca := newTestCA(b, ctrl)
	tca.cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.Certificate, _ *model.Event) (*model.Certificate, error) {
			res := *m
			res.ID = xdb.NewID(1)
			return &res, nil
		}).AnyTimes()
	svc := tca.service()
	ctx := testCtx("42", "1")
	_, csrPEM := newCSR(b, "bench.example.com")
	req := &pb.SignCertificateRequest{
		ProjectID: "201",
		Profile:   testProfile,
		Request:   csrPEM,
		SAN:       []string{"bench.example.com"},
	}
	_, err := svc.SignCertificate(ctx, req)
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, err := svc.SignCertificate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkService_SignOCSP measures a warm SignOCSP for a good certificate
// with the DB lookup mocked
func BenchmarkService_SignOCSP(b *testing.B) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	tca := newTestCA(b, ctrl)
	leaf := tca.sign(b, "ocsp.example.com")
	tca.cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), tca.issuer.Skid, leaf.SerialNumber.String()).
		Return(&model.Certificate{ID: xdb.NewID(5), Status: pb.CertificateStatus_Active}, nil).AnyTimes()
	der, err := ocsp.CreateRequest(leaf, tca.issuerCert, &ocsp.RequestOptions{Hash: crypto.SHA1})
	require.NoError(b, err)
	svc := tca.service()
	ctx := serviceCtx("trustyca-aia")
	req := &pb.OCSPRequest{Der: der}
	_, err = svc.SignOCSP(ctx, req)
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, err := svc.SignOCSP(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
