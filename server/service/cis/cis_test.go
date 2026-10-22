package cis_test

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/server/service/cis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestFactory(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() {
		cis.Factory(nil)
	})
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cadb := mocktrustycadb.NewMockCaReadonlyDb(ctrl)
	_, err := cis.New(nil, cadb, nil, nil)
	assert.EqualError(t, err, "cis.New: invalid parameter")
	_, err = cis.New(&config.Configuration{}, nil, nil, nil)
	assert.EqualError(t, err, "cis.New: invalid parameter")
	_, err = cis.New(&config.Configuration{CIS: config.CIS{OcspCacheSize: -1}}, cadb, nil, nil)
	assert.EqualError(t, err, "unable to create the OCSP cache: must provide a positive size")
	svc, err := cis.New(&config.Configuration{}, cadb, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, cis.ServiceName, svc.Name())
	assert.True(t, svc.IsReady())
	svc.Close()
}

func TestService_GetRoots(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctx := context.Background()

	_, err := e.svc.GetRoots(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = e.svc.GetRoots(ctx, &pb.ListRootsRequest{OrgID: "nope"})
	assert.EqualError(t, err, "bad_request: invalid org ID")
	_, err = e.svc.GetRoots(ctx, &pb.ListRootsRequest{Cursor: "!!"})
	assert.EqualError(t, err, "bad_request: invalid cursor")

	// the platform anchors without an org, the anchors of the org with one
	res, err := e.svc.GetRoots(ctx, &pb.ListRootsRequest{})
	require.NoError(t, err)
	require.Len(t, res.Roots, 1)
	assert.Equal(t, "", res.Roots[0].OrgID)
	assert.Equal(t, "CN=CIS Test Root,O=trustyca tests", res.Roots[0].Subject)
	assert.Equal(t, pb.Trust_Public, res.Roots[0].Trust)
	assert.NotEmpty(t, res.Roots[0].Pem)
	assert.Nil(t, res.NextPage)
	res, err = e.svc.GetRoots(ctx, &pb.ListRootsRequest{OrgID: "1"})
	require.NoError(t, err)
	require.Len(t, res.Roots, 1)
	assert.Equal(t, "1", res.Roots[0].OrgID)
	assert.Equal(t, "CN=Org Root,O=trustyca tests", res.Roots[0].Subject)
	res, err = e.svc.GetRoots(ctx, &pb.ListRootsRequest{OrgID: "2"})
	require.NoError(t, err)
	assert.Empty(t, res.Roots, "an unknown org has no anchors")

	e.store.setFail(errors.New("db down"))
	_, err = e.svc.GetRoots(ctx, &pb.ListRootsRequest{})
	assert.EqualError(t, err, "unexpected: failed to list roots")
}

func TestService_GetIssuer(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctx := context.Background()

	_, err := e.svc.GetIssuer(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = e.svc.GetIssuer(ctx, &pb.GetIssuerInfoRequest{})
	assert.EqualError(t, err, "bad_request: missing IKID")
	_, err = e.svc.GetIssuer(ctx, &pb.GetIssuerInfoRequest{IKID: "nope"})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = e.svc.GetIssuer(ctx, &pb.GetIssuerInfoRequest{IKID: pendingSKID})
	assert.EqualError(t, err, "not_found: issuer not found", "a Pending issuer has no certificate")
	_, err = e.svc.GetIssuer(ctx, &pb.GetIssuerInfoRequest{IKID: "broken-config"})
	assert.EqualError(t, err, "unexpected: unable to read issuer")

	res, err := e.svc.GetIssuer(ctx, &pb.GetIssuerInfoRequest{IKID: e.issuer.Skid})
	require.NoError(t, err)
	assert.Equal(t, testIssuerLabel, res.Label)
	assert.Equal(t, pb.AuthorityType_Issuing, res.Type)
	assert.Equal(t, pb.IssuerStatus_Active, res.Status)
	assert.Equal(t, e.issuer.Skid, res.SKID)
	assert.Equal(t, e.issuer.Subject, res.Subject)
	assert.Equal(t, e.issuer.NotBefore.String(), res.NotBefore)
	assert.Equal(t, e.issuer.NotAfter.String(), res.NotAfter)
	assert.Equal(t, e.issuer.Pem, res.Certificate)
	assert.Equal(t, e.issuer.ChainPem, res.Intermediates)
	assert.Equal(t, e.issuer.RootPem, res.Root)
	// both placeholders are replaced with the key identifier
	assert.Equal(t, "http://cis.test/v1/cert/"+e.issuer.Skid, res.AiaURL)
	assert.Equal(t, "http://cis.test/v1/crl/"+e.issuer.Skid, res.CrlURL)
	assert.Equal(t, "http://cis.test/v1/ocspi/"+e.issuer.Skid, res.OcspURL)

	e.store.setFail(errors.New("db down"))
	_, err = e.svc.GetIssuer(ctx, &pb.GetIssuerInfoRequest{IKID: e.issuer.Skid})
	assert.EqualError(t, err, "unexpected: unable to find issuer")
}

func TestService_GetCertificate(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctx := context.Background()

	_, err := e.svc.GetCertificate(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{})
	assert.EqualError(t, err, "bad_request: certificate ID, SKID, SHA-256 or issuer serial is required")
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{ID: "nope"})
	assert.EqualError(t, err, "bad_request: invalid certificate ID")
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{IssuerSerial: &pb.IssuerSerial{IKID: e.leaf.Ikid}})
	assert.EqualError(t, err, "bad_request: issuer key ID and serial number are required")
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{ID: "1"})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{SKID: "nope"})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{Sha256: "nope"})
	assert.EqualError(t, err, "not_found: certificate not found")

	// every selector finds the certificate; the view has no tenancy and no
	// client-owned fields
	for name, req := range map[string]*pb.GetCertificateInfoRequest{
		"id":     {ID: e.leaf.ID.String()},
		"serial": {IssuerSerial: &pb.IssuerSerial{IKID: e.leaf.Ikid, SerialNumber: e.leaf.SerialNumber}},
		"sha256": {Sha256: e.leaf.Sha256},
		"skid":   {SKID: e.leaf.Skid},
	} {
		res, err := e.svc.GetCertificate(ctx, req)
		require.NoError(t, err, name)
		crt := res.Certificate
		assert.Equal(t, e.leaf.ID.String(), crt.ID, name)
		assert.Equal(t, e.leaf.Skid, crt.SKID)
		assert.Equal(t, e.leaf.Ikid, crt.IKID)
		assert.Equal(t, e.leaf.SerialNumber, crt.SerialNumber)
		assert.Equal(t, e.leaf.Subject, crt.Subject)
		assert.Equal(t, e.leaf.Issuer, crt.Issuer)
		assert.Equal(t, e.leaf.Sha256, crt.Sha256)
		assert.Equal(t, e.leaf.Pem, crt.Pem)
		assert.Equal(t, e.leaf.IssuersPem, crt.IssuersPem)
		assert.Equal(t, []string(e.leaf.Locations), crt.Locations)
		assert.Equal(t, pb.CertificateStatus_Active, crt.Status)
		assert.Equal(t, e.leaf.NotAfter.String(), crt.NotAfter)
		assert.Empty(t, crt.OrgID)
		assert.Empty(t, crt.ProjectID)
		assert.Empty(t, crt.Profile)
		assert.Empty(t, crt.Label)
		assert.Nil(t, crt.Metadata)
	}
	// the selectors take the precedence of the CA: the ID wins over the
	// others, which are ignored
	res, err := e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{ID: e.revoked.ID.String(), SKID: e.leaf.Skid})
	require.NoError(t, err)
	assert.Equal(t, e.revoked.ID.String(), res.Certificate.ID)
	assert.Equal(t, pb.CertificateStatus_Revoked, res.Certificate.Status)
	// the lookup by SKID covers every org
	require.NotNil(t, e.store.lastList)
	assert.True(t, e.store.lastList.AllOrgs)
	assert.Equal(t, e.leaf.Skid, e.store.lastList.SKID)
	assert.EqualValues(t, 1, e.store.lastList.Limit)

	e.store.setFail(errors.New("db down"))
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{ID: e.leaf.ID.String()})
	assert.EqualError(t, err, "unexpected: unable to find certificate")
	_, err = e.svc.GetCertificate(ctx, &pb.GetCertificateInfoRequest{SKID: e.leaf.Skid})
	assert.EqualError(t, err, "unexpected: unable to find certificate")
}

func TestService_GetCertificateStatus(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctx := context.Background()

	_, err := e.svc.GetCertificateStatus(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = e.svc.GetCertificateStatus(ctx, &pb.GetCertificateInfoRequest{})
	assert.EqualError(t, err, "bad_request: certificate ID, SKID, SHA-256 or issuer serial is required")
	_, err = e.svc.GetCertificateStatus(ctx, &pb.GetCertificateInfoRequest{ID: "1"})
	assert.EqualError(t, err, "not_found: certificate not found")

	res, err := e.svc.GetCertificateStatus(ctx, &pb.GetCertificateInfoRequest{ID: e.leaf.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, &pb.CertificateStatusResponse{
		IKID:         e.leaf.Ikid,
		SerialNumber: e.leaf.SerialNumber,
		Status:       pb.CertificateStatus_Active,
		NotAfter:     e.leaf.NotAfter.String(),
	}, res)

	// an Active row whose validity ended is Expired before the task marks it
	res, err = e.svc.GetCertificateStatus(ctx, &pb.GetCertificateInfoRequest{Sha256: e.expired.Sha256})
	require.NoError(t, err)
	assert.Equal(t, pb.CertificateStatus_Expired, res.Status)
	assert.Empty(t, res.RevokedAt)
	assert.Equal(t, pb.ReasonCode_Unspecified, res.Reason)

	// a revoked one carries its revocation
	res, err = e.svc.GetCertificateStatus(ctx, &pb.GetCertificateInfoRequest{IssuerSerial: &pb.IssuerSerial{IKID: e.revoked.Ikid, SerialNumber: e.revoked.SerialNumber}})
	require.NoError(t, err)
	assert.Equal(t, &pb.CertificateStatusResponse{
		IKID:         e.revoked.Ikid,
		SerialNumber: e.revoked.SerialNumber,
		Status:       pb.CertificateStatus_Revoked,
		NotAfter:     e.revoked.NotAfter.String(),
		RevokedAt:    e.revRow.RevokedAt.String(),
		Reason:       pb.ReasonCode_KeyCompromise,
	}, res)

	// a Revoked row without its revocation is a defect of the data
	e.store.mu.Lock()
	delete(e.store.revoked, e.revoked.ID.UInt64())
	e.store.mu.Unlock()
	_, err = e.svc.GetCertificateStatus(ctx, &pb.GetCertificateInfoRequest{ID: e.revoked.ID.String()})
	assert.EqualError(t, err, "unexpected: revocation record is missing")
	e.store.mu.Lock()
	e.store.revoked[e.revoked.ID.UInt64()] = e.revRow
	e.store.mu.Unlock()

	e.store.setFail(errors.New("db down"))
	_, err = e.svc.GetCertificateStatus(ctx, &pb.GetCertificateInfoRequest{ID: e.revoked.ID.String()})
	assert.EqualError(t, err, "unexpected: unable to find certificate")
}

func TestService_GetCRL(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctx := context.Background()

	_, err := e.svc.GetCRL(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = e.svc.GetCRL(ctx, &pb.GetCrlRequest{})
	assert.EqualError(t, err, "bad_request: missing IKID")
	_, err = e.svc.GetCRL(ctx, &pb.GetCrlRequest{IKID: "nope"})
	assert.EqualError(t, err, "not_found: CRL not found")

	// the org of the CRL is not part of the view; an OrgID in the request
	// is ignored, since the CRL is the issuer's
	res, err := e.svc.GetCRL(ctx, &pb.GetCrlRequest{IKID: e.crl.Ikid, OrgID: "2"})
	require.NoError(t, err)
	require.NotNil(t, res.Crl)
	assert.Equal(t, e.crl.ID.String(), res.Crl.ID)
	assert.Empty(t, res.Crl.OrgID)
	assert.Equal(t, e.issuer.ID.String(), res.Crl.IssuerID)
	assert.Equal(t, e.crl.Ikid, res.Crl.IKID)
	assert.Equal(t, "3", res.Crl.Number)
	assert.Equal(t, e.crl.ThisUpdate.String(), res.Crl.ThisUpdate)
	assert.Equal(t, e.crl.NextUpdate.String(), res.Crl.NextUpdate)
	assert.Equal(t, e.crl.Issuer, res.Crl.Issuer)
	assert.Equal(t, e.crl.Pem, res.Crl.Pem)
	assert.Equal(t, []string{"s3://bucket/crl"}, res.Crl.Locations)

	e.store.setFail(errors.New("db down"))
	_, err = e.svc.GetCRL(ctx, &pb.GetCrlRequest{IKID: e.crl.Ikid})
	assert.EqualError(t, err, "unexpected: unable to find CRL")
}
