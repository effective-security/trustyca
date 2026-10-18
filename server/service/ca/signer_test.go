package ca

import (
	"context"
	"crypto"
	"database/sql"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ocsp"
)

func notFoundErr(table string, id any) error {
	return xdb.CheckNotFoundError(sql.ErrNoRows, table, id)
}

func TestService_SignCertificate(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cadb := mocktrustycadb.NewMockCaDb(ctrl)
	orgsdb := mocktrustycadb.NewMockOrgsReadonlyDb(ctrl)
	tca := newTestAuthority(t)
	svc := &Service{db: cadb, orgs: orgsdb, authorizer: newFakeAuthorizer(), ca: tca.authority}
	ctx := testCtx("42", "1")
	csrDER, csrPEM := newCSR(t, "peer.example.com")

	// validation
	_, err := svc.SignCertificate(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Profile: testProfile})
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM})
	assert.EqualError(t, err, "bad_request: missing profile")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, Label: string(make([]byte, 261))})
	assert.EqualError(t, err, "bad_request: invalid label length")
	noCA := &Service{db: cadb, orgs: orgsdb, authorizer: newFakeAuthorizer()}
	_, err = noCA.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "unavailable: CA is not configured")

	// tenancy of a user token
	_, err = svc.SignCertificate(testCtx("42", ""), &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{OrgID: "2", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "forbidden: org mismatch")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{ProjectID: "bad", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: invalid project ID")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{ProjectID: "301", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: project not found", "project of another org")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{ProjectID: "203", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: project not found", "inactive project")

	// tenancy of a service caller: the org is explicit and verified
	ra := serviceCtx("trustyca-ra")
	_, err = svc.SignCertificate(ra, &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: org ID is required")
	_, err = svc.SignCertificate(ra, &pb.SignCertificateRequest{OrgID: "bad", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: invalid org ID")
	orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(9)).Return(nil, notFoundErr("org", 9))
	_, err = svc.SignCertificate(ra, &pb.SignCertificateRequest{OrgID: "9", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: org not found")
	orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(3)).Return(inactiveOrg, nil)
	_, err = svc.SignCertificate(ra, &pb.SignCertificateRequest{OrgID: "3", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "conflict: org is deleted")
	orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(nil, errors.New("db down"))
	_, err = svc.SignCertificate(ra, &pb.SignCertificateRequest{OrgID: "1", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "unexpected: unable to find org")

	// issuer resolution
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{IssuerLabel: "nope", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: issuer not found: nope")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM, Profile: "nope"})
	assert.EqualError(t, err, "not_found: issuer not found for profile: nope")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{IssuerLabel: testIssuerLabel, Request: csrPEM, Profile: "nope"})
	assert.EqualError(t, err, `bad_request: issuer "L2_CA" does not support the profile: nope`)

	// request shape
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{RequestFormat: pb.EncodingFormat_PKCS7, Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: unsupported request format: PKCS7")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, NotAfter: "tomorrow"})
	assert.EqualError(t, err, "bad_request: invalid NotAfter: RFC3339 time expected")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, NotBefore: "yesterday"})
	assert.EqualError(t, err, "bad_request: invalid NotBefore: RFC3339 time expected")
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, Extensions: []*pb.X509Extension{{ID: "x"}}})
	assert.EqualError(t, err, "bad_request: invalid extension OID: x")

	// signing errors the request causes are the client's
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: []byte("not a csr"), Profile: testProfile})
	assert.ErrorContains(t, err, "bad_request: failed to sign certificate: ")
	farFuture := time.Now().AddDate(10, 0, 0).UTC().Format(time.RFC3339)
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, NotAfter: farFuture})
	assert.ErrorContains(t, err, "bad_request: failed to sign certificate: ")
	assert.ErrorContains(t, err, "exceeds profile expiry")

	// signed and registered with the issue event in one call
	cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.Certificate, evt *model.Event) (*model.Certificate, error) {
			assert.Equal(t, uint64(1), m.OrgID.UInt64())
			assert.Equal(t, uint64(201), m.ProjectID.UInt64())
			assert.Equal(t, testProfile, m.Profile)
			assert.Equal(t, "edge-1", m.Label)
			assert.Equal(t, xdb.Metadata{"requester": "ci"}, m.Metadata)
			assert.NotEmpty(t, m.Skid)
			assert.Equal(t, tca.issuer.SubjectKID(), m.Ikid)
			assert.Equal(t, tca.issuer.PEM(), m.IssuersPem)
			assert.Contains(t, m.Subject, "CN=peer.example.com")
			assert.Equal(t, certutil.GetSubjectKeyID(tca.ca.Cert), m.Ikid)

			require.NotNil(t, evt)
			assert.Equal(t, pb.EventType_CertificateIssued, evt.Type)
			assert.Equal(t, uint64(1), evt.OrgID.UInt64())
			assert.Equal(t, uint64(201), evt.ProjectID.UInt64())
			assert.True(t, evt.ReferenceID.IsZero(), "the DB references the certificate")
			assert.Equal(t, "Certificate issued", evt.Title)
			assert.Equal(t, ServiceName, evt.Source.String())
			assert.Equal(t, testCallerEmail, evt.Email.String())
			assert.Contains(t, evt.Description.String(), `issued by "L2_CA" with profile "peer"`)

			res := *m
			res.ID = xdb.NewID(777)
			res.Status = pb.CertificateStatus_Active
			return &res, nil
		})
	res, err := svc.SignCertificate(ctx, &pb.SignCertificateRequest{
		OrgID:     "1",
		ProjectID: "201",
		Profile:   testProfile,
		Request:   csrPEM,
		SAN:       []string{"peer.example.com"},
		Label:     "edge-1",
		Metadata:  map[string]string{"requester": "ci"},
	})
	require.NoError(t, err)
	assert.Equal(t, "777", res.Certificate.ID)
	assert.Equal(t, "1", res.Certificate.OrgID)
	assert.Equal(t, "201", res.Certificate.ProjectID)
	assert.Equal(t, testProfile, res.Certificate.Profile)
	assert.Equal(t, pb.CertificateStatus_Active, res.Certificate.Status)
	crt, err := certutil.ParseFromPEM([]byte(res.Certificate.Pem))
	require.NoError(t, err)
	assert.Equal(t, []string{"peer.example.com"}, crt.DNSNames)
	assert.Equal(t, tca.ca.Cert.Subject.String(), crt.Issuer.String())
	assert.Equal(t, tca.issuer.PEM(), res.Certificate.IssuersPem)

	// a DER request from the RA for an explicit, active org; no caller email
	orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.Certificate, evt *model.Event) (*model.Certificate, error) {
			assert.Equal(t, uint64(1), m.OrgID.UInt64())
			assert.True(t, m.ProjectID.IsZero(), "org scope")
			assert.Empty(t, evt.Email.String())
			res := *m
			res.ID = xdb.NewID(778)
			return &res, nil
		})
	res, err = svc.SignCertificate(ra, &pb.SignCertificateRequest{
		OrgID:         "1",
		Profile:       testProfile,
		RequestFormat: pb.EncodingFormat_DER,
		Request:       csrDER,
		SAN:           []string{"peer.example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "778", res.Certificate.ID)
	assert.Empty(t, res.Certificate.ProjectID)

	// registration failures
	cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, errors.New(`pq: duplicate key value violates unique constraint "unique_certificate_sha256"`))
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Profile: testProfile, Request: csrPEM})
	assert.EqualError(t, err, "conflict: certificate is already registered")
	cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.SignCertificate(ctx, &pb.SignCertificateRequest{Profile: testProfile, Request: csrPEM})
	assert.EqualError(t, err, "unexpected: failed to register certificate")
}

func TestService_SignOCSP(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cadb := mocktrustycadb.NewMockCaDb(ctrl)
	tca := newTestAuthority(t)
	svc := &Service{db: cadb, authorizer: newFakeAuthorizer(), ca: tca.authority}
	ctx := serviceCtx("trustyca-cis")

	now := time.Now()
	leaf := tca.ca.Issue(t, "ocsp.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	der, err := ocsp.CreateRequest(leaf, tca.ca.Cert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	require.NoError(t, err)
	ikid := tca.issuer.SubjectKID()
	serial := leaf.SerialNumber.String()
	certID := xdb.NewID(5)

	_, err = svc.SignOCSP(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: []byte("junk")})
	assert.EqualError(t, err, "bad_request: invalid request")
	noCA := &Service{db: cadb}
	_, err = noCA.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	assert.EqualError(t, err, "unavailable: CA is not configured")

	// a certificate of an issuer the CA does not know
	otherLeaf := tca.root.Issue(t, "other.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	otherDer, err := ocsp.CreateRequest(otherLeaf, tca.root.Cert, nil)
	require.NoError(t, err)
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: otherDer})
	assert.EqualError(t, err, "not_found: issuer not found")

	// good
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(&model.Certificate{ID: certID, Status: pb.CertificateStatus_Active}, nil)
	res, err := svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	require.NoError(t, err)
	resp, err := ocsp.ParseResponseForCert(res.Der, leaf, tca.ca.Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, resp.Status)
	assert.Equal(t, 0, leaf.SerialNumber.Cmp(resp.SerialNumber))
	assert.True(t, resp.NextUpdate.After(resp.ThisUpdate))

	// revoked, with the reason and time of the revocation
	revokedAt := now.Add(-30 * time.Minute).Truncate(time.Second).UTC()
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(&model.Certificate{ID: certID, Status: pb.CertificateStatus_Revoked}, nil)
	cadb.EXPECT().GetRevoked(gomock.Any(), &query.GetRevokedRequest{CertificateID: 5}).
		Return(&model.Revoked{
			CertificateID: certID,
			Ikid:          ikid,
			SerialNumber:  serial,
			RevokedAt:     xdb.UTC(revokedAt),
			Reason:        pb.ReasonCode_KeyCompromise,
		}, nil)
	res, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	require.NoError(t, err)
	resp, err = ocsp.ParseResponseForCert(res.Der, leaf, tca.ca.Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, resp.Status)
	assert.Equal(t, ocsp.KeyCompromise, resp.RevocationReason)
	assert.Equal(t, revokedAt.Unix(), resp.RevokedAt.Unix())

	// unknown: the issuer never registered the serial
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(nil, notFoundErr("certificate", ikid+"/"+serial))
	res, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	require.NoError(t, err)
	resp, err = ocsp.ParseResponseForCert(res.Der, leaf, tca.ca.Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Unknown, resp.Status)

	// DB failures
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).Return(nil, errors.New("db down"))
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	assert.EqualError(t, err, "unexpected: unable to get certificate")
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(&model.Certificate{ID: certID, Status: pb.CertificateStatus_Revoked}, nil)
	cadb.EXPECT().GetRevoked(gomock.Any(), &query.GetRevokedRequest{CertificateID: 5}).
		Return(nil, notFoundErr("revoked", 5))
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	assert.EqualError(t, err, "unexpected: revocation record is missing", "a revoked certificate without its revocation is an inconsistency")
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(&model.Certificate{ID: certID, Status: pb.CertificateStatus_Revoked}, nil)
	cadb.EXPECT().GetRevoked(gomock.Any(), &query.GetRevokedRequest{CertificateID: 5}).
		Return(nil, errors.New("db down"))
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	assert.EqualError(t, err, "unexpected: unable to get revoked certificate")
}
