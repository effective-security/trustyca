package backend

import (
	"context"
	"crypto"
	"crypto/x509"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/trustyca/privpb"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ocsp"
)

func TestService_SignCertificate(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tca := newTestCA(t, ctrl)
	cadb, orgsdb := tca.cadb, tca.orgsdb
	svc := tca.service()
	ctx := testCtx("42", "1")
	csrDER, csrPEM := newCSR(t, "peer.example.com")

	// validation
	_, err := svc.SignCertificate(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: testProfile})
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM})
	assert.EqualError(t, err, "bad_request: missing profile")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, Label: string(make([]byte, 261))})
	assert.EqualError(t, err, "bad_request: invalid label length")
	noCA := tca.noCA()
	_, err = noCA.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "unavailable: CA is not configured")

	// tenancy of a user token
	_, err = svc.SignCertificate(testCtx("42", ""), &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{OrgID: "2", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "forbidden: org mismatch")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{ProjectID: "bad", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: invalid project ID")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{ProjectID: "301", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: project not found", "project of another org")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{ProjectID: "203", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: project not found", "inactive project")

	// tenancy of a service caller: the org is explicit and verified
	ra := serviceCtx("trustyca-ra")
	_, err = svc.SignCertificate(ra, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: org ID is required")
	// the operator names the org too, whatever org its DPoP token selected
	_, err = svc.SignCertificate(operatorCtx("1"), &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: org ID is required")
	_, err = svc.SignCertificate(ra, &privpb.SignCertificateRequest{OrgID: "bad", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: invalid org ID")
	orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(9)).Return(nil, notFoundErr("org", 9))
	_, err = svc.SignCertificate(ra, &privpb.SignCertificateRequest{OrgID: "9", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: org not found")
	orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(3)).Return(inactiveOrg, nil)
	_, err = svc.SignCertificate(ra, &privpb.SignCertificateRequest{OrgID: "3", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "conflict: org is deleted")
	orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(nil, errors.New("db down"))
	_, err = svc.SignCertificate(ra, &privpb.SignCertificateRequest{OrgID: "1", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "unexpected: unable to find org")

	// issuer resolution in the scope of the request (DESIGN.md section 6)
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: "nope"})
	assert.EqualError(t, err, "not_found: profile not found: nope")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{IssuerLabel: testIssuerLabel, Request: csrPEM, Profile: "nope"})
	assert.EqualError(t, err, "not_found: profile not found: nope")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{IssuerLabel: "nope", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, `bad_request: issuer "nope" does not serve the profile: peer`)
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("orphan", "NOPE", "1h"))
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: "orphan"})
	assert.EqualError(t, err, "not_found: issuer not found for profile: orphan")
	tca.addProfile(testOrgID(), xdb.ID(0), ocspProfileDef(testOCSPProfile))
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testOCSPProfile})
	assert.EqualError(t, err, "bad_request: issuer label is required for profile: ocsp")
	tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "L3", pb.AuthorityType_Issuing, nil)
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{IssuerLabel: "L3", Request: csrPEM, Profile: testOCSPProfile})
	assert.EqualError(t, err, `bad_request: issuer "L3" does not support the profile: ocsp`)
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{IssuerLabel: "L3", Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, `bad_request: issuer "L3" does not serve the profile: peer`)
	// another org has no access to the profiles and issuers of org 1
	_, err = svc.SignCertificate(testCtx("42", "2"), &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "not_found: profile not found: peer")
	// an archived issuer does not sign
	archived := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "OLD", pb.AuthorityType_Issuing, nil)
	tca.rows.update(archived.ID, func(m *model.Issuer) { m.Status = pb.IssuerStatus_Archived })
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("old-peer", "OLD", "1h"))
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: "old-peer"})
	assert.EqualError(t, err, "conflict: issuer is not active")
	// an issuer that does not load is a server error
	broken := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "BROKEN", pb.AuthorityType_Issuing, nil)
	tca.rows.update(broken.ID, func(m *model.Issuer) { m.KeyProtected = "AAAA" })
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("broken-peer", "BROKEN", "1h"))
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: "broken-peer"})
	assert.EqualError(t, err, "unexpected: unable to load issuer")
	// so is one whose delegated OCSP profile is missing: the profile of the
	// request exists
	tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "NORESP", pb.AuthorityType_Issuing, &pb.IssuerConfig{
		DelegatedOcspProfile: "nope",
	})
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("noresp-peer", "NORESP", "1h"))
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: "noresp-peer"})
	assert.EqualError(t, err, "unexpected: unable to load issuer")

	// request shape
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{RequestFormat: pb.EncodingFormat_PKCS7, Request: csrPEM, Profile: testProfile})
	assert.EqualError(t, err, "bad_request: unsupported request format: PKCS7")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, NotAfter: "tomorrow"})
	assert.EqualError(t, err, "bad_request: invalid NotAfter: RFC3339 time expected")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, NotBefore: "yesterday"})
	assert.EqualError(t, err, "bad_request: invalid NotBefore: RFC3339 time expected")
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, Extensions: []*pb.X509Extension{{ID: "x"}}})
	assert.EqualError(t, err, "bad_request: invalid extension OID: x")

	// signing errors the request causes are the client's
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: []byte("not a csr"), Profile: testProfile})
	assert.ErrorContains(t, err, "bad_request: failed to sign certificate: ")
	farFuture := time.Now().AddDate(10, 0, 0).UTC().Format(time.RFC3339)
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Request: csrPEM, Profile: testProfile, NotAfter: farFuture})
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
			assert.Equal(t, tca.issuer.Skid, m.Ikid)
			assert.Equal(t, strings.TrimSpace(tca.issuer.Pem), m.IssuersPem)
			assert.Contains(t, m.Subject, "CN=peer.example.com")
			assert.Equal(t, certutil.GetSubjectKeyID(tca.issuerCert), m.Ikid)

			require.NotNil(t, evt)
			assert.Equal(t, pb.EventType_CertificateIssued, evt.Type)
			assert.Equal(t, uint64(1), evt.OrgID.UInt64())
			assert.Equal(t, uint64(201), evt.ProjectID.UInt64())
			assert.True(t, evt.ReferenceID.IsZero(), "the DB references the certificate")
			assert.Equal(t, "Certificate issued", evt.Title)
			assert.Equal(t, EventSource, evt.Source.String())
			assert.Equal(t, testCallerEmail, evt.Email.String())
			assert.Contains(t, evt.Description.String(), `issued by "L2_CA" with profile "peer"`)

			res := *m
			res.ID = xdb.NewID(777)
			res.Status = pb.CertificateStatus_Active
			return &res, nil
		})
	res, err := svc.SignCertificate(ctx, &privpb.SignCertificateRequest{
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
	assert.Equal(t, tca.issuerCert.Subject.String(), crt.Issuer.String())
	assert.Equal(t, strings.TrimSpace(tca.issuer.Pem), res.Certificate.IssuersPem)
	assert.Equal(t, 168*time.Hour, crt.NotAfter.Sub(crt.NotBefore).Round(time.Hour), "the org profile")

	// a project profile with the same label shadows the org one
	tca.addProfile(testOrgID(), testProject.ID, peerProfileDef(testProfile, testIssuerLabel, "24h"))
	tca.registry.InvalidateProfile(testOrgID(), testProject.ID, testProfile)
	cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.Certificate, _ *model.Event) (*model.Certificate, error) {
			res := *m
			res.ID = xdb.NewID(779)
			return &res, nil
		})
	res, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{ProjectID: "201", Profile: testProfile, Request: csrPEM})
	require.NoError(t, err)
	crt, err = certutil.ParseFromPEM([]byte(res.Certificate.Pem))
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, crt.NotAfter.Sub(crt.NotBefore).Round(time.Hour), "the project profile")

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
	res, err = svc.SignCertificate(ra, &privpb.SignCertificateRequest{
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
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: testProfile, Request: csrPEM})
	assert.EqualError(t, err, "conflict: certificate is already registered")
	cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: testProfile, Request: csrPEM})
	assert.EqualError(t, err, "unexpected: failed to register certificate")
}

// TestService_SignCertificate_Concurrent signs with one issuer from many
// requests at once: the resolution the registry serves is shared, and its
// rows are only read
func TestService_SignCertificate_Concurrent(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	tca.cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.Certificate, _ *model.Event) (*model.Certificate, error) {
			res := *m
			res.ID = xdb.NewID(900)
			return &res, nil
		}).AnyTimes()
	_, csrPEM := newCSR(t, "many.example.com")
	tca.addProfile(testOrgID(), testProject.ID, peerProfileDef(testProfile, testIssuerLabel, "24h"))

	const workers = 24
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// a request context of its own, as every request has
			ctx := testCtx(orgAdminUser, "1")
			req := &privpb.SignCertificateRequest{Profile: testProfile, Request: csrPEM}
			if i%2 == 0 {
				req.ProjectID = "201"
			}
			res, err := svc.SignCertificate(ctx, req)
			if assert.NoError(t, err) {
				assert.Equal(t, tca.issuer.Skid, res.Certificate.IKID)
			}
			if i%6 == 0 {
				tca.registry.InvalidateIssuer(tca.issuer)
			}
		}()
	}
	wg.Wait()
}

func TestService_SignOCSP(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tca := newTestCA(t, ctrl)
	cadb := tca.cadb
	svc := tca.service()
	ctx := serviceCtx("trustyca-aia")

	now := time.Now()
	leaf := tca.sign(t, "ocsp.example.com")
	der, err := ocsp.CreateRequest(leaf, tca.issuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	require.NoError(t, err)
	ikid := tca.issuer.Skid
	serial := leaf.SerialNumber.String()
	certID := xdb.NewID(5)

	_, err = svc.SignOCSP(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: []byte("junk")})
	assert.EqualError(t, err, "bad_request: invalid request")
	noCA := tca.noCA()
	_, err = noCA.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	assert.EqualError(t, err, "unavailable: CA is not configured")

	// a certificate of an issuer the CA does not know
	other := testutils.NewTestCA(t, "Other Root", nil)
	otherLeaf := other.Issue(t, "other.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	otherDer, err := ocsp.CreateRequest(otherLeaf, other.Cert, nil)
	require.NoError(t, err)
	_, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: otherDer})
	assert.EqualError(t, err, "not_found: issuer not found")

	// good, with the issuer found by its SHA-1 key hash through the SKID
	// index when it is not in memory
	tca.registry.Purge()
	sha1Der, err := ocsp.CreateRequest(leaf, tca.issuerCert, &ocsp.RequestOptions{Hash: crypto.SHA1})
	require.NoError(t, err)
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(&model.Certificate{ID: certID, Status: pb.CertificateStatus_Active}, nil)
	res, err := svc.SignOCSP(ctx, &pb.OCSPRequest{Der: sha1Der})
	require.NoError(t, err)
	resp, err := ocsp.ParseResponseForCert(res.Der, leaf, tca.issuerCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, resp.Status)
	assert.Equal(t, 0, leaf.SerialNumber.Cmp(resp.SerialNumber))
	assert.True(t, resp.NextUpdate.After(resp.ThisUpdate))
	assert.Equal(t, 8*time.Hour, resp.NextUpdate.Sub(resp.ThisUpdate), "the OCSP expiry of the issuer settings")

	// good, with the loaded issuer found by its SHA-256 key hash
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(&model.Certificate{ID: certID, Status: pb.CertificateStatus_Active}, nil)
	res, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	require.NoError(t, err)
	resp, err = ocsp.ParseResponseForCert(res.Der, leaf, tca.issuerCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, resp.Status)

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
	resp, err = ocsp.ParseResponseForCert(res.Der, leaf, tca.issuerCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, resp.Status)
	assert.Equal(t, ocsp.KeyCompromise, resp.RevocationReason)
	assert.Equal(t, revokedAt.Unix(), resp.RevokedAt.Unix())

	// unknown: the issuer never registered the serial
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), ikid, serial).
		Return(nil, notFoundErr("certificate", ikid+"/"+serial))
	res, err = svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	require.NoError(t, err)
	resp, err = ocsp.ParseResponseForCert(res.Der, leaf, tca.issuerCert)
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

// TestService_SignOCSP_Delegated covers an issuer whose settings name a
// delegated OCSP profile: the response is signed by a responder
// certificate the issuer issued, not by the issuer key, and is valid for
// the OCSP expiry of the settings
func TestService_SignOCSP_Delegated(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := serviceCtx("trustyca-aia")
	const delegatingLabel = "DELEGATING"
	const delegatedPeerProfile = "delegated_peer"

	tca.addProfile(testOrgID(), xdb.ID(0), ocspProfileDef(testOCSPProfile))
	delegating := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), delegatingLabel, pb.AuthorityType_Issuing, &pb.IssuerConfig{
		AllowedProfiles:      []string{testOCSPProfile},
		DelegatedOcspProfile: testOCSPProfile,
		OcspExpiry:           "1h",
	})
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef(delegatedPeerProfile, delegatingLabel, "168h"))
	delegatingCert, err := certutil.ParseFromPEM([]byte(delegating.Pem))
	require.NoError(t, err)

	res, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: delegatedPeerProfile})
	require.NoError(t, err)
	_, csrPEM := newCSR(t, "delegated.example.com")
	leaf, _, err := res.Issuer.Sign(csr.SignRequest{Request: string(csrPEM), Profile: res.ProfileName})
	require.NoError(t, err)
	der, err := ocsp.CreateRequest(leaf, delegatingCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	require.NoError(t, err)

	tca.cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), delegating.Skid, leaf.SerialNumber.String()).
		Return(&model.Certificate{ID: xdb.NewID(6), Status: pb.CertificateStatus_Active}, nil)
	ocspRes, err := svc.SignOCSP(ctx, &pb.OCSPRequest{Der: der})
	require.NoError(t, err)
	resp, err := ocsp.ParseResponseForCert(ocspRes.Der, leaf, delegatingCert)
	require.NoError(t, err, "the responder certificate is verified against the issuer")
	assert.Equal(t, ocsp.Good, resp.Status)
	require.NotNil(t, resp.Certificate, "a delegated responder certificate")
	assert.NotEqual(t, delegatingCert.SerialNumber, resp.Certificate.SerialNumber)
	assert.Contains(t, resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
	assert.Equal(t, delegatingCert.RawSubject, resp.Certificate.RawIssuer)
	assert.Equal(t, time.Hour, resp.NextUpdate.Sub(resp.ThisUpdate))
}
