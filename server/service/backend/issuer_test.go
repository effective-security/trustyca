package backend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/trustyca/privpb"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// storeIssuer is the RegisterIssuer expectation of an issuer that is not a
// root, so without a trust anchor; it stores the row after the assertions
// on it
func storeIssuer(tca *testCA, check func(m *model.Issuer)) {
	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, m *model.Issuer, _ *model.RootCertificate) (*model.Issuer, error) {
			if check != nil {
				check(m)
			}
			return tca.rows.addIssuer(m), nil
		})
}

// storeRootIssuer is the RegisterIssuer expectation of a root issuer, whose
// certificate is a trust anchor of its org registered in the same call; it
// stores the row after the assertions on both
func storeRootIssuer(tca *testCA, check func(m *model.Issuer, anchor *model.RootCertificate)) {
	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Not(gomock.Nil())).DoAndReturn(
		func(_ context.Context, m *model.Issuer, anchor *model.RootCertificate) (*model.Issuer, error) {
			if check != nil {
				check(m, anchor)
			}
			return tca.rows.addIssuer(m), nil
		})
}

// storeCertificate is the RegisterCertificate expectation of a signing
func storeCertificate(tca *testCA) {
	tca.cadb.EXPECT().RegisterCertificate(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.Certificate, _ *model.Event) (*model.Certificate, error) {
			res := *m
			res.ID = xdb.NewID(800)
			return &res, nil
		})
}

func TestService_RegisterIssuer(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	valid := func() *privpb.RegisterIssuerRequest {
		return &privpb.RegisterIssuerRequest{
			Label:   "L3",
			Type:    pb.AuthorityType_Issuing,
			Subject: &pb.X509Subject{CommonName: "Tenant CA"},
		}
	}

	// validation
	_, err := svc.RegisterIssuer(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	noCA := tca.noCA()
	_, err = noCA.RegisterIssuer(ctx, valid())
	assert.EqualError(t, err, "unavailable: CA is not configured")
	req := valid()
	req.Label = " "
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing label")
	req.Label = strings.Repeat("x", model.MaxLenForLabel+1)
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid label length")
	req = valid()
	req.Type = pb.AuthorityType_Unknown
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing type")
	req = valid()
	req.Subject = &pb.X509Subject{}
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing subject")
	req = valid()
	req.KeySpec = &pb.KeySpec{Algo: "DSA"}
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: unsupported key algorithm: DSA")
	req = valid()
	req.Config = &pb.IssuerConfig{CrlExpiry: "x"}
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, `bad_request: invalid config: invalid CrlExpiry: "x" is not a duration`)
	req = valid()
	req.Extensions = []*pb.X509Extension{{ID: "x"}}
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid extension OID: x")
	_, err = svc.RegisterIssuer(testCtx("42", ""), valid())
	assert.EqualError(t, err, "forbidden: org not selected")
	req = valid()
	req.ProjectID = "301"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "not_found: project not found")
	req = valid()
	req.KeyProvider = "AWSKMS"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid key provider: AWSKMS")

	// without a parent, an issuer that is not a root waits for its
	// certificate
	storeIssuer(tca, func(m *model.Issuer) {
		assert.Equal(t, uint64(1), m.OrgID.UInt64())
		assert.Equal(t, uint64(201), m.ProjectID.UInt64())
		assert.Equal(t, "L3", m.Label)
		assert.Equal(t, pb.AuthorityType_Issuing, m.Type)
		assert.Equal(t, pb.IssuerStatus_Pending, m.Status)
		assert.NotEmpty(t, m.CsrPem)
		assert.Empty(t, m.Pem)
		assert.NotEmpty(t, m.Skid, "the key identifies the issuer")
		assert.Equal(t, "CN=Tenant CA", m.Subject)
		assert.Equal(t, core.SoftwareKeyProvider, m.KeyProvider)
		assert.Equal(t, "trustyca/1/201/L3", m.KeyID)
		assert.NotEmpty(t, m.KeyProtected)
	})
	req = valid()
	req.ProjectID = "201"
	pending, err := svc.RegisterIssuer(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Pending, pending.Status)
	assert.NotEmpty(t, pending.Csr)
	assert.Empty(t, pending.Certificate)
	assert.Equal(t, "201", pending.ProjectID)
	assert.Equal(t, core.SoftwareKeyProvider, pending.KeyProvider)
	evt := tca.events.last(pb.EventType_IssuerRegistered)
	require.NotNil(t, evt)
	assert.Equal(t, uint64(1), evt.OrgID.UInt64())
	assert.Equal(t, uint64(201), evt.ProjectID.UInt64())
	assert.Equal(t, pending.ID, evt.ReferenceID.String())
	assert.Equal(t, testCallerEmail, evt.Email.String())
	assert.Contains(t, evt.Description.String(), `issuer "L3" registered with status Pending`)

	// a root signs itself with a CA profile of its scope
	req = valid()
	req.Label = "R2"
	req.Type = pb.AuthorityType_Root
	req.Subject = &pb.X509Subject{CommonName: "Tenant Root"}
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing profile")
	req.Profile = "nope"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "not_found: profile not found: nope")
	req.Profile = testProfile
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, `bad_request: profile "peer" is not a CA profile`)
	tca.addProfile(testOrgID(), xdb.ID(0), rootProfileDef("SELF"))
	req.Profile = "SELF"
	var rootSkid string
	storeRootIssuer(tca, func(m *model.Issuer, anchor *model.RootCertificate) {
		assert.Equal(t, pb.AuthorityType_Root, m.Type)
		assert.Equal(t, pb.IssuerStatus_Active, m.Status)
		assert.Equal(t, m.Pem, m.RootPem)
		assert.Empty(t, m.ChainPem)
		assert.True(t, m.ParentID.IsZero())
		rootSkid = m.Skid
		// the anchor is the certificate of the root in its org
		assert.Equal(t, uint64(1), anchor.OrgID.UInt64())
		assert.Equal(t, pb.Trust_Private, anchor.Trust)
		assert.Equal(t, m.Skid, anchor.Skid)
		assert.Equal(t, m.Sha256, anchor.Sha256)
		assert.Equal(t, m.Pem, anchor.Pem)
	})
	root, err := svc.RegisterIssuer(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, root.Status)
	assert.Equal(t, pb.AuthorityType_Root, root.Type)
	assert.Equal(t, root.Certificate, root.Root)
	assert.Equal(t, rootSkid, root.SKID)

	// the new root signs a subordinate CA with a CA profile bound to it
	tca.addProfile(testOrgID(), xdb.ID(0), caProfileDef("R2CA", "R2"))
	req = valid()
	req.Label = "R2CHILD"
	req.ParentID = root.ID
	req.Profile = "R2CA"
	storeIssuer(tca, func(m *model.Issuer) {
		assert.Equal(t, root.ID, m.ParentID.String())
		assert.Equal(t, rootSkid, m.Ikid)
		assert.Equal(t, root.Certificate, m.RootPem)
		assert.Empty(t, m.ChainPem)
	})
	child, err := svc.RegisterIssuer(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, root.ID, child.ParentID)

	// a parent of the org signs the issuer with a CA profile bound to it
	req = valid()
	req.Label = "L4"
	req.ParentID = "bad"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing profile")
	req.Profile = testCAProfile
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid parent ID")
	req.ParentID = "9999"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "not_found: parent issuer not found")
	org2Root := tca.newRoot(t, xdb.NewID(2), xdb.ID(0), testRootLabel)
	req.ParentID = org2Root.ID.String()
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "not_found: parent issuer not found", "the parent of another org")
	archived := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "ARCH", pb.AuthorityType_Intermediate, nil)
	tca.rows.update(archived.ID, func(m *model.Issuer) { m.Status = pb.IssuerStatus_Archived })
	req.ParentID = archived.ID.String()
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "conflict: parent issuer is not active")
	req.ParentID = tca.root.ID.String()
	req.Profile = testProfile
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, `bad_request: issuer "ROOT" does not serve the profile: peer`)
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("root-peer", testRootLabel, "1h"))
	req.Profile = "root-peer"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, `bad_request: profile "root-peer" is not a CA profile`)
	req.Profile = testCAProfile
	req.SAN = []string{"ca.example.com"}
	storeIssuer(tca, func(m *model.Issuer) {
		assert.Equal(t, tca.root.ID.UInt64(), m.ParentID.UInt64())
		assert.Equal(t, tca.root.Skid, m.Ikid)
		assert.Equal(t, tca.root.Pem, m.RootPem)
		assert.Empty(t, m.ChainPem)
		assert.Equal(t, pb.AuthorityType_Issuing, m.Type)
		assert.Equal(t, pb.IssuerStatus_Active, m.Status)
		assert.Equal(t, "trustyca/1/0/L4", m.KeyID)
	})
	l4, err := svc.RegisterIssuer(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, l4.Status)
	assert.Equal(t, tca.root.ID.String(), l4.ParentID)
	assert.Empty(t, l4.Intermediates)
	assert.Equal(t, tca.root.Pem, l4.Root)
	l4Cert, err := certutil.ParseFromPEM([]byte(l4.Certificate))
	require.NoError(t, err)
	assert.True(t, l4Cert.IsCA)
	assert.True(t, l4Cert.MaxPathLenZero, "the CA profile constraint")
	assert.Empty(t, l4Cert.DNSNames, "a CA certificate carries no names")

	// an issuing CA has path length zero: it signs no subordinate CA
	tca.addProfile(testOrgID(), xdb.ID(0), caProfileDef("L4CA", "L4"))
	req = valid()
	req.Label = "UNDER_L4"
	req.ParentID = l4.ID
	req.Profile = "L4CA"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, `bad_request: failed to create issuer: the path length of "CN=Tenant CA" disallows a subordinate CA`)

	// the new issuer signs through the service once a profile binds to it
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("l4-peer", "L4", "1h"))
	storeCertificate(tca)
	_, csrPEM := newCSR(t, "leaf.example.com")
	signed, err := svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: "l4-peer", Request: csrPEM})
	require.NoError(t, err)
	assert.Equal(t, l4.SKID, signed.Certificate.IKID)

	// a platform parent signs tenant CAs with the profiles it allows
	tca.addProfile(xdb.ID(0), xdb.ID(0), caProfileDef("PCA", "PROOT"))
	proot := tca.newRoot(t, xdb.ID(0), xdb.ID(0), "PROOT")
	tca.rows.update(proot.ID, func(m *model.Issuer) {
		_ = m.SetConfig(&pb.IssuerConfig{AllowedProfiles: []string{"PCA"}})
	})
	req = valid()
	req.Label = "L5"
	req.ParentID = proot.ID.String()
	req.Profile = "OTHER"
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, `forbidden: profile "OTHER" is not allowed by the parent issuer`)
	req.Profile = "PCA"
	storeIssuer(tca, func(m *model.Issuer) {
		assert.Equal(t, uint64(1), m.OrgID.UInt64())
		assert.Equal(t, proot.ID.UInt64(), m.ParentID.UInt64())
		assert.Equal(t, proot.Skid, m.Ikid)
		assert.Equal(t, proot.Pem, m.RootPem)
	})
	l5, err := svc.RegisterIssuer(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "1", l5.OrgID)
	assert.Equal(t, proot.ID.String(), l5.ParentID)

	// conflicts and failures of the registration
	req = valid()
	req.Label = "L6"
	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Nil()).
		Return(nil, errors.New(`pq: duplicate key value violates unique constraint "unique_issuer_org_project_label"`))
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "conflict: issuer label is already registered: L6")
	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Nil()).
		Return(nil, errors.New(`pq: duplicate key value violates unique constraint "unique_issuer_skid"`))
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "conflict: issuer key is already registered")
	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Nil()).Return(nil, errors.New("db down"))
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "unexpected: failed to register issuer")

	// the trust anchor of a root is registered with it: an anchor that
	// cannot be registered fails the root, and nothing is stored
	req = valid()
	req.Label = "R3"
	req.Type = pb.AuthorityType_Root
	req.Profile = "SELF"
	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Not(gomock.Nil())).
		Return(nil, errors.WithMessage(db.ErrRootConflict, "unable to register root"))
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "conflict: root certificate is registered in another scope")
	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Not(gomock.Nil())).
		Return(nil, errors.New("db down"))
	_, err = svc.RegisterIssuer(ctx, req)
	assert.EqualError(t, err, "unexpected: failed to register issuer")

	// a service caller names the org
	ra := serviceCtx("trustyca-ra")
	tca.orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	storeIssuer(tca, func(m *model.Issuer) {
		assert.Equal(t, uint64(1), m.OrgID.UInt64())
	})
	req = valid()
	req.OrgID = "1"
	req.Label = "L7"
	_, err = svc.RegisterIssuer(ra, req)
	require.NoError(t, err)
}

func TestService_ImportIssuer(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	root := testutils.NewTestCA(t, "Import Root", nil)
	l1 := testutils.NewTestCA(t, "Import L1", root)
	valid := func() *privpb.ImportIssuerRequest {
		return &privpb.ImportIssuerRequest{
			Label:       "BYO",
			Type:        pb.AuthorityType_Issuing,
			Certificate: testutils.CertPEM(l1.Cert),
			Root:        testutils.CertPEM(root.Cert),
			KeyPem:      keyPEM(t, l1.Key),
			Config:      &pb.IssuerConfig{CrlExpiry: "24h"},
		}
	}

	_, err := svc.ImportIssuer(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	noCA := tca.noCA()
	_, err = noCA.ImportIssuer(ctx, valid())
	assert.EqualError(t, err, "unavailable: CA is not configured")
	req := valid()
	req.Label = ""
	_, err = svc.ImportIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing label")
	req.Label = strings.Repeat("x", model.MaxLenForLabel+1)
	_, err = svc.ImportIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid label length")
	req = valid()
	req.Type = pb.AuthorityType_Unknown
	_, err = svc.ImportIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing type")
	req = valid()
	req.Certificate = ""
	_, err = svc.ImportIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing certificate")
	req = valid()
	req.KeyPem = ""
	_, err = svc.ImportIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: either key URI or key PEM is required")
	req = valid()
	req.KeyURI = "pkcs11:x"
	_, err = svc.ImportIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: either key URI or key PEM is required")
	_, err = svc.ImportIssuer(testCtx("42", ""), valid())
	assert.EqualError(t, err, "forbidden: org not selected")
	req = valid()
	req.KeyPem = keyPEM(t, root.Key)
	_, err = svc.ImportIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: failed to import issuer: key does not match the certificate")
	req = valid()
	req.Root = ""
	_, err = svc.ImportIssuer(ctx, req)
	assert.ErrorContains(t, err, "bad_request: failed to import issuer: invalid certificate chain")

	rootPEM, err := certutil.EncodeToPEMString(false, root.Cert)
	require.NoError(t, err)
	storeIssuer(tca, func(m *model.Issuer) {
		assert.Equal(t, uint64(1), m.OrgID.UInt64())
		assert.True(t, m.ProjectID.IsZero())
		assert.Equal(t, "BYO", m.Label)
		assert.Equal(t, pb.AuthorityType_Issuing, m.Type)
		assert.Equal(t, pb.IssuerStatus_Active, m.Status)
		assert.Equal(t, certutil.GetSubjectKeyID(l1.Cert), m.Skid)
		assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), m.Ikid)
		assert.Empty(t, m.ChainPem)
		assert.Equal(t, rootPEM, m.RootPem)
		assert.Equal(t, core.SoftwareKeyProvider, m.KeyProvider)
		assert.NotEmpty(t, m.KeyProtected)
	})
	res, err := svc.ImportIssuer(ctx, valid())
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, res.Status)
	assert.Equal(t, "24h", res.Config.CrlExpiry)
	assert.Equal(t, rootPEM, res.Root)
	evt := tca.events.last(pb.EventType_IssuerRegistered)
	require.NotNil(t, evt)
	assert.Equal(t, "Issuer imported", evt.Title)
	assert.Equal(t, res.ID, evt.ReferenceID.String())

	// the imported issuer signs
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("byo-peer", "BYO", "1h"))
	storeCertificate(tca)
	_, csrPEM := newCSR(t, "leaf.example.com")
	signed, err := svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: "byo-peer", Request: csrPEM})
	require.NoError(t, err)
	assert.Equal(t, certutil.GetSubjectKeyID(l1.Cert), signed.Certificate.IKID)

	// an imported root is a trust anchor of the org
	req = valid()
	req.Label = "BYO_ROOT"
	req.Type = pb.AuthorityType_Root
	req.Certificate = testutils.CertPEM(root.Cert)
	req.Root = ""
	req.KeyPem = keyPEM(t, root.Key)
	storeRootIssuer(tca, func(m *model.Issuer, anchor *model.RootCertificate) {
		assert.Equal(t, m.Pem, m.RootPem)
		assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), anchor.Skid)
		assert.Equal(t, m.Sha256, anchor.Sha256)
	})
	_, err = svc.ImportIssuer(ctx, req)
	require.NoError(t, err)

	tca.cadb.EXPECT().RegisterIssuer(gomock.Any(), gomock.Any(), gomock.Nil()).
		Return(nil, errors.New(`pq: duplicate key value violates unique constraint "unique_issuer_org_project_label"`))
	_, err = svc.ImportIssuer(ctx, valid())
	assert.EqualError(t, err, "conflict: issuer label is already registered: BYO")
}

func TestService_ActivateIssuer(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	pending := tca.newPending(t, testOrgID(), xdb.ID(0), "EXT")

	// an external CA, here the root of the org, signs the request
	res, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testCAProfile, IssuerLabel: testRootLabel})
	require.NoError(t, err)
	crt, certPEM, err := res.Issuer.Sign(csr.SignRequest{Request: pending.CsrPem, Profile: res.ProfileName})
	require.NoError(t, err)
	valid := func() *privpb.ActivateIssuerRequest {
		return &privpb.ActivateIssuerRequest{
			ID:          pending.ID.String(),
			Certificate: string(certPEM),
			Root:        tca.root.Pem,
		}
	}

	_, err = svc.ActivateIssuer(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	noCA := tca.noCA()
	_, err = noCA.ActivateIssuer(ctx, valid())
	assert.EqualError(t, err, "unavailable: CA is not configured")
	req := valid()
	req.Certificate = ""
	_, err = svc.ActivateIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing certificate")
	req = valid()
	req.ID = ""
	_, err = svc.ActivateIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: missing issuer ID")
	req.ID = "bad"
	_, err = svc.ActivateIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid issuer ID")
	req.ID = "9999"
	_, err = svc.ActivateIssuer(ctx, req)
	assert.EqualError(t, err, "not_found: issuer not found")
	other := tca.newPending(t, xdb.NewID(2), xdb.ID(0), "EXT")
	req.ID = other.ID.String()
	_, err = svc.ActivateIssuer(ctx, req)
	assert.EqualError(t, err, "not_found: issuer not found", "a pending issuer of another org")
	req.ID = tca.issuer.ID.String()
	_, err = svc.ActivateIssuer(ctx, req)
	assert.EqualError(t, err, "conflict: issuer is not pending")
	req = valid()
	req.Certificate = "junk"
	_, err = svc.ActivateIssuer(ctx, req)
	assert.ErrorContains(t, err, "bad_request: failed to activate issuer: invalid certificate")
	req = valid()
	req.Certificate = tca.issuer.Pem
	_, err = svc.ActivateIssuer(ctx, req)
	assert.EqualError(t, err, "bad_request: failed to activate issuer: certificate does not match the key of the issuer")
	req = valid()
	req.Root = ""
	_, err = svc.ActivateIssuer(ctx, req)
	assert.ErrorContains(t, err, "bad_request: failed to activate issuer: invalid certificate chain")

	tca.cadb.EXPECT().ActivateIssuer(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.Issuer) (*model.Issuer, error) {
			assert.Equal(t, pending.ID.UInt64(), m.ID.UInt64())
			assert.Equal(t, uint64(1), m.OrgID.UInt64())
			assert.Equal(t, certutil.GetSubjectKeyID(crt), m.Skid)
			assert.Equal(t, tca.root.Skid, m.Ikid)
			assert.Equal(t, tca.root.Pem, m.RootPem)
			assert.Empty(t, m.ChainPem)
			assert.Equal(t, certutil.SHA256Hex(crt.Raw), m.Sha256)
			return tca.rows.update(m.ID, func(r *model.Issuer) {
				*r = *m
				r.Status = pb.IssuerStatus_Active
				r.CsrPem = ""
			}), nil
		})
	activated, err := svc.ActivateIssuer(ctx, valid())
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, activated.Status)
	assert.Empty(t, activated.Csr)
	assert.Equal(t, tca.root.Skid, activated.IKID)
	evt := tca.events.last(pb.EventType_IssuerActivated)
	require.NotNil(t, evt)
	assert.Equal(t, pending.ID.UInt64(), evt.ReferenceID.UInt64())
	assert.Contains(t, evt.Description.String(), `issuer "EXT" activated`)

	// the activated issuer signs
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("ext-peer", "EXT", "1h"))
	storeCertificate(tca)
	_, csrPEM := newCSR(t, "leaf.example.com")
	signed, err := svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: "ext-peer", Request: csrPEM})
	require.NoError(t, err)
	assert.Equal(t, activated.SKID, signed.Certificate.IKID)

	// races with the DB
	p2 := tca.newPending(t, testOrgID(), xdb.ID(0), "EXT2")
	crt2, certPEM2, err := res.Issuer.Sign(csr.SignRequest{Request: p2.CsrPem, Profile: res.ProfileName})
	require.NoError(t, err)
	require.NotEqual(t, crt.SerialNumber, crt2.SerialNumber)
	req2 := &privpb.ActivateIssuerRequest{ID: p2.ID.String(), Certificate: string(certPEM2), Root: tca.root.Pem}
	tca.cadb.EXPECT().ActivateIssuer(gomock.Any(), gomock.Any()).Return(nil, notFoundErr("issuer", p2.ID.UInt64()))
	_, err = svc.ActivateIssuer(ctx, req2)
	assert.EqualError(t, err, "conflict: issuer is not pending")
	tca.cadb.EXPECT().ActivateIssuer(gomock.Any(), gomock.Any()).
		Return(nil, errors.New(`pq: duplicate key value violates unique constraint "unique_issuer_skid"`))
	_, err = svc.ActivateIssuer(ctx, req2)
	assert.EqualError(t, err, "conflict: issuer key is already registered")
	tca.cadb.EXPECT().ActivateIssuer(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.ActivateIssuer(ctx, req2)
	assert.EqualError(t, err, "unexpected: failed to activate issuer")
}

func TestService_UpdateIssuer(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	issuer := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "UPD", pb.AuthorityType_Issuing, nil)
	tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef("upd-peer", "UPD", "1h"))
	_, csrPEM := newCSR(t, "leaf.example.com")

	_, err := svc.UpdateIssuer(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	noCA := tca.noCA()
	_, err = noCA.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: issuer.ID.String(), Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "unavailable: CA is not configured")
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: issuer.ID.String()})
	assert.EqualError(t, err, "bad_request: nothing to update")
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "bad_request: missing issuer ID")
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: "9999", Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "not_found: issuer not found")
	org2Root := tca.newRoot(t, xdb.NewID(2), xdb.ID(0), testRootLabel)
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: org2Root.ID.String(), Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "not_found: issuer not found", "an issuer of another org")

	// the lifecycle moves one step at a time
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: issuer.ID.String(), Status: pb.IssuerStatus_Destroyed})
	assert.EqualError(t, err, "conflict: issuer status Active cannot change to Destroyed")
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: issuer.ID.String(), Status: pb.IssuerStatus_Pending})
	assert.EqualError(t, err, "conflict: issuer status Active cannot change to Pending")

	// the issuer signs until it is archived
	storeCertificate(tca)
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: "upd-peer", Request: csrPEM})
	require.NoError(t, err)
	tca.cadb.EXPECT().UpdateIssuer(gomock.Any(), &query.UpdateIssuerRequest{ID: issuer.ID.UInt64(), OrgID: 1, Status: pb.IssuerStatus_Archived}).DoAndReturn(
		func(_ context.Context, _ *query.UpdateIssuerRequest) (*model.Issuer, error) {
			return tca.rows.update(issuer.ID, func(m *model.Issuer) { m.Status = pb.IssuerStatus_Archived }), nil
		})
	res, err := svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: issuer.ID.String(), Status: pb.IssuerStatus_Archived})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Archived, res.Status)
	evt := tca.events.last(pb.EventType_IssuerUpdated)
	require.NotNil(t, evt)
	assert.Equal(t, issuer.ID.UInt64(), evt.ReferenceID.UInt64())
	assert.Contains(t, evt.Description.String(), `issuer "UPD" updated: status Archived`)
	_, err = svc.SignCertificate(ctx, &privpb.SignCertificateRequest{Profile: "upd-peer", Request: csrPEM})
	assert.EqualError(t, err, "conflict: issuer is not active", "the archived issuer left the registry at once")

	// a destroyed issuer loses its key
	tca.cadb.EXPECT().UpdateIssuer(gomock.Any(), &query.UpdateIssuerRequest{ID: issuer.ID.UInt64(), OrgID: 1, Status: pb.IssuerStatus_Destroyed}).DoAndReturn(
		func(_ context.Context, _ *query.UpdateIssuerRequest) (*model.Issuer, error) {
			return tca.rows.update(issuer.ID, func(m *model.Issuer) {
				m.Status = pb.IssuerStatus_Destroyed
				m.KeyProtected = ""
			}), nil
		})
	res, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: issuer.ID.String(), Status: pb.IssuerStatus_Destroyed})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Destroyed, res.Status)

	// the settings
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: tca.issuer.ID.String(), Config: &pb.IssuerConfig{CrlExpiry: "x"}})
	assert.EqualError(t, err, `bad_request: invalid config: invalid CrlExpiry: "x" is not a duration`)
	before, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testProfile})
	require.NoError(t, err)
	assert.Equal(t, 8*time.Hour, before.Issuer.OcspExpiry())
	tca.cadb.EXPECT().UpdateIssuer(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, q *query.UpdateIssuerRequest) (*model.Issuer, error) {
			assert.Equal(t, tca.issuer.ID.UInt64(), q.ID)
			assert.Equal(t, uint64(1), q.OrgID)
			assert.Equal(t, pb.IssuerStatus_Unknown, q.Status)
			assert.Contains(t, string(q.Config), `"OcspExpiry":"2h"`)
			return tca.rows.update(tca.issuer.ID, func(m *model.Issuer) { m.Config = model.JSON(q.Config) }), nil
		})
	res, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: tca.issuer.ID.String(), Config: &pb.IssuerConfig{
		AllowedProfiles: []string{testOCSPProfile},
		OcspExpiry:      "2h",
	}})
	require.NoError(t, err)
	assert.Equal(t, "2h", res.Config.OcspExpiry)
	assert.Equal(t, pb.IssuerStatus_Active, res.Status)
	after, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testProfile})
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, after.Issuer.OcspExpiry(), "the registry rebuilt the issuer")

	// DB failures
	tca.cadb.EXPECT().UpdateIssuer(gomock.Any(), gomock.Any()).Return(nil, notFoundErr("issuer", tca.issuer.ID.UInt64()))
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: tca.issuer.ID.String(), Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "not_found: issuer not found")
	tca.cadb.EXPECT().UpdateIssuer(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.UpdateIssuer(ctx, &privpb.UpdateIssuerRequest{ID: tca.issuer.ID.String(), Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "unexpected: failed to update issuer")
}

func TestService_GetIssuer(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	org2Root := tca.newRoot(t, xdb.NewID(2), xdb.ID(0), testRootLabel)
	platformRoot := tca.newRoot(t, xdb.ID(0), xdb.ID(0), "PROOT")

	_, err := svc.GetIssuer(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{})
	assert.EqualError(t, err, "bad_request: issuer ID, label or IKID is required")
	_, err = svc.GetIssuer(testCtx("42", ""), &privpb.GetIssuerRequest{ID: tca.issuer.ID.String()})
	assert.EqualError(t, err, "forbidden: org not selected")

	// by ID
	res, err := svc.GetIssuer(ctx, &privpb.GetIssuerRequest{ID: tca.issuer.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, testIssuerLabel, res.Label)
	assert.Equal(t, tca.issuer.Skid, res.SKID)
	assert.Equal(t, tca.root.Skid, res.IKID)
	assert.Equal(t, tca.root.ID.String(), res.ParentID)
	assert.Equal(t, tca.issuer.Pem, res.Certificate)
	assert.Equal(t, tca.root.Pem, res.Root)
	assert.Equal(t, []string{testOCSPProfile}, res.Config.AllowedProfiles)
	assert.Equal(t, core.SoftwareKeyProvider, res.KeyProvider)
	assert.Equal(t, "0", res.CrlNumber)
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{ID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid issuer ID")
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{ID: "9999"})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{ID: org2Root.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found", "an issuer of another org")
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{ID: platformRoot.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found", "a platform issuer")

	// by label, in the project then in the org
	res, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{Label: testIssuerLabel, ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, tca.issuer.ID.String(), res.ID)
	projectIssuer := tca.newChild(t, tca.root, testCAProfile, testOrgID(), testProject.ID, testIssuerLabel, pb.AuthorityType_Issuing, nil)
	res, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{Label: testIssuerLabel, ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, projectIssuer.ID.String(), res.ID)
	assert.Equal(t, "201", res.ProjectID)
	res, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{Label: testIssuerLabel})
	require.NoError(t, err)
	assert.Equal(t, tca.issuer.ID.String(), res.ID)
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{Label: "nope"})
	assert.EqualError(t, err, "not_found: issuer not found: nope")
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{Label: testIssuerLabel, ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")

	// by IKID
	res, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{IKID: tca.issuer.Skid})
	require.NoError(t, err)
	assert.Equal(t, tca.issuer.ID.String(), res.ID)
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{IKID: org2Root.Skid})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = svc.GetIssuer(ctx, &privpb.GetIssuerRequest{IKID: "nope"})
	assert.EqualError(t, err, "not_found: issuer not found")

	// a service caller names the org
	tca.orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	res, err = svc.GetIssuer(serviceCtx("trustyca-ra"), &privpb.GetIssuerRequest{OrgID: "1", ID: tca.issuer.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, tca.issuer.ID.String(), res.ID)
}

func TestService_IssuerProjectAccess(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	admin := testCtx(orgAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")
	projectIssuer := tca.newChild(t, tca.root, testCAProfile, testOrgID(), testProject.ID, "PRJ", pb.AuthorityType_Issuing, nil)
	// the sibling is an intermediate with path length one, so that it can
	// sign a subordinate below
	tca.addProfile(testOrgID(), xdb.ID(0), caProfileDefWithPathLen("INTCA", testRootLabel, 1))
	sibling := tca.newChild(t, tca.root, "INTCA", testOrgID(), siblingProject.ID, "SIB", pb.AuthorityType_Intermediate, nil)
	gone := tca.newChild(t, tca.root, testCAProfile, testOrgID(), inactiveProject.ID, "GONE", pb.AuthorityType_Issuing, nil)

	// a member with a grant in one project reads the org-wide issuers and
	// those of its project; an issuer of another project is not found,
	// whether by ID or by IKID, and so is one of an inactive project
	res, err := svc.GetIssuer(viewer, &privpb.GetIssuerRequest{ID: tca.issuer.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, testIssuerLabel, res.Label)
	res, err = svc.GetIssuer(viewer, &privpb.GetIssuerRequest{ID: projectIssuer.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, "201", res.ProjectID)
	_, err = svc.GetIssuer(viewer, &privpb.GetIssuerRequest{ID: sibling.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = svc.GetIssuer(viewer, &privpb.GetIssuerRequest{IKID: sibling.Skid})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = svc.GetIssuer(viewer, &privpb.GetIssuerRequest{ID: gone.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found")
	// an org-wide role reads every project
	res, err = svc.GetIssuer(admin, &privpb.GetIssuerRequest{ID: sibling.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, "202", res.ProjectID)
	_, err = svc.GetIssuer(admin, &privpb.GetIssuerRequest{ID: gone.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found", "an inactive project hides its rows")
	// a member without a grant reads nothing
	_, err = svc.GetIssuer(testCtx(strangerUser, "1"), &privpb.GetIssuerRequest{ID: tca.issuer.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found")
	// an API key restricted to a project reads the org-wide issuers and
	// those of its project; an org-wide key reads every project
	key := apiKeyCtx("1", "201")
	_, err = svc.GetIssuer(key, &privpb.GetIssuerRequest{ID: tca.issuer.ID.String()})
	require.NoError(t, err)
	_, err = svc.GetIssuer(key, &privpb.GetIssuerRequest{ID: projectIssuer.ID.String()})
	require.NoError(t, err)
	_, err = svc.GetIssuer(key, &privpb.GetIssuerRequest{ID: sibling.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = svc.GetIssuer(apiKeyCtx("1", ""), &privpb.GetIssuerRequest{ID: sibling.ID.String()})
	require.NoError(t, err)
	_, err = svc.GetIssuer(apiKeyCtx("1", ""), &privpb.GetIssuerRequest{ID: gone.ID.String()})
	assert.EqualError(t, err, "not_found: issuer not found")

	// a list without a project covers the org-wide issuers and the projects
	// of the member's grants; an org-wide role lists every project
	tca.cadb.EXPECT().ListIssuers(gomock.Any(), &query.ListIssuersRequest{
		OrgID:      1,
		ProjectIDs: []uint64{201},
		Limit:      xdb.DefaultPageSize,
	}).Return(&model.IssuerResult{Rows: []*model.Issuer{tca.issuer, projectIssuer}}, nil)
	list, err := svc.ListIssuers(viewer, &privpb.ListIssuersRequest{})
	require.NoError(t, err)
	assert.Len(t, list.Issuers, 2)
	tca.cadb.EXPECT().ListIssuers(gomock.Any(), &query.ListIssuersRequest{
		OrgID:     1,
		ProjectID: 201,
		Limit:     xdb.DefaultPageSize,
	}).Return(&model.IssuerResult{}, nil)
	_, err = svc.ListIssuers(viewer, &privpb.ListIssuersRequest{ProjectID: "201"})
	require.NoError(t, err)
	tca.cadb.EXPECT().ListIssuers(gomock.Any(), &query.ListIssuersRequest{
		OrgID:      1,
		ProjectIDs: []uint64{},
		Limit:      xdb.DefaultPageSize,
	}).Return(&model.IssuerResult{}, nil)
	_, err = svc.ListIssuers(testCtx(strangerUser, "1"), &privpb.ListIssuersRequest{})
	require.NoError(t, err)
	tca.cadb.EXPECT().ListIssuers(gomock.Any(), &query.ListIssuersRequest{
		OrgID: 1,
		Limit: xdb.DefaultPageSize,
	}).Return(&model.IssuerResult{}, nil)
	_, err = svc.ListIssuers(admin, &privpb.ListIssuersRequest{})
	require.NoError(t, err)

	// a project Admin changes the issuers of its project only: an org-wide
	// issuer is forbidden, one of another project is not found
	projectAdmin := testCtx(projectAdminUser, "1")
	_, err = svc.UpdateIssuer(projectAdmin, &privpb.UpdateIssuerRequest{ID: tca.issuer.ID.String(), Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "forbidden: access denied")
	_, err = svc.UpdateIssuer(projectAdmin, &privpb.UpdateIssuerRequest{ID: sibling.ID.String(), Status: pb.IssuerStatus_Archived})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = svc.ActivateIssuer(projectAdmin, &privpb.ActivateIssuerRequest{ID: sibling.ID.String(), Certificate: sibling.Pem})
	assert.EqualError(t, err, "not_found: issuer not found")
	tca.cadb.EXPECT().UpdateIssuer(gomock.Any(), &query.UpdateIssuerRequest{ID: projectIssuer.ID.UInt64(), OrgID: 1, Status: pb.IssuerStatus_Archived}).DoAndReturn(
		func(_ context.Context, _ *query.UpdateIssuerRequest) (*model.Issuer, error) {
			return tca.rows.update(projectIssuer.ID, func(m *model.Issuer) { m.Status = pb.IssuerStatus_Archived }), nil
		})
	res, err = svc.UpdateIssuer(projectAdmin, &privpb.UpdateIssuerRequest{ID: projectIssuer.ID.String(), Status: pb.IssuerStatus_Archived})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Archived, res.Status)
	_, err = svc.UpdateIssuer(viewer, &privpb.UpdateIssuerRequest{ID: projectIssuer.ID.String(), Status: pb.IssuerStatus_Destroyed})
	assert.EqualError(t, err, "forbidden: access denied", "a project Viewer")

	// the parent of a new issuer is visible from the scope of the new
	// issuer: org-wide or of the same project, never of another project
	req := &privpb.RegisterIssuerRequest{
		Label:     "UNDER_SIB",
		Type:      pb.AuthorityType_Issuing,
		Subject:   &pb.X509Subject{CommonName: "Under Sibling"},
		ProjectID: "201",
		ParentID:  sibling.ID.String(),
		Profile:   testCAProfile,
	}
	_, err = svc.RegisterIssuer(admin, req)
	assert.EqualError(t, err, "not_found: parent issuer not found")
	req.ProjectID = ""
	_, err = svc.RegisterIssuer(admin, req)
	assert.EqualError(t, err, "not_found: parent issuer not found", "an org-wide issuer under a project issuer")
	tca.addProfile(testOrgID(), siblingProject.ID, caProfileDef("SIBCA", "SIB"))
	req.ProjectID = "202"
	req.Profile = "SIBCA"
	storeIssuer(tca, func(m *model.Issuer) {
		assert.Equal(t, sibling.ID.UInt64(), m.ParentID.UInt64())
		assert.Equal(t, uint64(202), m.ProjectID.UInt64())
	})
	_, err = svc.RegisterIssuer(admin, req)
	require.NoError(t, err)

	// a Root is self-signed: a parent is refused before any key is made
	_, err = svc.RegisterIssuer(admin, &privpb.RegisterIssuerRequest{
		Label:    "R9",
		Type:     pb.AuthorityType_Root,
		Subject:  &pb.X509Subject{CommonName: "Root"},
		ParentID: tca.root.ID.String(),
		Profile:  testCAProfile,
	})
	assert.EqualError(t, err, "bad_request: a Root issuer is self-signed: parent ID is not allowed")
}

func TestService_ListIssuers(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")

	_, err := svc.ListIssuers(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.ListIssuers(testCtx("42", ""), &privpb.ListIssuersRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.ListIssuers(ctx, &privpb.ListIssuersRequest{ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")
	_, err = svc.ListIssuers(ctx, &privpb.ListIssuersRequest{Cursor: "zzz"})
	assert.EqualError(t, err, "bad_request: invalid cursor")

	tca.cadb.EXPECT().ListIssuers(gomock.Any(), &query.ListIssuersRequest{
		OrgID:     1,
		ProjectID: 201,
		Status:    pb.IssuerStatus_Active,
		Type:      pb.AuthorityType_Issuing,
		Limit:     xdb.DefaultPageSize,
	}).Return(&model.IssuerResult{
		Rows:        []*model.Issuer{tca.issuer},
		HasNextPage: true,
		NextOffset:  100,
	}, nil)
	res, err := svc.ListIssuers(ctx, &privpb.ListIssuersRequest{
		ProjectID: "201",
		Status:    pb.IssuerStatus_Active,
		Type:      pb.AuthorityType_Issuing,
	})
	require.NoError(t, err)
	require.Len(t, res.Issuers, 1)
	assert.Equal(t, testIssuerLabel, res.Issuers[0].Label)
	require.NotNil(t, res.NextPage)
	assert.EqualValues(t, 100, res.NextPage.Offset)

	initial, err := query.ParseCursor(query.InitialCursor)
	require.NoError(t, err)
	tca.cadb.EXPECT().ListIssuers(gomock.Any(), &query.ListIssuersRequest{
		OrgID:  1,
		Limit:  10,
		Cursor: initial,
	}).Return(&model.IssuerResult{}, nil)
	res, err = svc.ListIssuers(ctx, &privpb.ListIssuersRequest{Limit: 10, Cursor: query.InitialCursor})
	require.NoError(t, err)
	assert.Empty(t, res.Issuers)
	assert.Nil(t, res.NextPage)

	tca.cadb.EXPECT().ListIssuers(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.ListIssuers(ctx, &privpb.ListIssuersRequest{})
	assert.EqualError(t, err, "unexpected: failed to list issuers")
}

func TestService_Issuers_SoftwareKeysDisabled(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	tca.keys.DisableSoftwareKeys()
	svc := tca.service()
	ctx := testCtx("42", "1")

	// the inmem provider generates software keys: a new root is refused
	// before anything is stored
	_, err := svc.RegisterIssuer(ctx, &privpb.RegisterIssuerRequest{
		Label:   "NOSOFT",
		Type:    pb.AuthorityType_Root,
		Subject: &pb.X509Subject{CommonName: "No Software Root"},
		Profile: testCAProfile,
	})
	assert.EqualError(t, err, "bad_request: failed to create issuer: software keys are not allowed: use a key of a crypto provider")

	// a PEM key is a software key
	root := testutils.NewTestCA(t, "Import Root", nil)
	_, err = svc.ImportIssuer(ctx, &privpb.ImportIssuerRequest{
		Label:       "BYO",
		Type:        pb.AuthorityType_Root,
		Certificate: testutils.CertPEM(root.Cert),
		KeyPem:      keyPEM(t, root.Key),
	})
	assert.EqualError(t, err, "bad_request: failed to import issuer: software keys are not allowed: use a key of a crypto provider")
}
