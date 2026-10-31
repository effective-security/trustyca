package pgsql_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Issuer(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Issuer")
	project, err := provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Name: "CA"})
	require.NoError(t, err)

	root := testutils.NewTestCA(t, "Issuer Root", nil)
	l1 := testutils.NewTestCA(t, "Issuer L1", root)
	l2 := testutils.NewTestCA(t, "Issuer L2", l1)

	_, err = provider.RegisterIssuer(ctx, &model.Issuer{OrgID: org.ID, Label: "x"}, nil)
	assert.EqualError(t, err, "invalid issuer type")

	// a platform root, an org intermediate and a project issuing CA
	platformLabel := "ROOT_" + certutil.RandomString(8)
	rootIssuer := registerRootIssuer(t, newTestIssuer(xdb.ID(0), xdb.ID(0), platformLabel, root, pb.AuthorityType_Root, xdb.ID(0)), root.Cert)
	assert.True(t, rootIssuer.OrgID.IsZero(), "platform rows have no org")
	assert.True(t, rootIssuer.ProjectID.IsZero())
	assert.True(t, rootIssuer.ParentID.IsZero())
	assert.Equal(t, pb.IssuerStatus_Active, rootIssuer.Status)
	assert.EqualValues(t, 0, rootIssuer.CrlNumber)
	assert.Empty(t, rootIssuer.KeyProtected)
	assert.True(t, rootIssuer.Config.IsEmpty())
	assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), rootIssuer.Skid)
	assert.Equal(t, root.Cert.NotAfter.UnixMilli(), rootIssuer.NotAfter.UnixMilli())
	assert.False(t, rootIssuer.CreatedAt.IsZero())

	orgIssuer := registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "L1", l1, pb.AuthorityType_Intermediate, rootIssuer.ID))
	assert.Equal(t, org.ID.UInt64(), orgIssuer.OrgID.UInt64())
	assert.Equal(t, rootIssuer.ID.UInt64(), orgIssuer.ParentID.UInt64())
	assert.Equal(t, rootIssuer.Skid, orgIssuer.Ikid, "the IKID is the parent's SKID")
	assert.Equal(t, testutils.CertPEM(root.Cert), orgIssuer.ChainPem)
	assert.Equal(t, testutils.CertPEM(root.Cert), orgIssuer.RootPem)

	prjIssuer := registerIssuer(t, newTestIssuer(org.ID, project.ID, "L2", l2, pb.AuthorityType_Issuing, orgIssuer.ID))
	assert.Equal(t, project.ID.UInt64(), prjIssuer.ProjectID.UInt64())

	// the label is unique in its scope, the SKID across the table
	_, err = provider.RegisterIssuer(ctx, newTestIssuer(org.ID, xdb.ID(0), "L1", testutils.NewTestCA(t, "Other L1", root), pb.AuthorityType_Intermediate, rootIssuer.ID), nil)
	assert.ErrorContains(t, err, "unique_issuer_org_project_label")
	assert.True(t, db.IsUniqueViolation(err, db.UniqueIssuerLabel), "the driver's error names the constraint")
	assert.False(t, db.IsUniqueViolation(err, db.UniqueIssuerSkid))
	_, err = provider.RegisterIssuer(ctx, newTestIssuer(org.ID, xdb.ID(0), "L1-copy", l1, pb.AuthorityType_Intermediate, rootIssuer.ID), nil)
	assert.ErrorContains(t, err, "unique_issuer_skid")
	assert.True(t, db.IsUniqueViolation(err, db.UniqueIssuerSkid))
	assert.True(t, db.IsUniqueViolation(err, ""))
	// the same label in another scope is another issuer
	otherScope := registerIssuer(t, newTestIssuer(org.ID, project.ID, "L1", testutils.NewTestCA(t, "Project L1", root), pb.AuthorityType_Intermediate, rootIssuer.ID))
	assert.NotEqual(t, orgIssuer.ID.UInt64(), otherScope.ID.UInt64())

	// get
	got, err := provider.GetIssuer(ctx, orgIssuer.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, "L1", got.Label)
	cfg, err := got.GetConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.AllowedProfiles)
	_, err = provider.GetIssuer(ctx, 1)
	assert.ErrorContains(t, err, "record not found: issuer: 1")

	// find by exact scope: labels of other scopes are not visible
	found, err := provider.FindIssuer(ctx, org.ID.UInt64(), 0, "L1")
	require.NoError(t, err)
	assert.Equal(t, orgIssuer.ID.UInt64(), found.ID.UInt64())
	found, err = provider.FindIssuer(ctx, org.ID.UInt64(), project.ID.UInt64(), "L2")
	require.NoError(t, err)
	assert.Equal(t, prjIssuer.ID.UInt64(), found.ID.UInt64())
	found, err = provider.FindIssuer(ctx, org.ID.UInt64(), project.ID.UInt64(), "L1")
	require.NoError(t, err)
	assert.Equal(t, otherScope.ID.UInt64(), found.ID.UInt64())
	_, err = provider.FindIssuer(ctx, org.ID.UInt64(), 0, "L2")
	assert.ErrorContains(t, err, "record not found")
	found, err = provider.FindIssuer(ctx, 0, 0, platformLabel)
	require.NoError(t, err)
	assert.Equal(t, rootIssuer.ID.UInt64(), found.ID.UInt64())
	_, err = provider.FindIssuer(ctx, org.ID.UInt64(), 0, platformLabel)
	assert.ErrorContains(t, err, "record not found", "platform issuers are not visible to tenants")

	bySkid, err := provider.GetIssuerBySKID(ctx, orgIssuer.Skid)
	require.NoError(t, err)
	assert.Equal(t, orgIssuer.ID.UInt64(), bySkid.ID.UInt64())
	_, err = provider.GetIssuerBySKID(ctx, "nope")
	assert.ErrorContains(t, err, "record not found: issuer: nope")

	// list: newest first, filters
	list, err := provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 3)
	assert.Equal(t, otherScope.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.Equal(t, prjIssuer.ID.UInt64(), list.Rows[1].ID.UInt64())
	assert.Equal(t, orgIssuer.ID.UInt64(), list.Rows[2].ID.UInt64())
	assert.False(t, list.HasNextPage)

	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Scope: pb.Scope_Org, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgIssuer.ID.UInt64(), list.Rows[0].ID.UInt64())

	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), ProjectID: project.ID.UInt64(), Type: pb.AuthorityType_Issuing, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, prjIssuer.ID.UInt64(), list.Rows[0].ID.UInt64())

	// the org-wide rows and the rows of the caller's projects
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), ProjectIDs: []uint64{project.ID.UInt64()}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 3)
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), ProjectIDs: []uint64{project.ID.UInt64() + 1}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgIssuer.ID.UInt64(), list.Rows[0].ID.UInt64(), "no grant in the project: the org-wide rows only")

	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), ParentID: orgIssuer.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, prjIssuer.ID.UInt64(), list.Rows[0].ID.UInt64())

	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Status: pb.IssuerStatus_Archived, Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, list.Rows)

	// by label, in every scope of the org
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Label: prjIssuer.Label, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, prjIssuer.ID.UInt64(), list.Rows[0].ID.UInt64())
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Label: "nope", Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, list.Rows)

	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{Platform: true, Limit: 500})
	require.NoError(t, err)
	var platformIDs []uint64
	for _, r := range list.Rows {
		assert.True(t, r.OrgID.IsZero(), "platform list has no tenant rows")
		platformIDs = append(platformIDs, r.ID.UInt64())
	}
	assert.Contains(t, platformIDs, rootIssuer.ID.UInt64())

	// a list names its org scope, or every org explicitly
	_, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{Limit: 10})
	assert.ErrorIs(t, err, db.ErrOrgScopeRequired)
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{AllOrgs: true, Limit: 500})
	require.NoError(t, err)
	var allIDs []uint64
	for _, r := range list.Rows {
		allIDs = append(allIDs, r.ID.UInt64())
	}
	assert.Contains(t, allIDs, rootIssuer.ID.UInt64())
	assert.Contains(t, allIDs, orgIssuer.ID.UInt64())

	// cursor pagination
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Limit: 2, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	assert.Equal(t, otherScope.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.Equal(t, prjIssuer.ID.UInt64(), list.Rows[1].ID.UInt64())
	require.True(t, list.HasNextPage)
	require.NotEmpty(t, list.Cursor)
	assert.EqualValues(t, 0, list.NextOffset, "cursor pagination carries no offset")
	next, err := query.ParseCursor(list.Cursor)
	require.NoError(t, err)
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Limit: 2, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgIssuer.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.False(t, list.HasNextPage)
	assert.Empty(t, list.Cursor)

	// a page that ends exactly at the limit reports a next page, which is empty
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Limit: 2, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	require.True(t, list.HasNextPage)
	next, err = query.ParseCursor(list.Cursor)
	require.NoError(t, err)
	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Limit: 3, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgIssuer.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.False(t, list.HasNextPage)

	// update
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{})
	assert.EqualError(t, err, "issuer ID is required")
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: orgIssuer.ID.UInt64(), OrgID: org.ID.UInt64()})
	assert.EqualError(t, err, "no changes to update")
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: orgIssuer.ID.UInt64(), OrgID: org.ID.UInt64(), Config: json.RawMessage(`{`)})
	assert.ErrorContains(t, err, "invalid config")
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: orgIssuer.ID.UInt64(), OrgID: org.ID.UInt64(), Config: json.RawMessage(`{"AllowedProfiles":"peer"}`)})
	assert.ErrorContains(t, err, "invalid config", "the config must have the shape of pb.IssuerConfig")
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: 1, OrgID: org.ID.UInt64(), Status: pb.IssuerStatus_Archived})
	assert.ErrorContains(t, err, "record not found: issuer: 1")
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: orgIssuer.ID.UInt64(), OrgID: org.ID.UInt64() + 1, Status: pb.IssuerStatus_Archived})
	assert.ErrorContains(t, err, "record not found", "another org's issuer is not found")
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: orgIssuer.ID.UInt64(), Status: pb.IssuerStatus_Archived})
	assert.ErrorContains(t, err, "record not found", "a tenant issuer is not a platform issuer")

	cfgJSON, err := model.MarshalJSONValue(&pb.IssuerConfig{CrlExpiry: "48h", AllowedProfiles: []string{"peer"}})
	require.NoError(t, err)
	upd, err := provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: orgIssuer.ID.UInt64(), OrgID: org.ID.UInt64(), Config: json.RawMessage(cfgJSON)})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, upd.Status, "the status is kept")
	cfg, err = upd.GetConfig()
	require.NoError(t, err)
	assert.Equal(t, "48h", cfg.CrlExpiry)
	assert.Equal(t, []string{"peer"}, cfg.AllowedProfiles)
	assert.GreaterOrEqual(t, upd.UpdatedAt.UnixMilli(), orgIssuer.UpdatedAt.UnixMilli())

	upd, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: orgIssuer.ID.UInt64(), OrgID: org.ID.UInt64(), Status: pb.IssuerStatus_Archived})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Archived, upd.Status)
	cfg, err = upd.GetConfig()
	require.NoError(t, err)
	assert.Equal(t, "48h", cfg.CrlExpiry, "the config is kept")
	assert.Equal(t, []string{"peer"}, cfg.AllowedProfiles)

	// Destroyed clears the protected key material
	soft := newTestIssuer(org.ID, xdb.ID(0), "soft", testutils.NewTestCA(t, "Soft L1", root), pb.AuthorityType_Intermediate, rootIssuer.ID)
	soft.KeyProtected = "wrapped-key"
	soft = registerIssuer(t, soft)
	assert.Equal(t, xdb.NULLString("wrapped-key"), soft.KeyProtected)
	destroyed, err := provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: soft.ID.UInt64(), OrgID: org.ID.UInt64(), Status: pb.IssuerStatus_Destroyed})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Destroyed, destroyed.Status)
	assert.Empty(t, destroyed.KeyProtected)

	// delete is scoped by org
	n, err := provider.DeleteIssuer(ctx, org.ID.UInt64()+1, soft.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	n, err = provider.DeleteIssuer(ctx, org.ID.UInt64(), soft.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	n, err = provider.DeleteIssuer(ctx, org.ID.UInt64(), soft.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	_, err = provider.GetIssuer(ctx, soft.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
}

func Test_Issuer_Activate(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Issuer_Activate")

	root := testutils.NewTestCA(t, "External Root", nil)
	sub := testutils.NewTestCA(t, "Pending Sub", root)

	// the key exists, the certificate is signed externally
	pending, err := provider.RegisterIssuer(ctx, &model.Issuer{
		OrgID:       org.ID,
		Label:       "ext",
		Type:        pb.AuthorityType_Issuing,
		Status:      pb.IssuerStatus_Pending,
		Skid:        certutil.GetSubjectKeyID(sub.Cert),
		Subject:     "CN=Pending Sub,O=trustyca tests",
		KeyProvider: testKeyProvider,
		KeyID:       "trustyca/" + org.ID.String() + "/0/ext",
		CsrPem:      "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteIssuer(ctx, org.ID.UInt64(), pending.ID.UInt64())
	})
	assert.Equal(t, pb.IssuerStatus_Pending, pending.Status)
	assert.Empty(t, pending.Pem)
	assert.True(t, pending.NotAfter.IsZero(), "nullable validity of a pending issuer")
	assert.NotEmpty(t, pending.CsrPem)

	list, err := provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Status: pb.IssuerStatus_Pending, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)

	_, err = provider.ActivateIssuer(ctx, &model.Issuer{})
	assert.EqualError(t, err, "issuer ID is required")
	_, err = provider.ActivateIssuer(ctx, pending)
	assert.EqualError(t, err, "invalid serial number: required", "the certificate columns are validated")

	act := *pending
	act.SetCertificate(sub.Cert, testutils.CertPEM(sub.Cert), sub.ChainPEM(), testutils.CertPEM(root.Cert))
	otherOrg := act
	otherOrg.OrgID = xdb.NewID(org.ID.UInt64() + 1)
	_, err = provider.ActivateIssuer(ctx, &otherOrg)
	assert.ErrorContains(t, err, "record not found", "another org's issuer is not found")
	active, err := provider.ActivateIssuer(ctx, &act)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, active.Status)
	assert.Empty(t, active.CsrPem, "the CSR is cleared")
	assert.Equal(t, testutils.CertPEM(sub.Cert), active.Pem)
	assert.Equal(t, testutils.CertPEM(root.Cert), active.ChainPem)
	assert.Equal(t, certutil.SHA256Hex(sub.Cert.Raw), active.Sha256)
	assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), active.Ikid)
	assert.Equal(t, sub.Cert.NotAfter.UnixMilli(), active.NotAfter.UnixMilli())
	assert.Equal(t, pending.Skid, active.Skid)
	assert.Equal(t, pending.KeyID, active.KeyID)

	// only a Pending issuer can be activated
	_, err = provider.ActivateIssuer(ctx, &act)
	assert.ErrorContains(t, err, "record not found: issuer: "+pending.ID.String())

	list, err = provider.ListIssuers(ctx, &query.ListIssuersRequest{OrgID: org.ID.UInt64(), Status: pb.IssuerStatus_Pending, Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, list.Rows)
}

// Test_Issuer_RootAnchor covers the anchor of a root issuer: it is written
// in the transaction of the issuer, and an anchor that cannot be written
// leaves no issuer
func Test_Issuer_RootAnchor(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Issuer_RootAnchor")
	_, other := setupOwnerAndOrg(t, "Test_Issuer_RootAnchor_Other")

	root := testutils.NewTestCA(t, "Anchored Root", nil)
	m := newTestIssuer(org.ID, xdb.ID(0), "ANCHORED", root, pb.AuthorityType_Root, xdb.ID(0))

	// a root requires its anchor, any other issuer takes none
	_, err := provider.RegisterIssuer(ctx, m, nil)
	assert.EqualError(t, err, "a root issuer requires its anchor")
	l1 := testutils.NewTestCA(t, "Unanchored L1", root)
	_, err = provider.RegisterIssuer(ctx, newTestIssuer(org.ID, xdb.ID(0), "UNANCHORED", l1, pb.AuthorityType_Intermediate, xdb.ID(0)),
		model.NewRootCertificate(l1.Cert, org.ID, pb.Trust_Private, testutils.CertPEM(l1.Cert)))
	assert.EqualError(t, err, "only a root issuer has an anchor")

	// the anchor is the certificate of the issuer in its org
	wrong := model.NewRootCertificate(root.Cert, other.ID, pb.Trust_Private, m.Pem)
	_, err = provider.RegisterIssuer(ctx, m, wrong)
	assert.EqualError(t, err, "the anchor must be the certificate of the issuer in its org")
	foreign := testutils.NewTestCA(t, "Foreign Root", nil)
	wrong = model.NewRootCertificate(foreign.Cert, org.ID, pb.Trust_Private, testutils.CertPEM(foreign.Cert))
	_, err = provider.RegisterIssuer(ctx, m, wrong)
	assert.EqualError(t, err, "the anchor must be the certificate of the issuer in its org")
	// the identity columns are derived from the PEM, not taken as claimed
	wrong.Sha256 = m.Sha256
	wrong.Skid = m.Skid
	_, err = provider.RegisterIssuer(ctx, m, wrong)
	assert.EqualError(t, err, "the anchor must be the certificate of the issuer in its org")
	for name, mod := range map[string]func(a *model.RootCertificate){
		"skid":       func(a *model.RootCertificate) { a.Skid = certutil.GetSubjectKeyID(foreign.Cert) },
		"subject":    func(a *model.RootCertificate) { a.Subject = foreign.Cert.Subject.String() },
		"not_before": func(a *model.RootCertificate) { a.NotBefore = a.NotBefore.Add(time.Second) },
		"not_after":  func(a *model.RootCertificate) { a.NotAfter = a.NotAfter.Add(-time.Second) },
	} {
		wrong = model.NewRootCertificate(root.Cert, org.ID, pb.Trust_Private, m.Pem)
		mod(wrong)
		_, err = provider.RegisterIssuer(ctx, m, wrong)
		assert.EqualError(t, err, "the anchor must be the certificate of the issuer in its org", name)
	}
	wrong = model.NewRootCertificate(root.Cert, org.ID, pb.Trust_Private, "not a certificate")
	_, err = provider.RegisterIssuer(ctx, m, wrong)
	assert.EqualError(t, err, "invalid anchor certificate: unable to parse PEM")
	_, err = provider.FindIssuer(ctx, org.ID.UInt64(), 0, "ANCHORED")
	assert.True(t, xdb.IsNotFoundError(err), "no rejected anchor stores the issuer: %v", err)

	anchor := model.NewRootCertificate(root.Cert, org.ID, pb.Trust_Private, m.Pem)
	res, err := provider.RegisterIssuer(ctx, m, anchor)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteIssuer(ctx, org.ID.UInt64(), res.ID.UInt64())
	})
	roots, err := provider.ListRoots(ctx, &query.ListRootsRequest{OrgID: org.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, roots.Rows, 1)
	stored := roots.Rows[0]
	t.Cleanup(func() {
		_, _ = provider.DeleteRoot(ctx, org.ID.UInt64(), stored.ID.UInt64())
	})
	assert.Equal(t, res.Sha256, stored.Sha256)
	assert.Equal(t, res.Skid, stored.Skid)
	assert.Equal(t, pb.Trust_Private, stored.Trust)
	assert.Equal(t, res.Pem, stored.Pem)

	// the certificate of a root that another org registered as its anchor:
	// the anchor conflicts, and the issuer insert is rolled back with it
	shared := testutils.NewTestCA(t, "Shared Root", nil)
	ra, err := provider.RegisterRoot(ctx, model.NewRootCertificate(shared.Cert, other.ID, pb.Trust_Private, testutils.CertPEM(shared.Cert)))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteRoot(ctx, other.ID.UInt64(), ra.ID.UInt64())
	})
	m = newTestIssuer(org.ID, xdb.ID(0), "SHARED", shared, pb.AuthorityType_Root, xdb.ID(0))
	_, err = provider.RegisterIssuer(ctx, m, model.NewRootCertificate(shared.Cert, org.ID, pb.Trust_Private, m.Pem))
	assert.ErrorIs(t, err, db.ErrRootConflict)
	_, err = provider.FindIssuer(ctx, org.ID.UInt64(), 0, "SHARED")
	assert.True(t, xdb.IsNotFoundError(err), "the issuer is not stored: %v", err)
	_, err = provider.GetIssuerBySKID(ctx, certutil.GetSubjectKeyID(shared.Cert))
	assert.True(t, xdb.IsNotFoundError(err), "the issuer is not stored: %v", err)
}

// Test_Issuer_Counts covers the counts of the tenant summary by lifecycle
// status, for the org, a project and the visible projects
func Test_Issuer_Counts(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Issuer_Counts")
	project, err := provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Name: "Counts"})
	require.NoError(t, err)

	root := testutils.NewTestCA(t, "Issuer Counts Root", nil)
	registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "CNT_ORG", testutils.NewTestCA(t, "Issuer Counts L2", root), pb.AuthorityType_Issuing, xdb.ID(0)))
	registerIssuer(t, newTestIssuer(org.ID, project.ID, "CNT_PRJ", testutils.NewTestCA(t, "Issuer Counts L2 Project", root), pb.AuthorityType_Issuing, xdb.ID(0)))
	archived := registerIssuer(t, newTestIssuer(org.ID, project.ID, "CNT_ARCHIVED", testutils.NewTestCA(t, "Issuer Counts L2 Archived", root), pb.AuthorityType_Issuing, xdb.ID(0)))
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{
		ID:     archived.ID.UInt64(),
		OrgID:  org.ID.UInt64(),
		Status: pb.IssuerStatus_Archived,
	})
	require.NoError(t, err)

	orgID := org.ID.UInt64()
	count := func(projectID uint64, projectIDs []uint64) model.IssuerCounts {
		t.Helper()
		res, err := provider.CountIssuers(ctx, &query.CountIssuersRequest{
			OrgID:      orgID,
			ProjectID:  projectID,
			ProjectIDs: projectIDs,
		})
		require.NoError(t, err)
		return res
	}
	active, archivedStatus := pb.IssuerStatus_Active, pb.IssuerStatus_Archived
	assert.Equal(t, model.IssuerCounts{active: 2, archivedStatus: 1}, count(0, nil), "the org")
	assert.Equal(t, model.IssuerCounts{active: 1, archivedStatus: 1}, count(project.ID.UInt64(), nil), "a project")
	assert.Equal(t, model.IssuerCounts{active: 2, archivedStatus: 1}, count(0, []uint64{project.ID.UInt64()}), "the visible projects")
	assert.Equal(t, model.IssuerCounts{active: 1}, count(0, []uint64{}), "the org-wide rows only")
	assert.Equal(t, model.IssuerCounts{active: 1, archivedStatus: 1}, count(project.ID.UInt64(), []uint64{}), "a project takes precedence")
	assert.Empty(t, count(project.ID.UInt64()+1, nil), "a project without issuers")

	_, err = provider.CountIssuers(ctx, &query.CountIssuersRequest{})
	assert.EqualError(t, err, "org ID is required")
}
