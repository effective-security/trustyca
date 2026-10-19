package pgsql_test

import (
	"encoding/json"
	"testing"

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

	_, err = provider.RegisterIssuer(ctx, &model.Issuer{OrgID: org.ID, Label: "x"})
	assert.EqualError(t, err, "invalid issuer type")

	// a platform root, an org intermediate and a project issuing CA
	platformLabel := "ROOT_" + certutil.RandomString(8)
	rootIssuer := registerIssuer(t, newTestIssuer(xdb.ID(0), xdb.ID(0), platformLabel, root, pb.AuthorityType_Root, xdb.ID(0)))
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
	_, err = provider.RegisterIssuer(ctx, newTestIssuer(org.ID, xdb.ID(0), "L1", testutils.NewTestCA(t, "Other L1", root), pb.AuthorityType_Intermediate, rootIssuer.ID))
	assert.ErrorContains(t, err, "unique_issuer_org_project_label")
	_, err = provider.RegisterIssuer(ctx, newTestIssuer(org.ID, xdb.ID(0), "L1-copy", l1, pb.AuthorityType_Intermediate, rootIssuer.ID))
	assert.ErrorContains(t, err, "unique_issuer_skid")
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
	})
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
