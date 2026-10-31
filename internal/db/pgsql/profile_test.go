package pgsql_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_Profile(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Profile")
	project, err := provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Name: "CA"})
	require.NoError(t, err)

	def := &pb.CertProfile{
		Label:       "peer",
		IssuerLabel: "L2",
		Expiry:      "168h",
		Backdate:    "30m",
		Usages:      []string{"signing", "server auth", "client auth"},
	}

	_, err = provider.RegisterProfile(ctx, &model.CertificateProfile{OrgID: org.ID})
	assert.EqualError(t, err, "invalid label: required")

	registerProfile := func(orgID, projectID xdb.ID, p *pb.CertProfile) *model.CertificateProfile {
		t.Helper()
		m, err := model.NewCertificateProfile(orgID, projectID, p)
		require.NoError(t, err)
		res, err := provider.RegisterProfile(ctx, m)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = provider.DeleteProfile(ctx, res.OrgID.UInt64(), res.ID.UInt64())
		})
		return res
	}

	orgProfile := registerProfile(org.ID, xdb.ID(0), def)
	assert.Equal(t, pb.ItemStatus_Active, orgProfile.Status)
	assert.Equal(t, "peer", orgProfile.Label)
	assert.Equal(t, "L2", orgProfile.IssuerLabel)
	assert.False(t, orgProfile.CreatedAt.IsZero())
	op, err := orgProfile.Pb()
	require.NoError(t, err)
	assert.Equal(t, "168h", op.Expiry, "jsonb normalizes the document, so the config is compared parsed")
	assert.Equal(t, def.Usages, op.Usages)

	// the same label in the project scope is another profile
	prjProfile := registerProfile(org.ID, project.ID, def)
	assert.NotEqual(t, orgProfile.ID.UInt64(), prjProfile.ID.UInt64())
	assert.Equal(t, project.ID.UInt64(), prjProfile.ProjectID.UInt64())

	// a platform profile for any issuer
	platformLabel := "ocsp_" + certutil.RandomString(8)
	platformProfile := registerProfile(xdb.ID(0), xdb.ID(0), &pb.CertProfile{Label: platformLabel, IssuerLabel: model.AnyIssuerLabel})
	assert.True(t, platformProfile.OrgID.IsZero())

	// registering the label again in the same scope replaces the definition
	def2, ok := proto.Clone(def).(*pb.CertProfile)
	require.True(t, ok)
	def2.IssuerLabel = "L3"
	def2.Expiry = "24h"
	def2.Status = pb.ItemStatus_Inactive
	replaced := registerProfile(org.ID, xdb.ID(0), def2)
	assert.Equal(t, orgProfile.ID.UInt64(), replaced.ID.UInt64(), "the row is kept")
	assert.Equal(t, "L3", replaced.IssuerLabel)
	assert.Equal(t, pb.ItemStatus_Inactive, replaced.Status)
	assert.Equal(t, orgProfile.CreatedAt.UnixMilli(), replaced.CreatedAt.UnixMilli())
	assert.GreaterOrEqual(t, replaced.UpdatedAt.UnixMilli(), orgProfile.UpdatedAt.UnixMilli())
	rp, err := replaced.Pb()
	require.NoError(t, err)
	assert.Equal(t, "24h", rp.Expiry)
	assert.Equal(t, def.Usages, rp.Usages)
	assert.Equal(t, orgProfile.ID.String(), rp.ID)
	assert.Equal(t, org.ID.String(), rp.OrgID)
	assert.Empty(t, rp.ProjectID)

	// get and find by exact scope
	got, err := provider.GetProfile(ctx, prjProfile.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, "L2", got.IssuerLabel)
	_, err = provider.GetProfile(ctx, 1)
	assert.ErrorContains(t, err, "record not found: certificate_profile: 1")

	found, err := provider.FindProfile(ctx, org.ID.UInt64(), 0, "peer")
	require.NoError(t, err)
	assert.Equal(t, orgProfile.ID.UInt64(), found.ID.UInt64())
	found, err = provider.FindProfile(ctx, org.ID.UInt64(), project.ID.UInt64(), "peer")
	require.NoError(t, err)
	assert.Equal(t, prjProfile.ID.UInt64(), found.ID.UInt64())
	_, err = provider.FindProfile(ctx, org.ID.UInt64(), 0, "nope")
	assert.ErrorContains(t, err, "record not found")
	found, err = provider.FindProfile(ctx, 0, 0, platformLabel)
	require.NoError(t, err)
	assert.Equal(t, platformProfile.ID.UInt64(), found.ID.UInt64())
	_, err = provider.FindProfile(ctx, org.ID.UInt64(), 0, platformLabel)
	assert.ErrorContains(t, err, "record not found", "platform profiles are not visible to tenants")

	// list
	list, err := provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	assert.Equal(t, prjProfile.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.Equal(t, orgProfile.ID.UInt64(), list.Rows[1].ID.UInt64())
	res, err := list.Pb()
	require.NoError(t, err)
	require.Len(t, res.Profiles, 2)
	assert.Nil(t, res.NextPage)

	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), Scope: pb.Scope_Org, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgProfile.ID.UInt64(), list.Rows[0].ID.UInt64())

	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), ProjectID: project.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, prjProfile.ID.UInt64(), list.Rows[0].ID.UInt64())

	// the org-wide rows and the rows of the caller's projects
	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), ProjectIDs: []uint64{project.ID.UInt64()}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), ProjectIDs: []uint64{}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgProfile.ID.UInt64(), list.Rows[0].ID.UInt64(), "no project grant: the org-wide rows only")

	// the profiles of a page of certificates: by ID and by label, in every
	// scope the request covers
	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), IDs: []uint64{orgProfile.ID.UInt64(), 1}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgProfile.ID.UInt64(), list.Rows[0].ID.UInt64())
	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), Labels: []string{orgProfile.Label, "nope"}, Limit: 10})
	require.NoError(t, err)
	require.NotEmpty(t, list.Rows)
	for _, row := range list.Rows {
		assert.Equal(t, orgProfile.Label, row.Label)
	}
	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), Labels: []string{"nope"}, Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, list.Rows)

	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), IssuerLabel: "L3", Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgProfile.ID.UInt64(), list.Rows[0].ID.UInt64())

	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), Status: pb.ItemStatus_Active, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, prjProfile.ID.UInt64(), list.Rows[0].ID.UInt64())

	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{Platform: true, Limit: 500})
	require.NoError(t, err)
	var platformIDs []uint64
	for _, r := range list.Rows {
		assert.True(t, r.OrgID.IsZero())
		platformIDs = append(platformIDs, r.ID.UInt64())
	}
	assert.Contains(t, platformIDs, platformProfile.ID.UInt64())
	_, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{Limit: 10})
	assert.ErrorIs(t, err, db.ErrOrgScopeRequired)

	// cursor pagination
	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), Limit: 1, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, prjProfile.ID.UInt64(), list.Rows[0].ID.UInt64())
	require.True(t, list.HasNextPage)
	next, err := query.ParseCursor(list.Cursor)
	require.NoError(t, err)
	list, err = provider.ListProfiles(ctx, &query.ListProfilesRequest{OrgID: org.ID.UInt64(), Limit: 1, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgProfile.ID.UInt64(), list.Rows[0].ID.UInt64())

	// delete is scoped by org
	n, err := provider.DeleteProfile(ctx, 0, prjProfile.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n, "a tenant profile is not a platform profile")
	n, err = provider.DeleteProfile(ctx, org.ID.UInt64(), prjProfile.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	n, err = provider.DeleteProfile(ctx, org.ID.UInt64(), prjProfile.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	_, err = provider.GetProfile(ctx, prjProfile.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
}
