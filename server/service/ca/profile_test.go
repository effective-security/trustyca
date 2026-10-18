package ca

import (
	"context"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// storeProfile is the RegisterProfile expectation that stores the row after
// the assertions on it
func storeProfile(tca *testCA, check func(m *model.CertificateProfile)) {
	tca.cadb.EXPECT().RegisterProfile(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.CertificateProfile) (*model.CertificateProfile, error) {
			if check != nil {
				check(m)
			}
			return tca.rows.addProfile(m), nil
		})
}

func TestService_RegisterProfile(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	valid := func() *pb.RegisterProfileRequest {
		return &pb.RegisterProfileRequest{
			ProjectID: "201",
			Profile:   peerProfileDef("server", testIssuerLabel, "24h"),
		}
	}

	_, err := svc.RegisterProfile(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing profile")
	_, err = svc.RegisterProfile(ctx, &pb.RegisterProfileRequest{})
	assert.EqualError(t, err, "bad_request: missing profile")
	noCA := &Service{db: tca.cadb, orgs: tca.orgsdb, authorizer: newFakeAuthorizer()}
	_, err = noCA.RegisterProfile(ctx, valid())
	assert.EqualError(t, err, "unavailable: CA is not configured")
	req := valid()
	req.Profile.Label = " "
	_, err = svc.RegisterProfile(ctx, req)
	assert.EqualError(t, err, "bad_request: missing profile label")
	req.Profile.Label = strings.Repeat("x", model.MaxLenForLabel+1)
	_, err = svc.RegisterProfile(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid profile label length")
	req = valid()
	req.Profile.IssuerLabel = ""
	_, err = svc.RegisterProfile(ctx, req)
	assert.EqualError(t, err, "bad_request: missing issuer label")
	req.Profile.IssuerLabel = strings.Repeat("x", model.MaxLenForLabel+1)
	_, err = svc.RegisterProfile(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid issuer label length")
	req = valid()
	req.Profile.Expiry = ""
	_, err = svc.RegisterProfile(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid profile: no expiry set")
	req = valid()
	req.Profile.AllowedExtensions = []string{"x"}
	_, err = svc.RegisterProfile(ctx, req)
	assert.EqualError(t, err, "bad_request: invalid AllowedExtensions OID: x")
	_, err = svc.RegisterProfile(testCtx("42", ""), valid())
	assert.EqualError(t, err, "forbidden: org not selected")
	req = valid()
	req.ProjectID = "301"
	_, err = svc.RegisterProfile(ctx, req)
	assert.EqualError(t, err, "not_found: project not found")

	storeProfile(tca, func(m *model.CertificateProfile) {
		assert.Equal(t, uint64(1), m.OrgID.UInt64())
		assert.Equal(t, uint64(201), m.ProjectID.UInt64())
		assert.Equal(t, "server", m.Label)
		assert.Equal(t, testIssuerLabel, m.IssuerLabel)
		assert.Equal(t, pb.ItemStatus_Active, m.Status)
		def, err := m.Pb()
		require.NoError(t, err)
		assert.Equal(t, "24h", def.Expiry)
		assert.Equal(t, []string{"2.5.29.17"}, def.AllowedExtensions)
	})
	res, err := svc.RegisterProfile(ctx, valid())
	require.NoError(t, err)
	assert.NotEmpty(t, res.ID)
	assert.Equal(t, "1", res.OrgID)
	assert.Equal(t, "201", res.ProjectID)
	assert.Equal(t, "server", res.Label)
	assert.Equal(t, testIssuerLabel, res.IssuerLabel)
	assert.Equal(t, "24h", res.Expiry)
	assert.Equal(t, pb.ItemStatus_Active, res.Status)
	evt := tca.events.last(pb.EventType_ProfileRegistered)
	require.NotNil(t, evt)
	assert.Equal(t, res.ID, evt.ReferenceID.String())
	assert.Equal(t, uint64(201), evt.ProjectID.UInt64())
	assert.Contains(t, evt.Description.String(), `profile "server" registered for issuer "L2_CA"`)

	// the new project profile is used by the next signing of the project
	before, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), ProjectID: testProject.ID, Profile: testProfile})
	require.NoError(t, err)
	assert.Equal(t, tca.peer.ID.UInt64(), before.ProfileRow.ID.UInt64())
	storeProfile(tca, nil)
	_, err = svc.RegisterProfile(ctx, &pb.RegisterProfileRequest{ProjectID: "201", Profile: peerProfileDef(testProfile, testIssuerLabel, "1h")})
	require.NoError(t, err)
	after, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), ProjectID: testProject.ID, Profile: testProfile})
	require.NoError(t, err)
	assert.NotEqual(t, tca.peer.ID.UInt64(), after.ProfileRow.ID.UInt64())
	assert.Equal(t, uint64(201), after.ProfileRow.ProjectID.UInt64())

	tca.cadb.EXPECT().RegisterProfile(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.RegisterProfile(ctx, valid())
	assert.EqualError(t, err, "unexpected: failed to register profile")
}

func TestService_GetProfile(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	org2Peer := tca.addProfile(xdb.NewID(2), xdb.ID{}, peerProfileDef(testProfile, testIssuerLabel, "1h"))
	platform := tca.addProfile(xdb.ID{}, xdb.ID{}, peerProfileDef("platform", "PROOT", "1h"))

	_, err := svc.GetProfile(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.GetProfile(ctx, &pb.GetProfileRequest{})
	assert.EqualError(t, err, "bad_request: profile ID or label is required")
	_, err = svc.GetProfile(testCtx("42", ""), &pb.GetProfileRequest{Label: testProfile})
	assert.EqualError(t, err, "forbidden: org not selected")

	res, err := svc.GetProfile(ctx, &pb.GetProfileRequest{ID: tca.peer.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, testProfile, res.Label)
	assert.Equal(t, testIssuerLabel, res.IssuerLabel)
	assert.Equal(t, "168h", res.Expiry)
	assert.Equal(t, "1", res.OrgID)
	_, err = svc.GetProfile(ctx, &pb.GetProfileRequest{ID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid profile ID")
	_, err = svc.GetProfile(ctx, &pb.GetProfileRequest{ID: "9999"})
	assert.EqualError(t, err, "not_found: profile not found")
	_, err = svc.GetProfile(ctx, &pb.GetProfileRequest{ID: org2Peer.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found", "a profile of another org")
	_, err = svc.GetProfile(ctx, &pb.GetProfileRequest{ID: platform.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found", "a platform profile")

	res, err = svc.GetProfile(ctx, &pb.GetProfileRequest{Label: testProfile, ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, tca.peer.ID.String(), res.ID, "the org profile serves the project")
	projectPeer := tca.addProfile(testOrgID(), testProject.ID, peerProfileDef(testProfile, testIssuerLabel, "1h"))
	res, err = svc.GetProfile(ctx, &pb.GetProfileRequest{Label: testProfile, ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, projectPeer.ID.String(), res.ID)
	res, err = svc.GetProfile(ctx, &pb.GetProfileRequest{Label: testProfile})
	require.NoError(t, err)
	assert.Equal(t, tca.peer.ID.String(), res.ID)
	_, err = svc.GetProfile(ctx, &pb.GetProfileRequest{Label: "nope"})
	assert.EqualError(t, err, "not_found: profile not found: nope")
	_, err = svc.GetProfile(ctx, &pb.GetProfileRequest{Label: testProfile, ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")
}

func TestService_ProfileProjectAccess(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	admin := testCtx(orgAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")
	projectPeer := tca.addProfile(testOrgID(), testProject.ID, peerProfileDef("prj", testIssuerLabel, "1h"))
	siblingPeer := tca.addProfile(testOrgID(), siblingProject.ID, peerProfileDef("sib", testIssuerLabel, "1h"))
	gonePeer := tca.addProfile(testOrgID(), inactiveProject.ID, peerProfileDef("gone", testIssuerLabel, "1h"))

	// a member with a grant in one project reads the org-wide profiles and
	// those of its project; a profile of another project is not found
	res, err := svc.GetProfile(viewer, &pb.GetProfileRequest{ID: tca.peer.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, testProfile, res.Label)
	res, err = svc.GetProfile(viewer, &pb.GetProfileRequest{ID: projectPeer.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, "201", res.ProjectID)
	_, err = svc.GetProfile(viewer, &pb.GetProfileRequest{ID: siblingPeer.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found")
	_, err = svc.GetProfile(viewer, &pb.GetProfileRequest{ID: gonePeer.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found")
	_, err = svc.GetProfile(admin, &pb.GetProfileRequest{ID: siblingPeer.ID.String()})
	require.NoError(t, err)
	_, err = svc.GetProfile(testCtx(strangerUser, "1"), &pb.GetProfileRequest{ID: tca.peer.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found")
	key := apiKeyCtx("1", "201")
	_, err = svc.GetProfile(key, &pb.GetProfileRequest{ID: tca.peer.ID.String()})
	require.NoError(t, err)
	_, err = svc.GetProfile(key, &pb.GetProfileRequest{ID: siblingPeer.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found")
	_, err = svc.GetProfile(apiKeyCtx("1", ""), &pb.GetProfileRequest{ID: siblingPeer.ID.String()})
	require.NoError(t, err)

	// a list without a project covers the org-wide profiles and the
	// projects of the member's grants
	tca.cadb.EXPECT().ListProfiles(gomock.Any(), &query.ListProfilesRequest{
		OrgID:      1,
		ProjectIDs: []uint64{201},
		Limit:      defaultListLimit,
	}).Return(&model.CertificateProfileResult{Rows: []*model.CertificateProfile{tca.peer, projectPeer}}, nil)
	list, err := svc.ListProfiles(viewer, &pb.ListProfilesRequest{})
	require.NoError(t, err)
	assert.Len(t, list.Profiles, 2)
	tca.cadb.EXPECT().ListProfiles(gomock.Any(), &query.ListProfilesRequest{
		OrgID:     1,
		ProjectID: 201,
		Limit:     defaultListLimit,
	}).Return(&model.CertificateProfileResult{}, nil)
	_, err = svc.ListProfiles(viewer, &pb.ListProfilesRequest{ProjectID: "201"})
	require.NoError(t, err)
	tca.cadb.EXPECT().ListProfiles(gomock.Any(), &query.ListProfilesRequest{
		OrgID:      1,
		ProjectIDs: []uint64{},
		Limit:      defaultListLimit,
	}).Return(&model.CertificateProfileResult{}, nil)
	_, err = svc.ListProfiles(testCtx(strangerUser, "1"), &pb.ListProfilesRequest{})
	require.NoError(t, err)
	tca.cadb.EXPECT().ListProfiles(gomock.Any(), &query.ListProfilesRequest{
		OrgID: 1,
		Limit: defaultListLimit,
	}).Return(&model.CertificateProfileResult{}, nil)
	_, err = svc.ListProfiles(apiKeyCtx("1", ""), &pb.ListProfilesRequest{})
	require.NoError(t, err)

	// a project Admin deletes the profiles of its project only
	projectAdmin := testCtx(projectAdminUser, "1")
	_, err = svc.DeleteProfile(projectAdmin, &pb.DeleteProfileRequest{ID: tca.peer.ID.String()})
	assert.EqualError(t, err, "forbidden: access denied")
	_, err = svc.DeleteProfile(projectAdmin, &pb.DeleteProfileRequest{ID: siblingPeer.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found")
	_, err = svc.DeleteProfile(viewer, &pb.DeleteProfileRequest{ID: projectPeer.ID.String()})
	assert.EqualError(t, err, "forbidden: access denied")
	tca.cadb.EXPECT().DeleteProfile(gomock.Any(), uint64(1), projectPeer.ID.UInt64()).DoAndReturn(tca.rows.deleteProfile)
	_, err = svc.DeleteProfile(projectAdmin, &pb.DeleteProfileRequest{ID: projectPeer.ID.String()})
	require.NoError(t, err)
}

func TestService_ListProfiles(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")

	_, err := svc.ListProfiles(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.ListProfiles(testCtx("42", ""), &pb.ListProfilesRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.ListProfiles(ctx, &pb.ListProfilesRequest{Cursor: "zzz"})
	assert.EqualError(t, err, "bad_request: invalid cursor")

	tca.cadb.EXPECT().ListProfiles(gomock.Any(), &query.ListProfilesRequest{
		OrgID:       1,
		IssuerLabel: testIssuerLabel,
		Limit:       defaultListLimit,
	}).Return(&model.CertificateProfileResult{
		Rows:        []*model.CertificateProfile{tca.peer},
		HasNextPage: true,
		Cursor:      "next",
	}, nil)
	res, err := svc.ListProfiles(ctx, &pb.ListProfilesRequest{IssuerLabel: testIssuerLabel})
	require.NoError(t, err)
	require.Len(t, res.Profiles, 1)
	assert.Equal(t, testProfile, res.Profiles[0].Label)
	assert.Equal(t, "168h", res.Profiles[0].Expiry)
	require.NotNil(t, res.NextPage)
	assert.Equal(t, "next", res.NextPage.Cursor)

	tca.cadb.EXPECT().ListProfiles(gomock.Any(), &query.ListProfilesRequest{
		OrgID:     1,
		ProjectID: 201,
		Limit:     5,
		Offset:    10,
	}).Return(&model.CertificateProfileResult{}, nil)
	res, err = svc.ListProfiles(ctx, &pb.ListProfilesRequest{ProjectID: "201", Limit: 5, Offset: 10})
	require.NoError(t, err)
	assert.Empty(t, res.Profiles)

	tca.cadb.EXPECT().ListProfiles(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.ListProfiles(ctx, &pb.ListProfilesRequest{})
	assert.EqualError(t, err, "unexpected: failed to list profiles")
}

func TestService_DeleteProfile(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	org2Peer := tca.addProfile(xdb.NewID(2), xdb.ID{}, peerProfileDef(testProfile, testIssuerLabel, "1h"))

	_, err := svc.DeleteProfile(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	noCA := &Service{db: tca.cadb, orgs: tca.orgsdb, authorizer: newFakeAuthorizer()}
	_, err = noCA.DeleteProfile(ctx, &pb.DeleteProfileRequest{ID: tca.peer.ID.String()})
	assert.EqualError(t, err, "unavailable: CA is not configured")
	_, err = svc.DeleteProfile(ctx, &pb.DeleteProfileRequest{})
	assert.EqualError(t, err, "bad_request: missing profile ID")
	_, err = svc.DeleteProfile(ctx, &pb.DeleteProfileRequest{ID: "9999"})
	assert.EqualError(t, err, "not_found: profile not found")
	_, err = svc.DeleteProfile(ctx, &pb.DeleteProfileRequest{ID: org2Peer.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found", "a profile of another org")

	// the profile resolves until it is deleted
	_, err = tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testProfile})
	require.NoError(t, err)
	tca.cadb.EXPECT().DeleteProfile(gomock.Any(), uint64(1), tca.peer.ID.UInt64()).DoAndReturn(tca.rows.deleteProfile)
	_, err = svc.DeleteProfile(ctx, &pb.DeleteProfileRequest{ID: tca.peer.ID.String()})
	require.NoError(t, err)
	evt := tca.events.last(pb.EventType_ProfileDeleted)
	require.NotNil(t, evt)
	assert.Equal(t, tca.peer.ID.UInt64(), evt.ReferenceID.UInt64())
	assert.Contains(t, evt.Description.String(), `profile "peer" deleted`)
	_, err = tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testProfile})
	assert.ErrorIs(t, err, core.ErrProfileNotFound, "the deleted profile left the registry at once")

	// a row that is gone by the time of the delete
	other := tca.addProfile(testOrgID(), xdb.ID{}, peerProfileDef("other", testIssuerLabel, "1h"))
	tca.cadb.EXPECT().DeleteProfile(gomock.Any(), uint64(1), other.ID.UInt64()).Return(int64(0), nil)
	_, err = svc.DeleteProfile(ctx, &pb.DeleteProfileRequest{ID: other.ID.String()})
	assert.EqualError(t, err, "not_found: profile not found")
	tca.cadb.EXPECT().DeleteProfile(gomock.Any(), uint64(1), other.ID.UInt64()).Return(int64(0), errors.New("db down"))
	_, err = svc.DeleteProfile(ctx, &pb.DeleteProfileRequest{ID: other.ID.String()})
	assert.EqualError(t, err, "unexpected: failed to delete profile")
}
