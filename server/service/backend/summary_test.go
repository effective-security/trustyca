package backend

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// summaryReq matches the summary request of a scope with the expiry
// buckets and the CRL statuses of the summary after a recent time
func summaryReq(orgID, projectID uint64, projectIDs []uint64) gomock.Matcher {
	return gomock.Cond(func(x any) bool {
		req, ok := x.(*query.SummaryRequest)
		if !ok {
			return false
		}
		return req.OrgID == orgID && req.ProjectID == projectID &&
			assert.ObjectsAreEqual(projectIDs, req.ProjectIDs) &&
			assert.ObjectsAreEqual(expiryBuckets, req.Expiring) &&
			assert.ObjectsAreEqual(core.CrlStatuses, req.CrlStatuses) &&
			time.Since(req.Now) < time.Minute
	})
}

// crlState returns the state of an issuer that publishes CRLs, valid for a
// year, with the next update of its CRL; zero for an issuer without one
func crlState(id uint64, label string, nextUpdate time.Time) *model.CrlState {
	m := &model.CrlState{
		ID:       xdb.NewID(id),
		Label:    label,
		Skid:     label,
		NotAfter: xdb.UTC(time.Now().Add(365 * 24 * time.Hour)),
	}
	if !nextUpdate.IsZero() {
		m.NextUpdate = xdb.UTC(nextUpdate)
	}
	return m
}

// issuerLine renders the issuer counts of a summary
func issuerLine(counts []*pb.IssuerStatusCount) string {
	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", c.Status, c.Count))
	}
	return strings.Join(parts, " ")
}

// certLine renders the certificate counts of a summary
func certLine(counts []*pb.CertificateStatusCount) string {
	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", c.Status, c.Count))
	}
	return strings.Join(parts, " ")
}

// expiringLine renders the expiry buckets of a summary
func expiringLine(buckets []*pb.ExpiryBucket) string {
	parts := make([]string, 0, len(buckets))
	for _, b := range buckets {
		parts = append(parts, fmt.Sprintf("%d=%d", b.Days, b.Count))
	}
	return strings.Join(parts, " ")
}

// crlLine renders the CRL counts of a summary
func crlLine(c *pb.CrlCounts) string {
	return fmt.Sprintf("%d: current %d, due %d, overdue %d, missing %d", c.Issuers, c.Current, c.Due, c.Overdue, c.Missing)
}

func TestService_GetSummary(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	// the summary reads the tables only: a backend without a registry
	// serves it
	svc := tca.noCA()
	admin := testCtx(orgAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")
	now := time.Now()

	// the states the DB reads for the org: a current CRL, one due within
	// the renewal period, an overdue one, an issuer without one
	orgStates := []*model.CrlState{
		crlState(1, "current", now.Add(48*time.Hour)),
		crlState(2, "due", now.Add(time.Hour)),
		crlState(3, "overdue", now.Add(-time.Minute)),
		crlState(4, "missing", time.Time{}),
	}
	counts := func(states ...*model.CrlState) *model.SummaryCounts {
		return &model.SummaryCounts{
			Issuers: model.IssuerCounts{
				pb.IssuerStatus_Pending: 1,
				pb.IssuerStatus_Active:  4,
			},
			Certificates: &model.CertificateCounts{
				ByStatus: map[pb.CertificateStatus_Enum]uint64{
					pb.CertificateStatus_Active:  10,
					pb.CertificateStatus_Revoked: 2,
				},
				Expiring: []uint64{1, 3, 7},
			},
			CrlStates: states,
		}
	}

	_, err := svc.GetSummary(admin, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.GetSummary(testCtx(orgAdminUser, ""), &privpb.GetSummaryRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.GetSummary(admin, &privpb.GetSummaryRequest{ProjectID: "abc"})
	assert.EqualError(t, err, "bad_request: invalid project ID")
	_, err = svc.GetSummary(admin, &privpb.GetSummaryRequest{ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found", "a project of another org")
	_, err = svc.GetSummary(admin, &privpb.GetSummaryRequest{ProjectID: "203"})
	assert.EqualError(t, err, "not_found: project not found", "an inactive project")

	// the org of an org-wide role: no project filter, every status and
	// bucket reported, the CRL states classified
	tca.cadb.EXPECT().GetSummaryCounts(gomock.Any(), summaryReq(1, 0, nil)).Return(counts(orgStates...), nil)
	res, err := svc.GetSummary(admin, &privpb.GetSummaryRequest{})
	require.NoError(t, err)
	at, err := time.Parse(time.RFC3339, res.At)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), at, time.Minute)
	assert.Equal(t, "Pending=1 Active=4 Archived=0 Destroyed=0", issuerLine(res.Issuers))
	assert.Equal(t, "Active=10 Expired=0 Revoked=2", certLine(res.Certificates))
	assert.Equal(t, "7=1 30=3 90=7", expiringLine(res.Expiring))
	assert.Equal(t, "4: current 1, due 1, overdue 1, missing 1", crlLine(res.Crls))

	// a member with project grants only asks for the org-wide rows and its
	// projects; a scope without rows reports zero everywhere
	tca.cadb.EXPECT().GetSummaryCounts(gomock.Any(), summaryReq(1, 0, []uint64{201})).Return(&model.SummaryCounts{Certificates: &model.CertificateCounts{}}, nil)
	res, err = svc.GetSummary(viewer, &privpb.GetSummaryRequest{})
	require.NoError(t, err)
	assert.Equal(t, "Pending=0 Active=0 Archived=0 Destroyed=0", issuerLine(res.Issuers))
	assert.Equal(t, "Active=0 Expired=0 Revoked=0", certLine(res.Certificates))
	assert.Equal(t, "7=0 30=0 90=0", expiringLine(res.Expiring), "the buckets are reported without counts")
	assert.Equal(t, "0: current 0, due 0, overdue 0, missing 0", crlLine(res.Crls))

	// a project, for an org-wide role, a member of the project and an API
	// key restricted to it
	tca.cadb.EXPECT().GetSummaryCounts(gomock.Any(), summaryReq(1, 201, nil)).Return(counts(orgStates[2]), nil).Times(3)
	for _, c := range []struct {
		ctx context.Context
		req *privpb.GetSummaryRequest
	}{
		{admin, &privpb.GetSummaryRequest{ProjectID: "201"}},
		{viewer, &privpb.GetSummaryRequest{ProjectID: "201"}},
		{apiKeyCtx("1", "201"), &privpb.GetSummaryRequest{}},
	} {
		res, err = svc.GetSummary(c.ctx, c.req)
		require.NoError(t, err)
		assert.Equal(t, "1: current 0, due 0, overdue 1, missing 0", crlLine(res.Crls))
	}

	// an org-wide API key, and a service caller that names the org
	tca.cadb.EXPECT().GetSummaryCounts(gomock.Any(), summaryReq(1, 0, nil)).Return(counts(orgStates...), nil).Times(2)
	res, err = svc.GetSummary(apiKeyCtx("1", ""), &privpb.GetSummaryRequest{})
	require.NoError(t, err)
	assert.Equal(t, "4: current 1, due 1, overdue 1, missing 1", crlLine(res.Crls))
	tca.orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	res, err = svc.GetSummary(serviceCtx("trustyca-ra"), &privpb.GetSummaryRequest{OrgID: "1"})
	require.NoError(t, err)
	assert.Equal(t, "4: current 1, due 1, overdue 1, missing 1", crlLine(res.Crls))
	_, err = svc.GetSummary(operatorCtx("1"), &privpb.GetSummaryRequest{})
	assert.EqualError(t, err, "bad_request: org ID is required", "the org of the operator's token is not its scope")

	// a failure of the reads, and an issuer whose settings do not parse
	tca.cadb.EXPECT().GetSummaryCounts(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.GetSummary(admin, &privpb.GetSummaryRequest{})
	assert.EqualError(t, err, "unexpected: failed to read the summary")
	bad := crlState(5, "bad", now.Add(48*time.Hour))
	bad.Config, err = model.MarshalJSONValue(&pb.IssuerConfig{CrlRenewal: "x"})
	require.NoError(t, err)
	tca.cadb.EXPECT().GetSummaryCounts(gomock.Any(), gomock.Any()).Return(counts(bad), nil)
	_, err = svc.GetSummary(admin, &privpb.GetSummaryRequest{})
	assert.EqualError(t, err, "invalid_request: failed to count CRLs", "the settings of the row are the error, as the lists report it")
}

// TestService_GetSummary_CheckAccess runs the access check of the
// interceptor on the summary: a Viewer at the org or at the project of the
// request, an API key with ca:read in its project
func TestService_GetSummary_CheckAccess(t *testing.T) {
	t.Parallel()
	authorizer := newFakeAuthorizer()
	const method = pb.CA_GetSummary_FullMethodName
	admin := testCtx(orgAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")

	err := authctx.CheckAccess(admin, authorizer, &privpb.GetSummaryRequest{}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(admin, authorizer, &privpb.GetSummaryRequest{ProjectID: "202"}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(viewer, authorizer, &privpb.GetSummaryRequest{}, method)
	require.NoError(t, err, "a member with project grants only is a Viewer at org scope")
	err = authctx.CheckAccess(viewer, authorizer, &privpb.GetSummaryRequest{ProjectID: "201"}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(viewer, authorizer, &privpb.GetSummaryRequest{ProjectID: "202"}, method)
	assert.ErrorContains(t, err, "forbidden: ", "a project without a grant")
	err = authctx.CheckAccess(viewer, authorizer, &pb.GetSummaryRequest{ProjectID: "202"}, method)
	assert.ErrorContains(t, err, "forbidden: ", "the public request names the same scope")
	err = authctx.CheckAccess(testCtx(strangerUser, "1"), authorizer, &privpb.GetSummaryRequest{}, method)
	assert.ErrorContains(t, err, "forbidden: ")

	err = authctx.CheckAccess(apiKeyScopedCtx("1", "", "certs:read"), authorizer, &privpb.GetSummaryRequest{}, method)
	assert.ErrorContains(t, err, "forbidden: insufficient scope", "a key without ca:read")
	err = authctx.CheckAccess(apiKeyCtx("1", ""), authorizer, &privpb.GetSummaryRequest{}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(apiKeyCtx("1", "201"), authorizer, &privpb.GetSummaryRequest{}, method)
	require.NoError(t, err, "a restricted key acts in its project")
	err = authctx.CheckAccess(apiKeyCtx("1", "201"), authorizer, &privpb.GetSummaryRequest{ProjectID: "202"}, method)
	assert.ErrorContains(t, err, "forbidden: project mismatch")
}

// the requests name the project the interceptor authorizes
var (
	_ authctx.ProjectRequester = (*pb.GetSummaryRequest)(nil)
	_ authctx.ProjectRequester = (*privpb.GetSummaryRequest)(nil)
)
