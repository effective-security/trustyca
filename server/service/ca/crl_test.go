package ca

import (
	"context"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// crlRow returns the current CRL row of an issuer, as the DB stores it
func crlRow(issuer *model.Issuer, number int64) *model.Crl {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.Crl{
		ID:         xdb.NewID(9000 + uint64(number)),
		OrgID:      ownID(issuer.OrgID),
		ProjectID:  ownID(issuer.ProjectID),
		IssuerID:   ownID(issuer.ID),
		Ikid:       issuer.Skid,
		CrlNumber:  number,
		ThisUpdate: xdb.UTC(now),
		NextUpdate: xdb.UTC(now.Add(48 * time.Hour)),
		Issuer:     issuer.Subject,
		Pem:        "-----BEGIN X509 CRL-----\nMA==\n-----END X509 CRL-----\n",
		CreatedAt:  xdb.UTC(now),
	}
}

func TestService_GetCRL(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	admin := testCtx(orgAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")
	projectIssuer := tca.newChild(t, tca.root, testCAProfile, testOrgID(), testProject.ID, "PRJ", pb.AuthorityType_Issuing, nil)
	sibling := tca.newChild(t, tca.root, testCAProfile, testOrgID(), siblingProject.ID, "SIB", pb.AuthorityType_Issuing, nil)
	org2Root := tca.newRoot(t, xdb.NewID(2), xdb.ID(0), testRootLabel)
	platformRoot := tca.newRoot(t, xdb.ID(0), xdb.ID(0), "PROOT")
	crls := map[string]*model.Crl{}
	for i, issuer := range []*model.Issuer{tca.issuer, projectIssuer, sibling, org2Root, platformRoot} {
		crls[issuer.Skid] = crlRow(issuer, int64(i+1))
	}
	tca.cadb.EXPECT().GetCrl(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, ikid string) (*model.Crl, error) {
			if row, ok := crls[ikid]; ok {
				res := *row
				return &res, nil
			}
			return nil, notFoundErr("crl", ikid)
		}).AnyTimes()

	_, err := svc.GetCRL(admin, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.GetCRL(admin, &pb.GetCrlRequest{})
	assert.EqualError(t, err, "bad_request: missing IKID")
	_, err = svc.GetCRL(testCtx(orgAdminUser, ""), &pb.GetCrlRequest{IKID: tca.issuer.Skid})
	assert.EqualError(t, err, "forbidden: org not selected")

	// a tenant reads the CRLs of its org: org-wide, and of the projects
	// the caller may read
	res, err := svc.GetCRL(admin, &pb.GetCrlRequest{IKID: tca.issuer.Skid})
	require.NoError(t, err)
	require.NotNil(t, res.Crl)
	assert.Equal(t, tca.issuer.Skid, res.Crl.IKID)
	assert.Equal(t, tca.issuer.ID.String(), res.Crl.IssuerID)
	assert.Equal(t, "1", res.Crl.OrgID)
	assert.Equal(t, "1", res.Crl.Number)
	assert.Equal(t, tca.issuer.Subject, res.Crl.Issuer)
	assert.NotEmpty(t, res.Crl.Pem)
	assert.NotEmpty(t, res.Crl.ThisUpdate)
	assert.NotEmpty(t, res.Crl.NextUpdate)
	_, err = svc.GetCRL(admin, &pb.GetCrlRequest{IKID: "nope"})
	assert.EqualError(t, err, "not_found: CRL not found")
	_, err = svc.GetCRL(admin, &pb.GetCrlRequest{IKID: org2Root.Skid})
	assert.EqualError(t, err, "not_found: CRL not found", "the CRL of another org")
	_, err = svc.GetCRL(admin, &pb.GetCrlRequest{IKID: platformRoot.Skid})
	assert.EqualError(t, err, "not_found: CRL not found", "a platform CRL is served by CIS")
	res, err = svc.GetCRL(viewer, &pb.GetCrlRequest{IKID: projectIssuer.Skid})
	require.NoError(t, err)
	assert.Equal(t, "2", res.Crl.Number)
	_, err = svc.GetCRL(viewer, &pb.GetCrlRequest{IKID: sibling.Skid})
	assert.EqualError(t, err, "not_found: CRL not found", "a project without a grant")
	_, err = svc.GetCRL(testCtx(strangerUser, "1"), &pb.GetCrlRequest{IKID: tca.issuer.Skid})
	assert.EqualError(t, err, "not_found: CRL not found")
	_, err = svc.GetCRL(apiKeyCtx("1", "201"), &pb.GetCrlRequest{IKID: sibling.Skid})
	assert.EqualError(t, err, "not_found: CRL not found")
	_, err = svc.GetCRL(apiKeyCtx("1", ""), &pb.GetCrlRequest{IKID: sibling.Skid})
	require.NoError(t, err)

	// a service caller that names no org reads any CRL; one that names
	// the org reads the org's
	cis := serviceCtx("trustyca-cis")
	res, err = svc.GetCRL(cis, &pb.GetCrlRequest{IKID: platformRoot.Skid})
	require.NoError(t, err)
	assert.Equal(t, "5", res.Crl.Number)
	assert.Empty(t, res.Crl.OrgID)
	res, err = svc.GetCRL(cis, &pb.GetCrlRequest{IKID: org2Root.Skid})
	require.NoError(t, err)
	assert.Equal(t, "2", res.Crl.OrgID)
	_, err = svc.GetCRL(cis, &pb.GetCrlRequest{IKID: "nope"})
	assert.EqualError(t, err, "not_found: CRL not found")
	tca.orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil).Times(2)
	res, err = svc.GetCRL(serviceCtx("trustyca-ra"), &pb.GetCrlRequest{OrgID: "1", IKID: sibling.Skid})
	require.NoError(t, err)
	assert.Equal(t, sibling.Skid, res.Crl.IKID)
	_, err = svc.GetCRL(serviceCtx("trustyca-ra"), &pb.GetCrlRequest{OrgID: "1", IKID: org2Root.Skid})
	assert.EqualError(t, err, "not_found: CRL not found")
}

func TestService_GetCRL_DbError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()

	tca.cadb.EXPECT().GetCrl(gomock.Any(), "x").Return(nil, errors.New("db down"))
	_, err := svc.GetCRL(testCtx(orgAdminUser, "1"), &pb.GetCrlRequest{IKID: "x"})
	assert.EqualError(t, err, "unexpected: unable to find CRL")
}

func TestService_PublishCrls(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()

	_, err := svc.PublishCrls(testCtx(orgAdminUser, "1"), nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.PublishCrls(testCtx(orgAdminUser, "1"), &pb.PublishCrlsRequest{})
	assert.EqualError(t, err, "not_implemented: CRL publishing is not implemented")
}
