package backend

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/trustyca/privpb"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// certStore holds the certificate rows the mock DB serves to the
// certificate methods, and revokes them as the DB does: the revocation and
// the status change together
type certStore struct {
	mu      sync.Mutex
	nextID  uint64
	rows    map[uint64]*model.Certificate
	revoked map[uint64]*model.Revoked
}

func newCertStore() *certStore {
	return &certStore{
		nextID:  7000,
		rows:    map[uint64]*model.Certificate{},
		revoked: map[uint64]*model.Revoked{},
	}
}

// add stores the certificate signed by the issuing CA of the tests in the
// scope with the label; the row gets an ID of the store
func (s *certStore) add(tca *testCA, crt *x509.Certificate, orgID, projectID xdb.ID, label string) *model.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	m := model.NewCertificate(crt, ownID(orgID), ownID(projectID), testProfile, testutils.CertPEM(crt), tca.issuer.Pem, label, nil, nil)
	m.ID = xdb.NewID(s.nextID)
	s.rows[m.ID.UInt64()] = m
	res := *m
	return &res
}

func (s *certStore) get(_ context.Context, id uint64) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.rows[id]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("certificate", id)
}

func (s *certStore) getBySha256(_ context.Context, sha256 string) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.rows {
		if m.Sha256 == sha256 {
			res := *m
			return &res, nil
		}
	}
	return nil, notFoundErr("certificate", sha256)
}

func (s *certStore) getByIssuerSerial(_ context.Context, ikid, serial string) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.rows {
		if m.Ikid == ikid && m.SerialNumber == serial {
			res := *m
			return &res, nil
		}
	}
	return nil, notFoundErr("certificate", fmt.Sprintf("%s/%s", ikid, serial))
}

// list serves the org, project, visible projects, SKID and limit of the
// request, newest first
func (s *certStore) list(_ context.Context, req *query.ListCertificatesRequest) (*model.CertificateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res model.CertificateResult
	for _, m := range s.rows {
		switch {
		case m.OrgID.UInt64() != req.OrgID:
		case req.ProjectID != 0 && m.ProjectID.UInt64() != req.ProjectID:
		case req.ProjectID == 0 && req.ProjectIDs != nil && !m.ProjectID.IsZero() && !slices.Contains(req.ProjectIDs, m.ProjectID.UInt64()):
		case req.SKID != "" && m.Skid != req.SKID:
		default:
			row := *m
			res.Rows = append(res.Rows, &row)
		}
	}
	slices.SortFunc(res.Rows, func(a, b *model.Certificate) int {
		return int(b.ID.UInt64()) - int(a.ID.UInt64())
	})
	if req.Limit != 0 && uint32(len(res.Rows)) > req.Limit {
		res.Rows = res.Rows[:req.Limit]
		res.HasNextPage = true
	}
	return &res, nil
}

func (s *certStore) revoke(_ context.Context, req *query.RevokeCertificateRequest) (*model.RevokedCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.rows[req.CertificateID]
	if !ok || m.OrgID.UInt64() != req.OrgID {
		return nil, notFoundErr("certificate", req.CertificateID)
	}
	if m.Status == pb.CertificateStatus_Revoked {
		return nil, errors.WithStack(db.ErrAlreadyRevoked)
	}
	m.Status = pb.CertificateStatus_Revoked
	s.nextID++
	r := &model.Revoked{
		ID:            xdb.NewID(s.nextID),
		OrgID:         m.OrgID,
		ProjectID:     m.ProjectID,
		CertificateID: m.ID,
		Ikid:          m.Ikid,
		SerialNumber:  m.SerialNumber,
		NotAfter:      m.NotAfter,
		RevokedAt:     xdb.UTC(req.RevokedAt),
		Reason:        req.Reason,
		ReasonText:    req.ReasonText,
	}
	s.revoked[m.ID.UInt64()] = r
	return model.NewRevokedCertificate(m, r), nil
}

// setSKID gives a stored certificate the key identifier of another one,
// as a certificate renewed for the same key has
func (s *certStore) setSKID(id xdb.ID, skid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[id.UInt64()].Skid = skid
}

func (s *certStore) update(_ context.Context, req *query.UpdateCertificateRequest) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.rows[req.ID]
	if !ok || m.OrgID.UInt64() != req.OrgID {
		return nil, notFoundErr("certificate", req.ID)
	}
	if req.Label != nil {
		m.Label = *req.Label
	}
	if req.Metadata != nil {
		m.Metadata = req.Metadata
	}
	res := *m
	return &res, nil
}

// serve makes the mock DB serve the store for every read and mutation of
// the certificate methods
func (s *certStore) serve(cadb *mocktrustycadb.MockCaDb) {
	cadb.EXPECT().GetCertificate(gomock.Any(), gomock.Any()).DoAndReturn(s.get).AnyTimes()
	cadb.EXPECT().GetCertificateBySha256(gomock.Any(), gomock.Any()).DoAndReturn(s.getBySha256).AnyTimes()
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(s.getByIssuerSerial).AnyTimes()
	cadb.EXPECT().ListCertificates(gomock.Any(), gomock.Any()).DoAndReturn(s.list).AnyTimes()
	cadb.EXPECT().RevokeCertificate(gomock.Any(), gomock.Any()).DoAndReturn(s.revoke).AnyTimes()
	cadb.EXPECT().UpdateCertificate(gomock.Any(), gomock.Any()).DoAndReturn(s.update).AnyTimes()
}

func TestService_GetCertificate(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	store := newCertStore()
	store.serve(tca.cadb)
	ctx := testCtx(orgAdminUser, "1")

	orgCert := store.add(tca, tca.sign(t, "org.example.com"), testOrgID(), xdb.ID(0), "org")
	projectCert := store.add(tca, tca.sign(t, "prj.example.com"), testOrgID(), testProject.ID, "prj")
	siblingCert := store.add(tca, tca.sign(t, "sib.example.com"), testOrgID(), siblingProject.ID, "sib")
	goneCert := store.add(tca, tca.sign(t, "gone.example.com"), testOrgID(), inactiveProject.ID, "gone")
	foreignCert := store.add(tca, tca.sign(t, "foreign.example.com"), xdb.NewID(2), xdb.ID(0), "foreign")

	_, err := svc.GetCertificate(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{})
	assert.EqualError(t, err, "bad_request: certificate ID, SKID, SHA-256 or issuer serial is required")
	_, err = svc.GetCertificate(testCtx(orgAdminUser, ""), &privpb.GetCertificateRequest{ID: orgCert.ID.String()})
	assert.EqualError(t, err, "forbidden: org not selected")

	// by ID
	res, err := svc.GetCertificate(ctx, &privpb.GetCertificateRequest{ID: orgCert.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, orgCert.ID.String(), res.Certificate.ID)
	assert.Equal(t, "1", res.Certificate.OrgID)
	assert.Empty(t, res.Certificate.ProjectID)
	assert.Equal(t, orgCert.Sha256, res.Certificate.Sha256)
	assert.Equal(t, orgCert.Pem, res.Certificate.Pem)
	assert.Equal(t, tca.issuer.Skid, res.Certificate.IKID)
	assert.Equal(t, pb.CertificateStatus_Active, res.Certificate.Status)
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{ID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid certificate ID")
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{ID: "9999"})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{ID: foreignCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found", "a certificate of another org")
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{ID: goneCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found", "an inactive project hides its rows")

	// by thumbprint, and by issuer and serial number
	res, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{Sha256: projectCert.Sha256})
	require.NoError(t, err)
	assert.Equal(t, projectCert.ID.String(), res.Certificate.ID)
	assert.Equal(t, "201", res.Certificate.ProjectID)
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{Sha256: "nope"})
	assert.EqualError(t, err, "not_found: certificate not found")
	res, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{IssuerSerial: &pb.IssuerSerial{IKID: siblingCert.Ikid, SerialNumber: siblingCert.SerialNumber}})
	require.NoError(t, err)
	assert.Equal(t, siblingCert.ID.String(), res.Certificate.ID)
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{IssuerSerial: &pb.IssuerSerial{IKID: siblingCert.Ikid}})
	assert.EqualError(t, err, "bad_request: issuer key ID and serial number are required")
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{IssuerSerial: &pb.IssuerSerial{IKID: siblingCert.Ikid, SerialNumber: "1"}})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{IssuerSerial: &pb.IssuerSerial{}})
	assert.EqualError(t, err, "bad_request: certificate ID, SKID, SHA-256 or issuer serial is required", "an empty issuer serial selects nothing")

	// by SKID: the newest certificate of the key
	res, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{SKID: orgCert.Skid})
	require.NoError(t, err)
	assert.Equal(t, orgCert.ID.String(), res.Certificate.ID)
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{SKID: "nope"})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{SKID: foreignCert.Skid})
	assert.EqualError(t, err, "not_found: certificate not found", "another org's key")

	// a member with a grant in one project reads the org-wide certificates
	// and those of its project; one of another project is not found by any
	// selector
	viewer := testCtx(projectViewerUser, "1")
	_, err = svc.GetCertificate(viewer, &privpb.GetCertificateRequest{ID: orgCert.ID.String()})
	require.NoError(t, err)
	_, err = svc.GetCertificate(viewer, &privpb.GetCertificateRequest{ID: projectCert.ID.String()})
	require.NoError(t, err)
	_, err = svc.GetCertificate(viewer, &privpb.GetCertificateRequest{ID: siblingCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(viewer, &privpb.GetCertificateRequest{Sha256: siblingCert.Sha256})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(viewer, &privpb.GetCertificateRequest{SKID: siblingCert.Skid})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(viewer, &privpb.GetCertificateRequest{IssuerSerial: &pb.IssuerSerial{IKID: siblingCert.Ikid, SerialNumber: siblingCert.SerialNumber}})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(testCtx(strangerUser, "1"), &privpb.GetCertificateRequest{ID: orgCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found", "a member without a grant")

	// an API key restricted to a project reads the org-wide certificates
	// and those of its project; an org-wide key reads every project
	key := apiKeyCtx("1", "201")
	_, err = svc.GetCertificate(key, &privpb.GetCertificateRequest{ID: orgCert.ID.String()})
	require.NoError(t, err)
	res, err = svc.GetCertificate(key, &privpb.GetCertificateRequest{SKID: projectCert.Skid})
	require.NoError(t, err)
	assert.Equal(t, projectCert.ID.String(), res.Certificate.ID)
	res, err = svc.GetCertificate(key, &privpb.GetCertificateRequest{SKID: orgCert.Skid})
	require.NoError(t, err)
	assert.Equal(t, orgCert.ID.String(), res.Certificate.ID, "an org-wide certificate by SKID, as by ID")
	_, err = svc.GetCertificate(key, &privpb.GetCertificateRequest{ID: siblingCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(key, &privpb.GetCertificateRequest{SKID: siblingCert.Skid})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.GetCertificate(apiKeyCtx("1", ""), &privpb.GetCertificateRequest{ID: siblingCert.ID.String()})
	require.NoError(t, err)

	// a service caller names the org
	tca.orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	res, err = svc.GetCertificate(serviceCtx("trustyca-ra"), &privpb.GetCertificateRequest{OrgID: "1", ID: siblingCert.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, siblingCert.ID.String(), res.Certificate.ID)
	_, err = svc.GetCertificate(serviceCtx("trustyca-ra"), &privpb.GetCertificateRequest{ID: siblingCert.ID.String()})
	assert.EqualError(t, err, "bad_request: org ID is required")
}

func TestService_GetCertificate_DbError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx(orgAdminUser, "1")

	tca.cadb.EXPECT().GetCertificate(gomock.Any(), uint64(5)).Return(nil, errors.New("db down"))
	_, err := svc.GetCertificate(ctx, &privpb.GetCertificateRequest{ID: "5"})
	assert.EqualError(t, err, "unexpected: unable to find certificate")
	tca.cadb.EXPECT().ListCertificates(gomock.Any(), &query.ListCertificatesRequest{OrgID: 1, SKID: "s", Limit: 1}).Return(nil, errors.New("db down"))
	_, err = svc.GetCertificate(ctx, &privpb.GetCertificateRequest{SKID: "s"})
	assert.EqualError(t, err, "unexpected: unable to find certificate")
	// a key restricted to a project looks the SKID up among the org-wide
	// rows and those of its project
	tca.cadb.EXPECT().ListCertificates(gomock.Any(), &query.ListCertificatesRequest{OrgID: 1, ProjectIDs: []uint64{201}, SKID: "s", Limit: 1}).Return(&model.CertificateResult{}, nil)
	_, err = svc.GetCertificate(apiKeyCtx("1", "201"), &privpb.GetCertificateRequest{SKID: "s"})
	assert.EqualError(t, err, "not_found: certificate not found")
}

func TestService_ListCertificates(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	admin := testCtx(orgAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")
	crt := store(t, tca, "list.example.com", testProject.ID)
	expiring := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	_, err := svc.ListCertificates(admin, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.ListCertificates(testCtx(orgAdminUser, ""), &privpb.ListCertificatesRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.ListCertificates(admin, &privpb.ListCertificatesRequest{Cursor: "bad"})
	assert.EqualError(t, err, "bad_request: invalid cursor")
	_, err = svc.ListCertificates(admin, &privpb.ListCertificatesRequest{ExpiringBefore: "tomorrow"})
	assert.EqualError(t, err, "bad_request: invalid ExpiringBefore: RFC3339 time expected")
	_, err = svc.ListCertificates(admin, &privpb.ListCertificatesRequest{ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")

	// an org-wide role lists every project with the filters of the request
	tca.cadb.EXPECT().ListCertificates(gomock.Any(), &query.ListCertificatesRequest{
		OrgID:          1,
		IKID:           tca.issuer.Skid,
		Profile:        testProfile,
		Status:         pb.CertificateStatus_Active,
		ExpiringBefore: &expiring,
		Limit:          5,
		Offset:         10,
	}).Return(&model.CertificateResult{Rows: []*model.Certificate{crt}, HasNextPage: true, NextOffset: 15}, nil)
	res, err := svc.ListCertificates(admin, &privpb.ListCertificatesRequest{
		IKID:           tca.issuer.Skid,
		Profile:        testProfile,
		Status:         pb.CertificateStatus_Active,
		ExpiringBefore: expiring.Format(time.RFC3339),
		Limit:          5,
		Offset:         10,
	})
	require.NoError(t, err)
	require.Len(t, res.Certificates, 1)
	assert.Equal(t, crt.ID.String(), res.Certificates[0].ID)
	require.NotNil(t, res.NextPage)
	assert.Equal(t, uint32(15), res.NextPage.Offset)

	// a member with project grants only lists the org-wide rows and its
	// projects; a project of the request is listed alone
	tca.cadb.EXPECT().ListCertificates(gomock.Any(), &query.ListCertificatesRequest{
		OrgID:      1,
		ProjectIDs: []uint64{201},
		Limit:      defaultListLimit,
	}).Return(&model.CertificateResult{}, nil)
	res, err = svc.ListCertificates(viewer, &privpb.ListCertificatesRequest{})
	require.NoError(t, err)
	assert.Empty(t, res.Certificates)
	assert.Nil(t, res.NextPage)
	tca.cadb.EXPECT().ListCertificates(gomock.Any(), &query.ListCertificatesRequest{
		OrgID:     1,
		ProjectID: 201,
		Limit:     defaultListLimit,
	}).Return(&model.CertificateResult{}, nil)
	_, err = svc.ListCertificates(viewer, &privpb.ListCertificatesRequest{ProjectID: "201"})
	require.NoError(t, err)

	// an API key restricted to a project lists its project
	tca.cadb.EXPECT().ListCertificates(gomock.Any(), &query.ListCertificatesRequest{
		OrgID:     1,
		ProjectID: 201,
		Limit:     defaultListLimit,
	}).Return(&model.CertificateResult{}, nil)
	_, err = svc.ListCertificates(apiKeyCtx("1", "201"), &privpb.ListCertificatesRequest{})
	require.NoError(t, err)

	tca.cadb.EXPECT().ListCertificates(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.ListCertificates(admin, &privpb.ListCertificatesRequest{})
	assert.EqualError(t, err, "unexpected: failed to list certificates")
}

func TestService_UpdateCertificateLabel(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	store := newCertStore()
	store.serve(tca.cadb)
	admin := testCtx(orgAdminUser, "1")
	orgCert := store.add(tca, tca.sign(t, "org.example.com"), testOrgID(), xdb.ID(0), "org")
	projectCert := store.add(tca, tca.sign(t, "prj.example.com"), testOrgID(), testProject.ID, "prj")

	_, err := svc.UpdateCertificateLabel(admin, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Label: string(make([]byte, model.MaxLenForName+1))})
	assert.EqualError(t, err, "bad_request: invalid label length")
	_, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{})
	assert.EqualError(t, err, "bad_request: missing certificate ID")
	_, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ID: "9999", Label: "x"})
	assert.EqualError(t, err, "not_found: certificate not found")

	// the label is replaced and the metadata kept when the request has none
	res, err := svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Label: "renamed"})
	require.NoError(t, err)
	assert.Equal(t, "renamed", res.Certificate.Label)
	assert.Empty(t, res.Certificate.Metadata)
	res, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Label: "renamed", Metadata: map[string]string{"team": "edge"}})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"team": "edge"}, res.Certificate.Metadata)
	res, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Label: ""})
	require.NoError(t, err)
	assert.Empty(t, res.Certificate.Label, "an empty label clears it")
	assert.Equal(t, map[string]string{"team": "edge"}, res.Certificate.Metadata, "the metadata is kept")
	res, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Metadata: map[string]string{}})
	require.NoError(t, err)
	assert.Empty(t, res.Certificate.Metadata, "an empty metadata clears it")

	// a project Viewer reads but does not change; a project Admin changes
	// the certificates of its project only
	_, err = svc.UpdateCertificateLabel(testCtx(projectViewerUser, "1"), &privpb.UpdateCertificateLabelRequest{ID: projectCert.ID.String(), Label: "x"})
	assert.EqualError(t, err, "forbidden: access denied")
	projectAdmin := testCtx(projectAdminUser, "1")
	_, err = svc.UpdateCertificateLabel(projectAdmin, &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Label: "x"})
	assert.EqualError(t, err, "forbidden: access denied")
	res, err = svc.UpdateCertificateLabel(projectAdmin, &privpb.UpdateCertificateLabelRequest{ID: projectCert.ID.String(), Label: "x"})
	require.NoError(t, err)
	assert.Equal(t, "x", res.Certificate.Label)
	// an API key restricted to the project changes its project's
	// certificates; it reads an org-wide certificate but may not change it
	res, err = svc.UpdateCertificateLabel(apiKeyCtx("1", "201"), &privpb.UpdateCertificateLabelRequest{ID: projectCert.ID.String(), Label: "key"})
	require.NoError(t, err)
	assert.Equal(t, "key", res.Certificate.Label)
	_, err = svc.UpdateCertificateLabel(apiKeyCtx("1", "202"), &privpb.UpdateCertificateLabelRequest{ID: projectCert.ID.String(), Label: "key"})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.UpdateCertificateLabel(apiKeyCtx("1", "201"), &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Label: "key"})
	assert.EqualError(t, err, "forbidden: access denied")
	_, err = svc.GetCertificate(apiKeyCtx("1", "201"), &privpb.GetCertificateRequest{ID: orgCert.ID.String()})
	require.NoError(t, err)
	res, err = svc.UpdateCertificateLabel(apiKeyCtx("1", ""), &privpb.UpdateCertificateLabelRequest{ID: orgCert.ID.String(), Label: "org-key"})
	require.NoError(t, err)
	assert.Equal(t, "org-key", res.Certificate.Label, "an org-wide key")

	// the project of the request is the certificate's: the interceptor
	// authorized that scope
	res, err = svc.UpdateCertificateLabel(projectAdmin, &privpb.UpdateCertificateLabelRequest{ProjectID: "201", ID: projectCert.ID.String(), Label: "scoped"})
	require.NoError(t, err)
	assert.Equal(t, "scoped", res.Certificate.Label)
	_, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ProjectID: "202", ID: projectCert.ID.String(), Label: "x"})
	assert.EqualError(t, err, "not_found: certificate not found", "a certificate of another project")
	_, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ProjectID: "201", ID: orgCert.ID.String(), Label: "x"})
	assert.EqualError(t, err, "not_found: certificate not found", "an org-wide certificate is not the project's")
	_, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ProjectID: "301", ID: projectCert.ID.String(), Label: "x"})
	assert.EqualError(t, err, "not_found: project not found")
	_, err = svc.UpdateCertificateLabel(admin, &privpb.UpdateCertificateLabelRequest{ProjectID: "bad", ID: projectCert.ID.String(), Label: "x"})
	assert.EqualError(t, err, "bad_request: invalid project ID")
}

// TestService_CertificateMutations_CheckAccess runs the authorization of
// the interceptor on the two certificate mutations: a member whose role is
// granted in a project only passes when the request names that project,
// which is the scope the interceptor authorizes
func TestService_CertificateMutations_CheckAccess(t *testing.T) {
	t.Parallel()
	authorizer := newFakeAuthorizer()
	projectAdmin := testCtx(projectAdminUser, "1")
	admin := testCtx(orgAdminUser, "1")

	err := authctx.CheckAccess(projectAdmin, authorizer, &privpb.UpdateCertificateLabelRequest{ID: "1", Label: "x"}, pb.CA_UpdateCertificateLabel_FullMethodName)
	assert.ErrorContains(t, err, "forbidden: ", "org scope, where a project Admin is a Viewer")
	err = authctx.CheckAccess(projectAdmin, authorizer, &privpb.UpdateCertificateLabelRequest{ProjectID: "201", ID: "1", Label: "x"}, pb.CA_UpdateCertificateLabel_FullMethodName)
	require.NoError(t, err)
	err = authctx.CheckAccess(projectAdmin, authorizer, &privpb.RevokeCertificateRequest{ID: "1"}, pb.CA_RevokeCertificate_FullMethodName)
	assert.ErrorContains(t, err, "forbidden: ")
	err = authctx.CheckAccess(projectAdmin, authorizer, &privpb.RevokeCertificateRequest{ProjectID: "201", ID: "1"}, pb.CA_RevokeCertificate_FullMethodName)
	require.NoError(t, err)
	err = authctx.CheckAccess(projectAdmin, authorizer, &privpb.RevokeCertificateRequest{ProjectID: "202", ID: "1"}, pb.CA_RevokeCertificate_FullMethodName)
	assert.ErrorContains(t, err, "forbidden: ", "a project without a grant")
	err = authctx.CheckAccess(testCtx(projectViewerUser, "1"), authorizer, &privpb.RevokeCertificateRequest{ProjectID: "201", ID: "1"}, pb.CA_RevokeCertificate_FullMethodName)
	assert.ErrorContains(t, err, "forbidden: ", "a project Viewer")
	err = authctx.CheckAccess(admin, authorizer, &privpb.RevokeCertificateRequest{ID: "1"}, pb.CA_RevokeCertificate_FullMethodName)
	require.NoError(t, err, "an org-wide role at org scope")
}

func TestService_UpdateCertificateLabel_DbError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx(orgAdminUser, "1")
	crt := store(t, tca, "upd.example.com", xdb.ID(0))
	tca.cadb.EXPECT().GetCertificate(gomock.Any(), crt.ID.UInt64()).Return(crt, nil).AnyTimes()

	label := "x"
	tca.cadb.EXPECT().UpdateCertificate(gomock.Any(), &query.UpdateCertificateRequest{ID: crt.ID.UInt64(), OrgID: 1, Label: &label}).
		Return(nil, notFoundErr("certificate", crt.ID.UInt64()))
	_, err := svc.UpdateCertificateLabel(ctx, &privpb.UpdateCertificateLabelRequest{ID: crt.ID.String(), Label: "x"})
	assert.EqualError(t, err, "not_found: certificate not found", "a row that is gone by the time of the update")
	tca.cadb.EXPECT().UpdateCertificate(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.UpdateCertificateLabel(ctx, &privpb.UpdateCertificateLabelRequest{ID: crt.ID.String(), Label: "x"})
	assert.EqualError(t, err, "unexpected: failed to update certificate")
}

func TestService_RevokeCertificate(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	store := newCertStore()
	store.serve(tca.cadb)
	admin := testCtx(orgAdminUser, "1")
	orgCert := store.add(tca, tca.sign(t, "org.example.com"), testOrgID(), xdb.ID(0), "org")
	projectCert := store.add(tca, tca.sign(t, "prj.example.com"), testOrgID(), testProject.ID, "prj")
	siblingCert := store.add(tca, tca.sign(t, "sib.example.com"), testOrgID(), siblingProject.ID, "sib")
	bySerial := store.add(tca, tca.sign(t, "serial.example.com"), testOrgID(), xdb.ID(0), "serial")

	_, err := svc.RevokeCertificate(admin, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ID: orgCert.ID.String(), Reason: 7})
	assert.EqualError(t, err, "bad_request: invalid reason")
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ID: orgCert.ID.String(), Reason: 99})
	assert.EqualError(t, err, "bad_request: invalid reason")
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ID: orgCert.ID.String(), Reason: pb.ReasonCode_RemoveFromCRL})
	assert.EqualError(t, err, "bad_request: reason RemoveFromCRL releases a certificate from hold: not a revocation reason")
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ID: orgCert.ID.String(), ReasonText: string(make([]byte, model.MaxLenForName+1))})
	assert.EqualError(t, err, "bad_request: invalid reason text length")
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{})
	assert.EqualError(t, err, "bad_request: certificate ID, SKID, SHA-256 or issuer serial is required")
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ID: "9999"})
	assert.EqualError(t, err, "not_found: certificate not found")

	// by ID: the revocation carries the reason, and the event references
	// the certificate
	res, err := svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{
		ID:         orgCert.ID.String(),
		Reason:     pb.ReasonCode_KeyCompromise,
		ReasonText: "stolen",
	})
	require.NoError(t, err)
	require.NotNil(t, res.Revoked)
	assert.Equal(t, orgCert.ID.String(), res.Revoked.Certificate.ID)
	assert.Equal(t, pb.CertificateStatus_Revoked, res.Revoked.Certificate.Status)
	assert.Equal(t, pb.ReasonCode_KeyCompromise, res.Revoked.Reason)
	assert.Equal(t, "stolen", res.Revoked.ReasonText)
	assert.NotEmpty(t, res.Revoked.RevokedAt)
	revokedAt, err := time.Parse(time.RFC3339, res.Revoked.RevokedAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), revokedAt, time.Minute)
	evt := tca.events.last(pb.EventType_CertificateRevoked)
	require.NotNil(t, evt)
	assert.Equal(t, uint64(1), evt.OrgID.UInt64())
	assert.True(t, evt.ProjectID.IsZero())
	assert.Equal(t, orgCert.ID.UInt64(), evt.ReferenceID.UInt64())
	assert.Equal(t, "Certificate revoked", evt.Title)
	assert.Equal(t, EventSource, evt.Source.String())
	assert.Equal(t, testCallerEmail, evt.Email.String())
	assert.Equal(t, `certificate "CN=org.example.com" revoked: KeyCompromise`, evt.Description.String())

	// a revoked certificate is refused, whether the row or the DB says so
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ID: orgCert.ID.String()})
	assert.EqualError(t, err, "conflict: certificate is already revoked")
	got, err := svc.GetCertificate(admin, &privpb.GetCertificateRequest{ID: orgCert.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, pb.CertificateStatus_Revoked, got.Certificate.Status)

	// by SKID and by issuer and serial number; the default reason
	res, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{SKID: projectCert.Skid})
	require.NoError(t, err)
	assert.Equal(t, projectCert.ID.String(), res.Revoked.Certificate.ID)
	assert.Equal(t, pb.ReasonCode_Unspecified, res.Revoked.Reason)
	evt = tca.events.last(pb.EventType_CertificateRevoked)
	require.NotNil(t, evt)
	assert.Equal(t, uint64(201), evt.ProjectID.UInt64())
	assert.Equal(t, projectCert.ID.UInt64(), evt.ReferenceID.UInt64())
	res, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{
		IssuerSerial: &pb.IssuerSerial{IKID: bySerial.Ikid, SerialNumber: bySerial.SerialNumber},
		Reason:       pb.ReasonCode_Superseded,
	})
	require.NoError(t, err)
	assert.Equal(t, bySerial.ID.String(), res.Revoked.Certificate.ID)
	assert.Equal(t, pb.ReasonCode_Superseded, res.Revoked.Reason)

	// a project Viewer does not revoke; a project Admin revokes in its
	// project only, where a certificate of another project is not found
	_, err = svc.RevokeCertificate(testCtx(projectViewerUser, "1"), &privpb.RevokeCertificateRequest{ID: siblingCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.RevokeCertificate(testCtx(projectAdminUser, "1"), &privpb.RevokeCertificateRequest{ID: siblingCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.RevokeCertificate(apiKeyCtx("1", "201"), &privpb.RevokeCertificateRequest{ID: siblingCert.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found")
	res, err = svc.RevokeCertificate(apiKeyCtx("1", "202"), &privpb.RevokeCertificateRequest{ID: siblingCert.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, siblingCert.ID.String(), res.Revoked.Certificate.ID)
	evt = tca.events.last(pb.EventType_CertificateRevoked)
	require.NotNil(t, evt)
	assert.Empty(t, evt.Email.String(), "an API key has no email")

	// a key restricted to a project reads an org-wide certificate but may
	// not revoke it, by any selector
	orgCert2 := store.add(tca, tca.sign(t, "org2.example.com"), testOrgID(), xdb.ID(0), "org2")
	key := apiKeyCtx("1", "201")
	_, err = svc.GetCertificate(key, &privpb.GetCertificateRequest{ID: orgCert2.ID.String()})
	require.NoError(t, err)
	_, err = svc.RevokeCertificate(key, &privpb.RevokeCertificateRequest{ID: orgCert2.ID.String()})
	assert.EqualError(t, err, "forbidden: access denied")
	_, err = svc.RevokeCertificate(key, &privpb.RevokeCertificateRequest{SKID: orgCert2.Skid})
	assert.EqualError(t, err, "forbidden: access denied")
	_, err = svc.RevokeCertificate(key, &privpb.RevokeCertificateRequest{IssuerSerial: &pb.IssuerSerial{IKID: orgCert2.Ikid, SerialNumber: orgCert2.SerialNumber}})
	assert.EqualError(t, err, "forbidden: access denied")
	assert.Equal(t, pb.CertificateStatus_Active, store.rows[orgCert2.ID.UInt64()].Status)

	// the project of the request is the certificate's
	projectCert2 := store.add(tca, tca.sign(t, "prj2.example.com"), testOrgID(), testProject.ID, "prj2")
	_, err = svc.RevokeCertificate(testCtx(projectAdminUser, "1"), &privpb.RevokeCertificateRequest{ProjectID: "202", ID: projectCert2.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found")
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ProjectID: "201", ID: orgCert2.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found", "an org-wide certificate is not the project's")
	res, err = svc.RevokeCertificate(testCtx(projectAdminUser, "1"), &privpb.RevokeCertificateRequest{ProjectID: "201", ID: projectCert2.ID.String(), Reason: pb.ReasonCode_CertificateHold})
	require.NoError(t, err)
	assert.Equal(t, pb.ReasonCode_CertificateHold, res.Revoked.Reason)
	evt = tca.events.last(pb.EventType_CertificateRevoked)
	require.NotNil(t, evt)
	assert.Equal(t, uint64(201), evt.ProjectID.UInt64())

	// the same key renewed in two scopes: a request that names the project
	// finds the certificate of the project by SKID, not the newest one of
	// the org; without a project, the newest one the caller may read
	older := store.add(tca, tca.sign(t, "renew.example.com"), testOrgID(), testProject.ID, "renew-old")
	newer := store.add(tca, tca.sign(t, "renew.example.com"), testOrgID(), xdb.ID(0), "renew-new")
	store.setSKID(newer.ID, older.Skid)
	res, err = svc.RevokeCertificate(testCtx(projectAdminUser, "1"), &privpb.RevokeCertificateRequest{ProjectID: "201", SKID: older.Skid})
	require.NoError(t, err)
	assert.Equal(t, older.ID.String(), res.Revoked.Certificate.ID)
	_, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{ProjectID: "202", SKID: older.Skid})
	assert.EqualError(t, err, "not_found: certificate not found", "no certificate of the key in that project")
	res, err = svc.RevokeCertificate(admin, &privpb.RevokeCertificateRequest{SKID: older.Skid})
	require.NoError(t, err)
	assert.Equal(t, newer.ID.String(), res.Revoked.Certificate.ID, "the newest of the org")
}

func TestService_RevokeCertificate_DbError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx(orgAdminUser, "1")
	crt := store(t, tca, "rev.example.com", xdb.ID(0))
	tca.cadb.EXPECT().GetCertificate(gomock.Any(), crt.ID.UInt64()).Return(crt, nil).AnyTimes()

	// another request revoked the certificate first
	tca.cadb.EXPECT().RevokeCertificate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *query.RevokeCertificateRequest) (*model.RevokedCertificate, error) {
			assert.Equal(t, crt.ID.UInt64(), req.CertificateID)
			assert.Equal(t, uint64(1), req.OrgID)
			assert.Equal(t, pb.ReasonCode_CessationOfOperation, req.Reason)
			assert.Equal(t, "done", req.ReasonText)
			assert.WithinDuration(t, time.Now(), req.RevokedAt, time.Minute)
			return nil, errors.WithStack(db.ErrAlreadyRevoked)
		})
	_, err := svc.RevokeCertificate(ctx, &privpb.RevokeCertificateRequest{ID: crt.ID.String(), Reason: pb.ReasonCode_CessationOfOperation, ReasonText: "done"})
	assert.EqualError(t, err, "conflict: certificate is already revoked")
	assert.Nil(t, tca.events.last(pb.EventType_CertificateRevoked), "a refused revocation records no event")
	tca.cadb.EXPECT().RevokeCertificate(gomock.Any(), gomock.Any()).Return(nil, notFoundErr("certificate", crt.ID.UInt64()))
	_, err = svc.RevokeCertificate(ctx, &privpb.RevokeCertificateRequest{ID: crt.ID.String()})
	assert.EqualError(t, err, "not_found: certificate not found", "a row that is gone by the time of the revocation")
	tca.cadb.EXPECT().RevokeCertificate(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.RevokeCertificate(ctx, &privpb.RevokeCertificateRequest{ID: crt.ID.String()})
	assert.EqualError(t, err, "unexpected: failed to revoke certificate")
}

func TestService_ListRevokedCertificates(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	admin := testCtx(orgAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")
	crt := store(t, tca, "revoked.example.com", testProject.ID)
	crt.Status = pb.CertificateStatus_Revoked
	row := model.NewRevokedCertificate(crt, &model.Revoked{
		ID:            xdb.NewID(8001),
		OrgID:         crt.OrgID,
		ProjectID:     crt.ProjectID,
		CertificateID: crt.ID,
		Ikid:          crt.Ikid,
		SerialNumber:  crt.SerialNumber,
		NotAfter:      crt.NotAfter,
		RevokedAt:     xdb.UTC(time.Now()),
		Reason:        pb.ReasonCode_KeyCompromise,
		ReasonText:    "stolen",
	})

	_, err := svc.ListRevokedCertificates(admin, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.ListRevokedCertificates(testCtx(orgAdminUser, ""), &privpb.ListRevokedCertificatesRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.ListRevokedCertificates(admin, &privpb.ListRevokedCertificatesRequest{Cursor: "bad"})
	assert.EqualError(t, err, "bad_request: invalid cursor")
	_, err = svc.ListRevokedCertificates(admin, &privpb.ListRevokedCertificatesRequest{ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")

	tca.cadb.EXPECT().ListRevokedCertificates(gomock.Any(), &query.ListRevokedCertificatesRequest{
		OrgID: 1,
		IKID:  tca.issuer.Skid,
		Limit: 5,
	}).Return(&model.RevokedCertificateResult{Rows: []*model.RevokedCertificate{row}, HasNextPage: true, Cursor: "next"}, nil)
	res, err := svc.ListRevokedCertificates(admin, &privpb.ListRevokedCertificatesRequest{IKID: tca.issuer.Skid, Limit: 5})
	require.NoError(t, err)
	require.Len(t, res.RevokedCertificates, 1)
	assert.Equal(t, crt.ID.String(), res.RevokedCertificates[0].Certificate.ID)
	assert.Equal(t, pb.CertificateStatus_Revoked, res.RevokedCertificates[0].Certificate.Status)
	assert.Equal(t, pb.ReasonCode_KeyCompromise, res.RevokedCertificates[0].Reason)
	assert.Equal(t, "stolen", res.RevokedCertificates[0].ReasonText)
	require.NotNil(t, res.NextPage)
	assert.Equal(t, "next", res.NextPage.Cursor)

	tca.cadb.EXPECT().ListRevokedCertificates(gomock.Any(), &query.ListRevokedCertificatesRequest{
		OrgID:      1,
		ProjectIDs: []uint64{201},
		Limit:      defaultListLimit,
	}).Return(&model.RevokedCertificateResult{}, nil)
	res, err = svc.ListRevokedCertificates(viewer, &privpb.ListRevokedCertificatesRequest{})
	require.NoError(t, err)
	assert.Empty(t, res.RevokedCertificates)
	assert.Nil(t, res.NextPage)
	tca.cadb.EXPECT().ListRevokedCertificates(gomock.Any(), &query.ListRevokedCertificatesRequest{
		OrgID:     1,
		ProjectID: 201,
		Limit:     defaultListLimit,
	}).Return(&model.RevokedCertificateResult{}, nil)
	_, err = svc.ListRevokedCertificates(apiKeyCtx("1", "201"), &privpb.ListRevokedCertificatesRequest{})
	require.NoError(t, err)

	tca.cadb.EXPECT().ListRevokedCertificates(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.ListRevokedCertificates(admin, &privpb.ListRevokedCertificatesRequest{})
	assert.EqualError(t, err, "unexpected: failed to list revoked certificates")
}

// store returns the row of a certificate signed by the issuing CA of the
// tests in the project of org 1, as the DB would return it
func store(t testing.TB, tca *testCA, cn string, projectID xdb.ID) *model.Certificate {
	t.Helper()
	crt := tca.sign(t, cn)
	m := model.NewCertificate(crt, testOrgID(), ownID(projectID), testProfile, testutils.CertPEM(crt), tca.issuer.Pem, cn, nil, nil)
	m.ID = xdb.NewID(6001)
	return m
}
