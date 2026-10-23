package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/server/service/internal/caapi"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ocsp"
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
	svcCaller := serviceCtx("trustyca-admin")
	res, err = svc.GetCRL(svcCaller, &pb.GetCrlRequest{IKID: platformRoot.Skid})
	require.NoError(t, err)
	assert.Equal(t, "5", res.Crl.Number)
	assert.Empty(t, res.Crl.OrgID)
	res, err = svc.GetCRL(svcCaller, &pb.GetCrlRequest{IKID: org2Root.Skid})
	require.NoError(t, err)
	assert.Equal(t, "2", res.Crl.OrgID)
	_, err = svc.GetCRL(svcCaller, &pb.GetCrlRequest{IKID: "nope"})
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

// crlStore holds the CRLs and revocations the mock DB serves to the CRL
// publisher, and stores a CRL as the DB does: the number must be greater
// than the issuer's, which records it
type crlStore struct {
	mu      sync.Mutex
	rows    *caRows
	nextID  uint64
	crls    map[string]*model.Crl
	revoked []*model.Revoked
	// listErr fails the listing of the issuers of a status
	listErr map[pb.IssuerStatus_Enum]error
}

func newCrlStore(rows *caRows) *crlStore {
	return &crlStore{
		rows:    rows,
		nextID:  8000,
		crls:    map[string]*model.Crl{},
		listErr: map[pb.IssuerStatus_Enum]error{},
	}
}

// failList makes the listing of the issuers of the status fail
func (s *crlStore) failList(status pb.IssuerStatus_Enum, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listErr[status] = err
}

// listIssuers serves the issuer rows, unless the listing of the status
// fails
func (s *crlStore) listIssuers(ctx context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
	s.mu.Lock()
	err := s.listErr[req.Status]
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.rows.listIssuers(ctx, req)
}

// revoke records a revocation of a certificate of the issuer
func (s *crlStore) revoke(issuer *model.Issuer, serial string, notAfter time.Time, reason pb.ReasonCode_Enum) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.revoked = append(s.revoked, &model.Revoked{
		ID:            xdb.NewID(s.nextID),
		OrgID:         ownID(issuer.OrgID),
		ProjectID:     ownID(issuer.ProjectID),
		CertificateID: xdb.NewID(s.nextID),
		Ikid:          issuer.Skid,
		SerialNumber:  serial,
		NotAfter:      xdb.UTC(notAfter),
		RevokedAt:     xdb.UTC(time.Now()),
		Reason:        reason,
	})
}

func (s *crlStore) get(_ context.Context, ikid string) (*model.Crl, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.crls[ikid]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("crl", ikid)
}

// getMany serves the current CRLs of the IKIDs
func (s *crlStore) getMany(_ context.Context, ikids []string) ([]*model.Crl, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res []*model.Crl
	for _, ikid := range ikids {
		if m, ok := s.crls[ikid]; ok {
			row := *m
			res = append(res, &row)
		}
	}
	return res, nil
}

// listRevoked serves the IKID and validity of the request
func (s *crlStore) listRevoked(_ context.Context, req *query.ListRevokedRequest) (*model.RevokedResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res model.RevokedResult
	for _, m := range s.revoked {
		if req.IKID != "" && m.Ikid != req.IKID {
			continue
		}
		if req.ValidAfter != nil && !m.NotAfter.UTC().After(*req.ValidAfter) {
			continue
		}
		row := *m
		res.Rows = append(res.Rows, &row)
	}
	return &res, nil
}

func (s *crlStore) publish(ctx context.Context, m *model.Crl) (*model.Crl, error) {
	issuer, err := s.rows.getIssuer(ctx, m.IssuerID.UInt64())
	if err != nil {
		return nil, err
	}
	if issuer.Skid != m.Ikid {
		return nil, errors.Errorf("crl ikid %s does not match issuer", m.Ikid)
	}
	if m.CrlNumber <= issuer.CrlNumber {
		return nil, errors.WithStack(db.ErrStaleCrlNumber)
	}
	s.rows.setCrlNumber(issuer.ID, m.CrlNumber)
	s.mu.Lock()
	defer s.mu.Unlock()
	res := *m
	res.OrgID = ownID(issuer.OrgID)
	res.ProjectID = ownID(issuer.ProjectID)
	res.Issuer = issuer.Subject
	if err := res.Validate(); err != nil {
		return nil, err
	}
	if cur, ok := s.crls[m.Ikid]; ok {
		res.ID = cur.ID
		res.CreatedAt = cur.CreatedAt
	} else {
		s.nextID++
		res.ID = xdb.NewID(s.nextID)
		res.CreatedAt = xdb.UTC(time.Now())
	}
	s.crls[res.Ikid] = &res
	out := res
	return &out, nil
}

// serve makes the mock DB serve the store and the issuer rows for every
// read and mutation of the publisher
func (s *crlStore) serve(cadb *mocktrustycadb.MockCaDb) {
	cadb.EXPECT().GetCrl(gomock.Any(), gomock.Any()).DoAndReturn(s.get).AnyTimes()
	cadb.EXPECT().GetCrls(gomock.Any(), gomock.Any()).DoAndReturn(s.getMany).AnyTimes()
	cadb.EXPECT().ListRevoked(gomock.Any(), gomock.Any()).DoAndReturn(s.listRevoked).AnyTimes()
	cadb.EXPECT().PublishCrl(gomock.Any(), gomock.Any()).DoAndReturn(s.publish).AnyTimes()
	cadb.EXPECT().ListIssuers(gomock.Any(), gomock.Any()).DoAndReturn(s.listIssuers).AnyTimes()
}

// setCrlNumber records the number of a published CRL on the stored issuer,
// without touching updated_at as the DB does
func (r *caRows) setCrlNumber(id xdb.ID, number int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issuers[id.UInt64()].CrlNumber = number
}

// setNotAfter changes the expiry of a stored issuer
func (r *caRows) setNotAfter(id xdb.ID, notAfter time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issuers[id.UInt64()].NotAfter = xdb.UTC(notAfter)
}

// listIssuers serves the org scope, project, visible projects and status
// of the request, newest first
func (r *caRows) listIssuers(_ context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var res model.IssuerResult
	for _, m := range r.issuers {
		switch {
		case req.OrgID != 0 && m.OrgID.UInt64() != req.OrgID:
		case req.Platform && !m.OrgID.IsZero():
		case req.ProjectID != 0 && m.ProjectID.UInt64() != req.ProjectID:
		case req.ProjectID == 0 && req.ProjectIDs != nil && !m.ProjectID.IsZero() && !slices.Contains(req.ProjectIDs, m.ProjectID.UInt64()):
		case req.Status != pb.IssuerStatus_Unknown && m.Status != req.Status:
		default:
			row := *m
			res.Rows = append(res.Rows, &row)
		}
	}
	slices.SortFunc(res.Rows, func(a, b *model.Issuer) int {
		return int(b.ID.UInt64()) - int(a.ID.UInt64())
	})
	return &res, nil
}

// parseCRL parses the PEM of a published CRL and verifies its signature
// against the issuer row
func parseCRL(t *testing.T, crl *pb.Crl, issuer *model.Issuer) *x509.RevocationList {
	t.Helper()
	block, _ := pem.Decode([]byte(crl.Pem))
	require.NotNil(t, block)
	list, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	cert, err := certutil.ParseFromPEM([]byte(issuer.Pem))
	require.NoError(t, err)
	require.NoError(t, list.CheckSignatureFrom(cert))
	return list
}

// ikids returns the issuer key identifiers of the published CRLs
func ikids(res *pb.CrlsResponse) []string {
	var ids []string
	for _, crl := range res.Crls {
		ids = append(ids, crl.IKID)
	}
	return ids
}

func TestService_PublishCrls(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	store := newCrlStore(tca.rows)
	store.serve(tca.cadb)
	admin := testCtx(orgAdminUser, "1")
	projectAdmin := testCtx(projectAdminUser, "1")
	viewer := testCtx(projectViewerUser, "1")
	projectIssuer := tca.newChild(t, tca.root, testCAProfile, testOrgID(), testProject.ID, "PRJ", pb.AuthorityType_Issuing, nil)
	sibling := tca.newChild(t, tca.root, testCAProfile, testOrgID(), siblingProject.ID, "SIB", pb.AuthorityType_Issuing, nil)
	pending := tca.newPending(t, testOrgID(), xdb.ID(0), "PENDING")
	destroyed := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "DESTROYED", pb.AuthorityType_Issuing, nil)
	tca.rows.update(destroyed.ID, func(m *model.Issuer) { m.Status = pb.IssuerStatus_Destroyed })
	archived := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "ARCHIVED", pb.AuthorityType_Issuing, nil)
	tca.rows.update(archived.ID, func(m *model.Issuer) { m.Status = pb.IssuerStatus_Archived })
	expired := tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), "EXPIRED", pb.AuthorityType_Issuing, nil)
	tca.rows.setNotAfter(expired.ID, time.Now().Add(-time.Minute))
	org2Root := tca.newRoot(t, xdb.NewID(2), xdb.ID(0), testRootLabel)
	platformRoot := tca.newRoot(t, xdb.ID(0), xdb.ID(0), "PROOT")
	leaf := tca.sign(t, "revoked.example.com")
	store.revoke(tca.issuer, leaf.SerialNumber.String(), leaf.NotAfter, pb.ReasonCode_KeyCompromise)

	_, err := svc.PublishCrls(admin, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	noCA, noKeys := tca.noCA()
	_, err = noCA.PublishCrls(admin, &pb.PublishCrlsRequest{})
	assert.EqualError(t, err, "unavailable: CA is not configured")
	_, err = noKeys.PublishCrls(admin, &pb.PublishCrlsRequest{})
	assert.EqualError(t, err, "unavailable: CA is not configured")
	_, err = svc.PublishCrls(testCtx(orgAdminUser, ""), &pb.PublishCrlsRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{OrgID: "2"})
	assert.EqualError(t, err, "forbidden: org mismatch")

	// one issuer by IKID: of the org, visible and publishing
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: "nope"})
	assert.EqualError(t, err, "not_found: issuer not found")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: org2Root.Skid})
	assert.EqualError(t, err, "not_found: issuer not found", "another org's issuer")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: platformRoot.Skid})
	assert.EqualError(t, err, "not_found: issuer not found", "a platform issuer")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: pending.Skid})
	assert.EqualError(t, err, "conflict: issuer is pending")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: destroyed.Skid})
	assert.EqualError(t, err, "conflict: issuer is destroyed")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: expired.Skid})
	assert.EqualError(t, err, "conflict: issuer certificate has expired")
	_, err = svc.PublishCrls(viewer, &pb.PublishCrlsRequest{IKID: projectIssuer.Skid})
	assert.EqualError(t, err, "forbidden: access denied", "a Viewer of the project")
	_, err = svc.PublishCrls(viewer, &pb.PublishCrlsRequest{IKID: tca.issuer.Skid})
	assert.EqualError(t, err, "forbidden: access denied", "the derived org Viewer")
	_, err = svc.PublishCrls(projectAdmin, &pb.PublishCrlsRequest{IKID: sibling.Skid})
	assert.EqualError(t, err, "not_found: issuer not found", "a project without a grant")
	_, err = svc.PublishCrls(apiKeyCtx("1", "201"), &pb.PublishCrlsRequest{IKID: tca.issuer.Skid})
	assert.EqualError(t, err, "forbidden: access denied", "a key restricted to a project does not change an org-wide row")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: tca.issuer.Skid, ProjectID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid project ID")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: projectIssuer.Skid, ProjectID: "203"})
	assert.EqualError(t, err, "not_found: project not found", "an inactive project")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: projectIssuer.Skid, ProjectID: "202"})
	assert.EqualError(t, err, "not_found: issuer not found", "an issuer of another project than the request names")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: tca.issuer.Skid, ProjectID: "201"})
	assert.EqualError(t, err, "not_found: issuer not found", "an org-wide issuer when the request names a project")

	res, err := svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: tca.issuer.Skid})
	require.NoError(t, err)
	require.Len(t, res.Crls, 1)
	crl := res.Crls[0]
	assert.Equal(t, "1", crl.Number)
	assert.Equal(t, tca.issuer.Skid, crl.IKID)
	assert.Equal(t, tca.issuer.ID.String(), crl.IssuerID)
	assert.Equal(t, "1", crl.OrgID)
	assert.Equal(t, tca.issuer.Subject, crl.Issuer)
	assert.NotEmpty(t, crl.ID)
	assert.NotEmpty(t, crl.ThisUpdate)
	assert.NotEmpty(t, crl.NextUpdate)
	list := parseCRL(t, crl, tca.issuer)
	require.Len(t, list.RevokedCertificateEntries, 1)
	assert.Equal(t, 0, leaf.SerialNumber.Cmp(list.RevokedCertificateEntries[0].SerialNumber))
	assert.Equal(t, ocsp.KeyCompromise, list.RevokedCertificateEntries[0].ReasonCode)
	assert.EqualValues(t, 1, list.Number.Int64())
	evt := tca.events.last(pb.EventType_CrlPublished)
	require.NotNil(t, evt)
	assert.Equal(t, crl.ID, evt.ReferenceID.String())
	assert.Equal(t, "1", evt.OrgID.String())
	assert.True(t, evt.ProjectID.IsZero())
	assert.Equal(t, caapi.EventSource, evt.Source.String())
	assert.Equal(t, testCallerEmail, evt.Email.String())
	assert.Equal(t, `CRL 1 of issuer "`+tca.issuer.Subject+`" published`, evt.Description.String())

	// not due: nothing is published; forced: the next number
	res, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: tca.issuer.Skid})
	require.NoError(t, err)
	assert.Empty(t, res.Crls)
	res, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: tca.issuer.Skid, Force: true})
	require.NoError(t, err)
	require.Len(t, res.Crls, 1)
	assert.Equal(t, "2", res.Crls[0].Number)
	assert.Equal(t, crl.ID, res.Crls[0].ID, "the current CRL is replaced")
	res, err = svc.PublishCrls(projectAdmin, &pb.PublishCrlsRequest{IKID: projectIssuer.Skid})
	require.NoError(t, err)
	require.Len(t, res.Crls, 1)
	assert.Equal(t, "201", tca.events.last(pb.EventType_CrlPublished).ProjectID.String())
	res, err = svc.PublishCrls(apiKeyCtx("1", "201"), &pb.PublishCrlsRequest{IKID: projectIssuer.Skid, Force: true})
	require.NoError(t, err)
	assert.Equal(t, "2", res.Crls[0].Number)
	res, err = svc.PublishCrls(projectAdmin, &pb.PublishCrlsRequest{IKID: projectIssuer.Skid, ProjectID: "201", Force: true})
	require.NoError(t, err)
	assert.Equal(t, "3", res.Crls[0].Number, "the project the request names")
	res, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: archived.Skid})
	require.NoError(t, err)
	require.Len(t, res.Crls, 1, "an Archived issuer keeps publishing")

	// the scope of a request without an IKID: the due CRLs of the org-wide
	// issuers and the projects the caller may read; a project of a
	// restricted key; every org for a service caller without an org
	res, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{sibling.Skid, tca.root.Skid}, ikids(res), "the issuers without a CRL")
	res, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{})
	require.NoError(t, err)
	assert.Empty(t, res.Crls, "nothing is due")
	res, err = svc.PublishCrls(projectAdmin, &pb.PublishCrlsRequest{Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{projectIssuer.Skid, tca.issuer.Skid, tca.root.Skid, archived.Skid}, ikids(res))
	res, err = svc.PublishCrls(apiKeyCtx("1", "201"), &pb.PublishCrlsRequest{Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{projectIssuer.Skid}, ikids(res))
	res, err = svc.PublishCrls(projectAdmin, &pb.PublishCrlsRequest{ProjectID: "201", Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{projectIssuer.Skid}, ikids(res), "the project the request names")
	res, err = svc.PublishCrls(apiKeyCtx("1", "201"), &pb.PublishCrlsRequest{ProjectID: "201", Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{projectIssuer.Skid}, ikids(res))
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{ProjectID: "203", Force: true})
	assert.EqualError(t, err, "not_found: project not found")
	res, err = svc.PublishCrls(apiKeyCtx("1", ""), &pb.PublishCrlsRequest{Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{sibling.Skid, projectIssuer.Skid, tca.issuer.Skid, tca.root.Skid, archived.Skid}, ikids(res))
	jobs := serviceCtx("trustyca-admin")
	_, err = svc.PublishCrls(jobs, &pb.PublishCrlsRequest{ProjectID: "201"})
	assert.EqualError(t, err, "bad_request: org ID is required", "a project needs its org")
	res, err = svc.PublishCrls(jobs, &pb.PublishCrlsRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{platformRoot.Skid, org2Root.Skid}, ikids(res), "every org and the platform")
	res, err = svc.PublishCrls(jobs, &pb.PublishCrlsRequest{IKID: platformRoot.Skid, Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{platformRoot.Skid}, ikids(res))
	assert.Empty(t, res.Crls[0].OrgID)
	evt = tca.events.last(pb.EventType_CrlPublished)
	assert.True(t, evt.OrgID.IsZero())
	assert.Empty(t, evt.Email.String())
	tca.orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	res, err = svc.PublishCrls(serviceCtx("trustyca-ra"), &pb.PublishCrlsRequest{OrgID: "1", Force: true})
	require.NoError(t, err)
	assert.Len(t, res.Crls, 5, "the org named by a service caller")

	// an issuer that fails does not stop the others, and fails the request
	tca.addProfile(testOrgID(), xdb.ID(0), &pb.CertProfile{
		Label:       "NOCRL",
		IssuerLabel: testRootLabel,
		Expiry:      "8760h",
		Backdate:    "30m",
		Usages:      []string{"cert sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: 0,
		},
	})
	noCrl := tca.newChild(t, tca.root, "NOCRL", testOrgID(), xdb.ID(0), "NOCRL", pb.AuthorityType_Issuing, nil)
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{IKID: noCrl.Skid})
	assert.EqualError(t, err, "unexpected: unable to publish CRL")
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{Force: true})
	assert.EqualError(t, err, "unexpected: failed to publish 1 CRLs")
	got, err := store.get(context.Background(), tca.root.Skid)
	require.NoError(t, err)
	assert.EqualValues(t, 5, got.CrlNumber, "the others were published")
}

func TestService_PublishCrls_DbError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	store := newCrlStore(tca.rows)
	store.serve(tca.cadb)
	admin := testCtx(orgAdminUser, "1")

	// the Active issuers publish, then the listing of the Archived ones
	// fails: the published CRLs record their events before the request
	// fails, since a retry finds them fresh
	store.failList(pb.IssuerStatus_Archived, errors.New("db down"))
	_, err := svc.PublishCrls(admin, &pb.PublishCrlsRequest{})
	assert.EqualError(t, err, "unexpected: failed to publish CRLs")
	assert.Equal(t, 2, tca.events.count(pb.EventType_CrlPublished), "the issuing CA and the root")
	rootCrl, err := store.get(context.Background(), tca.root.Skid)
	require.NoError(t, err)
	assert.EqualValues(t, 1, rootCrl.CrlNumber)
	evt := tca.events.last(pb.EventType_CrlPublished)
	require.NotNil(t, evt)
	assert.Equal(t, rootCrl.ID.String(), evt.ReferenceID.String())

	// nothing publishes when the first listing fails
	store.failList(pb.IssuerStatus_Active, errors.New("db down"))
	_, err = svc.PublishCrls(admin, &pb.PublishCrlsRequest{})
	assert.EqualError(t, err, "unexpected: failed to publish CRLs")
	assert.Equal(t, 2, tca.events.count(pb.EventType_CrlPublished))
}

// TestService_PublishCrls_CheckAccess runs the scopes of PublishCrls
// through the interceptor's authorization: a project Admin names its
// project, and an API key needs the ca:write scope within its project
func TestService_PublishCrls_CheckAccess(t *testing.T) {
	t.Parallel()
	authorizer := newFakeAuthorizer()
	projectAdmin := testCtx(projectAdminUser, "1")
	admin := testCtx(orgAdminUser, "1")
	const method = pb.CA_PublishCrls_FullMethodName

	err := authctx.CheckAccess(admin, authorizer, &pb.PublishCrlsRequest{}, method)
	require.NoError(t, err, "an org-wide role at org scope")
	err = authctx.CheckAccess(admin, authorizer, &pb.PublishCrlsRequest{ProjectID: "201"}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(projectAdmin, authorizer, &pb.PublishCrlsRequest{}, method)
	assert.ErrorContains(t, err, "forbidden: ", "org scope, where a project Admin is a Viewer")
	err = authctx.CheckAccess(projectAdmin, authorizer, &pb.PublishCrlsRequest{IKID: "x"}, method)
	assert.ErrorContains(t, err, "forbidden: ", "an IKID does not select the project")
	err = authctx.CheckAccess(projectAdmin, authorizer, &pb.PublishCrlsRequest{ProjectID: "201"}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(projectAdmin, authorizer, &pb.PublishCrlsRequest{ProjectID: "201", IKID: "x"}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(projectAdmin, authorizer, &pb.PublishCrlsRequest{ProjectID: "202"}, method)
	assert.ErrorContains(t, err, "forbidden: ", "a project without a grant")
	err = authctx.CheckAccess(testCtx(projectViewerUser, "1"), authorizer, &pb.PublishCrlsRequest{ProjectID: "201"}, method)
	assert.ErrorContains(t, err, "forbidden: ", "a project Viewer")

	err = authctx.CheckAccess(apiKeyCtx("1", ""), authorizer, &pb.PublishCrlsRequest{}, method)
	assert.ErrorContains(t, err, "forbidden: insufficient scope", "a key without ca:write")
	writer := apiKeyScopedCtx("1", "", "ca:write")
	err = authctx.CheckAccess(writer, authorizer, &pb.PublishCrlsRequest{}, method)
	require.NoError(t, err, "an org-wide key with ca:write")
	err = authctx.CheckAccess(writer, authorizer, &pb.PublishCrlsRequest{ProjectID: "201"}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(writer, authorizer, &pb.PublishCrlsRequest{ProjectID: "203"}, method)
	assert.ErrorContains(t, err, "forbidden: ", "an inactive project")
	restricted := apiKeyScopedCtx("1", "201", "ca:write")
	err = authctx.CheckAccess(restricted, authorizer, &pb.PublishCrlsRequest{}, method)
	require.NoError(t, err, "a restricted key acts in its project")
	err = authctx.CheckAccess(restricted, authorizer, &pb.PublishCrlsRequest{ProjectID: "201", IKID: "x"}, method)
	require.NoError(t, err)
	err = authctx.CheckAccess(restricted, authorizer, &pb.PublishCrlsRequest{ProjectID: "202"}, method)
	assert.ErrorContains(t, err, "forbidden: project mismatch", "another project than the key's")
}
