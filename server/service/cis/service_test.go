package cis_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/server/service/cis"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// The fixtures of the tests: org 1 with project 201, and the platform
const (
	testIssuerLabel = "L2_CA"
	testCrlNumber   = 3
	// pendingSKID is the key identifier of the Pending issuer of the store
	pendingSKID = "pending-skid"
)

// The URL templates of the issuer settings, one with each placeholder;
// they name the AIA listener, which the CIS does not serve
const (
	testAiaURL  = "http://aia.test/v1/cert/${ISSUER_ID}"
	testCrlURL  = "http://aia.test/v1/crl/:ISSUER_ID"
	testOcspURL = "http://aia.test/v1/ocspi/:ISSUER_ID"
)

func notFoundErr(table string, id any) error {
	return xdb.CheckNotFoundError(sql.ErrNoRows, table, id)
}

// testStore holds the rows the mock DB serves; a failure set on it is
// returned by every read
type testStore struct {
	mu       sync.Mutex
	fail     error
	issuers  map[string]*model.Issuer
	crls     map[string]*model.Crl
	certs    map[uint64]*model.Certificate
	revoked  map[uint64]*model.Revoked
	roots    []*model.RootCertificate
	calls    map[string]int
	lastList *query.ListCertificatesRequest
}

func newTestStore() *testStore {
	return &testStore{
		issuers: map[string]*model.Issuer{},
		crls:    map[string]*model.Crl{},
		certs:   map[uint64]*model.Certificate{},
		revoked: map[uint64]*model.Revoked{},
		calls:   map[string]int{},
	}
}

// setFail makes every read fail with the error; nil restores the reads
func (s *testStore) setFail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

func (s *testStore) count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

func (s *testStore) getIssuerBySKID(_ context.Context, skid string) (*model.Issuer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["GetIssuerBySKID"]++
	if s.fail != nil {
		return nil, s.fail
	}
	if m, ok := s.issuers[skid]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("issuer", skid)
}

func (s *testStore) getCrl(_ context.Context, ikid string) (*model.Crl, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["GetCrl"]++
	if s.fail != nil {
		return nil, s.fail
	}
	if m, ok := s.crls[ikid]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("crl", ikid)
}

func (s *testStore) listRoots(_ context.Context, req *query.ListRootsRequest) (*model.RootCertificateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["ListRoots"]++
	if s.fail != nil {
		return nil, s.fail
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	res := &model.RootCertificateResult{}
	for _, m := range s.roots {
		switch {
		case req.Platform && !m.OrgID.IsZero():
			continue
		case req.OrgID != 0 && m.OrgID.UInt64() != req.OrgID:
			continue
		}
		row := *m
		res.Rows = append(res.Rows, &row)
	}
	return res, nil
}

func (s *testStore) getCertificate(_ context.Context, id uint64) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["GetCertificate"]++
	if s.fail != nil {
		return nil, s.fail
	}
	if m, ok := s.certs[id]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("certificate", id)
}

func (s *testStore) getCertificateBySha256(_ context.Context, sha string) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["GetCertificateBySha256"]++
	if s.fail != nil {
		return nil, s.fail
	}
	for _, m := range s.certs {
		if m.Sha256 == sha {
			res := *m
			return &res, nil
		}
	}
	return nil, notFoundErr("certificate", sha)
}

func (s *testStore) getCertificateByIssuerSerial(_ context.Context, ikid, serial string) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["GetCertificateByIssuerSerial"]++
	if s.fail != nil {
		return nil, s.fail
	}
	for _, m := range s.certs {
		if m.Ikid == ikid && m.SerialNumber == serial {
			res := *m
			return &res, nil
		}
	}
	return nil, notFoundErr("certificate", ikid+"/"+serial)
}

// listCertificates serves the lookup by SKID: the newest certificate of
// the key, the one with the highest ID
func (s *testStore) listCertificates(_ context.Context, req *query.ListCertificatesRequest) (*model.CertificateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["ListCertificates"]++
	s.lastList = req
	if s.fail != nil {
		return nil, s.fail
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	res := &model.CertificateResult{}
	var newest *model.Certificate
	for _, m := range s.certs {
		if req.SKID != "" && m.Skid != req.SKID {
			continue
		}
		if newest == nil || m.ID.UInt64() > newest.ID.UInt64() {
			newest = m
		}
	}
	if newest != nil {
		row := *newest
		res.Rows = append(res.Rows, &row)
	}
	return res, nil
}

func (s *testStore) getRevoked(_ context.Context, req *query.GetRevokedRequest) (*model.Revoked, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["GetRevoked"]++
	if s.fail != nil {
		return nil, s.fail
	}
	if m, ok := s.revoked[req.CertificateID]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("revoked", req.CertificateID)
}

// testEnv is the service of the tests over the store, with the rows of the
// issuing CA of org 1: an Active leaf, an expired one, a revoked one, and
// the current CRL with the revoked one
type testEnv struct {
	svc     *cis.Service
	store   *testStore
	handler http.Handler
	root    *testutils.TestCA
	issuing *testutils.TestCA
	issuer  *model.Issuer
	crl     *model.Crl
	leaf    *model.Certificate
	leafCrt *x509.Certificate
	expired *model.Certificate
	expCrt  *x509.Certificate
	revoked *model.Certificate
	revCrt  *x509.Certificate
	revRow  *model.Revoked
}

// newTestEnv builds the service with the fixtures; the org IDs are created
// per test, since parallel tests never share an xdb.ID
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	now := time.Now().UTC().Truncate(time.Second)
	orgID := xdb.NewID(1)
	projectID := xdb.NewID(201)

	root := testutils.NewTestCA(t, "CIS Test Root", nil)
	issuing := testutils.NewTestCA(t, "CIS Test Issuing", root)
	store := newTestStore()

	issuer := &model.Issuer{
		ID:          xdb.NewID(5001),
		OrgID:       orgID,
		Label:       testIssuerLabel,
		Type:        pb.AuthorityType_Issuing,
		Status:      pb.IssuerStatus_Active,
		KeyProvider: "inmem",
		KeyID:       "key-1",
		CreatedAt:   xdb.UTC(now),
		UpdatedAt:   xdb.UTC(now),
	}
	issuer.SetCertificate(issuing.Cert, testutils.CertPEM(issuing.Cert), issuing.ChainPEM(), testutils.CertPEM(root.Cert))
	require.NoError(t, issuer.SetConfig(&pb.IssuerConfig{
		AiaURL:  testAiaURL,
		CrlURL:  testCrlURL,
		OcspURL: testOcspURL,
	}))
	store.issuers[issuer.Skid] = issuer
	store.issuers[pendingSKID] = &model.Issuer{
		ID:     xdb.NewID(5002),
		OrgID:  orgID,
		Label:  "PENDING",
		Type:   pb.AuthorityType_Issuing,
		Status: pb.IssuerStatus_Pending,
		Skid:   pendingSKID,
		CsrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMA==\n-----END CERTIFICATE REQUEST-----\n",
	}
	// a row whose settings do not parse
	broken := *issuer
	broken.ID = xdb.NewID(5003)
	broken.Skid = "broken-config"
	broken.Config = model.JSON(`{"AiaURL": 1}`)
	store.issuers[broken.Skid] = &broken

	leafCrt := issuing.Issue(t, "leaf.example.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	expiredCrt := issuing.Issue(t, "old.example.com", now.Add(-48*time.Hour), now.Add(-time.Hour))
	revCrt := issuing.Issue(t, "revoked.example.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	chainPEM := testutils.CertPEM(issuing.Cert) + testutils.CertPEM(root.Cert)
	newCert := func(id uint64, crt *x509.Certificate, status pb.CertificateStatus_Enum) *model.Certificate {
		m := model.NewCertificate(crt, orgID, projectID, "peer", testutils.CertPEM(crt), chainPEM, "edge-1", []string{"s3://bucket/" + crt.Subject.CommonName}, xdb.Metadata{"requester": "test"})
		m.ID = xdb.NewID(id)
		m.Status = status
		store.certs[id] = m
		return m
	}
	leaf := newCert(7001, leafCrt, pb.CertificateStatus_Active)
	expired := newCert(7002, expiredCrt, pb.CertificateStatus_Active)
	revoked := newCert(7003, revCrt, pb.CertificateStatus_Revoked)
	revRow := &model.Revoked{
		ID:            xdb.NewID(8001),
		OrgID:         orgID,
		ProjectID:     projectID,
		CertificateID: revoked.ID,
		Ikid:          revoked.Ikid,
		SerialNumber:  revoked.SerialNumber,
		NotAfter:      revoked.NotAfter,
		RevokedAt:     xdb.UTC(now.Add(-time.Minute)),
		Reason:        pb.ReasonCode_KeyCompromise,
		ReasonText:    "test",
	}
	store.revoked[revoked.ID.UInt64()] = revRow

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(testCrlNumber),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(48 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   revCrt.SerialNumber,
			RevocationTime: revRow.RevokedAt.UTC(),
			ReasonCode:     int(pb.ReasonCode_KeyCompromise),
		}},
	}, issuing.Cert, issuing.Key)
	require.NoError(t, err)
	crl := &model.Crl{
		ID:         xdb.NewID(9001),
		OrgID:      orgID,
		IssuerID:   issuer.ID,
		Ikid:       issuer.Skid,
		CrlNumber:  testCrlNumber,
		ThisUpdate: xdb.UTC(now.Add(-time.Minute)),
		NextUpdate: xdb.UTC(now.Add(48 * time.Hour)),
		Issuer:     issuer.Subject,
		Pem:        string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})),
		Locations:  []string{"s3://bucket/crl"},
		CreatedAt:  xdb.UTC(now),
	}
	store.crls[crl.Ikid] = crl

	platformRoot := model.NewRootCertificate(root.Cert, xdb.ID(0), pb.Trust_Public, testutils.CertPEM(root.Cert))
	platformRoot.ID = xdb.NewID(6001)
	orgRoot := testutils.NewTestCA(t, "Org Root", nil)
	orgRootRow := model.NewRootCertificate(orgRoot.Cert, orgID, pb.Trust_Private, testutils.CertPEM(orgRoot.Cert))
	orgRootRow.ID = xdb.NewID(6002)
	store.roots = []*model.RootCertificate{platformRoot, orgRootRow}

	cadb := mocktrustycadb.NewMockCaReadonlyDb(ctrl)
	cadb.EXPECT().GetIssuerBySKID(gomock.Any(), gomock.Any()).DoAndReturn(store.getIssuerBySKID).AnyTimes()
	cadb.EXPECT().GetCrl(gomock.Any(), gomock.Any()).DoAndReturn(store.getCrl).AnyTimes()
	cadb.EXPECT().ListRoots(gomock.Any(), gomock.Any()).DoAndReturn(store.listRoots).AnyTimes()
	cadb.EXPECT().GetCertificate(gomock.Any(), gomock.Any()).DoAndReturn(store.getCertificate).AnyTimes()
	cadb.EXPECT().GetCertificateBySha256(gomock.Any(), gomock.Any()).DoAndReturn(store.getCertificateBySha256).AnyTimes()
	cadb.EXPECT().GetCertificateByIssuerSerial(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(store.getCertificateByIssuerSerial).AnyTimes()
	cadb.EXPECT().ListCertificates(gomock.Any(), gomock.Any()).DoAndReturn(store.listCertificates).AnyTimes()
	cadb.EXPECT().GetRevoked(gomock.Any(), gomock.Any()).DoAndReturn(store.getRevoked).AnyTimes()

	svc, err := cis.New(cadb)
	require.NoError(t, err)
	r := restserver.NewRouter(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
	})
	svc.RegisterRoute(r)

	return &testEnv{
		svc:     svc,
		store:   store,
		handler: r.Handler(),
		root:    root,
		issuing: issuing,
		issuer:  issuer,
		crl:     crl,
		leaf:    leaf,
		leafCrt: leafCrt,
		expired: expired,
		expCrt:  expiredCrt,
		revoked: revoked,
		revCrt:  revCrt,
		revRow:  revRow,
	}
}

// serve runs a request through the routes of the service
func (e *testEnv) serve(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w
}
