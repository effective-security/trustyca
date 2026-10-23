package aia_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/service/aia"
	"github.com/effective-security/trustyca/server/service/shared"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc/codes"
)

// The media types of the binary routes
const (
	certContentType = "application/pkix-cert"
	crlContentType  = "application/pkix-crl"
	ocspContentType = "application/ocsp-response"
)

// The fixtures of the tests: the issuing CA of org 1
const (
	testIssuerLabel = "L2_CA"
	testCrlNumber   = 3
	// ocspValidity is the validity of the responses the fake CA signs
	ocspValidity = time.Hour
	// pendingSKID is the key identifier of the Pending issuer of the store
	pendingSKID = "pending-skid"
)

func notFoundErr(table string, id any) error {
	return xdb.CheckNotFoundError(sql.ErrNoRows, table, id)
}

// testStore holds the rows the mock DB serves; a failure set on it is
// returned by every read
type testStore struct {
	mu      sync.Mutex
	fail    error
	issuers map[string]*model.Issuer
	crls    map[string]*model.Crl
	calls   map[string]int
}

func newTestStore() *testStore {
	return &testStore{
		issuers: map[string]*model.Issuer{},
		crls:    map[string]*model.Crl{},
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

// fakeCA is the backend the service forwards OCSP requests to: it signs
// with the key of its issuing CA for the serials it knows, revoked ones
// with their reason, and answers unknown for the others; a request for
// another issuer is not found, as the backend service answers. A failure
// set on it is returned instead, and the calls are counted.
type fakeCA struct {
	privpb.UnimplementedBackendServer
	ca       *testutils.TestCA
	mu       sync.Mutex
	calls    int
	fail     error
	validity time.Duration
	// garbage makes the fake return bytes that are not an OCSP response
	garbage  bool
	known    map[string]bool
	revoked  map[string]*model.Revoked
	issuerKH map[crypto.Hash][]byte
}

func newFakeCA(ca *testutils.TestCA) *fakeCA {
	return &fakeCA{
		ca:       ca,
		validity: ocspValidity,
		known:    map[string]bool{},
		revoked:  map[string]*model.Revoked{},
		issuerKH: map[crypto.Hash][]byte{},
	}
}

func (f *fakeCA) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = err
}

func (f *fakeCA) setValidity(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validity = d
}

func (f *fakeCA) setGarbage(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.garbage = on
}

func (f *fakeCA) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// register makes the serial of the certificate known, revoked when a
// revocation is given
func (f *fakeCA) register(crt *x509.Certificate, revoked *model.Revoked) {
	f.mu.Lock()
	defer f.mu.Unlock()
	serial := crt.SerialNumber.String()
	f.known[serial] = true
	if revoked != nil {
		f.revoked[serial] = revoked
	}
}

// issuerKeyHash returns the hash of the public key of the issuing CA, as
// an OCSP request identifies the issuer (RFC 6960 section 4.1.1)
func (f *fakeCA) issuerKeyHash(h crypto.Hash) []byte {
	if kh, ok := f.issuerKH[h]; ok {
		return kh
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(f.ca.Cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return nil
	}
	hasher := h.New()
	hasher.Write(spki.PublicKey.RightAlign())
	kh := hasher.Sum(nil)
	f.issuerKH[h] = kh
	return kh
}

func (f *fakeCA) SignOCSP(_ context.Context, req *pb.OCSPRequest) (*pb.OCSPResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail != nil {
		return nil, f.fail
	}
	ocspReq, err := ocsp.ParseRequest(req.Der)
	if err != nil || ocspReq.SerialNumber == nil {
		return nil, httperror.NewGrpc(codes.InvalidArgument, "invalid request")
	}
	if string(ocspReq.IssuerKeyHash) != string(f.issuerKeyHash(ocspReq.HashAlgorithm)) {
		return nil, httperror.NewGrpc(codes.NotFound, "issuer not found")
	}
	if f.garbage {
		return &pb.OCSPResponse{Der: []byte("not an OCSP response")}, nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	serial := ocspReq.SerialNumber.String()
	template := ocsp.Response{
		Status:       ocsp.Unknown,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(f.validity),
		IssuerHash:   ocspReq.HashAlgorithm,
	}
	if f.known[serial] {
		template.Status = ocsp.Good
	}
	if rev, ok := f.revoked[serial]; ok {
		template.Status = ocsp.Revoked
		template.RevokedAt = rev.RevokedAt.UTC()
		template.RevocationReason = int(rev.Reason)
	}
	der, err := ocsp.CreateResponse(f.ca.Cert, f.ca.Cert, template, f.ca.Key)
	if err != nil {
		return nil, httperror.NewGrpc(codes.Internal, "unable to sign: %s", err.Error())
	}
	return &pb.OCSPResponse{Der: der}, nil
}

// testEnv is the service of the tests over the store and the fake CA, with
// the issuing CA of org 1: an Active leaf, an expired one, a revoked one,
// and the current CRL with the revoked one
type testEnv struct {
	svc     *aia.Service
	store   *testStore
	ca      *fakeCA
	handler http.Handler
	root    *testutils.TestCA
	issuing *testutils.TestCA
	issuer  *model.Issuer
	crl     *model.Crl
	leafCrt *x509.Certificate
	expCrt  *x509.Certificate
	revCrt  *x509.Certificate
	revRow  *model.Revoked
	other   *testutils.TestCA
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

	root := testutils.NewTestCA(t, "AIA Test Root", nil)
	issuing := testutils.NewTestCA(t, "AIA Test Issuing", root)
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

	leafCrt := issuing.Issue(t, "leaf.example.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	expiredCrt := issuing.Issue(t, "old.example.com", now.Add(-48*time.Hour), now.Add(-time.Hour))
	revCrt := issuing.Issue(t, "revoked.example.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	revRow := &model.Revoked{
		ID:            xdb.NewID(8001),
		OrgID:         orgID,
		ProjectID:     projectID,
		CertificateID: xdb.NewID(7003),
		Ikid:          issuer.Skid,
		SerialNumber:  revCrt.SerialNumber.String(),
		NotAfter:      xdb.UTC(revCrt.NotAfter),
		RevokedAt:     xdb.UTC(now.Add(-time.Minute)),
		Reason:        pb.ReasonCode_KeyCompromise,
		ReasonText:    "test",
	}

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
		CreatedAt:  xdb.UTC(now),
	}
	store.crls[crl.Ikid] = crl

	cadb := mocktrustycadb.NewMockCaReadonlyDb(ctrl)
	cadb.EXPECT().GetIssuerBySKID(gomock.Any(), gomock.Any()).DoAndReturn(store.getIssuerBySKID).AnyTimes()
	cadb.EXPECT().GetCrl(gomock.Any(), gomock.Any()).DoAndReturn(store.getCrl).AnyTimes()

	ca := newFakeCA(issuing)
	ca.register(leafCrt, nil)
	ca.register(expiredCrt, nil)
	ca.register(revCrt, revRow)

	svc, err := aia.New(&config.Configuration{}, cadb, shared.NewStaticBackendLocator(ca))
	require.NoError(t, err)
	r := restserver.NewRouter(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
	})
	svc.RegisterRoute(r)

	return &testEnv{
		svc:     svc,
		store:   store,
		ca:      ca,
		handler: r.Handler(),
		root:    root,
		issuing: issuing,
		issuer:  issuer,
		crl:     crl,
		leafCrt: leafCrt,
		expCrt:  expiredCrt,
		revCrt:  revCrt,
		revRow:  revRow,
		other:   testutils.NewTestCA(t, "Other Root", nil),
	}
}

// serve runs a request through the routes of the service
func (e *testEnv) serve(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w
}

// ocspRequest returns the DER OCSP request for the certificate of the
// issuing CA with the hash
func (e *testEnv) ocspRequest(t *testing.T, crt *x509.Certificate, hash crypto.Hash) []byte {
	t.Helper()
	der, err := ocsp.CreateRequest(crt, e.issuing.Cert, &ocsp.RequestOptions{Hash: hash})
	require.NoError(t, err)
	return der
}
