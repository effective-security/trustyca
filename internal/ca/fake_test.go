package ca_test

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
)

// fakeDb is a map-backed CaDb for the issuer, root and profile rows the
// registry and the bootstrap use; the methods it does not implement panic
// through the nil embedded interface. It counts the calls per method and
// can fail every query with Err.
type fakeDb struct {
	db.CaDb

	mu       sync.Mutex
	nextID   uint64
	issuers  map[uint64]*model.Issuer
	profiles map[uint64]*model.CertificateProfile
	roots    map[string]*model.RootCertificate
	revoked  map[uint64]*model.Revoked
	crls     map[string]*model.Crl
	calls    map[string]int
	// Err fails every query when set
	Err error
	// ErrOn fails the queries of the named method when set
	ErrOn string
	// Stale is the number of upcoming PublishCrl calls that behave as if
	// another publisher stored a CRL of the issuer first: the issuer
	// number is bumped and db.ErrStaleCrlNumber returned
	Stale int
}

func newFakeDb() *fakeDb {
	return &fakeDb{
		nextID:   1000,
		issuers:  map[uint64]*model.Issuer{},
		profiles: map[uint64]*model.CertificateProfile{},
		roots:    map[string]*model.RootCertificate{},
		revoked:  map[uint64]*model.Revoked{},
		crls:     map[string]*model.Crl{},
		calls:    map[string]int{},
	}
}

func notFound(table string, id any) error {
	return xdb.CheckNotFoundError(sql.ErrNoRows, table, id)
}

// enter counts the call and returns the configured failure
func (f *fakeDb) enter(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[name]++
	if f.Err == nil && f.ErrOn == name {
		return errors.Errorf("%s failed", name)
	}
	return f.Err
}

// Calls returns the number of calls of the method
func (f *fakeDb) Calls(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

// ResetCalls clears the call counters
func (f *fakeDb) ResetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = map[string]int{}
}

func (f *fakeDb) id() xdb.ID {
	f.nextID++
	return xdb.NewID(f.nextID)
}

func sameScope(orgID, projectID xdb.ID, org, project uint64) bool {
	return orgID.UInt64() == org && projectID.UInt64() == project
}

func (f *fakeDb) GetIssuer(_ context.Context, id uint64) (*model.Issuer, error) {
	if err := f.enter("GetIssuer"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.issuers[id]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFound("issuer", id)
}

func (f *fakeDb) FindIssuer(_ context.Context, orgID, projectID uint64, label string) (*model.Issuer, error) {
	if err := f.enter("FindIssuer"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.issuers {
		if sameScope(m.OrgID, m.ProjectID, orgID, projectID) && m.Label == label {
			res := *m
			return &res, nil
		}
	}
	return nil, notFound("issuer", fmt.Sprintf("%d/%d/%s", orgID, projectID, label))
}

func (f *fakeDb) GetIssuerBySKID(_ context.Context, skid string) (*model.Issuer, error) {
	if err := f.enter("GetIssuerBySKID"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.issuers {
		if m.Skid == skid {
			res := *m
			return &res, nil
		}
	}
	return nil, notFound("issuer", skid)
}

func (f *fakeDb) RegisterIssuer(_ context.Context, m *model.Issuer) (*model.Issuer, error) {
	if err := f.enter("RegisterIssuer"); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.issuers {
		if sameScope(r.OrgID, r.ProjectID, m.OrgID.UInt64(), m.ProjectID.UInt64()) && r.Label == m.Label {
			return nil, errors.New(`pq: duplicate key value violates unique constraint "unique_issuer_org_project_label"`)
		}
		if m.Skid != "" && r.Skid == m.Skid {
			return nil, errors.New(`pq: duplicate key value violates unique constraint "unique_issuer_skid"`)
		}
	}
	res := *m
	res.ID = f.id()
	res.CreatedAt = xdb.UTC(time.Now())
	res.UpdatedAt = res.CreatedAt
	f.issuers[res.ID.UInt64()] = &res
	out := res
	return &out, nil
}

func (f *fakeDb) UpdateIssuer(_ context.Context, req *query.UpdateIssuerRequest) (*model.Issuer, error) {
	if err := f.enter("UpdateIssuer"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.issuers[req.ID]
	if !ok || m.OrgID.UInt64() != req.OrgID {
		return nil, notFound("issuer", req.ID)
	}
	if req.Status != pb.IssuerStatus_Unknown {
		m.Status = req.Status
		if req.Status == pb.IssuerStatus_Destroyed {
			m.KeyProtected = ""
		}
	}
	if len(req.Config) > 0 {
		m.Config = model.JSON(req.Config)
	}
	// the DB clock has millisecond precision; make the update observable
	m.UpdatedAt = xdb.UTC(m.UpdatedAt.UTC().Add(time.Millisecond))
	res := *m
	return &res, nil
}

func (f *fakeDb) ActivateIssuer(_ context.Context, m *model.Issuer) (*model.Issuer, error) {
	if err := f.enter("ActivateIssuer"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.issuers[m.ID.UInt64()]
	if !ok || cur.Status != pb.IssuerStatus_Pending || cur.OrgID.UInt64() != m.OrgID.UInt64() {
		return nil, notFound("issuer", m.ID.UInt64())
	}
	res := *m
	res.Status = pb.IssuerStatus_Active
	res.CsrPem = ""
	res.UpdatedAt = xdb.UTC(cur.UpdatedAt.UTC().Add(time.Millisecond))
	f.issuers[res.ID.UInt64()] = &res
	out := res
	return &out, nil
}

func (f *fakeDb) RegisterRoot(_ context.Context, m *model.RootCertificate) (*model.RootCertificate, error) {
	if err := f.enter("RegisterRoot"); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.roots[m.Sha256]; ok {
		if cur.OrgID.UInt64() != m.OrgID.UInt64() {
			return nil, errors.WithStack(db.ErrRootConflict)
		}
		cur.Trust = m.Trust
		res := *cur
		return &res, nil
	}
	res := *m
	res.ID = f.id()
	res.CreatedAt = xdb.UTC(time.Now())
	f.roots[res.Sha256] = &res
	out := res
	return &out, nil
}

func (f *fakeDb) GetProfile(_ context.Context, id uint64) (*model.CertificateProfile, error) {
	if err := f.enter("GetProfile"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.profiles[id]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFound("certificate_profile", id)
}

func (f *fakeDb) FindProfile(_ context.Context, orgID, projectID uint64, label string) (*model.CertificateProfile, error) {
	if err := f.enter("FindProfile"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.profiles {
		if sameScope(m.OrgID, m.ProjectID, orgID, projectID) && m.Label == label {
			res := *m
			return &res, nil
		}
	}
	return nil, notFound("certificate_profile", fmt.Sprintf("%d/%d/%s", orgID, projectID, label))
}

func (f *fakeDb) RegisterProfile(_ context.Context, m *model.CertificateProfile) (*model.CertificateProfile, error) {
	if err := f.enter("RegisterProfile"); err != nil {
		return nil, err
	}
	im := *m
	if im.Status == pb.ItemStatus_Unknown {
		im.Status = pb.ItemStatus_Active
	}
	if err := im.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cur := range f.profiles {
		if sameScope(cur.OrgID, cur.ProjectID, im.OrgID.UInt64(), im.ProjectID.UInt64()) && cur.Label == im.Label {
			cur.IssuerLabel = im.IssuerLabel
			cur.Status = im.Status
			cur.Config = im.Config
			cur.UpdatedAt = xdb.UTC(cur.UpdatedAt.UTC().Add(time.Millisecond))
			res := *cur
			return &res, nil
		}
	}
	im.ID = f.id()
	im.CreatedAt = xdb.UTC(time.Now())
	im.UpdatedAt = im.CreatedAt
	f.profiles[im.ID.UInt64()] = &im
	res := im
	return &res, nil
}

func (f *fakeDb) DeleteProfile(_ context.Context, orgID, id uint64) (int64, error) {
	if err := f.enter("DeleteProfile"); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.profiles[id]; ok && m.OrgID.UInt64() == orgID {
		delete(f.profiles, id)
		return 1, nil
	}
	return 0, nil
}

// rootCount returns the number of trust anchors
func (f *fakeDb) rootCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.roots)
}

// clearRoots removes every trust anchor, as when a start failed between a
// root issuer and its anchor
func (f *fakeDb) clearRoots() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roots = map[string]*model.RootCertificate{}
}

// configJSON returns the stored config of the issuer as a generic document,
// for assertions on the stored settings
func (f *fakeDb) configJSON(id xdb.ID) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res map[string]any
	_ = json.Unmarshal([]byte(f.issuers[id.UInt64()].Config), &res)
	return res
}

// ListIssuers serves the org scope, project, visible projects and status
// of the request, newest first, paged by the cursor
func (f *fakeDb) ListIssuers(_ context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
	if err := f.enter("ListIssuers"); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var rows []*model.Issuer
	for _, m := range f.issuers {
		switch {
		case req.OrgID != 0 && m.OrgID.UInt64() != req.OrgID:
		case req.Platform && !m.OrgID.IsZero():
		case req.ProjectID != 0 && m.ProjectID.UInt64() != req.ProjectID:
		case req.ProjectID == 0 && req.ProjectIDs != nil && !m.ProjectID.IsZero() && !slices.Contains(req.ProjectIDs, m.ProjectID.UInt64()):
		case req.Status != pb.IssuerStatus_Unknown && m.Status != req.Status:
		default:
			row := *m
			rows = append(rows, &row)
		}
	}
	var res model.IssuerResult
	res.Rows = page(rows, func(m *model.Issuer) uint64 { return m.ID.UInt64() }, req.Limit, req.Cursor, &res.HasNextPage, &res.Cursor)
	return &res, nil
}

// revoke records the revocation of a certificate of the issuer, as
// RevokeCertificate copies it from the certificate row
func (f *fakeDb) revoke(issuer *model.Issuer, serial string, notAfter, revokedAt time.Time, reason pb.ReasonCode_Enum) *model.Revoked {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := &model.Revoked{
		ID:            f.id(),
		OrgID:         issuer.OrgID,
		ProjectID:     issuer.ProjectID,
		CertificateID: f.id(),
		Ikid:          issuer.Skid,
		SerialNumber:  serial,
		NotAfter:      xdb.UTC(notAfter),
		RevokedAt:     xdb.UTC(revokedAt),
		Reason:        reason,
	}
	f.revoked[m.ID.UInt64()] = m
	res := *m
	return &res
}

// ListRevoked serves the org scope, IKID and validity of the request,
// newest first, paged by the cursor
func (f *fakeDb) ListRevoked(_ context.Context, req *query.ListRevokedRequest) (*model.RevokedResult, error) {
	if err := f.enter("ListRevoked"); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var rows []*model.Revoked
	for _, m := range f.revoked {
		switch {
		case req.OrgID != 0 && m.OrgID.UInt64() != req.OrgID:
		case req.IKID != "" && m.Ikid != req.IKID:
		case req.ValidAfter != nil && !m.NotAfter.UTC().After(*req.ValidAfter):
		default:
			row := *m
			rows = append(rows, &row)
		}
	}
	var res model.RevokedResult
	res.Rows = page(rows, func(m *model.Revoked) uint64 { return m.ID.UInt64() }, req.Limit, req.Cursor, &res.HasNextPage, &res.Cursor)
	return &res, nil
}

// page sorts the rows newest first and returns the page of the cursor and
// limit, setting the next cursor when the page is full, as listRows does
func page[T any](rows []*T, id func(*T) uint64, limit uint32, cursor query.Cursor, hasNext *bool, next *string) []*T {
	slices.SortFunc(rows, func(a, b *T) int {
		return cmp.Compare(id(b), id(a))
	})
	if lastID := cursor.LastID(); lastID != 0 {
		rows = slices.DeleteFunc(rows, func(m *T) bool { return id(m) >= lastID })
	}
	if limit != 0 && uint32(len(rows)) > limit {
		rows = rows[:limit]
	}
	if limit != 0 && uint32(len(rows)) == limit && cursor.IsSet() {
		*hasNext = true
		*next = query.EncodeCursor(xdb.NewID(id(rows[len(rows)-1])))
	}
	return rows
}

func (f *fakeDb) GetCrl(_ context.Context, ikid string) (*model.Crl, error) {
	if err := f.enter("GetCrl"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.crls[ikid]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFound("crl", ikid)
}

// PublishCrl stores the CRL and the number on the issuer as the DB does:
// the IKID must be the issuer's SKID and the number greater than the
// issuer's, else nothing is stored
func (f *fakeDb) GetCrls(_ context.Context, ikids []string) ([]*model.Crl, error) {
	if err := f.enter("GetCrls"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var res []*model.Crl
	for _, ikid := range ikids {
		if m, ok := f.crls[ikid]; ok {
			row := *m
			res = append(res, &row)
		}
	}
	return res, nil
}

func (f *fakeDb) PublishCrl(_ context.Context, m *model.Crl) (*model.Crl, error) {
	if err := f.enter("PublishCrl"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	issuer, ok := f.issuers[m.IssuerID.UInt64()]
	if !ok {
		return nil, notFound("issuer", m.IssuerID.UInt64())
	}
	if issuer.Skid != m.Ikid {
		return nil, errors.Errorf("crl ikid %s does not match issuer %s", m.Ikid, m.IssuerID.String())
	}
	if f.Stale > 0 {
		f.Stale--
		issuer.CrlNumber = m.CrlNumber
		f.crls[m.Ikid] = &model.Crl{
			ID:         f.id(),
			OrgID:      issuer.OrgID,
			ProjectID:  issuer.ProjectID,
			IssuerID:   issuer.ID,
			Ikid:       issuer.Skid,
			CrlNumber:  m.CrlNumber,
			ThisUpdate: m.ThisUpdate,
			NextUpdate: m.NextUpdate,
			Issuer:     issuer.Subject,
			Pem:        "other publisher",
			CreatedAt:  xdb.UTC(time.Now()),
		}
		return nil, errors.WithStack(db.ErrStaleCrlNumber)
	}
	if m.CrlNumber <= issuer.CrlNumber {
		return nil, errors.WithStack(db.ErrStaleCrlNumber)
	}
	res := *m
	res.OrgID = issuer.OrgID
	res.ProjectID = issuer.ProjectID
	res.Issuer = issuer.Subject
	if err := res.Validate(); err != nil {
		return nil, err
	}
	if cur, ok := f.crls[m.Ikid]; ok {
		res.ID = cur.ID
		res.CreatedAt = cur.CreatedAt
	} else {
		res.ID = f.id()
		res.CreatedAt = xdb.UTC(time.Now())
	}
	issuer.CrlNumber = res.CrlNumber
	f.crls[res.Ikid] = &res
	out := res
	return &out, nil
}

// setCrlNextUpdate moves the next update of the current CRL of the issuer,
// to make it due or not
func (f *fakeDb) setCrlNextUpdate(ikid string, nextUpdate time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.crls[ikid].NextUpdate = xdb.UTC(nextUpdate)
}

// setIssuerStatus changes the status of a stored issuer
func (f *fakeDb) setIssuerStatus(id xdb.ID, status pb.IssuerStatus_Enum) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issuers[id.UInt64()].Status = status
}

// setIssuerNotAfter changes the expiry of a stored issuer
func (f *fakeDb) setIssuerNotAfter(id xdb.ID, notAfter time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issuers[id.UInt64()].NotAfter = xdb.UTC(notAfter)
}
