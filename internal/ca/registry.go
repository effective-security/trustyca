package ca

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"encoding/hex"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/internal", "ca")

const (
	// DefaultCacheTTL bounds the staleness of the cached issuers and
	// profiles when the configuration sets none: a change made by another
	// instance is visible within five minutes (DESIGN.md section 5.1)
	DefaultCacheTTL = 5 * time.Minute
	// DefaultCacheSize is the number of issuers kept in memory when the
	// configuration sets none
	DefaultCacheSize = 1000

	// labelCacheFactor sizes the label and profile caches relative to the
	// issuer cache: an issuer is reached from several scopes and profiles
	labelCacheFactor = 4
	// buildLocks is the number of locks that serialize the construction of
	// one issuer; the lock of an issuer is its ID modulo the count
	buildLocks = 64
)

// Options configure a Registry
type Options struct {
	// TTL bounds the staleness of the cached issuers and profiles; a change
	// made by another instance is visible after it. Zero is DefaultCacheTTL.
	TTL time.Duration
	// Size is the number of issuers kept in memory; the least recently used
	// is evicted first. Zero is DefaultCacheSize.
	Size int
}

// Registry resolves the issuer and the profile that serve a tenant request
// and keeps the built authority issuers in memory.
//
// Every lookup names its tenant scope: a label resolves in the project, then
// in the org, never in the platform or in another org (DESIGN.md section 6),
// and the DB finds rows by exact scope. The built issuers are cached by row
// ID, which is unique across orgs, so equal labels of different orgs or
// projects never collide; the resolutions of a scope and label are cached
// under the requested scope. Both caches are bounded by size and TTL, and a
// mutation made through this instance invalidates its entries at once
// (InvalidateIssuer, InvalidateProfile); a mutation made by another instance
// is visible after the TTL. Resolutions that fail are not cached.
//
// A Registry is safe for concurrent use.
type Registry struct {
	db   db.CaReadonlyDb
	keys *Keys

	// issuers caches the built issuers by row ID
	issuers *expirable.LRU[uint64, *issuerEntry]
	// issuerLabels caches the row a scope and label resolve to, under the
	// requested scope: a project key may hold the org-wide row
	issuerLabels *expirable.LRU[scopeKey, *model.Issuer]
	// profiles caches the profile a scope and label resolve to
	profiles *expirable.LRU[scopeKey, *model.CertificateProfile]
	// builds serialize the construction of one issuer, so that a burst of
	// cold requests loads its key once
	builds [buildLocks]sync.Mutex
}

// scopeKey is the exact tenant scope and label of a cached resolution
type scopeKey struct {
	orgID     uint64
	projectID uint64
	label     string
}

// issuerEntry is a built issuer with the row it was built from and the
// profiles bound to any issuer that the row allows
type issuerEntry struct {
	row     *model.Issuer
	issuer  *authority.Issuer
	allowed []string
}

// ResolveRequest names the issuer and the profile of a sign request
type ResolveRequest struct {
	// OrgID is the org of the request; required
	OrgID xdb.ID
	// ProjectID is the project of the request; zero is the org scope
	ProjectID xdb.ID
	// Profile is the label of the profile; required
	Profile string
	// IssuerLabel selects the issuer when the profile binds to any issuer;
	// otherwise it must be empty or the profile's issuer
	IssuerLabel string
}

// Resolution is the issuer and the profile that sign a request
type Resolution struct {
	// Issuer signs with the key of Row
	Issuer *authority.Issuer
	// Row is the issuer row
	Row *model.Issuer
	// ProfileRow is the profile row the request resolved to
	ProfileRow *model.CertificateProfile
	// Profile is the authority profile of ProfileRow
	Profile *authority.CertProfile
	// ProfileName is the name Profile is registered under in Issuer; a
	// csr.SignRequest names it in Profile
	ProfileName string
}

// NewRegistry returns a registry over the CA tables and the key management
func NewRegistry(caDb db.CaReadonlyDb, keys *Keys, opts Options) *Registry {
	ttl := cmp.Or(opts.TTL, DefaultCacheTTL)
	size := cmp.Or(opts.Size, DefaultCacheSize)
	return &Registry{
		db:           caDb,
		keys:         keys,
		issuers:      expirable.NewLRU[uint64, *issuerEntry](size, nil, ttl),
		issuerLabels: expirable.NewLRU[scopeKey, *model.Issuer](size*labelCacheFactor, nil, ttl),
		profiles:     expirable.NewLRU[scopeKey, *model.CertificateProfile](size*labelCacheFactor, nil, ttl),
	}
}

// Keys returns the key management of the registry
func (r *Registry) Keys() *Keys {
	return r.keys
}

// Resolve returns the issuer and the profile of a sign request: the profile
// of the scope, the issuer it binds to (or the requested one, when the
// profile binds to any issuer that allows it), which must be Active, with
// the profile registered on the issuer.
func (r *Registry) Resolve(ctx context.Context, req *ResolveRequest) (*Resolution, error) {
	if req == nil || req.Profile == "" {
		return nil, errors.New("profile is required")
	}
	profile, err := r.FindProfile(ctx, req.OrgID, req.ProjectID, req.Profile)
	if err != nil {
		return nil, err
	}
	label := profile.IssuerLabel
	anyIssuer := label == model.AnyIssuerLabel
	switch {
	case anyIssuer && req.IssuerLabel == "":
		return nil, errors.WithStack(ErrIssuerLabelRequired)
	case anyIssuer:
		label = req.IssuerLabel
	case req.IssuerLabel != "" && req.IssuerLabel != label:
		return nil, errors.WithStack(ErrIssuerMismatch)
	}
	row, err := r.FindIssuer(ctx, req.OrgID, req.ProjectID, label)
	if err != nil {
		return nil, err
	}
	if row.Status != pb.IssuerStatus_Active {
		return nil, errors.WithStack(ErrIssuerNotActive)
	}
	entry, err := r.entry(ctx, row)
	if err != nil {
		return nil, err
	}
	if !profileBinds(profile, entry.row, entry.allowed) {
		return nil, errors.WithStack(ErrProfileNotAllowed)
	}
	name, ap, err := addProfile(entry.issuer, profile)
	if err != nil {
		return nil, err
	}
	return &Resolution{
		Issuer:      entry.issuer,
		Row:         entry.row,
		ProfileRow:  profile,
		Profile:     ap,
		ProfileName: name,
	}, nil
}

// FindProfile returns the active profile with the label of the project, or
// of the org when the project has none; an inactive profile is not found
// and does not fall back to the org
func (r *Registry) FindProfile(ctx context.Context, orgID, projectID xdb.ID, label string) (*model.CertificateProfile, error) {
	key := scopeKey{
		orgID:     orgID.UInt64(),
		projectID: projectID.UInt64(),
		label:     label,
	}
	if p, ok := r.profiles.Get(key); ok {
		return p, nil
	}
	p, err := r.db.FindProfile(ctx, key.orgID, key.projectID, key.label)
	if err != nil && xdb.IsNotFoundError(err) && key.projectID != 0 {
		p, err = r.db.FindProfile(ctx, key.orgID, 0, key.label)
	}
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, errors.WithStack(ErrProfileNotFound)
		}
		return nil, errors.WithMessage(err, "unable to find profile")
	}
	if p.Status != pb.ItemStatus_Active {
		return nil, errors.WithStack(ErrProfileNotFound)
	}
	r.profiles.Add(key, p)
	return p, nil
}

// FindIssuer returns the issuer with the label of the project, or of the
// org when the project has none, in any lifecycle status
func (r *Registry) FindIssuer(ctx context.Context, orgID, projectID xdb.ID, label string) (*model.Issuer, error) {
	key := scopeKey{
		orgID:     orgID.UInt64(),
		projectID: projectID.UInt64(),
		label:     label,
	}
	if m, ok := r.issuerLabels.Get(key); ok {
		return m, nil
	}
	m, err := r.db.FindIssuer(ctx, key.orgID, key.projectID, key.label)
	if err != nil && xdb.IsNotFoundError(err) && key.projectID != 0 {
		m, err = r.db.FindIssuer(ctx, key.orgID, 0, key.label)
	}
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, errors.WithStack(ErrIssuerNotFound)
		}
		return nil, errors.WithMessage(err, "unable to find issuer")
	}
	r.issuerLabels.Add(key, m)
	return m, nil
}

// Issuer returns the authority issuer of the row, built from its
// certificate, chain and key on the first use and kept until the TTL, an
// eviction or an invalidation
func (r *Registry) Issuer(ctx context.Context, row *model.Issuer) (*authority.Issuer, error) {
	entry, err := r.entry(ctx, row)
	if err != nil {
		return nil, err
	}
	return entry.issuer, nil
}

// IssuerBySKID returns the issuer whose Subject Key Identifier is the IKID
// of the certificates it issued, for revocation status: an Active or
// Archived issuer, since an Archived one still answers for its certificates
func (r *Registry) IssuerBySKID(ctx context.Context, skid string) (*authority.Issuer, *model.Issuer, error) {
	for _, e := range r.issuers.Values() {
		if e.row.Skid == skid {
			return e.issuer, e.row, nil
		}
	}
	row, err := r.db.GetIssuerBySKID(ctx, skid)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, nil, errors.WithStack(ErrIssuerNotFound)
		}
		return nil, nil, errors.WithMessage(err, "unable to find issuer")
	}
	if row.Status != pb.IssuerStatus_Active && row.Status != pb.IssuerStatus_Archived {
		return nil, nil, errors.WithStack(ErrIssuerNotActive)
	}
	entry, err := r.entry(ctx, row)
	if err != nil {
		return nil, nil, err
	}
	return entry.issuer, entry.row, nil
}

// IssuerByKeyHash returns the issuer whose public key has the hash, as an
// OCSP request identifies it. The issuers in memory are matched for any
// algorithm; a SHA-1 hash is also the Subject Key Identifier of a CA
// certificate this CA issued (RFC 5280 method 1), so it is looked up in the
// DB. A certificate of an issuer that is not in memory and whose key
// identifier is not its SHA-1 key hash is not found.
func (r *Registry) IssuerByKeyHash(ctx context.Context, alg crypto.Hash, hash []byte) (*authority.Issuer, *model.Issuer, error) {
	for _, e := range r.issuers.Values() {
		if bytes.Equal(e.issuer.KeyHash(alg), hash) {
			return e.issuer, e.row, nil
		}
	}
	if alg != crypto.SHA1 {
		return nil, nil, errors.WithStack(ErrIssuerNotFound)
	}
	return r.IssuerBySKID(ctx, hex.EncodeToString(hash))
}

// IssuerByNameHash returns the issuer whose subject name has the hash, as
// an OCSP request may identify it; only the issuers in memory are matched
func (r *Registry) IssuerByNameHash(_ context.Context, alg crypto.Hash, hash []byte) (*authority.Issuer, *model.Issuer, error) {
	for _, e := range r.issuers.Values() {
		if bytes.Equal(e.issuer.NameHash(alg), hash) {
			return e.issuer, e.row, nil
		}
	}
	return nil, nil, errors.WithStack(ErrIssuerNotFound)
}

// InvalidateIssuer drops the issuer and the resolutions of its label from
// memory, after a mutation of its row is committed
func (r *Registry) InvalidateIssuer(row *model.Issuer) {
	if row == nil {
		return
	}
	r.issuers.Remove(row.ID.UInt64())
	invalidateLabel(r.issuerLabels, row.OrgID, row.ProjectID, row.Label)
}

// InvalidateProfile drops the resolutions of the profile label of the scope
// from memory, after a mutation of the profile is committed: a project
// profile from its project, an org profile from every project of the org
func (r *Registry) InvalidateProfile(orgID, projectID xdb.ID, label string) {
	invalidateLabel(r.profiles, orgID, projectID, label)
}

// Purge drops every cached issuer and resolution
func (r *Registry) Purge() {
	r.issuers.Purge()
	r.issuerLabels.Purge()
	r.profiles.Purge()
}

// Len returns the number of issuers in memory
func (r *Registry) Len() int {
	return r.issuers.Len()
}

// entry returns the built issuer of the row, building it under the lock of
// its ID when it is not in memory or the row is newer than the build
func (r *Registry) entry(ctx context.Context, row *model.Issuer) (*issuerEntry, error) {
	id := row.ID.UInt64()
	if e, ok := r.issuers.Get(id); ok && !newer(row, e.row) {
		return e, nil
	}
	mu := &r.builds[id%buildLocks]
	mu.Lock()
	defer mu.Unlock()
	if e, ok := r.issuers.Get(id); ok && !newer(row, e.row) {
		return e, nil
	}
	e, err := r.build(ctx, row)
	if err != nil {
		return nil, err
	}
	r.issuers.Add(id, e)
	return e, nil
}

// newer returns true when the row was updated after the built one
func newer(row, built *model.Issuer) bool {
	return row.UpdatedAt.UTC().After(built.UpdatedAt.UTC())
}

// build creates the authority issuer of the row: its runtime settings, the
// profile of its delegated OCSP responder when it has one, its key and its
// certificate chain
func (r *Registry) build(ctx context.Context, row *model.Issuer) (*issuerEntry, error) {
	id := idString(row.ID)
	if row.Pem == "" {
		return nil, errors.Errorf("issuer %s has no certificate", id)
	}
	cfg, err := row.GetConfig()
	if err != nil {
		return nil, err
	}
	acfg, err := pbconv.IssuerConfigFromPb(row.Label, cfg)
	if err != nil {
		return nil, errors.WithMessagef(err, "invalid config of issuer %s", id)
	}
	if name := acfg.AIA.DelegatedOCSPProfile; name != "" {
		p, err := r.FindProfile(ctx, row.OrgID, row.ProjectID, name)
		if err != nil {
			if errors.Is(err, ErrProfileNotFound) {
				// the profile of the request exists: a responder profile the
				// issuer names and that is missing is the issuer's failure,
				// not one the caller fixes by changing the request
				return nil, errors.Errorf("delegated OCSP profile %q of issuer %s is not found", name, id)
			}
			return nil, errors.WithMessagef(err, "delegated OCSP profile %q of issuer %s", name, id)
		}
		if !profileBinds(p, row, cfg.AllowedProfiles) {
			return nil, errors.Errorf("delegated OCSP profile %q is not bound to issuer %s", name, id)
		}
		ap, err := AuthorityProfile(p)
		if err != nil {
			return nil, err
		}
		acfg.Profiles[name] = ap
	}
	signer, err := r.keys.Signer(ctx, row)
	if err != nil {
		return nil, err
	}
	issuer, err := createIssuer(acfg, []byte(row.Pem), []byte(row.ChainPem), []byte(row.RootPem), signer)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to create issuer %s", id)
	}
	logger.ContextKV(ctx, xlog.DEBUG,
		"status", "issuer_loaded",
		"issuer_id", id,
		"org_id", idString(row.OrgID),
		"project_id", idString(row.ProjectID),
		"issuer", row.Label,
		"skid", row.Skid)
	return &issuerEntry{
		row:     row,
		issuer:  issuer,
		allowed: cfg.AllowedProfiles,
	}, nil
}

// profileBinds reports whether the profile binds to the issuer: by its
// label, or to any issuer that lists it in AllowedProfiles
func profileBinds(p *model.CertificateProfile, row *model.Issuer, allowed []string) bool {
	if p.IssuerLabel == model.AnyIssuerLabel {
		return slices.Contains(allowed, p.Label)
	}
	return p.IssuerLabel == row.Label
}

// addProfile registers the profile on the issuer under its versioned name,
// once per version of the profile, and returns the name and the profile
func addProfile(issuer *authority.Issuer, p *model.CertificateProfile) (string, *authority.CertProfile, error) {
	name := profileName(p)
	if ap := issuer.Profile(name); ap != nil {
		return name, ap, nil
	}
	ap, err := AuthorityProfile(p)
	if err != nil {
		return "", nil, err
	}
	issuer.AddProfile(name, ap)
	return name, ap, nil
}

// profileName is the name a profile row is registered under in an issuer.
// An issuer serves profiles of several scopes with equal labels, and a
// replaced profile keeps its ID, so the name is the ID and the version.
func profileName(p *model.CertificateProfile) string {
	return idString(p.ID) + "@" + strconv.FormatInt(p.UpdatedAt.UnixMilli(), 10)
}

// idString formats an ID of a row that goroutines share: xdb.ID.String
// caches its result without synchronization, so the cached rows are never
// formatted with it
func idString(id xdb.ID) string {
	return xdb.IDString(id.UInt64())
}

// AuthorityProfile converts a profile row to the profile the authority
// signs with. It reads the row only: a row the registry returned is shared
// with other requests, and its IDs must not be formatted (model.Definition).
func AuthorityProfile(p *model.CertificateProfile) (*authority.CertProfile, error) {
	def, err := p.Definition()
	if err != nil {
		return nil, err
	}
	ap, err := pbconv.ProfileFromPb(def)
	if err != nil {
		return nil, errors.WithMessagef(err, "profile %s", idString(p.ID))
	}
	return ap, nil
}

// invalidateLabel removes the resolutions of the label of the scope: the
// exact key of a project scope, every key of the org for the org scope
func invalidateLabel[V any](c *expirable.LRU[scopeKey, V], orgID, projectID xdb.ID, label string) {
	org := orgID.UInt64()
	if project := projectID.UInt64(); project != 0 {
		c.Remove(scopeKey{
			orgID:     org,
			projectID: project,
			label:     label,
		})
		return
	}
	for _, key := range c.Keys() {
		if key.orgID == org && key.label == label {
			c.Remove(key)
		}
	}
}

// createIssuer creates the authority issuer of a certificate, its chain and
// its root. A self-signed certificate is its own root and the bundler
// refuses it as a leaf under trust roots, so it is built without them, as
// the authority builds its roots.
func createIssuer(cfg *authority.IssuerConfig, certPEM, chainPEM, rootPEM []byte, signer crypto.Signer) (*authority.Issuer, error) {
	crt, err := certutil.ParseFromPEM(certPEM)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid certificate")
	}
	if IsSelfSigned(crt) {
		chainPEM, rootPEM = nil, nil
	}
	return authority.CreateIssuer(cfg, certPEM, chainPEM, rootPEM, signer)
}
