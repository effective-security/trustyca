package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/x/fileutil/resolve"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"google.golang.org/protobuf/proto"
)

// issuerIDEnvVariables are the spellings of the issuer placeholder that the
// config loader expands as an environment variable (os.Expand)
var issuerIDEnvVariables = []string{pbconv.IssuerIDVariable, "$ISSUER_ID"}

// LoadBootstrapConfig loads the ca-config of the platform bootstrap with
// authority.LoadConfig, which expands `$VAR` and `${VAR}` as environment
// variables in every value: a `${ISSUER_ID}` in the AIA, CRL or OCSP URL
// template of an issuer would become an empty string, and every certificate
// the issuer signs would name the URL without the issuer. A file whose
// templates name the issuer that way is refused before it is loaded; file
// issuers use pbconv.IssuerIDPlaceholder (`:ISSUER_ID`).
func LoadBootstrapConfig(path string) (*authority.Config, error) {
	if path == "" {
		return nil, errors.New("CA config path is required")
	}
	// the values as written, before the loader expands them
	var raw authority.Config
	err := configloader.Unmarshal(resolve.ExpandPath(path), &raw)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to read CA config")
	}
	if raw.Authority != nil {
		for _, iss := range raw.Authority.Issuers {
			if iss.AIA == nil {
				continue
			}
			for _, tmpl := range []string{iss.AIA.AiaURL, iss.AIA.CrlURL, iss.AIA.OcspURL} {
				if slices.ContainsFunc(issuerIDEnvVariables, func(v string) bool { return strings.Contains(tmpl, v) }) {
					return nil, errors.Errorf("issuer %q: the URL template %q names the issuer as an environment variable, which the config loader expands: use %s",
						iss.Label, tmpl, pbconv.IssuerIDPlaceholder)
				}
			}
		}
	}
	cfg, err := authority.LoadConfig(path)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to load CA config")
	}
	return cfg, nil
}

// BootstrapResult counts the rows a bootstrap registered or updated
type BootstrapResult struct {
	// Issuers is the number of issuers registered
	Issuers int
	// Updated is the number of issuers whose runtime settings changed, or
	// that the configuration enabled again
	Updated int
	// Archived is the number of issuers the configuration disabled
	Archived int
	// Roots is the number of trust anchors registered or refreshed
	Roots int
	// Profiles is the number of profiles registered or replaced
	Profiles int
}

// Bootstrap mirrors the issuers, trust anchors and profiles of a ca-config
// into the platform rows (org_id IS NULL), so that the platform issuers
// sign tenant CA certificates and CIS serves their chains from the same
// tables (DESIGN.md section 5.1), then loads every enabled issuer, so that
// a key that does not load or a delegated OCSP profile that does not bind
// fails the start instead of the first request.
//
// It is idempotent: a registered issuer with the same key only has its
// runtime settings refreshed, roots are registered by thumbprint and
// profiles are replaced by label. It is also safe when several instances
// start against one fresh DB at once: an issuer insert that loses the race
// to another instance continues with the row that instance registered. The key of an issuer is a key URI, stored
// as the reference, or key material, stored wrapped; both are checked
// against the certificate. An issuer whose certificate is for a new key is
// an error: renewal keeps the label unique, so the old issuer must be
// archived under another label first. A disabled issuer is archived, so
// that it stops signing on every instance, and enabled again when the
// configuration enables it; a destroyed one has no key and is an error.
// The anchor of a root issuer is written in the transaction of the issuer
// insert, and registered again on every start from the stored certificate,
// which restores an anchor that was deleted or that a version without the
// transaction failed to write.
func (r *Registry) Bootstrap(ctx context.Context, caDb db.CaDb, cfg *authority.Config) (*BootstrapResult, error) {
	if cfg == nil {
		return nil, errors.New("authority configuration is required")
	}
	res := &BootstrapResult{}
	var enabled []string
	if cfg.Authority != nil {
		rootBundle, err := certutil.LoadPEMFiles(cfg.Authority.RootsBundleFiles...)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to load root bundles")
		}
		caBundle, err := certutil.LoadPEMFiles(cfg.Authority.CABundleFiles...)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to load CA bundles")
		}
		res.Roots, err = registerRoots(ctx, caDb, rootBundle)
		if err != nil {
			return nil, err
		}
		for i := range cfg.Authority.Issuers {
			isscfg := &cfg.Authority.Issuers[i]
			if isscfg.GetDisabled() {
				archived, err := r.archiveIssuer(ctx, caDb, isscfg.Label)
				if err != nil {
					return nil, errors.WithMessagef(err, "issuer %q", isscfg.Label)
				}
				if archived {
					res.Archived++
				}
				continue
			}
			outcome, err := r.bootstrapIssuer(ctx, caDb, isscfg, caBundle, rootBundle)
			if err != nil {
				return nil, errors.WithMessagef(err, "issuer %q", isscfg.Label)
			}
			if outcome.registered {
				res.Issuers++
			}
			if outcome.updated {
				res.Updated++
			}
			if outcome.root {
				res.Roots++
			}
			enabled = append(enabled, isscfg.Label)
		}
	}
	for _, label := range slices.Sorted(maps.Keys(cfg.Profiles)) {
		profile := cfg.Profiles[label]
		if profile == nil {
			return nil, errors.Errorf("profile %q is empty", label)
		}
		err := profile.Validate()
		if err != nil {
			return nil, errors.WithMessagef(err, "profile %q", label)
		}
		def := pbconv.ProfileToPb(label, profile)
		if def.IssuerLabel == "" {
			// a self-signing profile of a ca-config without issuers
			def.IssuerLabel = model.AnyIssuerLabel
		}
		m, err := model.NewCertificateProfile(xdb.ID(0), xdb.ID(0), def)
		if err != nil {
			return nil, errors.WithMessagef(err, "profile %q", label)
		}
		_, err = caDb.RegisterProfile(ctx, m)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to register profile %q", label)
		}
		r.InvalidateProfile(xdb.ID(0), xdb.ID(0), label)
		res.Profiles++
	}
	// the enabled issuers load with their keys and delegated OCSP profiles,
	// or the start fails
	for _, label := range enabled {
		row, err := r.FindIssuer(ctx, xdb.ID(0), xdb.ID(0), label)
		if err != nil {
			return nil, errors.WithMessagef(err, "issuer %q", label)
		}
		_, err = r.entry(ctx, row)
		if err != nil {
			return nil, errors.WithMessagef(err, "issuer %q", label)
		}
	}
	logger.KV(xlog.NOTICE,
		"status", "bootstrapped",
		"issuers", res.Issuers,
		"updated", res.Updated,
		"archived", res.Archived,
		"roots", res.Roots,
		"profiles", res.Profiles)
	return res, nil
}

// registerRoots registers the self-signed certificates of the bundle as
// private platform trust anchors
func registerRoots(ctx context.Context, caDb db.CaDb, bundle []byte) (int, error) {
	if len(strings.TrimSpace(string(bundle))) == 0 {
		return 0, nil
	}
	certs, err := certutil.ParseChainFromPEM(bundle)
	if err != nil {
		return 0, errors.WithMessage(err, "invalid root bundle")
	}
	count := 0
	for _, crt := range certs {
		if !IsSelfSigned(crt) {
			continue
		}
		pem, err := certutil.EncodeToPEMString(false, crt)
		if err != nil {
			return 0, errors.WithMessage(err, "unable to encode root certificate")
		}
		_, err = caDb.RegisterRoot(ctx, model.NewRootCertificate(crt, xdb.ID(0), pb.Trust_Private, pem))
		if err != nil {
			return 0, errors.WithMessagef(err, "unable to register root %q", crt.Subject.String())
		}
		count++
	}
	return count, nil
}

// issuerOutcome reports what the bootstrap of one issuer did
type issuerOutcome struct {
	// registered is true when the issuer row was inserted
	registered bool
	// updated is true when the row was changed: its runtime settings
	// replaced, or the issuer enabled again
	updated bool
	// root is true when the issuer is a root and its trust anchor was
	// registered or refreshed
	root bool
}

// archiveIssuer archives the registered platform issuer of a disabled
// ca-config entry, so that it stops signing on every instance once its
// cached resolutions expire; it returns whether it did. An issuer that is
// not registered, or not Active, is left as it is.
func (r *Registry) archiveIssuer(ctx context.Context, caDb db.CaDb, label string) (bool, error) {
	if label == "" {
		return false, errors.New("label is required")
	}
	existing, err := caDb.FindIssuer(ctx, 0, 0, label)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			logger.KV(xlog.INFO, "reason", "disabled", "issuer", label)
			return false, nil
		}
		return false, errors.WithMessage(err, "unable to find issuer")
	}
	if existing.Status != pb.IssuerStatus_Active {
		return false, nil
	}
	row, err := caDb.UpdateIssuer(ctx, &query.UpdateIssuerRequest{
		ID:     existing.ID.UInt64(),
		OrgID:  0,
		Status: pb.IssuerStatus_Archived,
	})
	if err != nil {
		return false, errors.WithMessage(err, "unable to archive issuer")
	}
	r.InvalidateIssuer(row)
	logger.KV(xlog.NOTICE,
		"status", "issuer_archived",
		"reason", "disabled",
		"issuer_id", idString(row.ID),
		"issuer", label)
	return true, nil
}

// bootstrapIssuer registers the issuer of a ca-config as a platform row, or
// brings the registered one up to date
func (r *Registry) bootstrapIssuer(ctx context.Context, caDb db.CaDb, isscfg *authority.IssuerConfig, caBundle, rootBundle []byte) (issuerOutcome, error) {
	var out issuerOutcome
	label := isscfg.Label
	if label == "" {
		return out, errors.New("label is required")
	}
	certPEM, err := os.ReadFile(isscfg.CertFile)
	if err != nil {
		return out, errors.WithMessage(err, "unable to read certificate")
	}
	crt, err := certutil.ParseFromPEM(certPEM)
	if err != nil {
		return out, errors.WithMessage(err, "invalid certificate")
	}
	skid := certutil.GetSubjectKeyID(crt)
	cfg := pbconv.IssuerConfigToPb(isscfg)

	existing, err := caDb.FindIssuer(ctx, 0, 0, label)
	switch {
	case err == nil && existing.Skid == skid:
		return r.refreshIssuer(ctx, caDb, existing, cfg)
	case err == nil:
		return out, errors.Errorf("the certificate is for key %s and the registered issuer has key %s: archive the registered issuer under another label before renewing it", skid, existing.Skid)
	case !xdb.IsNotFoundError(err):
		return out, errors.WithMessage(err, "unable to find issuer")
	}

	key, err := os.ReadFile(isscfg.KeyFile)
	if err != nil {
		return out, errors.WithMessage(err, "unable to read key")
	}
	key = []byte(strings.TrimSpace(string(key)))
	keyLabel := KeyLabel(xdb.ID(0), xdb.ID(0), label)
	var signer crypto.Signer
	var ref *KeyRef
	if IsKeyURI(string(key)) {
		signer, ref, err = r.keys.ImportKey(ctx, string(key), nil, keyLabel, crt.PublicKey)
	} else {
		signer, ref, err = r.keys.ImportKey(ctx, "", key, keyLabel, crt.PublicKey)
	}
	if err != nil {
		return out, err
	}

	chainPEM := caBundle
	if isscfg.CABundleFile != "" {
		b, err := os.ReadFile(isscfg.CABundleFile)
		if err != nil {
			return out, errors.WithMessage(err, "unable to read CA bundle")
		}
		chainPEM = certutil.JoinPEM(b, caBundle)
	}
	rootPEM := rootBundle
	if isscfg.RootBundleFile != "" {
		b, err := os.ReadFile(isscfg.RootBundleFile)
		if err != nil {
			return out, errors.WithMessage(err, "unable to read root bundle")
		}
		rootPEM = certutil.JoinPEM(b, rootBundle)
	}

	m := &model.Issuer{
		Label:  label,
		Type:   issuerType(crt),
		Status: pb.IssuerStatus_Active,
	}
	ref.Apply(m)
	err = m.SetConfig(cfg)
	if err != nil {
		return out, err
	}
	err = setVerifiedCertificate(m, cfg, crt, string(chainPEM), string(rootPEM), signer)
	if err != nil {
		return out, err
	}
	if ikid := m.Ikid; ikid != "" && ikid != skid {
		parent, err := caDb.GetIssuerBySKID(ctx, ikid)
		switch {
		case err == nil && parent.OrgID.IsZero():
			m.ParentID = parent.ID
		case err != nil && !xdb.IsNotFoundError(err):
			return out, errors.WithMessage(err, "unable to find parent issuer")
		}
	}
	var anchor *model.RootCertificate
	if m.Type == pb.AuthorityType_Root {
		// a self-signed issuer is a private anchor of the platform, written
		// with its row
		anchor = model.NewRootCertificate(crt, xdb.ID(0), pb.Trust_Private, m.Pem)
	}
	row, err := caDb.RegisterIssuer(ctx, m, anchor)
	if err != nil {
		if !db.IsUniqueViolation(err, "") {
			return out, errors.WithMessage(err, "unable to register issuer")
		}
		// another instance registered the issuer between the lookup and
		// the insert: several processes bootstrap one fresh DB at once
		// (the service instances, the test packages). Continue with its
		// row when it is the issuer of this configuration; a row with
		// another key is the renewal error of the lookup, and a key
		// registered under another label is the conflict itself.
		existing, ferr := caDb.FindIssuer(ctx, 0, 0, label)
		switch {
		case ferr != nil && xdb.IsNotFoundError(ferr):
			return out, errors.WithMessage(err, "unable to register issuer")
		case ferr != nil:
			return out, errors.WithMessage(ferr, "unable to find issuer")
		case existing.Skid != skid:
			return out, errors.Errorf("the certificate is for key %s and the registered issuer has key %s: archive the registered issuer under another label before renewing it", skid, existing.Skid)
		}
		logger.KV(xlog.INFO,
			"status", "issuer_registered_elsewhere",
			"issuer_id", idString(existing.ID),
			"issuer", label,
			"skid", skid)
		return r.refreshIssuer(ctx, caDb, existing, cfg)
	}
	r.InvalidateIssuer(row)
	out.registered = true
	out.root = anchor != nil
	logger.KV(xlog.NOTICE,
		"status", "issuer_registered",
		"issuer_id", idString(row.ID),
		"issuer", label,
		"type", row.Type.String(),
		"skid", skid,
		"key_provider", row.KeyProvider)
	return out, nil
}

// refreshIssuer brings the registered platform issuer of a ca-config entry
// up to date: an Archived issuer the configuration enables again becomes
// Active, changed runtime settings are replaced, both in one update, and
// the trust anchor of a root is registered again from the stored
// certificate. A Destroyed issuer has no key, and a Pending one no
// certificate: neither is the issuer of the configuration.
func (r *Registry) refreshIssuer(ctx context.Context, caDb db.CaDb, existing *model.Issuer, cfg *pb.IssuerConfig) (issuerOutcome, error) {
	var out issuerOutcome
	update := &query.UpdateIssuerRequest{
		ID:    existing.ID.UInt64(),
		OrgID: 0,
	}
	switch existing.Status {
	case pb.IssuerStatus_Active:
	case pb.IssuerStatus_Archived:
		update.Status = pb.IssuerStatus_Active
	default:
		return out, errors.Errorf("the registered issuer is %s: register it under another label", existing.Status.String())
	}
	current, err := existing.GetConfig()
	if err != nil {
		return out, err
	}
	if !proto.Equal(current, cfg) {
		j, err := model.MarshalJSONValue(cfg)
		if err != nil {
			return out, err
		}
		update.Config = []byte(j)
	}
	if update.Status != pb.IssuerStatus_Unknown || len(update.Config) > 0 {
		row, err := caDb.UpdateIssuer(ctx, update)
		if err != nil {
			return out, errors.WithMessage(err, "unable to update issuer")
		}
		r.InvalidateIssuer(row)
		out.updated = true
		logger.KV(xlog.NOTICE,
			"status", "issuer_updated",
			"issuer_id", idString(row.ID),
			"issuer", row.Label,
			"issuer_status", row.Status.String())
	}
	if existing.Type == pb.AuthorityType_Root {
		crt, err := certutil.ParseFromPEM([]byte(existing.Pem))
		if err != nil {
			return out, errors.WithMessage(err, "invalid stored certificate")
		}
		_, err = caDb.RegisterRoot(ctx, model.NewRootCertificate(crt, xdb.ID(0), pb.Trust_Private, existing.Pem))
		if err != nil {
			return out, errors.WithMessage(err, "unable to register root")
		}
		out.root = true
	}
	return out, nil
}

// issuerType infers the authority type of a certificate: a self-signed
// certificate is a Root, a CA that signs no subordinate CA is Issuing, any
// other CA is Intermediate
func issuerType(crt *x509.Certificate) pb.AuthorityType_Enum {
	switch {
	case IsSelfSigned(crt):
		return pb.AuthorityType_Root
	case crt.MaxPathLen == 0 && crt.MaxPathLenZero:
		return pb.AuthorityType_Issuing
	default:
		return pb.AuthorityType_Intermediate
	}
}
