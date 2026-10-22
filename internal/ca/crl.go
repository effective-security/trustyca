package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/metricskey"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
)

const (
	// CrlPEMType is the PEM block type of a CRL
	CrlPEMType = "X509 CRL"

	// crlPageSize is the number of revocations read per query when a CRL is
	// built
	crlPageSize = 1000
	// issuerPageSize is the number of issuers read per query when the due
	// CRLs of a scope are published
	issuerPageSize = 100
	// publishAttempts is the number of times a CRL is signed when another
	// publisher stores a CRL of the issuer first (db.ErrStaleCrlNumber)
	publishAttempts = 2
)

// crlStatuses are the lifecycle statuses of the issuers that publish CRLs:
// an Archived issuer signs no certificate but keeps answering for the ones
// it issued (DESIGN.md section 4.2)
var crlStatuses = []pb.IssuerStatus_Enum{
	pb.IssuerStatus_Active,
	pb.IssuerStatus_Archived,
}

// CrlPublisher signs and stores the CRLs of the issuers (DESIGN.md section
// 8). The PublishCrls method of the CA service and the crl_renewal task
// share it: a CRL is published when the issuer has none, when the current
// one is within the renewal period of its next update, or on demand. The
// CRL number is the issuer's current number plus one, and db.PublishCrl
// stores the CRL and the number in one transaction, refusing a number that
// is not greater than the issuer's: when another instance publishes first,
// the CRL is signed again with the next number.
//
// A CrlPublisher is safe for concurrent use.
type CrlPublisher struct {
	db       db.CaDb
	registry *Registry
}

// NewCrlPublisher returns a publisher over the CA tables and the registry
// that loads the issuers
func NewCrlPublisher(caDb db.CaDb, registry *Registry) *CrlPublisher {
	return &CrlPublisher{
		db:       caDb,
		registry: registry,
	}
}

// PublishCrlsRequest selects the issuers whose due CRLs are published: the
// Active and Archived issuers of the scope, as query.ListIssuersRequest
// names it
type PublishCrlsRequest struct {
	// OrgID limits the issuers to the org
	OrgID xdb.ID
	// AllOrgs selects the issuers of every org and the platform when OrgID
	// is zero, for the renewal task
	AllOrgs bool
	// ProjectID limits the issuers to the project
	ProjectID xdb.ID
	// ProjectIDs limits the issuers to the org-wide ones and those of the
	// projects; nil applies no project filter
	ProjectIDs []uint64
	// Force publishes the CRLs that are not due
	Force bool
}

// PublishCrlsResult is the outcome of a run over the issuers of a scope
type PublishCrlsResult struct {
	// Crls are the CRLs the run published
	Crls []*model.Crl
	// Skipped is the number of issuers whose CRL was not due, and of the
	// issuers whose certificate has expired
	Skipped int
	// Failed is the number of issuers whose CRL could not be published;
	// every failure is logged
	Failed int
}

// PublishCrls publishes the due CRLs of the Active and Archived issuers of
// the scope, every CRL when forced. The current CRLs of a page of issuers
// are read in one query (db.GetCrls), and an issuer whose CRL is not due is
// skipped from the settings of its row, before its signer is loaded. An
// issuer that fails does not stop the run: the failure is logged and
// counted. The error is a failure to list the issuers or to read their
// CRLs; the CRLs published before it are in the result.
func (p *CrlPublisher) PublishCrls(ctx context.Context, req *PublishCrlsRequest) (*PublishCrlsResult, error) {
	res := &PublishCrlsResult{}
	for _, status := range crlStatuses {
		cursor := query.NewCursor(0)
		for {
			page, err := p.db.ListIssuers(ctx, &query.ListIssuersRequest{
				OrgID:      req.OrgID.UInt64(),
				AllOrgs:    req.AllOrgs,
				ProjectID:  req.ProjectID.UInt64(),
				ProjectIDs: req.ProjectIDs,
				Status:     status,
				Limit:      issuerPageSize,
				Cursor:     cursor,
			})
			if err != nil {
				return res, errors.WithMessage(err, "unable to list issuers")
			}
			current, err := p.currentCrls(ctx, page.Rows)
			if err != nil {
				return res, err
			}
			for _, row := range page.Rows {
				p.publishOne(ctx, row, current[row.Skid], req.Force, res)
			}
			if !page.HasNextPage {
				break
			}
			cursor, err = query.ParseCursor(page.Cursor)
			if err != nil {
				return res, errors.WithMessage(err, "unable to list issuers")
			}
		}
	}
	return res, nil
}

// currentCrls reads the current CRLs of a page of issuer rows in one query
// and returns them by IKID; an issuer without a CRL has no entry
func (p *CrlPublisher) currentCrls(ctx context.Context, rows []*model.Issuer) (map[string]*model.Crl, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	ikids := make([]string, 0, len(rows))
	for _, row := range rows {
		ikids = append(ikids, row.Skid)
	}
	crls, err := p.db.GetCrls(ctx, ikids)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to read current CRLs")
	}
	res := make(map[string]*model.Crl, len(crls))
	for _, crl := range crls {
		res[crl.Ikid] = crl
	}
	return res, nil
}

// publishOne publishes the CRL of one issuer of a run, given its current
// CRL, and records the outcome in the result
func (p *CrlPublisher) publishOne(ctx context.Context, row *model.Issuer, current *model.Crl, force bool, res *PublishCrlsResult) {
	id := idString(row.ID)
	if issuerExpired(row, time.Now()) {
		logger.ContextKV(ctx, xlog.DEBUG,
			"status", "crl_skipped",
			"reason", "issuer_expired",
			"issuer_id", id,
			"issuer", row.Label,
			"not_after", row.NotAfter.UTC().Format(time.RFC3339))
		res.Skipped++
		return
	}
	crl, published, err := p.publish(ctx, row, current, force)
	switch {
	case err != nil:
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "publish_crl",
			"issuer_id", id,
			"org_id", idString(row.OrgID),
			"project_id", idString(row.ProjectID),
			"issuer", row.Label,
			"err", err.Error())
		res.Failed++
	case published:
		res.Crls = append(res.Crls, crl)
	default:
		res.Skipped++
	}
}

// PublishCrl signs and stores the CRL of the issuer row when it is due
// (CrlDue with the renewal period of the issuer settings), or when forced,
// and returns the CRL and true. When the current CRL (db.GetCrl) is not due
// it is returned with false. The row must be an Active or Archived issuer
// whose certificate is valid; its CRL number is the current one, so the row
// comes from the DB, not from a cache.
func (p *CrlPublisher) PublishCrl(ctx context.Context, row *model.Issuer, force bool) (*model.Crl, bool, error) {
	if row.Status != pb.IssuerStatus_Active && row.Status != pb.IssuerStatus_Archived {
		return nil, false, errors.WithStack(ErrIssuerNotActive)
	}
	current, err := p.currentCrl(ctx, row.Skid)
	if err != nil {
		return nil, false, err
	}
	return p.publish(ctx, row, current, force)
}

// publish signs and stores the CRL of the issuer row when the current one
// is due or the publish is forced, and returns the CRL and true; otherwise
// it returns the current CRL with false. An expired issuer certificate is
// ErrIssuerExpired. The renewal period comes from the settings of the row,
// so the issuer and its key are loaded through the registry only when a
// CRL is signed. When another publisher stores a CRL of the issuer first,
// the row and its CRL are read again and the CRL signed with the next
// number, once.
func (p *CrlPublisher) publish(ctx context.Context, row *model.Issuer, current *model.Crl, force bool) (*model.Crl, bool, error) {
	now := time.Now().UTC().Truncate(time.Second)
	if issuerExpired(row, now) {
		return nil, false, errors.WithStack(ErrIssuerExpired)
	}
	renewal, err := crlRenewal(row)
	if err != nil {
		return nil, false, err
	}
	if !force && !CrlDue(current, renewal, now) {
		return current, false, nil
	}
	issuer, err := p.registry.Issuer(ctx, row)
	if err != nil {
		return nil, false, err
	}

	for attempt := 1; ; attempt++ {
		crl, entries, err := p.buildCrl(ctx, issuer, row, row.CrlNumber+1, now)
		if err != nil {
			metricskey.CAFailPublishCrl.IncrCounter(1, row.Label)
			return nil, false, err
		}
		stored, err := p.db.PublishCrl(ctx, crl)
		if err == nil {
			metricskey.CACrlPublished.IncrCounter(1, row.Label)
			logger.ContextKV(ctx, xlog.NOTICE,
				"status", "crl_published",
				"issuer_id", idString(row.ID),
				"org_id", idString(stored.OrgID),
				"project_id", idString(stored.ProjectID),
				"issuer", row.Label,
				"ikid", stored.Ikid,
				"crl_number", stored.CrlNumber,
				"entries", entries,
				"next_update", stored.NextUpdate.UTC().Format(time.RFC3339))
			return stored, true, nil
		}
		if !errors.Is(err, db.ErrStaleCrlNumber) || attempt >= publishAttempts {
			metricskey.CAFailPublishCrl.IncrCounter(1, row.Label)
			return nil, false, errors.WithMessagef(err, "unable to publish CRL of issuer %s", idString(row.ID))
		}
		// another publisher stored a CRL of the issuer first: continue
		// from its number, unless its CRL makes this one needless
		logger.ContextKV(ctx, xlog.DEBUG,
			"status", "crl_number_stale",
			"issuer_id", idString(row.ID),
			"crl_number", crl.CrlNumber)
		row, err = p.db.GetIssuer(ctx, row.ID.UInt64())
		if err != nil {
			return nil, false, errors.WithMessage(err, "unable to read issuer")
		}
		if row.Status != pb.IssuerStatus_Active && row.Status != pb.IssuerStatus_Archived {
			return nil, false, errors.WithStack(ErrIssuerNotActive)
		}
		current, err = p.currentCrl(ctx, row.Skid)
		if err != nil {
			return nil, false, err
		}
		if !force && !CrlDue(current, renewal, now) {
			return current, false, nil
		}
	}
}

// crlRenewal returns the CRL renewal period of the settings of the issuer
// row, as the registry configures the issuer: the value of the row, or the
// authority default
func crlRenewal(row *model.Issuer) (time.Duration, error) {
	cfg, err := row.GetConfig()
	if err != nil {
		return 0, err
	}
	acfg, err := IssuerConfigFromPb(row.Label, cfg)
	if err != nil {
		return 0, errors.WithMessagef(err, "invalid config of issuer %s", idString(row.ID))
	}
	return acfg.AIA.GetCRLRenewal(), nil
}

// buildCrl signs the CRL of the issuer with the number at the time and
// returns the row for db.PublishCrl, not stored, with the number of its
// entries: the revocations of the certificates of the issuer that are still
// valid at the time, with their reason codes. The CRL is valid for the CRL
// expiry of the issuer settings, capped at the expiry of the issuer
// certificate.
func (p *CrlPublisher) buildCrl(ctx context.Context, issuer *authority.Issuer, row *model.Issuer, number int64, now time.Time) (*model.Crl, int, error) {
	entries, err := p.crlEntries(ctx, row.Skid, now)
	if err != nil {
		return nil, 0, err
	}
	cert := issuer.Bundle().Cert
	nextUpdate := now.Add(issuer.CrlExpiry())
	if nextUpdate.After(cert.NotAfter) {
		nextUpdate = cert.NotAfter.UTC()
	}
	if !nextUpdate.After(now) {
		return nil, 0, errors.WithStack(ErrIssuerExpired)
	}
	template := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, cert, issuer.Signer())
	if err != nil {
		return nil, 0, errors.WithMessagef(err, "unable to sign CRL of issuer %s", idString(row.ID))
	}
	return &model.Crl{
		OrgID:      row.OrgID,
		ProjectID:  row.ProjectID,
		IssuerID:   row.ID,
		Ikid:       row.Skid,
		CrlNumber:  number,
		ThisUpdate: xdb.UTC(now),
		NextUpdate: xdb.UTC(nextUpdate),
		Issuer:     row.Subject,
		Pem:        string(pem.EncodeToMemory(&pem.Block{Type: CrlPEMType, Bytes: der})),
	}, len(entries), nil
}

// crlEntries lists the revocations of the issuer whose certificate is valid
// at the time, a page at a time, as CRL entries
func (p *CrlPublisher) crlEntries(ctx context.Context, ikid string, now time.Time) ([]x509.RevocationListEntry, error) {
	var entries []x509.RevocationListEntry
	cursor := query.NewCursor(0)
	for {
		page, err := p.db.ListRevoked(ctx, &query.ListRevokedRequest{
			AllOrgs:    true,
			IKID:       ikid,
			ValidAfter: &now,
			Limit:      crlPageSize,
			Cursor:     cursor,
		})
		if err != nil {
			return nil, errors.WithMessage(err, "unable to list revoked certificates")
		}
		for _, r := range page.Rows {
			serial, ok := new(big.Int).SetString(r.SerialNumber, 10)
			if !ok {
				return nil, errors.Errorf("invalid serial number %q of revoked certificate %s", r.SerialNumber, idString(r.CertificateID))
			}
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   serial,
				RevocationTime: r.RevokedAt.UTC(),
				ReasonCode:     int(r.Reason),
			})
		}
		if !page.HasNextPage {
			return entries, nil
		}
		cursor, err = query.ParseCursor(page.Cursor)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to list revoked certificates")
		}
	}
}

// currentCrl returns the current CRL of the issuer, or nil when it has none
func (p *CrlPublisher) currentCrl(ctx context.Context, ikid string) (*model.Crl, error) {
	crl, err := p.db.GetCrl(ctx, ikid)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.WithMessage(err, "unable to read current CRL")
	}
	return crl, nil
}

// CrlDue reports whether a CRL must be published at the time: the issuer
// has none, or the next update of the current one is within the renewal
// period
func CrlDue(current *model.Crl, renewal time.Duration, now time.Time) bool {
	return current == nil || !current.NextUpdate.UTC().After(now.Add(renewal))
}

// issuerExpired reports whether the certificate of the issuer row is no
// longer valid at the time
func issuerExpired(row *model.Issuer, now time.Time) bool {
	return !row.NotAfter.IsZero() && !row.NotAfter.UTC().After(now)
}
