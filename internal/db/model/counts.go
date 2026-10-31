package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
)

// StatusCount is a row of a count by status: the status column of a CA
// table and the number of its rows in the scope of the query
type StatusCount struct {
	Status int32
	Count  int64
}

// ScanRow scans the status and the count
func (m *StatusCount) ScanRow(rows xdb.Row) error {
	err := rows.Scan(&m.Status, &m.Count)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// IssuerCounts are the issuers of a scope by lifecycle status; a status
// without issuers has no entry
type IssuerCounts map[pb.IssuerStatus_Enum]uint64

// CertificateCounts are the counts of the certificates of a scope
type CertificateCounts struct {
	// ByStatus counts the certificates by status; a status without
	// certificates has no entry
	ByStatus map[pb.CertificateStatus_Enum]uint64
	// Expiring counts the Active certificates whose validity ends within
	// each period of the request, in the order of the request; a period
	// counts the certificates of the shorter ones too
	Expiring []uint64
}

// CrlState is the state of the CRL of an issuer that publishes CRLs, as
// the tenant summary classifies it: the issuer, its settings and the end of
// its validity, and the next update of its current CRL, zero when it has
// published none. The row is a projection of the issuer and crl tables
// without their PEMs, which a dashboard never reads.
type CrlState struct {
	ID         xdb.ID
	Label      string
	Skid       string
	NotAfter   xdb.Time
	Config     JSON
	NextUpdate xdb.Time
}

// ScanRow scans the projection
func (m *CrlState) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.Label,
		&m.Skid,
		&m.NotAfter,
		&m.Config,
		&m.NextUpdate,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// GetConfig returns the settings of the issuer
func (m *CrlState) GetConfig() (*pb.IssuerConfig, error) {
	cfg := new(pb.IssuerConfig)
	err := m.Config.Unmarshal(cfg)
	if err != nil {
		return nil, errors.WithMessagef(err, "invalid config of issuer %s", m.ID.String())
	}
	return cfg, nil
}

// CrlStateResult is a page of CRL states
type CrlStateResult struct {
	Rows        []*CrlState
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

// SetResult sets the page of an offset list
func (p *CrlStateResult) SetResult(rows []*CrlState, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

// SetResultWithCursor sets the page of a cursor list and the cursor of the
// next page from its last row
func (p *CrlStateResult) SetResultWithCursor(rows []*CrlState, hasNextPage bool, cursor func(lastRow *CrlState) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

// SummaryCounts are the counts of the tenant summary, read at one snapshot
type SummaryCounts struct {
	// Issuers counts the issuers of the scope by lifecycle status
	Issuers IssuerCounts
	// Certificates counts the certificates of the scope by status and by
	// expiry period
	Certificates *CertificateCounts
	// CrlStates are the issuers of the scope that publish CRLs with the
	// state of their CRL, every page of them
	CrlStates []*CrlState
}
