package query

import (
	"time"

	"github.com/effective-security/trustyca/api/pb"
)

// SummaryRequest defines request for the counts of the tenant summary,
// read at one snapshot: the issuers by status, the certificates by status
// and by expiry period, and the CRL states of the issuers that publish
// CRLs, of an org, one of its projects or the org-wide scope and the
// projects of ProjectIDs
type SummaryRequest struct {
	// OrgID is the org of the summary
	OrgID uint64
	// ProjectID limits the summary to the project
	ProjectID uint64
	// ProjectIDs limits the summary to the org-wide rows and the rows of the
	// projects, for a caller with grants in some projects only; nil applies
	// no project filter and an empty list keeps the org-wide rows.
	// ProjectID takes precedence.
	ProjectIDs []uint64
	// Now is the time of the summary: the start of the expiry periods
	Now time.Time
	// Expiring are the periods after Now within which the Active
	// certificates are counted, ascending
	Expiring []time.Duration
	// CrlStatuses are the lifecycle statuses of the issuers that publish
	// CRLs
	CrlStatuses []pb.IssuerStatus_Enum
}

// Validate validates the requests of the three reads
func (r *SummaryRequest) Validate() error {
	err := r.Issuers().Validate()
	if err != nil {
		return err
	}
	err = r.Certificates().Validate()
	if err != nil {
		return err
	}
	return r.CrlStates(NewCursor(0)).Validate()
}

// Issuers returns the request of the issuer counts of the scope
func (r *SummaryRequest) Issuers() *CountIssuersRequest {
	return &CountIssuersRequest{
		OrgID:      r.OrgID,
		ProjectID:  r.ProjectID,
		ProjectIDs: r.ProjectIDs,
	}
}

// Certificates returns the request of the certificate counts of the scope
func (r *SummaryRequest) Certificates() *CountCertificatesRequest {
	return &CountCertificatesRequest{
		OrgID:      r.OrgID,
		ProjectID:  r.ProjectID,
		ProjectIDs: r.ProjectIDs,
		Now:        r.Now,
		Expiring:   r.Expiring,
	}
}

// CrlStates returns the request of a page of the CRL states of the scope:
// the first page with NewCursor(0), the next with the cursor of the
// previous page, the default page size
func (r *SummaryRequest) CrlStates(cursor Cursor) *ListCrlStatesRequest {
	return &ListCrlStatesRequest{
		OrgID:      r.OrgID,
		ProjectID:  r.ProjectID,
		ProjectIDs: r.ProjectIDs,
		Statuses:   r.CrlStatuses,
		Limit:      Limit(0),
		Cursor:     cursor,
	}
}
