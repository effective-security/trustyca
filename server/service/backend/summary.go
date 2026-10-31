package backend

import (
	"context"
	"math"
	"time"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/privpb"
	"google.golang.org/grpc/codes"
)

// day is the unit of the expiry buckets of the summary
const day = 24 * time.Hour

// expiryBuckets are the cumulative periods within which the summary counts
// the Active certificates that expire: a week, a month and a quarter
var expiryBuckets = []time.Duration{
	7 * day,
	30 * day,
	90 * day,
}

// issuerStatuses are the lifecycle statuses the summary reports, in order
var issuerStatuses = []pb.IssuerStatus_Enum{
	pb.IssuerStatus_Pending,
	pb.IssuerStatus_Active,
	pb.IssuerStatus_Archived,
	pb.IssuerStatus_Destroyed,
}

// certificateStatuses are the certificate statuses the summary reports, in
// order
var certificateStatuses = []pb.CertificateStatus_Enum{
	pb.CertificateStatus_Active,
	pb.CertificateStatus_Expired,
	pb.CertificateStatus_Revoked,
}

// GetSummary returns the counts of the tenant's dashboard: the issuers by
// status, the certificates by status and the Active ones that expire
// within 7, 30 and 90 days, and the issuers that publish CRLs by the state
// of their CRL. The scope is the org, the project the request names (or
// the project of a restricted API key) or, for a member with project
// grants only, the org-wide rows and those of its projects, as the lists
// cover them. The counts are read at one snapshot (db.GetSummaryCounts)
// and from the tables only, so a backend without an issuer registry
// serves them.
func (s *Service) GetSummary(ctx context.Context, req *privpb.GetSummaryRequest) (*pb.SummaryResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.scope.Org(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.scope.Project(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	var projectIDs []uint64
	if projectID.IsZero() {
		projectIDs, err = s.scope.ListProjects(ctx, orgID)
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC().Truncate(time.Second)

	counts, err := s.db.GetSummaryCounts(ctx, &query.SummaryRequest{
		OrgID:       orgID.UInt64(),
		ProjectID:   projectID.UInt64(),
		ProjectIDs:  projectIDs,
		Now:         now,
		Expiring:    expiryBuckets,
		CrlStatuses: core.CrlStatuses,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to read the summary")
	}
	crls, err := core.CountCrls(counts.CrlStates, now)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to count CRLs")
	}
	return summaryPb(now, counts.Issuers, counts.Certificates, crls), nil
}

// summaryPb builds the response of GetSummary: every status with its
// count, zero included, the expiry buckets in days and the CRL counts
func summaryPb(now time.Time, issuers model.IssuerCounts, certs *model.CertificateCounts, crls *core.CrlCounts) *pb.SummaryResponse {
	res := &pb.SummaryResponse{
		At: now.Format(time.RFC3339),
		Crls: &pb.CrlCounts{
			Issuers: count32(uint64(crls.Issuers)),
			Current: count32(uint64(crls.Current)),
			Due:     count32(uint64(crls.Due)),
			Overdue: count32(uint64(crls.Overdue)),
			Missing: count32(uint64(crls.Missing)),
		},
	}
	for _, status := range issuerStatuses {
		res.Issuers = append(res.Issuers, &pb.IssuerStatusCount{
			Status: status,
			Count:  count32(issuers[status]),
		})
	}
	for _, status := range certificateStatuses {
		res.Certificates = append(res.Certificates, &pb.CertificateStatusCount{
			Status: status,
			Count:  count32(certs.ByStatus[status]),
		})
	}
	for i, within := range expiryBuckets {
		var n uint64
		if i < len(certs.Expiring) {
			n = certs.Expiring[i]
		}
		res.Expiring = append(res.Expiring, &pb.ExpiryBucket{
			Days:  uint32(within / day),
			Count: count32(n),
		})
	}
	return res
}

// count32 converts a count to the 32-bit count of the API, saturated
func count32(n uint64) uint32 {
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}
