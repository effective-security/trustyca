package backend

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
)

// PublishCrls publishes the CRLs that are due, or every CRL in scope when
// forced, and returns the CRLs it published. A tenant publishes for the
// issuers of its org: the one of the IKID, which must belong to the
// project when the request names one; the Active and Archived issuers of
// the project the request names, or of a restricted API key; or else the
// org-wide issuers and those of the projects the caller may read. A
// trusted service caller that names no org publishes for every org and the
// platform, as the crl_renewal task does in-process. An issuer that does
// not publish CRLs (Pending, Destroyed, expired) is refused with a
// precondition failure when named by its IKID; in a scope it is skipped,
// and an issuer whose CRL fails is logged and counted, so the request fails
// after the others are published. Every published CRL records a
// CrlPublished event before the request fails, since a retry finds those
// CRLs fresh.
func (s *Service) PublishCrls(ctx context.Context, req *privpb.PublishCrlsRequest) (*pb.CrlsResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	tctx := authctx.FromContext(ctx)
	all := req.OrgID == "" && req.ProjectID == "" && tctx.OrgID().IsZero() && strings.HasPrefix(tctx.AppRole(), authctx.ServiceRolePrefix)
	var orgID xdb.ID
	if !all {
		orgID, err = s.scope.Org(ctx, req.OrgID)
		if err != nil {
			return nil, err
		}
	}

	var crls []*model.Crl
	var failed int
	var runErr error
	if req.IKID != "" {
		row, err := s.db.GetIssuerBySKID(ctx, req.IKID)
		if err != nil {
			if xdb.IsNotFoundError(err) {
				return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
			}
			return nil, httperror.WrapWithCtx(ctx, err, "unable to find issuer")
		}
		if !all {
			projectID, err := s.scope.RequestProject(ctx, orgID, req.ProjectID)
			if err != nil {
				return nil, err
			}
			if !projectID.IsZero() && row.ProjectID.UInt64() != projectID.UInt64() {
				return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
			}
			row, err = s.scope.VisibleIssuer(ctx, orgID, row, pb.CA_PublishCrls_FullMethodName)
			if err != nil {
				return nil, err
			}
		}
		if row.Status != pb.IssuerStatus_Active && row.Status != pb.IssuerStatus_Archived {
			return nil, preconditionFailed(ctx, "issuer is %s", strings.ToLower(row.Status.String()))
		}
		crl, published, err := s.publisher.PublishCrl(ctx, row, req.Force)
		if err != nil {
			if errors.Is(err, core.ErrIssuerExpired) {
				return nil, preconditionFailed(ctx, "issuer certificate has expired")
			}
			logger.ContextKV(ctx, xlog.ERROR,
				"reason", "publish_crl",
				"issuer_id", row.ID.UnderscoreString(),
				"issuer", row.Label,
				"err", err.Error())
			return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "unable to publish CRL")
		}
		if published {
			crls = append(crls, crl)
		}
	} else {
		q := &core.PublishCrlsRequest{
			AllOrgs: all,
			Force:   req.Force,
		}
		if !all {
			q.OrgID = orgID
			projectID, err := s.scope.Project(ctx, orgID, req.ProjectID)
			if err != nil {
				return nil, err
			}
			if projectID.IsZero() {
				q.ProjectIDs, err = s.scope.ListProjects(ctx, orgID)
				if err != nil {
					return nil, err
				}
			} else {
				q.ProjectID = projectID
			}
		}
		res, err := s.publisher.PublishCrls(ctx, q)
		crls = res.Crls
		failed = res.Failed
		runErr = err
	}

	resp := &pb.CrlsResponse{
		Crls: make([]*pb.Crl, len(crls)),
	}
	for i, crl := range crls {
		events.New(ctx, EventSource, pb.EventType_CrlPublished, "CRL published").
			Org(crl.OrgID).
			Project(crl.ProjectID).
			Reference(crl.ID).
			Description("CRL %d of issuer %q published", crl.CrlNumber, crl.Issuer).
			Emit(s.orgs)
		resp.Crls[i] = crl.Pb()
	}
	if runErr != nil {
		return nil, httperror.WrapWithCtx(ctx, runErr, "failed to publish CRLs")
	}
	if failed > 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "failed to publish %d CRLs", failed)
	}
	return resp, nil
}

// GetCRL returns the current CRL of the issuer with the key identifier. A
// tenant reads the CRLs of its org: the CRL of another org, of the platform
// or of a project the caller cannot read is not found. A trusted service
// caller that names no org (CIS) reads the CRL of any issuer, since CRLs
// are public.
func (s *Service) GetCRL(ctx context.Context, req *privpb.GetCrlRequest) (*pb.CrlResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	if req.IKID == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing IKID")
	}
	tctx := authctx.FromContext(ctx)
	public := req.OrgID == "" && tctx.OrgID().IsZero() && strings.HasPrefix(tctx.AppRole(), authctx.ServiceRolePrefix)
	var orgID xdb.ID
	if !public {
		var err error
		orgID, err = s.scope.Org(ctx, req.OrgID)
		if err != nil {
			return nil, err
		}
	}
	row, err := s.db.GetCrl(ctx, req.IKID)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "CRL not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find CRL")
	}
	if !public {
		if row.OrgID.UInt64() != orgID.UInt64() {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "CRL not found")
		}
		err = s.scope.RowAccess(ctx, orgID, row.ProjectID, pb.CA_GetCRL_FullMethodName, "CRL")
		if err != nil {
			return nil, err
		}
	}
	return &pb.CrlResponse{
		Crl: row.Pb(),
	}, nil
}
