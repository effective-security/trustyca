package ca

import (
	"context"
	"strings"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

// GetCRL returns the current CRL of the issuer with the key identifier. A
// tenant reads the CRLs of its org: the CRL of another org, of the platform
// or of a project the caller cannot read is not found. A trusted service
// caller that names no org (CIS) reads the CRL of any issuer, since CRLs
// are public.
func (s *Service) GetCRL(ctx context.Context, req *pb.GetCrlRequest) (*pb.CrlResponse, error) {
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
