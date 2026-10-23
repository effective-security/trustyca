package ca

import (
	"context"
	"strings"

	"github.com/effective-security/trustyca/server/service/internal/caapi"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"google.golang.org/grpc/codes"
)

// RegisterRoot registers a self-signed CA certificate as a trust anchor of
// the org; registering it again updates its trust
func (s *Service) RegisterRoot(ctx context.Context, req *pb.RegisterRootRequest) (*pb.RootCertificate, error) {
	if req == nil || strings.TrimSpace(req.Pem) == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing certificate")
	}
	orgID, err := s.scope.Org(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	crt, err := certutil.ParseFromPEM([]byte(req.Pem))
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid certificate")
	}
	if !core.IsSelfSigned(crt) {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "certificate is not a self-signed CA certificate")
	}
	pem, err := certutil.EncodeToPEMString(false, crt)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to encode certificate")
	}
	res, err := s.db.RegisterRoot(ctx, model.NewRootCertificate(crt, orgID, req.Trust, pem))
	if err != nil {
		if errors.Is(err, db.ErrRootConflict) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.AlreadyExists, "certificate is registered in another scope")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register root")
	}
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "root_registered",
		"root_id", res.ID.UnderscoreString(),
		"org_id", res.OrgID.UnderscoreString(),
		"skid", res.Skid,
		"subject", res.Subject)
	events.New(ctx, caapi.EventSource, pb.EventType_RootRegistered, "Root registered").
		Org(orgID).
		Reference(res.ID).
		Description("root %q registered", res.Subject).
		Emit(s.orgs)
	return res.Pb(), nil
}

// ListRoots returns the trust anchors of the org, newest first; a trusted
// service caller that names no org lists the platform anchors
func (s *Service) ListRoots(ctx context.Context, req *pb.ListRootsRequest) (*pb.RootsResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	cursor, err := listCursor(ctx, req.Cursor)
	if err != nil {
		return nil, err
	}
	q := &query.ListRootsRequest{
		Limit:  listLimit(req.Limit),
		Offset: req.Offset,
		Cursor: cursor,
	}
	tctx := authctx.FromContext(ctx)
	if req.OrgID == "" && tctx.OrgID().IsZero() && strings.HasPrefix(tctx.AppRole(), authctx.ServiceRolePrefix) {
		q.Platform = true
	} else {
		orgID, err := s.scope.Org(ctx, req.OrgID)
		if err != nil {
			return nil, err
		}
		q.OrgID = orgID.UInt64()
	}
	res, err := s.db.ListRoots(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list roots")
	}
	return res.Pb(), nil
}
