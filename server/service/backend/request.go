package backend

import (
	"context"
	"net/http"

	"time"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

// EventSource is the source of the audit events the CA records
const EventSource = "ca"

// preconditionFailed returns the error of a request that the current state
// of the org refuses, and that the caller can make pass by changing that
// state: HTTP 409 Conflict with code "conflict", and gRPC FailedPrecondition.
// The pinned porto maps FailedPrecondition to HTTP 400, so it is built from
// the HTTP status and returned unwrapped; a remote backend's refusal is
// restored by the CA service that forwards to it (ca.forwardedError).
func preconditionFailed(ctx context.Context, msgFormat string, vals ...any) *httperror.Error {
	e := httperror.NewFromCtx(ctx, http.StatusConflict, httperror.CodeConflict, msgFormat, vals...)
	e.RPCStatus = codes.FailedPrecondition
	return e
}

// parseID parses a required ID of a request
func parseID(ctx context.Context, val, what string) (xdb.ID, error) {
	if val == "" {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing %s", what)
	}
	id, err := xdb.ParseID(val)
	if err != nil {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid %s", what)
	}
	return id, nil
}

// issuerPb converts an issuer row to its API message
func issuerPb(ctx context.Context, row *model.Issuer) (*pb.Issuer, error) {
	res, err := row.Pb()
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "invalid issuer config")
	}
	return res, nil
}

// parseTime parses an optional RFC3339 time of a request; empty is the zero
// time
func parseTime(ctx context.Context, val, what string) (time.Time, error) {
	if val == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid %s: RFC3339 time expected", what)
	}
	return t.UTC(), nil
}
