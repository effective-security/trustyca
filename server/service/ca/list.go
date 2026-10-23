package ca

import (
	"cmp"
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"google.golang.org/grpc/codes"
)

// defaultListLimit is used when a list request does not specify a limit
const defaultListLimit = 100

// listCursor parses the cursor of a list request
func listCursor(ctx context.Context, cursor string) (query.Cursor, error) {
	c, err := query.ParseCursor(cursor)
	if err != nil {
		return query.Cursor{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid cursor")
	}
	return c, nil
}

// listLimit returns the page size of a list request
func listLimit(limit uint32) uint32 {
	return cmp.Or(limit, defaultListLimit)
}
