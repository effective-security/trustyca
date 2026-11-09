package query

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
	"google.golang.org/grpc/codes"
)

// InitialCursor names the first page, as an empty cursor does; the next pages
// pass the cursor of the previous result
const InitialCursor = "initial"

// cursorPosition is the parameter position setPage records a cursor key
// at: it is not a column position, so a list may filter by any column,
// including its id, and page by cursor
const cursorPosition = 60

// Cursor is the decoded position of a list request that pages by keyset:
// the typed sort key of the last row of the previous page, in ORDER BY
// order, which the query binds in a row comparison past that row. The zero
// value is the first page of any list. A list decodes its cursor with the
// parser of its sort key (ParseCursor, ParseTimeCursor, ParseNameCursor) and
// encodes the cursor of its next page with the matching encoder.
type Cursor struct {
	key []any
}

// cursorKind is the first value of a cursor token, the sort key it was encoded
// for: a parser refuses the token of another list, even of a key with as many
// values, which would otherwise decode into a wrong page
type cursorKind string

const (
	// keyID is the key of the lists by id: the CA lists
	keyID cursorKind = "id"
	// keyTime is the key of the lists by (created_at, id): the events and the
	// API keys
	keyTime cursorKind = "time"
	// keyName is the key of the lists by (name, id): the orgs and the projects
	keyName cursorKind = "name"
)

// LastID returns the ID of the last row of the previous page, the last value
// of the key, after which the listing continues; zero for the first page
func (c Cursor) LastID() uint64 {
	if c.key == nil {
		return 0
	}
	id, _ := c.key[len(c.key)-1].(uint64)
	return id
}

// Key returns a copy of the sort key of the last row of the previous page,
// after which the listing continues: the ID of a list by id, the time and
// the ID of a list by (created_at, id), the name and the ID of a list by
// (name, id); nil for the first page
func (c Cursor) Key() []any {
	return slices.Clone(c.key)
}

// ParseCursor decodes the cursor of a list that pages by id, newest first
// (the CA lists): empty and InitialCursor are the first page, otherwise the
// cursor returned with the previous page, encoded by EncodeCursor
func ParseCursor(cursor string) (Cursor, error) {
	var id uint64
	decoded, err := decodeCursor(cursor, keyID, &id)
	if err != nil || !decoded {
		return Cursor{}, err
	}
	return keyCursor(id, id)
}

// ParseTimeCursor decodes the cursor of a list that pages by
// (created_at, id), newest first (the events and the API keys), encoded by
// EncodeTimeCursor; empty and InitialCursor are as in ParseCursor
func ParseTimeCursor(cursor string) (Cursor, error) {
	var at time.Time
	var id uint64
	decoded, err := decodeCursor(cursor, keyTime, &at, &id)
	if err != nil || !decoded {
		return Cursor{}, err
	}
	return keyCursor(id, at, id)
}

// ParseNameCursor decodes the cursor of a list that pages by (name, id),
// ascending (the orgs and the projects), encoded by EncodeNameCursor; empty
// and InitialCursor are as in ParseCursor
func ParseNameCursor(cursor string) (Cursor, error) {
	var name string
	var id uint64
	decoded, err := decodeCursor(cursor, keyName, &name, &id)
	if err != nil || !decoded {
		return Cursor{}, err
	}
	return keyCursor(id, name, id)
}

// decodeCursor decodes a cursor token of the kind into the sort key dest point
// to and reports true. An empty cursor and InitialCursor are the first page,
// reported as false; a token that does not decode into dest, or of another
// kind, is an error the caller reports as an invalid argument.
func decodeCursor(cursor string, kind cursorKind, dest ...any) (bool, error) {
	if cursor == "" || cursor == InitialCursor {
		return false, nil
	}
	c, err := xdb.ParseCursor(cursor)
	if err != nil {
		return false, err
	}
	var encoded string
	if err = c.Scan(append([]any{&encoded}, dest...)...); err != nil {
		return false, err
	}
	if cursorKind(encoded) != kind {
		return false, errors.New("invalid cursor: the cursor of another list")
	}
	return true, nil
}

// keyCursor returns the cursor of a decoded sort key, whose last value is the
// row ID: never zero and within the bigint of the column, so that a crafted
// token is an invalid argument and not a failed statement
func keyCursor(id uint64, key ...any) (Cursor, error) {
	if id == 0 {
		return Cursor{}, errors.New("invalid cursor: missing id")
	}
	if id > math.MaxInt64 {
		return Cursor{}, errors.New("invalid cursor: id out of range")
	}
	return Cursor{key: key}, nil
}

// EncodeCursor returns the cursor of the page that follows the row with the
// ID, for a list that pages by id
func EncodeCursor(lastID xdb.ID) string {
	return encodeCursor(keyID, lastID.UInt64())
}

// EncodeTimeCursor returns the cursor of the page that follows the row with
// the creation time and the ID, for a list that pages by (created_at, id)
func EncodeTimeCursor(lastAt xdb.Time, lastID xdb.ID) string {
	return encodeCursor(keyTime, lastAt, lastID.UInt64())
}

// EncodeNameCursor returns the cursor of the page that follows the row with
// the name and the ID, for a list that pages by (name, id)
func EncodeNameCursor(lastName string, lastID xdb.ID) string {
	return encodeCursor(keyName, lastName, lastID.UInt64())
}

// encodeCursor returns the token of a sort key of the kind, of times, strings
// and integers, which xdb.NewCursor always encodes; its error is for other
// types, which the encoders above never pass
func encodeCursor(kind cursorKind, key ...any) string {
	c, _ := xdb.NewCursor(append([]any{string(kind)}, key...)...)
	return c.String()
}

// setPage records the pagination of a list request after its filters: the
// key values of the cursor are the last positional arguments before the
// limit, recorded at cursorPosition. The first page has no key, and xdb binds
// it as LIMIT and OFFSET 0.
func setPage(b *xdb.QueryParamsBuilder, limit uint32, cursor Cursor) {
	b.SetCursor(limit, cursorPosition, cursor.key...)
}

// pageByIDDesc orders the rows newest first by id and adds the pagination
// recorded by setPage
func pageByIDDesc(q xsql.Builder, p xdb.QueryParams) {
	pageBy(q, p, OrderDirectionDesc, idColumn)
}

// OrderDirection is the direction of the sort key of a list: its columns
// are all ascending or all descending, and a cursor page filters past the
// key of the last row with the matching comparison
type OrderDirection int

const (
	// OrderDirectionAsc lists the rows in ascending order of the key, and
	// a cursor page the rows greater than the key
	OrderDirectionAsc OrderDirection = 0
	// OrderDirectionDesc lists the rows in descending order of the key,
	// newest first for a key that ends with the id, and a cursor page the
	// rows less than the key
	OrderDirectionDesc OrderDirection = 1
)

// pageBy orders the rows by the columns of the sort key, all descending or
// all ascending, and adds the pagination recorded by setPage: a page after
// the first filters past the key of the last row of the previous page,
// `id < ?` or a row comparison such as `(created_at, id) < (?, ?)`, and has a
// LIMIT; the first page has LIMIT and OFFSET, which is always 0. It is the
// last clause of a list query, since the key values follow the filters in the
// positional arguments.
func pageBy(q xsql.Builder, p xdb.QueryParams, orderDirection OrderDirection, columns ...string) {
	dir, op := " ASC", " > "
	if orderDirection == OrderDirectionDesc {
		dir, op = " DESC", " < "
	}
	order := make([]string, len(columns))
	for i, column := range columns {
		order[i] = column + dir
	}
	q.OrderBy(order...)

	if _, cursor := p.Cursor(); cursor == nil {
		q.Limit(nil).Offset(nil)
		return
	}
	if len(columns) == 1 {
		q.Where(columns[0]+op+"?", nil)
	} else {
		marks := strings.Repeat("?, ", len(columns)-1) + "?"
		q.Where("("+strings.Join(columns, ", ")+")"+op+"("+marks+")", make([]any, len(columns))...)
	}
	q.Limit(nil)
}

// ListCursor parses the cursor of a list request with the parser of the
// list's sort key (query.ParseNameCursor for the projects); an empty cursor
// is the first page, and a token that does not decode an invalid argument
func ListCursor(ctx context.Context, cursor string, parse func(string) (Cursor, error)) (Cursor, error) {
	c, err := parse(cursor)
	if err != nil {
		return Cursor{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid cursor")
	}
	return c, nil
}

// Limit returns the page size of a list request: xdb.DefaultPageSize without a
// limit and at most that, so a request never loads more rows into memory
func Limit(limit uint32) uint32 {
	return min(cmp.Or(limit, xdb.DefaultPageSize), xdb.DefaultPageSize)
}
