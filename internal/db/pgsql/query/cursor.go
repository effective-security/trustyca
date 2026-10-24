package query

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
	"google.golang.org/grpc/codes"
)

// InitialCursor starts cursor pagination; the next pages pass the cursor of
// the previous result
const InitialCursor = "initial"

// cursorPosition is the parameter position setPage records a cursor key
// at: it is not a column position, so a list may filter by any column,
// including its id, and page by cursor
const cursorPosition = 60

// Cursor is the decoded position of a list request that pages by keyset:
// the typed sort key of the last row of the previous page, in ORDER BY
// order, which the query binds in a row comparison past that row. The zero
// value selects offset pagination; NewCursor(0) is the first page of cursor
// pagination. A list decodes its cursor with the parser of its sort key
// (ParseCursor, ParseTimeCursor, ParseNameCursor) and encodes the cursor of
// its next page with the matching encoder. A parser records the kind of
// its key, and the Validate of a list request refuses the cursor of another
// list (checkKey) before the query runs.
type Cursor struct {
	set  bool
	kind cursorKind
	key  []any
}

// cursorKind is the sort key a cursor was decoded for
type cursorKind int

const (
	// keyNone is a cursor without a key: the first page, or offset pagination
	keyNone cursorKind = iota
	// keyID is the key of the lists by id: the CA lists
	keyID
	// keyTime is the key of the lists by (created_at, id): the events
	keyTime
	// keyName is the key of the lists by (name, id): the orgs and the projects
	keyName
)

// NewCursor returns the cursor of a list by id that continues after the row
// with the ID; a zero ID is the first page of cursor pagination of any list
func NewCursor(lastID uint64) Cursor {
	if lastID == 0 {
		return Cursor{set: true}
	}
	return Cursor{set: true, kind: keyID, key: []any{lastID}}
}

// IsSet returns true when the request uses cursor pagination
func (c Cursor) IsSet() bool {
	return c.set
}

// checkKey fails a cursor decoded for another list than one of the kind; a
// cursor without a key continues any list
func (c Cursor) checkKey(kind cursorKind) error {
	if c.kind != keyNone && c.kind != kind {
		return errors.New("invalid cursor: the cursor of another list")
	}
	return nil
}

// LastID returns the ID of the last row of the previous page, the last value
// of the key, after which the listing continues; zero for the first page and
// for offset pagination
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
// (name, id); nil for the first page and for offset pagination
func (c Cursor) Key() []any {
	return slices.Clone(c.key)
}

// ParseCursor decodes the cursor of a list that pages by id, newest first
// (the CA lists): empty selects offset pagination, InitialCursor the first
// page of cursor pagination, otherwise the cursor returned with the previous
// page, encoded by EncodeCursor
func ParseCursor(cursor string) (Cursor, error) {
	var id uint64
	c, decoded, err := decodeCursor(cursor, &id)
	if err != nil || !decoded {
		return c, err
	}
	return keyCursor(keyID, id, id)
}

// ParseTimeCursor decodes the cursor of a list that pages by
// (created_at, id), newest first (the events), encoded by EncodeTimeCursor;
// empty and InitialCursor are as in ParseCursor
func ParseTimeCursor(cursor string) (Cursor, error) {
	var at time.Time
	var id uint64
	c, decoded, err := decodeCursor(cursor, &at, &id)
	if err != nil || !decoded {
		return c, err
	}
	return keyCursor(keyTime, id, at, id)
}

// ParseNameCursor decodes the cursor of a list that pages by (name, id),
// ascending (the orgs and the projects), encoded by EncodeNameCursor; empty
// and InitialCursor are as in ParseCursor
func ParseNameCursor(cursor string) (Cursor, error) {
	var name string
	var id uint64
	c, decoded, err := decodeCursor(cursor, &name, &id)
	if err != nil || !decoded {
		return c, err
	}
	return keyCursor(keyName, id, name, id)
}

// decodeCursor decodes a cursor token into the sort key dest point to and
// reports true. An empty cursor is the zero Cursor and InitialCursor the
// first page, both without a key, reported as false; a token that does not
// decode into dest is an error the caller reports as an invalid argument.
func decodeCursor(cursor string, dest ...any) (Cursor, bool, error) {
	switch cursor {
	case "":
		return Cursor{}, false, nil
	case InitialCursor:
		return NewCursor(0), false, nil
	}
	c, err := xdb.ParseCursor(cursor)
	if err != nil {
		return Cursor{}, false, err
	}
	if err = c.Scan(dest...); err != nil {
		return Cursor{}, false, err
	}
	return Cursor{}, true, nil
}

// keyCursor returns the cursor of a decoded sort key of the kind, whose
// last value is the row ID, which is never zero
func keyCursor(kind cursorKind, id uint64, key ...any) (Cursor, error) {
	if id == 0 {
		return Cursor{}, errors.New("invalid cursor: missing id")
	}
	return Cursor{set: true, kind: kind, key: key}, nil
}

// EncodeCursor returns the cursor of the page that follows the row with the
// ID, for a list that pages by id
func EncodeCursor(lastID xdb.ID) string {
	return encodeCursor(lastID.UInt64())
}

// EncodeTimeCursor returns the cursor of the page that follows the row with
// the creation time and the ID, for a list that pages by (created_at, id)
func EncodeTimeCursor(lastAt xdb.Time, lastID xdb.ID) string {
	return encodeCursor(lastAt, lastID.UInt64())
}

// EncodeNameCursor returns the cursor of the page that follows the row with
// the name and the ID, for a list that pages by (name, id)
func EncodeNameCursor(lastName string, lastID xdb.ID) string {
	return encodeCursor(lastName, lastID.UInt64())
}

// encodeCursor returns the token of a sort key of times, strings and
// integers, which xdb.NewCursor always encodes; its error is for other
// types, which the encoders above never pass
func encodeCursor(key ...any) string {
	c, _ := xdb.NewCursor(key...)
	return c.String()
}

// setPage records the pagination of a list request after its filters: with
// the key of a cursor, the key values are the last positional arguments
// before the limit, recorded at cursorPosition; otherwise the limit and the
// offset are the last two, and the first page of cursor pagination is
// offset 0
func setPage(b *xdb.QueryParamsBuilder, limit, offset uint32, cursor Cursor) {
	switch {
	case cursor.key != nil:
		b.SetCursor(limit, cursorPosition, cursor.key...)
	case cursor.set:
		b.SetPage(limit, 0)
	default:
		b.SetPage(limit, offset)
	}
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
// all ascending, and adds the pagination recorded by setPage: a cursor page
// filters past the key of the last row of the previous page, `id < ?` or a
// row comparison such as `(created_at, id) < (?, ?)`, and has a LIMIT; an
// offset page has LIMIT and OFFSET. It is the last clause of a list query,
// since the key values follow the filters in the positional arguments.
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
// list's sort key (query.ParseNameCursor for the projects)
func ListCursor(ctx context.Context, cursor string, parse func(string) (Cursor, error)) (Cursor, error) {
	c, err := parse(cursor)
	if err != nil {
		return Cursor{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid cursor")
	}
	return c, nil
}

// Limit returns the page size of a list request
func Limit(limit uint32) uint32 {
	return cmp.Or(limit, xdb.DefaultPageSize)
}
