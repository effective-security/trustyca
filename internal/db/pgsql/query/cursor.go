package query

import (
	"strconv"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// InitialCursor starts cursor pagination; the next pages pass the cursor of
// the previous result
const InitialCursor = "initial"

// cursorKeyID is the key of the last ID in the encoded cursor; the ID is
// encoded as a string because JSON numbers do not hold a 64-bit ID
const cursorKeyID = "id"

// Cursor is the decoded position of a list request that pages by id, newest
// first. The zero value selects offset pagination.
type Cursor struct {
	set bool
	id  uint64
}

// ParseCursor decodes the cursor of a list request: empty selects offset
// pagination, InitialCursor the first page of cursor pagination, otherwise
// the cursor returned with the previous page
func ParseCursor(cursor string) (Cursor, error) {
	switch cursor {
	case "":
		return Cursor{}, nil
	case InitialCursor:
		return Cursor{set: true}, nil
	}
	m, err := xdb.DecodeCursor(cursor)
	if err != nil {
		return Cursor{}, errors.WithMessage(err, "invalid cursor")
	}
	id, err := strconv.ParseUint(m.String(cursorKeyID), 10, 64)
	if err != nil || id == 0 {
		return Cursor{}, errors.New("invalid cursor: missing id")
	}
	return Cursor{set: true, id: id}, nil
}

// NewCursor returns the cursor that continues a listing after the row with
// the ID; a zero ID starts at the newest row
func NewCursor(lastID uint64) Cursor {
	return Cursor{set: true, id: lastID}
}

// IsSet returns true when the request uses cursor pagination
func (c Cursor) IsSet() bool {
	return c.set
}

// EncodeCursor returns the cursor of the page that follows the row with the ID
func EncodeCursor(lastID xdb.ID) string {
	return xdb.EncodeCursor(values.MapAny{cursorKeyID: lastID.String()})
}

// setPage records the pagination of a list request after its filters.
// With a cursor the last ID of the previous page is the last positional
// argument before the limit; otherwise the limit and offset are the last two.
func setPage(b *xdb.QueryParamsBuilder, idPos uint32, limit, offset uint32, cursor Cursor) {
	switch {
	case cursor.set && cursor.id != 0:
		b.SetCursor(limit, idPos, cursor.id)
	case cursor.set:
		b.SetPage(limit, 0)
	default:
		b.SetPage(limit, offset)
	}
}

// pageByID orders the rows newest first and adds the keyset or the offset
// pagination recorded by setPage
func pageByID(q xsql.Builder, p xdb.QueryParams) {
	q.OrderBy(idColumn + " DESC")
	if _, cursor := p.Cursor(); cursor != nil {
		q.Where(idColumn+" < ?", nil).Limit(nil)
	} else {
		q.Limit(nil).Offset(nil)
	}
}
