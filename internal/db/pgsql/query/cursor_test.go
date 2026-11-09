package query_test

import (
	"math"
	"testing"
	"time"

	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// token encodes a sort key as xdb does, for the tokens of other lists
func token(t *testing.T, key ...any) string {
	c, err := xdb.NewCursor(key...)
	require.NoError(t, err)
	return c.String()
}

func Test_Cursor(t *testing.T) {
	t.Parallel()

	c, err := query.ParseCursor("")
	require.NoError(t, err)
	assert.Equal(t, query.Cursor{}, c, "empty is the first page")
	assert.Nil(t, c.Key())
	assert.Zero(t, c.LastID())

	c, err = query.ParseCursor(query.InitialCursor)
	require.NoError(t, err)
	assert.Equal(t, query.Cursor{}, c, "initial is the first page")

	const maxID = uint64(math.MaxInt64)
	c, err = query.ParseCursor(query.EncodeCursor(xdb.NewID(maxID)))
	require.NoError(t, err)
	assert.Equal(t, []any{maxID}, c.Key(), "the largest ID of the bigint column round trips")
	assert.Equal(t, maxID, c.LastID())
	key := c.Key()
	key[0] = uint64(1)
	assert.Equal(t, []any{maxID}, c.Key(), "Key returns a copy")

	_, err = query.ParseCursor(query.EncodeCursor(xdb.NewID(maxID + 1)))
	assert.EqualError(t, err, "invalid cursor: id out of range", "beyond the bigint column")

	_, err = query.ParseCursor("not base64!")
	assert.ErrorContains(t, err, "invalid cursor")

	_, err = query.ParseCursor(query.EncodeCursor(xdb.ID(0)))
	assert.EqualError(t, err, "invalid cursor: missing id")

	_, err = query.ParseCursor(token(t, "id", "abc"))
	assert.ErrorContains(t, err, "invalid cursor value 1", "an id that is not a number")

	// the token of the former encoding, a JSON object {"id":"5"}
	_, err = query.ParseCursor("eyJpZCI6IjUifQ")
	assert.EqualError(t, err, "invalid cursor", "the legacy map token is not accepted")
}

func Test_TimeCursor(t *testing.T) {
	t.Parallel()

	at := xdb.Time(time.Date(2026, 10, 24, 12, 30, 45, 123456789, time.UTC))
	c, err := query.ParseTimeCursor(query.EncodeTimeCursor(at, xdb.NewID(7)))
	require.NoError(t, err)
	assert.Equal(t, []any{time.Time(at), uint64(7)}, c.Key(), "the time keeps its precision")
	assert.Equal(t, uint64(7), c.LastID())

	local := xdb.Time(time.Time(at).In(time.FixedZone("x", 3600)))
	c, err = query.ParseTimeCursor(query.EncodeTimeCursor(local, xdb.NewID(7)))
	require.NoError(t, err)
	assert.Equal(t, []any{time.Time(at), uint64(7)}, c.Key(), "the key is UTC")

	c, err = query.ParseTimeCursor("")
	require.NoError(t, err)
	assert.Equal(t, query.Cursor{}, c)

	c, err = query.ParseTimeCursor(query.InitialCursor)
	require.NoError(t, err)
	assert.Equal(t, query.Cursor{}, c)

	_, err = query.ParseTimeCursor(token(t, "time", "yesterday", uint64(7)))
	assert.ErrorContains(t, err, "invalid cursor value 1", "a time that does not parse")

	_, err = query.ParseTimeCursor(query.EncodeTimeCursor(at, xdb.ID(0)))
	assert.EqualError(t, err, "invalid cursor: missing id")

	_, err = query.ParseTimeCursor(query.EncodeTimeCursor(at, xdb.NewID(math.MaxUint64)))
	assert.EqualError(t, err, "invalid cursor: id out of range")
}

func Test_NameCursor(t *testing.T) {
	t.Parallel()

	c, err := query.ParseNameCursor(query.EncodeNameCursor("Org B", xdb.NewID(9)))
	require.NoError(t, err)
	assert.Equal(t, []any{"Org B", uint64(9)}, c.Key())
	assert.Equal(t, uint64(9), c.LastID())

	c, err = query.ParseNameCursor(query.EncodeNameCursor("", xdb.NewID(9)))
	require.NoError(t, err)
	assert.Equal(t, []any{"", uint64(9)}, c.Key(), "an empty name is a key")

	c, err = query.ParseNameCursor("")
	require.NoError(t, err)
	assert.Equal(t, query.Cursor{}, c)

	c, err = query.ParseNameCursor(query.InitialCursor)
	require.NoError(t, err)
	assert.Equal(t, query.Cursor{}, c)

	_, err = query.ParseNameCursor(query.EncodeNameCursor("Org B", xdb.ID(0)))
	assert.EqualError(t, err, "invalid cursor: missing id")

	_, err = query.ParseNameCursor(query.EncodeNameCursor("Org B", xdb.NewID(math.MaxUint64)))
	assert.EqualError(t, err, "invalid cursor: id out of range")
}

// Test_Cursor_OtherList checks that a parser refuses the token of another
// list, also of a key with as many values, whose values would decode
func Test_Cursor_OtherList(t *testing.T) {
	t.Parallel()

	const otherList = "invalid cursor: the cursor of another list"
	byID := query.EncodeCursor(xdb.NewID(5))
	byTime := query.EncodeTimeCursor(xdb.Time(time.Now()), xdb.NewID(5))
	byName := query.EncodeNameCursor("Org A", xdb.NewID(5))
	nameAsTime := query.EncodeNameCursor("2026-11-09T10:00:00Z", xdb.NewID(5))

	tcases := []struct {
		name  string
		parse func(string) (query.Cursor, error)
		token string
		err   string
	}{
		{"name list, time token", query.ParseNameCursor, byTime, otherList},
		{"time list, name that reads as a time", query.ParseTimeCursor, nameAsTime, otherList},
		{"time list, name token", query.ParseTimeCursor, byName, "invalid cursor value 1"},
		{"id list, time token", query.ParseCursor, byTime, "invalid cursor: 3 values, expected 2"},
		{"id list, name token", query.ParseCursor, byName, "invalid cursor: 3 values, expected 2"},
		{"time list, id token", query.ParseTimeCursor, byID, "invalid cursor: 2 values, expected 3"},
		{"name list, id token", query.ParseNameCursor, byID, "invalid cursor: 2 values, expected 3"},
		{"id list, no kind", query.ParseCursor, token(t, uint64(5)), "invalid cursor: 1 values, expected 2"},
		{"id list, unknown kind", query.ParseCursor, token(t, "other", uint64(5)), otherList},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.parse(tc.token)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func Test_Limit(t *testing.T) {
	t.Parallel()

	tcases := []struct {
		limit, want uint32
	}{
		{0, xdb.DefaultPageSize},
		{1, 1},
		{xdb.DefaultPageSize, xdb.DefaultPageSize},
		{xdb.DefaultPageSize + 1, xdb.DefaultPageSize},
		{math.MaxUint32, xdb.DefaultPageSize},
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.want, query.Limit(tc.limit), "limit %d", tc.limit)
	}
}
