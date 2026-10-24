package query_test

import (
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
	assert.False(t, c.IsSet(), "empty selects offset pagination")
	assert.Nil(t, c.Key())
	assert.Zero(t, c.LastID())

	c, err = query.ParseCursor(query.InitialCursor)
	require.NoError(t, err)
	assert.True(t, c.IsSet())
	assert.Equal(t, query.NewCursor(0), c, "initial is the first page")
	assert.Nil(t, c.Key())
	assert.Zero(t, c.LastID())

	const maxID = uint64(18446744073709551615)
	encoded := query.EncodeCursor(xdb.NewID(maxID))
	c, err = query.ParseCursor(encoded)
	require.NoError(t, err)
	assert.Equal(t, query.NewCursor(maxID), c, "a 64-bit ID round trips")
	assert.Equal(t, []any{maxID}, c.Key())
	assert.Equal(t, maxID, c.LastID())
	key := c.Key()
	key[0] = uint64(1)
	assert.Equal(t, []any{maxID}, c.Key(), "Key returns a copy")

	_, err = query.ParseCursor("not base64!")
	assert.ErrorContains(t, err, "invalid cursor")

	_, err = query.ParseCursor(query.EncodeCursor(xdb.ID(0)))
	assert.EqualError(t, err, "invalid cursor: missing id")

	_, err = query.ParseCursor(token(t, "abc"))
	assert.ErrorContains(t, err, "invalid cursor value 0", "an id that is not a number")

	_, err = query.ParseCursor(query.EncodeNameCursor("name", xdb.NewID(5)))
	assert.EqualError(t, err, "invalid cursor: 2 values, expected 1", "the cursor of another list")

	// the token of the former encoding, a JSON object {"id":"5"}
	_, err = query.ParseCursor("eyJpZCI6IjUifQ")
	assert.EqualError(t, err, "invalid cursor", "the legacy map token is not accepted")
}

func Test_TimeCursor(t *testing.T) {
	t.Parallel()

	at := xdb.Time(time.Date(2026, 10, 24, 12, 30, 45, 123456789, time.UTC))
	c, err := query.ParseTimeCursor(query.EncodeTimeCursor(at, xdb.NewID(7)))
	require.NoError(t, err)
	assert.True(t, c.IsSet())
	assert.Equal(t, []any{time.Time(at), uint64(7)}, c.Key(), "the time keeps its precision")
	assert.Equal(t, uint64(7), c.LastID())

	local := xdb.Time(time.Time(at).In(time.FixedZone("x", 3600)))
	c, err = query.ParseTimeCursor(query.EncodeTimeCursor(local, xdb.NewID(7)))
	require.NoError(t, err)
	assert.Equal(t, []any{time.Time(at), uint64(7)}, c.Key(), "the key is UTC")

	c, err = query.ParseTimeCursor("")
	require.NoError(t, err)
	assert.False(t, c.IsSet())

	c, err = query.ParseTimeCursor(query.InitialCursor)
	require.NoError(t, err)
	assert.Equal(t, query.NewCursor(0), c)

	_, err = query.ParseTimeCursor(query.EncodeCursor(xdb.NewID(7)))
	assert.EqualError(t, err, "invalid cursor: 1 values, expected 2", "the cursor of another list")

	_, err = query.ParseTimeCursor(token(t, "yesterday", uint64(7)))
	assert.ErrorContains(t, err, "invalid cursor value 0", "a time that does not parse")

	_, err = query.ParseTimeCursor(query.EncodeTimeCursor(at, xdb.ID(0)))
	assert.EqualError(t, err, "invalid cursor: missing id")
}

func Test_NameCursor(t *testing.T) {
	t.Parallel()

	c, err := query.ParseNameCursor(query.EncodeNameCursor("Org B", xdb.NewID(9)))
	require.NoError(t, err)
	assert.True(t, c.IsSet())
	assert.Equal(t, []any{"Org B", uint64(9)}, c.Key())
	assert.Equal(t, uint64(9), c.LastID())

	c, err = query.ParseNameCursor(query.EncodeNameCursor("", xdb.NewID(9)))
	require.NoError(t, err)
	assert.Equal(t, []any{"", uint64(9)}, c.Key(), "an empty name is a key")

	c, err = query.ParseNameCursor("")
	require.NoError(t, err)
	assert.False(t, c.IsSet())

	c, err = query.ParseNameCursor(query.InitialCursor)
	require.NoError(t, err)
	assert.Equal(t, query.NewCursor(0), c)

	_, err = query.ParseNameCursor(query.EncodeCursor(xdb.NewID(9)))
	assert.EqualError(t, err, "invalid cursor: 1 values, expected 2", "the cursor of another list")

	_, err = query.ParseNameCursor(query.EncodeNameCursor("Org B", xdb.ID(0)))
	assert.EqualError(t, err, "invalid cursor: missing id")
}

func Test_Cursor_Validate(t *testing.T) {
	t.Parallel()

	idCursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)
	timeCursor, err := query.ParseTimeCursor(query.EncodeTimeCursor(xdb.Time(time.Now()), xdb.NewID(5)))
	require.NoError(t, err)
	nameCursor, err := query.ParseNameCursor(query.EncodeNameCursor("Org A", xdb.NewID(5)))
	require.NoError(t, err)
	const other = "invalid cursor: the cursor of another list"

	// the CA lists page by id, after their scope
	assert.NoError(t, (&query.ListCertificatesRequest{OrgID: 1, Cursor: idCursor}).Validate())
	assert.EqualError(t, (&query.ListCertificatesRequest{OrgID: 1, Cursor: nameCursor}).Validate(), other)
	assert.ErrorIs(t, (&query.ListCertificatesRequest{Cursor: nameCursor}).Validate(), query.ErrOrgScopeRequired, "the scope is checked first")
	assert.EqualError(t, (&query.ListIssuersRequest{Platform: true, Cursor: timeCursor}).Validate(), other)
	assert.EqualError(t, (&query.ListRootsRequest{AllOrgs: true, Cursor: timeCursor}).Validate(), other)
	assert.EqualError(t, (&query.ListProfilesRequest{OrgID: 1, Cursor: timeCursor}).Validate(), other)
	assert.EqualError(t, (&query.ListRevokedRequest{AllOrgs: true, Cursor: nameCursor}).Validate(), other)
	assert.EqualError(t, (&query.ListRevokedCertificatesRequest{OrgID: 1, Cursor: nameCursor}).Validate(), other)
	assert.EqualError(t, (&query.ListCrlsRequest{OrgID: 1, Cursor: nameCursor}).Validate(), other)

	// the events page by (created_at, id)
	assert.NoError(t, (&query.ListEventsRequest{Cursor: timeCursor}).Validate())
	assert.EqualError(t, (&query.ListEventsRequest{Cursor: nameCursor}).Validate(), other, "a key of the same length")
	assert.EqualError(t, (&query.ListEventsRequest{Cursor: idCursor}).Validate(), other)

	// the orgs and the projects page by (name, id)
	assert.NoError(t, (&query.ListOrgsRequest{Cursor: nameCursor}).Validate())
	assert.EqualError(t, (&query.ListOrgsRequest{Cursor: timeCursor}).Validate(), other)
	assert.NoError(t, (&query.ListProjectsRequest{Cursor: nameCursor}).Validate())
	assert.EqualError(t, (&query.ListProjectsRequest{Cursor: idCursor}).Validate(), other)

	// a cursor without a key continues any list
	assert.NoError(t, (&query.ListProjectsRequest{Cursor: query.NewCursor(0)}).Validate(), "the first page")
	assert.NoError(t, (&query.ListProjectsRequest{}).Validate(), "offset pagination")
}
