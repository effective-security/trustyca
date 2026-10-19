package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Cursor(t *testing.T) {
	t.Parallel()

	c, err := query.ParseCursor("")
	require.NoError(t, err)
	assert.False(t, c.IsSet(), "empty selects offset pagination")

	c, err = query.ParseCursor(query.InitialCursor)
	require.NoError(t, err)
	assert.True(t, c.IsSet())
	assert.Equal(t, query.NewCursor(0), c, "initial is the first page")

	encoded := query.EncodeCursor(xdb.NewID(18446744073709551615))
	c, err = query.ParseCursor(encoded)
	require.NoError(t, err)
	assert.Equal(t, query.NewCursor(18446744073709551615), c, "a 64-bit ID round trips")

	_, err = query.ParseCursor("not base64!")
	assert.ErrorContains(t, err, "invalid cursor")

	_, err = query.ParseCursor(query.EncodeCursor(xdb.ID(0)))
	assert.EqualError(t, err, "invalid cursor: missing id")

	c, err = query.ParseCursor(xdb.EncodeCursor(map[string]any{"id": 5}))
	require.NoError(t, err)
	assert.Equal(t, query.NewCursor(5), c, "a numeric id is accepted")

	_, err = query.ParseCursor(xdb.EncodeCursor(map[string]any{"offset": 5}))
	assert.EqualError(t, err, "invalid cursor: missing id")
}
