package model_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordsResultPb(t *testing.T) {
	res := (&model.RecordsResult{Created: 1, Updated: 2, Deleted: 3}).Pb()
	require.NotNil(t, res)
	assert.EqualValues(t, 1, res.Created)
	assert.EqualValues(t, 2, res.Updated)
	assert.EqualValues(t, 3, res.Deleted)

	res = (&model.RecordsResult{}).Pb()
	require.NotNil(t, res)
	assert.EqualValues(t, 0, res.Created)
	assert.EqualValues(t, 0, res.Updated)
	assert.EqualValues(t, 0, res.Deleted)
}
