package model_test

import (
	"encoding/json"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_JSON(t *testing.T) {
	t.Parallel()

	var empty model.JSON
	assert.True(t, empty.IsEmpty())
	assert.Equal(t, "{}", empty.String())
	v, err := empty.Value()
	require.NoError(t, err)
	assert.Equal(t, "{}", v, "an empty value is written as the empty object")
	assert.True(t, model.JSON(`{}`).IsEmpty())

	cfg := &pb.IssuerConfig{
		AiaURL:          "https://cis/v1/cert/${ISSUER_ID}",
		CrlExpiry:       "48h",
		AllowedProfiles: []string{"peer", "server"},
	}
	j, err := model.MarshalJSONValue(cfg)
	require.NoError(t, err)
	assert.False(t, j.IsEmpty())
	// protojson varies its spacing between builds, so the document is compared parsed
	assert.JSONEq(t, `{"AiaURL":"https://cis/v1/cert/${ISSUER_ID}","CrlExpiry":"48h","AllowedProfiles":["peer","server"]}`, j.String())
	v, err = j.Value()
	require.NoError(t, err)
	assert.Equal(t, j.String(), v)

	var parsed pb.IssuerConfig
	require.NoError(t, j.Unmarshal(&parsed))
	assert.Equal(t, cfg.AiaURL, parsed.AiaURL)
	assert.Equal(t, cfg.CrlExpiry, parsed.CrlExpiry)
	assert.Equal(t, cfg.AllowedProfiles, parsed.AllowedProfiles)

	// an empty value leaves the target unchanged
	require.NoError(t, empty.Unmarshal(&parsed))
	assert.Equal(t, cfg.AiaURL, parsed.AiaURL)

	assert.ErrorContains(t, model.JSON(`{`).Unmarshal(&parsed), "unable to unmarshal JSON value")
	_, err = model.MarshalJSONValue(make(chan int))
	assert.ErrorContains(t, err, "unable to marshal JSON value")

	// the document is embedded when the model is marshaled
	doc := struct {
		Config model.JSON
		Empty  model.JSON
	}{Config: j}
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	assert.Equal(t, `{"Config":`+j.String()+`,"Empty":null}`, string(b))
	var back struct {
		Config model.JSON
		Empty  model.JSON
	}
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, j.String(), back.Config.String())
	assert.True(t, back.Empty.IsEmpty(), "null is read as an empty value")
	assert.Nil(t, back.Empty)

	// scan
	var scanned model.JSON
	require.NoError(t, scanned.Scan(nil))
	assert.True(t, scanned.IsEmpty())
	require.NoError(t, scanned.Scan([]byte(`{"a":1}`)))
	assert.Equal(t, `{"a":1}`, scanned.String())
	require.NoError(t, scanned.Scan(`{"b":2}`))
	assert.Equal(t, `{"b":2}`, scanned.String())
	assert.ErrorContains(t, scanned.Scan(42), "unsupported scan type for JSON: int")
}
