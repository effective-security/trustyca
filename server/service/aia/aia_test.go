package aia_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/server/service/aia"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestFactory(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() {
		aia.Factory(nil)
	})
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cadb := mocktrustycadb.NewMockCaReadonlyDb(ctrl)
	_, err := aia.New(nil, cadb, nil, nil)
	assert.EqualError(t, err, "aia.New: invalid parameter")
	_, err = aia.New(&config.Configuration{}, nil, nil, nil)
	assert.EqualError(t, err, "aia.New: invalid parameter")
	_, err = aia.New(&config.Configuration{AIA: config.AIA{OcspCacheSize: -1}}, cadb, nil, nil)
	assert.EqualError(t, err, "unable to create the OCSP cache: must provide a positive size")
	svc, err := aia.New(&config.Configuration{}, cadb, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, aia.ServiceName, svc.Name())
	assert.True(t, svc.IsReady())
	svc.Close()
}
