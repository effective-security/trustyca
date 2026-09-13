package client

import (
	"context"
	"os"
	"testing"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/gserver/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	homeDir := os.Getenv("HOME")
	require.NotEmpty(t, homeDir, "HOME is not set")
	f := NewFactory(Config{
		ServerURL: map[string]string{
			"local": "https://localhost:8880",
		},
		ClientTLS: gserver.TLSInfo{
			CertFile:      homeDir + "/.trustyca/certs/trustyca_client.pem",
			KeyFile:       homeDir + "/.trustyca/certs/trustyca_client.key",
			TrustedCAFile: homeDir + "/.trustyca/certs/trusty_root_ca.pem",
		},
	}, WithTLS(nil))
	_, _, err := f.StatusClient("invalid")
	assert.EqualError(t, err, "service invalid not found")

	_, closer, err := f.StatusClient("local")
	require.NoError(t, err)
	defer closer.Close()

	_, closer, err = f.OrgsClient("local")
	require.NoError(t, err)
	defer closer.Close()

	assert.Nil(t, f.(*factory).dops.callerIdentity)
}

func TestFactoryCNA(t *testing.T) {
	ci := &callerIdentityMock{}

	f := NewFactory(Config{
		ServerURL: map[string]string{
			"local": "https://localhost:8880",
		},
		EnableCNA: true,
	}, WithCallerIdentity(ci))
	assert.NotNil(t, f.(*factory).dops.callerIdentity)

	f = NewFactory(Config{
		ServerURL: map[string]string{
			"local": "https://localhost:8880",
		},
		EnableCNA: true,
	})
	assert.Nil(t, f.(*factory).dops.callerIdentity)

	c, err := f.(*factory).NewClient("local", WithCallerIdentity(ci))
	require.NoError(t, err)
	ops := c.Opts()
	assert.NotNil(t, ops)
	con := c.Conn()
	assert.NotNil(t, con)
}

type callerIdentityMock struct {
	credentials.CallerIdentity
}

func (ci *callerIdentityMock) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	return &credentials.Token{}, nil
}
