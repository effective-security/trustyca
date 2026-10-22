package client

import (
	"context"
	"crypto/tls"
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
			TrustedCAFile: homeDir + "/.trustyca/certs/trustyca_root.pem",
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

	_, closer, err = f.CAClient("local")
	require.NoError(t, err)
	defer closer.Close()
	_, _, err = f.CAClient("invalid")
	assert.EqualError(t, err, "service invalid not found")

	assert.Nil(t, f.(*factory).dops.callerIdentity)
}

// TestFactory_WithTLS checks that the TLS configuration of the WithTLS
// option is the one the client dials with: the client TLS files, which do
// not exist here, are not read
func TestFactory_WithTLS(t *testing.T) {
	f := NewFactory(Config{
		ServerURL: map[string]string{
			"local": "https://localhost:8880",
		},
		ClientTLS: gserver.TLSInfo{
			CertFile:      "/nope/client.pem",
			KeyFile:       "/nope/client.key",
			TrustedCAFile: "/nope/root.pem",
		},
	})
	_, _, err := f.CAClient("local")
	require.Error(t, err, "the client TLS files do not exist")
	assert.Contains(t, err.Error(), "unable to build TLS configuration")

	c, err := f.(*factory).NewClient("local", WithTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
	require.NoError(t, err)
	defer c.Close()
	assert.NotNil(t, c.Conn())
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
