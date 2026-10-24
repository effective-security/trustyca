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
	f, err := NewFactory([]Config{
		{
			Name: ClientNameCA,
			ServerURL: map[string]string{
				"local": "https://localhost:8880",
			},
			ClientTLS: gserver.TLSInfo{
				CertFile:      homeDir + "/.trustyca/certs/trustyca_peer.pem",
				KeyFile:       homeDir + "/.trustyca/certs/trustyca_peer.key",
				TrustedCAFile: homeDir + "/.trustyca/certs/trustyca_root.pem",
			},
		},
	}, WithTLS(nil))
	require.NoError(t, err)
	_, _, err = f.StatusClient(ClientNameCA, "invalid")
	assert.EqualError(t, err, "server invalid not found in client ca")
	_, _, err = f.StatusClient(ClientNameAIA, "local")
	assert.EqualError(t, err, "client aia not found")

	_, closer, err := f.StatusClient(ClientNameCA, "local")
	require.NoError(t, err)
	defer closer.Close()

	_, closer, err = f.OrgsClient(ClientNameCA, "local")
	require.NoError(t, err)
	defer closer.Close()

	_, closer, err = f.CAClient(ClientNameCA, "local")
	require.NoError(t, err)
	defer closer.Close()
	_, _, err = f.CAClient(ClientNameCA, "invalid")
	assert.EqualError(t, err, "server invalid not found in client ca")

	_, closer, err = f.CISClient(ClientNameCA, "local")
	require.NoError(t, err)
	defer closer.Close()

	assert.Nil(t, f.(*factory).dops.callerIdentity)
}

// TestNewFactory_Names covers the names of the clients: every client needs
// one, a name is unique, and each client dials with its own settings
func TestNewFactory_Names(t *testing.T) {
	_, err := NewFactory([]Config{
		{
			Name: ClientNameAIA,
		},
		{
			ServerURL: map[string]string{
				"backend": "https://localhost:8881",
			},
		},
	})
	assert.EqualError(t, err, "client 1 has no name")

	_, err = NewFactory([]Config{
		{
			Name: ClientNameAIA,
		},
		{
			Name: ClientNameAIA,
		},
	})
	assert.EqualError(t, err, "duplicate client: aia")

	f, err := NewFactory(nil)
	require.NoError(t, err)
	_, _, err = f.CAClient(ClientNameCA, "backend")
	assert.EqualError(t, err, "client ca not found")

	// the clients do not share their files: the aia client builds its TLS
	// configuration from files that do not exist, the ca client dials in
	// plaintext
	f, err = NewFactory([]Config{
		{
			Name: ClientNameAIA,
			ServerURL: map[string]string{
				"backend": "https://localhost:8881",
			},
			ClientTLS: gserver.TLSInfo{
				CertFile:      "/nope/aia.pem",
				KeyFile:       "/nope/aia.key",
				TrustedCAFile: "/nope/root.pem",
			},
		},
		{
			Name: ClientNameCA,
			ServerURL: map[string]string{
				"backend": "http://localhost:8881",
			},
		},
	})
	require.NoError(t, err)
	_, _, err = f.CAClient(ClientNameAIA, "backend")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to build TLS configuration")
	_, closer, err := f.CAClient(ClientNameCA, "backend")
	require.NoError(t, err)
	assert.NoError(t, closer.Close())
}

// TestFactory_WithTLS checks that the TLS configuration of the WithTLS
// option is the one the client dials with: the client TLS files, which do
// not exist here, are not read
func TestFactory_WithTLS(t *testing.T) {
	f, err := NewFactory([]Config{
		{
			Name: ClientNameCA,
			ServerURL: map[string]string{
				"local": "https://localhost:8880",
			},
			ClientTLS: gserver.TLSInfo{
				CertFile:      "/nope/client.pem",
				KeyFile:       "/nope/client.key",
				TrustedCAFile: "/nope/root.pem",
			},
		},
	})
	require.NoError(t, err)
	_, _, err = f.CAClient(ClientNameCA, "local")
	require.Error(t, err, "the client TLS files do not exist")
	assert.Contains(t, err.Error(), "unable to build TLS configuration")

	c, err := f.(*factory).NewClient(ClientNameCA, "local", WithTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
	require.NoError(t, err)
	defer c.Close()
	assert.NotNil(t, c.Conn())
}

func TestFactoryCNA(t *testing.T) {
	ci := &callerIdentityMock{}
	cfgs := []Config{
		{
			Name: ClientNameCA,
			ServerURL: map[string]string{
				"local": "https://localhost:8880",
			},
			EnableCNA: true,
		},
	}

	f, err := NewFactory(cfgs, WithCallerIdentity(ci))
	require.NoError(t, err)
	assert.NotNil(t, f.(*factory).dops.callerIdentity)

	f, err = NewFactory(cfgs)
	require.NoError(t, err)
	assert.Nil(t, f.(*factory).dops.callerIdentity)

	c, err := f.(*factory).NewClient(ClientNameCA, "local", WithCallerIdentity(ci))
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
