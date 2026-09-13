package admin_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/effective-security/trustyca/internal/ctl/admin"
	"github.com/effective-security/trustyca/internal/ctl/ctlsuite"
	"github.com/effective-security/xpki/certutil"
	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type testSuiteRest struct {
	ctlsuite.TestSuite
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(testSuiteRest))
}

func (s *testSuiteRest) TestKeys() {
	var a admin.DpopKeyGenCmd
	a.Label = certutil.RandomString(8)

	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	out := s.Out.String()
	s.Contains(out, "key saved to")

	s.Out.Reset()

	// overrite
	err = a.Run(s.Ctl)
	s.NoError(err)

	var b admin.DpopKeyListCmd
	err = b.Run(s.Ctl)
	s.Require().NoError(err)
	out = s.Out.String()
	s.Contains(out, "ALGO")
	s.Contains(out, "ALGO")
}

func TestKeyInfo(t *testing.T) {
	rsaSizes := []int{2024, 3072, 4096}
	for _, nbits := range rsaSizes {
		privateKey, err := rsa.GenerateKey(rand.Reader, nbits)
		require.NoError(t, err)

		k := &jose.JSONWebKey{
			Key:   privateKey,
			KeyID: "123",
		}
		ki, err := admin.NewKeyInfo(k)
		require.NoError(t, err)
		assert.Equal(t, nbits, ki.KeySize())
		assert.Equal(t, "RSA", ki.Type())
	}

	tcases := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, tc := range tcases {
		ecKey, err := ecdsa.GenerateKey(tc, rand.Reader)
		require.NoError(t, err)

		k := &jose.JSONWebKey{
			Key:   ecKey,
			KeyID: "123",
		}
		ki, err := admin.NewKeyInfo(k)
		require.NoError(t, err)
		assert.Equal(t, tc.Params().BitSize, ki.KeySize())
		assert.Equal(t, "ECDSA", ki.Type())
	}
}
