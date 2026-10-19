package ca_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeySpec(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		name string
		spec *pb.KeySpec
		algo string
		size int
		err  string
	}{
		{name: "defaults", algo: "ECDSA", size: 256},
		{name: "empty", spec: &pb.KeySpec{}, algo: "ECDSA", size: 256},
		{name: "size only", spec: &pb.KeySpec{Size: 384}, algo: "ECDSA", size: 384},
		{name: "rsa", spec: &pb.KeySpec{Algo: "rsa", Size: 2048}, algo: "RSA", size: 2048},
		{name: "rsa 4096", spec: &pb.KeySpec{Algo: "RSA", Size: 4096}, algo: "RSA", size: 4096},
		{name: "rsa default size", spec: &pb.KeySpec{Algo: "RSA"}, err: "unsupported RSA key size: 256"},
		{name: "rsa small", spec: &pb.KeySpec{Algo: "RSA", Size: 1024}, err: "unsupported RSA key size: 1024"},
		{name: "p521", spec: &pb.KeySpec{Algo: "ECDSA", Size: 521}, err: "unsupported ECDSA key size: 521"},
		{name: "dsa", spec: &pb.KeySpec{Algo: "DSA", Size: 2048}, err: "unsupported key algorithm: DSA"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			algo, size, err := ca.KeySpec(tc.spec)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.algo, algo)
			assert.Equal(t, tc.size, size)
		})
	}
}

func TestKeyLabel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "trustyca/1/201/L2", ca.KeyLabel(xdb.NewID(1), xdb.NewID(201), "L2"))
	assert.Equal(t, "trustyca/0/0/ROOT", ca.KeyLabel(xdb.ID{}, xdb.ID{}, "ROOT"))
	assert.True(t, ca.IsKeyURI("pkcs11:manufacturer=AWSKMS;id=1"))
	assert.True(t, ca.IsKeyURI("  pkcs11:manufacturer=AWSKMS;id=1\n"))
	assert.False(t, ca.IsKeyURI("-----BEGIN EC PRIVATE KEY-----"))
	assert.False(t, ca.IsKeyURI(""))
}

func TestSubjectKeyID(t *testing.T) {
	t.Parallel()
	// the identifier the authority puts in the certificates it issues
	f := newFixture(t)
	root := f.root(xdb.NewID(1), xdb.ID{}, "R", nil)
	signer, err := f.keys.Signer(f.ctx, root)
	require.NoError(t, err)
	skid, err := ca.SubjectKeyID(signer.Public())
	require.NoError(t, err)
	assert.Equal(t, root.Skid, skid)
	_, err = ca.SubjectKeyID("not a key")
	assert.ErrorContains(t, err, "unable to encode public key")
}

// inmemURI returns the key URI of a key the inmem provider holds
func inmemURI(prov cryptoprov.Provider, keyID string) string {
	return fmt.Sprintf("pkcs11:manufacturer=%s;model=%s;serial=1;type=private;id=%s", prov.Manufacturer(), prov.Model(), keyID)
}

func TestKeys_Generate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	keyLabel := ca.KeyLabel(xdb.NewID(1), xdb.ID{}, "L2")

	csrPEM, signer, ref, err := f.keys.Generate(f.ctx, f.prov, keyLabel, nil, &csr.CertificateRequest{CommonName: "Generated"})
	require.NoError(t, err)
	assert.Equal(t, ca.SoftwareKeyProvider, ref.Provider)
	assert.Equal(t, keyLabel, ref.KeyID)
	require.NotEmpty(t, ref.Protected)
	assert.NotContains(t, ref.Protected, "PRIVATE KEY", "the key material is wrapped")
	req, err := csr.ParsePEM(csrPEM)
	require.NoError(t, err)
	assert.Equal(t, "Generated", req.Subject.CommonName)
	assert.True(t, ca.PublicKeysEqual(signer.Public(), req.PublicKey))
	assert.IsType(t, &ecdsa.PublicKey{}, signer.Public())

	// the row loads the same key back
	row := &model.Issuer{ID: xdb.NewID(7)}
	ref.Apply(row)
	assert.Equal(t, ca.SoftwareKeyProvider, row.KeyProvider)
	assert.Equal(t, keyLabel, row.KeyID)
	loaded, err := f.keys.Signer(f.ctx, row)
	require.NoError(t, err)
	assert.True(t, ca.PublicKeysEqual(signer.Public(), loaded.Public()))

	// RSA
	_, signer, _, err = f.keys.Generate(f.ctx, f.prov, keyLabel, &pb.KeySpec{Algo: "RSA", Size: 2048}, &csr.CertificateRequest{CommonName: "RSA"})
	require.NoError(t, err)
	assert.Equal(t, "*rsa.PublicKey", fmt.Sprintf("%T", signer.Public()))

	// invalid spec
	_, _, _, err = f.keys.Generate(f.ctx, f.prov, keyLabel, &pb.KeySpec{Algo: "DSA"}, &csr.CertificateRequest{CommonName: "x"})
	assert.EqualError(t, err, "unsupported key algorithm: DSA")

	// a key can only be wrapped with a data protection provider
	keys := ca.NewKeys(f.keys.Crypto(), nil)
	_, _, _, err = keys.Generate(f.ctx, f.prov, keyLabel, nil, &csr.CertificateRequest{CommonName: "x"})
	assert.EqualError(t, err, "data protection provider is not configured")
}

func TestKeys_Signer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// a key a provider holds is loaded from its URI
	priv, err := f.prov.GenerateECDSAKey("uri-key", elliptic.P256())
	require.NoError(t, err)
	keyID, _, err := f.prov.IdentifyKey(priv)
	require.NoError(t, err)
	uri := inmemURI(f.prov, keyID)
	ref, err := f.keys.KeyRefFromExport(f.ctx, f.prov, "label", []byte(uri+"\n"))
	require.NoError(t, err)
	assert.Equal(t, &ca.KeyRef{Provider: inmemcrypto.ProviderName, KeyID: uri}, ref)
	row := &model.Issuer{ID: xdb.NewID(1)}
	ref.Apply(row)
	assert.Empty(t, row.KeyProtected)
	signer, err := f.keys.Signer(f.ctx, row)
	require.NoError(t, err)
	assert.True(t, ca.PublicKeysEqual(priv.(crypto.Signer).Public(), signer.Public()))

	// a provider key that does not exist
	_, err = f.keys.Signer(f.ctx, &model.Issuer{ID: xdb.NewID(2), KeyID: inmemURI(f.prov, "nope")})
	assert.ErrorContains(t, err, "unable to load key of issuer 2")

	// no key reference
	_, err = f.keys.Signer(f.ctx, &model.Issuer{ID: xdb.NewID(3), KeyID: "trustyca/0/0/x"})
	assert.EqualError(t, err, "issuer 3 has no key")

	// a protected key that is not ours
	_, err = f.keys.Signer(f.ctx, &model.Issuer{ID: xdb.NewID(4), KeyProtected: "!!!"})
	assert.ErrorContains(t, err, "invalid protected key of issuer 4")
	_, err = f.keys.Signer(f.ctx, &model.Issuer{ID: xdb.NewID(5), KeyProtected: "AAAA"})
	assert.ErrorContains(t, err, "unable to unprotect key of issuer 5")

	// a key wrapped with another secret
	_, _, ref, err = f.keys.Generate(f.ctx, f.prov, "label", nil, &csr.CertificateRequest{CommonName: "x"})
	require.NoError(t, err)
	ref.Apply(row)
	otherDp, err := dataprotection.NewSymmetric([]byte("other-seed"))
	require.NoError(t, err)
	_, err = ca.NewKeys(f.keys.Crypto(), otherDp).Signer(f.ctx, row)
	assert.ErrorContains(t, err, "unable to unprotect key of issuer 1")

	// without providers
	none := ca.NewKeys(nil, nil)
	_, err = none.Signer(f.ctx, row)
	assert.EqualError(t, err, "data protection provider is not configured")
	_, err = none.Signer(f.ctx, &model.Issuer{ID: xdb.NewID(6), KeyID: uri})
	assert.EqualError(t, err, "crypto providers are not configured")
	_, err = none.Provider("")
	assert.EqualError(t, err, "crypto providers are not configured")
	_, _, err = none.ImportKey(f.ctx, uri, nil, "label", signer.Public())
	assert.EqualError(t, err, "crypto providers are not configured")
	assert.NoError(t, none.Destroy(f.ctx, row), "a software key needs no provider")
	assert.EqualError(t, none.Destroy(f.ctx, &model.Issuer{ID: xdb.NewID(7), KeyID: uri}), "crypto providers are not configured")
}

func TestKeys_Provider(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, name := range []string{"", "inmem", "inmem/inmem"} {
		p, err := f.keys.Provider(name)
		require.NoError(t, err, name)
		assert.Same(t, f.prov, p, name)
	}
	_, err := f.keys.Provider("AWSKMS")
	assert.ErrorContains(t, err, "key provider not found: AWSKMS")
	_, err = f.keys.Provider("inmem/other")
	assert.ErrorContains(t, err, "key provider not found: inmem/other")

	// a second provider is found by manufacturer and model
	other := inmemcrypto.NewProvider()
	crypto, err := cryptoprov.New(f.prov, nil)
	require.NoError(t, err)
	require.Error(t, crypto.Add(other), "the same manufacturer and model is a duplicate")
}

func TestKeys_ImportKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, ref, err := f.keys.ImportKey(f.ctx, "", keyPEM, "label", &key.PublicKey)
	require.NoError(t, err)
	assert.True(t, ca.PublicKeysEqual(&key.PublicKey, signer.Public()))
	assert.Equal(t, ca.SoftwareKeyProvider, ref.Provider)
	assert.Equal(t, "label", ref.KeyID)
	assert.NotEmpty(t, ref.Protected)

	_, _, err = f.keys.ImportKey(f.ctx, "", keyPEM, "label", &other.PublicKey)
	assert.EqualError(t, err, "key does not match the certificate")
	_, _, err = f.keys.ImportKey(f.ctx, "", nil, "label", &key.PublicKey)
	assert.EqualError(t, err, "key is required")
	_, _, err = f.keys.ImportKey(f.ctx, "", []byte("junk"), "label", &key.PublicKey)
	assert.ErrorContains(t, err, "invalid key")
	_, _, err = f.keys.ImportKey(f.ctx, "https://kms/key", nil, "label", &key.PublicKey)
	assert.EqualError(t, err, "invalid key URI")
	_, _, err = f.keys.ImportKey(f.ctx, "pkcs11:manufacturer=inmem", nil, "label", &key.PublicKey)
	assert.ErrorContains(t, err, "invalid key URI")
	_, _, err = f.keys.ImportKey(f.ctx, inmemURI(f.prov, "nope"), nil, "label", &key.PublicKey)
	assert.ErrorContains(t, err, "unable to load key")

	// a key by URI
	priv, err := f.prov.GenerateECDSAKey("imported", elliptic.P256())
	require.NoError(t, err)
	keyID, _, err := f.prov.IdentifyKey(priv)
	require.NoError(t, err)
	uri := inmemURI(f.prov, keyID)
	signer, ref, err = f.keys.ImportKey(f.ctx, uri, nil, "label", priv.(crypto.Signer).Public())
	require.NoError(t, err)
	assert.Equal(t, &ca.KeyRef{Provider: inmemcrypto.ProviderName, KeyID: uri}, ref)
	assert.True(t, ca.PublicKeysEqual(priv.(crypto.Signer).Public(), signer.Public()))
	_, _, err = f.keys.ImportKey(f.ctx, uri, nil, "label", &other.PublicKey)
	assert.EqualError(t, err, "key does not match the certificate")

	// the inmem provider does not manage keys, so a URI key is not destroyed
	row := &model.Issuer{ID: xdb.NewID(1)}
	ref.Apply(row)
	assert.EqualError(t, f.keys.Destroy(f.ctx, row), "key provider inmem does not manage keys")
	assert.NoError(t, f.keys.Destroy(f.ctx, &model.Issuer{KeyID: "trustyca/1/0/x"}), "a software key is destroyed by the row")
	assert.ErrorContains(t, f.keys.Destroy(f.ctx, &model.Issuer{ID: xdb.NewID(2), KeyID: "pkcs11:manufacturer=x"}), "invalid key URI of issuer 2")
	assert.ErrorContains(t, f.keys.Destroy(f.ctx, &model.Issuer{ID: xdb.NewID(3), KeyID: strings.Replace(uri, "manufacturer=inmem", "manufacturer=AWSKMS", 1)}), "key provider of issuer 3")

	_, err = f.keys.KeyRefFromExport(f.ctx, f.prov, "label", []byte("  "))
	assert.EqualError(t, err, "exported key is empty")
}

func TestPublicKeysEqual(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.True(t, ca.PublicKeysEqual(&key.PublicKey, &key.PublicKey))
	assert.False(t, ca.PublicKeysEqual(&key.PublicKey, nil))
	assert.False(t, ca.PublicKeysEqual("x", &key.PublicKey))
	assert.False(t, ca.PublicKeysEqual(&key.PublicKey, "x"))
	_ = context.Background()
	_ = certutil.GetSubjectKeyID
}
