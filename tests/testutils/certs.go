package testutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCA is an in-memory certificate authority for tests: an ECDSA P-256 key
// and a CA certificate, self-signed or signed by Parent. Every certificate it
// signs carries a Subject Key Identifier and the Authority Key Identifier of
// the CA, as the certificates the service issues do.
type TestCA struct {
	Key    *ecdsa.PrivateKey
	Cert   *x509.Certificate
	Parent *TestCA
}

// serialNumberBytes is the length of the random serial numbers
const serialNumberBytes = 16

// NewTestCA creates a CA with the common name, signed by the parent or
// self-signed when the parent is nil; the certificate is valid for ten years
func NewTestCA(t testing.TB, cn string, parent *TestCA) *TestCA {
	t.Helper()
	key := newTestKey(t)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          randomSerialNumber(t),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustyca tests"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID(t, &key.PublicKey),
	}
	ca := &TestCA{Key: key, Parent: parent}
	ca.Cert = sign(t, template, parent, ca)
	return ca
}

// Issue signs an end-entity certificate with the common name and validity
func (ca *TestCA) Issue(t testing.TB, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key := newTestKey(t)
	template := &x509.Certificate{
		SerialNumber:          randomSerialNumber(t),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustyca tests"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          subjectKeyID(t, &key.PublicKey),
	}
	return sign(t, template, ca, &TestCA{Key: key})
}

// ChainPEM returns the PEM encoding of the CA certificates above this one,
// from the parent up to the root; empty for a root
func (ca *TestCA) ChainPEM() string {
	var chain strings.Builder
	for p := ca.Parent; p != nil; p = p.Parent {
		chain.WriteString(CertPEM(p.Cert))
	}
	return chain.String()
}

// Root returns the self-signed CA at the top of the chain
func (ca *TestCA) Root() *TestCA {
	root := ca
	for root.Parent != nil {
		root = root.Parent
	}
	return root
}

// CertPEM returns the PEM encoding of the certificate
func CertPEM(crt *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw}))
}

// sign creates the certificate of the template for the subject's key, signed
// by the issuer, or self-signed when the issuer is nil
func sign(t testing.TB, template *x509.Certificate, issuer, subject *TestCA) *x509.Certificate {
	t.Helper()
	parent := template
	signer := subject.Key
	if issuer != nil {
		parent = issuer.Cert
		signer = issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &subject.Key.PublicKey, signer)
	require.NoError(t, err)
	crt, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return crt
}

func newTestKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func randomSerialNumber(t testing.TB) *big.Int {
	t.Helper()
	b := make([]byte, serialNumberBytes)
	_, err := rand.Read(b)
	require.NoError(t, err)
	// clear the top bit so the serial number is positive
	b[0] &= 0x7f
	return new(big.Int).SetBytes(b)
}

// subjectKeyID returns the SHA-1 of the public key, the method 1 key
// identifier of RFC 5280
func subjectKeyID(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	sum := sha1.Sum(der)
	return sum[:]
}
