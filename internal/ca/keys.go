package ca

import (
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/dataprotection"
)

const (
	// SoftwareKeyProvider names the provider of a key that no crypto
	// provider holds: the key material is kept wrapped by the data
	// protection provider in key_protected. It is the name of the xpki
	// in-memory provider, which generates such keys and is for tests and
	// development only.
	SoftwareKeyProvider = "inmem"

	// DefaultKeyAlgo is the algorithm of a generated key when the request
	// names none
	DefaultKeyAlgo = "ECDSA"
	// DefaultKeySize is the curve of a generated key when the request names
	// none
	DefaultKeySize = 256

	// keyURIPrefix starts a reference to a key in a crypto provider, which
	// cryptoprov resolves to the provider and the key
	keyURIPrefix = "pkcs11:"
	// keyLabelFormat is the label of the key of an issuer in its provider
	keyLabelFormat = "trustyca/%d/%d/%s"
	// providerModelSeparator separates the manufacturer and the model in a
	// key provider name
	providerModelSeparator = "/"
)

// allowedKeySizes lists the accepted sizes per key algorithm
var allowedKeySizes = map[string][]int{
	"RSA":   {2048, 3072, 4096},
	"ECDSA": {256, 384},
}

// KeySpec returns the algorithm and size of the key to generate for a
// request; a nil or empty specification takes the defaults, and a size the
// algorithm does not accept is an error
func KeySpec(spec *pb.KeySpec) (string, int, error) {
	algo := DefaultKeyAlgo
	size := DefaultKeySize
	if spec != nil {
		if spec.Algo != "" {
			algo = strings.ToUpper(spec.Algo)
		}
		if spec.Size != 0 {
			size = int(spec.Size)
		}
	}
	sizes, ok := allowedKeySizes[algo]
	if !ok {
		return "", 0, errors.Errorf("unsupported key algorithm: %s", algo)
	}
	if !slices.Contains(sizes, size) {
		return "", 0, errors.Errorf("unsupported %s key size: %d", algo, size)
	}
	return algo, size, nil
}

// KeyLabel returns the label of the key of an issuer in its crypto provider:
// trustyca/{org}/{project}/{label}, with 0 for the platform and the org scope
func KeyLabel(orgID, projectID xdb.ID, label string) string {
	return fmt.Sprintf(keyLabelFormat, orgID.UInt64(), projectID.UInt64(), label)
}

// IsKeyURI returns true when the key is a reference to a key in a crypto
// provider rather than key material
func IsKeyURI(key string) bool {
	return strings.HasPrefix(strings.TrimSpace(key), keyURIPrefix)
}

// KeyRef locates the private key of an issuer; it is stored in the key
// columns of the issuer row and never carries plain key material
type KeyRef struct {
	// Provider is the manufacturer of the crypto provider that holds the
	// key, or SoftwareKeyProvider
	Provider string
	// KeyID is the URI of the key in its provider, or the key label of a
	// software key
	KeyID string
	// Protected is the wrapped PEM of a software key; empty for a key a
	// provider holds
	Protected string
}

// Apply sets the key columns of the issuer row
func (r *KeyRef) Apply(m *model.Issuer) {
	m.KeyProvider = r.Provider
	m.KeyID = r.KeyID
	m.KeyProtected = xdb.NULLString(r.Protected)
}

// Keys generates, loads and protects the private keys of the issuers. A key
// generated in a KMS or HSM provider is referenced by its URI and never
// leaves the provider; a software key is wrapped by the data protection
// provider before it is stored.
type Keys struct {
	crypto *cryptoprov.Crypto
	dp     dataprotection.Provider
}

// NewKeys returns the key management over the crypto providers and the data
// protection provider; either may be nil when the deployment has none, and
// the operations that need it fail
func NewKeys(crypto *cryptoprov.Crypto, dp dataprotection.Provider) *Keys {
	return &Keys{
		crypto: crypto,
		dp:     dp,
	}
}

// Crypto returns the crypto providers
func (k *Keys) Crypto() *cryptoprov.Crypto {
	return k.crypto
}

// Provider returns the crypto provider with the name, `manufacturer` or
// `manufacturer/model`; an empty name is the default provider
func (k *Keys) Provider(name string) (cryptoprov.Provider, error) {
	if k.crypto == nil {
		return nil, errors.New("crypto providers are not configured")
	}
	def := k.crypto.Default()
	if name == "" {
		if def == nil {
			return nil, errors.New("default crypto provider is not configured")
		}
		return def, nil
	}
	manufacturer, model, _ := strings.Cut(name, providerModelSeparator)
	if def != nil && def.Manufacturer() == manufacturer && (model == "" || def.Model() == model) {
		return def, nil
	}
	p, err := k.crypto.ByManufacturer(manufacturer, model)
	if err != nil {
		return nil, errors.WithMessagef(err, "key provider not found: %s", name)
	}
	return p, nil
}

// Generate generates the key of an issuer in the provider, with the label
// and specification, and signs the certificate request with it. It returns
// the PEM encoded CSR, the signer and the reference to store on the row.
func (k *Keys) Generate(ctx context.Context, prov cryptoprov.Provider, keyLabel string, spec *pb.KeySpec, req *csr.CertificateRequest) ([]byte, crypto.Signer, *KeyRef, error) {
	algo, size, err := KeySpec(spec)
	if err != nil {
		return nil, nil, nil, err
	}
	c := csr.NewProvider(prov)
	req.KeyRequest = c.NewKeyRequest(keyLabel, algo, size, csr.SigningKey)
	csrPEM, priv, keyID, err := c.GenerateKeyAndRequest(req)
	if err != nil {
		return nil, nil, nil, errors.WithMessage(err, "unable to generate key")
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.Errorf("generated key of %T type does not sign", priv)
	}
	uri, exported, err := prov.ExportKey(keyID)
	if err != nil {
		return nil, nil, nil, errors.WithMessage(err, "unable to export key")
	}
	if len(exported) == 0 {
		exported = []byte(uri)
	}
	ref, err := k.KeyRefFromExport(ctx, prov, keyLabel, exported)
	if err != nil {
		return nil, nil, nil, err
	}
	return csrPEM, signer, ref, nil
}

// KeyRefFromExport returns the reference of a key its provider exported
// (cryptoprov.KeyGenerator.ExportKey, or the key authority.NewRoot returns):
// a key URI references the key in the provider, key material is wrapped
// and the reference carries the key label
func (k *Keys) KeyRefFromExport(ctx context.Context, prov cryptoprov.Provider, keyLabel string, exported []byte) (*KeyRef, error) {
	key := strings.TrimSpace(string(exported))
	if key == "" {
		return nil, errors.New("exported key is empty")
	}
	if IsKeyURI(key) {
		return &KeyRef{
			Provider: prov.Manufacturer(),
			KeyID:    key,
		}, nil
	}
	protected, err := k.ProtectKey(ctx, []byte(key))
	if err != nil {
		return nil, err
	}
	return &KeyRef{
		Provider:  SoftwareKeyProvider,
		KeyID:     keyLabel,
		Protected: protected,
	}, nil
}

// ProtectKey wraps the PEM of a software key with the data protection
// provider; the result is what key_protected stores
func (k *Keys) ProtectKey(ctx context.Context, keyPEM []byte) (string, error) {
	if k.dp == nil {
		return "", errors.New("data protection provider is not configured")
	}
	protected, err := k.dp.Protect(ctx, keyPEM)
	if err != nil {
		return "", errors.WithMessage(err, "unable to protect key")
	}
	return base64.RawURLEncoding.EncodeToString(protected), nil
}

// Signer returns the signer of an issuer row: the wrapped software key, or
// the key its URI references in a crypto provider
func (k *Keys) Signer(ctx context.Context, m *model.Issuer) (crypto.Signer, error) {
	if protected := m.KeyProtected.String(); protected != "" {
		if k.dp == nil {
			return nil, errors.New("data protection provider is not configured")
		}
		raw, err := base64.RawURLEncoding.DecodeString(protected)
		if err != nil {
			return nil, errors.WithMessagef(err, "invalid protected key of issuer %s", idString(m.ID))
		}
		keyPEM, err := k.dp.Unprotect(ctx, raw)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to unprotect key of issuer %s", idString(m.ID))
		}
		return signerFromPEM(keyPEM)
	}
	if IsKeyURI(m.KeyID) {
		if k.crypto == nil {
			return nil, errors.New("crypto providers are not configured")
		}
		signer, err := k.crypto.NewSignerFromPEM([]byte(m.KeyID))
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to load key of issuer %s", idString(m.ID))
		}
		return signer, nil
	}
	return nil, errors.Errorf("issuer %s has no key", idString(m.ID))
}

// ImportKey returns the signer and the reference of an existing key: by its
// URI in a crypto provider, or as PEM, which is wrapped. The key must be the
// private key of the public key.
func (k *Keys) ImportKey(ctx context.Context, keyURI string, keyPEM []byte, keyLabel string, pub crypto.PublicKey) (crypto.Signer, *KeyRef, error) {
	var signer crypto.Signer
	var ref *KeyRef
	switch {
	case keyURI != "":
		keyURI = strings.TrimSpace(keyURI)
		if !IsKeyURI(keyURI) {
			return nil, nil, errors.New("invalid key URI")
		}
		puri, err := cryptoprov.ParsePrivateKeyURI(keyURI)
		if err != nil {
			return nil, nil, errors.WithMessage(err, "invalid key URI")
		}
		if k.crypto == nil {
			return nil, nil, errors.New("crypto providers are not configured")
		}
		signer, err = k.crypto.NewSignerFromPEM([]byte(keyURI))
		if err != nil {
			return nil, nil, errors.WithMessage(err, "unable to load key")
		}
		ref = &KeyRef{
			Provider: puri.Manufacturer(),
			KeyID:    keyURI,
		}
	case len(keyPEM) > 0:
		var err error
		signer, err = signerFromPEM(keyPEM)
		if err != nil {
			return nil, nil, err
		}
		protected, err := k.ProtectKey(ctx, keyPEM)
		if err != nil {
			return nil, nil, err
		}
		ref = &KeyRef{
			Provider:  SoftwareKeyProvider,
			KeyID:     keyLabel,
			Protected: protected,
		}
	default:
		return nil, nil, errors.New("key is required")
	}
	if !PublicKeysEqual(signer.Public(), pub) {
		return nil, nil, errors.New("key does not match the certificate")
	}
	return signer, ref, nil
}

// Destroy removes the key of an issuer from its crypto provider, when the
// provider manages keys. A software key has no provider copy: it is
// destroyed when the row clears key_protected.
func (k *Keys) Destroy(_ context.Context, m *model.Issuer) error {
	if !IsKeyURI(m.KeyID) {
		return nil
	}
	puri, err := cryptoprov.ParsePrivateKeyURI(m.KeyID)
	if err != nil {
		return errors.WithMessagef(err, "invalid key URI of issuer %s", idString(m.ID))
	}
	if k.crypto == nil {
		return errors.New("crypto providers are not configured")
	}
	prov, err := k.crypto.ByManufacturer(puri.Manufacturer(), puri.Model())
	if err != nil {
		return errors.WithMessagef(err, "key provider of issuer %s", idString(m.ID))
	}
	km, ok := prov.(cryptoprov.KeyManager)
	if !ok {
		return errors.Errorf("key provider %s does not manage keys", prov.Manufacturer())
	}
	err = km.DestroyKeyPairOnSlot(km.CurrentSlotID(), puri.ID())
	if err != nil {
		return errors.WithMessagef(err, "unable to destroy key of issuer %s", idString(m.ID))
	}
	return nil
}

// PublicKeysEqual reports whether the two public keys are the same key
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	e, ok := a.(interface {
		Equal(crypto.PublicKey) bool
	})
	return ok && b != nil && e.Equal(b)
}

// signerFromPEM parses the PEM of a software key
func signerFromPEM(keyPEM []byte) (crypto.Signer, error) {
	priv, err := cryptoprov.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid key")
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.Errorf("key of %T type does not sign", priv)
	}
	return signer, nil
}

// SubjectKeyID returns the key identifier of a public key: the SHA-1 of its
// subjectPublicKey bits (RFC 5280 section 4.2.1.2 method 1). It is the
// identifier the CA puts in the certificates it issues, the IKID of the
// certificates the key signs and the issuer key hash of their OCSP
// requests, so a Pending issuer is identified by it before it has a
// certificate.
func SubjectKeyID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", errors.WithMessage(err, "unable to encode public key")
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &spki)
	if err != nil {
		return "", errors.WithMessage(err, "unable to decode public key")
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
