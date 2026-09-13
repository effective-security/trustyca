package admin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/go-jose/go-jose/v3"
	"github.com/olekukonko/tablewriter"
)

// DpopKeysCmd is the parent for keys command
type DpopKeysCmd struct {
	Gen  DpopKeyGenCmd  `cmd:"" help:"generate new key"`
	List DpopKeyListCmd `cmd:"" help:"list keys"`
}

// DpopKeyGenCmd generate new key
type DpopKeyGenCmd struct {
	Label string `kong:"arg" required:"" help:"flag specifies key label"`
}

var keyNamePattern = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

// Run the command
func (a *DpopKeyGenCmd) Run(app App) error {
	client, err := app.HTTPClient(true)
	if err != nil {
		return err
	}
	k, err := dpop.GenerateKey(keyNamePattern.ReplaceAllString(a.Label, "_"))
	if err != nil {
		return err
	}

	fn, err := client.Config.Storage().SaveKey(k)
	if err != nil {
		return err
	}

	fmt.Fprintf(app.Writer(), "key saved to '%s': \n", fn)
	app.Print(k.Public())
	return nil
}

// DpopKeyListCmd lists keys
type DpopKeyListCmd struct {
}

// Run the command
func (a *DpopKeyListCmd) Run(app App) error {
	client, err := app.HTTPClient(true)
	if err != nil {
		return err
	}

	list, err := client.Storage().ListKeys()
	if err != nil {
		return err
	}

	PrintKeys(app.Writer(), list)
	return nil
}

// PrintKeys prints keys
func PrintKeys(w io.Writer, list []*retriable.KeyInfo) {
	table := tablewriter.NewTable(w)
	table.Header([]string{"thumbprint", "type", "algo", "size", "label"})

	for _, c := range list {
		_ = table.Append([]string{
			c.Thumbprint,
			c.Type,
			c.Algo,
			fmt.Sprintf("%d", c.KeySize),
			c.Key.KeyID,
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

// KeyInfo specifies key info
type KeyInfo struct {
	keySize int
	typ     string
	algo    string
	tp      string
	key     *jose.JSONWebKey
}

// KeySize returns key size
func (k *KeyInfo) KeySize() int {
	return k.keySize
}

// Type returns key type
func (k *KeyInfo) Type() string {
	return k.typ
}

// NewKeyInfo returns *keyInfo
func NewKeyInfo(k *jose.JSONWebKey) (*KeyInfo, error) {
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	si := &KeyInfo{
		key: k,
		tp:  base64.RawURLEncoding.EncodeToString(tp),
	}

	switch typ := k.Key.(type) {
	case *rsa.PrivateKey:
		si.keySize = typ.N.BitLen()
		si.typ = "RSA"
		switch {
		case si.keySize >= 4096:
			si.algo = "RS512"
		case si.keySize >= 3072:
			si.algo = "RS384"
		default:
			si.algo = "RS256"
		}
	case *ecdsa.PrivateKey:
		si.typ = "ECDSA"
		switch typ.Curve {
		case elliptic.P521():
			si.algo = "ES512"
		case elliptic.P384():
			si.algo = "ES384"
		default:
			si.algo = "ES256"
		}
		si.keySize = typ.Curve.Params().BitSize
	default:
		return nil, errors.Errorf("key not supported: %T", typ)
	}
	return si, nil
}
