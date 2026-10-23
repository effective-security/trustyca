package backend

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/effective-security/trustyca/privpb"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// logCapture is the log output of a test, written by every goroutine
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// TestService_KeyMaterialNeverLogged imports an issuer with a known PEM key
// and creates one with a generated key at the TRACE level, and checks that
// neither the key nor its wrapped form reaches the log. It is not
// parallel: the log formatter is process-wide, so the output of the tests
// that run meanwhile is captured too, which only widens the check.
func TestService_KeyMaterialNeverLogged(t *testing.T) {
	capture := &logCapture{}
	prev := xlog.GetFormatter()
	xlog.SetFormatter(xlog.NewStringFormatter(capture))
	xlog.SetGlobalLogLevel(xlog.TRACE)
	t.Cleanup(func() {
		xlog.SetFormatter(prev)
		xlog.SetGlobalLogLevel(xlog.INFO)
	})

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	storeRootIssuer(tca, nil)
	storeRootIssuer(tca, nil)

	root := testutils.NewTestCA(t, "Logged Root", nil)
	key := keyPEM(t, root.Key)
	imported, err := svc.ImportIssuer(ctx, &privpb.ImportIssuerRequest{
		Label:       "LOGCHK",
		Type:        pb.AuthorityType_Root,
		Certificate: testutils.CertPEM(root.Cert),
		KeyPem:      key,
	})
	require.NoError(t, err)
	generated, err := svc.RegisterIssuer(ctx, &privpb.RegisterIssuerRequest{
		Label:   "LOGGEN",
		Type:    pb.AuthorityType_Root,
		Subject: &pb.X509Subject{CommonName: "Logged Generated Root"},
		Profile: testCAProfile,
	})
	require.NoError(t, err)

	logs := capture.String()
	require.Contains(t, logs, "issuer_imported", "the log is captured")
	require.Contains(t, logs, "issuer_registered")
	// the PEM key, line by line, since a log line may wrap it
	for _, line := range strings.Split(strings.TrimSpace(key), "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		assert.NotContains(t, logs, line, "the imported key is logged")
	}
	// the wrapped keys of both rows
	for _, label := range []string{imported.Label, generated.Label} {
		row, err := tca.rows.findIssuer(ctx, 1, 0, label)
		require.NoError(t, err)
		protected := row.KeyProtected.String()
		require.NotEmpty(t, protected, "%s is a software key", label)
		assert.NotContains(t, logs, protected, "the wrapped key of %s is logged", label)
		assert.NotContains(t, logs, protected[:32])
	}
	// the responses carry no key either
	for _, res := range []*pb.Issuer{imported, generated} {
		assert.NotContains(t, res.String(), "PRIVATE KEY")
		assert.NotContains(t, res.String(), "KeyProtected")
	}
}
