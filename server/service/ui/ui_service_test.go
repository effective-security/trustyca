package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/server/service/ui"
	"github.com/effective-security/trustyca/tests/mockappcontainer"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRecaptchaSiteKey = "recaptcha-site-key-123"
	testPublishableKey   = "pk_test_publishable123"
)

var (
	testServer gserver.GServer
	httpAddr   string
)

var htmlHeaders = map[string]string{
	header.Accept: "text/html,application/xhtml+xml",
}

// serviceFactories provides map of gserver.ServiceFactory
var serviceFactories = map[string]gserver.ServiceFactory{
	ui.ServiceName: ui.Factory,
}

func TestMain(m *testing.M) {
	var err error

	httpAddr = testutils.CreateURL("http", "")

	cfg := &gserver.Config{
		ListenURLs: []string{httpAddr},
		Services:   []string{ui.ServiceName},
	}

	container := mockappcontainer.NewBuilder().
		WithConfig(&config.Configuration{
			Auth: config.Auth{
				RecaptchaSiteKey: testRecaptchaSiteKey,
			},
			// TrustyRA: config.TrustyRA{
			// 	Payments: &payment.Config{
			// 		PublishableKey: testPublishableKey,
			// 	},
			// },
		}).
		WithDiscovery(discovery.New()).
		Container()

	testServer, err = gserver.Start("UITest", cfg, container, serviceFactories)
	if err != nil || testServer == nil {
		panic(errors.WithStack(err))
	}

	rc := m.Run()

	testServer.Close()
	os.Exit(rc)
}

func TestFactory(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() {
		ui.Factory(nil)
	})
}

func TestService(t *testing.T) {
	t.Parallel()
	svc := testServer.Service(ui.ServiceName).(*ui.Service)
	require.NotNil(t, svc)
	assert.Equal(t, ui.ServiceName, svc.Name())
	assert.True(t, svc.IsReady())
	assert.NotPanics(t, svc.Close)
}

func getPage(t *testing.T, path string, headers map[string]string) (http.Header, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := context.Background()
	if headers != nil {
		ctx = retriable.WithHeaders(ctx, headers)
	}
	hdr, _, err := client.Get(ctx, path, w)
	require.NoError(t, err)
	return hdr, w
}

func TestIndex_Plain(t *testing.T) {
	t.Parallel()
	// no Accept: text/html, as a load balancer or curl would send
	hdr, w := getPage(t, "/", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, hdr.Get(header.ContentType), header.TextPlain)
	assert.Equal(t, "ALIVE", w.Body.String())
}

func TestIndex_HTML(t *testing.T) {
	t.Parallel()
	hdr, w := getPage(t, "/", htmlHeaders)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, hdr.Get(header.ContentType), "text/html")
	assert.Equal(t, "no-store", hdr.Get("Cache-Control"))

	body := w.Body.String()
	assert.Contains(t, body, "<title>Trusty · Trusty</title>")
	assert.Contains(t, body, "<h1>ALIVE</h1>")
	assert.Contains(t, body, "Use API to access the server.")
	assert.NotContains(t, body, `href="/login"`)
	assert.NotContains(t, body, `href="/payment"`)
}

func TestLoginPage(t *testing.T) {
	t.Parallel()
	hdr, w := getPage(t, pb.PathForLoginPage, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, hdr.Get(header.ContentType), "text/html")

	body := w.Body.String()
	assert.Contains(t, body, "<title>Login · Trusty</title>")
	// reCAPTCHA v3 is loaded with the configured site key,
	// and the same key is handed to the script that executes it
	assert.Contains(t, body, `https://www.google.com/recaptcha/api.js?render=`+testRecaptchaSiteKey)
	assert.Contains(t, body, `var recaptchaSiteKey = "`+testRecaptchaSiteKey+`";`)
	assert.NotContains(t, body, "reCAPTCHA is not configured")
	// the page discovers providers and starts the flow via the auth end-points
	assert.Contains(t, body, `fetch('`+pb.PathForAuthProviders+`'`)
	assert.Contains(t, body, `window.location.origin + '`+pb.PathForAuthenticatedPage+`'`)
	assert.Contains(t, body, "q.set('recaptcha_token', recaptcha)")
}

func TestAuthenticatedPage(t *testing.T) {
	t.Parallel()
	hdr, w := getPage(t, pb.PathForAuthenticatedPage, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, hdr.Get(header.ContentType), "text/html")

	body := w.Body.String()
	assert.Contains(t, body, "<title>Authenticated · Trusty</title>")
	assert.Contains(t, body, "Done.")
	assert.Contains(t, body, "You are authenticated and can close this window.")
	assert.Contains(t, body, "export TRUSTYCA_AUTH_TOKEN=")
}

func TestPaymentPage(t *testing.T) {
	t.Parallel()
	hdr, w := getPage(t, pb.PathForPaymentPage, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, hdr.Get(header.ContentType), "text/html")

	body := w.Body.String()
	assert.Contains(t, body, "<title>Payment · Trusty</title>")
	assert.Contains(t, body, `<script src="https://js.stripe.com/v3/"></script>`)
	assert.NotContains(t, body, `var publishableKey = "`+testPublishableKey+`";`)
	assert.Contains(t, body, `fragment.get('`+pb.CheckoutClientSecretParam+`')`)
	assert.Contains(t, body, "stripe.confirmPayment(")
	// the secret API key must never be rendered
	assert.NotContains(t, body, "sk_")
}

// The pages must render when the optional keys are not configured,
// telling the tester what is missing instead of failing.
func TestPages_NotConfigured(t *testing.T) {
	t.Parallel()

	for _, cfg := range []*config.Configuration{
		{},
		//{RA: config.TrustyRA{Payments: &payment.Config{}}},
	} {
		svc := ui.New(cfg)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, pb.PathForLoginPage, nil)
		svc.PageHandler(pb.PathForLoginPage)(w, r, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "reCAPTCHA is not configured in Trusty (auth.recaptcha_site_key)")
		assert.Contains(t, w.Body.String(), `var recaptchaSiteKey = "";`)
		assert.NotContains(t, w.Body.String(), "recaptcha/api.js")

		w = httptest.NewRecorder()
		r = httptest.NewRequest(http.MethodGet, pb.PathForPaymentPage, nil)
		svc.PageHandler(pb.PathForPaymentPage)(w, r, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `var publishableKey = "";`)
		assert.Contains(t, w.Body.String(), "Stripe is not configured on the server (trustyca.payments.publishable_key)")
	}
}

func TestPageHandler_Unknown(t *testing.T) {
	t.Parallel()
	svc := ui.New(&config.Configuration{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/missing", nil)
	svc.PageHandler("/missing")(w, r, nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to render page")
}
