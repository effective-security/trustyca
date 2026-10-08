package command

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/x/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLoginState(t *testing.T, out io.Writer, port int) *svcState {
	c, err := retriable.New(retriable.ClientConfig{
		StorageFolder: t.TempDir(),
	})
	require.NoError(t, err)

	return &svcState{
		writer:       out,
		listenPort:   port,
		responseType: "token",
		client:       c,
		done:         make(chan struct{}),
	}
}

func isLoginDone(s *svcState) bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func TestLoginHandler(t *testing.T) {
	t.Parallel()

	port, err := netutil.FindFreePort("localhost", 5)
	require.NoError(t, err)

	t.Run("get", func(t *testing.T) {
		s := newTestLoginState(t, &bytes.Buffer{}, port)
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, "/login/done", nil)
		require.NoError(t, err)

		s.loginHandler(w, r)

		assert.Contains(t, w.Body.String(), "Authenticated!")
		assert.True(t, isLoginDone(s))
		assert.NoError(t, s.err)
	})

	t.Run("post_invalid_encoding", func(t *testing.T) {
		s := newTestLoginState(t, &bytes.Buffer{}, port)
		params := url.Values{
			"token": {"1123"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)

		s.loginHandler(w, r)

		assert.Contains(t, w.Body.String(), "{\"code\":\"invalid_request\",\"message\":\"missing token parameter\"}")
		assert.True(t, isLoginDone(s))
		assert.EqualError(t, s.err, "invalid_request: missing token parameter")
	})

	t.Run("post_error", func(t *testing.T) {
		s := newTestLoginState(t, &bytes.Buffer{}, port)
		params := url.Values{
			"error":             {"401"},
			"error_description": {"invalid request"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		s.loginHandler(w, r)

		assert.Contains(t, w.Body.String(), "{\"code\":\"401\",\"message\":\"invalid request\"}")
		assert.True(t, isLoginDone(s))
		assert.EqualError(t, s.err, "401: invalid request")
	})

	t.Run("post_token", func(t *testing.T) {
		s := newTestLoginState(t, &bytes.Buffer{}, port)
		s.dpopKey = "dpop"
		params := url.Values{
			"token":      {"178263549812635496125349"},
			"expires_in": {"3600"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		s.loginHandler(w, r)
		assert.Equal(t, http.StatusSeeOther, w.Code)
		// the local done page calls back, so the command keeps waiting
		assert.Equal(t, fmt.Sprintf("http://localhost:%d/login/done", port), w.Header().Get("Location"))
		assert.False(t, isLoginDone(s))
	})

	t.Run("post_token_done_url", func(t *testing.T) {
		s := newTestLoginState(t, &bytes.Buffer{}, port)
		s.doneURL = "https://localhost:8880/authenticated"
		params := url.Values{
			"token":      {"178263549812635496125349"},
			"expires_in": {"3600"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		s.loginHandler(w, r)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "https://localhost:8880/authenticated", w.Header().Get("Location"))
		// the server's page does not call back, so the handler completes the login itself
		assert.True(t, isLoginDone(s))
		assert.NoError(t, s.err)
	})

	t.Run("post_token_no_save", func(t *testing.T) {
		s := newTestLoginState(t, &bytes.Buffer{}, port)
		s.noStore = true
		params := url.Values{
			"token":      {"178263549812635496125349"},
			"expires_in": {"3600"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		s.loginHandler(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "To use the token with the server, run")
		// the token is shown in the browser, nothing else to wait for
		assert.True(t, isLoginDone(s))
		assert.NoError(t, s.err)
	})

	t.Run("complete_once", func(t *testing.T) {
		s := newTestLoginState(t, &bytes.Buffer{}, port)
		s.complete(nil)
		// a reloaded page must not change the result or panic
		s.complete(errors.Errorf("late"))
		assert.True(t, isLoginDone(s))
		assert.NoError(t, s.err)
	})
}

func TestWaitForLogin(t *testing.T) {
	// Not parallel: overrides package-level openBrowserFn.
	orig := openBrowserFn
	t.Cleanup(func() { openBrowserFn = orig })

	// browse simulates the browser: it calls the local listener and
	// reports the page it received
	type page struct {
		body string
		err  error
	}
	browse := func(u string, pages chan<- page) {
		res, err := http.Get(u)
		if err != nil {
			pages <- page{err: err}
			return
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		pages <- page{body: string(b), err: err}
	}

	// assertPortReleased checks the listener is shut down,
	// so the next login can bind the same port
	assertPortReleased := func(t *testing.T, port int) {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		require.NoError(t, err)
		_ = ln.Close()
	}

	t.Run("done", func(t *testing.T) {
		port, err := netutil.FindFreePort("localhost", 5)
		require.NoError(t, err)
		s := newTestLoginState(t, &bytes.Buffer{}, port)

		pages := make(chan page, 1)
		openBrowserFn = func(string) error {
			go browse(fmt.Sprintf("http://localhost:%d/login/done", port), pages)
			return nil
		}

		require.NoError(t, s.waitForLogin(context.Background(), "https://localhost:8880/login"))
		// the page that completed the login must reach the browser in full
		p := <-pages
		require.NoError(t, p.err)
		assert.Contains(t, p.body, "Authenticated!")
		assertPortReleased(t, port)
	})

	t.Run("login_error", func(t *testing.T) {
		port, err := netutil.FindFreePort("localhost", 5)
		require.NoError(t, err)
		s := newTestLoginState(t, &bytes.Buffer{}, port)

		pages := make(chan page, 1)
		openBrowserFn = func(string) error {
			go browse(fmt.Sprintf("http://localhost:%d/login?error=access_denied&error_description=denied", port), pages)
			return nil
		}

		err = s.waitForLogin(context.Background(), "https://localhost:8880/login")
		assert.EqualError(t, err, "access_denied: denied")
		p := <-pages
		require.NoError(t, p.err)
		assert.Contains(t, p.body, "access_denied")
		assertPortReleased(t, port)
	})

	t.Run("port_in_use", func(t *testing.T) {
		busy, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		defer busy.Close()
		port := busy.Addr().(*net.TCPAddr).Port
		s := newTestLoginState(t, &bytes.Buffer{}, port)

		opened := false
		openBrowserFn = func(string) error {
			opened = true
			return nil
		}

		err = s.waitForLogin(context.Background(), "https://localhost:8880/login")
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("unable to listen on port %d, use --listen-port to choose another one", port))
		// the browser must not be sent to whatever holds the port
		assert.False(t, opened)
	})

	t.Run("browser_error", func(t *testing.T) {
		port, err := netutil.FindFreePort("localhost", 5)
		require.NoError(t, err)
		s := newTestLoginState(t, &bytes.Buffer{}, port)

		openBrowserFn = func(string) error {
			return errors.Errorf("no browser")
		}

		err = s.waitForLogin(context.Background(), "https://localhost:8880/login")
		assert.EqualError(t, err, "no browser")
		assertPortReleased(t, port)
	})

	t.Run("canceled", func(t *testing.T) {
		port, err := netutil.FindFreePort("localhost", 5)
		require.NoError(t, err)
		s := newTestLoginState(t, &bytes.Buffer{}, port)

		ctx, cancel := context.WithCancel(context.Background())
		openBrowserFn = func(string) error {
			cancel()
			return nil
		}

		err = s.waitForLogin(ctx, "https://localhost:8880/login")
		assert.ErrorIs(t, err, context.Canceled)
		assertPortReleased(t, port)
	})
}

func TestLoginPageURL(t *testing.T) {
	t.Parallel()

	q := url.Values{
		"redirect_uri":  {"http://localhost:38987/login"},
		"response_type": {"code"},
	}
	assert.Equal(t,
		"https://localhost:8880/login?redirect_uri=http%3A%2F%2Flocalhost%3A38987%2Flogin&response_type=code",
		loginPageURL("https://localhost:8880", q))
}

// func TestCheckoutPageURL(t *testing.T) {
// 	t.Parallel()

// 	assert.Equal(t,
// 		"https://localhost:8880/payment#checkout_client_secret=pi_123_secret_abc",
// 		checkoutPageURL("https://localhost:8880", "pi_123_secret_abc"))
// 	// the secret is escaped so it survives as a single fragment parameter
// 	assert.Equal(t,
// 		"https://localhost:8880/payment#checkout_client_secret=a%26b%3Dc",
// 		checkoutPageURL("https://localhost:8880", "a&b=c"))
// }
