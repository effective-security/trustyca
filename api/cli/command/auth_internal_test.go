package command

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/x/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginHandler(t *testing.T) {
	// Not parallel: loginHandler and LoginCmd.Run share package-level `state`.
	out := bytes.Buffer{}

	port, err := netutil.FindFreePort("localhost", 5)
	require.NoError(t, err)

	tmp := t.TempDir()

	c, err := retriable.New(retriable.ClientConfig{
		StorageFolder: tmp,
	})
	require.NoError(t, err)

	state = &svcState{
		writer:       &out,
		listenPort:   port,
		responseType: "token",
		client:       c,
	}
	t.Cleanup(func() { state = nil })

	t.Run("get", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, "/login/done", nil)
		require.NoError(t, err)

		state.wg.Add(1)
		loginHandler(w, r)
		state.wg.Wait()

		assert.Contains(t, w.Body.String(), "Authenticated!")
	})

	t.Run("post_invalid_encoding", func(t *testing.T) {
		params := url.Values{
			"token": {"1123"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)

		state.wg.Add(1)
		loginHandler(w, r)
		state.wg.Wait()

		assert.Contains(t, w.Body.String(), "{\"code\":\"invalid_request\",\"message\":\"missing token parameter\"}")
	})

	t.Run("post_error", func(t *testing.T) {
		params := url.Values{
			"error":             {"401"},
			"error_description": {"invalid request"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		state.wg.Add(1)
		loginHandler(w, r)
		state.wg.Wait()

		assert.Contains(t, w.Body.String(), "{\"code\":\"401\",\"message\":\"invalid request\"}")
	})

	t.Run("post_token", func(t *testing.T) {
		params := url.Values{
			"token":      {"178263549812635496125349"},
			"expires_in": {"3600"},
		}
		state.dpopKey = "dpop"

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		loginHandler(w, r)
		assert.Equal(t, http.StatusSeeOther, w.Code)
		// the local done page calls back, so the command keeps waiting
		assert.Equal(t, fmt.Sprintf("http://localhost:%d/login/done", port), w.Header().Get("Location"))
	})

	t.Run("post_token_done_url", func(t *testing.T) {
		params := url.Values{
			"token":      {"178263549812635496125349"},
			"expires_in": {"3600"},
		}
		state.doneURL = "https://localhost:7880/authenticated"
		t.Cleanup(func() { state.doneURL = "" })

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		// the server's page does not call back, so the handler releases the wait itself
		state.wg.Add(1)
		loginHandler(w, r)
		state.wg.Wait()

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "https://localhost:7880/authenticated", w.Header().Get("Location"))
		assert.True(t, w.Flushed)
	})

	t.Run("post_token_no_save", func(t *testing.T) {
		params := url.Values{
			"token":      {"178263549812635496125349"},
			"expires_in": {"3600"},
		}
		state.noStore = true
		t.Cleanup(func() { state.noStore = false })

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		// the token is shown in the browser, so the wait is released
		state.wg.Add(1)
		loginHandler(w, r)
		state.wg.Wait()

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "To use the token with the server, run")
	})
}

func TestLoginPageURL(t *testing.T) {
	t.Parallel()

	q := url.Values{
		"redirect_uri":  {"http://localhost:38987/login"},
		"response_type": {"code"},
	}
	assert.Equal(t,
		"https://localhost:7880/login?redirect_uri=http%3A%2F%2Flocalhost%3A38987%2Flogin&response_type=code",
		loginPageURL("https://localhost:7880", q))
}

// func TestCheckoutPageURL(t *testing.T) {
// 	t.Parallel()

// 	assert.Equal(t,
// 		"https://localhost:7880/payment#checkout_client_secret=pi_123_secret_abc",
// 		checkoutPageURL("https://localhost:7880", "pi_123_secret_abc"))
// 	// the secret is escaped so it survives as a single fragment parameter
// 	assert.Equal(t,
// 		"https://localhost:7880/payment#checkout_client_secret=a%26b%3Dc",
// 		checkoutPageURL("https://localhost:7880", "a&b=c"))
// }
