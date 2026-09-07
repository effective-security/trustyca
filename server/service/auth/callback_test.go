package auth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGetUserInfo(t *testing.T) {
	// Can't run in parallel because of the server.URL
	//t.Parallel()

	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	// Mock the token
	token := &oauth2.Token{AccessToken: "mockAccessToken"}

	var response string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, response)
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(h)
	defer server.Close()

	clientConfig := &oauth2client.ClientConfig{ProviderID: "someProvider", UserinfoURL: server.URL + "/userinfo"}

	oldURL := service.BaseURL
	service.BaseURL, _ = url.Parse(server.URL)
	defer func() { service.BaseURL = oldURL }()

	t.Run("empty name2", func(t *testing.T) {
		response = `{"email": "test.user@example.com"}`
		// Call getUser
		userInfo, _, err := service.GetUserInfo(context.Background(), pb.IDP_Github, clientConfig, nil, token)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, "Test User", userInfo.Name)
		assert.Equal(t, "test.user@example.com", userInfo.Email)
	})

	t.Run("empty name1", func(t *testing.T) {
		response = `{"email": "denis@example.com"}`
		// Call getUser
		userInfo, _, err := service.GetUserInfo(context.Background(), pb.IDP_Github, clientConfig, nil, token)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, "Denis", userInfo.Name)
		assert.Equal(t, "denis@example.com", userInfo.Email)
	})

	t.Run("non empty name", func(t *testing.T) {
		response = `{"email": "test.user@example.com", "name": "Test User"}`
		// Call getUser
		userInfo, _, err := service.GetUserInfo(context.Background(), pb.IDP_Github, clientConfig, nil, token)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, "Test User", userInfo.Name)
		assert.Equal(t, "test.user@example.com", userInfo.Email)
	})
}
