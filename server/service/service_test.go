package service_test

import (
	"net/http"
	"testing"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/server/service"
	"github.com/effective-security/trustyca/server/service/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var serviceFactories = map[string]gserver.ServiceFactory{
	status.ServiceName: status.Factory,
	// advisor.ServiceName:      advisors.Factory,
	// swagger.ServiceName: swagger.Factory,
}

func Test_invalidArgs(t *testing.T) {
	for _, f := range serviceFactories {
		testInvalidServiceArgs(t, f)
	}
}

func TestGetPublicServerURL(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, pb.Status_Server_FullMethodName, nil)
	require.NoError(t, err)

	u := service.GetPublicServerURL(r, "/v1").String()
	assert.Equal(t, "https:///v1", u)

	r.URL.Scheme = "https"
	r.Host = "trustyca.io:8443"
	u = service.GetPublicServerURL(r, "/v1").String()
	assert.Equal(t, "https://trustyca.io:8443/v1", u)
}

func testInvalidServiceArgs(t *testing.T, f gserver.ServiceFactory) {
	defer func() {
		err := recover()
		if err == nil {
			t.Fatalf("Expected panic but didn't get one")
		}
	}()
	f(nil)
}
