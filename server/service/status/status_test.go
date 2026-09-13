package status_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	pb "github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/proxypb"
	"github.com/effective-security/trustyca/api/version"
	"github.com/effective-security/trustyca/server/service/status"
	"github.com/effective-security/trustyca/tests/mockappcontainer"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	adviserServer gserver.GServer
	statusClient  pb.StatusServer
	httpAddr      string
	httpsAddr     string
)

var jsonContentHeaders = map[string]string{
	header.Accept:      header.ApplicationJSON,
	header.ContentType: header.ApplicationJSON,
}

var textContentHeaders = map[string]string{
	header.Accept:      header.TextPlain,
	header.ContentType: header.ApplicationJSON,
}

// serviceFactories provides map of trustyserver.ServiceFactory
var serviceFactories = map[string]gserver.ServiceFactory{
	status.ServiceName: status.Factory,
}

func TestMain(m *testing.M) {
	var err error

	httpsAddr = testutils.CreateURL("https", "")
	httpAddr = testutils.CreateURL("http", "")

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		panic("HOME is not set")
	}

	cfg := &gserver.Config{
		ListenURLs: []string{httpsAddr, httpAddr},
		ServerTLS: &gserver.TLSInfo{
			CertFile:      homeDir + "/.trustyca/certs/trustyca_peer.pem",
			KeyFile:       homeDir + "/.trustyca/certs/trustyca_peer.key",
			TrustedCAFile: homeDir + "/.trustyca/certs/trusty_root_ca.pem",
		},
		Services: []string{status.ServiceName},
	}

	container := mockappcontainer.NewBuilder().
		WithJwtParser(nil).
		WithDiscovery(discovery.New()).
		Container()

	adviserServer, err = gserver.Start("StatusTest", cfg, container, serviceFactories)
	if err != nil || adviserServer == nil {
		panic(errors.WithStack(err))
	}

	svc := adviserServer.Service(status.ServiceName).(*status.Service)
	statusClient = proxypb.NewStatusClientFromProxy(proxypb.StatusServerToClient(svc))

	// err = svc.OnStarted()
	// if err != nil {
	// 	panic(err)
	// }

	for i := 0; i < 10; i++ {
		if !svc.IsReady() {
			time.Sleep(time.Second)
		}
	}

	// Run the tests
	rc := m.Run()

	// cleanup
	adviserServer.Close()

	os.Exit(rc)
}

func TestVersionHttpText(t *testing.T) {
	w := httptest.NewRecorder()

	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := retriable.WithHeaders(context.Background(), textContentHeaders)
	hdr, _, err := client.Get(ctx, pb.Status_Version_FullMethodName, w)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)

	assert.Contains(t, hdr.Get(header.ContentType), header.TextPlain)
	res := w.Body.String()
	assert.Equal(t, version.Current().Build, res)
}

func TestVersionHttpJSON(t *testing.T) {
	res := new(pb.ServerVersion)

	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := retriable.WithHeaders(context.Background(), jsonContentHeaders)
	hdr, rc, err := client.Get(ctx, pb.Status_Version_FullMethodName, res)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rc)

	assert.Contains(t, hdr.Get(header.ContentType), header.ApplicationJSON)
	assert.Equal(t, version.Current().Build, res.Build)
	assert.Equal(t, version.Current().Runtime, res.Runtime)
}

func TestVersionGrpc(t *testing.T) {
	res := new(pb.ServerVersion)
	res, err := statusClient.Version(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)

	ver := version.Current()
	assert.Equal(t, ver.Build, res.Build)
	assert.Equal(t, ver.Runtime, res.Runtime)
}

func TestNodeStatusHttp(t *testing.T) {
	w := httptest.NewRecorder()

	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	hdr, _, err := client.Get(context.Background(), "/healthz", w)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)

	assert.Contains(t, hdr.Get(header.ContentType), "text/plain")
	assert.Equal(t, "ALIVE", w.Body.String())
}

func TestServerStatusHttp(t *testing.T) {
	w := httptest.NewRecorder()
	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := retriable.WithHeaders(context.Background(), textContentHeaders)

	hdr, _, err := client.Get(ctx, pb.Status_Server_FullMethodName, w)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, hdr.Get(header.ContentType), header.TextPlain)
}

func TestServerStatusHttpJSON(t *testing.T) {
	res := new(pb.ServerStatusResponse)
	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := retriable.WithHeaders(context.Background(), jsonContentHeaders)

	hdr, sc, err := client.Get(ctx, pb.Status_Server_FullMethodName, res)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, sc)
	assert.Contains(t, hdr.Get(header.ContentType), header.ApplicationJSON)
	require.NotNil(t, res.Status)
	assert.Equal(t, adviserServer.Name(), res.Status.Name)
	assert.Equal(t, version.Current().Build, res.Version.Build)
}

func TestServerStatusGrpc(t *testing.T) {
	res := new(pb.ServerStatusResponse)
	res, err := statusClient.Server(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)

	require.NotNil(t, res.Status)
	assert.Equal(t, adviserServer.Name(), res.Status.Name)
	assert.Equal(t, version.Current().Build, res.Version.Build)
}

/*
func TestCallerStatusHttp(t *testing.T) {
	w := httptest.NewRecorder()
	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := retriable.WithHeaders(context.Background(), textContentHeaders)

	hdr, _, err := client.Get(ctx, pb.Status_Caller_FullMethodName, w)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, hdr.Get(header.ContentType), header.TextPlain)
}

func TestCallerStatusHttpJSON(t *testing.T) {
	res := new(pb.CallerStatusResponse)
	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := retriable.WithHeaders(context.Background(), jsonContentHeaders)

	hdr, sc, err := client.Get(ctx, pb.Status_Caller_FullMethodName, res)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, sc)
	assert.Contains(t, hdr.Get(header.ContentType), header.ApplicationJSON)
	assert.NotEmpty(t, res.Role)
}

func TestCallerStatusGrpc(t *testing.T) {
	res, err := statusClient.Caller(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, identity.GuestRoleName, res.Role)
}
*/
