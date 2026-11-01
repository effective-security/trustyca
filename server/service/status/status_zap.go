package status

import (
	"context"

	"github.com/effective-security/trustyca/api/version"
	"github.com/zap-proto/go"
	"github.com/zap-proto/zip"
)

// VersionInput is the typed input for the Version operation in zip/ZAP.
type VersionInput struct{}

// VersionOutput is the typed output for the Version operation in zip/ZAP.
type VersionOutput struct {
	Build   string `json:"build"`
	Runtime string `json:"runtime"`
	Major   uint   `json:"major"`
	Minor   uint   `json:"minor"`
	Commit  uint   `json:"commit"`
}

// ZAPVersionHandler handles Version requests with zero-copy ZAP framing.
func (s *Service) ZAPVersionHandler(ctx context.Context, _ *VersionInput) (*VersionOutput, error) {
	v := version.Current()
	return &VersionOutput{
		Build:   v.Build,
		Runtime: v.Runtime,
		Major:   v.Major,
		Minor:   v.Minor,
		Commit:  v.Commit,
	}, nil
}

// RegisterZAP registers the status operations on a zip.App.
// This automatically exposes:
//  1. REST endpoint: GET /v1/status/version
//  2. ZAP native zero-copy RPC route
//  3. MCP Tool: "status_version" for AI agents
//  4. OpenAPI 3.1 specification
func (s *Service) RegisterZAP(app *zip.App) {
	zip.Get(app, "/v1/status/version", s.ZAPVersionHandler)
}

// EncodeZAPVersion writes the version data into a zero-copy ZAP wire buffer.
func EncodeZAPVersion(builder *zap.Builder, v version.Info) []byte {
	builder.Reset()
	buildOffset := builder.WriteText(v.Build)
	runtimeOffset := builder.WriteText(v.Runtime)

	obj := builder.StartObject(32)
	obj.SetUint32(0, uint32(v.Major))
	obj.SetUint32(4, uint32(v.Minor))
	obj.SetUint32(8, uint32(v.Commit))
	obj.SetUint32(12, uint32(buildOffset))
	obj.SetUint32(16, uint32(len(v.Build)))
	obj.SetUint32(20, uint32(runtimeOffset))
	obj.SetUint32(24, uint32(len(v.Runtime)))
	obj.FinishAsRoot()

	return builder.Finish()
}
