package status_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/pkg/retriable"
	pb "github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/version"
	"github.com/zap-proto/go"
	"google.golang.org/protobuf/types/known/emptypb"
)

// BenchmarkStatus_LegacyHTTP_JSON measures the existing HTTP/JSON REST route
// through porto's restserver and standard net/http handler.
func BenchmarkStatus_LegacyHTTP_JSON(b *testing.B) {
	client, err := retriable.Default(httpAddr)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}

	ctx := retriable.WithHeaders(context.Background(), jsonContentHeaders)
	res := new(pb.ServerVersion)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		hdr, sc, err := client.Get(ctx, pb.Status_Version_FullMethodName, w)
		if err != nil || sc != http.StatusOK {
			b.Fatalf("request failed: %v, status: %d", err, sc)
		}
		_ = hdr
		_ = res
	}
}

// BenchmarkStatus_LegacyGRPC measures the gRPC protobuf method call through
// porto's gserver and google.golang.org/grpc.
func BenchmarkStatus_LegacyGRPC(b *testing.B) {
	ctx := context.Background()
	req := &emptypb.Empty{}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res, err := statusClient.Version(ctx, req)
		if err != nil {
			b.Fatalf("gRPC call failed: %v", err)
		}
		_ = res
	}
}

// BenchmarkStatus_ZAPNative_Wire measures zero-copy ZAP wire framing and
// reading for the same Version payload (build, runtime, commit, major, minor).
func BenchmarkStatus_ZAPNative_Wire(b *testing.B) {
	v := version.Current()

	// Pre-create builder with reusable buffer
	builder := zap.NewBuilder(128)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder.Reset()

		// Write strings as offsets
		buildOffset := builder.WriteText(v.Build)
		runtimeOffset := builder.WriteText(v.Runtime)

		// Pack object: 2 uint32s + 2 offsets
		obj := builder.StartObject(32)
		obj.SetUint32(0, uint32(v.Major))
		obj.SetUint32(4, uint32(v.Minor))
		obj.SetUint32(8, uint32(v.Commit))
		obj.SetUint32(12, uint32(buildOffset))
		obj.SetUint32(16, uint32(len(v.Build)))
		obj.SetUint32(20, uint32(runtimeOffset))
		obj.SetUint32(24, uint32(len(v.Runtime)))
		obj.FinishAsRoot()

		wireData := builder.Finish()

		// Zero-copy read
		msg, err := zap.Parse(wireData)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
		root := msg.Root()
		_ = root.Uint32(0) // major
		_ = root.Uint32(4) // minor
		_ = root.Uint32(8) // commit
	}
}
