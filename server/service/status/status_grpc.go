package status

import (
	"context"
	"time"

	pb "github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/version"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Version returns the server version.
func (s *Service) Version(_ context.Context, _ *emptypb.Empty) (*pb.ServerVersion, error) {
	v := version.Current()
	return &pb.ServerVersion{
		Build:   v.Build,
		Runtime: v.Runtime,
	}, nil
}

// Server returns the server version.
func (s *Service) Server(_ context.Context, _ *emptypb.Empty) (*pb.ServerStatusResponse, error) {
	v := version.Current()
	res := &pb.ServerStatusResponse{
		Status: &pb.ServerStatus{
			Name:       s.server.Name(),
			Hostname:   s.server.Hostname(),
			ListenUrls: s.server.ListenURLs(),
			StartedAt:  s.server.StartedAt().Format(time.RFC3339),
		},
		Version: &pb.ServerVersion{
			Build:   v.Build,
			Runtime: v.Runtime,
		},
	}
	return res, nil
}

// Caller returns the status of the caller.
// func (s *Service) Caller(ctx context.Context, _ *emptypb.Empty) (*pb.CallerStatusResponse, error) {
// 	callerCtx := identity.FromContext(ctx)
// 	caller := callerCtx.Identity()
// 	res := &pb.CallerStatusResponse{
// 		Subject: caller.Subject(),
// 		Role:    caller.Role(),
// 	}

// 	cl := caller.Claims()
// 	if len(cl) > 0 {
// 		res.Claims = make([]*pb.KVPair, 0, len(cl))
// 		for k := range cl {
// 			res.Claims = append(res.Claims, &pb.KVPair{Key: k, Value: cl.String(k)})
// 		}
// 	}

// 	return res, nil
// }
