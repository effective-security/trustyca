package ca

import (
	"context"

	"github.com/effective-security/trustyca/api/pb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Service) RegisterProfile(ctx context.Context, req *pb.RegisterProfileRequest) (*pb.CertProfile, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.CertProfile, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) ListProfiles(ctx context.Context, req *pb.ListProfilesRequest) (*pb.ProfilesResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) DeleteProfile(ctx context.Context, req *pb.DeleteProfileRequest) (*emptypb.Empty, error) {
	// TODO: Implement
	return nil, nil
}
