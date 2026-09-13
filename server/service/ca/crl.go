package ca

import (
	"context"

	"github.com/effective-security/trustyca/api/pb"
)

func (s *Service) GetCRL(ctx context.Context, req *pb.GetCrlRequest) (*pb.CrlResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) PublishCrls(ctx context.Context, req *pb.PublishCrlsRequest) (*pb.CrlsResponse, error) {
	// TODO: Implement
	return nil, nil
}
