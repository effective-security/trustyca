package cis

import (
	"context"

	"github.com/effective-security/trustyca/api/pb"
)

func (s *Service) GetRoots(ctx context.Context, req *pb.ListRootsRequest) (*pb.RootsResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) GetIssuer(ctx context.Context, req *pb.GetIssuerInfoRequest) (*pb.IssuerInfo, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) GetCertificate(ctx context.Context, req *pb.GetCertificateInfoRequest) (*pb.CertificateResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) GetCertificateStatus(ctx context.Context, req *pb.GetCertificateInfoRequest) (*pb.CertificateStatusResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) GetCRL(ctx context.Context, req *pb.GetCrlRequest) (*pb.CrlResponse, error) {
	// TODO: Implement
	return nil, nil
}
