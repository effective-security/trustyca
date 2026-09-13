package ca

import (
	"context"

	"github.com/effective-security/trustyca/api/pb"
)

func (s *Service) GetCertificate(ctx context.Context, req *pb.GetCertificateRequest) (*pb.CertificateResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) ListCertificates(ctx context.Context, req *pb.ListCertificatesRequest) (*pb.CertificatesResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) UpdateCertificateLabel(ctx context.Context, req *pb.UpdateCertificateLabelRequest) (*pb.CertificateResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) RevokeCertificate(ctx context.Context, req *pb.RevokeCertificateRequest) (*pb.RevokedCertificateResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) ListRevokedCertificates(ctx context.Context, req *pb.ListRevokedCertificatesRequest) (*pb.RevokedCertificatesResponse, error) {
	// TODO: Implement
	return nil, nil
}
