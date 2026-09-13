package ca

import (
	"context"

	"github.com/effective-security/trustyca/api/pb"
)

func (s *Service) SignCertificate(ctx context.Context, req *pb.SignCertificateRequest) (*pb.CertificateResponse, error) {
	// TODO: Implement
	return nil, nil
}

func (s *Service) SignOCSP(ctx context.Context, req *pb.OCSPRequest) (*pb.OCSPResponse, error) {
	// TODO: Implement
	return nil, nil
}
