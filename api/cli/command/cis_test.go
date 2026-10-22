package command_test

import (
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/pb"
	"google.golang.org/grpc/codes"
)

const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

func cisCertificate() *pb.Certificate {
	return &pb.Certificate{
		ID:           "30",
		SKID:         "ee00ee",
		IKID:         "0a1b2c",
		SerialNumber: "98765",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-04-01T00:00:00Z",
		Subject:      "CN=edge.example.com",
		Issuer:       "CN=Corp Issuing CA",
		Sha256:       "cafe01",
		Pem:          testCertPEM,
		Status:       pb.CertificateStatus_Active,
		CreatedAt:    "2026-01-01T00:00:00Z",
	}
}

// runPrintedCIS runs a command of the CIS in the table and the JSON
// format, captures the output for the golden file, and checks the error of
// a failed call
func (s *testSuiteGrpc) runPrintedCIS(run func() error) {
	err := run()
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()
	err = run()
	s.Require().NoError(err)
	s.CapturePrint()
	s.Ctl.O = ""

	s.MockCIS.Err = httperror.NewGrpc(codes.NotFound, "certificate not found")
	defer func() { s.MockCIS.Err = nil }()
	err = run()
	s.EqualError(err, "not_found: certificate not found")
}

func (s *testSuiteGrpc) Test_CertGetCmd() {
	s.MockCIS.SetResponse(&pb.CertificateResponse{Certificate: cisCertificate()})
	a := command.CertGetCmd{CertSelector: command.CertSelector{IKID: "0a1b2c", Serial: "98765"}}
	s.runPrintedCIS(func() error { return a.Run(s.Ctl) })

	s.EqualError((&command.CertGetCmd{}).Run(s.Ctl), "certificate ID, --skid, --sha256 or --ikid with --serial is required")
	s.EqualError((&command.CertGetCmd{CertSelector: command.CertSelector{Serial: "98765"}}).Run(s.Ctl), "--ikid and --serial are used together")
}

func (s *testSuiteGrpc) Test_CertStatusCmd() {
	s.MockCIS.SetResponse(&pb.CertificateStatusResponse{
		IKID:         "0a1b2c",
		SerialNumber: "98765",
		Status:       pb.CertificateStatus_Revoked,
		NotAfter:     "2026-04-01T00:00:00Z",
		RevokedAt:    "2026-02-01T00:00:00Z",
		Reason:       pb.ReasonCode_KeyCompromise,
	})
	a := command.CertStatusCmd{CertSelector: command.CertSelector{SKID: "ee00ee"}}
	s.runPrintedCIS(func() error { return a.Run(s.Ctl) })

	s.MockCIS.SetResponse(&pb.CertificateStatusResponse{
		IKID:         "0a1b2c",
		SerialNumber: "98765",
		Status:       pb.CertificateStatus_Active,
		NotAfter:     "2026-04-01T00:00:00Z",
	})
	s.Out.Reset()
	s.Require().NoError((&command.CertStatusCmd{CertSelector: command.CertSelector{ID: "30"}}).Run(s.Ctl))
	s.CapturePrint()
}

func (s *testSuiteGrpc) Test_IssuerGetCmd() {
	s.MockCIS.SetResponse(&pb.IssuerInfo{
		Label:       "issuing",
		Type:        pb.AuthorityType_Issuing,
		Status:      pb.IssuerStatus_Active,
		SKID:        "0a1b2c",
		Subject:     "CN=Corp Issuing CA",
		NotBefore:   "2026-01-01T00:00:00Z",
		NotAfter:    "2031-01-01T00:00:00Z",
		Certificate: testCertPEM,
		CrlURL:      "http://localhost:8880/v1/crl/0a1b2c",
		OcspURL:     "http://localhost:8880/v1/ocspi/0a1b2c",
		AiaURL:      "http://localhost:8880/v1/cert/0a1b2c",
	})
	a := command.IssuerGetCmd{IKID: "0a1b2c"}
	s.runPrintedCIS(func() error { return a.Run(s.Ctl) })
}

func (s *testSuiteGrpc) Test_CrlGetCmd() {
	s.MockCIS.SetResponse(&pb.CrlResponse{Crl: &pb.Crl{
		ID:         "40",
		IssuerID:   "10",
		IKID:       "0a1b2c",
		Number:     "4",
		ThisUpdate: "2026-01-02T00:00:00Z",
		NextUpdate: "2026-01-04T00:00:00Z",
		Issuer:     "CN=Corp Issuing CA",
		Pem:        "-----BEGIN X509 CRL-----\nMIIBcrl\n-----END X509 CRL-----\n",
	}})
	a := command.CrlGetCmd{IKID: "0a1b2c"}
	s.runPrintedCIS(func() error { return a.Run(s.Ctl) })
}

func (s *testSuiteGrpc) Test_RootListCmd() {
	s.MockCIS.SetResponse(&pb.RootsResponse{Roots: []*pb.RootCertificate{{
		ID:        "50",
		SKID:      "r00t",
		NotBefore: "2020-01-01T00:00:00Z",
		NotAfter:  "2040-01-01T00:00:00Z",
		Subject:   "CN=Test Trusty Root CA",
		Sha256:    "beef",
		Trust:     pb.Trust_Private,
		Pem:       testCertPEM,
		CreatedAt: "2026-01-01T00:00:00Z",
	}}})
	a := command.RootListCmd{Limit: 10}
	s.runPrintedCIS(func() error { return a.Run(s.Ctl) })
}
