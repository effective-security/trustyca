package admin_test

import (
	"os"
	"path/filepath"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ctl/admin"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// the dev template profiles, the ones `ca org bootstrap` copies
const templatesDir = "../../../etc/dev/profiles"

const testPEM = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

func ctlIssuer() *pb.Issuer {
	return &pb.Issuer{
		ID:           "10",
		OrgID:        "5",
		Label:        "issuing",
		Type:         pb.AuthorityType_Issuing,
		Status:       pb.IssuerStatus_Active,
		ParentID:     "1",
		SKID:         "0a1b2c",
		IKID:         "l1l1l1",
		SerialNumber: "1234567890",
		Subject:      "CN=Corp Issuing CA",
		Issuer:       "CN=Test Trusty Level 1 CA",
		Sha256:       "ab12cd34",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2031-01-01T00:00:00Z",
		Certificate:  testPEM,
		KeyProvider:  "inmem",
		Config: &pb.IssuerConfig{
			AiaURL:               "http://localhost:8880/v1/cert/${ISSUER_ID}",
			CrlURL:               "http://localhost:8880/v1/crl/${ISSUER_ID}",
			OcspURL:              "http://localhost:8880/v1/ocspi/${ISSUER_ID}",
			CrlExpiry:            "48h",
			OcspExpiry:           "1h",
			DelegatedOcspProfile: "ocsp",
			AllowedProfiles:      []string{"ocsp"},
		},
		CrlNumber: "3",
		CreatedAt: "2026-01-01T00:00:00Z",
		UpdatedAt: "2026-01-02T00:00:00Z",
	}
}

func ctlPlatformIssuer() *pb.Issuer {
	return &pb.Issuer{
		ID:       "1",
		Label:    "trusty.l1",
		Type:     pb.AuthorityType_Intermediate,
		Status:   pb.IssuerStatus_Active,
		SKID:     "l1l1l1",
		Subject:  "CN=Test Trusty Level 1 CA",
		NotAfter: "2031-01-01T00:00:00Z",
		Config: &pb.IssuerConfig{
			AllowedProfiles: []string{"ocsp", "tenant_ca"},
		},
	}
}

func ctlProfile(label, issuer string) *pb.CertProfile {
	return &pb.CertProfile{
		ID:                "20",
		OrgID:             "5",
		Label:             label,
		IssuerLabel:       issuer,
		Description:       "TLS server certificate",
		Usages:            []string{"signing", "key encipherment", "server auth"},
		Expiry:            "2160h",
		Backdate:          "30m",
		AllowedExtensions: []string{"2.5.29.17"},
		Status:            pb.ItemStatus_Active,
		CreatedAt:         "2026-01-01T00:00:00Z",
	}
}

func ctlCertificate() *pb.Certificate {
	return &pb.Certificate{
		ID:           "30",
		OrgID:        "5",
		ProjectID:    "7",
		SKID:         "ee00ee",
		IKID:         "0a1b2c",
		SerialNumber: "98765",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-04-01T00:00:00Z",
		Subject:      "CN=edge.example.com",
		Issuer:       "CN=Corp Issuing CA",
		Sha256:       "cafe01",
		Profile:      "server",
		Pem:          testPEM,
		Label:        "edge-1",
		Metadata:     map[string]string{"requester": "ci"},
		Status:       pb.CertificateStatus_Active,
		CreatedAt:    "2026-01-01T00:00:00Z",
	}
}

func ctlCrl() *pb.Crl {
	return &pb.Crl{
		ID:         "40",
		OrgID:      "5",
		IssuerID:   "10",
		IKID:       "0a1b2c",
		Number:     "4",
		ThisUpdate: "2026-01-02T00:00:00Z",
		NextUpdate: "2026-01-04T00:00:00Z",
		Issuer:     "CN=Corp Issuing CA",
		Pem:        "-----BEGIN X509 CRL-----\nMIIBcrl\n-----END X509 CRL-----\n",
	}
}

// runPrinted runs a command in the table and the JSON format, captures the
// output for the golden file, and checks the error of a failed call
func (s *testSuiteGrpc) runPrinted(run func() error, errOf *error) {
	err := run()
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()
	err = run()
	s.Require().NoError(err)
	s.CapturePrint()
	s.Ctl.O = ""

	*errOf = httperror.NewGrpc(codes.Unknown, "request failed")
	defer func() { *errOf = nil }()
	err = run()
	s.EqualError(err, "unexpected: request failed")
}

// tempPEM writes a PEM file for the commands that read one
func (s *testSuiteGrpc) tempPEM(name string) string {
	fn := filepath.Join(s.T().TempDir(), name)
	s.Require().NoError(os.WriteFile(fn, []byte(testPEM), 0600))
	return fn
}

func (s *testSuiteGrpc) Test_IssuerListCmd() {
	s.MockAdmin.SetResponse(&pb.IssuersResponse{
		Issuers:  []*pb.Issuer{ctlIssuer(), ctlPlatformIssuer()},
		NextPage: &pb.NextPage{Cursor: "next-cursor"},
	})
	cmd := &admin.IssuerListCmd{Status: "Active", Type: "Issuing", PageFlags: admin.PageFlags{Limit: 10}}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockAdmin.Err)

	s.EqualError((&admin.IssuerListCmd{Status: "Nope"}).Run(s.Ctl), "invalid status: Nope")
	s.EqualError((&admin.IssuerListCmd{Type: "Nope"}).Run(s.Ctl), "invalid type: Nope")
}

func (s *testSuiteGrpc) Test_IssuerGetCmd() {
	s.MockBackend.SetResponse(ctlIssuer())
	cmd := &admin.IssuerGetCmd{OrgScope: admin.OrgScope{Org: "5"}, ID: "10"}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	// a pending issuer prints its CSR
	pending := ctlIssuer()
	pending.Status = pb.IssuerStatus_Pending
	pending.Certificate = ""
	pending.Csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBcsr\n-----END CERTIFICATE REQUEST-----\n"
	s.MockBackend.SetResponse(pending)
	s.Out.Reset()
	s.Require().NoError((&admin.IssuerGetCmd{OrgScope: admin.OrgScope{Org: "5"}, Label: "issuing"}).Run(s.Ctl))
	s.CapturePrint()

	s.EqualError((&admin.IssuerGetCmd{OrgScope: admin.OrgScope{Org: "5"}}).Run(s.Ctl), "issuer ID, label or key identifier is required")
}

func (s *testSuiteGrpc) Test_IssuerRegisterCmd() {
	s.MockBackend.SetResponse(ctlIssuer())
	cmd := &admin.IssuerRegisterCmd{
		OrgScope:     admin.OrgScope{Org: "5"},
		Label:        "issuing",
		Type:         "Issuing",
		SubjectFlags: admin.SubjectFlags{CN: "Corp Issuing CA", Organization: "Corp", Country: "US"},
		KeyFlags:     admin.KeyFlags{KeyAlgo: "ECDSA", KeySize: 384},
		Parent:       "1",
		Profile:      "tenant_ca",
		IssuerSettings: admin.IssuerSettings{
			CrlURL:          "http://localhost:8880/v1/crl/${ISSUER_ID}",
			AllowedProfiles: []string{"ocsp"},
		},
	}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	s.EqualError((&admin.IssuerRegisterCmd{Label: "root", Type: "Nope"}).Run(s.Ctl), "invalid type: Nope")
	s.EqualError((&admin.IssuerRegisterCmd{Label: "root"}).Run(s.Ctl), "type is required")
	s.EqualError((&admin.IssuerRegisterCmd{Label: "root", Type: "Root"}).Run(s.Ctl), "subject is required: --cn")
}

func (s *testSuiteGrpc) Test_IssuerImportCmd() {
	s.MockBackend.SetResponse(ctlIssuer())
	cert := s.tempPEM("issuer.pem")
	key := s.tempPEM("issuer.key")
	cmd := &admin.IssuerImportCmd{
		OrgScope:    admin.OrgScope{Org: "5"},
		Label:       "imported",
		Type:        "Issuing",
		Certificate: cert,
		KeyFile:     key,
	}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	cmd.KeyURI = "pkcs11:id=1"
	s.EqualError(cmd.Run(s.Ctl), "one of --key-uri and --key-file is required")
	cmd.KeyFile = ""
	cmd.Intermediates = filepath.Join(s.T().TempDir(), "missing.pem")
	s.ErrorContains(cmd.Run(s.Ctl), "unable to read the intermediates")
	s.EqualError((&admin.IssuerImportCmd{Label: "x", Type: "Nope"}).Run(s.Ctl), "invalid type: Nope")
	s.EqualError((&admin.IssuerImportCmd{Label: "x"}).Run(s.Ctl), "type is required")
}

func (s *testSuiteGrpc) Test_IssuerActivateCmd() {
	s.MockBackend.SetResponse(ctlIssuer())
	cmd := &admin.IssuerActivateCmd{Org: "5", Project: "7", ID: "10", Certificate: s.tempPEM("signed.pem"), Root: s.tempPEM("root.pem")}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	cmd.Certificate = filepath.Join(s.T().TempDir(), "missing.pem")
	s.ErrorContains(cmd.Run(s.Ctl), "unable to read the certificate")
}

func (s *testSuiteGrpc) Test_IssuerArchiveDestroyCmd() {
	archived := ctlIssuer()
	archived.Status = pb.IssuerStatus_Archived
	s.MockBackend.SetResponse(archived)
	cmd := &admin.IssuerArchiveCmd{Org: "5", Project: "7", ID: "10"}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	destroyed := ctlIssuer()
	destroyed.Status = pb.IssuerStatus_Destroyed
	s.MockBackend.SetResponse(destroyed)
	destroy := &admin.IssuerDestroyCmd{Org: "5", ID: "10"}
	s.runPrinted(func() error { return destroy.Run(s.Ctl) }, &s.MockBackend.Err)
}

func (s *testSuiteGrpc) Test_ProfileListCmd() {
	s.MockBackend.SetResponse(&pb.ProfilesResponse{
		Profiles: []*pb.CertProfile{ctlProfile("server", "issuing"), ctlProfile("ocsp", "*")},
		NextPage: &pb.NextPage{Offset: 2},
	})
	cmd := &admin.ProfileListCmd{OrgScope: admin.OrgScope{Org: "5"}, Issuer: "issuing"}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)
}

func (s *testSuiteGrpc) Test_ProfileGetCmd() {
	s.MockBackend.SetResponse(ctlProfile("server", "issuing"))
	cmd := &admin.ProfileGetCmd{OrgScope: admin.OrgScope{Org: "5"}, Label: "server"}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	s.EqualError((&admin.ProfileGetCmd{OrgScope: admin.OrgScope{Org: "5"}}).Run(s.Ctl), "profile ID or label is required")
}

func (s *testSuiteGrpc) Test_ProfileRegisterCmd() {
	s.MockBackend.SetResponse(ctlProfile("server", "issuing"))
	cmd := &admin.ProfileRegisterCmd{
		OrgScope: admin.OrgScope{Org: "5"},
		File:     filepath.Join(templatesDir, "server.yaml"),
		Issuer:   "issuing",
	}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	// the template binds to no issuer
	cmd.Issuer = ""
	s.EqualError(cmd.Run(s.Ctl), "profile server: the issuer label is required: issuer_label of the file, or --issuer")
	// the OCSP template binds to any issuer
	s.MockBackend.SetResponse(ctlProfile("ocsp", "*"))
	s.Require().NoError((&admin.ProfileRegisterCmd{OrgScope: admin.OrgScope{Org: "5"}, File: filepath.Join(templatesDir, "ocsp.yaml")}).Run(s.Ctl))

	s.ErrorContains((&admin.ProfileRegisterCmd{File: filepath.Join(s.T().TempDir(), "missing.yaml")}).Run(s.Ctl), "unable to read profile missing")
	broken := filepath.Join(s.T().TempDir(), "broken.yaml")
	s.Require().NoError(os.WriteFile(broken, []byte("expiry: 1h\n"), 0600))
	s.EqualError((&admin.ProfileRegisterCmd{File: broken, Label: "nope"}).Run(s.Ctl), "profile nope: invalid profile: no usages specified")
}

func (s *testSuiteGrpc) Test_ProfileDeleteCmd() {
	s.MockBackend.SetResponse(&emptypb.Empty{})
	cmd := &admin.ProfileDeleteCmd{Org: "5", Project: "7", ID: "20"}
	s.Require().NoError(cmd.Run(s.Ctl))
	s.Empty(s.Out.String())

	s.MockBackend.Err = errors.New("something happened")
	defer func() { s.MockBackend.Err = nil }()
	s.EqualError(cmd.Run(s.Ctl), "unexpected: something happened")
}

func (s *testSuiteGrpc) Test_RootCmds() {
	root := &pb.RootCertificate{
		ID:        "50",
		SKID:      "r00t",
		NotBefore: "2020-01-01T00:00:00Z",
		NotAfter:  "2040-01-01T00:00:00Z",
		Subject:   "CN=Test Trusty Root CA",
		Sha256:    "beef",
		Trust:     pb.Trust_Private,
		Pem:       testPEM,
		CreatedAt: "2026-01-01T00:00:00Z",
	}
	s.MockBackend.SetResponse(&pb.RootsResponse{Roots: []*pb.RootCertificate{root}})
	list := &admin.RootListCmd{}
	s.runPrinted(func() error { return list.Run(s.Ctl) }, &s.MockBackend.Err)

	s.MockBackend.SetResponse(root)
	register := &admin.RootRegisterCmd{Org: "5", Certificate: s.tempPEM("root.pem"), Trust: "Private"}
	s.runPrinted(func() error { return register.Run(s.Ctl) }, &s.MockBackend.Err)

	register.Trust = "Nope"
	s.EqualError(register.Run(s.Ctl), "invalid trust: Nope")
	register.Trust = ""
	register.Certificate = filepath.Join(s.T().TempDir(), "missing.pem")
	s.ErrorContains(register.Run(s.Ctl), "unable to read the certificate")
}

func (s *testSuiteGrpc) Test_CertListCmd() {
	s.MockAdmin.SetResponse(&pb.CertificatesResponse{Certificates: []*pb.Certificate{ctlCertificate()}})
	cmd := &admin.CertListCmd{Org: "5", IKID: "0a1b2c", Status: "Active"}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockAdmin.Err)

	s.EqualError((&admin.CertListCmd{Status: "Nope"}).Run(s.Ctl), "invalid status: Nope")
}

func (s *testSuiteGrpc) Test_CertGetCmd() {
	s.MockBackend.SetResponse(&pb.CertificateResponse{Certificate: ctlCertificate()})
	cmd := &admin.CertGetCmd{Org: "5", CertSelector: admin.CertSelector{IKID: "0a1b2c", Serial: "98765"}}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	s.EqualError((&admin.CertGetCmd{Org: "5"}).Run(s.Ctl), "certificate ID, --skid, --sha256 or --ikid with --serial is required")
	s.EqualError((&admin.CertGetCmd{Org: "5", CertSelector: admin.CertSelector{IKID: "0a1b2c"}}).Run(s.Ctl), "--ikid and --serial are used together")
}

func (s *testSuiteGrpc) Test_CertRevokeCmd() {
	s.MockBackend.SetResponse(&pb.RevokedCertificateResponse{Revoked: &pb.RevokedCertificate{
		Certificate: ctlCertificate(),
		RevokedAt:   "2026-02-01T00:00:00Z",
		Reason:      pb.ReasonCode_KeyCompromise,
		ReasonText:  "leaked",
	}})
	cmd := &admin.CertRevokeCmd{OrgScope: admin.OrgScope{Org: "5"}, CertSelector: admin.CertSelector{ID: "30"}, Reason: "KeyCompromise", ReasonText: "leaked"}
	s.runPrinted(func() error { return cmd.Run(s.Ctl) }, &s.MockBackend.Err)

	s.Require().NoError((&admin.CertRevokeCmd{OrgScope: admin.OrgScope{Org: "5"}, CertSelector: admin.CertSelector{ID: "30"}, Reason: "Unspecified"}).Run(s.Ctl))
	s.EqualError((&admin.CertRevokeCmd{OrgScope: admin.OrgScope{Org: "5"}, CertSelector: admin.CertSelector{ID: "30"}, Reason: "Nope"}).Run(s.Ctl), "invalid reason: Nope")
	s.EqualError((&admin.CertRevokeCmd{OrgScope: admin.OrgScope{Org: "5"}, CertSelector: admin.CertSelector{Sha256: "cafe01"}}).Run(s.Ctl), "a revocation names the certificate by ID, --skid or --ikid with --serial")
	s.EqualError((&admin.CertRevokeCmd{OrgScope: admin.OrgScope{Org: "5"}}).Run(s.Ctl), "certificate ID, --skid, --sha256 or --ikid with --serial is required")
}

func (s *testSuiteGrpc) Test_CrlCmds() {
	s.MockBackend.SetResponse(&pb.CrlResponse{Crl: ctlCrl()})
	get := &admin.CrlGetCmd{Org: "5", IKID: "0a1b2c"}
	s.runPrinted(func() error { return get.Run(s.Ctl) }, &s.MockBackend.Err)

	s.MockBackend.SetResponse(&pb.CrlsResponse{Crls: []*pb.Crl{ctlCrl()}})
	publish := &admin.CrlPublishCmd{Org: "5", IKID: "0a1b2c", Force: true}
	s.runPrinted(func() error { return publish.Run(s.Ctl) }, &s.MockBackend.Err)
}

func (s *testSuiteGrpc) Test_OrgBootstrapCmd() {
	// the parent by label, through the support list
	s.MockAdmin.SetResponse(&pb.IssuersResponse{Issuers: []*pb.Issuer{ctlPlatformIssuer()}})
	s.MockBackend.SetResponses([]proto.Message{
		ctlIssuer(),
		ctlProfile("client", "issuing"),
		ctlProfile("ocsp", "*"),
		ctlProfile("peer", "issuing"),
		ctlProfile("server", "issuing"),
	})
	cmd := &admin.OrgBootstrapCmd{
		OrgScope:  admin.OrgScope{Org: "5"},
		Templates: templatesDir,
		Parent:    "trusty.l1",
		Profile:   "tenant_ca",
		Label:     "issuing",
		IssuerSettings: admin.IssuerSettings{
			CrlURL:      "http://localhost:8880/v1/crl/${ISSUER_ID}",
			OcspProfile: "ocsp",
		},
	}
	s.Require().NoError(cmd.Run(s.Ctl))
	s.CapturePrint()
	s.Contains(s.Out.String(), "4 profiles registered")

	// the parent by ID needs no support list
	s.MockAdmin.Err = errors.New("not called")
	defer func() { s.MockAdmin.Err = nil }()
	cmd.Parent = "1"
	s.MockBackend.Index = 0
	s.Out.Reset()
	s.Require().NoError(cmd.Run(s.Ctl))
	cmd.Parent = "trusty.l1"
	s.EqualError(cmd.Run(s.Ctl), "unexpected: not called", "the parent by label needs the support list")
	s.MockAdmin.Err = nil

	// no such platform issuer, an ambiguous label, a failed profile
	cmd.Parent = "trusty.l1"
	s.MockAdmin.SetResponse(&pb.IssuersResponse{})
	s.EqualError(cmd.Run(s.Ctl), "active platform issuer not found: trusty.l1")
	s.MockAdmin.SetResponse(&pb.IssuersResponse{Issuers: []*pb.Issuer{ctlPlatformIssuer(), ctlPlatformIssuer()}})
	s.EqualError(cmd.Run(s.Ctl), "platform issuer label is ambiguous: trusty.l1")
	s.MockAdmin.SetResponse(&pb.IssuersResponse{Issuers: []*pb.Issuer{ctlPlatformIssuer()}})
	s.MockBackend.SetResponse(ctlIssuer())
	s.MockBackend.Err = httperror.NewGrpc(codes.AlreadyExists, "issuer exists")
	s.EqualError(cmd.Run(s.Ctl), "conflict: issuer exists")
	s.MockBackend.Err = nil

	// templates
	empty := s.T().TempDir()
	s.EqualError((&admin.OrgBootstrapCmd{Templates: empty, Parent: "1"}).Run(s.Ctl), "no profile files in "+empty)
	s.ErrorContains((&admin.OrgBootstrapCmd{Templates: filepath.Join(empty, "nope"), Parent: "1"}).Run(s.Ctl), "no profile files in ")
}
