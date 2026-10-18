package pgsql_test

import (
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
)

// testKeyProvider is the crypto provider of the issuers the tests register
const testKeyProvider = "inmem"

// newTestIssuer builds an Active issuer row of the scope for the CA
func newTestIssuer(orgID, projectID xdb.ID, label string, ca *testutils.TestCA, typ pb.AuthorityType_Enum, parentID xdb.ID) *model.Issuer {
	m := &model.Issuer{
		OrgID:       orgID,
		ProjectID:   projectID,
		Label:       label,
		Type:        typ,
		Status:      pb.IssuerStatus_Active,
		ParentID:    parentID,
		KeyProvider: testKeyProvider,
		KeyID:       fmt.Sprintf("trustyca/%d/%d/%s", orgID.UInt64(), projectID.UInt64(), label),
	}
	m.SetCertificate(ca.Cert, testutils.CertPEM(ca.Cert), ca.ChainPEM(), testutils.CertPEM(ca.Root().Cert))
	return m
}

// registerIssuer registers the issuer and deletes it after the test
func registerIssuer(t *testing.T, m *model.Issuer) *model.Issuer {
	t.Helper()
	res, err := provider.RegisterIssuer(ctx, m)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteIssuer(ctx, res.OrgID.UInt64(), res.ID.UInt64())
	})
	return res
}

// registerCertificate registers the certificate issued by the CA and deletes
// it after the test
func registerCertificate(t *testing.T, crt *x509.Certificate, ca *testutils.TestCA, orgID, projectID xdb.ID, profile string, mod func(m *model.Certificate)) *model.Certificate {
	t.Helper()
	m := model.NewCertificate(crt, orgID, projectID, profile, testutils.CertPEM(crt), testutils.CertPEM(ca.Cert)+ca.ChainPEM(), "edge-1", nil, nil)
	if mod != nil {
		mod(m)
	}
	res, err := provider.RegisterCertificate(ctx, m, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteCertificate(ctx, res.OrgID.UInt64(), res.ID.UInt64())
	})
	return res
}
