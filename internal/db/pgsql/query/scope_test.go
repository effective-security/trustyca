package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ListScope(t *testing.T) {
	t.Parallel()

	// a list of CA rows fails closed without an org scope
	for _, r := range []xdb.Validator{
		&query.ListIssuersRequest{},
		&query.ListRootsRequest{},
		&query.ListProfilesRequest{},
		&query.ListCertificatesRequest{IKID: "i"},
		&query.ListRevokedRequest{IKID: "i"},
		&query.ListRevokedCertificatesRequest{ProjectID: 2},
		&query.ListCrlsRequest{},
	} {
		assert.ErrorIs(t, r.Validate(), query.ErrOrgScopeRequired)
	}
	require.NoError(t, (&query.ListIssuersRequest{OrgID: 1}).Validate())
	require.NoError(t, (&query.ListIssuersRequest{Platform: true}).Validate())
	require.NoError(t, (&query.ListIssuersRequest{AllOrgs: true}).Validate())

	// a revocation is addressed by the certificate, or by issuer and serial
	assert.EqualError(t, (&query.GetRevokedRequest{}).Validate(), "certificate ID, or IKID and serial number, are required")
	assert.EqualError(t, (&query.GetRevokedRequest{IKID: "i"}).Validate(), "certificate ID, or IKID and serial number, are required")
	require.NoError(t, (&query.GetRevokedRequest{CertificateID: 1}).Validate())
	require.NoError(t, (&query.GetRevokedRequest{IKID: "i", SerialNumber: "1"}).Validate())

	// a zero org is the platform's NULL
	v, err := query.OrgArg(0).Value()
	require.NoError(t, err)
	assert.Nil(t, v)
	v, err = query.OrgArg(7).Value()
	require.NoError(t, err)
	assert.EqualValues(t, 7, v)
}
