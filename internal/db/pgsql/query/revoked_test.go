package query_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
)

func Test_RevokedQuery(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			query.RegisterRevoked, nil,
			`INSERT INTO trustyca.revoked 
( id, org_id, project_id, certificate_id, ikid, serial_number, not_after, revoked_at, reason, reason_text 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 
) 
RETURNING ` + schema.RevokedTableInfo.AllColumns(),
		},
		{
			query.GetRevoked, []any{&query.GetRevokedRequest{CertificateID: 1}},
			`SELECT ` + schema.RevokedTableInfo.AllColumns() + ` 
FROM trustyca.revoked 
WHERE certificate_id = $1`,
		},
		{
			// the OCSP lookup
			query.GetRevoked, []any{&query.GetRevokedRequest{IKID: "i", SerialNumber: "123"}},
			`SELECT ` + schema.RevokedTableInfo.AllColumns() + ` 
FROM trustyca.revoked 
WHERE ikid = $1 AND serial_number = $2`,
		},
		{
			query.GetRevoked, []any{&query.GetRevokedRequest{CertificateID: 1, IKID: "i", SerialNumber: "123"}},
			`SELECT ` + schema.RevokedTableInfo.AllColumns() + ` 
FROM trustyca.revoked 
WHERE certificate_id = $1 AND ikid = $2 AND serial_number = $3`,
		},
		{
			// the CRL entries of an issuer: one range scan on (ikid, not_after)
			query.ListRevoked, []any{&query.ListRevokedRequest{AllOrgs: true, IKID: "i", ValidAfter: &now, Limit: 1000, Cursor: cursor}},
			`SELECT ` + schema.RevokedTableInfo.AllColumns() + ` 
FROM trustyca.revoked 
WHERE ikid = $1 AND not_after > $2 AND id < $3 
ORDER BY id DESC 
LIMIT $4`,
		},
		{
			query.ListRevoked, []any{&query.ListRevokedRequest{OrgID: 1, Scope: pb.Scope_Project, Limit: 10}},
			`SELECT ` + schema.RevokedTableInfo.AllColumns() + ` 
FROM trustyca.revoked 
WHERE org_id = $1 AND project_id IS NOT NULL 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			query.ListRevokedCertificates, []any{&query.ListRevokedCertificatesRequest{OrgID: 1, IKID: "i", Limit: 10}},
			`SELECT ` + schema.RevokedCertificateTableInfo.AllColumns() + ` 
FROM trustyca.vw_revoked_certificate 
WHERE org_id = $1 AND ikid = $2 
ORDER BY id DESC 
LIMIT $3 
OFFSET $4`,
		},
		{
			query.ListRevokedCertificates, []any{&query.ListRevokedCertificatesRequest{OrgID: 1, ProjectID: 2, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.RevokedCertificateTableInfo.AllColumns() + ` 
FROM trustyca.vw_revoked_certificate 
WHERE org_id = $1 AND project_id = $2 AND id < $3 
ORDER BY id DESC 
LIMIT $4`,
		},
		{
			// the org-wide rows and the rows of the caller's projects, none here
			query.ListRevokedCertificates, []any{&query.ListRevokedCertificatesRequest{OrgID: 1, ProjectIDs: []uint64{}, IKID: "i", Limit: 10}},
			`SELECT ` + schema.RevokedCertificateTableInfo.AllColumns() + ` 
FROM trustyca.vw_revoked_certificate 
WHERE org_id = $1 AND (project_id IS NULL OR project_id = ANY($2)) AND ikid = $3 
ORDER BY id DESC 
LIMIT $4 
OFFSET $5`,
		},
	})
}
