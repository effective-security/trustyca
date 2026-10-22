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

func Test_CertificateQuery(t *testing.T) {
	t.Parallel()

	now := time.Now()
	label := "l"
	cursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			query.RegisterCertificate, nil,
			`INSERT INTO trustyca.certificate 
( id, org_id, project_id, skid, ikid, serial_number, not_before, not_after, subject, issuer, sha256, profile, label, locations, metadata, pem, issuers_pem, status, created_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, Now() 
) 
RETURNING ` + schema.CertificateTableInfo.AllColumns(),
		},
		{
			query.UpdateCertificate, []any{&query.UpdateCertificateRequest{ID: 1, OrgID: 2, Label: &label, Metadata: map[string]string{}, Locations: []string{}}},
			`UPDATE trustyca.certificate 
SET label=$1, metadata=$2, locations=$3 
WHERE id = $4 AND org_id IS NOT DISTINCT FROM $5 
RETURNING ` + schema.CertificateTableInfo.AllColumns(),
		},
		{
			query.UpdateCertificate, []any{&query.UpdateCertificateRequest{ID: 1, Locations: []string{"https://cis/v1/cert/1"}}},
			`UPDATE trustyca.certificate 
SET locations=$1 
WHERE id = $2 AND org_id IS NOT DISTINCT FROM $3 
RETURNING ` + schema.CertificateTableInfo.AllColumns(),
		},
		{
			query.UpdateCertificateStatus, nil,
			`UPDATE trustyca.certificate 
SET status=$1 
WHERE id = $2 
RETURNING ` + schema.CertificateTableInfo.AllColumns(),
		},
		{
			// the certificate status task: a batch of the lowest IDs of
			// the Active certificates that expired before the time
			// the status of the updated rows is checked again, on the row
			// version a concurrent revocation committed
			query.ExpireCertificates, nil,
			`UPDATE trustyca.certificate 
SET status=$1 
WHERE status = $2 AND id IN (SELECT id FROM trustyca.certificate WHERE status = $3 AND not_after < $4 ORDER BY id LIMIT $5)`,
		},
		{
			// retention: a batch of the lowest IDs of the certificates
			// that expired before the time, of any status
			query.DeleteExpiredCertificates, nil,
			`DELETE FROM trustyca.certificate 
WHERE id IN (SELECT id FROM trustyca.certificate WHERE not_after < $1 ORDER BY id LIMIT $2)`,
		},
		{
			query.GetCertificateForUpdate, nil,
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE id = $1 AND org_id IS NOT DISTINCT FROM $2 
FOR UPDATE`,
		},
		{
			query.GetCertificateBySha256, nil,
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE sha256 = $1`,
		},
		{
			query.GetCertificateByIssuerSerial, nil,
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE ikid = $1 AND serial_number = $2`,
		},
		{
			query.ListCertificates, []any{&query.ListCertificatesRequest{OrgID: 1, Limit: 10}},
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE org_id = $1 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			query.ListCertificates, []any{&query.ListCertificatesRequest{OrgID: 1, ProjectID: 2, IKID: "i", SKID: "s", Profile: "p", Status: pb.CertificateStatus_Active, ExpiringBefore: &now, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE org_id = $1 AND project_id = $2 AND ikid = $3 AND skid = $4 AND profile = $5 AND status = $6 AND not_after < $7 AND id < $8 
ORDER BY id DESC 
LIMIT $9`,
		},
		{
			// per issuer across orgs, as the CIS lists
			query.ListCertificates, []any{&query.ListCertificatesRequest{AllOrgs: true, IKID: "i", Limit: 10, Offset: 10}},
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE ikid = $1 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			// the org-wide rows and the rows of the caller's projects
			query.ListCertificates, []any{&query.ListCertificatesRequest{OrgID: 1, ProjectIDs: []uint64{2, 3}, Status: pb.CertificateStatus_Active, Limit: 10}},
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE org_id = $1 AND (project_id IS NULL OR project_id = ANY($2)) AND status = $3 
ORDER BY id DESC 
LIMIT $4 
OFFSET $5`,
		},
		{
			// an exact project takes precedence over the visible projects
			query.ListCertificates, []any{&query.ListCertificatesRequest{OrgID: 1, ProjectID: 2, ProjectIDs: []uint64{3}, Limit: 10}},
			`SELECT ` + schema.CertificateTableInfo.AllColumns() + ` 
FROM trustyca.certificate 
WHERE org_id = $1 AND project_id = $2 
ORDER BY id DESC 
LIMIT $3 
OFFSET $4`,
		},
	})
}
