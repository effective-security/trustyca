package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
)

func Test_ProfileQuery(t *testing.T) {
	t.Parallel()

	cursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			query.RegisterProfile, nil,
			`INSERT INTO trustyca.certificate_profile 
( id, org_id, project_id, label, issuer_label, status, config, created_at, updated_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, Now(), Now() 
) 
ON CONFLICT ON CONSTRAINT unique_certificate_profile_org_project_label DO UPDATE SET 
	issuer_label = EXCLUDED.issuer_label, 
	status = EXCLUDED.status, 
	config = EXCLUDED.config, 
	updated_at = Now() 
RETURNING ` + schema.CertificateProfileTableInfo.AllColumns(),
		},
		{
			query.FindProfile, []any{&query.FindProfileRequest{OrgID: 1, ProjectID: 2, Label: "peer"}},
			`SELECT ` + schema.CertificateProfileTableInfo.AllColumns() + ` 
FROM trustyca.certificate_profile 
WHERE org_id = $1 AND project_id = $2 AND label = $3`,
		},
		{
			query.FindProfile, []any{&query.FindProfileRequest{Label: "peer"}},
			`SELECT ` + schema.CertificateProfileTableInfo.AllColumns() + ` 
FROM trustyca.certificate_profile 
WHERE org_id IS NULL AND project_id IS NULL AND label = $1`,
		},
		{
			query.ListProfiles, []any{&query.ListProfilesRequest{OrgID: 1, Scope: pb.Scope_Org, IssuerLabel: "L2_CA", Status: pb.ItemStatus_Active, Limit: 10}},
			`SELECT ` + schema.CertificateProfileTableInfo.AllColumns() + ` 
FROM trustyca.certificate_profile 
WHERE org_id = $1 AND project_id IS NULL AND issuer_label = $2 AND status = $3 
ORDER BY id DESC 
LIMIT $4 
OFFSET $5`,
		},
		{
			query.ListProfiles, []any{&query.ListProfilesRequest{OrgID: 1, ProjectID: 2, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.CertificateProfileTableInfo.AllColumns() + ` 
FROM trustyca.certificate_profile 
WHERE org_id = $1 AND project_id = $2 AND id < $3 
ORDER BY id DESC 
LIMIT $4`,
		},
	})
}
