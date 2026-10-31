package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
)

func Test_IssuerQuery(t *testing.T) {
	t.Parallel()

	cursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			// the counts of the summary: the org, a project, the visible projects
			query.CountIssuers, []any{&query.CountIssuersRequest{OrgID: 1}},
			`SELECT status, COUNT(*) 
FROM trustyca.issuer 
WHERE org_id = $1 
GROUP BY status`,
		},
		{
			query.CountIssuers, []any{&query.CountIssuersRequest{OrgID: 1, ProjectID: 2, ProjectIDs: []uint64{3}}},
			`SELECT status, COUNT(*) 
FROM trustyca.issuer 
WHERE org_id = $1 AND project_id = $2 
GROUP BY status`,
		},
		{
			query.CountIssuers, []any{&query.CountIssuersRequest{OrgID: 1, ProjectIDs: []uint64{}}},
			`SELECT status, COUNT(*) 
FROM trustyca.issuer 
WHERE org_id = $1 AND (project_id IS NULL OR project_id = ANY($2)) 
GROUP BY status`,
		},
		{
			query.RegisterIssuer, nil,
			`INSERT INTO trustyca.issuer 
( id, org_id, project_id, label, type, status, parent_id, skid, ikid, serial_number, subject, issuer, sha256, not_before, not_after, pem, chain_pem, root_pem, csr_pem, key_provider, key_id, key_protected, config, crl_number, created_at, updated_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, Now(), Now() 
) 
RETURNING ` + schema.IssuerTableInfo.AllColumns(),
		},
		{
			query.UpdateIssuer, []any{&query.UpdateIssuerRequest{ID: 1, Status: pb.IssuerStatus_Archived}},
			`UPDATE trustyca.issuer 
SET status=$1, updated_at=Now() 
WHERE id = $2 AND org_id IS NOT DISTINCT FROM $3 
RETURNING ` + schema.IssuerTableInfo.AllColumns(),
		},
		{
			// Destroyed clears the protected key
			query.UpdateIssuer, []any{&query.UpdateIssuerRequest{ID: 1, Status: pb.IssuerStatus_Destroyed, Config: []byte(`{}`)}},
			`UPDATE trustyca.issuer 
SET status=$1, key_protected=NULL, config=$2, updated_at=Now() 
WHERE id = $3 AND org_id IS NOT DISTINCT FROM $4 
RETURNING ` + schema.IssuerTableInfo.AllColumns(),
		},
		{
			query.UpdateIssuer, []any{&query.UpdateIssuerRequest{ID: 1, Config: []byte(`{}`)}},
			`UPDATE trustyca.issuer 
SET config=$1, updated_at=Now() 
WHERE id = $2 AND org_id IS NOT DISTINCT FROM $3 
RETURNING ` + schema.IssuerTableInfo.AllColumns(),
		},
		{
			query.ActivateIssuer, nil,
			`UPDATE trustyca.issuer 
SET skid=$1, ikid=$2, serial_number=$3, subject=$4, issuer=$5, sha256=$6, not_before=$7, not_after=$8, pem=$9, chain_pem=$10, root_pem=$11, csr_pem='', status=$12, updated_at=Now() 
WHERE id = $13 AND status = $14 AND org_id IS NOT DISTINCT FROM $15 
RETURNING ` + schema.IssuerTableInfo.AllColumns(),
		},
		{
			// the number only grows for the issuer whose SKID is the CRL's IKID;
			// updated_at is kept so issuer caches stay valid
			query.SetIssuerCrlNumber, nil,
			`UPDATE trustyca.issuer 
SET crl_number=$1 
WHERE id = $2 AND skid = $3 AND crl_number < $4 
RETURNING ` + schema.IssuerTableInfo.AllColumns(),
		},
		{
			query.FindIssuer, []any{&query.FindIssuerRequest{OrgID: 1, ProjectID: 2, Label: "l2"}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND project_id = $2 AND label = $3`,
		},
		{
			// org scope
			query.FindIssuer, []any{&query.FindIssuerRequest{OrgID: 1, Label: "l2"}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND project_id IS NULL AND label = $2`,
		},
		{
			// platform scope
			query.FindIssuer, []any{&query.FindIssuerRequest{Label: "L2_CA"}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id IS NULL AND project_id IS NULL AND label = $1`,
		},
		{
			query.GetIssuerBySKID, nil,
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE skid = $1`,
		},
		{
			// every org, for the service's own tasks
			query.ListIssuers, []any{&query.ListIssuersRequest{AllOrgs: true, Status: pb.IssuerStatus_Active, Limit: 10}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE status = $1 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			query.ListIssuers, []any{&query.ListIssuersRequest{OrgID: 1, ProjectID: 2, ParentID: 3, Type: pb.AuthorityType_Issuing, Limit: 10, Offset: 20}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND project_id = $2 AND parent_id = $3 AND type = $4 
ORDER BY id DESC 
LIMIT $5 
OFFSET $6`,
		},
		{
			// a platform issuer by label, for the admin
			query.ListIssuers, []any{&query.ListIssuersRequest{Platform: true, Label: "trusty.l1", Limit: 10}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id IS NULL AND label = $1 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			// platform rows of project scope, cursor page
			query.ListIssuers, []any{&query.ListIssuersRequest{Platform: true, Scope: pb.Scope_Project, Status: pb.IssuerStatus_Active, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id IS NULL AND project_id IS NOT NULL AND status = $1 AND id < $2 
ORDER BY id DESC 
LIMIT $3`,
		},
		{
			// the org-wide rows and the rows of the caller's projects, none here
			query.ListIssuers, []any{&query.ListIssuersRequest{OrgID: 1, ProjectIDs: []uint64{}, Status: pb.IssuerStatus_Active, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND (project_id IS NULL OR project_id = ANY($2)) AND status = $3 AND id < $4 
ORDER BY id DESC 
LIMIT $5`,
		},
		{
			// the issuers of a page of certificates: by ID, and by the key
			// identifier the certificates carry
			query.ListIssuers, []any{&query.ListIssuersRequest{OrgID: 1, IDs: []uint64{4, 5}, IKIDs: []string{"k1", "k2"}, Limit: 10}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND id = ANY($2) AND skid = ANY($3) 
ORDER BY id DESC 
LIMIT $4 
OFFSET $5`,
		},
		{
			// an exact project takes precedence over the visible projects
			query.ListIssuers, []any{&query.ListIssuersRequest{OrgID: 1, ProjectID: 2, ProjectIDs: []uint64{3}, Limit: 10}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND project_id = $2 
ORDER BY id DESC 
LIMIT $3 
OFFSET $4`,
		},
		{
			// the first cursor page has no cursor predicate
			query.ListIssuers, []any{&query.ListIssuersRequest{OrgID: 1, Scope: pb.Scope_Org, Limit: 10, Cursor: query.NewCursor(0)}},
			`SELECT ` + schema.IssuerTableInfo.AllColumns() + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND project_id IS NULL 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
	})
}
