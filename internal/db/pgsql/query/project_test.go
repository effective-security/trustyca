package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_ProjectQueries(t *testing.T) {
	t.Parallel()

	check(t, []tcase{
		{
			query.RegisterProject, nil,
			`INSERT INTO trustyca.project 
( id, org_id, alias, name, description, status, created_at, updated_at 
) VALUES ( $1, $2, $3, $4, $5, 2, Now(), Now() 
) 
RETURNING ` + schema.ProjectTableInfo.AllColumns(),
		},
		{
			query.UpdateProject, []any{&query.UpdateProjectRequest{ID: 1, Name: "name", Description: "desc"}},
			`UPDATE trustyca.project 
SET name=$1, description=$2, updated_at=Now() 
WHERE id = $3 
RETURNING ` + schema.ProjectTableInfo.AllColumns(),
		},
		{
			query.UpdateProject, []any{&query.UpdateProjectRequest{ID: 1, Status: pb.ItemStatus_Inactive}},
			`UPDATE trustyca.project 
SET status=$1, updated_at=Now() 
WHERE id = $2 
RETURNING ` + schema.ProjectTableInfo.AllColumns(),
		},
		{
			query.ListProjects, []any{&query.ListProjectsRequest{OrgID: 1, Status: pb.ItemStatus_Active, Limit: 10}},
			`SELECT ` + schema.ProjectTableInfo.AllColumns() + ` 
FROM trustyca.project 
WHERE org_id = $1 AND status = $2 
ORDER BY name ASC, id ASC 
LIMIT $3 
OFFSET $4`,
		},
		{
			query.ListProjects, []any{&query.ListProjectsRequest{OrgID: 1, Limit: 10}},
			`SELECT ` + schema.ProjectTableInfo.AllColumns() + ` 
FROM trustyca.project 
WHERE org_id = $1 
ORDER BY name ASC, id ASC 
LIMIT $2 
OFFSET $3`,
		},
		{
			// only the projects with a grant
			query.ListProjects, []any{&query.ListProjectsRequest{OrgID: 1, IDs: []uint64{201, 202}, Limit: 10}},
			`SELECT ` + schema.ProjectTableInfo.AllColumns() + ` 
FROM trustyca.project 
WHERE org_id = $1 AND id = ANY($2) 
ORDER BY name ASC, id ASC 
LIMIT $3 
OFFSET $4`,
		},
		{
			query.GetProjectByAlias, nil,
			`SELECT ` + schema.ProjectTableInfo.AllColumns() + ` 
FROM trustyca.project 
WHERE org_id = $1 AND alias = $2`,
		},
	})
}
