package query

import (
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
	"github.com/lib/pq"
)

// RegisterAPIKey inserts a new API key into the database
func RegisterAPIKey(args ...any) (string, string) {
	key := "RegisterAPIKey"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.APIKeyTableInfo.InsertInto().
			Returning(schema.APIKeyTableInfo.AllColumns())
		// set all columns to nil as placeholders
		q.NewRow().
			Set(schema.APIKey.ID.Name, nil).
			Set(schema.APIKey.OrgID.Name, nil).
			Set(schema.APIKey.ProjectID.Name, nil).
			Set(schema.APIKey.Key.Name, nil).
			Set(schema.APIKey.Secret.Name, nil).
			Set(schema.APIKey.Label.Name, nil).
			Set(schema.APIKey.Scopes.Name, nil).
			Set(schema.APIKey.Metadata.Name, nil).
			Set(schema.APIKey.Status.Name, nil).
			Set(schema.APIKey.ExpiresAt.Name, nil).
			SetExpr(schema.APIKey.CreatedAt.Name, "Now()")
		return q
	})
}

// ListAPIKeysRequest defines request to list API keys of an org.
// Scopes limits the result to keys that hold all the listed scopes.
type ListAPIKeysRequest struct {
	OrgID     uint64
	ProjectID uint64
	Key       string
	Scopes    []string
	Status    pb.ItemStatus_Enum
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for pagination
	Offset uint32
}

// QueryParams returns the query params builder
func (r *ListAPIKeysRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListAPIKeys")

	if r.OrgID != 0 {
		b.Set(schema.APIKey.OrgID.Position, r.OrgID)
	}
	if r.ProjectID != 0 {
		b.Set(schema.APIKey.ProjectID.Position, r.ProjectID)
	}
	if len(r.Scopes) > 0 {
		b.Set(schema.APIKey.Scopes.Position, pq.Array(r.Scopes))
	}
	if r.Key != "" {
		b.Set(schema.APIKey.Key.Position, r.Key)
	}
	if r.Status != pb.ItemStatus_Unknown {
		b.Set(schema.APIKey.Status.Position, r.Status)
	}
	b.SetPage(r.Limit, r.Offset)

	return b
}

// ListAPIKeys selects API keys from the database
func ListAPIKeys(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.APIKeyTableInfo.Select().Limit(nil).Offset(nil)

		if p.IsSet(schema.APIKey.OrgID.Position) {
			q.Where("org_id = ?", nil)
		}
		if p.IsSet(schema.APIKey.ProjectID.Position) {
			q.Where("project_id = ?", nil)
		}
		if p.IsSet(schema.APIKey.Scopes.Position) {
			// the key must hold all the requested scopes
			q.Where("scopes @> ?", nil)
		}
		if p.IsSet(schema.APIKey.Key.Position) {
			q.Where("key = ?", nil)
		}
		if p.IsSet(schema.APIKey.Status.Position) {
			q.Where("status = ?", nil)
		}
		return q.OrderBy("created_at DESC, id DESC")
	})
}

// GetAPIKey returns API key by ID
func GetAPIKey(args ...any) (string, string) {
	const key = "GetAPIKey"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.APIKeyTableInfo.Select().
			Where("org_id = ?", nil).
			Where("id = ?", nil)
		return q
	})
}

// DeleteAPIKey returns SQL query to delete an API key of an org
func DeleteAPIKey(args ...any) (string, string) {
	const key = "DeleteAPIKey"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.APIKeyTableInfo.DeleteFrom().
			Where("org_id = ?", nil).
			Where("id = ?", nil)
	})
}

// UseAPIKey increments the used count and sets the used at time
func UseAPIKey(args ...any) (string, string) {
	const key = "UseAPIKey"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.APIKeyTableInfo.Update().
			Where("org_id = ?", nil).
			Where("id = ?", nil).
			Returning(schema.APIKeyTableInfo.AllColumns())
		// set all columns to nil as placeholders
		q.SetExpr(schema.APIKey.UsedCount.Name, schema.APIKey.UsedCount.Name+"+1").
			SetExpr(schema.APIKey.UsedAt.Name, "Now()")
		return q
	})
}
