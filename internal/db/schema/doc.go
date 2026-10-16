// Package schema exposes generated table and column metadata to query builders.
//
// make gen-sql-schema generates schema.gen.go and model/model.gen.go from a
// recreated local database; typesmap.yaml controls conversions. init warms
// the column lists of the generated tables, which xdb caches without a lock.
package schema
