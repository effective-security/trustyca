package model

import "github.com/effective-security/trustyca/api/pb"

// RecordsResult reports how many rows a bulk operation
// created, updated or deleted.
type RecordsResult struct {
	Created int64
	Updated int64
	Deleted int64
}

// Pb converts the result to proto
func (r *RecordsResult) Pb() *pb.RecordsResult {
	return &pb.RecordsResult{
		Created: r.Created,
		Updated: r.Updated,
		Deleted: r.Deleted,
	}
}
