package model

import "github.com/effective-security/trustyca/api/pb"

// nextPage returns the pagination of a list response: the cursor of the next
// page, nil on the last page
func nextPage(hasNextPage bool, cursor string) *pb.NextPage {
	if !hasNextPage {
		return nil
	}
	return &pb.NextPage{Cursor: cursor}
}
