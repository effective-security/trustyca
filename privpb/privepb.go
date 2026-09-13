package privpb

import "strings"

const adminServicePrefix = "/privpb.Admin/"

// GetAdminMethodsInfo returns the methods info for the admin service.
// It filters out the methods that are not prefixed with "/privpb.Admin/".
func GetAdminMethodsInfo() map[string]*MethodInfo {
	res := make(map[string]*MethodInfo, len(methods))
	for name, info := range methods {
		if !strings.HasPrefix(name, adminServicePrefix) {
			continue
		}
		res[name] = info
	}
	return res
}
