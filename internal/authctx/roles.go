package authctx

import (
	"strings"

	"github.com/effective-security/trustyca/api/pb"
)

// CanAssumeRoles specifies which roles a caller role may satisfy when a
// method declares (es.api.allowed_roles). The listed roles are the minimum
// roles allowed; a caller passes when its own role can assume one of them.
// For example, with allowed_roles "User" a Viewer is denied and a Security
// caller is allowed, because Security may assume User.
var CanAssumeRoles = map[pb.Role_Enum][]pb.Role_Enum{
	pb.Role_APIKey:   {pb.Role_APIKey},
	pb.Role_Viewer:   {pb.Role_Viewer},
	pb.Role_User:     {pb.Role_User, pb.Role_Viewer},
	pb.Role_Support:  {pb.Role_Support, pb.Role_User, pb.Role_Viewer},
	pb.Role_Billing:  {pb.Role_Billing, pb.Role_User, pb.Role_Viewer},
	pb.Role_Security: {pb.Role_Security, pb.Role_User, pb.Role_Viewer},
	pb.Role_Admin:    {pb.Role_Admin, pb.Role_Security, pb.Role_Support, pb.Role_User, pb.Role_Billing, pb.Role_Viewer},
	pb.Role_Owner:    {pb.Role_Owner, pb.Role_Admin, pb.Role_Security, pb.Role_Support, pb.Role_User, pb.Role_Billing, pb.Role_Viewer},
}

// RoleEnumValue maps role names, in the proto and lowercase spelling, to roles
var RoleEnumValue = map[string]pb.Role_Enum{
	"apikey":   pb.Role_APIKey,
	"APIKey":   pb.Role_APIKey,
	"viewer":   pb.Role_Viewer,
	"Viewer":   pb.Role_Viewer,
	"user":     pb.Role_User,
	"User":     pb.Role_User,
	"billing":  pb.Role_Billing,
	"Billing":  pb.Role_Billing,
	"security": pb.Role_Security,
	"Security": pb.Role_Security,
	"support":  pb.Role_Support,
	"Support":  pb.Role_Support,
	"admin":    pb.Role_Admin,
	"Admin":    pb.Role_Admin,
	"owner":    pb.Role_Owner,
	"Owner":    pb.Role_Owner,
}

// ParseRole parses a role name case-insensitively; None when unknown
func ParseRole(name string) pb.Role_Enum {
	if r, ok := RoleEnumValue[name]; ok {
		return r
	}
	for v, n := range pb.Role_Enum_name {
		if strings.EqualFold(n, name) {
			return pb.Role_Enum(v)
		}
	}
	return pb.Role_None
}

// CanAssumeRole returns true if a caller with the role may assume one of the
// allowed roles
func CanAssumeRole(callerRole pb.Role_Enum, allowedRoles []string) bool {
	callerCan := CanAssumeRoles[callerRole]
	for _, allowedRole := range allowedRoles {
		role := ParseRole(strings.TrimSpace(allowedRole))
		for _, can := range callerCan {
			if can == role {
				return true
			}
		}
	}
	return false
}

// AllowsRole returns true if the allowed roles list contains the role itself
func AllowsRole(allowedRoles []string, role pb.Role_Enum) bool {
	for _, allowedRole := range allowedRoles {
		if ParseRole(strings.TrimSpace(allowedRole)) == role {
			return true
		}
	}
	return false
}

// OrgRoles are the roles that can be granted org-wide
var OrgRoles = []pb.Role_Enum{
	pb.Role_Viewer, pb.Role_User, pb.Role_Support, pb.Role_Billing,
	pb.Role_Security, pb.Role_Admin, pb.Role_Owner,
}

// ProjectRoles are the roles that can be granted in a project.
// Owner and Billing are org-wide concepts and cannot be granted per project.
var ProjectRoles = []pb.Role_Enum{
	pb.Role_Viewer, pb.Role_User, pb.Role_Support, pb.Role_Security, pb.Role_Admin,
}

// IsProjectRole returns true if the role can be granted in a project
func IsProjectRole(role pb.Role_Enum) bool {
	for _, r := range ProjectRoles {
		if r == role {
			return true
		}
	}
	return false
}

// IsOrgRole returns true if the role can be granted org-wide
func IsOrgRole(role pb.Role_Enum) bool {
	for _, r := range OrgRoles {
		if r == role {
			return true
		}
	}
	return false
}

// Role source claim values
const (
	// RoleSourceDirect marks an explicit org-wide grant
	RoleSourceDirect = "direct"
	// RoleSourceProject marks a derived Viewer classification from project grants
	RoleSourceProject = "project"
)

// RoleSourceClaim returns the token claim value for the role source
func RoleSourceClaim(source pb.RoleSource_Enum) string {
	switch source {
	case pb.RoleSource_Direct:
		return RoleSourceDirect
	case pb.RoleSource_Project:
		return RoleSourceProject
	default:
		return ""
	}
}
