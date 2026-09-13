package authctx

import (
	"context"
	"sort"
	"strings"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
)

// methodAllowed applies the CheckAccess rules to a method without a request:
// roles are judged at org scope, or at the API key's project for a project
// scoped key.
func methodAllowed(tctx TrustyCtx, grants *Grants, rule *pb.MethodInfo) bool {
	if rule == nil || len(rule.AllowedRoles) == 0 {
		return true
	}
	if tctx.IsAPIKey() {
		return AllowsRole(rule.AllowedRoles, pb.Role_APIKey) &&
			HasScopes(tctx.Scopes(), ParseScopes(rule.Scopes))
	}
	if grants == nil || grants.HighestRole(0, rule.AllowedRoles) == pb.Role_None {
		return false
	}
	if scopes := tctx.Scopes(); len(scopes) > 0 && !HasScopes(scopes, ParseScopes(rule.Scopes)) {
		return false
	}
	return true
}

// GetAllowedMethods returns the methods the caller may call in the org
// selected in the token, grouped by service. Roles are judged at org
// scope; a project grant may allow more methods within its project.
func GetAllowedMethods(ctx context.Context, authorizer Authorizer) (*pb.ServiceAccessInfo, error) {
	tctx := FromContext(ctx)

	var grants *Grants
	if !tctx.IsAPIKey() && tctx.OrgID().UInt64() != 0 {
		var err error
		grants, err = authorizer.Grants(ctx, tctx.OrgID(), tctx.UserID())
		if err != nil {
			return nil, err
		}
	}

	byService := map[string]*pb.AllowedMethods{}
	addMethod := func(name, prefix string) {
		parts := strings.Split(name, "/")
		if len(parts) < 3 {
			return
		}
		service := strings.TrimPrefix(parts[1], prefix)
		si := byService[service]
		if si == nil {
			si = &pb.AllowedMethods{Service: service}
			byService[service] = si
		}
		si.Methods = append(si.Methods, &pb.KVPair{Key: parts[2], Value: name})
	}

	for name, info := range pb.GetMethodsInfo() {
		if strings.HasPrefix(name, identityServicePrefix) || methodAllowed(tctx, grants, info) {
			addMethod(name, "pb.")
		}
	}

	// only internal service roles may call the admin service
	if strings.HasPrefix(tctx.AppRole(), ServiceRolePrefix) {
		for name := range privpb.GetAdminMethodsInfo() {
			addMethod(name, "privpb.")
		}
	}

	res := &pb.ServiceAccessInfo{}
	for _, si := range byService {
		sort.Slice(si.Methods, func(i, j int) bool {
			return si.Methods[i].Key < si.Methods[j].Key
		})
		res.Allowed = append(res.Allowed, si)
	}
	sort.Slice(res.Allowed, func(i, j int) bool {
		return res.Allowed[i].Service < res.Allowed[j].Service
	})
	return res, nil
}

// ProjectFromRequest returns the ProjectID carried by the request, zero when
// the request has none
func ProjectFromRequest(req any) (xdb.ID, error) {
	if byProject, ok := req.(ProjectRequester); ok {
		if pid := byProject.GetProjectID(); pid != "" {
			return xdb.ParseID(pid)
		}
	}
	return xdb.ID{}, nil
}

// GetCallerScope returns the caller's resolved scope in the org selected in
// the token, and the access rules of every public method with the verdict
// at org scope
func GetCallerScope(ctx context.Context, authorizer Authorizer) (*pb.CallerScope, error) {
	tctx := FromContext(ctx)

	res := &pb.CallerScope{
		ProjectRoles: map[string]string{},
		Scopes:       tctx.Scopes(),
		IsAPIKey:     tctx.IsAPIKey(),
	}
	if orgID := tctx.OrgID(); orgID.UInt64() != 0 {
		res.OrgID = orgID.String()
	}
	if projectID := tctx.ProjectID(); projectID.UInt64() != 0 {
		res.ProjectID = projectID.String()
	}

	var grants *Grants
	switch {
	case tctx.IsAPIKey():
		res.Role = pb.Role_APIKey
		res.RoleSource = pb.RoleSource_Direct
	case tctx.OrgID().UInt64() != 0:
		var err error
		grants, err = authorizer.Grants(ctx, tctx.OrgID(), tctx.UserID())
		if err != nil {
			return nil, err
		}
		res.Role, res.RoleSource = grants.ResolvedOrgRole()
		for pid, role := range grants.ProjectRoles {
			res.ProjectRoles[xdb.NewID(pid).String()] = role.String()
		}
	}

	for name, info := range pb.GetMethodsInfo() {
		res.Methods = append(res.Methods, &pb.MethodAccess{
			Method:       name,
			AllowedRoles: info.AllowedRoles,
			Scopes:       ParseScopes(info.Scopes),
			Allowed:      strings.HasPrefix(name, identityServicePrefix) || methodAllowed(tctx, grants, info),
		})
	}
	sort.Slice(res.Methods, func(i, j int) bool {
		return res.Methods[i].Method < res.Methods[j].Method
	})
	return res, nil
}
