// Package caapi holds the request handling that the CA service
// (server/service/ca, pb.CA) and the backend service
// (server/service/backend, privpb.Backend) share: the tenant scope of a
// request and the authorization of the rows it reaches (Scope), the
// precondition refusal of the CA (HTTP 409 conflict, gRPC
// FailedPrecondition), request parsing and the source of the audit events.
// It is internal to server/service.
//
//	scope := caapi.NewScope(authorizer, caDb, orgsDb)
//	orgID, err := scope.Org(ctx, req.OrgID)
//	if err != nil {
//		return nil, err
//	}
//	projectID, err := scope.Project(ctx, orgID, req.ProjectID)
package caapi
