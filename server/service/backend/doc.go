// Package backend implements the backend service (privpb.Backend): the CA
// of the service identities and the signing plane (DESIGN.md section 2.1).
// It serves every method of pb.CA with the org of the request named
// explicitly (the privpb copies of the pb.CA requests), owns the issuer
// registry and the CRL publisher of internal/ca, and is served by the
// backend listener only, to service identities over mTLS.
//
// The CA service of the tenants (server/service/ca) forwards every call
// here with the org of the caller's token and the caller's context: in
// process when both run in one process, else over gRPC, where the backend
// interceptor authorizes the forwarded caller again. The RA and the
// operator call it directly and name the org of every request; the AIA
// calls SignOCSP. A method runs as its caller and checks the tenant scope
// of the request and of the rows it reaches (tenantScope).
//
// The service is built by its Factory from the app container; a test calls
// it directly:
//
//	svc := backend.New(caDb, orgsDb, authorizer, registry)
//	res, err := svc.SignCertificate(ctx, &privpb.SignCertificateRequest{
//		OrgID:   orgID,
//		Profile: "server",
//		Request: csrPEM,
//	})
package backend
