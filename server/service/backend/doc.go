// Package backend implements the backend service (privpb.Backend), the
// signing plane of the CA (DESIGN.md section 2.1): the methods of pb.CA
// that use an issuer key or change the issuer registry, RegisterIssuer,
// ImportIssuer, ActivateIssuer, UpdateIssuer, SignCertificate, PublishCrls
// and SignOCSP. It owns the issuer registry and the CRL publisher of
// internal/ca, and is served by the backend listener only, to service
// identities over mTLS.
//
// The CA service (server/service/ca) forwards those methods here with the
// context of its caller: in process when both run in one process, else
// over gRPC, where the backend interceptor authorizes the forwarded caller
// again. A method runs as that caller, or as the service identity that
// calls it (the AIA for SignOCSP). The tenant checks are the CA's
// (server/service/internal/caapi).
//
// The service is built by its Factory from the app container; a test wires
// it to a CA service in one process:
//
//	backendSvc := backend.New(caDb, orgsDb, authorizer, registry)
//	svc := ca.New(caDb, orgsDb, authorizer, client.NewStaticBackendLocator(backendSvc))
//	res, err := svc.SignCertificate(ctx, req)
package backend
