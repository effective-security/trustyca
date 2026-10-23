// Package ca implements the CA service (pb.CA), the CA API of the tenants
// on the wfe listener and of the RA and the operator on the backend
// listener (DESIGN.md section 2.1).
//
// The service holds no issuer key and no issuer registry. It serves the
// methods that read and write the CA tables (issuers, roots, profiles,
// certificates, revocation, CRLs), and forwards RegisterIssuer,
// ImportIssuer, ActivateIssuer, UpdateIssuer, SignCertificate, PublishCrls
// and SignOCSP to the backend service (server/service/backend,
// privpb.Backend) with the context of its caller. It finds the backend
// through a client.BackendLocator: the backend service of the same
// process, else the backend listener with the `ca` service client. The
// tenant checks are shared with the backend
// (server/service/internal/caapi).
//
// The service is built by its Factory from the app container; a test wires
// it to a backend in one process:
//
//	backendSvc := backend.New(caDb, orgsDb, authorizer, registry)
//	svc := ca.New(caDb, orgsDb, authorizer, client.NewStaticBackendLocator(backendSvc))
//	res, err := svc.SignCertificate(ctx, req)
package ca
