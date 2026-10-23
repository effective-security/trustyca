// Package ca implements the CA service of the tenants (pb.CA): the CA API
// of the users and the API keys of an org on the wfe listener (DESIGN.md
// section 2.1). The public requests carry no OrgID: the org is the org of
// the caller's token.
//
// The service holds no issuer key and reads no CA table: every method
// copies the public request into its privpb counterpart, with the org of
// the token in OrgID, and forwards it with the caller's context to the
// backend service (server/service/backend, privpb.Backend). It finds the
// backend through a shared.BackendLocator: the backend service of the same
// process, else the backend listener with the `ca` service client. A
// precondition refusal of a remote backend is HTTP 409 conflict again
// (forwardedError).
//
// The service is built by its Factory from the app container; a test wires
// it to a backend:
//
//	svc := ca.New(shared.NewStaticBackendLocator(backendSvc))
//	res, err := svc.SignCertificate(ctx, &pb.SignCertificateRequest{
//		Profile: "server",
//		Request: csrPEM,
//	})
package ca
