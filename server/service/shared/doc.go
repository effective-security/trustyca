// Package shared contains the helpers that several services use.
//
// BackendLocator returns the backend service (privpb.Backend) that the CA
// service forwards every call to and the AIA its OCSP requests: the one of
// the same process when porto discovery has a privpb.BackendServer, else a
// client of the backend listener created on the first call with the named
// service client.
//
//	backend := shared.NewBackendLocator(server.Discovery, factory, client.ClientNameCA, config.BackendServerName)
//	srv, err := backend.Backend()
//	if err != nil {
//		return err
//	}
//	res, err := srv.SignCertificate(ctx, req)
package shared
