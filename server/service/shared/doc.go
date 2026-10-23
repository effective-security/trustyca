// Package shared contains shared utilities for the services.
// BackendLocator returns the backend service (privpb.Backend) that the CA and AIA services forward the
// key operations and OCSP requests to: the one of the same process when
// porto discovery has it (LocalBackend), else a client of the backend
// listener created on the first call.
//
//	backend := client.NewBackendLocator(server.Discovery, factory, client.ClientNameCA, config.BackendServerName)
//	signer, err := backend.Backend()
//	if err != nil {
//		return err
//	}
//	res, err := signer.SignCertificate(ctx, req)
package shared
