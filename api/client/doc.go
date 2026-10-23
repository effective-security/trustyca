// Package client creates the gRPC clients the services and tools of
// trustyca dial other listeners with.
//
// A Factory holds the named service clients of the configuration
// (`clients`): each one has the TLS certificate it presents and the URLs of
// the listeners it dials, by listener name, so that one process can call
// with several identities, such as the `ca` client of the WFE and the `aia`
// client of the AIA (DESIGN.md section 2.2). A
//
//	factory, err := client.NewFactory(cfg.Clients)
//	if err != nil {
//		return err
//	}
package client
