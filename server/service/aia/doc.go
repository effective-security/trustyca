// Package aia implements the Authority Information Access service: the
// public, read-only routes the issued certificates point at, served over
// plain HTTP without authentication, as a TLS verifier fetches them: the
// issuer certificate (AIA caIssuers, GET /v1/cert/{ikid}), the current CRL
// (CRL Distribution Point, GET /v1/crl/{ikid}) and the OCSP responder (GET
// and POST under /v1/ocsp and /v1/ocspi). The service is REST only; the
// JSON and gRPC API of the certificate information (pb.CIS) is the cis
// service of the wfe listener.
//
// The service reads the CA tables and holds no issuer keys. An OCSP request
// is forwarded to pb.CA.SignOCSP over the backend gRPC client, which is
// created on the first request with the certificate of the
// `aia.client_tls` configuration (the `trustyca-aia` identity), and the
// signed response is cached by the hash of the request until its
// NextUpdate. Every lookup is by the key identifier of the issuer, or by
// the OCSP request itself: the service lists nothing.
//
// The service is built by its Factory from the app container; a test wires
// a CA directly:
//
//	svc, err := aia.New(cfg, caReadonlyDb, caServer, nil)
//	if err != nil {
//		return err
//	}
//	svc.RegisterRoute(router)
package aia
