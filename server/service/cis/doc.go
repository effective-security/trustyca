// Package cis implements the Certificate Information Service (pb.CIS): the
// public, read-only side of the CA. It serves the trust anchors, issuer
// chains, certificate information and revocation status of every org over
// the JSON API (POST /pb.CIS/{Method}) and the binary routes the issued
// certificates point at: the issuer certificate (AIA caIssuers,
// GET /v1/cert/{ikid}), the current CRL (CDP, GET /v1/crl/{ikid}) and the
// OCSP responder (GET and POST under /v1/ocsp and /v1/ocspi).
//
// The service holds no issuer keys. An OCSP request is forwarded to
// pb.CA.SignOCSP over the backend gRPC client, which is created on the
// first request with the certificate of the `cis.client_tls`
// configuration, and the signed response is cached by the hash of the
// request until its NextUpdate. Every lookup needs an IKID, a serial, a
// SKID, a thumbprint or an ID: the service lists nothing of an org but its
// trust anchors.
//
// The service is built by its Factory from the app container; a test wires
// a CA directly:
//
//	svc, err := cis.New(cfg, caReadonlyDb, caServer, nil)
//	if err != nil {
//		return err
//	}
//	svc.RegisterRoute(router)
package cis
