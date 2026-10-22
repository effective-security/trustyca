// Package cis implements the Certificate Information Service (pb.CIS): the
// read-only view of the CA for authenticated callers. It serves the trust
// anchors, issuer chains, certificate information, revocation status and
// CRLs of every org over gRPC and the JSON API (POST /pb.CIS/{Method}) of
// the wfe listener, which admits any authenticated caller to /pb.CIS. The
// binary routes the issued certificates point at (the issuer certificate,
// the CRL Distribution Point and the OCSP responder) are the aia service.
//
// The service reads the CA tables and holds no issuer keys. Every lookup
// needs an IKID, a serial, a SKID, a thumbprint or an ID: the service lists
// nothing of an org but its trust anchors, and its views carry no tenancy
// and no client-owned fields.
//
// The service is built by its Factory from the app container; a test wires
// it directly:
//
//	svc, err := cis.New(caReadonlyDb)
//	if err != nil {
//		return err
//	}
//	svc.RegisterRoute(router)
package cis
