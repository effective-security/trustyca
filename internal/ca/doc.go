// Package ca is the core of the Certification Authority: it resolves the
// issuer and the profile that serve a tenant request, builds authority
// issuers from the issuer rows and their keys, creates and imports issuers,
// and mirrors the platform ca-config into the CA tables.
//
// The Registry is the entry point of the signing services. Every lookup
// names its tenant scope and the built issuers are cached by row ID, so the
// labels of different orgs and projects never collide (DESIGN.md sections
// 5 and 6):
//
//	keys := ca.NewKeys(cryptoProviders, dataProtection)
//	registry := ca.NewRegistry(caDb, keys, ca.Options{TTL: 5 * time.Minute})
//
//	res, err := registry.Resolve(ctx, &ca.ResolveRequest{
//		OrgID:     orgID,
//		ProjectID: projectID,
//		Profile:   "server",
//	})
//	if err != nil {
//		// errors.Is(err, ca.ErrProfileNotFound), ca.ErrIssuerNotFound, ...
//	}
//	crt, pem, err := res.Issuer.Sign(csr.SignRequest{
//		Request: csrPEM,
//		Profile: res.ProfileName,
//	})
//
// Keys generates the key of a new issuer in a crypto provider, or wraps a
// software key with the data protection provider, and loads the key of a
// row; NewRootIssuer, NewSignedIssuer, NewPendingIssuer, ImportIssuer and
// ActivatedIssuer build the rows the service registers. Registry.Bootstrap
// registers the platform issuers, roots and profiles of an authority.Config
// at startup and loads the enabled issuers, so that one that does not load
// fails the start.
package ca
