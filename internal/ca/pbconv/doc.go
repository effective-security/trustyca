// Package pbconv converts between the CA API messages and the xpki
// authority configuration: a profile definition (pb.CertProfile) and the
// authority.CertProfile that signs with it, the runtime settings of an
// issuer (pb.IssuerConfig) and the authority.IssuerConfig the registry
// builds, and the X.509 extensions of requests and profiles.
//
// The package is a leaf: the CA core, the CA and CIS services and the
// administrative CLI share it, so a profile written in the YAML shape of a
// ca-config file is registered through the API with the same conversion the
// bootstrap uses:
//
//	var p authority.CertProfile
//	if err := yaml.Unmarshal(data, &p); err != nil {
//		return err
//	}
//	def := pbconv.ProfileToPb("server", &p)
//	_, err := caClient.RegisterProfile(ctx, &pb.RegisterProfileRequest{
//		OrgID:   orgID,
//		Profile: def,
//	})
//
// ExpandIssuerURL replaces the issuer placeholders of the AIA, CRL and OCSP
// URL templates (`${ISSUER_ID}` of the API, `:ISSUER_ID` of a ca-config
// file) with the key identifier of an issuer.
package pbconv
