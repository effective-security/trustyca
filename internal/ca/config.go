package ca

import (
	"slices"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xpki/authority"
)

// IssuerConfigFromPb converts the runtime settings of an issuer row to the
// configuration of the authority issuer with the label. The AIA section is
// always present, so that the CRL and OCSP timings fall back to the
// authority defaults when the row does not set them; the profiles are empty
// and are registered by the Registry.
func IssuerConfigFromPb(label string, c *pb.IssuerConfig) (*authority.IssuerConfig, error) {
	res := &authority.IssuerConfig{
		Label:    label,
		AIA:      &authority.AIAConfig{},
		Profiles: map[string]*authority.CertProfile{},
	}
	if c == nil {
		return res, nil
	}
	crlExpiry, err := parseDuration(c.CrlExpiry, "CrlExpiry")
	if err != nil {
		return nil, err
	}
	crlRenewal, err := parseDuration(c.CrlRenewal, "CrlRenewal")
	if err != nil {
		return nil, err
	}
	ocspExpiry, err := parseDuration(c.OcspExpiry, "OcspExpiry")
	if err != nil {
		return nil, err
	}
	res.AllowedProfiles = slices.Clone(c.AllowedProfiles)
	res.OmitDisabledExtensions = c.OmitDisabledExtensions
	res.AIA = &authority.AIAConfig{
		AiaURL:               c.AiaURL,
		OcspURL:              c.OcspURL,
		CrlURL:               c.CrlURL,
		CRLExpiry:            crlExpiry,
		OCSPExpiry:           ocspExpiry,
		CRLRenewal:           crlRenewal,
		DelegatedOCSPProfile: c.DelegatedOcspProfile,
	}
	return res, nil
}

// IssuerConfigToPb converts the configuration of a ca-config issuer to the
// runtime settings stored on its row: the AIA section, the allowed profiles
// and the extension policy. File locations and the loaded profiles are not
// settings of the row.
func IssuerConfigToPb(c *authority.IssuerConfig) *pb.IssuerConfig {
	res := &pb.IssuerConfig{
		AllowedProfiles:        slices.Clone(c.AllowedProfiles),
		OmitDisabledExtensions: c.OmitDisabledExtensions,
	}
	if c.AIA != nil {
		res.AiaURL = c.AIA.AiaURL
		res.OcspURL = c.AIA.OcspURL
		res.CrlURL = c.AIA.CrlURL
		res.CrlExpiry = formatDuration(c.AIA.CRLExpiry)
		res.CrlRenewal = formatDuration(c.AIA.CRLRenewal)
		res.OcspExpiry = formatDuration(c.AIA.OCSPExpiry)
		res.DelegatedOcspProfile = c.AIA.DelegatedOCSPProfile
	}
	return res
}
