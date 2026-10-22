package pbconv

import (
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/csr"
)

// ProfileFromPb converts a profile definition to the authority profile that
// signs with it and validates it with authority.CertProfile.Validate, which
// also compiles the allowed name patterns. The identity fields of the
// definition (ID, scope, status and timestamps) are not part of the result.
func ProfileFromPb(p *pb.CertProfile) (*authority.CertProfile, error) {
	if p == nil {
		return nil, errors.New("invalid profile: required")
	}
	expiry, err := parseDuration(p.Expiry, "Expiry")
	if err != nil {
		return nil, err
	}
	backdate, err := parseDuration(p.Backdate, "Backdate")
	if err != nil {
		return nil, err
	}
	extensions, err := ExtensionsFromPb(p.Extensions)
	if err != nil {
		return nil, err
	}
	allowedExtensions := make([]csr.OID, 0, len(p.AllowedExtensions))
	for _, val := range p.AllowedExtensions {
		oid, err := csr.ParseObjectIdentifier(val)
		if err != nil {
			return nil, errors.Errorf("invalid AllowedExtensions OID: %s", val)
		}
		allowedExtensions = append(allowedExtensions, oid)
	}
	policies := make([]csr.CertificatePolicy, 0, len(p.Policies))
	for _, policy := range p.Policies {
		if policy == nil {
			continue
		}
		oid, err := csr.ParseObjectIdentifier(policy.ID)
		if err != nil {
			return nil, errors.Errorf("invalid Policies OID: %s", policy.ID)
		}
		cp := csr.CertificatePolicy{
			ID:         oid,
			Qualifiers: make([]csr.CertificatePolicyQualifier, 0, len(policy.Qualifiers)),
		}
		for _, q := range policy.Qualifiers {
			if q == nil {
				continue
			}
			cp.Qualifiers = append(cp.Qualifiers, csr.CertificatePolicyQualifier{
				Type:  q.Type,
				Value: q.Value,
			})
		}
		policies = append(policies, cp)
	}

	res := &authority.CertProfile{
		IssuerLabel:       p.IssuerLabel,
		Description:       p.Description,
		Usage:             slices.Clone(p.Usages),
		OCSPNoCheck:       p.OcspNoCheck,
		Expiry:            csr.Duration(expiry),
		Backdate:          csr.Duration(backdate),
		Extensions:        extensions,
		AllowedExtensions: allowedExtensions,
		AllowedNames:      p.AllowedNames,
		AllowedDNS:        p.AllowedDns,
		AllowedEmail:      p.AllowedEmail,
		AllowedURI:        p.AllowedUri,
		Policies:          policies,
		PoliciesCritical:  p.PoliciesCritical,
		AllowedRoles:      slices.Clone(p.AllowedRoles),
		DeniedRoles:       slices.Clone(p.DeniedRoles),
	}
	if p.CAConstraint != nil {
		res.CAConstraint = authority.CAConstraint{
			IsCA:       p.CAConstraint.IsCA,
			MaxPathLen: int(p.CAConstraint.MaxPathLen),
		}
	}
	if p.AllowedFields != nil {
		res.AllowedCSRFields = &csr.AllowedFields{
			Subject:        p.AllowedFields.Subject,
			DNSNames:       p.AllowedFields.Dns,
			IPAddresses:    p.AllowedFields.Ip,
			EmailAddresses: p.AllowedFields.Email,
			URIs:           p.AllowedFields.Uri,
		}
	}
	err = res.Validate()
	if err != nil {
		return nil, errors.WithMessage(err, "invalid profile")
	}
	return res, nil
}

// ProfileToPb converts an authority profile, such as one loaded from a
// ca-config file, to the profile definition stored for the label
func ProfileToPb(label string, p *authority.CertProfile) *pb.CertProfile {
	res := &pb.CertProfile{
		Label:             label,
		IssuerLabel:       p.IssuerLabel,
		Description:       p.Description,
		Usages:            slices.Clone(p.Usage),
		OcspNoCheck:       p.OCSPNoCheck,
		Expiry:            formatDuration(p.Expiry.TimeDuration()),
		Backdate:          formatDuration(p.Backdate.TimeDuration()),
		Extensions:        ExtensionsToPb(p.Extensions),
		AllowedExtensions: p.AllowedExtensionsStrings(),
		AllowedNames:      p.AllowedNames,
		AllowedDns:        p.AllowedDNS,
		AllowedEmail:      p.AllowedEmail,
		AllowedUri:        p.AllowedURI,
		PoliciesCritical:  p.PoliciesCritical,
		AllowedRoles:      slices.Clone(p.AllowedRoles),
		DeniedRoles:       slices.Clone(p.DeniedRoles),
	}
	if p.CAConstraint.IsCA || p.CAConstraint.MaxPathLen != 0 {
		res.CAConstraint = &pb.CAConstraint{
			IsCA:       p.CAConstraint.IsCA,
			MaxPathLen: int32(p.CAConstraint.MaxPathLen),
		}
	}
	if p.AllowedCSRFields != nil {
		res.AllowedFields = &pb.CSRAllowedFields{
			Subject: p.AllowedCSRFields.Subject,
			Dns:     p.AllowedCSRFields.DNSNames,
			Ip:      p.AllowedCSRFields.IPAddresses,
			Email:   p.AllowedCSRFields.EmailAddresses,
			Uri:     p.AllowedCSRFields.URIs,
		}
	}
	for _, policy := range p.Policies {
		cp := &pb.CertificatePolicy{
			ID: policy.ID.String(),
		}
		for _, q := range policy.Qualifiers {
			cp.Qualifiers = append(cp.Qualifiers, &pb.CertificatePolicyQualifier{
				Type:  q.Type,
				Value: q.Value,
			})
		}
		res.Policies = append(res.Policies, cp)
	}
	return res
}

// ExtensionsFromPb converts the extensions of a request or a profile; the
// value stays encoded, as csr.X509Extension expects it
func ExtensionsFromPb(list []*pb.X509Extension) ([]csr.X509Extension, error) {
	if len(list) == 0 {
		return nil, nil
	}
	res := make([]csr.X509Extension, 0, len(list))
	for _, ex := range list {
		if ex == nil {
			continue
		}
		oid, err := csr.ParseObjectIdentifier(ex.ID)
		if err != nil {
			return nil, errors.Errorf("invalid extension OID: %s", ex.ID)
		}
		res = append(res, csr.X509Extension{
			ID:       oid,
			Critical: ex.Critical,
			Value:    ex.Value,
		})
	}
	return res, nil
}

// ExtensionsToPb converts the extensions of an authority profile
func ExtensionsToPb(list []csr.X509Extension) []*pb.X509Extension {
	if len(list) == 0 {
		return nil
	}
	res := make([]*pb.X509Extension, 0, len(list))
	for _, ex := range list {
		res = append(res, &pb.X509Extension{
			ID:       ex.ID.String(),
			Critical: ex.Critical,
			Value:    ex.Value,
		})
	}
	return res
}

// parseDuration parses an optional duration of a definition, such as "168h";
// empty is zero
func parseDuration(val, what string) (time.Duration, error) {
	if val == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return 0, errors.Errorf("invalid %s: %q is not a duration", what, val)
	}
	return d, nil
}

// formatDuration formats a duration of a definition; zero is empty
func formatDuration(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}
