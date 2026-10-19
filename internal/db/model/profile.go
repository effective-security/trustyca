package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"google.golang.org/protobuf/proto"
)

// AnyIssuerLabel is the profile issuer label that allows any issuer whose
// config lists the profile in AllowedProfiles
const AnyIssuerLabel = "*"

// NewCertificateProfile builds a profile row of the scope from the profile
// definition: the label, issuer label and status come from the definition,
// the rest of it is stored as the config. A zero orgID is a platform profile.
func NewCertificateProfile(orgID, projectID xdb.ID, p *pb.CertProfile) (*CertificateProfile, error) {
	if p == nil {
		return nil, errors.New("invalid profile: required")
	}
	m := &CertificateProfile{
		OrgID:       orgID,
		ProjectID:   projectID,
		Label:       p.Label,
		IssuerLabel: p.IssuerLabel,
		Status:      p.Status,
	}
	if m.Status == pb.ItemStatus_Unknown {
		m.Status = pb.ItemStatus_Active
	}
	err := m.SetConfig(p)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Validate returns error if the model is not valid
func (m *CertificateProfile) Validate() error {
	if err := validateTenancy(m.OrgID, m.ProjectID); err != nil {
		return err
	}
	if err := validateLength("label", m.Label, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("issuer label", m.IssuerLabel, MaxLenForLabel, true); err != nil {
		return err
	}
	if m.Status == pb.ItemStatus_Unknown {
		return errors.New("invalid profile status")
	}
	return nil
}

// SetConfig stores the profile definition. The columns own the identity of
// the row, so ID, OrgID, ProjectID, Label, IssuerLabel, Status and the
// timestamps are not stored in the config.
func (m *CertificateProfile) SetConfig(p *pb.CertProfile) error {
	if p == nil {
		return errors.New("invalid profile: required")
	}
	cfg, ok := proto.Clone(p).(*pb.CertProfile)
	if !ok {
		return errors.New("invalid profile type")
	}
	cfg.ID = ""
	cfg.OrgID = ""
	cfg.ProjectID = ""
	cfg.Label = ""
	cfg.IssuerLabel = ""
	cfg.Status = pb.ItemStatus_Unknown
	cfg.CreatedAt = ""
	cfg.UpdatedAt = ""

	j, err := MarshalJSONValue(cfg)
	if err != nil {
		return err
	}
	m.Config = j
	return nil
}

// Definition returns the profile definition from the config with the
// labels and the status of the row, without its identity: the IDs are left
// empty. It is for the rows a cache shares between goroutines, since an
// xdb.ID formats itself into an unsynchronized cache.
func (m *CertificateProfile) Definition() (*pb.CertProfile, error) {
	p := new(pb.CertProfile)
	err := m.Config.Unmarshal(p)
	if err != nil {
		return nil, errors.WithMessagef(err, "invalid config of profile %s", xdb.IDString(m.ID.UInt64()))
	}
	p.Label = m.Label
	p.IssuerLabel = m.IssuerLabel
	p.Status = m.Status
	p.CreatedAt = m.CreatedAt.String()
	p.UpdatedAt = m.UpdatedAt.String()
	return p, nil
}

// Pb converts model to proto: the profile definition from the config with
// the identity of the row
func (m *CertificateProfile) Pb() (*pb.CertProfile, error) {
	p, err := m.Definition()
	if err != nil {
		return nil, err
	}
	p.ID = m.ID.String()
	p.OrgID = m.OrgID.String()
	p.ProjectID = m.ProjectID.String()
	return p, nil
}

// NextPage returns the next page of the result
func (v *CertificateProfileResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (v *CertificateProfileResult) Pb() (*pb.ProfilesResponse, error) {
	res := &pb.ProfilesResponse{
		Profiles: make([]*pb.CertProfile, len(v.Rows)),
		NextPage: v.NextPage(),
	}
	for i, r := range v.Rows {
		p, err := r.Pb()
		if err != nil {
			return nil, err
		}
		res.Profiles[i] = p
	}
	return res, nil
}
