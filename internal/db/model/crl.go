package model

import (
	"strconv"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// Validate returns error if the model is not valid. PublishCrl copies OrgID,
// ProjectID and Issuer from the issuer row before it validates.
func (m *Crl) Validate() error {
	if err := validateTenancy(m.OrgID, m.ProjectID); err != nil {
		return err
	}
	if m.IssuerID.IsZero() {
		return errors.New("invalid issuer ID")
	}
	if err := validateLength("ikid", m.Ikid, MaxLenForLabel, true); err != nil {
		return err
	}
	if m.CrlNumber <= 0 {
		return errors.New("invalid crl number: must be positive")
	}
	if m.ThisUpdate.IsZero() || m.NextUpdate.IsZero() || !m.NextUpdate.UTC().After(m.ThisUpdate.UTC()) {
		return errors.New("invalid update period")
	}
	if err := validateLength("issuer", m.Issuer, MaxLenForName, true); err != nil {
		return err
	}
	for _, loc := range m.Locations {
		if err := validateLength("location", loc, MaxLenForName, true); err != nil {
			return err
		}
	}
	if m.Pem == "" {
		return errors.New("invalid pem: required")
	}
	return nil
}

// Pb converts model to proto
func (m *Crl) Pb() *pb.Crl {
	return &pb.Crl{
		ID:         m.ID.String(),
		OrgID:      m.OrgID.String(),
		IssuerID:   m.IssuerID.String(),
		IKID:       m.Ikid,
		Number:     strconv.FormatInt(m.CrlNumber, 10),
		ThisUpdate: m.ThisUpdate.String(),
		NextUpdate: m.NextUpdate.String(),
		Issuer:     m.Issuer,
		Pem:        m.Pem,
		Locations:  []string(m.Locations),
	}
}

// NextPage returns the next page of the result
func (v *CrlResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto; pb.CrlsResponse carries no pagination,
// so the caller pages with NextPage
func (v *CrlResult) Pb() *pb.CrlsResponse {
	res := &pb.CrlsResponse{
		Crls: make([]*pb.Crl, len(v.Rows)),
	}
	for i, r := range v.Rows {
		res.Crls[i] = r.Pb()
	}
	return res
}
