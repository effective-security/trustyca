package pgsql_test

import (
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Certificate(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Certificate")
	project, err := provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Name: "CA"})
	require.NoError(t, err)

	root := testutils.NewTestCA(t, "Cert Root", nil)
	ca := testutils.NewTestCA(t, "Cert L2", root)
	issuer := registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "CERT_L2", ca, pb.AuthorityType_Issuing, xdb.ID(0)))
	now := time.Now()

	_, err = provider.RegisterCertificate(ctx, &model.Certificate{OrgID: org.ID}, nil)
	assert.EqualError(t, err, "invalid skid: required")
	orgID := org.ID.UInt64()
	label := func(s string) *string { return &s }

	crt1 := ca.Issue(t, "a.example.com", now.Add(-time.Minute), now.Add(24*time.Hour))
	c1 := registerCertificate(t, crt1, ca, org.ID, project.ID, "peer", func(m *model.Certificate) {
		m.Label = "a"
		m.Metadata = xdb.Metadata{"requester": "ci"}
	})
	assert.Equal(t, pb.CertificateStatus_Active, c1.Status, "the status defaults to Active")
	assert.Equal(t, "a", c1.Label)
	assert.Equal(t, xdb.Metadata{"requester": "ci"}, c1.Metadata)
	assert.Empty(t, c1.Locations)
	assert.Equal(t, certutil.GetSubjectKeyID(crt1), c1.Skid)
	assert.Equal(t, issuer.Skid, c1.Ikid)
	assert.Equal(t, crt1.SerialNumber.String(), c1.SerialNumber)
	assert.Equal(t, certutil.SHA256Hex(crt1.Raw), c1.Sha256)
	assert.Equal(t, testutils.CertPEM(crt1), c1.Pem)
	assert.Equal(t, testutils.CertPEM(ca.Cert)+testutils.CertPEM(root.Cert), c1.IssuersPem)
	assert.Equal(t, crt1.NotAfter.UnixMilli(), c1.NotAfter.UnixMilli())
	assert.False(t, c1.CreatedAt.IsZero())

	// the thumbprint is unique
	_, err = provider.RegisterCertificate(ctx, model.NewCertificate(crt1, org.ID, project.ID, "peer", c1.Pem, c1.IssuersPem, "edge-1", nil, nil), nil)
	assert.ErrorContains(t, err, "unique_certificate_sha256")

	// an org scope certificate expiring soon, and a project one with locations
	crt2 := ca.Issue(t, "b.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	c2 := registerCertificate(t, crt2, ca, org.ID, xdb.ID(0), "server", nil)
	assert.True(t, c2.ProjectID.IsZero())
	assert.Empty(t, c2.Metadata)
	crt3 := ca.Issue(t, "c.example.com", now.Add(-time.Minute), now.Add(48*time.Hour))
	c3 := registerCertificate(t, crt3, ca, org.ID, project.ID, "peer", func(m *model.Certificate) {
		m.Locations = []string{"https://cis/v1/cert/c"}
	})
	assert.Equal(t, []string{"https://cis/v1/cert/c"}, []string(c3.Locations))

	// get
	got, err := provider.GetCertificate(ctx, c1.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, c1.Sha256, got.Sha256)
	_, err = provider.GetCertificate(ctx, 1)
	assert.ErrorContains(t, err, "record not found: certificate: 1")
	got, err = provider.GetCertificateBySha256(ctx, c2.Sha256)
	require.NoError(t, err)
	assert.Equal(t, c2.ID.UInt64(), got.ID.UInt64())
	_, err = provider.GetCertificateBySha256(ctx, "nope")
	assert.ErrorContains(t, err, "record not found: certificate: nope")
	got, err = provider.GetCertificateByIssuerSerial(ctx, c3.Ikid, c3.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, c3.ID.UInt64(), got.ID.UInt64())
	_, err = provider.GetCertificateByIssuerSerial(ctx, c3.Ikid, "1")
	assert.ErrorContains(t, err, "record not found: certificate: "+c3.Ikid+"/1")

	// list: newest first, filters
	list, err := provider.ListCertificates(ctx, &query.ListCertificatesRequest{OrgID: org.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 3)
	assert.Equal(t, c3.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.Equal(t, c2.ID.UInt64(), list.Rows[1].ID.UInt64())
	assert.Equal(t, c1.ID.UInt64(), list.Rows[2].ID.UInt64())
	assert.False(t, list.HasNextPage)
	assert.Len(t, list.Pb().Certificates, 3)

	ids := func(req *query.ListCertificatesRequest) []uint64 {
		t.Helper()
		req.Limit = 10
		list, err := provider.ListCertificates(ctx, req)
		require.NoError(t, err)
		res := make([]uint64, len(list.Rows))
		for i, r := range list.Rows {
			res[i] = r.ID.UInt64()
		}
		return res
	}
	_, err = provider.ListCertificates(ctx, &query.ListCertificatesRequest{IKID: issuer.Skid, Limit: 10})
	assert.ErrorIs(t, err, db.ErrOrgScopeRequired, "a list names its org scope")
	assert.Equal(t, []uint64{c3.ID.UInt64(), c1.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, ProjectID: project.ID.UInt64()}))
	assert.Equal(t, []uint64{c3.ID.UInt64(), c1.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, Scope: pb.Scope_Project}))
	assert.Equal(t, []uint64{c2.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, Scope: pb.Scope_Org}))
	assert.Equal(t, []uint64{c3.ID.UInt64(), c2.ID.UInt64(), c1.ID.UInt64()}, ids(&query.ListCertificatesRequest{AllOrgs: true, IKID: issuer.Skid}), "per issuer across orgs")
	assert.Equal(t, []uint64{c2.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, SKID: c2.Skid}))
	assert.Equal(t, []uint64{c2.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, Profile: "server"}))
	assert.Equal(t, []uint64{c3.ID.UInt64(), c2.ID.UInt64(), c1.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, Status: pb.CertificateStatus_Active}))
	assert.Empty(t, ids(&query.ListCertificatesRequest{OrgID: orgID, Status: pb.CertificateStatus_Revoked}))
	in2h := now.Add(2 * time.Hour)
	in30h := now.Add(30 * time.Hour)
	assert.Equal(t, []uint64{c2.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, ExpiringBefore: &in2h}))
	assert.Equal(t, []uint64{c2.ID.UInt64(), c1.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, ExpiringBefore: &in30h}))
	assert.NotContains(t, ids(&query.ListCertificatesRequest{Platform: true}), c1.ID.UInt64(), "tenant rows are not platform rows")
	assert.Equal(t, []uint64{c3.ID.UInt64(), c2.ID.UInt64(), c1.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, ProjectIDs: []uint64{project.ID.UInt64()}}), "the org-wide rows and those of the visible projects")
	assert.Equal(t, []uint64{c2.ID.UInt64()}, ids(&query.ListCertificatesRequest{OrgID: orgID, ProjectIDs: []uint64{}}), "the org-wide rows only")

	// cursor pagination
	list, err = provider.ListCertificates(ctx, &query.ListCertificatesRequest{OrgID: orgID, Limit: 2, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	assert.Equal(t, c3.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.Equal(t, c2.ID.UInt64(), list.Rows[1].ID.UInt64())
	require.True(t, list.HasNextPage)
	require.NotEmpty(t, list.Cursor)
	assert.Equal(t, list.Cursor, list.Pb().NextPage.Cursor)
	next, err := query.ParseCursor(list.Cursor)
	require.NoError(t, err)
	list, err = provider.ListCertificates(ctx, &query.ListCertificatesRequest{OrgID: orgID, Limit: 2, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, c1.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.False(t, list.HasNextPage)
	assert.Empty(t, list.Cursor)

	// update
	_, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{})
	assert.EqualError(t, err, "certificate ID is required")
	_, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID})
	assert.EqualError(t, err, "no changes to update")
	_, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID, Label: label(string(make([]byte, 261)))})
	assert.EqualError(t, err, "invalid label length: 261")
	_, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID, Locations: []string{""}})
	assert.EqualError(t, err, "invalid location length: 0")
	_, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: 1, OrgID: orgID, Label: label("x")})
	assert.ErrorContains(t, err, "record not found: certificate: 1")
	_, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID + 1, Label: label("x")})
	assert.ErrorContains(t, err, "record not found", "another org's certificate is not found")

	upd, err := provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID, Label: label("renamed"), Locations: []string{"https://cis/v1/cert/a"}})
	require.NoError(t, err)
	assert.Equal(t, "renamed", upd.Label)
	assert.Equal(t, []string{"https://cis/v1/cert/a"}, []string(upd.Locations))
	assert.Equal(t, xdb.Metadata{"requester": "ci"}, upd.Metadata, "the metadata is kept")
	upd, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID, Metadata: xdb.Metadata{}})
	require.NoError(t, err)
	assert.Empty(t, upd.Metadata, "an empty metadata clears it")
	assert.Equal(t, "renamed", upd.Label)
	upd, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID, Metadata: xdb.Metadata{"team": "edge"}})
	require.NoError(t, err)
	assert.Equal(t, xdb.Metadata{"team": "edge"}, upd.Metadata)
	upd, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID, Label: label("")})
	require.NoError(t, err)
	assert.Empty(t, upd.Label, "an empty label clears it")
	upd, err = provider.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: c1.ID.UInt64(), OrgID: orgID, Label: label("renamed")})
	require.NoError(t, err)
	assert.Equal(t, "renamed", upd.Label)

	// revoke: the revocation and the status change are one transaction
	_, err = provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{})
	assert.EqualError(t, err, "certificate ID is required")
	_, err = provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{CertificateID: c1.ID.UInt64(), OrgID: orgID, ReasonText: string(make([]byte, 261))})
	assert.EqualError(t, err, "invalid reason text length: 261")
	_, err = provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{CertificateID: 1, OrgID: orgID})
	assert.ErrorContains(t, err, "record not found: certificate: 1")
	_, err = provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{CertificateID: c1.ID.UInt64(), OrgID: orgID + 1})
	assert.ErrorContains(t, err, "record not found", "another org's certificate is not found")
	got, err = provider.GetCertificate(ctx, c1.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, pb.CertificateStatus_Active, got.Status, "nothing was revoked")

	revokedAt := now.Add(-time.Second)
	rc, err := provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{
		CertificateID: c1.ID.UInt64(),
		OrgID:         orgID,
		RevokedAt:     revokedAt,
		Reason:        pb.ReasonCode_KeyCompromise,
		ReasonText:    "stolen",
	})
	require.NoError(t, err)
	assert.False(t, rc.ID.IsZero())
	assert.Equal(t, c1.ID.UInt64(), rc.CertificateID.UInt64())
	assert.Equal(t, pb.CertificateStatus_Revoked, rc.Status)
	assert.Equal(t, xdb.UTC(revokedAt).UnixMilli(), rc.RevokedAt.UnixMilli())
	assert.Equal(t, pb.ReasonCode_KeyCompromise, rc.Reason)
	assert.Equal(t, "stolen", rc.ReasonText)
	assert.Equal(t, c1.Pem, rc.Pem)
	assert.Equal(t, c1.Ikid, rc.Ikid)
	assert.Equal(t, "renamed", rc.Label)
	got, err = provider.GetCertificate(ctx, c1.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, pb.CertificateStatus_Revoked, got.Status)

	_, err = provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{CertificateID: c1.ID.UInt64(), OrgID: orgID})
	assert.ErrorIs(t, err, db.ErrAlreadyRevoked)

	rc2, err := provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{CertificateID: c2.ID.UInt64(), OrgID: orgID, Reason: pb.ReasonCode_Superseded})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), rc2.RevokedAt.UTC(), 5*time.Second, "a zero time is now")
	assert.Empty(t, rc2.ReasonText)

	// revocations: by certificate, or by issuer and serial as OCSP asks
	_, err = provider.GetRevoked(ctx, &query.GetRevokedRequest{IKID: c1.Ikid})
	assert.EqualError(t, err, "certificate ID, or IKID and serial number, are required")
	r, err := provider.GetRevoked(ctx, &query.GetRevokedRequest{CertificateID: c1.ID.UInt64()})
	require.NoError(t, err)
	assert.Equal(t, rc.ID.UInt64(), r.ID.UInt64())
	assert.Equal(t, c1.Ikid, r.Ikid)
	assert.Equal(t, c1.SerialNumber, r.SerialNumber)
	assert.Equal(t, c1.NotAfter.UnixMilli(), r.NotAfter.UnixMilli())
	assert.Equal(t, org.ID.UInt64(), r.OrgID.UInt64())
	assert.Equal(t, project.ID.UInt64(), r.ProjectID.UInt64())
	r, err = provider.GetRevoked(ctx, &query.GetRevokedRequest{IKID: c1.Ikid, SerialNumber: c1.SerialNumber})
	require.NoError(t, err)
	assert.Equal(t, rc.ID.UInt64(), r.ID.UInt64())
	_, err = provider.GetRevoked(ctx, &query.GetRevokedRequest{CertificateID: c3.ID.UInt64()})
	assert.ErrorContains(t, err, "record not found: revoked: "+c3.ID.String())
	_, err = provider.GetRevoked(ctx, &query.GetRevokedRequest{IKID: c3.Ikid, SerialNumber: c3.SerialNumber})
	assert.ErrorContains(t, err, "record not found: revoked: "+c3.Ikid+"/"+c3.SerialNumber)
	_, err = provider.GetRevoked(ctx, &query.GetRevokedRequest{CertificateID: c1.ID.UInt64(), IKID: c3.Ikid, SerialNumber: c3.SerialNumber})
	assert.ErrorContains(t, err, "record not found", "both identifiers must match")

	// the CRL entries: revoked and still valid
	_, err = provider.ListRevoked(ctx, &query.ListRevokedRequest{IKID: issuer.Skid, Limit: 10})
	assert.ErrorIs(t, err, db.ErrOrgScopeRequired)
	revoked, err := provider.ListRevoked(ctx, &query.ListRevokedRequest{AllOrgs: true, IKID: issuer.Skid, ValidAfter: &now, Limit: 10})
	require.NoError(t, err)
	require.Len(t, revoked.Rows, 2)
	assert.Equal(t, rc2.ID.UInt64(), revoked.Rows[0].ID.UInt64())
	assert.Equal(t, rc.ID.UInt64(), revoked.Rows[1].ID.UInt64())
	revoked, err = provider.ListRevoked(ctx, &query.ListRevokedRequest{AllOrgs: true, IKID: issuer.Skid, ValidAfter: &in2h, Limit: 10})
	require.NoError(t, err)
	require.Len(t, revoked.Rows, 1)
	assert.Equal(t, c1.ID.UInt64(), revoked.Rows[0].CertificateID.UInt64(), "the certificate expiring within 2h is left out")
	revoked, err = provider.ListRevoked(ctx, &query.ListRevokedRequest{OrgID: orgID, Scope: pb.Scope_Org, Limit: 10})
	require.NoError(t, err)
	require.Len(t, revoked.Rows, 1)
	assert.Equal(t, c2.ID.UInt64(), revoked.Rows[0].CertificateID.UInt64())
	revoked, err = provider.ListRevoked(ctx, &query.ListRevokedRequest{OrgID: orgID, ProjectID: project.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, revoked.Rows, 1)
	assert.Equal(t, c1.ID.UInt64(), revoked.Rows[0].CertificateID.UInt64())

	// revoked certificates with their certificate columns
	rcs, err := provider.ListRevokedCertificates(ctx, &query.ListRevokedCertificatesRequest{OrgID: orgID, Limit: 10})
	require.NoError(t, err)
	require.Len(t, rcs.Rows, 2)
	assert.Equal(t, rc2.ID.UInt64(), rcs.Rows[0].ID.UInt64())
	assert.Equal(t, c2.ID.UInt64(), rcs.Rows[0].CertificateID.UInt64())
	assert.Equal(t, c2.Pem, rcs.Rows[0].Pem)
	assert.Equal(t, pb.CertificateStatus_Revoked, rcs.Rows[0].Status)
	assert.Equal(t, pb.ReasonCode_Superseded, rcs.Rows[0].Reason)
	assert.Equal(t, c1.ID.UInt64(), rcs.Rows[1].CertificateID.UInt64())
	assert.Equal(t, "stolen", rcs.Rows[1].ReasonText)
	assert.Equal(t, xdb.Metadata{"team": "edge"}, rcs.Rows[1].Metadata)
	res := rcs.Pb()
	require.Len(t, res.RevokedCertificates, 2)
	assert.Equal(t, c1.ID.String(), res.RevokedCertificates[1].Certificate.ID)
	assert.Nil(t, res.NextPage)

	_, err = provider.ListRevokedCertificates(ctx, &query.ListRevokedCertificatesRequest{ProjectID: project.ID.UInt64(), Limit: 10})
	assert.ErrorIs(t, err, db.ErrOrgScopeRequired)
	rcs, err = provider.ListRevokedCertificates(ctx, &query.ListRevokedCertificatesRequest{OrgID: orgID, IKID: issuer.Skid, ProjectID: project.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, rcs.Rows, 1)
	assert.Equal(t, c1.ID.UInt64(), rcs.Rows[0].CertificateID.UInt64())
	rcs, err = provider.ListRevokedCertificates(ctx, &query.ListRevokedCertificatesRequest{OrgID: orgID, ProjectIDs: []uint64{}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, rcs.Rows, 1, "the org-wide rows only")
	assert.Equal(t, c2.ID.UInt64(), rcs.Rows[0].CertificateID.UInt64())
	rcs, err = provider.ListRevokedCertificates(ctx, &query.ListRevokedCertificatesRequest{OrgID: orgID, ProjectIDs: []uint64{project.ID.UInt64()}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, rcs.Rows, 2, "the org-wide rows and those of the visible projects")

	rcs, err = provider.ListRevokedCertificates(ctx, &query.ListRevokedCertificatesRequest{OrgID: orgID, Limit: 1, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	require.Len(t, rcs.Rows, 1)
	assert.Equal(t, rc2.ID.UInt64(), rcs.Rows[0].ID.UInt64())
	require.True(t, rcs.HasNextPage)
	next, err = query.ParseCursor(rcs.Cursor)
	require.NoError(t, err)
	rcs, err = provider.ListRevokedCertificates(ctx, &query.ListRevokedCertificatesRequest{OrgID: orgID, Limit: 1, Cursor: next})
	require.NoError(t, err)
	require.Len(t, rcs.Rows, 1)
	assert.Equal(t, rc.ID.UInt64(), rcs.Rows[0].ID.UInt64())

	// deleting the certificate deletes its revocation; delete is scoped by org
	n, err := provider.DeleteCertificate(ctx, orgID+1, c1.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	n, err = provider.DeleteCertificate(ctx, orgID, c1.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	_, err = provider.GetRevoked(ctx, &query.GetRevokedRequest{CertificateID: c1.ID.UInt64()})
	assert.ErrorContains(t, err, "record not found")
	n, err = provider.DeleteCertificate(ctx, orgID, c1.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
}

func Test_Certificate_RevokeConcurrently(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Certificate_RevokeConcurrently")
	ca := testutils.NewTestCA(t, "Concurrent L2", nil)
	now := time.Now()
	crt := ca.Issue(t, "race.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	c := registerCertificate(t, crt, ca, org.ID, xdb.ID(0), "peer", nil)
	certID := c.ID.UInt64()
	orgID := org.ID.UInt64()

	// the row lock serializes the revocations: exactly one wins
	const revokers = 4
	results := make(chan error, revokers)
	var wg sync.WaitGroup
	for range revokers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{
				CertificateID: certID,
				OrgID:         orgID,
				Reason:        pb.ReasonCode_KeyCompromise,
			})
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var revoked, already int
	for err := range results {
		switch {
		case err == nil:
			revoked++
		case errors.Is(err, db.ErrAlreadyRevoked):
			already++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, revoked)
	assert.Equal(t, revokers-1, already)

	revocations, err := provider.ListRevoked(ctx, &query.ListRevokedRequest{OrgID: orgID, Limit: 10})
	require.NoError(t, err)
	assert.Len(t, revocations.Rows, 1)
}

func Test_Certificate_RegisterWithEvent(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Certificate_RegisterWithEvent")
	project, err := provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Name: "CA"})
	require.NoError(t, err)
	ca := testutils.NewTestCA(t, "Event L2", nil)
	now := time.Now()
	crt := ca.Issue(t, "event.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	m := model.NewCertificate(crt, org.ID, project.ID, "peer", testutils.CertPEM(crt), testutils.CertPEM(ca.Cert), "edge-1", nil, nil)

	// an invalid event is refused before anything is written
	_, err = provider.RegisterCertificate(ctx, m, &model.Event{OrgID: org.ID, Type: pb.EventType_CertificateIssued})
	assert.EqualError(t, err, "invalid title")
	_, err = provider.GetCertificateBySha256(ctx, m.Sha256)
	assert.ErrorContains(t, err, "record not found")

	// an event that fails to insert rolls the certificate back
	_, err = provider.RegisterCertificate(ctx, m, &model.Event{
		OrgID: xdb.NewID(1),
		Type:  pb.EventType_CertificateIssued,
		Title: "certificate issued",
	})
	assert.ErrorContains(t, err, "unable to record event")
	_, err = provider.GetCertificateBySha256(ctx, m.Sha256)
	assert.ErrorContains(t, err, "record not found", "the certificate insert was rolled back")

	c, err := provider.RegisterCertificate(ctx, m, &model.Event{
		OrgID:     org.ID,
		ProjectID: project.ID,
		Type:      pb.EventType_CertificateIssued,
		Title:     "certificate issued",
		Email:     "ra@example.com",
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteCertificate(ctx, org.ID.UInt64(), c.ID.UInt64())
	})
	assert.Equal(t, pb.CertificateStatus_Active, c.Status)

	events, err := provider.ListEvents(ctx, &query.ListEventsRequest{OrgID: org.ID.UInt64(), ReferenceID: c.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, events.Rows, 1, "the event references the certificate")
	assert.Equal(t, pb.EventType_CertificateIssued, events.Rows[0].Type)
	assert.Equal(t, project.ID.UInt64(), events.Rows[0].ProjectID.UInt64())
	assert.Equal(t, "ra@example.com", events.Rows[0].Email.String())
}

// Test_Certificate_Expiry covers the batches of the certificate status task:
// expired Active certificates become Expired, and retention deletes expired
// certificates of any status with their revocations. The certificates
// expired decades ago, so the statements touch the rows of this test only.
func Test_Certificate_Expiry(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Certificate_Expiry")
	root := testutils.NewTestCA(t, "Expiry Root", nil)
	ca := testutils.NewTestCA(t, "Expiry L2", root)
	registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "EXPIRY_L2", ca, pb.AuthorityType_Issuing, xdb.ID(0)))
	orgID := org.ID.UInt64()

	// the validity periods: ancient, old and current
	ancientEnd := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	oldEnd := time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2003, 1, 1, 0, 0, 0, 0, time.UTC)
	ancient := registerCertificate(t, ca.Issue(t, "ancient.example.com", ancientEnd.Add(-time.Hour), ancientEnd), ca, org.ID, xdb.ID(0), "peer", nil)
	revoked := registerCertificate(t, ca.Issue(t, "revoked.example.com", ancientEnd.Add(-time.Hour), ancientEnd), ca, org.ID, xdb.ID(0), "peer", nil)
	old := registerCertificate(t, ca.Issue(t, "old.example.com", oldEnd.Add(-time.Hour), oldEnd), ca, org.ID, xdb.ID(0), "peer", nil)
	current := registerCertificate(t, ca.Issue(t, "current.example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour)), ca, org.ID, xdb.ID(0), "peer", nil)
	_, err := provider.RevokeCertificate(ctx, &query.RevokeCertificateRequest{
		CertificateID: revoked.ID.UInt64(),
		OrgID:         orgID,
		Reason:        pb.ReasonCode_Superseded,
	})
	require.NoError(t, err)

	status := func(id xdb.ID) pb.CertificateStatus_Enum {
		t.Helper()
		got, err := provider.GetCertificate(ctx, id.UInt64())
		require.NoError(t, err)
		return got.Status
	}

	// expire: the batches take the lowest IDs first, so the next batch
	// continues without an offset; a Revoked certificate keeps its status
	_, err = provider.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{})
	assert.EqualError(t, err, "expiry time is required")
	_, err = provider.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{Before: cutoff})
	assert.EqualError(t, err, "limit is required")
	n, err := provider.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{Before: ancientEnd, Limit: 10})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n, "nothing expired before the ancient end")
	n, err = provider.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{Before: cutoff, Limit: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	assert.Equal(t, pb.CertificateStatus_Expired, status(ancient.ID), "the lowest ID first")
	assert.Equal(t, pb.CertificateStatus_Active, status(old.ID))
	n, err = provider.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{Before: cutoff, Limit: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	assert.Equal(t, pb.CertificateStatus_Expired, status(old.ID))
	n, err = provider.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{Before: cutoff, Limit: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n, "the batches are exhausted")
	assert.Equal(t, pb.CertificateStatus_Revoked, status(revoked.ID))
	assert.Equal(t, pb.CertificateStatus_Active, status(current.ID))

	// retention: the certificates expired before the time are deleted with
	// their revocations, whatever their status
	_, err = provider.DeleteExpiredCertificates(ctx, &query.DeleteExpiredCertificatesRequest{})
	assert.EqualError(t, err, "expiry time is required")
	_, err = provider.DeleteExpiredCertificates(ctx, &query.DeleteExpiredCertificatesRequest{Before: cutoff})
	assert.EqualError(t, err, "limit is required")
	n, err = provider.DeleteExpiredCertificates(ctx, &query.DeleteExpiredCertificatesRequest{Before: oldEnd, Limit: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	_, err = provider.GetCertificate(ctx, ancient.ID.UInt64())
	assert.ErrorContains(t, err, "record not found", "the lowest ID first")
	n, err = provider.DeleteExpiredCertificates(ctx, &query.DeleteExpiredCertificatesRequest{Before: oldEnd, Limit: 10})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	_, err = provider.GetCertificate(ctx, revoked.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
	_, err = provider.GetRevoked(ctx, &query.GetRevokedRequest{CertificateID: revoked.ID.UInt64()})
	assert.ErrorContains(t, err, "record not found", "the revocation follows the certificate")
	n, err = provider.DeleteExpiredCertificates(ctx, &query.DeleteExpiredCertificatesRequest{Before: oldEnd, Limit: 10})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	assert.Equal(t, pb.CertificateStatus_Expired, status(old.ID), "not expired before the time")
	n, err = provider.DeleteExpiredCertificates(ctx, &query.DeleteExpiredCertificatesRequest{Before: cutoff, Limit: 10})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	assert.Equal(t, pb.CertificateStatus_Active, status(current.ID))
}

// waitingExpiryQuery counts the sessions whose expiry statement waits for
// a row lock
const waitingExpiryQuery = `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%trustyca.certificate WHERE status = % AND not_after < %'`

// Test_Certificate_Expiry_Revoked checks that the expiry statement does not
// overwrite a revocation it waited for: PostgreSQL rechecks the status of
// the row the statement updates on the version the revocation committed
func Test_Certificate_Expiry_Revoked(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Certificate_Expiry_Revoked")
	root := testutils.NewTestCA(t, "Expiry Race Root", nil)
	ca := testutils.NewTestCA(t, "Expiry Race L2", root)
	registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "EXPIRY_RACE_L2", ca, pb.AuthorityType_Issuing, xdb.ID(0)))
	end := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	crt := registerCertificate(t, ca.Issue(t, "race.example.com", end.Add(-time.Hour), end), ca, org.ID, xdb.ID(0), "peer", nil)
	t.Cleanup(func() {
		_, _ = provider.DeleteCertificate(ctx, org.ID.UInt64(), crt.ID.UInt64())
	})

	// the revocation locks the certificate row until it commits, as
	// RevokeCertificate does
	tx, err := provider.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Close() }()
	forUpdate, _ := query.GetCertificateForUpdate()
	_, err = xdb.QueryRow[model.Certificate](ctx, tx, forUpdate, crt.ID, query.OrgArg(org.ID.UInt64()))
	require.NoError(t, err)

	// the expiry statement selects the certificate and waits for the row
	done := make(chan error, 1)
	go func() {
		_, err := provider.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{Before: end.Add(time.Hour), Limit: 10})
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting int
		err := provider.QueryRowContext(ctx, waitingExpiryQuery).Scan(&waiting)
		return err == nil && waiting > 0
	}, 10*time.Second, 20*time.Millisecond, "the expiry statement waits for the lock")

	// the revocation commits: the statement rechecks the row it waited for
	setStatus, _ := query.UpdateCertificateStatus()
	_, err = xdb.QueryRow[model.Certificate](ctx, tx, setStatus, pb.CertificateStatus_Revoked, crt.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	require.NoError(t, <-done)
	got, err := provider.GetCertificate(ctx, crt.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, pb.CertificateStatus_Revoked, got.Status, "the revocation is kept")
}
