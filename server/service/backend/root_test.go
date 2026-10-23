package backend

import (
	"context"
	"testing"

	"github.com/effective-security/trustyca/privpb"

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
	"go.uber.org/mock/gomock"
)

func TestService_RegisterRoot(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	root := testutils.NewTestCA(t, "External Root", nil)
	rootPEM, err := certutil.EncodeToPEMString(false, root.Cert)
	require.NoError(t, err)

	_, err = svc.RegisterRoot(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing certificate")
	_, err = svc.RegisterRoot(ctx, &privpb.RegisterRootRequest{Pem: " "})
	assert.EqualError(t, err, "bad_request: missing certificate")
	_, err = svc.RegisterRoot(testCtx("42", ""), &privpb.RegisterRootRequest{Pem: testutils.CertPEM(root.Cert)})
	assert.EqualError(t, err, "forbidden: org not selected")
	_, err = svc.RegisterRoot(ctx, &privpb.RegisterRootRequest{Pem: "junk"})
	assert.EqualError(t, err, "bad_request: invalid certificate")
	_, err = svc.RegisterRoot(ctx, &privpb.RegisterRootRequest{Pem: tca.issuer.Pem})
	assert.EqualError(t, err, "bad_request: certificate is not a self-signed CA certificate")

	tca.cadb.EXPECT().RegisterRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *model.RootCertificate) (*model.RootCertificate, error) {
			assert.Equal(t, uint64(1), m.OrgID.UInt64())
			assert.Equal(t, pb.Trust_Public, m.Trust)
			assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), m.Skid)
			assert.Equal(t, rootPEM, m.Pem)
			assert.Equal(t, root.Cert.Subject.String(), m.Subject)
			res := *m
			res.ID = xdb.NewID(77)
			return &res, nil
		})
	res, err := svc.RegisterRoot(ctx, &privpb.RegisterRootRequest{Pem: testutils.CertPEM(root.Cert), Trust: pb.Trust_Public})
	require.NoError(t, err)
	assert.Equal(t, "77", res.ID)
	assert.Equal(t, "1", res.OrgID)
	assert.Equal(t, pb.Trust_Public, res.Trust)
	assert.Equal(t, rootPEM, res.Pem)
	evt := tca.events.last(pb.EventType_RootRegistered)
	require.NotNil(t, evt)
	assert.Equal(t, uint64(77), evt.ReferenceID.UInt64())
	assert.Equal(t, uint64(1), evt.OrgID.UInt64())

	tca.cadb.EXPECT().RegisterRoot(gomock.Any(), gomock.Any()).Return(nil, errors.WithStack(db.ErrRootConflict))
	_, err = svc.RegisterRoot(ctx, &privpb.RegisterRootRequest{Pem: testutils.CertPEM(root.Cert)})
	assert.EqualError(t, err, "conflict: certificate is registered in another scope")
	tca.cadb.EXPECT().RegisterRoot(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.RegisterRoot(ctx, &privpb.RegisterRootRequest{Pem: testutils.CertPEM(root.Cert)})
	assert.EqualError(t, err, "unexpected: failed to register root")
}

func TestService_ListRoots(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	svc := tca.service()
	ctx := testCtx("42", "1")
	anchor := &model.RootCertificate{
		ID:      xdb.NewID(77),
		OrgID:   testOrgID(),
		Skid:    tca.root.Skid,
		Subject: tca.root.Subject,
		Trust:   pb.Trust_Private,
		Pem:     tca.root.Pem,
	}

	_, err := svc.ListRoots(ctx, nil)
	assert.EqualError(t, err, "bad_request: missing request")
	_, err = svc.ListRoots(ctx, &privpb.ListRootsRequest{Cursor: "zzz"})
	assert.EqualError(t, err, "bad_request: invalid cursor")
	_, err = svc.ListRoots(testCtx("42", ""), &privpb.ListRootsRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")

	// a tenant lists the anchors of its org
	tca.cadb.EXPECT().ListRoots(gomock.Any(), &query.ListRootsRequest{OrgID: 1, Limit: defaultListLimit}).
		Return(&model.RootCertificateResult{Rows: []*model.RootCertificate{anchor}}, nil)
	res, err := svc.ListRoots(ctx, &privpb.ListRootsRequest{})
	require.NoError(t, err)
	require.Len(t, res.Roots, 1)
	assert.Equal(t, "77", res.Roots[0].ID)
	assert.Equal(t, tca.root.Skid, res.Roots[0].SKID)
	assert.Nil(t, res.NextPage)

	// a service caller lists the platform anchors, or names an org
	svcCaller := serviceCtx("trustyca-admin")
	tca.cadb.EXPECT().ListRoots(gomock.Any(), &query.ListRootsRequest{Platform: true, Limit: 10, Offset: 20}).
		Return(&model.RootCertificateResult{}, nil)
	res, err = svc.ListRoots(svcCaller, &privpb.ListRootsRequest{Limit: 10, Offset: 20})
	require.NoError(t, err)
	assert.Empty(t, res.Roots)
	tca.orgsdb.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	tca.cadb.EXPECT().ListRoots(gomock.Any(), &query.ListRootsRequest{OrgID: 1, Limit: defaultListLimit}).
		Return(&model.RootCertificateResult{}, nil)
	_, err = svc.ListRoots(svcCaller, &privpb.ListRootsRequest{OrgID: "1"})
	require.NoError(t, err)

	tca.cadb.EXPECT().ListRoots(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
	_, err = svc.ListRoots(ctx, &privpb.ListRootsRequest{})
	assert.EqualError(t, err, "unexpected: failed to list roots")
}
