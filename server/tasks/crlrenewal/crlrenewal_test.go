package crlrenewal_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/server/tasks/crlrenewal"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	testDPSeed    = "crlrenewal-test-seed"
	testRootLabel = "ROOT"
)

// testCA is a root issuer of org 1 served by the mock DB, with the CRL the
// publisher stores and the events the task records
type testCA struct {
	mu       sync.Mutex
	cadb     *mocktrustycadb.MockCaDb
	orgsdb   *mocktrustycadb.MockOrgsDb
	registry *core.Registry
	root     *model.Issuer
	crl      *model.Crl
	events   []*model.Event
	// listErr fails the issuer listing when set
	listErr error
}

// newTestCA creates the root with the inmem provider and makes the mock DB
// serve it, as the registry and the publisher read and write it
func newTestCA(t *testing.T, ctrl *gomock.Controller) *testCA {
	t.Helper()
	prov := inmemcrypto.NewProvider()
	crypto, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)
	dp, err := dataprotection.NewSymmetric([]byte(testDPSeed))
	require.NoError(t, err)
	keys := core.NewKeys(crypto, dp)
	profile, err := core.ProfileFromPb(&pb.CertProfile{
		Label:       testRootLabel,
		IssuerLabel: model.AnyIssuerLabel,
		Expiry:      "8760h",
		Backdate:    "30m",
		Usages:      []string{"cert sign", "crl sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: -1,
		},
	})
	require.NoError(t, err)
	root, err := keys.NewRootIssuer(context.Background(), &core.IssuerRequest{
		OrgID:    xdb.NewID(1),
		Label:    testRootLabel,
		Type:     pb.AuthorityType_Root,
		Subject:  &csr.X509Subject{CommonName: "Task Root"},
		Provider: prov,
	}, testRootLabel, profile)
	require.NoError(t, err)
	root.ID = xdb.NewID(10)
	root.CreatedAt = xdb.UTC(time.Now())
	root.UpdatedAt = root.CreatedAt

	tca := &testCA{
		cadb:   mocktrustycadb.NewMockCaDb(ctrl),
		orgsdb: mocktrustycadb.NewMockOrgsDb(ctrl),
		root:   root,
	}
	tca.registry = core.NewRegistry(tca.cadb, keys, core.Options{})
	tca.cadb.EXPECT().ListIssuers(gomock.Any(), gomock.Any()).DoAndReturn(tca.listIssuers).AnyTimes()
	tca.cadb.EXPECT().GetIssuer(gomock.Any(), root.ID.UInt64()).DoAndReturn(tca.getIssuer).AnyTimes()
	tca.cadb.EXPECT().GetCrl(gomock.Any(), root.Skid).DoAndReturn(tca.getCrl).AnyTimes()
	tca.cadb.EXPECT().GetCrls(gomock.Any(), []string{root.Skid}).DoAndReturn(tca.getCrls).AnyTimes()
	tca.cadb.EXPECT().ListRevoked(gomock.Any(), gomock.Any()).Return(&model.RevokedResult{}, nil).AnyTimes()
	tca.cadb.EXPECT().PublishCrl(gomock.Any(), gomock.Any()).DoAndReturn(tca.publishCrl).AnyTimes()
	tca.orgsdb.EXPECT().TryCreateEvent(gomock.Any()).Do(tca.record).AnyTimes()
	return tca
}

func (tca *testCA) listIssuers(_ context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
	tca.mu.Lock()
	defer tca.mu.Unlock()
	if tca.listErr != nil {
		return nil, tca.listErr
	}
	res := &model.IssuerResult{}
	if req.AllOrgs && req.Status == pb.IssuerStatus_Active {
		row := *tca.root
		res.Rows = []*model.Issuer{&row}
	}
	return res, nil
}

func (tca *testCA) getIssuer(context.Context, uint64) (*model.Issuer, error) {
	tca.mu.Lock()
	defer tca.mu.Unlock()
	row := *tca.root
	return &row, nil
}

func (tca *testCA) getCrl(_ context.Context, ikid string) (*model.Crl, error) {
	tca.mu.Lock()
	defer tca.mu.Unlock()
	if tca.crl == nil {
		return nil, xdb.CheckNotFoundError(sql.ErrNoRows, "crl", ikid)
	}
	res := *tca.crl
	return &res, nil
}

func (tca *testCA) getCrls(_ context.Context, _ []string) ([]*model.Crl, error) {
	tca.mu.Lock()
	defer tca.mu.Unlock()
	if tca.crl == nil {
		return nil, nil
	}
	res := *tca.crl
	return []*model.Crl{&res}, nil
}

func (tca *testCA) publishCrl(_ context.Context, m *model.Crl) (*model.Crl, error) {
	tca.mu.Lock()
	defer tca.mu.Unlock()
	if m.CrlNumber <= tca.root.CrlNumber {
		return nil, errors.WithStack(db.ErrStaleCrlNumber)
	}
	tca.root.CrlNumber = m.CrlNumber
	res := *m
	res.ID = xdb.NewID(77)
	tca.crl = &res
	out := res
	return &out, nil
}

func (tca *testCA) record(evt *model.Event) {
	tca.mu.Lock()
	defer tca.mu.Unlock()
	tca.events = append(tca.events, evt)
}

func (tca *testCA) lastEvent() *model.Event {
	tca.mu.Lock()
	defer tca.mu.Unlock()
	if len(tca.events) == 0 {
		return nil
	}
	return tca.events[len(tca.events)-1]
}

func TestTask_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	ctx := context.Background()
	task := crlrenewal.New(crlrenewal.TaskName, "every 10 minutes", core.NewCrlPublisher(tca.cadb, tca.registry), tca.orgsdb)

	// the first run publishes the missing CRL and records the event
	res, err := task.Run(ctx)
	require.NoError(t, err)
	require.Zero(t, res.Failed)
	require.Zero(t, res.Skipped)
	require.Len(t, res.Crls, 1)
	assert.EqualValues(t, 1, res.Crls[0].CrlNumber)
	assert.Equal(t, tca.root.Skid, res.Crls[0].Ikid)
	evt := tca.lastEvent()
	require.NotNil(t, evt)
	assert.Equal(t, pb.EventType_CrlPublished, evt.Type)
	assert.Equal(t, crlrenewal.TaskName, evt.Source.String())
	assert.Equal(t, "1", evt.OrgID.String())
	assert.Equal(t, "77", evt.ReferenceID.String())
	assert.Empty(t, evt.Email.String(), "no actor")
	assert.Equal(t, `CRL 1 of issuer "`+tca.root.Subject+`" published`, evt.Description.String())

	// the next run finds the CRL fresh
	res, err = task.Run(ctx)
	require.NoError(t, err)
	assert.Empty(t, res.Crls)
	assert.Equal(t, 1, res.Skipped)
	assert.Len(t, tca.events, 1)

	// a listing failure is returned
	tca.mu.Lock()
	tca.listErr = errors.New("db down")
	tca.mu.Unlock()
	_, err = task.Run(ctx)
	assert.EqualError(t, err, "unable to list issuers: db down")
}

func TestFactory(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	tca := newTestCA(t, ctrl)
	scheduler := tasks.NewScheduler()

	fact, ok := crlrenewal.Factory(scheduler, crlrenewal.TaskName, "every 10 minutes").(func(db.CaDb, db.OrgsDb, *core.Registry) error)
	require.True(t, ok)
	require.NoError(t, fact(tca.cadb, tca.orgsdb, tca.registry))
	require.Equal(t, 1, scheduler.Count())
	// the task runs at once when scheduled
	require.Eventually(t, func() bool {
		list := scheduler.List()
		return len(list) == 1 && list[0].RunCount() == 1 && !list[0].IsRunning()
	}, 10*time.Second, 10*time.Millisecond)
	assert.NotNil(t, tca.lastEvent(), "the first run published")
	assert.Equal(t, 10*time.Minute, scheduler.List()[0].Schedule().NextRunAt.Sub(*scheduler.List()[0].Schedule().LastRunAt).Round(time.Minute))

	bad, ok := crlrenewal.Factory(scheduler, crlrenewal.TaskName, "never").(func(db.CaDb, db.OrgsDb, *core.Registry) error)
	require.True(t, ok)
	err := bad(tca.cadb, tca.orgsdb, tca.registry)
	assert.ErrorContains(t, err, `unable to schedule task "crl_renewal": never`)
	assert.Equal(t, 1, scheduler.Count())
}
