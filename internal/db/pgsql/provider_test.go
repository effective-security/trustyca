package pgsql_test

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/x/flake"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	provider db.Provider
	ctx      = context.Background()
)

func TestMain(m *testing.M) {
	xlog.SetGlobalLogLevel(xlog.TRACE)

	// var err error
	// grunner, err = dbrunner.New(nil)
	// if err != nil {
	// 	panic(err)
	// }
	// provider = grunner.Provider

	cfg, err := testutils.LoadConfig("UNIT_TEST")
	if err != nil {
		panic(err)
	}

	provider, err = db.New(
		cfg.SQL.DataSource,
		cfg.SQL.MigrationsDir,
		0, 0,
		flake.DefaultIDGenerator,
	)
	if err != nil {
		panic(err)
	}

	// Run the tests
	rc := m.Run()

	// // NOTE: os.Exit does not respect defer
	// grunner.Close()
	_ = provider.Close()

	os.Exit(rc)
}

// setupOwnerAndOrg sets up an owner and an org for testing.
// The owner is a user who is logged in and the org is an org that the owner has created.
// The owner and org are returned for use in the test.
// The owner and org are cleaned up after the test.
func setupOwnerAndOrg(t *testing.T, namePrefix string) (*model.User, *model.Org) {
	t.Helper()
	ownerID := provider.NextID()
	login := &model.Login{
		ID:         ownerID,
		ExternalID: ownerID.String(),
		Name:       namePrefix + " Owner",
		Email:      ownerID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, owner, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := provider.DeleteUserByEmail(ctx, login.Email)
		assert.NoError(t, err)
	})

	org := &model.Org{Name: namePrefix + " Org"}
	org, err = provider.RegisterOrg(ctx, org, owner.ID.UInt64())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := provider.DeleteOrg(ctx, org.ID.UInt64())
		assert.NoError(t, err)
	})

	return owner, org
}

func TestCheckErrIDConflict(t *testing.T) {
	tw := bytes.Buffer{}
	writer := bufio.NewWriter(&tw)
	xlog.SetFormatter(xlog.NewStringFormatter(writer))

	p := provider.(*pgsql.Provider)
	id := p.NextID()
	p.CheckErrIDConflict(context.Background(), errors.New("duplicate key value violates unique constraint \"users_pkey\""), id.UInt64())

	writer.Flush()
	log := tw.String()
	assert.Contains(t, log, `func=CheckErrIDConflict reason=duplicate_key`)
	assert.Contains(t, log, `caller="TestCheckErrIDConflict [provider_test.go:`)
}

func Test_ListTables(t *testing.T) {
	expectedTables := []string{
		"event",
		"invite",
		"login",
		"membership",
		"org",
		"schema_migrations",
		"user",
	}

	require.NotNil(t, provider)
	require.NotNil(t, provider.DB())
	res, err := provider.QueryContext(ctx, `
	SELECT
		tablename
	FROM
		pg_catalog.pg_tables
	;`)
	require.NoError(t, err)
	defer res.Close()

	var tables []string
	var table string
	for res.Next() {
		err = res.Scan(&table)
		require.NoError(t, err)
		if !strings.HasPrefix(table, "sql_") && !strings.HasPrefix(table, "pg_") {
			tables = append(tables, table)
		}
	}
	sort.Strings(tables)
	assert.Equal(t, expectedTables, tables)
}

func slowMethod() {
	defer pgsql.DbMeasureSince(time.Now())
	time.Sleep(time.Millisecond * time.Duration(pgsql.DbSlowMethodMilliseconds+1))
}

func Test_DbMeasureSince(t *testing.T) {
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)
	xlog.SetPackageLogLevel("github.com/effective-security/trustyca/internal/db", "pgsql", xlog.DEBUG)
	xlog.SetFormatter(xlog.NewStringFormatter(writer).Options(xlog.FormatSkipTime(true)))

	slowMethod()

	pgsql.DbMeasureQuerySince("GetXXX_1_2", time.Now())
	pgsql.DbMeasureQuerySince("ListYYY", time.Now())

	writer.Flush()
	assert.Contains(t, b.String(), "level=D pkg=pgsql func=DbMeasureQuerySince reason=slow db=trustycadb query=slowMethod ms=")
}
