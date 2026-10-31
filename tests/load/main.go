package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/pkg/flake"
	"github.com/lib/pq"
)

// The defaults of the local stack (Makefile start-sql)
const (
	defaultAdminDSN  = "postgres://postgres:postgres@localhost:55432/postgres?sslmode=disable"
	defaultAppDSN    = "postgres://trustyca:trustyca%3Flocal%23%26@localhost:55432/?sslmode=disable&dbname="
	defaultDB        = "trustycadb_load"
	defaultMigration = "sql/trustycadb/migrations"
	schemaName       = "trustyca"
	// loadDBPrefix is the prefix every load database name must carry: the
	// tool creates, fills, updates and drops its database, and never
	// touches the service's
	loadDBPrefix = "trustycadb_load"
)

// The shape of the synthetic data
const (
	validity      = 180 * 24 * time.Hour
	issuedWithin  = 365 * 24 * time.Hour
	pageSize      = 100
	crlPageSize   = 1000
	taskBatchSize = 1000
	// the org with the share of the rows that bigOrgShare names
	bigOrg = 1
)

var profiles = []string{"server", "client", "peer", "ocsp"}

type options struct {
	adminDSN     string
	appDSN       string
	dbName       string
	migrations   string
	rows         int
	orgs         int
	projects     int
	issuers      int
	batch        int
	revokedEvery int
	bigOrgShare  float64
	load         bool
	explain      bool
	sign         int
	drop         bool
	out          string
	fillfactor   int
}

func main() {
	var o options
	flag.StringVar(&o.adminDSN, "admin-dsn", defaultAdminDSN, "the superuser connection that creates the database")
	flag.StringVar(&o.appDSN, "app-dsn", "", "the connection of the service role to the load database; the dev one by default")
	flag.StringVar(&o.dbName, "db", defaultDB, "the name of the load database")
	flag.StringVar(&o.migrations, "migrations", defaultMigration, "the migrations directory")
	flag.IntVar(&o.rows, "rows", 10_000_000, "the number of certificate rows to load")
	flag.IntVar(&o.orgs, "orgs", 200, "the number of orgs the rows spread over")
	flag.IntVar(&o.projects, "projects", 5, "the number of projects per org; a fifth of the rows are org-wide")
	flag.IntVar(&o.issuers, "issuers", 2, "the number of issuers per org")
	flag.IntVar(&o.batch, "batch", 20_000, "the rows per COPY transaction")
	flag.IntVar(&o.revokedEvery, "revoked-every", 100, "every Nth certificate is revoked")
	flag.Float64Var(&o.bigOrgShare, "big-org-share", 0.2, "the share of the rows of the biggest org")
	flag.BoolVar(&o.load, "load", false, "load the rows")
	flag.BoolVar(&o.explain, "explain", false, "run the queries with EXPLAIN (ANALYZE, BUFFERS)")
	flag.IntVar(&o.sign, "sign", 0, "register this many certificates through the provider, as SignCertificate does")
	flag.BoolVar(&o.drop, "drop", false, "drop the load database and exit")
	flag.StringVar(&o.out, "out", "", "write the report to the file as well")
	flag.IntVar(&o.fillfactor, "fillfactor", 0, "set the fillfactor of the certificate table before the load; 0 keeps the default")
	flag.Parse()
	if o.appDSN == "" {
		o.appDSN = defaultAppDSN + o.dbName
	}

	if err := o.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(2)
	}
	if err := run(&o); err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
}

// validate refuses the options the tool cannot run with, before any
// connection is opened: a database that is not a load database, and the
// sizes the generator and the loader divide by or index with
func (o *options) validate() error {
	if !strings.HasPrefix(o.dbName, loadDBPrefix) {
		return errors.Errorf("the load database must be named %s*: %q is not disposable", loadDBPrefix, o.dbName)
	}
	appDB, err := databaseOf(o.appDSN)
	if err != nil {
		return errors.WithMessage(err, "invalid -app-dsn")
	}
	if appDB != o.dbName {
		return errors.Errorf("-app-dsn connects to %q, not to the load database %q", appDB, o.dbName)
	}
	if o.rows < 0 || o.sign < 0 || o.revokedEvery < 0 {
		return errors.New("-rows, -sign and -revoked-every are not negative")
	}
	if o.batch <= 0 || o.orgs <= 0 || o.projects <= 0 || o.issuers <= 0 {
		return errors.New("-batch, -orgs, -projects and -issuers are positive")
	}
	if o.bigOrgShare < 0 || o.bigOrgShare > 1 {
		return errors.New("-big-org-share is between 0 and 1")
	}
	if o.fillfactor < 0 || o.fillfactor > 100 {
		return errors.New("-fillfactor is between 0 and 100")
	}
	return nil
}

// databaseOf returns the database a connection URL names, in its path or
// its dbname option
func databaseOf(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	if name := u.Query().Get("dbname"); name != "" {
		return name, nil
	}
	return strings.TrimPrefix(u.Path, "/"), nil
}

// withDatabase returns the connection URL with the database replaced,
// keeping the credentials, the host and the options
func withDatabase(dsn, name string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	q := u.Query()
	if q.Has("dbname") {
		q.Set("dbname", name)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// checkDatabase verifies that the connection is to the database, before
// anything is created, written or dropped through it
func checkDatabase(ctx context.Context, sqlDB *sql.DB, name string) error {
	var current string
	err := sqlDB.QueryRowContext(ctx, "SELECT current_database()").Scan(&current)
	if err != nil {
		return errors.WithMessage(err, "unable to query the current database")
	}
	if current != name {
		return errors.Errorf("connected to %q, not to the load database %q", current, name)
	}
	return nil
}

func run(o *options) error {
	ctx := context.Background()
	if o.drop {
		return dropDatabase(ctx, o)
	}
	var w io.Writer = os.Stdout
	var f *os.File
	if o.out != "" {
		var err error
		f, err = os.Create(o.out)
		if err != nil {
			return errors.WithMessage(err, "unable to create the report")
		}
		w = io.MultiWriter(os.Stdout, f)
	}
	r := &report{w: w}
	err := runPhases(ctx, o, r)
	if err == nil {
		err = r.err
	}
	if f != nil {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = errors.WithMessage(cerr, "unable to write the report")
		}
	}
	return err
}

// runPhases creates the database and runs the phases the options select
func runPhases(ctx context.Context, o *options, r *report) error {
	err := ensureDatabase(ctx, o)
	if err != nil {
		return err
	}
	sqlDB, err := sql.Open("postgres", o.appDSN)
	if err != nil {
		return errors.WithMessage(err, "unable to open the load database")
	}
	defer sqlDB.Close()
	err = checkDatabase(ctx, sqlDB, o.dbName)
	if err != nil {
		return err
	}
	provider, err := db.New(o.appDSN, o.migrations, 0, 0, flake.DefaultIDGenerator)
	if err != nil {
		return errors.WithMessage(err, "unable to open the load database")
	}
	defer provider.Close()

	if o.load {
		err = load(ctx, sqlDB, o, r)
		if err != nil {
			return err
		}
	}
	if o.explain {
		err = explain(ctx, sqlDB, provider, o, r)
		if err != nil {
			return err
		}
	}
	if o.sign > 0 {
		err = signBench(ctx, sqlDB, provider, o, r)
		if err != nil {
			return err
		}
	}
	return nil
}

// ensureDatabase creates the load database, owned by the service role,
// when it does not exist
func ensureDatabase(ctx context.Context, o *options) error {
	admin, err := sql.Open("postgres", o.adminDSN)
	if err != nil {
		return errors.WithMessage(err, "unable to open the admin connection")
	}
	defer admin.Close()
	var exists bool
	err = admin.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", o.dbName).Scan(&exists)
	if err != nil {
		return errors.WithMessage(err, "unable to query databases")
	}
	if exists {
		return nil
	}
	_, err = admin.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s WITH OWNER = trustyca ENCODING = 'UTF8' TEMPLATE template0", pq.QuoteIdentifier(o.dbName)))
	if err != nil {
		return errors.WithMessage(err, "unable to create the load database")
	}
	// the schema exists before the migrations run, as create_local_db.sql
	// does for the dev database: the migration runner keeps its version
	// table in the current schema, which is the role's search_path head
	// once the schema exists
	loadDSN, err := withDatabase(o.adminDSN, o.dbName)
	if err != nil {
		return errors.WithMessage(err, "invalid -admin-dsn")
	}
	appAdmin, err := sql.Open("postgres", loadDSN)
	if err != nil {
		return errors.WithMessage(err, "unable to open the load database")
	}
	defer appAdmin.Close()
	err = checkDatabase(ctx, appAdmin, o.dbName)
	if err != nil {
		return err
	}
	for _, stmt := range []string{
		"CREATE SCHEMA IF NOT EXISTS " + schemaName + " AUTHORIZATION trustyca",
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
		"GRANT ALL ON SCHEMA " + schemaName + " TO trustyca",
		"GRANT USAGE ON SCHEMA public TO trustyca",
	} {
		_, err = appAdmin.ExecContext(ctx, stmt)
		if err != nil {
			return errors.WithMessagef(err, "unable to prepare the load database: %s", stmt)
		}
	}
	fmt.Printf("created database %s\n", o.dbName)
	return nil
}

// dropDatabase drops the load database
func dropDatabase(ctx context.Context, o *options) error {
	admin, err := sql.Open("postgres", o.adminDSN)
	if err != nil {
		return errors.WithMessage(err, "unable to open the admin connection")
	}
	defer admin.Close()
	_, err = admin.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", pq.QuoteIdentifier(o.dbName)))
	if err != nil {
		return errors.WithMessage(err, "unable to drop the load database")
	}
	fmt.Printf("dropped database %s\n", o.dbName)
	return nil
}

// synthetic is the generator of the rows: the IDs grow, as flake IDs do,
// the orgs and issuers repeat, and every key signs a few certificates
type synthetic struct {
	o        *options
	rnd      *mrand.Rand
	now      time.Time
	pem      string
	issuers  []string // the IKID of each issuer, orgs*issuers
	subjects []string
}

func newSynthetic(o *options) *synthetic {
	s := &synthetic{
		o:   o,
		rnd: mrand.New(mrand.NewPCG(7, 11)),
		now: time.Now().UTC().Truncate(time.Second),
		pem: samplePEM(),
	}
	for org := 1; org <= o.orgs; org++ {
		for i := range o.issuers {
			s.issuers = append(s.issuers, hexOf(sha1.New(), fmt.Sprintf("issuer-%d-%d", org, i), 40))
		}
	}
	return s
}

// orgOf picks the org of a row: the big org gets its share, the others
// share the rest evenly
func (s *synthetic) orgOf() int {
	if s.rnd.Float64() < s.o.bigOrgShare {
		return bigOrg
	}
	return 1 + s.rnd.IntN(s.o.orgs)
}

type certRow struct {
	id        int64
	orgID     int64
	projectID sql.NullInt64
	skid      string
	ikid      string
	serial    string
	notBefore time.Time
	notAfter  time.Time
	subject   string
	issuer    string
	sha256    string
	profile   string
	status    int
	revoked   bool
}

func (s *synthetic) row(i int) certRow {
	org := s.orgOf()
	issuerIdx := (org-1)*s.o.issuers + s.rnd.IntN(s.o.issuers)
	notBefore := s.now.Add(-time.Duration(s.rnd.Int64N(int64(issuedWithin))))
	r := certRow{
		id:        int64(1<<40) + int64(i),
		orgID:     int64(org),
		skid:      hexOf(sha1.New(), fmt.Sprintf("key-%d", i/3), 40),
		ikid:      s.issuers[issuerIdx],
		serial:    hexOf(sha256.New(), fmt.Sprintf("serial-%d", i), 32),
		notBefore: notBefore,
		notAfter:  notBefore.Add(validity),
		subject:   fmt.Sprintf("CN=host-%d.example.com", i),
		issuer:    fmt.Sprintf("CN=Issuing CA %d", issuerIdx),
		sha256:    hexOf(sha256.New(), fmt.Sprintf("cert-%d", i), 64),
		profile:   profiles[s.rnd.IntN(len(profiles))],
		status:    int(pb.CertificateStatus_Active),
	}
	if s.rnd.IntN(5) != 0 {
		r.projectID = sql.NullInt64{Int64: int64(org*100 + 1 + s.rnd.IntN(s.o.projects)), Valid: true}
	}
	if s.o.revokedEvery > 0 && i%s.o.revokedEvery == 0 {
		r.revoked = true
		r.status = int(pb.CertificateStatus_Revoked)
	}
	return r
}

// load copies the rows in batches, then analyzes the tables
func load(ctx context.Context, sqlDB *sql.DB, o *options, r *report) error {
	s := newSynthetic(o)
	r.section("Load")
	r.printf("rows=%d orgs=%d projects/org=%d issuers/org=%d big org share=%.2f revoked every %d fillfactor=%d\n", o.rows, o.orgs, o.projects, o.issuers, o.bigOrgShare, o.revokedEvery, o.fillfactor)
	if o.fillfactor > 0 {
		_, err := sqlDB.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s.certificate SET (fillfactor = %d)", schemaName, o.fillfactor))
		if err != nil {
			return errors.WithMessage(err, "unable to set the fillfactor")
		}
	}
	start := time.Now()
	for from := 0; from < o.rows; from += o.batch {
		to := min(from+o.batch, o.rows)
		err := copyBatch(ctx, sqlDB, s, from, to)
		if err != nil {
			return errors.WithMessagef(err, "batch %d", from)
		}
		if (to/o.batch)%25 == 0 || to == o.rows {
			elapsed := time.Since(start)
			r.printf("  %d rows in %s (%.0f rows/s)\n", to, elapsed.Round(time.Second), float64(to)/elapsed.Seconds())
		}
	}
	// a vacuum sets the visibility map of the loaded pages, which the
	// index-only scans of the counts rely on (autovacuum covers part of the
	// table during the load); without parallel workers, since the shared
	// memory of the dev container cannot hold theirs
	for _, table := range []string{"certificate", "revoked"} {
		_, err := sqlDB.ExecContext(ctx, "VACUUM (ANALYZE, PARALLEL 0) "+schemaName+"."+table)
		if err != nil {
			return errors.WithMessagef(err, "unable to vacuum %s", table)
		}
	}
	r.printf("loaded in %s\n", time.Since(start).Round(time.Second))
	return sizes(ctx, sqlDB, r)
}

func copyBatch(ctx context.Context, sqlDB *sql.DB, s *synthetic, from, to int) error {
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	certs, err := tx.PrepareContext(ctx, copyFrom("certificate",
		"id", "org_id", "project_id", "skid", "ikid", "serial_number", "not_before", "not_after",
		"subject", "issuer", "sha256", "profile", "label", "locations", "metadata", "pem", "issuers_pem", "status", "created_at"))
	if err != nil {
		return err
	}
	var revoked []certRow
	for i := from; i < to; i++ {
		row := s.row(i)
		_, err = certs.ExecContext(ctx, row.id, row.orgID, row.projectID, row.skid, row.ikid, row.serial, row.notBefore, row.notAfter,
			row.subject, row.issuer, row.sha256, row.profile, "", "{}", "{}", s.pem, "", row.status, row.notBefore)
		if err != nil {
			return err
		}
		if row.revoked {
			revoked = append(revoked, row)
		}
	}
	_, err = certs.ExecContext(ctx)
	if err != nil {
		return err
	}
	err = certs.Close()
	if err != nil {
		return err
	}
	if len(revoked) > 0 {
		rev, err := tx.PrepareContext(ctx, copyFrom("revoked",
			"id", "org_id", "project_id", "certificate_id", "ikid", "serial_number", "not_after", "revoked_at", "reason", "reason_text"))
		if err != nil {
			return err
		}
		for _, row := range revoked {
			_, err = rev.ExecContext(ctx, row.id+int64(1<<41), row.orgID, row.projectID, row.id, row.ikid, row.serial, row.notAfter,
				row.notBefore.Add(time.Hour), int(pb.ReasonCode_Superseded), "")
			if err != nil {
				return err
			}
		}
		_, err = rev.ExecContext(ctx)
		if err != nil {
			return err
		}
		err = rev.Close()
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// copyFrom is the COPY statement of the table that the driver prepares for
// a bulk load
func copyFrom(table string, columns ...string) string {
	return "COPY " + schemaName + "." + table + " (" + strings.Join(columns, ", ") + ") FROM STDIN"
}

// sizes reports the table and index sizes
func sizes(ctx context.Context, sqlDB *sql.DB, r *report) error {
	rows, err := sqlDB.QueryContext(ctx, `
SELECT c.relname, pg_size_pretty(pg_relation_size(c.oid)), c.reltuples::bigint
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relkind IN ('r', 'i') AND (c.relname LIKE '%certificate%' OR c.relname LIKE '%revoked%')
ORDER BY c.relname`, schemaName)
	if err != nil {
		return errors.WithMessage(err, "unable to query sizes")
	}
	defer rows.Close()
	r.section("Sizes")
	r.printf("| relation | size | rows |\n|---|---|---|\n")
	for rows.Next() {
		var name, size string
		var tuples int64
		if err := rows.Scan(&name, &size, &tuples); err != nil {
			return err
		}
		r.printf("| %s | %s | %d |\n", name, size, tuples)
	}
	return rows.Err()
}

// explain runs every query of the CA at this volume through the provider,
// for the wall time of the service, and through EXPLAIN (ANALYZE, BUFFERS),
// for the plan
func explain(ctx context.Context, sqlDB *sql.DB, provider db.Provider, o *options, r *report) error {
	s := newSynthetic(o)
	bigIKID := s.issuers[(bigOrg-1)*o.issuers]
	smallOrg := int64(o.orgs)
	smallIKID := s.issuers[(o.orgs-1)*o.issuers]
	expiring := s.now.Add(30 * 24 * time.Hour)

	// a row of the big org and one of a small org, for the lookups
	var sample, smallSample certRow
	err := sqlDB.QueryRowContext(ctx, "SELECT id, skid, ikid, serial_number, sha256 FROM "+schemaName+".certificate WHERE org_id = $1 ORDER BY id DESC LIMIT 1 OFFSET 1000", bigOrg).
		Scan(&sample.id, &sample.skid, &sample.ikid, &sample.serial, &sample.sha256)
	if err != nil {
		return errors.WithMessage(err, "unable to read a sample row: load the rows first")
	}
	err = sqlDB.QueryRowContext(ctx, "SELECT id, skid, ikid, serial_number, sha256 FROM "+schemaName+".certificate WHERE org_id = $1 ORDER BY id DESC LIMIT 1 OFFSET 10", smallOrg).
		Scan(&smallSample.id, &smallSample.skid, &smallSample.ikid, &smallSample.serial, &smallSample.sha256)
	if err != nil {
		return errors.WithMessage(err, "unable to read a sample row of a small org")
	}
	// a tiny org: the worst case of a list that scans the table backwards
	// for the rows of an org
	tinyOrg := int64(o.orgs + 1000)
	for i := range 10 {
		row := s.row(i)
		_, err = sqlDB.ExecContext(ctx, "INSERT INTO "+schemaName+".certificate (id, org_id, skid, ikid, serial_number, not_before, not_after, subject, issuer, sha256, profile, pem, issuers_pem, status) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, '', $13) ON CONFLICT DO NOTHING",
			int64(1<<42)+int64(i), tinyOrg, row.skid+"t", smallIKID, row.serial+"t", row.notBefore, row.notAfter, row.subject, row.issuer, row.sha256[:60]+"tiny", row.profile, s.pem, row.status)
		if err != nil {
			return errors.WithMessage(err, "unable to insert the tiny org")
		}
	}
	cursorAt := query.EncodeCursor(xdb.NewID(uint64(sample.id)))
	cursor, err := query.ParseCursor(cursorAt)
	if err != nil {
		return err
	}
	bigProject := uint64(bigOrg*100 + 1)

	type listCase struct {
		name string
		req  *query.ListCertificatesRequest
	}
	lists := []listCase{
		{"big org, first page", &query.ListCertificatesRequest{OrgID: bigOrg, Limit: pageSize}},
		{"big org, cursor page (1000 rows in)", &query.ListCertificatesRequest{OrgID: bigOrg, Limit: pageSize, Cursor: cursor}},
		{"big org, offset page 10000", &query.ListCertificatesRequest{OrgID: bigOrg, Limit: pageSize, Offset: 10000}},
		{"big org, project, first page", &query.ListCertificatesRequest{OrgID: bigOrg, ProjectID: bigProject, Limit: pageSize}},
		{"big org, org scope only", &query.ListCertificatesRequest{OrgID: bigOrg, Scope: pb.Scope_Org, Limit: pageSize}},
		{"big org, visible projects", &query.ListCertificatesRequest{OrgID: bigOrg, ProjectIDs: []uint64{bigProject, bigProject + 1}, Limit: pageSize}},
		{"big org, status Revoked", &query.ListCertificatesRequest{OrgID: bigOrg, Status: pb.CertificateStatus_Revoked, Limit: pageSize}},
		{"big org, profile", &query.ListCertificatesRequest{OrgID: bigOrg, Profile: profiles[0], Limit: pageSize}},
		{"big org, expiring within 30 days", &query.ListCertificatesRequest{OrgID: bigOrg, ExpiringBefore: &expiring, Limit: pageSize}},
		{"big org, by issuer", &query.ListCertificatesRequest{OrgID: bigOrg, IKID: bigIKID, Limit: pageSize}},
		{"big org, by issuer, cursor page", &query.ListCertificatesRequest{OrgID: bigOrg, IKID: bigIKID, Limit: pageSize, Cursor: cursor}},
		{"small org, first page", &query.ListCertificatesRequest{OrgID: uint64(smallOrg), Limit: pageSize}},
		{"small org, by issuer", &query.ListCertificatesRequest{OrgID: uint64(smallOrg), IKID: smallIKID, Limit: pageSize}},
		{"tiny org (10 rows), first page", &query.ListCertificatesRequest{OrgID: uint64(tinyOrg), Limit: pageSize}},
		{"tiny org, by issuer", &query.ListCertificatesRequest{OrgID: uint64(tinyOrg), IKID: smallIKID, Limit: pageSize}},
		{"CIS: newest of a key, every org", &query.ListCertificatesRequest{AllOrgs: true, SKID: sample.skid, Limit: 1}},
		{"support: every org, by issuer", &query.ListCertificatesRequest{AllOrgs: true, IKID: smallIKID, Limit: pageSize}},
		{"small org, by issuer of another org", &query.ListCertificatesRequest{OrgID: uint64(smallOrg), IKID: bigIKID, Limit: pageSize}},
		{"support: every org, status Active", &query.ListCertificatesRequest{AllOrgs: true, Status: pb.CertificateStatus_Active, Limit: pageSize}},
	}
	r.section("ListCertificates")
	for _, c := range lists {
		qp := c.req.QueryParams()
		q, _ := query.ListCertificates(qp)
		elapsed, err := timeIt(3, func() error {
			_, err := provider.ListCertificates(ctx, c.req)
			return err
		})
		if err != nil {
			return errors.WithMessagef(err, "%s", c.name)
		}
		err = r.plan(ctx, sqlDB, c.name, elapsed, q, qp.Args())
		if err != nil {
			return err
		}
	}

	// the counts of the tenant summary: every status of a scope in one
	// statement, and the Active certificates expiring within each of the
	// three periods, served by (org_id, project_id, status, not_after)
	r.section("Summary counts (CountCertificates)")
	summaryPeriods := []time.Duration{7 * 24 * time.Hour, 30 * 24 * time.Hour, 90 * 24 * time.Hour}
	summaries := []struct {
		name string
		req  *query.CountCertificatesRequest
	}{
		{"big org", &query.CountCertificatesRequest{OrgID: bigOrg}},
		{"big org, project", &query.CountCertificatesRequest{OrgID: bigOrg, ProjectID: bigProject}},
		{"big org, visible projects", &query.CountCertificatesRequest{OrgID: bigOrg, ProjectIDs: []uint64{bigProject, bigProject + 1}}},
		{"small org", &query.CountCertificatesRequest{OrgID: uint64(smallOrg)}},
		{"tiny org (10 rows)", &query.CountCertificatesRequest{OrgID: uint64(tinyOrg)}},
	}
	for _, c := range summaries {
		full := *c.req
		full.Now = s.now
		full.Expiring = summaryPeriods
		elapsed, err := timeIt(3, func() error {
			_, err := provider.CountCertificates(ctx, &full)
			return err
		})
		if err != nil {
			return errors.WithMessagef(err, "%s", c.name)
		}
		qp := c.req.QueryParams()
		q, _ := query.CountCertificates(qp)
		err = r.plan(ctx, sqlDB, c.name+", by status (provider: the statuses and the three periods)", elapsed, q, qp.Args())
		if err != nil {
			return err
		}
		qp = full.ExpiringParams(summaryPeriods[len(summaryPeriods)-1])
		q, _ = query.CountExpiringCertificates(qp)
		err = r.plan(ctx, sqlDB, c.name+", Active expiring within 90 days", 0, q, qp.Args())
		if err != nil {
			return err
		}
	}

	r.section("Lookups")
	lookups := []struct {
		name string
		q    func() (string, []any)
		run  func() error
	}{
		{"by issuer and serial (OCSP)", func() (string, []any) {
			q, _ := query.GetCertificateByIssuerSerial()
			return q, []any{sample.ikid, sample.serial}
		}, func() error {
			_, err := provider.GetCertificateByIssuerSerial(ctx, sample.ikid, sample.serial)
			return err
		}},
		{"by thumbprint", func() (string, []any) {
			q, _ := query.GetCertificateBySha256()
			return q, []any{sample.sha256}
		}, func() error {
			_, err := provider.GetCertificateBySha256(ctx, sample.sha256)
			return err
		}},
		{"revocation by issuer and serial (OCSP)", func() (string, []any) {
			qp := (&query.GetRevokedRequest{IKID: smallSample.ikid, SerialNumber: smallSample.serial}).QueryParams()
			q, _ := query.GetRevoked(qp)
			return q, qp.Args()
		}, func() error {
			_, err := provider.GetRevoked(ctx, &query.GetRevokedRequest{IKID: smallSample.ikid, SerialNumber: smallSample.serial})
			return err
		}},
	}
	for _, c := range lookups {
		elapsed, err := timeIt(5, c.run)
		if err != nil && !xdb.IsNotFoundError(err) {
			return errors.WithMessagef(err, "%s", c.name)
		}
		q, args := c.q()
		err = r.plan(ctx, sqlDB, c.name, elapsed, q, args)
		if err != nil {
			return err
		}
	}

	r.section("CRL entries (ListRevoked by issuer, valid now)")
	now := s.now
	revReq := &query.ListRevokedRequest{AllOrgs: true, IKID: bigIKID, ValidAfter: &now, Limit: crlPageSize, Cursor: query.NewCursor(0)}
	pages := 0
	var total int
	elapsed, err := timeIt(1, func() error {
		req := *revReq
		for {
			res, err := provider.ListRevoked(ctx, &req)
			if err != nil {
				return err
			}
			pages++
			total += len(res.Rows)
			if !res.HasNextPage {
				return nil
			}
			req.Cursor, err = query.ParseCursor(res.Cursor)
			if err != nil {
				return err
			}
		}
	})
	if err != nil {
		return errors.WithMessage(err, "ListRevoked")
	}
	r.printf("all pages: %d entries in %d pages, %s\n\n", total, pages, elapsed.Round(time.Millisecond))
	elapsed, err = timeIt(3, func() error {
		_, err := provider.ListRevoked(ctx, revReq)
		return err
	})
	if err != nil {
		return errors.WithMessage(err, "ListRevoked first page")
	}
	qp := revReq.QueryParams()
	q, _ := query.ListRevoked(qp)
	err = r.plan(ctx, sqlDB, "first page, big issuer", elapsed, q, qp.Args())
	if err != nil {
		return err
	}
	smallRev := &query.ListRevokedRequest{AllOrgs: true, IKID: smallIKID, ValidAfter: &now, Limit: crlPageSize, Cursor: query.NewCursor(0)}
	elapsed, err = timeIt(3, func() error {
		_, err := provider.ListRevoked(ctx, smallRev)
		return err
	})
	if err != nil {
		return errors.WithMessage(err, "ListRevoked small issuer")
	}
	qp = smallRev.QueryParams()
	q, _ = query.ListRevoked(qp)
	err = r.plan(ctx, sqlDB, "first page, small issuer", elapsed, q, qp.Args())
	if err != nil {
		return err
	}

	r.section("Certificate status task")
	expire := &query.ExpireCertificatesRequest{Before: s.now, Limit: taskBatchSize}
	q, _ = query.ExpireCertificates()
	err = r.rollbackPlan(ctx, sqlDB, "expire a batch (status Active, not_after < now, lowest IDs)", q, expire.Args())
	if err != nil {
		return err
	}
	elapsed, err = timeIt(3, func() error {
		_, err := provider.ExpireCertificates(ctx, expire)
		return err
	})
	if err != nil {
		return errors.WithMessage(err, "ExpireCertificates")
	}
	r.printf("ExpireCertificates batch of %d, mean of 3: %s\n\n", taskBatchSize, elapsed.Round(time.Millisecond))
	del := &query.DeleteExpiredCertificatesRequest{Before: s.now.Add(-validity / 2), Limit: taskBatchSize}
	q, _ = query.DeleteExpiredCertificates()
	err = r.rollbackPlan(ctx, sqlDB, "delete a batch (retention, not_after < cutoff, lowest IDs)", q, del.Args())
	if err != nil {
		return err
	}
	return nil
}

// signBench registers certificates through the provider as SignCertificate
// does, with the issue event in the same transaction, and reports the
// latency percentiles
func signBench(ctx context.Context, sqlDB *sql.DB, provider db.Provider, o *options, r *report) error {
	r.section("RegisterCertificate (the insert of SignCertificate)")
	orgID := xdb.NewID(bigOrg)
	_, err := sqlDB.ExecContext(ctx, "INSERT INTO "+schemaName+".org (id, alias, name, status) VALUES ($1, 'load', 'Load Org', 1) ON CONFLICT DO NOTHING", bigOrg)
	if err != nil {
		return errors.WithMessage(err, "unable to insert the org")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Load Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte("load-issuing-ca"),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	latencies := make([]time.Duration, 0, o.sign)
	start := time.Now()
	for i := range o.sign {
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		if err != nil {
			return err
		}
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("signed-%d.example.com", i)},
			NotBefore:    time.Now().Add(-30 * time.Minute),
			NotAfter:     time.Now().Add(validity),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			SubjectKeyId: fmt.Appendf(nil, "signed-%d", i),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			return err
		}
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		crtPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		m := model.NewCertificate(crt, orgID, xdb.ID(0), profiles[0], crtPEM, caPEM, "load", nil, nil)
		evt := &model.Event{
			OrgID:  orgID,
			Type:   pb.EventType_CertificateIssued,
			Title:  "Certificate issued",
			Source: "load",
		}
		at := time.Now()
		_, err = provider.RegisterCertificate(ctx, m, evt)
		if err != nil {
			return errors.WithMessagef(err, "register %d", i)
		}
		latencies = append(latencies, time.Since(at))
	}
	total := time.Since(start)
	slices.Sort(latencies)
	pct := func(p float64) time.Duration {
		return latencies[min(len(latencies)-1, int(float64(len(latencies))*p))]
	}
	r.printf("| inserts | total | rate | p50 | p95 | p99 | max |\n|---|---|---|---|---|---|---|\n")
	r.printf("| %d | %s | %.0f/s | %s | %s | %s | %s |\n\n", o.sign, total.Round(time.Millisecond), float64(o.sign)/total.Seconds(),
		pct(0.5).Round(time.Microsecond), pct(0.95).Round(time.Microsecond), pct(0.99).Round(time.Microsecond), latencies[len(latencies)-1].Round(time.Microsecond))
	return nil
}

// timeIt runs f n times and returns the mean duration
func timeIt(n int, f func() error) (time.Duration, error) {
	var total time.Duration
	for range n {
		at := time.Now()
		err := f()
		if err != nil {
			return 0, err
		}
		total += time.Since(at)
	}
	return total / time.Duration(n), nil
}

// report writes the markdown report and keeps the first write error, which
// run reports: a report of a long run is not lost quietly
type report struct {
	w   io.Writer
	err error
}

func (r *report) printf(format string, args ...any) {
	_, err := fmt.Fprintf(r.w, format, args...)
	if err != nil && r.err == nil {
		r.err = errors.WithMessage(err, "unable to write the report")
	}
}

func (r *report) section(title string) {
	r.printf("\n## %s\n\n", title)
}

// plan prints the query with its provider time and its EXPLAIN (ANALYZE,
// BUFFERS) plan
func (r *report) plan(ctx context.Context, sqlDB *sql.DB, name string, elapsed time.Duration, q string, args []any) error {
	lines, err := explainQuery(ctx, sqlDB, q, args, false)
	if err != nil {
		return errors.WithMessagef(err, "explain %s", name)
	}
	r.printPlan(name, elapsed, q, lines)
	return nil
}

// rollbackPlan explains a statement that writes, inside a transaction that
// is rolled back
func (r *report) rollbackPlan(ctx context.Context, sqlDB *sql.DB, name string, q string, args []any) error {
	lines, err := explainQuery(ctx, sqlDB, q, args, true)
	if err != nil {
		return errors.WithMessagef(err, "explain %s", name)
	}
	r.printPlan(name, 0, q, lines)
	return nil
}

func (r *report) printPlan(name string, elapsed time.Duration, q string, lines []string) {
	r.printf("### %s\n\n", name)
	if elapsed > 0 {
		r.printf("provider: %s\n\n", elapsed.Round(10*time.Microsecond))
	}
	r.printf("```sql\n%s\n```\n\n```text\n%s\n```\n\n", strings.TrimSpace(q), strings.Join(lines, "\n"))
}

func explainQuery(ctx context.Context, sqlDB *sql.DB, q string, args []any, rollback bool) ([]string, error) {
	var lines []string
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !rollback {
		return lines, tx.Commit()
	}
	return lines, nil
}

// samplePEM is the PEM of one self-signed certificate, reused by every
// synthetic row: the queries never read it, the row width matters
func samplePEM() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "synthetic.example.com", Organization: []string{"Load Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{"synthetic.example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: []string{"http://localhost:8888/v1/crl/0000000000000000000000000000000000000000"},
		OCSPServer:            []string{"http://localhost:8888/v1/ocspi/0000000000000000000000000000000000000000"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// hexOf hashes the value and returns the first n hex characters
func hexOf(h interface {
	io.Writer
	Sum([]byte) []byte
}, val string, n int) string {
	_, _ = io.WriteString(h, val)
	return hex.EncodeToString(h.Sum(nil))[:n]
}
