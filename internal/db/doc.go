// Package db defines the database interfaces of the service and constructs
// the PostgreSQL provider that implements them.
//
// OrgsReadonlyDb and OrgsDb own the access layer (users, logins, orgs,
// projects, memberships, invites, API keys, events); CaReadonlyDb and CaDb
// own the CA data plane (issuers, trust anchors, profiles, certificates,
// revocations, CRLs). Provider implements all of them:
//
//	p, err := db.New(cfg.SQL.DataSource, cfg.SQL.MigrationsDir, 0, 0, flake.DefaultIDGenerator)
//	if err != nil {
//		return err
//	}
//	defer p.Close()
//	issuer, err := p.FindIssuer(ctx, orgID, projectID, "L2_CA")
//
// New runs the SQL migrations of the migrations directory. The DB layer is
// plain CRUD: it never imports the authorization code, and the caller
// verifies that a row returned by ID belongs to the caller's org and
// project. The sentinel errors of the CA mutations (ErrAlreadyRevoked,
// ErrStaleCrlNumber, ErrRootConflict, ErrOrgScopeRequired) are compared
// with errors.Is.
package db
