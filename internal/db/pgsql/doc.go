// Package pgsql implements the database interfaces of internal/db on
// PostgreSQL.
//
// Provider wraps an xdb.Provider; every method builds its SQL through the
// query package, measures the query and maps a missing row to
// xdb.ErrorNotFound. A method that writes more than one row (AcceptInvite,
// RegisterCertificate with an event, RegisterIssuer with an anchor,
// RevokeCertificate, PublishCrl) opens a transaction with BeginTx and runs
// every statement on the provider it returns:
//
//	tx, err := p.BeginTx(ctx, nil)
//	defer tx.Close() // rolls back unless committed
//	txProvider := tx.(*Provider)
//
// Lists page by offset or by a keyset cursor on their sort key (listRows):
// id for the CA lists, (created_at, id) for the events, (name, id) for the
// orgs and the projects. The tests need the configured local PostgreSQL
// database.
package pgsql
