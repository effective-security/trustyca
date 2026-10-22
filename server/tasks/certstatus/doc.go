// Package certstatus is the cert_status task: on every run it marks the
// Active certificates whose validity ended as Expired and, when
// ca.retention.expired_after is set, deletes the certificates of any status
// that expired longer ago than that, with their revocations. Both run in
// batches of the lowest IDs (db.ExpireCertificates and
// db.DeleteExpiredCertificates), repeated until a batch is not full, so a
// run touches every tenant without holding a long transaction; a run is
// bounded by MaxBatches and the next run continues. The task runs at once
// when scheduled, then on its schedule.
//
//	ca:
//	  retention:
//	    expired_after: 720h
//	tasks:
//	  - name: cert_status
//	    schedule: "every 1 hour"
package certstatus
