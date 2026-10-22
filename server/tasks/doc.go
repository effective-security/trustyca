// Package tasks registers the scheduled tasks of the service. The `tasks:`
// section of the configuration names a task, its schedule and its
// arguments; App.scheduleTasks looks the name up in Factories and invokes
// the function the factory returns through the application container, so a
// task declares the dependencies it needs as the parameters of that
// function:
//
//	tasks:
//	  - name: crl_renewal
//	    schedule: "every 10 minutes"
//	  - name: cert_status
//	    schedule: "every 1 hour"
//
// Every task runs once when it is scheduled, then on its schedule; the
// scheduler of porto/pkg/tasks recovers a panic of a run and never runs a
// task concurrently with itself. A task is multi-instance safe by design:
// the CRL renewal relies on the CRL number of the DB, the certificate
// status on idempotent batches.
package tasks
