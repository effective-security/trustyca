// Command load fills a disposable database with synthetic certificate and
// revocation rows and reports the plans and timings of the CA queries at
// that volume (PLAN.md phase 7): the lists of ListCertificates, the lookups
// of OCSP and the CIS, the CRL entries, the batches of the certificate
// status task, and the insert of SignCertificate.
//
// It needs the local stack (make start-localstack) and creates the database
// with the superuser of the dev container:
//
//	go run ./tests/load -rows 10000000 -load -explain -sign 2000
//	go run ./tests/load -drop
//
// The plans are written to stdout; -out writes the full report to a file.
package main
