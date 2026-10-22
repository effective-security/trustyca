// Package crlrenewal is the crl_renewal task: on every run it publishes
// the CRLs that are due for the Active and Archived issuers of every org
// and the platform, through the CRL publisher of internal/ca that the
// PublishCrls method of the CA service uses (DESIGN.md section 8). A CRL
// is due when the issuer has none, or when the current one is within the
// crl_renewal period of the issuer settings of its next update; the task
// runs at once when scheduled, so a new deployment serves CRLs without
// waiting for the first tick. Every published CRL records a CrlPublished
// event. Several instances may run the task: the DB refuses a CRL number
// that is not greater than the issuer's, so the instance that publishes
// second keeps the other's CRL.
//
//	tasks:
//	  - name: crl_renewal
//	    schedule: "every 10 minutes"
package crlrenewal
