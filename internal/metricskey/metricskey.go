package metricskey

import (
	"github.com/effective-security/metrics"
)

// Perf
var (
	// PerfDbOperation is perf metric
	PerfDbOperation = metrics.Describe{
		Type:         metrics.TypeSample,
		Name:         "perf_db_query",
		Help:         "perf_db_query provides the sample metrics of db query",
		RequiredTags: []string{"method"},
	}

	// PerfTaskRun is perf metric
	PerfTaskRun = metrics.Describe{
		Type:         metrics.TypeSample,
		Name:         "perf_task_run",
		Help:         "perf_task_run provides the sample metrics of task run",
		RequiredTags: []string{"task"},
	}

	// PerfMethodRun is perf metric
	PerfMethodRun = metrics.Describe{
		Type:         metrics.TypeSample,
		Name:         "perf_method_run",
		Help:         "perf_method_run provides the sample metrics of method run",
		RequiredTags: []string{"pkg", "method"},
	}
)

// Stats
var (
	// StatsDbTableRowsTotal is base for gauge metric for total rows in a table
	StatsDbTableRowsTotal = metrics.Describe{
		Type:         metrics.TypeGauge,
		Name:         "stats_table_rows",
		Help:         "provides total rows in a table",
		RequiredTags: []string{"table"},
	}
	StatsDbQueryCount = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "stats_db_query_count",
		Help:         "stats_db_query_count provides counter of DB queries",
		RequiredTags: []string{"method"},
	}
)

// Login
var (
	// LoginCount is counter metric to show number of logins
	LoginCount = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "login_count",
		Help:         "login_count is counter metric to show number of logins",
		RequiredTags: []string{"email"},
	}

	// SupportLoginCount is counter metric to show number of support logins to a customer org
	SupportLoginCount = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "support_login_count",
		Help:         "support_login_count is counter metric to show number of support logins to a customer org",
		RequiredTags: []string{"email", "org"},
	}
)

// CA
var (
	// CACertIssued is counter metric for issued certs
	CACertIssued = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "ca_cert_issued",
		Help:         "provides the counter of issued certs",
		RequiredTags: []string{"ca", "profile"},
	}

	// CACertRevoked is counter metric for revoked certs
	CACertRevoked = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "ca_cert_revoked",
		Help:         "provides the counter of revoked certs",
		RequiredTags: []string{"ikid"},
	}

	// CACrlPublished is counter metric for published CRL
	CACrlPublished = metrics.Describe{
		Type: metrics.TypeCounter,
		Name: "ca_crl_published",
		Help: "provides the counter of published CRLs",
		//RequiredTags: []string{"ca"},
	}

	// CAOcspSigned is counter metric for signed ocsp
	CAOcspSigned = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "ca_ocsp_signed",
		Help:         "provides the counter of signed OCSP",
		RequiredTags: []string{"ikid", "status"},
	}

	// CAFailSignCert is counter metric
	CAFailSignCert = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "ca_fail_sign_cert",
		Help:         "provides the counter of failures to sign cert",
		RequiredTags: []string{"ca", "profile"},
	}

	// CAFailPublishCert is counter metric
	CAFailPublishCert = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "ca_fail_publish_cert",
		Help:         "provides the counter of failures to publish cert",
		RequiredTags: []string{"ca"},
	}

	// CAFailPublishCrl is counter metric
	CAFailPublishCrl = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "ca_fail_publish_crl",
		Help:         "provides the counter of failures to publish CRL",
		RequiredTags: []string{"ca"},
	}

	// CAExpiryCertDays is gauge metric
	CAExpiryCertDays = metrics.Describe{
		Type:         metrics.TypeGauge,
		Name:         "ca_expiry_cert_days",
		Help:         "provides number of days til CA cert expiry",
		RequiredTags: []string{"type", "cn", "sn", "iki", "ski"},
	}

	// CAExpiryCrlDays is gauge metric
	CAExpiryCrlDays = metrics.Describe{
		Type:         metrics.TypeGauge,
		Name:         "ca_expiry_crl_days",
		Help:         "provides number of days til CRL expiry",
		RequiredTags: []string{"cn", "sn", "iki"},
	}
)

// Certs
var (
	// CertExpiryDays is gauge metric
	CertExpiryDays = metrics.Describe{
		Type:         metrics.TypeGauge,
		Name:         "cert_expiry_days",
		Help:         "provides number of days til cert expiry",
		RequiredTags: []string{"type", "cn", "sn", "iki", "ski"},
	}

	// CertExpiryHours is gauge metric
	CertExpiryHours = metrics.Describe{
		Type:         metrics.TypeGauge,
		Name:         "cert_expiry_hours",
		Help:         "provides number of hours til cert expiry",
		RequiredTags: []string{"type", "cn", "sn", "iki", "ski"},
	}
)

// AIA
var (
	// AIADownloadSuccessCert is counter metric
	AIADownloadSuccessCert = metrics.Describe{
		Type: metrics.TypeCounter,
		Name: "aia_download_success_cert",
		Help: "provides the counter of downloaded certs",
	}

	// AIADownloadSuccessCrl is counter metric
	AIADownloadSuccessCrl = metrics.Describe{
		Type: metrics.TypeCounter,
		Name: "aia_download_success_crl",
		Help: "provides the counter of downloaded CRLs",
	}

	// AIADownloadSuccessOCSP is counter metric
	AIADownloadSuccessOCSP = metrics.Describe{
		Type: metrics.TypeCounter,
		Name: "aia_download_success_ocsp",
		Help: "provides the counter of downloaded OCSP",
	}

	// AIADownloadFailCert is counter metric
	AIADownloadFailCert = metrics.Describe{
		Type: metrics.TypeCounter,
		Name: "aia_download_fail_cert",
		Help: "provides the counter of failed cert downloads",
	}

	// AIADownloadFailCrl is counter metric
	AIADownloadFailCrl = metrics.Describe{
		Type: metrics.TypeCounter,
		Name: "aia_download_fail_crl",
		Help: "provides the counter of failed CRL downloads",
	}

	// AIADownloadFailOCSP is counter metric
	AIADownloadFailOCSP = metrics.Describe{
		Type: metrics.TypeCounter,
		Name: "aia_download_fail_ocsp",
		Help: "provides the counter of failed OCSP downloads",
	}
)

// Metrics provides the list of emitted metrics by this repo
var Metrics = []*metrics.Describe{
	&AIADownloadFailCert,
	&AIADownloadFailCrl,
	&AIADownloadFailOCSP,
	&AIADownloadSuccessCert,
	&AIADownloadSuccessCrl,
	&AIADownloadSuccessOCSP,
	&CACertIssued,
	&CACertRevoked,
	&CACrlPublished,
	&CAExpiryCertDays,
	&CAExpiryCrlDays,
	&CAFailPublishCert,
	&CAFailPublishCrl,
	&CAFailSignCert,
	&CAOcspSigned,
	&CertExpiryDays,
	&CertExpiryHours,
	&LoginCount,
	&PerfDbOperation,
	&PerfMethodRun,
	&PerfTaskRun,
	&StatsDbQueryCount,
	&StatsDbTableRowsTotal,
	&SupportLoginCount,
}
