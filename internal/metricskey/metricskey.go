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

// Metrics provides the list of emitted metrics by this repo
var Metrics = []*metrics.Describe{
	&PerfDbOperation,
	&PerfMethodRun,
	&PerfTaskRun,
	&StatsDbTableRowsTotal,
	&StatsDbQueryCount,
	&LoginCount,
	&SupportLoginCount,
}
