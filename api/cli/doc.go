// Package cli configures the public trustyca command, client connections and output formatting.
//
// Cli.AfterApply changes process-wide xlog and time formatting, so CLIs are
// never parsed concurrently in one process; the test suites of
// api/cli/command are not parallel for that reason.
package cli
