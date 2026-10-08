// Package clisuite supports CLI tests with fixture-backed HTTP servers and gRPC mocks.
//
// CapturePrint records the output of a test, with the address of the mock
// server replaced by "{server}". TearDownSuite compares it with the suite's
// golden file, testdata/prints_<suite test>.txt (testutils.CheckGolden); run
// with TRUSTYCA_UPDATE_GOLDEN=1 to rewrite it. Suites share CLI globals
// (Cli.AfterApply), so they must not run in parallel.
package clisuite
