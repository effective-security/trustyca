// Package testutils loads development test configuration and builds request, JSON and golden output assertions.
//
// Config paths resolve against the repository fixtures. JSON and JSONIndent
// are convenience helpers that intentionally swallow marshal errors;
// CompareJSON uses testing assertions.
//
// CreateURL, CreateURLs and CreateBindAddr return free ports, none twice in
// one process; another process may still bind one after the probe.
//
// CheckGolden compares output a test suite captured with a golden file:
//
//	testutils.CheckGolden(t, "testdata/prints_TestRpc.txt", entries)
//
// and rewrites the file instead when GoldenUpdateEnv is set and the suite
// passed:
//
//	TRUSTYCA_UPDATE_GOLDEN=1 go test ./api/cli/command
package testutils
