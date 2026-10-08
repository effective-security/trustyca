package testutils

import (
	"flag"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GoldenUpdateEnv names the environment variable that makes CheckGolden
// rewrite a golden file instead of comparing with it:
//
//	TRUSTYCA_UPDATE_GOLDEN=1 go test ./api/cli/command
const GoldenUpdateEnv = "TRUSTYCA_UPDATE_GOLDEN"

// GoldenEntry is one output captured by a test, under a name unique in its
// golden file
type GoldenEntry struct {
	Name string
	Out  string
}

// goldenHeader matches the line that starts an entry of a golden file,
// "- <test path>:"
var goldenHeader = regexp.MustCompile(`^- (Test\S+):$`)

// filterFlags are the go test and testify flags that run a subset of the
// tests
var filterFlags = []string{"test.run", "test.skip", "testify.m"}

// CheckGolden compares the entries captured by a test suite with the
// golden file at path, entry by entry. An entry missing from the file
// fails, and so does an entry of the file the suite did not capture,
// unless the run was filtered with -run, -skip or -testify.m.
//
// With GoldenUpdateEnv set to a true value it writes the entries to the
// file instead, unless a test of the suite failed: a failed test may not
// have captured its output. An unfiltered run replaces the file; a
// filtered run merges its entries into it, so that it keeps the outputs of
// the tests it did not run. Captured output must not contain values that
// change between runs, such as ephemeral ports; the caller replaces them
// first.
func CheckGolden(t testing.TB, path string, entries []GoldenEntry) {
	t.Helper()
	update, _ := strconv.ParseBool(os.Getenv(GoldenUpdateEnv))
	checkGolden(t, path, entries, update, isFilteredRun())
}

// checkGolden is CheckGolden with the update mode and the filtered run
// given
func checkGolden(t testing.TB, path string, entries []GoldenEntry, update, filtered bool) {
	t.Helper()

	golden, err := readGolden(path)
	require.NoError(t, err)

	if update {
		if t.Failed() {
			t.Errorf("%s: not updated, as the suite failed", path)
			return
		}
		if !filtered {
			golden = map[string]string{}
		}
		for _, e := range entries {
			golden[e.Name] = e.Out
		}
		require.NoError(t, writeGolden(path, golden))
		return
	}

	captured := map[string]bool{}
	for _, e := range entries {
		captured[e.Name] = true
		want, ok := golden[e.Name]
		if !ok {
			t.Errorf("%s: no golden output for %s; run with %s=1 to add it", path, e.Name, GoldenUpdateEnv)
			continue
		}
		assert.Equal(t, want, e.Out, "%s: output of %s differs; run with %s=1 to update it", path, e.Name, GoldenUpdateEnv)
	}
	if filtered {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(golden)) {
		if !captured[name] {
			t.Errorf("%s: golden output of %s was not printed; run with %s=1 to remove it", path, name, GoldenUpdateEnv)
		}
	}
}

// UniqueGoldenName returns name, or name with a "#<n>" suffix when the
// entries already have it, so that a test can capture more than one output
// of the same format
func UniqueGoldenName(entries []GoldenEntry, name string) string {
	unique := name
	for n := 2; slices.ContainsFunc(entries, func(e GoldenEntry) bool { return e.Name == unique }); n++ {
		unique = name + "#" + strconv.Itoa(n)
	}
	return unique
}

// isFilteredRun returns true when the test binary runs a subset of the
// tests
func isFilteredRun() bool {
	for _, name := range filterFlags {
		if f := flag.Lookup(name); f != nil && f.Value.String() != "" {
			return true
		}
	}
	return false
}

// readGolden parses a golden file into its entries by name; a missing file
// has none. An entry is a "- <name>:" line, then the output, then a
// newline, which is an empty line when the output ends with one.
func readGolden(path string) (map[string]string, error) {
	golden := map[string]string{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return golden, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read golden file %s", path)
	}

	var (
		name string
		out  strings.Builder
	)
	flush := func() {
		if name != "" {
			// writeGolden adds a newline after each output
			golden[name] = strings.TrimSuffix(out.String(), "\n")
		}
		out.Reset()
	}
	for line := range strings.SplitAfterSeq(string(b), "\n") {
		if m := goldenHeader.FindStringSubmatch(strings.TrimSuffix(line, "\n")); m != nil {
			flush()
			name = m[1]
			continue
		}
		out.WriteString(line)
	}
	flush()
	return golden, nil
}

// writeGolden writes the entries sorted by name; it removes the file when
// there are none. An output with a line that reads as an entry header is
// refused, as readGolden would split it.
func writeGolden(path string, golden map[string]string) error {
	for name, out := range golden {
		for line := range strings.SplitSeq(out, "\n") {
			if goldenHeader.MatchString(line) {
				return errors.Errorf("output of %s has a line that reads as a golden entry: %q", name, line)
			}
		}
	}

	if len(golden) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return errors.Wrapf(err, "unable to remove golden file %s", path)
		}
		return nil
	}

	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(golden)) {
		b.WriteString("- ")
		b.WriteString(name)
		b.WriteString(":\n")
		b.WriteString(golden[name])
		b.WriteString("\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "unable to create golden file folder %s", path)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return errors.Wrapf(err, "unable to write golden file %s", path)
	}
	return nil
}
