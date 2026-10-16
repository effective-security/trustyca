package testutils

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTB records the failures checkGolden reports, instead of
// failing the test that checks it
type recordingTB struct {
	testing.TB
	errors []string
	failed bool
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *recordingTB) FailNow() {
	r.failed = true
}

func (r *recordingTB) Failed() bool {
	return r.failed || len(r.errors) > 0
}

// goldenSample is a golden file as writeGolden writes it: outputs with and
// without a trailing newline, an empty one, and lines that resemble a
// header but are not one
const goldenSample = `- TestRpc/TestA/json:
{
	"a": 1
}

- TestRpc/TestA/txt:
- not a header:
plain

- TestRpc/TestB/txt:

- TestRpc/TestC/txt:
no newline
`

func goldenSampleEntries() []GoldenEntry {
	return []GoldenEntry{
		{Name: "TestRpc/TestA/json", Out: "{\n\t\"a\": 1\n}\n"},
		{Name: "TestRpc/TestA/txt", Out: "- not a header:\nplain\n"},
		{Name: "TestRpc/TestB/txt", Out: ""},
		{Name: "TestRpc/TestC/txt", Out: "no newline"},
	}
}

func writeSample(t *testing.T) string {
	path := filepath.Join(t.TempDir(), "testdata", "prints_TestRpc.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(goldenSample), 0o644))
	return path
}

func readFile(t *testing.T, path string) string {
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func Test_readGolden(t *testing.T) {
	t.Parallel()

	golden, err := readGolden(writeSample(t))
	require.NoError(t, err)
	want := map[string]string{}
	for _, e := range goldenSampleEntries() {
		want[e.Name] = e.Out
	}
	assert.Equal(t, want, golden)

	golden, err = readGolden(filepath.Join(t.TempDir(), "missing.txt"))
	require.NoError(t, err)
	assert.Empty(t, golden)

	_, err = readGolden(t.TempDir())
	assert.ErrorContains(t, err, "unable to read golden file")
}

func Test_checkGolden(t *testing.T) {
	t.Parallel()

	t.Run("matches", func(t *testing.T) {
		t.Parallel()
		rec := &recordingTB{TB: t}
		checkGolden(rec, writeSample(t), goldenSampleEntries(), false, false)
		assert.Empty(t, rec.errors)
	})

	t.Run("differs_missing_and_stale", func(t *testing.T) {
		t.Parallel()
		path := writeSample(t)
		entries := goldenSampleEntries()
		entries[0].Out = "{}\n"
		entries = append(entries[:3], GoldenEntry{Name: "TestRpc/TestD/txt", Out: "new\n"})

		rec := &recordingTB{TB: t}
		checkGolden(rec, path, entries, false, false)
		require.Len(t, rec.errors, 3)
		assert.Contains(t, rec.errors[0], "output of TestRpc/TestA/json differs; run with TRUSTYCA_UPDATE_GOLDEN=1 to update it")
		assert.Contains(t, rec.errors[1], "no golden output for TestRpc/TestD/txt; run with TRUSTYCA_UPDATE_GOLDEN=1 to add it")
		assert.Contains(t, rec.errors[2], "golden output of TestRpc/TestC/txt was not printed; run with TRUSTYCA_UPDATE_GOLDEN=1 to remove it")
		assert.Equal(t, goldenSample, readFile(t, path), "compare mode never writes")
	})

	t.Run("filtered_run_ignores_tests_not_run", func(t *testing.T) {
		t.Parallel()
		rec := &recordingTB{TB: t}
		checkGolden(rec, writeSample(t), goldenSampleEntries()[1:2], false, true)
		assert.Empty(t, rec.errors)
	})

	t.Run("update_replaces", func(t *testing.T) {
		t.Parallel()
		path := writeSample(t)
		rec := &recordingTB{TB: t}
		checkGolden(rec, path, []GoldenEntry{{Name: "TestRpc/TestZ/txt", Out: "z\n"}}, true, false)
		assert.Empty(t, rec.errors)
		assert.Equal(t, "- TestRpc/TestZ/txt:\nz\n\n", readFile(t, path))
	})

	t.Run("filtered_update_merges", func(t *testing.T) {
		t.Parallel()
		path := writeSample(t)
		rec := &recordingTB{TB: t}
		checkGolden(rec, path, []GoldenEntry{
			{Name: "TestRpc/TestB/txt", Out: "b\n"},
			{Name: "TestRpc/TestAA/txt", Out: "aa\n"},
		}, true, true)
		assert.Empty(t, rec.errors)

		golden, err := readGolden(path)
		require.NoError(t, err)
		assert.Len(t, golden, 5, "the tests not run are kept")
		assert.Equal(t, "b\n", golden["TestRpc/TestB/txt"])
		assert.Equal(t, "aa\n", golden["TestRpc/TestAA/txt"])
		assert.Equal(t, "no newline", golden["TestRpc/TestC/txt"])
	})

	t.Run("update_round_trips", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "new", "prints.txt")
		rec := &recordingTB{TB: t}
		checkGolden(rec, path, goldenSampleEntries(), true, false)
		assert.Empty(t, rec.errors)
		assert.Equal(t, goldenSample, readFile(t, path))
	})

	t.Run("update_without_entries_removes", func(t *testing.T) {
		t.Parallel()
		path := writeSample(t)
		rec := &recordingTB{TB: t}
		checkGolden(rec, path, nil, true, false)
		assert.Empty(t, rec.errors)
		assert.NoFileExists(t, path)

		// nothing captured and no file: nothing to write
		checkGolden(rec, path, nil, true, false)
		assert.Empty(t, rec.errors)
		checkGolden(rec, path, nil, false, false)
		assert.Empty(t, rec.errors)
	})

	t.Run("update_refused_when_suite_failed", func(t *testing.T) {
		t.Parallel()
		path := writeSample(t)
		rec := &recordingTB{TB: t, failed: true}
		checkGolden(rec, path, []GoldenEntry{{Name: "TestRpc/TestZ/txt", Out: "z\n"}}, true, false)
		require.Len(t, rec.errors, 1)
		assert.Contains(t, rec.errors[0], "not updated, as the suite failed")
		assert.Equal(t, goldenSample, readFile(t, path), "the file is kept")
	})

	t.Run("unreadable", func(t *testing.T) {
		t.Parallel()
		rec := &recordingTB{TB: t}
		checkGolden(rec, t.TempDir(), nil, false, false)
		assert.True(t, rec.failed)
		require.Len(t, rec.errors, 1)
		assert.Contains(t, rec.errors[0], "unable to read golden file")
	})
}

func Test_writeGolden_errors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	golden := map[string]string{"TestRpc/TestA/txt": "a\n"}

	// the folder of the file is a file
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o644))
	assert.ErrorContains(t, writeGolden(filepath.Join(file, "prints.txt"), golden), "unable to create golden file folder")

	// the file is a folder
	folder := filepath.Join(dir, "folder")
	require.NoError(t, os.MkdirAll(filepath.Join(folder, "child"), 0o755))
	assert.ErrorContains(t, writeGolden(folder, golden), "unable to write golden file")
	// and a folder that is not empty cannot be removed
	assert.ErrorContains(t, writeGolden(folder, nil), "unable to remove golden file")

	// an output line that reads as a header would split the entry
	err := writeGolden(filepath.Join(dir, "prints.txt"), map[string]string{"TestRpc/TestA/txt": "a\n- TestRpc/TestB/txt:\nb\n"})
	assert.ErrorContains(t, err, `output of TestRpc/TestA/txt has a line that reads as a golden entry: "- TestRpc/TestB/txt:"`)
	assert.NoFileExists(t, filepath.Join(dir, "prints.txt"))
}

func Test_UniqueGoldenName(t *testing.T) {
	t.Parallel()
	var entries []GoldenEntry
	for _, want := range []string{"TestRpc/TestA/txt", "TestRpc/TestA/txt#2", "TestRpc/TestA/txt#3"} {
		name := UniqueGoldenName(entries, "TestRpc/TestA/txt")
		assert.Equal(t, want, name)
		entries = append(entries, GoldenEntry{Name: name})
	}
	assert.Equal(t, "TestRpc/TestA/json", UniqueGoldenName(entries, "TestRpc/TestA/json"))
}

// Test_CheckGolden reads the update mode and the run filter from the
// environment and the flags of the test binary. It is not parallel: it
// changes both.
func Test_CheckGolden(t *testing.T) {
	runFlag := flag.Lookup("test.run")
	require.NotNil(t, runFlag)
	prev := runFlag.Value.String()
	t.Cleanup(func() { _ = runFlag.Value.Set(prev) })

	path := writeSample(t)
	require.NoError(t, runFlag.Value.Set(""))
	assert.False(t, isFilteredRun())
	t.Setenv(GoldenUpdateEnv, "")
	CheckGolden(t, path, goldenSampleEntries())

	// a filtered update merges
	require.NoError(t, runFlag.Value.Set("Test_CheckGolden"))
	assert.True(t, isFilteredRun())
	t.Setenv(GoldenUpdateEnv, "1")
	CheckGolden(t, path, []GoldenEntry{{Name: "TestRpc/TestZ/txt", Out: "z\n"}})
	assert.Equal(t, goldenSample+"- TestRpc/TestZ/txt:\nz\n\n", readFile(t, path))
}
