package schema

// TableInfo.AllColumns caches its result in the table on first use without
// a lock, so the first concurrent callers race on the write. Warm the cache
// while the process is still single-threaded: at init.
func init() {
	for _, t := range TrustycadbTables {
		_ = t.AllColumns()
	}
}
