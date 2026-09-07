# HOT TO PAGINATE

```sql
--
-- Events
--
CREATE TABLE IF NOT EXISTS trustyca.event
(
    id BIGINT NOT NULL,
    project_id BIGINT NOT NULL REFERENCES trustyca.project ON DELETE CASCADE,
    type INTEGER NOT NULL,
    title VARCHAR(256) COLLATE pg_catalog."default" NOT NULL,
    description TEXT COLLATE pg_catalog."default" NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    ref_id BIGINT NULL,
    email VARCHAR(160) COLLATE pg_catalog."default" NULL,
    source VARCHAR(256) COLLATE pg_catalog."default" NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT event_pkey PRIMARY KEY (id)
)
WITH (
    OIDS = FALSE
);

ALTER TABLE trustyca.event
    OWNER to trustyca;

CREATE INDEX IF NOT EXISTS idx_event_project_id
    ON trustyca.event USING btree
    (project_id);

CREATE INDEX idx_event_project_created_id_desc
    ON trustyca.event USING btree (project_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_event_type
    ON trustyca.event USING btree
    (type);

CREATE INDEX IF NOT EXISTS idx_event_email
    ON trustyca.event USING btree
    (email);

CREATE INDEX IF NOT EXISTS idx_event_project_ref_id
    ON trustyca.event USING btree
    (project_id, ref_id);
```

Your index set is the first thing to fix — the two single-column `created_at` indexes don't help here at all, and one of them is redundant on its own.

## Index

Postgres can scan a btree backwards, so `ASC` and `DESC` single-column indexes are duplicates of each other. What you actually need is a composite that matches the filter + the full sort key:

```sql
DROP INDEX trustyca.idx_event_created_at_asc;
DROP INDEX trustyca.idx_event_created_at_desc;
DROP INDEX trustyca.idx_event_project_id;  -- now redundant, project_id is the leading col

CREATE INDEX idx_event_project_created_id_desc
    ON trustyca.event USING btree (project_id, created_at DESC, id DESC);
```

Two schema notes while you're in there: `created_at` should be `NOT NULL` (a NULL sort key breaks tuple comparison in cursor mode, and `DESC` puts NULLs first by default), and `TIMESTAMP(3)` means millisecond granularity — bulk-inserted events _will_ collide, which is exactly why `id` has to be in the sort key as a tiebreaker.

Change to

    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW()

## Offset mode (page ≤ 10K)

```sql
SELECT id, type, title, created_at, COUNT(*) OVER () AS total
  FROM trustyca.event
 WHERE project_id = $1
 ORDER BY created_at DESC, id DESC
 LIMIT $2 OFFSET $3;
```

The `COUNT(*) OVER ()` is what makes offset mode worth having — you get an exact total for page-number UI in one round trip. It's also the part that stops scaling, since the window count reads the whole matching set.

## Keyset mode (beyond that)

Forward (older events), given the last row of the previous page:

```sql
SELECT id, type, title, created_at
  FROM trustyca.event
 WHERE project_id = $1
   AND (created_at, id) < ($2, $3)
 ORDER BY created_at DESC, id DESC
 LIMIT $4;
```

The row-wise comparison is the important bit. `(created_at, id) < ($2, $3)` is lexicographic and maps exactly onto the `DESC, DESC` index order, and Postgres pushes it down as an index qual — you get a single index descent, no filtering. Don't expand it into `created_at < $2 OR (created_at = $2 AND id < $3)`; the planner handles that worse, and it's easy to get the boundary wrong.

Backward (newer events) flips both the comparison and the sort, then re-sorts the slice:

```sql
SELECT * FROM (
    SELECT id, type, title, created_at
      FROM trustyca.event
     WHERE project_id = $1
       AND (created_at, id) > ($2, $3)
     ORDER BY created_at ASC, id ASC
     LIMIT $4
) p ORDER BY created_at DESC, id DESC;
```

Always `LIMIT n+1` and discard the extra row — that's your `has_more` without a second query.

## Cursor payload

```go
type cursor struct {
	V   uint8  `json:"v"`  // format version
	TS  int64  `json:"t"`  // created_at as unix millis — matches TIMESTAMP(3) exactly
	ID  int64  `json:"i"`
	Dir int8   `json:"d"`  // +1 forward, -1 backward
	FP  string `json:"f"`  // fingerprint of the frozen query params
}

func (c cursor) encode(key []byte) string {
	b, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:8])
}
```

Two things that save you grief later:

**The fingerprint.** Hash the immutable parts of the request — `project_id`, type filters, sort field, sort direction — and reject the cursor if it doesn't match the current request. Otherwise a client pages three deep, changes a filter, keeps the cursor, and gets a silently wrong window.

**Round-trip the timestamp from the database, never from `time.Now()`.** Postgres rounds to milliseconds on write; if you build the cursor from an app-side `time.Time` you may land a microsecond off the stored value and skip or duplicate a row at the boundary.

The HMAC is optional but cheap. It doesn't hide anything (the client already saw the timestamp and id), it just stops people hand-crafting cursors and turning your pagination internals into de facto API surface.

## The hybrid switch

Emit `next_cursor` in _both_ modes, computed from the last row of the page. Then the transition at 10K is invisible: offset pages carry a valid cursor, so when the client crosses the threshold it just keeps following cursors and you stop serving `total`. Return something like `total_is_estimate: true` (or drop `total` entirely) past the boundary rather than silently changing its meaning.

One shortcut worth checking: if your `id` is an app-generated snowflake or a plain sequence, it's already monotonic in time. In that case drop `created_at` from the sort key entirely and paginate on `id DESC` alone — smaller index, smaller cursor, single-column comparison, and no tie handling. It only breaks if you ever backfill historical events with fresh ids.
