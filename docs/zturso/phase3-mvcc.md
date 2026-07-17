# Phase 3 — MVCC / `BEGIN CONCURRENT`: design note & honest status

**Status: NOT implemented. This is a design note, not a shipped feature.**

Unlike Phases 1, 2, and 4 — which are working demonstrators you can run — true
MVCC is a multi-month rewrite of the pager and B-tree. Claiming it "done" would
be dishonest. `zig build zturso-mvcc` runs a demonstrator that marks the exact
boundary this phase must move; this note is the plan.

## What the ported engine does today

Run `zig build zturso-mvcc`. It shows, on the real ported engine over one WAL
database with two connections:

- **(A) Concurrent readers + snapshot isolation already work.** A reader's
  snapshot is stable across another connection's commit — WAL gives us this for
  free, and the port reproduces it exactly.
- **(B) Writers are serialized.** A second `BEGIN IMMEDIATE` returns
  `SQLITE_BUSY`. SQLite (and therefore this port) is **single-writer**: one write
  transaction at a time, whole-database.

Lifting exactly (B) — letting multiple writers proceed concurrently and reconcile
— is what `BEGIN CONCURRENT` / MVCC delivers. Turso built this in `core/mvcc`.

## Why it's a large rewrite (not a flag)

SQLite's concurrency is structural, not a setting:

1. **Rollback/WAL are single-version.** A page has exactly one current image.
   Two writers editing different tables still contend on the single write lock
   because the pager cannot represent two uncommitted versions of the file.
2. **The B-tree mutates pages in place.** MVCC needs *versioned* rows (each row
   carries visibility metadata, e.g. begin/end transaction ids) so a reader sees
   the version valid as of its snapshot while a writer creates a newer one.
3. **No transaction manager.** There is no global notion of concurrently-active
   transactions, snapshot timestamps, conflict detection, or version GC.

## Sketch of an implementation (the real Phase 3 work)

This is the order the rewrite would proceed, each step testable in isolation:

1. **Transaction/version manager.** A monotonically increasing txn id, a table of
   active snapshots, and a commit sequence. (Deterministic-sim-testable in the
   spirit of the fidelity harness.)
2. **Versioned row store.** Either (a) an MVCC overlay keyed by `(rowid, tableId)`
   holding `{xmin, xmax, payload}` chained versions consulted before the on-disk
   B-tree, or (b) Turso's approach — a dedicated MVCC store the VDBE cursor reads
   through. (a) is less invasive to the ported btree and is the recommended first
   cut for this fork.
3. **Snapshot-aware cursors.** `OP_Column`/`OP_Rewind`/`OP_Next` (already ported)
   gain a visibility filter: skip versions not visible to the current snapshot.
   This is a cursor-layer change, not a btree-format change — keeps blast radius
   contained, consistent with the fork's phase discipline.
4. **`BEGIN CONCURRENT` + commit-time conflict check.** On commit, verify no
   committed transaction wrote a row this txn's write-set also touched; abort with
   `SQLITE_BUSY_SNAPSHOT` on conflict (matching libSQL/Turso semantics).
5. **Version GC.** Reclaim versions older than the oldest live snapshot.

## Why it's sequenced last

Per [EXPERIMENT.md](../../EXPERIMENT.md), Phase 3 is intentionally the final,
most-invasive experiment. Phases 1 (frontend), 2 (VFS), and 4 (vector) are
isolated and shipped as working demos precisely so the lessons and the stable
base are in hand before touching storage — where byte-identity with SQLite is
permanently and deliberately abandoned.

## Non-goal reminder

None of this ever returns to `main`/`dev`. MVCC breaks file-format and
concurrency identity with upstream SQLite by design; it lives only on the
`sqlite-zturso` fork (which may graduate to its own repository).
