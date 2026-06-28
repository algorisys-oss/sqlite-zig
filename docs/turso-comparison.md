# sqlite-zig vs. Turso — a feature & strategy comparison

A side-by-side comparison of this project (**sqlite-zig**) with **Turso**
(`/home/rajesh/opensource/turso`), another effort to re-implement SQLite in a
modern systems language. No code is shared between the two; this document only
compares their goals, approaches, and feature coverage.

> Sources: Turso's [`README.md`](file:///home/rajesh/opensource/turso/README.md)
> and [`COMPAT.md`](file:///home/rajesh/opensource/turso/COMPAT.md) (its
> self-reported compatibility matrix), and this repo's
> [PROGRESS.md](../PROGRESS.md) / [CLAUDE.md](../CLAUDE.md). Turso's status is a
> moving target — treat its ✅/🚧/❌ marks as a snapshot.

## TL;DR

The two projects share a tagline ("SQLite, in a memory-safe language") but are
philosophically opposite:

| | **sqlite-zig** (this repo) | **Turso** |
|---|---|---|
| Language | Zig | Rust |
| Method | **Port** — transliterate upstream C, module by module | **Rewrite** — clean-room re-implementation |
| Spec / oracle | Upstream's own C source + its TCL test suite | Differential testing vs. SQLite; DST + Antithesis |
| Compatibility goal | **Byte-for-byte** behavioral identity with SQLite 3.54.0 | "SQLite-compatible" file format & dialect; deviations are bugs, new features are opt-in |
| C ABI (`sqlite3_*`) | Preserved exactly — it's the migration boundary | Partial shim; many functions stubbed or absent |
| New features | None by design (a port has nothing to add) | Many: MVCC, CDC, async I/O, vector, encryption, DBSP |
| Maturity stance | Faithful to a frozen upstream; correctness = tests pass | BETA; "not yet production" but powers some prod apps |
| License | Public domain (follows SQLite) | MIT |

**The one-liner:** sqlite-zig aims to *be* SQLite (same code, same behavior, in
Zig); Turso aims to *replace* SQLite (new code, new engine, mostly-compatible
surface, plus features SQLite doesn't have).

## Why the approaches diverge

This is the root cause of every difference below.

- **sqlite-zig** keeps the upstream C ABI at every module boundary, so ported
  Zig and not-yet-ported C coexist in one binary. The C test suite *is* the
  specification — a module is "done" only when SQLite's own TCL tests still
  pass with the Zig object swapped in. Because the engine is the same algorithms
  reimplemented in Zig, it inherits SQLite's full feature set "for free": FTS3/4/5,
  R*Tree, sessions, the whole VDBE opcode set, every PRAGMA, every C API function.
  The hard part isn't *features*, it's *fidelity* (struct layouts, opcode
  numbers, bitfields — see [architecture.md](architecture.md)).

- **Turso** is a from-scratch engine. It owns its own parser, its own VDBE-like
  bytecode VM, its own B-tree/pager/WAL. That freedom lets it add things SQLite
  can't easily do (MVCC concurrency, async I/O, incremental views), but it also
  means every SQLite feature must be re-built and re-validated one at a time —
  so its compatibility matrix has real gaps (no UDFs via C API, no rollback
  journal, partial window functions, partial WITHOUT ROWID, etc.).

## SQL language coverage

### Where they're roughly even

Both handle the everyday SQL surface: `CREATE/DROP TABLE|INDEX|VIEW|TRIGGER`,
`INSERT/UPDATE/DELETE`, `SELECT` with all join types, `GROUP BY`/`HAVING`,
`ORDER BY`/`LIMIT`, subqueries, `INSERT ... ON CONFLICT` (UPSERT), `RETURNING`,
`SAVEPOINT`, `ALTER TABLE`, `ANALYZE`, `ATTACH`, `STRICT` tables, CTEs (non-
recursive), CHECK/UNIQUE/FK constraints, and a large scalar/aggregate/math/
date/JSON function library.

sqlite-zig has these because it ports the modules that implement them
(`build.zig`, `select.zig`, `insert.zig`, `expr.zig`, `where*.zig`, `func.zig`,
`json.zig`, etc.) and validates against the upstream tests for each.

### Where sqlite-zig is ahead (full SQLite parity)

These are first-class in SQLite, so the port has them; Turso's `COMPAT.md` marks
them partial or missing:

| Feature | sqlite-zig | Turso (per COMPAT.md) |
|---|---|---|
| `WITH RECURSIVE` | ✅ ported (`select.zig` recursive CTEs) | ❌ not yet supported |
| Window functions (full) | ✅ `window.zig` (rank, lag/lead, ntile, frame specs, …) | 🚧 only `row_number()` + aggregate `OVER`; many funcs missing; `FILTER … OVER` panics |
| `WITHOUT ROWID` | ✅ full (the port's btree handles it) | 🚧 experimental, effectively insert-only |
| Generated columns | ✅ (`STORED` + `VIRTUAL`) | 🚧 virtual-only, behind `--experimental` flag |
| `agg() FILTER (WHERE …)` | ✅ (one known sibling-aggregate bug, tracked) | ❌ not supported |
| `INSTEAD OF` triggers (views) | ✅ | ❌ errors with "no such table" |
| Plain in-place `VACUUM` | ✅ (`vacuum.zig`) | 🚧 experimental; `VACUUM INTO` works |
| Custom collations | ✅ | 🚧 not supported (unknown collation silently ignored) |
| `%` modulo / `!<` / `!>` operators | ✅ | ❌ unsupported |
| Rowid `MATCH` operator (generic) | ✅ | ❌ |

### PRAGMA & introspection

sqlite-zig ports `pragma.c` wholesale — all ~66 production PRAGMAs (75 under
`--dev`), validated `pragma`/`pragma2`/`pragma3`/`pragma4` 0-error. Turso
implements a curated subset (`COMPAT.md` lists ~40 supported, many ❌/partial:
no `optimize`, `mmap_size`, `secure_delete`, `wal_autocheckpoint`,
`data_version`, `recursive_triggers`, etc.) and adds **Turso-only** PRAGMAs that
have no SQLite equivalent (`capture_data_changes_conn`, `cipher`/`hexkey`,
`mvcc_checkpoint_threshold`, `require_where`/`i_am_a_dummy`).

## C API (`sqlite3_*`) coverage

This is the starkest divide and follows directly from the two strategies.

- **sqlite-zig**: the C ABI is the *migration mechanism*, so it is preserved in
  full. `main.c` is ported with ~100 exports; every hook
  (`commit/rollback/update/preupdate/wal`), `create_function`/`create_collation`,
  `serialize`/`deserialize`, the backup API, `blob_*` I/O, etc., exist because
  the C TUs that implement them are linked (ported or not-yet-ported C). The
  goal is that a program linking `libsqlite3.a` cannot tell the difference.

- **Turso**: re-implements only the slice its bindings need. From `COMPAT.md`,
  large areas are **stubbed or absent**:
  - **User-defined functions**: `sqlite3_create_function*` ❌, all
    `sqlite3_result_*` ❌/stub, `sqlite3_aggregate_context` ❌ — no C-API UDFs.
  - **Collations** via C API: ❌.
  - **Backup API**: all five functions stubbed.
  - **BLOB incremental I/O** (`sqlite3_blob_*`): stubbed.
  - **Hooks**: `commit/rollback/update/preupdate/wal_hook` ❌; `trace_v2`,
    `set_authorizer` stubbed.
  - **Virtual-table C API** (`sqlite3_create_module`, `declare_vtab`,
    `vtab_*`): ❌ — Turso's vtabs are internal/Rust, not via the public ABI.
  - **Loadable C extensions** (`.so`/`.dll`): ❌ — only Turso-native (Rust)
    extensions load.
  - **Serialize/deserialize**, `sqlite3_config`, `db_config`, most
    `sqlite3_status*`, `mprintf` family: ❌/stub.
  - Reports `sqlite3_libversion()` as **"3.42.0"** (sqlite-zig tracks **3.54.0**).

If your program drives SQLite through its C API (ORMs, language bindings that
wrap libsqlite3, extensions), sqlite-zig is a drop-in and Turso generally is
not — Turso expects you to use *its* native bindings instead.

## VDBE / bytecode engine

Both run a register-based bytecode VM modeled on SQLite's VDBE.

- **sqlite-zig** ports `vdbe.c` (the ~9.5k-LOC interpreter) with **all 192
  opcodes** handled, plus `vdbeaux`/`vdbeapi`/`vdbemem`/`vdbesort`. Opcode
  numbers are kept identical to `opcodes.h` (a wrong opcode number was one of the
  integration bugs found and fixed). `EXPLAIN`/`EXPLAIN QUERY PLAN` output is
  byte-identical to upstream.

- **Turso** has its own opcode set (similar names, its own numbering and
  semantics). `COMPAT.md` lists most opcodes ✅ but several ❌/partial
  (`Clear`, `IfZero`, `IsUnique`, `Param`, `Permutation`, `Sort`, `RowKey`,
  `SCopy`, `Seek`, `Trace`, temp-DB paths on `CreateBTree`/`Pagecount`/
  `ReadCookie`). Because the VM is new, EXPLAIN output is *not* expected to match
  SQLite byte-for-byte.

## Storage, journaling & concurrency

| | sqlite-zig | Turso |
|---|---|---|
| File format | SQLite 3.54.0, identical (ported btree/pager) | SQLite-compatible; opens SQLite files |
| Rollback journal modes (delete/truncate/persist/memory) | ✅ all (ported `pager.c`) | ❌ "Not Needed" — **WAL only** by design |
| WAL | ✅ ported `wal.c` | ✅ (its primary/only journal mode) |
| Concurrency model | SQLite's (single writer, reader/writer locks) | **MVCC** via `BEGIN CONCURRENT` — multiple concurrent writers |
| Async I/O | No (SQLite's synchronous VFS, ported `os_unix.c`) | **`io_uring`** on Linux; async-first design |
| Multi-process WAL | SQLite's shm protocol (ported) | `.tshm` sidecar for cross-process WAL coordination |

Turso's headline architectural bets — **MVCC** (`core/mvcc`) and **async I/O** —
are deliberately *non-goals* for sqlite-zig: a faithful port reproduces SQLite's
concurrency and synchronous VFS exactly, since changing them would break
behavioral identity.

## Full-text search

- **sqlite-zig** ports SQLite's own FTS engines: **FTS3/FTS4** (`fts3*.zig`) and
  **FTS5** (`fts5.zig` + 14 modular sub-files), validated byte-identical to the
  C amalgamation including bm25, highlight/snippet, `fts5vocab`, porter/unicode61
  tokenizers, and `integrity_check`.

- **Turso** does **not** implement SQLite's FTS3/4/5. Instead it offers a
  *different* full-text search built on the **Tantivy** library, with
  Turso-specific syntax (`CREATE INDEX … USING fts`, `fts_match()`,
  `fts_score()`, `fts_highlight()`). `snippet()` is absent. So FTS exists in both
  but they are **not compatible** — queries written for SQLite FTS won't run on
  Turso and vice-versa.

## Extensions

- **sqlite-zig** ports the bundled SQLite extensions as-is: **R*Tree + geopoly**
  (`rtree.zig`), **session/changeset** (`sqlite3session.zig`), `carray`, the
  `dbpage`/`dbstat`/`pragma` vtabs, JSON. Flag-inactive ones (ICU, RBU) compile
  to nothing exactly as upstream.

- **Turso** ships its own Rust extension set, several with no SQLite equivalent:
  **vector search** (`vector*`, libSQL-compatible), **UUID** v4/v7, **regexp**
  (sqlean-compatible), **time** (sqlean-compatible), **percentile/median**,
  **CSV** vtab, `generate_series`. It has **no R*Tree** and **no SQLite
  session/changeset** extension. Conversely, sqlite-zig has none of Turso's
  vector/uuid/sqlean functions (they aren't part of upstream SQLite).

## Features unique to Turso (no counterpart in a port)

A faithful port can't have these — they're new engine capabilities:

- **`BEGIN CONCURRENT` + MVCC** — multiple concurrent writers.
- **Change Data Capture (CDC)** — real-time change tracking (`PRAGMA
  capture_data_changes_conn`).
- **Encryption at rest** (experimental) — `PRAGMA cipher`/`hexkey`.
- **Incremental computation via DBSP** (`core/incremental`) — incremental view
  maintenance / query subscriptions.
- **Async I/O** (`io_uring`).
- **First-class multi-language bindings** — Go, JavaScript/WASM, Java (JDBC),
  .NET, Python (`pyturso`), Rust — all in-tree.
- **Built-in MCP server** — `tursodb db.sqlite --mcp` exposes the DB to AI
  assistants over JSON-RPC (9 tools).
- **`require_where`** safety pragma (refuses unguarded `UPDATE`/`DELETE`).

## Features unique to sqlite-zig (vs. Turso today)

- **Full C-ABI drop-in** for `libsqlite3` (UDFs, collations, hooks, backup, blob
  I/O, vtab C API, loadable C extensions, serialize/deserialize).
- **SQLite FTS3/4/5** (byte-compatible), **R*Tree/geopoly**, **session/
  changeset**.
- **Rollback journal** modes; full **window functions**; **`WITH RECURSIVE`**;
  full **`WITHOUT ROWID`**; stored generated columns; custom collations.
- **Behavioral identity** with a specific upstream version (3.54.0), validated by
  SQLite's own TCL suite rather than by differential sampling.

## Testing philosophy

- **sqlite-zig** — the upstream **TCL `testfixture` suite is the spec**. Each
  port is relinked into testfixture (`tools/tcltest.sh --zig`) and must pass
  0-error; plus a Zig-native gate (`zig build test`, `engine_test.zig`) and a
  functional SQL battery. Correctness is defined as "SQLite's own tests still
  pass."

- **Turso** — **differential testing** against SQLite, a native **Deterministic
  Simulation Testing** suite, and **Antithesis**. It also runs a subset of
  SQLite's TCL tests, but as a from-scratch engine its bar is "behaves like
  SQLite on observed inputs," not "runs SQLite's code."

## When to use which

- **Choose sqlite-zig** if you need a **drop-in libsqlite3 replacement** with
  exact behavioral compatibility, the full C API, SQLite's own extensions
  (FTS5/R*Tree/sessions), or you're studying how SQLite works internally with a
  memory-safe reimplementation that stays 1:1 with the C.

- **Choose Turso** if you want **new capabilities** — concurrent writers (MVCC),
  async I/O, CDC, vector search, encryption, incremental views — and first-class
  bindings for many languages, and you can live with a partial C API and an
  evolving compatibility surface.

## Scope & status snapshot

- **sqlite-zig**: Phase 1, **90 of ~105 translation units ported to Zig**; the
  entire active Linux engine + FTS3/4/5 + R*Tree + session are Zig. The
  unported remainder is non-portable for a Linux build (generated `parse.c`/
  `opcodes.c`, Windows-only files, flag-inactive stubs). See
  [PROGRESS.md](../PROGRESS.md) and [not-migrated.md](not-migrated.md).

- **Turso**: self-described **BETA**, "not yet production" for mission-critical
  use though it powers some production apps. Compatibility is "partially
  supported" for both the SQL dialect and the C API per its own `COMPAT.md`.

---

*This is a documentation-only comparison; no code in either project was
modified. Turso details reflect its repository state at the time of writing and
will drift as it evolves.*
</content>
</invoke>
