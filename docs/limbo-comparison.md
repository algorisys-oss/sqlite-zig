# sqlite-zig vs. Limbo — a feature & strategy comparison

A side-by-side comparison of this project (**sqlite-zig**) with **Limbo**
(`/home/rajesh/opensource/sqlite-ports/limbo-rs/limbo`), an effort to
re-implement SQLite in Rust. No code is shared between the two; this document
only compares goals, approaches, and feature coverage.

> **Important — Limbo *is* Turso.** "Limbo" was the original name of the project
> now called **Turso Database** (same repo, `github.com/tursodatabase/limbo` →
> `tursodatabase/turso`). The tree here is an **early snapshot — v0.0.19-pre.4,
> last commit 2025‑04‑08**. It is therefore *much* less complete than the
> current Turso. If you want the comparison against the current, renamed
> project, read [turso-comparison.md](turso-comparison.md); this document
> captures where the Rust rewrite stood at this earlier point and how far ahead
> the sqlite-zig port already was.

> Sources: Limbo's [`README.md`](file:///home/rajesh/opensource/sqlite-ports/limbo-rs/limbo/README.md)
> and [`COMPAT.md`](file:///home/rajesh/opensource/sqlite-ports/limbo-rs/limbo/COMPAT.md)
> (its self-reported matrix), and this repo's [PROGRESS.md](../PROGRESS.md) /
> [CLAUDE.md](../CLAUDE.md).

## TL;DR

| | **sqlite-zig** (this repo) | **Limbo** (≈ early Turso, v0.0.19, Apr 2025) |
|---|---|---|
| Language | Zig | Rust |
| Method | **Port** — transliterate upstream C, module by module | **Rewrite** — clean-room re-implementation |
| Spec / oracle | Upstream's own C source + its TCL test suite | Differential testing vs. SQLite; DST + Antithesis |
| Compatibility goal | **Byte-for-byte** behavioral identity with SQLite 3.54.0 | "Fully compatible with SQLite," opt-in extras — but still early |
| C ABI (`sqlite3_*`) | Preserved exactly (it's the migration boundary) | ~6 functions, mostly partial |
| New features | None by design | Async I/O (`io_uring`); vector/uuid/regexp/time extensions |
| Maturity | Faithful to a frozen upstream; correctness = tests pass | Work-in-progress; large gaps (no indexes/triggers/views/savepoints) |
| License | Public domain (follows SQLite) | MIT |

**The one-liner:** sqlite-zig aims to *be* SQLite in Zig (same code, same
behavior); Limbo is an early-stage from-scratch Rust engine that, at this
snapshot, runs basic `SELECT`/`INSERT`/`UPDATE`/`DELETE` with WAL and an
async-first VDBE, but is missing most of SQLite's surface.

## Why the approaches diverge

Same root cause as the Turso comparison — port vs. rewrite — so the same
dynamics apply (see [turso-comparison.md § Why the approaches diverge](turso-comparison.md#why-the-approaches-diverge)).
The difference here is only one of *degree*: this Limbo snapshot is a year-or-so
earlier in the rewrite's life, so the gaps are far wider than current Turso's.

- **sqlite-zig** inherits SQLite's full feature set because it ports the actual
  modules and validates each against the upstream TCL suite. At this writing it
  has **90 of ~105 translation units in Zig** — the entire active Linux engine
  plus FTS3/4/5, R*Tree, and sessions.

- **Limbo** (this snapshot) had implemented the read/write hot path and an
  async VDBE, but its own `COMPAT.md` "Limitations" list is blunt: **no indexes,
  no triggers, no views, no savepoints, no VACUUM** were supported yet, and no
  cross-process access.

## SQL language coverage

### Where they're roughly even

Core `SELECT` works in both: `WHERE`/`LIKE`/`GLOB`, `LIMIT`, `ORDER BY`,
`GROUP BY`/`HAVING`, most join types (`INNER`/`CROSS`/`LEFT OUTER`/`USING`/
`NATURAL`), `CASE`, `CAST`, `IS [NOT] [DISTINCT FROM]`, basic
`INSERT`/`UPDATE`/`DELETE`, and a solid scalar/math/aggregate/date/JSON function
library. Limbo's JSON and math coverage in particular is already broad.

### Where sqlite-zig is ahead (Limbo lists ❌/partial)

This list is long because the snapshot is early. Per Limbo's `COMPAT.md`:

| Feature | sqlite-zig | Limbo (this snapshot) |
|---|---|---|
| Secondary indexes (`CREATE INDEX` usable) | ✅ | ⛔️ "Indexes are not supported" (Limitations) |
| Triggers (`CREATE TRIGGER`, `INSTEAD OF`) | ✅ | ⛔️ not supported |
| Views (`CREATE VIEW`) | ✅ | ⛔️ not supported |
| `SAVEPOINT` / `RELEASE` | ✅ | ⛔️ not supported |
| `VACUUM` | ✅ | ⛔️ not supported |
| `ALTER TABLE` | ✅ | ❌ |
| `ANALYZE` | ✅ | ❌ |
| `ATTACH` / `DETACH` | ✅ | ❌ |
| `DROP TABLE` / `DROP INDEX` | ✅ | ❌ |
| `INSERT … ON CONFLICT` (UPSERT) / `REPLACE` | ✅ | ❌ |
| `RETURNING` | ✅ | ❌ |
| `ROLLBACK` | ✅ | ❌ (only `BEGIN`/`COMMIT`, partial) |
| `CREATE VIRTUAL TABLE` | ✅ | ❌ |
| `WITH RECURSIVE` (and any CTE writes) | ✅ | 🚧 no RECURSIVE/MATERIALIZED, SELECT-only |
| Subqueries: `IN (SELECT…)`, `EXISTS (SELECT…)` | ✅ | ❌ |
| `BETWEEN … AND …` | ✅ | ❌ |
| Window functions (`OVER`) | ✅ | ❌ ("incorrectly ignored") |
| `agg() FILTER (WHERE …)` | ✅ (one tracked bug) | ❌ ("incorrectly ignored") |
| `COLLATE` / custom collations | ✅ | ❌ |
| `REGEXP` / `MATCH` operators | ✅ | ❌ (regexp only as an extension fn) |
| `RAISE()` | ✅ | ❌ |
| `RIGHT JOIN` | ✅ | ❌ (LEFT only) |
| `%` modulo, `!<`, `!>` | ✅ | ❌ |
| `format()`, `likelihood()`, `unlikely()` | ✅ | ❌ |
| `timediff()` + full datetime modifiers | ✅ | 🚧 partial modifiers |

In short: at this snapshot the sqlite-zig port supports essentially the entire
SQLite language, while Limbo supported a basic DML/SELECT core without indexes,
triggers, views, savepoints, subqueries, or window functions.

### PRAGMA & introspection

sqlite-zig ports `pragma.c` wholesale (~66 production PRAGMAs, validated
0-error). Limbo's `COMPAT.md` lists only a handful supported (`cache_size`,
`journal_mode`, `legacy_file_format`, `page_count`, `pragma_list`, `table_info`,
partial `user_version`/`wal_checkpoint`); the large majority are ❌, including
`integrity_check`, `foreign_keys`, `synchronous`, `index_list`/`index_info`, and
`table_list`.

## C API (`sqlite3_*`) coverage

The starkest divide, and it follows from the strategies.

- **sqlite-zig**: the C ABI *is* the migration mechanism, so it is preserved in
  full — every hook, `create_function`/`create_collation`, serialize/deserialize,
  backup API, blob I/O, the vtab C API, loadable C extensions. A program linking
  `libsqlite3.a` can't tell it's Zig.

- **Limbo** (this snapshot): `COMPAT.md` lists a **6-function** surface and most
  are partial — `sqlite3_open` (partial), `sqlite3_close`, `sqlite3_prepare`
  (partial), `sqlite3_finalize`, `sqlite3_step`, `sqlite3_column_text`. There is
  effectively **no C-API UDF/collation/hook/backup/blob/vtab support** at this
  point; Limbo expects you to use its native Rust/JS/Python/Go/Java bindings
  instead.

## VDBE / bytecode engine

Both run a register-based bytecode VM modeled on SQLite's VDBE, but Limbo's was
**async-first**: its `COMPAT.md` shows opcodes split into explicit
`…Async`/`…Await` pairs (`InsertAsync`/`InsertAwait`, `NextAsync`/`NextAwait`,
`OpenReadAsync`, `RewindAsync`/`RewindAwait`, etc.) to drive `io_uring`. Many
synchronous opcodes are still ❌ (`Insert`, `Next`, `Prev`, `Delete`, `Found`,
`Last`, `Once`, `OpenWrite`, `Sort`, `String`, `Variable`, `IdxInsert`,
`IdxRowid`, `IntegrityCk`, `Savepoint`, `SetCookie`, the `To*` casts).

- **sqlite-zig** ports `vdbe.c` with **all 192 opcodes** handled and **identical
  opcode numbers** to upstream `opcodes.h`; `EXPLAIN`/`EXPLAIN QUERY PLAN` is
  byte-identical. There are no async opcode variants — the port reproduces
  SQLite's synchronous VDBE exactly.

The async/await-opcode design is the most interesting architectural divergence
in this snapshot, and it's a deliberate non-goal for a faithful port.

## Storage, journaling & concurrency

| | sqlite-zig | Limbo (this snapshot) |
|---|---|---|
| File format | SQLite 3.54.0, identical (ported btree/pager) | SQLite-compatible; opens SQLite files |
| Rollback journal modes | ✅ all (ported `pager.c`) | ❌ "Not Needed" — **WAL only** by design |
| WAL | ✅ ported `wal.c` | ✅ (its only journal mode) |
| Async I/O | No (synchronous VFS, ported `os_unix.c`) | **`io_uring`** on Linux; async-first VDBE |
| Multi-process access | SQLite's locking (ported) | ⛔️ not supported |
| Secondary indexes on disk | ✅ | ⛔️ not yet |

## Extensions

- **sqlite-zig** ports SQLite's bundled extensions: **FTS3/4/5**, **R*Tree +
  geopoly**, **session/changeset**, `carray`, the `dbpage`/`dbstat`/`pragma`
  vtabs, JSON. All byte-validated against the C amalgamation.

- **Limbo** ships its own Rust extensions, several with no SQLite equivalent:
  **UUID** v4/v7, **regexp** (sqlean-compatible, partial), **vector** search
  (libSQL-compatible — `vector`, `vector32/64`, `vector_distance_cos`), and
  **time** (sqlean-compatible, extensive). It has **no FTS**, **no R*Tree**, and
  **no session/changeset** at this snapshot. Conversely sqlite-zig has none of
  Limbo's vector/uuid/sqlean functions (not part of upstream SQLite).

## Features unique to Limbo (vs. a port)

- **Async I/O** via `io_uring` and an async/await-opcode VDBE.
- **Vector / UUID / sqlean-time / regexp** extension functions.
- **Multi-language bindings** in-tree — JS/WASM, Rust, Go, Python (`pylimbo`),
  Java.
- (Roadmap at this snapshot, *not yet implemented*: `BEGIN CONCURRENT`,
  integrated vector search, better `ALTER`. These largely landed later, under
  the Turso name — see [turso-comparison.md](turso-comparison.md).)

## Features unique to sqlite-zig (vs. this Limbo snapshot)

Almost the entire SQLite feature set beyond the basic DML core: indexes,
triggers, views, savepoints, VACUUM, ALTER, ANALYZE, ATTACH, UPSERT, RETURNING,
subqueries, BETWEEN, window functions, custom collations, the full C ABI,
FTS3/4/5, R*Tree, sessions, and behavioral identity validated by SQLite's own
TCL suite.

## Testing philosophy

- **sqlite-zig** — the upstream **TCL `testfixture` suite is the spec**; each
  port must pass it 0-error with the Zig object swapped in, plus a Zig-native
  gate.
- **Limbo** — **differential testing** against SQLite, DST, and Antithesis; it
  also vendors a `sqlite3/` tree and runs a subset of SQLite's tests. As a
  from-scratch engine its bar is "behaves like SQLite on observed inputs."

## When to use which

- **Choose sqlite-zig** if you need a **drop-in libsqlite3 replacement** with
  exact behavioral compatibility, the full C API, indexes/triggers/views/
  savepoints, SQLite's own extensions, or you're studying SQLite internals via a
  memory-safe 1:1 reimplementation.

- **Choose Limbo/Turso** if you want the Rust rewrite's trajectory — async I/O
  now, and (in the renamed Turso) MVCC, CDC, vector search, encryption — with
  first-class bindings for many languages, accepting an evolving and (at *this*
  snapshot, quite partial) compatibility surface. For anything current, use
  Turso, not this snapshot.

## Scope & status snapshot

- **sqlite-zig**: Phase 1, **90 of ~105 TUs ported**; entire active Linux engine
  + FTS3/4/5 + R*Tree + session in Zig. See [PROGRESS.md](../PROGRESS.md) and
  [not-migrated.md](not-migrated.md).

- **Limbo**: **v0.0.19-pre.4 (2025‑04‑08)**, work-in-progress; basic
  DML/SELECT + WAL + async VDBE, but no indexes/triggers/views/savepoints/VACUUM
  yet. Later renamed and continued as **Turso** —
  [turso-comparison.md](turso-comparison.md) compares against that current
  state.

---

*This is a documentation-only comparison; no code in either project was
modified. Limbo details reflect the v0.0.19-pre.4 snapshot at the path above and
do not represent the current Turso project.*
</content>
