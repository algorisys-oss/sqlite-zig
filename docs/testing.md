# Testing & validation

How correctness is established for the C→Zig port. Read alongside
[architecture.md](architecture.md) (the swap mechanism), [../plan.md](../plan.md)
(roadmap) and [../PROGRESS.md](../PROGRESS.md) (status).

The guiding rule (from [../CLAUDE.md](../CLAUDE.md)): **SQLite's own test suite is
the spec.** A port is "done" only when the tests still pass. There are three
layers of validation, cheapest first.

## 1. Functional regression battery — `zig build test`

The fast gate every change must keep green. Runs
[../test/functional.sql](../test/functional.sql) and compares output
byte-for-byte against the golden file. Exercises core DML, the WHERE/index
optimizer, transactions, joins, triggers, math/JSON functions, FTS5, and R-Tree.

```bash
zig build test                       # split build (the ported-Zig path)
zig build test -Damalgamation=true   # pure-C amalgamation (sanity baseline)
```

Exit code 0 = pass. Run `zig build sample` too — it builds + integrity-checks the
sample blog database (FTS5 + triggers + foreign keys) through the public API.

## 2. Differential against pure C

For any subsystem under suspicion, run the same workload through both builds and
diff the output (or the on-disk bytes). The amalgamation build (`-Damalgamation`)
is 100% upstream C and makes an exact oracle:

```bash
SQL="...your workload..."
zig build                 && zig-out/bin/sqlite3 :memory: "$SQL" > /tmp/zig.txt
zig build -Damalgamation=true && zig-out/bin/sqlite3 :memory: "$SQL" > /tmp/c.txt
diff /tmp/c.txt /tmp/zig.txt && echo IDENTICAL
```

This is how FTS5 was validated to be **byte-identical** to upstream across
insert/delete/update, merge/optimize, MATCH (AND/OR/NOT/phrase/prefix/absent),
`snippet`, `bm25` ranking, and `fts5vocab`. Diffing the `%_data` blobs
(`SELECT id, quote(block) FROM <fts>_data`) localizes a bug to the *writer* vs
the *reader*: identical bytes + wrong result ⇒ a read-side bug.

## 3. Upstream TCL `testfixture` suite

SQLite's authoritative suite is ~thousands of TCL `.test` files driven by a
`testfixture` interpreter (the library + TCL + test extensions). We run them
**with the ported Zig modules linked in**, so they assert against our engine.

This is wired in [../tools/tcltest.sh](../tools/tcltest.sh) using the vendored
TCL 8.6 headers (`vendor/tcl/`) + the system `libtcl8.6` — no `tcl-dev` package
needed, and the upstream tree stays untouched.

```bash
tools/tcltest.sh                          # baseline: upstream C testfixture, sample set
tools/tcltest.sh --zig                    # same, but our Zig objects swapped in
tools/tcltest.sh --zig fts5simple fts5aa  # named suites (test/ and ext/*/test/)
```

### How `--zig` works

1. Configure the upstream tree out-of-tree (`build/gen/`) with `--dev` and the
   vendored TCL, then `make testfixture` to capture the real link command.
2. `zig build test-objs -Dtestfixture=true` emits each `src/<m>.zig` as an object
   compiled in the **testfixture config** (`SQLITE_DEBUG` + `SQLITE_TEST` via the
   `config` module), so one source serves both prod and the `--dev` fixture.
3. Replay the captured link command with each `src/<m>.c` replaced by its Zig
   `<m>.o`, producing `testfixture_zig`.
4. Run the requested `.test` files; report each file's "N errors out of M tests".

Test files are located in `test/` plus the per-extension dirs
(`ext/fts5/test`, `ext/rtree`, `ext/session`, `ext/rbu`, `ext/fts3`). Each
invocation relinks `testfixture_zig`, so **batch several suite names together**.

### Testfixture-only symbols

The `--dev` config compiles test hooks that prod does not. Where the C lived in a
ported module, the Zig port must export the same test-only symbol, gated on the
config flag so prod is unaffected — e.g. `src/os.zig` exports the
`sqlite3_io_error_*` counters under `config.sqlite_test`, and `src/main.zig`
exports `sqlite3OSTrace` (a `SQLITE_HAVE_OS_TRACE` global the harness reads). A
missing one shows up as an `undefined reference` at the `testfixture_zig` link
step; add an `@export(&v, .{ .name = "..." })` inside the matching
`if (config.sqlite_test)` / `if (config.sqlite_debug)` block.

## FTS5 validation results

FTS5 (the last active module, ported as `src/fts5*.zig`) is confirmed correct by
both the differential (byte-identical to C) and the upstream TCL suites run
against `testfixture_zig`:

| Suite | Tests | Errors |
|---|---|---|
| fts5simple | 86 | 0 |
| fts5aa | 1427 | 0 |
| fts5ab | 287 | 0 |
| fts5ac | 713 | 0 |
| fts5delete | 23 | 0 |
| fts5merge | 48 | 0 |
| fts5rowid | 30 | 0 |
| fts5integrity | 67 | 0 |
| fts5rank | 43 | 0 |
| fts5prefix | 355 | 0 |
| fts5update | 60 | 0 |
| **Total** | **~3,139** | **0** |

Extend coverage by naming more suites, e.g.
`tools/tcltest.sh --zig fts5ad fts5af fts5corrupt fts5fault1`.

## Bug patterns this caught

The validation layers above repeatedly surfaced the same C→Zig porting hazards.
When a ported module misbehaves, suspect these first:

- **ABI return-width mismatch.** A C function returning `i16`/`u8` declared
  `extern ... c_int` in Zig: x86-64 leaves the upper return-register bits
  undefined for sub-32-bit returns, so the caller reads garbage. Declare the
  exact C return type. (Hit `sqlite3Fts5GetVarint` and
  `sqlite3TableColumnToStorage` — the latter turned a `-1` rowid into `65535`,
  segfaulting `NEW.rowid` in triggers.)
- **Wrong-width field write.** Writing an `i64` field as `c_int` clears only the
  low half. (Hit `Vdbe.iCurrentTime` → `datetime('now')` drifted after the first
  call.)
- **Checked vs truncating cast.** C's `(u8)x` truncates; Zig's `@intCast` panics
  if it doesn't fit. Port truncating casts as `@truncate`. (Hit `allocateIndexInfo`
  for an FTS5 aux-function constraint.)
- **`goto` modeled with the handler inside the wrong labeled block**, so
  `break :label` skips it. (Hit `fts5LeafSeek`'s `search_failed`.)
- **Force-unwrapping a legitimately-null pointer** that C passes through to a
  size-guarded callee. (Hit `fts5PoslistBlob`.)
- **Hardcoded constant ≠ the C header value**, and **struct field offsets** —
  validated by `tools/offsets.c` → `src/c_layout.zig` comptime asserts.
