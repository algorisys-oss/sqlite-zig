# CLAUDE.md — sqlite-zig

Guidance for Claude (and other agents) working in this repository.

## What this project is

A from-scratch **migration of SQLite from C to Zig**. The goal is a Zig
implementation of the SQLite database engine that is behaviorally compatible
with upstream SQLite and passes its test suite.

This directory (`/home/rajesh/lab/ai-port/sqlite-zig`) is currently empty
except for planning docs. Implementation has not started; see [plan.md](plan.md)
for the staged approach.

## Reference sources (read-only — never edit)

| What | Path | Notes |
|---|---|---|
| SQLite C source | `/home/rajesh/opensource/sqlite` | v3.54.0, ~219k LOC of C/H in `src/`. Public domain. Uses **Fossil**, not Git. |
| Zig compiler/stdlib | `/home/rajesh/opensource/ziglang/zig` | Build/run toolchain reference. |
| Zig toolchain in PATH | `zig` (`~/.asdf/shims/zig`) | `0.17.0-dev.644+3de725074`. |

Treat both source trees as **immutable references**. All new work lands here.

## SQLite architecture (the thing we are porting)

```
SQL text
  → tokenizer        src/tokenize.c
  → parser           src/parse.y (Lemon grammar → generated parse.c)
  → code generator   src/build.c, select.c, insert.c, update.c, delete.c, expr.c
  → optimizer        src/where*.c
  → VDBE (bytecode)  src/vdbe.c, vdbeaux.c   (the virtual machine that runs queries)
  → B-Tree           src/btree.c             (largest file, ~406 KB)
  → Pager            src/pager.c             (page cache + transactions)
  → WAL              src/wal.c               (write-ahead log)
  → VFS / OS         src/os_unix.c, os_win.c (OS abstraction layer)
```

- Master internal header: `src/sqliteInt.h`. Subsystem headers: `vdbeInt.h`,
  `btreeInt.h`, `whereInt.h`, `pager.h`, `btree.h`.
- Public API template: `src/sqlite.h.in` → generates `sqlite3.h`.
- **Generated files** (never hand-port from these — port from the generators or
  the grammar): `sqlite3.h`, `parse.c`/`parse.h` (from `parse.y` via Lemon),
  `opcodes.h`/`opcodes.c` (from `vdbe.c` via `tool/mkopcodeh.tcl`),
  `keywordhash.h`, the amalgamation `sqlite3.c`.

## Core strategy (see plan.md for detail)

We do **not** attempt a big-bang rewrite. The approach:

1. Stand up a Zig build that compiles upstream C (via `zig cc` / `@cImport`),
   producing a working `sqlite3` we can test against from day one.
2. Port subsystem-by-subsystem, keeping the **C ABI** at module boundaries so
   ported-Zig and not-yet-ported-C coexist in one binary.
3. After every port, run the SQLite test suite. **The C test suite is the
   spec** — a port is "done" only when tests still pass.
4. Port bottom-up along the dependency graph (utilities → pager → btree →
   VDBE → SQL front-end) so each layer rests on already-ported layers.

## Testing = the definition of correctness

SQLite's tests are TCL scripts run through a `testfixture` interpreter.

```bash
# in the upstream C tree, to understand the baseline:
./configure --dev && make testfixture
test/testrunner.tcl          # quick suite
test/testrunner.tcl full     # full suite
make devtest                 # fast representative subset
```

For this project, every ported component must keep `make devtest` (or the
equivalent harness we build) green. Prefer porting in slices small enough to
validate. Never mark a migration step complete without a passing test run, and
report the actual test output.

## Token tracking (required)

[tokens.txt](tokens.txt) records **actual** per-prompt token usage — real API
figures (input + cache creation + cache read + output), with real start/end
times, **not** chars/4 estimates. The numbers come from the Claude Code session
transcript, parsed by [tools/token_usage.py](tools/token_usage.py):

```bash
python3 tools/token_usage.py          # human-readable table
python3 tools/token_usage.py --tsv    # machine-readable
```

Refresh `tokens.txt` from the script's output at/near the **end of a session**
(the transcript only records a turn's full cost once the turn completes, so the
in-progress turn can't be self-counted — capture it next session). The script
reads the newest `*.jsonl` in
`/home/rajesh/.claude/projects/-home-rajesh-lab-ai-port-sqlite-zig/`; it is
session-specific. Follow-up messages sent mid-turn are queued into that turn by
the harness, so their cost folds into it — list them under the turn.

## Conventions

- SQLite source is **public domain** — preserve the blessing comment if you
  copy structure, but add no license headers.
- Match idiomatic Zig (errors as error unions, `std.mem.Allocator`, slices over
  raw ptr+len, `comptime` where C used macros) rather than transliterating C
  line-for-line — *except* at ABI boundaries that must stay C-compatible.
- Keep `plan.md` updated as the living source of truth for progress. Check off
  steps as they land; record deviations.

## Build (this project)

Phase 0 foundation is in place. From the project root:

```bash
zig build                      # build static libsqlite3.a + sqlite3 shell (split build)
zig build test                 # functional regression battery (test/functional.sql)
zig build smoke                # one-query end-to-end check
zig build -Damalgamation=true  # build the single-file amalgamation instead (sanity check)
zig-out/bin/sqlite3 :memory: "select sqlite_version();"
```

- **Split build (default):** compiles each C translation unit from
  `vendor/tsrc/` separately, listed in `vendor/tu.txt`. This is what enables the
  migration: to port a module, write `src/<name>.zig` exporting the same C-ABI
  symbols, then add `"<name>.c"` to `ported_modules` in [build.zig](build.zig).
  The C file is dropped and the Zig object linked in its place.
- **Vendored sources** (`vendor/`) are generated from upstream (see
  [PROGRESS.md](PROGRESS.md) for how to regenerate). The `build/` dir is the
  out-of-tree generator workspace and is gitignored.
- Compile-time `SQLITE_*` flags live in `sqlite_flags` in build.zig; they mirror
  the upstream `--dev` configure.

See [PROGRESS.md](PROGRESS.md) for current status and the resume point.
