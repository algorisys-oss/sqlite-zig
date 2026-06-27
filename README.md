# sqlite-zig

An incremental migration of [SQLite](https://sqlite.org) from C to
[Zig](https://ziglang.org). The goal is a Zig implementation of the SQLite
database engine that stays behaviorally compatible with upstream SQLite and
passes its test suite — reached **one module at a time**, never as a big-bang
rewrite.

> **Status:** Phase 1 — **90 modules ported to Zig**, including the whole active
> Linux engine: pager, B-tree, VDBE, the SQL compiler (tokenizer → parser glue →
> code generator → optimizer), the OS/VFS layer, and every active extension
> (R-Tree/Geopoly, Session, FTS3/4, **FTS5**, JSON). The Zig build compiles
> upstream SQLite **v3.54.0** into `libsqlite3.a` + the `sqlite3`/`sqlite-zig`
> CLI, gated by a green test step. Output is byte-identical to upstream C across
> the regression battery. The only `.c` files still compiled are non-portable for
> a Linux engine: the Lemon-generated `parse.c`/`opcodes.c` (we port from the
> generators, not the generated files), the Windows VFS, and flag-inactive
> alternates. See [PROGRESS.md](PROGRESS.md) and [plan.md](plan.md).

## How it works

SQLite is built from its individual C translation units (not the amalgamation),
so each file can be replaced independently. To port a module we add a Zig file
that exports the same C-ABI symbols and drop the corresponding `.c` — the rest
of the engine keeps linking against it unchanged. This lets a mixed C/Zig binary
build and pass tests at every step.

```
SQL → tokenizer → parser → code-gen → optimizer → VDBE → B-tree → pager → WAL → VFS
                         (porting proceeds bottom-up: VFS/storage first, SQL front-end last)
```

## Requirements

- **Zig** `0.17.0-dev.644+3de725074` (the build uses the module-based build API).
- A system **zlib** and **libm** (linked by the shell).
- Only to *regenerate* vendored sources from upstream: `tclsh`, `make`, a C
  compiler, and the upstream SQLite tree. Day-to-day building needs only Zig —
  the generated sources are vendored under [`vendor/`](vendor/).

## Build

```bash
zig build                      # static libsqlite3.a + sqlite3 shell  → zig-out/
zig build run                  # launch the interactive shell
zig-out/bin/sqlite3 :memory: "select sqlite_version();"
```

Build modes:

| Command | What it builds |
|---|---|
| `zig build` | **Split build** (default) — each C TU compiled separately; this is the mode that supports porting. |
| `zig build -Damalgamation=true` | Single-file amalgamation build — a fast sanity check; cannot be swapped file-by-file. |
| `zig build -Doptimize=ReleaseFast` | Optimized build (default is Debug). |

Artifacts land in `zig-out/bin/sqlite3`, `zig-out/bin/sqlite-zig`, and
`zig-out/lib/libsqlite3.a`.

## Using the `sqlite-zig` executable

`zig build` installs the command-line shell under **two** names:
`zig-out/bin/sqlite3` and `zig-out/bin/sqlite-zig`. They are the same binary —
the standard SQLite shell linked against this project's ported-Zig
`libsqlite3.a` — so every query runs through the Zig engine. The `sqlite-zig`
name makes it obvious which build you are invoking next to a stock `sqlite3`.

```bash
# one-off query against an in-memory database
zig-out/bin/sqlite-zig :memory: "select sqlite_version();"        # -> 3.54.0

# open (or create) a database file and run statements
zig-out/bin/sqlite-zig blog.db "create table t(a,b); insert into t values(1,'x');"
zig-out/bin/sqlite-zig blog.db "select * from t;"

# interactive shell — dot-commands work as in upstream
zig-out/bin/sqlite-zig blog.db
sqlite> .tables
sqlite> .schema t
sqlite> .mode box
sqlite> select * from t;
sqlite> .quit

# read a SQL script
zig-out/bin/sqlite-zig blog.db ".read schema.sql"

# pipe SQL in on stdin
echo "select count(*) from t;" | zig-out/bin/sqlite-zig blog.db

# `zig build run` launches the same shell interactively
zig build run
```

Files it writes are bit-for-bit standard SQLite databases — a stock `sqlite3`
can read a database created by `sqlite-zig` and vice-versa:

```bash
zig-out/bin/sqlite-zig t.db "create table x(a); insert into x values(1),(2);"
sqlite3 t.db "select count(*) from x;"   # stock sqlite3 reads our file -> 2
```

## Examples

[`examples/`](examples/) holds standalone Zig programs that drive the ported
engine through the C API. The headline one is an interactive blog **CRUD**
terminal (FTS5 search, triggers, foreign-key cascades):

```bash
zig build sample     # build sampledata/blog.db (schema + seed) from Zig
zig build example    # interactive CRUD REPL over sampledata/blog.db
```

See [examples/README.md](examples/README.md) for the command list and a sample
session.

## How to verify / test

### 1. Quick gate (what CI / every port must keep green)

```bash
zig build test
```

Runs the functional regression battery in
[`test/functional.sql`](test/functional.sql) and compares output byte-for-byte
against [`test/functional.expected`](test/functional.expected). It exercises
core DML, the index/WHERE optimizer, transaction rollback, joins, triggers,
math functions, JSON, FTS5 full-text search, and the R-Tree spatial index.
**Exit code 0 = pass.** Run it in both modes to be sure:

```bash
zig build test                       # split build
zig build test -Damalgamation=true   # amalgamation build
```

### 2. One-line smoke check

```bash
zig build smoke      # builds, runs a single query, asserts the exact output
```

### 3. Manual / interactive verification

```bash
zig-out/bin/sqlite3 :memory: ".read test/functional.sql"   # see the battery output
zig-out/bin/sqlite3 mydb.db                                # open a real database file
zig-out/bin/sqlite3 :memory: "select sqlite_version();"    # should print 3.54.0
```

Round-trip compatibility with stock SQLite (the on-disk format must match):

```bash
zig-out/bin/sqlite3 t.db "create table x(a); insert into x values(1),(2);"
sqlite3 t.db "select count(*) from x;"   # stock sqlite3 reads our file → 2
```

### 4. Updating the test battery

When a change alters expected output (or you add cases), regenerate the golden
file:

```bash
zig-out/bin/sqlite3 :memory: ".read test/functional.sql" > test/functional.expected
```

### Upstream TCL testfixture suite

SQLite's own test suite runs through `testfixture` (a TCL interpreter + the
library + test extensions). It's wired here via vendored TCL 8.6.14 headers
(`vendor/tcl/`) + the system `libtcl8.6` — no `tcl-dev` package needed:

```bash
tools/tcltest.sh                       # baseline (upstream C) on a sample set
tools/tcltest.sh --zig                 # same, but our Zig ports linked in
tools/tcltest.sh --zig func randexpr1  # specific upstream .test files
```

`--zig` relinks `testfixture` with our `src/*.zig` objects swapping the matching
C files, so ports are validated against SQLite's own assertions. Broadening
beyond the sample set (`veryquick` / `testrunner.tcl`) is the next step — see
[PROGRESS.md](PROGRESS.md).

## Repository layout

| Path | Purpose |
|---|---|
| [build.zig](build.zig) | Build: split/amalgamation modes, `run`/`smoke`/`test` steps, the `ported_modules` swap list. |
| `vendor/tsrc/` | Upstream C translation units (the per-file set ports replace one at a time). |
| `vendor/tu.txt` | The library's translation-unit manifest. |
| `vendor/amalg/` | The single-file amalgamation (sanity-build mode). |
| `src/` | Zig ports of SQLite modules (90 ported — pager, btree, vdbe, SQL compiler, VFS, FTS5, …). |
| `examples/` | Standalone Zig programs using the engine via the C API (e.g. the blog CRUD REPL). |
| `sampledata/` | The sample blog schema/seed + `zig build sample` builder. |
| `test/` | Functional regression battery + golden output. |
| [plan.md](plan.md) | Phased migration roadmap. |
| [PROGRESS.md](PROGRESS.md) | Current status, resume point, and how to port a module. |
| [CLAUDE.md](CLAUDE.md) | Agent/contributor conventions. |

## License

SQLite is in the **public domain**; this port carries no license headers and
preserves the upstream blessing comments. This is a downstream experiment, not
an upstreamable SQLite contribution (upstream does not accept agentic code).
