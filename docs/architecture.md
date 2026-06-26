# Migration architecture & decisions

Living record of the architectural decisions behind the C→Zig migration. Read
alongside [../plan.md](../plan.md) (roadmap) and [../PROGRESS.md](../PROGRESS.md)
(status). New decisions get appended here with a date.

## How a module is ported (the swap mechanism)

Each ported module is a `src/<name>.zig` that **exports the same C-ABI symbols**
as `vendor/tsrc/<name>.c`. The C file is dropped from the build via
`ported_modules` in [../build.zig](../build.zig) and the Zig object linked in its
place. Mixed C/Zig links because, outside the amalgamation, `SQLITE_PRIVATE`
expands to empty, so cross-TU symbols stay visible.

Two struct-coupling patterns have emerged:

- **ABI-shared struct** (defined in a header other C reads — e.g. `Hash`):
  mirror it field-for-field as a Zig `extern struct`. C callers reach into it via
  macros, so the layout must match exactly.
- **Opaque struct** (defined only in the `.c`, others hold a pointer — e.g.
  `Bitvec`, `RowSet`): the layout is internal; only allocation `sizeof`
  invariants are ABI-relevant. Assert them at comptime.

## Decision 2026-06-26: the dual-build config-divergence problem

This is the central constraint shaping which modules can be ported next.

### The two builds

A ported Zig object is validated in **two** separately-configured builds, and the
same single `.o` is linked into both:

1. **`zig build`** — the production static lib / shell. Flags = `sqlite_flags`
   in build.zig (THREADSAFE=1, FTS5, RTREE, DQS=0, …). **No** `SQLITE_DEBUG`,
   **no** `SQLITE_TEST`.
2. **`testfixture`** (`tools/tcltest.sh --zig`) — SQLite's own TCL harness,
   built by upstream `configure --dev`. Adds `SQLITE_DEBUG=1`, `SQLITE_TEST=1`,
   `SQLITE_ENABLE_SELECTTRACE/WHERETRACE`, `SQLITE_STRICT_SUBTYPE=1`,
   `SQLITE_DEFAULT_PAGE_SIZE=1024`, `SQLITE_NO_SYNC=1`, … and notably does **not**
   set `SQLITE_DQS=0`. ~33 `-D` flags, a materially different set.

### Why it matters

The two builds have **different struct layouts and different behavior**:

- `SQLITE_DEBUG` appends fields to core structs. `Mem` gains a
  `pScopyFrom`/`mScopyFlags`/`bScopy` tail; `Sqlite3Config` gains `bJsonSelfcheck`
  (early!) and an `aTune[]` tail. An early conditional field shifts the offset of
  **every** field after it — e.g. `Sqlite3Config.iPrngSeed` lands at a different
  offset in the two builds.
- `SQLITE_TEST` adds globals and behavior: `os.c` gains the `sqlite3_io_error_*`
  fault-injection counters and the `DO_OS_MALLOC_TEST` OOM-injection macro.

A single Zig object compiled one way cannot match both layouts/behaviors at once.
The modules ported so far work in both builds **only because they are
config-invariant** — they touch no debug-conditional struct fields and gate no
behavior on `SQLITE_TEST`/`SQLITE_DEBUG`.

### Consequence: a module is "cleanly portable now" iff

1. It couples only to **opaque** structs, **public** ABI structs (sqlite3.h),
   or **config-invariant** internal data (e.g. `sqlite3CtypeMap[]`), AND
2. its behavior/symbols don't diverge across the two builds' flags.

Ported under this rule: `random`, `hash`, `bitvec`, `rowset`, `fault`, `mem1`,
`complete`.

### Deferred and why

- `utf.c` — reaches into `Mem` (offsets) **and** `sqlite3.mallocFailed`.
- `printf.c` — couples to `StrAccum`/`sqlite3`/`Expr` and gates on
  `WHERETRACE`/`TREETRACE` (which differ between builds); also it is the
  formatting engine, where a subtle bug is catastrophic and hard to detect.
- `os.c` — reads `sqlite3Config.iPrngSeed` (build-divergent offset) and owns the
  `SQLITE_TEST` IO-error counters + `DO_OS_MALLOC_TEST`.
- `status.c` — `sqlite3_db_status64` walks `lookaside`/`Schema`/`Vdbe` internals.
- `mutex.c` / `malloc.c` / the storage & VDBE layers — pervasive internal-struct
  coupling.

### Recommended path forward (the "config foundation")

To unblock the deeply-coupled tier, introduce a **comptime config** in Zig that
mirrors the C `-D` flags, compiled per-target-build (exactly as C uses `-D`):

- `build.zig` exposes a `config` options module; a `-Dtestfixture=true` flips the
  flag set to the testfixture's (SQLITE_DEBUG, SQLITE_TEST, …).
- Ported Zig modules gate debug-only struct fields and test-only code on those
  comptime flags, so each emitted object matches the build it is linked into.
- `tcltest.sh` consumes objects emitted with the testfixture flag set (e.g. via a
  dedicated `zig build` step) instead of a bare `zig build-obj`.

Until that exists, prefer config-invariant leaves. `@cImport`/`zig translate-c`
were evaluated for auto-importing `sqliteInt.h` to get exact layouts — both fail
(`@cImport` is removed in this Zig; `translate-c` chokes on the header's macros),
so struct mirrors remain manual and the config foundation is the real unlock.

### Note on the `SQLITE_NOMEM_BKPT`-style macros

Where a macro only differs in debug bookkeeping (`SQLITE_NOMEM_BKPT` →
`sqlite3NomemError(line)` under DEBUG vs plain `SQLITE_NOMEM` in production), the
ported code uses the **production** behavior (return the code). The return value
is identical; only a debug breakpoint/log side effect is dropped, which does not
affect test correctness.
