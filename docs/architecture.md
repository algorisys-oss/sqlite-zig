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

### The "config foundation" — IMPLEMENTED (2026-06-26)

To unblock the deeply-coupled tier, a **comptime config** in Zig mirrors the C
`-D` flags, compiled per-target-build (exactly as C uses `-D`):

- `build.zig` exposes a `config` options module (`@import("config")` →
  `sqlite_debug`, `sqlite_test`). `-Dtestfixture=true` flips them on.
- Each ported object imports `config`; a `test-objs` build step emits the objects
  with the chosen config (ReleaseSafe+PIC). `tcltest.sh --zig` runs
  `zig build test-objs -Dtestfixture=true` and links those, so each object's
  struct layout / test instrumentation matches the build it links against.

#### Provably-correct struct mirrors (no silent corruption)

`@cImport`/`zig translate-c` can't auto-import `sqliteInt.h` (`@cImport` is
removed in this Zig; `translate-c` chokes on the macros), so mirrors are manual.
To make them *safe*, layout is verified against **C ground truth**:

- `tools/offsets.c` prints `offsetof`/`sizeof` for the needed structs.
- `tools/gen_layout.sh` compiles it under BOTH configs (production + `--dev`
  testfixture) and generates [../src/c_layout.zig](../src/c_layout.zig) with the
  numbers, selected at comptime by `config.sqlite_debug`.
- Each Zig struct mirror has `comptime` `@offsetOf`/`@sizeOf` asserts against
  those numbers. **A wrong mirror fails to compile** in the affected config —
  it can never silently corrupt memory.

This also corrected a mistaken assumption: `Sqlite3Config.iPrngSeed` and
`sqlite3.mallocFailed` turned out to be at *config-invariant* offsets (the
ground-truth extractor showed `SQLITE_DEBUG`'s early `bJsonSelfcheck` is absorbed
by padding). Only `sizeof(Mem)` actually moves (56 → 72); its field offsets are
invariant. Reason about layout from the extractor, not from reading the structs.

**First module on this foundation:** `utf.c` → `src/utf.zig` (mirrors `Mem` with
a config-gated tail; reads `db->mallocFailed` at its ground-truth offset).
Validated by enc/enc2/enc3/enc4 in the testfixture (debug) config.

Regenerate `src/c_layout.zig` (after adding fields to `tools/offsets.c` or
bumping the vendored sources): `tools/gen_layout.sh`.

### Note on the `SQLITE_NOMEM_BKPT`-style macros

Where a macro only differs in debug bookkeeping (`SQLITE_NOMEM_BKPT` →
`sqlite3NomemError(line)` under DEBUG vs plain `SQLITE_NOMEM` in production), the
ported code uses the **production** behavior (return the code). The return value
is identical; only a debug breakpoint/log side effect is dropped, which does not
affect test correctness.
