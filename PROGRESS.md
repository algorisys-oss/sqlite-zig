# PROGRESS.md — status & resume point

The running log of where the migration stands and exactly how to pick it back
up. Read this first when resuming. See [plan.md](plan.md) for the full roadmap
and [CLAUDE.md](CLAUDE.md) for conventions.

## Current status: Phase 0 done; Phase 1 in progress (9 modules ported)

A Zig build system compiles upstream SQLite C (v3.54.0) into a static
`libsqlite3.a` and a working `sqlite3` CLI, with a green test gate. Nine modules
are now **ported to Zig** and linked in place of their C versions: `random.c`,
`hash.c`, `bitvec.c`, `rowset.c`, `fault.c`, `mem1.c`, `complete.c`,
`memjournal.c` (first storage-layer module), `fts3_hash.c`.
Each passes the functional gate (`zig build test`) and SQLite's own TCL
`testfixture` suite with the Zig objects swapped in. Notably the Zig `mem1`
allocator now backs **every** allocation in the engine, validated across a broad
cross-subsystem run (memsubsys1, malloc5, pragma, index, trigger1, fkey1,
json101, savepoint, attach, collate1, analyze, where, func, …).

> **Why progress now slows:** the remaining modules couple to *build-divergent*
> internal structs (`Mem`, `sqlite3`, `Sqlite3Config`). The `zig build` and
> `--dev` testfixture configs differ (SQLITE_DEBUG/TEST + ~30 flags), so a single
> Zig object can't satisfy both for config-dependent modules. The unblock is a
> comptime config foundation — see [docs/architecture.md](docs/architecture.md).

### Ports so far (src/*.zig; listed in `ported_modules` in build.zig)
- `random.c` → `src/random.zig` (+ `src/chacha.zig`) — PRNG; first port.
- `hash.c` → `src/hash.zig` — generic hash table. ABI-shared structs
  (`Hash`/`HashElem`/`_ht`) kept as `extern struct` (C callers reach in via the
  `sqliteHashFirst/Next/Data/Count` macros). TCL: select1/func/collate1/trigger1.
- `bitvec.c` → `src/bitvec.zig` — fixed-length bitmap. `Bitvec` is opaque, so
  only `sizeof==BITVEC_SZ(512)` is ABI-relevant (asserted at comptime). Full
  three-representation layout (bitmap / hash / recursive sub-vecs) +
  `sqlite3BitvecBuiltinTest`. TCL: `bitvec.test` (72 tests via the self-test).
- `rowset.c` → `src/rowset.zig` — rowid set (forest of balanced trees). Opaque
  struct; `sqlite3RowSetDelete`'s address is compared in vdbemem.c, so it is
  exported. TCL: where/where2/where9/in (the OR-optimization exercises RowSet).
- `fault.c` → `src/fault.zig` — benign-malloc fault hooks. Tiny static hook
  vector (`sqlite3BenignMallocHooks`/`Begin`/`End`). TCL: memory tests green.
- `mem1.c` → `src/mem1.zig` — default system-malloc allocator (the
  `sqlite3_mem_methods` drivers). Only `sqlite3MemSetDefault` is external; the
  rest register via `sqlite3_config(SQLITE_CONFIG_MALLOC,…)`. Uses the
  size-prefix strategy (alloc `n+8`, stash size) — both this project's `zig
  build` and the testfixture lack `HAVE_MALLOC_USABLE_SIZE`, so this matches the
  active C path exactly. TCL: memsubsys1/malloc5 + full cross-subsystem run.
- `complete.c` → `src/complete.zig` — the `sqlite3_complete()` SQL tokenizer
  (`sqlite3_incomplete`/`sqlite3_complete`/`sqlite3_complete16`). A config-
  invariant state machine over `sqlite3CtypeMap[]`; no struct coupling (the UTF-16
  path passes `sqlite3_value*` opaquely). TCL: main/tclsqlite/enc2.
- `memjournal.c` → `src/memjournal.zig` — in-memory rollback journal (backs
  `:memory:` dbs, `journal_mode=MEMORY`, and statement journals with spill-to-
  disk). Own opaque structs + public `sqlite3_file`/`sqlite3_io_methods` ABI +
  `sqlite3Os*` wrappers. `sqlite3JournalCreate` is ATOMIC_WRITE-gated (off) so
  not exported. TCL: jrnlmode/savepoint/trigger2/fkey2/tempdb.
- `fts3_hash.c` → `src/fts3_hash.zig` — FTS3's standalone hash table (STRING /
  BINARY key classes, optional key-copy). ABI-shared structs like `hash.c`;
  config-invariant (sqlite3_malloc64/free + libc compare). TCL:
  fts3aa/fts3ab/fts3expr/fts3near/fts3query/fts4aa.

### Validating ports against the TCL suite
`tools/tcltest.sh --zig [tests...]` relinks upstream `testfixture` with every
ported Zig object swapped in for its C counterpart. The list of ported stems is
the `MODULES=(...)` array in that script — **keep it in sync with
`ported_modules` in build.zig** when adding a port.

### First port: random.c → src/random.zig (+ src/chacha.zig)
- C `random.c` is excluded from the build (via `ported_modules` in build.zig);
  `src/random.zig` exports the same C-ABI symbols (`sqlite3_randomness`,
  `sqlite3PrngSaveState`, `sqlite3PrngRestoreState`) and calls back into the
  remaining C helpers (mutex, vfs, OsRandomness).
- Verified: `nm`/`ar` confirm only the Zig object provides the symbols; the
  functional suite passes; and the ChaCha20 core (`src/chacha.zig`) matches the
  **RFC 7539 §2.3.2 test vector** (`zig build test-unit`) → byte-identical to C.

### Done
- [x] Out-of-tree generation of amalgamation + generated sources from upstream
      (upstream tree left untouched). Workspace: `build/gen/`.
- [x] Vendored sources into `vendor/`:
    - `vendor/amalg/` — `sqlite3.c`, `sqlite3.h`, `shell.c`, `sqlite3ext.h`
    - `vendor/tsrc/` — 105 individually-compilable TUs + 36 headers (the
      per-file set that enables module-by-module swapping)
    - `vendor/tu.txt` — the 102-entry library TU manifest (tsrc minus
      `geopoly.c` [#include'd by rtree.c], `shell.c` [CLI], `tclsqlite-ex.c` [tcl])
- [x] [build.zig](build.zig): split build (default) + amalgamation mode
      (`-Damalgamation=true`); static lib + shell; `run`/`smoke`/`test` steps;
      per-file C→Zig swap mechanism (`ported_modules` list).
- [x] Verified: `zig build`, `zig build test`, `zig build smoke` all green in
      BOTH split and amalgamation modes. `test/functional.sql` exercises core
      DML, indexes, transactions, joins, triggers, math funcs, JSON, FTS5, rtree.

### TCL testfixture suite — WIRED ✓
- The real SQLite TCL `testfixture` now builds and runs here, using vendored TCL
  8.6.14 headers (`vendor/tcl/`) + the system `libtcl8.6` (no `tcl-dev` needed).
- [tools/tcltest.sh](tools/tcltest.sh) automates it:
    - `tools/tcltest.sh [tests...]` — baseline (upstream C) testfixture.
    - `tools/tcltest.sh --zig [tests...]` — relinks testfixture with our Zig
      object(s) swapped in for the matching C file(s).
- Verified green (0 errors) on `select1 func randexpr1 where2` — 17,931
  assertions — in BOTH the baseline and `--zig` (Zig PRNG) builds. `func.test`
  exercises `random()`/`randomblob()`, so this validates the Zig PRNG inside the
  full engine under SQLite's own harness.

### Not done yet (next)
- [ ] Run the **broader** suite (`testrunner.tcl` / `veryquick` / `make
      devtest`) under `--zig`, not just hand-picked files, and wire it as a `zig
      build` step or CI script.
- [ ] Continue Phase 1 leaf ports. Good next candidates: `printf.c` (xprintf —
      self-contained but large), `mutex_noop.c`/`mutex.c`, `global.c`,
      `ctime.c`. Deferred (need core structs first): `utf.c` and `status.c`'s
      `db_status` reach into the `Mem`/connection layouts.

## How to resume

```bash
cd /home/rajesh/lab/ai-port/sqlite-zig
zig build test        # green: functional suite with 6 Zig modules swapped in
tools/tcltest.sh --zig select1 func bitvec where   # green: TCL suite, Zig objs
```

If `vendor/` is missing or upstream is bumped, regenerate it:

```bash
mkdir -p build/gen && cd build/gen
/home/rajesh/opensource/sqlite/configure --dev      # out-of-tree; keeps upstream clean
make sqlite3.c sqlite3.h                             # builds amalgamation + parse.c/opcodes.*/keywordhash.h
# vendor amalgamation:
cp sqlite3.c sqlite3.h shell.c sqlite3ext.h ../../vendor/amalg/
# vendor per-file set:
cp tsrc/*.c tsrc/*.h ../../vendor/tsrc/
cp /home/rajesh/opensource/sqlite/ext/rtree/sqlite3rtree.h ../../vendor/tsrc/
# regenerate the TU manifest (exclude non-standalone files):
( cd ../../vendor/tsrc && for f in *.c; do case "$f" in geopoly.c|shell.c|tclsqlite-ex.c) ;; *) echo "$f";; esac; done | sort ) > ../../vendor/tu.txt
```

## How to port a module (the migration loop)

1. Pick the next module per [plan.md](plan.md) (bottom-up: utils → OS → storage
   → VDBE → front-end). Read its C in `vendor/tsrc/<name>.c`.
2. Write `src/<name>.zig` exporting the **same C-ABI symbols** (use
   `export fn`, match signatures from `sqliteInt.h`). It must satisfy every
   caller that still links the C side.
3. Add `"<name>.c"` to `ported_modules` in [build.zig](build.zig), AND add the
   stem to `MODULES=(...)` in [tools/tcltest.sh](tools/tcltest.sh) so the TCL
   relink swaps it in too.
4. `zig build test` — must stay green. Add targeted cases to
   `test/functional.sql` (regenerate `test/functional.expected`) and run the TCL
   suite: `tools/tcltest.sh --zig <relevant tests>` (0 errors required).
5. Update this file's checklist + [plan.md](plan.md) + log tokens.

### Porting playbook (patterns established so far)
- **ABI-shared struct** (defined in a header other C reads, e.g. `Hash`): mirror
  it as a Zig `extern struct` field-for-field.
- **Opaque struct** (defined only in the `.c`, others hold a pointer, e.g.
  `Bitvec`/`RowSet`): layout is internal; only allocation `sizeof` invariants
  matter — assert them at comptime.
- **Whole-file swap**: you must provide *every* exported symbol of the `.c`
  (incl. test-only ones like `sqlite3BitvecBuiltinTest` when `SQLITE_UNTESTABLE`
  is off). Symbols only referenced under `SQLITE_DEBUG` with no external callers
  (e.g. `sqlite3ShowBitvec`) can be omitted — verify with a tree-wide grep.
- **Config divergence**: the `zig build` library and the `--dev` testfixture use
  different flags (e.g. testfixture has `SQLITE_DEBUG`). One Zig object serves
  both, so port the behavior that is identical across configs, or the production
  one when a macro like `SQLITE_NOMEM_BKPT` only differs in debug bookkeeping.

## Key facts / gotchas discovered
- Outside the amalgamation, `SQLITE_PRIVATE` expands to empty → symbols are
  visible across TUs, so separate compilation + cross-TU linking works.
- `-DSQLITE_CORE=1` is **required** for the split build, else bundled extensions
  (fts5, stmt, …) each declare their own `sqlite3_api` → duplicate-symbol link
  error.
- `geopoly.c` is `#include`d into `rtree.c`; `rtree.c` needs
  `sqlite3rtree.h` (copied from `ext/rtree/`, not auto-placed in tsrc).
- Toolchain: Zig `0.17.0-dev.644+3de725074`. Build API is the module-based one
  (`b.addLibrary`/`b.addExecutable` with `root_module`; C sources/includes/links
  go on the **Module**, not the Compile step). `b.args` and
  `ArrayListUnmanaged{}` no longer exist (`.empty`).

## Log
- 2026-06-24: Scaffolding docs (CLAUDE.md, plan.md, token-count.md, tokens.txt).
- 2026-06-25: Phase 0 build foundation landed — vendored sources, build.zig
  (split + amalgamation), `zig build test` green in both modes. Next:
  TCL suite integration, then first real port (random.c).
- 2026-06-25: First port — `random.c` → `src/random.zig` (+ chacha). TCL
  testfixture wiring + `tools/tcltest.sh`.
- 2026-06-26: Phase 1 batch — ported `hash.c`, `bitvec.c`, `rowset.c`,
  `fault.c`, `mem1.c` to Zig (6 modules total). Generalized `tcltest.sh` to
  swap all ported objects (`MODULES` array). The Zig `mem1` allocator now backs
  every allocation in the engine. Validated green on the functional gate and a
  broad TCL run (memsubsys1, malloc5, pragma, index, trigger1, fkey1, json101,
  savepoint, attach, collate1, analyze, where, func, bitvec, select1, in, …).
- 2026-06-26: Ported `complete.c` (`sqlite3_complete`) — 7 modules total.
  Documented the dual-build config-divergence problem and the struct-coupling
  taxonomy in `docs/architecture.md` (explains why the next tier needs a comptime
  config foundation). TCL: main/tclsqlite/enc2 green with Zig objects.
- 2026-06-26: Ported `memjournal.c` (in-memory rollback journal) — 8 modules,
  first storage-layer module. Config-invariant (opaque structs + public
  sqlite3_file ABI). TCL green incl. the statement-journal spill path
  (jrnlmode/savepoint/trigger2/fkey2/tempdb).
- 2026-06-26: Ported `fts3_hash.c` (FTS3 hash table) — 9 modules. ABI-shared
  structs like hash.c. TCL fts3aa/ab/expr/near/query/fts4aa green (incl.
  fts3query's 1258 assertions). Broad cross-subsystem --zig sweep also green
  (insert/select4/update/view/subquery/window1/cast/vacuum/incrblob/boundary1…).
