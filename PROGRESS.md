# PROGRESS.md — status & resume point

The running log of where the migration stands and exactly how to pick it back
up. Read this first when resuming. See [plan.md](plan.md) for the full roadmap
and [CLAUDE.md](CLAUDE.md) for conventions.

## Current status: Phase 0 done; Phase 1 started (1 module ported)

A Zig build system compiles upstream SQLite C (v3.54.0) into a static
`libsqlite3.a` and a working `sqlite3` CLI, with a green test gate. The first
module — `random.c` — is now **ported to Zig** and linked in place of the C
version, proving the swap mechanism end-to-end.

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
      per-file C→Zig swap mechanism (`ported_modules` list — currently empty).
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
      devtest`), not just the 4-file smoke set, and wire it as a `zig build`
      step or CI script.
- [ ] Continue Phase 1 leaf-utility ports (hash.c, bitvec.c, rowset.c, …).

## How to resume

```bash
cd /home/rajesh/lab/ai-port/sqlite-zig
zig build test        # should be green (100% C baseline)
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
3. Add `"<name>.c"` to `ported_modules` in [build.zig](build.zig).
4. `zig build test` — must stay green. Add targeted cases to
   `test/functional.sql` (regenerate `test/functional.expected`) and, once
   wired, run the TCL suite.
5. Update this file's checklist + [plan.md](plan.md) + log tokens.

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
