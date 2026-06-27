# plan.md — Migrating SQLite (C → Zig)

Living migration plan. Source of truth for scope, strategy, and progress.
Update checkboxes and notes as work lands.

- **Target to port:** SQLite v3.54.0 (`/home/rajesh/opensource/sqlite`)
- **Toolchain:** Zig `0.17.0-dev.644+3de725074`
- **Scope:** ~219k LOC of C/H across 125 files in `src/` (excludes `ext/`,
  `test/`, `tool/`). See [token-count.md](token-count.md) for size tracking.
- **Definition of done for any step:** SQLite's own test suite still passes.

---

## Guiding principles

1. **Tests are the spec.** SQLite ships ~millions of test assertions. We port
   against them continuously, not at the end.
2. **Incremental, never big-bang.** A mixed C/Zig binary must build and pass
   tests at every commit. Zig links C trivially (`zig cc`, `@cImport`,
   `addCSourceFile`), so we can replace one `.c` at a time.
3. **Preserve the C ABI at boundaries.** Each module keeps its existing
   function signatures (`extern`/`export`) until *all* its callers are ported,
   so half-ported builds link.
4. **Bottom-up.** Port leaf dependencies before their dependents.
5. **Idiomatic Zig inside, C-compatible outside.** Rewrite internals using Zig
   idioms; expose C-ABI shims where C still calls in.

---

## CURRENT STATUS (2026-06-27) — 89/105 modules; whole engine + RTree/Session/FTS3 in Zig

**The entire active Linux SQLite engine is now Zig**, plus the RTree, Session, and
FTS3/FTS4 extensions — 89 of 105 build TUs ported, every one committed and
validated (`zig build test` green). The phase checkboxes below are historical and
partly stale; **PROGRESS.md is the authoritative live status** (with the resume
guide). Snapshot by phase:
- Phase 0 (foundation/harness): done.
- Phase 1 (leaf utils): done — incl. the deferred keystones **global.c**
  (sqlite3Config byte-exact) and **ctime.c**.
- Phase 2 (OS/VFS): done — **os_unix.c** (all file I/O, locking, WAL shm, mmap),
  os.c, memjournal.c, memdb.c. (os_win/os_kv: other-platform/inactive.)
- Phase 3 (storage): done — pager, **wal**, btree, backup, all pcache.
- Phase 4 (VDBE): done — vdbe + vdbeaux/api/mem/sort/trace/blob.
- Phase 5 (SQL compiler): done — tokenize, resolve, **expr, where/whereexpr/
  wherecode, select**, build/insert/update/delete, trigger, fkey, alter, analyze,
  upsert, pragma, vacuum, attach, walker, func, json, window, date. (parse.c is
  Lemon-generated → stays C, like all generated files.)
- Phase 6 (public API): done — **main.c** (open/close/config/errors/all hooks),
  prepare, legacy, vdbeapi, loadext, table, callback, util.
- Phase 7 (extensions): **RTree+Geopoly, Session/changeset, FTS3/4 (vtab+writer+
  parser+snippet+tokenizer), and FTS5 DONE.** FTS5 is ported as a modular Zig
  object (foundation src/fts5_int.zig + 14 per-section src/fts5_*.zig, swapping the
  ~26k-line fts5.c amalgamation) and now produces BYTE-IDENTICAL %_data to upstream
  C across a broad differential (insert/delete/update, merge/optimize, MATCH AND/OR/
  NOT/phrase/prefix/absent-term, bm25/snippet, fts5vocab); integrity_check ok at
  3k–5k rows. ICU/RBU are flag-inactive. **All active modules are now Zig.**

NOT portable for a Linux engine (no Zig port needed): generated parse.c/opcodes.c,
Windows os_win/mutex_w32, flag-inactive mem0/2/3/notify/os_kv/icu/fts3_icu/rbu,
and the tclsqlite-ex test harness.

---

## Phase 0 — Foundation & harness (no porting yet)

Goal: a Zig-driven build of *unmodified* upstream C that produces a working
`sqlite3` and runs the test suite. This is the safety net for everything after.

- [x] Create `build.zig` for this project (module-based Zig 0.17-dev API).
- [x] Vendor generated sources from upstream (out-of-tree, upstream untouched);
      build `libsqlite3.a` + `sqlite3` shell with the Zig toolchain. Split
      (per-file) build is default; amalgamation available via `-Damalgamation`.
- [x] Set up the per-file swap mechanism: `ported_modules` list in build.zig
      selects the Zig implementation of a module over its C counterpart,
      defaulting to C. (Empty for now → 100% C baseline.)
- [x] Minimal green gate: `zig build test` runs `test/functional.sql` (core +
      extensions) green in both build modes.
- [x] Wire the upstream TCL `testfixture` against our build (vendored TCL
      headers + system libtcl8.6); `tools/tcltest.sh` builds it and can relink
      with our Zig objects (`--zig`). Verified green on a representative set.
- [ ] Run the broader suite (`testrunner.tcl`/`veryquick`/`devtest`), not just
      the smoke set; wire as a build step / CI.

**Exit criteria:** full SQLite TCL suite green via our Zig build.
**Status:** build foundation + testfixture wiring done; broaden suite coverage
next. See [PROGRESS.md](PROGRESS.md).

## Phase 1 — Leaf utilities (low-risk, high-confidence)

Self-contained modules with narrow interfaces; good for establishing porting
patterns (error handling, allocator strategy, C-ABI shims, test parity).

- [x] `random.c` — PRNG → `src/random.zig` (+ `src/chacha.zig`). First port;
      proves the swap mechanism. ChaCha20 verified against the RFC 7539 vector.
- [x] `hash.c` — internal hash table → `src/hash.zig`. ABI-shared structs
      (`Hash`/`HashElem`/`_ht`) kept via `extern struct`; TCL suite green.
- [x] `bitvec.c` — bitmap → `src/bitvec.zig`. Opaque struct (only `sizeof==512`
      is ABI-relevant); `bitvec.test` (BuiltinTest harness) green.
- [x] `rowset.c` — row-id sets → `src/rowset.zig`. Opaque forest-of-trees;
      `sqlite3RowSetDelete` address-compared in vdbemem.c. where/in tests green.
- [x] `fault.c` — benign-malloc fault hooks → `src/fault.zig`. Tiny leaf; the
      hook vector other modules toggle around recoverable allocs.
- [x] `mem1.c` — default system-malloc allocator → `src/mem1.zig`. The
      `sqlite3_mem_methods` drivers now back **every** allocation in the engine
      (size-prefix strategy, matching the no-`malloc_usable_size` config).
      memsubsys1/malloc5 green; full cross-subsystem suite green.
- [x] `printf.c` — sqlite3-internal formatting (xprintf / `sqlite3_str`) →
      `src/printf.zig`. Used by ~every subsystem. Established the va_list ABI
      pattern: a Zig fn receiving a C `va_list` must take `*std.builtin.VaList`
      (by-value is mis-lowered → GP fault); variadic origins forward `&ap`.
      printf/printf2/format4 + the error-text-bearing suite green.
- [x] `utf.c` — UTF-8/16 conversions → `src/utf.zig`. **First core-struct-coupled
      port.** Mirrors `Mem` (config-gated tail: sizeof 56 prod / 72 debug) and
      reads `db->mallocFailed`, all asserted at comptime against C ground truth
      ([src/c_layout.zig](src/c_layout.zig), generated by tools/gen_layout.sh).
      Validated by enc/enc2/enc3/enc4 (1115 round-trips) in the testfixture
      config. Enabled by the comptime-config foundation (see docs/architecture.md).
- [x] `mem5.c` — MEMSYS5 buddy allocator → `src/mem5.zig` (agent-ported; reads
      `sqlite3Config.nHeap/pHeap/mnReq/bMemstat`). mem5 green. `mem2/3.c`,
      `malloc.c`, `status.c` still C (`status.c` deferred: `sqlite3_db_status64`
      reaches deep into connection internals — not a clean leaf).
- [x] `mutex_noop.c` + `mutex.c` — mutex dispatch + debug checking mutex →
      `src/mutex_noop.zig`/`src/mutex.zig` (the mutex subsystem is fully Zig;
      reads `sqlite3Config.mutex@/bCoreMutex@`). `threads.c` (pthreads sorter
      helper) also ported. mutex1/mutex2 green. `mutex_unix.c` still C.
- [x] `global.c` (sqlite3Config byte-exact), `ctime.c` — DONE (were deferred:
      struct every c_layout offset depends on; ctime.c's option list diverges by
      many flags. Do after expanding the `config` options module.)
- [x] `complete.c` — `sqlite3_complete()` SQL tokenizer → `src/complete.zig`.
      Config-invariant leaf: a state machine over `sqlite3CtypeMap[]`, no struct
      coupling (the UTF-16 path passes `sqlite3_value*` opaquely). Validated via
      main/tclsqlite/enc2 (`db complete` + `complete16`). See
      [docs/architecture.md](docs/architecture.md) for why deeper modules are
      blocked on a config foundation.

**Exit criteria:** these modules are Zig; suite green; porting playbook written.

## Phase 2 — OS / VFS layer

The interface to the host. Port the Unix path first; defer Windows.

- [x] `os.c` (VFS dispatch + VFS registry) → `src/os.zig`. Wrappers over the
      public `sqlite3_file`/`sqlite3_vfs` method tables; reads
      `sqlite3Config.iPrngSeed` at its ground-truth offset; the SQLITE_TEST
      fault-injection state (`sqlite3_io_error_*`, `DO_OS_MALLOC_TEST`) gated on
      `config.sqlite_test`. Validated: ioerr (10885), pager1 (1373), lock,
      mmap1, oserror in the testfixture config.
- [x] `os_unix.c` (file I/O, locking, WAL shm, mmap) → `src/os_unix.zig`.
- [x] `memjournal.c` — in-memory rollback journal → `src/memjournal.zig`.
      Config-invariant: own opaque structs + the public `sqlite3_file`/
      `sqlite3_io_methods`/`sqlite3_vfs` ABI; `sqlite3JournalCreate` is
      ATOMIC_WRITE-gated (off) so omitted. Validated incl. the spill-to-disk
      path: jrnlmode/savepoint/trigger2/fkey2 (statement journals) green.
- [x] `memdb.c` — in-memory VFS → `src/memdb.zig`.
- [ ] (defer) `os_win.c`, `os_kv.c`

**Exit criteria:** Zig VFS backs all I/O on Linux; suite green.

## Phase 3 — Storage engine (pager → btree → WAL)

The heart of durability and on-disk format. Highest risk; port carefully with
heavy reliance on the corruption/recovery tests.

- [x] `pcache.c`, `pcache1.c` — page cache → `src/pcache.zig`/`src/pcache1.zig`.
      `PgHdr` mirrored (ABI-shared) with offset asserts; `PCache`/`PCache1` kept
      opaque. Surfaced the `extern var` vs `extern const` optimizer-CSE gotcha
      (a mutable C global read from Zig must be `extern var`). pcache/pcache2/
      pager1 green. First Phase-3 storage modules.
- [x] `pager.c` — page-level transactions / rollback journal / savepoints /
      hot-journal recovery / WAL handoff → `src/pager.zig` (75 exports; the
      private Pager struct owned here, PgHdr mirrored with comptime asserts).
      Every byte of file I/O now flows through Zig pager→pcache→os/VFS. TCL
      pagerfault(31589)/ioerr(10885)/savepoint4(3469)/wal/wal2/jrnlmode green.
- [x] `wal.c` — write-ahead log → `src/wal.zig`.
- [x] `btree.c` (on-disk format, cursors, balancing, autovacuum, shared-cache,
      overflow, integrity_check) -> src/btree.zig. Agent byte-exact-validated vs
      C + cross-version compat; TCL corrupt(12288)/autovacuum/index green.
- [x] `backup.c` → `src/backup.zig`.

**Exit criteria:** on-disk format byte-compatible; pager/btree/wal/corrupt
tests green; can open a file created by upstream and vice versa.

## Phase 4 — VDBE (the bytecode virtual machine)

The execution engine queries compile down to. Depends on storage + utils.

- [x] `vdbemem.c`, `vdbeaux.c`, `vdbeapi.c` — Mem cells, prepared-stmt plumbing
- [x] `vdbe.c` — the opcode interpreter (all 192 opcodes; `src/vdbe.zig`).
      Core SQL + vtab writes (FTS5/FTS3/RTree) validated against the upstream TCL
      suite in the `--dev` config. FTS5-write corruption and vtab `UPDATE` both
      fixed. One minor `--dev`-only FTS3 savepoint assert tracked (production
      correct). See PROGRESS.md "Known issues".
- [x] `vdbetrace.c`, `vdbeblob.c` — ported. [ ] `vdbesort.c` (sorter still C).
- [ ] opcode generation: port `tool/mkopcodeh.tcl` flow or generate `opcodes.*`
      at build time so opcodes stay in sync with the interpreter.

**Exit criteria:** VDBE runs ported bytecode; suite green. — **met** (interpreter
is Zig; 1000+ upstream tests pass; FTS5/RTree vtab writes work). One minor
`--dev`-only FTS3 savepoint assert remains (production correct).

## Phase 5 — SQL compiler front-end

Tokenizer → parser → code generator → optimizer. Depends on VDBE.

- [x] `tokenize.c` (+ keyword hash) → `src/tokenize.zig`.
- [ ] Parser: port `parse.y`. Decide **Lemon strategy** — either (a) keep Lemon
      generating C `parse.c` and call it via ABI, (b) port the Lemon-generated
      table-driven parser to Zig, or (c) port the `lemon` generator itself.
      Recommend (a) first, then (b). **Decision pending — flag for user.**
- [x] `vtab.c` (virtual-table object mgmt) → `src/vtab.zig`. `auth.c` →
      `src/auth.zig`. `vacuum.c` → `src/vacuum.zig`. `attach.c` (+ the DbFixer
      schema-fixer AST walkers) → `src/attach.zig`. (Done ahead of the rest of
      Phase 5; they sit on the already-ported prepare/callback/util layer.)
- [x] `trigger.c` (triggers + RETURNING + INSTEAD OF) → `src/trigger.zig`.
      `fkey.c` (foreign-key codegen) → `src/fkey.zig`.
- [x] Code generators DONE: `expr.c`, `build.c`, `select.c`, `insert.c`, `where*.c`, `resolve.c`,
      `update.c`, `delete.c`, `where*.c` (optimizer), `resolve.c`, `walker.c`,
      `analyze.c`, `pragma.c`, `alter.c`
- [x] `date.c` (date/time fns) → `src/date.zig`. SQL functions remaining:
      `func.c`, `json.c`, `window.c`.

**Exit criteria:** full SQL pipeline in Zig; suite green.

## Phase 6 — Public API & entry points

- [x] `table.c` — sqlite3_get_table → `src/table.zig` (reads db->errCode at a
      ground-truth offset).
- [x] `legacy.c` — `sqlite3_exec` → `src/legacy.zig`.
- [x] `callback.c` — collation/function registry → `src/callback.zig` (reads
      sqlite3/Parse/CollSeq/FuncDef/Schema hashes via c_layout offsets; fixed the
      `char[]`-symbol-as-pointer and `(u16)nArg` truncate gotchas).
- [x] `util.c` — utility grab-bag (varint, atoi/atof, FpDecode, error/progress)
      → `src/util.zig`. 50 exports; bit-exact numeric paths (u64 wrap via `*%`/
      `+%`, GCC<5 add/sub/mul-overflow fallback).
- [x] `vdbevtab.c` — bytecode()/tables_used() vtab → `src/vdbevtab.zig`.
- [x] `loadext.c` — runtime extension loading + the 279-slot `sqlite3_api_routines`
      table → `src/loadext.zig`.
- [x] `prepare.c` → `src/prepare.zig`. `main.c` (open/close/config/errors/hooks) → `src/main.zig`.
      `vtab.c` → `src/vtab.zig`. `main.c` remains.
- [ ] `sqlite.h.in` → produce a Zig-friendly + C-ABI `sqlite3.h`
- [ ] `shell.c.in` — CLI (can stay C longest; low value to port early)

**Exit criteria:** `libsqlite3` is fully Zig; C-ABI compatible drop-in;
full `testrunner.tcl full` green.

## Phase 7 — Extensions & platform breadth (optional / later)

- [x] `fts3_hash.c` — FTS3 standalone hash table → `src/fts3_hash.zig` (ported
      early as a clean config-invariant leaf; TCL fts3*/fts4aa green).
- [x] FTS3 tokenizers → `src/fts3_porter.zig` / `src/fts3_tokenizer1.zig` /
      `src/fts3_unicode.zig` (agent-ported, config-invariant; fts3ad/fts4unicode).
- [x] `carray.c` — table-valued fn / vtab → `src/carray.zig` (carray01/tabfunc01).
- [x] `fts3_unicode2.c` (fold data) and `fts3_aux.c` (fts4aux vtab) →
      `src/fts3_unicode2.zig`/`src/fts3_aux.zig` (fts3aux1/2, fts4unicode green).
- [x] `stmt.c` — the `sqlite_stmt` eponymous vtab → `src/stmt.zig`.
- [x] RTREE+geopoly, session, FTS3/4 DONE; JSON1 folded in (json.zig); FTS5 DONE (src/fts5*.zig, byte-identical differential); rbu inactive.
- [ ] Windows VFS (`os_win.c`), other platforms
- [ ] A native Zig API surface (idiomatic, not just the C ABI)

---

## Cross-cutting decisions to resolve (flag to user before committing)

- **Lemon parser:** wrap generated C vs. port (see Phase 5).
- **Allocator model:** thread `std.mem.Allocator` vs. mirror SQLite's pluggable
  `sqlite3_mem_methods`. Must stay compatible with the public API.
- **Error handling:** Zig error unions internally vs. SQLite's int result codes
  at the ABI boundary (need translation shims).
- **Compile-time config:** SQLite's ~hundreds of `SQLITE_*` macros → Zig
  `comptime` build options. Decide which to support initially.
- **Concurrency/threading model** parity (`SQLITE_THREADSAFE` modes).

## Risks

- B-tree / pager / WAL on-disk format must be **bit-exact** — highest risk.
- The macro-heavy, `#ifdef`-heavy C is hard to port faithfully; easy to drop a
  configuration path silently. Mitigate with test coverage per config.
- Generated-file drift (opcodes, parser, keyword hash) if generators aren't
  also ported/automated.
- Sheer scale (~219k LOC). Expect this to be a long, multi-stage effort.

## Progress log

- 2026-06-24: Repo scaffolding — `CLAUDE.md`, `plan.md`, `token-count.md`
  created. No code yet. Phase 0 not started.
- 2026-06-25: Phase 0 done (build foundation + TCL wiring); first port random.c.
- 2026-06-26: Phase 1 leaf ports — hash.c, bitvec.c, rowset.c, fault.c, mem1.c
  to Zig (6 modules). Functional + broad TCL suites green with Zig objects
  linked in. Allocator (`mem1`) now backs all engine allocations.
- 2026-06-26: Built the comptime-config + ground-truth-offset foundation
  (`-Dtestfixture`, `config` module, tools/offsets.c → src/c_layout.zig) and an
  agent-parallelized porting workflow. Ported, in waves: complete, utf, os,
  memjournal, fts3_hash, fts3_porter/tokenizer1/unicode/unicode2, carray, table,
  threads, mem5, mutex_noop, stmt, mutex, vdbetrace, legacy, pcache, pcache1,
  printf, fts3_aux, callback, vdbevtab, util, loadext — **30 modules** total.
  Per-port: comptime offset asserts validate the struct mirrors against C, then
  `zig build test` + engine_test + a targeted TCL `--zig` sweep gate each commit.
  Also added the `sqlite-zig` CLI binary. Notable bug classes found & fixed:
  va_list-by-value mis-lowering, `%z` NULL adoption, `char[]`-symbol-as-pointer,
  `(u16)` truncate-vs-rangecheck, and u64 accumulation wrap (`*%`/`+%`). See
  [PROGRESS.md](PROGRESS.md) for the detailed per-module log. Next: prepare.c,
  vtab.c, then analyze/pragma and the storage/VDBE core.
