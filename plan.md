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
- [ ] `printf.c` — sqlite3-internal formatting (xprintf)
- [ ] `utf.c` — UTF-8/16 conversions (needs the `Mem` struct mirrored — defer
      until VDBE `Mem` layout is pinned down)
- [ ] `mem2/3/5.c`, `malloc.c`, `status.c` — rest of the allocator stack
      (`status.c` deferred: `sqlite3_db_status64` reaches deep into connection
      internals — not a clean leaf)
- [ ] `mutex*.c` — mutex backends (start with `mutex_noop`, then `mutex_unix`)
- [ ] `global.c`, `ctime.c`
- [x] `complete.c` — `sqlite3_complete()` SQL tokenizer → `src/complete.zig`.
      Config-invariant leaf: a state machine over `sqlite3CtypeMap[]`, no struct
      coupling (the UTF-16 path passes `sqlite3_value*` opaquely). Validated via
      main/tclsqlite/enc2 (`db complete` + `complete16`). See
      [docs/architecture.md](docs/architecture.md) for why deeper modules are
      blocked on a config foundation.

**Exit criteria:** these modules are Zig; suite green; porting playbook written.

## Phase 2 — OS / VFS layer

The interface to the host. Port the Unix path first; defer Windows.

- [ ] `os.c` (VFS dispatch), `os.h`, `os_common.h`
- [ ] `os_unix.c` (file I/O, locking, mmap) — large, ~296 KB
- [x] `memjournal.c` — in-memory rollback journal → `src/memjournal.zig`.
      Config-invariant: own opaque structs + the public `sqlite3_file`/
      `sqlite3_io_methods`/`sqlite3_vfs` ABI; `sqlite3JournalCreate` is
      ATOMIC_WRITE-gated (off) so omitted. Validated incl. the spill-to-disk
      path: jrnlmode/savepoint/trigger2/fkey2 (statement journals) green.
- [ ] `memdb.c` — in-memory VFS
- [ ] (defer) `os_win.c`, `os_kv.c`

**Exit criteria:** Zig VFS backs all I/O on Linux; suite green.

## Phase 3 — Storage engine (pager → btree → WAL)

The heart of durability and on-disk format. Highest risk; port carefully with
heavy reliance on the corruption/recovery tests.

- [ ] `pcache.c`, `pcache1.c`, `pcache.h` — page cache
- [ ] `pager.c`, `pager.h` — page-level transactions/journaling (~302 KB)
- [ ] `wal.c` — write-ahead log (~178 KB)
- [ ] `btree.c`, `btree.h`, `btreeInt.h`, `btmutex.c` — B-tree (~406 KB, largest)
- [ ] `backup.c`

**Exit criteria:** on-disk format byte-compatible; pager/btree/wal/corrupt
tests green; can open a file created by upstream and vice versa.

## Phase 4 — VDBE (the bytecode virtual machine)

The execution engine queries compile down to. Depends on storage + utils.

- [ ] `vdbemem.c`, `vdbeaux.c`, `vdbeapi.c` — Mem cells, prepared-stmt plumbing
- [ ] `vdbe.c` — the opcode interpreter (~322 KB)
- [ ] `vdbesort.c`, `vdbeblob.c`, `vdbetrace.c`
- [ ] opcode generation: port `tool/mkopcodeh.tcl` flow or generate `opcodes.*`
      at build time so opcodes stay in sync with the interpreter.

**Exit criteria:** VDBE runs ported bytecode; suite green.

## Phase 5 — SQL compiler front-end

Tokenizer → parser → code generator → optimizer. Depends on VDBE.

- [ ] `tokenize.c` + `keywordhash.h` generation
- [ ] Parser: port `parse.y`. Decide **Lemon strategy** — either (a) keep Lemon
      generating C `parse.c` and call it via ABI, (b) port the Lemon-generated
      table-driven parser to Zig, or (c) port the `lemon` generator itself.
      Recommend (a) first, then (b). **Decision pending — flag for user.**
- [ ] Code generators: `expr.c`, `build.c`, `select.c`, `insert.c`, `update.c`,
      `delete.c`, `where*.c` (optimizer), `resolve.c`, `walker.c`, `attach.c`,
      `trigger.c`, `fkey.c`, `vtab.c`, `analyze.c`, `pragma.c`, `vacuum.c`,
      `alter.c`, `auth.c`
- [ ] SQL functions: `func.c`, `date.c`, `json.c`, `window.c`

**Exit criteria:** full SQL pipeline in Zig; suite green.

## Phase 6 — Public API & entry points

- [ ] `main.c`, `legacy.c`, `prepare.c`, `callback.c`, `loadext.c`, `table.c`
- [ ] `sqlite.h.in` → produce a Zig-friendly + C-ABI `sqlite3.h`
- [ ] `shell.c.in` — CLI (can stay C longest; low value to port early)

**Exit criteria:** `libsqlite3` is fully Zig; C-ABI compatible drop-in;
full `testrunner.tcl full` green.

## Phase 7 — Extensions & platform breadth (optional / later)

- [x] `fts3_hash.c` — FTS3 standalone hash table → `src/fts3_hash.zig` (ported
      early as a clean config-invariant leaf; TCL fts3*/fts4aa green).
- [ ] FTS5, RTREE, JSON1 (if not folded in), session, rbu — under `ext/`
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
