# PROGRESS.md — status & resume point

The running log of where the migration stands and exactly how to pick it back
up. Read this first when resuming. See [plan.md](plan.md) for the full roadmap
and [CLAUDE.md](CLAUDE.md) for conventions.

## Current status: Phase 1 — 86 modules; core + rtree + session + FTS3 core in Zig

**Modules 84–86: FTS3/FTS4 full-text search** (atop core + rtree + session):
- `fts3.c` (84) → `src/fts3.zig` — the FTS3/FTS4 vtab. ALSO fixed a main.zig
  REGRESSION: sqlite3BuiltinExtensions dropped sqlite3Fts3Init, so FTS3/4 was
  unregistered ("no such module: fts4") since module 77 — restored.
- `fts3_write.c` (85) → index writer + segment merging (28 exports).
- `fts3_expr.c` (86) → the MATCH-query parser.
  All three mirror fts3Int.h structs file-locally (extern struct, no c_layout
  offsets). FTS4 validated end-to-end through Zig vtab+writer+parser: MATCH,
  -NOT, implicit-AND, OR, phrase, NEAR, prefix f*, offsets(), INSERT/UPDATE/
  DELETE/merge/optimize/integrity-check. Fixed a fts3.zig phrase-cleanup crash
  (force-unwrapped a null pSegcsr).
- IN FLIGHT (agents drafting): fts3_snippet.c (snippet/offsets/matchinfo +
  sqlite3Fts3ExprIterate), fts3_tokenizer.c (tokenizer registry),
  fts3_tokenize_vtab.c (fts3tokenize vtab) — these complete FTS3.

### Remaining after FTS3 family
- **FTS5** (active): fts5.c is a 28k-line generated amalgamation (ext/fts5/*.c +
  Lemon fts5parse). Per project rule, port the individual ext/fts5 sources, not
  the amalgam — a multi-file sub-project.
- Non-portable for a Linux engine: parse.c/opcodes.c (generated), os_win/
  mutex_w32 (Windows), mem0/2/3/notify/os_kv/icu/fts3_icu/rbu (flag-inactive),
  tclsqlite-ex (TCL harness).

### Known issues (FTS3, to fix later — both in fts3.zig query-eval side)
- `order=desc` FTS tables corrupt after a segment flush (reproduces with C
  fts3_write linked → a fts3.zig bug). Default order=asc works.
- (FIXED in 86) fts3SegReaderCursorFree null force-unwrap crashing phrase cleanup.

## Earlier status: 83 modules; core engine + rtree + session in Zig

**Modules 82–83: the first two self-contained extensions** (atop the complete
core engine):
- `rtree.c` (82) → `src/rtree.zig` — R*Tree spatial vtabs + the geopoly extension
  (geopoly.c is #include'd in, so one Zig module). Byte-exact big-endian node
  format; agent self-validated byte-identical to C (5000-row 3-D rtree + full
  geopoly) and fixed a real rtreeStepToLeaf double-pop bug.
- `sqlite3session.c` (83) → `src/sqlite3session.zig` — session/changeset/
  changegroup/rebaser (59 exports); changeset binary format byte-exact (emits
  byte-identical changesets to C).

### Remaining work (all NON-core)
- **FTS3 family** (active via FTS4): fts3.c, fts3_write.c, fts3_snippet.c,
  fts3_expr.c, fts3_tokenizer.c, fts3_tokenize_vtab.c (~16k lines, share fts3Int.h;
  fts3_hash/porter/tokenizer1/unicode/unicode2/aux already ported). Portable
  per-file.
- **FTS5** (active): fts5.c is a 28k-line AMALGAMATION (generated: ext/fts5/*.c +
  Lemon fts5parse). Per the project rule (don't hand-port generated files), the
  correct approach is to port the individual ext/fts5/fts5_*.c sources, not the
  amalgam — a multi-file sub-project.
- **Not portable for a Linux engine:** parse.c/opcodes.c (generated from
  parse.y/vdbe.c), os_win.c/mutex_w32.c (Windows), mem0/2/3.c/notify.c/os_kv.c/
  icu.c/fts3_icu.c/sqlite3rbu.c (flag-inactive → compile to nothing), tclsqlite-ex.c
  (TCL test harness, non_tu).

### Known issues added this batch
- `sqlite3_preupdate_new` (vdbeapi.zig) returns SQLITE_NULL for an INTEGER PRIMARY
  KEY rowid-alias column (iPKey path mis-fires) → breaks session change-recording
  for rowid tables (WITHOUT ROWID / non-alias-PK work). Pre-existing, reproducible
  without session; a vdbeapi fix for later. See Known issues.

## Earlier status: 81 modules; the ENTIRE ACTIVE LINUX CORE is now Zig

**Modules 76–81 (this batch) complete the core engine:**
- `mutex_unix.c` (76) — pthreads mutex backend (every mutex op).
- `main.c` (77) — connection control surface (open/close/config/errors/all hooks/
  create_function/collation; 100 exports; variadic config via @cVaArg).
- `ctime.c` (78) — compile-option list (comptime 56 prod / 59 tf; was deferred,
  resolved by C-probing both flag sets).
- `global.c` (79) — THE KEYSTONE: sqlite3Config instance (byte-exact 440/488) +
  CtypeMap/UpperToLower/OpcodeProperty tables (byte-verified) + all global data.
  Was deferred ("every offset depends on it"); resolved by byte-diffing vs C.
- `treeview.c` (80) — DEBUG-only AST printing (0 symbols prod / 31 tf).
- `os_unix.c` (81) — the Unix VFS: ALL file I/O, POSIX locking, WAL shm, mmap,
  the aSyscall fault table, 4 registered VFSes. Agent self-validated (WAL+
  checkpoint, rollback journal, mmap, 20k external sort, cross-process locking).

Every layer is now Zig on Linux: global config + ctype tables → os_unix VFS →
pager/wal → btree → vdbe → tokenize/resolve → expr/where*/select codegen →
func/json/window → main/legacy/prepare API → pragma/alter/analyze/vacuum/etc.
What remains is NOT core: optional extensions (fts3*/fts5/rtree/icu/session/rbu),
other-platform files (os_win/mutex_w32), flag-inactive stubs (mem0/2/3/notify/
os_kv), and generated files never hand-ported (parse.c/opcodes.c).

Recurring integration bug classes (caught across all big ports via gdb/EXPLAIN-
diff): wrong hardcoded constants (P4_/SRT_/SF_/TF_/SQLITE_DYNAMIC/WO_), C `int`/
`i16` fields read at the wrong width, char[]-symbol address-is-data, inline-array-
vs-pointer, struct bitfield bit positions, and C macros declared as extern fns.

## Earlier status: 75 modules; the ENTIRE SQL COMPILER is now Zig

**Modules 72–75: the SQL query-processing quintet completed** (expr was #71):
`whereexpr.c`, `wherecode.c`, `where.c`, `select.c` →
`src/{whereexpr,wherecode,where,select}.zig`. Drafted by parallel agents,
integrated + validated one at a time atop a C base.
- `whereexpr.c` (72) — WHERE→WhereTerm analysis, LIKE/GLOB/OR optimization.
  Fixes: exprIColumn i16-read, sqlite3StrBINARY char-array, Toupper/Tolower macros.
- `wherecode.c` (73) — WHERE-loop VDBE codegen (seeks/scans/OR/joins/vtab/RJ).
  Fix: sqlite3VdbeScanStatus no-op (SCANSTATUS off).
- `where.c` (75) — the cost-based optimizer/planner. Agent self-validated
  (20/20 + EXPLAIN QUERY PLAN byte-identical to C) and pre-fixed iColumn/StrBINARY
  → integrated with ZERO additional fixes. 148 new whereInt.h offsets.
- `select.c` (74) — SELECT codegen (GROUP BY/HAVING/DISTINCT/compounds/subquery
  co-routines+materialization/recursive CTEs). Fixes: constInsert null-ptr guard;
  4 macros inline; **SQLITE_DYNAMIC** is &sqlite3RowSetClear not 1 (corrupted every
  aggregate's colName Mem); **TF_Ephemeral** is 0x4000 not 0x2 (materialized CTEs
  opened as real tables → -32768 transient-iDb segfault).
Now Zig end-to-end: tokenize → resolve → expr/where*/select codegen → VDBE →
btree → pager. Validated: zig build test GREEN; broad smoke correct across
aggregates, all compound selects, subqueries, views, joins, window funcs,
recursive CTEs, index selection, EXPLAIN QUERY PLAN.

**71st module: `expr.c` → `src/expr.zig` — expression code generation** (~5400
lines, 112 exports): affinity/collation, sqlite3Expr* construction & dup,
ExprCode/CodeTarget + IfTrue/IfFalse, IN/EXISTS/scalar-subquery setup, CASE/
BETWEEN, scalar+aggregate function calls, vector compares, aggregate analysis.
Six integration bugs found & fixed while validating (all in the drafted port,
see commit): listA() deref of the ExprList.a INLINE array; wrong P4_* operand
constants (P4_REAL collided with P4_VTAB); FUNC_RETURNED sentinel vs the
RunJustOnce register (scalar funcs → 0.0); wrong SRT_Set/Mem/Exists; the
ExprCodeExprList OMITREF two-counter loop (ORDER BY/window dropped columns past
the first); FG_fixedSchema bit 1<<25→1<<24 (views/triggers "no such table .t").
Validated: zig build + `zig build test` GREEN; broad production-shell smoke
correct across arithmetic/CASE/IN/EXISTS/subquery/CAST/collation/LIKE/GLOB/
window/CTE/**views**/**triggers**/JSON. Two surfaced issues are BOTH **confirmed
PRE-EXISTING** (each reproduces with C `expr.c` linked, so neither is from this
port — they live in another already-ported module): (1) select1-6.20 (compound
`UNION…ORDER BY LIMIT` inside IN) is correct in the production shell but
segfaults in the `--dev` SQLITE_DEBUG testfixture; (2) `agg() FILTER(WHERE…)`
combined with other aggregates returns a wrong count (sibling-aggregate register
issue). Added to Known issues for separate follow-up.

**70th module: `malloc.c` → `src/malloc.zig` — the core allocation interface
above mem1/mem5** (public sqlite3_malloc* API + internal sqlite3DbMalloc*/
sqlite3OomFault/ApiExit/…; 37 exports). Feeds the SQLITE_STATUS_MEMORY_*
counters via the just-ported status.zig. Validated via the **main build**
(functional + 200k-blob/5000-row-CTE smoke green; clean link = C dropped);
malloc.c is library-core so the testfixture `--zig` swap can't reach it. Its
`malloc.test --zig` run aborts at malloc-13.transient.284 on the pre-existing
OOM-unwind double-free (Known issues) — baseline C fixture passes, so unrelated.

**Modules 65–69 (batch): `status.c`, `btmutex.c`, `dbpage.c`, `dbstat.c`,
`memdb.c` → `src/{status,btmutex,dbpage,dbstat,memdb}.zig`.** Drafted by parallel
sub-agents, integrated against HEAD.
- `status.c` — sqlite3_status / sqlite3_db_status counters (reads sqlite3
  lookaside + Hash internals via ground-truth offsets).
- `btmutex.c` — btree-subsystem mutex (Enter/Leave/EnterAll/EnterCursor);
  Holds*/SchemaMutexHeld `@export`-gated on `config.sqlite_debug`.
- `dbpage.c` — `sqlite_dbpage` vtab (raw page read/write). **--zig validated:
  dbpage 0/34.**
- `dbstat.c` — `dbstat` vtab (per-page btree storage stats; byte-exact page
  parsing).
- `memdb.c` — in-memory VFS + sqlite3_serialize/deserialize.
`notify.c` evaluated and **skipped**: `SQLITE_ENABLE_UNLOCK_NOTIFY` is OFF →
preprocesses to zero symbols, nothing to swap.

While validating, fixed a **pre-existing crash** in `build.zig`
`sqlite3FinishCoding` (commit 73f8cbc): OP_Transaction read `Schema.schema_cookie`
/`iGeneration` (C `int`) as `u32`+`@intCast`, panicking on high-bit-set cookies
(reachable via PRAGMA schema_version on a deserialized db). Now reads `c_int`
sign-preserving. Repro `memdb1-710`: was a hard crash, now 0/38.

### ⚠ Testfixture --zig swap limitation (discovered this session)
`tools/tcltest.sh --zig` swaps a module only if upstream's `make testfixture`
link command compiles `$UPSTREAM/src/<m>.c` as a **standalone** object (verified
via `build/gen/relink_zig.sh`). Modules that live only inside `libsqlite3.a`
(e.g. `status`, `btmutex`, `memdb`, and the earlier `vdbesort`) are **not**
reachable by the textual swap, so `--zig` runs their **C** version — a passing
`--zig` line for those does NOT prove the Zig port. Swappable this batch:
`dbpage`, `dbstat`, `pragma`, `build` (and most front-end modules). For the
non-swappable ones, the **main `zig build`** is the real validator: `build.zig`
`ported_modules` drops the C TU and links `src/<m>.zig`, so a clean link (no
duplicate-symbol error) + green `zig build test` + smoke tests confirm the Zig
code is the one running. TODO: extend the harness to also rebuild the static lib
from swapped objects so library-core modules get true `--zig` coverage.

**64th module: `pragma.c` → `src/pragma.zig` — PRAGMA statements + the
eponymous `pragma_*` virtual table. The giant `sqlite3Pragma()` dispatcher plus
`sqlite3GetBoolean`, `sqlite3JournalModename`, `sqlite3PragmaVtabRegister`. The
`aPragmaName[]`/`pragCName[]` tables are config-divergent (66 prod / 75 --dev,
9 SQLITE_DEBUG-only pragmas) — both built, selected via `config.sqlite_debug`.
Bitfield byte reads (Column.notNull/eCType, Index.idxType/hasStat1, Parse
okConstFactor) probed and config-invariant. Validated `--zig`: pragma 0/236,
pragma2 0/27, pragma3 0/29, pragma4 0/108 — 0 errors out of 400.**

**63rd module: `vdbesort.c` → `src/vdbesort.zig` — the external merge sorter
(ORDER BY / GROUP BY / CREATE INDEX): in-memory sort, PMA spill-to-disk,
multi-way merge, multi-threaded worker paths. Validated `--zig`: orderby8 201,
orderby1 65, sort2, sorterref (0 errors), 150k-row external sorts correct.
Drafted by a background agent, integrated against HEAD.**

**62nd module: `alter.c` → `src/alter.zig` — ALTER TABLE (RENAME TABLE / ADD /
DROP / RENAME COLUMN, ADD/DROP CONSTRAINT, the rename-token walkers + 9 internal
SQL functions). Validated `--zig`: altercol 258, altertab 138, alterdropcol 103
(0 errors); the one alter-20.3 failure is a pre-existing STRICT-table bug (see
Known issues). Drafted by a background agent, reviewed/integrated against HEAD.**

**61st module: `tokenize.c` → `src/tokenize.zig` — the SQL tokenizer,
the keywordhash.h keyword tables, and the Lemon-parser driver
(`sqlite3GetToken`/`sqlite3RunParser`/`sqlite3KeywordCode`/`sqlite3_keyword_*`).
Keyword tables verified byte-for-byte; validated via `tcltest --zig` tokenize
(15) / keyword1 (117) / select1 (192) / where2 (107), 0 errors. (Drafted by a
background agent; integration fixed an `nVar` read-as-c_int that spilled into
`Parse.explain` and broke EXPLAIN reprepare — see Known issues "fixed".)**

**60th module: `upsert.c` → `src/upsert.zig` — UPSERT / ON CONFLICT.**
Implements the whole Upsert lifecycle + codegen
(`sqlite3Upsert{Delete,Dup,New,AnalyzeTarget,NextIsIPK,OfIndex,DoUpdate}`).
Validated through the production `zig build` across every path upsert.c
handles: DO UPDATE / DO NOTHING, `excluded.*`, composite-UNIQUE targets,
partial-index targets, expression-index targets (XN_EXPR/aColExpr), WITHOUT
ROWID (the `sqlite3PrimaryKeyIndex`/`OP_Found` leg of DoUpdate), and chained
multi-ON CONFLICT. `zig build test` green.

While validating module 60, found + fixed a **RETURNING crash** and diagnosed
two more pre-existing bugs — see Known issues.

**59th module: `analyze.c` → `src/analyze.zig` — the ANALYZE command
(statInit/statPush/openStatTable writing `sqlite_stat1`) and
`sqlite3AnalysisLoad`/`analysisLoader` (reading stats back so the planner uses
them). Gold-validated: all upstream `analyze*` TCL tests pass with the Zig
module linked in (`analyze`=41, `analyze7`=16, `analyzeC`=25, … 0 errors
across 13 files), plus a new in-gate `engine_test` ANALYZE case (the functional
battery never exercised ANALYZE). STAT4 is off in this config, so the sampling
paths are compiled out.**

While integrating it, ran down a long-standing **false-alarm flake** in
`zig build test`: rare "exec error: FOREIGN KEY constraint failed" + "failed
command" reports. Root cause was *not* an engine bug — the `engine_test.zig`
`exec()` helper unconditionally wrote the errmsg to stderr even for the FK
test's *expected* constraint failure, and a mid-test stderr write occasionally
upset the Zig `--listen=-` build-runner protocol. The engine binary itself
passes 0/600 seed orderings with non-zero exit. Fixed by adding a silent
`execExpectFail()` helper for statements expected to fail. (analyze.zig was
exonerated early: the flake reproduced identically with C `analyze.c`.)


**Milestone (this commit): `vdbe.c` → `src/vdbe.zig` — the 9.5k-LOC bytecode
interpreter (`sqlite3VdbeExec`) now runs in Zig.** All 192 opcodes are handled;
the entire storage engine (pager/wal/btree), the VDBE plumbing
(vdbemem/vdbeapi/vdbeaux), and now the interpreter itself are Zig. The Zig
interpreter passes the upstream TCL suite broadly in the strict `--dev`
(SQLITE_DEBUG) config — `select1/select2/select4/subquery/join/aggnested/
update/delete/trigger1/index/insert/where` all **0 errors** (1000+ tests) — plus
the local `zig build test` gate (18/18 Zig unit tests + `functional.sql`).

Bugs found and fixed while integrating `vdbe.zig` (an agent-generated file whose
connection dropped mid-task, so it was never run before integration): missing
`pc += 1` fall-throughs in `OP_Next`/`OP_Prev`/`OP_SorterNext`/`OP_Count`/
`OP_IntegrityCk`/`OP_RowSetRead`/`OP_VNext` (infinite opcode re-execution);
`sqlite3aGTb/aLTb/aEQb` mis-declared as arrays instead of pointer variables
(broke every comparison operator → "malformed" on `CREATE TABLE`); `@memcpy`→
`@memmove` for legitimately-aliasing rows in `OP_MakeRecord` and `vdbemem`
SetStr/SetText; two dropped no-op/DEBUG-only helpers (`sqlite3VdbeIOTraceSql`,
`sqlite3VdbeIncrWriteCounter`).

### Fixed since the vdbe.zig integration

- **FTS5 write lookaside corruption** — FIXED (commit `f0c8136`). Root cause was
  `MEMCELLSIZE` defined as 48 instead of `offsetof(Mem,db)`=24, so `OP_Variable`'s
  `memcpy(pOut,pVar,MEMCELLSIZE)` copied past the shallow-copy prefix into the
  `szMalloc`/`zMalloc` ownership fields → register and bound-param shared a buffer
  → double-free. FTS5 re-enabled in `functional.sql`.
- **`UPDATE` on a virtual table** — FIXED (commit `497a211`). `update.zig` had
  `TABTYP_VTAB`/`VIEW` swapped, so vtabs misclassified as views and skipped the
  one-pass `updateVirtualTable` path.

### Known issues

Two pre-existing bugs surfaced (proven *not* in vdbesort — both reproduce with C
`vdbesort.c` linked); both are off the default path:

- **`printf.zig` va_list crash from a worker thread.** With `PRAGMA threads=N>0`,
  a background sorter thread's temp-file name creation
  (`unixGetTempname`→`sqlite3_snprintf`→`sqlite3_str_vappendf`) crashes in the
  va_list path. Default `PRAGMA threads` is 0, so normal use is unaffected;
  `testfixture_zig` (sane stack) passes the `nWorker=3` sort combos.
- **`btree.zig balance` OOM panic** (btree.zig:5610) on a `fakeheap`/OOM-injection
  path during a post-sort index insert (`sort.test` combo 5 / `sortfault` final
  abort). A btree OOM-unwind issue, not sorter.
- **Compound subquery in IN segfaults under SQLITE_DEBUG** — `select1-6.20`
  (`… IN (SELECT … UNION SELECT … ORDER BY 1 LIMIT 1)`) is correct in the
  production shell but raw-segfaults (memory corruption, no Zig trace) in the
  `--dev` testfixture. Proven PRE-EXISTING: reproduces with C `expr.c` linked, so
  it lives in another ported module (vdbe/btree/select-coordination), not expr.
- **`agg() FILTER(WHERE…)` with sibling aggregates** returns a wrong count
  (`count(*) FILTER(WHERE a>1), max(c), min(a)` → 0 instead of 2; the count drops
  by one per sibling aggregate — a register-assignment collision). PRE-EXISTING:
  reproduces with C `expr.c` linked.

**Fixed (STRICT enforcement + view/op-array corruption + EXPLAIN-reprepare):**

- **STRICT tables silently accepted type-mismatched values** (`vdbe.zig`
  COLTYPE_* off-by-one). eCType is CUSTOM=0/ANY=1/…/TEXT=6, but opTypeCheck used
  ANY=0…TEXT=5, so a TEXT column matched no switch arm (no check) and others got
  a neighbour's check. Fixed → strict1 0/51, alter 0/123. insert.zig/build.zig
  already had the right values.

- **Op-array corruption on any view query** (`695a494`). `build.zig`'s
  view-column-name resolver read/wrote `Lookaside.sz`/`szTrue` as u32 instead of
  u16 (real: u16 @436/@438), zeroing `szTrue`. `sqlite3DbMallocSize` then
  returned a bogus size and `growOpArray`'s realloc dropped already-emitted
  opcodes → zeroed op-slots dispatched as `OP_Savepoint(0)` → crash. Hit ANY
  query referencing a view; surfaced as the EXISTS-over-compound-view crash and
  `where2-6.17.2`. Root-caused via gdb (background agent); fkey.zig/c_layout
  already had the correct layout. `where2` now 0/107.
- **`tokenize.zig` nVar read-as-c_int** (`540ff3c`). `nVar` is `ynVar`=i16; the
  c_int read in the `sqlite3RunParser` preamble assert spilled into
  `Parse.explain@299`, so an EXPLAIN going through `sqlite3Reprepare` (explain=2)
  spuriously panicked (`where2-12.1`). Read as i16.

**Fixed earlier this session (RETURNING was completely broken + 2 Index-flag bugs):**

0. **`Index_bHasExpr_byte` off-by-one** in delete.zig & insert.zig (101→100,
   commit `67894c4`). bHasExpr is at byte onError+2, not onError+3 (padding), so
   `idxBHasExpr()` always read false → expression/virtual-column index
   maintenance shortcuts were skipped on DELETE/UPDATE. Found by an audit of all
   ported modules' hardcoded offsets/opcodes/bitfield-masks vs probed ground
   truth (the audit otherwise came back clean: all 488 opcode constants and the
   other live offset fallbacks/bitfield masks verified correct).


1. **`build.zig deleteReturning`** dereferenced the inline `Returning.zName`
   char[40] as a pointer → **every `… RETURNING` statement segfaulted**. Now
   passes the buffer address (commit `121e029`).
2. **`update.zig` `OP_OpenWrite` misnumbered 113 → 116.** 113 is actually
   `OP_ReopenIdx`, so the UPDATE data cursor opened as an index cursor and
   `UPDATE … RETURNING` returned the *rowid* for any unchanged column. Audited
   every `OP_* = n` constant across `src/*.zig` vs opcodes.h — this was the only
   one wrong (commit `de664ed`).
3. **`build.zig` Index bitfield masks** were laid out for an older field order
   (byte-1 omitted `isResized`; byte-2 bits for `bAscKeyBug`/`bHasVCol`/
   `bHasExpr` shifted; `isResized` placed in a bogus third byte) → `bHasExpr`
   set at the wrong bit and read as 0. Probed the real layout
   (`tools/bitprobe.c`, identical prod/testfixture) and corrected it (commit
   `d3384fc`). Now `testfixture_zig` passes upsert1 (36 tests) where it
   previously aborted on `assert(pIdx->bHasExpr)`; index/index2/index3/
   indexedby/where all 0 errors under `--zig`.

A new `engine_test` "RETURNING on insert/update/delete/upsert" guards #1 and #2
in the gate (the functional battery had no RETURNING coverage, which is why
these survived).

(Note: `tools/tcltest.sh --zig` cannot validate `analyze`/`upsert` — both come
from `libsqlite3.a` rather than an individual testfixture object, so the
`.c`→`.o` swap has nothing to replace. They are validated via the production
build instead. Making tcltest force archive-only objects into the link is a
future improvement.)

(Previously tracked: the vtab1-24.2 FTS3 savepoint assertion — FIXED. It turned
out to share a root cause with an `fkey2` production crash: `OP_Savepoint`'s
RELEASE cleanup recomputed `isTransaction` *after* the commit path had cleared
`db->isTransactionSavepoint`, so it wrongly decremented `db->nSavepoint` for a
transaction savepoint. nSavepoint went negative and a later `ROLLBACK TO`
null-dereffed the pager's savepoint array. Fixed by reusing the single
`isTransaction` local computed before the commit path, matching upstream.)

### Earlier baseline

A Zig build system compiles upstream SQLite C (v3.54.0) into a static
`libsqlite3.a` and a working `sqlite3` CLI, with a green test gate. Twenty-five
modules are now **ported to Zig**: `random.c`, `hash.c`, `bitvec.c`, `rowset.c`,
`fault.c`, `mem1.c`, `complete.c`, `memjournal.c`, `fts3_hash.c`, `utf.c` (first
**core-struct-coupled** module), `os.c` (VFS dispatch — every file I/O now Zig),
plus a parallel-agent batch: `fts3_porter.c`, `fts3_tokenizer1.c`,
`fts3_unicode.c` (FTS3 tokenizers), `carray.c` (table-valued fn / vtab), and
`table.c` (`sqlite3_get_table`).

**Zig-native test suite:** beyond validating against SQLite's TCL `testfixture`,
test cases are also ported to Zig — `test/engine_test.zig` (`zig build test-zig`,
folded into `zig build test`) drives the engine through the public C API and
asserts results, linked against this `libsqlite3.a` so it exercises every ported
Zig module from Zig. Some modules also carry pure-logic Zig `test` blocks.

**Scaling via agents:** ports are now parallelized — sub-agents do the
read-C/write-Zig work (each a new `src/<name>.zig`); the orchestrator owns the
shared files (build.zig, tcltest.sh, c_layout.zig/offsets.c) and runs the
authoritative build + TCL validation + commit, sequentially.

Each passes the functional gate (`zig build test`) and SQLite's own TCL
`testfixture` suite with the Zig objects swapped in. Notably the Zig `mem1`
allocator now backs **every** allocation in the engine, and `os.c` means every
file I/O dispatches through Zig.

The **comptime-config foundation** is in place (build.zig `-Dtestfixture`, the
`config` options module, the `test-objs` step, and `tools/gen_layout.sh` →
`src/c_layout.zig` ground-truth offset asserts). This is the unblock for modules
that couple to *build-divergent* internal structs (`Mem`, `sqlite3`,
`Sqlite3Config`): the production `zig build` and the `--dev` testfixture differ
by ~33 `-D` flags, so a single Zig object can only satisfy both by mirroring the
struct with config-gated layout and asserting it at comptime against C ground
truth. `utf.c` (Mem) and `os.c` (Sqlite3Config.iPrngSeed) are ported this way.
See [docs/architecture.md](docs/architecture.md).

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
- `utf.c` → `src/utf.zig` — UTF-8/16/16LE/16BE translation. First module to
  mirror a build-divergent core struct (`Mem`): field offsets are invariant but
  sizeof moves 56→72 under SQLITE_DEBUG, matched by a config-gated tail and
  asserted at comptime vs `src/c_layout.zig`. Reads `db->mallocFailed` at its
  ground-truth offset. TCL: enc/enc2/enc3/enc4 (enc4 = 1115 round-trips) in the
  testfixture (debug) config.
- `os.c` → `src/os.zig` — the architecture-independent OS interface: `sqlite3Os*`
  wrappers over the public `sqlite3_file`/`sqlite3_vfs` method tables, plus the
  VFS registry. Reads `sqlite3Config.iPrngSeed` at its (config-invariant)
  ground-truth offset; the SQLITE_TEST fault-injection state
  (`sqlite3_io_error_*` globals + `DO_OS_MALLOC_TEST`) is gated on
  `config.sqlite_test` via comptime `@export` (so it exists only in the
  testfixture build, like C's -DSQLITE_TEST). TCL: ioerr (10885), pager1 (1373),
  lock, mmap1, oserror. (Gotcha fixed: `sqlite3_vfs_unregister(NULL)` must be a
  no-op — the C `vfsUnlink` has a `pVfs==0` branch.)

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
- A mutable C global read from Zig must be declared `extern var`, NOT
  `extern const`, even if Zig only reads it. `const` lets the ReleaseSafe
  optimizer assume the memory never changes and CSE a read across an opaque C
  call that mutates it (observed: `sqlite3Config.pcache2` stale after
  `sqlite3PCacheSetDefault`, crashing `sqlite3PcacheInitialize`). Production
  Debug builds dodge it; the testfixture ReleaseSafe objects expose it.
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
- 2026-06-26: Built the comptime-config foundation (build.zig `-Dtestfixture`,
  `config` module, `test-objs` step; tcltest.sh consumes per-config objects) and
  the ground-truth offset tooling (tools/offsets.c + gen_layout.sh →
  src/c_layout.zig). Then ported `utf.c` on it — 10 modules; first core-struct
  (`Mem`) coupled port, layout asserted at comptime against C. enc/enc2/enc3/enc4
  green in the testfixture (debug) config.
- 2026-06-26: Ported `os.c` (VFS dispatch + registry) on the config foundation —
  11 modules; every file I/O now flows through Zig. SQLITE_TEST fault-injection
  state gated on config.sqlite_test via comptime @export. TCL ioerr(10885)/
  pager1(1373)/lock/mmap1/oserror green.
- 2026-06-26: Began agent-parallelized porting. Added a Zig-native engine test
  suite (test/engine_test.zig, `zig build test-zig`). Integrated a wave of
  agent-written ports: fts3_porter.c, fts3_tokenizer1.c, fts3_unicode.c,
  carray.c (config-invariant) and table.c (reads db->errCode at a ground-truth
  offset) — 16 modules. TCL fts3aa/fts3ad/fts4unicode/carray01/tabfunc01(246)/
  table(97)/tableapi(171)/capi2 green.
- 2026-06-26: Agent wave 2 (4 modules) — mem5 (MEMSYS5; sqlite3Config offsets),
  mutex_noop (debug checking mutex), threads (pthreads sorter helper),
  fts3_unicode2 (fold data). TCL mutex1/mutex2/mem5/fts4unicode/sort green.
- 2026-06-26: Agent wave 3 (2 modules) — stmt.c (sqlite_stmt vtab), mutex.c
  (mutex dispatch; reads sqlite3Config.mutex@96/bCoreMutex@4). The mutex
  subsystem is now fully Zig. TCL mutex1/mutex2/stmtvtab1 green. 22 modules.
- 2026-06-26: Agent wave 4 (2 modules) — vdbetrace.c (sqlite3VdbeExpandSql; reads
  Vdbe + sqlite3 fields at offsets, mirrors StrAccum) and legacy.c (sqlite3_exec;
  now driven by test/engine_test.zig). TCL trace/trace2/capi3(250)/exec/main
  green. 24 modules.
- 2026-06-26: Agent wave 5 — pcache.c (page-cache dispatch; first Phase-3 storage
  module). PgHdr mirrored (ABI-shared) with offset asserts; PCache kept internal
  (opaque). Fixed a latent optimizer bug: `sqlite3Config` is a MUTABLE global but
  was declared `extern const`, letting ReleaseSafe CSE a read across an opaque
  mutation (crashed sqlite3PcacheInitialize in the testfixture) — changed to
  `extern var` in pcache/os/mem5/threads/mutex. TCL pcache/pcache2/pager1(1373)
  green. 25 modules.
- 2026-06-26: Ported `printf.c` (the xprintf / `sqlite3_str` formatting engine —
  used by virtually every subsystem). 26 modules. Two bugs found and fixed:
  (1) **va_list ABI** — Zig mis-lowers a *by-value* `std.builtin.VaList`
  parameter received across the C ABI; `@cVaArg`/`@cVaCopy` on it GP-faults at
  runtime (the prior `@cVaCopy(&ap_in)` workaround crashed at the first arg).
  On x86-64 SysV a C `va_list` param is already a pointer to `__va_list_tag`, so
  every va_list-receiving fn now takes `*VaList` and variadic origins forward
  `&ap` from `@cVaStart()`. Isolated via a C→Zig→Zig micro-test before fixing.
  (2) **`%z` NULL** — `sbufpt = @cVaArg(...) orelse ""` then *unconditionally*
  entered the `%z` adopt-allocation fast-path, calling `sqlite3DbMallocSize` on
  the static `""` (mem1 alignment panic, hit via fts5 `"%z%s?%d"` with a NULL
  seed). Restructured to upstream's `if(bufpt==0) bufpt=""` **else-if**
  etDYNSTRING so a NULL arg skips adoption. TCL --zig green: printf(1439)/
  printf2(51)/format4/func(15031)/func2/e_expr(16619)/select1/where2/misc1/misc3/
  randexpr1/in; engine_test 18/18; functional + amalgamation builds green.
- 2026-06-26: Ported `fts3_aux.c` (fts4aux vtab) — 27 modules. Single export
  sqlite3Fts3InitAux; no new offsets (Fts3Table fields are leading; the
  DEBUG/TEST-only trailing fields gated via @import("config") to match struct
  size). TCL fts3aux1(95)/fts3aux2(24) green.
- 2026-06-26: Ported `callback.c` (collation/function registry) + `vdbevtab.c`
  (bytecode()/tables_used() vtab) — 29 modules. callback bugs: (1) sqlite3StrBINARY
  is a C `char[]` (symbol address IS the string) but was declared as a pointer →
  Zig deref'd the bytes "BINARY\0" as a pointer in strHash at open time; bind it
  as a symbol byte and take its address. (2) FuncDef.nArg (i16) ← C's `(u16)nArg`
  is a bit-truncate (nArg may be -1); @intCast panicked → use @truncate. New
  offsets for sqlite3/Parse/CollSeq/FuncDef/Schema/Hash/Db/VdbeOp/Table/Index/
  Column. TCL collate1-4/func/distinct2/having/upsert1/stmtvtab1/enc green.
- 2026-06-26: Ported `util.c` (varint, atoi/atof, error/progress helpers) — 30
  modules; the foundational utility grab-bag (50 exports). Agent's 45M-case
  differential fuzzing caught sqlite3LogEstToInt (@mod→@rem) and AddInt64/SubInt64/
  MulInt64 (zig cc compiles the GCC<5 fallback that leaves *pA unchanged on
  overflow). The TCL suite caught a third: sqlite3Atoi64 + DecOrHexToI64 hex
  accumulate magnitude in u64 with defined unsigned wrap (re-checked after), but
  the Zig `+` was checked and panicked on 19+ digit literals → `+%`. TCL
  e_expr(16619)/boundary2(3022)/boundary1(1512)/func(15031)/where(318)/expr(661)/
  cast/hexlit/like/misc1,3,5/quote/between/in/intpkey/select1,4 green.
- 2026-06-26: build.zig now also installs the CLI shell as `sqlite-zig` (same
  bytes as `sqlite3`, linked against the ported-Zig lib) so the project ships a
  CLI under its own name.
- 2026-06-26: Ported `loadext.c` (runtime extension loading) — 31 modules. 7
  exports + the 279-slot `sqlite3_api_routines` dispatch table (preprocessed
  from the C initializer). Bug: the agent emitted the 6 ENABLE_COLUMN_METADATA
  entries (sqlite3_column_{database,table,origin}_name(16)) as real symbols, but
  that flag is OFF in both configs → upstream `#define`s them to 0 and the
  symbols don't exist (link error). Nulled those 6 slots. New offsets sqlite3
  aExtension/nExtension. TCL loadext(54)/loadext2(23) green.
- 2026-06-26: Ported `vtab.c` (virtual-table object management) — 32 modules; 30
  exports, the most struct-coupled port (Module/VTable/sqlite3_vtab/Table.u.vtab
  union/Parse/sqlite3 at ground-truth offsets). Bug: `extern fn sqlite3StrNICmp`
  — that name is a C macro aliasing the public sqlite3_strnicmp (no such symbol);
  call sqlite3_strnicmp. Parse.disableTriggers (:1 bitfield) gated on config
  (byte 39 prod / 42 tf). TCL vtab1-9/vtabH/vtabA/fts3aa/fts4aa/carray01/
  stmtvtab1/bestindex1 green.
- 2026-06-26: Ported `prepare.c` (sqlite3_prepare* + schema init) — 33 modules,
  16 exports, on every query's hot path. Two bugs: (1) TriggerPrg.pNext is at
  off 8 (pTrigger is the first field), not 0 — reading 0 corrupted the
  end-of-prepare TriggerPrg cleanup walk and segfaulted on any INSERT firing a
  trigger. (2) SQLITE_*_BKPT helpers (sqlite3{Nomem,Corrupt,Misuse}Error) exist
  only under SQLITE_DEBUG; gated on config.sqlite_debug so the production link
  resolves. Many new offsets incl. nested init.*/lookaside.* composites and the
  PARSE_HDR_SZ/PARSE_RECURSE_SZ macros; Parse.checkSchema (:1 bitfield) gated on
  config. TCL trigger1-3/view/schema/reindex/alter/attach2/capi3(250)/tableapi/
  bind/shared(211) green.

- 2026-06-26: Wave 3 — SQL-command modules `auth.c` (authorization callbacks),
  `vacuum.c` (VACUUM), `attach.c` (ATTACH/DETACH + the DbFixer AST walkers) — 36
  modules. Agents briefed with the gotcha checklist; auth & vacuum landed with no
  new bugs, attach needed only a dup-offset fixup (openFlags already added by
  vacuum) at integration. attach is heavily coupled (SrcItem fg bitfield bytes +
  u3/u4 unions, Select/With/Cte/TriggerStep/Trigger/Upsert/Walker/DbFixer at
  ground-truth offsets; sqlite3_vfs.zName is at off 24 not 0). TCL --zig green:
  auth(377) vacuum3(6062) attach(113)/attachmalloc(3037) + trigger1/2/4/view/
  alter exercising the fixers.

- 2026-06-26: Wave 4 — `backup.c` (online backup; first to read Btree/BtShared,
  added btreeInt.h to offsets.c), `date.c` (date/time fns, bit-exact; fixed a
  0-arg null-argv @ptrCast panic), `vdbeblob.c` (incremental BLOB; 4 config-
  DIVERGENT VdbeCursor offsets), `fkey.c` (foreign keys), `trigger.c` (triggers
  +RETURNING; agent self-fixed a FinishTrigger double-free), and **`pager.c`**
  (the ~7800-LOC pager monolith — 75 exports, page txns/rollback journal/
  savepoints/WAL-handoff/hot-journal recovery; only 1 new offset). 43 modules.
  Every byte of file I/O now flows through ported-Zig pager→pcache→os/VFS.
  TCL --zig green incl. pagerfault(31589), ioerr(10885), savepoint4(3469),
  backup_ioerr(81377), fkey2(1217), triggerA(214), date4(24860), incrblob_err(2700).

- 2026-06-26: Wave 5 (storage core + VDBE plumbing). Committed: `pager.c`,
  `wal.c`, `vdbemem.c`, `vdbeapi.c` — **46 modules**. The whole transaction layer
  (rollback journal + WAL) and the Mem/value layer and the public step/column/
  bind/result API are now Zig. Integration bugs fixed: vdbemem UTF-16 number
  prefix (check high byte before copying low); vdbeapi `db->mTrace` is u8 not u32
  (misaligned u32 load crashed step on the first query). TCL --zig green incl.
  pagerfault(31589), walfault(6520), capi3(250), bind(119), func(15031),
  fkey2(1217), select1/where/expr.
- 2026-06-26: Ported **`btree.c`** — 47 modules. The largest, most format-
  critical file (~11600 LOC, 83 exports): on-disk page format, cursors, balancing,
  overflow chains, autovacuum/ptrmap, shared-cache. The agent self-validated via
  byte-exact differential testing vs C + bidirectional cross-version compat and
  fixed 5 bugs itself; integration only needed exporting sqlite3SharedCacheList
  under config.sqlite_test (test_btree.c reads it). TCL --zig green incl.
  **corrupt(12288)**, autovacuum(339), index(121), shared2, fkey2(1217). The
  whole storage engine (pager+wal+btree) is now Zig.
- 2026-06-26: Ported `vdbeaux.c` (bytecode assembly + record/serial codec) —
  48 modules. The whole VDBE plumbing (vdbemem+vdbeapi+vdbeaux) is now Zig; only
  the vdbe.c interpreter stays C. 9 integration bugs fixed, incl. KeyInfo.aColl
  being an inline array (3 double-deref crashes), Parse.nVar as i16 (EXPLAIN's
  explain byte made nVar=0x02000000 → 2.4GB alloc), and sqlite3_module.xClose at
  56 not 64 (=xFilter, segfaulting vtab teardown). TCL --zig green: join(192)
  where(318) eqp(65) collate(384) vtab1(223) tabfunc01(246) rowvalue(307) etc. vdbeaux had 7 bugs found
  & fixed during integration (3 macro/config-gated externs — sqlite3VtabInSync is
  a macro, sqlite3ConnectionUnlocked/sqlite3FileSuffix3 are no-ops, disable/
  enable_simulated_io_errors are SQLITE_TEST-only; SQLITE_LIMIT_VDBE_OP index is 5
  not 11; the colCache check must read the :1 bitfield bit 0x10 at byte 5/7, NOT
  pCache!=0 since allocateCursor only zeroes up to offsetof(pAltCursor); nTempReg
  is u8 not int; sqlite3OpcodeProperty is a char[] — bind the symbol address, not
  a [*]const u8). It now runs basic queries/index seeks/order-by/integrity_check,
  but still crashes in the FindCompare/RecordCompare path (pKeyInfo deref) — the
  record codec is correctness-critical (silently-wrong comparators corrupt index
  order), so it needs a dedicated validation pass against the full suite before
  committing. btree.zig (66 exports) was never integrated/debugged. See
  [[vdbeaux-btree-deferred-wip]].

- 2026-06-26: Ported `insert.c` (INSERT-statement codegen) — `src/insert.zig`.
  14 exports incl. sqlite3Insert, sqlite3GenerateConstraintChecks (the big
  NOT-NULL/CHECK/UNIQUE/PK + REPLACE-recheck constraint engine),
  sqlite3CompleteInsertion, sqlite3OpenTableAndIndices, sqlite3OpenTable,
  sqlite3{Index,Table}AffinityStr, sqlite3TableAffinity,
  sqlite3ComputeGeneratedColumns, sqlite3Autoincrement{Begin,End},
  sqlite3MultiValues{,End}, sqlite3ExprReferencesUpdatedColumn, plus the
  SQLITE_TEST-only `sqlite3_xferopt_count` (comptime @export). Static helpers
  (xferOptimization + the xferCompatible* checks, autoIncBegin/Step/End,
  readsTable, computeIndexAffStr, IndexIterator, codeWithoutRowidPreupdate)
  are private Zig fns. New c_layout offsets (all config-invariant): Table
  zColAff/nNVCol/keyConf/pCheck, Subquery addrFillSub/regReturn/regResult,
  AutoincInfo {pNext,pTab,iDb,regCtr}+sizeof, Index zColAff/aSortOrder/aColExpr,
  Parse.pAinc, Schema.pSeqTab, Select.op. Bugs found & fixed: (1) IdList.a is an
  INLINE flex array (`int nId; struct{char*zName;} a[]`) — take its address, not
  deref-as-pointer (the classic gotcha; produced empty column names →
  "table t has no column named " + segfault). (2) ~40 opcode/token/flag/offset
  constants re-probed against ground truth (OP_Eq/Ne and OP_Affinity/TypeCheck
  were *swapped* vs my first guess; OP_Goto=9, TK_INSERT=128, SRT_Coroutine=11,
  COLFLAG_NOTAVAIL=0x80, Upsert isDoUpdate@40/pUpsertIdx@56, etc.).
  (3) VdbeVerifyAbortable/VdbeReleaseRegisters are SQLITE_DEBUG-only macros —
  `@extern` them only inside `if (config.sqlite_debug)` so production never
  references the symbol. (4) VdbeModuleComment ("BEGIN/END: GenCnstCks") is a
  no-op unless SQLITE_ENABLE_MODULE_COMMENTS (off both configs) — must NOT emit
  those Noops, but VdbeComment/VdbeNoopComment ARE on (EXPLAIN_COMMENTS) and must
  be reproduced for address-identical bytecode. Validated: `zig build`/`zig build
  test` green; EXPLAIN of upsert + OR REPLACE insert byte-identical vs pure-C;
  differential smoke (multi-row, INSERT…SELECT, OR REPLACE/IGNORE, ON CONFLICT DO
  UPDATE, AUTOINCREMENT, trigger insert) byte-identical Zig vs amalgamation. TCL
  --zig 0 errors: insert(84) insert2(32) insert3(19) insert4(96) insert5(13)
  conflict(148) upsert1(36) autoinc(88) trigger1(89). NOTE: fkey2-2.48 crashes in
  `sqlite3PagerSavepoint` (pager.zig:3156, `aSavepoint.?` null-deref on a
  SAVEPOINT) — confirmed PRE-EXISTING by reverting insert.c to C and reproducing
  the identical panic; unrelated to insert codegen (it's the documented debug-only
  savepoint path in pager.zig). Differential C-baseline fkey2 = 0/1217.

### Resume guide — continuing the agent-parallelized migration
The authoritative ordered list of ported modules (with one-line descriptions) is
`ported_modules` in [build.zig](build.zig). To port the next module(s):
1. Spawn a general-purpose sub-agent per module with the playbook prompt used
   this session (point it at docs/architecture.md, PROGRESS "Porting playbook",
   and the closest example in src/*.zig; tell it to ONLY create src/<name>.zig,
   use ground-truth offsets via @import("c_layout.zig") for build-divergent
   internal struct fields, and report needed offsets — never edit shared files).
2. Integrate (orchestrator, sequential): if the agent reported new struct field
   offsets, add `P(<Struct>, <field>);` to tools/offsets.c and run
   `tools/gen_layout.sh`; add `"<name>.c"` to `ported_modules` in build.zig and
   the stem to `MODULES` in tools/tcltest.sh; `zig build` (comptime offset
   asserts validate the mirror); `zig build test`; `tools/tcltest.sh --zig
   <relevant tests>`; commit.
Good next targets: the storage core `btree.c`/`wal.c` and the VDBE plumbing
`vdbeaux.c`/`vdbemem.c`/`vdbeapi.c`/`vdbesort.c`, then the `vdbe.c` interpreter
and the SQL codegen (expr/select/where/build/insert/update/delete/resolve/
walker), analyze.c, pragma.c, alter.c. See `ported_modules` in build.zig for the
43 done (… prepare, auth, vacuum, attach, backup, date, vdbeblob, fkey, trigger,
pager). pager is Zig; btree (still C) calls into it via the stable Pager ABI.
Gotcha patterns that each cost real debug time — brief the agents on these:
  - **Struct field ORDER**: never assume a field is at offset 0 / "first". Probe
    EVERY field with offsetof (TriggerPrg.pNext is at 8, not 0 — that crashed the
    trigger path). Add a `P(Struct,field)` so the comptime assert catches it.
  - **u64 wrap**: C unsigned accumulation (`x = x*10 + d`) wraps by definition —
    port with `*%`/`+%` where magnitude is re-validated after (not bounded before).
  - **`char[]` symbol**: its *address* is the data — bind `extern const <name>: u8`
    and take `&`, never a `[*:0]const u8` value.
  - **`(u16)x`/`(i16)x` to a field**: bit-truncate → `@truncate`, not `@intCast`.
  - **C `va_list` parameter**: take `*std.builtin.VaList`, not by value.
  - **Macro-alias symbols**: `sqlite3StrNICmp`=macro→`sqlite3_strnicmp`;
    `SQLITE_*_BKPT` error fns (`sqlite3{Nomem,Corrupt,Misuse}Error`) exist only
    under SQLITE_DEBUG — gate calls on `config.sqlite_debug`.
  - **Flag-gated api/table entries** (loadext): match the build's flags; OFF →
    the symbol may not exist (NULL the slot).
Deferred and why: ctime.c (compile-option list diverges by ~many flags → expand
the `config` options module first); global.c (defines the sqlite3Config struct
itself — every c_layout offset depends on it; high-stakes, do deliberately).
