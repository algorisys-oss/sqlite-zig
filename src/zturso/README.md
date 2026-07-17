# sqlite-zturso — experiments over the ported Zig engine

> **Branch-only.** These files exist on the `sqlite-zturso` fork and never merge
> to `main`/`dev`. See [EXPERIMENT.md](../../EXPERIMENT.md) for the charter and
> governance. `main` stays byte-identical to upstream SQLite; this fork builds
> Turso-style capabilities *on top of* the already-ported Zig VDBE/engine.

This directory answers one question: **the sqlite-zig port already reimplemented
SQLite's engine in Zig — what can we build on it that upstream SQLite can't do,
the way Turso does on its own engine?** (Inspired by Turso's "LLVM of databases"
thesis; see [docs/turso-comparison.md](../../docs/turso-comparison.md).)

Every file here is compiled with the **same `sqlite_flags`** as the ported
modules and linked against our `libsqlite3.a`, so the demos exercise the **real
ported Zig engine**, not stock SQLite.

## Run it

```bash
zig build zturso-test     # run every demo as a pass/fail gate (all must exit 0)

zig build zturso          # Phase 1: SQL frontend (text -> AST -> VDBE), incl. FROM/WHERE
zig build zturso-poc      # Phase 1a: the atomic hand-emitted-bytecode proof
zig build zturso-vfs      # Phase 2: route engine I/O through a pluggable VFS
zig build zturso-vector   # Phase 4: vector search (kNN) via registered functions
zig build zturso-mvcc     # Phase 3: concurrency baseline demo (marks the MVCC boundary)

# ad-hoc: our frontend compiling arbitrary SQL to VDBE and running it
zig build zturso && ./zig-out/bin/zturso_frontend "SELECT name, salary FROM emp WHERE salary >= 125"
```

None of these touch `zig build` or `zig build test` — the fidelity build stays
free of experimental artifacts and `libsqlite3` is unchanged.

## Status by phase

| Phase | What | Status | Demo |
|---|---|---|---|
| **1a** | Hand-emitted VDBE program (no parser) runs on the ported interpreter | ✅ working | `zturso-poc` → `poc_frontend.c` |
| **1b** | Integer-expression dialect: text → tokenizer → AST → register-allocating codegen | ✅ working | `zturso` → `frontend.c` |
| **1c** | Real table reads: `SELECT … FROM t WHERE …` via cursor opcodes; output **byte-identical to SQLite** (differential self-check) | ✅ working | `zturso` → `frontend.c` |
| **2** | Pluggable VFS: all engine I/O routed through a custom `sqlite3_vfs` (the seam an `io_uring` backend plugs into) | ✅ seam proven | `zturso-vfs` → `trace_vfs.c` |
| **4** | Vector search: `vec_l2`/`vec_cosine`/`vec_dot` + a kNN query, all via the public function API | ✅ working | `zturso-vector` → `vector.c` |
| **3** | MVCC / `BEGIN CONCURRENT` (concurrent writers) | ⛔ **design only** — multi-month pager/btree rewrite; demo marks the boundary | `zturso-mvcc` → `mvcc_demo.c`, [design note](../../docs/zturso/phase3-mvcc.md) |

**Honesty note:** Phases 1, 2, 4 are working code you can run. Phase 3 (true
MVCC) is **not implemented** — it requires versioned rows and a transaction
manager inside the storage engine. The `zturso-mvcc` demo shows exactly what the
ported engine does today (concurrent readers + snapshot isolation) and where MVCC
would begin (lifting the single-writer limit); the plan is in
[docs/zturso/phase3-mvcc.md](../../docs/zturso/phase3-mvcc.md).

## What each file is

- **`poc_frontend.c`** — Phase 1a. Drives `sqlite3GetVdbe` + `sqlite3VdbeAddOp*`
  + `sqlite3FinishCoding` to hand-build `OP_Integer/OP_ResultRow/OP_Halt`, then
  `sqlite3_step`. Proves the VDBE is a pluggable IR.
- **`frontend.c`** — Phases 1b/1c. A self-contained tokenizer + recursive-descent
  parser + AST + code generator for a small SQL dialect
  (`SELECT expr… [FROM t [WHERE cond…]]`), emitting real arithmetic and cursor
  opcodes. Includes a differential self-check against the fidelity engine.
- **`trace_vfs.c`** — Phase 2. A `sqlite3_vfs` wrapping the default VFS, counting
  every read/write/sync; demonstrates the I/O backend is swappable.
- **`vector.c`** — Phase 4. Registers vector-distance functions and runs kNN as
  plain SQL over the ported VDBE.
- **`mvcc_demo.c`** — Phase 3. Concurrency baseline demonstrator (design only).

## The thesis, checked

Turso claims the VDBE is a pluggable IR that new frontends (and now a Postgres
frontend) can target. Phase 1 **demonstrates that claim in this codebase**: a
non-SQLite frontend compiles SQL to VDBE bytecode and the ported Zig interpreter
runs it, returning results **byte-identical to SQLite** for the supported subset.
Phases 2 and 4 show the VFS and function seams are equally open. Phase 3 shows the
one place the thesis stops being cheap: concurrent writers need real storage-layer
MVCC — which is the fork's next (large) undertaking.
