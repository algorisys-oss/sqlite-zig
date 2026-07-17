# EXPERIMENT.md — the `sqlite-zturso` fork

> **This file exists only on the `sqlite-zturso` branch.** It does not belong on
> `main` or `dev`. If you are reading it on any other branch, that is a mistake.

## Charter

`sqlite-zturso` is an **independent experimental fork** of sqlite-zig that
deliberately **abandons the fidelity contract**. Where the mainline promises "it
*is* SQLite 3.54.0, byte-for-byte," this branch asks the opposite question:

> The sqlite-zig port already has a complete Zig VDBE (all 192 opcodes) and
> engine. What can we build *on top of it* that upstream SQLite cannot do —
> pluggable SQL frontends, async I/O, MVCC concurrent writers — the way Turso
> does on its own engine?

This is inspired by Turso's "LLVM of databases" thesis
(`/home/rajesh/opensource/sqlite-ports/turso`, and its 2026-07 Postgres-in-Rust
announcement — see [docs/turso-comparison.md](docs/turso-comparison.md)). The
difference: Turso rewrote the engine in Rust; we reuse the **already-ported Zig
VDBE** and grow outward from it.

## Governance (non-negotiable)

1. **`main` is always at parity with upstream SQLite C.** `dev` is the fidelity
   working branch. Neither ever takes code from here.
2. **`sqlite-zturso` never merges back.** No PR from this branch targets
   `main`/`dev`. It may one day be **extracted into its own repository**; until
   then it lives here as an isolated branch.
3. **The fidelity build must still compile clean.** Every experimental feature
   lands behind a build flag (`-Dzturso=...`) or in isolated `src/zturso/`
   files, so `zig build` / `zig build test` on the mainline is untouched. You can
   check out this branch and still produce a byte-identical libsqlite3.
4. **Divergence is the point.** Byte-identity and the C test suite are *not* the
   spec here. Each experiment defines its own success gate (below).

## Phased roadmap (risk-ascending, dependency-respecting)

| Phase | Experiment | Blast radius | Success gate |
|---|---|---|---|
| **1** | **Pluggable SQL frontend** over the ported VDBE | isolated: parse → codegen only (`src/zturso/`), zero storage change | a non-SQLite statement compiles to VDBE bytecode and returns correct rows; `EXPLAIN` shows a valid opcode stream |
| **2** | **Async VFS (`io_uring`)** behind the `sqlite3_vfs` seam | isolated: OS boundary | a query runs through the async VFS with identical results (⚠ Zig 0.17-dev async is unsettled — may need a manual submit/complete loop) |
| **3** | **MVCC / `BEGIN CONCURRENT`** | cross-cutting: pager + btree | two connections write concurrently without blocking; snapshot isolation holds |
| **4+** | CDC → DBSP incremental views → vector search | rides on 1–3 | each has its own demo gate |

Do them **in order**. Cheapest / most-isolated / highest-signal first; the
invasive storage rework (MVCC) last, with the earlier phases' lessons in hand.

## Current status

- **Phase 1: in progress.** Branch created off `dev@b5c8ae0` (full ported tree).
  Building a `zig build zturso` demo target that hand-emits a VDBE program via the
  ported `sqlite3VdbeAddOp*` API and runs it on the ported interpreter — proving
  the VDBE is a genuinely pluggable IR before we grow a real parser.

## Why bother

If Phase 1 works, Turso's central "pluggable IR" claim is demonstrated in *our*
codebase, cheaply, and Phases 2–3 become sensible follow-ons. If it doesn't, we
learn the thesis is shakier than the marketing — also cheaply. Either outcome is
a win the fidelity mainline can't give us.
