# Migration workflow — how modules get ported

The agent-driven process that actually moves this port forward, one C
translation unit at a time. Read alongside [testing.md](testing.md) (the
validation gates), [architecture.md](architecture.md) (the C→Zig swap
mechanism), [../CLAUDE.md](../CLAUDE.md) (conventions) and
[../PROGRESS.md](../PROGRESS.md) (status / resume point).

The guiding rule (from [../CLAUDE.md](../CLAUDE.md)): **SQLite's own test suite
is the spec.** Everything below exists to keep that gate honest while porting at
scale.

## The role split

Porting is parallelized with sub-agents, but with a strict division of labor —
this is what keeps a large autonomous run from drifting into a broken database.

- **The orchestrator (main session)** owns shared state and the test gate. It
  picks the next module bottom-up along the dependency graph, spawns one drafting
  agent, then *independently* verifies and commits. It never writes the module's
  Zig itself.
- **One drafting sub-agent per module** does the read-C / write-Zig work in a
  fresh context (each produces a new `src/<name>.zig`).

Shared files — [../build.zig](../build.zig) (`ported_modules`),
[../tools/tcltest.sh](../tools/tcltest.sh) (`MODULES`),
[../tools/offsets.c](../tools/offsets.c) → `src/c_layout.zig` — are touched
**only by the orchestrator**, and only one drafting agent runs in the main tree
at a time. Parallel edits to those files corrupt each other.

The design principle: **drafting is parallel and disposable** (a bad draft is
just redone), but **verification is serial, owned by one actor, and gated on the
original project's own tests.** The model is allowed to be wrong; the gate is not
allowed to be skipped.

## The per-module loop

1. **Pick** the next module per [../plan.md](../plan.md) (bottom-up: utils → OS →
   storage → VDBE → SQL front-end), so each Zig layer rests on already-ported Zig.
2. **Draft** it with the sub-agent prompt below.
3. **Wire it in:** add `"<name>.c"` to `ported_modules` in build.zig, add the stem
   to `MODULES` in tcltest.sh, add any new struct offsets to offsets.c and run
   `tools/gen_layout.sh`.
4. **Validate** — must all be green (see [testing.md](testing.md)):
   - `zig build && zig build test`
   - `tools/tcltest.sh --zig <relevant upstream TCL tests>` → **0 errors**
   - EXPLAIN / smoke-diff vs the pure-C amalgamation (`zig build -Damalgamation=true`)
     for anything behavioral.
5. **Commit** — only when green. Update [../PROGRESS.md](../PROGRESS.md) and
   [../plan.md](../plan.md); log tokens.

**Never commit anything that isn't green.** The last committed state must always
build. That single rule — the test suite, not the model's confidence, decides
"done" — is what makes a long autonomous run safe.

## The drafting-agent prompt template

Each module gets a fresh sub-agent with a self-contained prompt. The shape that
works:

```
Port vendor/tsrc/<module>.c to src/<module>.zig.

DO THE WORK YOURSELF — do not delegate or spawn further agents.

Contract:
- Export the SAME C-ABI symbols the C file exports (match signatures
  from sqliteInt.h). Every still-C caller must link unchanged.
- Match idiomatic Zig (error unions, slices, comptime for macros)
  EXCEPT at ABI boundaries, which stay byte-compatible.

Wire it in:
- add "<module>.c" to ported_modules in build.zig
- add <module> to MODULES in tools/tcltest.sh
- add any new struct offsets to tools/offsets.c, run tools/gen_layout.sh

Validate (this is the bar, not optional):
- zig build && zig build test  → green
- tools/tcltest.sh --zig <relevant upstream TCL tests>  → 0 errors
- EXPLAIN/smoke-diff vs the pure-C amalgamation
  (zig build -Damalgamation=true) for anything behavioral

GOTCHA CHECKLIST — verify each before claiming done:
- inline-array-vs-pointer: ExprList.a / IdList.a / SrcList.a /
  KeyInfo.aColl are INLINE (take the address);
  KeyInfo.aSortFlags IS a pointer
- read i16/u16/u8 at their REAL width, never as c_int
- (u16)/(i16) C casts = @truncate, NOT @intCast
- @memcpy → @memmove wherever source/dest can overlap
- SQLITE_DEBUG/TEST-only symbols gated on config flags via comptime @export
- re-probe every OP_* / TK_* / flag constant vs ground truth
  (constant swaps have bitten EVERY port)
- MEMCELLSIZE = offsetof(Mem,db) = 24
```

## The gotcha checklist is the asset

That checklist is the single most valuable part of the prompt. It is **every bug
class that has burned a previous module**, fed forward so the next agent checks
for it up front instead of rediscovering it in gdb. It grows over time: when a
new failure mode surfaces, it goes in the list.

Every entry is a real, debugged failure — see the [../PROGRESS.md](../PROGRESS.md)
"Known issues / fixed" log for the post-mortems. A few representative ones and
what they cost:

- **Return-register width.** A function returning `u8`/`i16` while callers
  `extern`-declared `int`/`c_int` leaves the upper return-register bytes
  undefined. A 2-byte varint read as length **258** → FTS5 "malformed inverted
  index"; a `-1` rowid read as **65535** → `NEW.rowid` in a trigger segfaulted.
- **`MEMCELLSIZE` = `offsetof(Mem,db)` = 24** (not 48). Too large and
  `OP_Variable`'s memcpy copies past the shallow-copy prefix into the
  malloc-ownership fields → a register and a bound parameter share a buffer →
  double-free.
- **Hardcoded constants drift.** `TF_Ephemeral` as `0x2` instead of `0x4000` →
  materialized CTEs opened as real tables → segfault. `OP_OpenWrite` numbered 113
  (actually `OP_ReopenIdx`) → an UPDATE data cursor opened as an index cursor.
- **Inline array vs pointer.** Dereferencing an inline `char[40]`/`ExprList.a` as
  a pointer (or vice-versa) → every `RETURNING` statement segfaulted.

The throughline: porting the *logic* is the easy part. Getting struct offsets,
bitfield positions, opcode constants, and return-register widths **byte-exact
against C ground truth** is the hard part — and the only thing that catches it is
the test gate. The comptime offset asserts generated by `tools/gen_layout.sh`
(see [architecture.md](architecture.md)) turn many of these into compile-time
failures instead of runtime corruption.
