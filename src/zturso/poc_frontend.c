/*
** sqlite-zturso — Phase 1 proof-of-concept
** ==========================================
** A "frontend" that emits VDBE bytecode BY HAND and runs it on the ported Zig
** VDBE interpreter — no tokenizer, no parser, no SQL text.
**
** This exists to test Turso's central "LLVM of databases" thesis directly in
** this codebase: that the VDBE is a genuinely *pluggable IR*. sqlite3_prepare_v2
** normally does three things — (1) tokenize+parse SQL, (2) run the code
** generators to emit VDBE ops, (3) finalize into a runnable statement. Here we
** *replace step 1+2 entirely*: we drive sqlite3GetVdbe + sqlite3VdbeAddOp* +
** sqlite3FinishCoding ourselves, then step the result on the ported engine.
**
** If this returns 42, the ported Zig VDBE is confirmed to be a pluggable
** backend that a non-SQLite frontend can target. See EXPERIMENT.md.
**
** NOTE: this is a fork-only file (branch `sqlite-zturso`). It reaches into
** SQLite's *internal* API via sqliteInt.h — deliberately, since a frontend is
** exactly the layer that lives below the public sqlite3.h. All the internal
** symbols it calls are exported by the ported Zig modules (vdbeaux.zig,
** select.zig, build.zig, vdbe.zig, ...), so it links against our libsqlite3.a.
*/
#include "sqliteInt.h"
#include <stdio.h>
#include <string.h>

/*
** Emit and run the hand-built program:
**
**     OP_Init      0 1 0     ; (auto-emitted by sqlite3VdbeCreate)
**     OP_Integer  42 1 0     ; r[1] = 42
**     OP_ResultRow 1 1 0     ; yield 1 column starting at r[1]
**     OP_Halt      0 0 0     ; (appended by sqlite3FinishCoding)
**
** This is the bytecode `SELECT 42;` compiles to, but produced without ever
** seeing that SQL text. Returns SQLITE_OK and writes the yielded value to *pOut.
*/
static int zturso_emit_and_run(sqlite3 *db, int *pOut){
  Parse sParse;
  Vdbe *v;
  sqlite3_stmt *stmt;
  int rc;

  /* A frontend needs a Parse context; zero it and point it at the db. The code
  ** generators read only a handful of fields (db, pVdbe, nMem, nTab, nVar). */
  memset(&sParse, 0, sizeof(sParse));
  sParse.db = db;

  /* prepare_v2 holds the connection mutex across code generation; do the same. */
  sqlite3_mutex_enter(sqlite3_db_mutex(db));

  v = sqlite3GetVdbe(&sParse);            /* allocate Vdbe; auto-emits OP_Init */
  if( v==0 ){
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return SQLITE_NOMEM;
  }

  /* Declare one result column so OP_ResultRow's `assert(nResColumn==p2)` holds
  ** and sqlite3_column_*() will surface the value. */
  sqlite3VdbeSetNumCols(v, 1);

  /* ---- the "frontend" output: three opcodes ---- */
  sqlite3VdbeAddOp2(v, OP_Integer, 42, 1);   /* r[1] = 42                     */
  sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);  /* return 1 col beginning at r[1] */
  sParse.nMem = 1;                           /* we used register 1            */

  /* Finalize: appends OP_Halt, patches the OP_Init jump, calls
  ** sqlite3VdbeMakeReady — the statement is now runnable. */
  sqlite3FinishCoding(&sParse);
  rc = sParse.rc;                            /* SQLITE_DONE on success         */
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  if( rc!=SQLITE_OK && rc!=SQLITE_DONE ) return rc;

  /* sqlite3_stmt IS a Vdbe* — step it on the ported interpreter. */
  stmt = (sqlite3_stmt*)v;
  rc = sqlite3_step(stmt);
  if( rc==SQLITE_ROW ){
    *pOut = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);
  return rc==SQLITE_ROW ? SQLITE_OK : rc;
}

int main(void){
  sqlite3 *db;
  int out = -1, rc;

  if( sqlite3_open(":memory:", &db)!=SQLITE_OK ){
    fprintf(stderr, "zturso: sqlite3_open failed\n");
    return 1;
  }

  rc = zturso_emit_and_run(db, &out);
  if( rc!=SQLITE_OK ){
    fprintf(stderr, "zturso: emit/run failed rc=%d (%s)\n", rc, sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }

  printf("zturso Phase 1: hand-emitted VDBE program (no parser) returned %d\n", out);
  printf("thesis check: ported Zig VDBE is a pluggable IR -> %s\n",
         out==42 ? "CONFIRMED" : "FAILED");
  sqlite3_close(db);
  return out==42 ? 0 : 2;
}
