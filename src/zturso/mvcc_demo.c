/*
** sqlite-zturso — Phase 3: concurrency baseline + what MVCC would add
** ==================================================================
** HONEST SCOPE: true MVCC / `BEGIN CONCURRENT` (multiple concurrent writers,
** versioned tuples, snapshot GC) is a multi-month rewrite of the pager and
** B-tree and is NOT implemented here. Faking it would be dishonest. Instead this
** program demonstrates, on the *real ported engine*, exactly where the current
** concurrency model ends and where MVCC would begin — the precise boundary the
** Phase 3 rewrite has to move. See docs/zturso/phase3-mvcc.md for the design.
**
** It shows two true facts using two live connections over one WAL database:
**   (A) WAL already gives concurrent READERS + snapshot isolation: a reader's
**       snapshot is stable across a concurrent writer's commit.
**   (B) The engine is SINGLE-WRITER: a second writer gets SQLITE_BUSY. Lifting
**       exactly this — concurrent writers that don't block — is what MVCC adds.
**
** Public API only; linked against our libsqlite3.a (so this is the ported
** engine's real locking behavior).
*/
#include "sqlite3.h"
#include <stdio.h>
#include <string.h>

static int scalar(sqlite3 *db, const char *sql){
  sqlite3_stmt *st=0; int v=-1;
  if( sqlite3_prepare_v2(db, sql, -1, &st, 0)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW )
    v=sqlite3_column_int(st,0);
  sqlite3_finalize(st);
  return v;
}
static int exec(sqlite3 *db, const char *sql){ return sqlite3_exec(db, sql, 0,0,0); }

int main(void){
  const char *path="zturso_mvcc_demo.db";
  remove(path);
  char wal[256], shm[256];
  snprintf(wal,sizeof wal,"%s-wal",path); snprintf(shm,sizeof shm,"%s-shm",path);

  sqlite3 *A=0, *B=0;
  if( sqlite3_open(path,&A)!=SQLITE_OK || sqlite3_open(path,&B)!=SQLITE_OK ){
    fprintf(stderr,"open failed\n"); return 1;
  }
  sqlite3_busy_timeout(A,0); sqlite3_busy_timeout(B,0);   /* fail fast, don't wait */

  exec(A,"PRAGMA journal_mode=WAL;");
  exec(A,"CREATE TABLE acct(id INTEGER PRIMARY KEY, bal INTEGER);");
  exec(A,"INSERT INTO acct(bal) VALUES(100),(200),(300);");

  printf("sqlite-zturso Phase 3 — concurrency baseline of the ported engine (WAL)\n\n");

  /* ---- (A) reader snapshot isolation across a concurrent commit ---- */
  printf("(A) reader snapshot stability while another connection commits:\n");
  exec(A,"BEGIN;");                            /* deferred read txn */
  int a_before = scalar(A,"SELECT count(*) FROM acct;");   /* takes A's snapshot */
  printf("    A begins read txn, sees %d rows\n", a_before);
  int rcB = exec(B,"INSERT INTO acct(bal) VALUES(400);");  /* B commits (autocommit) */
  printf("    B inserts a row concurrently -> %s\n", sqlite3_errstr(rcB));
  int a_during = scalar(A,"SELECT count(*) FROM acct;");   /* still A's snapshot */
  printf("    A re-reads inside its txn, still sees %d rows (snapshot isolation)\n", a_during);
  exec(A,"COMMIT;");
  int a_after = scalar(A,"SELECT count(*) FROM acct;");    /* now sees B's commit */
  printf("    A commits and re-reads, now sees %d rows\n", a_after);
  int okA = (a_before==3 && a_during==3 && a_after==4 && rcB==SQLITE_OK);
  printf("    => concurrent reader + writer, isolated snapshot: %s\n\n", okA?"OK":"FAIL");

  /* ---- (B) single-writer limit: the thing MVCC removes ---- */
  printf("(B) single-writer limit (what BEGIN CONCURRENT / MVCC would lift):\n");
  int rc1 = exec(A,"BEGIN IMMEDIATE;");        /* A takes the write lock */
  printf("    A: BEGIN IMMEDIATE -> %s\n", sqlite3_errstr(rc1));
  int rc2 = exec(B,"BEGIN IMMEDIATE;");        /* B wants to write too */
  printf("    B: BEGIN IMMEDIATE -> %s  (expected SQLITE_BUSY)\n", sqlite3_errstr(rc2));
  exec(A,"COMMIT;");
  int okB = (rc1==SQLITE_OK && rc2==SQLITE_BUSY);
  printf("    => second writer is serialized, not concurrent: %s\n", okB?"OK":"FAIL");

  printf("\nverdict:\n");
  printf("  ✔ ported engine already gives concurrent readers + snapshot isolation (WAL).\n");
  printf("  ✗ concurrent WRITERS are NOT supported — that is the Phase 3 MVCC target.\n");
  printf("    Implementing it means versioned rows + per-txn snapshots in btree/pager;\n");
  printf("    see docs/zturso/phase3-mvcc.md. This demo marks the exact boundary.\n");

  sqlite3_close(A); sqlite3_close(B);
  remove(path); remove(wal); remove(shm);
  return (okA && okB) ? 0 : 2;
}
