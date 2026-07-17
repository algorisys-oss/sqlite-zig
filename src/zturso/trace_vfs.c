/*
** sqlite-zturso — Phase 2: a pluggable VFS over the ported engine
** ===============================================================
** Turso's async-I/O bet (io_uring) rests on one fact: SQLite's OS access all
** funnels through the `sqlite3_vfs` abstraction, so an alternate I/O backend can
** be slotted in without touching the engine. This demonstrates that seam is open
** in *our* ported build: a "trace VFS" that wraps the default VFS, counts every
** xOpen/xRead/xWrite/xSync, and runs a real CRUD workload through it.
**
** A production async VFS (io_uring) is exactly this shape — implement the same
** sqlite3_io_methods, but submit reads/writes to an io_uring SQE ring and reap
** completions instead of doing blocking pread/pwrite. This file proves the
** plug-in point works end-to-end; the async submission loop is the remaining
** (large) engineering, tracked in EXPERIMENT.md as Phase 2's real payload.
**
** Uses ONLY the public sqlite3.h VFS API — no internal headers. Linked against
** our libsqlite3.a, so the I/O it counts is the ported engine's actual I/O.
*/
#include "sqlite3.h"
#include <stdio.h>
#include <string.h>

/* ── counters ── */
static struct { long opens, reads, writes, syncs, rbytes, wbytes; } g;

/* Our file wraps the real file: the real sqlite3_file lives right after us. */
typedef struct TraceFile {
  const sqlite3_io_methods *pMethods;   /* our methods (must be first) */
  sqlite3_file *pReal;                   /* the underlying VFS file */
} TraceFile;

/* The VFS wraps the underlying (default) VFS. */
typedef struct TraceVfs {
  sqlite3_vfs base;         /* our vfs (base.pAppData holds the real vfs) */
} TraceVfs;

#define REAL_VFS(pVfs) ((sqlite3_vfs*)((pVfs)->pAppData))
#define REAL(p)        (((TraceFile*)(p))->pReal)

/* ── io_methods: each delegates to the real file, counting the interesting ops ── */
static int tvClose(sqlite3_file *p){
  sqlite3_file *r = REAL(p);
  int rc = r->pMethods->xClose(r);
  ((TraceFile*)p)->pMethods = 0;
  return rc;
}
static int tvRead(sqlite3_file *p, void *buf, int n, sqlite3_int64 ofst){
  g.reads++; g.rbytes += n;
  return REAL(p)->pMethods->xRead(REAL(p), buf, n, ofst);
}
static int tvWrite(sqlite3_file *p, const void *buf, int n, sqlite3_int64 ofst){
  g.writes++; g.wbytes += n;
  return REAL(p)->pMethods->xWrite(REAL(p), buf, n, ofst);
}
static int tvSync(sqlite3_file *p, int flags){
  g.syncs++;
  return REAL(p)->pMethods->xSync(REAL(p), flags);
}
static int tvTruncate(sqlite3_file *p, sqlite3_int64 sz){ return REAL(p)->pMethods->xTruncate(REAL(p), sz); }
static int tvFileSize(sqlite3_file *p, sqlite3_int64 *pSz){ return REAL(p)->pMethods->xFileSize(REAL(p), pSz); }
static int tvLock(sqlite3_file *p, int e){ return REAL(p)->pMethods->xLock(REAL(p), e); }
static int tvUnlock(sqlite3_file *p, int e){ return REAL(p)->pMethods->xUnlock(REAL(p), e); }
static int tvCheckLock(sqlite3_file *p, int *pRes){ return REAL(p)->pMethods->xCheckReservedLock(REAL(p), pRes); }
static int tvFileControl(sqlite3_file *p, int op, void *pArg){ return REAL(p)->pMethods->xFileControl(REAL(p), op, pArg); }
static int tvSectorSize(sqlite3_file *p){ return REAL(p)->pMethods->xSectorSize(REAL(p)); }
static int tvDeviceChar(sqlite3_file *p){ return REAL(p)->pMethods->xDeviceCharacteristics(REAL(p)); }

static const sqlite3_io_methods trace_io_methods = {
  1,                 /* iVersion 1: engine won't call shm/fetch — rollback journal path */
  tvClose, tvRead, tvWrite, tvTruncate, tvSync, tvFileSize,
  tvLock, tvUnlock, tvCheckLock, tvFileControl, tvSectorSize, tvDeviceChar,
};

/* ── vfs methods ── */
static int tvOpen(sqlite3_vfs *pVfs, sqlite3_filename zName, sqlite3_file *pFile, int flags, int *pOut){
  TraceFile *tf = (TraceFile*)pFile;
  sqlite3_vfs *pReal = REAL_VFS(pVfs);
  /* the real file sits in the bytes right after our TraceFile header */
  tf->pReal = (sqlite3_file*)&tf[1];
  int rc = pReal->xOpen(pReal, zName, tf->pReal, flags, pOut);
  if( rc==SQLITE_OK && tf->pReal->pMethods ){
    tf->pMethods = &trace_io_methods;   /* only wrap files the real VFS opened */
    g.opens++;
  }else{
    tf->pMethods = 0;
  }
  return rc;
}
/* everything else delegates straight through to the real VFS */
static int tvDelete(sqlite3_vfs *p, const char *z, int s){ return REAL_VFS(p)->xDelete(REAL_VFS(p), z, s); }
static int tvAccess(sqlite3_vfs *p, const char *z, int f, int *r){ return REAL_VFS(p)->xAccess(REAL_VFS(p), z, f, r); }
static int tvFullPath(sqlite3_vfs *p, const char *z, int n, char *o){ return REAL_VFS(p)->xFullPathname(REAL_VFS(p), z, n, o); }
static int tvRandom(sqlite3_vfs *p, int n, char *o){ return REAL_VFS(p)->xRandomness(REAL_VFS(p), n, o); }
static int tvSleep(sqlite3_vfs *p, int m){ return REAL_VFS(p)->xSleep(REAL_VFS(p), m); }
static int tvCurTime(sqlite3_vfs *p, double *o){ return REAL_VFS(p)->xCurrentTime(REAL_VFS(p), o); }
static int tvGetLastErr(sqlite3_vfs *p, int n, char *o){ return REAL_VFS(p)->xGetLastError(REAL_VFS(p), n, o); }

static TraceVfs trace_vfs;

static int registerTraceVfs(void){
  sqlite3_vfs *pReal = sqlite3_vfs_find(0);   /* the current default VFS */
  if( pReal==0 ) return SQLITE_ERROR;
  memset(&trace_vfs, 0, sizeof(trace_vfs));
  trace_vfs.base.iVersion   = 1;
  trace_vfs.base.szOsFile   = (int)sizeof(TraceFile) + pReal->szOsFile;  /* room for both */
  trace_vfs.base.mxPathname = pReal->mxPathname;
  trace_vfs.base.zName      = "zturso_trace";
  trace_vfs.base.pAppData   = pReal;
  trace_vfs.base.xOpen = tvOpen;   trace_vfs.base.xDelete = tvDelete;
  trace_vfs.base.xAccess = tvAccess; trace_vfs.base.xFullPathname = tvFullPath;
  trace_vfs.base.xRandomness = tvRandom; trace_vfs.base.xSleep = tvSleep;
  trace_vfs.base.xCurrentTime = tvCurTime; trace_vfs.base.xGetLastError = tvGetLastErr;
  return sqlite3_vfs_register(&trace_vfs.base, 0 /* not default */);
}

static int run(sqlite3 *db, const char *sql){
  char *e=0; int rc=sqlite3_exec(db, sql, 0,0,&e);
  if( rc!=SQLITE_OK ){ fprintf(stderr, "  SQL error: %s\n", e); sqlite3_free(e); }
  return rc;
}

int main(void){
  if( registerTraceVfs()!=SQLITE_OK ){ fprintf(stderr, "zturso: VFS register failed\n"); return 1; }

  /* Open a FILE-backed db (so real I/O flows) through our pluggable VFS. */
  const char *path = "zturso_vfs_demo.db";
  sqlite3_vfs *v = sqlite3_vfs_find("zturso_trace");
  remove(path);

  sqlite3 *db;
  int rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, "zturso_trace");
  if( rc!=SQLITE_OK ){ fprintf(stderr, "open failed: %s\n", sqlite3_errmsg(db)); return 1; }

  printf("sqlite-zturso Phase 2 — a pluggable VFS over the ported engine\n");
  printf("(all engine I/O routed through a custom sqlite3_vfs named \"%s\")\n\n", v?v->zName:"?");

  run(db, "PRAGMA journal_mode=DELETE;");         /* rollback journal (iVersion-1 path) */
  run(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT);");
  run(db, "BEGIN;");
  for(int i=1;i<=200;i++){ char sql[64]; snprintf(sql,sizeof sql,"INSERT INTO t(v) VALUES('row-%d');", i); run(db, sql); }
  run(db, "COMMIT;");

  sqlite3_stmt *st=0; long sum=0, cnt=0;
  sqlite3_prepare_v2(db, "SELECT id FROM t WHERE id%7=0;", -1, &st, 0);
  while( sqlite3_step(st)==SQLITE_ROW ){ sum += sqlite3_column_int(st,0); cnt++; }
  sqlite3_finalize(st);

  printf("workload: 200 inserts + a filtered scan (through the trace VFS)\n");
  printf("  query result: %ld rows, id-sum=%ld\n\n", cnt, sum);
  printf("VFS I/O observed by the pluggable layer:\n");
  printf("  file opens : %ld\n", g.opens);
  printf("  reads      : %-6ld (%ld bytes)\n", g.reads, g.rbytes);
  printf("  writes     : %-6ld (%ld bytes)\n", g.writes, g.wbytes);
  printf("  syncs      : %ld\n", g.syncs);

  int ok = (g.opens>0 && g.writes>0 && g.reads>0 && cnt==28 /* 7,14..196 => 28 rows */);
  printf("\nthesis check: an alternate I/O backend plugs into the ported engine -> %s\n",
         ok ? "CONFIRMED" : "FAILED");
  printf("(io_uring would implement these same io_methods with async submit/reap)\n");

  sqlite3_close(db);
  remove(path);
  return ok ? 0 : 2;
}
