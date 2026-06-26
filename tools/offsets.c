/*
** Ground-truth struct layout extractor for the C->Zig migration.
**
** Compiled (by tools/gen_layout.sh) under both the production library config
** and the --dev testfixture config; its stdout drives src/c_layout.zig, whose
** numbers the Zig struct mirrors assert against at comptime. This guarantees a
** ported module's view of an internal struct matches the C the build links
** against — a wrong mirror fails to compile rather than silently corrupting.
**
** Add a P()/SZ() line here whenever a new port needs another field/struct, then
** re-run tools/gen_layout.sh.
*/
#include "sqliteInt.h"
#include "vdbeInt.h"
#include "vdbe.h"
#include <stdio.h>
#include <stddef.h>

#define P(STRUCT, FIELD) printf("%s_%s %zu\n", #STRUCT, #FIELD, offsetof(struct STRUCT, FIELD))
#define SZ(TAG, STRUCT)  printf("sizeof_%s %zu\n", #TAG, sizeof(struct STRUCT))

int main(void) {
    /* Mem (== struct sqlite3_value) — needed by utf.c (stack-allocates one). */
    SZ(Mem, sqlite3_value);
    P(sqlite3_value, z);
    P(sqlite3_value, n);
    P(sqlite3_value, flags);
    P(sqlite3_value, enc);
    P(sqlite3_value, eSubtype);
    P(sqlite3_value, db);
    P(sqlite3_value, szMalloc);
    P(sqlite3_value, uTemp);
    P(sqlite3_value, zMalloc);
    P(sqlite3_value, xDel);

    /* sqlite3 connection — utf.c reads db->mallocFailed; table.c writes db->errCode;
    ** vdbetrace.c reads db->enc/nVdbeExec/aLimit. */
    SZ(sqlite3, sqlite3);
    P(sqlite3, mallocFailed);
    P(sqlite3, errCode);
    P(sqlite3, enc);
    P(sqlite3, nVdbeExec);
    P(sqlite3, aLimit);
    P(sqlite3, mutex); /* legacy.c (sqlite3_exec) */
    P(sqlite3, flags);
    P(sqlite3, errMask);
    P(sqlite3, errByteOffset); /* printf.c — error-offset helpers */
    P(sqlite3, pParse);
    P(Parse, zTail);
    /* callback.c — collation/function registry on the connection. */
    P(sqlite3, pDfltColl);
    P(sqlite3, mDbFlags);
    P(sqlite3, xCollNeeded);
    P(sqlite3, xCollNeeded16);
    P(sqlite3, pCollNeededArg);
    P(sqlite3, aFunc);
    P(sqlite3, aCollSeq);
    /* db->init.busy — nested sqlite3InitInfo; synthesized composite offset. */
    printf("sqlite3_initBusy %zu\n",
           offsetof(struct sqlite3, init) + offsetof(struct sqlite3InitInfo, busy));
    P(Parse, db); /* callback.c reads pParse->db/rc */
    P(Parse, rc);
    /* vdbevtab.c — bytecode() vtab walks Vdbe ops + schema hashes. */
    P(sqlite3, aDb);
    SZ(VdbeOp, VdbeOp);
    P(VdbeOp, opcode);
    P(VdbeOp, p1);
    P(VdbeOp, p2);
    P(VdbeOp, p3);
    P(VdbeOp, p4);
    P(VdbeOp, p5);
    SZ(Db, Db);
    P(Db, zDbSName);
    P(Db, pSchema);
    P(Schema, tblHash);
    P(Schema, idxHash);
    P(Hash, first);
    P(HashElem, next);
    P(HashElem, data);
    P(Table, zName);
    P(Table, tnum);
    P(Table, eTabType);
    P(Index, zName);
    P(Index, tnum);
    /* util.c — error/progress/identity fields on the connection + Parse/Column. */
    P(sqlite3, pErr);
    P(sqlite3, eOpenState);
    P(sqlite3, iSysErrno);
    P(sqlite3, pVfs);
    P(sqlite3, suppressErr);
    P(sqlite3, u1);
    P(sqlite3, xProgress);
    P(sqlite3, pProgressArg);
    P(sqlite3, nProgressOps);
    P(Parse, nErr);
    P(Parse, zErrMsg);
    P(Parse, pWith);
    P(Parse, pToplevel);
    P(Parse, nProgressSteps);
    P(Column, zCnName);
    P(Column, colFlags);
    P(Sqlite3Config, xTestCallback);
    /* loadext.c — extension registry on the connection. */
    P(sqlite3, nExtension);
    P(sqlite3, aExtension);

    /* Vdbe — vdbetrace.c reads db/nVar/aVar/pVList. */
    P(Vdbe, db);
    P(Vdbe, nVar);
    P(Vdbe, aVar);
    P(Vdbe, pVList);

    /* Sqlite3Config — os.c reads iPrngSeed; mem5.c reads nHeap/pHeap/mnReq/bMemstat. */
    SZ(Sqlite3Config, Sqlite3Config);
    P(Sqlite3Config, iPrngSeed);
    P(Sqlite3Config, nHeap);
    P(Sqlite3Config, pHeap);
    P(Sqlite3Config, mnReq);
    P(Sqlite3Config, bMemstat);
    P(Sqlite3Config, mutex); /* mutex.c dispatches through this embedded methods sub-struct */
    P(Sqlite3Config, bCoreMutex);
    P(Sqlite3Config, pcache2); /* pcache.c dispatches through this embedded methods sub-struct */
    P(Sqlite3Config, pPage); /* pcache1.c — SQLITE_CONFIG_PAGECACHE buffer */
    P(Sqlite3Config, nPage);
    P(Sqlite3Config, xLog); /* printf.c — sqlite3_log */
    P(Sqlite3Config, pLogArg);

    /* PgHdr — pcache.c; ABI-shared (defined in pcache.h, the pager reads it). */
    SZ(PgHdr, PgHdr);
    P(PgHdr, pPage);
    P(PgHdr, pData);
    P(PgHdr, pExtra);
    P(PgHdr, pCache);
    P(PgHdr, pDirty);
    P(PgHdr, pPager);
    P(PgHdr, pgno);
    P(PgHdr, flags);
    P(PgHdr, nRef);
    P(PgHdr, pDirtyNext);
    P(PgHdr, pDirtyPrev);
    /* NOTE: struct PCache is opaque (defined only in pcache.c, not a header), so
    ** its layout is owned by src/pcache.zig and not extracted here. */
    return 0;
}
