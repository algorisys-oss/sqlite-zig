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
#include "btreeInt.h"
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
    /* vtab.c — virtual-table object management. (Parse.disableTriggers is a
    ** :1 bitfield → not offsetof-able; src/vtab.zig gates its byte on config.) */
    P(sqlite3, aModule);
    P(sqlite3, pVtabCtx);
    P(sqlite3, aVTrans);
    P(sqlite3, nVTrans);
    P(sqlite3, pDisconnect);
    P(sqlite3, nSchemaLock);
    P(sqlite3, vtabOnConflict);
    P(sqlite3, nStatement);
    P(sqlite3, nSavepoint);
    P(sqlite3, pnBytesFreed);
    P(Parse, pNewTable);
    P(Parse, apVtabLock);
    SZ(Parse, Parse);
    SZ(Table, Table);
    /* prepare.c — statement preparation + schema init. (Parse.checkSchema is a
    ** :1 bitfield → not offsetof-able; src/prepare.zig gates its byte on config.) */
    P(sqlite3, pVdbe);
    P(sqlite3, nDb);
    P(sqlite3, noSharedCache);
    P(sqlite3, busyHandler);
    P(sqlite3, xAuth);
    P(Parse, pVdbe);
    P(Parse, nQueryLoop);
    P(Parse, nested);
    P(Parse, disableLookaside);
    P(Parse, prepFlags);
    P(Parse, nTableLock);
    P(Parse, aTableLock);
    P(Parse, pTriggerPrg);
    P(Parse, pCleanup);
    P(Parse, aLabel);
    P(Parse, pConstExpr);
    P(Parse, pOuterParse);
    P(Parse, explain);
    P(Parse, pReprepare);
    P(Db, pBt);
    P(Index, pNext);
    P(Index, pTable);
    P(Table, pIndex);
    P(Schema, schemaFlags);
    P(TriggerPrg, pNext); /* prepare.c walks the TriggerPrg cleanup list */
    /* auth.c — authorization callback over schema objects. */
    P(sqlite3, pAuthArg);
    P(Parse, zAuthContext);
    P(Parse, eParseMode);
    P(Parse, pTriggerTab);
    P(Table, nCol);
    P(Table, iPKey);
    P(Table, aCol);
    SZ(Column, Column);
    P(Expr, op);
    P(Expr, iTable);
    P(Expr, iColumn);
    P(SrcList, nSrc);
    P(SrcList, a);
    P(SrcItem, iCursor);
    P(SrcItem, pSTab);
    SZ(SrcItem, SrcItem);
    /* vacuum.c — VACUUM (attach temp db, mirror+copy, swap meta). */
    P(sqlite3, autoCommit);
    P(sqlite3, nVdbeActive);
    P(sqlite3, openFlags);
    P(sqlite3, nChange);
    P(sqlite3, nTotalChange);
    P(sqlite3, mTrace);
    P(sqlite3, nextPagesize);
    P(sqlite3, nextAutovac);
    P(Db, safety_level);
    P(Parse, nMem);
    P(Schema, cache_size);
    /* attach.c — ATTACH/DETACH + the DbFixer AST walkers. SrcItem.fg is a struct
    ** of bitfields (its byte offset is taken; individual bits via masks in-code). */
    P(sqlite3, aDbStatic);
    P(sqlite3, dfltLockMode);
    P(sqlite3_vfs, zName);
    P(Schema, enc);
    P(Schema, file_format);
    P(Schema, trigHash);
    SZ(DbFixer, DbFixer);
    P(DbFixer, w);
    P(DbFixer, pSchema);
    P(DbFixer, bTemp);
    P(DbFixer, zDb);
    P(DbFixer, zType);
    P(DbFixer, pName);
    SZ(Walker, Walker);
    P(Walker, pParse);
    P(Walker, xExprCallback);
    P(Walker, xSelectCallback);
    P(Walker, xSelectCallback2);
    P(Walker, walkerDepth);
    P(Walker, eCode);
    P(Walker, u);
    P(SrcItem, fg);
    P(SrcItem, u3);
    P(SrcItem, u4);
    SZ(Select, Select);
    P(Select, pSrc);
    P(Select, pWith);
    SZ(NameContext, NameContext);
    P(With, nCte);
    P(With, a);
    SZ(Cte, Cte);
    P(Cte, pSelect);
    P(TriggerStep, pSelect);
    P(TriggerStep, pSrc);
    P(TriggerStep, pWhere);
    P(TriggerStep, pExprList);
    P(TriggerStep, pUpsert);
    P(TriggerStep, pNext);
    P(Trigger, pSchema);
    P(Trigger, pTabSchema);
    P(Upsert, pUpsertTarget);
    P(Upsert, pUpsertTargetWhere);
    P(Upsert, pUpsertSet);
    P(Upsert, pUpsertWhere);
    P(Upsert, pNextUpsert);
    /* backup.c — reaches into Btree/BtShared (btreeInt.h) leading fields. */
    P(Btree, db);
    P(Btree, pBt);
    P(Btree, nBackup);
    P(BtShared, inTransaction);
    P(BtShared, btsFlags);
    P(BtShared, pageSize);
    /* vdbeblob.c — incremental BLOB I/O reaches into Vdbe/VdbeCursor/Table/
    ** Schema/Index/FKey. The 4 VdbeCursor fields below DIVERGE prod vs --dev. */
    P(Vdbe, pc);
    P(Vdbe, rc);
    P(Vdbe, aMem);
    P(Vdbe, apCsr);
    P(VdbeCursor, eCurType);
    P(VdbeCursor, nField);
    P(VdbeCursor, nHdrParsed);
    P(VdbeCursor, uc);
    P(VdbeCursor, aType);
    P(VdbeOp, p4type);
    P(Parse, nVar);
    P(Parse, nTab);
    P(Table, u);
    P(Table, tabFlags);
    P(Table, pSchema);
    P(Schema, schema_cookie);
    P(Schema, iGeneration);
    P(Index, aiColumn);
    P(Index, nKeyCol);
    P(FKey, pNextFrom);
    P(FKey, nCol);
    P(FKey, aCol);
    SZ(FKeyCol, sColMap);
    P(sqlite3, xPreUpdateCallback);
    /* fkey.c — foreign-key codegen. (Index.idxType / SrcItem.fixedSchema are
    ** bitfields → not offsetof-able; src/fkey.zig gates those bytes itself.) */
    P(CollSeq, zName);
    P(Column, affinity);
    P(Expr, affExpr);
    P(Expr, flags);
    printf("Expr_yTab %zu\n", offsetof(struct Expr, y.pTab));
    P(FKey, pFrom);
    P(FKey, zTo);
    P(FKey, pNextTo);
    P(FKey, pPrevTo);
    P(FKey, isDeferred);
    P(FKey, aAction);
    P(FKey, apTrigger);
    printf("Table_u_tab_pFKey %zu\n", offsetof(struct Table, u.tab.pFKey));
    P(Table, nTabRef);
    P(Index, azColl);
    P(Index, onError);
    P(Index, pPartIdxWhere);
    P(NameContext, pParse);
    P(NameContext, pSrcList);
    P(Parse, isMultiWrite);
    P(Schema, fkeyHash);
    P(SrcItem, zName);
    P(Trigger, op);
    P(Trigger, pWhen);
    P(Trigger, step_list);
    SZ(Trigger, Trigger);
    P(TriggerStep, op);
    P(TriggerStep, pTrig);
    SZ(TriggerStep, TriggerStep);
    P(TriggerPrg, pTrigger);
    P(sColMap, iFrom);
    P(sColMap, zCol);
    SZ(sColMap, sColMap);
    /* trigger.c — trigger machinery + sub-program codegen. (Parse bitfields
    ** disableTriggers/bReturning/okConstFactor/checkSchema gated in-module.) */
    P(ExprList, a);
    P(ExprList, nExpr);
    P(ExprList_item, pExpr);
    P(ExprList_item, zEName);
    SZ(ExprList_item, ExprList_item);
    P(Expr, pLeft);
    P(Expr, pRight);
    P(Expr, u);
    P(Expr, x);
    P(NameContext, ncFlags);
    P(NameContext, uNC);
    P(Parse, eOrconf);
    P(Parse, eTriggerOp);
    P(Parse, newmask);
    P(Parse, nMaxArg);
    P(Parse, oldmask);
    P(Parse, pNewTrigger);
    P(Parse, u1);
    P(Returning, iRetCur);
    P(Returning, iRetReg);
    P(Returning, nRetCol);
    P(Returning, pReturnEL);
    P(Returning, retTrig);
    P(Select, pEList);
    P(Select, selFlags);
    P(SubProgram, aOp);
    P(SubProgram, nOp);
    P(SubProgram, nMem);
    P(SubProgram, nCsr);
    P(SubProgram, token);
    SZ(SubProgram, SubProgram);
    printf("SZ_SRCLIST_1 %zu\n", (size_t)SZ_SRCLIST_1);
    P(Table, pTrigger);
    P(Trigger, zName);
    P(Trigger, table);
    P(Trigger, tr_tm);
    P(Trigger, bReturning);
    P(Trigger, pColumns);
    P(Trigger, pNext);
    SZ(TriggerPrg, TriggerPrg);
    P(TriggerPrg, pProgram);
    P(TriggerPrg, orconf);
    P(TriggerPrg, aColmask);
    P(TriggerStep, orconf);
    P(TriggerStep, pIdList);
    P(TriggerStep, zSpan);
    /* walker.c — generic Expr/Select AST traversal. */
    P(Expr, y);
    P(Select, pWhere);
    P(Select, pGroupBy);
    P(Select, pHaving);
    P(Select, pOrderBy);
    P(Select, pPrior);
    P(Select, pLimit);
    P(Select, pWinDefn);
    P(SrcItem, u1);
    P(Subquery, pSelect);
    P(Window, pPartition);
    P(Window, pOrderBy);
    P(Window, pStart);
    P(Window, pEnd);
    P(Window, pNextWin);
    P(Window, pFilter);
    /* vdbeapi.c — public step/column/bind/result API. Vdbe trailing fields
    ** DIVERGE prod/tf (SQLITE_DEBUG inserts rcApp/nWrite/napArg); gen_layout
    ** emits per-config values. Vdbe.rcApp (debug-only) + the .bits bitfield byte
    ** are not offsetof-able here and stay config-gated in src/vdbeapi.zig. */
    P(Vdbe, pVNext);
    P(Vdbe, nMem);
    P(Vdbe, iCurrentTime);
    P(Vdbe, aOp);
    P(Vdbe, nOp);
    P(Vdbe, aColName);
    P(Vdbe, pResultRow);
    P(Vdbe, zErrMsg);
    P(Vdbe, startTime);
    P(Vdbe, nResColumn);
    P(Vdbe, nResAlloc);
    P(Vdbe, errorAction);
    P(Vdbe, minWriteFileFormat);
    P(Vdbe, prepFlags);
    P(Vdbe, eVdbeState);
    P(Vdbe, aCounter);
    P(Vdbe, zSql);
    P(Vdbe, expmask);
    P(Vdbe, pFrame);
    P(Vdbe, nFrame);
    P(Vdbe, pAuxData);
    P(sqlite3_context, pOut);
    P(sqlite3_context, pFunc);
    P(sqlite3_context, pMem);
    P(sqlite3_context, pVdbe);
    P(sqlite3_context, iOp);
    P(sqlite3_context, isError);
    P(sqlite3_context, enc);
    SZ(AuxData, AuxData);
    P(AuxData, iAuxOp);
    P(AuxData, iAuxArg);
    P(AuxData, pAux);
    P(AuxData, xDeleteAux);
    P(AuxData, pNextAux);
    P(FuncDef, funcFlags);
    P(FuncDef, pUserData);
    P(FuncDef, zName);
    P(KeyInfo, nKeyField);
    P(UnpackedRecord, aMem);
    P(UnpackedRecord, nField);
    P(Column, iDflt);
    P(sqlite3, init);
    P(sqlite3, lookaside);
    printf("sqlite3_lookaside_pStart %zu\n", offsetof(struct sqlite3, lookaside) + offsetof(struct Lookaside, pStart));
    printf("sqlite3_lookaside_pEnd %zu\n", offsetof(struct sqlite3, lookaside) + offsetof(struct Lookaside, pEnd));
    printf("sqlite3_lookaside_pTrueEnd %zu\n", offsetof(struct sqlite3, lookaside) + offsetof(struct Lookaside, pTrueEnd));
    P(sqlite3, nVdbeRead);
    P(sqlite3, nVdbeWrite);
    P(sqlite3, trace);
    P(sqlite3, pTraceArg);
    P(sqlite3, xProfile);
    P(sqlite3, pProfileArg);
    P(sqlite3, pPreUpdate);
    P(sqlite3, xWalCallback);
    P(sqlite3, pWalArg);
    P(sqlite3, nDeferredCons);
    P(sqlite3, nDeferredImmCons);
    printf("Table_u_tab_pDfltList %zu\n", offsetof(struct Table, u.tab.pDfltList));
    /* sqlite3.init sub-struct (sqlite3InitInfo) — nested composite offsets. */
    printf("sqlite3_init_newTnum %zu\n", offsetof(struct sqlite3, init) + offsetof(struct sqlite3InitInfo, newTnum));
    printf("sqlite3_init_iDb %zu\n",     offsetof(struct sqlite3, init) + offsetof(struct sqlite3InitInfo, iDb));
    printf("sqlite3_init_azInit %zu\n",  offsetof(struct sqlite3, init) + offsetof(struct sqlite3InitInfo, azInit));
    /* orphanTrigger is the :1 bitfield in the byte right after `busy`. */
    printf("sqlite3_init_bitbyte %zu\n", offsetof(struct sqlite3, init) + offsetof(struct sqlite3InitInfo, busy) + 1);
    /* sqlite3.lookaside sub-struct (Lookaside) — nested composite offsets. */
    printf("sqlite3_lookaside_bDisable %zu\n", offsetof(struct sqlite3, lookaside) + offsetof(struct Lookaside, bDisable));
    printf("sqlite3_lookaside_sz %zu\n",       offsetof(struct sqlite3, lookaside) + offsetof(struct Lookaside, sz));
    printf("sqlite3_lookaside_szTrue %zu\n",   offsetof(struct sqlite3, lookaside) + offsetof(struct Lookaside, szTrue));
    /* Parse recursive-region sizes (macros in sqliteInt.h, offsetof-derived). */
    printf("PARSE_HDR_SZ %d\n", (int)PARSE_HDR_SZ);
    printf("PARSE_RECURSE_SZ %d\n", (int)PARSE_RECURSE_SZ);

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
    P(Sqlite3Config, nStmtSpill); /* pager.c — statement-journal spill threshold */

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
