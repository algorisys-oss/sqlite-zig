//! Zig port of the fts5_vocab.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 27227-28050).
//!
//! The "fts5vocab" virtual table: direct read access to an existing FTS5 index,
//! in one of three shapes — 'col', 'row' or 'instance'. Mirrors the C
//! sqlite3_module (iVersion 2) field-for-field via int.sqlite3_module.
//!
//! Only sqlite3Fts5VocabInit is non-static in C; the vtab methods are private
//! and reached only through the module table, so they are plain Zig fns here.
//! Fts5VocabTable / Fts5VocabCursor are section-private structs (defined here).
//! Sibling/core helpers are called via `extern fn`.

const int = @import("fts5_int.zig");

const sqlite3 = int.sqlite3;
const sqlite3_stmt = int.sqlite3_stmt;
const sqlite3_value = int.sqlite3_value;
const sqlite3_context = int.sqlite3_context;
const sqlite3_vtab = int.sqlite3_vtab;
const sqlite3_vtab_cursor = int.sqlite3_vtab_cursor;
const sqlite3_index_info = int.sqlite3_index_info;
const sqlite3_module = int.sqlite3_module;
const Fts5Global = int.Fts5Global;
const Fts5Index = int.Fts5Index;
const Fts5Table = int.Fts5Table;
const Fts5IndexIter = int.Fts5IndexIter;
const Fts5Buffer = int.Fts5Buffer;

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_ERROR = int.SQLITE_ERROR;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_ROW = int.SQLITE_ROW;
const SQLITE_TRANSIENT = int.SQLITE_TRANSIENT;
const SQLITE_STATIC = int.SQLITE_STATIC;
const SQLITE_INDEX_CONSTRAINT_EQ = int.SQLITE_INDEX_CONSTRAINT_EQ;
const SQLITE_INDEX_CONSTRAINT_LE = int.SQLITE_INDEX_CONSTRAINT_LE;
const SQLITE_INDEX_CONSTRAINT_LT = int.SQLITE_INDEX_CONSTRAINT_LT;
const SQLITE_INDEX_CONSTRAINT_GE = int.SQLITE_INDEX_CONSTRAINT_GE;
const SQLITE_INDEX_CONSTRAINT_GT = int.SQLITE_INDEX_CONSTRAINT_GT;
const SQLITE_CORRUPT_VTAB = int.SQLITE_CORRUPT_VTAB;
const FTS5_DETAIL_NONE = int.FTS5_DETAIL_NONE;
const FTS5_DETAIL_FULL = int.FTS5_DETAIL_FULL;
const FTS5_DETAIL_COLUMNS = int.FTS5_DETAIL_COLUMNS;
const FTS5INDEX_QUERY_SCAN = int.FTS5INDEX_QUERY_SCAN;
const FTS5INDEX_QUERY_NOTOKENDATA = int.FTS5INDEX_QUERY_NOTOKENDATA;

// FTS5_CORRUPT: in --dev this is sqlite3Fts5Corrupt() which simply returns
// SQLITE_CORRUPT_VTAB (no side effects), so the value is config-invariant.
const FTS5_CORRUPT = SQLITE_CORRUPT_VTAB;

// fts5.c 27310-27325: vocab constants.
const FTS5_VOCAB_COL: c_int = 0;
const FTS5_VOCAB_ROW: c_int = 1;
const FTS5_VOCAB_INSTANCE: c_int = 2;

const FTS5_VOCAB_COL_SCHEMA = "term, col, doc, cnt";
const FTS5_VOCAB_ROW_SCHEMA = "term, doc, cnt";
const FTS5_VOCAB_INST_SCHEMA = "term, doc, col, offset";

const FTS5_VOCAB_TERM_EQ: c_int = 0x0100;
const FTS5_VOCAB_TERM_GE: c_int = 0x0200;
const FTS5_VOCAB_TERM_LE: c_int = 0x0400;
const FTS5_VOCAB_COLUSED_MASK: c_int = 0xFF;

// --- sibling sections + core sqlite3 API ------------------------------------
extern fn sqlite3Fts5Strndup(pRc: *c_int, pIn: [*]const u8, nIn: c_int) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5Dequote(z: [*:0]u8) callconv(.c) void;
extern fn sqlite3Fts5MallocZero(pRc: *c_int, nByte: i64) callconv(.c) ?*anyopaque;
extern fn sqlite3Fts5Mprintf(pRc: *c_int, zFmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5BufferFree(pBuf: *Fts5Buffer) callconv(.c) void;
extern fn sqlite3Fts5BufferSet(pRc: *c_int, pBuf: *Fts5Buffer, nData: c_int, pData: [*]const u8) callconv(.c) void;
extern fn sqlite3Fts5PoslistNext64(a: ?[*]const u8, n: c_int, pi: *c_int, piOff: *i64) callconv(.c) c_int;
extern fn sqlite3Fts5GetVarint32(p: [*]const u8, v: *u32) callconv(.c) c_int;

extern fn sqlite3Fts5TableFromCsrid(pGlobal: ?*Fts5Global, iCsrId: i64) callconv(.c) ?*Fts5Table;
extern fn sqlite3Fts5FlushToDisk(pTab: *Fts5Table) callconv(.c) c_int;
extern fn sqlite3Fts5IndexQuery(p: ?*Fts5Index, pToken: ?[*]const u8, nToken: c_int, flags: c_int, pColset: ?*anyopaque, ppIter: *?*Fts5IndexIter) callconv(.c) c_int;
extern fn sqlite3Fts5IterClose(p: ?*Fts5IndexIter) callconv(.c) void;
extern fn sqlite3Fts5IterNextScan(p: *Fts5IndexIter) callconv(.c) c_int;
extern fn sqlite3Fts5IterTerm(p: *Fts5IndexIter, pn: *c_int) callconv(.c) ?[*]const u8;
extern fn sqlite3Fts5StructureRef(p: ?*Fts5Index) callconv(.c) ?*anyopaque;
extern fn sqlite3Fts5StructureRelease(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3Fts5StructureTest(p: ?*Fts5Index, pStruct: ?*anyopaque) callconv(.c) c_int;

extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn strlen(s: [*:0]const u8) usize;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3_stricmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_prepare_v2(db: ?*sqlite3, zSql: [*]const u8, nByte: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, iCol: c_int) i64;
extern fn sqlite3_value_text(pVal: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_bytes(pVal: ?*sqlite3_value) c_int;
extern fn sqlite3_result_text(pCtx: ?*sqlite3_context, z: ?[*]const u8, n: c_int, d: int.DestructorFn) void;
extern fn sqlite3_result_int(pCtx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_int64(pCtx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_create_module_v2(db: ?*sqlite3, zName: [*:0]const u8, p: ?*const sqlite3_module, pAux: ?*anyopaque, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) c_int;

// ===========================================================================
// Section-private structs (fts5.c 27273-27308).
// ===========================================================================
const Fts5VocabTable = extern struct {
    base: sqlite3_vtab,
    zFts5Tbl: ?[*:0]u8, // name of fts5 table
    zFts5Db: ?[*:0]u8, // db containing fts5 table
    db: ?*sqlite3, // database handle
    pGlobal: ?*Fts5Global, // FTS5 global object
    eType: c_int, // FTS5_VOCAB_COL, ROW or INSTANCE
    bBusy: c_uint, // true if busy
};

const Fts5VocabCursor = extern struct {
    base: sqlite3_vtab_cursor,
    pStmt: ?*sqlite3_stmt, // statement holding lock on pIndex
    pFts5: ?*Fts5Table, // associated FTS5 table

    bEof: c_int, // true if at EOF
    pIter: ?*Fts5IndexIter, // term/rowid iterator
    pStruct: ?*anyopaque, // from sqlite3Fts5StructureRef()

    nLeTerm: c_int, // size of zLeTerm in bytes
    zLeTerm: ?[*]u8, // (term <= $zLeTerm) param, or NULL
    colUsed: c_int, // copy of sqlite3_index_info.colUsed

    // 'col' tables only
    iCol: c_int,
    aCnt: ?[*]i64,
    aDoc: ?[*]i64,

    // all tables
    rowid: i64, // current rowid value
    term: Fts5Buffer, // current value of 'term' column

    // 'instance' tables only
    iInstPos: i64,
    iInstOff: c_int,
};

inline fn MIN(a: c_int, b: c_int) c_int {
    return if (a < b) a else b;
}

// fts5Int.h 1422-1428: fts5FastGetVarint32 with an i64 offset (vocab uses i64).
inline fn fts5FastGetVarint32(a: [*]const u8, iOff: *i64, nVal: *u32) void {
    nVal.* = a[@intCast(iOff.*)];
    iOff.* += 1;
    if (nVal.* & 0x80 != 0) {
        iOff.* -= 1;
        iOff.* += sqlite3Fts5GetVarint32(a + @as(usize, @intCast(iOff.*)), nVal);
    }
}

// FTS5_POS2COLUMN / FTS5_POS2OFFSET from the foundation.
const FTS5_POS2COLUMN = int.FTS5_POS2COLUMN;
const FTS5_POS2OFFSET = int.FTS5_POS2OFFSET;

// ===========================================================================
// fts5.c 27334-27357: translate a vocab type string to FTS5_VOCAB_XXX.
// ===========================================================================
fn fts5VocabTableType(zType: [*:0]const u8, pzErr: *?[*:0]u8, peType: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    const zCopy = sqlite3Fts5Strndup(&rc, zType, -1);
    if (rc == SQLITE_OK) {
        const z = zCopy.?;
        sqlite3Fts5Dequote(z);
        if (sqlite3_stricmp(z, "col") == 0) {
            peType.* = FTS5_VOCAB_COL;
        } else if (sqlite3_stricmp(z, "row") == 0) {
            peType.* = FTS5_VOCAB_ROW;
        } else if (sqlite3_stricmp(z, "instance") == 0) {
            peType.* = FTS5_VOCAB_INSTANCE;
        } else {
            pzErr.* = sqlite3_mprintf("fts5vocab: unknown table type: %Q", z);
            rc = SQLITE_ERROR;
        }
        sqlite3_free(z);
    }
    return rc;
}

// ===========================================================================
// fts5.c 27363-27376: xDisconnect / xDestroy.
// ===========================================================================
fn fts5VocabDisconnectMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}
fn fts5VocabDestroyMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 27399-27454: xConnect/xCreate shared implementation.
// ===========================================================================
fn fts5VocabInitVtab(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVTab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) c_int {
    const azSchema = [_][*:0]const u8{
        "CREATE TABlE vocab(" ++ FTS5_VOCAB_COL_SCHEMA ++ ")",
        "CREATE TABlE vocab(" ++ FTS5_VOCAB_ROW_SCHEMA ++ ")",
        "CREATE TABlE vocab(" ++ FTS5_VOCAB_INST_SCHEMA ++ ")",
    };

    var pRet: ?*Fts5VocabTable = null;
    var rc: c_int = SQLITE_OK;
    const av = argv.?;

    const bDb: bool = (argc == 6 and strlen(av[1].?) == 4 and memcmp("temp", av[1].?, 4) == 0);

    if (argc != 5 and bDb == false) {
        pzErr.* = sqlite3_mprintf("wrong number of vtable arguments");
        rc = SQLITE_ERROR;
    } else {
        const zDb = if (bDb) av[3].? else av[1].?;
        const zTab = if (bDb) av[4].? else av[3].?;
        const zType = if (bDb) av[5].? else av[4].?;
        const nDb: i64 = @as(i64, @intCast(strlen(zDb))) + 1;
        const nTab: i64 = @as(i64, @intCast(strlen(zTab))) + 1;
        var eType: c_int = 0;

        rc = fts5VocabTableType(zType, pzErr, &eType);
        if (rc == SQLITE_OK) {
            // assert( eType>=0 && eType<ArraySize(azSchema) );
            rc = sqlite3_declare_vtab(db, azSchema[@intCast(eType)]);
        }

        const nByte: i64 = @as(i64, @sizeOf(Fts5VocabTable)) + nDb + nTab;
        pRet = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
        if (pRet) |p| {
            p.pGlobal = @ptrCast(@alignCast(pAux));
            p.eType = eType;
            p.db = db;
            const after: [*]u8 = @ptrCast(@as([*]Fts5VocabTable, @ptrCast(p)) + 1);
            p.zFts5Tbl = @ptrCast(after);
            p.zFts5Db = @ptrCast(after + @as(usize, @intCast(nTab)));
            _ = memcpy(p.zFts5Tbl, zTab, @intCast(nTab));
            _ = memcpy(p.zFts5Db, zDb, @intCast(nDb));
            sqlite3Fts5Dequote(p.zFts5Tbl.?);
            sqlite3Fts5Dequote(p.zFts5Db.?);
        }
    }

    ppVTab.* = @ptrCast(pRet);
    return rc;
}

// ===========================================================================
// fts5.c 27461-27480: xConnect / xCreate.
// ===========================================================================
fn fts5VocabConnectMethod(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    return fts5VocabInitVtab(db, pAux, argc, argv, ppVtab, pzErr);
}
fn fts5VocabCreateMethod(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    return fts5VocabInitVtab(db, pAux, argc, argv, ppVtab, pzErr);
}

// ===========================================================================
// fts5.c 27494-27553: xBestIndex.
// ===========================================================================
fn fts5VocabBestIndexMethod(pUnused: *sqlite3_vtab, pInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = pUnused;
    var iTermEq: c_int = -1;
    var iTermGe: c_int = -1;
    var iTermLe: c_int = -1;
    var idxNum: c_int = @intCast(pInfo.colUsed);
    var nArg: c_int = 0;

    // assert( (pInfo->colUsed & FTS5_VOCAB_COLUSED_MASK)==pInfo->colUsed );

    const aCons = pInfo.aConstraint.?;
    var i: c_int = 0;
    while (i < pInfo.nConstraint) : (i += 1) {
        const p = &aCons[@intCast(i)];
        if (p.usable == 0) continue;
        if (p.iColumn == 0) { // term column
            if (p.op == SQLITE_INDEX_CONSTRAINT_EQ) iTermEq = i;
            if (p.op == SQLITE_INDEX_CONSTRAINT_LE) iTermLe = i;
            if (p.op == SQLITE_INDEX_CONSTRAINT_LT) iTermLe = i;
            if (p.op == SQLITE_INDEX_CONSTRAINT_GE) iTermGe = i;
            if (p.op == SQLITE_INDEX_CONSTRAINT_GT) iTermGe = i;
        }
    }

    const aUsage = pInfo.aConstraintUsage.?;
    if (iTermEq >= 0) {
        idxNum |= FTS5_VOCAB_TERM_EQ;
        nArg += 1;
        aUsage[@intCast(iTermEq)].argvIndex = nArg;
        pInfo.estimatedCost = 100;
    } else {
        pInfo.estimatedCost = 1000000;
        if (iTermGe >= 0) {
            idxNum |= FTS5_VOCAB_TERM_GE;
            nArg += 1;
            aUsage[@intCast(iTermGe)].argvIndex = nArg;
            pInfo.estimatedCost = pInfo.estimatedCost / 2;
        }
        if (iTermLe >= 0) {
            idxNum |= FTS5_VOCAB_TERM_LE;
            nArg += 1;
            aUsage[@intCast(iTermLe)].argvIndex = nArg;
            pInfo.estimatedCost = pInfo.estimatedCost / 2;
        }
    }

    if (pInfo.nOrderBy == 1 and
        pInfo.aOrderBy.?[0].iColumn == 0 and
        pInfo.aOrderBy.?[0].desc == 0)
    {
        pInfo.orderByConsumed = 1;
    }

    pInfo.idxNum = idxNum;
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 27558-27624: xOpen.
// ===========================================================================
fn fts5VocabOpenMethod(pVTab: *sqlite3_vtab, ppCsr: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pTab: *Fts5VocabTable = @ptrCast(pVTab);
    var pFts5: ?*Fts5Table = null;
    var pCsr: ?*Fts5VocabCursor = null;
    var rc: c_int = SQLITE_OK;
    var pStmt: ?*sqlite3_stmt = null;
    var zSql: ?[*:0]u8 = null;

    if (pTab.bBusy != 0) {
        pVTab.zErrMsg = sqlite3_mprintf(
            "recursive definition for %s.%s",
            pTab.zFts5Db,
            pTab.zFts5Tbl,
        );
        return SQLITE_ERROR;
    }
    zSql = sqlite3Fts5Mprintf(
        &rc,
        "SELECT t.%Q FROM %Q.%Q AS t WHERE t.%Q MATCH '*id'",
        pTab.zFts5Tbl,
        pTab.zFts5Db,
        pTab.zFts5Tbl,
        pTab.zFts5Tbl,
    );
    if (zSql) |z| {
        rc = sqlite3_prepare_v2(pTab.db, z, -1, &pStmt, null);
    }
    sqlite3_free(zSql);
    // assert( rc==SQLITE_OK || pStmt==0 );
    if (rc == SQLITE_ERROR) rc = SQLITE_OK;

    pTab.bBusy = 1;
    if (pStmt != null and sqlite3_step(pStmt) == SQLITE_ROW) {
        const iId = sqlite3_column_int64(pStmt, 0);
        pFts5 = sqlite3Fts5TableFromCsrid(pTab.pGlobal, iId);
    }
    pTab.bBusy = 0;

    if (rc == SQLITE_OK) {
        if (pFts5 == null) {
            rc = sqlite3_finalize(pStmt);
            pStmt = null;
            if (rc == SQLITE_OK) {
                pVTab.zErrMsg = sqlite3_mprintf(
                    "no such fts5 table: %s.%s",
                    pTab.zFts5Db,
                    pTab.zFts5Tbl,
                );
                rc = SQLITE_ERROR;
            }
        } else {
            rc = sqlite3Fts5FlushToDisk(pFts5.?);
        }
    }

    if (rc == SQLITE_OK) {
        const nByte: i64 = @as(i64, pFts5.?.pConfig.?.nCol) * @sizeOf(i64) * 2 + @sizeOf(Fts5VocabCursor);
        pCsr = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
    }

    if (pCsr) |c| {
        c.pFts5 = pFts5;
        c.pStmt = pStmt;
        const aCnt: [*]i64 = @ptrCast(@alignCast(@as([*]Fts5VocabCursor, @ptrCast(c)) + 1));
        c.aCnt = aCnt;
        c.aDoc = aCnt + @as(usize, @intCast(pFts5.?.pConfig.?.nCol));
    } else {
        _ = sqlite3_finalize(pStmt);
    }

    ppCsr.* = @ptrCast(pCsr);
    return rc;
}

// ===========================================================================
// fts5.c 27630-27647: reset cursor to post-xOpen state.
// ===========================================================================
fn fts5VocabResetCursor(pCsr: *Fts5VocabCursor) void {
    const nCol: c_int = pCsr.pFts5.?.pConfig.?.nCol;
    pCsr.rowid = 0;
    sqlite3Fts5IterClose(pCsr.pIter);
    sqlite3Fts5StructureRelease(pCsr.pStruct);
    pCsr.pStruct = null;
    pCsr.pIter = null;
    sqlite3_free(pCsr.zLeTerm);
    pCsr.nLeTerm = -1;
    pCsr.zLeTerm = null;
    pCsr.bEof = 0;
    pCsr.iCol = 0;
    pCsr.iInstPos = 0;
    pCsr.iInstOff = 0;
    pCsr.colUsed = 0;
    _ = memset(pCsr.aCnt, 0, @sizeOf(i64) * @as(usize, @intCast(nCol)));
    _ = memset(pCsr.aDoc, 0, @sizeOf(i64) * @as(usize, @intCast(nCol)));
}

// ===========================================================================
// fts5.c 27653-27660: xClose.
// ===========================================================================
fn fts5VocabCloseMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5VocabCursor = @ptrCast(pCursor);
    fts5VocabResetCursor(pCsr);
    sqlite3Fts5BufferFree(&pCsr.term);
    _ = sqlite3_finalize(pCsr.pStmt);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 27662-27682: advance to a new term ('instance' tables).
// ===========================================================================
fn fts5VocabInstanceNewTerm(pCsr: *Fts5VocabCursor) c_int {
    var rc: c_int = SQLITE_OK;

    if (int.sqlite3Fts5IterEof(pCsr.pIter.?) != 0) {
        pCsr.bEof = 1;
    } else {
        var nTerm: c_int = undefined;
        const zTerm = sqlite3Fts5IterTerm(pCsr.pIter.?, &nTerm);
        if (pCsr.nLeTerm >= 0) {
            const nCmp = MIN(nTerm, pCsr.nLeTerm);
            const bCmp = memcmp(pCsr.zLeTerm, zTerm, @intCast(nCmp));
            if (bCmp < 0 or (bCmp == 0 and pCsr.nLeTerm < nTerm)) {
                pCsr.bEof = 1;
            }
        }
        sqlite3Fts5BufferSet(&rc, &pCsr.term, nTerm, zTerm.?);
    }
    return rc;
}

// ===========================================================================
// fts5.c 27684-27711: advance ('instance' tables).
// ===========================================================================
fn fts5VocabInstanceNext(pCsr: *Fts5VocabCursor) c_int {
    const eDetail: c_int = pCsr.pFts5.?.pConfig.?.eDetail;
    var rc: c_int = SQLITE_OK;
    const pIter = pCsr.pIter.?;
    const pp: *i64 = &pCsr.iInstPos;
    const po: *c_int = &pCsr.iInstOff;

    while (eDetail == FTS5_DETAIL_NONE or
        sqlite3Fts5PoslistNext64(pIter.pData, pIter.nData, po, pp) != 0)
    {
        pCsr.iInstPos = 0;
        pCsr.iInstOff = 0;

        rc = sqlite3Fts5IterNextScan(pCsr.pIter.?);
        if (rc == SQLITE_OK) {
            rc = fts5VocabInstanceNewTerm(pCsr);
            if (pCsr.bEof != 0 or eDetail == FTS5_DETAIL_NONE) break;
        }
        if (rc != 0) {
            pCsr.bEof = 1;
            break;
        }
    }

    return rc;
}

// ===========================================================================
// fts5.c 27716-27849: xNext.
// ===========================================================================
fn fts5VocabNextMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5VocabCursor = @ptrCast(pCursor);
    const pTab: *Fts5VocabTable = @ptrCast(pCursor.pVtab);
    const nCol: c_int = pCsr.pFts5.?.pConfig.?.nCol;
    var rc: c_int = undefined;

    rc = sqlite3Fts5StructureTest(pCsr.pFts5.?.pIndex, pCsr.pStruct);
    if (rc != SQLITE_OK) return rc;
    pCsr.rowid += 1;

    if (pTab.eType == FTS5_VOCAB_INSTANCE) {
        return fts5VocabInstanceNext(pCsr);
    }

    if (pTab.eType == FTS5_VOCAB_COL) {
        pCsr.iCol += 1;
        while (pCsr.iCol < nCol) : (pCsr.iCol += 1) {
            if (pCsr.aDoc.?[@intCast(pCsr.iCol)] != 0) break;
        }
    }

    if (pTab.eType != FTS5_VOCAB_COL or pCsr.iCol >= nCol) {
        if (int.sqlite3Fts5IterEof(pCsr.pIter.?) != 0) {
            pCsr.bEof = 1;
        } else {
            var nTerm: c_int = undefined;
            var zTerm = sqlite3Fts5IterTerm(pCsr.pIter.?, &nTerm);
            // assert( nTerm>=0 );
            if (pCsr.nLeTerm >= 0) {
                const nCmp = MIN(nTerm, pCsr.nLeTerm);
                const bCmp = memcmp(pCsr.zLeTerm, zTerm, @intCast(nCmp));
                if (bCmp < 0 or (bCmp == 0 and pCsr.nLeTerm < nTerm)) {
                    pCsr.bEof = 1;
                    return SQLITE_OK;
                }
            }

            sqlite3Fts5BufferSet(&rc, &pCsr.term, nTerm, zTerm.?);
            _ = memset(pCsr.aCnt, 0, @as(usize, @intCast(nCol)) * @sizeOf(i64));
            _ = memset(pCsr.aDoc, 0, @as(usize, @intCast(nCol)) * @sizeOf(i64));
            pCsr.iCol = 0;

            while (rc == SQLITE_OK) {
                const eDetail: c_int = pCsr.pFts5.?.pConfig.?.eDetail;
                const pPos = pCsr.pIter.?.pData;
                const nPos = pCsr.pIter.?.nData;
                var iPos: i64 = 0;
                var iOff: c_int = 0;

                switch (pTab.eType) {
                    FTS5_VOCAB_ROW => {
                        if (eDetail == FTS5_DETAIL_FULL and (pCsr.colUsed & 0x04) != 0) {
                            while (iPos < nPos) {
                                var ii: u32 = undefined;
                                fts5FastGetVarint32(pPos.?, &iPos, &ii);
                                if (ii == 1) {
                                    // new column
                                    fts5FastGetVarint32(pPos.?, &iPos, &ii);
                                } else {
                                    pCsr.aCnt.?[0] += 1;
                                }
                            }
                        }
                        pCsr.aDoc.?[0] += 1;
                    },

                    FTS5_VOCAB_COL => {
                        if (eDetail == FTS5_DETAIL_FULL) {
                            var iCol: c_int = -1;
                            while (0 == sqlite3Fts5PoslistNext64(pPos, nPos, &iOff, &iPos)) {
                                const ii = FTS5_POS2COLUMN(iPos);
                                if (iCol != ii) {
                                    if (ii >= nCol) {
                                        rc = FTS5_CORRUPT;
                                        break;
                                    }
                                    pCsr.aDoc.?[@intCast(ii)] += 1;
                                    iCol = ii;
                                }
                                pCsr.aCnt.?[@intCast(ii)] += 1;
                            }
                        } else if (eDetail == FTS5_DETAIL_COLUMNS) {
                            while (0 == sqlite3Fts5PoslistNext64(pPos, nPos, &iOff, &iPos)) {
                                if (iPos >= nCol) {
                                    rc = FTS5_CORRUPT;
                                    break;
                                }
                                pCsr.aDoc.?[@intCast(iPos)] += 1;
                            }
                        } else {
                            // assert( eDetail==FTS5_DETAIL_NONE );
                            pCsr.aDoc.?[0] += 1;
                        }
                    },

                    else => {
                        // assert( pTab->eType==FTS5_VOCAB_INSTANCE );
                    },
                }

                if (rc == SQLITE_OK) {
                    rc = sqlite3Fts5IterNextScan(pCsr.pIter.?);
                }
                if (pTab.eType == FTS5_VOCAB_INSTANCE) break;

                if (rc == SQLITE_OK) {
                    zTerm = sqlite3Fts5IterTerm(pCsr.pIter.?, &nTerm);
                    if (nTerm != pCsr.term.n or
                        (nTerm > 0 and memcmp(zTerm, pCsr.term.p, @intCast(nTerm)) != 0))
                    {
                        break;
                    }
                    if (int.sqlite3Fts5IterEof(pCsr.pIter.?) != 0) break;
                }
            }
        }
    }

    if (rc == SQLITE_OK and pCsr.bEof == 0 and pTab.eType == FTS5_VOCAB_COL) {
        while (pCsr.iCol < nCol and pCsr.aDoc.?[@intCast(pCsr.iCol)] == 0) : (pCsr.iCol += 1) {}
        if (pCsr.iCol == nCol) {
            rc = FTS5_CORRUPT;
        }
    }
    return rc;
}

// ===========================================================================
// fts5.c 27854-27923: xFilter.
// ===========================================================================
fn fts5VocabFilterMethod(
    pCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    zUnused: ?[*:0]const u8,
    nUnused: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = zUnused;
    _ = nUnused;
    const pTab: *Fts5VocabTable = @ptrCast(pCursor.pVtab);
    const pCsr: *Fts5VocabCursor = @ptrCast(pCursor);
    const eType: c_int = pTab.eType;
    var rc: c_int = SQLITE_OK;

    var iVal: c_int = 0;
    var f: c_int = FTS5INDEX_QUERY_SCAN;
    var zTerm: ?[*]const u8 = null;
    var nTerm: c_int = 0;

    var pEq: ?*sqlite3_value = null;
    var pGe: ?*sqlite3_value = null;
    var pLe: ?*sqlite3_value = null;

    const av = apVal.?;

    fts5VocabResetCursor(pCsr);
    if (idxNum & FTS5_VOCAB_TERM_EQ != 0) {
        pEq = av[@intCast(iVal)];
        iVal += 1;
    }
    if (idxNum & FTS5_VOCAB_TERM_GE != 0) {
        pGe = av[@intCast(iVal)];
        iVal += 1;
    }
    if (idxNum & FTS5_VOCAB_TERM_LE != 0) {
        pLe = av[@intCast(iVal)];
        iVal += 1;
    }
    pCsr.colUsed = (idxNum & FTS5_VOCAB_COLUSED_MASK);

    if (pEq != null) {
        zTerm = @ptrCast(sqlite3_value_text(pEq));
        nTerm = sqlite3_value_bytes(pEq);
        f = FTS5INDEX_QUERY_NOTOKENDATA;
    } else {
        if (pGe != null) {
            zTerm = @ptrCast(sqlite3_value_text(pGe));
            nTerm = sqlite3_value_bytes(pGe);
        }
        if (pLe != null) {
            var zCopy = sqlite3_value_text(pLe);
            if (zCopy == null) zCopy = "";
            pCsr.nLeTerm = sqlite3_value_bytes(pLe);
            pCsr.zLeTerm = @ptrCast(sqlite3_malloc64(@intCast(pCsr.nLeTerm + 1)));
            if (pCsr.zLeTerm == null) {
                rc = SQLITE_NOMEM;
            } else {
                _ = memcpy(pCsr.zLeTerm, zCopy, @intCast(pCsr.nLeTerm + 1));
            }
        }
    }

    if (rc == SQLITE_OK) {
        const pIndex = pCsr.pFts5.?.pIndex;
        rc = sqlite3Fts5IndexQuery(pIndex, zTerm, nTerm, f, null, &pCsr.pIter);
        if (rc == SQLITE_OK) {
            pCsr.pStruct = sqlite3Fts5StructureRef(pIndex);
        }
    }
    if (rc == SQLITE_OK and eType == FTS5_VOCAB_INSTANCE) {
        rc = fts5VocabInstanceNewTerm(pCsr);
    }
    if (rc == SQLITE_OK and pCsr.bEof == 0 and
        (eType != FTS5_VOCAB_INSTANCE or
            pCsr.pFts5.?.pConfig.?.eDetail != FTS5_DETAIL_NONE))
    {
        rc = fts5VocabNextMethod(pCursor);
    }

    return rc;
}

// ===========================================================================
// fts5.c 27929-27932: xEof.
// ===========================================================================
fn fts5VocabEofMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5VocabCursor = @ptrCast(pCursor);
    return pCsr.bEof;
}

// ===========================================================================
// fts5.c 27934-27999: xColumn.
// ===========================================================================
fn fts5VocabColumnMethod(pCursor: *sqlite3_vtab_cursor, pCtx: ?*sqlite3_context, iCol: c_int) callconv(.c) c_int {
    const pCsr: *Fts5VocabCursor = @ptrCast(pCursor);
    const eDetail: c_int = pCsr.pFts5.?.pConfig.?.eDetail;
    const eType: c_int = @as(*Fts5VocabTable, @ptrCast(pCursor.pVtab)).eType;
    var iVal: i64 = 0;

    if (iCol == 0) {
        sqlite3_result_text(pCtx, pCsr.term.p, pCsr.term.n, SQLITE_TRANSIENT);
    } else if (eType == FTS5_VOCAB_COL) {
        // assert( iCol==1 || iCol==2 || iCol==3 );
        if (iCol == 1) {
            if (eDetail != FTS5_DETAIL_NONE) {
                const z = pCsr.pFts5.?.pConfig.?.azCol.?[@intCast(pCsr.iCol)];
                sqlite3_result_text(pCtx, @ptrCast(z), -1, SQLITE_STATIC);
            }
        } else if (iCol == 2) {
            iVal = pCsr.aDoc.?[@intCast(pCsr.iCol)];
        } else {
            iVal = pCsr.aCnt.?[@intCast(pCsr.iCol)];
        }
    } else if (eType == FTS5_VOCAB_ROW) {
        // assert( iCol==1 || iCol==2 );
        if (iCol == 1) {
            iVal = pCsr.aDoc.?[0];
        } else {
            iVal = pCsr.aCnt.?[0];
        }
    } else {
        // assert( eType==FTS5_VOCAB_INSTANCE );
        switch (iCol) {
            1 => {
                sqlite3_result_int64(pCtx, pCsr.pIter.?.iRowid);
            },
            2 => {
                var ii: c_int = -1;
                if (eDetail == FTS5_DETAIL_FULL) {
                    ii = FTS5_POS2COLUMN(pCsr.iInstPos);
                } else if (eDetail == FTS5_DETAIL_COLUMNS) {
                    ii = @intCast(pCsr.iInstPos);
                }
                if (ii >= 0 and ii < pCsr.pFts5.?.pConfig.?.nCol) {
                    const z = pCsr.pFts5.?.pConfig.?.azCol.?[@intCast(ii)];
                    sqlite3_result_text(pCtx, @ptrCast(z), -1, SQLITE_STATIC);
                }
            },
            else => {
                // assert( iCol==3 );
                if (eDetail == FTS5_DETAIL_FULL) {
                    const ii = FTS5_POS2OFFSET(pCsr.iInstPos);
                    sqlite3_result_int(pCtx, ii);
                }
            },
        }
    }

    if (iVal > 0) sqlite3_result_int64(pCtx, iVal);
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 28006-28013: xRowid.
// ===========================================================================
fn fts5VocabRowidMethod(pCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *Fts5VocabCursor = @ptrCast(pCursor);
    pRowid.* = pCsr.rowid;
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 28015-28046: register the fts5vocab module (iVersion 2).
// ===========================================================================
const fts5Vocab = sqlite3_module{
    .iVersion = 2,
    .xCreate = fts5VocabCreateMethod,
    .xConnect = fts5VocabConnectMethod,
    .xBestIndex = fts5VocabBestIndexMethod,
    .xDisconnect = fts5VocabDisconnectMethod,
    .xDestroy = fts5VocabDestroyMethod,
    .xOpen = fts5VocabOpenMethod,
    .xClose = fts5VocabCloseMethod,
    .xFilter = fts5VocabFilterMethod,
    .xNext = fts5VocabNextMethod,
    .xEof = fts5VocabEofMethod,
    .xColumn = fts5VocabColumnMethod,
    .xRowid = fts5VocabRowidMethod,
    .xUpdate = null,
    .xBegin = null,
    .xSync = null,
    .xCommit = null,
    .xRollback = null,
    .xFindFunction = null,
    .xRename = null,
    .xSavepoint = null,
    .xRelease = null,
    .xRollbackTo = null,
    .xShadowName = null,
    .xIntegrity = null,
};

export fn sqlite3Fts5VocabInit(pGlobal: ?*Fts5Global, db: ?*sqlite3) callconv(.c) c_int {
    const p: ?*anyopaque = @ptrCast(pGlobal);
    return sqlite3_create_module_v2(db, "fts5vocab", &fts5Vocab, p, null);
}

comptime {
    _ = int;
}
