//! Zig port of SQLite's incremental BLOB I/O (src/vdbeblob.c).
//!
//! Implements the public-API surface that lets a program open a handle on a
//! single TEXT/BLOB cell and stream bytes in/out without materializing the
//! whole value: sqlite3_blob_open / _close / _read / _write / _reopen /
//! _bytes, plus the private Incrblob handle struct and the blobReadWrite /
//! blobSeekToRow helpers.
//!
//! SQLITE_OMIT_INCRBLOB is OFF in both this project's `zig build` and the
//! `--dev` testfixture, so the full implementation (not the omitted stub) is
//! the one we port. SQLITE_ENABLE_PREUPDATE_HOOK is ON in BOTH configs, so the
//! pre-update-hook branch in blobReadWrite is compiled. SQLITE_OMIT_SHARED_CACHE
//! and SQLITE_OMIT_VIEW / SQLITE_OMIT_FOREIGN_KEY are OFF, so the
//! BtreeEnterAll/LeaveAll, OP_TableLock-config, view-reject and FK-reject paths
//! are all live. SQLITE_ENABLE_API_ARMOR is OFF, so the armor MISUSE checks are
//! NOT compiled and are intentionally absent.
//!
//! ---------------------------------------------------------------------------
//! Strategy
//! ---------------------------------------------------------------------------
//! This module is a thin orchestrator: nearly all of the heavy lifting stays in
//! already-linked C helpers (sqlite3LocateTable, sqlite3VdbeCreate,
//! sqlite3VdbeAddOpList, sqlite3VdbeMakeReady, sqlite3VdbeExec, the b-tree
//! payload accessors, the parse-object lifecycle, the error/malloc helpers).
//! What we own:
//!   * the `Incrblob` handle struct — it is PRIVATE to vdbeblob.c (no other TU
//!     sees its layout), so we control it; mirrored as `extern struct` for a
//!     C-ABI-stable sizeof passed to sqlite3DbMallocZero.
//!   * a stack/heap `Parse` object (sParse) handed to the C helpers. Parse is a
//!     large config-divergent struct; we never interpret most of it. We size it
//!     from c_layout (`sizeof_Parse`) as an 8-aligned byte buffer, let
//!     sqlite3ParseObjectInit fill it, and only ever poke the four fields the C
//!     code writes/reads (zErrMsg, nVar, nMem, nTab) at their ground-truth
//!     offsets.
//!   * reaching into Vdbe / VdbeCursor / Table / Schema / Db / Index / FKey at
//!     ground-truth offsets to reproduce the few struct accesses the C makes
//!     (r[1] register, pc rewind, the cursor's parsed-type cache, etc.).
//!
//! ---------------------------------------------------------------------------
//! Config divergence
//! ---------------------------------------------------------------------------
//! All Vdbe and sqlite3 fields touched here are config-INVARIANT (verified in
//! both configs). The VdbeCursor fields DIVERGE under SQLITE_DEBUG (it inserts
//! seekOp/wrFlag bytes), so nField/nHdrParsed/aType/uc are routed through
//! c_layout's config-selected namespace. Parse/Table/Schema/Db/Index/FKey
//! offsets touched here are all config-invariant. Every offset uses the
//! `@hasDecl(L,...) else <probe>` idiom (cf. vdbevtab.zig) so authoritative
//! values win once added to tools/offsets.c, with verified probe fallbacks.
//!
//! No standalone Zig unit test is feasible: every path needs a live connection,
//! a real schema, a compiled Vdbe and an open b-tree cursor. Validated
//! end-to-end through the engine (upstream test/incrblob*.test) under the
//! testfixture and the functional gate.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ===========================================================================
// Result codes / constants (sqlite3.h, sqliteInt.h, vdbeInt.h)
// ===========================================================================
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_ABORT: c_int = 4;
const SQLITE_MISUSE: c_int = 21;
const SQLITE_ROW: c_int = 100;
const SQLITE_SCHEMA: c_int = 17;

// SQLITE_DELETE authorizer/preupdate op code (sqlite3.h)
const SQLITE_DELETE: c_int = 9;

// db->flags bit (sqliteInt.h): SQLITE_ForeignKeys.
const SQLITE_ForeignKeys: u64 = 0x00004000;

// Table.tabFlags (sqliteInt.h): TF_HasGenerated (combo), TF_WithoutRowid.
const TF_HasGenerated: u32 = 0x00000060;
const TF_WithoutRowid: u32 = 0x00000080;

// Table.eTabType (sqliteInt.h).
const TABTYP_NORM: u8 = 0;
const TABTYP_VTAB: u8 = 1;
const TABTYP_VIEW: u8 = 2;

// Index.aiColumn sentinel (sqliteInt.h): XN_EXPR == -2.
const XN_EXPR: i16 = -2;

// vdbeInt.h: SQLITE_MAX_SCHEMA_RETRY.
const SQLITE_MAX_SCHEMA_RETRY: c_int = 50;

// VdbeCursor.eCurType (vdbeInt.h): CURTYPE_BTREE == 0.
const CURTYPE_BTREE: u8 = 0;

// VdbeOp.p4type sentinels (vdbe.h): P4_TRANSIENT==0, P4_INT32==-3.
const P4_TRANSIENT: i8 = 0;
const P4_INT32: i8 = -3;

// Opcodes (opcodes.h).
const OP_Transaction: u8 = 2;
const OP_NotExists: u8 = 31;
const OP_Halt: u8 = 72;
const OP_ResultRow: u8 = 86;
const OP_Column: u8 = 96;
const OP_OpenRead: u8 = 114;
const OP_OpenWrite: u8 = 116;
const OP_TableLock: u8 = 171;
const OP_Noop: u8 = 189;

// ===========================================================================
// Opaque public handles
// ===========================================================================
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_blob = anyopaque;
const BtCursor = anyopaque;
const Table = anyopaque;
const Vdbe = anyopaque;
const Parse = anyopaque;

// ===========================================================================
// Ground-truth offsets (c_layout fallback idiom — cf. vdbevtab.zig).
// ===========================================================================

// --- struct Vdbe (== sqlite3_stmt); all CONFIG-INVARIANT ---
const Vdbe_pc: usize = if (@hasDecl(L, "Vdbe_pc")) L.Vdbe_pc else 48;
const Vdbe_rc: usize = if (@hasDecl(L, "Vdbe_rc")) L.Vdbe_rc else 52;
const Vdbe_aMem: usize = if (@hasDecl(L, "Vdbe_aMem")) L.Vdbe_aMem else 104;
const Vdbe_apCsr: usize = if (@hasDecl(L, "Vdbe_apCsr")) L.Vdbe_apCsr else 120;

// --- struct Mem (== sqlite3_value) — only sizeof matters (aMem[1] stride) ---
const sizeof_Mem: usize = L.sizeof_Mem; // 56 prod / 72 tf

// --- struct VdbeCursor — DIVERGES under SQLITE_DEBUG ---
const VdbeCursor_eCurType: usize = if (@hasDecl(L, "VdbeCursor_eCurType")) L.VdbeCursor_eCurType else 0;
const VdbeCursor_nField: usize = if (@hasDecl(L, "VdbeCursor_nField")) L.VdbeCursor_nField else (if (config.sqlite_debug) 72 else 64);
const VdbeCursor_nHdrParsed: usize = if (@hasDecl(L, "VdbeCursor_nHdrParsed")) L.VdbeCursor_nHdrParsed else (if (config.sqlite_debug) 74 else 66);
const VdbeCursor_uc: usize = if (@hasDecl(L, "VdbeCursor_uc")) L.VdbeCursor_uc else (if (config.sqlite_debug) 48 else 40);
const VdbeCursor_aType: usize = if (@hasDecl(L, "VdbeCursor_aType")) L.VdbeCursor_aType else (if (config.sqlite_debug) 120 else 112);

// --- struct VdbeOp — CONFIG-INVARIANT (sizeof 32) ---
const Op_opcode: usize = if (@hasDecl(L, "VdbeOp_opcode")) L.VdbeOp_opcode else 0;
const Op_p4type: usize = if (@hasDecl(L, "VdbeOp_p4type")) L.VdbeOp_p4type else 1;
const Op_p1: usize = if (@hasDecl(L, "VdbeOp_p1")) L.VdbeOp_p1 else 4;
const Op_p2: usize = if (@hasDecl(L, "VdbeOp_p2")) L.VdbeOp_p2 else 8;
const Op_p3: usize = if (@hasDecl(L, "VdbeOp_p3")) L.VdbeOp_p3 else 12;
const Op_p4: usize = if (@hasDecl(L, "VdbeOp_p4")) L.VdbeOp_p4 else 16;
const sizeof_Op: usize = if (@hasDecl(L, "sizeof_VdbeOp")) L.sizeof_VdbeOp else 32;

// --- struct sqlite3 — all CONFIG-INVARIANT ---
const sqlite3_mutex: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const sqlite3_aDb: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_flags: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_mallocFailed: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_xPreUpdateCallback: usize = if (@hasDecl(L, "sqlite3_xPreUpdateCallback")) L.sqlite3_xPreUpdateCallback else 360;

// --- struct Db (sizeof 32) ---
const Db_zDbSName: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

// --- struct Parse — sizeof + the four fields we poke (CONFIG-INVARIANT) ---
const sizeof_Parse: usize = if (@hasDecl(L, "sizeof_Parse")) L.sizeof_Parse else 416;
const Parse_zErrMsg: usize = if (@hasDecl(L, "Parse_zErrMsg")) L.Parse_zErrMsg else 8;
const Parse_nVar: usize = if (@hasDecl(L, "Parse_nVar")) L.Parse_nVar else 296;
const Parse_nMem: usize = if (@hasDecl(L, "Parse_nMem")) L.Parse_nMem else 60;
const Parse_nTab: usize = if (@hasDecl(L, "Parse_nTab")) L.Parse_nTab else 56;

// --- struct Table — CONFIG-INVARIANT ---
const Table_zName: usize = if (@hasDecl(L, "Table_zName")) L.Table_zName else 0;
const Table_tnum: usize = if (@hasDecl(L, "Table_tnum")) L.Table_tnum else 40;
const Table_tabFlags: usize = if (@hasDecl(L, "Table_tabFlags")) L.Table_tabFlags else 48;
const Table_nCol: usize = if (@hasDecl(L, "Table_nCol")) L.Table_nCol else 54;
const Table_eTabType: usize = if (@hasDecl(L, "Table_eTabType")) L.Table_eTabType else 63;
const Table_u: usize = if (@hasDecl(L, "Table_u")) L.Table_u else 64; // u.tab.pFKey lives here
const Table_pIndex: usize = if (@hasDecl(L, "Table_pIndex")) L.Table_pIndex else 16;
const Table_pSchema: usize = if (@hasDecl(L, "Table_pSchema")) L.Table_pSchema else 96;

// u.tab: { int addColOffset; FKey *pFKey; ... } — pFKey is the 2nd member.
// addColOffset(int)@0 padded to 8, pFKey@8 within the union.
const Table_u_tab_pFKey: usize = Table_u + 8;

// --- struct Schema — CONFIG-INVARIANT ---
const Schema_schema_cookie: usize = if (@hasDecl(L, "Schema_schema_cookie")) L.Schema_schema_cookie else 0;
const Schema_iGeneration: usize = if (@hasDecl(L, "Schema_iGeneration")) L.Schema_iGeneration else 4;

// --- struct Index — CONFIG-INVARIANT ---
const Index_aiColumn: usize = if (@hasDecl(L, "Index_aiColumn")) L.Index_aiColumn else 8;
const Index_pNext: usize = if (@hasDecl(L, "Index_pNext")) L.Index_pNext else 40;
const Index_nKeyCol: usize = if (@hasDecl(L, "Index_nKeyCol")) L.Index_nKeyCol else 94;

// --- struct FKey — CONFIG-INVARIANT ---
const FKey_pNextFrom: usize = if (@hasDecl(L, "FKey_pNextFrom")) L.FKey_pNextFrom else 8;
const FKey_nCol: usize = if (@hasDecl(L, "FKey_nCol")) L.FKey_nCol else 40;
const FKey_aCol: usize = if (@hasDecl(L, "FKey_aCol")) L.FKey_aCol else 64;
// struct sColMap { int iFrom; char *zCol; } — sizeof 16, iFrom@0.
const sizeof_FKeyCol: usize = if (@hasDecl(L, "sizeof_FKeyCol")) L.sizeof_FKeyCol else 16;

// ===========================================================================
// Typed field readers/writers over opaque base pointers.
// ===========================================================================
inline fn fieldPtr(comptime T: type, base: ?*anyopaque, off: usize) *T {
    const p: [*]u8 = @ptrCast(base.?);
    return @ptrCast(@alignCast(p + off));
}
inline fn rdU8(base: ?*anyopaque, off: usize) u8 {
    const p: [*]const u8 = @ptrCast(base.?);
    return p[off];
}
inline fn rdU16(base: ?*anyopaque, off: usize) u16 {
    return fieldPtr(u16, base, off).*;
}
inline fn rdI16(base: ?*anyopaque, off: usize) i16 {
    return fieldPtr(i16, base, off).*;
}
inline fn rdInt(base: ?*anyopaque, off: usize) c_int {
    return fieldPtr(c_int, base, off).*;
}
inline fn rdU32(base: ?*anyopaque, off: usize) u32 {
    return fieldPtr(u32, base, off).*;
}
inline fn rdU64(base: ?*anyopaque, off: usize) u64 {
    return fieldPtr(u64, base, off).*;
}
inline fn rdPtr(base: ?*anyopaque, off: usize) ?*anyopaque {
    return fieldPtr(?*anyopaque, base, off).*;
}
inline fn wrPtr(base: ?*anyopaque, off: usize, v: ?*anyopaque) void {
    fieldPtr(?*anyopaque, base, off).* = v;
}
inline fn wrInt(base: ?*anyopaque, off: usize, v: c_int) void {
    fieldPtr(c_int, base, off).* = v;
}
inline fn wrU8(base: ?*anyopaque, off: usize, v: u8) void {
    const p: [*]u8 = @ptrCast(base.?);
    p[off] = v;
}

// ===========================================================================
// The private Incrblob handle. vdbeblob.c owns this layout (no other TU sees
// it), so we mirror the field order/types as `extern struct`.
//   int nByte; int iOffset; u16 iCol; BtCursor *pCsr; sqlite3_stmt *pStmt;
//   sqlite3 *db; char *zDb; Table *pTab;
// ===========================================================================
const Incrblob = extern struct {
    nByte: c_int, // Size of open blob, in bytes
    iOffset: c_int, // Byte offset of blob in cursor data
    iCol: u16, // Table column this handle is open on
    pCsr: ?*BtCursor, // Cursor pointing at blob row
    pStmt: ?*sqlite3_stmt, // Statement holding cursor open
    db: ?*sqlite3, // The associated database
    zDb: ?[*:0]u8, // Database name
    pTab: ?*Table, // Table object
};

// ===========================================================================
// External C symbols resolved at link time.
// ===========================================================================

// --- public API ---
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_errmsg(db: ?*sqlite3) ?[*:0]const u8;

// --- internal helpers (sqliteInt.h / vdbe.h / vdbeInt.h / btree.h) ---
extern fn sqlite3DbMallocZero(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3MPrintf(db: ?*sqlite3, zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3ErrorMsg(pParse: ?*Parse, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3ErrorWithMsg(db: ?*sqlite3, rc: c_int, zFormat: ?[*:0]const u8, ...) void;
extern fn sqlite3Error(db: ?*sqlite3, rc: c_int) void;
extern fn sqlite3ApiExit(db: ?*sqlite3, rc: c_int) c_int;

extern fn sqlite3ParseObjectInit(pParse: ?*Parse, db: ?*sqlite3) void;
extern fn sqlite3ParseObjectReset(pParse: ?*Parse) void;
extern fn sqlite3BtreeEnterAll(db: ?*sqlite3) void;
extern fn sqlite3BtreeLeaveAll(db: ?*sqlite3) void;
extern fn sqlite3LocateTable(pParse: ?*Parse, flags: u32, zName: [*:0]const u8, zDbase: ?[*:0]const u8) ?*Table;
extern fn sqlite3SchemaToIndex(db: ?*sqlite3, pSchema: ?*anyopaque) c_int;
extern fn sqlite3OpenTempDatabase(pParse: ?*Parse) c_int;
extern fn sqlite3ColumnIndex(pTab: ?*Table, zCol: [*:0]const u8) c_int;

extern fn sqlite3VdbeCreate(pParse: ?*Parse) ?*Vdbe;
extern fn sqlite3VdbeAddOp4Int(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeChangeP5(p: ?*Vdbe, p5: u16) void;
extern fn sqlite3VdbeCurrentAddr(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeAddOpList(p: ?*Vdbe, nOp: c_int, aOp: [*]const VdbeOpList, iLineno: c_int) ?*anyopaque;
extern fn sqlite3VdbeUsesBtree(p: ?*Vdbe, i: c_int) void;
extern fn sqlite3VdbeChangeP4(p: ?*Vdbe, addr: c_int, zP4: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3VdbeMakeReady(p: ?*Vdbe, pParse: ?*Parse) void;
extern fn sqlite3VdbeFinalize(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeExec(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeMemSetInt64(pMem: ?*anyopaque, val: i64) void;
extern fn sqlite3VdbeSerialTypeLen(serial_type: u32) u32;

extern fn sqlite3BtreeIncrblobCursor(pCur: ?*BtCursor) void;
extern fn sqlite3BtreeEnterCursor(pCur: ?*BtCursor) void;
extern fn sqlite3BtreeLeaveCursor(pCur: ?*BtCursor) void;
extern fn sqlite3BtreePayloadChecked(pCur: ?*BtCursor, offset: u32, amt: u32, pBuf: ?*anyopaque) c_int;
extern fn sqlite3BtreePutData(pCur: ?*BtCursor, offset: u32, amt: u32, pBuf: ?*anyopaque) c_int;

// preupdate-hook helpers (ENABLE_PREUPDATE_HOOK is ON in both configs)
extern fn sqlite3BtreeCursorIsValidNN(pCur: ?*BtCursor) c_int;
extern fn sqlite3BtreeCursorRestore(pCur: ?*BtCursor, pDifferentRow: *c_int) c_int;
extern fn sqlite3BtreeIntegerKey(pCur: ?*BtCursor) i64;
extern fn sqlite3VdbePreUpdateHook(
    v: ?*Vdbe,
    pCsr: ?*anyopaque, // VdbeCursor*
    op: c_int,
    zDb: ?[*:0]const u8,
    pTab: ?*Table,
    iKey1: i64,
    iReg: c_int,
    iBlobWrite: c_int,
) void;

// xCall signature for read/write dispatch.
const XCallFn = *const fn (?*BtCursor, u32, u32, ?*anyopaque) callconv(.c) c_int;

// VdbeOpList: { u8 opcode; signed char p1, p2, p3; } (vdbe.h).
const VdbeOpList = extern struct {
    opcode: u8,
    p1: i8,
    p2: i8,
    p3: i8,
};

// ===========================================================================
// blobSeekToRow — seek the b-tree cursor of handle p to row iRow.
// ===========================================================================
fn blobSeekToRow(p: *Incrblob, iRow: i64, pzErr: *?[*:0]u8) c_int {
    var rc: c_int = undefined;
    var zErr: ?[*:0]u8 = null;
    const v = p.pStmt; // (Vdbe*)p->pStmt

    // Set register r[1] to integer iRow directly (a performance optimization).
    // aMem is Mem*; aMem[1] is one Mem-stride past aMem.
    const aMem = rdPtr(v, Vdbe_aMem).?;
    const aMem1: *anyopaque = @ptrCast(@as([*]u8, @ptrCast(aMem)) + sizeof_Mem);
    sqlite3VdbeMemSetInt64(aMem1, iRow);

    // If the statement has run before (paused at OP_ResultRow), back the program
    // counter up to the OP_NotExists instead of re-stepping from the top.
    if (rdInt(v, Vdbe_pc) > 4) {
        wrInt(v, Vdbe_pc, 4);
        // assert aOp[4].opcode==OP_NotExists
        rc = sqlite3VdbeExec(v);
    } else {
        rc = sqlite3_step(p.pStmt);
    }

    if (rc == SQLITE_ROW) {
        // pC = v->apCsr[0]
        const apCsr = rdPtr(v, Vdbe_apCsr).?;
        const pC = rdPtr(apCsr, 0).?; // apCsr[0]
        // type = pC->nHdrParsed>p->iCol ? pC->aType[p->iCol] : 0
        const nHdrParsed: u16 = rdU16(pC, VdbeCursor_nHdrParsed);
        const aType: [*]u32 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pC)) + VdbeCursor_aType));
        const ty: u32 = if (nHdrParsed > p.iCol) aType[p.iCol] else 0;
        if (ty < 12) {
            zErr = sqlite3MPrintf(p.db, "cannot open value of type %s", typeName(ty));
            rc = SQLITE_ERROR;
            _ = sqlite3_finalize(p.pStmt);
            p.pStmt = null;
        } else {
            // p->iOffset = pC->aType[p->iCol + pC->nField]
            const nField: i16 = rdI16(pC, VdbeCursor_nField);
            const idx: usize = @as(usize, p.iCol) + @as(usize, @intCast(nField));
            p.iOffset = @bitCast(aType[idx]);
            p.nByte = @bitCast(sqlite3VdbeSerialTypeLen(ty));
            // p->pCsr = pC->uc.pCursor
            p.pCsr = rdPtr(pC, VdbeCursor_uc);
            sqlite3BtreeIncrblobCursor(p.pCsr);
        }
    }

    if (rc == SQLITE_ROW) {
        rc = SQLITE_OK;
    } else if (p.pStmt != null) {
        rc = sqlite3_finalize(p.pStmt);
        p.pStmt = null;
        if (rc == SQLITE_OK) {
            zErr = sqlite3MPrintf(p.db, "no such rowid: %lld", iRow);
            rc = SQLITE_ERROR;
        } else {
            zErr = sqlite3MPrintf(p.db, "%s", sqlite3_errmsg(p.db));
        }
    }

    pzErr.* = zErr;
    return rc;
}

// helper for the "%s" type name in the cannot-open-value message.
inline fn typeName(ty: u32) [*:0]const u8 {
    return if (ty == 0) "null" else if (ty == 7) "real" else "integer";
}

// ===========================================================================
// sqlite3_blob_open — open a blob handle.
// ===========================================================================
export fn sqlite3_blob_open(
    db: ?*sqlite3,
    zDb: ?[*:0]const u8,
    zTable: [*:0]const u8,
    zColumn: [*:0]const u8,
    iRow: i64,
    wrFlagIn: c_int,
    ppBlob: *?*sqlite3_blob,
) callconv(.c) c_int {
    var nAttempt: c_int = 0;
    var iCol: c_int = undefined;
    var rc: c_int = SQLITE_OK;
    var zErr: ?[*:0]u8 = null;
    var pTab: ?*Table = undefined;
    var pBlob: ?*Incrblob = null;
    var iDb: c_int = 0;

    // sParse: a Parse object handed to the C helpers. We never interpret most of
    // it; size it from c_layout and only poke the four fields C writes/reads.
    var sParseBuf: [sizeof_Parse]u8 align(8) = undefined;
    const sParse: *Parse = @ptrCast(&sParseBuf);

    ppBlob.* = null;

    const wrFlag: c_int = @intFromBool(wrFlagIn != 0); // wrFlag = !!wrFlag

    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));

    pBlob = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @sizeOf(Incrblob))));
    while (true) {
        sqlite3ParseObjectInit(sParse, db);
        if (pBlob == null) break; // goto blob_open_out
        sqlite3DbFree(db, zErr);
        zErr = null;

        sqlite3BtreeEnterAll(db);
        pTab = sqlite3LocateTable(sParse, 0, zTable, zDb);
        if (pTab != null and isVirtual(pTab.?)) {
            pTab = null;
            sqlite3ErrorMsg(sParse, "cannot open virtual table: %s", zTable);
        }
        if (pTab != null and !hasRowid(pTab.?)) {
            pTab = null;
            sqlite3ErrorMsg(sParse, "cannot open table without rowid: %s", zTable);
        }
        if (pTab != null and (rdU32(pTab, Table_tabFlags) & TF_HasGenerated) != 0) {
            pTab = null;
            sqlite3ErrorMsg(sParse, "cannot open table with generated columns: %s", zTable);
        }
        // SQLITE_OMIT_VIEW is OFF.
        if (pTab != null and isView(pTab.?)) {
            pTab = null;
            sqlite3ErrorMsg(sParse, "cannot open view: %s", zTable);
        }

        var noTable = (pTab == null);
        if (!noTable) {
            iDb = sqlite3SchemaToIndex(db, rdPtr(pTab, Table_pSchema));
            if (iDb == 1 and sqlite3OpenTempDatabase(sParse) != 0) {
                noTable = true;
            }
        }
        if (noTable) {
            const zErrMsg = rdPtr(sParse, Parse_zErrMsg);
            if (zErrMsg != null) {
                sqlite3DbFree(db, zErr);
                zErr = @ptrCast(zErrMsg);
                wrPtr(sParse, Parse_zErrMsg, null);
            }
            rc = SQLITE_ERROR;
            sqlite3BtreeLeaveAll(db);
            break; // goto blob_open_out
        }
        pBlob.?.pTab = pTab;
        // pBlob->zDb = db->aDb[iDb].zDbSName
        pBlob.?.zDb = @ptrCast(rdPtr(dbEnt(db, iDb), Db_zDbSName));

        // Search pTab for the exact column.
        iCol = sqlite3ColumnIndex(pTab, zColumn);
        if (iCol < 0) {
            sqlite3DbFree(db, zErr);
            zErr = sqlite3MPrintf(db, "no such column: \"%s\"", zColumn);
            rc = SQLITE_ERROR;
            sqlite3BtreeLeaveAll(db);
            break;
        }

        // If opening for writing, the column must not be indexed or part of an FK.
        if (wrFlag != 0) {
            var zFault: ?[*:0]const u8 = null;
            // SQLITE_OMIT_FOREIGN_KEY is OFF.
            if ((rdU64(db, sqlite3_flags) & SQLITE_ForeignKeys) != 0) {
                // pTab is ordinary here; walk its child FKeys.
                var pFKey = rdPtr(pTab, Table_u_tab_pFKey);
                while (pFKey != null) : (pFKey = rdPtr(pFKey, FKey_pNextFrom)) {
                    const nFkCol = rdInt(pFKey, FKey_nCol);
                    const aCol: [*]u8 = @ptrCast(@as([*]u8, @ptrCast(pFKey.?)) + FKey_aCol);
                    var j: c_int = 0;
                    while (j < nFkCol) : (j += 1) {
                        // aCol[j].iFrom (int) at the start of each sColMap entry.
                        const iFrom = rdInt(aCol + @as(usize, @intCast(j)) * sizeof_FKeyCol, 0);
                        if (iFrom == iCol) zFault = "foreign key";
                    }
                }
            }
            var pIdx = rdPtr(pTab, Table_pIndex);
            while (pIdx != null) : (pIdx = rdPtr(pIdx, Index_pNext)) {
                const nKeyCol: u16 = rdU16(pIdx, Index_nKeyCol);
                const aiColumn: [*]i16 = @ptrCast(@alignCast(rdPtr(pIdx, Index_aiColumn).?));
                var j: usize = 0;
                while (j < nKeyCol) : (j += 1) {
                    const col = aiColumn[j];
                    if (col == @as(i16, @truncate(iCol)) or col == XN_EXPR) zFault = "indexed";
                }
            }
            if (zFault != null) {
                sqlite3DbFree(db, zErr);
                zErr = sqlite3MPrintf(db, "cannot open %s column for writing", zFault.?);
                rc = SQLITE_ERROR;
                sqlite3BtreeLeaveAll(db);
                break;
            }
        }

        pBlob.?.pStmt = @ptrCast(sqlite3VdbeCreate(sParse));
        if (pBlob.?.pStmt != null) {
            const v = pBlob.?.pStmt; // (Vdbe*)
            const pSchema = rdPtr(pTab, Table_pSchema);

            // OP_Transaction with the schema cookie/generation, then the openBlob
            // program. iLn (VDBE_OFFSET_LINENO) is 0 in both configs.
            _ = sqlite3VdbeAddOp4Int(
                v,
                OP_Transaction,
                iDb,
                wrFlag,
                @bitCast(rdU32(pSchema, Schema_schema_cookie)),
                @bitCast(rdU32(pSchema, Schema_iGeneration)),
            );
            sqlite3VdbeChangeP5(v, 1);
            // assert currentAddr==2
            const aOpAny = sqlite3VdbeAddOpList(v, openBlob.len, &openBlob, 0);

            sqlite3VdbeUsesBtree(v, iDb);

            if (rdU8(db, sqlite3_mallocFailed) == 0) {
                const aOp = aOpAny.?; // Op* base of the appended ops
                // Configure OP_TableLock (SQLITE_OMIT_SHARED_CACHE is OFF).
                wrInt(opAt(aOp, 0), Op_p1, iDb);
                wrInt(opAt(aOp, 0), Op_p2, @bitCast(rdU32(pTab, Table_tnum)));
                wrInt(opAt(aOp, 0), Op_p3, wrFlag);
                sqlite3VdbeChangeP4(v, 2, @ptrCast(rdPtr(pTab, Table_zName)), P4_TRANSIENT);

                if (rdU8(db, sqlite3_mallocFailed) == 0) {
                    // Pick OpenWrite/OpenRead; set P2=tnum, P3=iDb on aOp[1].
                    if (wrFlag != 0) wrU8(opAt(aOp, 1), Op_opcode, OP_OpenWrite);
                    wrInt(opAt(aOp, 1), Op_p2, @bitCast(rdU32(pTab, Table_tnum)));
                    wrInt(opAt(aOp, 1), Op_p3, iDb);

                    // Pretend the table has one extra column (always NULL); this
                    // lets OP_Column populate the cursor type/offset cache w/o IO.
                    const nCol: c_int = rdI16(pTab, Table_nCol);
                    wrU8(opAt(aOp, 1), Op_p4type, @bitCast(P4_INT32));
                    wrInt(opAt(aOp, 1), Op_p4, nCol + 1); // p4.i
                    wrInt(opAt(aOp, 3), Op_p2, nCol);

                    wrInt(sParse, Parse_nVar, 0);
                    wrInt(sParse, Parse_nMem, 1);
                    wrInt(sParse, Parse_nTab, 1);
                    sqlite3VdbeMakeReady(v, sParse);
                }
            }
        }

        pBlob.?.iCol = @truncate(@as(c_uint, @bitCast(iCol)));
        pBlob.?.db = db;
        sqlite3BtreeLeaveAll(db);
        if (rdU8(db, sqlite3_mallocFailed) != 0) break;
        rc = blobSeekToRow(pBlob.?, iRow, &zErr);
        nAttempt += 1;
        if (nAttempt >= SQLITE_MAX_SCHEMA_RETRY or rc != SQLITE_SCHEMA) break;
        sqlite3ParseObjectReset(sParse);
    }

    // blob_open_out:
    if (rc == SQLITE_OK and rdU8(db, sqlite3_mallocFailed) == 0) {
        ppBlob.* = @ptrCast(pBlob);
    } else {
        if (pBlob != null and pBlob.?.pStmt != null) {
            _ = sqlite3VdbeFinalize(pBlob.?.pStmt);
        }
        sqlite3DbFree(db, pBlob);
    }
    sqlite3ErrorWithMsg(db, rc, if (zErr != null) "%s" else null, zErr);
    sqlite3DbFree(db, zErr);
    sqlite3ParseObjectReset(sParse);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return rc;
}

// The VDBE program that seeks a btree cursor to the db/table/row entry.
//   0: OP_TableLock   acquire a read/write lock
//   1: OP_OpenRead    open a cursor (becomes OpenWrite for wrFlag)
//   2: OP_NotExists   seek cursor to rowid=r[1]   (blobSeekToRow sets r[1])
//   3: OP_Column
//   4: OP_ResultRow
//   5: OP_Halt
const openBlob = [_]VdbeOpList{
    .{ .opcode = OP_TableLock, .p1 = 0, .p2 = 0, .p3 = 0 },
    .{ .opcode = OP_OpenRead, .p1 = 0, .p2 = 0, .p3 = 0 },
    .{ .opcode = OP_NotExists, .p1 = 0, .p2 = 5, .p3 = 1 },
    .{ .opcode = OP_Column, .p1 = 0, .p2 = 0, .p3 = 1 },
    .{ .opcode = OP_ResultRow, .p1 = 1, .p2 = 0, .p3 = 0 },
    .{ .opcode = OP_Halt, .p1 = 0, .p2 = 0, .p3 = 0 },
};

// opAt(base, i): Op* pointer to the i-th opcode (stride sizeof_Op).
inline fn opAt(base: ?*anyopaque, i: usize) ?*anyopaque {
    return @as([*]u8, @ptrCast(base.?)) + i * sizeof_Op;
}

// db->aDb[iDb] entry pointer.
inline fn dbEnt(db: ?*sqlite3, iDb: c_int) ?*anyopaque {
    const aDb = rdPtr(db, sqlite3_aDb).?;
    return @as([*]u8, @ptrCast(aDb)) + @as(usize, @intCast(iDb)) * sizeof_Db;
}

// --- Table flag/type predicates (the C macros) ---
inline fn isVirtual(pTab: *Table) bool {
    return rdU8(pTab, Table_eTabType) == TABTYP_VTAB;
}
inline fn isView(pTab: *Table) bool {
    return rdU8(pTab, Table_eTabType) == TABTYP_VIEW;
}
inline fn hasRowid(pTab: *Table) bool {
    return (rdU32(pTab, Table_tabFlags) & TF_WithoutRowid) == 0;
}

// ===========================================================================
// sqlite3_blob_close
// ===========================================================================
export fn sqlite3_blob_close(pBlob: ?*sqlite3_blob) callconv(.c) c_int {
    const p: ?*Incrblob = @ptrCast(@alignCast(pBlob));
    var rc: c_int = undefined;
    if (p) |blob| {
        const pStmt = blob.pStmt;
        const db = blob.db;
        sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
        sqlite3DbFree(db, blob);
        sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
        rc = sqlite3_finalize(pStmt);
    } else {
        rc = SQLITE_OK;
    }
    return rc;
}

// ===========================================================================
// blobReadWrite — perform a read or write on a blob handle.
// ===========================================================================
fn blobReadWrite(
    pBlob: ?*sqlite3_blob,
    z: ?*anyopaque,
    n: c_int,
    iOffset: c_int,
    xCall: XCallFn,
) c_int {
    var rc: c_int = SQLITE_OK;
    const p: ?*Incrblob = @ptrCast(@alignCast(pBlob));
    if (p == null) return SQLITE_MISUSE;
    const blob = p.?;
    const db = blob.db;
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
    const v = blob.pStmt; // (Vdbe*)

    if (n < 0 or iOffset < 0 or (@as(i64, iOffset) + @as(i64, n)) > @as(i64, blob.nByte)) {
        // Request out of range — return a transient error.
        rc = SQLITE_ERROR;
    } else if (v == null) {
        // Handle already invalidated.
        rc = SQLITE_ABORT;
    } else {
        sqlite3BtreeEnterCursor(blob.pCsr);

        // SQLITE_ENABLE_PREUPDATE_HOOK is ON in both configs.
        if (@intFromPtr(xCall) == @intFromPtr(&sqlite3BtreePutData) and
            rdPtr(db, sqlite3_xPreUpdateCallback) != null)
        {
            if (sqlite3BtreeCursorIsValidNN(blob.pCsr) == 0) {
                // Cursor not valid — try to reseek (always fails or finds the row).
                var bDiff: c_int = 0;
                rc = sqlite3BtreeCursorRestore(blob.pCsr, &bDiff);
            }
            if (sqlite3BtreeCursorIsValidNN(blob.pCsr) != 0) {
                const iKey = sqlite3BtreeIntegerKey(blob.pCsr);
                const apCsr = rdPtr(v, Vdbe_apCsr).?;
                const csr0 = rdPtr(apCsr, 0);
                sqlite3VdbePreUpdateHook(
                    v,
                    csr0,
                    SQLITE_DELETE,
                    @ptrCast(blob.zDb),
                    blob.pTab,
                    iKey,
                    -1,
                    blob.iCol,
                );
            }
        }
        if (rc == SQLITE_OK) {
            rc = xCall(blob.pCsr, @bitCast(iOffset + blob.iOffset), @bitCast(n), z);
        }

        sqlite3BtreeLeaveCursor(blob.pCsr);
        if (rc == SQLITE_ABORT) {
            _ = sqlite3VdbeFinalize(v);
            blob.pStmt = null;
        } else {
            wrInt(v, Vdbe_rc, rc);
        }
    }
    sqlite3Error(db, rc);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return rc;
}

// ===========================================================================
// sqlite3_blob_read / _write
// ===========================================================================
export fn sqlite3_blob_read(pBlob: ?*sqlite3_blob, z: ?*anyopaque, n: c_int, iOffset: c_int) callconv(.c) c_int {
    return blobReadWrite(pBlob, z, n, iOffset, &sqlite3BtreePayloadChecked);
}

export fn sqlite3_blob_write(pBlob: ?*sqlite3_blob, z: ?*const anyopaque, n: c_int, iOffset: c_int) callconv(.c) c_int {
    return blobReadWrite(pBlob, @constCast(z), n, iOffset, &sqlite3BtreePutData);
}

// ===========================================================================
// sqlite3_blob_bytes — Incrblob.nByte is fixed for the lifetime, no mutex.
// ===========================================================================
export fn sqlite3_blob_bytes(pBlob: ?*sqlite3_blob) callconv(.c) c_int {
    const p: ?*Incrblob = @ptrCast(@alignCast(pBlob));
    if (p) |blob| {
        return if (blob.pStmt != null) blob.nByte else 0;
    }
    return 0;
}

// ===========================================================================
// sqlite3_blob_reopen — move the handle to a different row of the same table.
// ===========================================================================
export fn sqlite3_blob_reopen(pBlob: ?*sqlite3_blob, iRow: i64) callconv(.c) c_int {
    var rc: c_int = undefined;
    const p: ?*Incrblob = @ptrCast(@alignCast(pBlob));
    if (p == null) return SQLITE_MISUSE;
    const blob = p.?;
    const db = blob.db;
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));

    if (blob.pStmt == null) {
        // Handle already invalidated.
        rc = SQLITE_ABORT;
    } else {
        var zErr: ?[*:0]u8 = undefined;
        // ((Vdbe*)p->pStmt)->rc = SQLITE_OK;
        wrInt(blob.pStmt, Vdbe_rc, SQLITE_OK);
        rc = blobSeekToRow(blob, iRow, &zErr);
        if (rc != SQLITE_OK) {
            sqlite3ErrorWithMsg(db, rc, if (zErr != null) "%s" else null, zErr);
            sqlite3DbFree(db, zErr);
        }
        // assert rc != SQLITE_SCHEMA
    }

    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return rc;
}

// Reference the union members so the compiler keeps eCurType/CURTYPE constants
// from being flagged unused (they document the asserted invariant).
comptime {
    std.debug.assert(VdbeCursor_eCurType == 0);
    std.debug.assert(CURTYPE_BTREE == 0);
    std.debug.assert(TABTYP_NORM == 0);
    std.debug.assert(OP_Noop != 0);
    std.debug.assert(Op_p4 != 0);
}
