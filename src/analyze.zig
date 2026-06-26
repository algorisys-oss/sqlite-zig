//! Zig port of SQLite's src/analyze.c — the ANALYZE command.
//!
//! ANALYZE gathers statistics about table/index content into the
//! sqlite_stat1 system table, and on schema load those stats are read back
//! into the in-memory Index/Table structures to guide the query planner.
//!
//! This is a CODEGEN + runtime module:
//!   - sqlite3Analyze emits VDBE bytecode that scans every index, counting
//!     distinct-prefix cardinalities via the internal stat_init/stat_push/
//!     stat_get SQL functions (defined here), and INSERTs the result rows
//!     into sqlite_stat1.
//!   - sqlite3AnalysisLoad runs `SELECT tbl,idx,stat FROM sqlite_stat1` and
//!     decodes the integer lists into Index.aiRowLogEst / Table.nRowLogEst.
//!
//! ─── BUILD CONFIG: SQLITE_ENABLE_STAT4 is OFF ──────────────────────────────
//! Neither the production library nor the --dev testfixture enables STAT4 (the
//! configure --dev / --all path does NOT set it; verified against the linked
//! testfixture's `pragma compile_options`). So the entire `#ifdef
//! SQLITE_ENABLE_STAT4` machinery (StatSample.anEq/anLt/u/iHash, the aBest[]/a[]
//! sample arrays, sampleInsert/sampleCopy/samplePushPrevious, the sqlite_stat4
//! table, IndexSample loading, initAvgEq, loadStat4) is excluded — exactly as
//! the C preprocessor excludes it. IsStat4 == 0, SQLITE_STAT4_SAMPLES == 1.
//!
//! The sqlite3Stat4* symbols (Stat4ProbeSetValue/Stat4Column/etc.) live in
//! vdbemem.c, not analyze.c, so they are not this module's concern.
//!
//! Exported (non-static) symbols — the complete external set of analyze.c with
//! SQLITE_OMIT_ANALYZE OFF, SQLITE_ENABLE_STAT4 OFF:
//!   - sqlite3Analyze
//!   - sqlite3DeleteIndexSamples   (a no-op when STAT4 is off)
//!   - sqlite3AnalysisLoad
//! Static helpers (openStatTable, statInit/statPush/statGet, callStatGet,
//! analyzeOneTable, analyzeDatabase, analyzeTable, loadAnalysis, decodeIntArray,
//! analysisLoader) become private Zig fns.
//!
//! ─── Other config assumptions (true in both build configs) ─────────────────
//!   * SQLITE_OMIT_AUTHORIZATION OFF (auth check compiled).
//!   * SQLITE_ENABLE_PREUPDATE_HOOK ON — but db->xPreUpdateCallback is checked
//!     at runtime; when null (the common case) the preupdate Noop/pStat1 path is
//!     skipped. We reproduce it for byte-identical bytecode when a hook is set.
//!   * SQLITE_ENABLE_EXPLAIN_COMMENTS ON → VdbeComment is a real call.
//!   * SQLITE_ENABLE_COSTMULT / SQLITE_OMIT_VIEW / OMIT_VIRTUALTABLE OFF/handled.
//!   * isCreate/ifNotExists are SQLITE_DEBUG-only and only referenced in an
//!     assert() in C → not touched here. u1.cr.regRoot is config-invariant (240).
//!   * Little-endian x86-64.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers ──────────────────────────────────────────────────────
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, offs: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + offs);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, offs: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + offs);
    q.* = v;
}
fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

// ─── ground-truth offsets (all config-invariant: STAT4 off, fields precede
//     the SQLITE_DEBUG-divergent tails) ────────────────────────────────────
// Parse
const Parse_db_off = off("Parse_db", 0);
const Parse_pVdbe_off = off("Parse_pVdbe", 16);
const Parse_nErr_off = off("Parse_nErr", 52);
const Parse_nTab_off = off("Parse_nTab", 56);
const Parse_nMem_off = off("Parse_nMem", 60);
const Parse_u1_cr_regRoot_off = off("Parse_u1_cr_regRoot", 240);
// sqlite3
const sqlite3_aDb_off = off("sqlite3_aDb", 32);
const sqlite3_nDb_off = off("sqlite3_nDb", 40);
const sqlite3_nSqlExec_off = off("sqlite3_nSqlExec", 112);
const sqlite3_nAnalysisLimit_off = off("sqlite3_nAnalysisLimit", 760);
const sqlite3_dbOptFlags_off = off("sqlite3_dbOptFlags", 96);
const sqlite3_xPreUpdateCallback_off = off("sqlite3_xPreUpdateCallback", 360);
// Db
const Db_zDbSName_off = off("Db_zDbSName", 0);
const Db_pSchema_off = off("Db_pSchema", 24);
const sizeof_Db = off("sizeof_Db", 32);
// Schema
const Schema_tblHash_off = off("Schema_tblHash", 8);
const Schema_idxHash_off = off("Schema_idxHash", 32);
// Hash / HashElem
const Hash_first_off = off("Hash_first", 8);
const HashElem_next_off = off("HashElem_next", 0);
const HashElem_data_off = off("HashElem_data", 16);
// Table
const Table_zName_off = off("Table_zName", 0);
const Table_pIndex_off = off("Table_pIndex", 16);
const Table_tnum_off = off("Table_tnum", 40);
const Table_tabFlags_off = off("Table_tabFlags", 48);
const Table_nRowLogEst_off = off("Table_nRowLogEst", 58);
const Table_szTabRow_off = off("Table_szTabRow", 60);
const Table_pSchema_off = off("Table_pSchema", 96);
const Table_eTabType_off = off("Table_eTabType", 63);
const Table_nCol_off = off("Table_nCol", 54);
const Table_iPKey_off = off("Table_iPKey", 52);
const sizeof_Table = off("sizeof_Table", 120);
// Index
const Index_aiColumn_off = off("Index_aiColumn", 8);
const Index_aiRowLogEst_off = off("Index_aiRowLogEst", 16);
const Index_pTable_off = off("Index_pTable", 24);
const Index_pNext_off = off("Index_pNext", 40);
const Index_pSchema_off = off("Index_pSchema", 48);
const Index_azColl_off = off("Index_azColl", 64);
const Index_pPartIdxWhere_off = off("Index_pPartIdxWhere", 72);
const Index_tnum_off = off("Index_tnum", 88);
const Index_szIdxRow_off = off("Index_szIdxRow", 92);
const Index_nKeyCol_off = off("Index_nKeyCol", 94);
const Index_nColumn_off = off("Index_nColumn", 96);
const Index_onError_off = off("Index_onError", 98);
const Index_zName_off = off("Index_zName", 0);
const sizeof_Index = off("sizeof_Index", 112);
// Index bitfield byte (= onError+1 = 99):
//   bit0,1 idxType:2 ; bit2 bUnordered ; bit3 uniqNotNull ; bit4 isResized ;
//   bit5 isCovering ; bit6 noSkipScan ; bit7 hasStat1
const Index_bit_byte = Index_onError_off + 1;
const IDXBIT_bUnordered: u8 = 0x04;
const IDXBIT_uniqNotNull: u8 = 0x08;
const IDXBIT_noSkipScan: u8 = 0x40;
const IDXBIT_hasStat1: u8 = 0x80;
// Token
const Token_n_off = off("Token_n", 8);

// ─── constants ──────────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_XFER: c_int = 1;
const SQLITE_UTF8: u32 = 1;

const TF_WithoutRowid: u32 = 0x0080;
const TF_HasStat1: u32 = off("TF_HasStat1", 16);

const SQLITE_IDXTYPE_PRIMARYKEY: u8 = 2;

const SQLITE_Stat4: u32 = 0x0800;
const SQLITE_NULLEQ: u16 = 0x80;
const OPFLAG_P2ISREG: u16 = 0x10;
const OPFLAG_APPEND: u16 = 0x08;

const P4_DYNAMIC: c_int = -7;
const P4_TABLE: c_int = -5;
const P4_COLLSEQ: c_int = -2;

const SQLITE_ANALYZE: c_int = 28;

// opcodes (opcodes.h is generated identically in both configs)
const OP_Integer: c_int = 73;
const OP_Count: c_int = 100;
const OP_Rewind: c_int = 36;
const OP_Goto: c_int = 9;
const OP_Ne: c_int = 53;
const OP_Column: c_int = 96;
const OP_Next: c_int = 40;
const OP_IsNull: c_int = 51;
const OP_If: c_int = 16;
const OP_IfNot: c_int = 17;
const OP_SeekGT: c_int = 24;
const OP_MakeRecord: c_int = 99;
const OP_NewRowid: c_int = 129;
const OP_Insert: c_int = 130;
const OP_Null: c_int = 77;
const OP_Clear: c_int = 147;
const OP_OpenWrite: c_int = 116;
const OP_OpenRead: c_int = 114;
const OP_NotNull: c_int = 52;
const OP_Noop: c_int = 189;
const OP_LoadAnalysis: c_int = off("OP_LoadAnalysis", 152);
const OP_Expire: c_int = off("OP_Expire", 168);

// ─── extern C-ABI helpers (resolved at link time) ───────────────────────────
const Parse = anyopaque;
const Vdbe = anyopaque;
const Sqlite3 = anyopaque;
const Table = anyopaque;
const Index = anyopaque;
const Token = anyopaque;
const Ctx = anyopaque; // sqlite3_context*
const Val = anyopaque; // sqlite3_value*

extern fn sqlite3GetVdbe(p: ?*Parse) ?*Vdbe;
extern fn sqlite3VdbeAddOp0(v: ?*Vdbe, op: c_int) c_int;
extern fn sqlite3VdbeAddOp1(v: ?*Vdbe, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeAddFunctionCall(p: ?*Parse, p1: c_int, p2: c_int, p3: c_int, nArg: c_int, pFunc: *const FuncDef, eCallCtx: c_int) c_int;
extern fn sqlite3VdbeChangeP5(v: ?*Vdbe, p5: u16) void;
extern fn sqlite3VdbeChangeP4(v: ?*Vdbe, addr: c_int, zP4: ?[*]const u8, n: c_int) void;
extern fn sqlite3VdbeJumpHere(v: ?*Vdbe, addr: c_int) void;
extern fn sqlite3VdbeGoto(v: ?*Vdbe, addr: c_int) c_int;
extern fn sqlite3VdbeMakeLabel(p: ?*Parse) c_int;
extern fn sqlite3VdbeResolveLabel(v: ?*Vdbe, x: c_int) void;
extern fn sqlite3VdbeCurrentAddr(v: ?*Vdbe) c_int;
extern fn sqlite3VdbeLoadString(v: ?*Vdbe, iReg: c_int, z: ?[*:0]const u8) c_int;
extern fn sqlite3VdbeSetP4KeyInfo(p: ?*Parse, pIdx: ?*Index) void;
// EXPLAIN_COMMENTS ON in both configs → real variadic symbol.
extern fn sqlite3VdbeComment(v: ?*Vdbe, fmt: [*:0]const u8, ...) void;

extern fn sqlite3NestedParse(p: ?*Parse, fmt: [*:0]const u8, ...) void;
extern fn sqlite3OpenTable(p: ?*Parse, iCur: c_int, iDb: c_int, pTab: ?*Table, opcode: c_int) void;
extern fn sqlite3TableLock(p: ?*Parse, iDb: c_int, tnum: u32, isWriteLock: u8, zName: ?[*:0]const u8) void;
extern fn sqlite3FindTable(db: ?*Sqlite3, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) ?*Table;
extern fn sqlite3FindIndex(db: ?*Sqlite3, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) ?*Index;
extern fn sqlite3FindDb(db: ?*Sqlite3, p: ?*Token) c_int;
extern fn sqlite3SchemaToIndex(db: ?*Sqlite3, pSchema: ?*anyopaque) c_int;
extern fn sqlite3BeginWriteOperation(p: ?*Parse, setStatement: c_int, iDb: c_int) void;
extern fn sqlite3TwoPartName(p: ?*Parse, p1: ?*Token, p2: ?*Token, ppTab: *?*Token) c_int;
extern fn sqlite3NameFromToken(db: ?*Sqlite3, p: ?*Token) ?[*:0]u8;
extern fn sqlite3LocateTable(p: ?*Parse, flags: u32, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) ?*Table;
extern fn sqlite3DbFree(db: ?*Sqlite3, p: ?*anyopaque) void;
extern fn sqlite3ReadSchema(p: ?*Parse) c_int;
extern fn sqlite3LocateCollSeq(p: ?*Parse, zName: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3TouchRegister(p: ?*Parse, n: c_int) void;
extern fn sqlite3PrimaryKeyIndex(pTab: ?*Table) ?*Index;
extern fn sqlite3DbMallocRawNN(db: ?*Sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocZero(db: ?*Sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DefaultRowEst(pIdx: ?*Index) void;
extern fn sqlite3LogEst(x: u64) i16;
extern fn sqlite3OomFault(db: ?*Sqlite3) ?*anyopaque;
extern fn sqlite3MPrintf(db: ?*Sqlite3, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_exec(db: ?*Sqlite3, sql: ?[*:0]const u8, cb: ?*const fn (?*anyopaque, c_int, ?[*]?[*:0]u8, ?[*]?[*:0]u8) callconv(.c) c_int, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3Atoi(z: ?[*:0]const u8) c_int;
extern fn sqlite3_strlike(zGlob: ?[*:0]const u8, zStr: ?[*:0]const u8, esc: c_uint) c_int;
extern fn sqlite3_strglob(zGlob: ?[*:0]const u8, zStr: ?[*:0]const u8) c_int;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3AuthCheck(p: ?*Parse, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;

// stat function plumbing
extern fn sqlite3_value_int(v: ?*Val) c_int;
extern fn sqlite3_value_int64(v: ?*Val) i64;
extern fn sqlite3_value_blob(v: ?*Val) ?*anyopaque;
extern fn sqlite3_context_db_handle(ctx: ?*Ctx) ?*Sqlite3;
extern fn sqlite3_result_blob(ctx: ?*Ctx, z: ?*const anyopaque, n: c_int, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3_result_error_nomem(ctx: ?*Ctx) void;
extern fn sqlite3_result_int(ctx: ?*Ctx, n: c_int) void;
extern fn sqlite3_result_str(ctx: ?*Ctx, p: ?*anyopaque, eDestructor: c_int) void;
extern fn sqlite3StrAccumInit(p: *StrAccum, db: ?*Sqlite3, zBase: ?[*]u8, n: c_int, mx: c_int) void;
extern fn sqlite3_str_appendf(p: *StrAccum, fmt: [*:0]const u8, ...) void;

// ─── struct mirrors ─────────────────────────────────────────────────────────

// FuncDef (ABI; sizeof 72) — must match func.zig / date.zig exactly.
const FuncDef = extern struct {
    nArg: i16, // 0
    funcFlags: u32, // 4
    pUserData: ?*anyopaque, // 8
    pNext: ?*FuncDef, // 16
    xSFunc: ?*const anyopaque, // 24
    xFinalize: ?*const anyopaque, // 32
    xValue: ?*const anyopaque, // 40
    xInverse: ?*const anyopaque, // 48
    zName: ?[*:0]const u8, // 56
    u: extern union { pHash: ?*FuncDef, pDestructor: ?*anyopaque }, // 64
};
comptime {
    std.debug.assert(@sizeOf(FuncDef) == 72);
    std.debug.assert(@offsetOf(FuncDef, "funcFlags") == 4);
    std.debug.assert(@offsetOf(FuncDef, "zName") == 56);
    std.debug.assert(@offsetOf(FuncDef, "u") == 64);
}

// StrAccum (sqlite3_str) — config-invariant, sizeof 32.
const StrAccum = extern struct {
    db: ?*Sqlite3, // 0
    zText: ?[*]u8, // 8
    nAlloc: u32, // 16
    mxAlloc: u32, // 20
    nChar: u32, // 24
    accError: u8, // 28
    printfFlags: u8, // 29
};
comptime {
    std.debug.assert(@sizeOf(StrAccum) == 32);
    std.debug.assert(@offsetOf(StrAccum, "zText") == 8);
    std.debug.assert(@offsetOf(StrAccum, "nChar") == 24);
}

// StatAccum (analyze.c-internal; non-STAT4 layout, sizeof 48).
// StatSample is only { tRowcnt *anDLt; } when STAT4 is off, so we inline it.
const StatAccum = extern struct {
    db: ?*Sqlite3, // 0
    nEst: u64, // 8   (tRowcnt)
    nRow: u64, // 16  (tRowcnt)
    nLimit: c_int, // 24
    nCol: c_int, // 28
    nKeyCol: c_int, // 32
    nSkipAhead: u8, // 36
    // current.anDLt at offset 40
    current_anDLt: ?[*]u64, // 40
};
comptime {
    std.debug.assert(@sizeOf(StatAccum) == 48);
    std.debug.assert(@offsetOf(StatAccum, "current_anDLt") == 40);
    std.debug.assert(@offsetOf(StatAccum, "nSkipAhead") == 36);
}

// ─── tiny field accessors ───────────────────────────────────────────────────
inline fn parseDb(p: ?*Parse) ?*Sqlite3 {
    return rd(?*Sqlite3, p, Parse_db_off);
}
inline fn parseNTab(p: ?*Parse) c_int {
    return rd(c_int, p, Parse_nTab_off);
}
inline fn parseSetNTab(p: ?*Parse, v: c_int) void {
    wr(c_int, p, Parse_nTab_off, v);
}
inline fn parseNMem(p: ?*Parse) c_int {
    return rd(c_int, p, Parse_nMem_off);
}
inline fn parseRegRoot(p: ?*Parse) c_int {
    return rd(c_int, p, Parse_u1_cr_regRoot_off);
}

inline fn dbNDb(db: ?*Sqlite3) c_int {
    return rd(c_int, db, sqlite3_nDb_off);
}
inline fn dbNSqlExec(db: ?*Sqlite3) u8 {
    // nSqlExec is a u8, NOT an int — reading 4 bytes would pick up the
    // adjacent eOpenState/nFpDigit fields and wrongly suppress OP_Expire.
    return rd(u8, db, sqlite3_nSqlExec_off);
}
inline fn dbNAnalysisLimit(db: ?*Sqlite3) c_int {
    return rd(c_int, db, sqlite3_nAnalysisLimit_off);
}
inline fn dbOptFlags(db: ?*Sqlite3) u32 {
    return rd(u32, db, sqlite3_dbOptFlags_off);
}
inline fn optDisabled(db: ?*Sqlite3, mask: u32) bool {
    return (dbOptFlags(db) & mask) != 0;
}
inline fn dbXPreUpdate(db: ?*Sqlite3) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_xPreUpdateCallback_off);
}
inline fn dbAt(db: ?*Sqlite3, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, db, sqlite3_aDb_off).?);
    return @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Db);
}
inline fn dbZDbSName(dbEntry: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, dbEntry, Db_zDbSName_off);
}
inline fn dbPSchema(dbEntry: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, dbEntry, Db_pSchema_off);
}

// Hash iteration (sqliteHashFirst/Next/Data macros)
inline fn hashFirst(pHash: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pHash, Hash_first_off);
}
inline fn hashNext(elem: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, elem, HashElem_next_off);
}
inline fn hashData(elem: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, elem, HashElem_data_off);
}

inline fn tabZName(p: ?*Table) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Table_zName_off);
}
inline fn tabPIndex(p: ?*Table) ?*Index {
    return rd(?*Index, p, Table_pIndex_off);
}
inline fn tabTnum(p: ?*Table) u32 {
    return rd(u32, p, Table_tnum_off);
}
inline fn tabPSchema(p: ?*Table) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pSchema_off);
}
inline fn tabTabFlags(p: ?*Table) u32 {
    return rd(u32, p, Table_tabFlags_off);
}
inline fn tabSetTabFlags(p: ?*Table, v: u32) void {
    wr(u32, p, Table_tabFlags_off, v);
}
inline fn tabHasRowid(p: ?*Table) bool {
    return (tabTabFlags(p) & TF_WithoutRowid) == 0;
}
inline fn tabIsOrdinary(p: ?*Table) bool {
    return base(p)[Table_eTabType_off] == 0;
}
inline fn tabNRowLogEst(p: ?*Table) i16 {
    return rd(i16, p, Table_nRowLogEst_off);
}
inline fn tabSetNRowLogEst(p: ?*Table, v: i16) void {
    wr(i16, p, Table_nRowLogEst_off, v);
}
inline fn tabSzTabRow(p: ?*Table) i16 {
    return rd(i16, p, Table_szTabRow_off);
}
inline fn tabSetSzTabRow(p: ?*Table, v: i16) void {
    wr(i16, p, Table_szTabRow_off, v);
}

inline fn idxZName(p: ?*Index) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Index_zName_off);
}
inline fn idxPNext(p: ?*Index) ?*Index {
    return rd(?*Index, p, Index_pNext_off);
}
inline fn idxPTable(p: ?*Index) ?*Table {
    return rd(?*Table, p, Index_pTable_off);
}
inline fn idxTnum(p: ?*Index) u32 {
    return rd(u32, p, Index_tnum_off);
}
inline fn idxNKeyCol(p: ?*Index) u16 {
    return rd(u16, p, Index_nKeyCol_off);
}
inline fn idxNColumn(p: ?*Index) u16 {
    return rd(u16, p, Index_nColumn_off);
}
inline fn idxPPartIdxWhere(p: ?*Index) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pPartIdxWhere_off);
}
inline fn idxAiRowLogEst(p: ?*Index) [*]i16 {
    return @ptrCast(@alignCast(rd(?*anyopaque, p, Index_aiRowLogEst_off).?));
}
inline fn idxSzIdxRow(p: ?*Index) i16 {
    return rd(i16, p, Index_szIdxRow_off);
}
inline fn idxSetSzIdxRow(p: ?*Index, v: i16) void {
    wr(i16, p, Index_szIdxRow_off, v);
}
inline fn idxBit(p: ?*Index) u8 {
    return base(p)[Index_bit_byte];
}
inline fn idxType(p: ?*Index) u8 {
    return idxBit(p) & 0x03;
}
inline fn idxIsPrimaryKey(p: ?*Index) bool {
    return idxType(p) == SQLITE_IDXTYPE_PRIMARYKEY;
}
inline fn idxIsUnique(p: ?*Index) bool {
    return idxType(p) != 0;
}
inline fn idxUniqNotNull(p: ?*Index) bool {
    return (idxBit(p) & IDXBIT_uniqNotNull) != 0;
}
inline fn idxSetBUnordered(p: ?*Index, v: bool) void {
    if (v) {
        base(p)[Index_bit_byte] |= IDXBIT_bUnordered;
    } else {
        base(p)[Index_bit_byte] &= ~IDXBIT_bUnordered;
    }
}
inline fn idxSetNoSkipScan(p: ?*Index, v: bool) void {
    if (v) {
        base(p)[Index_bit_byte] |= IDXBIT_noSkipScan;
    } else {
        base(p)[Index_bit_byte] &= ~IDXBIT_noSkipScan;
    }
}
inline fn idxSetHasStat1(p: ?*Index, v: bool) void {
    if (v) {
        base(p)[Index_bit_byte] |= IDXBIT_hasStat1;
    } else {
        base(p)[Index_bit_byte] &= ~IDXBIT_hasStat1;
    }
}
inline fn idxHasStat1(p: ?*Index) bool {
    return (idxBit(p) & IDXBIT_hasStat1) != 0;
}
inline fn idxAzColl(p: ?*Index, i: usize) ?[*:0]const u8 {
    // azColl is `const char**`
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_azColl_off).?);
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(a + i * @sizeOf(usize));
    return q.*;
}
inline fn idxAiColumn(p: ?*Index, k: usize) i16 {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_aiColumn_off).?);
    const q: *align(1) const i16 = @ptrCast(a + k * 2);
    return q.*;
}
// bHasExpr lives in the next bitfield byte (101? no — byte 100 bit3, mask 0x08).
inline fn idxBHasExpr(p: ?*Index) bool {
    return (base(p)[Index_onError_off + 2] & 0x08) != 0;
}

const Table_aCol_off = off("Table_aCol", 8);
const Column_zCnName_off = off("Column_zCnName", 0);
const sizeof_Column = off("sizeof_Column", 16);
inline fn tabColZCnName(pTab: ?*Table, i: i16) ?[*:0]const u8 {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, pTab, Table_aCol_off).?);
    const col: ?*anyopaque = @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Column);
    return rd(?[*:0]const u8, col, Column_zCnName_off);
}

const XN_ROWID: i16 = -1;
const XN_EXPR: i16 = -2;

// EXPLAIN_COMMENTS ON in both configs → emit the per-column comment for
// byte-identical EXPLAIN output (matches analyzeVdbeCommentIndexWithColumnName).
fn analyzeVdbeCommentIndexWithColumnName(v: ?*Vdbe, pIdx: ?*Index, k: c_int) void {
    const i: i16 = idxAiColumn(pIdx, @intCast(k));
    if (i == XN_ROWID) {
        sqlite3VdbeComment(v, "%s.rowid", idxZName(pIdx).?);
    } else if (i == XN_EXPR) {
        sqlite3VdbeComment(v, "%s.expr(%d)", idxZName(pIdx).?, k);
    } else {
        sqlite3VdbeComment(v, "%s.%s", idxZName(pIdx).?, tabColZCnName(idxPTable(pIdx), i).?);
    }
}

// ─── internal stat_init / stat_push / stat_get FuncDefs ─────────────────────
// IsStat4 == 0, so: stat_init nArg=4, stat_push nArg=2, stat_get nArg=1.
fn mkFuncDef(comptime nArg: i16, comptime xSFunc: anytype, comptime name: [*:0]const u8) FuncDef {
    return .{
        .nArg = nArg,
        .funcFlags = SQLITE_UTF8,
        .pUserData = null,
        .pNext = null,
        .xSFunc = @ptrCast(&xSFunc),
        .xFinalize = null,
        .xValue = null,
        .xInverse = null,
        .zName = name,
        .u = .{ .pHash = null },
    };
}

var statInitFuncdef: FuncDef = mkFuncDef(4, statInit, "stat_init");
var statPushFuncdef: FuncDef = mkFuncDef(2, statPush, "stat_push");
var statGetFuncdef: FuncDef = mkFuncDef(1, statGet, "stat_get");

// Reclaim all memory of a StatAccum structure (non-STAT4: just free p).
fn statAccumDestructor(pOld: ?*anyopaque) callconv(.c) void {
    const p: *StatAccum = @ptrCast(@alignCast(pOld.?));
    sqlite3DbFree(p.db, pOld);
}

// stat_init(N,K,C,L) — allocate the StatAccum object.
fn statInit(context: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    const db = sqlite3_context_db_handle(context);
    const nCol = sqlite3_value_int(argv[0]);
    // nColUp: sizeof(tRowcnt)==8 → nColUp = nCol (no rounding).
    const nColUp = nCol;
    const nKeyCol = sqlite3_value_int(argv[1]);

    // n = sizeof(StatAccum) + sizeof(tRowcnt)*nColUp   (StatAccum.anDLt)
    const n: u64 = @as(u64, @sizeOf(StatAccum)) + @as(u64, 8) * @as(u64, @intCast(nColUp));
    const pRaw = sqlite3DbMallocZero(db, n);
    if (pRaw == null) {
        sqlite3_result_error_nomem(context);
        return;
    }
    const p: *StatAccum = @ptrCast(@alignCast(pRaw.?));
    p.db = db;
    p.nEst = @bitCast(sqlite3_value_int64(argv[2]));
    p.nRow = 0;
    p.nLimit = sqlite3_value_int(argv[3]);
    p.nCol = nCol;
    p.nKeyCol = nKeyCol;
    p.nSkipAhead = 0;
    // p->current.anDLt = (tRowcnt*)&p[1];
    const after: [*]u8 = @as([*]u8, @ptrCast(pRaw.?)) + @sizeOf(StatAccum);
    p.current_anDLt = @ptrCast(@alignCast(after));

    // Return the pointer as a BLOB; only the pointer matters.
    sqlite3_result_blob(context, pRaw, @sizeOf(StatAccum), statAccumDestructor);
}

// stat_push(P,C) — collect distinct-prefix counts (non-STAT4: no rowid arg).
fn statPush(context: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    const p: *StatAccum = @ptrCast(@alignCast(sqlite3_value_blob(argv[0]).?));
    const iChng = sqlite3_value_int(argv[1]);

    if (p.nRow != 0) {
        // Second and subsequent calls: bump anDLt[] from iChng..nCol.
        var i: c_int = iChng;
        const anDLt = p.current_anDLt.?;
        while (i < p.nCol) : (i += 1) {
            anDLt[@intCast(i)] += 1;
        }
    }
    p.nRow += 1;

    if (p.nLimit != 0 and p.nRow > @as(u64, @intCast(p.nLimit)) * (@as(u64, p.nSkipAhead) + 1)) {
        p.nSkipAhead += 1;
        sqlite3_result_int(context, @intFromBool(p.current_anDLt.?[0] > 0));
    }
}

// stat_get(P) — build the sqlite_stat1 "stat" text column (non-STAT4: 1 arg).
fn statGet(context: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    const p: *StatAccum = @ptrCast(@alignCast(sqlite3_value_blob(argv[0]).?));

    var sStat: StrAccum = undefined;
    sqlite3StrAccumInit(&sStat, null, null, 0, (p.nKeyCol + 1) * 100);
    const first: u64 = if (p.nSkipAhead != 0) p.nEst else p.nRow;
    sqlite3_str_appendf(&sStat, "%llu", first);
    var i: c_int = 0;
    const anDLt = p.current_anDLt.?;
    while (i < p.nKeyCol) : (i += 1) {
        const nDistinct: u64 = anDLt[@intCast(i)] + 1;
        var iVal: u64 = (p.nRow + nDistinct - 1) / nDistinct;
        if (iVal == 2 and p.nRow * 10 <= nDistinct * 11) iVal = 1;
        sqlite3_str_appendf(&sStat, " %llu", iVal);
    }
    sqlite3_result_str(context, &sStat, SQLITE_XFER);
}

const STAT_GET_STAT1: c_int = 0;

fn callStatGet(pParse: ?*Parse, regStat: c_int, iParam: c_int, regOut: c_int) void {
    _ = iParam; // STAT4-only param; not emitted when STAT4 off.
    _ = sqlite3VdbeAddFunctionCall(pParse, 0, regStat, regOut, 1, &statGetFuncdef, 0);
}

// ─── openStatTable ──────────────────────────────────────────────────────────
// Only sqlite_stat1 is created/opened (nToOpen == 1; STAT4 off). The loop still
// visits all 3 entries to delete/clear existing rows of stat1/stat4/stat3.
fn openStatTable(
    pParse: ?*Parse,
    iDb: c_int,
    iStatCur: c_int,
    zWhere: ?[*:0]const u8,
    zWhereType: ?[*:0]const u8,
) void {
    const db = parseDb(pParse);
    const v = sqlite3GetVdbe(pParse);
    if (v == null) return;
    const pDb = dbAt(db, iDb);
    const zDbSName = dbZDbSName(pDb);

    const nToOpen: c_int = 1;

    const aName = [_][*:0]const u8{ "sqlite_stat1", "sqlite_stat4", "sqlite_stat3" };

    var aRoot: [3]u32 = .{ 0, 0, 0 };
    var aCreateTbl: [3]u16 = .{ 0, 0, 0 };

    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const zTab = aName[i];
        const pStat = sqlite3FindTable(db, zTab, zDbSName);
        if (pStat == null) {
            if (@as(c_int, @intCast(i)) < nToOpen) {
                // Create sqlite_stat1. CREATE TABLE leaves its rootpage in
                // pParse->u1.cr.regRoot.
                sqlite3NestedParse(pParse, "CREATE TABLE %Q.%s(%s)", zDbSName, zTab, @as([*:0]const u8, "tbl,idx,stat"));
                aRoot[i] = @bitCast(parseRegRoot(pParse));
                aCreateTbl[i] = OPFLAG_P2ISREG;
            }
        } else {
            aRoot[i] = tabTnum(pStat);
            sqlite3TableLock(pParse, iDb, aRoot[i], 1, zTab);
            if (zWhere != null) {
                sqlite3NestedParse(pParse, "DELETE FROM %Q.%s WHERE %s=%Q", zDbSName, zTab, zWhereType.?, zWhere.?);
            } else if (dbXPreUpdate(db) != null) {
                sqlite3NestedParse(pParse, "DELETE FROM %Q.%s", zDbSName, zTab);
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_Clear, @bitCast(aRoot[i]), iDb);
            }
        }
    }

    // Open sqlite_stat1 for writing.
    var j: usize = 0;
    while (@as(c_int, @intCast(j)) < nToOpen) : (j += 1) {
        _ = sqlite3VdbeAddOp4Int(v, OP_OpenWrite, iStatCur + @as(c_int, @intCast(j)), @bitCast(aRoot[j]), iDb, 3);
        sqlite3VdbeChangeP5(v, aCreateTbl[j]);
        sqlite3VdbeComment(v, "%s", aName[j]);
    }
}

// ─── analyzeOneTable ────────────────────────────────────────────────────────
fn analyzeOneTable(
    pParse: ?*Parse,
    pTab: ?*Table,
    pOnlyIdx: ?*Index,
    iStatCur: c_int,
    iMemIn: c_int,
    iTabIn: c_int,
) void {
    const db = parseDb(pParse);
    var iMem = iMemIn;
    var iTab = iTabIn;
    var jZeroRows: c_int = -1;
    var needTableCnt: bool = true;

    const regNewRowid = iMem;
    iMem += 1;
    const regStat = iMem;
    iMem += 1;
    const regChng = iMem;
    iMem += 1;
    const regRowid = iMem;
    iMem += 1;
    const regTemp = iMem;
    iMem += 1;
    const regTemp2 = iMem;
    iMem += 1;
    const regTabname = iMem;
    iMem += 1;
    const regIdxname = iMem;
    iMem += 1;
    const regStat1 = iMem;
    iMem += 1;
    const regPrev = iMem; // MUST BE LAST

    var pStat1: ?*anyopaque = null;

    sqlite3TouchRegister(pParse, iMem);
    const v = sqlite3GetVdbe(pParse);
    if (v == null or pTab == null) return;
    if (!tabIsOrdinary(pTab)) return; // no stats on views/vtabs
    if (sqlite3_strlike("sqlite\\_%", tabZName(pTab), '\\') == 0) return; // no system tables

    const iDb = sqlite3SchemaToIndex(db, tabPSchema(pTab));

    if (sqlite3AuthCheck(pParse, SQLITE_ANALYZE, tabZName(pTab), null, dbZDbSName(dbAt(db, iDb))) != 0) {
        return;
    }

    // PREUPDATE-hook path: build a faux sqlite_stat1 Table* used in P4_TABLE.
    if (dbXPreUpdate(db) != null) {
        const raw = sqlite3DbMallocZero(db, @as(u64, sizeof_Table) + 13);
        if (raw == null) return;
        pStat1 = raw;
        const namePtr: [*]u8 = @as([*]u8, @ptrCast(raw.?)) + sizeof_Table;
        wr(?*anyopaque, pStat1, Table_zName_off, @ptrCast(namePtr));
        const src = "sqlite_stat1\x00";
        @memcpy(namePtr[0..13], src[0..13]);
        wr(i16, pStat1, Table_nCol_off, 3);
        wr(i16, pStat1, Table_iPKey_off, -1);
        _ = sqlite3VdbeAddOp4(v, OP_Noop, 0, 0, 0, @ptrCast(pStat1), P4_DYNAMIC);
    }

    // Read-lock + open read cursor on the table; reserve an index cursor.
    sqlite3TableLock(pParse, iDb, tabTnum(pTab), 0, tabZName(pTab));
    const iTabCur = iTab;
    iTab += 1;
    const iIdxCur = iTab;
    iTab += 1;
    if (iTab > parseNTab(pParse)) parseSetNTab(pParse, iTab);
    sqlite3OpenTable(pParse, iTabCur, iDb, pTab, OP_OpenRead);
    _ = sqlite3VdbeLoadString(v, regTabname, tabZName(pTab));

    var pIdx = tabPIndex(pTab);
    while (pIdx != null) : (pIdx = idxPNext(pIdx)) {
        if (pOnlyIdx != null and pOnlyIdx != pIdx) continue;
        if (idxPPartIdxWhere(pIdx) == null) needTableCnt = false;

        var nCol: c_int = undefined;
        var zIdxName: ?[*:0]const u8 = undefined;
        var nColTest: c_int = undefined;
        if (!tabHasRowid(pTab) and idxIsPrimaryKey(pIdx)) {
            nCol = idxNKeyCol(pIdx);
            zIdxName = tabZName(pTab);
            nColTest = nCol - 1;
        } else {
            nCol = idxNColumn(pIdx);
            zIdxName = idxZName(pIdx);
            nColTest = if (idxUniqNotNull(pIdx)) @as(c_int, idxNKeyCol(pIdx)) - 1 else nCol - 1;
        }

        _ = sqlite3VdbeLoadString(v, regIdxname, zIdxName);
        sqlite3VdbeComment(v, "Analysis for %s.%s", tabZName(pTab), zIdxName.?);

        // Ensure regPrev[] (+ trailing rowid) registers exist.
        sqlite3TouchRegister(pParse, regPrev + nColTest);

        // Open a read-only cursor on the index.
        _ = sqlite3VdbeAddOp3(v, OP_OpenRead, iIdxCur, @bitCast(idxTnum(pIdx)), iDb);
        sqlite3VdbeSetP4KeyInfo(pParse, pIdx);
        sqlite3VdbeComment(v, "%s", idxZName(pIdx).?);

        // regTemp2 == regStat+4
        _ = sqlite3VdbeAddOp2(v, OP_Integer, dbNAnalysisLimit(db), regTemp2);
        // stat_init() args
        _ = sqlite3VdbeAddOp2(v, OP_Integer, nCol, regStat + 1);
        // regRowid == regStat+2
        _ = sqlite3VdbeAddOp2(v, OP_Integer, idxNKeyCol(pIdx), regRowid);
        _ = sqlite3VdbeAddOp3(v, OP_Count, iIdxCur, regTemp, @intFromBool(optDisabled(db, SQLITE_Stat4)));
        _ = sqlite3VdbeAddFunctionCall(pParse, 0, regStat + 1, regStat, 4, &statInitFuncdef, 0);
        var addrGotoEnd = sqlite3VdbeAddOp1(v, OP_Rewind, iIdxCur);

        _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, regChng);
        var addrNextRow = sqlite3VdbeCurrentAddr(v);

        if (nColTest > 0) {
            const endDistinctTest = sqlite3VdbeMakeLabel(pParse);
            const aGotoChng: ?*anyopaque = sqlite3DbMallocRawNN(db, @as(u64, @intCast(nColTest)) * @sizeOf(c_int));
            if (aGotoChng == null) continue;
            const aGoto: [*]c_int = @ptrCast(@alignCast(aGotoChng.?));

            _ = sqlite3VdbeAddOp0(v, OP_Goto);
            addrNextRow = sqlite3VdbeCurrentAddr(v);
            if (nColTest == 1 and idxNKeyCol(pIdx) == 1 and idxIsUnique(pIdx)) {
                _ = sqlite3VdbeAddOp2(v, OP_NotNull, regPrev, endDistinctTest);
            }
            var i: c_int = 0;
            while (i < nColTest) : (i += 1) {
                const pColl = sqlite3LocateCollSeq(pParse, idxAzColl(pIdx, @intCast(i)));
                _ = sqlite3VdbeAddOp2(v, OP_Integer, i, regChng);
                _ = sqlite3VdbeAddOp3(v, OP_Column, iIdxCur, i, regTemp);
                analyzeVdbeCommentIndexWithColumnName(v, pIdx, i);
                aGoto[@intCast(i)] = sqlite3VdbeAddOp4(v, OP_Ne, regTemp, 0, regPrev + i, @ptrCast(pColl), P4_COLLSEQ);
                sqlite3VdbeChangeP5(v, SQLITE_NULLEQ);
            }
            _ = sqlite3VdbeAddOp2(v, OP_Integer, nColTest, regChng);
            _ = sqlite3VdbeGoto(v, endDistinctTest);

            sqlite3VdbeJumpHere(v, addrNextRow - 1);
            i = 0;
            while (i < nColTest) : (i += 1) {
                sqlite3VdbeJumpHere(v, aGoto[@intCast(i)]);
                _ = sqlite3VdbeAddOp3(v, OP_Column, iIdxCur, i, regPrev + i);
                analyzeVdbeCommentIndexWithColumnName(v, pIdx, i);
            }
            sqlite3VdbeResolveLabel(v, endDistinctTest);
            sqlite3DbFree(db, aGotoChng);
        }

        // stat_push(P, regChng) ; Next csr ; loop.
        _ = sqlite3VdbeAddFunctionCall(pParse, 1, regStat, regTemp, 2, &statPushFuncdef, 0);
        if (dbNAnalysisLimit(db) != 0) {
            const j1 = sqlite3VdbeAddOp1(v, OP_IsNull, regTemp);
            const j2 = sqlite3VdbeAddOp1(v, OP_If, regTemp);
            const j3 = sqlite3VdbeAddOp4Int(v, OP_SeekGT, iIdxCur, 0, regPrev, 1);
            sqlite3VdbeJumpHere(v, j1);
            _ = sqlite3VdbeAddOp2(v, OP_Next, iIdxCur, addrNextRow);
            sqlite3VdbeJumpHere(v, j2);
            sqlite3VdbeJumpHere(v, j3);
        } else {
            _ = sqlite3VdbeAddOp2(v, OP_Next, iIdxCur, addrNextRow);
        }

        // Add the entry to sqlite_stat1.
        if (idxPPartIdxWhere(pIdx) != null) {
            sqlite3VdbeJumpHere(v, addrGotoEnd);
            addrGotoEnd = 0;
        }
        callStatGet(pParse, regStat, STAT_GET_STAT1, regStat1);
        _ = sqlite3VdbeAddOp4(v, OP_MakeRecord, regTabname, 3, regTemp, "BBB", 0);
        _ = sqlite3VdbeAddOp2(v, OP_NewRowid, iStatCur, regNewRowid);
        _ = sqlite3VdbeAddOp3(v, OP_Insert, iStatCur, regTemp, regNewRowid);
        if (pStat1 != null) {
            sqlite3VdbeChangeP4(v, -1, @ptrCast(pStat1), P4_TABLE);
        }
        sqlite3VdbeChangeP5(v, OPFLAG_APPEND);

        // End of analysis for this index.
        if (addrGotoEnd != 0) sqlite3VdbeJumpHere(v, addrGotoEnd);
    }

    // Single sqlite_stat1 entry with NULL index name + table row count.
    if (pOnlyIdx == null and needTableCnt) {
        sqlite3VdbeComment(v, "%s", tabZName(pTab).?);
        _ = sqlite3VdbeAddOp2(v, OP_Count, iTabCur, regStat1);
        jZeroRows = sqlite3VdbeAddOp1(v, OP_IfNot, regStat1);
        _ = sqlite3VdbeAddOp2(v, OP_Null, 0, regIdxname);
        _ = sqlite3VdbeAddOp4(v, OP_MakeRecord, regTabname, 3, regTemp, "BBB", 0);
        _ = sqlite3VdbeAddOp2(v, OP_NewRowid, iStatCur, regNewRowid);
        _ = sqlite3VdbeAddOp3(v, OP_Insert, iStatCur, regTemp, regNewRowid);
        sqlite3VdbeChangeP5(v, OPFLAG_APPEND);
        if (pStat1 != null) {
            sqlite3VdbeChangeP4(v, -1, @ptrCast(pStat1), P4_TABLE);
        }
        sqlite3VdbeJumpHere(v, jZeroRows);
    }
}

fn loadAnalysis(pParse: ?*Parse, iDb: c_int) void {
    const v = sqlite3GetVdbe(pParse);
    if (v != null) {
        _ = sqlite3VdbeAddOp1(v, OP_LoadAnalysis, iDb);
    }
}

fn analyzeDatabase(pParse: ?*Parse, iDb: c_int) void {
    const db = parseDb(pParse);
    const pDb = dbAt(db, iDb);
    const pSchema = dbPSchema(pDb);

    sqlite3BeginWriteOperation(pParse, 0, iDb);
    const iStatCur = parseNTab(pParse);
    parseSetNTab(pParse, parseNTab(pParse) + 3);
    openStatTable(pParse, iDb, iStatCur, null, null);
    // STAT4 off: iMem is constant across the loop (C only updates it under
    // SQLITE_ENABLE_STAT4; otherwise it asserts iMem is unchanged).
    const iMem = parseNMem(pParse) + 1;
    const iTab = parseNTab(pParse);

    const tblHash: *anyopaque = @ptrCast(@as([*]u8, @ptrCast(pSchema.?)) + Schema_tblHash_off);
    var k = hashFirst(tblHash);
    while (k != null) : (k = hashNext(k)) {
        const pTab = hashData(k);
        analyzeOneTable(pParse, pTab, null, iStatCur, iMem, iTab);
    }
    loadAnalysis(pParse, iDb);
}

fn analyzeTable(pParse: ?*Parse, pTab: ?*Table, pOnlyIdx: ?*Index) void {
    const db = parseDb(pParse);
    const iDb = sqlite3SchemaToIndex(db, tabPSchema(pTab));
    sqlite3BeginWriteOperation(pParse, 0, iDb);
    const iStatCur = parseNTab(pParse);
    parseSetNTab(pParse, parseNTab(pParse) + 3);
    if (pOnlyIdx != null) {
        openStatTable(pParse, iDb, iStatCur, idxZName(pOnlyIdx), "idx");
    } else {
        openStatTable(pParse, iDb, iStatCur, tabZName(pTab), "tbl");
    }
    analyzeOneTable(pParse, pTab, pOnlyIdx, iStatCur, parseNMem(pParse) + 1, parseNTab(pParse));
    loadAnalysis(pParse, iDb);
}

// ─── sqlite3Analyze (the ANALYZE command parser callback) ───────────────────
export fn sqlite3Analyze(pParse: ?*Parse, pName1: ?*Token, pName2: ?*Token) void {
    const db = parseDb(pParse);

    if (SQLITE_OK != sqlite3ReadSchema(pParse)) return;

    if (pName1 == null) {
        // Form 1: analyze everything (skip the TEMP database, iDb==1).
        var i: c_int = 0;
        const nDb = dbNDb(db);
        while (i < nDb) : (i += 1) {
            if (i == 1) continue;
            analyzeDatabase(pParse, i);
        }
    } else {
        const iDbName = sqlite3FindDb(db, pName1);
        if (tokenN(pName2) == 0 and iDbName >= 0) {
            // Form 2: a named schema.
            analyzeDatabase(pParse, iDbName);
        } else {
            // Form 3: a named table or index.
            var pTableName: ?*Token = null;
            const iDb = sqlite3TwoPartName(pParse, pName1, pName2, &pTableName);
            if (iDb >= 0) {
                const zDb: ?[*:0]const u8 = if (tokenN(pName2) != 0) dbZDbSName(dbAt(db, iDb)) else null;
                const z = sqlite3NameFromToken(db, pTableName);
                if (z != null) {
                    const pIdx = sqlite3FindIndex(db, z, zDb);
                    if (pIdx != null) {
                        analyzeTable(pParse, idxPTable(pIdx), pIdx);
                    } else {
                        const pTab = sqlite3LocateTable(pParse, 0, z, zDb);
                        if (pTab != null) {
                            analyzeTable(pParse, pTab, null);
                        }
                    }
                    sqlite3DbFree(db, z);
                }
            }
        }
    }
    if (dbNSqlExec(db) == 0) {
        const v = sqlite3GetVdbe(pParse);
        if (v != null) {
            _ = sqlite3VdbeAddOp0(v, OP_Expire);
        }
    }
}

inline fn tokenN(p: ?*Token) c_uint {
    if (p == null) return 0;
    return rd(c_uint, p, Token_n_off);
}

// ─── stat-loading: decode + analysisLoader ──────────────────────────────────

// Decode a space-separated integer list. With STAT4 off, aOut is always null
// and only aLog (LogEst) is filled. pIndex (if non-null) parses trailing flags.
fn decodeIntArray(zIntArray: ?[*:0]const u8, nOut: c_int, aOut: ?[*]u64, aLog: ?[*]i16, pIndex: ?*Index) void {
    var z: [*:0]const u8 = zIntArray.?;
    var i: c_int = 0;
    while (z[0] != 0 and i < nOut) : (i += 1) {
        var val: u64 = 0;
        while (z[0] >= '0' and z[0] <= '9') {
            val = val *% 10 +% (z[0] - '0');
            z += 1;
        }
        if (aOut) |a| {
            a[@intCast(i)] = val;
        }
        if (aLog) |lg| {
            lg[@intCast(i)] = sqlite3LogEst(val);
        }
        if (z[0] == ' ') z += 1;
    }

    // STAT4 off: pIndex is asserted non-null in C. Parse trailing keyword flags.
    if (pIndex) |pIdx| {
        idxSetBUnordered(pIdx, false);
        idxSetNoSkipScan(pIdx, false);
        while (z[0] != 0) {
            if (sqlite3_strglob("unordered*", z) == 0) {
                idxSetBUnordered(pIdx, true);
            } else if (sqlite3_strglob("sz=[0-9]*", z) == 0) {
                var sz = sqlite3Atoi(z + 3);
                if (sz < 2) sz = 2;
                idxSetSzIdxRow(pIdx, sqlite3LogEst(@intCast(sz)));
            } else if (sqlite3_strglob("noskipscan*", z) == 0) {
                idxSetNoSkipScan(pIdx, true);
            }
            // SQLITE_ENABLE_COSTMULT is OFF → no costmult= branch.
            while (z[0] != 0 and z[0] != ' ') z += 1;
            while (z[0] == ' ') z += 1;
        }
    }
}

const analysisInfo = extern struct {
    db: ?*Sqlite3,
    zDatabase: ?[*:0]const u8,
};

fn analysisLoader(pData: ?*anyopaque, argc: c_int, argv: ?[*]?[*:0]u8, notUsed: ?[*]?[*:0]u8) callconv(.c) c_int {
    _ = argc;
    _ = notUsed;
    const pInfo: *analysisInfo = @ptrCast(@alignCast(pData.?));
    const av = argv orelse return 0;
    if (av[0] == null or av[2] == null) return 0;

    const pTable = sqlite3FindTable(pInfo.db, av[0], pInfo.zDatabase);
    if (pTable == null) return 0;

    var pIndex: ?*Index = undefined;
    if (av[1] == null) {
        pIndex = null;
    } else if (sqlite3_stricmp(av[0], av[1]) == 0) {
        pIndex = sqlite3PrimaryKeyIndex(pTable);
    } else {
        pIndex = sqlite3FindIndex(pInfo.db, av[1], pInfo.zDatabase);
    }
    const z = av[2];

    if (pIndex) |pIdx| {
        const nCol: c_int = @as(c_int, idxNKeyCol(pIdx)) + 1;
        idxSetBUnordered(pIdx, false);
        // STAT4 off: aiRowEst arg is null.
        decodeIntArray(@ptrCast(z), nCol, null, idxAiRowLogEst(pIdx), pIdx);
        idxSetHasStat1(pIdx, true);
        if (idxPPartIdxWhere(pIdx) == null) {
            tabSetNRowLogEst(pTable, idxAiRowLogEst(pIdx)[0]);
            tabSetTabFlags(pTable, tabTabFlags(pTable) | TF_HasStat1);
        }
    } else {
        // Fake index for the table-rowcount row; we only touch its szIdxRow
        // (offset 92 < 99) so an Index-sized buffer is plenty and 8-aligned.
        var fakeIdx: [sizeof_Index]u8 align(8) = undefined;
        const pFake: ?*Index = @ptrCast(&fakeIdx);
        idxSetSzIdxRow(pFake, tabSzTabRow(pTable));
        // SQLITE_ENABLE_COSTMULT off → fakeIdx.pTable unused.
        var logTmp: [1]i16 = .{tabNRowLogEst(pTable)};
        decodeIntArray(@ptrCast(z), 1, null, &logTmp, pFake);
        tabSetNRowLogEst(pTable, logTmp[0]);
        tabSetSzTabRow(pTable, idxSzIdxRow(pFake));
        tabSetTabFlags(pTable, tabTabFlags(pTable) | TF_HasStat1);
    }
    return 0;
}

// ─── sqlite3DeleteIndexSamples ──────────────────────────────────────────────
// STAT4 off → no aSample[] arrays exist; this is a no-op.
export fn sqlite3DeleteIndexSamples(db: ?*Sqlite3, pIdx: ?*Index) void {
    _ = db;
    _ = pIdx;
}

// ─── sqlite3AnalysisLoad ────────────────────────────────────────────────────
export fn sqlite3AnalysisLoad(db: ?*Sqlite3, iDb: c_int) c_int {
    var sInfo: analysisInfo = undefined;
    var rc: c_int = SQLITE_OK;
    const pDb = dbAt(db, iDb);
    const pSchema = dbPSchema(pDb);

    // Clear any prior statistics.
    const tblHash: *anyopaque = @ptrCast(@as([*]u8, @ptrCast(pSchema.?)) + Schema_tblHash_off);
    const idxHash: *anyopaque = @ptrCast(@as([*]u8, @ptrCast(pSchema.?)) + Schema_idxHash_off);

    var it = hashFirst(tblHash);
    while (it != null) : (it = hashNext(it)) {
        const pTab = hashData(it);
        tabSetTabFlags(pTab, tabTabFlags(pTab) & ~TF_HasStat1);
    }
    it = hashFirst(idxHash);
    while (it != null) : (it = hashNext(it)) {
        const pIdx = hashData(it);
        idxSetHasStat1(pIdx, false);
        // STAT4 off: no aSample to delete.
    }

    // Load new statistics from sqlite_stat1.
    sInfo.db = db;
    sInfo.zDatabase = dbZDbSName(pDb);
    const pStat1 = sqlite3FindTable(db, "sqlite_stat1", sInfo.zDatabase);
    if (pStat1 != null and tabIsOrdinary(pStat1)) {
        const zSql = sqlite3MPrintf(db, "SELECT tbl,idx,stat FROM %Q.sqlite_stat1", sInfo.zDatabase.?);
        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3_exec(db, zSql, analysisLoader, &sInfo, null);
            sqlite3DbFree(db, zSql);
        }
    }

    // Defaults for indexes not in sqlite_stat1.
    it = hashFirst(idxHash);
    while (it != null) : (it = hashNext(it)) {
        const pIdx = hashData(it);
        if (!idxHasStat1(pIdx)) sqlite3DefaultRowEst(pIdx);
    }

    // STAT4 off: no loadStat4 / aiRowEst cleanup.

    if (rc == SQLITE_NOMEM) {
        _ = sqlite3OomFault(db);
    }
    return rc;
}
