//! Zig port of SQLite's src/update.c — UPDATE statement code generation.
//!
//! Exported (non-static) symbols — the complete external set of update.c,
//! matching prototypes in sqliteInt.h (SQLITE_OMIT_VIRTUALTABLE,
//! SQLITE_OMIT_TRIGGER, SQLITE_OMIT_VIEW, SQLITE_OMIT_GENERATED_COLUMNS,
//! SQLITE_OMIT_AUTHORIZATION, SQLITE_ENABLE_UPDATE_DELETE_LIMIT all in their
//! default state for this project's two build configs):
//!   - sqlite3ColumnDefault
//!   - sqlite3Update
//! The static helpers (indexColumnIsBeingUpdated, indexWhereClauseMightChange,
//! exprRowColumn, updateFromSelect, updateVirtualTable) are private here.
//!
//! ─── Config assumptions (true in both this project's builds) ────────────────
//!   * SQLITE_OMIT_VIRTUALTABLE / OMIT_TRIGGER / OMIT_VIEW /
//!     OMIT_GENERATED_COLUMNS / OMIT_AUTHORIZATION  OFF.
//!   * SQLITE_OMIT_SUBQUERY / OMIT_FLOATING_POINT  OFF.
//!   * SQLITE_ENABLE_UPDATE_DELETE_LIMIT  OFF  (no LIMIT/ORDER BY on UPDATE).
//!   * SQLITE_ENABLE_PREUPDATE_HOOK  ON  → sqlite3TableColumnToStorage is a real
//!     function; the OP_Delete pre-update path is compiled.
//!   * SQLITE_ALLOW_ROWID_IN_VIEW  OFF.
//!   * TREETRACE_ENABLED behavior is debug-only tracing → omitted (no codegen
//!     effect).
//!   * Little-endian x86-64.
//!
//! ─── Struct coupling / ground-truth offsets ────────────────────────────────
//! Offsets are pulled from c_layout (probe-verified by tools/offsets.c) where
//! present, else from a probe-verified fallback. NEW offsets needed by this
//! module (all config-invariant): Upsert.iDataCur@76 / iIdxCur@80,
//! Index.nColumn@96 / aColExpr@80, SrcItem.colUsed@32, SelectDest layout,
//! KeyInfo.nAllField@8. The only config divergence anywhere is the Parse
//! bft-bitfield byte (39 prod / 42 tf) — same as fkey.zig.
//!
//! Validated through the engine by the TCL suite (update*, upsert*, trigger*,
//! vtab*, fkey*); every path couples to the live parser/VDBE/btree/schema, so
//! no standalone Zig unit test is feasible.

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

// ─── ground-truth offsets (reuse c_layout, else probe-verified fallback) ─────
fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

// Parse
const Parse_db_off = off("Parse_db", 0);
const Parse_nErr_off = off("Parse_nErr", 52);
const Parse_nTab_off = off("Parse_nTab", 56);
const Parse_nMem_off = off("Parse_nMem", 60);
const Parse_nested_off = off("Parse_nested", 30);
const Parse_pVdbe_off = off("Parse_pVdbe", 16);
const Parse_pTriggerTab_off = off("Parse_pTriggerTab", 144);
// bft bitfield byte holding disableTriggers(0x01)..bReturning(0x08). Divergent.
const Parse_bft_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_bReturning: u8 = 0x08;

// sqlite3
const sqlite3_flags_off = off("sqlite3_flags", 48);
const sqlite3_mallocFailed_off = off("sqlite3_mallocFailed", 103);
const sqlite3_aDb_off = off("sqlite3_aDb", 32);

// Db
const sizeof_Db = off("sizeof_Db", 32);
const Db_zDbSName_off = off("Db_zDbSName", 0);

// Table
const Table_zName_off = off("Table_zName", 0);
const Table_aCol_off = off("Table_aCol", 8);
const Table_pIndex_off = off("Table_pIndex", 16);
const Table_tabFlags_off = off("Table_tabFlags", 48);
const Table_iPKey_off = off("Table_iPKey", 52);
const Table_nCol_off = off("Table_nCol", 54);
const Table_eTabType_off = off("Table_eTabType", 63);
const Table_pSchema_off = off("Table_pSchema", 96);

// Column
const Column_zCnName_off = off("Column_zCnName", 0);
const Column_affinity_off = off("Column_affinity", 9);
const Column_iDflt_off = off("Column_iDflt", 12);
const Column_colFlags_off = off("Column_colFlags", 14);
const sizeof_Column = off("sizeof_Column", 16);

// Index
const Index_aiColumn_off = off("Index_aiColumn", 8);
const Index_pNext_off = off("Index_pNext", 40);
const Index_pPartIdxWhere_off = off("Index_pPartIdxWhere", 72);
const Index_aColExpr_off = off("Index_aColExpr", 80); // NEW
const Index_nKeyCol_off = off("Index_nKeyCol", 94);
const Index_nColumn_off = off("Index_nColumn", 96); // NEW
const Index_onError_off = off("Index_onError", 98);

// ExprList / item
const ExprList_nExpr_off = off("ExprList_nExpr", 0);
const ExprList_a_off = off("ExprList_a", 8);
const ExprList_item_pExpr_off = off("ExprList_item_pExpr", 0);
const ExprList_item_zEName_off = off("ExprList_item_zEName", 8);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);

// SrcList / SrcItem
const SrcList_nSrc_off = off("SrcList_nSrc", 0);
const SrcList_a_off = off("SrcList_a", 8);
const SrcItem_iCursor_off = off("SrcItem_iCursor", 28);
const SrcItem_colUsed_off = off("SrcItem_colUsed", 32); // NEW

// Expr
const Expr_op2_off: usize = 2; // u8, invariant
const Expr_iColumn_off = off("Expr_iColumn", 48);

// Upsert
const Upsert_iDataCur_off = off("Upsert_iDataCur", 76); // NEW
const Upsert_iIdxCur_off = off("Upsert_iIdxCur", 80); // NEW

// KeyInfo
const KeyInfo_nAllField_off = off("KeyInfo_nAllField", 8); // NEW (probe-verified)

// SelectDest (NEW; probe-verified, config-invariant)
const SelectDest_iSDParm2_off: usize = 8;

// ─── constants ───────────────────────────────────────────────────────────────
const TABTYP_NORM: u8 = 0;
const TF_WithoutRowid: u32 = 0x00000080;
const TF_HasGenerated: u32 = 0x60;

const COLFLAG_PRIMKEY: u16 = 0x0001;
const COLFLAG_GENERATED: u16 = 0x0060;
const COLFLAG_VIRTUAL: u16 = 0x0020;

const SQLITE_AFF_REAL: u8 = 0x45;

const XN_ROWID: i16 = -1;
const XN_EXPR: i16 = -2;

const OE_Default: c_int = 11;
const OE_Replace: c_int = 5;
const OE_Abort: c_int = 2;

const ONEPASS_OFF: c_int = 0;
const ONEPASS_SINGLE: c_int = 1;
const ONEPASS_MULTI: c_int = 2;

const WHERE_ONEPASS_DESIRED: u16 = 0x0004;
const WHERE_ONEPASS_MULTIROW: u16 = 0x0008;

const SF_UFSrcCheck: u32 = 0x800000;
const SF_IncludeHidden: u32 = 0x20000;
const SF_UpdateFrom: u32 = 0x10000000;
const SF_OrderByReqd: u32 = 0x8000000;

const SRT_Table: c_int = 12;
const SRT_Upfrom: c_int = 13;

const NC_UUpsert: c_int = 0x200;

const SQLITE_CountRows: u64 = 0x100000000;

const ALLBITS: u64 = 0xffffffffffffffff;

const EP_Subquery: u32 = 0x400000;

const TK_ROW: c_int = 67;

const OPFLAG_ISUPDATE: u16 = 0x04;
const OPFLAG_SAVEPOSITION: u16 = 0x02;
const OPFLAG_ISNOOP: u16 = 0x40;
const OPFLAG_NOCHNG: u16 = 0x01;
const OPFLAG_NOCHNG_MAGIC: u16 = 0x6d;

const P4_MEM: c_int = -11;
const P4_KEYINFO: c_int = -9;
const P4_TABLE: c_int = -5;
const P4_VTAB: c_int = -12;

const SQLITE_JUMPIFNULL: c_int = 0x10;

const TRIGGER_BEFORE: c_int = 1;
const TRIGGER_AFTER: c_int = 2;
const TK_UPDATE: c_int = 130;

const MASKBIT32_lim: usize = 32;

// VDBE opcodes
const OP_VUpdate: c_int = 7;
const OP_MustBeInt: c_int = 13;
const OP_Once: c_int = 15;
const OP_NotFound: c_int = 28;
const OP_NotExists: c_int = 31;
const OP_Rewind: c_int = 36;
const OP_Next: c_int = 40;
const OP_IsNull: c_int = 51;
const OP_Integer: c_int = 73;
const OP_Null: c_int = 77;
const OP_Copy: c_int = 82;
const OP_SCopy: c_int = 83;
const OP_AddImm: c_int = 88;
const OP_RealAffinity: c_int = 89;
const OP_Column: c_int = 96;
const OP_MakeRecord: c_int = 99;
const OP_OpenEphemeral: c_int = 120;
const OP_Close: c_int = 124;
const OP_NewRowid: c_int = 129;
const OP_Insert: c_int = 130;
const OP_Delete: c_int = 132;
const OP_RowData: c_int = 136;
const OP_Rowid: c_int = 137;
const OP_IdxInsert: c_int = 140;
const OP_FinishSeek: c_int = 145;
const OP_VColumn: c_int = 178;

const OP_OpenWrite: c_int = 116; // sqlite3OpenTableAndIndices opcode arg

// ─── accessors ───────────────────────────────────────────────────────────────
inline fn pDb(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_db_off);
}
inline fn pNErr(pParse: ?*anyopaque) c_int {
    return rd(c_int, pParse, Parse_nErr_off);
}
inline fn pNTab(pParse: ?*anyopaque) c_int {
    return rd(c_int, pParse, Parse_nTab_off);
}
inline fn pSetNTab(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_nTab_off, v);
}
inline fn pNMem(pParse: ?*anyopaque) c_int {
    return rd(c_int, pParse, Parse_nMem_off);
}
inline fn pSetNMem(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_nMem_off, v);
}
inline fn pIncNMem(pParse: ?*anyopaque) c_int {
    const v = pNMem(pParse) + 1;
    pSetNMem(pParse, v);
    return v;
}
inline fn pIncNTab(pParse: ?*anyopaque) c_int {
    const v = pNTab(pParse);
    pSetNTab(pParse, v + 1);
    return v;
}
inline fn pNested(pParse: ?*anyopaque) u8 {
    return base(pParse)[Parse_nested_off];
}
inline fn pPTriggerTab(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pTriggerTab_off);
}
inline fn pBReturning(pParse: ?*anyopaque) bool {
    return (base(pParse)[Parse_bft_byte] & BFT_bReturning) != 0;
}

inline fn dbFlags(db: ?*anyopaque) u64 {
    return rd(u64, db, sqlite3_flags_off);
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}
inline fn dbAtZDbSName(db: ?*anyopaque, i: c_int) ?[*:0]const u8 {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, db, sqlite3_aDb_off).?);
    const slot: ?*anyopaque = @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Db);
    return rd(?[*:0]const u8, slot, Db_zDbSName_off);
}

inline fn tabZName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Table_zName_off);
}
inline fn tabPSchema(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pSchema_off);
}
inline fn tabPIndex(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pIndex_off);
}
inline fn tabIPKey(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_iPKey_off);
}
inline fn tabNCol(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_nCol_off);
}
inline fn tabTabFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tabFlags_off);
}
inline fn tabETabType(p: ?*anyopaque) u8 {
    return base(p)[Table_eTabType_off];
}
inline fn tabIsVirtual(p: ?*anyopaque) bool {
    return tabETabType(p) == 1; // TABTYP_VTAB (sqliteInt.h: NORM=0, VTAB=1, VIEW=2)
}
inline fn tabIsView(p: ?*anyopaque) bool {
    return tabETabType(p) == 2; // TABTYP_VIEW
}
inline fn tabHasRowid(p: ?*anyopaque) bool {
    return (tabTabFlags(p) & TF_WithoutRowid) == 0;
}
inline fn tabColAt(p: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Table_aCol_off).?);
    return @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Column);
}

inline fn colZCnName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Column_zCnName_off);
}
inline fn colAffinity(p: ?*anyopaque) u8 {
    return base(p)[Column_affinity_off];
}
inline fn colIDflt(p: ?*anyopaque) u16 {
    return rd(u16, p, Column_iDflt_off);
}
inline fn colColFlags(p: ?*anyopaque) u16 {
    return rd(u16, p, Column_colFlags_off);
}

inline fn idxPNext(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pNext_off);
}
inline fn idxNKeyCol(p: ?*anyopaque) u16 {
    return rd(u16, p, Index_nKeyCol_off);
}
inline fn idxNColumn(p: ?*anyopaque) u16 {
    return rd(u16, p, Index_nColumn_off);
}
inline fn idxOnError(p: ?*anyopaque) u8 {
    return base(p)[Index_onError_off];
}
inline fn idxPPartIdxWhere(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pPartIdxWhere_off);
}
inline fn idxPColExpr(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_aColExpr_off);
}
inline fn idxAiColumn(p: ?*anyopaque, i: usize) i16 {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_aiColumn_off).?);
    const q: *align(1) const i16 = @ptrCast(a + i * @sizeOf(i16));
    return q.*;
}
// Index.aColExpr->a[i].pExpr
inline fn idxColExprAt(p: ?*anyopaque, i: usize) ?*anyopaque {
    const pList = idxPColExpr(p);
    // ExprList.a is an INLINE array at ExprList_a_off — take its address, do not deref.
    const a: [*]u8 = @as([*]u8, @ptrCast(pList.?)) + ExprList_a_off;
    return rd(?*anyopaque, @as(?*anyopaque, @ptrCast(a + i * sizeof_ExprList_item)), ExprList_item_pExpr_off);
}

inline fn elNExpr(p: ?*anyopaque) c_int {
    return rd(c_int, p, ExprList_nExpr_off);
}
inline fn elItem(p: ?*anyopaque, i: usize) ?*anyopaque {
    // ExprList.a is an INLINE array at ExprList_a_off — take its address.
    const a: [*]u8 = @as([*]u8, @ptrCast(p.?)) + ExprList_a_off;
    return @ptrCast(a + i * sizeof_ExprList_item);
}
inline fn elPExpr(p: ?*anyopaque, i: usize) ?*anyopaque {
    return rd(?*anyopaque, elItem(p, i), ExprList_item_pExpr_off);
}
inline fn elZEName(p: ?*anyopaque, i: usize) ?[*:0]const u8 {
    return rd(?[*:0]const u8, elItem(p, i), ExprList_item_zEName_off);
}

inline fn srcNSrc(p: ?*anyopaque) c_int {
    return rd(c_int, p, SrcList_nSrc_off);
}
inline fn srcItem0(p: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(p) + SrcList_a_off);
}
inline fn itemSetICursor(pItem: ?*anyopaque, v: c_int) void {
    wr(c_int, pItem, SrcItem_iCursor_off, v);
}
inline fn itemICursor(pItem: ?*anyopaque) c_int {
    return rd(c_int, pItem, SrcItem_iCursor_off);
}
inline fn itemSetColUsed(pItem: ?*anyopaque, v: u64) void {
    wr(u64, pItem, SrcItem_colUsed_off, v);
}

inline fn exprSetIColumn(p: ?*anyopaque, v: i16) void {
    wr(i16, p, Expr_iColumn_off, v);
}
inline fn exprSetOp2(p: ?*anyopaque, v: u8) void {
    base(p)[Expr_op2_off] = v;
}

inline fn upIDataCur(p: ?*anyopaque) c_int {
    return rd(c_int, p, Upsert_iDataCur_off);
}
inline fn upIIdxCur(p: ?*anyopaque) c_int {
    return rd(c_int, p, Upsert_iIdxCur_off);
}

inline fn keyInfoSetNAllField(p: ?*anyopaque, v: u16) void {
    wr(u16, p, KeyInfo_nAllField_off, v);
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ═════════════════
extern fn sqlite3VdbeDb(v: ?*anyopaque) ?*anyopaque;
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeMakeLabel(pParse: ?*anyopaque) c_int;
extern fn sqlite3VdbeCurrentAddr(p: ?*anyopaque) c_int;
extern fn sqlite3VdbeAddOp0(p: ?*anyopaque, op: c_int) c_int;
extern fn sqlite3VdbeAddOp1(p: ?*anyopaque, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*:0]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeChangeP5(p: ?*anyopaque, p5: u16) void;
extern fn sqlite3VdbeChangeToNoop(p: ?*anyopaque, addr: c_int) c_int;
extern fn sqlite3VdbeJumpHere(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeJumpHereOrPopInst(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeResolveLabel(p: ?*anyopaque, x: c_int) void;
extern fn sqlite3VdbeAppendP4(p: ?*anyopaque, pP4: ?*anyopaque, p4type: c_int) void;
extern fn sqlite3VdbeCountChanges(v: ?*anyopaque) void;

extern fn sqlite3ValueFromExpr(db: ?*anyopaque, pExpr: ?*const anyopaque, enc: u8, aff: u8, ppVal: *?*anyopaque) c_int;
extern fn sqlite3ColumnExpr(pTab: ?*anyopaque, pCol: ?*anyopaque) ?*anyopaque;

extern fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;

extern fn sqlite3ExprReferencesUpdatedColumn(pExpr: ?*anyopaque, aXRef: [*c]c_int, chngRowid: c_int) c_int;
extern fn sqlite3PExpr(pParse: ?*anyopaque, op: c_int, pLeft: ?*anyopaque, pRight: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprListAppend(pParse: ?*anyopaque, pList: ?*anyopaque, pExpr: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprCode(pParse: ?*anyopaque, pExpr: ?*anyopaque, target: c_int) void;
extern fn sqlite3ExprIfFalse(pParse: ?*anyopaque, pExpr: ?*anyopaque, dest: c_int, jumpIfNull: c_int) void;
extern fn sqlite3ExprCodeGetColumnOfTable(v: ?*anyopaque, pTab: ?*anyopaque, iCur: c_int, iCol: c_int, regOut: c_int) void;

extern fn sqlite3SrcListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3SrcListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SrcListLookup(pParse: ?*anyopaque, pSrc: ?*anyopaque) ?*anyopaque;

extern fn sqlite3SelectNew(pParse: ?*anyopaque, pEList: ?*anyopaque, pSrc: ?*anyopaque, pWhere: ?*anyopaque, pGroupBy: ?*anyopaque, pHaving: ?*anyopaque, pOrderBy: ?*anyopaque, selFlags: u32, pLimit: ?*anyopaque) ?*anyopaque;
extern fn sqlite3Select(pParse: ?*anyopaque, p: ?*anyopaque, pDest: ?*anyopaque) c_int;
extern fn sqlite3SelectDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SelectDestInit(pDest: ?*anyopaque, eDest: c_int, iParm: c_int) void;

extern fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) c_int;
extern fn sqlite3PrimaryKeyIndex(pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3KeyInfoOfIndex(pParse: ?*anyopaque, pIdx: ?*anyopaque) ?*anyopaque;
extern fn sqlite3IndexAffinityStr(db: ?*anyopaque, pIdx: ?*anyopaque) ?[*:0]const u8;

extern fn sqlite3TriggersExist(pParse: ?*anyopaque, pTab: ?*anyopaque, op: c_int, pChanges: ?*anyopaque, pMask: *c_int) ?*anyopaque;
extern fn sqlite3TriggerColmask(pParse: ?*anyopaque, pTrigger: ?*anyopaque, pChanges: ?*anyopaque, isNew: c_int, tr_tm: c_int, pTab: ?*anyopaque, orconf: c_int) u32;
extern fn sqlite3CodeRowTrigger(pParse: ?*anyopaque, pTrigger: ?*anyopaque, op: c_int, pChanges: ?*anyopaque, tr_tm: c_int, pTab: ?*anyopaque, reg: c_int, orconf: c_int, ignoreJump: c_int) void;

extern fn sqlite3ViewGetColumnNames(pParse: ?*anyopaque, pTab: ?*anyopaque) c_int;
extern fn sqlite3IsReadOnly(pParse: ?*anyopaque, pTab: ?*anyopaque, pTrigger: ?*anyopaque) c_int;
extern fn sqlite3MaterializeView(pParse: ?*anyopaque, pTab: ?*anyopaque, pWhere: ?*anyopaque, pOrderBy: ?*anyopaque, pLimit: ?*anyopaque, iCur: c_int) void;

extern fn sqlite3ColumnIndex(pTab: ?*anyopaque, zCol: ?[*:0]const u8) c_int;
extern fn sqlite3IsRowid(z: ?[*:0]const u8) c_int;
extern fn sqlite3ResolveExprNames(pNC: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;

extern fn sqlite3FkRequired(pParse: ?*anyopaque, pTab: ?*anyopaque, aChange: [*c]c_int, chngRowid: c_int) c_int;
extern fn sqlite3FkOldmask(pParse: ?*anyopaque, pTab: ?*anyopaque) u32;
extern fn sqlite3FkCheck(pParse: ?*anyopaque, pTab: ?*anyopaque, regOld: c_int, regNew: c_int, aChange: [*c]c_int, chngRowid: c_int) void;
extern fn sqlite3FkActions(pParse: ?*anyopaque, pTab: ?*anyopaque, pChanges: ?*anyopaque, regOld: c_int, aChange: [*c]c_int, chngRowid: c_int) void;

extern fn sqlite3MultiWrite(pParse: ?*anyopaque) void;
extern fn sqlite3BeginWriteOperation(pParse: ?*anyopaque, setStatement: c_int, iDb: c_int) void;
extern fn sqlite3AutoincrementEnd(pParse: ?*anyopaque) void;
extern fn sqlite3CodeChangeCount(v: ?*anyopaque, regCounter: c_int, zColName: [*:0]const u8) void;

extern fn sqlite3WhereBegin(pParse: ?*anyopaque, pTabList: ?*anyopaque, pWhere: ?*anyopaque, pOrderBy: ?*anyopaque, pResultSet: ?*anyopaque, pSelect: ?*anyopaque, wctrlFlags: u16, iAuxArg: c_int) ?*anyopaque;
extern fn sqlite3WhereEnd(pWInfo: ?*anyopaque) void;
extern fn sqlite3WhereOkOnePass(pWInfo: ?*anyopaque, aiCur: [*c]c_int) c_int;
extern fn sqlite3WhereUsesDeferredSeek(pWInfo: ?*anyopaque) c_int;

extern fn sqlite3OpenTableAndIndices(pParse: ?*anyopaque, pTab: ?*anyopaque, op: c_int, p5: u8, iBase: c_int, aToOpen: [*c]u8, piDataCur: *c_int, piIdxCur: *c_int) c_int;
extern fn sqlite3GenerateConstraintChecks(pParse: ?*anyopaque, pTab: ?*anyopaque, aRegIdx: [*c]c_int, iDataCur: c_int, iIdxCur: c_int, regNewData: c_int, regOldData: c_int, pkChng: u8, overrideError: u8, ignoreDest: c_int, pbMayReplace: *c_int, aiChng: [*c]c_int, pUpsert: ?*anyopaque) void;
extern fn sqlite3GenerateRowIndexDelete(pParse: ?*anyopaque, pTab: ?*anyopaque, iDataCur: c_int, iIdxCur: c_int, aRegIdx: [*c]c_int, iIdxNoSeek: c_int) void;
extern fn sqlite3CompleteInsertion(pParse: ?*anyopaque, pTab: ?*anyopaque, iDataCur: c_int, iIdxCur: c_int, regNewData: c_int, aRegIdx: [*c]c_int, update_flags: c_int, appendBias: c_int, useSeekResult: c_int) void;
extern fn sqlite3TableAffinity(v: ?*anyopaque, pTab: ?*anyopaque, iReg: c_int) void;
extern fn sqlite3ComputeGeneratedColumns(pParse: ?*anyopaque, iRegStore: c_int, pTab: ?*anyopaque) void;
extern fn sqlite3TableColumnToStorage(pTab: ?*anyopaque, iCol: i16) i16;

extern fn sqlite3GetVTable(db: ?*anyopaque, pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VtabMakeWritable(pParse: ?*anyopaque, pTab: ?*anyopaque) void;
extern fn sqlite3MayAbort(pParse: ?*anyopaque) void;

// Authorization (real fns; OMIT_AUTHORIZATION OFF)
extern fn sqlite3AuthCheck(pParse: ?*anyopaque, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;
extern fn sqlite3AuthContextPush(pParse: ?*anyopaque, pContext: ?*anyopaque, zContext: ?[*:0]const u8) void;
extern fn sqlite3AuthContextPop(pContext: ?*anyopaque) void;
const SQLITE_UPDATE: c_int = 23;
const SQLITE_DENY: c_int = 1;
const SQLITE_IGNORE: c_int = 2;

// ═══ MASKBIT32 ═══════════════════════════════════════════════════════════════
inline fn maskbit32(i: usize) u32 {
    return @as(u32, 1) << @intCast(i);
}

// ═══ sqlite3ColumnDefault ════════════════════════════════════════════════════
// ENC(db): u8 enc field of sqlite3 (offset config-invariant).
const sqlite3_enc_off = off("sqlite3_enc", 100);
inline fn dbEnc(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_enc_off];
}

export fn sqlite3ColumnDefault(v: ?*anyopaque, pTab: ?*anyopaque, i: c_int, iReg: c_int) callconv(.c) void {
    // assert pTab!=0 && pTab->nCol>i
    const pCol = tabColAt(pTab, i);
    if (colIDflt(pCol) != 0) {
        var pValue: ?*anyopaque = null;
        const enc = dbEnc(sqlite3VdbeDb(v));
        // assert !IsView(pTab)
        _ = sqlite3ValueFromExpr(
            sqlite3VdbeDb(v),
            sqlite3ColumnExpr(pTab, pCol),
            enc,
            colAffinity(pCol),
            &pValue,
        );
        if (pValue != null) {
            sqlite3VdbeAppendP4(v, pValue, P4_MEM);
        }
    }
    if (colAffinity(pCol) == SQLITE_AFF_REAL and !tabIsVirtual(pTab)) {
        _ = sqlite3VdbeAddOp1(v, OP_RealAffinity, iReg);
    }
}

// ═══ indexColumnIsBeingUpdated (static) ══════════════════════════════════════
fn indexColumnIsBeingUpdated(pIdx: ?*anyopaque, iCol: usize, aXRef: [*c]c_int, chngRowid: c_int) bool {
    const iIdxCol: i16 = idxAiColumn(pIdx, iCol);
    // assert iIdxCol != XN_ROWID
    if (iIdxCol >= 0) {
        return aXRef[@intCast(iIdxCol)] >= 0;
    }
    // assert iIdxCol == XN_EXPR
    return sqlite3ExprReferencesUpdatedColumn(idxColExprAt(pIdx, iCol), aXRef, chngRowid) != 0;
}

// ═══ indexWhereClauseMightChange (static) ════════════════════════════════════
fn indexWhereClauseMightChange(pIdx: ?*anyopaque, aXRef: [*c]c_int, chngRowid: c_int) bool {
    if (idxPPartIdxWhere(pIdx) == null) return false;
    return sqlite3ExprReferencesUpdatedColumn(idxPPartIdxWhere(pIdx), aXRef, chngRowid) != 0;
}

// ═══ exprRowColumn (static) ══════════════════════════════════════════════════
fn exprRowColumn(pParse: ?*anyopaque, iCol: c_int) ?*anyopaque {
    const pRet = sqlite3PExpr(pParse, TK_ROW, null, null);
    if (pRet != null) exprSetIColumn(pRet, @intCast(iCol + 1));
    return pRet;
}

// ═══ updateFromSelect (static) ═══════════════════════════════════════════════
fn updateFromSelect(
    pParse: ?*anyopaque,
    iEph: c_int,
    pPk: ?*anyopaque,
    pChanges: ?*anyopaque,
    pTabList: ?*anyopaque,
    pWhere: ?*anyopaque,
    pOrderBy: ?*anyopaque,
    pLimit: ?*anyopaque,
) void {
    _ = pOrderBy;
    _ = pLimit;
    var dest: [SelectDest_sz]u8 align(8) = undefined;
    const pDest: ?*anyopaque = @ptrCast(&dest);
    var pSelect: ?*anyopaque = null;
    var pList: ?*anyopaque = null;
    const pGrp: ?*anyopaque = null;
    const pLimit2: ?*anyopaque = null;
    const pOrderBy2: ?*anyopaque = null;
    const db = pDb(pParse);
    const pTab = rd(?*anyopaque, srcItem0(pTabList), SrcItem_pSTab_off);
    var eDest: c_int = undefined;

    const pSrc = sqlite3SrcListDup(db, pTabList, 0);
    const pWhere2 = sqlite3ExprDup(db, pWhere, 0);

    // assert pTabList->nSrc>1
    if (pSrc != null) {
        // assert pSrc->a[0].fg.notCte
        itemSetICursor(srcItem0(pSrc), -1);
        // pSrc->a[0].pSTab->nTabRef--
        const pStab0 = rd(?*anyopaque, srcItem0(pSrc), SrcItem_pSTab_off);
        wr(u32, pStab0, Table_nTabRef_off, rd(u32, pStab0, Table_nTabRef_off) - 1);
        wr(?*anyopaque, srcItem0(pSrc), SrcItem_pSTab_off, null);
    }
    if (pPk) |pk| {
        var i: usize = 0;
        const nKeyCol: usize = @intCast(idxNKeyCol(pk));
        while (i < nKeyCol) : (i += 1) {
            const pNew = exprRowColumn(pParse, idxAiColumn(pk, i));
            pList = sqlite3ExprListAppend(pParse, pList, pNew);
        }
        eDest = if (tabIsVirtual(pTab)) SRT_Table else SRT_Upfrom;
    } else if (tabIsView(pTab)) {
        var i: c_int = 0;
        while (i < tabNCol(pTab)) : (i += 1) {
            pList = sqlite3ExprListAppend(pParse, pList, exprRowColumn(pParse, i));
        }
        eDest = SRT_Table;
    } else {
        eDest = if (tabIsVirtual(pTab)) SRT_Table else SRT_Upfrom;
        pList = sqlite3ExprListAppend(pParse, null, sqlite3PExpr(pParse, TK_ROW, null, null));
    }
    // assert pChanges!=0 || db->mallocFailed
    if (pChanges != null) {
        var i: usize = 0;
        const n: usize = @intCast(elNExpr(pChanges));
        while (i < n) : (i += 1) {
            pList = sqlite3ExprListAppend(pParse, pList, sqlite3ExprDup(db, elPExpr(pChanges, i), 0));
        }
    }
    pSelect = sqlite3SelectNew(pParse, pList, pSrc, pWhere2, pGrp, null, pOrderBy2, SF_UFSrcCheck | SF_IncludeHidden | SF_UpdateFrom, pLimit2);
    if (pSelect != null) {
        const sf = rd(u32, pSelect, Select_selFlags_off);
        wr(u32, pSelect, Select_selFlags_off, sf | SF_OrderByReqd);
    }
    sqlite3SelectDestInit(pDest, eDest, iEph);
    // dest.iSDParm2 = pPk ? pPk->nKeyCol : -1
    wr(c_int, pDest, SelectDest_iSDParm2_off, if (pPk) |pk| @intCast(idxNKeyCol(pk)) else -1);
    _ = sqlite3Select(pParse, pSelect, pDest);
    sqlite3SelectDelete(db, pSelect);
}

const SelectDest_sz: usize = 40;
const Select_selFlags_off = off("Select_selFlags", 4);
const SrcItem_pSTab_off = off("SrcItem_pSTab", 16);
const Table_nTabRef_off = off("Table_nTabRef", 44);

// ═══ sqlite3Update ═══════════════════════════════════════════════════════════
export fn sqlite3Update(
    pParse: ?*anyopaque,
    pTabList_in: ?*anyopaque,
    pChanges_in: ?*anyopaque,
    pWhere_in: ?*anyopaque,
    onError: c_int,
    pOrderBy_in: ?*anyopaque,
    pLimit_in: ?*anyopaque,
    pUpsert: ?*anyopaque,
) callconv(.c) void {
    var pTabList = pTabList_in;
    const pChanges = pChanges_in;
    var pWhere = pWhere_in;
    const pOrderBy = pOrderBy_in;
    const pLimit = pLimit_in;

    var i: c_int = undefined;
    var j: c_int = undefined;
    var k: c_int = undefined;
    var pTab: ?*anyopaque = undefined;
    var addrTop: c_int = 0;
    var pWInfo: ?*anyopaque = null;
    var v: ?*anyopaque = undefined;
    var pIdx: ?*anyopaque = undefined;
    var pPk: ?*anyopaque = undefined;
    var nIdx: c_int = undefined;
    var nAllIdx: c_int = undefined;
    var iBaseCur: c_int = undefined;
    var iDataCur: c_int = undefined;
    var iIdxCur: c_int = undefined;
    var db: ?*anyopaque = undefined;
    var aXRef: [*c]c_int = null;
    var aRegIdx: [*c]c_int = null;
    var aToOpen: [*c]u8 = undefined;
    var chngPk: u8 = undefined;
    var chngRowid: u8 = undefined;
    var chngKey: u8 = undefined;
    var pRowidExpr: ?*anyopaque = null;
    var iRowidExpr: c_int = -1;
    // AuthContext sContext — { const char *zAuthContext; AuthContext *pParent; } => 16 bytes
    var sContext: [16]u8 align(8) = @splat(0);
    var sNC: [sizeof_NameContext]u8 align(8) = @splat(0);
    var iDb: c_int = undefined;
    var eOnePass: c_int = undefined;
    var hasFK: c_int = undefined;
    var labelBreak: c_int = undefined;
    var labelContinue: c_int = undefined;
    var flags: u16 = undefined;

    var isView: c_int = undefined;
    var pTrigger: ?*anyopaque = undefined;
    var tmask: c_int = undefined;

    var newmask: c_int = undefined;
    var iEph: c_int = 0;
    var nKey: c_int = 0;
    var aiCurOnePass: [2]c_int = .{ 0, 0 };
    var addrOpen: c_int = 0;
    var iPk: c_int = 0;
    var nPk: i16 = 0;
    var bReplace: c_int = 0;
    var bFinishSeek: c_int = 1;
    var nChangeFrom: c_int = 0;

    var regRowCount: c_int = 0;
    var regOldRowid: c_int = 0;
    var regNewRowid: c_int = 0;
    var regNew: c_int = 0;
    var regOld: c_int = 0;
    var regRowSet: c_int = 0;
    var regKey: c_int = 0;

    db = pDb(pParse);
    if (pNErr(pParse) != 0) {
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }

    // Locate the table which we want to update.
    pTab = sqlite3SrcListLookup(pParse, pTabList);
    if (pTab == null) {
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }
    iDb = sqlite3SchemaToIndex(pDb(pParse), tabPSchema(pTab));

    // Triggers / view detection.
    tmask = 0;
    pTrigger = sqlite3TriggersExist(pParse, pTab, TK_UPDATE, pChanges, &tmask);
    isView = if (tabIsView(pTab)) 1 else 0;
    // assert pTrigger || tmask==0

    // FROM clause → nChangeFrom.
    nChangeFrom = if (srcNSrc(pTabList) > 1) elNExpr(pChanges) else 0;
    // assert nChangeFrom==0 || pUpsert==0

    if (sqlite3ViewGetColumnNames(pParse, pTab) != 0) {
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }
    if (sqlite3IsReadOnly(pParse, pTab, pTrigger) != 0) {
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }

    // Allocate cursors for the main table and indices.
    iBaseCur = pNTab(pParse);
    iDataCur = iBaseCur;
    pSetNTab(pParse, pNTab(pParse) + 1);
    iIdxCur = iDataCur + 1;
    pPk = if (tabHasRowid(pTab)) null else sqlite3PrimaryKeyIndex(pTab);
    nIdx = 0;
    pIdx = tabPIndex(pTab);
    while (pIdx != null) : (pIdx = idxPNext(pIdx)) {
        if (pPk == pIdx) {
            iDataCur = pNTab(pParse);
        }
        pSetNTab(pParse, pNTab(pParse) + 1);
        nIdx += 1;
    }
    if (pUpsert != null) {
        // On an UPSERT, reuse the same cursors already opened by INSERT.
        iDataCur = upIDataCur(pUpsert);
        iIdxCur = upIIdxCur(pUpsert);
        pSetNTab(pParse, iBaseCur);
    }
    itemSetICursor(srcItem0(pTabList), iDataCur);

    // Allocate aXRef[], aRegIdx[], aToOpen[].
    const nCol: c_int = tabNCol(pTab);
    {
        const szInts: u64 = @as(u64, @intCast(@sizeOf(c_int))) * @as(u64, @intCast(nCol + nIdx + 1));
        const szBytes: u64 = @as(u64, @intCast(nIdx + 2));
        aXRef = @ptrCast(@alignCast(sqlite3DbMallocRawNN(db, szInts + szBytes)));
    }
    if (aXRef == null) {
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }
    aRegIdx = aXRef + @as(usize, @intCast(nCol));
    aToOpen = @ptrCast(aRegIdx + @as(usize, @intCast(nIdx + 1)));
    @memset(aToOpen[0..@intCast(nIdx + 1)], 1);
    aToOpen[@intCast(nIdx + 1)] = 0;
    i = 0;
    while (i < nCol) : (i += 1) aXRef[@intCast(i)] = -1;

    // Name-context.
    ncSetPParse(@ptrCast(&sNC), pParse);
    ncSetPSrcList(@ptrCast(&sNC), pTabList);
    // sNC.uNC.pUpsert = pUpsert
    wr(?*anyopaque, @ptrCast(&sNC), NameContext_uNC_off, pUpsert);
    wr(c_int, @ptrCast(&sNC), NameContext_ncFlags_off, NC_UUpsert);

    v = sqlite3GetVdbe(pParse);
    if (v == null) {
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }

    // Resolve SET column names; build aXRef; check authorization.
    chngRowid = 0;
    chngPk = 0;
    i = 0;
    while (i < elNExpr(pChanges)) : (i += 1) {
        if (nChangeFrom == 0 and sqlite3ResolveExprNames(@ptrCast(&sNC), elPExpr(pChanges, @intCast(i))) != 0) {
            cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
            return;
        }
        j = sqlite3ColumnIndex(pTab, elZEName(pChanges, @intCast(i)));
        if (j >= 0) {
            if (j == tabIPKey(pTab)) {
                chngRowid = 1;
                pRowidExpr = elPExpr(pChanges, @intCast(i));
                iRowidExpr = i;
            } else if (pPk != null and (colColFlags(tabColAt(pTab, j)) & COLFLAG_PRIMKEY) != 0) {
                chngPk = 1;
            } else if ((colColFlags(tabColAt(pTab, j)) & COLFLAG_GENERATED) != 0) {
                sqlite3ErrorMsg(pParse, "cannot UPDATE generated column \"%s\"", colZCnName(tabColAt(pTab, j)));
                cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
                return;
            }
            aXRef[@intCast(j)] = i;
        } else {
            if (pPk == null and sqlite3IsRowid(elZEName(pChanges, @intCast(i))) != 0) {
                j = -1;
                chngRowid = 1;
                pRowidExpr = elPExpr(pChanges, @intCast(i));
                iRowidExpr = i;
            } else {
                sqlite3ErrorMsg(pParse, "no such column: %s", elZEName(pChanges, @intCast(i)));
                // pParse->checkSchema = 1  (bft byte, bit 0x100 of bitgroup) — set via byte
                setCheckSchema(pParse);
                cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
                return;
            }
        }
        // Authorization (OMIT_AUTHORIZATION OFF).
        {
            const rc = sqlite3AuthCheck(
                pParse,
                SQLITE_UPDATE,
                tabZName(pTab),
                if (j < 0) "ROWID" else colZCnName(tabColAt(pTab, j)),
                dbAtZDbSName(db, iDb),
            );
            if (rc == SQLITE_DENY) {
                cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
                return;
            } else if (rc == SQLITE_IGNORE) {
                aXRef[@intCast(j)] = -1;
            }
        }
    }
    // assert (chngRowid & chngPk)==0
    chngKey = chngRowid + chngPk;

    // Mark generated columns whose generator references a changing column.
    if ((tabTabFlags(pTab) & TF_HasGenerated) != 0) {
        var bProgress: bool = true;
        while (bProgress) {
            bProgress = false;
            i = 0;
            while (i < nCol) : (i += 1) {
                if (aXRef[@intCast(i)] >= 0) continue;
                if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_GENERATED) == 0) continue;
                if (sqlite3ExprReferencesUpdatedColumn(sqlite3ColumnExpr(pTab, tabColAt(pTab, i)), aXRef, chngRowid) != 0) {
                    aXRef[@intCast(i)] = 99999;
                    bProgress = true;
                }
            }
        }
    }

    // Reset (or set, for vtab) the colUsed mask.
    itemSetColUsed(srcItem0(pTabList), if (tabIsVirtual(pTab)) ALLBITS else 0);

    hasFK = sqlite3FkRequired(pParse, pTab, aXRef, chngKey);

    // Fill aRegIdx[]: a register per index that holds the key.
    if (onError == OE_Replace) bReplace = 1;
    nAllIdx = 0;
    pIdx = tabPIndex(pTab);
    while (pIdx != null) : ({
        pIdx = idxPNext(pIdx);
        nAllIdx += 1;
    }) {
        var reg: c_int = undefined;
        if (chngKey != 0 or hasFK > 1 or pIdx == pPk or indexWhereClauseMightChange(pIdx, aXRef, chngRowid)) {
            reg = pIncNMem(pParse);
            pSetNMem(pParse, pNMem(pParse) + @as(c_int, @intCast(idxNColumn(pIdx))));
        } else {
            reg = 0;
            var ic: usize = 0;
            const nk: usize = @intCast(idxNKeyCol(pIdx));
            while (ic < nk) : (ic += 1) {
                if (indexColumnIsBeingUpdated(pIdx, ic, aXRef, chngRowid)) {
                    reg = pIncNMem(pParse);
                    pSetNMem(pParse, pNMem(pParse) + @as(c_int, @intCast(idxNColumn(pIdx))));
                    if (onError == OE_Default and idxOnError(pIdx) == OE_Replace) {
                        bReplace = 1;
                    }
                    break;
                }
            }
        }
        if (reg == 0) aToOpen[@intCast(nAllIdx + 1)] = 0;
        aRegIdx[@intCast(nAllIdx)] = reg;
    }
    aRegIdx[@intCast(nAllIdx)] = pIncNMem(pParse); // register storing the table record
    if (bReplace != 0) {
        @memset(aToOpen[0..@intCast(nIdx + 1)], 1);
    }

    if (pNested(pParse) == 0) sqlite3VdbeCountChanges(v);
    sqlite3BeginWriteOperation(pParse, if (pTrigger != null or hasFK != 0) 1 else 0, iDb);

    // Allocate required registers.
    if (!tabIsVirtual(pTab)) {
        // assert aRegIdx[nAllIdx]==pParse->nMem
        regRowSet = aRegIdx[@intCast(nAllIdx)];
        regOldRowid = pIncNMem(pParse);
        regNewRowid = regOldRowid;
        if (chngPk != 0 or pTrigger != null or hasFK != 0) {
            regOld = pNMem(pParse) + 1;
            pSetNMem(pParse, pNMem(pParse) + nCol);
        }
        if (chngKey != 0 or pTrigger != null or hasFK != 0) {
            regNewRowid = pIncNMem(pParse);
        }
        regNew = pNMem(pParse) + 1;
        pSetNMem(pParse, pNMem(pParse) + nCol);
    }

    // View context.
    if (isView != 0) {
        sqlite3AuthContextPush(pParse, @ptrCast(&sContext), tabZName(pTab));
    }

    // Materialize a view into an ephemeral table.
    if (nChangeFrom == 0 and isView != 0) {
        sqlite3MaterializeView(pParse, pTab, pWhere, pOrderBy, pLimit, iDataCur);
        // pOrderBy = 0; pLimit = 0;  (locals; unused thereafter)
    }

    // Resolve WHERE column names.
    if (nChangeFrom == 0 and sqlite3ResolveExprNames(@ptrCast(&sNC), pWhere) != 0) {
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }

    // Virtual tables handled separately.
    if (tabIsVirtual(pTab)) {
        updateVirtualTable(pParse, pTabList, pTab, pChanges, pRowidExpr, aXRef, pWhere, onError);
        cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
        return;
    }

    labelBreak = sqlite3VdbeMakeLabel(pParse);
    labelContinue = labelBreak;

    // Initialize the count of updated rows.
    if ((dbFlags(db) & SQLITE_CountRows) != 0 and pPTriggerTab(pParse) == null and pNested(pParse) == 0 and !pBReturning(pParse) and pUpsert == null) {
        regRowCount = pIncNMem(pParse);
        _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, regRowCount);
    }

    if (nChangeFrom == 0 and tabHasRowid(pTab)) {
        _ = sqlite3VdbeAddOp3(v, OP_Null, 0, regRowSet, regOldRowid);
        iEph = pIncNTab(pParse);
        addrOpen = sqlite3VdbeAddOp3(v, OP_OpenEphemeral, iEph, 0, regRowSet);
    } else {
        // assert pPk!=0 || HasRowid(pTab)
        nPk = if (pPk != null) @intCast(idxNKeyCol(pPk)) else 0;
        iPk = pNMem(pParse) + 1;
        pSetNMem(pParse, pNMem(pParse) + nPk);
        pSetNMem(pParse, pNMem(pParse) + nChangeFrom);
        regKey = pIncNMem(pParse);
        if (pUpsert == null) {
            const nEphCol: c_int = @as(c_int, nPk) + nChangeFrom + (if (isView != 0) nCol else 0);
            iEph = pIncNTab(pParse);
            if (pPk != null) _ = sqlite3VdbeAddOp3(v, OP_Null, 0, iPk, iPk + nPk - 1);
            addrOpen = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, iEph, nEphCol);
            if (pPk != null) {
                const pKeyInfo = sqlite3KeyInfoOfIndex(pParse, pPk);
                if (pKeyInfo != null) {
                    keyInfoSetNAllField(pKeyInfo, @intCast(nEphCol));
                    sqlite3VdbeAppendP4(v, pKeyInfo, P4_KEYINFO);
                }
            }
            if (nChangeFrom != 0) {
                updateFromSelect(pParse, iEph, pPk, pChanges, pTabList, pWhere, pOrderBy, pLimit);
                if (isView != 0) iDataCur = iEph;
            }
        }
    }

    if (nChangeFrom != 0) {
        sqlite3MultiWrite(pParse);
        eOnePass = ONEPASS_OFF;
        nKey = nPk;
        regKey = iPk;
    } else {
        if (pUpsert != null) {
            pWInfo = null;
            eOnePass = ONEPASS_SINGLE;
            sqlite3ExprIfFalse(pParse, pWhere, labelBreak, SQLITE_JUMPIFNULL);
            bFinishSeek = 0;
        } else {
            flags = WHERE_ONEPASS_DESIRED;
            if (pNested(pParse) == 0 and pTrigger == null and hasFK == 0 and chngKey == 0 and bReplace == 0 and (pWhere == null or !exprHasSubquery(pWhere))) {
                flags |= WHERE_ONEPASS_MULTIROW;
            }
            pWInfo = sqlite3WhereBegin(pParse, pTabList, pWhere, null, null, null, flags, iIdxCur);
            if (pWInfo == null) {
                cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
                return;
            }
            eOnePass = sqlite3WhereOkOnePass(pWInfo, &aiCurOnePass);
            bFinishSeek = sqlite3WhereUsesDeferredSeek(pWInfo);
            if (eOnePass != ONEPASS_SINGLE) {
                sqlite3MultiWrite(pParse);
                if (eOnePass == ONEPASS_MULTI) {
                    const iCur = aiCurOnePass[1];
                    if (iCur >= 0 and iCur != iDataCur and aToOpen[@intCast(iCur - iBaseCur)] != 0) {
                        eOnePass = ONEPASS_OFF;
                    }
                }
            }
        }

        if (tabHasRowid(pTab)) {
            _ = sqlite3VdbeAddOp2(v, OP_Rowid, iDataCur, regOldRowid);
            if (eOnePass == ONEPASS_OFF) {
                aRegIdx[@intCast(nAllIdx)] = pIncNMem(pParse);
                _ = sqlite3VdbeAddOp3(v, OP_Insert, iEph, regRowSet, regOldRowid);
            } else {
                if (addrOpen != 0) _ = sqlite3VdbeChangeToNoop(v, addrOpen);
            }
        } else {
            i = 0;
            while (i < nPk) : (i += 1) {
                // assert pPk->aiColumn[i]>=0
                sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, idxAiColumn(pPk, @intCast(i)), iPk + i);
            }
            if (eOnePass != ONEPASS_OFF) {
                if (addrOpen != 0) _ = sqlite3VdbeChangeToNoop(v, addrOpen);
                nKey = nPk;
                regKey = iPk;
            } else {
                _ = sqlite3VdbeAddOp4(v, OP_MakeRecord, iPk, nPk, regKey, sqlite3IndexAffinityStr(db, pPk), nPk);
                _ = sqlite3VdbeAddOp4Int(v, OP_IdxInsert, iEph, regKey, iPk, nPk);
            }
        }
    }

    if (pUpsert == null) {
        if (nChangeFrom == 0 and eOnePass != ONEPASS_MULTI) {
            sqlite3WhereEnd(pWInfo);
        }

        if (isView == 0) {
            var addrOnce: c_int = 0;
            var iNotUsed1: c_int = 0;
            var iNotUsed2: c_int = 0;

            if (eOnePass != ONEPASS_OFF) {
                if (aiCurOnePass[0] >= 0) aToOpen[@intCast(aiCurOnePass[0] - iBaseCur)] = 0;
                if (aiCurOnePass[1] >= 0) aToOpen[@intCast(aiCurOnePass[1] - iBaseCur)] = 0;
            }

            if (eOnePass == ONEPASS_MULTI and (nIdx - @as(c_int, @intFromBool(aiCurOnePass[1] >= 0))) > 0) {
                addrOnce = sqlite3VdbeAddOp0(v, OP_Once);
            }
            _ = sqlite3OpenTableAndIndices(pParse, pTab, OP_OpenWrite, 0, iBaseCur, aToOpen, &iNotUsed1, &iNotUsed2);
            if (addrOnce != 0) {
                sqlite3VdbeJumpHereOrPopInst(v, addrOnce);
            }
        }

        // Top of the update loop.
        if (eOnePass != ONEPASS_OFF) {
            if (aiCurOnePass[0] != iDataCur and aiCurOnePass[1] != iDataCur) {
                // assert pPk
                _ = sqlite3VdbeAddOp4Int(v, OP_NotFound, iDataCur, labelBreak, regKey, nKey);
            }
            if (eOnePass != ONEPASS_SINGLE) {
                labelContinue = sqlite3VdbeMakeLabel(pParse);
            }
            _ = sqlite3VdbeAddOp2(v, OP_IsNull, if (pPk != null) regKey else regOldRowid, labelBreak);
        } else if (pPk != null or nChangeFrom != 0) {
            labelContinue = sqlite3VdbeMakeLabel(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_Rewind, iEph, labelBreak);
            addrTop = sqlite3VdbeCurrentAddr(v);
            if (nChangeFrom != 0) {
                if (isView == 0) {
                    if (pPk != null) {
                        i = 0;
                        while (i < nPk) : (i += 1) {
                            _ = sqlite3VdbeAddOp3(v, OP_Column, iEph, i, iPk + i);
                        }
                        _ = sqlite3VdbeAddOp4Int(v, OP_NotFound, iDataCur, labelContinue, iPk, nPk);
                    } else {
                        _ = sqlite3VdbeAddOp2(v, OP_Rowid, iEph, regOldRowid);
                        _ = sqlite3VdbeAddOp3(v, OP_NotExists, iDataCur, labelContinue, regOldRowid);
                    }
                }
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_RowData, iEph, regKey);
                _ = sqlite3VdbeAddOp4Int(v, OP_NotFound, iDataCur, labelContinue, regKey, 0);
            }
        } else {
            _ = sqlite3VdbeAddOp2(v, OP_Rewind, iEph, labelBreak);
            labelContinue = sqlite3VdbeMakeLabel(pParse);
            addrTop = sqlite3VdbeAddOp2(v, OP_Rowid, iEph, regOldRowid);
            _ = sqlite3VdbeAddOp3(v, OP_NotExists, iDataCur, labelContinue, regOldRowid);
        }
    }

    // Compute new rowid register.
    // assert chngKey || pTrigger || hasFK || regOldRowid==regNewRowid
    if (chngRowid != 0) {
        // assert iRowidExpr>=0
        if (nChangeFrom == 0) {
            sqlite3ExprCode(pParse, pRowidExpr, regNewRowid);
        } else {
            _ = sqlite3VdbeAddOp3(v, OP_Column, iEph, iRowidExpr, regNewRowid);
        }
        _ = sqlite3VdbeAddOp1(v, OP_MustBeInt, regNewRowid);
    }

    // Compute old pre-UPDATE content of the row if needed.
    if (chngPk != 0 or hasFK != 0 or pTrigger != null) {
        var oldmask: u32 = if (hasFK != 0) sqlite3FkOldmask(pParse, pTab) else 0;
        oldmask |= sqlite3TriggerColmask(pParse, pTrigger, pChanges, 0, TRIGGER_BEFORE | TRIGGER_AFTER, pTab, onError);
        i = 0;
        while (i < nCol) : (i += 1) {
            const colFlags: u32 = colColFlags(tabColAt(pTab, i));
            k = sqlite3TableColumnToStorage(pTab, @intCast(i)) + regOld;
            if (oldmask == 0xffffffff or (i < 32 and (oldmask & maskbit32(@intCast(i))) != 0) or (colFlags & COLFLAG_PRIMKEY) != 0) {
                sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, i, k);
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_Null, 0, k);
            }
        }
        if (chngRowid == 0 and pPk == null) {
            _ = sqlite3VdbeAddOp2(v, OP_Copy, regOldRowid, regNewRowid);
        }
    }

    // Populate regNew with the new row data.
    newmask = @bitCast(sqlite3TriggerColmask(pParse, pTrigger, pChanges, 1, TRIGGER_BEFORE, pTab, onError));
    i = 0;
    k = regNew;
    while (i < nCol) : ({
        i += 1;
        k += 1;
    }) {
        if (i == tabIPKey(pTab)) {
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, k);
        } else if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_GENERATED) != 0) {
            if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_VIRTUAL) != 0) k -= 1;
        } else {
            j = aXRef[@intCast(i)];
            if (j >= 0) {
                if (nChangeFrom != 0) {
                    const nOff: c_int = if (isView != 0) nCol else nPk;
                    // assert eOnePass==ONEPASS_OFF
                    _ = sqlite3VdbeAddOp3(v, OP_Column, iEph, nOff + j, k);
                } else {
                    sqlite3ExprCode(pParse, elPExpr(pChanges, @intCast(j)), k);
                }
            } else if ((tmask & TRIGGER_BEFORE) == 0 or i > 31 or (newmask & @as(c_int, @bitCast(maskbit32(@intCast(i))))) != 0) {
                sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, i, k);
                bFinishSeek = 0;
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_Null, 0, k);
            }
        }
    }
    if ((tabTabFlags(pTab) & TF_HasGenerated) != 0) {
        sqlite3ComputeGeneratedColumns(pParse, regNew, pTab);
    }

    // Fire BEFORE UPDATE triggers.
    if ((tmask & TRIGGER_BEFORE) != 0) {
        sqlite3TableAffinity(v, pTab, regNew);
        sqlite3CodeRowTrigger(pParse, pTrigger, TK_UPDATE, pChanges, TRIGGER_BEFORE, pTab, regOldRowid, onError, labelContinue);

        if (isView == 0) {
            if (pPk != null) {
                _ = sqlite3VdbeAddOp4Int(v, OP_NotFound, iDataCur, labelContinue, regKey, nKey);
            } else {
                _ = sqlite3VdbeAddOp3(v, OP_NotExists, iDataCur, labelContinue, regOldRowid);
            }

            // Reload unmodified columns after BEFORE triggers.
            i = 0;
            k = regNew;
            while (i < nCol) : ({
                i += 1;
                k += 1;
            }) {
                if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_GENERATED) != 0) {
                    if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_VIRTUAL) != 0) k -= 1;
                } else if (aXRef[@intCast(i)] < 0 and i != tabIPKey(pTab)) {
                    sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, i, k);
                }
            }
            if ((tabTabFlags(pTab) & TF_HasGenerated) != 0) {
                sqlite3ComputeGeneratedColumns(pParse, regNew, pTab);
            }
        }
    }

    if (isView == 0) {
        // Constraint checks.
        // assert regOldRowid>0
        sqlite3GenerateConstraintChecks(pParse, pTab, aRegIdx, iDataCur, iIdxCur, regNewRowid, regOldRowid, chngKey, @intCast(onError), labelContinue, &bReplace, aXRef, null);

        // Reseek iDataCur if it may have moved.
        if (bReplace != 0 or chngKey != 0) {
            if (pPk != null) {
                _ = sqlite3VdbeAddOp4Int(v, OP_NotFound, iDataCur, labelContinue, regKey, nKey);
            } else {
                _ = sqlite3VdbeAddOp3(v, OP_NotExists, iDataCur, labelContinue, regOldRowid);
            }
        }

        // FK constraint checks.
        if (hasFK != 0) {
            sqlite3FkCheck(pParse, pTab, regOldRowid, 0, aXRef, chngKey);
        }

        // Delete index entries for the current record.
        sqlite3GenerateRowIndexDelete(pParse, pTab, iDataCur, iIdxCur, aRegIdx, -1);

        if (bFinishSeek != 0) {
            _ = sqlite3VdbeAddOp1(v, OP_FinishSeek, iDataCur);
        }

        // Delete the old record (PREUPDATE_HOOK ON).
        // assert regNew==regNewRowid+1
        _ = sqlite3VdbeAddOp3(v, OP_Delete, iDataCur, @intCast(OPFLAG_ISUPDATE | (if (hasFK > 1 or chngKey != 0) @as(u16, 0) else OPFLAG_ISNOOP)), regNewRowid);
        if (eOnePass == ONEPASS_MULTI) {
            // assert hasFK==0 && chngKey==0
            sqlite3VdbeChangeP5(v, OPFLAG_SAVEPOSITION);
        }
        if (pNested(pParse) == 0) {
            sqlite3VdbeAppendP4(v, pTab, P4_TABLE);
        }

        if (hasFK != 0) {
            sqlite3FkCheck(pParse, pTab, 0, regNewRowid, aXRef, chngKey);
        }

        // Insert the new index entries and the new record.
        sqlite3CompleteInsertion(pParse, pTab, iDataCur, iIdxCur, regNewRowid, aRegIdx, @intCast(OPFLAG_ISUPDATE | (if (eOnePass == ONEPASS_MULTI) OPFLAG_SAVEPOSITION else @as(u16, 0))), 0, 0);

        // FK cascade actions.
        if (hasFK != 0) {
            sqlite3FkActions(pParse, pTab, pChanges, regOldRowid, aXRef, chngKey);
        }
    }

    // Increment the row counter.
    if (regRowCount != 0) {
        _ = sqlite3VdbeAddOp2(v, OP_AddImm, regRowCount, 1);
    }

    if (pTrigger != null) {
        sqlite3CodeRowTrigger(pParse, pTrigger, TK_UPDATE, pChanges, TRIGGER_AFTER, pTab, regOldRowid, onError, labelContinue);
    }

    // Loop to next record.
    if (eOnePass == ONEPASS_SINGLE) {
        // Nothing to do.
    } else if (eOnePass == ONEPASS_MULTI) {
        sqlite3VdbeResolveLabel(v, labelContinue);
        sqlite3WhereEnd(pWInfo);
    } else {
        sqlite3VdbeResolveLabel(v, labelContinue);
        _ = sqlite3VdbeAddOp2(v, OP_Next, iEph, addrTop);
    }
    sqlite3VdbeResolveLabel(v, labelBreak);

    // Update sqlite_sequence for autoincrement tables.
    if (pNested(pParse) == 0 and pPTriggerTab(pParse) == null and pUpsert == null) {
        sqlite3AutoincrementEnd(pParse);
    }

    // Return the number of rows changed.
    if (regRowCount != 0) {
        sqlite3CodeChangeCount(v, regRowCount, "rows updated");
    }

    cleanup(db, aXRef, pTabList, pChanges, pWhere, &sContext);
    _ = &pTabList;
    _ = &pWhere;
}

// cleanup: the `update_cleanup:` label tail.
fn cleanup(db: ?*anyopaque, aXRef: [*c]c_int, pTabList: ?*anyopaque, pChanges: ?*anyopaque, pWhere: ?*anyopaque, sContext: *anyopaque) void {
    sqlite3AuthContextPop(sContext);
    sqlite3DbFree(db, @ptrCast(aXRef)); // also frees aRegIdx[] and aToOpen[]
    sqlite3SrcListDelete(db, pTabList);
    sqlite3ExprListDelete(db, pChanges);
    sqlite3ExprDelete(db, pWhere);
}

// ─── ExprHasProperty(pWhere, EP_Subquery) ────────────────────────────────────
const Expr_flags_off = off("Expr_flags", 4);
inline fn exprHasSubquery(p: ?*anyopaque) bool {
    return (rd(u32, p, Expr_flags_off) & EP_Subquery) != 0;
}

// ─── NameContext field offsets ───────────────────────────────────────────────
const sizeof_NameContext = off("sizeof_NameContext", 56);
const NameContext_pParse_off = off("NameContext_pParse", 0);
const NameContext_pSrcList_off = off("NameContext_pSrcList", 8);
const NameContext_uNC_off = off("NameContext_uNC", 16);
const NameContext_ncFlags_off = off("NameContext_ncFlags", 40);
inline fn ncSetPParse(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NameContext_pParse_off, v);
}
inline fn ncSetPSrcList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NameContext_pSrcList_off, v);
}

// ─── Parse.checkSchema (:1 bft bit 0x100 within the bft group) ───────────────
// checkSchema is the 9th bft after disableTriggers in the same bitfield group:
// disableTriggers..usesAinc are 10 consecutive :1 fields; checkSchema is bit
// 0x100. The group starts at Parse_bft_byte; bit 0x100 is byte+1, bit 0x01.
inline fn setCheckSchema(pParse: ?*anyopaque) void {
    base(pParse)[Parse_bft_byte + 1] |= 0x01;
}

// ═══ updateVirtualTable (static) ═════════════════════════════════════════════
fn updateVirtualTable(
    pParse: ?*anyopaque,
    pSrc: ?*anyopaque,
    pTab: ?*anyopaque,
    pChanges: ?*anyopaque,
    pRowid: ?*anyopaque,
    aXRef: [*c]c_int,
    pWhere: ?*anyopaque,
    onError: c_int,
) void {
    const v = rd(?*anyopaque, pParse, Parse_pVdbe_off);
    var ephemTab: c_int = undefined;
    var i: c_int = undefined;
    const db = pDb(pParse);
    const pVTab: ?[*:0]const u8 = @ptrCast(sqlite3GetVTable(db, pTab));
    var pWInfo: ?*anyopaque = null;
    const nCol: c_int = tabNCol(pTab);
    const nArg: c_int = 2 + nCol; // arguments to VUpdate
    var regArg: c_int = undefined;
    var regRec: c_int = undefined;
    var regRowid: c_int = undefined;
    const iCsr: c_int = itemICursor(srcItem0(pSrc));
    var aDummy: [2]c_int = .{ 0, 0 };
    var eOnePass: c_int = undefined;
    var addr: c_int = undefined;

    ephemTab = pIncNTab(pParse);
    addr = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, ephemTab, nArg);
    regArg = pNMem(pParse) + 1;
    pSetNMem(pParse, pNMem(pParse) + nArg);

    if (srcNSrc(pSrc) > 1) {
        var pPk: ?*anyopaque = null;
        var pRow: ?*anyopaque = undefined;
        var pList: ?*anyopaque = undefined;
        if (tabHasRowid(pTab)) {
            if (pRowid != null) {
                pRow = sqlite3ExprDup(db, pRowid, 0);
            } else {
                pRow = sqlite3PExpr(pParse, TK_ROW, null, null);
            }
        } else {
            pPk = sqlite3PrimaryKeyIndex(pTab);
            // assert pPk!=0 && pPk->nKeyCol==1
            const iPkCol: i16 = idxAiColumn(pPk, 0);
            if (aXRef[@intCast(iPkCol)] >= 0) {
                pRow = sqlite3ExprDup(db, elPExpr(pChanges, @intCast(aXRef[@intCast(iPkCol)])), 0);
            } else {
                pRow = exprRowColumn(pParse, iPkCol);
            }
        }
        pList = sqlite3ExprListAppend(pParse, null, pRow);

        i = 0;
        while (i < nCol) : (i += 1) {
            if (aXRef[@intCast(i)] >= 0) {
                pList = sqlite3ExprListAppend(pParse, pList, sqlite3ExprDup(db, elPExpr(pChanges, @intCast(aXRef[@intCast(i)])), 0));
            } else {
                const pRowExpr = exprRowColumn(pParse, i);
                if (pRowExpr != null) exprSetOp2(pRowExpr, @intCast(OPFLAG_NOCHNG));
                pList = sqlite3ExprListAppend(pParse, pList, pRowExpr);
            }
        }

        updateFromSelect(pParse, ephemTab, pPk, pList, pSrc, pWhere, null, null);
        sqlite3ExprListDelete(db, pList);
        eOnePass = ONEPASS_OFF;
    } else {
        regRec = pIncNMem(pParse);
        regRowid = pIncNMem(pParse);

        pWInfo = sqlite3WhereBegin(pParse, pSrc, pWhere, null, null, null, WHERE_ONEPASS_DESIRED, 0);
        if (pWInfo == null) return;

        i = 0;
        while (i < nCol) : (i += 1) {
            // assert (colFlags & COLFLAG_GENERATED)==0
            if (aXRef[@intCast(i)] >= 0) {
                sqlite3ExprCode(pParse, elPExpr(pChanges, @intCast(aXRef[@intCast(i)])), regArg + 2 + i);
            } else {
                _ = sqlite3VdbeAddOp3(v, OP_VColumn, iCsr, i, regArg + 2 + i);
                sqlite3VdbeChangeP5(v, OPFLAG_NOCHNG);
            }
        }
        if (tabHasRowid(pTab)) {
            _ = sqlite3VdbeAddOp2(v, OP_Rowid, iCsr, regArg);
            if (pRowid != null) {
                sqlite3ExprCode(pParse, pRowid, regArg + 1);
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_Rowid, iCsr, regArg + 1);
            }
        } else {
            const pPk = sqlite3PrimaryKeyIndex(pTab);
            // assert pPk!=0 && pPk->nKeyCol==1
            const iPkCol: i16 = idxAiColumn(pPk, 0);
            _ = sqlite3VdbeAddOp3(v, OP_VColumn, iCsr, iPkCol, regArg);
            _ = sqlite3VdbeAddOp2(v, OP_SCopy, regArg + 2 + iPkCol, regArg + 1);
        }

        eOnePass = sqlite3WhereOkOnePass(pWInfo, &aDummy);
        // assert eOnePass==ONEPASS_OFF || eOnePass==ONEPASS_SINGLE

        if (eOnePass != 0) {
            _ = sqlite3VdbeChangeToNoop(v, addr);
            _ = sqlite3VdbeAddOp1(v, OP_Close, iCsr);
        } else {
            sqlite3MultiWrite(pParse);
            _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, regArg, nArg, regRec);
            if (config.sqlite_debug) {
                // SQLITE_DEBUG && !SQLITE_ENABLE_NULL_TRIM
                sqlite3VdbeChangeP5(v, OPFLAG_NOCHNG_MAGIC);
            }
            _ = sqlite3VdbeAddOp2(v, OP_NewRowid, ephemTab, regRowid);
            _ = sqlite3VdbeAddOp3(v, OP_Insert, ephemTab, regRec, regRowid);
        }
    }

    if (eOnePass == ONEPASS_OFF) {
        if (srcNSrc(pSrc) == 1) {
            sqlite3WhereEnd(pWInfo);
        }

        addr = sqlite3VdbeAddOp1(v, OP_Rewind, ephemTab);

        i = 0;
        while (i < nArg) : (i += 1) {
            _ = sqlite3VdbeAddOp3(v, OP_Column, ephemTab, i, regArg + i);
        }
    }
    sqlite3VtabMakeWritable(pParse, pTab);
    _ = sqlite3VdbeAddOp4(v, OP_VUpdate, 0, nArg, regArg, pVTab, P4_VTAB);
    sqlite3VdbeChangeP5(v, @intCast(if (onError == OE_Default) OE_Abort else onError));
    sqlite3MayAbort(pParse);

    if (eOnePass == ONEPASS_OFF) {
        _ = sqlite3VdbeAddOp2(v, OP_Next, ephemTab, addr + 1);
        sqlite3VdbeJumpHere(v, addr);
        _ = sqlite3VdbeAddOp2(v, OP_Close, ephemTab, 0);
    } else {
        sqlite3WhereEnd(pWInfo);
    }
}
