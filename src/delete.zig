//! Zig port of SQLite's src/delete.c — VDBE code generation for DELETE FROM.
//!
//! Exported (non-static, C-ABI) symbols — the complete external set of delete.c
//! that is compiled in this project's two build configs:
//!   - sqlite3SrcListLookup
//!   - sqlite3CodeChangeCount
//!   - sqlite3IsReadOnly
//!   - sqlite3MaterializeView    (compiled: OMIT_VIEW & OMIT_TRIGGER both OFF)
//!   - sqlite3DeleteFrom
//!   - sqlite3GenerateRowDelete
//!   - sqlite3GenerateRowIndexDelete
//!   - sqlite3GenerateIndexKey
//!   - sqlite3ResolvePartIdxLabel
//!
//! NOT exported (gated OFF in both configs):
//!   - sqlite3LimitWhere — only compiled under SQLITE_ENABLE_UPDATE_DELETE_LIMIT,
//!     which is OFF here; its callers reference it under the same flag, so the
//!     symbol must not exist (matching the C build).
//!
//! Static helpers (vtabIsReadOnly, tabIsReadOnly) are private to this module.
//!
//! ─── Config assumptions (true in both this project's builds) ────────────────
//!   * SQLITE_OMIT_TRIGGER / SQLITE_OMIT_VIEW / SQLITE_OMIT_VIRTUALTABLE OFF.
//!   * SQLITE_OMIT_FOREIGN_KEY OFF → sqlite3Fk* are real fns (ported in fkey.zig).
//!   * SQLITE_OMIT_TRUNCATE_OPTIMIZATION OFF → OP_Clear fast path compiled.
//!   * SQLITE_OMIT_AUTHORIZATION OFF → sqlite3AuthCheck/Push/Pop are real fns.
//!   * SQLITE_ENABLE_PREUPDATE_HOOK ON → sqlite3TableColumnToStorage is a real fn.
//!   * SQLITE_ENABLE_UPDATE_DELETE_LIMIT OFF → no LimitWhere; pOrderBy/pLimit
//!     never owned here, so no list cleanup in the cleanup path.
//!   * SQLITE_ENABLE_PREUPDATE_HOOK ON for the truncate-opt: db->xPreUpdateCallback
//!     guard. Conservatively never truncate-clear when bComplex (which already
//!     subsumes FK/trigger); the xPreUpdate guard is handled by always taking the
//!     individual-delete path when a preupdate hook may exist — see note below.
//!   * Little-endian x86-64.
//!
//! ─── Struct coupling / ground-truth offsets ────────────────────────────────
//! Probe-verified with offsetof in BOTH configs. Most reuse c_layout entries
//! shared from fkey/trigger/attach/auth. NEW (added/needed by this port):
//!   Index.nColumn@96 Index.pSchema@48 Index.aColExpr@80
//!     idxType/uniqNotNull bitfield byte = onError+1 = 99 (idxType mask 0x03,
//!     uniqNotNull mask 0x08); bHasExpr byte = 101 (onError+3) mask 0x08.
//!   Parse.iSelfTab@64
//!   Parse.bReturning bitfield byte = 39 (prod) / 42 (tf), mask 0x08 — the same
//!     bft byte as fkey's disableTriggers/mayAbort (config-divergent).
//!   SrcItem.fg.isIndexedBy = fg+1 mask 0x02; SrcItem.fg.notCte = fg+2 mask 0x04.
//! All other offsets are config-invariant (verified prod == tf).
//!
//! Validated through the engine by the TCL suite (delete*, fkey*, trigger*,
//! without_rowid*, e_delete); no standalone Zig unit test is feasible — every
//! path couples to the live parser, WHERE optimizer, VDBE, btree and schema.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── Result / auth codes ────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_DENY: c_int = 1;
const SQLITE_IGNORE: c_int = 2;
const SQLITE_DELETE: c_int = 9;
const SQLITE_STATIC: ?*const anyopaque = null;

// ─── Conflict-resolution codes ──────────────────────────────────────────────
const OE_None: c_int = 0;
const OE_Abort: c_int = 2;
const OE_Default: c_int = 11;

// ─── ONEPASS modes ──────────────────────────────────────────────────────────
const ONEPASS_OFF: c_int = 0;
const ONEPASS_SINGLE: c_int = 1;
const ONEPASS_MULTI: c_int = 2;

// ─── WHERE control flags ────────────────────────────────────────────────────
const WHERE_ONEPASS_DESIRED: u16 = 0x0004;
const WHERE_ONEPASS_MULTIROW: u16 = 0x0008;
const WHERE_DUPLICATES_OK: u16 = 0x0010;

// ─── NameContext flags ──────────────────────────────────────────────────────
const NC_Subquery: c_int = 0x000040;

// ─── sqlite3.flags / dbFlags bits ───────────────────────────────────────────
const SQLITE_CountRows: u64 = 0x00001 << 32; // HI(0x00001)

// ─── Table flags / type ─────────────────────────────────────────────────────
const TF_Readonly: u32 = 0x00000001;
const TF_WithoutRowid: u32 = 0x00000080;
const TF_Shadow: u32 = 0x00001000;
const TABTYP_NORM: u8 = 0;
const TABTYP_VIEW: u8 = 2;

// ─── Column / index flags ───────────────────────────────────────────────────
const SQLITE_IDXTYPE_PRIMARYKEY: u8 = 2;
const XN_EXPR: i16 = -2;

// ─── OPFLAG / P4 / P5 markers ───────────────────────────────────────────────
const OPFLAG_NCHANGE: u16 = 0x01;
const OPFLAG_SAVEPOSITION: u16 = 0x02;
const OPFLAG_AUXDELETE: u16 = 0x04;
const OPFLAG_FORDELETE: u8 = 0x08;
const P4_STATIC: c_int = -1;
const P4_INDEX: c_int = -6;
const P4_TABLE: c_int = -5;
const P4_VTAB: c_int = -12;
const COLNAME_NAME: c_int = 0;
const SQLITE_JUMPIFNULL: c_int = 0x10;

// ─── Trigger directions / tokens ────────────────────────────────────────────
const TRIGGER_BEFORE: c_int = 1;
const TRIGGER_AFTER: c_int = 2;
const TK_DELETE: c_int = 129;

// ─── VDBE opcodes ───────────────────────────────────────────────────────────
const OP_VUpdate: c_int = 7;
const OP_Once: c_int = 15;
const OP_NotFound: c_int = 28;
const OP_NotExists: c_int = 31;
const OP_Rewind: c_int = 36;
const OP_Next: c_int = 40;
const OP_RowSetRead: c_int = 48;
const OP_Integer: c_int = 73;
const OP_Null: c_int = 77;
const OP_FkCheck: c_int = 85;
const OP_ResultRow: c_int = 86;
const OP_AddImm: c_int = 88;
const OP_RealAffinity: u8 = 89;
const OP_Column: c_int = 96;
const OP_Copy: c_int = 82;
const OP_OpenWrite: c_int = 116;
const OP_MakeRecord: c_int = 99;
const OP_OpenEphemeral: c_int = 120;
const OP_Close: c_int = 124;
const OP_Delete: c_int = 132;
const OP_RowData: c_int = 136;
const OP_IdxInsert: c_int = 140;
const OP_IdxDelete: c_int = 142;
const OP_FinishSeek: c_int = 145;
const OP_Clear: c_int = 147;
const OP_RowSetAdd: c_int = 158;

// ═══ ground-truth offsets ════════════════════════════════════════════════════
// Reuse c_layout where present (shared from earlier ports), else probe fallback.

// Table
const Table_zName_off: usize = if (@hasDecl(L, "Table_zName")) L.Table_zName else 0;
const Table_aCol_off: usize = if (@hasDecl(L, "Table_aCol")) L.Table_aCol else 8;
const Table_pIndex_off: usize = if (@hasDecl(L, "Table_pIndex")) L.Table_pIndex else 16;
const Table_tnum_off: usize = if (@hasDecl(L, "Table_tnum")) L.Table_tnum else 40;
const Table_nTabRef_off: usize = if (@hasDecl(L, "Table_nTabRef")) L.Table_nTabRef else 44;
const Table_tabFlags_off: usize = if (@hasDecl(L, "Table_tabFlags")) L.Table_tabFlags else 48;
const Table_iPKey_off: usize = if (@hasDecl(L, "Table_iPKey")) L.Table_iPKey else 52;
const Table_nCol_off: usize = if (@hasDecl(L, "Table_nCol")) L.Table_nCol else 54;
const Table_eTabType_off: usize = if (@hasDecl(L, "Table_eTabType")) L.Table_eTabType else 63;
const Table_pSchema_off: usize = if (@hasDecl(L, "Table_pSchema")) L.Table_pSchema else 96;

// Column
const sizeof_Column: usize = if (@hasDecl(L, "sizeof_Column")) L.sizeof_Column else 16;

// Index
const Index_aiColumn_off: usize = if (@hasDecl(L, "Index_aiColumn")) L.Index_aiColumn else 8;
const Index_pNext_off: usize = if (@hasDecl(L, "Index_pNext")) L.Index_pNext else 40;
const Index_pSchema_off: usize = if (@hasDecl(L, "Index_pSchema")) L.Index_pSchema else 48;
const Index_pPartIdxWhere_off: usize = if (@hasDecl(L, "Index_pPartIdxWhere")) L.Index_pPartIdxWhere else 72;
const Index_tnum_off: usize = if (@hasDecl(L, "Index_tnum")) L.Index_tnum else 88;
const Index_nKeyCol_off: usize = if (@hasDecl(L, "Index_nKeyCol")) L.Index_nKeyCol else 94;
const Index_nColumn_off: usize = if (@hasDecl(L, "Index_nColumn")) L.Index_nColumn else 96;
const Index_onError_off: usize = if (@hasDecl(L, "Index_onError")) L.Index_onError else 98;
// bitfield byte: idxType:2 bUnordered:1 uniqNotNull:1 ... (byte = onError+1 = 99)
const Index_idxType_byte: usize = if (@hasDecl(L, "Index_idxType_byte")) L.Index_idxType_byte else 99;
// bHasExpr is the 12th flag → byte onError+3 = 101, bit 3 → mask 0x08
const Index_bHasExpr_byte: usize = 101;
const Index_bHasExpr_mask: u8 = 0x08;

// Parse
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_pVdbe_off: usize = if (@hasDecl(L, "Parse_pVdbe")) L.Parse_pVdbe else 16;
const Parse_nested_off: usize = if (@hasDecl(L, "Parse_nested")) L.Parse_nested else 30;
const Parse_nErr_off: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;
const Parse_nTab_off: usize = if (@hasDecl(L, "Parse_nTab")) L.Parse_nTab else 56;
const Parse_nMem_off: usize = if (@hasDecl(L, "Parse_nMem")) L.Parse_nMem else 60;
const Parse_iSelfTab_off: usize = if (@hasDecl(L, "Parse_iSelfTab")) L.Parse_iSelfTab else 64;
const Parse_pToplevel_off: usize = if (@hasDecl(L, "Parse_pToplevel")) L.Parse_pToplevel else 136;
const Parse_pTriggerTab_off: usize = if (@hasDecl(L, "Parse_pTriggerTab")) L.Parse_pTriggerTab else 144;
const Parse_isMultiWrite_byte: usize = if (@hasDecl(L, "Parse_isMultiWrite")) L.Parse_isMultiWrite else 32;
// bft byte holding bReturning (mask 0x08). Config-divergent (same byte as fkey).
const Parse_bft_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_bReturning: u8 = 0x08;

// sqlite3
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
// SQLITE_ENABLE_PREUPDATE_HOOK is ON in both configs → this field exists.
const sqlite3_xPreUpdateCallback_off: usize = if (@hasDecl(L, "sqlite3_xPreUpdateCallback")) L.sqlite3_xPreUpdateCallback else 360;

// Db
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;

// SrcList / SrcItem
const SrcList_nSrc_off: usize = if (@hasDecl(L, "SrcList_nSrc")) L.SrcList_nSrc else 0;
const SrcList_a_off: usize = if (@hasDecl(L, "SrcList_a")) L.SrcList_a else 8;
const SrcItem_pSTab_off: usize = if (@hasDecl(L, "SrcItem_pSTab")) L.SrcItem_pSTab else 16;
const SrcItem_fg_off: usize = if (@hasDecl(L, "SrcItem_fg")) L.SrcItem_fg else 24;
const SrcItem_iCursor_off: usize = if (@hasDecl(L, "SrcItem_iCursor")) L.SrcItem_iCursor else 28;
const FG_isIndexedBy_byte: usize = SrcItem_fg_off + 1;
const FG_isIndexedBy_mask: u8 = 0x02;
const FG_notCte_byte: usize = SrcItem_fg_off + 2;
const FG_notCte_mask: u8 = 0x04;

// NameContext
const sizeof_NameContext: usize = if (@hasDecl(L, "sizeof_NameContext")) L.sizeof_NameContext else 56;
const NameContext_pParse_off: usize = if (@hasDecl(L, "NameContext_pParse")) L.NameContext_pParse else 0;
const NameContext_pSrcList_off: usize = if (@hasDecl(L, "NameContext_pSrcList")) L.NameContext_pSrcList else 8;
const NameContext_ncFlags_off: usize = if (@hasDecl(L, "NameContext_ncFlags")) L.NameContext_ncFlags else 40;

// AuthContext (stack-allocated; opaque — only its size matters).
const sizeof_AuthContext: usize = if (@hasDecl(L, "sizeof_AuthContext")) L.sizeof_AuthContext else 16;

// ═══ raw memory helpers ══════════════════════════════════════════════════════
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, off: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + off);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, off: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + off);
    q.* = v;
}

// ─── Table accessors ─────────────────────────────────────────────────────────
inline fn tabZName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Table_zName_off);
}
inline fn tabPIndex(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pIndex_off);
}
inline fn tabTnum(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tnum_off);
}
inline fn tabNTabRef(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_nTabRef_off);
}
inline fn tabSetNTabRef(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Table_nTabRef_off, v);
}
inline fn tabTabFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tabFlags_off);
}
inline fn tabIPKey(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_iPKey_off);
}
inline fn tabNCol(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_nCol_off);
}
inline fn tabETabType(p: ?*anyopaque) u8 {
    return base(p)[Table_eTabType_off];
}
inline fn tabPSchema(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pSchema_off);
}
inline fn tabHasRowid(p: ?*anyopaque) bool {
    return (tabTabFlags(p) & TF_WithoutRowid) == 0;
}
inline fn tabIsView(p: ?*anyopaque) bool {
    return tabETabType(p) == TABTYP_VIEW;
}

// ─── Index accessors ─────────────────────────────────────────────────────────
inline fn idxPNext(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pNext_off);
}
inline fn idxPSchema(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pSchema_off);
}
inline fn idxTnum(p: ?*anyopaque) u32 {
    return rd(u32, p, Index_tnum_off);
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
inline fn idxIdxType(p: ?*anyopaque) u8 {
    return base(p)[Index_idxType_byte] & 0x03;
}
inline fn idxIsPrimaryKey(p: ?*anyopaque) bool {
    return idxIdxType(p) == SQLITE_IDXTYPE_PRIMARYKEY;
}
inline fn idxUniqNotNull(p: ?*anyopaque) bool {
    return (base(p)[Index_idxType_byte] & 0x08) != 0;
}
inline fn idxBHasExpr(p: ?*anyopaque) bool {
    return (base(p)[Index_bHasExpr_byte] & Index_bHasExpr_mask) != 0;
}
inline fn idxPPartIdxWhere(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pPartIdxWhere_off);
}
// Index.aiColumn[i] (i16)
inline fn idxAiColumn(p: ?*anyopaque, i: usize) i16 {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_aiColumn_off).?);
    const q: *align(1) const i16 = @ptrCast(a + i * @sizeOf(i16));
    return q.*;
}

// ─── Parse accessors ─────────────────────────────────────────────────────────
inline fn pDb(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_db_off);
}
inline fn pVdbe(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pVdbe_off);
}
inline fn pNested(pParse: ?*anyopaque) u8 {
    return base(pParse)[Parse_nested_off];
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
inline fn pSetISelfTab(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_iSelfTab_off, v);
}
inline fn pPToplevel(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pToplevel_off);
}
inline fn pPTriggerTab(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pTriggerTab_off);
}
inline fn pBReturning(pParse: ?*anyopaque) bool {
    return (base(pParse)[Parse_bft_byte] & BFT_bReturning) != 0;
}

// ─── sqlite3 accessors ───────────────────────────────────────────────────────
inline fn dbFlags(db: ?*anyopaque) u64 {
    return rd(u64, db, sqlite3_flags_off);
}
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rd(c_int, db, sqlite3_nDb_off);
}
inline fn dbADb(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_aDb_off);
}
inline fn dbAtZDbSName(db: ?*anyopaque, i: c_int) ?[*:0]const u8 {
    const a: [*]u8 = @ptrCast(dbADb(db).?);
    const slot: ?*anyopaque = @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Db);
    return rd(?[*:0]const u8, slot, Db_zDbSName_off);
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}

// ─── SrcList / SrcItem accessors ─────────────────────────────────────────────
inline fn srcNSrc(pList: ?*anyopaque) c_int {
    return rd(c_int, pList, SrcList_nSrc_off);
}
inline fn srcItem0(pList: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(pList) + SrcList_a_off);
}
inline fn itemPSTab(pItem: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pItem, SrcItem_pSTab_off);
}
inline fn itemSetPSTab(pItem: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, pItem, SrcItem_pSTab_off, v);
}
inline fn itemICursor(pItem: ?*anyopaque) c_int {
    return rd(c_int, pItem, SrcItem_iCursor_off);
}
inline fn itemSetICursor(pItem: ?*anyopaque, v: c_int) void {
    wr(c_int, pItem, SrcItem_iCursor_off, v);
}
inline fn itemSetNotCte(pItem: ?*anyopaque) void {
    base(pItem)[FG_notCte_byte] |= FG_notCte_mask;
}
inline fn itemIsIndexedBy(pItem: ?*anyopaque) bool {
    return (base(pItem)[FG_isIndexedBy_byte] & FG_isIndexedBy_mask) != 0;
}

// ─── NameContext accessor ────────────────────────────────────────────────────
inline fn ncNcFlags(p: ?*anyopaque) c_int {
    return rd(c_int, p, NameContext_ncFlags_off);
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ═════════════════
// VDBE assembly (vdbeaux.zig — already ported)
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeMakeLabel(pParse: ?*anyopaque) c_int;
extern fn sqlite3VdbeAddOp0(p: ?*anyopaque, op: c_int) c_int;
extern fn sqlite3VdbeAddOp1(p: ?*anyopaque, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*:0]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeGoto(p: ?*anyopaque, addr: c_int) c_int;
extern fn sqlite3VdbeChangeP4(p: ?*anyopaque, addr: c_int, zP4: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3VdbeAppendP4(p: ?*anyopaque, pP4: ?*anyopaque, p4type: c_int) void;
extern fn sqlite3VdbeChangeP5(p: ?*anyopaque, p5: u16) void;
extern fn sqlite3VdbeChangeToNoop(p: ?*anyopaque, addr: c_int) c_int;
extern fn sqlite3VdbeDeletePriorOpcode(p: ?*anyopaque, op: u8) c_int;
extern fn sqlite3VdbeJumpHere(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeJumpHereOrPopInst(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeCurrentAddr(p: ?*anyopaque) c_int;
extern fn sqlite3VdbeResolveLabel(p: ?*anyopaque, x: c_int) void;
extern fn sqlite3VdbeSetP4KeyInfo(pParse: ?*anyopaque, pIdx: ?*anyopaque) void;
extern fn sqlite3VdbeSetNumCols(p: ?*anyopaque, n: c_int) void;
extern fn sqlite3VdbeSetColName(p: ?*anyopaque, idx: c_int, var_: c_int, name: ?[*:0]const u8, xDel: ?*const anyopaque) c_int;
extern fn sqlite3VdbeCountChanges(p: ?*anyopaque) void;

// Codegen / schema helpers
extern fn sqlite3LocateTableItem(pParse: ?*anyopaque, flags: u32, pItem: ?*anyopaque) ?*anyopaque;
extern fn sqlite3DeleteTable(db: ?*anyopaque, pTab: ?*anyopaque) void;
extern fn sqlite3IndexedByLookup(pParse: ?*anyopaque, pItem: ?*anyopaque) c_int;
extern fn sqlite3TriggersExist(pParse: ?*anyopaque, pTab: ?*anyopaque, op: c_int, pChanges: ?*anyopaque, pMask: ?*c_int) ?*anyopaque;
extern fn sqlite3ViewGetColumnNames(pParse: ?*anyopaque, pTab: ?*anyopaque) c_int;
extern fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) c_int;
extern fn sqlite3PrimaryKeyIndex(pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3TableLock(pParse: ?*anyopaque, iDb: c_int, tnum: u32, isWriteLock: u8, zName: ?[*:0]const u8) void;
extern fn sqlite3BeginWriteOperation(pParse: ?*anyopaque, setStatement: c_int, iDb: c_int) void;
extern fn sqlite3MultiWrite(pParse: ?*anyopaque) void;
extern fn sqlite3MayAbort(pParse: ?*anyopaque) void;
extern fn sqlite3AutoincrementEnd(pParse: ?*anyopaque) void;
extern fn sqlite3TableColumnToStorage(pTab: ?*anyopaque, iCol: i16) i16;
extern fn sqlite3IndexAffinityStr(db: ?*anyopaque, pIdx: ?*anyopaque) ?[*:0]const u8;

// Auth (real fns; OMIT_AUTHORIZATION off)
extern fn sqlite3AuthCheck(pParse: ?*anyopaque, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;
extern fn sqlite3AuthContextPush(pParse: ?*anyopaque, pContext: ?*anyopaque, zCtx: ?[*:0]const u8) void;
extern fn sqlite3AuthContextPop(pContext: ?*anyopaque) void;

// Read-only checks
extern fn sqlite3WritableSchema(db: ?*anyopaque) c_int;
extern fn sqlite3ReadOnlyShadowTables(db: ?*anyopaque) c_int;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;

// Expr / resolve / WHERE
extern fn sqlite3ResolveExprNames(pNC: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprCodeGetColumnOfTable(v: ?*anyopaque, pTab: ?*anyopaque, iTabCur: c_int, iCol: c_int, regOut: c_int) void;
extern fn sqlite3ExprCodeLoadIndexColumn(pParse: ?*anyopaque, pIdx: ?*anyopaque, iTabCur: c_int, iIdxCol: c_int, regOut: c_int) void;
extern fn sqlite3ExprIfFalseDup(pParse: ?*anyopaque, pExpr: ?*anyopaque, dest: c_int, jumpIfNull: c_int) void;
extern fn sqlite3WhereBegin(pParse: ?*anyopaque, pTabList: ?*anyopaque, pWhere: ?*anyopaque, pOrderBy: ?*anyopaque, pResultSet: ?*anyopaque, pSelect: ?*anyopaque, wctrlFlags: u16, iAuxArg: c_int) ?*anyopaque;
extern fn sqlite3WhereEnd(pWInfo: ?*anyopaque) void;
extern fn sqlite3WhereOkOnePass(pWInfo: ?*anyopaque, aiCur: [*]c_int) c_int;
extern fn sqlite3WhereUsesDeferredSeek(pWInfo: ?*anyopaque) c_int;

// Temp registers
extern fn sqlite3GetTempRange(pParse: ?*anyopaque, n: c_int) c_int;
extern fn sqlite3ReleaseTempRange(pParse: ?*anyopaque, iReg: c_int, n: c_int) void;

// Table/index open
extern fn sqlite3OpenTableAndIndices(pParse: ?*anyopaque, pTab: ?*anyopaque, op: c_int, p5: u8, iBase: c_int, aToOpen: ?[*]u8, piDataCur: *c_int, piIdxCur: *c_int) c_int;

// Foreign keys & triggers (real fns; ported in fkey.zig / trigger.zig)
extern fn sqlite3FkRequired(pParse: ?*anyopaque, pTab: ?*anyopaque, aChange: ?*c_int, chngRowid: c_int) c_int;
extern fn sqlite3FkCheck(pParse: ?*anyopaque, pTab: ?*anyopaque, regOld: c_int, regNew: c_int, aChange: ?*c_int, bChngRowid: c_int) void;
extern fn sqlite3FkActions(pParse: ?*anyopaque, pTab: ?*anyopaque, pChanges: ?*anyopaque, regOld: c_int, aChange: ?*c_int, bChngRowid: c_int) void;
extern fn sqlite3FkOldmask(pParse: ?*anyopaque, pTab: ?*anyopaque) u32;
extern fn sqlite3TriggerColmask(pParse: ?*anyopaque, pTrigger: ?*anyopaque, pChanges: ?*anyopaque, isNew: c_int, tr_tm: c_int, pTab: ?*anyopaque, orconf: c_int) u32;
extern fn sqlite3CodeRowTrigger(pParse: ?*anyopaque, pTrigger: ?*anyopaque, op: c_int, pChanges: ?*anyopaque, tr_tm: c_int, pTab: ?*anyopaque, reg: c_int, orconf: c_int, ignoreJump: c_int) void;

// Virtual tables
extern fn sqlite3GetVTable(db: ?*anyopaque, pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VtabMakeWritable(pParse: ?*anyopaque, pTab: ?*anyopaque) void;

// Memory
extern fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbNNFreeNN(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SrcListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;

// ─── MASKBIT32 helper ────────────────────────────────────────────────────────
inline fn maskbit32(n: c_int) u32 {
    return @as(u32, 1) << @intCast(n);
}

// ═══ sqlite3SrcListLookup ════════════════════════════════════════════════════
export fn sqlite3SrcListLookup(pParse: ?*anyopaque, pSrc: ?*anyopaque) callconv(.c) ?*anyopaque {
    const pItem = srcItem0(pSrc);
    // assert pItem && pSrc->nSrc>=1
    var pTab = sqlite3LocateTableItem(pParse, 0, pItem);
    if (itemPSTab(pItem) != null) {
        sqlite3DeleteTable(pDb(pParse), itemPSTab(pItem));
    }
    itemSetPSTab(pItem, pTab);
    itemSetNotCte(pItem);
    if (pTab != null) {
        tabSetNTabRef(pTab, tabNTabRef(pTab) + 1);
        if (itemIsIndexedBy(pItem) and sqlite3IndexedByLookup(pParse, pItem) != 0) {
            pTab = null;
        }
    }
    return pTab;
}

// ═══ sqlite3CodeChangeCount ══════════════════════════════════════════════════
export fn sqlite3CodeChangeCount(v: ?*anyopaque, regCounter: c_int, zColName: ?[*:0]const u8) callconv(.c) void {
    _ = sqlite3VdbeAddOp0(v, OP_FkCheck);
    _ = sqlite3VdbeAddOp2(v, OP_ResultRow, regCounter, 1);
    sqlite3VdbeSetNumCols(v, 1);
    _ = sqlite3VdbeSetColName(v, 0, COLNAME_NAME, zColName, SQLITE_STATIC);
}

// ═══ vtabIsReadOnly (static) ═════════════════════════════════════════════════
// IsVirtual(pTab) asserted by caller. Mirrors the C: checks
// sqlite3GetVTable(db,pTab)->pMod->pModule->xUpdate==0, then the eVtabRisk vs
// TrustedSchema gate within triggers / FROM_DDL prepares.
const SQLITE_TrustedSchema: u64 = 0x00000080;
const SQLITE_PREPARE_FROM_DDL: u8 = 0x20;
const VTable_pMod_off: usize = if (@hasDecl(L, "VTable_pMod")) L.VTable_pMod else 8;
const VTable_eVtabRisk_off: usize = if (@hasDecl(L, "VTable_eVtabRisk")) L.VTable_eVtabRisk else 30;
const Module_pModule_off: usize = if (@hasDecl(L, "Module_pModule")) L.Module_pModule else 0;
const sqlite3_module_xUpdate_off: usize = if (@hasDecl(L, "sqlite3_module_xUpdate")) L.sqlite3_module_xUpdate else 104;
const Table_u_vtab_p_off: usize = if (@hasDecl(L, "Table_u_vtab_p")) L.Table_u_vtab_p else 80;
const Parse_prepFlags_off: usize = if (@hasDecl(L, "Parse_prepFlags")) L.Parse_prepFlags else 34;

fn vtabIsReadOnly(pParse: ?*anyopaque, pTab: ?*anyopaque) bool {
    const db = pDb(pParse);
    const pVtab = sqlite3GetVTable(db, pTab); // VTable*
    const pMod = rd(?*anyopaque, pVtab, VTable_pMod_off); // Module*
    const pModule = rd(?*anyopaque, pMod, Module_pModule_off); // sqlite3_module*
    if (rd(?*anyopaque, pModule, sqlite3_module_xUpdate_off) == null) {
        return true;
    }
    // Within triggers / FROM_DDL: disallow risky virtual tables.
    const prepFromDdl = (base(pParse)[Parse_prepFlags_off] & SQLITE_PREPARE_FROM_DDL) != 0;
    if (pPToplevel(pParse) != null or prepFromDdl) {
        const pVt = rd(?*anyopaque, pTab, Table_u_vtab_p_off); // Table.u.vtab.p (VTable*)
        const eVtabRisk: u8 = base(pVt)[VTable_eVtabRisk_off];
        const trusted: u8 = @intFromBool((dbFlags(db) & SQLITE_TrustedSchema) != 0);
        if (eVtabRisk > trusted) {
            sqlite3ErrorMsg(pParse, "unsafe use of virtual table \"%s\"", tabZName(pTab));
        }
    }
    return false;
}

// ═══ tabIsReadOnly (static) ══════════════════════════════════════════════════
fn tabIsReadOnly(pParse: ?*anyopaque, pTab: ?*anyopaque) bool {
    if (tabIsVirtual(pTab)) {
        return vtabIsReadOnly(pParse, pTab);
    }
    const flags = tabTabFlags(pTab);
    if ((flags & (TF_Readonly | TF_Shadow)) == 0) return false;
    const db = pDb(pParse);
    if ((flags & TF_Readonly) != 0) {
        return sqlite3WritableSchema(db) == 0 and pNested(pParse) == 0;
    }
    // assert pTab->tabFlags & TF_Shadow
    return sqlite3ReadOnlyShadowTables(db) != 0;
}

// IsVirtual(pTab) <=> eTabType==TABTYP_VTAB(1). Ordinary/View are 0/2.
const TABTYP_VTAB: u8 = 1;
inline fn tabIsVirtual(p: ?*anyopaque) bool {
    return tabETabType(p) == TABTYP_VTAB;
}

// ═══ sqlite3IsReadOnly ═══════════════════════════════════════════════════════
export fn sqlite3IsReadOnly(pParse: ?*anyopaque, pTab: ?*anyopaque, pTrigger: ?*anyopaque) callconv(.c) c_int {
    if (tabIsReadOnly(pParse, pTab)) {
        sqlite3ErrorMsg(pParse, "table %s may not be modified", tabZName(pTab));
        return 1;
    }
    // OMIT_VIEW off
    if (tabIsView(pTab) and (pTrigger == null or (trigBReturningNextNull(pTrigger)))) {
        sqlite3ErrorMsg(pParse, "cannot modify %s because it is a view", tabZName(pTab));
        return 1;
    }
    return 0;
}

// (pTrigger->bReturning && pTrigger->pNext==0). Trigger.bReturning is a u8 flag
// and pNext is a pointer; offsets from trigger.zig's mirror.
const Trigger_bReturning_off: usize = if (@hasDecl(L, "Trigger_bReturning")) L.Trigger_bReturning else 18;
const Trigger_pNext_off: usize = if (@hasDecl(L, "Trigger_pNext")) L.Trigger_pNext else 64;
inline fn trigBReturningNextNull(pTrigger: ?*anyopaque) bool {
    const bRet = base(pTrigger)[Trigger_bReturning_off] != 0;
    const pNext = rd(?*anyopaque, pTrigger, Trigger_pNext_off);
    return bRet and pNext == null;
}

// ═══ sqlite3MaterializeView ══════════════════════════════════════════════════
// Evaluate a view into an ephemeral table. Couples to Select construction; the
// SrcItem union writes (zName/u4.zDatabase/u.tab assertions) mirror the C. We
// delegate the Select assembly to the existing internal helpers.
extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3SrcListAppend(pParse: ?*anyopaque, pList: ?*anyopaque, pTable: ?*anyopaque, pDatabase: ?*anyopaque) ?*anyopaque;
extern fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3SelectNew(pParse: ?*anyopaque, pEList: ?*anyopaque, pSrc: ?*anyopaque, pWhere: ?*anyopaque, pGroupBy: ?*anyopaque, pHaving: ?*anyopaque, pOrderBy: ?*anyopaque, selFlags: u32, pLimit: ?*anyopaque) ?*anyopaque;
extern fn sqlite3SelectDestInit(pDest: ?*anyopaque, eDest: c_int, iParm: c_int) void;
extern fn sqlite3Select(pParse: ?*anyopaque, p: ?*anyopaque, pDest: ?*anyopaque) c_int;
extern fn sqlite3SelectDelete(db: ?*anyopaque, p: ?*anyopaque) void;

const SF_IncludeHidden: u32 = 0x0020000;
const SRT_EphemTab: c_int = 10;
// SrcItem.zName / u4.zDatabase offsets (u4 union follows colUsed).
const SrcItem_zName_off: usize = if (@hasDecl(L, "SrcItem_zName")) L.SrcItem_zName else 0;
const SrcItem_u4_zDatabase_off: usize = if (@hasDecl(L, "SrcItem_u4_zDatabase")) L.SrcItem_u4_zDatabase else 64;
// SelectDest is stack-allocated; size from c_layout or fallback.
const sizeof_SelectDest: usize = if (@hasDecl(L, "sizeof_SelectDest")) L.sizeof_SelectDest else 40;

export fn sqlite3MaterializeView(
    pParse: ?*anyopaque,
    pView: ?*anyopaque,
    pWhereIn: ?*anyopaque,
    pOrderBy: ?*anyopaque,
    pLimit: ?*anyopaque,
    iCur: c_int,
) callconv(.c) void {
    const db = pDb(pParse);
    const iDb = sqlite3SchemaToIndex(db, tabPSchema(pView));
    const pWhere = sqlite3ExprDup(db, pWhereIn, 0);
    const pFrom = sqlite3SrcListAppend(pParse, null, null, null);
    if (pFrom) |from| {
        // assert pFrom->nSrc==1
        const it = srcItem0(from);
        wr(?[*:0]u8, it, SrcItem_zName_off, sqlite3DbStrDup(db, tabZName(pView)));
        // assert fg.fixedSchema==0 && fg.isSubquery==0
        wr(?[*:0]u8, it, SrcItem_u4_zDatabase_off, sqlite3DbStrDup(db, dbAtZDbSName(db, iDb)));
        // assert fg.isUsing==0 && u3.pOn==0
    }
    const pSel = sqlite3SelectNew(pParse, null, pFrom, pWhere, null, null, pOrderBy, SF_IncludeHidden, pLimit);

    var dest: [sizeof_SelectDest]u8 align(8) = undefined;
    sqlite3SelectDestInit(&dest, SRT_EphemTab, iCur);
    _ = sqlite3Select(pParse, pSel, &dest);
    sqlite3SelectDelete(db, pSel);
}

// ═══ sqlite3DeleteFrom ═══════════════════════════════════════════════════════
export fn sqlite3DeleteFrom(
    pParse: ?*anyopaque,
    pTabList: ?*anyopaque,
    pWhereIn: ?*anyopaque,
    pOrderBy: ?*anyopaque,
    pLimit: ?*anyopaque,
) callconv(.c) void {
    _ = pOrderBy;
    _ = pLimit;
    const pWhere = pWhereIn;

    var iDataCur: c_int = 0;
    var iIdxCur: c_int = 0;
    var nIdx: c_int = 0;
    var memCnt: c_int = 0;
    var eOnePass: c_int = ONEPASS_OFF;
    var aiCurOnePass: [2]c_int = .{ 0, 0 };
    var aToOpen: ?[*]u8 = null;
    var pPk: ?*anyopaque = null;
    var iPk: c_int = 0;
    var nPk: i16 = 1;
    var iKey: c_int = 0;
    var nKey: i16 = 0;
    var iEphCur: c_int = 0;
    var iRowSet: c_int = 0;
    var addrBypass: c_int = 0;
    var addrLoop: c_int = 0;
    var addrEphOpen: c_int = 0;

    // AuthContext sContext = {0}
    var sContext: [sizeof_AuthContext]u8 align(8) = @splat(0);
    const db = pDb(pParse);

    if (pNErr(pParse) != 0) {
        cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
        return;
    }
    // assert db->mallocFailed==0 ; assert pTabList->nSrc==1

    const pTab = sqlite3SrcListLookup(pParse, pTabList);
    if (pTab == null) {
        cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
        return;
    }

    // triggers / view
    const pTrigger = sqlite3TriggersExist(pParse, pTab, TK_DELETE, null, null);
    const isView = tabIsView(pTab);
    var bComplex: bool = (pTrigger != null) or (sqlite3FkRequired(pParse, pTab, null, 0) != 0);

    // (SQLITE_ENABLE_UPDATE_DELETE_LIMIT OFF: no LimitWhere)

    if (sqlite3ViewGetColumnNames(pParse, pTab) != 0) {
        cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
        return;
    }
    if (sqlite3IsReadOnly(pParse, pTab, pTrigger) != 0) {
        cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
        return;
    }
    const iDb = sqlite3SchemaToIndex(db, tabPSchema(pTab));
    // assert iDb<db->nDb
    const rcauth = sqlite3AuthCheck(pParse, SQLITE_DELETE, tabZName(pTab), null, dbAtZDbSName(db, iDb));
    if (rcauth == SQLITE_DENY) {
        cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
        return;
    }
    // assert(!isView || pTrigger)

    // Assign cursor numbers to the table and all its indices.
    const iTabCur: c_int = pNTab(pParse);
    itemSetICursor(srcItem0(pTabList), iTabCur);
    pSetNTab(pParse, pNTab(pParse) + 1);
    {
        var pIdx = tabPIndex(pTab);
        while (pIdx != null) : (pIdx = idxPNext(pIdx)) {
            pSetNTab(pParse, pNTab(pParse) + 1);
            nIdx += 1;
        }
    }

    if (isView) {
        sqlite3AuthContextPush(pParse, &sContext, tabZName(pTab));
    }

    const v = sqlite3GetVdbe(pParse);
    if (v == null) {
        cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
        return;
    }
    if (pNested(pParse) == 0) sqlite3VdbeCountChanges(v);
    sqlite3BeginWriteOperation(pParse, @intFromBool(bComplex), iDb);

    if (isView) {
        sqlite3MaterializeView(pParse, pTab, pWhere, null, null, iTabCur);
        iDataCur = iTabCur;
        iIdxCur = iTabCur;
    }

    // Resolve the column names in the WHERE clause.
    var sNC: [sizeof_NameContext]u8 align(8) = @splat(0);
    wr(?*anyopaque, &sNC, NameContext_pParse_off, pParse);
    wr(?*anyopaque, &sNC, NameContext_pSrcList_off, pTabList);
    if (sqlite3ResolveExprNames(&sNC, pWhere) != 0) {
        cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
        return;
    }

    // Initialize the row-deletion counter, if counting rows.
    if ((dbFlags(db) & SQLITE_CountRows) != 0 and pNested(pParse) == 0 and pPTriggerTab(pParse) == null and !pBReturning(pParse)) {
        pSetNMem(pParse, pNMem(pParse) + 1);
        memCnt = pNMem(pParse);
        _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, memCnt);
    }

    // Special case: truncate optimization (TRUNCATE_OPTIMIZATION not omitted).
    const xPreUpdate = sqlite3_xPreUpdateCallback_off != 0 and rd(?*anyopaque, db, sqlite3_xPreUpdateCallback_off) != null;
    if (rcauth == SQLITE_OK and pWhere == null and !bComplex and !tabIsVirtual(pTab) and !xPreUpdate) {
        // assert !isView
        sqlite3TableLock(pParse, iDb, tabTnum(pTab), 1, tabZName(pTab));
        if (tabHasRowid(pTab)) {
            _ = sqlite3VdbeAddOp4(v, OP_Clear, @bitCast(tabTnum(pTab)), iDb, if (memCnt != 0) memCnt else -1, tabZName(pTab), P4_STATIC);
        }
        var pIdx = tabPIndex(pTab);
        while (pIdx != null) : (pIdx = idxPNext(pIdx)) {
            // assert pIdx->pSchema==pTab->pSchema
            if (idxIsPrimaryKey(pIdx) and !tabHasRowid(pTab)) {
                _ = sqlite3VdbeAddOp3(v, OP_Clear, @bitCast(idxTnum(pIdx)), iDb, if (memCnt != 0) memCnt else -1);
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_Clear, @bitCast(idxTnum(pIdx)), iDb);
            }
        }
    } else {
        // ── General (non-truncate) path ───────────────────────────────────────
        var wcf: u16 = WHERE_ONEPASS_DESIRED | WHERE_DUPLICATES_OK;
        if ((ncNcFlags(&sNC) & NC_Subquery) != 0) bComplex = true;
        wcf |= (if (bComplex) 0 else WHERE_ONEPASS_MULTIROW);
        if (tabHasRowid(pTab)) {
            pPk = null;
            // assert nPk==1
            pSetNMem(pParse, pNMem(pParse) + 1);
            iRowSet = pNMem(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, iRowSet);
        } else {
            pPk = sqlite3PrimaryKeyIndex(pTab);
            // assert pPk!=0
            nPk = @bitCast(idxNKeyCol(pPk));
            iPk = pNMem(pParse) + 1;
            pSetNMem(pParse, pNMem(pParse) + nPk);
            iEphCur = pNTab(pParse);
            pSetNTab(pParse, pNTab(pParse) + 1);
            addrEphOpen = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, iEphCur, nPk);
            sqlite3VdbeSetP4KeyInfo(pParse, pPk);
        }

        const pWInfo = sqlite3WhereBegin(pParse, pTabList, pWhere, null, null, null, wcf, iTabCur + 1);
        if (pWInfo == null) {
            cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
            return;
        }
        eOnePass = sqlite3WhereOkOnePass(pWInfo, &aiCurOnePass);
        if (eOnePass != ONEPASS_SINGLE) sqlite3MultiWrite(pParse);
        if (sqlite3WhereUsesDeferredSeek(pWInfo) != 0) {
            _ = sqlite3VdbeAddOp1(v, OP_FinishSeek, iTabCur);
        }

        if (memCnt != 0) {
            _ = sqlite3VdbeAddOp2(v, OP_AddImm, memCnt, 1);
        }

        // Extract the rowid or primary key for the current row.
        if (pPk != null) {
            var i: usize = 0;
            while (i < @as(usize, @intCast(nPk))) : (i += 1) {
                // assert pPk->aiColumn[i]>=0
                sqlite3ExprCodeGetColumnOfTable(v, pTab, iTabCur, idxAiColumn(pPk, i), iPk + @as(c_int, @intCast(i)));
            }
            iKey = iPk;
        } else {
            pSetNMem(pParse, pNMem(pParse) + 1);
            iKey = pNMem(pParse);
            sqlite3ExprCodeGetColumnOfTable(v, pTab, iTabCur, -1, iKey);
        }

        if (eOnePass != ONEPASS_OFF) {
            nKey = nPk; // OP_Found will use an unpacked key
            aToOpen = @ptrCast(sqlite3DbMallocRawNN(db, @intCast(nIdx + 2)));
            if (aToOpen == null) {
                sqlite3WhereEnd(pWInfo);
                cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
                return;
            }
            const ato = aToOpen.?;
            var k: usize = 0;
            while (k < @as(usize, @intCast(nIdx + 1))) : (k += 1) ato[k] = 1;
            ato[@intCast(nIdx + 1)] = 0;
            if (aiCurOnePass[0] >= 0) ato[@intCast(aiCurOnePass[0] - iTabCur)] = 0;
            if (aiCurOnePass[1] >= 0) ato[@intCast(aiCurOnePass[1] - iTabCur)] = 0;
            if (addrEphOpen != 0) _ = sqlite3VdbeChangeToNoop(v, addrEphOpen);
            addrBypass = sqlite3VdbeMakeLabel(pParse);
        } else {
            if (pPk != null) {
                // Add the PK key for this row to the temporary table.
                pSetNMem(pParse, pNMem(pParse) + 1);
                iKey = pNMem(pParse);
                nKey = 0; // composite key
                _ = sqlite3VdbeAddOp4(v, OP_MakeRecord, iPk, nPk, iKey, sqlite3IndexAffinityStr(db, pPk), nPk);
                _ = sqlite3VdbeAddOp4Int(v, OP_IdxInsert, iEphCur, iKey, iPk, nPk);
            } else {
                nKey = 1; // single rowid
                _ = sqlite3VdbeAddOp2(v, OP_RowSetAdd, iRowSet, iKey);
            }
            sqlite3WhereEnd(pWInfo);
        }

        // Open cursors for the table + its indices (unless a view).
        if (!isView) {
            var iAddrOnce: c_int = 0;
            if (eOnePass == ONEPASS_MULTI) {
                iAddrOnce = sqlite3VdbeAddOp0(v, OP_Once);
            }
            _ = sqlite3OpenTableAndIndices(pParse, pTab, OP_OpenWrite, OPFLAG_FORDELETE, iTabCur, aToOpen, &iDataCur, &iIdxCur);
            if (eOnePass == ONEPASS_MULTI) {
                sqlite3VdbeJumpHereOrPopInst(v, iAddrOnce);
            }
        }

        // Loop over the rowids/primary-keys found in the WHERE loop.
        if (eOnePass != ONEPASS_OFF) {
            // assert nKey==nPk
            if (!tabIsVirtual(pTab) and aToOpen.?[@intCast(iDataCur - iTabCur)] != 0) {
                _ = sqlite3VdbeAddOp4Int(v, OP_NotFound, iDataCur, addrBypass, iKey, nKey);
            }
        } else if (pPk != null) {
            addrLoop = sqlite3VdbeAddOp1(v, OP_Rewind, iEphCur);
            if (tabIsVirtual(pTab)) {
                _ = sqlite3VdbeAddOp3(v, OP_Column, iEphCur, 0, iKey);
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_RowData, iEphCur, iKey);
            }
            // assert nKey==0
        } else {
            addrLoop = sqlite3VdbeAddOp3(v, OP_RowSetRead, iRowSet, 0, iKey);
            // assert nKey==1
        }

        // Delete the row.
        if (tabIsVirtual(pTab)) {
            const pVTab: ?[*:0]const u8 = @ptrCast(sqlite3GetVTable(db, pTab));
            sqlite3VtabMakeWritable(pParse, pTab);
            // assert eOnePass==OFF || ==SINGLE
            sqlite3MayAbort(pParse);
            if (eOnePass == ONEPASS_SINGLE) {
                _ = sqlite3VdbeAddOp1(v, OP_Close, iTabCur);
                if (pPToplevel(pParse) == null) {
                    // pParse->isMultiWrite = 0
                    base(pParse)[Parse_isMultiWrite_byte] = 0;
                }
            }
            _ = sqlite3VdbeAddOp4(v, OP_VUpdate, 0, 1, iKey, pVTab, P4_VTAB);
            sqlite3VdbeChangeP5(v, @intCast(OE_Abort));
        } else {
            const count: c_int = @intFromBool(pNested(pParse) == 0);
            sqlite3GenerateRowDelete(pParse, pTab, pTrigger, iDataCur, iIdxCur, iKey, nKey, @intCast(count), @intCast(OE_Default), @intCast(eOnePass), aiCurOnePass[1]);
        }

        // End of the loop.
        if (eOnePass != ONEPASS_OFF) {
            sqlite3VdbeResolveLabel(v, addrBypass);
            sqlite3WhereEnd(pWInfo);
        } else if (pPk != null) {
            _ = sqlite3VdbeAddOp2(v, OP_Next, iEphCur, addrLoop + 1);
            sqlite3VdbeJumpHere(v, addrLoop);
        } else {
            _ = sqlite3VdbeGoto(v, addrLoop);
            sqlite3VdbeJumpHere(v, addrLoop);
        }
    } // end non-truncate path

    // Update sqlite_sequence for autoincrement tables.
    if (pNested(pParse) == 0 and pPTriggerTab(pParse) == null) {
        sqlite3AutoincrementEnd(pParse);
    }

    // Return the number of rows deleted.
    if (memCnt != 0) {
        sqlite3CodeChangeCount(v, memCnt, "rows deleted");
    }

    cleanup(pParse, db, &sContext, pTabList, pWhere, aToOpen);
}

// delete_from_cleanup
inline fn cleanup(
    pParse: ?*anyopaque,
    db: ?*anyopaque,
    sContext: ?*anyopaque,
    pTabList: ?*anyopaque,
    pWhere: ?*anyopaque,
    aToOpen: ?[*]u8,
) void {
    _ = pParse;
    sqlite3AuthContextPop(sContext);
    sqlite3SrcListDelete(db, pTabList);
    sqlite3ExprDelete(db, pWhere);
    // (SQLITE_ENABLE_UPDATE_DELETE_LIMIT OFF: no pOrderBy/pLimit owned here)
    if (aToOpen != null) sqlite3DbNNFreeNN(db, @ptrCast(aToOpen));
}

// ═══ sqlite3GenerateRowDelete ════════════════════════════════════════════════
export fn sqlite3GenerateRowDelete(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    pTrigger: ?*anyopaque,
    iDataCur: c_int,
    iIdxCur: c_int,
    iPk: c_int,
    nPk: i16,
    count: u8,
    onconf: u8,
    eMode: u8,
    iIdxNoSeekIn: c_int,
) callconv(.c) void {
    var iIdxNoSeek = iIdxNoSeekIn;
    const v = pVdbe(pParse);
    var iOld: c_int = 0;
    // assert v

    const iLabel = sqlite3VdbeMakeLabel(pParse);
    const opSeek: c_int = if (tabHasRowid(pTab)) OP_NotExists else OP_NotFound;
    if (@as(c_int, eMode) == ONEPASS_OFF) {
        _ = sqlite3VdbeAddOp4Int(v, opSeek, iDataCur, iLabel, iPk, nPk);
    }

    // If there are triggers / FKs, set up the OLD.* register array.
    if (sqlite3FkRequired(pParse, pTab, null, 0) != 0 or pTrigger != null) {
        var mask = sqlite3TriggerColmask(pParse, pTrigger, null, 0, TRIGGER_BEFORE | TRIGGER_AFTER, pTab, onconf);
        mask |= sqlite3FkOldmask(pParse, pTab);
        iOld = pNMem(pParse) + 1;
        pSetNMem(pParse, pNMem(pParse) + (1 + @as(c_int, tabNCol(pTab))));

        // Populate the OLD.* pseudo-table register array.
        _ = sqlite3VdbeAddOp2(v, OP_Copy, iPk, iOld);
        var iCol: c_int = 0;
        while (iCol < @as(c_int, tabNCol(pTab))) : (iCol += 1) {
            if (mask == 0xffffffff or (iCol <= 31 and (mask & maskbit32(iCol)) != 0)) {
                const kk = sqlite3TableColumnToStorage(pTab, @intCast(iCol));
                sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, iCol, iOld + kk + 1);
            }
        }

        // Invoke BEFORE DELETE triggers.
        const addrStart = sqlite3VdbeCurrentAddr(v);
        sqlite3CodeRowTrigger(pParse, pTrigger, TK_DELETE, null, TRIGGER_BEFORE, pTab, iOld, onconf, iLabel);

        // If any BEFORE triggers were coded, re-seek and disable iIdxNoSeek.
        if (addrStart < sqlite3VdbeCurrentAddr(v)) {
            _ = sqlite3VdbeAddOp4Int(v, opSeek, iDataCur, iLabel, iPk, nPk);
            iIdxNoSeek = -1;
        }

        // FK processing (constraints referencing this table).
        sqlite3FkCheck(pParse, pTab, iOld, 0, null, 0);
    }

    // Delete the index and table entries (unless a view).
    if (!tabIsView(pTab)) {
        var p5: u8 = 0;
        sqlite3GenerateRowIndexDelete(pParse, pTab, iDataCur, iIdxCur, null, iIdxNoSeek);
        _ = sqlite3VdbeAddOp2(v, OP_Delete, iDataCur, if (count != 0) @as(c_int, OPFLAG_NCHANGE) else 0);
        if (pNested(pParse) == 0 or 0 == sqlite3_stricmp(tabZName(pTab), "sqlite_stat1")) {
            sqlite3VdbeAppendP4(v, pTab, P4_TABLE);
        }
        if (@as(c_int, eMode) != ONEPASS_OFF) {
            sqlite3VdbeChangeP5(v, OPFLAG_AUXDELETE);
        }
        if (iIdxNoSeek >= 0 and iIdxNoSeek != iDataCur) {
            _ = sqlite3VdbeAddOp1(v, OP_Delete, iIdxNoSeek);
        }
        if (@as(c_int, eMode) == ONEPASS_MULTI) p5 |= @intCast(OPFLAG_SAVEPOSITION);
        sqlite3VdbeChangeP5(v, p5);
    }

    // ON CASCADE / SET NULL / SET DEFAULT actions for child rows.
    sqlite3FkActions(pParse, pTab, null, iOld, null, 0);

    // Invoke AFTER DELETE triggers.
    if (pTrigger != null) {
        sqlite3CodeRowTrigger(pParse, pTrigger, TK_DELETE, null, TRIGGER_AFTER, pTab, iOld, onconf, iLabel);
    }

    sqlite3VdbeResolveLabel(v, iLabel);
}

// ═══ sqlite3GenerateRowIndexDelete ═══════════════════════════════════════════
export fn sqlite3GenerateRowIndexDelete(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    iDataCur: c_int,
    iIdxCur: c_int,
    aRegIdx: ?[*]c_int,
    iIdxNoSeek: c_int,
) callconv(.c) void {
    var r1: c_int = -1;
    var iPartIdxLabel: c_int = 0;
    var pPrior: ?*anyopaque = null;
    const v = pVdbe(pParse);
    const pPk: ?*anyopaque = if (tabHasRowid(pTab)) null else sqlite3PrimaryKeyIndex(pTab);

    var i: c_int = 0;
    var pIdx = tabPIndex(pTab);
    while (pIdx != null) : ({
        i += 1;
        pIdx = idxPNext(pIdx);
    }) {
        var p3: c_int = 0;
        // assert iIdxCur+i!=iDataCur || pPk==pIdx
        if (aRegIdx != null and aRegIdx.?[@intCast(i)] == 0) continue;
        if (pIdx == pPk) continue;
        if (iIdxCur + i == iIdxNoSeek) continue;
        r1 = sqlite3GenerateIndexKey(pParse, pIdx, iDataCur, 0, 1, &iPartIdxLabel, pPrior, r1);
        if (idxBHasExpr(pIdx) and aRegIdx != null) {
            p3 = aRegIdx.?[@intCast(i)];
        }
        _ = sqlite3VdbeAddOp3(v, OP_IdxDelete, iIdxCur + i, r1, p3);
        sqlite3VdbeChangeP4(v, -1, @ptrCast(pIdx), P4_INDEX);
        sqlite3VdbeChangeP5(v, if (idxUniqNotNull(pIdx)) idxNKeyCol(pIdx) else idxNColumn(pIdx));
        sqlite3ResolvePartIdxLabel(pParse, iPartIdxLabel);
        pPrior = pIdx;
    }
}

// ═══ sqlite3GenerateIndexKey ═════════════════════════════════════════════════
export fn sqlite3GenerateIndexKey(
    pParse: ?*anyopaque,
    pIdx: ?*anyopaque,
    iDataCur: c_int,
    regOut: c_int,
    prefixOnly: c_int,
    piPartIdxLabel: ?*c_int,
    pPriorIn: ?*anyopaque,
    regPrior: c_int,
) callconv(.c) c_int {
    var pPrior = pPriorIn;
    const v = pVdbe(pParse);

    if (piPartIdxLabel) |lbl| {
        if (idxPPartIdxWhere(pIdx) != null) {
            lbl.* = sqlite3VdbeMakeLabel(pParse);
            pSetISelfTab(pParse, iDataCur + 1);
            sqlite3ExprIfFalseDup(pParse, idxPPartIdxWhere(pIdx), lbl.*, SQLITE_JUMPIFNULL);
            pSetISelfTab(pParse, 0);
            pPrior = null; // pPartIdxWhere may have corrupted regPrior registers
        } else {
            lbl.* = 0;
        }
    }
    const nCol: c_int = if (prefixOnly != 0 and idxUniqNotNull(pIdx)) @as(c_int, idxNKeyCol(pIdx)) else @as(c_int, idxNColumn(pIdx));
    const regBase = sqlite3GetTempRange(pParse, nCol);
    if (pPrior != null and (regBase != regPrior or idxPPartIdxWhere(pPrior) != null)) pPrior = null;
    var j: c_int = 0;
    while (j < nCol) : (j += 1) {
        if (pPrior != null and idxAiColumn(pPrior, @intCast(j)) == idxAiColumn(pIdx, @intCast(j)) and idxAiColumn(pPrior, @intCast(j)) != XN_EXPR) {
            // Already computed by the previous index.
            continue;
        }
        sqlite3ExprCodeLoadIndexColumn(pParse, pIdx, iDataCur, j, regBase + j);
        if (idxAiColumn(pIdx, @intCast(j)) >= 0) {
            // Omit OP_RealAffinity if present (index stores ints compactly).
            _ = sqlite3VdbeDeletePriorOpcode(v, OP_RealAffinity);
        }
    }
    if (regOut != 0) {
        _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, regBase, nCol, regOut);
    }
    sqlite3ReleaseTempRange(pParse, regBase, nCol);
    return regBase;
}

// ═══ sqlite3ResolvePartIdxLabel ══════════════════════════════════════════════
export fn sqlite3ResolvePartIdxLabel(pParse: ?*anyopaque, iLabel: c_int) callconv(.c) void {
    if (iLabel != 0) {
        sqlite3VdbeResolveLabel(pVdbe(pParse), iLabel);
    }
}
