//! Zig port of SQLite's src/fkey.c — foreign-key constraint code generation.
//!
//! Exported (non-static) symbols — the complete external set of fkey.c, matching
//! the prototypes in sqliteInt.h (SQLITE_OMIT_FOREIGN_KEY and SQLITE_OMIT_TRIGGER
//! both OFF in this project's two build configs):
//!   - sqlite3FkLocateIndex
//!   - sqlite3FkReferences
//!   - sqlite3FkClearTriggerCache
//!   - sqlite3FkDropTable
//!   - sqlite3FkCheck
//!   - sqlite3FkOldmask
//!   - sqlite3FkRequired
//!   - sqlite3FkActions
//!   - sqlite3FkDelete
//! The static helpers (fkLookupParent, exprTableRegister, exprTableColumn,
//! fkScanChildren, fkTriggerDelete, fkChildIsModified, fkParentIsModified,
//! isSetNullAction, fkActionTrigger) are private to this module.
//!
//! ─── Struct coupling / ground-truth offsets ────────────────────────────────
//! All offsets below were probe-verified with offsetof in BOTH the production
//! library config and the `--dev` testfixture (SQLITE_DEBUG + SQLITE_TEST)
//! config. The ONLY divergence is the Parse bft-bitfield byte (disableTriggers/
//! mayAbort live at byte 39 in prod, byte 42 in tf) — gated on config.
//!
//!   FKey   : pFrom@0 pNextFrom@8 zTo@16 pNextTo@24 pPrevTo@32 nCol@40
//!            isDeferred@44 aAction@45 apTrigger@48 aCol@64
//!   sColMap: iFrom@0 zCol@8  (sizeof 16)
//!   Table  : zName@0 aCol@8 pIndex@16 tnum@40 nTabRef@44 iPKey@52 nCol@54
//!            eTabType@63 u@64 (u.tab.pFKey@72) pSchema@96
//!   Column : zCnName@0 affinity@9 colFlags@14
//!   Index  : aiColumn@8 pTable@24 pNext@40 azColl@64 pPartIdxWhere@72 tnum@88
//!            nKeyCol@94 onError@98 idxType(byte 99, low 2 bits)
//!   Schema : tblHash@8 fkeyHash@80
//!   Parse  : db@0 nErr@52 nTab@56 pToplevel@136 pTriggerPrg@152
//!            disableTriggers/mayAbort bft byte = 39 (prod) / 42 (tf)
//!   sqlite3: aDb@32 nDb@40 mDbFlags@44 flags@48 mallocFailed@103 pDfltColl@16
//!   Db     : zDbSName@0 pSchema@24  (sizeof 32)
//!   Trigger: op@16 pWhen@24 pSchema@40 pTabSchema@48 step_list@56 pNext@64 (sz72)
//!   TriggerStep: op@0 pTrig@8 pSelect@16 pSrc@24 pWhere@32 pExprList@40 pNext@72
//!   TriggerPrg: pTrigger@0 pNext@8
//!   SrcList: nSrc@0 a@8   SrcItem: zName@0 pSTab@16 fg@24 iCursor@28 (sizeof 72)
//!   Expr   : op@0 affExpr@1 iTable@44 iColumn@48 u@8(zToken) y@64(pTab)
//!   NameContext: pParse@0 pSrcList@8  (sizeof 56)
//!   CollSeq: zName@0
//!
//! ─── Config assumptions (true in both this project's builds) ────────────────
//!   * SQLITE_OMIT_FOREIGN_KEY / SQLITE_OMIT_TRIGGER  OFF.
//!   * SQLITE_OMIT_AUTHORIZATION OFF → AuthReadCol path compiled.
//!   * SQLITE_ENABLE_PREUPDATE_HOOK ON → sqlite3TableColumnToStorage is a real
//!     function (not the no-op pass-through macro), so we call it.
//!   * Little-endian x86-64.
//!
//! Validated through the engine by the TCL suite (fkey1..fkey8); no standalone
//! Zig unit test is feasible — every path couples to the live parser, VDBE,
//! btree and schema.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── Result codes ───────────────────────────────────────────────────────────
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_CONSTRAINT_FOREIGNKEY: c_int = SQLITE_CONSTRAINT | (3 << 8); // 787
const SQLITE_IGNORE: c_int = 2;

// ─── Conflict-resolution / ON-action codes (OE_*) ───────────────────────────
const OE_None: c_int = 0;
const OE_Abort: c_int = 2;
const OE_Ignore: c_int = 4;
const OE_Restrict: c_int = 7;
const OE_SetNull: c_int = 8;
const OE_SetDflt: c_int = 9;
const OE_Cascade: c_int = 10;

// ─── sqlite3.flags bits ─────────────────────────────────────────────────────
const SQLITE_ForeignKeys: u64 = 0x00004000;
const SQLITE_DeferFKs: u64 = 0x00080000;
const SQLITE_FkNoAction: u64 = 0x00008 << 32; // HI(0x00008)

// ─── Column flag / index-type / affinity / token constants ──────────────────
const COLFLAG_PRIMKEY: u16 = 0x0001;
const COLFLAG_GENERATED: u16 = 0x0060;
const TF_WithoutRowid: u32 = 0x00000080;
const SQLITE_IDXTYPE_PRIMARYKEY: u8 = 2;
const TABTYP_NORM: u8 = 0;
const SQLITE_AFF_INTEGER: u8 = 0x44;

// ─── VDBE opcodes ───────────────────────────────────────────────────────────
const OP_MustBeInt: c_int = 13;
const OP_Found: c_int = 29;
const OP_NotExists: c_int = 31;
const OP_IsNull: c_int = 51;
const OP_Ne: c_int = 53;
const OP_Eq: c_int = 54;
const OP_FkIfZero: c_int = 60;
const OP_Copy: c_int = 82;
const OP_SCopy: c_int = 83;
const OP_Affinity: c_int = 98;
const OP_OpenRead: c_int = 114;
const OP_Close: c_int = 124;
const OP_FkCounter: c_int = 160;

// ─── P4/P5 markers ──────────────────────────────────────────────────────────
const P4_STATIC: c_int = -1;
const P5_ConstraintFK: u16 = 4;
const SQLITE_JUMPIFNULL: u16 = 0x10;
const SQLITE_NOTNULL: u16 = 0x90;

// ─── Tokens ─────────────────────────────────────────────────────────────────
const TK_NOT: c_int = 19;
const TK_IS: c_int = 45;
const TK_NE: c_int = 53;
const TK_EQ: c_int = 54;
const TK_ID: c_int = 60;
const TK_RAISE: c_int = 72;
const TK_STRING: c_int = 118;
const TK_NULL: c_int = 122;
const TK_DELETE: c_int = 129;
const TK_UPDATE: c_int = 130;
const TK_SELECT: c_int = 139;
const TK_DOT: c_int = 142;
const TK_COLUMN: c_int = 168;
const TK_REGISTER: c_int = 176;

// ─── Expr flags ─────────────────────────────────────────────────────────────
const EP_WinFunc: u32 = 0x1000000;
const EP_Subrtn: u32 = 0x2000000;
const EXPRDUP_REDUCE: c_int = 0x0001;

// ═══ ground-truth offsets ════════════════════════════════════════════════════
// Reuse c_layout entries where present, else the probe-verified fallback.

// FKey
const FKey_pFrom_off: usize = if (@hasDecl(L, "FKey_pFrom")) L.FKey_pFrom else 0;
const FKey_pNextFrom_off: usize = if (@hasDecl(L, "FKey_pNextFrom")) L.FKey_pNextFrom else 8;
const FKey_zTo_off: usize = if (@hasDecl(L, "FKey_zTo")) L.FKey_zTo else 16;
const FKey_pNextTo_off: usize = if (@hasDecl(L, "FKey_pNextTo")) L.FKey_pNextTo else 24;
const FKey_pPrevTo_off: usize = if (@hasDecl(L, "FKey_pPrevTo")) L.FKey_pPrevTo else 32;
const FKey_nCol_off: usize = if (@hasDecl(L, "FKey_nCol")) L.FKey_nCol else 40;
const FKey_isDeferred_off: usize = if (@hasDecl(L, "FKey_isDeferred")) L.FKey_isDeferred else 44;
const FKey_aAction_off: usize = if (@hasDecl(L, "FKey_aAction")) L.FKey_aAction else 45;
const FKey_apTrigger_off: usize = if (@hasDecl(L, "FKey_apTrigger")) L.FKey_apTrigger else 48;
const FKey_aCol_off: usize = if (@hasDecl(L, "FKey_aCol")) L.FKey_aCol else 64;
const sizeof_sColMap: usize = if (@hasDecl(L, "sizeof_sColMap")) L.sizeof_sColMap else 16;
const sColMap_iFrom_off: usize = if (@hasDecl(L, "sColMap_iFrom")) L.sColMap_iFrom else 0;
const sColMap_zCol_off: usize = if (@hasDecl(L, "sColMap_zCol")) L.sColMap_zCol else 8;

// Table
const Table_zName_off: usize = if (@hasDecl(L, "Table_zName")) L.Table_zName else 0;
const Table_aCol_off: usize = if (@hasDecl(L, "Table_aCol")) L.Table_aCol else 8;
const Table_pIndex_off: usize = if (@hasDecl(L, "Table_pIndex")) L.Table_pIndex else 16;
const Table_tnum_off: usize = if (@hasDecl(L, "Table_tnum")) L.Table_tnum else 40;
const Table_tabFlags_off: usize = if (@hasDecl(L, "Table_tabFlags")) L.Table_tabFlags else 48;
const Table_nTabRef_off: usize = if (@hasDecl(L, "Table_nTabRef")) L.Table_nTabRef else 44;
const Table_iPKey_off: usize = if (@hasDecl(L, "Table_iPKey")) L.Table_iPKey else 52;
const Table_nCol_off: usize = if (@hasDecl(L, "Table_nCol")) L.Table_nCol else 54;
const Table_eTabType_off: usize = if (@hasDecl(L, "Table_eTabType")) L.Table_eTabType else 63;
const Table_u_tab_pFKey_off: usize = if (@hasDecl(L, "Table_u_tab_pFKey")) L.Table_u_tab_pFKey else 72;
const Table_pSchema_off: usize = if (@hasDecl(L, "Table_pSchema")) L.Table_pSchema else 96;

// Column
const Column_zCnName_off: usize = if (@hasDecl(L, "Column_zCnName")) L.Column_zCnName else 0;
const Column_affinity_off: usize = if (@hasDecl(L, "Column_affinity")) L.Column_affinity else 9;
const Column_colFlags_off: usize = if (@hasDecl(L, "Column_colFlags")) L.Column_colFlags else 14;
const sizeof_Column: usize = if (@hasDecl(L, "sizeof_Column")) L.sizeof_Column else 16;

// Index
const Index_aiColumn_off: usize = if (@hasDecl(L, "Index_aiColumn")) L.Index_aiColumn else 8;
const Index_pTable_off: usize = if (@hasDecl(L, "Index_pTable")) L.Index_pTable else 24;
const Index_pNext_off: usize = if (@hasDecl(L, "Index_pNext")) L.Index_pNext else 40;
const Index_azColl_off: usize = if (@hasDecl(L, "Index_azColl")) L.Index_azColl else 64;
const Index_pPartIdxWhere_off: usize = if (@hasDecl(L, "Index_pPartIdxWhere")) L.Index_pPartIdxWhere else 72;
const Index_tnum_off: usize = if (@hasDecl(L, "Index_tnum")) L.Index_tnum else 88;
const Index_nKeyCol_off: usize = if (@hasDecl(L, "Index_nKeyCol")) L.Index_nKeyCol else 94;
const Index_onError_off: usize = if (@hasDecl(L, "Index_onError")) L.Index_onError else 98;
const Index_idxType_byte: usize = if (@hasDecl(L, "Index_idxType_byte")) L.Index_idxType_byte else 99;

// Schema
const Schema_tblHash_off: usize = if (@hasDecl(L, "Schema_tblHash")) L.Schema_tblHash else 8;
const Schema_fkeyHash_off: usize = if (@hasDecl(L, "Schema_fkeyHash")) L.Schema_fkeyHash else 80;

// Parse
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_nErr_off: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;
const Parse_nTab_off: usize = if (@hasDecl(L, "Parse_nTab")) L.Parse_nTab else 56;
const Parse_pToplevel_off: usize = if (@hasDecl(L, "Parse_pToplevel")) L.Parse_pToplevel else 136;
const Parse_pTriggerPrg_off: usize = if (@hasDecl(L, "Parse_pTriggerPrg")) L.Parse_pTriggerPrg else 152;
// bft bitfield byte holding disableTriggers(0x01) / mayAbort(0x02). Divergent.
const Parse_bft_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_disableTriggers: u8 = 0x01;
const BFT_isMultiWrite_byte: usize = if (@hasDecl(L, "Parse_isMultiWrite")) L.Parse_isMultiWrite else 32;

// sqlite3
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_mDbFlags_off: usize = if (@hasDecl(L, "sqlite3_mDbFlags")) L.sqlite3_mDbFlags else 44;
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_pDfltColl_off: usize = if (@hasDecl(L, "sqlite3_pDfltColl")) L.sqlite3_pDfltColl else 16;
const sqlite3_xAuth_off: usize = if (@hasDecl(L, "sqlite3_xAuth")) L.sqlite3_xAuth else 528;

// Db
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pSchema_off: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;

// Trigger
const Trigger_op_off: usize = if (@hasDecl(L, "Trigger_op")) L.Trigger_op else 16;
const Trigger_pWhen_off: usize = if (@hasDecl(L, "Trigger_pWhen")) L.Trigger_pWhen else 24;
const Trigger_pSchema_off: usize = if (@hasDecl(L, "Trigger_pSchema")) L.Trigger_pSchema else 40;
const Trigger_pTabSchema_off: usize = if (@hasDecl(L, "Trigger_pTabSchema")) L.Trigger_pTabSchema else 48;
const Trigger_step_list_off: usize = if (@hasDecl(L, "Trigger_step_list")) L.Trigger_step_list else 56;
const sizeof_Trigger: usize = if (@hasDecl(L, "sizeof_Trigger")) L.sizeof_Trigger else 72;

// TriggerStep
const TriggerStep_op_off: usize = if (@hasDecl(L, "TriggerStep_op")) L.TriggerStep_op else 0;
const TriggerStep_pTrig_off: usize = if (@hasDecl(L, "TriggerStep_pTrig")) L.TriggerStep_pTrig else 8;
const TriggerStep_pSelect_off: usize = if (@hasDecl(L, "TriggerStep_pSelect")) L.TriggerStep_pSelect else 16;
const TriggerStep_pSrc_off: usize = if (@hasDecl(L, "TriggerStep_pSrc")) L.TriggerStep_pSrc else 24;
const TriggerStep_pWhere_off: usize = if (@hasDecl(L, "TriggerStep_pWhere")) L.TriggerStep_pWhere else 32;
const TriggerStep_pExprList_off: usize = if (@hasDecl(L, "TriggerStep_pExprList")) L.TriggerStep_pExprList else 40;
const sizeof_TriggerStep: usize = if (@hasDecl(L, "sizeof_TriggerStep")) L.sizeof_TriggerStep else 88;

// TriggerPrg
const TriggerPrg_pTrigger_off: usize = if (@hasDecl(L, "TriggerPrg_pTrigger")) L.TriggerPrg_pTrigger else 0;

// SrcList / SrcItem
const SrcList_nSrc_off: usize = if (@hasDecl(L, "SrcList_nSrc")) L.SrcList_nSrc else 0;
const SrcList_a_off: usize = if (@hasDecl(L, "SrcList_a")) L.SrcList_a else 8;
const SrcItem_zName_off: usize = if (@hasDecl(L, "SrcItem_zName")) L.SrcItem_zName else 0;
const SrcItem_pSTab_off: usize = if (@hasDecl(L, "SrcItem_pSTab")) L.SrcItem_pSTab else 16;
const SrcItem_iCursor_off: usize = if (@hasDecl(L, "SrcItem_iCursor")) L.SrcItem_iCursor else 28;

// Expr
const Expr_op_off: usize = if (@hasDecl(L, "Expr_op")) L.Expr_op else 0;
const Expr_affExpr_off: usize = if (@hasDecl(L, "Expr_affExpr")) L.Expr_affExpr else 1;
const Expr_flags_off: usize = if (@hasDecl(L, "Expr_flags")) L.Expr_flags else 4;
const Expr_iTable_off: usize = if (@hasDecl(L, "Expr_iTable")) L.Expr_iTable else 44;
const Expr_iColumn_off: usize = if (@hasDecl(L, "Expr_iColumn")) L.Expr_iColumn else 48;
const Expr_yTab_off: usize = if (@hasDecl(L, "Expr_yTab")) L.Expr_yTab else 64;

// NameContext
const sizeof_NameContext: usize = if (@hasDecl(L, "sizeof_NameContext")) L.sizeof_NameContext else 56;
const NameContext_pParse_off: usize = if (@hasDecl(L, "NameContext_pParse")) L.NameContext_pParse else 0;
const NameContext_pSrcList_off: usize = if (@hasDecl(L, "NameContext_pSrcList")) L.NameContext_pSrcList else 8;

// CollSeq
const CollSeq_zName_off: usize = if (@hasDecl(L, "CollSeq_zName")) L.CollSeq_zName else 0;

// Hash / HashElem (sqliteHashFirst/Next/Data are C macros)
const Hash_first_off: usize = if (@hasDecl(L, "Hash_first")) L.Hash_first else 8;
const HashElem_next_off: usize = if (@hasDecl(L, "HashElem_next")) L.HashElem_next else 0;
const HashElem_data_off: usize = if (@hasDecl(L, "HashElem_data")) L.HashElem_data else 16;

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

// ─── FKey accessors ──────────────────────────────────────────────────────────
inline fn fkPFrom(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, FKey_pFrom_off);
}
inline fn fkPNextFrom(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, FKey_pNextFrom_off);
}
inline fn fkZTo(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, FKey_zTo_off);
}
inline fn fkPNextTo(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, FKey_pNextTo_off);
}
inline fn fkSetPNextTo(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, FKey_pNextTo_off, v);
}
inline fn fkPPrevTo(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, FKey_pPrevTo_off);
}
inline fn fkSetPPrevTo(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, FKey_pPrevTo_off, v);
}
inline fn fkNCol(p: ?*anyopaque) c_int {
    return rd(c_int, p, FKey_nCol_off);
}
inline fn fkIsDeferred(p: ?*anyopaque) u8 {
    return base(p)[FKey_isDeferred_off];
}
inline fn fkAction(p: ?*anyopaque, i: usize) u8 {
    return base(p)[FKey_aAction_off + i];
}
inline fn fkApTrigger(p: ?*anyopaque, i: usize) ?*anyopaque {
    return rd(?*anyopaque, p, FKey_apTrigger_off + i * @sizeOf(usize));
}
inline fn fkSetApTrigger(p: ?*anyopaque, i: usize, v: ?*anyopaque) void {
    wr(?*anyopaque, p, FKey_apTrigger_off + i * @sizeOf(usize), v);
}
// FKey.aCol[i].iFrom / .zCol
inline fn fkColIFrom(p: ?*anyopaque, i: usize) c_int {
    return rd(c_int, p, FKey_aCol_off + i * sizeof_sColMap + sColMap_iFrom_off);
}
inline fn fkColZCol(p: ?*anyopaque, i: usize) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, FKey_aCol_off + i * sizeof_sColMap + sColMap_zCol_off);
}

// ─── Table accessors ─────────────────────────────────────────────────────────
inline fn tabZName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Table_zName_off);
}
inline fn tabPSchema(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pSchema_off);
}
inline fn tabPFKey(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_u_tab_pFKey_off);
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
inline fn tabTnum(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tnum_off);
}
inline fn tabTabFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tabFlags_off);
}
inline fn tabSetNTabRef(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Table_nTabRef_off, v);
}
inline fn tabNTabRef(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_nTabRef_off);
}
inline fn tabETabType(p: ?*anyopaque) u8 {
    return base(p)[Table_eTabType_off];
}
inline fn tabIsOrdinary(p: ?*anyopaque) bool {
    return tabETabType(p) == TABTYP_NORM;
}
inline fn tabHasRowid(p: ?*anyopaque) bool {
    return (tabTabFlags(p) & TF_WithoutRowid) == 0;
}
// pointer to Table.aCol[i]
inline fn tabColAt(p: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Table_aCol_off).?);
    return @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Column);
}

// ─── Column accessors ────────────────────────────────────────────────────────
inline fn colZCnName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Column_zCnName_off);
}
inline fn colAffinity(p: ?*anyopaque) u8 {
    return base(p)[Column_affinity_off];
}
inline fn colColFlags(p: ?*anyopaque) u16 {
    return rd(u16, p, Column_colFlags_off);
}

// ─── Index accessors ─────────────────────────────────────────────────────────
inline fn idxPTable(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pTable_off);
}
inline fn idxPNext(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pNext_off);
}
inline fn idxTnum(p: ?*anyopaque) u32 {
    return rd(u32, p, Index_tnum_off);
}
inline fn idxNKeyCol(p: ?*anyopaque) u16 {
    return rd(u16, p, Index_nKeyCol_off);
}
inline fn idxOnError(p: ?*anyopaque) u8 {
    return base(p)[Index_onError_off];
}
inline fn idxIsUnique(p: ?*anyopaque) bool {
    return idxOnError(p) != OE_None;
}
inline fn idxIdxType(p: ?*anyopaque) u8 {
    return base(p)[Index_idxType_byte] & 0x03;
}
inline fn idxIsPrimaryKey(p: ?*anyopaque) bool {
    return idxIdxType(p) == SQLITE_IDXTYPE_PRIMARYKEY;
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
// Index.azColl[i] (const char*)
inline fn idxAzColl(p: ?*anyopaque, i: usize) ?[*:0]const u8 {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_azColl_off).?);
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(a + i * @sizeOf(usize));
    return q.*;
}

// ─── Schema accessors ────────────────────────────────────────────────────────
inline fn schemaFkeyHash(p: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(p) + Schema_fkeyHash_off);
}
inline fn schemaTblHash(p: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(p) + Schema_tblHash_off);
}

// ─── Parse accessors ─────────────────────────────────────────────────────────
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
inline fn pPToplevel(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pToplevel_off);
}
inline fn pPTriggerPrg(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pTriggerPrg_off);
}
inline fn pDisableTriggers(pParse: ?*anyopaque) bool {
    return (base(pParse)[Parse_bft_byte] & BFT_disableTriggers) != 0;
}
inline fn pSetDisableTriggers(pParse: ?*anyopaque, on: bool) void {
    if (on) {
        base(pParse)[Parse_bft_byte] |= BFT_disableTriggers;
    } else {
        base(pParse)[Parse_bft_byte] &= ~BFT_disableTriggers;
    }
}
inline fn pIsMultiWrite(pParse: ?*anyopaque) bool {
    return base(pParse)[BFT_isMultiWrite_byte] != 0;
}
// sqlite3ParseToplevel(p) == (p->pToplevel ? p->pToplevel : p)
inline fn parseToplevel(pParse: ?*anyopaque) ?*anyopaque {
    const top = pPToplevel(pParse);
    return if (top != null) top else pParse;
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
inline fn dbAtPSchema(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(dbADb(db).?);
    const slot: ?*anyopaque = @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Db);
    return rd(?*anyopaque, slot, Db_pSchema_off);
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}
inline fn dbXAuth(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_xAuth_off);
}
// db->pDfltColl->zName
inline fn dbDfltCollName(db: ?*anyopaque) ?[*:0]const u8 {
    const pColl = rd(?*anyopaque, db, sqlite3_pDfltColl_off);
    return rd(?[*:0]const u8, pColl, CollSeq_zName_off);
}

// ─── Trigger / TriggerStep accessors ─────────────────────────────────────────
inline fn trigStepList(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Trigger_step_list_off);
}
inline fn trigSetStepList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Trigger_step_list_off, v);
}
inline fn trigSetOp(p: ?*anyopaque, v: u8) void {
    base(p)[Trigger_op_off] = v;
}
inline fn trigPWhen(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Trigger_pWhen_off);
}
inline fn trigSetPWhen(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Trigger_pWhen_off, v);
}
inline fn trigSetPSchema(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Trigger_pSchema_off, v);
}
inline fn trigSetPTabSchema(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Trigger_pTabSchema_off, v);
}
inline fn stepSetOp(p: ?*anyopaque, v: u8) void {
    base(p)[TriggerStep_op_off] = v;
}
inline fn stepSetPTrig(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, TriggerStep_pTrig_off, v);
}
inline fn stepPSelect(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, TriggerStep_pSelect_off);
}
inline fn stepSetPSelect(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, TriggerStep_pSelect_off, v);
}
inline fn stepPSrc(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, TriggerStep_pSrc_off);
}
inline fn stepSetPSrc(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, TriggerStep_pSrc_off, v);
}
inline fn stepPWhere(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, TriggerStep_pWhere_off);
}
inline fn stepSetPWhere(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, TriggerStep_pWhere_off, v);
}
inline fn stepPExprList(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, TriggerStep_pExprList_off);
}
inline fn stepSetPExprList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, TriggerStep_pExprList_off, v);
}

// ─── TriggerPrg accessor ─────────────────────────────────────────────────────
inline fn prgPTrigger(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, TriggerPrg_pTrigger_off);
}

// ─── SrcList / SrcItem accessors ─────────────────────────────────────────────
inline fn srcItem0(pList: ?*anyopaque) ?*anyopaque {
    // pSrc->a — the SrcItem array starts at SrcList_a_off.
    return @ptrCast(base(pList) + SrcList_a_off);
}
inline fn itemSetZName(pItem: ?*anyopaque, v: ?[*:0]const u8) void {
    wr(?[*:0]const u8, pItem, SrcItem_zName_off, v);
}
inline fn itemSetPSTab(pItem: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, pItem, SrcItem_pSTab_off, v);
}
inline fn itemPSTab(pItem: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pItem, SrcItem_pSTab_off);
}
inline fn itemSetICursor(pItem: ?*anyopaque, v: c_int) void {
    wr(c_int, pItem, SrcItem_iCursor_off, v);
}
inline fn itemICursor(pItem: ?*anyopaque) c_int {
    return rd(c_int, pItem, SrcItem_iCursor_off);
}

// ─── Expr accessors ──────────────────────────────────────────────────────────
inline fn exprFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Expr_flags_off);
}
inline fn exprUseYTab(p: ?*anyopaque) bool {
    return (exprFlags(p) & (EP_WinFunc | EP_Subrtn)) == 0;
}
inline fn exprSetAffExpr(p: ?*anyopaque, v: u8) void {
    base(p)[Expr_affExpr_off] = v;
}
inline fn exprSetITable(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Expr_iTable_off, v);
}
inline fn exprSetIColumn(p: ?*anyopaque, v: i16) void {
    wr(i16, p, Expr_iColumn_off, v);
}
inline fn exprSetYTab(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Expr_yTab_off, v);
}

// ─── NameContext accessors ───────────────────────────────────────────────────
inline fn ncSetPParse(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NameContext_pParse_off, v);
}
inline fn ncSetPSrcList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NameContext_pSrcList_off, v);
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ═════════════════
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeMakeLabel(pParse: ?*anyopaque) c_int;
extern fn sqlite3VdbeAddOp1(p: ?*anyopaque, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*:0]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeGoto(p: ?*anyopaque, addr: c_int) c_int;
extern fn sqlite3VdbeChangeP5(p: ?*anyopaque, p5: u16) void;
extern fn sqlite3VdbeJumpHere(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeJumpHereOrPopInst(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeCurrentAddr(p: ?*anyopaque) c_int;
extern fn sqlite3VdbeResolveLabel(p: ?*anyopaque, x: c_int) void;
extern fn sqlite3VdbeSetP4KeyInfo(pParse: ?*anyopaque, pIdx: ?*anyopaque) void;

extern fn sqlite3HaltConstraint(pParse: ?*anyopaque, errCode: c_int, onError: c_int, p4: ?[*:0]const u8, p4type: i8, p5: u8) void;
extern fn sqlite3MayAbort(pParse: ?*anyopaque) void;
extern fn sqlite3TableColumnToStorage(pTab: ?*anyopaque, iCol: i16) i16;
extern fn sqlite3GetTempReg(pParse: ?*anyopaque) c_int;
extern fn sqlite3GetTempRange(pParse: ?*anyopaque, n: c_int) c_int;
extern fn sqlite3ReleaseTempReg(pParse: ?*anyopaque, iReg: c_int) void;
extern fn sqlite3ReleaseTempRange(pParse: ?*anyopaque, iReg: c_int, n: c_int) void;
extern fn sqlite3OpenTable(pParse: ?*anyopaque, iCur: c_int, iDb: c_int, pTab: ?*anyopaque, opcode: c_int) void;
extern fn sqlite3IndexAffinityStr(db: ?*anyopaque, pIdx: ?*anyopaque) ?[*:0]const u8;

extern fn sqlite3HashFind(pH: ?*anyopaque, pKey: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3HashInsert(pH: ?*anyopaque, pKey: ?[*:0]const u8, pData: ?*anyopaque) ?*anyopaque;

extern fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*:0]const u8, n: u64) ?[*:0]u8;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3ColumnColl(pCol: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3ColumnExpr(pTab: ?*anyopaque, pCol: ?*anyopaque) ?*anyopaque;

extern fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) c_int;
extern fn sqlite3FindTable(db: ?*anyopaque, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3LocateTable(pParse: ?*anyopaque, flags: u32, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3TableLock(pParse: ?*anyopaque, iDb: c_int, tnum: u32, isWriteLock: u8, zName: ?[*:0]const u8) void;
extern fn sqlite3AuthReadCol(pParse: ?*anyopaque, zTab: ?[*:0]const u8, zCol: ?[*:0]const u8, iDb: c_int) c_int;

// Expr / list / select construction
extern fn sqlite3Expr(db: ?*anyopaque, op: c_int, zToken: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3ExprAlloc(db: ?*anyopaque, op: c_int, pToken: ?*const anyopaque, dequote: c_int) ?*anyopaque;
extern fn sqlite3PExpr(pParse: ?*anyopaque, op: c_int, pLeft: ?*anyopaque, pRight: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprAnd(pParse: ?*anyopaque, pLeft: ?*anyopaque, pRight: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprAddCollateString(pParse: ?*anyopaque, pExpr: ?*anyopaque, zC: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprListAppend(pParse: ?*anyopaque, pList: ?*anyopaque, pExpr: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprListSetName(pParse: ?*anyopaque, pList: ?*anyopaque, pName: ?*const anyopaque, dequote: c_int) void;
extern fn sqlite3ExprListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SelectNew(pParse: ?*anyopaque, pEList: ?*anyopaque, pSrc: ?*anyopaque, pWhere: ?*anyopaque, pGroupBy: ?*anyopaque, pHaving: ?*anyopaque, pOrderBy: ?*anyopaque, selFlags: u32, pLimit: ?*anyopaque) ?*anyopaque;
extern fn sqlite3SelectDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3SelectDelete(db: ?*anyopaque, p: ?*anyopaque) void;

extern fn sqlite3SrcListAppend(pParse: ?*anyopaque, pList: ?*anyopaque, pTable: ?*anyopaque, pDatabase: ?*anyopaque) ?*anyopaque;
extern fn sqlite3SrcListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SrcListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3DeleteFrom(pParse: ?*anyopaque, pTabList: ?*anyopaque, pWhere: ?*anyopaque, pOrderBy: ?*anyopaque, pLimit: ?*anyopaque) void;

extern fn sqlite3ResolveExprNames(pNC: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3WhereBegin(pParse: ?*anyopaque, pTabList: ?*anyopaque, pWhere: ?*anyopaque, pOrderBy: ?*anyopaque, pResultSet: ?*anyopaque, pSelect: ?*anyopaque, wctrlFlags: u16, iAuxArg: c_int) ?*anyopaque;
extern fn sqlite3WhereEnd(pWInfo: ?*anyopaque) void;
extern fn sqlite3CodeRowTriggerDirect(pParse: ?*anyopaque, p: ?*anyopaque, pTab: ?*anyopaque, reg: c_int, orconf: c_int, ignoreJump: c_int) void;
extern fn sqlite3TokenInit(p: ?*anyopaque, z: ?[*:0]const u8) void;

// sqlite3StrBINARY is a C `char[]` — the symbol's *address* is the string.
extern const sqlite3StrBINARY: u8;
inline fn strBINARY() ?[*:0]const u8 {
    return @ptrCast(&sqlite3StrBINARY);
}

// VerifyAbortable is a real function only under SQLITE_DEBUG; otherwise a no-op.
extern fn sqlite3VdbeVerifyAbortable(p: ?*anyopaque, x: c_int) void;
inline fn vdbeVerifyAbortable(p: ?*anyopaque, x: c_int) void {
    if (config.sqlite_debug) sqlite3VdbeVerifyAbortable(p, x);
}

// ═══ COLUMN_MASK macro ═══════════════════════════════════════════════════════
inline fn columnMask(x: c_int) u32 {
    return if (x > 31) 0xffffffff else (@as(u32, 1) << @intCast(x));
}

// ═══ sqlite3FkLocateIndex ════════════════════════════════════════════════════
export fn sqlite3FkLocateIndex(
    pParse: ?*anyopaque,
    pParent: ?*anyopaque,
    pFKey: ?*anyopaque,
    ppIdx: *?*anyopaque,
    paiCol: ?*?[*]c_int,
) callconv(.c) c_int {
    var pIdx: ?*anyopaque = null;
    var aiCol: ?[*]c_int = null;
    const nCol: c_int = fkNCol(pFKey);
    const zKey: ?[*:0]const u8 = fkColZCol(pFKey, 0); // pFKey->aCol[0].zCol

    if (nCol == 1) {
        if (tabIPKey(pParent) >= 0) {
            if (zKey == null) return 0;
            const pkCol = tabColAt(pParent, tabIPKey(pParent));
            if (sqlite3StrICmp(colZCnName(pkCol), zKey) == 0) {
                return 0;
            }
        }
    } else if (paiCol != null) {
        // assert nCol>1
        aiCol = @ptrCast(@alignCast(sqlite3DbMallocRawNN(pDb(pParse), @as(u64, @intCast(nCol)) * @sizeOf(c_int))));
        if (aiCol == null) return 1;
        paiCol.?.* = aiCol;
    }

    pIdx = tabPIndex(pParent);
    while (pIdx != null) : (pIdx = idxPNext(pIdx)) {
        if (@as(c_int, idxNKeyCol(pIdx)) == nCol and idxIsUnique(pIdx) and idxPPartIdxWhere(pIdx) == null) {
            if (zKey == null) {
                if (idxIsPrimaryKey(pIdx)) {
                    if (aiCol) |ac| {
                        var i: usize = 0;
                        while (i < @as(usize, @intCast(nCol))) : (i += 1) {
                            ac[i] = fkColIFrom(pFKey, i);
                        }
                    }
                    break;
                }
            } else {
                var i: usize = 0;
                while (i < @as(usize, @intCast(nCol))) : (i += 1) {
                    const iColIdx: i16 = idxAiColumn(pIdx, i);
                    if (iColIdx < 0) break; // no FKs against expression indexes

                    var zDfltColl = sqlite3ColumnColl(tabColAt(pParent, iColIdx));
                    if (zDfltColl == null) zDfltColl = strBINARY();
                    if (sqlite3StrICmp(idxAzColl(pIdx, i), zDfltColl) != 0) break;

                    const zIdxCol = colZCnName(tabColAt(pParent, iColIdx));
                    var j: usize = 0;
                    while (j < @as(usize, @intCast(nCol))) : (j += 1) {
                        if (sqlite3StrICmp(fkColZCol(pFKey, j), zIdxCol) == 0) {
                            if (aiCol) |ac| ac[i] = fkColIFrom(pFKey, j);
                            break;
                        }
                    }
                    if (j == @as(usize, @intCast(nCol))) break;
                }
                if (i == @as(usize, @intCast(nCol))) break; // pIdx is usable
            }
        }
    }

    if (pIdx == null) {
        if (!pDisableTriggers(pParse)) {
            sqlite3ErrorMsg(pParse, "foreign key mismatch - \"%w\" referencing \"%w\"", tabZName(fkPFrom(pFKey)), fkZTo(pFKey));
        }
        sqlite3DbFree(pDb(pParse), @ptrCast(aiCol));
        return 1;
    }

    ppIdx.* = pIdx;
    return 0;
}

// ═══ fkLookupParent (static) ═════════════════════════════════════════════════
fn fkLookupParent(
    pParse: ?*anyopaque,
    iDb: c_int,
    pTab: ?*anyopaque,
    pIdx: ?*anyopaque,
    pFKey: ?*anyopaque,
    aiCol: [*]const c_int,
    regData: c_int,
    nIncr: c_int,
    isIgnore: c_int,
) void {
    const v = sqlite3GetVdbe(pParse);
    const iCur: c_int = pNTab(pParse) - 1;
    const iOk: c_int = sqlite3VdbeMakeLabel(pParse);

    vdbeVerifyAbortable(v, if (fkIsDeferred(pFKey) == 0 and (dbFlags(pDb(pParse)) & SQLITE_DeferFKs) == 0 and pPToplevel(pParse) == null and !pIsMultiWrite(pParse)) OE_Abort else OE_Ignore);

    if (nIncr < 0) {
        _ = sqlite3VdbeAddOp2(v, OP_FkIfZero, fkIsDeferred(pFKey), iOk);
    }
    {
        var i: c_int = 0;
        while (i < fkNCol(pFKey)) : (i += 1) {
            const iReg: c_int = sqlite3TableColumnToStorage(fkPFrom(pFKey), @intCast(aiCol[@intCast(i)])) + regData + 1;
            _ = sqlite3VdbeAddOp2(v, OP_IsNull, iReg, iOk);
        }
    }

    if (isIgnore == 0) {
        if (pIdx == null) {
            const regTemp = sqlite3GetTempReg(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_SCopy, sqlite3TableColumnToStorage(fkPFrom(pFKey), @intCast(aiCol[0])) + 1 + regData, regTemp);
            const iMustBeInt = sqlite3VdbeAddOp2(v, OP_MustBeInt, regTemp, 0);

            if (pTab == fkPFrom(pFKey) and nIncr == 1) {
                _ = sqlite3VdbeAddOp3(v, OP_Eq, regData, iOk, regTemp);
                sqlite3VdbeChangeP5(v, SQLITE_NOTNULL);
            }

            sqlite3OpenTable(pParse, iCur, iDb, pTab, OP_OpenRead);
            _ = sqlite3VdbeAddOp3(v, OP_NotExists, iCur, 0, regTemp);
            _ = sqlite3VdbeGoto(v, iOk);
            sqlite3VdbeJumpHere(v, sqlite3VdbeCurrentAddr(v) - 2);
            sqlite3VdbeJumpHere(v, iMustBeInt);
            sqlite3ReleaseTempReg(pParse, regTemp);
        } else {
            const nCol: c_int = fkNCol(pFKey);
            const regTemp = sqlite3GetTempRange(pParse, nCol);

            _ = sqlite3VdbeAddOp3(v, OP_OpenRead, iCur, @bitCast(idxTnum(pIdx)), iDb);
            sqlite3VdbeSetP4KeyInfo(pParse, pIdx);
            {
                var i: c_int = 0;
                while (i < nCol) : (i += 1) {
                    _ = sqlite3VdbeAddOp2(v, OP_Copy, sqlite3TableColumnToStorage(fkPFrom(pFKey), @intCast(aiCol[@intCast(i)])) + 1 + regData, regTemp + i);
                }
            }

            if (pTab == fkPFrom(pFKey) and nIncr == 1) {
                const iJump: c_int = sqlite3VdbeCurrentAddr(v) + nCol + 1;
                var i: c_int = 0;
                while (i < nCol) : (i += 1) {
                    const iChild: c_int = sqlite3TableColumnToStorage(fkPFrom(pFKey), @intCast(aiCol[@intCast(i)])) + 1 + regData;
                    var iParent: c_int = 1 + regData;
                    iParent += sqlite3TableColumnToStorage(idxPTable(pIdx), idxAiColumn(pIdx, @intCast(i)));
                    // assert aiColumn[i]>=0, aiCol[i]!=pTab->iPKey
                    if (idxAiColumn(pIdx, @intCast(i)) == tabIPKey(pTab)) {
                        iParent = regData;
                    }
                    _ = sqlite3VdbeAddOp3(v, OP_Ne, iChild, iJump, iParent);
                    sqlite3VdbeChangeP5(v, SQLITE_JUMPIFNULL);
                }
                _ = sqlite3VdbeGoto(v, iOk);
            }

            _ = sqlite3VdbeAddOp4(v, OP_Affinity, regTemp, nCol, 0, sqlite3IndexAffinityStr(pDb(pParse), pIdx), nCol);
            _ = sqlite3VdbeAddOp4Int(v, OP_Found, iCur, iOk, regTemp, nCol);
            sqlite3ReleaseTempRange(pParse, regTemp, nCol);
        }
    }

    if (fkIsDeferred(pFKey) == 0 and (dbFlags(pDb(pParse)) & SQLITE_DeferFKs) == 0 and pPToplevel(pParse) == null and !pIsMultiWrite(pParse)) {
        // assert nIncr==1
        sqlite3HaltConstraint(pParse, SQLITE_CONSTRAINT_FOREIGNKEY, OE_Abort, null, P4_STATIC, @intCast(P5_ConstraintFK));
    } else {
        if (nIncr > 0 and fkIsDeferred(pFKey) == 0) {
            sqlite3MayAbort(pParse);
        }
        _ = sqlite3VdbeAddOp2(v, OP_FkCounter, fkIsDeferred(pFKey), nIncr);
    }

    sqlite3VdbeResolveLabel(v, iOk);
    _ = sqlite3VdbeAddOp1(v, OP_Close, iCur);
}

// ═══ exprTableRegister (static) ══════════════════════════════════════════════
fn exprTableRegister(pParse: ?*anyopaque, pTab: ?*anyopaque, regBase: c_int, iCol: i16) ?*anyopaque {
    const db = pDb(pParse);
    var pExpr = sqlite3Expr(db, TK_REGISTER, null);
    if (pExpr != null) {
        if (iCol >= 0 and iCol != tabIPKey(pTab)) {
            const pCol = tabColAt(pTab, iCol);
            exprSetITable(pExpr, regBase + sqlite3TableColumnToStorage(pTab, iCol) + 1);
            exprSetAffExpr(pExpr, colAffinity(pCol));
            var zColl = sqlite3ColumnColl(pCol);
            if (zColl == null) zColl = dbDfltCollName(db);
            pExpr = sqlite3ExprAddCollateString(pParse, pExpr, zColl);
        } else {
            exprSetITable(pExpr, regBase);
            exprSetAffExpr(pExpr, SQLITE_AFF_INTEGER);
        }
    }
    return pExpr;
}

// ═══ exprTableColumn (static) ════════════════════════════════════════════════
fn exprTableColumn(db: ?*anyopaque, pTab: ?*anyopaque, iCursor: c_int, iCol: i16) ?*anyopaque {
    const pExpr = sqlite3Expr(db, TK_COLUMN, null);
    if (pExpr != null) {
        // assert ExprUseYTab(pExpr)
        std.debug.assert(exprUseYTab(pExpr));
        exprSetYTab(pExpr, pTab);
        exprSetITable(pExpr, iCursor);
        exprSetIColumn(pExpr, iCol);
    }
    return pExpr;
}

// ═══ fkScanChildren (static) ═════════════════════════════════════════════════
fn fkScanChildren(
    pParse: ?*anyopaque,
    pSrc: ?*anyopaque,
    pTab: ?*anyopaque,
    pIdx: ?*anyopaque,
    pFKey: ?*anyopaque,
    aiCol: ?[*]const c_int,
    regData: c_int,
    nIncr: c_int,
) void {
    const db = pDb(pParse);
    var pWhere: ?*anyopaque = null;
    var sNameContext: [sizeof_NameContext]u8 align(8) = undefined;
    var iFkIfZero: c_int = 0;
    const v = sqlite3GetVdbe(pParse);

    // assertions about pIdx/pTab elided.

    if (nIncr < 0) {
        iFkIfZero = sqlite3VdbeAddOp2(v, OP_FkIfZero, fkIsDeferred(pFKey), 0);
    }

    {
        var i: c_int = 0;
        while (i < fkNCol(pFKey)) : (i += 1) {
            const iCol: i16 = if (pIdx != null) idxAiColumn(pIdx, @intCast(i)) else -1;
            const pLeft = exprTableRegister(pParse, pTab, regData, iCol);
            const iChildCol: c_int = if (aiCol) |ac| ac[@intCast(i)] else fkColIFrom(pFKey, 0);
            // assert iChildCol>=0
            const zCol = colZCnName(tabColAt(fkPFrom(pFKey), iChildCol));
            const pRight = sqlite3Expr(db, TK_ID, zCol);
            const pEq = sqlite3PExpr(pParse, TK_EQ, pLeft, pRight);
            pWhere = sqlite3ExprAnd(pParse, pWhere, pEq);
        }
    }

    if (pTab == fkPFrom(pFKey) and nIncr > 0) {
        var pNe: ?*anyopaque = undefined;
        if (tabHasRowid(pTab)) {
            const pLeft = exprTableRegister(pParse, pTab, regData, -1);
            const pRight = exprTableColumn(db, pTab, itemICursor(srcItem0(pSrc)), -1);
            pNe = sqlite3PExpr(pParse, TK_NE, pLeft, pRight);
        } else {
            var pAll: ?*anyopaque = null;
            // assert pIdx!=0
            var i: c_int = 0;
            while (i < @as(c_int, idxNKeyCol(pIdx))) : (i += 1) {
                const iCol: i16 = idxAiColumn(pIdx, @intCast(i));
                // assert iCol>=0
                const pLeft = exprTableRegister(pParse, pTab, regData, iCol);
                const pRight = sqlite3Expr(db, TK_ID, colZCnName(tabColAt(pTab, iCol)));
                const pEq = sqlite3PExpr(pParse, TK_IS, pLeft, pRight);
                pAll = sqlite3ExprAnd(pParse, pAll, pEq);
            }
            pNe = sqlite3PExpr(pParse, TK_NOT, pAll, null);
        }
        pWhere = sqlite3ExprAnd(pParse, pWhere, pNe);
    }

    // memset(&sNameContext, 0, sizeof) then set pSrcList + pParse.
    @memset(sNameContext[0..], 0);
    const pNC: ?*anyopaque = @ptrCast(&sNameContext);
    ncSetPSrcList(pNC, pSrc);
    ncSetPParse(pNC, pParse);
    _ = sqlite3ResolveExprNames(pNC, pWhere);

    if (pNErr(pParse) == 0) {
        const pWInfo = sqlite3WhereBegin(pParse, pSrc, pWhere, null, null, null, 0, 0);
        _ = sqlite3VdbeAddOp2(v, OP_FkCounter, fkIsDeferred(pFKey), nIncr);
        if (pWInfo != null) {
            sqlite3WhereEnd(pWInfo);
        }
    }

    sqlite3ExprDelete(db, pWhere);
    if (iFkIfZero != 0) {
        sqlite3VdbeJumpHereOrPopInst(v, iFkIfZero);
    }
}

// ═══ sqlite3FkReferences ═════════════════════════════════════════════════════
export fn sqlite3FkReferences(pTab: ?*anyopaque) callconv(.c) ?*anyopaque {
    return sqlite3HashFind(schemaFkeyHash(tabPSchema(pTab)), tabZName(pTab));
}

// ═══ fkTriggerDelete (static) ════════════════════════════════════════════════
fn fkTriggerDelete(dbMem: ?*anyopaque, p: ?*anyopaque) void {
    if (p != null) {
        const pStep = trigStepList(p);
        sqlite3SrcListDelete(dbMem, stepPSrc(pStep));
        sqlite3ExprDelete(dbMem, stepPWhere(pStep));
        sqlite3ExprListDelete(dbMem, stepPExprList(pStep));
        sqlite3SelectDelete(dbMem, stepPSelect(pStep));
        sqlite3ExprDelete(dbMem, trigPWhen(p));
        sqlite3DbFree(dbMem, p);
    }
}

// ═══ sqlite3FkClearTriggerCache ══════════════════════════════════════════════
export fn sqlite3FkClearTriggerCache(db: ?*anyopaque, iDb: c_int) callconv(.c) void {
    const pSchema = dbAtPSchema(db, iDb);
    const pHash = schemaTblHash(pSchema);
    // for(k=sqliteHashFirst(pHash); k; k=sqliteHashNext(k))
    var k = rd(?*anyopaque, pHash, Hash_first_off);
    while (k) |elem| {
        const pTab = rd(?*anyopaque, elem, HashElem_data_off); // sqliteHashData
        if (tabIsOrdinary(pTab)) {
            var pFKey = tabPFKey(pTab);
            while (pFKey != null) : (pFKey = fkPNextFrom(pFKey)) {
                fkTriggerDelete(db, fkApTrigger(pFKey, 0));
                fkSetApTrigger(pFKey, 0, null);
                fkTriggerDelete(db, fkApTrigger(pFKey, 1));
                fkSetApTrigger(pFKey, 1, null);
            }
        }
        k = rd(?*anyopaque, elem, HashElem_next_off); // sqliteHashNext
    }
}

// ═══ sqlite3FkDropTable ══════════════════════════════════════════════════════
export fn sqlite3FkDropTable(pParse: ?*anyopaque, pName: ?*anyopaque, pTab: ?*anyopaque) callconv(.c) void {
    const db = pDb(pParse);
    if ((dbFlags(db) & SQLITE_ForeignKeys) != 0 and tabIsOrdinary(pTab)) {
        var iSkip: c_int = 0;
        const v = sqlite3GetVdbe(pParse);
        // assert v
        if (sqlite3FkReferences(pTab) == null) {
            var p = tabPFKey(pTab);
            while (p != null) : (p = fkPNextFrom(p)) {
                if (fkIsDeferred(p) != 0 or (dbFlags(db) & SQLITE_DeferFKs) != 0) break;
            }
            if (p == null) return;
            iSkip = sqlite3VdbeMakeLabel(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_FkIfZero, 1, iSkip);
        }

        pSetDisableTriggers(pParse, true);
        sqlite3DeleteFrom(pParse, sqlite3SrcListDup(db, pName, 0), null, null, null);
        pSetDisableTriggers(pParse, false);

        if ((dbFlags(db) & SQLITE_DeferFKs) == 0) {
            vdbeVerifyAbortable(v, OE_Abort);
            _ = sqlite3VdbeAddOp2(v, OP_FkIfZero, 0, sqlite3VdbeCurrentAddr(v) + 2);
            sqlite3HaltConstraint(pParse, SQLITE_CONSTRAINT_FOREIGNKEY, OE_Abort, null, P4_STATIC, @intCast(P5_ConstraintFK));
        }

        if (iSkip != 0) {
            sqlite3VdbeResolveLabel(v, iSkip);
        }
    }
}

// ═══ fkChildIsModified (static) ══════════════════════════════════════════════
fn fkChildIsModified(pTab: ?*anyopaque, p: ?*anyopaque, aChange: [*]const c_int, bChngRowid: c_int) c_int {
    var i: c_int = 0;
    while (i < fkNCol(p)) : (i += 1) {
        const iChildKey: c_int = fkColIFrom(p, @intCast(i));
        if (aChange[@intCast(iChildKey)] >= 0) return 1;
        if (iChildKey == tabIPKey(pTab) and bChngRowid != 0) return 1;
    }
    return 0;
}

// ═══ fkParentIsModified (static) ═════════════════════════════════════════════
fn fkParentIsModified(pTab: ?*anyopaque, p: ?*anyopaque, aChange: [*]const c_int, bChngRowid: c_int) c_int {
    var i: c_int = 0;
    while (i < fkNCol(p)) : (i += 1) {
        const zKey: ?[*:0]const u8 = fkColZCol(p, @intCast(i));
        var iKey: c_int = 0;
        while (iKey < @as(c_int, tabNCol(pTab))) : (iKey += 1) {
            if (aChange[@intCast(iKey)] >= 0 or (iKey == tabIPKey(pTab) and bChngRowid != 0)) {
                const pCol = tabColAt(pTab, iKey);
                if (zKey != null) {
                    if (sqlite3StrICmp(colZCnName(pCol), zKey) == 0) return 1;
                } else if ((colColFlags(pCol) & COLFLAG_PRIMKEY) != 0) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

// ═══ isSetNullAction (static) ════════════════════════════════════════════════
fn isSetNullAction(pParse: ?*anyopaque, pFKey: ?*anyopaque) c_int {
    const pTop = parseToplevel(pParse);
    const pTriggerPrg = pPTriggerPrg(pTop);
    if (pTriggerPrg != null) {
        const p = prgPTrigger(pTriggerPrg);
        if ((p == fkApTrigger(pFKey, 0) and fkAction(pFKey, 0) == OE_SetNull) or
            (p == fkApTrigger(pFKey, 1) and fkAction(pFKey, 1) == OE_SetNull))
        {
            // assert (pTop->db->flags & SQLITE_FkNoAction)==0
            return 1;
        }
    }
    return 0;
}

// ═══ sqlite3FkCheck ══════════════════════════════════════════════════════════
export fn sqlite3FkCheck(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    regOld: c_int,
    regNew: c_int,
    aChange: ?[*]const c_int,
    bChngRowid: c_int,
) callconv(.c) void {
    const db = pDb(pParse);
    const isIgnoreErrors: bool = pDisableTriggers(pParse);

    // assert (regOld==0) != (regNew==0)

    if ((dbFlags(db) & SQLITE_ForeignKeys) == 0) return;
    if (!tabIsOrdinary(pTab)) return;

    const iDb: c_int = sqlite3SchemaToIndex(db, tabPSchema(pTab));
    const zDb: ?[*:0]const u8 = dbAtZDbSName(db, iDb);

    // Loop through FKs where pTab is the child table.
    var pFKey = tabPFKey(pTab);
    while (pFKey != null) : (pFKey = fkPNextFrom(pFKey)) {
        var pTo: ?*anyopaque = null;
        var pIdx: ?*anyopaque = null;
        var aiFree: ?[*]c_int = null;
        var aiCol: [*]const c_int = undefined;
        var iColLocal: c_int = undefined;
        var bIgnore: c_int = 0;

        if (aChange != null and sqlite3_stricmp(tabZName(pTab), fkZTo(pFKey)) != 0 and fkChildIsModified(pTab, pFKey, aChange.?, bChngRowid) == 0) {
            continue;
        }

        if (pDisableTriggers(pParse)) {
            pTo = sqlite3FindTable(db, fkZTo(pFKey), zDb);
        } else {
            pTo = sqlite3LocateTable(pParse, 0, fkZTo(pFKey), zDb);
        }
        if (pTo == null or sqlite3FkLocateIndex(pParse, pTo, pFKey, &pIdx, &aiFree) != 0) {
            if (!isIgnoreErrors or dbMallocFailed(db)) return;
            if (pTo == null) {
                const v = sqlite3GetVdbe(pParse);
                const iJump: c_int = sqlite3VdbeCurrentAddr(v) + fkNCol(pFKey) + 1;
                var i: c_int = 0;
                while (i < fkNCol(pFKey)) : (i += 1) {
                    const iFromCol: c_int = fkColIFrom(pFKey, @intCast(i));
                    const iReg: c_int = sqlite3TableColumnToStorage(fkPFrom(pFKey), @intCast(iFromCol)) + regOld + 1;
                    _ = sqlite3VdbeAddOp2(v, OP_IsNull, iReg, iJump);
                }
                _ = sqlite3VdbeAddOp2(v, OP_FkCounter, fkIsDeferred(pFKey), -1);
            }
            continue;
        }
        // assert pFKey->nCol==1 || (aiFree && pIdx)

        if (aiFree) |af| {
            aiCol = af;
        } else {
            iColLocal = fkColIFrom(pFKey, 0);
            aiCol = @ptrCast(&iColLocal);
        }
        {
            var i: c_int = 0;
            while (i < fkNCol(pFKey)) : (i += 1) {
                if (aiFree) |af| {
                    if (af[@intCast(i)] == tabIPKey(pTab)) af[@intCast(i)] = -1;
                } else {
                    if (iColLocal == tabIPKey(pTab)) iColLocal = -1;
                }
                // SQLITE_OMIT_AUTHORIZATION OFF: request read permission.
                if (dbXAuth(db) != null) {
                    const parentColIdx: i16 = if (pIdx != null) idxAiColumn(pIdx, @intCast(i)) else tabIPKey(pTo);
                    const zCol = colZCnName(tabColAt(pTo, parentColIdx));
                    const rcauth = sqlite3AuthReadCol(pParse, tabZName(pTo), zCol, iDb);
                    bIgnore = @intFromBool(rcauth == SQLITE_IGNORE);
                }
            }
        }

        sqlite3TableLock(pParse, iDb, tabTnum(pTo), 0, tabZName(pTo));
        pSetNTab(pParse, pNTab(pParse) + 1);

        if (regOld != 0) {
            fkLookupParent(pParse, iDb, pTo, pIdx, pFKey, aiCol, regOld, -1, bIgnore);
        }
        if (regNew != 0 and isSetNullAction(pParse, pFKey) == 0) {
            fkLookupParent(pParse, iDb, pTo, pIdx, pFKey, aiCol, regNew, 1, bIgnore);
        }

        sqlite3DbFree(db, @ptrCast(aiFree));
    }

    // Loop through FKs that refer to this table (the "child" constraints).
    pFKey = sqlite3FkReferences(pTab);
    while (pFKey != null) : (pFKey = fkPNextTo(pFKey)) {
        var pIdx: ?*anyopaque = null;
        var aiCol: ?[*]c_int = null;

        if (aChange != null and fkParentIsModified(pTab, pFKey, aChange.?, bChngRowid) == 0) {
            continue;
        }

        if (fkIsDeferred(pFKey) == 0 and (dbFlags(db) & SQLITE_DeferFKs) == 0 and pPToplevel(pParse) == null and !pIsMultiWrite(pParse)) {
            // assert regOld==0 && regNew!=0
            continue;
        }

        if (sqlite3FkLocateIndex(pParse, pTab, pFKey, &pIdx, &aiCol) != 0) {
            if (!isIgnoreErrors or dbMallocFailed(db)) return;
            continue;
        }
        // assert aiCol || pFKey->nCol==1

        const pSrc = sqlite3SrcListAppend(pParse, null, null, null);
        if (pSrc != null) {
            const pItem = srcItem0(pSrc);
            itemSetPSTab(pItem, fkPFrom(pFKey));
            itemSetZName(pItem, tabZName(fkPFrom(pFKey)));
            tabSetNTabRef(fkPFrom(pFKey), tabNTabRef(fkPFrom(pFKey)) + 1);
            itemSetICursor(pItem, pNTab(pParse));
            pSetNTab(pParse, pNTab(pParse) + 1);

            if (regNew != 0) {
                fkScanChildren(pParse, pSrc, pTab, pIdx, pFKey, aiCol, regNew, -1);
            }
            if (regOld != 0) {
                var eAction: c_int = fkAction(pFKey, @intFromBool(aChange != null));
                if ((dbFlags(db) & SQLITE_FkNoAction) != 0) eAction = OE_None;

                fkScanChildren(pParse, pSrc, pTab, pIdx, pFKey, aiCol, regOld, 1);
                if (fkIsDeferred(pFKey) == 0 and eAction != OE_Cascade and eAction != OE_SetNull) {
                    sqlite3MayAbort(pParse);
                }
            }
            itemSetZName(pItem, null);
            sqlite3SrcListDelete(db, pSrc);
        }
        sqlite3DbFree(db, @ptrCast(aiCol));
    }
}

// ═══ sqlite3FkOldmask ════════════════════════════════════════════════════════
export fn sqlite3FkOldmask(pParse: ?*anyopaque, pTab: ?*anyopaque) callconv(.c) u32 {
    var mask: u32 = 0;
    if ((dbFlags(pDb(pParse)) & SQLITE_ForeignKeys) != 0 and tabIsOrdinary(pTab)) {
        var p = tabPFKey(pTab);
        while (p != null) : (p = fkPNextFrom(p)) {
            var i: c_int = 0;
            while (i < fkNCol(p)) : (i += 1) {
                mask |= columnMask(fkColIFrom(p, @intCast(i)));
            }
        }
        p = sqlite3FkReferences(pTab);
        while (p != null) : (p = fkPNextTo(p)) {
            var pIdx: ?*anyopaque = null;
            _ = sqlite3FkLocateIndex(pParse, pTab, p, &pIdx, null);
            if (pIdx != null) {
                var i: c_int = 0;
                while (i < @as(c_int, idxNKeyCol(pIdx))) : (i += 1) {
                    mask |= columnMask(idxAiColumn(pIdx, @intCast(i)));
                }
            }
        }
    }
    return mask;
}

// ═══ sqlite3FkRequired ═══════════════════════════════════════════════════════
export fn sqlite3FkRequired(pParse: ?*anyopaque, pTab: ?*anyopaque, aChange: ?[*]const c_int, chngRowid: c_int) callconv(.c) c_int {
    var eRet: c_int = 1;
    var bHaveFK: c_int = 0;
    if ((dbFlags(pDb(pParse)) & SQLITE_ForeignKeys) != 0 and tabIsOrdinary(pTab)) {
        if (aChange == null) {
            bHaveFK = @intFromBool(sqlite3FkReferences(pTab) != null or tabPFKey(pTab) != null);
        } else {
            var p = tabPFKey(pTab);
            while (p != null) : (p = fkPNextFrom(p)) {
                if (fkChildIsModified(pTab, p, aChange.?, chngRowid) != 0) {
                    if (sqlite3_stricmp(tabZName(pTab), fkZTo(p)) == 0) eRet = 2;
                    bHaveFK = 1;
                }
            }
            p = sqlite3FkReferences(pTab);
            while (p != null) : (p = fkPNextTo(p)) {
                if (fkParentIsModified(pTab, p, aChange.?, chngRowid) != 0) {
                    if ((dbFlags(pDb(pParse)) & SQLITE_FkNoAction) == 0 and fkAction(p, 1) != OE_None) {
                        return 2;
                    }
                    bHaveFK = 1;
                }
            }
        }
    }
    return if (bHaveFK != 0) eRet else 0;
}

// ═══ fkActionTrigger (static) ════════════════════════════════════════════════
// A tiny stack Token used to seed Expr nodes (matches `struct Token{z;n}`).
const Token = extern struct { z: ?[*:0]const u8, n: c_uint };

fn fkActionTrigger(pParse: ?*anyopaque, pTab: ?*anyopaque, pFKey: ?*anyopaque, pChanges: ?*anyopaque) ?*anyopaque {
    const db = pDb(pParse);
    var action: c_int = undefined;
    var pTrigger: ?*anyopaque = null;
    const iAction: usize = @intFromBool(pChanges != null);

    action = fkAction(pFKey, iAction);
    if ((dbFlags(db) & SQLITE_FkNoAction) != 0) action = OE_None;
    if (action == OE_Restrict and (dbFlags(db) & SQLITE_DeferFKs) != 0) {
        return null;
    }
    pTrigger = fkApTrigger(pFKey, iAction);

    if (action != OE_None and pTrigger == null) {
        var pIdx: ?*anyopaque = null;
        var aiCol: ?[*]c_int = null;
        var pStep: ?*anyopaque = null;
        var pWhere: ?*anyopaque = null;
        var pList: ?*anyopaque = null;
        var pSelect: ?*anyopaque = null;
        var pWhen: ?*anyopaque = null;

        if (sqlite3FkLocateIndex(pParse, pTab, pFKey, &pIdx, &aiCol) != 0) return null;
        // assert aiCol || pFKey->nCol==1

        var i: c_int = 0;
        while (i < fkNCol(pFKey)) : (i += 1) {
            var tOld: Token = .{ .z = "old", .n = 3 };
            var tNew: Token = .{ .z = "new", .n = 3 };
            var tFromCol: Token = undefined;
            var tToCol: Token = undefined;

            const iFromCol: c_int = if (aiCol) |ac| ac[@intCast(i)] else fkColIFrom(pFKey, 0);
            // asserts elided
            const toColIdx: i16 = if (pIdx != null) idxAiColumn(pIdx, @intCast(i)) else tabIPKey(pTab);
            sqlite3TokenInit(&tToCol, colZCnName(tabColAt(pTab, toColIdx)));
            sqlite3TokenInit(&tFromCol, colZCnName(tabColAt(fkPFrom(pFKey), iFromCol)));

            // pEq = OLD.zToCol = zFromCol
            var pEq = sqlite3PExpr(pParse, TK_EQ, sqlite3PExpr(pParse, TK_DOT, sqlite3ExprAlloc(db, TK_ID, &tOld, 0), sqlite3ExprAlloc(db, TK_ID, &tToCol, 0)), sqlite3ExprAlloc(db, TK_ID, &tFromCol, 0));
            pWhere = sqlite3ExprAnd(pParse, pWhere, pEq);

            // For ON UPDATE, build the WHEN clause term.
            if (pChanges != null) {
                pEq = sqlite3PExpr(pParse, TK_IS, sqlite3PExpr(pParse, TK_DOT, sqlite3ExprAlloc(db, TK_ID, &tOld, 0), sqlite3ExprAlloc(db, TK_ID, &tToCol, 0)), sqlite3PExpr(pParse, TK_DOT, sqlite3ExprAlloc(db, TK_ID, &tNew, 0), sqlite3ExprAlloc(db, TK_ID, &tToCol, 0)));
                pWhen = sqlite3ExprAnd(pParse, pWhen, pEq);
            }

            if (action != OE_Restrict and (action != OE_Cascade or pChanges != null)) {
                var pNew: ?*anyopaque = undefined;
                if (action == OE_Cascade) {
                    pNew = sqlite3PExpr(pParse, TK_DOT, sqlite3ExprAlloc(db, TK_ID, &tNew, 0), sqlite3ExprAlloc(db, TK_ID, &tToCol, 0));
                } else if (action == OE_SetDflt) {
                    const pCol = tabColAt(fkPFrom(pFKey), iFromCol);
                    var pDflt: ?*anyopaque = null;
                    if ((colColFlags(pCol) & COLFLAG_GENERATED) != 0) {
                        pDflt = null;
                    } else {
                        pDflt = sqlite3ColumnExpr(fkPFrom(pFKey), pCol);
                    }
                    if (pDflt != null) {
                        pNew = sqlite3ExprDup(db, pDflt, 0);
                    } else {
                        pNew = sqlite3ExprAlloc(db, TK_NULL, null, 0);
                    }
                } else {
                    pNew = sqlite3ExprAlloc(db, TK_NULL, null, 0);
                }
                pList = sqlite3ExprListAppend(pParse, pList, pNew);
                sqlite3ExprListSetName(pParse, pList, &tFromCol, 0);
            }
        }
        sqlite3DbFree(db, @ptrCast(aiCol));

        const zFrom = tabZName(fkPFrom(pFKey));
        const nFrom: c_int = sqlite3Strlen30(zFrom);

        if (action == OE_Restrict) {
            var pRaise = sqlite3Expr(db, TK_STRING, "FOREIGN KEY constraint failed");
            pRaise = sqlite3PExpr(pParse, TK_RAISE, pRaise, null);
            if (pRaise != null) {
                exprSetAffExpr(pRaise, OE_Abort);
            }
            const pSrc = sqlite3SrcListAppend(pParse, null, null, null);
            if (pSrc != null) {
                const pItem = srcItem0(pSrc);
                itemSetZName(pItem, sqlite3DbStrDup(db, zFrom));
                // pItem->fg.fixedSchema = 1; pItem->u4.pSchema = pTab->pSchema
                itemSetFixedSchema(pItem);
                itemSetU4PSchema(pItem, tabPSchema(pTab));
            }
            pSelect = sqlite3SelectNew(pParse, sqlite3ExprListAppend(pParse, null, pRaise), pSrc, pWhere, null, null, null, 0, null);
            pWhere = null;
        }

        // Disable lookaside allocation.
        const savedDLA = dbDisableLookaside(db);

        pTrigger = sqlite3DbMallocZero(db, @as(u64, sizeof_Trigger) + @as(u64, sizeof_TriggerStep));
        if (pTrigger != null) {
            // pStep = pTrigger->step_list = (TriggerStep*)&pTrigger[1]
            pStep = @ptrCast(base(pTrigger) + sizeof_Trigger);
            trigSetStepList(pTrigger, pStep);
            stepSetPSrc(pStep, sqlite3SrcListAppend(pParse, null, null, null));
            if (stepPSrc(pStep) != null) {
                const pItem = srcItem0(stepPSrc(pStep));
                itemSetZName(pItem, sqlite3DbStrNDup(db, zFrom, @intCast(nFrom)));
                itemSetU4PSchema(pItem, tabPSchema(pTab));
                itemSetFixedSchema(pItem);
            }
            stepSetPWhere(pStep, sqlite3ExprDup(db, pWhere, EXPRDUP_REDUCE));
            stepSetPExprList(pStep, sqlite3ExprListDup(db, pList, EXPRDUP_REDUCE));
            stepSetPSelect(pStep, sqlite3SelectDup(db, pSelect, EXPRDUP_REDUCE));
            if (pWhen != null) {
                pWhen = sqlite3PExpr(pParse, TK_NOT, pWhen, null);
                trigSetPWhen(pTrigger, sqlite3ExprDup(db, pWhen, EXPRDUP_REDUCE));
            }
        }

        // Re-enable lookaside.
        dbRestoreLookaside(db, savedDLA);

        sqlite3ExprDelete(db, pWhere);
        sqlite3ExprDelete(db, pWhen);
        sqlite3ExprListDelete(db, pList);
        sqlite3SelectDelete(db, pSelect);
        if (dbMallocFailedIs1(db)) {
            fkTriggerDelete(db, pTrigger);
            return null;
        }
        // assert pStep!=0, pTrigger!=0

        switch (action) {
            OE_Restrict => stepSetOp(pStep, TK_SELECT),
            OE_Cascade => {
                if (pChanges == null) {
                    stepSetOp(pStep, TK_DELETE);
                } else {
                    stepSetOp(pStep, TK_UPDATE);
                }
            },
            else => stepSetOp(pStep, TK_UPDATE),
        }
        stepSetPTrig(pStep, pTrigger);
        trigSetPSchema(pTrigger, tabPSchema(pTab));
        trigSetPTabSchema(pTrigger, tabPSchema(pTab));
        fkSetApTrigger(pFKey, iAction, pTrigger);
        trigSetOp(pTrigger, @intCast(if (pChanges != null) TK_UPDATE else TK_DELETE));
    }

    return pTrigger;
}

// ─── lookaside enable/disable (DisableLookaside/EnableLookaside macros) ───────
// db->lookaside.bDisable++ ; db->lookaside.sz=0  (disable)
// db->lookaside.bDisable-- ; db->lookaside.sz = bDisable ? 0 : szTrue (enable)
const sqlite3_lookaside_bDisable_off: usize = if (@hasDecl(L, "sqlite3_lookaside_bDisable")) L.sqlite3_lookaside_bDisable else 432;
const sqlite3_lookaside_sz_off: usize = if (@hasDecl(L, "sqlite3_lookaside_sz")) L.sqlite3_lookaside_sz else 436;
const sqlite3_lookaside_szTrue_off: usize = if (@hasDecl(L, "sqlite3_lookaside_szTrue")) L.sqlite3_lookaside_szTrue else 438;

fn dbDisableLookaside(db: ?*anyopaque) u16 {
    const bd = rd(u32, db, sqlite3_lookaside_bDisable_off);
    wr(u32, db, sqlite3_lookaside_bDisable_off, bd +% 1);
    const oldSz = rd(u16, db, sqlite3_lookaside_sz_off);
    wr(u16, db, sqlite3_lookaside_sz_off, 0);
    return oldSz;
}
fn dbRestoreLookaside(db: ?*anyopaque, _: u16) void {
    const bd = rd(u32, db, sqlite3_lookaside_bDisable_off) -% 1;
    wr(u32, db, sqlite3_lookaside_bDisable_off, bd);
    const szTrue = rd(u16, db, sqlite3_lookaside_szTrue_off);
    wr(u16, db, sqlite3_lookaside_sz_off, if (bd != 0) 0 else szTrue);
}

// db->mallocFailed==1 (the strict ==1 test C uses here)
inline fn dbMallocFailedIs1(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] == 1;
}

// SrcItem.fg.fixedSchema (bit) and u4.pSchema (offset).
const SrcItem_fixedSchema_byte: usize = if (@hasDecl(L, "SrcItem_fixedSchema_byte")) L.SrcItem_fixedSchema_byte else 27;
const SrcItem_fixedSchema_bit: u8 = 0x01;
const SrcItem_u4_off: usize = if (@hasDecl(L, "SrcItem_u4")) L.SrcItem_u4 else 64;
inline fn itemSetFixedSchema(pItem: ?*anyopaque) void {
    base(pItem)[SrcItem_fixedSchema_byte] |= SrcItem_fixedSchema_bit;
}
inline fn itemSetU4PSchema(pItem: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, pItem, SrcItem_u4_off, v);
}

// ═══ sqlite3FkActions ════════════════════════════════════════════════════════
export fn sqlite3FkActions(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    pChanges: ?*anyopaque,
    regOld: c_int,
    aChange: ?[*]const c_int,
    bChngRowid: c_int,
) callconv(.c) void {
    if ((dbFlags(pDb(pParse)) & SQLITE_ForeignKeys) != 0) {
        var pFKey = sqlite3FkReferences(pTab);
        while (pFKey != null) : (pFKey = fkPNextTo(pFKey)) {
            if (aChange == null or fkParentIsModified(pTab, pFKey, aChange.?, bChngRowid) != 0) {
                const pAct = fkActionTrigger(pParse, pTab, pFKey, pChanges);
                if (pAct != null) {
                    sqlite3CodeRowTriggerDirect(pParse, pAct, pTab, regOld, OE_Abort, 0);
                }
            }
        }
    }
}

// ═══ sqlite3FkDelete ═════════════════════════════════════════════════════════
const sqlite3_pnBytesFreed_off: usize = if (@hasDecl(L, "sqlite3_pnBytesFreed")) L.sqlite3_pnBytesFreed else 792;
inline fn dbPnBytesFreed(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_pnBytesFreed_off);
}

export fn sqlite3FkDelete(db: ?*anyopaque, pTab: ?*anyopaque) callconv(.c) void {
    // assert IsOrdinaryTable(pTab); assert db!=0
    var pFKey = tabPFKey(pTab);
    var pNext: ?*anyopaque = undefined;
    while (pFKey != null) : (pFKey = pNext) {
        // Remove the FK from the fkeyHash hash table.
        if (dbPnBytesFreed(db) == null) {
            if (fkPPrevTo(pFKey) != null) {
                // pFKey->pPrevTo->pNextTo = pFKey->pNextTo
                fkSetPNextTo(fkPPrevTo(pFKey), fkPNextTo(pFKey));
            } else {
                const z: ?[*:0]const u8 = if (fkPNextTo(pFKey) != null) fkZTo(fkPNextTo(pFKey)) else fkZTo(pFKey);
                _ = sqlite3HashInsert(schemaFkeyHash(tabPSchema(pTab)), z, fkPNextTo(pFKey));
            }
            if (fkPNextTo(pFKey) != null) {
                // pFKey->pNextTo->pPrevTo = pFKey->pPrevTo
                fkSetPPrevTo(fkPNextTo(pFKey), fkPPrevTo(pFKey));
            }
        }

        // assert isDeferred==0 || ==1

        fkTriggerDelete(db, fkApTrigger(pFKey, 0));
        fkTriggerDelete(db, fkApTrigger(pFKey, 1));

        pNext = fkPNextFrom(pFKey);
        sqlite3DbFree(db, pFKey);
    }
}
