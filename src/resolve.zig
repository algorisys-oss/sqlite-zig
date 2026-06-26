//! Zig port of SQLite's src/resolve.c — name resolution: binding identifiers in
//! expressions to tables/columns/result-set aliases, resolving ORDER BY/GROUP BY
//! ordinals, and the NameContext machinery.
//!
//! Exported (callconv(.c)) external-linkage symbols — the complete external set
//! of resolve.c, matching the prototypes in sqliteInt.h:
//!   - sqlite3MatchEName
//!   - sqlite3ExprColUsed
//!   - sqlite3CreateColumnExpr
//!   - sqlite3ResolveExprNames
//!   - sqlite3ResolveExprListNames
//!   - sqlite3ResolveSelectNames
//!   - sqlite3ResolveSelfReference
//!   - sqlite3ResolveOrderGroupBy
//! All other routines (lookupName, resolveExprStep, resolveSelectStep,
//! resolveAlias, resolveOrderGroupBy, etc.) are static in C and kept private
//! here. resolveExprStep/resolveSelectStep are passed to the C walker via the
//! Walker callback fields (C ABI), so they carry callconv(.c).
//!
//! ─── Config / build assumptions (true in BOTH configs of this project) ───────
//!   * SQLITE_OMIT_TRIGGER / SQLITE_OMIT_UPSERT / SQLITE_OMIT_SUBQUERY OFF
//!   * SQLITE_OMIT_WINDOWFUNC OFF, SQLITE_OMIT_AUTHORIZATION OFF
//!   * SQLITE_OMIT_CHECK / SQLITE_OMIT_GENERATED_COLUMNS OFF
//!   * SQLITE_ALLOW_ROWID_IN_VIEW OFF (the common, simpler ROWID path)
//!   * SQLITE_ENABLE_NORMALIZE OFF (no sqlite3VdbeAddDblquoteStr call)
//!   * SQLITE_ENABLE_UNKNOWN_SQL_FUNCTION ON (no-such-func gated on explain==0)
//!   * SQLITE_MAX_EXPR_DEPTH == 1000 (>0 → nHeight tracking active)
//!   * IN_RENAME_OBJECT == (pParse->eParseMode >= PARSE_MODE_RENAME)
//!   * Little-endian x86-64.
//!
//! ─── Ground-truth offsets ───────────────────────────────────────────────────
//! Every offset probe-verified with offsetof in BOTH the production library and
//! the `--dev` testfixture (SQLITE_DEBUG+SQLITE_TEST) config. ALL are IDENTICAL
//! across configs EXCEPT Parse.bReturning/bHasExists (the known SQLITE_DEBUG-
//! divergent Parse bitfield region: byte 39 prod / byte 42 dev), gated on config.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ═══ result codes / encodings ════════════════════════════════════════════════
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_WARNING: c_int = 28;

// ═══ WRC walk return codes ═══════════════════════════════════════════════════
const WRC_Continue: c_int = 0;
const WRC_Prune: c_int = 1;
const WRC_Abort: c_int = 2;

// ═══ TK_* tokens (from parse.h) ══════════════════════════════════════════════
const TK_EXISTS: u8 = 20;
const TK_IS: u8 = 45;
const TK_ISNOT: u8 = 46;
const TK_BETWEEN: u8 = 49;
const TK_IN: u8 = 50;
const TK_ISNULL: u8 = 51;
const TK_NOTNULL: u8 = 52;
const TK_NE: u8 = 53;
const TK_EQ: u8 = 54;
const TK_GT: u8 = 55;
const TK_LE: u8 = 56;
const TK_LT: u8 = 57;
const TK_GE: u8 = 58;
const TK_ID: u8 = 60;
const TK_ROW: u8 = 76;
const TK_TRIGGER: u8 = 78;
const TK_COLLATE: u8 = 114;
const TK_STRING: u8 = 118;
const TK_NULL: u8 = 122;
const TK_INSERT: u8 = 128;
const TK_DELETE: u8 = 129;
const TK_UPDATE: u8 = 130;
const TK_SELECT: u8 = 139;
const TK_DOT: u8 = 142;
const TK_ORDER: u8 = 146;
const TK_FLOAT: u8 = 154;
const TK_INTEGER: u8 = 156;
const TK_VARIABLE: u8 = 157;
const TK_COLUMN: u8 = 168;
const TK_AGG_FUNCTION: u8 = 169;
const TK_TRUEFALSE: u8 = 171;
const TK_FUNCTION: u8 = 172;
const TK_TRUTH: u8 = 175;
const TK_REGISTER: u8 = 176;

// ═══ NC_* name-context flags ═════════════════════════════════════════════════
const NC_AllowAgg: c_int = 0x000001;
const NC_PartIdx: c_int = 0x000002;
const NC_IsCheck: c_int = 0x000004;
const NC_GenCol: c_int = 0x000008;
const NC_HasAgg: c_int = 0x000010;
const NC_IdxExpr: c_int = 0x000020;
const NC_SelfRef: c_int = 0x00002e;
const NC_Subquery: c_int = 0x000040;
const NC_UEList: c_int = 0x000080;
const NC_UAggInfo: c_int = 0x000100;
const NC_UUpsert: c_int = 0x000200;
const NC_UBaseReg: c_int = 0x000400;
const NC_MinMaxAgg: c_int = 0x001000;
const NC_AllowWin: c_int = 0x004000;
const NC_HasWin: c_int = 0x008000;
const NC_IsDDL: c_int = 0x010000;
const NC_FromDDL: c_int = 0x040000;
const NC_NoSelect: c_int = 0x080000;
const NC_Where: c_int = 0x100000;
const NC_OrderAgg: c_int = 0x8000000;

// ═══ ENAME_* result-set-name kinds ═══════════════════════════════════════════
const ENAME_NAME: u8 = 0;
const ENAME_TAB: u8 = 2;
const ENAME_ROWID: u8 = 3;

// ═══ EP_* expr flags (u32 bitmask) ═══════════════════════════════════════════
const EP_Agg: u32 = 0x000010;
const EP_VarSelect: u32 = 0x000040;
const EP_DblQuoted: u32 = 0x000080;
const EP_IntValue: u32 = 0x000800;
const EP_xIsSelect: u32 = 0x001000;
const EP_Reduced: u32 = 0x004000;
const EP_Win: u32 = 0x008000;
const EP_TokenOnly: u32 = 0x010000;
const EP_Unlikely: u32 = 0x080000;
const EP_ConstFunc: u32 = 0x100000;
const EP_CanBeNull: u32 = 0x200000;
const EP_Leaf: u32 = 0x800000;
const EP_WinFunc: u32 = 0x1000000;
const EP_FromDDL: u32 = 0x40000000;
const EP_SubtArg: u32 = 0x80000000;
// vvaFlags (Expr.vvaFlags, SQLITE_DEBUG only): EP_NoReduce 0x01.

// ═══ misc constants ══════════════════════════════════════════════════════════
const EXCLUDED_TABLE_NUMBER: c_int = 2;
const SQLITE_LIMIT_COLUMN: usize = 2;
const PARSE_MODE_RENAME: u8 = 2;
const DBFLAG_InternalFunc: u32 = 0x0020;

// affinity
const SQLITE_AFF_INTEGER: u8 = 0x44;
const SQLITE_AFF_DEFER: u8 = 0x58;

// join-type bits (SrcItem.fg.jointype)
const JT_LEFT: u8 = 0x08;
const JT_RIGHT: u8 = 0x10;
const JT_LTORJ: u8 = 0x40;

// FuncDef.funcFlags
const SQLITE_FUNC_UNLIKELY: u32 = 0x0400;
const SQLITE_FUNC_CONSTANT: u32 = 0x0800;
const SQLITE_FUNC_MINMAX: u32 = 0x1000;
const SQLITE_FUNC_SLOCHNG: u32 = 0x2000;
const SQLITE_FUNC_WINDOW: u32 = 0x00010000;
const SQLITE_FUNC_INTERNAL: u32 = 0x00040000;
const SQLITE_FUNC_DIRECT: u32 = 0x00080000;
const SQLITE_SUBTYPE: u32 = 0x00100000;
const SQLITE_FUNC_UNSAFE: u32 = 0x00200000;
const SQLITE_FUNC_ANYORDER: u32 = 0x08000000;

// Select.selFlags
const SF_Resolved: u32 = 0x0000004;
const SF_Aggregate: u32 = 0x0000008;
const SF_Expanded: u32 = 0x0000040;
const SF_NestedFrom: u32 = 0x0000800;
const SF_MinMaxAgg: u32 = 0x0001000;
const SF_Converted: u32 = 0x0010000;
const SF_OrderByReqd: u32 = 0x8000000;
const SF_Correlated: u32 = 0x20000000;
const SF_OnToWhere: u32 = 0x40000000;

// Table.tabFlags / Column.colFlags
const TF_HasGenerated: u32 = 0x00000060;
const TF_NoVisibleRowid: u32 = 0x00000200;
const COLFLAG_GENERATED: u16 = 0x0060;

// Bitmask width
const BMS: c_int = 64;
const ALLBITS: u64 = ~@as(u64, 0);

// ═══ ground-truth offsets (c_layout where present, probe fallback else) ═══════
fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

// Expr (config-invariant: vvaFlags padding keeps offsets stable)
const Expr_op_off = off("Expr_op", 0);
const Expr_affExpr_off = off("Expr_affExpr", 1);
const Expr_op2_off: usize = 2;
const Expr_flags_off = off("Expr_flags", 4);
const Expr_u_off = off("Expr_u", 8);
const Expr_pLeft_off = off("Expr_pLeft", 16);
const Expr_pRight_off = off("Expr_pRight", 24);
const Expr_x_off = off("Expr_x", 32);
const Expr_nHeight_off: usize = 40;
const Expr_iTable_off = off("Expr_iTable", 44);
const Expr_iColumn_off = off("Expr_iColumn", 48);
const Expr_iAgg_off: usize = 50;
const Expr_pAggInfo_off: usize = 56;
const Expr_y_off = off("Expr_yTab", 64); // y.pTab / y.pWin share y's first member

// ExprList / ExprList_item
const ExprList_nExpr_off = off("ExprList_nExpr", 0);
const ExprList_a_off = off("ExprList_a", 8);
const ExprList_item_pExpr_off = off("ExprList_item_pExpr", 0);
const ExprList_item_zEName_off = off("ExprList_item_zEName", 8);
const ExprList_item_fg_off: usize = 16;
const ExprList_item_u_off: usize = 20; // u.x.iOrderByCol is first (u16)
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);
// ELi.fg bitfield bytes (relative to fg @16): eEName byte1 0x03, done byte1 0x04,
// bUsed byte1 0x40, bUsingTerm byte1 0x80.
const ELi_fg_eEName_byte: usize = 1;
const ELi_fg_done_bit: u8 = 0x04;
const ELi_fg_bUsed_bit: u8 = 0x40;
const ELi_fg_bUsingTerm_bit: u8 = 0x80;

// NameContext
const NC_pParse_off = off("NameContext_pParse", 0);
const NC_pSrcList_off = off("NameContext_pSrcList", 8);
const NC_uNC_off = off("NameContext_uNC", 16);
const NC_pNext_off: usize = 24;
const NC_nRef_off: usize = 32;
const NC_nNcErr_off: usize = 36;
const NC_ncFlags_off = off("NameContext_ncFlags", 40);
const NC_nNestedSelect_off: usize = 44;
const NC_pWinSelect_off: usize = 48;
const sizeof_NameContext = off("sizeof_NameContext", 56);

// Select
const Select_selFlags_off = off("Select_selFlags", 4);
const Select_pEList_off = off("Select_pEList", 24);
const Select_pSrc_off = off("Select_pSrc", 32);
const Select_pWhere_off: usize = 40;
const Select_pGroupBy_off: usize = 48;
const Select_pHaving_off: usize = 56;
const Select_pOrderBy_off: usize = 64;
const Select_pPrior_off: usize = 72;
const Select_pNext_off: usize = 80;
const Select_pLimit_off: usize = 88;
const Select_pWin_off: usize = 104;
const Select_pWinDefn_off: usize = 112;

// Window (pWinDefn list)
const Window_pPartition_off: usize = 16;
const Window_pOrderBy_off: usize = 24;
const Window_pFilter_off: usize = 72;
const Window_pNextWin_off: usize = 64;
const Window_pOwner_off: usize = 112; // probe-verified (NOT first member)

// SrcList / SrcItem
const SrcList_nSrc_off = off("SrcList_nSrc", 0);
const SrcList_nAlloc_off: usize = 4;
const SrcList_a_off = off("SrcList_a", 8);
const SrcItem_pSTab_off = off("SrcItem_pSTab", 16);
const SrcItem_iCursor_off = off("SrcItem_iCursor", 28);
const SrcItem_zAlias_off: usize = 8;
const SrcItem_fg_off = off("SrcItem_fg", 24);
const SrcItem_colUsed_off: usize = 32;
const SrcItem_u1_off: usize = 40;
const SrcItem_u3_off = off("SrcItem_u3", 56);
const SrcItem_u4_off = off("SrcItem_u4", 64);
const sizeof_SrcItem = off("sizeof_SrcItem", 72);
// SrcItem.fg bitfield bytes (relative to fg @24):
const SI_fg_jointype_byte: usize = 0; // jointype is u8 at fg+0
const SI_fg_isSubquery_byte: usize = 1;
const SI_fg_isSubquery_bit: u8 = 0x04;
const SI_fg_isTabFunc_byte: usize = 1;
const SI_fg_isTabFunc_bit: u8 = 0x08;
const SI_fg_isCorrelated_byte: usize = 1;
const SI_fg_isCorrelated_bit: u8 = 0x10;
const SI_fg_isNestedFrom_byte: usize = 2;
const SI_fg_isNestedFrom_bit: u8 = 0x40;
const SI_fg_isUsing_byte: usize = 2;
const SI_fg_isUsing_bit: u8 = 0x08;
const SI_fg_rowidUsed_byte: usize = 2;
const SI_fg_rowidUsed_bit: u8 = 0x80;

// Table
const Table_zName_off = off("Table_zName", 0);
const Table_aCol_off = off("Table_aCol", 8);
const Table_tnum_off = off("Table_tnum", 40);
const Table_tabFlags_off = off("Table_tabFlags", 48);
const Table_iPKey_off = off("Table_iPKey", 52);
const Table_nCol_off = off("Table_nCol", 54);
const Table_pSchema_off = off("Table_pSchema", 96);
const sizeof_Column = off("sizeof_Column", 16);
const Column_colFlags_off = off("Column_colFlags", 14);

// Parse
const Parse_db_off = off("Parse_db", 0);
const Parse_pVdbe_off = off("Parse_pVdbe", 16);
const Parse_nested_off = off("Parse_nested", 30);
const Parse_nErr_off = off("Parse_nErr", 52);
const Parse_eParseMode_off = off("Parse_eParseMode", 300);
const Parse_explain_off = off("Parse_explain", 299);
const Parse_pTriggerTab_off = off("Parse_pTriggerTab", 144);
const Parse_eTriggerOp_off = off("Parse_eTriggerOp", 37);
const Parse_oldmask_off = off("Parse_oldmask", 224);
const Parse_newmask_off = off("Parse_newmask", 228);
const Parse_zAuthContext_off = off("Parse_zAuthContext", 368);
const Parse_nHeight_off: usize = 308;
// Parse.bReturning / bHasExists / checkSchema — SQLITE_DEBUG-divergent bitfield
// region (probe-verified bytes prod / dev).
const Parse_bReturning_byte: usize = if (config.sqlite_debug) 42 else 39;
const Parse_bReturning_bit: u8 = 0x08;
const Parse_bHasExists_byte: usize = if (config.sqlite_debug) 42 else 39;
const Parse_bHasExists_bit: u8 = 0x10;
const Parse_checkSchema_byte: usize = if (config.sqlite_debug) 43 else 40;
const Parse_checkSchema_bit: u8 = 0x01;

// sqlite3
const db_nDb_off = off("sqlite3_nDb", 40);
const db_aDb_off = off("sqlite3_aDb", 32);
const db_aLimit_off = off("sqlite3_aLimit", 136);
const db_flags_off = off("sqlite3_flags", 48);
const db_mDbFlags_off = off("sqlite3_mDbFlags", 44);
const db_mallocFailed_off = off("sqlite3_mallocFailed", 103);
const db_enc_off = off("sqlite3_enc", 100);
const db_suppressErr_off = off("sqlite3_suppressErr", 107);
const db_xAuth_off = off("sqlite3_xAuth", 528);
const db_init_off = off("sqlite3_init", 192);
const db_initBusy_off = off("sqlite3_initBusy", 197);

// Db
const sizeof_Db = off("sizeof_Db", 32);
const Db_zDbSName_off = off("Db_zDbSName", 0);
const Db_pSchema_off = off("Db_pSchema", 24);

// Walker
const Walker_pParse_off = off("Walker_pParse", 0);
const Walker_xExprCallback_off = off("Walker_xExprCallback", 8);
const Walker_xSelectCallback_off = off("Walker_xSelectCallback", 16);
const Walker_xSelectCallback2_off = off("Walker_xSelectCallback2", 24);
const Walker_u_off = off("Walker_u", 40);
const sizeof_Walker = off("sizeof_Walker", 48);

// ═══ raw memory helpers ══════════════════════════════════════════════════════
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn cbase(p: ?*const anyopaque) [*]const u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*const anyopaque, o: usize) T {
    const q: *align(1) const T = @ptrCast(cbase(p) + o);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, o: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + o);
    q.* = v;
}
inline fn bit(p: ?*const anyopaque, byte: usize, b: u8) bool {
    return (cbase(p)[byte] & b) != 0;
}
inline fn setBit(p: ?*anyopaque, byte: usize, b: u8) void {
    base(p)[byte] |= b;
}

// ═══ Expr accessors ══════════════════════════════════════════════════════════
inline fn exprOp(p: ?*const anyopaque) u8 {
    return cbase(p)[Expr_op_off];
}
inline fn exprSetOp(p: ?*anyopaque, v: u8) void {
    base(p)[Expr_op_off] = v;
}
inline fn exprOp2(p: ?*const anyopaque) u8 {
    return cbase(p)[Expr_op2_off];
}
inline fn exprSetOp2(p: ?*anyopaque, v: u8) void {
    base(p)[Expr_op2_off] = v;
}
inline fn exprSetAffExpr(p: ?*anyopaque, v: u8) void {
    base(p)[Expr_affExpr_off] = v;
}
inline fn exprFlags(p: ?*const anyopaque) u32 {
    return rd(u32, p, Expr_flags_off);
}
inline fn exprSetFlags(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Expr_flags_off, v);
}
inline fn exprHasProperty(p: ?*const anyopaque, prop: u32) bool {
    return (exprFlags(p) & prop) != 0;
}
inline fn exprSetProperty(p: ?*anyopaque, prop: u32) void {
    exprSetFlags(p, exprFlags(p) | prop);
}
inline fn exprClearProperty(p: ?*anyopaque, prop: u32) void {
    exprSetFlags(p, exprFlags(p) & ~prop);
}
inline fn exprZToken(p: ?*const anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Expr_u_off);
}
inline fn exprSetZTokenConst(p: ?*anyopaque, v: [*:0]const u8) void {
    wr([*:0]const u8, p, Expr_u_off, v);
}
inline fn exprIValue(p: ?*const anyopaque) c_int {
    return rd(c_int, p, Expr_u_off);
}
inline fn exprSetIValue(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Expr_u_off, v);
}
inline fn exprPLeft(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Expr_pLeft_off);
}
inline fn exprSetPLeft(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Expr_pLeft_off, v);
}
inline fn exprPRight(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Expr_pRight_off);
}
inline fn exprSetPRight(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Expr_pRight_off, v);
}
inline fn exprXList(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Expr_x_off);
}
inline fn exprSetXList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Expr_x_off, v);
}
inline fn exprXSelect(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Expr_x_off);
}
inline fn exprNHeight(p: ?*const anyopaque) c_int {
    return rd(c_int, p, Expr_nHeight_off);
}
inline fn exprITable(p: ?*const anyopaque) c_int {
    return rd(c_int, p, Expr_iTable_off);
}
inline fn exprSetITable(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Expr_iTable_off, v);
}
inline fn exprIColumn(p: ?*const anyopaque) i16 {
    return rd(i16, p, Expr_iColumn_off);
}
inline fn exprSetIColumn(p: ?*anyopaque, v: i16) void {
    wr(i16, p, Expr_iColumn_off, v);
}
inline fn exprPAggInfo(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Expr_pAggInfo_off);
}
inline fn exprYTab(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Expr_y_off);
}
inline fn exprSetYTab(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Expr_y_off, v);
}
inline fn exprYWin(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Expr_y_off);
}
// Zero out the whole y union (sizeof = 8 bytes here; covers pTab/pWin/sub).
inline fn exprZeroY(p: ?*anyopaque) void {
    wr(u64, p, Expr_y_off, 0);
}

// ═══ ExprList accessors ══════════════════════════════════════════════════════
inline fn elNExpr(p: ?*const anyopaque) c_int {
    return rd(c_int, p, ExprList_nExpr_off);
}
inline fn elItem(p: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(base(p) + ExprList_a_off);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_ExprList_item));
}
inline fn eliPExpr(it: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, it, ExprList_item_pExpr_off);
}
inline fn eliSetPExpr(it: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, it, ExprList_item_pExpr_off, v);
}
inline fn eliZEName(it: ?*const anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, it, ExprList_item_zEName_off);
}
inline fn eliEEName(it: ?*const anyopaque) u8 {
    return cbase(it)[ExprList_item_fg_off + ELi_fg_eEName_byte] & 0x03;
}
inline fn eliFgBit(it: ?*const anyopaque, b: u8) bool {
    return bit(it, ExprList_item_fg_off + ELi_fg_eEName_byte, b);
}
inline fn eliFgSet(it: ?*anyopaque, b: u8) void {
    setBit(it, ExprList_item_fg_off + ELi_fg_eEName_byte, b);
}
inline fn eliIOrderByCol(it: ?*const anyopaque) u16 {
    return rd(u16, it, ExprList_item_u_off);
}
inline fn eliSetIOrderByCol(it: ?*anyopaque, v: u16) void {
    wr(u16, it, ExprList_item_u_off, v);
}

// ═══ NameContext accessors ═══════════════════════════════════════════════════
inline fn ncPParse(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, NC_pParse_off);
}
inline fn ncSetPParse(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NC_pParse_off, v);
}
inline fn ncPSrcList(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, NC_pSrcList_off);
}
inline fn ncSetPSrcList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NC_pSrcList_off, v);
}
inline fn ncUEList(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, NC_uNC_off);
}
inline fn ncSetUEList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NC_uNC_off, v);
}
inline fn ncUUpsert(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, NC_uNC_off);
}
inline fn ncUBaseReg(p: ?*const anyopaque) c_int {
    return rd(c_int, p, NC_uNC_off);
}
inline fn ncPNext(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, NC_pNext_off);
}
inline fn ncSetPNext(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NC_pNext_off, v);
}
inline fn ncNRef(p: ?*const anyopaque) c_int {
    return rd(c_int, p, NC_nRef_off);
}
inline fn ncSetNRef(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, NC_nRef_off, v);
}
inline fn ncNNcErr(p: ?*const anyopaque) c_int {
    return rd(c_int, p, NC_nNcErr_off);
}
inline fn ncSetNNcErr(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, NC_nNcErr_off, v);
}
inline fn ncFlags(p: ?*const anyopaque) c_int {
    return rd(c_int, p, NC_ncFlags_off);
}
inline fn ncSetFlags(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, NC_ncFlags_off, v);
}
inline fn ncNNestedSelect(p: ?*const anyopaque) u32 {
    return rd(u32, p, NC_nNestedSelect_off);
}
inline fn ncSetNNestedSelect(p: ?*anyopaque, v: u32) void {
    wr(u32, p, NC_nNestedSelect_off, v);
}
inline fn ncPWinSelect(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, NC_pWinSelect_off);
}
inline fn ncSetPWinSelect(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, NC_pWinSelect_off, v);
}

// ═══ Select accessors ════════════════════════════════════════════════════════
inline fn selFlags(p: ?*const anyopaque) u32 {
    return rd(u32, p, Select_selFlags_off);
}
inline fn selSetFlags(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Select_selFlags_off, v);
}
inline fn selPEList(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pEList_off);
}
inline fn selPSrc(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pSrc_off);
}
inline fn selPWhere(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pWhere_off);
}
inline fn selPGroupBy(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pGroupBy_off);
}
inline fn selPHaving(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pHaving_off);
}
inline fn selPOrderBy(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pOrderBy_off);
}
inline fn selSetPOrderBy(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Select_pOrderBy_off, v);
}
inline fn selPPrior(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pPrior_off);
}
inline fn selPNext(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pNext_off);
}
inline fn selSetPNext(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Select_pNext_off, v);
}
inline fn selPLimit(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pLimit_off);
}
inline fn selPWin(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pWin_off);
}
inline fn selPWinDefn(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pWinDefn_off);
}

// ═══ Window accessors ════════════════════════════════════════════════════════
inline fn winPPartition(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Window_pPartition_off);
}
inline fn winPOrderBy(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Window_pOrderBy_off);
}
inline fn winPFilter(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Window_pFilter_off);
}
inline fn winPNextWin(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Window_pNextWin_off);
}
inline fn winSetPOwner(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Window_pOwner_off, v);
}

// ═══ SrcList / SrcItem accessors ═════════════════════════════════════════════
inline fn srcNSrc(p: ?*const anyopaque) c_int {
    return rd(c_int, p, SrcList_nSrc_off);
}
inline fn srcSetNSrc(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, SrcList_nSrc_off, v);
}
inline fn srcNAlloc(p: ?*const anyopaque) c_int {
    return rd(c_int, p, SrcList_nAlloc_off);
}
inline fn srcItem(p: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(base(p) + SrcList_a_off);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_SrcItem));
}
inline fn siPSTab(it: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, it, SrcItem_pSTab_off);
}
inline fn siSetPSTab(it: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, it, SrcItem_pSTab_off, v);
}
inline fn siICursor(it: ?*const anyopaque) c_int {
    return rd(c_int, it, SrcItem_iCursor_off);
}
inline fn siSetICursor(it: ?*anyopaque, v: c_int) void {
    wr(c_int, it, SrcItem_iCursor_off, v);
}
inline fn siZAlias(it: ?*const anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, it, SrcItem_zAlias_off);
}
inline fn siZName(it: ?*const anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, it, 0);
}
inline fn siColUsed(it: ?*const anyopaque) u64 {
    return rd(u64, it, SrcItem_colUsed_off);
}
inline fn siSetColUsed(it: ?*anyopaque, v: u64) void {
    wr(u64, it, SrcItem_colUsed_off, v);
}
inline fn siJointype(it: ?*const anyopaque) u8 {
    return cbase(it)[SrcItem_fg_off + SI_fg_jointype_byte];
}
inline fn siFgBit(it: ?*const anyopaque, byte: usize, b: u8) bool {
    return bit(it, SrcItem_fg_off + byte, b);
}
inline fn siFgSet(it: ?*anyopaque, byte: usize, b: u8) void {
    setBit(it, SrcItem_fg_off + byte, b);
}
inline fn siU1PFuncArg(it: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, it, SrcItem_u1_off);
}
inline fn siU3PUsing(it: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, it, SrcItem_u3_off);
}
inline fn siU4PSubq(it: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, it, SrcItem_u4_off);
}
// Subquery.pSelect is at offset 0 of the Subq object.
inline fn subqPSelect(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, 0);
}

// ═══ Table / Column accessors ════════════════════════════════════════════════
inline fn tabZName(t: ?*const anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, t, Table_zName_off);
}
inline fn tabNCol(t: ?*const anyopaque) i16 {
    return rd(i16, t, Table_nCol_off);
}
inline fn tabIPKey(t: ?*const anyopaque) i16 {
    return rd(i16, t, Table_iPKey_off);
}
inline fn tabTnum(t: ?*const anyopaque) u32 {
    return rd(u32, t, Table_tnum_off);
}
inline fn tabTabFlags(t: ?*const anyopaque) u32 {
    return rd(u32, t, Table_tabFlags_off);
}
inline fn tabPSchema(t: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, t, Table_pSchema_off);
}
inline fn tabACol(t: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, t, Table_aCol_off);
}
inline fn colFlagsAt(t: ?*const anyopaque, n: c_int) u16 {
    const aCol: [*]u8 = @ptrCast(tabACol(t).?);
    const colp = aCol + (@as(usize, @intCast(n)) * sizeof_Column);
    const q: *align(1) const u16 = @ptrCast(colp + Column_colFlags_off);
    return q.*;
}
inline fn visibleRowid(t: ?*const anyopaque) bool {
    return (tabTabFlags(t) & TF_NoVisibleRowid) == 0;
}

// ═══ Parse / sqlite3 accessors ═══════════════════════════════════════════════
inline fn pDb(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Parse_db_off);
}
inline fn pNErr(p: ?*const anyopaque) c_int {
    return rd(c_int, p, Parse_nErr_off);
}
inline fn pVdbe(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Parse_pVdbe_off);
}
inline fn pNested(p: ?*const anyopaque) u8 {
    return cbase(p)[Parse_nested_off];
}
inline fn pEParseMode(p: ?*const anyopaque) u8 {
    return cbase(p)[Parse_eParseMode_off];
}
inline fn inRenameObject(p: ?*const anyopaque) bool {
    return pEParseMode(p) >= PARSE_MODE_RENAME;
}
inline fn pExplain(p: ?*const anyopaque) u8 {
    return cbase(p)[Parse_explain_off];
}
inline fn pNHeight(p: ?*const anyopaque) c_int {
    return rd(c_int, p, Parse_nHeight_off);
}
inline fn pSetNHeight(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Parse_nHeight_off, v);
}
inline fn pPTriggerTab(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Parse_pTriggerTab_off);
}
inline fn pETriggerOp(p: ?*const anyopaque) u8 {
    return cbase(p)[Parse_eTriggerOp_off];
}
inline fn pBReturning(p: ?*const anyopaque) bool {
    return bit(p, Parse_bReturning_byte, Parse_bReturning_bit);
}
inline fn pSetBHasExists(p: ?*anyopaque) void {
    setBit(p, Parse_bHasExists_byte, Parse_bHasExists_bit);
}
inline fn pSetCheckSchema(p: ?*anyopaque) void {
    setBit(p, Parse_checkSchema_byte, Parse_checkSchema_bit);
}
inline fn pOldmask(p: ?*const anyopaque) u32 {
    return rd(u32, p, Parse_oldmask_off);
}
inline fn pSetOldmask(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Parse_oldmask_off, v);
}
inline fn pNewmask(p: ?*const anyopaque) u32 {
    return rd(u32, p, Parse_newmask_off);
}
inline fn pSetNewmask(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Parse_newmask_off, v);
}
inline fn pZAuthContext(p: ?*const anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Parse_zAuthContext_off);
}
inline fn pSetZAuthContext(p: ?*anyopaque, v: ?[*:0]const u8) void {
    wr(?[*:0]const u8, p, Parse_zAuthContext_off, v);
}

inline fn dbNDb(db: ?*const anyopaque) c_int {
    return rd(c_int, db, db_nDb_off);
}
inline fn dbAt(db: ?*const anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, db, db_aDb_off).?);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_Db));
}
inline fn dbAtZName(db: ?*const anyopaque, i: c_int) ?[*:0]const u8 {
    return rd(?[*:0]const u8, dbAt(db, i), Db_zDbSName_off);
}
inline fn dbAtPSchema(db: ?*const anyopaque, i: c_int) ?*anyopaque {
    return rd(?*anyopaque, dbAt(db, i), Db_pSchema_off);
}
inline fn dbALimit(db: ?*const anyopaque, lim: usize) c_int {
    return rd(c_int, db, db_aLimit_off + lim * @sizeOf(c_int));
}
inline fn dbFlags(db: ?*const anyopaque) u64 {
    return rd(u64, db, db_flags_off);
}
inline fn dbMDbFlags(db: ?*const anyopaque) u32 {
    return rd(u32, db, db_mDbFlags_off);
}
inline fn dbMallocFailed(db: ?*const anyopaque) bool {
    return base(@constCast(db))[db_mallocFailed_off] != 0;
}
inline fn dbEnc(db: ?*const anyopaque) u8 {
    return cbase(db)[db_enc_off];
}
inline fn dbSuppressErr(db: ?*const anyopaque) u8 {
    return cbase(db)[db_suppressErr_off];
}
inline fn dbSetSuppressErr(db: ?*anyopaque, v: u8) void {
    base(db)[db_suppressErr_off] = v;
}
inline fn dbXAuth(db: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, db_xAuth_off);
}
inline fn dbInitBusy(db: ?*const anyopaque) u8 {
    return cbase(db)[db_initBusy_off];
}

// ═══ Walker accessors (we build a Walker on the C stack via a byte buffer) ════
inline fn wSetPParse(w: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, w, Walker_pParse_off, v);
}
inline fn wPParse(w: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, w, Walker_pParse_off);
}
inline fn wSetXExpr(w: ?*anyopaque, v: ?*const anyopaque) void {
    wr(?*const anyopaque, w, Walker_xExprCallback_off, v);
}
inline fn wSetXSelect(w: ?*anyopaque, v: ?*const anyopaque) void {
    wr(?*const anyopaque, w, Walker_xSelectCallback_off, v);
}
inline fn wSetXSelect2(w: ?*anyopaque, v: ?*const anyopaque) void {
    wr(?*const anyopaque, w, Walker_xSelectCallback2_off, v);
}
inline fn wSetU(w: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, w, Walker_u_off, v);
}
inline fn wU(w: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, w, Walker_u_off);
}
inline fn wUN(w: ?*const anyopaque) c_int {
    return rd(c_int, w, Walker_u_off);
}
inline fn wSetUN(w: ?*anyopaque, v: c_int) void {
    wr(c_int, w, Walker_u_off, v);
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ═════════════════
extern fn sqlite3WalkExpr(w: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3WalkExprNN(w: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3WalkExprList(w: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3WalkSelect(w: ?*anyopaque, pSelect: ?*anyopaque) c_int;

extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*const anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprDeferredDelete(pParse: ?*anyopaque, p: ?*anyopaque) c_int;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprAlloc(db: ?*anyopaque, op: c_int, pToken: ?*const anyopaque, dequote: c_int) ?*anyopaque;
extern fn sqlite3ExprListAppend(pParse: ?*anyopaque, pList: ?*anyopaque, pExpr: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprInt32(db: ?*anyopaque, v: c_int) ?*anyopaque;
extern fn sqlite3ExprAddCollateString(pParse: ?*anyopaque, p: ?*anyopaque, z: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3ExprSkipCollateAndLikely(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprVectorSize(p: ?*const anyopaque) c_int;
extern fn sqlite3ExprIsInteger(p: ?*const anyopaque, pValue: *c_int, pParse: ?*anyopaque) c_int;
extern fn sqlite3ExprCompare(pParse: ?*const anyopaque, pA: ?*const anyopaque, pB: ?*const anyopaque, iTab: c_int) c_int;
extern fn sqlite3ExprCanBeNull(p: ?*const anyopaque) c_int;
extern fn sqlite3ExprIdToTrueFalse(p: ?*anyopaque) c_int;
extern fn sqlite3ExprCheckHeight(pParse: ?*anyopaque, nHeight: c_int) c_int;
extern fn sqlite3ExprFunctionUsable(pParse: ?*anyopaque, pExpr: ?*const anyopaque, pDef: ?*const anyopaque) void;
extern fn sqlite3ExprOrderByAggregateError(pParse: ?*anyopaque, p: ?*anyopaque) void;

extern fn sqlite3IsRowid(z: ?[*:0]const u8) c_int;
extern fn sqlite3ColumnIndex(pTab: ?*anyopaque, zCol: ?[*:0]const u8) c_int;
extern fn sqlite3IdListIndex(pList: ?*anyopaque, z: ?[*:0]const u8) c_int;
extern fn sqlite3SrcItemColumnUsed(pItem: ?*anyopaque, n: c_int) void;
extern fn sqlite3ReferencesSrcList(pParse: ?*anyopaque, pExpr: ?*anyopaque, pSrcList: ?*anyopaque) c_int;
extern fn sqlite3TableColumnToStorage(pTab: ?*anyopaque, x: i16) i16;

extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;
const sqlite3StrNICmp = sqlite3_strnicmp;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn strcmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3AtoF(z: ?[*:0]const u8, pResult: *f64) c_int;

extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3RecordErrorOffsetOfExpr(db: ?*anyopaque, pExpr: ?*const anyopaque) void;
extern fn sqlite3_log(errcode: c_int, fmt: [*:0]const u8, ...) void;

extern fn sqlite3FindFunction(db: ?*anyopaque, zName: ?[*:0]const u8, nArg: c_int, enc: u8, createFlag: u8) ?*anyopaque;
extern fn sqlite3SelectPrep(pParse: ?*anyopaque, p: ?*anyopaque, pOuterNC: ?*anyopaque) void;
extern fn sqlite3SelectWrongNumTermsError(pParse: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SelectCheckOnClauses(pParse: ?*anyopaque, pSelect: ?*anyopaque) void;
extern fn sqlite3RenameTokenRemap(pParse: ?*anyopaque, pTo: ?*const anyopaque, pFrom: ?*const anyopaque) void;
extern fn sqlite3AuthRead(pParse: ?*anyopaque, pExpr: ?*anyopaque, pSchema: ?*anyopaque, pSrcList: ?*anyopaque) void;

extern fn sqlite3WindowUpdate(pParse: ?*anyopaque, pList: ?*anyopaque, pWin: ?*anyopaque, pDef: ?*const anyopaque) void;
extern fn sqlite3WindowLink(pSel: ?*anyopaque, pWin: ?*anyopaque) void;
extern fn sqlite3WindowUnlinkFromSelect(pWin: ?*anyopaque) void;

// FuncDef field accessors
const FuncDef_funcFlags_off = off("FuncDef_funcFlags", 4);
const FuncDef_zName_off = off("FuncDef_zName", 56);
const FuncDef_xFinalize_off: usize = 32; // xSFunc@24, xFinalize@32, xValue@40, xInverse@48
const FuncDef_xValue_off: usize = 40;
inline fn fnFlags(p: ?*const anyopaque) u32 {
    return rd(u32, p, FuncDef_funcFlags_off);
}
inline fn fnZName(p: ?*const anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, FuncDef_zName_off);
}
inline fn fnXFinalize(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, FuncDef_xFinalize_off);
}
inline fn fnXValue(p: ?*const anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, FuncDef_xValue_off);
}

// ═══ incrAggFunctionDepth ════════════════════════════════════════════════════
fn incrAggDepth(pWalker: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_AGG_FUNCTION) {
        const n: u8 = @truncate(@as(u32, @bitCast(wUN(pWalker))));
        exprSetOp2(pExpr, exprOp2(pExpr) +% n);
    }
    return WRC_Continue;
}
fn incrAggFunctionDepth(pExpr: ?*anyopaque, n: c_int) void {
    if (n > 0) {
        var wbuf: [sizeof_Walker]u8 align(8) = @splat(0);
        const w: ?*anyopaque = @ptrCast(&wbuf);
        wSetXExpr(w, @ptrCast(&incrAggDepth));
        wSetUN(w, n);
        _ = sqlite3WalkExpr(w, pExpr);
    }
}

// ═══ resolveAlias ════════════════════════════════════════════════════════════
fn resolveAlias(
    pParse: ?*anyopaque,
    pEList: ?*anyopaque,
    iCol: c_int,
    pExpr: ?*anyopaque,
    nSubquery: c_int,
) void {
    const pOrig = eliPExpr(elItem(pEList, iCol));
    // assert !EP_Reduced|EP_TokenOnly on pExpr
    if (exprPAggInfo(pExpr) != null) return;
    const db = pDb(pParse);
    var pDup = sqlite3ExprDup(db, pOrig, 0);
    if (dbMallocFailed(db)) {
        sqlite3ExprDelete(db, pDup);
        pDup = null;
    } else {
        incrAggFunctionDepth(pDup, nSubquery);
        if (exprOp(pExpr) == TK_COLLATE) {
            pDup = sqlite3ExprAddCollateString(pParse, pDup, exprZToken(pExpr));
        }
        // swap the full Expr structs: temp=*pDup; *pDup=*pExpr; *pExpr=temp.
        var temp: [@as(usize, off("sizeof_Expr", 72))]u8 align(8) = undefined;
        const sz = off("sizeof_Expr", 72);
        const dupB: [*]u8 = @ptrCast(pDup.?);
        const exB: [*]u8 = @ptrCast(pExpr.?);
        @memcpy(temp[0..sz], dupB[0..sz]);
        @memcpy(dupB[0..sz], exB[0..sz]);
        @memcpy(exB[0..sz], temp[0..sz]);
        if (exprHasProperty(pExpr, EP_WinFunc)) {
            const pWin = exprYWin(pExpr);
            if (pWin != null) winSetPOwner(pWin, pExpr);
        }
        _ = sqlite3ExprDeferredDelete(pParse, pDup);
    }
}

// ═══ sqlite3MatchEName ═══════════════════════════════════════════════════════
export fn sqlite3MatchEName(
    pItem: ?*const anyopaque,
    zCol: ?[*:0]const u8,
    zTab: ?[*:0]const u8,
    zDb: ?[*:0]const u8,
    pbRowid: ?*c_int,
) callconv(.c) c_int {
    const eEName = eliEEName(pItem);
    if (eEName != ENAME_TAB and (eEName != ENAME_ROWID or pbRowid == null)) {
        return 0;
    }
    var zSpan: [*:0]const u8 = eliZEName(pItem).?;
    var n: usize = 0;
    while (zSpan[n] != 0 and zSpan[n] != '.') : (n += 1) {}
    if (zDb) |db| {
        if (sqlite3StrNICmp(zSpan, db, @intCast(n)) != 0 or db[n] != 0) return 0;
    }
    zSpan = @ptrCast(zSpan + n + 1);
    n = 0;
    while (zSpan[n] != 0 and zSpan[n] != '.') : (n += 1) {}
    if (zTab) |tab| {
        if (sqlite3StrNICmp(zSpan, tab, @intCast(n)) != 0 or tab[n] != 0) return 0;
    }
    zSpan = @ptrCast(zSpan + n + 1);
    if (zCol) |col| {
        if (eEName == ENAME_TAB and sqlite3StrICmp(zSpan, col) != 0) return 0;
        if (eEName == ENAME_ROWID and sqlite3IsRowid(col) == 0) return 0;
    }
    if (eEName == ENAME_ROWID) pbRowid.?.* = 1;
    return 1;
}

// ═══ areDoubleQuotedStringsEnabled ═══════════════════════════════════════════
// SQLITE_DqsDDL / SQLITE_DqsDML — direct db->flags bits.
const DQS_DDL: u64 = 0x20000000;
const DQS_DML: u64 = 0x40000000;
extern fn sqlite3WritableSchema(db: ?*anyopaque) c_int;
fn areDoubleQuotedStringsEnabled(db: ?*anyopaque, pTopNC: ?*const anyopaque) bool {
    if (dbInitBusy(db) != 0) return true;
    if ((ncFlags(pTopNC) & NC_IsDDL) != 0) {
        if (sqlite3WritableSchema(db) != 0 and (dbFlags(db) & DQS_DML) != 0) {
            return true;
        }
        return (dbFlags(db) & DQS_DDL) != 0;
    } else {
        return (dbFlags(db) & DQS_DML) != 0;
    }
}

// ═══ sqlite3ExprColUsed ══════════════════════════════════════════════════════
export fn sqlite3ExprColUsed(pExpr: ?*anyopaque) callconv(.c) u64 {
    var n: c_int = exprIColumn(pExpr);
    const pExTab = exprYTab(pExpr);
    if ((tabTabFlags(pExTab) & TF_HasGenerated) != 0 and
        (colFlagsAt(pExTab, n) & COLFLAG_GENERATED) != 0)
    {
        const nCol: c_int = tabNCol(pExTab);
        return if (nCol >= BMS) ALLBITS else (maskbit(nCol) - 1);
    } else {
        if (n >= BMS) n = BMS - 1;
        return @as(u64, 1) << @intCast(n);
    }
}
inline fn maskbit(n: c_int) u64 {
    return @as(u64, 1) << @intCast(n);
}

// ═══ extendFJMatch ═══════════════════════════════════════════════════════════
fn extendFJMatch(pParse: ?*anyopaque, ppList: *?*anyopaque, pMatch: ?*anyopaque, iColumn: i16) void {
    const pNew = sqlite3ExprAlloc(pDb(pParse), TK_COLUMN, null, 0);
    if (pNew) |e| {
        exprSetITable(e, siICursor(pMatch));
        exprSetIColumn(e, iColumn);
        exprSetYTab(e, siPSTab(pMatch));
        exprSetProperty(e, EP_CanBeNull);
        ppList.* = sqlite3ExprListAppend(pParse, ppList.*, e);
    }
}

// ═══ isValidSchemaTableName ══════════════════════════════════════════════════
// The schema-table name literals appear as macro-defined string constants in C;
// we re-derive them by comparing suffixes (after the "sqlite_" prefix), which are
// stable in SQLite.
const LEGACY_TEMP_SUFFIX: [*:0]const u8 = "temp_master"; // sqlite_temp_master
const PREFERRED_TEMP_SUFFIX: [*:0]const u8 = "temp_schema"; // sqlite_temp_schema
const LEGACY_SUFFIX: [*:0]const u8 = "master"; // sqlite_master
const PREFERRED_SUFFIX: [*:0]const u8 = "schema"; // sqlite_schema
fn isValidSchemaTableName(zTab: ?[*:0]const u8, pTab: ?*const anyopaque, zDb: ?[*:0]const u8) c_int {
    // assert pTab->tnum==1
    if (sqlite3StrNICmp(zTab, "sqlite_", 7) != 0) return 0;
    const zLegacy = tabZName(pTab).?;
    const zLegacy7: [*:0]const u8 = @ptrCast(zLegacy + 7);
    const zTab7: [*:0]const u8 = @ptrCast(zTab.? + 7);
    if (strcmp(zLegacy7, LEGACY_TEMP_SUFFIX) == 0) {
        if (sqlite3StrICmp(zTab7, PREFERRED_TEMP_SUFFIX) == 0) return 1;
        if (zDb == null) return 0;
        if (sqlite3StrICmp(zTab7, LEGACY_SUFFIX) == 0) return 1;
        if (sqlite3StrICmp(zTab7, PREFERRED_SUFFIX) == 0) return 1;
    } else {
        if (sqlite3StrICmp(zTab7, PREFERRED_SUFFIX) == 0) return 1;
    }
    return 0;
}

// ═══ lookupName ══════════════════════════════════════════════════════════════
fn lookupName(
    pParse: ?*anyopaque,
    zDbIn: ?[*:0]const u8,
    zTab: ?[*:0]const u8,
    pRight: ?*const anyopaque,
    pNCin: ?*anyopaque,
    pExpr: ?*anyopaque,
) c_int {
    var zDb = zDbIn;
    var pNC = pNCin;
    var cnt: c_int = 0;
    var cntTab: c_int = 0;
    var nSubquery: c_int = 0;
    const db = pDb(pParse);
    var pMatch: ?*anyopaque = null;
    const pTopNC = pNCin;
    var pSchema: ?*anyopaque = null;
    var eNewExprOp: u8 = TK_COLUMN;
    var pTab: ?*anyopaque = null;
    var pFJMatch: ?*anyopaque = null;
    const zCol = exprZToken(pRight);

    exprSetITable(pExpr, -1);

    // Translate schema name zDb -> pSchema.
    if (zDb) |zd| {
        if ((ncFlags(pNC) & (NC_PartIdx | NC_IsCheck)) != 0) {
            zDb = null;
        } else {
            var i: c_int = 0;
            while (i < dbNDb(db)) : (i += 1) {
                if (sqlite3StrICmp(dbAtZName(db, i), zd) == 0) {
                    pSchema = dbAtPSchema(db, i);
                    break;
                }
            }
            if (i == dbNDb(db) and sqlite3StrICmp("main", zd) == 0) {
                pSchema = dbAtPSchema(db, 0);
                zDb = dbAtZName(db, 0);
            }
        }
    }

    // Walk name contexts inner -> outer.
    while (true) {
        var pEList: ?*anyopaque = null;
        const pSrcList = ncPSrcList(pNC);

        if (pSrcList) |srcList| {
            var i: c_int = 0;
            const nSrc = srcNSrc(srcList);
            while (i < nSrc) : (i += 1) {
                const pItem = srcItem(srcList, i);
                pTab = siPSTab(pItem);
                if (siFgBit(pItem, SI_fg_isNestedFrom_byte, SI_fg_isNestedFrom_bit)) {
                    var hit: c_int = 0;
                    const pSel = subqPSelect(siU4PSubq(pItem));
                    pEList = selPEList(pSel);
                    var j: c_int = 0;
                    const nE = elNExpr(pEList);
                    while (j < nE) : (j += 1) {
                        var bRowid: c_int = 0;
                        if (sqlite3MatchEName(elItem(pEList, j), zCol, zTab, zDb, &bRowid) == 0) {
                            continue;
                        }
                        if (bRowid == 0) {
                            if (cnt > 0) {
                                if (!siFgBit(pItem, SI_fg_isUsing_byte, SI_fg_isUsing_bit) or
                                    sqlite3IdListIndex(siU3PUsing(pItem), zCol) < 0 or
                                    pMatch == pItem)
                                {
                                    sqlite3ExprListDelete(db, pFJMatch);
                                    pFJMatch = null;
                                } else if ((siJointype(pItem) & JT_RIGHT) == 0) {
                                    continue;
                                } else if ((siJointype(pItem) & JT_LEFT) == 0) {
                                    cnt = 0;
                                    sqlite3ExprListDelete(db, pFJMatch);
                                    pFJMatch = null;
                                } else {
                                    extendFJMatch(pParse, &pFJMatch, pMatch, exprIColumn(pExpr));
                                }
                            }
                            cnt += 1;
                            hit = 1;
                        } else if (cnt > 0) {
                            continue;
                        }
                        cntTab += 1;
                        pMatch = pItem;
                        exprSetIColumn(pExpr, @truncate(j));
                        eliFgSet(elItem(pEList, j), ELi_fg_bUsed_bit);
                        if (eliFgBit(elItem(pEList, j), ELi_fg_bUsingTerm_bit)) break;
                    }
                    if (hit != 0 or zTab == null) continue;
                }
                if (zTab) |zt| {
                    if (zDb) |zd| {
                        if (tabPSchema(pTab) != pSchema) continue;
                        if (pSchema == null and strcmp(zd, "*") != 0) continue;
                    }
                    if (siZAlias(pItem)) |za| {
                        if (sqlite3StrICmp(zt, za) != 0) continue;
                    } else if (sqlite3StrICmp(zt, tabZName(pTab)) != 0) {
                        if (tabTnum(pTab) != 1) continue;
                        if (isValidSchemaTableName(zt, pTab, zDb) == 0) continue;
                    }
                    if (inRenameObject(pParse) and siZAlias(pItem) != null) {
                        sqlite3RenameTokenRemap(pParse, null, @ptrCast(base(pExpr) + Expr_y_off));
                    }
                }
                const j = sqlite3ColumnIndex(pTab, zCol);
                if (j >= 0) {
                    if (cnt > 0) {
                        if (!siFgBit(pItem, SI_fg_isUsing_byte, SI_fg_isUsing_bit) or
                            sqlite3IdListIndex(siU3PUsing(pItem), zCol) < 0)
                        {
                            sqlite3ExprListDelete(db, pFJMatch);
                            pFJMatch = null;
                        } else if ((siJointype(pItem) & JT_RIGHT) == 0) {
                            continue;
                        } else if ((siJointype(pItem) & JT_LEFT) == 0) {
                            cnt = 0;
                            sqlite3ExprListDelete(db, pFJMatch);
                            pFJMatch = null;
                        } else {
                            extendFJMatch(pParse, &pFJMatch, pMatch, exprIColumn(pExpr));
                        }
                    }
                    cnt += 1;
                    pMatch = pItem;
                    exprSetIColumn(pExpr, if (j == tabIPKey(pTab)) -1 else @truncate(j));
                    if (siFgBit(pItem, SI_fg_isNestedFrom_byte, SI_fg_isNestedFrom_bit)) {
                        sqlite3SrcItemColumnUsed(pItem, j);
                    }
                }
                if (cnt == 0 and visibleRowid(pTab)) {
                    // common non-ROWID-IN-VIEW path: require exactly one candidate.
                    cntTab += 1;
                    pMatch = pItem;
                }
            }
            if (pMatch) |m| {
                exprSetITable(pExpr, siICursor(m));
                exprSetYTab(pExpr, siPSTab(m));
                if ((siJointype(m) & (JT_LEFT | JT_LTORJ)) != 0) {
                    exprSetProperty(pExpr, EP_CanBeNull);
                }
                pSchema = tabPSchema(exprYTab(pExpr));
            }
        } // if pSrcList

        // new.*/old.* trigger args, excluded.* upsert, RETURNING references.
        if (cnt == 0 and zDb == null) {
            pTab = null;
            if (pPTriggerTab(pParse) != null) {
                const op = pETriggerOp(pParse);
                if (pBReturning(pParse)) {
                    if ((ncFlags(pNC) & NC_UBaseReg) != 0 and
                        (zTab == null or
                            sqlite3StrICmp(zTab, tabZName(pPTriggerTab(pParse))) == 0 or
                            isValidSchemaTableName(zTab, pPTriggerTab(pParse), null) != 0))
                    {
                        exprSetITable(pExpr, @intFromBool(op != TK_DELETE));
                        pTab = pPTriggerTab(pParse);
                    }
                } else if (op != TK_DELETE and zTab != null and sqlite3StrICmp("new", zTab) == 0) {
                    exprSetITable(pExpr, 1);
                    pTab = pPTriggerTab(pParse);
                } else if (op != TK_INSERT and zTab != null and sqlite3StrICmp("old", zTab) == 0) {
                    exprSetITable(pExpr, 0);
                    pTab = pPTriggerTab(pParse);
                }
            }
            if ((ncFlags(pNC) & NC_UUpsert) != 0 and zTab != null) {
                const pUpsert = ncUUpsert(pNC);
                if (pUpsert != null and sqlite3StrICmp("excluded", zTab) == 0) {
                    // pTab = pUpsert->pUpsertSrc->a[0].pSTab
                    const pUpsertSrc = rd(?*anyopaque, pUpsert, upsert_pUpsertSrc_off);
                    pTab = siPSTab(srcItem(pUpsertSrc, 0));
                    exprSetITable(pExpr, EXCLUDED_TABLE_NUMBER);
                }
            }

            if (pTab) |tab| {
                pSchema = tabPSchema(tab);
                cntTab += 1;
                var iCol = sqlite3ColumnIndex(tab, zCol);
                if (iCol >= 0) {
                    if (tabIPKey(tab) == iCol) iCol = -1;
                } else {
                    if (sqlite3IsRowid(zCol) != 0 and visibleRowid(tab)) {
                        iCol = -1;
                    } else {
                        iCol = tabNCol(tab);
                    }
                }
                if (iCol < tabNCol(tab)) {
                    cnt += 1;
                    pMatch = null;
                    if (exprITable(pExpr) == EXCLUDED_TABLE_NUMBER) {
                        if (inRenameObject(pParse)) {
                            exprSetIColumn(pExpr, @truncate(iCol));
                            exprSetYTab(pExpr, tab);
                            eNewExprOp = TK_COLUMN;
                        } else {
                            const regData = rd(c_int, ncUUpsert(pNC), upsert_regData_off);
                            exprSetITable(pExpr, regData + sqlite3TableColumnToStorage(tab, @intCast(iCol)));
                            eNewExprOp = TK_REGISTER;
                        }
                    } else {
                        exprSetYTab(pExpr, tab);
                        if (pBReturning(pParse)) {
                            eNewExprOp = TK_REGISTER;
                            exprSetOp2(pExpr, TK_COLUMN);
                            exprSetIColumn(pExpr, @truncate(iCol));
                            const ibase = ncUBaseReg(pNC);
                            exprSetITable(pExpr, ibase + (tabNCol(tab) + 1) * exprITable(pExpr) +
                                sqlite3TableColumnToStorage(tab, @intCast(iCol)) + 1);
                        } else {
                            exprSetIColumn(pExpr, @truncate(iCol));
                            eNewExprOp = TK_TRIGGER;
                            if (iCol < 0) {
                                exprSetAffExpr(pExpr, SQLITE_AFF_INTEGER);
                            } else if (exprITable(pExpr) == 0) {
                                const bitn: u32 = if (iCol >= 32) 0xffffffff else (@as(u32, 1) << @intCast(iCol));
                                pSetOldmask(pParse, pOldmask(pParse) | bitn);
                            } else {
                                const bitn: u32 = if (iCol >= 32) 0xffffffff else (@as(u32, 1) << @intCast(iCol));
                                pSetNewmask(pParse, pNewmask(pParse) | bitn);
                            }
                        }
                    }
                }
            }
        }

        // ROWID reference.
        if (cnt == 0 and cntTab >= 1 and pMatch != null and
            (ncFlags(pNC) & (NC_IdxExpr | NC_GenCol)) == 0 and
            sqlite3IsRowid(zCol) != 0 and
            (visibleRowid(siPSTab(pMatch)) or siFgBit(pMatch, SI_fg_isNestedFrom_byte, SI_fg_isNestedFrom_bit)))
        {
            cnt = cntTab;
            if (!siFgBit(pMatch, SI_fg_isNestedFrom_byte, SI_fg_isNestedFrom_bit)) {
                exprSetIColumn(pExpr, -1);
            }
            exprSetAffExpr(pExpr, SQLITE_AFF_INTEGER);
        }

        // Result-set alias (form Z, no X.Y).
        if (cnt == 0 and (ncFlags(pNC) & NC_UEList) != 0 and zTab == null) {
            pEList = ncUEList(pNC);
            var j: c_int = 0;
            const nE = elNExpr(pEList);
            while (j < nE) : (j += 1) {
                const it = elItem(pEList, j);
                const zAs = eliZEName(it);
                if (eliEEName(it) == ENAME_NAME and sqlite3_stricmp(zAs, zCol) == 0) {
                    const pOrig = eliPExpr(it);
                    if ((ncFlags(pNC) & NC_AllowAgg) == 0 and exprHasProperty(pOrig, EP_Agg)) {
                        sqlite3ErrorMsg(pParse, "misuse of aliased aggregate %s", zAs);
                        return WRC_Abort;
                    }
                    if (exprHasProperty(pOrig, EP_Win) and
                        ((ncFlags(pNC) & NC_AllowWin) == 0 or pNC != pTopNC))
                    {
                        sqlite3ErrorMsg(pParse, "misuse of aliased window function %s", zAs);
                        return WRC_Abort;
                    }
                    if (sqlite3ExprVectorSize(pOrig) != 1) {
                        sqlite3ErrorMsg(pParse, "row value misused");
                        return WRC_Abort;
                    }
                    resolveAlias(pParse, pEList, j, pExpr, nSubquery);
                    cnt = 1;
                    pMatch = null;
                    if (inRenameObject(pParse)) {
                        sqlite3RenameTokenRemap(pParse, null, pExpr);
                    }
                    return lookupNameEnd(pParse, pExpr, pNC, pTopNC, pSchema, pFJMatch, cnt, eNewExprOp, pMatch);
                }
            }
        }

        if (cnt != 0) break;
        pNC = ncPNext(pNC);
        nSubquery += 1;
        if (pNC == null) break;
    }

    // Double-quoted identifier with no match -> string literal.
    if (cnt == 0 and zTab == null) {
        if (exprHasProperty(pExpr, EP_DblQuoted) and areDoubleQuotedStringsEnabled(db, pTopNC)) {
            sqlite3_log(SQLITE_WARNING, "double-quoted string literal: \"%w\"", zCol);
            exprSetOp(pExpr, TK_STRING);
            exprZeroY(pExpr);
            return WRC_Prune;
        }
        if (sqlite3ExprIdToTrueFalse(pExpr) != 0) {
            return WRC_Prune;
        }
    }

    if (cnt != 1) {
        var zErr: [*:0]const u8 = undefined;
        if (pFJMatch) |fj| {
            if (elNExpr(fj) == cnt - 1) {
                if (exprHasProperty(pExpr, EP_Leaf)) {
                    exprClearProperty(pExpr, EP_Leaf);
                } else {
                    sqlite3ExprDelete(db, exprPLeft(pExpr));
                    exprSetPLeft(pExpr, null);
                    sqlite3ExprDelete(db, exprPRight(pExpr));
                    exprSetPRight(pExpr, null);
                }
                extendFJMatch(pParse, &pFJMatch, pMatch, exprIColumn(pExpr));
                exprSetOp(pExpr, TK_FUNCTION);
                exprSetZTokenConst(pExpr, "coalesce");
                exprSetXList(pExpr, pFJMatch);
                exprSetAffExpr(pExpr, SQLITE_AFF_DEFER);
                cnt = 1;
                return lookupNameEnd(pParse, pExpr, pNC, pTopNC, pSchema, pFJMatch, cnt, eNewExprOp, pMatch);
            } else {
                sqlite3ExprListDelete(db, fj);
                pFJMatch = null;
            }
        }
        zErr = if (cnt == 0) "no such column" else "ambiguous column name";
        if (zDb != null) {
            sqlite3ErrorMsg(pParse, "%s: %s.%s.%s", zErr, zDb, zTab, zCol);
        } else if (zTab != null) {
            sqlite3ErrorMsg(pParse, "%s: %s.%s", zErr, zTab, zCol);
        } else if (cnt == 0 and exprHasProperty(pRight, EP_DblQuoted)) {
            sqlite3ErrorMsg(pParse, "%s: \"%s\" - should this be a string literal in single-quotes?", zErr, zCol);
        } else {
            sqlite3ErrorMsg(pParse, "%s: %s", zErr, zCol);
        }
        sqlite3RecordErrorOffsetOfExpr(pDb(pParse), pExpr);
        pSetCheckSchema(pParse);
        ncSetNNcErr(pTopNC, ncNNcErr(pTopNC) + 1);
        eNewExprOp = TK_NULL;
    }

    // Remove substructure.
    if (!exprHasProperty(pExpr, EP_TokenOnly | EP_Leaf)) {
        sqlite3ExprDelete(db, exprPLeft(pExpr));
        exprSetPLeft(pExpr, null);
        sqlite3ExprDelete(db, exprPRight(pExpr));
        exprSetPRight(pExpr, null);
        exprSetProperty(pExpr, EP_Leaf);
    }

    // Record colUsed.
    if (pMatch) |m| {
        if (exprIColumn(pExpr) >= 0) {
            siSetColUsed(m, siColUsed(m) | sqlite3ExprColUsed(pExpr));
        } else {
            siFgSet(m, SI_fg_rowidUsed_byte, SI_fg_rowidUsed_bit);
        }
    }

    exprSetOp(pExpr, eNewExprOp);
    return lookupNameEnd(pParse, pExpr, pNC, pTopNC, pSchema, pFJMatch, cnt, eNewExprOp, pMatch);
}

// Upsert offsets (regData read for excluded.* reg base; pUpsertSrc holds the
// excluded source table).
const upsert_pUpsertSrc_off = off("Upsert_pUpsertSrc", 64);
const upsert_regData_off = off("Upsert_regData", 72);

fn lookupNameEnd(
    pParse: ?*anyopaque,
    pExprIn: ?*anyopaque,
    pNC: ?*anyopaque,
    pTopNCin: ?*anyopaque,
    pSchema: ?*anyopaque,
    pFJMatch: ?*anyopaque,
    cnt: c_int,
    eNewExprOp: u8,
    pMatch: ?*anyopaque,
) c_int {
    _ = eNewExprOp;
    _ = pMatch;
    var pExpr = pExprIn;
    var pTopNC = pTopNCin;
    if (cnt == 1) {
        const db = pDb(pParse);
        if (dbXAuth(db) != null) {
            if (pFJMatch) |fj| {
                pExpr = eliPExpr(elItem(fj, 0));
            }
            if (exprOp(pExpr) == TK_COLUMN or exprOp(pExpr) == TK_TRIGGER) {
                sqlite3AuthRead(pParse, pExpr, pSchema, ncPSrcList(pNC));
            }
        }
        while (true) {
            ncSetNRef(pTopNC, ncNRef(pTopNC) + 1);
            if (pTopNC == pNC) break;
            pTopNC = ncPNext(pTopNC);
        }
        return WRC_Prune;
    } else {
        return WRC_Abort;
    }
}

// ═══ sqlite3CreateColumnExpr ═════════════════════════════════════════════════
export fn sqlite3CreateColumnExpr(db: ?*anyopaque, pSrc: ?*anyopaque, iSrc: c_int, iCol: c_int) callconv(.c) ?*anyopaque {
    const p = sqlite3ExprAlloc(db, TK_COLUMN, null, 0);
    if (p) |e| {
        const pItem = srcItem(pSrc, iSrc);
        const pTab = siPSTab(pItem);
        exprSetYTab(e, pTab);
        exprSetITable(e, siICursor(pItem));
        if (tabIPKey(pTab) == iCol) {
            exprSetIColumn(e, -1);
        } else {
            exprSetIColumn(e, @truncate(iCol));
            if ((tabTabFlags(pTab) & TF_HasGenerated) != 0 and
                (colFlagsAt(pTab, iCol) & COLFLAG_GENERATED) != 0)
            {
                const nCol: c_int = tabNCol(pTab);
                siSetColUsed(pItem, if (nCol >= 64) ALLBITS else (maskbit(nCol) - 1));
            } else {
                const b: c_int = if (iCol >= BMS) BMS - 1 else iCol;
                siSetColUsed(pItem, siColUsed(pItem) | (@as(u64, 1) << @intCast(b)));
            }
        }
    }
    return p;
}

// ═══ notValid / sqlite3ResolveNotValid ═══════════════════════════════════════
fn notValidImpl(pParse: ?*anyopaque, pNC: ?*const anyopaque, zMsg: [*:0]const u8, pExpr: ?*anyopaque, pError: ?*const anyopaque) void {
    var zIn: [*:0]const u8 = "partial index WHERE clauses";
    if ((ncFlags(pNC) & NC_IdxExpr) != 0) {
        zIn = "index expressions";
    } else if ((ncFlags(pNC) & NC_IsCheck) != 0) {
        zIn = "CHECK constraints";
    } else if ((ncFlags(pNC) & NC_GenCol) != 0) {
        zIn = "generated columns";
    }
    sqlite3ErrorMsg(pParse, "%s prohibited in %s", zMsg, zIn);
    if (pExpr) |e| exprSetOp(e, TK_NULL);
    sqlite3RecordErrorOffsetOfExpr(pDb(pParse), pError);
}
inline fn resolveNotValid(pParse: ?*anyopaque, pNC: ?*const anyopaque, zMsg: [*:0]const u8, validMask: c_int, pExpr: ?*anyopaque, pError: ?*const anyopaque) void {
    if ((ncFlags(pNC) & validMask) != 0) notValidImpl(pParse, pNC, zMsg, pExpr, pError);
}

// ═══ exprProbability ═════════════════════════════════════════════════════════
fn exprProbability(p: ?*const anyopaque) c_int {
    var r: f64 = -1.0;
    if (exprOp(p) != TK_FLOAT) return -1;
    _ = sqlite3AtoF(exprZToken(p), &r);
    if (r > 1.0) return -1;
    return @intFromFloat(r * 134217728.0);
}

// ═══ resolveSetExprSubtypeArg ════════════════════════════════════════════════
fn resolveSetExprSubtypeArg(pList: ?*anyopaque) void {
    const nn = if (pList != null) elNExpr(pList) else 0;
    var ii: c_int = 0;
    while (ii < nn) : (ii += 1) {
        const pExpr = eliPExpr(elItem(pList, ii));
        exprSetProperty(pExpr, EP_SubtArg);
        if (exprOp(pExpr) == TK_SELECT) {
            resolveSetExprSubtypeArg(selPEList(exprXSelect(pExpr)));
        }
    }
}

// ═══ resolveExprStep ═════════════════════════════════════════════════════════
fn resolveExprStep(pWalker: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    const pNC = wU(pWalker);
    const pParse = ncPParse(pNC);

    switch (exprOp(pExpr)) {
        TK_ROW => {
            const pSrcList = ncPSrcList(pNC);
            const pItem = srcItem(pSrcList, 0);
            exprSetOp(pExpr, TK_COLUMN);
            exprSetYTab(pExpr, siPSTab(pItem));
            exprSetITable(pExpr, siICursor(pItem));
            exprSetIColumn(pExpr, exprIColumn(pExpr) - 1);
            exprSetAffExpr(pExpr, SQLITE_AFF_INTEGER);
        },
        TK_NOTNULL, TK_ISNULL => {
            var anRef: [8]c_int = undefined;
            var p = pNC;
            var i: usize = 0;
            while (p != null and i < anRef.len) : (i += 1) {
                anRef[i] = ncNRef(p);
                p = ncPNext(p);
            }
            _ = sqlite3WalkExpr(pWalker, exprPLeft(pExpr));
            if (inRenameObject(pParse)) return WRC_Prune;
            if (sqlite3ExprCanBeNull(exprPLeft(pExpr)) != 0) {
                return WRC_Prune;
            }
            p = pNC;
            while (p != null) {
                if ((ncFlags(p) & NC_Where) == 0) {
                    return WRC_Prune;
                }
                p = ncPNext(p);
            }
            exprSetIValue(pExpr, @intFromBool(exprOp(pExpr) == TK_NOTNULL));
            exprSetFlags(pExpr, exprFlags(pExpr) | EP_IntValue);
            exprSetOp(pExpr, TK_INTEGER);
            p = pNC;
            i = 0;
            while (p != null and i < anRef.len) : (i += 1) {
                ncSetNRef(p, anRef[i]);
                p = ncPNext(p);
            }
            sqlite3ExprDelete(pDb(pParse), exprPLeft(pExpr));
            exprSetPLeft(pExpr, null);
            return WRC_Prune;
        },
        TK_ID, TK_DOT => {
            var zTable: ?[*:0]const u8 = null;
            var zDb: ?[*:0]const u8 = null;
            var pRight: ?*anyopaque = null;
            if (exprOp(pExpr) == TK_ID) {
                pRight = pExpr;
            } else {
                var pLeft = exprPLeft(pExpr);
                resolveNotValid(pParse, pNC, "the \".\" operator", NC_IdxExpr | NC_GenCol, null, pExpr);
                pRight = exprPRight(pExpr);
                if (exprOp(pRight) == TK_ID) {
                    zDb = null;
                } else {
                    zDb = exprZToken(pLeft);
                    pLeft = exprPLeft(pRight);
                    pRight = exprPRight(pRight);
                }
                zTable = exprZToken(pLeft);
                if (inRenameObject(pParse)) {
                    sqlite3RenameTokenRemap(pParse, pExpr, pRight);
                    sqlite3RenameTokenRemap(pParse, @ptrCast(base(pExpr) + Expr_y_off), pLeft);
                }
            }
            return lookupName(pParse, zDb, zTable, pRight, pNC, pExpr);
        },
        TK_FUNCTION => return resolveFunction(pWalker, pExpr, pNC, pParse),
        TK_EXISTS, TK_SELECT, TK_IN => {
            if (exprHasProperty(pExpr, EP_xIsSelect)) {
                const nRef = ncNRef(pNC);
                if (exprOp(pExpr) == TK_EXISTS) pSetBHasExists(pParse);
                if ((ncFlags(pNC) & NC_SelfRef) != 0) {
                    notValidImpl(pParse, pNC, "subqueries", pExpr, pExpr);
                } else {
                    _ = sqlite3WalkSelect(pWalker, exprXSelect(pExpr));
                }
                if (nRef != ncNRef(pNC)) {
                    exprSetProperty(pExpr, EP_VarSelect);
                    const pSel = exprXSelect(pExpr);
                    selSetFlags(pSel, selFlags(pSel) | SF_Correlated);
                }
                ncSetFlags(pNC, ncFlags(pNC) | NC_Subquery);
            }
        },
        TK_VARIABLE => {
            resolveNotValid(pParse, pNC, "parameters", NC_IsCheck | NC_PartIdx | NC_IdxExpr | NC_GenCol, pExpr, pExpr);
        },
        TK_IS, TK_ISNOT => {
            const pRight = sqlite3ExprSkipCollateAndLikely(exprPRight(pExpr));
            if (pRight != null and (exprOp(pRight) == TK_ID or exprOp(pRight) == TK_TRUEFALSE)) {
                const rc = resolveExprStep(pWalker, pRight);
                if (rc == WRC_Abort) return WRC_Abort;
                if (exprOp(pRight) == TK_TRUEFALSE) {
                    exprSetOp2(pExpr, exprOp(pExpr));
                    exprSetOp(pExpr, TK_TRUTH);
                    return WRC_Continue;
                }
            }
            // fall through to comparison handling
            return resolveComparison(pExpr, pParse);
        },
        TK_BETWEEN, TK_EQ, TK_NE, TK_LT, TK_LE, TK_GT, TK_GE => return resolveComparison(pExpr, pParse),
        else => {},
    }
    return if (pNErr(pParse) != 0) WRC_Abort else WRC_Continue;
}

fn resolveComparison(pExpr: ?*anyopaque, pParse: ?*anyopaque) c_int {
    if (dbMallocFailed(pDb(pParse))) {
        return if (pNErr(pParse) != 0) WRC_Abort else WRC_Continue;
    }
    const nLeft = sqlite3ExprVectorSize(exprPLeft(pExpr));
    var nRight: c_int = undefined;
    if (exprOp(pExpr) == TK_BETWEEN) {
        const pList = exprXList(pExpr);
        nRight = sqlite3ExprVectorSize(eliPExpr(elItem(pList, 0)));
        if (nRight == nLeft) {
            nRight = sqlite3ExprVectorSize(eliPExpr(elItem(pList, 1)));
        }
    } else {
        nRight = sqlite3ExprVectorSize(exprPRight(pExpr));
    }
    if (nLeft != nRight) {
        sqlite3ErrorMsg(pParse, "row value misused");
        sqlite3RecordErrorOffsetOfExpr(pDb(pParse), pExpr);
    }
    return if (pNErr(pParse) != 0) WRC_Abort else WRC_Continue;
}

fn resolveFunction(pWalker: ?*anyopaque, pExpr: ?*anyopaque, pNC: ?*anyopaque, pParse: ?*anyopaque) c_int {
    var no_such_func: c_int = 0;
    var wrong_num_args: c_int = 0;
    var is_agg: c_int = 0;
    const enc = dbEnc(pDb(pParse));
    const savedAllowFlags = ncFlags(pNC) & (NC_AllowAgg | NC_AllowWin);
    const pWin: ?*anyopaque = if (exprHasProperty(pExpr, EP_WinFunc)) exprYWin(pExpr) else null;
    const pList = exprXList(pExpr);
    const n: c_int = if (pList != null) elNExpr(pList) else 0;
    const zId = exprZToken(pExpr);
    var pDef = sqlite3FindFunction(pDb(pParse), zId, n, enc, 0);
    if (pDef == null) {
        pDef = sqlite3FindFunction(pDb(pParse), zId, -2, enc, 0);
        if (pDef == null) {
            no_such_func = 1;
        } else {
            wrong_num_args = 1;
        }
    } else {
        is_agg = @intFromBool(fnXFinalize(pDef) != null);
        if ((fnFlags(pDef) & SQLITE_FUNC_UNLIKELY) != 0) {
            exprSetProperty(pExpr, EP_Unlikely);
            if (n == 2) {
                exprSetITable(pExpr, exprProbability(eliPExpr(elItem(pList, 1))));
                if (exprITable(pExpr) < 0) {
                    sqlite3ErrorMsg(pParse, "second argument to %#T() must be a constant between 0.0 and 1.0", pExpr);
                    ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
                }
            } else {
                exprSetITable(pExpr, if (fnZName(pDef).?[0] == 'u') 8388608 else 125829120);
            }
        }
        {
            const auth = sqlite3AuthCheck(pParse, SQLITE_FUNCTION, null, fnZName(pDef), null);
            if (auth != SQLITE_OK) {
                if (auth == SQLITE_DENY) {
                    sqlite3ErrorMsg(pParse, "not authorized to use function: %#T", pExpr);
                    ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
                }
                exprSetOp(pExpr, TK_NULL);
                return WRC_Prune;
            }
        }
        if ((fnFlags(pDef) & SQLITE_SUBTYPE) != 0 or exprHasProperty(pExpr, EP_SubtArg)) {
            resolveSetExprSubtypeArg(pList);
        }
        if ((fnFlags(pDef) & (SQLITE_FUNC_CONSTANT | SQLITE_FUNC_SLOCHNG)) != 0) {
            exprSetProperty(pExpr, EP_ConstFunc);
        }
        if ((fnFlags(pDef) & SQLITE_FUNC_CONSTANT) == 0) {
            resolveNotValid(pParse, pNC, "non-deterministic functions", NC_IdxExpr | NC_PartIdx | NC_GenCol, null, pExpr);
        } else {
            exprSetOp2(pExpr, @truncate(@as(u32, @bitCast(ncFlags(pNC) & NC_SelfRef))));
        }
        if ((fnFlags(pDef) & SQLITE_FUNC_INTERNAL) != 0 and
            pNested(pParse) == 0 and
            (dbMDbFlags(pDb(pParse)) & DBFLAG_InternalFunc) == 0)
        {
            no_such_func = 2;
            pDef = null;
        } else if ((fnFlags(pDef) & (SQLITE_FUNC_DIRECT | SQLITE_FUNC_UNSAFE)) != 0 and !inRenameObject(pParse)) {
            if ((ncFlags(pNC) & NC_FromDDL) != 0) exprSetProperty(pExpr, EP_FromDDL);
            sqlite3ExprFunctionUsable(pParse, pExpr, pDef);
        }
    }

    if (!inRenameObject(pParse)) {
        if (pDef != null and fnXValue(pDef) == null and pWin != null) {
            sqlite3ErrorMsg(pParse, "%#T() may not be used as a window function", pExpr);
            ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
        } else if ((is_agg != 0 and (ncFlags(pNC) & NC_AllowAgg) == 0) or
            (is_agg != 0 and (fnFlags(pDef) & SQLITE_FUNC_WINDOW) != 0 and pWin == null) or
            (is_agg != 0 and pWin != null and (ncFlags(pNC) & NC_AllowWin) == 0))
        {
            const zType: [*:0]const u8 = if ((fnFlags(pDef) & SQLITE_FUNC_WINDOW) != 0 or pWin != null) "window" else "aggregate";
            sqlite3ErrorMsg(pParse, "misuse of %s function %#T()", zType, pExpr);
            ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
            is_agg = 0;
        } else if (no_such_func != 0 and
            (dbInitBusy(pDb(pParse)) == 0 or (no_such_func == 2 and dbInitBusy(pDb(pParse)) == 2)) and
            pExplain(pParse) == 0)
        {
            sqlite3ErrorMsg(pParse, "no such function: %#T", pExpr);
            ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
        } else if (wrong_num_args != 0) {
            sqlite3ErrorMsg(pParse, "wrong number of arguments to function %#T()", pExpr);
            ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
        } else if (is_agg == 0 and exprHasProperty(pExpr, EP_WinFunc)) {
            sqlite3ErrorMsg(pParse, "FILTER may not be used with non-aggregate %#T()", pExpr);
            ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
        } else if (is_agg == 0 and exprPLeft(pExpr) != null) {
            sqlite3ExprOrderByAggregateError(pParse, pExpr);
            ncSetNNcErr(pNC, ncNNcErr(pNC) + 1);
        }
        if (is_agg != 0) {
            const clr: c_int = NC_AllowWin | (if (pWin == null) NC_AllowAgg else 0);
            ncSetFlags(pNC, ncFlags(pNC) & ~clr);
        }
    } else if (exprHasProperty(pExpr, EP_WinFunc) or exprPLeft(pExpr) != null) {
        is_agg = 1;
    }

    _ = sqlite3WalkExprList(pWalker, pList);
    if (is_agg != 0) {
        if (exprPLeft(pExpr)) |pl| {
            _ = sqlite3WalkExprList(pWalker, exprXList(pl));
        }
        if (pWin != null and pNErr(pParse) == 0) {
            const pSel = ncPWinSelect(pNC);
            if (!inRenameObject(pParse)) {
                sqlite3WindowUpdate(pParse, if (pSel != null) selPWinDefn(pSel) else null, pWin, pDef);
                if (dbMallocFailed(pDb(pParse))) return finishFunction(pNC, savedAllowFlags);
            }
            _ = sqlite3WalkExprList(pWalker, winPPartition(pWin));
            _ = sqlite3WalkExprList(pWalker, winPOrderBy(pWin));
            _ = sqlite3WalkExpr(pWalker, winPFilter(pWin));
            sqlite3WindowLink(pSel, pWin);
            ncSetFlags(pNC, ncFlags(pNC) | NC_HasWin);
        } else {
            exprSetOp(pExpr, TK_AGG_FUNCTION);
            exprSetOp2(pExpr, 0);
            if (exprHasProperty(pExpr, EP_WinFunc)) {
                _ = sqlite3WalkExpr(pWalker, winPFilter(exprYWin(pExpr)));
            }
            var pNC2 = pNC;
            while (pNC2 != null and sqlite3ReferencesSrcList(pParse, pExpr, ncPSrcList(pNC2)) == 0) {
                exprSetOp2(pExpr, exprOp2(pExpr) +% @as(u8, @truncate(1 + ncNNestedSelect(pNC2))));
                pNC2 = ncPNext(pNC2);
            }
            if (pNC2 != null and pDef != null) {
                exprSetOp2(pExpr, exprOp2(pExpr) +% @as(u8, @truncate(ncNNestedSelect(pNC2))));
                const ff = fnFlags(pDef);
                const add: c_int = @intCast((ff ^ SQLITE_FUNC_ANYORDER) & (SQLITE_FUNC_MINMAX | SQLITE_FUNC_ANYORDER));
                ncSetFlags(pNC2, ncFlags(pNC2) | NC_HasAgg | add);
            }
        }
        ncSetFlags(pNC, ncFlags(pNC) | savedAllowFlags);
    }
    return WRC_Prune;
}

fn finishFunction(pNC: ?*anyopaque, savedAllowFlags: c_int) c_int {
    ncSetFlags(pNC, ncFlags(pNC) | savedAllowFlags);
    return WRC_Prune;
}

extern fn sqlite3AuthCheck(pParse: ?*anyopaque, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;
const SQLITE_FUNCTION: c_int = 31;
const SQLITE_DENY: c_int = 1;

// ═══ resolveAsName ═══════════════════════════════════════════════════════════
fn resolveAsName(pParse: ?*anyopaque, pEList: ?*anyopaque, pE: ?*const anyopaque) c_int {
    _ = pParse;
    if (exprOp(pE) == TK_ID) {
        const zCol = exprZToken(pE);
        var i: c_int = 0;
        const nE = elNExpr(pEList);
        while (i < nE) : (i += 1) {
            const it = elItem(pEList, i);
            if (eliEEName(it) == ENAME_NAME and sqlite3_stricmp(eliZEName(it), zCol) == 0) {
                return i + 1;
            }
        }
    }
    return 0;
}

// ═══ resolveOrderByTermToExprList ════════════════════════════════════════════
fn resolveOrderByTermToExprList(pParse: ?*anyopaque, pSelect: ?*anyopaque, pE: ?*anyopaque) c_int {
    var ncbuf: [sizeof_NameContext]u8 align(8) = @splat(0);
    const nc: ?*anyopaque = @ptrCast(&ncbuf);
    const pEList = selPEList(pSelect);
    ncSetPParse(nc, pParse);
    ncSetPSrcList(nc, selPSrc(pSelect));
    ncSetUEList(nc, pEList);
    ncSetFlags(nc, NC_AllowAgg | NC_UEList | NC_NoSelect);
    ncSetNNcErr(nc, 0);
    const db = pDb(pParse);
    const savedSuppErr = dbSuppressErr(db);
    dbSetSuppressErr(db, 1);
    const rc = sqlite3ResolveExprNames(nc, pE);
    dbSetSuppressErr(db, savedSuppErr);
    if (rc != 0) return 0;
    var i: c_int = 0;
    const nE = elNExpr(pEList);
    while (i < nE) : (i += 1) {
        if (sqlite3ExprCompare(null, eliPExpr(elItem(pEList, i)), pE, -1) < 2) {
            return i + 1;
        }
    }
    return 0;
}

// ═══ resolveOutOfRangeError ══════════════════════════════════════════════════
fn resolveOutOfRangeError(pParse: ?*anyopaque, zType: [*:0]const u8, i: c_int, mx: c_int, pError: ?*const anyopaque) void {
    sqlite3ErrorMsg(pParse, "%r %s BY term out of range - should be between 1 and %d", i, zType, mx);
    sqlite3RecordErrorOffsetOfExpr(pDb(pParse), pError);
}

// ═══ resolveCompoundOrderBy ══════════════════════════════════════════════════
fn resolveCompoundOrderBy(pParse: ?*anyopaque, pSelectIn: ?*anyopaque) c_int {
    var pSelect = pSelectIn;
    const pOrderBy = selPOrderBy(pSelect);
    if (pOrderBy == null) return 0;
    const db = pDb(pParse);
    var moreToDo: c_int = 1;
    if (elNExpr(pOrderBy) > dbALimit(db, SQLITE_LIMIT_COLUMN)) {
        sqlite3ErrorMsg(pParse, "too many terms in ORDER BY clause");
        return 1;
    }
    {
        var i: c_int = 0;
        while (i < elNExpr(pOrderBy)) : (i += 1) {
            // clear fg.done bit
            base(elItem(pOrderBy, i))[ExprList_item_fg_off + ELi_fg_eEName_byte] &= ~ELi_fg_done_bit;
        }
    }
    selSetPNext(pSelect, null);
    while (selPPrior(pSelect) != null) {
        selSetPNext(selPPrior(pSelect), pSelect);
        pSelect = selPPrior(pSelect);
    }
    while (pSelect != null and moreToDo != 0) {
        moreToDo = 0;
        const pEList = selPEList(pSelect);
        var i: c_int = 0;
        const nOB = elNExpr(pOrderBy);
        while (i < nOB) : (i += 1) {
            const pItem = elItem(pOrderBy, i);
            var iCol: c_int = -1;
            if (eliFgBit(pItem, ELi_fg_done_bit)) continue;
            const pE = sqlite3ExprSkipCollateAndLikely(eliPExpr(pItem));
            if (pE == null) continue;
            if (sqlite3ExprIsInteger(pE, &iCol, null) != 0) {
                if (iCol <= 0 or iCol > elNExpr(pEList)) {
                    resolveOutOfRangeError(pParse, "ORDER", i + 1, elNExpr(pEList), pE);
                    return 1;
                }
            } else {
                iCol = resolveAsName(pParse, pEList, pE);
                if (iCol == 0) {
                    const pDup = sqlite3ExprDup(db, pE, 0);
                    if (!dbMallocFailed(db)) {
                        iCol = resolveOrderByTermToExprList(pParse, pSelect, pDup);
                        if (inRenameObject(pParse) and iCol > 0) {
                            _ = resolveOrderByTermToExprList(pParse, pSelect, pE);
                        }
                    }
                    sqlite3ExprDelete(db, pDup);
                }
            }
            if (iCol > 0) {
                if (!inRenameObject(pParse)) {
                    const pNew = sqlite3ExprInt32(db, iCol);
                    if (pNew == null) return 1;
                    if (eliPExpr(pItem) == pE) {
                        eliSetPExpr(pItem, pNew);
                    } else {
                        var pParent = eliPExpr(pItem);
                        while (exprOp(exprPLeft(pParent)) == TK_COLLATE) pParent = exprPLeft(pParent);
                        exprSetPLeft(pParent, pNew);
                    }
                    sqlite3ExprDelete(db, pE);
                    eliSetIOrderByCol(pItem, @intCast(@as(u16, @truncate(@as(u32, @bitCast(iCol))))));
                }
                eliFgSet(pItem, ELi_fg_done_bit);
            } else {
                moreToDo = 1;
            }
        }
        pSelect = selPNext(pSelect);
    }
    {
        var i: c_int = 0;
        while (i < elNExpr(pOrderBy)) : (i += 1) {
            if (!eliFgBit(elItem(pOrderBy, i), ELi_fg_done_bit)) {
                sqlite3ErrorMsg(pParse, "%r ORDER BY term does not match any column in the result set", i + 1);
                return 1;
            }
        }
    }
    return 0;
}

// ═══ sqlite3ResolveOrderGroupBy ══════════════════════════════════════════════
export fn sqlite3ResolveOrderGroupBy(pParse: ?*anyopaque, pSelect: ?*anyopaque, pOrderBy: ?*anyopaque, zType: [*:0]const u8) callconv(.c) c_int {
    const db = pDb(pParse);
    if (pOrderBy == null or dbMallocFailed(db) or inRenameObject(pParse)) return 0;
    if (elNExpr(pOrderBy) > dbALimit(db, SQLITE_LIMIT_COLUMN)) {
        sqlite3ErrorMsg(pParse, "too many terms in %s BY clause", zType);
        return 1;
    }
    const pEList = selPEList(pSelect);
    var i: c_int = 0;
    const nOB = elNExpr(pOrderBy);
    while (i < nOB) : (i += 1) {
        const pItem = elItem(pOrderBy, i);
        const oc = eliIOrderByCol(pItem);
        if (oc != 0) {
            if (@as(c_int, oc) > elNExpr(pEList)) {
                resolveOutOfRangeError(pParse, zType, i + 1, elNExpr(pEList), null);
                return 1;
            }
            resolveAlias(pParse, pEList, @as(c_int, oc) - 1, eliPExpr(pItem), 0);
        }
    }
    return 0;
}

// ═══ resolveRemoveWindowsCb / windowRemoveExprFromSelect ═════════════════════
fn resolveRemoveWindowsCb(pWalker: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    _ = pWalker;
    if (exprHasProperty(pExpr, EP_WinFunc)) {
        sqlite3WindowUnlinkFromSelect(exprYWin(pExpr));
    }
    return WRC_Continue;
}
fn windowRemoveExprFromSelect(pSelect: ?*anyopaque, pExpr: ?*anyopaque) void {
    if (selPWin(pSelect) != null) {
        var wbuf: [sizeof_Walker]u8 align(8) = @splat(0);
        const w: ?*anyopaque = @ptrCast(&wbuf);
        wSetXExpr(w, @ptrCast(&resolveRemoveWindowsCb));
        wSetU(w, pSelect);
        _ = sqlite3WalkExpr(w, pExpr);
    }
}

// ═══ resolveOrderGroupBy (static) ════════════════════════════════════════════
fn resolveOrderGroupBy(pNC: ?*anyopaque, pSelect: ?*anyopaque, pOrderBy: ?*anyopaque, zType: [*:0]const u8) c_int {
    const pParse = ncPParse(pNC);
    const nResult = elNExpr(selPEList(pSelect));
    var i: c_int = 0;
    const nOB = elNExpr(pOrderBy);
    while (i < nOB) : (i += 1) {
        const pItem = elItem(pOrderBy, i);
        const pE = eliPExpr(pItem);
        const pE2 = sqlite3ExprSkipCollateAndLikely(pE);
        if (pE2 == null) continue;
        var iCol: c_int = undefined;
        if (zType[0] != 'G') {
            iCol = resolveAsName(pParse, selPEList(pSelect), pE2);
            if (iCol > 0) {
                eliSetIOrderByCol(pItem, @intCast(@as(u16, @truncate(@as(u32, @bitCast(iCol))))));
                continue;
            }
        }
        if (sqlite3ExprIsInteger(pE2, &iCol, null) != 0) {
            if (iCol < 1 or iCol > 0xffff) {
                resolveOutOfRangeError(pParse, zType, i + 1, nResult, pE2);
                return 1;
            }
            eliSetIOrderByCol(pItem, @intCast(@as(u16, @truncate(@as(u32, @bitCast(iCol))))));
            continue;
        }
        eliSetIOrderByCol(pItem, 0);
        if (sqlite3ResolveExprNames(pNC, pE) != 0) {
            return 1;
        }
        var j: c_int = 0;
        const nE = elNExpr(selPEList(pSelect));
        while (j < nE) : (j += 1) {
            if (sqlite3ExprCompare(null, pE, eliPExpr(elItem(selPEList(pSelect), j)), -1) == 0) {
                windowRemoveExprFromSelect(pSelect, pE);
                eliSetIOrderByCol(pItem, @intCast(@as(u16, @truncate(@as(u32, @bitCast(j + 1))))));
            }
        }
    }
    return sqlite3ResolveOrderGroupBy(pParse, pSelect, pOrderBy, zType);
}

// ═══ resolveSelectStep ═══════════════════════════════════════════════════════
fn resolveSelectStep(pWalker: ?*anyopaque, pIn: ?*anyopaque) callconv(.c) c_int {
    var p = pIn;
    if ((selFlags(p) & SF_Resolved) != 0) {
        return WRC_Prune;
    }
    const pOuterNC = wU(pWalker);
    const pParse = wPParse(pWalker);
    const db = pDb(pParse);

    if ((selFlags(p) & SF_Expanded) == 0) {
        sqlite3SelectPrep(pParse, p, pOuterNC);
        return if (pNErr(pParse) != 0) WRC_Abort else WRC_Prune;
    }

    const isCompound: c_int = @intFromBool(selPPrior(p) != null);
    var nCompound: c_int = 0;
    const pLeftmost = p;
    var sncbuf: [sizeof_NameContext]u8 align(8) = undefined;
    const sNC: ?*anyopaque = @ptrCast(&sncbuf);

    while (p != null) {
        selSetFlags(p, selFlags(p) | SF_Resolved);

        @memset(sncbuf[0..], 0);
        ncSetPParse(sNC, pParse);
        ncSetPWinSelect(sNC, p);
        if (sqlite3ResolveExprNames(sNC, selPLimit(p)) != 0) {
            return WRC_Abort;
        }

        if ((selFlags(p) & SF_Converted) != 0) {
            const pSub = subqPSelect(siU4PSubq(srcItem(selPSrc(p), 0)));
            selSetPOrderBy(pSub, selPOrderBy(p));
            selSetPOrderBy(p, null);
        }

        // Recursively resolve subqueries in FROM.
        if (pOuterNC != null) ncSetNNestedSelect(pOuterNC, ncNNestedSelect(pOuterNC) + 1);
        {
            var i: c_int = 0;
            const nSrc = srcNSrc(selPSrc(p));
            while (i < nSrc) : (i += 1) {
                const pItem = srcItem(selPSrc(p), i);
                if (siFgBit(pItem, SI_fg_isSubquery_byte, SI_fg_isSubquery_bit)) {
                    const pSubSel = subqPSelect(siU4PSubq(pItem));
                    if ((selFlags(pSubSel) & SF_Resolved) == 0) {
                        const nRef: c_int = if (pOuterNC != null) ncNRef(pOuterNC) else 0;
                        const zSavedContext = pZAuthContext(pParse);
                        if (siZName(pItem) != null) pSetZAuthContext(pParse, siZName(pItem));
                        sqlite3ResolveSelectNames(pParse, pSubSel, pOuterNC);
                        pSetZAuthContext(pParse, zSavedContext);
                        if (pNErr(pParse) != 0) return WRC_Abort;
                        if (pOuterNC != null) {
                            siFgSetCorrelated(pItem, ncNRef(pOuterNC) > nRef);
                        }
                    }
                }
            }
        }
        if (pOuterNC != null and ncNNestedSelect(pOuterNC) > 0) {
            ncSetNNestedSelect(pOuterNC, ncNNestedSelect(pOuterNC) - 1);
        }

        ncSetFlags(sNC, NC_AllowAgg | NC_AllowWin);
        ncSetPSrcList(sNC, selPSrc(p));
        ncSetPNext(sNC, pOuterNC);

        if (sqlite3ResolveExprListNames(sNC, selPEList(p)) != 0) return WRC_Abort;
        ncSetFlags(sNC, ncFlags(sNC) & ~NC_AllowWin);

        const pGroupBy = selPGroupBy(p);
        if (pGroupBy != null or (ncFlags(sNC) & NC_HasAgg) != 0) {
            selSetFlags(p, selFlags(p) | SF_Aggregate | @as(u32, @bitCast(ncFlags(sNC) & (NC_MinMaxAgg | NC_OrderAgg))));
        } else {
            ncSetFlags(sNC, ncFlags(sNC) & ~NC_AllowAgg);
        }

        ncSetUEList(sNC, selPEList(p));
        ncSetFlags(sNC, ncFlags(sNC) | NC_UEList);
        if (selPHaving(p) != null) {
            if ((selFlags(p) & SF_Aggregate) == 0) {
                sqlite3ErrorMsg(pParse, "HAVING clause on a non-aggregate query");
                return WRC_Abort;
            }
            if (sqlite3ResolveExprNames(sNC, selPHaving(p)) != 0) return WRC_Abort;
        }
        ncSetFlags(sNC, ncFlags(sNC) | NC_Where);
        if (sqlite3ResolveExprNames(sNC, selPWhere(p)) != 0) return WRC_Abort;
        ncSetFlags(sNC, ncFlags(sNC) & ~NC_Where);

        // table-valued-function arguments
        {
            var i: c_int = 0;
            const nSrc = srcNSrc(selPSrc(p));
            while (i < nSrc) : (i += 1) {
                const pItem = srcItem(selPSrc(p), i);
                if (siFgBit(pItem, SI_fg_isTabFunc_byte, SI_fg_isTabFunc_bit) and
                    sqlite3ResolveExprListNames(sNC, siU1PFuncArg(pItem)) != 0)
                {
                    return WRC_Abort;
                }
            }
        }

        if (inRenameObject(pParse)) {
            var pWin = selPWinDefn(p);
            while (pWin != null) : (pWin = winPNextWin(pWin)) {
                if (sqlite3ResolveExprListNames(sNC, winPOrderBy(pWin)) != 0 or
                    sqlite3ResolveExprListNames(sNC, winPPartition(pWin)) != 0)
                {
                    return WRC_Abort;
                }
            }
        }

        ncSetFlags(sNC, ncFlags(sNC) | NC_AllowAgg | NC_AllowWin);

        if ((selFlags(p) & SF_Converted) != 0) {
            const pSub = subqPSelect(siU4PSubq(srcItem(selPSrc(p), 0)));
            selSetPOrderBy(p, selPOrderBy(pSub));
            selSetPOrderBy(pSub, null);
        }

        if (selPOrderBy(p) != null and isCompound <= nCompound and
            resolveOrderGroupBy(sNC, p, selPOrderBy(p), "ORDER") != 0)
        {
            return WRC_Abort;
        }
        if (dbMallocFailed(db)) {
            return WRC_Abort;
        }
        ncSetFlags(sNC, ncFlags(sNC) & ~NC_AllowWin);

        if (pGroupBy != null) {
            if (resolveOrderGroupBy(sNC, p, pGroupBy, "GROUP") != 0 or dbMallocFailed(db)) {
                return WRC_Abort;
            }
            var i: c_int = 0;
            const nG = elNExpr(pGroupBy);
            while (i < nG) : (i += 1) {
                if (exprHasProperty(eliPExpr(elItem(pGroupBy, i)), EP_Agg)) {
                    sqlite3ErrorMsg(pParse, "aggregate functions are not allowed in the GROUP BY clause");
                    return WRC_Abort;
                }
            }
        }

        if (selPNext(p) != null and elNExpr(selPEList(p)) != elNExpr(selPEList(selPNext(p)))) {
            sqlite3SelectWrongNumTermsError(pParse, selPNext(p));
            return WRC_Abort;
        }

        if ((selFlags(p) & SF_OnToWhere) != 0) {
            sqlite3SelectCheckOnClauses(pParse, p);
            if (pNErr(pParse) != 0) return WRC_Abort;
        }

        p = selPPrior(p);
        nCompound += 1;
    }

    if (isCompound != 0 and resolveCompoundOrderBy(pParse, pLeftmost) != 0) {
        return WRC_Abort;
    }
    return WRC_Prune;
}

inline fn siFgSetCorrelated(it: ?*anyopaque, v: bool) void {
    if (v) siFgSet(it, SI_fg_isCorrelated_byte, SI_fg_isCorrelated_bit);
    // when false: bit was 0 (item zeroed); C also only sets, never clears here.
}

// ═══ sqlite3ResolveExprNames ═════════════════════════════════════════════════
export fn sqlite3ResolveExprNames(pNC: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    if (pExpr == null) return SQLITE_OK;
    const savedHasAgg = ncFlags(pNC) & (NC_HasAgg | NC_MinMaxAgg | NC_HasWin | NC_OrderAgg);
    ncSetFlags(pNC, ncFlags(pNC) & ~(NC_HasAgg | NC_MinMaxAgg | NC_HasWin | NC_OrderAgg));
    var wbuf: [sizeof_Walker]u8 align(8) = undefined;
    const w: ?*anyopaque = @ptrCast(&wbuf);
    wSetPParse(w, ncPParse(pNC));
    wSetXExpr(w, @ptrCast(&resolveExprStep));
    wSetXSelect(w, if ((ncFlags(pNC) & NC_NoSelect) != 0) null else @ptrCast(&resolveSelectStep));
    wSetXSelect2(w, null);
    wSetU(w, pNC);
    const pParse = ncPParse(pNC);
    pSetNHeight(pParse, pNHeight(pParse) + exprNHeight(pExpr));
    if (sqlite3ExprCheckHeight(pParse, pNHeight(pParse)) != 0) {
        return SQLITE_ERROR;
    }
    _ = sqlite3WalkExprNN(w, pExpr);
    pSetNHeight(pParse, pNHeight(pParse) - exprNHeight(pExpr));
    exprSetProperty(pExpr, @bitCast(ncFlags(pNC) & (NC_HasAgg | NC_HasWin)));
    ncSetFlags(pNC, ncFlags(pNC) | savedHasAgg);
    return @intFromBool(ncNNcErr(pNC) > 0 or pNErr(pParse) > 0);
}

// ═══ sqlite3ResolveExprListNames ═════════════════════════════════════════════
export fn sqlite3ResolveExprListNames(pNC: ?*anyopaque, pList: ?*anyopaque) callconv(.c) c_int {
    if (pList == null) return SQLITE_OK;
    var wbuf: [sizeof_Walker]u8 align(8) = undefined;
    const w: ?*anyopaque = @ptrCast(&wbuf);
    const pParse = ncPParse(pNC);
    wSetPParse(w, pParse);
    wSetXExpr(w, @ptrCast(&resolveExprStep));
    wSetXSelect(w, @ptrCast(&resolveSelectStep));
    wSetXSelect2(w, null);
    wSetU(w, pNC);
    var savedHasAgg = ncFlags(pNC) & (NC_HasAgg | NC_MinMaxAgg | NC_HasWin | NC_OrderAgg);
    ncSetFlags(pNC, ncFlags(pNC) & ~(NC_HasAgg | NC_MinMaxAgg | NC_HasWin | NC_OrderAgg));
    var i: c_int = 0;
    const nE = elNExpr(pList);
    while (i < nE) : (i += 1) {
        const pExpr = eliPExpr(elItem(pList, i));
        if (pExpr == null) continue;
        pSetNHeight(pParse, pNHeight(pParse) + exprNHeight(pExpr));
        if (sqlite3ExprCheckHeight(pParse, pNHeight(pParse)) != 0) {
            return SQLITE_ERROR;
        }
        _ = sqlite3WalkExprNN(w, pExpr);
        pSetNHeight(pParse, pNHeight(pParse) - exprNHeight(pExpr));
        if ((ncFlags(pNC) & (NC_HasAgg | NC_MinMaxAgg | NC_HasWin | NC_OrderAgg)) != 0) {
            exprSetProperty(pExpr, @bitCast(ncFlags(pNC) & (NC_HasAgg | NC_HasWin)));
            savedHasAgg |= ncFlags(pNC) & (NC_HasAgg | NC_MinMaxAgg | NC_HasWin | NC_OrderAgg);
            ncSetFlags(pNC, ncFlags(pNC) & ~(NC_HasAgg | NC_MinMaxAgg | NC_HasWin | NC_OrderAgg));
        }
        if (pNErr(pParse) > 0) return SQLITE_ERROR;
    }
    ncSetFlags(pNC, ncFlags(pNC) | savedHasAgg);
    return SQLITE_OK;
}

// ═══ sqlite3ResolveSelectNames ═══════════════════════════════════════════════
export fn sqlite3ResolveSelectNames(pParse: ?*anyopaque, p: ?*anyopaque, pOuterNC: ?*anyopaque) callconv(.c) void {
    var wbuf: [sizeof_Walker]u8 align(8) = undefined;
    const w: ?*anyopaque = @ptrCast(&wbuf);
    wSetXExpr(w, @ptrCast(&resolveExprStep));
    wSetXSelect(w, @ptrCast(&resolveSelectStep));
    wSetXSelect2(w, null);
    wSetPParse(w, pParse);
    wSetU(w, pOuterNC);
    _ = sqlite3WalkSelect(w, p);
}

// ═══ sqlite3ResolveSelfReference ═════════════════════════════════════════════
const SZ_SRCLIST_1 = off("SZ_SRCLIST_1", 80);
export fn sqlite3ResolveSelfReference(pParse: ?*anyopaque, pTab: ?*anyopaque, typeIn: c_int, pExpr: ?*anyopaque, pList: ?*anyopaque) callconv(.c) c_int {
    var typ = typeIn;
    var sncbuf: [sizeof_NameContext]u8 align(8) = @splat(0);
    const sNC: ?*anyopaque = @ptrCast(&sncbuf);
    var srcbuf: [SZ_SRCLIST_1]u8 align(8) = @splat(0);
    const pSrc: ?*anyopaque = @ptrCast(&srcbuf);
    if (pTab) |tab| {
        srcSetNSrc(pSrc, 1);
        // a[0].zName = pTab->zName
        wr(?[*:0]const u8, srcItem(pSrc, 0), 0, tabZName(tab));
        siSetPSTab(srcItem(pSrc, 0), tab);
        siSetICursor(srcItem(pSrc, 0), -1);
        // if pTab->pSchema != db->aDb[1].pSchema -> type |= NC_FromDDL
        if (tabPSchema(tab) != dbAtPSchema(pDb(pParse), 1)) {
            typ |= NC_FromDDL;
        }
    }
    ncSetPParse(sNC, pParse);
    ncSetPSrcList(sNC, pSrc);
    ncSetFlags(sNC, typ | NC_IsDDL);
    var rc = sqlite3ResolveExprNames(sNC, pExpr);
    if (rc != SQLITE_OK) return rc;
    if (pList != null) rc = sqlite3ResolveExprListNames(sNC, pList);
    return rc;
}

comptime {
    // Sanity: divergent bitfield byte must differ by config.
    if (config.sqlite_debug) {
        std.debug.assert(Parse_bReturning_byte == 42);
    } else {
        std.debug.assert(Parse_bReturning_byte == 39);
    }
}
