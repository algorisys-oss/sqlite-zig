//! Zig port of SQLite's src/whereexpr.c — WHERE-clause analysis.  Decomposes
//! the WHERE expression into WhereTerm objects (sqlite3WhereClauseInit/Clear,
//! sqlite3WhereSplit, exprAnalyze, the LIKE/GLOB/REGEXP optimization, OR-term
//! analysis, virtual-term generation, sqlite3WhereExpr*Usage, sqlite3WhereAddLimit,
//! sqlite3WhereTabFuncArgs).
//!
//! It shares the whereInt.h internal structs (WhereClause, WhereTerm, WhereInfo,
//! WhereMaskSet, WhereOrInfo, WhereAndInfo) with the still-C where.c/wherecode.c.
//! Those structs are accessed via ground-truth offsets (raw-memory helper idiom
//! shared with expr.zig).  CRITICAL: SQLITE_DEBUG adds WhereTerm.iTerm, which
//! shifts WhereTerm.u / prereqRight / prereqAll and the sizeof of WhereTerm,
//! WhereClause, WhereOrInfo, WhereInfo.  All such offsets are config-gated below.
//!
//! Config assumptions (true in BOTH production and the --dev testfixture):
//! SQLITE_OMIT_LIKE_OPTIMIZATION / _OR_OPTIMIZATION / _SUBQUERY / _BETWEEN_OPTIMIZATION
//! / _VIRTUALTABLE / _WINDOWFUNC all OFF.  SQLITE_EBCDIC OFF.
//! SQLITE_LIKE_DOESNT_MATCH_BLOBS OFF.  SQLITE_SMALL_STACK OFF (aStatic[8]).
//! SQLITE_ENABLE_STAT4 OFF for TERM_HIGHTRUTH (=0).  SQLITE_DEBUG via config.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers (copied from expr.zig / build.zig) ──────────────────
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
inline fn fieldPtr(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return @ptrCast(base(p) + offs);
}
inline fn rdp(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return rd(?*anyopaque, p, offs);
}
fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

const Ptr = ?*anyopaque;

// ─── TK_* token / opcode codes (parse.h) ────────────────────────────────────
const TK_AS: c_int = 24;
const TK_OR: c_int = 43;
const TK_AND: c_int = 44;
const TK_IS: c_int = 45;
const TK_ISNOT: c_int = 46;
const TK_MATCH: c_int = 47;
const TK_BETWEEN: c_int = 49;
const TK_IN: c_int = 50;
const TK_ISNULL: c_int = 51;
const TK_NOTNULL: c_int = 52;
const TK_NE: c_int = 53;
const TK_EQ: c_int = 54;
const TK_GT: c_int = 55;
const TK_LE: c_int = 56;
const TK_LT: c_int = 57;
const TK_GE: c_int = 58;
const TK_COLLATE: c_int = 114;
const TK_STRING: c_int = 118;
const TK_NULL: c_int = 122;
const TK_LIMIT: c_int = 149;
const TK_VARIABLE: c_int = 157;
const TK_COLUMN: c_int = 168;
const TK_TRUEFALSE: c_int = 171;
const TK_FUNCTION: c_int = 172;
const TK_UPLUS: c_int = 173;
const TK_REGISTER: c_int = 176;
const TK_VECTOR: c_int = 177;

// ─── EP_* flags (Expr.flags, u32) ───────────────────────────────────────────
const EP_OuterON: u32 = 0x000001;
const EP_InnerON: u32 = 0x000002;
const EP_FixedCol: u32 = 0x000020;
const EP_VarSelect: u32 = 0x000040;
const EP_Collate: u32 = 0x000200;
const EP_Commuted: u32 = 0x000400;
const EP_IntValue: u32 = 0x000800;
const EP_xIsSelect: u32 = 0x001000;
const EP_Unlikely: u32 = 0x080000;
const EP_TokenOnly: u32 = 0x010000;
const EP_IfNullRow: u32 = 0x040000;
const EP_Leaf: u32 = 0x800000;
const EP_WinFunc: u32 = 0x1000000;
const EP_Subrtn: u32 = 0x2000000;
const EP_IsFalse: u32 = 0x20000000;

// ─── WO_* operator bitmask (whereInt.h) ─────────────────────────────────────
const WO_IN: u16 = 0x0001;
const WO_EQ: u16 = 0x0002;
const WO_LT: u16 = WO_EQ << (TK_LT - TK_EQ);
const WO_LE: u16 = WO_EQ << (TK_LE - TK_EQ);
const WO_GT: u16 = WO_EQ << (TK_GT - TK_EQ);
const WO_GE: u16 = WO_EQ << (TK_GE - TK_EQ);
const WO_AUX: u16 = 0x0040;
const WO_IS: u16 = 0x0080;
const WO_ISNULL: u16 = 0x0100;
const WO_OR: u16 = 0x0200;
const WO_AND: u16 = 0x0400;
const WO_EQUIV: u16 = 0x0800;
const WO_ROWVAL: u16 = 0x2000;
const WO_ALL: u16 = 0x3fff;
const WO_SINGLE: u16 = 0x01ff;

// ─── TERM_* flags (WhereTerm.wtFlags, u16) ──────────────────────────────────
const TERM_DYNAMIC: u16 = 0x0001;
const TERM_VIRTUAL: u16 = 0x0002;
const TERM_CODED: u16 = 0x0004;
const TERM_COPIED: u16 = 0x0008;
const TERM_ORINFO: u16 = 0x0010;
const TERM_ANDINFO: u16 = 0x0020;
const TERM_OK: u16 = 0x0040;
const TERM_VNULL: u16 = 0x0080;
const TERM_LIKEOPT: u16 = 0x0100;
const TERM_LIKE: u16 = 0x0400;
const TERM_IS: u16 = 0x0800;
const TERM_VARSELECT: u16 = 0x1000;
const TERM_SLICE: u16 = 0x8000;

// ─── affinity / encoding / type constants ───────────────────────────────────
const SQLITE_AFF_BLOB: u8 = 0x41;
const SQLITE_AFF_TEXT: u8 = 0x42;
const SQLITE_UTF8: c_int = 1;
const SQLITE_UTF16LE: c_int = 2;
const SQLITE_TEXT: c_int = 3;

// ─── join / select / opt / col flags ────────────────────────────────────────
const JT_LEFT: u32 = 0x08;
const JT_RIGHT: u32 = 0x10;
const JT_LTORJ: u32 = 0x40;
const SF_Distinct: u32 = 0x0000001;
const SF_Aggregate: u32 = 0x0000008;
const SF_Compound: u32 = 0x0000100;
const SF_Values: u32 = 0x0000200;
const SQLITE_Transitive: u32 = 0x00000080;
const SQLITE_EnableQPSG: u32 = 0x00800000; // db->flags is u64
const COLFLAG_HIDDEN: u16 = 0x0002;
const TABTYP_VTAB: u8 = 1;
const XN_EXPR: c_int = -2;

// ─── SQLITE_INDEX_CONSTRAINT_* values (sqlite3.h) ───────────────────────────
const IC_EQ: c_int = 2;
const IC_MATCH: c_int = 64;
const IC_LIKE: c_int = 65;
const IC_GLOB: c_int = 66;
const IC_REGEXP: c_int = 67;
const IC_NE: c_int = 68;
const IC_ISNOT: c_int = 69;
const IC_ISNOTNULL: c_int = 70;
const IC_FUNCTION: c_int = 150;
const IC_LIMIT: c_int = 73;
const IC_OFFSET: c_int = 74;

// ─── struct offsets ─────────────────────────────────────────────────────────
// Expr (config-invariant; mostly already in c_layout)
const Expr_op = off("Expr_op", 0);
const Expr_flags = off("Expr_flags", 4);
const Expr_iTable = off("Expr_iTable", 44);
const Expr_iColumn = off("Expr_iColumn", 48);
const Expr_pLeft = off("Expr_pLeft", 16);
const Expr_pRight = off("Expr_pRight", 24);
const Expr_u = off("Expr_u", 8); // u.zToken / u.iValue
const Expr_x = off("Expr_x", 32); // x.pList / x.pSelect
const Expr_w_iJoin = off("Expr_w_iJoin", 52);
const Expr_yTab = off("Expr_yTab", 64); // y.pTab

// sqlite3
const db_mallocFailed = off("sqlite3_mallocFailed", 103);
const db_flags = off("sqlite3_flags", 48); // u64
const db_enc = off("sqlite3_enc", 100); // u8
const db_dbOptFlags = off("sqlite3_dbOptFlags", 96); // u32

// Parse
const Parse_db = off("Parse_db", 0);
const Parse_pVdbe = off("Parse_pVdbe", 16);
const Parse_pReprepare = off("Parse_pReprepare", 328);

// Table / Column / Index
const Table_zName = off("Table_zName", 0);
const Table_nCol = off("Table_nCol", 54); // i16
const Table_aCol = off("Table_aCol", 8);
const Table_eTabType = off("Table_eTabType", 63); // u8
const Column_colFlags = off("Column_colFlags", 14); // u16
const sizeof_Column = off("sizeof_Column", 16);
const Index_pNext = off("Index_pNext", 40);
const Index_aColExpr = off("Index_aColExpr", 80);
const Index_nKeyCol = off("Index_nKeyCol", 94); // u16
const Index_aiColumn = off("Index_aiColumn", 8); // i16*

// SrcList / SrcItem
const SrcList_nSrc = off("SrcList_nSrc", 0); // i32
const SrcList_a = off("SrcList_a", 8);
const SrcItem_pSTab = off("SrcItem_pSTab", 16);
const SrcItem_fg = off("SrcItem_fg", 24); // jointype is low byte (u8)
const SrcItem_iCursor = off("SrcItem_iCursor", 28); // i32
const SrcItem_colUsed = off("SrcItem_colUsed", 32); // Bitmask u64
const SrcItem_u1_pFuncArg = off("SrcItem_u1_pFuncArg", 40);
const SrcItem_u3_pOn = off("SrcItem_u3_pOn", 56);
const SrcItem_u4_pSubq = off("SrcItem_u4_pSubq", 64);
const sizeof_SrcItem = off("sizeof_SrcItem", 72);
const Subquery_pSelect = off("Subquery_pSelect", 0);
// SrcItem.fg bitfield: probed in the 32-bit word at SrcItem_fg.
const FG_isUsing: u32 = 0x80000; // bit 19
const FG_isSubquery: u32 = 0x400; // bit 10
const FG_isTabFunc: u32 = 0x800; // bit 11

// Select
const Select_pEList = off("Select_pEList", 24);
const Select_pSrc = off("Select_pSrc", 32);
const Select_pWhere = off("Select_pWhere", 40);
const Select_pGroupBy = off("Select_pGroupBy", 48);
const Select_pHaving = off("Select_pHaving", 56);
const Select_pOrderBy = off("Select_pOrderBy", 64);
const Select_pPrior = off("Select_pPrior", 72);
const Select_pLimit = off("Select_pLimit", 88);
const Select_pWin = off("Select_pWin", 104);
const Select_selFlags = off("Select_selFlags", 4); // u32
const Select_iLimit = off("Select_iLimit", 8); // i32
const Select_iOffset = off("Select_iOffset", 12); // i32

// ExprList
const ExprList_nExpr = off("ExprList_nExpr", 0); // i32
const ExprList_a = off("ExprList_a", 8);
const ELItem_pExpr = off("ExprList_item_pExpr", 8);
const sizeof_ELItem = off("sizeof_ExprList_item", 24);
const ELItem_fg_sortFlags = off("ExprList_item_fg_sortFlags", 24); // u8
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

// CollSeq
const CollSeq_zName = off("CollSeq_zName", 0);

// ─── Where* structs — CONFIG-GATED (SQLITE_DEBUG adds WhereTerm.iTerm) ───────
const dbg = config.sqlite_debug;

// WhereClause
const WhereClause_pWInfo = off("WhereClause_pWInfo", 0);
const WhereClause_pOuter = off("WhereClause_pOuter", 8);
const WhereClause_op = off("WhereClause_op", 16); // u8
const WhereClause_hasOr = off("WhereClause_hasOr", 17); // u8
const WhereClause_nTerm = off("WhereClause_nTerm", 20); // i32
const WhereClause_nSlot = off("WhereClause_nSlot", 24); // i32
const WhereClause_nBase = off("WhereClause_nBase", 28); // i32
const WhereClause_a = off("WhereClause_a", 32); // WhereTerm*
const WhereClause_aStatic = off("WhereClause_aStatic", 40); // inline WhereTerm[8]
const sizeof_WhereClause = if (dbg) off("sizeof_WhereClause", 552) else off("sizeof_WhereClause", 488);
const WHERECLAUSE_NSTATIC: c_int = 8;

// WhereTerm (sizeof 56 prod / 64 debug)
const sizeof_WhereTerm = if (dbg) off("sizeof_WhereTerm", 64) else off("sizeof_WhereTerm", 56);
const WhereTerm_pExpr = off("WhereTerm_pExpr", 0);
const WhereTerm_pWC = off("WhereTerm_pWC", 8);
const WhereTerm_truthProb = off("WhereTerm_truthProb", 16); // i16 LogEst
const WhereTerm_wtFlags = off("WhereTerm_wtFlags", 18); // u16
const WhereTerm_eOperator = off("WhereTerm_eOperator", 20); // u16
const WhereTerm_nChild = off("WhereTerm_nChild", 22); // u8
const WhereTerm_eMatchOp = off("WhereTerm_eMatchOp", 23); // u8
const WhereTerm_iParent = off("WhereTerm_iParent", 24); // i32
const WhereTerm_leftCursor = off("WhereTerm_leftCursor", 28); // i32
const WhereTerm_iTerm = off("WhereTerm_iTerm", 32); // i32, SQLITE_DEBUG only
const WhereTerm_u = if (dbg) off("WhereTerm_u", 40) else off("WhereTerm_u", 32);
const WhereTerm_u_x_leftColumn = if (dbg) off("WhereTerm_u_x_leftColumn", 40) else off("WhereTerm_u_x_leftColumn", 32); // i32
const WhereTerm_u_x_iField = if (dbg) off("WhereTerm_u_x_iField", 44) else off("WhereTerm_u_x_iField", 36); // i32
const WhereTerm_prereqRight = if (dbg) off("WhereTerm_prereqRight", 48) else off("WhereTerm_prereqRight", 40); // u64
const WhereTerm_prereqAll = if (dbg) off("WhereTerm_prereqAll", 56) else off("WhereTerm_prereqAll", 48); // u64
// memset target offset: offsetof(WhereTerm, eOperator) = 20 both configs
const WT_MEMSET0_FROM: usize = 20;

// WhereInfo
const WhereInfo_pParse = off("WhereInfo_pParse", 0);
const WhereInfo_pTabList = off("WhereInfo_pTabList", 8);
const WhereInfo_sMaskSet = if (dbg) off("WhereInfo_sMaskSet", 672) else off("WhereInfo_sMaskSet", 592);

// WhereMaskSet (config-invariant; embedded in WhereInfo)
const WhereMaskSet_bVarSelect = off("WhereMaskSet_bVarSelect", 0); // i32

// WhereOrInfo / WhereAndInfo
const sizeof_WhereOrInfo = if (dbg) off("sizeof_WhereOrInfo", 560) else off("sizeof_WhereOrInfo", 496);
const WhereOrInfo_wc = off("WhereOrInfo_wc", 0);
const WhereOrInfo_indexable = if (dbg) off("WhereOrInfo_indexable", 552) else off("WhereOrInfo_indexable", 488); // u64
const sizeof_WhereAndInfo = if (dbg) off("sizeof_WhereAndInfo", 552) else off("sizeof_WhereAndInfo", 488);
const WhereAndInfo_wc = off("WhereAndInfo_wc", 0);

const Bitmask = u64;

// ─── typed field accessors ──────────────────────────────────────────────────
inline fn exprOp(p: Ptr) c_int {
    return rd(u8, p, Expr_op);
}
inline fn setExprOp(p: Ptr, v: c_int) void {
    wr(u8, p, Expr_op, @truncate(@as(c_uint, @bitCast(v))));
}
inline fn exprFlags(p: Ptr) u32 {
    return rd(u32, p, Expr_flags);
}
inline fn setExprFlags(p: Ptr, v: u32) void {
    wr(u32, p, Expr_flags, v);
}
inline fn hasProp(p: Ptr, m: u32) bool {
    return (exprFlags(p) & m) != 0;
}
inline fn setProp(p: Ptr, m: u32) void {
    setExprFlags(p, exprFlags(p) | m);
}
inline fn clearProp(p: Ptr, m: u32) void {
    setExprFlags(p, exprFlags(p) & ~m);
}
inline fn useXList(p: Ptr) bool {
    return (exprFlags(p) & EP_xIsSelect) == 0;
}
inline fn useXSelect(p: Ptr) bool {
    return (exprFlags(p) & EP_xIsSelect) != 0;
}
inline fn exprLeft(p: Ptr) Ptr {
    return rdp(p, Expr_pLeft);
}
inline fn exprRight(p: Ptr) Ptr {
    return rdp(p, Expr_pRight);
}
inline fn exprPList(p: Ptr) Ptr {
    return rdp(p, Expr_x);
}
inline fn exprPSelect(p: Ptr) Ptr {
    return rdp(p, Expr_x);
}
inline fn exprITable(p: Ptr) c_int {
    return rd(c_int, p, Expr_iTable);
}
inline fn exprIColumn(p: Ptr) c_int {
    return rd(i16, p, Expr_iColumn); // ynVar is i16 (-1 for rowid) — sign-extend, NOT a 4-byte read
}
inline fn exprZToken(p: Ptr) ?[*:0]u8 {
    return @ptrCast(rdp(p, Expr_u));
}
inline fn exprYpTab(p: Ptr) Ptr {
    return rdp(p, Expr_yTab);
}
/// ExprIsVtab(X): X->op==TK_COLUMN && X->y.pTab->eTabType==TABTYP_VTAB
inline fn exprIsVtab(p: Ptr) bool {
    if (exprOp(p) != TK_COLUMN) return false;
    const tab = exprYpTab(p);
    if (tab == null) return false;
    return rd(u8, tab, Table_eTabType) == TABTYP_VTAB;
}
inline fn isVirtual(tab: Ptr) bool {
    return rd(u8, tab, Table_eTabType) == TABTYP_VTAB;
}

// ExprList helpers
inline fn elNExpr(p: Ptr) c_int {
    return rd(c_int, p, ExprList_nExpr);
}
inline fn elItem(p: Ptr, i: usize) Ptr {
    return fieldPtr(p, ExprList_a + i * sizeof_ELItem);
}
inline fn elItemExpr(p: Ptr, i: usize) Ptr {
    return rdp(elItem(p, i), ELItem_pExpr);
}

// SrcList helpers
inline fn slNSrc(p: Ptr) c_int {
    return rd(c_int, p, SrcList_nSrc);
}
inline fn slItem(p: Ptr, i: usize) Ptr {
    return fieldPtr(p, SrcList_a + i * sizeof_SrcItem);
}

// WhereClause accessors
inline fn wcWInfo(p: Ptr) Ptr {
    return rdp(p, WhereClause_pWInfo);
}
inline fn wcA(p: Ptr) Ptr {
    return rdp(p, WhereClause_a);
}
inline fn wcTermAt(p: Ptr, idx: c_int) Ptr {
    const a = wcA(p);
    return fieldPtr(a, @as(usize, @intCast(idx)) * sizeof_WhereTerm);
}
inline fn wcNTerm(p: Ptr) c_int {
    return rd(c_int, p, WhereClause_nTerm);
}
inline fn wcOp(p: Ptr) c_int {
    return rd(u8, p, WhereClause_op);
}

// WhereTerm accessors
inline fn wtWtFlags(t: Ptr) u16 {
    return rd(u16, t, WhereTerm_wtFlags);
}
inline fn wtSetWtFlags(t: Ptr, v: u16) void {
    wr(u16, t, WhereTerm_wtFlags, v);
}
inline fn wtEOperator(t: Ptr) u16 {
    return rd(u16, t, WhereTerm_eOperator);
}
inline fn wtLeftCursor(t: Ptr) c_int {
    return rd(c_int, t, WhereTerm_leftCursor);
}
inline fn wtExpr(t: Ptr) Ptr {
    return rdp(t, WhereTerm_pExpr);
}

// Parse / db helpers
inline fn parseDb(pParse: Ptr) Ptr {
    return rdp(pParse, Parse_db);
}
inline fn dbMallocFailed(db: Ptr) bool {
    return rd(u8, db, db_mallocFailed) != 0;
}
inline fn dbEnc(db: Ptr) c_int {
    return rd(u8, db, db_enc);
}

// ─── inline ports of macros ─────────────────────────────────────────────────
inline fn sqlite3Strlen30(z: ?[*:0]const u8) c_int {
    // strlen(z) & 0x3fffffff
    const n: c_int = @intCast(std.mem.len(z.?) & 0x3fffffff);
    return n;
}
inline fn optimizationEnabled(db: Ptr, mask: u32) bool {
    return (rd(u32, db, db_dbOptFlags) & mask) == 0;
}
inline fn isNumericAffinity(aff: u8) bool {
    return aff >= 0x43; // SQLITE_AFF_NUMERIC
}

// ─── extern C ABI functions ─────────────────────────────────────────────────
const c = struct {
    extern fn sqlite3DbMallocZero(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbMallocRawNN(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbFree(db: Ptr, p: Ptr) void;
    extern fn sqlite3LogEst(v: u64) i16;
    extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
    extern fn sqlite3ExprSkipCollate(p: Ptr) Ptr;
    extern fn sqlite3ExprSkipCollateAndLikely(p: Ptr) Ptr;
    extern fn sqlite3ExprDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3ExprDup(db: Ptr, p: Ptr, flags: c_int) Ptr;
    extern fn sqlite3Expr(db: Ptr, op: c_int, z: ?[*:0]const u8) Ptr;
    extern fn sqlite3ExprAlloc(db: Ptr, op: c_int, pToken: Ptr, dequote: c_int) Ptr;
    extern fn sqlite3ExprInt32(db: Ptr, v: c_int) Ptr;
    extern fn sqlite3PExpr(pParse: Ptr, op: c_int, pLeft: Ptr, pRight: Ptr) Ptr;
    extern fn sqlite3ExprListAppend(pParse: Ptr, pList: Ptr, p: Ptr) Ptr;
    extern fn sqlite3ExprListDelete(db: Ptr, pList: Ptr) void;
    extern fn sqlite3ExprAddCollateString(pParse: Ptr, p: Ptr, z: ?[*:0]const u8) Ptr;
    extern fn sqlite3ExprAffinity(p: Ptr) u8;
    extern fn sqlite3ExprCanBeNull(p: Ptr) c_int;
    extern fn sqlite3ExprIsConstant(pParse: Ptr, p: Ptr) c_int;
    extern fn sqlite3ExprIsInteger(p: Ptr, v: *c_int, pParse: Ptr) c_int;
    extern fn sqlite3ExprCompare(pParse: Ptr, a: Ptr, b: Ptr, iTab: c_int) c_int;
    extern fn sqlite3ExprCompareSkip(a: Ptr, b: Ptr, iTab: c_int) c_int;
    extern fn sqlite3ExprCheckIN(pParse: Ptr, p: Ptr) c_int;
    extern fn sqlite3ExprVectorSize(p: Ptr) c_int;
    extern fn sqlite3ExprForVectorField(pParse: Ptr, pVector: Ptr, iField: c_int, nField: c_int) Ptr;
    extern fn sqlite3ExprCollSeq(pParse: Ptr, p: Ptr) Ptr;
    extern fn sqlite3ExprCollSeqMatch(pParse: Ptr, a: Ptr, b: Ptr) c_int;
    extern fn sqlite3ExprCompareCollSeq(pParse: Ptr, p: Ptr) Ptr;
    extern fn sqlite3BinaryCompareCollSeq(pParse: Ptr, a: Ptr, b: Ptr) Ptr;
    extern fn sqlite3ExprColUsed(p: Ptr) u64;
    extern fn sqlite3ExprCodeTarget(pParse: Ptr, p: Ptr, target: c_int) c_int;
    extern fn sqlite3SetJoinExpr(p: Ptr, iTable: c_int, joinFlag: u32) void;
    extern fn sqlite3IsLikeFunction(db: Ptr, pExpr: Ptr, pIsNocase: *c_int, wc: [*]u8) c_int;
    extern fn sqlite3Utf8Read(pz: *[*]const u8) u32;
    extern fn sqlite3AtoF(z: ?[*:0]const u8, p: *f64) c_int;
    extern fn sqlite3ErrorMsg(pParse: Ptr, fmt: ?[*:0]const u8, ...) void;
    extern fn sqlite3GetTempReg(pParse: Ptr) c_int;
    extern fn sqlite3ReleaseTempReg(pParse: Ptr, r: c_int) void;
    extern fn sqlite3VdbeChangeP3(v: Ptr, addr: c_int, p3: c_int) void;
    extern fn sqlite3VdbeCurrentAddr(v: Ptr) c_int;
    extern fn sqlite3VdbeSetVarmask(v: Ptr, i: c_int) void;
    extern fn sqlite3VdbeGetBoundValue(p: Ptr, i: c_int, aff: u8) Ptr;
    extern fn sqlite3_value_type(p: Ptr) c_int;
    extern fn sqlite3_value_text(p: Ptr) ?[*:0]const u8;
    extern fn sqlite3ValueFree(p: Ptr) void;
    extern fn sqlite3GetVTable(db: Ptr, pTab: Ptr) Ptr;
    // where.c (still C):
    extern fn sqlite3WhereGetMask(pMaskSet: Ptr, iCursor: c_int) u64;
    extern fn sqlite3WhereMalloc(pWInfo: Ptr, n: u64) Ptr;
    // case tables (extern const char[256]):
    extern const sqlite3UpperToLower: [256]u8;
    // char sqlite3StrBINARY[] = "BINARY" — the SYMBOL'S ADDRESS is the data; bind
    // as u8 and take &, never as a [*:0] value (that reads "BINARY" bytes as a ptr).
    extern const sqlite3StrBINARY: u8;
    extern const sqlite3CtypeMap: [256]u8;
    // SQLITE_ASCII macros, not real symbols:
    //   sqlite3Toupper(x) = x & ~(CtypeMap[x] & 0x20);  sqlite3Tolower(x) = UpperToLower[x]
    fn sqlite3Toupper(c_: c_int) c_int {
        const x: u8 = @truncate(@as(u32, @bitCast(c_)));
        return c_ & ~@as(c_int, sqlite3CtypeMap[x] & 0x20);
    }
    fn sqlite3Tolower(c_: c_int) c_int {
        const x: u8 = @truncate(@as(u32, @bitCast(c_)));
        return sqlite3UpperToLower[x];
    }
};

inline fn atoF(z: ?[*:0]const u8, p: *f64) c_int {
    return c.sqlite3AtoF(z, p);
}

// ─── static helpers ─────────────────────────────────────────────────────────

fn whereOrInfoDelete(db: Ptr, p: Ptr) void {
    sqlite3WhereClauseClear(fieldPtr(p, WhereOrInfo_wc));
    c.sqlite3DbFree(db, p);
}

fn whereAndInfoDelete(db: Ptr, p: Ptr) void {
    sqlite3WhereClauseClear(fieldPtr(p, WhereAndInfo_wc));
    c.sqlite3DbFree(db, p);
}

/// Add a single new WhereTerm entry to pWC.  Returns the index in pWC->a[].
fn whereClauseInsert(pWC: Ptr, p: Ptr, wtFlags: u16) c_int {
    if (wcNTerm(pWC) >= rd(c_int, pWC, WhereClause_nSlot)) {
        const pOld = wcA(pWC);
        const pWInfo = wcWInfo(pWC);
        const pParse = rdp(pWInfo, WhereInfo_pParse);
        const db = parseDb(pParse);
        const nSlot = rd(c_int, pWC, WhereClause_nSlot);
        const newA = c.sqlite3WhereMalloc(pWInfo, sizeof_WhereTerm * @as(u64, @intCast(nSlot)) * 2);
        if (newA == null) {
            if ((wtFlags & TERM_DYNAMIC) != 0) {
                c.sqlite3ExprDelete(db, p);
            }
            // pWC->a = pOld (unchanged); just restore pointer.
            wr(?*anyopaque, pWC, WhereClause_a, pOld);
            return 0;
        }
        wr(?*anyopaque, pWC, WhereClause_a, newA);
        const nTerm: usize = @intCast(wcNTerm(pWC));
        @memcpy(@as([*]u8, @ptrCast(newA.?))[0 .. sizeof_WhereTerm * nTerm], @as([*]u8, @ptrCast(pOld.?))[0 .. sizeof_WhereTerm * nTerm]);
        wr(c_int, pWC, WhereClause_nSlot, nSlot * 2);
    }
    const idx = wcNTerm(pWC);
    wr(c_int, pWC, WhereClause_nTerm, idx + 1);
    const pTerm = wcTermAt(pWC, idx);
    if ((wtFlags & TERM_VIRTUAL) == 0) {
        wr(c_int, pWC, WhereClause_nBase, idx + 1);
    }
    if (p != null and hasProp(p, EP_Unlikely)) {
        const le = c.sqlite3LogEst(@as(u64, @bitCast(@as(i64, exprITable(p)))));
        wr(i16, pTerm, WhereTerm_truthProb, le - 270);
    } else {
        wr(i16, pTerm, WhereTerm_truthProb, 1);
    }
    wr(?*anyopaque, pTerm, WhereTerm_pExpr, c.sqlite3ExprSkipCollateAndLikely(p));
    wtSetWtFlags(pTerm, wtFlags);
    wr(?*anyopaque, pTerm, WhereTerm_pWC, pWC);
    wr(c_int, pTerm, WhereTerm_iParent, -1);
    // memset(&pTerm->eOperator, 0, sizeof(WhereTerm)-offsetof(WhereTerm,eOperator))
    const dst: [*]u8 = @as([*]u8, @ptrCast(pTerm.?)) + WT_MEMSET0_FROM;
    @memset(dst[0 .. sizeof_WhereTerm - WT_MEMSET0_FROM], 0);
    return idx;
}

/// allowedOp — operators allowed for an indexable WHERE term.
fn allowedOp(op: c_int) bool {
    if (op > TK_GE) return false;
    if (op >= TK_EQ) return true;
    return op == TK_IN or op == TK_ISNULL or op == TK_IS;
}

/// exprCommute — commute "X op Y" -> "Y op X".  Returns extra eOperator bits (0).
fn exprCommute(pParse: Ptr, pExpr: Ptr) u16 {
    const pLeft = exprLeft(pExpr);
    const pRight = exprRight(pExpr);
    if (exprOp(pLeft) == TK_VECTOR or
        exprOp(pRight) == TK_VECTOR or
        c.sqlite3BinaryCompareCollSeq(pParse, pLeft, pRight) !=
            c.sqlite3BinaryCompareCollSeq(pParse, pRight, pLeft))
    {
        setExprFlags(pExpr, exprFlags(pExpr) ^ EP_Commuted);
    }
    // SWAP(pExpr->pRight, pExpr->pLeft)
    wr(?*anyopaque, pExpr, Expr_pRight, pLeft);
    wr(?*anyopaque, pExpr, Expr_pLeft, pRight);
    const op = exprOp(pExpr);
    if (op >= TK_GT) {
        setExprOp(pExpr, ((op - TK_GT) ^ 2) + TK_GT);
    }
    return 0;
}

/// operatorMask — TK_xx -> WO_xx bitmask.
fn operatorMask(op: c_int) u16 {
    if (op >= TK_EQ) {
        return @as(u16, WO_EQ) << @intCast(op - TK_EQ);
    } else if (op == TK_IN) {
        return WO_IN;
    } else if (op == TK_ISNULL) {
        return WO_ISNULL;
    } else {
        return WO_IS;
    }
}

/// isLikeOrGlob — LIKE/GLOB optimization test.  ppPrefix/pisComplete/pnoCase out.
fn isLikeOrGlob(pParse: Ptr, pExpr: Ptr, ppPrefix: *Ptr, pisComplete: *c_int, pnoCase: *c_int) c_int {
    var z: ?[*:0]const u8 = null;
    var wc: [4]u8 = undefined;
    const db = parseDb(pParse);
    var pVal: Ptr = null;

    if (c.sqlite3IsLikeFunction(db, pExpr, pnoCase, &wc) == 0) {
        return 0;
    }
    const pList = exprPList(pExpr);
    const pLeft = elItemExpr(pList, 1);

    const pRight = c.sqlite3ExprSkipCollate(elItemExpr(pList, 0));
    const op = exprOp(pRight);
    if (op == TK_VARIABLE and (rd(u64, db, db_flags) & SQLITE_EnableQPSG) == 0) {
        const pReprepare = rdp(pParse, Parse_pReprepare);
        const iCol = exprIColumn(pRight);
        pVal = c.sqlite3VdbeGetBoundValue(pReprepare, iCol, SQLITE_AFF_BLOB);
        if (pVal != null and c.sqlite3_value_type(pVal) == SQLITE_TEXT) {
            z = c.sqlite3_value_text(pVal);
        }
        c.sqlite3VdbeSetVarmask(rdp(pParse, Parse_pVdbe), iCol);
    } else if (op == TK_STRING) {
        z = exprZToken(pRight);
    }
    if (z) |zz| {
        var cnt: c_int = 0;
        var ch: u8 = zz[@intCast(cnt)];
        while (ch != 0 and ch != wc[0] and ch != wc[1] and ch != wc[2]) {
            cnt += 1;
            if (ch == wc[3] and zz[@intCast(cnt)] > 0 and zz[@intCast(cnt)] < 0x80) {
                cnt += 1;
            } else if (ch >= 0x80) {
                var z2: [*]const u8 = @ptrCast(zz + @as(usize, @intCast(cnt - 1)));
                if (ch == 0xff or c.sqlite3Utf8Read(&z2) == 0xfffd or dbEnc(db) == SQLITE_UTF16LE) {
                    cnt -= 1;
                    break;
                } else {
                    cnt = @intCast(@intFromPtr(z2) - @intFromPtr(@as([*]const u8, @ptrCast(zz))));
                }
            }
            ch = zz[@intCast(cnt)];
        }

        if ((cnt > 1 or (cnt > 0 and zz[0] != wc[3])) and 255 != zz[@intCast(cnt - 1)]) {
            // A "complete" match if the pattern ends with "*" or "%"
            pisComplete.* = @intFromBool(ch == wc[0] and zz[@intCast(cnt + 1)] == 0 and dbEnc(db) != SQLITE_UTF16LE);

            const pPrefix = c.sqlite3Expr(db, TK_STRING, zz);
            if (pPrefix != null) {
                const zNew = exprZToken(pPrefix).?;
                zNew[@intCast(cnt)] = 0;
                var iFrom: c_int = 0;
                var iTo: c_int = 0;
                while (iFrom < cnt) : (iFrom += 1) {
                    if (zNew[@intCast(iFrom)] == wc[3]) iFrom += 1;
                    zNew[@intCast(iTo)] = zNew[@intCast(iFrom)];
                    iTo += 1;
                }
                zNew[@intCast(iTo)] = 0;

                // If LHS isn't an ordinary TEXT column (or is on a vtab), the
                // prefix boundaries must not look like a number.
                const leftNotPlainText = exprOp(pLeft) != TK_COLUMN or
                    c.sqlite3ExprAffinity(pLeft) != SQLITE_AFF_TEXT or
                    (exprYpTab(pLeft) != null and isVirtual(exprYpTab(pLeft)));
                if (leftNotPlainText) {
                    var rDummy: f64 = undefined;
                    var isNum = atoF(zNew, &rDummy);
                    if (isNum <= 0) {
                        if (iTo == 1 and zNew[0] == '-') {
                            isNum = 1;
                        } else {
                            zNew[@intCast(iTo - 1)] +%= 1;
                            isNum = atoF(zNew, &rDummy);
                            zNew[@intCast(iTo - 1)] -%= 1;
                        }
                    }
                    if (isNum > 0) {
                        c.sqlite3ExprDelete(db, pPrefix);
                        c.sqlite3ValueFree(pVal);
                        return 0;
                    }
                }
            }
            ppPrefix.* = pPrefix;

            if (op == TK_VARIABLE) {
                const v = rdp(pParse, Parse_pVdbe);
                c.sqlite3VdbeSetVarmask(v, exprIColumn(pRight));
                if (pisComplete.* != 0 and exprZToken(pRight).?[1] != 0) {
                    const r1 = c.sqlite3GetTempReg(pParse);
                    _ = c.sqlite3ExprCodeTarget(pParse, pRight, r1);
                    c.sqlite3VdbeChangeP3(v, c.sqlite3VdbeCurrentAddr(v) - 1, 0);
                    c.sqlite3ReleaseTempReg(pParse, r1);
                }
            }
        } else {
            z = null;
        }
    }

    const rc: c_int = @intFromBool(z != null);
    c.sqlite3ValueFree(pVal);
    return rc;
}

/// sqlite3ExprIsLikeOperator — match,glob,like,regexp -> SQLITE_INDEX_CONSTRAINT_*.
export fn sqlite3ExprIsLikeOperator(pExpr: Ptr) c_int {
    const names = [_][*:0]const u8{ "match", "glob", "like", "regexp" };
    const ops = [_]c_int{ IC_MATCH, IC_GLOB, IC_LIKE, IC_REGEXP };
    const z = exprZToken(pExpr);
    var i: usize = 0;
    while (i < names.len) : (i += 1) {
        if (c.sqlite3StrICmp(z, names[i]) == 0) {
            return ops[i];
        }
    }
    return 0;
}

/// isAuxiliaryVtabOperator — detect MATCH/GLOB/LIKE/REGEXP/!=/IS NOT/NOT NULL
/// forms for virtual tables.  Returns 0, 1, or 2.
fn isAuxiliaryVtabOperator(db: Ptr, pExpr: Ptr, peOp2: *u8, ppLeft: *Ptr, ppRight: *Ptr) c_int {
    if (exprOp(pExpr) == TK_FUNCTION) {
        const pList = exprPList(pExpr);
        if (pList == null or elNExpr(pList) != 2) {
            return 0;
        }

        var pCol = elItemExpr(pList, 1);
        if (exprIsVtab(pCol)) {
            const ii = sqlite3ExprIsLikeOperator(pExpr);
            if (ii != 0) {
                peOp2.* = @intCast(ii);
                ppRight.* = elItemExpr(pList, 0);
                ppLeft.* = pCol;
                return 1;
            }
        }

        pCol = elItemExpr(pList, 0);
        if (exprIsVtab(pCol)) {
            const pVtab = rdp(c.sqlite3GetVTable(db, exprYpTab(pCol)), VTable_pVtab);
            const pMod = rdp(pVtab, sqlite3_vtab_pModule);
            const xFind = rdp(pMod, sqlite3_module_xFindFunction);
            if (xFind != null) {
                const fn_t = *const fn (Ptr, c_int, ?[*:0]const u8, *Ptr, *Ptr) callconv(.c) c_int;
                const xff: fn_t = @ptrCast(xFind);
                var xNotUsed: Ptr = undefined;
                var pNotUsed: Ptr = undefined;
                const ii = xff(pVtab, 2, exprZToken(pExpr), &xNotUsed, &pNotUsed);
                if (ii >= IC_FUNCTION) {
                    peOp2.* = @intCast(ii);
                    ppRight.* = elItemExpr(pList, 1);
                    ppLeft.* = pCol;
                    return 1;
                }
            }
        }
    } else if (exprOp(pExpr) >= TK_EQ) {
        return 0;
    } else if (exprOp(pExpr) == TK_NE or exprOp(pExpr) == TK_ISNOT or exprOp(pExpr) == TK_NOTNULL) {
        var res: c_int = 0;
        var pLeft = exprLeft(pExpr);
        var pRight = exprRight(pExpr);
        if (exprIsVtab(pLeft)) {
            res += 1;
        }
        if (pRight != null and exprIsVtab(pRight)) {
            res += 1;
            const tmp = pLeft;
            pLeft = pRight;
            pRight = tmp;
        }
        ppLeft.* = pLeft;
        ppRight.* = pRight;
        if (exprOp(pExpr) == TK_NE) peOp2.* = @intCast(IC_NE);
        if (exprOp(pExpr) == TK_ISNOT) peOp2.* = @intCast(IC_ISNOT);
        if (exprOp(pExpr) == TK_NOTNULL) peOp2.* = @intCast(IC_ISNOTNULL);
        return res;
    }
    return 0;
}
// sqlite3_vtab / sqlite3_module field offsets (public ABI structs)
const VTable_pVtab = off("VTable_pVtab", 16);
const sqlite3_vtab_pModule = off("sqlite3_vtab_pModule", 0);
const sqlite3_module_xFindFunction = off("sqlite3_module_xFindFunction", 144);

/// transferJoinMarkings — copy ON/USING markings from pBase to pDerived.
fn transferJoinMarkings(pDerived: Ptr, pBase: Ptr) void {
    if (pDerived != null and hasProp(pBase, EP_OuterON | EP_InnerON)) {
        setExprFlags(pDerived, exprFlags(pDerived) | (exprFlags(pBase) & (EP_OuterON | EP_InnerON)));
        wr(c_int, pDerived, Expr_w_iJoin, rd(c_int, pBase, Expr_w_iJoin));
    }
}

/// markTermAsChild — mark term iChild a child of iParent.
fn markTermAsChild(pWC: Ptr, iChild: c_int, iParent: c_int) void {
    const childT = wcTermAt(pWC, iChild);
    const parentT = wcTermAt(pWC, iParent);
    wr(c_int, childT, WhereTerm_iParent, iParent);
    wr(i16, childT, WhereTerm_truthProb, rd(i16, parentT, WhereTerm_truthProb));
    wr(u8, parentT, WhereTerm_nChild, rd(u8, parentT, WhereTerm_nChild) + 1);
}

/// whereNthSubterm — N-th AND-connected subterm of pTerm (or pTerm itself).
fn whereNthSubterm(pTerm: Ptr, n: c_int) Ptr {
    if (wtEOperator(pTerm) != WO_AND) {
        return if (n == 0) pTerm else null;
    }
    const pAndInfo = rdp(pTerm, WhereTerm_u); // u.pAndInfo
    const pAndWc = fieldPtr(pAndInfo, WhereAndInfo_wc);
    if (n < wcNTerm(pAndWc)) {
        return wcTermAt(pAndWc, n);
    }
    return null;
}

/// whereCombineDisjuncts — combine x<y OR x=y -> x<=y etc.
fn whereCombineDisjuncts(pSrc: Ptr, pWC: Ptr, pOne: Ptr, pTwo: Ptr) void {
    var eOp: u16 = wtEOperator(pOne) | wtEOperator(pTwo);

    if (((wtWtFlags(pOne) | wtWtFlags(pTwo)) & TERM_VNULL) != 0) return;
    if ((wtEOperator(pOne) & (WO_EQ | WO_LT | WO_LE | WO_GT | WO_GE)) == 0) return;
    if ((wtEOperator(pTwo) & (WO_EQ | WO_LT | WO_LE | WO_GT | WO_GE)) == 0) return;
    if ((eOp & (WO_EQ | WO_LT | WO_LE)) != eOp and (eOp & (WO_EQ | WO_GT | WO_GE)) != eOp) return;
    const pA = wtExpr(pOne);
    const pB = wtExpr(pTwo);
    if (c.sqlite3ExprCompare(null, exprLeft(pA), exprLeft(pB), -1) != 0) return;
    if (c.sqlite3ExprCompare(null, exprRight(pA), exprRight(pB), -1) != 0) return;
    if (hasProp(pA, EP_Commuted) != hasProp(pB, EP_Commuted)) {
        return;
    }
    if ((eOp & (eOp -% 1)) != 0) {
        if ((eOp & (WO_LT | WO_LE)) != 0) {
            eOp = WO_LE;
        } else {
            eOp = WO_GE;
        }
    }
    const db = parseDb(rdp(wcWInfo(pWC), WhereInfo_pParse));
    const pNew = c.sqlite3ExprDup(db, pA, 0);
    if (pNew == null) return;
    var op: c_int = TK_EQ;
    while (eOp != (@as(u16, WO_EQ) << @intCast(op - TK_EQ))) : (op += 1) {}
    setExprOp(pNew, op);
    const idxNew = whereClauseInsert(pWC, pNew, TERM_VIRTUAL | TERM_DYNAMIC);
    exprAnalyze(pSrc, pWC, idxNew);
}

/// exprAnalyzeOrTerm — analyze an OR-connected term (cases 1/2/3).
fn exprAnalyzeOrTerm(pSrc: Ptr, pWC: Ptr, idxTerm: c_int) void {
    const pWInfo = wcWInfo(pWC);
    const pParse = rdp(pWInfo, WhereInfo_pParse);
    const db = parseDb(pParse);
    var pTerm = wcTermAt(pWC, idxTerm);
    const pExpr = wtExpr(pTerm);
    const pMaskSet = fieldPtr(pWInfo, WhereInfo_sMaskSet);

    const pOrInfo = c.sqlite3DbMallocZero(db, sizeof_WhereOrInfo);
    if (pOrInfo == null) return;
    wr(?*anyopaque, pTerm, WhereTerm_u, pOrInfo); // pTerm->u.pOrInfo
    wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_ORINFO);
    const pOrWc = fieldPtr(pOrInfo, WhereOrInfo_wc);
    // memset(pOrWc->aStatic, 0, sizeof(aStatic))
    @memset(@as([*]u8, @ptrCast(fieldPtr(pOrWc, WhereClause_aStatic).?))[0 .. @as(usize, @intCast(WHERECLAUSE_NSTATIC)) * sizeof_WhereTerm], 0);
    sqlite3WhereClauseInit(pOrWc, pWInfo);
    sqlite3WhereSplit(pOrWc, pExpr, TK_OR);
    sqlite3WhereExprAnalyze(pSrc, pOrWc);
    if (dbMallocFailed(db)) return;

    var indexable: Bitmask = ~@as(Bitmask, 0);
    var chngToIN: Bitmask = ~@as(Bitmask, 0);
    {
        var i: c_int = wcNTerm(pOrWc) - 1;
        var pOrTerm = wcA(pOrWc);
        while (i >= 0 and indexable != 0) : ({
            i -= 1;
            pOrTerm = fieldPtr(pOrTerm, sizeof_WhereTerm);
        }) {
            if ((wtEOperator(pOrTerm) & WO_SINGLE) == 0) {
                chngToIN = 0;
                const pAndInfo = c.sqlite3DbMallocRawNN(db, sizeof_WhereAndInfo);
                if (pAndInfo != null) {
                    var b: Bitmask = 0;
                    wr(?*anyopaque, pOrTerm, WhereTerm_u, pAndInfo); // u.pAndInfo
                    wtSetWtFlags(pOrTerm, wtWtFlags(pOrTerm) | TERM_ANDINFO);
                    wr(u16, pOrTerm, WhereTerm_eOperator, WO_AND);
                    wr(c_int, pOrTerm, WhereTerm_leftCursor, -1);
                    const pAndWC = fieldPtr(pAndInfo, WhereAndInfo_wc);
                    @memset(@as([*]u8, @ptrCast(fieldPtr(pAndWC, WhereClause_aStatic).?))[0 .. @as(usize, @intCast(WHERECLAUSE_NSTATIC)) * sizeof_WhereTerm], 0);
                    sqlite3WhereClauseInit(pAndWC, wcWInfo(pWC));
                    sqlite3WhereSplit(pAndWC, wtExpr(pOrTerm), TK_AND);
                    sqlite3WhereExprAnalyze(pSrc, pAndWC);
                    wr(?*anyopaque, pAndWC, WhereClause_pOuter, pWC);
                    if (!dbMallocFailed(db)) {
                        var j: c_int = 0;
                        var pAndTerm = wcA(pAndWC);
                        while (j < wcNTerm(pAndWC)) : ({
                            j += 1;
                            pAndTerm = fieldPtr(pAndTerm, sizeof_WhereTerm);
                        }) {
                            if (allowedOp(exprOp(wtExpr(pAndTerm))) or wtEOperator(pAndTerm) == WO_AUX) {
                                b |= c.sqlite3WhereGetMask(pMaskSet, wtLeftCursor(pAndTerm));
                            }
                        }
                    }
                    indexable &= b;
                }
            } else if ((wtWtFlags(pOrTerm) & TERM_COPIED) != 0) {
                // skip; revisit via TERM_VIRTUAL term
            } else {
                var b = c.sqlite3WhereGetMask(pMaskSet, wtLeftCursor(pOrTerm));
                if ((wtWtFlags(pOrTerm) & TERM_VIRTUAL) != 0) {
                    const pOther = wcTermAt(pOrWc, rd(c_int, pOrTerm, WhereTerm_iParent));
                    b |= c.sqlite3WhereGetMask(pMaskSet, wtLeftCursor(pOther));
                }
                indexable &= b;
                if ((wtEOperator(pOrTerm) & WO_EQ) == 0) {
                    chngToIN = 0;
                } else {
                    chngToIN &= b;
                }
            }
        }
    }

    wr(Bitmask, pOrInfo, WhereOrInfo_indexable, indexable);
    wr(u16, pTerm, WhereTerm_eOperator, WO_OR);
    wr(c_int, pTerm, WhereTerm_leftCursor, -1);
    if (indexable != 0) {
        wr(u8, pWC, WhereClause_hasOr, 1);
    }

    // Case 2: two-way OR.
    if (indexable != 0 and wcNTerm(pOrWc) == 2) {
        var iOne: c_int = 0;
        while (true) {
            const pOne = whereNthSubterm(wcTermAt(pOrWc, 0), iOne);
            iOne += 1;
            if (pOne == null) break;
            var iTwo: c_int = 0;
            while (true) {
                const pTwo = whereNthSubterm(wcTermAt(pOrWc, 1), iTwo);
                iTwo += 1;
                if (pTwo == null) break;
                whereCombineDisjuncts(pSrc, pWC, pOne, pTwo);
            }
        }
    }

    // Case 1: chngToIN -> convert OR to IN.
    if (chngToIN != 0) {
        var okToChngToIN: c_int = 0;
        var iColumn: c_int = -1;
        var iCursor: c_int = -1;
        var jOuter: c_int = 0;
        var i: c_int = 0;
        var pOrTerm: Ptr = undefined;
        while (jOuter < 2 and okToChngToIN == 0) : (jOuter += 1) {
            var pLeft: Ptr = null;
            pOrTerm = wcA(pOrWc);
            i = wcNTerm(pOrWc) - 1;
            while (i >= 0) : ({
                i -= 1;
                pOrTerm = fieldPtr(pOrTerm, sizeof_WhereTerm);
            }) {
                wtSetWtFlags(pOrTerm, wtWtFlags(pOrTerm) & ~TERM_OK);
                if (wtLeftCursor(pOrTerm) == iCursor) {
                    continue;
                }
                if ((chngToIN & c.sqlite3WhereGetMask(pMaskSet, wtLeftCursor(pOrTerm))) == 0) {
                    continue;
                }
                iColumn = rd(c_int, pOrTerm, WhereTerm_u_x_leftColumn);
                iCursor = wtLeftCursor(pOrTerm);
                pLeft = exprLeft(wtExpr(pOrTerm));
                break;
            }
            if (i < 0) {
                break;
            }

            okToChngToIN = 1;
            while (i >= 0 and okToChngToIN != 0) : ({
                i -= 1;
                pOrTerm = fieldPtr(pOrTerm, sizeof_WhereTerm);
            }) {
                if (wtLeftCursor(pOrTerm) != iCursor) {
                    wtSetWtFlags(pOrTerm, wtWtFlags(pOrTerm) & ~TERM_OK);
                } else if (rd(c_int, pOrTerm, WhereTerm_u_x_leftColumn) != iColumn or
                    (iColumn == XN_EXPR and
                        c.sqlite3ExprCompare(pParse, exprLeft(wtExpr(pOrTerm)), pLeft, -1) != 0))
                {
                    okToChngToIN = 0;
                } else {
                    const affRight = c.sqlite3ExprAffinity(exprRight(wtExpr(pOrTerm)));
                    const affLeft = c.sqlite3ExprAffinity(exprLeft(wtExpr(pOrTerm)));
                    if (affRight != 0 and affRight != affLeft) {
                        okToChngToIN = 0;
                    } else {
                        wtSetWtFlags(pOrTerm, wtWtFlags(pOrTerm) | TERM_OK);
                    }
                }
            }
        }

        if (okToChngToIN != 0) {
            var pList: Ptr = null;
            var pLeft: Ptr = null;
            var pCollSeq: Ptr = null;
            var pNew: Ptr = null;

            i = wcNTerm(pOrWc) - 1;
            pOrTerm = wcA(pOrWc);
            while (i >= 0) : ({
                i -= 1;
                pOrTerm = fieldPtr(pOrTerm, sizeof_WhereTerm);
            }) {
                if ((wtWtFlags(pOrTerm) & TERM_OK) == 0) continue;
                const pThis = wtExpr(pOrTerm);
                const pDup = c.sqlite3ExprDup(db, exprRight(pThis), 0);
                pList = c.sqlite3ExprListAppend(rdp(pWInfo, WhereInfo_pParse), pList, pDup);
                if (pLeft == null) {
                    pLeft = exprLeft(pThis);
                    pCollSeq = c.sqlite3ExprCompareCollSeq(pParse, pThis);
                } else {
                    if (pCollSeq != c.sqlite3ExprCompareCollSeq(pParse, pThis)) {
                        pLeft = null;
                        break;
                    }
                }
            }
            if (pLeft == null) {
                pNew = null;
            } else {
                var pDup = c.sqlite3ExprDup(db, pLeft, 0);
                if (c.sqlite3ExprCollSeq(pParse, pDup) != pCollSeq and pCollSeq != null) {
                    pDup = c.sqlite3ExprAddCollateString(pParse, pDup, rd(?[*:0]const u8, pCollSeq, CollSeq_zName));
                }
                pNew = c.sqlite3PExpr(pParse, TK_IN, pDup, null);
            }
            if (pNew != null) {
                transferJoinMarkings(pNew, pExpr);
                wr(?*anyopaque, pNew, Expr_x, pList); // pNew->x.pList
                const idxNew = whereClauseInsert(pWC, pNew, TERM_VIRTUAL | TERM_DYNAMIC);
                exprAnalyze(pSrc, pWC, idxNew);
                markTermAsChild(pWC, idxNew, idxTerm);
            } else {
                c.sqlite3ExprListDelete(db, pList);
            }
        }
    }
    _ = &pTerm;
}

/// termIsEquivalence — is pExpr an A==B equivalence (Transitive opt)?
fn termIsEquivalence(pParse: Ptr, pExpr: Ptr, pSrc: Ptr) c_int {
    const db = parseDb(pParse);
    if (!optimizationEnabled(db, SQLITE_Transitive)) return 0;
    if (exprOp(pExpr) != TK_EQ and exprOp(pExpr) != TK_IS) return 0;
    if (hasProp(pExpr, EP_OuterON | EP_Collate)) return 0;
    if (exprOp(pExpr) == TK_IS and slNSrc(pSrc) >= 2 and (rd(u8, slItem(pSrc, 0), SrcItem_fg) & @as(u8, @intCast(JT_LTORJ))) != 0) {
        return 0;
    }
    const aff1 = c.sqlite3ExprAffinity(exprLeft(pExpr));
    const aff2 = c.sqlite3ExprAffinity(exprRight(pExpr));
    if (aff1 != aff2 and (!isNumericAffinity(aff1) or !isNumericAffinity(aff2))) {
        return 0;
    }
    if (c.sqlite3ExprCollSeqMatch(pParse, exprLeft(pExpr), exprRight(pExpr)) == 0) {
        return 0;
    }
    return 1;
}

/// exprSelectUsage — bitmask of tables used by a SELECT.
fn exprSelectUsage(pMaskSet: Ptr, pSel: Ptr) Bitmask {
    var mask: Bitmask = 0;
    var pS = pSel;
    while (pS != null) {
        const pSrc = rdp(pS, Select_pSrc);
        mask |= sqlite3WhereExprListUsage(pMaskSet, rdp(pS, Select_pEList));
        mask |= sqlite3WhereExprListUsage(pMaskSet, rdp(pS, Select_pGroupBy));
        mask |= sqlite3WhereExprListUsage(pMaskSet, rdp(pS, Select_pOrderBy));
        mask |= sqlite3WhereExprUsage(pMaskSet, rdp(pS, Select_pWhere));
        mask |= sqlite3WhereExprUsage(pMaskSet, rdp(pS, Select_pHaving));
        if (pSrc != null) {
            var i: usize = 0;
            const n: usize = @intCast(slNSrc(pSrc));
            while (i < n) : (i += 1) {
                const it = slItem(pSrc, i);
                const fg = rd(u32, it, SrcItem_fg);
                if ((fg & FG_isSubquery) != 0) {
                    const pSubq = rdp(it, SrcItem_u4_pSubq);
                    mask |= exprSelectUsage(pMaskSet, rdp(pSubq, Subquery_pSelect));
                }
                if ((fg & FG_isUsing) == 0) {
                    mask |= sqlite3WhereExprUsage(pMaskSet, rdp(it, SrcItem_u3_pOn));
                }
                if ((fg & FG_isTabFunc) != 0) {
                    mask |= sqlite3WhereExprListUsage(pMaskSet, rdp(it, SrcItem_u1_pFuncArg));
                }
            }
        }
        pS = rdp(pS, Select_pPrior);
    }
    return mask;
}

/// exprMightBeIndexed2 — check whether pExpr matches an index-on-expression.
fn exprMightBeIndexed2(pFrom: Ptr, aiCurCol: *[2]c_int, pExpr: Ptr, jStart: c_int) c_int {
    var j = jStart;
    while (true) {
        const it = slItem(pFrom, @intCast(j));
        const iCur = rd(c_int, it, SrcItem_iCursor);
        var pIdx = rdp(rdp(it, SrcItem_pSTab), Table_pIndex);
        while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
            const aColExpr = rdp(pIdx, Index_aColExpr);
            if (aColExpr == null) continue;
            const nKeyCol = rd(u16, pIdx, Index_nKeyCol);
            const aiColumn: [*]i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn)));
            var i: usize = 0;
            while (i < nKeyCol) : (i += 1) {
                if (aiColumn[i] != XN_EXPR) continue;
                const colExpr = elItemExpr(aColExpr, i);
                if (c.sqlite3ExprCompareSkip(pExpr, colExpr, iCur) == 0 and
                    c.sqlite3ExprIsConstant(null, colExpr) == 0)
                {
                    aiCurCol[0] = iCur;
                    aiCurCol[1] = XN_EXPR;
                    return 1;
                }
            }
        }
        j += 1;
        if (j >= slNSrc(pFrom)) break;
    }
    return 0;
}
const Table_pIndex = off("Table_pIndex", 16);

/// exprMightBeIndexed — does pExpr appear in any index?
fn exprMightBeIndexed(pFrom: Ptr, aiCurCol: *[2]c_int, pExpr0: Ptr, op: c_int) c_int {
    var pExpr = pExpr0;
    if (exprOp(pExpr) == TK_VECTOR and (op >= TK_GT and op <= TK_GE)) {
        pExpr = elItemExpr(exprPList(pExpr), 0);
    }

    if (exprOp(pExpr) == TK_COLUMN) {
        aiCurCol[0] = exprITable(pExpr);
        aiCurCol[1] = exprIColumn(pExpr);
        return 1;
    }

    var i: c_int = 0;
    const n = slNSrc(pFrom);
    while (i < n) : (i += 1) {
        const it = slItem(pFrom, @intCast(i));
        var pIdx = rdp(rdp(it, SrcItem_pSTab), Table_pIndex);
        while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
            if (rdp(pIdx, Index_aColExpr) != null) {
                return exprMightBeIndexed2(pFrom, aiCurCol, pExpr, i);
            }
        }
    }
    return 0;
}

/// exprAnalyze — populate a WhereTerm from its pExpr.
fn exprAnalyze(pSrc: Ptr, pWC: Ptr, idxTerm: c_int) void {
    const pWInfo = wcWInfo(pWC);
    var extraRight: Bitmask = 0;
    var pStr1: Ptr = null;
    var isComplete: c_int = 0;
    var noCase: c_int = 0;
    const pParse = rdp(pWInfo, WhereInfo_pParse);
    const db = parseDb(pParse);
    var eOp2: u8 = 0;

    if (dbMallocFailed(db)) {
        return;
    }
    var pTerm = wcTermAt(pWC, idxTerm);
    if (dbg) {
        wr(c_int, pTerm, WhereTerm_iTerm, idxTerm);
    }
    const pMaskSet = fieldPtr(pWInfo, WhereInfo_sMaskSet);
    const pExpr = wtExpr(pTerm);
    wr(c_int, pMaskSet, WhereMaskSet_bVarSelect, 0);
    const prereqLeft = sqlite3WhereExprUsage(pMaskSet, exprLeft(pExpr));
    const op = exprOp(pExpr);
    var prereqAll: Bitmask = undefined;
    if (op == TK_IN) {
        if (c.sqlite3ExprCheckIN(pParse, pExpr) != 0) return;
        if (useXSelect(pExpr)) {
            wr(Bitmask, pTerm, WhereTerm_prereqRight, exprSelectUsage(pMaskSet, exprPSelect(pExpr)));
        } else {
            wr(Bitmask, pTerm, WhereTerm_prereqRight, sqlite3WhereExprListUsage(pMaskSet, exprPList(pExpr)));
        }
        prereqAll = prereqLeft | rd(Bitmask, pTerm, WhereTerm_prereqRight);
    } else {
        wr(Bitmask, pTerm, WhereTerm_prereqRight, sqlite3WhereExprUsage(pMaskSet, exprRight(pExpr)));
        if (exprLeft(pExpr) == null or hasProp(pExpr, EP_xIsSelect | EP_IfNullRow) or exprPList(pExpr) != null) {
            prereqAll = sqlite3WhereExprUsageNN(pMaskSet, pExpr);
        } else {
            prereqAll = prereqLeft | rd(Bitmask, pTerm, WhereTerm_prereqRight);
        }
    }
    if (rd(c_int, pMaskSet, WhereMaskSet_bVarSelect) != 0) {
        wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_VARSELECT);
    }

    if (hasProp(pExpr, EP_OuterON | EP_InnerON)) {
        const x = c.sqlite3WhereGetMask(pMaskSet, rd(c_int, pExpr, Expr_w_iJoin));
        if (hasProp(pExpr, EP_OuterON)) {
            prereqAll |= x;
            extraRight = x -% 1;
        } else if ((prereqAll >> 1) >= x) {
            clearProp(pExpr, EP_InnerON);
        }
    }
    wr(Bitmask, pTerm, WhereTerm_prereqAll, prereqAll);
    wr(c_int, pTerm, WhereTerm_leftCursor, -1);
    wr(c_int, pTerm, WhereTerm_iParent, -1);
    wr(u16, pTerm, WhereTerm_eOperator, 0);
    if (allowedOp(op)) {
        var aiCurCol: [2]c_int = undefined;
        var pLeft = c.sqlite3ExprSkipCollate(exprLeft(pExpr));
        const pRight = c.sqlite3ExprSkipCollate(exprRight(pExpr));
        const opMask: u16 = if ((rd(Bitmask, pTerm, WhereTerm_prereqRight) & prereqLeft) == 0) WO_ALL else WO_EQUIV;

        if (rd(c_int, pTerm, WhereTerm_u_x_iField) > 0) {
            pLeft = elItemExpr(exprPList(pLeft), @intCast(rd(c_int, pTerm, WhereTerm_u_x_iField) - 1));
        }

        if (exprMightBeIndexed(pSrc, &aiCurCol, pLeft, op) != 0) {
            wr(c_int, pTerm, WhereTerm_leftCursor, aiCurCol[0]);
            wr(c_int, pTerm, WhereTerm_u_x_leftColumn, aiCurCol[1]);
            wr(u16, pTerm, WhereTerm_eOperator, operatorMask(op) & opMask);
        }
        if (op == TK_IS) wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_IS);
        if (pRight != null and
            exprMightBeIndexed(pSrc, &aiCurCol, pRight, op) != 0 and
            !hasProp(pRight, EP_FixedCol))
        {
            var pNew: Ptr = undefined;
            var pDup: Ptr = undefined;
            var eExtraOp: u16 = 0;
            if (wtLeftCursor(pTerm) >= 0) {
                pDup = c.sqlite3ExprDup(db, pExpr, 0);
                if (dbMallocFailed(db)) {
                    c.sqlite3ExprDelete(db, pDup);
                    return;
                }
                const idxNew = whereClauseInsert(pWC, pDup, TERM_VIRTUAL | TERM_DYNAMIC);
                if (idxNew == 0) return;
                pNew = wcTermAt(pWC, idxNew);
                markTermAsChild(pWC, idxNew, idxTerm);
                if (op == TK_IS) wtSetWtFlags(pNew, wtWtFlags(pNew) | TERM_IS);
                pTerm = wcTermAt(pWC, idxTerm);
                wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_COPIED);
                if (termIsEquivalence(pParse, pDup, rdp(pWInfo, WhereInfo_pTabList)) != 0) {
                    wr(u16, pTerm, WhereTerm_eOperator, wtEOperator(pTerm) | WO_EQUIV);
                    eExtraOp = WO_EQUIV;
                }
            } else {
                pDup = pExpr;
                pNew = pTerm;
            }
            wtSetWtFlags(pNew, wtWtFlags(pNew) | exprCommute(pParse, pDup));
            wr(c_int, pNew, WhereTerm_leftCursor, aiCurCol[0]);
            wr(c_int, pNew, WhereTerm_u_x_leftColumn, aiCurCol[1]);
            wr(Bitmask, pNew, WhereTerm_prereqRight, prereqLeft | extraRight);
            wr(Bitmask, pNew, WhereTerm_prereqAll, prereqAll);
            wr(u16, pNew, WhereTerm_eOperator, (operatorMask(exprOp(pDup)) + eExtraOp) & opMask);
        } else if (op == TK_ISNULL and
            !hasProp(pExpr, EP_OuterON) and
            c.sqlite3ExprCanBeNull(pLeft) == 0)
        {
            setExprOp(pExpr, TK_TRUEFALSE);
            wr(?*anyopaque, pExpr, Expr_u, @constCast(@ptrCast("false")));
            setProp(pExpr, EP_IsFalse);
            wr(Bitmask, pTerm, WhereTerm_prereqAll, 0);
            wr(u16, pTerm, WhereTerm_eOperator, 0);
        }
    }

    // BETWEEN optimization
    if (exprOp(pExpr) == TK_BETWEEN and wcOp(pWC) == TK_AND) {
        const pList = exprPList(pExpr);
        const ops = [_]c_int{ TK_GE, TK_LE };
        var i: usize = 0;
        while (i < 2) : (i += 1) {
            const pNewExpr = c.sqlite3PExpr(pParse, ops[i], c.sqlite3ExprDup(db, exprLeft(pExpr), 0), c.sqlite3ExprDup(db, elItemExpr(pList, i), 0));
            transferJoinMarkings(pNewExpr, pExpr);
            const idxNew = whereClauseInsert(pWC, pNewExpr, TERM_VIRTUAL | TERM_DYNAMIC);
            exprAnalyze(pSrc, pWC, idxNew);
            pTerm = wcTermAt(pWC, idxTerm);
            markTermAsChild(pWC, idxNew, idxTerm);
        }
    }
    // OR optimization
    else if (exprOp(pExpr) == TK_OR and !hasProp(pExpr, EP_Collate)) {
        exprAnalyzeOrTerm(pSrc, pWC, idxTerm);
        pTerm = wcTermAt(pWC, idxTerm);
    }
    // x IS NOT NULL -> x>NULL virtual term
    else if (exprOp(pExpr) == TK_NOTNULL) {
        if (exprOp(exprLeft(pExpr)) == TK_COLUMN and
            exprIColumn(exprLeft(pExpr)) >= 0 and
            !hasProp(pExpr, EP_OuterON))
        {
            const pLeft = exprLeft(pExpr);
            const pNewExpr = c.sqlite3PExpr(pParse, TK_GT, c.sqlite3ExprDup(db, pLeft, 0), c.sqlite3ExprAlloc(db, TK_NULL, null, 0));
            const idxNew = whereClauseInsert(pWC, pNewExpr, TERM_VIRTUAL | TERM_DYNAMIC | TERM_VNULL);
            if (idxNew != 0) {
                const pNewTerm = wcTermAt(pWC, idxNew);
                wr(Bitmask, pNewTerm, WhereTerm_prereqRight, 0);
                wr(c_int, pNewTerm, WhereTerm_leftCursor, exprITable(pLeft));
                wr(c_int, pNewTerm, WhereTerm_u_x_leftColumn, exprIColumn(pLeft));
                wr(u16, pNewTerm, WhereTerm_eOperator, WO_GT);
                markTermAsChild(pWC, idxNew, idxTerm);
                pTerm = wcTermAt(pWC, idxTerm);
                wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_COPIED);
                wr(Bitmask, pNewTerm, WhereTerm_prereqAll, rd(Bitmask, pTerm, WhereTerm_prereqAll));
            }
        }
    }
    // LIKE/GLOB optimization
    else if (exprOp(pExpr) == TK_FUNCTION and
        wcOp(pWC) == TK_AND and
        isLikeOrGlob(pParse, pExpr, &pStr1, &isComplete, &noCase) != 0)
    {
        const wtFlags: u16 = TERM_LIKEOPT | TERM_VIRTUAL | TERM_DYNAMIC;
        const pLeft = elItemExpr(exprPList(pExpr), 1);
        const pStr2 = c.sqlite3ExprDup(db, pStr1, 0);

        if (noCase != 0 and !dbMallocFailed(db)) {
            wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_LIKE);
            const z1 = exprZToken(pStr1).?;
            const z2 = exprZToken(pStr2).?;
            var i: usize = 0;
            while (z1[i] != 0) : (i += 1) {
                const ch = z1[i];
                z1[i] = @intCast(c.sqlite3Toupper(ch));
                z2[i] = @intCast(c.sqlite3Tolower(ch));
            }
        }

        if (!dbMallocFailed(db)) {
            const z2 = exprZToken(pStr2).?;
            var pC: [*]u8 = z2 + @as(usize, @intCast(sqlite3Strlen30(z2) - 1));
            if (noCase != 0) {
                if (pC[0] == 'A' - 1) isComplete = 0;
                pC[0] = c.sqlite3UpperToLower[pC[0]];
            }
            while (pC[0] == 0xBF and @intFromPtr(pC) > @intFromPtr(z2)) {
                pC[0] = 0x80;
                pC -= 1;
            }
            pC[0] +%= 1;
        }
        const zCollSeqName: ?[*:0]const u8 = if (noCase != 0) "NOCASE" else @as([*:0]const u8, @ptrCast(&c.sqlite3StrBINARY));
        var pNewExpr1 = c.sqlite3ExprDup(db, pLeft, 0);
        pNewExpr1 = c.sqlite3PExpr(pParse, TK_GE, c.sqlite3ExprAddCollateString(pParse, pNewExpr1, zCollSeqName), pStr1);
        transferJoinMarkings(pNewExpr1, pExpr);
        const idxNew1 = whereClauseInsert(pWC, pNewExpr1, wtFlags);
        var pNewExpr2 = c.sqlite3ExprDup(db, pLeft, 0);
        pNewExpr2 = c.sqlite3PExpr(pParse, TK_LT, c.sqlite3ExprAddCollateString(pParse, pNewExpr2, zCollSeqName), pStr2);
        transferJoinMarkings(pNewExpr2, pExpr);
        const idxNew2 = whereClauseInsert(pWC, pNewExpr2, wtFlags);
        exprAnalyze(pSrc, pWC, idxNew1);
        exprAnalyze(pSrc, pWC, idxNew2);
        pTerm = wcTermAt(pWC, idxTerm);
        if (isComplete != 0) {
            markTermAsChild(pWC, idxNew1, idxTerm);
            markTermAsChild(pWC, idxNew2, idxTerm);
        }
    }

    // Vector == or IS -> component comparisons.
    if ((exprOp(pExpr) == TK_EQ or exprOp(pExpr) == TK_IS) and
        c.sqlite3ExprVectorSize(exprLeft(pExpr)) > 1)
    {
        const nLeft = c.sqlite3ExprVectorSize(exprLeft(pExpr));
        if (c.sqlite3ExprVectorSize(exprRight(pExpr)) == nLeft and
            ((exprFlags(exprLeft(pExpr)) & EP_xIsSelect) == 0 or
                (exprFlags(exprRight(pExpr)) & EP_xIsSelect) == 0) and
            wcOp(pWC) == TK_AND)
        {
            var i: c_int = 0;
            while (i < nLeft) : (i += 1) {
                const pL = c.sqlite3ExprForVectorField(pParse, exprLeft(pExpr), i, nLeft);
                const pR = c.sqlite3ExprForVectorField(pParse, exprRight(pExpr), i, nLeft);
                const pNew = c.sqlite3PExpr(pParse, exprOp(pExpr), pL, pR);
                transferJoinMarkings(pNew, pExpr);
                const idxNew = whereClauseInsert(pWC, pNew, TERM_DYNAMIC | TERM_SLICE);
                exprAnalyze(pSrc, pWC, idxNew);
            }
            pTerm = wcTermAt(pWC, idxTerm);
            wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_CODED | TERM_VIRTUAL);
            wr(u16, pTerm, WhereTerm_eOperator, WO_ROWVAL);
        }
    }
    // Vector IN -> per-component virtual terms.
    else if (exprOp(pExpr) == TK_IN and
        rd(c_int, pTerm, WhereTerm_u_x_iField) == 0 and
        exprOp(exprLeft(pExpr)) == TK_VECTOR and
        (rdp(exprPSelect(pExpr), Select_pPrior) == null or (rd(u32, exprPSelect(pExpr), Select_selFlags) & SF_Values) != 0) and
        rdp(exprPSelect(pExpr), Select_pWin) == null and
        wcOp(pWC) == TK_AND and
        elNExpr(rdp(exprPSelect(pExpr), Select_pEList)) <= 255 // UMXV(pTerm->nChild) (u8)
    ) {
        var i: c_int = 0;
        const nv = c.sqlite3ExprVectorSize(exprLeft(pExpr));
        while (i < nv) : (i += 1) {
            const idxNew = whereClauseInsert(pWC, pExpr, TERM_VIRTUAL | TERM_SLICE);
            wr(c_int, wcTermAt(pWC, idxNew), WhereTerm_u_x_iField, i + 1);
            exprAnalyze(pSrc, pWC, idxNew);
            markTermAsChild(pWC, idxNew, idxTerm);
        }
    }
    // WO_AUX auxiliary term for virtual tables.
    else if (wcOp(pWC) == TK_AND) {
        var pRight: Ptr = null;
        var pLeft: Ptr = null;
        var res = isAuxiliaryVtabOperator(db, pExpr, &eOp2, &pLeft, &pRight);
        while (res > 0) {
            res -= 1;
            const prereqExpr = sqlite3WhereExprUsage(pMaskSet, pRight);
            const prereqColumn = sqlite3WhereExprUsage(pMaskSet, pLeft);
            if ((prereqExpr & prereqColumn) == 0) {
                const pNewExpr = c.sqlite3PExpr(pParse, TK_MATCH, null, c.sqlite3ExprDup(db, pRight, 0));
                if (hasProp(pExpr, EP_OuterON) and pNewExpr != null) {
                    setProp(pNewExpr, EP_OuterON);
                    wr(c_int, pNewExpr, Expr_w_iJoin, rd(c_int, pExpr, Expr_w_iJoin));
                }
                const idxNew = whereClauseInsert(pWC, pNewExpr, TERM_VIRTUAL | TERM_DYNAMIC);
                const pNewTerm = wcTermAt(pWC, idxNew);
                wr(Bitmask, pNewTerm, WhereTerm_prereqRight, prereqExpr | extraRight);
                wr(c_int, pNewTerm, WhereTerm_leftCursor, exprITable(pLeft));
                wr(c_int, pNewTerm, WhereTerm_u_x_leftColumn, exprIColumn(pLeft));
                wr(u16, pNewTerm, WhereTerm_eOperator, WO_AUX);
                wr(u8, pNewTerm, WhereTerm_eMatchOp, eOp2);
                markTermAsChild(pWC, idxNew, idxTerm);
                pTerm = wcTermAt(pWC, idxTerm);
                wtSetWtFlags(pTerm, wtWtFlags(pTerm) | TERM_COPIED);
                wr(Bitmask, pNewTerm, WhereTerm_prereqAll, rd(Bitmask, pTerm, WhereTerm_prereqAll));
            }
            const tmp = pLeft;
            pLeft = pRight;
            pRight = tmp;
        }
    }

    pTerm = wcTermAt(pWC, idxTerm);
    wr(Bitmask, pTerm, WhereTerm_prereqRight, rd(Bitmask, pTerm, WhereTerm_prereqRight) | extraRight);
}

// ─── Public interface ───────────────────────────────────────────────────────

export fn sqlite3WhereSplit(pWC: Ptr, pExpr: Ptr, op: u8) void {
    const pE2 = c.sqlite3ExprSkipCollateAndLikely(pExpr);
    wr(u8, pWC, WhereClause_op, op);
    if (pE2 == null) return;
    if (exprOp(pE2) != op) {
        _ = whereClauseInsert(pWC, pExpr, 0);
    } else {
        sqlite3WhereSplit(pWC, exprLeft(pE2), op);
        sqlite3WhereSplit(pWC, exprRight(pE2), op);
    }
}

fn whereAddLimitExpr(pWC: Ptr, iReg: c_int, pExpr: Ptr, iCsr: c_int, eMatchOp: c_int) void {
    const pParse = rdp(wcWInfo(pWC), WhereInfo_pParse);
    const db = parseDb(pParse);
    var pNew: Ptr = undefined;
    var iVal: c_int = 0;

    if (c.sqlite3ExprIsInteger(pExpr, &iVal, pParse) != 0 and iVal >= 0) {
        const pVal = c.sqlite3ExprInt32(db, iVal);
        if (pVal == null) return;
        pNew = c.sqlite3PExpr(pParse, TK_MATCH, null, pVal);
    } else {
        const pVal = c.sqlite3ExprAlloc(db, TK_REGISTER, null, 0);
        if (pVal == null) return;
        wr(c_int, pVal, Expr_iTable, iReg);
        pNew = c.sqlite3PExpr(pParse, TK_MATCH, null, pVal);
    }
    if (pNew != null) {
        const idx = whereClauseInsert(pWC, pNew, TERM_DYNAMIC | TERM_VIRTUAL);
        const pTerm = wcTermAt(pWC, idx);
        wr(c_int, pTerm, WhereTerm_leftCursor, iCsr);
        wr(u16, pTerm, WhereTerm_eOperator, WO_AUX);
        wr(u8, pTerm, WhereTerm_eMatchOp, @intCast(eMatchOp));
    }
}

export fn sqlite3WhereAddLimit(pWC: Ptr, p: Ptr) void {
    if (rdp(p, Select_pGroupBy) == null and
        (rd(u32, p, Select_selFlags) & (SF_Distinct | SF_Aggregate)) == 0 and
        (slNSrc(rdp(p, Select_pSrc)) == 1 and isVirtual(rdp(slItem(rdp(p, Select_pSrc), 0), SrcItem_pSTab))))
    {
        const pSrc = rdp(p, Select_pSrc);
        const pOrderBy = rdp(p, Select_pOrderBy);
        const iCsr = rd(c_int, slItem(pSrc, 0), SrcItem_iCursor);

        var ii: c_int = 0;
        const nTerm = wcNTerm(pWC);
        while (ii < nTerm) : (ii += 1) {
            const t = wcTermAt(pWC, ii);
            if ((wtWtFlags(t) & TERM_CODED) != 0) {
                continue;
            }
            if (rd(u8, t, WhereTerm_nChild) != 0) {
                continue;
            }
            if (wtLeftCursor(t) == iCsr and rd(Bitmask, t, WhereTerm_prereqRight) == 0) continue;

            if (rd(c_int, t, WhereTerm_iParent) >= 0) {
                const pParent = wcTermAt(pWC, rd(c_int, t, WhereTerm_iParent));
                if (wtLeftCursor(pParent) == iCsr and
                    rd(Bitmask, pParent, WhereTerm_prereqRight) == 0 and
                    rd(u8, pParent, WhereTerm_nChild) == 1)
                {
                    continue;
                }
            }
            return;
        }

        if (pOrderBy != null) {
            var jj: c_int = 0;
            const nOB = elNExpr(pOrderBy);
            while (jj < nOB) : (jj += 1) {
                const pExpr = elItemExpr(pOrderBy, @intCast(jj));
                if (exprOp(pExpr) != TK_COLUMN) return;
                if (exprITable(pExpr) != iCsr) return;
                if ((rd(u8, elItem(pOrderBy, @intCast(jj)), ELItem_fg_sortFlags) & KEYINFO_ORDER_BIGNULL) != 0) return;
            }
        }

        const pLimit = rdp(p, Select_pLimit);
        const iOffset = rd(c_int, p, Select_iOffset);
        const selFlags = rd(u32, p, Select_selFlags);
        if (iOffset != 0 and (selFlags & SF_Compound) == 0) {
            whereAddLimitExpr(pWC, iOffset, exprRight(pLimit), iCsr, IC_OFFSET);
        }
        if (iOffset == 0 or (selFlags & SF_Compound) == 0) {
            whereAddLimitExpr(pWC, rd(c_int, p, Select_iLimit), exprLeft(pLimit), iCsr, IC_LIMIT);
        }
    }
}

export fn sqlite3WhereClauseInit(pWC: Ptr, pWInfo: Ptr) void {
    wr(?*anyopaque, pWC, WhereClause_pWInfo, pWInfo);
    wr(u8, pWC, WhereClause_hasOr, 0);
    wr(?*anyopaque, pWC, WhereClause_pOuter, null);
    wr(c_int, pWC, WhereClause_nTerm, 0);
    wr(c_int, pWC, WhereClause_nBase, 0);
    wr(c_int, pWC, WhereClause_nSlot, WHERECLAUSE_NSTATIC);
    wr(?*anyopaque, pWC, WhereClause_a, fieldPtr(pWC, WhereClause_aStatic));
}

export fn sqlite3WhereClauseClear(pWC: Ptr) void {
    const db = parseDb(rdp(wcWInfo(pWC), WhereInfo_pParse));
    const nTerm = wcNTerm(pWC);
    if (nTerm > 0) {
        var a = wcA(pWC);
        const aLast = wcTermAt(pWC, nTerm - 1);
        while (true) {
            const wtFlags = wtWtFlags(a);
            if ((wtFlags & TERM_DYNAMIC) != 0) {
                c.sqlite3ExprDelete(db, wtExpr(a));
            }
            if ((wtFlags & (TERM_ORINFO | TERM_ANDINFO)) != 0) {
                if ((wtFlags & TERM_ORINFO) != 0) {
                    whereOrInfoDelete(db, rdp(a, WhereTerm_u));
                } else {
                    whereAndInfoDelete(db, rdp(a, WhereTerm_u));
                }
            }
            if (a == aLast) break;
            a = fieldPtr(a, sizeof_WhereTerm);
        }
    }
}

fn whereExprUsageFull(pMaskSet: Ptr, p: Ptr) Bitmask {
    var mask: Bitmask = if (exprOp(p) == 179) // TK_IF_NULL_ROW
        c.sqlite3WhereGetMask(pMaskSet, exprITable(p)) else 0;
    if (exprLeft(p) != null) mask |= sqlite3WhereExprUsageNN(pMaskSet, exprLeft(p));
    if (exprRight(p) != null) {
        mask |= sqlite3WhereExprUsageNN(pMaskSet, exprRight(p));
    } else if (useXSelect(p)) {
        if (hasProp(p, EP_VarSelect)) wr(c_int, pMaskSet, WhereMaskSet_bVarSelect, 1);
        mask |= exprSelectUsage(pMaskSet, exprPSelect(p));
    } else if (exprPList(p) != null) {
        mask |= sqlite3WhereExprListUsage(pMaskSet, exprPList(p));
    }
    // Window functions
    if ((exprOp(p) == TK_FUNCTION or exprOp(p) == 169) and // TK_AGG_FUNCTION
        (exprFlags(p) & EP_WinFunc) != 0)
    {
        const pWin = exprYpTab(p); // y.pWin shares offset with y.pTab
        mask |= sqlite3WhereExprListUsage(pMaskSet, rdp(pWin, Window_pPartition));
        mask |= sqlite3WhereExprListUsage(pMaskSet, rdp(pWin, Window_pOrderBy));
        mask |= sqlite3WhereExprUsage(pMaskSet, rdp(pWin, Window_pFilter));
    }
    return mask;
}
const Window_pPartition = off("Window_pPartition", 16);
const Window_pOrderBy = off("Window_pOrderBy", 24);
const Window_pFilter = off("Window_pFilter", 72);

export fn sqlite3WhereExprUsageNN(pMaskSet: Ptr, p: Ptr) Bitmask {
    if (exprOp(p) == TK_COLUMN and !hasProp(p, EP_FixedCol)) {
        return c.sqlite3WhereGetMask(pMaskSet, exprITable(p));
    } else if (hasProp(p, EP_TokenOnly | EP_Leaf)) {
        return 0;
    }
    return whereExprUsageFull(pMaskSet, p);
}

export fn sqlite3WhereExprUsage(pMaskSet: Ptr, p: Ptr) Bitmask {
    return if (p != null) sqlite3WhereExprUsageNN(pMaskSet, p) else 0;
}

export fn sqlite3WhereExprListUsage(pMaskSet: Ptr, pList: Ptr) Bitmask {
    var mask: Bitmask = 0;
    if (pList != null) {
        var i: usize = 0;
        const n: usize = @intCast(elNExpr(pList));
        while (i < n) : (i += 1) {
            mask |= sqlite3WhereExprUsage(pMaskSet, elItemExpr(pList, i));
        }
    }
    return mask;
}

export fn sqlite3WhereExprAnalyze(pTabList: Ptr, pWC: Ptr) void {
    var i = wcNTerm(pWC) - 1;
    while (i >= 0) : (i -= 1) {
        exprAnalyze(pTabList, pWC, i);
    }
}

export fn sqlite3WhereTabFuncArgs(pParse: Ptr, pItem: Ptr, pWC: Ptr) void {
    const fg = rd(u32, pItem, SrcItem_fg);
    if ((fg & FG_isTabFunc) == 0) return;
    const pTab = rdp(pItem, SrcItem_pSTab);
    const pArgs = rdp(pItem, SrcItem_u1_pFuncArg);
    if (pArgs == null) return;
    const db = parseDb(pParse);
    var j: c_int = 0;
    var k: c_int = 0;
    const nArgs = elNExpr(pArgs);
    const nCol = rd(i16, pTab, Table_nCol);
    while (j < nArgs) : (j += 1) {
        const aCol = rdp(pTab, Table_aCol);
        while (k < nCol and (rd(u16, fieldPtr(aCol, @as(usize, @intCast(k)) * sizeof_Column), Column_colFlags) & COLFLAG_HIDDEN) == 0) {
            k += 1;
        }
        if (k >= nCol) {
            c.sqlite3ErrorMsg(pParse, "too many arguments on %s() - max %d", rd(?[*:0]const u8, pTab, Table_zName), j);
            return;
        }
        const pColRef = c.sqlite3ExprAlloc(db, TK_COLUMN, null, 0);
        if (pColRef == null) return;
        wr(c_int, pColRef, Expr_iTable, rd(c_int, pItem, SrcItem_iCursor));
        wr(c_int, pColRef, Expr_iColumn, k);
        k += 1;
        wr(?*anyopaque, pColRef, Expr_yTab, pTab);
        wr(Bitmask, pItem, SrcItem_colUsed, rd(Bitmask, pItem, SrcItem_colUsed) | c.sqlite3ExprColUsed(pColRef));
        const pRhs = c.sqlite3PExpr(pParse, TK_UPLUS, c.sqlite3ExprDup(db, elItemExpr(pArgs, @intCast(j)), 0), null);
        const pTerm = c.sqlite3PExpr(pParse, TK_EQ, pColRef, pRhs);
        const jointype = rd(u8, pItem, SrcItem_fg); // jointype is the low byte
        var joinType: u32 = undefined;
        if ((jointype & @as(u8, @intCast(JT_LEFT | JT_RIGHT))) != 0) {
            joinType = EP_OuterON;
        } else {
            joinType = EP_InnerON;
        }
        c.sqlite3SetJoinExpr(pTerm, rd(c_int, pItem, SrcItem_iCursor), joinType);
        _ = whereClauseInsert(pWC, pTerm, TERM_DYNAMIC);
    }
}

// ─── comptime layout asserts (catch a wrong mirror at compile time) ─────────
comptime {
    // memset start must be offsetof(WhereTerm, eOperator) in both configs.
    std.debug.assert(WT_MEMSET0_FROM == WhereTerm_eOperator);
}
