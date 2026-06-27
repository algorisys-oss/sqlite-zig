//! Zig port of SQLite's src/treeview.c — the AST / query-plan tree-printing
//! debug routines (sqlite3TreeView*).
//!
//! CONFIG-DIVERGENT MODULE.  The whole file in C is wrapped in
//! `#ifdef SQLITE_DEBUG`, so in the production library (no SQLITE_DEBUG) it
//! compiles to ZERO symbols, while in the --dev testfixture (SQLITE_DEBUG ON)
//! it provides the sqlite3TreeView* functions used by EXPLAIN / interactive
//! debugging.  We mirror that exactly: every public symbol is defined as a
//! plain (non-exported) Zig fn, and a single `comptime { if (config.sqlite_debug)
//! @export(...) }` block emits the C-ABI symbols ONLY in the debug config.  The
//! production object built from this file is therefore empty.
//!
//! Three routines (sqlite3TreeViewDelete/Insert/Update) are additionally
//! `#if TREETRACE_ENABLED`, which is `SQLITE_DEBUG && (SQLITE_TEST||...)`.  In
//! this project the testfixture sets sqlite_debug and sqlite_test together, so
//! they are gated on `config.sqlite_debug and config.sqlite_test`.
//!
//! Struct fields are read via ground-truth offsets (src/c_layout.zig) using the
//! same raw-memory helper idiom as expr.zig / select.zig.  treeview only READS
//! the AST; it never mutates it.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers (shared idiom) ──────────────────────────────────────
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, offs: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + offs);
    return q.*;
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
const VaList = std.builtin.VaList;

// ─── TreeView object (treeview.c-internal; opaque to all other TUs) ─────────
const TreeView = extern struct {
    iLevel: c_int, // 0
    bLine: [100]u8, // 4
};
comptime {
    std.debug.assert(@sizeOf(TreeView) == 104);
    std.debug.assert(@offsetOf(TreeView, "bLine") == 4);
}

// ─── StrAccum (sqlite3_str) — config-invariant, sizeof 32 ───────────────────
const StrAccum = extern struct {
    db: ?*anyopaque, // 0
    zText: ?[*]u8, // 8
    nAlloc: u32, // 16
    mxAlloc: u32, // 20
    nChar: u32, // 24
    accError: u8, // 28
    printfFlags: u8, // 29
};
comptime {
    std.debug.assert(@sizeOf(StrAccum) == 32);
    std.debug.assert(@offsetOf(StrAccum, "printfFlags") == 29);
}

// ─── externs (real C symbols) ───────────────────────────────────────────────
extern fn sqlite3_malloc64(n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, buf: [*]u8, fmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;

extern fn sqlite3StrAccumInit(p: *StrAccum, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) callconv(.c) void;
extern fn sqlite3StrAccumFinish(p: *StrAccum) callconv(.c) ?[*:0]u8;
extern fn sqlite3_str_append(p: *StrAccum, z: [*]const u8, n: c_int) callconv(.c) void;
extern fn sqlite3_str_appendf(p: *StrAccum, fmt: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3_str_vappendf(p: *StrAccum, fmt: [*:0]const u8, ap: *VaList) callconv(.c) void;
extern fn sqlite3_str_new(db: ?*anyopaque) callconv(.c) ?*StrAccum;
extern fn sqlite3_str_finish(p: ?*StrAccum) callconv(.c) ?[*:0]u8;

extern fn sqlite3ExprTruthValue(p: Ptr) callconv(.c) c_int;
extern fn sqlite3ExprSkipCollateAndLikely(p: Ptr) callconv(.c) Ptr;

extern var stdout: *anyopaque;
extern fn fprintf(stream: *anyopaque, fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn printf(fmt: [*:0]const u8, ...) callconv(.c) c_int;
extern fn fflush(stream: *anyopaque) callconv(.c) c_int;

extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) callconv(.c) ?*anyopaque;

// ─── offsets ────────────────────────────────────────────────────────────────
// Expr
const Expr_op = off("Expr_op", 0);
const Expr_affExpr = off("Expr_affExpr", 1);
const Expr_op2 = off("Expr_op2", 2);
const Expr_vvaFlags = off("Expr_vvaFlags", 3);
const Expr_flags = off("Expr_flags", 4);
const Expr_u = off("Expr_u", 8); // u.zToken / u.iValue
const Expr_pLeft = off("Expr_pLeft", 16);
const Expr_pRight = off("Expr_pRight", 24);
const Expr_x = off("Expr_x", 32); // x.pList / x.pSelect
const Expr_iTable = off("Expr_iTable", 44);
const Expr_iColumn = off("Expr_iColumn", 48); // ynVar (i16)
const Expr_iAgg = off("Expr_iAgg", 50); // i16
const Expr_w_iJoin = off("Expr_w_iJoin", 52);
const Expr_pAggInfo = off("Expr_pAggInfo", 56);
const Expr_y = off("Expr_y", 64); // y.pTab / y.pWin / y.sub.iAddr
const Expr_y_sub_iAddr = Expr_y;
const Expr_y_sub_regReturn = off("Expr_y_sub_regReturn", 68);

// ExprList
const ExprList_nExpr = off("ExprList_nExpr", 0);
const ExprList_a = off("ExprList_a", 8);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);
const EI_pExpr = off("ExprList_item_pExpr", 0);
const EI_zEName = off("ExprList_item_zEName", 8);
const EI_fg = off("ExprList_item_fg", 16); // byte 0 = sortFlags (u8)
const EI_u_x_iOrderByCol = off("ExprList_item_u_x_iOrderByCol", 20);

// Select
const Select_op = off("Select_op", 0);
const Select_selFlags = off("Select_selFlags", 4);
const Select_nSelectRow = off("Select_nSelectRow", 12);
const Select_pEList = off("Select_pEList", 16);
const Select_pSrc = off("Select_pSrc", 24);
const Select_pWhere = off("Select_pWhere", 32);
const Select_pGroupBy = off("Select_pGroupBy", 40);
const Select_pHaving = off("Select_pHaving", 48);
const Select_pOrderBy = off("Select_pOrderBy", 56);
const Select_pPrior = off("Select_pPrior", 64);
const Select_pLimit = off("Select_pLimit", 80);
const Select_pWith = off("Select_pWith", 88);
const Select_pWin = off("Select_pWin", 96);
const Select_pWinDefn = off("Select_pWinDefn", 104);
const Select_selId = off("Select_selId", 8);

// SrcList / SrcItem
const SrcList_nSrc = off("SrcList_nSrc", 0);
const SrcList_nAlloc = off("SrcList_nAlloc", 4);
const SrcList_a = off("SrcList_a", 8);
const sizeof_SrcItem = off("sizeof_SrcItem", 72);
const SI_pSTab = off("SrcItem_pSTab", 16);
const SI_fg = off("SrcItem_fg", 24); // byte 0 = jointype (u8)
const SI_iCursor = off("SrcItem_iCursor", 28);
const SI_colUsed = off("SrcItem_colUsed", 32);
const SI_u1_pFuncArg = off("SrcItem_u1_pFuncArg", 40);
const SI_u2_pCteUse = off("SrcItem_u2_pCteUse", 48);
const SI_u3_pOn = off("SrcItem_u3_pOn", 56); // u3.pOn / u3.pUsing
const SI_u4_pSubq = off("SrcItem_u4_pSubq", 64);

// Window
const Win_zName = off("Window_zName", 0);
const Win_zBase = off("Window_zBase", 8);
const Win_pPartition = off("Window_pPartition", 16);
const Win_pOrderBy = off("Window_pOrderBy", 24);
const Win_eFrmType = off("Window_eFrmType", 32);
const Win_eStart = off("Window_eStart", 33);
const Win_eEnd = off("Window_eEnd", 34);
const Win_bImplicitFrame = off("Window_bImplicitFrame", 35);
const Win_eExclude = off("Window_eExclude", 36);
const Win_pStart = off("Window_pStart", 40);
const Win_pEnd = off("Window_pEnd", 48);
const Win_pNextWin = off("Window_pNextWin", 64);
const Win_pFilter = off("Window_pFilter", 72);
const Win_pWFunc = off("Window_pWFunc", 80);

// With / Cte
const With_nCte = off("With_nCte", 0);
const With_pOuter = off("With_pOuter", 8);
const With_a = off("With_a", 16);
const sizeof_Cte = off("sizeof_Cte", 48);
const Cte_zName = off("Cte_zName", 0);
const Cte_pCols = off("Cte_pCols", 8);
const Cte_pSelect = off("Cte_pSelect", 16);
const Cte_pUse = off("Cte_pUse", 32);
const Cte_eM10d = off("Cte_eM10d", 40);
const CteUse_nUse = off("CteUse_nUse", 0);
const CteUse_eM10d = off("CteUse_eM10d", 4);

// Column / Table
const Table_zName = off("Table_zName", 0);
const Table_aCol = off("Table_aCol", 8);
const Table_nCol = off("Table_nCol", 54); // i16
const sizeof_Column = off("sizeof_Column", 16);
const Col_zCnName = off("Column_zCnName", 0);
const Col_notNull = off("Column_notNull", 8); // notNull:4 | eCType:4
const Col_colFlags = off("Column_colFlags", 14); // u16

// IdList
const IdList_nId = off("IdList_nId", 0);
const IdList_a = off("IdList_a", 8);
const sizeof_IdList_item = off("sizeof_IdList_item", 8);
const Id_zName = off("IdList_item_zName", 0);

// FuncDef
const FuncDef_nArg = off("FuncDef_nArg", 0); // i16
const FuncDef_zName = off("FuncDef_zName", 56);

// AggInfo
const AggInfo_selId = off("AggInfo_selId", 60);

// Subquery
const Subq_pSelect = off("Subquery_pSelect", 16);

// Upsert
const Upsert_pUpsertTarget = off("Upsert_pUpsertTarget", 0);
const Upsert_pUpsertSet = off("Upsert_pUpsertSet", 16);
const Upsert_pUpsertWhere = off("Upsert_pUpsertWhere", 24);
const Upsert_pNextUpsert = off("Upsert_pNextUpsert", 32);
const Upsert_isDoUpdate = off("Upsert_isDoUpdate", 40); // u8 (NEW — see report)

// Trigger / TriggerStep
const Trigger_zName = off("Trigger_zName", 0);
const Trigger_step_list = off("Trigger_step_list", 56);
const Trigger_pNext = off("Trigger_pNext", 64);
const TStep_zSpan = off("TriggerStep_zSpan", 64);
const TStep_pNext = off("TriggerStep_pNext", 72);

// ─── EP_* flags (Expr.flags, u32) ───────────────────────────────────────────
const EP_OuterON: u32 = 0x000001;
const EP_InnerON: u32 = 0x000002;
const EP_FixedCol: u32 = 0x000020;
const EP_IntValue: u32 = 0x000800;
const EP_xIsSelect: u32 = 0x001000;
const EP_TokenOnly: u32 = 0x010000;
const EP_WinFunc: u32 = 0x1000000;
const EP_Subrtn: u32 = 0x2000000;
const EP_Collate: u32 = 0x000200;
const EP_FromDDL: u32 = 0x40000000;

// vvaFlags (SQLITE_DEBUG only)
const EP_Immutable: u8 = 0x02;

// ─── Expr property macros (inline) ──────────────────────────────────────────
inline fn exprFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Expr_flags);
}
inline fn ExprHasProperty(p: ?*anyopaque, prop: u32) bool {
    return (exprFlags(p) & prop) != 0;
}
inline fn ExprHasVVAProperty(p: ?*anyopaque, prop: u8) bool {
    if (config.sqlite_debug) {
        return (rd(u8, p, Expr_vvaFlags) & prop) != 0;
    }
    return false;
}
inline fn ExprUseXList(p: ?*anyopaque) bool {
    return (exprFlags(p) & EP_xIsSelect) == 0;
}
inline fn ExprUseXSelect(p: ?*anyopaque) bool {
    return (exprFlags(p) & EP_xIsSelect) != 0;
}
inline fn IsWindowFunc(p: ?*anyopaque) bool {
    // ExprHasProperty(p, EP_WinFunc) && p->y.pWin->eFrmType != TK_FILTER
    if (!ExprHasProperty(p, EP_WinFunc)) return false;
    const pWin = rdp(p, Expr_y);
    return @as(c_int, rd(u8, pWin, Win_eFrmType)) != TK_FILTER;
}

// ─── TK_* token / opcode codes ──────────────────────────────────────────────
const TK_NOT: c_int = 19;
const TK_EXISTS: c_int = 20;
const TK_CAST: c_int = 36;
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
const TK_ID: c_int = 60;
const TK_NO: c_int = 67;
const TK_RAISE: c_int = 72;
const TK_ROW: c_int = 76;
const TK_TRIGGER: c_int = 78;
const TK_CURRENT: c_int = 86;
const TK_FOLLOWING: c_int = 87;
const TK_PRECEDING: c_int = 89;
const TK_RANGE: c_int = 90;
const TK_UNBOUNDED: c_int = 91;
const TK_GROUPS: c_int = 93;
const TK_TIES: c_int = 95;
const TK_BITAND: c_int = 103;
const TK_BITOR: c_int = 104;
const TK_LSHIFT: c_int = 105;
const TK_RSHIFT: c_int = 106;
const TK_PLUS: c_int = 107;
const TK_MINUS: c_int = 108;
const TK_STAR: c_int = 109;
const TK_SLASH: c_int = 110;
const TK_REM: c_int = 111;
const TK_CONCAT: c_int = 112;
const TK_COLLATE: c_int = 114;
const TK_BITNOT: c_int = 115;
const TK_STRING: c_int = 118;
const TK_NULL: c_int = 122;
const TK_ALL: c_int = 136;
const TK_EXCEPT: c_int = 137;
const TK_INTERSECT: c_int = 138;
const TK_SELECT: c_int = 139;
const TK_DOT: c_int = 142;
const TK_ORDER: c_int = 146;
const TK_GROUP: c_int = 147;
const TK_LIMIT: c_int = 149;
const TK_FLOAT: c_int = 154;
const TK_BLOB: c_int = 155;
const TK_INTEGER: c_int = 156;
const TK_VARIABLE: c_int = 157;
const TK_CASE: c_int = 158;
const TK_FILTER: c_int = 167;
const TK_COLUMN: c_int = 168;
const TK_AGG_FUNCTION: c_int = 169;
const TK_AGG_COLUMN: c_int = 170;
const TK_TRUEFALSE: c_int = 171;
const TK_FUNCTION: c_int = 172;
const TK_UPLUS: c_int = 173;
const TK_UMINUS: c_int = 174;
const TK_TRUTH: c_int = 175;
const TK_REGISTER: c_int = 176;
const TK_VECTOR: c_int = 177;
const TK_SELECT_COLUMN: c_int = 178;
const TK_IF_NULL_ROW: c_int = 179;
const TK_SPAN: c_int = 181;
const TK_ERROR: c_int = 182;

// ─── other constants ────────────────────────────────────────────────────────
const SF_Distinct: u32 = 0x0000001;
const SF_Aggregate: u32 = 0x0000008;
const SF_WhereBegin: u32 = 0x0080000;

const SQLITE_PRINTF_INTERNAL: u8 = 0x01;

const JT_CROSS: u8 = 0x02;
const JT_LEFT: u8 = 0x08;
const JT_RIGHT: u8 = 0x10;
const JT_LTORJ: u8 = 0x40;

const M10d_Yes: u8 = 0;
const M10d_Any: u8 = 1;
const M10d_No: u8 = 2;

const ENAME_NAME: u32 = 0;
const ENAME_SPAN: u32 = 1;
const ENAME_TAB: u32 = 2;

const NC_PartIdx: c_int = 0x000002;
const NC_IsCheck: c_int = 0x000004;
const NC_GenCol: c_int = 0x000008;
const NC_IdxExpr: c_int = 0x000020;

const OE_Rollback: c_int = 1;
const OE_Abort: c_int = 2;
const OE_Fail: c_int = 3;
const OE_Ignore: c_int = 4;
const OE_Replace: c_int = 5;

const KEYINFO_ORDER_DESC: u8 = 0x01;
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

const COLTYPE_CUSTOM: u4 = 0;
const COLTYPE_ANY: u4 = 1;
const COLTYPE_BLOB: u4 = 2;
const COLTYPE_INT: u4 = 3;
const COLTYPE_INTEGER: u4 = 4;
const COLTYPE_REAL: u4 = 5;
const COLTYPE_TEXT: u4 = 6;

const COLFLAG_PRIMKEY: u16 = 0x0001;
const COLFLAG_HIDDEN: u16 = 0x0002;
const COLFLAG_HASTYPE: u16 = 0x0004;

// ─── ExprList_item.fg bitfield accessors (byte EI_fg) ───────────────────────
//   byte 0: sortFlags (u8)
//   byte 1: eEName:2, done:1, reusable:1, bSorterRef:1, bNulls:1, bUsed:1,
//           bUsingTerm:1
//   byte 2: bNoExpand:1
inline fn ei_sortFlags(item: ?*anyopaque) u8 {
    return rd(u8, item, EI_fg);
}
inline fn ei_eEName(item: ?*anyopaque) u32 {
    return rd(u8, item, EI_fg + 1) & 0x03;
}
inline fn ei_bUsed(item: ?*anyopaque) bool {
    return (rd(u8, item, EI_fg + 1) & 0x40) != 0;
}
inline fn ei_bUsingTerm(item: ?*anyopaque) bool {
    return (rd(u8, item, EI_fg + 1) & 0x80) != 0;
}
inline fn ei_bNoExpand(item: ?*anyopaque) bool {
    return (rd(u8, item, EI_fg + 2) & 0x01) != 0;
}

// ─── SrcItem.fg bitfield accessors (byte SI_fg) ─────────────────────────────
//   byte 0: jointype (u8)
//   byte 1: notIndexed:1, isIndexedBy:1, isSubquery:1, isTabFunc:1,
//           isCorrelated:1, isMaterialized:1, viaCoroutine:1, isRecursive:1
//   byte 2: fromDDL:1, isCte:1, notCte:1, isUsing:1, isOn:1, isSynthUsing:1,
//           isNestedFrom:1, rowidUsed:1
//   byte 3: fixedSchema:1, hadSchema:1, fromExists:1
inline fn si_jointype(item: ?*anyopaque) u8 {
    return rd(u8, item, SI_fg);
}
inline fn si_b1(item: ?*anyopaque, mask: u8) bool {
    return (rd(u8, item, SI_fg + 1) & mask) != 0;
}
inline fn si_b2(item: ?*anyopaque, mask: u8) bool {
    return (rd(u8, item, SI_fg + 2) & mask) != 0;
}
inline fn si_b3(item: ?*anyopaque, mask: u8) bool {
    return (rd(u8, item, SI_fg + 3) & mask) != 0;
}
// byte 1 masks
const SIb1_isSubquery: u8 = 0x04;
const SIb1_isTabFunc: u8 = 0x08;
const SIb1_isCorrelated: u8 = 0x10;
const SIb1_isMaterialized: u8 = 0x20;
const SIb1_viaCoroutine: u8 = 0x40;
// byte 2 masks
const SIb2_fromDDL: u8 = 0x01;
const SIb2_isCte: u8 = 0x02;
const SIb2_notCte: u8 = 0x04;
const SIb2_isUsing: u8 = 0x08;
const SIb2_isOn: u8 = 0x10;
const SIb2_isNestedFrom: u8 = 0x40;
const SIb2_rowidUsed: u8 = 0x80;
// byte 3 masks
const SIb3_fixedSchema: u8 = 0x01;
const SIb3_hadSchema: u8 = 0x02;

// ─── tree-traversal core ────────────────────────────────────────────────────

/// Add a new subitem to the tree.  moreToFollow = not the last item.
fn treeViewPush(pp: *?*TreeView, moreToFollow: u8) void {
    var p = pp.*;
    if (p == null) {
        p = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(TreeView))));
        pp.* = p;
        if (p == null) return;
        _ = memset(p, 0, @sizeOf(TreeView));
    } else {
        p.?.iLevel += 1;
    }
    std.debug.assert(moreToFollow == 0 or moreToFollow == 1);
    const lvl = p.?.iLevel;
    if (lvl < @as(c_int, @intCast(p.?.bLine.len))) {
        p.?.bLine[@intCast(lvl)] = moreToFollow;
    }
}

/// Finished with one layer of the tree.
fn treeViewPop(pp: *?*TreeView) void {
    const p = pp.*;
    if (p == null) return;
    p.?.iLevel -= 1;
    if (p.?.iLevel < 0) {
        sqlite3_free(p);
        pp.* = null;
    }
}

/// Generate a single line of output for the tree, with the tree-line prefix.
fn sqlite3TreeViewLine(p: ?*TreeView, zFormat: ?[*:0]const u8, ...) callconv(.c) void {
    var acc: StrAccum = undefined;
    var zBuf: [1000]u8 = undefined;
    sqlite3StrAccumInit(&acc, null, &zBuf, zBuf.len, 0);
    if (p) |pv| {
        var i: c_int = 0;
        while (i < pv.iLevel and i < @as(c_int, @intCast(pv.bLine.len)) - 1) : (i += 1) {
            sqlite3_str_append(&acc, if (pv.bLine[@intCast(i)] != 0) "|   " else "    ", 4);
        }
        sqlite3_str_append(&acc, if (pv.bLine[@intCast(i)] != 0) "|-- " else "'-- ", 4);
    }
    if (zFormat) |fmt| {
        var ap = @cVaStart();
        sqlite3_str_vappendf(&acc, fmt, &ap);
        @cVaEnd(&ap);
        std.debug.assert(acc.nChar > 0 or acc.accError != 0);
        sqlite3_str_append(&acc, "\n", 1);
    }
    _ = sqlite3StrAccumFinish(&acc);
    _ = fprintf(stdout, "%s", @as([*:0]const u8, @ptrCast(&zBuf)));
    _ = fflush(stdout);
}

/// Shorthand for a new tree item that is a single label.
fn treeViewItem(p: ?*TreeView, zLabel: [*:0]const u8, moreFollows: u8) void {
    var pp: ?*TreeView = p;
    treeViewPush(&pp, moreFollows);
    sqlite3TreeViewLine(pp, "%s", zLabel);
}

// ─── Column list ────────────────────────────────────────────────────────────
fn sqlite3TreeViewColumnList(pView0: ?*TreeView, aCol: ?*anyopaque, nCol: c_int, moreToFollow: u8) callconv(.c) void {
    var pView = pView0;
    treeViewPush(&pView, moreToFollow);
    sqlite3TreeViewLine(pView, "COLUMNS");
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        const col = fieldPtr(aCol, @as(usize, @intCast(i)) * sizeof_Column);
        const flg = rd(u16, col, Col_colFlags);
        const eCType: u4 = @truncate(rd(u8, col, Col_notNull) >> 4);
        const colMoreToFollow: u8 = @intFromBool(i < (nCol - 1));
        treeViewPush(&pView, colMoreToFollow);
        sqlite3TreeViewLine(pView, null);
        const zCnName = rd(?[*:0]const u8, col, Col_zCnName);
        _ = printf(" %s", zCnName.?);
        switch (eCType) {
            COLTYPE_ANY => _ = printf(" ANY"),
            COLTYPE_BLOB => _ = printf(" BLOB"),
            COLTYPE_INT => _ = printf(" INT"),
            COLTYPE_INTEGER => _ = printf(" INTEGER"),
            COLTYPE_REAL => _ = printf(" REAL"),
            COLTYPE_TEXT => _ = printf(" TEXT"),
            COLTYPE_CUSTOM => {
                if ((flg & COLFLAG_HASTYPE) != 0) {
                    // type name follows column name (after its NUL)
                    var z = zCnName.?;
                    z += std.mem.len(z) + 1;
                    _ = printf(" X-%s", z);
                }
            },
            else => {},
        }
        if ((flg & COLFLAG_PRIMKEY) != 0) _ = printf(" PRIMARY KEY");
        if ((flg & COLFLAG_HIDDEN) != 0) _ = printf(" HIDDEN");
        // COLFLAG_NOEXPAND not defined in this build.
        if (flg != 0) _ = printf(" flags=%04x", @as(c_uint, flg));
        _ = printf("\n");
        _ = fflush(stdout);
        treeViewPop(&pView);
    }
    treeViewPop(&pView);
}

// ─── WITH clause ────────────────────────────────────────────────────────────
fn sqlite3TreeViewWith(pView0: ?*TreeView, pWith: ?*anyopaque, moreToFollow: u8) callconv(.c) void {
    var pView = pView0;
    if (pWith == null) return;
    const nCte = rd(c_int, pWith, With_nCte);
    if (nCte == 0) return;
    const pOuter = rdp(pWith, With_pOuter);
    if (pOuter != null) {
        sqlite3TreeViewLine(pView, "WITH (0x%p, pOuter=0x%p)", pWith, pOuter);
    } else {
        sqlite3TreeViewLine(pView, "WITH (0x%p)", pWith);
    }
    if (nCte > 0) {
        treeViewPush(&pView, moreToFollow);
        var i: c_int = 0;
        while (i < nCte) : (i += 1) {
            var x: StrAccum = undefined;
            var zLine: [1000]u8 = undefined;
            const pCte = fieldPtr(pWith, With_a + @as(usize, @intCast(i)) * sizeof_Cte);
            sqlite3StrAccumInit(&x, null, &zLine, zLine.len, 0);
            sqlite3_str_appendf(&x, "%s", rd(?[*:0]const u8, pCte, Cte_zName).?);
            const pCols = rdp(pCte, Cte_pCols);
            if (pCols != null and rd(c_int, pCols, ExprList_nExpr) > 0) {
                var cSep: u8 = '(';
                var j: c_int = 0;
                const ncol = rd(c_int, pCols, ExprList_nExpr);
                while (j < ncol) : (j += 1) {
                    const item = fieldPtr(pCols, ExprList_a + @as(usize, @intCast(j)) * sizeof_ExprList_item);
                    sqlite3_str_appendf(&x, "%c%s", @as(c_int, cSep), rd(?[*:0]const u8, item, EI_zEName).?);
                    cSep = ',';
                }
                sqlite3_str_appendf(&x, ")");
            }
            const eM10d = rd(u8, pCte, Cte_eM10d);
            if (eM10d != M10d_Any) {
                sqlite3_str_appendf(&x, " %sMATERIALIZED", @as([*:0]const u8, if (eM10d == M10d_No) "NOT " else ""));
            }
            const pUse = rdp(pCte, Cte_pUse);
            if (pUse != null) {
                sqlite3_str_appendf(&x, " (pUse=0x%p, nUse=%d)", pUse, rd(c_int, pUse, CteUse_nUse));
            }
            _ = sqlite3StrAccumFinish(&x);
            treeViewItem(pView, @ptrCast(&zLine), @intFromBool(i < nCte - 1));
            sqlite3TreeViewSelect(pView, rdp(pCte, Cte_pSelect), 0);
            treeViewPop(&pView);
        }
        treeViewPop(&pView);
    }
}

// ─── SrcList ────────────────────────────────────────────────────────────────
fn sqlite3TreeViewSrcList(pView0: ?*TreeView, pSrc: ?*anyopaque) callconv(.c) void {
    var pView = pView0;
    if (pSrc == null) return;
    const nSrc = rd(c_int, pSrc, SrcList_nSrc);
    var i: c_int = 0;
    while (i < nSrc) : (i += 1) {
        const pItem = fieldPtr(pSrc, SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem);
        var x: StrAccum = undefined;
        var n: c_int = 0;
        var zLine: [1000]u8 = undefined;
        sqlite3StrAccumInit(&x, null, &zLine, zLine.len, 0);
        x.printfFlags |= SQLITE_PRINTF_INTERNAL;
        sqlite3_str_appendf(&x, "{%d:*} %!S", rd(c_int, pItem, SI_iCursor), pItem);
        const pSTab = rdp(pItem, SI_pSTab);
        if (pSTab != null) {
            sqlite3_str_appendf(&x, " tab=%Q nCol=%d ptr=%p used=%llx%s", rd(?[*:0]const u8, pSTab, Table_zName), @as(c_int, rd(i16, pSTab, Table_nCol)), pSTab, rd(u64, pItem, SI_colUsed), @as([*:0]const u8, if (si_b2(pItem, SIb2_rowidUsed)) "+rowid" else ""));
        }
        const jt = si_jointype(pItem);
        if ((jt & (JT_LEFT | JT_RIGHT)) == (JT_LEFT | JT_RIGHT)) {
            sqlite3_str_appendf(&x, " FULL-OUTER-JOIN");
        } else if ((jt & JT_LEFT) != 0) {
            sqlite3_str_appendf(&x, " LEFT-JOIN");
        } else if ((jt & JT_RIGHT) != 0) {
            sqlite3_str_appendf(&x, " RIGHT-JOIN");
        } else if ((jt & JT_CROSS) != 0) {
            sqlite3_str_appendf(&x, " CROSS-JOIN");
        }
        if ((jt & JT_LTORJ) != 0) sqlite3_str_appendf(&x, " LTORJ");
        if (si_b2(pItem, SIb2_fromDDL)) sqlite3_str_appendf(&x, " DDL");
        if (si_b2(pItem, SIb2_isCte)) {
            const aMat = [_][*:0]const u8{ ",MAT", "", ",NO-MAT" };
            const pCteUse = rdp(pItem, SI_u2_pCteUse);
            sqlite3_str_appendf(&x, " CteUse=%d%s", rd(c_int, pCteUse, CteUse_nUse), aMat[rd(u8, pCteUse, CteUse_eM10d)]);
        }
        if (si_b2(pItem, SIb2_isOn) or (!si_b2(pItem, SIb2_isUsing) and rdp(pItem, SI_u3_pOn) != null)) {
            sqlite3_str_appendf(&x, " isOn");
        }
        if (si_b1(pItem, SIb1_isTabFunc)) sqlite3_str_appendf(&x, " isTabFunc");
        if (si_b1(pItem, SIb1_isCorrelated)) sqlite3_str_appendf(&x, " isCorrelated");
        if (si_b1(pItem, SIb1_isMaterialized)) sqlite3_str_appendf(&x, " isMaterialized");
        if (si_b1(pItem, SIb1_viaCoroutine)) sqlite3_str_appendf(&x, " viaCoroutine");
        if (si_b2(pItem, SIb2_notCte)) sqlite3_str_appendf(&x, " notCte");
        if (si_b2(pItem, SIb2_isNestedFrom)) sqlite3_str_appendf(&x, " isNestedFrom");
        if (si_b3(pItem, SIb3_fixedSchema)) sqlite3_str_appendf(&x, " fixedSchema");
        if (si_b3(pItem, SIb3_hadSchema)) sqlite3_str_appendf(&x, " hadSchema");
        if (si_b1(pItem, SIb1_isSubquery)) sqlite3_str_appendf(&x, " isSubquery");

        _ = sqlite3StrAccumFinish(&x);
        treeViewItem(pView, @ptrCast(&zLine), @intFromBool(i < nSrc - 1));
        n = 0;
        if (si_b1(pItem, SIb1_isSubquery)) n += 1;
        if (si_b1(pItem, SIb1_isTabFunc)) n += 1;
        if (si_b2(pItem, SIb2_isUsing) or rdp(pItem, SI_u3_pOn) != null) n += 1;
        if (si_b2(pItem, SIb2_isUsing)) {
            n -= 1;
            sqlite3TreeViewIdList(pView, rdp(pItem, SI_u3_pOn), @intFromBool(n > 0), "USING");
        } else if (rdp(pItem, SI_u3_pOn) != null) {
            n -= 1;
            treeViewItem(pView, "ON", @intFromBool(n > 0));
            sqlite3TreeViewExpr(pView, rdp(pItem, SI_u3_pOn), 0);
            treeViewPop(&pView);
        }
        if (si_b1(pItem, SIb1_isSubquery)) {
            std.debug.assert(n == 1);
            if (pSTab != null) {
                sqlite3TreeViewColumnList(pView, rdp(pSTab, Table_aCol), @as(c_int, rd(i16, pSTab, Table_nCol)), 1);
            }
            const pSubq = rdp(pItem, SI_u4_pSubq);
            sqlite3TreeViewSelect(pView, rdp(pSubq, Subq_pSelect), 0);
        }
        if (si_b1(pItem, SIb1_isTabFunc)) {
            sqlite3TreeViewExprList(pView, rdp(pItem, SI_u1_pFuncArg), 0, "func-args:");
        }
        treeViewPop(&pView);
    }
}

// ─── Select ─────────────────────────────────────────────────────────────────
fn sqlite3TreeViewSelect(pView0: ?*TreeView, p0: ?*anyopaque, moreToFollow: u8) callconv(.c) void {
    var pView = pView0;
    var p = p0;
    var n: c_int = 0;
    var cnt: c_int = 0;
    if (p == null) {
        sqlite3TreeViewLine(pView, "nil-SELECT");
        return;
    }
    treeViewPush(&pView, moreToFollow);
    const pWith = rdp(p, Select_pWith);
    if (pWith != null) {
        sqlite3TreeViewWith(pView, pWith, 1);
        cnt = 1;
        treeViewPush(&pView, 1);
    }
    while (true) {
        const selFlags = rd(u32, p, Select_selFlags);
        if ((selFlags & SF_WhereBegin) != 0) {
            sqlite3TreeViewLine(pView, "sqlite3WhereBegin()");
        } else {
            sqlite3TreeViewLine(pView, "SELECT%s%s (%u/%p) selFlags=0x%x nSelectRow=%d", @as([*:0]const u8, if ((selFlags & SF_Distinct) != 0) " DISTINCT" else ""), @as([*:0]const u8, if ((selFlags & SF_Aggregate) != 0) " agg_flag" else ""), rd(u32, p, Select_selId), p, selFlags, @as(c_int, @intFromFloat(rd(f64, p, Select_nSelectRow))));
        }
        if (cnt != 0) treeViewPop(&pView);
        cnt += 1;
        const pPrior = rdp(p, Select_pPrior);
        if (pPrior != null) {
            n = 1000;
        } else {
            n = 0;
            const pSrc = rdp(p, Select_pSrc);
            if (pSrc != null and rd(c_int, pSrc, SrcList_nSrc) != 0 and rd(c_int, pSrc, SrcList_nAlloc) != 0) n += 1;
            if (rdp(p, Select_pWhere) != null) n += 1;
            if (rdp(p, Select_pGroupBy) != null) n += 1;
            if (rdp(p, Select_pHaving) != null) n += 1;
            if (rdp(p, Select_pOrderBy) != null) n += 1;
            if (rdp(p, Select_pLimit) != null) n += 1;
            if (rdp(p, Select_pWin) != null) n += 1;
            if (rdp(p, Select_pWinDefn) != null) n += 1;
        }
        const pEList = rdp(p, Select_pEList);
        if (pEList != null) {
            sqlite3TreeViewExprList(pView, pEList, @intFromBool(n > 0), "result-set");
        }
        n -= 1;
        const pWin = rdp(p, Select_pWin);
        if (pWin != null) {
            treeViewPush(&pView, @intFromBool(n > 0));
            n -= 1;
            sqlite3TreeViewLine(pView, "window-functions");
            var pX = pWin;
            while (pX != null) : (pX = rdp(pX, Win_pNextWin)) {
                sqlite3TreeViewWinFunc(pView, pX, @intFromBool(rdp(pX, Win_pNextWin) != null));
            }
            treeViewPop(&pView);
        }
        const pSrc = rdp(p, Select_pSrc);
        if (pSrc != null and rd(c_int, pSrc, SrcList_nSrc) != 0 and rd(c_int, pSrc, SrcList_nAlloc) != 0) {
            treeViewPush(&pView, @intFromBool(n > 0));
            n -= 1;
            sqlite3TreeViewLine(pView, "FROM");
            sqlite3TreeViewSrcList(pView, pSrc);
            treeViewPop(&pView);
        }
        if (rdp(p, Select_pWhere) != null) {
            treeViewItem(pView, "WHERE", @intFromBool(n > 0));
            n -= 1;
            sqlite3TreeViewExpr(pView, rdp(p, Select_pWhere), 0);
            treeViewPop(&pView);
        }
        if (rdp(p, Select_pGroupBy) != null) {
            sqlite3TreeViewExprList(pView, rdp(p, Select_pGroupBy), @intFromBool(n > 0), "GROUPBY");
            n -= 1;
        }
        if (rdp(p, Select_pHaving) != null) {
            treeViewItem(pView, "HAVING", @intFromBool(n > 0));
            n -= 1;
            sqlite3TreeViewExpr(pView, rdp(p, Select_pHaving), 0);
            treeViewPop(&pView);
        }
        const pWinDefn = rdp(p, Select_pWinDefn);
        if (pWinDefn != null) {
            treeViewItem(pView, "WINDOW", @intFromBool(n > 0));
            n -= 1;
            var pX = pWinDefn;
            while (pX != null) : (pX = rdp(pX, Win_pNextWin)) {
                sqlite3TreeViewWindow(pView, pX, @intFromBool(rdp(pX, Win_pNextWin) != null));
            }
            treeViewPop(&pView);
        }
        if (rdp(p, Select_pOrderBy) != null) {
            sqlite3TreeViewExprList(pView, rdp(p, Select_pOrderBy), @intFromBool(n > 0), "ORDERBY");
            n -= 1;
        }
        const pLimit = rdp(p, Select_pLimit);
        if (pLimit != null) {
            treeViewItem(pView, "LIMIT", @intFromBool(n > 0));
            n -= 1;
            const pRight = rdp(pLimit, Expr_pRight);
            sqlite3TreeViewExpr(pView, rdp(pLimit, Expr_pLeft), @intFromBool(pRight != null));
            if (pRight != null) {
                treeViewItem(pView, "OFFSET", 0);
                sqlite3TreeViewExpr(pView, pRight, 0);
                treeViewPop(&pView);
            }
            treeViewPop(&pView);
        }
        if (pPrior != null) {
            var zOp: [*:0]const u8 = "UNION";
            switch (@as(c_int, rd(u8, p, Select_op))) {
                TK_ALL => zOp = "UNION ALL",
                TK_INTERSECT => zOp = "INTERSECT",
                TK_EXCEPT => zOp = "EXCEPT",
                else => {},
            }
            treeViewItem(pView, zOp, 1);
        }
        p = pPrior;
        if (p == null) break;
    }
    treeViewPop(&pView);
}

// ─── Window bound ───────────────────────────────────────────────────────────
fn treeViewBound(pView0: ?*TreeView, eBound: u8, pExpr: ?*anyopaque, moreToFollow: u8) void {
    var pView = pView0;
    switch (@as(c_int, eBound)) {
        TK_UNBOUNDED => {
            treeViewItem(pView, "UNBOUNDED", moreToFollow);
            treeViewPop(&pView);
        },
        TK_CURRENT => {
            treeViewItem(pView, "CURRENT", moreToFollow);
            treeViewPop(&pView);
        },
        TK_PRECEDING => {
            treeViewItem(pView, "PRECEDING", moreToFollow);
            sqlite3TreeViewExpr(pView, pExpr, 0);
            treeViewPop(&pView);
        },
        TK_FOLLOWING => {
            treeViewItem(pView, "FOLLOWING", moreToFollow);
            sqlite3TreeViewExpr(pView, pExpr, 0);
            treeViewPop(&pView);
        },
        else => {},
    }
}

// ─── Window ─────────────────────────────────────────────────────────────────
fn sqlite3TreeViewWindow(pView0: ?*TreeView, pWin: ?*anyopaque, more: u8) callconv(.c) void {
    var pView = pView0;
    var nElement: c_int = 0;
    if (pWin == null) return;
    const eFrmType: c_int = rd(u8, pWin, Win_eFrmType);
    const pFilter = rdp(pWin, Win_pFilter);
    if (pFilter != null) {
        treeViewItem(pView, "FILTER", 1);
        sqlite3TreeViewExpr(pView, pFilter, 0);
        treeViewPop(&pView);
        if (eFrmType == TK_FILTER) return;
    }
    treeViewPush(&pView, more);
    const zName = rd(?[*:0]const u8, pWin, Win_zName);
    if (zName != null) {
        sqlite3TreeViewLine(pView, "OVER %s (%p)", zName, pWin);
    } else {
        sqlite3TreeViewLine(pView, "OVER (%p)", pWin);
    }
    const zBase = rd(?[*:0]const u8, pWin, Win_zBase);
    const eExclude: c_int = rd(u8, pWin, Win_eExclude);
    if (zBase != null) nElement += 1;
    if (rdp(pWin, Win_pOrderBy) != null) nElement += 1;
    if (eFrmType != 0 and eFrmType != TK_FILTER) nElement += 1;
    if (eExclude != 0) nElement += 1;
    if (zBase != null) {
        nElement -= 1;
        treeViewPush(&pView, @intFromBool(nElement > 0));
        sqlite3TreeViewLine(pView, "window: %s", zBase);
        treeViewPop(&pView);
    }
    if (rdp(pWin, Win_pPartition) != null) {
        sqlite3TreeViewExprList(pView, rdp(pWin, Win_pPartition), @intFromBool(nElement > 0), "PARTITION-BY");
    }
    if (rdp(pWin, Win_pOrderBy) != null) {
        nElement -= 1;
        sqlite3TreeViewExprList(pView, rdp(pWin, Win_pOrderBy), @intFromBool(nElement > 0), "ORDER-BY");
    }
    if (eFrmType != 0 and eFrmType != TK_FILTER) {
        var zBuf: [30]u8 = undefined;
        var zFrmType: [*:0]const u8 = "ROWS";
        if (eFrmType == TK_RANGE) zFrmType = "RANGE";
        if (eFrmType == TK_GROUPS) zFrmType = "GROUPS";
        _ = sqlite3_snprintf(zBuf.len, &zBuf, "%s%s", zFrmType, @as([*:0]const u8, if (rd(u8, pWin, Win_bImplicitFrame) != 0) " (implied)" else ""));
        nElement -= 1;
        treeViewItem(pView, @ptrCast(&zBuf), @intFromBool(nElement > 0));
        treeViewBound(pView, rd(u8, pWin, Win_eStart), rdp(pWin, Win_pStart), 1);
        treeViewBound(pView, rd(u8, pWin, Win_eEnd), rdp(pWin, Win_pEnd), 0);
        treeViewPop(&pView);
    }
    if (eExclude != 0) {
        var zBuf: [30]u8 = undefined;
        var zExclude: [*:0]const u8 = undefined;
        switch (eExclude) {
            TK_NO => zExclude = "NO OTHERS",
            TK_CURRENT => zExclude = "CURRENT ROW",
            TK_GROUP => zExclude = "GROUP",
            TK_TIES => zExclude = "TIES",
            else => {
                _ = sqlite3_snprintf(zBuf.len, &zBuf, "invalid(%d)", @as(c_int, eExclude));
                zExclude = @ptrCast(&zBuf);
            },
        }
        treeViewPush(&pView, 0);
        sqlite3TreeViewLine(pView, "EXCLUDE %s", zExclude);
        treeViewPop(&pView);
    }
    treeViewPop(&pView);
}

// ─── Window function ────────────────────────────────────────────────────────
fn sqlite3TreeViewWinFunc(pView0: ?*TreeView, pWin: ?*anyopaque, more: u8) callconv(.c) void {
    var pView = pView0;
    if (pWin == null) return;
    treeViewPush(&pView, more);
    const pWFunc = rdp(pWin, Win_pWFunc);
    sqlite3TreeViewLine(pView, "WINFUNC %s(%d)", rd(?[*:0]const u8, pWFunc, FuncDef_zName).?, @as(c_int, rd(i16, pWFunc, FuncDef_nArg)));
    sqlite3TreeViewWindow(pView, pWin, 0);
    treeViewPop(&pView);
}

// ─── Expr ───────────────────────────────────────────────────────────────────
fn sqlite3TreeViewExpr(pView0: ?*TreeView, pExpr: ?*anyopaque, moreToFollow: u8) callconv(.c) void {
    var pView = pView0;
    var zBinOp: ?[*:0]const u8 = null;
    var zUniOp: ?[*:0]const u8 = null;
    var zFlgs: [200]u8 = undefined;
    treeViewPush(&pView, moreToFollow);
    if (pExpr == null) {
        sqlite3TreeViewLine(pView, "nil");
        treeViewPop(&pView);
        return;
    }
    const flags = exprFlags(pExpr);
    const affExpr = rd(u8, pExpr, Expr_affExpr);
    const vvaFlags: u8 = if (config.sqlite_debug) rd(u8, pExpr, Expr_vvaFlags) else 0;
    const pAggInfo = rdp(pExpr, Expr_pAggInfo);
    if (flags != 0 or affExpr != 0 or vvaFlags != 0 or pAggInfo != null) {
        var x: StrAccum = undefined;
        sqlite3StrAccumInit(&x, null, &zFlgs, zFlgs.len, 0);
        sqlite3_str_appendf(&x, " fg.af=%x.%c", flags, @as(c_int, if (affExpr != 0) affExpr else 'n'));
        if (ExprHasProperty(pExpr, EP_OuterON)) {
            sqlite3_str_appendf(&x, " outer.iJoin=%d", rd(c_int, pExpr, Expr_w_iJoin));
        }
        if (ExprHasProperty(pExpr, EP_InnerON)) {
            sqlite3_str_appendf(&x, " inner.iJoin=%d", rd(c_int, pExpr, Expr_w_iJoin));
        }
        if (ExprHasProperty(pExpr, EP_FromDDL)) {
            sqlite3_str_appendf(&x, " DDL");
        }
        if (ExprHasVVAProperty(pExpr, EP_Immutable)) {
            sqlite3_str_appendf(&x, " IMMUTABLE");
        }
        if (pAggInfo != null) {
            sqlite3_str_appendf(&x, " agg-column[%d]", @as(c_int, rd(i16, pExpr, Expr_iAgg)));
        }
        _ = sqlite3StrAccumFinish(&x);
    } else {
        zFlgs[0] = 0;
    }
    const zFlgsP: [*:0]const u8 = @ptrCast(&zFlgs);
    const op: c_int = rd(u8, pExpr, Expr_op);
    switch (op) {
        TK_AGG_COLUMN => {
            sqlite3TreeViewLine(pView, "AGG{%d:%d}%s", rd(c_int, pExpr, Expr_iTable), @as(c_int, rd(i16, pExpr, Expr_iColumn)), zFlgsP);
        },
        TK_COLUMN => {
            const iTable = rd(c_int, pExpr, Expr_iTable);
            if (iTable < 0) {
                var zOp2: [16]u8 = undefined;
                const op2 = rd(u8, pExpr, Expr_op2);
                if (op2 != 0) {
                    _ = sqlite3_snprintf(zOp2.len, &zOp2, " op2=0x%02x", @as(c_uint, op2));
                } else {
                    zOp2[0] = 0;
                }
                sqlite3TreeViewLine(pView, "COLUMN(%d)%s%s", @as(c_int, rd(i16, pExpr, Expr_iColumn)), zFlgsP, @as([*:0]const u8, @ptrCast(&zOp2)));
            } else {
                sqlite3TreeViewLine(pView, "{%d:%d} pTab=%p%s", iTable, @as(c_int, rd(i16, pExpr, Expr_iColumn)), rdp(pExpr, Expr_y), zFlgsP);
            }
            if (ExprHasProperty(pExpr, EP_FixedCol)) {
                sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 0);
            }
        },
        TK_INTEGER => {
            if ((flags & EP_IntValue) != 0) {
                sqlite3TreeViewLine(pView, "%d", rd(c_int, pExpr, Expr_u));
            } else {
                sqlite3TreeViewLine(pView, "%s", rd(?[*:0]const u8, pExpr, Expr_u).?);
            }
        },
        TK_FLOAT => {
            sqlite3TreeViewLine(pView, "%s", rd(?[*:0]const u8, pExpr, Expr_u).?);
        },
        TK_STRING => {
            sqlite3TreeViewLine(pView, "%Q", rd(?[*:0]const u8, pExpr, Expr_u));
        },
        TK_NULL => {
            sqlite3TreeViewLine(pView, "NULL");
        },
        TK_TRUEFALSE => {
            sqlite3TreeViewLine(pView, "%s%s", @as([*:0]const u8, if (sqlite3ExprTruthValue(pExpr) != 0) "TRUE" else "FALSE"), zFlgsP);
        },
        TK_BLOB => {
            sqlite3TreeViewLine(pView, "%s", rd(?[*:0]const u8, pExpr, Expr_u).?);
        },
        TK_VARIABLE => {
            sqlite3TreeViewLine(pView, "VARIABLE(%s,%d)", rd(?[*:0]const u8, pExpr, Expr_u).?, @as(c_int, rd(i16, pExpr, Expr_iColumn)));
        },
        TK_REGISTER => {
            sqlite3TreeViewLine(pView, "REGISTER(%d)", rd(c_int, pExpr, Expr_iTable));
        },
        TK_ID => {
            sqlite3TreeViewLine(pView, "ID \"%w\"", rd(?[*:0]const u8, pExpr, Expr_u).?);
        },
        TK_CAST => {
            sqlite3TreeViewLine(pView, "CAST %Q", rd(?[*:0]const u8, pExpr, Expr_u));
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 0);
        },
        TK_LT => zBinOp = "LT",
        TK_LE => zBinOp = "LE",
        TK_GT => zBinOp = "GT",
        TK_GE => zBinOp = "GE",
        TK_NE => zBinOp = "NE",
        TK_EQ => zBinOp = "EQ",
        TK_IS => zBinOp = "IS",
        TK_ISNOT => zBinOp = "ISNOT",
        TK_AND => zBinOp = "AND",
        TK_OR => zBinOp = "OR",
        TK_PLUS => zBinOp = "ADD",
        TK_STAR => zBinOp = "MUL",
        TK_MINUS => zBinOp = "SUB",
        TK_REM => zBinOp = "REM",
        TK_BITAND => zBinOp = "BITAND",
        TK_BITOR => zBinOp = "BITOR",
        TK_SLASH => zBinOp = "DIV",
        TK_LSHIFT => zBinOp = "LSHIFT",
        TK_RSHIFT => zBinOp = "RSHIFT",
        TK_CONCAT => zBinOp = "CONCAT",
        TK_DOT => zBinOp = "DOT",
        TK_LIMIT => zBinOp = "LIMIT",

        TK_UMINUS => zUniOp = "UMINUS",
        TK_UPLUS => zUniOp = "UPLUS",
        TK_BITNOT => zUniOp = "BITNOT",
        TK_NOT => zUniOp = "NOT",
        TK_ISNULL => zUniOp = "ISNULL",
        TK_NOTNULL => zUniOp = "NOTNULL",

        TK_TRUTH => {
            const azOp = [_][*:0]const u8{ "IS-FALSE", "IS-TRUE", "IS-NOT-FALSE", "IS-NOT-TRUE" };
            const op2 = rd(u8, pExpr, Expr_op2);
            const pRight = rdp(pExpr, Expr_pRight);
            const idx: usize = @as(usize, @intFromBool(op2 == TK_ISNOT)) * 2 + @as(usize, @intCast(sqlite3ExprTruthValue(sqlite3ExprSkipCollateAndLikely(pRight))));
            zUniOp = azOp[idx];
        },

        TK_SPAN => {
            sqlite3TreeViewLine(pView, "SPAN %Q", rd(?[*:0]const u8, pExpr, Expr_u));
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 0);
        },

        TK_COLLATE => {
            sqlite3TreeViewLine(pView, "%sCOLLATE %Q%s", @as([*:0]const u8, if (!ExprHasProperty(pExpr, EP_Collate)) "SOFT-" else ""), rd(?[*:0]const u8, pExpr, Expr_u), zFlgsP);
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 0);
        },

        TK_AGG_FUNCTION, TK_FUNCTION => {
            var pFarg: ?*anyopaque = null;
            var pWin: ?*anyopaque = null;
            if (ExprHasProperty(pExpr, EP_TokenOnly)) {
                pFarg = null;
                pWin = null;
            } else {
                pFarg = rdp(pExpr, Expr_x);
                pWin = if (IsWindowFunc(pExpr)) rdp(pExpr, Expr_y) else null;
            }
            const zToken = rd(?[*:0]const u8, pExpr, Expr_u);
            if (op == TK_AGG_FUNCTION) {
                const selId: u32 = if (pAggInfo != null) rd(u32, pAggInfo, AggInfo_selId) else 0;
                sqlite3TreeViewLine(pView, "AGG_FUNCTION%d %Q%s agg=%d[%d]/%p", @as(c_int, rd(u8, pExpr, Expr_op2)), zToken, zFlgsP, selId, @as(c_int, rd(i16, pExpr, Expr_iAgg)), pAggInfo);
            } else if (rd(u8, pExpr, Expr_op2) != 0) {
                const op2 = rd(u8, pExpr, Expr_op2);
                var zBuf: [8]u8 = undefined;
                _ = sqlite3_snprintf(zBuf.len, &zBuf, "0x%02x", @as(c_uint, op2));
                var zOp2: [*:0]const u8 = @ptrCast(&zBuf);
                if (op2 == NC_IsCheck) zOp2 = "NC_IsCheck";
                if (op2 == NC_IdxExpr) zOp2 = "NC_IdxExpr";
                if (op2 == NC_PartIdx) zOp2 = "NC_PartIdx";
                if (op2 == NC_GenCol) zOp2 = "NC_GenCol";
                sqlite3TreeViewLine(pView, "FUNCTION %Q%s op2=%s", zToken, zFlgsP, zOp2);
            } else {
                sqlite3TreeViewLine(pView, "FUNCTION %Q%s", zToken, zFlgsP);
            }
            if (pFarg != null) {
                const pLeft = rdp(pExpr, Expr_pLeft);
                sqlite3TreeViewExprList(pView, pFarg, @intFromBool(pWin != null or pLeft != null), null);
                if (pLeft != null) {
                    sqlite3TreeViewExprList(pView, rdp(pLeft, Expr_x), @intFromBool(pWin != null), "ORDERBY");
                }
            }
            if (pWin != null) {
                sqlite3TreeViewWindow(pView, pWin, 0);
            }
        },
        TK_ORDER => {
            sqlite3TreeViewExprList(pView, rdp(pExpr, Expr_x), 0, "ORDERBY");
        },
        TK_EXISTS => {
            sqlite3TreeViewLine(pView, "EXISTS-expr flags=0x%x", flags);
            sqlite3TreeViewSelect(pView, rdp(pExpr, Expr_x), 0);
        },
        TK_SELECT => {
            sqlite3TreeViewLine(pView, "subquery-expr flags=0x%x", flags);
            sqlite3TreeViewSelect(pView, rdp(pExpr, Expr_x), 0);
        },
        TK_IN => {
            const pStr = sqlite3_str_new(null);
            sqlite3_str_appendf(pStr.?, "IN flags=0x%x", flags);
            const iTable = rd(c_int, pExpr, Expr_iTable);
            if (iTable != 0) sqlite3_str_appendf(pStr.?, " iTable=%d", iTable);
            if (ExprHasProperty(pExpr, EP_Subrtn)) {
                sqlite3_str_appendf(pStr.?, " subrtn(%d,%d)", rd(c_int, pExpr, Expr_y_sub_regReturn), rd(c_int, pExpr, Expr_y_sub_iAddr));
            }
            const z = sqlite3_str_finish(pStr);
            sqlite3TreeViewLine(pView, z.?);
            sqlite3_free(z);
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 1);
            if (ExprUseXSelect(pExpr)) {
                sqlite3TreeViewSelect(pView, rdp(pExpr, Expr_x), 0);
            } else {
                sqlite3TreeViewExprList(pView, rdp(pExpr, Expr_x), 0, null);
            }
        },
        TK_BETWEEN => {
            const pList = rdp(pExpr, Expr_x);
            const pX = rdp(pExpr, Expr_pLeft);
            const a0 = fieldPtr(pList, ExprList_a);
            const a1 = fieldPtr(pList, ExprList_a + sizeof_ExprList_item);
            const pY = rdp(a0, EI_pExpr);
            const pZ = rdp(a1, EI_pExpr);
            sqlite3TreeViewLine(pView, "BETWEEN%s", zFlgsP);
            sqlite3TreeViewExpr(pView, pX, 1);
            sqlite3TreeViewExpr(pView, pY, 1);
            sqlite3TreeViewExpr(pView, pZ, 0);
        },
        TK_TRIGGER => {
            sqlite3TreeViewLine(pView, "%s(%d)", @as([*:0]const u8, if (rd(c_int, pExpr, Expr_iTable) != 0) "NEW" else "OLD"), @as(c_int, rd(i16, pExpr, Expr_iColumn)));
        },
        TK_CASE => {
            sqlite3TreeViewLine(pView, "CASE");
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 1);
            sqlite3TreeViewExprList(pView, rdp(pExpr, Expr_x), 0, null);
        },
        TK_RAISE => {
            var zType: [*:0]const u8 = "unk";
            switch (@as(c_int, affExpr)) {
                OE_Rollback => zType = "rollback",
                OE_Abort => zType = "abort",
                OE_Fail => zType = "fail",
                OE_Ignore => zType = "ignore",
                else => {},
            }
            sqlite3TreeViewLine(pView, "RAISE %s", zType);
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 0);
        },
        TK_MATCH => {
            sqlite3TreeViewLine(pView, "MATCH {%d:%d}%s", rd(c_int, pExpr, Expr_iTable), @as(c_int, rd(i16, pExpr, Expr_iColumn)), zFlgsP);
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pRight), 0);
        },
        TK_VECTOR => {
            const z = sqlite3_mprintf("VECTOR%s", zFlgsP);
            sqlite3TreeViewBareExprList(pView, rdp(pExpr, Expr_x), z);
            sqlite3_free(z);
        },
        TK_SELECT_COLUMN => {
            const pLeft = rdp(pExpr, Expr_pLeft);
            sqlite3TreeViewLine(pView, "SELECT-COLUMN %d of [0..%d]%s", @as(c_int, rd(i16, pExpr, Expr_iColumn)), rd(c_int, pExpr, Expr_iTable) - 1, @as([*:0]const u8, if (rdp(pExpr, Expr_pRight) == pLeft) " (SELECT-owner)" else ""));
            sqlite3TreeViewSelect(pView, rdp(pLeft, Expr_x), 0);
        },
        TK_IF_NULL_ROW => {
            sqlite3TreeViewLine(pView, "IF-NULL-ROW %d", rd(c_int, pExpr, Expr_iTable));
            sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 0);
        },
        TK_ERROR => {
            // tmp = *pExpr; tmp.op = pExpr->op2; recurse on tmp.
            var tmp: [sizeof_Expr_bytes]u8 = undefined;
            @memcpy(tmp[0..sizeof_Expr_bytes], @as([*]const u8, @ptrCast(pExpr.?))[0..sizeof_Expr_bytes]);
            tmp[Expr_op] = rd(u8, pExpr, Expr_op2);
            sqlite3TreeViewLine(pView, "ERROR");
            sqlite3TreeViewExpr(pView, @ptrCast(&tmp), 0);
        },
        TK_ROW => {
            const iColumn = rd(i16, pExpr, Expr_iColumn);
            if (iColumn <= 0) {
                sqlite3TreeViewLine(pView, "First FROM table rowid");
            } else {
                sqlite3TreeViewLine(pView, "First FROM table column %d", @as(c_int, iColumn) - 1);
            }
        },
        else => {
            sqlite3TreeViewLine(pView, "op=%d", @as(c_int, op));
        },
    }
    if (zBinOp) |z| {
        sqlite3TreeViewLine(pView, "%s%s", z, zFlgsP);
        sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 1);
        sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pRight), 0);
    } else if (zUniOp) |z| {
        sqlite3TreeViewLine(pView, "%s%s", z, zFlgsP);
        sqlite3TreeViewExpr(pView, rdp(pExpr, Expr_pLeft), 0);
    }
    treeViewPop(&pView);
}

const sizeof_Expr_bytes: usize = off("sizeof_Expr", 72);

// ─── ExprList ───────────────────────────────────────────────────────────────
fn sqlite3TreeViewBareExprList(pView0: ?*TreeView, pList: ?*anyopaque, zLabel0: ?[*:0]const u8) callconv(.c) void {
    var pView = pView0;
    var zLabel = zLabel0;
    if (zLabel == null or zLabel.?[0] == 0) zLabel = "LIST";
    if (pList == null) {
        sqlite3TreeViewLine(pView, "%s (empty)", zLabel.?);
    } else {
        const nExpr = rd(c_int, pList, ExprList_nExpr);
        var i: c_int = 0;
        sqlite3TreeViewLine(pView, "%s", zLabel.?);
        while (i < nExpr) : (i += 1) {
            const item = fieldPtr(pList, ExprList_a + @as(usize, @intCast(i)) * sizeof_ExprList_item);
            const j = rd(u16, item, EI_u_x_iOrderByCol);
            const sortFlags = ei_sortFlags(item);
            const zName = rd(?[*:0]const u8, item, EI_zEName);
            var moreToFollow: u8 = @intFromBool(i < nExpr - 1);
            if (j != 0 or zName != null or sortFlags != 0) {
                treeViewPush(&pView, moreToFollow);
                moreToFollow = 0;
                sqlite3TreeViewLine(pView, null);
                if (zName != null) {
                    switch (ei_eEName(item)) {
                        ENAME_TAB => {
                            _ = fprintf(stdout, "TABLE-ALIAS-NAME(\"%s\") ", zName.?);
                            if (ei_bUsed(item)) _ = fprintf(stdout, "(used) ");
                            if (ei_bUsingTerm(item)) _ = fprintf(stdout, "(USING-term) ");
                            if (ei_bNoExpand(item)) _ = fprintf(stdout, "(NoExpand) ");
                        },
                        ENAME_SPAN => {
                            _ = fprintf(stdout, "SPAN(\"%s\") ", zName.?);
                        },
                        else => {
                            _ = fprintf(stdout, "AS %s ", zName.?);
                        },
                    }
                }
                if (j != 0) {
                    _ = fprintf(stdout, "iOrderByCol=%d ", @as(c_int, j));
                }
                if ((sortFlags & KEYINFO_ORDER_DESC) != 0) {
                    _ = fprintf(stdout, "DESC ");
                } else if ((sortFlags & KEYINFO_ORDER_BIGNULL) != 0) {
                    _ = fprintf(stdout, "NULLS-LAST");
                }
                _ = fprintf(stdout, "\n");
                _ = fflush(stdout);
            }
            sqlite3TreeViewExpr(pView, rdp(item, EI_pExpr), moreToFollow);
            if (j != 0 or zName != null or sortFlags != 0) {
                treeViewPop(&pView);
            }
        }
    }
    _ = ENAME_NAME;
}

fn sqlite3TreeViewExprList(pView0: ?*TreeView, pList: ?*anyopaque, moreToFollow: u8, zLabel: ?[*:0]const u8) callconv(.c) void {
    var pView = pView0;
    treeViewPush(&pView, moreToFollow);
    sqlite3TreeViewBareExprList(pView, pList, zLabel);
    treeViewPop(&pView);
}

// ─── IdList ─────────────────────────────────────────────────────────────────
fn sqlite3TreeViewBareIdList(pView0: ?*TreeView, pList: ?*anyopaque, zLabel0: ?[*:0]const u8) callconv(.c) void {
    var pView = pView0;
    var zLabel = zLabel0;
    if (zLabel == null or zLabel.?[0] == 0) zLabel = "LIST";
    if (pList == null) {
        sqlite3TreeViewLine(pView, "%s (empty)", zLabel.?);
    } else {
        const nId = rd(c_int, pList, IdList_nId);
        var i: c_int = 0;
        sqlite3TreeViewLine(pView, "%s", zLabel.?);
        while (i < nId) : (i += 1) {
            const item = fieldPtr(pList, IdList_a + @as(usize, @intCast(i)) * sizeof_IdList_item);
            var zName = rd(?[*:0]const u8, item, Id_zName);
            const moreToFollow: u8 = @intFromBool(i < nId - 1);
            if (zName == null) zName = "(null)";
            treeViewPush(&pView, moreToFollow);
            sqlite3TreeViewLine(pView, null);
            _ = fprintf(stdout, "%s\n", zName.?);
            treeViewPop(&pView);
        }
    }
}

fn sqlite3TreeViewIdList(pView0: ?*TreeView, pList: ?*anyopaque, moreToFollow: u8, zLabel: ?[*:0]const u8) callconv(.c) void {
    var pView = pView0;
    treeViewPush(&pView, moreToFollow);
    sqlite3TreeViewBareIdList(pView, pList, zLabel);
    treeViewPop(&pView);
}

// ─── Upsert ─────────────────────────────────────────────────────────────────
fn sqlite3TreeViewUpsert(pView0: ?*TreeView, pUpsert0: ?*anyopaque, moreToFollow: u8) callconv(.c) void {
    var pView = pView0;
    var pUpsert = pUpsert0;
    if (pUpsert == null) return;
    treeViewPush(&pView, moreToFollow);
    while (pUpsert != null) {
        var n: c_int = 0;
        const pNext = rdp(pUpsert, Upsert_pNextUpsert);
        treeViewPush(&pView, @intFromBool(pNext != null or moreToFollow != 0));
        sqlite3TreeViewLine(pView, "ON CONFLICT DO %s", @as([*:0]const u8, if (rd(u8, pUpsert, Upsert_isDoUpdate) != 0) "UPDATE" else "NOTHING"));
        const pSet = rdp(pUpsert, Upsert_pUpsertSet);
        const pWhere = rdp(pUpsert, Upsert_pUpsertWhere);
        n = @as(c_int, @intFromBool(pSet != null)) + @as(c_int, @intFromBool(pWhere != null));
        sqlite3TreeViewExprList(pView, rdp(pUpsert, Upsert_pUpsertTarget), @intFromBool(n > 0), "TARGET");
        n -= 1;
        sqlite3TreeViewExprList(pView, pSet, @intFromBool(n > 0), "SET");
        n -= 1;
        if (pWhere != null) {
            treeViewItem(pView, "WHERE", @intFromBool(n > 0));
            n -= 1;
            sqlite3TreeViewExpr(pView, pWhere, 0);
            treeViewPop(&pView);
        }
        treeViewPop(&pView);
        pUpsert = pNext;
    }
    treeViewPop(&pView);
}

// ─── TREETRACE_ENABLED: Delete / Insert / Update ────────────────────────────
const treetrace_enabled = config.sqlite_debug and config.sqlite_test;

fn sqlite3TreeViewDelete(pWith: ?*anyopaque, pTabList: ?*anyopaque, pWhere: ?*anyopaque, pOrderBy: ?*anyopaque, pLimit: ?*anyopaque, pTrigger: ?*anyopaque) callconv(.c) void {
    var n: c_int = 0;
    var pView: ?*TreeView = null;
    treeViewPush(&pView, 0);
    sqlite3TreeViewLine(pView, "DELETE");
    if (pWith != null) n += 1;
    if (pTabList != null) n += 1;
    if (pWhere != null) n += 1;
    if (pOrderBy != null) n += 1;
    if (pLimit != null) n += 1;
    if (pTrigger != null) n += 1;
    if (pWith != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewWith(pView, pWith, 0);
        treeViewPop(&pView);
    }
    if (pTabList != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "FROM");
        sqlite3TreeViewSrcList(pView, pTabList);
        treeViewPop(&pView);
    }
    if (pWhere != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "WHERE");
        sqlite3TreeViewExpr(pView, pWhere, 0);
        treeViewPop(&pView);
    }
    if (pOrderBy != null) {
        n -= 1;
        sqlite3TreeViewExprList(pView, pOrderBy, @intFromBool(n > 0), "ORDER-BY");
    }
    if (pLimit != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "LIMIT");
        sqlite3TreeViewExpr(pView, pLimit, 0);
        treeViewPop(&pView);
    }
    if (pTrigger != null) {
        n -= 1;
        sqlite3TreeViewTrigger(pView, pTrigger, @intFromBool(n > 0), 1);
    }
    treeViewPop(&pView);
}

fn sqlite3TreeViewInsert(pWith: ?*anyopaque, pTabList: ?*anyopaque, pColumnList: ?*anyopaque, pSelect: ?*anyopaque, pExprList: ?*anyopaque, onError: c_int, pUpsert: ?*anyopaque, pTrigger: ?*anyopaque) callconv(.c) void {
    var pView: ?*TreeView = null;
    var n: c_int = 0;
    var zLabel: [*:0]const u8 = "INSERT";
    switch (onError) {
        OE_Replace => zLabel = "REPLACE",
        OE_Ignore => zLabel = "INSERT OR IGNORE",
        OE_Rollback => zLabel = "INSERT OR ROLLBACK",
        OE_Abort => zLabel = "INSERT OR ABORT",
        OE_Fail => zLabel = "INSERT OR FAIL",
        else => {},
    }
    treeViewPush(&pView, 0);
    sqlite3TreeViewLine(pView, zLabel);
    if (pWith != null) n += 1;
    if (pTabList != null) n += 1;
    if (pColumnList != null) n += 1;
    if (pSelect != null) n += 1;
    if (pExprList != null) n += 1;
    if (pUpsert != null) n += 1;
    if (pTrigger != null) n += 1;
    if (pWith != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewWith(pView, pWith, 0);
        treeViewPop(&pView);
    }
    if (pTabList != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "INTO");
        sqlite3TreeViewSrcList(pView, pTabList);
        treeViewPop(&pView);
    }
    if (pColumnList != null) {
        n -= 1;
        sqlite3TreeViewIdList(pView, pColumnList, @intFromBool(n > 0), "COLUMNS");
    }
    if (pSelect != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "DATA-SOURCE");
        sqlite3TreeViewSelect(pView, pSelect, 0);
        treeViewPop(&pView);
    }
    if (pExprList != null) {
        n -= 1;
        sqlite3TreeViewExprList(pView, pExprList, @intFromBool(n > 0), "VALUES");
    }
    if (pUpsert != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "UPSERT");
        sqlite3TreeViewUpsert(pView, pUpsert, 0);
        treeViewPop(&pView);
    }
    if (pTrigger != null) {
        n -= 1;
        sqlite3TreeViewTrigger(pView, pTrigger, @intFromBool(n > 0), 1);
    }
    treeViewPop(&pView);
}

fn sqlite3TreeViewUpdate(pWith: ?*anyopaque, pTabList: ?*anyopaque, pChanges: ?*anyopaque, pWhere: ?*anyopaque, onError: c_int, pOrderBy: ?*anyopaque, pLimit: ?*anyopaque, pUpsert: ?*anyopaque, pTrigger: ?*anyopaque) callconv(.c) void {
    var n: c_int = 0;
    var pView: ?*TreeView = null;
    var zLabel: [*:0]const u8 = "UPDATE";
    switch (onError) {
        OE_Replace => zLabel = "UPDATE OR REPLACE",
        OE_Ignore => zLabel = "UPDATE OR IGNORE",
        OE_Rollback => zLabel = "UPDATE OR ROLLBACK",
        OE_Abort => zLabel = "UPDATE OR ABORT",
        OE_Fail => zLabel = "UPDATE OR FAIL",
        else => {},
    }
    treeViewPush(&pView, 0);
    sqlite3TreeViewLine(pView, zLabel);
    if (pWith != null) n += 1;
    if (pTabList != null) n += 1;
    if (pChanges != null) n += 1;
    if (pWhere != null) n += 1;
    if (pOrderBy != null) n += 1;
    if (pLimit != null) n += 1;
    if (pUpsert != null) n += 1;
    if (pTrigger != null) n += 1;
    if (pWith != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewWith(pView, pWith, 0);
        treeViewPop(&pView);
    }
    if (pTabList != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "FROM");
        sqlite3TreeViewSrcList(pView, pTabList);
        treeViewPop(&pView);
    }
    if (pChanges != null) {
        n -= 1;
        sqlite3TreeViewExprList(pView, pChanges, @intFromBool(n > 0), "SET");
    }
    if (pWhere != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "WHERE");
        sqlite3TreeViewExpr(pView, pWhere, 0);
        treeViewPop(&pView);
    }
    if (pOrderBy != null) {
        n -= 1;
        sqlite3TreeViewExprList(pView, pOrderBy, @intFromBool(n > 0), "ORDER-BY");
    }
    if (pLimit != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "LIMIT");
        sqlite3TreeViewExpr(pView, pLimit, 0);
        treeViewPop(&pView);
    }
    if (pUpsert != null) {
        n -= 1;
        treeViewPush(&pView, @intFromBool(n > 0));
        sqlite3TreeViewLine(pView, "UPSERT");
        sqlite3TreeViewUpsert(pView, pUpsert, 0);
        treeViewPop(&pView);
    }
    if (pTrigger != null) {
        n -= 1;
        sqlite3TreeViewTrigger(pView, pTrigger, @intFromBool(n > 0), 1);
    }
    treeViewPop(&pView);
}

// ─── Trigger ────────────────────────────────────────────────────────────────
fn sqlite3TreeViewTriggerStep(pView0: ?*TreeView, pStep0: ?*anyopaque, moreToFollow: u8, showFullList: u8) callconv(.c) void {
    var pView = pView0;
    var pStep = pStep0;
    var cnt: c_int = 0;
    if (pStep == null) return;
    treeViewPush(&pView, @intFromBool(moreToFollow != 0 or (showFullList != 0 and rdp(pStep, TStep_pNext) != null)));
    while (true) {
        if (cnt != 0 and rdp(pStep, TStep_pNext) == null) {
            treeViewPop(&pView);
            treeViewPush(&pView, 0);
        }
        cnt += 1;
        const zSpan = rd(?[*:0]const u8, pStep, TStep_zSpan);
        sqlite3TreeViewLine(pView, "%s", @as([*:0]const u8, if (zSpan != null) zSpan.? else "RETURNING"));
        if (showFullList == 0) break;
        pStep = rdp(pStep, TStep_pNext);
        if (pStep == null) break;
    }
    treeViewPop(&pView);
}

fn sqlite3TreeViewTrigger(pView0: ?*TreeView, pTrigger0: ?*anyopaque, moreToFollow: u8, showFullList: u8) callconv(.c) void {
    var pView = pView0;
    var pTrigger = pTrigger0;
    var cnt: c_int = 0;
    if (pTrigger == null) return;
    treeViewPush(&pView, @intFromBool(moreToFollow != 0 or (showFullList != 0 and rdp(pTrigger, Trigger_pNext) != null)));
    while (true) {
        if (cnt != 0 and rdp(pTrigger, Trigger_pNext) == null) {
            treeViewPop(&pView);
            treeViewPush(&pView, 0);
        }
        cnt += 1;
        sqlite3TreeViewLine(pView, "TRIGGER %s", rd(?[*:0]const u8, pTrigger, Trigger_zName).?);
        treeViewPush(&pView, 0);
        sqlite3TreeViewTriggerStep(pView, rdp(pTrigger, Trigger_step_list), 0, 1);
        treeViewPop(&pView);
        if (showFullList == 0) break;
        pTrigger = rdp(pTrigger, Trigger_pNext);
        if (pTrigger == null) break;
    }
    treeViewPop(&pView);
}

// ─── gdb-friendly Show* wrappers ────────────────────────────────────────────
fn sqlite3ShowExpr(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewExpr(null, p, 0);
}
fn sqlite3ShowExprList(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewExprList(null, p, 0, null);
}
fn sqlite3ShowIdList(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewIdList(null, p, 0, null);
}
fn sqlite3ShowSrcList(p: ?*anyopaque) callconv(.c) void {
    var pView: ?*TreeView = null;
    treeViewPush(&pView, 0);
    sqlite3TreeViewLine(pView, "SRCLIST");
    sqlite3TreeViewSrcList(pView, p);
    treeViewPop(&pView);
}
fn sqlite3ShowSelect(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewSelect(null, p, 0);
}
fn sqlite3ShowWith(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewWith(null, p, 0);
}
fn sqlite3ShowUpsert(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewUpsert(null, p, 0);
}
fn sqlite3ShowTriggerStep(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewTriggerStep(null, p, 0, 0);
}
fn sqlite3ShowTriggerStepList(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewTriggerStep(null, p, 0, 1);
}
fn sqlite3ShowTrigger(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewTrigger(null, p, 0, 0);
}
fn sqlite3ShowTriggerList(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewTrigger(null, p, 0, 1);
}
fn sqlite3ShowWindow(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewWindow(null, p, 0);
}
fn sqlite3ShowWinFunc(p: ?*anyopaque) callconv(.c) void {
    sqlite3TreeViewWinFunc(null, p, 0);
}

// ─── exports (SQLITE_DEBUG only) ────────────────────────────────────────────
comptime {
    if (config.sqlite_debug) {
        @export(&sqlite3TreeViewLine, .{ .name = "sqlite3TreeViewLine" });
        @export(&sqlite3TreeViewColumnList, .{ .name = "sqlite3TreeViewColumnList" });
        @export(&sqlite3TreeViewWith, .{ .name = "sqlite3TreeViewWith" });
        @export(&sqlite3TreeViewSrcList, .{ .name = "sqlite3TreeViewSrcList" });
        @export(&sqlite3TreeViewSelect, .{ .name = "sqlite3TreeViewSelect" });
        @export(&sqlite3TreeViewWindow, .{ .name = "sqlite3TreeViewWindow" });
        @export(&sqlite3TreeViewWinFunc, .{ .name = "sqlite3TreeViewWinFunc" });
        @export(&sqlite3TreeViewExpr, .{ .name = "sqlite3TreeViewExpr" });
        @export(&sqlite3TreeViewBareExprList, .{ .name = "sqlite3TreeViewBareExprList" });
        @export(&sqlite3TreeViewExprList, .{ .name = "sqlite3TreeViewExprList" });
        @export(&sqlite3TreeViewBareIdList, .{ .name = "sqlite3TreeViewBareIdList" });
        @export(&sqlite3TreeViewIdList, .{ .name = "sqlite3TreeViewIdList" });
        @export(&sqlite3TreeViewUpsert, .{ .name = "sqlite3TreeViewUpsert" });
        @export(&sqlite3TreeViewTriggerStep, .{ .name = "sqlite3TreeViewTriggerStep" });
        @export(&sqlite3TreeViewTrigger, .{ .name = "sqlite3TreeViewTrigger" });

        @export(&sqlite3ShowExpr, .{ .name = "sqlite3ShowExpr" });
        @export(&sqlite3ShowExprList, .{ .name = "sqlite3ShowExprList" });
        @export(&sqlite3ShowIdList, .{ .name = "sqlite3ShowIdList" });
        @export(&sqlite3ShowSrcList, .{ .name = "sqlite3ShowSrcList" });
        @export(&sqlite3ShowSelect, .{ .name = "sqlite3ShowSelect" });
        @export(&sqlite3ShowWith, .{ .name = "sqlite3ShowWith" });
        @export(&sqlite3ShowUpsert, .{ .name = "sqlite3ShowUpsert" });
        @export(&sqlite3ShowTriggerStep, .{ .name = "sqlite3ShowTriggerStep" });
        @export(&sqlite3ShowTriggerStepList, .{ .name = "sqlite3ShowTriggerStepList" });
        @export(&sqlite3ShowTrigger, .{ .name = "sqlite3ShowTrigger" });
        @export(&sqlite3ShowTriggerList, .{ .name = "sqlite3ShowTriggerList" });
        @export(&sqlite3ShowWindow, .{ .name = "sqlite3ShowWindow" });
        @export(&sqlite3ShowWinFunc, .{ .name = "sqlite3ShowWinFunc" });
    }
    if (treetrace_enabled) {
        @export(&sqlite3TreeViewDelete, .{ .name = "sqlite3TreeViewDelete" });
        @export(&sqlite3TreeViewInsert, .{ .name = "sqlite3TreeViewInsert" });
        @export(&sqlite3TreeViewUpdate, .{ .name = "sqlite3TreeViewUpdate" });
    }
}
