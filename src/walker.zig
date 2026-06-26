//! Zig port of SQLite's src/walker.c — the generic Expr/Select parse-tree walker
//! used by name resolution, the optimizer and code generation.
//!
//! Exported (non-static) symbols — the complete external set of walker.c,
//! matching the prototypes in sqliteInt.h:
//!   - sqlite3WalkExprNN          sqlite3WalkExpr        sqlite3WalkExprList
//!   - sqlite3WalkSelectExpr      sqlite3WalkSelectFrom  sqlite3WalkSelect
//!   - sqlite3WalkWinDefnDummyCallback
//!   - sqlite3WalkerDepthIncrease sqlite3WalkerDepthDecrease
//!   - sqlite3ExprWalkNoop        sqlite3SelectWalkNoop
//! `walkWindowList` is `static` in C and stays private here.
//!
//! These functions are pure tree traversal: they invoke the Walker's
//! xExprCallback / xSelectCallback / xSelectCallback2 function pointers (read at
//! the Walker offsets attach.zig established) and recurse along Expr/Select/
//! ExprList/SrcList/Window field links. No memory allocation, no I/O.
//!
//! ─── Struct coupling / ground-truth offsets ────────────────────────────────
//! Every field offset below was probe-verified with offsetof in BOTH the
//! production library config and the `--dev` testfixture (SQLITE_DEBUG +
//! SQLITE_TEST) config. ALL probed offsets are IDENTICAL across the two configs.
//!
//!   Walker : pParse@0 xExprCallback@8 xSelectCallback@16 xSelectCallback2@24
//!            walkerDepth@32 (int)  u@40 (the .pParse here is the union member
//!            Walker.pParse used by the depth callbacks — same as Parse.pParse)
//!   Expr   : op@0 (u8) flags@4 (u32) u@8 pLeft@16 pRight@24 x@32 y@64
//!            x.pList / x.pSelect overlap at 32; y.pWin at 64.
//!   ExprList    : nExpr@0 (int) a@8 ;  ExprList_item: pExpr@0, sizeof 24
//!   Select : pEList@24 pSrc@32 pWhere@40 pGroupBy@48 pHaving@56 pOrderBy@64
//!            pPrior@72 pLimit@88 pWinDefn@112
//!   SrcList: nSrc@0 (int) a@8 ;  SrcItem: fg@24 u1@40 u4@64, sizeof 72
//!            fg.isSubquery = byte25 bit 0x04 ;  fg.isTabFunc = byte25 bit 0x08
//!            u1.pFuncArg (ExprList*) at 40 ; u4.pSubq (Subquery*) at 64
//!   Subquery: pSelect@0
//!   Window : pPartition@16 pOrderBy@24 pStart@40 pEnd@48 pNextWin@64 pFilter@72
//!   Parse  : eParseMode@300 (u8)
//!
//! ─── Config assumptions (true in both this project's builds) ────────────────
//!   * SQLITE_OMIT_WINDOWFUNC OFF → walkWindowList + the EP_WinFunc / pWinDefn
//!     window walks are compiled.
//!   * SQLITE_OMIT_ALTERTABLE OFF → IN_RENAME_OBJECT is
//!     (pParse->eParseMode >= PARSE_MODE_RENAME), i.e. eParseMode >= 2.
//!   * SQLITE_OMIT_CTE OFF → sqlite3SelectPopWith exists; its address is compared
//!     in sqlite3WalkSelectExpr.
//!   * Little-endian x86-64.
//!
//! Validated through the engine by the TCL suite — every query that resolves
//! names, optimizes, or codegens drives these walkers (select1, where, window1,
//! subquery, view, trigger, …). No standalone Zig unit test is feasible: every
//! path couples to the live Walker callbacks and the parser AST.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ─── WRC_* callback result codes (match exactly) ─────────────────────────────
const WRC_Continue: c_int = 0; // continue down into children
const WRC_Prune: c_int = 1; // omit children but continue siblings
const WRC_Abort: c_int = 2; // abandon the whole walk

// ─── Expr.flags (EP_*) bits used here ────────────────────────────────────────
const EP_xIsSelect: u32 = 0x001000; // x.pSelect valid (else x.pList)
const EP_TokenOnly: u32 = 0x010000; // truncated Expr — no fields past Expr.u
const EP_Leaf: u32 = 0x800000; // pLeft/pRight/x all NULL
const EP_WinFunc: u32 = 0x1000000; // TK_FUNCTION with y.pWin set

// PARSE_MODE_RENAME — IN_RENAME_OBJECT == (eParseMode >= 2).
const PARSE_MODE_RENAME: u8 = 2;

// ═══ ground-truth offsets ════════════════════════════════════════════════════
// Reuse c_layout entries where present, else the probe-verified fallback. All
// of these are identical in prod and tf.

// Walker
const Walker_pParse_off: usize = if (@hasDecl(L, "Walker_pParse")) L.Walker_pParse else 0;
const Walker_xExprCallback_off: usize = if (@hasDecl(L, "Walker_xExprCallback")) L.Walker_xExprCallback else 8;
const Walker_xSelectCallback_off: usize = if (@hasDecl(L, "Walker_xSelectCallback")) L.Walker_xSelectCallback else 16;
const Walker_xSelectCallback2_off: usize = if (@hasDecl(L, "Walker_xSelectCallback2")) L.Walker_xSelectCallback2 else 24;
const Walker_walkerDepth_off: usize = if (@hasDecl(L, "Walker_walkerDepth")) L.Walker_walkerDepth else 32;

// Parse
const Parse_eParseMode_off: usize = if (@hasDecl(L, "Parse_eParseMode")) L.Parse_eParseMode else 300;

// Expr
const Expr_op_off: usize = if (@hasDecl(L, "Expr_op")) L.Expr_op else 0;
const Expr_flags_off: usize = if (@hasDecl(L, "Expr_flags")) L.Expr_flags else 4;
const Expr_pLeft_off: usize = if (@hasDecl(L, "Expr_pLeft")) L.Expr_pLeft else 16;
const Expr_pRight_off: usize = if (@hasDecl(L, "Expr_pRight")) L.Expr_pRight else 24;
const Expr_x_off: usize = if (@hasDecl(L, "Expr_x")) L.Expr_x else 32; // x.pList / x.pSelect
const Expr_y_off: usize = if (@hasDecl(L, "Expr_y")) L.Expr_y else 64; // y.pWin (NEW)

// ExprList
const ExprList_nExpr_off: usize = if (@hasDecl(L, "ExprList_nExpr")) L.ExprList_nExpr else 0;
const ExprList_a_off: usize = if (@hasDecl(L, "ExprList_a")) L.ExprList_a else 8;
const sizeof_ExprList_item: usize = if (@hasDecl(L, "sizeof_ExprList_item")) L.sizeof_ExprList_item else 24;
const ExprList_item_pExpr_off: usize = if (@hasDecl(L, "ExprList_item_pExpr")) L.ExprList_item_pExpr else 0;

// Select
const Select_pEList_off: usize = if (@hasDecl(L, "Select_pEList")) L.Select_pEList else 24;
const Select_pSrc_off: usize = if (@hasDecl(L, "Select_pSrc")) L.Select_pSrc else 32;
const Select_pWhere_off: usize = if (@hasDecl(L, "Select_pWhere")) L.Select_pWhere else 40; // NEW
const Select_pGroupBy_off: usize = if (@hasDecl(L, "Select_pGroupBy")) L.Select_pGroupBy else 48; // NEW
const Select_pHaving_off: usize = if (@hasDecl(L, "Select_pHaving")) L.Select_pHaving else 56; // NEW
const Select_pOrderBy_off: usize = if (@hasDecl(L, "Select_pOrderBy")) L.Select_pOrderBy else 64; // NEW
const Select_pPrior_off: usize = if (@hasDecl(L, "Select_pPrior")) L.Select_pPrior else 72; // NEW
const Select_pLimit_off: usize = if (@hasDecl(L, "Select_pLimit")) L.Select_pLimit else 88; // NEW
const Select_pWinDefn_off: usize = if (@hasDecl(L, "Select_pWinDefn")) L.Select_pWinDefn else 112; // NEW

// SrcList / SrcItem
const SrcList_nSrc_off: usize = if (@hasDecl(L, "SrcList_nSrc")) L.SrcList_nSrc else 0;
const SrcList_a_off: usize = if (@hasDecl(L, "SrcList_a")) L.SrcList_a else 8;
const sizeof_SrcItem: usize = if (@hasDecl(L, "sizeof_SrcItem")) L.sizeof_SrcItem else 72;
const SrcItem_u1_off: usize = if (@hasDecl(L, "SrcItem_u1")) L.SrcItem_u1 else 40; // u1.pFuncArg (NEW)
const SrcItem_u4_off: usize = if (@hasDecl(L, "SrcItem_u4")) L.SrcItem_u4 else 64; // u4.pSubq
// fg bitfield byte/bit positions (relative to the SrcItem base).
const FG_isSubquery_byte: usize = 25;
const FG_isSubquery_bit: u8 = 0x04;
const FG_isTabFunc_byte: usize = 25;
const FG_isTabFunc_bit: u8 = 0x08;

// Subquery
const Subquery_pSelect_off: usize = if (@hasDecl(L, "Subquery_pSelect")) L.Subquery_pSelect else 0; // NEW

// Window
const Window_pPartition_off: usize = if (@hasDecl(L, "Window_pPartition")) L.Window_pPartition else 16; // NEW
const Window_pOrderBy_off: usize = if (@hasDecl(L, "Window_pOrderBy")) L.Window_pOrderBy else 24; // NEW
const Window_pStart_off: usize = if (@hasDecl(L, "Window_pStart")) L.Window_pStart else 40; // NEW
const Window_pEnd_off: usize = if (@hasDecl(L, "Window_pEnd")) L.Window_pEnd else 48; // NEW
const Window_pNextWin_off: usize = if (@hasDecl(L, "Window_pNextWin")) L.Window_pNextWin else 64; // NEW
const Window_pFilter_off: usize = if (@hasDecl(L, "Window_pFilter")) L.Window_pFilter else 72; // NEW

// ═══ raw memory helpers ══════════════════════════════════════════════════════
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rdPtr(comptime T: type, p: ?*anyopaque, off: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + off);
    return q.*;
}

// ─── Walker accessors ────────────────────────────────────────────────────────
// Callback signatures (C ABI). Result is WRC_* (int) for the expr/select forms;
// the depth callbacks and xSelectCallback2 vary, but for dispatch we only need
// the matching ABI shape.
const XExprCb = *const fn (?*anyopaque, ?*anyopaque) callconv(.c) c_int;
const XSelectCb = *const fn (?*anyopaque, ?*anyopaque) callconv(.c) c_int;
const XSelectCb2 = *const fn (?*anyopaque, ?*anyopaque) callconv(.c) void;

inline fn wXExpr(w: ?*anyopaque) XExprCb {
    return rdPtr(XExprCb, w, Walker_xExprCallback_off);
}
inline fn wXSelect(w: ?*anyopaque) ?XSelectCb {
    return rdPtr(?XSelectCb, w, Walker_xSelectCallback_off);
}
inline fn wXSelect2(w: ?*anyopaque) ?XSelectCb2 {
    return rdPtr(?XSelectCb2, w, Walker_xSelectCallback2_off);
}
inline fn wPParse(w: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, w, Walker_pParse_off);
}
inline fn wWalkerDepth(w: ?*anyopaque) c_int {
    return rdPtr(c_int, w, Walker_walkerDepth_off);
}
inline fn wSetWalkerDepth(w: ?*anyopaque, v: c_int) void {
    const q: *align(1) c_int = @ptrCast(base(w) + Walker_walkerDepth_off);
    q.* = v;
}

// ─── Expr accessors ──────────────────────────────────────────────────────────
inline fn exprFlags(p: ?*anyopaque) u32 {
    return rdPtr(u32, p, Expr_flags_off);
}
inline fn exprHasProperty(p: ?*anyopaque, prop: u32) bool {
    return (exprFlags(p) & prop) != 0;
}
inline fn exprPLeft(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Expr_pLeft_off);
}
inline fn exprPRight(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Expr_pRight_off);
}
inline fn exprXList(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Expr_x_off); // x.pList
}
inline fn exprXSelect(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Expr_x_off); // x.pSelect (overlaps x.pList)
}
inline fn exprYWin(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Expr_y_off); // y.pWin
}

// ─── Select accessors ────────────────────────────────────────────────────────
inline fn selField(p: ?*anyopaque, off: usize) ?*anyopaque {
    return rdPtr(?*anyopaque, p, off);
}

// ─── Window accessors ────────────────────────────────────────────────────────
inline fn winField(p: ?*anyopaque, off: usize) ?*anyopaque {
    return rdPtr(?*anyopaque, p, off);
}

// ═══ walkWindowList (static) ═════════════════════════════════════════════════
// Walk all expressions linked into the list of Window objects. bOneOnly stops
// after the first window (used for an EP_WinFunc node's single attached window).
fn walkWindowList(pWalker: ?*anyopaque, pList: ?*anyopaque, bOneOnly: c_int) c_int {
    var pWin = pList;
    while (pWin) |win| {
        if (sqlite3WalkExprList(pWalker, winField(win, Window_pOrderBy_off)) != 0) return WRC_Abort;
        if (sqlite3WalkExprList(pWalker, winField(win, Window_pPartition_off)) != 0) return WRC_Abort;
        if (sqlite3WalkExpr(pWalker, winField(win, Window_pFilter_off)) != 0) return WRC_Abort;
        if (sqlite3WalkExpr(pWalker, winField(win, Window_pStart_off)) != 0) return WRC_Abort;
        if (sqlite3WalkExpr(pWalker, winField(win, Window_pEnd_off)) != 0) return WRC_Abort;
        if (bOneOnly != 0) break;
        pWin = winField(win, Window_pNextWin_off);
    }
    return WRC_Continue;
}

// ═══ sqlite3WalkExprNN ═══════════════════════════════════════════════════════
// Walk an expression tree. Callback invoked pre-order (before children).
// SQLITE_NOINLINE in C — Zig has no direct equivalent; behavior is identical.
export fn sqlite3WalkExprNN(pWalker: ?*anyopaque, pExprIn: ?*anyopaque) callconv(.c) c_int {
    var pExpr = pExprIn;
    while (true) {
        const rc = wXExpr(pWalker)(pWalker, pExpr);
        if (rc != 0) return rc & WRC_Abort;
        if (!exprHasProperty(pExpr, EP_TokenOnly | EP_Leaf)) {
            // assert( x.pList==0 || pRight==0 )
            if (exprPLeft(pExpr)) |left| {
                if (sqlite3WalkExprNN(pWalker, left) != 0) return WRC_Abort;
            }
            if (exprPRight(pExpr)) |right| {
                // assert( !EP_WinFunc )
                pExpr = right;
                continue;
            } else if (exprHasProperty(pExpr, EP_xIsSelect)) {
                // assert( !EP_WinFunc )
                if (sqlite3WalkSelect(pWalker, exprXSelect(pExpr)) != 0) return WRC_Abort;
            } else {
                if (exprXList(pExpr)) |list| {
                    if (sqlite3WalkExprList(pWalker, list) != 0) return WRC_Abort;
                }
                if (exprHasProperty(pExpr, EP_WinFunc)) {
                    if (walkWindowList(pWalker, exprYWin(pExpr), 1) != 0) return WRC_Abort;
                }
            }
        }
        break;
    }
    return WRC_Continue;
}

// ═══ sqlite3WalkExpr ═════════════════════════════════════════════════════════
export fn sqlite3WalkExpr(pWalker: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    return if (pExpr != null) sqlite3WalkExprNN(pWalker, pExpr) else WRC_Continue;
}

// ═══ sqlite3WalkExprList ═════════════════════════════════════════════════════
export fn sqlite3WalkExprList(pWalker: ?*anyopaque, p: ?*anyopaque) callconv(.c) c_int {
    if (p) |list| {
        const n = rdPtr(c_int, list, ExprList_nExpr_off);
        const a: [*]u8 = @ptrCast(base(list) + ExprList_a_off);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            const pItem: ?*anyopaque = @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_ExprList_item));
            const pExpr = rdPtr(?*anyopaque, pItem, ExprList_item_pExpr_off);
            if (sqlite3WalkExpr(pWalker, pExpr) != 0) return WRC_Abort;
        }
    }
    return WRC_Continue;
}

// ═══ sqlite3WalkWinDefnDummyCallback ═════════════════════════════════════════
// No-op xSelectCallback2 whose *address* is tested in sqlite3WalkSelectExpr to
// decide whether to traverse Select.pWinDefn.
export fn sqlite3WalkWinDefnDummyCallback(pWalker: ?*anyopaque, p: ?*anyopaque) callconv(.c) void {
    _ = pWalker;
    _ = p;
}

// ═══ sqlite3WalkSelectExpr ═══════════════════════════════════════════════════
// Walk every expression of SELECT p (but not the SELECT callback on p itself).
export fn sqlite3WalkSelectExpr(pWalker: ?*anyopaque, p: ?*anyopaque) callconv(.c) c_int {
    if (sqlite3WalkExprList(pWalker, selField(p, Select_pEList_off)) != 0) return WRC_Abort;
    if (sqlite3WalkExpr(pWalker, selField(p, Select_pWhere_off)) != 0) return WRC_Abort;
    if (sqlite3WalkExprList(pWalker, selField(p, Select_pGroupBy_off)) != 0) return WRC_Abort;
    if (sqlite3WalkExpr(pWalker, selField(p, Select_pHaving_off)) != 0) return WRC_Abort;
    if (sqlite3WalkExprList(pWalker, selField(p, Select_pOrderBy_off)) != 0) return WRC_Abort;
    if (sqlite3WalkExpr(pWalker, selField(p, Select_pLimit_off)) != 0) return WRC_Abort;

    const pWinDefn = selField(p, Select_pWinDefn_off);
    if (pWinDefn != null) {
        const cb2 = wXSelect2(pWalker);
        // Compare the xSelectCallback2 function-pointer address against the two
        // dummy/real callbacks, OR check IN_RENAME_OBJECT (eParseMode >= RENAME).
        var doWalk = false;
        if (cb2) |fp| {
            if (@intFromPtr(fp) == @intFromPtr(&sqlite3WalkWinDefnDummyCallback)) doWalk = true;
            if (@intFromPtr(fp) == @intFromPtr(&sqlite3SelectPopWith)) doWalk = true;
        }
        if (!doWalk) {
            const pParse = wPParse(pWalker);
            if (pParse != null and inRenameObject(pParse)) doWalk = true;
        }
        if (doWalk) {
            // May return WRC_Abort if there are unresolvable symbols in a window
            // definition.
            return walkWindowList(pWalker, pWinDefn, 0);
        }
    }
    return WRC_Continue;
}

inline fn inRenameObject(pParse: ?*anyopaque) bool {
    const eParseMode = base(pParse)[Parse_eParseMode_off];
    return eParseMode >= PARSE_MODE_RENAME;
}

// ═══ sqlite3WalkSelectFrom ═══════════════════════════════════════════════════
// Walk the parse trees of all subqueries in the FROM clause of SELECT p.
export fn sqlite3WalkSelectFrom(pWalker: ?*anyopaque, p: ?*anyopaque) callconv(.c) c_int {
    const pSrc = selField(p, Select_pSrc_off);
    // ALWAYS(pSrc) — pSrc is never NULL for a real select.
    if (pSrc != null) {
        const n = rdPtr(c_int, pSrc, SrcList_nSrc_off);
        const a: [*]u8 = @ptrCast(base(pSrc) + SrcList_a_off);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            const pItem: ?*anyopaque = @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_SrcItem));
            if (fgBit(pItem, FG_isSubquery_byte, FG_isSubquery_bit)) {
                // u4.pSubq->pSelect
                const pSubq = rdPtr(?*anyopaque, pItem, SrcItem_u4_off);
                const pSubSelect = rdPtr(?*anyopaque, pSubq, Subquery_pSelect_off);
                if (sqlite3WalkSelect(pWalker, pSubSelect) != 0) return WRC_Abort;
            }
            if (fgBit(pItem, FG_isTabFunc_byte, FG_isTabFunc_bit)) {
                // u1.pFuncArg
                const pFuncArg = rdPtr(?*anyopaque, pItem, SrcItem_u1_off);
                if (sqlite3WalkExprList(pWalker, pFuncArg) != 0) return WRC_Abort;
            }
        }
    }
    return WRC_Continue;
}

inline fn fgBit(pItem: ?*anyopaque, byte: usize, bit: u8) bool {
    return (base(pItem)[byte] & bit) != 0;
}

// ═══ sqlite3WalkSelect ═══════════════════════════════════════════════════════
// Walk every expression of SELECT p, recurse into FROM-clause subqueries and the
// compound-select chain p->pPrior. Invokes xSelectCallback pre-order and
// xSelectCallback2 post-order (when both are set and the body returns Continue).
export fn sqlite3WalkSelect(pWalker: ?*anyopaque, pIn: ?*anyopaque) callconv(.c) c_int {
    var p = pIn;
    if (p == null) return WRC_Continue;
    const xSelect = wXSelect(pWalker);
    if (xSelect == null) return WRC_Continue;
    while (true) {
        const rc = xSelect.?(pWalker, p);
        if (rc != 0) return rc & WRC_Abort;
        if (sqlite3WalkSelectExpr(pWalker, p) != 0 or
            sqlite3WalkSelectFrom(pWalker, p) != 0)
        {
            return WRC_Abort;
        }
        if (wXSelect2(pWalker)) |cb2| {
            cb2(pWalker, p);
        }
        p = selField(p, Select_pPrior_off);
        if (p == null) break;
    }
    return WRC_Continue;
}

// ═══ sqlite3WalkerDepthIncrease / Decrease ═══════════════════════════════════
// Track subquery nesting depth — used as xSelectCallback / xSelectCallback2.
export fn sqlite3WalkerDepthIncrease(pWalker: ?*anyopaque, pSelect: ?*anyopaque) callconv(.c) c_int {
    _ = pSelect;
    wSetWalkerDepth(pWalker, wWalkerDepth(pWalker) + 1);
    return WRC_Continue;
}
export fn sqlite3WalkerDepthDecrease(pWalker: ?*anyopaque, pSelect: ?*anyopaque) callconv(.c) void {
    _ = pSelect;
    wSetWalkerDepth(pWalker, wWalkerDepth(pWalker) - 1);
}

// ═══ no-op callbacks ═════════════════════════════════════════════════════════
export fn sqlite3ExprWalkNoop(notUsed: ?*anyopaque, notUsed2: ?*anyopaque) callconv(.c) c_int {
    _ = notUsed;
    _ = notUsed2;
    return WRC_Continue;
}
export fn sqlite3SelectWalkNoop(notUsed: ?*anyopaque, notUsed2: ?*anyopaque) callconv(.c) c_int {
    _ = notUsed;
    _ = notUsed2;
    return WRC_Continue;
}

// sqlite3SelectPopWith — defined in select.c (CTE handling). Referenced only by
// address in sqlite3WalkSelectExpr. Declared extern so we can compare pointers.
extern fn sqlite3SelectPopWith(pWalker: ?*anyopaque, p: ?*anyopaque) callconv(.c) void;
