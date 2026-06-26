//! Zig port of SQLite's src/window.c — window-function support: the 11 built-in
//! window functions (row_number/rank/dense_rank/percent_rank/cume_dist/ntile/
//! lead/lag/first_value/last_value/nth_value) plus the OVER-clause machinery:
//! SELECT rewriting (sqlite3WindowRewrite), the Window object lifecycle
//! (Alloc/Assemble/Attach/Link/Chain/Update/Dup/Delete/Compare), and the
//! partition/frame VDBE codegen (sqlite3WindowCodeInit / sqlite3WindowCodeStep).
//!
//! External-linkage (non-static) symbols of window.c, all exported here:
//!   sqlite3WindowFunctions, sqlite3WindowUpdate, sqlite3WindowRewrite,
//!   sqlite3WindowUnlinkFromSelect, sqlite3WindowDelete, sqlite3WindowListDelete,
//!   sqlite3WindowAlloc, sqlite3WindowAssemble, sqlite3WindowChain,
//!   sqlite3WindowAttach, sqlite3WindowLink, sqlite3WindowCompare,
//!   sqlite3WindowCodeInit, sqlite3WindowDup, sqlite3WindowListDup,
//!   sqlite3WindowCodeStep, and sqlite3WindowExtraAggFuncDepth (non-static walker
//!   callback). Everything else is file-scope (private) exactly as in window.c.
//!
//! This is NOT a leaf module: every VDBE/expr/select helper window.c calls
//! (sqlite3VdbeAddOp*, sqlite3ExprDup, sqlite3SelectNew, sqlite3WhereEnd, …)
//! remains C (or already-ported Zig) and is declared `extern fn ... callconv(.c)`.
//! Only window.c's own functions are reproduced.
//!
//! Config: SQLITE_OMIT_WINDOWFUNC OFF. SQLITE_ENABLE_EXPLAIN_COMMENTS ON in both
//! builds → VdbeComment/VdbeNoopComment are real calls. SQLITE_ENABLE_MODULE_COMMENTS
//! OFF → VdbeModuleComment is a no-op (skipped). SQLITE_VDBE_COVERAGE OFF in both
//! → VdbeCoverage* are no-ops. TREETRACE_ENABLED only in the testfixture (debug)
//! config → the single TREETRACE() call is gated on config.sqlite_debug.

const std = @import("std");
const config = @import("config");
const L = @import("c_layout.zig");

inline fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L.c, name)) @field(L.c, name) else fallback;
}

// ─── opaque pointee aliases (C structs we hold by pointer) ──────────────────
const Parse = anyopaque;
const Select = anyopaque;
const Expr = anyopaque;
const ExprList = anyopaque;
const SrcList = anyopaque;
const Table = anyopaque;
const Vdbe = anyopaque;
const FuncDef = anyopaque;
const KeyInfo = anyopaque;
const CollSeq = anyopaque;
const Token = anyopaque;
const WhereInfo = anyopaque;
const Db = anyopaque;
const Walker = anyopaque;
const SqliteValue = anyopaque;

// ─── token / opcode / flag constants (ground-truth probed) ──────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_ERROR: c_int = 1;

const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;

const TK_NO: c_int = 67;
const TK_ROWS: c_int = 77;
const TK_CURRENT: c_int = 86;
const TK_FOLLOWING: c_int = 87;
const TK_PRECEDING: c_int = 89;
const TK_RANGE: c_int = 90;
const TK_UNBOUNDED: c_int = 91;
const TK_GROUPS: c_int = 93;
const TK_TIES: c_int = 95;
const TK_NULL: c_int = 122;
const TK_GROUP: c_int = 147;
const TK_FILTER: c_int = 167;
const TK_COLUMN: c_int = 168;
const TK_AGG_FUNCTION: c_int = 169;
const TK_FUNCTION: c_int = 172;
const TK_IF_NULL_ROW: c_int = 179;

const OP_Goto: c_int = 9;
const OP_Gosub: c_int = 10;
const OP_MustBeInt: c_int = 13;
const OP_Jump: c_int = 14;
const OP_IfNot: c_int = 17;
const OP_SeekGE: c_int = 23;
const OP_SeekRowid: c_int = 30;
const OP_Last: c_int = 32;
const OP_Rewind: c_int = 36;
const OP_Next: c_int = 40;
const OP_IsNull: c_int = 51;
const OP_NotNull: c_int = 52;
const OP_Ne: c_int = 53;
const OP_Eq: c_int = 54;
const OP_Gt: c_int = 55;
const OP_Le: c_int = 56;
const OP_Lt: c_int = 57;
const OP_Ge: c_int = 58;
const OP_IfPos: c_int = 61;
const OP_Return: c_int = 69;
const OP_Halt: c_int = 72;
const OP_Integer: c_int = 73;
const OP_Null: c_int = 77;
const OP_Copy: c_int = 82;
const OP_SCopy: c_int = 83;
const OP_CollSeq: c_int = 87;
const OP_AddImm: c_int = 88;
const OP_Compare: c_int = 92;
const OP_Column: c_int = 96;
const OP_MakeRecord: c_int = 99;
const OP_Add: c_int = 107;
const OP_Subtract: c_int = 108;
const OP_OpenDup: c_int = 117;
const OP_String8: c_int = 118;
const OP_OpenEphemeral: c_int = 120;
const OP_NewRowid: c_int = 129;
const OP_Insert: c_int = 130;
const OP_Delete: c_int = 132;
const OP_Rowid: c_int = 137;
const OP_IdxInsert: c_int = 140;
const OP_ResetSorter: c_int = 148;
const OP_AggInverse: c_int = 163;
const OP_AggStep: c_int = 164;
const OP_AggValue: c_int = 166;
const OP_AggFinal: c_int = 167;

const P4_STATIC: c_int = -1;
const P4_COLLSEQ: c_int = -2;
const P4_FUNCDEF: c_int = -8;
const P4_KEYINFO: c_int = -9;

const SQLITE_AFF_NONE: c_int = 0x40;
const SQLITE_AFF_NUMERIC: u16 = 0x43;
const SQLITE_JUMPIFNULL: u16 = 0x10;
const SQLITE_NULLEQ: u16 = 0x80;
const OPFLAG_SAVEPOSITION: u16 = 0x02;
const OE_Abort: c_int = 2;

const KEYINFO_ORDER_DESC: u8 = 0x01;
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

const EP_Distinct: u32 = 0x000004;
const EP_Collate: u32 = 0x000200;
const EP_IntValue: u32 = 0x000800;
const EP_FullSize: u32 = 0x020000;
const EP_WinFunc: u32 = 0x1000000;
const EP_Static: u32 = 0x8000000;
const EP_IsTrue: u32 = 0x10000000;
const EP_IsFalse: u32 = 0x20000000;
const EP_xIsSelect: u32 = 0x001000;
const EP_Reduced: u32 = 0x004000;
const EP_TokenOnly: u32 = 0x010000;

const WRC_Continue: c_int = 0;
const WRC_Prune: c_int = 1;
const WRC_Abort: c_int = 2;

const SF_Aggregate: u32 = 0x0000008;
const SF_Expanded: u32 = 0x0000040;
const SF_WinRewrite: u32 = 0x0100000;
const SF_MultiPart: u32 = 0x2000000;
const SF_OrderByReqd: u32 = 0x8000000;

const SQLITE_FUNC_NEEDCOLL: u32 = 0x0020;
const SQLITE_FUNC_MINMAX: u32 = 0x1000;
const SQLITE_FUNC_WINDOW: u32 = 0x00010000;
const SQLITE_FUNC_BUILTIN: u32 = 0x00800000;
const SQLITE_SUBTYPE: u32 = 0x000100000;
const SQLITE_UTF8: u32 = 1;

const SQLITE_WindowFunc: u32 = 0x00000002;
const TF_Ephemeral: u32 = 0x00004000;
const PARSE_MODE_RENAME: u8 = 2;

// ─── struct field offsets (config-invariant for these fields) ───────────────
const Parse_db = off("Parse_db", 0);
const Parse_nMem = off("Parse_nMem", 60);
const Parse_nTab = off("Parse_nTab", 56);
const Parse_nErr = off("Parse_nErr", 52);
const Parse_eParseMode = off("Parse_eParseMode", 300);
const Parse_addrExplain = off("Parse_addrExplain", 312);

const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103);
const sqlite3_enc = off("sqlite3_enc", 100);
const sqlite3_dbOptFlags = off("sqlite3_dbOptFlags", 0); // probed below

const Select_pSrc = off("Select_pSrc", 32);
const Select_pEList = off("Select_pEList", 24);
const Select_pWhere = off("Select_pWhere", 40);
const Select_pGroupBy = off("Select_pGroupBy", 48);
const Select_pHaving = off("Select_pHaving", 56);
const Select_pOrderBy = off("Select_pOrderBy", 64);
const Select_pPrior = off("Select_pPrior", 72);
const Select_selFlags = off("Select_selFlags", 4);
const Select_pWin = off("Select_pWin", 104); // probed below
const Select_selId = off("Select_selId", 16);

const SrcList_nSrc = off("SrcList_nSrc", 0);
const SrcList_a = off("SrcList_a", 8);
const SrcItem_sz = off("sizeof_SrcItem", 72);
const SrcItem_iCursor = off("SrcItem_iCursor", 28);
const SrcItem_pSTab = off("SrcItem_pSTab", 16);
const SrcItem_fg = off("SrcItem_fg", 24);
const SrcItem_u4 = off("SrcItem_u4", 64);
const SrcItem_u4_pSubq = off("SrcItem_u4_pSubq", 64);
const Subquery_pSelect = off("Subquery_pSelect", 0);
const fg_isSubquery_mask: u8 = 0x04; // byte fg+1
const fg_isCorrelated_mask: u8 = 0x10; // byte fg+1

const Table_nCol = off("Table_nCol", 54);
const Table_tabFlags = off("Table_tabFlags", 48);
const sizeof_Table = off("sizeof_Table", 120);

const Expr_op = off("Expr_op", 0);
const Expr_op2 = off("Expr_op2", 2);
const Expr_flags = off("Expr_flags", 4);
const Expr_u = off("Expr_u", 8); // u.zToken / u.iValue
const Expr_x = off("Expr_x", 32); // x.pList
const Expr_iTable = off("Expr_iTable", 44);
const Expr_iColumn = off("Expr_iColumn", 48);
const Expr_pAggInfo = off("Expr_pAggInfo", 56);
const Expr_y = off("Expr_y", 64); // y.pWin / y.pTab

const ExprList_nExpr = off("ExprList_nExpr", 0);
const ExprList_a = off("ExprList_a", 8);
const ExprList_item_sz = off("sizeof_ExprList_item", 24);
const ExprList_item_pExpr = off("ExprList_item_pExpr", 0);
const ExprList_item_fg_sortFlags = off("ExprList_item_fg_sortFlags", 16);

const FuncDef_funcFlags = off("FuncDef_funcFlags", 4);
const FuncDef_xSFunc = off("FuncDef_xSFunc", 24);
const FuncDef_zName = off("FuncDef_zName", 56);

const Walker_u = off("Walker_u", 40);
const Walker_pParse = off("Walker_pParse", 0);
const Walker_xExprCallback = off("Walker_xExprCallback", 8);
const Walker_xSelectCallback = off("Walker_xSelectCallback", 16);
const Walker_xSelectCallback2 = off("Walker_xSelectCallback2", 24);
const Walker_walkerDepth = off("Walker_walkerDepth", 32);
const sizeof_Walker = off("sizeof_Walker", 48);

const KeyInfo_aSortFlags = off("KeyInfo_aSortFlags", 24);

// ─── tiny byte-poke helpers ─────────────────────────────────────────────────
inline fn B(p: anytype) [*]u8 {
    return @ptrCast(@constCast(p));
}
inline fn rdPtr(p: ?*const anyopaque, comptime o: usize) ?*anyopaque {
    const q: *align(1) const ?*anyopaque = @ptrCast(B(p.?) + o);
    // C struct pointer fields target naturally-aligned objects; re-assert the
    // alignment so callers may @ptrCast the result to a typed (aligned) pointer.
    if (q.*) |v| return @alignCast(v);
    return null;
}
inline fn wrPtr(p: ?*anyopaque, comptime o: usize, v: ?*anyopaque) void {
    const q: *align(1) ?*anyopaque = @ptrCast(B(p.?) + o);
    q.* = v;
}
inline fn rdI32(p: ?*const anyopaque, o: usize) c_int {
    const q: *align(1) const c_int = @ptrCast(B(p.?) + o);
    return q.*;
}
inline fn wrI32(p: ?*anyopaque, o: usize, v: c_int) void {
    const q: *align(1) c_int = @ptrCast(B(p.?) + o);
    q.* = v;
}
inline fn rdU32(p: ?*const anyopaque, o: usize) u32 {
    const q: *align(1) const u32 = @ptrCast(B(p.?) + o);
    return q.*;
}
inline fn wrU32(p: ?*anyopaque, o: usize, v: u32) void {
    const q: *align(1) u32 = @ptrCast(B(p.?) + o);
    q.* = v;
}
inline fn rdU16(p: ?*const anyopaque, o: usize) u16 {
    const q: *align(1) const u16 = @ptrCast(B(p.?) + o);
    return q.*;
}
inline fn rdU8(p: ?*const anyopaque, o: usize) u8 {
    return B(p.?)[o];
}
inline fn wrU8(p: ?*anyopaque, o: usize, v: u8) void {
    B(p.?)[o] = v;
}

// ─── extern C globals ───────────────────────────────────────────────────────
extern var sqlite3TreeTrace: u32;

// ─── extern C helper functions (resolved at link) ──────────────────────────
const XCleanup = ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void;
const XWalkExpr = ?*const fn (?*Walker, ?*Expr) callconv(.c) c_int;
const XWalkSelect = ?*const fn (?*Walker, ?*Select) callconv(.c) c_int;

extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3ErrorMsg(p: ?*Parse, fmt: [*:0]const u8, ...) void;
extern fn sqlite3ErrorToParser(db: ?*anyopaque, rc: c_int) c_int;
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*]const u8, n: u64) ?[*:0]u8;

extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*const Expr, flags: c_int) ?*Expr;
extern fn sqlite3ExprListDup(db: ?*anyopaque, p: ?*const ExprList, flags: c_int) ?*ExprList;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*Expr) void;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*ExprList) void;
extern fn sqlite3ExprAlloc(db: ?*anyopaque, op: c_int, tok: ?*const Token, dq: c_int) ?*Expr;
extern fn sqlite3ExprInt32(db: ?*anyopaque, v: c_int) ?*Expr;
extern fn sqlite3ExprListAppend(p: ?*Parse, list: ?*ExprList, e: ?*Expr) ?*ExprList;
extern fn sqlite3ExprCompare(p: ?*const Parse, a: ?*const Expr, b: ?*const Expr, i: c_int) c_int;
extern fn sqlite3ExprListCompare(a: ?*const ExprList, b: ?*const ExprList, i: c_int) c_int;
extern fn sqlite3ExprIsConstant(p: ?*Parse, e: ?*Expr) c_int;
extern fn sqlite3ExprIsInteger(e: ?*const Expr, pv: *c_int, p: ?*Parse) c_int;
extern fn sqlite3ExprSkipCollateAndLikely(e: ?*Expr) ?*Expr;
extern fn sqlite3ExprNNCollSeq(p: ?*Parse, e: ?*const Expr) ?*CollSeq;
extern fn sqlite3ExprCode(p: ?*Parse, e: ?*Expr, reg: c_int) void;
extern fn sqlite3ExprCodeExprList(p: ?*Parse, l: ?*ExprList, t: c_int, srcReg: c_int, flags: u8) c_int;

extern fn sqlite3WalkExprList(w: ?*Walker, l: ?*ExprList) c_int;
extern fn sqlite3WalkSelect(w: ?*Walker, s: ?*Select) c_int;
extern fn sqlite3WalkerDepthIncrease(w: ?*Walker, s: ?*Select) c_int;
extern fn sqlite3WalkerDepthDecrease(w: ?*Walker, s: ?*Select) void;
extern fn sqlite3AggInfoPersistWalkerInit(w: ?*Walker, p: ?*Parse) void;

extern fn sqlite3GetVdbe(p: ?*Parse) ?*Vdbe;
extern fn sqlite3VdbeAddOp0(v: ?*Vdbe, op: c_int) c_int;
extern fn sqlite3VdbeAddOp1(v: ?*Vdbe, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(v: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeAppendP4(v: ?*Vdbe, p4: ?*anyopaque, p4type: c_int) void;
extern fn sqlite3VdbeChangeP1(v: ?*Vdbe, addr: c_int, p1: c_int) void;
extern fn sqlite3VdbeChangeP5(v: ?*Vdbe, p5: u16) void;
extern fn sqlite3VdbeJumpHere(v: ?*Vdbe, addr: c_int) void;
extern fn sqlite3VdbeGetOp(v: ?*Vdbe, addr: c_int) ?*anyopaque;
extern fn sqlite3VdbeMakeLabel(p: ?*Parse) c_int;
extern fn sqlite3VdbeResolveLabel(v: ?*Vdbe, x: c_int) void;
extern fn sqlite3VdbeCurrentAddr(v: ?*Vdbe) c_int;
extern fn sqlite3VdbeComment(v: ?*Vdbe, fmt: [*:0]const u8, ...) void;

extern fn sqlite3GetTempReg(p: ?*Parse) c_int;
extern fn sqlite3ReleaseTempReg(p: ?*Parse, r: c_int) void;
extern fn sqlite3GetTempRange(p: ?*Parse, n: c_int) c_int;
extern fn sqlite3ReleaseTempRange(p: ?*Parse, r: c_int, n: c_int) void;
extern fn sqlite3KeyInfoFromExprList(p: ?*Parse, l: ?*ExprList, a: c_int, b: c_int) ?*KeyInfo;
extern fn sqlite3MayAbort(p: ?*Parse) void;

extern fn sqlite3SelectNew(p: ?*Parse, e: ?*ExprList, src: ?*SrcList, w: ?*Expr, g: ?*ExprList, h: ?*Expr, o: ?*ExprList, sf: u32, lim: ?*Expr) ?*Select;
extern fn sqlite3SelectDelete(db: ?*anyopaque, p: ?*Select) void;
extern fn sqlite3SrcListAppend(p: ?*Parse, src: ?*SrcList, a: ?*Token, b: ?*Token) ?*SrcList;
extern fn sqlite3SrcListAssignCursors(p: ?*Parse, src: ?*SrcList) void;
extern fn sqlite3SrcItemAttachSubquery(p: ?*Parse, item: ?*anyopaque, sub: ?*Select, b: c_int) c_int;
extern fn sqlite3ResultSetOfSelect(p: ?*Parse, s: ?*Select, aff: u8) ?*Table;
extern fn sqlite3ParserAddCleanup(p: ?*Parse, x: XCleanup, ptr: ?*anyopaque) ?*anyopaque;
extern fn sqlite3WhereEnd(w: ?*WhereInfo) void;
extern fn sqlite3RenameExprUnmap(p: ?*Parse, e: ?*Expr) void;
extern fn sqlite3RealToI64(r: f64) i64;
extern fn sqlite3ValueFromExpr(db: ?*anyopaque, e: ?*const Expr, enc: u8, aff: u8, ppVal: *?*SqliteValue) c_int;
extern fn sqlite3ValueFree(v: ?*SqliteValue) void;
extern fn sqlite3_value_int(v: ?*SqliteValue) c_int;
extern fn sqlite3InsertBuiltinFuncs(aDef: [*]FuncDefRec, nDef: c_int) void;
extern fn sqlite3DebugPrintf(fmt: [*:0]const u8, ...) void;

// aggregate-API helpers used by the built-in window function implementations
const Ctx = anyopaque; // sqlite3_context*
const Val = anyopaque; // sqlite3_value*
extern fn sqlite3_aggregate_context(ctx: ?*Ctx, n: c_int) ?*anyopaque;
extern fn sqlite3_result_int64(ctx: ?*Ctx, n: i64) void;
extern fn sqlite3_result_double(ctx: ?*Ctx, r: f64) void;
extern fn sqlite3_result_value(ctx: ?*Ctx, v: ?*Val) void;
extern fn sqlite3_result_error(ctx: ?*Ctx, z: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*Ctx) void;
extern fn sqlite3_value_numeric_type(v: ?*Val) c_int;
extern fn sqlite3_value_int64(v: ?*Val) i64;
extern fn sqlite3_value_double(v: ?*Val) f64;
extern fn sqlite3_value_dup(v: ?*const Val) ?*Val;
extern fn sqlite3_value_free(v: ?*Val) void;

// ─── Window struct mirror (sqliteInt.h; config-invariant; sizeof 144) ───────
const W = extern struct {
    zName: ?[*:0]u8, // 0
    zBase: ?[*:0]u8, // 8
    pPartition: ?*ExprList, // 16
    pOrderBy: ?*ExprList, // 24
    eFrmType: u8, // 32
    eStart: u8, // 33
    eEnd: u8, // 34
    bImplicitFrame: u8, // 35
    eExclude: u8, // 36
    _pad0: [3]u8 = .{ 0, 0, 0 }, // 37
    pStart: ?*Expr, // 40
    pEnd: ?*Expr, // 48
    ppThis: ?*?*W, // 56
    pNextWin: ?*W, // 64
    pFilter: ?*Expr, // 72
    pWFunc: ?*FuncDef, // 80
    iEphCsr: c_int, // 88
    regAccum: c_int, // 92
    regResult: c_int, // 96
    csrApp: c_int, // 100
    regApp: c_int, // 104
    regPart: c_int, // 108
    pOwner: ?*Expr, // 112
    nBufferCol: c_int, // 120
    iArgCol: c_int, // 124
    regOne: c_int, // 128
    regStartRowid: c_int, // 132
    regEndRowid: c_int, // 136
    bExprArgs: u8, // 140
    _pad1: [3]u8 = .{ 0, 0, 0 }, // 141
};
comptime {
    std.debug.assert(@sizeOf(W) == 144);
    std.debug.assert(@offsetOf(W, "pPartition") == 16);
    std.debug.assert(@offsetOf(W, "eFrmType") == 32);
    std.debug.assert(@offsetOf(W, "eExclude") == 36);
    std.debug.assert(@offsetOf(W, "pStart") == 40);
    std.debug.assert(@offsetOf(W, "ppThis") == 56);
    std.debug.assert(@offsetOf(W, "pNextWin") == 64);
    std.debug.assert(@offsetOf(W, "pWFunc") == 80);
    std.debug.assert(@offsetOf(W, "iEphCsr") == 88);
    std.debug.assert(@offsetOf(W, "regPart") == 108);
    std.debug.assert(@offsetOf(W, "pOwner") == 112);
    std.debug.assert(@offsetOf(W, "nBufferCol") == 120);
    std.debug.assert(@offsetOf(W, "regOne") == 128);
    std.debug.assert(@offsetOf(W, "regStartRowid") == 132);
    std.debug.assert(@offsetOf(W, "bExprArgs") == 140);
}

// ─── FuncDef mirror (ABI; sizeof 72) — only used by the registration table ──
const FuncDefRec = extern struct {
    nArg: i16,
    funcFlags: u32,
    pUserData: ?*anyopaque = null,
    pNext: ?*FuncDefRec = null,
    xSFunc: ?*const anyopaque,
    xFinalize: ?*const anyopaque,
    xValue: ?*const anyopaque,
    xInverse: ?*const anyopaque,
    zName: ?[*:0]const u8,
    u: extern union { pHash: ?*FuncDefRec, pDestructor: ?*anyopaque } = .{ .pHash = null },
};
comptime {
    std.debug.assert(@sizeOf(FuncDefRec) == 72);
    std.debug.assert(@offsetOf(FuncDefRec, "zName") == 56);
}

// ─── ExprList accessors ─────────────────────────────────────────────────────
inline fn elNExpr(p: ?*const ExprList) c_int {
    return rdI32(p, ExprList_nExpr);
}
inline fn elItem(p: ?*const ExprList, i: usize) [*]u8 {
    return B(p.?) + ExprList_a + i * ExprList_item_sz;
}
inline fn elItemExpr(p: ?*const ExprList, i: usize) ?*Expr {
    const q: *align(1) const ?*Expr = @ptrCast(elItem(p, i) + ExprList_item_pExpr);
    return q.*;
}
inline fn elItemSortFlags(p: ?*const ExprList, i: usize) u8 {
    return (elItem(p, i) + ExprList_item_fg_sortFlags)[0];
}

// ─── Parse / db accessors ───────────────────────────────────────────────────
inline fn parseDb(p: ?*Parse) ?*anyopaque {
    return rdPtr(p, Parse_db);
}
inline fn parseNMem(p: ?*Parse) c_int {
    return rdI32(p, Parse_nMem);
}
inline fn parseSetNMem(p: ?*Parse, v: c_int) void {
    wrI32(p, Parse_nMem, v);
}
inline fn parseIncNMem(p: ?*Parse) c_int {
    const v = parseNMem(p) + 1;
    parseSetNMem(p, v);
    return v;
}
inline fn parseNTab(p: ?*Parse) c_int {
    return rdI32(p, Parse_nTab);
}
inline fn parseSetNTab(p: ?*Parse, v: c_int) void {
    wrI32(p, Parse_nTab, v);
}
inline fn parsePostIncNTab(p: ?*Parse) c_int {
    const v = parseNTab(p);
    parseSetNTab(p, v + 1);
    return v;
}
inline fn parseNErr(p: ?*Parse) c_int {
    return rdI32(p, Parse_nErr);
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return rdU8(db, sqlite3_mallocFailed) != 0;
}
inline fn dbEnc(db: ?*anyopaque) u8 {
    return rdU8(db, sqlite3_enc);
}
inline fn inRenameObject(p: ?*Parse) bool {
    // SQLITE_OMIT_ALTERTABLE OFF -> eParseMode >= PARSE_MODE_RENAME
    return rdU8(p, Parse_eParseMode) >= PARSE_MODE_RENAME;
}

// ─── Expr accessors ─────────────────────────────────────────────────────────
inline fn exprOp(e: ?*const Expr) u8 {
    return rdU8(e, Expr_op);
}
inline fn exprFlags(e: ?*const Expr) u32 {
    return rdU32(e, Expr_flags);
}
inline fn exprSetFlag(e: ?*Expr, m: u32) void {
    wrU32(e, Expr_flags, exprFlags(e) | m);
}
inline fn exprHasProp(e: ?*const Expr, m: u32) bool {
    return (exprFlags(e) & m) != 0;
}
inline fn exprUseXList(e: ?*const Expr) bool {
    return (exprFlags(e) & EP_xIsSelect) == 0;
}
inline fn exprXList(e: ?*const Expr) ?*ExprList {
    return @ptrCast(@alignCast(rdPtr(e, Expr_x)));
}
inline fn exprYWin(e: ?*const Expr) ?*W {
    return @ptrCast(@alignCast(rdPtr(e, Expr_y)));
}

// ─── Window field accessors via the mirror ──────────────────────────────────
inline fn win(p: ?*W) *W {
    return p.?;
}

// ─── built-in window function context objects ───────────────────────────────
const CallCount = extern struct { nValue: i64, nStep: i64, nTotal: i64 };
const NthValueCtx = extern struct { nStep: i64, pValue: ?*Val };
const NtileCtx = extern struct { nTotal: i64, nParam: i64, iRow: i64 };
const LastValueCtx = extern struct { pVal: ?*Val, nVal: c_int };

inline fn aggCtx(comptime T: type, ctx: ?*Ctx, alloc: bool) ?*T {
    const n: c_int = if (alloc) @sizeOf(T) else 0;
    return @ptrCast(@alignCast(sqlite3_aggregate_context(ctx, n)));
}

// row_number()
fn row_numberStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    if (aggCtx(i64, ctx, true)) |p| p.* += 1;
}
fn row_numberValueFunc(ctx: ?*Ctx) callconv(.c) void {
    const p = aggCtx(i64, ctx, true);
    sqlite3_result_int64(ctx, if (p) |q| q.* else 0);
}

// dense_rank()
fn dense_rankStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    if (aggCtx(CallCount, ctx, true)) |p| p.nStep = 1;
}
fn dense_rankValueFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(CallCount, ctx, true)) |p| {
        if (p.nStep != 0) {
            p.nValue += 1;
            p.nStep = 0;
        }
        sqlite3_result_int64(ctx, p.nValue);
    }
}

// nth_value()
fn nth_valueStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    const argv = @as([*]?*Val, @ptrCast(a.?));
    if (aggCtx(NthValueCtx, ctx, true)) |p| {
        var iVal: i64 = undefined;
        switch (sqlite3_value_numeric_type(argv[1])) {
            SQLITE_INTEGER => iVal = sqlite3_value_int64(argv[1]),
            SQLITE_FLOAT => {
                const fVal = sqlite3_value_double(argv[1]);
                if (@as(f64, @floatFromInt(sqlite3RealToI64(fVal))) != fVal) {
                    return nthValErr(ctx);
                }
                iVal = @intFromFloat(fVal);
            },
            else => return nthValErr(ctx),
        }
        if (iVal <= 0) return nthValErr(ctx);
        p.nStep += 1;
        if (iVal == p.nStep) {
            p.pValue = sqlite3_value_dup(argv[0]);
            if (p.pValue == null) sqlite3_result_error_nomem(ctx);
        }
    }
}
fn nthValErr(ctx: ?*Ctx) void {
    sqlite3_result_error(ctx, "second argument to nth_value must be a positive integer", -1);
}
fn nth_valueFinalizeFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(NthValueCtx, ctx, false)) |p| {
        if (p.pValue) |pv| {
            sqlite3_result_value(ctx, pv);
            sqlite3_value_free(pv);
            p.pValue = null;
        }
    }
}

// first_value()
fn first_valueStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    const argv = @as([*]?*Val, @ptrCast(a.?));
    if (aggCtx(NthValueCtx, ctx, true)) |p| {
        if (p.pValue == null) {
            p.pValue = sqlite3_value_dup(argv[0]);
            if (p.pValue == null) sqlite3_result_error_nomem(ctx);
        }
    }
}
fn first_valueFinalizeFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(NthValueCtx, ctx, true)) |p| {
        if (p.pValue) |pv| {
            sqlite3_result_value(ctx, pv);
            sqlite3_value_free(pv);
            p.pValue = null;
        }
    }
}

// rank()
fn rankStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    if (aggCtx(CallCount, ctx, true)) |p| {
        p.nStep += 1;
        if (p.nValue == 0) p.nValue = p.nStep;
    }
}
fn rankValueFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(CallCount, ctx, true)) |p| {
        sqlite3_result_int64(ctx, p.nValue);
        p.nValue = 0;
    }
}

// percent_rank()
fn percent_rankStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    if (aggCtx(CallCount, ctx, true)) |p| p.nTotal += 1;
}
fn percent_rankInvFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    const p = aggCtx(CallCount, ctx, true).?;
    p.nStep += 1;
}
fn percent_rankValueFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(CallCount, ctx, true)) |p| {
        p.nValue = p.nStep;
        if (p.nTotal > 1) {
            const r = @as(f64, @floatFromInt(p.nValue)) / @as(f64, @floatFromInt(p.nTotal - 1));
            sqlite3_result_double(ctx, r);
        } else {
            sqlite3_result_double(ctx, 0.0);
        }
    }
}

// cume_dist()
fn cume_distStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    if (aggCtx(CallCount, ctx, true)) |p| p.nTotal += 1;
}
fn cume_distInvFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    const p = aggCtx(CallCount, ctx, true).?;
    p.nStep += 1;
}
fn cume_distValueFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(CallCount, ctx, false)) |p| {
        const r = @as(f64, @floatFromInt(p.nStep)) / @as(f64, @floatFromInt(p.nTotal));
        sqlite3_result_double(ctx, r);
    }
}

// ntile()
fn ntileStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    const argv = @as([*]?*Val, @ptrCast(a.?));
    if (aggCtx(NtileCtx, ctx, true)) |p| {
        if (p.nTotal == 0) {
            p.nParam = sqlite3_value_int64(argv[0]);
            if (p.nParam <= 0) {
                sqlite3_result_error(ctx, "argument of ntile must be a positive integer", -1);
            }
        }
        p.nTotal += 1;
    }
}
fn ntileInvFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    const p = aggCtx(NtileCtx, ctx, true).?;
    p.iRow += 1;
}
fn ntileValueFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(NtileCtx, ctx, true)) |p| {
        if (p.nParam > 0) {
            const nSize = @divTrunc(p.nTotal, p.nParam);
            if (nSize == 0) {
                sqlite3_result_int64(ctx, p.iRow + 1);
            } else {
                const nLarge = p.nTotal - p.nParam * nSize;
                const iSmall = nLarge * (nSize + 1);
                const iRow = p.iRow;
                if (iRow < iSmall) {
                    sqlite3_result_int64(ctx, 1 + @divTrunc(iRow, nSize + 1));
                } else {
                    sqlite3_result_int64(ctx, 1 + nLarge + @divTrunc(iRow - iSmall, nSize));
                }
            }
        }
    }
}

// last_value()
fn last_valueStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    const argv = @as([*]?*Val, @ptrCast(a.?));
    if (aggCtx(LastValueCtx, ctx, true)) |p| {
        sqlite3_value_free(p.pVal);
        p.pVal = sqlite3_value_dup(argv[0]);
        if (p.pVal == null) {
            sqlite3_result_error_nomem(ctx);
        } else {
            p.nVal += 1;
        }
    }
}
fn last_valueInvFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = n;
    _ = a;
    const p = aggCtx(LastValueCtx, ctx, true).?;
    p.nVal -= 1;
    if (p.nVal == 0) {
        sqlite3_value_free(p.pVal);
        p.pVal = null;
    }
}
fn last_valueValueFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(LastValueCtx, ctx, false)) |p| {
        if (p.pVal) |pv| sqlite3_result_value(ctx, pv);
    }
}
fn last_valueFinalizeFunc(ctx: ?*Ctx) callconv(.c) void {
    if (aggCtx(LastValueCtx, ctx, true)) |p| {
        if (p.pVal) |pv| {
            sqlite3_result_value(ctx, pv);
            sqlite3_value_free(pv);
            p.pVal = null;
        }
    }
}

// no-op placeholders
fn noopStepFunc(ctx: ?*Ctx, n: c_int, a: ?*?*Val) callconv(.c) void {
    _ = ctx;
    _ = n;
    _ = a;
    unreachable;
}
fn noopValueFunc(ctx: ?*Ctx) callconv(.c) void {
    _ = ctx;
}

// ─── static window-function names (address-compared) ────────────────────────
const row_numberName: [:0]const u8 = "row_number";
const dense_rankName: [:0]const u8 = "dense_rank";
const rankName: [:0]const u8 = "rank";
const percent_rankName: [:0]const u8 = "percent_rank";
const cume_distName: [:0]const u8 = "cume_dist";
const ntileName: [:0]const u8 = "ntile";
const last_valueName: [:0]const u8 = "last_value";
const nth_valueName: [:0]const u8 = "nth_value";
const first_valueName: [:0]const u8 = "first_value";
const leadName: [:0]const u8 = "lead";
const lagName: [:0]const u8 = "lag";

inline fn nameEq(z: ?[*:0]const u8, n: [:0]const u8) bool {
    // window.c compares pointers, but our pointers differ from the C function
    // pointers stored in FuncDef.zName once registered. Compare contents.
    if (z == null) return false;
    return std.mem.orderZ(u8, z.?, n.ptr) == .eq;
}

inline fn funcName(f: ?*FuncDef) ?[*:0]const u8 {
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(B(f.?) + FuncDef_zName);
    return q.*;
}
inline fn funcFlags(f: ?*FuncDef) u32 {
    return rdU32(f, FuncDef_funcFlags);
}
inline fn funcXSFunc(f: ?*FuncDef) ?*const anyopaque {
    return rdPtr(f, FuncDef_xSFunc);
}

// ─── FuncDef registration table ─────────────────────────────────────────────
const FLAGS_BASE: u32 = SQLITE_FUNC_BUILTIN | SQLITE_UTF8 | SQLITE_FUNC_WINDOW;

fn wfAll(comptime nArg: i16, step: anytype, fin: anytype, val: anytype, inv: anytype, zName: [:0]const u8) FuncDefRec {
    return .{
        .nArg = nArg,
        .funcFlags = FLAGS_BASE,
        .xSFunc = @ptrCast(&step),
        .xFinalize = @ptrCast(&fin),
        .xValue = @ptrCast(&val),
        .xInverse = @ptrCast(&inv),
        .zName = zName.ptr,
    };
}
fn wfNoop(comptime nArg: i16, zName: [:0]const u8) FuncDefRec {
    return .{
        .nArg = nArg,
        .funcFlags = FLAGS_BASE,
        .xSFunc = @ptrCast(&noopStepFunc),
        .xFinalize = @ptrCast(&noopValueFunc),
        .xValue = @ptrCast(&noopValueFunc),
        .xInverse = @ptrCast(&noopStepFunc),
        .zName = zName.ptr,
    };
}
fn wfX(comptime nArg: i16, step: anytype, val: anytype, zName: [:0]const u8) FuncDefRec {
    return .{
        .nArg = nArg,
        .funcFlags = FLAGS_BASE,
        .xSFunc = @ptrCast(&step),
        .xFinalize = @ptrCast(&val),
        .xValue = @ptrCast(&val),
        .xInverse = @ptrCast(&noopStepFunc),
        .zName = zName.ptr,
    };
}

var aWindowFuncs = [_]FuncDefRec{
    wfX(0, row_numberStepFunc, row_numberValueFunc, row_numberName),
    wfX(0, dense_rankStepFunc, dense_rankValueFunc, dense_rankName),
    wfX(0, rankStepFunc, rankValueFunc, rankName),
    wfAll(0, percent_rankStepFunc, percent_rankValueFunc, percent_rankValueFunc, percent_rankInvFunc, percent_rankName),
    wfAll(0, cume_distStepFunc, cume_distValueFunc, cume_distValueFunc, cume_distInvFunc, cume_distName),
    wfAll(1, ntileStepFunc, ntileValueFunc, ntileValueFunc, ntileInvFunc, ntileName),
    wfAll(1, last_valueStepFunc, last_valueFinalizeFunc, last_valueValueFunc, last_valueInvFunc, last_valueName),
    wfAll(2, nth_valueStepFunc, nth_valueFinalizeFunc, noopValueFunc, noopStepFunc, nth_valueName),
    wfAll(1, first_valueStepFunc, first_valueFinalizeFunc, noopValueFunc, noopStepFunc, first_valueName),
    wfNoop(1, leadName),
    wfNoop(2, leadName),
    wfNoop(3, leadName),
    wfNoop(1, lagName),
    wfNoop(2, lagName),
    wfNoop(3, lagName),
};

export fn sqlite3WindowFunctions() callconv(.c) void {
    sqlite3InsertBuiltinFuncs(&aWindowFuncs, aWindowFuncs.len);
}

// ─── window lifecycle ───────────────────────────────────────────────────────
fn windowFind(pParse: ?*Parse, pList: ?*W, zName: ?[*:0]const u8) ?*W {
    var p: ?*W = pList;
    while (p) |pp| : (p = pp.pNextWin) {
        if (sqlite3StrICmp(@ptrCast(pp.zName), zName) == 0) break;
    }
    if (p == null) {
        sqlite3ErrorMsg(pParse, "no such window: %s", zName);
    }
    return p;
}

export fn sqlite3WindowUpdate(pParse: ?*Parse, pList: ?*W, pWin: ?*W, pFunc: ?*FuncDef) callconv(.c) void {
    const w = win(pWin);
    if (w.zName != null and w.eFrmType == 0) {
        const p = windowFind(pParse, pList, @ptrCast(w.zName)) orelse return;
        const db = parseDb(pParse);
        w.pPartition = sqlite3ExprListDup(db, p.pPartition, 0);
        w.pOrderBy = sqlite3ExprListDup(db, p.pOrderBy, 0);
        w.pStart = sqlite3ExprDup(db, p.pStart, 0);
        w.pEnd = sqlite3ExprDup(db, p.pEnd, 0);
        w.eStart = p.eStart;
        w.eEnd = p.eEnd;
        w.eFrmType = p.eFrmType;
        w.eExclude = p.eExclude;
    } else {
        sqlite3WindowChain(pParse, pWin, pList);
    }
    if (w.eFrmType == TK_RANGE and (w.pStart != null or w.pEnd != null) and
        (w.pOrderBy == null or elNExpr(w.pOrderBy) != 1))
    {
        sqlite3ErrorMsg(pParse, "RANGE with offset PRECEDING/FOLLOWING requires one ORDER BY expression");
    } else if ((funcFlags(pFunc) & SQLITE_FUNC_WINDOW) != 0) {
        const db = parseDb(pParse);
        if (w.pFilter != null) {
            sqlite3ErrorMsg(pParse, "FILTER clause may only be used with aggregate window functions");
        } else {
            const Up = struct { zFunc: [:0]const u8, eFrmType: c_int, eStart: c_int, eEnd: c_int };
            const aUp = [_]Up{
                .{ .zFunc = row_numberName, .eFrmType = TK_ROWS, .eStart = TK_UNBOUNDED, .eEnd = TK_CURRENT },
                .{ .zFunc = dense_rankName, .eFrmType = TK_RANGE, .eStart = TK_UNBOUNDED, .eEnd = TK_CURRENT },
                .{ .zFunc = rankName, .eFrmType = TK_RANGE, .eStart = TK_UNBOUNDED, .eEnd = TK_CURRENT },
                .{ .zFunc = percent_rankName, .eFrmType = TK_GROUPS, .eStart = TK_CURRENT, .eEnd = TK_UNBOUNDED },
                .{ .zFunc = cume_distName, .eFrmType = TK_GROUPS, .eStart = TK_FOLLOWING, .eEnd = TK_UNBOUNDED },
                .{ .zFunc = ntileName, .eFrmType = TK_ROWS, .eStart = TK_CURRENT, .eEnd = TK_UNBOUNDED },
                .{ .zFunc = leadName, .eFrmType = TK_ROWS, .eStart = TK_UNBOUNDED, .eEnd = TK_UNBOUNDED },
                .{ .zFunc = lagName, .eFrmType = TK_ROWS, .eStart = TK_UNBOUNDED, .eEnd = TK_CURRENT },
            };
            const fname = funcName(pFunc);
            for (aUp) |u| {
                if (nameEq(fname, u.zFunc)) {
                    sqlite3ExprDelete(db, w.pStart);
                    sqlite3ExprDelete(db, w.pEnd);
                    w.pEnd = null;
                    w.pStart = null;
                    w.eFrmType = @intCast(u.eFrmType);
                    w.eStart = @intCast(u.eStart);
                    w.eEnd = @intCast(u.eEnd);
                    w.eExclude = 0;
                    if (w.eStart == TK_FOLLOWING) {
                        w.pStart = sqlite3ExprInt32(db, 1);
                    }
                    break;
                }
            }
        }
    }
    w.pWFunc = pFunc;
}

// ─── WindowRewrite walker ───────────────────────────────────────────────────
const WindowRewrite = extern struct {
    pWin: ?*W,
    pSrc: ?*SrcList,
    pSub: ?*ExprList,
    pTab: ?*Table,
    pSubSelect: ?*Select,
};

inline fn walkerRewrite(w: ?*Walker) *?*WindowRewrite {
    return @ptrCast(@alignCast(B(w.?) + Walker_u));
}

fn selectWindowRewriteExprCb(pWalker: ?*Walker, pExpr: ?*Expr) callconv(.c) c_int {
    const p = walkerRewrite(pWalker).*.?;
    const pParse: ?*Parse = @ptrCast(@alignCast(rdPtr(pWalker, Walker_pParse)));
    const db = parseDb(pParse);

    if (p.pSubSelect != null) {
        if (exprOp(pExpr) != TK_COLUMN) {
            return WRC_Continue;
        } else {
            const nSrc = rdI32(p.pSrc, SrcList_nSrc);
            const iTab = rdI32(pExpr, Expr_iTable);
            var i: c_int = 0;
            while (i < nSrc) : (i += 1) {
                const item = B(p.pSrc.?) + SrcList_a + @as(usize, @intCast(i)) * SrcItem_sz;
                const cur: *align(1) const c_int = @ptrCast(item + SrcItem_iCursor);
                if (iTab == cur.*) break;
            }
            if (i == nSrc) return WRC_Continue;
        }
    }

    const op = exprOp(pExpr);
    switch (op) {
        TK_FUNCTION => {
            if (!exprHasProp(pExpr, EP_WinFunc)) {
                // fall through to the column-handling block (break in C)
            } else {
                var pw: ?*W = p.pWin;
                while (pw) |ww| : (pw = ww.pNextWin) {
                    if (exprYWin(pExpr) == ww) {
                        return WRC_Prune;
                    }
                }
                // deliberate fall-through to TK_COLUMN handling
                return rewriteColumn(p, pParse, db, pExpr);
            }
            // EP_WinFunc not set: C `break` -> no column handling.
            return WRC_Continue;
        },
        TK_IF_NULL_ROW, TK_AGG_FUNCTION, TK_COLUMN => return rewriteColumn(p, pParse, db, pExpr),
        else => return WRC_Continue,
    }
}

fn rewriteColumn(p: *WindowRewrite, pParse: ?*Parse, db: ?*anyopaque, pExpr: ?*Expr) c_int {
    var iCol: c_int = -1;
    if (dbMallocFailed(db)) return WRC_Abort;
    if (p.pSub) |sub| {
        var i: c_int = 0;
        const n = elNExpr(sub);
        while (i < n) : (i += 1) {
            if (sqlite3ExprCompare(null, elItemExpr(sub, @intCast(i)), pExpr, -1) == 0) {
                iCol = i;
                break;
            }
        }
    }
    if (iCol < 0) {
        const pDup = sqlite3ExprDup(db, pExpr, 0);
        if (pDup != null and exprOp(pDup) == TK_AGG_FUNCTION) {
            wrU8(pDup, Expr_op, TK_FUNCTION);
        }
        p.pSub = sqlite3ExprListAppend(pParse, p.pSub, pDup);
    }
    if (p.pSub) |sub| {
        const f = exprFlags(pExpr) & EP_Collate;
        exprSetFlag(pExpr, EP_Static);
        sqlite3ExprDelete(db, pExpr);
        exprClearFlag(pExpr, EP_Static);
        @memset(B(pExpr.?)[0..exprSizeFull()], 0);

        wrU8(pExpr, Expr_op, TK_COLUMN);
        const newCol: c_int = if (iCol < 0) elNExpr(sub) - 1 else iCol;
        wrI16(pExpr, Expr_iColumn, @truncate(newCol));
        wrI32(pExpr, Expr_iTable, p.pWin.?.iEphCsr);
        wrPtr(pExpr, Expr_y, @ptrCast(p.pTab)); // y.pTab
        wrU32(pExpr, Expr_flags, f);
    }
    if (dbMallocFailed(db)) return WRC_Abort;
    return WRC_Continue;
}

inline fn exprClearFlag(e: ?*Expr, m: u32) void {
    wrU32(e, Expr_flags, exprFlags(e) & ~m);
}
inline fn wrI16(p: ?*anyopaque, o: usize, v: i16) void {
    const q: *align(1) i16 = @ptrCast(B(p.?) + o);
    q.* = v;
}
// sizeof(Expr) — needed for the memset that clears the node in place.
fn exprSizeFull() usize {
    return off("sizeof_Expr", 72);
}

fn selectWindowRewriteSelectCb(pWalker: ?*Walker, pSelect: ?*Select) callconv(.c) c_int {
    const slot = walkerRewrite(pWalker);
    const p = slot.*.?;
    const pSave = p.pSubSelect;
    if (pSave == pSelect) {
        return WRC_Continue;
    } else {
        p.pSubSelect = pSelect;
        _ = sqlite3WalkSelect(pWalker, pSelect);
        p.pSubSelect = pSave;
    }
    return WRC_Prune;
}

fn selectWindowRewriteEList(
    pParse: ?*Parse,
    pWin: ?*W,
    pSrc: ?*SrcList,
    pEList: ?*ExprList,
    pTab: ?*Table,
    ppSub: *?*ExprList,
) void {
    var sWalker: [64]u8 align(8) = std.mem.zeroes([64]u8); // >= sizeof(Walker)=48
    var sRewrite: WindowRewrite = std.mem.zeroes(WindowRewrite);

    sRewrite.pSub = ppSub.*;
    sRewrite.pWin = pWin;
    sRewrite.pSrc = pSrc;
    sRewrite.pTab = pTab;

    const wptr: ?*Walker = @ptrCast(&sWalker);
    wrPtr(wptr, Walker_pParse, pParse);
    wrPtr(wptr, Walker_xExprCallback, @ptrCast(@constCast(&selectWindowRewriteExprCb)));
    wrPtr(wptr, Walker_xSelectCallback, @ptrCast(@constCast(&selectWindowRewriteSelectCb)));
    wrPtr(wptr, Walker_u, @ptrCast(&sRewrite));

    _ = sqlite3WalkExprList(wptr, pEList);

    ppSub.* = sRewrite.pSub;
}

fn exprListAppendList(pParse: ?*Parse, pListIn: ?*ExprList, pAppend: ?*ExprList, bIntToNull: c_int) ?*ExprList {
    var pList = pListIn;
    if (pAppend) |app| {
        const nInit: c_int = if (pList) |l| elNExpr(l) else 0;
        var i: c_int = 0;
        const n = elNExpr(app);
        while (i < n) : (i += 1) {
            const db = parseDb(pParse);
            const pDup = sqlite3ExprDup(db, elItemExpr(app, @intCast(i)), 0);
            if (dbMallocFailed(db)) {
                sqlite3ExprDelete(db, pDup);
                break;
            }
            if (bIntToNull != 0) {
                var iDummy: c_int = undefined;
                const pSub = sqlite3ExprSkipCollateAndLikely(pDup);
                if (sqlite3ExprIsInteger(pSub, &iDummy, null) != 0) {
                    wrU8(pSub, Expr_op, TK_NULL);
                    exprClearFlag(pSub, EP_IntValue | EP_IsTrue | EP_IsFalse);
                    wrPtr(pSub, Expr_u, null); // u.zToken = 0
                }
            }
            pList = sqlite3ExprListAppend(pParse, pList, pDup);
            if (pList) |l| {
                // copy fg.sortFlags from append[i] to list[nInit+i]
                const dstIdx: usize = @intCast(nInit + i);
                (elItem(l, dstIdx) + ExprList_item_fg_sortFlags)[0] = elItemSortFlags(app, @intCast(i));
            }
        }
    }
    return pList;
}

export fn sqlite3WindowExtraAggFuncDepth(pWalker: ?*Walker, pExpr: ?*Expr) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_AGG_FUNCTION) {
        const op2 = rdU8(pExpr, Expr_op2);
        const depth: c_int = rdI32(pWalker, Walker_walkerDepth);
        if (@as(c_int, op2) >= depth) {
            wrU8(pExpr, Expr_op2, op2 + 1);
        }
    }
    return WRC_Continue;
}

fn disallowAggregatesInOrderByCb(pWalker: ?*Walker, pExpr: ?*Expr) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_AGG_FUNCTION and rdPtr(pExpr, Expr_pAggInfo) == null) {
        const pParse: ?*Parse = @ptrCast(@alignCast(rdPtr(pWalker, Walker_pParse)));
        const zToken: ?[*:0]const u8 = @ptrCast(@alignCast(rdPtr(pExpr, Expr_u)));
        sqlite3ErrorMsg(pParse, "misuse of aggregate: %s()", zToken);
    }
    return WRC_Continue;
}

// ─── Select accessors ───────────────────────────────────────────────────────
inline fn selPWin(s: ?*Select) ?*W {
    return @ptrCast(@alignCast(rdPtr(s, Select_pWin)));
}
inline fn selSetPWin(s: ?*Select, v: ?*W) void {
    wrPtr(s, Select_pWin, @ptrCast(v));
}
inline fn selSelFlags(s: ?*Select) u32 {
    return rdU32(s, Select_selFlags);
}
inline fn selSetSelFlags(s: ?*Select, v: u32) void {
    wrU32(s, Select_selFlags, v);
}

export fn sqlite3WindowRewrite(pParse: ?*Parse, p: ?*Select) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pWinList = selPWin(p);
    if (pWinList != null and rdPtr(p, Select_pPrior) == null and
        (selSelFlags(p) & SF_WinRewrite) == 0 and !inRenameObject(pParse))
    {
        const v = sqlite3GetVdbe(pParse);
        const db = parseDb(pParse);
        var pSub: ?*Select = null;
        const pSrc: ?*SrcList = @ptrCast(@alignCast(rdPtr(p, Select_pSrc)));
        const pWhere: ?*Expr = @ptrCast(@alignCast(rdPtr(p, Select_pWhere)));
        const pGroupBy: ?*ExprList = @ptrCast(@alignCast(rdPtr(p, Select_pGroupBy)));
        const pHaving: ?*Expr = @ptrCast(@alignCast(rdPtr(p, Select_pHaving)));
        var pSort: ?*ExprList = null;
        var pSublist: ?*ExprList = null;
        const pMWin = pWinList.?;

        const selFlags = selSelFlags(p);

        const pTabAlloc = sqlite3DbMallocZero(db, sizeof_Table);
        if (pTabAlloc == null) {
            return sqlite3ErrorToParser(db, SQLITE_NOMEM);
        }
        var pTab: ?*Table = @ptrCast(pTabAlloc);

        var wbuf: [64]u8 align(8) = std.mem.zeroes([64]u8);
        const wp: ?*Walker = @ptrCast(&wbuf);
        sqlite3AggInfoPersistWalkerInit(wp, pParse);
        _ = sqlite3WalkSelect(wp, p);
        if ((selSelFlags(p) & SF_Aggregate) == 0) {
            wrPtr(wp, Walker_xExprCallback, @ptrCast(@constCast(&disallowAggregatesInOrderByCb)));
            wrPtr(wp, Walker_xSelectCallback, null);
            _ = sqlite3WalkExprList(wp, @ptrCast(@alignCast(rdPtr(p, Select_pOrderBy))));
        }

        wrPtr(p, Select_pSrc, null);
        wrPtr(p, Select_pWhere, null);
        wrPtr(p, Select_pGroupBy, null);
        wrPtr(p, Select_pHaving, null);
        selSetSelFlags(p, (selSelFlags(p) & ~SF_Aggregate) | SF_WinRewrite);

        pSort = exprListAppendList(pParse, null, pMWin.pPartition, 1);
        pSort = exprListAppendList(pParse, pSort, pMWin.pOrderBy, 1);
        const pParentOrderBy: ?*ExprList = @ptrCast(@alignCast(rdPtr(p, Select_pOrderBy)));
        if (pSort != null and pParentOrderBy != null and elNExpr(pParentOrderBy) <= elNExpr(pSort)) {
            const nSave = elNExpr(pSort);
            wrI32(pSort, ExprList_nExpr, elNExpr(pParentOrderBy));
            if (sqlite3ExprListCompare(pSort, pParentOrderBy, -1) == 0) {
                sqlite3ExprListDelete(db, pParentOrderBy);
                wrPtr(p, Select_pOrderBy, null);
            }
            wrI32(pSort, ExprList_nExpr, nSave);
        }

        pMWin.iEphCsr = parsePostIncNTab(pParse);
        parseSetNTab(pParse, parseNTab(pParse) + 3);

        selectWindowRewriteEList(pParse, pMWin, pSrc, @ptrCast(@alignCast(rdPtr(p, Select_pEList))), pTab, &pSublist);
        selectWindowRewriteEList(pParse, pMWin, pSrc, @ptrCast(@alignCast(rdPtr(p, Select_pOrderBy))), pTab, &pSublist);
        pMWin.nBufferCol = if (pSublist) |s| elNExpr(s) else 0;

        pSublist = exprListAppendList(pParse, pSublist, pMWin.pPartition, 0);
        pSublist = exprListAppendList(pParse, pSublist, pMWin.pOrderBy, 0);

        var pWin: ?*W = pMWin;
        while (pWin) |ww| : (pWin = ww.pNextWin) {
            const pArgs: ?*ExprList = exprXList(ww.pOwner);
            if ((funcFlags(ww.pWFunc) & SQLITE_SUBTYPE) != 0) {
                selectWindowRewriteEList(pParse, pMWin, pSrc, pArgs, pTab, &pSublist);
                ww.iArgCol = if (pSublist) |s| elNExpr(s) else 0;
                ww.bExprArgs = 1;
            } else {
                ww.iArgCol = if (pSublist) |s| elNExpr(s) else 0;
                pSublist = exprListAppendList(pParse, pSublist, pArgs, 0);
            }
            if (ww.pFilter) |filt| {
                const pFilter = sqlite3ExprDup(db, filt, 0);
                pSublist = sqlite3ExprListAppend(pParse, pSublist, pFilter);
            }
            ww.regAccum = parseIncNMem(pParse);
            ww.regResult = parseIncNMem(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, ww.regAccum);
        }

        if (pSublist == null) {
            pSublist = sqlite3ExprListAppend(pParse, null, sqlite3ExprInt32(db, 0));
        }

        pSub = sqlite3SelectNew(pParse, pSublist, pSrc, pWhere, pGroupBy, pHaving, pSort, 0, null);
        if (config.sqlite_debug) {
            if ((sqlite3TreeTrace & 0x40) != 0) {
                const selId = rdU32(p, Select_selId);
                const addrExplain = rdI32(pParse, Parse_addrExplain);
                sqlite3DebugPrintf("%u/%d/%p: ", selId, addrExplain, p);
                sqlite3DebugPrintf("New window-function subquery in FROM clause of (%u/%p)\n", selId, p);
            }
        }
        const newSrc = sqlite3SrcListAppend(pParse, null, null, null);
        wrPtr(p, Select_pSrc, newSrc);
        if (newSrc == null) {
            sqlite3SelectDelete(db, pSub);
        } else {
            const item0 = B(newSrc.?) + SrcList_a;
            if (sqlite3SrcItemAttachSubquery(pParse, @ptrCast(item0), pSub, 0) != 0) {
                // a[0].fg.isCorrelated = 1  (byte fg+1)
                item0[SrcItem_fg + 1] |= fg_isCorrelated_mask;
                sqlite3SrcListAssignCursors(pParse, newSrc);
                selSetSelFlags(pSub, selSelFlags(pSub) | SF_Expanded | SF_OrderByReqd);
                const pTab2 = sqlite3ResultSetOfSelect(pParse, pSub, SQLITE_AFF_NONE);
                selSetSelFlags(pSub, selSelFlags(pSub) | (selFlags & SF_Aggregate));
                if (pTab2 == null) {
                    rc = SQLITE_NOMEM;
                } else {
                    @memcpy(B(pTab.?)[0..sizeof_Table], B(pTab2.?)[0..sizeof_Table]);
                    wrU32(pTab, Table_tabFlags, rdU32(pTab, Table_tabFlags) | TF_Ephemeral);
                    // a[0].pSTab = pTab
                    const pSTabSlot: *align(1) ?*anyopaque = @ptrCast(item0 + SrcItem_pSTab);
                    pSTabSlot.* = @ptrCast(pTab);
                    pTab = pTab2;
                    @memset(wbuf[0..], 0);
                    wrPtr(wp, Walker_xExprCallback, @ptrCast(@constCast(&sqlite3WindowExtraAggFuncDepth)));
                    wrPtr(wp, Walker_xSelectCallback, @ptrCast(@constCast(&sqlite3WalkerDepthIncrease)));
                    wrPtr(wp, Walker_xSelectCallback2, @ptrCast(@constCast(&sqlite3WalkerDepthDecrease)));
                    _ = sqlite3WalkSelect(wp, pSub);
                }
            }
        }
        if (dbMallocFailed(db)) rc = SQLITE_NOMEM;

        _ = sqlite3ParserAddCleanup(pParse, @ptrCast(&sqlite3DbFree), @ptrCast(pTab));
    }

    return rc;
}

export fn sqlite3WindowUnlinkFromSelect(pIn: ?*W) callconv(.c) void {
    const p = win(pIn);
    if (p.ppThis) |pp| {
        pp.* = p.pNextWin;
        if (p.pNextWin) |nx| nx.ppThis = pp;
        p.ppThis = null;
    }
}

export fn sqlite3WindowDelete(db: ?*anyopaque, pIn: ?*W) callconv(.c) void {
    if (pIn) |p| {
        sqlite3WindowUnlinkFromSelect(p);
        const w = win(p);
        sqlite3ExprDelete(db, w.pFilter);
        sqlite3ExprListDelete(db, w.pPartition);
        sqlite3ExprListDelete(db, w.pOrderBy);
        sqlite3ExprDelete(db, w.pEnd);
        sqlite3ExprDelete(db, w.pStart);
        sqlite3DbFree(db, @ptrCast(w.zName));
        sqlite3DbFree(db, @ptrCast(w.zBase));
        sqlite3DbFree(db, @ptrCast(p));
    }
}

export fn sqlite3WindowListDelete(db: ?*anyopaque, pIn: ?*W) callconv(.c) void {
    var p: ?*W = pIn;
    while (p) |pp| {
        const pNext = pp.pNextWin;
        sqlite3WindowDelete(db, pp);
        p = pNext;
    }
}

fn sqlite3WindowOffsetExpr(pParse: ?*Parse, pExprIn: ?*Expr) ?*Expr {
    var pExpr = pExprIn;
    if (sqlite3ExprIsConstant(null, pExpr) == 0) {
        if (inRenameObject(pParse)) sqlite3RenameExprUnmap(pParse, pExpr);
        sqlite3ExprDelete(parseDb(pParse), pExpr);
        pExpr = sqlite3ExprAlloc(parseDb(pParse), TK_NULL, null, 0);
    }
    return pExpr;
}

export fn sqlite3WindowAlloc(
    pParse: ?*Parse,
    eType: c_int,
    eStart: c_int,
    pStart: ?*Expr,
    eEnd: c_int,
    pEnd: ?*Expr,
    eExcludeIn: u8,
) callconv(.c) ?*W {
    var eExclude = eExcludeIn;
    var bImplicitFrame: c_int = 0;
    var ty = eType;

    if (ty == 0) {
        bImplicitFrame = 1;
        ty = TK_RANGE;
    }

    if ((eStart == TK_CURRENT and eEnd == TK_PRECEDING) or
        (eStart == TK_FOLLOWING and (eEnd == TK_PRECEDING or eEnd == TK_CURRENT)))
    {
        sqlite3ErrorMsg(pParse, "unsupported frame specification");
        return windowAllocErr(pParse, pStart, pEnd);
    }

    const pWinAlloc = sqlite3DbMallocZero(parseDb(pParse), @sizeOf(W));
    if (pWinAlloc == null) return windowAllocErr(pParse, pStart, pEnd);
    const pWin: *W = @ptrCast(@alignCast(pWinAlloc));
    pWin.eFrmType = @intCast(ty);
    pWin.eStart = @intCast(eStart);
    pWin.eEnd = @intCast(eEnd);
    if (eExclude == 0 and optimizationDisabled(parseDb(pParse), SQLITE_WindowFunc)) {
        eExclude = TK_NO;
    }
    pWin.eExclude = eExclude;
    pWin.bImplicitFrame = @intCast(bImplicitFrame);
    pWin.pEnd = sqlite3WindowOffsetExpr(pParse, pEnd);
    pWin.pStart = sqlite3WindowOffsetExpr(pParse, pStart);
    return pWin;
}

fn windowAllocErr(pParse: ?*Parse, pStart: ?*Expr, pEnd: ?*Expr) ?*W {
    sqlite3ExprDelete(parseDb(pParse), pEnd);
    sqlite3ExprDelete(parseDb(pParse), pStart);
    return null;
}

inline fn optimizationDisabled(db: ?*anyopaque, mask: u32) bool {
    // OptimizationDisabled(db,mask) -> (db->dbOptFlags & mask)!=0
    const dbOptFlags = off("sqlite3_dbOptFlags", 0);
    if (dbOptFlags == 0) return false; // not probed -> not present; treat as enabled
    const v = rdU32(db, dbOptFlags);
    return (v & mask) != 0;
}

export fn sqlite3WindowAssemble(
    pParse: ?*Parse,
    pWinIn: ?*W,
    pPartition: ?*ExprList,
    pOrderBy: ?*ExprList,
    pBase: ?*Token,
) callconv(.c) ?*W {
    if (pWinIn) |p| {
        const w = win(p);
        w.pPartition = pPartition;
        w.pOrderBy = pOrderBy;
        if (pBase) |base| {
            // Token: {const char *z; unsigned int n;}
            const z: *align(1) const ?[*]const u8 = @ptrCast(B(base));
            const nq: *align(1) const c_uint = @ptrCast(B(base) + 8);
            w.zBase = sqlite3DbStrNDup(parseDb(pParse), z.*, nq.*);
        }
    } else {
        sqlite3ExprListDelete(parseDb(pParse), pPartition);
        sqlite3ExprListDelete(parseDb(pParse), pOrderBy);
    }
    return pWinIn;
}

export fn sqlite3WindowChain(pParse: ?*Parse, pWinIn: ?*W, pList: ?*W) callconv(.c) void {
    const pWin = win(pWinIn);
    if (pWin.zBase != null) {
        const db = parseDb(pParse);
        const pExist = windowFind(pParse, pList, @ptrCast(pWin.zBase));
        if (pExist) |ex| {
            var zErr: ?[*:0]const u8 = null;
            if (pWin.pPartition != null) {
                zErr = "PARTITION clause";
            } else if (ex.pOrderBy != null and pWin.pOrderBy != null) {
                zErr = "ORDER BY clause";
            } else if (ex.bImplicitFrame == 0) {
                zErr = "frame specification";
            }
            if (zErr) |e| {
                sqlite3ErrorMsg(pParse, "cannot override %s of window: %s", e, pWin.zBase);
            } else {
                pWin.pPartition = sqlite3ExprListDup(db, ex.pPartition, 0);
                if (ex.pOrderBy != null) {
                    pWin.pOrderBy = sqlite3ExprListDup(db, ex.pOrderBy, 0);
                }
                sqlite3DbFree(db, @ptrCast(pWin.zBase));
                pWin.zBase = null;
            }
        }
    }
}

export fn sqlite3WindowAttach(pParse: ?*Parse, pExpr: ?*Expr, pWin: ?*W) callconv(.c) void {
    if (pExpr) |e| {
        wrPtr(e, Expr_y, @ptrCast(pWin)); // y.pWin = pWin
        exprSetFlag(e, EP_WinFunc | EP_FullSize);
        win(pWin).pOwner = e;
        if ((exprFlags(e) & EP_Distinct) != 0 and win(pWin).eFrmType != TK_FILTER) {
            sqlite3ErrorMsg(pParse, "DISTINCT is not supported for window functions");
        }
    } else {
        sqlite3WindowDelete(parseDb(pParse), pWin);
    }
}

export fn sqlite3WindowLink(pSel: ?*Select, pWin: ?*W) callconv(.c) void {
    if (pSel) |sel| {
        const w = win(pWin);
        if (selPWin(sel) == null or sqlite3WindowCompare(null, selPWin(sel), pWin, 0) == 0) {
            w.pNextWin = selPWin(sel);
            if (selPWin(sel)) |head| {
                head.ppThis = &w.pNextWin;
            }
            selSetPWin(sel, pWin);
            w.ppThis = @ptrCast(@alignCast(B(sel) + Select_pWin));
        } else {
            if (sqlite3ExprListCompare(w.pPartition, selPWin(sel).?.pPartition, -1) != 0) {
                selSetSelFlags(sel, selSelFlags(sel) | SF_MultiPart);
            }
        }
    }
}

export fn sqlite3WindowCompare(pParse: ?*Parse, p1in: ?*const W, p2in: ?*const W, bFilter: c_int) callconv(.c) c_int {
    const p1 = @constCast(p1in).?;
    const p2 = @constCast(p2in).?;
    if (p1.eFrmType != p2.eFrmType) return 1;
    if (p1.eStart != p2.eStart) return 1;
    if (p1.eEnd != p2.eEnd) return 1;
    if (p1.eExclude != p2.eExclude) return 1;
    if (sqlite3ExprCompare(pParse, p1.pStart, p2.pStart, -1) != 0) return 1;
    if (sqlite3ExprCompare(pParse, p1.pEnd, p2.pEnd, -1) != 0) return 1;
    var res = sqlite3ExprListCompare(p1.pPartition, p2.pPartition, -1);
    if (res != 0) return res;
    res = sqlite3ExprListCompare(p1.pOrderBy, p2.pOrderBy, -1);
    if (res != 0) return res;
    if (bFilter != 0) {
        res = sqlite3ExprCompare(pParse, p1.pFilter, p2.pFilter, -1);
        if (res != 0) return res;
    }
    return 0;
}

// ─── codegen: code init ─────────────────────────────────────────────────────
export fn sqlite3WindowCodeInit(pParse: ?*Parse, pSelect: ?*Select) callconv(.c) void {
    // assert pSelect->pSrc->a[0].fg.isSubquery
    const pSrc: ?*SrcList = @ptrCast(@alignCast(rdPtr(pSelect, Select_pSrc)));
    const item0 = B(pSrc.?) + SrcList_a;
    // nEphExpr = a[0].u4.pSubq->pSelect->pEList->nExpr
    const pSubqPtr: *align(1) const ?*anyopaque = @ptrCast(item0 + SrcItem_u4_pSubq);
    const subSelect: ?*Select = @ptrCast(@alignCast(rdPtr(pSubqPtr.*, Subquery_pSelect)));
    const subEList = rdPtr(subSelect, Select_pEList);
    const nEphExpr = rdI32(subEList, ExprList_nExpr);

    const pMWin = selPWin(pSelect).?;
    const v = sqlite3GetVdbe(pParse);

    _ = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, pMWin.iEphCsr, nEphExpr);
    _ = sqlite3VdbeAddOp2(v, OP_OpenDup, pMWin.iEphCsr + 1, pMWin.iEphCsr);
    _ = sqlite3VdbeAddOp2(v, OP_OpenDup, pMWin.iEphCsr + 2, pMWin.iEphCsr);
    _ = sqlite3VdbeAddOp2(v, OP_OpenDup, pMWin.iEphCsr + 3, pMWin.iEphCsr);

    if (pMWin.pPartition) |part| {
        const nExpr = elNExpr(part);
        pMWin.regPart = parseNMem(pParse) + 1;
        parseSetNMem(pParse, parseNMem(pParse) + nExpr);
        _ = sqlite3VdbeAddOp3(v, OP_Null, 0, pMWin.regPart, pMWin.regPart + nExpr - 1);
    }

    pMWin.regOne = parseIncNMem(pParse);
    _ = sqlite3VdbeAddOp2(v, OP_Integer, 1, pMWin.regOne);

    if (pMWin.eExclude != 0) {
        pMWin.regStartRowid = parseIncNMem(pParse);
        pMWin.regEndRowid = parseIncNMem(pParse);
        pMWin.csrApp = parsePostIncNTab(pParse);
        _ = sqlite3VdbeAddOp2(v, OP_Integer, 1, pMWin.regStartRowid);
        _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, pMWin.regEndRowid);
        _ = sqlite3VdbeAddOp2(v, OP_OpenDup, pMWin.csrApp, pMWin.iEphCsr);
        return;
    }

    var pWin: ?*W = pMWin;
    while (pWin) |ww| : (pWin = ww.pNextWin) {
        const pf = ww.pWFunc;
        const fn_name = funcName(pf);
        if ((funcFlags(pf) & SQLITE_FUNC_MINMAX) != 0 and ww.eStart != TK_UNBOUNDED) {
            const pList = exprXList(ww.pOwner);
            const pKeyInfo = sqlite3KeyInfoFromExprList(pParse, pList, 0, 0);
            ww.csrApp = parsePostIncNTab(pParse);
            ww.regApp = parseNMem(pParse) + 1;
            parseSetNMem(pParse, parseNMem(pParse) + 3);
            // pWin->pWFunc->zName[1]=='i'  (min vs max). KeyInfo.aSortFlags is a
            // u8* POINTER (offset 24), so deref it then index [0].
            if (pKeyInfo != null and (fn_name.?)[1] == 'i') {
                const aSortFlags: [*]u8 = @ptrCast(rdPtr(pKeyInfo, KeyInfo_aSortFlags).?);
                aSortFlags[0] = KEYINFO_ORDER_DESC;
            }
            _ = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, ww.csrApp, 2);
            sqlite3VdbeAppendP4(v, pKeyInfo, P4_KEYINFO);
            _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, ww.regApp + 1);
        } else if (nameEq(fn_name, nth_valueName) or nameEq(fn_name, first_valueName)) {
            ww.regApp = parseNMem(pParse) + 1;
            ww.csrApp = parsePostIncNTab(pParse);
            parseSetNMem(pParse, parseNMem(pParse) + 2);
            _ = sqlite3VdbeAddOp2(v, OP_OpenDup, ww.csrApp, pMWin.iEphCsr);
        } else if (nameEq(fn_name, leadName) or nameEq(fn_name, lagName)) {
            ww.csrApp = parsePostIncNTab(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_OpenDup, ww.csrApp, pMWin.iEphCsr);
        }
    }
}

// WINDOW_*_INT eCond codes for windowCheckValue
const WINDOW_STARTING_NUM: c_int = 3;

fn windowCheckValue(pParse: ?*Parse, reg: c_int, eCond: c_int) void {
    const azErr = [_][*:0]const u8{
        "frame starting offset must be a non-negative integer",
        "frame ending offset must be a non-negative integer",
        "second argument to nth_value must be a positive integer",
        "frame starting offset must be a non-negative number",
        "frame ending offset must be a non-negative number",
    };
    const aOp = [_]c_int{ OP_Ge, OP_Ge, OP_Gt, OP_Ge, OP_Ge };
    const v = sqlite3GetVdbe(pParse);
    const regZero = sqlite3GetTempReg(pParse);
    _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, regZero);
    if (eCond >= WINDOW_STARTING_NUM) {
        const regString = sqlite3GetTempReg(pParse);
        _ = sqlite3VdbeAddOp4(v, OP_String8, 0, regString, 0, "", P4_STATIC);
        _ = sqlite3VdbeAddOp3(v, OP_Ge, regString, sqlite3VdbeCurrentAddr(v) + 2, reg);
        sqlite3VdbeChangeP5(v, SQLITE_AFF_NUMERIC | SQLITE_JUMPIFNULL);
    } else {
        _ = sqlite3VdbeAddOp2(v, OP_MustBeInt, reg, sqlite3VdbeCurrentAddr(v) + 2);
    }
    _ = sqlite3VdbeAddOp3(v, aOp[@intCast(eCond)], regZero, sqlite3VdbeCurrentAddr(v) + 2, reg);
    sqlite3VdbeChangeP5(v, SQLITE_AFF_NUMERIC);
    sqlite3MayAbort(pParse);
    _ = sqlite3VdbeAddOp2(v, OP_Halt, SQLITE_ERROR, OE_Abort);
    sqlite3VdbeAppendP4(v, @ptrCast(@constCast(azErr[@intCast(eCond)])), P4_STATIC);
    sqlite3ReleaseTempReg(pParse, regZero);
}

fn windowArgCount(pWin: ?*W) c_int {
    const pList = exprXList(win(pWin).pOwner);
    return if (pList) |l| elNExpr(l) else 0;
}

// ─── WindowCodeArg ──────────────────────────────────────────────────────────
const WindowCsrAndReg = struct { csr: c_int = 0, reg: c_int = 0 };
const WindowCodeArg = struct {
    pParse: ?*Parse = null,
    pMWin: ?*W = null,
    pVdbe: ?*Vdbe = null,
    addrGosub: c_int = 0,
    regGosub: c_int = 0,
    regArg: c_int = 0,
    eDelete: c_int = 0,
    regRowid: c_int = 0,
    start: WindowCsrAndReg = .{},
    current: WindowCsrAndReg = .{},
    end: WindowCsrAndReg = .{},
};

fn windowReadPeerValues(p: *WindowCodeArg, csr: c_int, reg: c_int) void {
    const pMWin = p.pMWin.?;
    const pOrderBy = pMWin.pOrderBy;
    if (pOrderBy) |ob| {
        const v = sqlite3GetVdbe(p.pParse);
        const pPart = pMWin.pPartition;
        const iColOff = pMWin.nBufferCol + (if (pPart) |pp| elNExpr(pp) else 0);
        var i: c_int = 0;
        const n = elNExpr(ob);
        while (i < n) : (i += 1) {
            _ = sqlite3VdbeAddOp3(v, OP_Column, csr, iColOff + i, reg + i);
        }
    }
}

const WINDOW_RETURN_ROW: c_int = 1;
const WINDOW_AGGINVERSE: c_int = 2;
const WINDOW_AGGSTEP: c_int = 3;

fn windowAggStep(p: *WindowCodeArg, pMWin: ?*W, csr: c_int, bInverse: c_int, reg: c_int) void {
    const pParse = p.pParse;
    const v = sqlite3GetVdbe(pParse);
    var pWin: ?*W = pMWin;
    while (pWin) |ww| : (pWin = ww.pNextWin) {
        const pFunc = ww.pWFunc;
        var regArg: c_int = undefined;
        var nArg: c_int = if (ww.bExprArgs != 0) 0 else windowArgCount(ww);
        var i: c_int = 0;
        var addrIf: c_int = 0;
        const fn_name = funcName(pFunc);

        while (i < nArg) : (i += 1) {
            if (i != 1 or !nameEq(fn_name, nth_valueName)) {
                _ = sqlite3VdbeAddOp3(v, OP_Column, csr, ww.iArgCol + i, reg + i);
            } else {
                _ = sqlite3VdbeAddOp3(v, OP_Column, pMWin.?.iEphCsr, ww.iArgCol + i, reg + i);
            }
        }
        regArg = reg;

        if (ww.pFilter != null) {
            const regTmp = sqlite3GetTempReg(pParse);
            _ = sqlite3VdbeAddOp3(v, OP_Column, csr, ww.iArgCol + nArg, regTmp);
            addrIf = sqlite3VdbeAddOp3(v, OP_IfNot, regTmp, 0, 1);
            sqlite3ReleaseTempReg(pParse, regTmp);
        }

        if (pMWin.?.regStartRowid == 0 and (funcFlags(pFunc) & SQLITE_FUNC_MINMAX) != 0 and ww.eStart != TK_UNBOUNDED) {
            const addrIsNull = sqlite3VdbeAddOp1(v, OP_IsNull, regArg);
            if (bInverse == 0) {
                _ = sqlite3VdbeAddOp2(v, OP_AddImm, ww.regApp + 1, 1);
                _ = sqlite3VdbeAddOp2(v, OP_SCopy, regArg, ww.regApp);
                _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, ww.regApp, 2, ww.regApp + 2);
                _ = sqlite3VdbeAddOp2(v, OP_IdxInsert, ww.csrApp, ww.regApp + 2);
            } else {
                _ = sqlite3VdbeAddOp4Int(v, OP_SeekGE, ww.csrApp, 0, regArg, 1);
                _ = sqlite3VdbeAddOp1(v, OP_Delete, ww.csrApp);
                sqlite3VdbeJumpHere(v, sqlite3VdbeCurrentAddr(v) - 2);
            }
            sqlite3VdbeJumpHere(v, addrIsNull);
        } else if (ww.regApp != 0) {
            _ = sqlite3VdbeAddOp2(v, OP_AddImm, ww.regApp + 1 - bInverse, 1);
        } else if (funcXSFunc(pFunc) != @as(?*const anyopaque, @ptrCast(&noopStepFunc))) {
            if (ww.bExprArgs != 0) {
                const iOp = sqlite3VdbeCurrentAddr(v);
                const ownerList = exprXList(ww.pOwner);
                nArg = elNExpr(ownerList);
                regArg = sqlite3GetTempRange(pParse, nArg);
                _ = sqlite3ExprCodeExprList(pParse, ownerList, regArg, 0, 0);

                var iOp2 = iOp;
                const iEnd = sqlite3VdbeCurrentAddr(v);
                while (iOp2 < iEnd) : (iOp2 += 1) {
                    const pOp = sqlite3VdbeGetOp(v, iOp2);
                    if (rdI32(pOp, off("VdbeOp_opcode", 0)) == OP_Column and
                        rdI32(pOp, off("VdbeOp_p1", 4)) == pMWin.?.iEphCsr)
                    {
                        wrI32(pOp, off("VdbeOp_p1", 4), csr);
                    }
                }
            }
            if ((funcFlags(pFunc) & SQLITE_FUNC_NEEDCOLL) != 0) {
                const arg0 = elItemExpr(exprXList(ww.pOwner), 0);
                const pColl = sqlite3ExprNNCollSeq(pParse, arg0);
                _ = sqlite3VdbeAddOp4(v, OP_CollSeq, 0, 0, 0, @ptrCast(pColl), P4_COLLSEQ);
            }
            _ = sqlite3VdbeAddOp3(v, if (bInverse != 0) OP_AggInverse else OP_AggStep, bInverse, regArg, ww.regAccum);
            sqlite3VdbeAppendP4(v, @ptrCast(pFunc), P4_FUNCDEF);
            sqlite3VdbeChangeP5(v, @as(u16, @truncate(@as(u32, @bitCast(nArg)))));
            if (ww.bExprArgs != 0) {
                sqlite3ReleaseTempRange(pParse, regArg, nArg);
            }
        }

        if (addrIf != 0) sqlite3VdbeJumpHere(v, addrIf);
    }
}

fn windowAggFinal(p: *WindowCodeArg, bFin: c_int) void {
    const pParse = p.pParse;
    const pMWin = p.pMWin.?;
    const v = sqlite3GetVdbe(pParse);
    var pWin: ?*W = pMWin;
    while (pWin) |ww| : (pWin = ww.pNextWin) {
        if (pMWin.regStartRowid == 0 and (funcFlags(ww.pWFunc) & SQLITE_FUNC_MINMAX) != 0 and ww.eStart != TK_UNBOUNDED) {
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, ww.regResult);
            _ = sqlite3VdbeAddOp1(v, OP_Last, ww.csrApp);
            _ = sqlite3VdbeAddOp3(v, OP_Column, ww.csrApp, 0, ww.regResult);
            sqlite3VdbeJumpHere(v, sqlite3VdbeCurrentAddr(v) - 2);
        } else if (ww.regApp != 0) {
            // assert
        } else {
            const nArg = windowArgCount(ww);
            if (bFin != 0) {
                _ = sqlite3VdbeAddOp2(v, OP_AggFinal, ww.regAccum, nArg);
                sqlite3VdbeAppendP4(v, @ptrCast(ww.pWFunc), P4_FUNCDEF);
                _ = sqlite3VdbeAddOp2(v, OP_Copy, ww.regAccum, ww.regResult);
                _ = sqlite3VdbeAddOp2(v, OP_Null, 0, ww.regAccum);
            } else {
                _ = sqlite3VdbeAddOp3(v, OP_AggValue, ww.regAccum, nArg, ww.regResult);
                sqlite3VdbeAppendP4(v, @ptrCast(ww.pWFunc), P4_FUNCDEF);
            }
        }
    }
}

fn windowFullScan(p: *WindowCodeArg) void {
    const pParse = p.pParse;
    const pMWin = p.pMWin.?;
    const v = p.pVdbe;

    var regCPeer: c_int = 0;
    var regPeer: c_int = 0;

    const csr = pMWin.csrApp;
    const nPeer: c_int = if (pMWin.pOrderBy) |ob| elNExpr(ob) else 0;

    const lblNext = sqlite3VdbeMakeLabel(pParse);
    const lblBrk = sqlite3VdbeMakeLabel(pParse);

    const regCRowid = sqlite3GetTempReg(pParse);
    const regRowid = sqlite3GetTempReg(pParse);
    if (nPeer != 0) {
        regCPeer = sqlite3GetTempRange(pParse, nPeer);
        regPeer = sqlite3GetTempRange(pParse, nPeer);
    }

    _ = sqlite3VdbeAddOp2(v, OP_Rowid, pMWin.iEphCsr, regCRowid);
    windowReadPeerValues(p, pMWin.iEphCsr, regCPeer);

    var pWin: ?*W = pMWin;
    while (pWin) |ww| : (pWin = ww.pNextWin) {
        _ = sqlite3VdbeAddOp2(v, OP_Null, 0, ww.regAccum);
    }

    _ = sqlite3VdbeAddOp3(v, OP_SeekGE, csr, lblBrk, pMWin.regStartRowid);
    const addrNext = sqlite3VdbeCurrentAddr(v);
    _ = sqlite3VdbeAddOp2(v, OP_Rowid, csr, regRowid);
    _ = sqlite3VdbeAddOp3(v, OP_Gt, pMWin.regEndRowid, lblBrk, regRowid);

    if (pMWin.eExclude == TK_CURRENT) {
        _ = sqlite3VdbeAddOp3(v, OP_Eq, regCRowid, lblNext, regRowid);
    } else if (pMWin.eExclude != TK_NO) {
        var addrEq: c_int = 0;
        var pKeyInfo: ?*KeyInfo = null;
        if (pMWin.pOrderBy != null) {
            pKeyInfo = sqlite3KeyInfoFromExprList(pParse, pMWin.pOrderBy, 0, 0);
        }
        if (pMWin.eExclude == TK_TIES) {
            addrEq = sqlite3VdbeAddOp3(v, OP_Eq, regCRowid, 0, regRowid);
        }
        if (pKeyInfo != null) {
            windowReadPeerValues(p, csr, regPeer);
            _ = sqlite3VdbeAddOp3(v, OP_Compare, regPeer, regCPeer, nPeer);
            sqlite3VdbeAppendP4(v, @ptrCast(pKeyInfo), P4_KEYINFO);
            const addr = sqlite3VdbeCurrentAddr(v) + 1;
            _ = sqlite3VdbeAddOp3(v, OP_Jump, addr, lblNext, addr);
        } else {
            _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, lblNext);
        }
        if (addrEq != 0) sqlite3VdbeJumpHere(v, addrEq);
    }

    windowAggStep(p, pMWin, csr, 0, p.regArg);

    sqlite3VdbeResolveLabel(v, lblNext);
    _ = sqlite3VdbeAddOp2(v, OP_Next, csr, addrNext);
    sqlite3VdbeJumpHere(v, addrNext - 1);
    sqlite3VdbeJumpHere(v, addrNext + 1);
    sqlite3ReleaseTempReg(pParse, regRowid);
    sqlite3ReleaseTempReg(pParse, regCRowid);
    if (nPeer != 0) {
        sqlite3ReleaseTempRange(pParse, regPeer, nPeer);
        sqlite3ReleaseTempRange(pParse, regCPeer, nPeer);
    }

    windowAggFinal(p, 1);
}

fn windowReturnOneRow(p: *WindowCodeArg) void {
    const pMWin = p.pMWin.?;
    const v = p.pVdbe;

    if (pMWin.regStartRowid != 0) {
        windowFullScan(p);
    } else {
        const pParse = p.pParse;
        var pWin: ?*W = pMWin;
        while (pWin) |ww| : (pWin = ww.pNextWin) {
            const pFunc = ww.pWFunc;
            const fn_name = funcName(pFunc);
            if (nameEq(fn_name, nth_valueName) or nameEq(fn_name, first_valueName)) {
                const csr = ww.csrApp;
                const lbl = sqlite3VdbeMakeLabel(pParse);
                const tmpReg = sqlite3GetTempReg(pParse);
                _ = sqlite3VdbeAddOp2(v, OP_Null, 0, ww.regResult);

                if (nameEq(fn_name, nth_valueName)) {
                    _ = sqlite3VdbeAddOp3(v, OP_Column, pMWin.iEphCsr, ww.iArgCol + 1, tmpReg);
                    windowCheckValue(pParse, tmpReg, 2);
                } else {
                    _ = sqlite3VdbeAddOp2(v, OP_Integer, 1, tmpReg);
                }
                _ = sqlite3VdbeAddOp3(v, OP_Add, tmpReg, ww.regApp, tmpReg);
                _ = sqlite3VdbeAddOp3(v, OP_Gt, ww.regApp + 1, lbl, tmpReg);
                _ = sqlite3VdbeAddOp3(v, OP_SeekRowid, csr, 0, tmpReg);
                _ = sqlite3VdbeAddOp3(v, OP_Column, csr, ww.iArgCol, ww.regResult);
                sqlite3VdbeResolveLabel(v, lbl);
                sqlite3ReleaseTempReg(pParse, tmpReg);
            } else if (nameEq(fn_name, leadName) or nameEq(fn_name, lagName)) {
                const nArg = elNExpr(exprXList(ww.pOwner));
                const csr = ww.csrApp;
                const lbl = sqlite3VdbeMakeLabel(pParse);
                const tmpReg = sqlite3GetTempReg(pParse);
                const iEph = pMWin.iEphCsr;

                if (nArg < 3) {
                    _ = sqlite3VdbeAddOp2(v, OP_Null, 0, ww.regResult);
                } else {
                    _ = sqlite3VdbeAddOp3(v, OP_Column, iEph, ww.iArgCol + 2, ww.regResult);
                }
                _ = sqlite3VdbeAddOp2(v, OP_Rowid, iEph, tmpReg);
                if (nArg < 2) {
                    const val: c_int = if (nameEq(fn_name, leadName)) 1 else -1;
                    _ = sqlite3VdbeAddOp2(v, OP_AddImm, tmpReg, val);
                } else {
                    const op: c_int = if (nameEq(fn_name, leadName)) OP_Add else OP_Subtract;
                    const tmpReg2 = sqlite3GetTempReg(pParse);
                    _ = sqlite3VdbeAddOp3(v, OP_Column, iEph, ww.iArgCol + 1, tmpReg2);
                    _ = sqlite3VdbeAddOp3(v, op, tmpReg2, tmpReg, tmpReg);
                    sqlite3ReleaseTempReg(pParse, tmpReg2);
                }

                _ = sqlite3VdbeAddOp3(v, OP_SeekRowid, csr, lbl, tmpReg);
                _ = sqlite3VdbeAddOp3(v, OP_Column, csr, ww.iArgCol, ww.regResult);
                sqlite3VdbeResolveLabel(v, lbl);
                sqlite3ReleaseTempReg(pParse, tmpReg);
            }
        }
    }
    _ = sqlite3VdbeAddOp2(v, OP_Gosub, p.regGosub, p.addrGosub);
}

fn windowInitAccum(pParse: ?*Parse, pMWin: ?*W) c_int {
    const v = sqlite3GetVdbe(pParse);
    var nArg: c_int = 0;
    var pWin: ?*W = pMWin;
    while (pWin) |ww| : (pWin = ww.pNextWin) {
        const pFunc = ww.pWFunc;
        _ = sqlite3VdbeAddOp2(v, OP_Null, 0, ww.regAccum);
        nArg = @max(nArg, windowArgCount(ww));
        const fn_name = funcName(pFunc);
        if (pMWin.?.regStartRowid == 0) {
            if (nameEq(fn_name, nth_valueName) or nameEq(fn_name, first_valueName)) {
                _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, ww.regApp);
                _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, ww.regApp + 1);
            }
            if ((funcFlags(pFunc) & SQLITE_FUNC_MINMAX) != 0 and ww.csrApp != 0) {
                _ = sqlite3VdbeAddOp1(v, OP_ResetSorter, ww.csrApp);
                _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, ww.regApp + 1);
            }
        }
    }
    const regArg = parseNMem(pParse) + 1;
    parseSetNMem(pParse, parseNMem(pParse) + nArg);
    return regArg;
}

fn windowCacheFrame(pMWin: ?*W) bool {
    if (pMWin.?.regStartRowid != 0) return true;
    var pWin: ?*W = pMWin;
    while (pWin) |ww| : (pWin = ww.pNextWin) {
        const fn_name = funcName(ww.pWFunc);
        if (nameEq(fn_name, nth_valueName) or nameEq(fn_name, first_valueName) or
            nameEq(fn_name, leadName) or nameEq(fn_name, lagName))
        {
            return true;
        }
    }
    return false;
}

fn windowIfNewPeer(pParse: ?*Parse, pOrderBy: ?*ExprList, regNew: c_int, regOld: c_int, addr: c_int) void {
    const v = sqlite3GetVdbe(pParse);
    if (pOrderBy) |ob| {
        const nVal = elNExpr(ob);
        const pKeyInfo = sqlite3KeyInfoFromExprList(pParse, ob, 0, 0);
        _ = sqlite3VdbeAddOp3(v, OP_Compare, regOld, regNew, nVal);
        sqlite3VdbeAppendP4(v, @ptrCast(pKeyInfo), P4_KEYINFO);
        _ = sqlite3VdbeAddOp3(v, OP_Jump, sqlite3VdbeCurrentAddr(v) + 1, addr, sqlite3VdbeCurrentAddr(v) + 1);
        _ = sqlite3VdbeAddOp3(v, OP_Copy, regNew, regOld, nVal - 1);
    } else {
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addr);
    }
}

fn windowCodeRangeTest(p: *WindowCodeArg, opIn: c_int, csr1: c_int, regVal: c_int, csr2: c_int, lbl: c_int) void {
    const pParse = p.pParse;
    const v = sqlite3GetVdbe(pParse);
    const pOrderBy = p.pMWin.?.pOrderBy.?;
    const reg1 = sqlite3GetTempReg(pParse);
    const reg2 = sqlite3GetTempReg(pParse);
    const regString = parseIncNMem(pParse);
    var arith: c_int = OP_Add;
    var op = opIn;
    const addrDone = sqlite3VdbeMakeLabel(pParse);

    windowReadPeerValues(p, csr1, reg1);
    windowReadPeerValues(p, csr2, reg2);

    if ((elItemSortFlags(pOrderBy, 0) & KEYINFO_ORDER_DESC) != 0) {
        switch (op) {
            OP_Ge => op = OP_Le,
            OP_Gt => op = OP_Lt,
            else => op = OP_Ge, // op==OP_Le
        }
        arith = OP_Subtract;
    }

    if ((elItemSortFlags(pOrderBy, 0) & KEYINFO_ORDER_BIGNULL) != 0) {
        const addr = sqlite3VdbeAddOp1(v, OP_NotNull, reg1);
        switch (op) {
            OP_Ge => _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, lbl),
            OP_Gt => _ = sqlite3VdbeAddOp2(v, OP_NotNull, reg2, lbl),
            OP_Le => _ = sqlite3VdbeAddOp2(v, OP_IsNull, reg2, lbl),
            else => {}, // OP_Lt no-op
        }
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addrDone);

        sqlite3VdbeJumpHere(v, addr);
        _ = sqlite3VdbeAddOp2(v, OP_IsNull, reg2, if (op == OP_Gt or op == OP_Ge) addrDone else lbl);
    }

    _ = sqlite3VdbeAddOp4(v, OP_String8, 0, regString, 0, "", P4_STATIC);
    const addrGe = sqlite3VdbeAddOp3(v, OP_Ge, regString, 0, reg1);
    if ((op == OP_Ge and arith == OP_Add) or (op == OP_Le and arith == OP_Subtract)) {
        _ = sqlite3VdbeAddOp3(v, op, reg2, lbl, reg1);
    }
    _ = sqlite3VdbeAddOp3(v, arith, regVal, reg1, reg1);
    sqlite3VdbeJumpHere(v, addrGe);

    _ = sqlite3VdbeAddOp3(v, op, reg2, lbl, reg1);
    const pColl = sqlite3ExprNNCollSeq(pParse, elItemExpr(pOrderBy, 0));
    sqlite3VdbeAppendP4(v, @ptrCast(pColl), P4_COLLSEQ);
    sqlite3VdbeChangeP5(v, SQLITE_NULLEQ);
    sqlite3VdbeResolveLabel(v, addrDone);

    sqlite3ReleaseTempReg(pParse, reg1);
    sqlite3ReleaseTempReg(pParse, reg2);
}

fn windowCodeOp(p: *WindowCodeArg, op: c_int, regCountdown: c_int, jumpOnEof: c_int) c_int {
    var csr: c_int = 0;
    var reg: c_int = 0;
    const pParse = p.pParse;
    const pMWin = p.pMWin.?;
    var ret: c_int = 0;
    const v = p.pVdbe;
    var addrContinue: c_int = 0;
    const bPeer: c_int = if (pMWin.eFrmType != TK_ROWS) 1 else 0;

    const lblDone = sqlite3VdbeMakeLabel(pParse);
    var addrNextRange: c_int = 0;

    if (op == WINDOW_AGGINVERSE and pMWin.eStart == TK_UNBOUNDED) {
        return 0;
    }

    if (regCountdown > 0) {
        if (pMWin.eFrmType == TK_RANGE) {
            addrNextRange = sqlite3VdbeCurrentAddr(v);
            if (op == WINDOW_AGGINVERSE) {
                if (pMWin.eStart == TK_FOLLOWING) {
                    windowCodeRangeTest(p, OP_Le, p.current.csr, regCountdown, p.start.csr, lblDone);
                } else {
                    windowCodeRangeTest(p, OP_Ge, p.start.csr, regCountdown, p.current.csr, lblDone);
                }
            } else {
                windowCodeRangeTest(p, OP_Gt, p.end.csr, regCountdown, p.current.csr, lblDone);
            }
        } else {
            _ = sqlite3VdbeAddOp3(v, OP_IfPos, regCountdown, lblDone, 1);
        }
    }

    if (op == WINDOW_RETURN_ROW and pMWin.regStartRowid == 0) {
        windowAggFinal(p, 0);
    }
    addrContinue = sqlite3VdbeCurrentAddr(v);

    if (pMWin.eStart == pMWin.eEnd and regCountdown != 0 and pMWin.eFrmType == TK_RANGE) {
        const regRowid1 = sqlite3GetTempReg(pParse);
        const regRowid2 = sqlite3GetTempReg(pParse);
        if (op == WINDOW_AGGINVERSE) {
            _ = sqlite3VdbeAddOp2(v, OP_Rowid, p.start.csr, regRowid1);
            _ = sqlite3VdbeAddOp2(v, OP_Rowid, p.end.csr, regRowid2);
            _ = sqlite3VdbeAddOp3(v, OP_Ge, regRowid2, lblDone, regRowid1);
        } else if (p.regRowid != 0) {
            _ = sqlite3VdbeAddOp2(v, OP_Rowid, p.end.csr, regRowid1);
            _ = sqlite3VdbeAddOp3(v, OP_Ge, p.regRowid, lblDone, regRowid1);
        }
        sqlite3ReleaseTempReg(pParse, regRowid1);
        sqlite3ReleaseTempReg(pParse, regRowid2);
    }

    switch (op) {
        WINDOW_RETURN_ROW => {
            csr = p.current.csr;
            reg = p.current.reg;
            windowReturnOneRow(p);
        },
        WINDOW_AGGINVERSE => {
            csr = p.start.csr;
            reg = p.start.reg;
            if (pMWin.regStartRowid != 0) {
                _ = sqlite3VdbeAddOp2(v, OP_AddImm, pMWin.regStartRowid, 1);
            } else {
                windowAggStep(p, pMWin, csr, 1, p.regArg);
            }
        },
        else => {
            // WINDOW_AGGSTEP
            csr = p.end.csr;
            reg = p.end.reg;
            if (pMWin.regStartRowid != 0) {
                _ = sqlite3VdbeAddOp2(v, OP_AddImm, pMWin.regEndRowid, 1);
            } else {
                windowAggStep(p, pMWin, csr, 0, p.regArg);
            }
        },
    }

    if (op == p.eDelete) {
        _ = sqlite3VdbeAddOp1(v, OP_Delete, csr);
        sqlite3VdbeChangeP5(v, OPFLAG_SAVEPOSITION);
    }

    if (jumpOnEof != 0) {
        _ = sqlite3VdbeAddOp2(v, OP_Next, csr, sqlite3VdbeCurrentAddr(v) + 2);
        ret = sqlite3VdbeAddOp0(v, OP_Goto);
    } else {
        _ = sqlite3VdbeAddOp2(v, OP_Next, csr, sqlite3VdbeCurrentAddr(v) + 1 + bPeer);
        if (bPeer != 0) {
            _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, lblDone);
        }
    }

    if (bPeer != 0) {
        const nReg: c_int = if (pMWin.pOrderBy) |ob| elNExpr(ob) else 0;
        const regTmp: c_int = if (nReg != 0) sqlite3GetTempRange(pParse, nReg) else 0;
        windowReadPeerValues(p, csr, regTmp);
        windowIfNewPeer(pParse, pMWin.pOrderBy, regTmp, reg, addrContinue);
        sqlite3ReleaseTempRange(pParse, regTmp, nReg);
    }

    if (addrNextRange != 0) {
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addrNextRange);
    }
    sqlite3VdbeResolveLabel(v, lblDone);
    return ret;
}

export fn sqlite3WindowDup(db: ?*anyopaque, pOwner: ?*Expr, pIn: ?*W) callconv(.c) ?*W {
    const p = win(pIn);
    const pNewAlloc = sqlite3DbMallocZero(db, @sizeOf(W));
    if (pNewAlloc) |alloc| {
        const pNew: *W = @ptrCast(@alignCast(alloc));
        pNew.zName = sqlite3DbStrDup(db, @ptrCast(p.zName));
        pNew.zBase = sqlite3DbStrDup(db, @ptrCast(p.zBase));
        pNew.pFilter = sqlite3ExprDup(db, p.pFilter, 0);
        pNew.pWFunc = p.pWFunc;
        pNew.pPartition = sqlite3ExprListDup(db, p.pPartition, 0);
        pNew.pOrderBy = sqlite3ExprListDup(db, p.pOrderBy, 0);
        pNew.eFrmType = p.eFrmType;
        pNew.eEnd = p.eEnd;
        pNew.eStart = p.eStart;
        pNew.eExclude = p.eExclude;
        pNew.regResult = p.regResult;
        pNew.regAccum = p.regAccum;
        pNew.iArgCol = p.iArgCol;
        pNew.iEphCsr = p.iEphCsr;
        pNew.bExprArgs = p.bExprArgs;
        pNew.pStart = sqlite3ExprDup(db, p.pStart, 0);
        pNew.pEnd = sqlite3ExprDup(db, p.pEnd, 0);
        pNew.pOwner = pOwner;
        pNew.bImplicitFrame = p.bImplicitFrame;
        return pNew;
    }
    return null;
}

export fn sqlite3WindowListDup(db: ?*anyopaque, pIn: ?*W) callconv(.c) ?*W {
    var pRet: ?*W = null;
    var pp: *?*W = &pRet;
    var pWin: ?*W = pIn;
    while (pWin) |ww| : (pWin = ww.pNextWin) {
        pp.* = sqlite3WindowDup(db, null, ww);
        if (pp.* == null) break;
        pp = &(pp.*.?.pNextWin);
    }
    return pRet;
}

fn windowExprGtZero(pParse: ?*Parse, pExpr: ?*Expr) c_int {
    var ret: c_int = 0;
    const db = parseDb(pParse);
    var pVal: ?*SqliteValue = null;
    _ = sqlite3ValueFromExpr(db, pExpr, dbEnc(db), @intCast(SQLITE_AFF_NUMERIC), &pVal);
    if (pVal != null and sqlite3_value_int(pVal) > 0) {
        ret = 1;
    }
    sqlite3ValueFree(pVal);
    return ret;
}

// ─── the main codegen entry point ───────────────────────────────────────────
export fn sqlite3WindowCodeStep(
    pParse: ?*Parse,
    p: ?*Select,
    pWInfo: ?*WhereInfo,
    regGosub: c_int,
    addrGosub: c_int,
) callconv(.c) void {
    const pMWin = selPWin(p).?;
    const pOrderBy = pMWin.pOrderBy;
    const v = sqlite3GetVdbe(pParse);
    var csrWrite: c_int = undefined;
    const pSrc: ?*SrcList = @ptrCast(@alignCast(rdPtr(p, Select_pSrc)));
    const item0 = B(pSrc.?) + SrcList_a;
    const csrInput = rdI32(@ptrCast(item0), SrcItem_iCursor);
    const pSTab: ?*Table = @ptrCast(rdPtr(@ptrCast(item0), SrcItem_pSTab));
    const nInput: c_int = rdU16(pSTab, Table_nCol); // Table.nCol is i16/u16
    var iInput: c_int = undefined;
    var addrGosubFlush: c_int = 0;
    var addrInteger: c_int = 0;
    var regNewPeer: c_int = 0;
    var regPeer: c_int = 0;
    var regFlushPart: c_int = 0;
    var s: WindowCodeArg = .{};
    var regStart: c_int = 0;
    var regEnd: c_int = 0;

    const lblWhereEnd = sqlite3VdbeMakeLabel(pParse);

    s.pParse = pParse;
    s.pMWin = pMWin;
    s.pVdbe = v;
    s.regGosub = regGosub;
    s.addrGosub = addrGosub;
    s.current.csr = pMWin.iEphCsr;
    csrWrite = s.current.csr + 1;
    s.start.csr = s.current.csr + 2;
    s.end.csr = s.current.csr + 3;

    switch (pMWin.eStart) {
        TK_FOLLOWING => {
            if (pMWin.eFrmType != TK_RANGE and windowExprGtZero(pParse, pMWin.pStart) != 0) {
                s.eDelete = WINDOW_RETURN_ROW;
            }
        },
        TK_UNBOUNDED => {
            if (!windowCacheFrame(pMWin)) {
                if (pMWin.eEnd == TK_PRECEDING) {
                    if (pMWin.eFrmType != TK_RANGE and windowExprGtZero(pParse, pMWin.pEnd) != 0) {
                        s.eDelete = WINDOW_AGGSTEP;
                    }
                } else {
                    s.eDelete = WINDOW_RETURN_ROW;
                }
            }
        },
        else => {
            s.eDelete = WINDOW_AGGINVERSE;
        },
    }

    const regNew = parseNMem(pParse) + 1;
    parseSetNMem(pParse, parseNMem(pParse) + nInput);
    const regRecord = parseIncNMem(pParse);
    s.regRowid = parseIncNMem(pParse);

    if (pMWin.eStart == TK_PRECEDING or pMWin.eStart == TK_FOLLOWING) {
        regStart = parseIncNMem(pParse);
    }
    if (pMWin.eEnd == TK_PRECEDING or pMWin.eEnd == TK_FOLLOWING) {
        regEnd = parseIncNMem(pParse);
    }

    if (pMWin.eFrmType != TK_ROWS) {
        const nPeer: c_int = if (pOrderBy) |ob| elNExpr(ob) else 0;
        regNewPeer = regNew + pMWin.nBufferCol;
        if (pMWin.pPartition) |pp| regNewPeer += elNExpr(pp);
        regPeer = parseNMem(pParse) + 1;
        parseSetNMem(pParse, parseNMem(pParse) + nPeer);
        s.start.reg = parseNMem(pParse) + 1;
        parseSetNMem(pParse, parseNMem(pParse) + nPeer);
        s.current.reg = parseNMem(pParse) + 1;
        parseSetNMem(pParse, parseNMem(pParse) + nPeer);
        s.end.reg = parseNMem(pParse) + 1;
        parseSetNMem(pParse, parseNMem(pParse) + nPeer);
    }

    iInput = 0;
    while (iInput < nInput) : (iInput += 1) {
        _ = sqlite3VdbeAddOp3(v, OP_Column, csrInput, iInput, regNew + iInput);
    }
    _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, regNew, nInput, regRecord);

    if (pMWin.pPartition) |pPart| {
        const nPart = elNExpr(pPart);
        const regNewPart = regNew + pMWin.nBufferCol;
        const pKeyInfo = sqlite3KeyInfoFromExprList(pParse, pPart, 0, 0);

        regFlushPart = parseIncNMem(pParse);
        const addr = sqlite3VdbeAddOp3(v, OP_Compare, regNewPart, pMWin.regPart, nPart);
        sqlite3VdbeAppendP4(v, @ptrCast(pKeyInfo), P4_KEYINFO);
        _ = sqlite3VdbeAddOp3(v, OP_Jump, addr + 2, addr + 4, addr + 2);
        addrGosubFlush = sqlite3VdbeAddOp1(v, OP_Gosub, regFlushPart);
        sqlite3VdbeComment(v, "call flush_partition");
        _ = sqlite3VdbeAddOp3(v, OP_Copy, regNewPart, pMWin.regPart, nPart - 1);
    }

    _ = sqlite3VdbeAddOp2(v, OP_NewRowid, csrWrite, s.regRowid);
    _ = sqlite3VdbeAddOp3(v, OP_Insert, csrWrite, regRecord, s.regRowid);
    const addrNe = sqlite3VdbeAddOp3(v, OP_Ne, pMWin.regOne, 0, s.regRowid);

    s.regArg = windowInitAccum(pParse, pMWin);

    if (regStart != 0) {
        sqlite3ExprCode(pParse, pMWin.pStart, regStart);
        windowCheckValue(pParse, regStart, 0 + (if (pMWin.eFrmType == TK_RANGE) @as(c_int, 3) else 0));
    }
    if (regEnd != 0) {
        sqlite3ExprCode(pParse, pMWin.pEnd, regEnd);
        windowCheckValue(pParse, regEnd, 1 + (if (pMWin.eFrmType == TK_RANGE) @as(c_int, 3) else 0));
    }

    if (pMWin.eFrmType != TK_RANGE and pMWin.eStart == pMWin.eEnd and regStart != 0) {
        const op: c_int = if (pMWin.eStart == TK_FOLLOWING) OP_Ge else OP_Le;
        const addrGe = sqlite3VdbeAddOp3(v, op, regStart, 0, regEnd);
        windowAggFinal(&s, 0);
        _ = sqlite3VdbeAddOp1(v, OP_Rewind, s.current.csr);
        windowReturnOneRow(&s);
        _ = sqlite3VdbeAddOp1(v, OP_ResetSorter, s.current.csr);
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, lblWhereEnd);
        sqlite3VdbeJumpHere(v, addrGe);
    }
    if (pMWin.eStart == TK_FOLLOWING and pMWin.eFrmType != TK_RANGE and regEnd != 0) {
        _ = sqlite3VdbeAddOp3(v, OP_Subtract, regStart, regEnd, regStart);
    }

    if (pMWin.eStart != TK_UNBOUNDED) {
        _ = sqlite3VdbeAddOp1(v, OP_Rewind, s.start.csr);
    }
    _ = sqlite3VdbeAddOp1(v, OP_Rewind, s.current.csr);
    _ = sqlite3VdbeAddOp1(v, OP_Rewind, s.end.csr);
    if (regPeer != 0 and pOrderBy != null) {
        const nE = elNExpr(pOrderBy.?);
        _ = sqlite3VdbeAddOp3(v, OP_Copy, regNewPeer, regPeer, nE - 1);
        _ = sqlite3VdbeAddOp3(v, OP_Copy, regPeer, s.start.reg, nE - 1);
        _ = sqlite3VdbeAddOp3(v, OP_Copy, regPeer, s.current.reg, nE - 1);
        _ = sqlite3VdbeAddOp3(v, OP_Copy, regPeer, s.end.reg, nE - 1);
    }

    _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, lblWhereEnd);

    sqlite3VdbeJumpHere(v, addrNe);

    if (regPeer != 0) {
        windowIfNewPeer(pParse, pOrderBy, regNewPeer, regPeer, lblWhereEnd);
    }
    if (pMWin.eStart == TK_FOLLOWING) {
        _ = windowCodeOp(&s, WINDOW_AGGSTEP, 0, 0);
        if (pMWin.eEnd != TK_UNBOUNDED) {
            if (pMWin.eFrmType == TK_RANGE) {
                const lbl = sqlite3VdbeMakeLabel(pParse);
                const addrNext = sqlite3VdbeCurrentAddr(v);
                windowCodeRangeTest(&s, OP_Ge, s.current.csr, regEnd, s.end.csr, lbl);
                _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
                _ = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 0);
                _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addrNext);
                sqlite3VdbeResolveLabel(v, lbl);
            } else {
                _ = windowCodeOp(&s, WINDOW_RETURN_ROW, regEnd, 0);
                _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
            }
        }
    } else if (pMWin.eEnd == TK_PRECEDING) {
        const bRPS = (pMWin.eStart == TK_PRECEDING and pMWin.eFrmType == TK_RANGE);
        _ = windowCodeOp(&s, WINDOW_AGGSTEP, regEnd, 0);
        if (bRPS) _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
        _ = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 0);
        if (!bRPS) _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
    } else {
        var addr: c_int = 0;
        _ = windowCodeOp(&s, WINDOW_AGGSTEP, 0, 0);
        if (pMWin.eEnd != TK_UNBOUNDED) {
            if (pMWin.eFrmType == TK_RANGE) {
                var lbl: c_int = 0;
                addr = sqlite3VdbeCurrentAddr(v);
                if (regEnd != 0) {
                    lbl = sqlite3VdbeMakeLabel(pParse);
                    windowCodeRangeTest(&s, OP_Ge, s.current.csr, regEnd, s.end.csr, lbl);
                }
                _ = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 0);
                _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
                if (regEnd != 0) {
                    _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addr);
                    sqlite3VdbeResolveLabel(v, lbl);
                }
            } else {
                if (regEnd != 0) {
                    addr = sqlite3VdbeAddOp3(v, OP_IfPos, regEnd, 0, 1);
                }
                _ = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 0);
                _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
                if (regEnd != 0) sqlite3VdbeJumpHere(v, addr);
            }
        }
    }

    sqlite3VdbeResolveLabel(v, lblWhereEnd);
    sqlite3WhereEnd(pWInfo);

    if (pMWin.pPartition != null) {
        addrInteger = sqlite3VdbeAddOp2(v, OP_Integer, 0, regFlushPart);
        sqlite3VdbeJumpHere(v, addrGosubFlush);
    }

    s.regRowid = 0;
    const addrEmpty = sqlite3VdbeAddOp1(v, OP_Rewind, csrWrite);
    if (pMWin.eEnd == TK_PRECEDING) {
        const bRPS = (pMWin.eStart == TK_PRECEDING and pMWin.eFrmType == TK_RANGE);
        _ = windowCodeOp(&s, WINDOW_AGGSTEP, regEnd, 0);
        if (bRPS) _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
        _ = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 0);
    } else if (pMWin.eStart == TK_FOLLOWING) {
        var addrStart: c_int = undefined;
        var addrBreak1: c_int = undefined;
        var addrBreak2: c_int = undefined;
        var addrBreak3: c_int = undefined;
        _ = windowCodeOp(&s, WINDOW_AGGSTEP, 0, 0);
        if (pMWin.eFrmType == TK_RANGE) {
            addrStart = sqlite3VdbeCurrentAddr(v);
            addrBreak2 = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 1);
            addrBreak1 = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 1);
        } else if (pMWin.eEnd == TK_UNBOUNDED) {
            addrStart = sqlite3VdbeCurrentAddr(v);
            addrBreak1 = windowCodeOp(&s, WINDOW_RETURN_ROW, regStart, 1);
            addrBreak2 = windowCodeOp(&s, WINDOW_AGGINVERSE, 0, 1);
        } else {
            _ = sqlite3VdbeAddOp3(v, OP_Subtract, regStart, regEnd, regEnd);
            _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, regStart);
            addrStart = sqlite3VdbeCurrentAddr(v);
            addrBreak1 = windowCodeOp(&s, WINDOW_RETURN_ROW, regEnd, 1);
            addrBreak2 = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 1);
        }
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addrStart);
        sqlite3VdbeJumpHere(v, addrBreak2);
        addrStart = sqlite3VdbeCurrentAddr(v);
        addrBreak3 = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 1);
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addrStart);
        sqlite3VdbeJumpHere(v, addrBreak1);
        sqlite3VdbeJumpHere(v, addrBreak3);
    } else {
        var addrStart: c_int = undefined;
        _ = windowCodeOp(&s, WINDOW_AGGSTEP, 0, 0);
        addrStart = sqlite3VdbeCurrentAddr(v);
        const addrBreak = windowCodeOp(&s, WINDOW_RETURN_ROW, 0, 1);
        _ = windowCodeOp(&s, WINDOW_AGGINVERSE, regStart, 0);
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, addrStart);
        sqlite3VdbeJumpHere(v, addrBreak);
    }
    sqlite3VdbeJumpHere(v, addrEmpty);

    _ = sqlite3VdbeAddOp1(v, OP_ResetSorter, s.current.csr);
    if (pMWin.pPartition != null) {
        if (pMWin.regStartRowid != 0) {
            _ = sqlite3VdbeAddOp2(v, OP_Integer, 1, pMWin.regStartRowid);
            _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, pMWin.regEndRowid);
        }
        sqlite3VdbeChangeP1(v, addrInteger, sqlite3VdbeCurrentAddr(v));
        _ = sqlite3VdbeAddOp1(v, OP_Return, regFlushPart);
    }
}
