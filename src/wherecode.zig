//! Zig port of SQLite's src/wherecode.c — VDBE code generation for the WHERE
//! clause loops.  This module contains the routines that emit the bulk of the
//! WHERE-loop bytecode: sqlite3WhereCodeOneLoopStart (index seeks/scans, the
//! IPK rowid cases, virtual-table VFilter, the OR-optimization loop, and the
//! per-term constraint coding), the EXPLAIN QUERY PLAN helpers
//! (sqlite3WhereExplainOneScan / sqlite3WhereExplainBloomFilter /
//! sqlite3WhereAddExplainText), the scan-status entries
//! (sqlite3WhereAddScanStatus, only with SQLITE_ENABLE_STMT_SCANSTATUS), and
//! sqlite3WhereRightJoinLoop.
//!
//! Every non-static function of wherecode.c is exported with the same C ABI;
//! static helpers become private Zig fns.  The Where* internal structs
//! (WhereInfo, WhereLevel, WhereLoop, WhereClause, WhereTerm, WhereMaskSet,
//! InLoop, WhereRightJoin) are shared with where.c / whereexpr.c (still C);
//! their fields are accessed via ground-truth offsets (src/c_layout.zig) using
//! the raw-memory helper idiom shared with expr.zig / build.zig.
//!
//! Config assumptions (verified against build.zig sqlite_flags):
//!   SQLITE_OMIT_EXPLAIN          OFF  -> explain fns compiled + exported.
//!   SQLITE_ENABLE_STMT_SCANSTATUS OFF -> sqlite3WhereAddScanStatus is NOT a
//!                                        symbol in production; gated on
//!                                        config.stmt_scanstatus (here false),
//!                                        scan-status side effects elided.
//!   SQLITE_OMIT_VIRTUALTABLE     OFF  -> vtab Case 1 present.
//!   SQLITE_OMIT_OR_OPTIMIZATION  OFF  -> OR Case 5 present.
//!   SQLITE_OMIT_SUBQUERY         OFF  -> codeINTerm present.
//!   SQLITE_LIKE_DOESNT_MATCH_BLOBS OFF -> LIKE-opt string fixup present.
//!   SQLITE_ENABLE_CURSOR_HINTS   OFF  -> codeCursorHint is a no-op.
//!   SQLITE_DEBUG / WHERETRACE_ENABLED handled via config.sqlite_debug:
//!     these add fields (WhereLoop.cId, WhereTerm.iTerm, WhereInfo.pWhere,
//!     rTotalCost) that shift offsets — handled via off() ground-truth.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers (copied from expr.zig) ──────────────────────────────
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

// Whether SQLITE_ENABLE_STMT_SCANSTATUS is on.  Not in build.zig flags, so OFF.
const stmt_scanstatus = @hasDecl(config, "stmt_scanstatus") and config.stmt_scanstatus;

// ─── struct field offsets (ground truth — see c_layout / probe report) ──────
// Config-stable structs (identical prod/debug):
const WhereRightJoin = struct {
    const iMatch = 0;
    const regBloom = 4;
    const regReturn = 8;
    const addrSubrtn = 12;
    const endSubrtn = 16;
};
const WhereLevel = struct {
    const iLeftJoin = 0;
    const iTabCur = 4;
    const iIdxCur = 8;
    const addrBrk = 12;
    const addrHalt = 16;
    const addrNxt = 20;
    const addrSkip = 24;
    const addrCont = 28;
    const addrFirst = 32;
    const addrBody = 36;
    const regBignull = 40;
    const addrBignull = 44;
    const iLikeRepCntr = 48; // u32
    const addrLikeRep = 52;
    const regFilter = 56;
    const pRJ = 64;
    const iFrom = 72; // u8
    const op = 73; // u8
    const p3 = 74; // u8
    const p5 = 75; // u8
    const p1 = 76; // int
    const p2 = 80; // int
    const u = 88; // union
    const u_in_nIn = 88; // int
    const u_in_aInLoop = 96; // ptr
    const u_pCoveringIdx = 88; // ptr
    const pWLoop = 104;
    const notReady = 112; // Bitmask u64
    const addrVisit = 120; // only if SCANSTATUS (sizeof grows)
};
const InLoop = struct {
    const sizeof = 20;
    const iCur = 0;
    const addrInTop = 4;
    const iBase = 8;
    const nPrefix = 12;
    const eEndLoopOp = 16; // u8
};
const WhereMaskSet = struct {
    const bVarSelect = 0;
    const n = 4;
    const ix = 8;
};
const WhereClause = struct {
    const pWInfo = 0;
    const pOuter = 8;
    const op = 16; // u8
    const hasOr = 17; // u8
    const nTerm = 20; // int
    const nSlot = 24; // int
    const nBase = 28; // int
    const a = 32; // ptr
};
// Config-divergent structs: prod fallback; debug values reported to orchestrator.
// WhereTerm: +iTerm(int) under SQLITE_DEBUG shifts u/prereq by 8.
const WhereTerm = struct {
    const sizeof_prod = 56;
    const pExpr = 0;
    const pWC = 8;
    const truthProb = 16; // i16
    const wtFlags = 18; // u16
    const eOperator = 20; // u16
    const nChild = 22; // u8
    const eMatchOp = 23; // u8
    const iParent = 24; // int
    const leftCursor = 28; // int
    // u union @ 32 prod / 40 debug:
    const u_x_leftColumn_prod = 32;
    const u_x_iField_prod = 36;
    const u_pOrInfo_prod = 32;
    const prereqRight_prod = 40; // Bitmask
    const prereqAll_prod = 48; // Bitmask
};
// WhereLoop: +cId(char)->+8 aligned under SQLITE_DEBUG.
const WhereLoop = struct {
    const prereq = 0;
    const maskSelf = 8;
    // prod offsets (debug = +8):
    const iTab_prod = 16; // u8
    const iSortIdx_prod = 17; // u8
    const rSetup_prod = 18; // i16
    const rRun_prod = 20; // i16
    const nOut_prod = 22; // i16
    const u_prod = 24;
    const u_btree_nEq_prod = 24; // u16
    const u_btree_nBtm_prod = 26; // u16
    const u_btree_nTop_prod = 28; // u16
    const u_btree_nDistinctCol_prod = 30; // u16
    const u_btree_pIndex_prod = 32; // ptr
    const u_btree_pOrderBy_prod = 40; // ptr
    const u_vtab_idxNum_prod = 24; // int
    const u_vtab_bits_prod = 28; // u32 word holding needFree/bOmitOffset/bIdxNumHex
    const u_vtab_isOrdered_prod = 29; // i8
    const u_vtab_omitMask_prod = 30; // u16
    const u_vtab_idxStr_prod = 32; // ptr
    const u_vtab_mHandleIn_prod = 40; // u32
    const wsFlags_prod = 48; // u32
    const nLTerm_prod = 52; // u16
    const nSkip_prod = 54; // u16
    const aLTerm_prod = 64; // ptr
};
// WhereInfo: +pWhere(ptr) & +rTotalCost under WHERETRACE (= SQLITE_DEBUG).
const WhereInfo = struct {
    const pParse = 0;
    const pTabList = 8;
    const pOrderBy = 16;
    const pResultSet = 24;
    // prod offsets (debug shifts those after pResultSet by 8 for pWhere):
    const pSelect_prod = 32;
    const wctrlFlags_prod = 60; // u16
    const nLevel_prod = 64; // u8
    const eOnePass_prod = 66; // u8
    const bits_prod = 68; // word after eDistinct holding bDeferredSeek etc.
    const revMask_prod = 96; // Bitmask
    const sWC_prod = 104; // WhereClause (embedded)
    const sMaskSet_prod = 592; // WhereMaskSet (embedded)
    const a_prod = 856; // WhereLevel[] (flex array base)
};

// WhereTerm helpers
inline fn wt_prereqAll(p: Ptr) u64 {
    return rd(u64, p, off("WhereTerm_prereqAll", WhereTerm.prereqAll_prod));
}
inline fn wt_prereqRight(p: Ptr) u64 {
    return rd(u64, p, off("WhereTerm_prereqRight", WhereTerm.prereqRight_prod));
}
inline fn wt_uxLeftColumn(p: Ptr) c_int {
    return rd(c_int, p, off("WhereTerm_u_x_leftColumn", WhereTerm.u_x_leftColumn_prod));
}
inline fn wt_uxIField(p: Ptr) c_int {
    return rd(c_int, p, off("WhereTerm_u_x_iField", WhereTerm.u_x_iField_prod));
}
inline fn wt_pOrInfo(p: Ptr) Ptr {
    return rdp(p, off("WhereTerm_u_pOrInfo", WhereTerm.u_pOrInfo_prod));
}
inline fn wtSize() usize {
    return off("sizeof_WhereTerm", WhereTerm.sizeof_prod);
}

// WhereLoop helpers (config-divergent group)
inline fn wl_wsFlags(p: Ptr) u32 {
    return rd(u32, p, off("WhereLoop_wsFlags", WhereLoop.wsFlags_prod));
}
inline fn wl_set_wsFlags(p: Ptr, v: u32) void {
    wr(u32, p, off("WhereLoop_wsFlags", WhereLoop.wsFlags_prod), v);
}
inline fn wl_nLTerm(p: Ptr) u16 {
    return rd(u16, p, off("WhereLoop_nLTerm", WhereLoop.nLTerm_prod));
}
inline fn wl_nSkip(p: Ptr) u16 {
    return rd(u16, p, off("WhereLoop_nSkip", WhereLoop.nSkip_prod));
}
inline fn wl_aLTermBase(_: Ptr) usize {
    return off("WhereLoop_aLTerm", WhereLoop.aLTerm_prod);
}
inline fn wl_aLTerm(p: Ptr) ?[*]Ptr {
    return @ptrCast(@alignCast(rdp(p, wl_aLTermBase(p))));
}
inline fn wl_aLTermAt(p: Ptr, i: usize) Ptr {
    const a = wl_aLTerm(p) orelse return null;
    return a[i];
}
inline fn wl_uBtreeNEq(p: Ptr) u16 {
    return rd(u16, p, off("WhereLoop_u_btree_nEq", WhereLoop.u_btree_nEq_prod));
}
inline fn wl_uBtreeNBtm(p: Ptr) u16 {
    return rd(u16, p, off("WhereLoop_u_btree_nBtm", WhereLoop.u_btree_nBtm_prod));
}
inline fn wl_uBtreeNTop(p: Ptr) u16 {
    return rd(u16, p, off("WhereLoop_u_btree_nTop", WhereLoop.u_btree_nTop_prod));
}
inline fn wl_uBtreePIndex(p: Ptr) Ptr {
    return rdp(p, off("WhereLoop_u_btree_pIndex", WhereLoop.u_btree_pIndex_prod));
}
inline fn wl_uVtabIdxNum(p: Ptr) c_int {
    return rd(c_int, p, off("WhereLoop_u_vtab_idxNum", WhereLoop.u_vtab_idxNum_prod));
}
inline fn wl_uVtabIdxStrBase(_: Ptr) usize {
    return off("WhereLoop_u_vtab_idxStr", WhereLoop.u_vtab_idxStr_prod);
}
inline fn wl_uVtabIdxStr(p: Ptr) Ptr {
    return rdp(p, wl_uVtabIdxStrBase(p));
}
inline fn wl_set_uVtabIdxStr(p: Ptr, v: Ptr) void {
    wr(Ptr, p, wl_uVtabIdxStrBase(p), v);
}
inline fn wl_uVtabMHandleIn(p: Ptr) u32 {
    return rd(u32, p, off("WhereLoop_u_vtab_mHandleIn", WhereLoop.u_vtab_mHandleIn_prod));
}
inline fn wl_uVtabOmitMask(p: Ptr) u16 {
    return rd(u16, p, off("WhereLoop_u_vtab_omitMask", WhereLoop.u_vtab_omitMask_prod));
}
inline fn wl_uVtabBits(p: Ptr) u32 {
    return rd(u32, p, off("WhereLoop_u_vtab_bits", WhereLoop.u_vtab_bits_prod));
}
inline fn wl_set_uVtabBits(p: Ptr, v: u32) void {
    wr(u32, p, off("WhereLoop_u_vtab_bits", WhereLoop.u_vtab_bits_prod), v);
}
const VTAB_needFree: u32 = 0x1;
const VTAB_bOmitOffset: u32 = 0x2;
const VTAB_bIdxNumHex: u32 = 0x4;
inline fn wl_uVtabNeedFree(p: Ptr) bool {
    return (wl_uVtabBits(p) & VTAB_needFree) != 0;
}
inline fn wl_clear_uVtabNeedFree(p: Ptr) void {
    wl_set_uVtabBits(p, wl_uVtabBits(p) & ~VTAB_needFree);
}
inline fn wl_uVtabBOmitOffset(p: Ptr) bool {
    return (wl_uVtabBits(p) & VTAB_bOmitOffset) != 0;
}
inline fn wl_uVtabBIdxNumHex(p: Ptr) bool {
    return (wl_uVtabBits(p) & VTAB_bIdxNumHex) != 0;
}
inline fn wl_maskSelf(p: Ptr) u64 {
    return rd(u64, p, WhereLoop.maskSelf);
}
inline fn wl_nOut(p: Ptr) i16 {
    return rd(i16, p, off("WhereLoop_nOut", WhereLoop.nOut_prod));
}

// WhereInfo helpers
inline fn wi_pParse(p: Ptr) Ptr {
    return rdp(p, WhereInfo.pParse);
}
inline fn wi_pTabList(p: Ptr) Ptr {
    return rdp(p, WhereInfo.pTabList);
}
inline fn wi_pSelect(p: Ptr) Ptr {
    return rdp(p, off("WhereInfo_pSelect", WhereInfo.pSelect_prod));
}
inline fn wi_wctrlFlags(p: Ptr) u16 {
    return rd(u16, p, off("WhereInfo_wctrlFlags", WhereInfo.wctrlFlags_prod));
}
inline fn wi_nLevel(p: Ptr) u8 {
    return rd(u8, p, off("WhereInfo_nLevel", WhereInfo.nLevel_prod));
}
inline fn wi_eOnePass(p: Ptr) u8 {
    return rd(u8, p, off("WhereInfo_eOnePass", WhereInfo.eOnePass_prod));
}
inline fn wi_revMask(p: Ptr) u64 {
    return rd(u64, p, off("WhereInfo_revMask", WhereInfo.revMask_prod));
}
inline fn wi_sWC(p: Ptr) Ptr {
    return fieldPtr(p, off("WhereInfo_sWC", WhereInfo.sWC_prod));
}
inline fn wi_sMaskSet(p: Ptr) Ptr {
    return fieldPtr(p, off("WhereInfo_sMaskSet", WhereInfo.sMaskSet_prod));
}
inline fn wi_aBase(_: Ptr) usize {
    return off("WhereInfo_a", WhereInfo.a_prod);
}
inline fn wi_levelAt(p: Ptr, i: usize) Ptr {
    return fieldPtr(p, wi_aBase(p) + i * levelSize());
}
inline fn levelSize() usize {
    return off("sizeof_WhereLevel", 120);
}
// bitfield byte holding bDeferredSeek(0x01)/untestedTerms(0x02), just after eDistinct.
const WHEREINFO_bits_bDeferredSeek: u8 = 0x01;
const WHEREINFO_bits_untestedTerms: u8 = 0x02;
inline fn wi_bitsOff() usize {
    return off("WhereInfo_bits", WhereInfo.bits_prod);
}
inline fn wi_set_bDeferredSeek(p: Ptr) void {
    const o = wi_bitsOff();
    wr(u8, p, o, rd(u8, p, o) | WHEREINFO_bits_bDeferredSeek);
}
inline fn wi_set_untestedTerms(p: Ptr) void {
    const o = wi_bitsOff();
    wr(u8, p, o, rd(u8, p, o) | WHEREINFO_bits_untestedTerms);
}

// SrcList / SrcItem (config-stable)
const SrcList = struct {
    const nSrc = 0; // int
    const nAlloc = 4; // int
    const a = 8;
};
const SrcItem = struct {
    const sizeof = 72;
    const zName = 0;
    const pSTab = 16;
    const fg = 24; // 32-bit bitfield word
    const iCursor = 28; // int
    const u4_ = 64; // union (pSubq / zDatabase)
};
// SrcItem.fg bitfield masks (within 32-bit word at SrcItem.fg):
const FG_jointype_mask: u32 = 0xFF;
const FG_isSubquery: u32 = 0x00000400;
const FG_isMaterialized: u32 = 0x00002000;
const FG_viaCoroutine: u32 = 0x00004000;
const FG_isRecursive: u32 = 0x00008000;
const FG_fromExists: u32 = 0x04000000;
inline fn srcItemAt(pList: Ptr, i: usize) Ptr {
    return fieldPtr(pList, SrcList.a + i * SrcItem.sizeof);
}
inline fn si_fg(p: Ptr) u32 {
    return rd(u32, p, SrcItem.fg);
}
inline fn si_set_fg(p: Ptr, v: u32) void {
    wr(u32, p, SrcItem.fg, v);
}
inline fn si_jointype(p: Ptr) u8 {
    return rd(u8, p, SrcItem.fg);
}
inline fn si_iCursor(p: Ptr) c_int {
    return rd(c_int, p, SrcItem.iCursor);
}
inline fn si_pSTab(p: Ptr) Ptr {
    return rdp(p, SrcItem.pSTab);
}
inline fn si_u4pSubq(p: Ptr) Ptr {
    return rdp(p, SrcItem.u4_);
}

// Subquery (config-stable; offsets from c_layout)
inline fn sq_regReturn(p: Ptr) c_int {
    return rd(c_int, p, off("Subquery_regReturn", 12));
}
inline fn sq_addrFillSub(p: Ptr) c_int {
    return rd(c_int, p, off("Subquery_addrFillSub", 8));
}
inline fn sq_pSelect(p: Ptr) Ptr {
    return rdp(p, off("Subquery_pSelect", 0));
}
inline fn sq_regResult(p: Ptr) c_int {
    return rd(c_int, p, off("Subquery_regResult", 16));
}

// Index (config-stable)
inline fn idx_zName(p: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(p, off("Index_zName", 0)));
}
inline fn idx_pTable(p: Ptr) Ptr {
    return rdp(p, off("Index_pTable", 24));
}
inline fn idx_aiColumn(p: Ptr) ?[*]i16 {
    return @ptrCast(@alignCast(rdp(p, off("Index_aiColumn", 8))));
}
inline fn idx_aSortOrder(p: Ptr) ?[*]u8 {
    return @ptrCast(rdp(p, off("Index_aSortOrder", 56)));
}
inline fn idx_aiRowLogEst(p: Ptr) ?[*]i16 {
    return @ptrCast(@alignCast(rdp(p, off("Index_aiRowLogEst", 16))));
}
inline fn idx_nColumn(p: Ptr) i16 {
    return rd(i16, p, off("Index_nColumn", 96));
}
inline fn idx_nKeyCol(p: Ptr) i16 {
    return rd(i16, p, off("Index_nKeyCol", 94));
}
inline fn idx_onError(p: Ptr) u8 {
    return rd(u8, p, off("Index_onError", 98));
}
inline fn idx_pPartIdxWhere(p: Ptr) Ptr {
    return rdp(p, off("Index_pPartIdxWhere", 72));
}
// idxType bitfield: low 2 bits of byte at Index_idxType (probe: 99).
inline fn idx_isPrimaryKey(p: Ptr) bool {
    return (rd(u8, p, off("Index_idxType", 99)) & 0x3) == SQLITE_IDXTYPE_PRIMARYKEY;
}

// Table (config-stable)
inline fn tab_zName(p: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(p, off("Table_zName", 0)));
}
inline fn tab_aCol(p: Ptr) Ptr {
    return rdp(p, off("Table_aCol", 8));
}
inline fn tab_iPKey(p: Ptr) i16 {
    return rd(i16, p, off("Table_iPKey", 52));
}
inline fn tab_nCol(p: Ptr) i16 {
    return rd(i16, p, off("Table_nCol", 54));
}
inline fn tab_tabFlags(p: Ptr) u32 {
    return rd(u32, p, off("Table_tabFlags", 48));
}
inline fn tab_hasRowid(p: Ptr) bool {
    return (tab_tabFlags(p) & TF_WithoutRowid) == 0;
}
const colSize = 16;
inline fn col_zCnName(pCol: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(pCol, off("Column_zCnName", 0)));
}
inline fn col_notNull(pCol: Ptr) bool {
    return (rd(u8, pCol, off("Column_notNull", 8)) & 0x1) != 0;
}
inline fn tab_colAt(pTab: Ptr, i: usize) Ptr {
    return fieldPtr(tab_aCol(pTab), i * colSize);
}

// Expr (config-stable; offsets from c_layout / expr.zig)
inline fn expr_op(p: Ptr) u8 {
    return rd(u8, p, off("Expr_op", 0));
}
inline fn expr_set_op(p: Ptr, v: u8) void {
    wr(u8, p, off("Expr_op", 0), v);
}
inline fn expr_flags(p: Ptr) u32 {
    return rd(u32, p, off("Expr_flags", 4));
}
inline fn expr_pLeft(p: Ptr) Ptr {
    return rdp(p, off("Expr_pLeft", 16));
}
inline fn expr_set_pLeft(p: Ptr, v: Ptr) void {
    wr(Ptr, p, off("Expr_pLeft", 16), v);
}
inline fn expr_pRight(p: Ptr) Ptr {
    return rdp(p, off("Expr_pRight", 24));
}
inline fn expr_set_pRight(p: Ptr, v: Ptr) void {
    wr(Ptr, p, off("Expr_pRight", 24), v);
}
inline fn expr_iTable(p: Ptr) c_int {
    return rd(c_int, p, off("Expr_iTable", 44));
}
inline fn expr_set_iTable(p: Ptr, v: c_int) void {
    wr(c_int, p, off("Expr_iTable", 44), v);
}
// Expr.x union (pList/pSelect) — same offset; from c_layout Expr_x
inline fn expr_xPSelect(p: Ptr) Ptr {
    return rdp(p, off("Expr_x", 32));
}
inline fn expr_xPList(p: Ptr) Ptr {
    return rdp(p, off("Expr_x", 32));
}
const EP_OuterON: u32 = 0x000001;
const EP_InnerON: u32 = 0x000002;
const EP_Collate: u32 = 0x000200;
const EP_xIsSelect: u32 = 0x001000;
const EP_Subquery: u32 = 0x400000;
inline fn exprHasProperty(p: Ptr, mask: u32) bool {
    return (expr_flags(p) & mask) != 0;
}
inline fn exprUseXSelect(p: Ptr) bool {
    return (expr_flags(p) & EP_xIsSelect) != 0;
}

// ExprList (for nExpr access in IN handling)
inline fn el_nExpr(p: Ptr) c_int {
    return rd(c_int, p, off("ExprList_nExpr", 0));
}

// Select pEList / iOffset
inline fn sel_pEList(p: Ptr) Ptr {
    return rdp(p, off("Select_pEList", 24));
}
inline fn sel_pPrior(p: Ptr) Ptr {
    return rdp(p, off("Select_pPrior", 72));
}
inline fn sel_iOffset(p: Ptr) c_int {
    return rd(c_int, p, off("Select_iOffset", 12));
}

// Parse fields
inline fn parse_pVdbe(p: Ptr) Ptr {
    return rdp(p, off("Parse_pVdbe", 16));
}
inline fn parse_db(p: Ptr) Ptr {
    return rdp(p, off("Parse_db", 0));
}
inline fn parse_nMem(p: Ptr) c_int {
    return rd(c_int, p, off("Parse_nMem", 60));
}
inline fn parse_inc_nMem(p: Ptr) c_int {
    const o = off("Parse_nMem", 60);
    const v = rd(c_int, p, o) + 1;
    wr(c_int, p, o, v);
    return v;
}
inline fn parse_add_nMem(p: Ptr, n: c_int) void {
    const o = off("Parse_nMem", 60);
    wr(c_int, p, o, rd(c_int, p, o) + n);
}
inline fn parse_nTab(p: Ptr) c_int {
    return rd(c_int, p, off("Parse_nTab", 56));
}
inline fn parse_postinc_nTab(p: Ptr) c_int {
    const o = off("Parse_nTab", 56);
    const v = rd(c_int, p, o);
    wr(c_int, p, o, v + 1);
    return v;
}
inline fn parse_nErr(p: Ptr) c_int {
    return rd(c_int, p, off("Parse_nErr", 52));
}
inline fn parse_addrExplain(p: Ptr) c_int {
    return rd(c_int, p, off("Parse_addrExplain", 312));
}
inline fn parse_withinRJSubrtn(p: Ptr) u8 {
    return rd(u8, p, off("Parse_withinRJSubrtn", 35));
}
inline fn parse_inc_withinRJSubrtn(p: Ptr) void {
    const o = off("Parse_withinRJSubrtn", 35);
    wr(u8, p, o, rd(u8, p, o) +% 1);
}
inline fn parse_dec_withinRJSubrtn(p: Ptr) void {
    const o = off("Parse_withinRJSubrtn", 35);
    wr(u8, p, o, rd(u8, p, o) -% 1);
}

// sqlite3 db
inline fn db_mallocFailed(db: Ptr) bool {
    return rd(u8, db, off("sqlite3_mallocFailed", 103)) != 0;
}
inline fn db_flags(db: Ptr) u64 {
    return rd(u64, db, off("sqlite3_flags", 48));
}
inline fn db_dbOptFlags(db: Ptr) u32 {
    return rd(u32, db, off("sqlite3_dbOptFlags", 96));
}

// VdbeOp fields
inline fn vop_opcode(p: Ptr) u8 {
    return rd(u8, p, off("VdbeOp_opcode", 0));
}
inline fn vop_p1(p: Ptr) c_int {
    return rd(c_int, p, off("VdbeOp_p1", 4));
}
inline fn vop_p2(p: Ptr) c_int {
    return rd(c_int, p, off("VdbeOp_p2", 8));
}
inline fn vop_set_p2(p: Ptr, v: c_int) void {
    wr(c_int, p, off("VdbeOp_p2", 8), v);
}
inline fn vop_p3(p: Ptr) c_int {
    return rd(c_int, p, off("VdbeOp_p3", 12));
}
inline fn vop_set_p3(p: Ptr, v: c_int) void {
    wr(c_int, p, off("VdbeOp_p3", 12), v);
}
inline fn vop_set_p5(p: Ptr, v: u16) void {
    wr(u16, p, off("VdbeOp_p5", 2), v);
}
inline fn vop_set_p4z(p: Ptr, v: Ptr) void {
    wr(Ptr, p, off("VdbeOp_p4", 16), v);
}
inline fn vop_p4z(p: Ptr) Ptr {
    return rdp(p, off("VdbeOp_p4", 16));
}
inline fn vop_set_p4type(p: Ptr, v: i8) void {
    wr(i8, p, off("VdbeOp_p4type", 1), v);
}

// ─── constants ──────────────────────────────────────────────────────────────
const XN_ROWID: c_int = -1;
const XN_EXPR: c_int = -2;

const SQLITE_OK: c_int = 0;
const SQLITE_MAX_LENGTH: c_int = 1000000000;
const SQLITE_PRINTF_INTERNAL: u8 = 0x01;
const SQLITE_JUMPIFNULL: c_int = 0x10;
const SQLITE_IDXTYPE_PRIMARYKEY: u8 = 2;
const TF_WithoutRowid: u32 = 0x00000080;
const JT_LEFT: u8 = 0x08;
const JT_RIGHT: u8 = 0x10;
const JT_LTORJ: u8 = 0x40;

const SQLITE_AFF_BLOB: u8 = 0x41;
const SQLITE_AFF_NUMERIC: u8 = 0x43;
const SQLITE_SO_ASC: u8 = 0;
const SQLITE_SO_DESC: u8 = 1;

const SQLITE_CursorHints: u32 = 0x00000400;
const SQLITE_StmtScanStatus: u64 = 0x00000400;
const SQLITE_INDEX_CONSTRAINT_OFFSET: u8 = 74;
const SQLITE_STMTSTATUS_FULLSCAN_STEP: u8 = 1;
const OPFLAG_USESEEKRESULT: u16 = 0x10;

// TK_* operator codes
const TK_EQ: u8 = 54;
const TK_IS: u8 = 45;
const TK_ISNULL: u8 = 51;
const TK_IN: u8 = 50;
const TK_GT: u8 = 55;
const TK_LE: u8 = 56;
const TK_LT: u8 = 57;
const TK_GE: u8 = 58;
const TK_AND: c_int = 44;
const TK_REGISTER: u8 = 176;
const TK_VECTOR: u8 = 177;
const TK_SELECT: u8 = 139;
const TK_STRING: u8 = 118;

// WhereTerm.wtFlags
const TERM_CODED: u16 = 0x0004;
const TERM_VIRTUAL: u16 = 0x0002;
const TERM_LIKE: u16 = 0x0400;
const TERM_LIKECOND: u16 = 0x0200;
const TERM_LIKEOPT: u16 = 0x0100;
const TERM_IS: u16 = 0x0800;
const TERM_VNULL: u16 = 0x0080;
const TERM_VARSELECT: u16 = 0x1000;
const TERM_SLICE: u16 = 0x8000;

// WO_* operator masks
const WO_IN: u16 = 0x0001;
const WO_EQ: u16 = 0x0002;
// WO_LE/WO_GE = WO_EQ<<(TK_xx-TK_EQ). TK_EQ=54. WO_LE=0x0008, WO_GE=0x0020.
const WO_LE_v: u16 = WO_EQ << (TK_LE - TK_EQ);
const WO_GE_v: u16 = WO_EQ << (TK_GE - TK_EQ);
const WO_AUX: u16 = 0x0040;
const WO_IS: u16 = 0x0080;
const WO_ISNULL: u16 = 0x0100;
const WO_OR: u16 = 0x0200;
const WO_AND: u16 = 0x0400;
const WO_EQUIV: u16 = 0x0800;
const WO_ROWVAL: u16 = 0x2000;

// WHERE_* wsFlags
const WHERE_COLUMN_EQ: u32 = 0x00000001;
const WHERE_COLUMN_RANGE: u32 = 0x00000002;
const WHERE_COLUMN_IN: u32 = 0x00000004;
const WHERE_CONSTRAINT: u32 = 0x0000000f;
const WHERE_TOP_LIMIT: u32 = 0x00000010;
const WHERE_BTM_LIMIT: u32 = 0x00000020;
const WHERE_BOTH_LIMIT: u32 = 0x00000030;
const WHERE_IDX_ONLY: u32 = 0x00000040;
const WHERE_IPK: u32 = 0x00000100;
const WHERE_INDEXED: u32 = 0x00000200;
const WHERE_VIRTUALTABLE: u32 = 0x00000400;
const WHERE_IN_ABLE: u32 = 0x00000800;
const WHERE_ONEROW: u32 = 0x00001000;
const WHERE_MULTI_OR: u32 = 0x00002000;
const WHERE_AUTO_INDEX: u32 = 0x00004000;
const WHERE_UNQ_WANTED: u32 = 0x00010000;
const WHERE_PARTIALIDX: u32 = 0x00020000;
const WHERE_IN_EARLYOUT: u32 = 0x00040000;
const WHERE_BIGNULL_SORT: u32 = 0x00080000;
const WHERE_IN_SEEKSCAN: u32 = 0x00100000;
const WHERE_TRANSCONS: u32 = 0x00200000;
const WHERE_EXPRIDX: u32 = 0x04000000;

// WHERE_* wctrlFlags (sqlite3WhereBegin)
const WHERE_ORDERBY_MIN: u16 = 0x0001;
const WHERE_ORDERBY_MAX: u16 = 0x0002;
const WHERE_DUPLICATES_OK: u16 = 0x0010;
const WHERE_OR_SUBCLAUSE: u16 = 0x0020;
const WHERE_RIGHT_JOIN: u16 = 0x1000;

// ONEPASS
const ONEPASS_OFF: u8 = 0;

// OP_* opcodes (from vendor opcodes.h)
const op = struct {
    const VFilter: c_int = 6;
    const Goto: c_int = 9;
    const Gosub: c_int = 10;
    const InitCoroutine: c_int = 11;
    const Yield: c_int = 12;
    const MustBeInt: c_int = 13;
    const If: c_int = 16;
    const IfNot: c_int = 17;
    const SeekLT: c_int = 21;
    const SeekLE: c_int = 22;
    const SeekGE: c_int = 23;
    const SeekGT: c_int = 24;
    const NotFound: c_int = 28;
    const Found: c_int = 29;
    const SeekRowid: c_int = 30;
    const Last: c_int = 32;
    const Rewind: c_int = 36;
    const Prev: c_int = 39;
    const Next: c_int = 40;
    const IdxLE: c_int = 41;
    const IdxGT: c_int = 42;
    const IdxLT: c_int = 45;
    const IdxGE: c_int = 46;
    const RowSetTest: c_int = 49;
    const IsNull: c_int = 51;
    const Le: c_int = 56;
    const Lt: c_int = 57;
    const Ge: c_int = 58;
    const Gt: c_int = 55;
    const VNext: c_int = 65;
    const Filter: c_int = 66;
    const Return: c_int = 69;
    const BeginSubrtn: c_int = 76;
    const Null: c_int = 77;
    const Integer: c_int = 73;
    const AddImm: c_int = 88;
    const Column: c_int = 96;
    const Affinity: c_int = 98;
    const MakeRecord: c_int = 99;
    const String8: c_int = 118;
    const OpenEphemeral: c_int = 120;
    const SeekScan: c_int = 126;
    const SeekHit: c_int = 127;
    const Rowid: c_int = 137;
    const NullRow: c_int = 138;
    const IdxInsert: c_int = 140;
    const DeferredSeek: c_int = 143;
    const VInitIn: c_int = 177;
    const FilterAdd: c_int = 185;
    const CursorHint: c_int = 187;
    const Noop: c_int = 189;
    const Explain: c_int = 190;
};

// P4_* (vdbe.h)
const P4_STATIC: c_int = -1;
const P4_DYNAMIC: c_int = -7;
const P4_KEYINFO: c_int = -9;
const P4_EXPR: c_int = -10;
const P4_INTARRAY: c_int = -15;

// IN_INDEX (sqlite3FindInIndex returns)
const IN_INDEX_ROWID: c_int = 1;
const IN_INDEX_INDEX_DESC: c_int = 4;
const IN_INDEX_NOOP: c_int = 5;
const IN_INDEX_LOOP: u32 = 0x0004;

// ─── extern ABI functions (resolved at link time from still-C modules) ──────
const c = struct {
    // memory
    extern fn sqlite3DbMallocRawNN(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbMallocZero(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbStrDup(db: Ptr, z: ?[*:0]const u8) ?[*:0]u8;
    extern fn sqlite3DbFree(db: Ptr, p: Ptr) void;
    extern fn sqlite3DbFreeNN(db: Ptr, p: Ptr) void;
    extern fn sqlite3DbNNFreeNN(db: Ptr, p: Ptr) void;
    extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
    // str accum
    extern fn sqlite3StrAccumInit(p: Ptr, db: Ptr, zBase: ?[*]u8, n: c_int, mx: c_int) void;
    extern fn sqlite3_str_append(p: Ptr, z: ?[*]const u8, n: c_int) void;
    extern fn sqlite3_str_appendall(p: Ptr, z: ?[*:0]const u8) void;
    extern fn sqlite3_str_appendf(p: Ptr, fmt: ?[*:0]const u8, ...) void;
    extern fn sqlite3StrAccumFinish(p: Ptr) ?[*:0]u8;
    // vdbe codegen
    extern fn sqlite3VdbeAddOp0(v: Ptr, op_: c_int) c_int;
    extern fn sqlite3VdbeAddOp1(v: Ptr, op_: c_int, p1: c_int) c_int;
    extern fn sqlite3VdbeAddOp2(v: Ptr, op_: c_int, p1: c_int, p2: c_int) c_int;
    extern fn sqlite3VdbeAddOp3(v: Ptr, op_: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
    extern fn sqlite3VdbeAddOp4(v: Ptr, op_: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*:0]const u8, p4type: c_int) c_int;
    extern fn sqlite3VdbeAddOp4Int(v: Ptr, op_: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
    extern fn sqlite3VdbeGoto(v: Ptr, addr: c_int) c_int;
    extern fn sqlite3VdbeChangeP1(v: Ptr, addr: c_int, p1: c_int) void;
    extern fn sqlite3VdbeChangeP2(v: Ptr, addr: c_int, p2: c_int) void;
    extern fn sqlite3VdbeChangeP5(v: Ptr, p5: u16) void;
    extern fn sqlite3VdbeChangeP4(v: Ptr, addr: c_int, zP4: ?[*]const u8, n: c_int) void;
    extern fn sqlite3VdbeJumpHere(v: Ptr, addr: c_int) void;
    extern fn sqlite3VdbeSetP4KeyInfo(p: Ptr, pIdx: Ptr) void;
    extern fn sqlite3VdbeGetOp(v: Ptr, addr: c_int) Ptr;
    extern fn sqlite3VdbeGetLastOp(v: Ptr) Ptr;
    extern fn sqlite3VdbeMakeLabel(p: Ptr) c_int;
    extern fn sqlite3VdbeResolveLabel(v: Ptr, x: c_int) void;
    extern fn sqlite3VdbeCurrentAddr(v: Ptr) c_int;
    extern fn sqlite3VdbeComment(v: Ptr, fmt: ?[*:0]const u8, ...) void;
    extern fn sqlite3VdbeNoopComment(v: Ptr, fmt: ?[*:0]const u8, ...) void;
    extern fn sqlite3VdbeExplain(pParse: Ptr, bPush: u8, fmt: ?[*:0]const u8, ...) c_int;
    extern fn sqlite3VdbeExplainPop(pParse: Ptr) void;
    // no-op macro unless SQLITE_ENABLE_STMT_SCANSTATUS (OFF in this build).
    fn sqlite3VdbeScanStatus(_: Ptr, _: c_int, _: c_int, _: c_int, _: i16, _: ?[*:0]const u8) void {}
    extern fn sqlite3VdbeScanStatusRange(v: Ptr, a: c_int, b: c_int, cc: c_int) void;
    extern fn sqlite3VdbeNoJumpsOutsideSubrtn(v: Ptr, a: c_int, b: c_int, cc: c_int) void;
    // temp regs
    extern fn sqlite3GetTempReg(p: Ptr) c_int;
    extern fn sqlite3ReleaseTempReg(p: Ptr, r: c_int) void;
    extern fn sqlite3GetTempRange(p: Ptr, n: c_int) c_int;
    extern fn sqlite3ReleaseTempRange(p: Ptr, r: c_int, n: c_int) void;
    // expr codegen / analysis
    extern fn sqlite3ExprCode(p: Ptr, e: Ptr, target: c_int) void;
    extern fn sqlite3ExprCodeTarget(p: Ptr, e: Ptr, target: c_int) c_int;
    extern fn sqlite3ExprCodeTemp(p: Ptr, e: Ptr, pReg: *c_int) c_int;
    extern fn sqlite3ExprIfFalse(p: Ptr, e: Ptr, dest: c_int, jumpIfNull: c_int) void;
    extern fn sqlite3ExprIsVector(e: Ptr) c_int;
    extern fn sqlite3ExprCanBeNull(e: Ptr) c_int;
    extern fn sqlite3ExprCompare(p: Ptr, a: Ptr, b: Ptr, iTab: c_int) c_int;
    extern fn sqlite3CompareAffinity(e: Ptr, aff2: u8) u8;
    extern fn sqlite3ExprNeedsNoAffinityChange(e: Ptr, aff: u8) c_int;
    extern fn sqlite3VectorFieldSubexpr(e: Ptr, i: c_int) Ptr;
    extern fn sqlite3ExprContainsSubquery(e: Ptr) c_int;
    extern fn sqlite3ExprCoveredByIndex(e: Ptr, iCur: c_int, pIdx: Ptr) c_int;
    extern fn sqlite3ExprDup(db: Ptr, e: Ptr, flags: c_int) Ptr;
    extern fn sqlite3ExprDelete(db: Ptr, e: Ptr) void;
    extern fn sqlite3ExprAnd(p: Ptr, a: Ptr, b: Ptr) Ptr;
    extern fn sqlite3PExpr(p: Ptr, op_: c_int, a: Ptr, b: Ptr) Ptr;
    extern fn sqlite3Expr(db: Ptr, op_: c_int, z: ?[*:0]const u8) Ptr;
    extern fn sqlite3ExprListAppend(p: Ptr, list: Ptr, e: Ptr) Ptr;
    extern fn sqlite3ExprListDelete(db: Ptr, list: Ptr) void;
    extern fn sqlite3ExprCodeGetColumnOfTable(v: Ptr, pTab: Ptr, iTabCur: c_int, iCol: c_int, regOut: c_int) void;
    // misc helpers
    extern fn sqlite3IndexAffinityStr(db: Ptr, pIdx: Ptr) ?[*:0]const u8;
    extern fn sqlite3PrimaryKeyIndex(pTab: Ptr) Ptr;
    extern fn sqlite3TableColumnToIndex(pIdx: Ptr, iCol: i16) c_int;
    extern fn sqlite3TableColumnToStorage(pTab: Ptr, iCol: i16) i16;
    extern fn sqlite3FindInIndex(p: Ptr, e: Ptr, flags: u32, prRhsHasNull: ?*c_int, aiMap: ?[*]c_int, piTab: ?*c_int) c_int;
    extern fn sqlite3CodeRhsOfIN(p: Ptr, e: Ptr, iTab: c_int, isRowid: c_int) void;
    extern fn sqlite3CodeSubselect(p: Ptr, e: Ptr) c_int;
    extern fn sqlite3LogEstToInt(x: i16) u64;
    extern fn sqlite3IsLikeFunction(db: Ptr, e: Ptr, pIsNocase: ?*c_int, aWc: ?[*]u8) c_int;
    // where.c (still C)
    extern fn sqlite3WhereGetMask(pMaskSet: Ptr, iCursor: c_int) u64;
    extern fn sqlite3WhereFindTerm(pWC: Ptr, iCur: c_int, iColumn: c_int, notReady: u64, op_: u32, pIdx: Ptr) Ptr;
    extern fn sqlite3WhereRealloc(pWInfo: Ptr, pOld: Ptr, nByte: u64) Ptr;
    extern fn sqlite3WhereBegin(p: Ptr, pTabList: Ptr, pWhere: Ptr, pOrderBy: Ptr, pResultSet: Ptr, pSelect: Ptr, wctrlFlags: u16, iAuxArg: c_int) Ptr;
    extern fn sqlite3WhereEnd(pWInfo: Ptr) void;
    extern fn sqlite3WhereContinueLabel(pWInfo: Ptr) c_int;
    extern fn sqlite3WhereUsesDeferredSeek(pWInfo: Ptr) c_int;
};

// ─── inline macro re-implementations ────────────────────────────────────────
inline fn SMASKBIT32(n: usize) u32 {
    return if (n <= 31) (@as(u32, 1) << @intCast(n)) else 0;
}
inline fn vdbeComment(v: Ptr, comptime fmt: [*:0]const u8, args: anytype) void {
    if (config.sqlite_debug) {
        @call(.auto, c.sqlite3VdbeComment, .{ v, fmt } ++ args);
    }
}
inline fn vdbeNoopComment(v: Ptr, comptime fmt: [*:0]const u8, args: anytype) void {
    if (config.sqlite_debug) {
        @call(.auto, c.sqlite3VdbeNoopComment, .{ v, fmt } ++ args);
    }
}
inline fn explainQueryPlan(pParse: Ptr, bPush: u8, comptime fmt: [*:0]const u8, args: anytype) void {
    _ = @call(.auto, c.sqlite3VdbeExplain, .{ pParse, bPush, fmt } ++ args);
}
inline fn explainQueryPlanPop(pParse: Ptr) void {
    c.sqlite3VdbeExplainPop(pParse);
}
inline fn isStmtScanStatus(db: Ptr) bool {
    return stmt_scanstatus and (db_flags(db) & SQLITE_StmtScanStatus) != 0;
}
inline fn optimizationDisabled(db: Ptr, mask: u32) bool {
    return (db_dbOptFlags(db) & mask) != 0;
}

// ════════════════════════════════════════════════════════════════════════════
// EXPLAIN helpers
// ════════════════════════════════════════════════════════════════════════════

fn explainIndexColumnName(pIdx: Ptr, i: c_int) [*:0]const u8 {
    const col = idx_aiColumn(pIdx).?[@intCast(i)];
    if (col == @as(i16, @intCast(XN_EXPR))) return "<expr>";
    if (col == @as(i16, @intCast(XN_ROWID))) return "rowid";
    const pTab = idx_pTable(pIdx);
    return col_zCnName(tab_colAt(pTab, @intCast(col))).?;
}

fn explainAppendTerm(pStr: Ptr, pIdx: Ptr, nTerm: c_int, iTerm: c_int, bAnd: c_int, zOp: [*:0]const u8) void {
    if (bAnd != 0) c.sqlite3_str_append(pStr, " AND ", 5);
    if (nTerm > 1) c.sqlite3_str_append(pStr, "(", 1);
    var i: c_int = 0;
    while (i < nTerm) : (i += 1) {
        if (i != 0) c.sqlite3_str_append(pStr, ",", 1);
        c.sqlite3_str_appendall(pStr, explainIndexColumnName(pIdx, iTerm + i));
    }
    if (nTerm > 1) c.sqlite3_str_append(pStr, ")", 1);
    c.sqlite3_str_append(pStr, zOp, 1);
    if (nTerm > 1) c.sqlite3_str_append(pStr, "(", 1);
    i = 0;
    while (i < nTerm) : (i += 1) {
        if (i != 0) c.sqlite3_str_append(pStr, ",", 1);
        c.sqlite3_str_append(pStr, "?", 1);
    }
    if (nTerm > 1) c.sqlite3_str_append(pStr, ")", 1);
}

fn explainIndexRange(pStr: Ptr, pLoop: Ptr) void {
    const pIndex = wl_uBtreePIndex(pLoop);
    const nEq: c_int = wl_uBtreeNEq(pLoop);
    const nSkip: c_int = wl_nSkip(pLoop);
    const wsFlags = wl_wsFlags(pLoop);
    if (nEq == 0 and (wsFlags & (WHERE_BTM_LIMIT | WHERE_TOP_LIMIT)) == 0) return;
    c.sqlite3_str_append(pStr, " (", 2);
    var i: c_int = 0;
    while (i < nEq) : (i += 1) {
        const z = explainIndexColumnName(pIndex, i);
        if (i != 0) c.sqlite3_str_append(pStr, " AND ", 5);
        c.sqlite3_str_appendf(pStr, if (i >= nSkip) "%s=?" else "ANY(%s)", z);
    }
    const j = i;
    if (wsFlags & WHERE_BTM_LIMIT != 0) {
        explainAppendTerm(pStr, pIndex, wl_uBtreeNBtm(pLoop), j, i, ">");
        i = 1;
    }
    if (wsFlags & WHERE_TOP_LIMIT != 0) {
        explainAppendTerm(pStr, pIndex, wl_uBtreeNTop(pLoop), j, i, "<");
    }
    c.sqlite3_str_append(pStr, ")", 1);
}

export fn sqlite3WhereAddExplainText(pParse: Ptr, addr: c_int, pTabList: Ptr, pLevel: Ptr, wctrlFlags: u16) void {
    // !defined(SQLITE_DEBUG) guard: in production, only emit if EXPLAIN==2 or scanstatus.
    if (!config.sqlite_debug) {
        const tl = parseToplevel(pParse);
        const explain = rd(u8, tl, off("Parse_explain", 299));
        if (!(explain == 2 or isStmtScanStatus(parse_db(pParse)))) return;
    }
    const v = parse_pVdbe(pParse);
    const pOp = c.sqlite3VdbeGetOp(v, addr);
    const pItem = srcItemAt(pTabList, @intCast(rd(u8, pLevel, WhereLevel.iFrom)));
    const db = parse_db(pParse);
    if (db_mallocFailed(db)) return;

    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    const flags = wl_wsFlags(pLoop);

    const isSearch = (flags & (WHERE_BTM_LIMIT | WHERE_TOP_LIMIT)) != 0 or
        ((flags & WHERE_VIRTUALTABLE) == 0 and wl_uBtreeNEq(pLoop) > 0) or
        (wctrlFlags & (WHERE_ORDERBY_MIN | WHERE_ORDERBY_MAX)) != 0;

    var strBuf: [128]u8 = undefined;
    var zBuf: [100]u8 = undefined;
    const str: Ptr = @ptrCast(&strBuf);
    c.sqlite3StrAccumInit(str, db, &zBuf, zBuf.len, SQLITE_MAX_LENGTH);
    setPrintfInternal(str);
    c.sqlite3_str_appendf(str, "%s %S%s", @as([*:0]const u8, if (isSearch) "SEARCH" else "SCAN"), pItem, @as([*:0]const u8, if (siFromExists(pItem)) " EXISTS" else ""));

    if ((flags & (WHERE_IPK | WHERE_VIRTUALTABLE)) == 0) {
        var zFmt: ?[*:0]const u8 = null;
        const pIdx = wl_uBtreePIndex(pLoop);
        if (!tab_hasRowid(si_pSTab(pItem)) and idx_isPrimaryKey(pIdx)) {
            if (isSearch) zFmt = "PRIMARY KEY";
        } else if (flags & WHERE_PARTIALIDX != 0) {
            zFmt = "AUTOMATIC PARTIAL COVERING INDEX";
        } else if (flags & WHERE_AUTO_INDEX != 0) {
            zFmt = "AUTOMATIC COVERING INDEX";
        } else if (flags & (WHERE_IDX_ONLY | WHERE_EXPRIDX) != 0) {
            zFmt = "COVERING INDEX %s";
        } else {
            zFmt = "INDEX %s";
        }
        if (zFmt) |fmt| {
            c.sqlite3_str_append(str, " USING ", 7);
            c.sqlite3_str_appendf(str, fmt, idx_zName(pIdx));
            explainIndexRange(str, pLoop);
        }
    } else if ((flags & WHERE_IPK) != 0 and (flags & WHERE_CONSTRAINT) != 0) {
        var cRangeOp: u8 = undefined;
        const zRowid: [*:0]const u8 = "rowid";
        c.sqlite3_str_appendf(str, " USING INTEGER PRIMARY KEY (%s", zRowid);
        if (flags & (WHERE_COLUMN_EQ | WHERE_COLUMN_IN) != 0) {
            cRangeOp = '=';
        } else if ((flags & WHERE_BOTH_LIMIT) == WHERE_BOTH_LIMIT) {
            c.sqlite3_str_appendf(str, ">? AND %s", zRowid);
            cRangeOp = '<';
        } else if (flags & WHERE_BTM_LIMIT != 0) {
            cRangeOp = '>';
        } else {
            cRangeOp = '<';
        }
        c.sqlite3_str_appendf(str, "%c?)", @as(c_int, cRangeOp));
    } else if ((flags & WHERE_VIRTUALTABLE) != 0) {
        c.sqlite3_str_appendall(str, " VIRTUAL TABLE INDEX ");
        c.sqlite3_str_appendf(str, if (wl_uVtabBIdxNumHex(pLoop)) "0x%x:%s" else "%d:%s", wl_uVtabIdxNum(pLoop), wl_uVtabIdxStr(pLoop));
    }
    if (si_jointype(pItem) & JT_LEFT != 0) {
        c.sqlite3_str_appendf(str, " LEFT-JOIN", @as(c_int, 0));
    }
    // SQLITE_EXPLAIN_ESTIMATED_ROWS is OFF; skip.

    // assert pOp->opcode==OP_Explain; free old p4 then set new
    c.sqlite3DbFree(db, vop_p4z(pOp));
    vop_set_p4type(pOp, @intCast(P4_DYNAMIC));
    vop_set_p4z(pOp, @ptrCast(c.sqlite3StrAccumFinish(str)));
}

export fn sqlite3WhereExplainOneScan(pParse: Ptr, pTabList: Ptr, pLevel: Ptr, wctrlFlags: u16) c_int {
    var ret: c_int = 0;
    if (!config.sqlite_debug) {
        const tl = parseToplevel(pParse);
        const explain = rd(u8, tl, off("Parse_explain", 299));
        if (!(explain == 2 or isStmtScanStatus(parse_db(pParse)))) return 0;
    }
    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    if ((wl_wsFlags(pLoop) & WHERE_MULTI_OR) == 0 and (wctrlFlags & WHERE_OR_SUBCLAUSE) == 0) {
        const v = parse_pVdbe(pParse);
        const addr = c.sqlite3VdbeCurrentAddr(v);
        ret = c.sqlite3VdbeAddOp3(v, op.Explain, addr, parse_addrExplain(pParse), wl_nOut(pLoop));
        sqlite3WhereAddExplainText(pParse, addr, pTabList, pLevel, wctrlFlags);
    }
    return ret;
}

export fn sqlite3WhereExplainBloomFilter(pParse: Ptr, pWInfo: Ptr, pLevel: Ptr) c_int {
    var ret: c_int = 0;
    const pItem = srcItemAt(wi_pTabList(pWInfo), @intCast(rd(u8, pLevel, WhereLevel.iFrom)));
    const v = parse_pVdbe(pParse);
    const db = parse_db(pParse);

    var strBuf: [128]u8 = undefined;
    var zBuf: [100]u8 = undefined;
    const str: Ptr = @ptrCast(&strBuf);
    c.sqlite3StrAccumInit(str, db, &zBuf, zBuf.len, SQLITE_MAX_LENGTH);
    setPrintfInternal(str);
    c.sqlite3_str_appendf(str, "BLOOM FILTER ON %S (", pItem);
    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    if (wl_wsFlags(pLoop) & WHERE_IPK != 0) {
        const pTab = si_pSTab(pItem);
        if (tab_iPKey(pTab) >= 0) {
            c.sqlite3_str_appendf(str, "%s=?", col_zCnName(tab_colAt(pTab, @intCast(tab_iPKey(pTab)))));
        } else {
            c.sqlite3_str_appendf(str, "rowid=?", @as(c_int, 0));
        }
    } else {
        const nSkip: c_int = wl_nSkip(pLoop);
        const nEq: c_int = wl_uBtreeNEq(pLoop);
        var i: c_int = nSkip;
        while (i < nEq) : (i += 1) {
            const z = explainIndexColumnName(wl_uBtreePIndex(pLoop), i);
            if (i > nSkip) c.sqlite3_str_append(str, " AND ", 5);
            c.sqlite3_str_appendf(str, "%s=?", z);
        }
    }
    c.sqlite3_str_append(str, ")", 1);
    const zMsg = c.sqlite3StrAccumFinish(str);
    ret = c.sqlite3VdbeAddOp4(v, op.Explain, c.sqlite3VdbeCurrentAddr(v), parse_addrExplain(pParse), 0, zMsg, @intCast(P4_DYNAMIC));
    c.sqlite3VdbeScanStatus(v, c.sqlite3VdbeCurrentAddr(v) - 1, 0, 0, 0, null);
    return ret;
}

// sqlite3WhereAddScanStatus: only a real symbol under SQLITE_ENABLE_STMT_SCANSTATUS.
// That flag is OFF in build.zig, so this is compiled out (no export, callers
// invoke the no-op macro version inline).  Gated via comptime to match.
comptime {
    if (stmt_scanstatus) {
        @export(&whereAddScanStatusImpl, .{ .name = "sqlite3WhereAddScanStatus", .linkage = .strong });
    }
}
fn whereAddScanStatusImpl(v: Ptr, pSrclist: Ptr, pLvl: Ptr, addrExplain: c_int) callconv(.c) void {
    // Not reachable in this build (scanstatus OFF).  Full impl omitted.
    _ = .{ v, pSrclist, pLvl, addrExplain };
}
// Inline no-op for our own callers when scanstatus is off.
inline fn whereAddScanStatus(v: Ptr, pSrclist: Ptr, pLvl: Ptr, addrExplain: c_int) void {
    if (stmt_scanstatus) whereAddScanStatusImpl(v, pSrclist, pLvl, addrExplain);
    _ = .{ v, pSrclist, pLvl, addrExplain };
}

// ════════════════════════════════════════════════════════════════════════════
// Static helpers
// ════════════════════════════════════════════════════════════════════════════

fn parseToplevel(pParse: Ptr) Ptr {
    const tl = rdp(pParse, off("Parse_pToplevel", 136));
    return if (tl) |t| t else pParse;
}
fn setPrintfInternal(str: Ptr) void {
    // StrAccum.printfFlags |= SQLITE_PRINTF_INTERNAL.  Offset via c_layout.
    const o = off("StrAccum_printfFlags", 29);
    wr(u8, str, o, rd(u8, str, o) | SQLITE_PRINTF_INTERNAL);
}
fn siFromExists(pItem: Ptr) bool {
    return (si_fg(pItem) & FG_fromExists_bit()) != 0;
}
inline fn FG_fromExists_bit() u32 {
    return FG_fromExists;
}
inline fn siViaCoroutine(pItem: Ptr) bool {
    return (si_fg(pItem) & FG_viaCoroutine) != 0;
}
inline fn siIsSubquery(pItem: Ptr) bool {
    return (si_fg(pItem) & FG_isSubquery) != 0;
}

fn disableTerm(pLevel: Ptr, pTermIn: Ptr) void {
    var pTerm = pTermIn;
    var nLoop: c_int = 0;
    while ((rd(u16, pTerm, WhereTerm.wtFlags) & TERM_CODED) == 0 and
        (rd(c_int, pLevel, WhereLevel.iLeftJoin) == 0 or exprHasProperty(rdp(pTerm, WhereTerm.pExpr), EP_OuterON)) and
        (rd(u64, pLevel, WhereLevel.notReady) & wt_prereqAll(pTerm)) == 0)
    {
        const wtf = rd(u16, pTerm, WhereTerm.wtFlags);
        if (nLoop != 0 and (wtf & TERM_LIKE) != 0) {
            wr(u16, pTerm, WhereTerm.wtFlags, wtf | TERM_LIKECOND);
        } else {
            wr(u16, pTerm, WhereTerm.wtFlags, wtf | TERM_CODED);
        }
        const iParent = rd(c_int, pTerm, WhereTerm.iParent);
        if (iParent < 0) break;
        const pWC = rdp(pTerm, WhereTerm.pWC);
        const aBase = rdp(pWC, WhereClause.a);
        pTerm = fieldPtr(aBase, @as(usize, @intCast(iParent)) * wtSize());
        // nChild--
        const nChild = rd(u8, pTerm, WhereTerm.nChild) -% 1;
        wr(u8, pTerm, WhereTerm.nChild, nChild);
        if (nChild != 0) break;
        nLoop += 1;
    }
}

fn codeApplyAffinity(pParse: Ptr, baseReg: c_int, nIn: c_int, zAffIn: ?[*:0]u8) void {
    const v = parse_pVdbe(pParse);
    if (zAffIn == null) return;
    var zAff = zAffIn.?;
    var n = nIn;
    var b = baseReg;
    // skip BLOB/NONE at start
    while (n > 0 and zAff[0] <= SQLITE_AFF_BLOB) {
        n -= 1;
        b += 1;
        zAff += 1;
    }
    while (n > 1 and zAff[@intCast(n - 1)] <= SQLITE_AFF_BLOB) {
        n -= 1;
    }
    if (n > 0) {
        _ = c.sqlite3VdbeAddOp4(v, op.Affinity, b, n, 0, @ptrCast(zAff), n);
    }
}

fn updateRangeAffinityStr(pRight: Ptr, n: c_int, zAff: [*]u8) void {
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const p = c.sqlite3VectorFieldSubexpr(pRight, i);
        if (c.sqlite3CompareAffinity(p, zAff[@intCast(i)]) == SQLITE_AFF_BLOB or
            c.sqlite3ExprNeedsNoAffinityChange(p, zAff[@intCast(i)]) != 0)
        {
            zAff[@intCast(i)] = SQLITE_AFF_BLOB;
        }
    }
}

fn adjustOrderByCol(pOrderBy: Ptr, pEList: Ptr) void {
    if (pOrderBy == null) return;
    const itemSz = off("sizeof_ExprList_item", 24);
    const aOB = fieldPtr(pOrderBy, off("ExprList_a", 8));
    const aEL = fieldPtr(pEList, off("ExprList_a", 8));
    const ucOff = off("ExprList_item_u_x_iOrderByCol", 20);
    const nOB = el_nExpr(pOrderBy);
    const nEL = el_nExpr(pEList);
    var i: c_int = 0;
    while (i < nOB) : (i += 1) {
        const pOB = fieldPtr(aOB, @as(usize, @intCast(i)) * itemSz);
        const t = rd(u16, pOB, ucOff);
        if (t == 0) continue;
        var j: c_int = 0;
        while (j < nEL) : (j += 1) {
            const pEl = fieldPtr(aEL, @as(usize, @intCast(j)) * itemSz);
            if (rd(u16, pEl, ucOff) == t) {
                wr(u16, pOB, ucOff, @intCast(j + 1));
                break;
            }
        }
        if (j >= nEL) wr(u16, pOB, ucOff, 0);
    }
}

fn removeUnindexableInClauseTerms(pParse: Ptr, iEq: c_int, pLoop: Ptr, pX: Ptr) Ptr {
    const db = parse_db(pParse);
    const pNew = c.sqlite3ExprDup(db, pX, 0);
    if (!db_mallocFailed(db)) {
        var pSelect = expr_xPSelect(pNew);
        while (pSelect != null) : (pSelect = sel_pPrior(pSelect)) {
            const pOrigRhs = sel_pEList(pSelect);
            var pOrigLhs: Ptr = null;
            var pRhs: Ptr = null;
            var pLhs: Ptr = null;
            const itemSz = off("sizeof_ExprList_item", 24);
            const aOff = off("ExprList_a", 8);
            const pExprOff = off("ExprList_item_pExpr", 0);
            const ucOff = off("ExprList_item_u_x_iOrderByCol", 20);
            if (pSelect == expr_xPSelect(pNew)) {
                pOrigLhs = expr_xPList(expr_pLeft(pNew));
            }
            var i: c_int = iEq;
            const nLTerm: c_int = wl_nLTerm(pLoop);
            while (i < nLTerm) : (i += 1) {
                const pLTerm = wl_aLTermAt(pLoop, @intCast(i));
                if (rdp(pLTerm, WhereTerm.pExpr) == pX) {
                    const iField = wt_uxIField(pLTerm) - 1;
                    const aRhs = fieldPtr(pOrigRhs, aOff);
                    const itemRhs = fieldPtr(aRhs, @as(usize, @intCast(iField)) * itemSz);
                    if (rdp(itemRhs, pExprOff) == null) continue; // NEVER, dup PK col
                    pRhs = c.sqlite3ExprListAppend(pParse, pRhs, rdp(itemRhs, pExprOff));
                    wr(Ptr, itemRhs, pExprOff, null);
                    if (pRhs != null) {
                        const aR = fieldPtr(pRhs, aOff);
                        const last = fieldPtr(aR, @as(usize, @intCast(el_nExpr(pRhs) - 1)) * itemSz);
                        wr(u16, last, ucOff, @intCast(iField + 1));
                    }
                    if (pOrigLhs != null) {
                        const aLhs = fieldPtr(pOrigLhs, aOff);
                        const itemLhs = fieldPtr(aLhs, @as(usize, @intCast(iField)) * itemSz);
                        pLhs = c.sqlite3ExprListAppend(pParse, pLhs, rdp(itemLhs, pExprOff));
                        wr(Ptr, itemLhs, pExprOff, null);
                    }
                }
            }
            c.sqlite3ExprListDelete(db, pOrigRhs);
            if (pOrigLhs != null) {
                c.sqlite3ExprListDelete(db, pOrigLhs);
                wr(Ptr, expr_pLeft(pNew), off("Expr_x", 32), pLhs);
            }
            wr(Ptr, pSelect, off("Select_pEList", 24), pRhs);
            // selId = ++pParse->nSelect
            const nselO = off("Parse_nSelect", 124);
            const nsel = rd(c_int, pParse, nselO) + 1;
            wr(c_int, pParse, nselO, nsel);
            wr(c_int, pSelect, off("Select_selId", 16), nsel);
            if (pLhs != null and el_nExpr(pLhs) == 1) {
                const aL = fieldPtr(pLhs, aOff);
                const p0 = fieldPtr(aL, 0);
                const pe = rdp(p0, pExprOff);
                wr(Ptr, p0, pExprOff, null);
                c.sqlite3ExprDelete(db, expr_pLeft(pNew));
                expr_set_pLeft(pNew, pe);
            }
            if (pRhs != null) {
                adjustOrderByCol(rdp(pSelect, off("Select_pOrderBy", 64)), pRhs);
                adjustOrderByCol(rdp(pSelect, off("Select_pGroupBy", 48)), pRhs);
                var k: c_int = 0;
                const nR = el_nExpr(pRhs);
                const aR2 = fieldPtr(pRhs, aOff);
                while (k < nR) : (k += 1) {
                    wr(u16, fieldPtr(aR2, @as(usize, @intCast(k)) * itemSz), ucOff, 0);
                }
            }
        }
    }
    return pNew;
}

fn codeINTerm(pParse: Ptr, pTerm: Ptr, pLevel: Ptr, iEq: c_int, bRevIn: c_int, iTarget: c_int) void {
    const pX = rdp(pTerm, WhereTerm.pExpr);
    var eType: c_int = IN_INDEX_NOOP;
    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    const v = parse_pVdbe(pParse);
    var nEq: c_int = 0;
    var aiMap: ?[*]c_int = null;
    var bRev = bRevIn;

    if ((wl_wsFlags(pLoop) & WHERE_VIRTUALTABLE) == 0 and
        wl_uBtreePIndex(pLoop) != null and
        idx_aSortOrder(wl_uBtreePIndex(pLoop)).?[@intCast(iEq)] != 0)
    {
        bRev = if (bRev != 0) 0 else 1;
    }

    var i: c_int = 0;
    while (i < iEq) : (i += 1) {
        const lt = wl_aLTermAt(pLoop, @intCast(i));
        if (lt != null and rdp(lt, WhereTerm.pExpr) == pX) {
            disableTerm(pLevel, pTerm);
            return;
        }
    }
    const nLTerm: c_int = wl_nLTerm(pLoop);
    i = iEq;
    while (i < nLTerm) : (i += 1) {
        if (rdp(wl_aLTermAt(pLoop, @intCast(i)), WhereTerm.pExpr) == pX) nEq += 1;
    }

    var iTab: c_int = 0;
    if (!exprUseXSelect(pX) or el_nExpr(sel_pEList(expr_xPSelect(pX))) == 1) {
        eType = c.sqlite3FindInIndex(pParse, pX, IN_INDEX_LOOP, null, null, &iTab);
    } else {
        const db = parse_db(pParse);
        const pXMod = removeUnindexableInClauseTerms(pParse, iEq, pLoop, pX);
        if (!db_mallocFailed(db)) {
            aiMap = @ptrCast(@alignCast(c.sqlite3DbMallocZero(db, @intCast(@sizeOf(c_int) * @as(usize, @intCast(nEq))))));
            eType = c.sqlite3FindInIndex(pParse, pXMod, IN_INDEX_LOOP, null, aiMap, &iTab);
        }
        c.sqlite3ExprDelete(db, pXMod);
    }

    if (eType == IN_INDEX_INDEX_DESC) bRev = if (bRev != 0) 0 else 1;
    _ = c.sqlite3VdbeAddOp2(v, if (bRev != 0) op.Last else op.Rewind, iTab, 0);

    wl_set_wsFlags(pLoop, wl_wsFlags(pLoop) | WHERE_IN_ABLE);
    if (rd(c_int, pLevel, WhereLevel.u_in_nIn) == 0) {
        wr(c_int, pLevel, WhereLevel.addrNxt, c.sqlite3VdbeMakeLabel(pParse));
    }
    if (iEq > 0 and (wl_wsFlags(pLoop) & WHERE_IN_SEEKSCAN) == 0) {
        wl_set_wsFlags(pLoop, wl_wsFlags(pLoop) | WHERE_IN_EARLYOUT);
    }

    i = rd(c_int, pLevel, WhereLevel.u_in_nIn);
    const newNIn = i + nEq;
    wr(c_int, pLevel, WhereLevel.u_in_nIn, newNIn);
    const pWInfoForRealloc = rdp(rdp(pTerm, WhereTerm.pWC), WhereClause.pWInfo);
    const aInLoopNew = c.sqlite3WhereRealloc(pWInfoForRealloc, rdp(pLevel, WhereLevel.u_in_aInLoop), @intCast(InLoop.sizeof * @as(usize, @intCast(newNIn))));
    wr(Ptr, pLevel, WhereLevel.u_in_aInLoop, aInLoopNew);
    var pIn = aInLoopNew;
    if (pIn != null) {
        var iMap: usize = 0;
        pIn = fieldPtr(pIn, @as(usize, @intCast(i)) * InLoop.sizeof);
        i = iEq;
        while (i < nLTerm) : (i += 1) {
            const lt = wl_aLTermAt(pLoop, @intCast(i));
            if (rdp(lt, WhereTerm.pExpr) == pX) {
                const iOut = iTarget + i - iEq;
                if (eType == IN_INDEX_ROWID) {
                    wr(c_int, pIn, InLoop.addrInTop, c.sqlite3VdbeAddOp2(v, op.Rowid, iTab, iOut));
                } else {
                    const iCol: c_int = if (aiMap) |m| m[iMap] else 0;
                    if (aiMap != null) iMap += 1;
                    wr(c_int, pIn, InLoop.addrInTop, c.sqlite3VdbeAddOp3(v, op.Column, iTab, iCol, iOut));
                }
                _ = c.sqlite3VdbeAddOp1(v, op.IsNull, iOut);
                if (i == iEq) {
                    wr(c_int, pIn, InLoop.iCur, iTab);
                    wr(u8, pIn, InLoop.eEndLoopOp, @intCast(if (bRev != 0) op.Prev else op.Next));
                    if (iEq > 0) {
                        wr(c_int, pIn, InLoop.iBase, iTarget - i);
                        wr(c_int, pIn, InLoop.nPrefix, i);
                    } else {
                        wr(c_int, pIn, InLoop.nPrefix, 0);
                    }
                } else {
                    wr(u8, pIn, InLoop.eEndLoopOp, @intCast(op.Noop));
                }
                pIn = fieldPtr(pIn, InLoop.sizeof);
            }
        }
        if (iEq > 0 and (wl_wsFlags(pLoop) & (WHERE_IN_SEEKSCAN | WHERE_VIRTUALTABLE)) == 0) {
            _ = c.sqlite3VdbeAddOp3(v, op.SeekHit, rd(c_int, pLevel, WhereLevel.iIdxCur), 0, iEq);
        }
    } else {
        wr(c_int, pLevel, WhereLevel.u_in_nIn, 0);
    }
    c.sqlite3DbFree(parse_db(pParse), @ptrCast(aiMap));
}

fn codeEqualityTerm(pParse: Ptr, pTerm: Ptr, pLevel: Ptr, iEq: c_int, bRev: c_int, iTarget: c_int) c_int {
    const pX = rdp(pTerm, WhereTerm.pExpr);
    var iReg: c_int = undefined;
    const xop = expr_op(pX);
    if (xop == TK_EQ or xop == TK_IS) {
        iReg = c.sqlite3ExprCodeTarget(pParse, expr_pRight(pX), iTarget);
    } else if (xop == TK_ISNULL) {
        iReg = iTarget;
        _ = c.sqlite3VdbeAddOp2(parse_pVdbe(pParse), op.Null, 0, iReg);
    } else {
        iReg = iTarget;
        codeINTerm(pParse, pTerm, pLevel, iEq, bRev, iTarget);
    }
    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    if ((wl_wsFlags(pLoop) & WHERE_TRANSCONS) == 0 or (rd(u16, pTerm, WhereTerm.eOperator) & WO_EQUIV) == 0) {
        disableTerm(pLevel, pTerm);
    }
    return iReg;
}

fn codeAllEqualityTerms(pParse: Ptr, pLevel: Ptr, bRev: c_int, nExtraReg: c_int, pzAff: *?[*:0]u8) c_int {
    const v = parse_pVdbe(pParse);
    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    const nEq: c_int = wl_uBtreeNEq(pLoop);
    const nSkip: c_int = wl_nSkip(pLoop);
    const pIdx = wl_uBtreePIndex(pLoop);

    var regBase = parse_nMem(pParse) + 1;
    const nReg = nEq + nExtraReg;
    parse_add_nMem(pParse, nReg);

    const zAff = c.sqlite3DbStrDup(parse_db(pParse), c.sqlite3IndexAffinityStr(parse_db(pParse), pIdx));

    var j: c_int = 0;
    if (nSkip != 0) {
        const iIdxCur = rd(c_int, pLevel, WhereLevel.iIdxCur);
        _ = c.sqlite3VdbeAddOp3(v, op.Null, 0, regBase, regBase + nSkip - 1);
        _ = c.sqlite3VdbeAddOp1(v, if (bRev != 0) op.Last else op.Rewind, iIdxCur);
        vdbeComment(v, "begin skip-scan on %s", .{idx_zName(pIdx)});
        j = c.sqlite3VdbeAddOp0(v, op.Goto);
        wr(c_int, pLevel, WhereLevel.addrSkip, c.sqlite3VdbeAddOp4Int(v, if (bRev != 0) op.SeekLT else op.SeekGT, iIdxCur, 0, regBase, nSkip));
        c.sqlite3VdbeJumpHere(v, j);
        var k: c_int = 0;
        while (k < nSkip) : (k += 1) {
            _ = c.sqlite3VdbeAddOp3(v, op.Column, iIdxCur, k, regBase + k);
            vdbeComment(v, "%s", .{explainIndexColumnName(pIdx, k)});
        }
    }

    j = nSkip;
    while (j < nEq) : (j += 1) {
        const pTerm = wl_aLTermAt(pLoop, @intCast(j));
        const r1 = codeEqualityTerm(pParse, pTerm, pLevel, j, bRev, regBase + j);
        if (r1 != regBase + j) {
            if (nReg == 1) {
                c.sqlite3ReleaseTempReg(pParse, regBase);
                regBase = r1;
            } else {
                _ = c.sqlite3VdbeAddOp2(v, 82, r1, regBase + j); // OP_Copy=82
            }
        }
        const eOp = rd(u16, pTerm, WhereTerm.eOperator);
        if (eOp & WO_IN != 0) {
            if (expr_flags(rdp(pTerm, WhereTerm.pExpr)) & EP_xIsSelect != 0) {
                if (zAff) |za| za[@intCast(j)] = SQLITE_AFF_BLOB;
            }
        } else if ((eOp & WO_ISNULL) == 0) {
            const pRight = expr_pRight(rdp(pTerm, WhereTerm.pExpr));
            if ((rd(u16, pTerm, WhereTerm.wtFlags) & TERM_IS) == 0 and c.sqlite3ExprCanBeNull(pRight) != 0) {
                _ = c.sqlite3VdbeAddOp2(v, op.IsNull, regBase + j, rd(c_int, pLevel, WhereLevel.addrBrk));
            }
            if (parse_nErr(pParse) == 0) {
                if (zAff) |za| {
                    if (c.sqlite3CompareAffinity(pRight, za[@intCast(j)]) == SQLITE_AFF_BLOB) za[@intCast(j)] = SQLITE_AFF_BLOB;
                    if (c.sqlite3ExprNeedsNoAffinityChange(pRight, za[@intCast(j)]) != 0) za[@intCast(j)] = SQLITE_AFF_BLOB;
                }
            }
        }
    }
    pzAff.* = zAff;
    return regBase;
}

fn whereLikeOptimizationStringFixup(v: Ptr, pLevel: Ptr, pTerm: Ptr) void {
    if (rd(u16, pTerm, WhereTerm.wtFlags) & TERM_LIKEOPT != 0) {
        const pOp = c.sqlite3VdbeGetLastOp(v);
        const cntr = rd(u32, pLevel, WhereLevel.iLikeRepCntr);
        vop_set_p3(pOp, @intCast(cntr >> 1));
        vop_set_p5(pOp, @intCast(cntr & 1));
    }
}

// codeCursorHint: SQLITE_ENABLE_CURSOR_HINTS is OFF -> no-op.
inline fn codeCursorHint(pTabItem: Ptr, pWInfo: Ptr, pLevel: Ptr, pEndRange: Ptr) void {
    _ = pTabItem;
    _ = pWInfo;
    _ = pLevel;
    _ = pEndRange;
}

fn codeDeferredSeek(pWInfo: Ptr, pIdx: Ptr, iCur: c_int, iIdxCur: c_int) void {
    const pParse = wi_pParse(pWInfo);
    const v = parse_pVdbe(pParse);
    // pWInfo->bDeferredSeek = 1
    wi_set_bDeferredSeek(pWInfo);
    _ = c.sqlite3VdbeAddOp3(v, op.DeferredSeek, iIdxCur, 0, iCur);
    const tl = parseToplevel(pParse);
    const writeMask = rd(u32, tl, off("Parse_writeMask", 112));
    if ((wi_wctrlFlags(pWInfo) & (WHERE_OR_SUBCLAUSE | WHERE_RIGHT_JOIN)) != 0 and writeMask == 0) {
        const pTab = idx_pTable(pIdx);
        const nCol: c_int = tab_nCol(pTab);
        const ai: ?[*]u32 = @ptrCast(@alignCast(c.sqlite3DbMallocZero(parse_db(pParse), @intCast(@sizeOf(u32) * @as(usize, @intCast(nCol + 1))))));
        if (ai) |a| {
            a[0] = @intCast(nCol);
            var i: c_int = 0;
            const nColumn: c_int = idx_nColumn(pIdx);
            while (i < nColumn - 1) : (i += 1) {
                const x1 = idx_aiColumn(pIdx).?[@intCast(i)];
                const x2 = c.sqlite3TableColumnToStorage(pTab, x1);
                if (x1 >= 0) a[@intCast(x2 + 1)] = @intCast(i + 1);
            }
            c.sqlite3VdbeChangeP4(v, -1, @ptrCast(a), @intCast(P4_INTARRAY));
        }
    }
}

fn codeExprOrVector(pParse: Ptr, p: Ptr, iReg: c_int, nReg: c_int) void {
    if (p != null and c.sqlite3ExprIsVector(p) != 0) {
        if (exprUseXSelect(p)) {
            const v = parse_pVdbe(pParse);
            const iSelect = c.sqlite3CodeSubselect(pParse, p);
            _ = c.sqlite3VdbeAddOp3(v, 82, iSelect, iReg, nReg - 1); // OP_Copy
        } else {
            const pList = expr_xPList(p);
            const aOff = off("ExprList_a", 8);
            const itemSz = off("sizeof_ExprList_item", 24);
            const pExprOff = off("ExprList_item_pExpr", 0);
            const a = fieldPtr(pList, aOff);
            var i: c_int = 0;
            while (i < nReg) : (i += 1) {
                c.sqlite3ExprCode(pParse, rdp(fieldPtr(a, @as(usize, @intCast(i)) * itemSz), pExprOff), iReg + i);
            }
        }
    } else {
        c.sqlite3ExprCode(pParse, p, iReg);
    }
}

fn whereApplyPartialIndexConstraints(pTruthIn: Ptr, iTabCur: c_int, pWC: Ptr) void {
    var pTruth = pTruthIn;
    while (expr_op(pTruth) == TK_AND) {
        whereApplyPartialIndexConstraints(expr_pLeft(pTruth), iTabCur, pWC);
        pTruth = expr_pRight(pTruth);
    }
    const nTerm = rd(c_int, pWC, WhereClause.nTerm);
    const aBase = rdp(pWC, WhereClause.a);
    var i: c_int = 0;
    while (i < nTerm) : (i += 1) {
        const pTerm = fieldPtr(aBase, @as(usize, @intCast(i)) * wtSize());
        if (rd(u16, pTerm, WhereTerm.wtFlags) & TERM_CODED != 0) continue;
        const pExpr = rdp(pTerm, WhereTerm.pExpr);
        if (c.sqlite3ExprCompare(null, pExpr, pTruth, iTabCur) == 0) {
            wr(u16, pTerm, WhereTerm.wtFlags, rd(u16, pTerm, WhereTerm.wtFlags) | TERM_CODED);
        }
    }
}

fn filterPullDown(pParse: Ptr, pWInfo: Ptr, iLevelIn: c_int, addrNxt: c_int, notReady: u64) void {
    var iLevel = iLevelIn;
    const nLevel: c_int = wi_nLevel(pWInfo);
    while (true) {
        iLevel += 1;
        if (iLevel >= nLevel) break;
        const pLevel = wi_levelAt(pWInfo, @intCast(iLevel));
        const pLoop = rdp(pLevel, WhereLevel.pWLoop);
        if (rd(c_int, pLevel, WhereLevel.regFilter) == 0) continue;
        if (wl_nSkip(pLoop) != 0) continue;
        if ((wl_maskSelf(pLoop) == 0) and (rd(u64, pLoop, WhereLoop.prereq) & notReady) != 0) continue; // NEVER guard approximated
        const saved_addrBrk = rd(c_int, pLevel, WhereLevel.addrBrk);
        wr(c_int, pLevel, WhereLevel.addrBrk, addrNxt);
        if (wl_wsFlags(pLoop) & WHERE_IPK != 0) {
            const pTerm = wl_aLTermAt(pLoop, 0);
            var regRowid = c.sqlite3GetTempReg(pParse);
            regRowid = codeEqualityTerm(pParse, pTerm, pLevel, 0, 0, regRowid);
            _ = c.sqlite3VdbeAddOp2(parse_pVdbe(pParse), op.MustBeInt, regRowid, addrNxt);
            _ = c.sqlite3VdbeAddOp4Int(parse_pVdbe(pParse), op.Filter, rd(c_int, pLevel, WhereLevel.regFilter), addrNxt, regRowid, 1);
        } else {
            const nEq: c_int = wl_uBtreeNEq(pLoop);
            var zStartAff: ?[*:0]u8 = null;
            const r1 = codeAllEqualityTerms(pParse, pLevel, 0, 0, &zStartAff);
            codeApplyAffinity(pParse, r1, nEq, zStartAff);
            c.sqlite3DbFree(parse_db(pParse), @ptrCast(zStartAff));
            _ = c.sqlite3VdbeAddOp4Int(parse_pVdbe(pParse), op.Filter, rd(c_int, pLevel, WhereLevel.regFilter), addrNxt, r1, nEq);
        }
        wr(c_int, pLevel, WhereLevel.regFilter, 0);
        wr(c_int, pLevel, WhereLevel.addrBrk, saved_addrBrk);
    }
}

fn whereLoopIsOneRow(pLoop: Ptr) c_int {
    const pIdx = wl_uBtreePIndex(pLoop);
    if (idx_onError(pIdx) != 0 and wl_nSkip(pLoop) == 0 and wl_uBtreeNEq(pLoop) == idx_nKeyCol(pIdx)) {
        const nEq: c_int = wl_uBtreeNEq(pLoop);
        var ii: c_int = 0;
        while (ii < nEq) : (ii += 1) {
            if (rd(u16, wl_aLTermAt(pLoop, @intCast(ii)), WhereTerm.eOperator) & (WO_IS | WO_ISNULL) != 0) return 0;
        }
        return 1;
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3WhereCodeOneLoopStart
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3WhereCodeOneLoopStart(pParse: Ptr, v: Ptr, pWInfo: Ptr, iLevel: c_int, pLevel: Ptr, notReady: u64) callconv(.c) u64 {
    var j: c_int = 0;
    var addrNxt: c_int = 0;
    var iRowidReg: c_int = 0;
    var iReleaseReg: c_int = 0;
    var pIdx: Ptr = null;
    var iLoop: c_int = 0;

    const pWC = wi_sWC(pWInfo);
    const db = parse_db(pParse);
    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    const pTabItem = srcItemAt(wi_pTabList(pWInfo), @intCast(rd(u8, pLevel, WhereLevel.iFrom)));
    const iCur = si_iCursor(pTabItem);
    // pLevel->notReady = notReady & ~GetMask
    wr(u64, pLevel, WhereLevel.notReady, notReady & ~c.sqlite3WhereGetMask(wi_sMaskSet(pWInfo), iCur));
    const bRev: c_int = @intCast((wi_revMask(pWInfo) >> @intCast(iLevel)) & 1);
    vdbeNoopComment(v, "Begin WHERE-loop%d: %s", .{ iLevel, tab_zName(si_pSTab(pTabItem)) });

    // addrBrk = pLevel->addrNxt = pLevel->addrBrk;
    const addrBrk0 = rd(c_int, pLevel, WhereLevel.addrBrk);
    wr(c_int, pLevel, WhereLevel.addrNxt, addrBrk0);
    const addrBrk = addrBrk0;
    const addrCont = c.sqlite3VdbeMakeLabel(pParse);
    wr(c_int, pLevel, WhereLevel.addrCont, addrCont);

    // LEFT JOIN match flag
    if (rd(u8, pLevel, WhereLevel.iFrom) > 0 and (si_jointype(pTabItem) & JT_LEFT) != 0) {
        wr(c_int, pLevel, WhereLevel.iLeftJoin, parse_inc_nMem(pParse));
        _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, rd(c_int, pLevel, WhereLevel.iLeftJoin));
        vdbeComment(v, "init LEFT JOIN match flag", .{});
    }

    var handled = false;

    // co-routine subquery
    if (siViaCoroutine(pTabItem)) {
        const pSubq = si_u4pSubq(pTabItem);
        const regYield = sq_regReturn(pSubq);
        _ = c.sqlite3VdbeAddOp3(v, op.InitCoroutine, regYield, 0, sq_addrFillSub(pSubq));
        wr(c_int, pLevel, WhereLevel.p2, c.sqlite3VdbeAddOp2(v, op.Yield, regYield, addrBrk));
        vdbeComment(v, "next row of %s", .{tab_zName(si_pSTab(pTabItem))});
        wr(u8, pLevel, WhereLevel.op, @intCast(op.Goto));
        handled = true;
    }

    // Case 1: virtual table
    if (!handled and (wl_wsFlags(pLoop) & WHERE_VIRTUALTABLE) != 0) {
        const nConstraint: c_int = wl_nLTerm(pLoop);
        const iReg = c.sqlite3GetTempRange(pParse, nConstraint + 2);
        var addrNotFound = rd(c_int, pLevel, WhereLevel.addrBrk);
        j = 0;
        while (j < nConstraint) : (j += 1) {
            const iTarget = iReg + j + 2;
            const pTerm = wl_aLTermAt(pLoop, @intCast(j));
            if (pTerm == null) continue;
            if (rd(u16, pTerm, WhereTerm.eOperator) & WO_IN != 0) {
                if ((SMASKBIT32(@intCast(j)) & wl_uVtabMHandleIn(pLoop)) != 0) {
                    const iTab2 = parse_postinc_nTab(pParse);
                    const iCache = parse_inc_nMem(pParse);
                    c.sqlite3CodeRhsOfIN(pParse, rdp(pTerm, WhereTerm.pExpr), iTab2, 0);
                    _ = c.sqlite3VdbeAddOp3(v, op.VInitIn, iTab2, iTarget, iCache);
                } else {
                    _ = codeEqualityTerm(pParse, pTerm, pLevel, j, bRev, iTarget);
                    addrNotFound = rd(c_int, pLevel, WhereLevel.addrNxt);
                }
            } else {
                const pRight = expr_pRight(rdp(pTerm, WhereTerm.pExpr));
                codeExprOrVector(pParse, pRight, iTarget, 1);
                if (rd(u8, pTerm, WhereTerm.eMatchOp) == SQLITE_INDEX_CONSTRAINT_OFFSET and wl_uVtabBOmitOffset(pLoop)) {
                    _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, sel_iOffset(wi_pSelect(pWInfo)));
                    vdbeComment(v, "Zero OFFSET counter", .{});
                }
            }
        }
        _ = c.sqlite3VdbeAddOp2(v, op.Integer, wl_uVtabIdxNum(pLoop), iReg);
        _ = c.sqlite3VdbeAddOp2(v, op.Integer, nConstraint, iReg + 1);
        _ = c.sqlite3VdbeAddOp4(v, op.VFilter, iCur, addrNotFound, iReg, @ptrCast(wl_uVtabIdxStr(pLoop)), if (wl_uVtabNeedFree(pLoop)) @intCast(P4_DYNAMIC) else @intCast(P4_STATIC));
        wl_clear_uVtabNeedFree(pLoop);
        if (db_mallocFailed(db)) wl_set_uVtabIdxStr(pLoop, null);
        wr(c_int, pLevel, WhereLevel.p1, iCur);
        wr(u8, pLevel, WhereLevel.op, @intCast(if (wi_eOnePass(pWInfo) != ONEPASS_OFF) op.Noop else op.VNext));
        wr(c_int, pLevel, WhereLevel.p2, c.sqlite3VdbeCurrentAddr(v));

        j = 0;
        while (j < nConstraint) : (j += 1) {
            const pTerm = wl_aLTermAt(pLoop, @intCast(j));
            if (j < 16 and (wl_uVtabOmitMask(pLoop) >> @intCast(j)) & 1 != 0) {
                disableTerm(pLevel, pTerm);
                continue;
            }
            if ((rd(u16, pTerm, WhereTerm.eOperator) & WO_IN) != 0 and
                (SMASKBIT32(@intCast(j)) & wl_uVtabMHandleIn(pLoop)) == 0 and
                !db_mallocFailed(db))
            {
                // reload constraint value
                var iIn: c_int = 0;
                const nIn = rd(c_int, pLevel, WhereLevel.u_in_nIn);
                const aInLoop = rdp(pLevel, WhereLevel.u_in_aInLoop);
                while (iIn < nIn) : (iIn += 1) {
                    const inItem = fieldPtr(aInLoop, @as(usize, @intCast(iIn)) * InLoop.sizeof);
                    const pOp = c.sqlite3VdbeGetOp(v, rd(c_int, inItem, InLoop.addrInTop));
                    if ((vop_opcode(pOp) == op.Column and vop_p3(pOp) == iReg + j + 2) or
                        (vop_opcode(pOp) == op.Rowid and vop_p2(pOp) == iReg + j + 2))
                    {
                        _ = c.sqlite3VdbeAddOp3(v, vop_opcode(pOp), vop_p1(pOp), vop_p2(pOp), vop_p3(pOp));
                        break;
                    }
                }
                const pCompare = c.sqlite3PExpr(pParse, TK_EQ, null, null);
                if (!db_mallocFailed(db)) {
                    const iFld = wt_uxIField(pTerm);
                    const pLeft = expr_pLeft(rdp(pTerm, WhereTerm.pExpr));
                    if (iFld > 0) {
                        const lst = expr_xPList(pLeft);
                        const aOff = off("ExprList_a", 8);
                        const itemSz = off("sizeof_ExprList_item", 24);
                        const pExprOff = off("ExprList_item_pExpr", 0);
                        expr_set_pLeft(pCompare, rdp(fieldPtr(fieldPtr(lst, aOff), @as(usize, @intCast(iFld - 1)) * itemSz), pExprOff));
                    } else {
                        expr_set_pLeft(pCompare, pLeft);
                    }
                    const pRight = c.sqlite3Expr(db, TK_REGISTER, null);
                    expr_set_pRight(pCompare, pRight);
                    if (pRight != null) {
                        expr_set_iTable(pRight, iReg + j + 2);
                        c.sqlite3ExprIfFalse(pParse, pCompare, rd(c_int, pLevel, WhereLevel.addrCont), SQLITE_JUMPIFNULL);
                    }
                    expr_set_pLeft(pCompare, null);
                }
                c.sqlite3ExprDelete(db, pCompare);
            }
        }
        handled = true;
    }

    // Case 2: IPK == / IN
    if (!handled and (wl_wsFlags(pLoop) & WHERE_IPK) != 0 and (wl_wsFlags(pLoop) & (WHERE_COLUMN_IN | WHERE_COLUMN_EQ)) != 0) {
        const pTerm = wl_aLTermAt(pLoop, 0);
        iReleaseReg = parse_inc_nMem(pParse);
        iRowidReg = codeEqualityTerm(pParse, pTerm, pLevel, 0, bRev, iReleaseReg);
        if (iRowidReg != iReleaseReg) c.sqlite3ReleaseTempReg(pParse, iReleaseReg);
        addrNxt = rd(c_int, pLevel, WhereLevel.addrNxt);
        if (rd(c_int, pLevel, WhereLevel.regFilter) != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.MustBeInt, iRowidReg, addrNxt);
            _ = c.sqlite3VdbeAddOp4Int(v, op.Filter, rd(c_int, pLevel, WhereLevel.regFilter), addrNxt, iRowidReg, 1);
            filterPullDown(pParse, pWInfo, iLevel, addrNxt, notReady);
        }
        _ = c.sqlite3VdbeAddOp3(v, op.SeekRowid, iCur, addrNxt, iRowidReg);
        wr(u8, pLevel, WhereLevel.op, @intCast(op.Noop));
        handled = true;
    }

    // Case 3: IPK range
    if (!handled and (wl_wsFlags(pLoop) & WHERE_IPK) != 0 and (wl_wsFlags(pLoop) & WHERE_COLUMN_RANGE) != 0) {
        var testOp: c_int = op.Noop;
        var start: c_int = 0;
        var memEndValue: c_int = 0;
        var pStart: Ptr = null;
        var pEnd: Ptr = null;
        j = 0;
        if (wl_wsFlags(pLoop) & WHERE_BTM_LIMIT != 0) {
            pStart = wl_aLTermAt(pLoop, @intCast(j));
            j += 1;
        }
        if (wl_wsFlags(pLoop) & WHERE_TOP_LIMIT != 0) {
            pEnd = wl_aLTermAt(pLoop, @intCast(j));
            j += 1;
        }
        if (bRev != 0) {
            const tmp = pStart;
            pStart = pEnd;
            pEnd = tmp;
        }
        codeCursorHint(pTabItem, pWInfo, pLevel, pEnd);
        const aMoveOp = [_]c_int{ op.SeekGT, op.SeekLE, op.SeekLT, op.SeekGE };
        if (pStart != null) {
            const pX = rdp(pStart, WhereTerm.pExpr);
            var r1: c_int = undefined;
            var rTemp: c_int = undefined;
            var opSeek: c_int = undefined;
            if (c.sqlite3ExprIsVector(expr_pRight(pX)) != 0) {
                r1 = c.sqlite3GetTempReg(pParse);
                rTemp = r1;
                codeExprOrVector(pParse, expr_pRight(pX), r1, 1);
                opSeek = aMoveOp[@intCast(((@as(c_int, expr_op(pX)) - TK_GT - 1) & 0x3) | 0x1)];
            } else {
                r1 = c.sqlite3ExprCodeTemp(pParse, expr_pRight(pX), &rTemp);
                disableTerm(pLevel, pStart);
                opSeek = aMoveOp[@intCast(@as(c_int, expr_op(pX)) - TK_GT)];
            }
            _ = c.sqlite3VdbeAddOp3(v, opSeek, iCur, addrBrk, r1);
            vdbeComment(v, "pk", .{});
            c.sqlite3ReleaseTempReg(pParse, rTemp);
        } else {
            _ = c.sqlite3VdbeAddOp2(v, if (bRev != 0) op.Last else op.Rewind, iCur, rd(c_int, pLevel, WhereLevel.addrHalt));
        }
        if (pEnd != null) {
            const pX = rdp(pEnd, WhereTerm.pExpr);
            memEndValue = parse_inc_nMem(pParse);
            codeExprOrVector(pParse, expr_pRight(pX), memEndValue, 1);
            const isVec = c.sqlite3ExprIsVector(expr_pRight(pX)) != 0;
            const xop = expr_op(pX);
            if (!isVec and (xop == TK_LT or xop == TK_GT)) {
                testOp = if (bRev != 0) op.Le else op.Ge;
            } else {
                testOp = if (bRev != 0) op.Lt else op.Gt;
            }
            if (!isVec) disableTerm(pLevel, pEnd);
        }
        start = c.sqlite3VdbeCurrentAddr(v);
        wr(u8, pLevel, WhereLevel.op, @intCast(if (bRev != 0) op.Prev else op.Next));
        wr(c_int, pLevel, WhereLevel.p1, iCur);
        wr(c_int, pLevel, WhereLevel.p2, start);
        if (testOp != op.Noop) {
            iRowidReg = parse_inc_nMem(pParse);
            _ = c.sqlite3VdbeAddOp2(v, op.Rowid, iCur, iRowidReg);
            _ = c.sqlite3VdbeAddOp3(v, testOp, memEndValue, addrBrk, iRowidReg);
            c.sqlite3VdbeChangeP5(v, SQLITE_AFF_NUMERIC | @as(u16, @intCast(SQLITE_JUMPIFNULL)));
        }
        handled = true;
    }

    // Case 4: indexed
    if (!handled and (wl_wsFlags(pLoop) & WHERE_INDEXED) != 0) {
        codeIndexedLoop(pParse, v, pWInfo, iLevel, pLevel, pLoop, pTabItem, iCur, bRev, addrBrk, addrCont, notReady, &iRowidReg, &pIdx);
        handled = true;
    }

    // Case 5: multi-index OR
    if (!handled and (wl_wsFlags(pLoop) & WHERE_MULTI_OR) != 0) {
        if (codeOrLoop(pParse, v, pWInfo, iLevel, pLevel, pLoop, pTabItem, iCur, db, notReady)) |earlyRet| {
            return earlyRet;
        }
        handled = true;
    }

    // Case 6: full scan
    if (!handled) {
        const aStep = [_]c_int{ op.Next, op.Prev };
        const aStart = [_]c_int{ op.Rewind, op.Last };
        if (siIsRecursive(pTabItem)) {
            wr(u8, pLevel, WhereLevel.op, @intCast(op.Noop));
        } else {
            codeCursorHint(pTabItem, pWInfo, pLevel, null);
            wr(u8, pLevel, WhereLevel.op, @intCast(aStep[@intCast(bRev)]));
            wr(c_int, pLevel, WhereLevel.p1, iCur);
            wr(c_int, pLevel, WhereLevel.p2, 1 + c.sqlite3VdbeAddOp2(v, aStart[@intCast(bRev)], iCur, rd(c_int, pLevel, WhereLevel.addrHalt)));
            wr(u8, pLevel, WhereLevel.p5, SQLITE_STMTSTATUS_FULLSCAN_STEP);
        }
    }

    if (stmt_scanstatus) {
        wr(c_int, pLevel, WhereLevel.addrVisit, c.sqlite3VdbeCurrentAddr(v));
    }

    // ── push-down constraint coding loop (iLoop 1..3) ──
    iLoop = if (pIdx != null) 1 else 2;
    while (true) {
        var iNext: c_int = 0;
        const nTerm = rd(c_int, pWC, WhereClause.nTerm);
        const aBase = rdp(pWC, WhereClause.a);
        j = nTerm;
        var ti: c_int = 0;
        while (j > 0) : ({
            j -= 1;
            ti += 1;
        }) {
            const pTerm = fieldPtr(aBase, @as(usize, @intCast(ti)) * wtSize());
            var skipLikeAddr: c_int = 0;
            const wtf = rd(u16, pTerm, WhereTerm.wtFlags);
            if (wtf & (TERM_VIRTUAL | TERM_CODED) != 0) continue;
            if ((wt_prereqAll(pTerm) & rd(u64, pLevel, WhereLevel.notReady)) != 0) {
                wi_set_untestedTerms(pWInfo);
                continue;
            }
            const pE = rdp(pTerm, WhereTerm.pExpr);
            if (si_jointype(pTabItem) & (JT_LEFT | JT_LTORJ | JT_RIGHT) != 0) {
                if (!exprHasProperty(pE, EP_OuterON | EP_InnerON)) {
                    continue;
                } else if ((si_jointype(pTabItem) & JT_LEFT) == JT_LEFT and !exprHasProperty(pE, EP_OuterON)) {
                    continue;
                } else {
                    const iJoin = rd(c_int, pE, off("Expr_w", 52));
                    const m = c.sqlite3WhereGetMask(wi_sMaskSet(pWInfo), iJoin);
                    if (m & rd(u64, pLevel, WhereLevel.notReady) != 0) continue;
                }
            }
            if (iLoop == 1 and c.sqlite3ExprCoveredByIndex(pE, rd(c_int, pLevel, WhereLevel.iTabCur), pIdx) == 0) {
                iNext = 2;
                continue;
            }
            if (iLoop < 3 and (wtf & TERM_VARSELECT) != 0) {
                if (iNext == 0) iNext = 3;
                continue;
            }
            if (wtf & TERM_LIKECOND != 0) {
                const x = rd(u32, pLevel, WhereLevel.iLikeRepCntr);
                if (x > 0) {
                    skipLikeAddr = c.sqlite3VdbeAddOp1(v, if (x & 1 != 0) op.IfNot else op.If, @intCast(x >> 1));
                }
            }
            c.sqlite3ExprIfFalse(pParse, pE, addrCont, SQLITE_JUMPIFNULL);
            if (skipLikeAddr != 0) c.sqlite3VdbeJumpHere(v, skipLikeAddr);
            wr(u16, pTerm, WhereTerm.wtFlags, rd(u16, pTerm, WhereTerm.wtFlags) | TERM_CODED);
        }
        iLoop = iNext;
        if (iLoop <= 0) break;
    }

    // ── transitive constraints ──
    {
        const nBase = rd(c_int, pWC, WhereClause.nBase);
        const aBase = rdp(pWC, WhereClause.a);
        j = nBase;
        var ti: c_int = 0;
        while (j > 0) : ({
            j -= 1;
            ti += 1;
        }) {
            const pTerm = fieldPtr(aBase, @as(usize, @intCast(ti)) * wtSize());
            if (rd(u16, pTerm, WhereTerm.wtFlags) & (TERM_VIRTUAL | TERM_CODED) != 0) continue;
            const eOp = rd(u16, pTerm, WhereTerm.eOperator);
            if ((eOp & (WO_EQ | WO_IS)) == 0) continue;
            if ((eOp & WO_EQUIV) == 0) continue;
            if (rd(c_int, pTerm, WhereTerm.leftCursor) != iCur) continue;
            if (si_jointype(pTabItem) & (JT_LEFT | JT_LTORJ | JT_RIGHT) != 0) continue;
            const pE = rdp(pTerm, WhereTerm.pExpr);
            const pAlt = c.sqlite3WhereFindTerm(pWC, iCur, wt_uxLeftColumn(pTerm), notReady, WO_EQ | WO_IN | WO_IS, null);
            if (pAlt == null) continue;
            if (rd(u16, pAlt, WhereTerm.wtFlags) & TERM_CODED != 0) continue;
            if (exprHasProperty(rdp(pAlt, WhereTerm.pExpr), EP_Collate)) continue;
            const altEOp = rd(u16, pAlt, WhereTerm.eOperator);
            if ((altEOp & WO_IN) != 0 and exprUseXSelect(rdp(pAlt, WhereTerm.pExpr)) and el_nExpr(sel_pEList(expr_xPSelect(rdp(pAlt, WhereTerm.pExpr)))) > 1) {
                continue;
            }
            vdbeNoopComment(v, "begin transitive constraint", .{});
            // sEAlt = *pAlt->pExpr; sEAlt.pLeft = pE->pLeft;
            const exprSz = off("sizeof_Expr", 72);
            var sEAlt: [128]u8 = undefined;
            const pAltExpr = rdp(pAlt, WhereTerm.pExpr);
            @memcpy(sEAlt[0..exprSz], @as([*]const u8, @ptrCast(pAltExpr))[0..exprSz]);
            const pSE: Ptr = @ptrCast(&sEAlt);
            expr_set_pLeft(pSE, expr_pLeft(pE));
            c.sqlite3ExprIfFalse(pParse, pSE, addrCont, SQLITE_JUMPIFNULL);
            wr(u16, pAlt, WhereTerm.wtFlags, rd(u16, pAlt, WhereTerm.wtFlags) | TERM_CODED);
        }
    }

    // ── RIGHT JOIN match recording ──
    if (rdp(pLevel, WhereLevel.pRJ) != null) {
        codeRightJoinMatch(pParse, v, pWInfo, pLevel, iCur);
    }

    // ── LEFT JOIN hit recording ──
    var goto_outer = false;
    if (rd(c_int, pLevel, WhereLevel.iLeftJoin) != 0) {
        wr(c_int, pLevel, WhereLevel.addrFirst, c.sqlite3VdbeCurrentAddr(v));
        _ = c.sqlite3VdbeAddOp2(v, op.Integer, 1, rd(c_int, pLevel, WhereLevel.iLeftJoin));
        vdbeComment(v, "record LEFT JOIN hit", .{});
        if (rdp(pLevel, WhereLevel.pRJ) == null) {
            goto_outer = true;
        }
    }

    if (!goto_outer and rdp(pLevel, WhereLevel.pRJ) != null) {
        const pRJ = rdp(pLevel, WhereLevel.pRJ);
        _ = c.sqlite3VdbeAddOp2(v, op.BeginSubrtn, 0, rd(c_int, pRJ, WhereRightJoin.regReturn));
        wr(c_int, pRJ, WhereRightJoin.addrSubrtn, c.sqlite3VdbeCurrentAddr(v));
        parse_inc_withinRJSubrtn(pParse);
        goto_outer = true;
    }

    // code_outer_join_constraints:
    if (goto_outer) {
        const nBase = rd(c_int, pWC, WhereClause.nBase);
        const aBase = rdp(pWC, WhereClause.a);
        j = 0;
        while (j < nBase) : (j += 1) {
            const pTerm = fieldPtr(aBase, @as(usize, @intCast(j)) * wtSize());
            if (rd(u16, pTerm, WhereTerm.wtFlags) & (TERM_VIRTUAL | TERM_CODED) != 0) continue;
            if ((wt_prereqAll(pTerm) & rd(u64, pLevel, WhereLevel.notReady)) != 0) continue;
            if (si_jointype(pTabItem) & JT_LTORJ != 0) continue;
            c.sqlite3ExprIfFalse(pParse, rdp(pTerm, WhereTerm.pExpr), addrCont, SQLITE_JUMPIFNULL);
            wr(u16, pTerm, WhereTerm.wtFlags, rd(u16, pTerm, WhereTerm.wtFlags) | TERM_CODED);
        }
    }

    return rd(u64, pLevel, WhereLevel.notReady);
}

inline fn siIsRecursive(pItem: Ptr) bool {
    return (si_fg(pItem) & FG_isRecursive) != 0;
}

// Case 4 body — broken out for readability.
fn codeIndexedLoop(pParse: Ptr, v: Ptr, pWInfo: Ptr, iLevel: c_int, pLevel: Ptr, pLoop: Ptr, pTabItem: Ptr, iCur: c_int, bRev: c_int, _: c_int, addrCont: c_int, notReady: u64, pIrowidReg: *c_int, pIdxOut: *Ptr) void {
    const db = parse_db(pParse);
    const aStartOp = [_]c_int{ 0, 0, op.Rewind, op.Last, op.SeekGT, op.SeekLT, op.SeekGE, op.SeekLE };
    const aEndOp = [_]c_int{ op.IdxGE, op.IdxGT, op.IdxLE, op.IdxLT };
    const nEq: c_int = wl_uBtreeNEq(pLoop);
    var nBtm: c_int = wl_uBtreeNBtm(pLoop);
    var nTop: c_int = wl_uBtreeNTop(pLoop);
    var regBase: c_int = 0;
    var pRangeStart: Ptr = null;
    var pRangeEnd: Ptr = null;
    var startEq: c_int = 0;
    var endEq: c_int = 0;
    var start_constraints: c_int = 0;
    var nConstraint: c_int = 0;
    var nExtraReg: c_int = 0;
    var opv: c_int = 0;
    var zStartAff: ?[*:0]u8 = null;
    var zEndAff: ?[*:0]u8 = null;
    var bSeekPastNull: c_int = 0;
    var bStopAtNull: c_int = 0;
    var regBignull: c_int = 0;
    var addrSeekScan: c_int = 0;

    const pIdx = wl_uBtreePIndex(pLoop);
    pIdxOut.* = pIdx;
    const iIdxCur = rd(c_int, pLevel, WhereLevel.iIdxCur);

    var addrNxt: c_int = 0;
    var j: c_int = nEq;
    if (wl_wsFlags(pLoop) & WHERE_BTM_LIMIT != 0) {
        pRangeStart = wl_aLTermAt(pLoop, @intCast(j));
        j += 1;
        nExtraReg = @max(nExtraReg, @as(c_int, wl_uBtreeNBtm(pLoop)));
    }
    if (wl_wsFlags(pLoop) & WHERE_TOP_LIMIT != 0) {
        pRangeEnd = wl_aLTermAt(pLoop, @intCast(j));
        j += 1;
        nExtraReg = @max(nExtraReg, @as(c_int, wl_uBtreeNTop(pLoop)));
        if (rd(u16, pRangeEnd, WhereTerm.wtFlags) & TERM_LIKEOPT != 0) {
            const cntr = parse_inc_nMem(pParse);
            wr(u32, pLevel, WhereLevel.iLikeRepCntr, @intCast(cntr));
            _ = c.sqlite3VdbeAddOp2(v, op.Integer, 1, cntr);
            vdbeComment(v, "LIKE loop counter", .{});
            wr(c_int, pLevel, WhereLevel.addrLikeRep, c.sqlite3VdbeCurrentAddr(v));
            var rep = rd(u32, pLevel, WhereLevel.iLikeRepCntr) << 1;
            const descBit: u32 = @intFromBool(idx_aSortOrder(pIdx).?[@intCast(nEq)] == SQLITE_SO_DESC);
            rep |= @as(u32, @intCast(bRev)) ^ descBit;
            wr(u32, pLevel, WhereLevel.iLikeRepCntr, rep);
        }
        if (pRangeStart == null) {
            const col = idx_aiColumn(pIdx).?[@intCast(nEq)];
            if ((col >= 0 and !col_notNull(tab_colAt(idx_pTable(pIdx), @intCast(col)))) or col == @as(i16, @intCast(XN_EXPR))) {
                bSeekPastNull = 1;
            }
        }
    }

    if ((wl_wsFlags(pLoop) & (WHERE_TOP_LIMIT | WHERE_BTM_LIMIT)) == 0 and (wl_wsFlags(pLoop) & WHERE_BIGNULL_SORT) != 0) {
        nExtraReg = 1;
        bSeekPastNull = 1;
        regBignull = parse_inc_nMem(pParse);
        wr(c_int, pLevel, WhereLevel.regBignull, regBignull);
        if (rd(c_int, pLevel, WhereLevel.iLeftJoin) != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, regBignull);
        }
        wr(c_int, pLevel, WhereLevel.addrBignull, c.sqlite3VdbeMakeLabel(pParse));
    }

    if (nEq < idx_nColumn(pIdx) and bRev == @intFromBool(idx_aSortOrder(pIdx).?[@intCast(nEq)] == SQLITE_SO_ASC)) {
        const t1 = pRangeEnd;
        pRangeEnd = pRangeStart;
        pRangeStart = t1;
        const t2 = bSeekPastNull;
        bSeekPastNull = bStopAtNull;
        bStopAtNull = t2;
        const t3 = nBtm;
        nBtm = nTop;
        nTop = t3;
    }

    if (iLevel > 0 and (wl_wsFlags(pLoop) & WHERE_IN_SEEKSCAN) != 0) {
        _ = c.sqlite3VdbeAddOp1(v, op.NullRow, iIdxCur);
    }

    codeCursorHint(pTabItem, pWInfo, pLevel, pRangeEnd);
    regBase = codeAllEqualityTerms(pParse, pLevel, bRev, nExtraReg, &zStartAff);
    if (zStartAff != null and nTop != 0) {
        zEndAff = c.sqlite3DbStrDup(db, @ptrCast(zStartAff.? + @as(usize, @intCast(nEq))));
    }
    addrNxt = if (regBignull != 0) rd(c_int, pLevel, WhereLevel.addrBignull) else rd(c_int, pLevel, WhereLevel.addrNxt);

    startEq = @intFromBool(pRangeStart == null or (rd(u16, pRangeStart, WhereTerm.eOperator) & (WO_LE_v | WO_GE_v)) != 0);
    endEq = @intFromBool(pRangeEnd == null or (rd(u16, pRangeEnd, WhereTerm.eOperator) & (WO_LE_v | WO_GE_v)) != 0);
    start_constraints = @intFromBool(pRangeStart != null or nEq > 0);

    nConstraint = nEq;
    if (pRangeStart != null) {
        const pRight = expr_pRight(rdp(pRangeStart, WhereTerm.pExpr));
        codeExprOrVector(pParse, pRight, regBase + nEq, nBtm);
        whereLikeOptimizationStringFixup(v, pLevel, pRangeStart);
        if ((rd(u16, pRangeStart, WhereTerm.wtFlags) & TERM_VNULL) == 0 and c.sqlite3ExprCanBeNull(pRight) != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.IsNull, regBase + nEq, addrNxt);
        }
        if (zStartAff) |za| {
            updateRangeAffinityStr(pRight, nBtm, za + @as(usize, @intCast(nEq)));
        }
        nConstraint += nBtm;
        if (c.sqlite3ExprIsVector(pRight) == 0) {
            disableTerm(pLevel, pRangeStart);
        } else {
            startEq = 1;
        }
        bSeekPastNull = 0;
    } else if (bSeekPastNull != 0) {
        startEq = 0;
        _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, regBase + nEq);
        start_constraints = 1;
        nConstraint += 1;
    } else if (regBignull != 0) {
        _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, regBase + nEq);
        start_constraints = 1;
        nConstraint += 1;
    }
    codeApplyAffinity(pParse, regBase, nConstraint - bSeekPastNull, zStartAff);
    if (wl_nSkip(pLoop) > 0 and nConstraint == wl_nSkip(pLoop)) {
        // skip-scan already positioned cursor
    } else {
        if (regBignull != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.Integer, 1, regBignull);
            vdbeComment(v, "NULL-scan pass ctr", .{});
        }
        if (rd(c_int, pLevel, WhereLevel.regFilter) != 0) {
            _ = c.sqlite3VdbeAddOp4Int(v, op.Filter, rd(c_int, pLevel, WhereLevel.regFilter), addrNxt, regBase, nEq);
            filterPullDown(pParse, pWInfo, iLevel, addrNxt, notReady);
        }
        opv = aStartOp[@intCast((start_constraints << 2) + (startEq << 1) + bRev)];
        if ((wl_wsFlags(pLoop) & WHERE_IN_SEEKSCAN) != 0 and opv == op.SeekGE) {
            addrSeekScan = c.sqlite3VdbeAddOp1(v, op.SeekScan, @divTrunc(@as(c_int, idx_aiRowLogEst(pIdx).?[0]) + 9, 10));
            if (pRangeStart != null or pRangeEnd != null) {
                c.sqlite3VdbeChangeP5(v, 1);
                c.sqlite3VdbeChangeP2(v, addrSeekScan, c.sqlite3VdbeCurrentAddr(v) + 1);
                addrSeekScan = 0;
            }
        }
        _ = c.sqlite3VdbeAddOp4Int(v, opv, iIdxCur, addrNxt, regBase, nConstraint);
        if (regBignull != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.Goto, 0, c.sqlite3VdbeCurrentAddr(v) + 2);
            opv = aStartOp[@intCast(@as(c_int, @intFromBool(nConstraint > 1)) * 4 + 2 + bRev)];
            _ = c.sqlite3VdbeAddOp4Int(v, opv, iIdxCur, addrNxt, regBase, nConstraint - startEq);
        }
    }

    nConstraint = nEq;
    if (pRangeEnd != null) {
        const pRight = expr_pRight(rdp(pRangeEnd, WhereTerm.pExpr));
        codeExprOrVector(pParse, pRight, regBase + nEq, nTop);
        whereLikeOptimizationStringFixup(v, pLevel, pRangeEnd);
        if ((rd(u16, pRangeEnd, WhereTerm.wtFlags) & TERM_VNULL) == 0 and c.sqlite3ExprCanBeNull(pRight) != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.IsNull, regBase + nEq, addrNxt);
        }
        if (zEndAff) |za| {
            updateRangeAffinityStr(pRight, nTop, za);
            codeApplyAffinity(pParse, regBase + nEq, nTop, zEndAff);
        }
        nConstraint += nTop;
        if (c.sqlite3ExprIsVector(pRight) == 0) {
            disableTerm(pLevel, pRangeEnd);
        } else {
            endEq = 1;
        }
    } else if (bStopAtNull != 0) {
        if (regBignull == 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, regBase + nEq);
            endEq = 0;
        }
        nConstraint += 1;
    }
    if (zStartAff != null) c.sqlite3DbNNFreeNN(db, @ptrCast(zStartAff));
    if (zEndAff != null) c.sqlite3DbNNFreeNN(db, @ptrCast(zEndAff));

    wr(c_int, pLevel, WhereLevel.p2, c.sqlite3VdbeCurrentAddr(v));

    if (nConstraint != 0) {
        if (regBignull != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.IfNot, regBignull, c.sqlite3VdbeCurrentAddr(v) + 3);
            vdbeComment(v, "If NULL-scan 2nd pass", .{});
        }
        opv = aEndOp[@intCast(bRev * 2 + endEq)];
        _ = c.sqlite3VdbeAddOp4Int(v, opv, iIdxCur, addrNxt, regBase, nConstraint);
        if (addrSeekScan != 0) c.sqlite3VdbeJumpHere(v, addrSeekScan);
    }
    if (regBignull != 0) {
        _ = c.sqlite3VdbeAddOp2(v, op.If, regBignull, c.sqlite3VdbeCurrentAddr(v) + 2);
        vdbeComment(v, "If NULL-scan 1st pass", .{});
        opv = aEndOp[@intCast(bRev * 2 + bSeekPastNull)];
        _ = c.sqlite3VdbeAddOp4Int(v, opv, iIdxCur, addrNxt, regBase, nConstraint + bSeekPastNull);
    }

    if ((wl_wsFlags(pLoop) & WHERE_IN_EARLYOUT) != 0) {
        _ = c.sqlite3VdbeAddOp3(v, op.SeekHit, iIdxCur, nEq, nEq);
    }

    // Seek table cursor if required
    const omitTable = (wl_wsFlags(pLoop) & WHERE_IDX_ONLY) != 0 and (wi_wctrlFlags(pWInfo) & (WHERE_OR_SUBCLAUSE | WHERE_RIGHT_JOIN)) == 0;
    if (omitTable) {
        // covering index — no table access
    } else if (tab_hasRowid(idx_pTable(pIdx))) {
        codeDeferredSeek(pWInfo, pIdx, iCur, iIdxCur);
    } else if (iCur != iIdxCur) {
        const pPk = c.sqlite3PrimaryKeyIndex(idx_pTable(pIdx));
        const nKeyCol: c_int = idx_nKeyCol(pPk);
        pIrowidReg.* = c.sqlite3GetTempRange(pParse, nKeyCol);
        var jj: c_int = 0;
        while (jj < nKeyCol) : (jj += 1) {
            const kk = c.sqlite3TableColumnToIndex(pIdx, idx_aiColumn(pPk).?[@intCast(jj)]);
            _ = c.sqlite3VdbeAddOp3(v, op.Column, iIdxCur, kk, pIrowidReg.* + jj);
        }
        _ = c.sqlite3VdbeAddOp4Int(v, op.NotFound, iCur, addrCont, pIrowidReg.*, nKeyCol);
    }

    if (rd(c_int, pLevel, WhereLevel.iLeftJoin) == 0) {
        if (idx_pPartIdxWhere(pIdx) != null and rdp(pLevel, WhereLevel.pRJ) == null) {
            whereApplyPartialIndexConstraints(idx_pPartIdxWhere(pIdx), iCur, wi_sWC(pWInfo));
        }
    }

    if ((wl_wsFlags(pLoop) & WHERE_ONEROW) != 0 or
        (rd(c_int, pLevel, WhereLevel.u_in_nIn) != 0 and regBignull == 0 and whereLoopIsOneRow(pLoop) != 0))
    {
        wr(u8, pLevel, WhereLevel.op, @intCast(op.Noop));
    } else if (bRev != 0) {
        wr(u8, pLevel, WhereLevel.op, @intCast(op.Prev));
    } else {
        wr(u8, pLevel, WhereLevel.op, @intCast(op.Next));
    }
    wr(c_int, pLevel, WhereLevel.p1, iIdxCur);
    wr(u8, pLevel, WhereLevel.p3, if ((wl_wsFlags(pLoop) & WHERE_UNQ_WANTED) != 0) 1 else 0);
    if ((wl_wsFlags(pLoop) & WHERE_CONSTRAINT) == 0) {
        wr(u8, pLevel, WhereLevel.p5, SQLITE_STMTSTATUS_FULLSCAN_STEP);
    }
    if (omitTable) pIdxOut.* = null;
}

// Case 5 body — returns the early-return Bitmask (on OOM) or null.
fn codeOrLoop(pParse: Ptr, v: Ptr, pWInfo: Ptr, iLevel: c_int, pLevel: Ptr, pLoop: Ptr, pTabItem: Ptr, iCur: c_int, db: Ptr, notReady: u64) ?u64 {
    const pTerm0 = wl_aLTermAt(pLoop, 0);
    const pOrWc = wt_pOrInfo(pTerm0); // WhereOrInfo.wc is at offset 0
    wr(u8, pLevel, WhereLevel.op, @intCast(op.Return));
    var pCov: Ptr = null;
    const iCovCur = parse_postinc_nTab(pParse);
    const regReturn = parse_inc_nMem(pParse);
    var regRowset: c_int = 0;
    var regRowid: c_int = 0;
    const iLoopBody = c.sqlite3VdbeMakeLabel(pParse);
    var untestedTerms: c_int = 0;
    var pAndExpr: Ptr = null;
    const pTab = si_pSTab(pTabItem);
    wr(c_int, pLevel, WhereLevel.p1, regReturn);

    var pOrTab: Ptr = undefined;
    if (wi_nLevel(pWInfo) > 1 or siFromExists(pTabItem)) {
        const nNotReady: c_int = @as(c_int, wi_nLevel(pWInfo)) - iLevel - 1;
        pOrTab = c.sqlite3DbMallocRawNN(db, @intCast(SrcList.a + @as(usize, @intCast(nNotReady + 1)) * SrcItem.sizeof));
        if (pOrTab == null) return notReady;
        wr(c_int, pOrTab, SrcList.nAlloc, nNotReady + 1);
        wr(c_int, pOrTab, SrcList.nSrc, nNotReady + 1);
        @memcpy(@as([*]u8, @ptrCast(srcItemAt(pOrTab, 0)))[0..SrcItem.sizeof], @as([*]const u8, @ptrCast(pTabItem))[0..SrcItem.sizeof]);
        const origSrc = wi_pTabList(pWInfo);
        var kk: c_int = 1;
        while (kk <= nNotReady) : (kk += 1) {
            const lvlK = wi_levelAt(pWInfo, @intCast(kk));
            const fromK = rd(u8, lvlK, WhereLevel.iFrom);
            @memcpy(@as([*]u8, @ptrCast(srcItemAt(pOrTab, @intCast(kk))))[0..SrcItem.sizeof], @as([*]const u8, @ptrCast(srcItemAt(origSrc, @intCast(fromK))))[0..SrcItem.sizeof]);
        }
        // clear fromExists on a[0]
        const a0 = srcItemAt(pOrTab, 0);
        si_set_fg(a0, si_fg(a0) & ~FG_fromExists);
    } else {
        pOrTab = wi_pTabList(pWInfo);
    }

    if ((wi_wctrlFlags(pWInfo) & WHERE_DUPLICATES_OK) == 0) {
        if (tab_hasRowid(pTab)) {
            regRowset = parse_inc_nMem(pParse);
            _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, regRowset);
        } else {
            const pPk = c.sqlite3PrimaryKeyIndex(pTab);
            regRowset = parse_postinc_nTab(pParse);
            _ = c.sqlite3VdbeAddOp2(v, op.OpenEphemeral, regRowset, idx_nKeyCol(pPk));
            c.sqlite3VdbeSetP4KeyInfo(pParse, pPk);
        }
        regRowid = parse_inc_nMem(pParse);
    }
    const iRetInit = c.sqlite3VdbeAddOp2(v, op.Integer, 0, regReturn);

    if (rd(c_int, pWC_of(pWInfo), WhereClause.nTerm) > 1) {
        const pWC = pWC_of(pWInfo);
        const nTerm = rd(c_int, pWC, WhereClause.nTerm);
        const aBase = rdp(pWC, WhereClause.a);
        var iTerm: c_int = 0;
        while (iTerm < nTerm) : (iTerm += 1) {
            const pT = fieldPtr(aBase, @as(usize, @intCast(iTerm)) * wtSize());
            var pExpr = rdp(pT, WhereTerm.pExpr);
            if (pT == pTerm0) continue;
            if ((rd(u16, pT, WhereTerm.wtFlags) & (TERM_VIRTUAL | TERM_CODED | TERM_SLICE)) != 0) continue;
            if ((rd(u16, pT, WhereTerm.eOperator) & 0x3fff) == 0) continue; // WO_ALL
            if (exprHasProperty(pExpr, EP_Subquery)) continue;
            pExpr = c.sqlite3ExprDup(db, pExpr, 0);
            pAndExpr = c.sqlite3ExprAnd(pParse, pAndExpr, pExpr);
        }
        if (pAndExpr != null) {
            pAndExpr = c.sqlite3PExpr(pParse, TK_AND | 0x10000, null, pAndExpr);
        }
    }

    explainQueryPlan(pParse, 1, "MULTI-INDEX OR", .{});
    const nOrTerm = rd(c_int, pOrWc, WhereClause.nTerm);
    const aOrBase = rdp(pOrWc, WhereClause.a);
    var ii: c_int = 0;
    while (ii < nOrTerm) : (ii += 1) {
        const pOrTerm = fieldPtr(aOrBase, @as(usize, @intCast(ii)) * wtSize());
        if (rd(c_int, pOrTerm, WhereTerm.leftCursor) == iCur or (rd(u16, pOrTerm, WhereTerm.eOperator) & WO_AND) != 0) {
            var pOrExpr = rdp(pOrTerm, WhereTerm.pExpr);
            const pDelete = c.sqlite3ExprDup(db, pOrExpr, 0);
            pOrExpr = pDelete;
            if (db_mallocFailed(db)) {
                c.sqlite3ExprDelete(db, pDelete);
                continue;
            }
            if (pAndExpr != null) {
                expr_set_pLeft(pAndExpr, pOrExpr);
                pOrExpr = pAndExpr;
            }
            explainQueryPlan(pParse, 1, "INDEX %d", .{ii + 1});
            const pSubWInfo = c.sqlite3WhereBegin(pParse, pOrTab, pOrExpr, null, null, null, WHERE_OR_SUBCLAUSE, iCovCur);
            if (pSubWInfo != null) {
                const subA0 = wi_levelAt(pSubWInfo, 0);
                const addrExplain = sqlite3WhereExplainOneScan(pParse, pOrTab, subA0, 0);
                whereAddScanStatus(v, pOrTab, subA0, addrExplain);
                var jmp1: c_int = 0;
                if ((wi_wctrlFlags(pWInfo) & WHERE_DUPLICATES_OK) == 0) {
                    const iSet: c_int = if (ii == nOrTerm - 1) -1 else ii;
                    if (tab_hasRowid(pTab)) {
                        c.sqlite3ExprCodeGetColumnOfTable(v, pTab, iCur, -1, regRowid);
                        jmp1 = c.sqlite3VdbeAddOp4Int(v, op.RowSetTest, regRowset, 0, regRowid, iSet);
                    } else {
                        const pPk = c.sqlite3PrimaryKeyIndex(pTab);
                        const nPk: c_int = idx_nKeyCol(pPk);
                        const r = c.sqlite3GetTempRange(pParse, nPk);
                        var iPk: c_int = 0;
                        while (iPk < nPk) : (iPk += 1) {
                            const iCol = idx_aiColumn(pPk).?[@intCast(iPk)];
                            c.sqlite3ExprCodeGetColumnOfTable(v, pTab, iCur, iCol, r + iPk);
                        }
                        if (iSet != 0) {
                            jmp1 = c.sqlite3VdbeAddOp4Int(v, op.Found, regRowset, 0, r, nPk);
                        }
                        if (iSet >= 0) {
                            _ = c.sqlite3VdbeAddOp3(v, op.MakeRecord, r, nPk, regRowid);
                            _ = c.sqlite3VdbeAddOp4Int(v, op.IdxInsert, regRowset, regRowid, r, nPk);
                            if (iSet != 0) c.sqlite3VdbeChangeP5(v, OPFLAG_USESEEKRESULT);
                        }
                        c.sqlite3ReleaseTempRange(pParse, r, nPk);
                    }
                }
                // Invoke the main loop body as a subroutine
                _ = c.sqlite3VdbeAddOp2(v, op.Gosub, regReturn, iLoopBody);
                if (jmp1 != 0) c.sqlite3VdbeJumpHere(v, jmp1);
                finishOrBranch(pParse, v, pWInfo, pSubWInfo, pTab, iCovCur, &pCov, &untestedTerms, ii);
            }
            c.sqlite3ExprDelete(db, pDelete);
        }
    }
    explainQueryPlanPop(pParse);

    wr(Ptr, pLevel, WhereLevel.u_pCoveringIdx, pCov);
    if (pCov != null) wr(c_int, pLevel, WhereLevel.iIdxCur, iCovCur);
    if (pAndExpr != null) {
        expr_set_pLeft(pAndExpr, null);
        c.sqlite3ExprDelete(db, pAndExpr);
    }
    c.sqlite3VdbeChangeP1(v, iRetInit, c.sqlite3VdbeCurrentAddr(v));
    _ = c.sqlite3VdbeGoto(v, rd(c_int, pLevel, WhereLevel.addrBrk));
    c.sqlite3VdbeResolveLabel(v, iLoopBody);
    wr(c_int, pLevel, WhereLevel.p2, c.sqlite3VdbeCurrentAddr(v));

    if (wi_pTabList(pWInfo) != pOrTab) c.sqlite3DbFreeNN(db, pOrTab);
    if (untestedTerms == 0) disableTerm(pLevel, pTerm0);
    return null;
}

inline fn pWC_of(pWInfo: Ptr) Ptr {
    return wi_sWC(pWInfo);
}

fn finishOrBranch(pParse: Ptr, v: Ptr, pWInfo: Ptr, pSubWInfo: Ptr, pTab: Ptr, iCovCur: c_int, pCov: *Ptr, untestedTerms: *c_int, ii: c_int) void {
    _ = v;
    // untestedTerms |= pSubWInfo->untestedTerms
    if ((rd(u8, pSubWInfo, off("WhereInfo_bits", WhereInfo.bits_prod)) & WHEREINFO_bits_untestedTerms) != 0) {
        untestedTerms.* = 1;
    }
    const subA0 = wi_levelAt(pSubWInfo, 0);
    const pSubLoop = rdp(subA0, WhereLevel.pWLoop);
    if ((wl_wsFlags(pSubLoop) & WHERE_INDEXED) != 0 and
        (ii == 0 or wl_uBtreePIndex(pSubLoop) == pCov.*) and
        (tab_hasRowid(pTab) or !idx_isPrimaryKey(wl_uBtreePIndex(pSubLoop))))
    {
        pCov.* = wl_uBtreePIndex(pSubLoop);
    } else {
        pCov.* = null;
    }
    _ = iCovCur;
    if (c.sqlite3WhereUsesDeferredSeek(pSubWInfo) != 0) {
        wi_set_bDeferredSeek(pWInfo);
    }
    c.sqlite3WhereEnd(pSubWInfo);
    explainQueryPlanPop(pParse);
}

// RIGHT JOIN match recording block (within OneLoopStart, after constraint coding).
fn codeRightJoinMatch(pParse: Ptr, v: Ptr, pWInfo: Ptr, pLevel: Ptr, iCur: c_int) void {
    const pRJ = rdp(pLevel, WhereLevel.pRJ);
    var nPk: c_int = undefined;
    var r: c_int = undefined;
    const pTab = si_pSTab(srcItemAt(wi_pTabList(pWInfo), @intCast(rd(u8, pLevel, WhereLevel.iFrom))));
    if (tab_hasRowid(pTab)) {
        r = c.sqlite3GetTempRange(pParse, 2);
        c.sqlite3ExprCodeGetColumnOfTable(v, pTab, rd(c_int, pLevel, WhereLevel.iTabCur), -1, r + 1);
        nPk = 1;
    } else {
        const pPk = c.sqlite3PrimaryKeyIndex(pTab);
        nPk = idx_nKeyCol(pPk);
        r = c.sqlite3GetTempRange(pParse, nPk + 1);
        var iPk: c_int = 0;
        while (iPk < nPk) : (iPk += 1) {
            const iCol = idx_aiColumn(pPk).?[@intCast(iPk)];
            c.sqlite3ExprCodeGetColumnOfTable(v, pTab, iCur, iCol, r + 1 + iPk);
        }
    }
    const jmp1 = c.sqlite3VdbeAddOp4Int(v, op.Found, rd(c_int, pRJ, WhereRightJoin.iMatch), 0, r + 1, nPk);
    vdbeComment(v, "match against %s", .{tab_zName(pTab)});
    _ = c.sqlite3VdbeAddOp3(v, op.MakeRecord, r + 1, nPk, r);
    _ = c.sqlite3VdbeAddOp4Int(v, op.IdxInsert, rd(c_int, pRJ, WhereRightJoin.iMatch), r, r + 1, nPk);
    _ = c.sqlite3VdbeAddOp4Int(v, op.FilterAdd, rd(c_int, pRJ, WhereRightJoin.regBloom), 0, r + 1, nPk);
    c.sqlite3VdbeChangeP5(v, OPFLAG_USESEEKRESULT);
    c.sqlite3VdbeJumpHere(v, jmp1);
    c.sqlite3ReleaseTempRange(pParse, r, nPk + 1);
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3WhereRightJoinLoop
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3WhereRightJoinLoop(pWInfo: Ptr, iLevel: c_int, pLevel: Ptr) callconv(.c) void {
    const pParse = wi_pParse(pWInfo);
    const v = parse_pVdbe(pParse);
    const pRJ = rdp(pLevel, WhereLevel.pRJ);
    var pSubWhere: Ptr = null;
    const pWC = wi_sWC(pWInfo);
    const pLoop = rdp(pLevel, WhereLevel.pWLoop);
    const pTabItem = srcItemAt(wi_pTabList(pWInfo), @intCast(rd(u8, pLevel, WhereLevel.iFrom)));
    // union { SrcList sSrc; u8 fromSpace[SZ_SRCLIST_1]; } — allocate enough.
    var uSrc: [SrcList.a + SrcItem.sizeof + 16]u8 = undefined;
    var mAll: u64 = 0;

    explainQueryPlan(pParse, 1, "RIGHT-JOIN %s", .{tab_zName(si_pSTab(pTabItem))});
    if (config.sqlite_debug) {
        c.sqlite3VdbeNoJumpsOutsideSubrtn(v, rd(c_int, pRJ, WhereRightJoin.addrSubrtn), rd(c_int, pRJ, WhereRightJoin.endSubrtn), rd(c_int, pRJ, WhereRightJoin.regReturn));
    }
    var kk: c_int = 0;
    while (kk < iLevel) : (kk += 1) {
        const lvlK = wi_levelAt(pWInfo, @intCast(kk));
        const fromK = rd(u8, lvlK, WhereLevel.iFrom);
        const pRight = srcItemAt(wi_pTabList(pWInfo), @intCast(fromK));
        mAll |= wl_maskSelf(rdp(lvlK, WhereLevel.pWLoop));
        if (siViaCoroutine(pRight)) {
            const pSubq = si_u4pSubq(pRight);
            _ = c.sqlite3VdbeAddOp3(v, op.Null, 0, sq_regResult(pSubq), sq_regResult(pSubq) + el_nExpr(sel_pEList(sq_pSelect(pSubq))) - 1);
        }
        _ = c.sqlite3VdbeAddOp1(v, op.NullRow, rd(c_int, lvlK, WhereLevel.iTabCur));
        const iIdxCur = rd(c_int, lvlK, WhereLevel.iIdxCur);
        if (iIdxCur != 0) {
            _ = c.sqlite3VdbeAddOp1(v, op.NullRow, iIdxCur);
        }
    }
    if ((si_jointype(pTabItem) & JT_LTORJ) == 0) {
        mAll |= wl_maskSelf(pLoop);
        const nTerm = rd(c_int, pWC, WhereClause.nTerm);
        const aBase = rdp(pWC, WhereClause.a);
        var kkt: c_int = 0;
        while (kkt < nTerm) : (kkt += 1) {
            const pTerm = fieldPtr(aBase, @as(usize, @intCast(kkt)) * wtSize());
            if ((rd(u16, pTerm, WhereTerm.wtFlags) & (TERM_VIRTUAL | TERM_SLICE)) != 0 and rd(u16, pTerm, WhereTerm.eOperator) != WO_ROWVAL) {
                break;
            }
            if (wt_prereqAll(pTerm) & ~mAll != 0) continue;
            if (exprHasProperty(rdp(pTerm, WhereTerm.pExpr), EP_OuterON | EP_InnerON)) continue;
            pSubWhere = c.sqlite3ExprAnd(pParse, pSubWhere, c.sqlite3ExprDup(parse_db(pParse), rdp(pTerm, WhereTerm.pExpr), 0));
        }
    }
    if (rd(c_int, pLevel, WhereLevel.iIdxCur) != 0) {
        _ = c.sqlite3VdbeAddOp1(v, op.NullRow, rd(c_int, pLevel, WhereLevel.iIdxCur));
    }
    const pFrom: Ptr = @ptrCast(&uSrc);
    wr(c_int, pFrom, SrcList.nSrc, 1);
    wr(c_int, pFrom, SrcList.nAlloc, 1);
    @memcpy(@as([*]u8, @ptrCast(srcItemAt(pFrom, 0)))[0..SrcItem.sizeof], @as([*]const u8, @ptrCast(pTabItem))[0..SrcItem.sizeof]);
    // pFrom->a[0].fg.jointype = 0  (clear low byte of fg word, keep nothing else — C sets full jointype=0)
    const a0 = srcItemAt(pFrom, 0);
    si_set_fg(a0, si_fg(a0) & ~FG_jointype_mask);
    parse_inc_withinRJSubrtn(pParse);
    const pSubWInfo = c.sqlite3WhereBegin(pParse, pFrom, pSubWhere, null, null, null, WHERE_RIGHT_JOIN, 0);
    if (pSubWInfo != null) {
        const iCur = rd(c_int, pLevel, WhereLevel.iTabCur);
        const r = parse_inc_nMem(pParse);
        var nPk: c_int = undefined;
        const addrCont = c.sqlite3WhereContinueLabel(pSubWInfo);
        const pTab = si_pSTab(pTabItem);
        if (tab_hasRowid(pTab)) {
            c.sqlite3ExprCodeGetColumnOfTable(v, pTab, iCur, -1, r);
            nPk = 1;
        } else {
            const pPk = c.sqlite3PrimaryKeyIndex(pTab);
            nPk = idx_nKeyCol(pPk);
            parse_add_nMem(pParse, nPk - 1);
            var iPk: c_int = 0;
            while (iPk < nPk) : (iPk += 1) {
                const iCol = idx_aiColumn(pPk).?[@intCast(iPk)];
                c.sqlite3ExprCodeGetColumnOfTable(v, pTab, iCur, iCol, r + iPk);
            }
        }
        const jmp = c.sqlite3VdbeAddOp4Int(v, op.Filter, rd(c_int, pRJ, WhereRightJoin.regBloom), 0, r, nPk);
        _ = c.sqlite3VdbeAddOp4Int(v, op.Found, rd(c_int, pRJ, WhereRightJoin.iMatch), addrCont, r, nPk);
        c.sqlite3VdbeJumpHere(v, jmp);
        _ = c.sqlite3VdbeAddOp2(v, op.Gosub, rd(c_int, pRJ, WhereRightJoin.regReturn), rd(c_int, pRJ, WhereRightJoin.addrSubrtn));
        c.sqlite3WhereEnd(pSubWInfo);
    }
    c.sqlite3ExprDelete(parse_db(pParse), pSubWhere);
    explainQueryPlanPop(pParse);
    parse_dec_withinRJSubrtn(pParse);
}
