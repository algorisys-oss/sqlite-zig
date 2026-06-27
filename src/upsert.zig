//! Zig port of SQLite's src/upsert.c — UPSERT (ON CONFLICT) processing and the
//! Upsert object lifecycle.
//!
//! Exported (non-static) symbols — the complete external set of upsert.c
//! (SQLITE_OMIT_UPSERT is OFF in both build configs):
//!   - sqlite3UpsertDelete
//!   - sqlite3UpsertDup
//!   - sqlite3UpsertNew
//!   - sqlite3UpsertAnalyzeTarget
//!   - sqlite3UpsertNextIsIPK
//!   - sqlite3UpsertOfIndex
//!   - sqlite3UpsertDoUpdate
//! The static upsertDelete() helper becomes a private Zig fn.
//!
//! This is a struct-coupled + codegen module: it walks the parse tree (Upsert /
//! Expr / ExprList / Index / Table / SrcList) by raw offset and emits VDBE
//! bytecode via the same C-ABI helpers the rest of the front-end uses. Offsets
//! come from c_layout.zig (generated ground truth) with probe-verified
//! fallbacks shared with insert.zig / update.zig.
//!
//! ─── Config assumptions (true in both build configs) ───────────────────────
//!   * SQLITE_OMIT_UPSERT OFF.
//!   * SQLITE_ENABLE_EXPLAIN_COMMENTS ON → VdbeComment / VdbeNoopComment are
//!     real symbols (the latter emits an OP_Noop and must be reproduced).
//!   * SQLITE_VDBE_COVERAGE OFF → VdbeCoverage(...) is a no-op in this config.
//!   * VdbeVerifyAbortable is SQLITE_DEBUG-only (no-op macro in production).
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

// ─── struct offsets ──────────────────────────────────────────────────────────
// Upsert
const Upsert_pUpsertTarget_off = off("Upsert_pUpsertTarget", 0);
const Upsert_pUpsertTargetWhere_off = off("Upsert_pUpsertTargetWhere", 8);
const Upsert_pUpsertSet_off = off("Upsert_pUpsertSet", 16);
const Upsert_pUpsertWhere_off = off("Upsert_pUpsertWhere", 24);
const Upsert_pNextUpsert_off = off("Upsert_pNextUpsert", 32);
const Upsert_isDoUpdate_off: usize = 40; // probe-verified (shared with insert.zig)
const Upsert_pToFree_off: usize = 48;
const Upsert_pUpsertIdx_off: usize = 56;
const Upsert_pUpsertSrc_off: usize = 64;
const Upsert_regData_off: usize = 72;
const Upsert_iDataCur_off = off("Upsert_iDataCur", 76);
const Upsert_iIdxCur_off = off("Upsert_iIdxCur", 80);
const sizeof_Upsert: usize = 88;

// SrcList / SrcItem (only the single a[0] item is ever touched here)
const SrcList_nSrc_off = off("SrcList_nSrc", 0);
const SrcList_a_off = off("SrcList_a", 8);
const SrcItem_pSTab_off = off("SrcItem_pSTab", 16);
const SrcItem_iCursor_off = off("SrcItem_iCursor", 28);

// Table
const Table_aCol_off = off("Table_aCol", 8);
const Table_pIndex_off = off("Table_pIndex", 16);
const Table_tabFlags_off = off("Table_tabFlags", 48);
const Table_nCol_off = off("Table_nCol", 54);
// Column
const Column_zCnName_off = off("Column_zCnName", 0);
const Column_affinity_off = off("Column_affinity", 9);
const sizeof_Column = off("sizeof_Column", 16);

// Index
const Index_zName_off = off("Index_zName", 0);
const Index_aiColumn_off = off("Index_aiColumn", 8);
const Index_pNext_off = off("Index_pNext", 40);
const Index_azColl_off = off("Index_azColl", 64);
const Index_pPartIdxWhere_off = off("Index_pPartIdxWhere", 72);
const Index_aColExpr_off = off("Index_aColExpr", 80);
const Index_nKeyCol_off = off("Index_nKeyCol", 94);
const Index_onError_off = off("Index_onError", 98);

// Expr (the on-stack sCol[2] scratch nodes use these)
const Expr_op_off = off("Expr_op", 0);
const Expr_u_off = off("Expr_u", 8); // u.zToken is the first union member (char*)
const Expr_pLeft_off = off("Expr_pLeft", 16);
const Expr_iTable_off = off("Expr_iTable", 44);
const Expr_iColumn_off = off("Expr_iColumn", 48);
const sizeof_Expr = off("sizeof_Expr", 72);

// ExprList
const ExprList_nExpr_off = off("ExprList_nExpr", 0);
const ExprList_a_off = off("ExprList_a", 8);
const ExprList_item_pExpr_off = off("ExprList_item_pExpr", 0);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);

// NameContext
const NameContext_pParse_off = off("NameContext_pParse", 0);
const NameContext_pSrcList_off = off("NameContext_pSrcList", 8);
const sizeof_NameContext = off("sizeof_NameContext", 56);

// ─── constants ───────────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_CORRUPT: c_int = 11;
const TK_COLLATE: u8 = 114;
const TK_COLUMN: u8 = 168;
const XN_ROWID: i16 = -1;
const XN_EXPR: i16 = -2;
const OE_None: c_int = 0;
const OE_Abort: c_int = 2;
const TF_WithoutRowid: u32 = 0x0080;
const SQLITE_AFF_REAL: u8 = 0x45;
const P4_STATIC: c_int = -1;
const OP_Column: c_int = 96;
const OP_Found: c_int = 29;
const OP_Halt: c_int = 72;
const OP_IdxRowid: c_int = 144;
const OP_SeekRowid: c_int = 30;
const OP_RealAffinity: c_int = 89;

// ─── field accessors ─────────────────────────────────────────────────────────
inline fn upTarget(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertTarget_off);
}
inline fn upTargetWhere(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertTargetWhere_off);
}
inline fn upSet(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertSet_off);
}
inline fn upWhere(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertWhere_off);
}
inline fn upNext(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pNextUpsert_off);
}
inline fn upIdx(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertIdx_off);
}
inline fn upIsDup(p: ?*anyopaque) u8 {
    return rd(u8, p, Upsert_isDoUpdate_off + 1); // isDup follows isDoUpdate
}
inline fn upSrc(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertSrc_off);
}
inline fn upRegData(p: ?*anyopaque) c_int {
    return rd(c_int, p, Upsert_regData_off);
}
inline fn upIDataCur(p: ?*anyopaque) c_int {
    return rd(c_int, p, Upsert_iDataCur_off);
}

inline fn srcItem0(pSrc: ?*anyopaque) ?*anyopaque {
    // &pSrc->a[0]
    return @ptrCast(base(pSrc) + SrcList_a_off);
}
inline fn tabPIndex(pTab: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pTab, Table_pIndex_off);
}
inline fn hasRowid(pTab: ?*anyopaque) bool {
    return (rd(u32, pTab, Table_tabFlags_off) & TF_WithoutRowid) == 0;
}
inline fn isUniqueIndex(pIdx: ?*anyopaque) bool {
    return rd(u8, pIdx, Index_onError_off) != @as(u8, @intCast(OE_None));
}
inline fn idxNKeyCol(pIdx: ?*anyopaque) c_int {
    return @intCast(rd(u16, pIdx, Index_nKeyCol_off));
}
inline fn idxAiColumn(pIdx: ?*anyopaque, i: usize) i16 {
    const a = rd(?*anyopaque, pIdx, Index_aiColumn_off);
    return rd(i16, a, i * @sizeOf(i16));
}
inline fn idxAzColl(pIdx: ?*anyopaque, i: usize) ?[*:0]const u8 {
    const a = rd(?*anyopaque, pIdx, Index_azColl_off);
    return rd(?[*:0]const u8, a, i * @sizeOf(usize));
}
inline fn idxColExpr(pIdx: ?*anyopaque, i: usize) ?*anyopaque {
    // pIdx->aColExpr->a[i].pExpr
    const pList = rd(?*anyopaque, pIdx, Index_aColExpr_off);
    const aBase: [*]u8 = base(pList) + ExprList_a_off;
    return rd(?*anyopaque, @as(?*anyopaque, @ptrCast(aBase + i * sizeof_ExprList_item)), ExprList_item_pExpr_off);
}
inline fn elNExpr(pList: ?*anyopaque) c_int {
    return rd(c_int, pList, ExprList_nExpr_off);
}
inline fn elItemExpr(pList: ?*anyopaque, i: usize) ?*anyopaque {
    const aBase: [*]u8 = base(pList) + ExprList_a_off;
    return rd(?*anyopaque, @as(?*anyopaque, @ptrCast(aBase + i * sizeof_ExprList_item)), ExprList_item_pExpr_off);
}
inline fn exprOp(p: ?*anyopaque) u8 {
    return rd(u8, p, Expr_op_off);
}

// ─── extern C helpers (already-ported Zig or still-C, all C ABI) ─────────────
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3SrcListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;

extern fn sqlite3ResolveExprListNames(pNC: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3ResolveExprNames(pNC: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3ExprCompare(pParse: ?*anyopaque, pA: ?*anyopaque, pB: ?*anyopaque, iTab: c_int) c_int;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_snprintf(n: c_int, buf: [*]u8, fmt: [*:0]const u8, ...) ?[*:0]u8;

extern fn sqlite3PrimaryKeyIndex(pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3TableColumnToIndex(pIdx: ?*anyopaque, iCol: i16) i16;
extern fn sqlite3TableColumnToStorage(pTab: ?*anyopaque, iCol: i16) i16;
extern fn sqlite3GetTempReg(pParse: ?*anyopaque) c_int;
extern fn sqlite3ReleaseTempReg(pParse: ?*anyopaque, iReg: c_int) void;
extern fn sqlite3MayAbort(pParse: ?*anyopaque) void;
extern fn sqlite3Update(pParse: ?*anyopaque, pTabList: ?*anyopaque, pChanges: ?*anyopaque, pWhere: ?*anyopaque, onError: c_int, pOrderBy: ?*anyopaque, pLimit: ?*anyopaque, pUpsert: ?*anyopaque) void;

extern fn sqlite3VdbeAddOp1(p: ?*anyopaque, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*:0]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeJumpHere(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeComment(v: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3VdbeNoopComment(v: ?*anyopaque, fmt: [*:0]const u8, ...) void;

// VdbeVerifyAbortable is SQLITE_DEBUG-only; @extern only inside the debug branch
// so production never references the symbol.
inline fn vdbeVerifyAbortable(p: ?*anyopaque, onError: c_int) void {
    if (config.sqlite_debug) {
        const f = @extern(*const fn (?*anyopaque, c_int) callconv(.c) void, .{ .name = "sqlite3VdbeVerifyAbortable" });
        f(p, onError);
    }
}

// Pull the codegen Vdbe / db handle out of a Parse* the way the macros do.
const Parse_db_off = off("Parse_db", 0);
const Parse_pVdbe_off = off("Parse_pVdbe", 16);
const Parse_nMem_off = off("Parse_nMem", 60);
inline fn pDb(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_db_off);
}
inline fn pVdbe(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pVdbe_off);
}
inline fn pNMem(pParse: ?*anyopaque) c_int {
    return rd(c_int, pParse, Parse_nMem_off);
}
inline fn setNMem(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_nMem_off, v);
}

// ─── upsertDelete: free a list of Upsert objects ─────────────────────────────
fn upsertDelete(db: ?*anyopaque, p0: ?*anyopaque) void {
    var p = p0;
    while (true) {
        const pNext = upNext(p);
        sqlite3ExprListDelete(db, upTarget(p));
        sqlite3ExprDelete(db, upTargetWhere(p));
        sqlite3ExprListDelete(db, upSet(p));
        sqlite3ExprDelete(db, upWhere(p));
        sqlite3DbFree(db, rd(?*anyopaque, p, Upsert_pToFree_off));
        sqlite3DbFree(db, p);
        p = pNext;
        if (p == null) break;
    }
}

export fn sqlite3UpsertDelete(db: ?*anyopaque, p: ?*anyopaque) void {
    if (p != null) upsertDelete(db, p);
}

// ─── sqlite3UpsertDup: deep-copy an Upsert chain ─────────────────────────────
export fn sqlite3UpsertDup(db: ?*anyopaque, p: ?*anyopaque) ?*anyopaque {
    if (p == null) return null;
    return sqlite3UpsertNew(
        db,
        sqlite3ExprListDup(db, upTarget(p), 0),
        sqlite3ExprDup(db, upTargetWhere(p), 0),
        sqlite3ExprListDup(db, upSet(p), 0),
        sqlite3ExprDup(db, upWhere(p), 0),
        sqlite3UpsertDup(db, upNext(p)),
    );
}

// ─── sqlite3UpsertNew: allocate and populate a new Upsert ─────────────────────
export fn sqlite3UpsertNew(
    db: ?*anyopaque,
    pTarget: ?*anyopaque,
    pTargetWhere: ?*anyopaque,
    pSet: ?*anyopaque,
    pWhere: ?*anyopaque,
    pNext: ?*anyopaque,
) ?*anyopaque {
    const pNew = sqlite3DbMallocZero(db, sizeof_Upsert);
    if (pNew == null) {
        sqlite3ExprListDelete(db, pTarget);
        sqlite3ExprDelete(db, pTargetWhere);
        sqlite3ExprListDelete(db, pSet);
        sqlite3ExprDelete(db, pWhere);
        sqlite3UpsertDelete(db, pNext);
        return null;
    }
    wr(?*anyopaque, pNew, Upsert_pUpsertTarget_off, pTarget);
    wr(?*anyopaque, pNew, Upsert_pUpsertTargetWhere_off, pTargetWhere);
    wr(?*anyopaque, pNew, Upsert_pUpsertSet_off, pSet);
    wr(?*anyopaque, pNew, Upsert_pUpsertWhere_off, pWhere);
    wr(u8, pNew, Upsert_isDoUpdate_off, @intFromBool(pSet != null));
    wr(?*anyopaque, pNew, Upsert_pNextUpsert_off, pNext);
    return pNew;
}

// ─── sqlite3UpsertAnalyzeTarget: resolve the conflict-target ──────────────────
export fn sqlite3UpsertAnalyzeTarget(
    pParse: ?*anyopaque,
    pTabList: ?*anyopaque,
    pUpsert0: ?*anyopaque,
    pAll: ?*anyopaque,
) c_int {
    var pUpsert = pUpsert0;
    var nClause: c_int = 0;

    const pItem0 = srcItem0(pTabList);
    const iCursor = rd(c_int, pItem0, SrcItem_iCursor_off);

    // Resolve all symbolic names in the conflict-target clause.
    var sNC: [sizeof_NameContext]u8 align(8) = undefined;
    @memset(&sNC, 0);
    wr(?*anyopaque, &sNC, NameContext_pParse_off, pParse);
    wr(?*anyopaque, &sNC, NameContext_pSrcList_off, pTabList);

    while (pUpsert != null and upTarget(pUpsert) != null) : ({
        pUpsert = upNext(pUpsert);
        nClause += 1;
    }) {
        var rc = sqlite3ResolveExprListNames(&sNC, upTarget(pUpsert));
        if (rc != 0) return rc;
        rc = sqlite3ResolveExprNames(&sNC, upTargetWhere(pUpsert));
        if (rc != 0) return rc;

        // Does the conflict target match the rowid?
        const pTab = rd(?*anyopaque, pItem0, SrcItem_pSTab_off);
        const pTarget = upTarget(pUpsert);
        if (hasRowid(pTab) and elNExpr(pTarget) == 1) {
            const pTerm = elItemExpr(pTarget, 0);
            if (exprOp(pTerm) == TK_COLUMN and rd(i16, pTerm, Expr_iColumn_off) == XN_ROWID) {
                // The conflict-target is the rowid of the primary table.
                continue;
            }
        }

        // Build sCol[0..1]: TK_COLLATE over a TK_COLUMN, reused per index column.
        var sColBuf: [2 * sizeof_Expr]u8 align(8) = undefined;
        @memset(&sColBuf, 0);
        const sCol0: ?*anyopaque = @ptrCast(&sColBuf[0]);
        const sCol1: ?*anyopaque = @ptrCast(&sColBuf[sizeof_Expr]);
        wr(u8, sCol0, Expr_op_off, TK_COLLATE);
        wr(?*anyopaque, sCol0, Expr_pLeft_off, sCol1);
        wr(u8, sCol1, Expr_op_off, TK_COLUMN);
        wr(c_int, sCol1, Expr_iTable_off, iCursor);

        // Search the indexes for one matching the conflict target.
        var pIdx = tabPIndex(pTab);
        while (pIdx != null) : (pIdx = rd(?*anyopaque, pIdx, Index_pNext_off)) {
            if (!isUniqueIndex(pIdx)) continue;
            const nn = idxNKeyCol(pIdx);
            if (elNExpr(pTarget) != nn) continue;
            if (rd(?*anyopaque, pIdx, Index_pPartIdxWhere_off) != null) {
                if (upTargetWhere(pUpsert) == null) continue;
                if (sqlite3ExprCompare(pParse, upTargetWhere(pUpsert), rd(?*anyopaque, pIdx, Index_pPartIdxWhere_off), iCursor) != 0) {
                    continue;
                }
            }
            var ii: c_int = 0;
            while (ii < nn) : (ii += 1) {
                const uii: usize = @intCast(ii);
                var pExpr: ?*anyopaque = undefined;
                wr(?*anyopaque, sCol0, Expr_u_off, @constCast(@as(?*const anyopaque, idxAzColl(pIdx, uii))));
                if (idxAiColumn(pIdx, uii) == XN_EXPR) {
                    pExpr = idxColExpr(pIdx, uii);
                    if (exprOp(pExpr) != TK_COLLATE) {
                        wr(?*anyopaque, sCol0, Expr_pLeft_off, pExpr);
                        pExpr = sCol0;
                    }
                } else {
                    wr(?*anyopaque, sCol0, Expr_pLeft_off, sCol1);
                    wr(i16, sCol1, Expr_iColumn_off, idxAiColumn(pIdx, uii));
                    pExpr = sCol0;
                }
                var jj: c_int = 0;
                while (jj < nn) : (jj += 1) {
                    if (sqlite3ExprCompare(null, elItemExpr(pTarget, @intCast(jj)), pExpr, iCursor) < 2) {
                        break; // column ii of index matches column jj of target
                    }
                }
                if (jj >= nn) break; // no match for column ii
            }
            if (ii < nn) continue; // some index column unmatched → next index

            wr(?*anyopaque, pUpsert, Upsert_pUpsertIdx_off, pIdx);
            if (sqlite3UpsertOfIndex(pAll, pIdx) != pUpsert) {
                // A duplicate ON CONFLICT clause that will never fire; tolerated
                // for backwards compatibility.
                wr(u8, pUpsert, Upsert_isDoUpdate_off + 1, 1); // isDup = 1
            }
            break;
        }
        if (upIdx(pUpsert) == null) {
            var zWhich: [16]u8 = undefined;
            if (nClause == 0 and upNext(pUpsert) == null) {
                zWhich[0] = 0;
            } else {
                _ = sqlite3_snprintf(zWhich.len, &zWhich, "%r ", nClause + 1);
            }
            sqlite3ErrorMsg(pParse, "%sON CONFLICT clause does not match any " ++
                "PRIMARY KEY or UNIQUE constraint", @as([*:0]const u8, @ptrCast(&zWhich)));
            return SQLITE_ERROR;
        }
    }
    return SQLITE_OK;
}

// ─── sqlite3UpsertNextIsIPK ───────────────────────────────────────────────────
export fn sqlite3UpsertNextIsIPK(pUpsert: ?*anyopaque) c_int {
    if (pUpsert == null) return 0; // NEVER() in C
    var pNext = upNext(pUpsert);
    while (true) {
        if (pNext == null) return 1;
        if (upTarget(pNext) == null) return 1;
        if (upIdx(pNext) == null) return 1;
        if (upIsDup(pNext) == 0) return 0;
        pNext = upNext(pNext);
    }
}

// ─── sqlite3UpsertOfIndex ─────────────────────────────────────────────────────
export fn sqlite3UpsertOfIndex(pUpsert0: ?*anyopaque, pIdx: ?*anyopaque) ?*anyopaque {
    var pUpsert = pUpsert0;
    while (pUpsert != null and upTarget(pUpsert) != null and upIdx(pUpsert) != pIdx) {
        pUpsert = upNext(pUpsert);
    }
    return pUpsert;
}

// ─── sqlite3UpsertDoUpdate: emit the DO UPDATE leg of an upsert ───────────────
export fn sqlite3UpsertDoUpdate(
    pParse: ?*anyopaque,
    pUpsert0: ?*anyopaque,
    pTab: ?*anyopaque,
    pIdx: ?*anyopaque,
    iCur: c_int,
) void {
    const v = pVdbe(pParse);
    const db = pDb(pParse);
    const pTop = pUpsert0;

    const iDataCur = upIDataCur(pUpsert0);
    const pUpsert = sqlite3UpsertOfIndex(pTop, pIdx);
    sqlite3VdbeNoopComment(v, "Begin DO UPDATE of UPSERT");
    if (pIdx != null and iCur != iDataCur) {
        if (hasRowid(pTab)) {
            const regRowid = sqlite3GetTempReg(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_IdxRowid, iCur, regRowid);
            _ = sqlite3VdbeAddOp3(v, OP_SeekRowid, iDataCur, 0, regRowid);
            sqlite3ReleaseTempReg(pParse, regRowid);
        } else {
            const pPk = sqlite3PrimaryKeyIndex(pTab);
            const nPk = idxNKeyCol(pPk);
            const iPk = pNMem(pParse) + 1;
            setNMem(pParse, pNMem(pParse) + nPk);
            var i: c_int = 0;
            while (i < nPk) : (i += 1) {
                const ui: usize = @intCast(i);
                const colNo = idxAiColumn(pPk, ui);
                const k = sqlite3TableColumnToIndex(pIdx, colNo);
                _ = sqlite3VdbeAddOp3(v, OP_Column, iCur, k, iPk + i);
                if (config.sqlite_debug) {
                    const aCol = rd(?*anyopaque, pTab, Table_aCol_off);
                    const pCol: ?*anyopaque = @ptrCast(base(aCol) + @as(usize, @intCast(colNo)) * sizeof_Column);
                    sqlite3VdbeComment(v, "%s.%s", rd(?[*:0]const u8, pIdx, Index_zName_off), rd(?[*:0]const u8, pCol, Column_zCnName_off));
                }
            }
            vdbeVerifyAbortable(v, OE_Abort);
            const j = sqlite3VdbeAddOp4Int(v, OP_Found, iDataCur, 0, iPk, nPk);
            _ = sqlite3VdbeAddOp4(v, OP_Halt, SQLITE_CORRUPT, OE_Abort, 0, "corrupt database", P4_STATIC);
            sqlite3MayAbort(pParse);
            sqlite3VdbeJumpHere(v, j);
        }
    }
    // pUpsert does not own pTop->pUpsertSrc — copy it before sqlite3Update().
    const pSrc = sqlite3SrcListDup(db, upSrc(pTop), 0);
    // excluded.* REAL columns need a hard real-affinity conversion.
    const nCol: c_int = @intCast(rd(i16, pTab, Table_nCol_off));
    const aCol = rd(?*anyopaque, pTab, Table_aCol_off);
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        const ui: usize = @intCast(i);
        const pCol: ?*anyopaque = @ptrCast(base(aCol) + ui * sizeof_Column);
        if (rd(u8, pCol, Column_affinity_off) == SQLITE_AFF_REAL) {
            const iStorage = upRegData(pTop) + sqlite3TableColumnToStorage(pTab, @intCast(i));
            _ = sqlite3VdbeAddOp1(v, OP_RealAffinity, iStorage);
        }
    }
    sqlite3Update(pParse, pSrc, sqlite3ExprListDup(db, upSet(pUpsert), 0), sqlite3ExprDup(db, upWhere(pUpsert), 0), OE_Abort, null, null, pUpsert);
    sqlite3VdbeNoopComment(v, "End DO UPDATE of UPSERT");
}
