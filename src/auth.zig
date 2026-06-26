//! Zig port of SQLite's src/auth.c — the authorization-callback layer that
//! implements the sqlite3_set_authorizer() API.
//!
//! Exported (non-static) symbols — the complete external set of auth.c, matching
//! the prototypes in sqlite.h.in / sqliteInt.h:
//!   - sqlite3_set_authorizer   (public C API)
//!   - sqlite3AuthReadCol
//!   - sqlite3AuthRead
//!   - sqlite3AuthCheck
//!   - sqlite3AuthContextPush
//!   - sqlite3AuthContextPop
//! The static helpers (sqliteAuthBadReturnCode, realAuthCheck) are private to
//! this module and stay non-exported. auth.c defines no file-scope globals.
//!
//! ─── Config assumptions (true in both this project's builds) ───────────────
//!   * SQLITE_OMIT_AUTHORIZATION OFF → this whole file is compiled (it is wholly
//!     wrapped in `#ifndef SQLITE_OMIT_AUTHORIZATION`).
//!   * SQLITE_OMIT_ALTERTABLE  OFF and SQLITE_OMIT_VIRTUALTABLE OFF → both
//!     IN_RENAME_OBJECT and IN_SPECIAL_PARSE are *real* expressions over
//!     pParse->eParseMode (not the constant 0). realAuthCheck honours
//!     IN_SPECIAL_PARSE; sqlite3AuthRead only asserts !IN_RENAME_OBJECT.
//!   * SQLITE_ENABLE_API_ARMOR OFF → the SafetyCheckOk/MISUSE_BKPT armor in
//!     sqlite3_set_authorizer is omitted (matches the C preprocessor result).
//!   * Little-endian x86-64.
//!
//! ─── Struct coupling ──────────────────────────────────────────────────────
//! Every offset used here was probe-verified (offsetof program built with this
//! project's exact -D flags) in BOTH the production library config and the
//! `--dev` testfixture (SQLITE_DEBUG + SQLITE_TEST) config. Every field used has
//! an IDENTICAL offset in both configs:
//!   sqlite3 : xAuth(528), pAuthArg(536), nDb(40), aDb(32), mutex(24),
//!             init.busy(197)
//!   Parse   : db(0), rc(24), nErr(52), zAuthContext(368), eParseMode(300),
//!             pTriggerTab(144)
//!   Db      : zDbSName(0), sizeof 32
//!   Table   : zName(0), nCol(54), iPKey(52), aCol(8)
//!   Column  : zCnName(0), sizeof 16
//!   Expr    : op(0,u8), iTable(44), iColumn(48)
//!   SrcList : nSrc(0), a(8); SrcItem: iCursor(28), pSTab(16), sizeof 72
//!   AuthContext : zAuthContext(0), pParse(8), sizeof 16
//!
//! No standalone Zig unit test is feasible — every path couples to the live
//! connection and parser. Validated through the engine by the TCL suite
//! (auth.test, auth2.test, auth3.test and every test registering an authorizer).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── Result / action codes ──────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_DENY: c_int = 1;
const SQLITE_IGNORE: c_int = 2;
const SQLITE_READ: c_int = 20;
const SQLITE_AUTH: c_int = 23;

// ─── parse token values (from parse.h) ──────────────────────────────────────
const TK_TRIGGER: u8 = 78;
const TK_NULL: u8 = 122;
const TK_COLUMN: u8 = 168;

// Parse.eParseMode values
const PARSE_MODE_NORMAL: u8 = 0;
const PARSE_MODE_RENAME: u8 = 2;

// ═══ ground-truth offsets ═══════════════════════════════════════════════════
// Reuse the c_layout entry where the orchestrator has added it, else a
// probe-verified fallback constant. All identical in prod and tf.

// sqlite3
const sqlite3_xAuth_off: usize = if (@hasDecl(L, "sqlite3_xAuth")) L.sqlite3_xAuth else 528;
const sqlite3_pAuthArg_off: usize = if (@hasDecl(L, "sqlite3_pAuthArg")) L.sqlite3_pAuthArg else 536;
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_mutex_off: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const sqlite3_initBusy_off: usize = if (@hasDecl(L, "sqlite3_initBusy")) L.sqlite3_initBusy else 197;

const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;

// Parse
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_rc_off: usize = if (@hasDecl(L, "Parse_rc")) L.Parse_rc else 24;
const Parse_nErr_off: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;
const Parse_zAuthContext_off: usize = if (@hasDecl(L, "Parse_zAuthContext")) L.Parse_zAuthContext else 368;
const Parse_eParseMode_off: usize = if (@hasDecl(L, "Parse_eParseMode")) L.Parse_eParseMode else 300;
const Parse_pTriggerTab_off: usize = if (@hasDecl(L, "Parse_pTriggerTab")) L.Parse_pTriggerTab else 144;

// Table
const Table_zName_off: usize = if (@hasDecl(L, "Table_zName")) L.Table_zName else 0;
const Table_nCol_off: usize = if (@hasDecl(L, "Table_nCol")) L.Table_nCol else 54;
const Table_iPKey_off: usize = if (@hasDecl(L, "Table_iPKey")) L.Table_iPKey else 52;
const Table_aCol_off: usize = if (@hasDecl(L, "Table_aCol")) L.Table_aCol else 8;

// Column
const Column_zCnName_off: usize = if (@hasDecl(L, "Column_zCnName")) L.Column_zCnName else 0;
const sizeof_Column: usize = if (@hasDecl(L, "sizeof_Column")) L.sizeof_Column else 16;

// Expr
const Expr_op_off: usize = if (@hasDecl(L, "Expr_op")) L.Expr_op else 0;
const Expr_iTable_off: usize = if (@hasDecl(L, "Expr_iTable")) L.Expr_iTable else 44;
const Expr_iColumn_off: usize = if (@hasDecl(L, "Expr_iColumn")) L.Expr_iColumn else 48;

// SrcList / SrcItem
const SrcList_nSrc_off: usize = if (@hasDecl(L, "SrcList_nSrc")) L.SrcList_nSrc else 0;
const SrcList_a_off: usize = if (@hasDecl(L, "SrcList_a")) L.SrcList_a else 8;
const SrcItem_iCursor_off: usize = if (@hasDecl(L, "SrcItem_iCursor")) L.SrcItem_iCursor else 28;
const SrcItem_pSTab_off: usize = if (@hasDecl(L, "SrcItem_pSTab")) L.SrcItem_pSTab else 16;
const sizeof_SrcItem: usize = if (@hasDecl(L, "sizeof_SrcItem")) L.sizeof_SrcItem else 72;

// AuthContext (caller-stack struct; we mirror it directly as an extern struct).
const AuthContext = extern struct {
    zAuthContext: ?[*:0]const u8, // 0
    pParse: ?*anyopaque, // 8
};
comptime {
    std.debug.assert(@offsetOf(AuthContext, "zAuthContext") == 0);
    std.debug.assert(@offsetOf(AuthContext, "pParse") == 8);
    std.debug.assert(@sizeOf(AuthContext) == 16);
}

// ─── raw field accessors ────────────────────────────────────────────────────
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

// The authorizer callback type: int(*)(void*,int,const char*,const char*,
//                                       const char*,const char*)
const XAuth = ?*const fn (
    ?*anyopaque,
    c_int,
    ?[*:0]const u8,
    ?[*:0]const u8,
    ?[*:0]const u8,
    ?[*:0]const u8,
) callconv(.c) c_int;

// sqlite3 accessors
inline fn dbXAuth(db: ?*anyopaque) XAuth {
    return rd(XAuth, db, sqlite3_xAuth_off);
}
inline fn dbSetXAuth(db: ?*anyopaque, v: XAuth) void {
    wr(XAuth, db, sqlite3_xAuth_off, v);
}
inline fn dbSetPAuthArg(db: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, db, sqlite3_pAuthArg_off, v);
}
inline fn dbPAuthArg(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_pAuthArg_off);
}
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rd(c_int, db, sqlite3_nDb_off);
}
inline fn dbMutex(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_mutex_off);
}
inline fn dbInitBusy(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_initBusy_off];
}
// db->aDb is a `Db*` pointer; db->aDb[iDb].zDbSName
inline fn dbAtZDbSName(db: ?*anyopaque, iDb: c_int) ?[*:0]const u8 {
    const aDb: [*]u8 = @ptrCast(rd(?*anyopaque, db, sqlite3_aDb_off).?);
    const item = aDb + (@as(usize, @intCast(iDb)) * sizeof_Db) + Db_zDbSName_off;
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(item);
    return q.*;
}

// Parse accessors
inline fn pDb(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_db_off);
}
inline fn pSetRc(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_rc_off, v);
}
inline fn pZAuthContext(pParse: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, pParse, Parse_zAuthContext_off);
}
inline fn pSetZAuthContext(pParse: ?*anyopaque, v: ?[*:0]const u8) void {
    wr(?[*:0]const u8, pParse, Parse_zAuthContext_off, v);
}
inline fn pEParseMode(pParse: ?*anyopaque) u8 {
    return base(pParse)[Parse_eParseMode_off];
}
inline fn pPTriggerTab(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pTriggerTab_off);
}

// IN_RENAME_OBJECT / IN_SPECIAL_PARSE (both OMIT flags are OFF here).
inline fn inRenameObject(pParse: ?*anyopaque) bool {
    return pEParseMode(pParse) >= PARSE_MODE_RENAME;
}
inline fn inSpecialParse(pParse: ?*anyopaque) bool {
    return pEParseMode(pParse) != PARSE_MODE_NORMAL;
}

// Table accessors
inline fn tabZName(pTab: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, pTab, Table_zName_off);
}
inline fn tabNCol(pTab: ?*anyopaque) i16 {
    return rd(i16, pTab, Table_nCol_off);
}
inline fn tabIPKey(pTab: ?*anyopaque) i16 {
    return rd(i16, pTab, Table_iPKey_off);
}
// pTab->aCol is a `Column*`; pTab->aCol[i].zCnName
inline fn tabColZName(pTab: ?*anyopaque, iCol: i16) ?[*:0]const u8 {
    const aCol: [*]u8 = @ptrCast(rd(?*anyopaque, pTab, Table_aCol_off).?);
    const col = aCol + (@as(usize, @intCast(iCol)) * sizeof_Column) + Column_zCnName_off;
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(col);
    return q.*;
}

// Expr accessors
inline fn exprOp(pExpr: ?*anyopaque) u8 {
    return base(pExpr)[Expr_op_off];
}
inline fn exprSetOp(pExpr: ?*anyopaque, v: u8) void {
    base(pExpr)[Expr_op_off] = v;
}
inline fn exprITable(pExpr: ?*anyopaque) c_int {
    return rd(c_int, pExpr, Expr_iTable_off);
}
inline fn exprIColumn(pExpr: ?*anyopaque) i16 {
    return rd(i16, pExpr, Expr_iColumn_off);
}

// SrcList accessors
inline fn srcNSrc(pTabList: ?*anyopaque) c_int {
    return rd(c_int, pTabList, SrcList_nSrc_off);
}
// pTabList->a[i] base pointer (SrcItem is inline array)
inline fn srcItemAt(pTabList: ?*anyopaque, i: c_int) [*]u8 {
    return base(pTabList) + SrcList_a_off + (@as(usize, @intCast(i)) * sizeof_SrcItem);
}
inline fn srcItemICursor(item: [*]u8) c_int {
    const q: *align(1) const c_int = @ptrCast(item + SrcItem_iCursor_off);
    return q.*;
}
inline fn srcItemPSTab(item: [*]u8) ?*anyopaque {
    const q: *align(1) const ?*anyopaque = @ptrCast(item + SrcItem_pSTab_off);
    return q.*;
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ════════════════
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;
extern fn sqlite3ExpirePreparedStatements(db: ?*anyopaque, i: c_int) void;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) c_int;

// ═══ sqlite3_set_authorizer ══════════════════════════════════════════════════
// Set or clear the access authorization function.
export fn sqlite3_set_authorizer(
    db: ?*anyopaque,
    xAuth: XAuth,
    pArg: ?*anyopaque,
) callconv(.c) c_int {
    // SQLITE_ENABLE_API_ARMOR is OFF → no SafetyCheckOk guard.
    sqlite3_mutex_enter(dbMutex(db));
    dbSetXAuth(db, xAuth);
    dbSetPAuthArg(db, pArg);
    sqlite3ExpirePreparedStatements(db, 1);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

// ═══ sqliteAuthBadReturnCode (static) ════════════════════════════════════════
// Write an error message explaining that the user-supplied authorization
// function returned an illegal value.
fn sqliteAuthBadReturnCode(pParse: ?*anyopaque) void {
    sqlite3ErrorMsg(pParse, "authorizer malfunction");
    pSetRc(pParse, SQLITE_ERROR);
}

// ═══ sqlite3AuthReadCol ══════════════════════════════════════════════════════
// Invoke the authorization callback for permission to read column zCol from
// table zTab in database (index) iDb. Assumes db->xAuth != NULL.
export fn sqlite3AuthReadCol(
    pParse: ?*anyopaque,
    zTab: ?[*:0]const u8,
    zCol: ?[*:0]const u8,
    iDb: c_int,
) callconv(.c) c_int {
    const db = pDb(pParse);
    const zDb = dbAtZDbSName(db, iDb);

    if (dbInitBusy(db) != 0) return SQLITE_OK;
    const xAuth = dbXAuth(db).?;
    const rc = xAuth(dbPAuthArg(db), SQLITE_READ, zTab, zCol, zDb, pZAuthContext(pParse));
    if (rc == SQLITE_DENY) {
        var z = sqlite3_mprintf("%s.%s", zTab, zCol);
        if (dbNDb(db) > 2 or iDb != 0) {
            // %z frees the previous result `z` after formatting.
            z = sqlite3_mprintf("%s.%z", zDb, z);
        }
        sqlite3ErrorMsg(pParse, "access to %z is prohibited", z);
        pSetRc(pParse, SQLITE_AUTH);
    } else if (rc != SQLITE_IGNORE and rc != SQLITE_OK) {
        sqliteAuthBadReturnCode(pParse);
    }
    return rc;
}

// ═══ sqlite3AuthRead ═════════════════════════════════════════════════════════
// pExpr is a TK_COLUMN (or TK_TRIGGER) expression. Check whether it is OK to
// read this particular column; on SQLITE_IGNORE rewrite the node to TK_NULL.
export fn sqlite3AuthRead(
    pParse: ?*anyopaque,
    pExpr: ?*anyopaque,
    pSchema: ?*anyopaque,
    pTabList: ?*anyopaque,
) callconv(.c) void {
    var pTab: ?*anyopaque = null;
    const db = pDb(pParse);

    std.debug.assert(exprOp(pExpr) == TK_COLUMN or exprOp(pExpr) == TK_TRIGGER);
    std.debug.assert(!inRenameObject(pParse));
    std.debug.assert(dbXAuth(db) != null);

    const iDb = sqlite3SchemaToIndex(db, pSchema);
    if (iDb < 0) {
        // An attempt to read a column out of a subquery or other temporary
        // table.
        return;
    }

    if (exprOp(pExpr) == TK_TRIGGER) {
        pTab = pPTriggerTab(pParse);
    } else {
        std.debug.assert(pTabList != null);
        var iSrc: c_int = 0;
        const nSrc = srcNSrc(pTabList);
        while (iSrc < nSrc) : (iSrc += 1) {
            const item = srcItemAt(pTabList, iSrc);
            if (exprITable(pExpr) == srcItemICursor(item)) {
                pTab = srcItemPSTab(item);
                break;
            }
        }
    }
    const iCol = exprIColumn(pExpr);
    if (pTab == null) return;

    var zCol: ?[*:0]const u8 = undefined;
    if (iCol >= 0) {
        std.debug.assert(iCol < tabNCol(pTab));
        zCol = tabColZName(pTab, iCol);
    } else if (tabIPKey(pTab) >= 0) {
        std.debug.assert(tabIPKey(pTab) < tabNCol(pTab));
        zCol = tabColZName(pTab, tabIPKey(pTab));
    } else {
        zCol = "ROWID";
    }
    std.debug.assert(iDb >= 0 and iDb < dbNDb(db));
    if (sqlite3AuthReadCol(pParse, tabZName(pTab), zCol, iDb) == SQLITE_IGNORE) {
        exprSetOp(pExpr, TK_NULL);
    }
}

// ═══ realAuthCheck (static) ══════════════════════════════════════════════════
// Do an authorization check using the code and arguments given. Returns
// SQLITE_OK / SQLITE_IGNORE / SQLITE_DENY. The C version is SQLITE_NOINLINE; in
// Zig we simply keep it a private function.
fn realAuthCheck(
    pParse: ?*anyopaque,
    code: c_int,
    zArg1: ?[*:0]const u8,
    zArg2: ?[*:0]const u8,
    zArg3: ?[*:0]const u8,
) c_int {
    const db = pDb(pParse);

    // Don't do any authorization checks if the database is initializing or if
    // the parser is being invoked from within sqlite3_declare_vtab.
    std.debug.assert(!inRenameObject(pParse) or dbXAuth(db) == null);
    if (inSpecialParse(pParse)) {
        return SQLITE_OK;
    }

    const xAuth = dbXAuth(db).?;
    var rc = xAuth(dbPAuthArg(db), code, zArg1, zArg2, zArg3, pZAuthContext(pParse));
    if (rc == SQLITE_DENY) {
        sqlite3ErrorMsg(pParse, "not authorized");
        pSetRc(pParse, SQLITE_AUTH);
    } else if (rc != SQLITE_OK and rc != SQLITE_IGNORE) {
        rc = SQLITE_DENY;
        sqliteAuthBadReturnCode(pParse);
    }
    return rc;
}

// ═══ sqlite3AuthCheck ════════════════════════════════════════════════════════
export fn sqlite3AuthCheck(
    pParse: ?*anyopaque,
    code: c_int,
    zArg1: ?[*:0]const u8,
    zArg2: ?[*:0]const u8,
    zArg3: ?[*:0]const u8,
) callconv(.c) c_int {
    const db = pDb(pParse);
    if (dbXAuth(db) != null and dbInitBusy(db) == 0) {
        return realAuthCheck(pParse, code, zArg1, zArg2, zArg3);
    } else {
        return SQLITE_OK;
    }
}

// ═══ sqlite3AuthContextPush ══════════════════════════════════════════════════
// Push an authorization context. After this, the zArg3 argument to authorization
// callbacks will be zContext until popped.
export fn sqlite3AuthContextPush(
    pParse: ?*anyopaque,
    pContext: *AuthContext,
    zContext: ?[*:0]const u8,
) callconv(.c) void {
    std.debug.assert(pParse != null);
    pContext.pParse = pParse;
    pContext.zAuthContext = pZAuthContext(pParse);
    pSetZAuthContext(pParse, zContext);
}

// ═══ sqlite3AuthContextPop ═══════════════════════════════════════════════════
// Pop an authorization context previously pushed by sqlite3AuthContextPush.
export fn sqlite3AuthContextPop(pContext: *AuthContext) callconv(.c) void {
    if (pContext.pParse != null) {
        pSetZAuthContext(pContext.pParse, pContext.zAuthContext);
        pContext.pParse = null;
    }
}
