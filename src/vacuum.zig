//! Zig port of SQLite's src/vacuum.c — the VACUUM command.
//!
//! Exported (non-static) symbols — the COMPLETE external set of vacuum.c, as
//! declared in sqliteInt.h:
//!   - sqlite3Vacuum     (codegen: emits OP_Vacuum during parse)
//!   - sqlite3RunVacuum  (the OP_Vacuum opcode handler: copy-to-temp-db + swap)
//! The static helpers (execSql, execSqlF, vacuumFinalize) are private to this
//! module. (Upstream's vacuumFinalize was removed in the version we vendor; the
//! current file inlines sqlite3_finalize. We follow the vendored source.)
//!
//! ─── Config assumptions (verified true in BOTH this project's builds) ───────
//!   * SQLITE_OMIT_VACUUM        OFF → the whole file is compiled.
//!   * SQLITE_OMIT_ATTACH        OFF → the whole file is compiled.
//!   * SQLITE_OMIT_AUTOVACUUM    OFF → the SetAutoVacuum / GetAutoVacuum calls
//!                                     are present (both blocks).
//!   * SQLITE_BUG_COMPATIBLE_20160819 OFF → the default (error-on-bad-arg)
//!                                     branch of sqlite3Vacuum is used.
//!   * Little-endian x86-64.
//!
//! ─── Struct coupling ──────────────────────────────────────────────────────
//! sqlite3RunVacuum reads/writes many internal `sqlite3` and `Db` fields. Every
//! offset used was probe-verified (offsetof program over the vendored headers)
//! in BOTH the production library config and the `--dev` testfixture
//! (SQLITE_DEBUG + SQLITE_TEST) config; ALL are IDENTICAL between the two:
//!   sqlite3: autoCommit@101, nVdbeActive@208, openFlags@76, flags@48,
//!            mDbFlags@44, nChange@120, nTotalChange@128, mTrace@110,
//!            nextPagesize@116, nextAutovac@106, mallocFailed@103, nDb@40,
//!            aDb@32, init.iDb@196.
//!   Db:      zDbSName@0, pBt@8, pSchema@24, safety_level@16, sizeof==32.
//!   Schema:  cache_size@116.
//!   Parse:   db@0, nErr@52, nMem@60.
//!   sqlite3_file: pMethods@0.
//!
//! No standalone Zig unit test is feasible — every path drives the live btree,
//! pager and prepared-statement machinery. Validated through the engine by the
//! TCL suite (vacuum*.test, vacuum-into, etc.).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ─── Result codes ───────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;

// ─── value types ────────────────────────────────────────────────────────────
const SQLITE_TEXT: c_int = 3;

// ─── sqlite3.flags bits (u64) ───────────────────────────────────────────────
inline fn HI(comptime x: u64) u64 {
    return x << 32;
}
const SQLITE_WriteSchema: u64 = 0x00000001;
const SQLITE_IgnoreChecks: u64 = 0x00000200;
const SQLITE_ReverseOrder: u64 = 0x00001000;
const SQLITE_ForeignKeys: u64 = 0x00004000;
const SQLITE_Defensive: u64 = 0x10000000;
const SQLITE_CountRows: u64 = HI(0x00001);
const SQLITE_AttachCreate: u64 = HI(0x00010);
const SQLITE_AttachWrite: u64 = HI(0x00020);
const SQLITE_Comments: u64 = HI(0x00040);

// ─── sqlite3.mDbFlags bits (u32) ────────────────────────────────────────────
const DBFLAG_PreferBuiltin: u32 = 0x0002;
const DBFLAG_Vacuum: u32 = 0x0004;
const DBFLAG_VacuumInto: u32 = 0x0008;

// ─── open flags ─────────────────────────────────────────────────────────────
const SQLITE_OPEN_READONLY: u32 = 0x00000001;
const SQLITE_OPEN_READWRITE: u32 = 0x00000002;
const SQLITE_OPEN_CREATE: u32 = 0x00000004;

// ─── pager flags ────────────────────────────────────────────────────────────
const PAGER_SYNCHRONOUS_OFF: u32 = 0x01;
const PAGER_CACHESPILL: u32 = 0x20;
const PAGER_FLAGS_MASK: u64 = 0x38;
const PAGER_JOURNALMODE_WAL: c_int = 5;

// ─── btree meta indices + txn states ────────────────────────────────────────
const BTREE_SCHEMA_VERSION: c_int = 1;
const BTREE_DEFAULT_CACHE_SIZE: c_int = 3;
const BTREE_TEXT_ENCODING: c_int = 5;
const BTREE_USER_VERSION: c_int = 6;
const BTREE_APPLICATION_ID: c_int = 8;
const SQLITE_TXN_WRITE: c_int = 2;

// ─── opcodes ────────────────────────────────────────────────────────────────
const OP_Vacuum: c_int = 5;

// ═══ ground-truth offsets (identical in prod and --dev) ══════════════════════
const sqlite3_autoCommit_off: usize = if (@hasDecl(L, "sqlite3_autoCommit")) L.sqlite3_autoCommit else 101;
const sqlite3_nVdbeActive_off: usize = if (@hasDecl(L, "sqlite3_nVdbeActive")) L.sqlite3_nVdbeActive else 208;
const sqlite3_openFlags_off: usize = if (@hasDecl(L, "sqlite3_openFlags")) L.sqlite3_openFlags else 76;
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_mDbFlags_off: usize = if (@hasDecl(L, "sqlite3_mDbFlags")) L.sqlite3_mDbFlags else 44;
const sqlite3_nChange_off: usize = if (@hasDecl(L, "sqlite3_nChange")) L.sqlite3_nChange else 120;
const sqlite3_nTotalChange_off: usize = if (@hasDecl(L, "sqlite3_nTotalChange")) L.sqlite3_nTotalChange else 128;
const sqlite3_mTrace_off: usize = if (@hasDecl(L, "sqlite3_mTrace")) L.sqlite3_mTrace else 110;
const sqlite3_nextPagesize_off: usize = if (@hasDecl(L, "sqlite3_nextPagesize")) L.sqlite3_nextPagesize else 116;
const sqlite3_nextAutovac_off: usize = if (@hasDecl(L, "sqlite3_nextAutovac")) L.sqlite3_nextAutovac else 106;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_init_iDb_off: usize = if (@hasDecl(L, "sqlite3_init_iDb")) L.sqlite3_init_iDb else 196;

const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pBt_off: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;
const Db_safety_level_off: usize = if (@hasDecl(L, "Db_safety_level")) L.Db_safety_level else 16;
const Db_pSchema_off: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

const Schema_cache_size_off: usize = if (@hasDecl(L, "Schema_cache_size")) L.Schema_cache_size else 116;

const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_nErr_off: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;
const Parse_nMem_off: usize = if (@hasDecl(L, "Parse_nMem")) L.Parse_nMem else 60;

// sqlite3_file.pMethods is the first (only) field.
const sqlite3_file_pMethods_off: usize = 0;

// ═══ raw field accessors ════════════════════════════════════════════════════
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

// sqlite3 fields
inline fn dbAutoCommit(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_autoCommit_off];
}
inline fn dbSetAutoCommit(db: ?*anyopaque, v: u8) void {
    base(db)[sqlite3_autoCommit_off] = v;
}
inline fn dbNVdbeActive(db: ?*anyopaque) c_int {
    return rd(c_int, db, sqlite3_nVdbeActive_off);
}
inline fn dbOpenFlags(db: ?*anyopaque) u32 {
    return rd(u32, db, sqlite3_openFlags_off);
}
inline fn dbSetOpenFlags(db: ?*anyopaque, v: u32) void {
    wr(u32, db, sqlite3_openFlags_off, v);
}
inline fn dbFlags(db: ?*anyopaque) u64 {
    return rd(u64, db, sqlite3_flags_off);
}
inline fn dbSetFlags(db: ?*anyopaque, v: u64) void {
    wr(u64, db, sqlite3_flags_off, v);
}
inline fn dbMDbFlags(db: ?*anyopaque) u32 {
    return rd(u32, db, sqlite3_mDbFlags_off);
}
inline fn dbSetMDbFlags(db: ?*anyopaque, v: u32) void {
    wr(u32, db, sqlite3_mDbFlags_off, v);
}
inline fn dbNChange(db: ?*anyopaque) i64 {
    return rd(i64, db, sqlite3_nChange_off);
}
inline fn dbSetNChange(db: ?*anyopaque, v: i64) void {
    wr(i64, db, sqlite3_nChange_off, v);
}
inline fn dbNTotalChange(db: ?*anyopaque) i64 {
    return rd(i64, db, sqlite3_nTotalChange_off);
}
inline fn dbSetNTotalChange(db: ?*anyopaque, v: i64) void {
    wr(i64, db, sqlite3_nTotalChange_off, v);
}
inline fn dbMTrace(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_mTrace_off];
}
inline fn dbSetMTrace(db: ?*anyopaque, v: u8) void {
    base(db)[sqlite3_mTrace_off] = v;
}
inline fn dbNextPagesize(db: ?*anyopaque) c_int {
    return rd(c_int, db, sqlite3_nextPagesize_off);
}
inline fn dbSetNextPagesize(db: ?*anyopaque, v: c_int) void {
    wr(c_int, db, sqlite3_nextPagesize_off, v);
}
inline fn dbNextAutovac(db: ?*anyopaque) i8 {
    return rd(i8, db, sqlite3_nextAutovac_off);
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rd(c_int, db, sqlite3_nDb_off);
}
inline fn dbSetInitIDb(db: ?*anyopaque, v: u8) void {
    base(db)[sqlite3_init_iDb_off] = v;
}

// aDb is a `Db*` field. Dereference, then index by sizeof(Db).
inline fn dbADb(db: ?*anyopaque) [*]u8 {
    return @ptrCast(rd(?*anyopaque, db, sqlite3_aDb_off).?);
}
inline fn dbAt(db: ?*anyopaque, i: c_int) [*]u8 {
    return dbADb(db) + (@as(usize, @intCast(i)) * sizeof_Db);
}
inline fn dbAtZName(db: ?*anyopaque, i: c_int) ?[*:0]const u8 {
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(dbAt(db, i) + Db_zDbSName_off);
    return q.*;
}
inline fn dbAtPBt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const q: *align(1) const ?*anyopaque = @ptrCast(dbAt(db, i) + Db_pBt_off);
    return q.*;
}
inline fn dbAtSetPBt(db: ?*anyopaque, i: c_int, v: ?*anyopaque) void {
    const q: *align(1) ?*anyopaque = @ptrCast(dbAt(db, i) + Db_pBt_off);
    q.* = v;
}
inline fn dbAtPSchema(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const q: *align(1) const ?*anyopaque = @ptrCast(dbAt(db, i) + Db_pSchema_off);
    return q.*;
}
inline fn dbAtSetPSchema(db: ?*anyopaque, i: c_int, v: ?*anyopaque) void {
    const q: *align(1) ?*anyopaque = @ptrCast(dbAt(db, i) + Db_pSchema_off);
    q.* = v;
}
inline fn dbAtSafetyLevel(db: ?*anyopaque, i: c_int) u8 {
    return (dbAt(db, i) + Db_safety_level_off)[0];
}

inline fn schemaCacheSize(p: ?*anyopaque) c_int {
    return rd(c_int, p, Schema_cache_size_off);
}

// Parse fields
inline fn pDb(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Parse_db_off);
}
inline fn pNErr(p: ?*anyopaque) c_int {
    return rd(c_int, p, Parse_nErr_off);
}
inline fn pNMem(p: ?*anyopaque) c_int {
    return rd(c_int, p, Parse_nMem_off);
}
inline fn pSetNMem(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Parse_nMem_off, v);
}

// sqlite3_file.pMethods
inline fn fileMethods(id: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, id, sqlite3_file_pMethods_off);
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ════════════════
const VaList = std.builtin.VaList;

// memory / strings (printf.zig / malloc.c / util.zig)
extern fn sqlite3VMPrintf(db: ?*anyopaque, zFormat: [*:0]const u8, ap: *VaList) callconv(.c) ?[*:0]u8;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SetString(pz: *align(1) ?*anyopaque, db: ?*anyopaque, z: ?[*:0]const u8) void;
extern fn sqlite3_snprintf(n: c_int, zBuf: [*]u8, zFormat: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3_randomness(N: c_int, P: ?*anyopaque) void;

// public C-API prepare/step (legacy.zig drives sqlite3_exec; here we use the
// prepared-statement API directly, as upstream execSql does).
extern fn sqlite3_prepare_v2(db: ?*anyopaque, zSql: ?[*:0]const u8, nByte: c_int, ppStmt: *?*anyopaque, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_column_text(pStmt: ?*anyopaque, N: c_int) ?[*:0]const u8;
extern fn sqlite3_finalize(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_errmsg(db: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;

extern fn sqlite3_value_type(pVal: ?*anyopaque) c_int;
extern fn sqlite3_value_text(pVal: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3_uri_int64(zFilename: ?[*:0]const u8, zParam: [*:0]const u8, bDflt: i64) i64;

// codegen helpers (build.c / expr.c / vdbeaux.c)
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*anyopaque;
extern fn sqlite3TwoPartName(pParse: ?*anyopaque, pName1: ?*anyopaque, pName2: ?*anyopaque, pUnqual: *?*anyopaque) c_int;
extern fn sqlite3ResolveSelfReference(pParse: ?*anyopaque, pTab: ?*anyopaque, typ: c_int, pExpr: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3ExprCode(pParse: ?*anyopaque, pExpr: ?*anyopaque, target: c_int) void;
extern fn sqlite3ExprDelete(db: ?*anyopaque, pExpr: ?*anyopaque) void;
extern fn sqlite3VdbeAddOp2(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeUsesBtree(p: ?*anyopaque, i: c_int) void;

// btree / pager (btree.c / pager.c — still C)
extern fn sqlite3BtreePager(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3PagerIsMemdb(p: ?*anyopaque) c_int;
extern fn sqlite3PagerFile(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3PagerGetJournalMode(p: ?*anyopaque) c_int;
extern fn sqlite3OsFileSize(id: ?*anyopaque, pSize: *i64) c_int;
extern fn sqlite3BtreeGetRequestedReserve(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeGetFilename(p: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3BtreeSetCacheSize(p: ?*anyopaque, mxPage: c_int) c_int;
extern fn sqlite3BtreeSetSpillSize(p: ?*anyopaque, mxPage: c_int) c_int;
extern fn sqlite3BtreeSetPagerFlags(p: ?*anyopaque, flags: c_uint) c_int;
extern fn sqlite3BtreeBeginTrans(p: ?*anyopaque, wrflag: c_int, pSchemaVersion: ?*c_int) c_int;
extern fn sqlite3BtreeSetPageSize(p: ?*anyopaque, nPagesize: c_int, nReserve: c_int, eFix: c_int) c_int;
extern fn sqlite3BtreeGetPageSize(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeSetAutoVacuum(p: ?*anyopaque, autoVacuum: c_int) c_int;
extern fn sqlite3BtreeGetAutoVacuum(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeGetMeta(p: ?*anyopaque, idx: c_int, pValue: *u32) void;
extern fn sqlite3BtreeUpdateMeta(p: ?*anyopaque, idx: c_int, value: u32) c_int;
extern fn sqlite3BtreeTxnState(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeCopyFile(pTo: ?*anyopaque, pFrom: ?*anyopaque) c_int;
extern fn sqlite3BtreeCommit(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeClose(p: ?*anyopaque) c_int;

// schema reset (build.c)
extern fn sqlite3ResetAllSchemasOfConnection(db: ?*anyopaque) void;

// ═══ execSql / execSqlF ══════════════════════════════════════════════════════
// Execute zSql on database db. If zSql returns rows, each row has exactly one
// column (only happens when zSql begins with "SELECT"). For each such row,
// recurse into execSql with that row's text — but only when it begins with
// "CRE" (CREATE TABLE/INDEX) or "INS" (INSERT), to harden against schema-row
// poisoning attacks.
fn execSql(db: ?*anyopaque, pzErrMsg: *align(1) ?*anyopaque, zSql: ?[*:0]const u8) c_int {
    var pStmt: ?*anyopaque = null;

    var rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, null);
    if (rc != SQLITE_OK) return rc;
    while (true) {
        rc = sqlite3_step(pStmt);
        if (rc != SQLITE_ROW) break;
        const zSubSql = sqlite3_column_text(pStmt, 0);
        // assert( sqlite3_strnicmp(zSql,"SELECT",6)==0 )
        if (zSubSql) |sub| {
            if (strncmp3(sub, "CRE") or strncmp3(sub, "INS")) {
                rc = execSql(db, pzErrMsg, sub);
                if (rc != SQLITE_OK) break;
            }
        }
    }
    // assert( rc!=SQLITE_ROW )
    if (rc == SQLITE_DONE) rc = SQLITE_OK;
    if (rc != 0) {
        sqlite3SetString(pzErrMsg, db, sqlite3_errmsg(db));
    }
    _ = sqlite3_finalize(pStmt);
    return rc;
}

// strncmp(z,"XXX",3)==0
inline fn strncmp3(z: [*:0]const u8, comptime lit: *const [3:0]u8) bool {
    return z[0] == lit[0] and z[1] == lit[1] and z[2] == lit[2];
}

// execSqlF: same as execSql but takes a printf-style format. Variadic origin:
// @cVaStart() / forward &ap to sqlite3VMPrintf (which takes *VaList).
fn execSqlF(db: ?*anyopaque, pzErrMsg: *align(1) ?*anyopaque, zSql: [*:0]const u8, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    const z = sqlite3VMPrintf(db, zSql, &ap);
    @cVaEnd(&ap);
    if (z == null) return SQLITE_NOMEM;
    const rc = execSql(db, pzErrMsg, z);
    sqlite3DbFree(db, @ptrCast(z));
    return rc;
}

// ═══ sqlite3Vacuum ═══════════════════════════════════════════════════════════
// Generate VDBE code to implement the VACUUM command (an OP_Vacuum op).
export fn sqlite3Vacuum(pParse: ?*anyopaque, pNm: ?*anyopaque, pInto: ?*anyopaque) callconv(.c) void {
    const v = sqlite3GetVdbe(pParse);
    var iDb: c_int = 0;
    const db = pDb(pParse);

    if (v == null) {
        sqlite3ExprDelete(db, pInto);
        return;
    }
    if (pNErr(pParse) != 0) {
        sqlite3ExprDelete(db, pInto);
        return;
    }
    if (pNm != null) {
        // Default behavior (SQLITE_BUG_COMPATIBLE_20160819 off): error on an
        // unrecognized argument.
        var pUnqual: ?*anyopaque = pNm;
        iDb = sqlite3TwoPartName(pParse, pNm, pNm, &pUnqual);
        if (iDb < 0) {
            sqlite3ExprDelete(db, pInto);
            return;
        }
    }
    if (iDb != 1) {
        var iIntoReg: c_int = 0;
        if (pInto != null and sqlite3ResolveSelfReference(pParse, null, 0, pInto, null) == 0) {
            pSetNMem(pParse, pNMem(pParse) + 1);
            iIntoReg = pNMem(pParse);
            sqlite3ExprCode(pParse, pInto, iIntoReg);
        }
        _ = sqlite3VdbeAddOp2(v, OP_Vacuum, iDb, iIntoReg);
        sqlite3VdbeUsesBtree(v, iDb);
    }
    sqlite3ExprDelete(db, pInto);
}

// ═══ sqlite3RunVacuum ════════════════════════════════════════════════════════
// Implements the OP_Vacuum opcode. pOut!=NULL ⇒ VACUUM INTO <file>.
//
// NOTE on @setRuntimeSafety: this routine drives the btree-copy and an explicit
// sequence of pragma/SQL writes against two transactions; it mirrors C exactly.
export fn sqlite3RunVacuum(
    pzErrMsg_in: ?*align(1) ?*anyopaque,
    db: ?*anyopaque,
    iDb: c_int,
    pOut: ?*anyopaque,
) callconv(.c) c_int {
    const pzErrMsg = pzErrMsg_in.?;
    var rc: c_int = SQLITE_OK;
    var pgflags: u32 = PAGER_SYNCHRONOUS_OFF;
    var pDbDetach: ?*anyopaque = null; // Db* to detach at end (as Db base pointer)
    var pDbIdx: c_int = undefined; // its index in aDb (== nDb after attach)
    var zDbVacuum: [42]u8 = undefined;

    if (dbAutoCommit(db) == 0) {
        sqlite3SetString(pzErrMsg, db, "cannot VACUUM from within a transaction");
        return SQLITE_ERROR;
    }
    if (dbNVdbeActive(db) > 1) {
        sqlite3SetString(pzErrMsg, db, "cannot VACUUM - SQL statements in progress");
        return SQLITE_ERROR;
    }
    const saved_openFlags = dbOpenFlags(db);
    var zOut: [*:0]const u8 = "";
    if (pOut) |po| {
        if (sqlite3_value_type(po) != SQLITE_TEXT) {
            sqlite3SetString(pzErrMsg, db, "non-text filename");
            return SQLITE_ERROR;
        }
        zOut = sqlite3_value_text(po) orelse "";
        var of = dbOpenFlags(db);
        of &= ~SQLITE_OPEN_READONLY;
        of |= SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE;
        dbSetOpenFlags(db, of);
    }

    // Save current flags, then set writable-schema and disable CHECK/FK.
    const saved_flags = dbFlags(db);
    const saved_mDbFlags = dbMDbFlags(db);
    const saved_nChange = dbNChange(db);
    const saved_nTotalChange = dbNTotalChange(db);
    const saved_mTrace = dbMTrace(db);
    dbSetFlags(db, dbFlags(db) | SQLITE_WriteSchema | SQLITE_IgnoreChecks | SQLITE_Comments | SQLITE_AttachCreate | SQLITE_AttachWrite);
    dbSetMDbFlags(db, dbMDbFlags(db) | DBFLAG_PreferBuiltin | DBFLAG_Vacuum);
    dbSetFlags(db, dbFlags(db) & ~(SQLITE_ForeignKeys | SQLITE_ReverseOrder | SQLITE_Defensive | SQLITE_CountRows));
    dbSetMTrace(db, 0);

    const zDbMain = dbAtZName(db, iDb);
    const pMain = dbAtPBt(db, iDb);
    const isMemDb = sqlite3PagerIsMemdb(sqlite3BtreePager(pMain)) != 0;

    // Attach a transient db as 'vacuum_XXXXXXXXXXXXXXXX'.
    var iRandom: u64 = undefined;
    sqlite3_randomness(@sizeOf(u64), &iRandom);
    _ = sqlite3_snprintf(@intCast(zDbVacuum.len), &zDbVacuum, "vacuum_%016llx", iRandom);
    const nDb = dbNDb(db);

    var pTemp: ?*anyopaque = null;
    var nRes: c_int = undefined;

    // ─── inline goto-emulation: everything up to end_of_vacuum returns via the
    // `vac:` block below. We use a labeled block + a small state machine so the
    // `goto end_of_vacuum` translations are linear.
    vac: {
        rc = execSqlF(db, pzErrMsg, "ATTACH %Q AS %s", zOut, @as([*:0]const u8, @ptrCast(&zDbVacuum)));
        dbSetOpenFlags(db, saved_openFlags);
        if (rc != SQLITE_OK) break :vac;
        // assert( (db->nDb-1)==nDb )
        pDbIdx = nDb;
        pDbDetach = dbAt(db, nDb);
        // assert( strcmp(pDb->zDbSName, zDbVacuum)==0 )
        pTemp = dbAtPBt(db, nDb);
        nRes = sqlite3BtreeGetRequestedReserve(pMain);

        if (pOut != null) {
            const id = sqlite3PagerFile(sqlite3BtreePager(pTemp));
            var sz: i64 = 0;
            if (fileMethods(id) != null and (sqlite3OsFileSize(id, &sz) != SQLITE_OK or sz > 0)) {
                rc = SQLITE_ERROR;
                sqlite3SetString(pzErrMsg, db, "output file already exists");
                break :vac;
            }
            dbSetMDbFlags(db, dbMDbFlags(db) | DBFLAG_VacuumInto);

            // For VACUUM INTO, pager-flags match the source db, plus CACHESPILL.
            pgflags = @as(u32, dbAtSafetyLevel(db, iDb)) |
                @as(u32, @truncate(dbFlags(db) & PAGER_FLAGS_MASK));

            // Honour a "reserve=N" URI parameter on the target, if present.
            const zFilename = sqlite3BtreeGetFilename(pTemp);
            // ALWAYS(zFilename)
            if (zFilename != null) {
                const nNew: c_int = @intCast(sqlite3_uri_int64(zFilename, "reserve", nRes));
                if (nNew >= 0 and nNew <= 255) nRes = nNew;
            }
        }

        _ = sqlite3BtreeSetCacheSize(pTemp, schemaCacheSize(dbAtPSchema(db, iDb)));
        _ = sqlite3BtreeSetSpillSize(pTemp, sqlite3BtreeSetSpillSize(pMain, 0));
        _ = sqlite3BtreeSetPagerFlags(pTemp, pgflags | PAGER_CACHESPILL);

        // Begin a transaction and take an exclusive lock on the main db file.
        rc = execSql(db, pzErrMsg, "BEGIN");
        if (rc != SQLITE_OK) break :vac;
        rc = sqlite3BtreeBeginTrans(pMain, if (pOut == null) @as(c_int, 2) else 0, null);
        if (rc != SQLITE_OK) break :vac;

        // Do not attempt to change the page size for a WAL database.
        if (sqlite3PagerGetJournalMode(sqlite3BtreePager(pMain)) == PAGER_JOURNALMODE_WAL and pOut == null) {
            dbSetNextPagesize(db, 0);
        }

        if (sqlite3BtreeSetPageSize(pTemp, sqlite3BtreeGetPageSize(pMain), nRes, 0) != 0 or
            (!isMemDb and sqlite3BtreeSetPageSize(pTemp, dbNextPagesize(db), nRes, 0) != 0) or
            dbMallocFailed(db) // NEVER(...)
        ) {
            rc = SQLITE_NOMEM; // SQLITE_NOMEM_BKPT
            break :vac;
        }

        // SQLITE_OMIT_AUTOVACUUM off:
        {
            const av: c_int = if (dbNextAutovac(db) >= 0) @intCast(dbNextAutovac(db)) else sqlite3BtreeGetAutoVacuum(pMain);
            _ = sqlite3BtreeSetAutoVacuum(pTemp, av);
        }

        // Query the schema of the main database, mirroring it into vacuum_db.
        dbSetInitIDb(db, @intCast(nDb)); // force new CREATE stmts into vacuum_db
        rc = execSqlF(db, pzErrMsg, "SELECT sql FROM \"%w\".sqlite_schema" ++
            " WHERE type='table'AND name<>'sqlite_sequence'" ++
            " AND coalesce(rootpage,1)>0", zDbMain);
        if (rc != SQLITE_OK) break :vac;
        rc = execSqlF(db, pzErrMsg, "SELECT sql FROM \"%w\".sqlite_schema" ++
            " WHERE type='index'", zDbMain);
        if (rc != SQLITE_OK) break :vac;
        dbSetInitIDb(db, 0);

        // INSERT INTO vacuum_db.xxx SELECT * FROM main.xxx; for each table.
        rc = execSqlF(db, pzErrMsg, "SELECT'INSERT INTO %s.'||quote(name)" ++
            "||' SELECT*FROM\"%w\".'||quote(name)" ++
            "FROM %s.sqlite_schema " ++
            "WHERE type='table'AND coalesce(rootpage,1)>0", @as([*:0]const u8, @ptrCast(&zDbVacuum)), zDbMain, @as([*:0]const u8, @ptrCast(&zDbVacuum)));
        // assert( (db->mDbFlags & DBFLAG_Vacuum)!=0 )
        dbSetMDbFlags(db, dbMDbFlags(db) & ~DBFLAG_Vacuum);
        if (rc != SQLITE_OK) break :vac;

        // Copy triggers, views, and virtual tables (no storage; just rows).
        rc = execSqlF(db, pzErrMsg, "INSERT INTO %s.sqlite_schema" ++
            " SELECT*FROM \"%w\".sqlite_schema" ++
            " WHERE type IN('view','trigger')" ++
            " OR(type='table'AND rootpage=0)", @as([*:0]const u8, @ptrCast(&zDbVacuum)), zDbMain);
        if (rc != 0) break :vac;

        // Both vacuum and main now have write transactions open. On success both
        // are closed by this block (main by CopyFile, temp by an explicit Commit).
        {
            // Even entries: meta value index. Odd entries: increment to apply.
            const aCopy = [_]u8{
                @intCast(BTREE_SCHEMA_VERSION),     1, // bump cookie so others reread
                @intCast(BTREE_DEFAULT_CACHE_SIZE), 0,
                @intCast(BTREE_TEXT_ENCODING),      0,
                @intCast(BTREE_USER_VERSION),       0,
                @intCast(BTREE_APPLICATION_ID),     0,
            };

            // assert( SQLITE_TXN_WRITE==sqlite3BtreeTxnState(pTemp) )
            std.debug.assert(SQLITE_TXN_WRITE == sqlite3BtreeTxnState(pTemp));
            // assert( pOut!=0 || SQLITE_TXN_WRITE==sqlite3BtreeTxnState(pMain) )
            std.debug.assert(pOut != null or SQLITE_TXN_WRITE == sqlite3BtreeTxnState(pMain));

            var i: usize = 0;
            while (i < aCopy.len) : (i += 2) {
                var meta: u32 = undefined;
                sqlite3BtreeGetMeta(pMain, aCopy[i], &meta);
                rc = sqlite3BtreeUpdateMeta(pTemp, aCopy[i], meta + aCopy[i + 1]);
                if (rc != SQLITE_OK) break :vac; // NEVER(rc!=SQLITE_OK)
            }

            if (pOut == null) {
                rc = sqlite3BtreeCopyFile(pMain, pTemp);
            }
            if (rc != SQLITE_OK) break :vac;
            rc = sqlite3BtreeCommit(pTemp);
            if (rc != SQLITE_OK) break :vac;
            // SQLITE_OMIT_AUTOVACUUM off:
            if (pOut == null) {
                _ = sqlite3BtreeSetAutoVacuum(pMain, sqlite3BtreeGetAutoVacuum(pTemp));
            }
        }

        // assert( rc==SQLITE_OK )
        if (pOut == null) {
            nRes = sqlite3BtreeGetRequestedReserve(pTemp);
            rc = sqlite3BtreeSetPageSize(pMain, sqlite3BtreeGetPageSize(pTemp), nRes, 1);
        }
    } // end_of_vacuum:

    // Restore the original value of db->flags and friends.
    dbSetInitIDb(db, 0);
    dbSetMDbFlags(db, saved_mDbFlags);
    dbSetFlags(db, saved_flags);
    dbSetNChange(db, saved_nChange);
    dbSetNTotalChange(db, saved_nTotalChange);
    dbSetMTrace(db, saved_mTrace);
    _ = sqlite3BtreeSetPageSize(pMain, -1, 0, 1);

    // End the SQL-level transaction on the vacuum db by forcing autoCommit and
    // detaching the vacuum db (its journal is deleted when the pager closes).
    dbSetAutoCommit(db, 1);

    if (pDbDetach != null) {
        _ = sqlite3BtreeClose(dbAtPBt(db, pDbIdx));
        dbAtSetPBt(db, pDbIdx, null);
        dbAtSetPSchema(db, pDbIdx, null);
    }

    // Clears schemas and shrinks db->aDb[].
    sqlite3ResetAllSchemasOfConnection(db);

    return rc;
}
