//! Zig port of SQLite's src/dbpage.c — the `sqlite_dbpage` eponymous virtual
//! table, which reads and writes whole raw pages of a database file through the
//! pager interface (so uncommitted/WAL changes are seen correctly).
//!
//!   SELECT data FROM sqlite_dbpage('aux1') WHERE pgno=123;
//!
//! Exported (C-ABI) symbol:
//!   - sqlite3DbpageRegister(db) -> int   (registers the eponymous module)
//!
//! All vtab methods (dbpageConnect/Disconnect/BestIndex/Open/Close/Filter/
//! Next/Eof/Column/Rowid/Update/Begin/Sync/RollbackTo) and the
//! dbpageBeginTrans helper are private Zig fns.
//!
//! Built because SQLITE_ENABLE_DBPAGE_VTAB is defined in build.zig sqlite_flags
//! (and in the --dev testfixture), and SQLITE_OMIT_VIRTUALTABLE is OFF in both,
//! so we port the full implementation (not the trivial `#elif` stub).
//!
//! ---------------------------------------------------------------------------
//! Structs we own vs structs we mirror
//! ---------------------------------------------------------------------------
//! DbpageTable / DbpageCursor are THIS module's own structs (C-style
//! subclassing: base class first), so we control their layout; mirrored as
//! `extern struct` so the sqlite3_malloc64() sizes match the C byte-for-byte.
//!
//! The public ABI structs (sqlite3_vtab, sqlite3_module, sqlite3_index_info,
//! ...) are mirrored exactly as in src/vdbevtab.zig.
//!
//! Reaches into core structs sqlite3 (aDb, nDb, flags) and Db (pBt, zDbSName).
//! Those offsets are routed through @import("c_layout.zig") with a probe-number
//! fallback (the vdbevtab.zig idiom). They are config-invariant: every field
//! touched sits before any SQLITE_DEBUG-only members.  Public domain (SQLite).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// --- Result codes / type codes (sqlite3.h) ---
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_NULL: c_int = 5;
const SQLITE_BLOB: c_int = 4;

// --- xBestIndex constraint op / scan flags (sqlite3.h) ---
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_INDEX_SCAN_UNIQUE: c_int = 1;

// --- sqlite3_vtab_config() verbs (sqlite3.h) ---
const SQLITE_VTAB_DIRECTONLY: c_int = 3;
const SQLITE_VTAB_USES_ALL_SCHEMAS: c_int = 4;

// --- db->flags bit (sqliteInt.h) ---
const SQLITE_Defensive: u64 = 0x10000000;

// --- Column indices ---
const DBPAGE_COLUMN_PGNO: c_int = 0;
const DBPAGE_COLUMN_DATA: c_int = 1;
const DBPAGE_COLUMN_SCHEMA: c_int = 2;

// --- Destructor sentinels (sqlite3.h) ---
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// --- Public ABI opaque handles ---
const sqlite3 = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;
const Pager = anyopaque;
const Btree = anyopaque;
const DbPage = anyopaque;

const Pgno = u32;

// ===========================================================================
// Public ABI structs (sqlite3.h) — mirrored exactly (cf. src/vdbevtab.zig).
// ===========================================================================

const sqlite3_vtab = extern struct {
    pModule: ?*const sqlite3_module,
    nRef: c_int,
    zErrMsg: ?[*:0]u8,
};

const sqlite3_vtab_cursor = extern struct {
    pVtab: ?*sqlite3_vtab,
};

const sqlite3_index_constraint = extern struct {
    iColumn: c_int,
    op: u8,
    usable: u8,
    iTermOffset: c_int,
};

const sqlite3_index_orderby = extern struct {
    iColumn: c_int,
    desc: u8,
};

const sqlite3_index_constraint_usage = extern struct {
    argvIndex: c_int,
    omit: u8,
};

const sqlite3_index_info = extern struct {
    // Inputs
    nConstraint: c_int,
    aConstraint: ?[*]sqlite3_index_constraint,
    nOrderBy: c_int,
    aOrderBy: ?[*]sqlite3_index_orderby,
    // Outputs
    aConstraintUsage: ?[*]sqlite3_index_constraint_usage,
    idxNum: c_int,
    idxStr: ?[*:0]u8,
    needToFreeIdxStr: c_int,
    orderByConsumed: c_int,
    estimatedCost: f64,
    estimatedRows: i64,
    idxFlags: c_int,
    colUsed: u64,
};

const sqlite3_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int,
    xConnect: ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int,
    xBestIndex: ?*const fn (*sqlite3_vtab, *sqlite3_index_info) callconv(.c) c_int,
    xDisconnect: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xDestroy: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xOpen: ?*const fn (*sqlite3_vtab, *?*sqlite3_vtab_cursor) callconv(.c) c_int,
    xClose: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xFilter: ?*const fn (*sqlite3_vtab_cursor, c_int, ?[*:0]const u8, c_int, ?[*]?*sqlite3_value) callconv(.c) c_int,
    xNext: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xEof: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xColumn: ?*const fn (*sqlite3_vtab_cursor, ?*sqlite3_context, c_int) callconv(.c) c_int,
    xRowid: ?*const fn (*sqlite3_vtab_cursor, *i64) callconv(.c) c_int,
    xUpdate: ?*const fn (*sqlite3_vtab, c_int, ?[*]?*sqlite3_value, *i64) callconv(.c) c_int,
    xBegin: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xSync: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xCommit: ?*const anyopaque,
    xRollback: ?*const anyopaque,
    xFindFunction: ?*const anyopaque,
    xRename: ?*const anyopaque,
    // version 2+
    xSavepoint: ?*const anyopaque,
    xRelease: ?*const anyopaque,
    xRollbackTo: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    // version 3+
    xShadowName: ?*const anyopaque,
    // version 4+
    xIntegrity: ?*const anyopaque,
};

// ===========================================================================
// Ground-truth offsets (config-INVARIANT; c_layout fallback idiom).
// ===========================================================================

// struct sqlite3: aDb(Db*)@32, nDb(int)@40, flags(u64)@48.
const sqlite3_aDb: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_nDb: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_flags: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;

// struct Db: zDbSName(char*)@0, pBt(Btree*)@8, sizeof==32.
const Db_zDbSName: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pBt: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

// ---- typed field readers over opaque pointers ----
inline fn fieldPtr(comptime T: type, b: ?*const anyopaque, offs: usize) *align(1) const T {
    const p: [*]const u8 = @ptrCast(b.?);
    return @ptrCast(p + offs);
}
inline fn rdInt(b: ?*const anyopaque, offs: usize) c_int {
    return fieldPtr(c_int, b, offs).*;
}
inline fn rdU64(b: ?*const anyopaque, offs: usize) u64 {
    return fieldPtr(u64, b, offs).*;
}
inline fn rdPtr(b: ?*const anyopaque, offs: usize) ?*anyopaque {
    return fieldPtr(?*anyopaque, b, offs).*;
}

/// db->aDb[i] — pointer to the i-th Db row.
inline fn dbAt(db: ?*sqlite3, i: c_int) ?*anyopaque {
    const aDb = rdPtr(db, sqlite3_aDb).?;
    const p: [*]u8 = @ptrCast(aDb);
    return @ptrCast(p + @as(usize, @intCast(i)) * sizeof_Db);
}
/// db->aDb[i].pBt
inline fn dbBtreeAt(db: ?*sqlite3, i: c_int) ?*Btree {
    return @ptrCast(rdPtr(dbAt(db, i), Db_pBt));
}

// ===========================================================================
// This module's own structs (we own their layout).
// ===========================================================================

const DbpageCursor = extern struct {
    base: sqlite3_vtab_cursor, // Base class.  Must be first
    pgno: Pgno, // Current page number
    mxPgno: Pgno, // Last page to visit on this scan
    pPager: ?*Pager, // Pager being read/written
    pPage1: ?*DbPage, // Page 1 of the database
    iDb: c_int, // Index of database to analyze
    szPage: c_int, // Size of each page in bytes
};

const DbpageTable = extern struct {
    base: sqlite3_vtab, // Base class.  Must be first
    db: ?*sqlite3, // The database
    iDbTrunc: c_int, // Database to truncate
    pgnoTrunc: Pgno, // Size to truncate to
};

// ===========================================================================
// External C symbols resolved at link time.
// ===========================================================================

// PENDING_BYTE (SQLITE_OMIT_WSD is OFF, so it's the global int variable).
extern var sqlite3PendingByte: c_int;

// Public API
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_create_module(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pClientData: ?*anyopaque) c_int;
extern fn sqlite3_vtab_config(db: ?*sqlite3, op: c_int, ...) c_int;
extern fn sqlite3_context_db_handle(ctx: ?*sqlite3_context) ?*sqlite3;

extern fn sqlite3_value_type(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_text(v: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_blob(v: ?*sqlite3_value) ?*const anyopaque;
extern fn sqlite3_value_bytes(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(v: ?*sqlite3_value) i64;

extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_result_blob(ctx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_zeroblob(ctx: ?*sqlite3_context, n: c_int) void;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;

// Internal helpers (sqliteInt.h / btree.h / pager.h)
extern fn sqlite3FindDbName(db: ?*sqlite3, zName: ?[*:0]const u8) c_int;
extern fn sqlite3BtreePager(p: ?*Btree) ?*Pager;
extern fn sqlite3BtreeGetPageSize(p: ?*Btree) c_int;
extern fn sqlite3BtreeLastPage(p: ?*Btree) Pgno;
extern fn sqlite3BtreeBeginTrans(p: ?*Btree, wrflag: c_int, pSchemaVersion: ?*c_int) c_int;
extern fn sqlite3BtreeEnter(p: ?*Btree) void;
extern fn sqlite3BtreeLeave(p: ?*Btree) void;
extern fn sqlite3PagerGet(pPager: ?*Pager, pgno: Pgno, ppPage: *?*DbPage, clrFlag: c_int) c_int;
extern fn sqlite3PagerUnref(pPage: ?*DbPage) void;
extern fn sqlite3PagerUnrefPageOne(pPage: ?*DbPage) void;
extern fn sqlite3PagerWrite(pPage: ?*DbPage) c_int;
extern fn sqlite3PagerGetData(pPage: ?*DbPage) ?*anyopaque;
extern fn sqlite3PagerTruncateImage(pPager: ?*Pager, nPage: Pgno) void;

// ===========================================================================
// vtab methods
// ===========================================================================

/// Connect to or create a dbpagevfs virtual table.
fn dbpageConnect(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    _ = pAux;
    _ = argc;
    _ = argv;
    _ = pzErr;

    _ = sqlite3_vtab_config(db, SQLITE_VTAB_DIRECTONLY);
    _ = sqlite3_vtab_config(db, SQLITE_VTAB_USES_ALL_SCHEMAS);
    var rc = sqlite3_declare_vtab(
        db,
        "CREATE TABLE x(pgno INTEGER PRIMARY KEY, data BLOB, schema HIDDEN)",
    );
    var pTab: ?*DbpageTable = null;
    if (rc == SQLITE_OK) {
        pTab = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(DbpageTable))));
        if (pTab == null) rc = SQLITE_NOMEM;
    }

    if (config.sqlite_debug) std.debug.assert(rc == SQLITE_OK or pTab == null);
    if (rc == SQLITE_OK) {
        pTab.?.* = std.mem.zeroes(DbpageTable);
        pTab.?.db = db;
    }

    ppVtab.* = @ptrCast(pTab);
    return rc;
}

/// Disconnect from or destroy a dbpagevfs virtual table.
fn dbpageDisconnect(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

/// idxNum:
///   0  schema=main, full table scan
///   1  schema=main, pgno=?1
///   2  schema=?1, full table scan
///   3  schema=?1, pgno=?2
fn dbpageBestIndex(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = tab;
    var iPlan: c_int = 0;
    const aCons = pIdxInfo.aConstraint.?;
    const aUse = pIdxInfo.aConstraintUsage.?;

    // If there is a schema= constraint, it must be honored.  Report a
    // ridiculously large estimated cost if the schema= constraint is
    // unavailable.
    var i: c_int = 0;
    while (i < pIdxInfo.nConstraint) : (i += 1) {
        const p = &aCons[@intCast(i)];
        if (p.iColumn != DBPAGE_COLUMN_SCHEMA) continue;
        if (p.op != SQLITE_INDEX_CONSTRAINT_EQ) continue;
        if (p.usable == 0) {
            // No solution.
            return SQLITE_CONSTRAINT;
        }
        iPlan = 2;
        aUse[@intCast(i)].argvIndex = 1;
        aUse[@intCast(i)].omit = 1;
        break;
    }

    // Either no schema= constraint (use "main") or it was accepted.  Lower the
    // estimated cost accordingly.
    pIdxInfo.estimatedCost = 1.0e6;

    // Check for constraints against pgno.
    i = 0;
    while (i < pIdxInfo.nConstraint) : (i += 1) {
        const p = &aCons[@intCast(i)];
        if (p.usable != 0 and p.iColumn <= 0 and p.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            pIdxInfo.estimatedRows = 1;
            pIdxInfo.idxFlags = SQLITE_INDEX_SCAN_UNIQUE;
            pIdxInfo.estimatedCost = 1.0;
            aUse[@intCast(i)].argvIndex = if (iPlan != 0) 2 else 1;
            aUse[@intCast(i)].omit = 1;
            iPlan |= 1;
            break;
        }
    }
    pIdxInfo.idxNum = iPlan;

    if (pIdxInfo.nOrderBy >= 1 and
        pIdxInfo.aOrderBy.?[0].iColumn <= 0 and
        pIdxInfo.aOrderBy.?[0].desc == 0)
    {
        pIdxInfo.orderByConsumed = 1;
    }
    return SQLITE_OK;
}

/// Open a new dbpagevfs cursor.
fn dbpageOpen(pVTab: *sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: ?*DbpageCursor = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(DbpageCursor))));
    if (pCsr == null) {
        return SQLITE_NOMEM;
    }
    pCsr.?.* = std.mem.zeroes(DbpageCursor);
    pCsr.?.base.pVtab = pVTab;
    pCsr.?.pgno = 0;

    ppCursor.* = &pCsr.?.base;
    return SQLITE_OK;
}

/// Close a dbpagevfs cursor.
fn dbpageClose(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *DbpageCursor = @ptrCast(@alignCast(pCursor));
    if (pCsr.pPage1 != null) sqlite3PagerUnrefPageOne(pCsr.pPage1);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

/// Move a dbpagevfs cursor to the next entry in the file.
fn dbpageNext(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *DbpageCursor = @ptrCast(@alignCast(pCursor));
    pCsr.pgno +%= 1;
    return SQLITE_OK;
}

fn dbpageEof(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *DbpageCursor = @ptrCast(@alignCast(pCursor));
    return @intFromBool(pCsr.pgno > pCsr.mxPgno);
}

/// idxNum (see dbpageBestIndex); idxStr is not used.
fn dbpageFilter(
    pCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = idxStr;
    _ = argc;
    const pCsr: *DbpageCursor = @ptrCast(@alignCast(pCursor));
    const pTab: *DbpageTable = @ptrCast(@alignCast(pCursor.pVtab.?));
    const db = pTab.db;

    // Default setting is no rows of result.
    pCsr.pgno = 1;
    pCsr.mxPgno = 0;

    if (idxNum & 2 != 0) {
        const zSchema = sqlite3_value_text(argv.?[0]);
        pCsr.iDb = sqlite3FindDbName(db, zSchema);
        if (pCsr.iDb < 0) return SQLITE_OK;
    } else {
        pCsr.iDb = 0;
    }
    const pBt = dbBtreeAt(db, pCsr.iDb);
    if (pBt == null) return SQLITE_OK; // NEVER()
    pCsr.pPager = sqlite3BtreePager(pBt);
    pCsr.szPage = sqlite3BtreeGetPageSize(pBt);
    pCsr.mxPgno = sqlite3BtreeLastPage(pBt);
    if (idxNum & 1 != 0) {
        const iPg = sqlite3_value_int64(argv.?[@intCast(idxNum >> 1)]);
        if (iPg < 1 or iPg > pCsr.mxPgno) {
            pCsr.pgno = 1;
            pCsr.mxPgno = 0;
        } else {
            pCsr.pgno = @intCast(iPg);
            pCsr.mxPgno = pCsr.pgno;
        }
    } else {
        if (config.sqlite_debug) std.debug.assert(pCsr.pgno == 1);
    }
    if (pCsr.pPage1 != null) sqlite3PagerUnrefPageOne(pCsr.pPage1);
    const rc = sqlite3PagerGet(pCsr.pPager, 1, &pCsr.pPage1, 0);
    return rc;
}

fn dbpageColumn(pCursor: *sqlite3_vtab_cursor, ctx: ?*sqlite3_context, i: c_int) callconv(.c) c_int {
    const pCsr: *DbpageCursor = @ptrCast(@alignCast(pCursor));
    var rc: c_int = SQLITE_OK;
    switch (i) {
        0 => { // pgno
            sqlite3_result_int64(ctx, @as(i64, pCsr.pgno));
        },
        1 => { // data
            var pDbPage: ?*DbPage = null;
            const pendingPage: Pgno = @intCast(@divTrunc(sqlite3PendingByte, pCsr.szPage) + 1);
            if (pCsr.pgno == pendingPage) {
                // The pending byte page. Assume it is zeroed out. Requesting
                // this page from the pager is an SQLITE_CORRUPT error.
                sqlite3_result_zeroblob(ctx, pCsr.szPage);
            } else {
                rc = sqlite3PagerGet(pCsr.pPager, pCsr.pgno, &pDbPage, 0);
                if (rc == SQLITE_OK) {
                    sqlite3_result_blob(ctx, sqlite3PagerGetData(pDbPage), pCsr.szPage, SQLITE_TRANSIENT);
                }
                sqlite3PagerUnref(pDbPage);
            }
        },
        else => { // schema
            const db = sqlite3_context_db_handle(ctx);
            const zDbSName: ?[*:0]const u8 = @ptrCast(rdPtr(dbAt(db, pCsr.iDb), Db_zDbSName));
            sqlite3_result_text(ctx, zDbSName, -1, SQLITE_STATIC);
        },
    }
    return rc;
}

fn dbpageRowid(pCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *DbpageCursor = @ptrCast(@alignCast(pCursor));
    pRowid.* = pCsr.pgno;
    return SQLITE_OK;
}

/// Open write transactions. Since we do not know in advance which database
/// files will be written, start a write transaction on them all.
fn dbpageBeginTrans(pTab: *DbpageTable) c_int {
    const db = pTab.db;
    var rc: c_int = SQLITE_OK;
    const nDb = rdInt(db, sqlite3_nDb);
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nDb) : (i += 1) {
        const pBt = dbBtreeAt(db, i);
        if (pBt != null) rc = sqlite3BtreeBeginTrans(pBt, 1, null);
    }
    return rc;
}

fn dbpageUpdate(
    pVtab: *sqlite3_vtab,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
    pRowid: *i64,
) callconv(.c) c_int {
    _ = pRowid;
    const pTab: *DbpageTable = @ptrCast(@alignCast(pVtab));
    const av = argv.?;
    var pgno: Pgno = undefined;
    var pgno64: i64 = undefined;
    var pDbPage: ?*DbPage = null;
    var rc: c_int = SQLITE_OK;
    var zErr: ?[*:0]const u8 = null;
    var iDb: c_int = undefined;
    var isInsert: bool = undefined;

    if ((rdU64(pTab.db, sqlite3_flags) & SQLITE_Defensive) != 0) {
        zErr = "read-only";
        return updateFail(pTab, pVtab, zErr);
    }
    if (argc == 1) {
        zErr = "cannot delete";
        return updateFail(pTab, pVtab, zErr);
    }
    if (sqlite3_value_type(av[0]) == SQLITE_NULL) {
        pgno64 = sqlite3_value_int64(av[2]);
        isInsert = true;
    } else {
        pgno64 = @as(i64, @as(Pgno, @truncate(@as(u64, @bitCast(sqlite3_value_int64(av[0]))))));
        if (sqlite3_value_int64(av[1]) != pgno64) {
            zErr = "cannot insert";
            return updateFail(pTab, pVtab, zErr);
        }
        isInsert = false;
    }
    if (sqlite3_value_type(av[4]) == SQLITE_NULL) {
        iDb = 0;
    } else {
        const zSchema = sqlite3_value_text(av[4]);
        iDb = sqlite3FindDbName(pTab.db, zSchema);
        if (iDb < 0) {
            zErr = "no such schema";
            return updateFail(pTab, pVtab, zErr);
        }
    }
    const pBt = dbBtreeAt(pTab.db, iDb);
    if (pgno64 < 1 or pgno64 > 4294967294 or pBt == null) { // pBt==0 is NEVER()
        zErr = "bad page number";
        return updateFail(pTab, pVtab, zErr);
    }
    pgno = @intCast(pgno64);
    const szPage = sqlite3BtreeGetPageSize(pBt);
    if (sqlite3_value_type(av[3]) != SQLITE_BLOB or
        sqlite3_value_bytes(av[3]) != szPage)
    {
        if (sqlite3_value_type(av[3]) == SQLITE_NULL and isInsert and pgno > 1) {
            // "INSERT INTO dbpage($PGNO,NULL)" causes page number $PGNO and all
            // subsequent pages to be deleted.
            pTab.iDbTrunc = iDb;
            pTab.pgnoTrunc = pgno - 1;
            pgno = 1;
        } else {
            zErr = "bad page value";
            return updateFail(pTab, pVtab, zErr);
        }
    }

    if (dbpageBeginTrans(pTab) != SQLITE_OK) {
        zErr = "failed to open transaction";
        return updateFail(pTab, pVtab, zErr);
    }

    const pPager = sqlite3BtreePager(pBt);
    rc = sqlite3PagerGet(pPager, pgno, &pDbPage, 0);
    if (rc == SQLITE_OK) {
        const pData = sqlite3_value_blob(av[3]);
        rc = sqlite3PagerWrite(pDbPage);
        if (rc == SQLITE_OK and pData != null) {
            const aPage: [*]u8 = @ptrCast(sqlite3PagerGetData(pDbPage).?);
            const src: [*]const u8 = @ptrCast(pData.?);
            @memcpy(aPage[0..@intCast(szPage)], src[0..@intCast(szPage)]);
            pTab.pgnoTrunc = 0;
        }
    }
    if (rc != SQLITE_OK) {
        pTab.pgnoTrunc = 0;
    }
    sqlite3PagerUnref(pDbPage);
    return rc;
}

/// The `update_fail:` label in C.
fn updateFail(pTab: *DbpageTable, pVtab: *sqlite3_vtab, zErr: ?[*:0]const u8) c_int {
    pTab.pgnoTrunc = 0;
    const pv: *sqlite3_vtab = pVtab;
    sqlite3_free(pv.zErrMsg);
    pv.zErrMsg = sqlite3_mprintf("%s", zErr);
    return SQLITE_ERROR;
}

fn dbpageBegin(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pTab: *DbpageTable = @ptrCast(@alignCast(pVtab));
    pTab.pgnoTrunc = 0;
    return SQLITE_OK;
}

/// Invoke sqlite3PagerTruncateImage() as necessary, just prior to COMMIT.
fn dbpageSync(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pTab: *DbpageTable = @ptrCast(@alignCast(pVtab));
    if (pTab.pgnoTrunc > 0) {
        const pBt = dbBtreeAt(pTab.db, pTab.iDbTrunc);
        const pPager = sqlite3BtreePager(pBt);
        sqlite3BtreeEnter(pBt);
        if (pTab.pgnoTrunc < sqlite3BtreeLastPage(pBt)) {
            sqlite3PagerTruncateImage(pPager, pTab.pgnoTrunc);
        }
        sqlite3BtreeLeave(pBt);
    }
    pTab.pgnoTrunc = 0;
    return SQLITE_OK;
}

/// Cancel any pending truncate.
fn dbpageRollbackTo(pVtab: *sqlite3_vtab, notUsed1: c_int) callconv(.c) c_int {
    _ = notUsed1;
    const pTab: *DbpageTable = @ptrCast(@alignCast(pVtab));
    pTab.pgnoTrunc = 0;
    return SQLITE_OK;
}

/// The virtual-table method table. Mirrors the C `dbpage_module`.
const dbpage_module: sqlite3_module = .{
    .iVersion = 2,
    .xCreate = &dbpageConnect,
    .xConnect = &dbpageConnect,
    .xBestIndex = &dbpageBestIndex,
    .xDisconnect = &dbpageDisconnect,
    .xDestroy = &dbpageDisconnect,
    .xOpen = &dbpageOpen,
    .xClose = &dbpageClose,
    .xFilter = &dbpageFilter,
    .xNext = &dbpageNext,
    .xEof = &dbpageEof,
    .xColumn = &dbpageColumn,
    .xRowid = &dbpageRowid,
    .xUpdate = &dbpageUpdate,
    .xBegin = &dbpageBegin,
    .xSync = &dbpageSync,
    .xCommit = null,
    .xRollback = null,
    .xFindFunction = null,
    .xRename = null,
    .xSavepoint = null,
    .xRelease = null,
    .xRollbackTo = &dbpageRollbackTo,
    .xShadowName = null,
    .xIntegrity = null,
};

/// Invoke this routine to register the "dbpage" virtual table module.
export fn sqlite3DbpageRegister(db: ?*sqlite3) callconv(.c) c_int {
    return sqlite3_create_module(db, "sqlite_dbpage", &dbpage_module, null);
}
