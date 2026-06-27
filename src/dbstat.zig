//! Zig port of SQLite's src/dbstat.c — the `dbstat` virtual table, which
//! extracts low-level per-page btree storage statistics from a database (the
//! engine behind sqlite3_analyzer / spaceanal.tcl).
//!
//!   SELECT * FROM dbstat WHERE schema='main';
//!
//! Exported (C-ABI) symbol:
//!   - sqlite3DbstatRegister(db) -> int   (registers the "dbstat" module)
//!
//! Built because SQLITE_ENABLE_DBSTAT_VTAB is defined in build.zig sqlite_flags
//! and SQLITE_OMIT_VIRTUALTABLE is OFF, so we port the full implementation
//! (not the trivial `#elif` stub).
//!
//! ---------------------------------------------------------------------------
//! Structs we own vs structs we mirror
//! ---------------------------------------------------------------------------
//! StatTable / StatCursor / StatPage / StatCell are THIS module's own structs
//! (C-style subclassing: base class first), so we control their layout;
//! mirrored as `extern struct` so sqlite3_malloc64() sizes match the C
//! byte-for-byte.
//!
//! The public ABI structs (sqlite3_vtab, sqlite3_module, sqlite3_index_info,
//! ...) are mirrored exactly as in src/dbpage.zig / src/vdbevtab.zig.
//!
//! Reaches into core structs sqlite3 (aDb) and Db (pBt, zDbSName); those
//! offsets are routed through @import("c_layout.zig") with a probe-number
//! fallback (the dbpage.zig idiom).  Public domain (SQLite).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// --- Result codes (sqlite3.h) ---
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;

// --- xBestIndex constraint op / scan flags (sqlite3.h) ---
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_INDEX_SCAN_HEX: c_int = 0x00000002;

// --- sqlite3_vtab_config() verbs (sqlite3.h) ---
const SQLITE_VTAB_DIRECTONLY: c_int = 3;

// --- Padding (see C comment) ---
const DBSTAT_PAGE_PADDING_BYTES: usize = 256;
const ARRAY_SIZE_APAGE: usize = 32;

// --- Destructor sentinels (sqlite3.h) ---
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// --- Public ABI opaque handles ---
const sqlite3 = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_str = anyopaque;
const sqlite3_file = anyopaque;
const Pager = anyopaque;
const Btree = anyopaque;
const DbPage = anyopaque;

const Pgno = u32;

// ===========================================================================
// Public ABI structs (sqlite3.h) — mirrored exactly (cf. src/dbpage.zig).
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
    xUpdate: ?*const anyopaque,
    xBegin: ?*const anyopaque,
    xSync: ?*const anyopaque,
    xCommit: ?*const anyopaque,
    xRollback: ?*const anyopaque,
    xFindFunction: ?*const anyopaque,
    xRename: ?*const anyopaque,
    // version 2+
    xSavepoint: ?*const anyopaque,
    xRelease: ?*const anyopaque,
    xRollbackTo: ?*const anyopaque,
    // version 3+
    xShadowName: ?*const anyopaque,
    // version 4+
    xIntegrity: ?*const anyopaque,
};

// ===========================================================================
// Ground-truth offsets (config-INVARIANT; c_layout fallback idiom).
// ===========================================================================

// struct sqlite3: aDb(Db*)@32.
const sqlite3_aDb: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
// struct Db: zDbSName(char*)@0, pBt(Btree*)@8, sizeof==32.
const Db_zDbSName: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pBt: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

// ---- typed field readers over opaque pointers ----
inline fn fieldPtr(comptime T: type, b: ?*const anyopaque, offs: usize) *align(1) const T {
    const p: [*]const u8 = @ptrCast(b.?);
    return @ptrCast(p + offs);
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
/// db->aDb[i].zDbSName
inline fn dbNameAt(db: ?*sqlite3, i: c_int) ?[*:0]const u8 {
    return @ptrCast(rdPtr(dbAt(db, i), Db_zDbSName));
}

// ===========================================================================
// Big-endian page-byte parsing helpers (get2byte / get4byte macros).
// ===========================================================================

inline fn get2byte(a: [*]const u8) c_int {
    return (@as(c_int, a[0]) << 8) | @as(c_int, a[1]);
}

// ===========================================================================
// This module's own structs (we own their layout).
// ===========================================================================

/// Size information for a single cell within a btree page.
const StatCell = extern struct {
    nLocal: c_int, // Bytes of local payload
    iChildPg: u32, // Child node (or 0 if this is a leaf)
    nOvfl: c_int, // Entries in aOvfl[]
    aOvfl: ?[*]u32, // Array of overflow page numbers
    nLastOvfl: c_int, // Bytes of payload on final overflow page
    iOvfl: c_int, // Iterates through aOvfl[]
};

/// Size information for a single btree page.
const StatPage = extern struct {
    iPgno: u32, // Page number
    aPg: ?[*]u8, // Page buffer from sqlite3_malloc()
    iCell: c_int, // Current cell
    zPath: ?[*:0]u8, // Path to this page

    // Variables populated by statDecodePage():
    flags: u8, // Copy of flags byte
    nCell: c_int, // Number of cells on page
    nUnused: c_int, // Number of unused bytes on page
    aCell: ?[*]StatCell, // Array of parsed cells
    iRightChildPg: u32, // Right-child page number (or 0)
    nMxPayload: c_int, // Largest payload of any cell on the page
};

/// The cursor for scanning the dbstat virtual table.
const StatCursor = extern struct {
    base: sqlite3_vtab_cursor, // base class.  MUST BE FIRST!
    pStmt: ?*sqlite3_stmt, // Iterates through set of root pages
    isEof: u8, // After pStmt has returned SQLITE_DONE
    isAgg: u8, // Aggregate results for each table
    iDb: c_int, // Schema used for this query

    aPage: [ARRAY_SIZE_APAGE]StatPage, // Pages in path to current page
    iPage: c_int, // Current entry in aPage[]

    // Values to return.
    iPageno: u32, // Value of 'pageno' column
    zName: ?[*:0]const u8, // Value of 'name' column
    zPath: ?[*:0]u8, // Value of 'path' column
    zPagetype: ?[*:0]const u8, // Value of 'pagetype' column
    nPage: c_int, // Number of pages in current btree
    nCell: c_int, // Value of 'ncell' column
    nMxPayload: c_int, // Value of 'mx_payload' column
    nUnused: i64, // Value of 'unused' column
    nPayload: i64, // Value of 'payload' column
    iOffset: i64, // Value of 'pgOffset' column
    szPage: i64, // Value of 'pgSize' column
};

/// An instance of the DBSTAT virtual table.
const StatTable = extern struct {
    base: sqlite3_vtab, // base class.  MUST BE FIRST!
    db: ?*sqlite3, // Database connection that owns this vtab
    iDb: c_int, // Index of database to analyze
};

/// Token (sqliteInt.h) — only used transiently inside statConnect.
const Token = extern struct {
    z: ?[*]const u8,
    n: c_uint,
};

// ===========================================================================
// External C symbols resolved at link time.
// ===========================================================================

// Public API
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_create_module(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pClientData: ?*anyopaque) c_int;
extern fn sqlite3_vtab_config(db: ?*sqlite3, op: c_int, ...) c_int;
extern fn sqlite3_context_db_handle(ctx: ?*sqlite3_context) ?*sqlite3;

extern fn sqlite3_value_text(v: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_double(v: ?*sqlite3_value) f64;

extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;

extern fn sqlite3_prepare_v2(db: ?*sqlite3, zSql: [*:0]const u8, nByte: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, iCol: c_int) i64;
extern fn sqlite3_column_text(pStmt: ?*sqlite3_stmt, iCol: c_int) ?[*:0]const u8;

extern fn sqlite3_str_new(db: ?*sqlite3) ?*sqlite3_str;
extern fn sqlite3_str_appendf(p: ?*sqlite3_str, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_str_finish(p: ?*sqlite3_str) ?[*:0]u8;

// Internal helpers (sqliteInt.h / btree.h / pager.h)
extern fn sqlite3FindDb(db: ?*sqlite3, pName: *Token) c_int;
extern fn sqlite3FindDbName(db: ?*sqlite3, zName: ?[*:0]const u8) c_int;
extern fn sqlite3TokenInit(p: *Token, z: ?[*]u8) void;
extern fn sqlite3BtreePager(p: ?*Btree) ?*Pager;
extern fn sqlite3BtreeGetPageSize(p: ?*Btree) c_int;
extern fn sqlite3BtreeGetReserveNoMutex(p: ?*Btree) c_int;
extern fn sqlite3BtreeEnter(p: ?*Btree) void;
extern fn sqlite3BtreeLeave(p: ?*Btree) void;
extern fn sqlite3PagerGet(pPager: ?*Pager, pgno: Pgno, ppPage: *?*DbPage, clrFlag: c_int) c_int;
extern fn sqlite3PagerUnref(pPage: ?*DbPage) void;
extern fn sqlite3PagerGetData(pPage: ?*DbPage) ?*anyopaque;
extern fn sqlite3PagerFile(pPager: ?*Pager) ?*sqlite3_file;
extern fn sqlite3PagerPagecount(pPager: ?*Pager, pnPage: *c_int) void;
extern fn sqlite3OsFileControl(fd: ?*sqlite3_file, op: c_int, pArg: ?*anyopaque) c_int;
extern fn sqlite3Get4byte(p: [*]const u8) u32;
extern fn sqlite3GetVarint(p: [*]const u8, v: *u64) u8;
extern fn sqlite3GetVarint32(p: [*]const u8, v: *u32) u8;

// getVarint32 macro: single-byte fast path inline, else call sqlite3GetVarint32.
inline fn getVarint32(a: [*]const u8, b: *u32) c_int {
    if (a[0] < 0x80) {
        b.* = a[0];
        return 1;
    }
    return sqlite3GetVarint32(a, b);
}

// ===========================================================================
// vtab methods
// ===========================================================================

/// Connect to or create a new DBSTAT virtual table.
fn statConnect(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    _ = pAux;
    var pTab: ?*StatTable = null;
    var rc: c_int = SQLITE_OK;
    var iDb: c_int = undefined;

    if (argc >= 4) {
        var nm: Token = undefined;
        // (char*)argv[3]
        sqlite3TokenInit(&nm, @constCast(@ptrCast(argv.?[3])));
        iDb = sqlite3FindDb(db, &nm);
        if (iDb < 0) {
            pzErr.* = sqlite3_mprintf("no such database: %s", argv.?[3]);
            return SQLITE_ERROR;
        }
    } else {
        iDb = 0;
    }
    _ = sqlite3_vtab_config(db, SQLITE_VTAB_DIRECTONLY);
    rc = sqlite3_declare_vtab(db, zDbstatSchema);
    if (rc == SQLITE_OK) {
        pTab = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(StatTable))));
        if (pTab == null) rc = SQLITE_NOMEM;
    }

    if (config.sqlite_debug) std.debug.assert(rc == SQLITE_OK or pTab == null);
    if (rc == SQLITE_OK) {
        pTab.?.* = std.mem.zeroes(StatTable);
        pTab.?.db = db;
        pTab.?.iDb = iDb;
    }

    ppVtab.* = @ptrCast(pTab);
    return rc;
}

/// Disconnect from or destroy the DBSTAT virtual table.
fn statDisconnect(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

/// Compute the best query strategy and return the result in idxNum.
fn statBestIndex(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = tab;
    var iSchema: c_int = -1;
    var iName: c_int = -1;
    var iAgg: c_int = -1;
    const aCons = pIdxInfo.aConstraint.?;
    const aUse = pIdxInfo.aConstraintUsage.?;

    var i: c_int = 0;
    while (i < pIdxInfo.nConstraint) : (i += 1) {
        const p = &aCons[@intCast(i)];
        if (p.op != SQLITE_INDEX_CONSTRAINT_EQ) continue;
        if (p.usable == 0) {
            // Force DBSTAT table to always be the right-most table in a join.
            return SQLITE_CONSTRAINT;
        }
        switch (p.iColumn) {
            0 => iName = i, // name
            10 => iSchema = i, // schema
            11 => iAgg = i, // aggregate
            else => {},
        }
    }
    i = 0;
    if (iSchema >= 0) {
        i += 1;
        aUse[@intCast(iSchema)].argvIndex = i;
        aUse[@intCast(iSchema)].omit = 1;
        pIdxInfo.idxNum |= 0x01;
    }
    if (iName >= 0) {
        i += 1;
        aUse[@intCast(iName)].argvIndex = i;
        pIdxInfo.idxNum |= 0x02;
    }
    if (iAgg >= 0) {
        i += 1;
        aUse[@intCast(iAgg)].argvIndex = i;
        pIdxInfo.idxNum |= 0x04;
    }
    pIdxInfo.estimatedCost = 1.0;

    // Records are always returned in ascending order of (name, path).
    if ((pIdxInfo.nOrderBy == 1 and
        pIdxInfo.aOrderBy.?[0].iColumn == 0 and
        pIdxInfo.aOrderBy.?[0].desc == 0) or
        (pIdxInfo.nOrderBy == 2 and
            pIdxInfo.aOrderBy.?[0].iColumn == 0 and
            pIdxInfo.aOrderBy.?[0].desc == 0 and
            pIdxInfo.aOrderBy.?[1].iColumn == 1 and
            pIdxInfo.aOrderBy.?[1].desc == 0))
    {
        pIdxInfo.orderByConsumed = 1;
        pIdxInfo.idxNum |= 0x08;
    }
    pIdxInfo.idxFlags |= SQLITE_INDEX_SCAN_HEX;

    return SQLITE_OK;
}

/// Open a new DBSTAT cursor.
fn statOpen(pVTab: *sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pTab: *StatTable = @ptrCast(@alignCast(pVTab));
    const pCsr: ?*StatCursor = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(StatCursor))));
    if (pCsr == null) {
        return SQLITE_NOMEM;
    }
    pCsr.?.* = std.mem.zeroes(StatCursor);
    pCsr.?.base.pVtab = pVTab;
    pCsr.?.iDb = pTab.iDb;

    ppCursor.* = &pCsr.?.base;
    return SQLITE_OK;
}

fn statClearCells(p: *StatPage) void {
    if (p.aCell) |aCell| {
        var i: c_int = 0;
        while (i < p.nCell) : (i += 1) {
            sqlite3_free(aCell[@intCast(i)].aOvfl);
        }
        sqlite3_free(aCell);
    }
    p.nCell = 0;
    p.aCell = null;
}

fn statClearPage(p: *StatPage) void {
    const aPg = p.aPg;
    statClearCells(p);
    sqlite3_free(p.zPath);
    p.* = std.mem.zeroes(StatPage);
    p.aPg = aPg;
}

fn statResetCsr(pCsr: *StatCursor) void {
    // statClearPage() must run before sqlite3_reset(), which can reset the
    // pager on OOM (dbsqlfuzz 9ed3e4e3816219d3509d711636c38542bf3f40b1).
    var i: usize = 0;
    while (i < ARRAY_SIZE_APAGE) : (i += 1) {
        statClearPage(&pCsr.aPage[i]);
        sqlite3_free(pCsr.aPage[i].aPg);
        pCsr.aPage[i].aPg = null;
    }
    _ = sqlite3_reset(pCsr.pStmt);
    pCsr.iPage = 0;
    sqlite3_free(pCsr.zPath);
    pCsr.zPath = null;
    pCsr.isEof = 0;
}

/// Reset the space-used counters inside of the cursor.
fn statResetCounts(pCsr: *StatCursor) void {
    pCsr.nCell = 0;
    pCsr.nMxPayload = 0;
    pCsr.nUnused = 0;
    pCsr.nPayload = 0;
    pCsr.szPage = 0;
    pCsr.nPage = 0;
}

/// Close a DBSTAT cursor.
fn statClose(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *StatCursor = @ptrCast(@alignCast(pCursor));
    statResetCsr(pCsr);
    _ = sqlite3_finalize(pCsr.pStmt);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

/// For a single cell on a btree page, compute the number of bytes of content
/// (payload) stored on that page (not on overflow pages).
fn getLocalPayload(
    nUsable: c_int, // Usable bytes per page
    flags: u8, // Page flags
    nTotal: c_int, // Total record (payload) size
) c_int {
    var nMinLocal: c_int = undefined;
    var nMaxLocal: c_int = undefined;

    if (flags == 0x0D) { // Table leaf node
        nMinLocal = @divTrunc((nUsable - 12) * 32, 255) - 23;
        nMaxLocal = nUsable - 35;
    } else { // Index interior and leaf nodes
        nMinLocal = @divTrunc((nUsable - 12) * 32, 255) - 23;
        nMaxLocal = @divTrunc((nUsable - 12) * 64, 255) - 23;
    }

    var nLocal = nMinLocal + @rem(nTotal - nMinLocal, nUsable - 4);
    if (nLocal > nMaxLocal) nLocal = nMinLocal;
    return nLocal;
}

/// Populate the StatPage object with information about all cells found on the
/// page currently under analysis.
fn statDecodePage(pBt: ?*Btree, p: *StatPage) c_int {
    var nUnused: c_int = undefined;
    var iOff: c_int = undefined;
    var nHdr: c_int = undefined;
    var isLeaf: c_int = undefined;
    var szPage: c_int = undefined;

    const aData: [*]u8 = p.aPg.?;
    const aHdr: [*]u8 = aData + @as(usize, if (p.iPgno == 1) 100 else 0);

    p.flags = aHdr[0];
    if (p.flags == 0x0A or p.flags == 0x0D) {
        isLeaf = 1;
        nHdr = 8;
    } else if (p.flags == 0x05 or p.flags == 0x02) {
        isLeaf = 0;
        nHdr = 12;
    } else {
        return statPageIsCorrupt(p);
    }
    if (p.iPgno == 1) nHdr += 100;
    p.nCell = get2byte(aHdr + 3);
    p.nMxPayload = 0;
    szPage = sqlite3BtreeGetPageSize(pBt);

    nUnused = get2byte(aHdr + 5) - nHdr - 2 * p.nCell;
    nUnused += @as(c_int, aHdr[7]);
    iOff = get2byte(aHdr + 1);
    while (iOff != 0) {
        if (iOff >= szPage) return statPageIsCorrupt(p);
        nUnused += get2byte(aData + @as(usize, @intCast(iOff)) + 2);
        const iNext = get2byte(aData + @as(usize, @intCast(iOff)));
        if (iNext < iOff + 4 and iNext > 0) return statPageIsCorrupt(p);
        iOff = iNext;
    }
    p.nUnused = nUnused;
    p.iRightChildPg = if (isLeaf != 0) 0 else sqlite3Get4byte(aHdr + 8);

    if (p.nCell != 0) {
        sqlite3BtreeEnter(pBt);
        const nUsable: c_int = szPage - sqlite3BtreeGetReserveNoMutex(pBt);
        sqlite3BtreeLeave(pBt);
        const nCells: usize = @intCast(p.nCell + 1);
        p.aCell = @ptrCast(@alignCast(sqlite3_malloc64(nCells * @sizeOf(StatCell))));
        if (p.aCell == null) return SQLITE_NOMEM;
        @memset(p.aCell.?[0..nCells], std.mem.zeroes(StatCell));

        var i: c_int = 0;
        while (i < p.nCell) : (i += 1) {
            const pCell = &p.aCell.?[@intCast(i)];

            iOff = get2byte(aData + @as(usize, @intCast(nHdr + i * 2)));
            if (iOff < nHdr or iOff >= szPage) return statPageIsCorrupt(p);
            if (isLeaf == 0) {
                pCell.iChildPg = sqlite3Get4byte(aData + @as(usize, @intCast(iOff)));
                iOff += 4;
            }
            if (p.flags == 0x05) {
                // A table interior node. nPayload==0.
            } else {
                var nPayload: u32 = undefined; // Bytes of payload total
                iOff += getVarint32(aData + @as(usize, @intCast(iOff)), &nPayload);
                if (p.flags == 0x0D) {
                    var dummy: u64 = undefined;
                    iOff += @as(c_int, sqlite3GetVarint(aData + @as(usize, @intCast(iOff)), &dummy));
                }
                if (nPayload > @as(u32, @bitCast(p.nMxPayload))) p.nMxPayload = @bitCast(nPayload);
                const nLocal = getLocalPayload(nUsable, p.flags, @bitCast(nPayload));
                if (nLocal < 0) return statPageIsCorrupt(p);
                pCell.nLocal = nLocal;
                if (config.sqlite_debug) {
                    std.debug.assert(nPayload >= @as(u32, @bitCast(nLocal)));
                    std.debug.assert(nLocal <= (nUsable - 35));
                }
                if (nPayload > @as(u32, @bitCast(nLocal))) {
                    const nOvfl = @divTrunc((@as(c_int, @bitCast(nPayload)) - nLocal) + nUsable - 4 - 1, nUsable - 4);
                    if (iOff + nLocal + 4 > nUsable or nPayload > 0x7fffffff) {
                        return statPageIsCorrupt(p);
                    }
                    pCell.nLastOvfl = (@as(c_int, @bitCast(nPayload)) - nLocal) - (nOvfl - 1) * (nUsable - 4);
                    pCell.nOvfl = nOvfl;
                    pCell.aOvfl = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(u32) * @as(u64, @intCast(nOvfl)))));
                    if (pCell.aOvfl == null) return SQLITE_NOMEM;
                    pCell.aOvfl.?[0] = sqlite3Get4byte(aData + @as(usize, @intCast(iOff + nLocal)));
                    var j: c_int = 1;
                    while (j < nOvfl) : (j += 1) {
                        const iPrev = pCell.aOvfl.?[@intCast(j - 1)];
                        var pPg: ?*DbPage = null;
                        const rc = sqlite3PagerGet(sqlite3BtreePager(pBt), iPrev, &pPg, 0);
                        if (rc != SQLITE_OK) {
                            if (config.sqlite_debug) std.debug.assert(pPg == null);
                            return rc;
                        }
                        pCell.aOvfl.?[@intCast(j)] = sqlite3Get4byte(@ptrCast(sqlite3PagerGetData(pPg).?));
                        sqlite3PagerUnref(pPg);
                    }
                }
            }
        }
    }

    return SQLITE_OK;
}

/// The `statPageIsCorrupt:` label in C.
fn statPageIsCorrupt(p: *StatPage) c_int {
    p.flags = 0;
    statClearCells(p);
    return SQLITE_OK;
}

/// Populate pCsr->iOffset and pCsr->szPage based on pCsr->iPageno.
fn statSizeAndOffset(pCsr: *StatCursor) void {
    const pTab: *StatTable = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    const pBt = dbBtreeAt(pTab.db, pTab.iDb);
    const pPager = sqlite3BtreePager(pBt);

    // If connected to a ZIPVFS backend, find the page size and offset from it.
    const fd = sqlite3PagerFile(pPager);
    var x: [2]i64 = undefined;
    x[0] = pCsr.iPageno;
    if (sqlite3OsFileControl(fd, 230440, @ptrCast(&x)) == SQLITE_OK) {
        pCsr.iOffset = x[0];
        pCsr.szPage += x[1];
    } else {
        // Not ZIPVFS: the default page size and offset.
        pCsr.szPage += @as(i64, sqlite3BtreeGetPageSize(pBt));
        pCsr.iOffset = pCsr.szPage * (@as(i64, pCsr.iPageno) - 1);
    }
}

/// Load a copy of the page data for page iPg into pPg's buffer.
fn statGetPage(pBt: ?*Btree, iPg: u32, pPg: *StatPage) c_int {
    const pgsz: c_int = sqlite3BtreeGetPageSize(pBt);
    var pDbPage: ?*DbPage = null;

    if (pPg.aPg == null) {
        const total: usize = @as(usize, @intCast(pgsz)) + DBSTAT_PAGE_PADDING_BYTES;
        pPg.aPg = @ptrCast(sqlite3_malloc(@intCast(total)));
        if (pPg.aPg == null) {
            return SQLITE_NOMEM;
        }
        @memset(pPg.aPg.?[@intCast(pgsz)..total], 0);
    }

    const rc = sqlite3PagerGet(sqlite3BtreePager(pBt), iPg, &pDbPage, 0);
    if (rc == SQLITE_OK) {
        const a: [*]const u8 = @ptrCast(sqlite3PagerGetData(pDbPage).?);
        @memcpy(pPg.aPg.?[0..@intCast(pgsz)], a[0..@intCast(pgsz)]);
        sqlite3PagerUnref(pDbPage);
    }

    return rc;
}

/// Move a DBSTAT cursor to the next entry.
fn statNext(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var z: ?[*:0]u8 = undefined;
    const pCsr: *StatCursor = @ptrCast(@alignCast(pCursor));
    const pTab: *StatTable = @ptrCast(@alignCast(pCursor.pVtab.?));
    const pBt = dbBtreeAt(pTab.db, pCsr.iDb);
    const pPager = sqlite3BtreePager(pBt);

    sqlite3_free(pCsr.zPath);
    pCsr.zPath = null;

    statNextRestart: while (true) {
        if (pCsr.iPage < 0) {
            // Start measuring space on the next btree.
            statResetCounts(pCsr);
            rc = sqlite3_step(pCsr.pStmt);
            if (rc == SQLITE_ROW) {
                const iRoot: u32 = @truncate(@as(u64, @bitCast(sqlite3_column_int64(pCsr.pStmt, 1))));
                var nPage: c_int = undefined;
                sqlite3PagerPagecount(pPager, &nPage);
                if (nPage == 0) {
                    pCsr.isEof = 1;
                    return sqlite3_reset(pCsr.pStmt);
                }
                rc = statGetPage(pBt, iRoot, &pCsr.aPage[0]);
                pCsr.aPage[0].iPgno = iRoot;
                pCsr.aPage[0].iCell = 0;
                if (pCsr.isAgg == 0) {
                    z = sqlite3_mprintf("/");
                    pCsr.aPage[0].zPath = z;
                    if (z == null) rc = SQLITE_NOMEM;
                }
                pCsr.iPage = 0;
                pCsr.nPage = 1;
            } else {
                pCsr.isEof = 1;
                return sqlite3_reset(pCsr.pStmt);
            }
        } else {
            // Continue analyzing the btree previously started.
            const p = &pCsr.aPage[@intCast(pCsr.iPage)];
            if (pCsr.isAgg == 0) statResetCounts(pCsr);
            while (p.iCell < p.nCell) {
                const pCell = &p.aCell.?[@intCast(p.iCell)];
                while (pCell.iOvfl < pCell.nOvfl) {
                    sqlite3BtreeEnter(pBt);
                    const nUsable = sqlite3BtreeGetPageSize(pBt) - sqlite3BtreeGetReserveNoMutex(pBt);
                    sqlite3BtreeLeave(pBt);
                    pCsr.nPage += 1;
                    statSizeAndOffset(pCsr);
                    if (pCell.iOvfl < pCell.nOvfl - 1) {
                        pCsr.nPayload += @as(i64, nUsable - 4);
                    } else {
                        pCsr.nPayload += @as(i64, pCell.nLastOvfl);
                        pCsr.nUnused += @as(i64, nUsable - 4 - pCell.nLastOvfl);
                    }
                    const iOvfl = pCell.iOvfl;
                    pCell.iOvfl += 1;
                    if (pCsr.isAgg == 0) {
                        pCsr.zName = sqlite3_column_text(pCsr.pStmt, 0);
                        pCsr.iPageno = pCell.aOvfl.?[@intCast(iOvfl)];
                        pCsr.zPagetype = "overflow";
                        z = sqlite3_mprintf("%s%.3x+%.6x", p.zPath, p.iCell, iOvfl);
                        pCsr.zPath = z;
                        return if (z == null) SQLITE_NOMEM else SQLITE_OK;
                    }
                }
                if (p.iRightChildPg != 0) break;
                p.iCell += 1;
            }

            if (p.iRightChildPg == 0 or p.iCell > p.nCell) {
                statClearPage(p);
                pCsr.iPage -= 1;
                if (pCsr.isAgg != 0 and pCsr.iPage < 0) {
                    // label-statNext-done: exit point for aggregate mode.
                    return SQLITE_OK;
                }
                continue :statNextRestart; // Tail recursion.
            }
            pCsr.iPage += 1;
            if (pCsr.iPage >= @as(c_int, ARRAY_SIZE_APAGE)) {
                statResetCsr(pCsr);
                return SQLITE_CORRUPT;
            }
            if (config.sqlite_debug) std.debug.assert(p == &pCsr.aPage[@intCast(pCsr.iPage - 1)]);

            if (p.iCell == p.nCell) {
                pCsr.aPage[@intCast(pCsr.iPage)].iPgno = p.iRightChildPg;
            } else {
                pCsr.aPage[@intCast(pCsr.iPage)].iPgno = p.aCell.?[@intCast(p.iCell)].iChildPg;
            }
            const pNext = &pCsr.aPage[@intCast(pCsr.iPage)];
            rc = statGetPage(pBt, pNext.iPgno, pNext);
            pCsr.nPage += 1;
            pNext.iCell = 0;
            if (pCsr.isAgg == 0) {
                z = sqlite3_mprintf("%s%.3x/", p.zPath, p.iCell);
                pNext.zPath = z;
                if (z == null) rc = SQLITE_NOMEM;
            }
            p.iCell += 1;
        }

        // Populate the StatCursor fields with the values to be returned by the
        // xColumn() and xRowid() methods.
        if (rc == SQLITE_OK) {
            const p = &pCsr.aPage[@intCast(pCsr.iPage)];
            pCsr.zName = sqlite3_column_text(pCsr.pStmt, 0);
            pCsr.iPageno = p.iPgno;

            rc = statDecodePage(pBt, p);
            if (rc == SQLITE_OK) {
                statSizeAndOffset(pCsr);

                switch (p.flags) {
                    0x05, 0x02 => pCsr.zPagetype = "internal", // table/index internal
                    0x0D, 0x0A => pCsr.zPagetype = "leaf", // table/index leaf
                    else => pCsr.zPagetype = "corrupted",
                }
                pCsr.nCell += p.nCell;
                pCsr.nUnused += @as(i64, p.nUnused);
                if (p.nMxPayload > pCsr.nMxPayload) pCsr.nMxPayload = p.nMxPayload;
                if (pCsr.isAgg == 0) {
                    z = sqlite3_mprintf("%s", p.zPath);
                    pCsr.zPath = z;
                    if (z == null) rc = SQLITE_NOMEM;
                }
                var nPayload: c_int = 0;
                var i: c_int = 0;
                while (i < p.nCell) : (i += 1) {
                    nPayload += p.aCell.?[@intCast(i)].nLocal;
                }
                pCsr.nPayload += @as(i64, nPayload);

                // If computing aggregate space usage by btree, continue with
                // the next page (exits via label-statNext-done).
                if (pCsr.isAgg != 0) continue :statNextRestart;
            }
        }

        return rc;
    }
}

fn statEof(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *StatCursor = @ptrCast(@alignCast(pCursor));
    return pCsr.isEof;
}

/// Initialize a cursor according to the query plan idxNum.
fn statFilter(
    pCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = idxStr;
    _ = argc;
    const pCsr: *StatCursor = @ptrCast(@alignCast(pCursor));
    const pTab: *StatTable = @ptrCast(@alignCast(pCursor.pVtab.?));
    var iArg: usize = 0; // Count of argv[] params used so far
    var rc: c_int = SQLITE_OK;
    var zName: ?[*:0]const u8 = null; // Only analyze this table

    statResetCsr(pCsr);
    _ = sqlite3_finalize(pCsr.pStmt);
    pCsr.pStmt = null;
    if (idxNum & 0x01 != 0) {
        // schema=? constraint is present.  Get its value.
        const zDbase = sqlite3_value_text(argv.?[iArg]);
        iArg += 1;
        pCsr.iDb = sqlite3FindDbName(pTab.db, zDbase);
        if (pCsr.iDb < 0) {
            pCsr.iDb = 0;
            pCsr.isEof = 1;
            return SQLITE_OK;
        }
    } else {
        pCsr.iDb = pTab.iDb;
    }
    if (idxNum & 0x02 != 0) {
        // name=? constraint is present.
        zName = sqlite3_value_text(argv.?[iArg]);
        iArg += 1;
    }
    if (idxNum & 0x04 != 0) {
        // aggregate=? constraint is present.
        pCsr.isAgg = @intFromBool(sqlite3_value_double(argv.?[iArg]) != 0.0);
        iArg += 1;
    } else {
        pCsr.isAgg = 0;
    }
    const pSql = sqlite3_str_new(pTab.db);
    sqlite3_str_appendf(
        pSql,
        "SELECT * FROM (" ++
            "SELECT 'sqlite_schema' AS name,1 AS rootpage,'table' AS type" ++
            " UNION ALL " ++
            "SELECT name,rootpage,type" ++
            " FROM \"%w\".sqlite_schema WHERE rootpage!=0)",
        dbNameAt(pTab.db, pCsr.iDb),
    );
    if (zName != null) {
        sqlite3_str_appendf(pSql, "WHERE name=%Q", zName);
    }
    if (idxNum & 0x08 != 0) {
        sqlite3_str_appendf(pSql, " ORDER BY name");
    }
    const zSql = sqlite3_str_finish(pSql);
    if (zSql == null) {
        return SQLITE_NOMEM;
    } else {
        rc = sqlite3_prepare_v2(pTab.db, zSql.?, -1, &pCsr.pStmt, null);
        sqlite3_free(zSql);
    }

    if (rc == SQLITE_OK) {
        pCsr.iPage = -1;
        rc = statNext(pCursor);
    }
    return rc;
}

fn statColumn(pCursor: *sqlite3_vtab_cursor, ctx: ?*sqlite3_context, i: c_int) callconv(.c) c_int {
    const pCsr: *StatCursor = @ptrCast(@alignCast(pCursor));
    switch (i) {
        0 => sqlite3_result_text(ctx, pCsr.zName, -1, SQLITE_TRANSIENT), // name
        1 => { // path
            if (pCsr.isAgg == 0) {
                sqlite3_result_text(ctx, pCsr.zPath, -1, SQLITE_TRANSIENT);
            }
        },
        2 => { // pageno
            if (pCsr.isAgg != 0) {
                sqlite3_result_int64(ctx, pCsr.nPage);
            } else {
                sqlite3_result_int64(ctx, pCsr.iPageno);
            }
        },
        3 => { // pagetype
            if (pCsr.isAgg == 0) {
                sqlite3_result_text(ctx, pCsr.zPagetype, -1, SQLITE_STATIC);
            }
        },
        4 => sqlite3_result_int64(ctx, pCsr.nCell), // ncell
        5 => sqlite3_result_int64(ctx, pCsr.nPayload), // payload
        6 => sqlite3_result_int64(ctx, pCsr.nUnused), // unused
        7 => sqlite3_result_int64(ctx, pCsr.nMxPayload), // mx_payload
        8 => { // pgoffset
            if (pCsr.isAgg == 0) {
                sqlite3_result_int64(ctx, pCsr.iOffset);
            }
        },
        9 => sqlite3_result_int64(ctx, pCsr.szPage), // pgsize
        10 => { // schema
            const db = sqlite3_context_db_handle(ctx);
            sqlite3_result_text(ctx, dbNameAt(db, pCsr.iDb), -1, SQLITE_STATIC);
        },
        else => sqlite3_result_int(ctx, pCsr.isAgg), // aggregate
    }
    return SQLITE_OK;
}

fn statRowid(pCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *StatCursor = @ptrCast(@alignCast(pCursor));
    pRowid.* = pCsr.iPageno;
    return SQLITE_OK;
}

/// The dbstat schema (zDbstatSchema in C).
const zDbstatSchema: [*:0]const u8 =
    "CREATE TABLE x(" ++
    " name       TEXT," ++ //  0 Name of table or index
    " path       TEXT," ++ //  1 Path to page from root (NULL for agg)
    " pageno     INTEGER," ++ //  2 Page number (page count for aggregates)
    " pagetype   TEXT," ++ //  3 'internal', 'leaf', 'overflow', or NULL
    " ncell      INTEGER," ++ //  4 Cells on page (0 for overflow)
    " payload    INTEGER," ++ //  5 Bytes of payload on this page
    " unused     INTEGER," ++ //  6 Bytes of unused space on this page
    " mx_payload INTEGER," ++ //  7 Largest payload size of all cells
    " pgoffset   INTEGER," ++ //  8 Offset of page in file (NULL for agg)
    " pgsize     INTEGER," ++ //  9 Size of the page (sum for aggregate)
    " schema     TEXT HIDDEN," ++ // 10 Database schema being analyzed
    " aggregate  BOOLEAN HIDDEN" ++ // 11 aggregate info for each table
    ")";

/// The virtual-table method table. Mirrors the C `dbstat_module`.
const dbstat_module: sqlite3_module = .{
    .iVersion = 0,
    .xCreate = &statConnect,
    .xConnect = &statConnect,
    .xBestIndex = &statBestIndex,
    .xDisconnect = &statDisconnect,
    .xDestroy = &statDisconnect,
    .xOpen = &statOpen,
    .xClose = &statClose,
    .xFilter = &statFilter,
    .xNext = &statNext,
    .xEof = &statEof,
    .xColumn = &statColumn,
    .xRowid = &statRowid,
    .xUpdate = null,
    .xBegin = null,
    .xSync = null,
    .xCommit = null,
    .xRollback = null,
    .xFindFunction = null,
    .xRename = null,
    .xSavepoint = null,
    .xRelease = null,
    .xRollbackTo = null,
    .xShadowName = null,
    .xIntegrity = null,
};

/// Invoke this routine to register the "dbstat" virtual table module.
export fn sqlite3DbstatRegister(db: ?*sqlite3) callconv(.c) c_int {
    return sqlite3_create_module(db, "dbstat", &dbstat_module, null);
}
