//! Zig port of SQLite's "sqlite_stmt" eponymous virtual table (ext/misc/stmt.c).
//!
//! Drop-in replacement exporting the single internal entry point
//! `sqlite3StmtVtabInit` (called from main.c's built-in-extension table to
//! register the `sqlite_stmt` module). The vtab enumerates every prepared
//! statement on a connection — one row per statement — exposing its SQL text
//! and a handful of per-statement counters.
//!
//! Compiled because SQLITE_ENABLE_STMTVTAB is set (true in both builds).
//!
//! Config-invariance: this module is CONFIG-INVARIANT and needs NO ground-truth
//! offsets. Unlike utf.c / os.c / table.c, it reaches into NO internal `sqlite3`
//! or `Vdbe` field. Every per-statement value flows through the PUBLIC
//! sqlite3_stmt API:
//!   * statement enumeration   — sqlite3_next_stmt(db, prev)
//!   * SQL text                — sqlite3_sql(p)
//!   * column count            — sqlite3_column_count(p)
//!   * read-only / busy        — sqlite3_stmt_readonly(p) / sqlite3_stmt_busy(p)
//!   * the 7 status counters    — sqlite3_stmt_status(p, SQLITE_STMTSTATUS_*, 0)
//! and the only `sqlite3*` it holds (stmt_vtab.db / stmt_cursor.db) is passed
//! opaquely straight back into sqlite3_next_stmt(). Registration is the public
//! sqlite3_create_module() (NOT the internal sqlite3VtabCreateModule used by
//! carray) — exactly as the C does. So one Zig object is correct in both the
//! production `zig build` and the `--dev` testfixture (SQLITE_DEBUG/TEST) links.
//!
//! Note the loadable-extension entry `sqlite3_stmt_init` from the C file is
//! behind `#ifndef SQLITE_CORE`; this split build sets -DSQLITE_CORE=1, so that
//! symbol is NOT compiled and is intentionally absent here (it would otherwise
//! collide with the per-extension sqlite3_api machinery).
//!
//! StmtRow / stmt_vtab / stmt_cursor are this module's OWN structs (base class
//! first for the C-style subclassing), so we control their layout; mirrored as
//! `extern struct` to match the C allocation sizes byte-for-byte.
//!
//! Pure-Zig unit testing is not feasible: every code path needs a live
//! connection with prepared statements and the SQLite VM. Validated end-to-end
//! by the engine via test/stmtvtab1.test (upstream) under the testfixture.

const std = @import("std");

// --- Result codes (sqlite3.h) ---
const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7;

// --- Column numbers (match the declared schema order) ---
const STMT_COLUMN_SQL: c_int = 0; // SQL for the statement
const STMT_COLUMN_NCOL: usize = 1; // Number of result columns
const STMT_COLUMN_RO: usize = 2; // True if read-only
const STMT_COLUMN_BUSY: usize = 3; // True if currently busy
const STMT_COLUMN_NSCAN: usize = 4; // SQLITE_STMTSTATUS_FULLSCAN_STEP
const STMT_COLUMN_NSORT: usize = 5; // SQLITE_STMTSTATUS_SORT
const STMT_COLUMN_NAIDX: usize = 6; // SQLITE_STMTSTATUS_AUTOINDEX
const STMT_COLUMN_NSTEP: usize = 7; // SQLITE_STMTSTATUS_VM_STEP
const STMT_COLUMN_REPREP: usize = 8; // SQLITE_STMTSTATUS_REPREPARE
const STMT_COLUMN_RUN: usize = 9; // SQLITE_STMTSTATUS_RUN
const STMT_COLUMN_MEM: usize = 10; // SQLITE_STMTSTATUS_MEMUSED
const STMT_NUM_INTEGER_COLUMN: usize = 10;

// --- sqlite3_stmt_status opcodes (sqlite3.h) ---
const SQLITE_STMTSTATUS_FULLSCAN_STEP: c_int = 1;
const SQLITE_STMTSTATUS_SORT: c_int = 2;
const SQLITE_STMTSTATUS_AUTOINDEX: c_int = 3;
const SQLITE_STMTSTATUS_VM_STEP: c_int = 4;
const SQLITE_STMTSTATUS_REPREPARE: c_int = 5;
const SQLITE_STMTSTATUS_RUN: c_int = 6;
const SQLITE_STMTSTATUS_MEMUSED: c_int = 99;

// --- Destructor sentinel: SQLITE_TRANSIENT == -1 (sqlite3.h) ---
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// --- Public ABI opaque handles (sqlite3.h) ---
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;

// --- Public ABI structs (sqlite3.h) ---

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

/// The virtual table method table — PUBLIC ABI. Must match sqlite3_module field
/// for field (mirrored exactly as in src/carray.zig). Unused slots stay null;
/// the sqlite_stmt vtab is read-only and eponymous.
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

// --- This module's own structs (we own their layout) ---

/// One materialized row, holding the SQL text and all integer columns. The SQL
/// string is allocated immediately after the struct (`&pNew[1]`), so the
/// allocation is `sizeof(StmtRow) + nSql`. `extern struct` so the trailing-byte
/// layout matches the C allocation exactly.
const StmtRow = extern struct {
    iRowid: i64, // Rowid value
    zSql: ?[*:0]u8, // column "sql"
    aCol: [STMT_NUM_INTEGER_COLUMN + 1]c_int, // all other column values
    pNext: ?*StmtRow, // Next row to return
};

/// Subclass of sqlite3_vtab. `base` MUST be first for the vtab*<->base* subclassing.
const stmt_vtab = extern struct {
    base: sqlite3_vtab, // Base class - must be first
    db: ?*sqlite3, // Database connection for this stmt vtab
};

/// Subclass of sqlite3_vtab_cursor. `base` MUST be first.
const stmt_cursor = extern struct {
    base: sqlite3_vtab_cursor, // Base class - must be first
    db: ?*sqlite3, // Database connection for this cursor
    pRow: ?*StmtRow, // Current row
};

// --- Public sqlite3 API resolved at link time ---
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_create_module(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pClientData: ?*anyopaque) c_int;

extern fn sqlite3_next_stmt(db: ?*sqlite3, pStmt: ?*sqlite3_stmt) ?*sqlite3_stmt;
extern fn sqlite3_sql(pStmt: ?*sqlite3_stmt) ?[*:0]const u8;
extern fn sqlite3_column_count(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_stmt_readonly(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_stmt_busy(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_stmt_status(pStmt: ?*sqlite3_stmt, op: c_int, resetFlg: c_int) c_int;

extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;

extern fn strlen(s: [*:0]const u8) usize;
extern fn memcpy(dest: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;

/// The stmtConnect() method: declare the schema and allocate the stmt_vtab.
/// Eponymous virtual table, so this serves as xConnect with xCreate left null.
fn stmtConnect(
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
    const rc = sqlite3_declare_vtab(
        db,
        "CREATE TABLE x(sql,ncol,ro,busy,nscan,nsort,naidx,nstep,reprep,run,mem)",
    );
    if (rc == SQLITE_OK) {
        const pNew: ?*stmt_vtab = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(stmt_vtab))));
        ppVtab.* = @ptrCast(pNew);
        if (pNew == null) return SQLITE_NOMEM;
        pNew.?.* = std.mem.zeroes(stmt_vtab);
        pNew.?.db = db;
    }
    return rc;
}

/// Destructor for stmt_vtab objects.
fn stmtDisconnect(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

/// Constructor for a new stmt_cursor object.
fn stmtOpen(p: *sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: ?*stmt_cursor = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(stmt_cursor))));
    if (pCur == null) return SQLITE_NOMEM;
    pCur.?.* = std.mem.zeroes(stmt_cursor);
    pCur.?.db = @as(*stmt_vtab, @ptrCast(p)).db;
    ppCursor.* = &pCur.?.base;
    return SQLITE_OK;
}

/// Free every materialized row hanging off the cursor.
fn stmtCsrReset(pCur: *stmt_cursor) void {
    var pRow = pCur.pRow;
    while (pRow) |r| {
        const pNext = r.pNext;
        sqlite3_free(r);
        pRow = pNext;
    }
    pCur.pRow = null;
}

/// Destructor for a stmt_cursor.
fn stmtClose(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    stmtCsrReset(@ptrCast(@alignCast(cur)));
    sqlite3_free(cur);
    return SQLITE_OK;
}

/// Advance a stmt_cursor to its next row of output.
fn stmtNext(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: *stmt_cursor = @ptrCast(@alignCast(cur));
    const pNext = pCur.pRow.?.pNext;
    sqlite3_free(pCur.pRow);
    pCur.pRow = pNext;
    return SQLITE_OK;
}

/// Return values of columns for the current row.
fn stmtColumn(cur: *sqlite3_vtab_cursor, ctx: ?*sqlite3_context, i: c_int) callconv(.c) c_int {
    const pCur: *stmt_cursor = @ptrCast(@alignCast(cur));
    const pRow = pCur.pRow.?;
    if (i == STMT_COLUMN_SQL) {
        sqlite3_result_text(ctx, pRow.zSql, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_int(ctx, pRow.aCol[@intCast(i)]);
    }
    return SQLITE_OK;
}

/// Return the rowid for the current row (same as the output value's position).
fn stmtRowid(cur: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCur: *stmt_cursor = @ptrCast(@alignCast(cur));
    pRowid.* = pCur.pRow.?.iRowid;
    return SQLITE_OK;
}

/// Return TRUE if the cursor has moved off the last row of output.
fn stmtEof(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: *stmt_cursor = @ptrCast(@alignCast(cur));
    return @intFromBool(pCur.pRow == null);
}

/// "Rewind" the cursor: walk the connection's prepared-statement list and
/// materialize one StmtRow per statement, reading each counter via the public
/// sqlite3_stmt API.
fn stmtFilter(
    pVtabCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = idxNum;
    _ = idxStr;
    _ = argc;
    _ = argv;
    const pCur: *stmt_cursor = @ptrCast(@alignCast(pVtabCursor));
    var iRowid: i64 = 1;

    stmtCsrReset(pCur);
    var ppRow: *?*StmtRow = &pCur.pRow;
    var p = sqlite3_next_stmt(pCur.db, null);
    while (p) |stmt| : (p = sqlite3_next_stmt(pCur.db, stmt)) {
        const zSql = sqlite3_sql(stmt);
        const nSql: u64 = if (zSql) |z| @as(u64, strlen(z)) + 1 else 0;
        const pNew: ?*StmtRow = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(StmtRow) + nSql)));
        if (pNew == null) return SQLITE_NOMEM;
        const row = pNew.?;
        row.* = std.mem.zeroes(StmtRow);
        if (zSql) |z| {
            // The SQL text lives in the bytes immediately after the struct.
            const dst: [*:0]u8 = @ptrCast(@as([*]StmtRow, @ptrCast(row)) + 1);
            row.zSql = dst;
            _ = memcpy(dst, z, nSql);
        }
        row.aCol[STMT_COLUMN_NCOL] = sqlite3_column_count(stmt);
        row.aCol[STMT_COLUMN_RO] = sqlite3_stmt_readonly(stmt);
        row.aCol[STMT_COLUMN_BUSY] = sqlite3_stmt_busy(stmt);
        row.aCol[STMT_COLUMN_NSCAN] = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_FULLSCAN_STEP, 0);
        row.aCol[STMT_COLUMN_NSORT] = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_SORT, 0);
        row.aCol[STMT_COLUMN_NAIDX] = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_AUTOINDEX, 0);
        row.aCol[STMT_COLUMN_NSTEP] = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_VM_STEP, 0);
        row.aCol[STMT_COLUMN_REPREP] = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_REPREPARE, 0);
        row.aCol[STMT_COLUMN_RUN] = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_RUN, 0);
        row.aCol[STMT_COLUMN_MEM] = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_MEMUSED, 0);
        row.iRowid = iRowid;
        iRowid += 1;
        ppRow.* = row;
        ppRow = &row.pNext;
    }

    return SQLITE_OK;
}

/// Trivial query plan — fixed cost, the table is always a full scan.
fn stmtBestIndex(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = tab;
    pIdxInfo.estimatedCost = 500.0;
    pIdxInfo.estimatedRows = 500;
    return SQLITE_OK;
}

/// The sqlite_stmt virtual table method table.
const stmtModule: sqlite3_module = .{
    .iVersion = 0,
    .xCreate = null,
    .xConnect = &stmtConnect,
    .xBestIndex = &stmtBestIndex,
    .xDisconnect = &stmtDisconnect,
    .xDestroy = null,
    .xOpen = &stmtOpen,
    .xClose = &stmtClose,
    .xFilter = &stmtFilter,
    .xNext = &stmtNext,
    .xEof = &stmtEof,
    .xColumn = &stmtColumn,
    .xRowid = &stmtRowid,
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

/// Register the `sqlite_stmt` eponymous module on `db`. Called from main.c's
/// built-in-extension table. Uses the PUBLIC sqlite3_create_module().
export fn sqlite3StmtVtabInit(db: ?*sqlite3) callconv(.c) c_int {
    return sqlite3_create_module(db, "sqlite_stmt", &stmtModule, null);
}
