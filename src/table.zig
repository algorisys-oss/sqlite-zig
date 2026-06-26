//! Zig port of SQLite's sqlite3_get_table() / sqlite3_free_table() (src/table.c).
//!
//! These are the legacy "run a query and hand back every result cell as one flat
//! char** array" convenience API. They are thin wrappers around the public
//! sqlite3_exec(): an internal callback (`getTableCb`, static in C) accumulates
//! column names + row data into a growable `char*[]`, and the result count is
//! smuggled into slot 0 of the over-allocated array so sqlite3_free_table() can
//! later walk and free it.
//!
//! Exported symbols (the only two non-static externals in table.c):
//!   - sqlite3_get_table
//!   - sqlite3_free_table
//! The accumulator (`TabResult`) and the row callback are internal to this
//! module — we own their layout, so they are plain Zig.
//!
//! Couplings:
//!   - Public API where C uses it: sqlite3_exec, sqlite3_malloc64, sqlite3_free,
//!     sqlite3_mprintf. Internal-but-ABI helpers: sqlite3Realloc, sqlite3Strlen30.
//!   - ONE internal sqlite3 connection field is written: `db->errCode` (int),
//!     read/written at its ground-truth offset via `c_layout.c.sqlite3_errCode`
//!     (C does `db->errCode = SQLITE_NOMEM;` and `db->errCode = res.rc;`). We do
//!     NOT mirror the sqlite3 struct — just poke the int at that offset.
//!
//! Config assumptions (true in both this project's builds):
//!   - SQLITE_OMIT_GET_TABLE is off (these functions are compiled).
//!   - SQLITE_ENABLE_API_ARMOR is off, so the get_table() armor guard
//!     (sqlite3SafetyCheckOk / pazResult==0 check) is not emitted — matching the
//!     production and --dev testfixture configs.
//! The `db->errCode` offset is config-invariant (the orchestrator asserts this
//! at comptime in c_layout once the offset is extracted), so this single Zig
//! object is correct in both the production and testfixture links.
//!
//! Validated via the engine: test/table.test, test/tableapi.test, and the capi
//! suite (test1.c's sqlite3_get_table_printf wrapper). No standalone Zig test is
//! meaningful here — every path runs the live VDBE through sqlite3_exec.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_ABORT: c_int = 4;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT collapses to this in production

// --- C / public helpers resolved at link time ---
const ExecCallback = ?*const fn (?*anyopaque, c_int, ?[*]?[*:0]u8, ?[*]?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3_exec(
    db: ?*anyopaque,
    sql: ?[*:0]const u8,
    callback: ExecCallback,
    arg: ?*anyopaque,
    errmsg: ?*?[*:0]u8,
) c_int;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3Strlen30(z: [*:0]const u8) c_int;
extern fn memcpy(dest: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;

/// Write `db->errCode` (an int) at its ground-truth offset. C assumes the 32-bit
/// store is atomic; a plain write matches.
inline fn setDbErrCode(db: ?*anyopaque, code: c_int) void {
    const base: [*]u8 = @ptrCast(db.?);
    const p: *align(1) c_int = @ptrCast(base + L.sqlite3_errCode);
    p.* = code;
}

/// Accumulator passed (as void*) from sqlite3_get_table through the exec
/// callback. We own this layout entirely (TabResult is a static C struct).
const TabResult = struct {
    azResult: ?[*]?[*:0]u8, // Accumulated output
    zErrMsg: ?[*:0]u8, // Error message text, if an error occurs
    nAlloc: u32, // Slots allocated for azResult[]
    nRow: u32, // Number of rows in the result
    nColumn: u32, // Number of columns in the result
    nData: u32, // Slots used in azResult[].  (nRow+1)*nColumn
    rc: c_int, // Return code from sqlite3_exec()
};

/// Called once per result row (and once for the header). Fills in TabResult,
/// allocating as needed. Returns non-zero to abort the query.
fn getTableCb(pArg: ?*anyopaque, nCol: c_int, argv: ?[*]?[*:0]u8, colv: ?[*]?[*:0]u8) callconv(.c) c_int {
    const p: *TabResult = @ptrCast(@alignCast(pArg.?));

    // Ensure azResult has room for everything this invocation needs.
    const need: c_int = if (p.nRow == 0 and argv != null) nCol *% 2 else nCol;
    if (p.nData +% @as(u32, @bitCast(need)) > p.nAlloc) {
        p.nAlloc = p.nAlloc *% 2 +% @as(u32, @bitCast(need));
        const azNew: ?[*]?[*:0]u8 = @ptrCast(@alignCast(
            sqlite3Realloc(@ptrCast(p.azResult), @sizeOf(?*anyopaque) * @as(u64, p.nAlloc)),
        ));
        if (azNew == null) return mallocFailed(p);
        p.azResult = azNew;
    }

    const az = p.azResult.?;

    // First row: emit an extra header row holding the column names.
    if (p.nRow == 0) {
        p.nColumn = @bitCast(nCol);
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const z = sqlite3_mprintf("%s", colv.?[@intCast(i)]);
            if (z == null) return mallocFailed(p);
            az[p.nData] = z;
            p.nData += 1;
        }
    } else if (@as(c_int, @bitCast(p.nColumn)) != nCol) {
        sqlite3_free(p.zErrMsg);
        p.zErrMsg = sqlite3_mprintf(
            "sqlite3_get_table() called with two or more incompatible queries",
        );
        p.rc = SQLITE_ERROR;
        return 1;
    }

    // Copy over the row data.
    if (argv) |a| {
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const idx: usize = @intCast(i);
            var z: ?[*:0]u8 = null;
            if (a[idx]) |src| {
                const n: c_int = sqlite3Strlen30(src) + 1;
                const dst: ?[*:0]u8 = @ptrCast(sqlite3_malloc64(@intCast(n)));
                if (dst == null) return mallocFailed(p);
                _ = memcpy(dst, src, @intCast(n));
                z = dst;
            }
            az[p.nData] = z;
            p.nData += 1;
        }
        p.nRow += 1;
    }
    return 0;
}

/// `malloc_failed:` label in C — set NOMEM and abort.
inline fn mallocFailed(p: *TabResult) c_int {
    p.rc = SQLITE_NOMEM; // SQLITE_NOMEM_BKPT
    return 1;
}

/// Query the database, collecting every result cell into a freshly malloc'd
/// char** table written to *pazResult (free with sqlite3_free_table).
export fn sqlite3_get_table(
    db: ?*anyopaque,
    zSql: ?[*:0]const u8,
    pazResult: ?*?[*]?[*:0]u8,
    pnRow: ?*c_int,
    pnColumn: ?*c_int,
    pzErrMsg: ?*?[*:0]u8,
) callconv(.c) c_int {
    // SQLITE_ENABLE_API_ARMOR is off, so no safety-check guard here.
    pazResult.?.* = null;
    if (pnColumn) |q| q.* = 0;
    if (pnRow) |q| q.* = 0;
    if (pzErrMsg) |q| q.* = null;

    var res: TabResult = .{
        .azResult = null,
        .zErrMsg = null,
        .nAlloc = 20,
        .nRow = 0,
        .nColumn = 0,
        .nData = 1,
        .rc = SQLITE_OK,
    };
    res.azResult = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(?*anyopaque) * @as(u64, res.nAlloc))));
    if (res.azResult == null) {
        setDbErrCode(db, SQLITE_NOMEM);
        return SQLITE_NOMEM; // SQLITE_NOMEM_BKPT
    }
    res.azResult.?[0] = null;
    const rc = sqlite3_exec(db, zSql, getTableCb, &res, pzErrMsg);
    // assert( sizeof(res.azResult[0]) >= sizeof(res.nData) ) — pointer >= u32.
    // Stash the slot count into slot 0 (SQLITE_INT_TO_PTR).
    res.azResult.?[0] = @ptrFromInt(@as(usize, res.nData));
    if ((rc & 0xff) == SQLITE_ABORT) {
        sqlite3_free_table(@ptrCast(res.azResult.? + 1));
        if (res.zErrMsg) |em| {
            if (pzErrMsg) |q| {
                sqlite3_free(q.*);
                q.* = sqlite3_mprintf("%s", em);
            }
            sqlite3_free(em);
        }
        setDbErrCode(db, res.rc); // Assume 32-bit assignment is atomic
        return res.rc;
    }
    sqlite3_free(res.zErrMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free_table(@ptrCast(res.azResult.? + 1));
        return rc;
    }
    if (res.nAlloc > res.nData) {
        const azNew: ?[*]?[*:0]u8 = @ptrCast(@alignCast(
            sqlite3Realloc(@ptrCast(res.azResult), @sizeOf(?*anyopaque) * @as(u64, res.nData)),
        ));
        if (azNew == null) {
            sqlite3_free_table(@ptrCast(res.azResult.? + 1));
            setDbErrCode(db, SQLITE_NOMEM);
            return SQLITE_NOMEM; // SQLITE_NOMEM_BKPT
        }
        res.azResult = azNew;
    }
    pazResult.?.* = res.azResult.? + 1;
    if (pnColumn) |q| q.* = @bitCast(res.nColumn);
    if (pnRow) |q| q.* = @bitCast(res.nRow);
    return rc;
}

/// Free the space allocated by sqlite3_get_table().
export fn sqlite3_free_table(azResult_in: ?[*]?[*:0]u8) callconv(.c) void {
    if (azResult_in) |az_plus1| {
        const azResult = az_plus1 - 1; // step back to the count slot
        const n: c_int = @intCast(@intFromPtr(azResult[0]));
        var i: c_int = 1;
        while (i < n) : (i += 1) {
            if (azResult[@intCast(i)]) |cell| sqlite3_free(cell);
        }
        sqlite3_free(@ptrCast(azResult));
    }
}
