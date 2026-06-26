//! Zig port of SQLite's sqlite3_exec() (src/legacy.c).
//!
//! Drop-in replacement exporting the single non-static symbol in legacy.c:
//!   - sqlite3_exec
//! the convenience "prepare -> step -> callback-per-row -> finalize" loop over a
//! SQL string. It is mostly a driver of the public sqlite3 prepare/step/column
//! API; it reaches into a few internal `sqlite3` connection fields, each read at
//! its ground-truth offset via `c_layout` (modelled on src/table.zig).
//!
//! Internal `sqlite3` fields touched directly (offset reads, NOT a struct mirror):
//!   - `db->mutex`   (pointer) -> c_layout.c.sqlite3_mutex   : passed to
//!     sqlite3_mutex_enter/leave. C reads the field directly; we do the same.
//!   - `db->flags`   (u64)     -> c_layout.c.sqlite3_flags   : tested
//!     `db->flags & SQLITE_NullCallback`.
//!   - `db->errMask` (int)     -> c_layout.c.sqlite3_errMask : ONLY used by the
//!     `assert( (rc&db->errMask)==rc )` near the end, which is live only under
//!     SQLITE_DEBUG. We read it (and run the assert) solely when
//!     `config.sqlite_debug`, so production never references the offset.
//! Everything else goes through public API / internal ABI helpers:
//!   sqlite3SafetyCheckOk, sqlite3Error, sqlite3_prepare_v2, sqlite3_step,
//!   sqlite3_column_count/name/text/type, sqlite3DbMallocRaw, sqlite3OomFault,
//!   sqlite3VdbeFinalize, sqlite3DbFree, sqlite3ApiExit, sqlite3_errmsg,
//!   sqlite3DbStrDup, sqlite3Isspace (via sqlite3CtypeMap), sqlite3_mutex_*.
//!
//! Config assumptions (true in both this project's builds):
//!   - SQLITE_ENABLE_API_ARMOR is off, so the only safety guard is the
//!     sqlite3SafetyCheckOk() at entry (present in C unconditionally), matching
//!     both the production and --dev testfixture configs.
//!   - SQLITE_MISUSE_BKPT / SQLITE_NOMEM_BKPT collapse to their plain codes
//!     (SQLITE_MISUSE / SQLITE_NOMEM); the only difference under SQLITE_DEBUG is a
//!     breakpoint/log side effect, with an identical return value (per the
//!     project convention in docs/architecture.md).
//!
//! The `db->flags`/`db->mutex` offsets are config-invariant; `db->errMask` is
//! only referenced under config.sqlite_debug. c_layout asserts the offsets at
//! comptime, so this single Zig object is correct in both links.
//!
//! No standalone Zig test is meaningful here -- every path runs the live VDBE
//! through prepare/step. Validated via the engine: capi3*.test, exec.test and
//! main.test (and badutf*/alter etc. drive it through the TCL `sqlite3_exec`).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT collapses to this in production
const SQLITE_MISUSE: c_int = 21; // SQLITE_MISUSE_BKPT collapses to this
const SQLITE_ABORT: c_int = 4;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_NULL: c_int = 5;

const SQLITE_NullCallback: u64 = 0x00000100;

// --- public / internal-ABI helpers resolved at link time ---
const ExecCallback = ?*const fn (?*anyopaque, c_int, ?[*]?[*:0]u8, ?[*]?[*:0]u8) callconv(.c) c_int;

extern fn sqlite3SafetyCheckOk(db: ?*anyopaque) c_int;
extern fn sqlite3Error(db: ?*anyopaque, errCode: c_int) void;
extern fn sqlite3OomFault(db: ?*anyopaque) void;
extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3ApiExit(db: ?*anyopaque, rc: c_int) c_int;
extern fn sqlite3VdbeFinalize(p: ?*anyopaque) c_int;

extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3_prepare_v2(db: ?*anyopaque, zSql: ?[*]const u8, nByte: c_int, ppStmt: *?*anyopaque, pzTail: *?[*:0]const u8) c_int;
extern fn sqlite3_step(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_column_count(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_column_name(pStmt: ?*anyopaque, N: c_int) ?[*:0]u8;
extern fn sqlite3_column_text(pStmt: ?*anyopaque, N: c_int) ?[*:0]u8;
extern fn sqlite3_column_type(pStmt: ?*anyopaque, N: c_int) c_int;
extern fn sqlite3_errmsg(db: ?*anyopaque) ?[*:0]const u8;

/// sqlite3Isspace(x): SQLITE_ASCII ctype lookup, mask 0x01.
extern const sqlite3CtypeMap: [256]u8;
inline fn isSpace(ch: u8) bool {
    return (sqlite3CtypeMap[ch] & 0x01) != 0;
}

/// Read `db->mutex` (a pointer) at its ground-truth offset. C reads the field
/// directly to feed sqlite3_mutex_enter/leave.
inline fn dbMutex(db: ?*anyopaque) ?*anyopaque {
    const base: [*]u8 = @ptrCast(db.?);
    const p: *align(1) ?*anyopaque = @ptrCast(base + L.sqlite3_mutex);
    return p.*;
}

/// Read `db->flags` (u64) at its ground-truth offset.
inline fn dbFlags(db: ?*anyopaque) u64 {
    const base: [*]const u8 = @ptrCast(db.?);
    const p: *align(1) const u64 = @ptrCast(base + L.sqlite3_flags);
    return p.*;
}

/// Read `db->errMask` (int) at its ground-truth offset. Only referenced under
/// SQLITE_DEBUG (the assert), so the offset is touched only in that config.
inline fn dbErrMask(db: ?*anyopaque) c_int {
    const base: [*]const u8 = @ptrCast(db.?);
    const p: *align(1) const c_int = @ptrCast(base + L.sqlite3_errMask);
    return p.*;
}

/// Execute SQL code. Return one of the SQLITE_ success/failure codes. Also write
/// an error message into memory obtained from malloc() and make *pzErrMsg point
/// to that message. If the SQL is a query, xCallback() is invoked once per row
/// (with pArg as its first argument); xCallback==NULL means no callback.
export fn sqlite3_exec(
    db: ?*anyopaque, // The database on which the SQL executes
    zSql_in: ?[*:0]const u8, // The SQL to be executed
    xCallback: ExecCallback, // Invoke this callback routine
    pArg: ?*anyopaque, // First argument to xCallback()
    pzErrMsg: ?*?[*:0]u8, // Write error messages here
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK; // Return code
    var zLeftover: ?[*:0]const u8 = undefined; // Tail of unprocessed SQL
    var pStmt: ?*anyopaque = null; // The current SQL statement
    var azCols: ?[*]?[*:0]u8 = null; // Names of result columns
    var callbackIsInit: bool = false; // True if callback data is initialized

    if (sqlite3SafetyCheckOk(db) == 0) return SQLITE_MISUSE; // SQLITE_MISUSE_BKPT
    // zSql==0 -> "". An empty C string is a single NUL terminator.
    const empty: [*:0]const u8 = "";
    var zSql: [*:0]const u8 = zSql_in orelse empty;

    const mutex = dbMutex(db);
    sqlite3_mutex_enter(mutex);
    sqlite3Error(db, SQLITE_OK);

    while (rc == SQLITE_OK and zSql[0] != 0) {
        var nCol: c_int = 0;
        var azVals: ?[*]?[*:0]u8 = null;

        pStmt = null;
        rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, &zLeftover);
        // assert( rc==SQLITE_OK || pStmt==0 );
        if (rc != SQLITE_OK) {
            continue;
        }
        if (pStmt == null) {
            // this happens for a comment or white-space
            zSql = zLeftover.?;
            continue;
        }
        callbackIsInit = false;

        while (true) {
            var i: c_int = undefined;
            rc = sqlite3_step(pStmt);

            // Invoke the callback function if required
            if (xCallback != null and (rc == SQLITE_ROW or
                (rc == SQLITE_DONE and !callbackIsInit and
                    (dbFlags(db) & SQLITE_NullCallback) != 0)))
            {
                if (!callbackIsInit) {
                    nCol = sqlite3_column_count(pStmt);
                    azCols = @ptrCast(@alignCast(sqlite3DbMallocRaw(
                        db,
                        @as(u64, @intCast(2 * nCol + 1)) * @sizeOf(?*anyopaque),
                    )));
                    if (azCols == null) {
                        return execOut(db, pStmt, azCols, rc, pzErrMsg, mutex);
                    }
                    i = 0;
                    while (i < nCol) : (i += 1) {
                        azCols.?[@intCast(i)] = sqlite3_column_name(pStmt, i);
                        // sqlite3VdbeSetColName() installs column names as UTF8
                        // strings so sqlite3_column_name() cannot fail here.
                        // assert( azCols[i]!=0 );
                    }
                    callbackIsInit = true;
                }
                if (rc == SQLITE_ROW) {
                    azVals = azCols.? + @as(usize, @intCast(nCol));
                    i = 0;
                    while (i < nCol) : (i += 1) {
                        const idx: usize = @intCast(i);
                        azVals.?[idx] = sqlite3_column_text(pStmt, i);
                        if (azVals.?[idx] == null and sqlite3_column_type(pStmt, i) != SQLITE_NULL) {
                            sqlite3OomFault(db);
                            return execOut(db, pStmt, azCols, rc, pzErrMsg, mutex);
                        }
                    }
                    azVals.?[@intCast(i)] = null;
                }
                if (xCallback.?(pArg, nCol, azVals, azCols) != 0) {
                    // R-38229-40159: a non-zero callback return makes
                    // sqlite3_exec() return SQLITE_ABORT.
                    rc = SQLITE_ABORT;
                    _ = sqlite3VdbeFinalize(pStmt);
                    pStmt = null;
                    sqlite3Error(db, SQLITE_ABORT);
                    return execOut(db, pStmt, azCols, rc, pzErrMsg, mutex);
                }
            }

            if (rc != SQLITE_ROW) {
                rc = sqlite3VdbeFinalize(pStmt);
                pStmt = null;
                zSql = zLeftover.?;
                while (isSpace(zSql[0])) zSql += 1;
                break;
            }
        }

        sqlite3DbFree(db, @ptrCast(azCols));
        azCols = null;
    }

    return execOut(db, pStmt, azCols, rc, pzErrMsg, mutex);
}

/// The `exec_out:` label: finalize any leftover statement, build the error
/// message, run sqlite3ApiExit, and release the mutex.
fn execOut(
    db: ?*anyopaque,
    pStmt_in: ?*anyopaque,
    azCols: ?[*]?[*:0]u8,
    rc_in: c_int,
    pzErrMsg: ?*?[*:0]u8,
    mutex: ?*anyopaque,
) c_int {
    if (pStmt_in) |p| _ = sqlite3VdbeFinalize(p);
    sqlite3DbFree(db, @ptrCast(azCols));

    var rc = sqlite3ApiExit(db, rc_in);
    if (rc != SQLITE_OK and pzErrMsg != null) {
        pzErrMsg.?.* = sqlite3DbStrDup(null, sqlite3_errmsg(db));
        if (pzErrMsg.?.* == null) {
            rc = SQLITE_NOMEM; // SQLITE_NOMEM_BKPT
            sqlite3Error(db, SQLITE_NOMEM);
        }
    } else if (pzErrMsg) |q| {
        q.* = null;
    }

    if (config.sqlite_debug) {
        std.debug.assert((rc & dbErrMask(db)) == rc);
    }
    sqlite3_mutex_leave(mutex);
    return rc;
}
