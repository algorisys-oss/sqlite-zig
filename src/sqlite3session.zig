//! Zig port of SQLite's session extension (ext/session/sqlite3session.c).
//!
//! The session extension implements change-tracking and changeset/patchset
//! application on top of the SQLite preupdate hook. It owns:
//!   * sqlite3session_*    — record changes to a database (create/attach/diff/
//!     changeset/patchset/enable/indirect/isempty/...).
//!   * sqlite3changeset_*  — iterate, query, invert, concat and apply changesets.
//!   * sqlite3changegroup_* — accumulate/merge multiple changesets.
//!   * sqlite3rebaser_*    — rebase changesets after conflict resolution.
//!   * sqlite3session_config — global (streaming-chunk-size) configuration.
//!
//! ---------------------------------------------------------------------------
//! Config matrix
//! ---------------------------------------------------------------------------
//! This whole translation unit is gated by
//!   SQLITE_ENABLE_SESSION && SQLITE_ENABLE_PREUPDATE_HOOK
//! Both flags are ON in BOTH the production library and the --dev testfixture
//! in this build, so the entire module is always compiled. SQLITE_DEBUG only
//! affects asserts (which compile to nothing here).
//!
//! ---------------------------------------------------------------------------
//! Struct coupling
//! ---------------------------------------------------------------------------
//! Almost every struct used here (sqlite3_session, sqlite3_changeset_iter,
//! SessionTable, SessionChange, SessionBuffer, SessionInput, sqlite3_changegroup,
//! sqlite3_rebaser, ...) is PRIVATE to this file in C, so we reproduce them as
//! Zig `extern struct`s with the same field layout — no c_layout offsets needed
//! for those. The only external structs touched are sqlite3 (db->flags, db->aDb,
//! pSchema->schema_cookie) and Mem/sqlite3_value (pVal->z), accessed via the few
//! offsets pulled from c_layout. The heavy lifting (Mem set, value accessors,
//! varint codec, malloc) stays in already-linked C helpers.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ===========================================================================
// Opaque public handles
// ===========================================================================
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_value = anyopaque;

// ===========================================================================
// Result codes & datatype codes (sqlite3.h)
// ===========================================================================
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_ABORT: c_int = 4;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_SCHEMA: c_int = 17;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_MISUSE: c_int = 21;
const SQLITE_RANGE: c_int = 25;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;

// SQLITE_CORRUPT_BKPT — in C this is a macro that calls sqlite3CorruptError()
// with a line number. We inline it as plain SQLITE_CORRUPT (the line-number
// reporting is debug-only bookkeeping).
inline fn corruptBkpt() c_int {
    return SQLITE_CORRUPT;
}

// datatype codes (sqlite3.h)
const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;
const SQLITE_TEXT: c_int = 3;
const SQLITE_BLOB: c_int = 4;
const SQLITE_NULL: c_int = 5;

// changeset operation bytes / authorizer op codes (sqlite3.h)
//   SQLITE_DELETE=9 (0x09), SQLITE_INSERT=18 (0x12), SQLITE_UPDATE=23 (0x17)
const SQLITE_DELETE: c_int = 9;
const SQLITE_INSERT: c_int = 18;
const SQLITE_UPDATE: c_int = 23;

// text encoding (sqlite3.h)
const SQLITE_UTF8: u8 = 1;

// Destructor sentinels.
const SQLITE_STATIC: ?*const anyopaque = null;
inline fn sqliteTransient() ?*anyopaque {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
}
const SQLITE_TRANSIENT_INT: c_int = -1;

// db->flags bit (sqliteInt.h):  SQLITE_FkNoAction == HI(0x00008) == (u64)8<<32.
const SQLITE_FkNoAction: u64 = @as(u64, 0x00008) << 32;

// sqlite3_db_status verb (sqlite3.h)
const SQLITE_DBSTATUS_DEFERRED_FKS: c_int = 10;

// ---------------------------------------------------------------------------
// session.h public constants (verified against ext/session/sqlite3session.h)
// ---------------------------------------------------------------------------
const SQLITE_SESSION_OBJCONFIG_SIZE: c_int = 1;
const SQLITE_SESSION_OBJCONFIG_ROWID: c_int = 2;
const SQLITE_CHANGESETSTART_INVERT: c_int = 0x0002;
const SQLITE_CHANGESETAPPLY_NOSAVEPOINT: c_int = 0x0001;
const SQLITE_CHANGESETAPPLY_INVERT: c_int = 0x0002;
const SQLITE_CHANGESETAPPLY_IGNORENOOP: c_int = 0x0004;
const SQLITE_CHANGESETAPPLY_FKNOACTION: c_int = 0x0008;
const SQLITE_CHANGESETAPPLY_NOUPDATELOOP: c_int = 0x0010;

const SQLITE_CHANGESET_DATA: c_int = 1;
const SQLITE_CHANGESET_NOTFOUND: c_int = 2;
const SQLITE_CHANGESET_CONFLICT: c_int = 3;
const SQLITE_CHANGESET_CONSTRAINT: c_int = 4;
const SQLITE_CHANGESET_FOREIGN_KEY: c_int = 5;

const SQLITE_CHANGESET_OMIT: c_int = 0;
const SQLITE_CHANGESET_REPLACE: c_int = 1;
const SQLITE_CHANGESET_ABORT: c_int = 2;

const SQLITE_SESSION_CONFIG_STRMSIZE: c_int = 1;
const SQLITE_CHANGEGROUP_CONFIG_PATCHSET: c_int = 1;

// Streaming chunk default (non-SQLITE_TEST production value is 1024). The
// testfixture sets SQLITE_TEST → 64, but this constant is only the initial
// value of a mutable global, and the test harness overrides it via
// sqlite3session_config(). We keep the production default of 1024; the
// session3 test sets the size explicitly when it matters.
const SESSIONS_STRM_CHUNK_SIZE: c_int = if (config.sqlite_debug) 64 else 1024;

const SESSIONS_ROWID = "_rowid_";

const SESSION_MAX_BUFFER_SZ: i64 = 0x7FFFFF00 - 1;
const SESSION_UPDATE_CACHE_SZ: c_int = 12;

// mutable global
var sessions_strm_chunk_size: c_int = SESSIONS_STRM_CHUNK_SIZE;

// ===========================================================================
// Callback function pointer types
// ===========================================================================
const XInput = ?*const fn (?*anyopaque, ?*anyopaque, *c_int) callconv(.c) c_int;
const XOutput = ?*const fn (?*anyopaque, ?*const anyopaque, c_int) callconv(.c) c_int;
const XHookOldNew = ?*const fn (?*anyopaque, c_int, *?*sqlite3_value) callconv(.c) c_int;
const XHookCount = ?*const fn (?*anyopaque) callconv(.c) c_int;
const XTableFilter = ?*const fn (?*anyopaque, [*:0]const u8) callconv(.c) c_int;
const XFilter = ?*const fn (?*anyopaque, [*:0]const u8) callconv(.c) c_int;
const XFilterIter = ?*const fn (?*anyopaque, *sqlite3_changeset_iter) callconv(.c) c_int;
const XConflict = ?*const fn (?*anyopaque, c_int, *sqlite3_changeset_iter) callconv(.c) c_int;
const XValue = ?*const fn (*sqlite3_changeset_iter, c_int, *?*sqlite3_value) callconv(.c) c_int;

// ===========================================================================
// Private struct definitions (mirror the C layouts exactly)
// ===========================================================================
const SessionHook = extern struct {
    pCtx: ?*anyopaque = null,
    xOld: XHookOldNew = null,
    xNew: XHookOldNew = null,
    xCount: XHookCount = null,
    xDepth: XHookCount = null,
};

const sqlite3_session = extern struct {
    db: ?*sqlite3,
    zDb: ?[*:0]u8,
    bEnableSize: c_int,
    bEnable: c_int,
    bIndirect: c_int,
    bAutoAttach: c_int,
    bImplicitPK: c_int,
    rc: c_int,
    pFilterCtx: ?*anyopaque,
    xTableFilter: XTableFilter,
    nMalloc: i64,
    nMaxChangesetSize: i64,
    pZeroBlob: ?*sqlite3_value,
    pNext: ?*sqlite3_session,
    pTable: ?*SessionTable,
    hook: SessionHook,
};

const SessionBuffer = extern struct {
    aBuf: ?[*]u8 = null,
    nBuf: c_int = 0,
    nAlloc: c_int = 0,
};

const SessionInput = extern struct {
    bNoDiscard: c_int = 0,
    iCurrent: c_int = 0,
    iNext: c_int = 0,
    aData: ?[*]u8 = null,
    nData: c_int = 0,
    buf: SessionBuffer = .{},
    xInput: XInput = null,
    pIn: ?*anyopaque = null,
    bEof: c_int = 0,
};

const sqlite3_changeset_iter = extern struct {
    in: SessionInput,
    tblhdr: SessionBuffer,
    bPatchset: c_int,
    bInvert: c_int,
    bSkipEmpty: c_int,
    rc: c_int,
    pConflict: ?*sqlite3_stmt,
    zTab: ?[*:0]u8,
    nCol: c_int,
    op: c_int,
    bIndirect: c_int,
    abPK: ?[*]u8,
    apValue: ?[*]?*sqlite3_value,
};

const SessionTable = extern struct {
    pNext: ?*SessionTable,
    zName: ?[*:0]u8,
    nCol: c_int,
    nTotalCol: c_int,
    bStat1: c_int,
    bRowid: c_int,
    azCol: ?[*]?[*:0]const u8,
    azDflt: ?[*]?[*:0]const u8,
    aiIdx: ?[*]c_int,
    abPK: ?[*]u8,
    nEntry: c_int,
    nChange: c_int,
    apChange: ?[*]?*SessionChange,
    pDfltStmt: ?*sqlite3_stmt,
};

const SessionChange = extern struct {
    op: u8,
    bIndirect: u8,
    nRecordField: u16,
    nMaxSize: c_int,
    nRecord: c_int,
    aRecord: ?[*]u8,
    pNext: ?*SessionChange,
};

const SessionStat1Ctx = extern struct {
    hook: SessionHook,
    pSession: ?*sqlite3_session,
};

const SessionDiffCtx = extern struct {
    pStmt: ?*sqlite3_stmt,
    bRowid: c_int,
    nOldOff: c_int,
};

const SessionUpdate = extern struct {
    pStmt: ?*sqlite3_stmt,
    aMask: ?[*]u32,
    pNext: ?*SessionUpdate,
};

const SessionApplyCtx = extern struct {
    db: ?*sqlite3,
    pDelete: ?*sqlite3_stmt,
    pInsert: ?*sqlite3_stmt,
    pSelect: ?*sqlite3_stmt,
    nCol: c_int,
    azCol: ?[*]?[*:0]const u8,
    abPK: ?[*]u8,
    aUpdateMask: ?[*]u32,
    pUp: ?*SessionUpdate,
    bStat1: c_int,
    bDeferConstraints: c_int,
    bInvertConstraints: c_int,
    constraints: SessionBuffer,
    rebase: SessionBuffer,
    bRebaseStarted: u8,
    bRebase: u8,
    bIgnoreNoop: u8,
    bNoUpdateLoop: u8,
    bRowid: c_int,
    zErr: ?[*:0]u8,
};

const ChangeData = extern struct {
    pTab: ?*SessionTable,
    bIndirect: c_int,
    eOp: c_int,
    nBufAlloc: c_int,
    aBuf: ?[*]SessionBuffer,
    record: SessionBuffer,
};

const sqlite3_changegroup = extern struct {
    rc: c_int,
    bPatch: c_int,
    pList: ?*SessionTable,
    rec: SessionBuffer,
    db: ?*sqlite3,
    zDb: ?[*:0]u8,
    cd: ChangeData,
};

const sqlite3_rebaser = extern struct {
    grp: sqlite3_changegroup,
};

// ===========================================================================
// External C symbols (resolved at link time)
// ===========================================================================
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc(p: ?*anyopaque, n: c_int) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_msize(p: ?*anyopaque) u64;
extern fn sqlite3_mprintf(zFmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_vmprintf(zFmt: [*:0]const u8, ap: *anyopaque) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, z: [*]u8, zFmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;

extern fn sqlite3_db_mutex(db: ?*sqlite3) ?*anyopaque;
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;

extern fn sqlite3_prepare_v2(db: ?*sqlite3, zSql: [*]const u8, nByte: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_finalize(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_clear_bindings(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_exec(db: ?*sqlite3, zSql: [*:0]const u8, cb: ?*anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_errmsg(db: ?*sqlite3) ?[*:0]const u8;
extern fn sqlite3_errcode(db: ?*sqlite3) c_int;
extern fn sqlite3_set_errmsg(db: ?*sqlite3, errcode: c_int, zMsg: ?[*:0]const u8) c_int;
extern fn sqlite3_changes(db: ?*sqlite3) c_int;
extern fn sqlite3_db_status(db: ?*sqlite3, op: c_int, pCur: *c_int, pHiwtr: *c_int, resetFlg: c_int) c_int;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;
extern fn sqlite3_table_column_metadata(db: ?*sqlite3, zDbName: ?[*:0]const u8, zTableName: ?[*:0]const u8, zColumnName: ?[*:0]const u8, pzDataType: ?*?[*:0]const u8, pzCollSeq: ?*?[*:0]const u8, pNotNull: ?*c_int, pPrimaryKey: ?*c_int, pAutoinc: ?*c_int) c_int;

extern fn sqlite3_preupdate_hook(db: ?*sqlite3, xPreUpdate: ?*const anyopaque, pCtx: ?*anyopaque) ?*anyopaque;
extern fn sqlite3_preupdate_old(db: ?*sqlite3, iVal: c_int, ppVal: *?*sqlite3_value) c_int;
extern fn sqlite3_preupdate_new(db: ?*sqlite3, iVal: c_int, ppVal: *?*sqlite3_value) c_int;
extern fn sqlite3_preupdate_count(db: ?*sqlite3) c_int;
extern fn sqlite3_preupdate_depth(db: ?*sqlite3) c_int;
extern fn sqlite3_preupdate_blobwrite(db: ?*sqlite3) c_int;

extern fn sqlite3_value_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(p: ?*sqlite3_value) i64;
extern fn sqlite3_value_double(p: ?*sqlite3_value) f64;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*]const u8;
extern fn sqlite3_value_blob(p: ?*sqlite3_value) ?*const anyopaque;
extern fn sqlite3_value_bytes(p: ?*sqlite3_value) c_int;

extern fn sqlite3_column_type(p: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_int(p: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_int64(p: ?*sqlite3_stmt, i: c_int) i64;
extern fn sqlite3_column_double(p: ?*sqlite3_stmt, i: c_int) f64;
extern fn sqlite3_column_text(p: ?*sqlite3_stmt, i: c_int) ?[*]const u8;
extern fn sqlite3_column_blob(p: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_bytes(p: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_count(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_value(p: ?*sqlite3_stmt, i: c_int) ?*sqlite3_value;

extern fn sqlite3_bind_int(p: ?*sqlite3_stmt, i: c_int, v: c_int) c_int;
extern fn sqlite3_bind_int64(p: ?*sqlite3_stmt, i: c_int, v: i64) c_int;
extern fn sqlite3_bind_double(p: ?*sqlite3_stmt, i: c_int, v: f64) c_int;
extern fn sqlite3_bind_text(p: ?*sqlite3_stmt, i: c_int, z: ?[*]const u8, n: c_int, xDel: ?*const anyopaque) c_int;
extern fn sqlite3_bind_blob(p: ?*sqlite3_stmt, i: c_int, z: ?*const anyopaque, n: c_int, xDel: ?*const anyopaque) c_int;
extern fn sqlite3_bind_value(p: ?*sqlite3_stmt, i: c_int, v: ?*sqlite3_value) c_int;
extern fn sqlite3_bind_parameter_count(p: ?*sqlite3_stmt) c_int;

// SQLite-internal helpers (sqliteInt.h)
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3VarintLen(v: u64) c_int;
extern fn sqlite3PutVarint(p: [*]u8, v: u64) c_int;
extern fn sqlite3GetVarint32(p: [*]const u8, v: *u32) u8;
extern fn sqlite3ValueNew(db: ?*sqlite3) ?*sqlite3_value;
extern fn sqlite3ValueFree(v: ?*sqlite3_value) void;
extern fn sqlite3ValueSetStr(v: ?*sqlite3_value, n: c_int, z: ?*const anyopaque, enc: u8, xDel: ?*const anyopaque) void;
extern fn sqlite3VdbeMemSetInt64(v: ?*sqlite3_value, val: i64) void;
extern fn sqlite3VdbeMemSetDouble(v: ?*sqlite3_value, val: f64) void;

// ===========================================================================
// Small inline helpers
// ===========================================================================
const c = std.c; // for memcpy/memmove/memcmp/memset/strlen via libc

inline fn memcpy(dst: [*]u8, src: [*]const u8, n: usize) void {
    if (n > 0) @memcpy(dst[0..n], src[0..n]);
}
inline fn memmove(dst: [*]u8, src: [*]const u8, n: usize) void {
    if (n == 0) return;
    std.mem.copyBackwards(u8, dst[0..n], src[0..n]);
}
inline fn memset0(dst: [*]u8, n: usize) void {
    if (n > 0) @memset(dst[0..n], 0);
}
inline fn memcmpn(a: [*]const u8, b: [*]const u8, n: usize) c_int {
    if (n == 0) return 0;
    return switch (std.mem.order(u8, a[0..n], b[0..n])) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}
inline fn strlen0(z: [*:0]const u8) usize {
    return std.mem.len(z);
}

// putVarint32(A,B): single byte if B<0x80, else sqlite3PutVarint(A,(u64)B).
inline fn putVarint32(a: [*]u8, b: c_int) c_int {
    const ub: u32 = @bitCast(b);
    if (ub < 0x80) {
        a[0] = @intCast(ub);
        return 1;
    }
    return sqlite3PutVarint(a, ub);
}
// getVarint32(A,B): single byte if *A<0x80, else sqlite3GetVarint32(A,&B).
inline fn getVarint32(a: [*]const u8, b: *c_int) c_int {
    if (a[0] < 0x80) {
        b.* = @intCast(a[0]);
        return 1;
    }
    var u: u32 = 0;
    const n = sqlite3GetVarint32(a, &u);
    b.* = @bitCast(u);
    return n;
}

// ===========================================================================
// Varint / integer (de)serialization
// ===========================================================================
fn sessionVarintPut(aBuf: [*]u8, iVal: c_int) c_int {
    return putVarint32(aBuf, iVal);
}
fn sessionVarintLen(iVal: c_int) c_int {
    return sqlite3VarintLen(@as(u64, @intCast(@as(u32, @bitCast(iVal)))));
}
fn sessionVarintGet(aBuf: [*]const u8, piVal: *c_int) c_int {
    const ret = getVarint32(aBuf, piVal);
    piVal.* = piVal.* & 0x7FFFFFFF;
    return ret;
}
fn sessionVarintGetSafe(aBuf: [*]const u8, nBuf: c_int, piVal: *c_int) c_int {
    var aCopy: [9]u8 = undefined;
    @memset(&aCopy, 0);
    var aRead: [*]const u8 = aBuf;
    if (nBuf < @as(c_int, 9)) {
        if (nBuf > 0) memcpy(&aCopy, aBuf, @intCast(nBuf));
        aRead = &aCopy;
    }
    return sessionVarintGet(aRead, piVal);
}

inline fn sessionUint32(x: [*]const u8) u32 {
    return (@as(u32, x[0]) << 24) | (@as(u32, x[1]) << 16) | (@as(u32, x[2]) << 8) | @as(u32, x[3]);
}
fn sessionGetI64(aRec: [*]const u8) i64 {
    var x: u64 = sessionUint32(aRec);
    const y: u64 = sessionUint32(aRec + 4);
    x = (x << 32) + y;
    return @bitCast(x);
}
fn sessionPutI64(aBuf: [*]u8, i: i64) void {
    const u: u64 = @bitCast(i);
    aBuf[0] = @truncate(u >> 56);
    aBuf[1] = @truncate(u >> 48);
    aBuf[2] = @truncate(u >> 40);
    aBuf[3] = @truncate(u >> 32);
    aBuf[4] = @truncate(u >> 24);
    aBuf[5] = @truncate(u >> 16);
    aBuf[6] = @truncate(u >> 8);
    aBuf[7] = @truncate(u >> 0);
}
fn sessionPutDouble(aBuf: [*]u8, r: f64) void {
    const i: u64 = @bitCast(r);
    sessionPutI64(aBuf, @bitCast(i));
}

// ===========================================================================
// Value serialization (RECORD FORMAT)
// ===========================================================================
fn sessionSerializeValue(aBuf: ?[*]u8, pValue: ?*sqlite3_value, pnWrite: ?*i64) c_int {
    var nByte: c_int = undefined;

    if (pValue) |pv| {
        const eType = sqlite3_value_type(pv);
        if (aBuf) |b| b[0] = @intCast(eType);

        switch (eType) {
            SQLITE_NULL => {
                nByte = 1;
            },
            SQLITE_INTEGER, SQLITE_FLOAT => {
                if (aBuf) |b| {
                    if (eType == SQLITE_INTEGER) {
                        const i: u64 = @bitCast(sqlite3_value_int64(pv));
                        sessionPutI64(b + 1, @bitCast(i));
                    } else {
                        const r = sqlite3_value_double(pv);
                        sessionPutDouble(b + 1, r);
                    }
                }
                nByte = 9;
            },
            else => {
                var z: ?[*]const u8 = undefined;
                if (eType == SQLITE_TEXT) {
                    z = sqlite3_value_text(pv);
                } else {
                    z = @ptrCast(sqlite3_value_blob(pv));
                }
                const n = sqlite3_value_bytes(pv);
                if (z == null and (eType != SQLITE_BLOB or n > 0)) return SQLITE_NOMEM;
                const nVarint = sessionVarintLen(n);
                if (aBuf) |b| {
                    _ = sessionVarintPut(b + 1, n);
                    if (n > 0) memcpy(b + @as(usize, @intCast(nVarint + 1)), z.?, @intCast(n));
                }
                nByte = 1 + nVarint + n;
            },
        }
    } else {
        nByte = 1;
        if (aBuf) |b| b[0] = 0;
    }

    if (pnWrite) |pw| pw.* += nByte;
    return SQLITE_OK;
}

// ===========================================================================
// Memory accounting wrappers
// ===========================================================================
fn sessionMalloc64(pSession: ?*sqlite3_session, nByte: i64) ?*anyopaque {
    const pRet = sqlite3_malloc64(@intCast(nByte));
    if (pSession) |ps| ps.nMalloc += @intCast(sqlite3_msize(pRet));
    return pRet;
}
fn sessionFree(pSession: ?*sqlite3_session, pFree: ?*anyopaque) void {
    if (pSession) |ps| ps.nMalloc -= @intCast(sqlite3_msize(pFree));
    sqlite3_free(pFree);
}

// ===========================================================================
// Hashing
// ===========================================================================
inline fn hashAppend(hash: u32, add: u32) u32 {
    return (hash << 3) ^ hash ^ add;
}
fn sessionHashAppendI64(h0: u32, i: i64) u32 {
    const u: u64 = @bitCast(i);
    var h = hashAppend(h0, @truncate(u & 0xFFFFFFFF));
    h = hashAppend(h, @truncate((u >> 32) & 0xFFFFFFFF));
    return h;
}
fn sessionHashAppendBlob(h0: u32, n: c_int, z: [*]const u8) u32 {
    var h = h0;
    var i: c_int = 0;
    while (i < n) : (i += 1) h = hashAppend(h, z[@intCast(i)]);
    return h;
}
fn sessionHashAppendType(h: u32, eType: c_int) u32 {
    return hashAppend(h, @bitCast(eType));
}

fn sessionPreupdateHash(
    pSession: *sqlite3_session,
    iRowid: i64,
    pTab: *SessionTable,
    bNew: c_int,
    piHash: *c_int,
    pbNullPK: *c_int,
) c_int {
    var h: u32 = 0;
    if (pTab.bRowid != 0) {
        h = sessionHashAppendI64(h, iRowid);
    } else {
        var i: c_int = 0;
        while (i < pTab.nCol) : (i += 1) {
            if (pTab.abPK.?[@intCast(i)] != 0) {
                var pVal: ?*sqlite3_value = null;
                const iIdx = pTab.aiIdx.?[@intCast(i)];
                const rc = if (bNew != 0)
                    pSession.hook.xNew.?(pSession.hook.pCtx, iIdx, &pVal)
                else
                    pSession.hook.xOld.?(pSession.hook.pCtx, iIdx, &pVal);
                if (rc != SQLITE_OK) return rc;

                const eType = sqlite3_value_type(pVal);
                h = sessionHashAppendType(h, eType);
                if (eType == SQLITE_INTEGER or eType == SQLITE_FLOAT) {
                    var iVal: i64 = undefined;
                    if (eType == SQLITE_INTEGER) {
                        iVal = sqlite3_value_int64(pVal);
                    } else {
                        const rVal = sqlite3_value_double(pVal);
                        iVal = @bitCast(rVal);
                    }
                    h = sessionHashAppendI64(h, iVal);
                } else if (eType == SQLITE_TEXT or eType == SQLITE_BLOB) {
                    var z: ?[*]const u8 = undefined;
                    if (eType == SQLITE_TEXT) {
                        z = sqlite3_value_text(pVal);
                    } else {
                        z = @ptrCast(sqlite3_value_blob(pVal));
                    }
                    const n = sqlite3_value_bytes(pVal);
                    if (z == null and (eType != SQLITE_BLOB or n > 0)) return SQLITE_NOMEM;
                    h = sessionHashAppendBlob(h, n, if (n > 0) z.? else (&[_]u8{}).ptr);
                } else {
                    pbNullPK.* = 1;
                }
            }
        }
    }
    piHash.* = @intCast(@mod(h, @as(u32, @bitCast(pTab.nChange))));
    return SQLITE_OK;
}

fn sessionSerialLen(a: [*]const u8) c_int {
    const e = a[0];
    if (e == SQLITE_INTEGER or e == SQLITE_FLOAT) return 9;
    if (e == SQLITE_TEXT or e == SQLITE_BLOB) {
        var n: c_int = undefined;
        return sessionVarintGet(a + 1, &n) + 1 + n;
    }
    return 1;
}

fn sessionChangeHash(pTab: *SessionTable, bPkOnly: c_int, aRecord: [*]u8, nBucket: c_int) u32 {
    var h: u32 = 0;
    var a: [*]u8 = aRecord;
    var i: c_int = 0;
    while (i < pTab.nCol) : (i += 1) {
        const isPK = pTab.abPK.?[@intCast(i)];
        if (bPkOnly != 0 and isPK == 0) continue;
        if (isPK != 0) {
            const eType = a[0];
            a += 1;
            h = sessionHashAppendType(h, eType);
            if (eType == SQLITE_INTEGER or eType == SQLITE_FLOAT) {
                h = sessionHashAppendI64(h, sessionGetI64(a));
                a += 8;
            } else if (eType == SQLITE_TEXT or eType == SQLITE_BLOB) {
                var n: c_int = undefined;
                a += @intCast(sessionVarintGet(a, &n));
                h = sessionHashAppendBlob(h, n, a);
                a += @intCast(n);
            }
        } else {
            a += @intCast(sessionSerialLen(a));
        }
    }
    return @mod(h, @as(u32, @bitCast(nBucket)));
}

fn sessionChangeEqual(pTab: *SessionTable, bLeftPkOnly: c_int, aLeft: [*]u8, bRightPkOnly: c_int, aRight: [*]u8) c_int {
    var a1: [*]u8 = aLeft;
    var a2: [*]u8 = aRight;
    var iCol: c_int = 0;
    while (iCol < pTab.nCol) : (iCol += 1) {
        if (pTab.abPK.?[@intCast(iCol)] != 0) {
            const n1 = sessionSerialLen(a1);
            const n2 = sessionSerialLen(a2);
            if (n1 != n2 or memcmpn(a1, a2, @intCast(n1)) != 0) {
                return 0;
            }
            a1 += @intCast(n1);
            a2 += @intCast(n2);
        } else {
            if (bLeftPkOnly == 0) a1 += @intCast(sessionSerialLen(a1));
            if (bRightPkOnly == 0) a2 += @intCast(sessionSerialLen(a2));
        }
    }
    return 1;
}

fn sessionMergeRecord(paOut: *[*]u8, nCol: c_int, aLeft: [*]u8, aRight: [*]u8) void {
    var a1: [*]u8 = aLeft;
    var a2: [*]u8 = aRight;
    var aOut: [*]u8 = paOut.*;
    var iCol: c_int = 0;
    while (iCol < nCol) : (iCol += 1) {
        const n1 = sessionSerialLen(a1);
        const n2 = sessionSerialLen(a2);
        if (a2[0] != 0) {
            memcpy(aOut, a2, @intCast(n2));
            aOut += @intCast(n2);
        } else {
            memcpy(aOut, a1, @intCast(n1));
            aOut += @intCast(n1);
        }
        a1 += @intCast(n1);
        a2 += @intCast(n2);
    }
    paOut.* = aOut;
}

fn sessionMergeValue(paOne: *[*]u8, paTwo: *?[*]u8, pnVal: *c_int) [*]u8 {
    const a1: [*]u8 = paOne.*;
    const a2o = paTwo.*;
    var pRet: ?[*]u8 = null;
    if (a2o) |a2| {
        const n2 = sessionSerialLen(a2);
        if (a2[0] != 0) {
            pnVal.* = n2;
            pRet = a2;
        }
        paTwo.* = a2 + @as(usize, @intCast(n2));
    }
    const n1 = sessionSerialLen(a1);
    if (pRet == null) {
        pnVal.* = n1;
        pRet = a1;
    }
    paOne.* = a1 + @as(usize, @intCast(n1));
    return pRet.?;
}

fn sessionMergeUpdate(
    paOut: *[*]u8,
    pTab: *SessionTable,
    bPatchset: c_int,
    aOldRecord1: [*]u8,
    aOldRecord2: ?[*]u8,
    aNewRecord1: [*]u8,
    aNewRecord2: ?[*]u8,
) c_int {
    var aOld1: [*]u8 = aOldRecord1;
    var aOld2: ?[*]u8 = aOldRecord2;
    var aNew1: [*]u8 = aNewRecord1;
    var aNew2: ?[*]u8 = aNewRecord2;
    var aOut: [*]u8 = paOut.*;
    var i: c_int = 0;

    if (bPatchset == 0) {
        var bRequired: c_int = 0;
        i = 0;
        while (i < pTab.nCol) : (i += 1) {
            var nOld: c_int = undefined;
            var nNew: c_int = undefined;
            const aOld = sessionMergeValue(&aOld1, &aOld2, &nOld);
            const aNew = sessionMergeValue(&aNew1, &aNew2, &nNew);
            if (pTab.abPK.?[@intCast(i)] != 0 or nOld != nNew or memcmpn(aOld, aNew, @intCast(nNew)) != 0) {
                if (pTab.abPK.?[@intCast(i)] == 0) bRequired = 1;
                memcpy(aOut, aOld, @intCast(nOld));
                aOut += @intCast(nOld);
            } else {
                aOut[0] = 0;
                aOut += 1;
            }
        }
        if (bRequired == 0) return 0;
    }

    aOld1 = aOldRecord1;
    aOld2 = aOldRecord2;
    aNew1 = aNewRecord1;
    aNew2 = aNewRecord2;
    i = 0;
    while (i < pTab.nCol) : (i += 1) {
        var nOld: c_int = undefined;
        var nNew: c_int = undefined;
        const aOld = sessionMergeValue(&aOld1, &aOld2, &nOld);
        const aNew = sessionMergeValue(&aNew1, &aNew2, &nNew);
        if (bPatchset == 0 and (pTab.abPK.?[@intCast(i)] != 0 or (nOld == nNew and memcmpn(aOld, aNew, @intCast(nNew)) == 0))) {
            aOut[0] = 0;
            aOut += 1;
        } else {
            memcpy(aOut, aNew, @intCast(nNew));
            aOut += @intCast(nNew);
        }
    }
    paOut.* = aOut;
    return 1;
}

fn sessionPreupdateEqual(
    pSession: *sqlite3_session,
    iRowid: i64,
    pTab: *SessionTable,
    pChange: *SessionChange,
    op: c_int,
) c_int {
    var a: [*]u8 = pChange.aRecord.?;
    if (pTab.bRowid != 0) {
        if (a[0] != SQLITE_INTEGER) return 0;
        return @intFromBool(sessionGetI64(a + 1) == iRowid);
    }
    var iCol: c_int = 0;
    while (iCol < pTab.nCol) : (iCol += 1) {
        if (pTab.abPK.?[@intCast(iCol)] == 0) {
            a += @intCast(sessionSerialLen(a));
        } else {
            var pVal: ?*sqlite3_value = null;
            const eType: c_int = a[0];
            a += 1;
            const iIdx = pTab.aiIdx.?[@intCast(iCol)];
            if (op == SQLITE_INSERT) {
                _ = pSession.hook.xNew.?(pSession.hook.pCtx, iIdx, &pVal);
            } else {
                _ = pSession.hook.xOld.?(pSession.hook.pCtx, iIdx, &pVal);
            }
            if (sqlite3_value_type(pVal) != eType) return 0;

            if (eType == SQLITE_INTEGER or eType == SQLITE_FLOAT) {
                const iVal = sessionGetI64(a);
                a += 8;
                if (eType == SQLITE_INTEGER) {
                    if (sqlite3_value_int64(pVal) != iVal) return 0;
                } else {
                    const rVal: f64 = @bitCast(iVal);
                    if (sqlite3_value_double(pVal) != rVal) return 0;
                }
            } else {
                var n: c_int = undefined;
                a += @intCast(sessionVarintGet(a, &n));
                if (sqlite3_value_bytes(pVal) != n) return 0;
                var z: ?[*]const u8 = undefined;
                if (eType == SQLITE_TEXT) {
                    z = sqlite3_value_text(pVal);
                } else {
                    z = @ptrCast(sqlite3_value_blob(pVal));
                }
                if (n > 0 and memcmpn(a, z.?, @intCast(n)) != 0) return 0;
                a += @intCast(n);
            }
        }
    }
    return 1;
}

fn sessionGrowHash(pSession: ?*sqlite3_session, bPatchset: c_int, pTab: *SessionTable) c_int {
    if (pTab.nChange == 0 or pTab.nEntry >= @divTrunc(pTab.nChange, 2)) {
        const nNew: i64 = 2 * @as(i64, if (pTab.nChange != 0) pTab.nChange else 128);
        const apNew: ?[*]?*SessionChange = @ptrCast(@alignCast(sessionMalloc64(pSession, @sizeOf(?*SessionChange) * nNew)));
        if (apNew == null) {
            if (pTab.nChange == 0) return SQLITE_ERROR;
            return SQLITE_OK;
        }
        memset0(@ptrCast(apNew.?), @intCast(@as(i64, @sizeOf(?*SessionChange)) * nNew));

        var i: c_int = 0;
        while (i < pTab.nChange) : (i += 1) {
            var p: ?*SessionChange = pTab.apChange.?[@intCast(i)];
            while (p) |pc| {
                const bPkOnly: c_int = @intFromBool(pc.op == SQLITE_DELETE and bPatchset != 0);
                const iHash = sessionChangeHash(pTab, bPkOnly, pc.aRecord.?, @intCast(nNew));
                const pNext = pc.pNext;
                pc.pNext = apNew.?[iHash];
                apNew.?[iHash] = pc;
                p = pNext;
            }
        }

        sessionFree(pSession, @ptrCast(pTab.apChange));
        pTab.nChange = @intCast(nNew);
        pTab.apChange = apNew;
    }
    return SQLITE_OK;
}

fn sessionTableInfo(
    pSession: ?*sqlite3_session,
    db: ?*sqlite3,
    zDb: [*:0]const u8,
    zThis: [*:0]const u8,
    pnCol: *c_int,
    pnTotalCol: ?*c_int,
    pzTab: ?*?[*:0]const u8,
    pazCol: *?[*]?[*:0]const u8,
    pazDflt: ?*?[*]?[*:0]const u8,
    paiIdx: ?*?[*]c_int,
    pabPK: *?[*]u8,
    pbRowid: ?*c_int,
) c_int {
    var zPragma: ?[*:0]u8 = null;
    var pStmt: ?*sqlite3_stmt = null;
    var rc: c_int = undefined;
    var nByte: i64 = undefined;
    var nDbCol: c_int = 0;
    var i: c_int = undefined;
    var azCol: ?[*]?[*:0]const u8 = null;
    var azDflt: ?[*]?[*:0]const u8 = null;
    var abPK: ?[*]u8 = null;
    var aiIdx: ?[*]c_int = null;
    var bRowid: c_int = 0;

    pazCol.* = null;
    pabPK.* = null;
    pnCol.* = 0;
    if (pnTotalCol) |p| p.* = 0;
    if (paiIdx) |p| p.* = null;
    if (pzTab) |p| p.* = null;
    if (pazDflt) |p| p.* = null;

    const nThis = sqlite3Strlen30(zThis);
    if (nThis == 12 and sqlite3_stricmp("sqlite_stat1", zThis) == 0) {
        rc = sqlite3_table_column_metadata(db, zDb, zThis, null, null, null, null, null, null);
        if (rc == SQLITE_OK) {
            zPragma = sqlite3_mprintf(
                "SELECT 0, 'tbl',  '', 0, '', 1, 0     UNION ALL " ++
                    "SELECT 1, 'idx',  '', 0, '', 2, 0     UNION ALL " ++
                    "SELECT 2, 'stat', '', 0, '', 0, 0",
            );
        } else if (rc == SQLITE_ERROR) {
            zPragma = sqlite3_mprintf("");
        } else {
            return rc;
        }
    } else {
        zPragma = sqlite3_mprintf("PRAGMA '%q'.table_xinfo('%q')", zDb, zThis);
    }
    if (zPragma == null) return SQLITE_NOMEM;

    rc = sqlite3_prepare_v2(db, zPragma.?, -1, &pStmt, null);
    sqlite3_free(zPragma);
    if (rc != SQLITE_OK) return rc;

    nByte = nThis + 1;
    bRowid = @intFromBool(pbRowid != null);
    while (SQLITE_ROW == sqlite3_step(pStmt)) {
        nByte += sqlite3_column_bytes(pStmt, 1); // name
        nByte += sqlite3_column_bytes(pStmt, 4); // dflt_value
        if (sqlite3_column_int(pStmt, 6) == 0) nDbCol += 1; // !hidden
        if (sqlite3_column_int(pStmt, 5) != 0) bRowid = 0; // pk
    }
    if (nDbCol == 0) bRowid = 0;
    nDbCol += bRowid;
    nByte += @intCast(SESSIONS_ROWID.len);
    rc = sqlite3_reset(pStmt);

    var pAlloc: ?[*]u8 = null;
    if (rc == SQLITE_OK) {
        nByte += @as(i64, nDbCol) * (@sizeOf(?*anyopaque) * 2 + @sizeOf(c_int) + @sizeOf(u8) + 1 + 1);
        pAlloc = @ptrCast(sessionMalloc64(pSession, nByte));
        if (pAlloc == null) {
            rc = SQLITE_NOMEM;
        } else {
            memset0(pAlloc.?, @intCast(nByte));
        }
    }
    if (rc == SQLITE_OK) {
        azCol = @ptrCast(@alignCast(pAlloc.?));
        azDflt = @ptrCast(@alignCast(azCol.? + @as(usize, @intCast(nDbCol))));
        aiIdx = @ptrCast(@alignCast(azDflt.? + @as(usize, @intCast(nDbCol))));
        abPK = @ptrCast(aiIdx.? + @as(usize, @intCast(nDbCol)));
        pAlloc = abPK.? + @as(usize, @intCast(nDbCol));
        if (pzTab) |pt| {
            memcpy(pAlloc.?, zThis, @intCast(nThis + 1));
            pt.* = @ptrCast(pAlloc.?);
            pAlloc = pAlloc.? + @as(usize, @intCast(nThis + 1));
        }

        i = 0;
        if (bRowid != 0) {
            const nName = SESSIONS_ROWID.len;
            memcpy(pAlloc.?, SESSIONS_ROWID, nName + 1);
            azCol.?[@intCast(i)] = @ptrCast(pAlloc.?);
            pAlloc = pAlloc.? + nName + 1;
            abPK.?[@intCast(i)] = 1;
            aiIdx.?[@intCast(i)] = -1;
            i += 1;
        }
        while (SQLITE_ROW == sqlite3_step(pStmt)) {
            if (sqlite3_column_int(pStmt, 6) == 0) { // !hidden
                const nName = sqlite3_column_bytes(pStmt, 1);
                const nDflt = sqlite3_column_bytes(pStmt, 4);
                const zName = sqlite3_column_text(pStmt, 1);
                const zDflt = sqlite3_column_text(pStmt, 4);
                if (zName == null) break;
                memcpy(pAlloc.?, zName.?, @intCast(nName + 1));
                azCol.?[@intCast(i)] = @ptrCast(pAlloc.?);
                pAlloc = pAlloc.? + @as(usize, @intCast(nName + 1));
                if (zDflt) |zd| {
                    memcpy(pAlloc.?, zd, @intCast(nDflt + 1));
                    azDflt.?[@intCast(i)] = @ptrCast(pAlloc.?);
                    pAlloc = pAlloc.? + @as(usize, @intCast(nDflt + 1));
                } else {
                    azDflt.?[@intCast(i)] = null;
                }
                abPK.?[@intCast(i)] = @intCast(sqlite3_column_int(pStmt, 5));
                aiIdx.?[@intCast(i)] = sqlite3_column_int(pStmt, 0);
                i += 1;
            }
            if (pnTotalCol) |p| p.* += 1;
        }
        rc = sqlite3_reset(pStmt);
    }

    if (rc == SQLITE_OK) {
        pazCol.* = azCol;
        if (pazDflt) |p| p.* = azDflt;
        pabPK.* = abPK;
        pnCol.* = nDbCol;
        if (paiIdx) |p| p.* = aiIdx;
    } else {
        sessionFree(pSession, @ptrCast(azCol));
    }
    if (pbRowid) |p| p.* = bRowid;
    _ = sqlite3_finalize(pStmt);
    return rc;
}

fn sessionInitTable(pSession: ?*sqlite3_session, pTab: *SessionTable, db: ?*sqlite3, zDb: [*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    if (pTab.nCol == 0) {
        var abPK: ?[*]u8 = null;
        sqlite3_free(@ptrCast(pTab.azCol));
        pTab.abPK = null;
        rc = sessionTableInfo(pSession, db, zDb, pTab.zName.?, &pTab.nCol, &pTab.nTotalCol, null, &pTab.azCol, &pTab.azDflt, &pTab.aiIdx, &abPK, if (pSession == null or pSession.?.bImplicitPK != 0) &pTab.bRowid else null);
        if (rc == SQLITE_OK) {
            var i: c_int = 0;
            while (i < pTab.nCol) : (i += 1) {
                if (abPK.?[@intCast(i)] != 0) {
                    pTab.abPK = abPK;
                    break;
                }
            }
            if (sqlite3_stricmp("sqlite_stat1", pTab.zName.?) == 0) pTab.bStat1 = 1;
            if (pSession) |ps| {
                if (ps.bEnableSize != 0) {
                    ps.nMaxChangesetSize += (1 + sessionVarintLen(pTab.nCol) + pTab.nCol + @as(c_int, @intCast(strlen0(pTab.zName.?))) + 1);
                }
            }
        }
    }
    if (pSession) |ps| {
        ps.rc = rc;
        return @intFromBool(rc != 0 or pTab.abPK == null);
    }
    return rc;
}

fn sessionReinitTable(pSession: *sqlite3_session, pTab: *SessionTable) c_int {
    var nCol: c_int = 0;
    var nTotalCol: c_int = 0;
    var azCol: ?[*]?[*:0]const u8 = null;
    var azDflt: ?[*]?[*:0]const u8 = null;
    var aiIdx: ?[*]c_int = null;
    var abPK: ?[*]u8 = null;
    var bRowid: c_int = 0;

    pSession.rc = sessionTableInfo(pSession, pSession.db, pSession.zDb.?, pTab.zName.?, &nCol, &nTotalCol, null, &azCol, &azDflt, &aiIdx, &abPK, if (pSession.bImplicitPK != 0) &bRowid else null);
    if (pSession.rc == SQLITE_OK) {
        if (pTab.nCol > nCol or pTab.bRowid != bRowid) {
            pSession.rc = SQLITE_SCHEMA;
        } else {
            var ii: c_int = 0;
            const nOldCol = pTab.nCol;
            while (ii < nCol) : (ii += 1) {
                if (ii < pTab.nCol) {
                    if (pTab.abPK.?[@intCast(ii)] != abPK.?[@intCast(ii)]) pSession.rc = SQLITE_SCHEMA;
                } else if (abPK.?[@intCast(ii)] != 0) {
                    pSession.rc = SQLITE_SCHEMA;
                }
            }
            if (pSession.rc == SQLITE_OK) {
                const a = pTab.azCol;
                pTab.azCol = azCol;
                pTab.nCol = nCol;
                pTab.nTotalCol = nTotalCol;
                pTab.azDflt = azDflt;
                pTab.abPK = abPK;
                pTab.aiIdx = aiIdx;
                azCol = a;
            }
            if (pSession.bEnableSize != 0) {
                pSession.nMaxChangesetSize += (nCol - nOldCol);
                pSession.nMaxChangesetSize += sessionVarintLen(nCol);
                pSession.nMaxChangesetSize -= sessionVarintLen(nOldCol);
            }
        }
    }
    sqlite3_free(@ptrCast(azCol));
    return pSession.rc;
}

// ===========================================================================
// SessionBuffer growth & append helpers
// ===========================================================================
fn sessionBufferGrow(p: *SessionBuffer, nByte: i64, pRc: *c_int) c_int {
    const nReq: i64 = p.nBuf + nByte;
    if (pRc.* == SQLITE_OK and nReq > p.nAlloc) {
        var nNew: i64 = if (p.nAlloc != 0) p.nAlloc else 128;
        while (nNew < nReq) nNew = nNew * 2;
        if (nNew > SESSION_MAX_BUFFER_SZ) {
            nNew = SESSION_MAX_BUFFER_SZ;
            if (nNew < nReq) {
                pRc.* = SQLITE_NOMEM;
                return 1;
            }
        }
        const aNew: ?[*]u8 = @ptrCast(sqlite3_realloc64(@ptrCast(p.aBuf), @intCast(nNew)));
        if (aNew == null) {
            pRc.* = SQLITE_NOMEM;
        } else {
            p.aBuf = aNew;
            p.nAlloc = @intCast(nNew);
        }
    }
    return @intFromBool(pRc.* != SQLITE_OK);
}

fn sessionAppendStr(p: *SessionBuffer, zStr: [*:0]const u8, pRc: *c_int) void {
    const nStr = sqlite3Strlen30(zStr);
    if (0 == sessionBufferGrow(p, nStr + 1, pRc)) {
        memcpy(p.aBuf.? + @as(usize, @intCast(p.nBuf)), zStr, @intCast(nStr));
        p.nBuf += nStr;
        p.aBuf.?[@intCast(p.nBuf)] = 0;
    }
}

fn sessionAppendPrintf(p: *SessionBuffer, pRc: *c_int, zFmt: [*:0]const u8, args: anytype) void {
    if (pRc.* == SQLITE_OK) {
        const zApp = @call(.auto, sqlite3_mprintf, .{zFmt} ++ args);
        if (zApp == null) {
            pRc.* = SQLITE_NOMEM;
        } else {
            sessionAppendStr(p, zApp.?, pRc);
        }
        sqlite3_free(zApp);
    }
}

fn sessionPrepareDfltStmt(db: ?*sqlite3, pTab: *SessionTable, ppStmt: *?*sqlite3_stmt) c_int {
    var sql: SessionBuffer = .{};
    var rc: c_int = SQLITE_OK;
    var zSep: [*:0]const u8 = " ";
    var ii: c_int = 0;

    ppStmt.* = null;
    sessionAppendPrintf(&sql, &rc, "SELECT", .{});
    while (ii < pTab.nCol) : (ii += 1) {
        const zDflt: [*:0]const u8 = if (pTab.azDflt.?[@intCast(ii)]) |z| z else "NULL";
        sessionAppendPrintf(&sql, &rc, "%s%s", .{ zSep, zDflt });
        zSep = ", ";
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_prepare_v2(db, sql.aBuf.?, -1, ppStmt, null);
    }
    sqlite3_free(@ptrCast(sql.aBuf));
    return rc;
}

fn sessionFinalizeStmt(pStmt: ?*sqlite3_stmt, pRc: *c_int) void {
    const rc = sqlite3_finalize(pStmt);
    if (pRc.* == SQLITE_OK) pRc.* = rc;
}

fn sessionUpdateOneChange(pSession: ?*sqlite3_session, pRc: *c_int, pp: *?*SessionChange, nCol: c_int, pDflt: ?*sqlite3_stmt) void {
    var pOld: *SessionChange = pp.*.?;
    while (pOld.nRecordField < nCol) {
        var nByte: i64 = 0;
        var nIncr: c_int = 0;
        const iField: c_int = pOld.nRecordField;
        const eType = sqlite3_column_type(pDflt, iField);
        switch (eType) {
            SQLITE_NULL => nIncr = 1,
            SQLITE_INTEGER, SQLITE_FLOAT => nIncr = 9,
            else => {
                const n = sqlite3_column_bytes(pDflt, iField);
                nIncr = 1 + sessionVarintLen(n) + n;
            },
        }

        nByte = nIncr + (@as(i64, @sizeOf(SessionChange)) + pOld.nRecord);
        const pNew: ?*SessionChange = @ptrCast(@alignCast(sessionMalloc64(pSession, nByte)));
        if (pNew == null) {
            pRc.* = SQLITE_NOMEM;
            return;
        }
        const pn = pNew.?;
        @as([*]u8, @ptrCast(pn))[0..@sizeOf(SessionChange)].* = @as([*]const u8, @ptrCast(pOld))[0..@sizeOf(SessionChange)].*;
        pn.aRecord = @ptrCast(@as([*]SessionChange, @ptrCast(pn)) + 1);
        memcpy(pn.aRecord.?, pOld.aRecord.?, @intCast(pOld.nRecord));
        pn.aRecord.?[@intCast(pn.nRecord)] = @intCast(eType);
        pn.nRecord += 1;
        switch (eType) {
            SQLITE_INTEGER => {
                const iVal = sqlite3_column_int64(pDflt, iField);
                sessionPutI64(pn.aRecord.? + @as(usize, @intCast(pn.nRecord)), iVal);
                pn.nRecord += 8;
            },
            SQLITE_FLOAT => {
                const rVal = sqlite3_column_double(pDflt, iField);
                sessionPutDouble(pn.aRecord.? + @as(usize, @intCast(pn.nRecord)), rVal);
                pn.nRecord += 8;
            },
            SQLITE_TEXT => {
                const n = sqlite3_column_bytes(pDflt, iField);
                const z = sqlite3_column_text(pDflt, iField);
                pn.nRecord += sessionVarintPut(pn.aRecord.? + @as(usize, @intCast(pn.nRecord)), n);
                memcpy(pn.aRecord.? + @as(usize, @intCast(pn.nRecord)), z.?, @intCast(n));
                pn.nRecord += n;
            },
            SQLITE_BLOB => {
                const n = sqlite3_column_bytes(pDflt, iField);
                const z: ?[*]const u8 = @ptrCast(sqlite3_column_blob(pDflt, iField));
                pn.nRecord += sessionVarintPut(pn.aRecord.? + @as(usize, @intCast(pn.nRecord)), n);
                memcpy(pn.aRecord.? + @as(usize, @intCast(pn.nRecord)), z.?, @intCast(n));
                pn.nRecord += n;
            },
            else => {},
        }

        sessionFree(pSession, pOld);
        pp.* = pn;
        pOld = pn;
        pn.nRecordField += 1;
        pn.nMaxSize += nIncr;
        if (pSession) |ps| ps.nMaxChangesetSize += nIncr;
    }
}

fn sessionUpdateChanges(pSession: *sqlite3_session, pTab: *SessionTable) c_int {
    var pStmt: ?*sqlite3_stmt = null;
    var rc: c_int = pSession.rc;

    rc = sessionPrepareDfltStmt(pSession.db, pTab, &pStmt);
    if (rc == SQLITE_OK and SQLITE_ROW == sqlite3_step(pStmt)) {
        var ii: c_int = 0;
        while (ii < pTab.nChange) : (ii += 1) {
            var pp: *?*SessionChange = &pTab.apChange.?[@intCast(ii)];
            while (pp.* != null) {
                if (pp.*.?.nRecordField != pTab.nCol) {
                    sessionUpdateOneChange(pSession, &rc, pp, pTab.nCol, pStmt);
                }
                pp = &pp.*.?.pNext;
            }
        }
    }

    sessionFinalizeStmt(pStmt, &rc);
    pSession.rc = rc;
    return pSession.rc;
}

// ---------------------------------------------------------------------------
// sqlite_stat1 hook shims
// ---------------------------------------------------------------------------
fn sessionStat1Old(pCtx: ?*anyopaque, iCol: c_int, ppVal: *?*sqlite3_value) callconv(.c) c_int {
    const p: *SessionStat1Ctx = @ptrCast(@alignCast(pCtx));
    var pVal: ?*sqlite3_value = null;
    const rc = p.hook.xOld.?(p.hook.pCtx, iCol, &pVal);
    if (rc == SQLITE_OK and iCol == 1 and sqlite3_value_type(pVal) == SQLITE_NULL) {
        pVal = p.pSession.?.pZeroBlob;
    }
    ppVal.* = pVal;
    return rc;
}
fn sessionStat1New(pCtx: ?*anyopaque, iCol: c_int, ppVal: *?*sqlite3_value) callconv(.c) c_int {
    const p: *SessionStat1Ctx = @ptrCast(@alignCast(pCtx));
    var pVal: ?*sqlite3_value = null;
    const rc = p.hook.xNew.?(p.hook.pCtx, iCol, &pVal);
    if (rc == SQLITE_OK and iCol == 1 and sqlite3_value_type(pVal) == SQLITE_NULL) {
        pVal = p.pSession.?.pZeroBlob;
    }
    ppVal.* = pVal;
    return rc;
}
fn sessionStat1Count(pCtx: ?*anyopaque) callconv(.c) c_int {
    const p: *SessionStat1Ctx = @ptrCast(@alignCast(pCtx));
    return p.hook.xCount.?(p.hook.pCtx);
}
fn sessionStat1Depth(pCtx: ?*anyopaque) callconv(.c) c_int {
    const p: *SessionStat1Ctx = @ptrCast(@alignCast(pCtx));
    return p.hook.xDepth.?(p.hook.pCtx);
}

fn sessionUpdateMaxSize(op: c_int, pSession: *sqlite3_session, pTab: *SessionTable, pC: *SessionChange) c_int {
    var nNew: i64 = 2;
    if (pC.op == SQLITE_INSERT) {
        if (pTab.bRowid != 0) nNew += 9;
        if (op != SQLITE_DELETE) {
            var ii: c_int = 0;
            while (ii < pTab.nCol) : (ii += 1) {
                var p: ?*sqlite3_value = null;
                _ = pSession.hook.xNew.?(pSession.hook.pCtx, pTab.aiIdx.?[@intCast(ii)], &p);
                _ = sessionSerializeValue(null, p, &nNew);
            }
        }
    } else if (op == SQLITE_DELETE) {
        nNew += pC.nRecord;
        if (sqlite3_preupdate_blobwrite(pSession.db) >= 0) {
            nNew += pC.nRecord;
        }
    } else {
        var pCsr: [*]u8 = pC.aRecord.?;
        if (pTab.bRowid != 0) {
            nNew += 9 + 1;
            pCsr += 9;
        }
        var ii: c_int = pTab.bRowid;
        while (ii < pTab.nCol) : (ii += 1) {
            var bChanged: c_int = 1;
            var nOld: c_int = 0;
            const iIdx = pTab.aiIdx.?[@intCast(ii)];
            var p: ?*sqlite3_value = null;
            _ = pSession.hook.xNew.?(pSession.hook.pCtx, iIdx, &p);
            if (p == null) return SQLITE_NOMEM;

            const eType: c_int = pCsr[0];
            pCsr += 1;
            switch (eType) {
                SQLITE_NULL => bChanged = @intFromBool(sqlite3_value_type(p) != SQLITE_NULL),
                SQLITE_FLOAT, SQLITE_INTEGER => {
                    if (eType == sqlite3_value_type(p)) {
                        const iVal = sessionGetI64(pCsr);
                        if (eType == SQLITE_INTEGER) {
                            bChanged = @intFromBool(iVal != sqlite3_value_int64(p));
                        } else {
                            const dVal: f64 = @bitCast(iVal);
                            bChanged = @intFromBool(dVal != sqlite3_value_double(p));
                        }
                    }
                    nOld = 8;
                    pCsr += 8;
                },
                else => {
                    var nByte: c_int = undefined;
                    nOld = sessionVarintGet(pCsr, &nByte);
                    pCsr += @intCast(nOld);
                    nOld += nByte;
                    if (eType == sqlite3_value_type(p) and nByte == sqlite3_value_bytes(p) and (nByte == 0 or memcmpn(pCsr, @ptrCast(sqlite3_value_blob(p).?), @intCast(nByte)) == 0)) {
                        bChanged = 0;
                    }
                    pCsr += @intCast(nByte);
                },
            }

            if (bChanged != 0 and pTab.abPK.?[@intCast(ii)] != 0) {
                nNew = pC.nRecord + 2;
                break;
            }

            if (bChanged != 0) {
                nNew += 1 + nOld;
                _ = sessionSerializeValue(null, p, &nNew);
            } else if (pTab.abPK.?[@intCast(ii)] != 0) {
                nNew += 2 + nOld;
            } else {
                nNew += 2;
            }
        }
    }

    if (nNew > pC.nMaxSize) {
        const nIncr = nNew - pC.nMaxSize;
        pC.nMaxSize = @intCast(nNew);
        pSession.nMaxChangesetSize += nIncr;
    }
    return SQLITE_OK;
}

fn sessionPreupdateOneChange(op: c_int, iRowid: i64, pSession: *sqlite3_session, pTab: *SessionTable) void {
    var iHash: c_int = undefined;
    var bNull: c_int = 0;
    var rc: c_int = SQLITE_OK;
    var stat1: SessionStat1Ctx = std.mem.zeroes(SessionStat1Ctx);

    if (pSession.rc != 0) return;

    if (sessionInitTable(pSession, pTab, pSession.db, pSession.zDb.?) != 0) return;

    const nExpect = pSession.hook.xCount.?(pSession.hook.pCtx);
    if (pTab.nTotalCol < nExpect) {
        if (sessionReinitTable(pSession, pTab) != 0) return;
        if (sessionUpdateChanges(pSession, pTab) != 0) return;
    }
    if (pTab.nTotalCol != nExpect) {
        pSession.rc = SQLITE_SCHEMA;
        return;
    }

    if (sessionGrowHash(pSession, 0, pTab) != 0) {
        pSession.rc = SQLITE_NOMEM;
        return;
    }

    if (pTab.bStat1 != 0) {
        stat1.hook = pSession.hook;
        stat1.pSession = pSession;
        pSession.hook.pCtx = @ptrCast(&stat1);
        pSession.hook.xNew = sessionStat1New;
        pSession.hook.xOld = sessionStat1Old;
        pSession.hook.xCount = sessionStat1Count;
        pSession.hook.xDepth = sessionStat1Depth;
        if (pSession.pZeroBlob == null) {
            const p = sqlite3ValueNew(null);
            if (p == null) {
                rc = SQLITE_NOMEM;
                // goto error_out
                if (pTab.bStat1 != 0) pSession.hook = stat1.hook;
                if (rc != SQLITE_OK) pSession.rc = rc;
                return;
            }
            sqlite3ValueSetStr(p, 0, "", 0, SQLITE_STATIC);
            pSession.pZeroBlob = p;
        }
    }

    rc = sessionPreupdateHash(pSession, iRowid, pTab, @intFromBool(op == SQLITE_INSERT), &iHash, &bNull);
    if (rc != SQLITE_OK) {
        if (pTab.bStat1 != 0) pSession.hook = stat1.hook;
        if (rc != SQLITE_OK) pSession.rc = rc;
        return;
    }

    if (bNull == 0) {
        var pC: ?*SessionChange = pTab.apChange.?[@intCast(iHash)];
        while (pC) |c2| {
            if (sessionPreupdateEqual(pSession, iRowid, pTab, c2, op) != 0) break;
            pC = c2.pNext;
        }

        if (pC == null) {
            var nByte: i64 = @sizeOf(SessionChange);
            var i: c_int = pTab.bRowid;
            pTab.nEntry += 1;

            while (i < pTab.nCol) : (i += 1) {
                const iIdx = pTab.aiIdx.?[@intCast(i)];
                var p: ?*sqlite3_value = null;
                if (op != SQLITE_INSERT) {
                    rc = pSession.hook.xOld.?(pSession.hook.pCtx, iIdx, &p);
                } else if (pTab.abPK.?[@intCast(i)] != 0) {
                    _ = pSession.hook.xNew.?(pSession.hook.pCtx, iIdx, &p);
                }
                if (rc == SQLITE_OK) {
                    rc = sessionSerializeValue(null, p, &nByte);
                }
                if (rc != SQLITE_OK) {
                    if (pTab.bStat1 != 0) pSession.hook = stat1.hook;
                    pSession.rc = rc;
                    return;
                }
            }
            if (pTab.bRowid != 0) nByte += 9;

            const pCa: ?*SessionChange = @ptrCast(@alignCast(sessionMalloc64(pSession, nByte)));
            if (pCa == null) {
                rc = SQLITE_NOMEM;
                if (pTab.bStat1 != 0) pSession.hook = stat1.hook;
                pSession.rc = rc;
                return;
            }
            pC = pCa;
            memset0(@ptrCast(pCa.?), @sizeOf(SessionChange));
            pCa.?.aRecord = @ptrCast(@as([*]SessionChange, @ptrCast(pCa.?)) + 1);

            nByte = 0;
            if (pTab.bRowid != 0) {
                pCa.?.aRecord.?[0] = SQLITE_INTEGER;
                sessionPutI64(pCa.?.aRecord.? + 1, iRowid);
                nByte = 9;
            }
            i = pTab.bRowid;
            while (i < pTab.nCol) : (i += 1) {
                var p: ?*sqlite3_value = null;
                const iIdx = pTab.aiIdx.?[@intCast(i)];
                if (op != SQLITE_INSERT) {
                    _ = pSession.hook.xOld.?(pSession.hook.pCtx, iIdx, &p);
                } else if (pTab.abPK.?[@intCast(i)] != 0) {
                    _ = pSession.hook.xNew.?(pSession.hook.pCtx, iIdx, &p);
                }
                _ = sessionSerializeValue(pCa.?.aRecord.? + @as(usize, @intCast(nByte)), p, &nByte);
            }

            if (pSession.bIndirect != 0 or pSession.hook.xDepth.?(pSession.hook.pCtx) != 0) {
                pCa.?.bIndirect = 1;
            }
            pCa.?.nRecordField = @intCast(pTab.nCol);
            pCa.?.nRecord = @intCast(nByte);
            pCa.?.op = @intCast(op);
            pCa.?.pNext = pTab.apChange.?[@intCast(iHash)];
            pTab.apChange.?[@intCast(iHash)] = pCa;
        } else if (pC.?.bIndirect != 0) {
            if (pSession.hook.xDepth.?(pSession.hook.pCtx) == 0 and pSession.bIndirect == 0) {
                pC.?.bIndirect = 0;
            }
        }

        if (pSession.bEnableSize != 0) {
            rc = sessionUpdateMaxSize(op, pSession, pTab, pC.?);
        }
    }

    // error_out:
    if (pTab.bStat1 != 0) pSession.hook = stat1.hook;
    if (rc != SQLITE_OK) pSession.rc = rc;
}

fn sessionFindTable(pSession: *sqlite3_session, zName: [*:0]const u8, ppTab: *?*SessionTable) c_int {
    var rc: c_int = SQLITE_OK;
    const nName = sqlite3Strlen30(zName);
    var pRet: ?*SessionTable = pSession.pTable;

    while (pRet) |pr| {
        if (0 == sqlite3_strnicmp(pr.zName.?, zName, nName + 1)) break;
        pRet = pr.pNext;
    }

    if (pRet == null and pSession.bAutoAttach != 0) {
        if (pSession.xTableFilter == null or pSession.xTableFilter.?(pSession.pFilterCtx, zName) != 0) {
            rc = sqlite3session_attach(pSession, zName);
            if (rc == SQLITE_OK) {
                pRet = pSession.pTable;
                while (pRet.?.pNext != null) {
                    pRet = pRet.?.pNext;
                }
            }
        }
    }

    ppTab.* = pRet;
    return rc;
}

fn xPreUpdate(pCtx: ?*anyopaque, db: ?*sqlite3, op: c_int, zDb: [*:0]const u8, zName: [*:0]const u8, iKey1: i64, iKey2: i64) callconv(.c) void {
    _ = db;
    const nDb = sqlite3Strlen30(zDb);
    var pSession: ?*sqlite3_session = @ptrCast(@alignCast(pCtx));
    while (pSession) |ps| {
        if (ps.bEnable == 0) {
            pSession = ps.pNext;
            continue;
        }
        if (ps.rc != 0) {
            pSession = ps.pNext;
            continue;
        }
        if (sqlite3_strnicmp(zDb, ps.zDb.?, nDb + 1) != 0) {
            pSession = ps.pNext;
            continue;
        }

        var pTab: ?*SessionTable = null;
        ps.rc = sessionFindTable(ps, zName, &pTab);
        if (pTab) |pt| {
            sessionPreupdateOneChange(op, iKey1, ps, pt);
            if (op == SQLITE_UPDATE) {
                sessionPreupdateOneChange(SQLITE_INSERT, iKey2, ps, pt);
            }
        }
        pSession = ps.pNext;
    }
}

fn sessionPreupdateOld(pCtx: ?*anyopaque, iVal: c_int, ppVal: *?*sqlite3_value) callconv(.c) c_int {
    return sqlite3_preupdate_old(@ptrCast(pCtx), iVal, ppVal);
}
fn sessionPreupdateNew(pCtx: ?*anyopaque, iVal: c_int, ppVal: *?*sqlite3_value) callconv(.c) c_int {
    return sqlite3_preupdate_new(@ptrCast(pCtx), iVal, ppVal);
}
fn sessionPreupdateCount(pCtx: ?*anyopaque) callconv(.c) c_int {
    return sqlite3_preupdate_count(@ptrCast(pCtx));
}
fn sessionPreupdateDepth(pCtx: ?*anyopaque) callconv(.c) c_int {
    return sqlite3_preupdate_depth(@ptrCast(pCtx));
}

fn sessionPreupdateHooks(pSession: *sqlite3_session) void {
    pSession.hook.pCtx = @ptrCast(pSession.db);
    pSession.hook.xOld = sessionPreupdateOld;
    pSession.hook.xNew = sessionPreupdateNew;
    pSession.hook.xCount = sessionPreupdateCount;
    pSession.hook.xDepth = sessionPreupdateDepth;
}

// ---------------------------------------------------------------------------
// diff hooks
// ---------------------------------------------------------------------------
fn sessionDiffOld(pCtx: ?*anyopaque, iVal: c_int, ppVal: *?*sqlite3_value) callconv(.c) c_int {
    const p: *SessionDiffCtx = @ptrCast(@alignCast(pCtx));
    ppVal.* = sqlite3_column_value(p.pStmt, iVal + p.nOldOff + p.bRowid);
    return SQLITE_OK;
}
fn sessionDiffNew(pCtx: ?*anyopaque, iVal: c_int, ppVal: *?*sqlite3_value) callconv(.c) c_int {
    const p: *SessionDiffCtx = @ptrCast(@alignCast(pCtx));
    ppVal.* = sqlite3_column_value(p.pStmt, iVal + p.bRowid);
    return SQLITE_OK;
}
fn sessionDiffCount(pCtx: ?*anyopaque) callconv(.c) c_int {
    const p: *SessionDiffCtx = @ptrCast(@alignCast(pCtx));
    return (if (p.nOldOff != 0) p.nOldOff else sqlite3_column_count(p.pStmt)) - p.bRowid;
}
fn sessionDiffDepth(pCtx: ?*anyopaque) callconv(.c) c_int {
    _ = pCtx;
    return 0;
}

fn sessionDiffHooks(pSession: *sqlite3_session, pDiffCtx: *SessionDiffCtx) void {
    pSession.hook.pCtx = @ptrCast(pDiffCtx);
    pSession.hook.xOld = sessionDiffOld;
    pSession.hook.xNew = sessionDiffNew;
    pSession.hook.xCount = sessionDiffCount;
    pSession.hook.xDepth = sessionDiffDepth;
}

fn sessionExprComparePK(nCol: c_int, zDb1: [*:0]const u8, zDb2: [*:0]const u8, zTab: [*:0]const u8, azCol: [*]?[*:0]const u8, abPK: [*]u8) ?[*:0]u8 {
    var zSep: [*:0]const u8 = "";
    var zRet: ?[*:0]u8 = null;
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        if (abPK[@intCast(i)] != 0) {
            zRet = sqlite3_mprintf("%z%s\"%w\".\"%w\".\"%w\"=\"%w\".\"%w\".\"%w\"", zRet, zSep, zDb1, zTab, azCol[@intCast(i)], zDb2, zTab, azCol[@intCast(i)]);
            zSep = " AND ";
            if (zRet == null) break;
        }
    }
    return zRet;
}

fn sessionExprCompareOther(nCol: c_int, zDb1: [*:0]const u8, zDb2: [*:0]const u8, zTab: [*:0]const u8, azCol: [*]?[*:0]const u8, abPK: [*]u8) ?[*:0]u8 {
    var zSep: [*:0]const u8 = "";
    var zRet: ?[*:0]u8 = null;
    var bHave: c_int = 0;
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        if (abPK[@intCast(i)] == 0) {
            bHave = 1;
            zRet = sqlite3_mprintf("%z%s\"%w\".\"%w\".\"%w\" IS NOT \"%w\".\"%w\".\"%w\"", zRet, zSep, zDb1, zTab, azCol[@intCast(i)], zDb2, zTab, azCol[@intCast(i)]);
            zSep = " OR ";
            if (zRet == null) break;
        }
    }
    if (bHave == 0) {
        zRet = sqlite3_mprintf("0");
    }
    return zRet;
}

fn sessionSelectFindNew(zDb1: [*:0]const u8, zDb2: [*:0]const u8, bRowid: c_int, zTbl: [*:0]const u8, zExpr: [*:0]const u8) ?[*:0]u8 {
    const zSel: [*:0]const u8 = if (bRowid != 0) (SESSIONS_ROWID ++ ", *") else "*";
    return sqlite3_mprintf("SELECT %s FROM \"%w\".\"%w\" WHERE NOT EXISTS (  SELECT 1 FROM \"%w\".\"%w\" WHERE %s)", zSel, zDb1, zTbl, zDb2, zTbl, zExpr);
}

fn sessionDiffFindNew(op: c_int, pSession: *sqlite3_session, pTab: *SessionTable, zDb1: [*:0]const u8, zDb2: [*:0]const u8, zExpr: [*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    const zStmt = sessionSelectFindNew(zDb1, zDb2, pTab.bRowid, pTab.zName.?, zExpr);
    if (zStmt == null) {
        rc = SQLITE_NOMEM;
    } else {
        var pStmt: ?*sqlite3_stmt = null;
        rc = sqlite3_prepare_v2(pSession.db, zStmt.?, -1, &pStmt, null);
        if (rc == SQLITE_OK) {
            const pDiffCtx: *SessionDiffCtx = @ptrCast(@alignCast(pSession.hook.pCtx));
            pDiffCtx.pStmt = pStmt;
            pDiffCtx.nOldOff = 0;
            pDiffCtx.bRowid = pTab.bRowid;
            while (SQLITE_ROW == sqlite3_step(pStmt)) {
                const iRowid: i64 = if (pTab.bRowid != 0) sqlite3_column_int64(pStmt, 0) else 0;
                sessionPreupdateOneChange(op, iRowid, pSession, pTab);
            }
            rc = sqlite3_finalize(pStmt);
        }
        sqlite3_free(@ptrCast(zStmt));
    }
    return rc;
}

fn sessionAllCols(zDb: [*:0]const u8, pTab: *SessionTable) ?[*:0]u8 {
    var zRet: ?[*:0]u8 = null;
    var ii: c_int = 0;
    while (ii < pTab.nCol) : (ii += 1) {
        zRet = sqlite3_mprintf("%z%s\"%w\".\"%w\".\"%w\"", zRet, @as([*:0]const u8, if (zRet != null) ", " else ""), zDb, pTab.zName.?, pTab.azCol.?[@intCast(ii)]);
        if (zRet == null) break;
    }
    return zRet;
}

fn sessionDiffFindModified(pSession: *sqlite3_session, pTab: *SessionTable, zFrom: [*:0]const u8, zExpr: [*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    const zExpr2 = sessionExprCompareOther(pTab.nCol, pSession.zDb.?, zFrom, pTab.zName.?, pTab.azCol.?, pTab.abPK.?);
    if (zExpr2 == null) {
        rc = SQLITE_NOMEM;
    } else {
        const z1 = sessionAllCols(pSession.zDb.?, pTab);
        const z2 = sessionAllCols(zFrom, pTab);
        const zStmt = sqlite3_mprintf("SELECT %s,%s FROM \"%w\".\"%w\", \"%w\".\"%w\" WHERE %s AND (%z)", z1, z2, pSession.zDb.?, pTab.zName.?, zFrom, pTab.zName.?, zExpr, zExpr2);
        if (zStmt == null or z1 == null or z2 == null) {
            rc = SQLITE_NOMEM;
        } else {
            var pStmt: ?*sqlite3_stmt = null;
            rc = sqlite3_prepare_v2(pSession.db, zStmt.?, -1, &pStmt, null);
            if (rc == SQLITE_OK) {
                const pDiffCtx: *SessionDiffCtx = @ptrCast(@alignCast(pSession.hook.pCtx));
                pDiffCtx.pStmt = pStmt;
                pDiffCtx.nOldOff = pTab.nCol;
                while (SQLITE_ROW == sqlite3_step(pStmt)) {
                    const iRowid: i64 = if (pTab.bRowid != 0) sqlite3_column_int64(pStmt, 0) else 0;
                    sessionPreupdateOneChange(SQLITE_UPDATE, iRowid, pSession, pTab);
                }
                rc = sqlite3_finalize(pStmt);
            }
        }
        sqlite3_free(@ptrCast(zStmt));
        sqlite3_free(@ptrCast(z1));
        sqlite3_free(@ptrCast(z2));
    }
    return rc;
}

// ===========================================================================
// Public: sqlite3session_diff / create / delete / table_filter / attach
// ===========================================================================
export fn sqlite3session_diff(pSession: *sqlite3_session, zFrom: [*:0]const u8, zTbl: [*:0]const u8, pzErrMsg: ?*?[*:0]u8) c_int {
    const zDb: [*:0]const u8 = pSession.zDb.?;
    var rc: c_int = pSession.rc;
    var d: SessionDiffCtx = std.mem.zeroes(SessionDiffCtx);

    sessionDiffHooks(pSession, &d);

    sqlite3_mutex_enter(sqlite3_db_mutex(pSession.db));
    if (pzErrMsg) |p| p.* = null;
    if (rc == SQLITE_OK) {
        var zExpr: ?[*:0]u8 = null;
        const db = pSession.db;
        var pTo: ?*SessionTable = null;

        pSession.bAutoAttach += 1;
        rc = sessionFindTable(pSession, zTbl, &pTo);
        pSession.bAutoAttach -= 1;
        diff: {
            if (pTo == null) break :diff;
            if (sessionInitTable(pSession, pTo.?, pSession.db, pSession.zDb.?) != 0) {
                rc = pSession.rc;
                break :diff;
            }

            if (rc == SQLITE_OK) {
                var bHasPk: c_int = 0;
                var bMismatch: c_int = 0;
                var nCol: c_int = 0;
                var bRowid: c_int = 0;
                var abPK: ?[*]u8 = null;
                var azCol: ?[*]?[*:0]const u8 = null;

                const zDbExists = sqlite3_mprintf("SELECT * FROM %Q.sqlite_schema", zFrom);
                if (zDbExists == null) {
                    rc = SQLITE_NOMEM;
                } else {
                    var pDbExists: ?*sqlite3_stmt = null;
                    rc = sqlite3_prepare_v2(db, zDbExists.?, -1, &pDbExists, null);
                    if (rc == SQLITE_ERROR) {
                        rc = SQLITE_OK;
                        nCol = -1;
                    }
                    _ = sqlite3_finalize(pDbExists);
                    sqlite3_free(@ptrCast(zDbExists));
                }

                if (rc == SQLITE_OK and nCol == 0) {
                    rc = sessionTableInfo(null, db, zFrom, zTbl, &nCol, null, null, &azCol, null, null, &abPK, if (pSession.bImplicitPK != 0) &bRowid else null);
                }
                if (rc == SQLITE_OK) {
                    if (pTo.?.nCol != nCol) {
                        if (nCol <= 0) {
                            rc = SQLITE_SCHEMA;
                            if (pzErrMsg) |p| p.* = sqlite3_mprintf("no such table: %s.%s", zFrom, zTbl);
                        } else {
                            bMismatch = 1;
                        }
                    } else {
                        var i: c_int = 0;
                        while (i < nCol) : (i += 1) {
                            if (pTo.?.abPK.?[@intCast(i)] != abPK.?[@intCast(i)]) bMismatch = 1;
                            if (sqlite3_stricmp(azCol.?[@intCast(i)].?, pTo.?.azCol.?[@intCast(i)].?) != 0) bMismatch = 1;
                            if (abPK.?[@intCast(i)] != 0) bHasPk = 1;
                        }
                    }
                }
                sqlite3_free(@ptrCast(azCol));
                if (bMismatch != 0) {
                    if (pzErrMsg) |p| p.* = sqlite3_mprintf("table schemas do not match");
                    rc = SQLITE_SCHEMA;
                }
                if (bHasPk == 0) break :diff;
            }

            if (rc == SQLITE_OK) {
                zExpr = sessionExprComparePK(pTo.?.nCol, zDb, zFrom, pTo.?.zName.?, pTo.?.azCol.?, pTo.?.abPK.?);
            }
            if (rc == SQLITE_OK) {
                rc = sessionDiffFindNew(SQLITE_INSERT, pSession, pTo.?, zDb, zFrom, zExpr.?);
            }
            if (rc == SQLITE_OK) {
                rc = sessionDiffFindNew(SQLITE_DELETE, pSession, pTo.?, zFrom, zDb, zExpr.?);
            }
            if (rc == SQLITE_OK) {
                rc = sessionDiffFindModified(pSession, pTo.?, zFrom, zExpr.?);
            }
            sqlite3_free(@ptrCast(zExpr));
        }
    }

    sessionPreupdateHooks(pSession);
    sqlite3_mutex_leave(sqlite3_db_mutex(pSession.db));
    return rc;
}

export fn sqlite3session_create(db: ?*sqlite3, zDb: [*:0]const u8, ppSession: *?*sqlite3_session) c_int {
    const nDb = sqlite3Strlen30(zDb);
    ppSession.* = null;

    const pNew: ?*sqlite3_session = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @sizeOf(sqlite3_session)) + @as(u64, @intCast(nDb)) + 1)));
    if (pNew == null) return SQLITE_NOMEM;
    const pn = pNew.?;
    memset0(@ptrCast(pn), @sizeOf(sqlite3_session));
    pn.db = db;
    pn.zDb = @ptrCast(@as([*]sqlite3_session, @ptrCast(pn)) + 1);
    pn.bEnable = 1;
    memcpy(@ptrCast(pn.zDb.?), zDb, @intCast(nDb + 1));
    sessionPreupdateHooks(pn);

    sqlite3_mutex_enter(sqlite3_db_mutex(db));
    const pOld: ?*sqlite3_session = @ptrCast(@alignCast(sqlite3_preupdate_hook(db, @ptrCast(&xPreUpdate), @ptrCast(pn))));
    pn.pNext = pOld;
    sqlite3_mutex_leave(sqlite3_db_mutex(db));

    ppSession.* = pn;
    return SQLITE_OK;
}

fn sessionDeleteTable(pSession: ?*sqlite3_session, pList: ?*SessionTable) void {
    var pTab: ?*SessionTable = pList;
    while (pTab) |pt| {
        const pNext = pt.pNext;
        var i: c_int = 0;
        while (i < pt.nChange) : (i += 1) {
            var p: ?*SessionChange = pt.apChange.?[@intCast(i)];
            while (p) |pc| {
                const pNextChange = pc.pNext;
                sessionFree(pSession, pc);
                p = pNextChange;
            }
        }
        _ = sqlite3_finalize(pt.pDfltStmt);
        sessionFree(pSession, @ptrCast(pt.azCol));
        sessionFree(pSession, @ptrCast(pt.apChange));
        sessionFree(pSession, pt);
        pTab = pNext;
    }
}

export fn sqlite3session_delete(pSession: *sqlite3_session) void {
    const db = pSession.db;

    sqlite3_mutex_enter(sqlite3_db_mutex(db));
    var pHead: ?*sqlite3_session = @ptrCast(@alignCast(sqlite3_preupdate_hook(db, null, null)));
    var pp: *?*sqlite3_session = &pHead;
    while (pp.*) |cur| {
        if (cur == pSession) {
            pp.* = cur.pNext;
            if (pHead != null) _ = sqlite3_preupdate_hook(db, @ptrCast(&xPreUpdate), @ptrCast(pHead));
            break;
        }
        pp = &cur.pNext;
    }
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    sqlite3ValueFree(pSession.pZeroBlob);

    sessionDeleteTable(pSession, pSession.pTable);
    sqlite3_free(@ptrCast(pSession));
}

export fn sqlite3session_table_filter(pSession: *sqlite3_session, xFilter: XTableFilter, pCtx: ?*anyopaque) void {
    pSession.bAutoAttach = 1;
    pSession.pFilterCtx = pCtx;
    pSession.xTableFilter = xFilter;
}

export fn sqlite3session_attach(pSession: *sqlite3_session, zName: ?[*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    sqlite3_mutex_enter(sqlite3_db_mutex(pSession.db));

    if (zName == null) {
        pSession.bAutoAttach = 1;
    } else {
        const nName = sqlite3Strlen30(zName.?);
        var pTab: ?*SessionTable = pSession.pTable;
        while (pTab) |pt| {
            if (0 == sqlite3_strnicmp(pt.zName.?, zName.?, nName + 1)) break;
            pTab = pt.pNext;
        }

        if (pTab == null) {
            const nByte: i64 = @as(i64, @sizeOf(SessionTable)) + nName + 1;
            const pNew: ?*SessionTable = @ptrCast(@alignCast(sessionMalloc64(pSession, nByte)));
            if (pNew == null) {
                rc = SQLITE_NOMEM;
            } else {
                const pt = pNew.?;
                memset0(@ptrCast(pt), @sizeOf(SessionTable));
                pt.zName = @ptrCast(@as([*]SessionTable, @ptrCast(pt)) + 1);
                memcpy(@ptrCast(pt.zName.?), zName.?, @intCast(nName + 1));
                var ppTab: *?*SessionTable = &pSession.pTable;
                while (ppTab.*) |existing| ppTab = &existing.pNext;
                ppTab.* = pt;
            }
        }
    }

    sqlite3_mutex_leave(sqlite3_db_mutex(pSession.db));
    return rc;
}

// ===========================================================================
// Changeset-building append helpers
// ===========================================================================
fn sessionAppendValue(p: *SessionBuffer, pVal: ?*sqlite3_value, pRc: *c_int) void {
    var rc: c_int = pRc.*;
    if (rc == SQLITE_OK) {
        var nByte: i64 = 0;
        rc = sessionSerializeValue(null, pVal, &nByte);
        _ = sessionBufferGrow(p, nByte, &rc);
        if (rc == SQLITE_OK) {
            rc = sessionSerializeValue(p.aBuf.? + @as(usize, @intCast(p.nBuf)), pVal, null);
            p.nBuf += @intCast(nByte);
        } else {
            pRc.* = rc;
        }
    }
}

fn sessionAppendByte(p: *SessionBuffer, v: u8, pRc: *c_int) void {
    if (0 == sessionBufferGrow(p, 1, pRc)) {
        p.aBuf.?[@intCast(p.nBuf)] = v;
        p.nBuf += 1;
    }
}

fn sessionAppendVarint(p: *SessionBuffer, v: c_int, pRc: *c_int) void {
    if (0 == sessionBufferGrow(p, 9, pRc)) {
        p.nBuf += sessionVarintPut(p.aBuf.? + @as(usize, @intCast(p.nBuf)), v);
    }
}

fn sessionAppendBlob(p: *SessionBuffer, aBlob: ?[*]const u8, nBlob: c_int, pRc: *c_int) void {
    if (nBlob > 0 and 0 == sessionBufferGrow(p, nBlob, pRc)) {
        memcpy(p.aBuf.? + @as(usize, @intCast(p.nBuf)), aBlob.?, @intCast(nBlob));
        p.nBuf += nBlob;
    }
}

fn sessionAppendInteger(p: *SessionBuffer, iVal: c_int, pRc: *c_int) void {
    var aBuf: [24]u8 = undefined;
    _ = sqlite3_snprintf(@as(c_int, @intCast(aBuf.len)) - 1, &aBuf, "%d", iVal);
    sessionAppendStr(p, @ptrCast(&aBuf), pRc);
}

fn sessionAppendIdent(p: *SessionBuffer, zStr: [*:0]const u8, pRc: *c_int) void {
    const nStr = sqlite3Strlen30(zStr) * 2 + 2 + 2;
    if (0 == sessionBufferGrow(p, nStr, pRc)) {
        var zOut: [*]u8 = p.aBuf.? + @as(usize, @intCast(p.nBuf));
        var zIn: [*:0]const u8 = zStr;
        zOut[0] = '"';
        zOut += 1;
        while (zIn[0] != 0) {
            if (zIn[0] == '"') {
                zOut[0] = '"';
                zOut += 1;
            }
            zOut[0] = zIn[0];
            zOut += 1;
            zIn += 1;
        }
        zOut[0] = '"';
        zOut += 1;
        p.nBuf = @intCast(@intFromPtr(zOut) - @intFromPtr(p.aBuf.?));
        p.aBuf.?[@intCast(p.nBuf)] = 0;
    }
}

fn sessionAppendCol(p: *SessionBuffer, pStmt: ?*sqlite3_stmt, iCol: c_int, pRc: *c_int) void {
    if (pRc.* == SQLITE_OK) {
        const eType = sqlite3_column_type(pStmt, iCol);
        sessionAppendByte(p, @intCast(eType), pRc);
        if (eType == SQLITE_INTEGER or eType == SQLITE_FLOAT) {
            var aBuf: [8]u8 = undefined;
            if (eType == SQLITE_INTEGER) {
                const i = sqlite3_column_int64(pStmt, iCol);
                sessionPutI64(&aBuf, i);
            } else {
                const r = sqlite3_column_double(pStmt, iCol);
                sessionPutDouble(&aBuf, r);
            }
            sessionAppendBlob(p, &aBuf, 8, pRc);
        }
        if (eType == SQLITE_BLOB or eType == SQLITE_TEXT) {
            var z: ?[*]const u8 = undefined;
            if (eType == SQLITE_BLOB) {
                z = @ptrCast(sqlite3_column_blob(pStmt, iCol));
            } else {
                z = sqlite3_column_text(pStmt, iCol);
            }
            const nByte = sqlite3_column_bytes(pStmt, iCol);
            if (z != null or (eType == SQLITE_BLOB and nByte == 0)) {
                sessionAppendVarint(p, nByte, pRc);
                sessionAppendBlob(p, z, nByte, pRc);
            } else {
                pRc.* = SQLITE_NOMEM;
            }
        }
    }
}

fn sessionAppendUpdate(pBuf: *SessionBuffer, bPatchset: c_int, pStmt: ?*sqlite3_stmt, p: *SessionChange, abPK: [*]u8) c_int {
    var rc: c_int = SQLITE_OK;
    var buf2: SessionBuffer = .{};
    var bNoop: c_int = 1;
    const nRewind: c_int = pBuf.nBuf;
    var pCsr: [*]u8 = p.aRecord.?;

    sessionAppendByte(pBuf, SQLITE_UPDATE, &rc);
    sessionAppendByte(pBuf, p.bIndirect, &rc);
    var i: c_int = 0;
    while (i < sqlite3_column_count(pStmt)) : (i += 1) {
        var bChanged: c_int = 0;
        var nAdvance: c_int = undefined;
        const eType: c_int = pCsr[0];
        switch (eType) {
            SQLITE_NULL => {
                nAdvance = 1;
                if (sqlite3_column_type(pStmt, i) != SQLITE_NULL) bChanged = 1;
            },
            SQLITE_FLOAT, SQLITE_INTEGER => {
                nAdvance = 9;
                blk: {
                    if (eType == sqlite3_column_type(pStmt, i)) {
                        const iVal = sessionGetI64(pCsr + 1);
                        if (eType == SQLITE_INTEGER) {
                            if (iVal == sqlite3_column_int64(pStmt, i)) break :blk;
                        } else {
                            const dVal: f64 = @bitCast(iVal);
                            if (dVal == sqlite3_column_double(pStmt, i)) break :blk;
                        }
                    }
                    bChanged = 1;
                }
            },
            else => {
                var n: c_int = undefined;
                const nHdr = 1 + sessionVarintGet(pCsr + 1, &n);
                nAdvance = nHdr + n;
                blk: {
                    if (eType == sqlite3_column_type(pStmt, i) and n == sqlite3_column_bytes(pStmt, i) and (n == 0 or memcmpn(pCsr + @as(usize, @intCast(nHdr)), @ptrCast(sqlite3_column_blob(pStmt, i).?), @intCast(n)) == 0)) {
                        break :blk;
                    }
                    bChanged = 1;
                }
            },
        }

        if (bChanged != 0) bNoop = 0;

        if (bPatchset == 0) {
            if (bChanged != 0 or abPK[@intCast(i)] != 0) {
                sessionAppendBlob(pBuf, pCsr, nAdvance, &rc);
            } else {
                sessionAppendByte(pBuf, 0, &rc);
            }
        }

        if (bChanged != 0 or (bPatchset != 0 and abPK[@intCast(i)] != 0)) {
            sessionAppendCol(&buf2, pStmt, i, &rc);
        } else {
            sessionAppendByte(&buf2, 0, &rc);
        }

        pCsr += @intCast(nAdvance);
    }

    if (bNoop != 0) {
        pBuf.nBuf = nRewind;
    } else {
        sessionAppendBlob(pBuf, buf2.aBuf, buf2.nBuf, &rc);
    }
    sqlite3_free(@ptrCast(buf2.aBuf));
    return rc;
}

fn sessionAppendDelete(pBuf: *SessionBuffer, bPatchset: c_int, p: *SessionChange, nCol: c_int, abPK: [*]u8) c_int {
    var rc: c_int = SQLITE_OK;

    sessionAppendByte(pBuf, SQLITE_DELETE, &rc);
    sessionAppendByte(pBuf, p.bIndirect, &rc);

    if (bPatchset == 0) {
        sessionAppendBlob(pBuf, p.aRecord, p.nRecord, &rc);
    } else {
        var a: [*]u8 = p.aRecord.?;
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const pStart: [*]u8 = a;
            const eType: c_int = a[0];
            a += 1;
            switch (eType) {
                0, SQLITE_NULL => {},
                SQLITE_FLOAT, SQLITE_INTEGER => a += 8,
                else => {
                    var n: c_int = undefined;
                    a += @intCast(sessionVarintGet(a, &n));
                    a += @intCast(n);
                },
            }
            if (abPK[@intCast(i)] != 0) {
                sessionAppendBlob(pBuf, pStart, @intCast(@intFromPtr(a) - @intFromPtr(pStart)), &rc);
            }
        }
    }
    return rc;
}

fn sessionPrepare(db: ?*sqlite3, pp: *?*sqlite3_stmt, pzErrmsg: ?*?[*:0]u8, zSql: [*:0]const u8) c_int {
    const rc = sqlite3_prepare_v2(db, zSql, -1, pp, null);
    if (pzErrmsg != null and rc != SQLITE_OK) {
        pzErrmsg.?.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
    }
    return rc;
}

fn sessionSelectStmt(
    db: ?*sqlite3,
    bIgnoreNoop: c_int,
    zDb: [*:0]const u8,
    zTab: [*:0]const u8,
    bRowid: c_int,
    nCol: c_int,
    azCol: [*]?[*:0]const u8,
    abPK: [*]u8,
    ppStmt: *?*sqlite3_stmt,
    pzErrmsg: ?*?[*:0]u8,
) c_int {
    _ = bRowid;
    var rc: c_int = SQLITE_OK;
    var zSql: ?[*:0]u8 = null;
    var zSep: [*:0]const u8 = "";
    var i: c_int = 0;

    var cols: SessionBuffer = .{};
    var nooptest: SessionBuffer = .{};
    var pkfield: SessionBuffer = .{};
    var pkvar: SessionBuffer = .{};

    sessionAppendStr(&nooptest, ", 1", &rc);

    if (0 == sqlite3_stricmp("sqlite_stat1", zTab)) {
        sessionAppendStr(&nooptest, " AND (?6 OR ?3 IS stat)", &rc);
        sessionAppendStr(&pkfield, "tbl, idx", &rc);
        sessionAppendStr(&pkvar, "?1, (CASE WHEN ?2=X'' THEN NULL ELSE ?2 END)", &rc);
        sessionAppendStr(&cols, "tbl, ?2, stat", &rc);
    } else {
        i = 0;
        while (i < nCol) : (i += 1) {
            if (cols.nBuf != 0) sessionAppendStr(&cols, ", ", &rc);
            sessionAppendIdent(&cols, azCol[@intCast(i)].?, &rc);
            if (abPK[@intCast(i)] != 0) {
                sessionAppendStr(&pkfield, zSep, &rc);
                sessionAppendStr(&pkvar, zSep, &rc);
                zSep = ", ";
                sessionAppendIdent(&pkfield, azCol[@intCast(i)].?, &rc);
                sessionAppendPrintf(&pkvar, &rc, "?%d", .{i + 1});
            } else {
                sessionAppendPrintf(&nooptest, &rc, " AND (?%d OR ?%d IS %w.%w)", .{ i + 1 + nCol, i + 1, zTab, azCol[@intCast(i)] });
            }
        }
    }

    if (rc == SQLITE_OK) {
        zSql = sqlite3_mprintf("SELECT %s%s FROM %Q.%Q WHERE (%s) IS (%s)", @as([*:0]const u8, @ptrCast(cols.aBuf.?)), @as([*:0]const u8, if (bIgnoreNoop != 0) @ptrCast(nooptest.aBuf.?) else ""), zDb, zTab, @as([*:0]const u8, @ptrCast(pkfield.aBuf.?)), @as([*:0]const u8, @ptrCast(pkvar.aBuf.?)));
        if (zSql == null) rc = SQLITE_NOMEM;
    }

    if (rc == SQLITE_OK) {
        rc = sessionPrepare(db, ppStmt, pzErrmsg, zSql.?);
    }
    sqlite3_free(@ptrCast(zSql));
    sqlite3_free(@ptrCast(nooptest.aBuf));
    sqlite3_free(@ptrCast(pkfield.aBuf));
    sqlite3_free(@ptrCast(pkvar.aBuf));
    sqlite3_free(@ptrCast(cols.aBuf));
    return rc;
}

fn sessionSelectBind(pSelect: ?*sqlite3_stmt, nCol: c_int, abPK: [*]u8, pChange: *SessionChange) c_int {
    var rc: c_int = SQLITE_OK;
    var a: [*]u8 = pChange.aRecord.?;
    var i: c_int = 0;
    while (i < nCol and rc == SQLITE_OK) : (i += 1) {
        const eType: c_int = a[0];
        a += 1;
        switch (eType) {
            0, SQLITE_NULL => {},
            SQLITE_INTEGER => {
                if (abPK[@intCast(i)] != 0) {
                    const iVal = sessionGetI64(a);
                    rc = sqlite3_bind_int64(pSelect, i + 1, iVal);
                }
                a += 8;
            },
            SQLITE_FLOAT => {
                if (abPK[@intCast(i)] != 0) {
                    const iVal = sessionGetI64(a);
                    const rVal: f64 = @bitCast(iVal);
                    rc = sqlite3_bind_double(pSelect, i + 1, rVal);
                }
                a += 8;
            },
            SQLITE_TEXT => {
                var n: c_int = undefined;
                a += @intCast(sessionVarintGet(a, &n));
                if (abPK[@intCast(i)] != 0) {
                    rc = sqlite3_bind_text(pSelect, i + 1, a, n, sqliteTransient());
                }
                a += @intCast(n);
            },
            else => {
                var n: c_int = undefined;
                a += @intCast(sessionVarintGet(a, &n));
                if (abPK[@intCast(i)] != 0) {
                    rc = sqlite3_bind_blob(pSelect, i + 1, a, n, sqliteTransient());
                }
                a += @intCast(n);
            },
        }
    }
    return rc;
}

fn sessionAppendTableHdr(pBuf: *SessionBuffer, bPatchset: c_int, pTab: *SessionTable, pRc: *c_int) void {
    sessionAppendByte(pBuf, if (bPatchset != 0) 'P' else 'T', pRc);
    sessionAppendVarint(pBuf, pTab.nCol, pRc);
    sessionAppendBlob(pBuf, pTab.abPK, pTab.nCol, pRc);
    sessionAppendBlob(pBuf, @ptrCast(pTab.zName), @intCast(strlen0(pTab.zName.?) + 1), pRc);
}

fn sessionGenerateChangeset(
    pSession: *sqlite3_session,
    bPatchset: c_int,
    xOutput: XOutput,
    pOut: ?*anyopaque,
    pnChangeset: ?*c_int,
    ppChangeset: ?*?*anyopaque,
) c_int {
    const db = pSession.db;
    var buf: SessionBuffer = .{};
    var rc: c_int = undefined;

    if (xOutput == null) {
        pnChangeset.?.* = 0;
        ppChangeset.?.* = null;
    }

    if (pSession.rc != 0) return pSession.rc;

    sqlite3_mutex_enter(sqlite3_db_mutex(db));
    rc = sqlite3_exec(pSession.db, "SAVEPOINT changeset", null, null, null);
    if (rc != SQLITE_OK) {
        sqlite3_mutex_leave(sqlite3_db_mutex(db));
        return rc;
    }

    var pTab: ?*SessionTable = pSession.pTable;
    while (rc == SQLITE_OK and pTab != null) : (pTab = pTab.?.pNext) {
        const pt = pTab.?;
        if (pt.nEntry != 0) {
            const zName = pt.zName.?;
            var pSel: ?*sqlite3_stmt = null;
            const nRewind: c_int = buf.nBuf;
            var nNoop: c_int = undefined;
            const nOldCol = pt.nCol;

            rc = sessionReinitTable(pSession, pt);
            if (rc == SQLITE_OK and pt.nCol != nOldCol) {
                rc = sessionUpdateChanges(pSession, pt);
            }

            sessionAppendTableHdr(&buf, bPatchset, pt, &rc);

            if (rc == SQLITE_OK) {
                rc = sessionSelectStmt(db, 0, pSession.zDb.?, zName, pt.bRowid, pt.nCol, pt.azCol.?, pt.abPK.?, &pSel, null);
            }

            nNoop = buf.nBuf;
            var i: c_int = 0;
            while (i < pt.nChange and rc == SQLITE_OK) : (i += 1) {
                var p: ?*SessionChange = pt.apChange.?[@intCast(i)];
                while (rc == SQLITE_OK and p != null) : (p = p.?.pNext) {
                    rc = sessionSelectBind(pSel, pt.nCol, pt.abPK.?, p.?);
                    if (rc != SQLITE_OK) continue;
                    if (sqlite3_step(pSel) == SQLITE_ROW) {
                        if (p.?.op == SQLITE_INSERT) {
                            sessionAppendByte(&buf, SQLITE_INSERT, &rc);
                            sessionAppendByte(&buf, p.?.bIndirect, &rc);
                            var iCol: c_int = 0;
                            while (iCol < pt.nCol) : (iCol += 1) {
                                sessionAppendCol(&buf, pSel, iCol, &rc);
                            }
                        } else {
                            rc = sessionAppendUpdate(&buf, bPatchset, pSel, p.?, pt.abPK.?);
                        }
                    } else if (p.?.op != SQLITE_INSERT) {
                        rc = sessionAppendDelete(&buf, bPatchset, p.?, pt.nCol, pt.abPK.?);
                    }
                    if (rc == SQLITE_OK) {
                        rc = sqlite3_reset(pSel);
                    }

                    if (xOutput != null and rc == SQLITE_OK and buf.nBuf > nNoop and buf.nBuf > sessions_strm_chunk_size) {
                        rc = xOutput.?(pOut, @ptrCast(buf.aBuf), buf.nBuf);
                        nNoop = -1;
                        buf.nBuf = 0;
                    }
                }
            }

            _ = sqlite3_finalize(pSel);
            if (buf.nBuf == nNoop) {
                buf.nBuf = nRewind;
            }
        }
    }

    if (rc == SQLITE_OK) {
        if (xOutput == null) {
            pnChangeset.?.* = buf.nBuf;
            ppChangeset.?.* = @ptrCast(buf.aBuf);
            buf.aBuf = null;
        } else if (buf.nBuf > 0) {
            rc = xOutput.?(pOut, @ptrCast(buf.aBuf), buf.nBuf);
        }
    }

    sqlite3_free(@ptrCast(buf.aBuf));
    _ = sqlite3_exec(db, "RELEASE changeset", null, null, null);
    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return rc;
}

export fn sqlite3session_changeset(pSession: *sqlite3_session, pnChangeset: ?*c_int, ppChangeset: ?*?*anyopaque) c_int {
    if (pnChangeset == null or ppChangeset == null) return SQLITE_MISUSE;
    return sessionGenerateChangeset(pSession, 0, null, null, pnChangeset, ppChangeset);
}

export fn sqlite3session_changeset_strm(pSession: *sqlite3_session, xOutput: XOutput, pOut: ?*anyopaque) c_int {
    if (xOutput == null) return SQLITE_MISUSE;
    return sessionGenerateChangeset(pSession, 0, xOutput, pOut, null, null);
}

export fn sqlite3session_patchset_strm(pSession: *sqlite3_session, xOutput: XOutput, pOut: ?*anyopaque) c_int {
    if (xOutput == null) return SQLITE_MISUSE;
    return sessionGenerateChangeset(pSession, 1, xOutput, pOut, null, null);
}

export fn sqlite3session_patchset(pSession: *sqlite3_session, pnPatchset: ?*c_int, ppPatchset: ?*?*anyopaque) c_int {
    if (pnPatchset == null or ppPatchset == null) return SQLITE_MISUSE;
    return sessionGenerateChangeset(pSession, 1, null, null, pnPatchset, ppPatchset);
}

export fn sqlite3session_enable(pSession: *sqlite3_session, bEnable: c_int) c_int {
    sqlite3_mutex_enter(sqlite3_db_mutex(pSession.db));
    if (bEnable >= 0) pSession.bEnable = bEnable;
    const ret = pSession.bEnable;
    sqlite3_mutex_leave(sqlite3_db_mutex(pSession.db));
    return ret;
}

export fn sqlite3session_indirect(pSession: *sqlite3_session, bIndirect: c_int) c_int {
    sqlite3_mutex_enter(sqlite3_db_mutex(pSession.db));
    if (bIndirect >= 0) pSession.bIndirect = bIndirect;
    const ret = pSession.bIndirect;
    sqlite3_mutex_leave(sqlite3_db_mutex(pSession.db));
    return ret;
}

export fn sqlite3session_isempty(pSession: *sqlite3_session) c_int {
    var ret: c_int = 0;
    sqlite3_mutex_enter(sqlite3_db_mutex(pSession.db));
    var pTab: ?*SessionTable = pSession.pTable;
    while (pTab != null and ret == 0) : (pTab = pTab.?.pNext) {
        ret = @intFromBool(pTab.?.nEntry > 0);
    }
    sqlite3_mutex_leave(sqlite3_db_mutex(pSession.db));
    return @intFromBool(ret == 0);
}

export fn sqlite3session_memory_used(pSession: *sqlite3_session) i64 {
    return pSession.nMalloc;
}

export fn sqlite3session_object_config(pSession: *sqlite3_session, op: c_int, pArg: ?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    switch (op) {
        SQLITE_SESSION_OBJCONFIG_SIZE => {
            const pi: *c_int = @ptrCast(@alignCast(pArg));
            const iArg = pi.*;
            if (iArg >= 0) {
                if (pSession.pTable != null) {
                    rc = SQLITE_MISUSE;
                } else {
                    pSession.bEnableSize = @intFromBool(iArg != 0);
                }
            }
            pi.* = pSession.bEnableSize;
        },
        SQLITE_SESSION_OBJCONFIG_ROWID => {
            const pi: *c_int = @ptrCast(@alignCast(pArg));
            const iArg = pi.*;
            if (iArg >= 0) {
                if (pSession.pTable != null) {
                    rc = SQLITE_MISUSE;
                } else {
                    pSession.bImplicitPK = @intFromBool(iArg != 0);
                }
            }
            pi.* = pSession.bImplicitPK;
        },
        else => rc = SQLITE_MISUSE,
    }
    return rc;
}

export fn sqlite3session_changeset_size(pSession: *sqlite3_session) i64 {
    return pSession.nMaxChangesetSize;
}

// ===========================================================================
// Changeset iterator
// ===========================================================================
fn sessionChangesetStart(
    pp: *?*sqlite3_changeset_iter,
    xInput: XInput,
    pIn: ?*anyopaque,
    nChangeset: c_int,
    pChangeset: ?*anyopaque,
    bInvert: c_int,
    bSkipEmpty: c_int,
) c_int {
    pp.* = null;
    const nByte: c_int = @sizeOf(sqlite3_changeset_iter);
    const pRet: ?*sqlite3_changeset_iter = @ptrCast(@alignCast(sqlite3_malloc(nByte)));
    if (pRet == null) return SQLITE_NOMEM;
    const p = pRet.?;
    memset0(@ptrCast(p), @sizeOf(sqlite3_changeset_iter));
    p.in.aData = @ptrCast(pChangeset);
    p.in.nData = nChangeset;
    p.in.xInput = xInput;
    p.in.pIn = pIn;
    p.in.bEof = if (xInput != null) 0 else 1;
    p.bInvert = bInvert;
    p.bSkipEmpty = bSkipEmpty;
    pp.* = p;
    return SQLITE_OK;
}

export fn sqlite3changeset_start(pp: *?*sqlite3_changeset_iter, nChangeset: c_int, pChangeset: ?*anyopaque) c_int {
    return sessionChangesetStart(pp, null, null, nChangeset, pChangeset, 0, 0);
}
export fn sqlite3changeset_start_v2(pp: *?*sqlite3_changeset_iter, nChangeset: c_int, pChangeset: ?*anyopaque, flags: c_int) c_int {
    const bInvert: c_int = @intFromBool((flags & SQLITE_CHANGESETSTART_INVERT) != 0);
    return sessionChangesetStart(pp, null, null, nChangeset, pChangeset, bInvert, 0);
}
export fn sqlite3changeset_start_strm(pp: *?*sqlite3_changeset_iter, xInput: XInput, pIn: ?*anyopaque) c_int {
    return sessionChangesetStart(pp, xInput, pIn, 0, null, 0, 0);
}
export fn sqlite3changeset_start_v2_strm(pp: *?*sqlite3_changeset_iter, xInput: XInput, pIn: ?*anyopaque, flags: c_int) c_int {
    const bInvert: c_int = @intFromBool((flags & SQLITE_CHANGESETSTART_INVERT) != 0);
    return sessionChangesetStart(pp, xInput, pIn, 0, null, bInvert, 0);
}

fn sessionDiscardData(pIn: *SessionInput) void {
    if (pIn.xInput != null and pIn.iCurrent >= sessions_strm_chunk_size) {
        const nMove = pIn.buf.nBuf - pIn.iCurrent;
        if (nMove > 0) {
            memmove(pIn.buf.aBuf.?, pIn.buf.aBuf.? + @as(usize, @intCast(pIn.iCurrent)), @intCast(nMove));
        }
        pIn.buf.nBuf -= pIn.iCurrent;
        pIn.iNext -= pIn.iCurrent;
        pIn.iCurrent = 0;
        pIn.nData = pIn.buf.nBuf;
    }
}

fn sessionInputBuffer(pIn: *SessionInput, nByte: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (pIn.xInput != null) {
        while (pIn.bEof == 0 and (pIn.iNext + nByte) >= pIn.nData and rc == SQLITE_OK) {
            var nNew: c_int = sessions_strm_chunk_size;
            if (pIn.bNoDiscard == 0) sessionDiscardData(pIn);
            if (SQLITE_OK == sessionBufferGrow(&pIn.buf, nNew, &rc)) {
                rc = pIn.xInput.?(pIn.pIn, @ptrCast(pIn.buf.aBuf.? + @as(usize, @intCast(pIn.buf.nBuf))), &nNew);
                if (nNew == 0) {
                    pIn.bEof = 1;
                } else {
                    pIn.buf.nBuf += nNew;
                }
            }
            pIn.aData = pIn.buf.aBuf;
            pIn.nData = pIn.buf.nBuf;
        }
    }
    return rc;
}

fn sessionSkipRecord(ppRec: *[*]u8, nCol: c_int) void {
    var aRec: [*]u8 = ppRec.*;
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        const eType: c_int = aRec[0];
        aRec += 1;
        if (eType == SQLITE_TEXT or eType == SQLITE_BLOB) {
            var nByte: c_int = undefined;
            aRec += @intCast(sessionVarintGet(aRec, &nByte));
            aRec += @intCast(nByte);
        } else if (eType == SQLITE_INTEGER or eType == SQLITE_FLOAT) {
            aRec += 8;
        }
    }
    ppRec.* = aRec;
}

fn sessionValueSetStr(pVal: ?*sqlite3_value, aData: [*]const u8, nData: c_int, enc: u8) c_int {
    const aCopy: ?[*]u8 = @ptrCast(sqlite3_malloc64(@as(u64, @intCast(nData)) + 1));
    if (aCopy == null) return SQLITE_NOMEM;
    memcpy(aCopy.?, aData, @intCast(nData));
    sqlite3ValueSetStr(pVal, nData, @ptrCast(aCopy.?), enc, @ptrCast(&sqlite3_free));
    return SQLITE_OK;
}

fn sessionReadRecord(pIn: *SessionInput, nCol: c_int, abPK: ?[*]u8, apOut: [*]?*sqlite3_value, pbEmpty: ?*c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (pbEmpty) |p| p.* = 1;
    var i: c_int = 0;
    while (i < nCol and rc == SQLITE_OK) : (i += 1) {
        var eType: c_int = 0;
        if (abPK != null and abPK.?[@intCast(i)] == 0) continue;
        rc = sessionInputBuffer(pIn, 9);
        if (rc == SQLITE_OK) {
            if (pIn.iNext >= pIn.nData) {
                rc = corruptBkpt();
            } else {
                eType = pIn.aData.?[@intCast(pIn.iNext)];
                pIn.iNext += 1;
                if (eType != 0) {
                    if (pbEmpty) |p| p.* = 0;
                    apOut[@intCast(i)] = sqlite3ValueNew(null);
                    if (apOut[@intCast(i)] == null) rc = SQLITE_NOMEM;
                }
            }
        }

        if (rc == SQLITE_OK) {
            const aVal: [*]u8 = pIn.aData.? + @as(usize, @intCast(pIn.iNext));
            if (eType == SQLITE_TEXT or eType == SQLITE_BLOB) {
                var nByte: c_int = undefined;
                const nRem = pIn.nData - pIn.iNext;
                pIn.iNext += sessionVarintGetSafe(aVal, nRem, &nByte);
                rc = sessionInputBuffer(pIn, nByte);
                if (rc == SQLITE_OK) {
                    if (nByte < 0 or nByte > pIn.nData - pIn.iNext) {
                        rc = corruptBkpt();
                    } else {
                        const enc: u8 = if (eType == SQLITE_TEXT) SQLITE_UTF8 else 0;
                        rc = sessionValueSetStr(apOut[@intCast(i)], pIn.aData.? + @as(usize, @intCast(pIn.iNext)), nByte, enc);
                        pIn.iNext += nByte;
                    }
                }
            }
            if (eType == SQLITE_INTEGER or eType == SQLITE_FLOAT) {
                if ((pIn.nData - pIn.iNext) < 8) {
                    rc = corruptBkpt();
                } else {
                    const v = sessionGetI64(aVal);
                    if (eType == SQLITE_INTEGER) {
                        sqlite3VdbeMemSetInt64(apOut[@intCast(i)], v);
                    } else {
                        const d: f64 = @bitCast(v);
                        sqlite3VdbeMemSetDouble(apOut[@intCast(i)], d);
                    }
                    pIn.iNext += 8;
                }
            }
        }
    }
    return rc;
}

fn sessionChangesetBufferTblhdr(pIn: *SessionInput, pnByte: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    var nCol: c_int = 0;
    var nRead: c_int = 0;

    rc = sessionInputBuffer(pIn, 9);
    if (rc == SQLITE_OK) {
        const nBuf = pIn.nData - pIn.iNext;
        nRead += sessionVarintGetSafe(pIn.aData.? + @as(usize, @intCast(pIn.iNext)), nBuf, &nCol);
        if (nCol < 0 or nCol > 65536) {
            rc = corruptBkpt();
        } else {
            rc = sessionInputBuffer(pIn, nRead + nCol + 100);
            nRead += nCol;
        }
    }

    while (rc == SQLITE_OK) {
        while ((pIn.iNext + nRead) < pIn.nData and pIn.aData.?[@intCast(pIn.iNext + nRead)] != 0) {
            nRead += 1;
        }
        if ((pIn.iNext + nRead) < pIn.nData) break;
        rc = sessionInputBuffer(pIn, nRead + 100);
        if (rc == SQLITE_OK and (pIn.iNext + nRead) >= pIn.nData) {
            rc = corruptBkpt();
        }
    }
    pnByte.* = nRead + 1;
    return rc;
}

fn sessionChangesetBufferRecord(pIn: *SessionInput, nCol: c_int, pnByte: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    var nByte: i64 = 0;
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nCol) : (i += 1) {
        rc = sessionInputBuffer(pIn, @intCast(nByte + 10));
        if (rc == SQLITE_OK) {
            if (pIn.iNext + nByte >= pIn.nData) {
                rc = corruptBkpt();
            } else {
                const eType: c_int = pIn.aData.?[@intCast(pIn.iNext + @as(c_int, @intCast(nByte)))];
                nByte += 1;
                if (eType == SQLITE_TEXT or eType == SQLITE_BLOB) {
                    var n: c_int = undefined;
                    const nRem = pIn.nData - (pIn.iNext + @as(c_int, @intCast(nByte)));
                    nByte += sessionVarintGetSafe(pIn.aData.? + @as(usize, @intCast(pIn.iNext + @as(c_int, @intCast(nByte)))), nRem, &n);
                    nByte += n;
                    rc = sessionInputBuffer(pIn, @intCast(nByte));
                } else if (eType == SQLITE_INTEGER or eType == SQLITE_FLOAT) {
                    nByte += 8;
                } else if (eType != 0 and eType != SQLITE_NULL) {
                    rc = corruptBkpt();
                }
            }
        }
        if (rc == SQLITE_OK and (pIn.iNext + @as(c_int, @intCast(nByte))) > pIn.nData) {
            rc = corruptBkpt();
        }
    }
    pnByte.* = @intCast(nByte);
    return rc;
}

fn sessionChangesetReadTblhdr(p: *sqlite3_changeset_iter) c_int {
    var rc: c_int = undefined;
    var nCopy: c_int = undefined;

    rc = sessionChangesetBufferTblhdr(&p.in, &nCopy);
    if (rc == SQLITE_OK) {
        var nByte: c_int = undefined;
        var nVarint: c_int = undefined;
        nVarint = sessionVarintGet(p.in.aData.? + @as(usize, @intCast(p.in.iNext)), &p.nCol);
        if (p.nCol > 0) {
            nCopy -= nVarint;
            p.in.iNext += nVarint;
            nByte = p.nCol * @sizeOf(?*sqlite3_value) * 2 + nCopy;
            p.tblhdr.nBuf = 0;
            _ = sessionBufferGrow(&p.tblhdr, nByte, &rc);
        } else {
            rc = corruptBkpt();
        }
    }

    if (rc == SQLITE_OK) {
        const iPK: usize = @sizeOf(?*sqlite3_value) * @as(usize, @intCast(p.nCol)) * 2;
        memset0(p.tblhdr.aBuf.?, iPK);
        memcpy(p.tblhdr.aBuf.? + iPK, p.in.aData.? + @as(usize, @intCast(p.in.iNext)), @intCast(nCopy));
        p.in.iNext += nCopy;
    }

    p.apValue = @ptrCast(@alignCast(p.tblhdr.aBuf));
    if (p.apValue == null) {
        p.abPK = null;
        p.zTab = null;
    } else {
        p.abPK = @ptrCast(p.apValue.? + @as(usize, @intCast(p.nCol * 2)));
        p.zTab = @ptrCast(p.abPK.? + @as(usize, @intCast(p.nCol)));
    }
    p.rc = rc;
    return rc;
}

fn sessionChangesetNextOne(p: *sqlite3_changeset_iter, paRec: ?*[*]u8, pnRec: ?*c_int, pbNew: ?*c_int, pbEmpty: ?*c_int) c_int {
    var i: c_int = undefined;
    var op: u8 = undefined;

    if (p.rc != SQLITE_OK) return p.rc;

    if (p.apValue) |apv| {
        i = 0;
        while (i < p.nCol * 2) : (i += 1) {
            sqlite3ValueFree(apv[@intCast(i)]);
        }
        memset0(@ptrCast(apv), @sizeOf(?*sqlite3_value) * @as(usize, @intCast(p.nCol)) * 2);
    }

    p.rc = sessionInputBuffer(&p.in, 2);
    if (p.rc != SQLITE_OK) return p.rc;

    p.in.iCurrent = p.in.iNext;
    sessionDiscardData(&p.in);

    if (p.in.iNext >= p.in.nData) return SQLITE_DONE;

    op = p.in.aData.?[@intCast(p.in.iNext)];
    p.in.iNext += 1;
    while (op == 'T' or op == 'P') {
        if (pbNew) |pn| pn.* = 1;
        p.bPatchset = @intFromBool(op == 'P');
        if (sessionChangesetReadTblhdr(p) != 0) return p.rc;
        p.rc = sessionInputBuffer(&p.in, 2);
        if (p.rc != 0) return p.rc;
        p.in.iCurrent = p.in.iNext;
        if (p.in.iNext >= p.in.nData) return SQLITE_DONE;
        op = p.in.aData.?[@intCast(p.in.iNext)];
        p.in.iNext += 1;
    }

    if (p.zTab == null or (p.bPatchset != 0 and p.bInvert != 0)) {
        p.rc = corruptBkpt();
        return p.rc;
    }

    if ((op != SQLITE_UPDATE and op != SQLITE_DELETE and op != SQLITE_INSERT) or (p.in.iNext >= p.in.nData)) {
        p.rc = corruptBkpt();
        return p.rc;
    }
    p.op = op;
    p.bIndirect = p.in.aData.?[@intCast(p.in.iNext)];
    p.in.iNext += 1;

    if (paRec) |pr| {
        var nVal: c_int = undefined;
        if (p.bPatchset == 0 and op == SQLITE_UPDATE) {
            nVal = p.nCol * 2;
        } else if (p.bPatchset != 0 and op == SQLITE_DELETE) {
            nVal = 0;
            i = 0;
            while (i < p.nCol) : (i += 1) {
                if (p.abPK.?[@intCast(i)] != 0) nVal += 1;
            }
        } else {
            nVal = p.nCol;
        }
        p.rc = sessionChangesetBufferRecord(&p.in, nVal, pnRec.?);
        if (p.rc != SQLITE_OK) return p.rc;
        pr.* = p.in.aData.? + @as(usize, @intCast(p.in.iNext));
        p.in.iNext += pnRec.?.*;
    } else {
        const apv = p.apValue.?;
        const apOld: [*]?*sqlite3_value = if (p.bInvert != 0) (apv + @as(usize, @intCast(p.nCol))) else apv;
        const apNew: [*]?*sqlite3_value = if (p.bInvert != 0) apv else (apv + @as(usize, @intCast(p.nCol)));

        if (p.op != SQLITE_INSERT and (p.bPatchset == 0 or p.op == SQLITE_DELETE)) {
            const abPK: ?[*]u8 = if (p.bPatchset != 0) p.abPK else null;
            p.rc = sessionReadRecord(&p.in, p.nCol, abPK, apOld, null);
            if (p.rc != SQLITE_OK) return p.rc;
        }

        if (p.op != SQLITE_DELETE) {
            p.rc = sessionReadRecord(&p.in, p.nCol, null, apNew, pbEmpty);
            if (p.rc != SQLITE_OK) return p.rc;
        }

        if ((p.bPatchset != 0 or p.bInvert != 0) and p.op == SQLITE_UPDATE) {
            i = 0;
            while (i < p.nCol) : (i += 1) {
                if (p.abPK.?[@intCast(i)] != 0) {
                    apv[@intCast(i)] = apv[@intCast(i + p.nCol)];
                    if (apv[@intCast(i)] == null) {
                        p.rc = corruptBkpt();
                        return p.rc;
                    }
                    apv[@intCast(i + p.nCol)] = null;
                }
            }
        } else if (p.bInvert != 0) {
            if (p.op == SQLITE_INSERT) {
                p.op = SQLITE_DELETE;
            } else if (p.op == SQLITE_DELETE) {
                p.op = SQLITE_INSERT;
            }
        }

        if (p.bPatchset == 0 and p.op == SQLITE_UPDATE) {
            i = 0;
            while (i < p.nCol) : (i += 1) {
                if (p.abPK.?[@intCast(i)] == 0 and apv[@intCast(i + p.nCol)] == null) {
                    sqlite3ValueFree(apv[@intCast(i)]);
                    apv[@intCast(i)] = null;
                }
            }
        }
    }

    return SQLITE_ROW;
}

fn sessionChangesetNext(p: *sqlite3_changeset_iter, paRec: ?*[*]u8, pnRec: ?*c_int, pbNew: ?*c_int) c_int {
    var bEmpty: c_int = undefined;
    var rc: c_int = undefined;
    while (true) {
        bEmpty = 0;
        rc = sessionChangesetNextOne(p, paRec, pnRec, pbNew, &bEmpty);
        if (!(rc == SQLITE_ROW and p.bSkipEmpty != 0 and bEmpty != 0)) break;
    }
    return rc;
}

export fn sqlite3changeset_next(p: *sqlite3_changeset_iter) c_int {
    return sessionChangesetNext(p, null, null, null);
}

export fn sqlite3changeset_op(pIter: *sqlite3_changeset_iter, pzTab: *?[*:0]const u8, pnCol: *c_int, pOp: *c_int, pbIndirect: ?*c_int) c_int {
    pOp.* = pIter.op;
    pnCol.* = pIter.nCol;
    pzTab.* = pIter.zTab;
    if (pbIndirect) |p| p.* = pIter.bIndirect;
    return SQLITE_OK;
}

export fn sqlite3changeset_pk(pIter: *sqlite3_changeset_iter, pabPK: *?[*]u8, pnCol: ?*c_int) c_int {
    pabPK.* = pIter.abPK;
    if (pnCol) |p| p.* = pIter.nCol;
    return SQLITE_OK;
}

export fn sqlite3changeset_old(pIter: *sqlite3_changeset_iter, iVal: c_int, ppValue: *?*sqlite3_value) c_int {
    if (pIter.op != SQLITE_UPDATE and pIter.op != SQLITE_DELETE) return SQLITE_MISUSE;
    if (iVal < 0 or iVal >= pIter.nCol) return SQLITE_RANGE;
    ppValue.* = pIter.apValue.?[@intCast(iVal)];
    return SQLITE_OK;
}

export fn sqlite3changeset_new(pIter: *sqlite3_changeset_iter, iVal: c_int, ppValue: *?*sqlite3_value) c_int {
    if (pIter.op != SQLITE_UPDATE and pIter.op != SQLITE_INSERT) return SQLITE_MISUSE;
    if (iVal < 0 or iVal >= pIter.nCol) return SQLITE_RANGE;
    ppValue.* = pIter.apValue.?[@intCast(pIter.nCol + iVal)];
    return SQLITE_OK;
}

inline fn sessionChangesetNew(pIter: *sqlite3_changeset_iter, iVal: c_int) ?*sqlite3_value {
    return pIter.apValue.?[@intCast(pIter.nCol + iVal)];
}
inline fn sessionChangesetOld(pIter: *sqlite3_changeset_iter, iVal: c_int) ?*sqlite3_value {
    return pIter.apValue.?[@intCast(iVal)];
}

export fn sqlite3changeset_conflict(pIter: *sqlite3_changeset_iter, iVal: c_int, ppValue: *?*sqlite3_value) c_int {
    if (pIter.pConflict == null) return SQLITE_MISUSE;
    if (iVal < 0 or iVal >= pIter.nCol) return SQLITE_RANGE;
    ppValue.* = sqlite3_column_value(pIter.pConflict, iVal);
    return SQLITE_OK;
}

export fn sqlite3changeset_fk_conflicts(pIter: *sqlite3_changeset_iter, pnOut: *c_int) c_int {
    if (pIter.pConflict != null or pIter.apValue != null) return SQLITE_MISUSE;
    pnOut.* = pIter.nCol;
    return SQLITE_OK;
}

export fn sqlite3changeset_finalize(p: ?*sqlite3_changeset_iter) c_int {
    var rc: c_int = SQLITE_OK;
    if (p) |pi| {
        rc = pi.rc;
        if (pi.apValue) |apv| {
            var i: c_int = 0;
            while (i < pi.nCol * 2) : (i += 1) sqlite3ValueFree(apv[@intCast(i)]);
        }
        sqlite3_free(@ptrCast(pi.tblhdr.aBuf));
        sqlite3_free(@ptrCast(pi.in.buf.aBuf));
        sqlite3_free(@ptrCast(pi));
    }
    return rc;
}

fn sessionChangesetInvert(pInput: *SessionInput, xOutput: XOutput, pOut: ?*anyopaque, pnInverted: ?*c_int, ppInverted: ?*?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    var sOut: SessionBuffer = .{};
    var nCol: c_int = 0;
    var abPK: ?[*]u8 = null;
    var apVal: ?[*]?*sqlite3_value = null;
    var sPK: SessionBuffer = .{};

    if (ppInverted) |p| {
        p.* = null;
        pnInverted.?.* = 0;
    }

    done: {
        while (true) {
            rc = sessionInputBuffer(pInput, 2);
            if (rc != 0) break :done;
            if (pInput.iNext + 1 >= pInput.nData) {
                if (pInput.iNext != pInput.nData) {
                    rc = corruptBkpt();
                    break :done;
                }
                break;
            }
            const eType = pInput.aData.?[@intCast(pInput.iNext)];

            switch (eType) {
                'T' => {
                    var nByte: c_int = undefined;
                    var nVar: c_int = undefined;
                    pInput.iNext += 1;
                    rc = sessionChangesetBufferTblhdr(pInput, &nByte);
                    if (rc != 0) break :done;
                    nVar = sessionVarintGet(pInput.aData.? + @as(usize, @intCast(pInput.iNext)), &nCol);
                    sPK.nBuf = 0;
                    sessionAppendBlob(&sPK, pInput.aData.? + @as(usize, @intCast(pInput.iNext + nVar)), nCol, &rc);
                    sessionAppendByte(&sOut, eType, &rc);
                    sessionAppendBlob(&sOut, pInput.aData.? + @as(usize, @intCast(pInput.iNext)), nByte, &rc);
                    if (rc != 0) break :done;
                    pInput.iNext += nByte;
                    sqlite3_free(@ptrCast(apVal));
                    apVal = null;
                    abPK = sPK.aBuf;
                },
                SQLITE_INSERT, SQLITE_DELETE => {
                    var nByte: c_int = undefined;
                    const bIndirect = pInput.aData.?[@intCast(pInput.iNext + 1)];
                    const eType2: c_int = if (eType == SQLITE_DELETE) SQLITE_INSERT else SQLITE_DELETE;
                    pInput.iNext += 2;
                    rc = sessionChangesetBufferRecord(pInput, nCol, &nByte);
                    sessionAppendByte(&sOut, @intCast(eType2), &rc);
                    sessionAppendByte(&sOut, bIndirect, &rc);
                    sessionAppendBlob(&sOut, pInput.aData.? + @as(usize, @intCast(pInput.iNext)), nByte, &rc);
                    pInput.iNext += nByte;
                    if (rc != 0) break :done;
                },
                SQLITE_UPDATE => {
                    var iCol: c_int = undefined;
                    if (apVal == null) {
                        apVal = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @sizeOf(?*sqlite3_value)) * @as(u64, @intCast(nCol)) * 2)));
                        if (apVal == null) {
                            rc = SQLITE_NOMEM;
                            break :done;
                        }
                        memset0(@ptrCast(apVal.?), @sizeOf(?*sqlite3_value) * @as(usize, @intCast(nCol)) * 2);
                    }

                    sessionAppendByte(&sOut, eType, &rc);
                    sessionAppendByte(&sOut, pInput.aData.?[@intCast(pInput.iNext + 1)], &rc);

                    pInput.iNext += 2;
                    rc = sessionReadRecord(pInput, nCol, null, apVal.?, null);
                    if (rc == SQLITE_OK) {
                        rc = sessionReadRecord(pInput, nCol, null, apVal.? + @as(usize, @intCast(nCol)), null);
                    }

                    iCol = 0;
                    while (iCol < nCol) : (iCol += 1) {
                        const pVal = apVal.?[@intCast(iCol + (if (abPK.?[@intCast(iCol)] != 0) @as(c_int, 0) else nCol))];
                        sessionAppendValue(&sOut, pVal, &rc);
                    }
                    iCol = 0;
                    while (iCol < nCol) : (iCol += 1) {
                        const pVal: ?*sqlite3_value = if (abPK.?[@intCast(iCol)] != 0) null else apVal.?[@intCast(iCol)];
                        sessionAppendValue(&sOut, pVal, &rc);
                    }
                    iCol = 0;
                    while (iCol < nCol * 2) : (iCol += 1) {
                        sqlite3ValueFree(apVal.?[@intCast(iCol)]);
                    }
                    memset0(@ptrCast(apVal.?), @sizeOf(?*sqlite3_value) * @as(usize, @intCast(nCol)) * 2);
                    if (rc != SQLITE_OK) break :done;
                },
                else => {
                    rc = corruptBkpt();
                    break :done;
                },
            }

            if (xOutput != null and sOut.nBuf >= sessions_strm_chunk_size) {
                rc = xOutput.?(pOut, sOut.aBuf, sOut.nBuf);
                sOut.nBuf = 0;
                if (rc != SQLITE_OK) break :done;
            }
        }

        if (pnInverted != null) {
            pnInverted.?.* = sOut.nBuf;
            ppInverted.?.* = @ptrCast(sOut.aBuf);
            sOut.aBuf = null;
        } else if (sOut.nBuf > 0) {
            rc = xOutput.?(pOut, sOut.aBuf, sOut.nBuf);
        }
    }

    sqlite3_free(@ptrCast(sOut.aBuf));
    sqlite3_free(@ptrCast(apVal));
    sqlite3_free(@ptrCast(sPK.aBuf));
    return rc;
}

export fn sqlite3changeset_invert(nChangeset: c_int, pChangeset: ?*const anyopaque, pnInverted: ?*c_int, ppInverted: ?*?*anyopaque) c_int {
    var sInput: SessionInput = .{};
    sInput.nData = nChangeset;
    sInput.aData = @constCast(@ptrCast(pChangeset));
    return sessionChangesetInvert(&sInput, null, null, pnInverted, ppInverted);
}

export fn sqlite3changeset_invert_strm(xInput: XInput, pIn: ?*anyopaque, xOutput: XOutput, pOut: ?*anyopaque) c_int {
    var sInput: SessionInput = .{};
    sInput.xInput = xInput;
    sInput.pIn = pIn;
    const rc = sessionChangesetInvert(&sInput, xOutput, pOut, null, null);
    sqlite3_free(@ptrCast(sInput.buf.aBuf));
    return rc;
}

// ===========================================================================
// Changeset apply
// ===========================================================================
fn sessionUpdateFind(pIter: *sqlite3_changeset_iter, p: *SessionApplyCtx, bPatchset: c_int, ppStmt: *?*sqlite3_stmt) c_int {
    var rc: c_int = SQLITE_OK;
    var pUp: ?*SessionUpdate = null;
    const nCol = pIter.nCol;
    const nU32 = @divTrunc(pIter.nCol + 33, 32);
    var ii: c_int = undefined;

    if (p.aUpdateMask == null) {
        p.aUpdateMask = @ptrCast(@alignCast(sqlite3_malloc(nU32 * @sizeOf(u32))));
        if (p.aUpdateMask == null) rc = SQLITE_NOMEM;
    }

    if (rc == SQLITE_OK) {
        memset0(@ptrCast(p.aUpdateMask.?), @intCast(nU32 * @sizeOf(u32)));
        rc = SQLITE_CORRUPT;
        ii = 0;
        while (ii < pIter.nCol) : (ii += 1) {
            if (sessionChangesetNew(pIter, ii) != null) {
                p.aUpdateMask.?[@intCast(@divTrunc(ii, 32))] |= (@as(u32, 1) << @intCast(@mod(ii, 32)));
                rc = SQLITE_OK;
            }
        }
    }

    if (rc == SQLITE_OK) {
        if (bPatchset != 0) p.aUpdateMask.?[@intCast(@divTrunc(nCol, 32))] |= (@as(u32, 1) << @intCast(@mod(nCol, 32)));

        if (p.pUp != null) {
            var nUp: c_int = 0;
            var pp: *?*SessionUpdate = &p.pUp;
            while (true) {
                nUp += 1;
                if (0 == memcmpn(@ptrCast(p.aUpdateMask.?), @ptrCast(pp.*.?.aMask.?), @intCast(nU32 * @sizeOf(u32)))) {
                    pUp = pp.*;
                    pp.* = pUp.?.pNext;
                    pUp.?.pNext = p.pUp;
                    p.pUp = pUp;
                    break;
                }
                if (pp.*.?.pNext != null) {
                    pp = &pp.*.?.pNext;
                } else {
                    if (nUp >= SESSION_UPDATE_CACHE_SZ) {
                        _ = sqlite3_finalize(pp.*.?.pStmt);
                        sqlite3_free(@ptrCast(pp.*));
                        pp.* = null;
                    }
                    break;
                }
            }
        }

        if (pUp == null) {
            const nByte: c_int = @sizeOf(SessionUpdate) * nU32 * @sizeOf(u32);
            const bStat1: c_int = @intFromBool(sqlite3_stricmp(pIter.zTab.?, "sqlite_stat1") == 0);
            pUp = @ptrCast(@alignCast(sqlite3_malloc(nByte)));
            if (pUp == null) {
                rc = SQLITE_NOMEM;
            } else {
                var zSep: [*:0]const u8 = "";
                var buf: SessionBuffer = .{};
                pUp.?.aMask = @ptrCast(@alignCast(@as([*]SessionUpdate, @ptrCast(pUp.?)) + 1));
                memcpy(@ptrCast(pUp.?.aMask.?), @ptrCast(p.aUpdateMask.?), @intCast(nU32 * @sizeOf(u32)));

                sessionAppendStr(&buf, "UPDATE main.", &rc);
                sessionAppendIdent(&buf, pIter.zTab.?, &rc);
                sessionAppendStr(&buf, " SET ", &rc);

                ii = 0;
                while (ii < pIter.nCol) : (ii += 1) {
                    if (p.abPK.?[@intCast(ii)] == 0 and sessionChangesetNew(pIter, ii) != null) {
                        sessionAppendStr(&buf, zSep, &rc);
                        sessionAppendIdent(&buf, p.azCol.?[@intCast(ii)].?, &rc);
                        sessionAppendStr(&buf, " = ?", &rc);
                        sessionAppendInteger(&buf, ii * 2 + 1, &rc);
                        zSep = ", ";
                    }
                }

                zSep = "";
                sessionAppendStr(&buf, " WHERE ", &rc);
                ii = 0;
                while (ii < pIter.nCol) : (ii += 1) {
                    if (p.abPK.?[@intCast(ii)] != 0 or (bPatchset == 0 and sessionChangesetOld(pIter, ii) != null)) {
                        sessionAppendStr(&buf, zSep, &rc);
                        if (bStat1 != 0 and ii == 1) {
                            sessionAppendStr(&buf, "idx IS CASE WHEN length(?4)=0 AND typeof(?4)='blob' THEN NULL ELSE ?4 END ", &rc);
                        } else {
                            sessionAppendIdent(&buf, p.azCol.?[@intCast(ii)].?, &rc);
                            sessionAppendStr(&buf, " IS ?", &rc);
                            sessionAppendInteger(&buf, ii * 2 + 2, &rc);
                        }
                        zSep = " AND ";
                    }
                }

                if (rc == SQLITE_OK) {
                    rc = sqlite3_prepare_v2(p.db, buf.aBuf.?, buf.nBuf, &pUp.?.pStmt, null);
                }

                if (rc != SQLITE_OK) {
                    sqlite3_free(@ptrCast(pUp));
                    pUp = null;
                } else {
                    pUp.?.pNext = p.pUp;
                    p.pUp = pUp;
                }
                sqlite3_free(@ptrCast(buf.aBuf));
            }
        }
    }

    if (pUp) |u| {
        ppStmt.* = u.pStmt;
    } else {
        ppStmt.* = null;
    }
    return rc;
}

fn sessionUpdateFree(p: *SessionApplyCtx) void {
    var pUp: ?*SessionUpdate = p.pUp;
    while (pUp) |u| {
        const pNext = u.pNext;
        _ = sqlite3_finalize(u.pStmt);
        sqlite3_free(@ptrCast(u));
        pUp = pNext;
    }
    p.pUp = null;
    sqlite3_free(@ptrCast(p.aUpdateMask));
    p.aUpdateMask = null;
}

fn sessionDeleteRow(db: ?*sqlite3, zTab: [*:0]const u8, p: *SessionApplyCtx) c_int {
    var zSep: [*:0]const u8 = "";
    var rc: c_int = SQLITE_OK;
    var buf: SessionBuffer = .{};
    var nPk: c_int = 0;

    sessionAppendStr(&buf, "DELETE FROM main.", &rc);
    sessionAppendIdent(&buf, zTab, &rc);
    sessionAppendStr(&buf, " WHERE ", &rc);

    var i: c_int = 0;
    while (i < p.nCol) : (i += 1) {
        if (p.abPK.?[@intCast(i)] != 0) {
            nPk += 1;
            sessionAppendStr(&buf, zSep, &rc);
            sessionAppendIdent(&buf, p.azCol.?[@intCast(i)].?, &rc);
            sessionAppendStr(&buf, " = ?", &rc);
            sessionAppendInteger(&buf, i + 1, &rc);
            zSep = " AND ";
        }
    }

    if (nPk < p.nCol) {
        sessionAppendStr(&buf, " AND (?", &rc);
        sessionAppendInteger(&buf, p.nCol + 1, &rc);
        sessionAppendStr(&buf, " OR ", &rc);

        zSep = "";
        i = 0;
        while (i < p.nCol) : (i += 1) {
            if (p.abPK.?[@intCast(i)] == 0) {
                sessionAppendStr(&buf, zSep, &rc);
                sessionAppendIdent(&buf, p.azCol.?[@intCast(i)].?, &rc);
                sessionAppendStr(&buf, " IS ?", &rc);
                sessionAppendInteger(&buf, i + 1, &rc);
                zSep = "AND ";
            }
        }
        sessionAppendStr(&buf, ")", &rc);
    }

    if (rc == SQLITE_OK) {
        rc = sessionPrepare(db, &p.pDelete, &p.zErr, @ptrCast(buf.aBuf.?));
    }
    sqlite3_free(@ptrCast(buf.aBuf));
    return rc;
}

fn sessionSelectRow(db: ?*sqlite3, zTab: [*:0]const u8, p: *SessionApplyCtx) c_int {
    return sessionSelectStmt(db, p.bIgnoreNoop, "main", zTab, p.bRowid, p.nCol, p.azCol.?, p.abPK.?, &p.pSelect, &p.zErr);
}

fn sessionInsertRow(db: ?*sqlite3, zTab: [*:0]const u8, p: *SessionApplyCtx) c_int {
    var rc: c_int = SQLITE_OK;
    var buf: SessionBuffer = .{};

    sessionAppendStr(&buf, "INSERT INTO main.", &rc);
    sessionAppendIdent(&buf, zTab, &rc);
    sessionAppendStr(&buf, "(", &rc);
    var i: c_int = 0;
    while (i < p.nCol) : (i += 1) {
        if (i != 0) sessionAppendStr(&buf, ", ", &rc);
        sessionAppendIdent(&buf, p.azCol.?[@intCast(i)].?, &rc);
    }
    sessionAppendStr(&buf, ") VALUES(?", &rc);
    i = 1;
    while (i < p.nCol) : (i += 1) {
        sessionAppendStr(&buf, ", ?", &rc);
    }
    sessionAppendStr(&buf, ")", &rc);

    if (rc == SQLITE_OK) {
        rc = sessionPrepare(db, &p.pInsert, &p.zErr, @ptrCast(buf.aBuf.?));
    }
    sqlite3_free(@ptrCast(buf.aBuf));
    return rc;
}

fn sessionStat1Sql(db: ?*sqlite3, p: *SessionApplyCtx) c_int {
    var rc = sessionSelectRow(db, "sqlite_stat1", p);
    if (rc == SQLITE_OK) {
        rc = sessionPrepare(db, &p.pInsert, null, "INSERT INTO main.sqlite_stat1 VALUES(?1, CASE WHEN length(?2)=0 AND typeof(?2)='blob' THEN NULL ELSE ?2 END, ?3)");
    }
    if (rc == SQLITE_OK) {
        rc = sessionPrepare(db, &p.pDelete, null, "DELETE FROM main.sqlite_stat1 WHERE tbl=?1 AND idx IS CASE WHEN length(?2)=0 AND typeof(?2)='blob' THEN NULL ELSE ?2 END AND (?4 OR stat IS ?3)");
    }
    return rc;
}

fn sessionBindValue(pStmt: ?*sqlite3_stmt, i: c_int, pVal: ?*sqlite3_value) c_int {
    const eType = sqlite3_value_type(pVal);
    // pVal->z is the Mem text/blob pointer (offset sqlite3_value_z in c_layout).
    const pz: ?*anyopaque = memValZ(pVal);
    if ((eType == SQLITE_TEXT or eType == SQLITE_BLOB) and pz == null) {
        return SQLITE_NOMEM;
    }
    return sqlite3_bind_value(pStmt, i, pVal);
}

const Mem_z: usize = if (@hasDecl(L, "sqlite3_value_z")) L.sqlite3_value_z else 8;
inline fn memValZ(pVal: ?*sqlite3_value) ?*anyopaque {
    const base: [*]const u8 = @ptrCast(pVal.?);
    const pp: *const ?*anyopaque = @ptrCast(@alignCast(base + Mem_z));
    return pp.*;
}

fn sessionBindRow(pIter: *sqlite3_changeset_iter, xValue: XValue, nCol: c_int, abPK: ?[*]u8, pStmt: ?*sqlite3_stmt) c_int {
    var rc: c_int = SQLITE_OK;
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nCol) : (i += 1) {
        if (abPK == null or abPK.?[@intCast(i)] != 0) {
            var pVal: ?*sqlite3_value = null;
            _ = xValue.?(pIter, i, &pVal);
            if (pVal == null) {
                rc = corruptBkpt();
            } else {
                rc = sessionBindValue(pStmt, i + 1, pVal);
            }
        }
    }
    return rc;
}

fn sessionSeekToRow(pIter: *sqlite3_changeset_iter, p: *SessionApplyCtx) c_int {
    const pSelect = p.pSelect;
    var rc: c_int = undefined;
    var nCol: c_int = undefined;
    var op: c_int = undefined;
    var zDummy: ?[*:0]const u8 = undefined;

    _ = sqlite3_clear_bindings(pSelect);
    _ = sqlite3changeset_op(pIter, &zDummy, &nCol, &op, null);
    rc = sessionBindRow(pIter, if (op == SQLITE_INSERT) sqlite3changeset_new else sqlite3changeset_old, nCol, p.abPK, pSelect);

    if (op != SQLITE_DELETE and p.bIgnoreNoop != 0) {
        var ii: c_int = 0;
        while (rc == SQLITE_OK and ii < nCol) : (ii += 1) {
            if (p.abPK.?[@intCast(ii)] == 0) {
                var pVal: ?*sqlite3_value = null;
                _ = sqlite3changeset_new(pIter, ii, &pVal);
                _ = sqlite3_bind_int(pSelect, ii + 1 + nCol, @intFromBool(pVal == null));
                if (pVal != null) rc = sessionBindValue(pSelect, ii + 1, pVal);
            }
        }
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_step(pSelect);
        if (rc != SQLITE_ROW) rc = sqlite3_reset(pSelect);
    }
    return rc;
}

fn sessionRebaseAdd(p: *SessionApplyCtx, eType: c_int, pIter: *sqlite3_changeset_iter) c_int {
    var rc: c_int = SQLITE_OK;
    if (p.bRebase != 0) {
        const eOp = pIter.op;
        if (p.bRebaseStarted == 0) {
            const zTab = pIter.zTab.?;
            sessionAppendByte(&p.rebase, 'T', &rc);
            sessionAppendVarint(&p.rebase, p.nCol, &rc);
            sessionAppendBlob(&p.rebase, p.abPK, p.nCol, &rc);
            sessionAppendBlob(&p.rebase, @ptrCast(zTab), @intCast(strlen0(zTab) + 1), &rc);
            p.bRebaseStarted = 1;
        }

        sessionAppendByte(&p.rebase, if (eOp == SQLITE_DELETE) @as(u8, SQLITE_DELETE) else @as(u8, SQLITE_INSERT), &rc);
        sessionAppendByte(&p.rebase, @intFromBool(eType == SQLITE_CHANGESET_REPLACE), &rc);
        var i: c_int = 0;
        while (i < p.nCol) : (i += 1) {
            var pVal: ?*sqlite3_value = null;
            if (eOp == SQLITE_DELETE or (eOp == SQLITE_UPDATE and p.abPK.?[@intCast(i)] != 0)) {
                _ = sqlite3changeset_old(pIter, i, &pVal);
            } else {
                _ = sqlite3changeset_new(pIter, i, &pVal);
            }
            sessionAppendValue(&p.rebase, pVal, &rc);
        }
    }
    return rc;
}

fn sessionConflictHandler(eType: c_int, p: *SessionApplyCtx, pIter: *sqlite3_changeset_iter, xConflict: XConflict, pCtx: ?*anyopaque, pbReplace: ?*c_int) c_int {
    var res: c_int = SQLITE_CHANGESET_OMIT;
    var rc: c_int = undefined;
    var nCol: c_int = undefined;
    var op: c_int = undefined;
    var zDummy: ?[*:0]const u8 = undefined;

    _ = sqlite3changeset_op(pIter, &zDummy, &nCol, &op, null);

    if (pbReplace != null) {
        rc = sessionSeekToRow(pIter, p);
    } else {
        rc = SQLITE_OK;
    }

    if (rc == SQLITE_ROW) {
        if (p.bIgnoreNoop == 0 or 0 == sqlite3_column_int(p.pSelect, sqlite3_column_count(p.pSelect) - 1)) {
            pIter.pConflict = p.pSelect;
            res = xConflict.?(pCtx, eType, pIter);
            pIter.pConflict = null;
        }
        rc = sqlite3_reset(p.pSelect);
    } else if (rc == SQLITE_OK) {
        if (p.bDeferConstraints != 0 and eType == SQLITE_CHANGESET_CONFLICT) {
            const aBlob: [*]u8 = pIter.in.aData.? + @as(usize, @intCast(pIter.in.iCurrent));
            const nBlob = pIter.in.iNext - pIter.in.iCurrent;
            sessionAppendBlob(&p.constraints, aBlob, nBlob, &rc);
            return rc;
        } else if (p.bIgnoreNoop == 0 or op != SQLITE_DELETE or eType == SQLITE_CHANGESET_CONFLICT) {
            res = xConflict.?(pCtx, eType + 1, pIter);
            if (res == SQLITE_CHANGESET_REPLACE) rc = SQLITE_MISUSE;
        }
    }

    if (rc == SQLITE_OK) {
        switch (res) {
            SQLITE_CHANGESET_REPLACE => pbReplace.?.* = 1,
            SQLITE_CHANGESET_OMIT => {},
            SQLITE_CHANGESET_ABORT => rc = SQLITE_ABORT,
            else => rc = SQLITE_MISUSE,
        }
        if (rc == SQLITE_OK) {
            rc = sessionRebaseAdd(p, res, pIter);
        }
    }
    return rc;
}

fn sessionApplyOneOp(pIter: *sqlite3_changeset_iter, p: *SessionApplyCtx, xConflict: XConflict, pCtx: ?*anyopaque, pbReplace: ?*c_int, pbRetry: ?*c_int) c_int {
    var zDummy: ?[*:0]const u8 = undefined;
    var op: c_int = undefined;
    var nCol: c_int = undefined;
    var rc: c_int = SQLITE_OK;

    _ = sqlite3changeset_op(pIter, &zDummy, &nCol, &op, null);

    if (op == SQLITE_DELETE) {
        const abPK: ?[*]u8 = if (pIter.bPatchset != 0) p.abPK else null;
        rc = sessionBindRow(pIter, sqlite3changeset_old, nCol, abPK, p.pDelete);
        if (rc == SQLITE_OK and sqlite3_bind_parameter_count(p.pDelete) > nCol) {
            rc = sqlite3_bind_int(p.pDelete, nCol + 1, @intFromBool(pbRetry == null or abPK != null));
        }
        if (rc != SQLITE_OK) return rc;

        _ = sqlite3_step(p.pDelete);
        rc = sqlite3_reset(p.pDelete);
        if (rc == SQLITE_OK and sqlite3_changes(p.db) == 0) {
            rc = sessionConflictHandler(SQLITE_CHANGESET_DATA, p, pIter, xConflict, pCtx, pbRetry);
        } else if ((rc & 0xff) == SQLITE_CONSTRAINT) {
            rc = sessionConflictHandler(SQLITE_CHANGESET_CONFLICT, p, pIter, xConflict, pCtx, null);
        }
    } else if (op == SQLITE_UPDATE) {
        var pUp: ?*sqlite3_stmt = null;
        const bPatchset: c_int = @intFromBool(pbRetry == null or pIter.bPatchset != 0);

        rc = sessionUpdateFind(pIter, p, bPatchset, &pUp);

        var i: c_int = 0;
        while (rc == SQLITE_OK and i < nCol) : (i += 1) {
            const pOld = sessionChangesetOld(pIter, i);
            const pNew = sessionChangesetNew(pIter, i);
            if (pOld != null and (p.abPK.?[@intCast(i)] != 0 or bPatchset == 0)) {
                rc = sessionBindValue(pUp, i * 2 + 2, pOld);
            }
            if (rc == SQLITE_OK and pNew != null) {
                rc = sessionBindValue(pUp, i * 2 + 1, pNew);
            }
        }
        if (rc != SQLITE_OK) return rc;

        _ = sqlite3_step(pUp);
        rc = sqlite3_reset(pUp);

        if (rc == SQLITE_OK and sqlite3_changes(p.db) == 0) {
            rc = sessionConflictHandler(SQLITE_CHANGESET_DATA, p, pIter, xConflict, pCtx, pbRetry);
        } else if ((rc & 0xff) == SQLITE_CONSTRAINT) {
            rc = sessionConflictHandler(SQLITE_CHANGESET_CONFLICT, p, pIter, xConflict, pCtx, null);
        }
    } else {
        if (p.bStat1 != 0) {
            rc = sessionSeekToRow(pIter, p);
            if (rc == SQLITE_ROW) {
                rc = SQLITE_CONSTRAINT;
                _ = sqlite3_reset(p.pSelect);
            }
        }

        if (rc == SQLITE_OK) {
            rc = sessionBindRow(pIter, sqlite3changeset_new, nCol, null, p.pInsert);
            if (rc != SQLITE_OK) return rc;
            _ = sqlite3_step(p.pInsert);
            rc = sqlite3_reset(p.pInsert);
        }

        if ((rc & 0xff) == SQLITE_CONSTRAINT) {
            rc = sessionConflictHandler(SQLITE_CHANGESET_CONFLICT, p, pIter, xConflict, pCtx, pbReplace);
        }
    }
    return rc;
}

fn sessionApplyOneWithRetry(db: ?*sqlite3, pIter: *sqlite3_changeset_iter, pApply: *SessionApplyCtx, xConflict: XConflict, pCtx: ?*anyopaque) c_int {
    var bReplace: c_int = 0;
    var bRetry: c_int = 0;
    var rc: c_int = undefined;

    rc = sessionApplyOneOp(pIter, pApply, xConflict, pCtx, &bReplace, &bRetry);
    if (rc == SQLITE_OK) {
        if (bRetry != 0) {
            rc = sessionApplyOneOp(pIter, pApply, xConflict, pCtx, null, null);
        } else if (bReplace != 0) {
            rc = sqlite3_exec(db, "SAVEPOINT replace_op", null, null, null);
            if (rc == SQLITE_OK) {
                rc = sessionBindRow(pIter, sqlite3changeset_new, pApply.nCol, pApply.abPK, pApply.pDelete);
                _ = sqlite3_bind_int(pApply.pDelete, pApply.nCol + 1, 1);
            }
            if (rc == SQLITE_OK) {
                _ = sqlite3_step(pApply.pDelete);
                rc = sqlite3_reset(pApply.pDelete);
            }
            if (rc == SQLITE_OK) {
                rc = sessionApplyOneOp(pIter, pApply, xConflict, pCtx, null, null);
            }
            if (rc == SQLITE_OK) {
                rc = sqlite3_exec(db, "RELEASE replace_op", null, null, null);
            }
        }
    }
    return rc;
}

fn sessionRetryIterInit(pRetry: *SessionBuffer, bPatchset: c_int, zTab: [*:0]const u8, pApply: *SessionApplyCtx, ppIter: *?*sqlite3_changeset_iter) c_int {
    var pRet: ?*sqlite3_changeset_iter = null;
    var rc: c_int = SQLITE_OK;

    rc = sessionChangesetStart(&pRet, null, null, pRetry.nBuf, @ptrCast(pRetry.aBuf), pApply.bInvertConstraints, 1);
    if (rc == SQLITE_OK) {
        const nByte: usize = 2 * @as(usize, @intCast(pApply.nCol)) * @sizeOf(?*sqlite3_value);
        pRet.?.bPatchset = bPatchset;
        pRet.?.zTab = @constCast(zTab);
        pRet.?.nCol = pApply.nCol;
        pRet.?.abPK = pApply.abPK;
        _ = sessionBufferGrow(&pRet.?.tblhdr, @intCast(nByte), &rc);
        pRet.?.apValue = @ptrCast(@alignCast(pRet.?.tblhdr.aBuf));
        if (rc == SQLITE_OK) {
            memset0(@ptrCast(pRet.?.apValue.?), nByte);
        } else {
            _ = sqlite3changeset_finalize(pRet);
            pRet = null;
        }
    }
    ppIter.* = pRet;
    return rc;
}

fn sessionApplyRetryBuffer(pRetry: *SessionBuffer, iSkip: c_int, db: ?*sqlite3, bPatchset: c_int, zTab: [*:0]const u8, pApply: *SessionApplyCtx, xConflict: XConflict, pCtx: ?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    var rc2: c_int = SQLITE_OK;
    var ii: c_int = 0;
    var pIter: ?*sqlite3_changeset_iter = null;

    rc = sessionRetryIterInit(pRetry, bPatchset, zTab, pApply, &pIter);

    ii = 0;
    while (rc == SQLITE_OK and SQLITE_ROW == sqlite3changeset_next(pIter.?)) : (ii += 1) {
        if (ii != iSkip) {
            rc = sessionApplyOneWithRetry(db, pIter.?, pApply, xConflict, pCtx);
        }
    }

    rc2 = sqlite3changeset_finalize(pIter);
    if (rc == SQLITE_OK) rc = rc2;
    return rc;
}

fn sessionTableIsWithoutRowid(db: ?*sqlite3, zTab: [*:0]const u8, pbWR: *c_int) c_int {
    var pList: ?*sqlite3_stmt = null;
    var rc: c_int = SQLITE_OK;

    const zSql = sqlite3_mprintf("PRAGMA table_list = %Q", zTab);
    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else {
        rc = sqlite3_prepare_v2(db, zSql.?, -1, &pList, null);
        sqlite3_free(@ptrCast(zSql));
    }

    if (rc == SQLITE_OK) {
        _ = sqlite3_step(pList);
        pbWR.* = sqlite3_column_int(pList, 4);
        rc = sqlite3_finalize(pList);
    }
    return rc;
}

fn sessionUpdateToDeleteInsert(db: ?*sqlite3, zTab: [*:0]const u8, pApply: *SessionApplyCtx, pUp: *sqlite3_changeset_iter, ppInsert: *?*sqlite3_stmt) c_int {
    var pRet: ?*sqlite3_stmt = null;
    var pSelect: ?*sqlite3_stmt = null;
    var rc: c_int = SQLITE_OK;
    var bWR: c_int = 0;

    rc = sessionTableIsWithoutRowid(db, zTab, &bWR);
    if (rc == SQLITE_OK) {
        var zSelect: ?[*:0]u8 = null;
        var zInsert: ?[*:0]u8 = null;
        var cols: SessionBuffer = .{};
        var insbind: SessionBuffer = .{};
        var pkcols: SessionBuffer = .{};
        var selbind: SessionBuffer = .{};

        var zComma: [*:0]const u8 = "";
        var zComma2: [*:0]const u8 = "";
        var ii: c_int = 0;
        while (ii < pApply.nCol) : (ii += 1) {
            sessionAppendStr(&cols, zComma, &rc);
            sessionAppendIdent(&cols, pApply.azCol.?[@intCast(ii)].?, &rc);
            sessionAppendStr(&insbind, zComma, &rc);
            sessionAppendStr(&insbind, "?", &rc);
            zComma = ", ";

            if (pApply.abPK.?[@intCast(ii)] != 0) {
                sessionAppendStr(&pkcols, zComma2, &rc);
                sessionAppendIdent(&pkcols, pApply.azCol.?[@intCast(ii)].?, &rc);
                sessionAppendStr(&selbind, zComma2, &rc);
                sessionAppendPrintf(&selbind, &rc, "?%d", .{ii + 1});
                zComma2 = ", ";
            }
        }
        if (bWR == 0) {
            sessionAppendStr(&cols, zComma, &rc);
            sessionAppendStr(&cols, SESSIONS_ROWID, &rc);
            sessionAppendStr(&insbind, zComma, &rc);
            sessionAppendStr(&insbind, "?", &rc);
        }

        if (rc == SQLITE_OK) {
            zSelect = sqlite3_mprintf("SELECT %s FROM %Q WHERE (%s) IS (%s)", cols.aBuf.?, zTab, pkcols.aBuf.?, selbind.aBuf.?);
            if (zSelect == null) rc = SQLITE_NOMEM;
        }
        if (rc == SQLITE_OK) {
            zInsert = sqlite3_mprintf("INSERT INTO %Q(%s) VALUES(%s)", zTab, cols.aBuf.?, insbind.aBuf.?);
            if (zInsert == null) rc = SQLITE_NOMEM;
        }

        if (rc == SQLITE_OK) rc = sessionPrepare(db, &pSelect, &pApply.zErr, zSelect.?);
        if (rc == SQLITE_OK) rc = sessionPrepare(db, &pRet, &pApply.zErr, zInsert.?);

        sqlite3_free(@ptrCast(zSelect));
        sqlite3_free(@ptrCast(zInsert));
        sqlite3_free(@ptrCast(cols.aBuf));
        sqlite3_free(@ptrCast(insbind.aBuf));
        sqlite3_free(@ptrCast(pkcols.aBuf));
        sqlite3_free(@ptrCast(selbind.aBuf));
    }

    if (rc == SQLITE_OK) {
        rc = sessionBindRow(pUp, sqlite3changeset_old, pApply.nCol, pApply.abPK, pSelect);
    }

    if (rc == SQLITE_OK and sqlite3_step(pSelect) == SQLITE_ROW) {
        var iCol: c_int = 0;
        while (iCol < pApply.nCol) : (iCol += 1) {
            var pVal = pUp.apValue.?[@intCast(iCol + pApply.nCol)];
            if (pVal == null) {
                pVal = sqlite3_column_value(pSelect, iCol);
            }
            rc = sqlite3_bind_value(pRet, iCol + 1, pVal);
        }
        if (bWR == 0) {
            _ = sqlite3_bind_int64(pRet, iCol + 1, sqlite3_column_int64(pSelect, iCol));
        }
    }
    sessionFinalizeStmt(pSelect, &rc);

    if (rc == SQLITE_OK) {
        rc = sessionBindRow(pUp, sqlite3changeset_old, pApply.nCol, pApply.abPK, pApply.pDelete);
        _ = sqlite3_bind_int(pApply.pDelete, pApply.nCol + 1, 1);
    }
    if (rc == SQLITE_OK) {
        _ = sqlite3_step(pApply.pDelete);
        rc = sqlite3_reset(pApply.pDelete);
    }

    if (rc != SQLITE_OK) {
        _ = sqlite3_finalize(pRet);
        pRet = null;
    }

    ppInsert.* = pRet;
    return rc;
}

fn sessionRetryConstraints(db: ?*sqlite3, bPatchset: c_int, zTab: ?[*:0]const u8, pApply: *SessionApplyCtx, xConflict: XConflict, pCtx: ?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    var iUpdate: c_int = 0;

    // Step (1)
    while (pApply.constraints.nBuf != 0) {
        var cons: SessionBuffer = pApply.constraints;
        pApply.constraints = .{};

        rc = sessionApplyRetryBuffer(&cons, -1, db, bPatchset, zTab.?, pApply, xConflict, pCtx);

        sqlite3_free(@ptrCast(cons.aBuf));
        if (rc != SQLITE_OK) break;
        if (pApply.constraints.nBuf >= cons.nBuf) break;
    }

    // Step (2)
    while (rc == SQLITE_OK and pApply.constraints.nBuf != 0 and pApply.bNoUpdateLoop == 0) {
        var cons: SessionBuffer = .{};
        var pUp: ?*sqlite3_changeset_iter = null;
        var pInsert: ?*sqlite3_stmt = null;
        var iSkip: c_int = 0;

        rc = sessionRetryIterInit(&pApply.constraints, bPatchset, zTab.?, pApply, &pUp);
        if (rc == SQLITE_OK) {
            var iThis: c_int = -1;
            while (SQLITE_ROW == sqlite3changeset_next(pUp.?)) {
                if (pUp.?.op == SQLITE_UPDATE) iThis += 1;
                if (iThis == iUpdate) break;
                iSkip += 1;
            }
            if (iThis == iUpdate) {
                rc = sqlite3_exec(db, "SAVEPOINT update_op", null, null, null);
                if (rc == SQLITE_OK) {
                    rc = sessionUpdateToDeleteInsert(db, zTab.?, pApply, pUp.?, &pInsert);
                }
            }
            _ = sqlite3changeset_finalize(pUp);
            if (iThis != iUpdate) break;
        }

        if (rc == SQLITE_OK) {
            cons = pApply.constraints;
            while (rc == SQLITE_OK and pApply.constraints.nBuf > 0) {
                var app: SessionBuffer = pApply.constraints;
                pApply.constraints = .{};
                rc = sessionApplyRetryBuffer(&app, iSkip, db, bPatchset, zTab.?, pApply, xConflict, pCtx);
                if (app.aBuf != cons.aBuf) {
                    sqlite3_free(@ptrCast(app.aBuf));
                }
                if (pApply.constraints.nBuf >= app.nBuf) break;
                iSkip = -1;
            }
        }

        iUpdate += 1;
        if (rc == SQLITE_OK) {
            _ = sqlite3_step(pInsert);
            rc = sqlite3_finalize(pInsert);
            if (rc == SQLITE_CONSTRAINT) {
                _ = sqlite3_exec(db, "ROLLBACK TO update_op", null, null, null);
                sqlite3_free(@ptrCast(pApply.constraints.aBuf));
                pApply.constraints = cons;
                cons = .{};
            } else if (rc == SQLITE_OK) {
                iUpdate = 0;
            }
            if (rc == SQLITE_OK) {
                rc = sqlite3_exec(db, "RELEASE update_op", null, null, null);
            }
        } else {
            _ = sqlite3_finalize(pInsert);
        }

        sqlite3_free(@ptrCast(cons.aBuf));
    }

    // Step (3)
    if (rc == SQLITE_OK and pApply.constraints.nBuf != 0) {
        var cons: SessionBuffer = pApply.constraints;
        pApply.constraints = .{};
        pApply.bDeferConstraints = 0;
        rc = sessionApplyRetryBuffer(&cons, -1, db, bPatchset, zTab.?, pApply, xConflict, pCtx);
        sqlite3_free(@ptrCast(cons.aBuf));
    }

    return rc;
}

fn sessionChangesetApply(
    db: ?*sqlite3,
    pIter: *sqlite3_changeset_iter,
    xFilter: XFilter,
    xFilterIter: XFilterIter,
    xConflict: XConflict,
    pCtx: ?*anyopaque,
    ppRebase: ?*?*anyopaque,
    pnRebase: ?*c_int,
    flags: c_int,
) c_int {
    var schemaMismatch: c_int = 0;
    var rc: c_int = SQLITE_OK;
    var zTab: ?[*:0]const u8 = null;
    var nTab: c_int = 0;
    var sApply: SessionApplyCtx = std.mem.zeroes(SessionApplyCtx);
    var bPatchset: c_int = undefined;
    const savedFlag: u64 = dbFlags(db) & SQLITE_FkNoAction;

    sqlite3_mutex_enter(sqlite3_db_mutex(db));
    if ((flags & SQLITE_CHANGESETAPPLY_FKNOACTION) != 0) {
        setDbFlags(db, dbFlags(db) | SQLITE_FkNoAction);
        bumpSchemaCookie(db, -32);
    }

    pIter.in.bNoDiscard = 1;
    sApply.bRebase = @intFromBool(ppRebase != null and pnRebase != null);
    sApply.bInvertConstraints = @intFromBool((flags & SQLITE_CHANGESETAPPLY_INVERT) != 0);
    sApply.bIgnoreNoop = @intFromBool((flags & SQLITE_CHANGESETAPPLY_IGNORENOOP) != 0);
    sApply.bNoUpdateLoop = @intFromBool((flags & SQLITE_CHANGESETAPPLY_NOUPDATELOOP) != 0);
    if ((flags & SQLITE_CHANGESETAPPLY_NOSAVEPOINT) == 0) {
        rc = sqlite3_exec(db, "SAVEPOINT changeset_apply", null, null, null);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_exec(db, "PRAGMA defer_foreign_keys = 1", null, null, null);
    }
    while (rc == SQLITE_OK and SQLITE_ROW == sqlite3changeset_next(pIter)) {
        var nCol: c_int = undefined;
        var op: c_int = undefined;
        var zNew: ?[*:0]const u8 = undefined;

        _ = sqlite3changeset_op(pIter, &zNew, &nCol, &op, null);

        if (zTab == null or sqlite3_strnicmp(zNew.?, zTab.?, nTab + 1) != 0) {
            var abPK: ?[*]u8 = null;

            rc = sessionRetryConstraints(db, pIter.bPatchset, zTab, &sApply, xConflict, pCtx);
            if (rc != SQLITE_OK) break;

            sessionUpdateFree(&sApply);
            sqlite3_free(@ptrCast(sApply.azCol));
            _ = sqlite3_finalize(sApply.pDelete);
            _ = sqlite3_finalize(sApply.pInsert);
            _ = sqlite3_finalize(sApply.pSelect);
            sApply.db = db;
            sApply.pDelete = null;
            sApply.pInsert = null;
            sApply.pSelect = null;
            sApply.nCol = 0;
            sApply.azCol = null;
            sApply.abPK = null;
            sApply.bStat1 = 0;
            sApply.bDeferConstraints = 1;
            sApply.bRebaseStarted = 0;
            sApply.bRowid = 0;
            sApply.constraints = .{};

            schemaMismatch = @intFromBool(xFilter != null and 0 == xFilter.?(pCtx, zNew.?));
            if (schemaMismatch != 0) {
                zTab = sqlite3_mprintf("%s", zNew.?);
                if (zTab == null) {
                    rc = SQLITE_NOMEM;
                    break;
                }
                nTab = @intCast(strlen0(zTab.?));
                sApply.azCol = @ptrCast(@alignCast(@constCast(zTab.?)));
            } else {
                var nMinCol: c_int = 0;
                var i: c_int = 0;

                _ = sqlite3changeset_pk(pIter, &abPK, null);
                rc = sessionTableInfo(null, db, "main", zNew.?, &sApply.nCol, null, &zTab, &sApply.azCol, null, null, &sApply.abPK, &sApply.bRowid);
                if (rc != SQLITE_OK) break;
                i = 0;
                while (i < sApply.nCol) : (i += 1) {
                    if (sApply.abPK.?[@intCast(i)] != 0) nMinCol = i + 1;
                }

                if (sApply.nCol == 0) {
                    schemaMismatch = 1;
                    sqlite3_log(SQLITE_SCHEMA, "sqlite3changeset_apply(): no such table: %s", zTab.?);
                } else if (sApply.nCol < nCol) {
                    schemaMismatch = 1;
                    sqlite3_log(SQLITE_SCHEMA, "sqlite3changeset_apply(): table %s has %d columns, expected %d or more", zTab.?, sApply.nCol, nCol);
                } else if (nCol < nMinCol or memcmpn(sApply.abPK.?, abPK.?, @intCast(nCol)) != 0) {
                    schemaMismatch = 1;
                    sqlite3_log(SQLITE_SCHEMA, "sqlite3changeset_apply(): primary key mismatch for table %s", zTab.?);
                } else {
                    sApply.nCol = nCol;
                    if (0 == sqlite3_stricmp(zTab.?, "sqlite_stat1")) {
                        rc = sessionStat1Sql(db, &sApply);
                        if (rc != 0) break;
                        sApply.bStat1 = 1;
                    } else {
                        rc = sessionSelectRow(db, zTab.?, &sApply);
                        if (rc == 0) rc = sessionDeleteRow(db, zTab.?, &sApply);
                        if (rc == 0) rc = sessionInsertRow(db, zTab.?, &sApply);
                        if (rc != 0) break;
                        sApply.bStat1 = 0;
                    }
                }
                nTab = sqlite3Strlen30(zTab.?);
            }
        }

        if (schemaMismatch != 0) continue;
        if (xFilterIter != null and 0 == xFilterIter.?(pCtx, pIter)) continue;

        rc = sessionApplyOneWithRetry(db, pIter, &sApply, xConflict, pCtx);
    }

    bPatchset = pIter.bPatchset;
    if (rc == SQLITE_OK) {
        rc = sqlite3changeset_finalize(pIter);
    } else {
        _ = sqlite3changeset_finalize(pIter);
    }

    if (rc == SQLITE_OK) {
        rc = sessionRetryConstraints(db, bPatchset, zTab, &sApply, xConflict, pCtx);
    }

    if (rc == SQLITE_OK) {
        var nFk: c_int = undefined;
        var notUsed: c_int = undefined;
        _ = sqlite3_db_status(db, SQLITE_DBSTATUS_DEFERRED_FKS, &nFk, &notUsed, 0);
        if (nFk != 0) {
            var sIter: sqlite3_changeset_iter = std.mem.zeroes(sqlite3_changeset_iter);
            sIter.nCol = nFk;
            const res = xConflict.?(pCtx, SQLITE_CHANGESET_FOREIGN_KEY, &sIter);
            if (res != SQLITE_CHANGESET_OMIT) {
                rc = SQLITE_CONSTRAINT;
            }
        }
    }

    {
        const rc2 = sqlite3_exec(db, "PRAGMA defer_foreign_keys = 0", null, null, null);
        if (rc == SQLITE_OK) rc = rc2;
    }

    if ((flags & SQLITE_CHANGESETAPPLY_NOSAVEPOINT) == 0) {
        if (rc == SQLITE_OK) {
            rc = sqlite3_exec(db, "RELEASE changeset_apply", null, null, null);
        }
        if (rc != SQLITE_OK) {
            _ = sqlite3_exec(db, "ROLLBACK TO changeset_apply", null, null, null);
            _ = sqlite3_exec(db, "RELEASE changeset_apply", null, null, null);
        }
    }

    if (rc == SQLITE_OK and bPatchset == 0 and sApply.bRebase != 0) {
        ppRebase.?.* = @ptrCast(sApply.rebase.aBuf);
        pnRebase.?.* = sApply.rebase.nBuf;
        sApply.rebase.aBuf = null;
    }
    sessionUpdateFree(&sApply);
    _ = sqlite3_finalize(sApply.pInsert);
    _ = sqlite3_finalize(sApply.pDelete);
    _ = sqlite3_finalize(sApply.pSelect);
    sqlite3_free(@ptrCast(sApply.azCol));
    sqlite3_free(@ptrCast(sApply.constraints.aBuf));
    sqlite3_free(@ptrCast(sApply.rebase.aBuf));

    if ((flags & SQLITE_CHANGESETAPPLY_FKNOACTION) != 0 and savedFlag == 0) {
        setDbFlags(db, dbFlags(db) & ~SQLITE_FkNoAction);
        bumpSchemaCookie(db, -32);
    }

    _ = sqlite3_set_errmsg(db, rc, sApply.zErr);
    sqlite3_free(@ptrCast(sApply.zErr));

    sqlite3_mutex_leave(sqlite3_db_mutex(db));
    return rc;
}

// --- sqlite3 struct field accessors (c_layout offsets) ---
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
const Db_pSchema_off: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;
const Schema_schema_cookie_off: usize = if (@hasDecl(L, "Schema_schema_cookie")) L.Schema_schema_cookie else 0;

inline fn dbFlags(db: ?*sqlite3) u64 {
    const base: [*]const u8 = @ptrCast(db.?);
    const p: *const u64 = @ptrCast(@alignCast(base + sqlite3_flags_off));
    return p.*;
}
inline fn setDbFlags(db: ?*sqlite3, v: u64) void {
    const base: [*]u8 = @ptrCast(db.?);
    const p: *u64 = @ptrCast(@alignCast(base + sqlite3_flags_off));
    p.* = v;
}
inline fn bumpSchemaCookie(db: ?*sqlite3, delta: c_int) void {
    // db->aDb[0].pSchema->schema_cookie += delta
    const base: [*]const u8 = @ptrCast(db.?);
    const aDb: [*]u8 = @as(*const [*]u8, @ptrCast(@alignCast(base + sqlite3_aDb_off))).*;
    const pSchemaPtr: *const ?*anyopaque = @ptrCast(@alignCast(aDb + Db_pSchema_off));
    const pSchema: [*]u8 = @ptrCast(pSchemaPtr.*.?);
    const pCookie: *c_int = @ptrCast(@alignCast(pSchema + Schema_schema_cookie_off));
    pCookie.* +%= delta;
}

fn sessionChangesetApplyV23(
    db: ?*sqlite3,
    nChangeset: c_int,
    pChangeset: ?*anyopaque,
    xInput: XInput,
    pIn: ?*anyopaque,
    xFilter: XFilter,
    xFilterIter: XFilterIter,
    xConflict: XConflict,
    pCtx: ?*anyopaque,
    ppRebase: ?*?*anyopaque,
    pnRebase: ?*c_int,
    flags: c_int,
) c_int {
    var pIter: ?*sqlite3_changeset_iter = null;
    const bInverse: c_int = @intFromBool((flags & SQLITE_CHANGESETAPPLY_INVERT) != 0);
    var rc = sessionChangesetStart(&pIter, xInput, pIn, nChangeset, pChangeset, bInverse, 1);
    if (rc == SQLITE_OK) {
        rc = sessionChangesetApply(db, pIter.?, xFilter, xFilterIter, xConflict, pCtx, ppRebase, pnRebase, flags);
    }
    return rc;
}

export fn sqlite3changeset_apply_v2(db: ?*sqlite3, nChangeset: c_int, pChangeset: ?*anyopaque, xFilter: XFilter, xConflict: XConflict, pCtx: ?*anyopaque, ppRebase: ?*?*anyopaque, pnRebase: ?*c_int, flags: c_int) c_int {
    return sessionChangesetApplyV23(db, nChangeset, pChangeset, null, null, xFilter, null, xConflict, pCtx, ppRebase, pnRebase, flags);
}
export fn sqlite3changeset_apply_v3(db: ?*sqlite3, nChangeset: c_int, pChangeset: ?*anyopaque, xFilter: XFilterIter, xConflict: XConflict, pCtx: ?*anyopaque, ppRebase: ?*?*anyopaque, pnRebase: ?*c_int, flags: c_int) c_int {
    return sessionChangesetApplyV23(db, nChangeset, pChangeset, null, null, null, xFilter, xConflict, pCtx, ppRebase, pnRebase, flags);
}
export fn sqlite3changeset_apply(db: ?*sqlite3, nChangeset: c_int, pChangeset: ?*anyopaque, xFilter: XFilter, xConflict: XConflict, pCtx: ?*anyopaque) c_int {
    return sessionChangesetApplyV23(db, nChangeset, pChangeset, null, null, xFilter, null, xConflict, pCtx, null, null, 0);
}
export fn sqlite3changeset_apply_v3_strm(db: ?*sqlite3, xInput: XInput, pIn: ?*anyopaque, xFilter: XFilterIter, xConflict: XConflict, pCtx: ?*anyopaque, ppRebase: ?*?*anyopaque, pnRebase: ?*c_int, flags: c_int) c_int {
    return sessionChangesetApplyV23(db, 0, null, xInput, pIn, null, xFilter, xConflict, pCtx, ppRebase, pnRebase, flags);
}
export fn sqlite3changeset_apply_v2_strm(db: ?*sqlite3, xInput: XInput, pIn: ?*anyopaque, xFilter: XFilter, xConflict: XConflict, pCtx: ?*anyopaque, ppRebase: ?*?*anyopaque, pnRebase: ?*c_int, flags: c_int) c_int {
    return sessionChangesetApplyV23(db, 0, null, xInput, pIn, xFilter, null, xConflict, pCtx, ppRebase, pnRebase, flags);
}
export fn sqlite3changeset_apply_strm(db: ?*sqlite3, xInput: XInput, pIn: ?*anyopaque, xFilter: XFilter, xConflict: XConflict, pCtx: ?*anyopaque) c_int {
    return sessionChangesetApplyV23(db, 0, null, xInput, pIn, xFilter, null, xConflict, pCtx, null, null, 0);
}

// ===========================================================================
// Changegroup
// ===========================================================================
fn sessionChangeMerge(
    pTab: *SessionTable,
    bRebase: c_int,
    bPatchset: c_int,
    pExist: ?*SessionChange,
    op2: c_int,
    bIndirect: c_int,
    aRec: [*]u8,
    nRec: c_int,
    ppNew: *?*SessionChange,
) c_int {
    var pNew: ?*SessionChange = null;
    var rc: c_int = SQLITE_OK;

    if (pExist == null) {
        pNew = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @sizeOf(SessionChange)) + @as(u64, @intCast(nRec)))));
        if (pNew == null) return SQLITE_NOMEM;
        const pn = pNew.?;
        memset0(@ptrCast(pn), @sizeOf(SessionChange));
        pn.op = @intCast(op2);
        pn.bIndirect = @intCast(bIndirect);
        pn.aRecord = @ptrCast(@as([*]SessionChange, @ptrCast(pn)) + 1);
        if (bIndirect == 0 or bRebase == 0) {
            pn.nRecord = nRec;
            memcpy(pn.aRecord.?, aRec, @intCast(nRec));
        } else {
            var pIn: [*]u8 = aRec;
            var pOut: [*]u8 = pn.aRecord.?;
            var i: c_int = 0;
            while (i < pTab.nCol) : (i += 1) {
                const nIn = sessionSerialLen(pIn);
                if (pIn[0] == 0) {
                    pOut[0] = 0;
                    pOut += 1;
                } else if (pTab.abPK.?[@intCast(i)] == 0) {
                    pOut[0] = 0xFF;
                    pOut += 1;
                } else {
                    memcpy(pOut, pIn, @intCast(nIn));
                    pOut += @intCast(nIn);
                }
                pIn += @intCast(nIn);
            }
            pn.nRecord = @intCast(@intFromPtr(pOut) - @intFromPtr(pn.aRecord.?));
        }
    } else if (bRebase != 0) {
        const pe = pExist.?;
        if (pe.op == SQLITE_DELETE and pe.bIndirect != 0) {
            ppNew.* = pExist;
            return SQLITE_OK;
        } else {
            const nByte: i64 = nRec + pe.nRecord + @as(i64, @sizeOf(SessionChange));
            pNew = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
            if (pNew == null) {
                rc = SQLITE_NOMEM;
            } else {
                const pn = pNew.?;
                var a1: [*]u8 = pe.aRecord.?;
                var a2: [*]u8 = aRec;
                memset0(@ptrCast(pn), @intCast(nByte));
                pn.bIndirect = @intCast(@intFromBool(bIndirect != 0 or pe.bIndirect != 0));
                pn.op = @intCast(op2);
                pn.aRecord = @ptrCast(@as([*]SessionChange, @ptrCast(pn)) + 1);
                var pOut: [*]u8 = pn.aRecord.?;
                var i: c_int = 0;
                while (i < pTab.nCol) : (i += 1) {
                    const n1 = sessionSerialLen(a1);
                    const n2 = sessionSerialLen(a2);
                    if (a1[0] == 0xFF or (pTab.abPK.?[@intCast(i)] == 0 and bIndirect != 0)) {
                        pOut[0] = 0xFF;
                        pOut += 1;
                    } else if (a2[0] == 0) {
                        memcpy(pOut, a1, @intCast(n1));
                        pOut += @intCast(n1);
                    } else {
                        memcpy(pOut, a2, @intCast(n2));
                        pOut += @intCast(n2);
                    }
                    a1 += @intCast(n1);
                    a2 += @intCast(n2);
                }
                pn.nRecord = @intCast(@intFromPtr(pOut) - @intFromPtr(pn.aRecord.?));
            }
            sqlite3_free(@ptrCast(pExist));
        }
    } else {
        const pe = pExist.?;
        const op1 = pe.op;
        if ((op1 == SQLITE_INSERT and op2 == SQLITE_INSERT) or (op1 == SQLITE_UPDATE and op2 == SQLITE_INSERT) or (op1 == SQLITE_DELETE and op2 == SQLITE_UPDATE) or (op1 == SQLITE_DELETE and op2 == SQLITE_DELETE)) {
            pNew = pExist;
        } else if (op1 == SQLITE_INSERT and op2 == SQLITE_DELETE) {
            sqlite3_free(@ptrCast(pExist));
        } else {
            const aExist: [*]u8 = pe.aRecord.?;
            const nByte: i64 = @as(i64, @sizeOf(SessionChange)) + pe.nRecord + nRec;
            pNew = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
            if (pNew == null) {
                sqlite3_free(@ptrCast(pExist));
                return SQLITE_NOMEM;
            }
            const pn = pNew.?;
            memset0(@ptrCast(pn), @sizeOf(SessionChange));
            pn.bIndirect = @intCast(@intFromBool(bIndirect != 0 and pe.bIndirect != 0));
            pn.aRecord = @ptrCast(@as([*]SessionChange, @ptrCast(pn)) + 1);
            var aCsr: [*]u8 = pn.aRecord.?;

            if (op1 == SQLITE_INSERT) { // INSERT + UPDATE
                var a1: [*]u8 = aRec;
                pn.op = SQLITE_INSERT;
                if (bPatchset == 0) sessionSkipRecord(&a1, pTab.nCol);
                sessionMergeRecord(&aCsr, pTab.nCol, aExist, a1);
            } else if (op1 == SQLITE_DELETE) { // DELETE + INSERT
                pn.op = SQLITE_UPDATE;
                if (bPatchset != 0) {
                    memcpy(aCsr, aRec, @intCast(nRec));
                    aCsr += @intCast(nRec);
                } else {
                    if (0 == sessionMergeUpdate(&aCsr, pTab, bPatchset, aExist, null, aRec, null)) {
                        sqlite3_free(@ptrCast(pNew));
                        pNew = null;
                    }
                }
            } else if (op2 == SQLITE_UPDATE) { // UPDATE + UPDATE
                var a1: [*]u8 = aExist;
                var a2: [*]u8 = aRec;
                if (bPatchset == 0) {
                    sessionSkipRecord(&a1, pTab.nCol);
                    sessionSkipRecord(&a2, pTab.nCol);
                }
                pn.op = SQLITE_UPDATE;
                if (0 == sessionMergeUpdate(&aCsr, pTab, bPatchset, aRec, aExist, a1, a2)) {
                    sqlite3_free(@ptrCast(pNew));
                    pNew = null;
                }
            } else { // UPDATE + DELETE
                pn.op = SQLITE_DELETE;
                if (bPatchset != 0) {
                    memcpy(aCsr, aRec, @intCast(nRec));
                    aCsr += @intCast(nRec);
                } else {
                    sessionMergeRecord(&aCsr, pTab.nCol, aRec, aExist);
                }
            }

            if (pNew) |pnn| {
                pnn.nRecord = @intCast(@intFromPtr(aCsr) - @intFromPtr(pnn.aRecord.?));
            }
            sqlite3_free(@ptrCast(pExist));
        }
    }

    ppNew.* = pNew;
    return rc;
}

fn sessionChangesetCheckCompat(pTab: *SessionTable, nCol: c_int, abPK: [*]u8) c_int {
    if (pTab.azCol != null and nCol < pTab.nCol) {
        var ii: c_int = 0;
        while (ii < pTab.nCol) : (ii += 1) {
            const bPK: u8 = if (ii < nCol) abPK[@intCast(ii)] else 0;
            if (pTab.abPK.?[@intCast(ii)] != bPK) return 0;
        }
        return 1;
    }
    return @intFromBool(pTab.nCol == nCol and 0 == memcmpn(abPK, pTab.abPK.?, @intCast(nCol)));
}

fn sessionChangesetExtendRecord(pGrp: *sqlite3_changegroup, pTab: *SessionTable, nCol: c_int, op: c_int, aRec: [*]const u8, nRec: c_int, pOut: *SessionBuffer) c_int {
    var rc: c_int = SQLITE_OK;
    var ii: c_int = 0;

    pOut.nBuf = 0;
    if (op == SQLITE_INSERT or (op == SQLITE_DELETE and pGrp.bPatch == 0)) {
        sessionAppendBlob(pOut, aRec, nRec, &rc);
        if (rc == SQLITE_OK and pTab.pDfltStmt == null) {
            rc = sessionPrepareDfltStmt(pGrp.db, pTab, &pTab.pDfltStmt);
            if (rc == SQLITE_OK and SQLITE_ROW != sqlite3_step(pTab.pDfltStmt)) {
                rc = sqlite3_errcode(pGrp.db);
            }
        }
        ii = nCol;
        while (rc == SQLITE_OK and ii < pTab.nCol) : (ii += 1) {
            const eType = sqlite3_column_type(pTab.pDfltStmt, ii);
            sessionAppendByte(pOut, @intCast(eType), &rc);
            switch (eType) {
                SQLITE_FLOAT, SQLITE_INTEGER => {
                    if (SQLITE_OK == sessionBufferGrow(pOut, 8, &rc)) {
                        if (eType == SQLITE_INTEGER) {
                            const iVal = sqlite3_column_int64(pTab.pDfltStmt, ii);
                            sessionPutI64(pOut.aBuf.? + @as(usize, @intCast(pOut.nBuf)), iVal);
                        } else {
                            const rVal = sqlite3_column_double(pTab.pDfltStmt, ii);
                            sessionPutDouble(pOut.aBuf.? + @as(usize, @intCast(pOut.nBuf)), rVal);
                        }
                        pOut.nBuf += 8;
                    }
                },
                SQLITE_BLOB, SQLITE_TEXT => {
                    const n = sqlite3_column_bytes(pTab.pDfltStmt, ii);
                    sessionAppendVarint(pOut, n, &rc);
                    if (eType == SQLITE_TEXT) {
                        const z = sqlite3_column_text(pTab.pDfltStmt, ii);
                        sessionAppendBlob(pOut, z, n, &rc);
                    } else {
                        const z: ?[*]const u8 = @ptrCast(sqlite3_column_blob(pTab.pDfltStmt, ii));
                        sessionAppendBlob(pOut, z, n, &rc);
                    }
                },
                else => {},
            }
        }
    } else if (op == SQLITE_UPDATE) {
        var iOff: c_int = 0;
        if (pGrp.bPatch == 0) {
            ii = 0;
            while (ii < nCol) : (ii += 1) {
                iOff += sessionSerialLen(aRec + @as(usize, @intCast(iOff)));
            }
            sessionAppendBlob(pOut, aRec, iOff, &rc);
            ii = 0;
            while (ii < (pTab.nCol - nCol)) : (ii += 1) {
                sessionAppendByte(pOut, 0, &rc);
            }
        }
        sessionAppendBlob(pOut, aRec + @as(usize, @intCast(iOff)), nRec - iOff, &rc);
        ii = 0;
        while (ii < (pTab.nCol - nCol)) : (ii += 1) {
            sessionAppendByte(pOut, 0, &rc);
        }
    } else {
        sessionAppendBlob(pOut, aRec, nRec, &rc);
    }

    return rc;
}

fn sessionChangesetFindTable(pGrp: *sqlite3_changegroup, zTab: [*:0]const u8, pIter: ?*sqlite3_changeset_iter, ppTab: *?*SessionTable) c_int {
    var rc: c_int = SQLITE_OK;
    var pTab: ?*SessionTable = null;
    const nTab: c_int = @intCast(strlen0(zTab));
    var abPK: ?[*]u8 = null;
    var nCol: c_int = 0;

    ppTab.* = null;

    pTab = pGrp.pList;
    while (pTab) |pt| {
        if (0 == sqlite3_strnicmp(pt.zName.?, zTab, nTab + 1)) break;
        pTab = pt.pNext;
    }

    if (pIter) |pi| {
        _ = sqlite3changeset_pk(pi, &abPK, &nCol);
    } else if (pTab == null and pGrp.db == null) {
        return SQLITE_OK;
    }

    if (pTab == null) {
        const pNew: ?*SessionTable = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @sizeOf(SessionTable)) + @as(u64, @intCast(nCol)) + @as(u64, @intCast(nTab)) + 1)));
        if (pNew == null) return SQLITE_NOMEM;
        pTab = pNew;
        const pt = pNew.?;
        memset0(@ptrCast(pt), @sizeOf(SessionTable));
        pt.nCol = nCol;
        pt.abPK = @ptrCast(@as([*]SessionTable, @ptrCast(pt)) + 1);
        if (nCol > 0) {
            memcpy(pt.abPK.?, abPK.?, @intCast(nCol));
        }
        pt.zName = @ptrCast(pt.abPK.? + @as(usize, @intCast(nCol)));
        memcpy(@ptrCast(pt.zName.?), zTab, @intCast(nTab + 1));

        if (pGrp.db != null) {
            pt.nCol = 0;
            rc = sessionInitTable(null, pt, pGrp.db, pGrp.zDb.?);
            if (rc != 0 or pt.nCol == 0) {
                sqlite3_free(@ptrCast(pt.azCol));
                sqlite3_free(@ptrCast(pt));
                return rc;
            }
        }

        var ppNew: *?*SessionTable = &pGrp.pList;
        while (ppNew.*) |existing| ppNew = &existing.pNext;
        ppNew.* = pt;
    }

    if (pIter != null and sessionChangesetCheckCompat(pTab.?, nCol, abPK.?) == 0) {
        rc = SQLITE_SCHEMA;
    }

    ppTab.* = pTab;
    return rc;
}

fn sessionOneChangeToHash(pGrp: *sqlite3_changegroup, pTab: *SessionTable, op: c_int, bIndirect: c_int, nCol0: c_int, aRec0: [*]u8, nRec0: c_int, bRebase: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    var iHash: c_int = 0;
    var pChange: ?*SessionChange = null;
    var pExist: ?*SessionChange = null;
    var aRec: [*]u8 = aRec0;
    var nRec: c_int = nRec0;

    if (nCol0 < pTab.nCol) {
        const pBuf = &pGrp.rec;
        rc = sessionChangesetExtendRecord(pGrp, pTab, nCol0, op, aRec, nRec, pBuf);
        aRec = pBuf.aBuf.?;
        nRec = pBuf.nBuf;
    }

    if (rc == SQLITE_OK and sessionGrowHash(null, pGrp.bPatch, pTab) != 0) {
        rc = SQLITE_NOMEM;
    }

    if (rc == SQLITE_OK) {
        iHash = @intCast(sessionChangeHash(pTab, @intFromBool(pGrp.bPatch != 0 and op == SQLITE_DELETE), aRec, pTab.nChange));
        var pp: *?*SessionChange = &pTab.apChange.?[@intCast(iHash)];
        while (pp.*) |cur| {
            var bPkOnly1: c_int = 0;
            var bPkOnly2: c_int = 0;
            if (pGrp.bPatch != 0) {
                bPkOnly1 = @intFromBool(cur.op == SQLITE_DELETE);
                bPkOnly2 = @intFromBool(op == SQLITE_DELETE);
            }
            if (sessionChangeEqual(pTab, bPkOnly1, cur.aRecord.?, bPkOnly2, aRec) != 0) {
                pExist = cur;
                pp.* = cur.pNext;
                pTab.nEntry -= 1;
                break;
            }
            pp = &cur.pNext;
        }
    }

    if (rc == SQLITE_OK) {
        rc = sessionChangeMerge(pTab, bRebase, pGrp.bPatch, pExist, op, bIndirect, aRec, nRec, &pChange);
    }
    if (rc == SQLITE_OK and pChange != null) {
        pChange.?.pNext = pTab.apChange.?[@intCast(iHash)];
        pTab.apChange.?[@intCast(iHash)] = pChange;
        pTab.nEntry += 1;
    }

    return rc;
}

fn sessionOneChangeIterToHash(pGrp: *sqlite3_changegroup, pIter: *sqlite3_changeset_iter, bRebase: c_int) c_int {
    const aRec: [*]u8 = pIter.in.aData.? + @as(usize, @intCast(pIter.in.iCurrent + 2));
    const nRec: c_int = (pIter.in.iNext - pIter.in.iCurrent) - 2;
    var zTab: ?[*:0]const u8 = null;
    var nCol: c_int = 0;
    var op: c_int = 0;
    var bIndirect: c_int = 0;
    var rc: c_int = SQLITE_OK;
    var pTab: ?*SessionTable = null;

    if (pGrp.pList == null) {
        pGrp.bPatch = pIter.bPatchset;
    } else if (pIter.bPatchset != pGrp.bPatch) {
        rc = SQLITE_ERROR;
    }

    if (rc == SQLITE_OK) {
        _ = sqlite3changeset_op(pIter, &zTab, &nCol, &op, &bIndirect);
        rc = sessionChangesetFindTable(pGrp, zTab.?, pIter, &pTab);
    }

    if (rc == SQLITE_OK) {
        rc = sessionOneChangeToHash(pGrp, pTab.?, op, bIndirect, nCol, aRec, nRec, bRebase);
    }

    if (rc == SQLITE_OK) rc = pIter.rc;
    return rc;
}

fn sessionChangesetToHash(pIter: *sqlite3_changeset_iter, pGrp: *sqlite3_changegroup, bRebase: c_int) c_int {
    var aRec: [*]u8 = undefined;
    var nRec: c_int = undefined;
    var rc: c_int = SQLITE_OK;

    pIter.in.bNoDiscard = 1;
    while (SQLITE_ROW == sessionChangesetNext(pIter, &aRec, &nRec, null)) {
        rc = sessionOneChangeIterToHash(pGrp, pIter, bRebase);
        if (rc != SQLITE_OK) break;
    }
    if (rc == SQLITE_OK) rc = pIter.rc;
    return rc;
}

fn sessionChangegroupOutput(pGrp: *sqlite3_changegroup, xOutput: XOutput, pOut: ?*anyopaque, pnOut: ?*c_int, ppOut: ?*?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    var buf: SessionBuffer = .{};
    var pTab: ?*SessionTable = pGrp.pList;
    while (rc == SQLITE_OK and pTab != null) : (pTab = pTab.?.pNext) {
        const pt = pTab.?;
        if (pt.nEntry == 0) continue;
        sessionAppendTableHdr(&buf, pGrp.bPatch, pt, &rc);
        var i: c_int = 0;
        while (i < pt.nChange) : (i += 1) {
            var p: ?*SessionChange = pt.apChange.?[@intCast(i)];
            while (p) |pc| {
                sessionAppendByte(&buf, pc.op, &rc);
                sessionAppendByte(&buf, pc.bIndirect, &rc);
                sessionAppendBlob(&buf, pc.aRecord, pc.nRecord, &rc);
                if (rc == SQLITE_OK and xOutput != null and buf.nBuf >= sessions_strm_chunk_size) {
                    rc = xOutput.?(pOut, buf.aBuf, buf.nBuf);
                    buf.nBuf = 0;
                }
                p = pc.pNext;
            }
        }
    }

    if (rc == SQLITE_OK) {
        if (xOutput != null) {
            if (buf.nBuf > 0) rc = xOutput.?(pOut, buf.aBuf, buf.nBuf);
        } else if (ppOut != null) {
            ppOut.?.* = @ptrCast(buf.aBuf);
            if (pnOut) |p| p.* = buf.nBuf;
            buf.aBuf = null;
        }
    }
    sqlite3_free(@ptrCast(buf.aBuf));
    return rc;
}

export fn sqlite3changegroup_new(pp: *?*sqlite3_changegroup) c_int {
    var rc: c_int = SQLITE_OK;
    const p: ?*sqlite3_changegroup = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(sqlite3_changegroup))));
    if (p == null) {
        rc = SQLITE_NOMEM;
    } else {
        memset0(@ptrCast(p.?), @sizeOf(sqlite3_changegroup));
    }
    pp.* = p;
    return rc;
}

export fn sqlite3changegroup_config(pGrp: *sqlite3_changegroup, op: c_int, pArg: ?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    switch (op) {
        SQLITE_CHANGEGROUP_CONFIG_PATCHSET => {
            const pi: *c_int = @ptrCast(@alignCast(pArg));
            const arg = pi.*;
            if (pGrp.pList == null and arg >= 0) {
                pGrp.bPatch = @intFromBool(arg > 0);
            }
            pi.* = pGrp.bPatch;
        },
        else => rc = SQLITE_MISUSE,
    }
    return rc;
}

export fn sqlite3changegroup_schema(pGrp: *sqlite3_changegroup, db: ?*sqlite3, zDb: [*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    if (pGrp.pList != null or pGrp.db != null) {
        rc = SQLITE_MISUSE;
    } else {
        pGrp.zDb = sqlite3_mprintf("%s", zDb);
        if (pGrp.zDb == null) {
            rc = SQLITE_NOMEM;
        } else {
            pGrp.db = db;
        }
    }
    return rc;
}

export fn sqlite3changegroup_add(pGrp: *sqlite3_changegroup, nData: c_int, pData: ?*anyopaque) c_int {
    var pIter: ?*sqlite3_changeset_iter = null;
    var rc = sqlite3changeset_start(&pIter, nData, pData);
    if (rc == SQLITE_OK) {
        rc = sessionChangesetToHash(pIter.?, pGrp, 0);
    }
    _ = sqlite3changeset_finalize(pIter);
    return rc;
}

export fn sqlite3changegroup_add_change(pGrp: *sqlite3_changegroup, pIter: *sqlite3_changeset_iter) c_int {
    var rc: c_int = SQLITE_OK;
    if (pIter.in.iCurrent == pIter.in.iNext or pIter.rc != SQLITE_OK or pIter.bInvert != 0) {
        rc = SQLITE_ERROR;
    } else {
        pIter.in.bNoDiscard = 1;
        rc = sessionOneChangeIterToHash(pGrp, pIter, 0);
    }
    return rc;
}

export fn sqlite3changegroup_output(pGrp: *sqlite3_changegroup, pnData: ?*c_int, ppData: ?*?*anyopaque) c_int {
    return sessionChangegroupOutput(pGrp, null, null, pnData, ppData);
}

export fn sqlite3changegroup_add_strm(pGrp: *sqlite3_changegroup, xInput: XInput, pIn: ?*anyopaque) c_int {
    var pIter: ?*sqlite3_changeset_iter = null;
    var rc = sqlite3changeset_start_strm(&pIter, xInput, pIn);
    if (rc == SQLITE_OK) {
        rc = sessionChangesetToHash(pIter.?, pGrp, 0);
    }
    _ = sqlite3changeset_finalize(pIter);
    return rc;
}

export fn sqlite3changegroup_output_strm(pGrp: *sqlite3_changegroup, xOutput: XOutput, pOut: ?*anyopaque) c_int {
    return sessionChangegroupOutput(pGrp, xOutput, pOut, null, null);
}

export fn sqlite3changegroup_delete(pGrp: ?*sqlite3_changegroup) void {
    if (pGrp) |g| {
        var ii: c_int = 0;
        while (ii < g.cd.nBufAlloc) : (ii += 1) {
            sqlite3_free(@ptrCast(g.cd.aBuf.?[@intCast(ii)].aBuf));
        }
        sqlite3_free(@ptrCast(g.cd.record.aBuf));
        sqlite3_free(@ptrCast(g.cd.aBuf));
        sqlite3_free(@ptrCast(g.zDb));
        sessionDeleteTable(null, g.pList);
        sqlite3_free(@ptrCast(g.rec.aBuf));
        sqlite3_free(@ptrCast(g));
    }
}

export fn sqlite3changeset_concat(nLeft: c_int, pLeft: ?*anyopaque, nRight: c_int, pRight: ?*anyopaque, pnOut: ?*c_int, ppOut: ?*?*anyopaque) c_int {
    var pGrp: ?*sqlite3_changegroup = null;
    var rc = sqlite3changegroup_new(&pGrp);
    if (rc == SQLITE_OK) rc = sqlite3changegroup_add(pGrp.?, nLeft, pLeft);
    if (rc == SQLITE_OK) rc = sqlite3changegroup_add(pGrp.?, nRight, pRight);
    if (rc == SQLITE_OK) rc = sqlite3changegroup_output(pGrp.?, pnOut, ppOut);
    sqlite3changegroup_delete(pGrp);
    return rc;
}

export fn sqlite3changeset_concat_strm(xInputA: XInput, pInA: ?*anyopaque, xInputB: XInput, pInB: ?*anyopaque, xOutput: XOutput, pOut: ?*anyopaque) c_int {
    var pGrp: ?*sqlite3_changegroup = null;
    var rc = sqlite3changegroup_new(&pGrp);
    if (rc == SQLITE_OK) rc = sqlite3changegroup_add_strm(pGrp.?, xInputA, pInA);
    if (rc == SQLITE_OK) rc = sqlite3changegroup_add_strm(pGrp.?, xInputB, pInB);
    if (rc == SQLITE_OK) rc = sqlite3changegroup_output_strm(pGrp.?, xOutput, pOut);
    sqlite3changegroup_delete(pGrp);
    return rc;
}

// ===========================================================================
// Rebaser
// ===========================================================================
fn sessionAppendRecordMerge(pBuf: *SessionBuffer, nCol: c_int, a1i: [*]u8, n1: c_int, a2i: [*]u8, n2: c_int, pRc: *c_int) void {
    _ = sessionBufferGrow(pBuf, n1 + n2, pRc);
    if (pRc.* == SQLITE_OK) {
        var a1: [*]u8 = a1i;
        var a2: [*]u8 = a2i;
        var pOut: [*]u8 = pBuf.aBuf.? + @as(usize, @intCast(pBuf.nBuf));
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const nn1 = sessionSerialLen(a1);
            const nn2 = sessionSerialLen(a2);
            if (a1[0] == 0 or a1[0] == 0xFF) {
                memcpy(pOut, a2, @intCast(nn2));
                pOut += @intCast(nn2);
            } else {
                memcpy(pOut, a1, @intCast(nn1));
                pOut += @intCast(nn1);
            }
            a1 += @intCast(nn1);
            a2 += @intCast(nn2);
        }
        pBuf.nBuf = @intCast(@intFromPtr(pOut) - @intFromPtr(pBuf.aBuf.?));
    }
}

fn sessionAppendPartialUpdate(pBuf: *SessionBuffer, pIter: *sqlite3_changeset_iter, aRec: [*]u8, nRec: c_int, aChange: [*]u8, nChange: c_int, pRc: *c_int) void {
    _ = sessionBufferGrow(pBuf, 2 + nRec + nChange, pRc);
    if (pRc.* == SQLITE_OK) {
        var bData: c_int = 0;
        var pOut: [*]u8 = pBuf.aBuf.? + @as(usize, @intCast(pBuf.nBuf));
        var a1: [*]u8 = aRec;
        var a2: [*]u8 = aChange;

        pOut[0] = SQLITE_UPDATE;
        pOut += 1;
        pOut[0] = @intCast(pIter.bIndirect);
        pOut += 1;
        var i: c_int = 0;
        while (i < pIter.nCol) : (i += 1) {
            const nn1 = sessionSerialLen(a1);
            const nn2 = sessionSerialLen(a2);
            if (pIter.abPK.?[@intCast(i)] != 0 or a2[0] == 0) {
                if (pIter.abPK.?[@intCast(i)] == 0 and a1[0] != 0) bData = 1;
                memcpy(pOut, a1, @intCast(nn1));
                pOut += @intCast(nn1);
            } else if (a2[0] != 0xFF and a1[0] != 0) {
                bData = 1;
                memcpy(pOut, a2, @intCast(nn2));
                pOut += @intCast(nn2);
            } else {
                pOut[0] = 0;
                pOut += 1;
            }
            a1 += @intCast(nn1);
            a2 += @intCast(nn2);
        }
        if (bData != 0) {
            a2 = aChange;
            i = 0;
            while (i < pIter.nCol) : (i += 1) {
                const nn1 = sessionSerialLen(a1);
                const nn2 = sessionSerialLen(a2);
                if (pIter.abPK.?[@intCast(i)] != 0 or a2[0] != 0xFF) {
                    memcpy(pOut, a1, @intCast(nn1));
                    pOut += @intCast(nn1);
                } else {
                    pOut[0] = 0;
                    pOut += 1;
                }
                a1 += @intCast(nn1);
                a2 += @intCast(nn2);
            }
            pBuf.nBuf = @intCast(@intFromPtr(pOut) - @intFromPtr(pBuf.aBuf.?));
        }
    }
}

fn sessionRebase(p: *sqlite3_rebaser, pIter: *sqlite3_changeset_iter, xOutput: XOutput, pOut: ?*anyopaque, pnOut: ?*c_int, ppOut: ?*?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    var aRec: [*]u8 = undefined;
    var nRec: c_int = 0;
    var bNew: c_int = 0;
    var pTab: ?*SessionTable = null;
    var sOut: SessionBuffer = .{};

    while (SQLITE_ROW == sessionChangesetNext(pIter, &aRec, &nRec, &bNew)) {
        var pChange: ?*SessionChange = null;
        var bDone: c_int = 0;

        if (bNew != 0) {
            const zTab = pIter.zTab.?;
            pTab = p.grp.pList;
            while (pTab) |pt| {
                if (0 == sqlite3_stricmp(pt.zName.?, zTab)) break;
                pTab = pt.pNext;
            }
            bNew = 0;

            if (pIter.bPatchset != 0) rc = SQLITE_ERROR;

            sessionAppendByte(&sOut, if (pIter.bPatchset != 0) 'P' else 'T', &rc);
            sessionAppendVarint(&sOut, pIter.nCol, &rc);
            sessionAppendBlob(&sOut, pIter.abPK, pIter.nCol, &rc);
            sessionAppendBlob(&sOut, @ptrCast(pIter.zTab), @intCast(strlen0(pIter.zTab.?) + 1), &rc);
        }

        if (pTab != null and rc == SQLITE_OK) {
            const iHash = sessionChangeHash(pTab.?, 0, aRec, pTab.?.nChange);
            pChange = pTab.?.apChange.?[@intCast(iHash)];
            while (pChange) |pc| {
                if (sessionChangeEqual(pTab.?, 0, aRec, 0, pc.aRecord.?) != 0) break;
                pChange = pc.pNext;
            }
        }

        if (pChange) |pc| {
            switch (pIter.op) {
                SQLITE_INSERT => {
                    if (pc.op == SQLITE_INSERT) {
                        bDone = 1;
                        if (pc.bIndirect == 0) {
                            sessionAppendByte(&sOut, SQLITE_UPDATE, &rc);
                            sessionAppendByte(&sOut, @intCast(pIter.bIndirect), &rc);
                            sessionAppendBlob(&sOut, pc.aRecord, pc.nRecord, &rc);
                            sessionAppendBlob(&sOut, aRec, nRec, &rc);
                        }
                    }
                },
                SQLITE_UPDATE => {
                    bDone = 1;
                    if (pc.op == SQLITE_DELETE) {
                        if (pc.bIndirect == 0) {
                            var pCsr: [*]u8 = aRec;
                            sessionSkipRecord(&pCsr, pIter.nCol);
                            sessionAppendByte(&sOut, SQLITE_INSERT, &rc);
                            sessionAppendByte(&sOut, @intCast(pIter.bIndirect), &rc);
                            sessionAppendRecordMerge(&sOut, pIter.nCol, pCsr, nRec - @as(c_int, @intCast(@intFromPtr(pCsr) - @intFromPtr(aRec))), pc.aRecord.?, pc.nRecord, &rc);
                        }
                    } else {
                        sessionAppendPartialUpdate(&sOut, pIter, aRec, nRec, pc.aRecord.?, pc.nRecord, &rc);
                    }
                },
                else => {
                    bDone = 1;
                    if (pc.op == SQLITE_INSERT) {
                        sessionAppendByte(&sOut, SQLITE_DELETE, &rc);
                        sessionAppendByte(&sOut, @intCast(pIter.bIndirect), &rc);
                        sessionAppendRecordMerge(&sOut, pIter.nCol, pc.aRecord.?, pc.nRecord, aRec, nRec, &rc);
                    }
                },
            }
        }

        if (bDone == 0) {
            sessionAppendByte(&sOut, @intCast(pIter.op), &rc);
            sessionAppendByte(&sOut, @intCast(pIter.bIndirect), &rc);
            sessionAppendBlob(&sOut, aRec, nRec, &rc);
        }
        if (rc == SQLITE_OK and xOutput != null and sOut.nBuf > sessions_strm_chunk_size) {
            rc = xOutput.?(pOut, sOut.aBuf, sOut.nBuf);
            sOut.nBuf = 0;
        }
        if (rc != 0) break;
    }

    if (rc != SQLITE_OK) {
        sqlite3_free(@ptrCast(sOut.aBuf));
        sOut = .{};
    }

    if (rc == SQLITE_OK) {
        if (xOutput != null) {
            if (sOut.nBuf > 0) {
                rc = xOutput.?(pOut, sOut.aBuf, sOut.nBuf);
            }
        } else if (ppOut != null) {
            ppOut.?.* = @ptrCast(sOut.aBuf);
            pnOut.?.* = sOut.nBuf;
            sOut.aBuf = null;
        }
    }
    sqlite3_free(@ptrCast(sOut.aBuf));
    return rc;
}

export fn sqlite3rebaser_create(ppNew: *?*sqlite3_rebaser) c_int {
    var rc: c_int = SQLITE_OK;
    const pNew: ?*sqlite3_rebaser = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(sqlite3_rebaser))));
    if (pNew == null) {
        rc = SQLITE_NOMEM;
    } else {
        memset0(@ptrCast(pNew.?), @sizeOf(sqlite3_rebaser));
    }
    ppNew.* = pNew;
    return rc;
}

export fn sqlite3rebaser_configure(p: *sqlite3_rebaser, nRebase: c_int, pRebase: ?*const anyopaque) c_int {
    var pIter: ?*sqlite3_changeset_iter = null;
    var rc = sqlite3changeset_start(&pIter, nRebase, @constCast(pRebase));
    if (rc == SQLITE_OK) {
        rc = sessionChangesetToHash(pIter.?, &p.grp, 1);
    }
    _ = sqlite3changeset_finalize(pIter);
    return rc;
}

export fn sqlite3rebaser_rebase(p: *sqlite3_rebaser, nIn: c_int, pIn: ?*const anyopaque, pnOut: ?*c_int, ppOut: ?*?*anyopaque) c_int {
    var pIter: ?*sqlite3_changeset_iter = null;
    var rc = sqlite3changeset_start(&pIter, nIn, @constCast(pIn));
    if (rc == SQLITE_OK) {
        rc = sessionRebase(p, pIter.?, null, null, pnOut, ppOut);
        _ = sqlite3changeset_finalize(pIter);
    }
    return rc;
}

export fn sqlite3rebaser_rebase_strm(p: *sqlite3_rebaser, xInput: XInput, pIn: ?*anyopaque, xOutput: XOutput, pOut: ?*anyopaque) c_int {
    var pIter: ?*sqlite3_changeset_iter = null;
    var rc = sqlite3changeset_start_strm(&pIter, xInput, pIn);
    if (rc == SQLITE_OK) {
        rc = sessionRebase(p, pIter.?, xOutput, pOut, null, null);
        _ = sqlite3changeset_finalize(pIter);
    }
    return rc;
}

export fn sqlite3rebaser_delete(p: ?*sqlite3_rebaser) void {
    if (p) |pr| {
        sessionDeleteTable(null, pr.grp.pList);
        sqlite3_free(@ptrCast(pr.grp.rec.aBuf));
        sqlite3_free(@ptrCast(pr));
    }
}

// ===========================================================================
// Global config
// ===========================================================================
export fn sqlite3session_config(op: c_int, pArg: ?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    switch (op) {
        SQLITE_SESSION_CONFIG_STRMSIZE => {
            const pInt: *c_int = @ptrCast(@alignCast(pArg));
            if (pInt.* > 0) {
                sessions_strm_chunk_size = pInt.*;
            }
            pInt.* = sessions_strm_chunk_size;
        },
        else => rc = SQLITE_MISUSE,
    }
    return rc;
}

// ===========================================================================
// changegroup_change_* incremental API
// ===========================================================================
export fn sqlite3changegroup_change_begin(pGrp: *sqlite3_changegroup, eOp: c_int, zTab: [*:0]const u8, bIndirect: c_int, pzErr: ?*?[*:0]u8) c_int {
    var pTab: ?*SessionTable = null;
    var rc: c_int = SQLITE_OK;

    if (pGrp.cd.pTab != null) {
        rc = SQLITE_MISUSE;
    } else if (eOp != SQLITE_INSERT and eOp != SQLITE_UPDATE and eOp != SQLITE_DELETE) {
        rc = SQLITE_ERROR;
    } else {
        rc = sessionChangesetFindTable(pGrp, zTab, null, &pTab);
    }
    if (rc == SQLITE_OK) {
        if (pTab == null) {
            if (pzErr) |p| p.* = sqlite3_mprintf("no such table: %s", zTab);
            rc = SQLITE_ERROR;
        } else {
            const nReq: c_int = pTab.?.nCol * (if (eOp == SQLITE_UPDATE) @as(c_int, 2) else 1);
            pGrp.cd.pTab = pTab;
            pGrp.cd.eOp = eOp;
            pGrp.cd.bIndirect = bIndirect;

            if (pGrp.cd.nBufAlloc < nReq) {
                const aBuf: ?[*]SessionBuffer = @ptrCast(@alignCast(sqlite3_realloc(@ptrCast(pGrp.cd.aBuf), nReq * @sizeOf(SessionBuffer))));
                if (aBuf == null) {
                    rc = SQLITE_NOMEM;
                } else {
                    memset0(@ptrCast(aBuf.? + @as(usize, @intCast(pGrp.cd.nBufAlloc))), @sizeOf(SessionBuffer) * @as(usize, @intCast(nReq - pGrp.cd.nBufAlloc)));
                    pGrp.cd.aBuf = aBuf;
                    pGrp.cd.nBufAlloc = nReq;
                }
            }
        }
    }
    return rc;
}

fn checkChangeParams(pGrp: *sqlite3_changegroup, bNew: c_int, iCol: c_int, nReq: i64, ppBuf: *?*SessionBuffer) c_int {
    var rc: c_int = SQLITE_OK;
    if (pGrp.cd.pTab == null) {
        rc = SQLITE_MISUSE;
    } else if (iCol < 0 or iCol >= pGrp.cd.pTab.?.nCol) {
        rc = SQLITE_RANGE;
    } else if ((bNew != 0 and pGrp.cd.eOp == SQLITE_DELETE) or (bNew == 0 and pGrp.cd.eOp == SQLITE_INSERT)) {
        rc = SQLITE_ERROR;
    } else {
        var pBuf: *SessionBuffer = &pGrp.cd.aBuf.?[@intCast(iCol)];
        if (pGrp.cd.eOp == SQLITE_UPDATE and bNew != 0) {
            pBuf = @ptrCast(@as([*]SessionBuffer, @ptrCast(pBuf)) + @as(usize, @intCast(pGrp.cd.pTab.?.nCol)));
        }
        pBuf.nBuf = 0;
        _ = sessionBufferGrow(pBuf, nReq, &rc);
        pBuf.nBuf = @intCast(nReq);
        ppBuf.* = pBuf;
    }
    return rc;
}

export fn sqlite3changegroup_change_int64(pGrp: *sqlite3_changegroup, bNew: c_int, iCol: c_int, iVal: i64) c_int {
    var pBuf: ?*SessionBuffer = null;
    const rc = checkChangeParams(pGrp, bNew, iCol, 9, &pBuf);
    if (rc != SQLITE_OK) return rc;
    pBuf.?.aBuf.?[0] = SQLITE_INTEGER;
    sessionPutI64(pBuf.?.aBuf.? + 1, iVal);
    return SQLITE_OK;
}

export fn sqlite3changegroup_change_null(pGrp: *sqlite3_changegroup, bNew: c_int, iCol: c_int) c_int {
    var pBuf: ?*SessionBuffer = null;
    const rc = checkChangeParams(pGrp, bNew, iCol, 1, &pBuf);
    if (rc != SQLITE_OK) return rc;
    pBuf.?.aBuf.?[0] = SQLITE_NULL;
    return SQLITE_OK;
}

export fn sqlite3changegroup_change_double(pGrp: *sqlite3_changegroup, bNew: c_int, iCol: c_int, fVal: f64) c_int {
    var pBuf: ?*SessionBuffer = null;
    const rc = checkChangeParams(pGrp, bNew, iCol, 9, &pBuf);
    if (rc != SQLITE_OK) return rc;
    pBuf.?.aBuf.?[0] = SQLITE_FLOAT;
    sessionPutDouble(pBuf.?.aBuf.? + 1, fVal);
    return SQLITE_OK;
}

export fn sqlite3changegroup_change_text(pGrp: *sqlite3_changegroup, bNew: c_int, iCol: c_int, pVal: [*:0]const u8, nVal: c_int) c_int {
    const nText: i64 = if (nVal >= 0) nVal else @intCast(strlen0(pVal));
    const nByte: i64 = 1 + sessionVarintLen(@intCast(nText)) + nText;
    var pBuf: ?*SessionBuffer = null;
    const rc = checkChangeParams(pGrp, bNew, iCol, nByte, &pBuf);
    if (rc != SQLITE_OK) return rc;
    pBuf.?.aBuf.?[0] = SQLITE_TEXT;
    pBuf.?.nBuf = 1 + sessionVarintPut(pBuf.?.aBuf.? + 1, @intCast(nText));
    memcpy(pBuf.?.aBuf.? + @as(usize, @intCast(pBuf.?.nBuf)), pVal, @intCast(nText));
    pBuf.?.nBuf += @intCast(nText);
    return SQLITE_OK;
}

export fn sqlite3changegroup_change_blob(pGrp: *sqlite3_changegroup, bNew: c_int, iCol: c_int, pVal: ?*const anyopaque, nVal: c_int) c_int {
    const nByte: i64 = 1 + sessionVarintLen(nVal) + @as(i64, nVal);
    var pBuf: ?*SessionBuffer = null;
    const rc = checkChangeParams(pGrp, bNew, iCol, nByte, &pBuf);
    if (rc != SQLITE_OK) return rc;
    pBuf.?.aBuf.?[0] = SQLITE_BLOB;
    pBuf.?.nBuf = 1 + sessionVarintPut(pBuf.?.aBuf.? + 1, nVal);
    memcpy(pBuf.?.aBuf.? + @as(usize, @intCast(pBuf.?.nBuf)), @ptrCast(pVal.?), @intCast(nVal));
    pBuf.?.nBuf += nVal;
    return SQLITE_OK;
}

export fn sqlite3changegroup_change_finish(pGrp: *sqlite3_changegroup, bDiscard: c_int, pzErr: ?*?[*:0]u8) c_int {
    var rc: c_int = SQLITE_OK;
    var zErr: ?[*:0]u8 = null;
    if (pGrp.cd.pTab) |pTab| {
        const aBuf = pGrp.cd.aBuf.?;
        var ii: c_int = 0;

        if (bDiscard == 0) {
            var nBuf: c_int = pTab.nCol;
            var eUndef: u8 = SQLITE_NULL;
            if (pGrp.cd.eOp == SQLITE_UPDATE) {
                ii = 0;
                while (ii < nBuf) : (ii += 1) {
                    if (pTab.abPK.?[@intCast(ii)] != 0) {
                        if (aBuf[@intCast(ii)].nBuf <= 1) {
                            zErr = sqlite3_mprintf("invalid change: %s value in PK of old.* record", @as([*:0]const u8, if (aBuf[@intCast(ii)].nBuf == 1) "null" else "undefined"));
                            rc = SQLITE_ERROR;
                            break;
                        } else if (aBuf[@intCast(ii + nBuf)].nBuf > 0) {
                            zErr = sqlite3_mprintf("invalid change: defined value in PK of new.* record");
                            rc = SQLITE_ERROR;
                            break;
                        }
                    } else if (pGrp.bPatch == 0 and (aBuf[@intCast(ii)].nBuf > 0) != (aBuf[@intCast(ii + nBuf)].nBuf > 0)) {
                        zErr = sqlite3_mprintf("invalid change: column %d - old.* value is %sdefined but new.* is %sdefined", ii, @as([*:0]const u8, if (aBuf[@intCast(ii)].nBuf != 0) "" else "un"), @as([*:0]const u8, if (aBuf[@intCast(ii + nBuf)].nBuf != 0) "" else "un"));
                        rc = SQLITE_ERROR;
                        break;
                    }
                }
                eUndef = 0;
                if (pGrp.bPatch == 0) nBuf = nBuf * 2;
            } else {
                ii = 0;
                while (ii < nBuf) : (ii += 1) {
                    const isPK = pTab.abPK.?[@intCast(ii)];
                    if ((pGrp.cd.eOp == SQLITE_INSERT or pGrp.bPatch == 0 or isPK != 0) and aBuf[@intCast(ii)].nBuf == 0) {
                        zErr = sqlite3_mprintf("invalid change: column %d is undefined", ii);
                        rc = SQLITE_ERROR;
                        break;
                    }
                    if (aBuf[@intCast(ii)].nBuf == 1 and isPK != 0) {
                        zErr = sqlite3_mprintf("invalid change: null value in PK");
                        rc = SQLITE_ERROR;
                        break;
                    }
                }
            }

            pGrp.cd.record.nBuf = 0;
            ii = 0;
            while (ii < nBuf) : (ii += 1) {
                var p: *SessionBuffer = &pGrp.cd.aBuf.?[@intCast(ii)];
                if (pGrp.bPatch != 0) {
                    if (pTab.abPK.?[@intCast(ii)] == 0) {
                        if (pGrp.cd.eOp == SQLITE_UPDATE) {
                            p = @ptrCast(@as([*]SessionBuffer, @ptrCast(p)) + @as(usize, @intCast(pTab.nCol)));
                        } else if (pGrp.cd.eOp == SQLITE_DELETE) {
                            continue;
                        }
                    }
                }
                if (0 == sessionBufferGrow(&pGrp.cd.record, if (p.nBuf != 0) p.nBuf else 1, &rc)) {
                    if (p.nBuf != 0) {
                        memcpy(pGrp.cd.record.aBuf.? + @as(usize, @intCast(pGrp.cd.record.nBuf)), p.aBuf.?, @intCast(p.nBuf));
                        pGrp.cd.record.nBuf += p.nBuf;
                    } else {
                        pGrp.cd.record.aBuf.?[@intCast(pGrp.cd.record.nBuf)] = eUndef;
                        pGrp.cd.record.nBuf += 1;
                    }
                }
            }
            if (rc == SQLITE_OK) {
                rc = sessionOneChangeToHash(pGrp, pTab, pGrp.cd.eOp, pGrp.cd.bIndirect, pTab.nCol, pGrp.cd.record.aBuf.?, pGrp.cd.record.nBuf, 0);
            }
        }

        {
            var nZero: c_int = pTab.nCol;
            if (pGrp.cd.eOp == SQLITE_UPDATE) nZero += nZero;
            ii = 0;
            while (ii < nZero) : (ii += 1) {
                pGrp.cd.aBuf.?[@intCast(ii)].nBuf = 0;
            }
        }
        pGrp.cd.pTab = null;
    }

    if (pzErr) |p| {
        p.* = zErr;
    } else {
        sqlite3_free(@ptrCast(zErr));
    }
    return rc;
}
