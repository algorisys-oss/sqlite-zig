//! Zig port of SQLite's "carray" table-valued function (ext/misc/carray.c).
//!
//! Drop-in replacement exporting the public bind helpers `sqlite3_carray_bind`
//! and `sqlite3_carray_bind_v2`, plus the internal registration entry point
//! `sqlite3CarrayRegister` (called from build.c when a query references the
//! `carray` module). The module implements an eponymous virtual table that
//! reads values out of a C-language array whose address is passed in via
//! `sqlite3_bind_pointer()`.
//!
//! Coupling is config-invariant. Everything this module touches is either:
//!   * the PUBLIC sqlite3.h ABI — `sqlite3_module` (the ~25-pointer vtab method
//!     table, mirrored here as an `extern struct` exactly like src/memjournal.zig
//!     mirrors `sqlite3_io_methods`), `sqlite3_vtab`, `sqlite3_vtab_cursor`,
//!     `sqlite3_index_info` and its substructures, and the `sqlite3_result_*` /
//!     `sqlite3_value_*` / `sqlite3_malloc*` / `sqlite3_bind_pointer` /
//!     `sqlite3_declare_vtab` / `sqlite3_mprintf` / `sqlite3_stricmp` calls; or
//!   * this module's OWN structs (`carray_cursor`, `carray_bind`) whose layout we
//!     control. The cursor's first field is the base `sqlite3_vtab_cursor` so the
//!     C-style subclassing (cursor* <-> base*) is sound.
//!
//! Because none of those depend on SQLITE_DEBUG / SQLITE_TEST, the single Zig
//! object is correct in both the production `zig build` and the `--dev`
//! testfixture builds; no `@import("config")` gating is required. The module is
//! only compiled because SQLITE_ENABLE_CARRAY is set (true in both builds).
//!
//! Validated end-to-end by the engine via test/carray.test (upstream) rather
//! than a unit test here: every code path needs the live SQLite VM, a prepared
//! statement, and sqlite3_bind_pointer, so there is no self-contained helper to
//! exercise in a Zig `test`.

const std = @import("std");

// --- Result codes (sqlite3.h) ---
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CONSTRAINT: c_int = 19;

// --- Constraint operator (sqlite3.h) ---
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;

// --- Destructor sentinels (sqlite3.h): SQLITE_STATIC==0, SQLITE_TRANSIENT==-1.
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// --- carray datatype codes (also exposed publicly as SQLITE_CARRAY_*) ---
const CARRAY_INT32: u8 = 0; // Data is 32-bit signed integers
const CARRAY_INT64: u8 = 1; // Data is 64-bit signed integers
const CARRAY_DOUBLE: u8 = 2; // Data is doubles
const CARRAY_TEXT: u8 = 3; // Data is char*
const CARRAY_BLOB: u8 = 4; // Data is struct iovec

// Column numbers (match the declared schema).
const CARRAY_COLUMN_VALUE: c_int = 0;
const CARRAY_COLUMN_POINTER: c_int = 1;
const CARRAY_COLUMN_COUNT: c_int = 2;
const CARRAY_COLUMN_CTYPE: c_int = 3;

/// Names of allowed datatypes, indexed by the CARRAY_* code.
const azCarrayType = [_][*:0]const u8{
    "int32", "int64", "double", "char*", "struct iovec",
};

// --- Public ABI opaque handles (sqlite3.h) ---
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;

/// struct iovec (sys/uio.h). Layout mirrored so we can index a carray of blobs.
const iovec = extern struct {
    iov_base: ?*anyopaque,
    iov_len: usize,
};

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
/// for field. Unused slots stay null (the carray vtab is read-only and
/// eponymous, so xCreate/xDestroy/xUpdate/etc. are all 0).
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

// --- This module's own (internal-layout) structs ---

/// Holds the sqlite3_carray_bind() information; pointed at by a bound "carray-bind".
const carray_bind = extern struct {
    aData: ?*anyopaque, // The data
    nData: c_int, // Number of elements
    mFlags: c_int, // Control flags
    xDel: DestructorFn, // Destructor for aData
    pDel: ?*anyopaque, // Alternative argument to xDel()
};

/// Subclass of sqlite3_vtab_cursor scanning rows of the result. `base` MUST be
/// first so cursor* and base* are interchangeable.
const carray_cursor = extern struct {
    base: sqlite3_vtab_cursor, // Base class - must be first
    iRowid: i64, // The rowid
    pPtr: ?*anyopaque, // Pointer to the array of values
    iCnt: i64, // Number of integers in the array
    eType: u8, // One of the CARRAY_* values
};

// --- Public sqlite3 API resolved at link time ---
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_bind_pointer(pStmt: ?*sqlite3_stmt, i: c_int, pPtr: ?*anyopaque, zPType: ?[*:0]const u8, xDel: DestructorFn) c_int;

extern fn sqlite3_value_pointer(p: ?*sqlite3_value, zPType: [*:0]const u8) ?*anyopaque;
extern fn sqlite3_value_int64(p: ?*sqlite3_value) i64;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;

extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_result_double(ctx: ?*sqlite3_context, v: f64) void;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_blob(ctx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: DestructorFn) void;

/// Internal vtab registration helper (vtab.c). Returns an opaque Module*.
extern fn sqlite3VtabCreateModule(db: ?*sqlite3, zName: [*:0]const u8, pModule: *const sqlite3_module, pAux: ?*anyopaque, xDestroy: DestructorFn) ?*anyopaque;

extern fn strlen(s: [*:0]const u8) usize;

/// The carrayConnect() method: declare the schema and allocate the vtab object.
/// Eponymous virtual table, so this serves as xConnect with xCreate left null.
fn carrayConnect(
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
    const rc = sqlite3_declare_vtab(db, "CREATE TABLE x(value,pointer hidden,count hidden,ctype hidden)");
    if (rc == SQLITE_OK) {
        const pNew: *sqlite3_vtab = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(sqlite3_vtab)) orelse return SQLITE_NOMEM));
        ppVtab.* = pNew;
        pNew.* = std.mem.zeroes(sqlite3_vtab);
    }
    return rc;
}

/// Destructor for the carray vtab.
fn carrayDisconnect(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

/// Constructor for a new carray_cursor object.
fn carrayOpen(p: *sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    _ = p;
    const pCur: *carray_cursor = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(carray_cursor)) orelse return SQLITE_NOMEM));
    pCur.* = std.mem.zeroes(carray_cursor);
    ppCursor.* = &pCur.base;
    return SQLITE_OK;
}

/// Destructor for a carray_cursor.
fn carrayClose(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    sqlite3_free(cur);
    return SQLITE_OK;
}

/// Advance a carray_cursor to its next row of output.
fn carrayNext(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: *carray_cursor = @ptrCast(@alignCast(cur));
    pCur.iRowid +%= 1;
    return SQLITE_OK;
}

/// Return values of columns for the current row.
fn carrayColumn(cur: *sqlite3_vtab_cursor, ctx: ?*sqlite3_context, i: c_int) callconv(.c) c_int {
    const pCur: *carray_cursor = @ptrCast(@alignCast(cur));
    var x: i64 = 0;
    switch (i) {
        CARRAY_COLUMN_POINTER => return SQLITE_OK,
        CARRAY_COLUMN_COUNT => x = pCur.iCnt,
        CARRAY_COLUMN_CTYPE => {
            sqlite3_result_text(ctx, azCarrayType[pCur.eType], -1, SQLITE_STATIC);
            return SQLITE_OK;
        },
        else => {
            const idx: usize = @intCast(pCur.iRowid - 1);
            switch (pCur.eType) {
                CARRAY_INT32 => {
                    const p: [*]const c_int = @ptrCast(@alignCast(pCur.pPtr.?));
                    sqlite3_result_int(ctx, p[idx]);
                    return SQLITE_OK;
                },
                CARRAY_INT64 => {
                    const p: [*]const i64 = @ptrCast(@alignCast(pCur.pPtr.?));
                    sqlite3_result_int64(ctx, p[idx]);
                    return SQLITE_OK;
                },
                CARRAY_DOUBLE => {
                    const p: [*]const f64 = @ptrCast(@alignCast(pCur.pPtr.?));
                    sqlite3_result_double(ctx, p[idx]);
                    return SQLITE_OK;
                },
                CARRAY_TEXT => {
                    const p: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(pCur.pPtr.?));
                    sqlite3_result_text(ctx, p[idx], -1, SQLITE_TRANSIENT);
                    return SQLITE_OK;
                },
                else => {
                    // CARRAY_BLOB
                    const p: [*]const iovec = @ptrCast(@alignCast(pCur.pPtr.?));
                    sqlite3_result_blob(ctx, p[idx].iov_base, @intCast(p[idx].iov_len), SQLITE_TRANSIENT);
                    return SQLITE_OK;
                },
            }
        },
    }
    sqlite3_result_int64(ctx, x);
    return SQLITE_OK;
}

/// Return the rowid for the current row (same as the output value's position).
fn carrayRowid(cur: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCur: *carray_cursor = @ptrCast(@alignCast(cur));
    pRowid.* = pCur.iRowid;
    return SQLITE_OK;
}

/// Return TRUE if the cursor has moved off the last row of output.
fn carrayEof(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: *carray_cursor = @ptrCast(@alignCast(cur));
    return @intFromBool(pCur.iRowid > pCur.iCnt);
}

/// "Rewind" the cursor and bind the array described by the xFilter arguments.
fn carrayFilter(
    pVtabCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = idxStr;
    _ = argc;
    const pCur: *carray_cursor = @ptrCast(@alignCast(pVtabCursor));
    const av = argv.?;
    pCur.pPtr = null;
    pCur.iCnt = 0;
    switch (idxNum) {
        1 => {
            const pBind: ?*carray_bind = @ptrCast(@alignCast(sqlite3_value_pointer(av[0], "carray-bind")));
            if (pBind) |b| {
                pCur.pPtr = b.aData;
                pCur.iCnt = b.nData;
                pCur.eType = @intCast(b.mFlags & 0x07);
            }
        },
        2, 3 => {
            pCur.pPtr = sqlite3_value_pointer(av[0], "carray");
            pCur.iCnt = if (pCur.pPtr != null) sqlite3_value_int64(av[1]) else 0;
            if (idxNum < 3) {
                pCur.eType = CARRAY_INT32;
            } else {
                const zType = sqlite3_value_text(av[2]);
                var ti: usize = 0;
                while (ti < azCarrayType.len) : (ti += 1) {
                    if (sqlite3_stricmp(zType, azCarrayType[ti]) == 0) break;
                }
                if (ti >= azCarrayType.len) {
                    pVtabCursor.pVtab.?.zErrMsg = sqlite3_mprintf("unknown datatype: %Q", zType);
                    return SQLITE_ERROR;
                } else {
                    pCur.eType = @intCast(ti);
                }
            }
        },
        else => {},
    }
    pCur.iRowid = 1;
    return SQLITE_OK;
}

/// Build a query plan: idxNum 1/2/3 select pointer-only / pointer+count /
/// pointer+count+ctype constraint sets; 0 means an empty table.
fn carrayBestIndex(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = tab;
    var ptrIdx: c_int = -1; // Index of the pointer= constraint, or -1
    var cntIdx: c_int = -1; // Index of the count= constraint, or -1
    var ctypeIdx: c_int = -1; // Index of the ctype= constraint, or -1
    var seen: c_uint = 0; // Bitmask of == constrained columns

    const aConstraint = pIdxInfo.aConstraint.?;
    var i: c_int = 0;
    while (i < pIdxInfo.nConstraint) : (i += 1) {
        const pConstraint = &aConstraint[@intCast(i)];
        if (pConstraint.op != SQLITE_INDEX_CONSTRAINT_EQ) continue;
        if (pConstraint.iColumn >= 0) {
            seen |= @as(c_uint, 1) << @intCast(pConstraint.iColumn);
        }
        if (pConstraint.usable == 0) continue;
        switch (pConstraint.iColumn) {
            CARRAY_COLUMN_POINTER => ptrIdx = i,
            CARRAY_COLUMN_COUNT => cntIdx = i,
            CARRAY_COLUMN_CTYPE => ctypeIdx = i,
            else => {},
        }
    }
    const aUsage = pIdxInfo.aConstraintUsage.?;
    if (ptrIdx >= 0) {
        aUsage[@intCast(ptrIdx)].argvIndex = 1;
        aUsage[@intCast(ptrIdx)].omit = 1;
        pIdxInfo.estimatedCost = 1.0;
        pIdxInfo.estimatedRows = 100;
        pIdxInfo.idxNum = 1;
        if (cntIdx >= 0) {
            aUsage[@intCast(cntIdx)].argvIndex = 2;
            aUsage[@intCast(cntIdx)].omit = 1;
            pIdxInfo.idxNum = 2;
            if (ctypeIdx >= 0) {
                aUsage[@intCast(ctypeIdx)].argvIndex = 3;
                aUsage[@intCast(ctypeIdx)].omit = 1;
                pIdxInfo.idxNum = 3;
            } else if (seen & (@as(c_uint, 1) << @intCast(CARRAY_COLUMN_CTYPE)) != 0) {
                // In a three-argument carray(), we need all three arguments.
                return SQLITE_CONSTRAINT;
            }
        } else if (seen & (@as(c_uint, 1) << @intCast(CARRAY_COLUMN_COUNT)) != 0) {
            // In a two-argument carray(), we need both arguments.
            return SQLITE_CONSTRAINT;
        }
    } else {
        pIdxInfo.estimatedCost = 2147483647.0;
        pIdxInfo.estimatedRows = 2147483647;
        pIdxInfo.idxNum = 0;
    }
    return SQLITE_OK;
}

/// The carray virtual table method table.
const carrayModule: sqlite3_module = .{
    .iVersion = 0,
    .xCreate = null,
    .xConnect = &carrayConnect,
    .xBestIndex = &carrayBestIndex,
    .xDisconnect = &carrayDisconnect,
    .xDestroy = null,
    .xOpen = &carrayOpen,
    .xClose = &carrayClose,
    .xFilter = &carrayFilter,
    .xNext = &carrayNext,
    .xEof = &carrayEof,
    .xColumn = &carrayColumn,
    .xRowid = &carrayRowid,
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

/// Destructor for the carray_bind object.
fn carrayBindDel(pPtr: ?*anyopaque) callconv(.c) void {
    const p: *carray_bind = @ptrCast(@alignCast(pPtr.?));
    if (p.xDel != SQLITE_STATIC) {
        p.xDel.?(p.pDel);
    }
    sqlite3_free(p);
}

/// Bind to the single-argument version of CARRAY().
///
/// The destructor is called against pDestroy if pDestroy!=NULL, or against
/// aData if pDestroy==NULL.
export fn sqlite3_carray_bind_v2(
    pStmt: ?*sqlite3_stmt,
    idx: c_int,
    aData: ?*anyopaque,
    nData: c_int,
    mFlags: c_int,
    xDestroy: DestructorFn,
    pDestroy: ?*anyopaque,
) callconv(.c) c_int {
    var pNew: ?*carray_bind = null;
    var rc: c_int = SQLITE_OK;

    // Ensure that the mFlags value is acceptable.
    if (mFlags < CARRAY_INT32 or mFlags > CARRAY_BLOB) {
        rc = SQLITE_ERROR;
        return carrayBindError(rc, pNew, xDestroy, pDestroy);
    }

    pNew = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(carray_bind))));
    if (pNew == null) {
        rc = SQLITE_NOMEM;
        return carrayBindError(rc, pNew, xDestroy, pDestroy);
    }
    const p = pNew.?;

    p.nData = nData;
    p.mFlags = mFlags;
    if (xDestroy == SQLITE_TRANSIENT) {
        var sz: i64 = nData;
        switch (mFlags) {
            CARRAY_INT32 => sz *%= 4,
            CARRAY_INT64 => sz *%= 8,
            CARRAY_DOUBLE => sz *%= 8,
            CARRAY_TEXT => sz *%= @sizeOf(?*anyopaque),
            else => sz *%= @sizeOf(iovec),
        }
        if (mFlags == CARRAY_TEXT) {
            const src: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(aData.?));
            var i: usize = 0;
            while (i < @as(usize, @intCast(nData))) : (i += 1) {
                if (src[i]) |z| sz += @as(i64, @intCast(strlen(z))) + 1;
            }
        } else if (mFlags == CARRAY_BLOB) {
            const src: [*]const iovec = @ptrCast(@alignCast(aData.?));
            var i: usize = 0;
            while (i < @as(usize, @intCast(nData))) : (i += 1) {
                sz += @intCast(src[i].iov_len);
            }
        }

        p.aData = sqlite3_malloc64(@intCast(sz));
        if (p.aData == null) {
            rc = SQLITE_NOMEM;
            return carrayBindError(rc, pNew, xDestroy, pDestroy);
        }

        if (mFlags == CARRAY_TEXT) {
            const az: [*]?[*:0]u8 = @ptrCast(@alignCast(p.aData.?));
            const src: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(aData.?));
            var z: [*]u8 = @ptrCast(&az[@intCast(nData)]);
            var i: usize = 0;
            while (i < @as(usize, @intCast(nData))) : (i += 1) {
                const zData = src[i];
                if (zData == null) {
                    az[i] = null;
                    continue;
                }
                az[i] = @ptrCast(z);
                const n = strlen(zData.?);
                @memcpy(z[0 .. n + 1], zData.?[0 .. n + 1]);
                z += n + 1;
            }
        } else if (mFlags == CARRAY_BLOB) {
            const p2: [*]iovec = @ptrCast(@alignCast(p.aData.?));
            const src: [*]const iovec = @ptrCast(@alignCast(aData.?));
            var z: [*]u8 = @ptrCast(&p2[@intCast(nData)]);
            var i: usize = 0;
            while (i < @as(usize, @intCast(nData))) : (i += 1) {
                const n = src[i].iov_len;
                p2[i].iov_len = n;
                p2[i].iov_base = @ptrCast(z);
                const srcBytes: [*]const u8 = @ptrCast(src[i].iov_base.?);
                @memcpy(z[0..n], srcBytes[0..n]);
                z += n;
            }
        } else {
            const dst: [*]u8 = @ptrCast(@alignCast(p.aData.?));
            const src: [*]const u8 = @ptrCast(@alignCast(aData.?));
            const n: usize = @intCast(sz);
            @memcpy(dst[0..n], src[0..n]);
        }
        p.xDel = @ptrCast(&sqlite3_free);
        p.pDel = p.aData;
    } else {
        p.aData = aData;
        p.xDel = xDestroy;
        p.pDel = pDestroy;
    }
    return sqlite3_bind_pointer(pStmt, idx, p, "carray-bind", &carrayBindDel);
}

/// Error path shared by sqlite3_carray_bind_v2 (the C `carray_bind_error:` goto).
inline fn carrayBindError(rc: c_int, pNew: ?*carray_bind, xDestroy: DestructorFn, pDestroy: ?*anyopaque) c_int {
    if (xDestroy != SQLITE_STATIC and xDestroy != SQLITE_TRANSIENT) {
        xDestroy.?(pDestroy);
    }
    sqlite3_free(pNew);
    return rc;
}

/// Bind to the single-argument CARRAY(); same as _v2 with pDestroy == aData.
export fn sqlite3_carray_bind(
    pStmt: ?*sqlite3_stmt,
    idx: c_int,
    aData: ?*anyopaque,
    nData: c_int,
    mFlags: c_int,
    xDestroy: DestructorFn,
) callconv(.c) c_int {
    return sqlite3_carray_bind_v2(pStmt, idx, aData, nData, mFlags, xDestroy, aData);
}

/// Register the carray() module. Returns the internal Module* (opaque here).
export fn sqlite3CarrayRegister(db: ?*sqlite3) callconv(.c) ?*anyopaque {
    return sqlite3VtabCreateModule(db, "carray", &carrayModule, null, null);
}
