//! Zig port of SQLite's R*Tree spatial-index virtual table (ext/rtree/rtree.c)
//! plus the geopoly extension (ext/rtree/geopoly.c, which upstream #include's
//! textually into rtree.c).
//!
//! This module registers the `rtree` / `rtree_i32` virtual-table modules, the
//! `rtreenode` / `rtreedepth` / `rtreecheck` SQL functions, the public
//! geometry-callback registration entry points
//! (`sqlite3_rtree_geometry_callback` / `sqlite3_rtree_query_callback`), and —
//! because SQLITE_ENABLE_GEOPOLY is on in this build — the `geopoly` virtual
//! table and the `geopoly_*` SQL functions.
//!
//! Exported (non-static) symbols, matching rtree.c+geopoly.c:
//!   * sqlite3RtreeInit                     (internal registration)
//!   * sqlite3_rtree_geometry_callback      (public ABI)
//!   * sqlite3_rtree_query_callback         (public ABI)
//! Everything else (the vtab method tables, the geopoly funcs, etc.) is
//! file-private and registered through sqlite3RtreeInit.
//!
//! Coupling: the Rtree/RtreeCursor/RtreeNode/RtreeCell/RtreeConstraint/...
//! structs are rtree.c's OWN (file-private), so we control their layout. Only
//! the PUBLIC ABI (sqlite3_module, sqlite3_vtab, sqlite3_index_info, the
//! sqlite3_rtree_geometry / _query_info structs from sqlite3rtree.h, and the
//! sqlite3_* API surface) crosses the boundary, and none of that is build-
//! divergent — so a single Zig object serves both the production `zig build`
//! and the `--dev` testfixture without `@import("config")` gating. The on-disk
//! node format (big-endian 16-bit counts, big-endian 32-bit coords, big-endian
//! 64-bit rowids) is reproduced byte-exact.

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Result codes (sqlite3.h)
// ---------------------------------------------------------------------------
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_ABORT: c_int = 4;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_FULL: c_int = 13;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_CORRUPT_VTAB: c_int = SQLITE_CORRUPT | (1 << 8);
const SQLITE_LOCKED_VTAB: c_int = SQLITE_LOCKED | (2 << 8);

// Datatypes (sqlite3.h)
const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;
const SQLITE_TEXT: c_int = 3;
const SQLITE_BLOB: c_int = 4;
const SQLITE_NULL: c_int = 5;

// Conflict resolution (sqlite3.h)
const SQLITE_REPLACE: c_int = 5;

// Function-encoding flags (sqlite3.h)
const SQLITE_UTF8: c_int = 1;
const SQLITE_ANY: c_int = 5;
const SQLITE_DETERMINISTIC: c_int = 0x000000800;
const SQLITE_DIRECTONLY: c_int = 0x000080000;
const SQLITE_INNOCUOUS: c_int = 0x000200000;

// vtab_config (sqlite3.h)
const SQLITE_VTAB_CONSTRAINT_SUPPORT: c_int = 1;
const SQLITE_VTAB_INNOCUOUS: c_int = 2;

// Prepare flags (sqlite3.h)
const SQLITE_PREPARE_PERSISTENT: c_uint = 0x01;
const SQLITE_PREPARE_NO_VTAB: c_uint = 0x04;

// xBestIndex constraint operators / flags (sqlite3.h)
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_INDEX_CONSTRAINT_GT: u8 = 4;
const SQLITE_INDEX_CONSTRAINT_LE: u8 = 8;
const SQLITE_INDEX_CONSTRAINT_LT: u8 = 16;
const SQLITE_INDEX_CONSTRAINT_GE: u8 = 32;
const SQLITE_INDEX_CONSTRAINT_MATCH: u8 = 64;
const SQLITE_INDEX_CONSTRAINT_FUNCTION: c_int = 150;
const SQLITE_INDEX_SCAN_UNIQUE: c_int = 0x00000001;

// sqlite3rtree.h: eWithin values
const NOT_WITHIN: c_int = 0;
const PARTLY_WITHIN: c_int = 1;
const FULLY_WITHIN: c_int = 2;

// Destructor sentinels.
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// ---------------------------------------------------------------------------
// Opaque public handles
// ---------------------------------------------------------------------------
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;
const sqlite3_blob = anyopaque;
const sqlite3_str = anyopaque;
const sqlite3_api_routines = anyopaque;

// ---------------------------------------------------------------------------
// Public ABI structs (sqlite3.h)
// ---------------------------------------------------------------------------
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
    nConstraint: c_int,
    aConstraint: ?[*]sqlite3_index_constraint,
    nOrderBy: c_int,
    aOrderBy: ?[*]sqlite3_index_orderby,
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

const XFunc = ?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void;
const XStep = ?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void;
const XFinal = ?*const fn (?*sqlite3_context) callconv(.c) void;

/// PUBLIC ABI sqlite3_module method table. Field order + iVersion EXACT.
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
    xCommit: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xRollback: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xFindFunction: ?*const fn (*sqlite3_vtab, c_int, [*:0]const u8, *XFunc, *?*anyopaque) callconv(.c) c_int,
    xRename: ?*const fn (*sqlite3_vtab, [*:0]const u8) callconv(.c) c_int,
    xSavepoint: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xRelease: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xRollbackTo: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xShadowName: ?*const fn ([*:0]const u8) callconv(.c) c_int,
    xIntegrity: ?*const fn (*sqlite3_vtab, [*:0]const u8, [*:0]const u8, c_int, *?[*:0]u8) callconv(.c) c_int,
};

// ---------------------------------------------------------------------------
// sqlite3rtree.h public structs (subclassing: query_info begins with the same
// 5 fields as geometry).
// ---------------------------------------------------------------------------
const RtreeDValue = f64; // SQLITE_RTREE_INT_ONLY is OFF
const RtreeValue = f32;
const RTREE_ZERO: RtreeDValue = 0.0;

const XGeom = ?*const fn (*sqlite3_rtree_geometry, c_int, [*]RtreeDValue, *c_int) callconv(.c) c_int;
const XQueryFunc = ?*const fn (*sqlite3_rtree_query_info) callconv(.c) c_int;

const sqlite3_rtree_geometry = extern struct {
    pContext: ?*anyopaque,
    nParam: c_int,
    aParam: ?[*]RtreeDValue,
    pUser: ?*anyopaque,
    xDelUser: ?*const fn (?*anyopaque) callconv(.c) void,
};

const sqlite3_rtree_query_info = extern struct {
    pContext: ?*anyopaque,
    nParam: c_int,
    aParam: ?[*]RtreeDValue,
    pUser: ?*anyopaque,
    xDelUser: ?*const fn (?*anyopaque) callconv(.c) void,
    aCoord: ?[*]RtreeDValue,
    anQueue: ?[*]c_uint,
    nCoord: c_int,
    iLevel: c_int,
    mxLevel: c_int,
    iRowid: i64,
    rParentScore: RtreeDValue,
    eParentWithin: c_int,
    eWithin: c_int,
    rScore: RtreeDValue,
    apSqlParam: ?[*]?*sqlite3_value,
};

// ---------------------------------------------------------------------------
// rtree.c compile-time constants
// ---------------------------------------------------------------------------
const RTREE_MAX_DIMENSIONS: c_int = 5;
const RTREE_MAX_AUX_COLUMN: c_int = 100;
const HASHSIZE: usize = 97;
const RTREE_DEFAULT_ROWEST: i64 = 1048576;
const RTREE_MIN_ROWEST: i64 = 100;

const RTREE_COORD_REAL32: u8 = 0;
const RTREE_COORD_INT32: u8 = 1;

const RTREE_MAXCELLS: c_int = 51;
const RTREE_MAX_DEPTH: c_int = 40;
const RTREE_CACHE_SZ: usize = 5;

// RtreeConstraint.op values
const RTREE_EQ: u8 = 0x41; // A
const RTREE_LE: u8 = 0x42; // B
const RTREE_LT: u8 = 0x43; // C
const RTREE_GE: u8 = 0x44; // D
const RTREE_GT: u8 = 0x45; // E
const RTREE_MATCH: u8 = 0x46; // F
const RTREE_QUERY: u8 = 0x47; // G
const RTREE_TRUE: u8 = 0x3f; // ?
const RTREE_FALSE: u8 = 0x40; // @

const RTREE_CHECK_MAX_ERROR: c_int = 100;

// ---------------------------------------------------------------------------
// rtree.c private structs (our layout; not ABI-shared)
// ---------------------------------------------------------------------------
const RtreeCoord = extern union {
    f: RtreeValue,
    i: c_int,
    u: u32,
};

const Rtree = extern struct {
    base: sqlite3_vtab, // Base class. Must be first
    db: ?*sqlite3,
    iNodeSize: c_int,
    nDim: u8,
    nDim2: u8,
    eCoordType: u8,
    nBytesPerCell: u8,
    inWrTrans: u8,
    nAux: u16,
    // SQLITE_ENABLE_GEOPOLY is ON in this build:
    nAuxNotNull: u8,
    // bCorrupt only exists under SQLITE_DEBUG; include it unconditionally —
    // it is private layout, and the few RTREE_IS_CORRUPT writes are no-ops in
    // production so an extra byte here is harmless (sizeof of a private struct
    // is irrelevant across the ABI; all callers are within this module).
    bCorrupt: u8,
    iDepth: c_int,
    zDb: ?[*:0]u8,
    zName: ?[*:0]u8,
    zNodeName: ?[*:0]u8,
    nBusy: u32,
    nRowEst: i64,
    nCursor: u32,
    nNodeRef: u32,
    zReadAuxSql: ?[*:0]u8,
    pDeleted: ?*RtreeNode,
    pNodeBlob: ?*sqlite3_blob,
    pWriteNode: ?*sqlite3_stmt,
    pDeleteNode: ?*sqlite3_stmt,
    pReadRowid: ?*sqlite3_stmt,
    pWriteRowid: ?*sqlite3_stmt,
    pDeleteRowid: ?*sqlite3_stmt,
    pReadParent: ?*sqlite3_stmt,
    pWriteParent: ?*sqlite3_stmt,
    pDeleteParent: ?*sqlite3_stmt,
    pWriteAux: ?*sqlite3_stmt,
    aHash: [HASHSIZE]?*RtreeNode,
};

const RtreeSearchPoint = extern struct {
    rScore: RtreeDValue,
    id: i64,
    iLevel: u8,
    eWithin: u8,
    iCell: u8,
};

const RtreeCursor = extern struct {
    base: sqlite3_vtab_cursor, // Base class. Must be first
    atEOF: u8,
    bPoint: u8,
    bAuxValid: u8,
    iStrategy: c_int,
    nConstraint: c_int,
    aConstraint: ?[*]RtreeConstraint,
    nPointAlloc: c_int,
    nPoint: c_int,
    mxLevel: c_int,
    aPoint: ?[*]RtreeSearchPoint,
    pReadAux: ?*sqlite3_stmt,
    sPoint: RtreeSearchPoint,
    aNode: [RTREE_CACHE_SZ]?*RtreeNode,
    anQueue: [RTREE_MAX_DEPTH + 1]u32,
};

const RtreeConstraintU = extern union {
    rValue: RtreeDValue,
    xGeom: XGeom,
    xQueryFunc: XQueryFunc,
};

const RtreeConstraint = extern struct {
    iCoord: c_int,
    op: c_int,
    u: RtreeConstraintU,
    pInfo: ?*sqlite3_rtree_query_info,
};

const RtreeNode = extern struct {
    pParent: ?*RtreeNode,
    iNode: i64,
    nRef: c_int,
    isDirty: c_int,
    zData: ?[*]u8,
    pNext: ?*RtreeNode,
};

const RtreeCell = extern struct {
    iRowid: i64,
    aCoord: [RTREE_MAX_DIMENSIONS * 2]RtreeCoord,
};

const RtreeGeomCallback = extern struct {
    xGeom: XGeom,
    xQueryFunc: XQueryFunc,
    xDestructor: ?*const fn (?*anyopaque) callconv(.c) void,
    pContext: ?*anyopaque,
};

const RtreeMatchArg = extern struct {
    iSize: u32,
    cb: RtreeGeomCallback,
    nParam: c_int,
    apSqlParam: ?[*]?*sqlite3_value,
    // aParam[] flex array follows; offset computed by szRtreeMatchArg().
};

/// offsetof(RtreeMatchArg, aParam): the flex array sits right after apSqlParam.
fn offsetofAParam() usize {
    return std.mem.alignForward(usize, @offsetOf(RtreeMatchArg, "apSqlParam") + @sizeOf(?*anyopaque), @alignOf(RtreeDValue));
}
fn szRtreeMatchArg(n: usize) usize {
    return offsetofAParam() + n * @sizeOf(RtreeDValue);
}
fn aParamPtr(p: *RtreeMatchArg) [*]RtreeDValue {
    const base: [*]u8 = @ptrCast(p);
    return @ptrCast(@alignCast(base + offsetofAParam()));
}

// ---------------------------------------------------------------------------
// sqlite3 API (resolved at link time)
// ---------------------------------------------------------------------------
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *std.builtin.VaList) ?[*:0]u8;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;

extern fn sqlite3_str_new(db: ?*sqlite3) ?*sqlite3_str;
extern fn sqlite3_str_append(p: ?*sqlite3_str, z: [*]const u8, n: c_int) void;
extern fn sqlite3_str_appendf(p: ?*sqlite3_str, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_str_finish(p: ?*sqlite3_str) ?[*:0]u8;
extern fn sqlite3_str_errcode(p: ?*sqlite3_str) c_int;

extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_vtab_config(db: ?*sqlite3, op: c_int, ...) c_int;
extern fn sqlite3_vtab_on_conflict(db: ?*sqlite3) c_int;
extern fn sqlite3_vtab_nochange(ctx: ?*sqlite3_context) c_int;
extern fn sqlite3_create_module_v2(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pAux: ?*anyopaque, xDestroy: DestructorFn) c_int;
extern fn sqlite3_create_function(db: ?*sqlite3, zName: [*:0]const u8, nArg: c_int, eTextRep: c_int, pApp: ?*anyopaque, xFunc: XFunc, xStep: XStep, xFinal: XFinal) c_int;
extern fn sqlite3_create_function_v2(db: ?*sqlite3, zName: [*:0]const u8, nArg: c_int, eTextRep: c_int, pApp: ?*anyopaque, xFunc: XFunc, xStep: XStep, xFinal: XFinal, xDestroy: DestructorFn) c_int;

extern fn sqlite3_exec(db: ?*sqlite3, sql: [*:0]const u8, cb: ?*anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_errmsg(db: ?*sqlite3) ?[*:0]const u8;
extern fn sqlite3_last_insert_rowid(db: ?*sqlite3) i64;
extern fn sqlite3_context_db_handle(ctx: ?*sqlite3_context) ?*sqlite3;
extern fn sqlite3_user_data(ctx: ?*sqlite3_context) ?*anyopaque;
extern fn sqlite3_aggregate_context(ctx: ?*sqlite3_context, n: c_int) ?*anyopaque;
extern fn sqlite3_table_column_metadata(db: ?*sqlite3, zDb: ?[*:0]const u8, zTab: [*:0]const u8, zCol: ?[*:0]const u8, pDataType: ?*?[*:0]const u8, pCollSeq: ?*?[*:0]const u8, pNotNull: ?*c_int, pPrimaryKey: ?*c_int, pAutoinc: ?*c_int) c_int;

extern fn sqlite3_prepare_v2(db: ?*sqlite3, zSql: [*:0]const u8, nByte: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_prepare_v3(db: ?*sqlite3, zSql: [*:0]const u8, nByte: c_int, prepFlags: c_uint, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_finalize(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_count(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_int(p: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_int64(p: ?*sqlite3_stmt, i: c_int) i64;
extern fn sqlite3_column_bytes(p: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_blob(p: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_type(p: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_name(p: ?*sqlite3_stmt, i: c_int) ?[*:0]const u8;
extern fn sqlite3_column_value(p: ?*sqlite3_stmt, i: c_int) ?*sqlite3_value;

extern fn sqlite3_bind_int64(p: ?*sqlite3_stmt, i: c_int, v: i64) c_int;
extern fn sqlite3_bind_null(p: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_bind_blob(p: ?*sqlite3_stmt, i: c_int, z: ?*const anyopaque, n: c_int, xDel: DestructorFn) c_int;
extern fn sqlite3_bind_value(p: ?*sqlite3_stmt, i: c_int, v: ?*sqlite3_value) c_int;

extern fn sqlite3_blob_open(db: ?*sqlite3, zDb: [*:0]const u8, zTable: [*:0]const u8, zColumn: [*:0]const u8, iRow: i64, flags: c_int, ppBlob: *?*sqlite3_blob) c_int;
extern fn sqlite3_blob_close(p: ?*sqlite3_blob) c_int;
extern fn sqlite3_blob_reopen(p: ?*sqlite3_blob, iRow: i64) c_int;
extern fn sqlite3_blob_bytes(p: ?*sqlite3_blob) c_int;
extern fn sqlite3_blob_read(p: ?*sqlite3_blob, z: ?*anyopaque, n: c_int, iOffset: c_int) c_int;

extern fn sqlite3_value_type(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_numeric_type(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(v: ?*sqlite3_value) i64;
extern fn sqlite3_value_double(v: ?*sqlite3_value) f64;
extern fn sqlite3_value_bytes(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_blob(v: ?*sqlite3_value) ?*const anyopaque;
extern fn sqlite3_value_text(v: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_pointer(v: ?*sqlite3_value, zPType: [*:0]const u8) ?*anyopaque;
extern fn sqlite3_value_dup(v: ?*const sqlite3_value) ?*sqlite3_value;
extern fn sqlite3_value_free(v: ?*sqlite3_value) void;
extern fn sqlite3_value_nochange(v: ?*sqlite3_value) c_int;

extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_result_double(ctx: ?*sqlite3_context, v: f64) void;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_blob(ctx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_value(ctx: ?*sqlite3_context, v: ?*sqlite3_value) void;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: [*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(ctx: ?*sqlite3_context, code: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*sqlite3_context) void;
extern fn sqlite3_result_pointer(ctx: ?*sqlite3_context, p: ?*anyopaque, zType: [*:0]const u8, xDel: DestructorFn) void;

// In SQLite core: sqlite3GetToken / sqlite3IntFloatCompare
extern fn sqlite3GetToken(z: [*]const u8, pType: *c_int) c_int;
extern fn sqlite3IntFloatCompare(i: i64, r: f64) c_int;

// ---------------------------------------------------------------------------
// SQLITE_STATIC adoption pointer for sqlite3_free as a destructor
// ---------------------------------------------------------------------------
fn freeDestructor(p: ?*anyopaque) callconv(.c) void {
    sqlite3_free(p);
}

// ---------------------------------------------------------------------------
// Big-endian (de)serialization — byte-exact with the on-disk node format.
// ---------------------------------------------------------------------------
fn readInt16(p: [*]const u8) c_int {
    return (@as(c_int, p[0]) << 8) + @as(c_int, p[1]);
}
fn readCoord(p: [*]const u8, pCoord: *RtreeCoord) void {
    pCoord.u = (@as(u32, p[0]) << 24) +
        (@as(u32, p[1]) << 16) +
        (@as(u32, p[2]) << 8) +
        (@as(u32, p[3]) << 0);
}
fn readInt64(p: [*]const u8) i64 {
    const v: u64 = (@as(u64, p[0]) << 56) +
        (@as(u64, p[1]) << 48) +
        (@as(u64, p[2]) << 40) +
        (@as(u64, p[3]) << 32) +
        (@as(u64, p[4]) << 24) +
        (@as(u64, p[5]) << 16) +
        (@as(u64, p[6]) << 8) +
        (@as(u64, p[7]) << 0);
    return @bitCast(v);
}
fn writeInt16(p: [*]u8, i: c_int) void {
    p[0] = @truncate(@as(c_uint, @bitCast(i >> 8)) & 0xFF);
    p[1] = @truncate(@as(c_uint, @bitCast(i >> 0)) & 0xFF);
}
fn writeCoord(p: [*]u8, pCoord: *const RtreeCoord) c_int {
    const i = pCoord.u;
    p[0] = @truncate((i >> 24) & 0xFF);
    p[1] = @truncate((i >> 16) & 0xFF);
    p[2] = @truncate((i >> 8) & 0xFF);
    p[3] = @truncate((i >> 0) & 0xFF);
    return 4;
}
fn writeInt64(p: [*]u8, i: i64) c_int {
    const u: u64 = @bitCast(i);
    p[0] = @truncate((u >> 56) & 0xFF);
    p[1] = @truncate((u >> 48) & 0xFF);
    p[2] = @truncate((u >> 40) & 0xFF);
    p[3] = @truncate((u >> 32) & 0xFF);
    p[4] = @truncate((u >> 24) & 0xFF);
    p[5] = @truncate((u >> 16) & 0xFF);
    p[6] = @truncate((u >> 8) & 0xFF);
    p[7] = @truncate((u >> 0) & 0xFF);
    return 8;
}

/// NCELL(pNode) = readInt16(&pNode->zData[2])
fn NCELL(pNode: *RtreeNode) c_int {
    return readInt16(pNode.zData.? + 2);
}

/// RTREE_OF_CURSOR
fn rtreeOfCursor(p: *RtreeCursor) *Rtree {
    return @ptrCast(@alignCast(p.base.pVtab.?));
}

/// DCOORD(coord) for the current pRtree.
fn dcoord(pRtree: *Rtree, coord: RtreeCoord) RtreeDValue {
    if (pRtree.eCoordType == RTREE_COORD_REAL32) {
        return @floatCast(coord.f);
    } else {
        return @floatFromInt(coord.i);
    }
}

inline fn nDim2usize(pRtree: *Rtree) usize {
    return @intCast(pRtree.nDim2);
}

// RTREE_MINCELLS(p) = (((p->iNodeSize-4)/p->nBytesPerCell)/3)
fn rtreeMincells(p: *Rtree) c_int {
    return @divTrunc(@divTrunc(p.iNodeSize - 4, @as(c_int, p.nBytesPerCell)), 3);
}

inline fn maxd(x: RtreeDValue, y: RtreeDValue) RtreeDValue {
    return if (x < y) y else x;
}
inline fn mind(x: RtreeDValue, y: RtreeDValue) RtreeDValue {
    return if (x > y) y else x;
}

// ---------------------------------------------------------------------------
// Node management
// ---------------------------------------------------------------------------
fn nodeReference(p: ?*RtreeNode) void {
    if (p) |n| {
        n.nRef += 1;
    }
}

fn nodeZero(pRtree: *Rtree, p: *RtreeNode) void {
    const z = p.zData.?;
    const n: usize = @intCast(pRtree.iNodeSize - 2);
    @memset(z[2 .. 2 + n], 0);
    p.isDirty = 1;
}

fn nodeHash(iNode: i64) usize {
    return @as(usize, @intCast(@as(u32, @truncate(@as(u64, @bitCast(iNode)))))) % HASHSIZE;
}

fn nodeHashLookup(pRtree: *Rtree, iNode: i64) ?*RtreeNode {
    var p = pRtree.aHash[nodeHash(iNode)];
    while (p) |n| {
        if (n.iNode == iNode) break;
        p = n.pNext;
    }
    return p;
}

fn nodeHashInsert(pRtree: *Rtree, pNode: *RtreeNode) void {
    const iHash = nodeHash(pNode.iNode);
    pNode.pNext = pRtree.aHash[iHash];
    pRtree.aHash[iHash] = pNode;
}

fn nodeHashDelete(pRtree: *Rtree, pNode: *RtreeNode) void {
    if (pNode.iNode != 0) {
        var pp = &pRtree.aHash[nodeHash(pNode.iNode)];
        while (pp.* != pNode) {
            pp = &pp.*.?.pNext;
        }
        pp.* = pNode.pNext;
        pNode.pNext = null;
    }
}

fn nodeNew(pRtree: *Rtree, pParent: ?*RtreeNode) ?*RtreeNode {
    const sz = @sizeOf(RtreeNode) + @as(usize, @intCast(pRtree.iNodeSize));
    const pNode: ?*RtreeNode = @ptrCast(@alignCast(sqlite3_malloc64(sz)));
    if (pNode) |n| {
        const bytes: [*]u8 = @ptrCast(n);
        @memset(bytes[0..sz], 0);
        n.zData = bytes + @sizeOf(RtreeNode);
        n.nRef = 1;
        pRtree.nNodeRef += 1;
        n.pParent = pParent;
        n.isDirty = 1;
        nodeReference(pParent);
    }
    return pNode;
}

fn nodeBlobReset(pRtree: *Rtree) void {
    const pBlob = pRtree.pNodeBlob;
    pRtree.pNodeBlob = null;
    _ = sqlite3_blob_close(pBlob);
}

fn nodeAcquire(
    pRtree: *Rtree,
    iNode: i64,
    pParent: ?*RtreeNode,
    ppNode: *?*RtreeNode,
) c_int {
    var rc: c_int = SQLITE_OK;
    var pNode: ?*RtreeNode = null;

    if (nodeHashLookup(pRtree, iNode)) |nd| {
        if (pParent != null and pParent != nd.pParent) {
            return SQLITE_CORRUPT_VTAB;
        }
        nd.nRef += 1;
        ppNode.* = nd;
        return SQLITE_OK;
    }

    if (pRtree.pNodeBlob != null) {
        const pBlob = pRtree.pNodeBlob;
        pRtree.pNodeBlob = null;
        rc = sqlite3_blob_reopen(pBlob, iNode);
        pRtree.pNodeBlob = pBlob;
        if (rc != 0) {
            nodeBlobReset(pRtree);
            if (rc == SQLITE_NOMEM) return SQLITE_NOMEM;
        }
    }
    if (pRtree.pNodeBlob == null) {
        rc = sqlite3_blob_open(pRtree.db, pRtree.zDb.?, pRtree.zNodeName.?, "data", iNode, 0, &pRtree.pNodeBlob);
    }
    if (rc != 0) {
        ppNode.* = null;
        if (rc == SQLITE_ERROR) {
            rc = SQLITE_CORRUPT_VTAB;
        }
    } else if (iNode <= 0) {
        rc = SQLITE_CORRUPT_VTAB;
    } else if (pRtree.iNodeSize == sqlite3_blob_bytes(pRtree.pNodeBlob)) {
        const sz = @sizeOf(RtreeNode) + @as(usize, @intCast(pRtree.iNodeSize));
        pNode = @ptrCast(@alignCast(sqlite3_malloc64(sz)));
        if (pNode == null) {
            rc = SQLITE_NOMEM;
        } else {
            const nd = pNode.?;
            const bytes: [*]u8 = @ptrCast(nd);
            nd.pParent = pParent;
            nd.zData = bytes + @sizeOf(RtreeNode);
            nd.nRef = 1;
            pRtree.nNodeRef += 1;
            nd.iNode = iNode;
            nd.isDirty = 0;
            nd.pNext = null;
            rc = sqlite3_blob_read(pRtree.pNodeBlob, nd.zData, pRtree.iNodeSize, 0);
        }
    }

    if (rc == SQLITE_OK and pNode != null and iNode == 1) {
        pRtree.iDepth = readInt16(pNode.?.zData.?);
        if (pRtree.iDepth > RTREE_MAX_DEPTH) {
            rc = SQLITE_CORRUPT_VTAB;
        }
    }

    if (pNode != null and rc == SQLITE_OK) {
        if (NCELL(pNode.?) > @divTrunc(pRtree.iNodeSize - 4, @as(c_int, pRtree.nBytesPerCell))) {
            rc = SQLITE_CORRUPT_VTAB;
        }
    }

    if (rc == SQLITE_OK) {
        if (pNode != null) {
            nodeReference(pParent);
            nodeHashInsert(pRtree, pNode.?);
        } else {
            rc = SQLITE_CORRUPT_VTAB;
        }
        ppNode.* = pNode;
    } else {
        nodeBlobReset(pRtree);
        if (pNode) |nd| {
            pRtree.nNodeRef -= 1;
            sqlite3_free(nd);
        }
        ppNode.* = null;
    }

    return rc;
}

fn nodeOverwriteCell(pRtree: *Rtree, pNode: *RtreeNode, pCell: *const RtreeCell, iCell: c_int) void {
    var p = pNode.zData.? + @as(usize, @intCast(4 + @as(c_int, pRtree.nBytesPerCell) * iCell));
    p += @intCast(writeInt64(p, pCell.iRowid));
    var ii: usize = 0;
    while (ii < nDim2usize(pRtree)) : (ii += 1) {
        p += @intCast(writeCoord(p, &pCell.aCoord[ii]));
    }
    pNode.isDirty = 1;
}

fn nodeDeleteCell(pRtree: *Rtree, pNode: *RtreeNode, iCell: c_int) void {
    const bpc: usize = pRtree.nBytesPerCell;
    const pDst = pNode.zData.? + @as(usize, @intCast(4 + @as(c_int, pRtree.nBytesPerCell) * iCell));
    const pSrc = pDst + bpc;
    const nByte: usize = @intCast((NCELL(pNode) - iCell - 1) * @as(c_int, pRtree.nBytesPerCell));
    std.mem.copyForwards(u8, pDst[0..nByte], pSrc[0..nByte]);
    writeInt16(pNode.zData.? + 2, NCELL(pNode) - 1);
    pNode.isDirty = 1;
}

fn nodeInsertCell(pRtree: *Rtree, pNode: *RtreeNode, pCell: *const RtreeCell) c_int {
    const nMaxCell = @divTrunc(pRtree.iNodeSize - 4, @as(c_int, pRtree.nBytesPerCell));
    const nCell = NCELL(pNode);
    if (nCell < nMaxCell) {
        nodeOverwriteCell(pRtree, pNode, pCell, nCell);
        writeInt16(pNode.zData.? + 2, nCell + 1);
        pNode.isDirty = 1;
    }
    return @intFromBool(nCell == nMaxCell);
}

fn nodeWrite(pRtree: *Rtree, pNode: *RtreeNode) c_int {
    var rc: c_int = SQLITE_OK;
    if (pNode.isDirty != 0) {
        const p = pRtree.pWriteNode;
        if (pNode.iNode != 0) {
            _ = sqlite3_bind_int64(p, 1, pNode.iNode);
        } else {
            _ = sqlite3_bind_null(p, 1);
        }
        _ = sqlite3_bind_blob(p, 2, pNode.zData, pRtree.iNodeSize, SQLITE_STATIC);
        _ = sqlite3_step(p);
        pNode.isDirty = 0;
        rc = sqlite3_reset(p);
        _ = sqlite3_bind_null(p, 2);
        if (pNode.iNode == 0 and rc == SQLITE_OK) {
            pNode.iNode = sqlite3_last_insert_rowid(pRtree.db);
            nodeHashInsert(pRtree, pNode);
        }
    }
    return rc;
}

fn nodeRelease(pRtree: *Rtree, pNodeOpt: ?*RtreeNode) c_int {
    var rc: c_int = SQLITE_OK;
    if (pNodeOpt) |pNode| {
        pNode.nRef -= 1;
        if (pNode.nRef == 0) {
            pRtree.nNodeRef -= 1;
            if (pNode.iNode == 1) {
                pRtree.iDepth = -1;
            }
            if (pNode.pParent) |par| {
                rc = nodeRelease(pRtree, par);
            }
            if (rc == SQLITE_OK) {
                rc = nodeWrite(pRtree, pNode);
            }
            nodeHashDelete(pRtree, pNode);
            sqlite3_free(pNode);
        }
    }
    return rc;
}

fn nodeGetRowid(pRtree: *Rtree, pNode: *RtreeNode, iCell: c_int) i64 {
    return readInt64(pNode.zData.? + @as(usize, @intCast(4 + @as(c_int, pRtree.nBytesPerCell) * iCell)));
}

fn nodeGetCoord(pRtree: *Rtree, pNode: *RtreeNode, iCell: c_int, iCoord: c_int, pCoord: *RtreeCoord) void {
    readCoord(pNode.zData.? + @as(usize, @intCast(12 + @as(c_int, pRtree.nBytesPerCell) * iCell + 4 * iCoord)), pCoord);
}

fn nodeGetCell(pRtree: *Rtree, pNode: *RtreeNode, iCell: c_int, pCell: *RtreeCell) void {
    pCell.iRowid = nodeGetRowid(pRtree, pNode, iCell);
    var pData = pNode.zData.? + @as(usize, @intCast(12 + @as(c_int, pRtree.nBytesPerCell) * iCell));
    var ii: usize = 0;
    while (true) {
        readCoord(pData, &pCell.aCoord[ii]);
        readCoord(pData + 4, &pCell.aCoord[ii + 1]);
        pData += 8;
        ii += 2;
        if (ii >= nDim2usize(pRtree)) break;
    }
}

// ---------------------------------------------------------------------------
// xCreate/xConnect/xDisconnect/xDestroy/xOpen and forward decls
// ---------------------------------------------------------------------------
fn rtreeCreate(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return rtreeInit(db, pAux, argc, argv, ppVtab, pzErr, 1);
}
fn rtreeConnect(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return rtreeInit(db, pAux, argc, argv, ppVtab, pzErr, 0);
}

fn rtreeReference(pRtree: *Rtree) void {
    pRtree.nBusy += 1;
}

fn rtreeRelease(pRtree: *Rtree) void {
    pRtree.nBusy -= 1;
    if (pRtree.nBusy == 0) {
        pRtree.inWrTrans = 0;
        nodeBlobReset(pRtree);
        if (pRtree.nNodeRef != 0) {
            var i: usize = 0;
            while (i < HASHSIZE) : (i += 1) {
                while (pRtree.aHash[i]) |h| {
                    const pNext = h.pNext;
                    sqlite3_free(h);
                    pRtree.aHash[i] = pNext;
                }
            }
        }
        _ = sqlite3_finalize(pRtree.pWriteNode);
        _ = sqlite3_finalize(pRtree.pDeleteNode);
        _ = sqlite3_finalize(pRtree.pReadRowid);
        _ = sqlite3_finalize(pRtree.pWriteRowid);
        _ = sqlite3_finalize(pRtree.pDeleteRowid);
        _ = sqlite3_finalize(pRtree.pReadParent);
        _ = sqlite3_finalize(pRtree.pWriteParent);
        _ = sqlite3_finalize(pRtree.pDeleteParent);
        _ = sqlite3_finalize(pRtree.pWriteAux);
        sqlite3_free(pRtree.zReadAuxSql);
        sqlite3_free(pRtree);
    }
}

fn rtreeDisconnect(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    rtreeRelease(@ptrCast(@alignCast(pVtab)));
    return SQLITE_OK;
}

fn rtreeDestroy(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    var rc: c_int = undefined;
    const zCreate = sqlite3_mprintf(
        "DROP TABLE '%q'.'%q_node';" ++
            "DROP TABLE '%q'.'%q_rowid';" ++
            "DROP TABLE '%q'.'%q_parent';",
        pRtree.zDb,
        pRtree.zName,
        pRtree.zDb,
        pRtree.zName,
        pRtree.zDb,
        pRtree.zName,
    );
    if (zCreate == null) {
        rc = SQLITE_NOMEM;
    } else {
        nodeBlobReset(pRtree);
        rc = sqlite3_exec(pRtree.db, zCreate.?, null, null, null);
        sqlite3_free(zCreate);
    }
    if (rc == SQLITE_OK) {
        rtreeRelease(pRtree);
    }
    return rc;
}

fn rtreeOpen(pVTab: *sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    var rc: c_int = SQLITE_NOMEM;
    const pRtree: *Rtree = @ptrCast(@alignCast(pVTab));
    const pCsr: ?*RtreeCursor = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(RtreeCursor))));
    if (pCsr) |c| {
        c.* = std.mem.zeroes(RtreeCursor);
        c.base.pVtab = pVTab;
        rc = SQLITE_OK;
        pRtree.nCursor += 1;
    }
    ppCursor.* = if (pCsr) |c| &c.base else null;
    return rc;
}

fn resetCursor(pCsr: *RtreeCursor) void {
    const pRtree: *Rtree = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    if (pCsr.aConstraint) |ac| {
        var i: usize = 0;
        const n: usize = @intCast(pCsr.nConstraint);
        while (i < n) : (i += 1) {
            if (ac[i].pInfo) |pInfo| {
                if (pInfo.xDelUser) |xd| xd(pInfo.pUser);
                sqlite3_free(pInfo);
            }
        }
        sqlite3_free(ac);
        pCsr.aConstraint = null;
    }
    var ii: usize = 0;
    while (ii < RTREE_CACHE_SZ) : (ii += 1) _ = nodeRelease(pRtree, pCsr.aNode[ii]);
    sqlite3_free(pCsr.aPoint);
    const pStmt = pCsr.pReadAux;
    pCsr.* = std.mem.zeroes(RtreeCursor);
    pCsr.base.pVtab = @ptrCast(pRtree);
    pCsr.pReadAux = pStmt;
    _ = sqlite3_reset(pStmt);
}

fn rtreeClose(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(cur.pVtab.?));
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(cur));
    resetCursor(pCsr);
    _ = sqlite3_finalize(pCsr.pReadAux);
    sqlite3_free(pCsr);
    pRtree.nCursor -= 1;
    if (pRtree.nCursor == 0 and pRtree.inWrTrans == 0) {
        nodeBlobReset(pRtree);
    }
    return SQLITE_OK;
}

fn rtreeEof(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(cur));
    return pCsr.atEOF;
}

/// RTREE_DECODE_COORD generic path: big-endian decode into a double.
fn rtreeDecodeCoord(eInt: c_int, a: [*]const u8) RtreeDValue {
    var c: RtreeCoord = undefined;
    c.u = (@as(u32, a[0]) << 24) + (@as(u32, a[1]) << 16) + (@as(u32, a[2]) << 8) + @as(u32, a[3]);
    if (eInt != 0) {
        return @floatFromInt(c.i);
    } else {
        return @floatCast(c.f);
    }
}

fn rtreeCallbackConstraint(
    pConstraint: *RtreeConstraint,
    eInt: c_int,
    pCellData0: [*]const u8,
    pSearch: *RtreeSearchPoint,
    prScore: *RtreeDValue,
    peWithin: *c_int,
) c_int {
    const pInfo = pConstraint.pInfo.?;
    const nCoord = pInfo.nCoord;
    var rc: c_int = undefined;
    var c: RtreeCoord = undefined;
    _ = &c;
    var aCoord: [RTREE_MAX_DIMENSIONS * 2]RtreeDValue = undefined;

    if (pConstraint.op == RTREE_QUERY and pSearch.iLevel == 1) {
        pInfo.iRowid = readInt64(pCellData0);
    }
    const pCellData = pCellData0 + 8;

    // eInt==0 -> float coords; else integer. Fill aCoord with a fall-through
    // switch (mirrors the C duff-style decode).
    var ci: usize = 0;
    if (eInt == 0) {
        ci = 0;
        const ncu: usize = @intCast(nCoord);
        while (ci < ncu) : (ci += 1) {
            readCoord(pCellData + ci * 4, &c);
            aCoord[ci] = @floatCast(c.f);
        }
    } else {
        ci = 0;
        const ncu: usize = @intCast(nCoord);
        while (ci < ncu) : (ci += 1) {
            readCoord(pCellData + ci * 4, &c);
            aCoord[ci] = @floatFromInt(c.i);
        }
    }

    if (pConstraint.op == RTREE_MATCH) {
        var eWithin: c_int = 0;
        rc = pConstraint.u.xGeom.?(@ptrCast(pInfo), nCoord, &aCoord, &eWithin);
        if (eWithin == 0) peWithin.* = NOT_WITHIN;
        prScore.* = RTREE_ZERO;
    } else {
        pInfo.aCoord = &aCoord;
        pInfo.iLevel = @as(c_int, pSearch.iLevel) - 1;
        pInfo.rScore = pSearch.rScore;
        pInfo.rParentScore = pSearch.rScore;
        pInfo.eWithin = pSearch.eWithin;
        pInfo.eParentWithin = pSearch.eWithin;
        rc = pConstraint.u.xQueryFunc.?(pInfo);
        if (pInfo.eWithin < peWithin.*) peWithin.* = pInfo.eWithin;
        if (pInfo.rScore < prScore.* or prScore.* < RTREE_ZERO) {
            prScore.* = pInfo.rScore;
        }
    }
    return rc;
}

fn rtreeNonleafConstraint(p: *RtreeConstraint, eInt: c_int, pCellData0: [*]const u8, peWithin: *c_int) void {
    var val: RtreeDValue = undefined;
    var pCellData = pCellData0 + @as(usize, @intCast(8 + 4 * (p.iCoord & 0xfe)));
    switch (@as(u8, @intCast(p.op))) {
        RTREE_TRUE => return,
        RTREE_FALSE => {},
        RTREE_EQ => {
            val = rtreeDecodeCoord(eInt, pCellData);
            if (p.u.rValue >= val) {
                pCellData += 4;
                val = rtreeDecodeCoord(eInt, pCellData);
                if (p.u.rValue <= val) return;
            }
        },
        RTREE_LE, RTREE_LT => {
            val = rtreeDecodeCoord(eInt, pCellData);
            if (p.u.rValue >= val) return;
        },
        else => {
            pCellData += 4;
            val = rtreeDecodeCoord(eInt, pCellData);
            if (p.u.rValue <= val) return;
        },
    }
    peWithin.* = NOT_WITHIN;
}

fn rtreeLeafConstraint(p: *RtreeConstraint, eInt: c_int, pCellData0: [*]const u8, peWithin: *c_int) void {
    const pCellData = pCellData0 + @as(usize, @intCast(8 + p.iCoord * 4));
    const xN = rtreeDecodeCoord(eInt, pCellData);
    switch (@as(u8, @intCast(p.op))) {
        RTREE_TRUE => return,
        RTREE_FALSE => {},
        RTREE_LE => {
            if (xN <= p.u.rValue) return;
        },
        RTREE_LT => {
            if (xN < p.u.rValue) return;
        },
        RTREE_GE => {
            if (xN >= p.u.rValue) return;
        },
        RTREE_GT => {
            if (xN > p.u.rValue) return;
        },
        else => {
            if (xN == p.u.rValue) return;
        },
    }
    peWithin.* = NOT_WITHIN;
}

fn nodeRowidIndex(pRtree: *Rtree, pNode: *RtreeNode, iRowid: i64, piIndex: *c_int) c_int {
    const nCell = NCELL(pNode);
    var ii: c_int = 0;
    while (ii < nCell) : (ii += 1) {
        if (nodeGetRowid(pRtree, pNode, ii) == iRowid) {
            piIndex.* = ii;
            return SQLITE_OK;
        }
    }
    return SQLITE_CORRUPT_VTAB;
}

fn nodeParentIndex(pRtree: *Rtree, pNode: *RtreeNode, piIndex: *c_int) c_int {
    if (pNode.pParent) |pParent| {
        return nodeRowidIndex(pRtree, pParent, pNode.iNode, piIndex);
    } else {
        piIndex.* = -1;
        return SQLITE_OK;
    }
}

fn rtreeSearchPointCompare(pA: *const RtreeSearchPoint, pB: *const RtreeSearchPoint) c_int {
    if (pA.rScore < pB.rScore) return -1;
    if (pA.rScore > pB.rScore) return 1;
    if (pA.iLevel < pB.iLevel) return -1;
    if (pA.iLevel > pB.iLevel) return 1;
    return 0;
}

fn rtreeSearchPointSwap(p: *RtreeCursor, i: c_int, j: c_int) void {
    const ap = p.aPoint.?;
    const t = ap[@intCast(i)];
    ap[@intCast(i)] = ap[@intCast(j)];
    ap[@intCast(j)] = t;
    const ci2: usize = @intCast(i + 1);
    const cj2: usize = @intCast(j + 1);
    if (ci2 < RTREE_CACHE_SZ) {
        if (cj2 >= RTREE_CACHE_SZ) {
            _ = nodeRelease(rtreeOfCursor(p), p.aNode[ci2]);
            p.aNode[ci2] = null;
        } else {
            const pTemp = p.aNode[ci2];
            p.aNode[ci2] = p.aNode[cj2];
            p.aNode[cj2] = pTemp;
        }
    }
}

fn rtreeSearchPointFirst(pCur: *RtreeCursor) ?*RtreeSearchPoint {
    if (pCur.bPoint != 0) return &pCur.sPoint;
    if (pCur.nPoint != 0) return &pCur.aPoint.?[0];
    return null;
}

fn rtreeNodeOfFirstSearchPoint(pCur: *RtreeCursor, pRC: *c_int) ?*RtreeNode {
    const ii: usize = @intCast(1 - @as(c_int, pCur.bPoint));
    if (pCur.aNode[ii] == null) {
        const id = if (ii != 0) pCur.aPoint.?[0].id else pCur.sPoint.id;
        pRC.* = nodeAcquire(rtreeOfCursor(pCur), id, null, &pCur.aNode[ii]);
    }
    return pCur.aNode[ii];
}

fn rtreeEnqueue(pCur: *RtreeCursor, rScore: RtreeDValue, iLevel: u8) ?*RtreeSearchPoint {
    if (pCur.nPoint >= pCur.nPointAlloc) {
        const nNew = pCur.nPointAlloc * 2 + 8;
        const pNew: ?[*]RtreeSearchPoint = @ptrCast(@alignCast(sqlite3_realloc64(pCur.aPoint, @as(u64, @intCast(nNew)) * @sizeOf(RtreeSearchPoint))));
        if (pNew == null) return null;
        pCur.aPoint = pNew;
        pCur.nPointAlloc = nNew;
    }
    var i: c_int = pCur.nPoint;
    pCur.nPoint += 1;
    var pNew = &pCur.aPoint.?[@intCast(i)];
    pNew.rScore = rScore;
    pNew.iLevel = iLevel;
    while (i > 0) {
        const j = @divTrunc(i - 1, 2);
        const pParent = &pCur.aPoint.?[@intCast(j)];
        if (rtreeSearchPointCompare(pNew, pParent) >= 0) break;
        rtreeSearchPointSwap(pCur, j, i);
        i = j;
        pNew = pParent;
    }
    return pNew;
}

fn rtreeSearchPointNew(pCur: *RtreeCursor, rScore: RtreeDValue, iLevel: u8) ?*RtreeSearchPoint {
    const pFirst = rtreeSearchPointFirst(pCur);
    pCur.anQueue[iLevel] += 1;
    if (pFirst == null or pFirst.?.rScore > rScore or (pFirst.?.rScore == rScore and pFirst.?.iLevel > iLevel)) {
        if (pCur.bPoint != 0) {
            const pNew = rtreeEnqueue(pCur, rScore, iLevel);
            if (pNew == null) return null;
            const ii: usize = @as(usize, @intCast((@intFromPtr(pNew.?) - @intFromPtr(pCur.aPoint.?)) / @sizeOf(RtreeSearchPoint))) + 1;
            if (ii < RTREE_CACHE_SZ) {
                pCur.aNode[ii] = pCur.aNode[0];
            } else {
                _ = nodeRelease(rtreeOfCursor(pCur), pCur.aNode[0]);
            }
            pCur.aNode[0] = null;
            pNew.?.* = pCur.sPoint;
        }
        pCur.sPoint.rScore = rScore;
        pCur.sPoint.iLevel = iLevel;
        pCur.bPoint = 1;
        return &pCur.sPoint;
    } else {
        return rtreeEnqueue(pCur, rScore, iLevel);
    }
}

fn rtreeSearchPointPop(p: *RtreeCursor) void {
    var i: c_int = 1 - @as(c_int, p.bPoint);
    if (p.aNode[@intCast(i)] != null) {
        _ = nodeRelease(rtreeOfCursor(p), p.aNode[@intCast(i)]);
        p.aNode[@intCast(i)] = null;
    }
    if (p.bPoint != 0) {
        p.anQueue[p.sPoint.iLevel] -= 1;
        p.bPoint = 0;
    } else if (p.nPoint != 0) {
        p.anQueue[p.aPoint.?[0].iLevel] -= 1;
        p.nPoint -= 1;
        const n = p.nPoint;
        p.aPoint.?[0] = p.aPoint.?[@intCast(n)];
        if (n < RTREE_CACHE_SZ - 1) {
            p.aNode[1] = p.aNode[@intCast(n + 1)];
            p.aNode[@intCast(n + 1)] = null;
        }
        i = 0;
        while (true) {
            const j = i * 2 + 1;
            if (j >= n) break;
            const k = j + 1;
            if (k < n and rtreeSearchPointCompare(&p.aPoint.?[@intCast(k)], &p.aPoint.?[@intCast(j)]) < 0) {
                if (rtreeSearchPointCompare(&p.aPoint.?[@intCast(k)], &p.aPoint.?[@intCast(i)]) < 0) {
                    rtreeSearchPointSwap(p, i, k);
                    i = k;
                } else break;
            } else {
                if (rtreeSearchPointCompare(&p.aPoint.?[@intCast(j)], &p.aPoint.?[@intCast(i)]) < 0) {
                    rtreeSearchPointSwap(p, i, j);
                    i = j;
                } else break;
            }
        }
    }
}

fn rtreeStepToLeaf(pCur: *RtreeCursor) c_int {
    const pRtree = rtreeOfCursor(pCur);
    var rc: c_int = SQLITE_OK;
    const nConstraint = pCur.nConstraint;
    const eInt: c_int = @intFromBool(pRtree.eCoordType == RTREE_COORD_INT32);
    var x: RtreeSearchPoint = undefined;

    var p = rtreeSearchPointFirst(pCur);
    while (p != null and p.?.iLevel > 0) : (p = rtreeSearchPointFirst(pCur)) {
        var pp = p.?;
        const pNode = rtreeNodeOfFirstSearchPoint(pCur, &rc) orelse return rc;
        if (rc != 0) return rc;
        const nCell = NCELL(pNode);
        if (nCell > RTREE_MAXCELLS) {
            return SQLITE_CORRUPT_VTAB;
        }
        var pCellData = pNode.zData.? + @as(usize, @intCast(4 + @as(c_int, pRtree.nBytesPerCell) * pp.iCell));
        while (pp.iCell < nCell) {
            var rScore: RtreeDValue = -1;
            var eWithin: c_int = FULLY_WITHIN;
            var ii: c_int = 0;
            while (ii < nConstraint) : (ii += 1) {
                const pConstraint = &pCur.aConstraint.?[@intCast(ii)];
                if (pConstraint.op >= RTREE_MATCH) {
                    rc = rtreeCallbackConstraint(pConstraint, eInt, pCellData, pp, &rScore, &eWithin);
                    if (rc != 0) return rc;
                } else if (pp.iLevel == 1) {
                    rtreeLeafConstraint(pConstraint, eInt, pCellData, &eWithin);
                } else {
                    rtreeNonleafConstraint(pConstraint, eInt, pCellData, &eWithin);
                }
                if (eWithin == NOT_WITHIN) {
                    pp.iCell += 1;
                    pCellData += pRtree.nBytesPerCell;
                    break;
                }
            }
            if (eWithin == NOT_WITHIN) continue;
            pp.iCell += 1;
            x.iLevel = pp.iLevel - 1;
            if (x.iLevel != 0) {
                x.id = readInt64(pCellData);
                var jj: c_int = 0;
                while (jj < pCur.nPoint) : (jj += 1) {
                    if (pCur.aPoint.?[@intCast(jj)].id == x.id) {
                        return SQLITE_CORRUPT_VTAB;
                    }
                }
                x.iCell = 0;
            } else {
                x.id = pp.id;
                x.iCell = pp.iCell - 1;
            }
            if (pp.iCell >= nCell) {
                rtreeSearchPointPop(pCur);
            }
            if (rScore < RTREE_ZERO) rScore = RTREE_ZERO;
            const pNew = rtreeSearchPointNew(pCur, rScore, x.iLevel) orelse return SQLITE_NOMEM;
            pNew.eWithin = @intCast(eWithin);
            pNew.id = x.id;
            pNew.iCell = x.iCell;
            pp = pNew; // C reassigns `p`; the post-loop iCell check must see the new point.
            break;
        }
        if (pp.iCell >= nCell) {
            rtreeSearchPointPop(pCur);
        }
    }
    pCur.atEOF = @intFromBool(p == null);
    return SQLITE_OK;
}

fn rtreeNext(pVtabCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(pVtabCursor));
    if (pCsr.bAuxValid != 0) {
        pCsr.bAuxValid = 0;
        _ = sqlite3_reset(pCsr.pReadAux);
    }
    rtreeSearchPointPop(pCsr);
    return rtreeStepToLeaf(pCsr);
}

fn rtreeRowid(pVtabCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(pVtabCursor));
    const p = rtreeSearchPointFirst(pCsr);
    var rc: c_int = SQLITE_OK;
    const pNode = rtreeNodeOfFirstSearchPoint(pCsr, &rc);
    if (rc == SQLITE_OK and p != null) {
        if (p.?.iCell >= NCELL(pNode.?)) {
            rc = SQLITE_ABORT;
        } else {
            pRowid.* = nodeGetRowid(rtreeOfCursor(pCsr), pNode.?, p.?.iCell);
        }
    }
    return rc;
}

fn rtreeColumn(cur: *sqlite3_vtab_cursor, ctx: ?*sqlite3_context, i: c_int) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(cur.pVtab.?));
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(cur));
    const p = rtreeSearchPointFirst(pCsr);
    var c: RtreeCoord = undefined;
    var rc: c_int = SQLITE_OK;
    const pNode = rtreeNodeOfFirstSearchPoint(pCsr, &rc);

    if (rc != 0) return rc;
    if (p == null) return SQLITE_OK;
    if (p.?.iCell >= NCELL(pNode.?)) return SQLITE_ABORT;
    if (i == 0) {
        sqlite3_result_int64(ctx, nodeGetRowid(pRtree, pNode.?, p.?.iCell));
    } else if (i <= pRtree.nDim2) {
        nodeGetCoord(pRtree, pNode.?, p.?.iCell, i - 1, &c);
        if (pRtree.eCoordType == RTREE_COORD_REAL32) {
            sqlite3_result_double(ctx, c.f);
        } else {
            sqlite3_result_int(ctx, c.i);
        }
    } else {
        if (pCsr.bAuxValid == 0) {
            if (pCsr.pReadAux == null) {
                rc = sqlite3_prepare_v3(pRtree.db, pRtree.zReadAuxSql.?, -1, 0, &pCsr.pReadAux, null);
                if (rc != 0) return rc;
            }
            _ = sqlite3_bind_int64(pCsr.pReadAux, 1, nodeGetRowid(pRtree, pNode.?, p.?.iCell));
            rc = sqlite3_step(pCsr.pReadAux);
            if (rc == SQLITE_ROW) {
                pCsr.bAuxValid = 1;
            } else {
                _ = sqlite3_reset(pCsr.pReadAux);
                if (rc == SQLITE_DONE) rc = SQLITE_OK;
                return rc;
            }
        }
        sqlite3_result_value(ctx, sqlite3_column_value(pCsr.pReadAux, i - pRtree.nDim2 + 1));
    }
    return SQLITE_OK;
}

fn findLeafNode(pRtree: *Rtree, iRowid: i64, ppLeaf: *?*RtreeNode, piNode: ?*i64) c_int {
    var rc: c_int = undefined;
    ppLeaf.* = null;
    _ = sqlite3_bind_int64(pRtree.pReadRowid, 1, iRowid);
    if (sqlite3_step(pRtree.pReadRowid) == SQLITE_ROW) {
        const iNode = sqlite3_column_int64(pRtree.pReadRowid, 0);
        if (piNode) |pn| pn.* = iNode;
        rc = nodeAcquire(pRtree, iNode, null, ppLeaf);
        _ = sqlite3_reset(pRtree.pReadRowid);
    } else {
        rc = sqlite3_reset(pRtree.pReadRowid);
    }
    return rc;
}

fn deserializeGeometry(pValue: ?*sqlite3_value, pCons: *RtreeConstraint) c_int {
    const pSrc: *RtreeMatchArg = @ptrCast(@alignCast(sqlite3_value_pointer(pValue, "RtreeMatchArg") orelse return SQLITE_ERROR));
    const pInfo: ?*sqlite3_rtree_query_info = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(sqlite3_rtree_query_info) + pSrc.iSize)));
    if (pInfo == null) return SQLITE_NOMEM;
    const info = pInfo.?;
    info.* = std.mem.zeroes(sqlite3_rtree_query_info);
    const pBlob: *RtreeMatchArg = @ptrCast(@alignCast(@as([*]u8, @ptrCast(info)) + @sizeOf(sqlite3_rtree_query_info)));
    const srcBytes: [*]const u8 = @ptrCast(pSrc);
    const dstBytes: [*]u8 = @ptrCast(pBlob);
    @memcpy(dstBytes[0..pSrc.iSize], srcBytes[0..pSrc.iSize]);
    info.pContext = pBlob.cb.pContext;
    info.nParam = pBlob.nParam;
    info.aParam = aParamPtr(pBlob);
    info.apSqlParam = pBlob.apSqlParam;

    if (pBlob.cb.xGeom != null) {
        pCons.u.xGeom = pBlob.cb.xGeom;
    } else {
        pCons.op = RTREE_QUERY;
        pCons.u.xQueryFunc = pBlob.cb.xQueryFunc;
    }
    pCons.pInfo = pInfo;
    return SQLITE_OK;
}

fn rtreeFilter(pVtabCursor: *sqlite3_vtab_cursor, idxNum: c_int, idxStr: ?[*:0]const u8, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtabCursor.pVtab.?));
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(pVtabCursor));
    var pRoot: ?*RtreeNode = null;
    var rc: c_int = SQLITE_OK;
    var iCell: c_int = 0;

    rtreeReference(pRtree);
    resetCursor(pCsr);
    pCsr.iStrategy = idxNum;
    if (idxNum == 1) {
        var pLeaf: ?*RtreeNode = undefined;
        const iRowid = sqlite3_value_int64(argv.?[0]);
        var iNode: i64 = 0;
        const eType = sqlite3_value_numeric_type(argv.?[0]);
        if (eType == SQLITE_INTEGER or (eType == SQLITE_FLOAT and 0 == sqlite3IntFloatCompare(iRowid, sqlite3_value_double(argv.?[0])))) {
            rc = findLeafNode(pRtree, iRowid, &pLeaf, &iNode);
        } else {
            rc = SQLITE_OK;
            pLeaf = null;
        }
        if (rc == SQLITE_OK and pLeaf != null) {
            const p = rtreeSearchPointNew(pCsr, RTREE_ZERO, 0).?;
            pCsr.aNode[0] = pLeaf;
            p.id = iNode;
            p.eWithin = PARTLY_WITHIN;
            rc = nodeRowidIndex(pRtree, pLeaf.?, iRowid, &iCell);
            p.iCell = @intCast(iCell);
        } else {
            pCsr.atEOF = 1;
        }
    } else {
        rc = nodeAcquire(pRtree, 1, null, &pRoot);
        if (rc == SQLITE_OK and argc > 0) {
            pCsr.aConstraint = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(RtreeConstraint) * @as(u64, @intCast(argc)))));
            pCsr.nConstraint = argc;
            if (pCsr.aConstraint == null) {
                rc = SQLITE_NOMEM;
            } else {
                const ac = pCsr.aConstraint.?;
                @memset(@as([*]u8, @ptrCast(ac))[0 .. @sizeOf(RtreeConstraint) * @as(usize, @intCast(argc))], 0);
                @memset(@as([*]u8, @ptrCast(&pCsr.anQueue))[0 .. @sizeOf(u32) * @as(usize, @intCast(pRtree.iDepth + 1))], 0);
                const istr = idxStr.?;
                var ii: c_int = 0;
                while (ii < argc) : (ii += 1) {
                    const p = &ac[@intCast(ii)];
                    const eType = sqlite3_value_numeric_type(argv.?[@intCast(ii)]);
                    p.op = istr[@intCast(ii * 2)];
                    p.iCoord = @as(c_int, istr[@intCast(ii * 2 + 1)]) - '0';
                    if (p.op >= RTREE_MATCH) {
                        rc = deserializeGeometry(argv.?[@intCast(ii)], p);
                        if (rc != SQLITE_OK) break;
                        p.pInfo.?.nCoord = pRtree.nDim2;
                        p.pInfo.?.anQueue = &pCsr.anQueue;
                        p.pInfo.?.mxLevel = pRtree.iDepth + 1;
                    } else if (eType == SQLITE_INTEGER) {
                        const iVal = sqlite3_value_int64(argv.?[@intCast(ii)]);
                        p.u.rValue = @floatFromInt(iVal);
                        if (iVal >= (@as(i64, 1) << 48) or iVal <= -(@as(i64, 1) << 48)) {
                            if (p.op == RTREE_LT) p.op = RTREE_LE;
                            if (p.op == RTREE_GT) p.op = RTREE_GE;
                        }
                    } else if (eType == SQLITE_FLOAT) {
                        p.u.rValue = sqlite3_value_double(argv.?[@intCast(ii)]);
                    } else {
                        p.u.rValue = RTREE_ZERO;
                        if (eType == SQLITE_NULL) {
                            p.op = RTREE_FALSE;
                        } else if (p.op == RTREE_LT or p.op == RTREE_LE) {
                            p.op = RTREE_TRUE;
                        } else {
                            p.op = RTREE_FALSE;
                        }
                    }
                }
            }
        }
        if (rc == SQLITE_OK) {
            const pNew = rtreeSearchPointNew(pCsr, RTREE_ZERO, @intCast(pRtree.iDepth + 1));
            if (pNew == null) return SQLITE_NOMEM;
            pNew.?.id = 1;
            pNew.?.iCell = 0;
            pNew.?.eWithin = PARTLY_WITHIN;
            pCsr.aNode[0] = pRoot;
            pRoot = null;
            rc = rtreeStepToLeaf(pCsr);
        }
    }

    _ = nodeRelease(pRtree, pRoot);
    rtreeRelease(pRtree);
    return rc;
}

fn rtreeBestIndex(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(tab));
    const rc: c_int = SQLITE_OK;
    var bMatch: c_int = 0;
    var iIdx: usize = 0;
    const zIdxStrLen: usize = @as(usize, RTREE_MAX_DIMENSIONS) * 8 + 1;
    var zIdxStr = std.mem.zeroes([zIdxStrLen]u8);

    const aCon = pIdxInfo.aConstraint.?;
    const aUse = pIdxInfo.aConstraintUsage.?;

    var ii: c_int = 0;
    while (ii < pIdxInfo.nConstraint) : (ii += 1) {
        if (aCon[@intCast(ii)].op == SQLITE_INDEX_CONSTRAINT_MATCH) {
            bMatch = 1;
        }
    }

    ii = 0;
    while (ii < pIdxInfo.nConstraint and iIdx < zIdxStr.len - 1) : (ii += 1) {
        const p = &aCon[@intCast(ii)];

        if (bMatch == 0 and p.usable != 0 and p.iColumn <= 0 and p.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            var jj: c_int = 0;
            while (jj < ii) : (jj += 1) {
                aUse[@intCast(jj)].argvIndex = 0;
                aUse[@intCast(jj)].omit = 0;
            }
            pIdxInfo.idxNum = 1;
            aUse[@intCast(ii)].argvIndex = 1;
            aUse[@intCast(jj)].omit = 1;
            pIdxInfo.estimatedCost = 30.0;
            pIdxInfo.estimatedRows = 1;
            pIdxInfo.idxFlags = SQLITE_INDEX_SCAN_UNIQUE;
            return SQLITE_OK;
        }

        if (p.usable != 0 and ((p.iColumn > 0 and p.iColumn <= pRtree.nDim2) or p.op == SQLITE_INDEX_CONSTRAINT_MATCH)) {
            var op: u8 = 0;
            var doOmit: u8 = 1;
            switch (p.op) {
                SQLITE_INDEX_CONSTRAINT_EQ => {
                    op = RTREE_EQ;
                    doOmit = 0;
                },
                SQLITE_INDEX_CONSTRAINT_GT => {
                    op = RTREE_GT;
                    doOmit = 0;
                },
                SQLITE_INDEX_CONSTRAINT_LE => op = RTREE_LE,
                SQLITE_INDEX_CONSTRAINT_LT => {
                    op = RTREE_LT;
                    doOmit = 0;
                },
                SQLITE_INDEX_CONSTRAINT_GE => op = RTREE_GE,
                SQLITE_INDEX_CONSTRAINT_MATCH => op = RTREE_MATCH,
                else => op = 0,
            }
            if (op != 0) {
                zIdxStr[iIdx] = op;
                iIdx += 1;
                zIdxStr[iIdx] = @intCast(p.iColumn - 1 + '0');
                iIdx += 1;
                aUse[@intCast(ii)].argvIndex = @intCast(iIdx / 2);
                aUse[@intCast(ii)].omit = doOmit;
            }
        }
    }

    pIdxInfo.idxNum = 2;
    pIdxInfo.needToFreeIdxStr = 1;
    if (iIdx > 0) {
        const dst: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc(@intCast(iIdx + 1))));
        if (dst == null) return SQLITE_NOMEM;
        @memcpy(dst.?[0 .. iIdx + 1], zIdxStr[0 .. iIdx + 1]);
        pIdxInfo.idxStr = @ptrCast(dst);
    }

    const nRow = pRtree.nRowEst >> @intCast(iIdx / 2);
    pIdxInfo.estimatedCost = 6.0 * @as(f64, @floatFromInt(nRow));
    pIdxInfo.estimatedRows = nRow;
    return rc;
}

fn cellArea(pRtree: *Rtree, p: *const RtreeCell) RtreeDValue {
    var area: RtreeDValue = 1;
    if (pRtree.eCoordType == RTREE_COORD_REAL32) {
        switch (pRtree.nDim) {
            5 => {
                area = @as(RtreeDValue, p.aCoord[9].f) - p.aCoord[8].f;
                area *= @as(RtreeDValue, p.aCoord[7].f) - p.aCoord[6].f;
                area *= @as(RtreeDValue, p.aCoord[5].f) - p.aCoord[4].f;
                area *= @as(RtreeDValue, p.aCoord[3].f) - p.aCoord[2].f;
                area *= @as(RtreeDValue, p.aCoord[1].f) - p.aCoord[0].f;
            },
            4 => {
                area *= @as(RtreeDValue, p.aCoord[7].f) - p.aCoord[6].f;
                area *= @as(RtreeDValue, p.aCoord[5].f) - p.aCoord[4].f;
                area *= @as(RtreeDValue, p.aCoord[3].f) - p.aCoord[2].f;
                area *= @as(RtreeDValue, p.aCoord[1].f) - p.aCoord[0].f;
            },
            3 => {
                area *= @as(RtreeDValue, p.aCoord[5].f) - p.aCoord[4].f;
                area *= @as(RtreeDValue, p.aCoord[3].f) - p.aCoord[2].f;
                area *= @as(RtreeDValue, p.aCoord[1].f) - p.aCoord[0].f;
            },
            2 => {
                area *= @as(RtreeDValue, p.aCoord[3].f) - p.aCoord[2].f;
                area *= @as(RtreeDValue, p.aCoord[1].f) - p.aCoord[0].f;
            },
            else => {
                area *= @as(RtreeDValue, p.aCoord[1].f) - p.aCoord[0].f;
            },
        }
    } else {
        switch (pRtree.nDim) {
            5 => {
                area = @floatFromInt(@as(i64, p.aCoord[9].i) - @as(i64, p.aCoord[8].i));
                area *= @floatFromInt(@as(i64, p.aCoord[7].i) - @as(i64, p.aCoord[6].i));
                area *= @floatFromInt(@as(i64, p.aCoord[5].i) - @as(i64, p.aCoord[4].i));
                area *= @floatFromInt(@as(i64, p.aCoord[3].i) - @as(i64, p.aCoord[2].i));
                area *= @floatFromInt(@as(i64, p.aCoord[1].i) - @as(i64, p.aCoord[0].i));
            },
            4 => {
                area *= @floatFromInt(@as(i64, p.aCoord[7].i) - @as(i64, p.aCoord[6].i));
                area *= @floatFromInt(@as(i64, p.aCoord[5].i) - @as(i64, p.aCoord[4].i));
                area *= @floatFromInt(@as(i64, p.aCoord[3].i) - @as(i64, p.aCoord[2].i));
                area *= @floatFromInt(@as(i64, p.aCoord[1].i) - @as(i64, p.aCoord[0].i));
            },
            3 => {
                area *= @floatFromInt(@as(i64, p.aCoord[5].i) - @as(i64, p.aCoord[4].i));
                area *= @floatFromInt(@as(i64, p.aCoord[3].i) - @as(i64, p.aCoord[2].i));
                area *= @floatFromInt(@as(i64, p.aCoord[1].i) - @as(i64, p.aCoord[0].i));
            },
            2 => {
                area *= @floatFromInt(@as(i64, p.aCoord[3].i) - @as(i64, p.aCoord[2].i));
                area *= @floatFromInt(@as(i64, p.aCoord[1].i) - @as(i64, p.aCoord[0].i));
            },
            else => {
                area *= @floatFromInt(@as(i64, p.aCoord[1].i) - @as(i64, p.aCoord[0].i));
            },
        }
    }
    return area;
}

fn cellMargin(pRtree: *Rtree, p: *const RtreeCell) RtreeDValue {
    var margin: RtreeDValue = 0;
    var ii: c_int = @as(c_int, pRtree.nDim2) - 2;
    while (true) {
        margin += dcoord(pRtree, p.aCoord[@intCast(ii + 1)]) - dcoord(pRtree, p.aCoord[@intCast(ii)]);
        ii -= 2;
        if (ii < 0) break;
    }
    return margin;
}

fn cellUnion(pRtree: *Rtree, p1: *RtreeCell, p2: *const RtreeCell) void {
    var ii: usize = 0;
    if (pRtree.eCoordType == RTREE_COORD_REAL32) {
        while (true) {
            p1.aCoord[ii].f = @min(p1.aCoord[ii].f, p2.aCoord[ii].f);
            p1.aCoord[ii + 1].f = @max(p1.aCoord[ii + 1].f, p2.aCoord[ii + 1].f);
            ii += 2;
            if (ii >= nDim2usize(pRtree)) break;
        }
    } else {
        while (true) {
            p1.aCoord[ii].i = @min(p1.aCoord[ii].i, p2.aCoord[ii].i);
            p1.aCoord[ii + 1].i = @max(p1.aCoord[ii + 1].i, p2.aCoord[ii + 1].i);
            ii += 2;
            if (ii >= nDim2usize(pRtree)) break;
        }
    }
}

fn cellContains(pRtree: *Rtree, p1: *const RtreeCell, p2: *const RtreeCell) c_int {
    var ii: usize = 0;
    if (pRtree.eCoordType == RTREE_COORD_INT32) {
        while (ii < nDim2usize(pRtree)) : (ii += 2) {
            const a1: [*]const RtreeCoord = @ptrCast(&p1.aCoord[ii]);
            const a2: [*]const RtreeCoord = @ptrCast(&p2.aCoord[ii]);
            if (a2[0].i < a1[0].i or a2[1].i > a1[1].i) return 0;
        }
    } else {
        while (ii < nDim2usize(pRtree)) : (ii += 2) {
            const a1: [*]const RtreeCoord = @ptrCast(&p1.aCoord[ii]);
            const a2: [*]const RtreeCoord = @ptrCast(&p2.aCoord[ii]);
            if (a2[0].f < a1[0].f or a2[1].f > a1[1].f) return 0;
        }
    }
    return 1;
}

fn cellOverlap(pRtree: *Rtree, p: *const RtreeCell, aCell: [*]const RtreeCell, nCell: c_int) RtreeDValue {
    var overlap: RtreeDValue = RTREE_ZERO;
    var ii: usize = 0;
    while (ii < @as(usize, @intCast(nCell))) : (ii += 1) {
        var o: RtreeDValue = 1;
        var jj: usize = 0;
        while (jj < nDim2usize(pRtree)) : (jj += 2) {
            const x1 = maxd(dcoord(pRtree, p.aCoord[jj]), dcoord(pRtree, aCell[ii].aCoord[jj]));
            const x2 = mind(dcoord(pRtree, p.aCoord[jj + 1]), dcoord(pRtree, aCell[ii].aCoord[jj + 1]));
            if (x2 < x1) {
                o = 0;
                break;
            } else {
                o = o * (x2 - x1);
            }
        }
        overlap += o;
    }
    return overlap;
}

fn chooseLeaf(pRtree: *Rtree, pCell: *const RtreeCell, iHeight: c_int, ppLeaf: *?*RtreeNode) c_int {
    var pNode: ?*RtreeNode = null;
    var rc = nodeAcquire(pRtree, 1, null, &pNode);

    var ii: c_int = 0;
    while (rc == SQLITE_OK and ii < (pRtree.iDepth - iHeight)) : (ii += 1) {
        var iBest: i64 = 0;
        var bFound: c_int = 0;
        var fMinGrowth: RtreeDValue = RTREE_ZERO;
        var fMinArea: RtreeDValue = RTREE_ZERO;
        const nCell = NCELL(pNode.?);
        var pChild: ?*RtreeNode = null;

        var iCell: c_int = 0;
        while (iCell < nCell) : (iCell += 1) {
            var cell: RtreeCell = undefined;
            nodeGetCell(pRtree, pNode.?, iCell, &cell);
            if (cellContains(pRtree, &cell, pCell) != 0) {
                const area = cellArea(pRtree, &cell);
                if (bFound == 0 or area < fMinArea) {
                    iBest = cell.iRowid;
                    fMinArea = area;
                    bFound = 1;
                }
            }
        }
        if (bFound == 0) {
            iCell = 0;
            while (iCell < nCell) : (iCell += 1) {
                var cell: RtreeCell = undefined;
                nodeGetCell(pRtree, pNode.?, iCell, &cell);
                const area = cellArea(pRtree, &cell);
                cellUnion(pRtree, &cell, pCell);
                const growth = cellArea(pRtree, &cell) - area;
                if (iCell == 0 or growth < fMinGrowth or (growth == fMinGrowth and area < fMinArea)) {
                    fMinGrowth = growth;
                    fMinArea = area;
                    iBest = cell.iRowid;
                }
            }
        }

        rc = nodeAcquire(pRtree, iBest, pNode, &pChild);
        _ = nodeRelease(pRtree, pNode);
        pNode = pChild;
    }

    ppLeaf.* = pNode;
    return rc;
}

fn adjustTree(pRtree: *Rtree, pNode: *RtreeNode, pCell: *const RtreeCell) c_int {
    var p = pNode;
    var cnt: c_int = 0;
    while (p.pParent) |pParent| {
        var cell: RtreeCell = undefined;
        var iCell: c_int = undefined;
        cnt += 1;
        if (cnt > 100) {
            return SQLITE_CORRUPT_VTAB;
        }
        const rc = nodeParentIndex(pRtree, p, &iCell);
        if (rc != SQLITE_OK) {
            return SQLITE_CORRUPT_VTAB;
        }
        nodeGetCell(pRtree, pParent, iCell, &cell);
        if (cellContains(pRtree, &cell, pCell) == 0) {
            cellUnion(pRtree, &cell, pCell);
            nodeOverwriteCell(pRtree, pParent, &cell, iCell);
        }
        p = pParent;
    }
    return SQLITE_OK;
}

fn rowidWrite(pRtree: *Rtree, iRowid: i64, iNode: i64) c_int {
    _ = sqlite3_bind_int64(pRtree.pWriteRowid, 1, iRowid);
    _ = sqlite3_bind_int64(pRtree.pWriteRowid, 2, iNode);
    _ = sqlite3_step(pRtree.pWriteRowid);
    return sqlite3_reset(pRtree.pWriteRowid);
}

fn parentWrite(pRtree: *Rtree, iNode: i64, iPar: i64) c_int {
    _ = sqlite3_bind_int64(pRtree.pWriteParent, 1, iNode);
    _ = sqlite3_bind_int64(pRtree.pWriteParent, 2, iPar);
    _ = sqlite3_step(pRtree.pWriteParent);
    return sqlite3_reset(pRtree.pWriteParent);
}

fn sortByDimension(pRtree: *Rtree, aIdx: [*]c_int, nIdx: c_int, iDim: c_int, aCell: [*]const RtreeCell, aSpare: [*]c_int) void {
    if (nIdx > 1) {
        var iLeft: c_int = 0;
        var iRight: c_int = 0;
        const nLeft = @divTrunc(nIdx, 2);
        const nRight = nIdx - nLeft;
        var aLeft = aIdx;
        const aRight = aIdx + @as(usize, @intCast(nLeft));

        sortByDimension(pRtree, aLeft, nLeft, iDim, aCell, aSpare);
        sortByDimension(pRtree, aRight, nRight, iDim, aCell, aSpare);

        @memcpy(aSpare[0..@intCast(nLeft)], aLeft[0..@intCast(nLeft)]);
        aLeft = aSpare;
        while (iLeft < nLeft or iRight < nRight) {
            const xleft1 = dcoord(pRtree, aCell[@intCast(aLeft[@intCast(iLeft)])].aCoord[@intCast(iDim * 2)]);
            const xleft2 = dcoord(pRtree, aCell[@intCast(aLeft[@intCast(iLeft)])].aCoord[@intCast(iDim * 2 + 1)]);
            const xright1 = dcoord(pRtree, aCell[@intCast(aRight[@intCast(iRight)])].aCoord[@intCast(iDim * 2)]);
            const xright2 = dcoord(pRtree, aCell[@intCast(aRight[@intCast(iRight)])].aCoord[@intCast(iDim * 2 + 1)]);
            if ((iLeft != nLeft) and ((iRight == nRight) or (xleft1 < xright1) or (xleft1 == xright1 and xleft2 < xright2))) {
                aIdx[@intCast(iLeft + iRight)] = aLeft[@intCast(iLeft)];
                iLeft += 1;
            } else {
                aIdx[@intCast(iLeft + iRight)] = aRight[@intCast(iRight)];
                iRight += 1;
            }
        }
    }
}

fn splitNodeStartree(pRtree: *Rtree, aCell: [*]const RtreeCell, nCell: c_int, pLeft: *RtreeNode, pRight: *RtreeNode, pBboxLeft: *RtreeCell, pBboxRight: *RtreeCell) c_int {
    var iBestDim: c_int = 0;
    var iBestSplit: c_int = 0;
    var fBestMargin: RtreeDValue = RTREE_ZERO;

    const nDim: usize = pRtree.nDim;
    const nCellU: usize = @intCast(nCell);
    // nByte = (nDim+1)*(sizeof(int*) + nCell*sizeof(int))
    const nByte: usize = (nDim + 1) * (@sizeOf(usize) + nCellU * @sizeOf(c_int));
    const raw: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc64(nByte)));
    if (raw == null) return SQLITE_NOMEM;
    @memset(raw.?[0..nByte], 0);
    // aaSorted is an array of nDim pointers into the int storage that follows.
    const aaSorted: [*]?[*]c_int = @ptrCast(@alignCast(raw.?));
    const intBase: [*]c_int = @ptrCast(@alignCast(raw.? + nDim * @sizeOf(usize)));
    const aSpare: [*]c_int = intBase + nDim * nCellU;

    var ii: usize = 0;
    while (ii < nDim) : (ii += 1) {
        aaSorted[ii] = intBase + ii * nCellU;
        var jj: usize = 0;
        while (jj < nCellU) : (jj += 1) {
            aaSorted[ii].?[jj] = @intCast(jj);
        }
        sortByDimension(pRtree, aaSorted[ii].?, nCell, @intCast(ii), aCell, aSpare);
    }

    ii = 0;
    while (ii < nDim) : (ii += 1) {
        var margin: RtreeDValue = RTREE_ZERO;
        var fBestOverlap: RtreeDValue = RTREE_ZERO;
        var fBestArea: RtreeDValue = RTREE_ZERO;
        var iBestLeft: c_int = 0;
        const aS = aaSorted[ii].?;

        var nLeft = rtreeMincells(pRtree);
        while (nLeft <= (nCell - rtreeMincells(pRtree))) : (nLeft += 1) {
            var left: RtreeCell = undefined;
            var right: RtreeCell = undefined;
            left = aCell[@intCast(aS[0])];
            right = aCell[@intCast(aS[@intCast(nCell - 1)])];
            var kk: c_int = 1;
            while (kk < (nCell - 1)) : (kk += 1) {
                if (kk < nLeft) {
                    cellUnion(pRtree, &left, &aCell[@intCast(aS[@intCast(kk)])]);
                } else {
                    cellUnion(pRtree, &right, &aCell[@intCast(aS[@intCast(kk)])]);
                }
            }
            margin += cellMargin(pRtree, &left);
            margin += cellMargin(pRtree, &right);
            const overlap = cellOverlap(pRtree, &left, @ptrCast(&right), 1);
            const area = cellArea(pRtree, &left) + cellArea(pRtree, &right);
            if ((nLeft == rtreeMincells(pRtree)) or (overlap < fBestOverlap) or (overlap == fBestOverlap and area < fBestArea)) {
                iBestLeft = nLeft;
                fBestOverlap = overlap;
                fBestArea = area;
            }
        }

        if (ii == 0 or margin < fBestMargin) {
            iBestDim = @intCast(ii);
            fBestMargin = margin;
            iBestSplit = iBestLeft;
        }
    }

    const aBest = aaSorted[@intCast(iBestDim)].?;
    pBboxLeft.* = aCell[@intCast(aBest[0])];
    pBboxRight.* = aCell[@intCast(aBest[@intCast(iBestSplit)])];
    var jj: c_int = 0;
    while (jj < nCell) : (jj += 1) {
        const pTarget = if (jj < iBestSplit) pLeft else pRight;
        const pBbox = if (jj < iBestSplit) pBboxLeft else pBboxRight;
        const pCell = &aCell[@intCast(aBest[@intCast(jj)])];
        _ = nodeInsertCell(pRtree, pTarget, pCell);
        cellUnion(pRtree, pBbox, pCell);
    }

    sqlite3_free(raw);
    return SQLITE_OK;
}

fn updateMapping(pRtree: *Rtree, iRowid: i64, pNode: ?*RtreeNode, iHeight: c_int) c_int {
    const xSetMapping = if (iHeight == 0) &rowidWrite else &parentWrite;
    if (iHeight > 0) {
        const pChild = nodeHashLookup(pRtree, iRowid);
        var p = pNode;
        while (p) |pp| {
            if (pp == pChild) return SQLITE_CORRUPT_VTAB;
            p = pp.pParent;
        }
        if (pChild) |pc| {
            _ = nodeRelease(pRtree, pc.pParent);
            nodeReference(pNode);
            pc.pParent = pNode;
        }
    }
    if (pNode == null) return SQLITE_ERROR;
    return xSetMapping(pRtree, iRowid, pNode.?.iNode);
}

fn splitNode(pRtree: *Rtree, pNode: *RtreeNode, pCell: *const RtreeCell, iHeight: c_int) c_int {
    var newCellIsRight: c_int = 0;
    var rc: c_int = SQLITE_OK;
    var nCell = NCELL(pNode);
    var pLeft: ?*RtreeNode = null;
    var pRight: ?*RtreeNode = null;
    var leftbbox: RtreeCell = undefined;
    var rightbbox: RtreeCell = undefined;

    // aCell: (nCell+1) RtreeCells followed by (nCell+1) ints (aiUsed).
    const nC1: usize = @intCast(nCell + 1);
    const allocSz = (@sizeOf(RtreeCell) + @sizeOf(c_int)) * nC1;
    const aCellRaw: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc64(allocSz)));
    if (aCellRaw == null) {
        rc = SQLITE_NOMEM;
        return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
    }
    const aCell: [*]RtreeCell = @ptrCast(@alignCast(aCellRaw.?));
    const aiUsed: [*]c_int = @ptrCast(@alignCast(aCellRaw.? + @sizeOf(RtreeCell) * nC1));
    @memset(@as([*]u8, @ptrCast(aiUsed))[0 .. @sizeOf(c_int) * nC1], 0);
    var i: c_int = 0;
    while (i < nCell) : (i += 1) {
        nodeGetCell(pRtree, pNode, i, &aCell[@intCast(i)]);
    }
    nodeZero(pRtree, pNode);
    aCell[@intCast(nCell)] = pCell.*;
    nCell += 1;

    if (pNode.iNode == 1) {
        pRight = nodeNew(pRtree, pNode);
        pLeft = nodeNew(pRtree, pNode);
        pRtree.iDepth += 1;
        pNode.isDirty = 1;
        writeInt16(pNode.zData.?, pRtree.iDepth);
    } else {
        pLeft = pNode;
        pRight = nodeNew(pRtree, pLeft.?.pParent);
        pLeft.?.nRef += 1;
    }

    if (pLeft == null or pRight == null) {
        rc = SQLITE_NOMEM;
        return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
    }

    @memset(pLeft.?.zData.?[0..@intCast(pRtree.iNodeSize)], 0);
    @memset(pRight.?.zData.?[0..@intCast(pRtree.iNodeSize)], 0);

    rc = splitNodeStartree(pRtree, aCell, nCell, pLeft.?, pRight.?, &leftbbox, &rightbbox);
    if (rc != SQLITE_OK) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);

    rc = nodeWrite(pRtree, pRight.?);
    if (rc != SQLITE_OK) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
    if (pLeft.?.iNode == 0) {
        rc = nodeWrite(pRtree, pLeft.?);
        if (rc != SQLITE_OK) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
    }

    rightbbox.iRowid = pRight.?.iNode;
    leftbbox.iRowid = pLeft.?.iNode;

    if (pNode.iNode == 1) {
        rc = rtreeInsertCell(pRtree, pLeft.?.pParent.?, &leftbbox, iHeight + 1);
        if (rc != SQLITE_OK) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
    } else {
        const pParent = pLeft.?.pParent.?;
        var iCell: c_int = undefined;
        rc = nodeParentIndex(pRtree, pLeft.?, &iCell);
        if (rc == SQLITE_OK) {
            nodeOverwriteCell(pRtree, pParent, &leftbbox, iCell);
            rc = adjustTree(pRtree, pParent, &leftbbox);
        }
        if (rc != SQLITE_OK) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
    }
    rc = rtreeInsertCell(pRtree, pRight.?.pParent.?, &rightbbox, iHeight + 1);
    if (rc != 0) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);

    i = 0;
    while (i < NCELL(pRight.?)) : (i += 1) {
        const iRowid = nodeGetRowid(pRtree, pRight.?, i);
        rc = updateMapping(pRtree, iRowid, pRight, iHeight);
        if (iRowid == pCell.iRowid) {
            newCellIsRight = 1;
        }
        if (rc != SQLITE_OK) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
    }
    if (pNode.iNode == 1) {
        i = 0;
        while (i < NCELL(pLeft.?)) : (i += 1) {
            const iRowid = nodeGetRowid(pRtree, pLeft.?, i);
            rc = updateMapping(pRtree, iRowid, pLeft, iHeight);
            if (rc != SQLITE_OK) return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
        }
    } else if (newCellIsRight == 0) {
        rc = updateMapping(pRtree, pCell.iRowid, pLeft, iHeight);
    }

    return splitnodeOut(pRtree, pRight, pLeft, aCellRaw, rc);
}

fn splitnodeOut(pRtree: *Rtree, pRight: ?*RtreeNode, pLeft: ?*RtreeNode, aCellRaw: ?[*]u8, rc: c_int) c_int {
    _ = nodeRelease(pRtree, pRight);
    _ = nodeRelease(pRtree, pLeft);
    sqlite3_free(aCellRaw);
    return rc;
}

fn fixLeafParent(pRtree: *Rtree, pLeaf: *RtreeNode) c_int {
    var rc: c_int = SQLITE_OK;
    var pChild: ?*RtreeNode = pLeaf;
    while (rc == SQLITE_OK and pChild.?.iNode != 1 and pChild.?.pParent == null) {
        var rc2: c_int = SQLITE_OK;
        _ = sqlite3_bind_int64(pRtree.pReadParent, 1, pChild.?.iNode);
        rc = sqlite3_step(pRtree.pReadParent);
        if (rc == SQLITE_ROW) {
            const iNode = sqlite3_column_int64(pRtree.pReadParent, 0);
            var pTest: ?*RtreeNode = pLeaf;
            while (pTest != null and pTest.?.iNode != iNode) pTest = pTest.?.pParent;
            if (pTest == null) {
                rc2 = nodeAcquire(pRtree, iNode, null, &pChild.?.pParent);
            }
        }
        rc = sqlite3_reset(pRtree.pReadParent);
        if (rc == SQLITE_OK) rc = rc2;
        if (rc == SQLITE_OK and pChild.?.pParent == null) {
            rc = SQLITE_CORRUPT_VTAB;
        }
        pChild = pChild.?.pParent;
    }
    return rc;
}

fn removeNode(pRtree: *Rtree, pNode: *RtreeNode, iHeight: c_int) c_int {
    var pParent: ?*RtreeNode = null;
    var iCell: c_int = undefined;

    var rc = nodeParentIndex(pRtree, pNode, &iCell);
    if (rc == SQLITE_OK) {
        pParent = pNode.pParent;
        pNode.pParent = null;
        rc = deleteCell(pRtree, pParent.?, iCell, iHeight + 1);
    }
    const rc2 = nodeRelease(pRtree, pParent);
    if (rc == SQLITE_OK) rc = rc2;
    if (rc != SQLITE_OK) return rc;

    _ = sqlite3_bind_int64(pRtree.pDeleteNode, 1, pNode.iNode);
    _ = sqlite3_step(pRtree.pDeleteNode);
    rc = sqlite3_reset(pRtree.pDeleteNode);
    if (rc != SQLITE_OK) return rc;

    _ = sqlite3_bind_int64(pRtree.pDeleteParent, 1, pNode.iNode);
    _ = sqlite3_step(pRtree.pDeleteParent);
    rc = sqlite3_reset(pRtree.pDeleteParent);
    if (rc != SQLITE_OK) return rc;

    nodeHashDelete(pRtree, pNode);
    pNode.iNode = iHeight;
    pNode.pNext = pRtree.pDeleted;
    pNode.nRef += 1;
    pRtree.pDeleted = pNode;

    return SQLITE_OK;
}

fn fixBoundingBox(pRtree: *Rtree, pNode: *RtreeNode) c_int {
    var rc: c_int = SQLITE_OK;
    if (pNode.pParent) |pParent| {
        const nCell = NCELL(pNode);
        var box: RtreeCell = undefined;
        nodeGetCell(pRtree, pNode, 0, &box);
        var ii: c_int = 1;
        while (ii < nCell) : (ii += 1) {
            var cell: RtreeCell = undefined;
            nodeGetCell(pRtree, pNode, ii, &cell);
            cellUnion(pRtree, &box, &cell);
        }
        box.iRowid = pNode.iNode;
        rc = nodeParentIndex(pRtree, pNode, &ii);
        if (rc == SQLITE_OK) {
            nodeOverwriteCell(pRtree, pParent, &box, ii);
            rc = fixBoundingBox(pRtree, pParent);
        }
    }
    return rc;
}

fn deleteCell(pRtree: *Rtree, pNode: *RtreeNode, iCell: c_int, iHeight: c_int) c_int {
    var rc = fixLeafParent(pRtree, pNode);
    if (rc != SQLITE_OK) return rc;

    nodeDeleteCell(pRtree, pNode, iCell);

    const pParent = pNode.pParent;
    if (pParent != null) {
        if (NCELL(pNode) < rtreeMincells(pRtree)) {
            rc = removeNode(pRtree, pNode, iHeight);
        } else {
            rc = fixBoundingBox(pRtree, pNode);
        }
    }
    return rc;
}

fn rtreeInsertCell(pRtree: *Rtree, pNode: *RtreeNode, pCell: *const RtreeCell, iHeight: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (iHeight > 0) {
        const pChild = nodeHashLookup(pRtree, pCell.iRowid);
        if (pChild) |pc| {
            _ = nodeRelease(pRtree, pc.pParent);
            nodeReference(pNode);
            pc.pParent = pNode;
        }
    }
    if (nodeInsertCell(pRtree, pNode, pCell) != 0) {
        rc = splitNode(pRtree, pNode, pCell, iHeight);
    } else {
        rc = adjustTree(pRtree, pNode, pCell);
        if (rc == SQLITE_OK) {
            if (iHeight == 0) {
                rc = rowidWrite(pRtree, pCell.iRowid, pNode.iNode);
            } else {
                rc = parentWrite(pRtree, pCell.iRowid, pNode.iNode);
            }
        }
    }
    return rc;
}

fn reinsertNodeContent(pRtree: *Rtree, pNode: *RtreeNode) c_int {
    var rc: c_int = SQLITE_OK;
    const nCell = NCELL(pNode);
    var ii: c_int = 0;
    while (rc == SQLITE_OK and ii < nCell) : (ii += 1) {
        var pInsert: ?*RtreeNode = null;
        var cell: RtreeCell = undefined;
        nodeGetCell(pRtree, pNode, ii, &cell);
        rc = chooseLeaf(pRtree, &cell, @intCast(pNode.iNode), &pInsert);
        if (rc == SQLITE_OK) {
            rc = rtreeInsertCell(pRtree, pInsert.?, &cell, @intCast(pNode.iNode));
            const rc2 = nodeRelease(pRtree, pInsert);
            if (rc == SQLITE_OK) rc = rc2;
        }
    }
    return rc;
}

fn rtreeNewRowid(pRtree: *Rtree, piRowid: *i64) c_int {
    _ = sqlite3_bind_null(pRtree.pWriteRowid, 1);
    _ = sqlite3_bind_null(pRtree.pWriteRowid, 2);
    _ = sqlite3_step(pRtree.pWriteRowid);
    const rc = sqlite3_reset(pRtree.pWriteRowid);
    piRowid.* = sqlite3_last_insert_rowid(pRtree.db);
    return rc;
}

fn rtreeDeleteRowid(pRtree: *Rtree, iDelete: i64) c_int {
    var pLeaf: ?*RtreeNode = null;
    var iCell: c_int = undefined;
    var pRoot: ?*RtreeNode = null;

    var rc = nodeAcquire(pRtree, 1, null, &pRoot);
    if (rc == SQLITE_OK) {
        rc = findLeafNode(pRtree, iDelete, &pLeaf, null);
    }

    if (rc == SQLITE_OK and pLeaf != null) {
        rc = nodeRowidIndex(pRtree, pLeaf.?, iDelete, &iCell);
        if (rc == SQLITE_OK) {
            rc = deleteCell(pRtree, pLeaf.?, iCell, 0);
        }
        const rc2 = nodeRelease(pRtree, pLeaf);
        if (rc == SQLITE_OK) rc = rc2;
    }

    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pRtree.pDeleteRowid, 1, iDelete);
        _ = sqlite3_step(pRtree.pDeleteRowid);
        rc = sqlite3_reset(pRtree.pDeleteRowid);
    }

    if (rc == SQLITE_OK and pRtree.iDepth > 0 and NCELL(pRoot.?) == 1) {
        var pChild: ?*RtreeNode = null;
        const iChild = nodeGetRowid(pRtree, pRoot.?, 0);
        rc = nodeAcquire(pRtree, iChild, pRoot, &pChild);
        if (rc == SQLITE_OK) {
            rc = removeNode(pRtree, pChild.?, pRtree.iDepth - 1);
        }
        const rc2 = nodeRelease(pRtree, pChild);
        if (rc == SQLITE_OK) rc = rc2;
        if (rc == SQLITE_OK) {
            pRtree.iDepth -= 1;
            writeInt16(pRoot.?.zData.?, pRtree.iDepth);
            pRoot.?.isDirty = 1;
        }
    }

    pLeaf = pRtree.pDeleted;
    while (pLeaf) |pl| {
        if (rc == SQLITE_OK) {
            rc = reinsertNodeContent(pRtree, pl);
        }
        pRtree.pDeleted = pl.pNext;
        pRtree.nNodeRef -= 1;
        sqlite3_free(pl);
        pLeaf = pRtree.pDeleted;
    }

    if (rc == SQLITE_OK) {
        rc = nodeRelease(pRtree, pRoot);
    } else {
        _ = nodeRelease(pRtree, pRoot);
    }

    return rc;
}

const RNDTOWARDS: f64 = (1.0 - 1.0 / 8388608.0);
const RNDAWAY: f64 = (1.0 + 1.0 / 8388608.0);

fn rtreeValueDown(v: ?*sqlite3_value) RtreeValue {
    const d = sqlite3_value_double(v);
    var f: f32 = @floatCast(d);
    if (f > d) {
        f = @floatCast(d * (if (d < 0) RNDAWAY else RNDTOWARDS));
    }
    return f;
}
fn rtreeValueUp(v: ?*sqlite3_value) RtreeValue {
    const d = sqlite3_value_double(v);
    var f: f32 = @floatCast(d);
    if (f < d) {
        f = @floatCast(d * (if (d < 0) RNDTOWARDS else RNDAWAY));
    }
    return f;
}

fn rtreeConstraintError(pRtree: *Rtree, iCol: c_int) c_int {
    var pStmt: ?*sqlite3_stmt = null;
    var rc: c_int = undefined;

    const zSql = sqlite3_mprintf("SELECT * FROM %Q.%Q", pRtree.zDb, pRtree.zName);
    if (zSql != null) {
        rc = sqlite3_prepare_v2(pRtree.db, zSql.?, -1, &pStmt, null);
    } else {
        rc = SQLITE_NOMEM;
    }
    sqlite3_free(zSql);

    if (rc == SQLITE_OK) {
        if (iCol == 0) {
            const zCol = sqlite3_column_name(pStmt, 0);
            pRtree.base.zErrMsg = sqlite3_mprintf("UNIQUE constraint failed: %s.%s", pRtree.zName, zCol);
        } else {
            const zCol1 = sqlite3_column_name(pStmt, iCol);
            const zCol2 = sqlite3_column_name(pStmt, iCol + 1);
            pRtree.base.zErrMsg = sqlite3_mprintf("rtree constraint failed: %s.(%s<=%s)", pRtree.zName, zCol1, zCol2);
        }
    }

    _ = sqlite3_finalize(pStmt);
    return if (rc == SQLITE_OK) SQLITE_CONSTRAINT else rc;
}

fn rtreeUpdate(pVtab: *sqlite3_vtab, nData: c_int, aData: ?[*]?*sqlite3_value, pRowid: *i64) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    var rc: c_int = SQLITE_OK;
    var cell: RtreeCell = std.mem.zeroes(RtreeCell);
    var bHaveRowid: c_int = 0;
    const av = aData.?;

    if (pRtree.nNodeRef != 0) {
        return SQLITE_LOCKED_VTAB;
    }
    rtreeReference(pRtree);

    if (nData > 1) {
        var nn = nData - 4;
        if (nn > pRtree.nDim2) nn = pRtree.nDim2;

        if (pRtree.eCoordType == RTREE_COORD_REAL32) {
            var ii: c_int = 0;
            while (ii < nn) : (ii += 2) {
                cell.aCoord[@intCast(ii)].f = rtreeValueDown(av[@intCast(ii + 3)]);
                cell.aCoord[@intCast(ii + 1)].f = rtreeValueUp(av[@intCast(ii + 4)]);
                if (cell.aCoord[@intCast(ii)].f > cell.aCoord[@intCast(ii + 1)].f) {
                    rc = rtreeConstraintError(pRtree, ii + 1);
                    rtreeRelease(pRtree);
                    return rc;
                }
            }
        } else {
            var ii: c_int = 0;
            while (ii < nn) : (ii += 2) {
                cell.aCoord[@intCast(ii)].i = sqlite3_value_int(av[@intCast(ii + 3)]);
                cell.aCoord[@intCast(ii + 1)].i = sqlite3_value_int(av[@intCast(ii + 4)]);
                if (cell.aCoord[@intCast(ii)].i > cell.aCoord[@intCast(ii + 1)].i) {
                    rc = rtreeConstraintError(pRtree, ii + 1);
                    rtreeRelease(pRtree);
                    return rc;
                }
            }
        }

        if (sqlite3_value_type(av[2]) != SQLITE_NULL) {
            cell.iRowid = sqlite3_value_int64(av[2]);
            if (sqlite3_value_type(av[0]) == SQLITE_NULL or sqlite3_value_int64(av[0]) != cell.iRowid) {
                _ = sqlite3_bind_int64(pRtree.pReadRowid, 1, cell.iRowid);
                const steprc = sqlite3_step(pRtree.pReadRowid);
                rc = sqlite3_reset(pRtree.pReadRowid);
                if (steprc == SQLITE_ROW) {
                    if (sqlite3_vtab_on_conflict(pRtree.db) == SQLITE_REPLACE) {
                        rc = rtreeDeleteRowid(pRtree, cell.iRowid);
                    } else {
                        rc = rtreeConstraintError(pRtree, 0);
                        rtreeRelease(pRtree);
                        return rc;
                    }
                }
            }
            bHaveRowid = 1;
        }
    }

    if (sqlite3_value_type(av[0]) != SQLITE_NULL) {
        rc = rtreeDeleteRowid(pRtree, sqlite3_value_int64(av[0]));
    }

    if (rc == SQLITE_OK and nData > 1) {
        var pLeaf: ?*RtreeNode = null;
        if (bHaveRowid == 0) {
            rc = rtreeNewRowid(pRtree, &cell.iRowid);
        }
        pRowid.* = cell.iRowid;

        if (rc == SQLITE_OK) {
            rc = chooseLeaf(pRtree, &cell, 0, &pLeaf);
        }
        if (rc == SQLITE_OK) {
            rc = rtreeInsertCell(pRtree, pLeaf.?, &cell, 0);
            const rc2 = nodeRelease(pRtree, pLeaf);
            if (rc == SQLITE_OK) rc = rc2;
        }
        if (rc == SQLITE_OK and pRtree.nAux != 0) {
            const pUp = pRtree.pWriteAux;
            _ = sqlite3_bind_int64(pUp, 1, pRowid.*);
            var jj: c_int = 0;
            while (jj < pRtree.nAux) : (jj += 1) {
                _ = sqlite3_bind_value(pUp, jj + 2, av[@intCast(@as(c_int, pRtree.nDim2) + 3 + jj)]);
            }
            _ = sqlite3_step(pUp);
            rc = sqlite3_reset(pUp);
        }
    }

    rtreeRelease(pRtree);
    return rc;
}

fn rtreeBeginTransaction(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    pRtree.inWrTrans = 1;
    return SQLITE_OK;
}

fn rtreeEndTransaction(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    pRtree.inWrTrans = 0;
    nodeBlobReset(pRtree);
    return SQLITE_OK;
}
fn rtreeRollback(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    return rtreeEndTransaction(pVtab);
}

fn rtreeRename(pVtab: *sqlite3_vtab, zNewName: [*:0]const u8) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    var rc: c_int = SQLITE_NOMEM;
    const zSql = sqlite3_mprintf(
        "ALTER TABLE %Q.'%q_node'   RENAME TO \"%w_node\";" ++
            "ALTER TABLE %Q.'%q_parent' RENAME TO \"%w_parent\";" ++
            "ALTER TABLE %Q.'%q_rowid'  RENAME TO \"%w_rowid\";",
        pRtree.zDb,
        pRtree.zName,
        zNewName,
        pRtree.zDb,
        pRtree.zName,
        zNewName,
        pRtree.zDb,
        pRtree.zName,
        zNewName,
    );
    if (zSql != null) {
        nodeBlobReset(pRtree);
        rc = sqlite3_exec(pRtree.db, zSql.?, null, null, null);
        sqlite3_free(zSql);
    }
    return rc;
}

fn rtreeSavepoint(pVtab: *sqlite3_vtab, iSavepoint: c_int) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    const iwt = pRtree.inWrTrans;
    _ = iSavepoint;
    pRtree.inWrTrans = 0;
    nodeBlobReset(pRtree);
    pRtree.inWrTrans = iwt;
    return SQLITE_OK;
}

fn rtreeQueryStat1(db: ?*sqlite3, pRtree: *Rtree) c_int {
    const zFmt = "SELECT stat FROM %Q.sqlite_stat1 WHERE tbl = '%q_rowid'";
    var p: ?*sqlite3_stmt = undefined;
    var nRow: i64 = RTREE_MIN_ROWEST;

    var rc = sqlite3_table_column_metadata(db, pRtree.zDb, "sqlite_stat1", null, null, null, null, null, null);
    if (rc != SQLITE_OK) {
        pRtree.nRowEst = RTREE_DEFAULT_ROWEST;
        return if (rc == SQLITE_ERROR) SQLITE_OK else rc;
    }
    const zSql = sqlite3_mprintf(zFmt, pRtree.zDb, pRtree.zName);
    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else {
        rc = sqlite3_prepare_v2(db, zSql.?, -1, &p, null);
        if (rc == SQLITE_OK) {
            if (sqlite3_step(p) == SQLITE_ROW) nRow = sqlite3_column_int64(p, 0);
            rc = sqlite3_finalize(p);
        }
        sqlite3_free(zSql);
    }
    pRtree.nRowEst = @max(nRow, RTREE_MIN_ROWEST);
    return rc;
}

fn rtreeShadowName(zName: [*:0]const u8) callconv(.c) c_int {
    const azName = [_][*:0]const u8{ "node", "parent", "rowid" };
    for (azName) |n| {
        if (sqlite3_stricmp(zName, n) == 0) return 1;
    }
    return 0;
}

const rtreeModule: sqlite3_module = .{
    .iVersion = 4,
    .xCreate = &rtreeCreate,
    .xConnect = &rtreeConnect,
    .xBestIndex = &rtreeBestIndex,
    .xDisconnect = &rtreeDisconnect,
    .xDestroy = &rtreeDestroy,
    .xOpen = &rtreeOpen,
    .xClose = &rtreeClose,
    .xFilter = &rtreeFilter,
    .xNext = &rtreeNext,
    .xEof = &rtreeEof,
    .xColumn = &rtreeColumn,
    .xRowid = &rtreeRowid,
    .xUpdate = &rtreeUpdate,
    .xBegin = &rtreeBeginTransaction,
    .xSync = &rtreeEndTransaction,
    .xCommit = &rtreeEndTransaction,
    .xRollback = &rtreeRollback,
    .xFindFunction = null,
    .xRename = &rtreeRename,
    .xSavepoint = &rtreeSavepoint,
    .xRelease = null,
    .xRollbackTo = null,
    .xShadowName = &rtreeShadowName,
    .xIntegrity = &rtreeIntegrity,
};

const N_STATEMENT: usize = 8;
fn rtreeSqlInit(pRtree: *Rtree, db: ?*sqlite3, zDb: [*:0]const u8, zPrefix: [*:0]const u8, isCreate: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    const azSql = [N_STATEMENT][*:0]const u8{
        "INSERT OR REPLACE INTO '%q'.'%q_node' VALUES(?1, ?2)",
        "DELETE FROM '%q'.'%q_node' WHERE nodeno = ?1",
        "SELECT nodeno FROM '%q'.'%q_rowid' WHERE rowid = ?1",
        "INSERT OR REPLACE INTO '%q'.'%q_rowid' VALUES(?1, ?2)",
        "DELETE FROM '%q'.'%q_rowid' WHERE rowid = ?1",
        "SELECT parentnode FROM '%q'.'%q_parent' WHERE nodeno = ?1",
        "INSERT OR REPLACE INTO '%q'.'%q_parent' VALUES(?1, ?2)",
        "DELETE FROM '%q'.'%q_parent' WHERE nodeno = ?1",
    };
    const f: c_uint = SQLITE_PREPARE_PERSISTENT | SQLITE_PREPARE_NO_VTAB;
    pRtree.db = db;

    if (isCreate != 0) {
        const p = sqlite3_str_new(db);
        sqlite3_str_appendf(p, "CREATE TABLE \"%w\".\"%w_rowid\"(rowid INTEGER PRIMARY KEY,nodeno", zDb, zPrefix);
        var ii: c_int = 0;
        while (ii < pRtree.nAux) : (ii += 1) {
            sqlite3_str_appendf(p, ",a%d", ii);
        }
        sqlite3_str_appendf(p, ");CREATE TABLE \"%w\".\"%w_node\"(nodeno INTEGER PRIMARY KEY,data);", zDb, zPrefix);
        sqlite3_str_appendf(p, "CREATE TABLE \"%w\".\"%w_parent\"(nodeno INTEGER PRIMARY KEY,parentnode);", zDb, zPrefix);
        sqlite3_str_appendf(p, "INSERT INTO \"%w\".\"%w_node\"VALUES(1,zeroblob(%d))", zDb, zPrefix, pRtree.iNodeSize);
        const zCreate = sqlite3_str_finish(p);
        if (zCreate == null) {
            return SQLITE_NOMEM;
        }
        rc = sqlite3_exec(db, zCreate.?, null, null, null);
        sqlite3_free(zCreate);
        if (rc != SQLITE_OK) {
            return rc;
        }
    }

    const appStmt = [N_STATEMENT]*?*sqlite3_stmt{
        &pRtree.pWriteNode,
        &pRtree.pDeleteNode,
        &pRtree.pReadRowid,
        &pRtree.pWriteRowid,
        &pRtree.pDeleteRowid,
        &pRtree.pReadParent,
        &pRtree.pWriteParent,
        &pRtree.pDeleteParent,
    };

    rc = rtreeQueryStat1(db, pRtree);
    var i: usize = 0;
    while (i < N_STATEMENT and rc == SQLITE_OK) : (i += 1) {
        var zFormat: [*:0]const u8 = undefined;
        if (i != 3 or pRtree.nAux == 0) {
            zFormat = azSql[i];
        } else {
            zFormat = "INSERT INTO\"%w\".\"%w_rowid\"(rowid,nodeno)VALUES(?1,?2)" ++
                "ON CONFLICT(rowid)DO UPDATE SET nodeno=excluded.nodeno";
        }
        const zSql = sqlite3_mprintf(zFormat, zDb, zPrefix);
        if (zSql != null) {
            rc = sqlite3_prepare_v3(db, zSql.?, -1, f, appStmt[i], null);
        } else {
            rc = SQLITE_NOMEM;
        }
        sqlite3_free(zSql);
    }
    if (pRtree.nAux != 0 and rc != SQLITE_NOMEM) {
        pRtree.zReadAuxSql = sqlite3_mprintf("SELECT * FROM \"%w\".\"%w_rowid\" WHERE rowid=?1", zDb, zPrefix);
        if (pRtree.zReadAuxSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            const p = sqlite3_str_new(db);
            sqlite3_str_appendf(p, "UPDATE \"%w\".\"%w_rowid\"SET ", zDb, zPrefix);
            var ii: c_int = 0;
            while (ii < pRtree.nAux) : (ii += 1) {
                if (ii != 0) sqlite3_str_append(p, ",", 1);
                if (ii < pRtree.nAuxNotNull) {
                    sqlite3_str_appendf(p, "a%d=coalesce(?%d,a%d)", ii, ii + 2, ii);
                } else {
                    sqlite3_str_appendf(p, "a%d=?%d", ii, ii + 2);
                }
            }
            sqlite3_str_appendf(p, " WHERE rowid=?1");
            const zSql = sqlite3_str_finish(p);
            if (zSql == null) {
                rc = SQLITE_NOMEM;
            } else {
                rc = sqlite3_prepare_v3(db, zSql.?, -1, f, &pRtree.pWriteAux, null);
                sqlite3_free(zSql);
            }
        }
    }

    return rc;
}

fn getIntFromStmt(db: ?*sqlite3, zSql: ?[*:0]const u8, piVal: *c_int) c_int {
    var rc: c_int = SQLITE_NOMEM;
    if (zSql) |z| {
        var pStmt: ?*sqlite3_stmt = null;
        rc = sqlite3_prepare_v2(db, z, -1, &pStmt, null);
        if (rc == SQLITE_OK) {
            if (sqlite3_step(pStmt) == SQLITE_ROW) {
                piVal.* = sqlite3_column_int(pStmt, 0);
            }
            rc = sqlite3_finalize(pStmt);
        }
    }
    return rc;
}

fn getNodeSize(db: ?*sqlite3, pRtree: *Rtree, isCreate: c_int, pzErr: *?[*:0]u8) c_int {
    var rc: c_int = undefined;
    var zSql: ?[*:0]u8 = undefined;
    if (isCreate != 0) {
        var iPageSize: c_int = 0;
        zSql = sqlite3_mprintf("PRAGMA %Q.page_size", pRtree.zDb);
        rc = getIntFromStmt(db, zSql, &iPageSize);
        if (rc == SQLITE_OK) {
            pRtree.iNodeSize = iPageSize - 64;
            if ((4 + @as(c_int, pRtree.nBytesPerCell) * RTREE_MAXCELLS) < pRtree.iNodeSize) {
                pRtree.iNodeSize = 4 + @as(c_int, pRtree.nBytesPerCell) * RTREE_MAXCELLS;
            }
        } else {
            pzErr.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
        }
    } else {
        zSql = sqlite3_mprintf("SELECT length(data) FROM '%q'.'%q_node' WHERE nodeno = 1", pRtree.zDb, pRtree.zName);
        rc = getIntFromStmt(db, zSql, &pRtree.iNodeSize);
        if (rc != SQLITE_OK) {
            pzErr.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
        } else if (pRtree.iNodeSize < (512 - 64)) {
            rc = SQLITE_CORRUPT_VTAB;
            pzErr.* = sqlite3_mprintf("undersize RTree blobs in \"%q_node\"", pRtree.zName);
        }
    }
    sqlite3_free(zSql);
    return rc;
}

fn rtreeTokenLength(z: [*:0]const u8) c_int {
    var dummy: c_int = 0;
    return sqlite3GetToken(@ptrCast(z), &dummy);
}

fn rtreeInit(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argvOpt: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8, isCreate: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    const eCoordType: c_int = if (pAux != null) RTREE_COORD_INT32 else RTREE_COORD_REAL32;
    var iErr: usize = 0;
    const argv = argvOpt.?;

    const aErrMsg = [_][*:0]const u8{
        "",
        "Wrong number of columns for an rtree table",
        "Too few columns for an rtree table",
        "Too many columns for an rtree table",
        "Auxiliary rtree columns must be last",
    };

    if (argc < 6 or argc > RTREE_MAX_AUX_COLUMN + 3) {
        pzErr.* = sqlite3_mprintf("%s", aErrMsg[@as(usize, 2) + @intFromBool(argc >= 6)]);
        return SQLITE_ERROR;
    }

    _ = sqlite3_vtab_config(db, SQLITE_VTAB_CONSTRAINT_SUPPORT, @as(c_int, 1));
    _ = sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);

    const nDb = strlen0(argv[1].?);
    const nName = strlen0(argv[2].?);
    const allocSz = @sizeOf(Rtree) + nDb + nName * 2 + 8;
    const pRtreeOpt: ?*Rtree = @ptrCast(@alignCast(sqlite3_malloc64(allocSz)));
    if (pRtreeOpt == null) {
        return SQLITE_NOMEM;
    }
    const pRtree = pRtreeOpt.?;
    @memset(@as([*]u8, @ptrCast(pRtree))[0..allocSz], 0);
    pRtree.nBusy = 1;
    pRtree.base.pModule = &rtreeModule;
    const tail: [*]u8 = @as([*]u8, @ptrCast(pRtree)) + @sizeOf(Rtree);
    pRtree.zDb = @ptrCast(tail);
    pRtree.zName = @ptrCast(tail + nDb + 1);
    pRtree.zNodeName = @ptrCast(tail + nDb + 1 + nName + 1);
    pRtree.eCoordType = @intCast(eCoordType);
    @memcpy(pRtree.zDb.?[0..nDb], argv[1].?[0..nDb]);
    @memcpy(pRtree.zName.?[0..nName], argv[2].?[0..nName]);
    @memcpy(pRtree.zNodeName.?[0..nName], argv[2].?[0..nName]);
    @memcpy(pRtree.zNodeName.?[nName .. nName + 6], "_node\x00");

    const pSql = sqlite3_str_new(db);
    sqlite3_str_appendf(pSql, "CREATE TABLE x(%.*s INT", rtreeTokenLength(argv[3].?), argv[3].?);
    var ii: c_int = 4;
    while (ii < argc) : (ii += 1) {
        const zArg = argv[@intCast(ii)].?;
        if (zArg[0] == '+') {
            pRtree.nAux += 1;
            sqlite3_str_appendf(pSql, ",%.*s", rtreeTokenLength(@ptrCast(zArg + 1)), zArg + 1);
        } else if (pRtree.nAux > 0) {
            break;
        } else {
            const azFormat = [_][*:0]const u8{ ",%.*s REAL", ",%.*s INT" };
            pRtree.nDim2 += 1;
            sqlite3_str_appendf(pSql, azFormat[@intCast(eCoordType)], rtreeTokenLength(zArg), zArg);
        }
    }
    sqlite3_str_appendf(pSql, ");");
    const zSql = sqlite3_str_finish(pSql);
    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else if (ii < argc) {
        pzErr.* = sqlite3_mprintf("%s", aErrMsg[4]);
        rc = SQLITE_ERROR;
    } else {
        rc = sqlite3_declare_vtab(db, zSql.?);
        if (rc != SQLITE_OK) {
            pzErr.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
        }
    }
    sqlite3_free(zSql);
    if (rc != 0) return rtreeInitFail(pRtree, ppVtab, rc);
    pRtree.nDim = pRtree.nDim2 / 2;
    if (pRtree.nDim < 1) {
        iErr = 2;
    } else if (pRtree.nDim2 > RTREE_MAX_DIMENSIONS * 2) {
        iErr = 3;
    } else if (pRtree.nDim2 % 2 != 0) {
        iErr = 1;
    } else {
        iErr = 0;
    }
    if (iErr != 0) {
        pzErr.* = sqlite3_mprintf("%s", aErrMsg[iErr]);
        return rtreeInitFail(pRtree, ppVtab, rc);
    }
    pRtree.nBytesPerCell = @intCast(8 + @as(c_int, pRtree.nDim2) * 4);

    rc = getNodeSize(db, pRtree, isCreate, pzErr);
    if (rc != 0) return rtreeInitFail(pRtree, ppVtab, rc);
    rc = rtreeSqlInit(pRtree, db, argv[1].?, argv[2].?, isCreate);
    if (rc != 0) {
        pzErr.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
        return rtreeInitFail(pRtree, ppVtab, rc);
    }

    ppVtab.* = @ptrCast(pRtree);
    return SQLITE_OK;
}

fn rtreeInitFail(pRtree: *Rtree, ppVtab: *?*sqlite3_vtab, rcIn: c_int) c_int {
    var rc = rcIn;
    if (rc == SQLITE_OK) rc = SQLITE_ERROR;
    _ = ppVtab;
    rtreeRelease(pRtree);
    return rc;
}

fn strlen0(z: [*:0]const u8) usize {
    return std.mem.len(z);
}

fn rtreenode(ctx: ?*sqlite3_context, nArg: c_int, apArg: ?[*]?*sqlite3_value) callconv(.c) void {
    var node: RtreeNode = std.mem.zeroes(RtreeNode);
    var tree: Rtree = std.mem.zeroes(Rtree);
    _ = nArg;
    const av = apArg.?;
    tree.nDim = @intCast(sqlite3_value_int(av[0]));
    if (tree.nDim < 1 or tree.nDim > 5) return;
    tree.nDim2 = tree.nDim * 2;
    tree.nBytesPerCell = @intCast(8 + 8 * @as(c_int, tree.nDim));
    node.zData = @constCast(@ptrCast(sqlite3_value_blob(av[1])));
    if (node.zData == null) return;
    const nData = sqlite3_value_bytes(av[1]);
    if (nData < 4) return;
    if (nData < 4 + NCELL(&node) * @as(c_int, tree.nBytesPerCell)) return;

    const pOut = sqlite3_str_new(null);
    var ii: c_int = 0;
    while (ii < NCELL(&node)) : (ii += 1) {
        var cell: RtreeCell = undefined;
        nodeGetCell(&tree, &node, ii, &cell);
        if (ii > 0) sqlite3_str_append(pOut, " ", 1);
        sqlite3_str_appendf(pOut, "{%lld", cell.iRowid);
        var jj: c_int = 0;
        while (jj < tree.nDim2) : (jj += 1) {
            sqlite3_str_appendf(pOut, " %g", @as(f64, cell.aCoord[@intCast(jj)].f));
        }
        sqlite3_str_append(pOut, "}", 1);
    }
    const errCode = sqlite3_str_errcode(pOut);
    sqlite3_result_error_code(ctx, errCode);
    sqlite3_result_text(ctx, sqlite3_str_finish(pOut), -1, &freeDestructor);
}

fn rtreedepth(ctx: ?*sqlite3_context, nArg: c_int, apArg: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = nArg;
    const av = apArg.?;
    if (sqlite3_value_type(av[0]) != SQLITE_BLOB or sqlite3_value_bytes(av[0]) < 2) {
        sqlite3_result_error(ctx, "Invalid argument to rtreedepth()", -1);
    } else {
        const zBlob: ?[*]const u8 = @ptrCast(sqlite3_value_blob(av[0]));
        if (zBlob) |zb| {
            sqlite3_result_int(ctx, readInt16(zb));
        } else {
            sqlite3_result_error_nomem(ctx);
        }
    }
}

// --------------------------- rtreecheck ------------------------------------
const RtreeCheck = extern struct {
    db: ?*sqlite3,
    zDb: ?[*:0]const u8,
    zTab: ?[*:0]const u8,
    bInt: c_int,
    nDim: c_int,
    pGetNode: ?*sqlite3_stmt,
    aCheckMapping: [2]?*sqlite3_stmt,
    nLeaf: c_int,
    nNonLeaf: c_int,
    rc: c_int,
    zReport: ?[*:0]u8,
    nErr: c_int,
};

fn rtreeCheckReset(pCheck: *RtreeCheck, pStmt: ?*sqlite3_stmt) void {
    const rc = sqlite3_reset(pStmt);
    if (pCheck.rc == SQLITE_OK) pCheck.rc = rc;
}

fn rtreeCheckPrepare(pCheck: *RtreeCheck, zFmt: [*:0]const u8, ap: *std.builtin.VaList) ?*sqlite3_stmt {
    var pRet: ?*sqlite3_stmt = null;
    const z = sqlite3_vmprintf(zFmt, ap);
    if (pCheck.rc == SQLITE_OK) {
        if (z == null) {
            pCheck.rc = SQLITE_NOMEM;
        } else {
            pCheck.rc = sqlite3_prepare_v2(pCheck.db, z.?, -1, &pRet, null);
        }
    }
    sqlite3_free(z);
    return pRet;
}

fn rtreeCheckPrepareV(pCheck: *RtreeCheck, zFmt: [*:0]const u8, ...) callconv(.c) ?*sqlite3_stmt {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    return rtreeCheckPrepare(pCheck, zFmt, &ap);
}

fn rtreeCheckAppendMsg(pCheck: *RtreeCheck, zFmt: [*:0]const u8, ap: *std.builtin.VaList) void {
    if (pCheck.rc == SQLITE_OK and pCheck.nErr < RTREE_CHECK_MAX_ERROR) {
        const z = sqlite3_vmprintf(zFmt, ap);
        if (z == null) {
            pCheck.rc = SQLITE_NOMEM;
        } else {
            pCheck.zReport = sqlite3_mprintf("%z%s%z", pCheck.zReport, if (pCheck.zReport != null) @as([*:0]const u8, "\n") else @as([*:0]const u8, ""), z);
            if (pCheck.zReport == null) {
                pCheck.rc = SQLITE_NOMEM;
            }
        }
        pCheck.nErr += 1;
    }
}

fn rtreeCheckAppendMsgV(pCheck: *RtreeCheck, zFmt: [*:0]const u8, ...) callconv(.c) void {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    rtreeCheckAppendMsg(pCheck, zFmt, &ap);
}

fn rtreeCheckGetNode(pCheck: *RtreeCheck, iNode: i64, pnNode: *c_int) ?[*]u8 {
    var pRet: ?[*]u8 = null;

    if (pCheck.rc == SQLITE_OK and pCheck.pGetNode == null) {
        pCheck.pGetNode = rtreeCheckPrepareV(pCheck, "SELECT data FROM %Q.'%q_node' WHERE nodeno=?", pCheck.zDb, pCheck.zTab);
    }

    if (pCheck.rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pCheck.pGetNode, 1, iNode);
        if (sqlite3_step(pCheck.pGetNode) == SQLITE_ROW) {
            const nNode = sqlite3_column_bytes(pCheck.pGetNode, 0);
            const pNode: ?[*]const u8 = @ptrCast(sqlite3_column_blob(pCheck.pGetNode, 0));
            pRet = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nNode))));
            if (pRet == null) {
                pCheck.rc = SQLITE_NOMEM;
            } else {
                @memcpy(pRet.?[0..@intCast(nNode)], pNode.?[0..@intCast(nNode)]);
                pnNode.* = nNode;
            }
        }
        rtreeCheckReset(pCheck, pCheck.pGetNode);
        if (pCheck.rc == SQLITE_OK and pRet == null) {
            rtreeCheckAppendMsgV(pCheck, "Node %lld missing from database", iNode);
        }
    }

    return pRet;
}

fn rtreeCheckMapping(pCheck: *RtreeCheck, bLeaf: c_int, iKey: i64, iVal: i64) void {
    const azSql = [_][*:0]const u8{
        "SELECT parentnode FROM %Q.'%q_parent' WHERE nodeno=?1",
        "SELECT nodeno FROM %Q.'%q_rowid' WHERE rowid=?1",
    };

    if (pCheck.aCheckMapping[@intCast(bLeaf)] == null) {
        pCheck.aCheckMapping[@intCast(bLeaf)] = rtreeCheckPrepareV(pCheck, azSql[@intCast(bLeaf)], pCheck.zDb, pCheck.zTab);
    }
    if (pCheck.rc != SQLITE_OK) return;

    const pStmt = pCheck.aCheckMapping[@intCast(bLeaf)];
    _ = sqlite3_bind_int64(pStmt, 1, iKey);
    const rc = sqlite3_step(pStmt);
    if (rc == SQLITE_DONE) {
        rtreeCheckAppendMsgV(pCheck, "Mapping (%lld -> %lld) missing from %s table", iKey, iVal, if (bLeaf != 0) @as([*:0]const u8, "%_rowid") else @as([*:0]const u8, "%_parent"));
    } else if (rc == SQLITE_ROW) {
        const iiv = sqlite3_column_int64(pStmt, 0);
        if (iiv != iVal) {
            rtreeCheckAppendMsgV(pCheck, "Found (%lld -> %lld) in %s table, expected (%lld -> %lld)", iKey, iiv, if (bLeaf != 0) @as([*:0]const u8, "%_rowid") else @as([*:0]const u8, "%_parent"), iKey, iVal);
        }
    }
    rtreeCheckReset(pCheck, pStmt);
}

fn rtreeCheckCellCoord(pCheck: *RtreeCheck, iNode: i64, iCell: c_int, pCell: [*]const u8, pParent: ?[*]const u8) void {
    var c1: RtreeCoord = undefined;
    var c2: RtreeCoord = undefined;
    var p1: RtreeCoord = undefined;
    var p2: RtreeCoord = undefined;

    var i: c_int = 0;
    while (i < pCheck.nDim) : (i += 1) {
        readCoord(pCell + @as(usize, @intCast(4 * 2 * i)), &c1);
        readCoord(pCell + @as(usize, @intCast(4 * (2 * i + 1))), &c2);

        const corrupt = if (pCheck.bInt != 0) c1.i > c2.i else c1.f > c2.f;
        if (corrupt) {
            rtreeCheckAppendMsgV(pCheck, "Dimension %d of cell %d on node %lld is corrupt", i, iCell, iNode);
        }

        if (pParent) |pp| {
            readCoord(pp + @as(usize, @intCast(4 * 2 * i)), &p1);
            readCoord(pp + @as(usize, @intCast(4 * (2 * i + 1))), &p2);
            const c1lt = if (pCheck.bInt != 0) c1.i < p1.i else c1.f < p1.f;
            const c2gt = if (pCheck.bInt != 0) c2.i > p2.i else c2.f > p2.f;
            if (c1lt or c2gt) {
                rtreeCheckAppendMsgV(pCheck, "Dimension %d of cell %d on node %lld is corrupt relative to parent", i, iCell, iNode);
            }
        }
    }
}

fn rtreeCheckNode(pCheck: *RtreeCheck, iDepthIn: c_int, aParent: ?[*]const u8, iNode: i64) void {
    var iDepth = iDepthIn;
    var nNode: c_int = 0;

    const aNode = rtreeCheckGetNode(pCheck, iNode, &nNode);
    if (aNode) |an| {
        if (nNode < 4) {
            rtreeCheckAppendMsgV(pCheck, "Node %lld is too small (%d bytes)", iNode, nNode);
        } else {
            if (aParent == null) {
                iDepth = readInt16(an);
                if (iDepth > RTREE_MAX_DEPTH) {
                    rtreeCheckAppendMsgV(pCheck, "Rtree depth out of range (%d)", iDepth);
                    sqlite3_free(an);
                    return;
                }
            }
            const nCell = readInt16(an + 2);
            if ((4 + nCell * (8 + pCheck.nDim * 2 * 4)) > nNode) {
                rtreeCheckAppendMsgV(pCheck, "Node %lld is too small for cell count of %d (%d bytes)", iNode, nCell, nNode);
            } else {
                var i: c_int = 0;
                while (i < nCell) : (i += 1) {
                    const pCell = an + @as(usize, @intCast(4 + i * (8 + pCheck.nDim * 2 * 4)));
                    const iVal = readInt64(pCell);
                    rtreeCheckCellCoord(pCheck, iNode, i, pCell + 8, aParent);

                    if (iDepth > 0) {
                        rtreeCheckMapping(pCheck, 0, iVal, iNode);
                        rtreeCheckNode(pCheck, iDepth - 1, pCell + 8, iVal);
                        pCheck.nNonLeaf += 1;
                    } else {
                        rtreeCheckMapping(pCheck, 1, iVal, iNode);
                        pCheck.nLeaf += 1;
                    }
                }
            }
        }
        sqlite3_free(an);
    }
}

fn rtreeCheckCount(pCheck: *RtreeCheck, zTbl: [*:0]const u8, nExpect: i64) void {
    if (pCheck.rc == SQLITE_OK) {
        const pCount = rtreeCheckPrepareV(pCheck, "SELECT count(*) FROM %Q.'%q%s'", pCheck.zDb, pCheck.zTab, zTbl);
        if (pCount != null) {
            if (sqlite3_step(pCount) == SQLITE_ROW) {
                const nActual = sqlite3_column_int64(pCount, 0);
                if (nActual != nExpect) {
                    rtreeCheckAppendMsgV(pCheck, "Wrong number of entries in %%%s table - expected %lld, actual %lld", zTbl, nExpect, nActual);
                }
            }
            pCheck.rc = sqlite3_finalize(pCount);
        }
    }
}

fn rtreeCheckTable(db: ?*sqlite3, zDb: [*:0]const u8, zTab: [*:0]const u8, pzReport: *?[*:0]u8) c_int {
    var check: RtreeCheck = std.mem.zeroes(RtreeCheck);
    var nAux: c_int = 0;

    check.db = db;
    check.zDb = zDb;
    check.zTab = zTab;

    var pStmt = rtreeCheckPrepareV(&check, "SELECT * FROM %Q.'%q_rowid'", zDb, zTab);
    if (pStmt != null) {
        nAux = sqlite3_column_count(pStmt) - 2;
        _ = sqlite3_finalize(pStmt);
    } else if (check.rc != SQLITE_NOMEM) {
        check.rc = SQLITE_OK;
    }

    pStmt = rtreeCheckPrepareV(&check, "SELECT * FROM %Q.%Q", zDb, zTab);
    if (pStmt != null) {
        check.nDim = @divTrunc(sqlite3_column_count(pStmt) - 1 - nAux, 2);
        if (check.nDim < 1) {
            rtreeCheckAppendMsgV(&check, "Schema corrupt or not an rtree");
        } else if (SQLITE_ROW == sqlite3_step(pStmt)) {
            check.bInt = @intFromBool(sqlite3_column_type(pStmt, 1) == SQLITE_INTEGER);
        }
        const rc = sqlite3_finalize(pStmt);
        if (rc != SQLITE_CORRUPT) check.rc = rc;
    }

    if (check.nDim >= 1) {
        if (check.rc == SQLITE_OK) {
            rtreeCheckNode(&check, 0, null, 1);
        }
        rtreeCheckCount(&check, "_rowid", check.nLeaf);
        rtreeCheckCount(&check, "_parent", check.nNonLeaf);
    }

    _ = sqlite3_finalize(check.pGetNode);
    _ = sqlite3_finalize(check.aCheckMapping[0]);
    _ = sqlite3_finalize(check.aCheckMapping[1]);

    pzReport.* = check.zReport;
    return check.rc;
}

fn rtreeIntegrity(pVtab: *sqlite3_vtab, zSchema: [*:0]const u8, zName: [*:0]const u8, isQuick: c_int, pzErr: *?[*:0]u8) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    _ = zSchema;
    _ = zName;
    _ = isQuick;
    var rc = rtreeCheckTable(pRtree.db, pRtree.zDb.?, pRtree.zName.?, pzErr);
    if (rc == SQLITE_OK and pzErr.* != null) {
        pzErr.* = sqlite3_mprintf("In RTree %s.%s:\n%z", pRtree.zDb, pRtree.zName, pzErr.*);
        if (pzErr.* == null) rc = SQLITE_NOMEM;
    }
    return rc;
}

fn rtreecheck(ctx: ?*sqlite3_context, nArg: c_int, apArg: ?[*]?*sqlite3_value) callconv(.c) void {
    const av = apArg.?;
    if (nArg != 1 and nArg != 2) {
        sqlite3_result_error(ctx, "wrong number of arguments to function rtreecheck()", -1);
    } else {
        var zReport: ?[*:0]u8 = null;
        var zDb = sqlite3_value_text(av[0]);
        var zTab: ?[*:0]const u8 = undefined;
        if (nArg == 1) {
            zTab = zDb;
            zDb = "main";
        } else {
            zTab = sqlite3_value_text(av[1]);
        }
        const rc = rtreeCheckTable(sqlite3_context_db_handle(ctx), zDb.?, zTab.?, &zReport);
        if (rc == SQLITE_OK) {
            sqlite3_result_text(ctx, if (zReport != null) @as([*:0]const u8, @ptrCast(zReport)) else @as([*:0]const u8, "ok"), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_result_error_code(ctx, rc);
        }
        sqlite3_free(zReport);
    }
}

// ===========================================================================
// GEOPOLY (geopoly.c — textually #include'd into rtree.c upstream)
// ===========================================================================
const GeoCoord = f32;

const GeoPoly = extern struct {
    nVertex: c_int,
    hdr: [4]u8,
    a: [8]GeoCoord, // 2*nVertex values; allocation sized as needed
};

/// GEOPOLY_SZ(N) = sizeof(GeoPoly) + sizeof(GeoCoord)*2*(N-4)
fn geopolySz(n: i64) usize {
    return @intCast(@as(i64, @intCast(@sizeOf(GeoPoly))) + @as(i64, @sizeOf(GeoCoord)) * 2 * (n - 4));
}

/// GeoX(P,I) / GeoY(P,I): index into the trailing coordinate array.
fn geoCoordPtr(p: *GeoPoly) [*]GeoCoord {
    return @ptrCast(&p.a);
}
fn geoX(p: *GeoPoly, i: usize) GeoCoord {
    return geoCoordPtr(p)[i * 2];
}
fn geoY(p: *GeoPoly, i: usize) GeoCoord {
    return geoCoordPtr(p)[i * 2 + 1];
}
fn setGeoX(p: *GeoPoly, i: usize, v: GeoCoord) void {
    geoCoordPtr(p)[i * 2] = v;
}
fn setGeoY(p: *GeoPoly, i: usize, v: GeoCoord) void {
    geoCoordPtr(p)[i * 2 + 1] = v;
}

const GeoParse = extern struct {
    z: [*]const u8,
    nVertex: c_int,
    nAlloc: c_int,
    nErr: c_int,
    a: ?[*]GeoCoord,
};

extern fn atof(s: [*:0]const u8) f64;

fn geopolySwab32(a: [*]u8) void {
    const t = a[0];
    a[0] = a[3];
    a[3] = t;
    const t2 = a[1];
    a[1] = a[2];
    a[2] = t2;
}

const geopolyIsSpace = blk: {
    var arr = std.mem.zeroes([256]u8);
    arr[9] = 1;
    arr[10] = 1;
    arr[13] = 1;
    arr[32] = 1;
    break :blk arr;
};
fn fastIsspace(x: u8) bool {
    return geopolyIsSpace[x] != 0;
}
fn safeIsdigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

fn geopolySkipSpace(p: *GeoParse) u8 {
    while (fastIsspace(p.z[0])) p.z += 1;
    return p.z[0];
}

fn geopolyParseNumber(p: *GeoParse, pVal: ?*GeoCoord) c_int {
    var c = geopolySkipSpace(p);
    const z = p.z;
    var j: usize = 0;
    var seenDP: c_int = 0;
    var seenE: c_int = 0;
    if (c == '-') {
        j = 1;
        c = z[j];
    }
    if (c == '0' and z[j + 1] >= '0' and z[j + 1] <= '9') return 0;
    while (true) : (j += 1) {
        c = z[j];
        if (safeIsdigit(c)) continue;
        if (c == '.') {
            if (z[j - 1] == '-') return 0;
            if (seenDP != 0) return 0;
            seenDP = 1;
            continue;
        }
        if (c == 'e' or c == 'E') {
            if (z[j - 1] < '0') return 0;
            if (seenE != 0) return -1;
            seenDP = 1;
            seenE = 1;
            c = z[j + 1];
            if (c == '+' or c == '-') {
                j += 1;
                c = z[j + 1];
            }
            if (c < '0' or c > '9') return 0;
            continue;
        }
        break;
    }
    if (z[j - 1] < '0') return 0;
    if (pVal) |pv| {
        pv.* = @floatCast(atof(@ptrCast(p.z)));
    }
    p.z += j;
    return 1;
}

fn geopolyParseJson(z: [*]const u8, pRc: ?*c_int) ?*GeoPoly {
    var s: GeoParse = std.mem.zeroes(GeoParse);
    var rc: c_int = SQLITE_OK;
    s.z = z;
    if (geopolySkipSpace(&s) == '[') {
        s.z += 1;
        json_outer: while (geopolySkipSpace(&s) == '[') {
            var ii: c_int = 0;
            s.z += 1;
            if (s.nVertex >= s.nAlloc) {
                s.nAlloc = s.nAlloc * 2 + 16;
                const aNew: ?[*]GeoCoord = @ptrCast(@alignCast(sqlite3_realloc64(s.a, @as(u64, @intCast(s.nAlloc)) * @sizeOf(GeoCoord) * 2)));
                if (aNew == null) {
                    rc = SQLITE_NOMEM;
                    s.nErr += 1;
                    break;
                }
                s.a = aNew;
            }
            while (geopolyParseNumber(&s, if (ii <= 1) &s.a.?[@intCast(s.nVertex * 2 + ii)] else null) != 0) {
                ii += 1;
                if (ii == 2) s.nVertex += 1;
                const c = geopolySkipSpace(&s);
                s.z += 1;
                if (c == ',') continue;
                if (c == ']' and ii >= 2) break;
                s.nErr += 1;
                rc = SQLITE_ERROR;
                break :json_outer;
            }
            if (geopolySkipSpace(&s) == ',') {
                s.z += 1;
                continue;
            }
            break;
        }
        if (geopolySkipSpace(&s) == ']' and s.nVertex >= 4 and
            s.a.?[0] == s.a.?[@intCast(s.nVertex * 2 - 2)] and
            s.a.?[1] == s.a.?[@intCast(s.nVertex * 2 - 1)] and
            (incZ(&s) == 0))
        {
            var x: c_int = 1;
            s.nVertex -= 1;
            const pOut: ?*GeoPoly = @ptrCast(@alignCast(sqlite3_malloc64(geopolySz(s.nVertex))));
            x = 1;
            if (pOut == null) {
                if (pRc) |pr| pr.* = rc;
                sqlite3_free(s.a);
                return null;
            }
            const po = pOut.?;
            po.nVertex = s.nVertex;
            @memcpy(@as([*]u8, @ptrCast(geoCoordPtr(po)))[0..@intCast(s.nVertex * 2 * @sizeOf(GeoCoord))], @as([*]const u8, @ptrCast(s.a.?))[0..@intCast(s.nVertex * 2 * @sizeOf(GeoCoord))]);
            po.hdr[0] = @as([*]u8, @ptrCast(&x))[0];
            po.hdr[1] = @truncate(@as(u32, @bitCast(s.nVertex >> 16)) & 0xff);
            po.hdr[2] = @truncate(@as(u32, @bitCast(s.nVertex >> 8)) & 0xff);
            po.hdr[3] = @truncate(@as(u32, @bitCast(s.nVertex)) & 0xff);
            sqlite3_free(s.a);
            if (pRc) |pr| pr.* = SQLITE_OK;
            return pOut;
        } else {
            s.nErr += 1;
            rc = SQLITE_ERROR;
        }
    }
    if (pRc) |pr| pr.* = rc;
    sqlite3_free(s.a);
    return null;
}

/// Helper for the `(s.z++, geopolySkipSpace(&s)==0)` comma expression.
fn incZ(s: *GeoParse) u8 {
    s.z += 1;
    return geopolySkipSpace(s);
}

fn geopolyFuncParam(pCtx: ?*sqlite3_context, pVal: ?*sqlite3_value, pRc: ?*c_int) ?*GeoPoly {
    var p: ?*GeoPoly = null;
    if (sqlite3_value_type(pVal) == SQLITE_BLOB) {
        const nByte = sqlite3_value_bytes(pVal);
        if (nByte >= @as(c_int, @intCast(4 + 6 * @sizeOf(GeoCoord)))) {
            const a: ?[*]const u8 = @ptrCast(sqlite3_value_blob(pVal));
            if (a == null) {
                if (pCtx != null) sqlite3_result_error_nomem(pCtx);
                return null;
            }
            const aa = a.?;
            const nVertex: c_int = (@as(c_int, aa[1]) << 16) + (@as(c_int, aa[2]) << 8) + aa[3];
            if ((aa[0] == 0 or aa[0] == 1) and (@as(usize, @intCast(nVertex)) * 2 * @sizeOf(GeoCoord) + 4) == @as(usize, @intCast(nByte))) {
                p = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(GeoPoly) + @as(usize, @intCast(nVertex - 1)) * 2 * @sizeOf(GeoCoord))));
                if (p == null) {
                    if (pRc) |pr| pr.* = SQLITE_NOMEM;
                    if (pCtx != null) sqlite3_result_error_nomem(pCtx);
                } else {
                    var x: c_int = 1;
                    const pp = p.?;
                    pp.nVertex = nVertex;
                    @memcpy(@as([*]u8, @ptrCast(&pp.hdr))[0..@intCast(nByte)], aa[0..@intCast(nByte)]);
                    if (aa[0] != @as([*]u8, @ptrCast(&x))[0]) {
                        var ip: usize = 0;
                        while (ip < @as(usize, @intCast(nVertex))) : (ip += 1) {
                            geopolySwab32(@ptrCast(&geoCoordPtr(pp)[ip * 2]));
                            geopolySwab32(@ptrCast(&geoCoordPtr(pp)[ip * 2 + 1]));
                        }
                        pp.hdr[0] ^= 1;
                    }
                }
            }
            if (pRc) |pr| pr.* = SQLITE_OK;
            return p;
        }
        if (pRc) |pr| pr.* = SQLITE_ERROR;
        return null;
    } else if (sqlite3_value_type(pVal) == SQLITE_TEXT) {
        const zJson = sqlite3_value_text(pVal);
        if (zJson == null) {
            if (pRc) |pr| pr.* = SQLITE_NOMEM;
            return null;
        }
        return geopolyParseJson(@ptrCast(zJson.?), pRc);
    } else {
        if (pRc) |pr| pr.* = SQLITE_ERROR;
        return null;
    }
}

fn geopolyBlobFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const p = geopolyFuncParam(context, argv.?[0], null);
    if (p) |pp| {
        sqlite3_result_blob(context, &pp.hdr, 4 + 8 * pp.nVertex, SQLITE_TRANSIENT);
        sqlite3_free(pp);
    }
}

fn geopolyJsonFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const p = geopolyFuncParam(context, argv.?[0], null);
    if (p) |pp| {
        const db = sqlite3_context_db_handle(context);
        const x = sqlite3_str_new(db);
        sqlite3_str_append(x, "[", 1);
        var i: usize = 0;
        while (i < @as(usize, @intCast(pp.nVertex))) : (i += 1) {
            sqlite3_str_appendf(x, "[%!g,%!g],", @as(f64, geoX(pp, i)), @as(f64, geoY(pp, i)));
        }
        sqlite3_str_appendf(x, "[%!g,%!g]]", @as(f64, geoX(pp, 0)), @as(f64, geoY(pp, 0)));
        sqlite3_result_text(context, sqlite3_str_finish(x), -1, &freeDestructor);
        sqlite3_free(pp);
    }
}

fn geopolySvgFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    if (argc < 1) return;
    const p = geopolyFuncParam(context, argv.?[0], null);
    if (p) |pp| {
        const db = sqlite3_context_db_handle(context);
        const x = sqlite3_str_new(db);
        var cSep: u8 = '\'';
        sqlite3_str_appendf(x, "<polyline points=");
        var i: usize = 0;
        while (i < @as(usize, @intCast(pp.nVertex))) : (i += 1) {
            sqlite3_str_appendf(x, "%c%g,%g", @as(c_int, cSep), @as(f64, geoX(pp, i)), @as(f64, geoY(pp, i)));
            cSep = ' ';
        }
        sqlite3_str_appendf(x, " %g,%g'", @as(f64, geoX(pp, 0)), @as(f64, geoY(pp, 0)));
        var ai: c_int = 1;
        while (ai < argc) : (ai += 1) {
            const z = sqlite3_value_text(argv.?[@intCast(ai)]);
            if (z != null and z.?[0] != 0) {
                sqlite3_str_appendf(x, " %s", z.?);
            }
        }
        sqlite3_str_appendf(x, "></polyline>");
        sqlite3_result_text(context, sqlite3_str_finish(x), -1, &freeDestructor);
        sqlite3_free(pp);
    }
}

fn geopolyXformFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const av = argv.?;
    const p = geopolyFuncParam(context, av[0], null);
    const A = sqlite3_value_double(av[1]);
    const B = sqlite3_value_double(av[2]);
    const C = sqlite3_value_double(av[3]);
    const D = sqlite3_value_double(av[4]);
    const E = sqlite3_value_double(av[5]);
    const F = sqlite3_value_double(av[6]);
    if (p) |pp| {
        var ii: usize = 0;
        while (ii < @as(usize, @intCast(pp.nVertex))) : (ii += 1) {
            const x0: f64 = geoX(pp, ii);
            const y0: f64 = geoY(pp, ii);
            setGeoX(pp, ii, @floatCast(A * x0 + B * y0 + E));
            setGeoY(pp, ii, @floatCast(C * x0 + D * y0 + F));
        }
        sqlite3_result_blob(context, &pp.hdr, 4 + 8 * pp.nVertex, SQLITE_TRANSIENT);
        sqlite3_free(pp);
    }
}

fn geopolyArea(p: *GeoPoly) f64 {
    var rArea: f64 = 0.0;
    var ii: usize = 0;
    const last: usize = @intCast(p.nVertex - 1);
    while (ii < last) : (ii += 1) {
        rArea += (@as(f64, geoX(p, ii)) - geoX(p, ii + 1)) * (@as(f64, geoY(p, ii)) + geoY(p, ii + 1)) * 0.5;
    }
    rArea += (@as(f64, geoX(p, ii)) - geoX(p, 0)) * (@as(f64, geoY(p, ii)) + geoY(p, 0)) * 0.5;
    return rArea;
}

fn geopolyAreaFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const p = geopolyFuncParam(context, argv.?[0], null);
    if (p) |pp| {
        sqlite3_result_double(context, geopolyArea(pp));
        sqlite3_free(pp);
    }
}

fn geopolyCcwFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const p = geopolyFuncParam(context, argv.?[0], null);
    if (p) |pp| {
        if (geopolyArea(pp) < 0.0) {
            var ii: usize = 1;
            var jj: usize = @intCast(pp.nVertex - 1);
            while (ii < jj) : ({
                ii += 1;
                jj -= 1;
            }) {
                var t = geoX(pp, ii);
                setGeoX(pp, ii, geoX(pp, jj));
                setGeoX(pp, jj, t);
                t = geoY(pp, ii);
                setGeoY(pp, ii, geoY(pp, jj));
                setGeoY(pp, jj, t);
            }
        }
        sqlite3_result_blob(context, &pp.hdr, 4 + 8 * pp.nVertex, SQLITE_TRANSIENT);
        sqlite3_free(pp);
    }
}

const GEOPOLY_PI: f64 = 3.1415926535897932385;

fn geopolySine(rIn: f64) f64 {
    var r = rIn;
    if (r >= 1.5 * GEOPOLY_PI) {
        r -= 2.0 * GEOPOLY_PI;
    }
    if (r >= 0.5 * GEOPOLY_PI) {
        return -geopolySine(r - GEOPOLY_PI);
    } else {
        const r2 = r * r;
        const r3 = r2 * r;
        const r5 = r3 * r2;
        return 0.9996949 * r - 0.1656700 * r3 + 0.0075134 * r5;
    }
}

fn geopolyRegularFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const av = argv.?;
    const x = sqlite3_value_double(av[0]);
    const y = sqlite3_value_double(av[1]);
    const r = sqlite3_value_double(av[2]);
    var n = sqlite3_value_int(av[3]);

    if (n < 3 or r <= 0.0) return;
    if (n > 1000) n = 1000;
    const p: ?*GeoPoly = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(GeoPoly) + @as(usize, @intCast(n - 1)) * 2 * @sizeOf(GeoCoord))));
    if (p == null) {
        sqlite3_result_error_nomem(context);
        return;
    }
    const pp = p.?;
    var iv: c_int = 1;
    pp.hdr[0] = @as([*]u8, @ptrCast(&iv))[0];
    pp.hdr[1] = 0;
    pp.hdr[2] = @truncate(@as(u32, @bitCast(n >> 8)) & 0xff);
    pp.hdr[3] = @truncate(@as(u32, @bitCast(n)) & 0xff);
    iv = 0;
    while (iv < n) : (iv += 1) {
        const rAngle = 2.0 * GEOPOLY_PI * @as(f64, @floatFromInt(iv)) / @as(f64, @floatFromInt(n));
        setGeoX(pp, @intCast(iv), @floatCast(x - r * geopolySine(rAngle - 0.5 * GEOPOLY_PI)));
        setGeoY(pp, @intCast(iv), @floatCast(y + r * geopolySine(rAngle)));
    }
    sqlite3_result_blob(context, &pp.hdr, 4 + 8 * n, SQLITE_TRANSIENT);
    sqlite3_free(pp);
}

fn geopolyBBox(context: ?*sqlite3_context, pPoly: ?*sqlite3_value, aCoord: ?[*]RtreeCoord, pRc: ?*c_int) ?*GeoPoly {
    var pOut: ?*GeoPoly = null;
    var p: ?*GeoPoly = null;
    var mnX: f32 = undefined;
    var mxX: f32 = undefined;
    var mnY: f32 = undefined;
    var mxY: f32 = undefined;
    var doFill = false;
    if (pPoly == null and aCoord != null) {
        p = null;
        mnX = aCoord.?[0].f;
        mxX = aCoord.?[1].f;
        mnY = aCoord.?[2].f;
        mxY = aCoord.?[3].f;
        doFill = true;
    } else {
        p = geopolyFuncParam(context, pPoly, pRc);
    }
    if (!doFill) {
        if (p) |pp| {
            mnX = geoX(pp, 0);
            mxX = mnX;
            mnY = geoY(pp, 0);
            mxY = mnY;
            var ii: usize = 1;
            while (ii < @as(usize, @intCast(pp.nVertex))) : (ii += 1) {
                var rr: f64 = geoX(pp, ii);
                if (rr < mnX) {
                    mnX = @floatCast(rr);
                } else if (rr > mxX) {
                    mxX = @floatCast(rr);
                }
                rr = geoY(pp, ii);
                if (rr < mnY) {
                    mnY = @floatCast(rr);
                } else if (rr > mxY) {
                    mxY = @floatCast(rr);
                }
            }
            if (pRc) |pr| pr.* = SQLITE_OK;
            if (aCoord == null) {
                doFill = true;
            } else {
                sqlite3_free(pp);
                aCoord.?[0].f = mnX;
                aCoord.?[1].f = mxX;
                aCoord.?[2].f = mnY;
                aCoord.?[3].f = mxY;
            }
        } else if (aCoord != null) {
            @memset(@as([*]u8, @ptrCast(aCoord.?))[0 .. @sizeOf(RtreeCoord) * 4], 0);
        }
    }
    if (doFill) {
        pOut = @ptrCast(@alignCast(sqlite3_realloc64(p, geopolySz(4))));
        if (pOut == null) {
            sqlite3_free(p);
            if (context != null) sqlite3_result_error_nomem(context);
            if (pRc) |pr| pr.* = SQLITE_NOMEM;
            return null;
        }
        const po = pOut.?;
        po.nVertex = 4;
        var iv: c_int = 1;
        po.hdr[0] = @as([*]u8, @ptrCast(&iv))[0];
        po.hdr[1] = 0;
        po.hdr[2] = 0;
        po.hdr[3] = 4;
        setGeoX(po, 0, mnX);
        setGeoY(po, 0, mnY);
        setGeoX(po, 1, mxX);
        setGeoY(po, 1, mnY);
        setGeoX(po, 2, mxX);
        setGeoY(po, 2, mxY);
        setGeoX(po, 3, mnX);
        setGeoY(po, 3, mxY);
    }
    return pOut;
}

fn geopolyBBoxFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const p = geopolyBBox(context, argv.?[0], null, null);
    if (p) |pp| {
        sqlite3_result_blob(context, &pp.hdr, 4 + 8 * pp.nVertex, SQLITE_TRANSIENT);
        sqlite3_free(pp);
    }
}

const GeoBBox = extern struct {
    isInit: c_int,
    a: [4]RtreeCoord,
};

fn geopolyBBoxStep(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    var a: [4]RtreeCoord = undefined;
    var rc: c_int = SQLITE_OK;
    _ = geopolyBBox(context, argv.?[0], &a, &rc);
    if (rc == SQLITE_OK) {
        const pBBox: ?*GeoBBox = @ptrCast(@alignCast(sqlite3_aggregate_context(context, @sizeOf(GeoBBox))));
        if (pBBox == null) return;
        const pb = pBBox.?;
        if (pb.isInit == 0) {
            pb.isInit = 1;
            @memcpy(@as([*]u8, @ptrCast(&pb.a))[0 .. @sizeOf(RtreeCoord) * 4], @as([*]const u8, @ptrCast(&a))[0 .. @sizeOf(RtreeCoord) * 4]);
        } else {
            if (a[0].f < pb.a[0].f) pb.a[0] = a[0];
            if (a[1].f > pb.a[1].f) pb.a[1] = a[1];
            if (a[2].f < pb.a[2].f) pb.a[2] = a[2];
            if (a[3].f > pb.a[3].f) pb.a[3] = a[3];
        }
    }
}
fn geopolyBBoxFinal(context: ?*sqlite3_context) callconv(.c) void {
    const pBBox: ?*GeoBBox = @ptrCast(@alignCast(sqlite3_aggregate_context(context, 0)));
    if (pBBox == null) return;
    const p = geopolyBBox(context, null, &pBBox.?.a, null);
    if (p) |pp| {
        sqlite3_result_blob(context, &pp.hdr, 4 + 8 * pp.nVertex, SQLITE_TRANSIENT);
        sqlite3_free(pp);
    }
}

fn pointBeneathLine(x0: f64, y0: f64, x1: f64, y1: f64, x2: f64, y2: f64) c_int {
    if (x0 == x1 and y0 == y1) return 2;
    if (x1 < x2) {
        if (x0 <= x1 or x0 > x2) return 0;
    } else if (x1 > x2) {
        if (x0 <= x2 or x0 > x1) return 0;
    } else {
        if (x0 != x1) return 0;
        if (y0 < y1 and y0 < y2) return 0;
        if (y0 > y1 and y0 > y2) return 0;
        return 2;
    }
    const y = y1 + (y2 - y1) * (x0 - x1) / (x2 - x1);
    if (y0 == y) return 2;
    if (y0 < y) return 1;
    return 0;
}

fn geopolyContainsPointFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const av = argv.?;
    const p1 = geopolyFuncParam(context, av[0], null);
    const x0 = sqlite3_value_double(av[1]);
    const y0 = sqlite3_value_double(av[2]);
    var v: c_int = 0;
    var cnt: c_int = 0;
    if (p1 == null) return;
    const pp = p1.?;
    var ii: usize = 0;
    const last: usize = @intCast(pp.nVertex - 1);
    while (ii < last) : (ii += 1) {
        v = pointBeneathLine(x0, y0, geoX(pp, ii), geoY(pp, ii), geoX(pp, ii + 1), geoY(pp, ii + 1));
        if (v == 2) break;
        cnt += v;
    }
    if (v != 2) {
        v = pointBeneathLine(x0, y0, geoX(pp, ii), geoY(pp, ii), geoX(pp, 0), geoY(pp, 0));
    }
    if (v == 2) {
        sqlite3_result_int(context, 1);
    } else if (((v + cnt) & 1) == 0) {
        sqlite3_result_int(context, 0);
    } else {
        sqlite3_result_int(context, 2);
    }
    sqlite3_free(pp);
}

const GeoEvent = extern struct {
    x: f64,
    eType: c_int,
    pSeg: ?*GeoSegment,
    pNext: ?*GeoEvent,
};
const GeoSegment = extern struct {
    C: f64,
    B: f64,
    y: f64,
    y0: f32,
    side: u8,
    idx: c_uint,
    pNext: ?*GeoSegment,
};
const GeoOverlap = extern struct {
    aEvent: ?[*]GeoEvent,
    aSegment: ?[*]GeoSegment,
    nEvent: c_int,
    nSegment: c_int,
};

fn geopolyAddOneSegment(p: *GeoOverlap, x0in: GeoCoord, y0in: GeoCoord, x1in: GeoCoord, y1in: GeoCoord, side: u8, idx: c_uint) void {
    var x0 = x0in;
    var y0 = y0in;
    var x1 = x1in;
    var y1 = y1in;
    if (x0 == x1) return;
    if (x0 > x1) {
        const t = x0;
        x0 = x1;
        x1 = t;
        const t2 = y0;
        y0 = y1;
        y1 = t2;
    }
    const pSeg = &p.aSegment.?[@intCast(p.nSegment)];
    p.nSegment += 1;
    pSeg.C = (@as(f64, y1) - y0) / (@as(f64, x1) - x0);
    pSeg.B = @as(f64, y1) - @as(f64, x1) * pSeg.C;
    pSeg.y0 = y0;
    pSeg.side = side;
    pSeg.idx = idx;
    var pEvent = &p.aEvent.?[@intCast(p.nEvent)];
    p.nEvent += 1;
    pEvent.x = x0;
    pEvent.eType = 0;
    pEvent.pSeg = pSeg;
    pEvent = &p.aEvent.?[@intCast(p.nEvent)];
    p.nEvent += 1;
    pEvent.x = x1;
    pEvent.eType = 1;
    pEvent.pSeg = pSeg;
}

fn geopolyAddSegments(p: *GeoOverlap, pPoly: *GeoPoly, side: u8) void {
    const coords = geoCoordPtr(pPoly);
    var i: usize = 0;
    const last: usize = @intCast(pPoly.nVertex - 1);
    while (i < last) : (i += 1) {
        const x = coords + i * 2;
        geopolyAddOneSegment(p, x[0], x[1], x[2], x[3], side, @intCast(i));
    }
    const x = coords + i * 2;
    geopolyAddOneSegment(p, x[0], x[1], coords[0], coords[1], side, @intCast(i));
}

fn geopolyEventMerge(pLeftIn: ?*GeoEvent, pRightIn: ?*GeoEvent) ?*GeoEvent {
    var head: GeoEvent = undefined;
    head.pNext = null;
    var pLast = &head;
    var pLeft = pLeftIn;
    var pRight = pRightIn;
    while (pRight != null and pLeft != null) {
        if (pRight.?.x <= pLeft.?.x) {
            pLast.pNext = pRight;
            pLast = pRight.?;
            pRight = pRight.?.pNext;
        } else {
            pLast.pNext = pLeft;
            pLast = pLeft.?;
            pLeft = pLeft.?.pNext;
        }
    }
    pLast.pNext = if (pRight != null) pRight else pLeft;
    return head.pNext;
}

fn geopolySortEventsByX(aEvent: [*]GeoEvent, nEvent: c_int) ?*GeoEvent {
    var mx: usize = 0;
    var a: [50]?*GeoEvent = undefined;
    var i: usize = 0;
    while (i < @as(usize, @intCast(nEvent))) : (i += 1) {
        var p: ?*GeoEvent = &aEvent[i];
        p.?.pNext = null;
        var j: usize = 0;
        while (j < mx and a[j] != null) : (j += 1) {
            p = geopolyEventMerge(a[j], p);
            a[j] = null;
        }
        a[j] = p;
        if (j >= mx) mx = j + 1;
    }
    var p: ?*GeoEvent = null;
    i = 0;
    while (i < mx) : (i += 1) {
        p = geopolyEventMerge(a[i], p);
    }
    return p;
}

fn geopolySegmentMerge(pLeftIn: ?*GeoSegment, pRightIn: ?*GeoSegment) ?*GeoSegment {
    var head: GeoSegment = undefined;
    head.pNext = null;
    var pLast = &head;
    var pLeft = pLeftIn;
    var pRight = pRightIn;
    while (pRight != null and pLeft != null) {
        var r = pRight.?.y - pLeft.?.y;
        if (r == 0.0) r = pRight.?.C - pLeft.?.C;
        if (r < 0.0) {
            pLast.pNext = pRight;
            pLast = pRight.?;
            pRight = pRight.?.pNext;
        } else {
            pLast.pNext = pLeft;
            pLast = pLeft.?;
            pLeft = pLeft.?.pNext;
        }
    }
    pLast.pNext = if (pRight != null) pRight else pLeft;
    return head.pNext;
}

fn geopolySortSegmentsByYAndC(pListIn: ?*GeoSegment) ?*GeoSegment {
    var mx: usize = 0;
    var a: [50]?*GeoSegment = undefined;
    var pList = pListIn;
    while (pList) |pl| {
        var p: ?*GeoSegment = pl;
        pList = pl.pNext;
        p.?.pNext = null;
        var i: usize = 0;
        while (i < mx and a[i] != null) : (i += 1) {
            p = geopolySegmentMerge(a[i], p);
            a[i] = null;
        }
        a[i] = p;
        if (i >= mx) mx = i + 1;
    }
    var p: ?*GeoSegment = null;
    var i: usize = 0;
    while (i < mx) : (i += 1) {
        p = geopolySegmentMerge(a[i], p);
    }
    return p;
}

fn geopolyOverlap(p1: *GeoPoly, p2: *GeoPoly) c_int {
    const nVertex: i64 = @as(i64, p1.nVertex) + p2.nVertex + 2;
    var rc: c_int = 0;
    var needSort: c_int = 0;
    var pActive: ?*GeoSegment = null;
    var pSeg: ?*GeoSegment = null;
    var aOverlap: [4]u8 = undefined;

    const nByte: usize = @intCast(@as(i64, @sizeOf(GeoEvent)) * nVertex * 2 + @as(i64, @sizeOf(GeoSegment)) * nVertex + @sizeOf(GeoOverlap));
    const pOpt: ?*GeoOverlap = @ptrCast(@alignCast(sqlite3_malloc64(nByte)));
    if (pOpt == null) return -1;
    const p = pOpt.?;
    p.aEvent = @ptrCast(@alignCast(@as([*]u8, @ptrCast(p)) + @sizeOf(GeoOverlap)));
    p.aSegment = @ptrCast(@alignCast(&p.aEvent.?[@intCast(nVertex * 2)]));
    p.nEvent = 0;
    p.nSegment = 0;
    geopolyAddSegments(p, p1, 1);
    geopolyAddSegments(p, p2, 2);
    var pThisEvent = geopolySortEventsByX(p.aEvent.?, p.nEvent);
    var rX: f64 = if (pThisEvent != null and pThisEvent.?.x == 0.0) -1.0 else 0.0;
    @memset(&aOverlap, 0);
    while (pThisEvent) |pte| {
        if (pte.x != rX) {
            var pPrev: ?*GeoSegment = null;
            var iMask: usize = 0;
            rX = pte.x;
            if (needSort != 0) {
                pActive = geopolySortSegmentsByYAndC(pActive);
                needSort = 0;
            }
            pSeg = pActive;
            while (pSeg) |ps| {
                if (pPrev) |pp| {
                    if (pp.y != ps.y) {
                        aOverlap[iMask] = 1;
                    }
                }
                iMask ^= ps.side;
                pPrev = ps;
                pSeg = ps.pNext;
            }
            pPrev = null;
            pSeg = pActive;
            while (pSeg) |ps| {
                const y = ps.C * rX + ps.B;
                ps.y = y;
                if (pPrev) |pp| {
                    if (pp.y > ps.y and pp.side != ps.side) {
                        rc = 1;
                        sqlite3_free(p);
                        return rc;
                    } else if (pp.y != ps.y) {
                        aOverlap[iMask] = 1;
                    }
                }
                iMask ^= ps.side;
                pPrev = ps;
                pSeg = ps.pNext;
            }
        }
        if (pte.eType == 0) {
            const ps = pte.pSeg.?;
            ps.y = ps.y0;
            ps.pNext = pActive;
            pActive = ps;
            needSort = 1;
        } else {
            if (pActive == pte.pSeg) {
                pActive = if (pActive != null) pActive.?.pNext else null;
            } else {
                pSeg = pActive;
                while (pSeg) |ps| {
                    if (ps.pNext == pte.pSeg) {
                        ps.pNext = if (ps.pNext != null) ps.pNext.?.pNext else null;
                        break;
                    }
                    pSeg = ps.pNext;
                }
            }
        }
        pThisEvent = pte.pNext;
    }
    if (aOverlap[3] == 0) {
        rc = 0;
    } else if (aOverlap[1] != 0 and aOverlap[2] == 0) {
        rc = 3;
    } else if (aOverlap[1] == 0 and aOverlap[2] != 0) {
        rc = 2;
    } else if (aOverlap[1] == 0 and aOverlap[2] == 0) {
        rc = 4;
    } else {
        rc = 1;
    }

    sqlite3_free(p);
    return rc;
}

fn geopolyWithinFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const p1 = geopolyFuncParam(context, argv.?[0], null);
    const p2 = geopolyFuncParam(context, argv.?[1], null);
    if (p1 != null and p2 != null) {
        const x = geopolyOverlap(p1.?, p2.?);
        if (x < 0) {
            sqlite3_result_error_nomem(context);
        } else {
            sqlite3_result_int(context, if (x == 2) 1 else if (x == 4) @as(c_int, 2) else 0);
        }
    }
    sqlite3_free(p1);
    sqlite3_free(p2);
}

fn geopolyOverlapFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = argc;
    const p1 = geopolyFuncParam(context, argv.?[0], null);
    const p2 = geopolyFuncParam(context, argv.?[1], null);
    if (p1 != null and p2 != null) {
        const x = geopolyOverlap(p1.?, p2.?);
        if (x < 0) {
            sqlite3_result_error_nomem(context);
        } else {
            sqlite3_result_int(context, x);
        }
    }
    sqlite3_free(p1);
    sqlite3_free(p2);
}

fn geopolyDebugFunc(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = context;
    _ = argc;
    _ = argv;
}

fn geopolyInit(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argvOpt: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8, isCreate: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    _ = pAux;
    const argv = argvOpt.?;

    if (argc >= RTREE_MAX_AUX_COLUMN + 4) {
        pzErr.* = sqlite3_mprintf("Too many columns for a geopoly table");
        return SQLITE_ERROR;
    }

    _ = sqlite3_vtab_config(db, SQLITE_VTAB_CONSTRAINT_SUPPORT, @as(c_int, 1));
    _ = sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);

    const nDb = strlen0(argv[1].?);
    const nName = strlen0(argv[2].?);
    const allocSz = @sizeOf(Rtree) + nDb + nName * 2 + 8;
    const pRtreeOpt: ?*Rtree = @ptrCast(@alignCast(sqlite3_malloc64(allocSz)));
    if (pRtreeOpt == null) return SQLITE_NOMEM;
    const pRtree = pRtreeOpt.?;
    @memset(@as([*]u8, @ptrCast(pRtree))[0..allocSz], 0);
    pRtree.nBusy = 1;
    pRtree.base.pModule = &rtreeModule;
    const tail: [*]u8 = @as([*]u8, @ptrCast(pRtree)) + @sizeOf(Rtree);
    pRtree.zDb = @ptrCast(tail);
    pRtree.zName = @ptrCast(tail + nDb + 1);
    pRtree.zNodeName = @ptrCast(tail + nDb + 1 + nName + 1);
    pRtree.eCoordType = RTREE_COORD_REAL32;
    pRtree.nDim = 2;
    pRtree.nDim2 = 4;
    @memcpy(pRtree.zDb.?[0..nDb], argv[1].?[0..nDb]);
    @memcpy(pRtree.zName.?[0..nName], argv[2].?[0..nName]);
    @memcpy(pRtree.zNodeName.?[0..nName], argv[2].?[0..nName]);
    @memcpy(pRtree.zNodeName.?[nName .. nName + 6], "_node\x00");

    const pSql = sqlite3_str_new(db);
    sqlite3_str_appendf(pSql, "CREATE TABLE x(_shape");
    pRtree.nAux = 1;
    pRtree.nAuxNotNull = 1;
    var ii: c_int = 3;
    while (ii < argc) : (ii += 1) {
        pRtree.nAux += 1;
        sqlite3_str_appendf(pSql, ",%s", argv[@intCast(ii)].?);
    }
    sqlite3_str_appendf(pSql, ");");
    const zSql = sqlite3_str_finish(pSql);
    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else {
        rc = sqlite3_declare_vtab(db, zSql.?);
        if (rc != SQLITE_OK) {
            pzErr.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
        }
    }
    sqlite3_free(zSql);
    if (rc != 0) return rtreeInitFail(pRtree, ppVtab, rc);
    pRtree.nBytesPerCell = @intCast(8 + @as(c_int, pRtree.nDim2) * 4);

    rc = getNodeSize(db, pRtree, isCreate, pzErr);
    if (rc != 0) return rtreeInitFail(pRtree, ppVtab, rc);
    rc = rtreeSqlInit(pRtree, db, argv[1].?, argv[2].?, isCreate);
    if (rc != 0) {
        pzErr.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
        return rtreeInitFail(pRtree, ppVtab, rc);
    }

    ppVtab.* = @ptrCast(pRtree);
    return SQLITE_OK;
}

fn geopolyCreate(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return geopolyInit(db, pAux, argc, argv, ppVtab, pzErr, 1);
}
fn geopolyConnect(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return geopolyInit(db, pAux, argc, argv, ppVtab, pzErr, 0);
}

fn geopolyFilter(pVtabCursor: *sqlite3_vtab_cursor, idxNum: c_int, idxStr: ?[*:0]const u8, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtabCursor.pVtab.?));
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(pVtabCursor));
    var pRoot: ?*RtreeNode = null;
    var rc: c_int = SQLITE_OK;
    var iCell: c_int = 0;
    _ = idxStr;
    _ = argc;

    rtreeReference(pRtree);
    resetCursor(pCsr);
    pCsr.iStrategy = idxNum;
    if (idxNum == 1) {
        var pLeaf: ?*RtreeNode = undefined;
        const iRowid = sqlite3_value_int64(argv.?[0]);
        var iNode: i64 = 0;
        rc = findLeafNode(pRtree, iRowid, &pLeaf, &iNode);
        if (rc == SQLITE_OK and pLeaf != null) {
            const p = rtreeSearchPointNew(pCsr, RTREE_ZERO, 0).?;
            pCsr.aNode[0] = pLeaf;
            p.id = iNode;
            p.eWithin = PARTLY_WITHIN;
            rc = nodeRowidIndex(pRtree, pLeaf.?, iRowid, &iCell);
            p.iCell = @intCast(iCell);
        } else {
            pCsr.atEOF = 1;
        }
    } else {
        rc = nodeAcquire(pRtree, 1, null, &pRoot);
        if (rc == SQLITE_OK and idxNum <= 3) {
            var bbox: [4]RtreeCoord = undefined;
            _ = geopolyBBox(null, argv.?[0], &bbox, &rc);
            if (rc != 0) {
                _ = nodeRelease(pRtree, pRoot);
                rtreeRelease(pRtree);
                return rc;
            }
            const ac: ?[*]RtreeConstraint = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(RtreeConstraint) * 4)));
            pCsr.aConstraint = ac;
            pCsr.nConstraint = 4;
            if (ac == null) {
                rc = SQLITE_NOMEM;
            } else {
                @memset(@as([*]u8, @ptrCast(ac.?))[0 .. @sizeOf(RtreeConstraint) * 4], 0);
                @memset(@as([*]u8, @ptrCast(&pCsr.anQueue))[0 .. @sizeOf(u32) * @as(usize, @intCast(pRtree.iDepth + 1))], 0);
                if (idxNum == 2) {
                    ac.?[0].op = 'B';
                    ac.?[0].iCoord = 0;
                    ac.?[0].u.rValue = bbox[1].f;
                    ac.?[1].op = 'D';
                    ac.?[1].iCoord = 1;
                    ac.?[1].u.rValue = bbox[0].f;
                    ac.?[2].op = 'B';
                    ac.?[2].iCoord = 2;
                    ac.?[2].u.rValue = bbox[3].f;
                    ac.?[3].op = 'D';
                    ac.?[3].iCoord = 3;
                    ac.?[3].u.rValue = bbox[2].f;
                } else {
                    ac.?[0].op = 'D';
                    ac.?[0].iCoord = 0;
                    ac.?[0].u.rValue = bbox[0].f;
                    ac.?[1].op = 'B';
                    ac.?[1].iCoord = 1;
                    ac.?[1].u.rValue = bbox[1].f;
                    ac.?[2].op = 'D';
                    ac.?[2].iCoord = 2;
                    ac.?[2].u.rValue = bbox[2].f;
                    ac.?[3].op = 'B';
                    ac.?[3].iCoord = 3;
                    ac.?[3].u.rValue = bbox[3].f;
                }
            }
        }
        if (rc == SQLITE_OK) {
            const pNew = rtreeSearchPointNew(pCsr, RTREE_ZERO, @intCast(pRtree.iDepth + 1));
            if (pNew == null) {
                rc = SQLITE_NOMEM;
                _ = nodeRelease(pRtree, pRoot);
                rtreeRelease(pRtree);
                return rc;
            }
            pNew.?.id = 1;
            pNew.?.iCell = 0;
            pNew.?.eWithin = PARTLY_WITHIN;
            pCsr.aNode[0] = pRoot;
            pRoot = null;
            rc = rtreeStepToLeaf(pCsr);
        }
    }

    _ = nodeRelease(pRtree, pRoot);
    rtreeRelease(pRtree);
    return rc;
}

fn geopolyBestIndex(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    var iRowidTerm: c_int = -1;
    var iFuncTerm: c_int = -1;
    var idxNum: c_int = 0;
    _ = tab;
    const aCon = pIdxInfo.aConstraint.?;
    const aUse = pIdxInfo.aConstraintUsage.?;

    var ii: c_int = 0;
    while (ii < pIdxInfo.nConstraint) : (ii += 1) {
        const p = &aCon[@intCast(ii)];
        if (p.usable == 0) continue;
        if (p.iColumn < 0 and p.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            iRowidTerm = ii;
            break;
        }
        if (p.iColumn == 0 and p.op >= SQLITE_INDEX_CONSTRAINT_FUNCTION) {
            iFuncTerm = ii;
            idxNum = @as(c_int, p.op) - SQLITE_INDEX_CONSTRAINT_FUNCTION + 2;
        }
    }

    if (iRowidTerm >= 0) {
        pIdxInfo.idxNum = 1;
        pIdxInfo.idxStr = @constCast("rowid");
        aUse[@intCast(iRowidTerm)].argvIndex = 1;
        aUse[@intCast(iRowidTerm)].omit = 1;
        pIdxInfo.estimatedCost = 30.0;
        pIdxInfo.estimatedRows = 1;
        pIdxInfo.idxFlags = SQLITE_INDEX_SCAN_UNIQUE;
        return SQLITE_OK;
    }
    if (iFuncTerm >= 0) {
        pIdxInfo.idxNum = idxNum;
        pIdxInfo.idxStr = @constCast("rtree");
        aUse[@intCast(iFuncTerm)].argvIndex = 1;
        aUse[@intCast(iFuncTerm)].omit = 0;
        pIdxInfo.estimatedCost = 300.0;
        pIdxInfo.estimatedRows = 10;
        return SQLITE_OK;
    }
    pIdxInfo.idxNum = 4;
    pIdxInfo.idxStr = @constCast("fullscan");
    pIdxInfo.estimatedCost = 3000000.0;
    pIdxInfo.estimatedRows = 100000;
    return SQLITE_OK;
}

fn geopolyColumn(cur: *sqlite3_vtab_cursor, ctx: ?*sqlite3_context, i: c_int) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(cur.pVtab.?));
    const pCsr: *RtreeCursor = @ptrCast(@alignCast(cur));
    const p = rtreeSearchPointFirst(pCsr);
    var rc: c_int = SQLITE_OK;
    const pNode = rtreeNodeOfFirstSearchPoint(pCsr, &rc);

    if (rc != 0) return rc;
    if (p == null) return SQLITE_OK;
    if (i == 0 and sqlite3_vtab_nochange(ctx) != 0) return SQLITE_OK;
    if (i <= pRtree.nAux) {
        if (pCsr.bAuxValid == 0) {
            if (pCsr.pReadAux == null) {
                rc = sqlite3_prepare_v3(pRtree.db, pRtree.zReadAuxSql.?, -1, 0, &pCsr.pReadAux, null);
                if (rc != 0) return rc;
            }
            _ = sqlite3_bind_int64(pCsr.pReadAux, 1, nodeGetRowid(pRtree, pNode.?, p.?.iCell));
            rc = sqlite3_step(pCsr.pReadAux);
            if (rc == SQLITE_ROW) {
                pCsr.bAuxValid = 1;
            } else {
                _ = sqlite3_reset(pCsr.pReadAux);
                if (rc == SQLITE_DONE) rc = SQLITE_OK;
                return rc;
            }
        }
        sqlite3_result_value(ctx, sqlite3_column_value(pCsr.pReadAux, i + 2));
    }
    return SQLITE_OK;
}

fn geopolyUpdate(pVtab: *sqlite3_vtab, nData: c_int, aData: ?[*]?*sqlite3_value, pRowid: *i64) callconv(.c) c_int {
    const pRtree: *Rtree = @ptrCast(@alignCast(pVtab));
    var rc: c_int = SQLITE_OK;
    var cell: RtreeCell = undefined;
    var coordChange: c_int = 0;
    const av = aData.?;

    if (pRtree.nNodeRef != 0) {
        return SQLITE_LOCKED_VTAB;
    }
    rtreeReference(pRtree);

    const oldRowidValid: c_int = @intFromBool(sqlite3_value_type(av[0]) != SQLITE_NULL);
    const oldRowid: i64 = if (oldRowidValid != 0) sqlite3_value_int64(av[0]) else 0;
    const newRowidValid: c_int = @intFromBool(nData > 1 and sqlite3_value_type(av[1]) != SQLITE_NULL);
    const newRowid: i64 = if (newRowidValid != 0) sqlite3_value_int64(av[1]) else 0;
    cell.iRowid = newRowid;

    if (nData > 1 and (oldRowidValid == 0 or sqlite3_value_nochange(av[2]) == 0 or oldRowid != newRowid)) {
        _ = geopolyBBox(null, av[2], &cell.aCoord, &rc);
        if (rc != 0) {
            if (rc == SQLITE_ERROR) {
                pVtab.zErrMsg = sqlite3_mprintf("_shape does not contain a valid polygon");
            }
            rtreeRelease(pRtree);
            return rc;
        }
        coordChange = 1;

        if (newRowidValid != 0 and (oldRowidValid == 0 or oldRowid != newRowid)) {
            _ = sqlite3_bind_int64(pRtree.pReadRowid, 1, cell.iRowid);
            const steprc = sqlite3_step(pRtree.pReadRowid);
            rc = sqlite3_reset(pRtree.pReadRowid);
            if (steprc == SQLITE_ROW) {
                if (sqlite3_vtab_on_conflict(pRtree.db) == SQLITE_REPLACE) {
                    rc = rtreeDeleteRowid(pRtree, cell.iRowid);
                } else {
                    rc = rtreeConstraintError(pRtree, 0);
                }
            }
        }
    }

    if (rc == SQLITE_OK and (nData == 1 or (coordChange != 0 and oldRowidValid != 0))) {
        rc = rtreeDeleteRowid(pRtree, oldRowid);
    }

    if (rc == SQLITE_OK and nData > 1 and coordChange != 0) {
        var pLeaf: ?*RtreeNode = null;
        if (newRowidValid == 0) {
            rc = rtreeNewRowid(pRtree, &cell.iRowid);
        }
        pRowid.* = cell.iRowid;
        if (rc == SQLITE_OK) {
            rc = chooseLeaf(pRtree, &cell, 0, &pLeaf);
        }
        if (rc == SQLITE_OK) {
            rc = rtreeInsertCell(pRtree, pLeaf.?, &cell, 0);
            const rc2 = nodeRelease(pRtree, pLeaf);
            if (rc == SQLITE_OK) rc = rc2;
        }
    }

    if (rc == SQLITE_OK and nData > 1) {
        const pUp = pRtree.pWriteAux;
        var nChange: c_int = 0;
        _ = sqlite3_bind_int64(pUp, 1, cell.iRowid);
        if (sqlite3_value_nochange(av[2]) != 0) {
            _ = sqlite3_bind_null(pUp, 2);
        } else {
            var pgon: ?*GeoPoly = null;
            if (sqlite3_value_type(av[2]) == SQLITE_TEXT) {
                pgon = geopolyFuncParam(null, av[2], &rc);
            }
            if (pgon != null and rc == SQLITE_OK) {
                _ = sqlite3_bind_blob(pUp, 2, &pgon.?.hdr, 4 + 8 * pgon.?.nVertex, SQLITE_TRANSIENT);
            } else {
                _ = sqlite3_bind_value(pUp, 2, av[2]);
            }
            sqlite3_free(pgon);
            nChange = 1;
        }
        var jj: c_int = 1;
        while (jj < nData - 2) : (jj += 1) {
            nChange += 1;
            _ = sqlite3_bind_value(pUp, jj + 2, av[@intCast(jj + 2)]);
        }
        if (nChange != 0) {
            _ = sqlite3_step(pUp);
            rc = sqlite3_reset(pUp);
        }
    }

    rtreeRelease(pRtree);
    return rc;
}

fn geopolyFindFunction(pVtab: *sqlite3_vtab, nArg: c_int, zName: [*:0]const u8, pxFunc: *XFunc, ppArg: *?*anyopaque) callconv(.c) c_int {
    _ = pVtab;
    _ = nArg;
    if (sqlite3_stricmp(zName, "geopoly_overlap") == 0) {
        pxFunc.* = &geopolyOverlapFunc;
        ppArg.* = null;
        return SQLITE_INDEX_CONSTRAINT_FUNCTION;
    }
    if (sqlite3_stricmp(zName, "geopoly_within") == 0) {
        pxFunc.* = &geopolyWithinFunc;
        ppArg.* = null;
        return SQLITE_INDEX_CONSTRAINT_FUNCTION + 1;
    }
    return 0;
}

const geopolyModule: sqlite3_module = .{
    .iVersion = 3,
    .xCreate = &geopolyCreate,
    .xConnect = &geopolyConnect,
    .xBestIndex = &geopolyBestIndex,
    .xDisconnect = &rtreeDisconnect,
    .xDestroy = &rtreeDestroy,
    .xOpen = &rtreeOpen,
    .xClose = &rtreeClose,
    .xFilter = &geopolyFilter,
    .xNext = &rtreeNext,
    .xEof = &rtreeEof,
    .xColumn = &geopolyColumn,
    .xRowid = &rtreeRowid,
    .xUpdate = &geopolyUpdate,
    .xBegin = &rtreeBeginTransaction,
    .xSync = &rtreeEndTransaction,
    .xCommit = &rtreeEndTransaction,
    .xRollback = &rtreeEndTransaction,
    .xFindFunction = &geopolyFindFunction,
    .xRename = &rtreeRename,
    .xSavepoint = &rtreeSavepoint,
    .xRelease = null,
    .xRollbackTo = null,
    .xShadowName = &rtreeShadowName,
    .xIntegrity = &rtreeIntegrity,
};

fn sqlite3_geopoly_init(db: ?*sqlite3) c_int {
    var rc: c_int = SQLITE_OK;
    const AggFunc = struct {
        xFunc: XFunc,
        nArg: i8,
        bPure: u8,
        zName: [*:0]const u8,
    };
    const aFunc = [_]AggFunc{
        .{ .xFunc = &geopolyAreaFunc, .nArg = 1, .bPure = 1, .zName = "geopoly_area" },
        .{ .xFunc = &geopolyBlobFunc, .nArg = 1, .bPure = 1, .zName = "geopoly_blob" },
        .{ .xFunc = &geopolyJsonFunc, .nArg = 1, .bPure = 1, .zName = "geopoly_json" },
        .{ .xFunc = &geopolySvgFunc, .nArg = -1, .bPure = 1, .zName = "geopoly_svg" },
        .{ .xFunc = &geopolyWithinFunc, .nArg = 2, .bPure = 1, .zName = "geopoly_within" },
        .{ .xFunc = &geopolyContainsPointFunc, .nArg = 3, .bPure = 1, .zName = "geopoly_contains_point" },
        .{ .xFunc = &geopolyOverlapFunc, .nArg = 2, .bPure = 1, .zName = "geopoly_overlap" },
        .{ .xFunc = &geopolyDebugFunc, .nArg = 1, .bPure = 0, .zName = "geopoly_debug" },
        .{ .xFunc = &geopolyBBoxFunc, .nArg = 1, .bPure = 1, .zName = "geopoly_bbox" },
        .{ .xFunc = &geopolyXformFunc, .nArg = 7, .bPure = 1, .zName = "geopoly_xform" },
        .{ .xFunc = &geopolyRegularFunc, .nArg = 4, .bPure = 1, .zName = "geopoly_regular" },
        .{ .xFunc = &geopolyCcwFunc, .nArg = 1, .bPure = 1, .zName = "geopoly_ccw" },
    };
    const Agg = struct {
        xStep: XStep,
        xFinal: XFinal,
        zName: [*:0]const u8,
    };
    const aAgg = [_]Agg{
        .{ .xStep = &geopolyBBoxStep, .xFinal = &geopolyBBoxFinal, .zName = "geopoly_group_bbox" },
    };
    for (aFunc) |fn_| {
        if (rc != SQLITE_OK) break;
        const enc: c_int = if (fn_.bPure != 0) SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS else SQLITE_UTF8 | SQLITE_DIRECTONLY;
        rc = sqlite3_create_function(db, fn_.zName, fn_.nArg, enc, null, fn_.xFunc, null, null);
    }
    for (aAgg) |ag| {
        if (rc != SQLITE_OK) break;
        rc = sqlite3_create_function(db, ag.zName, 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS, null, null, ag.xStep, ag.xFinal);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_create_module_v2(db, "geopoly", &geopolyModule, null, null);
    }
    return rc;
}

// ===========================================================================
// Registration + public geometry-callback API
// ===========================================================================
export fn sqlite3RtreeInit(db: ?*sqlite3) callconv(.c) c_int {
    const utf8 = SQLITE_UTF8;
    var rc: c_int = undefined;

    rc = sqlite3_create_function(db, "rtreenode", 2, utf8, null, &rtreenode, null, null);
    if (rc == SQLITE_OK) {
        rc = sqlite3_create_function(db, "rtreedepth", 1, utf8, null, &rtreedepth, null, null);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_create_function(db, "rtreecheck", -1, utf8, null, &rtreecheck, null, null);
    }
    if (rc == SQLITE_OK) {
        const c: ?*anyopaque = @ptrFromInt(@as(usize, RTREE_COORD_REAL32));
        rc = sqlite3_create_module_v2(db, "rtree", &rtreeModule, c, null);
    }
    if (rc == SQLITE_OK) {
        const c: ?*anyopaque = @ptrFromInt(@as(usize, RTREE_COORD_INT32));
        rc = sqlite3_create_module_v2(db, "rtree_i32", &rtreeModule, c, null);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_geopoly_init(db);
    }
    return rc;
}

fn rtreeFreeCallback(p: ?*anyopaque) callconv(.c) void {
    const pInfo: *RtreeGeomCallback = @ptrCast(@alignCast(p.?));
    if (pInfo.xDestructor) |xd| xd(pInfo.pContext);
    sqlite3_free(p);
}

fn rtreeMatchArgFree(pArg: ?*anyopaque) callconv(.c) void {
    const p: *RtreeMatchArg = @ptrCast(@alignCast(pArg.?));
    var i: c_int = 0;
    while (i < p.nParam) : (i += 1) {
        sqlite3_value_free(p.apSqlParam.?[@intCast(i)]);
    }
    sqlite3_free(p);
}

fn geomCallback(ctx: ?*sqlite3_context, nArg: c_int, aArg: ?[*]?*sqlite3_value) callconv(.c) void {
    const pGeomCtx: *RtreeGeomCallback = @ptrCast(@alignCast(sqlite3_user_data(ctx).?));
    var memErr: c_int = 0;
    const av = aArg.?;
    const nArgU: usize = @intCast(nArg);

    const nBlob: usize = szRtreeMatchArg(nArgU) + nArgU * @sizeOf(?*anyopaque);
    const pBlobOpt: ?*RtreeMatchArg = @ptrCast(@alignCast(sqlite3_malloc64(nBlob)));
    if (pBlobOpt == null) {
        sqlite3_result_error_nomem(ctx);
    } else {
        const pBlob = pBlobOpt.?;
        pBlob.iSize = @intCast(nBlob);
        pBlob.cb = pGeomCtx.*;
        const ap = aParamPtr(pBlob);
        // apSqlParam sits right after the aParam[nArg] values.
        pBlob.apSqlParam = @ptrCast(@alignCast(ap + nArgU));
        pBlob.nParam = nArg;
        var i: usize = 0;
        while (i < nArgU) : (i += 1) {
            pBlob.apSqlParam.?[i] = sqlite3_value_dup(av[i]);
            if (pBlob.apSqlParam.?[i] == null) memErr = 1;
            ap[i] = sqlite3_value_double(av[i]);
        }
        if (memErr != 0) {
            sqlite3_result_error_nomem(ctx);
            rtreeMatchArgFree(pBlob);
        } else {
            sqlite3_result_pointer(ctx, pBlob, "RtreeMatchArg", &rtreeMatchArgFree);
        }
    }
}

export fn sqlite3_rtree_geometry_callback(
    db: ?*sqlite3,
    zGeom: [*:0]const u8,
    xGeom: XGeom,
    pContext: ?*anyopaque,
) callconv(.c) c_int {
    const pGeomCtxOpt: ?*RtreeGeomCallback = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(RtreeGeomCallback))));
    if (pGeomCtxOpt == null) return SQLITE_NOMEM;
    const pGeomCtx = pGeomCtxOpt.?;
    pGeomCtx.xGeom = xGeom;
    pGeomCtx.xQueryFunc = null;
    pGeomCtx.xDestructor = null;
    pGeomCtx.pContext = pContext;
    return sqlite3_create_function_v2(db, zGeom, -1, SQLITE_ANY, pGeomCtx, &geomCallback, null, null, &rtreeFreeCallback);
}

export fn sqlite3_rtree_query_callback(
    db: ?*sqlite3,
    zQueryFunc: [*:0]const u8,
    xQueryFunc: XQueryFunc,
    pContext: ?*anyopaque,
    xDestructor: ?*const fn (?*anyopaque) callconv(.c) void,
) callconv(.c) c_int {
    const pGeomCtxOpt: ?*RtreeGeomCallback = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(RtreeGeomCallback))));
    if (pGeomCtxOpt == null) {
        if (xDestructor) |xd| xd(pContext);
        return SQLITE_NOMEM;
    }
    const pGeomCtx = pGeomCtxOpt.?;
    pGeomCtx.xGeom = null;
    pGeomCtx.xQueryFunc = xQueryFunc;
    pGeomCtx.xDestructor = xDestructor;
    pGeomCtx.pContext = pContext;
    return sqlite3_create_function_v2(db, zQueryFunc, -1, SQLITE_ANY, pGeomCtx, &geomCallback, null, null, &rtreeFreeCallback);
}

comptime {
    // Keep `builtin` referenced (byte-order is handled explicitly, but the
    // import documents intent and avoids an unused warning).
    _ = &builtin;
}
