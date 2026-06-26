//! Zig port of SQLite's src/json.c — the core JSON1/JSONB extension (the
//! json/jsonb scalar + aggregate SQL functions and the json_each/json_tree/
//! jsonb_each/jsonb_tree eponymous virtual tables).
//!
//! External-linkage (non-static) symbols of json.c — these two are exported:
//!   * sqlite3RegisterJsonFunctions(void)
//!   * sqlite3JsonVtabRegister(sqlite3*, const char*) -> Module*
//! Everything else (the text/JSONB parser, the JsonParse/JsonString/JsonCache
//! machinery, the JSONB binary codec, every json_*/jsonb_* scalar+aggregate
//! impl, and the json_each vtab methods) is file-scope (private here), exactly
//! as in json.c.
//!
//! Configuration assumed (matching BOTH this project's builds):
//!   SQLITE_OMIT_JSON OFF, SQLITE_OMIT_VIRTUALTABLE OFF, SQLITE_OMIT_WINDOWFUNC
//!   OFF, SQLITE_ASCII (not EBCDIC), SQLITE_BUG_COMPATIBLE_20250510 OFF,
//!   SQLITE_LEGACY_JSON_VALID OFF. The SQLITE_DEBUG-only json_parse() SQL
//!   function and its dump helpers are gated on config.sqlite_debug.
//!
//! Struct coupling: NONE of json.c's structs are coupled to a build-divergent
//! core struct — JsonCache/JsonString/JsonParse/JsonPretty/JsonParent/
//! JsonEachCursor/JsonEachConnection/NanInfName are file-internal and are
//! defined here as plain Zig structs with the same field layout. The only ABI
//! structs are the PUBLIC ones (sqlite3_module/vtab/cursor/index_info) plus the
//! FuncDef mirror, copied from carray.zig/func.zig. The one build-divergent
//! field read is sqlite3.mallocFailed (ground-truthed at offset 103).

const std = @import("std");
const config = @import("config");
const L = @import("c_layout.zig");

inline fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L.c, name)) @field(L.c, name) else fallback;
}

// ─── Result / type constants ────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CONSTRAINT: c_int = 19;

const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;
const SQLITE_TEXT: c_int = 3;
const SQLITE_BLOB: c_int = 4;
const SQLITE_NULL: c_int = 5;

const SQLITE_UTF8: c_int = 1;

const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_VTAB_INNOCUOUS: c_int = 2;

const SMALLEST_INT64: i64 = std.math.minInt(i64);

// destructor sentinels
const XDel = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_TRANSIENT: XDel = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const SQLITE_STATIC: XDel = null;

// ─── FuncDef flag constants (from func.zig / sqliteInt.h / sqlite.h.in) ──────
const SQLITE_FUNC_NEEDCOLL: u32 = 0x0020;
const SQLITE_FUNC_CONSTANT: u32 = 0x0800;
const SQLITE_FUNC_RUNONLY: u32 = 0x8000;
const SQLITE_FUNC_BUILTIN: u32 = 0x00800000;
// public flags (sqlite.h.in)
const SQLITE_DETERMINISTIC: u32 = 0x000000800;
const SQLITE_SUBTYPE: u32 = 0x000100000;
const SQLITE_RESULT_SUBTYPE: u32 = 0x001000000;
const SQLITE_UTF8_FLAG: u32 = 1;

// ─── JSONB element types ────────────────────────────────────────────────────
const JSONB_NULL: u8 = 0;
const JSONB_TRUE: u8 = 1;
const JSONB_FALSE: u8 = 2;
const JSONB_INT: u8 = 3;
const JSONB_INT5: u8 = 4;
const JSONB_FLOAT: u8 = 5;
const JSONB_FLOAT5: u8 = 6;
const JSONB_TEXT: u8 = 7;
const JSONB_TEXTJ: u8 = 8;
const JSONB_TEXT5: u8 = 9;
const JSONB_TEXTRAW: u8 = 10;
const JSONB_ARRAY: u8 = 11;
const JSONB_OBJECT: u8 = 12;

const jsonbType = [_][*:0]const u8{
    "null", "true",  "false",  "integer", "integer",
    "real", "real",  "text",   "text",    "text",
    "text", "array", "object", "",        "",
    "",     "",
};

const JSON_CACHE_ID: c_int = -429938;
const JSON_CACHE_SIZE: usize = 4;
const JSON_INVALID_CHAR: u32 = 0x99999;

// JsonString.eErr bits
const JSTRING_OOM: u8 = 0x01;
const JSTRING_MALFORMED: u8 = 0x02;
const JSTRING_TOODEEP: u8 = 0x04;
const JSTRING_ERR: u8 = 0x08;

const JSON_SUBTYPE: c_uint = 74; // 'J'

// sqlite3_user_data() flag bits
const JSON_JSON: c_int = 0x01;
const JSON_SQL: c_int = 0x02;
const JSON_ABPATH: c_int = 0x03;
const JSON_ISSET: c_int = 0x04;
const JSON_AINS: c_int = 0x08;
const JSON_BLOB: c_int = 0x10;

inline fn JSON_INSERT_TYPE(x: c_int) c_int {
    return (x & 0xC) >> 2;
}

// JsonParse.eEdit values
const JEDIT_DEL: u8 = 1;
const JEDIT_REPL: u8 = 2;
const JEDIT_INS: u8 = 3;
const JEDIT_SET: u8 = 4;
const JEDIT_AINS: u8 = 5;

const JSON_MAX_DEPTH: u32 = 1000;

// jsonParseFuncArg flgs
const JSON_EDITABLE: u32 = 0x01;
const JSON_KEEPERROR: u32 = 0x02;

// jsonLookupStep error returns
const JSON_LOOKUP_ERROR: u32 = 0xffffffff;
const JSON_LOOKUP_NOTFOUND: u32 = 0xfffffffe;
const JSON_LOOKUP_NOTARRAY: u32 = 0xfffffffd;
const JSON_LOOKUP_TOODEEP: u32 = 0xfffffffc;
const JSON_LOOKUP_PATHERROR: u32 = 0xfffffffb;
inline fn JSON_LOOKUP_ISERROR(x: u32) bool {
    return x >= JSON_LOOKUP_PATHERROR;
}

// jsonMergePatch return codes
const JSON_MERGE_OK: c_int = 0;
const JSON_MERGE_BADTARGET: c_int = 1;
const JSON_MERGE_BADPATCH: c_int = 2;
const JSON_MERGE_OOM: c_int = 3;
const JSON_MERGE_TOODEEP: c_int = 4;

// json_each column numbers
const JEACH_KEY: c_int = 0;
const JEACH_VALUE: c_int = 1;
const JEACH_TYPE: c_int = 2;
const JEACH_ATOM: c_int = 3;
const JEACH_ID: c_int = 4;
const JEACH_PARENT: c_int = 5;
const JEACH_FULLKEY: c_int = 6;
const JEACH_PATH: c_int = 7;
const JEACH_JSON: c_int = 8;
const JEACH_ROOT: c_int = 9;

// Module-level static blobs whose addresses escape into JsonParse.aBlob
// (json.c declares these `static`).
var aNullBlob = [_]u8{0x00};
var emptyObjectStatic = [_]u8{ JSONB_ARRAY, JSONB_OBJECT };

// ─── ctype table (const data) ───────────────────────────────────────────────
extern const sqlite3CtypeMap: [256]u8;

inline fn isalnum(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x06) != 0;
}
inline fn isalpha(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x02) != 0;
}
inline fn isdigit(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x04) != 0;
}
inline fn isxdigit(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x08) != 0;
}
inline fn jsonId1(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x42) != 0;
}
inline fn jsonId2(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x46) != 0;
}

// ─── Opaque public ABI handles ──────────────────────────────────────────────
const sqlite3 = anyopaque;
const Ctx = anyopaque; // sqlite3_context*
const Val = anyopaque; // sqlite3_value* / Mem*
const sqlite3_str = anyopaque;

// ─── extern public sqlite3 API (resolved at link time) ──────────────────────
extern fn sqlite3_value_type(v: ?*Val) c_int;
extern fn sqlite3_value_subtype(v: ?*Val) c_uint;
extern fn sqlite3_value_double(v: ?*Val) f64;
extern fn sqlite3_value_int64(v: ?*Val) i64;
extern fn sqlite3_value_text(v: ?*Val) ?[*:0]const u8;
extern fn sqlite3_value_blob(v: ?*Val) ?[*]const u8;
extern fn sqlite3_value_bytes(v: ?*Val) c_int;

extern fn sqlite3_result_double(ctx: ?*Ctx, r: f64) void;
extern fn sqlite3_result_int(ctx: ?*Ctx, n: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*Ctx, n: i64) void;
extern fn sqlite3_result_null(ctx: ?*Ctx) void;
extern fn sqlite3_result_text(ctx: ?*Ctx, z: ?[*]const u8, n: c_int, xDel: XDel) void;
extern fn sqlite3_result_text64(ctx: ?*Ctx, z: ?[*]const u8, n: u64, xDel: XDel, enc: u8) void;
extern fn sqlite3_result_blob(ctx: ?*Ctx, z: ?*const anyopaque, n: c_int, xDel: XDel) void;
extern fn sqlite3_result_error(ctx: ?*Ctx, z: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*Ctx) void;
extern fn sqlite3_result_value(ctx: ?*Ctx, v: ?*Val) void;
extern fn sqlite3_result_subtype(ctx: ?*Ctx, t: c_uint) void;

extern fn sqlite3_context_db_handle(ctx: ?*Ctx) ?*anyopaque;
extern fn sqlite3_user_data(ctx: ?*Ctx) ?*anyopaque;
extern fn sqlite3_aggregate_context(ctx: ?*Ctx, nByte: c_int) ?*anyopaque;
extern fn sqlite3_get_auxdata(ctx: ?*Ctx, N: c_int) ?*anyopaque;
extern fn sqlite3_set_auxdata(ctx: ?*Ctx, N: c_int, p: ?*anyopaque, xDel: XDel) void;

extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_strglob(zGlob: [*:0]const u8, zStr: [*:0]const u8) c_int;
extern fn sqlite3_snprintf(n: c_int, z: [*]u8, fmt: [*:0]const u8, ...) ?[*:0]u8;

extern fn sqlite3_str_append(p: ?*sqlite3_str, z: ?[*]const u8, n: c_int) void;
extern fn sqlite3_str_appendall(p: ?*sqlite3_str, z: ?[*:0]const u8) void;
extern fn sqlite3_str_appendf(p: ?*sqlite3_str, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_str_value(p: ?*sqlite3_str) ?[*:0]u8;
extern fn sqlite3_str_reset(p: ?*sqlite3_str) void;

extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_vtab_config(db: ?*sqlite3, op: c_int, ...) c_int;

// ─── extern internal sqlite3-prefixed helpers ───────────────────────────────
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbRealloc(db: ?*anyopaque, p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*]const u8, n: u64) ?[*:0]u8;
extern fn sqlite3AtoF(z: [*:0]const u8, pResult: *f64) c_int;
extern fn sqlite3Atoi64(z: [*]const u8, pResult: *i64, n: c_int, enc: u8) c_int;
extern fn sqlite3DecOrHexToI64(z: [*:0]const u8, pResult: *i64) c_int;
extern fn sqlite3HexToInt(h: c_int) u8;
extern fn sqlite3IsNaN(r: f64) c_int;
extern fn sqlite3StrICmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn sqlite3_strnicmp(a: [*]const u8, b: [*]const u8, n: c_int) c_int;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3Utf8ReadLimited(z: [*]const u8, n: c_int, pOut: *u32) c_int;
extern fn sqlite3ValueIsOfClass(v: ?*const Val, xFree: XDel) c_int;
extern fn sqlite3InsertBuiltinFuncs(aDef: [*]FuncDef, nDef: c_int) void;
extern fn sqlite3VtabCreateModule(db: ?*sqlite3, zName: [*:0]const u8, pModule: *const sqlite3_module, pAux: ?*anyopaque, xDestroy: XDel) ?*anyopaque;

// reference-counted strings
extern fn sqlite3RCStrNew(n: u64) ?[*:0]u8;
extern fn sqlite3RCStrRef(z: ?[*]u8) ?[*:0]u8;
extern fn sqlite3RCStrUnref(z: ?*anyopaque) void;
extern fn sqlite3RCStrResize(z: ?[*]u8, n: u64) ?[*:0]u8;

extern fn sqlite3StrAccumInit(p: *anyopaque, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) void;

// SQLITE_DYNAMIC = (sqlite3_destructor_type)sqlite3RowSetClear  (sqliteInt.h).
// It is a sentinel matched by pointer identity inside the VDBE, so it MUST be
// exactly &sqlite3RowSetClear — not sqlite3_free.
extern fn sqlite3RowSetClear(p: ?*anyopaque) callconv(.c) void;
const SQLITE_DYNAMIC: XDel = @ptrCast(&sqlite3RowSetClear);
// sqlite3RCStrUnref as a destructor
const RCStrUnrefDtor: XDel = @ptrCast(&sqlite3RCStrUnref);

// libc helpers
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn memchr(s: ?*const anyopaque, c: c_int, n: usize) ?*const anyopaque;
extern fn strncmp(a: [*]const u8, b: [*]const u8, n: usize) c_int;
extern fn strchr(s: [*:0]const u8, c: c_int) ?[*:0]const u8;
extern fn strspn(s: [*]const u8, accept: [*:0]const u8) usize;
extern fn strlen(s: [*:0]const u8) usize;

// jsonSpaces: second arg to strspn (whitespace set)
const jsonSpaces: [*:0]const u8 = "\t\n\r ";

// ─── sqlite3.mallocFailed accessor (ground-truth offset 103) ─────────────────
const Sqlite3_mallocFailed: usize = off("sqlite3_mallocFailed", 103);
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    if (db == null) return false;
    return @as([*]u8, @ptrCast(db.?))[Sqlite3_mallocFailed] != 0;
}

// ─── FuncDef mirror (ABI; sizeof 72) ────────────────────────────────────────
const FuncDef = extern struct {
    nArg: i16,
    funcFlags: u32,
    pUserData: ?*anyopaque,
    pNext: ?*FuncDef,
    xSFunc: ?*anyopaque,
    xFinalize: ?*anyopaque,
    xValue: ?*anyopaque,
    xInverse: ?*anyopaque,
    zName: ?[*:0]const u8,
    u: extern union { pHash: ?*FuncDef, pDestructor: ?*anyopaque },
};
comptime {
    std.debug.assert(@sizeOf(FuncDef) == 72);
    std.debug.assert(@offsetOf(FuncDef, "funcFlags") == 4);
    std.debug.assert(@offsetOf(FuncDef, "pUserData") == 8);
    std.debug.assert(@offsetOf(FuncDef, "zName") == 56);
}

inline fn intToPtr(v: c_int) ?*anyopaque {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, v))));
}
inline fn ptrToInt(p: ?*anyopaque) c_int {
    return @intCast(@as(isize, @bitCast(@intFromPtr(p))));
}

// ─── Public ABI vtab structs (copied from carray.zig) ───────────────────────
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
const sqlite3_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int,
    xConnect: ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int,
    xBestIndex: ?*const fn (*sqlite3_vtab, *sqlite3_index_info) callconv(.c) c_int,
    xDisconnect: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xDestroy: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xOpen: ?*const fn (*sqlite3_vtab, *?*sqlite3_vtab_cursor) callconv(.c) c_int,
    xClose: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xFilter: ?*const fn (*sqlite3_vtab_cursor, c_int, ?[*:0]const u8, c_int, ?[*]?*Val) callconv(.c) c_int,
    xNext: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xEof: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xColumn: ?*const fn (*sqlite3_vtab_cursor, ?*Ctx, c_int) callconv(.c) c_int,
    xRowid: ?*const fn (*sqlite3_vtab_cursor, *i64) callconv(.c) c_int,
    xUpdate: ?*const anyopaque,
    xBegin: ?*const anyopaque,
    xSync: ?*const anyopaque,
    xCommit: ?*const anyopaque,
    xRollback: ?*const anyopaque,
    xFindFunction: ?*const anyopaque,
    xRename: ?*const anyopaque,
    xSavepoint: ?*const anyopaque,
    xRelease: ?*const anyopaque,
    xRollbackTo: ?*const anyopaque,
    xShadowName: ?*const anyopaque,
    xIntegrity: ?*const anyopaque,
};

// ─── Internal json.c structs (plain Zig structs, same layout) ───────────────
const JsonParse = struct {
    aBlob: ?[*]u8 = null,
    nBlob: u32 = 0,
    nBlobAlloc: u32 = 0,
    zJson: ?[*]u8 = null,
    db: ?*anyopaque = null,
    nJson: c_int = 0,
    nJPRef: u32 = 0,
    iErr: u32 = 0,
    iDepth: u16 = 0,
    nErr: u8 = 0,
    oom: u8 = 0,
    bJsonIsRCStr: u8 = 0,
    hasNonstd: u8 = 0,
    bReadOnly: u8 = 0,
    eEdit: u8 = 0,
    delta: c_int = 0,
    nIns: u32 = 0,
    iLabel: u32 = 0,
    aIns: ?[*]u8 = null,
};

const JsonCache = struct {
    db: ?*anyopaque = null,
    nUsed: c_int = 0,
    a: [JSON_CACHE_SIZE]?*JsonParse = .{ null, null, null, null },
};

const JsonString = struct {
    pCtx: ?*Ctx = null,
    zBuf: [*]u8 = undefined,
    nAlloc: u64 = 0,
    nUsed: u64 = 0,
    bStatic: u8 = 0,
    eErr: u8 = 0,
    zSpace: [100]u8 = undefined,
};

const NanInfName = struct {
    c1: u8,
    c2: u8,
    n: u8,
    eType: u8,
    nRepl: u8,
    zMatch: [*:0]const u8,
    zRepl: [*:0]const u8,
};
const aNanInfName = [_]NanInfName{
    .{ .c1 = 'i', .c2 = 'I', .n = 3, .eType = JSONB_FLOAT, .nRepl = 7, .zMatch = "inf", .zRepl = "9.0e999" },
    .{ .c1 = 'i', .c2 = 'I', .n = 8, .eType = JSONB_FLOAT, .nRepl = 7, .zMatch = "infinity", .zRepl = "9.0e999" },
    .{ .c1 = 'n', .c2 = 'N', .n = 3, .eType = JSONB_NULL, .nRepl = 4, .zMatch = "NaN", .zRepl = "null" },
    .{ .c1 = 'q', .c2 = 'Q', .n = 4, .eType = JSONB_NULL, .nRepl = 4, .zMatch = "QNaN", .zRepl = "null" },
    .{ .c1 = 's', .c2 = 'S', .n = 4, .eType = JSONB_NULL, .nRepl = 4, .zMatch = "SNaN", .zRepl = "null" },
};

// jsonIsOk[256]: bytes that are "ok" (not special) within JSON strings.
const jsonIsOk = blk: {
    @setEvalBranchQuota(2000);
    var t: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        // control chars (0..0x1f) are not ok; '"'(0x22), '\\'(0x5c), '\''(0x27) not ok
        t[i] = if (i >= 0x20 and i != '"' and i != '\\' and i != '\'') 1 else 0;
    }
    break :blk t;
};

inline fn jsonIsspace(x: u8) bool {
    // jsonIsSpace[]: 0x09,0x0a,0x0d,0x20
    return x == 0x09 or x == 0x0a or x == 0x0d or x == 0x20;
}

// forward-declared in C; Zig functions in a file see each other.

// ───────────────────────────────────────────────────────────────────────────
// JsonCache utilities
// ───────────────────────────────────────────────────────────────────────────
fn jsonCacheDelete(p: *JsonCache) void {
    var i: c_int = 0;
    while (i < p.nUsed) : (i += 1) {
        jsonParseFree(p.a[@intCast(i)]);
    }
    sqlite3DbFree(p.db, p);
}
fn jsonCacheDeleteGeneric(p: ?*anyopaque) callconv(.c) void {
    jsonCacheDelete(@ptrCast(@alignCast(p.?)));
}

fn jsonCacheInsert(ctx: ?*Ctx, pParse: *JsonParse) c_int {
    var p: ?*JsonCache = @ptrCast(@alignCast(sqlite3_get_auxdata(ctx, JSON_CACHE_ID)));
    if (p == null) {
        const db = sqlite3_context_db_handle(ctx);
        p = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @sizeOf(JsonCache))));
        if (p == null) return SQLITE_NOMEM;
        p.?.db = db;
        sqlite3_set_auxdata(ctx, JSON_CACHE_ID, p, &jsonCacheDeleteGeneric);
        p = @ptrCast(@alignCast(sqlite3_get_auxdata(ctx, JSON_CACHE_ID)));
        if (p == null) return SQLITE_NOMEM;
    }
    const pc = p.?;
    if (pc.nUsed >= @as(c_int, @intCast(JSON_CACHE_SIZE))) {
        jsonParseFree(pc.a[0]);
        // memmove(p->a, &p->a[1], (SIZE-1)*sizeof)
        std.mem.copyForwards(?*JsonParse, pc.a[0 .. JSON_CACHE_SIZE - 1], pc.a[1..JSON_CACHE_SIZE]);
        pc.nUsed = @as(c_int, @intCast(JSON_CACHE_SIZE)) - 1;
    }
    pParse.eEdit = 0;
    pParse.nJPRef += 1;
    pParse.bReadOnly = 1;
    pc.a[@intCast(pc.nUsed)] = pParse;
    pc.nUsed += 1;
    return SQLITE_OK;
}

fn jsonCacheSearch(ctx: ?*Ctx, pArg: ?*Val) ?*JsonParse {
    if (sqlite3_value_type(pArg) != SQLITE_TEXT) return null;
    const zJsonOpt = sqlite3_value_text(pArg);
    if (zJsonOpt == null) return null;
    const zJson = zJsonOpt.?;
    const nJson = sqlite3_value_bytes(pArg);

    const p: *JsonCache = @ptrCast(@alignCast(sqlite3_get_auxdata(ctx, JSON_CACHE_ID) orelse return null));
    var i: c_int = 0;
    while (i < p.nUsed) : (i += 1) {
        const a = p.a[@intCast(i)].?;
        if (a.zJson) |zj| {
            if (@intFromPtr(zj) == @intFromPtr(zJson)) break;
        }
    }
    if (i >= p.nUsed) {
        i = 0;
        while (i < p.nUsed) : (i += 1) {
            const a = p.a[@intCast(i)].?;
            if (a.nJson != nJson) continue;
            if (a.zJson) |zj| {
                if (memcmp(zj, zJson, @intCast(nJson)) == 0) break;
            }
        }
    }
    if (i < p.nUsed) {
        if (i < p.nUsed - 1) {
            const tmp = p.a[@intCast(i)];
            const ui: usize = @intCast(i);
            const un: usize = @intCast(p.nUsed);
            std.mem.copyForwards(?*JsonParse, p.a[ui .. un - 1], p.a[ui + 1 .. un]);
            p.a[un - 1] = tmp;
            i = p.nUsed - 1;
        }
        return p.a[@intCast(i)];
    } else {
        return null;
    }
}

// ───────────────────────────────────────────────────────────────────────────
// JsonString utilities
// ───────────────────────────────────────────────────────────────────────────
fn jsonStringZero(p: *JsonString) void {
    p.zBuf = &p.zSpace;
    p.nAlloc = p.zSpace.len;
    p.nUsed = 0;
    p.bStatic = 1;
}
fn jsonStringInit(p: *JsonString, pCtx: ?*Ctx) void {
    p.pCtx = pCtx;
    p.eErr = 0;
    jsonStringZero(p);
}
fn jsonStringReset(p: *JsonString) void {
    if (p.bStatic == 0) sqlite3RCStrUnref(p.zBuf);
    jsonStringZero(p);
}
fn jsonStringOom(p: *JsonString) void {
    p.eErr |= JSTRING_OOM;
    if (p.pCtx) |c| sqlite3_result_error_nomem(c);
    jsonStringReset(p);
}
fn jsonStringTooDeep(p: *JsonString) void {
    p.eErr |= JSTRING_TOODEEP;
    sqlite3_result_error(p.pCtx, "JSON nested too deep", -1);
    jsonStringReset(p);
}
fn jsonStringGrow(p: *JsonString, N: u32) c_int {
    const nTotal: u64 = if (N < p.nAlloc) p.nAlloc * 2 else p.nAlloc + N + 10;
    if (p.bStatic != 0) {
        if (p.eErr != 0) return 1;
        const zNew = sqlite3RCStrNew(nTotal);
        if (zNew == null) {
            jsonStringOom(p);
            return SQLITE_NOMEM;
        }
        @memcpy(zNew.?[0..@intCast(p.nUsed)], p.zBuf[0..@intCast(p.nUsed)]);
        p.zBuf = zNew.?;
        p.bStatic = 0;
    } else {
        const r = sqlite3RCStrResize(p.zBuf, nTotal);
        if (r == null) {
            p.eErr |= JSTRING_OOM;
            jsonStringZero(p);
            return SQLITE_NOMEM;
        }
        p.zBuf = r.?;
    }
    p.nAlloc = nTotal;
    return SQLITE_OK;
}
fn jsonStringExpandAndAppend(p: *JsonString, zIn: [*]const u8, N: u32) void {
    if (jsonStringGrow(p, N) != 0) return;
    @memcpy(p.zBuf[@intCast(p.nUsed)..][0..N], zIn[0..N]);
    p.nUsed += N;
}
fn jsonAppendRaw(p: *JsonString, zIn: [*]const u8, N: u32) void {
    if (N == 0) return;
    if (N + p.nUsed >= p.nAlloc) {
        jsonStringExpandAndAppend(p, zIn, N);
    } else {
        @memcpy(p.zBuf[@intCast(p.nUsed)..][0..N], zIn[0..N]);
        p.nUsed += N;
    }
}
fn jsonAppendRawNZ(p: *JsonString, zIn: [*]const u8, N: u32) void {
    if (N + p.nUsed >= p.nAlloc) {
        jsonStringExpandAndAppend(p, zIn, N);
    } else {
        @memcpy(p.zBuf[@intCast(p.nUsed)..][0..N], zIn[0..N]);
        p.nUsed += N;
    }
}
fn jsonPrintf(N: c_int, p: *JsonString, comptime fmt: [*:0]const u8, args: anytype) void {
    if ((p.nUsed + @as(u64, @intCast(N)) >= p.nAlloc) and jsonStringGrow(p, @intCast(N)) != 0) return;
    const dst = p.zBuf + @as(usize, @intCast(p.nUsed));
    _ = @call(.auto, sqlite3_snprintf, .{ N, dst, fmt } ++ args);
    p.nUsed += strlen(@ptrCast(dst));
}
fn jsonAppendCharExpand(p: *JsonString, c: u8) void {
    if (jsonStringGrow(p, 1) != 0) return;
    p.zBuf[@intCast(p.nUsed)] = c;
    p.nUsed += 1;
}
fn jsonAppendChar(p: *JsonString, c: u8) void {
    if (p.nUsed >= p.nAlloc) {
        jsonAppendCharExpand(p, c);
    } else {
        p.zBuf[@intCast(p.nUsed)] = c;
        p.nUsed += 1;
    }
}
fn jsonStringTrimOneChar(p: *JsonString) void {
    if (p.eErr == 0) {
        p.nUsed -= 1;
    }
}
fn jsonStringTerminate(p: *JsonString) c_int {
    jsonAppendChar(p, 0);
    jsonStringTrimOneChar(p);
    return @intFromBool(p.eErr == 0);
}
fn jsonAppendSeparator(p: *JsonString) void {
    if (p.nUsed == 0) return;
    const c = p.zBuf[@intCast(p.nUsed - 1)];
    if (c == '[' or c == '{') return;
    jsonAppendChar(p, ',');
}

const aHexDigit = "0123456789abcdef";
fn jsonAppendControlChar(p: *JsonString, c: u8) void {
    const aSpecial = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 'b', 't', 'n', 0, 'f', 'r', 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0, 0,   0,   0, 0,
    };
    const n: usize = @intCast(p.nUsed);
    if (aSpecial[c] != 0) {
        p.zBuf[n] = '\\';
        p.zBuf[n + 1] = aSpecial[c];
        p.nUsed += 2;
    } else {
        p.zBuf[n] = '\\';
        p.zBuf[n + 1] = 'u';
        p.zBuf[n + 2] = '0';
        p.zBuf[n + 3] = '0';
        p.zBuf[n + 4] = aHexDigit[c >> 4];
        p.zBuf[n + 5] = aHexDigit[c & 0xf];
        p.nUsed += 6;
    }
}

fn jsonAppendString(p: *JsonString, zIn: ?[*]const u8, N0: u32) void {
    var N = N0;
    if (zIn == null) return;
    const z0 = zIn.?;
    if ((N + p.nUsed + 2 >= p.nAlloc) and jsonStringGrow(p, N + 2) != 0) return;
    p.zBuf[@intCast(p.nUsed)] = '"';
    p.nUsed += 1;
    var z = z0;
    while (true) {
        var k: u32 = 0;
        while (true) {
            if (k + 3 >= N) {
                while (k < N and jsonIsOk[z[k]] != 0) k += 1;
                break;
            }
            if (jsonIsOk[z[k]] == 0) break;
            if (jsonIsOk[z[k + 1]] == 0) {
                k += 1;
                break;
            }
            if (jsonIsOk[z[k + 2]] == 0) {
                k += 2;
                break;
            }
            if (jsonIsOk[z[k + 3]] == 0) {
                k += 3;
                break;
            } else {
                k += 4;
            }
        }
        if (k >= N) {
            if (k > 0) {
                @memcpy(p.zBuf[@intCast(p.nUsed)..][0..k], z[0..k]);
                p.nUsed += k;
            }
            break;
        }
        if (k > 0) {
            @memcpy(p.zBuf[@intCast(p.nUsed)..][0..k], z[0..k]);
            p.nUsed += k;
            z += k;
            N -= k;
        }
        const c = z[0];
        if (c == '"' or c == '\\') {
            if ((p.nUsed + N + 3 > p.nAlloc) and jsonStringGrow(p, N + 3) != 0) return;
            p.zBuf[@intCast(p.nUsed)] = '\\';
            p.nUsed += 1;
            p.zBuf[@intCast(p.nUsed)] = c;
            p.nUsed += 1;
        } else if (c == '\'') {
            p.zBuf[@intCast(p.nUsed)] = c;
            p.nUsed += 1;
        } else {
            if ((p.nUsed + N + 7 > p.nAlloc) and jsonStringGrow(p, N + 7) != 0) return;
            jsonAppendControlChar(p, c);
        }
        z += 1;
        N -= 1;
    }
    p.zBuf[@intCast(p.nUsed)] = '"';
    p.nUsed += 1;
}

// ───────────────────────────────────────────────────────────────────────────
// JsonParse free utilities
// ───────────────────────────────────────────────────────────────────────────
fn jsonParseReset(pParse: *JsonParse) void {
    if (pParse.bJsonIsRCStr != 0) {
        sqlite3RCStrUnref(pParse.zJson);
        pParse.zJson = null;
        pParse.nJson = 0;
        pParse.bJsonIsRCStr = 0;
    }
    if (pParse.nBlobAlloc != 0) {
        sqlite3DbFree(pParse.db, pParse.aBlob);
        pParse.aBlob = null;
        pParse.nBlob = 0;
        pParse.nBlobAlloc = 0;
    }
}
fn jsonParseFree(pParseOpt: ?*JsonParse) void {
    if (pParseOpt) |pParse| {
        if (pParse.nJPRef > 1) {
            pParse.nJPRef -= 1;
        } else {
            jsonParseReset(pParse);
            sqlite3DbFree(pParse.db, pParse);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// JSON text parser utilities
// ───────────────────────────────────────────────────────────────────────────
fn jsonHexToInt(h0: c_int) u8 {
    var h = h0;
    h += 9 * (1 & (h >> 6)); // SQLITE_ASCII
    return @truncate(@as(c_uint, @bitCast(h)) & 0xf);
}
fn jsonHexToInt4(z: [*]const u8) u32 {
    return (@as(u32, jsonHexToInt(z[0])) << 12) +
        (@as(u32, jsonHexToInt(z[1])) << 8) +
        (@as(u32, jsonHexToInt(z[2])) << 4) +
        jsonHexToInt(z[3]);
}
fn jsonIs2Hex(z: [*]const u8) bool {
    return isxdigit(z[0]) and isxdigit(z[1]);
}
fn jsonIs4Hex(z: [*]const u8) bool {
    return jsonIs2Hex(z) and jsonIs2Hex(z + 2);
}

fn json5Whitespace(zIn: [*]const u8) c_int {
    var n: c_int = 0;
    const z = zIn;
    whitespace: while (true) {
        switch (z[@intCast(n)]) {
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20 => {
                n += 1;
            },
            '/' => {
                const un: usize = @intCast(n);
                if (z[un + 1] == '*' and z[un + 2] != 0) {
                    var j: usize = un + 3;
                    while (z[j] != '/' or z[j - 1] != '*') : (j += 1) {
                        if (z[j] == 0) break :whitespace;
                    }
                    n = @intCast(j + 1);
                } else if (z[un + 1] == '/') {
                    var j: usize = un + 2;
                    while (z[j] != 0) : (j += 1) {
                        const c = z[j];
                        if (c == '\n' or c == '\r') break;
                        if (0xe2 == c and 0x80 == z[j + 1] and
                            (0xa8 == z[j + 2] or 0xa9 == z[j + 2]))
                        {
                            j += 2;
                            break;
                        }
                    }
                    n = @intCast(j);
                    if (z[@intCast(n)] != 0) n += 1;
                } else break :whitespace;
            },
            0xc2 => {
                if (z[@as(usize, @intCast(n)) + 1] == 0xa0) {
                    n += 2;
                } else break :whitespace;
            },
            0xe1 => {
                const un: usize = @intCast(n);
                if (z[un + 1] == 0x9a and z[un + 2] == 0x80) {
                    n += 3;
                } else break :whitespace;
            },
            0xe2 => {
                const un: usize = @intCast(n);
                if (z[un + 1] == 0x80) {
                    const c = z[un + 2];
                    if (c < 0x80) break :whitespace;
                    if (c <= 0x8a or c == 0xa8 or c == 0xa9 or c == 0xaf) {
                        n += 3;
                    } else break :whitespace;
                } else if (z[un + 1] == 0x81 and z[un + 2] == 0x9f) {
                    n += 3;
                } else break :whitespace;
            },
            0xe3 => {
                const un: usize = @intCast(n);
                if (z[un + 1] == 0x80 and z[un + 2] == 0x80) {
                    n += 3;
                } else break :whitespace;
            },
            0xef => {
                const un: usize = @intCast(n);
                if (z[un + 1] == 0xbb and z[un + 2] == 0xbf) {
                    n += 3;
                } else break :whitespace;
            },
            else => break :whitespace,
        }
    }
    return n;
}

fn jsonWrongNumArgs(pCtx: ?*Ctx, zFuncName: [*:0]const u8) void {
    const zMsg = sqlite3_mprintf("json_%s() needs an odd number of arguments", zFuncName);
    sqlite3_result_error(pCtx, zMsg, -1);
    sqlite3_free(zMsg);
}

// ───────────────────────────────────────────────────────────────────────────
// JSONB binary codec
// ───────────────────────────────────────────────────────────────────────────
fn jsonBlobExpand(pParse: *JsonParse, N: u32) c_int {
    var t: u64 = undefined;
    if (pParse.nBlobAlloc == 0) {
        t = 100;
    } else {
        t = @as(u64, pParse.nBlobAlloc) * 2;
    }
    if (t < N) t = @as(u64, N) + 100;
    const aNew = sqlite3DbRealloc(pParse.db, pParse.aBlob, t);
    if (aNew == null) {
        pParse.oom = 1;
        return 1;
    }
    pParse.aBlob = @ptrCast(aNew);
    pParse.nBlobAlloc = @truncate(t);
    return 0;
}

fn jsonBlobMakeEditable(pParse: *JsonParse, nExtra: u32) c_int {
    if (pParse.oom != 0) return 0;
    if (pParse.nBlobAlloc > 0) return 1;
    const aOld = pParse.aBlob;
    const nSize = pParse.nBlob + nExtra;
    pParse.aBlob = null;
    if (jsonBlobExpand(pParse, nSize) != 0) return 0;
    if (pParse.nBlob > 0) {
        @memcpy(pParse.aBlob.?[0..pParse.nBlob], aOld.?[0..pParse.nBlob]);
    }
    return 1;
}

fn jsonBlobExpandAndAppendOneByte(pParse: *JsonParse, c: u8) void {
    _ = jsonBlobExpand(pParse, pParse.nBlob + 1);
    if (pParse.oom == 0) {
        pParse.aBlob.?[pParse.nBlob] = c;
        pParse.nBlob += 1;
    }
}
fn jsonBlobAppendOneByte(pParse: *JsonParse, c: u8) void {
    if (pParse.nBlob >= pParse.nBlobAlloc) {
        jsonBlobExpandAndAppendOneByte(pParse, c);
    } else {
        pParse.aBlob.?[pParse.nBlob] = c;
        pParse.nBlob += 1;
    }
}

fn jsonBlobExpandAndAppendNode(pParse: *JsonParse, eType: u8, szPayload: u64, aPayload: ?[*]const u8) void {
    if (jsonBlobExpand(pParse, @truncate(@as(u64, pParse.nBlob) + szPayload + 9)) != 0) return;
    jsonBlobAppendNode(pParse, eType, szPayload, aPayload);
}

fn jsonBlobAppendNode(pParse: *JsonParse, eType: u8, szPayload: u64, aPayload: ?[*]const u8) void {
    if (@as(u64, pParse.nBlob) + szPayload + 9 > pParse.nBlobAlloc) {
        jsonBlobExpandAndAppendNode(pParse, eType, szPayload, aPayload);
        return;
    }
    const a = pParse.aBlob.? + pParse.nBlob;
    if (szPayload <= 11) {
        a[0] = eType | (@as(u8, @truncate(szPayload)) << 4);
        pParse.nBlob += 1;
    } else if (szPayload <= 0xff) {
        a[0] = eType | 0xc0;
        a[1] = @truncate(szPayload & 0xff);
        pParse.nBlob += 2;
    } else if (szPayload <= 0xffff) {
        a[0] = eType | 0xd0;
        a[1] = @truncate((szPayload >> 8) & 0xff);
        a[2] = @truncate(szPayload & 0xff);
        pParse.nBlob += 3;
    } else {
        a[0] = eType | 0xe0;
        a[1] = @truncate((szPayload >> 24) & 0xff);
        a[2] = @truncate((szPayload >> 16) & 0xff);
        a[3] = @truncate((szPayload >> 8) & 0xff);
        a[4] = @truncate(szPayload & 0xff);
        pParse.nBlob += 5;
    }
    if (aPayload) |ap| {
        const sp: u32 = @truncate(szPayload);
        pParse.nBlob += sp;
        @memcpy(pParse.aBlob.?[pParse.nBlob - sp ..][0..sp], ap[0..sp]);
    }
}

fn jsonBlobChangePayloadSize(pParse: *JsonParse, i: u32, szPayload: u32) c_int {
    if (pParse.oom != 0) return 0;
    var a = pParse.aBlob.? + i;
    const szType = a[0] >> 4;
    var nExtra: u8 = undefined;
    if (szType <= 11) {
        nExtra = 0;
    } else if (szType == 12) {
        nExtra = 1;
    } else if (szType == 13) {
        nExtra = 2;
    } else if (szType == 14) {
        nExtra = 4;
    } else {
        nExtra = 8;
    }
    var nNeeded: u8 = undefined;
    if (szPayload <= 11) {
        nNeeded = 0;
    } else if (szPayload <= 0xff) {
        nNeeded = 1;
    } else if (szPayload <= 0xffff) {
        nNeeded = 2;
    } else {
        nNeeded = 4;
    }
    const delta: i32 = @as(i32, nNeeded) - @as(i32, nExtra);
    if (delta != 0) {
        const newSize: u32 = @bitCast(@as(i32, @bitCast(pParse.nBlob)) +% delta);
        if (delta > 0) {
            if (newSize > pParse.nBlobAlloc and jsonBlobExpand(pParse, newSize) != 0) {
                return 0;
            }
            a = pParse.aBlob.? + i;
            const ud: usize = @intCast(delta);
            const cnt: usize = pParse.nBlob - (i + 1);
            // memmove(&a[1+delta], &a[1], cnt)
            std.mem.copyBackwards(u8, a[1 + ud ..][0..cnt], a[1..][0..cnt]);
        } else {
            const ud: usize = @intCast(-delta);
            const cnt: usize = pParse.nBlob - (i + 1 - @as(u32, @intCast(-delta)));
            // memmove(&a[1], &a[1-delta], cnt)  (1-delta = 1+ud)
            std.mem.copyForwards(u8, a[1..][0..cnt], a[1 + ud ..][0..cnt]);
        }
        pParse.nBlob = newSize;
    }
    if (nNeeded == 0) {
        a[0] = (a[0] & 0x0f) | (@as(u8, @truncate(szPayload)) << 4);
    } else if (nNeeded == 1) {
        a[0] = (a[0] & 0x0f) | 0xc0;
        a[1] = @truncate(szPayload & 0xff);
    } else if (nNeeded == 2) {
        a[0] = (a[0] & 0x0f) | 0xd0;
        a[1] = @truncate((szPayload >> 8) & 0xff);
        a[2] = @truncate(szPayload & 0xff);
    } else {
        a[0] = (a[0] & 0x0f) | 0xe0;
        a[1] = @truncate((szPayload >> 24) & 0xff);
        a[2] = @truncate((szPayload >> 16) & 0xff);
        a[3] = @truncate((szPayload >> 8) & 0xff);
        a[4] = @truncate(szPayload & 0xff);
    }
    return delta;
}

fn jsonbPayloadSize(pParse: *const JsonParse, i: u32, pSz: *u32) u32 {
    var sz: u32 = undefined;
    var n: u32 = undefined;
    if (i >= pParse.nBlob) {
        pSz.* = 0;
        return 0;
    }
    const x: u8 = pParse.aBlob.?[i] >> 4;
    if (x <= 11) {
        sz = x;
        n = 1;
    } else if (x == 12) {
        if (i + 1 >= pParse.nBlob) {
            pSz.* = 0;
            return 0;
        }
        sz = pParse.aBlob.?[i + 1];
        n = 2;
    } else if (x == 13) {
        if (i + 2 >= pParse.nBlob) {
            pSz.* = 0;
            return 0;
        }
        sz = (@as(u32, pParse.aBlob.?[i + 1]) << 8) + pParse.aBlob.?[i + 2];
        n = 3;
    } else if (x == 14) {
        if (i + 4 >= pParse.nBlob) {
            pSz.* = 0;
            return 0;
        }
        sz = (@as(u32, pParse.aBlob.?[i + 1]) << 24) + (@as(u32, pParse.aBlob.?[i + 2]) << 16) +
            (@as(u32, pParse.aBlob.?[i + 3]) << 8) + pParse.aBlob.?[i + 4];
        n = 5;
    } else {
        if (i + 8 >= pParse.nBlob or
            pParse.aBlob.?[i + 1] != 0 or pParse.aBlob.?[i + 2] != 0 or
            pParse.aBlob.?[i + 3] != 0 or pParse.aBlob.?[i + 4] != 0)
        {
            pSz.* = 0;
            return 0;
        }
        sz = (@as(u32, pParse.aBlob.?[i + 5]) << 24) + (@as(u32, pParse.aBlob.?[i + 6]) << 16) +
            (@as(u32, pParse.aBlob.?[i + 7]) << 8) + pParse.aBlob.?[i + 8];
        n = 9;
    }
    const lhs: i64 = @as(i64, i) + sz + n;
    if (lhs > pParse.nBlob and lhs > @as(i64, pParse.nBlob) - pParse.delta) {
        pSz.* = 0;
        return 0;
    }
    pSz.* = sz;
    return n;
}

fn jsonIs4HexB(z: [*]const u8, pOp: *u8) bool {
    if (z[0] != 'u') return false;
    if (!jsonIs4Hex(z + 1)) return false;
    pOp.* = JSONB_TEXTJ;
    return true;
}

fn jsonbValidityCheck(pParse: *const JsonParse, iA0: u32, iEnd: u32, iDepth: u32) u32 {
    const i = iA0;
    var n: u32 = undefined;
    var sz: u32 = 0;
    var j: u32 = undefined;
    var k: u32 = undefined;
    if (iDepth > JSON_MAX_DEPTH) return i + 1;
    n = jsonbPayloadSize(pParse, i, &sz);
    if (n == 0) return i + 1;
    if (i + n + sz != iEnd) return i + 1;
    const z = pParse.aBlob.?;
    var x: u8 = z[i] & 0x0f;
    switch (x) {
        JSONB_NULL, JSONB_TRUE, JSONB_FALSE => {
            return if (n + sz == 1) 0 else i + 1;
        },
        JSONB_INT => {
            if (sz < 1) return i + 1;
            j = i + n;
            if (z[j] == '-') {
                j += 1;
                if (sz < 2) return i + 1;
            }
            k = i + n + sz;
            while (j < k) {
                if (isdigit(z[j])) {
                    j += 1;
                } else return j + 1;
            }
            return 0;
        },
        JSONB_INT5 => {
            if (sz < 3) return i + 1;
            j = i + n;
            if (z[j] == '-') {
                if (sz < 4) return i + 1;
                j += 1;
            }
            if (z[j] != '0') return i + 1;
            if (z[j + 1] != 'x' and z[j + 1] != 'X') return j + 2;
            j += 2;
            k = i + n + sz;
            while (j < k) {
                if (isxdigit(z[j])) {
                    j += 1;
                } else return j + 1;
            }
            return 0;
        },
        JSONB_FLOAT, JSONB_FLOAT5 => {
            var seen: u8 = 0;
            if (sz < 2) return i + 1;
            j = i + n;
            k = j + sz;
            if (z[j] == '-') {
                j += 1;
                if (sz < 3) return i + 1;
            }
            if (z[j] == '.') {
                if (x == JSONB_FLOAT) return j + 1;
                if (!isdigit(z[j + 1])) return j + 1;
                j += 2;
                seen = 1;
            } else if (z[j] == '0' and x == JSONB_FLOAT) {
                if (j + 3 > k) return j + 1;
                if (z[j + 1] != '.' and z[j + 1] != 'e' and z[j + 1] != 'E') return j + 1;
                j += 1;
            }
            while (j < k) : (j += 1) {
                if (isdigit(z[j])) continue;
                if (z[j] == '.') {
                    if (seen > 0) return j + 1;
                    if (x == JSONB_FLOAT and (j == k - 1 or !isdigit(z[j + 1]))) return j + 1;
                    seen = 1;
                    continue;
                }
                if (z[j] == 'e' or z[j] == 'E') {
                    if (seen == 2) return j + 1;
                    if (j == k - 1) return j + 1;
                    if (z[j + 1] == '+' or z[j + 1] == '-') {
                        j += 1;
                        if (j == k - 1) return j + 1;
                    }
                    seen = 2;
                    continue;
                }
                return j + 1;
            }
            if (seen == 0) return i + 1;
            return 0;
        },
        JSONB_TEXT => {
            j = i + n;
            k = j + sz;
            while (j < k) : (j += 1) {
                if (jsonIsOk[z[j]] == 0 and z[j] != '\'') return j + 1;
            }
            return 0;
        },
        JSONB_TEXTJ, JSONB_TEXT5 => {
            j = i + n;
            k = j + sz;
            while (j < k) : (j += 1) {
                if (jsonIsOk[z[j]] == 0 and z[j] != '\'') {
                    if (z[j] == '"') {
                        if (x == JSONB_TEXTJ) return j + 1;
                    } else if (z[j] <= 0x1f) {
                        if (x == JSONB_TEXTJ) return j + 1;
                    } else if (z[j] != '\\' or j + 1 >= k) {
                        return j + 1;
                    } else if (strchr("\"\\/bfnrt", z[j + 1]) != null) {
                        j += 1;
                    } else if (z[j + 1] == 'u') {
                        if (j + 5 >= k) return j + 1;
                        if (!jsonIs4Hex(z + j + 2)) return j + 1;
                        j += 1;
                    } else if (x != JSONB_TEXT5) {
                        return j + 1;
                    } else {
                        var c: u32 = 0;
                        const szC = jsonUnescapeOneChar(@ptrCast(z + j), k - j, &c);
                        if (c == JSON_INVALID_CHAR) return j + 1;
                        j += szC - 1;
                    }
                }
            }
            return 0;
        },
        JSONB_TEXTRAW => {
            return 0;
        },
        JSONB_ARRAY => {
            j = i + n;
            k = j + sz;
            while (j < k) {
                sz = 0;
                n = jsonbPayloadSize(pParse, j, &sz);
                if (n == 0) return j + 1;
                if (j + n + sz > k) return j + 1;
                const sub = jsonbValidityCheck(pParse, j, j + n + sz, iDepth + 1);
                if (sub != 0) return sub;
                j += n + sz;
            }
            return 0;
        },
        JSONB_OBJECT => {
            var cnt: u32 = 0;
            j = i + n;
            k = j + sz;
            while (j < k) {
                sz = 0;
                n = jsonbPayloadSize(pParse, j, &sz);
                if (n == 0) return j + 1;
                if (j + n + sz > k) return j + 1;
                if ((cnt & 1) == 0) {
                    x = z[j] & 0x0f;
                    if (x < JSONB_TEXT or x > JSONB_TEXTRAW) return j + 1;
                }
                const sub = jsonbValidityCheck(pParse, j, j + n + sz, iDepth + 1);
                if (sub != 0) return sub;
                cnt += 1;
                j += n + sz;
            }
            if ((cnt & 1) != 0) return j + 1;
            return 0;
        },
        else => return i + 1,
    }
}

// Translate one JSON text element at zJson[i] into JSONB appended to aBlob.
// Returns index past the element, or 0/-1/-2/-3/-4/-5 (see json.c).
fn jsonTranslateTextToBlob(pParse: *JsonParse, iA0: u32) c_int {
    var i = iA0;
    const z = pParse.zJson.?;
    restart: while (true) {
        switch (z[i]) {
            '{' => return parseObject(pParse, i),
            '[' => return parseArray(pParse, i),
            '\'', '"' => return parseString(pParse, i),
            't' => {
                if (strncmp(z + i, "true", 4) == 0 and !isalnum(z[i + 4])) {
                    jsonBlobAppendOneByte(pParse, JSONB_TRUE);
                    return @intCast(i + 4);
                }
                pParse.iErr = i;
                return -1;
            },
            'f' => {
                if (strncmp(z + i, "false", 5) == 0 and !isalnum(z[i + 5])) {
                    jsonBlobAppendOneByte(pParse, JSONB_FALSE);
                    return @intCast(i + 5);
                }
                pParse.iErr = i;
                return -1;
            },
            '+', '.', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' => {
                return parseNumber(pParse, i);
            },
            '}' => {
                pParse.iErr = i;
                return -2;
            },
            ']' => {
                pParse.iErr = i;
                return -3;
            },
            ',' => {
                pParse.iErr = i;
                return -4;
            },
            ':' => {
                pParse.iErr = i;
                return -5;
            },
            0 => return 0,
            0x09, 0x0a, 0x0d, 0x20 => {
                i += 1 + @as(u32, @intCast(strspn(z + i + 1, jsonSpaces)));
                continue :restart;
            },
            0x0b, 0x0c, '/', 0xc2, 0xe1, 0xe2, 0xe3, 0xef => {
                const j = json5Whitespace(z + i);
                if (j > 0) {
                    i += @intCast(j);
                    pParse.hasNonstd = 1;
                    continue :restart;
                }
                pParse.iErr = i;
                return -1;
            },
            'n' => {
                if (strncmp(z + i, "null", 4) == 0 and !isalnum(z[i + 4])) {
                    jsonBlobAppendOneByte(pParse, JSONB_NULL);
                    return @intCast(i + 4);
                }
                return parseNanInf(pParse, i);
            },
            else => return parseNanInf(pParse, i),
        }
    }
}

fn parseNanInf(pParse: *JsonParse, i: u32) c_int {
    const z = pParse.zJson.?;
    const c = z[i];
    var kk: usize = 0;
    while (kk < aNanInfName.len) : (kk += 1) {
        const e = aNanInfName[kk];
        if (c != e.c1 and c != e.c2) continue;
        const nn: c_int = e.n;
        if (sqlite3_strnicmp(@ptrCast(z + i), e.zMatch, nn) != 0) continue;
        if (isalnum(z[i + @as(u32, @intCast(nn))])) continue;
        if (e.eType == JSONB_FLOAT) {
            jsonBlobAppendNode(pParse, JSONB_FLOAT, 5, "9e999");
        } else {
            jsonBlobAppendOneByte(pParse, JSONB_NULL);
        }
        pParse.hasNonstd = 1;
        return @intCast(i + @as(u32, @intCast(nn)));
    }
    pParse.iErr = i;
    return -1;
}

fn parseString(pParse: *JsonParse, i: u32) c_int {
    const z = pParse.zJson.?;
    var opcode: u8 = JSONB_TEXT;
    if (z[i] == '\'') pParse.hasNonstd = 1;
    const cDelim = z[i];
    var j: u32 = i + 1;
    while (true) {
        if (jsonIsOk[z[j]] != 0) {
            if (jsonIsOk[z[j + 1]] == 0) {
                j += 1;
            } else if (jsonIsOk[z[j + 2]] == 0) {
                j += 2;
            } else {
                j += 3;
                continue;
            }
        }
        var c = z[j];
        if (c == cDelim) {
            break;
        } else if (c == '\\') {
            j += 1;
            c = z[j];
            if (c == '"' or c == '\\' or c == '/' or c == 'b' or c == 'f' or
                c == 'n' or c == 'r' or c == 't' or
                (c == 'u' and jsonIs4Hex(z + j + 1)))
            {
                if (opcode == JSONB_TEXT) opcode = JSONB_TEXTJ;
            } else if (c == '\'' or c == 'v' or c == '\n' or
                (c == '0' and !isdigit(z[j + 1])) or
                (0xe2 == c and 0x80 == z[j + 1] and (0xa8 == z[j + 2] or 0xa9 == z[j + 2])) or
                (c == 'x' and jsonIs2Hex(z + j + 1)))
            {
                opcode = JSONB_TEXT5;
                pParse.hasNonstd = 1;
            } else if (c == '\r') {
                if (z[j + 1] == '\n') j += 1;
                opcode = JSONB_TEXT5;
                pParse.hasNonstd = 1;
            } else {
                pParse.iErr = j;
                return -1;
            }
        } else if (c <= 0x1f) {
            if (c == 0) {
                pParse.iErr = j;
                return -1;
            }
            opcode = JSONB_TEXT5;
            pParse.hasNonstd = 1;
        } else if (c == '"') {
            opcode = JSONB_TEXT5;
        }
        j += 1;
    }
    jsonBlobAppendNode(pParse, opcode, j - 1 - i, z + i + 1);
    return @intCast(j + 1);
}

fn parseNumber(pParse: *JsonParse, iA0: u32) c_int {
    const i = iA0;
    const z = pParse.zJson.?;
    var t: u8 = 0; // bit 0x01 JSON5, bit 0x02 FLOAT
    const seenE: bool = false;
    var j: u32 = undefined;
    const c = z[i];

    if (c == '+') {
        pParse.hasNonstd = 1;
        t = 0x00;
    } else if (c == '.') {
        if (isdigit(z[i + 1])) {
            pParse.hasNonstd = 1;
            t = 0x03;
            return parseNumber2(pParse, i, t, seenE);
        }
        pParse.iErr = i;
        return -1;
    }

    if (c <= '0') {
        if (c == '0') {
            if ((z[i + 1] == 'x' or z[i + 1] == 'X') and isxdigit(z[i + 2])) {
                pParse.hasNonstd = 1;
                t = 0x01;
                j = i + 3;
                while (isxdigit(z[j])) j += 1;
                return parseNumberFinish(pParse, i, j, t);
            } else if (isdigit(z[i + 1])) {
                pParse.iErr = i + 1;
                return -1;
            }
        } else {
            if (!isdigit(z[i + 1])) {
                if ((z[i + 1] == 'I' or z[i + 1] == 'i') and sqlite3_strnicmp(@ptrCast(z + i + 1), "inf", 3) == 0) {
                    pParse.hasNonstd = 1;
                    if (z[i] == '-') {
                        jsonBlobAppendNode(pParse, JSONB_FLOAT, 6, "-9e999");
                    } else {
                        jsonBlobAppendNode(pParse, JSONB_FLOAT, 5, "9e999");
                    }
                    return @intCast(i + (if (sqlite3_strnicmp(@ptrCast(z + i + 4), "inity", 5) == 0) @as(u32, 9) else 4));
                }
                if (z[i + 1] == '.') {
                    pParse.hasNonstd = 1;
                    t |= 0x01;
                    return parseNumber2(pParse, i, t, seenE);
                }
                pParse.iErr = i;
                return -1;
            }
            if (z[i + 1] == '0') {
                if (isdigit(z[i + 2])) {
                    pParse.iErr = i + 1;
                    return -1;
                } else if ((z[i + 2] == 'x' or z[i + 2] == 'X') and isxdigit(z[i + 3])) {
                    pParse.hasNonstd = 1;
                    t |= 0x01;
                    j = i + 4;
                    while (isxdigit(z[j])) j += 1;
                    return parseNumberFinish(pParse, i, j, t);
                }
            }
        }
    }
    return parseNumber2(pParse, iA0, t, seenE);
}

fn parseNumber2(pParse: *JsonParse, i: u32, t0: u8, seenE0: bool) c_int {
    const z = pParse.zJson.?;
    var t = t0;
    var seenE = seenE0;
    var j: u32 = i + 1;
    while (true) : (j += 1) {
        var c = z[j];
        if (isdigit(c)) continue;
        if (c == '.') {
            if ((t & 0x02) != 0) {
                pParse.iErr = j;
                return -1;
            }
            t |= 0x02;
            continue;
        }
        if (c == 'e' or c == 'E') {
            if (z[j - 1] < '0') {
                if (z[j - 1] == '.' and j >= i + 2 and isdigit(z[j - 2])) {
                    pParse.hasNonstd = 1;
                    t |= 0x01;
                } else {
                    pParse.iErr = j;
                    return -1;
                }
            }
            if (seenE) {
                pParse.iErr = j;
                return -1;
            }
            t |= 0x02;
            seenE = true;
            c = z[j + 1];
            if (c == '+' or c == '-') {
                j += 1;
                c = z[j + 1];
            }
            if (c < '0' or c > '9') {
                pParse.iErr = j;
                return -1;
            }
            continue;
        }
        break;
    }
    if (z[j - 1] < '0') {
        if (z[j - 1] == '.' and j >= i + 2 and isdigit(z[j - 2])) {
            pParse.hasNonstd = 1;
            t |= 0x01;
        } else {
            pParse.iErr = j;
            return -1;
        }
    }
    return parseNumberFinish(pParse, i, j, t);
}

fn parseNumberFinish(pParse: *JsonParse, iA0: u32, j: u32, t: u8) c_int {
    var i = iA0;
    const z = pParse.zJson.?;
    if (z[i] == '+') i += 1;
    jsonBlobAppendNode(pParse, JSONB_INT + t, j - i, z + i);
    return @intCast(j);
}

fn parseObject(pParse: *JsonParse, i: u32) c_int {
    const z = pParse.zJson.?;
    const iThis = pParse.nBlob;
    jsonBlobAppendNode(pParse, JSONB_OBJECT, @as(u64, @intCast(pParse.nJson)) - i, null);
    pParse.iDepth += 1;
    if (pParse.iDepth > JSON_MAX_DEPTH) {
        pParse.iErr = i;
        return -1;
    }
    const iStart = pParse.nBlob;
    var j: u32 = i + 1;
    var x: c_int = undefined;
    outer: while (true) : (j += 1) {
        const iBlob = pParse.nBlob;
        x = jsonTranslateTextToBlob(pParse, j);
        if (x <= 0) {
            if (x == -2) {
                j = pParse.iErr;
                if (pParse.nBlob != iStart) pParse.hasNonstd = 1;
                break;
            }
            j += @intCast(json5Whitespace(z + j));
            var op: u8 = JSONB_TEXT;
            if (jsonId1(z[j]) or (z[j] == '\\' and jsonIs4HexB(z + j + 1, &op))) {
                var k: u32 = j + 1;
                while ((jsonId2(z[k]) and json5Whitespace(z + k) == 0) or
                    (z[k] == '\\' and jsonIs4HexB(z + k + 1, &op)))
                {
                    k += 1;
                }
                jsonBlobAppendNode(pParse, op, k - j, z + j);
                pParse.hasNonstd = 1;
                x = @intCast(k);
            } else {
                if (x != -1) pParse.iErr = j;
                return -1;
            }
        }
        if (pParse.oom != 0) return -1;
        const t = pParse.aBlob.?[iBlob] & 0x0f;
        if (t < JSONB_TEXT or t > JSONB_TEXTRAW) {
            pParse.iErr = j;
            return -1;
        }
        j = @intCast(x);
        var doValue = false;
        if (z[j] == ':') {
            j += 1;
            doValue = true;
        } else {
            if (jsonIsspace(z[j])) {
                while (true) {
                    j += 1;
                    if (!jsonIsspace(z[j])) break;
                }
                if (z[j] == ':') {
                    j += 1;
                    doValue = true;
                }
            }
            if (!doValue) {
                x = jsonTranslateTextToBlob(pParse, j);
                if (x != -5) {
                    if (x != -1) pParse.iErr = j;
                    return -1;
                }
                j = pParse.iErr + 1;
                doValue = true;
            }
        }
        // parse_object_value:
        x = jsonTranslateTextToBlob(pParse, j);
        if (x <= 0) {
            if (x != -1) pParse.iErr = j;
            return -1;
        }
        j = @intCast(x);
        if (z[j] == ',') {
            continue :outer;
        } else if (z[j] == '}') {
            break;
        } else {
            if (jsonIsspace(z[j])) {
                j += 1 + @as(u32, @intCast(strspn(z + j + 1, jsonSpaces)));
                if (z[j] == ',') {
                    continue :outer;
                } else if (z[j] == '}') {
                    break;
                }
            }
            x = jsonTranslateTextToBlob(pParse, j);
            if (x == -4) {
                j = pParse.iErr;
                continue :outer;
            }
            if (x == -2) {
                j = pParse.iErr;
                break;
            }
        }
        pParse.iErr = j;
        return -1;
    }
    _ = jsonBlobChangePayloadSize(pParse, iThis, pParse.nBlob - iStart);
    pParse.iDepth -= 1;
    return @intCast(j + 1);
}

fn parseArray(pParse: *JsonParse, i: u32) c_int {
    const z = pParse.zJson.?;
    const iThis = pParse.nBlob;
    jsonBlobAppendNode(pParse, JSONB_ARRAY, @as(u64, @intCast(pParse.nJson)) - i, null);
    const iStart = pParse.nBlob;
    if (pParse.oom != 0) return -1;
    pParse.iDepth += 1;
    if (pParse.iDepth > JSON_MAX_DEPTH) {
        pParse.iErr = i;
        return -1;
    }
    var j: u32 = i + 1;
    var x: c_int = undefined;
    outer: while (true) : (j += 1) {
        x = jsonTranslateTextToBlob(pParse, j);
        if (x <= 0) {
            if (x == -3) {
                j = pParse.iErr;
                if (pParse.nBlob != iStart) pParse.hasNonstd = 1;
                break;
            }
            if (x != -1) pParse.iErr = j;
            return -1;
        }
        j = @intCast(x);
        if (z[j] == ',') {
            continue :outer;
        } else if (z[j] == ']') {
            break;
        } else {
            if (jsonIsspace(z[j])) {
                j += 1 + @as(u32, @intCast(strspn(z + j + 1, jsonSpaces)));
                if (z[j] == ',') {
                    continue :outer;
                } else if (z[j] == ']') {
                    break;
                }
            }
            x = jsonTranslateTextToBlob(pParse, j);
            if (x == -4) {
                j = pParse.iErr;
                continue :outer;
            }
            if (x == -3) {
                j = pParse.iErr;
                break;
            }
        }
        pParse.iErr = j;
        return -1;
    }
    _ = jsonBlobChangePayloadSize(pParse, iThis, pParse.nBlob - iStart);
    pParse.iDepth -= 1;
    return @intCast(j + 1);
}

fn jsonConvertTextToBlob(pParse: *JsonParse, pCtx: ?*Ctx) c_int {
    const zJson = pParse.zJson.?;
    var i = jsonTranslateTextToBlob(pParse, 0);
    if (pParse.oom != 0) i = -1;
    if (i > 0) {
        var ui: u32 = @intCast(i);
        while (jsonIsspace(zJson[ui])) ui += 1;
        if (zJson[ui] != 0) {
            ui += @intCast(json5Whitespace(zJson + ui));
            if (zJson[ui] != 0) {
                if (pCtx) |c| sqlite3_result_error(c, "malformed JSON", -1);
                jsonParseReset(pParse);
                return 1;
            }
            pParse.hasNonstd = 1;
        }
        return 0;
    }
    if (i <= 0) {
        if (pCtx) |c| {
            if (pParse.oom != 0) {
                sqlite3_result_error_nomem(c);
            } else {
                sqlite3_result_error(c, "malformed JSON", -1);
            }
        }
        jsonParseReset(pParse);
        return 1;
    }
    return 0;
}

fn jsonReturnStringAsBlob(pStr: *JsonString) void {
    var px: JsonParse = .{};
    px.zJson = pStr.zBuf;
    px.nJson = @intCast(pStr.nUsed);
    px.db = sqlite3_context_db_handle(pStr.pCtx);
    _ = jsonTranslateTextToBlob(&px, 0);
    if (px.oom != 0) {
        sqlite3DbFree(px.db, px.aBlob);
        sqlite3_result_error_nomem(pStr.pCtx);
    } else {
        sqlite3_result_blob(pStr.pCtx, px.aBlob, @intCast(px.nBlob), SQLITE_DYNAMIC);
    }
}

fn jsonTranslateBlobToText(pParse: *JsonParse, i: u32, pOut: *JsonString) u32 {
    var sz: u32 = undefined;
    var n: u32 = undefined;
    var j: u32 = undefined;
    var iEnd: u32 = undefined;
    n = jsonbPayloadSize(pParse, i, &sz);
    if (n == 0) {
        pOut.eErr |= JSTRING_MALFORMED;
        return pParse.nBlob + 1;
    }
    switch (pParse.aBlob.?[i] & 0x0f) {
        JSONB_NULL => {
            jsonAppendRawNZ(pOut, "null", 4);
            return i + 1;
        },
        JSONB_TRUE => {
            jsonAppendRawNZ(pOut, "true", 4);
            return i + 1;
        },
        JSONB_FALSE => {
            jsonAppendRawNZ(pOut, "false", 5);
            return i + 1;
        },
        JSONB_INT, JSONB_FLOAT => {
            if (sz == 0) {
                pOut.eErr |= JSTRING_MALFORMED;
                return i + n + sz;
            }
            jsonAppendRaw(pOut, pParse.aBlob.? + i + n, sz);
        },
        JSONB_INT5 => {
            var k: u32 = 2;
            var u: u64 = 0;
            const zIn = pParse.aBlob.? + i + n;
            var bOverflow: bool = false;
            if (sz == 0) {
                pOut.eErr |= JSTRING_MALFORMED;
                return i + n + sz;
            }
            if (zIn[0] == '-') {
                jsonAppendChar(pOut, '-');
                k += 1;
            } else if (zIn[0] == '+') {
                k += 1;
            }
            while (k < sz) : (k += 1) {
                if (!isxdigit(zIn[k])) {
                    pOut.eErr |= JSTRING_MALFORMED;
                    break;
                } else if ((u >> 60) != 0) {
                    bOverflow = true;
                } else {
                    u = u *% 16 +% sqlite3HexToInt(zIn[k]);
                }
            }
            if (bOverflow) {
                jsonPrintf(100, pOut, "9.0e999", .{});
            } else {
                jsonPrintf(100, pOut, "%llu", .{u});
            }
        },
        JSONB_FLOAT5 => {
            var k: u32 = 0;
            const zIn = pParse.aBlob.? + i + n;
            if (sz == 0) {
                pOut.eErr |= JSTRING_MALFORMED;
                return i + n + sz;
            }
            if (zIn[0] == '-') {
                jsonAppendChar(pOut, '-');
                k += 1;
            }
            if (zIn[k] == '.') {
                jsonAppendChar(pOut, '0');
            }
            while (k < sz) : (k += 1) {
                jsonAppendChar(pOut, zIn[k]);
                if (zIn[k] == '.' and (k + 1 == sz or !isdigit(zIn[k + 1]))) {
                    jsonAppendChar(pOut, '0');
                }
            }
        },
        JSONB_TEXT, JSONB_TEXTJ => {
            if (pOut.nUsed + sz + 2 <= pOut.nAlloc or jsonStringGrow(pOut, sz + 2) == 0) {
                const nu: usize = @intCast(pOut.nUsed);
                pOut.zBuf[nu] = '"';
                @memcpy(pOut.zBuf[nu + 1 ..][0..sz], (pParse.aBlob.? + i + n)[0..sz]);
                pOut.zBuf[nu + sz + 1] = '"';
                pOut.nUsed += sz + 2;
            }
        },
        JSONB_TEXT5 => {
            var zIn = pParse.aBlob.? + i + n;
            var sz2: u32 = sz;
            jsonAppendChar(pOut, '"');
            while (sz2 > 0) {
                var k: u32 = 0;
                while (k < sz2 and (jsonIsOk[zIn[k]] != 0 or zIn[k] == '\'')) k += 1;
                if (k > 0) {
                    jsonAppendRawNZ(pOut, zIn, k);
                    if (k >= sz2) break;
                    zIn += k;
                    sz2 -= k;
                }
                if (zIn[0] == '"') {
                    jsonAppendRawNZ(pOut, "\\\"", 2);
                    zIn += 1;
                    sz2 -= 1;
                    continue;
                }
                if (zIn[0] <= 0x1f) {
                    if (pOut.nUsed + 7 > pOut.nAlloc and jsonStringGrow(pOut, 7) != 0) break;
                    jsonAppendControlChar(pOut, zIn[0]);
                    zIn += 1;
                    sz2 -= 1;
                    continue;
                }
                if (sz2 < 2) {
                    pOut.eErr |= JSTRING_MALFORMED;
                    break;
                }
                switch (zIn[1]) {
                    '\'' => jsonAppendChar(pOut, '\''),
                    'v' => jsonAppendRawNZ(pOut, "\\u000b", 6),
                    'x' => {
                        if (sz2 < 4) {
                            pOut.eErr |= JSTRING_MALFORMED;
                            sz2 = 2;
                        } else {
                            jsonAppendRawNZ(pOut, "\\u00", 4);
                            jsonAppendRawNZ(pOut, zIn + 2, 2);
                            zIn += 2;
                            sz2 -= 2;
                        }
                    },
                    '0' => jsonAppendRawNZ(pOut, "\\u0000", 6),
                    '\r' => {
                        if (sz2 > 2 and zIn[2] == '\n') {
                            zIn += 1;
                            sz2 -= 1;
                        }
                    },
                    '\n' => {},
                    0xe2 => {
                        if (sz2 < 4 or 0x80 != zIn[2] or (0xa8 != zIn[3] and 0xa9 != zIn[3])) {
                            pOut.eErr |= JSTRING_MALFORMED;
                            sz2 = 2;
                        } else {
                            zIn += 2;
                            sz2 -= 2;
                        }
                    },
                    else => jsonAppendRawNZ(pOut, zIn, 2),
                }
                zIn += 2;
                sz2 -= 2;
            }
            jsonAppendChar(pOut, '"');
        },
        JSONB_TEXTRAW => {
            jsonAppendString(pOut, pParse.aBlob.? + i + n, sz);
        },
        JSONB_ARRAY => {
            jsonAppendChar(pOut, '[');
            j = i + n;
            iEnd = j + sz;
            pParse.iDepth += 1;
            if (pParse.iDepth > JSON_MAX_DEPTH) jsonStringTooDeep(pOut);
            while (j < iEnd and pOut.eErr == 0) {
                j = jsonTranslateBlobToText(pParse, j, pOut);
                jsonAppendChar(pOut, ',');
            }
            pParse.iDepth -= 1;
            if (j > iEnd) pOut.eErr |= JSTRING_MALFORMED;
            if (sz > 0) jsonStringTrimOneChar(pOut);
            jsonAppendChar(pOut, ']');
        },
        JSONB_OBJECT => {
            var x: u32 = 0;
            jsonAppendChar(pOut, '{');
            j = i + n;
            iEnd = j + sz;
            pParse.iDepth += 1;
            if (pParse.iDepth > JSON_MAX_DEPTH) jsonStringTooDeep(pOut);
            while (j < iEnd and pOut.eErr == 0) {
                j = jsonTranslateBlobToText(pParse, j, pOut);
                jsonAppendChar(pOut, if ((x & 1) != 0) ',' else ':');
                x += 1;
            }
            pParse.iDepth -= 1;
            if ((x & 1) != 0 or j > iEnd) pOut.eErr |= JSTRING_MALFORMED;
            if (sz > 0) jsonStringTrimOneChar(pOut);
            jsonAppendChar(pOut, '}');
        },
        else => {
            pOut.eErr |= JSTRING_MALFORMED;
        },
    }
    return i + n + sz;
}

const JsonPretty = struct {
    pParse: *JsonParse = undefined,
    pOut: *JsonString = undefined,
    zIndent: [*:0]const u8 = "",
    szIndent: u32 = 0,
    nIndent: u32 = 0,
};

fn jsonPrettyIndent(pPretty: *JsonPretty) void {
    var jj: u32 = 0;
    while (jj < pPretty.nIndent) : (jj += 1) {
        jsonAppendRaw(pPretty.pOut, pPretty.zIndent, pPretty.szIndent);
    }
}

fn jsonTranslateBlobToPrettyText(pPretty: *JsonPretty, iA0: u32) u32 {
    var i = iA0;
    var sz: u32 = undefined;
    var n: u32 = undefined;
    var j: u32 = undefined;
    var iEnd: u32 = undefined;
    const pParse = pPretty.pParse;
    const pOut = pPretty.pOut;
    n = jsonbPayloadSize(pParse, i, &sz);
    if (n == 0) {
        pOut.eErr |= JSTRING_MALFORMED;
        return pParse.nBlob + 1;
    }
    switch (pParse.aBlob.?[i] & 0x0f) {
        JSONB_ARRAY => {
            j = i + n;
            iEnd = j + sz;
            jsonAppendChar(pOut, '[');
            if (j < iEnd) {
                jsonAppendChar(pOut, '\n');
                pPretty.nIndent += 1;
                if (pPretty.nIndent >= JSON_MAX_DEPTH) jsonStringTooDeep(pOut);
                while (pOut.eErr == 0) {
                    jsonPrettyIndent(pPretty);
                    j = jsonTranslateBlobToPrettyText(pPretty, j);
                    if (j >= iEnd) break;
                    jsonAppendRawNZ(pOut, ",\n", 2);
                }
                jsonAppendChar(pOut, '\n');
                pPretty.nIndent -= 1;
                jsonPrettyIndent(pPretty);
            }
            jsonAppendChar(pOut, ']');
            i = iEnd;
        },
        JSONB_OBJECT => {
            j = i + n;
            iEnd = j + sz;
            jsonAppendChar(pOut, '{');
            if (j < iEnd) {
                jsonAppendChar(pOut, '\n');
                pPretty.nIndent += 1;
                if (pPretty.nIndent >= JSON_MAX_DEPTH) jsonStringTooDeep(pOut);
                pParse.iDepth = @truncate(pPretty.nIndent);
                while (pOut.eErr == 0) {
                    jsonPrettyIndent(pPretty);
                    j = jsonTranslateBlobToText(pParse, j, pOut);
                    if (j > iEnd) {
                        pOut.eErr |= JSTRING_MALFORMED;
                        break;
                    }
                    jsonAppendRawNZ(pOut, ": ", 2);
                    j = jsonTranslateBlobToPrettyText(pPretty, j);
                    if (j >= iEnd) break;
                    jsonAppendRawNZ(pOut, ",\n", 2);
                }
                jsonAppendChar(pOut, '\n');
                pPretty.nIndent -= 1;
                jsonPrettyIndent(pPretty);
            }
            jsonAppendChar(pOut, '}');
            i = iEnd;
        },
        else => {
            i = jsonTranslateBlobToText(pParse, i, pOut);
        },
    }
    return i;
}

fn jsonbArrayCount(pParse: *JsonParse, iRoot: u32) u32 {
    var n: u32 = undefined;
    var sz: u32 = 0;
    var i: u32 = undefined;
    var iEnd: u32 = undefined;
    var k: u32 = 0;
    n = jsonbPayloadSize(pParse, iRoot, &sz);
    iEnd = iRoot + n + sz;
    i = iRoot + n;
    while (n > 0 and i < iEnd) : ({
        i += sz + n;
        k += 1;
    }) {
        n = jsonbPayloadSize(pParse, i, &sz);
    }
    return k;
}

fn jsonAfterEditSizeAdjust(pParse: *JsonParse, iRoot: u32) void {
    var sz: u32 = 0;
    const nBlob = pParse.nBlob;
    pParse.nBlob = pParse.nBlobAlloc;
    _ = jsonbPayloadSize(pParse, iRoot, &sz);
    pParse.nBlob = nBlob;
    sz = @bitCast(@as(i32, @bitCast(sz)) +% pParse.delta);
    pParse.delta += jsonBlobChangePayloadSize(pParse, iRoot, sz);
}

fn jsonBlobOverwrite(aOut: [*]u8, aIns: [*]const u8, nIns: u32, d: u32) c_int {
    const aType = [_]u8{ 0xc0, 0xd0, 0, 0xe0, 0, 0, 0, 0xf0 };
    var i: u32 = undefined;
    var szHdr: u8 = undefined;
    if ((aIns[0] & 0x0f) <= 2) return 0;
    switch (aIns[0] >> 4) {
        12 => {
            if (((@as(u32, 1) << @intCast(d)) & 0x8a) == 0) return 0;
            i = d + 2;
            szHdr = 2;
        },
        13 => {
            if (d != 2 and d != 6) return 0;
            i = d + 3;
            szHdr = 3;
        },
        14 => {
            if (d != 4) return 0;
            i = 9;
            szHdr = 5;
        },
        15 => return 0,
        else => {
            if (((@as(u32, 1) << @intCast(d)) & 0x116) == 0) return 0;
            i = d + 1;
            szHdr = 1;
        },
    }
    aOut[0] = (aIns[0] & 0x0f) | aType[i - 2];
    @memcpy(aOut[i..][0 .. nIns - szHdr], aIns[szHdr..][0 .. nIns - szHdr]);
    var szPayload: u32 = nIns - szHdr;
    while (true) {
        i -= 1;
        aOut[i] = @truncate(szPayload & 0xff);
        if (i == 1) break;
        szPayload >>= 8;
    }
    return 1;
}

fn jsonBlobEdit(pParse: *JsonParse, iDel: u32, nDel: u32, aIns: ?[*]const u8, nIns: u32) void {
    const d: i64 = @as(i64, nIns) - @as(i64, nDel);
    if (d < 0 and d >= -8 and aIns != null and
        jsonBlobOverwrite(pParse.aBlob.? + iDel, aIns.?, nIns, @intCast(-d)) != 0)
    {
        return;
    }
    if (d != 0) {
        if (@as(i64, pParse.nBlob) + d > pParse.nBlobAlloc) {
            _ = jsonBlobExpand(pParse, @intCast(@as(i64, pParse.nBlob) + d));
            if (pParse.oom != 0) return;
        }
        const cnt: usize = pParse.nBlob - (iDel + nDel);
        // memmove(&aBlob[iDel+nIns], &aBlob[iDel+nDel], cnt)
        if (d > 0) {
            std.mem.copyBackwards(u8, pParse.aBlob.?[iDel + nIns ..][0..cnt], pParse.aBlob.?[iDel + nDel ..][0..cnt]);
        } else {
            std.mem.copyForwards(u8, pParse.aBlob.?[iDel + nIns ..][0..cnt], pParse.aBlob.?[iDel + nDel ..][0..cnt]);
        }
        pParse.nBlob = @truncate(@as(u64, @bitCast(@as(i64, pParse.nBlob) + d)));
        pParse.delta = @truncate(@as(i64, pParse.delta) + d);
    }
    if (nIns != 0 and aIns != null) {
        @memcpy(pParse.aBlob.?[iDel..][0..nIns], aIns.?[0..nIns]);
    }
}

fn jsonBytesToBypass(z: [*]const u8, n: u32) u32 {
    var i: u32 = 0;
    while (i + 1 < n) {
        if (z[i] != '\\') return i;
        if (z[i + 1] == '\n') {
            i += 2;
            continue;
        }
        if (z[i + 1] == '\r') {
            if (i + 2 < n and z[i + 2] == '\n') {
                i += 3;
            } else {
                i += 2;
            }
            continue;
        }
        if (0xe2 == z[i + 1] and i + 3 < n and 0x80 == z[i + 2] and
            (0xa8 == z[i + 3] or 0xa9 == z[i + 3]))
        {
            i += 4;
            continue;
        }
        break;
    }
    return i;
}

fn jsonUnescapeOneChar(z: [*]const u8, n: u32, piOut: *u32) u32 {
    if (n < 2) {
        piOut.* = JSON_INVALID_CHAR;
        return n;
    }
    switch (z[1]) {
        'u' => {
            if (n < 6) {
                piOut.* = JSON_INVALID_CHAR;
                return n;
            }
            const v = jsonHexToInt4(z + 2);
            if ((v & 0xfc00) == 0xd800 and n >= 12 and z[6] == '\\' and z[7] == 'u') {
                const vlo = jsonHexToInt4(z + 8);
                if ((vlo & 0xfc00) == 0xdc00) {
                    piOut.* = ((v & 0x3ff) << 10) + (vlo & 0x3ff) + 0x10000;
                    return 12;
                }
            }
            piOut.* = v;
            return 6;
        },
        'b' => {
            piOut.* = 0x08;
            return 2;
        },
        'f' => {
            piOut.* = 0x0c;
            return 2;
        },
        'n' => {
            piOut.* = '\n';
            return 2;
        },
        'r' => {
            piOut.* = '\r';
            return 2;
        },
        't' => {
            piOut.* = '\t';
            return 2;
        },
        'v' => {
            piOut.* = 0x0b;
            return 2;
        },
        '0' => {
            piOut.* = if (n > 2 and isdigit(z[2])) JSON_INVALID_CHAR else 0;
            return 2;
        },
        '\'', '"', '/', '\\' => {
            piOut.* = z[1];
            return 2;
        },
        'x' => {
            if (n < 4) {
                piOut.* = JSON_INVALID_CHAR;
                return n;
            }
            piOut.* = (@as(u32, jsonHexToInt(z[2])) << 4) | jsonHexToInt(z[3]);
            return 4;
        },
        0xe2, '\r', '\n' => {
            const nSkip = jsonBytesToBypass(z, n);
            if (nSkip == 0) {
                piOut.* = JSON_INVALID_CHAR;
                return n;
            } else if (nSkip == n) {
                piOut.* = 0;
                return n;
            } else if (z[nSkip] == '\\') {
                return nSkip + jsonUnescapeOneChar(z + nSkip, n - nSkip, piOut);
            } else {
                const szc = sqlite3Utf8ReadLimited(z + nSkip, @intCast(n - nSkip), piOut);
                return nSkip + @as(u32, @intCast(szc));
            }
        },
        else => {
            piOut.* = JSON_INVALID_CHAR;
            return 2;
        },
    }
}

fn jsonLabelCompareEscaped(
    zLeft0: [*]const u8,
    nLeft0: u32,
    rawLeft: bool,
    zRight0: [*]const u8,
    nRight0: u32,
    rawRight: bool,
) c_int {
    var zLeft = zLeft0;
    var nLeft = nLeft0;
    var zRight = zRight0;
    var nRight = nRight0;
    var cLeft: u32 = undefined;
    var cRight: u32 = undefined;
    while (true) {
        if (nLeft == 0) {
            cLeft = 0;
        } else if (rawLeft or zLeft[0] != '\\') {
            cLeft = zLeft[0];
            if (cLeft >= 0xc0) {
                const sz: u32 = @intCast(sqlite3Utf8ReadLimited(zLeft, @intCast(nLeft), &cLeft));
                zLeft += sz;
                nLeft -= sz;
            } else {
                zLeft += 1;
                nLeft -= 1;
            }
        } else {
            const nn = jsonUnescapeOneChar(zLeft, nLeft, &cLeft);
            zLeft += nn;
            nLeft -= nn;
        }
        if (nRight == 0) {
            cRight = 0;
        } else if (rawRight or zRight[0] != '\\') {
            cRight = zRight[0];
            if (cRight >= 0xc0) {
                const sz: u32 = @intCast(sqlite3Utf8ReadLimited(zRight, @intCast(nRight), &cRight));
                zRight += sz;
                nRight -= sz;
            } else {
                zRight += 1;
                nRight -= 1;
            }
        } else {
            const nn = jsonUnescapeOneChar(zRight, nRight, &cRight);
            zRight += nn;
            nRight -= nn;
        }
        if (cLeft != cRight) return 0;
        if (cLeft == 0) return 1;
    }
}

fn jsonLabelCompare(
    zLeft: [*]const u8,
    nLeft: u32,
    rawLeft: bool,
    zRight: [*]const u8,
    nRight: u32,
    rawRight: bool,
) c_int {
    if (rawLeft and rawRight) {
        if (nLeft != nRight) return 0;
        return @intFromBool(memcmp(zLeft, zRight, nLeft) == 0);
    } else {
        return jsonLabelCompareEscaped(zLeft, nLeft, rawLeft, zRight, nRight, rawRight);
    }
}

fn jsonCreateEditSubstructure(pParse: *JsonParse, pIns: *JsonParse, zTail: [*]const u8) u32 {
    var rc: u32 = 0;
    pIns.* = .{};
    pIns.db = pParse.db;
    if (zTail[0] == 0) {
        pIns.aBlob = pParse.aIns;
        pIns.nBlob = pParse.nIns;
        rc = 0;
    } else {
        pIns.nBlob = 1;
        pIns.aBlob = @ptrCast(&emptyObjectStatic[@intFromBool(zTail[0] == '.')]);
        pIns.eEdit = pParse.eEdit;
        pIns.nIns = pParse.nIns;
        pIns.aIns = pParse.aIns;
        pIns.iDepth = pParse.iDepth + 1;
        if (pIns.iDepth >= JSON_MAX_DEPTH) return JSON_LOOKUP_TOODEEP;
        rc = jsonLookupStep(pIns, 0, zTail, 0);
        pParse.iDepth -= 1;
        pParse.oom |= pIns.oom;
    }
    return rc;
}

fn jsonLookupStep(pParse: *JsonParse, iRoot0: u32, zPath0: [*]const u8, iLabel: u32) u32 {
    var iRoot = iRoot0;
    var zPath = zPath0;
    var i: u32 = undefined;
    var j: u32 = undefined;
    var k: u32 = undefined;
    var nKey: u32 = undefined;
    var sz: u32 = 0;
    var n: u32 = undefined;
    var iEnd: u32 = undefined;
    var rc: u32 = undefined;
    var zKey: [*]const u8 = undefined;
    var x: u8 = undefined;

    if (zPath[0] == 0) {
        if (pParse.eEdit != 0 and jsonBlobMakeEditable(pParse, pParse.nIns) != 0) {
            n = jsonbPayloadSize(pParse, iRoot, &sz);
            sz += n;
            if (pParse.eEdit == JEDIT_DEL) {
                if (iLabel > 0) {
                    sz += iRoot - iLabel;
                    iRoot = iLabel;
                }
                jsonBlobEdit(pParse, iRoot, sz, null, 0);
            } else if (pParse.eEdit == JEDIT_INS) {
                // no-op
            } else if (pParse.eEdit == JEDIT_AINS) {
                if ((zPath - 1)[0] != ']') {
                    return JSON_LOOKUP_NOTARRAY;
                } else {
                    jsonBlobEdit(pParse, iRoot, 0, pParse.aIns, pParse.nIns);
                }
            } else {
                jsonBlobEdit(pParse, iRoot, sz, pParse.aIns, pParse.nIns);
            }
        }
        pParse.iLabel = iLabel;
        return iRoot;
    }
    if (zPath[0] == '.') {
        var rawKey: bool = true;
        x = pParse.aBlob.?[iRoot];
        zPath += 1;
        if (zPath[0] == '"') {
            zKey = zPath + 1;
            i = 1;
            while (zPath[i] != 0 and zPath[i] != '"') : (i += 1) {
                if (zPath[i] == '\\' and zPath[i + 1] != 0) i += 1;
            }
            nKey = i - 1;
            if (zPath[i] != 0) {
                i += 1;
            } else {
                return JSON_LOOKUP_PATHERROR;
            }
            rawKey = memchr(zKey, '\\', nKey) == null;
        } else {
            zKey = zPath;
            i = 0;
            while (zPath[i] != 0 and zPath[i] != '.' and zPath[i] != '[') : (i += 1) {}
            nKey = i;
            if (nKey == 0) return JSON_LOOKUP_PATHERROR;
        }
        if ((x & 0x0f) != JSONB_OBJECT) return JSON_LOOKUP_NOTFOUND;
        n = jsonbPayloadSize(pParse, iRoot, &sz);
        j = iRoot + n;
        iEnd = j + sz;
        while (j < iEnd) {
            x = pParse.aBlob.?[j] & 0x0f;
            if (x < JSONB_TEXT or x > JSONB_TEXTRAW) return JSON_LOOKUP_ERROR;
            n = jsonbPayloadSize(pParse, j, &sz);
            if (n == 0) return JSON_LOOKUP_ERROR;
            k = j + n;
            if (k + sz >= iEnd) return JSON_LOOKUP_ERROR;
            const zLabel = pParse.aBlob.? + k;
            const rawLabel = x == JSONB_TEXT or x == JSONB_TEXTRAW;
            if (jsonLabelCompare(zKey, nKey, rawKey, zLabel, sz, rawLabel) != 0) {
                const v = k + sz;
                if ((pParse.aBlob.?[v] & 0x0f) > JSONB_OBJECT) return JSON_LOOKUP_ERROR;
                n = jsonbPayloadSize(pParse, v, &sz);
                if (n == 0 or v + n + sz > iEnd) return JSON_LOOKUP_ERROR;
                pParse.iDepth += 1;
                if (pParse.iDepth >= JSON_MAX_DEPTH) return JSON_LOOKUP_TOODEEP;
                rc = jsonLookupStep(pParse, v, zPath + i, j);
                pParse.iDepth -= 1;
                if (pParse.delta != 0) jsonAfterEditSizeAdjust(pParse, iRoot);
                return rc;
            }
            j = k + sz;
            if ((pParse.aBlob.?[j] & 0x0f) > JSONB_OBJECT) return JSON_LOOKUP_ERROR;
            n = jsonbPayloadSize(pParse, j, &sz);
            if (n == 0) return JSON_LOOKUP_ERROR;
            j += n + sz;
        }
        if (j > iEnd) return JSON_LOOKUP_ERROR;
        if (pParse.eEdit >= JEDIT_INS) {
            var v: JsonParse = undefined;
            var ix: JsonParse = .{};
            if (pParse.eEdit == JEDIT_AINS and sqlite3_strglob("*]", @ptrCast(zPath + i)) != 0) {
                return JSON_LOOKUP_NOTARRAY;
            }
            ix.db = pParse.db;
            jsonBlobAppendNode(&ix, if (rawKey) JSONB_TEXTRAW else JSONB_TEXT5, nKey, null);
            pParse.oom |= ix.oom;
            rc = jsonCreateEditSubstructure(pParse, &v, zPath + i);
            if (!JSON_LOOKUP_ISERROR(rc) and jsonBlobMakeEditable(pParse, ix.nBlob + nKey + v.nBlob) != 0) {
                const nIns = ix.nBlob + nKey + v.nBlob;
                jsonBlobEdit(pParse, j, 0, null, nIns);
                if (pParse.oom == 0) {
                    @memcpy(pParse.aBlob.?[j..][0..ix.nBlob], ix.aBlob.?[0..ix.nBlob]);
                    k = j + ix.nBlob;
                    @memcpy(pParse.aBlob.?[k..][0..nKey], zKey[0..nKey]);
                    k += nKey;
                    @memcpy(pParse.aBlob.?[k..][0..v.nBlob], v.aBlob.?[0..v.nBlob]);
                    if (pParse.delta != 0) jsonAfterEditSizeAdjust(pParse, iRoot);
                }
            }
            jsonParseReset(&v);
            jsonParseReset(&ix);
            return rc;
        }
    } else if (zPath[0] == '[') {
        var kk: u64 = 0;
        x = pParse.aBlob.?[iRoot] & 0x0f;
        if (x != JSONB_ARRAY) return JSON_LOOKUP_NOTFOUND;
        n = jsonbPayloadSize(pParse, iRoot, &sz);
        i = 1;
        while (isdigit(zPath[i])) {
            if (kk < 0xffffffff) kk = kk *% 10 +% (zPath[i] - '0');
            i += 1;
        }
        if (i < 2 or zPath[i] != ']') {
            if (zPath[1] == '#') {
                kk = jsonbArrayCount(pParse, iRoot);
                i = 2;
                if (zPath[2] == '-' and isdigit(zPath[3])) {
                    var nn: u64 = 0;
                    i = 3;
                    while (true) {
                        if (nn < 0xffffffff) nn = nn *% 10 +% (zPath[i] - '0');
                        i += 1;
                        if (!isdigit(zPath[i])) break;
                    }
                    if (nn > kk) return JSON_LOOKUP_NOTFOUND;
                    kk -= nn;
                }
                if (zPath[i] != ']') return JSON_LOOKUP_PATHERROR;
            } else {
                return JSON_LOOKUP_PATHERROR;
            }
        }
        j = iRoot + n;
        iEnd = j + sz;
        while (j < iEnd) {
            if (kk == 0) {
                pParse.iDepth += 1;
                if (pParse.iDepth >= JSON_MAX_DEPTH) return JSON_LOOKUP_TOODEEP;
                rc = jsonLookupStep(pParse, j, zPath + i + 1, 0);
                pParse.iDepth -= 1;
                if (pParse.delta != 0) jsonAfterEditSizeAdjust(pParse, iRoot);
                return rc;
            }
            kk -= 1;
            n = jsonbPayloadSize(pParse, j, &sz);
            if (n == 0) return JSON_LOOKUP_ERROR;
            j += n + sz;
        }
        if (j > iEnd) return JSON_LOOKUP_ERROR;
        if (kk > 0) return JSON_LOOKUP_NOTFOUND;
        if (pParse.eEdit >= JEDIT_INS) {
            var v: JsonParse = undefined;
            rc = jsonCreateEditSubstructure(pParse, &v, zPath + i + 1);
            if (!JSON_LOOKUP_ISERROR(rc) and jsonBlobMakeEditable(pParse, v.nBlob) != 0) {
                jsonBlobEdit(pParse, j, 0, v.aBlob, v.nBlob);
            }
            jsonParseReset(&v);
            if (pParse.delta != 0) jsonAfterEditSizeAdjust(pParse, iRoot);
            return rc;
        }
    } else {
        return JSON_LOOKUP_PATHERROR;
    }
    return JSON_LOOKUP_NOTFOUND;
}

fn jsonReturnTextJsonFromBlob(ctx: ?*Ctx, aBlob: ?[*]const u8, nBlob: u32) void {
    if (aBlob == null) return;
    var x: JsonParse = .{};
    var s: JsonString = undefined;
    x.aBlob = @constCast(aBlob.?);
    x.nBlob = nBlob;
    jsonStringInit(&s, ctx);
    _ = jsonTranslateBlobToText(&x, 0, &s);
    jsonReturnString(&s, null, null);
}

fn jsonReturnFromBlob(pParse: *JsonParse, i: u32, pCtx: ?*Ctx, eMode0: c_int) void {
    var eMode = eMode0;
    var n: u32 = undefined;
    var sz: u32 = undefined;
    var rc: c_int = undefined;
    const db = sqlite3_context_db_handle(pCtx);

    n = jsonbPayloadSize(pParse, i, &sz);
    if (n == 0) {
        sqlite3_result_error(pCtx, "malformed JSON", -1);
        return;
    }
    const blk = struct {
        fn malformed(c: ?*Ctx) void {
            sqlite3_result_error(c, "malformed JSON", -1);
        }
        fn oom(c: ?*Ctx) void {
            sqlite3_result_error_nomem(c);
        }
    };
    switch (pParse.aBlob.?[i] & 0x0f) {
        JSONB_NULL => {
            if (sz != 0) return blk.malformed(pCtx);
            sqlite3_result_null(pCtx);
        },
        JSONB_TRUE => {
            if (sz != 0) return blk.malformed(pCtx);
            sqlite3_result_int(pCtx, 1);
        },
        JSONB_FALSE => {
            if (sz != 0) return blk.malformed(pCtx);
            sqlite3_result_int(pCtx, 0);
        },
        JSONB_INT5, JSONB_INT => {
            var iRes: i64 = 0;
            var bNeg: bool = false;
            if (sz == 0) return blk.malformed(pCtx);
            const xc = pParse.aBlob.?[i + n];
            if (xc == '-') {
                if (sz < 2) return blk.malformed(pCtx);
                n += 1;
                sz -= 1;
                bNeg = true;
            }
            const z = sqlite3DbStrNDup(db, pParse.aBlob.? + i + n, sz);
            if (z == null) return blk.oom(pCtx);
            rc = sqlite3DecOrHexToI64(z.?, &iRes);
            sqlite3DbFree(db, z);
            if (rc == 0) {
                if (iRes < 0) {
                    const r: f64 = @floatFromInt(@as(u64, @bitCast(iRes)));
                    sqlite3_result_double(pCtx, if (bNeg) -r else r);
                } else {
                    sqlite3_result_int64(pCtx, if (bNeg) -iRes else iRes);
                }
            } else if (rc == 3 and bNeg) {
                sqlite3_result_int64(pCtx, SMALLEST_INT64);
            } else if (rc == 1) {
                return blk.malformed(pCtx);
            } else {
                if (bNeg) {
                    n -= 1;
                    sz += 1;
                }
                return jsonReturnDouble(pParse, i, n, sz, pCtx, db);
            }
        },
        JSONB_FLOAT5, JSONB_FLOAT => {
            if (sz == 0) return blk.malformed(pCtx);
            return jsonReturnDouble(pParse, i, n, sz, pCtx, db);
        },
        JSONB_TEXTRAW, JSONB_TEXT => {
            sqlite3_result_text(pCtx, pParse.aBlob.? + i + n, @intCast(sz), SQLITE_TRANSIENT);
        },
        JSONB_TEXT5, JSONB_TEXTJ => {
            const z = pParse.aBlob.? + i + n;
            const nOut = sz;
            const zOut: [*]u8 = @ptrCast(sqlite3DbMallocRaw(db, @as(u64, nOut) + 1) orelse return blk.oom(pCtx));
            var iIn: u32 = 0;
            var iOut: u32 = 0;
            while (iIn < sz) : (iIn += 1) {
                const c = z[iIn];
                if (c == '\\') {
                    var v: u32 = 0;
                    const szEscape = jsonUnescapeOneChar(z + iIn, sz - iIn, &v);
                    if (v <= 0x7f) {
                        zOut[iOut] = @truncate(v);
                        iOut += 1;
                    } else if (v <= 0x7ff) {
                        zOut[iOut] = @truncate(0xc0 | (v >> 6));
                        zOut[iOut + 1] = @truncate(0x80 | (v & 0x3f));
                        iOut += 2;
                    } else if (v < 0x10000) {
                        zOut[iOut] = @truncate(0xe0 | (v >> 12));
                        zOut[iOut + 1] = @truncate(0x80 | ((v >> 6) & 0x3f));
                        zOut[iOut + 2] = @truncate(0x80 | (v & 0x3f));
                        iOut += 3;
                    } else if (v == JSON_INVALID_CHAR) {
                        // ignore
                    } else {
                        zOut[iOut] = @truncate(0xf0 | (v >> 18));
                        zOut[iOut + 1] = @truncate(0x80 | ((v >> 12) & 0x3f));
                        zOut[iOut + 2] = @truncate(0x80 | ((v >> 6) & 0x3f));
                        zOut[iOut + 3] = @truncate(0x80 | (v & 0x3f));
                        iOut += 4;
                    }
                    iIn += szEscape - 1;
                } else {
                    zOut[iOut] = c;
                    iOut += 1;
                }
            }
            zOut[iOut] = 0;
            sqlite3_result_text(pCtx, zOut, @intCast(iOut), SQLITE_DYNAMIC);
        },
        JSONB_ARRAY, JSONB_OBJECT => {
            if (eMode == 0) {
                if ((ptrToInt(sqlite3_user_data(pCtx)) & JSON_BLOB) != 0) {
                    eMode = 2;
                } else {
                    eMode = 1;
                }
            }
            if (eMode == 2) {
                sqlite3_result_blob(pCtx, pParse.aBlob.? + i, @intCast(sz + n), SQLITE_TRANSIENT);
            } else {
                jsonReturnTextJsonFromBlob(pCtx, pParse.aBlob.? + i, sz + n);
            }
        },
        else => return blk.malformed(pCtx),
    }
}

fn jsonReturnDouble(pParse: *JsonParse, i: u32, n: u32, sz: u32, pCtx: ?*Ctx, db: ?*anyopaque) void {
    var r: f64 = undefined;
    const z = sqlite3DbStrNDup(db, pParse.aBlob.? + i + n, sz);
    if (z == null) {
        sqlite3_result_error_nomem(pCtx);
        return;
    }
    const rc = sqlite3AtoF(z.?, &r);
    sqlite3DbFree(db, z);
    if (rc <= 0) {
        sqlite3_result_error(pCtx, "malformed JSON", -1);
        return;
    }
    sqlite3_result_double(pCtx, r);
}

fn jsonFunctionArgToBlob(ctx: ?*Ctx, pArg: ?*Val, pParse: *JsonParse) c_int {
    const eType = sqlite3_value_type(pArg);
    pParse.* = .{};
    pParse.db = sqlite3_context_db_handle(ctx);
    switch (eType) {
        SQLITE_BLOB => {
            if (jsonArgIsJsonb(pArg, pParse) == 0) {
                sqlite3_result_error(ctx, "JSON cannot hold BLOB values", -1);
                return 1;
            }
        },
        SQLITE_TEXT => {
            const zJsonOpt = sqlite3_value_text(pArg);
            const nJson = sqlite3_value_bytes(pArg);
            if (zJsonOpt == null) return 1;
            const zJson = zJsonOpt.?;
            if (sqlite3_value_subtype(pArg) == JSON_SUBTYPE) {
                pParse.zJson = @constCast(zJson);
                pParse.nJson = nJson;
                if (jsonConvertTextToBlob(pParse, ctx) != 0) {
                    sqlite3_result_error(ctx, "malformed JSON", -1);
                    sqlite3DbFree(pParse.db, pParse.aBlob);
                    pParse.* = .{};
                    return 1;
                }
            } else {
                jsonBlobAppendNode(pParse, JSONB_TEXTRAW, @intCast(nJson), zJson);
            }
        },
        SQLITE_FLOAT => {
            if (sqlite3IsNaN(sqlite3_value_double(pArg)) != 0) {
                jsonBlobAppendNode(pParse, JSONB_NULL, 0, null);
            } else {
                const nn = sqlite3_value_bytes(pArg);
                const zOpt = sqlite3_value_text(pArg);
                if (zOpt == null) return 1;
                const z = zOpt.?;
                if (z[0] == 'I') {
                    jsonBlobAppendNode(pParse, JSONB_FLOAT, 5, "9e999");
                } else if (z[0] == '-' and z[1] == 'I') {
                    jsonBlobAppendNode(pParse, JSONB_FLOAT, 6, "-9e999");
                } else {
                    jsonBlobAppendNode(pParse, JSONB_FLOAT, @intCast(nn), z);
                }
            }
        },
        SQLITE_INTEGER => {
            const nn = sqlite3_value_bytes(pArg);
            const zOpt = sqlite3_value_text(pArg);
            if (zOpt == null) return 1;
            jsonBlobAppendNode(pParse, JSONB_INT, @intCast(nn), zOpt.?);
        },
        else => {
            pParse.aBlob = &aNullBlob;
            pParse.nBlob = 1;
            return 0;
        },
    }
    if (pParse.oom != 0) {
        sqlite3_result_error_nomem(ctx);
        return 1;
    }
    return 0;
}

fn jsonReturnString(p: *JsonString, pParse: ?*JsonParse, ctx: ?*Ctx) void {
    _ = jsonStringTerminate(p);
    if (p.eErr == 0) {
        const flags = ptrToInt(sqlite3_user_data(p.pCtx));
        if (flags & JSON_BLOB != 0) {
            jsonReturnStringAsBlob(p);
        } else if (p.bStatic != 0) {
            sqlite3_result_text64(p.pCtx, p.zBuf, p.nUsed, SQLITE_TRANSIENT, SQLITE_UTF8);
        } else {
            if (pParse) |pp| {
                if (pp.bJsonIsRCStr == 0 and pp.nBlobAlloc > 0) {
                    pp.zJson = sqlite3RCStrRef(p.zBuf);
                    pp.nJson = @intCast(p.nUsed);
                    pp.bJsonIsRCStr = 1;
                    const rc = jsonCacheInsert(ctx, pp);
                    if (rc == SQLITE_NOMEM) {
                        sqlite3_result_error_nomem(ctx);
                        jsonStringReset(p);
                        return;
                    }
                }
            }
            sqlite3_result_text64(p.pCtx, sqlite3RCStrRef(p.zBuf), p.nUsed, RCStrUnrefDtor, SQLITE_UTF8);
        }
    } else if (p.eErr & JSTRING_OOM != 0) {
        sqlite3_result_error_nomem(p.pCtx);
    } else if (p.eErr & JSTRING_TOODEEP != 0) {
        // already in p.pCtx
    } else if (p.eErr & JSTRING_MALFORMED != 0) {
        sqlite3_result_error(p.pCtx, "malformed JSON", -1);
    }
    jsonStringReset(p);
}

// Append an sqlite3_value to the JSON string under construction.
fn jsonAppendSqlValue(p: *JsonString, pValue: ?*Val) void {
    switch (sqlite3_value_type(pValue)) {
        SQLITE_NULL => jsonAppendRawNZ(p, "null", 4),
        SQLITE_FLOAT => jsonPrintf(100, p, "%!0.17g", .{sqlite3_value_double(pValue)}),
        SQLITE_INTEGER => {
            const z = sqlite3_value_text(pValue);
            const nn: u32 = @intCast(sqlite3_value_bytes(pValue));
            if (z) |zp| jsonAppendRaw(p, zp, nn);
        },
        SQLITE_TEXT => {
            const z = sqlite3_value_text(pValue);
            const nn: u32 = @intCast(sqlite3_value_bytes(pValue));
            if (z) |zp| {
                if (sqlite3_value_subtype(pValue) == JSON_SUBTYPE) {
                    jsonAppendRaw(p, zp, nn);
                } else {
                    jsonAppendString(p, zp, nn);
                }
            }
        },
        else => {
            var px: JsonParse = .{};
            if (jsonArgIsJsonb(pValue, &px) != 0) {
                _ = jsonTranslateBlobToText(&px, 0, p);
            } else if (p.eErr == 0) {
                sqlite3_result_error(p.pCtx, "JSON cannot hold BLOB values", -1);
                p.eErr = JSTRING_ERR;
                jsonStringReset(p);
            }
        },
    }
}

fn jsonBadPathError(ctx: ?*Ctx, zPath: ?[*:0]const u8, rc: c_int) ?[*:0]u8 {
    var zMsg: ?[*:0]u8 = undefined;
    if (rc == @as(c_int, @bitCast(JSON_LOOKUP_NOTARRAY))) {
        zMsg = sqlite3_mprintf("not an array element: %Q", zPath);
    } else if (rc == @as(c_int, @bitCast(JSON_LOOKUP_ERROR))) {
        zMsg = sqlite3_mprintf("malformed JSON");
    } else if (rc == @as(c_int, @bitCast(JSON_LOOKUP_TOODEEP))) {
        zMsg = sqlite3_mprintf("JSON path too deep");
    } else {
        zMsg = sqlite3_mprintf("bad JSON path: %Q", zPath);
    }
    if (ctx == null) return zMsg;
    if (zMsg) |m| {
        sqlite3_result_error(ctx, m, -1);
        sqlite3_free(m);
    } else {
        sqlite3_result_error_nomem(ctx);
    }
    return null;
}

fn jsonInsertIntoBlob(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val, eEdit: u8) void {
    var rc: u32 = 0;
    var zPath: ?[*:0]const u8 = null;
    const flgs: u32 = if (argc == 1) 0 else JSON_EDITABLE;
    const p = jsonParseFuncArg(ctx, argv[0], flgs) orelse return;
    var i: c_int = 1;
    while (i < argc - 1) : (i += 2) {
        if (sqlite3_value_type(argv[@intCast(i)]) == SQLITE_NULL) continue;
        zPath = sqlite3_value_text(argv[@intCast(i)]);
        if (zPath == null) {
            sqlite3_result_error_nomem(ctx);
            jsonParseFree(p);
            return;
        }
        if (zPath.?[0] != '$') {
            jsonParseFree(p);
            _ = jsonBadPathError(ctx, zPath, @bitCast(rc));
            return;
        }
        var ax: JsonParse = undefined;
        if (jsonFunctionArgToBlob(ctx, argv[@intCast(i + 1)], &ax) != 0) {
            jsonParseReset(&ax);
            jsonParseFree(p);
            return;
        }
        if (zPath.?[1] == 0) {
            if (eEdit == JEDIT_REPL or eEdit == JEDIT_SET) {
                jsonBlobEdit(p, 0, p.nBlob, ax.aBlob, ax.nBlob);
            }
            rc = 0;
        } else {
            p.eEdit = eEdit;
            p.nIns = ax.nBlob;
            p.aIns = ax.aBlob;
            p.delta = 0;
            p.iDepth = 0;
            rc = jsonLookupStep(p, 0, zPath.? + 1, 0);
        }
        jsonParseReset(&ax);
        if (rc == JSON_LOOKUP_NOTFOUND) continue;
        if (JSON_LOOKUP_ISERROR(rc)) {
            jsonParseFree(p);
            _ = jsonBadPathError(ctx, zPath, @bitCast(rc));
            return;
        }
    }
    jsonReturnParse(ctx, p);
    jsonParseFree(p);
}

fn jsonArgIsJsonb(pArg: ?*Val, p: *JsonParse) c_int {
    var sz: u32 = 0;
    if (sqlite3_value_type(pArg) != SQLITE_BLOB) return 0;
    p.aBlob = @constCast(sqlite3_value_blob(pArg));
    p.nBlob = @intCast(sqlite3_value_bytes(pArg));
    if (p.nBlob > 0 and p.aBlob != null) {
        const c = p.aBlob.?[0];
        if ((c & 0x0f) <= JSONB_OBJECT) {
            const n = jsonbPayloadSize(p, 0, &sz);
            if (n > 0 and sz + n == p.nBlob and ((c & 0x0f) > JSONB_FALSE or sz == 0) and
                (sz > 7 or (c != 0x7b and c != 0x5b and !isdigit(c)) or
                    jsonbValidityCheck(p, 0, p.nBlob, 1) == 0))
            {
                return 1;
            }
        }
    }
    p.aBlob = null;
    p.nBlob = 0;
    return 0;
}

fn jsonParseFuncArg(ctx: ?*Ctx, pArg: ?*Val, flgs: u32) ?*JsonParse {
    var p: ?*JsonParse = null;
    var pFromCache: ?*JsonParse = null;
    const eType = sqlite3_value_type(pArg);
    if (eType == SQLITE_NULL) return null;
    pFromCache = jsonCacheSearch(ctx, pArg);
    if (pFromCache) |pfc| {
        pfc.nJPRef += 1;
        if ((flgs & JSON_EDITABLE) == 0) return pfc;
    }
    const db = sqlite3_context_db_handle(ctx);
    while (true) { // rebuild_from_cache loop
        p = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @sizeOf(JsonParse))));
        if (p == null) return jsonPfaOom(ctx, pFromCache, null);
        const pp = p.?;
        pp.* = .{};
        pp.db = db;
        pp.nJPRef = 1;
        if (pFromCache) |pfc| {
            const nBlob = pfc.nBlob;
            pp.aBlob = @ptrCast(sqlite3DbMallocRaw(db, nBlob) orelse return jsonPfaOom(ctx, pFromCache, p));
            @memcpy(pp.aBlob.?[0..nBlob], pfc.aBlob.?[0..nBlob]);
            pp.nBlobAlloc = nBlob;
            pp.nBlob = nBlob;
            pp.hasNonstd = pfc.hasNonstd;
            jsonParseFree(pfc);
            return pp;
        }
        if (eType == SQLITE_BLOB) {
            if (jsonArgIsJsonb(pArg, pp) != 0) {
                if ((flgs & JSON_EDITABLE) != 0 and jsonBlobMakeEditable(pp, 0) == 0) {
                    return jsonPfaOom(ctx, pFromCache, p);
                }
                return pp;
            }
        }
        pp.zJson = @constCast(sqlite3_value_text(pArg));
        pp.nJson = sqlite3_value_bytes(pArg);
        if (dbMallocFailed(db)) return jsonPfaOom(ctx, pFromCache, p);
        if (pp.nJson == 0) return jsonPfaMalformed(ctx, flgs, pp);
        if (jsonConvertTextToBlob(pp, if (flgs & JSON_KEEPERROR != 0) null else ctx) != 0) {
            if (flgs & JSON_KEEPERROR != 0) {
                pp.nErr = 1;
                return pp;
            } else {
                jsonParseFree(pp);
                return null;
            }
        } else {
            const isRCStr = sqlite3ValueIsOfClass(pArg, RCStrUnrefDtor) != 0;
            if (!isRCStr) {
                const zNew = sqlite3RCStrNew(@intCast(pp.nJson)) orelse return jsonPfaOom(ctx, pFromCache, p);
                @memcpy(zNew[0..@intCast(pp.nJson)], pp.zJson.?[0..@intCast(pp.nJson)]);
                pp.zJson = zNew;
                pp.zJson.?[@intCast(pp.nJson)] = 0;
            } else {
                _ = sqlite3RCStrRef(pp.zJson);
            }
            pp.bJsonIsRCStr = 1;
            const rc = jsonCacheInsert(ctx, pp);
            if (rc == SQLITE_NOMEM) return jsonPfaOom(ctx, pFromCache, p);
            if (flgs & JSON_EDITABLE != 0) {
                pFromCache = pp;
                p = null;
                continue; // rebuild_from_cache
            }
        }
        return pp;
    }
}

fn jsonPfaMalformed(ctx: ?*Ctx, flgs: u32, p: *JsonParse) ?*JsonParse {
    if (flgs & JSON_KEEPERROR != 0) {
        p.nErr = 1;
        return p;
    } else {
        jsonParseFree(p);
        sqlite3_result_error(ctx, "malformed JSON", -1);
        return null;
    }
}

fn jsonPfaOom(ctx: ?*Ctx, pFromCache: ?*JsonParse, p: ?*JsonParse) ?*JsonParse {
    jsonParseFree(pFromCache);
    jsonParseFree(p);
    sqlite3_result_error_nomem(ctx);
    return null;
}

fn jsonReturnParse(ctx: ?*Ctx, p: *JsonParse) void {
    if (p.oom != 0) {
        sqlite3_result_error_nomem(ctx);
        return;
    }
    const flgs = ptrToInt(sqlite3_user_data(ctx));
    if (flgs & JSON_BLOB != 0) {
        if (p.nBlobAlloc > 0 and p.bReadOnly == 0) {
            sqlite3_result_blob(ctx, p.aBlob, @intCast(p.nBlob), SQLITE_DYNAMIC);
            p.nBlobAlloc = 0;
        } else {
            sqlite3_result_blob(ctx, p.aBlob, @intCast(p.nBlob), SQLITE_TRANSIENT);
        }
    } else {
        var s: JsonString = undefined;
        jsonStringInit(&s, ctx);
        p.delta = 0;
        _ = jsonTranslateBlobToText(p, 0, &s);
        jsonReturnString(&s, p, ctx);
        sqlite3_result_subtype(ctx, JSON_SUBTYPE);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Scalar SQL function implementations
// ───────────────────────────────────────────────────────────────────────────
fn jsonQuoteFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    var jx: JsonString = undefined;
    jsonStringInit(&jx, ctx);
    jsonAppendSqlValue(&jx, argv[0]);
    jsonReturnString(&jx, null, null);
    sqlite3_result_subtype(ctx, JSON_SUBTYPE);
}

fn jsonArrayFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var jx: JsonString = undefined;
    jsonStringInit(&jx, ctx);
    jsonAppendChar(&jx, '[');
    var i: c_int = 0;
    while (i < argc) : (i += 1) {
        jsonAppendSeparator(&jx);
        jsonAppendSqlValue(&jx, argv[@intCast(i)]);
    }
    jsonAppendChar(&jx, ']');
    jsonReturnString(&jx, null, null);
    sqlite3_result_subtype(ctx, JSON_SUBTYPE);
}

fn jsonArrayLengthFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var cnt: i64 = 0;
    var i: u32 = undefined;
    var eErr: bool = false;
    const p = jsonParseFuncArg(ctx, argv[0], 0) orelse return;
    if (argc == 2) {
        const zPath = sqlite3_value_text(argv[1]);
        if (zPath == null) {
            jsonParseFree(p);
            return;
        }
        i = jsonLookupStep(p, 0, if (zPath.?[0] == '$') zPath.? + 1 else "@", 0);
        if (JSON_LOOKUP_ISERROR(i)) {
            if (i != JSON_LOOKUP_NOTFOUND) {
                _ = jsonBadPathError(ctx, zPath, @bitCast(i));
            }
            eErr = true;
            i = 0;
        }
    } else {
        i = 0;
    }
    if ((p.aBlob.?[i] & 0x0f) == JSONB_ARRAY) {
        cnt = jsonbArrayCount(p, i);
    }
    if (!eErr) sqlite3_result_int64(ctx, cnt);
    jsonParseFree(p);
}

fn jsonAllAlphanum(z: [*]const u8, n: c_int) bool {
    var i: c_int = 0;
    while (i < n and (isalnum(z[@intCast(i)]) or z[@intCast(i)] == '_')) : (i += 1) {}
    return i == n;
}

fn jsonExtractFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var jx: JsonString = undefined;
    if (argc < 2) return;
    const p = jsonParseFuncArg(ctx, argv[0], 0) orelse return;
    const flags = ptrToInt(sqlite3_user_data(ctx));
    jsonStringInit(&jx, ctx);
    if (argc > 2) jsonAppendChar(&jx, '[');
    var i: c_int = 1;
    done: {
        while (i < argc) : (i += 1) {
            const zPathOpt = sqlite3_value_text(argv[@intCast(i)]);
            if (zPathOpt == null) break :done;
            const zPath = zPathOpt.?;
            const nPath = sqlite3Strlen30(zPath);
            var j: u32 = undefined;
            if (zPath[0] == '$') {
                j = jsonLookupStep(p, 0, zPath + 1, 0);
            } else if (flags & JSON_ABPATH != 0) {
                jsonStringInit(&jx, ctx);
                if (sqlite3_value_type(argv[@intCast(i)]) == SQLITE_INTEGER) {
                    jsonAppendRawNZ(&jx, "[", 1);
                    if (zPath[0] == '-') jsonAppendRawNZ(&jx, "#", 1);
                    jsonAppendRaw(&jx, zPath, @intCast(nPath));
                    jsonAppendRawNZ(&jx, "]", 2);
                } else if (jsonAllAlphanum(zPath, nPath)) {
                    jsonAppendRawNZ(&jx, ".", 1);
                    jsonAppendRaw(&jx, zPath, @intCast(nPath));
                } else if (zPath[0] == '[' and nPath >= 3 and zPath[@intCast(nPath - 1)] == ']') {
                    jsonAppendRaw(&jx, zPath, @intCast(nPath));
                } else {
                    jsonAppendRawNZ(&jx, ".\"", 2);
                    jsonAppendRaw(&jx, zPath, @intCast(nPath));
                    jsonAppendRawNZ(&jx, "\"", 1);
                }
                _ = jsonStringTerminate(&jx);
                j = jsonLookupStep(p, 0, jx.zBuf, 0);
                jsonStringReset(&jx);
            } else {
                _ = jsonBadPathError(ctx, zPath, 0);
                break :done;
            }
            if (j < p.nBlob) {
                if (argc == 2) {
                    if (flags & JSON_JSON != 0) {
                        jsonStringInit(&jx, ctx);
                        _ = jsonTranslateBlobToText(p, j, &jx);
                        jsonReturnString(&jx, null, null);
                        jsonStringReset(&jx);
                        sqlite3_result_subtype(ctx, JSON_SUBTYPE);
                    } else {
                        jsonReturnFromBlob(p, j, ctx, 0);
                        if ((flags & (JSON_SQL | JSON_BLOB)) == 0 and (p.aBlob.?[j] & 0x0f) >= JSONB_ARRAY) {
                            sqlite3_result_subtype(ctx, JSON_SUBTYPE);
                        }
                    }
                } else {
                    jsonAppendSeparator(&jx);
                    _ = jsonTranslateBlobToText(p, j, &jx);
                }
            } else if (j == JSON_LOOKUP_NOTFOUND) {
                if (argc == 2) {
                    break :done;
                } else {
                    jsonAppendSeparator(&jx);
                    jsonAppendRawNZ(&jx, "null", 4);
                }
            } else {
                _ = jsonBadPathError(ctx, zPath, @bitCast(j));
                break :done;
            }
        }
        if (argc > 2) {
            jsonAppendChar(&jx, ']');
            jsonReturnString(&jx, null, null);
            if ((flags & JSON_BLOB) == 0) sqlite3_result_subtype(ctx, JSON_SUBTYPE);
        }
    }
    jsonStringReset(&jx);
    jsonParseFree(p);
}

fn jsonMergePatch(pTarget: *JsonParse, iTarget: u32, pPatch: *const JsonParse, iPatch: u32, iDepth: u32) c_int {
    var n: u32 = undefined;
    var sz: u32 = 0;
    var x: u8 = pPatch.aBlob.?[iPatch] & 0x0f;
    if (x != JSONB_OBJECT) {
        n = jsonbPayloadSize(pPatch, iPatch, &sz);
        const szPatch = n + sz;
        sz = 0;
        n = jsonbPayloadSize(pTarget, iTarget, &sz);
        const szTarget = n + sz;
        jsonBlobEdit(pTarget, iTarget, szTarget, pPatch.aBlob.? + iPatch, szPatch);
        return if (pTarget.oom != 0) JSON_MERGE_OOM else JSON_MERGE_OK;
    }
    x = pTarget.aBlob.?[iTarget] & 0x0f;
    if (x != JSONB_OBJECT) {
        n = jsonbPayloadSize(pTarget, iTarget, &sz);
        jsonBlobEdit(pTarget, iTarget + n, sz, null, 0);
        const xx = pTarget.aBlob.?[iTarget];
        pTarget.aBlob.?[iTarget] = (xx & 0xf0) | JSONB_OBJECT;
    }
    n = jsonbPayloadSize(pPatch, iPatch, &sz);
    if (n == 0) return JSON_MERGE_BADPATCH;
    var iPCursor = iPatch + n;
    const iPEnd = iPCursor + sz;
    n = jsonbPayloadSize(pTarget, iTarget, &sz);
    if (n == 0) return JSON_MERGE_BADTARGET;
    const iTStart = iTarget + n;
    const iTEndBE = iTStart + sz;

    while (iPCursor < iPEnd) {
        const iPLabel = iPCursor;
        const ePLabel = pPatch.aBlob.?[iPCursor] & 0x0f;
        if (ePLabel < JSONB_TEXT or ePLabel > JSONB_TEXTRAW) return JSON_MERGE_BADPATCH;
        var szPLabel: u32 = 0;
        const nPLabel = jsonbPayloadSize(pPatch, iPCursor, &szPLabel);
        if (nPLabel == 0) return JSON_MERGE_BADPATCH;
        const iPValue = iPCursor + nPLabel + szPLabel;
        if (iPValue >= iPEnd) return JSON_MERGE_BADPATCH;
        var szPValue: u32 = 0;
        const nPValue = jsonbPayloadSize(pPatch, iPValue, &szPValue);
        if (nPValue == 0) return JSON_MERGE_BADPATCH;
        iPCursor = iPValue + nPValue + szPValue;
        if (iPCursor > iPEnd) return JSON_MERGE_BADPATCH;

        var iTCursor = iTStart;
        const iTEnd: u32 = @bitCast(@as(i32, @bitCast(iTEndBE)) +% pTarget.delta);
        var iTLabel: u32 = 0;
        while (iTCursor < iTEnd) {
            iTLabel = iTCursor;
            const eTLabel = pTarget.aBlob.?[iTCursor] & 0x0f;
            if (eTLabel < JSONB_TEXT or eTLabel > JSONB_TEXTRAW) return JSON_MERGE_BADTARGET;
            var szTLabel: u32 = 0;
            const nTLabel = jsonbPayloadSize(pTarget, iTCursor, &szTLabel);
            if (nTLabel == 0) return JSON_MERGE_BADTARGET;
            const iTValue = iTLabel + nTLabel + szTLabel;
            if (iTValue >= iTEnd) return JSON_MERGE_BADTARGET;
            var szTValue: u32 = 0;
            const nTValue = jsonbPayloadSize(pTarget, iTValue, &szTValue);
            if (nTValue == 0) return JSON_MERGE_BADTARGET;
            if (iTValue + nTValue + szTValue > iTEnd) return JSON_MERGE_BADTARGET;
            const isEqual = jsonLabelCompare(
                pPatch.aBlob.? + iPLabel + nPLabel,
                szPLabel,
                ePLabel == JSONB_TEXT or ePLabel == JSONB_TEXTRAW,
                pTarget.aBlob.? + iTLabel + nTLabel,
                szTLabel,
                eTLabel == JSONB_TEXT or eTLabel == JSONB_TEXTRAW,
            );
            if (isEqual != 0) break;
            iTCursor = iTValue + nTValue + szTValue;
        }
        x = pPatch.aBlob.?[iPValue] & 0x0f;
        if (iTCursor < iTEnd) {
            // recompute target value coords for the matched label
            var szTLabel: u32 = 0;
            const nTLabel = jsonbPayloadSize(pTarget, iTLabel, &szTLabel);
            const iTValue = iTLabel + nTLabel + szTLabel;
            var szTValue: u32 = 0;
            const nTValue = jsonbPayloadSize(pTarget, iTValue, &szTValue);
            if (x == 0) {
                jsonBlobEdit(pTarget, iTLabel, nTLabel + szTLabel + nTValue + szTValue, null, 0);
                if (pTarget.oom != 0) return JSON_MERGE_OOM;
            } else {
                const savedDelta = pTarget.delta;
                pTarget.delta = 0;
                if (iDepth >= JSON_MAX_DEPTH) return JSON_MERGE_TOODEEP;
                const rc = jsonMergePatch(pTarget, iTValue, pPatch, iPValue, iDepth + 1);
                if (rc != 0) return rc;
                pTarget.delta += savedDelta;
            }
        } else if (x > 0) {
            const szNew = szPLabel + nPLabel;
            if ((pPatch.aBlob.?[iPValue] & 0x0f) != JSONB_OBJECT) {
                jsonBlobEdit(pTarget, iTEnd, 0, null, szPValue + nPValue + szNew);
                if (pTarget.oom != 0) return JSON_MERGE_OOM;
                @memcpy(pTarget.aBlob.?[iTEnd..][0..szNew], (pPatch.aBlob.? + iPLabel)[0..szNew]);
                @memcpy(pTarget.aBlob.?[iTEnd + szNew ..][0 .. szPValue + nPValue], (pPatch.aBlob.? + iPValue)[0 .. szPValue + nPValue]);
            } else {
                jsonBlobEdit(pTarget, iTEnd, 0, null, szNew + 1);
                if (pTarget.oom != 0) return JSON_MERGE_OOM;
                @memcpy(pTarget.aBlob.?[iTEnd..][0..szNew], (pPatch.aBlob.? + iPLabel)[0..szNew]);
                pTarget.aBlob.?[iTEnd + szNew] = 0x00;
                const savedDelta = pTarget.delta;
                pTarget.delta = 0;
                if (iDepth >= JSON_MAX_DEPTH) return JSON_MERGE_TOODEEP;
                const rc = jsonMergePatch(pTarget, iTEnd + szNew, pPatch, iPValue, iDepth + 1);
                if (rc != 0) return rc;
                pTarget.delta += savedDelta;
            }
        }
    }
    if (pTarget.delta != 0) jsonAfterEditSizeAdjust(pTarget, iTarget);
    return if (pTarget.oom != 0) JSON_MERGE_OOM else JSON_MERGE_OK;
}

fn jsonPatchFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    const pTarget = jsonParseFuncArg(ctx, argv[0], JSON_EDITABLE) orelse return;
    const pPatch = jsonParseFuncArg(ctx, argv[1], 0);
    if (pPatch) |pp| {
        const rc = jsonMergePatch(pTarget, 0, pp, 0, 0);
        if (rc == JSON_MERGE_OK) {
            jsonReturnParse(ctx, pTarget);
        } else if (rc == JSON_MERGE_OOM) {
            sqlite3_result_error_nomem(ctx);
        } else if (rc == JSON_MERGE_TOODEEP) {
            sqlite3_result_error(ctx, "JSON nested too deep", -1);
        } else {
            sqlite3_result_error(ctx, "malformed JSON", -1);
        }
        jsonParseFree(pp);
    }
    jsonParseFree(pTarget);
}

fn jsonObjectFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var jx: JsonString = undefined;
    if (argc & 1 != 0) {
        sqlite3_result_error(ctx, "json_object() requires an even number of arguments", -1);
        return;
    }
    jsonStringInit(&jx, ctx);
    jsonAppendChar(&jx, '{');
    var i: c_int = 0;
    while (i < argc) : (i += 2) {
        if (sqlite3_value_type(argv[@intCast(i)]) != SQLITE_TEXT) {
            sqlite3_result_error(ctx, "json_object() labels must be TEXT", -1);
            jsonStringReset(&jx);
            return;
        }
        jsonAppendSeparator(&jx);
        const z = sqlite3_value_text(argv[@intCast(i)]);
        const nn: u32 = @intCast(sqlite3_value_bytes(argv[@intCast(i)]));
        jsonAppendString(&jx, z, nn);
        jsonAppendChar(&jx, ':');
        jsonAppendSqlValue(&jx, argv[@intCast(i + 1)]);
    }
    jsonAppendChar(&jx, '}');
    jsonReturnString(&jx, null, null);
    sqlite3_result_subtype(ctx, JSON_SUBTYPE);
}

fn jsonRemoveFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var zPath: ?[*:0]const u8 = null;
    var rc: u32 = undefined;
    if (argc < 1) return;
    const p = jsonParseFuncArg(ctx, argv[0], if (argc > 1) JSON_EDITABLE else 0) orelse return;
    var i: c_int = 1;
    done: {
        while (i < argc) : (i += 1) {
            zPath = sqlite3_value_text(argv[@intCast(i)]);
            if (zPath == null) break :done;
            if (zPath.?[0] != '$') {
                _ = jsonBadPathError(ctx, zPath, 0);
                break :done;
            }
            if (zPath.?[1] == 0) break :done;
            p.eEdit = JEDIT_DEL;
            p.delta = 0;
            rc = jsonLookupStep(p, 0, zPath.? + 1, 0);
            if (JSON_LOOKUP_ISERROR(rc)) {
                if (rc == JSON_LOOKUP_NOTFOUND) {
                    continue;
                } else {
                    _ = jsonBadPathError(ctx, zPath, @bitCast(rc));
                }
                break :done;
            }
        }
        jsonReturnParse(ctx, p);
        jsonParseFree(p);
        return;
    }
    jsonParseFree(p);
}

fn jsonReplaceFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    if (argc < 1) return;
    if ((argc & 1) == 0) {
        jsonWrongNumArgs(ctx, "replace");
        return;
    }
    jsonInsertIntoBlob(ctx, argc, argv, JEDIT_REPL);
}

fn jsonSetFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    const flags = ptrToInt(sqlite3_user_data(ctx));
    const eInsType = JSON_INSERT_TYPE(flags);
    const azInsType = [_][*:0]const u8{ "insert", "set", "array_insert" };
    const aEditType = [_]u8{ JEDIT_INS, JEDIT_SET, JEDIT_AINS };
    if (argc < 1) return;
    if ((argc & 1) == 0) {
        jsonWrongNumArgs(ctx, azInsType[@intCast(eInsType)]);
        return;
    }
    jsonInsertIntoBlob(ctx, argc, argv, aEditType[@intCast(eInsType)]);
}

fn jsonTypeFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var i: u32 = undefined;
    const p = jsonParseFuncArg(ctx, argv[0], 0) orelse return;
    done: {
        if (argc == 2) {
            const zPath = sqlite3_value_text(argv[1]);
            if (zPath == null) break :done;
            if (zPath.?[0] != '$') {
                _ = jsonBadPathError(ctx, zPath, 0);
                break :done;
            }
            i = jsonLookupStep(p, 0, zPath.? + 1, 0);
            if (JSON_LOOKUP_ISERROR(i)) {
                if (i != JSON_LOOKUP_NOTFOUND) {
                    _ = jsonBadPathError(ctx, zPath, @bitCast(i));
                }
                break :done;
            }
        } else {
            i = 0;
        }
        sqlite3_result_text(ctx, jsonbType[p.aBlob.?[i] & 0x0f], -1, SQLITE_STATIC);
    }
    jsonParseFree(p);
}

fn jsonPrettyFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var s: JsonString = undefined;
    var x: JsonPretty = .{};
    x.pParse = jsonParseFuncArg(ctx, argv[0], 0) orelse return;
    x.pOut = &s;
    jsonStringInit(&s, ctx);
    var zIndentOpt: ?[*:0]const u8 = null;
    if (argc == 1) {
        zIndentOpt = null;
    } else {
        zIndentOpt = sqlite3_value_text(argv[1]);
    }
    if (zIndentOpt) |zi| {
        x.zIndent = zi;
        x.szIndent = @intCast(strlen(zi));
    } else {
        x.zIndent = "    ";
        x.szIndent = 4;
    }
    _ = jsonTranslateBlobToPrettyText(&x, 0);
    jsonReturnString(&s, null, null);
    jsonParseFree(x.pParse);
}

fn jsonValidFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var flags: u8 = 1;
    var res: u8 = 0;
    if (argc == 2) {
        const f = sqlite3_value_int64(argv[1]);
        if (f < 1 or f > 15) {
            sqlite3_result_error(ctx, "FLAGS parameter to json_valid() must be between 1 and 15", -1);
            return;
        }
        flags = @intCast(f & 0x0f);
    }
    var doDefault: bool = false;
    switch (sqlite3_value_type(argv[0])) {
        SQLITE_NULL => return,
        SQLITE_BLOB => {
            var py: JsonParse = .{};
            if (jsonArgIsJsonb(argv[0], &py) != 0) {
                if (flags & 0x04 != 0) {
                    res = 1;
                } else if (flags & 0x08 != 0) {
                    res = @intFromBool(0 == jsonbValidityCheck(&py, 0, py.nBlob, 1));
                }
            } else {
                doDefault = true; // fall through to default
            }
        },
        else => doDefault = true,
    }
    if (doDefault and (flags & 0x3) != 0) {
        const p = jsonParseFuncArg(ctx, argv[0], JSON_KEEPERROR);
        if (p) |pp| {
            if (pp.oom != 0) {
                sqlite3_result_error_nomem(ctx);
            } else if (pp.nErr != 0) {
                // no-op
            } else if ((flags & 0x02) != 0 or pp.hasNonstd == 0) {
                res = 1;
            }
            jsonParseFree(pp);
        } else {
            sqlite3_result_error_nomem(ctx);
        }
    }
    sqlite3_result_int(ctx, res);
}

fn jsonErrorFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    var iErrPos: i64 = 0;
    var s: JsonParse = .{};
    s.db = sqlite3_context_db_handle(ctx);
    if (jsonArgIsJsonb(argv[0], &s) != 0) {
        iErrPos = @intCast(jsonbValidityCheck(&s, 0, s.nBlob, 1));
    } else {
        s.zJson = @constCast(sqlite3_value_text(argv[0]));
        if (s.zJson == null) return;
        s.nJson = sqlite3_value_bytes(argv[0]);
        if (jsonConvertTextToBlob(&s, null) != 0) {
            if (s.oom != 0) {
                iErrPos = -1;
            } else {
                var k: u32 = 0;
                while (k < s.iErr and s.zJson.?[k] != 0) : (k += 1) {
                    if ((s.zJson.?[k] & 0xc0) != 0x80) iErrPos += 1;
                }
                iErrPos += 1;
            }
        }
    }
    jsonParseReset(&s);
    if (iErrPos < 0) {
        sqlite3_result_error_nomem(ctx);
    } else {
        sqlite3_result_int64(ctx, iErrPos);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Aggregate SQL function implementations
// ───────────────────────────────────────────────────────────────────────────
fn jsonArrayStep(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    const pStr: ?*JsonString = @ptrCast(@alignCast(sqlite3_aggregate_context(ctx, @sizeOf(JsonString))));
    if (pStr) |p| {
        if (p.nUsed == 0 and p.nAlloc == 0) {
            jsonStringInit(p, ctx);
            jsonAppendChar(p, '[');
        } else if (p.nUsed > 1) {
            jsonAppendChar(p, ',');
        }
        p.pCtx = ctx;
        jsonAppendSqlValue(p, argv[0]);
    }
}
fn jsonArrayCompute(ctx: ?*Ctx, isFinal: bool) void {
    const flags = ptrToInt(sqlite3_user_data(ctx));
    const pStr: ?*JsonString = @ptrCast(@alignCast(sqlite3_aggregate_context(ctx, 0)));
    if (pStr) |p| {
        p.pCtx = ctx;
        jsonAppendRawNZ(p, "]", 2);
        jsonStringTrimOneChar(p);
        if (p.eErr != 0) {
            jsonReturnString(p, null, null);
            return;
        } else if (flags & JSON_BLOB != 0) {
            jsonReturnStringAsBlob(p);
            if (isFinal) {
                if (p.bStatic == 0) sqlite3RCStrUnref(p.zBuf);
            } else {
                jsonStringTrimOneChar(p);
            }
            return;
        } else if (isFinal) {
            sqlite3_result_text(ctx, p.zBuf, @intCast(p.nUsed), if (p.bStatic != 0) SQLITE_TRANSIENT else RCStrUnrefDtor);
            p.bStatic = 1;
        } else {
            sqlite3_result_text(ctx, p.zBuf, @intCast(p.nUsed), SQLITE_TRANSIENT);
            jsonStringTrimOneChar(p);
        }
    } else if (flags & JSON_BLOB != 0) {
        const emptyArray = [_]u8{0x0b};
        sqlite3_result_blob(ctx, &emptyArray, 1, SQLITE_STATIC);
    } else {
        sqlite3_result_text(ctx, "[]", 2, SQLITE_STATIC);
    }
    sqlite3_result_subtype(ctx, JSON_SUBTYPE);
}
fn jsonArrayValue(ctx: ?*Ctx) callconv(.c) void {
    jsonArrayCompute(ctx, false);
}
fn jsonArrayFinal(ctx: ?*Ctx) callconv(.c) void {
    jsonArrayCompute(ctx, true);
}

fn jsonGroupInverse(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    var inStr: bool = false;
    var nNest: i32 = 0;
    const pStr: ?*JsonString = @ptrCast(@alignCast(sqlite3_aggregate_context(ctx, 0)));
    if (pStr == null) return;
    const p = pStr.?;
    const z = p.zBuf;
    var i: u64 = 1;
    while (i < p.nUsed) : (i += 1) {
        const c = z[@intCast(i)];
        if (c == ',' and !inStr and nNest == 0) break;
        if (c == '"') {
            inStr = !inStr;
        } else if (c == '\\') {
            i += 1;
        } else if (!inStr) {
            if (c == '{' or c == '[') nNest += 1;
            if (c == '}' or c == ']') nNest -= 1;
        }
    }
    if (i < p.nUsed) {
        p.nUsed -= i;
        const cnt: usize = @intCast(p.nUsed - 1);
        // memmove(&z[1], &z[i+1], nUsed-1)
        std.mem.copyForwards(u8, z[1..][0..cnt], z[@intCast(i + 1)..][0..cnt]);
        z[@intCast(p.nUsed)] = 0;
    } else {
        p.nUsed = 1;
    }
}

fn jsonObjectStep(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    _ = argc;
    const pStr: ?*JsonString = @ptrCast(@alignCast(sqlite3_aggregate_context(ctx, @sizeOf(JsonString))));
    if (pStr) |p| {
        const z = sqlite3_value_text(argv[0]);
        const n: u32 = @intCast(sqlite3Strlen30(z));
        if (p.nUsed == 0 and p.nAlloc == 0) {
            jsonStringInit(p, ctx);
            jsonAppendChar(p, '{');
        } else if (p.nUsed > 1) {
            jsonAppendChar(p, ',');
        }
        p.pCtx = ctx;
        if (z) |zp| {
            jsonAppendString(p, zp, n);
            jsonAppendChar(p, ':');
            jsonAppendSqlValue(p, argv[1]);
        } else {
            p.zBuf[0] = '@';
            jsonAppendRawNZ(p, "@", 1);
        }
    }
}
fn jsonObjectCompute(ctx: ?*Ctx, isFinal: bool) void {
    const flags = ptrToInt(sqlite3_user_data(ctx));
    const pStrOpt: ?*JsonString = @ptrCast(@alignCast(sqlite3_aggregate_context(ctx, 0)));
    if (pStrOpt) |pOgStr| {
        var pStr = pOgStr;
        var tmpStr: JsonString = undefined;
        jsonAppendRawNZ(pOgStr, "}", 2);
        jsonStringTrimOneChar(pOgStr);
        pStr.pCtx = ctx;
        if (pStr.eErr != 0) {
            jsonReturnString(pStr, null, null);
            return;
        }
        if (pStr.zBuf[0] != '{') {
            var inStr: bool = false;
            if (!isFinal) {
                jsonStringInit(&tmpStr, ctx);
                jsonAppendRawNZ(&tmpStr, pStr.zBuf, @intCast(pStr.nUsed + 1));
                pStr = &tmpStr;
                if (pStr.eErr != 0) {
                    jsonReturnString(pStr, null, null);
                    return;
                }
                jsonStringTrimOneChar(pStr);
            }
            pStr.zBuf[0] = '{';
            var i: u64 = 1;
            var j: u64 = 1;
            while (i < pStr.nUsed) : (i += 1) {
                const c = pStr.zBuf[@intCast(i)];
                if (c == '"') {
                    inStr = !inStr;
                    pStr.zBuf[@intCast(j)] = '"';
                    j += 1;
                } else if (c == '\\') {
                    pStr.zBuf[@intCast(j)] = '\\';
                    j += 1;
                    i += 1;
                    pStr.zBuf[@intCast(j)] = pStr.zBuf[@intCast(i)];
                    j += 1;
                } else if (c == '@' and !inStr) {
                    if (pStr.zBuf[@intCast(i + 1)] == ',') {
                        i += 1;
                    } else if (pStr.zBuf[@intCast(j - 1)] == ',') {
                        j -= 1;
                    }
                } else {
                    pStr.zBuf[@intCast(j)] = c;
                    j += 1;
                }
            }
            pStr.zBuf[@intCast(j)] = 0;
            pStr.nUsed = j;
        }
        if (flags & JSON_BLOB != 0) {
            jsonReturnStringAsBlob(pStr);
            if (isFinal) {
                if (pStr.bStatic == 0) sqlite3RCStrUnref(pStr.zBuf);
            } else {
                jsonStringTrimOneChar(pOgStr);
            }
        } else if (isFinal) {
            sqlite3_result_text(ctx, pStr.zBuf, @intCast(pStr.nUsed), if (pStr.bStatic != 0) SQLITE_TRANSIENT else RCStrUnrefDtor);
            pStr.bStatic = 1;
        } else {
            sqlite3_result_text(ctx, pStr.zBuf, @intCast(pStr.nUsed), SQLITE_TRANSIENT);
            jsonStringTrimOneChar(pOgStr);
        }
        if (pStr != pOgStr) jsonStringReset(pStr);
    } else if (flags & JSON_BLOB != 0) {
        const emptyObject = [_]u8{0x0c};
        sqlite3_result_blob(ctx, &emptyObject, 1, SQLITE_STATIC);
    } else {
        sqlite3_result_text(ctx, "{}", 2, SQLITE_STATIC);
    }
    sqlite3_result_subtype(ctx, JSON_SUBTYPE);
}
fn jsonObjectValue(ctx: ?*Ctx) callconv(.c) void {
    jsonObjectCompute(ctx, false);
}
fn jsonObjectFinal(ctx: ?*Ctx) callconv(.c) void {
    jsonObjectCompute(ctx, true);
}

// ───────────────────────────────────────────────────────────────────────────
// Debug-only SQL functions (SQLITE_DEBUG). Gated on config.sqlite_debug.
// ───────────────────────────────────────────────────────────────────────────
const StrAccum_zText: usize = off("StrAccum_zText", 8);
const StrAccum_nChar: usize = off("StrAccum_nChar", 24);
const StrAccumSz: usize = off("sizeof_StrAccum", 32);

inline fn strAccumZText(p: *anyopaque) ?[*]const u8 {
    const q: *align(1) const ?[*]const u8 = @ptrCast(@as([*]u8, @ptrCast(p)) + StrAccum_zText);
    return q.*;
}
inline fn strAccumNChar(p: *anyopaque) u32 {
    const q: *align(1) const u32 = @ptrCast(@as([*]u8, @ptrCast(p)) + StrAccum_nChar);
    return q.*;
}

fn jsonDebugPrintBlob(pParse: *JsonParse, iStart0: u32, iEnd0: u32, nIndent: c_int, pOut: ?*sqlite3_str) void {
    var iStart = iStart0;
    var iEnd = iEnd0;
    while (iStart < iEnd) {
        var sz: u32 = 0;
        var showContent: bool = true;
        const x = pParse.aBlob.?[iStart] & 0x0f;
        const savedNBlob = pParse.nBlob;
        sqlite3_str_appendf(pOut, "%5d:%*s", iStart, nIndent, "");
        if (pParse.nBlobAlloc > pParse.nBlob) pParse.nBlob = pParse.nBlobAlloc;
        const n = jsonbPayloadSize(pParse, iStart, &sz);
        var nn = n;
        if (nn == 0) nn = 1;
        if (sz > 0 and x < JSONB_ARRAY) nn += sz;
        var i: u32 = 0;
        while (i < nn) : (i += 1) {
            sqlite3_str_appendf(pOut, " %02x", pParse.aBlob.?[iStart + i]);
        }
        if (n == 0) {
            sqlite3_str_appendf(pOut, "   ERROR invalid node size\n");
            iStart = iStart + 1;
            continue;
        }
        pParse.nBlob = savedNBlob;
        if (iStart + n + sz > iEnd) {
            iEnd = iStart + n + sz;
            if (iEnd > pParse.nBlob) {
                if (pParse.nBlobAlloc > 0 and iEnd > pParse.nBlobAlloc) {
                    iEnd = pParse.nBlobAlloc;
                } else {
                    iEnd = pParse.nBlob;
                }
            }
        }
        sqlite3_str_appendall(pOut, "  <-- ");
        switch (x) {
            JSONB_NULL => sqlite3_str_appendall(pOut, "null"),
            JSONB_TRUE => sqlite3_str_appendall(pOut, "true"),
            JSONB_FALSE => sqlite3_str_appendall(pOut, "false"),
            JSONB_INT => sqlite3_str_appendall(pOut, "int"),
            JSONB_INT5 => sqlite3_str_appendall(pOut, "int5"),
            JSONB_FLOAT => sqlite3_str_appendall(pOut, "float"),
            JSONB_FLOAT5 => sqlite3_str_appendall(pOut, "float5"),
            JSONB_TEXT => sqlite3_str_appendall(pOut, "text"),
            JSONB_TEXTJ => sqlite3_str_appendall(pOut, "textj"),
            JSONB_TEXT5 => sqlite3_str_appendall(pOut, "text5"),
            JSONB_TEXTRAW => sqlite3_str_appendall(pOut, "textraw"),
            JSONB_ARRAY => {
                sqlite3_str_appendf(pOut, "array, %u bytes\n", sz);
                jsonDebugPrintBlob(pParse, iStart + n, iStart + n + sz, nIndent + 2, pOut);
                showContent = false;
            },
            JSONB_OBJECT => {
                sqlite3_str_appendf(pOut, "object, %u bytes\n", sz);
                jsonDebugPrintBlob(pParse, iStart + n, iStart + n + sz, nIndent + 2, pOut);
                showContent = false;
            },
            else => {
                sqlite3_str_appendall(pOut, "ERROR: unknown node type\n");
                showContent = false;
            },
        }
        if (showContent) {
            if (sz == 0 and x <= JSONB_FALSE) {
                sqlite3_str_append(pOut, "\n", 1);
            } else {
                sqlite3_str_appendall(pOut, ": \"");
                var j: u32 = iStart + n;
                while (j < iStart + n + sz) : (j += 1) {
                    var c = pParse.aBlob.?[j];
                    if (c < 0x20 or c >= 0x7f) c = '.';
                    sqlite3_str_append(pOut, @ptrCast(&c), 1);
                }
                sqlite3_str_append(pOut, "\"\n", 2);
            }
        }
        iStart += n + sz;
    }
}

fn jsonParseFunc(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val) callconv(.c) void {
    var out: [64]u8 align(16) = undefined;
    const pOut: *anyopaque = @ptrCast(&out);
    sqlite3StrAccumInit(pOut, null, null, 0, 1000000);
    const p = jsonParseFuncArg(ctx, argv[0], 0) orelse return;
    if (argc == 1) {
        jsonDebugPrintBlob(p, 0, p.nBlob, 0, pOut);
        sqlite3_result_text64(ctx, strAccumZText(pOut), strAccumNChar(pOut), SQLITE_TRANSIENT, SQLITE_UTF8);
    }
    jsonParseFree(p);
    sqlite3_str_reset(pOut);
}

// ───────────────────────────────────────────────────────────────────────────
// The json_each / json_tree virtual table
// ───────────────────────────────────────────────────────────────────────────
const JsonParent = struct {
    iHead: u32,
    iValue: u32,
    iEnd: u32,
    nPath: u32,
    iKey: i64,
};

const JsonEachCursor = struct {
    base: sqlite3_vtab_cursor,
    iRowid: u32,
    i: u32,
    iEnd: u32,
    nRoot: u32,
    eType: u8,
    bRecursive: u8,
    eMode: u8,
    nParent: u32,
    nParentAlloc: u32,
    aParent: ?[*]JsonParent,
    db: ?*anyopaque,
    path: JsonString,
    sParse: JsonParse,
};

const JsonEachConnection = struct {
    base: sqlite3_vtab,
    db: ?*anyopaque,
    eMode: u8,
    bRecursive: u8,
};

fn jsonEachConnect(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    _ = pAux;
    _ = argc;
    _ = pzErr;
    const rc = sqlite3_declare_vtab(db, "CREATE TABLE x(key,value,type,atom,id,parent,fullkey,path," ++
        "json HIDDEN,root HIDDEN)");
    if (rc == SQLITE_OK) {
        const pNew: ?*JsonEachConnection = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @sizeOf(JsonEachConnection))));
        ppVtab.* = @ptrCast(pNew);
        if (pNew == null) return SQLITE_NOMEM;
        _ = sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);
        const av = argv.?;
        pNew.?.db = db;
        const a0 = av[0].?;
        pNew.?.eMode = if (a0[4] == 'b') 2 else 1;
        pNew.?.bRecursive = @intFromBool(a0[4 + pNew.?.eMode] == 't');
    }
    return rc;
}

fn jsonEachDisconnect(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const p: *JsonEachConnection = @ptrCast(@alignCast(pVtab));
    sqlite3DbFree(p.db, pVtab);
    return SQLITE_OK;
}

fn jsonEachOpen(pv: *sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pVtab: *JsonEachConnection = @ptrCast(@alignCast(pv));
    const pCur: ?*JsonEachCursor = @ptrCast(@alignCast(sqlite3DbMallocZero(pVtab.db, @sizeOf(JsonEachCursor))));
    if (pCur == null) return SQLITE_NOMEM;
    const c = pCur.?;
    c.db = pVtab.db;
    c.eMode = pVtab.eMode;
    c.bRecursive = pVtab.bRecursive;
    jsonStringZero(&c.path);
    ppCursor.* = &c.base;
    return SQLITE_OK;
}

fn jsonEachCursorReset(p: *JsonEachCursor) void {
    jsonParseReset(&p.sParse);
    jsonStringReset(&p.path);
    sqlite3DbFree(p.db, p.aParent);
    p.iRowid = 0;
    p.i = 0;
    p.aParent = null;
    p.nParent = 0;
    p.nParentAlloc = 0;
    p.iEnd = 0;
    p.eType = 0;
}

fn jsonEachClose(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const p: *JsonEachCursor = @ptrCast(@alignCast(cur));
    jsonEachCursorReset(p);
    sqlite3DbFree(p.db, cur);
    return SQLITE_OK;
}

fn jsonEachEof(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const p: *JsonEachCursor = @ptrCast(@alignCast(cur));
    return @intFromBool(p.i >= p.iEnd);
}

fn jsonSkipLabel(p: *JsonEachCursor) u32 {
    if (p.eType == JSONB_OBJECT) {
        var sz: u32 = 0;
        const n = jsonbPayloadSize(&p.sParse, p.i, &sz);
        return p.i + n + sz;
    } else {
        return p.i;
    }
}

fn jsonAppendPathName(p: *JsonEachCursor) void {
    if (p.eType == JSONB_ARRAY) {
        jsonPrintf(30, &p.path, "[%lld]", .{p.aParent.?[p.nParent - 1].iKey});
    } else {
        var sz: u32 = 0;
        const n = jsonbPayloadSize(&p.sParse, p.i, &sz);
        const k = p.i + n;
        const z = p.sParse.aBlob.? + k;
        var needQuote: bool = false;
        if (sz == 0 or !isalpha(z[0])) {
            needQuote = true;
        } else {
            var i: u32 = 0;
            while (i < sz) : (i += 1) {
                if (!isalnum(z[i])) {
                    needQuote = true;
                    break;
                }
            }
        }
        if (needQuote) {
            jsonPrintf(@intCast(sz + 4), &p.path, ".\"%.*s\"", .{ sz, z });
        } else {
            jsonPrintf(@intCast(sz + 2), &p.path, ".%.*s", .{ sz, z });
        }
    }
}

fn jsonEachMalformedInput(cur: *sqlite3_vtab_cursor) c_int {
    const vtab = cur.pVtab.?;
    sqlite3_free(vtab.zErrMsg);
    vtab.zErrMsg = sqlite3_mprintf("malformed JSON");
    jsonEachCursorReset(@ptrCast(@alignCast(cur)));
    return if (vtab.zErrMsg != null) SQLITE_ERROR else SQLITE_NOMEM;
}

fn jsonEachNext(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const p: *JsonEachCursor = @ptrCast(@alignCast(cur));
    var rc: c_int = SQLITE_OK;
    if (p.bRecursive != 0) {
        var levelChange: bool = false;
        var sz: u32 = 0;
        const i = jsonSkipLabel(p);
        const x = p.sParse.aBlob.?[i] & 0x0f;
        const n = jsonbPayloadSize(&p.sParse, i, &sz);
        if (n == 0) return jsonEachMalformedInput(cur);
        if (x == JSONB_OBJECT or x == JSONB_ARRAY) {
            if (p.nParent >= p.nParentAlloc) {
                const nNew: u64 = @as(u64, p.nParentAlloc) * 2 + 3;
                const pNew: ?[*]JsonParent = @ptrCast(@alignCast(sqlite3DbRealloc(p.db, p.aParent, @sizeOf(JsonParent) * nNew)));
                if (pNew == null) return SQLITE_NOMEM;
                p.nParentAlloc = @truncate(nNew);
                p.aParent = pNew;
            }
            levelChange = true;
            const pParent = &p.aParent.?[p.nParent];
            pParent.iHead = p.i;
            pParent.iValue = i;
            pParent.iEnd = i + n + sz;
            pParent.iKey = -1;
            pParent.nPath = @intCast(p.path.nUsed);
            if (p.eType != 0 and p.nParent != 0) {
                jsonAppendPathName(p);
                if (p.path.eErr != 0) rc = SQLITE_NOMEM;
            }
            p.nParent += 1;
            p.i = i + n;
        } else {
            p.i = i + n + sz;
        }
        while (p.nParent > 0 and p.i >= p.aParent.?[p.nParent - 1].iEnd) {
            p.nParent -= 1;
            p.path.nUsed = p.aParent.?[p.nParent].nPath;
            levelChange = true;
        }
        if (levelChange) {
            if (p.nParent > 0) {
                const pParent = &p.aParent.?[p.nParent - 1];
                p.eType = p.sParse.aBlob.?[pParent.iValue] & 0x0f;
            } else {
                p.eType = 0;
            }
        }
    } else {
        var sz: u32 = 0;
        const i = jsonSkipLabel(p);
        const n = jsonbPayloadSize(&p.sParse, i, &sz);
        if (n == 0) return jsonEachMalformedInput(cur);
        p.i = i + n + sz;
    }
    if (p.eType == JSONB_ARRAY and p.nParent != 0) {
        p.aParent.?[p.nParent - 1].iKey += 1;
    }
    p.iRowid += 1;
    return rc;
}

fn jsonEachPathLength(p: *JsonEachCursor) u32 {
    var n: u32 = @intCast(p.path.nUsed);
    const z = p.path.zBuf;
    if (p.iRowid == 0 and p.bRecursive != 0 and n >= 2) {
        while (n > 1) {
            n -= 1;
            if (z[n] == '[' or z[n] == '.') {
                var sz: u32 = 0;
                const cSaved = z[n];
                z[n] = 0;
                const x = jsonLookupStep(&p.sParse, 0, z + 1, 0);
                z[n] = cSaved;
                if (JSON_LOOKUP_ISERROR(x)) continue;
                if (x + jsonbPayloadSize(&p.sParse, x, &sz) == p.i) break;
            }
        }
    }
    return n;
}

fn jsonEachColumn(cur: *sqlite3_vtab_cursor, ctx: ?*Ctx, iColumn: c_int) callconv(.c) c_int {
    const p: *JsonEachCursor = @ptrCast(@alignCast(cur));
    switch (iColumn) {
        JEACH_KEY => {
            if (p.nParent == 0) {
                if (p.nRoot == 1) return SQLITE_OK;
                const j = jsonEachPathLength(p);
                const n = p.nRoot - j;
                if (n == 0) {
                    return SQLITE_OK;
                } else if (p.path.zBuf[j] == '[') {
                    var x: i64 = undefined;
                    _ = sqlite3Atoi64(p.path.zBuf + j + 1, &x, @intCast(n - 1), SQLITE_UTF8);
                    sqlite3_result_int64(ctx, x);
                } else if (p.path.zBuf[j + 1] == '"') {
                    sqlite3_result_text(ctx, p.path.zBuf + j + 2, @intCast(n - 3), SQLITE_TRANSIENT);
                } else {
                    sqlite3_result_text(ctx, p.path.zBuf + j + 1, @intCast(n - 1), SQLITE_TRANSIENT);
                }
                return SQLITE_OK;
            }
            if (p.eType == JSONB_OBJECT) {
                jsonReturnFromBlob(&p.sParse, p.i, ctx, 1);
            } else {
                sqlite3_result_int64(ctx, p.aParent.?[p.nParent - 1].iKey);
            }
        },
        JEACH_VALUE => {
            const i = jsonSkipLabel(p);
            jsonReturnFromBlob(&p.sParse, i, ctx, p.eMode);
            if ((p.sParse.aBlob.?[i] & 0x0f) >= JSONB_ARRAY) {
                sqlite3_result_subtype(ctx, JSON_SUBTYPE);
            }
        },
        JEACH_TYPE => {
            const i = jsonSkipLabel(p);
            const eType = p.sParse.aBlob.?[i] & 0x0f;
            sqlite3_result_text(ctx, jsonbType[eType], -1, SQLITE_STATIC);
        },
        JEACH_ATOM => {
            const i = jsonSkipLabel(p);
            if ((p.sParse.aBlob.?[i] & 0x0f) < JSONB_ARRAY) {
                jsonReturnFromBlob(&p.sParse, i, ctx, 1);
            }
        },
        JEACH_ID => {
            sqlite3_result_int64(ctx, @intCast(p.i));
        },
        JEACH_PARENT => {
            if (p.nParent > 0 and p.bRecursive != 0) {
                sqlite3_result_int64(ctx, @intCast(p.aParent.?[p.nParent - 1].iHead));
            }
        },
        JEACH_FULLKEY => {
            const nBase = p.path.nUsed;
            if (p.nParent != 0) jsonAppendPathName(p);
            sqlite3_result_text64(ctx, p.path.zBuf, p.path.nUsed, SQLITE_TRANSIENT, SQLITE_UTF8);
            p.path.nUsed = nBase;
        },
        JEACH_PATH => {
            const n = jsonEachPathLength(p);
            sqlite3_result_text64(ctx, p.path.zBuf, n, SQLITE_TRANSIENT, SQLITE_UTF8);
        },
        JEACH_JSON => {
            if (p.sParse.zJson == null) {
                sqlite3_result_blob(ctx, p.sParse.aBlob, @intCast(p.sParse.nBlob), SQLITE_TRANSIENT);
            } else {
                sqlite3_result_text(ctx, p.sParse.zJson, -1, SQLITE_TRANSIENT);
            }
        },
        else => {
            sqlite3_result_text(ctx, p.path.zBuf, @intCast(p.nRoot), SQLITE_STATIC);
        },
    }
    return SQLITE_OK;
}

fn jsonEachRowid(cur: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const p: *JsonEachCursor = @ptrCast(@alignCast(cur));
    pRowid.* = p.iRowid;
    return SQLITE_OK;
}

fn jsonEachBestIndex(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = tab;
    var aIdx = [_]c_int{ -1, -1 };
    var unusableMask: c_int = 0;
    var idxMask: c_int = 0;
    const aConstraint = pIdxInfo.aConstraint.?;
    var i: c_int = 0;
    while (i < pIdxInfo.nConstraint) : (i += 1) {
        const pConstraint = &aConstraint[@intCast(i)];
        if (pConstraint.iColumn < JEACH_JSON) continue;
        const iCol = pConstraint.iColumn - JEACH_JSON;
        const iMask: c_int = @as(c_int, 1) << @intCast(iCol);
        if (pConstraint.usable == 0) {
            unusableMask |= iMask;
        } else if (pConstraint.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            aIdx[@intCast(iCol)] = i;
            idxMask |= iMask;
        }
    }
    if (pIdxInfo.nOrderBy > 0 and pIdxInfo.aOrderBy.?[0].iColumn < 0 and pIdxInfo.aOrderBy.?[0].desc == 0) {
        pIdxInfo.orderByConsumed = 1;
    }
    if ((unusableMask & ~idxMask) != 0) {
        return SQLITE_CONSTRAINT;
    }
    if (aIdx[0] < 0) {
        pIdxInfo.idxNum = 0;
    } else {
        const aUsage = pIdxInfo.aConstraintUsage.?;
        pIdxInfo.estimatedCost = 1.0;
        aUsage[@intCast(aIdx[0])].argvIndex = 1;
        aUsage[@intCast(aIdx[0])].omit = 1;
        if (aIdx[1] < 0) {
            pIdxInfo.idxNum = 1;
        } else {
            aUsage[@intCast(aIdx[1])].argvIndex = 2;
            aUsage[@intCast(aIdx[1])].omit = 1;
            pIdxInfo.idxNum = 3;
        }
    }
    return SQLITE_OK;
}

fn jsonEachFilter(
    cur: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?[*]?*Val,
) callconv(.c) c_int {
    _ = idxStr;
    _ = argc;
    const p: *JsonEachCursor = @ptrCast(@alignCast(cur));
    var i: u32 = undefined;
    var n: u32 = undefined;
    var sz: u32 = undefined;
    jsonEachCursorReset(p);
    if (idxNum == 0) return SQLITE_OK;
    const av = argv.?;
    p.sParse = .{};
    p.sParse.nJPRef = 1;
    p.sParse.db = p.db;
    if (jsonArgIsJsonb(av[0], &p.sParse) != 0) {
        // have JSONB
    } else {
        p.sParse.zJson = @constCast(sqlite3_value_text(av[0]));
        p.sParse.nJson = sqlite3_value_bytes(av[0]);
        if (p.sParse.zJson == null) {
            p.i = 0;
            p.iEnd = 0;
            return SQLITE_OK;
        }
        if (jsonConvertTextToBlob(&p.sParse, null) != 0) {
            if (p.sParse.oom != 0) return SQLITE_NOMEM;
            return jsonEachMalformedInput(cur);
        }
    }
    if (idxNum == 3) {
        const zRootOpt = sqlite3_value_text(av[1]);
        if (zRootOpt == null) return SQLITE_OK;
        const zRoot = zRootOpt.?;
        if (zRoot[0] != '$') {
            const vtab = cur.pVtab.?;
            sqlite3_free(vtab.zErrMsg);
            vtab.zErrMsg = jsonBadPathError(null, zRoot, 0);
            jsonEachCursorReset(p);
            return if (vtab.zErrMsg != null) SQLITE_ERROR else SQLITE_NOMEM;
        }
        p.nRoot = @intCast(sqlite3Strlen30(zRoot));
        if (zRoot[1] == 0) {
            i = 0;
            p.i = 0;
            p.eType = 0;
        } else {
            i = jsonLookupStep(&p.sParse, 0, zRoot + 1, 0);
            if (JSON_LOOKUP_ISERROR(i)) {
                if (i == JSON_LOOKUP_NOTFOUND) {
                    p.i = 0;
                    p.eType = 0;
                    p.iEnd = 0;
                    return SQLITE_OK;
                }
                const vtab = cur.pVtab.?;
                sqlite3_free(vtab.zErrMsg);
                vtab.zErrMsg = jsonBadPathError(null, zRoot, 0);
                jsonEachCursorReset(p);
                return if (vtab.zErrMsg != null) SQLITE_ERROR else SQLITE_NOMEM;
            }
            if (p.sParse.iLabel != 0) {
                p.i = p.sParse.iLabel;
                p.eType = JSONB_OBJECT;
            } else {
                p.i = i;
                p.eType = JSONB_ARRAY;
            }
        }
        jsonAppendRaw(&p.path, zRoot, p.nRoot);
    } else {
        i = 0;
        p.i = 0;
        p.eType = 0;
        p.nRoot = 1;
        jsonAppendRaw(&p.path, "$", 1);
    }
    p.nParent = 0;
    n = jsonbPayloadSize(&p.sParse, i, &sz);
    p.iEnd = i + n + sz;
    if ((p.sParse.aBlob.?[i] & 0x0f) >= JSONB_ARRAY and p.bRecursive == 0) {
        p.i = i + n;
        p.eType = p.sParse.aBlob.?[i] & 0x0f;
        p.aParent = @ptrCast(@alignCast(sqlite3DbMallocZero(p.db, @sizeOf(JsonParent))));
        if (p.aParent == null) return SQLITE_NOMEM;
        p.nParent = 1;
        p.nParentAlloc = 1;
        p.aParent.?[0].iKey = 0;
        p.aParent.?[0].iEnd = p.iEnd;
        p.aParent.?[0].iHead = p.i;
        p.aParent.?[0].iValue = i;
    }
    return SQLITE_OK;
}

const jsonEachModule: sqlite3_module = .{
    .iVersion = 0,
    .xCreate = null,
    .xConnect = &jsonEachConnect,
    .xBestIndex = &jsonEachBestIndex,
    .xDisconnect = &jsonEachDisconnect,
    .xDestroy = null,
    .xOpen = &jsonEachOpen,
    .xClose = &jsonEachClose,
    .xFilter = &jsonEachFilter,
    .xNext = &jsonEachNext,
    .xEof = &jsonEachEof,
    .xColumn = &jsonEachColumn,
    .xRowid = &jsonEachRowid,
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

// ───────────────────────────────────────────────────────────────────────────
// Registration
// ───────────────────────────────────────────────────────────────────────────
const XFunc = ?*const fn (?*Ctx, c_int, [*]?*Val) callconv(.c) void;
const XFinal = ?*const fn (?*Ctx) callconv(.c) void;

fn jfunction(
    comptime zName: [*:0]const u8,
    nArg: i16,
    bUseCache: u1,
    bWS: u1,
    bRS: u1,
    bJsonB: u1,
    iArg: c_int,
    xFunc: XFunc,
) FuncDef {
    const flags: u32 = SQLITE_FUNC_BUILTIN | SQLITE_DETERMINISTIC | SQLITE_FUNC_CONSTANT |
        SQLITE_UTF8_FLAG |
        (@as(u32, bUseCache) * SQLITE_FUNC_RUNONLY) |
        (@as(u32, bRS) * SQLITE_SUBTYPE) |
        (@as(u32, bWS) * SQLITE_RESULT_SUBTYPE);
    return .{
        .nArg = nArg,
        .funcFlags = flags,
        .pUserData = intToPtr(iArg | (@as(c_int, bJsonB) * JSON_BLOB)),
        .pNext = null,
        .xSFunc = @ptrCast(@constCast(xFunc)),
        .xFinalize = null,
        .xValue = null,
        .xInverse = null,
        .zName = zName,
        .u = .{ .pHash = null },
    };
}

fn waggregate(
    comptime zName: [*:0]const u8,
    nArg: i16,
    arg: c_int,
    nc: u1,
    xStep: XFunc,
    xFinal: XFinal,
    xValue: XFinal,
    xInverse: XFunc,
    f: u32,
) FuncDef {
    const flags: u32 = SQLITE_FUNC_BUILTIN | SQLITE_UTF8_FLAG |
        (@as(u32, nc) * SQLITE_FUNC_NEEDCOLL) | f;
    return .{
        .nArg = nArg,
        .funcFlags = flags,
        .pUserData = intToPtr(arg),
        .pNext = null,
        .xSFunc = @ptrCast(@constCast(xStep)),
        .xFinalize = @ptrCast(@constCast(xFinal)),
        .xValue = @ptrCast(@constCast(xValue)),
        .xInverse = @ptrCast(@constCast(xInverse)),
        .zName = zName,
        .u = .{ .pHash = null },
    };
}

const WAGG_FLAGS: u32 = SQLITE_SUBTYPE | SQLITE_RESULT_SUBTYPE | SQLITE_UTF8_FLAG | SQLITE_DETERMINISTIC;

fn buildJsonFuncTable() [nJsonFunc]FuncDef {
    var a: [nJsonFunc]FuncDef = undefined;
    var k: usize = 0;
    const J = jfunction;
    // name, nArg, bUseCache, bWS, bRS, bJsonB, iArg, xFunc
    a[k] = J("json", 1, 1, 1, 0, 0, 0, &jsonRemoveFunc);
    k += 1;
    a[k] = J("jsonb", 1, 1, 0, 0, 1, 0, &jsonRemoveFunc);
    k += 1;
    a[k] = J("json_array", -1, 0, 1, 1, 0, 0, &jsonArrayFunc);
    k += 1;
    a[k] = J("jsonb_array", -1, 0, 1, 1, 1, 0, &jsonArrayFunc);
    k += 1;
    a[k] = J("json_array_insert", -1, 1, 1, 1, 0, JSON_AINS, &jsonSetFunc);
    k += 1;
    a[k] = J("jsonb_array_insert", -1, 1, 0, 1, 1, JSON_AINS, &jsonSetFunc);
    k += 1;
    a[k] = J("json_array_length", 1, 1, 0, 0, 0, 0, &jsonArrayLengthFunc);
    k += 1;
    a[k] = J("json_array_length", 2, 1, 0, 0, 0, 0, &jsonArrayLengthFunc);
    k += 1;
    a[k] = J("json_error_position", 1, 1, 0, 0, 0, 0, &jsonErrorFunc);
    k += 1;
    a[k] = J("json_extract", -1, 1, 1, 0, 0, 0, &jsonExtractFunc);
    k += 1;
    a[k] = J("jsonb_extract", -1, 1, 0, 0, 1, 0, &jsonExtractFunc);
    k += 1;
    a[k] = J("->", 2, 1, 1, 0, 0, JSON_JSON, &jsonExtractFunc);
    k += 1;
    a[k] = J("->>", 2, 1, 0, 0, 0, JSON_SQL, &jsonExtractFunc);
    k += 1;
    a[k] = J("json_insert", -1, 1, 1, 1, 0, 0, &jsonSetFunc);
    k += 1;
    a[k] = J("jsonb_insert", -1, 1, 0, 1, 1, 0, &jsonSetFunc);
    k += 1;
    a[k] = J("json_object", -1, 0, 1, 1, 0, 0, &jsonObjectFunc);
    k += 1;
    a[k] = J("jsonb_object", -1, 0, 1, 1, 1, 0, &jsonObjectFunc);
    k += 1;
    a[k] = J("json_patch", 2, 1, 1, 0, 0, 0, &jsonPatchFunc);
    k += 1;
    a[k] = J("jsonb_patch", 2, 1, 0, 0, 1, 0, &jsonPatchFunc);
    k += 1;
    a[k] = J("json_pretty", 1, 1, 0, 0, 0, 0, &jsonPrettyFunc);
    k += 1;
    a[k] = J("json_pretty", 2, 1, 0, 0, 0, 0, &jsonPrettyFunc);
    k += 1;
    a[k] = J("json_quote", 1, 0, 1, 1, 0, 0, &jsonQuoteFunc);
    k += 1;
    a[k] = J("json_remove", -1, 1, 1, 0, 0, 0, &jsonRemoveFunc);
    k += 1;
    a[k] = J("jsonb_remove", -1, 1, 0, 0, 1, 0, &jsonRemoveFunc);
    k += 1;
    a[k] = J("json_replace", -1, 1, 1, 1, 0, 0, &jsonReplaceFunc);
    k += 1;
    a[k] = J("jsonb_replace", -1, 1, 0, 1, 1, 0, &jsonReplaceFunc);
    k += 1;
    a[k] = J("json_set", -1, 1, 1, 1, 0, JSON_ISSET, &jsonSetFunc);
    k += 1;
    a[k] = J("jsonb_set", -1, 1, 0, 1, 1, JSON_ISSET, &jsonSetFunc);
    k += 1;
    a[k] = J("json_type", 1, 1, 0, 0, 0, 0, &jsonTypeFunc);
    k += 1;
    a[k] = J("json_type", 2, 1, 0, 0, 0, 0, &jsonTypeFunc);
    k += 1;
    a[k] = J("json_valid", 1, 1, 0, 0, 0, 0, &jsonValidFunc);
    k += 1;
    a[k] = J("json_valid", 2, 1, 0, 0, 0, 0, &jsonValidFunc);
    k += 1;
    if (config.sqlite_debug) {
        a[k] = J("json_parse", 1, 1, 0, 0, 0, 0, &jsonParseFunc);
        k += 1;
    }
    a[k] = waggregate("json_group_array", 1, 0, 0, &jsonArrayStep, &jsonArrayFinal, &jsonArrayValue, &jsonGroupInverse, WAGG_FLAGS);
    k += 1;
    a[k] = waggregate("jsonb_group_array", 1, JSON_BLOB, 0, &jsonArrayStep, &jsonArrayFinal, &jsonArrayValue, &jsonGroupInverse, WAGG_FLAGS);
    k += 1;
    a[k] = waggregate("json_group_object", 2, 0, 0, &jsonObjectStep, &jsonObjectFinal, &jsonObjectValue, &jsonGroupInverse, WAGG_FLAGS);
    k += 1;
    a[k] = waggregate("jsonb_group_object", 2, JSON_BLOB, 0, &jsonObjectStep, &jsonObjectFinal, &jsonObjectValue, &jsonGroupInverse, WAGG_FLAGS);
    k += 1;
    return a;
}

const nJsonFunc: usize = 32 + (if (config.sqlite_debug) @as(usize, 1) else 0) + 4;

var aJsonFunc: [nJsonFunc]FuncDef = buildJsonFuncTable();

pub export fn sqlite3RegisterJsonFunctions() callconv(.c) void {
    sqlite3InsertBuiltinFuncs(&aJsonFunc, @intCast(nJsonFunc));
}

pub export fn sqlite3JsonVtabRegister(db: ?*anyopaque, zName: [*:0]const u8) callconv(.c) ?*anyopaque {
    const azModule = [_][*:0]const u8{ "json_each", "json_tree", "jsonb_each", "jsonb_tree" };
    for (azModule) |m| {
        if (sqlite3StrICmp(m, zName) == 0) {
            return sqlite3VtabCreateModule(db, m, &jsonEachModule, null, null);
        }
    }
    return null;
}
