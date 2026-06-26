//! Zig port of SQLite's src/func.c — the C-language implementations of most of
//! SQLite's built-in SQL scalar and aggregate functions (length, substr, abs,
//! round, upper/lower, like/glob, char, hex, quote, replace, trim, min/max,
//! coalesce/iif, typeof, instr, printf/format, concat, sum/avg/total, count,
//! group_concat, the percentile family, and the math functions).
//!
//! External-linkage (non-static) symbols of func.c — these are exported here:
//!   * sqlite3_strglob(const char*, const char*)
//!   * sqlite3_strlike(const char*, const char*, unsigned int)
//!   * sqlite3QuoteValue(StrAccum*, sqlite3_value*, int)
//!   * sqlite3RegisterPerConnectionBuiltinFunctions(sqlite3*)
//!   * sqlite3RegisterLikeFunctions(sqlite3*, int)
//!   * sqlite3IsLikeFunction(sqlite3*, Expr*, int*, char*)
//!   * sqlite3RegisterBuiltinFunctions(void)
//!   * sqlite3_like_count (SQLITE_TEST only — gated on config.sqlite_test)
//! Everything else is file-scope (private here), exactly as in func.c.
//!
//! Configuration assumed (matching BOTH this project's builds):
//!   * SQLITE_OMIT_FLOATING_POINT OFF, SQLITE_ENABLE_MATH_FUNCTIONS ON,
//!     SQLITE_HAVE_C99_MATH_FUNCS ON (glibc), SQLITE_ENABLE_PERCENTILE ON,
//!     SQLITE_ENABLE_UNKNOWN_SQL_FUNCTION ON, SQLITE_ENABLE_OFFSET_SQL_FUNC ON,
//!     SQLITE_OMIT_COMPILEOPTION_DIAGS OFF, SQLITE_OMIT_LOAD_EXTENSION OFF,
//!     SQLITE_OMIT_WINDOWFUNC OFF, SQLITE_SOUNDEX OFF, SQLITE_EBCDIC OFF,
//!     SQLITE_CASE_SENSITIVE_LIKE OFF, SQLITE_LIKE_DOESNT_MATCH_BLOBS OFF,
//!     SQLITE_OMIT_ALTERTABLE OFF, SQLITE_SUBSTR_COMPATIBILITY OFF,
//!     SQLITE_OMIT_DEPRECATED OFF.
//!   * SQLITE_DEBUG / SQLITE_TEST: gated on config (testfixture build adds the
//!     fpdecode/parseuri/sqlite_filestat funcs, the implies_nonnull_row /
//!     expr_compare / expr_implies_expr / affinity TEST_FUNCs, and the
//!     sqlite3_like_count global).
//!
//! Struct coupling: FuncDef (ABI; sizeof 72, mirror identical to date.zig),
//! compareInfo (4 bytes; file-internal but its address is published as
//! pUserData and the first 3 bytes are memcpy'd by sqlite3IsLikeFunction),
//! sqlite3_context (skipFlag/iOp/isError/pVdbe at ground-truth offsets),
//! Mem/sqlite3_value (flags/db for the min/max aggregate at ground-truth
//! offsets), VdbeOp.p4 (the collating function pointer). The aggregate context
//! objects (SumCtx, CountCtx, GroupConcatCtx, Percentile) are purely internal
//! heap objects (sqlite3_aggregate_context) and are ordinary Zig structs.

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

const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;
const SQLITE_TEXT: c_int = 3;
const SQLITE_BLOB: c_int = 4;
const SQLITE_NULL: c_int = 5;

const SQLITE_UTF8: c_int = 1;
const SQLITE_UTF8_ZT: c_int = 16; // zero-terminated UTF8

// sqlite3_result_str eOwn control values
const SQLITE_COPY: c_int = 0;
const SQLITE_XFER: c_int = 1;
const SQLITE_FINISH: c_int = 2;

const SMALLEST_INT64: i64 = std.math.minInt(i64);
const LARGEST_INT64: i64 = std.math.maxInt(i64);

// limit indices
const SQLITE_LIMIT_LENGTH: usize = 0;
const SQLITE_LIMIT_LIKE_PATTERN_LENGTH: usize = 8;

// connection flag
const SQLITE_LoadExtFunc: u64 = 0x00020000;

// SQLITE_TRANSIENT = (sqlite3_destructor_type)-1, SQLITE_STATIC = 0
const XDel = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_TRANSIENT: XDel = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const SQLITE_STATIC: XDel = null;

// ─── FuncDef flag constants ─────────────────────────────────────────────────
const SQLITE_FUNC_NEEDCOLL: u32 = 0x0020;
const SQLITE_FUNC_LENGTH: u32 = 0x0040;
const SQLITE_FUNC_TYPEOF: u32 = 0x0080;
const SQLITE_FUNC_BYTELEN: u32 = 0x00c0;
const SQLITE_FUNC_COUNT: u32 = 0x0100;
const SQLITE_FUNC_UNLIKELY: u32 = 0x0400;
const SQLITE_FUNC_CONSTANT: u32 = 0x0800;
const SQLITE_FUNC_MINMAX: u32 = 0x1000;
const SQLITE_FUNC_SLOCHNG: u32 = 0x2000;
const SQLITE_FUNC_TEST: u32 = 0x4000;
const SQLITE_FUNC_INTERNAL: u32 = 0x00040000;
const SQLITE_FUNC_INLINE: u32 = 0x00400000;
const SQLITE_FUNC_BUILTIN: u32 = 0x00800000;
const SQLITE_FUNC_DIRECTONLY: u32 = 0x000080000;
const SQLITE_FUNC_UNSAFE: u32 = 0x00200000;
const SQLITE_FUNC_ANYORDER: u32 = 0x08000000;
const SQLITE_FUNC_LIKE: u32 = 0x0004;
const SQLITE_FUNC_CASE: u32 = 0x0008;
const SQLITE_UTF8_FLAG: u32 = 1;
// public flags reused in the table
const SQLITE_SUBTYPE: u32 = 0x000100000;
const SQLITE_INNOCUOUS: u32 = 0x000200000;
const SQLITE_SELFORDER1: u32 = 0x002000000;

// INLINEFUNC_* iArg constants
const INLINEFUNC_coalesce: c_int = 0;
const INLINEFUNC_implies_nonnull_row: c_int = 1;
const INLINEFUNC_expr_implies_expr: c_int = 2;
const INLINEFUNC_expr_compare: c_int = 3;
const INLINEFUNC_affinity: c_int = 4;
const INLINEFUNC_iif: c_int = 5;
const INLINEFUNC_sqlite_offset: c_int = 6;
const INLINEFUNC_unlikely: c_int = 99;

// ─── extern globals (config-invariant ctype/case tables) ────────────────────
extern var sqlite3Config: anyopaque;
extern const sqlite3CtypeMap: [256]u8;
extern const sqlite3UpperToLower: [256]u8;

inline fn toupper(x: u8) u8 {
    return x & ~(sqlite3CtypeMap[x] & 0x20);
}
inline fn tolower(x: u8) u8 {
    return sqlite3UpperToLower[x];
}
inline fn isalpha(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x02) != 0;
}
inline fn isxdigit(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x08) != 0;
}

// ─── extern internal-ABI helpers (resolved at link time) ────────────────────
const Ctx = anyopaque; // sqlite3_context*
const Val = anyopaque; // sqlite3_value* / Mem*

extern fn sqlite3_value_type(v: ?*Val) c_int;
extern fn sqlite3_value_numeric_type(v: ?*Val) c_int;
extern fn sqlite3_value_double(v: ?*Val) f64;
extern fn sqlite3_value_int(v: ?*Val) c_int;
extern fn sqlite3_value_int64(v: ?*Val) i64;
extern fn sqlite3_value_text(v: ?*Val) ?[*:0]const u8;
extern fn sqlite3_value_blob(v: ?*Val) ?[*]const u8;
extern fn sqlite3_value_bytes(v: ?*Val) c_int;
extern fn sqlite3_value_bytes16(v: ?*Val) c_int;
extern fn sqlite3_value_encoding(v: ?*Val) c_int;
extern fn sqlite3_value_subtype(v: ?*Val) c_uint;
extern fn sqlite3_value_dup(v: ?*const Val) ?*Val;
extern fn sqlite3_value_free(v: ?*Val) void;

extern fn sqlite3_result_double(ctx: ?*Ctx, r: f64) void;
extern fn sqlite3_result_int(ctx: ?*Ctx, n: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*Ctx, n: i64) void;
extern fn sqlite3_result_null(ctx: ?*Ctx) void;
extern fn sqlite3_result_text(ctx: ?*Ctx, z: ?[*]const u8, n: c_int, xDel: XDel) void;
extern fn sqlite3_result_text64(ctx: ?*Ctx, z: ?[*]const u8, n: u64, xDel: XDel, enc: u8) void;
extern fn sqlite3_result_blob(ctx: ?*Ctx, z: ?*const anyopaque, n: c_int, xDel: XDel) void;
extern fn sqlite3_result_blob64(ctx: ?*Ctx, z: ?*const anyopaque, n: u64, xDel: XDel) void;
extern fn sqlite3_result_str(ctx: ?*Ctx, p: ?*anyopaque, eOwn: c_int) void;
extern fn sqlite3_result_value(ctx: ?*Ctx, v: ?*Val) void;
extern fn sqlite3_result_error(ctx: ?*Ctx, z: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*Ctx) void;
extern fn sqlite3_result_error_toobig(ctx: ?*Ctx) void;
extern fn sqlite3_result_error_code(ctx: ?*Ctx, code: c_int) void;
extern fn sqlite3_result_zeroblob64(ctx: ?*Ctx, n: u64) c_int;

extern fn sqlite3_context_db_handle(ctx: ?*Ctx) ?*anyopaque;
extern fn sqlite3_user_data(ctx: ?*Ctx) ?*anyopaque;
extern fn sqlite3_aggregate_context(ctx: ?*Ctx, nByte: c_int) ?*anyopaque;
extern fn sqlite3_aggregate_count(ctx: ?*Ctx) c_int;

extern fn sqlite3_randomness(n: c_int, p: ?*anyopaque) void;
extern fn sqlite3_last_insert_rowid(db: ?*anyopaque) i64;
extern fn sqlite3_changes64(db: ?*anyopaque) i64;
extern fn sqlite3_total_changes64(db: ?*anyopaque) i64;
extern fn sqlite3_libversion() [*:0]const u8;
extern fn sqlite3_sourceid() [*:0]const u8;
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_compileoption_used(zName: [*:0]const u8) c_int;
extern fn sqlite3_compileoption_get(n: c_int) ?[*:0]const u8;
extern fn sqlite3_load_extension(db: ?*anyopaque, zFile: ?[*:0]const u8, zProc: ?[*:0]const u8, pzErrMsg: *?[*:0]u8) c_int;
extern fn sqlite3_overload_function(db: ?*anyopaque, zName: [*:0]const u8, nArg: c_int) c_int;

extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;

extern fn sqlite3StrAccumInit(p: *anyopaque, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) void;
extern fn sqlite3StrAccumEnlarge(p: *anyopaque, n: i64) c_int;
extern fn sqlite3StrAccumSetError(p: *anyopaque, code: u8) void;
extern fn sqlite3_str_new(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3_str_append(p: ?*anyopaque, z: ?[*]const u8, n: c_int) void;
extern fn sqlite3_str_appendchar(p: ?*anyopaque, n: c_int, c: u8) void;
extern fn sqlite3_str_appendf(p: ?*anyopaque, fmt: [*:0]const u8, ...) void;

extern fn sqlite3AtoF(z: ?[*:0]const u8, pResult: *f64) c_int;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *std.builtin.VaList) ?[*:0]u8;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3Utf8Read(pz: *[*:0]const u8) c_uint;
extern fn sqlite3Utf8CharLen(z: [*:0]const u8, n: c_int) c_int;
extern fn sqlite3AppendOneUtf8Character(z: [*]u8, c: c_uint) c_int;
extern fn sqlite3HexToInt(h: c_int) u8;
extern fn sqlite3IsOverflow(r: f64) c_int;

extern fn sqlite3AddInt64(pA: *i64, iB: i64) c_int;
extern fn sqlite3SubInt64(pA: *i64, iB: i64) c_int;

extern fn sqlite3MemCompare(a: ?*const Val, b: ?*const Val, pColl: ?*const anyopaque) c_int;
extern fn sqlite3VdbeMemCopy(dest: *Val, src: *const Val) c_int;
extern fn sqlite3VdbeMemRelease(p: *Val) void;
extern fn sqlite3VdbeFuncName(ctx: ?*const Ctx) ?[*:0]const u8;
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3InsertBuiltinFuncs(aDef: [*]FuncDef, nDef: c_int) void;

const XFunc = ?*const fn (?*Ctx, c_int, ?*?*Val) callconv(.c) void;
const XFinal = ?*const fn (?*Ctx) callconv(.c) void;
extern fn sqlite3CreateFunc(
    db: ?*anyopaque,
    zName: [*:0]const u8,
    nArg: c_int,
    enc: c_int,
    pUserData: ?*anyopaque,
    xSFunc: XFunc,
    xStep: XFunc,
    xFinal: XFinal,
    xValue: XFinal,
    xInverse: XFunc,
    pDestructor: ?*anyopaque,
) c_int;
extern fn sqlite3FindFunction(db: ?*anyopaque, zName: [*:0]const u8, nArg: c_int, enc: u8, createFlag: u8) ?*FuncDef;

// Other registration entry points called by sqlite3RegisterBuiltinFunctions.
extern fn sqlite3AlterFunctions() void;
extern fn sqlite3WindowFunctions() void;
extern fn sqlite3RegisterDateTimeFunctions() void;
extern fn sqlite3RegisterJsonFunctions() void;

// libm functions used by the math table.
extern fn ceil(x: f64) f64;
extern fn floor(x: f64) f64;
extern fn trunc(x: f64) f64;
extern fn exp(x: f64) f64;
extern fn pow(x: f64, y: f64) f64;
extern fn fmod(x: f64, y: f64) f64;
extern fn acos(x: f64) f64;
extern fn asin(x: f64) f64;
extern fn atan(x: f64) f64;
extern fn atan2(x: f64, y: f64) f64;
extern fn cos(x: f64) f64;
extern fn sin(x: f64) f64;
extern fn tan(x: f64) f64;
extern fn cosh(x: f64) f64;
extern fn sinh(x: f64) f64;
extern fn tanh(x: f64) f64;
extern fn acosh(x: f64) f64;
extern fn asinh(x: f64) f64;
extern fn atanh(x: f64) f64;
extern fn sqrt(x: f64) f64;
extern fn log(x: f64) f64;
extern fn log10(x: f64) f64;
extern fn log2(x: f64) f64;
extern fn fabs(x: f64) f64;

// ─── FuncDef mirror (ABI; identical to date.zig; sizeof 72) ─────────────────
const FuncDef = extern struct {
    nArg: i16, // 0
    funcFlags: u32, // 4
    pUserData: ?*anyopaque, // 8
    pNext: ?*FuncDef, // 16
    xSFunc: ?*anyopaque, // 24
    xFinalize: ?*anyopaque, // 32
    xValue: ?*anyopaque, // 40
    xInverse: ?*anyopaque, // 48
    zName: ?[*:0]const u8, // 56
    u: extern union { pHash: ?*FuncDef, pDestructor: ?*anyopaque }, // 64
};
comptime {
    std.debug.assert(@sizeOf(FuncDef) == 72);
    std.debug.assert(@offsetOf(FuncDef, "funcFlags") == 4);
    std.debug.assert(@offsetOf(FuncDef, "pUserData") == 8);
    std.debug.assert(@offsetOf(FuncDef, "zName") == 56);
    std.debug.assert(@offsetOf(FuncDef, "u") == 64);
}

// FuncDef accessors for sqlite3RegisterLikeFunctions / sqlite3IsLikeFunction.
const FuncDef_funcFlags: usize = 4;
const FuncDef_pUserData: usize = 8;

// ─── compareInfo (GLOB/LIKE comparison spec) ────────────────────────────────
const CompareInfo = extern struct {
    matchAll: u8, // "*" or "%"
    matchOne: u8, // "?" or "_"
    matchSet: u8, // "[" or 0
    noCase: u8, // true to ignore case
};

const globInfo = CompareInfo{ .matchAll = '*', .matchOne = '?', .matchSet = '[', .noCase = 0 };
// LIKE ignores case (SQL-92), unless SQLITE_CASE_SENSITIVE_LIKE (OFF).
var likeInfoNorm = CompareInfo{ .matchAll = '%', .matchOne = '_', .matchSet = 0, .noCase = 1 };
var likeInfoAlt = CompareInfo{ .matchAll = '%', .matchOne = '_', .matchSet = 0, .noCase = 0 };
var globInfoMut = globInfo; // address published as pUserData for the glob() function

// patternMatch return codes
const SQLITE_MATCH: c_int = 0;
const SQLITE_NOMATCH: c_int = 1;
const SQLITE_NOWILDCARDMATCH: c_int = 2;

// ─── sqlite3_context accessors (ground-truth offsets) ───────────────────────
const Ctx_pVdbe: usize = off("sqlite3_context_pVdbe", 24);
const Ctx_iOp: usize = off("sqlite3_context_iOp", 32);
const Ctx_isError: usize = off("sqlite3_context_isError", 36);
const Ctx_skipFlag: usize = off("sqlite3_context_skipFlag", 41);

inline fn ctxBytes(ctx: ?*Ctx) [*]u8 {
    return @ptrCast(ctx.?);
}
inline fn ctxPVdbe(ctx: ?*Ctx) ?*anyopaque {
    const p: *align(1) ?*anyopaque = @ptrCast(ctxBytes(ctx) + Ctx_pVdbe);
    return p.*;
}
inline fn ctxIOp(ctx: ?*Ctx) c_int {
    const p: *align(1) c_int = @ptrCast(ctxBytes(ctx) + Ctx_iOp);
    return p.*;
}
inline fn ctxSetIsError(ctx: ?*Ctx, v: c_int) void {
    const p: *align(1) c_int = @ptrCast(ctxBytes(ctx) + Ctx_isError);
    p.* = v;
}
inline fn ctxIsError(ctx: ?*Ctx) c_int {
    const p: *align(1) c_int = @ptrCast(ctxBytes(ctx) + Ctx_isError);
    return p.*;
}
inline fn ctxSetSkipFlag(ctx: ?*Ctx, v: u8) void {
    ctxBytes(ctx)[Ctx_skipFlag] = v;
}

// Vdbe.aOp (the opcode array) lives at offset Vdbe_aOp; each VdbeOp is sizeof
// VdbeOp; the p4 union (which holds p4.pColl) is at VdbeOp_p4 within it.
const Vdbe_aOp: usize = off("Vdbe_aOp", 32);
const VdbeOp_sz: usize = off("sizeof_VdbeOp", 32);
const VdbeOp_p4: usize = off("VdbeOp_p4", 16);

// CollSeq* sqlite3GetFuncCollSeq(context) — returns
// context->pVdbe->aOp[context->iOp-1].p4.pColl
fn getFuncCollSeq(ctx: ?*Ctx) ?*const anyopaque {
    const pVdbe = ctxPVdbe(ctx);
    const aOpPtr: *align(1) [*]u8 = @ptrCast(@as([*]u8, @ptrCast(pVdbe.?)) + Vdbe_aOp);
    const aOp = aOpPtr.*;
    const opIdx: usize = @intCast(ctxIOp(ctx) - 1);
    const opBase = aOp + opIdx * VdbeOp_sz;
    const pColl: *align(1) ?*const anyopaque = @ptrCast(opBase + VdbeOp_p4);
    return pColl.*;
}

fn skipAccumulatorLoad(ctx: ?*Ctx) void {
    // assert(context->isError<=0)
    ctxSetIsError(ctx, -1);
    ctxSetSkipFlag(ctx, 1);
}

// ─── Mem accessors for the min/max aggregate ────────────────────────────────
const Mem_flags: usize = off("sqlite3_value_flags", 20);
const Mem_db: usize = off("sqlite3_value_db", 24);

inline fn memFlags(p: ?*Val) u16 {
    const q: *align(1) const u16 = @ptrCast(@as([*]u8, @ptrCast(p.?)) + Mem_flags);
    return q.*;
}
inline fn memSetDb(p: ?*Val, db: ?*anyopaque) void {
    const q: *align(1) ?*anyopaque = @ptrCast(@as([*]u8, @ptrCast(p.?)) + Mem_db);
    q.* = db;
}

// sqlite3* accessors
inline fn dbLimit(db: ?*anyopaque, comptime idx: usize) c_int {
    const aLimitOff = off("sqlite3_aLimit", 136);
    const p: *align(1) const c_int = @ptrCast(@as([*]u8, @ptrCast(db.?)) + aLimitOff + idx * 4);
    return p.*;
}
inline fn dbEnc(db: ?*anyopaque) c_int {
    const encOff = off("sqlite3_enc", 100);
    return @as(*align(1) const u8, @ptrCast(@as([*]u8, @ptrCast(db.?)) + encOff)).*;
}
inline fn dbFlags(db: ?*anyopaque) u64 {
    const flagsOff = off("sqlite3_flags", 48);
    const p: *align(1) const u64 = @ptrCast(@as([*]u8, @ptrCast(db.?)) + flagsOff);
    return p.*;
}

// ─── UTF-8 helpers ──────────────────────────────────────────────────────────
// Utf8Read(A): A[0]<0x80 ? *(A++) : sqlite3Utf8Read(&A)
inline fn utf8Read(pz: *[*:0]const u8) c_uint {
    if (pz.*[0] < 0x80) {
        const c = pz.*[0];
        pz.* += 1;
        return c;
    }
    return sqlite3Utf8Read(pz);
}

// SQLITE_SKIP_UTF8(z): advance z past one UTF-8 character.
inline fn skipUtf8(pz: *[*:0]const u8) void {
    var z = pz.*;
    if (z[0] >= 0xc0) {
        z += 1;
        while ((z[0] & 0xc0) == 0x80) z += 1;
    } else {
        z += 1;
    }
    pz.* = z;
}

// ─── sqlite3GetFuncCollSeq used; below: the SQL function implementations ─────

fn minmaxFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    // mask = user_data==0 ? 0 (min) : -1 (max)
    const mask: c_int = if (sqlite3_user_data(ctx) == null) 0 else -1;
    const pColl = getFuncCollSeq(ctx);
    var iBest: usize = 0;
    if (sqlite3_value_type(a[0]) == SQLITE_NULL) return;
    var i: usize = 1;
    while (i < @as(usize, @intCast(argc))) : (i += 1) {
        if (sqlite3_value_type(a[i]) == SQLITE_NULL) return;
        if ((sqlite3MemCompare(a[iBest], a[i], pColl) ^ mask) >= 0) {
            iBest = i;
        }
    }
    sqlite3_result_value(ctx, a[iBest]);
}

const azType = [_][*:0]const u8{ "integer", "real", "text", "blob", "null" };

fn typeofFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const idx: usize = @intCast(sqlite3_value_type(a[0]) - 1);
    sqlite3_result_text(ctx, azType[idx], -1, SQLITE_STATIC);
}

fn subtypeFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    sqlite3_result_int(ctx, @bitCast(sqlite3_value_subtype(a[0])));
}

fn lengthFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    switch (sqlite3_value_type(a[0])) {
        SQLITE_BLOB, SQLITE_INTEGER, SQLITE_FLOAT => {
            sqlite3_result_int(ctx, sqlite3_value_bytes(a[0]));
        },
        SQLITE_TEXT => {
            const z0opt = sqlite3_value_text(a[0]);
            if (z0opt == null) return;
            var z: [*:0]const u8 = z0opt.?;
            var z0: [*:0]const u8 = z;
            while (true) {
                if (@as(u8, z[0] -% 1) < (0x80 - 1)) {
                    z += 1;
                } else if (z[0] == 0) {
                    break;
                } else {
                    z += 1;
                    while ((z[0] & 0xc0) == 0x80) {
                        z += 1;
                        z0 += 1;
                    }
                }
            }
            sqlite3_result_int(ctx, @intCast(@intFromPtr(z) - @intFromPtr(z0)));
        },
        else => sqlite3_result_null(ctx),
    }
}

fn bytelengthFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    switch (sqlite3_value_type(a[0])) {
        SQLITE_BLOB => sqlite3_result_int(ctx, sqlite3_value_bytes(a[0])),
        SQLITE_INTEGER, SQLITE_FLOAT => {
            const db = sqlite3_context_db_handle(ctx);
            const m: i64 = if (dbEnc(db) <= SQLITE_UTF8) 1 else 2;
            sqlite3_result_int64(ctx, @as(i64, sqlite3_value_bytes(a[0])) * m);
        },
        SQLITE_TEXT => {
            if (sqlite3_value_encoding(a[0]) <= SQLITE_UTF8) {
                sqlite3_result_int(ctx, sqlite3_value_bytes(a[0]));
            } else {
                sqlite3_result_int(ctx, sqlite3_value_bytes16(a[0]));
            }
        },
        else => sqlite3_result_null(ctx),
    }
}

fn absFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    switch (sqlite3_value_type(a[0])) {
        SQLITE_INTEGER => {
            var iVal = sqlite3_value_int64(a[0]);
            if (iVal < 0) {
                if (iVal == SMALLEST_INT64) {
                    sqlite3_result_error(ctx, "integer overflow", -1);
                    return;
                }
                iVal = -iVal;
            }
            sqlite3_result_int64(ctx, iVal);
        },
        SQLITE_NULL => sqlite3_result_null(ctx),
        else => {
            var rVal = sqlite3_value_double(a[0]);
            if (rVal < 0) rVal = -rVal;
            sqlite3_result_double(ctx, rVal);
        },
    }
}

fn instrFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var N: c_int = 1;
    var pC1: ?*Val = null;
    var pC2: ?*Val = null;

    const typeHay = sqlite3_value_type(a[0]);
    const typeNeedle = sqlite3_value_type(a[1]);
    if (typeHay == SQLITE_NULL or typeNeedle == SQLITE_NULL) return;
    var nHay = sqlite3_value_bytes(a[0]);
    var nNeedle = sqlite3_value_bytes(a[1]);
    var zHay: ?[*]const u8 = null;
    var zNeedle: ?[*]const u8 = null;
    var isText: bool = false;
    var oom = false;

    if (nNeedle > 0) {
        if (typeHay == SQLITE_BLOB and typeNeedle == SQLITE_BLOB) {
            zHay = sqlite3_value_blob(a[0]);
            zNeedle = sqlite3_value_blob(a[1]);
            isText = false;
        } else if (typeHay != SQLITE_BLOB and typeNeedle != SQLITE_BLOB) {
            zHay = sqlite3_value_text(a[0]);
            zNeedle = sqlite3_value_text(a[1]);
            isText = true;
        } else {
            pC1 = sqlite3_value_dup(a[0]);
            zHay = sqlite3_value_text(pC1);
            if (zHay == null) {
                oom = true;
            } else {
                nHay = sqlite3_value_bytes(pC1);
                pC2 = sqlite3_value_dup(a[1]);
                zNeedle = sqlite3_value_text(pC2);
                if (zNeedle == null) {
                    oom = true;
                } else {
                    nNeedle = sqlite3_value_bytes(pC2);
                    isText = true;
                }
            }
        }
        if (!oom) {
            if (zNeedle == null or (nHay != 0 and zHay == null)) {
                oom = true;
            } else {
                const firstChar = zNeedle.?[0];
                var hay = zHay.?;
                while (nNeedle <= nHay and
                    (hay[0] != firstChar or
                    !std.mem.eql(u8, hay[0..@intCast(nNeedle)], zNeedle.?[0..@intCast(nNeedle)])))
                {
                    N += 1;
                    while (true) {
                        nHay -= 1;
                        hay += 1;
                        if (!(isText and (hay[0] & 0xc0) == 0x80)) break;
                    }
                }
                if (nNeedle > nHay) N = 0;
            }
        }
    }
    if (oom) {
        sqlite3_result_error_nomem(ctx);
    } else {
        sqlite3_result_int(ctx, N);
    }
    sqlite3_value_free(pC1);
    sqlite3_value_free(pC2);
}

// PrintfArguments mirror — passed by pointer to sqlite3_str_appendf for %z-args.
const SQLITE_PRINTF_SQLFUNC: u8 = 0x02;
const StrAccumSz = off("sizeof_StrAccum", 32);
const PrintfArguments = extern struct {
    nArg: c_int,
    nUsed: c_int,
    apArg: ?[*]?*Val,
};

fn printfFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const db = sqlite3_context_db_handle(ctx);
    if (argc >= 1) {
        const zFormat = sqlite3_value_text(a[0]);
        if (zFormat) |fmt| {
            var x = PrintfArguments{
                .nArg = argc - 1,
                .nUsed = 0,
                .apArg = @ptrCast(a + 1),
            };
            var str: [64]u8 align(16) = undefined; // StrAccum storage (sizeof 32, give margin)
            const pStr: *anyopaque = @ptrCast(&str);
            sqlite3StrAccumInit(pStr, db, null, 0, dbLimit(db, SQLITE_LIMIT_LENGTH));
            // str.printfFlags = SQLITE_PRINTF_SQLFUNC  (offset 29)
            @as([*]u8, @ptrCast(pStr))[29] = SQLITE_PRINTF_SQLFUNC;
            sqlite3_str_appendf(pStr, fmt, &x);
            sqlite3_result_str(ctx, pStr, SQLITE_XFER);
        }
    }
}

fn substrFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const p0type = sqlite3_value_type(a[0]);
    var p1: i64 = sqlite3_value_int64(a[1]);
    var p2: i64 = undefined;
    var len: c_int = 0;
    var z: [*:0]const u8 = undefined;
    var zBlob: ?[*]const u8 = null;

    if (p0type == SQLITE_BLOB) {
        len = sqlite3_value_bytes(a[0]);
        const b = sqlite3_value_blob(a[0]);
        if (b == null) return;
        zBlob = b;
    } else {
        const zo = sqlite3_value_text(a[0]);
        if (zo == null) return;
        z = zo.?;
        len = 0;
        if (p1 < 0) {
            var z2: [*:0]const u8 = z;
            while (z2[0] != 0) {
                len += 1;
                skipUtf8(&z2);
            }
        }
    }
    if (argc == 3) {
        p2 = sqlite3_value_int64(a[2]);
        if (p2 == 0 and sqlite3_value_type(a[2]) == SQLITE_NULL) return;
    } else {
        p2 = dbLimit(sqlite3_context_db_handle(ctx), SQLITE_LIMIT_LENGTH);
    }
    if (p1 == 0) {
        if (sqlite3_value_type(a[1]) == SQLITE_NULL) return;
    }
    if (p1 < 0) {
        p1 += len;
        if (p1 < 0) {
            if (p2 < 0) {
                p2 = 0;
            } else {
                p2 += p1;
            }
            p1 = 0;
        }
    } else if (p1 > 0) {
        p1 -= 1;
    } else if (p2 > 0) {
        p2 -= 1;
    }
    if (p2 < 0) {
        if (p2 < -p1) {
            p2 = p1;
        } else {
            p2 = -p2;
        }
        p1 -= p2;
    }
    // assert(p1>=0 && p2>=0)
    if (p0type != SQLITE_BLOB) {
        var zp = z;
        while (p1 > 0) : (p1 -= 1) {
            if (@as(u8, zp[0] -% 1) < (0x80 - 1)) {
                zp += 1;
            } else if (zp[0] == 0) {
                break;
            } else {
                zp += 1;
                while ((zp[0] & 0xc0) == 0x80) zp += 1;
            }
        }
        var z2 = zp;
        while (p2 > 0) : (p2 -= 1) {
            if (@as(u8, z2[0] -% 1) < (0x80 - 1)) {
                z2 += 1;
            } else if (z2[0] == 0) {
                break;
            } else {
                z2 += 1;
                while ((z2[0] & 0xc0) == 0x80) z2 += 1;
            }
        }
        const n: u64 = @intCast(@intFromPtr(z2) - @intFromPtr(zp));
        sqlite3_result_text64(ctx, zp, n, SQLITE_TRANSIENT, SQLITE_UTF8);
    } else {
        const lenI: i64 = len;
        if (p1 >= lenI) {
            p1 = 0;
            p2 = 0;
        } else if (p2 > lenI - p1) {
            p2 = lenI - p1;
        }
        const base = zBlob.? + @as(usize, @intCast(p1));
        sqlite3_result_blob64(ctx, base, @intCast(p2), SQLITE_TRANSIENT);
    }
}

fn roundFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var n: i64 = 0;
    if (argc == 2) {
        if (sqlite3_value_type(a[1]) == SQLITE_NULL) return;
        n = sqlite3_value_int64(a[1]);
        if (n > 30) n = 30;
        if (n < 0) n = 0;
    }
    if (sqlite3_value_type(a[0]) == SQLITE_NULL) return;
    var r = sqlite3_value_double(a[0]);
    if (r < -4503599627370496.0 or r > 4503599627370496.0) {
        // no fractional part
    } else if (n == 0) {
        const adj: f64 = if (r < 0) -0.5 else 0.5;
        r = @floatFromInt(@as(i64, @intFromFloat(r + adj)));
    } else {
        const zBuf = sqlite3_mprintf("%!.*f", @as(c_int, @intCast(n)), r);
        if (zBuf == null) {
            sqlite3_result_error_nomem(ctx);
            return;
        }
        _ = sqlite3AtoF(zBuf, &r);
        sqlite3_free(zBuf);
    }
    sqlite3_result_double(ctx, r);
}

// contextMalloc: allocate nByte; result_error on too-big / nomem; return null.
fn contextMalloc(ctx: ?*Ctx, nByte: i64) ?[*]u8 {
    const db = sqlite3_context_db_handle(ctx);
    if (nByte > dbLimit(db, SQLITE_LIMIT_LENGTH)) {
        sqlite3_result_error_toobig(ctx);
        return null;
    }
    const z = sqlite3Malloc(@intCast(nByte));
    if (z == null) {
        sqlite3_result_error_nomem(ctx);
    }
    return @ptrCast(z);
}

fn upperFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const z2o = sqlite3_value_text(a[0]);
    const n = sqlite3_value_bytes(a[0]);
    if (z2o) |z2| {
        const z1 = contextMalloc(ctx, @as(i64, n) + 1);
        if (z1) |out| {
            var i: usize = 0;
            while (i < @as(usize, @intCast(n))) : (i += 1) {
                out[i] = toupper(z2[i]);
            }
            sqlite3_result_text(ctx, out, n, @ptrCast(&sqlite3_free));
        }
    }
}

fn lowerFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const z2o = sqlite3_value_text(a[0]);
    const n = sqlite3_value_bytes(a[0]);
    if (z2o) |z2| {
        const z1 = contextMalloc(ctx, @as(i64, n) + 1);
        if (z1) |out| {
            var i: usize = 0;
            while (i < @as(usize, @intCast(n))) : (i += 1) {
                out[i] = tolower(z2[i]);
            }
            sqlite3_result_text(ctx, out, n, @ptrCast(&sqlite3_free));
        }
    }
}

fn randomFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    var r: i64 = undefined;
    sqlite3_randomness(@sizeOf(i64), &r);
    if (r < 0) {
        r = -(r & LARGEST_INT64);
    }
    sqlite3_result_int64(ctx, r);
}

fn randomBlob(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var n = sqlite3_value_int64(a[0]);
    if (n < 1) n = 1;
    const p = contextMalloc(ctx, n);
    if (p) |buf| {
        sqlite3_randomness(@intCast(n), buf);
        sqlite3_result_blob(ctx, buf, @intCast(n), @ptrCast(&sqlite3_free));
    }
}

fn lastInsertRowid(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    const db = sqlite3_context_db_handle(ctx);
    sqlite3_result_int64(ctx, sqlite3_last_insert_rowid(db));
}

fn changesFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    const db = sqlite3_context_db_handle(ctx);
    sqlite3_result_int64(ctx, sqlite3_changes64(db));
}

fn totalChangesFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    const db = sqlite3_context_db_handle(ctx);
    sqlite3_result_int64(ctx, sqlite3_total_changes64(db));
}

// ─── patternCompare (GLOB/LIKE matcher) ─────────────────────────────────────
fn patternCompare(
    zPattern0: [*:0]const u8,
    zString0: [*:0]const u8,
    pInfo: *const CompareInfo,
    matchOther: c_uint,
) c_int {
    var zPattern: [*:0]const u8 = zPattern0;
    var zString: [*:0]const u8 = zString0;
    const matchOne: c_uint = pInfo.matchOne;
    const matchAll: c_uint = pInfo.matchAll;
    const noCase: bool = pInfo.noCase != 0;
    var zEscaped: ?[*:0]const u8 = null;
    var c: c_uint = undefined;
    var c2: c_uint = undefined;

    c = utf8Read(&zPattern);
    while (c != 0) {
        if (c == matchAll) {
            // skip multiple "*" / "?"
            c = utf8Read(&zPattern);
            while (c == matchAll or (c == matchOne and matchOne != 0)) {
                if (c == matchOne and sqlite3Utf8Read(&zString) == 0) {
                    return SQLITE_NOWILDCARDMATCH;
                }
                c = utf8Read(&zPattern);
            }
            if (c == 0) {
                return SQLITE_MATCH;
            } else if (c == matchOther) {
                if (pInfo.matchSet == 0) {
                    c = sqlite3Utf8Read(&zPattern);
                    if (c == 0) return SQLITE_NOWILDCARDMATCH;
                } else {
                    // "[...]" after "*": slow recursive search.
                    while (zString[0] != 0) {
                        const bMatch = patternCompare(@ptrCast(zPattern - 1), zString, pInfo, matchOther);
                        if (bMatch != SQLITE_NOMATCH) return bMatch;
                        skipUtf8(&zString);
                    }
                    return SQLITE_NOWILDCARDMATCH;
                }
            }
            if (c < 0x80) {
                var zStop: [3]u8 = undefined;
                if (noCase) {
                    zStop[0] = toupper(@truncate(c));
                    zStop[1] = tolower(@truncate(c));
                    zStop[2] = 0;
                } else {
                    zStop[0] = @truncate(c);
                    zStop[1] = 0;
                }
                while (true) {
                    // zString += strcspn(zString, zStop)
                    while (zString[0] != 0 and
                        zString[0] != zStop[0] and
                        (zStop[1] == 0 or zString[0] != zStop[1]))
                    {
                        zString += 1;
                    }
                    if (zString[0] == 0) break;
                    zString += 1;
                    const bMatch = patternCompare(zPattern, zString, pInfo, matchOther);
                    if (bMatch != SQLITE_NOMATCH) return bMatch;
                }
            } else {
                while (true) {
                    c2 = utf8Read(&zString);
                    if (c2 == 0) break;
                    if (c2 != c) continue;
                    const bMatch = patternCompare(zPattern, zString, pInfo, matchOther);
                    if (bMatch != SQLITE_NOMATCH) return bMatch;
                }
            }
            return SQLITE_NOWILDCARDMATCH;
        }
        if (c == matchOther) {
            if (pInfo.matchSet == 0) {
                c = sqlite3Utf8Read(&zPattern);
                if (c == 0) return SQLITE_NOMATCH;
                zEscaped = zPattern;
            } else {
                var prior_c: c_uint = 0;
                var seen: c_int = 0;
                var invert: c_int = 0;
                c = sqlite3Utf8Read(&zString);
                if (c == 0) return SQLITE_NOMATCH;
                c2 = sqlite3Utf8Read(&zPattern);
                if (c2 == '^') {
                    invert = 1;
                    c2 = sqlite3Utf8Read(&zPattern);
                }
                if (c2 == ']') {
                    if (c == ']') seen = 1;
                    c2 = sqlite3Utf8Read(&zPattern);
                }
                while (c2 != 0 and c2 != ']') {
                    if (c2 == '-' and zPattern[0] != ']' and zPattern[0] != 0 and prior_c > 0) {
                        c2 = sqlite3Utf8Read(&zPattern);
                        if (c >= prior_c and c <= c2) seen = 1;
                        prior_c = 0;
                    } else {
                        if (c == c2) seen = 1;
                        prior_c = c2;
                    }
                    c2 = sqlite3Utf8Read(&zPattern);
                }
                if (c2 == 0 or (seen ^ invert) == 0) {
                    return SQLITE_NOMATCH;
                }
                c = utf8Read(&zPattern);
                continue;
            }
        }
        c2 = utf8Read(&zString);
        if (c == c2) {
            c = utf8Read(&zPattern);
            continue;
        }
        if (noCase and c < 0x80 and c2 < 0x80 and tolower(@truncate(c)) == tolower(@truncate(c2))) {
            c = utf8Read(&zPattern);
            continue;
        }
        // C: if( c==matchOne && zPattern!=zEscaped && c2!=0 ) continue;
        // zEscaped is null until set; a live zPattern pointer never equals null,
        // so "zPattern != zEscaped" holds whenever zEscaped is null.
        const zEscAddr: usize = if (zEscaped) |z| @intFromPtr(z) else 0;
        if (c == matchOne and @intFromPtr(zPattern) != zEscAddr and c2 != 0) {
            c = utf8Read(&zPattern);
            continue;
        }
        return SQLITE_NOMATCH;
    }
    return if (zString[0] == 0) SQLITE_MATCH else SQLITE_NOMATCH;
}

fn likeFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const db = sqlite3_context_db_handle(ctx);
    var pInfo: *CompareInfo = @ptrCast(@alignCast(sqlite3_user_data(ctx).?));
    var backupInfo: CompareInfo = undefined;
    var escape: c_uint = undefined;

    const nPat = sqlite3_value_bytes(a[0]);
    if (nPat > dbLimit(db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH)) {
        sqlite3_result_error(ctx, "LIKE or GLOB pattern too complex", -1);
        return;
    }
    if (argc == 3) {
        const zEscO = sqlite3_value_text(a[2]);
        if (zEscO == null) return;
        var zEsc = zEscO.?;
        if (sqlite3Utf8CharLen(zEsc, -1) != 1) {
            sqlite3_result_error(ctx, "ESCAPE expression must be a single character", -1);
            return;
        }
        escape = sqlite3Utf8Read(&zEsc);
        if (escape == pInfo.matchAll or escape == pInfo.matchOne) {
            backupInfo = pInfo.*;
            pInfo = &backupInfo;
            if (escape == pInfo.matchAll) pInfo.matchAll = 0;
            if (escape == pInfo.matchOne) pInfo.matchOne = 0;
        }
    } else {
        escape = pInfo.matchSet;
    }
    const zB = sqlite3_value_text(a[0]);
    const zA = sqlite3_value_text(a[1]);
    if (zA != null and zB != null) {
        if (config.sqlite_test) {
            sqlite3_like_count += 1;
        }
        sqlite3_result_int(ctx, @intFromBool(patternCompare(zB.?, zA.?, pInfo, escape) == SQLITE_MATCH));
    }
}

fn nullifFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const pColl = getFuncCollSeq(ctx);
    if (sqlite3MemCompare(a[0], a[1], pColl) != 0) {
        sqlite3_result_value(ctx, a[0]);
    }
}

fn versionFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    sqlite3_result_text(ctx, sqlite3_libversion(), -1, SQLITE_STATIC);
}

fn sourceidFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    sqlite3_result_text(ctx, sqlite3_sourceid(), -1, SQLITE_STATIC);
}

fn errlogFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = ctx;
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    sqlite3_log(sqlite3_value_int(a[0]), "%s", sqlite3_value_text(a[1]) orelse "");
}

fn compileoptionusedFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    if (sqlite3_value_text(a[0])) |zOpt| {
        sqlite3_result_int(ctx, sqlite3_compileoption_used(zOpt));
    }
}

fn compileoptiongetFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const n = sqlite3_value_int(a[0]);
    sqlite3_result_text(ctx, sqlite3_compileoption_get(n), -1, SQLITE_STATIC);
}

const hexdigits = "0123456789ABCDEF";

pub export fn sqlite3QuoteValue(pStr: *anyopaque, pValue: ?*Val, bEscape: c_int) callconv(.c) void {
    switch (sqlite3_value_type(pValue)) {
        SQLITE_FLOAT => {
            sqlite3_str_appendf(pStr, "%!0.17g", sqlite3_value_double(pValue));
        },
        SQLITE_INTEGER => {
            sqlite3_str_appendf(pStr, "%lld", sqlite3_value_int64(pValue));
        },
        SQLITE_BLOB => {
            const zBlob = sqlite3_value_blob(pValue);
            const nBlob = sqlite3_value_bytes(pValue);
            _ = sqlite3StrAccumEnlarge(pStr, @as(i64, nBlob) * 2 + 4);
            // accError at offset 28
            const sb: [*]u8 = @ptrCast(pStr);
            if (sb[28] == 0) {
                // zText at offset 8
                const zTextPtr: *align(1) [*]u8 = @ptrCast(sb + 8);
                const zText = zTextPtr.*;
                var i: usize = 0;
                const nb: usize = @intCast(nBlob);
                while (i < nb) : (i += 1) {
                    const cb = zBlob.?[i];
                    zText[(i * 2) + 2] = hexdigits[(cb >> 4) & 0x0F];
                    zText[(i * 2) + 3] = hexdigits[cb & 0x0F];
                }
                zText[(nb * 2) + 2] = '\'';
                zText[(nb * 2) + 3] = 0;
                zText[0] = 'X';
                zText[1] = '\'';
                // nChar at offset 24
                const nCharPtr: *align(1) u32 = @ptrCast(sb + 24);
                nCharPtr.* = @intCast(nb * 2 + 3);
            }
        },
        SQLITE_TEXT => {
            const zArg = sqlite3_value_text(pValue);
            sqlite3_str_appendf(pStr, if (bEscape != 0) "%#Q" else "%Q", zArg orelse "");
        },
        else => {
            sqlite3_str_append(pStr, "NULL", 4);
        },
    }
}

fn isNHex(z: [*]const u8, N: c_int, pVal: *c_uint) c_int {
    var v: c_uint = 0;
    var i: usize = 0;
    while (i < @as(usize, @intCast(N))) : (i += 1) {
        if (!isxdigit(z[i])) return 0;
        v = (v << 4) + sqlite3HexToInt(z[i]);
    }
    pVal.* = v;
    return 1;
}

fn unistrFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const zInO = sqlite3_value_text(a[0]);
    if (zInO == null) return;
    const zIn = zInO.?;
    const nIn = sqlite3_value_bytes(a[0]);
    const zOutPtr = sqlite3_malloc64(@as(u64, @intCast(nIn)) + 1);
    if (zOutPtr == null) {
        sqlite3_result_error_nomem(ctx);
        return;
    }
    const zOut: [*]u8 = @ptrCast(zOutPtr.?);
    var i: usize = 0;
    var j: usize = 0;
    var v: c_uint = undefined;
    const nInU: usize = @intCast(nIn);
    var err = false;
    while (i < nInU) {
        // find next '\\'
        var k = i;
        while (k < nInU and zIn[k] != '\\') k += 1;
        if (k >= nInU) {
            const n = nInU - i;
            @memmove(zOut[j .. j + n], zIn[i .. i + n]);
            j += n;
            break;
        }
        const n0 = k - i;
        if (n0 > 0) {
            @memmove(zOut[j .. j + n0], zIn[i .. i + n0]);
            j += n0;
            i += n0;
        }
        // i points at '\\'
        const nb = zIn[i + 1];
        if (nb == '\\') {
            i += 2;
            zOut[j] = '\\';
            j += 1;
        } else if (isxdigit(nb)) {
            if (isNHex(zIn + i + 1, 4, &v) == 0) {
                err = true;
                break;
            }
            i += 5;
            j += @intCast(sqlite3AppendOneUtf8Character(zOut + j, v));
        } else if (nb == '+') {
            if (isNHex(zIn + i + 2, 6, &v) == 0) {
                err = true;
                break;
            }
            i += 8;
            j += @intCast(sqlite3AppendOneUtf8Character(zOut + j, v));
        } else if (nb == 'u') {
            if (isNHex(zIn + i + 2, 4, &v) == 0) {
                err = true;
                break;
            }
            i += 6;
            j += @intCast(sqlite3AppendOneUtf8Character(zOut + j, v));
        } else if (nb == 'U') {
            if (isNHex(zIn + i + 2, 8, &v) == 0) {
                err = true;
                break;
            }
            i += 10;
            j += @intCast(sqlite3AppendOneUtf8Character(zOut + j, v));
        } else {
            err = true;
            break;
        }
    }
    if (err) {
        sqlite3_free(zOut);
        sqlite3_result_error(ctx, "invalid Unicode escape", -1);
        return;
    }
    zOut[j] = 0;
    sqlite3_result_text64(ctx, zOut, j, @ptrCast(&sqlite3_free), SQLITE_UTF8_ZT);
}

fn quoteFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const db = sqlite3_context_db_handle(ctx);
    var str: [64]u8 align(16) = undefined;
    const pStr: *anyopaque = @ptrCast(&str);
    sqlite3StrAccumInit(pStr, db, null, 0, dbLimit(db, SQLITE_LIMIT_LENGTH));
    const bEscape: c_int = @truncate(@as(isize, @bitCast(@intFromPtr(sqlite3_user_data(ctx)))));
    sqlite3QuoteValue(pStr, a[0], bEscape);
    sqlite3_result_str(ctx, pStr, SQLITE_XFER);
}

fn unicodeFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const zo = sqlite3_value_text(a[0]);
    if (zo) |z0| {
        if (z0[0] != 0) {
            var z = z0;
            sqlite3_result_int(ctx, @bitCast(sqlite3Utf8Read(&z)));
        }
    }
}

fn charFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const zPtr = sqlite3_malloc64(@as(u64, @intCast(argc)) * 4 + 1);
    if (zPtr == null) {
        sqlite3_result_error_nomem(ctx);
        return;
    }
    const z: [*]u8 = @ptrCast(zPtr.?);
    var zOut: [*]u8 = z;
    var i: usize = 0;
    while (i < @as(usize, @intCast(argc))) : (i += 1) {
        var x = sqlite3_value_int64(a[i]);
        if (x < 0 or x > 0x10ffff) x = 0xfffd;
        const c: u32 = @intCast(x & 0x1fffff);
        if (c < 0x00080) {
            zOut[0] = @truncate(c & 0xFF);
            zOut += 1;
        } else if (c < 0x00800) {
            zOut[0] = 0xC0 + @as(u8, @truncate((c >> 6) & 0x1F));
            zOut[1] = 0x80 + @as(u8, @truncate(c & 0x3F));
            zOut += 2;
        } else if (c < 0x10000) {
            zOut[0] = 0xE0 + @as(u8, @truncate((c >> 12) & 0x0F));
            zOut[1] = 0x80 + @as(u8, @truncate((c >> 6) & 0x3F));
            zOut[2] = 0x80 + @as(u8, @truncate(c & 0x3F));
            zOut += 3;
        } else {
            zOut[0] = 0xF0 + @as(u8, @truncate((c >> 18) & 0x07));
            zOut[1] = 0x80 + @as(u8, @truncate((c >> 12) & 0x3F));
            zOut[2] = 0x80 + @as(u8, @truncate((c >> 6) & 0x3F));
            zOut[3] = 0x80 + @as(u8, @truncate(c & 0x3F));
            zOut += 4;
        }
    }
    zOut[0] = 0;
    const n: u64 = @intCast(@intFromPtr(zOut) - @intFromPtr(z));
    sqlite3_result_text64(ctx, z, n, @ptrCast(&sqlite3_free), SQLITE_UTF8_ZT);
}

fn hexFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const pBlob = sqlite3_value_blob(a[0]);
    const n = sqlite3_value_bytes(a[0]);
    const zHex = contextMalloc(ctx, @as(i64, n) * 2 + 1);
    if (zHex) |zh| {
        var z = zh;
        var i: usize = 0;
        while (i < @as(usize, @intCast(n))) : (i += 1) {
            const cb = pBlob.?[i];
            z[0] = hexdigits[(cb >> 4) & 0xf];
            z[1] = hexdigits[cb & 0xf];
            z += 2;
        }
        z[0] = 0;
        const len: u64 = @intCast(@intFromPtr(z) - @intFromPtr(zh));
        sqlite3_result_text64(ctx, zh, len, @ptrCast(&sqlite3_free), SQLITE_UTF8_ZT);
    }
}

fn strContainsChar(zStr: [*]const u8, nStr: c_int, ch: c_uint) c_int {
    var z: [*:0]const u8 = @ptrCast(zStr);
    const zEnd = @intFromPtr(zStr) + @as(usize, @intCast(nStr));
    while (@intFromPtr(z) < zEnd) {
        const tst = utf8Read(&z);
        if (tst == ch) return 1;
    }
    return 0;
}

fn unhexFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var zPass: [*]const u8 = "";
    var nPass: c_int = 0;
    const zHexO = sqlite3_value_text(a[0]);
    const nHex = sqlite3_value_bytes(a[0]);

    if (argc == 2) {
        const zp = sqlite3_value_text(a[1]);
        if (zp == null) return;
        zPass = zp.?;
        nPass = sqlite3_value_bytes(a[1]);
    }
    if (zHexO == null) return;
    var zHex: [*:0]const u8 = zHexO.?;

    const pBlobPtr = contextMalloc(ctx, @divTrunc(@as(i64, nHex), 2) + 1);
    if (pBlobPtr == null) return;
    const pBlob = pBlobPtr.?;
    var p = pBlob;
    var nulled = false;

    outer: while (zHex[0] != 0) {
        var c = zHex[0];
        while (!isxdigit(c)) {
            const ch = utf8Read(&zHex);
            if (strContainsChar(zPass, nPass, ch) == 0) {
                nulled = true;
                break :outer;
            }
            c = zHex[0];
            if (c == 0) break :outer; // unhex_done
        }
        zHex += 1;
        const d = zHex[0];
        zHex += 1;
        if (!isxdigit(d)) {
            nulled = true;
            break :outer;
        }
        p[0] = (sqlite3HexToInt(c) << 4) | sqlite3HexToInt(d);
        p += 1;
    }

    if (nulled) {
        sqlite3_free(pBlob);
        return;
    }
    sqlite3_result_blob(ctx, pBlob, @intCast(@intFromPtr(p) - @intFromPtr(pBlob)), @ptrCast(&sqlite3_free));
}

fn zeroblobFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var n = sqlite3_value_int64(a[0]);
    if (n < 0) n = 0;
    const rc = sqlite3_result_zeroblob64(ctx, @intCast(n));
    if (rc != 0) {
        sqlite3_result_error_code(ctx, rc);
    }
}

fn replaceFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const db = sqlite3_context_db_handle(ctx);
    const zStrO = sqlite3_value_text(a[0]);
    if (zStrO == null) return;
    const zStr = zStrO.?;
    const nStr = sqlite3_value_bytes(a[0]);
    const zPatO = sqlite3_value_text(a[1]);
    if (zPatO == null) return;
    const zPattern = zPatO.?;
    if (zPattern[0] == 0) {
        sqlite3_result_text(ctx, zStr, nStr, SQLITE_TRANSIENT);
        return;
    }
    const nPattern = sqlite3_value_bytes(a[1]);
    const zRepO = sqlite3_value_text(a[2]);
    if (zRepO == null) return;
    const zRep = zRepO.?;
    const nRep = sqlite3_value_bytes(a[2]);
    var nOut: i64 = nStr + 1;
    var zOutPtr = contextMalloc(ctx, nOut);
    if (zOutPtr == null) return;
    var zOut = zOutPtr.?;
    const loopLimit = nStr - nPattern;
    var cntExpand: u32 = 0;
    var i: i64 = 0;
    var j: i64 = 0;
    while (i <= loopLimit) : (i += 1) {
        const iu: usize = @intCast(i);
        if (zStr[iu] != zPattern[0] or
            !std.mem.eql(u8, zStr[iu .. iu + @as(usize, @intCast(nPattern))], zPattern[0..@intCast(nPattern)]))
        {
            zOut[@intCast(j)] = zStr[iu];
            j += 1;
        } else {
            if (nRep > nPattern) {
                nOut += nRep - nPattern;
                if (nOut - 1 > dbLimit(db, SQLITE_LIMIT_LENGTH)) {
                    sqlite3_result_error_toobig(ctx);
                    sqlite3_free(zOut);
                    return;
                }
                cntExpand += 1;
                if ((cntExpand & (cntExpand - 1)) == 0) {
                    const newSz = nOut + (nOut - nStr - 1);
                    const zNew = sqlite3Realloc(zOut, @intCast(newSz));
                    if (zNew == null) {
                        sqlite3_result_error_nomem(ctx);
                        sqlite3_free(zOut);
                        return;
                    }
                    zOut = @ptrCast(zNew.?);
                    zOutPtr = zOut;
                }
            }
            @memcpy(zOut[@intCast(j) .. @as(usize, @intCast(j)) + @as(usize, @intCast(nRep))], zRep[0..@intCast(nRep)]);
            j += nRep;
            i += nPattern - 1;
        }
    }
    const tail: usize = @intCast(nStr - i);
    @memmove(zOut[@intCast(j) .. @as(usize, @intCast(j)) + tail], zStr[@intCast(i) .. @as(usize, @intCast(i)) + tail]);
    j += nStr - i;
    zOut[@intCast(j)] = 0;
    sqlite3_result_text(ctx, zOut, @intCast(j), @ptrCast(&sqlite3_free));
}

fn trimFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    if (sqlite3_value_type(a[0]) == SQLITE_NULL) return;
    const zInO = sqlite3_value_text(a[0]);
    if (zInO == null) return;
    var zIn: [*]const u8 = zInO.?;
    var nIn: u32 = @intCast(sqlite3_value_bytes(a[0]));

    var nChar: c_int = 0;
    var aLen: ?[*]u32 = null;
    var azChar: ?[*][*]const u8 = null;
    var zCharSet: ?[*:0]const u8 = null;
    var allocated: ?*anyopaque = null;

    const lenOne = [_]u32{1};
    const spaceStr: [*]const u8 = " ";
    var azOne = [_][*]const u8{spaceStr};

    if (argc == 1) {
        nChar = 1;
        aLen = @constCast(&lenOne);
        azChar = &azOne;
        zCharSet = null;
    } else {
        const zcs = sqlite3_value_text(a[1]);
        if (zcs == null) return;
        zCharSet = zcs.?;
        var z: [*:0]const u8 = zcs.?;
        nChar = 0;
        while (z[0] != 0) {
            nChar += 1;
            skipUtf8(&z);
        }
        if (nChar > 0) {
            const ncu: usize = @intCast(nChar);
            const bytes: i64 = @as(i64, nChar) * @as(i64, @sizeOf(usize) + @sizeOf(u32));
            const buf = contextMalloc(ctx, bytes);
            if (buf == null) return;
            allocated = @ptrCast(buf.?);
            azChar = @ptrCast(@alignCast(buf.?));
            aLen = @ptrCast(@alignCast(buf.? + ncu * @sizeOf(usize)));
            z = zcs.?;
            var k: usize = 0;
            while (z[0] != 0) : (k += 1) {
                azChar.?[k] = z;
                skipUtf8(&z);
                aLen.?[k] = @intCast(@intFromPtr(z) - @intFromPtr(azChar.?[k]));
            }
        }
    }
    if (nChar > 0) {
        const flags: c_int = @truncate(@as(isize, @bitCast(@intFromPtr(sqlite3_user_data(ctx)))));
        if (flags & 1 != 0) {
            while (nIn > 0) {
                var len: u32 = 0;
                var ii: c_int = 0;
                while (ii < nChar) : (ii += 1) {
                    len = aLen.?[@intCast(ii)];
                    if (len <= nIn and std.mem.eql(u8, zIn[0..len], azChar.?[@intCast(ii)][0..len])) break;
                }
                if (ii >= nChar) break;
                zIn += len;
                nIn -= len;
            }
        }
        if (flags & 2 != 0) {
            while (nIn > 0) {
                var len: u32 = 0;
                var ii: c_int = 0;
                while (ii < nChar) : (ii += 1) {
                    len = aLen.?[@intCast(ii)];
                    if (len <= nIn and std.mem.eql(u8, zIn[nIn - len .. nIn], azChar.?[@intCast(ii)][0..len])) break;
                }
                if (ii >= nChar) break;
                nIn -= len;
            }
        }
        if (zCharSet != null) {
            sqlite3_free(allocated);
        }
    }
    sqlite3_result_text(ctx, zIn, @intCast(nIn), SQLITE_TRANSIENT);
}

fn concatFuncCore(ctx: ?*Ctx, argc: c_int, argv: [*]?*Val, nSep: c_int, zSep: [*]const u8) void {
    var n: i64 = 0;
    var i: usize = 0;
    while (i < @as(usize, @intCast(argc))) : (i += 1) {
        n += sqlite3_value_bytes(argv[i]);
    }
    n += @as(i64, argc - 1) * nSep;
    const zPtr = sqlite3_malloc64(@intCast(n + 1));
    if (zPtr == null) {
        sqlite3_result_error_nomem(ctx);
        return;
    }
    const z: [*]u8 = @ptrCast(zPtr.?);
    var j: usize = 0;
    var bNotNull = false;
    i = 0;
    while (i < @as(usize, @intCast(argc))) : (i += 1) {
        if (sqlite3_value_type(argv[i]) != SQLITE_NULL) {
            const k = sqlite3_value_bytes(argv[i]);
            const v = sqlite3_value_text(argv[i]);
            if (v) |vp| {
                if (bNotNull and nSep > 0) {
                    @memcpy(z[j .. j + @as(usize, @intCast(nSep))], zSep[0..@intCast(nSep)]);
                    j += @intCast(nSep);
                }
                @memcpy(z[j .. j + @as(usize, @intCast(k))], vp[0..@intCast(k)]);
                j += @intCast(k);
                bNotNull = true;
            }
        }
    }
    z[j] = 0;
    sqlite3_result_text64(ctx, z, j, @ptrCast(&sqlite3_free), SQLITE_UTF8_ZT);
}

fn concatFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    concatFuncCore(ctx, argc, @ptrCast(argv.?), 0, "");
}

fn concatwsFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const nSep = sqlite3_value_bytes(a[0]);
    const zSep = sqlite3_value_text(a[0]);
    if (zSep == null) return;
    concatFuncCore(ctx, argc - 1, a + 1, nSep, zSep.?);
}

fn unknownFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = ctx;
    _ = argc;
    _ = argv;
}

fn loadExt(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const zFile = sqlite3_value_text(a[0]);
    const db = sqlite3_context_db_handle(ctx);
    var zErrMsg: ?[*:0]u8 = null;
    if ((dbFlags(db) & SQLITE_LoadExtFunc) == 0) {
        sqlite3_result_error(ctx, "not authorized", -1);
        return;
    }
    const zProc: ?[*:0]const u8 = if (argc == 2) sqlite3_value_text(a[1]) else null;
    if (zFile != null and sqlite3_load_extension(db, zFile, zProc, &zErrMsg) != 0) {
        sqlite3_result_error(ctx, zErrMsg, -1);
        sqlite3_free(zErrMsg);
    }
}

// ─── sum() / avg() / total() aggregates (Kahan-Babushka-Neumaier) ────────────
const SumCtx = extern struct {
    rSum: f64,
    rErr: f64,
    iSum: i64,
    cnt: i64,
    approx: u8,
    ovrfl: u8,
};

fn kbnStep(pSum: *SumCtx, r: f64) void {
    const s = pSum.rSum;
    const t = s + r;
    if (fabs(s) > fabs(r)) {
        pSum.rErr += (s - t) + r;
    } else {
        pSum.rErr += (r - t) + s;
    }
    pSum.rSum = t;
}

fn kbnStepInt64(pSum: *SumCtx, iVal: i64) void {
    if (iVal <= -4503599627370496 or iVal >= 4503599627370496) {
        const iSm = @rem(iVal, 16384);
        const iBig = iVal - iSm;
        kbnStep(pSum, @floatFromInt(iBig));
        kbnStep(pSum, @floatFromInt(iSm));
    } else {
        kbnStep(pSum, @floatFromInt(iVal));
    }
}

fn kbnInit(p: *SumCtx, iVal: i64) void {
    if (iVal <= -4503599627370496 or iVal >= 4503599627370496) {
        const iSm = @rem(iVal, 16384);
        p.rSum = @floatFromInt(iVal - iSm);
        p.rErr = @floatFromInt(iSm);
    } else {
        p.rSum = @floatFromInt(iVal);
        p.rErr = 0.0;
    }
}

fn sumStep(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const pp = sqlite3_aggregate_context(ctx, @sizeOf(SumCtx));
    const ty = sqlite3_value_numeric_type(a[0]);
    if (pp != null and ty != SQLITE_NULL) {
        const p: *SumCtx = @ptrCast(@alignCast(pp.?));
        p.cnt += 1;
        if (p.approx == 0) {
            if (ty != SQLITE_INTEGER) {
                kbnInit(p, p.iSum);
                p.approx = 1;
                kbnStep(p, sqlite3_value_double(a[0]));
            } else {
                var x = p.iSum;
                if (sqlite3AddInt64(&x, sqlite3_value_int64(a[0])) == 0) {
                    p.iSum = x;
                } else {
                    p.ovrfl = 1;
                    kbnInit(p, p.iSum);
                    p.approx = 1;
                    kbnStepInt64(p, sqlite3_value_int64(a[0]));
                }
            }
        } else {
            if (ty == SQLITE_INTEGER) {
                kbnStepInt64(p, sqlite3_value_int64(a[0]));
            } else {
                p.ovrfl = 0;
                kbnStep(p, sqlite3_value_double(a[0]));
            }
        }
    }
}

fn sumInverse(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const pp = sqlite3_aggregate_context(ctx, @sizeOf(SumCtx));
    const ty = sqlite3_value_numeric_type(a[0]);
    if (pp != null and ty != SQLITE_NULL) {
        const p: *SumCtx = @ptrCast(@alignCast(pp.?));
        p.cnt -= 1;
        if (p.approx == 0) {
            var x = p.iSum;
            if (sqlite3SubInt64(&x, sqlite3_value_int64(a[0])) == 0) {
                p.iSum = x;
                return;
            }
            p.ovrfl = 1;
            p.approx = 1;
            kbnInit(p, p.iSum);
        }
        if (ty == SQLITE_INTEGER) {
            const iVal = sqlite3_value_int64(a[0]);
            if (iVal != SMALLEST_INT64) {
                kbnStepInt64(p, -iVal);
            } else {
                kbnStepInt64(p, LARGEST_INT64);
                kbnStepInt64(p, 1);
            }
        } else {
            kbnStep(p, -sqlite3_value_double(a[0]));
        }
    }
}

fn sumFinalize(ctx: ?*Ctx) callconv(.c) void {
    const pp = sqlite3_aggregate_context(ctx, 0);
    if (pp) |raw| {
        const p: *SumCtx = @ptrCast(@alignCast(raw));
        if (p.cnt > 0) {
            if (p.approx != 0) {
                if (p.ovrfl != 0) {
                    sqlite3_result_error(ctx, "integer overflow", -1);
                } else if (sqlite3IsOverflow(p.rErr) == 0) {
                    sqlite3_result_double(ctx, p.rSum + p.rErr);
                } else {
                    sqlite3_result_double(ctx, p.rSum);
                }
            } else {
                sqlite3_result_int64(ctx, p.iSum);
            }
        }
    }
}

fn avgFinalize(ctx: ?*Ctx) callconv(.c) void {
    const pp = sqlite3_aggregate_context(ctx, 0);
    if (pp) |raw| {
        const p: *SumCtx = @ptrCast(@alignCast(raw));
        if (p.cnt > 0) {
            var r: f64 = undefined;
            if (p.approx != 0) {
                r = p.rSum;
                if (sqlite3IsOverflow(p.rErr) == 0) r += p.rErr;
            } else {
                r = @floatFromInt(p.iSum);
            }
            sqlite3_result_double(ctx, r / @as(f64, @floatFromInt(p.cnt)));
        }
    }
}

fn totalFinalize(ctx: ?*Ctx) callconv(.c) void {
    var r: f64 = 0.0;
    const pp = sqlite3_aggregate_context(ctx, 0);
    if (pp) |raw| {
        const p: *SumCtx = @ptrCast(@alignCast(raw));
        if (p.approx != 0) {
            r = p.rSum;
            if (sqlite3IsOverflow(p.rErr) == 0) r += p.rErr;
        } else {
            r = @floatFromInt(p.iSum);
        }
    }
    sqlite3_result_double(ctx, r);
}

// ─── count() aggregate ──────────────────────────────────────────────────────
const CountCtx = extern struct {
    n: i64,
    bInverse: c_int, // only present under SQLITE_DEBUG, but harmless to keep
};

fn countStep(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const pp = sqlite3_aggregate_context(ctx, @sizeOf(CountCtx));
    if (pp) |raw| {
        const p: *CountCtx = @ptrCast(@alignCast(raw));
        if (argc == 0 or SQLITE_NULL != sqlite3_value_type(@as([*]?*Val, @ptrCast(argv.?))[0])) {
            p.n += 1;
        }
    }
}

fn countFinalize(ctx: ?*Ctx) callconv(.c) void {
    const pp = sqlite3_aggregate_context(ctx, 0);
    const n: i64 = if (pp) |raw| @as(*CountCtx, @ptrCast(@alignCast(raw))).n else 0;
    sqlite3_result_int64(ctx, n);
}

fn countInverse(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const pp = sqlite3_aggregate_context(ctx, @sizeOf(CountCtx));
    if (pp) |raw| {
        const p: *CountCtx = @ptrCast(@alignCast(raw));
        if (argc == 0 or SQLITE_NULL != sqlite3_value_type(@as([*]?*Val, @ptrCast(argv.?))[0])) {
            p.n -= 1;
            if (config.sqlite_debug) p.bInverse = 1;
        }
    }
}

// ─── min() / max() aggregates ───────────────────────────────────────────────
fn minmaxStep(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const pArg = a[0];
    const pBest = sqlite3_aggregate_context(ctx, @intCast(off("sizeof_Mem", 56)));
    if (pBest == null) return;

    if (sqlite3_value_type(pArg) == SQLITE_NULL) {
        if (memFlags(pBest) != 0) skipAccumulatorLoad(ctx);
    } else if (memFlags(pBest) != 0) {
        const pColl = getFuncCollSeq(ctx);
        const max = sqlite3_user_data(ctx) != null;
        const cmp = sqlite3MemCompare(pBest, pArg, pColl);
        if ((max and cmp < 0) or (!max and cmp > 0)) {
            _ = sqlite3VdbeMemCopy(pBest.?, pArg.?);
        } else {
            skipAccumulatorLoad(ctx);
        }
    } else {
        memSetDb(pBest, sqlite3_context_db_handle(ctx));
        _ = sqlite3VdbeMemCopy(pBest.?, pArg.?);
    }
}

fn minMaxValueFinalize(ctx: ?*Ctx, bValue: c_int) void {
    const pRes = sqlite3_aggregate_context(ctx, 0);
    if (pRes) |res| {
        if (memFlags(res) != 0) {
            sqlite3_result_value(ctx, res);
        }
        if (bValue == 0) sqlite3VdbeMemRelease(res);
    }
}

fn minMaxValue(ctx: ?*Ctx) callconv(.c) void {
    minMaxValueFinalize(ctx, 1);
}
fn minMaxFinalize(ctx: ?*Ctx) callconv(.c) void {
    minMaxValueFinalize(ctx, 0);
}

// ─── group_concat() / string_agg() ──────────────────────────────────────────
// GroupConcatCtx: leading StrAccum (sizeof 32) then windowfunc bookkeeping.
const GroupConcatCtx = extern struct {
    str: [StrAccumSz]u8 align(8),
    nAccum: c_int,
    nFirstSepLength: c_int,
    pnSepLengths: ?[*]c_int,
};

// StrAccum field offsets within the embedded buffer.
const SA_mxAlloc: usize = 20;
const SA_nChar: usize = 24;
const SA_zText: usize = 8;

inline fn saMxAlloc(gcc: *GroupConcatCtx) *align(1) u32 {
    return @ptrCast(&gcc.str[SA_mxAlloc]);
}
inline fn saNChar(gcc: *GroupConcatCtx) *align(1) u32 {
    return @ptrCast(&gcc.str[SA_nChar]);
}
inline fn saZText(gcc: *GroupConcatCtx) *align(1) ?[*]u8 {
    return @ptrCast(&gcc.str[SA_zText]);
}

fn groupConcatStep(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    if (sqlite3_value_type(a[0]) == SQLITE_NULL) return;
    const pp = sqlite3_aggregate_context(ctx, @sizeOf(GroupConcatCtx));
    if (pp) |raw| {
        const pGCC: *GroupConcatCtx = @ptrCast(@alignCast(raw));
        const db = sqlite3_context_db_handle(ctx);
        const firstTerm = saMxAlloc(pGCC).* == 0;
        saMxAlloc(pGCC).* = @bitCast(dbLimit(db, SQLITE_LIMIT_LENGTH));
        if (argc == 1) {
            if (!firstTerm) {
                sqlite3_str_appendchar(@ptrCast(&pGCC.str), 1, ',');
            } else {
                pGCC.nFirstSepLength = 1;
            }
        } else if (!firstTerm) {
            const zSep = sqlite3_value_text(a[1]);
            var nSep = sqlite3_value_bytes(a[1]);
            if (zSep) |zs| {
                sqlite3_str_append(@ptrCast(&pGCC.str), zs, nSep);
            } else {
                nSep = 0;
            }
            if (nSep != pGCC.nFirstSepLength or pGCC.pnSepLengths != null) {
                var pnsl = pGCC.pnSepLengths;
                if (pnsl == null) {
                    const newp = sqlite3_malloc64(@as(u64, @intCast(pGCC.nAccum + 1)) * @sizeOf(c_int));
                    pnsl = @ptrCast(@alignCast(newp));
                    if (pnsl) |list| {
                        var ii: usize = 0;
                        const nA: usize = @intCast(pGCC.nAccum - 1);
                        while (ii < nA) : (ii += 1) list[ii] = pGCC.nFirstSepLength;
                    }
                } else {
                    const newp = sqlite3_realloc64(pnsl, @as(u64, @intCast(pGCC.nAccum)) * @sizeOf(c_int));
                    pnsl = @ptrCast(@alignCast(newp));
                }
                if (pnsl) |list| {
                    if (pGCC.nAccum > 0) {
                        list[@intCast(pGCC.nAccum - 1)] = nSep;
                    }
                    pGCC.pnSepLengths = list;
                } else {
                    sqlite3StrAccumSetError(@ptrCast(&pGCC.str), @intCast(SQLITE_NOMEM));
                }
            }
        } else {
            pGCC.nFirstSepLength = sqlite3_value_bytes(a[1]);
        }
        pGCC.nAccum += 1;
        const zVal = sqlite3_value_text(a[0]);
        const nVal = sqlite3_value_bytes(a[0]);
        if (zVal) |zv| sqlite3_str_append(@ptrCast(&pGCC.str), zv, nVal);
    }
}

fn groupConcatInverse(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    if (sqlite3_value_type(a[0]) == SQLITE_NULL) return;
    const pp = sqlite3_aggregate_context(ctx, @sizeOf(GroupConcatCtx));
    if (pp) |raw| {
        const pGCC: *GroupConcatCtx = @ptrCast(@alignCast(raw));
        _ = sqlite3_value_text(a[0]);
        var nVS = sqlite3_value_bytes(a[0]);
        pGCC.nAccum -= 1;
        if (pGCC.pnSepLengths) |list| {
            if (pGCC.nAccum > 0) {
                nVS += list[0];
                @memmove(@as([*]u8, @ptrCast(list))[0 .. @as(usize, @intCast(pGCC.nAccum - 1)) * @sizeOf(c_int)], @as([*]u8, @ptrCast(list + 1))[0 .. @as(usize, @intCast(pGCC.nAccum - 1)) * @sizeOf(c_int)]);
            }
        } else {
            nVS += pGCC.nFirstSepLength;
        }
        const nChar = saNChar(pGCC);
        if (nVS >= @as(c_int, @bitCast(nChar.*))) {
            nChar.* = 0;
        } else {
            nChar.* -= @as(u32, @intCast(nVS));
            const zText = saZText(pGCC).*.?;
            @memmove(zText[0..nChar.*], zText[@intCast(nVS) .. @as(usize, @intCast(nVS)) + nChar.*]);
        }
        if (nChar.* == 0) {
            saMxAlloc(pGCC).* = 0;
            sqlite3_free(pGCC.pnSepLengths);
            pGCC.pnSepLengths = null;
        }
    }
}

fn groupConcatFinalize(ctx: ?*Ctx) callconv(.c) void {
    const pp = sqlite3_aggregate_context(ctx, 0);
    if (pp) |raw| {
        const pGCC: *GroupConcatCtx = @ptrCast(@alignCast(raw));
        sqlite3_result_str(ctx, @ptrCast(&pGCC.str), SQLITE_XFER);
        sqlite3_free(pGCC.pnSepLengths);
    }
}

fn groupConcatValue(ctx: ?*Ctx) callconv(.c) void {
    const pp = sqlite3_aggregate_context(ctx, 0);
    if (pp) |raw| {
        const pGCC: *GroupConcatCtx = @ptrCast(@alignCast(raw));
        if (pGCC.nAccum > 0) {
            sqlite3_result_str(ctx, @ptrCast(&pGCC.str), SQLITE_COPY);
        }
    }
}

// ─── math functions ─────────────────────────────────────────────────────────
const M_PI: f64 = 3.141592653589793238462643383279502884;

fn xCeil(x: f64) callconv(.c) f64 {
    return ceil(x);
}
fn xFloor(x: f64) callconv(.c) f64 {
    return floor(x);
}
fn degToRad(x: f64) callconv(.c) f64 {
    return x * (M_PI / 180.0);
}
fn radToDeg(x: f64) callconv(.c) f64 {
    return x * (180.0 / M_PI);
}

fn ceilingFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    switch (sqlite3_value_numeric_type(a[0])) {
        SQLITE_INTEGER => sqlite3_result_int64(ctx, sqlite3_value_int64(a[0])),
        SQLITE_FLOAT => {
            const x: *const fn (f64) callconv(.c) f64 = @ptrCast(sqlite3_user_data(ctx).?);
            sqlite3_result_double(ctx, x(sqlite3_value_double(a[0])));
        },
        else => {},
    }
}

fn logFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var x: f64 = undefined;
    var ans: f64 = undefined;
    switch (sqlite3_value_numeric_type(a[0])) {
        SQLITE_INTEGER, SQLITE_FLOAT => {
            x = sqlite3_value_double(a[0]);
            if (x <= 0.0) return;
        },
        else => return,
    }
    if (argc == 2) {
        switch (sqlite3_value_numeric_type(a[0])) {
            SQLITE_INTEGER, SQLITE_FLOAT => {
                const b = log(x);
                if (b <= 0.0) return;
                x = sqlite3_value_double(a[1]);
                if (x <= 0.0) return;
                ans = log(x) / b;
            },
            else => return,
        }
    } else {
        const sel: c_int = @truncate(@as(isize, @bitCast(@intFromPtr(sqlite3_user_data(ctx)))));
        ans = switch (sel) {
            1 => log10(x),
            2 => log2(x),
            else => log(x),
        };
    }
    sqlite3_result_double(ctx, ans);
}

fn math1Func(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const ty = sqlite3_value_numeric_type(a[0]);
    if (ty != SQLITE_INTEGER and ty != SQLITE_FLOAT) return;
    const v0 = sqlite3_value_double(a[0]);
    const x: *const fn (f64) callconv(.c) f64 = @ptrCast(sqlite3_user_data(ctx).?);
    sqlite3_result_double(ctx, x(v0));
}

fn math2Func(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const ty0 = sqlite3_value_numeric_type(a[0]);
    if (ty0 != SQLITE_INTEGER and ty0 != SQLITE_FLOAT) return;
    const ty1 = sqlite3_value_numeric_type(a[1]);
    if (ty1 != SQLITE_INTEGER and ty1 != SQLITE_FLOAT) return;
    const v0 = sqlite3_value_double(a[0]);
    const v1 = sqlite3_value_double(a[1]);
    const x: *const fn (f64, f64) callconv(.c) f64 = @ptrCast(sqlite3_user_data(ctx).?);
    sqlite3_result_double(ctx, x(v0, v1));
}

fn piFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    _ = argv;
    sqlite3_result_double(ctx, M_PI);
}

fn signFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const ty = sqlite3_value_numeric_type(a[0]);
    if (ty != SQLITE_INTEGER and ty != SQLITE_FLOAT) return;
    const x = sqlite3_value_double(a[0]);
    sqlite3_result_int(ctx, if (x < 0.0) -1 else if (x > 0.0) @as(c_int, 1) else 0);
}

// libm wrappers for direct names with callconv(.c) so their address matches the
// userdata pointer type the math funcs expect.
fn wExp(x: f64) callconv(.c) f64 {
    return exp(x);
}
fn wPow(x: f64, y: f64) callconv(.c) f64 {
    return pow(x, y);
}
fn wFmod(x: f64, y: f64) callconv(.c) f64 {
    return fmod(x, y);
}
fn wAcos(x: f64) callconv(.c) f64 {
    return acos(x);
}
fn wAsin(x: f64) callconv(.c) f64 {
    return asin(x);
}
fn wAtan(x: f64) callconv(.c) f64 {
    return atan(x);
}
fn wAtan2(x: f64, y: f64) callconv(.c) f64 {
    return atan2(x, y);
}
fn wCos(x: f64) callconv(.c) f64 {
    return cos(x);
}
fn wSin(x: f64) callconv(.c) f64 {
    return sin(x);
}
fn wTan(x: f64) callconv(.c) f64 {
    return tan(x);
}
fn wCosh(x: f64) callconv(.c) f64 {
    return cosh(x);
}
fn wSinh(x: f64) callconv(.c) f64 {
    return sinh(x);
}
fn wTanh(x: f64) callconv(.c) f64 {
    return tanh(x);
}
fn wAcosh(x: f64) callconv(.c) f64 {
    return acosh(x);
}
fn wAsinh(x: f64) callconv(.c) f64 {
    return asinh(x);
}
fn wAtanh(x: f64) callconv(.c) f64 {
    return atanh(x);
}
fn wSqrt(x: f64) callconv(.c) f64 {
    return sqrt(x);
}
fn wTrunc(x: f64) callconv(.c) f64 {
    return trunc(x);
}

// ─── percentile family ──────────────────────────────────────────────────────
const Percentile = extern struct {
    nAlloc: u64,
    nUsed: u64,
    bSorted: u8,
    bKeepSorted: u8,
    bPctValid: u8,
    rPct: f64,
    a: ?[*]f64,
};

fn percentIsInfinity(r: f64) bool {
    const u: u64 = @bitCast(r);
    return ((u >> 52) & 0x7ff) == 0x7ff;
}

fn percentSameValue(a: f64, b: f64) bool {
    const d = a - b;
    return d >= -0.001 and d <= 0.001;
}

fn percentBinarySearch(p: *Percentile, y: f64, bExact: bool) i64 {
    var iFirst: i64 = 0;
    var iLast: i64 = @as(i64, @intCast(p.nUsed)) - 1;
    while (iLast >= iFirst) {
        const iMid = @divTrunc(iFirst + iLast, 2);
        const x = p.a.?[@intCast(iMid)];
        if (x < y) {
            iFirst = iMid + 1;
        } else if (x > y) {
            iLast = iMid - 1;
        } else {
            return iMid;
        }
    }
    if (bExact) return -1;
    return iFirst;
}

fn percentError(pCtx: ?*Ctx, comptime zFormat: [*:0]const u8, args: anytype) void {
    var zMsg1: ?[*:0]u8 = null;
    {
        // sqlite3_vmprintf takes a va_list. We instead build via sqlite3_mprintf
        // which accepts variadics directly (the format strings here use only %s,
        // %.1f, %%s — passing through sqlite3_mprintf is exact).
        zMsg1 = @call(.auto, sqlite3_mprintf, .{zFormat} ++ args);
    }
    const zMsg2 = if (zMsg1) |m1| sqlite3_mprintf(m1, sqlite3VdbeFuncName(pCtx)) else null;
    sqlite3_result_error(pCtx, zMsg2, -1);
    sqlite3_free(zMsg1);
    sqlite3_free(zMsg2);
}

fn percentStep(pCtx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var rPct: f64 = undefined;
    var eType: c_int = undefined;

    if (argc == 1) {
        rPct = 0.5;
    } else {
        const ud: c_int = @truncate(@as(isize, @bitCast(@intFromPtr(sqlite3_user_data(pCtx)))));
        const mxFrac: f64 = if ((ud & 2) != 0) 100.0 else 1.0;
        eType = sqlite3_value_numeric_type(a[1]);
        rPct = sqlite3_value_double(a[1]) / mxFrac;
        if ((eType != SQLITE_INTEGER and eType != SQLITE_FLOAT) or rPct < 0.0 or rPct > 1.0) {
            percentError(pCtx, "the fraction argument to %%s() is not between 0.0 and %.1f", .{mxFrac});
            return;
        }
    }

    const pp = sqlite3_aggregate_context(pCtx, @sizeOf(Percentile));
    if (pp == null) return;
    const p: *Percentile = @ptrCast(@alignCast(pp.?));

    if (p.bPctValid == 0) {
        p.rPct = rPct;
        p.bPctValid = 1;
    } else if (!percentSameValue(p.rPct, rPct)) {
        percentError(pCtx, "the fraction argument to %%s() is not the same for all input rows", .{});
        return;
    }

    eType = sqlite3_value_type(a[0]);
    if (eType == SQLITE_NULL) return;
    if (eType != SQLITE_INTEGER and eType != SQLITE_FLOAT) {
        percentError(pCtx, "input to %%s() is not numeric", .{});
        return;
    }
    const y = sqlite3_value_double(a[0]);
    if (percentIsInfinity(y)) {
        percentError(pCtx, "Inf input to %%s()", .{});
        return;
    }

    if (p.nUsed >= p.nAlloc) {
        const n = p.nAlloc * 2 + 250;
        const aNew = sqlite3_realloc64(p.a, @sizeOf(f64) * n);
        if (aNew == null) {
            sqlite3_free(p.a);
            @memset(@as([*]u8, @ptrCast(p))[0..@sizeOf(Percentile)], 0);
            sqlite3_result_error_nomem(pCtx);
            return;
        }
        p.nAlloc = n;
        p.a = @ptrCast(@alignCast(aNew));
    }
    if (p.nUsed == 0) {
        p.a.?[p.nUsed] = y;
        p.nUsed += 1;
        p.bSorted = 1;
    } else if (p.bSorted == 0 or y >= p.a.?[p.nUsed - 1]) {
        p.a.?[p.nUsed] = y;
        p.nUsed += 1;
    } else if (p.bKeepSorted != 0) {
        const i = percentBinarySearch(p, y, false);
        const iu: usize = @intCast(i);
        if (iu < p.nUsed) {
            @memmove(@as([*]u8, @ptrCast(p.a.? + iu + 1))[0 .. (p.nUsed - iu) * @sizeOf(f64)], @as([*]u8, @ptrCast(p.a.? + iu))[0 .. (p.nUsed - iu) * @sizeOf(f64)]);
        }
        p.a.?[iu] = y;
        p.nUsed += 1;
    } else {
        p.a.?[p.nUsed] = y;
        p.nUsed += 1;
        p.bSorted = 0;
    }
}

fn swapD(a: *f64, b: *f64) void {
    const t = a.*;
    a.* = b.*;
    b.* = t;
}

fn percentSort(a0: [*]f64, n0: c_uint, iReq0: c_int) void {
    var a = a0;
    var n = n0;
    var iReq = iReq0;
    while (true) {
        if (a[0] > a[n - 1]) swapD(&a[0], &a[n - 1]);
        if (n == 2) return;
        var iGt: c_int = @intCast(n - 1);
        var i: c_int = @intCast(n / 2);
        if (a[0] > a[@intCast(i)]) {
            swapD(&a[0], &a[@intCast(i)]);
        } else if (a[@intCast(i)] > a[@intCast(iGt)]) {
            swapD(&a[@intCast(i)], &a[@intCast(iGt)]);
        }
        if (n == 3) return;
        const rPivot = a[@intCast(i)];
        var iLt: c_int = 1;
        i = 1;
        while (true) {
            if (a[@intCast(i)] < rPivot) {
                if (i > iLt) swapD(&a[@intCast(i)], &a[@intCast(iLt)]);
                iLt += 1;
                i += 1;
            } else if (a[@intCast(i)] > rPivot) {
                while (true) {
                    iGt -= 1;
                    if (!(iGt > i and a[@intCast(iGt)] > rPivot)) break;
                }
                swapD(&a[@intCast(i)], &a[@intCast(iGt)]);
            } else {
                i += 1;
            }
            if (!(i < iGt)) break;
        }

        if (iReq >= 0) {
            if (iReq < iLt) {
                n = @intCast(iLt);
            } else {
                a += @intCast(iGt);
                n -= @intCast(iGt);
                iReq = @max(0, iReq - iGt);
            }
        } else {
            if (iLt > @as(c_int, @intCast(n / 2))) {
                if (@as(c_int, @intCast(n)) - iGt >= 2) percentSort(a + @as(usize, @intCast(iGt)), n - @as(c_uint, @intCast(iGt)), -1);
                n = @intCast(iLt);
            } else {
                if (iLt >= 2) percentSort(a, @intCast(iLt), -1);
                a += @intCast(iGt);
                n -= @intCast(iGt);
            }
        }
        if (!(n >= 2)) break;
    }
}

fn percentInverse(pCtx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const pp = sqlite3_aggregate_context(pCtx, @sizeOf(Percentile));
    const p: *Percentile = @ptrCast(@alignCast(pp.?));
    const eType = sqlite3_value_type(a[0]);
    if (eType == SQLITE_NULL) return;
    if (eType != SQLITE_INTEGER and eType != SQLITE_FLOAT) return;
    const y = sqlite3_value_double(a[0]);
    if (percentIsInfinity(y)) return;
    if (p.bSorted == 0) {
        percentSort(p.a.?, @intCast(p.nUsed), -1);
        p.bSorted = 1;
    }
    p.bKeepSorted = 1;
    const i = percentBinarySearch(p, y, true);
    if (i >= 0) {
        p.nUsed -= 1;
        const iu: usize = @intCast(i);
        if (iu < p.nUsed) {
            @memmove(@as([*]u8, @ptrCast(p.a.? + iu))[0 .. (p.nUsed - iu) * @sizeOf(f64)], @as([*]u8, @ptrCast(p.a.? + iu + 1))[0 .. (p.nUsed - iu) * @sizeOf(f64)]);
        }
    }
}

fn percentCompute(pCtx: ?*Ctx, bIsFinal: bool) void {
    const settings: c_int = @as(c_int, @truncate(@as(isize, @bitCast(@intFromPtr(sqlite3_user_data(pCtx)))))) & 1;
    const pp = sqlite3_aggregate_context(pCtx, 0);
    if (pp == null) return;
    const p: *Percentile = @ptrCast(@alignCast(pp.?));
    if (p.a == null) return;
    if (p.nUsed != 0) {
        const ix = p.rPct * @as(f64, @floatFromInt(p.nUsed - 1));
        const idx1: u32 = @intFromFloat(ix);
        if (p.bSorted == 0) {
            percentSort(p.a.?, @intCast(p.nUsed), if (bIsFinal) @as(c_int, @intCast(idx1)) else -1);
            p.bSorted = 1;
        }
        var vx: f64 = undefined;
        if (settings & 1 != 0) {
            vx = p.a.?[idx1];
        } else {
            const idx2: u32 = if (ix == @as(f64, @floatFromInt(idx1)) or idx1 == p.nUsed - 1) idx1 else idx1 + 1;
            const v1 = p.a.?[idx1];
            const v2 = p.a.?[idx2];
            vx = v1 + (v2 - v1) * (ix - @as(f64, @floatFromInt(idx1)));
        }
        sqlite3_result_double(pCtx, vx);
    }
    if (bIsFinal) {
        sqlite3_free(p.a);
        @memset(@as([*]u8, @ptrCast(p))[0..@sizeOf(Percentile)], 0);
    } else {
        p.bKeepSorted = 1;
    }
}

fn percentFinal(pCtx: ?*Ctx) callconv(.c) void {
    percentCompute(pCtx, true);
}
fn percentValue(pCtx: ?*Ctx) callconv(.c) void {
    percentCompute(pCtx, false);
}

// ─── SQLITE_TEST: sqlite3_like_count ────────────────────────────────────────
var sqlite3_like_count: c_int = 0;
comptime {
    if (config.sqlite_test) {
        @export(&sqlite3_like_count, .{ .name = "sqlite3_like_count", .linkage = .strong });
    }
}

// ─── public strglob / strlike ───────────────────────────────────────────────
pub export fn sqlite3_strglob(zGlobPattern: ?[*:0]const u8, zString: ?[*:0]const u8) callconv(.c) c_int {
    if (zString == null) {
        return @intFromBool(zGlobPattern != null);
    } else if (zGlobPattern == null) {
        return 1;
    } else {
        return patternCompare(zGlobPattern.?, zString.?, &globInfo, '[');
    }
}

pub export fn sqlite3_strlike(zPattern: ?[*:0]const u8, zStr: ?[*:0]const u8, esc: c_uint) callconv(.c) c_int {
    if (zStr == null) {
        return @intFromBool(zPattern != null);
    } else if (zPattern == null) {
        return 1;
    } else {
        return patternCompare(zPattern.?, zStr.?, &likeInfoNorm, esc);
    }
}

// ─── per-connection / LIKE registration ─────────────────────────────────────
pub export fn sqlite3RegisterPerConnectionBuiltinFunctions(db: ?*anyopaque) callconv(.c) void {
    const rc = sqlite3_overload_function(db, "MATCH", 2);
    if (rc == SQLITE_NOMEM) {
        _ = sqlite3OomFault(db);
    }
}

inline fn funcFlagsPtr(pDef: *FuncDef) *align(1) u32 {
    return @ptrCast(@as([*]u8, @ptrCast(pDef)) + FuncDef_funcFlags);
}

pub export fn sqlite3RegisterLikeFunctions(db: ?*anyopaque, caseSensitive: c_int) callconv(.c) void {
    var pInfo: *CompareInfo = undefined;
    var flags: u32 = undefined;
    if (caseSensitive != 0) {
        pInfo = &likeInfoAlt;
        flags = SQLITE_FUNC_LIKE | SQLITE_FUNC_CASE;
    } else {
        pInfo = &likeInfoNorm;
        flags = SQLITE_FUNC_LIKE;
    }
    var nArg: c_int = 2;
    while (nArg <= 3) : (nArg += 1) {
        _ = sqlite3CreateFunc(db, "like", nArg, SQLITE_UTF8, @ptrCast(pInfo), likeFunc, null, null, null, null, null);
        const pDef = sqlite3FindFunction(db, "like", nArg, SQLITE_UTF8, 0);
        const ff = funcFlagsPtr(pDef.?);
        ff.* |= flags;
        ff.* &= ~SQLITE_FUNC_UNSAFE;
    }
}

// ─── sqlite3IsLikeFunction (reads Expr; mostly via offsets) ──────────────────
// Expr/ExprList offsets needed: op (u8 at 0), x.pList, u.zToken, EP_IntValue.
const Expr_op: usize = off("Expr_op", 0);
const Expr_x_pList: usize = off("Expr_x", 32);
const Expr_u_zToken: usize = off("Expr_u", 8);
const ExprList_nExpr: usize = off("ExprList_nExpr", 0);
const ExprList_a: usize = off("ExprList_a", 8);
const ExprListItem_sz: usize = off("sizeof_ExprList_item", 24);
const ExprListItem_pExpr: usize = off("ExprList_item_pExpr", 0);
// TK_STRING is a tokenizer constant (Lemon-generated parse.h); 118 in this build.
const TK_STRING: u8 = 118;

pub export fn sqlite3IsLikeFunction(db: ?*anyopaque, pExpr: ?*anyopaque, pIsNocase: *c_int, aWc: [*]u8) callconv(.c) c_int {
    const eBase: [*]u8 = @ptrCast(pExpr.?);
    // pExpr->x.pList
    const pListPtr: *align(1) ?*anyopaque = @ptrCast(eBase + Expr_x_pList);
    const pList = pListPtr.*;
    if (pList == null) return 0;
    const lBase: [*]u8 = @ptrCast(pList.?);
    const nExpr = @as(*align(1) const c_int, @ptrCast(lBase + ExprList_nExpr)).*;
    // pExpr->u.zToken
    const zTokenPtr: *align(1) ?[*:0]const u8 = @ptrCast(eBase + Expr_u_zToken);
    const zToken = zTokenPtr.*;
    const pDef = sqlite3FindFunction(db, zToken.?, nExpr, SQLITE_UTF8, 0);
    if (pDef == null) return 0;
    if ((funcFlagsPtr(pDef.?).* & SQLITE_FUNC_LIKE) == 0) return 0;

    // memcpy(aWc, pDef->pUserData, 3)
    const udPtr: *align(1) const ?*anyopaque = @ptrCast(@as([*]u8, @ptrCast(pDef.?)) + FuncDef_pUserData);
    const ud: [*]const u8 = @ptrCast(udPtr.*.?);
    aWc[0] = ud[0];
    aWc[1] = ud[1];
    aWc[2] = ud[2];

    if (nExpr < 3) {
        aWc[3] = 0;
    } else {
        // pEscape = pExpr->x.pList->a[2].pExpr.  a[] is an inline array at
        // ExprList.a (offset ExprList_a); each item is ExprListItem_sz; pExpr is
        // at ExprListItem_pExpr within the item.
        const itemsBase = lBase + ExprList_a;
        const item2 = itemsBase + 2 * ExprListItem_sz;
        const pEscapePtr: *align(1) ?*anyopaque = @ptrCast(item2 + ExprListItem_pExpr);
        const pEscape = pEscapePtr.*;
        const escBase: [*]u8 = @ptrCast(pEscape.?);
        const escOp = escBase[Expr_op];
        if (escOp != TK_STRING) return 0;
        const escTokPtr: *align(1) ?[*:0]const u8 = @ptrCast(escBase + Expr_u_zToken);
        const zEscape = escTokPtr.*.?;
        if (zEscape[0] == 0 or zEscape[1] != 0) return 0;
        if (zEscape[0] == aWc[0]) return 0;
        if (zEscape[0] == aWc[1]) return 0;
        aWc[3] = zEscape[0];
    }
    pIsNocase.* = @intFromBool((funcFlagsPtr(pDef.?).* & SQLITE_FUNC_CASE) == 0);
    return 1;
}

// ─── FuncDef table construction ─────────────────────────────────────────────
fn fd(
    nArg: i16,
    funcFlags: u32,
    pUserData: ?*anyopaque,
    xSFunc: ?*anyopaque,
    xFinalize: ?*anyopaque,
    xValue: ?*anyopaque,
    xInverse: ?*anyopaque,
    zName: [*:0]const u8,
) FuncDef {
    return .{
        .nArg = nArg,
        .funcFlags = funcFlags,
        .pUserData = pUserData,
        .pNext = null,
        .xSFunc = xSFunc,
        .xFinalize = xFinalize,
        .xValue = xValue,
        .xInverse = xInverse,
        .zName = zName,
        .u = .{ .pHash = null },
    };
}

inline fn intToPtr(i: c_int) ?*anyopaque {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, i))));
}

// Macro analogues producing FuncDef entries.
fn FUNCTION(comptime name: [*:0]const u8, nArg: i16, iArg: c_int, bNC: u32, x: XFunc) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_FUNC_CONSTANT | SQLITE_UTF8_FLAG | (bNC * SQLITE_FUNC_NEEDCOLL), intToPtr(iArg), @constCast(@ptrCast(x)), null, null, null, name);
}
fn FUNCTION2(comptime name: [*:0]const u8, nArg: i16, iArg: c_int, bNC: u32, x: XFunc, extra: u32) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_FUNC_CONSTANT | SQLITE_UTF8_FLAG | (bNC * SQLITE_FUNC_NEEDCOLL) | extra, intToPtr(iArg), @constCast(@ptrCast(x)), null, null, null, name);
}
fn VFUNCTION(comptime name: [*:0]const u8, nArg: i16, iArg: c_int, bNC: u32, x: XFunc) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_UTF8_FLAG | (bNC * SQLITE_FUNC_NEEDCOLL), intToPtr(iArg), @constCast(@ptrCast(x)), null, null, null, name);
}
fn SFUNCTION(comptime name: [*:0]const u8, nArg: i16, iArg: c_int, x: XFunc) FuncDef {
    _ = iArg;
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_UTF8_FLAG | SQLITE_FUNC_DIRECTONLY | SQLITE_FUNC_UNSAFE, intToPtr(0), @constCast(@ptrCast(x)), null, null, null, name);
}
fn DFUNCTION(comptime name: [*:0]const u8, nArg: i16, x: XFunc) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_FUNC_SLOCHNG | SQLITE_UTF8_FLAG, null, @constCast(@ptrCast(x)), null, null, null, name);
}
fn MFUNCTION(comptime name: [*:0]const u8, nArg: i16, xPtr: ?*const anyopaque, x: XFunc) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_FUNC_CONSTANT | SQLITE_UTF8_FLAG, @constCast(xPtr), @constCast(@ptrCast(x)), null, null, null, name);
}
fn INLINE_FUNC(comptime name: [*:0]const u8, nArg: i16, iArg: c_int, mFlags: u32) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_UTF8_FLAG | SQLITE_FUNC_INLINE | SQLITE_FUNC_CONSTANT | mFlags, intToPtr(iArg), @constCast(@ptrCast(@as(XFunc, versionFunc))), null, null, null, name);
}
fn TEST_FUNC(comptime name: [*:0]const u8, nArg: i16, iArg: c_int, mFlags: u32) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_UTF8_FLAG | SQLITE_FUNC_INTERNAL | SQLITE_FUNC_TEST | SQLITE_FUNC_INLINE | SQLITE_FUNC_CONSTANT | mFlags, intToPtr(iArg), @constCast(@ptrCast(@as(XFunc, versionFunc))), null, null, null, name);
}
fn LIKEFUNC(comptime name: [*:0]const u8, nArg: i16, arg: ?*anyopaque, flags: u32) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_FUNC_CONSTANT | SQLITE_UTF8_FLAG | flags, arg, @constCast(@ptrCast(@as(XFunc, likeFunc))), null, null, null, name);
}
fn WAGGREGATE(comptime name: [*:0]const u8, nArg: i16, arg: c_int, nc: u32, xStep: XFunc, xFinal: XFinal, xValue: XFinal, xInverse: XFunc, f: u32) FuncDef {
    return fd(nArg, SQLITE_FUNC_BUILTIN | SQLITE_UTF8_FLAG | (nc * SQLITE_FUNC_NEEDCOLL) | f, intToPtr(arg), @constCast(@ptrCast(xStep)), @constCast(@ptrCast(xFinal)), @constCast(@ptrCast(xValue)), @constCast(@ptrCast(xInverse)), name);
}

pub export fn sqlite3RegisterBuiltinFunctions() callconv(.c) void {
    sqlite3AlterFunctions();
    sqlite3WindowFunctions();
    sqlite3RegisterDateTimeFunctions();
    sqlite3RegisterJsonFunctions();
    sqlite3InsertBuiltinFuncs(&aBuiltinFunc, @intCast(aBuiltinFunc.len));
}

// The static builtin-function table. Built once at comptime into a mutable
// global (start-time writes to pHash require it be non-const), mirroring the C
// `static FuncDef aBuiltinFunc[]`.
var aBuiltinFunc: [tableLen]FuncDef = buildTable();

const TABLE_CAP = 160; // oversized scratch cap; tableLen is the real count

// tableLen is computed automatically at comptime by running buildTableInto with
// a counting-only writer, so it cannot drift from the actual entries below.
const tableLen = blk: {
    var scratch: [TABLE_CAP]FuncDef = undefined;
    var n: usize = 0;
    buildTableInto(&scratch, &n);
    break :blk n;
};

fn buildTable() [tableLen]FuncDef {
    var scratch: [TABLE_CAP]FuncDef = undefined;
    var k: usize = 0;
    buildTableInto(&scratch, &k);
    std.debug.assert(k == tableLen);
    var t: [tableLen]FuncDef = undefined;
    @memcpy(t[0..], scratch[0..tableLen]);
    return t;
}

fn buildTableInto(scratch: *[TABLE_CAP]FuncDef, idxOut: *usize) void {
    var k: usize = 0;
    const add = struct {
        fn f(arr: *[TABLE_CAP]FuncDef, i: *usize, e: FuncDef) void {
            arr[i.*] = e;
            i.* += 1;
        }
    }.f;

    // TEST_FUNCs (UNTESTABLE off in both configs)
    add(scratch, &k, TEST_FUNC("implies_nonnull_row", 2, INLINEFUNC_implies_nonnull_row, 0));
    add(scratch, &k, TEST_FUNC("expr_compare", 2, INLINEFUNC_expr_compare, 0));
    add(scratch, &k, TEST_FUNC("expr_implies_expr", 2, INLINEFUNC_expr_implies_expr, 0));
    add(scratch, &k, TEST_FUNC("affinity", 1, INLINEFUNC_affinity, 0));
    // load_extension
    add(scratch, &k, SFUNCTION("load_extension", 1, 0, loadExt));
    add(scratch, &k, SFUNCTION("load_extension", 2, 0, loadExt));
    // compileoption diags
    add(scratch, &k, DFUNCTION("sqlite_compileoption_used", 1, compileoptionusedFunc));
    add(scratch, &k, DFUNCTION("sqlite_compileoption_get", 1, compileoptiongetFunc));
    // inline funcs
    add(scratch, &k, INLINE_FUNC("unlikely", 1, INLINEFUNC_unlikely, SQLITE_FUNC_UNLIKELY));
    add(scratch, &k, INLINE_FUNC("likelihood", 2, INLINEFUNC_unlikely, SQLITE_FUNC_UNLIKELY));
    add(scratch, &k, INLINE_FUNC("likely", 1, INLINEFUNC_unlikely, SQLITE_FUNC_UNLIKELY));
    add(scratch, &k, INLINE_FUNC("sqlite_offset", 1, INLINEFUNC_sqlite_offset, 0));
    if (config.sqlite_debug) {
        add(scratch, &k, FUNCTION("sqlite_filestat", 1, 0, 0, filestatFunc));
    }
    add(scratch, &k, FUNCTION("ltrim", 1, 1, 0, trimFunc));
    add(scratch, &k, FUNCTION("ltrim", 2, 1, 0, trimFunc));
    add(scratch, &k, FUNCTION("rtrim", 1, 2, 0, trimFunc));
    add(scratch, &k, FUNCTION("rtrim", 2, 2, 0, trimFunc));
    add(scratch, &k, FUNCTION("trim", 1, 3, 0, trimFunc));
    add(scratch, &k, FUNCTION("trim", 2, 3, 0, trimFunc));
    add(scratch, &k, FUNCTION("min", -3, 0, 1, minmaxFunc));
    add(scratch, &k, WAGGREGATE("min", 1, 0, 1, minmaxStep, minMaxFinalize, minMaxValue, null, SQLITE_FUNC_MINMAX | SQLITE_FUNC_ANYORDER));
    add(scratch, &k, FUNCTION("max", -3, 1, 1, minmaxFunc));
    add(scratch, &k, WAGGREGATE("max", 1, 1, 1, minmaxStep, minMaxFinalize, minMaxValue, null, SQLITE_FUNC_MINMAX | SQLITE_FUNC_ANYORDER));
    add(scratch, &k, FUNCTION2("typeof", 1, 0, 0, typeofFunc, SQLITE_FUNC_TYPEOF));
    add(scratch, &k, FUNCTION2("subtype", 1, 0, 0, subtypeFunc, SQLITE_FUNC_TYPEOF | SQLITE_SUBTYPE));
    add(scratch, &k, FUNCTION2("length", 1, 0, 0, lengthFunc, SQLITE_FUNC_LENGTH));
    add(scratch, &k, FUNCTION2("octet_length", 1, 0, 0, bytelengthFunc, SQLITE_FUNC_BYTELEN));
    add(scratch, &k, FUNCTION("instr", 2, 0, 0, instrFunc));
    add(scratch, &k, FUNCTION("printf", -1, 0, 0, printfFunc));
    add(scratch, &k, FUNCTION("format", -1, 0, 0, printfFunc));
    add(scratch, &k, FUNCTION("unicode", 1, 0, 0, unicodeFunc));
    add(scratch, &k, FUNCTION("char", -1, 0, 0, charFunc));
    add(scratch, &k, FUNCTION("abs", 1, 0, 0, absFunc));
    if (config.sqlite_debug) {
        add(scratch, &k, FUNCTION("fpdecode", 3, 0, 0, fpdecodeFunc));
        add(scratch, &k, FUNCTION("parseuri", -1, 0, 0, parseuriFunc));
    }
    add(scratch, &k, FUNCTION("round", 1, 0, 0, roundFunc));
    add(scratch, &k, FUNCTION("round", 2, 0, 0, roundFunc));
    add(scratch, &k, FUNCTION("upper", 1, 0, 0, upperFunc));
    add(scratch, &k, FUNCTION("lower", 1, 0, 0, lowerFunc));
    add(scratch, &k, FUNCTION("hex", 1, 0, 0, hexFunc));
    add(scratch, &k, FUNCTION("unhex", 1, 0, 0, unhexFunc));
    add(scratch, &k, FUNCTION("unhex", 2, 0, 0, unhexFunc));
    add(scratch, &k, FUNCTION("concat", -3, 0, 0, concatFunc));
    add(scratch, &k, FUNCTION("concat_ws", -4, 0, 0, concatwsFunc));
    add(scratch, &k, INLINE_FUNC("ifnull", 2, INLINEFUNC_coalesce, 0));
    add(scratch, &k, VFUNCTION("random", 0, 0, 0, randomFunc));
    add(scratch, &k, VFUNCTION("randomblob", 1, 0, 0, randomBlob));
    add(scratch, &k, FUNCTION("nullif", 2, 0, 1, nullifFunc));
    add(scratch, &k, DFUNCTION("sqlite_version", 0, versionFunc));
    add(scratch, &k, DFUNCTION("sqlite_source_id", 0, sourceidFunc));
    add(scratch, &k, FUNCTION("sqlite_log", 2, 0, 0, errlogFunc));
    add(scratch, &k, FUNCTION("unistr", 1, 0, 0, unistrFunc));
    add(scratch, &k, FUNCTION("quote", 1, 0, 0, quoteFunc));
    add(scratch, &k, FUNCTION("unistr_quote", 1, 1, 0, quoteFunc));
    add(scratch, &k, VFUNCTION("last_insert_rowid", 0, 0, 0, lastInsertRowid));
    add(scratch, &k, VFUNCTION("changes", 0, 0, 0, changesFunc));
    add(scratch, &k, VFUNCTION("total_changes", 0, 0, 0, totalChangesFunc));
    add(scratch, &k, FUNCTION("replace", 3, 0, 0, replaceFunc));
    add(scratch, &k, FUNCTION("zeroblob", 1, 0, 0, zeroblobFunc));
    add(scratch, &k, FUNCTION("substr", 2, 0, 0, substrFunc));
    add(scratch, &k, FUNCTION("substr", 3, 0, 0, substrFunc));
    add(scratch, &k, FUNCTION("substring", 2, 0, 0, substrFunc));
    add(scratch, &k, FUNCTION("substring", 3, 0, 0, substrFunc));
    add(scratch, &k, WAGGREGATE("sum", 1, 0, 0, sumStep, sumFinalize, sumFinalize, sumInverse, 0));
    add(scratch, &k, WAGGREGATE("total", 1, 0, 0, sumStep, totalFinalize, totalFinalize, sumInverse, 0));
    add(scratch, &k, WAGGREGATE("avg", 1, 0, 0, sumStep, avgFinalize, avgFinalize, sumInverse, 0));
    add(scratch, &k, WAGGREGATE("count", 0, 0, 0, countStep, countFinalize, countFinalize, countInverse, SQLITE_FUNC_COUNT | SQLITE_FUNC_ANYORDER));
    add(scratch, &k, WAGGREGATE("count", 1, 0, 0, countStep, countFinalize, countFinalize, countInverse, SQLITE_FUNC_ANYORDER));
    add(scratch, &k, WAGGREGATE("group_concat", 1, 0, 0, groupConcatStep, groupConcatFinalize, groupConcatValue, groupConcatInverse, 0));
    add(scratch, &k, WAGGREGATE("group_concat", 2, 0, 0, groupConcatStep, groupConcatFinalize, groupConcatValue, groupConcatInverse, 0));
    add(scratch, &k, WAGGREGATE("string_agg", 2, 0, 0, groupConcatStep, groupConcatFinalize, groupConcatValue, groupConcatInverse, 0));
    add(scratch, &k, WAGGREGATE("median", 1, 0, 0, percentStep, percentFinal, percentValue, percentInverse, SQLITE_INNOCUOUS | SQLITE_SELFORDER1));
    add(scratch, &k, WAGGREGATE("percentile", 2, 0x2, 0, percentStep, percentFinal, percentValue, percentInverse, SQLITE_INNOCUOUS | SQLITE_SELFORDER1));
    add(scratch, &k, WAGGREGATE("percentile_cont", 2, 0, 0, percentStep, percentFinal, percentValue, percentInverse, SQLITE_INNOCUOUS | SQLITE_SELFORDER1));
    add(scratch, &k, WAGGREGATE("percentile_disc", 2, 0x1, 0, percentStep, percentFinal, percentValue, percentInverse, SQLITE_INNOCUOUS | SQLITE_SELFORDER1));
    add(scratch, &k, LIKEFUNC("glob", 2, @ptrCast(&globInfoMut), SQLITE_FUNC_LIKE | SQLITE_FUNC_CASE));
    add(scratch, &k, LIKEFUNC("like", 2, @ptrCast(&likeInfoNorm), SQLITE_FUNC_LIKE));
    add(scratch, &k, LIKEFUNC("like", 3, @ptrCast(&likeInfoNorm), SQLITE_FUNC_LIKE));
    add(scratch, &k, FUNCTION("unknown", -1, 0, 0, unknownFunc));
    // math
    add(scratch, &k, MFUNCTION("ceil", 1, @ptrCast(&xCeil), ceilingFunc));
    add(scratch, &k, MFUNCTION("ceiling", 1, @ptrCast(&xCeil), ceilingFunc));
    add(scratch, &k, MFUNCTION("floor", 1, @ptrCast(&xFloor), ceilingFunc));
    add(scratch, &k, MFUNCTION("trunc", 1, @ptrCast(&wTrunc), ceilingFunc));
    add(scratch, &k, FUNCTION("ln", 1, 0, 0, logFunc));
    add(scratch, &k, FUNCTION("log", 1, 1, 0, logFunc));
    add(scratch, &k, FUNCTION("log10", 1, 1, 0, logFunc));
    add(scratch, &k, FUNCTION("log2", 1, 2, 0, logFunc));
    add(scratch, &k, FUNCTION("log", 2, 0, 0, logFunc));
    add(scratch, &k, MFUNCTION("exp", 1, @ptrCast(&wExp), math1Func));
    add(scratch, &k, MFUNCTION("pow", 2, @ptrCast(&wPow), math2Func));
    add(scratch, &k, MFUNCTION("power", 2, @ptrCast(&wPow), math2Func));
    add(scratch, &k, MFUNCTION("mod", 2, @ptrCast(&wFmod), math2Func));
    add(scratch, &k, MFUNCTION("acos", 1, @ptrCast(&wAcos), math1Func));
    add(scratch, &k, MFUNCTION("asin", 1, @ptrCast(&wAsin), math1Func));
    add(scratch, &k, MFUNCTION("atan", 1, @ptrCast(&wAtan), math1Func));
    add(scratch, &k, MFUNCTION("atan2", 2, @ptrCast(&wAtan2), math2Func));
    add(scratch, &k, MFUNCTION("cos", 1, @ptrCast(&wCos), math1Func));
    add(scratch, &k, MFUNCTION("sin", 1, @ptrCast(&wSin), math1Func));
    add(scratch, &k, MFUNCTION("tan", 1, @ptrCast(&wTan), math1Func));
    add(scratch, &k, MFUNCTION("cosh", 1, @ptrCast(&wCosh), math1Func));
    add(scratch, &k, MFUNCTION("sinh", 1, @ptrCast(&wSinh), math1Func));
    add(scratch, &k, MFUNCTION("tanh", 1, @ptrCast(&wTanh), math1Func));
    add(scratch, &k, MFUNCTION("acosh", 1, @ptrCast(&wAcosh), math1Func));
    add(scratch, &k, MFUNCTION("asinh", 1, @ptrCast(&wAsinh), math1Func));
    add(scratch, &k, MFUNCTION("atanh", 1, @ptrCast(&wAtanh), math1Func));
    add(scratch, &k, MFUNCTION("sqrt", 1, @ptrCast(&wSqrt), math1Func));
    add(scratch, &k, MFUNCTION("radians", 1, @ptrCast(&degToRad), math1Func));
    add(scratch, &k, MFUNCTION("degrees", 1, @ptrCast(&radToDeg), math1Func));
    add(scratch, &k, MFUNCTION("pi", 0, null, piFunc));
    add(scratch, &k, FUNCTION("sign", 1, 0, 0, signFunc));
    add(scratch, &k, INLINE_FUNC("coalesce", -4, INLINEFUNC_coalesce, 0));
    add(scratch, &k, INLINE_FUNC("iif", -4, INLINEFUNC_iif, 0));
    add(scratch, &k, INLINE_FUNC("if", -4, INLINEFUNC_iif, 0));

    idxOut.* = k;
}

// ─── SQLITE_DEBUG-only functions (fpdecode/parseuri/filestat) ───────────────
// These are only registered in the testfixture (sqlite_debug) build, so they
// are only referenced under `if (config.sqlite_debug)`. They call C helpers
// (sqlite3FpDecode, sqlite3ParseUri, sqlite3DbNameToBtree, …). To keep the
// production build from pulling in those externs, gate the whole bodies on
// config and forward to C wrappers via extern when in the debug config.
const FpDecode = extern struct {
    sign: u8,
    isSpecial: u8,
    n: c_int,
    iDP: c_int,
    z: ?[*:0]u8,
    zBuf: [24]u8,
};
extern fn sqlite3FpDecode(p: *FpDecode, r: f64, iRound: c_int, mxRound: c_int) void;
extern fn sqlite3_snprintf(n: c_int, z: [*]u8, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_value_text_dbg(v: ?*Val) ?[*:0]const u8; // unused placeholder
extern fn sqlite3DbNameToBtree(db: ?*anyopaque, zName: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3BtreeEnter(p: ?*anyopaque) void;
extern fn sqlite3BtreeLeave(p: ?*anyopaque) void;
extern fn sqlite3BtreePager(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3PagerFile(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3PagerJrnlFile(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3OsFileControl(fd: ?*anyopaque, op: c_int, arg: ?*anyopaque) c_int;
extern fn sqlite3_str_errcode(p: ?*anyopaque) c_int;
extern fn sqlite3_str_appendall(p: ?*anyopaque, z: [*:0]const u8) void;
extern fn sqlite3_vfs_find(zName: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3ParseUri(zVfs: ?[*:0]const u8, zUri: ?[*:0]const u8, pFlags: *c_uint, ppVfs: *?*anyopaque, pzFile: *?[*:0]u8, pzErr: *?[*:0]u8) c_int;
extern fn sqlite3_uri_key(zFile: ?[*:0]const u8, n: c_int) ?[*:0]const u8;
extern fn sqlite3_uri_parameter(zFile: ?[*:0]const u8, zParam: [*:0]const u8) ?[*:0]const u8;
extern fn sqlite3_free_filename(z: ?[*:0]u8) void;

const SQLITE_FCNTL_FILESTAT: c_int = 51; // value of SQLITE_FCNTL_FILESTAT

fn fpdecodeFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    var s: FpDecode = undefined;
    var zBuf: [100]u8 = undefined;
    const x = sqlite3_value_double(a[0]);
    const y = sqlite3_value_int(a[1]);
    var z = sqlite3_value_int(a[2]);
    if (z <= 0) z = 1;
    sqlite3FpDecode(&s, x, y, z);
    if (s.isSpecial == 2) {
        _ = sqlite3_snprintf(zBuf.len, &zBuf, "NaN");
    } else {
        _ = sqlite3_snprintf(zBuf.len, &zBuf, "%c%.*s/%d", @as(c_int, s.sign), s.n, s.z, s.iDP);
    }
    sqlite3_result_text(ctx, &zBuf, -1, SQLITE_TRANSIENT);
}

fn filestatFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    _ = argc;
    const a = @as([*]?*Val, @ptrCast(argv.?));
    const db = sqlite3_context_db_handle(ctx);
    const zDbName = sqlite3_value_text(a[0]);
    const pBtree = sqlite3DbNameToBtree(db, zDbName);
    if (pBtree) |bt| {
        sqlite3BtreeEnter(bt);
        const pPager = sqlite3BtreePager(bt);
        var fd2 = sqlite3PagerFile(pPager);
        const pStr = sqlite3_str_new(db);
        if (sqlite3_str_errcode(pStr) != 0) {
            sqlite3_result_error_nomem(ctx);
        } else {
            sqlite3_str_append(pStr, "{\"db\":", 6);
            var rc = sqlite3OsFileControl(fd2, SQLITE_FCNTL_FILESTAT, pStr);
            if (rc != 0) sqlite3_str_append(pStr, "null", 4);
            fd2 = sqlite3PagerJrnlFile(pPager);
            if (fd2 != null and @as(*align(1) const ?*anyopaque, @ptrCast(@as([*]u8, @ptrCast(fd2.?)) + 0)).* != null) {
                sqlite3_str_appendall(pStr, ",\"journal\":");
                rc = sqlite3OsFileControl(fd2, SQLITE_FCNTL_FILESTAT, pStr);
                if (rc != 0) sqlite3_str_append(pStr, "null", 4);
            }
            sqlite3_str_append(pStr, "}", 1);
            sqlite3_result_str(ctx, pStr, SQLITE_FINISH);
        }
        sqlite3BtreeLeave(bt);
    } else {
        sqlite3_result_text(ctx, "{}", 2, SQLITE_STATIC);
    }
}

fn parseuriFunc(ctx: ?*Ctx, argc: c_int, argv: ?*?*Val) callconv(.c) void {
    const a = @as([*]?*Val, @ptrCast(argv.?));
    if (argc < 2) return;
    var pVfs = sqlite3_vfs_find(null);
    // zName at offset 16 in sqlite3_vfs
    const zVfs = @as(*align(1) const ?[*:0]const u8, @ptrCast(@as([*]u8, @ptrCast(pVfs.?)) + 16)).*;
    const zUri = sqlite3_value_text(a[0]);
    if (zUri == null) return;
    var flgs: c_uint = @intCast(sqlite3_value_int(a[1]));
    var zFile: ?[*:0]u8 = null;
    var zErr: ?[*:0]u8 = null;
    const rc = sqlite3ParseUri(zVfs, zUri, &flgs, &pVfs, &zFile, &zErr);
    const pResult = sqlite3_str_new(null);
    if (sqlite3_str_errcode(pResult) == 0) {
        sqlite3_str_appendf(pResult, "rc=%d", rc);
        sqlite3_str_appendf(pResult, ", flags=0x%x", flgs);
        const vfsName = if (pVfs) |v| @as(*align(1) const ?[*:0]const u8, @ptrCast(@as([*]u8, @ptrCast(v)) + 16)).* else null;
        sqlite3_str_appendf(pResult, ", vfs=%Q", vfsName orelse @as(?[*:0]const u8, null));
        sqlite3_str_appendf(pResult, ", err=%Q", zErr orelse @as(?[*:0]const u8, null));
        sqlite3_str_appendf(pResult, ", file=%Q", zFile orelse @as(?[*:0]const u8, null));
        if (zFile) |zf| {
            var z: [*:0]const u8 = zf;
            z += @intCast(sqlite3Strlen30(z) + 1);
            while (z[0] != 0) {
                sqlite3_str_appendf(pResult, ", %Q", z);
                z += @intCast(sqlite3Strlen30(z) + 1);
            }
            var i: usize = 2;
            while (i < @as(usize, @intCast(argc))) : (i += 1) {
                if (sqlite3_value_type(a[i]) == SQLITE_INTEGER) {
                    const kk = sqlite3_value_int(a[i]);
                    sqlite3_str_appendf(pResult, ", '%d:%q'", kk, sqlite3_uri_key(zf, kk));
                } else {
                    const zArg = sqlite3_value_text(a[i]);
                    if (zArg) |za| {
                        sqlite3_str_appendf(pResult, ", '%q:%q'", za, sqlite3_uri_parameter(zf, za));
                    } else {
                        sqlite3_str_appendf(pResult, ", NULL");
                    }
                }
            }
        }
    }
    sqlite3_result_str(ctx, pResult, SQLITE_FINISH);
    sqlite3_free_filename(zFile);
    sqlite3_free(zErr);
}
