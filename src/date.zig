//! Zig port of SQLite's src/date.c — the date & time SQL functions.
//!
//! The ONLY external-linkage symbol in date.c (and therefore the only one this
//! module exports) is `sqlite3RegisterDateTimeFunctions()`. Everything else in
//! date.c has file scope; here it is all module-private. This matches the
//! upstream header comment ("There is only one exported symbol in this file").
//!
//! Configuration assumed (true in BOTH this project's builds):
//!   * SQLITE_OMIT_DATETIME_FUNCS is OFF  → the full functions are compiled.
//!   * SQLITE_OMIT_LOCALTIME is OFF        → localtime/utc modifiers compiled.
//!   * HAVE_LOCALTIME_R is ON (Linux/glibc) → osLocaltime uses localtime_r,
//!     which needs no STATIC_MAIN mutex (matches the C HAVE_LOCALTIME_R branch).
//!   * SQLITE_UNTESTABLE is OFF             → the bLocaltimeFault / xAltLocaltime
//!     fault-injection check is compiled. (The flag is read at a config-invariant
//!     offset; it is only ever non-zero in the testfixture build, which sets it
//!     via the `tester` infrastructure — but the code path exists in both.)
//!   * SQLITE_DEBUG: the `datedebug(...)` function exists only under SQLITE_DEBUG.
//!     It is gated on `config.sqlite_debug` so the registered table has the same
//!     entries as the C build it links against.
//!   * SQLITE_ASCII is ON → sqlite3Isspace/Isdigit use sqlite3CtypeMap[].
//!
//! ─── Struct coupling ──────────────────────────────────────────────────────
//! `DateTime` is purely internal (stack/heap-local; never crosses the ABI), so
//! it is an ordinary Zig struct, NOT layout-pinned.
//! `FuncDef` is the registered function-table entry; it crosses the ABI to
//! sqlite3InsertBuiltinFuncs, so it is mirrored field-for-field as an extern
//! struct (identical to callback.zig's mirror; sizeof 72, config-invariant) and
//! the static `aDateTimeFuncs[]` table is built with byte-identical contents to
//! the C `PURE_DATE`/`DFUNCTION` macro expansions.
//! `sqlite3Config` is referenced (a) as the `pUserData` value of the PURE_DATE
//! entries (`(void*)&sqlite3Config`) and (b) for bLocaltimeFault/xAltLocaltime
//! at ground-truth offsets. It is a MUTABLE global → `extern var`.
//!
//! All numeric/Julian-day/modifier arithmetic is a line-for-line transliteration
//! of date.c; unsigned-wrap sites use Zig wrapping ops; float→int casts use
//! @intFromFloat (truncates toward zero, like a C cast).

const std = @import("std");
const config = @import("config");

// ─── Result / type constants ────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;

const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;

const SQLITE_UTF8: c_int = 1;

// sqlite3_result_str control flags
const SQLITE_XFER: c_int = 1;
const SQLITE_FINISH: c_int = 2;

// SQLITE_TRANSIENT = (sqlite3_destructor_type)-1
const SQLITE_TRANSIENT: ?*const fn (?*anyopaque) callconv(.c) void =
    @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// ─── FuncDef flag constants (for the registration table) ────────────────────
const SQLITE_UTF8_FLAG: u32 = 1; // SQLITE_UTF8 as a funcFlags bit
const SQLITE_FUNC_CONSTANT: u32 = 0x0800;
const SQLITE_FUNC_SLOCHNG: u32 = 0x2000;
const SQLITE_FUNC_BUILTIN: u32 = 0x00800000;

// PURE_DATE: BUILTIN | SLOCHNG | UTF8 | CONSTANT
const PURE_DATE_FLAGS: u32 =
    SQLITE_FUNC_BUILTIN | SQLITE_FUNC_SLOCHNG | SQLITE_UTF8_FLAG | SQLITE_FUNC_CONSTANT;
// DFUNCTION: BUILTIN | SLOCHNG | UTF8
const DFUNCTION_FLAGS: u32 =
    SQLITE_FUNC_BUILTIN | SQLITE_FUNC_SLOCHNG | SQLITE_UTF8_FLAG;

// ─── extern globals ─────────────────────────────────────────────────────────
// MUTABLE global — declare `extern var` (per the PROGRESS optimizer gotcha).
extern var sqlite3Config: anyopaque;
// Config-invariant ctype/case tables.
extern const sqlite3CtypeMap: [256]u8;
extern const sqlite3UpperToLower: [256]u8;

inline fn isSpace(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x01) != 0;
}
inline fn isDigit(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x04) != 0;
}
inline fn upperToLower(x: u8) u8 {
    return sqlite3UpperToLower[x];
}

// sqlite3Config field accessors (ground-truth offsets, config-invariant).
const cfg_bLocaltimeFault_off: usize = 408;
const cfg_xAltLocaltime_off: usize = 416;
const XAltLocaltime = ?*const fn (?*const anyopaque, ?*anyopaque) callconv(.c) c_int;
inline fn cfgBase() [*]u8 {
    return @ptrCast(&sqlite3Config);
}
inline fn cfgBLocaltimeFault() c_int {
    const p: *align(1) const c_int = @ptrCast(cfgBase() + cfg_bLocaltimeFault_off);
    return p.*;
}
inline fn cfgXAltLocaltime() XAltLocaltime {
    const p: *align(1) const XAltLocaltime = @ptrCast(cfgBase() + cfg_xAltLocaltime_off);
    return p.*;
}

// ─── extern C / internal-ABI helpers (resolved at link time) ────────────────
extern fn sqlite3StmtCurrentTime(context: ?*anyopaque) i64;
extern fn sqlite3NotPureFunc(context: ?*anyopaque) c_int;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;
extern fn sqlite3AtoF(z: ?[*:0]const u8, pResult: *f64) c_int;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*:0]const u8, n: u64) ?[*:0]u8;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3InsertBuiltinFuncs(aDef: [*]FuncDef, nDef: c_int) void;

// sqlite3_value / result / context public API
extern fn sqlite3_value_type(v: ?*anyopaque) c_int;
extern fn sqlite3_value_double(v: ?*anyopaque) f64;
extern fn sqlite3_value_text(v: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3_value_bytes(v: ?*anyopaque) c_int;
extern fn sqlite3_result_double(context: ?*anyopaque, r: f64) void;
extern fn sqlite3_result_int64(context: ?*anyopaque, n: i64) void;
extern fn sqlite3_result_text(context: ?*anyopaque, z: ?[*]const u8, n: c_int, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3_result_str(context: ?*anyopaque, p: ?*anyopaque, eDestructor: c_int) void;
extern fn sqlite3_result_error(context: ?*anyopaque, z: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3_context_db_handle(context: ?*anyopaque) ?*anyopaque;

// sqlite3_str (StrAccum) public API
extern fn sqlite3_str_new(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3_str_append(p: ?*anyopaque, z: ?[*]const u8, n: c_int) void;
extern fn sqlite3_str_appendchar(p: ?*anyopaque, n: c_int, c: u8) void;
extern fn sqlite3_str_appendf(p: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_str_free(p: ?*anyopaque) void;
extern fn sqlite3StrAccumInit(p: *StrAccum, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) void;

// libc localtime_r (HAVE_LOCALTIME_R path).
const time_t = c_long;
const struct_tm = extern struct {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: ?[*:0]const u8,
};
extern fn localtime_r(noalias timer: *const time_t, noalias result: *struct_tm) ?*struct_tm;

// ─── StrAccum mirror (config-invariant, sizeof 32) ──────────────────────────
const StrAccum = extern struct {
    db: ?*anyopaque, // 0
    zText: ?[*]u8, // 8
    nAlloc: u32, // 16
    mxAlloc: u32, // 20
    nChar: u32, // 24
    accError: u8, // 28
    printfFlags: u8, // 29
};
comptime {
    std.debug.assert(@sizeOf(StrAccum) == 32);
    std.debug.assert(@offsetOf(StrAccum, "zText") == 8);
    std.debug.assert(@offsetOf(StrAccum, "nAlloc") == 16);
    std.debug.assert(@offsetOf(StrAccum, "nChar") == 24);
    std.debug.assert(@offsetOf(StrAccum, "accError") == 28);
    std.debug.assert(@offsetOf(StrAccum, "printfFlags") == 29);
}

// ─── FuncDef mirror (ABI; identical to callback.zig; sizeof 72) ─────────────
const XFunc = ?*const fn (?*anyopaque, c_int, ?*?*anyopaque) callconv(.c) void;
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

// ─── DateTime — purely internal value object ────────────────────────────────
const DateTime = struct {
    iJD: i64 = 0, // The julian day number times 86400000
    Y: c_int = 0,
    M: c_int = 0,
    D: c_int = 0,
    h: c_int = 0,
    m: c_int = 0,
    tz: c_int = 0, // Timezone offset in minutes
    s: f64 = 0, // Seconds
    validJD: bool = false,
    validYMD: bool = false,
    validHMS: bool = false,
    nFloor: c_int = 0, // Days to implement "floor"
    rawS: bool = false,
    isError: bool = false,
    useSubsec: bool = false,
    isUtc: bool = false,
    isLocal: bool = false,
};

// ─── getDigits ──────────────────────────────────────────────────────────────
// C uses varargs; here `out` is a slice of out-pointers, one per format group.
// Behavior is identical: returns the number of successful conversions.
//
//   format char groups (4 chars each, last group 3 chars):
//     [0] N : number of digits ('2'/'4')
//     [1] min : minimum value ('0'/'1')
//     [2] max code : 'a'..'f'
//     [3] separator, or \000 for the last group
const aMx = [_]u16{ 12, 14, 24, 31, 59, 14712 };

fn getDigits(zDate: [*:0]const u8, zFormat: [*:0]const u8, out: []const *c_int) c_int {
    var cnt: c_int = 0;
    var zd: [*:0]const u8 = zDate;
    var zf: [*:0]const u8 = zFormat;
    var oi: usize = 0;
    var nextC: u8 = undefined;
    while (true) {
        const N0: i32 = @as(i32, zf[0]) - '0';
        const min: i32 = @as(i32, zf[1]) - '0';
        var val: c_int = 0;

        std.debug.assert(zf[2] >= 'a' and zf[2] <= 'f');
        const max: u16 = aMx[zf[2] - 'a'];
        nextC = zf[3];
        val = 0;
        var N: i32 = N0;
        while (N != 0) {
            N -= 1;
            if (!isDigit(zd[0])) {
                return cnt;
            }
            val = val * 10 + @as(c_int, zd[0]) - '0';
            zd += 1;
        }
        if (val < @as(c_int, min) or val > @as(c_int, @intCast(max)) or
            (nextC != 0 and nextC != zd[0]))
        {
            return cnt;
        }
        out[oi].* = val;
        oi += 1;
        zd += 1;
        cnt += 1;
        zf += 4;
        if (nextC == 0) break;
    }
    return cnt;
}

// ─── parseTimezone ──────────────────────────────────────────────────────────
fn parseTimezone(zDate: [*:0]const u8, p: *DateTime) c_int {
    var sgn: c_int = 0;
    var nHr: c_int = undefined;
    var nMn: c_int = undefined;
    var zd: [*:0]const u8 = zDate;
    while (isSpace(zd[0])) zd += 1;
    p.tz = 0;
    const c0 = zd[0];
    if (c0 == '-') {
        sgn = -1;
    } else if (c0 == '+') {
        sgn = 1;
    } else if (c0 == 'Z' or c0 == 'z') {
        zd += 1;
        p.isLocal = false;
        p.isUtc = true;
        // goto zulu_time
        while (isSpace(zd[0])) zd += 1;
        return @intFromBool(zd[0] != 0);
    } else {
        return @intFromBool(c0 != 0);
    }
    zd += 1;
    if (getDigits(zd, "20b:20e", &.{ &nHr, &nMn }) != 2) {
        return 1;
    }
    zd += 5;
    p.tz = sgn * (nMn + nHr * 60);
    if (p.tz == 0) { // Forum post 2025-09-17T10:12:14z
        p.isLocal = false;
        p.isUtc = true;
    }
    // zulu_time:
    while (isSpace(zd[0])) zd += 1;
    return @intFromBool(zd[0] != 0);
}

// ─── parseHhMmSs ────────────────────────────────────────────────────────────
fn parseHhMmSs(zDate: [*:0]const u8, p: *DateTime) c_int {
    var h: c_int = undefined;
    var m: c_int = undefined;
    var s: c_int = undefined;
    var ms: f64 = 0.0;
    var zd: [*:0]const u8 = zDate;
    if (getDigits(zd, "20c:20e", &.{ &h, &m }) != 2) {
        return 1;
    }
    zd += 5;
    if (zd[0] == ':') {
        zd += 1;
        if (getDigits(zd, "20e", &.{&s}) != 1) {
            return 1;
        }
        zd += 2;
        if (zd[0] == '.' and isDigit(zd[1])) {
            var rScale: f64 = 1.0;
            zd += 1;
            while (isDigit(zd[0])) {
                ms = ms * 10.0 + @as(f64, @floatFromInt(@as(c_int, zd[0]) - '0'));
                rScale *= 10.0;
                zd += 1;
            }
            ms /= rScale;
            // Truncate to avoid sub-millisecond rounding problems.
            if (ms > 0.999) ms = 0.999;
        }
    } else {
        s = 0;
    }
    p.validJD = false;
    p.rawS = false;
    p.validHMS = true;
    p.h = h;
    p.m = m;
    p.s = @as(f64, @floatFromInt(s)) + ms;
    if (parseTimezone(zd, p) != 0) return 1;
    return 0;
}

// ─── datetimeError ──────────────────────────────────────────────────────────
fn datetimeError(p: *DateTime) void {
    p.* = .{};
    p.isError = true;
}

// ─── computeJD ──────────────────────────────────────────────────────────────
fn computeJD(p: *DateTime) void {
    var Y: c_int = undefined;
    var M: c_int = undefined;
    var D: c_int = undefined;

    if (p.validJD) return;
    if (p.validYMD) {
        Y = p.Y;
        M = p.M;
        D = p.D;
    } else {
        Y = 2000; // If no YMD specified, assume 2000-Jan-01
        M = 1;
        D = 1;
    }
    if (Y < -4713 or Y > 9999 or p.rawS) {
        datetimeError(p);
        return;
    }
    if (M <= 2) {
        Y -= 1;
        M += 12;
    }
    const A: c_int = @divTrunc(Y + 4800, 100);
    const B: c_int = 38 - A + @divTrunc(A, 4);
    const X1: c_int = @divTrunc(36525 * (Y + 4716), 100);
    const X2: c_int = @divTrunc(306001 * (M + 1), 10000);
    p.iJD = @intFromFloat((@as(f64, @floatFromInt(X1 + X2 + D + B)) - 1524.5) * 86400000);
    p.validJD = true;
    if (p.validHMS) {
        p.iJD += @as(i64, p.h) * 3600000 + @as(i64, p.m) * 60000 +
            @as(i64, @intFromFloat(p.s * 1000 + 0.5));
        if (p.tz != 0) {
            p.iJD -= @as(i64, p.tz) * 60000;
            p.validYMD = false;
            p.validHMS = false;
            p.tz = 0;
            p.isUtc = true;
            p.isLocal = false;
        }
    }
}

// ─── computeFloor ───────────────────────────────────────────────────────────
fn computeFloor(p: *DateTime) void {
    std.debug.assert(p.validYMD or p.isError);
    std.debug.assert(p.D >= 0 and p.D <= 31);
    std.debug.assert(p.M >= 0 and p.M <= 12);
    if (p.D <= 28) {
        p.nFloor = 0;
    } else if ((@as(c_int, 1) << @intCast(p.M)) & 0x15aa != 0) {
        p.nFloor = 0;
    } else if (p.M != 2) {
        p.nFloor = @intFromBool(p.D == 31);
    } else if (@rem(p.Y, 4) != 0 or (@rem(p.Y, 100) == 0 and @rem(p.Y, 400) != 0)) {
        p.nFloor = p.D - 28;
    } else {
        p.nFloor = p.D - 29;
    }
}

// ─── parseYyyyMmDd ──────────────────────────────────────────────────────────
fn parseYyyyMmDd(zDate: [*:0]const u8, p: *DateTime) c_int {
    var Y: c_int = undefined;
    var M: c_int = undefined;
    var D: c_int = undefined;
    var neg: c_int = undefined;
    var zd: [*:0]const u8 = zDate;

    if (zd[0] == '-') {
        zd += 1;
        neg = 1;
    } else {
        neg = 0;
    }
    if (getDigits(zd, "40f-21a-21d", &.{ &Y, &M, &D }) != 3) {
        return 1;
    }
    zd += 10;
    while (isSpace(zd[0]) or 'T' == zd[0]) zd += 1;
    if (parseHhMmSs(zd, p) == 0) {
        // We got the time
    } else if (zd[0] == 0) {
        p.validHMS = false;
    } else {
        return 1;
    }
    p.validJD = false;
    p.validYMD = true;
    p.Y = if (neg != 0) -Y else Y;
    p.M = M;
    p.D = D;
    computeFloor(p);
    if (p.tz != 0) {
        computeJD(p);
    }
    return 0;
}

// ─── setDateTimeToCurrent ───────────────────────────────────────────────────
fn setDateTimeToCurrent(context: ?*anyopaque, p: *DateTime) c_int {
    p.iJD = sqlite3StmtCurrentTime(context);
    if (p.iJD > 0) {
        p.validJD = true;
        p.isUtc = true;
        p.isLocal = false;
        clearYMD_HMS_TZ(p);
        return 0;
    } else {
        return 1;
    }
}

// ─── setRawDateNumber ───────────────────────────────────────────────────────
fn setRawDateNumber(p: *DateTime, r: f64) void {
    p.s = r;
    p.rawS = true;
    if (r >= 0.0 and r < 5373484.5) {
        p.iJD = @intFromFloat(r * 86400000.0 + 0.5);
        p.validJD = true;
    }
}

// ─── parseDateOrTime ────────────────────────────────────────────────────────
fn parseDateOrTime(context: ?*anyopaque, zDate: [*:0]const u8, p: *DateTime) c_int {
    var r: f64 = undefined;
    if (parseYyyyMmDd(zDate, p) == 0) {
        return 0;
    } else if (parseHhMmSs(zDate, p) == 0) {
        return 0;
    } else if (sqlite3StrICmp(zDate, "now") == 0 and sqlite3NotPureFunc(context) != 0) {
        return setDateTimeToCurrent(context, p);
    } else if (sqlite3AtoF(zDate, &r) > 0) {
        setRawDateNumber(p, r);
        return 0;
    } else if ((sqlite3StrICmp(zDate, "subsec") == 0 or
        sqlite3StrICmp(zDate, "subsecond") == 0) and
        sqlite3NotPureFunc(context) != 0)
    {
        p.useSubsec = true;
        return setDateTimeToCurrent(context, p);
    }
    return 1;
}

// JD for 9999-12-31 23:59:59.999 * 86400000 = 464269060799999
const INT_464269060799999: i64 = (@as(i64, 0x1a640) << 32) | 0x1072fdff;

fn validJulianDay(iJD: i64) bool {
    return iJD >= 0 and iJD <= INT_464269060799999;
}

// ─── computeYMD ─────────────────────────────────────────────────────────────
fn computeYMD(p: *DateTime) void {
    if (p.validYMD) return;
    if (!p.validJD) {
        p.Y = 2000;
        p.M = 1;
        p.D = 1;
    } else if (!validJulianDay(p.iJD)) {
        datetimeError(p);
        return;
    } else {
        const Z: c_int = @intCast(@divTrunc(p.iJD + 43200000, 86400000));
        const alpha: c_int = @as(c_int, @intFromFloat((@as(f64, @floatFromInt(Z)) + 32044.75) / 36524.25)) - 52;
        const A: c_int = Z + 1 + alpha - @divTrunc(alpha + 100, 4) + 25;
        const B: c_int = A + 1524;
        const C: c_int = @intFromFloat((@as(f64, @floatFromInt(B)) - 122.1) / 365.25);
        const D: c_int = @divTrunc(36525 * (C & 32767), 100);
        const E: c_int = @intFromFloat(@as(f64, @floatFromInt(B - D)) / 30.6001);
        const X1: c_int = @intFromFloat(30.6001 * @as(f64, @floatFromInt(E)));
        p.D = B - D - X1;
        p.M = if (E < 14) E - 1 else E - 13;
        p.Y = if (p.M > 2) C - 4716 else C - 4715;
    }
    p.validYMD = true;
}

// ─── computeHMS ─────────────────────────────────────────────────────────────
fn computeHMS(p: *DateTime) void {
    if (p.validHMS) return;
    computeJD(p);
    const day_ms: c_int = @intCast(@rem(p.iJD + 43200000, 86400000));
    p.s = @as(f64, @floatFromInt(@rem(day_ms, 60000))) / 1000.0;
    const day_min: c_int = @divTrunc(day_ms, 60000);
    p.m = @rem(day_min, 60);
    p.h = @divTrunc(day_min, 60);
    p.rawS = false;
    p.validHMS = true;
}

fn computeYMD_HMS(p: *DateTime) void {
    computeYMD(p);
    computeHMS(p);
}

fn clearYMD_HMS_TZ(p: *DateTime) void {
    p.validYMD = false;
    p.validHMS = false;
    p.tz = 0;
}

// ─── osLocaltime (HAVE_LOCALTIME_R path) ────────────────────────────────────
// Returns 0 on success, non-zero on error.
fn osLocaltime(t: *time_t, pTm: *struct_tm) c_int {
    // SQLITE_UNTESTABLE is OFF → the fault-injection check is compiled.
    if (cfgBLocaltimeFault() != 0) {
        if (cfgXAltLocaltime()) |xf| {
            return xf(@ptrCast(t), @ptrCast(pTm));
        } else {
            return 1;
        }
    }
    // HAVE_LOCALTIME_R
    return @intFromBool(localtime_r(t, pTm) == null);
}

// ─── toLocaltime ────────────────────────────────────────────────────────────
fn toLocaltime(p: *DateTime, pCtx: ?*anyopaque) c_int {
    var t: time_t = undefined;
    var sLocal: struct_tm = std.mem.zeroes(struct_tm);
    var iYearDiff: c_int = undefined;

    computeJD(p);
    if (p.iJD < 2108667600 * @as(i64, 100000) // 1970-01-01
    or p.iJD > 2130141456 * @as(i64, 100000) // 2038-01-18
    ) {
        var x = p.*;
        computeYMD_HMS(&x);
        iYearDiff = (2000 + @rem(x.Y, 4)) - x.Y;
        x.Y += iYearDiff;
        x.validJD = false;
        computeJD(&x);
        t = @intCast(@divTrunc(x.iJD, 1000) - 21086676 * @as(i64, 10000));
    } else {
        iYearDiff = 0;
        t = @intCast(@divTrunc(p.iJD, 1000) - 21086676 * @as(i64, 10000));
    }
    if (osLocaltime(&t, &sLocal) != 0) {
        sqlite3_result_error(pCtx, "local time unavailable", -1);
        return SQLITE_ERROR;
    }
    p.Y = sLocal.tm_year + 1900 - iYearDiff;
    p.M = sLocal.tm_mon + 1;
    p.D = sLocal.tm_mday;
    p.h = sLocal.tm_hour;
    p.m = sLocal.tm_min;
    p.s = @as(f64, @floatFromInt(sLocal.tm_sec)) +
        @as(f64, @floatFromInt(@rem(p.iJD, 1000))) * 0.001;
    p.validYMD = true;
    p.validHMS = true;
    p.validJD = false;
    p.rawS = false;
    p.tz = 0;
    p.isError = false;
    return SQLITE_OK;
}

// ─── aXformType table ───────────────────────────────────────────────────────
// rLimit / rXform are C `float` (f32) — the comparisons/multiplications below
// promote them to f64, so they are stored as f32 and read as f64 to match.
const XformType = struct {
    nName: u8,
    zName: [*:0]const u8,
    rLimit: f32,
    rXform: f32,
};
const aXformType = [_]XformType{
    .{ .nName = 6, .zName = "second", .rLimit = 4.6427e+14, .rXform = 1.0 },
    .{ .nName = 6, .zName = "minute", .rLimit = 7.7379e+12, .rXform = 60.0 },
    .{ .nName = 4, .zName = "hour", .rLimit = 1.2897e+11, .rXform = 3600.0 },
    .{ .nName = 3, .zName = "day", .rLimit = 5373485.0, .rXform = 86400.0 },
    .{ .nName = 5, .zName = "month", .rLimit = 176546.0, .rXform = 2592000.0 },
    .{ .nName = 4, .zName = "year", .rLimit = 14713.0, .rXform = 31536000.0 },
};

// ─── autoAdjustDate ─────────────────────────────────────────────────────────
fn autoAdjustDate(p: *DateTime) void {
    if (!p.rawS or p.validJD) {
        p.rawS = false;
    } else if (p.s >= @as(f64, @floatFromInt(-21086676 * @as(i64, 10000))) // -4713-11-24 12:00:00
    and p.s <= @as(f64, @floatFromInt(25340230 * @as(i64, 10000) + 799)) // 9999-12-31 23:59:59
    ) {
        const r = p.s * 1000.0 + 210866760000000.0;
        clearYMD_HMS_TZ(p);
        p.iJD = @intFromFloat(r + 0.5);
        p.validJD = true;
        p.rawS = false;
    }
}

// ─── parseModifier ──────────────────────────────────────────────────────────
fn parseModifier(
    pCtx: ?*anyopaque,
    z_in: [*:0]const u8,
    n_in: c_int,
    p: *DateTime,
    idx: c_int,
) c_int {
    var rc: c_int = 1;
    var r: f64 = undefined;
    var z: [*:0]const u8 = z_in;
    var n: c_int = n_in;
    switch (upperToLower(z[0])) {
        'a' => {
            // auto
            if (sqlite3_stricmp(z, "auto") == 0) {
                if (idx > 1) return 1; // IMP: R-33611-57934
                autoAdjustDate(p);
                rc = 0;
            }
        },
        'c' => {
            // ceiling
            if (sqlite3_stricmp(z, "ceiling") == 0) {
                computeJD(p);
                clearYMD_HMS_TZ(p);
                rc = 0;
                p.nFloor = 0;
            }
        },
        'f' => {
            // floor
            if (sqlite3_stricmp(z, "floor") == 0) {
                computeJD(p);
                p.iJD -= @as(i64, p.nFloor) * 86400000;
                clearYMD_HMS_TZ(p);
                rc = 0;
            }
        },
        'j' => {
            // julianday
            if (sqlite3_stricmp(z, "julianday") == 0) {
                if (idx > 1) return 1; // IMP: R-31176-64601
                if (p.validJD and p.rawS) {
                    rc = 0;
                    p.rawS = false;
                }
            }
        },
        'l' => {
            // localtime  (SQLITE_OMIT_LOCALTIME is OFF)
            if (sqlite3_stricmp(z, "localtime") == 0 and sqlite3NotPureFunc(pCtx) != 0) {
                rc = if (p.isLocal) SQLITE_OK else toLocaltime(p, pCtx);
                p.isUtc = false;
                p.isLocal = true;
            }
        },
        'u' => {
            // unixepoch
            if (sqlite3_stricmp(z, "unixepoch") == 0 and p.rawS) {
                if (idx > 1) return 1; // IMP: R-49255-55373
                r = p.s * 1000.0 + 210866760000000.0;
                if (r >= 0.0 and r < 464269060800000.0) {
                    clearYMD_HMS_TZ(p);
                    p.iJD = @intFromFloat(r + 0.5);
                    p.validJD = true;
                    p.rawS = false;
                    rc = 0;
                }
            }
            // utc  (SQLITE_OMIT_LOCALTIME is OFF)
            else if (sqlite3_stricmp(z, "utc") == 0 and sqlite3NotPureFunc(pCtx) != 0) {
                if (!p.isUtc) {
                    var iGuess: i64 = undefined;
                    var iOrigJD: i64 = undefined;
                    var cnt: c_int = 0;
                    var iErr: i64 = 0;

                    computeJD(p);
                    iGuess = p.iJD;
                    iOrigJD = p.iJD;
                    iErr = 0;
                    while (true) {
                        var new: DateTime = .{};
                        iGuess -= iErr;
                        new.iJD = iGuess;
                        new.validJD = true;
                        rc = toLocaltime(&new, pCtx);
                        if (rc != 0) return rc;
                        computeJD(&new);
                        iErr = new.iJD - iOrigJD;
                        const continue_loop = (iErr != 0 and cnt < 3);
                        cnt += 1;
                        if (!continue_loop) break;
                    }
                    p.* = .{};
                    p.iJD = iGuess;
                    p.validJD = true;
                    p.isUtc = true;
                    p.isLocal = false;
                }
                rc = SQLITE_OK;
            }
        },
        'w' => {
            // weekday N
            if (sqlite3_strnicmp(z, "weekday ", 8) == 0 and
                sqlite3AtoF(@ptrCast(z + 8), &r) > 0 and
                r >= 0.0 and r < 7.0 and blk: {
                    n = @intFromFloat(r);
                    break :blk @as(f64, @floatFromInt(n)) == r;
                })
            {
                var Z: i64 = undefined;
                computeYMD_HMS(p);
                p.tz = 0;
                p.validJD = false;
                computeJD(p);
                Z = @rem(@divTrunc(p.iJD + 129600000, 86400000), 7);
                if (Z > @as(i64, n)) Z -= 7;
                p.iJD += (@as(i64, n) - Z) * 86400000;
                clearYMD_HMS_TZ(p);
                rc = 0;
            }
        },
        's' => {
            // start of TTTTT  /  subsec[ond]
            if (sqlite3_strnicmp(z, "start of ", 9) != 0) {
                if (sqlite3_stricmp(z, "subsec") == 0 or
                    sqlite3_stricmp(z, "subsecond") == 0)
                {
                    p.useSubsec = true;
                    rc = 0;
                }
            } else if (!p.validJD and !p.validYMD and !p.validHMS) {
                // break
            } else {
                z += 9;
                computeYMD(p);
                p.validHMS = true;
                p.h = 0;
                p.m = 0;
                p.s = 0.0;
                p.rawS = false;
                p.tz = 0;
                p.validJD = false;
                if (sqlite3_stricmp(z, "month") == 0) {
                    p.D = 1;
                    rc = 0;
                } else if (sqlite3_stricmp(z, "year") == 0) {
                    p.M = 1;
                    p.D = 1;
                    rc = 0;
                } else if (sqlite3_stricmp(z, "day") == 0) {
                    rc = 0;
                }
            }
        },
        '+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' => {
            rc = parseNumericModifier(pCtx, &z, &n, p, &r);
        },
        else => {},
    }
    return rc;
}

// The "+"/"-"/digit branch of parseModifier, extracted for clarity. Mutates
// z and n through pointers exactly as the C code mutates its locals. Returns rc.
fn parseNumericModifier(
    pCtx: ?*anyopaque,
    pz: *[*:0]const u8,
    pn: *c_int,
    p: *DateTime,
    pr: *f64,
) c_int {
    var rc: c_int = 1;
    var z = pz.*;
    var n = pn.*;
    var r = pr.*;
    defer {
        pz.* = z;
        pn.* = n;
        pr.* = r;
    }

    var rRounder: f64 = undefined;
    var Y: c_int = undefined;
    var M: c_int = undefined;
    var D: c_int = undefined;
    var h: c_int = undefined;
    var m: c_int = undefined;
    var x: c_int = undefined;
    var z2: [*:0]const u8 = z;
    const db = sqlite3_context_db_handle(pCtx);
    const z0: u8 = z[0];

    // Find the end of the leading number.
    n = 1;
    while (z[@intCast(n)] != 0) : (n += 1) {
        if (z[@intCast(n)] == ':') break;
        if (isSpace(z[@intCast(n)])) break;
        if (z[@intCast(n)] == '-') {
            if (n == 5 and getDigits(@ptrCast(z + 1), "40f", &.{&Y}) == 1) break;
            if (n == 6 and getDigits(@ptrCast(z + 1), "50f", &.{&Y}) == 1) break;
        }
    }
    const zCopy = sqlite3DbStrNDup(db, z, @intCast(n));
    if (zCopy == null) return rc;
    const rx = sqlite3AtoF(zCopy, &r) <= 0;
    sqlite3DbFree(db, zCopy);
    if (rx) {
        std.debug.assert(rc == 1);
        return rc;
    }
    if (z[@intCast(n)] == '-') {
        // (+|-)YYYY-MM-DD adds/subtracts years, months, days.
        if (z0 != '+' and z0 != '-') return rc; // Must start with +/-
        if (n == 5) {
            if (getDigits(@ptrCast(z + 1), "40f-20a-20d", &.{ &Y, &M, &D }) != 3) return rc;
        } else {
            std.debug.assert(n == 6);
            if (getDigits(@ptrCast(z + 1), "50f-20a-20d", &.{ &Y, &M, &D }) != 3) return rc;
            z += 1;
        }
        if (M >= 12) return rc; // M range 0..11
        if (D >= 31) return rc; // D range 0..30
        computeYMD_HMS(p);
        p.validJD = false;
        if (z0 == '-') {
            p.Y -= Y;
            p.M -= M;
            D = -D;
        } else {
            p.Y += Y;
            p.M += M;
        }
        x = if (p.M > 0) @divTrunc(p.M - 1, 12) else @divTrunc(p.M - 12, 12);
        p.Y += x;
        p.M -= x * 12;
        computeFloor(p);
        computeJD(p);
        p.validHMS = false;
        p.validYMD = false;
        p.iJD += @as(i64, D) * 86400000;
        if (z[11] == 0) {
            rc = 0;
            return rc;
        }
        if (isSpace(z[11]) and getDigits(@ptrCast(z + 12), "20c:20e", &.{ &h, &m }) == 2) {
            z2 = @ptrCast(z + 12);
            n = 2;
        } else {
            return rc;
        }
    }
    if (z2[@intCast(n)] == ':') {
        // (+|-)HH:MM:SS.FFF adds/subtracts hours, minutes, seconds, frac.
        var tx: DateTime = .{};
        var day: i64 = undefined;
        if (!isDigit(z2[0])) z2 += 1;
        if (parseHhMmSs(z2, &tx) != 0) return rc;
        computeJD(&tx);
        tx.iJD -= 43200000;
        day = @divTrunc(tx.iJD, 86400000);
        tx.iJD -= day * 86400000;
        if (z0 == '-') tx.iJD = -tx.iJD;
        computeJD(p);
        clearYMD_HMS_TZ(p);
        p.iJD += tx.iJD;
        rc = 0;
        return rc;
    }

    // One of the "+NNN days" forms.
    z += @intCast(n);
    while (isSpace(z[0])) z += 1;
    n = sqlite3Strlen30(z);
    if (n < 3 or n > 10) return rc;
    if (upperToLower(z[@intCast(n - 1)]) == 's') n -= 1;
    computeJD(p);
    std.debug.assert(rc == 1);
    rRounder = if (r < 0) -0.5 else 0.5;
    p.nFloor = 0;
    var i: usize = 0;
    while (i < aXformType.len) : (i += 1) {
        if (@as(c_int, aXformType[i].nName) == n and
            sqlite3_strnicmp(aXformType[i].zName, z, n) == 0 and
            r > -@as(f64, aXformType[i].rLimit) and r < @as(f64, aXformType[i].rLimit))
        {
            switch (i) {
                4 => { // months
                    computeYMD_HMS(p);
                    p.M += @as(c_int, @intFromFloat(r));
                    x = if (p.M > 0) @divTrunc(p.M - 1, 12) else @divTrunc(p.M - 12, 12);
                    p.Y += x;
                    p.M -= x * 12;
                    computeFloor(p);
                    p.validJD = false;
                    r -= @as(f64, @floatFromInt(@as(c_int, @intFromFloat(r))));
                },
                5 => { // years
                    const y: c_int = @intFromFloat(r);
                    std.debug.assert(p.M >= 0 and p.M <= 12);
                    computeYMD_HMS(p);
                    p.Y += y;
                    computeFloor(p);
                    p.validJD = false;
                    r -= @as(f64, @floatFromInt(@as(c_int, @intFromFloat(r))));
                },
                else => {},
            }
            computeJD(p);
            p.iJD += @as(i64, @intFromFloat(r * 1000.0 * @as(f64, aXformType[i].rXform) + rRounder));
            rc = 0;
            break;
        }
    }
    clearYMD_HMS_TZ(p);
    return rc;
}

// ─── isDate ─────────────────────────────────────────────────────────────────
// argv is optional: a 0-arg call (e.g. date()) passes a null argv, and the
// @ptrCast at the call sites would panic ("cast causes pointer to be null") if
// the param were a non-optional [*]. All derefs below happen only after the
// argc==0 early return, where argv is guaranteed non-null.
fn isDate(context: ?*anyopaque, argc: c_int, argv: ?[*]?*anyopaque, p: *DateTime) c_int {
    p.* = .{};
    if (argc == 0) {
        if (sqlite3NotPureFunc(context) == 0) return 1;
        return setDateTimeToCurrent(context, p);
    }
    const a = argv.?;
    const eType = sqlite3_value_type(a[0]);
    if (eType == SQLITE_FLOAT or eType == SQLITE_INTEGER) {
        setRawDateNumber(p, sqlite3_value_double(a[0]));
    } else {
        const z = sqlite3_value_text(a[0]);
        if (z == null or parseDateOrTime(context, z.?, p) != 0) {
            return 1;
        }
    }
    var i: c_int = 1;
    while (i < argc) : (i += 1) {
        const z = sqlite3_value_text(a[@intCast(i)]);
        const n = sqlite3_value_bytes(a[@intCast(i)]);
        if (z == null or parseModifier(context, z.?, n, p, i) != 0) return 1;
    }
    computeJD(p);
    if (p.isError or !validJulianDay(p.iJD)) return 1;
    if (argc == 1 and p.validYMD and p.D > 28) {
        // Normalize a YYYY-MM-DD. Example: 2023-02-31 -> 2023-03-03
        std.debug.assert(p.validJD);
        p.validYMD = false;
    }
    return 0;
}

// ─── juliandayFunc ──────────────────────────────────────────────────────────
fn juliandayFunc(context: ?*anyopaque, argc: c_int, argv: ?*?*anyopaque) callconv(.c) void {
    var x: DateTime = .{};
    if (isDate(context, argc, @ptrCast(argv), &x) == 0) {
        computeJD(&x);
        sqlite3_result_double(context, @as(f64, @floatFromInt(x.iJD)) / 86400000.0);
    }
}

// ─── unixepochFunc ──────────────────────────────────────────────────────────
fn unixepochFunc(context: ?*anyopaque, argc: c_int, argv: ?*?*anyopaque) callconv(.c) void {
    var x: DateTime = .{};
    if (isDate(context, argc, @ptrCast(argv), &x) == 0) {
        computeJD(&x);
        if (x.useSubsec) {
            sqlite3_result_double(context, @as(f64, @floatFromInt(x.iJD - 21086676 * @as(i64, 10000000))) / 1000.0);
        } else {
            sqlite3_result_int64(context, @divTrunc(x.iJD, 1000) - 21086676 * @as(i64, 10000));
        }
    }
}

// Convert a non-negative digit value 0..9 to its ASCII char with C's
// `'0' + (v)%10` semantics. v is a c_int that may be negative for stray cases;
// match `(int)` arithmetic via @rem.
inline fn digitChar(v: c_int) u8 {
    return @intCast('0' + @rem(v, 10));
}

// ─── datetimeFunc ───────────────────────────────────────────────────────────
fn datetimeFunc(context: ?*anyopaque, argc: c_int, argv: ?*?*anyopaque) callconv(.c) void {
    var x: DateTime = .{};
    if (isDate(context, argc, @ptrCast(argv), &x) == 0) {
        var s: c_int = undefined;
        var n: c_int = undefined;
        var zBuf: [32]u8 = undefined;
        computeYMD_HMS(&x);
        var Y = x.Y;
        if (Y < 0) Y = -Y;
        zBuf[1] = digitChar(@divTrunc(Y, 1000));
        zBuf[2] = digitChar(@divTrunc(Y, 100));
        zBuf[3] = digitChar(@divTrunc(Y, 10));
        zBuf[4] = digitChar(Y);
        zBuf[5] = '-';
        zBuf[6] = digitChar(@divTrunc(x.M, 10));
        zBuf[7] = digitChar(x.M);
        zBuf[8] = '-';
        zBuf[9] = digitChar(@divTrunc(x.D, 10));
        zBuf[10] = digitChar(x.D);
        zBuf[11] = ' ';
        zBuf[12] = digitChar(@divTrunc(x.h, 10));
        zBuf[13] = digitChar(x.h);
        zBuf[14] = ':';
        zBuf[15] = digitChar(@divTrunc(x.m, 10));
        zBuf[16] = digitChar(x.m);
        zBuf[17] = ':';
        if (x.useSubsec) {
            s = @intFromFloat(1000.0 * x.s + 0.5);
            zBuf[18] = digitChar(@divTrunc(s, 10000));
            zBuf[19] = digitChar(@divTrunc(s, 1000));
            zBuf[20] = '.';
            zBuf[21] = digitChar(@divTrunc(s, 100));
            zBuf[22] = digitChar(@divTrunc(s, 10));
            zBuf[23] = digitChar(s);
            zBuf[24] = 0;
            n = 24;
        } else {
            s = @intFromFloat(x.s);
            zBuf[18] = digitChar(@divTrunc(s, 10));
            zBuf[19] = digitChar(s);
            zBuf[20] = 0;
            n = 20;
        }
        if (x.Y < 0) {
            zBuf[0] = '-';
            sqlite3_result_text(context, &zBuf, n, SQLITE_TRANSIENT);
        } else {
            sqlite3_result_text(context, @ptrCast(&zBuf[1]), n - 1, SQLITE_TRANSIENT);
        }
    }
}

// ─── timeFunc ───────────────────────────────────────────────────────────────
fn timeFunc(context: ?*anyopaque, argc: c_int, argv: ?*?*anyopaque) callconv(.c) void {
    var x: DateTime = .{};
    if (isDate(context, argc, @ptrCast(argv), &x) == 0) {
        var s: c_int = undefined;
        var n: c_int = undefined;
        var zBuf: [16]u8 = undefined;
        computeHMS(&x);
        zBuf[0] = digitChar(@divTrunc(x.h, 10));
        zBuf[1] = digitChar(x.h);
        zBuf[2] = ':';
        zBuf[3] = digitChar(@divTrunc(x.m, 10));
        zBuf[4] = digitChar(x.m);
        zBuf[5] = ':';
        if (x.useSubsec) {
            s = @intFromFloat(1000.0 * x.s + 0.5);
            zBuf[6] = digitChar(@divTrunc(s, 10000));
            zBuf[7] = digitChar(@divTrunc(s, 1000));
            zBuf[8] = '.';
            zBuf[9] = digitChar(@divTrunc(s, 100));
            zBuf[10] = digitChar(@divTrunc(s, 10));
            zBuf[11] = digitChar(s);
            zBuf[12] = 0;
            n = 12;
        } else {
            s = @intFromFloat(x.s);
            zBuf[6] = digitChar(@divTrunc(s, 10));
            zBuf[7] = digitChar(s);
            zBuf[8] = 0;
            n = 8;
        }
        sqlite3_result_text(context, &zBuf, n, SQLITE_TRANSIENT);
    }
}

// ─── dateFunc ───────────────────────────────────────────────────────────────
fn dateFunc(context: ?*anyopaque, argc: c_int, argv: ?*?*anyopaque) callconv(.c) void {
    var x: DateTime = .{};
    if (isDate(context, argc, @ptrCast(argv), &x) == 0) {
        var zBuf: [16]u8 = undefined;
        computeYMD(&x);
        var Y = x.Y;
        if (Y < 0) Y = -Y;
        zBuf[1] = digitChar(@divTrunc(Y, 1000));
        zBuf[2] = digitChar(@divTrunc(Y, 100));
        zBuf[3] = digitChar(@divTrunc(Y, 10));
        zBuf[4] = digitChar(Y);
        zBuf[5] = '-';
        zBuf[6] = digitChar(@divTrunc(x.M, 10));
        zBuf[7] = digitChar(x.M);
        zBuf[8] = '-';
        zBuf[9] = digitChar(@divTrunc(x.D, 10));
        zBuf[10] = digitChar(x.D);
        zBuf[11] = 0;
        if (x.Y < 0) {
            zBuf[0] = '-';
            sqlite3_result_text(context, &zBuf, 11, SQLITE_TRANSIENT);
        } else {
            sqlite3_result_text(context, @ptrCast(&zBuf[1]), 10, SQLITE_TRANSIENT);
        }
    }
}

// ─── daysAfterJan01 / Monday / Sunday ───────────────────────────────────────
fn daysAfterJan01(pDate: *DateTime) c_int {
    var jan01 = pDate.*;
    std.debug.assert(jan01.validYMD);
    std.debug.assert(jan01.validHMS);
    std.debug.assert(pDate.validJD);
    jan01.validJD = false;
    jan01.M = 1;
    jan01.D = 1;
    computeJD(&jan01);
    return @intCast(@divTrunc(pDate.iJD - jan01.iJD + 43200000, 86400000));
}

fn daysAfterMonday(pDate: *DateTime) c_int {
    std.debug.assert(pDate.validJD);
    return @intCast(@rem(@divTrunc(pDate.iJD + 43200000, 86400000), 7));
}

fn daysAfterSunday(pDate: *DateTime) c_int {
    std.debug.assert(pDate.validJD);
    return @intCast(@rem(@divTrunc(pDate.iJD + 129600000, 86400000), 7));
}

// ─── strftimeFunc ───────────────────────────────────────────────────────────
fn strftimeFunc(context: ?*anyopaque, argc: c_int, argv: ?*?*anyopaque) callconv(.c) void {
    var x: DateTime = .{};
    const av: [*]?*anyopaque = @ptrCast(argv);

    if (argc == 0) return;
    const zFmt = sqlite3_value_text(av[0]);
    if (zFmt == null or isDate(context, argc - 1, av + 1, &x) != 0) return;
    const db = sqlite3_context_db_handle(context);
    const pRes = sqlite3_str_new(db);

    computeJD(&x);
    computeYMD_HMS(&x);
    const fmt = zFmt.?;
    var i: usize = 0;
    var j: usize = 0;
    while (fmt[i] != 0) : (i += 1) {
        if (fmt[i] != '%') continue;
        if (j < i) sqlite3_str_append(pRes, @ptrCast(fmt + j), @intCast(i - j));
        i += 1;
        j = i + 1;
        const cf = fmt[i];
        switch (cf) {
            'd', 'e' => {
                sqlite3_str_appendf(pRes, if (cf == 'd') "%02d" else "%2d", x.D);
            },
            'f' => { // Fractional seconds (non-standard)
                var s = x.s;
                if (s > 59.999) s = 59.999; // NEVER() in C; harmless guard
                sqlite3_str_appendf(pRes, "%06.3f", s);
            },
            'F' => {
                sqlite3_str_appendf(pRes, "%04d-%02d-%02d", x.Y, x.M, x.D);
            },
            'G', 'g' => {
                var y = x;
                std.debug.assert(y.validJD);
                y.iJD += @as(i64, (3 - daysAfterMonday(&x))) * 86400000;
                y.validYMD = false;
                computeYMD(&y);
                if (cf == 'g') {
                    sqlite3_str_appendf(pRes, "%02d", @rem(y.Y, 100));
                } else {
                    sqlite3_str_appendf(pRes, "%04d", y.Y);
                }
            },
            'H', 'k' => {
                sqlite3_str_appendf(pRes, if (cf == 'H') "%02d" else "%2d", x.h);
            },
            'I', 'l' => {
                var hh = x.h;
                if (hh > 12) hh -= 12;
                if (hh == 0) hh = 12;
                sqlite3_str_appendf(pRes, if (cf == 'I') "%02d" else "%2d", hh);
            },
            'j' => { // Day of year. Jan01==1
                sqlite3_str_appendf(pRes, "%03d", daysAfterJan01(&x) + 1);
            },
            'J' => { // Julian day number (non-standard)
                sqlite3_str_appendf(pRes, "%.16g", @as(f64, @floatFromInt(x.iJD)) / 86400000.0);
            },
            'm' => {
                sqlite3_str_appendf(pRes, "%02d", x.M);
            },
            'M' => {
                sqlite3_str_appendf(pRes, "%02d", x.m);
            },
            'p', 'P' => {
                if (x.h >= 12) {
                    sqlite3_str_append(pRes, if (cf == 'p') "PM" else "pm", 2);
                } else {
                    sqlite3_str_append(pRes, if (cf == 'p') "AM" else "am", 2);
                }
            },
            'R' => {
                sqlite3_str_appendf(pRes, "%02d:%02d", x.h, x.m);
            },
            's' => {
                if (x.useSubsec) {
                    sqlite3_str_appendf(pRes, "%.3f", @as(f64, @floatFromInt(x.iJD - 21086676 * @as(i64, 10000000))) / 1000.0);
                } else {
                    const iS: i64 = @divTrunc(x.iJD, 1000) - 21086676 * @as(i64, 10000);
                    sqlite3_str_appendf(pRes, "%lld", iS);
                }
            },
            'S' => {
                sqlite3_str_appendf(pRes, "%02d", @as(c_int, @intFromFloat(x.s)));
            },
            'T' => {
                sqlite3_str_appendf(pRes, "%02d:%02d:%02d", x.h, x.m, @as(c_int, @intFromFloat(x.s)));
            },
            'u', 'w' => {
                var ch: u8 = @as(u8, @intCast(daysAfterSunday(&x))) + '0';
                if (ch == '0' and cf == 'u') ch = '7';
                sqlite3_str_appendchar(pRes, 1, ch);
            },
            'U' => {
                sqlite3_str_appendf(pRes, "%02d", @divTrunc(daysAfterJan01(&x) - daysAfterSunday(&x) + 7, 7));
            },
            'V' => {
                var y = x;
                std.debug.assert(y.validJD);
                y.iJD += @as(i64, (3 - daysAfterMonday(&x))) * 86400000;
                y.validYMD = false;
                computeYMD(&y);
                sqlite3_str_appendf(pRes, "%02d", @divTrunc(daysAfterJan01(&y), 7) + 1);
            },
            'W' => {
                sqlite3_str_appendf(pRes, "%02d", @divTrunc(daysAfterJan01(&x) - daysAfterMonday(&x) + 7, 7));
            },
            'Y' => {
                sqlite3_str_appendf(pRes, "%04d", x.Y);
            },
            '%' => {
                sqlite3_str_appendchar(pRes, 1, '%');
            },
            else => {
                sqlite3_str_free(pRes);
                return;
            },
        }
    }
    if (j < i) sqlite3_str_append(pRes, @ptrCast(fmt + j), @intCast(i - j));
    sqlite3_result_str(context, pRes, SQLITE_FINISH);
}

// ─── ctimeFunc / cdateFunc / ctimestampFunc ─────────────────────────────────
fn ctimeFunc(context: ?*anyopaque, NotUsed: c_int, NotUsed2: ?*?*anyopaque) callconv(.c) void {
    _ = NotUsed;
    _ = NotUsed2;
    timeFunc(context, 0, null);
}

fn cdateFunc(context: ?*anyopaque, NotUsed: c_int, NotUsed2: ?*?*anyopaque) callconv(.c) void {
    _ = NotUsed;
    _ = NotUsed2;
    dateFunc(context, 0, null);
}

fn ctimestampFunc(context: ?*anyopaque, NotUsed: c_int, NotUsed2: ?*?*anyopaque) callconv(.c) void {
    _ = NotUsed;
    _ = NotUsed2;
    datetimeFunc(context, 0, null);
}

// ─── timediffFunc ───────────────────────────────────────────────────────────
fn timediffFunc(context: ?*anyopaque, NotUsed1: c_int, argv_in: ?*?*anyopaque) callconv(.c) void {
    _ = NotUsed1;
    const argv: [*]?*anyopaque = @ptrCast(argv_in);
    var sign: u8 = undefined;
    var Y: c_int = undefined;
    var M: c_int = undefined;
    var d1: DateTime = .{};
    var d2: DateTime = .{};
    var sRes: StrAccum = undefined;
    if (isDate(context, 1, argv, &d1) != 0) return;
    if (isDate(context, 1, argv + 1, &d2) != 0) return;
    computeYMD_HMS(&d1);
    computeYMD_HMS(&d2);
    if (d1.iJD >= d2.iJD) {
        sign = '+';
        Y = d1.Y - d2.Y;
        if (Y != 0) {
            d2.Y = d1.Y;
            d2.validJD = false;
            computeJD(&d2);
        }
        M = d1.M - d2.M;
        if (M < 0) {
            Y -= 1;
            M += 12;
        }
        if (M != 0) {
            d2.M = d1.M;
            d2.validJD = false;
            computeJD(&d2);
        }
        while (d1.iJD < d2.iJD) {
            M -= 1;
            if (M < 0) {
                M = 11;
                Y -= 1;
            }
            d2.M -= 1;
            if (d2.M < 1) {
                d2.M = 12;
                d2.Y -= 1;
            }
            d2.validJD = false;
            computeJD(&d2);
        }
        d1.iJD -= d2.iJD;
        // (u64)1486995408 * (u64)100000, with defined unsigned wrap.
        d1.iJD +%= @bitCast(@as(u64, 1486995408) *% @as(u64, 100000));
    } else { // d1<d2
        sign = '-';
        Y = d2.Y - d1.Y;
        if (Y != 0) {
            d2.Y = d1.Y;
            d2.validJD = false;
            computeJD(&d2);
        }
        M = d2.M - d1.M;
        if (M < 0) {
            Y -= 1;
            M += 12;
        }
        if (M != 0) {
            d2.M = d1.M;
            d2.validJD = false;
            computeJD(&d2);
        }
        while (d1.iJD > d2.iJD) {
            M -= 1;
            if (M < 0) {
                M = 11;
                Y -= 1;
            }
            d2.M += 1;
            if (d2.M > 12) {
                d2.M = 1;
                d2.Y += 1;
            }
            d2.validJD = false;
            computeJD(&d2);
        }
        d1.iJD = d2.iJD - d1.iJD;
        d1.iJD +%= @bitCast(@as(u64, 1486995408) *% @as(u64, 100000));
    }
    clearYMD_HMS_TZ(&d1);
    computeYMD_HMS(&d1);
    sqlite3StrAccumInit(&sRes, null, null, 0, 100);
    sqlite3_str_appendf(&sRes, "%c%04d-%02d-%02d %02d:%02d:%06.3f", @as(c_int, sign), Y, M, d1.D - 1, d1.h, d1.m, d1.s);
    sqlite3_result_str(context, &sRes, SQLITE_XFER);
}

// ─── datedebugFunc (SQLITE_DEBUG only) ──────────────────────────────────────
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_free(p: ?*anyopaque) void;
fn datedebugFunc(context: ?*anyopaque, argc: c_int, argv: ?*?*anyopaque) callconv(.c) void {
    var x: DateTime = .{};
    if (isDate(context, argc, @ptrCast(argv), &x) == 0) {
        const zJson = sqlite3_mprintf(
            "{iJD:%lld,Y:%d,M:%d,D:%d,h:%d,m:%d,tz:%d," ++
                "s:%.3f,validJD:%d,validYMD:%d,validHMS:%d," ++
                "nFloor:%d,rawS:%d,isError:%d,useSubsec:%d," ++
                "isUtc:%d,isLocal:%d}",
            x.iJD,
            x.Y,
            x.M,
            x.D,
            x.h,
            x.m,
            x.tz,
            x.s,
            @as(c_int, @intFromBool(x.validJD)),
            @as(c_int, @intFromBool(x.validYMD)),
            @as(c_int, @intFromBool(x.validHMS)),
            x.nFloor,
            @as(c_int, @intFromBool(x.rawS)),
            @as(c_int, @intFromBool(x.isError)),
            @as(c_int, @intFromBool(x.useSubsec)),
            @as(c_int, @intFromBool(x.isUtc)),
            @as(c_int, @intFromBool(x.isLocal)),
        );
        sqlite3_result_text(context, @ptrCast(zJson), -1, @ptrCast(&sqlite3_free));
    }
}

// ─── The registration table ─────────────────────────────────────────────────
// Built to be byte-identical to the C `aDateTimeFuncs[]`. The PURE_DATE entries
// set pUserData = (void*)&sqlite3Config; DFUNCTION sets it to 0.
//
// FuncDef field map for PURE_DATE(name,nArg,0,0,xFunc):
//   { nArg, PURE_DATE_FLAGS, &sqlite3Config, 0, xFunc, 0,0,0, "name", {0} }
// For DFUNCTION(name,nArg,0,0,xFunc):
//   { nArg, DFUNCTION_FLAGS, 0, 0, xFunc, 0,0,0, "name", {0} }

fn pureDate(comptime name: [:0]const u8, nArg: i16, xFunc: XFunc) FuncDef {
    return .{
        .nArg = nArg,
        .funcFlags = PURE_DATE_FLAGS,
        .pUserData = @ptrCast(&sqlite3Config),
        .pNext = null,
        .xSFunc = @ptrCast(@constCast(xFunc)),
        .xFinalize = null,
        .xValue = null,
        .xInverse = null,
        .zName = name.ptr,
        .u = .{ .pHash = null },
    };
}

fn dFunction(comptime name: [:0]const u8, nArg: i16, xFunc: XFunc) FuncDef {
    return .{
        .nArg = nArg,
        .funcFlags = DFUNCTION_FLAGS,
        .pUserData = null,
        .pNext = null,
        .xSFunc = @ptrCast(@constCast(xFunc)),
        .xFinalize = null,
        .xValue = null,
        .xInverse = null,
        .zName = name.ptr,
        .u = .{ .pHash = null },
    };
}

// The static, mutable function table. `var` (not `const`) because
// sqlite3InsertBuiltinFuncs writes pNext / u.pHash into these entries.
var aDateTimeFuncs = blk: {
    // datedebug is present only under SQLITE_DEBUG (matches the linked C build).
    const debug = config.sqlite_debug;
    const n: usize = if (debug) 11 else 10;
    var arr: [n]FuncDef = undefined;
    var k: usize = 0;
    arr[k] = pureDate("julianday", -1, @ptrCast(&juliandayFunc));
    k += 1;
    arr[k] = pureDate("unixepoch", -1, @ptrCast(&unixepochFunc));
    k += 1;
    arr[k] = pureDate("date", -1, @ptrCast(&dateFunc));
    k += 1;
    arr[k] = pureDate("time", -1, @ptrCast(&timeFunc));
    k += 1;
    arr[k] = pureDate("datetime", -1, @ptrCast(&datetimeFunc));
    k += 1;
    arr[k] = pureDate("strftime", -1, @ptrCast(&strftimeFunc));
    k += 1;
    arr[k] = pureDate("timediff", 2, @ptrCast(&timediffFunc));
    k += 1;
    if (debug) {
        arr[k] = pureDate("datedebug", -1, @ptrCast(&datedebugFunc));
        k += 1;
    }
    arr[k] = dFunction("current_time", 0, @ptrCast(&ctimeFunc));
    k += 1;
    arr[k] = dFunction("current_timestamp", 0, @ptrCast(&ctimestampFunc));
    k += 1;
    arr[k] = dFunction("current_date", 0, @ptrCast(&cdateFunc));
    k += 1;
    break :blk arr;
};

// ─── sqlite3RegisterDateTimeFunctions — the ONLY exported symbol ─────────────
export fn sqlite3RegisterDateTimeFunctions() callconv(.c) void {
    sqlite3InsertBuiltinFuncs(&aDateTimeFuncs, @intCast(aDateTimeFuncs.len));
}
