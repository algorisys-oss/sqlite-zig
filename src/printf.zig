//! Zig port of SQLite's internal printf/xprintf engine (src/printf.c).
//!
//! This is the formatting engine used everywhere in SQLite: the StrAccum /
//! sqlite3_str_* string-builder API, the big `%`-conversion engine
//! (`sqlite3_str_vappendf`), the public/internal printf wrappers
//! (sqlite3VMPrintf / sqlite3MPrintf / sqlite3_mprintf / sqlite3_vmprintf /
//! sqlite3_snprintf / sqlite3_vsnprintf), sqlite3_log, sqlite3DebugPrintf, the
//! error-byte-offset helpers, and the RCStr reference-counted-string helpers.
//!
//! ─── Struct coupling ──────────────────────────────────────────────────────
//! * `StrAccum` (== struct sqlite3_str): config-INVARIANT; mirrored directly as
//!   an extern struct with a comptime sizeof/offset assert (same mirror as
//!   src/vdbetrace.zig). No c_layout entry needed.
//! * The compiler/parser structs the internal `%S`/`%T` converters touch —
//!   `Expr`, `SrcItem`, `Subquery`, `Select`, `Token`, plus `FpDecode` and
//!   `PrintfArguments` — were verified (tools probe, both build configs) to have
//!   IDENTICAL offsets and sizeof in the production and the `--dev` testfixture
//!   builds (Expr's `#ifdef SQLITE_DEBUG u8 vvaFlags` fits in existing padding,
//!   so `flags`/`u`/`pLeft`/`w` do not shift). They are therefore mirrored
//!   directly as extern structs with comptime sizeof asserts — NO c_layout
//!   entries needed.
//! * The `sqlite3` connection and `Parse` structs DO depend on the (many)
//!   build `-D` feature flags, so the few fields read there
//!   (`db->mallocFailed`, `db->errByteOffset`, `db->pParse`, `db->aLimit[0]`,
//!   `Parse->zTail`) are read at GROUND-TRUTH offsets via @import("c_layout.zig").
//!   New c_layout entries requested (struct tag / field):
//!       sqlite3.errByteOffset  -> c_layout.c.sqlite3_errByteOffset   (=84)
//!       sqlite3.pParse         -> c_layout.c.sqlite3_pParse          (=344)
//!       Parse.zTail            -> c_layout.c.Parse_zTail             (=336)
//!   Already present and reused: sqlite3_mallocFailed (=103), sqlite3_aLimit (=136).
//! * `sqlite3Config.xLog` / `.pLogArg` are at config-invariant offsets
//!   (376 / 384 in both builds). Read via the `extern var sqlite3Config` base,
//!   using c_layout entries if added, else literal invariant offsets (asserted
//!   below). New c_layout entries requested:
//!       Sqlite3Config.xLog     -> c_layout.c.Sqlite3Config_xLog      (=376)
//!       Sqlite3Config.pLogArg  -> c_layout.c.Sqlite3Config_pLogArg   (=384)
//!
//! ─── Config / trace gating ────────────────────────────────────────────────
//! printf.c references the trace globals `sqlite3WhereTrace`/`sqlite3TreeTrace`
//! under `WHERETRACE_ENABLED`/`TREETRACE_ENABLED`. Those macros are
//!   `SQLITE_DEBUG && (SQLITE_TEST || SQLITE_ENABLE_{WHERE,SELECT}TRACE)`.
//! The production `zig build` defines none of those (=> 0); the testfixture
//! `configure --dev` defines SQLITE_DEBUG + SQLITE_TEST (and SELECTTRACE /
//! WHERETRACE) (=> 1). In this project both flags are tied to the single
//! `-Dtestfixture` switch, so the gate is exactly `config.sqlite_debug and
//! config.sqlite_test`. When enabled, the `%p` "show pointers as zero" debug
//! hooks are compiled and the trace globals referenced.
//! sqlite3DebugPrintf itself is compiled under `SQLITE_DEBUG ||
//! SQLITE_HAVE_OS_TRACE`; gated on config.sqlite_debug here (HAVE_OS_TRACE off).
//!
//! Other flags: SQLITE_OMIT_FLOATING_POINT is OFF (FP paths included).
//! SQLITE_ENABLE_API_ARMOR is OFF (the NULL-format guards are not compiled).
//! SQLITE_PRINTF_PRECISION_LIMIT is NOT defined in either build, so the width /
//! precision clamp blocks (`#ifdef SQLITE_PRINTF_PRECISION_LIMIT`) are omitted —
//! matching C. SQLITE_FP_PRECISION_LIMIT IS in effect (100000000) because the C
//! `#ifndef SQLITE_PRINTF_PRECISION_LIMIT` defines it. SQLITE_MAX_LENGTH =
//! 1000000000 (default). SQLITE_PRINT_BUF_SIZE = 70. HAVE_STRCHRNUL is off in
//! both builds; we use the strchr-or-end path.
//!
//! ─── va_list ──────────────────────────────────────────────────────────────
//! The format engine consumes a `va_list`. The Zig functions that *receive* a
//! `va_list` from C (`sqlite3_str_vappendf`, `sqlite3VMPrintf`,
//! `sqlite3_vmprintf`, `sqlite3_vsnprintf`, `renderLogMsg`) take a
//! `*std.builtin.VaList` — NOT a by-value `VaList` — and consume it with
//! `@cVaArg(ap,T)` exactly as C `va_arg(ap,T)` did (matching C widths: int /
//! long int / i64 / unsigned int / unsigned long int / u64 / double / pointer).
//!
//! Why a pointer: on the x86-64 SysV ABI a C `va_list` is `__va_list_tag[1]`,
//! so a `va_list` *parameter* is passed as a pointer to that tag. A C caller
//! passing `ap` is therefore ABI-identical to passing `&ap` (a `*VaList`).
//! Zig, however, mis-lowers a *by-value* `VaList` parameter received across the
//! C ABI: `@cVaArg`/`@cVaCopy` on it general-protection-faults at runtime.
//! Declaring the parameter `*VaList` matches the real C ABI and works. The
//! variadic wrappers (`sqlite3MPrintf`, `sqlite3_mprintf`, `sqlite3_snprintf`,
//! `sqlite3_log`, `sqlite3DebugPrintf`, `sqlite3_str_appendf`) do `@cVaStart()`
//! into a local and forward its address (`&ap`).
//!
//! No standalone Zig unit test is feasible — the engine couples to the live
//! allocator, connection, FpDecode, and the public sqlite3_value_* API.
//! Validated through the full engine via the TCL suite (printf/format4/tkt*,
//! and every error-message-bearing test, since %S/%T/%q drive error text).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const VaList = std.builtin.VaList;

// ─── Constants ─────────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: u8 = 7;
const SQLITE_TOOBIG: u8 = 18;

const SQLITE_PRINT_BUF_SIZE: usize = 70;
const etBUFSIZE: usize = SQLITE_PRINT_BUF_SIZE;
const SQLITE_FP_PRECISION_LIMIT: c_int = 100000000;
const SQLITE_MAX_LENGTH: c_int = 1000000000;
const SQLITE_MAX_LOG_MESSAGE: usize = if (SQLITE_PRINT_BUF_SIZE * 10 > 10000) 10000 else SQLITE_PRINT_BUF_SIZE * 10;

// printfFlags (sqliteInt.h)
const SQLITE_PRINTF_INTERNAL: u8 = 0x01;
const SQLITE_PRINTF_SQLFUNC: u8 = 0x02;
const SQLITE_PRINTF_MALLOCED: u8 = 0x04;

// Conversion paradigms (et*)
const etRADIX: u8 = 0;
const etFLOAT: u8 = 1;
const etEXP: u8 = 2;
const etGENERIC: u8 = 3;
const etSIZE: u8 = 4;
const etSTRING: u8 = 5;
const etDYNSTRING: u8 = 6;
const etPERCENT: u8 = 7;
const etCHARX: u8 = 8;
const etESCAPE_q: u8 = 9;
const etESCAPE_Q: u8 = 10;
const etTOKEN: u8 = 11;
const etSRCITEM: u8 = 12;
const etPOINTER: u8 = 13;
const etESCAPE_w: u8 = 14;
const etORDINAL: u8 = 15;
const etDECIMAL: u8 = 16;
const etESCAPE_j: u8 = 17;
const etESCAPE_J: u8 = 18;
const etINVALID: u8 = 19;

// et_info.flags
const FLAG_SIGNED: u8 = 1;
const FLAG_STRING: u8 = 4;

// Expr flag bits (sqliteInt.h)
const EP_OuterON: u32 = 0x000001;
const EP_InnerON: u32 = 0x000002;
const EP_IntValue: u32 = 0x000800;
const EP_FromDDL: u32 = 0x40000000;

// SrcItem.fg bitfield bit positions (verified via probe, LE-word bit numbers).
const FG_isIndexedBy: u32 = 1 << 9;
const FG_isSubquery: u32 = 1 << 10;
const FG_isTabFunc: u32 = 1 << 11;
const FG_fixedSchema: u32 = 1 << 24;

// Select.selFlags
const SF_MultiValue: u32 = 0x0000400;
const SF_NestedFrom: u32 = 0x0000800;

// EBCDIC is not defined. SMALLEST_INT64 from sqliteInt.h.
const SMALLEST_INT64: i64 = std.math.minInt(i64);

// ─── et_info table ─────────────────────────────────────────────────────────
const et_info = extern struct {
    fmttype: u8,
    base: u8,
    flags: u8,
    type: u8,
    charset: u8,
    prefix: u8,
    iNxt: u8,
};

const aDigits = "0123456789ABCDEF0123456789abcdef";
const aHex = "0123456789abcdef";
const aPrefix = "-x0\x00X0";

const fmtinfo = [25]et_info{
    .{ .fmttype = 'd', .base = 10, .flags = 1, .type = etDECIMAL, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'e', .base = 0, .flags = 1, .type = etEXP, .charset = 30, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'f', .base = 0, .flags = 1, .type = etFLOAT, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'g', .base = 0, .flags = 1, .type = etGENERIC, .charset = 30, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'j', .base = 0, .flags = 0, .type = etESCAPE_j, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'i', .base = 10, .flags = 1, .type = etDECIMAL, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'Q', .base = 0, .flags = 4, .type = etESCAPE_Q, .charset = 0, .prefix = 0, .iNxt = 4 },
    .{ .fmttype = 'p', .base = 16, .flags = 0, .type = etPOINTER, .charset = 0, .prefix = 1, .iNxt = 0 },
    .{ .fmttype = 'S', .base = 0, .flags = 0, .type = etSRCITEM, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'T', .base = 0, .flags = 0, .type = etTOKEN, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'n', .base = 0, .flags = 0, .type = etSIZE, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'o', .base = 8, .flags = 0, .type = etRADIX, .charset = 0, .prefix = 2, .iNxt = 0 },
    .{ .fmttype = '%', .base = 0, .flags = 0, .type = etPERCENT, .charset = 0, .prefix = 0, .iNxt = 7 },
    .{ .fmttype = 'q', .base = 0, .flags = 4, .type = etESCAPE_q, .charset = 0, .prefix = 0, .iNxt = 16 },
    .{ .fmttype = 'r', .base = 10, .flags = 1, .type = etORDINAL, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 's', .base = 0, .flags = 4, .type = etSTRING, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'X', .base = 16, .flags = 0, .type = etRADIX, .charset = 0, .prefix = 4, .iNxt = 0 },
    .{ .fmttype = 'u', .base = 10, .flags = 0, .type = etDECIMAL, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'w', .base = 0, .flags = 4, .type = etESCAPE_w, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'E', .base = 0, .flags = 1, .type = etEXP, .charset = 14, .prefix = 0, .iNxt = 18 },
    .{ .fmttype = 'x', .base = 16, .flags = 0, .type = etRADIX, .charset = 16, .prefix = 1, .iNxt = 0 },
    .{ .fmttype = 'G', .base = 0, .flags = 1, .type = etGENERIC, .charset = 14, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'z', .base = 0, .flags = 4, .type = etDYNSTRING, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'J', .base = 0, .flags = 0, .type = etESCAPE_J, .charset = 0, .prefix = 0, .iNxt = 0 },
    .{ .fmttype = 'c', .base = 0, .flags = 0, .type = etCHARX, .charset = 0, .prefix = 0, .iNxt = 23 },
};

// ─── StrAccum (== struct sqlite3_str). Config-invariant; direct mirror. ─────
const StrAccum = extern struct {
    db: ?*anyopaque, // sqlite3*
    zText: ?[*]u8,
    nAlloc: c_int,
    mxAlloc: c_int,
    nChar: u32,
    accError: u8,
    printfFlags: u8,
};

comptime {
    // db(0)+zText(8)+nAlloc(16)+mxAlloc(20)+nChar(24)+accError(28)+printfFlags(29)
    std.debug.assert(@sizeOf(StrAccum) == 32);
    std.debug.assert(@offsetOf(StrAccum, "nAlloc") == 16);
    std.debug.assert(@offsetOf(StrAccum, "mxAlloc") == 20);
    std.debug.assert(@offsetOf(StrAccum, "nChar") == 24);
    std.debug.assert(@offsetOf(StrAccum, "accError") == 28);
    std.debug.assert(@offsetOf(StrAccum, "printfFlags") == 29);
}

inline fn isMalloced(p: *const StrAccum) bool {
    return (p.printfFlags & SQLITE_PRINTF_MALLOCED) != 0;
}

// ─── Config-invariant compiler/runtime struct mirrors ──────────────────────
const FpDecode = extern struct {
    n: c_int,
    iDP: c_int,
    z: ?[*]u8,
    zBuf: [21]u8, // SQLITE_U64_DIGITS+1
    sign: u8,
    isSpecial: u8,
};
comptime {
    std.debug.assert(@sizeOf(FpDecode) == 40);
    std.debug.assert(@offsetOf(FpDecode, "z") == 8);
    std.debug.assert(@offsetOf(FpDecode, "zBuf") == 16);
    std.debug.assert(@offsetOf(FpDecode, "sign") == 37);
    std.debug.assert(@offsetOf(FpDecode, "isSpecial") == 38);
}

const PrintfArguments = extern struct {
    nArg: c_int,
    nUsed: c_int,
    apArg: ?[*]?*anyopaque, // sqlite3_value**
};
comptime {
    std.debug.assert(@sizeOf(PrintfArguments) == 16);
}

const Expr = extern struct {
    op: u8,
    affExpr: u8,
    op2: u8,
    _pad0: u8, // vvaFlags slot under SQLITE_DEBUG; padding otherwise (invariant)
    flags: u32,
    u: extern union { zToken: ?[*:0]const u8, iValue: c_int },
    pLeft: ?*Expr,
    pRight: ?*anyopaque,
    x: ?*anyopaque,
    nHeight: c_int,
    iTable: c_int,
    iColumn: i16,
    iAgg: i16,
    w: extern union { iJoin: c_int, iOfst: c_int },
    pAggInfo: ?*anyopaque,
    y: extern union { pTab: ?*anyopaque, nReg: c_int, sub: extern struct { iAddr: c_int, regReturn: c_int } },
};
comptime {
    std.debug.assert(@sizeOf(Expr) == 72);
    std.debug.assert(@offsetOf(Expr, "flags") == 4);
    std.debug.assert(@offsetOf(Expr, "u") == 8);
    std.debug.assert(@offsetOf(Expr, "pLeft") == 16);
    std.debug.assert(@offsetOf(Expr, "w") == 52);
}

inline fn exprHasProperty(p: *const Expr, prop: u32) bool {
    return (p.flags & prop) != 0;
}

const Token = extern struct {
    z: ?[*]const u8,
    n: c_uint,
};
comptime {
    std.debug.assert(@sizeOf(Token) == 16);
    std.debug.assert(@offsetOf(Token, "n") == 8);
}

const Subquery = extern struct {
    pSelect: ?*Select,
    addrFillSub: c_int,
    regReturn: c_int,
    regResult: c_int,
};
comptime {
    std.debug.assert(@sizeOf(Subquery) == 24);
}

// Only the prefix fields up to selId are read; remainder is opaque tail.
const Select = extern struct {
    op: u8,
    nSelectRow: i16, // LogEst
    selFlags: u32,
    iLimit: c_int,
    iOffset: c_int,
    selId: u32,
    _tail: [100]u8, // sizeof(Select)==120; offset 20 reached above
};
comptime {
    std.debug.assert(@sizeOf(Select) == 120);
    std.debug.assert(@offsetOf(Select, "selFlags") == 4);
    std.debug.assert(@offsetOf(Select, "selId") == 16);
}

const SrcItem = extern struct {
    zName: ?[*:0]const u8,
    zAlias: ?[*:0]const u8,
    pSTab: ?*anyopaque,
    fg: u32, // bitfield struct, 4 bytes (probe-verified)
    iCursor: c_int,
    colUsed: u64,
    u1: extern union { zIndexedBy: ?[*:0]const u8, pFuncArg: ?*anyopaque, nRow: u32 },
    u2: ?*anyopaque,
    u3: ?*anyopaque,
    u4: extern union { pSchema: ?*anyopaque, zDatabase: ?[*:0]const u8, pSubq: ?*Subquery },
};
comptime {
    std.debug.assert(@sizeOf(SrcItem) == 72);
    std.debug.assert(@offsetOf(SrcItem, "fg") == 24);
    std.debug.assert(@offsetOf(SrcItem, "u1") == 40);
    std.debug.assert(@offsetOf(SrcItem, "u4") == 64);
}

inline fn fgBits(p: *const SrcItem) u32 {
    return p.fg;
}

// ─── extern C helpers (resolved at link time) ──────────────────────────────
extern var sqlite3Config: u8; // mutable global; never const

extern fn sqlite3FpDecode(p: *FpDecode, r: f64, iRound: c_int, mxRound: c_int) void;
extern fn sqlite3Strlen30(z: [*:0]const u8) c_int;
extern fn sqlite3AppendOneUtf8Character(zOut: [*]u8, v: u32) c_int;
extern fn sqlite3ErrorToParser(db: ?*anyopaque, iErr: c_int) c_int;
extern fn sqlite3_initialize() c_int;

// allocation
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbRealloc(db: ?*anyopaque, p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocSize(db: ?*anyopaque, p: ?*const anyopaque) c_int;
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;

// public value accessors
extern fn sqlite3_value_int64(v: ?*anyopaque) i64;
extern fn sqlite3_value_double(v: ?*anyopaque) f64;
extern fn sqlite3_value_text(v: ?*anyopaque) ?[*:0]const u8;

// libc
extern fn strlen(s: [*:0]const u8) usize;
extern fn strchr(s: [*:0]const u8, c: c_int) ?[*:0]const u8;
extern fn memcpy(noalias d: [*]u8, noalias s: [*]const u8, n: usize) [*]u8;
extern fn memmove(d: [*]u8, s: [*]const u8, n: usize) [*]u8;
extern fn memset(d: [*]u8, c: c_int, n: usize) [*]u8;
extern fn fprintf(stream: *anyopaque, fmt: [*:0]const u8, ...) c_int;
extern fn fflush(stream: ?*anyopaque) c_int;
extern var stdout: *anyopaque;

// ─── sqlite3 / Parse / Sqlite3Config field reads at ground-truth offsets ────
inline fn dbMallocFailed(db: ?*anyopaque) u8 {
    const base: [*]const u8 = @ptrCast(db.?);
    return base[L.sqlite3_mallocFailed];
}
inline fn dbLimitLength(db: ?*anyopaque) c_int {
    const base: [*]const u8 = @ptrCast(db.?);
    return @as(*const c_int, @ptrCast(@alignCast(base + L.sqlite3_aLimit))).*;
}
inline fn dbErrByteOffsetPtr(db: ?*anyopaque) *c_int {
    const base: [*]u8 = @ptrCast(db.?);
    return @ptrCast(@alignCast(base + sqlite3_errByteOffset_off));
}
inline fn dbPParse(db: ?*anyopaque) ?*anyopaque {
    const base: [*]const u8 = @ptrCast(db.?);
    return @as(*const ?*anyopaque, @ptrCast(@alignCast(base + sqlite3_pParse_off))).*;
}
inline fn parseZTail(pParse: ?*anyopaque) ?[*:0]const u8 {
    const base: [*]const u8 = @ptrCast(pParse.?);
    return @as(*const ?[*:0]const u8, @ptrCast(@alignCast(base + Parse_zTail_off))).*;
}

// c_layout entries requested but not yet generated are read at the
// probe-verified (config-invariant for these particular fields) offsets, with
// a comptime preference for the c_layout symbol once added.
const sqlite3_errByteOffset_off: usize = if (@hasDecl(L, "sqlite3_errByteOffset")) L.sqlite3_errByteOffset else 84;
const sqlite3_pParse_off: usize = if (@hasDecl(L, "sqlite3_pParse")) L.sqlite3_pParse else 344;
const Parse_zTail_off: usize = if (@hasDecl(L, "Parse_zTail")) L.Parse_zTail else 336;
const Sqlite3Config_xLog_off: usize = if (@hasDecl(L, "Sqlite3Config_xLog")) L.Sqlite3Config_xLog else 376;
const Sqlite3Config_pLogArg_off: usize = if (@hasDecl(L, "Sqlite3Config_pLogArg")) L.Sqlite3Config_pLogArg else 384;

const XLogFn = ?*const fn (?*anyopaque, c_int, ?[*:0]const u8) callconv(.c) void;
inline fn configXLog() XLogFn {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    return @as(*const XLogFn, @ptrCast(@alignCast(base + Sqlite3Config_xLog_off))).*;
}
inline fn configPLogArg() ?*anyopaque {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    return @as(*const ?*anyopaque, @ptrCast(@alignCast(base + Sqlite3Config_pLogArg_off))).*;
}

// ─── PrintfArguments extraction ────────────────────────────────────────────
fn getIntArg(p: *PrintfArguments) i64 {
    if (p.nArg <= p.nUsed) return 0;
    const v = sqlite3_value_int64(p.apArg.?[@intCast(p.nUsed)]);
    p.nUsed += 1;
    return v;
}
fn getDoubleArg(p: *PrintfArguments) f64 {
    if (p.nArg <= p.nUsed) return 0.0;
    const v = sqlite3_value_double(p.apArg.?[@intCast(p.nUsed)]);
    p.nUsed += 1;
    return v;
}
fn getTextArg(p: *PrintfArguments) ?[*:0]const u8 {
    if (p.nArg <= p.nUsed) return null;
    const v = sqlite3_value_text(p.apArg.?[@intCast(p.nUsed)]);
    p.nUsed += 1;
    return v;
}

// ─── StrAccumSetError ──────────────────────────────────────────────────────
export fn sqlite3StrAccumSetError(p: *StrAccum, eError: u8) callconv(.c) void {
    std.debug.assert(eError == SQLITE_NOMEM or eError == SQLITE_TOOBIG);
    p.accError = eError;
    if (p.mxAlloc != 0) sqlite3_str_reset(p);
    if (eError == SQLITE_TOOBIG) _ = sqlite3ErrorToParser(p.db, eError);
}

// printfTempBuf: allocate temp buffer; TOOBIG/NOMEM check first.
fn printfTempBuf(pAccum: *StrAccum, n: i64) ?[*]u8 {
    if (pAccum.accError != 0) return null;
    if (n > pAccum.nAlloc and n > pAccum.mxAlloc) {
        sqlite3StrAccumSetError(pAccum, SQLITE_TOOBIG);
        return null;
    }
    const z = sqlite3_malloc(@intCast(n));
    if (z == null) {
        sqlite3StrAccumSetError(pAccum, SQLITE_NOMEM);
    }
    return @ptrCast(z);
}

// ─── The format engine ─────────────────────────────────────────────────────
export fn sqlite3_str_vappendf(pAccum: *StrAccum, fmt_in: [*:0]const u8, ap: *VaList) callconv(.c) void {

    var fmt: [*:0]const u8 = fmt_in;
    var c: u8 = undefined; // next char in format
    var bufpt: [*]u8 = undefined; // pointer to conversion buffer
    var precision: c_int = undefined;
    var length: c_int = undefined;
    var idx: c_int = undefined;
    var width: c_int = undefined;
    var flag_leftjustify: u8 = undefined;
    var flag_prefix: u8 = undefined;
    var flag_alternateform: u8 = undefined;
    var flag_altform2: u8 = undefined;
    var flag_zeropad: u8 = undefined;
    var flag_long: u8 = undefined;
    var done: u8 = undefined;
    var cThousand: u8 = undefined;
    var xtype: u8 = etINVALID;
    var bArgList: u8 = undefined;
    var prefix: u8 = undefined;
    var longvalue: u64 = undefined;
    var realvalue: f64 = undefined;
    var infop: *const et_info = undefined;
    var zOut: [*]u8 = undefined;
    var nOut: c_int = undefined;
    var zExtra: ?[*]u8 = null;
    var exp: c_int = undefined;
    var e2: c_int = undefined;
    var flag_dp: u8 = undefined;
    var flag_rtz: u8 = undefined;
    var pArgList: ?*PrintfArguments = null;
    var buf: [etBUFSIZE]u8 = undefined;

    std.debug.assert(pAccum.nChar > 0 or (pAccum.printfFlags & SQLITE_PRINTF_MALLOCED) == 0);

    if ((pAccum.printfFlags & SQLITE_PRINTF_SQLFUNC) != 0) {
        pArgList = @ptrCast(@alignCast(@cVaArg(ap,?*anyopaque)));
        bArgList = 1;
    } else {
        bArgList = 0;
    }

    c = fmt[0];
    while (c != 0) : ({
        fmt += 1;
        c = fmt[0];
    }) {
        if (c != '%') {
            const start = fmt;
            // strchrnul not available: strchr-or-end
            if (strchr(fmt, '%')) |p| {
                fmt = p;
            } else {
                fmt = start + strlen(start);
            }
            sqlite3_str_append(pAccum, start, @intCast(@intFromPtr(fmt) - @intFromPtr(start)));
            if (fmt[0] == 0) break;
        }
        fmt += 1;
        c = fmt[0];
        if (c == 0) {
            sqlite3_str_append(pAccum, "%", 1);
            break;
        }
        // Find out what flags are present
        flag_leftjustify = 0;
        flag_prefix = 0;
        cThousand = 0;
        flag_alternateform = 0;
        flag_altform2 = 0;
        flag_zeropad = 0;
        done = 0;
        width = 0;
        flag_long = 0;
        precision = -1;
        while (true) {
            switch (c) {
                '-' => flag_leftjustify = 1,
                '+' => flag_prefix = '+',
                ' ' => flag_prefix = ' ',
                '#' => flag_alternateform = 1,
                '!' => flag_altform2 = 1,
                '0' => flag_zeropad = 1,
                ',' => cThousand = ',',
                'l' => {
                    flag_long = 1;
                    fmt += 1;
                    c = fmt[0];
                    if (c == 'l') {
                        fmt += 1;
                        c = fmt[0];
                        flag_long = 2;
                    }
                    done = 1;
                },
                '1', '2', '3', '4', '5', '6', '7', '8', '9' => {
                    var wx: u32 = @as(u32, c) - '0';
                    fmt += 1;
                    c = fmt[0];
                    while (c >= '0' and c <= '9') {
                        wx = wx *% 10 +% (@as(u32, c) - '0');
                        fmt += 1;
                        c = fmt[0];
                    }
                    width = @intCast(wx & 0x7fffffff);
                    // SQLITE_PRINTF_PRECISION_LIMIT not defined.
                    if (c != '.' and c != 'l') {
                        done = 1;
                    } else {
                        fmt -= 1;
                    }
                },
                '*' => {
                    if (bArgList != 0) {
                        width = @intCast(getIntArg(pArgList.?));
                    } else {
                        width = @cVaArg(ap,c_int);
                    }
                    if (width < 0) {
                        flag_leftjustify = 1;
                        width = if (width >= -2147483647) -width else 0;
                    }
                    if (fmt[1] != '.' and fmt[1] != 'l') {
                        fmt += 1;
                        c = fmt[0];
                        done = 1;
                    } else {
                        c = fmt[1];
                    }
                },
                '.' => {
                    fmt += 1;
                    c = fmt[0];
                    if (c == '*') {
                        if (bArgList != 0) {
                            precision = @intCast(getIntArg(pArgList.?));
                        } else {
                            precision = @cVaArg(ap,c_int);
                        }
                        if (precision < 0) {
                            precision = if (precision >= -2147483647) -precision else -1;
                        }
                        fmt += 1;
                        c = fmt[0];
                    } else {
                        var px: u32 = 0;
                        while (c >= '0' and c <= '9') {
                            px = px *% 10 +% (@as(u32, c) - '0');
                            fmt += 1;
                            c = fmt[0];
                        }
                        precision = @intCast(px & 0x7fffffff);
                    }
                    if (c == 'l') {
                        fmt -= 1;
                    } else {
                        done = 1;
                    }
                },
                else => done = 1,
            }
            if (done != 0) break;
            fmt += 1;
            c = fmt[0];
            if (c == 0) break;
        }

        // Fetch the info entry for the field (fast hash; EBCDIC off).
        const hidx: usize = @as(usize, c) % 25;
        if (fmtinfo[hidx].fmttype == c) {
            infop = &fmtinfo[hidx];
            xtype = infop.type;
        } else if (fmtinfo[fmtinfo[hidx].iNxt].fmttype == c) {
            infop = &fmtinfo[fmtinfo[hidx].iNxt];
            xtype = infop.type;
        } else {
            infop = &fmtinfo[0];
            xtype = etINVALID;
        }

        std.debug.assert(width >= 0);
        std.debug.assert(precision >= -1);

        // The big switch over conversion type.
        sw: switch (xtype) {
            etPOINTER => {
                flag_long = if (@sizeOf(*anyopaque) == @sizeOf(i64)) 2 else if (@sizeOf(*anyopaque) == @sizeOf(c_long)) 1 else 0;
                continue :sw etORDINAL;
            },
            etORDINAL, etRADIX => {
                cThousand = 0;
                continue :sw etDECIMAL;
            },
            etDECIMAL => {
                if (infop.flags & FLAG_SIGNED != 0) {
                    var v: i64 = undefined;
                    if (bArgList != 0) {
                        v = getIntArg(pArgList.?);
                    } else if (flag_long != 0) {
                        if (flag_long == 2) {
                            v = @cVaArg(ap,i64);
                        } else {
                            v = @cVaArg(ap,c_long);
                        }
                    } else {
                        v = @cVaArg(ap,c_int);
                    }
                    if (v < 0) {
                        longvalue = ~@as(u64, @bitCast(v));
                        longvalue +%= 1;
                        prefix = '-';
                    } else {
                        longvalue = @bitCast(v);
                        prefix = flag_prefix;
                    }
                } else {
                    if (bArgList != 0) {
                        longvalue = @bitCast(getIntArg(pArgList.?));
                    } else if (flag_long != 0) {
                        if (flag_long == 2) {
                            longvalue = @cVaArg(ap,u64);
                        } else {
                            longvalue = @cVaArg(ap,c_ulong);
                        }
                    } else {
                        longvalue = @cVaArg(ap,c_uint);
                    }
                    prefix = 0;
                }

                if (whereTraceEnabled or treeTraceEnabled) {
                    if (xtype == etPOINTER and pointerShownAsZero()) longvalue = 0;
                }

                if (longvalue == 0) flag_alternateform = 0;
                if (flag_zeropad != 0 and precision < width - @as(c_int, @intFromBool(prefix != 0))) {
                    precision = width - @as(c_int, @intFromBool(prefix != 0));
                }
                if (precision < @as(c_int, @intCast(etBUFSIZE - 10 - etBUFSIZE / 3))) {
                    nOut = @intCast(etBUFSIZE);
                    zOut = &buf;
                } else {
                    var n: u64 = @as(u64, @intCast(precision)) + 10;
                    if (cThousand != 0) n += @intCast(@divTrunc(precision, 3));
                    const tmp = printfTempBuf(pAccum, @intCast(n));
                    if (tmp == null) return;
                    zExtra = tmp;
                    zOut = tmp.?;
                    nOut = @intCast(n);
                }
                bufpt = zOut + @as(usize, @intCast(nOut - 1));
                if (xtype == etORDINAL) {
                    const zOrd = "thstndrd";
                    var x: usize = @intCast(longvalue % 10);
                    if (x >= 4 or (longvalue / 10) % 10 == 1) x = 0;
                    bufpt -= 1;
                    bufpt[0] = zOrd[x * 2 + 1];
                    bufpt -= 1;
                    bufpt[0] = zOrd[x * 2];
                }
                {
                    const cset: [*]const u8 = aDigits[infop.charset..].ptr;
                    const base: u64 = infop.base;
                    while (true) {
                        bufpt -= 1;
                        bufpt[0] = cset[@intCast(longvalue % base)];
                        longvalue = longvalue / base;
                        if (longvalue == 0) break;
                    }
                }
                length = @intCast(@intFromPtr(zOut + @as(usize, @intCast(nOut - 1))) - @intFromPtr(bufpt));
                if (precision > length) { // zero pad
                    const nn: usize = @intCast(precision - length);
                    bufpt -= nn;
                    _ = memset(bufpt, '0', nn);
                    length = precision;
                }
                if (cThousand != 0) {
                    var nn: c_int = @divTrunc(length - 1, 3);
                    var ix: c_int = @rem(length - 1, 3) + 1;
                    bufpt -= @as(usize, @intCast(nn));
                    idx = 0;
                    while (nn > 0) : (idx += 1) {
                        bufpt[@intCast(idx)] = bufpt[@intCast(idx + nn)];
                        ix -= 1;
                        if (ix == 0) {
                            idx += 1;
                            bufpt[@intCast(idx)] = cThousand;
                            nn -= 1;
                            ix = 3;
                        }
                    }
                }
                if (prefix != 0) {
                    bufpt -= 1;
                    bufpt[0] = prefix;
                }
                if (flag_alternateform != 0 and infop.prefix != 0) { // "0" or "0x"
                    var pre: [*]const u8 = aPrefix[infop.prefix..].ptr;
                    while (pre[0] != 0) : (pre += 1) {
                        bufpt -= 1;
                        bufpt[0] = pre[0];
                    }
                }
                length = @intCast(@intFromPtr(zOut + @as(usize, @intCast(nOut - 1))) - @intFromPtr(bufpt));
            },
            etFLOAT, etEXP, etGENERIC => {
                var s: FpDecode = undefined;
                var iRound: c_int = undefined;
                var j: c_int = undefined;
                var szBufNeeded: i64 = undefined;

                if (bArgList != 0) {
                    realvalue = getDoubleArg(pArgList.?);
                } else {
                    realvalue = @cVaArg(ap,f64);
                }
                if (precision < 0) precision = 6;
                if (precision > SQLITE_FP_PRECISION_LIMIT) precision = SQLITE_FP_PRECISION_LIMIT;
                if (xtype == etFLOAT) {
                    iRound = -precision;
                } else if (xtype == etGENERIC) {
                    if (precision == 0) precision = 1;
                    iRound = precision;
                } else {
                    iRound = precision + 1;
                }
                sqlite3FpDecode(&s, realvalue, iRound, if (flag_altform2 != 0) 20 else 16);
                if (s.isSpecial != 0) {
                    if (s.isSpecial == 2) {
                        const lit: [*:0]const u8 = if (flag_zeropad != 0) "null" else "NaN";
                        bufpt = @constCast(lit);
                        length = sqlite3Strlen30(lit);
                        break :sw;
                    } else if (flag_zeropad != 0) {
                        s.z.?[0] = '9';
                        s.iDP = 1000;
                        s.n = 1;
                    } else {
                        _ = memcpy(&buf, "-Inf", 5);
                        bufpt = &buf;
                        if (s.sign == '-') {
                            // no-op
                        } else if (flag_prefix != 0) {
                            buf[0] = flag_prefix;
                        } else {
                            bufpt += 1;
                        }
                        length = sqlite3Strlen30(@ptrCast(bufpt));
                        break :sw;
                    }
                }
                if (s.sign == '-') {
                    if (flag_alternateform != 0 and flag_prefix == 0 and xtype == etFLOAT and s.iDP <= iRound) {
                        prefix = 0;
                    } else {
                        prefix = '-';
                    }
                } else {
                    prefix = flag_prefix;
                }

                exp = s.iDP - 1;

                if (xtype == etGENERIC) {
                    std.debug.assert(precision > 0);
                    precision -= 1;
                    flag_rtz = @intFromBool(flag_alternateform == 0);
                    if (exp < -4 or exp > precision) {
                        xtype = etEXP;
                    } else {
                        precision = precision - exp;
                        xtype = etFLOAT;
                    }
                } else {
                    flag_rtz = flag_altform2;
                }
                if (xtype == etEXP) {
                    e2 = 0;
                } else {
                    e2 = s.iDP - 1;
                }

                szBufNeeded = @as(i64, @max(e2, 0)) + @as(i64, precision) + @as(i64, width) + 10;
                if (cThousand != 0 and e2 > 0) szBufNeeded += @divTrunc(e2 + 2, 3);
                if (szBufNeeded + @as(i64, pAccum.nChar) >= pAccum.nAlloc) {
                    if (pAccum.mxAlloc == 0 and pAccum.accError == 0) {
                        const b = sqlite3_malloc(@intCast(szBufNeeded));
                        if (b == null) {
                            sqlite3StrAccumSetError(pAccum, SQLITE_NOMEM);
                            return;
                        }
                        bufpt = @ptrCast(b);
                        zExtra = bufpt;
                    } else if (sqlite3StrAccumEnlarge(pAccum, szBufNeeded) < szBufNeeded) {
                        width = 0;
                        length = 0;
                        break :sw;
                    } else {
                        bufpt = pAccum.zText.? + pAccum.nChar;
                    }
                } else {
                    bufpt = pAccum.zText.? + pAccum.nChar;
                }
                zOut = bufpt;

                flag_dp = (if (precision > 0) @as(u8, 1) else 0) | flag_alternateform | flag_altform2;
                if (prefix != 0) {
                    bufpt[0] = prefix;
                    bufpt += 1;
                }
                j = 0;
                std.debug.assert(s.n > 0);
                if (e2 < 0) {
                    bufpt[0] = '0';
                    bufpt += 1;
                } else if (cThousand != 0) {
                    while (e2 >= 0) : (e2 -= 1) {
                        bufpt[0] = if (j < s.n) blk: {
                            const ch = s.z.?[@intCast(j)];
                            j += 1;
                            break :blk ch;
                        } else '0';
                        bufpt += 1;
                        if (@rem(e2, 3) == 0 and e2 > 1) {
                            bufpt[0] = ',';
                            bufpt += 1;
                        }
                    }
                } else {
                    j = e2 + 1;
                    if (j > s.n) j = s.n;
                    _ = memcpy(bufpt, s.z.?, @intCast(j));
                    bufpt += @intCast(j);
                    e2 -= j;
                    if (e2 >= 0) {
                        _ = memset(bufpt, '0', @intCast(e2 + 1));
                        bufpt += @intCast(e2 + 1);
                        e2 = -1;
                    }
                }
                if (flag_dp != 0) {
                    bufpt[0] = '.';
                    bufpt += 1;
                }
                if (e2 < -1 and precision > 0) {
                    var nn: c_int = -1 - e2;
                    if (nn > precision) nn = precision;
                    _ = memset(bufpt, '0', @intCast(nn));
                    bufpt += @intCast(nn);
                    precision -= nn;
                }
                if (precision > 0) {
                    const nn: c_int = s.n - j;
                    // NEVER(nn>precision)
                    if (nn > 0) {
                        _ = memcpy(bufpt, s.z.? + @as(usize, @intCast(j)), @intCast(nn));
                        bufpt += @intCast(nn);
                        precision -= nn;
                    }
                    if (precision > 0 and flag_rtz == 0) {
                        _ = memset(bufpt, '0', @intCast(precision));
                        bufpt += @intCast(precision);
                    }
                }
                if (flag_rtz != 0 and flag_dp != 0) {
                    while ((bufpt - 1)[0] == '0') {
                        bufpt -= 1;
                        bufpt[0] = 0;
                    }
                    std.debug.assert(@intFromPtr(bufpt) > @intFromPtr(zOut));
                    if ((bufpt - 1)[0] == '.') {
                        if (flag_altform2 != 0) {
                            bufpt[0] = '0';
                            bufpt += 1;
                        } else {
                            bufpt -= 1;
                            bufpt[0] = 0;
                        }
                    }
                }
                if (xtype == etEXP) {
                    exp = s.iDP - 1;
                    bufpt[0] = aDigits[infop.charset];
                    bufpt += 1;
                    if (exp < 0) {
                        bufpt[0] = '-';
                        bufpt += 1;
                        exp = -exp;
                    } else {
                        bufpt[0] = '+';
                        bufpt += 1;
                    }
                    if (exp >= 100) {
                        bufpt[0] = @intCast(@divTrunc(exp, 100) + '0');
                        bufpt += 1;
                        exp = @rem(exp, 100);
                    }
                    bufpt[0] = @intCast(@divTrunc(exp, 10) + '0');
                    bufpt += 1;
                    bufpt[0] = @intCast(@rem(exp, 10) + '0');
                    bufpt += 1;
                }

                length = @intCast(@intFromPtr(bufpt) - @intFromPtr(zOut));
                std.debug.assert(length <= szBufNeeded);
                if (length < width) {
                    const nPad: usize = @intCast(width - length);
                    if (flag_leftjustify != 0) {
                        _ = memset(bufpt, ' ', nPad);
                    } else if (flag_zeropad == 0) {
                        _ = memmove(zOut + nPad, zOut, @intCast(length));
                        _ = memset(zOut, ' ', nPad);
                    } else {
                        const adj: usize = @intFromBool(prefix != 0);
                        _ = memmove(zOut + nPad + adj, zOut + adj, @intCast(length - @as(c_int, @intCast(adj))));
                        _ = memset(zOut + adj, '0', nPad);
                    }
                    length = width;
                }

                if (zExtra == null) {
                    pAccum.nChar += @intCast(length);
                    zOut[@intCast(length)] = 0;
                    continue;
                } else {
                    bufpt[0] = 0;
                    bufpt = zExtra.?;
                    break :sw;
                }
            },
            etSIZE => {
                if (bArgList == 0) {
                    const pn = @cVaArg(ap,*c_int);
                    pn.* = @intCast(pAccum.nChar);
                }
                length = 0;
                width = 0;
            },
            etPERCENT => {
                buf[0] = '%';
                bufpt = &buf;
                length = 1;
            },
            etCHARX => {
                if (bArgList != 0) {
                    const t = getTextArg(pArgList.?);
                    length = 1;
                    if (t) |tp| {
                        var bp: [*]const u8 = @ptrCast(tp);
                        c = bp[0];
                        bp += 1;
                        buf[0] = c;
                        if ((c & 0xc0) == 0xc0) {
                            while (length < 4 and (bp[0] & 0xc0) == 0x80) {
                                buf[@intCast(length)] = bp[0];
                                bp += 1;
                                length += 1;
                            }
                        }
                    } else {
                        buf[0] = 0;
                    }
                } else {
                    const ch = @cVaArg(ap,c_uint);
                    length = sqlite3AppendOneUtf8Character(&buf, ch);
                }
                if (precision > 1) {
                    var nPrior: i64 = 1;
                    width -= precision - 1;
                    if (width > 1 and flag_leftjustify == 0) {
                        sqlite3_str_appendchar(pAccum, width - 1, ' ');
                        width = 0;
                    }
                    sqlite3_str_append(pAccum, &buf, length);
                    precision -= 1;
                    while (precision > 1) {
                        if (nPrior > precision - 1) nPrior = precision - 1;
                        const nCopyBytes: i64 = @as(i64, length) * nPrior;
                        if (sqlite3StrAccumEnlargeIfNeeded(pAccum, nCopyBytes) != 0) break;
                        sqlite3_str_append(pAccum, pAccum.zText.? + (pAccum.nChar - @as(u32, @intCast(nCopyBytes))), @intCast(nCopyBytes));
                        precision -= @intCast(nPrior);
                        nPrior *= 2;
                    }
                }
                bufpt = &buf;
                flag_altform2 = 1;
                // goto adjust_width_for_utf8
                if (flag_altform2 != 0 and width > 0) {
                    var ii: c_int = length - 1;
                    while (ii >= 0) {
                        if ((bufpt[@intCast(ii)] & 0xc0) == 0x80) width += 1;
                        ii -= 1;
                    }
                }
                width -= length;
                if (width > 0) {
                    if (flag_leftjustify == 0) sqlite3_str_appendchar(pAccum, width, ' ');
                    sqlite3_str_append(pAccum, bufpt, length);
                    if (flag_leftjustify != 0) sqlite3_str_appendchar(pAccum, width, ' ');
                } else {
                    sqlite3_str_append(pAccum, bufpt, length);
                }
                if (zExtra) |ze| {
                    sqlite3DbFree(pAccum.db, ze);
                    zExtra = null;
                }
                continue;
            },
            etSTRING, etDYNSTRING => {
                var sbufpt: [*:0]const u8 = undefined;
                var bufpt_null = false;
                if (bArgList != 0) {
                    if (getTextArg(pArgList.?)) |a| sbufpt = a else bufpt_null = true;
                    xtype = etSTRING;
                } else {
                    if (@cVaArg(ap, ?[*:0]const u8)) |a| sbufpt = a else bufpt_null = true;
                }
                var did_break = false;
                if (bufpt_null) {
                    // Upstream: NULL arg → "" and skip the %z adoption path.
                    sbufpt = "";
                } else if (xtype == etDYNSTRING) {
                    if (pAccum.nChar == 0 and pAccum.mxAlloc != 0 and width == 0 and precision < 0 and pAccum.accError == 0) {
                        std.debug.assert((pAccum.printfFlags & SQLITE_PRINTF_MALLOCED) == 0);
                        pAccum.zText = @constCast(sbufpt);
                        pAccum.nAlloc = sqlite3DbMallocSize(pAccum.db, sbufpt);
                        pAccum.nChar = 0x7fffffff & @as(u32, @intCast(strlen(sbufpt)));
                        pAccum.printfFlags |= SQLITE_PRINTF_MALLOCED;
                        length = 0;
                        did_break = true;
                    } else {
                        zExtra = @constCast(sbufpt);
                    }
                }
                if (!did_break) {
                    if (precision >= 0) {
                        if (flag_altform2 != 0) {
                            var z: [*]const u8 = @ptrCast(sbufpt);
                            while (precision > 0 and z[0] != 0) {
                                precision -= 1;
                                // SQLITE_SKIP_UTF8
                                const first = z[0];
                                z += 1;
                                if (first >= 0xc0) {
                                    while ((z[0] & 0xc0) == 0x80) z += 1;
                                }
                            }
                            const dist: i64 = @intCast(@intFromPtr(z) - @intFromPtr(sbufpt));
                            length = @intCast(@min(dist, 0x7ffffff0));
                        } else {
                            length = 0;
                            while (length < precision and sbufpt[@intCast(length)] != 0) length += 1;
                        }
                    } else {
                        length = 0x7fffffff & @as(c_int, @intCast(strlen(sbufpt)));
                    }
                    bufpt = @constCast(sbufpt);
                    // adjust_width_for_utf8
                    if (flag_altform2 != 0 and width > 0) {
                        var ii: c_int = length - 1;
                        while (ii >= 0) {
                            if ((bufpt[@intCast(ii)] & 0xc0) == 0x80) width += 1;
                            ii -= 1;
                        }
                    }
                } else {
                    bufpt = @constCast(sbufpt);
                }
                // fall through to common output
                width -= length;
                if (width > 0) {
                    if (flag_leftjustify == 0) sqlite3_str_appendchar(pAccum, width, ' ');
                    sqlite3_str_append(pAccum, bufpt, length);
                    if (flag_leftjustify != 0) sqlite3_str_appendchar(pAccum, width, ' ');
                } else {
                    sqlite3_str_append(pAccum, bufpt, length);
                }
                if (zExtra) |ze| {
                    sqlite3DbFree(pAccum.db, ze);
                    zExtra = null;
                }
                continue;
            },
            etESCAPE_j, etESCAPE_J => {
                renderJson(pAccum, ap, pArgList, bArgList, xtype, precision, width, flag_altform2, flag_leftjustify);
                continue;
            },
            etESCAPE_q, etESCAPE_Q, etESCAPE_w => {
                // %q / %Q / %w
                const escarg_opt: ?[*:0]const u8 = if (bArgList != 0)
                    getTextArg(pArgList.?)
                else
                    @cVaArg(ap,?[*:0]const u8);
                var needQuote: c_int = 0;
                var escarg: [*:0]const u8 = undefined;
                if (escarg_opt == null) {
                    escarg = if (xtype == etESCAPE_Q) "NULL" else "(NULL)";
                } else {
                    escarg = escarg_opt.?;
                    if (xtype == etESCAPE_Q) needQuote = 1;
                }
                var q: u8 = undefined;
                if (xtype == etESCAPE_w) {
                    q = '"';
                    flag_alternateform = 0;
                } else {
                    q = '\'';
                }
                var i: i64 = 0;
                var n: i64 = 0;
                var k: i64 = precision;
                {
                    i = 0;
                    n = 0;
                    var ch: u8 = undefined;
                    while (k != 0 and escarg[@intCast(i)] != 0) : ({
                        i += 1;
                        k -= 1;
                    }) {
                        ch = escarg[@intCast(i)];
                        if (ch == q) n += 1;
                        if (flag_altform2 != 0 and (ch & 0xc0) == 0xc0) {
                            while ((escarg[@intCast(i + 1)] & 0xc0) == 0x80) i += 1;
                        }
                    }
                }
                if (flag_alternateform != 0) {
                    var nBack: i64 = 0;
                    var nCtrl: i64 = 0;
                    k = 0;
                    while (k < i) : (k += 1) {
                        if (escarg[@intCast(k)] == '\\') {
                            nBack += 1;
                        } else if (escarg[@intCast(k)] <= 0x1f) {
                            nCtrl += 1;
                        }
                    }
                    if (nCtrl != 0 or xtype == etESCAPE_q) {
                        n += nBack + 5 * nCtrl;
                        if (xtype == etESCAPE_Q) {
                            n += 10;
                            needQuote = 2;
                        }
                    } else {
                        flag_alternateform = 0;
                    }
                }
                n += i + 3;
                if (n > etBUFSIZE) {
                    const tmp = printfTempBuf(pAccum, n);
                    if (tmp == null) return;
                    zExtra = tmp;
                    bufpt = tmp.?;
                } else {
                    bufpt = &buf;
                }
                var j: i64 = 0;
                if (needQuote != 0) {
                    if (needQuote == 2) {
                        _ = memcpy(bufpt + @as(usize, @intCast(j)), "unistr('", 8);
                        j += 8;
                    } else {
                        bufpt[@intCast(j)] = '\'';
                        j += 1;
                    }
                }
                k = i;
                if (flag_alternateform != 0) {
                    i = 0;
                    while (i < k) : (i += 1) {
                        const ch = escarg[@intCast(i)];
                        bufpt[@intCast(j)] = ch;
                        j += 1;
                        if (ch == q) {
                            bufpt[@intCast(j)] = ch;
                            j += 1;
                        } else if (ch == '\\') {
                            bufpt[@intCast(j)] = '\\';
                            j += 1;
                        } else if (ch <= 0x1f) {
                            bufpt[@intCast(j - 1)] = '\\';
                            bufpt[@intCast(j)] = 'u';
                            j += 1;
                            bufpt[@intCast(j)] = '0';
                            j += 1;
                            bufpt[@intCast(j)] = '0';
                            j += 1;
                            bufpt[@intCast(j)] = if (ch >= 0x10) '1' else '0';
                            j += 1;
                            bufpt[@intCast(j)] = aHex[ch & 0xf];
                            j += 1;
                        }
                    }
                } else {
                    i = 0;
                    while (i < k) : (i += 1) {
                        const ch = escarg[@intCast(i)];
                        bufpt[@intCast(j)] = ch;
                        j += 1;
                        if (ch == q) {
                            bufpt[@intCast(j)] = ch;
                            j += 1;
                        }
                    }
                }
                if (needQuote != 0) {
                    bufpt[@intCast(j)] = '\'';
                    j += 1;
                    if (needQuote == 2) {
                        bufpt[@intCast(j)] = ')';
                        j += 1;
                    }
                }
                bufpt[@intCast(j)] = 0;
                length = @intCast(j);
                // adjust_width_for_utf8
                if (flag_altform2 != 0 and width > 0) {
                    var ii: c_int = length - 1;
                    while (ii >= 0) {
                        if ((bufpt[@intCast(ii)] & 0xc0) == 0x80) width += 1;
                        ii -= 1;
                    }
                }
                width -= length;
                if (width > 0) {
                    if (flag_leftjustify == 0) sqlite3_str_appendchar(pAccum, width, ' ');
                    sqlite3_str_append(pAccum, bufpt, length);
                    if (flag_leftjustify != 0) sqlite3_str_appendchar(pAccum, width, ' ');
                } else {
                    sqlite3_str_append(pAccum, bufpt, length);
                }
                if (zExtra) |ze| {
                    sqlite3DbFree(pAccum.db, ze);
                    zExtra = null;
                }
                continue;
            },
            etTOKEN => {
                if ((pAccum.printfFlags & SQLITE_PRINTF_INTERNAL) == 0) return;
                if (flag_alternateform != 0) {
                    const pExpr = @cVaArg(ap,?*Expr);
                    if (pExpr) |e| {
                        if (!exprHasProperty(e, EP_IntValue)) {
                            sqlite3_str_appendall(pAccum, @ptrCast(e.u.zToken.?));
                            sqlite3RecordErrorOffsetOfExpr(pAccum.db, e);
                        }
                    }
                } else {
                    const pToken = @cVaArg(ap,?*Token);
                    std.debug.assert(bArgList == 0);
                    if (pToken) |tk| {
                        if (tk.n != 0) {
                            sqlite3_str_append(pAccum, tk.z.?, @intCast(tk.n));
                            sqlite3RecordErrorByteOffset(pAccum.db, @ptrCast(tk.z.?));
                        }
                    }
                }
                length = 0;
                width = 0;
            },
            etSRCITEM => {
                if ((pAccum.printfFlags & SQLITE_PRINTF_INTERNAL) == 0) return;
                const pItem = @cVaArg(ap,*SrcItem);
                std.debug.assert(bArgList == 0);
                const fg = fgBits(pItem);
                if (pItem.zAlias != null and flag_altform2 == 0) {
                    sqlite3_str_appendall(pAccum, pItem.zAlias.?);
                } else if (pItem.zName) |zName| {
                    if ((fg & FG_fixedSchema) == 0 and (fg & FG_isSubquery) == 0 and pItem.u4.zDatabase != null) {
                        sqlite3_str_appendall(pAccum, pItem.u4.zDatabase.?);
                        sqlite3_str_append(pAccum, ".", 1);
                    }
                    sqlite3_str_appendall(pAccum, zName);
                } else if (pItem.zAlias) |zAlias| {
                    sqlite3_str_appendall(pAccum, zAlias);
                } else {
                    // ALWAYS(pItem->fg.isSubquery)
                    const pSel = pItem.u4.pSubq.?.pSelect.?;
                    if (pSel.selFlags & SF_NestedFrom != 0) {
                        sqlite3_str_appendf(pAccum, "(join-%u)", pSel.selId);
                    } else if (pSel.selFlags & SF_MultiValue != 0) {
                        sqlite3_str_appendf(pAccum, "%u-ROW VALUES CLAUSE", pItem.u1.nRow);
                    } else {
                        sqlite3_str_appendf(pAccum, "(subquery-%u)", pSel.selId);
                    }
                }
                length = 0;
                width = 0;
            },
            else => {
                std.debug.assert(xtype == etINVALID);
                return;
            },
        }

        // Common output (reached by the cases that fall through with bufpt/length/width).
        width -= length;
        if (width > 0) {
            if (flag_leftjustify == 0) sqlite3_str_appendchar(pAccum, width, ' ');
            sqlite3_str_append(pAccum, bufpt, length);
            if (flag_leftjustify != 0) sqlite3_str_appendchar(pAccum, width, ' ');
        } else {
            sqlite3_str_append(pAccum, bufpt, length);
        }

        if (zExtra) |ze| {
            sqlite3DbFree(pAccum.db, ze);
            zExtra = null;
        }
    }
}

// ─── %j / %J JSON rendering (separated to keep the giant switch readable) ───
fn renderJson(
    pAccum: *StrAccum,
    ap: *VaList,
    pArgList: ?*PrintfArguments,
    bArgList: u8,
    xtype: u8,
    precision: c_int,
    width: c_int,
    flag_altform2: u8,
    flag_leftjustify: u8,
) callconv(.c) void {
    var escarg: ?[*:0]const u8 = undefined;
    if (bArgList != 0) {
        escarg = getTextArg(pArgList.?);
    } else {
        escarg = @cVaArg(ap, ?[*:0]const u8);
    }
    const iStart: i64 = sqlite3_str_length(pAccum);
    if (escarg == null) {
        if (xtype == etESCAPE_J) sqlite3_str_append(pAccum, "null", 4);
    } else {
        const ea = escarg.?;
        if (xtype == etESCAPE_J) sqlite3_str_append(pAccum, "\"", 1);
        var px: i64 = precision;
        if (px < 0) {
            px = 0x7fffffff;
        } else if (flag_altform2 != 0) {
            var i: i64 = 0;
            while (i < px and ea[@intCast(i)] != 0) : (i += 1) {
                if ((ea[@intCast(i)] & 0xc0) == 0x80) px += 1;
            }
            if (i == px) {
                while ((ea[@intCast(px)] & 0xc0) == 0x80) px += 1;
            }
        }
        var i: i64 = 0;
        var j: i64 = 0;
        while (i < px) : (i += 1) {
            const ch: u8 = ea[@intCast(i)];
            if (ch <= 0x1f or ch == '"' or ch == '\\') {
                if (j < i) sqlite3_str_append(pAccum, ea + @as(usize, @intCast(j)), @intCast(i - j));
                j = i + 1;
                if (ch == 0) break;
                sqlite3_str_appendchar(pAccum, 1, '\\');
                if (ch > 0x1f) {
                    sqlite3_str_appendchar(pAccum, 1, ch);
                } else if (((@as(u32, 1) << @intCast(ch)) & 0x3700) != 0) {
                    const m = "btn?fr";
                    sqlite3_str_appendchar(pAccum, 1, m[@intCast(ch - 8)]);
                } else {
                    sqlite3_str_append(pAccum, "u00", 3);
                    sqlite3_str_appendchar(pAccum, 1, aHex[ch >> 4]);
                    sqlite3_str_appendchar(pAccum, 1, aHex[ch & 0xf]);
                }
            }
        }
        if (j < i) sqlite3_str_append(pAccum, ea + @as(usize, @intCast(j)), @intCast(i - j));
        if (xtype == etESCAPE_J) sqlite3_str_append(pAccum, "\"", 1);
    }
    if (width > 0 and sqlite3_str_errcode(pAccum) == SQLITE_OK) {
        const n: i64 = sqlite3_str_length(pAccum) - iStart;
        var len: i64 = n;
        if (flag_altform2 != 0 and n > 0) {
            const zz = sqlite3_str_value(pAccum).?;
            var i: i64 = iStart;
            while (zz[@intCast(i)] != 0) : (i += 1) {
                if ((zz[@intCast(i)] & 0xc0) == 0x80) len -= 1;
            }
        }
        if (width > len) {
            const sp: i64 = width - len;
            std.debug.assert(sp > 0 and sp < 0x7fffffff);
            sqlite3_str_appendchar(pAccum, @intCast(sp), ' ');
            if (flag_leftjustify == 0 and n > 0 and sqlite3_str_errcode(pAccum) == 0) {
                var zz = sqlite3_str_value(pAccum).?;
                zz += @intCast(iStart);
                _ = memmove(zz + @as(usize, @intCast(sp)), zz, @intCast(n));
                _ = memset(zz, ' ', @intCast(sp));
            }
        }
    }
}

// ─── Trace gating ──────────────────────────────────────────────────────────
// WHERETRACE_ENABLED / TREETRACE_ENABLED == SQLITE_DEBUG && (SQLITE_TEST || ...).
const whereTraceEnabled = config.sqlite_debug and config.sqlite_test;
const treeTraceEnabled = config.sqlite_debug and config.sqlite_test;

extern var sqlite3WhereTrace: u32;
extern var sqlite3TreeTrace: u32;

inline fn pointerShownAsZero() bool {
    if (!whereTraceEnabled and !treeTraceEnabled) return false;
    var r = false;
    if (whereTraceEnabled) r = r or (sqlite3WhereTrace & 0x100000) != 0;
    if (treeTraceEnabled) r = r or (sqlite3TreeTrace & 0x100000) != 0;
    return r;
}

// ─── Error-offset helpers ──────────────────────────────────────────────────
export fn sqlite3RecordErrorByteOffset(db: ?*anyopaque, z: [*:0]const u8) callconv(.c) void {
    if (db == null) return; // NEVER(db==0)
    const pOff = dbErrByteOffsetPtr(db);
    if (pOff.* != -2) return;
    const pParse = dbPParse(db);
    if (pParse == null) return; // NEVER(pParse==0)
    const zText = parseZTail(pParse);
    if (zText == null) return; // NEVER(zText==0)
    const zt = zText.?;
    const zEnd = zt + strlen(zt);
    const zp = @intFromPtr(z);
    if (zp >= @intFromPtr(zt) and zp < @intFromPtr(zEnd)) {
        pOff.* = @intCast(@intFromPtr(z) - @intFromPtr(zt));
    }
}

export fn sqlite3RecordErrorOffsetOfExpr(db: ?*anyopaque, pExpr_in: ?*const Expr) callconv(.c) void {
    var pExpr = pExpr_in;
    while (pExpr) |e| {
        if (exprHasProperty(e, EP_OuterON | EP_InnerON) or e.w.iOfst <= 0) {
            pExpr = e.pLeft;
        } else break;
    }
    const e = pExpr orelse return;
    if (exprHasProperty(e, EP_FromDDL)) return;
    const pOff = dbErrByteOffsetPtr(db);
    pOff.* = e.w.iOfst;
}

// ─── StrAccum enlarge / append ─────────────────────────────────────────────
export fn sqlite3StrAccumEnlarge(p: *StrAccum, N: i64) callconv(.c) c_int {
    std.debug.assert(@as(i64, p.nChar) + N >= p.nAlloc);
    if (p.accError != 0) return 0;
    if (p.mxAlloc == 0) {
        sqlite3StrAccumSetError(p, SQLITE_TOOBIG);
        return p.nAlloc - @as(c_int, @intCast(p.nChar)) - 1;
    } else {
        const zOld: ?*anyopaque = if (isMalloced(p)) p.zText else null;
        var szNew: i64 = @as(i64, p.nChar) + N + 1;
        if (szNew + @as(i64, p.nChar) <= p.mxAlloc) {
            szNew += @as(i64, p.nChar);
        }
        if (szNew > p.mxAlloc) {
            sqlite3_str_reset(p);
            sqlite3StrAccumSetError(p, SQLITE_TOOBIG);
            return 0;
        } else {
            p.nAlloc = @intCast(szNew);
        }
        const zNew: ?[*]u8 = if (p.db != null)
            @ptrCast(sqlite3DbRealloc(p.db, zOld, @intCast(p.nAlloc)))
        else
            @ptrCast(sqlite3Realloc(zOld, @intCast(p.nAlloc)));
        if (zNew) |zn| {
            std.debug.assert(p.zText != null or p.nChar == 0);
            if (!isMalloced(p) and p.nChar > 0) _ = memcpy(zn, p.zText.?, p.nChar);
            p.zText = zn;
            p.nAlloc = sqlite3DbMallocSize(p.db, zn);
            p.printfFlags |= SQLITE_PRINTF_MALLOCED;
        } else {
            sqlite3_str_reset(p);
            sqlite3StrAccumSetError(p, SQLITE_NOMEM);
            return 0;
        }
    }
    std.debug.assert(N >= 0 and N <= 0x7fffffff);
    return @intCast(N);
}

export fn sqlite3StrAccumEnlargeIfNeeded(p: *StrAccum, N: i64) callconv(.c) c_int {
    if (N + @as(i64, p.nChar) >= p.nAlloc) {
        _ = sqlite3StrAccumEnlarge(p, N);
    }
    return p.accError;
}

export fn sqlite3_str_appendchar(p: *StrAccum, N_in: c_int, c: u8) callconv(.c) void {
    var N = N_in;
    if (@as(i64, p.nChar) + @as(i64, N) >= p.nAlloc) {
        N = sqlite3StrAccumEnlarge(p, N);
        if (N <= 0) return;
    }
    while (N > 0) : (N -= 1) {
        p.zText.?[p.nChar] = c;
        p.nChar += 1;
    }
}

fn enlargeAndAppend(p: *StrAccum, z: [*]const u8, N_in: c_int) void {
    const N = sqlite3StrAccumEnlarge(p, N_in);
    if (N > 0) {
        _ = memcpy(p.zText.? + p.nChar, z, @intCast(N));
        p.nChar += @intCast(N);
    }
}

export fn sqlite3_str_append(p: *StrAccum, z: [*]const u8, N: c_int) callconv(.c) void {
    std.debug.assert(N >= 0);
    if (@as(i64, p.nChar) + @as(i64, N) >= p.nAlloc) {
        enlargeAndAppend(p, z, N);
    } else if (N != 0) {
        p.nChar += @intCast(N);
        _ = memcpy(p.zText.? + (p.nChar - @as(u32, @intCast(N))), z, @intCast(N));
    }
}

export fn sqlite3_str_appendall(p: *StrAccum, z: [*:0]const u8) callconv(.c) void {
    sqlite3_str_append(p, z, sqlite3Strlen30(z));
}

// ─── Finish / new / accessors / reset / free / init ────────────────────────
fn strAccumFinishRealloc(p: *StrAccum) ?[*:0]u8 {
    std.debug.assert(p.mxAlloc > 0 and !isMalloced(p));
    const zText: ?[*]u8 = @ptrCast(sqlite3DbMallocRaw(p.db, 1 + @as(u64, p.nChar)));
    if (zText) |zt| {
        _ = memcpy(zt, p.zText.?, p.nChar + 1);
        p.printfFlags |= SQLITE_PRINTF_MALLOCED;
    } else {
        sqlite3StrAccumSetError(p, SQLITE_NOMEM);
    }
    p.zText = zText;
    return @ptrCast(zText);
}

export fn sqlite3StrAccumFinish(p: *StrAccum) callconv(.c) ?[*:0]u8 {
    if (p.zText) |zt| {
        zt[p.nChar] = 0;
        if (p.mxAlloc > 0 and !isMalloced(p)) {
            return strAccumFinishRealloc(p);
        }
    }
    return @ptrCast(p.zText);
}

export fn sqlite3_str_finish(p: ?*StrAccum) callconv(.c) ?[*:0]u8 {
    if (p != null and p.? != oomStrPtr()) {
        const z = sqlite3StrAccumFinish(p.?);
        sqlite3_free(p);
        return z;
    }
    return null;
}

export fn sqlite3_str_errcode(p: ?*StrAccum) callconv(.c) c_int {
    return if (p) |pp| pp.accError else SQLITE_NOMEM;
}

export fn sqlite3_str_length(p: ?*StrAccum) callconv(.c) c_int {
    return if (p) |pp| @intCast(pp.nChar) else 0;
}

export fn sqlite3_str_truncate(p: ?*StrAccum, N: c_int) callconv(.c) void {
    if (p) |pp| {
        if (N >= 0 and @as(u32, @bitCast(N)) < pp.nChar) {
            pp.nChar = @intCast(N);
            pp.zText.?[pp.nChar] = 0;
        }
    }
}

export fn sqlite3_str_value(p: ?*StrAccum) callconv(.c) ?[*:0]u8 {
    const pp = p orelse return null;
    if (pp.nChar == 0) return null;
    pp.zText.?[pp.nChar] = 0;
    return @ptrCast(pp.zText);
}

export fn sqlite3_str_reset(p: *StrAccum) callconv(.c) void {
    if (isMalloced(p)) {
        sqlite3DbFree(p.db, p.zText);
        p.printfFlags &= ~SQLITE_PRINTF_MALLOCED;
    } else if (p == oomStrPtr()) {
        return;
    }
    p.nAlloc = 0;
    p.nChar = 0;
    p.zText = null;
}

export fn sqlite3_str_free(p: ?*StrAccum) callconv(.c) void {
    if (p != null and p.? != oomStrPtr()) {
        sqlite3_str_reset(p.?);
        sqlite3_free(p);
    }
}

export fn sqlite3StrAccumInit(p: *StrAccum, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) callconv(.c) void {
    p.zText = zBase;
    p.db = db;
    p.nAlloc = n;
    p.mxAlloc = mx;
    p.nChar = 0;
    p.accError = 0;
    p.printfFlags = 0;
}

extern const sqlite3OomStr: StrAccum;
inline fn oomStrPtr() *StrAccum {
    return @constCast(&sqlite3OomStr);
}

export fn sqlite3_str_new(db: ?*anyopaque) callconv(.c) ?*StrAccum {
    const p: ?*StrAccum = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(StrAccum))));
    if (p) |pp| {
        sqlite3StrAccumInit(pp, null, null, 0, if (db != null) dbLimitLength(db) else SQLITE_MAX_LENGTH);
        return pp;
    }
    return @constCast(&sqlite3OomStr);
}

// ─── printf wrappers ───────────────────────────────────────────────────────
export fn sqlite3VMPrintf(db: ?*anyopaque, zFormat: [*:0]const u8, ap: *VaList) callconv(.c) ?[*:0]u8 {
    var acc: StrAccum = undefined;
    var zBase: [SQLITE_PRINT_BUF_SIZE]u8 = undefined;
    std.debug.assert(db != null);
    sqlite3StrAccumInit(&acc, db, &zBase, @intCast(zBase.len), dbLimitLength(db));
    acc.printfFlags = SQLITE_PRINTF_INTERNAL;
    sqlite3_str_vappendf(&acc, zFormat, ap);
    const z = sqlite3StrAccumFinish(&acc);
    if (acc.accError == SQLITE_NOMEM) _ = sqlite3OomFault(db);
    return z;
}

export fn sqlite3MPrintf(db: ?*anyopaque, zFormat: [*:0]const u8, ...) callconv(.c) ?[*:0]u8 {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    return sqlite3VMPrintf(db, zFormat, &ap);
}

export fn sqlite3_vmprintf(zFormat: [*:0]const u8, ap: *VaList) callconv(.c) ?[*:0]u8 {
    var acc: StrAccum = undefined;
    var zBase: [SQLITE_PRINT_BUF_SIZE]u8 = undefined;
    // SQLITE_ENABLE_API_ARMOR off. SQLITE_OMIT_AUTOINIT off.
    if (sqlite3_initialize() != 0) return null;
    sqlite3StrAccumInit(&acc, null, &zBase, @intCast(zBase.len), SQLITE_MAX_LENGTH);
    sqlite3_str_vappendf(&acc, zFormat, ap);
    return sqlite3StrAccumFinish(&acc);
}

export fn sqlite3_mprintf(zFormat: [*:0]const u8, ...) callconv(.c) ?[*:0]u8 {
    if (sqlite3_initialize() != 0) return null;
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    return sqlite3_vmprintf(zFormat, &ap);
}

export fn sqlite3_vsnprintf(n: c_int, zBuf: [*]u8, zFormat: [*:0]const u8, ap: *VaList) callconv(.c) ?[*]u8 {
    var acc: StrAccum = undefined;
    if (n <= 0) return zBuf;
    // SQLITE_ENABLE_API_ARMOR off.
    sqlite3StrAccumInit(&acc, null, zBuf, n, 0);
    sqlite3_str_vappendf(&acc, zFormat, ap);
    zBuf[acc.nChar] = 0;
    return zBuf;
}

export fn sqlite3_snprintf(n: c_int, zBuf: [*]u8, zFormat: [*:0]const u8, ...) callconv(.c) ?[*]u8 {
    var acc: StrAccum = undefined;
    if (n <= 0) return zBuf;
    sqlite3StrAccumInit(&acc, null, zBuf, n, 0);
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    sqlite3_str_vappendf(&acc, zFormat, &ap);
    zBuf[acc.nChar] = 0;
    return zBuf;
}

// ─── sqlite3_log ───────────────────────────────────────────────────────────
fn renderLogMsg(iErrCode: c_int, zFormat: [*:0]const u8, ap: *VaList) void {
    var acc: StrAccum = undefined;
    var zMsg: [SQLITE_MAX_LOG_MESSAGE]u8 = undefined;
    sqlite3StrAccumInit(&acc, null, &zMsg, @intCast(zMsg.len), 0);
    sqlite3_str_vappendf(&acc, zFormat, ap);
    configXLog().?(configPLogArg(), iErrCode, sqlite3StrAccumFinish(&acc));
}

export fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) callconv(.c) void {
    if (configXLog() != null) {
        var ap = @cVaStart();
        defer @cVaEnd(&ap);
        renderLogMsg(iErrCode, zFormat, &ap);
    }
}

// ─── sqlite3DebugPrintf (debug builds only) ────────────────────────────────
comptime {
    if (config.sqlite_debug) {
        @export(&sqlite3DebugPrintf, .{ .name = "sqlite3DebugPrintf" });
    }
}
fn sqlite3DebugPrintf(zFormat: [*:0]const u8, ...) callconv(.c) void {
    var acc: StrAccum = undefined;
    var zBuf: [SQLITE_PRINT_BUF_SIZE * 10]u8 = undefined;
    sqlite3StrAccumInit(&acc, null, &zBuf, @intCast(zBuf.len), 0);
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    sqlite3_str_vappendf(&acc, zFormat, &ap);
    _ = sqlite3StrAccumFinish(&acc);
    // SQLITE_OS_TRACE_PROC not defined: fprintf to stdout.
    _ = fprintf(stdout, "%s", @as([*:0]const u8, @ptrCast(&zBuf)));
    _ = fflush(stdout);
}

// ─── sqlite3_str_appendf (variadic wrapper) ────────────────────────────────
export fn sqlite3_str_appendf(p: *StrAccum, zFormat: [*:0]const u8, ...) callconv(.c) void {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    sqlite3_str_vappendf(p, zFormat, &ap);
}

// ─── Reference-counted string/blob storage (RCStr) ─────────────────────────
const RCStr = extern struct {
    nRCRef: u64,
};
comptime {
    std.debug.assert(@sizeOf(RCStr) == 8);
}

export fn sqlite3RCStrRef(z: [*]u8) callconv(.c) [*]u8 {
    const p: *RCStr = @ptrCast(@alignCast(z - @sizeOf(RCStr)));
    p.nRCRef += 1;
    return z;
}

export fn sqlite3RCStrUnref(z: ?*anyopaque) callconv(.c) void {
    const zb: [*]u8 = @ptrCast(z.?);
    const p: *RCStr = @ptrCast(@alignCast(zb - @sizeOf(RCStr)));
    std.debug.assert(p.nRCRef > 0);
    if (p.nRCRef >= 2) {
        p.nRCRef -= 1;
    } else {
        sqlite3_free(p);
    }
}

export fn sqlite3RCStrNew(N: u64) callconv(.c) ?[*]u8 {
    const p: ?*RCStr = @ptrCast(@alignCast(sqlite3_malloc64(N + @sizeOf(RCStr) + 1)));
    if (p) |pp| {
        pp.nRCRef = 1;
        const base: [*]u8 = @ptrCast(pp);
        return base + @sizeOf(RCStr);
    }
    return null;
}

export fn sqlite3RCStrResize(z: [*]u8, N: u64) callconv(.c) ?[*]u8 {
    const p: *RCStr = @ptrCast(@alignCast(z - @sizeOf(RCStr)));
    std.debug.assert(p.nRCRef == 1);
    const pNew: ?*anyopaque = sqlite3_realloc64(p, N + @sizeOf(RCStr) + 1);
    if (pNew == null) {
        sqlite3_free(p);
        return null;
    }
    const base: [*]u8 = @ptrCast(pNew.?);
    return base + @sizeOf(RCStr);
}
