//! Zig port of SQLite's host-parameter expansion for tracing (src/vdbetrace.c).
//!
//! Implements `sqlite3VdbeExpandSql()`: given a prepared statement and its raw
//! SQL text, produce a malloc'd UTF-8 string in which every bound host
//! parameter (?, ?N, :A, $A, @A, #A) is replaced by a SQL literal rendering of
//! its current value. Used by sqlite3_trace()/sqlite3_trace_v2() and the
//! `nVdbeExec>1` (nested) case prepends "-- " to each line instead.
//!
//! Coupling — build-divergent core structs are read at GROUND-TRUTH OFFSETS via
//! @import("c_layout.zig"); we never hand-mirror their full layout except `Mem`,
//! which (like utf.zig) needs a size-correct stack instance for the UTF16->UTF8
//! conversion temporary. Every field read at an offset, with its proposed
//! c_layout name and C struct tag:
//!
//!   Vdbe (struct tag `Vdbe`):
//!     - p->db    -> c_layout.c.Vdbe_db     (sqlite3*,   8 bytes, ptr)
//!     - p->nVar  -> c_layout.c.Vdbe_nVar   (ynVar==i16, 2 bytes)
//!     - p->aVar  -> c_layout.c.Vdbe_aVar   (Mem*,       8 bytes, ptr)
//!     - p->pVList-> c_layout.c.Vdbe_pVList (VList*,      passed opaque to helper)
//!   sqlite3 (struct tag `sqlite3`):
//!     - db->enc       -> c_layout.c.sqlite3_enc       (u8, 1 byte)
//!     - db->nVdbeExec -> c_layout.c.sqlite3_nVdbeExec (int, 4 bytes)
//!     - db->aLimit[SQLITE_LIMIT_LENGTH] (index 0)
//!                     -> c_layout.c.sqlite3_aLimit    (int[], we read [0])
//!   Mem / struct sqlite3_value (struct tag `sqlite3_value`): existing offsets
//!     reused — sqlite3_value_z, _n, _flags, _enc, _db, _szMalloc, _uTemp,
//!     _zMalloc, _xDel, sizeof_Mem. Additionally the union `u` lives at offset 0
//!     (config-invariant); we read u.i (i64) / u.r (f64) / u.nZero (i32) there.
//!
//! StrAccum: the C uses a STACK `StrAccum out` initialized with
//! `sqlite3StrAccumInit(&out, 0, 0, 0, mxAlloc)` (db arg is 0 — NOT the
//! connection) and then both reads `out.accError` and, on the UTF16 OOM path,
//! writes `out.accError`/`out.nAlloc`. The public sqlite3_str_new(db) API would
//! init differently (lookaside + db-derived mxAlloc), so it does NOT match. We
//! therefore mirror `struct sqlite3_str` (== StrAccum). It is config-INVARIANT
//! (no SQLITE_DEBUG/TEST fields), so a direct extern-struct mirror with a
//! comptime sizeof assert is safe without a c_layout entry.
//!
//! Config: SQLITE_OMIT_TRACE is OFF in both builds (function is compiled).
//! SQLITE_OMIT_UTF16 is OFF (the enc!=UTF8 conversion path is included).
//! SQLITE_ENABLE_NORMALIZE is OFF and SQLITE_TRACE_SIZE_LIMIT is undefined in
//! both builds, so neither the normalize nor the size-limit/truncation code is
//! emitted — confirmed against build.zig sqlite_flags and the --dev config.
//! Behavior is otherwise config-invariant.
//!
//! No standalone Zig unit test is feasible: every path requires a live Vdbe with
//! bound parameters and the printf/StrAccum engine. Validated through the engine
//! (trace tests; see report).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT collapses to this in production
const SQLITE_UTF8: u8 = 1;
const SQLITE_STATIC: ?*const fn (?*anyopaque) callconv(.c) void = null;

// MEM_* flag bits (vdbeInt.h).
const MEM_Null: u16 = 0x0001;
const MEM_Str: u16 = 0x0002;
const MEM_Int: u16 = 0x0004;
const MEM_Real: u16 = 0x0008;
const MEM_Blob: u16 = 0x0010;
const MEM_IntReal: u16 = 0x0020;
const MEM_Zero: u16 = 0x0400;

// --- Mem (struct sqlite3_value), size-correct mirror for the UTF16 temp. ---
// Field offsets are identical in both configs; only sizeof differs (SQLITE_DEBUG
// appends a scopy-tracking tail), matched by a config-gated padding array. We
// only ever build/read the temp `utf8` Mem and read fields of p->aVar[] through
// this layout.
const debug_tail_len: usize = if (config.sqlite_debug) 16 else 0;
const Mem = extern struct {
    u: u64, // union MemValue (offset 0): u.i/u.r/u.nZero read via reinterpret
    z: ?[*]u8, // string/blob value
    n: c_int, // byte length
    flags: u16,
    enc: u8,
    eSubtype: u8,
    db: ?*anyopaque, // sqlite3*
    szMalloc: c_int,
    uTemp: u32,
    zMalloc: ?[*]u8,
    xDel: ?*const fn (?*anyopaque) callconv(.c) void,
    _debug_tail: [debug_tail_len]u8,
};

comptime {
    std.debug.assert(@sizeOf(Mem) == L.sizeof_Mem);
    std.debug.assert(@offsetOf(Mem, "z") == L.sqlite3_value_z);
    std.debug.assert(@offsetOf(Mem, "n") == L.sqlite3_value_n);
    std.debug.assert(@offsetOf(Mem, "flags") == L.sqlite3_value_flags);
    std.debug.assert(@offsetOf(Mem, "enc") == L.sqlite3_value_enc);
    std.debug.assert(@offsetOf(Mem, "db") == L.sqlite3_value_db);
    std.debug.assert(@offsetOf(Mem, "szMalloc") == L.sqlite3_value_szMalloc);
    std.debug.assert(@offsetOf(Mem, "uTemp") == L.sqlite3_value_uTemp);
    std.debug.assert(@offsetOf(Mem, "zMalloc") == L.sqlite3_value_zMalloc);
    std.debug.assert(@offsetOf(Mem, "xDel") == L.sqlite3_value_xDel);
}

inline fn memValI(p: *const Mem) i64 {
    return @bitCast(p.u);
}
inline fn memValR(p: *const Mem) f64 {
    return @bitCast(p.u);
}
inline fn memValNZero(p: *const Mem) i32 {
    return @bitCast(@as(u32, @truncate(p.u)));
}

// --- StrAccum (== struct sqlite3_str). Config-invariant; direct mirror. ---
const StrAccum = extern struct {
    db: ?*anyopaque, // sqlite3* (NULL here)
    zText: ?[*]u8,
    nAlloc: u32,
    mxAlloc: u32,
    nChar: u32,
    accError: u8,
    printfFlags: u8,
};

comptime {
    // db(0)+zText(8)+nAlloc(16)+mxAlloc(20)+nChar(24)+accError(28)+printfFlags(29)
    // -> sizeof 32. Verified against C offsetof in both configs.
    std.debug.assert(@sizeOf(StrAccum) == 32);
    std.debug.assert(@offsetOf(StrAccum, "accError") == 28);
    std.debug.assert(@offsetOf(StrAccum, "nAlloc") == 16);
}

// --- Vdbe / sqlite3 field reads at ground-truth offsets ---
inline fn vdbeDb(p: ?*anyopaque) ?*anyopaque {
    const base: [*]const u8 = @ptrCast(p.?);
    return @as(*const ?*anyopaque, @ptrCast(@alignCast(base + L.Vdbe_db))).*;
}
inline fn vdbeNVar(p: ?*anyopaque) i16 {
    const base: [*]const u8 = @ptrCast(p.?);
    return @as(*const i16, @ptrCast(@alignCast(base + L.Vdbe_nVar))).*;
}
inline fn vdbeAVar(p: ?*anyopaque) [*]Mem {
    const base: [*]const u8 = @ptrCast(p.?);
    return @as(*const [*]Mem, @ptrCast(@alignCast(base + L.Vdbe_aVar))).*;
}

inline fn dbNVdbeExec(db: ?*anyopaque) c_int {
    const base: [*]const u8 = @ptrCast(db.?);
    return @as(*const c_int, @ptrCast(@alignCast(base + L.sqlite3_nVdbeExec))).*;
}
inline fn dbEnc(db: ?*anyopaque) u8 {
    const base: [*]const u8 = @ptrCast(db.?);
    return base[L.sqlite3_enc];
}
inline fn dbLimitLength(db: ?*anyopaque) c_int {
    // db->aLimit[SQLITE_LIMIT_LENGTH], SQLITE_LIMIT_LENGTH == 0.
    const base: [*]const u8 = @ptrCast(db.?);
    return @as(*const c_int, @ptrCast(@alignCast(base + L.sqlite3_aLimit))).*;
}

// --- C helpers resolved at link time ---
extern fn sqlite3GetToken(z: [*]const u8, tokenType: *c_int) i64;
extern fn sqlite3GetInt32(z: [*]const u8, pValue: *c_int) c_int;
extern fn sqlite3Strlen30(z: [*:0]const u8) c_int;
extern fn sqlite3VdbeParameterIndex(p: ?*anyopaque, zName: [*]const u8, nName: c_int) c_int;
extern fn sqlite3StrAccumInit(p: *StrAccum, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) void;
extern fn sqlite3StrAccumFinish(p: *StrAccum) ?[*:0]u8;
extern fn sqlite3_str_append(p: *StrAccum, z: [*]const u8, N: c_int) void;
extern fn sqlite3_str_appendf(p: *StrAccum, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_str_reset(p: *StrAccum) void;
extern fn sqlite3VdbeMemSetStr(pMem: *Mem, z: ?[*]const u8, n: i64, enc: u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3VdbeChangeEncoding(pMem: *Mem, enc: c_int) c_int;
extern fn sqlite3VdbeMemRelease(pMem: *Mem) void;

// Token types from parse.h (vendored: TK_VARIABLE==157, TK_ILLEGAL==186).
const TK_VARIABLE: c_int = 157;
const TK_ILLEGAL: c_int = 186;

/// zSql is a zero-terminated UTF-8 SQL string. Return the number of bytes up to
/// but excluding the first host parameter; *pnToken receives that parameter's
/// token length (0 if none found).
fn findNextHostParameter(zSql_in: [*]const u8, pnToken: *i64) i64 {
    var zSql = zSql_in;
    var tokenType: c_int = undefined;
    var nTotal: i64 = 0;
    pnToken.* = 0;
    while (zSql[0] != 0) {
        const n = sqlite3GetToken(zSql, &tokenType);
        std.debug.assert(n > 0 and tokenType != TK_ILLEGAL);
        if (tokenType == TK_VARIABLE) {
            pnToken.* = n;
            break;
        }
        nTotal += n;
        zSql += @intCast(n);
    }
    return nTotal;
}

/// Expand bound host parameters in zRawSql into SQL literals; returns a
/// db-malloc'd UTF-8 string (caller frees). See file header for semantics.
export fn sqlite3VdbeExpandSql(p: ?*anyopaque, zRawSql_in: [*:0]const u8) callconv(.c) ?[*:0]u8 {
    var idx: c_int = 0;
    var nextIndex: c_int = 1;
    var out: StrAccum = undefined;

    const db = vdbeDb(p);
    sqlite3StrAccumInit(&out, null, null, 0, dbLimitLength(db));

    var zRawSql: [*]const u8 = zRawSql_in;
    if (dbNVdbeExec(db) > 1) {
        while (zRawSql[0] != 0) {
            const zStart = zRawSql;
            // advance until past a '\n' or to end-of-string
            while (true) {
                const ch = zRawSql[0];
                zRawSql += 1;
                if (ch == '\n' or zRawSql[0] == 0) break;
            }
            sqlite3_str_append(&out, "-- ", 3);
            std.debug.assert(@intFromPtr(zRawSql) - @intFromPtr(zStart) > 0);
            sqlite3_str_append(&out, zStart, @intCast(@intFromPtr(zRawSql) - @intFromPtr(zStart)));
        }
    } else if (vdbeNVar(p) == 0) {
        sqlite3_str_append(&out, zRawSql, sqlite3Strlen30(zRawSql_in));
    } else {
        const aVar = vdbeAVar(p);
        const nVar = vdbeNVar(p);
        while (zRawSql[0] != 0) {
            var nToken: i64 = undefined;
            const n = findNextHostParameter(zRawSql, &nToken);
            std.debug.assert(n > 0);
            sqlite3_str_append(&out, zRawSql, @intCast(n));
            zRawSql += @intCast(n);
            std.debug.assert(zRawSql[0] != 0 or nToken == 0);
            if (nToken == 0) break;
            if (zRawSql[0] == '?') {
                if (nToken > 1) {
                    std.debug.assert(zRawSql[1] >= '0' and zRawSql[1] <= '9');
                    _ = sqlite3GetInt32(zRawSql + 1, &idx);
                } else {
                    idx = nextIndex;
                }
            } else {
                std.debug.assert(zRawSql[0] == ':' or zRawSql[0] == '$' or
                    zRawSql[0] == '@' or zRawSql[0] == '#');
                idx = sqlite3VdbeParameterIndex(p, zRawSql, @intCast(nToken));
                std.debug.assert(idx > 0);
            }
            zRawSql += @intCast(nToken);
            nextIndex = @max(idx + 1, nextIndex);
            std.debug.assert(idx > 0 and idx <= nVar);
            var pVar: *Mem = &aVar[@intCast(idx - 1)];
            if (pVar.flags & MEM_Null != 0) {
                sqlite3_str_append(&out, "NULL", 4);
            } else if (pVar.flags & (MEM_Int | MEM_IntReal) != 0) {
                sqlite3_str_appendf(&out, "%lld", memValI(pVar));
            } else if (pVar.flags & MEM_Real != 0) {
                sqlite3_str_appendf(&out, "%!.15g", memValR(pVar));
            } else if (pVar.flags & MEM_Str != 0) {
                // SQLITE_OMIT_UTF16 is off: convert non-UTF8 to UTF8 for display.
                var utf8: Mem = std.mem.zeroes(Mem);
                const enc = dbEnc(db);
                if (enc != SQLITE_UTF8) {
                    utf8.db = db;
                    _ = sqlite3VdbeMemSetStr(&utf8, pVar.z, @intCast(pVar.n), enc, SQLITE_STATIC);
                    if (sqlite3VdbeChangeEncoding(&utf8, SQLITE_UTF8) == SQLITE_NOMEM) {
                        out.accError = SQLITE_NOMEM;
                        out.nAlloc = 0;
                    }
                    pVar = &utf8;
                }
                const nOut: c_int = pVar.n; // SQLITE_TRACE_SIZE_LIMIT undefined
                sqlite3_str_appendf(&out, "'%.*q'", nOut, pVar.z);
                if (enc != SQLITE_UTF8) sqlite3VdbeMemRelease(&utf8);
            } else if (pVar.flags & MEM_Zero != 0) {
                sqlite3_str_appendf(&out, "zeroblob(%d)", memValNZero(pVar));
            } else {
                std.debug.assert(pVar.flags & MEM_Blob != 0);
                sqlite3_str_append(&out, "x'", 2);
                const nOut: c_int = pVar.n; // SQLITE_TRACE_SIZE_LIMIT undefined
                const zb = pVar.z.?;
                var i: c_int = 0;
                while (i < nOut) : (i += 1) {
                    sqlite3_str_appendf(&out, "%02x", @as(c_int, zb[@intCast(i)]) & 0xff);
                }
                sqlite3_str_append(&out, "'", 1);
            }
        }
    }
    if (out.accError != 0) sqlite3_str_reset(&out);
    return sqlite3StrAccumFinish(&out);
}
