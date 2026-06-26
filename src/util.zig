//! Zig port of SQLite's internal utility grab-bag (src/util.c).
//!
//! This is the foundational utility module used by virtually every subsystem:
//!   * error helpers   : sqlite3Error / sqlite3ErrorClear / sqlite3SystemError /
//!                       sqlite3ErrorWithMsg / sqlite3ErrorMsg / sqlite3ErrorToParser /
//!                       sqlite3ProgressCheck
//!   * dequote/token   : sqlite3Dequote / sqlite3DequoteExpr / sqlite3DequoteNumber /
//!                       sqlite3DequoteToken / sqlite3TokenInit
//!   * string compares : sqlite3_stricmp / sqlite3StrICmp / sqlite3_strnicmp /
//!                       sqlite3StrIHash / sqlite3Strlen30 / sqlite3ColumnType
//!   * number parsing  : sqlite3AtoF / sqlite3Atoi64 / sqlite3DecOrHexToI64 /
//!                       sqlite3GetInt32 / sqlite3Atoi / sqlite3GetUInt32
//!   * number rendering: sqlite3Int64ToText / sqlite3FpDecode (+ FP helpers)
//!   * varint / 4byte  : sqlite3PutVarint / sqlite3GetVarint / sqlite3GetVarint32 /
//!                       sqlite3VarintLen / sqlite3Get4byte / sqlite3Put4byte
//!   * hex/blob        : sqlite3HexToInt / sqlite3HexToBlob
//!   * safety checks   : sqlite3SafetyCheckOk / sqlite3SafetyCheckSickOrOk
//!   * 64-bit math     : sqlite3AddInt64 / sqlite3SubInt64 / sqlite3MulInt64 /
//!                       sqlite3AbsInt32
//!   * LogEst          : sqlite3LogEstAdd / sqlite3LogEst / sqlite3LogEstFromDouble /
//!                       sqlite3LogEstToInt
//!   * VList           : sqlite3VListAdd / sqlite3VListNumToName / sqlite3VListNameToNum
//!   * misc            : sqlite3IsNaN / sqlite3IsOverflow / sqlite3FaultSim
//!
//! ─── Struct coupling ──────────────────────────────────────────────────────
//! All struct field accesses below are at GROUND-TRUTH offsets that were
//! verified (tools probe) to be IDENTICAL in the production `zig build` config
//! and the `--dev` testfixture config (SQLITE_DEBUG/SQLITE_TEST). The fields
//! touched all sit ahead of the SQLITE_DEBUG-added fields, so they do not shift.
//! Offsets are read via @import("c_layout.zig") where present, else a literal
//! constant guarded by a comptime fallback (printf.zig idiom). NEW c_layout
//! entries requested (struct tag / field -> value):
//!     sqlite3.pErr          -> 416     sqlite3.eOpenState    -> 113
//!     sqlite3.iSysErrno     -> 92      sqlite3.pVfs          -> 0
//!     sqlite3.suppressErr   -> 107     sqlite3.u1 (isInterrupted) -> 424
//!     sqlite3.xProgress     -> 544     sqlite3.pProgressArg  -> 552
//!     sqlite3.nProgressOps  -> 560
//!     Parse.db -> 0   Parse.nErr -> 52   Parse.rc -> 24   Parse.zErrMsg -> 8
//!     Parse.pWith -> 400   Parse.nProgressSteps -> 128   Parse.pToplevel -> 136
//!     Column.zCnName -> 0   Column.colFlags -> 14   (Column.eCType: bitfield,
//!         high nibble of the byte at offset 8)
//! Reused from c_layout (already present): sqlite3.errCode(80),
//!     errByteOffset(84), errMask(88), mallocFailed(103), pParse(344).
//! Token/Expr mirrors match printf.zig (z=0,n=8 / op=0,flags=4,u=8).
//!
//! ─── Config flags in effect ───────────────────────────────────────────────
//! SQLITE_OMIT_FLOATING_POINT  OFF (FP paths compiled)
//! SQLITE_OMIT_HEX_INTEGER     OFF (hex literal paths compiled)
//! SQLITE_OMIT_BLOB_LITERAL    OFF (sqlite3HexToBlob compiled)
//! SQLITE_OMIT_PROGRESS_CALLBACK OFF (progress callback in sqlite3ProgressCheck)
//! SQLITE_UNTESTABLE          OFF (sqlite3FaultSim compiled, has external callers)
//! SQLITE_ENABLE_8_3_NAMES    OFF (sqlite3FileSuffix3 NOT compiled — no extern callers)
//! SQLITE_AVOID_U64_DIVIDE    OFF (x86-64 has hw u64 div; fast path used)
//! SQLITE_USE_SEH             OFF (SEH path in sqlite3SystemError omitted)
//! SQLITE_ASCII is ON, SQLITE_EBCDIC OFF (hex-to-int adjust uses ASCII form).
//! SQLITE_HAVE_ISNAN / HAVE_ISNAN are OFF -> sqlite3IsNaN uses the bit-twiddling
//! IsNaN() path (memcpy double->u64), exactly as C.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ─── Integer-width constants (sqliteInt.h) ─────────────────────────────────
const LARGEST_INT64: i64 = std.math.maxInt(i64); //  0x7fffffffffffffff
const SMALLEST_INT64: i64 = std.math.minInt(i64); // -0x8000000000000000
const LARGEST_UINT64: u64 = std.math.maxInt(u64);
const SQLITE_MAX_U32: u64 = (@as(u64, 1) << 32) - 1;
const SQLITE_U64_DIGITS: usize = 20;
const SQLITE_DIGIT_SEPARATOR: u8 = '_';

// Result codes
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CANTOPEN: c_int = 14;
const SQLITE_MISUSE: c_int = 21;
const SQLITE_IOERR_NOMEM: c_int = 3082;

// Connection open-state codes (sqliteInt.h SQLITE_STATE_*)
const SQLITE_STATE_OPEN: u8 = 0x76; // 118
const SQLITE_STATE_SICK: u8 = 0xba; // 186
const SQLITE_STATE_BUSY: u8 = 0x6d; // 109

// Text encodings
const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_UTF16BE: u8 = 3;

// Column.colFlags / SQLITE_N_STDTYPE (sqliteInt.h)
const COLFLAG_HASTYPE: u16 = 0x0004;
const SQLITE_N_STDTYPE: u8 = 6;

// Expr flag bits (sqliteInt.h)
const EP_IntValue: u32 = 0x000800;
const EP_DblQuoted: u32 = 0x000080;
const EP_Quoted: u32 = 0x4000000;

// Token op codes (parse.h)
const TK_FLOAT: u8 = 154;
const TK_INTEGER: u8 = 156;
const TK_QNUMBER: u8 = 183;

// IEEE754 bit patterns for IsNaN / IsOvfl (sqliteInt.h)
const EXP754: u64 = @as(u64, 0x7ff) << 52;
const MAN754: u64 = (@as(u64, 1) << 52) - 1;

// SQLITE_DYNAMIC destructor sentinel: ((sqlite3_destructor_type)sqlite3RowSetClear)
extern fn sqlite3RowSetClear(p: ?*anyopaque) callconv(.c) void;

// ─── ground-truth offsets (config-invariant; verified prod==dev) ────────────
const off_errCode: usize = if (@hasDecl(L, "sqlite3_errCode")) L.sqlite3_errCode else 80;
const off_errByteOffset: usize = if (@hasDecl(L, "sqlite3_errByteOffset")) L.sqlite3_errByteOffset else 84;
const off_mallocFailed: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const off_pParse: usize = if (@hasDecl(L, "sqlite3_pParse")) L.sqlite3_pParse else 344;
const off_pErr: usize = if (@hasDecl(L, "sqlite3_pErr")) L.sqlite3_pErr else 416;
const off_eOpenState: usize = if (@hasDecl(L, "sqlite3_eOpenState")) L.sqlite3_eOpenState else 113;
const off_iSysErrno: usize = if (@hasDecl(L, "sqlite3_iSysErrno")) L.sqlite3_iSysErrno else 92;
const off_pVfs: usize = if (@hasDecl(L, "sqlite3_pVfs")) L.sqlite3_pVfs else 0;
const off_suppressErr: usize = if (@hasDecl(L, "sqlite3_suppressErr")) L.sqlite3_suppressErr else 107;
const off_u1: usize = if (@hasDecl(L, "sqlite3_u1")) L.sqlite3_u1 else 424; // isInterrupted (int)
const off_xProgress: usize = if (@hasDecl(L, "sqlite3_xProgress")) L.sqlite3_xProgress else 544;
const off_pProgressArg: usize = if (@hasDecl(L, "sqlite3_pProgressArg")) L.sqlite3_pProgressArg else 552;
const off_nProgressOps: usize = if (@hasDecl(L, "sqlite3_nProgressOps")) L.sqlite3_nProgressOps else 560;

const off_Parse_db: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const off_Parse_nErr: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;
const off_Parse_rc: usize = if (@hasDecl(L, "Parse_rc")) L.Parse_rc else 24;
const off_Parse_zErrMsg: usize = if (@hasDecl(L, "Parse_zErrMsg")) L.Parse_zErrMsg else 8;
const off_Parse_pWith: usize = if (@hasDecl(L, "Parse_pWith")) L.Parse_pWith else 400;
const off_Parse_nProgressSteps: usize = if (@hasDecl(L, "Parse_nProgressSteps")) L.Parse_nProgressSteps else 128;
const off_Parse_pToplevel: usize = if (@hasDecl(L, "Parse_pToplevel")) L.Parse_pToplevel else 136;

const off_Column_zCnName: usize = if (@hasDecl(L, "Column_zCnName")) L.Column_zCnName else 0;
const off_Column_colFlags: usize = if (@hasDecl(L, "Column_colFlags")) L.Column_colFlags else 14;
const COLUMN_ECTYPE_BYTE: usize = 8; // eCType is the high nibble of byte at offset 8

// ─── tiny struct-field accessor helpers (raw byte pointer arithmetic) ───────
inline fn fieldPtr(comptime T: type, base: ?*anyopaque, off: usize) *T {
    const p: [*]u8 = @ptrCast(base.?);
    return @ptrCast(@alignCast(p + off));
}
inline fn getField(comptime T: type, base: ?*anyopaque, off: usize) T {
    return fieldPtr(T, base, off).*;
}
inline fn setField(comptime T: type, base: ?*anyopaque, off: usize, v: T) void {
    fieldPtr(T, base, off).* = v;
}

// ─── extern C globals (lookup tables) ──────────────────────────────────────
// Mutable globals MUST be `extern var`, never `extern const`.
extern var sqlite3UpperToLower: [256]u8; // really const, but read-only use
extern var sqlite3CtypeMap: [256]u8;
extern var sqlite3StdType: [SQLITE_N_STDTYPE][*:0]const u8;
// sqlite3GlobalConfig is the internal name for the `struct Sqlite3Config sqlite3Config`.
extern var sqlite3Config: u8; // base; xTestCallback read via offset

// ─── extern C functions ────────────────────────────────────────────────────
extern fn sqlite3ValueSetNull(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3ValueNew(db: ?*anyopaque) callconv(.c) ?*anyopaque;
extern fn sqlite3ValueSetStr(
    p: ?*anyopaque,
    n: c_int,
    z: ?*const anyopaque,
    enc: u8,
    xDel: ?*const fn (?*anyopaque) callconv(.c) void,
) callconv(.c) void;
extern fn sqlite3OsGetLastError(pVfs: ?*anyopaque) callconv(.c) c_int;
extern fn sqlite3VMPrintf(db: ?*anyopaque, zFormat: [*:0]const u8, ap: *std.builtin.VaList) callconv(.c) ?[*:0]u8;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3DbRealloc(db: ?*anyopaque, p: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) callconv(.c) void;

// ─── ctype helpers (mirror sqliteInt.h macros; SQLITE_ASCII path) ───────────
inline fn isspace(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x01) != 0;
}
inline fn isdigit(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x04) != 0;
}
inline fn isxdigit(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x08) != 0;
}
inline fn isquote(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x80) != 0;
}

// ════════════════════════════════════════════════════════════════════════════
// FaultSim / IsNaN / IsOverflow
// ════════════════════════════════════════════════════════════════════════════

// sqlite3GlobalConfig.xTestCallback offset. Probe-derived; config-invariant.
const off_Config_xTestCallback: usize =
    if (@hasDecl(L, "Sqlite3Config_xTestCallback")) L.Sqlite3Config_xTestCallback else 400;

export fn sqlite3FaultSim(iTest: c_int) callconv(.c) c_int {
    const base: *u8 = &sqlite3Config;
    const pcb: *?*const fn (c_int) callconv(.c) c_int =
        @ptrCast(@alignCast(@as([*]u8, @ptrCast(base)) + off_Config_xTestCallback));
    if (pcb.*) |cb| {
        return cb(iTest);
    }
    return SQLITE_OK;
}

export fn sqlite3IsNaN(x: f64) callconv(.c) c_int {
    var y: u64 = undefined;
    @memcpy(std.mem.asBytes(&y), std.mem.asBytes(&x));
    // IsNaN(X): (X&EXP754)==EXP754 && (X&MAN754)!=0
    const rc = ((y & EXP754) == EXP754) and ((y & MAN754) != 0);
    return @intFromBool(rc);
}

export fn sqlite3IsOverflow(x: f64) callconv(.c) c_int {
    var y: u64 = undefined;
    @memcpy(std.mem.asBytes(&y), std.mem.asBytes(&x));
    // IsOvfl(X): (X&EXP754)==EXP754
    return @intFromBool((y & EXP754) == EXP754);
}

// ════════════════════════════════════════════════════════════════════════════
// Strlen30 / ColumnType
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3Strlen30(z: ?[*:0]const u8) callconv(.c) c_int {
    if (z == null) return 0;
    const n: usize = std.mem.len(z.?);
    return @intCast(n & 0x3fffffff);
}

export fn sqlite3ColumnType(pCol: ?*anyopaque, zDflt: ?[*:0]u8) callconv(.c) ?[*:0]u8 {
    const col = pCol.?;
    const colFlags = getField(u16, col, off_Column_colFlags);
    if ((colFlags & COLFLAG_HASTYPE) != 0) {
        const zCnName = getField([*:0]u8, col, off_Column_zCnName);
        const len = std.mem.len(zCnName);
        return @ptrCast(zCnName + len + 1);
    }
    // eCType: high nibble of the byte at offset 8 (notNull:4, eCType:4)
    const ecByte = getField(u8, col, COLUMN_ECTYPE_BYTE);
    const eCType: u8 = (ecByte >> 4) & 0x0f;
    if (eCType != 0) {
        // assert eCType<=SQLITE_N_STDTYPE
        return @constCast(sqlite3StdType[eCType - 1]);
    }
    return zDflt;
}

// ════════════════════════════════════════════════════════════════════════════
// Error helpers
// ════════════════════════════════════════════════════════════════════════════

fn errorFinish(db: ?*anyopaque, err_code: c_int) void {
    const pErr = getField(?*anyopaque, db, off_pErr);
    if (pErr != null) sqlite3ValueSetNull(pErr);
    sqlite3SystemError(db, err_code);
}

export fn sqlite3Error(db: ?*anyopaque, err_code: c_int) callconv(.c) void {
    setField(c_int, db, off_errCode, err_code);
    const pErr = getField(?*anyopaque, db, off_pErr);
    if (err_code != 0 or pErr != null) {
        errorFinish(db, err_code);
    } else {
        setField(c_int, db, off_errByteOffset, -1);
    }
}

export fn sqlite3ErrorClear(db: ?*anyopaque) callconv(.c) void {
    setField(c_int, db, off_errCode, SQLITE_OK);
    setField(c_int, db, off_errByteOffset, -1);
    const pErr = getField(?*anyopaque, db, off_pErr);
    if (pErr != null) sqlite3ValueSetNull(pErr);
}

export fn sqlite3SystemError(db: ?*anyopaque, rc: c_int) callconv(.c) void {
    if (rc == SQLITE_IOERR_NOMEM) return;
    // SQLITE_USE_SEH path omitted (off).
    const r = rc & 0xff;
    if (r == SQLITE_CANTOPEN or r == SQLITE_IOERR) {
        const pVfs = getField(?*anyopaque, db, off_pVfs);
        setField(c_int, db, off_iSysErrno, sqlite3OsGetLastError(pVfs));
    }
}

export fn sqlite3ErrorWithMsg(db: ?*anyopaque, err_code: c_int, zFormat: ?[*:0]const u8, ...) callconv(.c) void {
    setField(c_int, db, off_errCode, err_code);
    sqlite3SystemError(db, err_code);
    if (zFormat == null) {
        sqlite3Error(db, err_code);
        return;
    }
    var pErr = getField(?*anyopaque, db, off_pErr);
    if (pErr == null) {
        pErr = sqlite3ValueNew(db);
        setField(?*anyopaque, db, off_pErr, pErr);
        if (pErr == null) return;
    }
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const z = sqlite3VMPrintf(db, zFormat.?, &ap);
    // SQLITE_DYNAMIC destructor
    const xDel: *const fn (?*anyopaque) callconv(.c) void = @ptrCast(&sqlite3RowSetClear);
    sqlite3ValueSetStr(pErr, -1, z, SQLITE_UTF8, xDel);
}

export fn sqlite3ProgressCheck(p: ?*anyopaque) callconv(.c) void {
    const db = getField(?*anyopaque, p, off_Parse_db);
    // AtomicLoad(&db->u1.isInterrupted) — relaxed load
    const pb: [*]u8 = @ptrCast(db.?);
    const pInt: *volatile c_int = @ptrCast(@alignCast(pb + off_u1));
    if (pInt.* != 0) {
        setField(c_int, p, off_Parse_nErr, getField(c_int, p, off_Parse_nErr) + 1);
        setField(c_int, p, off_Parse_rc, SQLITE_INTERRUPT);
    }
    // SQLITE_OMIT_PROGRESS_CALLBACK is OFF
    const xProgress = getField(?*const fn (?*anyopaque) callconv(.c) c_int, db, off_xProgress);
    if (xProgress != null) {
        if (getField(c_int, p, off_Parse_rc) == SQLITE_INTERRUPT) {
            setField(c_int, p, off_Parse_nProgressSteps, 0);
        } else {
            const steps = getField(c_int, p, off_Parse_nProgressSteps) + 1;
            setField(c_int, p, off_Parse_nProgressSteps, steps);
            const nProgressOps: c_uint = getField(c_uint, db, off_nProgressOps);
            if (@as(c_uint, @bitCast(steps)) >= nProgressOps) {
                const pArg = getField(?*anyopaque, db, off_pProgressArg);
                if (xProgress.?(pArg) != 0) {
                    setField(c_int, p, off_Parse_nErr, getField(c_int, p, off_Parse_nErr) + 1);
                    setField(c_int, p, off_Parse_rc, SQLITE_INTERRUPT);
                }
                setField(c_int, p, off_Parse_nProgressSteps, 0);
            }
        }
    }
}

export fn sqlite3ErrorMsg(pParse: ?*anyopaque, zFormat: ?[*:0]const u8, ...) callconv(.c) void {
    const db = getField(?*anyopaque, pParse, off_Parse_db);
    setField(c_int, db, off_errByteOffset, -2);
    var ap = @cVaStart();
    const zMsg = sqlite3VMPrintf(db, zFormat.?, &ap);
    @cVaEnd(&ap);
    if (getField(c_int, db, off_errByteOffset) < -1) {
        setField(c_int, db, off_errByteOffset, -1);
    }
    const suppressErr = getField(u8, db, off_suppressErr);
    if (suppressErr != 0) {
        sqlite3DbFree(db, zMsg);
        if (getField(u8, db, off_mallocFailed) != 0) {
            setField(c_int, pParse, off_Parse_nErr, getField(c_int, pParse, off_Parse_nErr) + 1);
            setField(c_int, pParse, off_Parse_rc, SQLITE_NOMEM);
        }
    } else {
        setField(c_int, pParse, off_Parse_nErr, getField(c_int, pParse, off_Parse_nErr) + 1);
        sqlite3DbFree(db, getField(?*anyopaque, pParse, off_Parse_zErrMsg));
        setField(?*anyopaque, pParse, off_Parse_zErrMsg, @ptrCast(zMsg));
        setField(c_int, pParse, off_Parse_rc, SQLITE_ERROR);
        setField(?*anyopaque, pParse, off_Parse_pWith, null);
    }
}

export fn sqlite3ErrorToParser(db: ?*anyopaque, errCode: c_int) callconv(.c) c_int {
    if (db == null) return errCode;
    const pParse = getField(?*anyopaque, db, off_pParse);
    if (pParse == null) return errCode;
    setField(c_int, pParse, off_Parse_rc, errCode);
    setField(c_int, pParse, off_Parse_nErr, getField(c_int, pParse, off_Parse_nErr) + 1);
    return errCode;
}

// ════════════════════════════════════════════════════════════════════════════
// Dequote / Token helpers
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3Dequote(z: ?[*:0]u8) callconv(.c) void {
    if (z == null) return;
    const s = z.?;
    var quote = s[0];
    if (!isquote(quote)) return;
    if (quote == '[') quote = ']';
    var i: usize = 1;
    var j: usize = 0;
    while (true) : (i += 1) {
        // assert(z[i]) — input is well-formed
        if (s[i] == quote) {
            if (s[i + 1] == quote) {
                s[j] = quote;
                j += 1;
                i += 1;
            } else {
                break;
            }
        } else {
            s[j] = s[i];
            j += 1;
        }
    }
    s[j] = 0;
}

// Expr mirror (matches printf.zig: op@0, flags@4, u@8)
const Expr = extern struct {
    op: u8,
    affExpr: u8,
    op2: u8,
    _pad0: u8,
    flags: u32,
    u: extern union { zToken: ?[*:0]u8, iValue: c_int },
};
comptime {
    std.debug.assert(@offsetOf(Expr, "flags") == 4);
    std.debug.assert(@offsetOf(Expr, "u") == 8);
}

export fn sqlite3DequoteExpr(p: ?*Expr) callconv(.c) void {
    const e = p.?;
    const tok = e.u.zToken.?;
    e.flags |= if (tok[0] == '"') (EP_Quoted | EP_DblQuoted) else EP_Quoted;
    sqlite3Dequote(e.u.zToken);
}

export fn sqlite3DequoteNumber(pParse: ?*anyopaque, p: ?*Expr) callconv(.c) void {
    if (p) |e| {
        const zToken = e.u.zToken.?;
        var pIn: [*:0]const u8 = zToken;
        var pOut: [*]u8 = zToken;
        const bHex: bool = (pIn[0] == '0' and (pIn[1] == 'x' or pIn[1] == 'X'));
        e.op = TK_INTEGER;
        // do { ... } while(*pIn++)
        while (true) {
            const ch = pIn[0];
            if (ch != SQLITE_DIGIT_SEPARATOR) {
                pOut[0] = ch;
                pOut += 1;
                if (ch == 'e' or ch == 'E' or ch == '.') e.op = TK_FLOAT;
            } else {
                // pIn[-1] and pIn[1]
                const prev = (pIn - 1)[0];
                const next = pIn[1];
                const bad = if (!bHex)
                    (!isdigit(prev) or !isdigit(next))
                else
                    (!isxdigit(prev) or !isxdigit(next));
                if (bad) {
                    sqlite3ErrorMsg(pParse, "unrecognized token: \"%s\"", zToken);
                }
            }
            const cur = pIn[0];
            pIn += 1;
            if (cur == 0) break;
        }
        if (bHex) e.op = TK_INTEGER;

        // tag-20240227-a
        if (e.op == TK_INTEGER) {
            var iValue: c_int = undefined;
            if (sqlite3GetInt32(@ptrCast(zToken), &iValue) != 0) {
                e.u.iValue = iValue;
                e.flags |= EP_IntValue;
            }
        }
    }
}

// Token mirror (z@0, n@8)
const Token = extern struct {
    z: ?[*]u8,
    n: c_uint,
};
comptime {
    std.debug.assert(@offsetOf(Token, "n") == 8);
}

export fn sqlite3DequoteToken(p: ?*Token) callconv(.c) void {
    const t = p.?;
    if (t.n < 2) return;
    const z = t.z.?;
    if (!isquote(z[0])) return;
    var i: c_uint = 1;
    while (i < t.n - 1) : (i += 1) {
        if (isquote(z[i])) return;
    }
    t.n -= 2;
    t.z = z + 1;
}

export fn sqlite3TokenInit(p: ?*Token, z: ?[*:0]u8) callconv(.c) void {
    const t = p.?;
    t.z = z;
    t.n = @bitCast(sqlite3Strlen30(@ptrCast(z)));
}

// ════════════════════════════════════════════════════════════════════════════
// String comparison
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3_stricmp(zLeft: ?[*:0]const u8, zRight: ?[*:0]const u8) callconv(.c) c_int {
    if (zLeft == null) {
        return if (zRight != null) -1 else 0;
    } else if (zRight == null) {
        return 1;
    }
    return sqlite3StrICmp(zLeft, zRight);
}

export fn sqlite3StrICmp(zLeft: ?[*:0]const u8, zRight: ?[*:0]const u8) callconv(.c) c_int {
    var a: [*]const u8 = @ptrCast(zLeft.?);
    var b: [*]const u8 = @ptrCast(zRight.?);
    var c: c_int = undefined;
    while (true) {
        c = a[0];
        const x: c_int = b[0];
        if (c == x) {
            if (c == 0) break;
        } else {
            c = @as(c_int, sqlite3UpperToLower[@intCast(c)]) - @as(c_int, sqlite3UpperToLower[@intCast(x)]);
            if (c != 0) break;
        }
        a += 1;
        b += 1;
    }
    return c;
}

export fn sqlite3_strnicmp(zLeft: ?[*:0]const u8, zRight: ?[*:0]const u8, N: c_int) callconv(.c) c_int {
    if (zLeft == null) {
        return if (zRight != null) -1 else 0;
    } else if (zRight == null) {
        return 1;
    }
    var a: [*]const u8 = @ptrCast(zLeft.?);
    var b: [*]const u8 = @ptrCast(zRight.?);
    var n = N;
    // while( N-- > 0 && *a!=0 && UpperToLower[*a]==UpperToLower[*b]){ a++; b++; }
    while (true) {
        const old = n;
        n -= 1;
        if (!(old > 0)) break;
        if (a[0] == 0) break;
        if (sqlite3UpperToLower[a[0]] != sqlite3UpperToLower[b[0]]) break;
        a += 1;
        b += 1;
    }
    if (n < 0) return 0;
    return @as(c_int, sqlite3UpperToLower[a[0]]) - @as(c_int, sqlite3UpperToLower[b[0]]);
}

export fn sqlite3StrIHash(z: ?[*:0]const u8) callconv(.c) u8 {
    var h: u8 = 0;
    if (z == null) return 0;
    var p: [*]const u8 = @ptrCast(z.?);
    while (p[0] != 0) : (p += 1) {
        h +%= sqlite3UpperToLower[p[0]];
    }
    return h;
}

// ════════════════════════════════════════════════════════════════════════════
// 128/160-bit multiply helpers (used by FP decode/parse)
// ════════════════════════════════════════════════════════════════════════════

// Two u64 inputs -> 128-bit result. Low 64 into *pLo, return high 64.
fn multiply128(a: u64, b: u64, pLo: *u64) u64 {
    const r: u128 = @as(u128, a) * @as(u128, b);
    pLo.* = @truncate(r);
    return @truncate(r >> 64);
}

// A = (a<<32)+aLo (96-bit), B = b (64-bit). Compute upper 96 bits of A*B.
// Write middle 32 bits into *pLo, return upper 64 bits.
fn multiply160(a: u64, aLo: u32, b: u64, pLo: *u32) u64 {
    var r: u128 = @as(u128, a) * @as(u128, b);
    r += (@as(u128, aLo) * @as(u128, b)) >> 32;
    pLo.* = @truncate((r >> 32) & 0xffffffff);
    return @truncate(r >> 64);
}

inline fn U64_BIT(n: anytype) u64 {
    return @as(u64, 1) << @intCast(n);
}

const POWERSOF10_FIRST: c_int = -348;
const POWERSOF10_LAST: c_int = 347;

const aBase = [_]u64{
    0x8000000000000000, 0xa000000000000000, 0xc800000000000000, 0xfa00000000000000,
    0x9c40000000000000, 0xc350000000000000, 0xf424000000000000, 0x9896800000000000,
    0xbebc200000000000, 0xee6b280000000000, 0x9502f90000000000, 0xba43b74000000000,
    0xe8d4a51000000000, 0x9184e72a00000000, 0xb5e620f480000000, 0xe35fa931a0000000,
    0x8e1bc9bf04000000, 0xb1a2bc2ec5000000, 0xde0b6b3a76400000, 0x8ac7230489e80000,
    0xad78ebc5ac620000, 0xd8d726b7177a8000, 0x878678326eac9000, 0xa968163f0a57b400,
    0xd3c21bcecceda100, 0x84595161401484a0, 0xa56fa5b99019a5c8,
};
const aScale = [_]u64{
    0x8049a4ac0c5811ae, 0xcf42894a5dce35ea, 0xa76c582338ed2621, 0x873e4f75e2224e68,
    0xda7f5bf590966848, 0xb080392cc4349dec, 0x8e938662882af53e, 0xe65829b3046b0afa,
    0xba121a4650e4ddeb, 0x964e858c91ba2655, 0xf2d56790ab41c2a2, 0xc428d05aa4751e4c,
    0x9e74d1b791e07e48, 0xcccccccccccccccc, 0xcecb8f27f4200f3a, 0xa70c3c40a64e6c51,
    0x86f0ac99b4e8dafd, 0xda01ee641a708de9, 0xb01ae745b101e9e4, 0x8e41ade9fbebc27d,
    0xe5d3ef282a242e81, 0xb9a74a0637ce2ee1, 0x95f83d0a1fb69cd9, 0xf24a01a73cf2dccf,
    0xc3b8358109e84f07, 0x9e19db92b4e31ba9,
};
const aScaleLo = [_]u32{
    0x205b896d, 0x52064cad, 0xaf2af2b8, 0x5a7744a7, 0xaf39a475, 0xbd8d794e,
    0x547eb47b, 0x0cb4a5a3, 0x92f34d62, 0x3a6a07f9, 0xfae27299, 0xaa97e14c,
    0x775ea265, 0xcccccccc, 0x00000000, 0x999090b6, 0x69a028bb, 0xe80e6f48,
    0x5ec05dd0, 0x14588f14, 0x8f1668c9, 0x6d953e2c, 0x4abdaf10, 0xbc633b39,
    0x0a862f81, 0x6c07a2c2,
};

fn powerOfTen(p: c_int, pLo: *u32) u64 {
    var g: c_int = undefined;
    var n: c_int = undefined;
    // assert p in range
    if (p < 0) {
        if (p == -1) {
            pLo.* = aScaleLo[13];
            return aScale[13];
        }
        g = @divTrunc(p, 27);
        n = @rem(p, 27);
        if (n != 0) {
            g -= 1;
            n += 27;
        }
    } else if (p < 27) {
        pLo.* = 0;
        return aBase[@intCast(p)];
    } else {
        g = @divTrunc(p, 27);
        n = @rem(p, 27);
    }
    const s = aScale[@intCast(g + 13)];
    if (n == 0) {
        pLo.* = aScaleLo[@intCast(g + 13)];
        return s;
    }
    var lo: u32 = undefined;
    var x = multiply160(s, aScaleLo[@intCast(g + 13)], aBase[@intCast(n)], &lo);
    if ((U64_BIT(63) & x) == 0) {
        x = (x << 1) | ((lo >> 31) & 1);
        lo = (lo << 1) | 1;
    }
    pLo.* = lo;
    return x;
}

// pow10to2(x) = floor(log2(pow(10,x))); pow2to10(y) = floor(log10(pow(2,y))).
// Right-shift used so rounding of negatives goes the right direction (arithmetic).
fn pwr10to2(p: c_int) c_int {
    return (p *% 108853) >> 15;
}
fn pwr2to10(p: c_int) c_int {
    return (p *% 78913) >> 18;
}

fn countLeadingZeros(m: u64) c_int {
    // __builtin_clzll; m is required nonzero where used.
    return @clz(m);
}

fn fp2Convert10(m: u64, e: c_int, n: c_int, pD: *u64, pP: *c_int) void {
    // assert n>=1 && n<=18
    const p = n - 1 - pwr2to10(e + 63);
    var d1: u64 = undefined;
    var d2: u32 = undefined;
    const h = multiply128(m, powerOfTen(p, &d2), &d1);
    // shift amounts; C uses signed negation
    if (n == 18) {
        const sh: u6 = @intCast(-(e + pwr10to2(p) + 2));
        const hh = h >> sh;
        pD.* = (hh + ((hh << 1) & 2)) >> 1;
    } else {
        const sh: u6 = @intCast(-(e + pwr10to2(p) + 1));
        pD.* = h >> sh;
    }
    pP.* = -p;
}

fn fp10Convert2(d: u64, p: c_int) f64 {
    if (p < POWERSOF10_FIRST) return 0.0;
    if (p > POWERSOF10_LAST) return std.math.inf(f64);
    const b: c_int = 64 - countLeadingZeros(d);
    const lp = pwr10to2(p);
    var e: c_int = 53 - b - lp;
    if (e > 1074) {
        if (e >= 1130) return 0.0;
        e = 1074;
    }
    const s_amt: c_int = -(e - (64 - b) + lp + 3);
    var pwr10l: u32 = undefined;
    var pwr10h = powerOfTen(p, &pwr10l);
    if (pwr10l != 0) {
        pwr10h += 1;
        pwr10l = ~pwr10l;
    }
    const x: u64 = d << @intCast(64 - b);
    var lo: u64 = undefined;
    var hi = multiply128(x, pwr10h, &lo);
    const mid1: u32 = @truncate(lo >> 32);
    var sticky: u64 = 1;
    const sshift: u6 = @intCast(s_amt);
    if ((hi & (U64_BIT(s_amt) - 1)) == 0) {
        const mid2: u32 = @truncate(multiply128(x, @as(u64, pwr10l) << 32, &lo) >> 32);
        sticky = @intFromBool(mid1 -% mid2 > 1);
        hi -= @intFromBool(mid1 < mid2);
    }
    var u: u64 = (hi >> sshift) | sticky;
    const adj: c_int = @intFromBool(u >= U64_BIT(55) - 2);
    if (adj != 0) {
        u = (u >> @intCast(adj)) | (u & 1);
        e -= adj;
    }
    var m: u64 = (u + 1 + ((u >> 2) & 1)) >> 2;
    if (e <= -972) return std.math.inf(f64);
    if ((m & U64_BIT(52)) != 0) {
        m = (m & ~U64_BIT(52)) | (@as(u64, @intCast(1075 - e)) << 52);
    }
    var r: f64 = undefined;
    @memcpy(std.mem.asBytes(&r), std.mem.asBytes(&m));
    return r;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3AtoF
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3AtoF(zIn: ?[*:0]const u8, pResult: *f64) callconv(.c) c_int {
    var z: [*]const u8 = @ptrCast(zIn.?);
    var neg: bool = false;
    var s: u64 = 0;
    var d: c_int = 0;
    var mState: c_int = 0;
    var v: c_uint = undefined;

    // start_of_text / parse_integer_part: use a state machine with labels
    state: switch (@as(u8, 0)) {
        // 0 == start_of_text
        0 => {
            v = @as(c_uint, z[0]) -% '0';
            if (v < 10) {
                continue :state 1; // parse_integer_part
            } else if (z[0] == '-') {
                neg = true;
                z += 1;
                v = @as(c_uint, z[0]) -% '0';
                if (v < 10) continue :state 1;
            } else if (z[0] == '+') {
                z += 1;
                v = @as(c_uint, z[0]) -% '0';
                if (v < 10) continue :state 1;
            } else if (isspace(z[0])) {
                while (true) {
                    z += 1;
                    if (!isspace(z[0])) break;
                }
                continue :state 0; // goto start_of_text
            } else {
                s = 0;
            }
        },
        1 => {
            // parse_integer_part
            mState = 1;
            s = v;
            z += 1;
            while (true) {
                v = @as(c_uint, z[0]) -% '0';
                if (v >= 10) break;
                s = s *% 10 + v;
                z += 1;
                if (s >= (LARGEST_UINT64 - 9) / 10) {
                    mState = 9;
                    while (isdigit(z[0])) {
                        z += 1;
                        d += 1;
                    }
                    break;
                }
            }
        },
        else => unreachable,
    }

    // decimal point
    if (z[0] == '.') {
        z += 1;
        if (isdigit(z[0])) {
            mState |= 1;
            while (true) {
                if (s < (LARGEST_UINT64 - 9) / 10) {
                    s = s *% 10 + (z[0] - '0');
                    d -= 1;
                } else {
                    mState = 11;
                }
                z += 1;
                if (!isdigit(z[0])) break;
            }
        } else if (mState == 0) {
            pResult.* = 0.0;
            return 0;
        }
        mState |= 2;
    } else if (mState == 0) {
        pResult.* = 0.0;
        return 0;
    }

    // exponent
    if (z[0] == 'e' or z[0] == 'E') {
        var esign: c_int = undefined;
        z += 1;
        if (z[0] == '-') {
            esign = -1;
            z += 1;
        } else {
            esign = 1;
            if (z[0] == '+') z += 1;
        }
        v = @as(c_uint, z[0]) -% '0';
        if (v < 10) {
            var exp: c_int = @intCast(v);
            z += 1;
            mState |= 2;
            while (true) {
                v = @as(c_uint, z[0]) -% '0';
                if (v >= 10) break;
                exp = if (exp < 10000) (exp * 10 + @as(c_int, @intCast(v))) else 10000;
                z += 1;
            }
            d += esign * exp;
        } else {
            z -= 1; // leave z[0] at 'e'/'+'/'-'
        }
    }

    if (s == 0) {
        pResult.* = 0.0;
        mState |= 4;
    } else {
        pResult.* = fp10Convert2(s, d);
    }
    if (neg) pResult.* = -pResult.*;

    if (z[0] == 0) {
        return mState;
    }
    if (isspace(z[0])) {
        while (true) {
            z += 1;
            if (!isspace(z[0])) break;
        }
        if (z[0] == 0) {
            return mState;
        }
    }
    return @bitCast(@as(u32, 0xfffffff0) | @as(u32, @bitCast(mState)));
}

// ════════════════════════════════════════════════════════════════════════════
// Integer rendering
// ════════════════════════════════════════════════════════════════════════════

const sqlite3DigitPairs =
    "00010203040506070809" ++
    "10111213141516171819" ++
    "20212223242526272829" ++
    "30313233343536373839" ++
    "40414243444546474849" ++
    "50515253545556575859" ++
    "60616263646566676869" ++
    "70717273747576777879" ++
    "80818283848586878889" ++
    "90919293949596979899";

export fn sqlite3Int64ToText(v: i64, zOut: ?[*]u8) callconv(.c) c_int {
    const out = zOut.?;
    var x: u64 = undefined;
    var a: [SQLITE_U64_DIGITS + 1]u8 = undefined;
    if (v > 0) {
        x = @intCast(v);
    } else if (v == 0) {
        out[0] = '0';
        out[1] = 0;
        return 1;
    } else {
        x = if (v == SMALLEST_INT64) (@as(u64, 1) << 63) else @as(u64, @intCast(-v));
    }
    var i: usize = a.len - 1;
    a[i] = 0;
    while (x >= 10) {
        const kk: usize = @as(usize, @intCast(x % 100)) * 2;
        a[i - 2] = sqlite3DigitPairs[kk];
        a[i - 1] = sqlite3DigitPairs[kk + 1];
        i -= 2;
        x /= 100;
    }
    if (x != 0) {
        i -= 1;
        a[i] = @as(u8, @intCast(x)) + '0';
    }
    if (v < 0) {
        i -= 1;
        a[i] = '-';
    }
    const n = a.len - i;
    @memcpy(out[0..n], a[i .. i + n]);
    return @intCast(a.len - 1 - i);
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3Atoi64 / DecOrHexToI64 / GetInt32 / Atoi / GetUInt32
// ════════════════════════════════════════════════════════════════════════════

fn compare2pow63(zNum: [*]const u8, incr: usize) c_int {
    var c: c_int = 0;
    const pow63 = "922337203685477580";
    var i: usize = 0;
    while (c == 0 and i < 18) : (i += 1) {
        c = (@as(c_int, zNum[i * incr]) - @as(c_int, pow63[i])) * 10;
    }
    if (c == 0) {
        c = @as(c_int, zNum[18 * incr]) - '8';
    }
    return c;
}

export fn sqlite3Atoi64(zNum_in: ?[*]const u8, pNum: *i64, length_in: c_int, enc: u8) callconv(.c) c_int {
    var zNum: [*]const u8 = zNum_in.?;
    var incr: usize = undefined;
    var u: u64 = 0;
    var neg: bool = false;
    var nonNum: bool = false;
    var length = length_in;
    var zEnd: [*]const u8 = zNum + @as(usize, @intCast(length));
    // assert enc valid
    if (enc == SQLITE_UTF8) {
        incr = 1;
    } else {
        incr = 2;
        length &= ~@as(c_int, 1);
        // for(i=3-enc; i<length && zNum[i]==0; i+=2){}
        var i: usize = @intCast(3 - @as(c_int, enc));
        while (i < @as(usize, @intCast(length)) and zNum[i] == 0) : (i += 2) {}
        nonNum = i < @as(usize, @intCast(length));
        zEnd = zNum + (i ^ 1);
        zNum += @as(usize, @intCast(enc & 1));
    }
    while (@intFromPtr(zNum) < @intFromPtr(zEnd) and isspace(zNum[0])) zNum += incr;
    if (@intFromPtr(zNum) < @intFromPtr(zEnd)) {
        if (zNum[0] == '-') {
            neg = true;
            zNum += incr;
        } else if (zNum[0] == '+') {
            zNum += incr;
        }
    }
    const zStart = zNum;
    while (@intFromPtr(zNum) < @intFromPtr(zEnd) and zNum[0] == '0') zNum += incr; // skip leading zeros
    var i: usize = 0;
    var c: c_uint = 0;
    while (@intFromPtr(zNum + i) < @intFromPtr(zEnd)) : (i += incr) {
        c = @as(c_uint, zNum[i]) -% '0';
        if (c > 9) break;
        // C accumulates in u64 with defined unsigned wrap (the magnitude is
        // re-checked afterward via compare2pow63); the `+` must wrap too.
        u = u *% 10 +% c;
    }
    if (u > @as(u64, @bitCast(LARGEST_INT64))) {
        pNum.* = if (neg) SMALLEST_INT64 else LARGEST_INT64;
    } else if (neg) {
        pNum.* = -@as(i64, @bitCast(u));
    } else {
        pNum.* = @bitCast(u);
    }
    var rc: c_int = 0;
    if (i == 0 and @intFromPtr(zStart) == @intFromPtr(zNum)) {
        rc = -1;
    } else if (nonNum) {
        rc = 1;
    } else if (@intFromPtr(zNum + i) < @intFromPtr(zEnd)) {
        var jj: usize = i;
        while (true) {
            if (!isspace(zNum[jj])) {
                rc = 1;
                break;
            }
            jj += incr;
            if (!(@intFromPtr(zNum + jj) < @intFromPtr(zEnd))) break;
        }
    }
    if (i < 19 * incr) {
        return rc;
    } else {
        const j: c_int = if (i > 19 * incr) 1 else compare2pow63(zNum, incr);
        if (j < 0) {
            return rc;
        } else {
            pNum.* = if (neg) SMALLEST_INT64 else LARGEST_INT64;
            if (j > 0) {
                return 2;
            } else {
                return if (neg) rc else 3;
            }
        }
    }
}

export fn sqlite3DecOrHexToI64(z: ?[*:0]const u8, pOut: *i64) callconv(.c) c_int {
    const s: [*:0]const u8 = z.?;
    // SQLITE_OMIT_HEX_INTEGER is OFF
    if (s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
        var u: u64 = 0;
        var i: usize = 2;
        while (s[i] == '0') i += 1;
        var k: usize = i;
        while (isxdigit(s[k])) : (k += 1) {
            u = u *% 16 +% sqlite3HexToInt(s[k]);
        }
        @memcpy(std.mem.asBytes(pOut), std.mem.asBytes(&u));
        if (k - i > 16) return 2;
        if (s[k] != 0) return 1;
        return 0;
    } else {
        // n = 0x3fffffff & strspn(z,"+- \n\t0123456789")
        const accept = "+- \n\t0123456789";
        var n: usize = 0;
        while (s[n] != 0) : (n += 1) {
            if (std.mem.indexOfScalar(u8, accept, s[n]) == null) break;
        }
        n &= 0x3fffffff;
        if (s[n] != 0) n += 1;
        return sqlite3Atoi64(@ptrCast(s), pOut, @intCast(n), SQLITE_UTF8);
    }
}

export fn sqlite3GetInt32(zNum_in: ?[*:0]const u8, pValue: *c_int) callconv(.c) c_int {
    var zNum: [*]const u8 = @ptrCast(zNum_in.?);
    var v: i64 = 0;
    var neg: c_int = 0;
    if (zNum[0] == '-') {
        neg = 1;
        zNum += 1;
    } else if (zNum[0] == '+') {
        zNum += 1;
    } else if (zNum[0] == '0' and (zNum[1] == 'x' or zNum[1] == 'X') and isxdigit(zNum[2])) {
        // SQLITE_OMIT_HEX_INTEGER OFF
        var u: u32 = 0;
        zNum += 2;
        while (zNum[0] == '0') zNum += 1;
        var i: usize = 0;
        while (i < 8 and isxdigit(zNum[i])) : (i += 1) {
            u = u *% 16 +% sqlite3HexToInt(zNum[i]);
        }
        if ((u & 0x80000000) == 0 and !isxdigit(zNum[i])) {
            @memcpy(std.mem.asBytes(pValue), std.mem.asBytes(&u));
            return 1;
        } else {
            return 0;
        }
    }
    if (!isdigit(zNum[0])) return 0;
    while (zNum[0] == '0') zNum += 1;
    var i: usize = 0;
    while (i < 11) : (i += 1) {
        const c: c_int = @as(c_int, zNum[i]) - '0';
        if (c < 0 or c > 9) break;
        v = v * 10 + c;
    }
    if (i > 10) return 0;
    if (v - neg > 2147483647) return 0;
    if (neg != 0) v = -v;
    pValue.* = @intCast(v);
    return 1;
}

export fn sqlite3Atoi(z: ?[*:0]const u8) callconv(.c) c_int {
    var x: c_int = 0;
    _ = sqlite3GetInt32(z, &x);
    return x;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3FpDecode
// ════════════════════════════════════════════════════════════════════════════

const FpDecode = extern struct {
    n: c_int,
    iDP: c_int,
    z: ?[*]u8,
    zBuf: [SQLITE_U64_DIGITS + 1]u8,
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

// A static "0" literal used for the r==0.0 case. The C code sets p->z = "0",
// a pointer to a string literal; we mirror with a module-level const buffer.
const literal_zero = [_]u8{ '0', 0 };

export fn sqlite3FpDecode(p: *FpDecode, r_in: f64, iRound_in: c_int, mxRound: c_int) callconv(.c) void {
    var r = r_in;
    var iRound = iRound_in;
    p.isSpecial = 0;
    // assert mxRound>0

    if (r < 0.0) {
        p.sign = '-';
        r = -r;
    } else if (r == 0.0) {
        p.sign = '+';
        p.n = 1;
        p.iDP = 1;
        p.z = @constCast(@ptrCast(&literal_zero[0]));
        return;
    } else {
        p.sign = '+';
    }
    var v: u64 = undefined;
    @memcpy(std.mem.asBytes(&v), std.mem.asBytes(&r));
    var e: c_int = @intCast((v >> 52) & 0x7ff);
    if (e == 0x7ff) {
        p.isSpecial = @as(u8, 1) + @intFromBool(v != 0x7ff0000000000000);
        p.n = 0;
        p.iDP = 0;
        p.z = &p.zBuf;
        return;
    }
    v &= 0x000fffffffffffff;
    if (e == 0) {
        const nn = countLeadingZeros(v);
        v <<= @intCast(nn);
        e = -1074 - nn;
    } else {
        v = (v << 11) | U64_BIT(63);
        e -= 1086;
    }

    var exp: c_int = 0;
    fp2Convert10(v, e, if (iRound <= 0 or iRound >= 18) 18 else iRound + 1, &v, &exp);

    // Extract significant digits, right to left into zBuf.
    // assert v>0
    const zBuf: [*]u8 = &p.zBuf;
    var i: usize = SQLITE_U64_DIGITS;
    while (v >= 10) {
        const kk: usize = @as(usize, @intCast(v % 100)) * 2;
        zBuf[i - 2] = sqlite3DigitPairs[kk];
        zBuf[i - 1] = sqlite3DigitPairs[kk + 1];
        i -= 2;
        v /= 100;
    }
    if (v != 0) {
        i -= 1;
        zBuf[i] = @as(u8, @intCast(v)) + '0';
    }
    var n: c_int = @intCast(SQLITE_U64_DIGITS - i);
    p.iDP = n + exp;
    if (iRound <= 0) {
        iRound = p.iDP - iRound;
        if (iRound == 0 and zBuf[i] >= '5') {
            iRound = 1;
            i -= 1;
            zBuf[i] = '0';
            n += 1;
            p.iDP += 1;
        }
    }
    // z points to the first digit
    var zi: usize = i; // index into zBuf; z == &zBuf[zi]
    if (iRound > 0 and (iRound < n or n > mxRound)) {
        if (iRound > mxRound) iRound = mxRound;
        if (iRound == 17) {
            if (zBuf[zi + 15] == '9' and zBuf[zi + 14] == '9') {
                var jj: c_int = 14;
                while (jj > 0 and zBuf[zi + @as(usize, @intCast(jj - 1))] == '9') jj -= 1;
                var v2: u64 = undefined;
                if (jj == 0) {
                    v2 = 1;
                } else {
                    v2 = zBuf[zi] - '0';
                    var kk: c_int = 1;
                    while (kk < jj) : (kk += 1) {
                        v2 = (v2 *% 10) + zBuf[zi + @as(usize, @intCast(kk))] - '0';
                    }
                    v2 += 1;
                }
                if (r == fp10Convert2(v2, exp + n - jj)) {
                    iRound = jj + 1;
                }
            } else if (p.iDP >= n or (zBuf[zi + 15] == '0' and zBuf[zi + 14] == '0' and zBuf[zi + 13] == '0')) {
                var jj: c_int = 13;
                while (zBuf[zi + @as(usize, @intCast(jj - 1))] == '0') jj -= 1;
                var v2: u64 = zBuf[zi] - '0';
                var kk: c_int = 1;
                while (kk < jj) : (kk += 1) {
                    v2 = (v2 *% 10) + zBuf[zi + @as(usize, @intCast(kk))] - '0';
                }
                if (r == fp10Convert2(v2, exp + n - jj)) {
                    iRound = jj + 1;
                }
            }
        }
        n = iRound;
        if (zBuf[zi + @as(usize, @intCast(iRound))] >= '5') {
            var j: c_int = iRound - 1;
            while (true) {
                zBuf[zi + @as(usize, @intCast(j))] += 1;
                if (zBuf[zi + @as(usize, @intCast(j))] <= '9') break;
                zBuf[zi + @as(usize, @intCast(j))] = '0';
                if (j == 0) {
                    zi -= 1;
                    zBuf[zi] = '1';
                    n += 1;
                    p.iDP += 1;
                    break;
                } else {
                    j -= 1;
                }
            }
        }
    }
    // strip trailing zeros
    while (zBuf[zi + @as(usize, @intCast(n - 1))] == '0') {
        n -= 1;
    }
    p.n = n;
    p.z = zBuf + zi;
}

// ════════════════════════════════════════════════════════════════════════════
// GetUInt32
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3GetUInt32(z: ?[*:0]const u8, pI: *u32) callconv(.c) c_int {
    const s: [*]const u8 = @ptrCast(z.?);
    var v: u64 = 0;
    var i: usize = 0;
    while (isdigit(s[i])) : (i += 1) {
        v = v *% 10 + (s[i] - '0');
        if (v > 4294967296) {
            pI.* = 0;
            return 0;
        }
    }
    if (i == 0 or s[i] != 0) {
        pI.* = 0;
        return 0;
    }
    pI.* = @intCast(v);
    return 1;
}

// ════════════════════════════════════════════════════════════════════════════
// Varint encode/decode
// ════════════════════════════════════════════════════════════════════════════

const SLOT_2_0: u32 = 0x001fc07f;
const SLOT_4_2_0: u32 = 0xf01fc07f;

fn putVarint64(p: [*]u8, v_in: u64) c_int {
    var v = v_in;
    var buf: [10]u8 = undefined;
    if ((v & (@as(u64, 0xff000000) << 32)) != 0) {
        p[8] = @truncate(v);
        v >>= 8;
        var i: i32 = 7;
        while (i >= 0) : (i -= 1) {
            p[@intCast(i)] = @as(u8, @truncate(v & 0x7f)) | 0x80;
            v >>= 7;
        }
        return 9;
    }
    var n: usize = 0;
    while (true) {
        buf[n] = @as(u8, @truncate(v & 0x7f)) | 0x80;
        n += 1;
        v >>= 7;
        if (v == 0) break;
    }
    buf[0] &= 0x7f;
    var i: usize = 0;
    var j: i32 = @as(i32, @intCast(n)) - 1;
    while (j >= 0) : ({
        j -= 1;
        i += 1;
    }) {
        p[i] = buf[@intCast(j)];
    }
    return @intCast(n);
}

export fn sqlite3PutVarint(p: ?[*]u8, v: u64) callconv(.c) c_int {
    const pp = p.?;
    if (v <= 0x7f) {
        pp[0] = @as(u8, @truncate(v)) & 0x7f;
        return 1;
    }
    if (v <= 0x3fff) {
        pp[0] = @as(u8, @truncate(v >> 7)) & 0x7f | 0x80;
        pp[1] = @as(u8, @truncate(v)) & 0x7f;
        return 2;
    }
    return putVarint64(pp, v);
}

export fn sqlite3GetVarint(p_in: ?[*]const u8, v: *u64) callconv(.c) u8 {
    var p: [*]const u8 = p_in.?;
    var a: u32 = undefined;
    var b: u32 = undefined;
    var s: u32 = undefined;

    if (@as(i8, @bitCast(p[0])) >= 0) {
        v.* = p[0];
        return 1;
    }
    if (@as(i8, @bitCast(p[1])) >= 0) {
        v.* = (@as(u32, p[0] & 0x7f) << 7) | p[1];
        return 2;
    }

    a = @as(u32, p[0]) << 14;
    b = p[1];
    p += 2;
    a |= p[0];
    if ((a & 0x80) == 0) {
        a &= SLOT_2_0;
        b &= 0x7f;
        b = b << 7;
        a |= b;
        v.* = a;
        return 3;
    }

    a &= SLOT_2_0;
    p += 1;
    b = b << 14;
    b |= p[0];
    if ((b & 0x80) == 0) {
        b &= SLOT_2_0;
        a = a << 7;
        a |= b;
        v.* = a;
        return 4;
    }

    b &= SLOT_2_0;
    s = a;

    p += 1;
    a = a << 14;
    a |= p[0];
    if ((a & 0x80) == 0) {
        b = b << 7;
        a |= b;
        s = s >> 18;
        v.* = (@as(u64, s) << 32) | a;
        return 5;
    }

    s = s << 7;
    s |= b;

    p += 1;
    b = b << 14;
    b |= p[0];
    if ((b & 0x80) == 0) {
        a &= SLOT_2_0;
        a = a << 7;
        a |= b;
        s = s >> 18;
        v.* = (@as(u64, s) << 32) | a;
        return 6;
    }

    p += 1;
    a = a << 14;
    a |= p[0];
    if ((a & 0x80) == 0) {
        a &= SLOT_4_2_0;
        b &= SLOT_2_0;
        b = b << 7;
        a |= b;
        s = s >> 11;
        v.* = (@as(u64, s) << 32) | a;
        return 7;
    }

    a &= SLOT_2_0;
    p += 1;
    b = b << 14;
    b |= p[0];
    if ((b & 0x80) == 0) {
        b &= SLOT_4_2_0;
        a = a << 7;
        a |= b;
        s = s >> 4;
        v.* = (@as(u64, s) << 32) | a;
        return 8;
    }

    p += 1;
    a = a << 15;
    a |= p[0];

    b &= SLOT_2_0;
    b = b << 8;
    a |= b;

    s = s << 4;
    b = (p - 4)[0];
    b &= 0x7f;
    b = b >> 3;
    s |= b;

    v.* = (@as(u64, s) << 32) | a;

    return 9;
}

export fn sqlite3GetVarint32(p_in: ?[*]const u8, v: *u32) callconv(.c) u8 {
    const p: [*]const u8 = p_in.?;
    // assert (p[0]&0x80)!=0 — single-byte case handled by getVarint32 macro
    if ((p[1] & 0x80) == 0) {
        v.* = (@as(u32, p[0] & 0x7f) << 7) | p[1];
        return 2;
    }
    if ((p[2] & 0x80) == 0) {
        v.* = (@as(u32, p[0] & 0x7f) << 14) | (@as(u32, p[1] & 0x7f) << 7) | p[2];
        return 3;
    }
    var v64: u64 = undefined;
    const n = sqlite3GetVarint(p_in, &v64);
    if ((v64 & SQLITE_MAX_U32) != v64) {
        v.* = 0xffffffff;
    } else {
        v.* = @truncate(v64);
    }
    return n;
}

export fn sqlite3VarintLen(v_in: u64) callconv(.c) c_int {
    // C: for(i=1; (v >>= 7)!=0; i++){ assert(i<10); } return i;
    // The shift happens in the loop condition (before the i++), so the body is
    // empty and i is incremented once per nonzero post-shift value.
    var v = v_in;
    var i: c_int = 1;
    while (true) {
        v >>= 7;
        if (v == 0) break;
        i += 1;
    }
    return i;
}

// ════════════════════════════════════════════════════════════════════════════
// Get4byte / Put4byte (big-endian, SQLITE_BYTEORDER fallback path)
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3Get4byte(p: ?[*]const u8) callconv(.c) u32 {
    const s = p.?;
    return (@as(u32, s[0]) << 24) | (@as(u32, s[1]) << 16) | (@as(u32, s[2]) << 8) | s[3];
}

export fn sqlite3Put4byte(p: ?[*]u8, v: u32) callconv(.c) void {
    const s = p.?;
    s[0] = @truncate(v >> 24);
    s[1] = @truncate(v >> 16);
    s[2] = @truncate(v >> 8);
    s[3] = @truncate(v);
}

// ════════════════════════════════════════════════════════════════════════════
// Hex helpers
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3HexToInt(h_in: c_int) callconv(.c) u8 {
    // SQLITE_ASCII: h += 9*(1&(h>>6))
    const h = h_in + 9 * (1 & (h_in >> 6));
    return @intCast(h & 0xf);
}

export fn sqlite3HexToBlob(db: ?*anyopaque, z: ?[*]const u8, n_in: c_int) callconv(.c) ?*anyopaque {
    const zHex = z.?;
    const zBlob: ?[*]u8 = @ptrCast(sqlite3DbMallocRawNN(db, @intCast(@divTrunc(n_in, 2) + 1)));
    const n = n_in - 1;
    if (zBlob) |blob| {
        var i: c_int = 0;
        while (i < n) : (i += 2) {
            const hi = sqlite3HexToInt(zHex[@intCast(i)]);
            const lo = sqlite3HexToInt(zHex[@intCast(i + 1)]);
            blob[@intCast(@divTrunc(i, 2))] = (hi << 4) | lo;
        }
        blob[@intCast(@divTrunc(i, 2))] = 0;
    }
    return @ptrCast(zBlob);
}

// ════════════════════════════════════════════════════════════════════════════
// Safety checks
// ════════════════════════════════════════════════════════════════════════════

fn logBadConnection(zType: [*:0]const u8) void {
    sqlite3_log(SQLITE_MISUSE, "API call with %s database connection pointer", zType);
}

export fn sqlite3SafetyCheckOk(db: ?*anyopaque) callconv(.c) c_int {
    if (db == null) {
        logBadConnection("NULL");
        return 0;
    }
    const eOpenState = getField(u8, db, off_eOpenState);
    if (eOpenState != SQLITE_STATE_OPEN) {
        if (sqlite3SafetyCheckSickOrOk(db) != 0) {
            logBadConnection("unopened");
        }
        return 0;
    } else {
        return 1;
    }
}

export fn sqlite3SafetyCheckSickOrOk(db: ?*anyopaque) callconv(.c) c_int {
    const eOpenState = getField(u8, db, off_eOpenState);
    if (eOpenState != SQLITE_STATE_SICK and
        eOpenState != SQLITE_STATE_OPEN and
        eOpenState != SQLITE_STATE_BUSY)
    {
        logBadConnection("invalid");
        return 0;
    } else {
        return 1;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 64-bit overflow math (use Zig overflow builtins == C __builtin_*_overflow)
// ════════════════════════════════════════════════════════════════════════════

// NOTE: under `zig cc` (clang reports GCC_VERSION 4002001 < 5004000), the
// production C build compiles the *fallback* (non-__builtin) path of these
// routines, which LEAVES *pA UNCHANGED on overflow (returns 1). We replicate
// the exact fallback algorithm — not @addWithOverflow, which would write the
// wrapped result on overflow.
export fn sqlite3AddInt64(pA: *i64, iB: i64) callconv(.c) c_int {
    const iA = pA.*;
    if (iB >= 0) {
        if (iA > 0 and LARGEST_INT64 - iA < iB) return 1;
    } else {
        if (iA < 0 and -(iA + LARGEST_INT64) > iB + 1) return 1;
    }
    pA.* = iA +% iB;
    return 0;
}

export fn sqlite3SubInt64(pA: *i64, iB: i64) callconv(.c) c_int {
    if (iB == SMALLEST_INT64) {
        if (pA.* >= 0) return 1;
        pA.* -%= iB;
        return 0;
    } else {
        return sqlite3AddInt64(pA, -iB);
    }
}

export fn sqlite3MulInt64(pA: *i64, iB: i64) callconv(.c) c_int {
    const iA = pA.*;
    if (iB > 0) {
        if (iA > @divTrunc(LARGEST_INT64, iB)) return 1;
        if (iA < @divTrunc(SMALLEST_INT64, iB)) return 1;
    } else if (iB < 0) {
        if (iA > 0) {
            if (iB < @divTrunc(SMALLEST_INT64, iA)) return 1;
        } else if (iA < 0) {
            if (iB == SMALLEST_INT64) return 1;
            if (iA == SMALLEST_INT64) return 1;
            if (-iA > @divTrunc(LARGEST_INT64, -iB)) return 1;
        }
    }
    pA.* = iA *% iB;
    return 0;
}

export fn sqlite3AbsInt32(x: c_int) callconv(.c) c_int {
    if (x >= 0) return x;
    if (x == @as(c_int, @bitCast(@as(u32, 0x80000000)))) return 0x7fffffff;
    return -x;
}

// ════════════════════════════════════════════════════════════════════════════
// LogEst
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3LogEstAdd(a: i16, b: i16) callconv(.c) i16 {
    const x = [_]u8{
        10, 10,
        9,  9,
        8,  8,
        7,  7, 7,
        6,  6, 6,
        5,  5, 5,
        4,  4, 4, 4,
        3,  3, 3, 3, 3, 3,
        2,  2, 2, 2, 2, 2, 2,
    };
    if (a >= b) {
        if (a > b + 49) return a;
        if (a > b + 31) return a + 1;
        return a + x[@intCast(a - b)];
    } else {
        if (b > a + 49) return b;
        if (b > a + 31) return b + 1;
        return b + x[@intCast(b - a)];
    }
}

export fn sqlite3LogEst(x_in: u64) callconv(.c) i16 {
    const a = [_]i16{ 0, 2, 3, 5, 6, 7, 8, 9 };
    var x = x_in;
    var y: i16 = 40;
    if (x < 8) {
        if (x < 2) return 0;
        while (x < 8) {
            y -= 10;
            x <<= 1;
        }
    } else {
        // GCC_VERSION>=5004000 path: __builtin_clzll
        const i: c_int = 60 - @clz(x);
        y += @intCast(i * 10);
        x >>= @intCast(i);
    }
    return a[@intCast(x & 7)] + y - 10;
}

export fn sqlite3LogEstFromDouble(x: f64) callconv(.c) i16 {
    if (x <= 1) return 0;
    if (x <= 2000000000) return sqlite3LogEst(@intFromFloat(x));
    var a: u64 = undefined;
    @memcpy(std.mem.asBytes(&a), std.mem.asBytes(&x));
    const e: i64 = @as(i64, @intCast(a >> 52)) - 1022;
    return @intCast(e * 10);
}

export fn sqlite3LogEstToInt(x_in: i16) callconv(.c) u64 {
    // C: u64 n = x%10; x/=10; ... where x is LogEst(i16) and % is C-truncated.
    // The assignment n = x%10 widens a possibly-negative i16 to u64 by sign
    // extension (two's-complement), so we mirror via i64 -> @bitCast(u64).
    var x: c_int = x_in;
    var n: u64 = @bitCast(@as(i64, @rem(x, 10)));
    x = @divTrunc(x, 10);
    // Comparisons against unsigned literals: n>=5 / n>=1 (n is u64).
    if (n >= 5) {
        n -%= 2;
    } else if (n >= 1) {
        n -%= 1;
    }
    if (x > 60) return @bitCast(LARGEST_INT64);
    // Shift counts: C uses (x-3) and (3-x) as int; for in-range LogEst these are
    // 0..63. Mask to 6 bits to match C's well-defined-range usage (x in [-?,60]).
    if (x >= 3) {
        return (n +% 8) << @intCast(@as(c_int, x - 3) & 63);
    } else {
        return (n +% 8) >> @intCast(@as(c_int, 3 - x) & 63);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// VList
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3VListAdd(
    db: ?*anyopaque,
    pIn_in: ?[*]c_int,
    zName: ?[*]const u8,
    nName: c_int,
    iVal: c_int,
) callconv(.c) ?[*]c_int {
    var pIn = pIn_in;
    const nInt: c_int = @divTrunc(nName, 4) + 3;
    // assert pIn==0 || pIn[0]>=3
    if (pIn == null or pIn.?[1] + nInt > pIn.?[0]) {
        const nAlloc: i64 = (if (pIn != null) 2 * @as(i64, pIn.?[0]) else 10) + nInt;
        const pOut: ?[*]c_int = @ptrCast(@alignCast(sqlite3DbRealloc(
            db,
            @ptrCast(pIn),
            @as(u64, @intCast(nAlloc)) * @sizeOf(c_int),
        )));
        if (pOut == null) return pIn;
        if (pIn == null) pOut.?[1] = 2;
        pIn = pOut;
        pIn.?[0] = @intCast(nAlloc);
    }
    const arr = pIn.?;
    const i: usize = @intCast(arr[1]);
    arr[i] = iVal;
    arr[i + 1] = nInt;
    const z: [*]u8 = @ptrCast(&arr[i + 2]);
    arr[1] = @as(c_int, @intCast(i)) + nInt;
    // assert arr[1]<=arr[0]
    if (nName > 0) {
        @memcpy(z[0..@intCast(nName)], zName.?[0..@intCast(nName)]);
    }
    z[@intCast(nName)] = 0;
    return pIn;
}

export fn sqlite3VListNumToName(pIn: ?[*]c_int, iVal: c_int) callconv(.c) ?[*:0]const u8 {
    if (pIn == null) return null;
    const arr = pIn.?;
    const mx: usize = @intCast(arr[1]);
    var i: usize = 2;
    while (true) {
        if (arr[i] == iVal) return @ptrCast(&arr[i + 2]);
        i += @intCast(arr[i + 1]);
        if (!(i < mx)) break;
    }
    return null;
}

export fn sqlite3VListNameToNum(pIn: ?[*]c_int, zName: ?[*]const u8, nName: c_int) callconv(.c) c_int {
    if (pIn == null) return 0;
    const arr = pIn.?;
    const name: [*]const u8 = zName.?;
    const nn: usize = @intCast(nName);
    const mx: usize = @intCast(arr[1]);
    var i: usize = 2;
    while (true) {
        const z: [*]const u8 = @ptrCast(&arr[i + 2]);
        // strncmp(z,zName,nName)==0 && z[nName]==0
        if (std.mem.eql(u8, z[0..nn], name[0..nn]) and z[nn] == 0) return arr[i];
        i += @intCast(arr[i + 1]);
        if (!(i < mx)) break;
    }
    return 0;
}
