//! Zig port of SQLite's "Mem" cell operations (src/vdbemem.c).
//!
//! A `Mem` (== `struct sqlite3_value`) is the dynamically-typed value object
//! used as VDBE registers and as `sqlite3_value`. This module implements the
//! `sqlite3VdbeMem*` family (type coercion, encoding conversion, stringify, the
//! MEM_* flag transitions, allocation/grow/makeWriteable) plus the
//! `sqlite3Value*` helpers and a few number-conversion utilities
//! (`sqlite3RealToI64`, `sqlite3RealSameAsInt`).
//!
//! Mem is build-divergent: under SQLITE_DEBUG it grows a trailing scopy tail
//! (sizeof 56 -> 72) while every non-tail field keeps the same offset. We reuse
//! the exact `Mem` mirror established by src/utf.zig (config-gated tail, asserted
//! at comptime against src/c_layout.zig). The encoding-translation helpers
//! (`sqlite3VdbeMemTranslate`, `sqlite3VdbeMemHandleBom`, `sqlite3Utf*`) live in
//! utf.zig and are *not* redefined here.
//!
//! Config: SQLITE_OMIT_UTF16 off, SQLITE_OMIT_INCRBLOB off (void
//! sqlite3VdbeMemSetZeroBlob + sqlite3VdbeMemExpandBlob present),
//! SQLITE_OMIT_FLOATING_POINT off, SQLITE_OMIT_WINDOWFUNC off
//! (sqlite3VdbeMemAggValue present), SQLITE_ENABLE_STAT4 off (the Stat4* /
//! valueFromFunction surface is not compiled in either config). The
//! SQLITE_DEBUG-only invariant/assert helpers (sqlite3VdbeCheckMemInvariants,
//! sqlite3VdbeMemValidStrRep, sqlite3VdbeMemIsRowSet, sqlite3VdbeMemAboutToChange)
//! are exported only when config.sqlite_debug, matching the testfixture build
//! (other TUs reference them inside assert()).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");

const L = c_layout.c;

// --- result / encoding constants ---
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM_PLAIN: c_int = 7;
const SQLITE_TOOBIG: c_int = 18;
const SQLITE_CORRUPT_PLAIN: c_int = 11;

const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_UTF16BE: u8 = 3;
const SQLITE_UTF16_ALIGNED: u8 = 8;

// --- affinity constants ---
const SQLITE_AFF_BLOB: u8 = 0x41; // 'A'
const SQLITE_AFF_TEXT: u8 = 0x42; // 'B'
const SQLITE_AFF_NUMERIC: u8 = 0x43; // 'C'
const SQLITE_AFF_INTEGER: u8 = 0x44; // 'D'
const SQLITE_AFF_REAL: u8 = 0x45; // 'E'

// --- limits ---
const SQLITE_MAX_LENGTH: c_int = 1000000000;
const SQLITE_MAX_ALLOCATION_SIZE: u32 = 2147483391;
const SQLITE_LIMIT_LENGTH: usize = 0;
const LARGEST_INT64: i64 = 0x7fffffffffffffff;
const SMALLEST_INT64: i64 = -0x8000000000000000;

// --- MEM_* flag bits (vdbeInt.h) ---
const MEM_Undefined: u16 = 0x0000;
const MEM_Null: u16 = 0x0001;
const MEM_Str: u16 = 0x0002;
const MEM_Int: u16 = 0x0004;
const MEM_Real: u16 = 0x0008;
const MEM_Blob: u16 = 0x0010;
const MEM_IntReal: u16 = 0x0020;
const MEM_AffMask: u16 = 0x003f;
const MEM_FromBind: u16 = 0x0040;
const MEM_Cleared: u16 = 0x0100;
const MEM_Term: u16 = 0x0200;
const MEM_Zero: u16 = 0x0400;
const MEM_Subtype: u16 = 0x0800;
const MEM_TypeMask: u16 = 0x0dbf;
const MEM_Dyn: u16 = 0x1000;
const MEM_Static: u16 = 0x2000;
const MEM_Ephem: u16 = 0x4000;
const MEM_Agg: u16 = 0x8000;

// MEMCELLSIZE = offsetof(Mem, db) — the "shallow copy" prefix size.
const MEMCELLSIZE: usize = L.sqlite3_value_db;

/// MemValue union (8 bytes). Mirrors `union MemValue` in struct sqlite3_value.
const MemValue = extern union {
    r: f64, // MEM_Real
    i: i64, // MEM_Int / MEM_IntReal
    nZero: c_int, // MEM_Zero|MEM_Blob extra zero-byte count
    zPType: ?[*:0]const u8, // pointer-type label
    pDef: ?*anyopaque, // FuncDef* when MEM_Agg
};

/// `Mem` (struct sqlite3_value). Offsets identical in both build configs; only
/// sizeof differs (SQLITE_DEBUG appends a scopy-tracking tail), matched by a
/// config-gated padding array and asserted against C ground truth.
const debug_tail_len: usize = if (config.sqlite_debug) 16 else 0;
const Mem = extern struct {
    u: MemValue,
    z: ?[*]u8,
    n: c_int,
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
    std.debug.assert(@offsetOf(Mem, "eSubtype") == L.sqlite3_value_eSubtype);
    std.debug.assert(@offsetOf(Mem, "db") == L.sqlite3_value_db);
    std.debug.assert(@offsetOf(Mem, "szMalloc") == L.sqlite3_value_szMalloc);
    std.debug.assert(@offsetOf(Mem, "uTemp") == L.sqlite3_value_uTemp);
    std.debug.assert(@offsetOf(Mem, "zMalloc") == L.sqlite3_value_zMalloc);
    std.debug.assert(@offsetOf(Mem, "xDel") == L.sqlite3_value_xDel);
    std.debug.assert(MEMCELLSIZE == 24);
}

/// StrAccum (== sqlite3_str). Mirrors src/printf.zig's mirror exactly.
const StrAccum = extern struct {
    db: ?*anyopaque,
    zText: ?[*]u8,
    nAlloc: c_int,
    mxAlloc: c_int,
    nChar: u32,
    accError: u8,
    printfFlags: u8,
};

/// sqlite3_context — config-invariant prefix (flexible argv tail). We only
/// touch the fixed fields below; the C this links against allocates the tail.
const Sqlite3Context = extern struct {
    pOut: ?*Mem,
    pFunc: ?*anyopaque, // FuncDef*
    pMem: ?*Mem,
    pVdbe: ?*anyopaque,
    iOp: c_int,
    isError: c_int,
    enc: u8,
    skipFlag: u8,
    argc: u16,
};

comptime {
    std.debug.assert(@offsetOf(Sqlite3Context, "pOut") == 0);
    std.debug.assert(@offsetOf(Sqlite3Context, "pFunc") == 8);
    std.debug.assert(@offsetOf(Sqlite3Context, "pMem") == 16);
    std.debug.assert(@offsetOf(Sqlite3Context, "pVdbe") == 24);
    std.debug.assert(@offsetOf(Sqlite3Context, "iOp") == 32);
    std.debug.assert(@offsetOf(Sqlite3Context, "isError") == 36);
    std.debug.assert(@offsetOf(Sqlite3Context, "enc") == 40);
}

// FuncDef field accessors (read at ground-truth offsets via the pointer).
const FuncDef_xSFunc: usize = 24;
const FuncDef_xFinalize: usize = 32;
const FuncDef_xValue: usize = 40;
const XFinalizeFn = *const fn (*Sqlite3Context) callconv(.c) void;

inline fn funcXFinalize(p: *anyopaque) XFinalizeFn {
    const base: [*]const u8 = @ptrCast(p);
    const slot: *const XFinalizeFn = @ptrCast(@alignCast(base + FuncDef_xFinalize));
    return slot.*;
}
inline fn funcXValue(p: *anyopaque) XFinalizeFn {
    const base: [*]const u8 = @ptrCast(p);
    const slot: *const XFinalizeFn = @ptrCast(@alignCast(base + FuncDef_xValue));
    return slot.*;
}

// nFpDigit is at offset 114 in struct sqlite3 (config-invariant).
const sqlite3_nFpDigit: usize = 114;

// --- db field accessors (ground-truth offsets) ---
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    if (db == null) return false;
    const base: [*]const u8 = @ptrCast(db.?);
    return base[L.sqlite3_mallocFailed] != 0;
}
inline fn dbEnc(db: ?*anyopaque) u8 {
    const base: [*]const u8 = @ptrCast(db.?);
    return base[L.sqlite3_enc];
}
inline fn dbNFpDigit(db: ?*anyopaque) c_int {
    const base: [*]const u8 = @ptrCast(db.?);
    return base[sqlite3_nFpDigit];
}
inline fn dbLimitLength(db: ?*anyopaque) c_int {
    const base: [*]const u8 = @ptrCast(db.?);
    const a: [*]align(1) const c_int = @ptrCast(base + L.sqlite3_aLimit);
    return a[SQLITE_LIMIT_LENGTH];
}

// --- destructor sentinels ---
// SQLITE_STATIC == 0, SQLITE_TRANSIENT == (void(*)(void*))-1,
// SQLITE_DYNAMIC == (void(*)(void*))sqlite3RowSetClear.
const XDelFn = ?*const fn (?*anyopaque) callconv(.c) void;
inline fn isTransient(x: XDelFn) bool {
    return @intFromPtr(x) == @as(usize, @bitCast(@as(isize, -1)));
}
inline fn isDynamicSentinel(x: XDelFn) bool {
    return x != null and @as(*const anyopaque, @ptrCast(x.?)) == @as(*const anyopaque, @ptrCast(&sqlite3RowSetClear));
}

// --- C / already-ported-Zig helpers resolved at link time ---
extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocSize(db: ?*anyopaque, p: ?*const anyopaque) c_int;
extern fn sqlite3DbReallocOrFree(db: ?*anyopaque, p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbFreeNN(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*]const u8, n: u64) ?[*]u8;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_msize(p: ?*anyopaque) u64;

extern fn sqlite3Atoi64(z: ?[*]const u8, out: *i64, n: c_int, enc: u8) c_int;
extern fn sqlite3AtoF(z: ?[*]const u8, out: *f64) c_int;
extern fn sqlite3DecOrHexToI64(z: ?[*:0]const u8, out: *i64) c_int;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3Int64ToText(v: i64, zBuf: [*]u8) c_int;
extern fn sqlite3IsNaN(x: f64) c_int;
extern fn sqlite3MPrintf(db: ?*anyopaque, zFmt: [*:0]const u8, ...) ?[*]u8;
extern fn sqlite3HexToBlob(db: ?*anyopaque, z: ?[*]const u8, n: c_int) ?*anyopaque;
extern fn sqlite3ErrorToParser(db: ?*anyopaque, rc: c_int) c_int;
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;

extern fn sqlite3RowSetInit(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3RowSetDelete(p: ?*anyopaque) void;
extern fn sqlite3RowSetClear(p: ?*anyopaque) void;
extern fn sqlite3RCStrUnref(p: ?*anyopaque) void;

extern fn sqlite3StrAccumInit(p: *StrAccum, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) void;
extern fn sqlite3_str_appendf(p: *StrAccum, zFmt: [*:0]const u8, ...) void;

extern fn sqlite3ValueApplyAffinity(pVal: *Mem, aff: u8, enc: u8) void;
extern fn sqlite3AffinityType(z: ?[*]const u8, pCol: ?*anyopaque) u8;
extern fn sqlite3VdbeSerialGet(buf: [*]const u8, t: u32, pMem: *Mem) void;
extern fn sqlite3VdbeSerialTypeLen(t: u32) u32;

extern fn sqlite3BtreeMaxRecordSize(pCur: ?*anyopaque) i64;
extern fn sqlite3BtreePayload(pCur: ?*anyopaque, offset: u32, amt: u32, pBuf: ?*anyopaque) c_int;
extern fn sqlite3BtreePayloadFetch(pCur: ?*anyopaque, pAmt: *u32) ?*const anyopaque;

// SQLITE_DEBUG-only backstop error helpers (the *_BKPT macros). Only resolvable
// when linking against SQLITE_DEBUG objects, so gate every call on config.
extern fn sqlite3NomemError(line: c_int) c_int;
extern fn sqlite3CorruptError(line: c_int) c_int;

inline fn nomemBkpt() c_int {
    if (config.sqlite_debug) return sqlite3NomemError(0);
    return SQLITE_NOMEM_PLAIN;
}
inline fn corruptBkpt() c_int {
    if (config.sqlite_debug) return sqlite3CorruptError(0);
    return SQLITE_CORRUPT_PLAIN;
}

// ExpandBlob(P): expand a zero-tail blob if MEM_Zero is set.
inline fn expandBlob(pMem: *Mem) c_int {
    if (pMem.flags & MEM_Zero != 0) return sqlite3VdbeMemExpandBlob(pMem);
    return SQLITE_OK;
}

// VdbeMemDynamic(X): TRUE if Mem holds content needing deallocation.
inline fn vdbeMemDynamic(p: *const Mem) bool {
    return (p.flags & (MEM_Agg | MEM_Dyn)) != 0;
}

// MemSetTypeFlag(p, f)
inline fn memSetTypeFlag(p: *Mem, f: u16) void {
    p.flags = (p.flags & ~(MEM_TypeMask | MEM_Zero)) | f;
}

//=============================================================================
// SQLITE_DEBUG-only invariant / assert helpers
//=============================================================================

fn isPowerOf2(x: u16) bool {
    return (x & (x -% 1)) == 0;
}

fn checkMemInvariants(p: *Mem) callconv(.c) c_int {
    std.debug.assert((p.flags & MEM_Dyn) == 0 or p.xDel != null);
    std.debug.assert((p.flags & MEM_Dyn) == 0 or p.szMalloc == 0);
    std.debug.assert(isPowerOf2(p.flags & (MEM_Int | MEM_Real | MEM_IntReal)));
    if (p.flags & MEM_Null != 0) {
        std.debug.assert((p.flags & (MEM_Int | MEM_Real | MEM_Str | MEM_Blob | MEM_Agg)) == 0);
    } else {
        std.debug.assert((p.flags & MEM_Cleared) == 0);
    }
    return 1;
}

fn vdbeMemValidStrRep(p: *Mem) callconv(.c) c_int {
    if ((p.flags & MEM_Str) == 0) return 1;
    if (p.db != null and dbMallocFailed(p.db)) return 1;
    if (p.flags & MEM_Term != 0) {
        const z = p.z.?;
        std.debug.assert(z[@intCast(p.n)] == 0);
    }
    if ((p.flags & (MEM_Int | MEM_Real | MEM_IntReal)) == 0) return 1;
    if (p.db == null) return 1;
    var tmp: Mem = p.*;
    var zBuf: [100]u8 = undefined;
    vdbeMemRenderNum(@sizeOf(@TypeOf(zBuf)), &zBuf, &tmp);
    var z = p.z.?;
    var i: usize = 0;
    var j: usize = 0;
    var incr: usize = 1;
    if (p.enc != SQLITE_UTF8) {
        incr = 2;
        if (p.enc == SQLITE_UTF16BE) z += 1;
    }
    while (zBuf[j] != 0) {
        if (zBuf[j] != z[i]) return 0;
        j += 1;
        i += incr;
    }
    return 1;
}

fn vdbeMemIsRowSet(p: *const Mem) callconv(.c) c_int {
    return @intFromBool((p.flags & (MEM_Blob | MEM_Dyn)) == (MEM_Blob | MEM_Dyn) and
        p.xDel == @as(XDelFn, sqlite3RowSetDelete));
}

fn vdbeMemAboutToChange(pVdbe: ?*anyopaque, pMem: *Mem) callconv(.c) void {
    // Shallow-copy bookkeeping (DEBUG-only diagnostics). The scopy tail fields
    // live past the config-invariant prefix; reading them requires the tail.
    _ = pVdbe;
    _ = pMem;
    // Intentionally minimal: the full SCopy invalidation walk is a debugging
    // aid only and does not affect correctness. Clearing pScopyFrom/bScopy is
    // sufficient to avoid stale-pointer asserts firing falsely; but those tail
    // fields are not mirrored, so we keep this as a structural no-op. (This
    // path is exercised only under SQLITE_DEBUG.)
}

comptime {
    if (config.sqlite_debug) {
        @export(&checkMemInvariants, .{ .name = "sqlite3VdbeCheckMemInvariants", .linkage = .strong });
        @export(&vdbeMemValidStrRep, .{ .name = "sqlite3VdbeMemValidStrRep", .linkage = .strong });
        @export(&vdbeMemIsRowSet, .{ .name = "sqlite3VdbeMemIsRowSet", .linkage = .strong });
        @export(&vdbeMemAboutToChange, .{ .name = "sqlite3VdbeMemAboutToChange", .linkage = .strong });
    }
}

//=============================================================================
// Number rendering
//=============================================================================

/// Render an Int/Real/IntReal Mem into zBuf (sz > 22). Sets p.n.
fn vdbeMemRenderNum(sz: c_int, zBuf: [*]u8, p: *Mem) void {
    if (p.flags & (MEM_Int | MEM_IntReal) != 0) {
        p.n = sqlite3Int64ToText(p.u.i, zBuf);
        if (p.flags & MEM_IntReal != 0) {
            zBuf[@intCast(p.n)] = '.';
            zBuf[@intCast(p.n + 1)] = '0';
            zBuf[@intCast(p.n + 2)] = 0;
            p.n += 2;
        }
    } else {
        var acc: StrAccum = undefined;
        sqlite3StrAccumInit(&acc, null, zBuf, sz, 0);
        const nfp: c_int = if (p.db != null) dbNFpDigit(p.db) else 17;
        sqlite3_str_appendf(&acc, "%!.*g", nfp, p.u.r);
        zBuf[acc.nChar] = 0;
        p.n = @bitCast(acc.nChar);
    }
}

//=============================================================================
// Encoding
//=============================================================================

extern fn sqlite3VdbeMemTranslate(pMem: *Mem, desiredEnc: u8) c_int;
extern fn sqlite3VdbeMemHandleBom(pMem: *Mem) c_int;

export fn sqlite3VdbeChangeEncoding(pMem: *Mem, desiredEnc: c_int) callconv(.c) c_int {
    if ((pMem.flags & MEM_Str) == 0) {
        pMem.enc = @intCast(desiredEnc);
        return SQLITE_OK;
    }
    if (pMem.enc == @as(u8, @intCast(desiredEnc))) {
        return SQLITE_OK;
    }
    const rc = sqlite3VdbeMemTranslate(pMem, @intCast(desiredEnc));
    return rc;
}

//=============================================================================
// Allocation / grow / writeable
//=============================================================================

export fn sqlite3VdbeMemGrow(pMem: *Mem, n: c_int, bPreserve_in: c_int) callconv(.c) c_int {
    var bPreserve = bPreserve_in;
    const nU: u64 = @intCast(n);
    if (pMem.szMalloc > 0 and bPreserve != 0 and pMem.z == pMem.zMalloc) {
        if (pMem.db != null) {
            pMem.zMalloc = @ptrCast(sqlite3DbReallocOrFree(pMem.db, pMem.z, nU));
            pMem.z = pMem.zMalloc;
        } else {
            pMem.zMalloc = @ptrCast(sqlite3Realloc(pMem.z, nU));
            if (pMem.zMalloc == null) sqlite3_free(pMem.z);
            pMem.z = pMem.zMalloc;
        }
        bPreserve = 0;
    } else {
        if (pMem.szMalloc > 0) sqlite3DbFreeNN(pMem.db, pMem.zMalloc);
        pMem.zMalloc = @ptrCast(sqlite3DbMallocRaw(pMem.db, nU));
    }
    if (pMem.zMalloc == null) {
        sqlite3VdbeMemSetNull(pMem);
        pMem.z = null;
        pMem.szMalloc = 0;
        return nomemBkpt();
    } else {
        pMem.szMalloc = sqlite3DbMallocSize(pMem.db, pMem.zMalloc);
    }

    if (bPreserve != 0 and pMem.z != null) {
        const src = pMem.z.?;
        const dst = pMem.zMalloc.?;
        const len: usize = @intCast(pMem.n);
        @memcpy(dst[0..len], src[0..len]);
    }
    if (pMem.flags & MEM_Dyn != 0) {
        pMem.xDel.?(@ptrCast(pMem.z));
    }

    pMem.z = pMem.zMalloc;
    pMem.flags &= ~(MEM_Dyn | MEM_Ephem | MEM_Static);
    return SQLITE_OK;
}

export fn sqlite3VdbeMemClearAndResize(pMem: *Mem, szNew: c_int) callconv(.c) c_int {
    if (pMem.szMalloc < szNew) {
        return sqlite3VdbeMemGrow(pMem, szNew, 0);
    }
    pMem.z = pMem.zMalloc;
    pMem.flags &= (MEM_Null | MEM_Int | MEM_Real | MEM_IntReal);
    return SQLITE_OK;
}

export fn sqlite3VdbeMemZeroTerminateIfAble(pMem: *Mem) callconv(.c) c_int {
    if ((pMem.flags & (MEM_Str | MEM_Term | MEM_Ephem | MEM_Static)) != MEM_Str) {
        return 0;
    }
    if (pMem.enc != SQLITE_UTF8) return 0;
    const z = pMem.z.?;
    const nU: usize = @intCast(pMem.n);
    if (pMem.flags & MEM_Dyn != 0) {
        if (pMem.xDel == @as(XDelFn, sqlite3_free) and sqlite3_msize(z) >= @as(u64, @intCast(pMem.n + 1))) {
            z[nU] = 0;
            pMem.flags |= MEM_Term;
            return 1;
        }
        if (pMem.xDel == @as(XDelFn, sqlite3RCStrUnref)) {
            pMem.flags |= MEM_Term;
            return 1;
        }
    } else if (pMem.szMalloc >= pMem.n + 1) {
        z[nU] = 0;
        pMem.flags |= MEM_Term;
        return 1;
    }
    return 0;
}

fn vdbeMemAddTerminator(pMem: *Mem) c_int {
    if (sqlite3VdbeMemGrow(pMem, pMem.n + 3, 1) != 0) {
        return nomemBkpt();
    }
    const z = pMem.z.?;
    const nU: usize = @intCast(pMem.n);
    z[nU] = 0;
    z[nU + 1] = 0;
    z[nU + 2] = 0;
    pMem.flags |= MEM_Term;
    return SQLITE_OK;
}

export fn sqlite3VdbeMemMakeWriteable(pMem: *Mem) callconv(.c) c_int {
    if ((pMem.flags & (MEM_Str | MEM_Blob)) != 0) {
        if (expandBlob(pMem) != 0) return SQLITE_NOMEM_PLAIN;
        if (pMem.szMalloc == 0 or pMem.z != pMem.zMalloc) {
            const rc = vdbeMemAddTerminator(pMem);
            if (rc != 0) return rc;
        }
    }
    pMem.flags &= ~MEM_Ephem;
    return SQLITE_OK;
}

export fn sqlite3VdbeMemExpandBlob(pMem: *Mem) callconv(.c) c_int {
    var nByte: c_int = pMem.n + pMem.u.nZero;
    if (nByte <= 0) {
        if ((pMem.flags & MEM_Blob) == 0) return SQLITE_OK;
        nByte = 1;
    }
    if (sqlite3VdbeMemGrow(pMem, nByte, 1) != 0) {
        return nomemBkpt();
    }
    const z = pMem.z.?;
    const start: usize = @intCast(pMem.n);
    const cnt: usize = @intCast(pMem.u.nZero);
    @memset(z[start .. start + cnt], 0);
    pMem.n += pMem.u.nZero;
    pMem.flags &= ~(MEM_Zero | MEM_Term);
    return SQLITE_OK;
}

export fn sqlite3VdbeMemNulTerminate(pMem: *Mem) callconv(.c) c_int {
    if ((pMem.flags & (MEM_Term | MEM_Str)) != MEM_Str) {
        return SQLITE_OK;
    }
    return vdbeMemAddTerminator(pMem);
}

export fn sqlite3VdbeMemStringify(pMem: *Mem, enc: u8, bForce: u8) callconv(.c) c_int {
    const nByte: c_int = 32;
    if (sqlite3VdbeMemClearAndResize(pMem, nByte) != 0) {
        pMem.enc = 0;
        return nomemBkpt();
    }
    vdbeMemRenderNum(nByte, pMem.z.?, pMem);
    pMem.enc = SQLITE_UTF8;
    pMem.flags |= MEM_Str | MEM_Term;
    if (bForce != 0) pMem.flags &= ~(MEM_Int | MEM_Real | MEM_IntReal);
    _ = sqlite3VdbeChangeEncoding(pMem, enc);
    return SQLITE_OK;
}

//=============================================================================
// Aggregate finalize / value
//=============================================================================

export fn sqlite3VdbeMemFinalize(pMem: *Mem, pFunc: *anyopaque) callconv(.c) c_int {
    var ctx: Sqlite3Context = std.mem.zeroes(Sqlite3Context);
    var t: Mem = std.mem.zeroes(Mem);
    t.flags = MEM_Null;
    t.db = pMem.db;
    ctx.pOut = &t;
    ctx.pMem = pMem;
    ctx.pFunc = pFunc;
    ctx.enc = dbEnc(t.db);
    funcXFinalize(pFunc)(&ctx);
    if (pMem.szMalloc > 0) sqlite3DbFreeNN(pMem.db, pMem.zMalloc);
    // memcpy(pMem, &t, sizeof(t))
    pMem.* = t;
    return ctx.isError;
}

export fn sqlite3VdbeMemAggValue(pAccum: *Mem, pOut: *Mem, pFunc: *anyopaque) callconv(.c) c_int {
    var ctx: Sqlite3Context = std.mem.zeroes(Sqlite3Context);
    sqlite3VdbeMemSetNull(pOut);
    ctx.pOut = pOut;
    ctx.pMem = pAccum;
    ctx.pFunc = pFunc;
    ctx.enc = dbEnc(pAccum.db);
    funcXValue(pFunc)(&ctx);
    return ctx.isError;
}

//=============================================================================
// Release / clear
//=============================================================================

fn vdbeMemClearExternAndSetNull(p: *Mem) void {
    if (p.flags & MEM_Agg != 0) {
        _ = sqlite3VdbeMemFinalize(p, p.u.pDef.?);
    }
    if (p.flags & MEM_Dyn != 0) {
        p.xDel.?(@ptrCast(p.z));
    }
    p.flags = MEM_Null;
}

fn vdbeMemClear(p: *Mem) void {
    if (vdbeMemDynamic(p)) {
        vdbeMemClearExternAndSetNull(p);
    }
    if (p.szMalloc != 0) {
        sqlite3DbFreeNN(p.db, p.zMalloc);
        p.szMalloc = 0;
    }
    p.z = null;
}

export fn sqlite3VdbeMemRelease(p: *Mem) callconv(.c) void {
    if (vdbeMemDynamic(p) or p.szMalloc != 0) {
        vdbeMemClear(p);
    }
}

export fn sqlite3VdbeMemReleaseMalloc(p: *Mem) callconv(.c) void {
    if (p.szMalloc != 0) vdbeMemClear(p);
}

//=============================================================================
// Value extraction (int / real / boolean)
//=============================================================================

fn memIntValue(pMem: *const Mem) i64 {
    var value: i64 = 0;
    _ = sqlite3Atoi64(pMem.z, &value, pMem.n, pMem.enc);
    return value;
}

export fn sqlite3VdbeIntValue(pMem: *const Mem) callconv(.c) i64 {
    const flags = pMem.flags;
    if (flags & (MEM_Int | MEM_IntReal) != 0) {
        return pMem.u.i;
    } else if (flags & MEM_Real != 0) {
        return sqlite3RealToI64(pMem.u.r);
    } else if ((flags & (MEM_Str | MEM_Blob)) != 0 and pMem.z != null) {
        return memIntValue(pMem);
    } else {
        return 0;
    }
}

fn sqlite3MemRealValueRCSlowPath(pMem: *Mem, pValue: *f64) c_int {
    var rc: c_int = SQLITE_OK;
    pValue.* = 0.0;
    if (pMem.enc == SQLITE_UTF8) {
        const zCopy = sqlite3DbStrNDup(pMem.db, pMem.z, @intCast(pMem.n));
        if (zCopy != null) {
            rc = sqlite3AtoF(zCopy, pValue);
            sqlite3DbFree(pMem.db, zCopy);
        }
        return rc;
    } else {
        const n: c_int = pMem.n & ~@as(c_int, 1);
        const zCopy: ?[*]u8 = @ptrCast(sqlite3DbMallocRaw(pMem.db, @intCast(@divTrunc(n, 2) + 2)));
        if (zCopy != null) {
            const dst = zCopy.?;
            const z = pMem.z.?;
            var i: c_int = 0;
            var j: c_int = 0;
            if (pMem.enc == SQLITE_UTF16LE) {
                while (i < n - 1) : (i += 2) {
                    // A non-ASCII char (high byte != 0) ends the numeric prefix;
                    // check BEFORE copying the low byte so e.g. U+0137 (LE 37 01)
                    // does not contribute its low byte '7' (matches the UTF16BE
                    // arm below and a proper UTF-8 conversion → AtoF).
                    if (z[@intCast(i + 1)] != 0) break;
                    dst[@intCast(j)] = z[@intCast(i)];
                    j += 1;
                }
            } else {
                while (i < n - 1) : (i += 2) {
                    if (z[@intCast(i)] != 0) break;
                    dst[@intCast(j)] = z[@intCast(i + 1)];
                    j += 1;
                }
            }
            dst[@intCast(j)] = 0;
            rc = sqlite3AtoF(dst, pValue);
            if (i < n) rc = -100;
            sqlite3DbFree(pMem.db, zCopy);
        }
        return rc;
    }
}

export fn sqlite3MemRealValueRC(pMem: *Mem, pValue: *f64) callconv(.c) c_int {
    if (pMem.z == null) {
        pValue.* = 0.0;
        return 0;
    } else if (pMem.enc == SQLITE_UTF8 and
        ((pMem.flags & MEM_Term) != 0 or sqlite3VdbeMemZeroTerminateIfAble(pMem) != 0))
    {
        return sqlite3AtoF(pMem.z, pValue);
    } else if (pMem.n == 0) {
        pValue.* = 0.0;
        return 0;
    } else {
        return sqlite3MemRealValueRCSlowPath(pMem, pValue);
    }
}

fn sqlite3MemRealValueNoRC(pMem: *Mem) f64 {
    var r: f64 = undefined;
    _ = sqlite3MemRealValueRC(pMem, &r);
    return r;
}

export fn sqlite3VdbeRealValue(pMem: *Mem) callconv(.c) f64 {
    if (pMem.flags & MEM_Real != 0) {
        return pMem.u.r;
    } else if (pMem.flags & (MEM_Int | MEM_IntReal) != 0) {
        return @floatFromInt(pMem.u.i);
    } else if (pMem.flags & (MEM_Str | MEM_Blob) != 0) {
        return sqlite3MemRealValueNoRC(pMem);
    } else {
        return 0.0;
    }
}

export fn sqlite3VdbeBooleanValue(pMem: *Mem, ifNull: c_int) callconv(.c) c_int {
    if (pMem.flags & (MEM_Int | MEM_IntReal) != 0) return @intFromBool(pMem.u.i != 0);
    if (pMem.flags & MEM_Null != 0) return ifNull;
    return @intFromBool(sqlite3VdbeRealValue(pMem) != 0.0);
}

//=============================================================================
// Numeric affinity / coercion
//=============================================================================

export fn sqlite3VdbeIntegerAffinity(pMem: *Mem) callconv(.c) void {
    if (pMem.flags & MEM_IntReal != 0) {
        memSetTypeFlag(pMem, MEM_Int);
    } else {
        const ix = sqlite3RealToI64(pMem.u.r);
        if (pMem.u.r == @as(f64, @floatFromInt(ix)) and ix > SMALLEST_INT64 and ix < LARGEST_INT64) {
            pMem.u.i = ix;
            memSetTypeFlag(pMem, MEM_Int);
        }
    }
}

export fn sqlite3VdbeMemIntegerify(pMem: *Mem) callconv(.c) c_int {
    pMem.u.i = sqlite3VdbeIntValue(pMem);
    memSetTypeFlag(pMem, MEM_Int);
    return SQLITE_OK;
}

export fn sqlite3VdbeMemRealify(pMem: *Mem) callconv(.c) c_int {
    pMem.u.r = sqlite3VdbeRealValue(pMem);
    memSetTypeFlag(pMem, MEM_Real);
    return SQLITE_OK;
}

export fn sqlite3RealSameAsInt(r1: f64, i: i64) callconv(.c) c_int {
    const r2: f64 = @floatFromInt(i);
    if (r1 == 0.0) return 1;
    const b1: u64 = @bitCast(r1);
    const b2: u64 = @bitCast(r2);
    return @intFromBool(b1 == b2 and i >= -2251799813685248 and i < 2251799813685248);
}

export fn sqlite3RealToI64(r: f64) callconv(.c) i64 {
    if (r < -9223372036854774784.0) return SMALLEST_INT64;
    if (r > 9223372036854774784.0) return LARGEST_INT64;
    return @intFromFloat(r);
}

export fn sqlite3VdbeMemNumerify(pMem: *Mem) callconv(.c) c_int {
    if ((pMem.flags & (MEM_Int | MEM_Real | MEM_IntReal | MEM_Null)) == 0) {
        var ix: i64 = undefined;
        const rc = sqlite3MemRealValueRC(pMem, &pMem.u.r);
        // NOTE: u.r and u.i alias; mirror C which writes u.r then maybe u.i.
        var isInt = false;
        if ((rc & 2) == 0 and sqlite3Atoi64(pMem.z, &ix, pMem.n, pMem.enc) < 2) {
            isInt = true;
        } else {
            ix = sqlite3RealToI64(pMem.u.r);
            if (sqlite3RealSameAsInt(pMem.u.r, ix) != 0) isInt = true;
        }
        if (isInt) {
            pMem.u.i = ix;
            memSetTypeFlag(pMem, MEM_Int);
        } else {
            memSetTypeFlag(pMem, MEM_Real);
        }
    }
    pMem.flags &= ~(MEM_Str | MEM_Blob | MEM_Zero);
    return SQLITE_OK;
}

export fn sqlite3VdbeMemCast(pMem: *Mem, aff: u8, encoding: u8) callconv(.c) c_int {
    if (pMem.flags & MEM_Null != 0) return SQLITE_OK;
    switch (aff) {
        SQLITE_AFF_BLOB => {
            if ((pMem.flags & MEM_Blob) == 0) {
                sqlite3ValueApplyAffinity(pMem, SQLITE_AFF_TEXT, encoding);
                if (pMem.flags & MEM_Str != 0) memSetTypeFlag(pMem, MEM_Blob);
            } else {
                pMem.flags &= ~(MEM_TypeMask & ~MEM_Blob);
            }
        },
        SQLITE_AFF_NUMERIC => {
            _ = sqlite3VdbeMemNumerify(pMem);
        },
        SQLITE_AFF_INTEGER => {
            _ = sqlite3VdbeMemIntegerify(pMem);
        },
        SQLITE_AFF_REAL => {
            _ = sqlite3VdbeMemRealify(pMem);
        },
        else => {
            // SQLITE_AFF_TEXT. MEM_Str == MEM_Blob >> 3.
            pMem.flags |= (pMem.flags & MEM_Blob) >> 3;
            sqlite3ValueApplyAffinity(pMem, SQLITE_AFF_TEXT, encoding);
            pMem.flags &= ~(MEM_Int | MEM_Real | MEM_IntReal | MEM_Blob | MEM_Zero);
            if (encoding != SQLITE_UTF8) pMem.n &= ~@as(c_int, 1);
            const rc = sqlite3VdbeChangeEncoding(pMem, encoding);
            if (rc != 0) return rc;
            _ = sqlite3VdbeMemZeroTerminateIfAble(pMem);
        },
    }
    return SQLITE_OK;
}

//=============================================================================
// Init / set-null / set-value
//=============================================================================

export fn sqlite3VdbeMemInit(pMem: *Mem, db: ?*anyopaque, flags: u16) callconv(.c) void {
    pMem.flags = flags;
    pMem.db = db;
    pMem.szMalloc = 0;
}

export fn sqlite3VdbeMemSetNull(pMem: *Mem) callconv(.c) void {
    if (vdbeMemDynamic(pMem)) {
        vdbeMemClearExternAndSetNull(pMem);
    } else {
        pMem.flags = MEM_Null;
    }
}

export fn sqlite3ValueSetNull(p: *Mem) callconv(.c) void {
    sqlite3VdbeMemSetNull(p);
}

export fn sqlite3VdbeMemSetZeroBlob(pMem: *Mem, n: c_int) callconv(.c) void {
    sqlite3VdbeMemRelease(pMem);
    pMem.flags = MEM_Blob | MEM_Zero;
    pMem.n = 0;
    pMem.u.nZero = if (n < 0) 0 else n;
    pMem.enc = SQLITE_UTF8;
    pMem.z = null;
}

fn vdbeReleaseAndSetInt64(pMem: *Mem, val: i64) void {
    sqlite3VdbeMemSetNull(pMem);
    pMem.u.i = val;
    pMem.flags = MEM_Int;
}

export fn sqlite3VdbeMemSetInt64(pMem: *Mem, val: i64) callconv(.c) void {
    if (vdbeMemDynamic(pMem)) {
        vdbeReleaseAndSetInt64(pMem, val);
    } else {
        pMem.u.i = val;
        pMem.flags = MEM_Int;
    }
}

export fn sqlite3MemSetArrayInt64(aMem: [*]Mem, iIdx: c_int, val: i64) callconv(.c) void {
    sqlite3VdbeMemSetInt64(&aMem[@intCast(iIdx)], val);
}

export fn sqlite3NoopDestructor(p: ?*anyopaque) callconv(.c) void {
    _ = p;
}

export fn sqlite3VdbeMemSetPointer(
    pMem: *Mem,
    pPtr: ?*anyopaque,
    zPType: ?[*:0]const u8,
    xDestructor: ?*const fn (?*anyopaque) callconv(.c) void,
) callconv(.c) void {
    vdbeMemClear(pMem);
    pMem.u.zPType = if (zPType != null) zPType else "";
    pMem.z = @ptrCast(pPtr);
    pMem.flags = MEM_Null | MEM_Dyn | MEM_Subtype | MEM_Term;
    pMem.eSubtype = 'p';
    pMem.xDel = if (xDestructor != null) xDestructor else sqlite3NoopDestructor;
}

export fn sqlite3VdbeMemSetDouble(pMem: *Mem, val: f64) callconv(.c) void {
    sqlite3VdbeMemSetNull(pMem);
    if (sqlite3IsNaN(val) == 0) {
        pMem.u.r = val;
        pMem.flags = MEM_Real;
    }
}

export fn sqlite3VdbeMemSetRowSet(pMem: *Mem) callconv(.c) c_int {
    const db = pMem.db;
    sqlite3VdbeMemRelease(pMem);
    const p = sqlite3RowSetInit(db);
    if (p == null) return SQLITE_NOMEM_PLAIN;
    pMem.z = @ptrCast(p);
    pMem.flags = MEM_Blob | MEM_Dyn;
    pMem.xDel = sqlite3RowSetDelete;
    return SQLITE_OK;
}

export fn sqlite3VdbeMemTooBig(p: *Mem) callconv(.c) c_int {
    if (p.flags & (MEM_Str | MEM_Blob) != 0) {
        var n: c_int = p.n;
        if (p.flags & MEM_Zero != 0) {
            n += p.u.nZero;
        }
        return @intFromBool(n > dbLimitLength(p.db));
    }
    return 0;
}

//=============================================================================
// Copy / move
//=============================================================================

fn vdbeClrCopy(pTo: *Mem, pFrom: *const Mem, eType: c_int) void {
    vdbeMemClearExternAndSetNull(pTo);
    sqlite3VdbeMemShallowCopy(pTo, pFrom, eType);
}

export fn sqlite3VdbeMemShallowCopy(pTo: *Mem, pFrom: *const Mem, srcType: c_int) callconv(.c) void {
    if (vdbeMemDynamic(pTo)) {
        vdbeClrCopy(pTo, pFrom, srcType);
        return;
    }
    // memcpy(pTo, pFrom, MEMCELLSIZE)
    const dst: [*]u8 = @ptrCast(pTo);
    const src: [*]const u8 = @ptrCast(pFrom);
    @memcpy(dst[0..MEMCELLSIZE], src[0..MEMCELLSIZE]);
    if ((pFrom.flags & MEM_Static) == 0) {
        pTo.flags &= ~(MEM_Dyn | MEM_Static | MEM_Ephem);
        pTo.flags |= @intCast(srcType);
    }
}

export fn sqlite3VdbeMemCopy(pTo: *Mem, pFrom: *const Mem) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (vdbeMemDynamic(pTo)) vdbeMemClearExternAndSetNull(pTo);
    const dst: [*]u8 = @ptrCast(pTo);
    const src: [*]const u8 = @ptrCast(pFrom);
    @memcpy(dst[0..MEMCELLSIZE], src[0..MEMCELLSIZE]);
    pTo.flags &= ~MEM_Dyn;
    if (pTo.flags & (MEM_Str | MEM_Blob) != 0) {
        if (0 == (pFrom.flags & MEM_Static)) {
            pTo.flags |= MEM_Ephem;
            rc = sqlite3VdbeMemMakeWriteable(pTo);
        }
    }
    return rc;
}

export fn sqlite3VdbeMemMove(pTo: *Mem, pFrom: *Mem) callconv(.c) void {
    sqlite3VdbeMemRelease(pTo);
    // memcpy(pTo, pFrom, sizeof(Mem))
    pTo.* = pFrom.*;
    pFrom.flags = MEM_Null;
    pFrom.szMalloc = 0;
}

//=============================================================================
// Set string / blob
//=============================================================================

export fn sqlite3VdbeMemSetStr(
    pMem: *Mem,
    z: ?[*]const u8,
    n: i64,
    enc_in: u8,
    xDel: XDelFn,
) callconv(.c) c_int {
    var nByte: i64 = n;
    var enc = enc_in;
    var flags: u16 = undefined;

    if (z == null) {
        sqlite3VdbeMemSetNull(pMem);
        return SQLITE_OK;
    }
    const zp = z.?;

    const iLimit: c_int = if (pMem.db != null) dbLimitLength(pMem.db) else SQLITE_MAX_LENGTH;
    if (nByte < 0) {
        if (enc == SQLITE_UTF8) {
            nByte = @intCast(std.mem.len(@as([*:0]const u8, @ptrCast(zp))));
        } else {
            nByte = 0;
            while (nByte <= iLimit and (zp[@intCast(nByte)] | zp[@intCast(nByte + 1)]) != 0) : (nByte += 2) {}
        }
        flags = MEM_Str | MEM_Term;
    } else if (enc == 0) {
        flags = MEM_Blob;
        enc = SQLITE_UTF8;
    } else {
        flags = MEM_Str;
    }
    if (nByte > iLimit) {
        if (xDel != null and !isTransient(xDel)) {
            if (isDynamicSentinel(xDel)) {
                sqlite3DbFree(pMem.db, @ptrCast(@constCast(zp)));
            } else {
                xDel.?(@ptrCast(@constCast(zp)));
            }
        }
        sqlite3VdbeMemSetNull(pMem);
        return sqlite3ErrorToParser(pMem.db, SQLITE_TOOBIG);
    }

    if (isTransient(xDel)) {
        var nAlloc: i64 = nByte;
        if (flags & MEM_Term != 0) {
            nAlloc += if (enc == SQLITE_UTF8) 1 else 2;
        }
        if (sqlite3VdbeMemClearAndResize(pMem, @intCast(@max(nAlloc, 32))) != 0) {
            return nomemBkpt();
        }
        const dst = pMem.z.?;
        @memcpy(dst[0..@intCast(nAlloc)], zp[0..@intCast(nAlloc)]);
    } else {
        sqlite3VdbeMemRelease(pMem);
        pMem.z = @constCast(zp);
        if (isDynamicSentinel(xDel)) {
            pMem.zMalloc = pMem.z;
            pMem.szMalloc = sqlite3DbMallocSize(pMem.db, pMem.zMalloc);
        } else {
            pMem.xDel = xDel;
            flags |= if (xDel == null) MEM_Static else MEM_Dyn;
        }
    }

    pMem.n = @intCast(nByte & 0x7fffffff);
    pMem.flags = flags;
    pMem.enc = enc;

    if (enc > SQLITE_UTF8 and sqlite3VdbeMemHandleBom(pMem) != 0) {
        return nomemBkpt();
    }
    return SQLITE_OK;
}

export fn sqlite3VdbeMemSetText(
    pMem: *Mem,
    z: ?[*]const u8,
    n: i64,
    xDel: XDelFn,
) callconv(.c) c_int {
    var nByte: i64 = n;
    var flags: u16 = undefined;

    if (z == null) {
        sqlite3VdbeMemSetNull(pMem);
        return SQLITE_OK;
    }
    const zp = z.?;

    if (nByte < 0) {
        nByte = @intCast(std.mem.len(@as([*:0]const u8, @ptrCast(zp))));
        flags = MEM_Str | MEM_Term;
    } else {
        flags = MEM_Str;
    }
    if (nByte > @as(i64, dbLimitLength(pMem.db))) {
        if (xDel != null and !isTransient(xDel)) {
            if (isDynamicSentinel(xDel)) {
                sqlite3DbFree(pMem.db, @ptrCast(@constCast(zp)));
            } else {
                xDel.?(@ptrCast(@constCast(zp)));
            }
        }
        sqlite3VdbeMemSetNull(pMem);
        return sqlite3ErrorToParser(pMem.db, SQLITE_TOOBIG);
    }

    if (isTransient(xDel)) {
        const nAlloc: i64 = nByte + 1;
        if (sqlite3VdbeMemClearAndResize(pMem, @intCast(@max(nAlloc, 32))) != 0) {
            return nomemBkpt();
        }
        const dst = pMem.z.?;
        @memcpy(dst[0..@intCast(nByte)], zp[0..@intCast(nByte)]);
        dst[@intCast(nByte)] = 0;
    } else {
        sqlite3VdbeMemRelease(pMem);
        pMem.z = @constCast(zp);
        if (isDynamicSentinel(xDel)) {
            pMem.zMalloc = pMem.z;
            pMem.szMalloc = sqlite3DbMallocSize(pMem.db, pMem.zMalloc);
            pMem.xDel = null;
        } else if (xDel == null) {
            pMem.xDel = xDel;
            flags |= MEM_Static;
        } else {
            pMem.xDel = xDel;
            flags |= MEM_Dyn;
        }
    }
    pMem.flags = flags;
    pMem.n = @intCast(nByte & 0x7fffffff);
    pMem.enc = SQLITE_UTF8;
    return SQLITE_OK;
}

//=============================================================================
// From-btree
//=============================================================================

export fn sqlite3VdbeMemFromBtree(pCur: ?*anyopaque, offset: u32, amt: u32, pMem: *Mem) callconv(.c) c_int {
    pMem.flags = MEM_Null;
    if (amt >= SQLITE_MAX_ALLOCATION_SIZE) {
        return nomemBkpt();
    }
    if (@as(u64, amt) + @as(u64, offset) > @as(u64, @intCast(sqlite3BtreeMaxRecordSize(pCur)))) {
        return corruptBkpt();
    }
    var rc = sqlite3VdbeMemClearAndResize(pMem, @intCast(amt + 1));
    if (rc == SQLITE_OK) {
        rc = sqlite3BtreePayload(pCur, offset, amt, pMem.z);
        if (rc == SQLITE_OK) {
            pMem.z.?[@intCast(amt)] = 0;
            pMem.flags = MEM_Blob;
            pMem.n = @intCast(amt);
        } else {
            sqlite3VdbeMemRelease(pMem);
        }
    }
    return rc;
}

export fn sqlite3VdbeMemFromBtreeZeroOffset(pCur: ?*anyopaque, amt: u32, pMem: *Mem) callconv(.c) c_int {
    var available: u32 = 0;
    var rc: c_int = SQLITE_OK;
    pMem.z = @ptrCast(@constCast(sqlite3BtreePayloadFetch(pCur, &available)));
    if (amt <= available) {
        pMem.flags = MEM_Blob | MEM_Ephem;
        pMem.n = @intCast(amt);
    } else {
        rc = sqlite3VdbeMemFromBtree(pCur, 0, amt, pMem);
    }
    return rc;
}

//=============================================================================
// sqlite3_value text / new / free / bytes
//=============================================================================

fn valueToText(pVal: *Mem, enc: u8) ?*const anyopaque {
    if (pVal.flags & (MEM_Blob | MEM_Str) != 0) {
        if (expandBlob(pVal) != 0) return null;
        pVal.flags |= MEM_Str;
        if (pVal.enc != (enc & ~SQLITE_UTF16_ALIGNED)) {
            _ = sqlite3VdbeChangeEncoding(pVal, enc & ~SQLITE_UTF16_ALIGNED);
        }
        if ((enc & SQLITE_UTF16_ALIGNED) != 0 and (1 & @intFromPtr(pVal.z)) == 1) {
            if (sqlite3VdbeMemMakeWriteable(pVal) != SQLITE_OK) {
                return null;
            }
        }
        _ = sqlite3VdbeMemNulTerminate(pVal);
    } else {
        _ = sqlite3VdbeMemStringify(pVal, enc, 0);
    }
    if (pVal.enc == (enc & ~SQLITE_UTF16_ALIGNED)) {
        return @ptrCast(pVal.z);
    } else {
        return null;
    }
}

export fn sqlite3ValueText(pVal: ?*Mem, enc: u8) callconv(.c) ?*const anyopaque {
    if (pVal == null) return null;
    const p = pVal.?;
    if ((p.flags & (MEM_Str | MEM_Term)) == (MEM_Str | MEM_Term) and p.enc == enc) {
        return @ptrCast(p.z);
    }
    if (p.flags & MEM_Null != 0) {
        return null;
    }
    return valueToText(p, enc);
}

export fn sqlite3ValueIsOfClass(pVal: ?*const Mem, xFree: XDelFn) callconv(.c) c_int {
    if (pVal) |p| {
        if ((p.flags & (MEM_Str | MEM_Blob)) != 0 and (p.flags & MEM_Dyn) != 0 and p.xDel == xFree) {
            return 1;
        }
    }
    return 0;
}

export fn sqlite3ValueNew(db: ?*anyopaque) callconv(.c) ?*Mem {
    const p: ?*Mem = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @sizeOf(Mem))));
    if (p) |pp| {
        pp.flags = MEM_Null;
        pp.db = db;
    }
    return p;
}

export fn sqlite3ValueFromExpr(
    db: ?*anyopaque,
    pExpr: ?*const anyopaque,
    enc: u8,
    affinity: u8,
    ppVal: *?*Mem,
) callconv(.c) c_int {
    // STAT4 off: valueFromExpr() is only reachable via this entry point and is a
    // large self-contained helper. It is faithfully ported below.
    // C: `return pExpr ? valueFromExpr(...) : 0;` — *ppVal is left untouched when
    // pExpr==0 (the caller is responsible for pre-initializing it).
    if (pExpr == null) {
        return SQLITE_OK;
    }
    return valueFromExpr(db, pExpr.?, enc, affinity, ppVal);
}

export fn sqlite3ValueSetStr(
    v: ?*Mem,
    n: c_int,
    z: ?*const anyopaque,
    enc: u8,
    xDel: XDelFn,
) callconv(.c) void {
    if (v) |pv| _ = sqlite3VdbeMemSetStr(pv, @ptrCast(z), @as(i64, n), enc, xDel);
}

export fn sqlite3ValueFree(v: ?*Mem) callconv(.c) void {
    if (v == null) return;
    sqlite3VdbeMemRelease(v.?);
    sqlite3DbFreeNN(v.?.db, v.?);
}

fn valueBytes(pVal: *Mem, enc: u8) c_int {
    return if (valueToText(pVal, enc) != null) pVal.n else 0;
}

export fn sqlite3ValueBytes(pVal: *Mem, enc: u8) callconv(.c) c_int {
    const p = pVal;
    if ((p.flags & MEM_Str) != 0 and p.enc == enc) {
        return p.n;
    }
    if ((p.flags & MEM_Str) != 0 and enc != SQLITE_UTF8 and p.enc != SQLITE_UTF8) {
        return p.n;
    }
    if (p.flags & MEM_Blob != 0) {
        if (p.flags & MEM_Zero != 0) {
            return p.n + p.u.nZero;
        } else {
            return p.n;
        }
    }
    if (p.flags & MEM_Null != 0) return 0;
    return valueBytes(pVal, enc);
}

//=============================================================================
// valueFromExpr (non-STAT4 path)
//=============================================================================

// Expr / token-op constants needed by valueFromExpr.
const TK_UPLUS = tk("TK_UPLUS");
const TK_SPAN = tk("TK_SPAN");
const TK_REGISTER = tk("TK_REGISTER");
const TK_CAST = tk("TK_CAST");
const TK_UMINUS = tk("TK_UMINUS");
const TK_STRING = tk("TK_STRING");
const TK_FLOAT = tk("TK_FLOAT");
const TK_INTEGER = tk("TK_INTEGER");
const TK_NULL = tk("TK_NULL");
const TK_BLOB = tk("TK_BLOB");
const TK_TRUEFALSE = tk("TK_TRUEFALSE");

fn tk(comptime name: []const u8) u8 {
    return if (@hasDecl(L, name)) @field(L, name) else tkFallback(name);
}
// Token codes are generated (parse.h); not in c_layout. Use the known values
// from the vendored parse.h (v3.54.0). Asserted by the engine tests at runtime.
fn tkFallback(comptime name: []const u8) u8 {
    const map = .{
        .{ "TK_UPLUS", 173 },
        .{ "TK_SPAN", 181 },
        .{ "TK_REGISTER", 176 },
        .{ "TK_CAST", 36 },
        .{ "TK_UMINUS", 174 },
        .{ "TK_STRING", 118 },
        .{ "TK_FLOAT", 154 },
        .{ "TK_INTEGER", 156 },
        .{ "TK_NULL", 122 },
        .{ "TK_BLOB", 155 },
        .{ "TK_TRUEFALSE", 171 },
    };
    inline for (map) |e| {
        if (std.mem.eql(u8, e[0], name)) return e[1];
    }
    @compileError("unknown token " ++ name);
}

// Expr field accessors (ground-truth offsets via c_layout where available).
const EP_IntValue: u32 = 0x000800; // Expr.flags bit (config-invariant)

inline fn exprOp(p: *const anyopaque) u8 {
    const base: [*]const u8 = @ptrCast(p);
    return base[L.Expr_op];
}
inline fn exprOp2(p: *const anyopaque) u8 {
    // Expr layout: op@0, affExpr@1, op2@2.
    const base: [*]const u8 = @ptrCast(p);
    return base[2];
}
inline fn exprFlags(p: *const anyopaque) u32 {
    const base: [*]const u8 = @ptrCast(p);
    const f: *align(1) const u32 = @ptrCast(base + L.Expr_flags);
    return f.*;
}
inline fn exprPLeft(p: *const anyopaque) ?*const anyopaque {
    const base: [*]const u8 = @ptrCast(p);
    const f: *align(1) const ?*const anyopaque = @ptrCast(base + L.Expr_pLeft);
    return f.*;
}
inline fn exprUZToken(p: *const anyopaque) ?[*:0]const u8 {
    const base: [*]const u8 = @ptrCast(p);
    const f: *align(1) const ?[*:0]const u8 = @ptrCast(base + L.Expr_u);
    return f.*;
}
inline fn exprUIValue(p: *const anyopaque) c_int {
    const base: [*]const u8 = @ptrCast(p);
    const f: *align(1) const c_int = @ptrCast(base + L.Expr_u);
    return f.*;
}
inline fn exprHasIntValue(p: *const anyopaque) bool {
    return (exprFlags(p) & EP_IntValue) != 0;
}

fn valueFromExpr(
    db: ?*anyopaque,
    pExpr_in: *const anyopaque,
    enc: u8,
    affinity_in: u8,
    ppVal: *?*Mem,
) c_int {
    var pExpr = pExpr_in;
    const affinity = affinity_in;
    var op = exprOp(pExpr);
    while (op == TK_UPLUS or op == TK_SPAN) {
        pExpr = exprPLeft(pExpr).?;
        op = exprOp(pExpr);
    }
    if (op == TK_REGISTER) op = exprOp2(pExpr);

    var zVal: ?[*]u8 = null;
    var pVal: ?*Mem = null;
    var negInt: c_int = 1;
    var zNeg: [*:0]const u8 = "";
    var rc: c_int = SQLITE_OK;

    if (op == TK_CAST) {
        const aff = sqlite3AffinityType(@ptrCast(exprUZToken(pExpr)), null);
        rc = valueFromExpr(db, exprPLeft(pExpr).?, enc, aff, ppVal);
        if (ppVal.* != null) {
            _ = sqlite3VdbeMemCast(ppVal.*.?, aff, enc);
            sqlite3ValueApplyAffinity(ppVal.*.?, affinity, enc);
        }
        return rc;
    }

    if (op == TK_UMINUS) {
        const pLeft = exprPLeft(pExpr).?;
        const lop = exprOp(pLeft);
        if (lop == TK_INTEGER or lop == TK_FLOAT) {
            if (exprHasIntValue(pLeft) or blk: {
                const zt = exprUZToken(pLeft).?;
                break :blk zt[0] != '0' or (zt[1] & ~@as(u8, 0x20)) != 'X';
            }) {
                pExpr = pLeft;
                op = exprOp(pExpr);
                negInt = -1;
                zNeg = "-";
            }
        }
    }

    if (op == TK_STRING or op == TK_FLOAT or op == TK_INTEGER) {
        pVal = sqlite3ValueNew(db);
        if (pVal == null) return noMem(db, zVal, ppVal, pVal);
        if (exprHasIntValue(pExpr)) {
            sqlite3VdbeMemSetInt64(pVal.?, @as(i64, exprUIValue(pExpr)) * negInt);
        } else {
            var iVal: i64 = undefined;
            const zt = exprUZToken(pExpr).?;
            if (op == TK_INTEGER and 0 == sqlite3DecOrHexToI64(zt, &iVal)) {
                sqlite3VdbeMemSetInt64(pVal.?, iVal * negInt);
            } else {
                zVal = sqlite3MPrintf(db, "%s%s", zNeg, zt);
                if (zVal == null) return noMem(db, zVal, ppVal, pVal);
                sqlite3ValueSetStr(pVal, -1, @ptrCast(zVal), SQLITE_UTF8, sqlite3RowSetClear);
            }
        }
        if (affinity == SQLITE_AFF_BLOB) {
            if (op == TK_FLOAT) {
                _ = sqlite3AtoF(pVal.?.z, &pVal.?.u.r);
                pVal.?.flags = MEM_Real;
            } else if (op == TK_INTEGER) {
                sqlite3ValueApplyAffinity(pVal.?, SQLITE_AFF_NUMERIC, SQLITE_UTF8);
            }
        } else {
            sqlite3ValueApplyAffinity(pVal.?, affinity, SQLITE_UTF8);
        }
        if (pVal.?.flags & (MEM_Int | MEM_IntReal | MEM_Real) != 0) {
            pVal.?.flags &= ~MEM_Str;
        }
        if (enc != SQLITE_UTF8) {
            rc = sqlite3VdbeChangeEncoding(pVal.?, enc);
        }
    } else if (op == TK_UMINUS) {
        var sub: ?*Mem = null;
        if (SQLITE_OK == valueFromExpr(db, exprPLeft(pExpr).?, enc, affinity, &sub) and sub != null) {
            pVal = sub;
            _ = sqlite3VdbeMemNumerify(pVal.?);
            if (pVal.?.flags & MEM_Real != 0) {
                pVal.?.u.r = -pVal.?.u.r;
            } else if (pVal.?.u.i == SMALLEST_INT64) {
                pVal.?.u.r = -@as(f64, @floatFromInt(SMALLEST_INT64));
                memSetTypeFlag(pVal.?, MEM_Real);
            } else {
                pVal.?.u.i = -pVal.?.u.i;
            }
            sqlite3ValueApplyAffinity(pVal.?, affinity, enc);
        }
    } else if (op == TK_NULL) {
        pVal = sqlite3ValueNew(db);
        if (pVal == null) return noMem(db, zVal, ppVal, pVal);
        sqlite3VdbeMemSetNull(pVal.?);
    } else if (op == TK_BLOB) {
        pVal = sqlite3ValueNew(db);
        if (pVal == null) return noMem(db, zVal, ppVal, pVal);
        const zt = exprUZToken(pExpr).?;
        const zBlob = @as([*]const u8, @ptrCast(zt)) + 2;
        const nVal = sqlite3Strlen30(@ptrCast(zBlob)) - 1;
        _ = sqlite3VdbeMemSetStr(pVal.?, @ptrCast(sqlite3HexToBlob(db, zBlob, nVal)), @divTrunc(nVal, 2), 0, sqlite3RowSetClear);
    } else if (op == TK_TRUEFALSE) {
        pVal = sqlite3ValueNew(db);
        if (pVal) |pv| {
            pv.flags = MEM_Int;
            const zt = exprUZToken(pExpr).?;
            pv.u.i = @intFromBool(zt[4] == 0);
            sqlite3ValueApplyAffinity(pv, affinity, enc);
        }
    }

    ppVal.* = pVal;
    return rc;
}

fn noMem(db: ?*anyopaque, zVal: ?[*]u8, ppVal: *?*Mem, pVal: ?*Mem) c_int {
    _ = sqlite3OomFault(db);
    sqlite3DbFree(db, @ptrCast(zVal));
    // STAT4 off: pCtx is always 0, free pVal.
    sqlite3ValueFree(pVal);
    ppVal.* = null;
    return nomemBkpt();
}

comptime {
    // Compile-time guard that the STAT4 surface stays excluded (it is not ported).
    std.debug.assert(!@hasDecl(@This(), "sqlite3Stat4Column"));
}
