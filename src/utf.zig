//! Zig port of SQLite's UTF-8/16 translation (src/utf.c).
//!
//! Drop-in replacement exporting the public/internal UTF helpers. This is the
//! first port to touch a *build-divergent* core struct (`Mem` ==
//! `struct sqlite3_value`): under SQLITE_DEBUG it grows a trailing
//! scopy-tracking tail (sizeof 56 -> 72), though every field utf.c touches is at
//! an identical offset in both configs. We mirror `Mem` with those invariant
//! offsets plus a config-gated tail to match `sizeof`, and assert the whole
//! layout against C ground truth (src/c_layout.zig) at comptime — a wrong mirror
//! fails to build rather than corrupting memory. `db->mallocFailed` is read at
//! its (config-invariant) ground-truth offset.
//!
//! Config: SQLITE_OMIT_UTF16 off (all functions compiled), little-endian target
//! (SQLITE_UTF16NATIVE == SQLITE_UTF16LE, sqlite3one not emitted), no
//! SQLITE_REPLACE_INVALID_UTF, no SQLITE_ENABLE_API_ARMOR. `sqlite3Utf8To8` and
//! `sqlite3UtfSelfTest` are SQLITE_TEST-only in C but exported unconditionally
//! (test_hexio.c / test5.c reference them in the testfixture; harmless in prod).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");

const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT in production
const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_UTF16BE: u8 = 3;

const MEM_Str: u16 = 0x0002;
const MEM_AffMask: u16 = 0x003f;
const MEM_Term: u16 = 0x0200;
const MEM_Subtype: u16 = 0x0800;

/// `Mem` (struct sqlite3_value). Field offsets are identical in both build
/// configs; only sizeof differs (SQLITE_DEBUG appends a scopy-tracking tail), so
/// a config-gated padding array matches the size. utf.c only ever reads/writes
/// the fields below; the tail is never touched here (but the C it links against
/// may, in the testfixture build — hence the size must match).
const debug_tail_len: usize = if (config.sqlite_debug) 16 else 0;
const Mem = extern struct {
    u: u64, // union MemValue — 8 bytes, contents unused here
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
    std.debug.assert(@offsetOf(Mem, "eSubtype") == L.sqlite3_value_eSubtype);
    std.debug.assert(@offsetOf(Mem, "db") == L.sqlite3_value_db);
    std.debug.assert(@offsetOf(Mem, "szMalloc") == L.sqlite3_value_szMalloc);
    std.debug.assert(@offsetOf(Mem, "uTemp") == L.sqlite3_value_uTemp);
    std.debug.assert(@offsetOf(Mem, "zMalloc") == L.sqlite3_value_zMalloc);
    std.debug.assert(@offsetOf(Mem, "xDel") == L.sqlite3_value_xDel);
}

/// Read `db->mallocFailed` (a u8) at its ground-truth offset.
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    const base: [*]const u8 = @ptrCast(db.?);
    return base[L.sqlite3_mallocFailed] != 0;
}

// --- C helpers resolved at link time ---
extern fn sqlite3VdbeMemMakeWriteable(pMem: *Mem) c_int;
extern fn sqlite3VdbeMemRelease(pMem: *Mem) void;
extern fn sqlite3VdbeMemSetStr(pMem: *Mem, z: ?[*]const u8, n: i64, enc: u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3VdbeChangeEncoding(pMem: *Mem, enc: c_int) c_int;
extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocSize(db: ?*anyopaque, p: ?*const anyopaque) c_int;

/// Decode table for the first byte of a multi-byte UTF-8 character (static in C).
const sqlite3Utf8Trans1 = [64]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00,
};

// --- WRITE_UTF8 / WRITE_UTF16{LE,BE} (advance the *z cursor) ---

fn writeUtf8(z: *[*]u8, c: u32) void {
    if (c < 0x00080) {
        z.*[0] = @truncate(c & 0xFF);
        z.* += 1;
    } else if (c < 0x00800) {
        z.*[0] = @truncate(0xC0 + ((c >> 6) & 0x1F));
        z.*[1] = @truncate(0x80 + (c & 0x3F));
        z.* += 2;
    } else if (c < 0x10000) {
        z.*[0] = @truncate(0xE0 + ((c >> 12) & 0x0F));
        z.*[1] = @truncate(0x80 + ((c >> 6) & 0x3F));
        z.*[2] = @truncate(0x80 + (c & 0x3F));
        z.* += 3;
    } else {
        z.*[0] = @truncate(0xF0 + ((c >> 18) & 0x07));
        z.*[1] = @truncate(0x80 + ((c >> 12) & 0x3F));
        z.*[2] = @truncate(0x80 + ((c >> 6) & 0x3F));
        z.*[3] = @truncate(0x80 + (c & 0x3F));
        z.* += 4;
    }
}

fn writeUtf16le(z: *[*]u8, c: u32) void {
    if (c <= 0xFFFF) {
        z.*[0] = @truncate(c & 0x00FF);
        z.*[1] = @truncate((c >> 8) & 0x00FF);
        z.* += 2;
    } else {
        z.*[0] = @truncate(((c >> 10) & 0x003F) + (((c -% 0x10000) >> 10) & 0x00C0));
        z.*[1] = @truncate(0x00D8 + (((c -% 0x10000) >> 18) & 0x03));
        z.*[2] = @truncate(c & 0x00FF);
        z.*[3] = @truncate(0x00DC + ((c >> 8) & 0x03));
        z.* += 4;
    }
}

fn writeUtf16be(z: *[*]u8, c: u32) void {
    if (c <= 0xFFFF) {
        z.*[0] = @truncate((c >> 8) & 0x00FF);
        z.*[1] = @truncate(c & 0x00FF);
        z.* += 2;
    } else {
        z.*[0] = @truncate(0x00D8 + (((c -% 0x10000) >> 18) & 0x03));
        z.*[1] = @truncate(((c >> 10) & 0x003F) + (((c -% 0x10000) >> 10) & 0x00C0));
        z.*[2] = @truncate(0x00DC + ((c >> 8) & 0x03));
        z.*[3] = @truncate(c & 0x00FF);
        z.* += 4;
    }
}

/// READ_UTF8 with an end bound (used by the translate loops).
fn readUtf8Bounded(z: *[*]u8, zTerm: [*]u8) u32 {
    var c: u32 = z.*[0];
    z.* += 1;
    if (c >= 0xc0) {
        c = sqlite3Utf8Trans1[c - 0xc0];
        while (@intFromPtr(z.*) < @intFromPtr(zTerm) and (z.*[0] & 0xc0) == 0x80) {
            c = (c *% 64) +% (0x3f & @as(u32, z.*[0]));
            z.* += 1;
        }
        if (c < 0x80 or (c & 0xFFFFF800) == 0xD800 or (c & 0xFFFFFFFE) == 0xFFFE) c = 0xFFFD;
    }
    return c;
}

/// Write a single UTF-8 character into zOut (>= 4 bytes); return byte count.
export fn sqlite3AppendOneUtf8Character(zOut: [*]u8, v: u32) callconv(.c) c_int {
    if (v < 0x00080) {
        zOut[0] = @truncate(v & 0xff);
        return 1;
    }
    if (v < 0x00800) {
        zOut[0] = @truncate(0xc0 + ((v >> 6) & 0x1f));
        zOut[1] = @truncate(0x80 + (v & 0x3f));
        return 2;
    }
    if (v < 0x10000) {
        zOut[0] = @truncate(0xe0 + ((v >> 12) & 0x0f));
        zOut[1] = @truncate(0x80 + ((v >> 6) & 0x3f));
        zOut[2] = @truncate(0x80 + (v & 0x3f));
        return 3;
    }
    zOut[0] = @truncate(0xf0 + ((v >> 18) & 0x07));
    zOut[1] = @truncate(0x80 + ((v >> 12) & 0x3f));
    zOut[2] = @truncate(0x80 + ((v >> 6) & 0x3f));
    zOut[3] = @truncate(0x80 + (v & 0x3f));
    return 4;
}

/// Read one UTF-8 character from a zero-terminated string, advancing *pz.
export fn sqlite3Utf8Read(pz: *[*]const u8) callconv(.c) u32 {
    var c: u32 = pz.*[0];
    pz.* += 1;
    if (c >= 0xc0) {
        c = sqlite3Utf8Trans1[c - 0xc0];
        while ((pz.*[0] & 0xc0) == 0x80) {
            c = (c *% 64) +% (0x3f & @as(u32, pz.*[0]));
            pz.* += 1;
        }
        if (c < 0x80 or (c & 0xFFFFF800) == 0xD800 or (c & 0xFFFFFFFE) == 0xFFFE) c = 0xFFFD;
    }
    return c;
}

/// Read one UTF-8 character from z[], reading at most n (<=4) bytes; return the
/// byte count and write the codepoint to *piOut. No validity checking.
export fn sqlite3Utf8ReadLimited(z: [*]const u8, n_in: c_int, piOut: *u32) callconv(.c) c_int {
    var c: u32 = z[0];
    var i: c_int = 1;
    var n = n_in;
    if (c >= 0xc0) {
        c = sqlite3Utf8Trans1[c - 0xc0];
        if (n > 4) n = 4;
        while (i < n and (z[@intCast(i)] & 0xc0) == 0x80) {
            c = (c *% 64) +% (0x3f & @as(u32, z[@intCast(i)]));
            i += 1;
        }
    }
    piOut.* = c;
    return i;
}

/// Transform pMem's text from its current encoding to desiredEnc.
export fn sqlite3VdbeMemTranslate(pMem: *Mem, desiredEnc: u8) callconv(.c) c_int {
    // UTF16LE <-> UTF16BE: just byte-swap in place.
    if (pMem.enc != SQLITE_UTF8 and desiredEnc != SQLITE_UTF8) {
        if (sqlite3VdbeMemMakeWriteable(pMem) != SQLITE_OK) return SQLITE_NOMEM;
        var zIn = pMem.z.?;
        const zTerm = zIn + @as(usize, @intCast(pMem.n & ~@as(c_int, 1)));
        while (@intFromPtr(zIn) < @intFromPtr(zTerm)) {
            const temp = zIn[0];
            zIn[0] = zIn[1];
            zIn += 1;
            zIn[0] = temp;
            zIn += 1;
        }
        pMem.enc = desiredEnc;
        return SQLITE_OK;
    }

    var len: i64 = undefined;
    if (desiredEnc == SQLITE_UTF8) {
        pMem.n &= ~@as(c_int, 1);
        len = 2 * @as(i64, pMem.n) + 1;
    } else {
        len = 2 * @as(i64, pMem.n) + 2;
    }

    var zIn = pMem.z.?;
    const zTerm = zIn + @as(usize, @intCast(pMem.n));
    const zOut: [*]u8 = @ptrCast(sqlite3DbMallocRaw(pMem.db, @intCast(len)) orelse return SQLITE_NOMEM);
    var z = zOut;

    if (pMem.enc == SQLITE_UTF8) {
        if (desiredEnc == SQLITE_UTF16LE) {
            while (@intFromPtr(zIn) < @intFromPtr(zTerm)) {
                writeUtf16le(&z, readUtf8Bounded(&zIn, zTerm));
            }
        } else {
            while (@intFromPtr(zIn) < @intFromPtr(zTerm)) {
                writeUtf16be(&z, readUtf8Bounded(&zIn, zTerm));
            }
        }
        pMem.n = @intCast(@intFromPtr(z) - @intFromPtr(zOut));
        z[0] = 0;
        z += 1;
    } else if (pMem.enc == SQLITE_UTF16LE) {
        // UTF-16 little-endian -> UTF-8
        while (@intFromPtr(zIn) < @intFromPtr(zTerm)) {
            var ch: u32 = zIn[0];
            ch += @as(u32, zIn[1]) << 8;
            zIn += 2;
            if (ch >= 0xd800 and ch < 0xe000) {
                if (@intFromPtr(zIn) < @intFromPtr(zTerm)) {
                    var c2: u32 = zIn[0];
                    c2 += @as(u32, zIn[1]) << 8;
                    zIn += 2;
                    ch = (c2 & 0x03FF) + ((ch & 0x003F) << 10) + (((ch & 0x03C0) + 0x0040) << 10);
                }
            }
            writeUtf8(&z, ch);
        }
        pMem.n = @intCast(@intFromPtr(z) - @intFromPtr(zOut));
    } else {
        // UTF-16 big-endian -> UTF-8
        while (@intFromPtr(zIn) < @intFromPtr(zTerm)) {
            var ch: u32 = @as(u32, zIn[0]) << 8;
            ch += zIn[1];
            zIn += 2;
            if (ch >= 0xd800 and ch < 0xe000) {
                if (@intFromPtr(zIn) < @intFromPtr(zTerm)) {
                    var c2: u32 = @as(u32, zIn[0]) << 8;
                    c2 += zIn[1];
                    zIn += 2;
                    ch = (c2 & 0x03FF) + ((ch & 0x003F) << 10) + (((ch & 0x03C0) + 0x0040) << 10);
                }
            }
            writeUtf8(&z, ch);
        }
        pMem.n = @intCast(@intFromPtr(z) - @intFromPtr(zOut));
    }
    z[0] = 0;

    const newFlags: u16 = MEM_Str | MEM_Term | (pMem.flags & (MEM_AffMask | MEM_Subtype));
    sqlite3VdbeMemRelease(pMem);
    pMem.flags = newFlags;
    pMem.enc = desiredEnc;
    pMem.z = zOut;
    pMem.zMalloc = zOut;
    pMem.szMalloc = sqlite3DbMallocSize(pMem.db, zOut);
    return SQLITE_OK;
}

/// Strip a UTF-16 byte-order mark if present, adjusting Mem.enc accordingly.
export fn sqlite3VdbeMemHandleBom(pMem: *Mem) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var bom: u8 = 0;
    if (pMem.n > 1) {
        const z = pMem.z.?;
        if (z[0] == 0xFE and z[1] == 0xFF) bom = SQLITE_UTF16BE;
        if (z[0] == 0xFF and z[1] == 0xFE) bom = SQLITE_UTF16LE;
    }
    if (bom != 0) {
        rc = sqlite3VdbeMemMakeWriteable(pMem);
        if (rc == SQLITE_OK) {
            pMem.n -= 2;
            const z = pMem.z.?;
            const n: usize = @intCast(pMem.n);
            std.mem.copyForwards(u8, z[0..n], (z + 2)[0..n]);
            z[n] = 0;
            z[n + 1] = 0;
            pMem.flags |= MEM_Term;
            pMem.enc = bom;
        }
    }
    return rc;
}

/// Count unicode characters in a UTF-8 string (nByte<0 => to the first NUL).
export fn sqlite3Utf8CharLen(zIn: [*:0]const u8, nByte: c_int) callconv(.c) c_int {
    var r: c_int = 0;
    var z: [*]const u8 = @ptrCast(zIn);
    const zTerm: [*]const u8 = if (nByte >= 0) z + @as(usize, @intCast(nByte)) else @ptrFromInt(std.math.maxInt(usize));
    while (z[0] != 0 and @intFromPtr(z) < @intFromPtr(zTerm)) {
        const c = z[0];
        z += 1;
        if (c >= 0xc0) {
            while ((z[0] & 0xc0) == 0x80) z += 1;
        }
        r += 1;
    }
    return r;
}

/// Convert a native-encoding UTF-16 string to a freshly-malloc'd UTF-8 string.
export fn sqlite3Utf16to8(db: ?*anyopaque, z: ?*const anyopaque, nByte: c_int, enc: u8) callconv(.c) ?[*]u8 {
    var m: Mem = std.mem.zeroes(Mem);
    m.db = db;
    _ = sqlite3VdbeMemSetStr(&m, @ptrCast(z), @as(i64, nByte), enc, null);
    _ = sqlite3VdbeChangeEncoding(&m, SQLITE_UTF8);
    if (dbMallocFailed(db)) {
        sqlite3VdbeMemRelease(&m);
        m.z = null;
    }
    return m.z;
}

/// Bytes occupied by the first nChar characters of a UTF-16 string.
export fn sqlite3Utf16ByteLen(zIn: ?*const anyopaque, nByte: c_int, nChar: c_int) callconv(.c) c_int {
    const z0: [*]const u8 = @ptrCast(zIn.?);
    // SQLITE_UTF16NATIVE == SQLITE_UTF16LE on this (little-endian) target.
    var z = z0 + 1;
    const zEnd: [*]const u8 = @ptrFromInt(@intFromPtr(z0) +% @as(usize, @bitCast(@as(isize, nByte))) -% 1);
    var n: c_int = 0;
    while (n < nChar and @intFromPtr(z) <= @intFromPtr(zEnd)) {
        const ch: c_int = z[0];
        z += 2;
        if (ch >= 0xd8 and ch < 0xdc and @intFromPtr(z) <= @intFromPtr(zEnd) and z[0] >= 0xdc and z[0] < 0xe0) {
            z += 2;
        }
        n += 1;
    }
    return @intCast(@as(isize, @bitCast(@intFromPtr(z) -% @intFromPtr(z0))) - 1);
}

/// Clean up a UTF-8 string in place (drop malformed characters). Test-only in C.
export fn sqlite3Utf8To8(zIn_in: [*]u8) callconv(.c) c_int {
    var zIn: [*]const u8 = zIn_in;
    var zOut: [*]u8 = zIn_in;
    const zStart = zIn_in;
    while (zIn[0] != 0 and @intFromPtr(zOut) <= @intFromPtr(zIn)) {
        const c = sqlite3Utf8Read(&zIn);
        if (c != 0xfffd) writeUtf8(&zOut, c);
    }
    zOut[0] = 0;
    return @intCast(@intFromPtr(zOut) - @intFromPtr(zStart));
}

/// Self-test that the UTF-8 serialize/deserialize primitives are inverses.
/// Called from the TCL "translate_selftest". Asserts (live in ReleaseSafe) make
/// any divergence from the C semantics a hard failure.
export fn sqlite3UtfSelfTest() callconv(.c) void {
    var zBuf: [20]u8 = undefined;
    var i: u32 = 0;
    while (i < 0x00110000) : (i += 1) {
        var z: [*]u8 = &zBuf;
        writeUtf8(&z, i);
        const n = @intFromPtr(z) - @intFromPtr(&zBuf);
        z[0] = 0;
        var zr: [*]const u8 = &zBuf;
        const c = sqlite3Utf8Read(&zr);
        var t: u32 = i;
        if (i >= 0xD800 and i <= 0xDFFF) t = 0xFFFD;
        if ((i & 0xFFFFFFFE) == 0xFFFE) t = 0xFFFD;
        std.debug.assert(c == t);
        std.debug.assert(@intFromPtr(zr) - @intFromPtr(&zBuf) == n);
    }
}
