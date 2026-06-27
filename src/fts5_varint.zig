//! Zig port of the fts5_varint.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 26881-27226).
//!
//! Varint serialization/deserialization for FTS5. Self-contained leaf: no
//! sibling-section dependencies. Exports the four C-ABI symbols that the rest
//! of the FTS5 family calls:
//!
//!   sqlite3Fts5GetVarint32  - read a 32-bit varint (unrolled 1/2/3-byte cases)
//!   sqlite3Fts5GetVarint    - read a 64-bit varint, returns byte count (c_int)
//!   sqlite3Fts5PutVarint    - write a 64-bit varint, returns int byte count
//!   sqlite3Fts5GetVarintLen - bytes needed for a 32-bit value (assumes >=128)
//!
//! Byte-exact with the C originals (sqlite3GetVarint32 lineage).

const int = @import("fts5_int.zig");

const SLOT_2_0: u32 = 0x001fc07f; // (0x7f<<14) | 0x7f
const SLOT_4_2_0: u32 = 0xf01fc07f; // (0xf<<28) | SLOT_2_0

/// fts5.c 26983-27140: read a 64-bit varint from p[0]. Returns bytes read.
///
/// NOTE: the C prototype declares the return type as `u8`, but every Zig
/// declaration/caller in this project (e.g. the `extern` in fts5_index.zig)
/// treats it as `c_int`. Returning `u8` under callconv(.c) only writes the
/// low byte of the return register, leaving its upper bytes undefined; a caller
/// reading the full `c_int` then picks up garbage (observed: a 2-byte varint
/// reported as length 258). Return `c_int` so the whole register is defined and
/// matches the declared prototype.
export fn sqlite3Fts5GetVarint(p0: [*]const u8, v: *u64) callconv(.c) c_int {
    var p = p0;
    var a: u32 = undefined;
    var b: u32 = undefined;
    var s: u32 = undefined;

    a = p[0];
    if ((a & 0x80) == 0) {
        v.* = a;
        return 1;
    }

    p += 1;
    b = p[0];
    if ((b & 0x80) == 0) {
        a &= 0x7f;
        a = a << 7;
        a |= b;
        v.* = a;
        return 2;
    }

    p += 1;
    a = a << 14;
    a |= p[0];
    if ((a & 0x80) == 0) {
        a &= SLOT_2_0;
        b &= 0x7f;
        b = b << 7;
        a |= b;
        v.* = a;
        return 3;
    }

    // CSE1 from below
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

    // CSE2 from below
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
    // p[-4] : 4 bytes back from the current p
    b = (p - 4)[0];
    b &= 0x7f;
    b = b >> 3;
    s |= b;

    v.* = (@as(u64, s) << 32) | a;

    return 9;
}

/// fts5.c 26905-26964: read a 32-bit varint. Unrolls 1/2/3-byte cases; falls
/// back to the 64-bit reader for the rare larger values.
export fn sqlite3Fts5GetVarint32(p0: [*]const u8, v: *u32) callconv(.c) c_int {
    var p = p0;
    var a: u32 = undefined;
    var b: u32 = undefined;

    // The 1-byte case.
    a = p[0];
    if ((a & 0x80) == 0) {
        v.* = a;
        return 1;
    }

    // The 2-byte case.
    p += 1;
    b = p[0];
    if ((b & 0x80) == 0) {
        a &= 0x7f;
        a = a << 7;
        v.* = a | b;
        return 2;
    }

    // The 3-byte case.
    p += 1;
    a = a << 14;
    a |= p[0];
    if ((a & 0x80) == 0) {
        a &= (0x7f << 14) | (0x7f);
        b &= 0x7f;
        b = b << 7;
        v.* = a | b;
        return 3;
    }

    // The larger cases: defer to the 64-bit reader.
    var v64: u64 = undefined;
    p -= 2;
    const n = sqlite3Fts5GetVarint(p, &v64);
    v.* = @as(u32, @truncate(v64)) & 0x7FFFFFFF;
    return n;
}

/// fts5.c 27177-27200: the slow (>=3 byte) varint writer.
fn fts5PutVarint64(p: [*]u8, v0: u64) c_int {
    var v = v0;
    if ((v & (@as(u64, 0xff000000) << 32)) != 0) {
        p[8] = @truncate(v);
        v >>= 8;
        var i: i32 = 7;
        while (i >= 0) : (i -= 1) {
            p[@intCast(i)] = @truncate((v & 0x7f) | 0x80);
            v >>= 7;
        }
        return 9;
    }
    var buf: [10]u8 = undefined;
    var n: usize = 0;
    while (true) {
        buf[n] = @truncate((v & 0x7f) | 0x80);
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

/// fts5.c 27202-27213: write a 64-bit varint. Returns bytes written (1..9).
export fn sqlite3Fts5PutVarint(p: [*]u8, v: u64) callconv(.c) c_int {
    if (v <= 0x7f) {
        p[0] = @truncate(v & 0x7f);
        return 1;
    }
    if (v <= 0x3fff) {
        p[0] = @truncate(((v >> 7) & 0x7f) | 0x80);
        p[1] = @truncate(v & 0x7f);
        return 2;
    }
    return fts5PutVarint64(p, v);
}

/// fts5.c 27216-27225: number of bytes to encode iVal (assumed >= 1<<7).
export fn sqlite3Fts5GetVarintLen(iVal: u32) callconv(.c) c_int {
    if (iVal < (1 << 14)) return 2;
    if (iVal < (1 << 21)) return 3;
    if (iVal < (1 << 28)) return 4;
    return 5;
}

comptime {
    _ = int; // foundation import kept for type/constant access parity
}
