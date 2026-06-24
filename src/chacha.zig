//! RFC-7539 ChaCha20 block function — the pure core of SQLite's PRNG.
//! Kept separate from random.zig (which has the stateful C-ABI surface) so the
//! transform can be unit-tested in isolation against the RFC test vector.

const std = @import("std");

/// PRNG state, matching the C `struct sqlite3PrngType` layout/semantics.
/// `out` is u32 (the C block function writes it via a `(u32*)` cast); callers
/// draw bytes from it through a byte view.
pub const PrngType = struct {
    s: [16]u32,
    out: [16]u32,
    n: u8,
};

/// ChaCha20 quarter-round, in place on four state words.
inline fn qr(x: *[16]u32, ai: usize, bi: usize, ci: usize, di: usize) void {
    var a = x[ai];
    var b = x[bi];
    var c = x[ci];
    var d = x[di];
    a +%= b; d ^= a; d = std.math.rotl(u32, d, 16);
    c +%= d; b ^= c; b = std.math.rotl(u32, b, 12);
    a +%= b; d ^= a; d = std.math.rotl(u32, d, 8);
    c +%= d; b ^= c; b = std.math.rotl(u32, b, 7);
    x[ai] = a; x[bi] = b; x[ci] = c; x[di] = d;
}

/// 20-round ChaCha20 block: 10 iterations of (4 column + 4 diagonal) rounds,
/// then add the input. Identical to SQLite's `chacha_block` in random.c.
pub fn block(out: *[16]u32, in: *const [16]u32) void {
    var x: [16]u32 = in.*;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        qr(&x, 0, 4, 8, 12);
        qr(&x, 1, 5, 9, 13);
        qr(&x, 2, 6, 10, 14);
        qr(&x, 3, 7, 11, 15);
        qr(&x, 0, 5, 10, 15);
        qr(&x, 1, 6, 11, 12);
        qr(&x, 2, 7, 8, 13);
        qr(&x, 3, 4, 9, 14);
    }
    for (0..16) |j| out[j] = x[j] +% in[j];
}

test "RFC 7539 §2.3.2 ChaCha20 block test vector" {
    // Published input state: constants | key(00..1f) | counter=1 | nonce.
    const in = [16]u32{
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    };
    const expected = [16]u32{
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    };
    var out: [16]u32 = undefined;
    block(&out, &in);
    try std.testing.expectEqualSlices(u32, &expected, &out);
}
