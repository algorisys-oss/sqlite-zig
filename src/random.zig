//! Zig port of SQLite's PRNG (src/random.c).
//!
//! Drop-in replacement: exports the same C-ABI symbols
//! (`sqlite3_randomness`, `sqlite3PrngSaveState`, `sqlite3PrngRestoreState`)
//! and produces a byte-identical random stream to the C original — it is the
//! same RFC-7539 ChaCha20 generator with the same seeding, so existing tests
//! (which depend on the exact sequence) keep passing.
//!
//! Build config assumed (mirrors `sqlite_flags` in build.zig):
//!   SQLITE_THREADSAFE=1, no SQLITE_OMIT_WSD, no SQLITE_OMIT_AUTOINIT,
//!   no SQLITE_UNTESTABLE.

const std = @import("std");
const chacha = @import("chacha.zig");

const SQLITE_MUTEX_STATIC_PRNG: c_int = 5;

// --- C helpers we call back into (resolved at link time from the C objects) ---
extern fn sqlite3_initialize() c_int;
extern fn sqlite3MutexAlloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3_vfs_find(zVfsName: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3OsRandomness(pVfs: ?*anyopaque, nByte: c_int, zBufOut: [*]u8) c_int;

const PrngType = chacha.PrngType;

var sqlite3Prng: PrngType = std.mem.zeroes(PrngType);
var sqlite3SavedPrng: PrngType = std.mem.zeroes(PrngType);

/// Return N random bytes. Public SQLite API: `void sqlite3_randomness(int,void*)`.
export fn sqlite3_randomness(N_in: c_int, pBuf: ?*anyopaque) callconv(.c) void {
    var N = N_in;

    // SQLITE_OMIT_AUTOINIT is not set.
    if (sqlite3_initialize() != 0) return;

    // SQLITE_THREADSAFE is set.
    const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_PRNG);

    sqlite3_mutex_enter(mutex);
    if (N <= 0 or pBuf == null) {
        sqlite3Prng.s[0] = 0; // force re-seed on next call
        sqlite3_mutex_leave(mutex);
        return;
    }
    var zBuf: [*]u8 = @ptrCast(pBuf.?);

    // Seed once, on first use.
    if (sqlite3Prng.s[0] == 0) {
        const pVfs = sqlite3_vfs_find(null);
        const chacha20_init = [_]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
        @memcpy(sqlite3Prng.s[0..4], &chacha20_init);
        if (pVfs == null) {
            // NEVER() path in the C original.
            @memset(std.mem.sliceAsBytes(sqlite3Prng.s[4..15]), 0);
        } else {
            _ = sqlite3OsRandomness(pVfs, 44, @ptrCast(&sqlite3Prng.s[4]));
        }
        sqlite3Prng.s[15] = sqlite3Prng.s[12];
        sqlite3Prng.s[12] = 0;
        sqlite3Prng.n = 0;
    }

    std.debug.assert(N > 0);
    const out_bytes = std.mem.sliceAsBytes(sqlite3Prng.out[0..]); // 64-byte view
    while (true) {
        const n: c_int = sqlite3Prng.n;
        if (N <= n) {
            const len: usize = @intCast(N);
            const start: usize = sqlite3Prng.n - @as(u8, @intCast(N));
            @memcpy(zBuf[0..len], out_bytes[start .. start + len]);
            sqlite3Prng.n -= @intCast(N);
            break;
        }
        if (sqlite3Prng.n > 0) {
            const avail: usize = sqlite3Prng.n;
            @memcpy(zBuf[0..avail], out_bytes[0..avail]);
            N -= n;
            zBuf += avail;
        }
        sqlite3Prng.s[12] +%= 1;
        chacha.block(&sqlite3Prng.out, &sqlite3Prng.s);
        sqlite3Prng.n = 64;
    }
    sqlite3_mutex_leave(mutex);
}

// SQLITE_UNTESTABLE is not set: provide the test-control save/restore hooks.
export fn sqlite3PrngSaveState() callconv(.c) void {
    sqlite3SavedPrng = sqlite3Prng;
}

export fn sqlite3PrngRestoreState() callconv(.c) void {
    sqlite3Prng = sqlite3SavedPrng;
}
