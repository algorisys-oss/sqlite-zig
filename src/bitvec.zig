//! Zig port of SQLite's fixed-length bitmap (src/bitvec.c).
//!
//! Drop-in replacement exporting the same C-ABI symbols. The `Bitvec` object is
//! fully opaque — it is defined only in bitvec.c and every caller (the pager)
//! holds it as an opaque `Bitvec*` — so only `sizeof(Bitvec)==BITVEC_SZ` is
//! load-bearing across the boundary, not the field layout. We keep the faithful
//! three-representation layout (direct bitmap / hash table / recursive sub-vecs)
//! and assert the size at comptime.
//!
//! Build config assumed (mirrors `sqlite_flags` in build.zig):
//!   no SQLITE_USE_ALLOCA (stack allocs route through sqlite3DbMallocRaw),
//!   no SQLITE_UNTESTABLE (sqlite3BitvecBuiltinTest is compiled),
//!   SQLITE_NOMEM_BKPT == SQLITE_NOMEM in production (returns 7).
//!
//! `sqlite3ShowBitvec` is SQLITE_DEBUG-only and has no external callers, so it
//! is intentionally not provided.

const std = @import("std");

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT collapses to this in production

// --- Compile-time geometry (mirrors the BITVEC_* macros for a 64-bit target) ---
const PTR_SZ = @sizeOf(*anyopaque);
const BITVEC_SZ = 512; // Size of the Bitvec structure in bytes.
const BITVEC_USIZE = ((BITVEC_SZ - 3 * @sizeOf(u32)) / PTR_SZ) * PTR_SZ;
const BITVEC_SZELEM = 8; // bits per bitmap element (u8)
const BITVEC_NELEM = BITVEC_USIZE / @sizeOf(u8); // elements in the bitmap array
const BITVEC_NBIT = BITVEC_NELEM * BITVEC_SZELEM; // bits in the bitmap array
const BITVEC_NINT = BITVEC_USIZE / @sizeOf(u32); // u32 slots in the hash table
const BITVEC_MXHASH = BITVEC_NINT / 2; // hash entries before sub-dividing
const BITVEC_NPTR: u32 = @intCast(BITVEC_USIZE / PTR_SZ); // recursive sub-vec count

/// Hash function for the aHash representation (the *1 multiplier is empirically
/// as good as any prime here).
inline fn bitvecHash(x: u32) u32 {
    return x % BITVEC_NINT;
}

/// Mask for bit (i & 7) within a bitmap byte.
inline fn bitMask(i: u32) u8 {
    return @as(u8, 1) << @as(u3, @intCast(i & (BITVEC_SZELEM - 1)));
}

const BitvecU = extern union {
    aBitmap: [BITVEC_NELEM]u8, // direct bitmap
    aHash: [BITVEC_NINT]u32, // hash-table representation (values are 1-based)
    apSub: [BITVEC_NPTR]?*Bitvec, // recursive sub-bitmaps
};

const Bitvec = extern struct {
    iSize: u32, // Maximum bit index (1..iSize).
    nSet: u32, // Number of set bits — only meaningful for the aHash form.
    iDivisor: u32, // Bits handled per apSub[] entry (0 if not subdivided).
    u: BitvecU,
};

comptime {
    std.debug.assert(@sizeOf(Bitvec) == BITVEC_SZ);
}

// --- C helpers we call back into (resolved at link time from the C objects) ---
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3_randomness(N: c_int, pBuf: ?*anyopaque) void;

/// Create a new bitmap handling bits 1..iSize. Returns null if malloc fails.
export fn sqlite3BitvecCreate(iSize: u32) callconv(.c) ?*Bitvec {
    const p: ?*Bitvec = @ptrCast(@alignCast(sqlite3MallocZero(@sizeOf(Bitvec))));
    if (p) |pp| pp.iSize = iSize;
    return p;
}

/// Test whether bit i is set (p must be non-null; out-of-range → false).
export fn sqlite3BitvecTestNotNull(p_in: ?*Bitvec, i_in: u32) callconv(.c) c_int {
    var p = p_in.?;
    var i = i_in;
    i -%= 1;
    if (i >= p.iSize) return 0;
    while (p.iDivisor != 0) {
        const bin = i / p.iDivisor;
        i = i % p.iDivisor;
        p = p.u.apSub[bin] orelse return 0;
    }
    if (p.iSize <= BITVEC_NBIT) {
        return @intFromBool((p.u.aBitmap[i / BITVEC_SZELEM] & bitMask(i)) != 0);
    } else {
        var h = bitvecHash(i);
        i += 1;
        while (p.u.aHash[h] != 0) {
            if (p.u.aHash[h] == i) return 1;
            h = (h + 1) % BITVEC_NINT;
        }
        return 0;
    }
}

/// Test whether bit i is set; false if p is null.
export fn sqlite3BitvecTest(p: ?*Bitvec, i: u32) callconv(.c) c_int {
    return @intFromBool(p != null and sqlite3BitvecTestNotNull(p, i) != 0);
}

/// Set bit i. Returns SQLITE_OK, or SQLITE_NOMEM if a sub-bitmap alloc fails.
export fn sqlite3BitvecSet(p_in: ?*Bitvec, i_in: u32) callconv(.c) c_int {
    var p = p_in orelse return SQLITE_OK;
    var i = i_in;
    i -= 1;
    while (p.iSize > BITVEC_NBIT and p.iDivisor != 0) {
        const bin = i / p.iDivisor;
        i = i % p.iDivisor;
        if (p.u.apSub[bin] == null) {
            p.u.apSub[bin] = sqlite3BitvecCreate(p.iDivisor);
            if (p.u.apSub[bin] == null) return SQLITE_NOMEM;
        }
        p = p.u.apSub[bin].?;
    }
    if (p.iSize <= BITVEC_NBIT) {
        p.u.aBitmap[i / BITVEC_SZELEM] |= bitMask(i);
        return SQLITE_OK;
    }
    var h = bitvecHash(i);
    i += 1; // aHash stores 1-based values

    // Decide whether we still need the "is the hash too full?" rehash check.
    var rehash_check = true;
    if (p.u.aHash[h] == 0) {
        // No collision: add directly unless the table is nearly full.
        if (p.nSet < (BITVEC_NINT - 1)) {
            rehash_check = false; // -> bitvec_set_end
        }
    } else {
        // Collision: if already present we're done, else probe for a free slot.
        while (true) {
            if (p.u.aHash[h] == i) return SQLITE_OK;
            h += 1;
            if (h >= BITVEC_NINT) h = 0;
            if (p.u.aHash[h] == 0) break;
        }
    }

    if (rehash_check and p.nSet >= BITVEC_MXHASH) {
        // Hash is full: explode into BITVEC_NPTR sub-bitmaps and re-insert.
        const aiValues_raw = sqlite3DbMallocRaw(null, @sizeOf(@TypeOf(p.u.aHash)));
        if (aiValues_raw == null) return SQLITE_NOMEM;
        const aiValues: [*]u32 = @ptrCast(@alignCast(aiValues_raw.?));
        @memcpy(aiValues[0..BITVEC_NINT], p.u.aHash[0..]);
        @memset(std.mem.sliceAsBytes(p.u.apSub[0..]), 0);
        p.iDivisor = p.iSize / BITVEC_NPTR;
        if (p.iSize % BITVEC_NPTR != 0) p.iDivisor += 1;
        if (p.iDivisor < BITVEC_NBIT) p.iDivisor = BITVEC_NBIT;
        var rc = sqlite3BitvecSet(p, i);
        var j: u32 = 0;
        while (j < BITVEC_NINT) : (j += 1) {
            if (aiValues[j] != 0) rc |= sqlite3BitvecSet(p, aiValues[j]);
        }
        sqlite3DbFree(null, aiValues_raw);
        return rc;
    }

    // bitvec_set_end
    p.nSet += 1;
    p.u.aHash[h] = i;
    return SQLITE_OK;
}

/// Clear bit i. pBuf must point to at least BITVEC_SZ bytes of scratch storage
/// used to rebuild the hash table.
export fn sqlite3BitvecClear(p_in: ?*Bitvec, i_in: u32, pBuf: ?*anyopaque) callconv(.c) void {
    var p = p_in orelse return;
    var i = i_in;
    i -= 1;
    while (p.iDivisor != 0) {
        const bin = i / p.iDivisor;
        i = i % p.iDivisor;
        p = p.u.apSub[bin] orelse return;
    }
    if (p.iSize <= BITVEC_NBIT) {
        p.u.aBitmap[i / BITVEC_SZELEM] &= ~bitMask(i);
    } else {
        const aiValues: [*]u32 = @ptrCast(@alignCast(pBuf.?));
        @memcpy(aiValues[0..BITVEC_NINT], p.u.aHash[0..]);
        @memset(std.mem.sliceAsBytes(p.u.aHash[0..]), 0);
        p.nSet = 0;
        var j: u32 = 0;
        while (j < BITVEC_NINT) : (j += 1) {
            if (aiValues[j] != 0 and aiValues[j] != i + 1) {
                var h = bitvecHash(aiValues[j] - 1);
                p.nSet += 1;
                while (p.u.aHash[h] != 0) {
                    h += 1;
                    if (h >= BITVEC_NINT) h = 0;
                }
                p.u.aHash[h] = aiValues[j];
            }
        }
    }
}

/// Destroy a bitmap, recursively freeing sub-bitmaps.
export fn sqlite3BitvecDestroy(p_in: ?*Bitvec) callconv(.c) void {
    const p = p_in orelse return;
    if (p.iDivisor != 0) {
        var i: u32 = 0;
        while (i < BITVEC_NPTR) : (i += 1) {
            sqlite3BitvecDestroy(p.u.apSub[i]);
        }
    }
    sqlite3_free(p);
}

/// Return the iSize the bitmap was created with.
export fn sqlite3BitvecSize(p: *Bitvec) callconv(.c) u32 {
    return p.iSize;
}

// --- Built-in self test (SQLITE_UNTESTABLE is off) ---

inline fn opBit(idx: c_int) u8 {
    return @as(u8, 1) << @as(u3, @intCast(idx & 7));
}
inline fn opIdx(idx: c_int) usize {
    return @as(usize, @intCast(idx)) >> 3;
}

/// Run the Bitvec opcode program in aOp against both a Bitvec and a reference
/// linear array, returning 0 on match, a positive bit index on mismatch, or -1
/// on allocation failure. Opcodes 6/7 (debug dumps) are no-ops here.
export fn sqlite3BitvecBuiltinTest(sz: c_int, aOp: [*]c_int) callconv(.c) c_int {
    var pBitvec: ?*Bitvec = null;
    var pV: ?[*]u8 = null;
    var rc: c_int = -1;

    if (sz <= 0) {
        pBitvec = sqlite3BitvecCreate(2 * @as(u32, @intCast(-sz)));
        pV = null;
    } else {
        pBitvec = sqlite3BitvecCreate(@intCast(sz));
        pV = @ptrCast(sqlite3MallocZero(@intCast(@divTrunc(7 + @as(i64, sz), 8) + 1)));
    }
    const pTmpSpace = sqlite3_malloc64(BITVEC_SZ);

    run: {
        if (pBitvec == null or pTmpSpace == null or (pV == null and sz > 0)) break :run;

        // NULL pBitvec tests.
        _ = sqlite3BitvecSet(null, 1);
        sqlite3BitvecClear(null, 1, pTmpSpace);

        // Run the program.
        var pc: usize = 0;
        var i: c_int = 0;
        while (aOp[pc] != 0) {
            const op = aOp[pc];
            if (op >= 6) {
                pc += 1; // opcodes 6/7 are SQLITE_DEBUG-only dumps: no-op here
                continue;
            }
            var nx: c_int = undefined;
            switch (op) {
                1, 2, 5 => {
                    nx = 4;
                    i = aOp[pc + 2] - 1;
                    aOp[pc + 2] += aOp[pc + 3];
                },
                else => { // 3, 4, and default
                    nx = 2;
                    sqlite3_randomness(@sizeOf(c_int), &i);
                },
            }
            aOp[pc + 1] -= 1;
            if (aOp[pc + 1] > 0) nx = 0;
            pc += @intCast(nx);
            i = @rem(i & 0x7fffffff, sz);
            if ((op & 1) != 0) {
                if (pV) |v| v[opIdx(i + 1)] |= opBit(i + 1);
                if (op != 5) {
                    if (sqlite3BitvecSet(pBitvec, @intCast(i + 1)) != 0) break :run;
                }
            } else {
                if (pV) |v| v[opIdx(i + 1)] &= ~opBit(i + 1);
                sqlite3BitvecClear(pBitvec, @intCast(i + 1), pTmpSpace);
            }
        }

        // Compare the linear reference array against the Bitvec object.
        if (pV) |v| {
            rc = sqlite3BitvecTest(null, 0) + sqlite3BitvecTest(pBitvec, @intCast(sz + 1)) +
                sqlite3BitvecTest(pBitvec, 0) +
                (@as(c_int, @intCast(sqlite3BitvecSize(pBitvec.?))) - sz);
            var k: c_int = 1;
            while (k <= sz) : (k += 1) {
                const ref = @intFromBool((v[opIdx(k)] & opBit(k)) != 0);
                if (ref != sqlite3BitvecTest(pBitvec, @intCast(k))) {
                    rc = k;
                    break;
                }
            }
        } else {
            rc = 0;
        }
    }

    sqlite3_free(pTmpSpace);
    sqlite3_free(@ptrCast(pV));
    sqlite3BitvecDestroy(pBitvec);
    return rc;
}
