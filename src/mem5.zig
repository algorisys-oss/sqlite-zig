//! Zig port of SQLite's MEMSYS5 memory allocator (src/mem5.c).
//!
//! MEMSYS5 is a power-of-two buddy allocator over a single fixed buffer that
//! the application supplies via `sqlite3_config(SQLITE_CONFIG_HEAP, pBuf, n,
//! min)` before `sqlite3_initialize()`. It makes no use of the C library
//! malloc(): all allocations are carved out of that buffer. It is compiled only
//! when SQLITE_ENABLE_MEMSYS5 is defined (true in both builds of this project).
//!
//! Drivers (memsys5Malloc/Free/Realloc/Size/Roundup/Init/Shutdown) are static
//! in C; here they are plain (non-exported) functions, gathered into a static
//! `sqlite3_mem_methods` vtable returned by the one externally-linked routine
//! `sqlite3MemGetMemsys5()`. (main.c installs that vtable into
//! `sqlite3GlobalConfig.m` when a heap is configured.) Under SQLITE_TEST the
//! `sqlite3Memsys5Dump()` debug dumper is also exported.
//!
//! Internal state lives in the module-private `mem5` struct (we own its layout).
//! The control-byte array `aCtrl[]`, the per-size freelists, and the buddy bit
//! math are ported byte-for-byte from the C so behavior matches exactly.
//!
//! Coupling to internal SQLite globals: memsys5Init() reads four fields of
//! `sqlite3GlobalConfig` (a.k.a. `sqlite3Config`, since SQLITE_OMIT_WSD is off),
//! each at its GROUND-TRUTH OFFSET from c_layout.zig:
//!   * nHeap     (int)   -- Sqlite3Config_nHeap
//!   * pHeap     (void*) -- Sqlite3Config_pHeap
//!   * mnReq     (int)   -- Sqlite3Config_mnReq
//!   * bMemstat  (int)   -- Sqlite3Config_bMemstat
//! These offsets diverge between the production and testfixture configs (the
//! Sqlite3Config struct has SQLITE_DEBUG-conditional members), hence the
//! ground-truth read rather than mirroring the whole struct.
//!
//! Config divergence within this file:
//!   * The performance-statistics fields (nAlloc, totalAlloc, currentOut, ...)
//!     and their bookkeeping exist under `SQLITE_DEBUG || SQLITE_TEST`. We gate
//!     them on `config.sqlite_debug or config.sqlite_test`, which mirrors the C
//!     preprocessor exactly for the two project builds.
//!   * The 0xAA fill of fresh allocations and 0x55 fill of freed memory are
//!     SQLITE_DEBUG-only (`config.sqlite_debug`).
//!   * `sqlite3Memsys5Dump` is exported only under SQLITE_TEST
//!     (`config.sqlite_test`).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_MUTEX_STATIC_MEM: c_int = 6;

/// True when the stats fields/bookkeeping are compiled (SQLITE_DEBUG||SQLITE_TEST).
const have_stats = config.sqlite_debug or config.sqlite_test;
/// True when the debug memory-fill instrumentation is compiled (SQLITE_DEBUG).
const have_dbgfill = config.sqlite_debug;

// --- C / SQLite helpers resolved at link time ---
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3MutexAlloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, ch: c_int, n: usize) ?*anyopaque;

/// The public sqlite3_mem_methods vtable layout (from sqlite3.h).
const MemMethods = extern struct {
    xMalloc: ?*const fn (c_int) callconv(.c) ?*anyopaque,
    xFree: ?*const fn (?*anyopaque) callconv(.c) void,
    xRealloc: ?*const fn (?*anyopaque, c_int) callconv(.c) ?*anyopaque,
    xSize: ?*const fn (?*anyopaque) callconv(.c) c_int,
    xRoundup: ?*const fn (c_int) callconv(.c) c_int,
    xInit: ?*const fn (?*anyopaque) callconv(.c) c_int,
    xShutdown: ?*const fn (?*anyopaque) callconv(.c) void,
    pAppData: ?*anyopaque,
};

// --- Ground-truth reads of sqlite3GlobalConfig fields ---
// SQLITE_OMIT_WSD is off, so sqlite3GlobalConfig is literally the global
// `sqlite3Config`. We read four fields at their config-specific offsets.
extern const sqlite3Config: u8;
inline fn cfgBase() [*]const u8 {
    return @ptrCast(&sqlite3Config);
}
inline fn cfgInt(comptime off: usize) c_int {
    const p: *align(1) const c_int = @ptrCast(cfgBase() + off);
    return p.*;
}
inline fn cfgPtr(comptime off: usize) ?[*]u8 {
    const p: *align(1) const ?[*]u8 = @ptrCast(cfgBase() + off);
    return p.*;
}

// --- Module constants (mirror the #defines in mem5.c) ---
const LOGMAX: c_int = 30;
const CTRL_LOGSIZE: u8 = 0x1f; // Log2 size of this block
const CTRL_FREE: u8 = 0x20; // True if not checked out

/// One minimum-allocation slot, an array of which overlays zPool for freelists.
const Mem5Link = extern struct {
    next: c_int, // Index of next free chunk
    prev: c_int, // Index of previous free chunk
};

/// All module-static state. We own this layout entirely (internal struct).
const Mem5Global = struct {
    // Memory available for allocation
    szAtom: c_int = 0, // Smallest possible allocation in bytes
    nBlock: c_int = 0, // Number of szAtom sized blocks in zPool
    zPool: ?[*]u8 = null, // Memory available to be allocated

    // Mutex to control access to the memory allocation subsystem.
    mutex: ?*anyopaque = null,

    // Performance statistics (SQLITE_DEBUG || SQLITE_TEST)
    nAlloc: u64 = 0, // Total number of calls to malloc
    totalAlloc: u64 = 0, // Total of all malloc calls - includes internal frag
    totalExcess: u64 = 0, // Total internal fragmentation
    currentOut: u32 = 0, // Current checkout, including internal fragmentation
    currentCount: u32 = 0, // Current number of distinct checkouts
    maxOut: u32 = 0, // Maximum instantaneous currentOut
    maxCount: u32 = 0, // Maximum instantaneous currentCount
    maxRequest: u32 = 0, // Largest allocation (exclusive of internal frag)

    // Lists of free blocks. aiFreelist[i] holds blocks of size szAtom*2^i.
    aiFreelist: [LOGMAX + 1]c_int = @splat(0),

    // One control byte per block: tracks checkout state and size.
    aCtrl: ?[*]u8 = null,
};

var mem5: Mem5Global = .{};

/// Pointer to the idx-th Mem5Link overlaying zPool.
inline fn mem5Link(idx: c_int) *Mem5Link {
    const base = mem5.zPool.?;
    const byteOff: usize = @intCast(idx * mem5.szAtom);
    return @ptrCast(@alignCast(base + byteOff));
}

/// Unlink the chunk at index i from the iLogsize freelist.
fn memsys5Unlink(i: c_int, iLogsize: c_int) void {
    const next = mem5Link(i).next;
    const prev = mem5Link(i).prev;
    if (prev < 0) {
        mem5.aiFreelist[@intCast(iLogsize)] = next;
    } else {
        mem5Link(prev).next = next;
    }
    if (next >= 0) {
        mem5Link(next).prev = prev;
    }
}

/// Link the chunk at index i onto the iLogsize freelist.
fn memsys5Link(i: c_int, iLogsize: c_int) void {
    const x = mem5.aiFreelist[@intCast(iLogsize)];
    mem5Link(i).next = x;
    mem5Link(i).prev = -1;
    if (x >= 0) {
        mem5Link(x).prev = i;
    }
    mem5.aiFreelist[@intCast(iLogsize)] = i;
}

fn memsys5Enter() void {
    sqlite3_mutex_enter(mem5.mutex);
}
fn memsys5Leave() void {
    sqlite3_mutex_leave(mem5.mutex);
}

/// Return the size of an outstanding (checked-out) allocation, in bytes.
fn memsys5Size(p: ?*anyopaque) callconv(.c) c_int {
    const pb: [*]u8 = @ptrCast(p.?);
    const i: c_int = @intCast(@divTrunc(@as(isize, @intCast(@intFromPtr(pb) - @intFromPtr(mem5.zPool.?))), @as(isize, mem5.szAtom)));
    const logsize: c_int = mem5.aCtrl.?[@intCast(i)] & CTRL_LOGSIZE;
    // iSize = szAtom * (1 << logsize); wraps in C's int arithmetic.
    const iSize: c_int = mem5.szAtom *% (@as(c_int, 1) *% (@as(c_int, 1) << @intCast(logsize)));
    return iSize;
}

/// Allocate at least nByte bytes from the buddy pool. Caller holds the mutex.
fn memsys5MallocUnsafe(nByte: c_int) ?*anyopaque {
    var i: c_int = undefined; // Index of a slot
    var iBin: c_int = undefined; // Index into aiFreelist[]
    var iFullSz: c_int = undefined; // Size rounded up to power of 2
    var iLogsize: c_int = undefined; // Log2 of iFullSz/szAtom

    // No more than 1GiB per allocation
    if (nByte > 0x40000000) return null;

    if (have_stats) {
        // Track maximum allocation request (even unfulfilled ones).
        if (@as(u32, @bitCast(nByte)) > mem5.maxRequest) {
            mem5.maxRequest = @bitCast(nByte);
        }
    }

    // Round nByte up to the next valid power of two.
    iFullSz = mem5.szAtom;
    iLogsize = 0;
    while (iFullSz < nByte) {
        iFullSz *%= 2;
        iLogsize += 1;
    }

    // Find a freelist with a free block; split larger blocks if needed.
    iBin = iLogsize;
    while (iBin <= LOGMAX and mem5.aiFreelist[@intCast(iBin)] < 0) : (iBin += 1) {}
    if (iBin > LOGMAX) {
        // testcase( sqlite3GlobalConfig.xLog!=0 ) -- compiles away
        sqlite3_log(SQLITE_NOMEM, "failed to allocate %u bytes", @as(c_uint, @bitCast(nByte)));
        return null;
    }
    i = mem5.aiFreelist[@intCast(iBin)];
    memsys5Unlink(i, iBin);
    while (iBin > iLogsize) {
        iBin -= 1;
        const newSize: c_int = @as(c_int, 1) << @intCast(iBin);
        mem5.aCtrl.?[@intCast(i + newSize)] = CTRL_FREE | @as(u8, @intCast(iBin));
        memsys5Link(i + newSize, iBin);
    }
    mem5.aCtrl.?[@intCast(i)] = @intCast(iLogsize);

    if (have_stats) {
        // Update allocator performance statistics.
        mem5.nAlloc += 1;
        mem5.totalAlloc +%= @as(u64, @intCast(iFullSz));
        mem5.totalExcess +%= @as(u64, @intCast(iFullSz - nByte));
        mem5.currentCount += 1;
        mem5.currentOut +%= @as(u32, @bitCast(iFullSz));
        if (mem5.maxCount < mem5.currentCount) mem5.maxCount = mem5.currentCount;
        if (mem5.maxOut < mem5.currentOut) mem5.maxOut = mem5.currentOut;
    }

    if (have_dbgfill) {
        // Ensure callers do not rely on zeroed / stale memory.
        const off: usize = @intCast(i * mem5.szAtom);
        _ = memset(mem5.zPool.? + off, 0xAA, @intCast(iFullSz));
    }

    // Return a pointer to the allocated memory.
    const off: usize = @intCast(i * mem5.szAtom);
    return @ptrCast(mem5.zPool.? + off);
}

/// Free an outstanding allocation, coalescing buddies. Caller holds the mutex.
fn memsys5FreeUnsafe(pOld: ?*anyopaque) void {
    var iLogsize: u32 = undefined;
    var iBlock: c_int = undefined;

    const pb: [*]u8 = @ptrCast(pOld.?);
    iBlock = @intCast(@divTrunc(@as(isize, @intCast(@intFromPtr(pb) - @intFromPtr(mem5.zPool.?))), @as(isize, mem5.szAtom)));

    iLogsize = mem5.aCtrl.?[@intCast(iBlock)] & CTRL_LOGSIZE;
    var size: u32 = @as(u32, 1) << @intCast(iLogsize);

    mem5.aCtrl.?[@intCast(iBlock)] |= CTRL_FREE;
    mem5.aCtrl.?[@intCast(@as(u32, @intCast(iBlock)) +% size -% 1)] |= CTRL_FREE;

    if (have_stats) {
        mem5.currentCount -= 1;
        mem5.currentOut -%= size *% @as(u32, @bitCast(mem5.szAtom));
    }

    mem5.aCtrl.?[@intCast(iBlock)] = CTRL_FREE | @as(u8, @intCast(iLogsize));
    while (iLogsize < LOGMAX) { // ALWAYS(...) -- iLogsize<LOGMAX is the real test
        var iBuddy: c_int = undefined;
        if ((@as(u32, @bitCast(iBlock)) >> @intCast(iLogsize)) & 1 != 0) {
            iBuddy = iBlock - @as(c_int, @bitCast(size));
        } else {
            iBuddy = iBlock + @as(c_int, @bitCast(size));
            if (iBuddy >= mem5.nBlock) break;
        }
        if (mem5.aCtrl.?[@intCast(iBuddy)] != (CTRL_FREE | @as(u8, @intCast(iLogsize)))) break;
        memsys5Unlink(iBuddy, @intCast(iLogsize));
        iLogsize += 1;
        if (iBuddy < iBlock) {
            mem5.aCtrl.?[@intCast(iBuddy)] = CTRL_FREE | @as(u8, @intCast(iLogsize));
            mem5.aCtrl.?[@intCast(iBlock)] = 0;
            iBlock = iBuddy;
        } else {
            mem5.aCtrl.?[@intCast(iBlock)] = CTRL_FREE | @as(u8, @intCast(iLogsize));
            mem5.aCtrl.?[@intCast(iBuddy)] = 0;
        }
        size *%= 2;
    }

    if (have_dbgfill) {
        // Poison freed memory to catch use-after-free.
        const off: usize = @intCast(@as(usize, @intCast(iBlock)) * @as(usize, @intCast(mem5.szAtom)));
        _ = memset(mem5.zPool.? + off, 0x55, @intCast(size));
    }

    memsys5Link(iBlock, @intCast(iLogsize));
}

/// Allocate nBytes of memory.
fn memsys5Malloc(nBytes: c_int) callconv(.c) ?*anyopaque {
    var p: ?*anyopaque = null;
    if (nBytes > 0) {
        memsys5Enter();
        p = memsys5MallocUnsafe(nBytes);
        memsys5Leave();
    }
    return p;
}

/// Free memory. The outer allocator guarantees pPrior != 0.
fn memsys5Free(pPrior: ?*anyopaque) callconv(.c) void {
    memsys5Enter();
    memsys5FreeUnsafe(pPrior);
    memsys5Leave();
}

/// Resize an existing allocation. pPrior != 0, nBytes is a power of two
/// (a memsys5Roundup() result), and may be 0 for an oversize request.
fn memsys5Realloc(pPrior: ?*anyopaque, nBytes: c_int) callconv(.c) ?*anyopaque {
    if (nBytes == 0) {
        return null;
    }
    const nOld: c_int = memsys5Size(pPrior);
    if (nBytes <= nOld) {
        return pPrior;
    }
    const p = memsys5Malloc(nBytes);
    if (p) |np| {
        _ = memcpy(np, pPrior, @intCast(nOld));
        memsys5Free(pPrior);
    }
    return p;
}

/// Round a request up to the next valid allocation size (a power of two),
/// or 0 if it is too large for this system.
fn memsys5Roundup(n: c_int) callconv(.c) c_int {
    var iFullSz: c_int = undefined;
    if (n <= mem5.szAtom * 2) {
        if (n <= mem5.szAtom) return mem5.szAtom;
        return mem5.szAtom * 2;
    }
    if (n > 0x10000000) {
        if (n > 0x40000000) return 0;
        if (n > 0x20000000) return 0x40000000;
        return 0x20000000;
    }
    iFullSz = mem5.szAtom * 8;
    while (iFullSz < n) : (iFullSz *%= 4) {}
    if (@divTrunc(iFullSz, 2) >= n) return @divTrunc(iFullSz, 2);
    return iFullSz;
}

/// Ceiling of log2(iValue). e.g. Log(1)=0, Log(2)=1, Log(5)=3, Log(8)=3.
fn memsys5Log(iValue: c_int) c_int {
    var iLog: c_int = 0;
    const limit: c_int = @as(c_int, @intCast(@sizeOf(c_int) * 8)) - 1;
    while (iLog < limit and (@as(c_int, 1) << @intCast(iLog)) < iValue) : (iLog += 1) {}
    return iLog;
}

/// Initialize the allocator from the configured heap. Not threadsafe; caller
/// holds a mutex.
fn memsys5Init(NotUsed: ?*anyopaque) callconv(.c) c_int {
    _ = NotUsed;

    // Disable the mutex while initializing.
    mem5.mutex = null;

    const nByte: c_int = cfgInt(L.Sqlite3Config_nHeap);
    const zByte: ?[*]u8 = cfgPtr(L.Sqlite3Config_pHeap); // assumed non-null by sqlite3_config()

    const nMinLog: c_int = memsys5Log(cfgInt(L.Sqlite3Config_mnReq));
    mem5.szAtom = @as(c_int, 1) << @intCast(nMinLog);
    while (@as(c_int, @sizeOf(Mem5Link)) > mem5.szAtom) {
        mem5.szAtom = mem5.szAtom << 1;
    }

    mem5.nBlock = @divTrunc(nByte, mem5.szAtom + @as(c_int, @sizeOf(u8)));
    mem5.zPool = zByte;
    const ctrlOff: usize = @intCast(mem5.nBlock * mem5.szAtom);
    mem5.aCtrl = zByte.? + ctrlOff;

    var ii: c_int = 0;
    while (ii <= LOGMAX) : (ii += 1) {
        mem5.aiFreelist[@intCast(ii)] = -1;
    }

    var iOffset: c_int = 0;
    ii = LOGMAX;
    while (ii >= 0) : (ii -= 1) {
        const nAlloc: c_int = @as(c_int, 1) << @intCast(ii);
        if ((iOffset + nAlloc) <= mem5.nBlock) {
            mem5.aCtrl.?[@intCast(iOffset)] = @as(u8, @intCast(ii)) | CTRL_FREE;
            memsys5Link(iOffset, ii);
            iOffset += nAlloc;
        }
    }

    // If a mutex is required for normal operation, allocate one.
    if (cfgInt(L.Sqlite3Config_bMemstat) == 0) {
        mem5.mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MEM);
    }

    return SQLITE_OK;
}

/// Deinitialize this module.
fn memsys5Shutdown(NotUsed: ?*anyopaque) callconv(.c) void {
    _ = NotUsed;
    mem5.mutex = null;
}

/// Open the named file (or stdout) and dump a log of unfreed allocations.
/// SQLITE_TEST only — referenced by test_malloc.c's sqlite3_dump_memsys5.
fn sqlite3Memsys5Dump(zFilename: ?[*:0]const u8) callconv(.c) void {
    const c = struct {
        extern var stdout: *anyopaque;
        extern var stderr: *anyopaque;
        extern fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
        extern fn fclose(stream: *anyopaque) c_int;
        extern fn fflush(stream: *anyopaque) c_int;
        extern fn fprintf(stream: *anyopaque, fmt: [*:0]const u8, ...) c_int;
    };

    var out: *anyopaque = undefined;
    if (zFilename == null or zFilename.?[0] == 0) {
        out = c.stdout;
    } else {
        out = c.fopen(zFilename.?, "w") orelse {
            _ = c.fprintf(c.stderr, "** Unable to output memory debug output log: %s **\n", zFilename.?);
            return;
        };
    }
    memsys5Enter();
    const nMinLog: c_int = memsys5Log(mem5.szAtom);
    var i: c_int = 0;
    while (i <= LOGMAX and i + nMinLog < 32) : (i += 1) {
        var n: c_int = 0;
        var j: c_int = mem5.aiFreelist[@intCast(i)];
        while (j >= 0) : (j = mem5Link(j).next) {
            n += 1;
        }
        _ = c.fprintf(out, "freelist items of size %d: %d\n", mem5.szAtom << @intCast(i), n);
    }
    _ = c.fprintf(out, "mem5.nAlloc       = %llu\n", mem5.nAlloc);
    _ = c.fprintf(out, "mem5.totalAlloc   = %llu\n", mem5.totalAlloc);
    _ = c.fprintf(out, "mem5.totalExcess  = %llu\n", mem5.totalExcess);
    _ = c.fprintf(out, "mem5.currentOut   = %u\n", mem5.currentOut);
    _ = c.fprintf(out, "mem5.currentCount = %u\n", mem5.currentCount);
    _ = c.fprintf(out, "mem5.maxOut       = %u\n", mem5.maxOut);
    _ = c.fprintf(out, "mem5.maxCount     = %u\n", mem5.maxCount);
    _ = c.fprintf(out, "mem5.maxRequest   = %u\n", mem5.maxRequest);
    memsys5Leave();
    if (out == c.stdout) {
        _ = c.fflush(c.stdout);
    } else {
        _ = c.fclose(out);
    }
}

/// The memsys5 driver vtable.
const memsys5Methods: MemMethods = .{
    .xMalloc = &memsys5Malloc,
    .xFree = &memsys5Free,
    .xRealloc = &memsys5Realloc,
    .xSize = &memsys5Size,
    .xRoundup = &memsys5Roundup,
    .xInit = &memsys5Init,
    .xShutdown = &memsys5Shutdown,
    .pAppData = null,
};

/// The only routine in this file with external linkage (production builds):
/// returns the static memsys5 method table. main.c installs it.
export fn sqlite3MemGetMemsys5() callconv(.c) *const MemMethods {
    return &memsys5Methods;
}

comptime {
    if (config.sqlite_test) {
        @export(&sqlite3Memsys5Dump, .{ .name = "sqlite3Memsys5Dump" });
    }
}
