//! Zig port of SQLite's default page-cache implementation (src/pcache1.c).
//!
//! This is the `sqlite3_pcache_methods2` backend that pcache.zig (already
//! ported) dispatches to. `sqlite3PCacheSetDefault()` installs these methods
//! via `sqlite3_config(SQLITE_CONFIG_PCACHE2, ...)`. It also implements part of
//! the SQLITE_CONFIG_PAGECACHE (start-time buffer) feature and the
//! sqlite3PageMalloc/Free helpers used by btree.c.
//!
//! Struct coupling:
//!   * `PgHdr1`, `PGroup`, `PCache1`, `PgFreeslot`, and the `PCacheGlobal`
//!     state are ALL internal/opaque to pcache1.c — no other TU knows their
//!     layout. We own these layouts entirely; only self-consistency within
//!     this file matters (no ground-truth asserts apply, like Bitvec/RowSet).
//!   * The only ABI boundary to pcache.zig is the PUBLIC `sqlite3_pcache_page`
//!     (`page.pBuf`/`page.pExtra`), which is the first member of PgHdr1. The
//!     opaque `sqlite3_pcache*` handle pcache.zig holds is in fact a PCache1*.
//!
//! Coupling to internal SQLite globals: pcache1Init() reads three fields of
//! `sqlite3GlobalConfig` (a.k.a. `sqlite3Config`, since SQLITE_OMIT_WSD is off),
//! each at its GROUND-TRUTH OFFSET from c_layout.zig:
//!   * pPage      (void*) -- Sqlite3Config_pPage      (start-time page buffer)
//!   * bCoreMutex (int)   -- Sqlite3Config_bCoreMutex
//!   * nPage      (int)   -- Sqlite3Config_nPage      (bulk-alloc page count)
//! These offsets may diverge between the production and testfixture configs
//! (Sqlite3Config has SQLITE_DEBUG-conditional members), hence the ground-truth
//! read rather than mirroring the whole struct. The MEMORY_MANAGEMENT-only read
//! of pPage in sqlite3PcacheReleaseMemory is not compiled (see below).
//!
//! `sqlite3Config` is declared `extern var` (NOT const): it is a mutable global
//! (sqlite3PCacheSetDefault writes pcache2). const would let the optimizer CSE
//! a read across an opaque mutation and observe stale data (ReleaseSafe crash).
//!
//! Config gating (this project: SQLITE_THREADSAFE=1, and NEITHER
//! SQLITE_ENABLE_MEMORY_MANAGEMENT nor SQLITE_PCACHE_SEPARATE_HEADER
//! (discontinued upstream) nor SQLITE_DISABLE_PAGECACHE_OVERFLOW_STATS set):
//!   * PCACHE1_MIGHT_USE_GROUP_MUTEX == 0  (because !MEMORY_MANAGEMENT). So the
//!     PGroup-LRU mutex enter/leave are pure asserts (no-op in production) and
//!     pcache1FetchWithMutex is NOT compiled — pcache1Fetch always takes the
//!     no-mutex path. The PMEM mutex (pcache1.mutex) IS real and guards the
//!     SQLITE_CONFIG_PAGECACHE freelist in pcache1Alloc/Free.
//!   * `sqlite3PcacheReleaseMemory` and `pcache1MemSize`
//!     (SQLITE_ENABLE_MEMORY_MANAGEMENT) — OMITTED (flag off in both builds).
//!   * `sqlite3PcacheStats` (SQLITE_TEST) — exported under `config.sqlite_test`.
//!   * The overflow-stats bookkeeping is compiled (OVERFLOW_STATS not disabled).
//!   * sqlite3MemdebugSetType/HasType are SQLITE_MEMDEBUG-only no-ops (dropped).
//!
//! A pure-Zig test is not feasible: every routine couples to the SQLite memory
//! allocator, mutex, status, and benign-malloc subsystems via the C ABI.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7;

const SQLITE_CONFIG_PCACHE2: c_int = 18;

const SQLITE_MUTEX_STATIC_LRU: c_int = 6;
const SQLITE_MUTEX_STATIC_PMEM: c_int = 7;

const SQLITE_STATUS_PAGECACHE_USED: c_int = 1;
const SQLITE_STATUS_PAGECACHE_OVERFLOW: c_int = 2;
const SQLITE_STATUS_PAGECACHE_SIZE: c_int = 7;

const MEMTYPE_PCACHE: u8 = 0x04;

// --- C / SQLite helpers resolved at link time ---
extern fn sqlite3_config(op: c_int, ...) c_int;
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3MallocSize(p: ?*const anyopaque) c_int;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3HeapNearlyFull() c_int;
extern fn sqlite3MutexAlloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3_mutex_held(m: ?*anyopaque) c_int;
extern fn sqlite3_mutex_notheld(m: ?*anyopaque) c_int;
extern fn sqlite3StatusUp(op: c_int, n: c_int) void;
extern fn sqlite3StatusDown(op: c_int, n: c_int) void;
extern fn sqlite3StatusHighwater(op: c_int, n: c_int) void;
extern fn sqlite3BeginBenignMalloc() void;
extern fn sqlite3EndBenignMalloc() void;
extern fn memset(dst: ?*anyopaque, ch: c_int, n: usize) ?*anyopaque;

// --- Public ABI: sqlite3_pcache_page (sqlite3.h). Boundary to pcache.zig. ---
const Sqlite3PcachePage = extern struct {
    pBuf: ?*anyopaque, // The content of the page
    pExtra: ?*anyopaque, // Extra information associated with the page
};

// sqlite3_pcache opaque handle (== *PCache1 from pcache.zig's view).
const Sqlite3Pcache = anyopaque;

/// sqlite3_pcache_methods2 — PUBLIC ABI (sqlite3.h).
const PcacheMethods2 = extern struct {
    iVersion: c_int,
    pArg: ?*anyopaque,
    xInit: ?*const fn (?*anyopaque) callconv(.c) c_int,
    xShutdown: ?*const fn (?*anyopaque) callconv(.c) void,
    xCreate: ?*const fn (c_int, c_int, c_int) callconv(.c) ?*Sqlite3Pcache,
    xCachesize: ?*const fn (?*Sqlite3Pcache, c_int) callconv(.c) void,
    xPagecount: ?*const fn (?*Sqlite3Pcache) callconv(.c) c_int,
    xFetch: ?*const fn (?*Sqlite3Pcache, c_uint, c_int) callconv(.c) ?*Sqlite3PcachePage,
    xUnpin: ?*const fn (?*Sqlite3Pcache, ?*Sqlite3PcachePage, c_int) callconv(.c) void,
    xRekey: ?*const fn (?*Sqlite3Pcache, ?*Sqlite3PcachePage, c_uint, c_uint) callconv(.c) void,
    xTruncate: ?*const fn (?*Sqlite3Pcache, c_uint) callconv(.c) void,
    xDestroy: ?*const fn (?*Sqlite3Pcache) callconv(.c) void,
    xShrink: ?*const fn (?*Sqlite3Pcache) callconv(.c) void,
};

// --- Internal/opaque structs (we own these layouts) ---

/// PgHdr1 — one cache line header. The page buffer of pCache->szPage bytes sits
/// directly BEFORE this struct (page.pBuf points to it). Subclass of
/// sqlite3_pcache_page (must be first member).
const PgHdr1 = extern struct {
    page: Sqlite3PcachePage, // Base class. Must be first. pBuf & pExtra
    iKey: c_uint, // Key value (page number)
    isBulkLocal: u16, // This page from bulk local storage
    isAnchor: u16, // This is the PGroup.lru element
    pNext: ?*PgHdr1, // Next in hash table chain
    pCache: ?*PCache1, // Cache that currently owns this page
    pLruNext: ?*PgHdr1, // Next in circular LRU list of unpinned pages
    pLruPrev: ?*PgHdr1, // Previous in LRU list (valid only if pLruNext!=0)
};

/// PGroup — a set of PCaches that can recycle each other's unpinned pages.
const PGroup = extern struct {
    mutex: ?*anyopaque, // MUTEX_STATIC_LRU or NULL
    nMaxPage: c_uint, // Sum of nMax for purgeable caches
    nMinPage: c_uint, // Sum of nMin for purgeable caches
    mxPinned: c_uint, // nMaxpage + 10 - nMinPage
    nPurgeable: c_uint, // Number of purgeable pages allocated
    lru: PgHdr1, // The beginning and end of the LRU list
};

/// PCache1 — one page cache. Cast to/from the opaque sqlite3_pcache* handle.
const PCache1 = extern struct {
    pGroup: ?*PGroup, // PGroup this cache belongs to
    pnPurgeable: ?*c_uint, // Pointer to pGroup->nPurgeable
    szPage: c_int, // Size of database content section
    szExtra: c_int, // sizeof(MemPage)+sizeof(PgHdr)
    szAlloc: c_int, // Total size of one pcache line
    bPurgeable: c_int, // True if cache is purgeable
    nMin: c_uint, // Minimum number of pages reserved
    nMax: c_uint, // Configured "cache_size" value
    n90pct: c_uint, // nMax*9/10
    iMaxKey: c_uint, // Largest key seen since xTruncate()
    nPurgeableDummy: c_uint, // pnPurgeable points here when not used
    nRecyclable: c_uint, // Number of pages in the LRU list
    nPage: c_uint, // Total number of pages in apHash
    nHash: c_uint, // Number of slots in apHash[]
    apHash: ?[*]?*PgHdr1, // Hash table for fast lookup by key
    pFree: ?*PgHdr1, // List of unused pcache-local pages
    pBulk: ?*anyopaque, // Bulk memory used by pcache-local
};

/// Free slots in the SQLITE_CONFIG_PAGECACHE buffer allocator.
const PgFreeslot = extern struct {
    pNext: ?*PgFreeslot, // Next free slot
};

/// Global state for this cache. Internal — we own the layout. (SQLITE_WSD: WSD
/// emulation is off in this project, so a plain module global mirrors the C.)
const PCacheGlobal = extern struct {
    grp: PGroup, // The global PGroup for mode (2)
    isInit: c_int, // True if initialized
    separateCache: c_int, // Use a new PGroup for each PCache
    nInitPage: c_int, // Initial bulk allocation size
    szSlot: c_int, // Size of each free slot
    nSlot: c_int, // The number of pcache slots
    nReserve: c_int, // Try to keep nFreeSlot above this
    pStart: ?*anyopaque, // Bounds of global page cache memory (start)
    pEnd: ?*anyopaque, // Bounds of global page cache memory (end)
    mutex: ?*anyopaque, // Mutex for accessing the following (PMEM):
    pFree: ?*PgFreeslot, // Free page blocks
    nFreeSlot: c_int, // Number of unused pcache slots
    bUnderPressure: c_int, // True if low on PAGECACHE memory
};

var pcache1: PCacheGlobal = std.mem.zeroes(PCacheGlobal);

// --- Reading sqlite3GlobalConfig fields at ground-truth offsets ---
// SQLITE_OMIT_WSD is off, so sqlite3GlobalConfig == the global `sqlite3Config`.
extern var sqlite3Config: u8; // mutable global — see file doc comment
inline fn cfgBase() [*]const u8 {
    return @ptrCast(&sqlite3Config);
}
inline fn cfgInt(comptime off: usize) c_int {
    const p: *align(1) const c_int = @ptrCast(cfgBase() + off);
    return p.*;
}
inline fn cfgPtr(comptime off: usize) ?*anyopaque {
    const p: *align(1) const ?*anyopaque = @ptrCast(cfgBase() + off);
    return p.*;
}

// --- Bit/align helpers (mirror sqliteInt.h macros) ---
inline fn ROUND8(x: c_int) c_int {
    return (x + 7) & ~@as(c_int, 7);
}
inline fn ROUNDDOWN8(x: c_int) c_int {
    return x & ~@as(c_int, 7);
}
inline fn EIGHT_BYTE_ALIGNMENT(p: ?*const anyopaque) bool {
    return (@intFromPtr(p) & 7) == 0;
}
/// SQLITE_WITHIN(P,S,E): S<=P<E by address.
inline fn withinBuf(p: ?*const anyopaque, s: ?*const anyopaque, e: ?*const anyopaque) bool {
    return @intFromPtr(p) >= @intFromPtr(s) and @intFromPtr(p) < @intFromPtr(e);
}

// PAGE_IS_PINNED / PAGE_IS_UNPINNED
inline fn pageIsUnpinned(p: *PgHdr1) bool {
    return p.pLruNext != null;
}

// --- PGroup LRU mutex: pure asserts here (PCACHE1_MIGHT_USE_GROUP_MUTEX==0) ---
inline fn pcache1EnterMutex(g: *PGroup) void {
    std.debug.assert(g.mutex == null);
}
inline fn pcache1LeaveMutex(g: *PGroup) void {
    std.debug.assert(g.mutex == null);
}

/// AtomicStore(&pcache1.bUnderPressure, v) — RELAXED. Threadsafe in C; plain
/// store is acceptable here (matches the SQLITE_THREADSAFE __atomic_store_n
/// with __ATOMIC_RELAXED for an int written/read under the PMEM mutex anyway).
inline fn setUnderPressure(v: bool) void {
    @atomicStore(c_int, &pcache1.bUnderPressure, @intFromBool(v), .monotonic);
}
inline fn loadUnderPressure() c_int {
    return @atomicLoad(c_int, &pcache1.bUnderPressure, .monotonic);
}

// ============ Page Allocation / SQLITE_CONFIG_PAGECACHE =============

/// SQLITE_CONFIG_PAGECACHE static-buffer setup (called from sqlite3_initialize
/// path, already serialized).
export fn sqlite3PCacheBufferSetup(pBuf_in: ?*anyopaque, sz_in: c_int, n_in: c_int) callconv(.c) void {
    if (pcache1.isInit != 0) {
        var pBuf = pBuf_in;
        var sz = sz_in;
        var n = n_in;
        if (pBuf == null) {
            sz = 0;
            n = 0;
        }
        if (n == 0) sz = 0;
        sz = ROUNDDOWN8(sz);
        pcache1.szSlot = sz;
        pcache1.nSlot = n;
        pcache1.nFreeSlot = n;
        pcache1.nReserve = if (n > 90) 10 else (@divTrunc(n, 10) + 1);
        pcache1.pStart = pBuf;
        pcache1.pFree = null;
        setUnderPressure(false);
        while (n != 0) : (n -= 1) {
            const p: *PgFreeslot = @ptrCast(@alignCast(pBuf.?));
            p.pNext = pcache1.pFree;
            pcache1.pFree = p;
            const bytes: [*]u8 = @ptrCast(pBuf.?);
            pBuf = @ptrCast(bytes + @as(usize, @intCast(sz)));
        }
        pcache1.pEnd = pBuf;
    }
}

/// Try to initialize pCache->pFree and pCache->pBulk. Returns true if pFree
/// ends up with one or more pages.
fn pcache1InitBulk(pCache: *PCache1) bool {
    if (pcache1.nInitPage == 0) return false;
    // Do not bother with a bulk allocation if the cache size is very small.
    if (pCache.nMax < 3) return false;
    sqlite3BeginBenignMalloc();
    var szBulk: i64 = undefined;
    if (pcache1.nInitPage > 0) {
        szBulk = @as(i64, pCache.szAlloc) * @as(i64, pcache1.nInitPage);
    } else {
        szBulk = -1024 * @as(i64, pcache1.nInitPage);
    }
    if (szBulk > @as(i64, pCache.szAlloc) * @as(i64, pCache.nMax)) {
        szBulk = @as(i64, pCache.szAlloc) * @as(i64, pCache.nMax);
    }
    if (szBulk >= pCache.szAlloc) {
        const pBulk = sqlite3Malloc(@bitCast(szBulk));
        pCache.pBulk = pBulk;
        sqlite3EndBenignMalloc();
        if (pBulk) |raw| {
            var zBulk: [*]u8 = @ptrCast(raw);
            var nBulk: c_int = @divTrunc(sqlite3MallocSize(raw), pCache.szAlloc);
            while (true) {
                const pX: *PgHdr1 = @ptrCast(@alignCast(zBulk + @as(usize, @intCast(pCache.szPage))));
                pX.page.pBuf = zBulk;
                pX.page.pExtra = @ptrFromInt(@intFromPtr(pX) + @as(usize, @intCast(ROUND8(@sizeOf(PgHdr1)))));
                std.debug.assert(EIGHT_BYTE_ALIGNMENT(pX.page.pExtra));
                pX.isBulkLocal = 1;
                pX.isAnchor = 0;
                pX.pNext = pCache.pFree;
                pX.pLruPrev = null; // Initializing this saves a valgrind error
                pCache.pFree = pX;
                zBulk += @as(usize, @intCast(pCache.szAlloc));
                nBulk -= 1;
                if (nBulk == 0) break;
            }
        }
    } else {
        sqlite3EndBenignMalloc();
    }
    return pCache.pFree != null;
}

/// Allocate from the SQLITE_CONFIG_PAGECACHE buffer, else sqlite3Malloc().
fn pcache1Alloc(nByte: c_int) ?*anyopaque {
    var p: ?*anyopaque = null;
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_notheld(pcache1.grp.mutex) != 0);
    if (nByte <= pcache1.szSlot) {
        sqlite3_mutex_enter(pcache1.mutex);
        const slot = pcache1.pFree;
        if (slot) |s| {
            pcache1.pFree = s.pNext;
            pcache1.nFreeSlot -= 1;
            setUnderPressure(pcache1.nFreeSlot < pcache1.nReserve);
            std.debug.assert(pcache1.nFreeSlot >= 0);
            sqlite3StatusHighwater(SQLITE_STATUS_PAGECACHE_SIZE, nByte);
            sqlite3StatusUp(SQLITE_STATUS_PAGECACHE_USED, 1);
            p = @ptrCast(s);
        }
        sqlite3_mutex_leave(pcache1.mutex);
    }
    if (p == null) {
        // Not available from the SQLITE_CONFIG_PAGECACHE pool. Use sqlite3Malloc.
        p = sqlite3Malloc(@intCast(nByte));
        // SQLITE_DISABLE_PAGECACHE_OVERFLOW_STATS is not set -> track overflow.
        if (p) |pp| {
            const sz = sqlite3MallocSize(pp);
            sqlite3_mutex_enter(pcache1.mutex);
            sqlite3StatusHighwater(SQLITE_STATUS_PAGECACHE_SIZE, nByte);
            sqlite3StatusUp(SQLITE_STATUS_PAGECACHE_OVERFLOW, sz);
            sqlite3_mutex_leave(pcache1.mutex);
        }
        // sqlite3MemdebugSetType(p, MEMTYPE_PCACHE) — no-op (SQLITE_MEMDEBUG off)
    }
    return p;
}

/// Free a buffer obtained from pcache1Alloc().
fn pcache1Free(p: ?*anyopaque) void {
    if (p == null) return;
    if (withinBuf(p, pcache1.pStart, pcache1.pEnd)) {
        sqlite3_mutex_enter(pcache1.mutex);
        sqlite3StatusDown(SQLITE_STATUS_PAGECACHE_USED, 1);
        const pSlot: *PgFreeslot = @ptrCast(@alignCast(p.?));
        pSlot.pNext = pcache1.pFree;
        pcache1.pFree = pSlot;
        pcache1.nFreeSlot += 1;
        setUnderPressure(pcache1.nFreeSlot < pcache1.nReserve);
        std.debug.assert(pcache1.nFreeSlot <= pcache1.nSlot);
        sqlite3_mutex_leave(pcache1.mutex);
    } else {
        // sqlite3MemdebugHasType/SetType — no-ops (SQLITE_MEMDEBUG off).
        // SQLITE_DISABLE_PAGECACHE_OVERFLOW_STATS not set -> track overflow.
        const nFreed = sqlite3MallocSize(p);
        sqlite3_mutex_enter(pcache1.mutex);
        sqlite3StatusDown(SQLITE_STATUS_PAGECACHE_OVERFLOW, nFreed);
        sqlite3_mutex_leave(pcache1.mutex);
        sqlite3_free(p);
    }
}

// pcache1MemSize is SQLITE_ENABLE_MEMORY_MANAGEMENT-only — omitted.

/// Allocate a new page object initially associated with cache pCache.
fn pcache1AllocPage(pCache: *PCache1, benignMalloc: bool) ?*PgHdr1 {
    var p: ?*PgHdr1 = null;
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_held(pCache.pGroup.?.mutex) != 0);
    if (pCache.pFree != null or (pCache.nPage == 0 and pcache1InitBulk(pCache))) {
        std.debug.assert(pCache.pFree != null);
        p = pCache.pFree;
        pCache.pFree = p.?.pNext;
        p.?.pNext = null;
    } else {
        // SQLITE_ENABLE_MEMORY_MANAGEMENT block (group mutex release) omitted.
        if (benignMalloc) sqlite3BeginBenignMalloc();
        const pPg = pcache1Alloc(pCache.szAlloc);
        if (benignMalloc) sqlite3EndBenignMalloc();
        if (pPg == null) return null;
        const pg: *PgHdr1 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pPg.?)) + @as(usize, @intCast(pCache.szPage))));
        pg.page.pBuf = pPg;
        pg.page.pExtra = @ptrFromInt(@intFromPtr(pg) + @as(usize, @intCast(ROUND8(@sizeOf(PgHdr1)))));
        std.debug.assert(EIGHT_BYTE_ALIGNMENT(pg.page.pExtra));
        pg.isBulkLocal = 0;
        pg.isAnchor = 0;
        pg.pLruPrev = null; // Initializing this saves a valgrind error
        p = pg;
    }
    pCache.pnPurgeable.?.* += 1;
    return p;
}

/// Free a page object allocated by pcache1AllocPage().
fn pcache1FreePage(p: *PgHdr1) void {
    const pCache = p.pCache.?;
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_held(pCache.pGroup.?.mutex) != 0);
    if (p.isBulkLocal != 0) {
        p.pNext = pCache.pFree;
        pCache.pFree = p;
    } else {
        pcache1Free(p.page.pBuf);
    }
    pCache.pnPurgeable.?.* -= 1;
}

/// Public: allocate from the SQLITE_CONFIG_PAGECACHE buffer (or heap).
export fn sqlite3PageMalloc(sz: c_int) callconv(.c) ?*anyopaque {
    std.debug.assert(sz <= 65536 + 8); // These allocations are never very large
    return pcache1Alloc(sz);
}

/// Public: free a buffer obtained from sqlite3PageMalloc().
export fn sqlite3PageFree(p: ?*anyopaque) callconv(.c) void {
    pcache1Free(p);
}

/// Return true if it is desirable to avoid allocating a new page cache entry.
fn pcache1UnderMemoryPressure(pCache: *PCache1) bool {
    if (pcache1.nSlot != 0 and (pCache.szPage + pCache.szExtra) <= pcache1.szSlot) {
        return loadUnderPressure() != 0;
    } else {
        return sqlite3HeapNearlyFull() != 0;
    }
}

// ============ General Implementation Functions =====================

/// Resize the hash table used by the cache. PGroup mutex must be held.
fn pcache1ResizeHash(p: *PCache1) void {
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_held(p.pGroup.?.mutex) != 0);

    var nNew: u64 = 2 * @as(u64, p.nHash);
    if (nNew < 256) nNew = 256;

    pcache1LeaveMutex(p.pGroup.?);
    if (p.nHash != 0) sqlite3BeginBenignMalloc();
    const apNew: ?[*]?*PgHdr1 = @ptrCast(@alignCast(sqlite3MallocZero(@sizeOf(?*PgHdr1) * nNew)));
    if (p.nHash != 0) sqlite3EndBenignMalloc();
    pcache1EnterMutex(p.pGroup.?);
    if (apNew) |an| {
        var i: c_uint = 0;
        while (i < p.nHash) : (i += 1) {
            var pNext = p.apHash.?[i];
            while (pNext) |pPage| {
                const h: u64 = pPage.iKey % nNew;
                pNext = pPage.pNext;
                pPage.pNext = an[@intCast(h)];
                an[@intCast(h)] = pPage;
            }
        }
        sqlite3_free(@ptrCast(p.apHash));
        p.apHash = an;
        p.nHash = @intCast(nNew);
    }
}

/// Remove pPage from the PGroup LRU list, if part of it. PGroup mutex held.
fn pcache1PinPage(pPage: *PgHdr1) *PgHdr1 {
    std.debug.assert(pageIsUnpinned(pPage));
    std.debug.assert(pPage.pLruNext != null);
    std.debug.assert(pPage.pLruPrev != null);
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_held(pPage.pCache.?.pGroup.?.mutex) != 0);
    pPage.pLruPrev.?.pLruNext = pPage.pLruNext;
    pPage.pLruNext.?.pLruPrev = pPage.pLruPrev;
    pPage.pLruNext = null;
    // pLruPrev not cleared: never accessed while pLruNext==0.
    std.debug.assert(pPage.isAnchor == 0);
    std.debug.assert(pPage.pCache.?.pGroup.?.lru.isAnchor == 1);
    pPage.pCache.?.nRecyclable -= 1;
    return pPage;
}

/// Remove pPage from its hash chain; free it if freeFlag. PGroup mutex held.
fn pcache1RemoveFromHash(pPage: *PgHdr1, freeFlag: bool) void {
    const pCache = pPage.pCache.?;
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_held(pCache.pGroup.?.mutex) != 0);
    const h = pPage.iKey % pCache.nHash;
    var pp: *?*PgHdr1 = &pCache.apHash.?[h];
    while (pp.* != pPage) {
        pp = &pp.*.?.pNext;
    }
    pp.* = pp.*.?.pNext;

    pCache.nPage -= 1;
    if (freeFlag) pcache1FreePage(pPage);
}

/// If there are more than nMaxPage pages allocated, recycle down to nMaxPage.
fn pcache1EnforceMaxPage(pCache: *PCache1) void {
    const pGroup = pCache.pGroup.?;
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_held(pGroup.mutex) != 0);
    while (pGroup.nPurgeable > pGroup.nMaxPage) {
        const p = pGroup.lru.pLruPrev.?;
        if (p.isAnchor != 0) break;
        std.debug.assert(p.pCache.?.pGroup == pGroup);
        std.debug.assert(pageIsUnpinned(p));
        _ = pcache1PinPage(p);
        pcache1RemoveFromHash(p, true);
    }
    if (pCache.nPage == 0 and pCache.pBulk != null) {
        sqlite3_free(pCache.pBulk);
        pCache.pBulk = null;
        pCache.pFree = null;
    }
}

/// Discard all pages with key >= iLimit. Pinned ones are unpinned first.
fn pcache1TruncateUnsafe(pCache: *PCache1, iLimit: c_uint) void {
    var nPage: c_int = 0; // TESTONLY: to assert pCache->nPage is correct
    if (config.sqlite_debug) std.debug.assert(sqlite3_mutex_held(pCache.pGroup.?.mutex) != 0);
    std.debug.assert(pCache.iMaxKey >= iLimit);
    std.debug.assert(pCache.nHash > 0);
    var h: c_uint = undefined;
    var iStop: c_uint = undefined;
    if (pCache.iMaxKey - iLimit < pCache.nHash) {
        // Just shaving the last few pages off the end: scan only the relevant
        // hash slots.
        h = iLimit % pCache.nHash;
        iStop = pCache.iMaxKey % pCache.nHash;
        nPage = -10; // Disable the pCache->nPage validity check
    } else {
        // General case: scan the entire hash table.
        h = pCache.nHash / 2;
        iStop = h - 1;
    }
    while (true) {
        std.debug.assert(h < pCache.nHash);
        var pp: *?*PgHdr1 = &pCache.apHash.?[h];
        while (pp.*) |pPage| {
            if (pPage.iKey >= iLimit) {
                pCache.nPage -= 1;
                pp.* = pPage.pNext;
                if (pageIsUnpinned(pPage)) _ = pcache1PinPage(pPage);
                pcache1FreePage(pPage);
            } else {
                pp = &pPage.pNext;
                if (nPage >= 0) nPage += 1;
            }
        }
        if (h == iStop) break;
        h = (h + 1) % pCache.nHash;
    }
    std.debug.assert(nPage < 0 or pCache.nPage == @as(c_uint, @intCast(nPage)));
}

// ============ sqlite3_pcache Methods ===============================

/// xInit
fn pcache1Init(NotUsed: ?*anyopaque) callconv(.c) c_int {
    _ = NotUsed;
    std.debug.assert(pcache1.isInit == 0);
    pcache1 = std.mem.zeroes(PCacheGlobal);

    // separateCache: true => each PCache has its own PGroup (mode-1).
    // SQLITE_ENABLE_MEMORY_MANAGEMENT is off; SQLITE_THREADSAFE is on.
    pcache1.separateCache = @intFromBool(
        cfgPtr(L.Sqlite3Config_pPage) == null or cfgInt(L.Sqlite3Config_bCoreMutex) > 0,
    );

    // SQLITE_THREADSAFE: allocate the static mutexes if core-mutexing is on.
    if (cfgInt(L.Sqlite3Config_bCoreMutex) != 0) {
        pcache1.grp.mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_LRU);
        pcache1.mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_PMEM);
    }
    if (pcache1.separateCache != 0 and cfgInt(L.Sqlite3Config_nPage) != 0 and cfgPtr(L.Sqlite3Config_pPage) == null) {
        pcache1.nInitPage = cfgInt(L.Sqlite3Config_nPage);
    } else {
        pcache1.nInitPage = 0;
    }
    pcache1.grp.mxPinned = 10;
    pcache1.isInit = 1;
    return SQLITE_OK;
}

/// xShutdown. The static mutexes from xInit do not need to be freed.
fn pcache1Shutdown(NotUsed: ?*anyopaque) callconv(.c) void {
    _ = NotUsed;
    std.debug.assert(pcache1.isInit != 0);
    pcache1 = std.mem.zeroes(PCacheGlobal);
}

/// xCreate — allocate a new cache.
fn pcache1Create(szPage: c_int, szExtra: c_int, bPurgeable: c_int) callconv(.c) ?*Sqlite3Pcache {
    std.debug.assert((szPage & (szPage - 1)) == 0 and szPage >= 512 and szPage <= 65536);
    std.debug.assert(szExtra < 300);

    const sz: i64 = @as(i64, @sizeOf(PCache1)) + @as(i64, @sizeOf(PGroup)) * @as(i64, pcache1.separateCache);
    const pCache: ?*PCache1 = @ptrCast(@alignCast(sqlite3MallocZero(@bitCast(sz))));
    if (pCache) |pc| {
        var pGroup: *PGroup = undefined;
        if (pcache1.separateCache != 0) {
            // PGroup sits directly after the PCache1.
            pGroup = @ptrCast(@alignCast(@as([*]PCache1, @ptrCast(pc)) + 1));
            pGroup.mxPinned = 10;
        } else {
            pGroup = &pcache1.grp;
        }
        pcache1EnterMutex(pGroup);
        if (pGroup.lru.isAnchor == 0) {
            pGroup.lru.isAnchor = 1;
            pGroup.lru.pLruPrev = &pGroup.lru;
            pGroup.lru.pLruNext = &pGroup.lru;
        }
        pc.pGroup = pGroup;
        pc.szPage = szPage;
        pc.szExtra = szExtra;
        pc.szAlloc = szPage + szExtra + ROUND8(@sizeOf(PgHdr1));
        pc.bPurgeable = if (bPurgeable != 0) 1 else 0;
        pcache1ResizeHash(pc);
        if (bPurgeable != 0) {
            pc.nMin = 10;
            pGroup.nMinPage += pc.nMin;
            pGroup.mxPinned = pGroup.nMaxPage + 10 - pGroup.nMinPage;
            pc.pnPurgeable = &pGroup.nPurgeable;
        } else {
            pc.pnPurgeable = &pc.nPurgeableDummy;
        }
        pcache1LeaveMutex(pGroup);
        if (pc.nHash == 0) {
            pcache1Destroy(@ptrCast(pc));
            return null;
        }
    }
    return @ptrCast(pCache);
}

/// xCachesize — configure the cache_size limit for a cache.
fn pcache1Cachesize(p: ?*Sqlite3Pcache, nMax: c_int) callconv(.c) void {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
    std.debug.assert(nMax >= 0);
    if (pCache.bPurgeable != 0) {
        const pGroup = pCache.pGroup.?;
        pcache1EnterMutex(pGroup);
        var n: c_uint = @bitCast(nMax);
        if (n > 0x7fff0000 - pGroup.nMaxPage + pCache.nMax) {
            n = 0x7fff0000 - pGroup.nMaxPage + pCache.nMax;
        }
        pGroup.nMaxPage +%= (n -% pCache.nMax);
        pGroup.mxPinned = pGroup.nMaxPage + 10 - pGroup.nMinPage;
        pCache.nMax = n;
        pCache.n90pct = pCache.nMax * 9 / 10;
        pcache1EnforceMaxPage(pCache);
        pcache1LeaveMutex(pGroup);
    }
}

/// xShrink — free up as much memory as possible.
fn pcache1Shrink(p: ?*Sqlite3Pcache) callconv(.c) void {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
    if (pCache.bPurgeable != 0) {
        const pGroup = pCache.pGroup.?;
        pcache1EnterMutex(pGroup);
        const savedMaxPage = pGroup.nMaxPage;
        pGroup.nMaxPage = 0;
        pcache1EnforceMaxPage(pCache);
        pGroup.nMaxPage = savedMaxPage;
        pcache1LeaveMutex(pGroup);
    }
}

/// xPagecount.
fn pcache1Pagecount(p: ?*Sqlite3Pcache) callconv(.c) c_int {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
    pcache1EnterMutex(pCache.pGroup.?);
    const n = pCache.nPage;
    pcache1LeaveMutex(pCache.pGroup.?);
    return @bitCast(n);
}

/// Steps 3, 4, 5 of the pcache1Fetch() algorithm (split out for speed).
fn pcache1FetchStage2(pCache: *PCache1, iKey: c_uint, createFlag: c_int) ?*PgHdr1 {
    const pGroup = pCache.pGroup.?;
    var pPage: ?*PgHdr1 = null;

    // Step 3: Abort if createFlag==1 but the cache is nearly full.
    std.debug.assert(pCache.nPage >= pCache.nRecyclable);
    const nPinned = pCache.nPage - pCache.nRecyclable;
    std.debug.assert(pGroup.mxPinned == pGroup.nMaxPage + 10 - pGroup.nMinPage);
    std.debug.assert(pCache.n90pct == pCache.nMax * 9 / 10);
    if (createFlag == 1 and
        (nPinned >= pGroup.mxPinned or
            nPinned >= pCache.n90pct or
            (pcache1UnderMemoryPressure(pCache) and pCache.nRecyclable < nPinned)))
    {
        return null;
    }

    if (pCache.nPage >= pCache.nHash) pcache1ResizeHash(pCache);
    std.debug.assert(pCache.nHash > 0 and pCache.apHash != null);

    // Step 4: Try to recycle a page.
    if (pCache.bPurgeable != 0 and
        pGroup.lru.pLruPrev.?.isAnchor == 0 and
        ((pCache.nPage + 1 >= pCache.nMax) or pcache1UnderMemoryPressure(pCache)))
    {
        const pg = pGroup.lru.pLruPrev.?;
        std.debug.assert(pageIsUnpinned(pg));
        pcache1RemoveFromHash(pg, false);
        _ = pcache1PinPage(pg);
        const pOther = pg.pCache.?;
        if (pOther.szAlloc != pCache.szAlloc) {
            pcache1FreePage(pg);
            pPage = null;
        } else {
            // bPurgeable is 0/1; difference adjusts nPurgeable accounting.
            pGroup.nPurgeable -%= @as(c_uint, @bitCast(pOther.bPurgeable - pCache.bPurgeable));
            pPage = pg;
        }
    }

    // Step 5: If still no page, allocate a new one.
    if (pPage == null) {
        pPage = pcache1AllocPage(pCache, createFlag == 1);
    }

    if (pPage) |pg| {
        const h = iKey % pCache.nHash;
        pCache.nPage += 1;
        pg.iKey = iKey;
        pg.pNext = pCache.apHash.?[h];
        pg.pCache = pCache;
        pg.pLruNext = null;
        // pLruPrev not cleared: not accessed when pLruNext==0.
        const pExtraPtr: *?*anyopaque = @ptrCast(@alignCast(pg.page.pExtra.?));
        pExtraPtr.* = null;
        pCache.apHash.?[h] = pg;
        if (iKey > pCache.iMaxKey) {
            pCache.iMaxKey = iKey;
        }
    }
    return pPage;
}

/// Common no-mutex path of xFetch (PCACHE1_MIGHT_USE_GROUP_MUTEX==0, so this is
/// the only path).
fn pcache1FetchNoMutex(p: ?*Sqlite3Pcache, iKey: c_uint, createFlag: c_int) ?*PgHdr1 {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));

    // Step 1: Search the hash table for an existing entry.
    var pPage = pCache.apHash.?[iKey % pCache.nHash];
    while (pPage) |pg| {
        if (pg.iKey == iKey) break;
        pPage = pg.pNext;
    }

    // Step 2.
    if (pPage) |pg| {
        if (pageIsUnpinned(pg)) {
            return pcache1PinPage(pg);
        } else {
            return pg;
        }
    } else if (createFlag != 0) {
        return pcache1FetchStage2(pCache, iKey, createFlag);
    } else {
        return null;
    }
}

// pcache1FetchWithMutex is PCACHE1_MIGHT_USE_GROUP_MUTEX-only — omitted.

/// xFetch — fetch a page by key value.
fn pcache1Fetch(p: ?*Sqlite3Pcache, iKey: c_uint, createFlag: c_int) callconv(.c) ?*Sqlite3PcachePage {
    std.debug.assert(@offsetOf(PgHdr1, "page") == 0);
    if (config.sqlite_debug) {
        const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
        std.debug.assert(pCache.bPurgeable != 0 or createFlag != 1);
        std.debug.assert(pCache.bPurgeable != 0 or pCache.nMin == 0);
        std.debug.assert(pCache.bPurgeable == 0 or pCache.nMin == 10);
        std.debug.assert(pCache.nMin == 0 or pCache.bPurgeable != 0);
        std.debug.assert(pCache.nHash > 0);
    }
    // PCACHE1_MIGHT_USE_GROUP_MUTEX==0: always the no-mutex path.
    return @ptrCast(pcache1FetchNoMutex(p, iKey, createFlag));
}

/// xUnpin — mark a page as unpinned (eligible for recycling).
fn pcache1Unpin(p: ?*Sqlite3Pcache, pPg: ?*Sqlite3PcachePage, reuseUnlikely: c_int) callconv(.c) void {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
    const pPage: *PgHdr1 = @ptrCast(@alignCast(pPg.?));
    const pGroup = pCache.pGroup.?;

    std.debug.assert(pPage.pCache == pCache);
    pcache1EnterMutex(pGroup);

    // It is an error to call this if the page is already on the LRU list.
    std.debug.assert(pPage.pLruNext == null);

    if (reuseUnlikely != 0 or pGroup.nPurgeable > pGroup.nMaxPage) {
        pcache1RemoveFromHash(pPage, true);
    } else {
        // Add the page to the PGroup LRU list.
        const ppFirst = &pGroup.lru.pLruNext;
        pPage.pLruPrev = &pGroup.lru;
        pPage.pLruNext = ppFirst.*;
        ppFirst.*.?.pLruPrev = pPage;
        ppFirst.* = pPage;
        pCache.nRecyclable += 1;
    }

    pcache1LeaveMutex(pCache.pGroup.?);
}

/// xRekey.
fn pcache1Rekey(p: ?*Sqlite3Pcache, pPg: ?*Sqlite3PcachePage, iOld: c_uint, iNew: c_uint) callconv(.c) void {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
    const pPage: *PgHdr1 = @ptrCast(@alignCast(pPg.?));
    std.debug.assert(pPage.iKey == iOld);
    std.debug.assert(pPage.pCache == pCache);
    std.debug.assert(iOld != iNew); // The page number really is changing

    pcache1EnterMutex(pCache.pGroup.?);

    std.debug.assert(pcache1FetchNoMutex(p, iOld, 0) == pPage);
    const hOld = iOld % pCache.nHash;
    var pp: *?*PgHdr1 = &pCache.apHash.?[hOld];
    while (pp.* != pPage) {
        pp = &pp.*.?.pNext;
    }
    pp.* = pPage.pNext;

    std.debug.assert(pcache1FetchNoMutex(p, iNew, 0) == null);
    const hNew = iNew % pCache.nHash;
    pPage.iKey = iNew;
    pPage.pNext = pCache.apHash.?[hNew];
    pCache.apHash.?[hNew] = pPage;
    if (iNew > pCache.iMaxKey) {
        pCache.iMaxKey = iNew;
    }

    pcache1LeaveMutex(pCache.pGroup.?);
}

/// xTruncate — discard all unpinned pages with key >= iLimit.
fn pcache1Truncate(p: ?*Sqlite3Pcache, iLimit: c_uint) callconv(.c) void {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
    pcache1EnterMutex(pCache.pGroup.?);
    if (iLimit <= pCache.iMaxKey) {
        pcache1TruncateUnsafe(pCache, iLimit);
        pCache.iMaxKey = iLimit -% 1;
    }
    pcache1LeaveMutex(pCache.pGroup.?);
}

/// xDestroy — destroy a cache allocated by pcache1Create().
fn pcache1Destroy(p: ?*Sqlite3Pcache) callconv(.c) void {
    const pCache: *PCache1 = @ptrCast(@alignCast(p.?));
    const pGroup = pCache.pGroup.?;
    std.debug.assert(pCache.bPurgeable != 0 or (pCache.nMax == 0 and pCache.nMin == 0));
    pcache1EnterMutex(pGroup);
    if (pCache.nPage != 0) pcache1TruncateUnsafe(pCache, 0);
    std.debug.assert(pGroup.nMaxPage >= pCache.nMax);
    pGroup.nMaxPage -= pCache.nMax;
    std.debug.assert(pGroup.nMinPage >= pCache.nMin);
    pGroup.nMinPage -= pCache.nMin;
    pGroup.mxPinned = pGroup.nMaxPage + 10 - pGroup.nMinPage;
    pcache1EnforceMaxPage(pCache);
    pcache1LeaveMutex(pGroup);
    sqlite3_free(pCache.pBulk);
    sqlite3_free(@ptrCast(pCache.apHash));
    sqlite3_free(pCache);
}

/// Install the default pluggable cache module.
export fn sqlite3PCacheSetDefault() callconv(.c) void {
    const defaultMethods = PcacheMethods2{
        .iVersion = 1,
        .pArg = null,
        .xInit = &pcache1Init,
        .xShutdown = &pcache1Shutdown,
        .xCreate = &pcache1Create,
        .xCachesize = &pcache1Cachesize,
        .xPagecount = &pcache1Pagecount,
        .xFetch = &pcache1Fetch,
        .xUnpin = &pcache1Unpin,
        .xRekey = &pcache1Rekey,
        .xTruncate = &pcache1Truncate,
        .xDestroy = &pcache1Destroy,
        .xShrink = &pcache1Shrink,
    };
    _ = sqlite3_config(SQLITE_CONFIG_PCACHE2, &defaultMethods);
}

/// Return the size of the per-page header for this PCACHE implementation.
export fn sqlite3HeaderSizePcache1() callconv(.c) c_int {
    return ROUND8(@sizeOf(PgHdr1));
}

/// Return the global PMEM mutex (sqlite3_status needs access to it).
export fn sqlite3Pcache1Mutex() callconv(.c) ?*anyopaque {
    return pcache1.mutex;
}

// sqlite3PcacheReleaseMemory is SQLITE_ENABLE_MEMORY_MANAGEMENT-only — omitted.

// --- SQLITE_TEST-only ---

/// Inspect the internal state of the global cache (SQLITE_TEST only).
fn sqlite3PcacheStats(pnCurrent: *c_int, pnMax: *c_int, pnMin: *c_int, pnRecyclable: *c_int) callconv(.c) void {
    var nRecyclable: c_int = 0;
    var p = pcache1.grp.lru.pLruNext;
    while (p) |pg| {
        if (pg.isAnchor != 0) break;
        std.debug.assert(pageIsUnpinned(pg));
        nRecyclable += 1;
        p = pg.pLruNext;
    }
    pnCurrent.* = @bitCast(pcache1.grp.nPurgeable);
    pnMax.* = @bitCast(pcache1.grp.nMaxPage);
    pnMin.* = @bitCast(pcache1.grp.nMinPage);
    pnRecyclable.* = nRecyclable;
}

comptime {
    if (config.sqlite_test) {
        @export(&sqlite3PcacheStats, .{ .name = "sqlite3PcacheStats" });
    }
}
