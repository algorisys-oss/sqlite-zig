//! Zig port of SQLite's page-cache abstraction layer (src/pcache.c).
//!
//! This is the middleware between the pager and the pluggable page-cache
//! backend (pcache1.c, still C). The `sqlite3PcacheXXX` API that the pager
//! calls dispatches through the registered `sqlite3_pcache_methods2` vtable
//! (`sqlite3GlobalConfig.pcache2`) and maintains the per-cache dirty-page list,
//! the `pSynced` spill optimization, and the PgHdr reference counts.
//!
//! Like os.c, this is fundamentally a dispatch layer over a registered public
//! methods struct read at a config offset, but it owns more internal PgHdr /
//! PCache bookkeeping.
//!
//! Struct coupling:
//!   * `PgHdr` (a subclass of the public `sqlite3_pcache_page`) and `PCache`
//!     are internal structs from pcache.h / pcache.c. pcache.c reads/writes
//!     many fields, AND the pager (still C) reaches into PgHdr directly via
//!     macros, so PgHdr is effectively ABI-shared. Both are config-INVARIANT
//!     here: PgHdr's only conditional member (`pageHash`, SQLITE_CHECK_PAGES)
//!     and PCache have no SQLITE_DEBUG/SQLITE_TEST fields, and SQLITE_CHECK_PAGES
//!     is not set in either project build. They are mirrored field-for-field as
//!     `extern struct` and pinned with comptime @sizeOf/@offsetOf asserts
//!     against c_layout ground truth.
//!   * `sqlite3_pcache_methods2` is PUBLIC ABI (sqlite3.h) — mirrored as an
//!     extern struct.
//!   * `sqlite3GlobalConfig.pcache2` (the registered methods, an embedded
//!     struct, not a pointer) is read at its ground-truth offset
//!     (`Sqlite3Config_pcache2`), exactly as mem5.zig reads Sqlite3Config fields.
//!
//! Config gating:
//!   * The SQLITE_DEBUG-only invariant helpers (`sqlite3PcachePageSanity`,
//!     and the internal `pcacheTrace`/`pcacheDump` are compile-time-off in C —
//!     guarded by `#if defined(SQLITE_DEBUG) && 0` — so they are dropped here
//!     regardless of config, matching the C). `sqlite3PcachePageSanity` is
//!     exported only under `config.sqlite_debug`.
//!   * `pageOnDirtyList`/`pageNotOnDirtyList` are SQLITE_ENABLE_EXPENSIVE_ASSERT
//!     -only (not set in either build) — they only appear inside the
//!     PageSanity assert, which is debug-gated; folded into the sanity check.
//!   * `sqlite3PcacheIterateDirty` is `SQLITE_CHECK_PAGES || SQLITE_DEBUG`;
//!     exported under `config.sqlite_debug`.
//!   * `sqlite3PcacheGetCachesize` is SQLITE_TEST-only; exported under
//!     `config.sqlite_test`.
//!   * `sqlite3PCacheIsDirty` (SQLITE_DIRECT_OVERFLOW_READ),
//!     `sqlite3PcacheReleaseMemory` (SQLITE_ENABLE_MEMORY_MANAGEMENT) and
//!     SQLITE_LOG_CACHE_SPILL logging are not compiled in either build — omitted.
//!
//! A pure-Zig test is not feasible: every routine dispatches through the
//! registered pcache2 backend and touches ABI-shared structs.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_BUSY: c_int = 5;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT in production

const Pgno = u32;

// --- PgHdr flag bits (pcache.h) ---
const PGHDR_CLEAN: u16 = 0x001;
const PGHDR_DIRTY: u16 = 0x002;
const PGHDR_WRITEABLE: u16 = 0x004;
const PGHDR_NEED_SYNC: u16 = 0x008;
const PGHDR_DONT_WRITE: u16 = 0x010;

// --- pcacheManageDirtyList() addRemove values ---
const PCACHE_DIRTYLIST_REMOVE: u8 = 1;
const PCACHE_DIRTYLIST_ADD: u8 = 2;
const PCACHE_DIRTYLIST_FRONT: u8 = 3;

// --- Public ABI struct (sqlite3.h) ---

/// The pluggable page cache (pcache1) is opaque to this layer.
const Sqlite3Pcache = opaque {};

const Sqlite3PcachePage = extern struct {
    pBuf: ?*anyopaque, // The content of the page
    pExtra: ?*anyopaque, // Extra information associated with the page
};

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

// --- ABI-shared internal structs (pcache.h / pcache.c) ---

/// PgHdr — subclass of sqlite3_pcache_page. Config-invariant (no SQLITE_CHECK_PAGES
/// in either build, so no pageHash member). The pager reads the public head
/// (pPage..flags) via macros; pcache.c owns the private tail (nRef onward).
const PgHdr = extern struct {
    pPage: ?*Sqlite3PcachePage, // Pcache object page handle
    pData: ?*anyopaque, // Page data
    pExtra: ?*anyopaque, // Extra content
    pCache: ?*PCache, // PRIVATE: Cache that owns this page
    pDirty: ?*PgHdr, // Transient list of dirty sorted by pgno
    pPager: ?*anyopaque, // The pager this page is part of (Pager*)
    pgno: Pgno, // Page number for this page
    flags: u16, // PGHDR flags
    // Below here private to pcache.c:
    nRef: i64, // Number of users of this page
    pDirtyNext: ?*PgHdr, // Next element in list of dirty pages
    pDirtyPrev: ?*PgHdr, // Previous element in list of dirty pages
};

/// PCache — OPAQUE: defined only here (the C lives only in pcache.c, in no
/// header). The pager allocates `sqlite3PcacheSize()` bytes for it but does not
/// know its layout, so this module OWNS the layout entirely (like Bitvec /
/// RowSet). No ground-truth asserts apply; only self-consistency within this
/// file matters.
const PCache = extern struct {
    pDirty: ?*PgHdr, // List of dirty pages in LRU order (newest)
    pDirtyTail: ?*PgHdr, // ... oldest
    pSynced: ?*PgHdr, // Last synced page in dirty page list
    nRefSum: i64, // Sum of ref counts over all pages
    szCache: c_int, // Configured cache size
    szSpill: c_int, // Size before spilling occurs
    szPage: c_int, // Size of every page in this cache
    szExtra: c_int, // Size of extra space for each page
    bPurgeable: u8, // True if pages are on backing store
    eCreate: u8, // eCreate value for xFetch()
    xStress: ?*const fn (?*anyopaque, ?*PgHdr) callconv(.c) c_int, // Try to make a page clean
    pStress: ?*anyopaque, // Argument to xStress
    pCache: ?*Sqlite3Pcache, // Pluggable cache module
};

comptime {
    // PgHdr IS header-visible (pcache.h) and ABI-shared with the pager, so pin
    // it against C ground truth — a wrong mirror fails to compile. PCache is
    // opaque (no header), so it has no ground-truth entries and is not asserted.
    std.debug.assert(@sizeOf(PgHdr) == L.sizeof_PgHdr);
    std.debug.assert(@offsetOf(PgHdr, "pPage") == L.PgHdr_pPage);
    std.debug.assert(@offsetOf(PgHdr, "pData") == L.PgHdr_pData);
    std.debug.assert(@offsetOf(PgHdr, "pExtra") == L.PgHdr_pExtra);
    std.debug.assert(@offsetOf(PgHdr, "pCache") == L.PgHdr_pCache);
    std.debug.assert(@offsetOf(PgHdr, "pDirty") == L.PgHdr_pDirty);
    std.debug.assert(@offsetOf(PgHdr, "pPager") == L.PgHdr_pPager);
    std.debug.assert(@offsetOf(PgHdr, "pgno") == L.PgHdr_pgno);
    std.debug.assert(@offsetOf(PgHdr, "flags") == L.PgHdr_flags);
    std.debug.assert(@offsetOf(PgHdr, "nRef") == L.PgHdr_nRef);
    std.debug.assert(@offsetOf(PgHdr, "pDirtyNext") == L.PgHdr_pDirtyNext);
    std.debug.assert(@offsetOf(PgHdr, "pDirtyPrev") == L.PgHdr_pDirtyPrev);
}

// --- Reading sqlite3GlobalConfig.pcache2 at ground-truth offset ---
// SQLITE_OMIT_WSD is off, so sqlite3GlobalConfig is the global `sqlite3Config`.
// pcache2 is an embedded struct (not a pointer), so we take its address.
// `var` (not `const`): sqlite3Config is a mutable global (sqlite3PCacheSetDefault
// writes pcache2). Declaring it const lets the optimizer CSE a read across the
// opaque SetDefault call and observe a stale value (manifests in ReleaseSafe).
extern var sqlite3Config: u8;
inline fn pcache2() *const PcacheMethods2 {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    return @ptrCast(@alignCast(base + L.Sqlite3Config_pcache2));
}

// --- C / SQLite helpers resolved at link time ---
extern fn sqlite3PCacheSetDefault() void;
extern fn memset(dst: ?*anyopaque, ch: c_int, n: usize) ?*anyopaque;

const ROUND8_PgHdr: c_int = @intCast((@sizeOf(PgHdr) + 7) & ~@as(usize, 7));

// ===================== Linked List Management =======================

/// Manage pPage's participation on the dirty list (pcacheManageDirtyList).
/// The 0x01 bit removes first; the 0x02 bit adds back; both = move to front.
fn pcacheManageDirtyList(pPage: *PgHdr, addRemove: u8) void {
    const p = pPage.pCache.?;

    if ((addRemove & PCACHE_DIRTYLIST_REMOVE) != 0) {
        std.debug.assert(pPage.pDirtyNext != null or pPage == p.pDirtyTail);
        std.debug.assert(pPage.pDirtyPrev != null or pPage == p.pDirty);

        // Update PCache.pSynced if necessary.
        if (p.pSynced == pPage) {
            p.pSynced = pPage.pDirtyPrev;
        }

        if (pPage.pDirtyNext) |next| {
            next.pDirtyPrev = pPage.pDirtyPrev;
        } else {
            std.debug.assert(pPage == p.pDirtyTail);
            p.pDirtyTail = pPage.pDirtyPrev;
        }
        if (pPage.pDirtyPrev) |prev| {
            prev.pDirtyNext = pPage.pDirtyNext;
        } else {
            // No dirty pages now -> set eCreate to 2 (xFetch optimization).
            std.debug.assert(pPage == p.pDirty);
            p.pDirty = pPage.pDirtyNext;
            std.debug.assert(p.bPurgeable != 0 or p.eCreate == 2);
            if (p.pDirty == null) { // OPTIMIZATION-IF-TRUE
                std.debug.assert(p.bPurgeable == 0 or p.eCreate == 1);
                p.eCreate = 2;
            }
        }
    }
    if ((addRemove & PCACHE_DIRTYLIST_ADD) != 0) {
        pPage.pDirtyPrev = null;
        pPage.pDirtyNext = p.pDirty;
        if (pPage.pDirtyNext) |next| {
            std.debug.assert(next.pDirtyPrev == null);
            next.pDirtyPrev = pPage;
        } else {
            p.pDirtyTail = pPage;
            if (p.bPurgeable != 0) {
                std.debug.assert(p.eCreate == 2);
                p.eCreate = 1;
            }
        }
        p.pDirty = pPage;

        // If pSynced is NULL and this page has a clear NEED_SYNC flag, set
        // pSynced to point to it (optimization).
        if (p.pSynced == null and (pPage.flags & PGHDR_NEED_SYNC) == 0) { // OPTIMIZATION-IF-FALSE
            p.pSynced = pPage;
        }
    }
}

/// Wrapper around the pluggable cache xUnpin method. No-op for in-memory DBs.
fn pcacheUnpin(p: *PgHdr) void {
    if (p.pCache.?.bPurgeable != 0) {
        pcache2().xUnpin.?(p.pCache.?.pCache, p.pPage, 0);
    }
}

/// Compute the number of pages of cache requested (numberOfCachePages).
fn numberOfCachePages(p: *PCache) c_int {
    if (p.szCache >= 0) {
        // R-42059-47211: positive N -> suggested cache size is N.
        return p.szCache;
    } else {
        // R-59858-46238: negative N -> approx abs(N*1024) bytes of memory.
        var n: i64 = @divTrunc(-1024 * @as(i64, p.szCache), p.szPage + p.szExtra);
        if (n > 1000000000) n = 1000000000;
        return @intCast(n);
    }
}

// ===================== Debug invariant checks =======================
// In C these live under `#if defined(SQLITE_DEBUG) && 0` (pcacheTrace/Dump:
// compile-time off in all configs) and SQLITE_ENABLE_EXPENSIVE_ASSERT
// (pageOnDirtyList: off in both project builds). Folded away accordingly.

/// sqlite3PcachePageSanity — invariant check (SQLITE_DEBUG only). Returns 1
/// when OK. Used only inside asserts in C.
fn pcachePageSanity(pPg: *PgHdr) c_int {
    std.debug.assert(pPg.pgno > 0 or pPg.pPager == null); // pgno is 1+ for real pages
    const pCache = pPg.pCache;
    std.debug.assert(pCache != null); // Every page has an associated PCache
    if ((pPg.flags & PGHDR_CLEAN) != 0) {
        std.debug.assert((pPg.flags & PGHDR_DIRTY) == 0); // not both CLEAN and DIRTY
        // SQLITE_ENABLE_EXPENSIVE_ASSERT (off): pageNotOnDirtyList check.
    } else {
        std.debug.assert((pPg.flags & PGHDR_DIRTY) != 0); // if not CLEAN must be DIRTY
        std.debug.assert(pPg.pDirtyNext == null or pPg.pDirtyNext.?.pDirtyPrev == pPg);
        std.debug.assert(pPg.pDirtyPrev == null or pPg.pDirtyPrev.?.pDirtyNext == pPg);
        std.debug.assert(pPg.pDirtyPrev != null or pCache.?.pDirty == pPg);
        // SQLITE_ENABLE_EXPENSIVE_ASSERT (off): pageOnDirtyList check.
    }
    if ((pPg.flags & PGHDR_WRITEABLE) != 0) {
        std.debug.assert((pPg.flags & PGHDR_DIRTY) != 0); // WRITEABLE implies DIRTY
    }
    return 1;
}

/// Run the sanity check only when SQLITE_DEBUG is compiled (matches the C
/// `assert( sqlite3PcachePageSanity(p) )` which is a no-op in production).
inline fn assertPageSanity(pPg: *PgHdr) void {
    if (config.sqlite_debug) {
        std.debug.assert(pcachePageSanity(pPg) != 0);
    }
}

// ===================== General Interfaces ===========================

export fn sqlite3PcacheInitialize() callconv(.c) c_int {
    if (pcache2().xInit == null) {
        // R-26801-64137: NULL xInit -> install the built-in default cache.
        sqlite3PCacheSetDefault();
    }
    return pcache2().xInit.?(pcache2().pArg);
}

export fn sqlite3PcacheShutdown() callconv(.c) void {
    if (pcache2().xShutdown) |f| {
        // R-26000-56589: xShutdown may be NULL.
        f(pcache2().pArg);
    }
}

/// Return the size in bytes of a PCache object.
export fn sqlite3PcacheSize() callconv(.c) c_int {
    return @sizeOf(PCache);
}

/// Create a new PCache object in caller-supplied preallocated storage.
export fn sqlite3PcacheOpen(
    szPage: c_int,
    szExtra: c_int,
    bPurgeable: c_int,
    xStress: ?*const fn (?*anyopaque, ?*PgHdr) callconv(.c) c_int,
    pStress: ?*anyopaque,
    p: *PCache,
) callconv(.c) c_int {
    _ = memset(p, 0, @sizeOf(PCache));
    p.szPage = 1;
    p.szExtra = szExtra;
    std.debug.assert(szExtra >= 8); // First 8 bytes will be zeroed
    p.bPurgeable = @intCast(bPurgeable & 0xff);
    p.eCreate = 2;
    p.xStress = xStress;
    p.pStress = pStress;
    p.szCache = 100;
    p.szSpill = 1;
    return sqlite3PcacheSetPageSize(p, szPage);
}

/// Change the page size for a PCache. No outstanding page references allowed.
export fn sqlite3PcacheSetPageSize(pCache: *PCache, szPage: c_int) callconv(.c) c_int {
    std.debug.assert(pCache.nRefSum == 0 and pCache.pDirty == null);
    if (pCache.szPage != 0) {
        const pNew = pcache2().xCreate.?(
            szPage,
            pCache.szExtra + ROUND8_PgHdr,
            @intCast(pCache.bPurgeable),
        );
        if (pNew == null) return SQLITE_NOMEM;
        pcache2().xCachesize.?(pNew, numberOfCachePages(pCache));
        if (pCache.pCache) |old| {
            pcache2().xDestroy.?(old);
        }
        pCache.pCache = pNew;
        pCache.szPage = szPage;
    }
    return SQLITE_OK;
}

/// Try to obtain a page from the cache (does not initialize PgHdr).
export fn sqlite3PcacheFetch(pCache: *PCache, pgno: Pgno, createFlag: c_int) callconv(.c) ?*Sqlite3PcachePage {
    std.debug.assert(pCache.pCache != null);
    std.debug.assert(createFlag == 3 or createFlag == 0);
    std.debug.assert(pCache.eCreate == @as(u8, if (pCache.bPurgeable != 0 and pCache.pDirty != null) 1 else 2));

    // eCreate: 0 = no alloc; 1 = alloc if inexpensive; 2 = alloc even if hard.
    const eCreate = createFlag & pCache.eCreate;
    std.debug.assert(eCreate == 0 or eCreate == 1 or eCreate == 2);
    std.debug.assert(createFlag == 0 or pCache.eCreate == eCreate);
    return pcache2().xFetch.?(pCache.pCache, pgno, eCreate);
}

/// Try harder to allocate a page after sqlite3PcacheFetch() fails. May invoke
/// the stress callback to spill dirty pages.
export fn sqlite3PcacheFetchStress(pCache: *PCache, pgno: Pgno, ppPage: *?*Sqlite3PcachePage) callconv(.c) c_int {
    var pPg: ?*PgHdr = undefined;
    if (pCache.eCreate == 2) return 0;

    if (sqlite3PcachePagecount(pCache) > pCache.szSpill) {
        // Find a dirty page to write-out and recycle. Prefer one that does not
        // require a journal-sync (PGHDR_NEED_SYNC clear); else any unreferenced
        // dirty page.
        pPg = pCache.pSynced;
        while (pPg) |pg| {
            if (pg.nRef == 0 and (pg.flags & PGHDR_NEED_SYNC) == 0) break;
            pPg = pg.pDirtyPrev;
        }
        pCache.pSynced = pPg;
        if (pPg == null) {
            pPg = pCache.pDirtyTail;
            while (pPg) |pg| {
                if (pg.nRef == 0) break;
                pPg = pg.pDirtyPrev;
            }
        }
        if (pPg) |pg| {
            // SQLITE_LOG_CACHE_SPILL logging omitted (not enabled in either build).
            const rc = pCache.xStress.?(pCache.pStress, pg);
            if (rc != SQLITE_OK and rc != SQLITE_BUSY) {
                return rc;
            }
        }
    }
    ppPage.* = pcache2().xFetch.?(pCache.pCache, pgno, 2);
    return if (ppPage.* == null) SQLITE_NOMEM else SQLITE_OK;
}

/// Helper for sqlite3PcacheFetchFinish: initialize a freshly-fetched page.
fn pcacheFetchFinishWithInit(pCache: *PCache, pgno: Pgno, pPage: *Sqlite3PcachePage) *PgHdr {
    const pPgHdr: *PgHdr = @ptrCast(@alignCast(pPage.pExtra.?));
    std.debug.assert(pPgHdr.pPage == null);
    // memset(&pPgHdr->pDirty, 0, sizeof(PgHdr) - offsetof(PgHdr,pDirty));
    const base: [*]u8 = @ptrCast(pPgHdr);
    const off = @offsetOf(PgHdr, "pDirty");
    _ = memset(base + off, 0, @sizeOf(PgHdr) - off);
    pPgHdr.pPage = pPage;
    pPgHdr.pData = pPage.pBuf;
    // pExtra points just past the PgHdr (the extra space).
    pPgHdr.pExtra = @ptrCast(base + @sizeOf(PgHdr));
    _ = memset(pPgHdr.pExtra, 0, 8);
    pPgHdr.pCache = pCache;
    pPgHdr.pgno = pgno;
    pPgHdr.flags = PGHDR_CLEAN;
    return sqlite3PcacheFetchFinish(pCache, pgno, pPage);
}

/// Convert the sqlite3_pcache_page from sqlite3PcacheFetch() into a PgHdr.
export fn sqlite3PcacheFetchFinish(pCache: *PCache, pgno: Pgno, pPage: *Sqlite3PcachePage) callconv(.c) *PgHdr {
    const pPgHdr: *PgHdr = @ptrCast(@alignCast(pPage.pExtra.?));

    if (pPgHdr.pPage == null) {
        return pcacheFetchFinishWithInit(pCache, pgno, pPage);
    }
    pCache.nRefSum += 1;
    pPgHdr.nRef += 1;
    assertPageSanity(pPgHdr);
    return pPgHdr;
}

/// Decrement the reference count on a page; recycle if clean and unreferenced.
export fn sqlite3PcacheRelease(p: *PgHdr) callconv(.c) void {
    std.debug.assert(p.nRef > 0);
    p.pCache.?.nRefSum -= 1;
    p.nRef -= 1;
    if (p.nRef == 0) {
        if ((p.flags & PGHDR_CLEAN) != 0) {
            pcacheUnpin(p);
        } else {
            pcacheManageDirtyList(p, PCACHE_DIRTYLIST_FRONT);
            assertPageSanity(p);
        }
    }
}

/// Increase the reference count of a page by 1.
export fn sqlite3PcacheRef(p: *PgHdr) callconv(.c) void {
    std.debug.assert(p.nRef > 0);
    assertPageSanity(p);
    p.nRef += 1;
    p.pCache.?.nRefSum += 1;
}

/// Drop a page from the cache. There must be exactly one reference.
export fn sqlite3PcacheDrop(p: *PgHdr) callconv(.c) void {
    std.debug.assert(p.nRef == 1);
    assertPageSanity(p);
    if ((p.flags & PGHDR_DIRTY) != 0) {
        pcacheManageDirtyList(p, PCACHE_DIRTYLIST_REMOVE);
    }
    p.pCache.?.nRefSum -= 1;
    pcache2().xUnpin.?(p.pCache.?.pCache, p.pPage, 1);
}

/// Make sure the page is marked dirty.
export fn sqlite3PcacheMakeDirty(p: *PgHdr) callconv(.c) void {
    std.debug.assert(p.nRef > 0);
    assertPageSanity(p);
    if ((p.flags & (PGHDR_CLEAN | PGHDR_DONT_WRITE)) != 0) { // OPTIMIZATION-IF-FALSE
        p.flags &= ~PGHDR_DONT_WRITE;
        if ((p.flags & PGHDR_CLEAN) != 0) {
            p.flags ^= (PGHDR_DIRTY | PGHDR_CLEAN);
            std.debug.assert((p.flags & (PGHDR_DIRTY | PGHDR_CLEAN)) == PGHDR_DIRTY);
            pcacheManageDirtyList(p, PCACHE_DIRTYLIST_ADD);
            assertPageSanity(p);
        }
        assertPageSanity(p);
    }
}

/// Make sure the page is marked clean.
export fn sqlite3PcacheMakeClean(p: *PgHdr) callconv(.c) void {
    assertPageSanity(p);
    std.debug.assert((p.flags & PGHDR_DIRTY) != 0);
    std.debug.assert((p.flags & PGHDR_CLEAN) == 0);
    pcacheManageDirtyList(p, PCACHE_DIRTYLIST_REMOVE);
    p.flags &= ~(PGHDR_DIRTY | PGHDR_NEED_SYNC | PGHDR_WRITEABLE);
    p.flags |= PGHDR_CLEAN;
    assertPageSanity(p);
    if (p.nRef == 0) {
        pcacheUnpin(p);
    }
}

/// Make every page in the cache clean.
export fn sqlite3PcacheCleanAll(pCache: *PCache) callconv(.c) void {
    while (pCache.pDirty) |p| {
        sqlite3PcacheMakeClean(p);
    }
}

/// Clear PGHDR_NEED_SYNC and PGHDR_WRITEABLE from all dirty pages.
export fn sqlite3PcacheClearWritable(pCache: *PCache) callconv(.c) void {
    var p = pCache.pDirty;
    while (p) |pg| {
        pg.flags &= ~(PGHDR_NEED_SYNC | PGHDR_WRITEABLE);
        p = pg.pDirtyNext;
    }
    pCache.pSynced = pCache.pDirtyTail;
}

/// Clear PGHDR_NEED_SYNC from all dirty pages.
export fn sqlite3PcacheClearSyncFlags(pCache: *PCache) callconv(.c) void {
    var p = pCache.pDirty;
    while (p) |pg| {
        pg.flags &= ~PGHDR_NEED_SYNC;
        p = pg.pDirtyNext;
    }
    pCache.pSynced = pCache.pDirtyTail;
}

/// Change the page number of page p to newPgno.
export fn sqlite3PcacheMove(p: *PgHdr, newPgno: Pgno) callconv(.c) void {
    const pCache = p.pCache.?;
    std.debug.assert(p.nRef > 0);
    std.debug.assert(newPgno > 0);
    assertPageSanity(p);
    const pOther = pcache2().xFetch.?(pCache.pCache, newPgno, 0);
    if (pOther) |other| {
        const pXPage: *PgHdr = @ptrCast(@alignCast(other.pExtra.?));
        std.debug.assert(pXPage.nRef == 0);
        pXPage.nRef += 1;
        pCache.nRefSum += 1;
        sqlite3PcacheDrop(pXPage);
    }
    pcache2().xRekey.?(pCache.pCache, p.pPage, p.pgno, newPgno);
    p.pgno = newPgno;
    if ((p.flags & PGHDR_DIRTY) != 0 and (p.flags & PGHDR_NEED_SYNC) != 0) {
        pcacheManageDirtyList(p, PCACHE_DIRTYLIST_FRONT);
        assertPageSanity(p);
    }
}

/// Drop every cache entry whose page number is greater than "pgno".
export fn sqlite3PcacheTruncate(pCache: *PCache, pgno_in: Pgno) callconv(.c) void {
    var pgno = pgno_in;
    if (pCache.pCache != null) {
        var p = pCache.pDirty;
        while (p) |pg| {
            const pNext = pg.pDirtyNext;
            // Only ever called with positive pgno right after CleanAll, so any
            // dirty pages here imply pgno==0.
            std.debug.assert(pg.pgno > 0);
            if (pg.pgno > pgno) {
                std.debug.assert((pg.flags & PGHDR_DIRTY) != 0);
                sqlite3PcacheMakeClean(pg);
            }
            p = pNext;
        }
        if (pgno == 0 and pCache.nRefSum != 0) {
            const pPage1 = pcache2().xFetch.?(pCache.pCache, 1, 0);
            // Page 1 is always available because nRefSum>0 (ALWAYS in C).
            if (pPage1) |pg1| {
                _ = memset(pg1.pBuf, 0, @intCast(pCache.szPage));
                pgno = 1;
            }
        }
        pcache2().xTruncate.?(pCache.pCache, pgno + 1);
    }
}

/// Close a cache.
export fn sqlite3PcacheClose(pCache: *PCache) callconv(.c) void {
    std.debug.assert(pCache.pCache != null);
    pcache2().xDestroy.?(pCache.pCache);
}

/// Discard the contents of the cache.
export fn sqlite3PcacheClear(pCache: *PCache) callconv(.c) void {
    sqlite3PcacheTruncate(pCache, 0);
}

/// Merge two pgno-ordered pDirty lists. pDirtyPrev pointers not fixed.
fn pcacheMergeDirtyList(pA_in: *PgHdr, pB_in: *PgHdr) *PgHdr {
    var result: PgHdr = undefined;
    var pTail: *PgHdr = &result;
    var pA: ?*PgHdr = pA_in;
    var pB: ?*PgHdr = pB_in;
    while (true) {
        if (pA.?.pgno < pB.?.pgno) {
            pTail.pDirty = pA;
            pTail = pA.?;
            pA = pA.?.pDirty;
            if (pA == null) {
                pTail.pDirty = pB;
                break;
            }
        } else {
            pTail.pDirty = pB;
            pTail = pB.?;
            pB = pB.?.pDirty;
            if (pB == null) {
                pTail.pDirty = pA;
                break;
            }
        }
    }
    return result.pDirty.?;
}

const N_SORT_BUCKET: usize = 32;

/// Sort the pDirty list ascending by pgno (merge sort). pDirtyPrev corrupted.
fn pcacheSortDirtyList(pIn_in: ?*PgHdr) ?*PgHdr {
    var a: [N_SORT_BUCKET]?*PgHdr = undefined;
    _ = memset(&a, 0, @sizeOf(@TypeOf(a)));
    var pIn = pIn_in;
    while (pIn) |pInPg| {
        var p: *PgHdr = pInPg;
        pIn = p.pDirty;
        p.pDirty = null;
        var i: usize = 0;
        while (i < N_SORT_BUCKET - 1) : (i += 1) { // ALWAYS(i<N_SORT_BUCKET-1)
            if (a[i] == null) {
                a[i] = p;
                break;
            } else {
                p = pcacheMergeDirtyList(a[i].?, p);
                a[i] = null;
            }
        }
        // NEVER(i==N_SORT_BUCKET-1): impossible to need this many buckets.
        if (i == N_SORT_BUCKET - 1) {
            a[i] = pcacheMergeDirtyList(a[i].?, p);
        }
    }
    var p = a[0];
    var i: usize = 1;
    while (i < N_SORT_BUCKET) : (i += 1) {
        if (a[i] == null) continue;
        p = if (p) |pp| pcacheMergeDirtyList(pp, a[i].?) else a[i];
    }
    return p;
}

/// Return a list of all dirty pages in the cache, sorted by page number.
export fn sqlite3PcacheDirtyList(pCache: *PCache) callconv(.c) ?*PgHdr {
    var p = pCache.pDirty;
    while (p) |pg| {
        pg.pDirty = pg.pDirtyNext;
        p = pg.pDirtyNext;
    }
    return pcacheSortDirtyList(pCache.pDirty);
}

/// Return the total number of references to all pages held by the cache.
export fn sqlite3PcacheRefCount(pCache: *PCache) callconv(.c) i64 {
    return pCache.nRefSum;
}

/// True if the cache holds one or more dirty pages. (SQLITE_DIRECT_OVERFLOW_READ
/// is on by default, and pager.c references this in both builds.)
export fn sqlite3PCacheIsDirty(pCache: *PCache) callconv(.c) c_int {
    return @intFromBool(pCache.pDirty != null);
}

/// Return the number of references to the supplied page.
export fn sqlite3PcachePageRefcount(p: *PgHdr) callconv(.c) i64 {
    return p.nRef;
}

/// Return the total number of pages in the cache.
export fn sqlite3PcachePagecount(pCache: *PCache) callconv(.c) c_int {
    std.debug.assert(pCache.pCache != null);
    return pcache2().xPagecount.?(pCache.pCache);
}

/// Set the suggested cache-size value.
export fn sqlite3PcacheSetCachesize(pCache: *PCache, mxPage: c_int) callconv(.c) void {
    std.debug.assert(pCache.pCache != null);
    pCache.szCache = mxPage;
    pcache2().xCachesize.?(pCache.pCache, numberOfCachePages(pCache));
}

/// Set the suggested cache-spill value. No change if argument is zero.
export fn sqlite3PcacheSetSpillsize(p: *PCache, mxPage_in: c_int) callconv(.c) c_int {
    std.debug.assert(p.pCache != null);
    if (mxPage_in != 0) {
        var mxPage = mxPage_in;
        if (mxPage < 0) {
            mxPage = @intCast(@divTrunc(-1024 * @as(i64, mxPage), p.szPage + p.szExtra));
        }
        p.szSpill = mxPage;
    }
    var res = numberOfCachePages(p);
    if (res < p.szSpill) res = p.szSpill;
    return res;
}

/// Free up as much memory as possible from the page cache.
export fn sqlite3PcacheShrink(pCache: *PCache) callconv(.c) void {
    std.debug.assert(pCache.pCache != null);
    pcache2().xShrink.?(pCache.pCache);
}

/// Return the size of the header added by this middleware layer.
export fn sqlite3HeaderSizePcache() callconv(.c) c_int {
    return ROUND8_PgHdr;
}

/// Number of dirty pages as a percentage of the configured cache size.
export fn sqlite3PCachePercentDirty(pCache: *PCache) callconv(.c) c_int {
    var nDirty: c_int = 0;
    const nCache = numberOfCachePages(pCache);
    var pDirty = pCache.pDirty;
    while (pDirty) |pg| {
        nDirty += 1;
        pDirty = pg.pDirtyNext;
    }
    return if (nCache != 0) @intCast(@divTrunc(@as(i64, nDirty) * 100, nCache)) else 0;
}

// --- SQLITE_TEST-only ---

/// Get the suggested cache-size value (SQLITE_TEST only).
fn pcacheGetCachesize(pCache: *PCache) callconv(.c) c_int {
    return numberOfCachePages(pCache);
}

// --- SQLITE_CHECK_PAGES || SQLITE_DEBUG ---

/// For all dirty pages currently in the cache, invoke xIter. Used by the
/// SQLITE_CHECK_PAGES page-hash consistency checks.
fn pcacheIterateDirty(pCache: *PCache, xIter: *const fn (?*PgHdr) callconv(.c) void) callconv(.c) void {
    var pDirty = pCache.pDirty;
    while (pDirty) |pg| {
        xIter(pg);
        pDirty = pg.pDirtyNext;
    }
}

/// Exported wrapper for sqlite3PcachePageSanity (SQLITE_DEBUG only).
fn pcachePageSanityExport(pPg: *PgHdr) callconv(.c) c_int {
    return pcachePageSanity(pPg);
}

comptime {
    if (config.sqlite_test) {
        @export(&pcacheGetCachesize, .{ .name = "sqlite3PcacheGetCachesize" });
    }
    if (config.sqlite_debug) {
        @export(&pcachePageSanityExport, .{ .name = "sqlite3PcachePageSanity" });
        @export(&pcacheIterateDirty, .{ .name = "sqlite3PcacheIterateDirty" });
    }
}
