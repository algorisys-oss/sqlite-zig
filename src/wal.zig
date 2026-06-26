//! Zig port of SQLite's write-ahead log (src/wal.c).
//!
//! Implements journal_mode=WAL: the `-wal` file format, the wal-index
//! (shared-memory hash), frame read/write, checkpointing, WAL recovery, and the
//! reader/writer lock protocol. The on-disk `-wal` format and the shared-memory
//! `-shm` (wal-index) format are BIT-EXACT with upstream SQLite — same magic,
//! same checksum algorithm (native vs byte-swapped), same hash function, same
//! WalIndexHdr/WalCkptInfo byte layout. Cross-process / cross-implementation
//! compatibility depends on this.
//!
//! Coupling:
//!   * `Wal`, `WalIndexHdr`, `WalCkptInfo`, `WalIterator`, `WalHashLoc` are all
//!     PRIVATE to wal.c — every other subsystem holds an opaque `Wal*`. We own
//!     their layout. BUT `WalIndexHdr`/`WalCkptInfo` ARE the shm on-disk format,
//!     so their field order and sizes are fixed (asserted at comptime against
//!     the same constants C asserts in sqlite3WalOpen).
//!   * Calls the already-ported-to-Zig `sqlite3Os*` wrappers (os.zig), including
//!     the SHM methods (ShmMap/ShmLock/ShmBarrier/ShmUnmap), `sqlite3Get4byte`/
//!     `sqlite3Put4byte` (util.zig), and a handful of remaining-C helpers
//!     (malloc, randomness, log, faultsim, error helpers).
//!   * Reads `PgHdr` fields (pData/pgno/flags/pDirty — ABI-shared, pcache.h) and
//!     two `sqlite3` fields (`u1.isInterrupted`, `mallocFailed`) at their
//!     ground-truth (config-invariant) offsets via c_layout.zig.
//!
//! Disabled compile-time features (matching this project's flags): SQLITE_USE_SEH
//! (Windows-only), SQLITE_ENABLE_SNAPSHOT, SQLITE_ENABLE_SETLK_TIMEOUT,
//! SQLITE_ENABLE_ZIPVFS, SQLITE_OMIT_WAL. SQLITE_DEBUG / SQLITE_TEST differ
//! between the production and testfixture builds and are handled via @import("config").

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ───────────────────────── error codes (sqlite3.h) ─────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_BUSY: c_int = 5;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_READONLY: c_int = 8;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_CANTOPEN: c_int = 14;
const SQLITE_PROTOCOL: c_int = 15;

const SQLITE_IOERR_SHORT_READ: c_int = SQLITE_IOERR | (2 << 8);
const SQLITE_BUSY_RECOVERY: c_int = SQLITE_BUSY | (1 << 8);
const SQLITE_BUSY_SNAPSHOT: c_int = SQLITE_BUSY | (2 << 8);
const SQLITE_READONLY_RECOVERY: c_int = SQLITE_READONLY | (1 << 8);
const SQLITE_READONLY_CANTINIT: c_int = SQLITE_READONLY | (5 << 8);
const SQLITE_NOMEM_BKPT: c_int = SQLITE_NOMEM; // SQLITE_DEBUG bookkeeping is irrelevant to behaviour
const SQLITE_NOTICE_RECOVER_WAL: c_int = 27 | (1 << 8); // SQLITE_NOTICE==27

// ───────────────────────── other public constants ─────────────────────────
const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
const SQLITE_OPEN_CREATE: c_int = 0x00000004;
const SQLITE_OPEN_READONLY: c_int = 0x00000001;
const SQLITE_OPEN_WAL: c_int = 0x00080000;

const SQLITE_LOCK_EXCLUSIVE: c_int = 4;

const SQLITE_SHM_UNLOCK: c_int = 1;
const SQLITE_SHM_LOCK: c_int = 2;
const SQLITE_SHM_SHARED: c_int = 4;
const SQLITE_SHM_EXCLUSIVE: c_int = 8;
const SQLITE_SHM_NLOCK: c_int = 8;

const SQLITE_IOCAP_SEQUENTIAL: c_int = 0x00000400;
const SQLITE_IOCAP_POWERSAFE_OVERWRITE: c_int = 0x00001000;

const SQLITE_FCNTL_SIZE_HINT: c_int = 5;
const SQLITE_FCNTL_PERSIST_WAL: c_int = 10;
const SQLITE_FCNTL_CKPT_DONE: c_int = 37;
const SQLITE_FCNTL_CKPT_START: c_int = 39;

const SQLITE_CHECKPOINT_PASSIVE: c_int = 0;
const SQLITE_CHECKPOINT_FULL: c_int = 1;
const SQLITE_CHECKPOINT_RESTART: c_int = 2;
const SQLITE_CHECKPOINT_TRUNCATE: c_int = 3;
const SQLITE_CHECKPOINT_NOOP: c_int = -1; // SQLITE_CHECKPOINT_NOOP < PASSIVE

// SQLITE_BIGENDIAN is 0 on this (little-endian x86-64) target.
const SQLITE_BIGENDIAN: c_int = if (builtin.cpu.arch.endian() == .big) 1 else 0;

// PgHdr flags (pcache.h)
const PGHDR_WAL_APPEND: u16 = 0x040;

// WAL_SYNC_FLAGS(X) / CKPT_SYNC_FLAGS(X) (wal.h)
inline fn WAL_SYNC_FLAGS(x: c_int) c_int {
    return x & 0x03;
}
inline fn CKPT_SYNC_FLAGS(x: c_int) c_int {
    return (x >> 2) & 0x03;
}

// ───────────────────────── wal/wal-index format constants ──────────────────
const WAL_MAX_VERSION: u32 = 3007000;
const WALINDEX_MAX_VERSION: u32 = 3007000;

const WAL_WRITE_LOCK: c_int = 0;
const WAL_ALL_BUT_WRITE: c_int = 1;
const WAL_CKPT_LOCK: c_int = 1;
const WAL_RECOVER_LOCK: c_int = 2;
inline fn WAL_READ_LOCK(i: c_int) c_int {
    return 3 + i;
}
const WAL_NREADER: c_int = SQLITE_SHM_NLOCK - 3; // == 5

const WAL_FRAME_HDRSIZE: i64 = 24;
const WAL_HDRSIZE: i64 = 32;
const WAL_MAGIC: u32 = 0x377f0682;

const WAL_SAVEPOINT_NDATA: c_int = 4;

const READMARK_NOT_USED: u32 = 0xffffffff;

const HASHTABLE_NPAGE: u32 = 4096; // Must be power of 2
const HASHTABLE_HASH_1: u32 = 383; // Should be prime
const HASHTABLE_NSLOT: u32 = HASHTABLE_NPAGE * 2; // Must be a power of 2

// Wal.exclusiveMode candidate values
const WAL_NORMAL_MODE: u8 = 0;
const WAL_EXCLUSIVE_MODE: u8 = 1;
const WAL_HEAPMEMORY_MODE: u8 = 2;

// Wal.readOnly values
const WAL_RDWR: u8 = 0;
const WAL_RDONLY: u8 = 1;
const WAL_SHM_RDONLY: u8 = 2;

const WAL_RETRY: c_int = -1;
const WAL_RETRY_PROTOCOL_LIMIT: c_int = 100;
const WAL_RETRY_BLOCKED_MASK: c_int = 0; // SQLITE_ENABLE_SETLK_TIMEOUT off

const SQLITE_MAX_PAGE_SIZE: c_int = 65536;

const ht_slot = u16;

// ───────────────────────── opaque public types ─────────────────────────────
const Sqlite3 = opaque {};
const Sqlite3Vfs = opaque {};

const Sqlite3File = extern struct {
    pMethods: ?*const anyopaque,
};

const Pgno = u32;

/// PgHdr — ABI-shared (pcache.h). Mirrored field-for-field, pinned to c_layout
/// (identical to the mirror in pager.zig).
const PgHdr = extern struct {
    pPage: ?*anyopaque,
    pData: ?*anyopaque,
    pExtra: ?*anyopaque,
    pCache: ?*anyopaque,
    pDirty: ?*PgHdr,
    pPager: ?*anyopaque,
    pgno: Pgno,
    flags: u16,
    nRef: i64,
    pDirtyNext: ?*PgHdr,
    pDirtyPrev: ?*PgHdr,
};

comptime {
    std.debug.assert(@sizeOf(PgHdr) == L.sizeof_PgHdr);
    std.debug.assert(@offsetOf(PgHdr, "pData") == L.PgHdr_pData);
    std.debug.assert(@offsetOf(PgHdr, "pgno") == L.PgHdr_pgno);
    std.debug.assert(@offsetOf(PgHdr, "flags") == L.PgHdr_flags);
    std.debug.assert(@offsetOf(PgHdr, "pDirty") == L.PgHdr_pDirty);
}

// ───────────────────────── private wal structures ──────────────────────────
//
// WalIndexHdr / WalCkptInfo ARE the -shm on-disk format. Layout is fixed and
// asserted below (the same numbers C asserts in sqlite3WalOpen).

const WalIndexHdr = extern struct {
    iVersion: u32, // Wal-index version
    unused: u32, // Unused (padding) field
    iChange: u32, // Counter incremented each transaction
    isInit: u8, // 1 when initialized
    bigEndCksum: u8, // True if checksums in WAL are big-endian
    szPage: u16, // Database page size in bytes. 1==64K
    mxFrame: u32, // Index of last valid frame in the WAL
    nPage: u32, // Size of database in pages
    aFrameCksum: [2]u32, // Checksum of last frame in log
    aSalt: [2]u32, // Two salt values copied from WAL header
    aCksum: [2]u32, // Checksum over all prior fields
};

const WalCkptInfo = extern struct {
    nBackfill: u32, // Number of WAL frames backfilled into DB
    aReadMark: [@intCast(WAL_NREADER)]u32, // Reader marks
    aLock: [@intCast(SQLITE_SHM_NLOCK)]u8, // Reserved space for locks
    nBackfillAttempted: u32, // WAL frames perhaps written, or maybe not
    notUsed0: u32, // Available for future enhancements
};

// WALINDEX_LOCK_OFFSET = sizeof(WalIndexHdr)*2 + offsetof(WalCkptInfo,aLock)
const WALINDEX_LOCK_OFFSET: usize = @sizeOf(WalIndexHdr) * 2 + @offsetOf(WalCkptInfo, "aLock");
const WALINDEX_HDR_SIZE: usize = @sizeOf(WalIndexHdr) * 2 + @sizeOf(WalCkptInfo);

// HASHTABLE_NPAGE_ONE = HASHTABLE_NPAGE - (WALINDEX_HDR_SIZE/sizeof(u32))
const HASHTABLE_NPAGE_ONE: u32 = HASHTABLE_NPAGE - (WALINDEX_HDR_SIZE / @sizeOf(u32));
// WALINDEX_PGSZ = sizeof(ht_slot)*HASHTABLE_NSLOT + HASHTABLE_NPAGE*sizeof(u32)
const WALINDEX_PGSZ: usize = @sizeOf(ht_slot) * HASHTABLE_NSLOT + HASHTABLE_NPAGE * @sizeOf(u32);

comptime {
    // The same backward-compatibility asserts that C makes in sqlite3WalOpen.
    std.debug.assert(48 == @sizeOf(WalIndexHdr));
    std.debug.assert(40 == @sizeOf(WalCkptInfo));
    std.debug.assert(120 == WALINDEX_LOCK_OFFSET);
    std.debug.assert(136 == WALINDEX_HDR_SIZE);
    std.debug.assert(4096 == HASHTABLE_NPAGE);
    std.debug.assert(4062 == HASHTABLE_NPAGE_ONE);
    std.debug.assert(8192 == HASHTABLE_NSLOT);
    std.debug.assert(383 == HASHTABLE_HASH_1);
    std.debug.assert(32768 == WALINDEX_PGSZ);
    std.debug.assert(8 == SQLITE_SHM_NLOCK);
    std.debug.assert(5 == WAL_NREADER);
    std.debug.assert(24 == WAL_FRAME_HDRSIZE);
    std.debug.assert(32 == WAL_HDRSIZE);
    std.debug.assert(120 == WALINDEX_LOCK_OFFSET + WAL_WRITE_LOCK);
    std.debug.assert(127 == WALINDEX_LOCK_OFFSET + WAL_READ_LOCK(4));
    // The wal-index hash table & page-number array must fit one shm page.
    std.debug.assert(WALINDEX_HDR_SIZE % @sizeOf(u32) == 0);
}

/// An open write-ahead log. PRIVATE — every other module holds an opaque
/// pointer, so we own this layout entirely.
const Wal = extern struct {
    pVfs: *Sqlite3Vfs, // The VFS used to create pDbFd
    pDbFd: *Sqlite3File, // File handle for the database file
    pWalFd: *Sqlite3File, // File handle for WAL file
    iCallback: u32, // Value to pass to log callback (or 0)
    mxWalSize: i64, // Truncate WAL to this size upon reset
    nWiData: c_int, // Size of array apWiData
    szFirstBlock: c_int, // Size of first block written to WAL file
    apWiData: ?[*]?[*]volatile u32, // Pointer to wal-index content in memory
    szPage: u32, // Database page size
    readLock: i16, // Which read lock is being held.  -1 for none
    syncFlags: u8, // Flags to use to sync header writes
    exclusiveMode: u8, // Non-zero if connection is in exclusive mode
    writeLock: u8, // True if in a write transaction
    ckptLock: u8, // True if holding a checkpoint lock
    readOnly: u8, // WAL_RDWR, WAL_RDONLY, or WAL_SHM_RDONLY
    truncateOnCommit: u8, // True to truncate WAL file on commit
    syncHeader: u8, // Fsync the WAL header if true
    padToSectorBoundary: u8, // Pad transactions out to the next sector
    bShmUnreliable: u8, // SHM content is read-only and unreliable
    hdr: WalIndexHdr, // Wal-index header for current transaction
    minFrame: u32, // Ignore wal frames before this one
    iReCksum: u32, // On commit, recalculate checksums from here
    zWalName: [*:0]const u8, // Name of WAL file
    nCkpt: u32, // Checkpoint sequence counter in the wal-header
    // SQLITE_DEBUG adds: int nSehTry; u8 lockError. We track lockError only when
    // debug (it is read by an assert in sqlite3WalExclusiveMode). Layout is
    // private so the extra tail is harmless.
    lockError: if (config.sqlite_debug) u8 else void,
};

/// WalHashLoc — describes the location of a page hash table in the wal-index.
const WalHashLoc = struct {
    aHash: [*]volatile ht_slot, // Start of the wal-index hash table
    aPgno: [*]volatile u32, // aPgno[0] is the page of first frame indexed
    iZero: u32, // One less than frame number of first indexed
};

const WalSegment = extern struct {
    iNext: c_int, // Next slot in aIndex[] not yet returned
    aIndex: [*]ht_slot, // i0, i1, i2... such that aPgno[iN] ascend
    aPgno: [*]u32, // Array of page numbers.
    nEntry: c_int, // Nr. of entries in aPgno[] and aIndex[]
    iZero: c_int, // Frame number associated with aPgno[0]
};

/// WalIterator — loops through WAL frames in database page order. Allocated as
/// one block with a trailing flexible aSegment[] array.
const WalIterator = extern struct {
    iPrior: u32, // Last result returned from the iterator
    nSegment: c_int, // Number of entries in aSegment[]
    // aSegment[FLEXARRAY] follows here in the same allocation.

    inline fn seg(p: *WalIterator) [*]WalSegment {
        const base: [*]u8 = @ptrCast(p);
        return @ptrCast(@alignCast(base + SZ_WALITERATOR(0)));
    }
};

// offsetof(WalIterator,aSegment) — aSegment starts after the two leading ints,
// padded to the alignment of WalSegment (8, because of the pointers).
inline fn SZ_WALITERATOR(n: usize) usize {
    return std.mem.alignForward(usize, @sizeOf(WalIterator), @alignOf(WalSegment)) + n * @sizeOf(WalSegment);
}

// ───────────────────────── remaining-C helpers ─────────────────────────────
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_randomness(n: c_int, p: ?*anyopaque) void;
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3CorruptError(lineno: c_int) c_int;
extern fn sqlite3CantopenError(lineno: c_int) c_int;
extern fn sqlite3FaultSim(x: c_int) c_int;
extern fn sqlite3BeginBenignMalloc() void;
extern fn sqlite3EndBenignMalloc() void;
extern fn memset(s: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcpy(d: ?*anyopaque, s: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

// util.zig (ported Zig)
extern fn sqlite3Get4byte(p: ?[*]const u8) u32;
extern fn sqlite3Put4byte(p: ?[*]u8, v: u32) void;

// os.zig (ported Zig) — sqlite3_file wrappers (incl. SHM methods)
extern fn sqlite3OsOpen(*Sqlite3Vfs, ?[*:0]const u8, *Sqlite3File, c_int, ?*c_int) c_int;
extern fn sqlite3OsClose(*Sqlite3File) void;
extern fn sqlite3OsDelete(*Sqlite3Vfs, ?[*:0]const u8, c_int) c_int;
extern fn sqlite3OsRead(*Sqlite3File, ?*anyopaque, c_int, i64) c_int;
extern fn sqlite3OsWrite(*Sqlite3File, ?*const anyopaque, c_int, i64) c_int;
extern fn sqlite3OsTruncate(*Sqlite3File, i64) c_int;
extern fn sqlite3OsSync(*Sqlite3File, c_int) c_int;
extern fn sqlite3OsFileSize(*Sqlite3File, *i64) c_int;
extern fn sqlite3OsLock(*Sqlite3File, c_int) c_int;
extern fn sqlite3OsFileControl(*Sqlite3File, c_int, ?*anyopaque) c_int;
extern fn sqlite3OsFileControlHint(*Sqlite3File, c_int, ?*anyopaque) void;
extern fn sqlite3OsSectorSize(*Sqlite3File) c_int;
extern fn sqlite3OsDeviceCharacteristics(*Sqlite3File) c_int;
extern fn sqlite3OsShmMap(*Sqlite3File, c_int, c_int, c_int, ?*anyopaque) c_int;
extern fn sqlite3OsShmLock(*Sqlite3File, c_int, c_int, c_int) c_int;
extern fn sqlite3OsShmBarrier(*Sqlite3File) void;
extern fn sqlite3OsShmUnmap(*Sqlite3File, c_int) c_int;
extern fn sqlite3OsSleep(*Sqlite3Vfs, c_int) c_int;
extern fn sqlite3OsUnfetch(*Sqlite3File, i64, ?*anyopaque) c_int;

/// szOsFile of a VFS — read from the public sqlite3_vfs ABI. We avoid importing
/// the whole struct: szOsFile is the second `int` field (offset 4).
inline fn vfsSzOsFile(pVfs: *Sqlite3Vfs) c_int {
    const base: [*]const u8 = @ptrCast(pVfs);
    const p: *const c_int = @ptrCast(@alignCast(base + 4));
    return p.*;
}

/// iVersion of a sqlite3_io_methods (first field) — used by the FCNTL_CKPT path.
inline fn ioMethodsVersion(pFd: *Sqlite3File) c_int {
    const m = pFd.pMethods orelse return 0;
    const p: *const c_int = @ptrCast(@alignCast(m));
    return p.*;
}

// sqlite3 field accessors at ground-truth offsets (config-invariant).
inline fn dbIsInterrupted(db: *Sqlite3) bool {
    // u1.isInterrupted is the first member of the u1 union.
    const base: [*]const u8 = @ptrCast(db);
    const p: *const std.atomic.Value(c_int) = @ptrCast(@alignCast(base + L.sqlite3_u1));
    return p.load(.monotonic) != 0;
}
inline fn dbMallocFailed(db: *Sqlite3) bool {
    const base: [*]const u8 = @ptrCast(db);
    const p: *const u8 = @ptrCast(base + L.sqlite3_mallocFailed);
    return p.* != 0;
}

// ───────────────────────── small inline helpers ────────────────────────────

/// walFrameOffset(iFrame, szPage): byte offset of frame iFrame's header.
inline fn walFrameOffset(iFrame: u32, szPage: u32) i64 {
    return WAL_HDRSIZE + (@as(i64, iFrame) - 1) * (@as(i64, szPage) + WAL_FRAME_HDRSIZE);
}

/// BYTESWAP32 — interpret the 4 bytes in the opposite endianness.
inline fn byteswap32(x: u32) u32 {
    return @byteSwap(x);
}

fn min64(a: i64, b: i64) i64 {
    return if (a < b) a else b;
}
fn minU32(a: u32, b: u32) u32 {
    return if (a < b) a else b;
}

// Relaxed atomic load/store on a volatile u32 in shared memory, matching C's
// AtomicLoad/AtomicStore (__ATOMIC_RELAXED).
inline fn atomicLoadU32(p: *volatile u32) u32 {
    const ap: *const std.atomic.Value(u32) = @ptrCast(@volatileCast(p));
    return ap.load(.monotonic);
}
inline fn atomicStoreU32(p: *volatile u32, v: u32) void {
    const ap: *std.atomic.Value(u32) = @ptrCast(@volatileCast(p));
    ap.store(v, .monotonic);
}
inline fn atomicLoadHt(p: *volatile ht_slot) ht_slot {
    const ap: *const std.atomic.Value(ht_slot) = @ptrCast(@volatileCast(p));
    return ap.load(.monotonic);
}
inline fn atomicStoreHt(p: *volatile ht_slot, v: ht_slot) void {
    const ap: *std.atomic.Value(ht_slot) = @ptrCast(@volatileCast(p));
    ap.store(v, .monotonic);
}

// ───────────────────────── wal-index page access ───────────────────────────

fn walIndexPageRealloc(pWal: *Wal, iPage: c_int, ppPage: *?[*]volatile u32) c_int {
    var rc: c_int = SQLITE_OK;

    if (pWal.nWiData <= iPage) {
        const nByte: u64 = @sizeOf(?*anyopaque) * (1 + @as(u64, @intCast(iPage)));
        const apNew: ?[*]?[*]volatile u32 = @ptrCast(@alignCast(sqlite3Realloc(@ptrCast(pWal.apWiData), nByte)));
        if (apNew == null) {
            ppPage.* = null;
            return SQLITE_NOMEM_BKPT;
        }
        const oldN: usize = @intCast(pWal.nWiData);
        const newN: usize = @intCast(iPage + 1);
        var i = oldN;
        while (i < newN) : (i += 1) apNew.?[i] = null;
        pWal.apWiData = apNew;
        pWal.nWiData = iPage + 1;
    }

    std.debug.assert(pWal.apWiData.?[@intCast(iPage)] == null);
    if (pWal.exclusiveMode == WAL_HEAPMEMORY_MODE) {
        pWal.apWiData.?[@intCast(iPage)] = @ptrCast(@alignCast(sqlite3MallocZero(WALINDEX_PGSZ)));
        if (pWal.apWiData.?[@intCast(iPage)] == null) rc = SQLITE_NOMEM_BKPT;
    } else {
        rc = sqlite3OsShmMap(pWal.pDbFd, iPage, @intCast(WALINDEX_PGSZ), pWal.writeLock, @ptrCast(&pWal.apWiData.?[@intCast(iPage)]));
        if (rc == SQLITE_OK) {
            if (iPage > 0 and sqlite3FaultSim(600) != 0) rc = SQLITE_NOMEM;
        } else if ((rc & 0xff) == SQLITE_READONLY) {
            pWal.readOnly |= WAL_SHM_RDONLY;
            if (rc == SQLITE_READONLY) rc = SQLITE_OK;
        }
    }

    ppPage.* = pWal.apWiData.?[@intCast(iPage)];
    return rc;
}

fn walIndexPage(pWal: *Wal, iPage: c_int, ppPage: *?[*]volatile u32) c_int {
    if (pWal.nWiData <= iPage or blk: {
        ppPage.* = pWal.apWiData.?[@intCast(iPage)];
        break :blk ppPage.* == null;
    }) {
        return walIndexPageRealloc(pWal, iPage, ppPage);
    }
    return SQLITE_OK;
}

/// Pointer to the WalCkptInfo in the wal-index (lives at apWiData[0] +
/// sizeof(WalIndexHdr)/2 in u32 units, i.e. right after both header copies).
fn walCkptInfo(pWal: *Wal) *volatile WalCkptInfo {
    const page0 = pWal.apWiData.?[0].?;
    const p = page0 + (@sizeOf(WalIndexHdr) / 2);
    return @ptrCast(@alignCast(@volatileCast(p)));
}

/// Pointer to the (live) WalIndexHdr[2] in the wal-index.
fn walIndexHdr(pWal: *Wal) [*]volatile WalIndexHdr {
    const page0 = pWal.apWiData.?[0].?;
    return @ptrCast(@alignCast(@volatileCast(page0)));
}

// ───────────────────────── checksum ─────────────────────────────────────────

/// Generate or extend an 8-byte checksum. BIT-EXACT with upstream: native
/// byte-order if `nativeCksum`, else byte-swapped. Accumulation wraps (u32
/// overflow is defined for C unsigned), so we use wrapping +%.
fn walChecksumBytes(nativeCksum: bool, a: [*]const u8, nByte: usize, aIn: ?*const [2]u32, aOut: *[2]u32) void {
    var s1: u32 = undefined;
    var s2: u32 = undefined;
    if (aIn) |in| {
        s1 = in[0];
        s2 = in[1];
    } else {
        s1 = 0;
        s2 = 0;
    }

    std.debug.assert(nByte >= 8 and (nByte & 7) == 0 and nByte <= 65536);

    const n = nByte / 4; // number of u32 words (even)
    var i: usize = 0;
    if (!nativeCksum) {
        while (i < n) : (i += 2) {
            s1 +%= byteswap32(readWordUnaligned(a, i)) +% s2;
            s2 +%= byteswap32(readWordUnaligned(a, i + 1)) +% s1;
        }
    } else {
        while (i < n) : (i += 2) {
            s1 +%= readWordUnaligned(a, i) +% s2;
            s2 +%= readWordUnaligned(a, i + 1) +% s1;
        }
    }

    aOut[0] = s1;
    aOut[1] = s2;
}

/// Read the i-th host-endian u32 word from a byte buffer that the C code treats
/// as a `u32*`. The buffers passed in (wal header, frame header, page data) are
/// 4-byte aligned in practice, but read unaligned to be safe; the value is in
/// host byte order exactly as `((u32*)a)[i]` would yield.
inline fn readWordUnaligned(a: [*]const u8, i: usize) u32 {
    var v: u32 = undefined;
    @memcpy(std.mem.asBytes(&v), a[i * 4 ..][0..4]);
    return v;
}

/// Memory barrier if there may be concurrent SHM access.
fn walShmBarrier(pWal: *Wal) void {
    if (pWal.exclusiveMode != WAL_HEAPMEMORY_MODE) {
        sqlite3OsShmBarrier(pWal.pDbFd);
    }
}

/// Write pWal->hdr into the wal-index (after refreshing its checksum). Two
/// copies, with a barrier between, matching tag-20200519-1.
fn walIndexWriteHdr(pWal: *Wal) void {
    const aHdr = walIndexHdr(pWal);
    const nCksum: usize = @offsetOf(WalIndexHdr, "aCksum");

    std.debug.assert(pWal.writeLock != 0);
    pWal.hdr.isInit = 1;
    pWal.hdr.iVersion = WALINDEX_MAX_VERSION;
    walChecksumBytes(true, std.mem.asBytes(&pWal.hdr), nCksum, null, &pWal.hdr.aCksum);
    // Possible TSAN false-positive. See tag-20200519-1
    copyHdrTo(&aHdr[1], &pWal.hdr);
    walShmBarrier(pWal);
    copyHdrTo(&aHdr[0], &pWal.hdr);
}

inline fn copyHdrTo(dst: *volatile WalIndexHdr, src: *const WalIndexHdr) void {
    _ = memcpy(@volatileCast(dst), src, @sizeOf(WalIndexHdr));
}
inline fn copyHdrFrom(dst: *WalIndexHdr, src: *const volatile WalIndexHdr) void {
    _ = memcpy(dst, @volatileCast(src), @sizeOf(WalIndexHdr));
}

// ───────────────────────── frame encode/decode ─────────────────────────────

fn walEncodeFrame(pWal: *Wal, iPage: u32, nTruncate: u32, aData: [*]const u8, aFrame: [*]u8) void {
    const aCksum = &pWal.hdr.aFrameCksum;
    sqlite3Put4byte(aFrame, iPage);
    sqlite3Put4byte(aFrame + 4, nTruncate);
    if (pWal.iReCksum == 0) {
        _ = memcpy(aFrame + 8, &pWal.hdr.aSalt, 8);
        const nativeCksum = (pWal.hdr.bigEndCksum == SQLITE_BIGENDIAN);
        walChecksumBytes(nativeCksum, aFrame, 8, aCksum, aCksum);
        walChecksumBytes(nativeCksum, aData, pWal.szPage, aCksum, aCksum);
        sqlite3Put4byte(aFrame + 16, aCksum[0]);
        sqlite3Put4byte(aFrame + 20, aCksum[1]);
    } else {
        _ = memset(aFrame + 8, 0, 16);
    }
}

fn walDecodeFrame(pWal: *Wal, piPage: *u32, pnTruncate: *u32, aData: [*]const u8, aFrame: [*]const u8) bool {
    const aCksum = &pWal.hdr.aFrameCksum;

    if (memcmp(&pWal.hdr.aSalt, aFrame + 8, 8) != 0) return false;

    const pgno = sqlite3Get4byte(aFrame);
    if (pgno == 0) return false;
    if (pWal.szPage == 0) return false;

    const nativeCksum = (pWal.hdr.bigEndCksum == SQLITE_BIGENDIAN);
    walChecksumBytes(nativeCksum, aFrame, 8, aCksum, aCksum);
    walChecksumBytes(nativeCksum, aData, pWal.szPage, aCksum, aCksum);
    if (aCksum[0] != sqlite3Get4byte(aFrame + 16) or aCksum[1] != sqlite3Get4byte(aFrame + 20)) {
        return false;
    }

    piPage.* = pgno;
    pnTruncate.* = sqlite3Get4byte(aFrame + 4);
    return true;
}

// ───────────────────────── SHM locks ───────────────────────────────────────

fn walLockShared(pWal: *Wal, lockIdx: c_int) c_int {
    if (pWal.exclusiveMode != 0) return SQLITE_OK;
    const rc = sqlite3OsShmLock(pWal.pDbFd, lockIdx, 1, SQLITE_SHM_LOCK | SQLITE_SHM_SHARED);
    if (config.sqlite_debug) {
        pWal.lockError = @intFromBool(rc != SQLITE_OK and (rc & 0xFF) != SQLITE_BUSY);
    }
    return rc;
}
fn walUnlockShared(pWal: *Wal, lockIdx: c_int) void {
    if (pWal.exclusiveMode != 0) return;
    _ = sqlite3OsShmLock(pWal.pDbFd, lockIdx, 1, SQLITE_SHM_UNLOCK | SQLITE_SHM_SHARED);
}
fn walLockExclusive(pWal: *Wal, lockIdx: c_int, n: c_int) c_int {
    if (pWal.exclusiveMode != 0) return SQLITE_OK;
    const rc = sqlite3OsShmLock(pWal.pDbFd, lockIdx, n, SQLITE_SHM_LOCK | SQLITE_SHM_EXCLUSIVE);
    if (config.sqlite_debug) {
        pWal.lockError = @intFromBool(rc != SQLITE_OK and (rc & 0xFF) != SQLITE_BUSY);
    }
    return rc;
}
fn walUnlockExclusive(pWal: *Wal, lockIdx: c_int, n: c_int) void {
    if (pWal.exclusiveMode != 0) return;
    _ = sqlite3OsShmLock(pWal.pDbFd, lockIdx, n, SQLITE_SHM_UNLOCK | SQLITE_SHM_EXCLUSIVE);
}

// ───────────────────────── hash table helpers ──────────────────────────────

fn walHash(iPage: u32) usize {
    std.debug.assert(iPage > 0);
    return @intCast((iPage *% HASHTABLE_HASH_1) & (HASHTABLE_NSLOT - 1));
}
fn walNextHash(iPriorHash: usize) usize {
    return (iPriorHash + 1) & (HASHTABLE_NSLOT - 1);
}

/// Locate the iHash'th hash table & page-number array in the wal-index.
fn walHashGet(pWal: *Wal, iHash: c_int, pLoc: *WalHashLoc) c_int {
    var aPgno: ?[*]volatile u32 = undefined;
    const rc = walIndexPage(pWal, iHash, &aPgno);
    std.debug.assert(rc == SQLITE_OK or iHash > 0);

    if (aPgno) |pg| {
        // aHash sits at &aPgno[HASHTABLE_NPAGE]; aPgno then advances for iHash==0.
        pLoc.aHash = @ptrCast(@alignCast(pg + HASHTABLE_NPAGE));
        if (iHash == 0) {
            pLoc.aPgno = pg + (WALINDEX_HDR_SIZE / @sizeOf(u32));
            pLoc.iZero = 0;
        } else {
            pLoc.aPgno = pg;
            pLoc.iZero = HASHTABLE_NPAGE_ONE + @as(u32, @intCast(iHash - 1)) * HASHTABLE_NPAGE;
        }
        return SQLITE_OK;
    } else if (rc == SQLITE_OK) {
        // NEVER in practice (aPgno null with OK only for iHash==0).
        return SQLITE_ERROR;
    }
    return rc;
}

/// Which wal-index page holds the entries for WAL frame iFrame.
fn walFramePage(iFrame: u32) c_int {
    const iHash = (iFrame + HASHTABLE_NPAGE - HASHTABLE_NPAGE_ONE - 1) / HASHTABLE_NPAGE;
    return @intCast(iHash);
}

/// Page number associated with frame iFrame in this WAL (from the mapping).
fn walFramePgno(pWal: *Wal, iFrame: u32) u32 {
    const iHash = walFramePage(iFrame);
    if (iHash == 0) {
        return pWal.apWiData.?[0].?[WALINDEX_HDR_SIZE / @sizeOf(u32) + iFrame - 1];
    }
    return pWal.apWiData.?[@intCast(iHash)].?[(iFrame - 1 - HASHTABLE_NPAGE_ONE) % HASHTABLE_NPAGE];
}

/// Remove hash entries pointing to frames greater than pWal->hdr.mxFrame.
fn walCleanupHash(pWal: *Wal) void {
    var sLoc: WalHashLoc = undefined;

    std.debug.assert(pWal.writeLock != 0);
    if (pWal.hdr.mxFrame == 0) return;

    std.debug.assert(pWal.nWiData > walFramePage(pWal.hdr.mxFrame));
    if (walHashGet(pWal, walFramePage(pWal.hdr.mxFrame), &sLoc) != SQLITE_OK) return;

    const iLimit: u32 = pWal.hdr.mxFrame - sLoc.iZero;
    std.debug.assert(iLimit > 0);

    var i: usize = 0;
    while (i < HASHTABLE_NSLOT) : (i += 1) {
        if (sLoc.aHash[i] > iLimit) sLoc.aHash[i] = 0;
    }

    // Zero aPgno entries for frames > mxFrame. nByte = (char*)aHash - &aPgno[iLimit]
    const aHashBytes: [*]volatile u8 = @ptrCast(sLoc.aHash);
    const aPgnoLimit: [*]volatile u8 = @ptrCast(sLoc.aPgno + iLimit);
    const nByte: usize = @intFromPtr(aHashBytes) - @intFromPtr(aPgnoLimit);
    _ = memset(@volatileCast(aPgnoLimit), 0, nByte);
}

/// Map database page iPage into WAL frame iFrame in the wal-index hash table.
fn walIndexAppend(pWal: *Wal, iFrame: u32, iPage: u32) c_int {
    var sLoc: WalHashLoc = undefined;
    const rc = walHashGet(pWal, walFramePage(iFrame), &sLoc);
    if (rc != SQLITE_OK) return rc;

    const idx: u32 = iFrame - sLoc.iZero;
    std.debug.assert(idx <= HASHTABLE_NSLOT / 2 + 1);

    // First entry into this hash-table: zero the whole hash table + aPgno[].
    if (idx == 1) {
        const aHashEnd: [*]volatile u8 = @ptrCast(sLoc.aHash + HASHTABLE_NSLOT);
        const aPgnoStart: [*]volatile u8 = @ptrCast(sLoc.aPgno);
        const nByte: usize = @intFromPtr(aHashEnd) - @intFromPtr(aPgnoStart);
        _ = memset(@volatileCast(aPgnoStart), 0, nByte);
    }

    // Remnants of an aborted writer's transaction? Clean it up.
    if (sLoc.aPgno[idx - 1] != 0) {
        walCleanupHash(pWal);
        std.debug.assert(sLoc.aPgno[idx - 1] == 0);
    }

    // Write aPgno[] then the hash-table slot.
    var nCollide: i64 = idx;
    var iKey = walHash(iPage);
    while (sLoc.aHash[iKey] != 0) {
        nCollide -= 1;
        if (nCollide < 0) return SQLITE_CORRUPT_BKPT();
        iKey = walNextHash(iKey);
    }
    sLoc.aPgno[(idx - 1) & (HASHTABLE_NPAGE - 1)] = iPage;
    atomicStoreHt(&sLoc.aHash[iKey], @truncate(idx));

    return rc;
}

// SQLITE_CORRUPT_BKPT / SQLITE_CANTOPEN_BKPT — in C these are
// sqlite3CorruptError(__LINE__) / sqlite3CantopenError(__LINE__) in BOTH configs
// (they are not SQLITE_DEBUG-gated like NOMEM). The helper logs and returns the
// base code. We only need the log in debug builds; otherwise return the bare
// constant (same observable result), matching the project's other ports.
inline fn SQLITE_CORRUPT_BKPT() c_int {
    return if (config.sqlite_debug) sqlite3CorruptError(0) else SQLITE_CORRUPT;
}
inline fn SQLITE_CANTOPEN_BKPT() c_int {
    return if (config.sqlite_debug) sqlite3CantopenError(0) else SQLITE_CANTOPEN;
}

// ───────────────────────── recovery ─────────────────────────────────────────

fn walIndexRecover(pWal: *Wal) c_int {
    var rc: c_int = SQLITE_OK;
    var nSize: i64 = undefined;
    var aFrameCksum = [2]u32{ 0, 0 };

    std.debug.assert(pWal.ckptLock == 1 or pWal.ckptLock == 0);
    std.debug.assert(pWal.writeLock != 0);
    const iLock: c_int = WAL_ALL_BUT_WRITE + @as(c_int, pWal.ckptLock);
    rc = walLockExclusive(pWal, iLock, WAL_READ_LOCK(0) - iLock);
    if (rc != 0) return rc;

    _ = memset(&pWal.hdr, 0, @sizeOf(WalIndexHdr));

    rc = sqlite3OsFileSize(pWal.pWalFd, &nSize);
    if (rc != SQLITE_OK) {
        walUnlockExclusive(pWal, iLock, WAL_READ_LOCK(0) - iLock);
        return rc;
    }

    if (nSize > WAL_HDRSIZE) {
        var aBuf: [@intCast(WAL_HDRSIZE)]u8 = undefined;

        rc = sqlite3OsRead(pWal.pWalFd, &aBuf, @intCast(WAL_HDRSIZE), 0);
        if (rc != SQLITE_OK) {
            walUnlockExclusive(pWal, iLock, WAL_READ_LOCK(0) - iLock);
            return rc;
        }

        const magic = sqlite3Get4byte(&aBuf);
        const szPage = sqlite3Get4byte(aBuf[8..]);
        if ((magic & 0xFFFFFFFE) != WAL_MAGIC or (szPage & (szPage -% 1)) != 0 or szPage > SQLITE_MAX_PAGE_SIZE or szPage < 512) {
            return finishRecovery(pWal, rc, &aFrameCksum, iLock);
        }
        pWal.hdr.bigEndCksum = @truncate(magic & 0x00000001);
        pWal.szPage = szPage;
        pWal.nCkpt = sqlite3Get4byte(aBuf[12..]);
        _ = memcpy(&pWal.hdr.aSalt, aBuf[16..], 8);

        // Verify the WAL header checksum.
        walChecksumBytes(pWal.hdr.bigEndCksum == SQLITE_BIGENDIAN, &aBuf, @intCast(WAL_HDRSIZE - 2 * 4), null, &pWal.hdr.aFrameCksum);
        if (pWal.hdr.aFrameCksum[0] != sqlite3Get4byte(aBuf[24..]) or pWal.hdr.aFrameCksum[1] != sqlite3Get4byte(aBuf[28..])) {
            return finishRecovery(pWal, rc, &aFrameCksum, iLock);
        }

        const version = sqlite3Get4byte(aBuf[4..]);
        if (version != WAL_MAX_VERSION) {
            rc = SQLITE_CANTOPEN_BKPT();
            return finishRecovery(pWal, rc, &aFrameCksum, iLock);
        }

        // Buffer for one frame plus a wal-index page (private hash scratch).
        const szFrame: usize = @as(usize, szPage) + @as(usize, @intCast(WAL_FRAME_HDRSIZE));
        const aFrameBuf: ?[*]u8 = @ptrCast(sqlite3_malloc64(szFrame + WALINDEX_PGSZ));
        if (aFrameBuf == null) {
            rc = SQLITE_NOMEM_BKPT;
            walUnlockExclusive(pWal, iLock, WAL_READ_LOCK(0) - iLock);
            return rc;
        }
        const aFrame = aFrameBuf.?;
        const aData = aFrame + @as(usize, @intCast(WAL_FRAME_HDRSIZE));
        const aPrivate: [*]volatile u32 = @ptrCast(@alignCast(aData + szPage));

        const iLastFrame: u32 = @intCast(@divTrunc(nSize - WAL_HDRSIZE, @as(i64, @intCast(szFrame))));
        var iPg: u32 = 0;
        while (iPg <= @as(u32, @intCast(walFramePage(iLastFrame)))) : (iPg += 1) {
            var aShareOpt: ?[*]volatile u32 = undefined;
            const iLast = minU32(iLastFrame, HASHTABLE_NPAGE_ONE + iPg * HASHTABLE_NPAGE);
            const iFirst: u32 = 1 + (if (iPg == 0) 0 else HASHTABLE_NPAGE_ONE + (iPg - 1) * HASHTABLE_NPAGE);
            rc = walIndexPage(pWal, @intCast(iPg), &aShareOpt);
            std.debug.assert(aShareOpt != null or rc != SQLITE_OK);
            const aShare = aShareOpt orelse break;
            pWal.apWiData.?[iPg] = aPrivate;

            var iFrame = iFirst;
            while (iFrame <= iLast) : (iFrame += 1) {
                const iOffset = walFrameOffset(iFrame, szPage);
                var pgno: u32 = undefined;
                var nTruncate: u32 = undefined;

                rc = sqlite3OsRead(pWal.pWalFd, aFrame, @intCast(szFrame), iOffset);
                if (rc != SQLITE_OK) break;
                if (!walDecodeFrame(pWal, &pgno, &nTruncate, aData, aFrame)) break;
                rc = walIndexAppend(pWal, iFrame, pgno);
                if (rc != SQLITE_OK) break;

                if (nTruncate != 0) {
                    pWal.hdr.mxFrame = iFrame;
                    pWal.hdr.nPage = nTruncate;
                    pWal.hdr.szPage = @truncate((szPage & 0xff00) | (szPage >> 16));
                    aFrameCksum[0] = pWal.hdr.aFrameCksum[0];
                    aFrameCksum[1] = pWal.hdr.aFrameCksum[1];
                }
            }
            pWal.apWiData.?[iPg] = aShare;
            const nHdr: usize = if (iPg == 0) WALINDEX_HDR_SIZE else 0;
            const nHdr32: usize = nHdr / @sizeOf(u32);
            // memcpy the rebuilt private page into the shared wal-index page.
            const dst: [*]volatile u32 = aShare + nHdr32;
            const src: [*]volatile u32 = aPrivate + nHdr32;
            _ = memcpy(@volatileCast(dst), @volatileCast(src), WALINDEX_PGSZ - nHdr);
            if (iFrame <= iLast) break;
        }

        sqlite3_free(aFrame);
    }

    return finishRecovery(pWal, rc, &aFrameCksum, iLock);
}

/// The `finished:`/`recovery_error:` tail of walIndexRecover.
fn finishRecovery(pWal: *Wal, rc_in: c_int, aFrameCksum: *const [2]u32, iLock: c_int) c_int {
    var rc = rc_in;
    if (rc == SQLITE_OK) {
        pWal.hdr.aFrameCksum[0] = aFrameCksum[0];
        pWal.hdr.aFrameCksum[1] = aFrameCksum[1];
        walIndexWriteHdr(pWal);

        const pInfo = walCkptInfo(pWal);
        pInfo.nBackfill = 0;
        pInfo.nBackfillAttempted = pWal.hdr.mxFrame;
        pInfo.aReadMark[0] = 0;
        var i: c_int = 1;
        while (i < WAL_NREADER) : (i += 1) {
            rc = walLockExclusive(pWal, WAL_READ_LOCK(i), 1);
            if (rc == SQLITE_OK) {
                if (i == 1 and pWal.hdr.mxFrame != 0) {
                    pInfo.aReadMark[@intCast(i)] = pWal.hdr.mxFrame;
                } else {
                    pInfo.aReadMark[@intCast(i)] = READMARK_NOT_USED;
                }
                walUnlockExclusive(pWal, WAL_READ_LOCK(i), 1);
            } else if (rc != SQLITE_BUSY) {
                walUnlockExclusive(pWal, iLock, WAL_READ_LOCK(0) - iLock);
                return rc;
            }
        }

        if (pWal.hdr.nPage != 0) {
            sqlite3_log(SQLITE_NOTICE_RECOVER_WAL, "recovered %d frames from WAL file %s", pWal.hdr.mxFrame, pWal.zWalName);
        }
    }
    walUnlockExclusive(pWal, iLock, WAL_READ_LOCK(0) - iLock);
    return rc;
}

// ───────────────────────── open / close ────────────────────────────────────

fn walIndexClose(pWal: *Wal, isDelete: c_int) void {
    if (pWal.exclusiveMode == WAL_HEAPMEMORY_MODE or pWal.bShmUnreliable != 0) {
        var i: usize = 0;
        while (i < @as(usize, @intCast(pWal.nWiData))) : (i += 1) {
            sqlite3_free(@ptrCast(@volatileCast(pWal.apWiData.?[i])));
            pWal.apWiData.?[i] = null;
        }
    }
    if (pWal.exclusiveMode != WAL_HEAPMEMORY_MODE) {
        _ = sqlite3OsShmUnmap(pWal.pDbFd, isDelete);
    }
}

export fn sqlite3WalOpen(
    pVfs: *Sqlite3Vfs,
    pDbFd: *Sqlite3File,
    zWalName: [*:0]const u8,
    bNoShm: c_int,
    mxWalSize: i64,
    ppWal: *?*Wal,
) callconv(.c) c_int {
    var rc: c_int = undefined;

    std.debug.assert(zWalName[0] != 0);

    ppWal.* = null;
    const szOsFile: usize = @intCast(vfsSzOsFile(pVfs));
    const pRet: ?*Wal = @ptrCast(@alignCast(sqlite3MallocZero(@sizeOf(Wal) + szOsFile)));
    if (pRet == null) return SQLITE_NOMEM_BKPT;
    const w = pRet.?;

    w.pVfs = pVfs;
    // pWalFd lives in the bytes immediately following the Wal object.
    const base: [*]u8 = @ptrCast(w);
    w.pWalFd = @ptrCast(@alignCast(base + @sizeOf(Wal)));
    w.pDbFd = pDbFd;
    w.readLock = -1;
    w.mxWalSize = mxWalSize;
    w.zWalName = zWalName;
    w.syncHeader = 1;
    w.padToSectorBoundary = 1;
    w.exclusiveMode = if (bNoShm != 0) WAL_HEAPMEMORY_MODE else WAL_NORMAL_MODE;

    var flags: c_int = (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_WAL);
    rc = sqlite3OsOpen(pVfs, zWalName, w.pWalFd, flags, &flags);
    if (rc == SQLITE_OK and (flags & SQLITE_OPEN_READONLY) != 0) {
        w.readOnly = WAL_RDONLY;
    }

    if (rc != SQLITE_OK) {
        walIndexClose(w, 0);
        sqlite3OsClose(w.pWalFd);
        sqlite3_free(w);
    } else {
        const iDC = sqlite3OsDeviceCharacteristics(pDbFd);
        if (iDC & SQLITE_IOCAP_SEQUENTIAL != 0) w.syncHeader = 0;
        if (iDC & SQLITE_IOCAP_POWERSAFE_OVERWRITE != 0) w.padToSectorBoundary = 0;
        ppWal.* = w;
    }
    return rc;
}

export fn sqlite3WalLimit(pWal: ?*Wal, iLimit: i64) callconv(.c) void {
    if (pWal) |w| w.mxWalSize = iLimit;
}

// ───────────────────────── iterator (checkpoint) ───────────────────────────

fn walIteratorNext(p: *WalIterator, piPage: *u32, piFrame: *u32) c_int {
    var iRet: u32 = 0xFFFFFFFF;
    const iMin = p.iPrior;
    std.debug.assert(iMin < 0xffffffff);

    const segs = p.seg();
    var i: c_int = p.nSegment - 1;
    while (i >= 0) : (i -= 1) {
        const pSegment = &segs[@intCast(i)];
        while (pSegment.iNext < pSegment.nEntry) {
            const iPg = pSegment.aPgno[pSegment.aIndex[@intCast(pSegment.iNext)]];
            if (iPg > iMin) {
                if (iPg < iRet) {
                    iRet = iPg;
                    piFrame.* = @as(u32, @intCast(pSegment.iZero)) + pSegment.aIndex[@intCast(pSegment.iNext)];
                }
                break;
            }
            pSegment.iNext += 1;
        }
    }

    p.iPrior = iRet;
    piPage.* = iRet;
    return @intFromBool(iRet == 0xFFFFFFFF);
}

/// Merge two sorted index lists. aContent[] is the page-number sort key.
fn walMerge(aContent: [*]const u32, aLeft: [*]ht_slot, nLeft: c_int, paRight: *[*]ht_slot, pnRight: *c_int, aTmp: [*]ht_slot) void {
    var iLeft: c_int = 0;
    var iRight: c_int = 0;
    var iOut: c_int = 0;
    const nRight = pnRight.*;
    const aRight = paRight.*;

    std.debug.assert(nLeft > 0 and nRight > 0);
    while (iRight < nRight or iLeft < nLeft) {
        var logpage: ht_slot = undefined;
        if (iLeft < nLeft and (iRight >= nRight or aContent[aLeft[@intCast(iLeft)]] < aContent[aRight[@intCast(iRight)]])) {
            logpage = aLeft[@intCast(iLeft)];
            iLeft += 1;
        } else {
            logpage = aRight[@intCast(iRight)];
            iRight += 1;
        }
        const dbpage = aContent[logpage];

        aTmp[@intCast(iOut)] = logpage;
        iOut += 1;
        if (iLeft < nLeft and aContent[aLeft[@intCast(iLeft)]] == dbpage) iLeft += 1;
    }

    paRight.* = aLeft;
    pnRight.* = iOut;
    _ = memcpy(aLeft, aTmp, @sizeOf(ht_slot) * @as(usize, @intCast(iOut)));
}

fn walMergesort(aContent: [*]const u32, aBuffer: [*]ht_slot, aList: [*]ht_slot, pnList: *c_int) void {
    const Sublist = struct {
        nList: c_int,
        aList: [*]ht_slot,
    };

    const nList = pnList.*;
    var nMerge: c_int = 0;
    var aMerge: [*]ht_slot = aList;
    var aSub: [13]Sublist = undefined;
    @memset(std.mem.asBytes(&aSub), 0);

    std.debug.assert(nList <= HASHTABLE_NPAGE and nList > 0);

    var iList: c_int = 0;
    while (iList < nList) : (iList += 1) {
        nMerge = 1;
        aMerge = aList + @as(usize, @intCast(iList));
        var iSub: usize = 0;
        while ((iList & (@as(c_int, 1) << @intCast(iSub))) != 0) : (iSub += 1) {
            const pp = &aSub[iSub];
            walMerge(aContent, pp.aList, pp.nList, &aMerge, &nMerge, aBuffer);
        }
        aSub[iSub].aList = aMerge;
        aSub[iSub].nList = nMerge;
    }

    var iSub: usize = blk: {
        // continue from iSub+1 — recompute the final iSub used above.
        var s: usize = 0;
        var il: c_int = 0;
        while (il < nList) : (il += 1) {
            s = 0;
            while ((il & (@as(c_int, 1) << @intCast(s))) != 0) : (s += 1) {}
        }
        break :blk s + 1;
    };
    while (iSub < aSub.len) : (iSub += 1) {
        if ((nList & (@as(c_int, 1) << @intCast(iSub))) != 0) {
            const pp = &aSub[iSub];
            walMerge(aContent, pp.aList, pp.nList, &aMerge, &nMerge, aBuffer);
        }
    }
    std.debug.assert(aMerge == aList);
    pnList.* = nMerge;
}

fn walIteratorFree(p: ?*WalIterator) void {
    sqlite3_free(p);
}

fn walIteratorInit(pWal: *Wal, nBackfill: u32, pp: *?*WalIterator) c_int {
    var rc: c_int = SQLITE_OK;

    std.debug.assert(pWal.ckptLock != 0 and pWal.hdr.mxFrame > 0);
    const iLast = pWal.hdr.mxFrame;

    const nSegment: c_int = walFramePage(iLast) + 1;
    // nByte = SZ_WALITERATOR(nSegment) + iLast*sizeof(ht_slot)
    const nByte: u64 = SZ_WALITERATOR(@intCast(nSegment)) + @as(u64, iLast) * @sizeOf(ht_slot);
    const extra: u64 = @sizeOf(ht_slot) * @as(u64, if (iLast > HASHTABLE_NPAGE) HASHTABLE_NPAGE else iLast);
    const pAlloc: ?*WalIterator = @ptrCast(@alignCast(sqlite3_malloc64(nByte + extra)));
    if (pAlloc == null) return SQLITE_NOMEM_BKPT;
    const p = pAlloc.?;
    _ = memset(p, 0, nByte);
    p.nSegment = nSegment;

    // aTmp is the scratch buffer at the end of the allocation.
    const pBytes: [*]u8 = @ptrCast(p);
    const aTmp: [*]ht_slot = @ptrCast(@alignCast(pBytes + nByte));
    // The per-segment sorted-index arrays live right after the aSegment[] array.
    const aIndexBase: [*]ht_slot = @ptrCast(@alignCast(&p.seg()[@intCast(nSegment)]));

    var i: c_int = walFramePage(nBackfill + 1);
    while (rc == SQLITE_OK and i < nSegment) : (i += 1) {
        var sLoc: WalHashLoc = undefined;
        rc = walHashGet(pWal, i, &sLoc);
        if (rc == SQLITE_OK) {
            var nEntry: c_int = undefined;
            if (i + 1 == nSegment) {
                nEntry = @intCast(iLast - sLoc.iZero);
            } else {
                // (u32*)aHash - (u32*)aPgno
                const aHashU: [*]volatile u32 = @ptrCast(@alignCast(sLoc.aHash));
                nEntry = @intCast((@intFromPtr(aHashU) - @intFromPtr(sLoc.aPgno)) / @sizeOf(u32));
            }
            const aIndex = aIndexBase + sLoc.iZero;
            sLoc.iZero += 1;

            var j: usize = 0;
            while (j < @as(usize, @intCast(nEntry))) : (j += 1) aIndex[j] = @truncate(j);
            walMergesort(@ptrCast(@volatileCast(sLoc.aPgno)), aTmp, aIndex, &nEntry);
            const segs = p.seg();
            segs[@intCast(i)].iZero = @intCast(sLoc.iZero);
            segs[@intCast(i)].nEntry = nEntry;
            segs[@intCast(i)].aIndex = aIndex;
            segs[@intCast(i)].aPgno = @ptrCast(@volatileCast(sLoc.aPgno));
        }
    }
    if (rc != SQLITE_OK) {
        walIteratorFree(p);
        pp.* = null;
        return rc;
    }
    pp.* = p;
    return rc;
}

// ───────────────────────── busy lock, pagesize ─────────────────────────────

fn walBusyLock(pWal: *Wal, xBusy: ?*const fn (?*anyopaque) callconv(.c) c_int, pBusyArg: ?*anyopaque, lockIdx: c_int, n: c_int) c_int {
    var rc: c_int = undefined;
    while (true) {
        rc = walLockExclusive(pWal, lockIdx, n);
        if (!(xBusy != null and rc == SQLITE_BUSY and xBusy.?(pBusyArg) != 0)) break;
    }
    return rc;
}

fn walPagesize(pWal: *Wal) c_int {
    return (@as(c_int, pWal.hdr.szPage) & 0xfe00) + ((@as(c_int, pWal.hdr.szPage) & 0x0001) << 16);
}

/// Reset the wal-index header for a fresh WAL (after a checkpoint+restart).
fn walRestartHdr(pWal: *Wal, salt1: u32) void {
    const pInfo = walCkptInfo(pWal);
    const aSalt: [*]u8 = @ptrCast(&pWal.hdr.aSalt);
    pWal.nCkpt += 1;
    pWal.hdr.mxFrame = 0;
    sqlite3Put4byte(aSalt, 1 +% sqlite3Get4byte(aSalt));
    _ = memcpy(&pWal.hdr.aSalt[1], &salt1, 4);
    walIndexWriteHdr(pWal);
    atomicStoreU32(&pInfo.nBackfill, 0);
    pInfo.nBackfillAttempted = 0;
    pInfo.aReadMark[1] = 0;
    var i: usize = 2;
    while (i < WAL_NREADER) : (i += 1) pInfo.aReadMark[i] = READMARK_NOT_USED;
    std.debug.assert(pInfo.aReadMark[0] == 0);
}

// ───────────────────────── checkpoint core ─────────────────────────────────

fn walCheckpoint(
    pWal: *Wal,
    db: *Sqlite3,
    eMode_in: c_int,
    xBusy_in: ?*const fn (?*anyopaque) callconv(.c) c_int,
    pBusyArg: ?*anyopaque,
    sync_flags: c_int,
    zBuf: [*]u8,
) c_int {
    var rc: c_int = SQLITE_OK;
    var pIter: ?*WalIterator = null;
    var iDbpage: u32 = 0;
    var iFrame: u32 = 0;
    const eMode = eMode_in;
    var xBusy = xBusy_in;

    const szPage = walPagesize(pWal);
    const pInfo = walCkptInfo(pWal);

    if (pInfo.nBackfill < pWal.hdr.mxFrame) {
        std.debug.assert(eMode != SQLITE_CHECKPOINT_PASSIVE or xBusy == null);

        var mxSafeFrame = pWal.hdr.mxFrame;
        const mxPage = pWal.hdr.nPage;
        var i: c_int = 1;
        while (i < WAL_NREADER) : (i += 1) {
            const y = atomicLoadU32(&pInfo.aReadMark[@intCast(i)]);
            if (mxSafeFrame > y) {
                std.debug.assert(y <= pWal.hdr.mxFrame);
                rc = walBusyLock(pWal, xBusy, pBusyArg, WAL_READ_LOCK(i), 1);
                if (rc == SQLITE_OK) {
                    const iMark: u32 = if (i == 1) mxSafeFrame else READMARK_NOT_USED;
                    atomicStoreU32(&pInfo.aReadMark[@intCast(i)], iMark);
                    walUnlockExclusive(pWal, WAL_READ_LOCK(i), 1);
                } else if (rc == SQLITE_BUSY) {
                    mxSafeFrame = y;
                    xBusy = null;
                } else {
                    walIteratorFree(pIter);
                    return rc;
                }
            }
        }

        if (pInfo.nBackfill < mxSafeFrame) {
            rc = walIteratorInit(pWal, pInfo.nBackfill, &pIter);
        }

        if (pIter != null and blk: {
            rc = walBusyLock(pWal, xBusy, pBusyArg, WAL_READ_LOCK(0), 1);
            break :blk rc == SQLITE_OK;
        }) {
            const nBackfill = pInfo.nBackfill;
            const pLive = walIndexHdr(pWal);

            const bChg = memcmp(@volatileCast(&pLive[0].aSalt), &pWal.hdr.aSalt, @sizeOf(@TypeOf(pWal.hdr.aSalt)));
            if (bChg == 0) {
                pInfo.nBackfillAttempted = mxSafeFrame;

                rc = sqlite3OsSync(pWal.pWalFd, CKPT_SYNC_FLAGS(sync_flags));

                if (rc == SQLITE_OK) {
                    const nReq: i64 = @as(i64, mxPage) * szPage;
                    var nSize: i64 = undefined;
                    _ = sqlite3OsFileControl(pWal.pDbFd, SQLITE_FCNTL_CKPT_START, null);
                    rc = sqlite3OsFileSize(pWal.pDbFd, &nSize);
                    if (rc == SQLITE_OK and nSize < nReq) {
                        if ((nSize + 65536 + @as(i64, pWal.hdr.mxFrame) * szPage) < nReq) {
                            rc = SQLITE_CORRUPT_BKPT();
                        } else {
                            var nReqHint = nReq;
                            sqlite3OsFileControlHint(pWal.pDbFd, SQLITE_FCNTL_SIZE_HINT, &nReqHint);
                        }
                    }
                }

                while (rc == SQLITE_OK and 0 == walIteratorNext(pIter.?, &iDbpage, &iFrame)) {
                    var iOffset: i64 = undefined;
                    std.debug.assert(walFramePgno(pWal, iFrame) == iDbpage);
                    if (dbIsInterrupted(db)) {
                        rc = if (dbMallocFailed(db)) SQLITE_NOMEM_BKPT else SQLITE_INTERRUPT;
                        break;
                    }
                    if (iFrame <= nBackfill or iFrame > mxSafeFrame or iDbpage > mxPage) {
                        continue;
                    }
                    iOffset = walFrameOffset(iFrame, @intCast(szPage)) + WAL_FRAME_HDRSIZE;
                    rc = sqlite3OsRead(pWal.pWalFd, zBuf, szPage, iOffset);
                    if (rc != SQLITE_OK) break;
                    iOffset = (@as(i64, iDbpage) - 1) * szPage;
                    rc = sqlite3OsWrite(pWal.pDbFd, zBuf, szPage, iOffset);
                    if (rc != SQLITE_OK) break;
                }
                _ = sqlite3OsFileControl(pWal.pDbFd, SQLITE_FCNTL_CKPT_DONE, null);

                if (rc == SQLITE_OK) {
                    if (mxSafeFrame == walIndexHdr(pWal)[0].mxFrame) {
                        const szDb: i64 = @as(i64, pWal.hdr.nPage) * szPage;
                        rc = sqlite3OsTruncate(pWal.pDbFd, szDb);
                        if (rc == SQLITE_OK) {
                            rc = sqlite3OsSync(pWal.pDbFd, CKPT_SYNC_FLAGS(sync_flags));
                        }
                    }
                    if (rc == SQLITE_OK) {
                        atomicStoreU32(&pInfo.nBackfill, mxSafeFrame);
                    }
                }
            }

            walUnlockExclusive(pWal, WAL_READ_LOCK(0), 1);
        }

        if (rc == SQLITE_BUSY) rc = SQLITE_OK;
    }

    if (rc == SQLITE_OK and eMode != SQLITE_CHECKPOINT_PASSIVE) {
        std.debug.assert(pWal.writeLock != 0);
        if (pInfo.nBackfill < pWal.hdr.mxFrame) {
            rc = SQLITE_BUSY;
        } else if (eMode >= SQLITE_CHECKPOINT_RESTART) {
            var salt1: u32 = undefined;
            sqlite3_randomness(4, &salt1);
            std.debug.assert(pInfo.nBackfill == pWal.hdr.mxFrame);
            rc = walBusyLock(pWal, xBusy, pBusyArg, WAL_READ_LOCK(1), WAL_NREADER - 1);
            if (rc == SQLITE_OK) {
                if (eMode == SQLITE_CHECKPOINT_TRUNCATE) {
                    walRestartHdr(pWal, salt1);
                    rc = sqlite3OsTruncate(pWal.pWalFd, 0);
                }
                walUnlockExclusive(pWal, WAL_READ_LOCK(1), WAL_NREADER - 1);
            }
        }
    }

    walIteratorFree(pIter);
    return rc;
}

/// Truncate the WAL file to nMax bytes if currently larger. Errors ignored.
fn walLimitSize(pWal: *Wal, nMax: i64) void {
    var sz: i64 = undefined;
    sqlite3BeginBenignMalloc();
    var rx = sqlite3OsFileSize(pWal.pWalFd, &sz);
    if (rx == SQLITE_OK and sz > nMax) {
        rx = sqlite3OsTruncate(pWal.pWalFd, nMax);
    }
    sqlite3EndBenignMalloc();
    if (rx != 0) {
        sqlite3_log(rx, "cannot limit WAL size: %s", pWal.zWalName);
    }
}

// ───────────────────────── close ───────────────────────────────────────────

export fn sqlite3WalClose(pWal: ?*Wal, db: ?*Sqlite3, sync_flags: c_int, nBuf: c_int, zBuf: ?[*]u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const w = pWal orelse return SQLITE_OK;
    var isDelete: c_int = 0;

    if (zBuf != null and SQLITE_OK == blk: {
        rc = sqlite3OsLock(w.pDbFd, SQLITE_LOCK_EXCLUSIVE);
        break :blk rc;
    }) {
        if (w.exclusiveMode == WAL_NORMAL_MODE) {
            w.exclusiveMode = WAL_EXCLUSIVE_MODE;
        }
        rc = sqlite3WalCheckpoint(w, db, SQLITE_CHECKPOINT_PASSIVE, null, null, sync_flags, nBuf, zBuf, null, null);
        if (rc == SQLITE_OK) {
            var bPersist: c_int = -1;
            sqlite3OsFileControlHint(w.pDbFd, SQLITE_FCNTL_PERSIST_WAL, &bPersist);
            if (bPersist != 1) {
                isDelete = 1;
            } else if (w.mxWalSize >= 0) {
                walLimitSize(w, 0);
            }
        }
    }

    walIndexClose(w, isDelete);
    sqlite3OsClose(w.pWalFd);
    if (isDelete != 0) {
        sqlite3BeginBenignMalloc();
        _ = sqlite3OsDelete(w.pVfs, w.zWalName, 0);
        sqlite3EndBenignMalloc();
    }
    sqlite3_free(@ptrCast(w.apWiData));
    sqlite3_free(w);
    return rc;
}

// ───────────────────────── wal-index header read ───────────────────────────

fn walIndexTryHdr(pWal: *Wal, pChanged: *c_int) c_int {
    var aCksum: [2]u32 = undefined;
    var h1: WalIndexHdr = undefined;
    var h2: WalIndexHdr = undefined;
    const aHdr = walIndexHdr(pWal);

    copyHdrFrom(&h1, &aHdr[0]);
    walShmBarrier(pWal);
    copyHdrFrom(&h2, &aHdr[1]);

    if (memcmp(&h1, &h2, @sizeOf(WalIndexHdr)) != 0) return 1; // dirty read
    if (h1.isInit == 0) return 1; // malformed
    walChecksumBytes(true, std.mem.asBytes(&h1), @sizeOf(WalIndexHdr) - @sizeOf(@TypeOf(h1.aCksum)), null, &aCksum);
    if (aCksum[0] != h1.aCksum[0] or aCksum[1] != h1.aCksum[1]) return 1; // checksum mismatch

    if (memcmp(&pWal.hdr, &h1, @sizeOf(WalIndexHdr)) != 0) {
        pChanged.* = 1;
        _ = memcpy(&pWal.hdr, &h1, @sizeOf(WalIndexHdr));
        pWal.szPage = (@as(u32, pWal.hdr.szPage) & 0xfe00) + ((@as(u32, pWal.hdr.szPage) & 0x0001) << 16);
    }
    return 0;
}

fn walIndexReadHdr(pWal: *Wal, pChanged: *c_int) c_int {
    var rc: c_int = undefined;
    var page0: ?[*]volatile u32 = undefined;

    rc = walIndexPage(pWal, 0, &page0);
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_READONLY_CANTINIT) {
            pWal.bShmUnreliable = 1;
            pWal.exclusiveMode = WAL_HEAPMEMORY_MODE;
            pChanged.* = 1;
        } else {
            return rc;
        }
    }

    var badHdr: c_int = if (page0 != null) walIndexTryHdr(pWal, pChanged) else 1;

    if (badHdr != 0) {
        if (pWal.bShmUnreliable == 0 and (pWal.readOnly & WAL_SHM_RDONLY) != 0) {
            if (SQLITE_OK == blk: {
                rc = walLockShared(pWal, WAL_WRITE_LOCK);
                break :blk rc;
            }) {
                walUnlockShared(pWal, WAL_WRITE_LOCK);
                rc = SQLITE_READONLY_RECOVERY;
            }
        } else {
            const bWriteLock = pWal.writeLock;
            if (bWriteLock != 0 or SQLITE_OK == blk: {
                rc = walLockExclusive(pWal, WAL_WRITE_LOCK, 1);
                break :blk rc;
            }) {
                if (bWriteLock == 0) pWal.writeLock = 2;
                if (SQLITE_OK == blk: {
                    rc = walIndexPage(pWal, 0, &page0);
                    break :blk rc;
                }) {
                    badHdr = walIndexTryHdr(pWal, pChanged);
                    if (badHdr != 0) {
                        rc = walIndexRecover(pWal);
                        pChanged.* = 1;
                    }
                }
                if (bWriteLock == 0) {
                    pWal.writeLock = 0;
                    walUnlockExclusive(pWal, WAL_WRITE_LOCK, 1);
                }
            }
        }
    }

    if (badHdr == 0 and pWal.hdr.iVersion != WALINDEX_MAX_VERSION) {
        rc = SQLITE_CANTOPEN_BKPT();
    }
    if (pWal.bShmUnreliable != 0) {
        if (rc != SQLITE_OK) {
            walIndexClose(pWal, 0);
            pWal.bShmUnreliable = 0;
            if (rc == SQLITE_IOERR_SHORT_READ) rc = WAL_RETRY;
        }
        pWal.exclusiveMode = WAL_NORMAL_MODE;
    }

    return rc;
}

// ───────────────────────── read transaction (unreliable shm) ───────────────

fn walBeginShmUnreliable(pWal: *Wal, pChanged: *c_int) c_int {
    var szWal: i64 = undefined;
    var aBuf: [@intCast(WAL_HDRSIZE)]u8 = undefined;
    var rc: c_int = undefined;

    rc = walLockShared(pWal, WAL_READ_LOCK(0));
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_BUSY) rc = WAL_RETRY;
        return endUnreliable(pWal, rc, null, pChanged);
    }
    pWal.readLock = 0;

    var pDummy: ?*anyopaque = undefined;
    rc = sqlite3OsShmMap(pWal.pDbFd, 0, @intCast(WALINDEX_PGSZ), 0, @ptrCast(&pDummy));
    std.debug.assert(rc != SQLITE_OK);
    if (rc != SQLITE_READONLY_CANTINIT) {
        rc = if (rc == SQLITE_READONLY) WAL_RETRY else rc;
        return endUnreliable(pWal, rc, null, pChanged);
    }

    copyHdrFrom(&pWal.hdr, &walIndexHdr(pWal)[0]);

    rc = sqlite3OsFileSize(pWal.pWalFd, &szWal);
    if (rc != SQLITE_OK) return endUnreliable(pWal, rc, null, pChanged);
    if (szWal < WAL_HDRSIZE) {
        pChanged.* = 1;
        rc = if (pWal.hdr.mxFrame == 0) SQLITE_OK else WAL_RETRY;
        return endUnreliable(pWal, rc, null, pChanged);
    }

    rc = sqlite3OsRead(pWal.pWalFd, &aBuf, @intCast(WAL_HDRSIZE), 0);
    if (rc != SQLITE_OK) return endUnreliable(pWal, rc, null, pChanged);
    if (memcmp(&pWal.hdr.aSalt, aBuf[16..], 8) != 0) {
        return endUnreliable(pWal, WAL_RETRY, null, pChanged);
    }

    const szFrame: usize = @as(usize, pWal.szPage) + @as(usize, @intCast(WAL_FRAME_HDRSIZE));
    const aFrameOpt: ?[*]u8 = @ptrCast(sqlite3_malloc64(szFrame));
    if (aFrameOpt == null) return endUnreliable(pWal, SQLITE_NOMEM_BKPT, null, pChanged);
    const aFrame = aFrameOpt.?;
    const aData = aFrame + @as(usize, @intCast(WAL_FRAME_HDRSIZE));

    const aSaveCksum = pWal.hdr.aFrameCksum;
    var iOffset = walFrameOffset(pWal.hdr.mxFrame + 1, pWal.szPage);
    while (iOffset + @as(i64, @intCast(szFrame)) <= szWal) : (iOffset += @intCast(szFrame)) {
        var pgno: u32 = undefined;
        var nTruncate: u32 = undefined;
        rc = sqlite3OsRead(pWal.pWalFd, aFrame, @intCast(szFrame), iOffset);
        if (rc != SQLITE_OK) break;
        if (!walDecodeFrame(pWal, &pgno, &nTruncate, aData, aFrame)) break;
        if (nTruncate != 0) {
            rc = WAL_RETRY;
            break;
        }
    }
    pWal.hdr.aFrameCksum = aSaveCksum;

    return endUnreliable(pWal, rc, aFrame, pChanged);
}

fn endUnreliable(pWal: *Wal, rc: c_int, aFrame: ?[*]u8, pChanged: *c_int) c_int {
    sqlite3_free(aFrame);
    if (rc != SQLITE_OK) {
        var i: usize = 0;
        while (i < @as(usize, @intCast(pWal.nWiData))) : (i += 1) {
            sqlite3_free(@ptrCast(@volatileCast(pWal.apWiData.?[i])));
            pWal.apWiData.?[i] = null;
        }
        pWal.bShmUnreliable = 0;
        sqlite3WalEndReadTransaction(pWal);
        pChanged.* = 1;
    }
    return rc;
}

// ───────────────────────── read transaction ────────────────────────────────

fn walTryBeginRead(pWal: *Wal, pChanged: *c_int, useWal: c_int, pCnt: *c_int) c_int {
    var rc: c_int = SQLITE_OK;

    std.debug.assert(pWal.readLock < 0);

    pCnt.* += 1;
    if (pCnt.* > 5) {
        var nDelay: c_int = 1;
        const cnt = pCnt.* & ~WAL_RETRY_BLOCKED_MASK;
        if (cnt > WAL_RETRY_PROTOCOL_LIMIT) {
            if (config.sqlite_debug) pWal.lockError = 1;
            return SQLITE_PROTOCOL;
        }
        if (pCnt.* >= 10) nDelay = (cnt - 9) * (cnt - 9) * 39;
        _ = sqlite3OsSleep(pWal.pVfs, nDelay);
        pCnt.* &= ~WAL_RETRY_BLOCKED_MASK;
    }

    if (useWal == 0) {
        if (pWal.bShmUnreliable == 0) {
            rc = walIndexReadHdr(pWal, pChanged);
        }
        if (rc == SQLITE_BUSY) {
            if (pWal.apWiData.?[0] == null) {
                rc = WAL_RETRY;
            } else if (SQLITE_OK == blk: {
                rc = walLockShared(pWal, WAL_RECOVER_LOCK);
                break :blk rc;
            }) {
                walUnlockShared(pWal, WAL_RECOVER_LOCK);
                rc = WAL_RETRY;
            } else if (rc == SQLITE_BUSY) {
                rc = SQLITE_BUSY_RECOVERY;
            }
        }
        if (rc != SQLITE_OK) {
            return rc;
        } else if (pWal.bShmUnreliable != 0) {
            return walBeginShmUnreliable(pWal, pChanged);
        }
    }

    const pInfo = walCkptInfo(pWal);
    {
        var mxReadMark: u32 = 0;
        var mxI: c_int = 0;
        var i: c_int = undefined;
        const mxFrame: u32 = pWal.hdr.mxFrame;

        if (useWal == 0 and atomicLoadU32(&pInfo.nBackfill) == pWal.hdr.mxFrame) {
            rc = walLockShared(pWal, WAL_READ_LOCK(0));
            walShmBarrier(pWal);
            if (rc == SQLITE_OK) {
                if (memcmp(@volatileCast(&walIndexHdr(pWal)[0]), &pWal.hdr, @sizeOf(WalIndexHdr)) != 0) {
                    walUnlockShared(pWal, WAL_READ_LOCK(0));
                    return WAL_RETRY;
                }
                pWal.readLock = 0;
                return SQLITE_OK;
            } else if (rc != SQLITE_BUSY) {
                return rc;
            }
        }

        i = 1;
        while (i < WAL_NREADER) : (i += 1) {
            const thisMark = atomicLoadU32(&pInfo.aReadMark[@intCast(i)]);
            if (mxReadMark <= thisMark and thisMark <= mxFrame) {
                std.debug.assert(thisMark != READMARK_NOT_USED);
                mxReadMark = thisMark;
                mxI = i;
            }
        }
        if ((pWal.readOnly & WAL_SHM_RDONLY) == 0 and (mxReadMark < mxFrame or mxI == 0)) {
            i = 1;
            while (i < WAL_NREADER) : (i += 1) {
                rc = walLockExclusive(pWal, WAL_READ_LOCK(i), 1);
                if (rc == SQLITE_OK) {
                    atomicStoreU32(&pInfo.aReadMark[@intCast(i)], mxFrame);
                    mxReadMark = mxFrame;
                    mxI = i;
                    walUnlockExclusive(pWal, WAL_READ_LOCK(i), 1);
                    break;
                } else if (rc != SQLITE_BUSY) {
                    return rc;
                }
            }
        }
        if (mxI == 0) {
            std.debug.assert(rc == SQLITE_BUSY or (pWal.readOnly & WAL_SHM_RDONLY) != 0);
            return if (rc == SQLITE_BUSY) WAL_RETRY else SQLITE_READONLY_CANTINIT;
        }

        rc = walLockShared(pWal, WAL_READ_LOCK(mxI));
        if (rc != 0) {
            return if ((rc & 0xFF) == SQLITE_BUSY) WAL_RETRY else rc;
        }
        pWal.minFrame = atomicLoadU32(&pInfo.nBackfill) + 1;
        walShmBarrier(pWal);
        if (atomicLoadU32(&pInfo.aReadMark[@intCast(mxI)]) != mxReadMark or
            memcmp(@volatileCast(&walIndexHdr(pWal)[0]), &pWal.hdr, @sizeOf(WalIndexHdr)) != 0)
        {
            walUnlockShared(pWal, WAL_READ_LOCK(mxI));
            return WAL_RETRY;
        } else {
            std.debug.assert(mxReadMark <= pWal.hdr.mxFrame);
            pWal.readLock = @intCast(mxI);
        }
    }
    return rc;
}

fn walBeginReadTransaction(pWal: *Wal, pChanged: *c_int) c_int {
    var rc: c_int = undefined;
    var cnt: c_int = 0;
    while (true) {
        rc = walTryBeginRead(pWal, pChanged, 0, &cnt);
        if (rc != WAL_RETRY) break;
    }
    return rc;
}

export fn sqlite3WalBeginReadTransaction(pWal: ?*Wal, pChanged: *c_int) callconv(.c) c_int {
    return walBeginReadTransaction(pWal.?, pChanged);
}

export fn sqlite3WalEndReadTransaction(pWal: ?*Wal) callconv(.c) void {
    const w = pWal.?;
    std.debug.assert(w.writeLock == 0 or w.readLock < 0);
    if (w.readLock >= 0) {
        _ = sqlite3WalEndWriteTransaction(w);
        walUnlockShared(w, WAL_READ_LOCK(w.readLock));
        w.readLock = -1;
    }
}

// ───────────────────────── find / read frame ───────────────────────────────

fn walFindFrame(pWal: *Wal, pgno: Pgno, piRead: *u32) c_int {
    var iRead: u32 = 0;
    const iLast: u32 = pWal.hdr.mxFrame;

    std.debug.assert(pWal.readLock >= 0 or (config.sqlite_debug and pWal.lockError != 0));

    if (iLast == 0 or (pWal.readLock == 0 and pWal.bShmUnreliable == 0)) {
        piRead.* = 0;
        return SQLITE_OK;
    }

    const iMinHash = walFramePage(pWal.minFrame);
    var iHash: c_int = walFramePage(iLast);
    while (iHash >= iMinHash) : (iHash -= 1) {
        var sLoc: WalHashLoc = undefined;
        const rc = walHashGet(pWal, iHash, &sLoc);
        if (rc != SQLITE_OK) return rc;
        var nCollide: i64 = HASHTABLE_NSLOT;
        var iKey = walHash(pgno);
        var iH = atomicLoadHt(&sLoc.aHash[iKey]);
        while (iH != 0) {
            const iFrame: u32 = @as(u32, iH) + sLoc.iZero;
            if (iFrame <= iLast and iFrame >= pWal.minFrame and sLoc.aPgno[(iH - 1) & (HASHTABLE_NPAGE - 1)] == pgno) {
                iRead = iFrame;
            }
            nCollide -= 1;
            if (nCollide < 0) {
                piRead.* = 0;
                return SQLITE_CORRUPT_BKPT();
            }
            iKey = walNextHash(iKey);
            iH = atomicLoadHt(&sLoc.aHash[iKey]);
        }
        if (iRead != 0) break;
    }

    piRead.* = iRead;
    return SQLITE_OK;
}

export fn sqlite3WalFindFrame(pWal: ?*Wal, pgno: Pgno, piRead: *u32) callconv(.c) c_int {
    return walFindFrame(pWal.?, pgno, piRead);
}

export fn sqlite3WalReadFrame(pWal: ?*Wal, iRead: u32, nOut: c_int, pOut: ?*anyopaque) callconv(.c) c_int {
    const w = pWal.?;
    var sz: i64 = w.hdr.szPage;
    sz = (sz & 0xfe00) + ((sz & 0x0001) << 16);
    const iOffset = walFrameOffset(iRead, @intCast(sz)) + WAL_FRAME_HDRSIZE;
    return sqlite3OsRead(w.pWalFd, pOut, if (@as(i64, nOut) > sz) @intCast(sz) else nOut, iOffset);
}

export fn sqlite3WalDbsize(pWal: ?*Wal) callconv(.c) Pgno {
    if (pWal) |w| {
        if (w.readLock >= 0) return w.hdr.nPage;
    }
    return 0;
}

// ───────────────────────── write transaction ───────────────────────────────

export fn sqlite3WalBeginWriteTransaction(pWal: ?*Wal) callconv(.c) c_int {
    const w = pWal.?;
    std.debug.assert(w.readLock >= 0);
    std.debug.assert(w.writeLock == 0 and w.iReCksum == 0);

    if (w.readOnly != 0) return SQLITE_READONLY;

    var rc = walLockExclusive(w, WAL_WRITE_LOCK, 1);
    if (rc != 0) return rc;
    w.writeLock = 1;

    if (memcmp(&w.hdr, @volatileCast(&walIndexHdr(w)[0]), @sizeOf(WalIndexHdr)) != 0) {
        rc = SQLITE_BUSY_SNAPSHOT;
    }

    if (rc != SQLITE_OK) {
        walUnlockExclusive(w, WAL_WRITE_LOCK, 1);
        w.writeLock = 0;
    }
    return rc;
}

export fn sqlite3WalEndWriteTransaction(pWal: ?*Wal) callconv(.c) c_int {
    const w = pWal.?;
    if (w.writeLock != 0) {
        walUnlockExclusive(w, WAL_WRITE_LOCK, 1);
        w.writeLock = 0;
        w.iReCksum = 0;
        w.truncateOnCommit = 0;
    }
    return SQLITE_OK;
}

export fn sqlite3WalUndo(pWal: ?*Wal, xUndo: ?*const fn (?*anyopaque, Pgno) callconv(.c) c_int, pUndoCtx: ?*anyopaque) callconv(.c) c_int {
    const w = pWal.?;
    var rc: c_int = SQLITE_OK;
    if (w.writeLock != 0) {
        const iMax: Pgno = w.hdr.mxFrame;

        copyHdrFrom(&w.hdr, &walIndexHdr(w)[0]);

        var iFrame: Pgno = w.hdr.mxFrame + 1;
        while (rc == SQLITE_OK and iFrame <= iMax) : (iFrame += 1) {
            std.debug.assert(walFramePgno(w, iFrame) != 1);
            rc = xUndo.?(pUndoCtx, walFramePgno(w, iFrame));
        }
        if (iMax != w.hdr.mxFrame) walCleanupHash(w);
        w.iReCksum = 0;
    }
    return rc;
}

export fn sqlite3WalSavepoint(pWal: ?*Wal, aWalData: [*]u32) callconv(.c) void {
    const w = pWal.?;
    std.debug.assert(w.writeLock != 0);
    aWalData[0] = w.hdr.mxFrame;
    aWalData[1] = w.hdr.aFrameCksum[0];
    aWalData[2] = w.hdr.aFrameCksum[1];
    aWalData[3] = w.nCkpt;
}

export fn sqlite3WalSavepointUndo(pWal: ?*Wal, aWalData: [*]u32) callconv(.c) c_int {
    const w = pWal.?;
    const rc: c_int = SQLITE_OK;
    std.debug.assert(w.writeLock != 0);

    if (aWalData[3] != w.nCkpt) {
        aWalData[0] = 0;
        aWalData[3] = w.nCkpt;
    }

    if (aWalData[0] < w.hdr.mxFrame) {
        w.hdr.mxFrame = aWalData[0];
        w.hdr.aFrameCksum[0] = aWalData[1];
        w.hdr.aFrameCksum[1] = aWalData[2];
        walCleanupHash(w);
        if (w.iReCksum > w.hdr.mxFrame) w.iReCksum = 0;
    }

    return rc;
}

// ───────────────────────── frame writing ───────────────────────────────────

fn walRestartLog(pWal: *Wal) c_int {
    var rc: c_int = SQLITE_OK;

    if (pWal.readLock == 0) {
        const pInfo = walCkptInfo(pWal);
        std.debug.assert(pInfo.nBackfill == pWal.hdr.mxFrame);
        if (pInfo.nBackfill > 0) {
            var salt1: u32 = undefined;
            sqlite3_randomness(4, &salt1);
            rc = walLockExclusive(pWal, WAL_READ_LOCK(1), WAL_NREADER - 1);
            if (rc == SQLITE_OK) {
                walRestartHdr(pWal, salt1);
                walUnlockExclusive(pWal, WAL_READ_LOCK(1), WAL_NREADER - 1);
            } else if (rc != SQLITE_BUSY) {
                return rc;
            }
        }
        walUnlockShared(pWal, WAL_READ_LOCK(0));
        pWal.readLock = -1;
        var cnt: c_int = 0;
        while (true) {
            var notUsed: c_int = undefined;
            rc = walTryBeginRead(pWal, &notUsed, 1, &cnt);
            if (rc != WAL_RETRY) break;
        }
    }
    return rc;
}

const WalWriter = struct {
    pWal: *Wal,
    pFd: *Sqlite3File,
    iSyncPoint: i64,
    syncFlags: c_int,
    szPage: c_int,
};

fn walWriteToLog(p: *WalWriter, pContent_in: [*]u8, iAmt_in: c_int, iOffset_in: i64) c_int {
    var rc: c_int = undefined;
    var pContent = pContent_in;
    var iAmt = iAmt_in;
    var iOffset = iOffset_in;
    if (iOffset < p.iSyncPoint and iOffset + iAmt >= p.iSyncPoint) {
        const iFirstAmt: c_int = @intCast(p.iSyncPoint - iOffset);
        rc = sqlite3OsWrite(p.pFd, pContent, iFirstAmt, iOffset);
        if (rc != 0) return rc;
        iOffset += iFirstAmt;
        iAmt -= iFirstAmt;
        pContent += @intCast(iFirstAmt);
        rc = sqlite3OsSync(p.pFd, WAL_SYNC_FLAGS(p.syncFlags));
        if (iAmt == 0 or rc != 0) return rc;
    }
    return sqlite3OsWrite(p.pFd, pContent, iAmt, iOffset);
}

fn walWriteOneFrame(p: *WalWriter, pPage: *PgHdr, nTruncate: c_int, iOffset: i64) c_int {
    var aFrame: [@intCast(WAL_FRAME_HDRSIZE)]u8 = undefined;
    const pData: [*]u8 = @ptrCast(pPage.pData.?);
    walEncodeFrame(p.pWal, pPage.pgno, @intCast(nTruncate), pData, &aFrame);
    var rc = walWriteToLog(p, &aFrame, aFrame.len, iOffset);
    if (rc != 0) return rc;
    rc = walWriteToLog(p, pData, p.szPage, iOffset + aFrame.len);
    return rc;
}

fn walRewriteChecksums(pWal: *Wal, iLast: u32) c_int {
    const szPage: c_int = @intCast(pWal.szPage);
    var rc: c_int = SQLITE_OK;
    var aFrame: [@intCast(WAL_FRAME_HDRSIZE)]u8 = undefined;
    var iCksumOff: i64 = undefined;

    const aBufOpt: ?[*]u8 = @ptrCast(sqlite3_malloc(szPage + @as(c_int, @intCast(WAL_FRAME_HDRSIZE))));
    if (aBufOpt == null) return SQLITE_NOMEM_BKPT;
    const aBuf = aBufOpt.?;

    std.debug.assert(pWal.iReCksum > 0);
    if (pWal.iReCksum == 1) {
        iCksumOff = 24;
    } else {
        iCksumOff = walFrameOffset(pWal.iReCksum - 1, @intCast(szPage)) + 16;
    }
    rc = sqlite3OsRead(pWal.pWalFd, aBuf, @sizeOf(u32) * 2, iCksumOff);
    pWal.hdr.aFrameCksum[0] = sqlite3Get4byte(aBuf);
    pWal.hdr.aFrameCksum[1] = sqlite3Get4byte(aBuf + @sizeOf(u32));

    var iRead = pWal.iReCksum;
    pWal.iReCksum = 0;
    while (rc == SQLITE_OK and iRead <= iLast) : (iRead += 1) {
        const iOff = walFrameOffset(iRead, @intCast(szPage));
        rc = sqlite3OsRead(pWal.pWalFd, aBuf, szPage + @as(c_int, @intCast(WAL_FRAME_HDRSIZE)), iOff);
        if (rc == SQLITE_OK) {
            const iPgno = sqlite3Get4byte(aBuf);
            const nDbSize = sqlite3Get4byte(aBuf + 4);
            walEncodeFrame(pWal, iPgno, nDbSize, aBuf + @as(usize, @intCast(WAL_FRAME_HDRSIZE)), &aFrame);
            rc = sqlite3OsWrite(pWal.pWalFd, &aFrame, aFrame.len, iOff);
        }
    }

    sqlite3_free(aBuf);
    return rc;
}

fn walFrames(pWal: *Wal, szPage: c_int, pList: *PgHdr, nTruncate: Pgno, isCommit: c_int, sync_flags: c_int) c_int {
    var rc: c_int = undefined;
    var iFrame: u32 = undefined;
    var pLast: ?*PgHdr = null;
    var nExtra: c_int = 0;
    var iOffset: i64 = undefined;
    var w: WalWriter = undefined;
    var iFirst: u32 = 0;

    std.debug.assert(pWal.writeLock != 0);
    std.debug.assert((isCommit != 0) == (nTruncate != 0));

    const pLive = walIndexHdr(pWal);
    if (memcmp(&pWal.hdr, @volatileCast(&pLive[0]), @sizeOf(WalIndexHdr)) != 0) {
        iFirst = pLive[0].mxFrame + 1;
    }

    rc = walRestartLog(pWal);
    if (rc != SQLITE_OK) return rc;

    iFrame = pWal.hdr.mxFrame;
    if (iFrame == 0) {
        var aWalHdr: [@intCast(WAL_HDRSIZE)]u8 = undefined;
        var aCksum: [2]u32 = undefined;

        sqlite3Put4byte(&aWalHdr, WAL_MAGIC | @as(u32, @intCast(SQLITE_BIGENDIAN)));
        sqlite3Put4byte(aWalHdr[4..], WAL_MAX_VERSION);
        sqlite3Put4byte(aWalHdr[8..], @intCast(szPage));
        sqlite3Put4byte(aWalHdr[12..], pWal.nCkpt);
        if (pWal.nCkpt == 0) sqlite3_randomness(8, &pWal.hdr.aSalt);
        _ = memcpy(aWalHdr[16..], &pWal.hdr.aSalt, 8);
        walChecksumBytes(true, &aWalHdr, @intCast(WAL_HDRSIZE - 2 * 4), null, &aCksum);
        sqlite3Put4byte(aWalHdr[24..], aCksum[0]);
        sqlite3Put4byte(aWalHdr[28..], aCksum[1]);

        pWal.szPage = @intCast(szPage);
        pWal.hdr.bigEndCksum = @intCast(SQLITE_BIGENDIAN);
        pWal.hdr.aFrameCksum[0] = aCksum[0];
        pWal.hdr.aFrameCksum[1] = aCksum[1];
        pWal.truncateOnCommit = 1;

        rc = sqlite3OsWrite(pWal.pWalFd, &aWalHdr, aWalHdr.len, 0);
        if (rc != SQLITE_OK) return rc;

        if (pWal.syncHeader != 0) {
            rc = sqlite3OsSync(pWal.pWalFd, CKPT_SYNC_FLAGS(sync_flags));
            if (rc != 0) return rc;
        }
    }
    if (@as(c_int, @intCast(pWal.szPage)) != szPage) {
        return SQLITE_CORRUPT_BKPT();
    }

    w.pWal = pWal;
    w.pFd = pWal.pWalFd;
    w.iSyncPoint = 0;
    w.syncFlags = sync_flags;
    w.szPage = szPage;
    iOffset = walFrameOffset(iFrame + 1, @intCast(szPage));
    const szFrame: i64 = szPage + WAL_FRAME_HDRSIZE;

    // Write all frames into the log file exactly once.
    var p: ?*PgHdr = pList;
    while (p) |pg| : (p = pg.pDirty) {
        var nDbSize: c_int = undefined;

        if (iFirst != 0 and (pg.pDirty != null or isCommit == 0)) {
            var iWrite: u32 = 0;
            _ = walFindFrame(pWal, pg.pgno, &iWrite);
            if (iWrite >= iFirst) {
                const iOff = walFrameOffset(iWrite, @intCast(szPage)) + WAL_FRAME_HDRSIZE;
                if (pWal.iReCksum == 0 or iWrite < pWal.iReCksum) {
                    pWal.iReCksum = iWrite;
                }
                rc = sqlite3OsWrite(pWal.pWalFd, pg.pData, szPage, iOff);
                if (rc != 0) return rc;
                pg.flags &= ~PGHDR_WAL_APPEND;
                continue;
            }
        }

        iFrame += 1;
        nDbSize = if (isCommit != 0 and pg.pDirty == null) @intCast(nTruncate) else 0;
        rc = walWriteOneFrame(&w, pg, nDbSize, iOffset);
        if (rc != 0) return rc;
        pLast = pg;
        iOffset += szFrame;
        pg.flags |= PGHDR_WAL_APPEND;
    }

    if (isCommit != 0 and pWal.iReCksum != 0) {
        rc = walRewriteChecksums(pWal, iFrame);
        if (rc != 0) return rc;
    }

    if (isCommit != 0 and WAL_SYNC_FLAGS(sync_flags) != 0) {
        var bSync: bool = true;
        if (pWal.padToSectorBoundary != 0) {
            const sectorSize: i64 = sqlite3OsSectorSize(pWal.pWalFd);
            w.iSyncPoint = @divTrunc(iOffset + sectorSize - 1, sectorSize) * sectorSize;
            bSync = (w.iSyncPoint == iOffset);
            while (iOffset < w.iSyncPoint) {
                rc = walWriteOneFrame(&w, pLast.?, @intCast(nTruncate), iOffset);
                if (rc != 0) return rc;
                iOffset += szFrame;
                nExtra += 1;
            }
        }
        if (bSync) {
            rc = sqlite3OsSync(w.pFd, WAL_SYNC_FLAGS(sync_flags));
        }
    }

    if (isCommit != 0 and pWal.truncateOnCommit != 0 and pWal.mxWalSize >= 0) {
        var sz: i64 = pWal.mxWalSize;
        if (walFrameOffset(iFrame + @as(u32, @intCast(nExtra)) + 1, @intCast(szPage)) > pWal.mxWalSize) {
            sz = walFrameOffset(iFrame + @as(u32, @intCast(nExtra)) + 1, @intCast(szPage));
        }
        walLimitSize(pWal, sz);
        pWal.truncateOnCommit = 0;
    }

    // Append data to the wal-index.
    iFrame = pWal.hdr.mxFrame;
    p = pList;
    while (p != null and rc == SQLITE_OK) : (p = p.?.pDirty) {
        const pg = p.?;
        if ((pg.flags & PGHDR_WAL_APPEND) == 0) continue;
        iFrame += 1;
        rc = walIndexAppend(pWal, iFrame, pg.pgno);
    }
    std.debug.assert(pLast != null or nExtra == 0);
    while (rc == SQLITE_OK and nExtra > 0) {
        iFrame += 1;
        nExtra -= 1;
        rc = walIndexAppend(pWal, iFrame, pLast.?.pgno);
    }

    if (rc == SQLITE_OK) {
        pWal.hdr.szPage = @truncate(@as(u32, @intCast((szPage & 0xff00) | (szPage >> 16))));
        pWal.hdr.mxFrame = iFrame;
        if (isCommit != 0) {
            pWal.hdr.iChange += 1;
            pWal.hdr.nPage = nTruncate;
        }
        if (isCommit != 0) {
            walIndexWriteHdr(pWal);
            pWal.iCallback = iFrame;
        }
    }

    return rc;
}

export fn sqlite3WalFrames(pWal: ?*Wal, szPage: c_int, pList: ?*PgHdr, nTruncate: Pgno, isCommit: c_int, sync_flags: c_int) callconv(.c) c_int {
    return walFrames(pWal.?, szPage, pList.?, nTruncate, isCommit, sync_flags);
}

// ───────────────────────── checkpoint entry ────────────────────────────────

export fn sqlite3WalCheckpoint(
    pWal: ?*Wal,
    db: ?*Sqlite3,
    eMode: c_int,
    xBusy: ?*const fn (?*anyopaque) callconv(.c) c_int,
    pBusyArg: ?*anyopaque,
    sync_flags: c_int,
    nBuf: c_int,
    zBuf: ?[*]u8,
    pnLog: ?*c_int,
    pnCkpt: ?*c_int,
) callconv(.c) c_int {
    const w = pWal.?;
    var rc: c_int = undefined;
    var isChanged: c_int = 0;
    var eMode2 = eMode;
    var xBusy2 = xBusy;

    std.debug.assert(w.ckptLock == 0);
    std.debug.assert(w.writeLock == 0);

    if (w.readOnly != 0) return SQLITE_READONLY;

    if (eMode != SQLITE_CHECKPOINT_NOOP) {
        rc = walLockExclusive(w, WAL_CKPT_LOCK, 1);
        if (rc == SQLITE_OK) {
            w.ckptLock = 1;
            if (eMode != SQLITE_CHECKPOINT_PASSIVE) {
                rc = walBusyLock(w, xBusy2, pBusyArg, WAL_WRITE_LOCK, 1);
                if (rc == SQLITE_OK) {
                    w.writeLock = 1;
                } else if (rc == SQLITE_BUSY) {
                    eMode2 = SQLITE_CHECKPOINT_PASSIVE;
                    xBusy2 = null;
                    rc = SQLITE_OK;
                }
            }
        }
    } else {
        rc = SQLITE_OK;
    }

    if (rc == SQLITE_OK) {
        rc = walIndexReadHdr(w, &isChanged);
        if (isChanged != 0 and ioMethodsVersion(w.pDbFd) >= 3) {
            _ = sqlite3OsUnfetch(w.pDbFd, 0, null);
        }
    }

    if (rc == SQLITE_OK) {
        _ = sqlite3FaultSim(660);
        if (w.hdr.mxFrame != 0 and walPagesize(w) != nBuf) {
            rc = SQLITE_CORRUPT_BKPT();
        } else if (eMode2 != SQLITE_CHECKPOINT_NOOP) {
            rc = walCheckpoint(w, db.?, eMode2, xBusy2, pBusyArg, sync_flags, zBuf.?);
        }

        if (rc == SQLITE_OK or rc == SQLITE_BUSY) {
            if (pnLog) |pl| pl.* = @intCast(w.hdr.mxFrame);
            if (pnCkpt) |pc| pc.* = @intCast(walCkptInfo(w).nBackfill);
        }
    }

    if (isChanged != 0) {
        _ = memset(&w.hdr, 0, @sizeOf(WalIndexHdr));
    }

    _ = sqlite3WalEndWriteTransaction(w);
    if (w.ckptLock != 0) {
        walUnlockExclusive(w, WAL_CKPT_LOCK, 1);
        w.ckptLock = 0;
    }
    return if (rc == SQLITE_OK and eMode != eMode2) SQLITE_BUSY else rc;
}

export fn sqlite3WalCallback(pWal: ?*Wal) callconv(.c) c_int {
    var ret: u32 = 0;
    if (pWal) |w| {
        ret = w.iCallback;
        w.iCallback = 0;
    }
    return @intCast(ret);
}

export fn sqlite3WalExclusiveMode(pWal: ?*Wal, op: c_int) callconv(.c) c_int {
    const w = pWal.?;
    var rc: c_int = undefined;
    std.debug.assert(w.writeLock == 0);
    std.debug.assert(w.exclusiveMode != WAL_HEAPMEMORY_MODE or op == -1);

    if (op == 0) {
        if (w.exclusiveMode != WAL_NORMAL_MODE) {
            w.exclusiveMode = WAL_NORMAL_MODE;
            if (walLockShared(w, WAL_READ_LOCK(w.readLock)) != SQLITE_OK) {
                w.exclusiveMode = WAL_EXCLUSIVE_MODE;
            }
            rc = @intFromBool(w.exclusiveMode == WAL_NORMAL_MODE);
        } else {
            rc = 0;
        }
    } else if (op > 0) {
        std.debug.assert(w.exclusiveMode == WAL_NORMAL_MODE);
        std.debug.assert(w.readLock >= 0);
        walUnlockShared(w, WAL_READ_LOCK(w.readLock));
        w.exclusiveMode = WAL_EXCLUSIVE_MODE;
        rc = 1;
    } else {
        rc = @intFromBool(w.exclusiveMode == WAL_NORMAL_MODE);
    }
    return rc;
}

export fn sqlite3WalHeapMemory(pWal: ?*Wal) callconv(.c) c_int {
    if (pWal) |w| return @intFromBool(w.exclusiveMode == WAL_HEAPMEMORY_MODE);
    return 0;
}

export fn sqlite3WalFile(pWal: ?*Wal) callconv(.c) ?*Sqlite3File {
    return pWal.?.pWalFd;
}

// SQLITE_TEST hook: the wal-index params are exposed to the TCL harness via the
// sqlite3_wal_trace symbol only when SQLITE_TEST && SQLITE_DEBUG. The TCL test
// harness references `sqlite3WalTrace` in that build (it is an `int` global).
var wal_trace: c_int = 0;
comptime {
    if (config.sqlite_test and config.sqlite_debug) {
        @export(&wal_trace, .{ .name = "sqlite3WalTrace" });
    }
}
