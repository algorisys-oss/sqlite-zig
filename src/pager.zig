//! Zig port of SQLite's pager (src/pager.c) — page-level transactions, the
//! rollback journal, savepoints, and the bridge to the WAL and the VFS.
//!
//! Struct coupling:
//!   * `Pager` is PRIVATE to pager.c — other modules hold an opaque `Pager*`,
//!     so this module OWNS its layout. Only its allocation `sizeof` matters
//!     externally (sqlite3PagerOpen computes the block; nothing else inspects
//!     the struct). We mirror it as a Zig `extern struct`; no ground-truth
//!     asserts apply (no header to compare against).
//!   * `PgHdr` is ABI-shared (pcache.h) — mirrored field-for-field exactly as
//!     pcache.zig does, pinned to c_layout ground truth.
//!   * `PagerSavepoint` is internal to pager.c — we own it.
//!   * `sqlite3_vfs` / `sqlite3_file` / `sqlite3_io_methods` are PUBLIC ABI
//!     (sqlite3.h) — mirrored as extern structs (copied from os.zig).
//!   * `sqlite3Config.nStmtSpill` is read at its (config-invariant) offset 28.
//!
//! Everything the pager calls into — the VFS (sqlite3Os*), the page cache
//! (sqlite3Pcache*), bitvec (sqlite3Bitvec*), the WAL (sqlite3Wal*, still C),
//! the journal-file shim (sqlite3Journal*/sqlite3MemJournalOpen), backup
//! (sqlite3Backup*), malloc/util — is declared `extern` and resolved at link.
//!
//! Build-config notes (this single object serves both the production zig build
//! and the --dev testfixture):
//!   * SQLITE_MAX_MMAP_SIZE>0 on linux x86-64 → the mmap getter path
//!     (getPageMMap / pagerAcquireMapPage / pagerReleaseMapPage) is compiled.
//!   * SQLITE_DIRECT_OVERFLOW_READ is on by default → sqlite3PagerDirectReadOk
//!     is exported.
//!   * SQLITE_DEFAULT_PAGE_SIZE differs: 4096 (prod) vs 1024 (testfixture) —
//!     gated on config.sqlite_test.
//!   * SQLITE_OMIT_WAL is OFF → all WAL paths compiled (sqlite3Wal* are extern).
//!   * OFF in both builds: ATOMIC_WRITE, BATCH_ATOMIC_WRITE, SNAPSHOT, SEH,
//!     SETLK_TIMEOUT, ZIPVFS, OMIT_AUTOVACUUM, OMIT_VACUUM, OMIT_MEMORYDB,
//!     CHECK_PAGES, OMIT_WSD. Code paths for those are dropped/folded.
//!   * SQLITE_TEST-only globals/symbols (sqlite3_pager_*_count, opentemp_count,
//!     sqlite3PagerStats/Refdump, disable/enable_simulated_io_errors,
//!     sqlite3PagerPagenumber/Iswriteable) gated on config.sqlite_test /
//!     config.sqlite_debug via comptime @export.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ===================== Constants =======================

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_ABORT: c_int = 4;
const SQLITE_BUSY: c_int = 5;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT in production
const SQLITE_READONLY: c_int = 8;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CORRUPT: c_int = 11; // SQLITE_CORRUPT_BKPT
const SQLITE_NOTFOUND: c_int = 12;
const SQLITE_FULL: c_int = 13;
const SQLITE_CANTOPEN: c_int = 14; // SQLITE_CANTOPEN_BKPT
const SQLITE_DONE: c_int = 101;

const SQLITE_IOERR_SHORT_READ: c_int = SQLITE_IOERR | (2 << 8);
const SQLITE_IOERR_NOMEM: c_int = SQLITE_IOERR | (12 << 8);
const SQLITE_IOERR_BLOCKED: c_int = SQLITE_IOERR | (11 << 8);
const SQLITE_CANTOPEN_SYMLINK: c_int = SQLITE_CANTOPEN | (6 << 8);
const SQLITE_READONLY_ROLLBACK: c_int = SQLITE_READONLY | (3 << 8);
const SQLITE_READONLY_DBMOVED: c_int = SQLITE_READONLY | (4 << 8);
const SQLITE_OK_SYMLINK: c_int = SQLITE_OK | (2 << 8);
const SQLITE_NOTICE_RECOVER_ROLLBACK: c_int = 27 | (2 << 8); // SQLITE_NOTICE=27

const SQLITE_VERSION_NUMBER: c_int = 3054000;

// Pager states (Pager.eState)
const PAGER_OPEN: u8 = 0;
const PAGER_READER: u8 = 1;
const PAGER_WRITER_LOCKED: u8 = 2;
const PAGER_WRITER_CACHEMOD: u8 = 3;
const PAGER_WRITER_DBMOD: u8 = 4;
const PAGER_WRITER_FINISHED: u8 = 5;
const PAGER_ERROR: u8 = 6;

// Lock levels (os.h)
const NO_LOCK: u8 = 0;
const SHARED_LOCK: u8 = 1;
const RESERVED_LOCK: u8 = 2;
const PENDING_LOCK: u8 = 3;
const EXCLUSIVE_LOCK: u8 = 4;
const UNKNOWN_LOCK: u8 = EXCLUSIVE_LOCK + 1;

const MAX_SECTOR_SIZE: c_int = 0x10000;

// Journal modes (pager.h)
const PAGER_JOURNALMODE_QUERY: c_int = -1;
const PAGER_JOURNALMODE_DELETE: u8 = 0;
const PAGER_JOURNALMODE_PERSIST: u8 = 1;
const PAGER_JOURNALMODE_OFF: u8 = 2;
const PAGER_JOURNALMODE_TRUNCATE: u8 = 3;
const PAGER_JOURNALMODE_MEMORY: u8 = 4;
const PAGER_JOURNALMODE_WAL: u8 = 5;

// Open flags (pager.h)
const PAGER_OMIT_JOURNAL: c_int = 0x0001;
const PAGER_MEMORY: c_int = 0x0002;

// Locking mode (pager.h)
const PAGER_LOCKINGMODE_QUERY: c_int = -1;
const PAGER_LOCKINGMODE_NORMAL: c_int = 0;
const PAGER_LOCKINGMODE_EXCLUSIVE: c_int = 1;

// PagerGet flags (pager.h)
const PAGER_GET_NOCONTENT: c_int = 0x01;
const PAGER_GET_READONLY: c_int = 0x02;

// SetFlags flags (pager.h)
const PAGER_SYNCHRONOUS_OFF: c_uint = 0x01;
const PAGER_SYNCHRONOUS_NORMAL: c_uint = 0x02;
const PAGER_SYNCHRONOUS_FULL: c_uint = 0x03;
const PAGER_SYNCHRONOUS_EXTRA: c_uint = 0x04;
const PAGER_SYNCHRONOUS_MASK: c_uint = 0x07;
const PAGER_FULLFSYNC: c_uint = 0x08;
const PAGER_CKPT_FULLFSYNC: c_uint = 0x10;
const PAGER_CACHESPILL: c_uint = 0x20;

// doNotSpill bits
const SPILLFLAG_OFF: u8 = 0x01;
const SPILLFLAG_ROLLBACK: u8 = 0x02;
const SPILLFLAG_NOSYNC: u8 = 0x04;

// aStat[] indices
const PAGER_STAT_HIT: usize = 0;
const PAGER_STAT_MISS: usize = 1;
const PAGER_STAT_WRITE: usize = 2;
const PAGER_STAT_SPILL: usize = 3;

// PgHdr flags (pcache.h)
const PGHDR_CLEAN: u16 = 0x001;
const PGHDR_DIRTY: u16 = 0x002;
const PGHDR_WRITEABLE: u16 = 0x004;
const PGHDR_NEED_SYNC: u16 = 0x008;
const PGHDR_DONT_WRITE: u16 = 0x010;
const PGHDR_MMAP: u16 = 0x020;

// Savepoint ops (sqliteInt.h)
const SAVEPOINT_RELEASE: c_int = 1;
const SAVEPOINT_ROLLBACK: c_int = 2;

const WAL_SAVEPOINT_NDATA: usize = 4;

// sqlite3_vfs.xOpen / VFS open flags (sqlite3.h)
const SQLITE_OPEN_READONLY: c_int = 0x00000001;
const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
const SQLITE_OPEN_CREATE: c_int = 0x00000004;
const SQLITE_OPEN_DELETEONCLOSE: c_int = 0x00000008;
const SQLITE_OPEN_EXCLUSIVE: c_int = 0x00000010;
const SQLITE_OPEN_MEMORY: c_int = 0x00000080;
const SQLITE_OPEN_MAIN_JOURNAL: c_int = 0x00000800;
const SQLITE_OPEN_TEMP_JOURNAL: c_int = 0x00001000;
const SQLITE_OPEN_SUBJOURNAL: c_int = 0x00002000;
const SQLITE_OPEN_SUPER_JOURNAL: c_int = 0x00004000;
const SQLITE_OPEN_NOFOLLOW: c_int = 0x01000000;

// IO capabilities
const SQLITE_IOCAP_ATOMIC: c_int = 0x00000001;
const SQLITE_IOCAP_SAFE_APPEND: c_int = 0x00000200;
const SQLITE_IOCAP_SEQUENTIAL: c_int = 0x00000400;
const SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN: c_int = 0x00000800;
const SQLITE_IOCAP_POWERSAFE_OVERWRITE: c_int = 0x00001000;
const SQLITE_IOCAP_IMMUTABLE: c_int = 0x00002000;
const SQLITE_IOCAP_BATCH_ATOMIC: c_int = 0x00004000;
const SQLITE_IOCAP_SUBPAGE_READ: c_int = 0x00008000;

const SQLITE_ACCESS_EXISTS: c_int = 0;

const SQLITE_SYNC_NORMAL: u8 = 0x02;
const SQLITE_SYNC_FULL: u8 = 0x03;
const SQLITE_SYNC_DATAONLY: c_int = 0x10;

const SQLITE_FCNTL_SIZE_HINT: c_int = 5;
const SQLITE_FCNTL_BUSYHANDLER: c_int = 15;
const SQLITE_FCNTL_MMAP_SIZE: c_int = 18;
const SQLITE_FCNTL_HAS_MOVED: c_int = 20;
const SQLITE_FCNTL_SYNC: c_int = 21;
const SQLITE_FCNTL_COMMIT_PHASETWO: c_int = 22;
const SQLITE_FCNTL_DB_UNCHANGED: c_int = 0xca093fa0;

const SQLITE_DBSTATUS_CACHE_HIT: c_int = 7;
const SQLITE_DBSTATUS_CACHE_MISS: c_int = 8;
const SQLITE_DBSTATUS_CACHE_WRITE: c_int = 9;

const SQLITE_CHECKPOINT_PASSIVE: c_int = 0;

const SQLITE_NoCkptOnClose: u64 = 0x00000800;

// Limits (sqliteLimit.h)
const SQLITE_MAX_PAGE_SIZE: u32 = 65536;
const SQLITE_MAX_DEFAULT_PAGE_SIZE: u32 = 8192;
const SQLITE_MAX_PAGE_COUNT: Pgno = 0xfffffffe;
const SQLITE_DEFAULT_SYNCHRONOUS: c_uint = 2;
const SQLITE_DEFAULT_JOURNAL_SIZE_LIMIT: i64 = -1;
const SQLITE_PTRSIZE: usize = 8;

/// SQLITE_DEFAULT_PAGE_SIZE differs between the two builds.
const SQLITE_DEFAULT_PAGE_SIZE: u32 = if (config.sqlite_test) 1024 else 4096;

const Pgno = u32;

const aJournalMagic = [8]u8{ 0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7 };

// ===================== ABI structs =======================

const IoMethods = extern struct {
    iVersion: c_int,
    xClose: ?*const fn (*Sqlite3File) callconv(.c) c_int,
    xRead: ?*const fn (*Sqlite3File, ?*anyopaque, c_int, i64) callconv(.c) c_int,
    xWrite: ?*const fn (*Sqlite3File, ?*const anyopaque, c_int, i64) callconv(.c) c_int,
    xTruncate: ?*const fn (*Sqlite3File, i64) callconv(.c) c_int,
    xSync: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xFileSize: ?*const fn (*Sqlite3File, *i64) callconv(.c) c_int,
    xLock: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xUnlock: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xCheckReservedLock: ?*const fn (*Sqlite3File, *c_int) callconv(.c) c_int,
    xFileControl: ?*const fn (*Sqlite3File, c_int, ?*anyopaque) callconv(.c) c_int,
    xSectorSize: ?*const fn (*Sqlite3File) callconv(.c) c_int,
    xDeviceCharacteristics: ?*const fn (*Sqlite3File) callconv(.c) c_int,
    xShmMap: ?*const fn (*Sqlite3File, c_int, c_int, c_int, ?*anyopaque) callconv(.c) c_int,
    xShmLock: ?*const fn (*Sqlite3File, c_int, c_int, c_int) callconv(.c) c_int,
    xShmBarrier: ?*const fn (*Sqlite3File) callconv(.c) void,
    xShmUnmap: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xFetch: ?*const fn (*Sqlite3File, i64, c_int, ?*?*anyopaque) callconv(.c) c_int,
    xUnfetch: ?*const fn (*Sqlite3File, i64, ?*anyopaque) callconv(.c) c_int,
};

const Sqlite3File = extern struct {
    pMethods: ?*const IoMethods,
};

const VoidFn = ?*const fn () callconv(.c) void;

const Sqlite3Vfs = extern struct {
    iVersion: c_int,
    szOsFile: c_int,
    mxPathname: c_int,
    pNext: ?*Sqlite3Vfs,
    zName: ?[*:0]const u8,
    pAppData: ?*anyopaque,
    xOpen: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8, *Sqlite3File, c_int, ?*c_int) callconv(.c) c_int,
    xDelete: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8, c_int) callconv(.c) c_int,
    xAccess: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8, c_int, *c_int) callconv(.c) c_int,
    xFullPathname: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8, c_int, [*]u8) callconv(.c) c_int,
    xDlOpen: ?*const anyopaque,
    xDlError: ?*const anyopaque,
    xDlSym: ?*const anyopaque,
    xDlClose: ?*const anyopaque,
    xRandomness: ?*const anyopaque,
    xSleep: ?*const anyopaque,
    xCurrentTime: ?*const anyopaque,
    xGetLastError: ?*const anyopaque,
    xCurrentTimeInt64: ?*const anyopaque,
    xSetSystemCall: ?*const anyopaque,
    xGetSystemCall: ?*const anyopaque,
    xNextSystemCall: ?*const anyopaque,
};

/// PgHdr — ABI-shared (pcache.h). Mirrored field-for-field, pinned to c_layout.
const PgHdr = extern struct {
    pPage: ?*anyopaque, // sqlite3_pcache_page* (opaque here)
    pData: ?*anyopaque, // Page data
    pExtra: ?*anyopaque, // Extra content
    pCache: ?*anyopaque, // PCache*
    pDirty: ?*PgHdr, // Transient list of dirty sorted by pgno
    pPager: ?*Pager, // The pager this page is part of
    pgno: Pgno, // Page number for this page
    flags: u16, // PGHDR flags
    nRef: i64, // Number of users of this page (private to pcache)
    pDirtyNext: ?*PgHdr,
    pDirtyPrev: ?*PgHdr,
};

comptime {
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

const Bitvec = opaque {};
const Backup = opaque {};
const Wal = opaque {};
const Sqlite3 = opaque {};

const Sqlite3PcachePage = extern struct {
    pBuf: ?*anyopaque,
    pExtra: ?*anyopaque,
};

/// PagerSavepoint — internal to pager.c. We own the layout.
const PagerSavepoint = extern struct {
    iOffset: i64, // Starting offset in main journal
    iHdrOffset: i64, // See pager.c comment
    pInSavepoint: ?*Bitvec, // Set of pages in this savepoint
    nOrig: Pgno, // Original number of pages in file
    iSubRec: Pgno, // Index of first record in sub-journal
    bTruncateOnRelease: c_int, // If stmt journal may be truncated on RELEASE
    aWalData: [WAL_SAVEPOINT_NDATA]u32, // WAL savepoint context (OMIT_WAL off)
};

/// Pager — PRIVATE to this module. Layout owned here; field order follows
/// pager.c so behavior matches. nothing external inspects fields.
const Pager = extern struct {
    pVfs: ?*Sqlite3Vfs,
    exclusiveMode: u8,
    journalMode: u8,
    useJournal: u8,
    noSync: u8,
    fullSync: u8,
    extraSync: u8,
    syncFlags: u8,
    walSyncFlags: u8,
    tempFile: u8,
    noLock: u8,
    readOnly: u8,
    memDb: u8,
    memVfs: u8,
    // routinely-changing members
    eState: u8,
    eLock: u8,
    changeCountDone: u8,
    setSuper: u8,
    doNotSpill: u8,
    subjInMemory: u8,
    bUseFetch: u8,
    hasHeldSharedLock: u8,
    dbSize: Pgno,
    dbOrigSize: Pgno,
    dbFileSize: Pgno,
    dbHintSize: Pgno,
    errCode: c_int,
    nRec: c_int,
    cksumInit: u32,
    nSubRec: u32,
    pInJournal: ?*Bitvec,
    fd: *Sqlite3File,
    jfd: *Sqlite3File,
    sjfd: *Sqlite3File,
    journalOff: i64,
    journalHdr: i64,
    pBackup: ?*Backup,
    aSavepoint: ?[*]PagerSavepoint,
    nSavepoint: c_int,
    iDataVersion: u32,
    dbFileVers: [16]u8,
    nMmapOut: c_int,
    szMmap: i64,
    pMmapFreelist: ?*PgHdr,
    // configuration members
    nExtra: u16,
    nReserve: i16,
    vfsFlags: u32,
    sectorSize: u32,
    mxPgno: Pgno,
    lckPgno: Pgno,
    pageSize: i64,
    journalSizeLimit: i64,
    zFilename: ?[*:0]u8,
    zJournal: ?[*:0]u8,
    xBusyHandler: ?*const fn (?*anyopaque) callconv(.c) c_int,
    pBusyHandlerArg: ?*anyopaque,
    aStat: [4]u32,
    nRead: c_int, // SQLITE_TEST only — kept unconditionally for layout simplicity
    xReiniter: ?*const fn (*PgHdr) callconv(.c) void,
    xGet: ?*const fn (*Pager, Pgno, *?*PgHdr, c_int) callconv(.c) c_int,
    pTmpSpace: ?[*]u8,
    pPCache: *anyopaque, // PCache*
    // OMIT_WAL is off
    pWal: ?*Wal,
    zWal: ?[*:0]u8,
};

// ===================== extern decls =======================
// VFS (sqlite3Os* — already-ported Zig in os.zig)
extern fn sqlite3OsClose(*Sqlite3File) void;
extern fn sqlite3OsRead(*Sqlite3File, ?*anyopaque, c_int, i64) c_int;
extern fn sqlite3OsWrite(*Sqlite3File, ?*const anyopaque, c_int, i64) c_int;
extern fn sqlite3OsTruncate(*Sqlite3File, i64) c_int;
extern fn sqlite3OsSync(*Sqlite3File, c_int) c_int;
extern fn sqlite3OsFileSize(*Sqlite3File, *i64) c_int;
extern fn sqlite3OsLock(*Sqlite3File, c_int) c_int;
extern fn sqlite3OsUnlock(*Sqlite3File, c_int) c_int;
extern fn sqlite3OsCheckReservedLock(*Sqlite3File, *c_int) c_int;
extern fn sqlite3OsFileControl(*Sqlite3File, c_int, ?*anyopaque) c_int;
extern fn sqlite3OsFileControlHint(*Sqlite3File, c_int, ?*anyopaque) void;
extern fn sqlite3OsSectorSize(*Sqlite3File) c_int;
extern fn sqlite3OsDeviceCharacteristics(*Sqlite3File) c_int;
extern fn sqlite3OsFetch(*Sqlite3File, i64, c_int, *?*anyopaque) c_int;
extern fn sqlite3OsUnfetch(*Sqlite3File, i64, ?*anyopaque) c_int;
extern fn sqlite3OsOpen(*Sqlite3Vfs, ?[*:0]const u8, *Sqlite3File, c_int, ?*c_int) c_int;
extern fn sqlite3OsDelete(*Sqlite3Vfs, ?[*:0]const u8, c_int) c_int;
extern fn sqlite3OsAccess(*Sqlite3Vfs, ?[*:0]const u8, c_int, *c_int) c_int;
extern fn sqlite3OsFullPathname(*Sqlite3Vfs, ?[*:0]const u8, c_int, [*]u8) c_int;

// page cache (sqlite3Pcache* — already-ported Zig in pcache.zig)
extern fn sqlite3PcacheSize() c_int;
extern fn sqlite3PcacheOpen(c_int, c_int, c_int, ?*const fn (?*anyopaque, ?*PgHdr) callconv(.c) c_int, ?*anyopaque, *anyopaque) c_int;
extern fn sqlite3PcacheSetPageSize(*anyopaque, c_int) c_int;
extern fn sqlite3PcacheFetch(*anyopaque, Pgno, c_int) ?*Sqlite3PcachePage;
extern fn sqlite3PcacheFetchStress(*anyopaque, Pgno, *?*Sqlite3PcachePage) c_int;
extern fn sqlite3PcacheFetchFinish(*anyopaque, Pgno, *Sqlite3PcachePage) *PgHdr;
extern fn sqlite3PcacheRelease(*PgHdr) void;
extern fn sqlite3PcacheRef(*PgHdr) void;
extern fn sqlite3PcacheDrop(*PgHdr) void;
extern fn sqlite3PcacheMakeDirty(*PgHdr) void;
extern fn sqlite3PcacheMakeClean(*PgHdr) void;
extern fn sqlite3PcacheCleanAll(*anyopaque) void;
extern fn sqlite3PcacheClearWritable(*anyopaque) void;
extern fn sqlite3PcacheClearSyncFlags(*anyopaque) void;
extern fn sqlite3PcacheMove(*PgHdr, Pgno) void;
extern fn sqlite3PcacheTruncate(*anyopaque, Pgno) void;
extern fn sqlite3PcacheClose(*anyopaque) void;
extern fn sqlite3PcacheClear(*anyopaque) void;
extern fn sqlite3PcacheDirtyList(*anyopaque) ?*PgHdr;
extern fn sqlite3PcacheRefCount(*anyopaque) i64;
extern fn sqlite3PCacheIsDirty(*anyopaque) c_int;
extern fn sqlite3PcachePageRefcount(*PgHdr) i64;
extern fn sqlite3PcachePagecount(*anyopaque) c_int;
extern fn sqlite3PcacheSetCachesize(*anyopaque, c_int) void;
extern fn sqlite3PcacheSetSpillsize(*anyopaque, c_int) c_int;
extern fn sqlite3PcacheShrink(*anyopaque) void;
extern fn sqlite3PCachePercentDirty(*anyopaque) c_int;
extern fn sqlite3PcacheGetCachesize(*anyopaque) c_int; // SQLITE_TEST only

// bitvec (sqlite3Bitvec* — already-ported Zig in bitvec.zig)
extern fn sqlite3BitvecCreate(u32) ?*Bitvec;
extern fn sqlite3BitvecTest(?*Bitvec, u32) c_int;
extern fn sqlite3BitvecTestNotNull(?*Bitvec, u32) c_int;
extern fn sqlite3BitvecSet(?*Bitvec, u32) c_int;
extern fn sqlite3BitvecClear(?*Bitvec, u32, ?*anyopaque) void;
extern fn sqlite3BitvecDestroy(?*Bitvec) void;

// WAL (sqlite3Wal* — still C)
extern fn sqlite3WalClose(?*Wal, ?*Sqlite3, c_int, c_int, ?[*]u8) c_int;
extern fn sqlite3WalLimit(?*Wal, i64) void;
extern fn sqlite3WalBeginReadTransaction(?*Wal, *c_int) c_int;
extern fn sqlite3WalEndReadTransaction(?*Wal) void;
extern fn sqlite3WalFindFrame(?*Wal, Pgno, *u32) c_int;
extern fn sqlite3WalReadFrame(?*Wal, u32, c_int, ?*anyopaque) c_int;
extern fn sqlite3WalDbsize(?*Wal) Pgno;
extern fn sqlite3WalBeginWriteTransaction(?*Wal) c_int;
extern fn sqlite3WalEndWriteTransaction(?*Wal) c_int;
extern fn sqlite3WalUndo(?*Wal, ?*const fn (?*anyopaque, Pgno) callconv(.c) c_int, ?*anyopaque) c_int;
extern fn sqlite3WalSavepoint(?*Wal, [*]u32) void;
extern fn sqlite3WalSavepointUndo(?*Wal, [*]u32) c_int;
extern fn sqlite3WalFrames(?*Wal, c_int, ?*PgHdr, Pgno, c_int, c_int) c_int;
extern fn sqlite3WalCheckpoint(?*Wal, ?*Sqlite3, c_int, ?*const fn (?*anyopaque) callconv(.c) c_int, ?*anyopaque, c_int, c_int, ?[*]u8, ?*c_int, ?*c_int) c_int;
extern fn sqlite3WalCallback(?*Wal) c_int;
extern fn sqlite3WalExclusiveMode(?*Wal, c_int) c_int;
extern fn sqlite3WalHeapMemory(?*Wal) c_int;
extern fn sqlite3WalFile(?*Wal) ?*Sqlite3File;
extern fn sqlite3WalOpen(*Sqlite3Vfs, *Sqlite3File, ?[*:0]const u8, c_int, i64, *?*Wal) c_int;

// journal-file shim & helpers
extern fn sqlite3JournalOpen(*Sqlite3Vfs, ?[*:0]const u8, *Sqlite3File, c_int, c_int) c_int;
extern fn sqlite3JournalSize(*Sqlite3Vfs) c_int;
extern fn sqlite3JournalIsInMemory(*Sqlite3File) c_int;
extern fn sqlite3MemJournalOpen(*Sqlite3File) void;

// backup
extern fn sqlite3BackupRestart(?*Backup) void;
extern fn sqlite3BackupUpdate(?*Backup, Pgno, ?*const u8) void;

// malloc / util
extern fn sqlite3MallocZero(u64) ?*anyopaque;
extern fn sqlite3Malloc(u64) ?*anyopaque;
extern fn sqlite3Realloc(?*anyopaque, u64) ?*anyopaque;
extern fn sqlite3_free(?*anyopaque) void;
extern fn sqlite3DbStrDup(?*Sqlite3, ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbMallocRaw(?*Sqlite3, u64) ?*anyopaque;
extern fn sqlite3DbFree(?*Sqlite3, ?*anyopaque) void;
extern fn sqlite3PageMalloc(c_int) ?*anyopaque;
extern fn sqlite3PageFree(?*anyopaque) void;
extern fn sqlite3MallocSize(?*const anyopaque) c_int;
extern fn sqlite3Strlen30(?[*:0]const u8) c_int;
extern fn sqlite3Get4byte(?*const u8) u32;
extern fn sqlite3Put4byte(?*u8, u32) void;
extern fn sqlite3FaultSim(c_int) c_int;
extern fn sqlite3IsMemdb(?*const Sqlite3Vfs) c_int;
extern fn sqlite3BeginBenignMalloc() void;
extern fn sqlite3EndBenignMalloc() void;
extern fn sqlite3_randomness(c_int, ?*anyopaque) void;
extern fn sqlite3_uri_boolean(?[*:0]const u8, ?[*:0]const u8, c_int) c_int;
extern fn sqlite3_log(c_int, ?[*:0]const u8, ...) void;
extern fn sqlite3_exec(?*Sqlite3, ?[*:0]const u8, ?*anyopaque, ?*anyopaque, ?*?[*:0]u8) c_int;

// libc
extern fn memset(?*anyopaque, c_int, usize) ?*anyopaque;
extern fn memcpy(?*anyopaque, ?*const anyopaque, usize) ?*anyopaque;
extern fn memcmp(?*const anyopaque, ?*const anyopaque, usize) c_int;
extern fn strcmp(?[*:0]const u8, ?[*:0]const u8) c_int;
extern fn strlen(?[*:0]const u8) usize;

// `sqlite3Config` global; we read only `nStmtSpill` (offset 28, config-invariant).
extern var sqlite3Config: u8;
inline fn nStmtSpill() c_int {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    const off: usize = if (@hasDecl(L, "Sqlite3Config_nStmtSpill")) L.Sqlite3Config_nStmtSpill else 28;
    const p4: *align(1) const c_int = @ptrCast(base + off);
    return p4.*;
}

/// PENDING_BYTE == sqlite3PendingByte (OMIT_WSD off). Mutable global (tests set it).
extern var sqlite3PendingByte: c_int;
inline fn pendingByte() i64 {
    return sqlite3PendingByte;
}

// ===================== small helpers =======================

inline fn isOpen(pFd: *Sqlite3File) bool {
    return pFd.pMethods != null;
}

inline fn pagerUseWal(p: *Pager) bool {
    return p.pWal != null;
}

inline fn MEMDB(p: *Pager) bool {
    return p.memDb != 0;
}

inline fn USEFETCH(p: *Pager) bool {
    return p.bUseFetch != 0; // SQLITE_MAX_MMAP_SIZE>0
}

inline fn JOURNAL_PG_SZ(p: *Pager) i64 {
    return p.pageSize + 8;
}

inline fn JOURNAL_HDR_SZ(p: *Pager) i64 {
    return @intCast(p.sectorSize);
}

inline fn PAGER_SJ_PGNO(p: *Pager) Pgno {
    return p.lckPgno;
}

inline fn ROUND8(comptime T: type, x: T) T {
    return (x + 7) & ~@as(T, 7);
}

inline fn put32bits(buf: [*]u8, v: u32) void {
    sqlite3Put4byte(@ptrCast(buf), v);
}

/// Read a 32-bit big-endian integer from fd at offset.
fn read32bits(fd: *Sqlite3File, offset: i64, pRes: *u32) c_int {
    var ac: [4]u8 = undefined;
    const rc = sqlite3OsRead(fd, &ac, 4, offset);
    if (rc == SQLITE_OK) {
        pRes.* = sqlite3Get4byte(&ac[0]);
    }
    return rc;
}

fn write32bits(fd: *Sqlite3File, offset: i64, val: u32) c_int {
    var ac: [4]u8 = undefined;
    put32bits(&ac, val);
    return sqlite3OsWrite(fd, &ac, 4, offset);
}

// ===================== getter dispatch =======================
// Forward refs needed; declared as fn values.

fn setGetterMethod(pPager: *Pager) void {
    if (pPager.errCode != 0) {
        pPager.xGet = getPageError;
    } else if (USEFETCH(pPager)) {
        pPager.xGet = getPageMMap;
    } else {
        pPager.xGet = getPageNormal;
    }
}

/// Return true if page *pPg must be written into the sub-journal.
fn subjRequiresPage(pPg: *PgHdr) c_int {
    const pPager = pPg.pPager.?;
    const pgno = pPg.pgno;
    var i: c_int = 0;
    while (i < pPager.nSavepoint) : (i += 1) {
        const p = &pPager.aSavepoint.?[@intCast(i)];
        if (p.nOrig >= pgno and 0 == sqlite3BitvecTestNotNull(p.pInSavepoint, pgno)) {
            var j: c_int = i + 1;
            while (j < pPager.nSavepoint) : (j += 1) {
                pPager.aSavepoint.?[@intCast(j)].bTruncateOnRelease = 0;
            }
            return 1;
        }
    }
    return 0;
}

/// SQLITE_DEBUG-only: page already in journal file. Inlined where used.
inline fn pageInJournal(pPager: *Pager, pPg: *PgHdr) c_int {
    return sqlite3BitvecTest(pPager.pInJournal, pPg.pgno);
}

// ===================== lock wrappers =======================

fn pagerUnlockDb(pPager: *Pager, eLock: u8) c_int {
    var rc: c_int = SQLITE_OK;
    if (isOpen(pPager.fd)) {
        rc = if (pPager.noLock != 0) SQLITE_OK else sqlite3OsUnlock(pPager.fd, eLock);
        if (pPager.eLock != UNKNOWN_LOCK) {
            pPager.eLock = eLock;
        }
    }
    pPager.changeCountDone = pPager.tempFile;
    return rc;
}

fn pagerLockDb(pPager: *Pager, eLock: u8) c_int {
    var rc: c_int = SQLITE_OK;
    if (pPager.eLock < eLock or pPager.eLock == UNKNOWN_LOCK) {
        rc = if (pPager.noLock != 0) SQLITE_OK else sqlite3OsLock(pPager.fd, eLock);
        if (rc == SQLITE_OK and (pPager.eLock != UNKNOWN_LOCK or eLock == EXCLUSIVE_LOCK)) {
            pPager.eLock = eLock;
        }
    }
    return rc;
}

/// Atomic-write/batch-atomic optimizations are off → returns 0 except for MEMDB
/// assertion path. (SQLITE_ENABLE_ATOMIC_WRITE / BATCH_ATOMIC_WRITE off.)
fn jrnlBufferSize(pPager: *Pager) c_int {
    _ = pPager;
    return 0;
}

// ===================== super-journal name read =======================

fn freeSuperJournal(zSuper: ?[*]u8) void {
    if (zSuper) |z| {
        sqlite3_free(z - 4);
    }
}

fn readSuperJournal(pJrnl: *Sqlite3File, nSuper: u64, pzSuper: *?[*]u8) c_int {
    var rc: c_int = undefined;
    var len: u32 = undefined;
    var szJ: i64 = undefined;
    var cksum: u32 = undefined;
    var aMagic: [8]u8 = undefined;
    var zOut: ?[*]u8 = null;

    pzSuper.* = null;
    rc = sqlite3OsFileSize(pJrnl, &szJ);
    if (rc != SQLITE_OK) return rc;
    if (szJ < 16) return rc;
    rc = read32bits(pJrnl, szJ - 16, &len);
    if (rc != SQLITE_OK) return rc;
    if (len >= nSuper) return rc;
    if (len > szJ - 16) return rc;
    if (len == 0) return rc;
    rc = read32bits(pJrnl, szJ - 12, &cksum);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3OsRead(pJrnl, &aMagic, 8, szJ - 8);
    if (rc != SQLITE_OK) return rc;
    if (memcmp(&aMagic, &aJournalMagic, 8) != 0) return rc;

    const buf = sqlite3MallocZero(4 + @as(u64, len) + 2);
    if (buf == null) {
        rc = SQLITE_NOMEM;
    } else {
        var z: [*]u8 = @ptrCast(buf.?);
        z = z + 4;
        zOut = z;
        rc = sqlite3OsRead(pJrnl, z, @intCast(len), szJ - 16 - @as(i64, len));
        if (rc == SQLITE_OK) {
            var u: u32 = 0;
            while (u < len) : (u += 1) {
                cksum -%= z[u];
            }
        }
        if (rc != SQLITE_OK or cksum != 0) {
            freeSuperJournal(zOut);
            zOut = null;
        }
    }
    pzSuper.* = zOut;
    return rc;
}

// ===================== journal header offset & I/O =======================

fn journalHdrOffset(pPager: *Pager) i64 {
    var offset: i64 = 0;
    const c = pPager.journalOff;
    if (c != 0) {
        const hsz = JOURNAL_HDR_SZ(pPager);
        offset = (@divTrunc(c - 1, hsz) + 1) * hsz;
    }
    return offset;
}

fn zeroJournalHdr(pPager: *Pager, doTruncate: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (pPager.journalOff != 0) {
        const iLimit = pPager.journalSizeLimit;
        if (doTruncate != 0 or iLimit == 0) {
            rc = sqlite3OsTruncate(pPager.jfd, 0);
        } else {
            const zeroHdr = std.mem.zeroes([28]u8);
            rc = sqlite3OsWrite(pPager.jfd, &zeroHdr, 28, 0);
        }
        if (rc == SQLITE_OK and pPager.noSync == 0) {
            rc = sqlite3OsSync(pPager.jfd, SQLITE_SYNC_DATAONLY | @as(c_int, pPager.syncFlags));
        }
        if (rc == SQLITE_OK and iLimit > 0) {
            var sz: i64 = undefined;
            rc = sqlite3OsFileSize(pPager.jfd, &sz);
            if (rc == SQLITE_OK and sz > iLimit) {
                rc = sqlite3OsTruncate(pPager.jfd, iLimit);
            }
        }
    }
    return rc;
}

fn writeJournalHdr(pPager: *Pager) c_int {
    var rc: c_int = SQLITE_OK;
    const zHeader: [*]u8 = pPager.pTmpSpace.?;
    var nHeader: u32 = @intCast(pPager.pageSize);
    var nWrite: u32 = undefined;

    const hsz_u32: u32 = @intCast(JOURNAL_HDR_SZ(pPager));
    if (nHeader > hsz_u32) {
        nHeader = hsz_u32;
    }

    var ii: c_int = 0;
    while (ii < pPager.nSavepoint) : (ii += 1) {
        if (pPager.aSavepoint.?[@intCast(ii)].iHdrOffset == 0) {
            pPager.aSavepoint.?[@intCast(ii)].iHdrOffset = pPager.journalOff;
        }
    }

    pPager.journalOff = journalHdrOffset(pPager);
    pPager.journalHdr = pPager.journalOff;

    if (pPager.noSync != 0 or (pPager.journalMode == PAGER_JOURNALMODE_MEMORY) or
        (sqlite3OsDeviceCharacteristics(pPager.fd) & SQLITE_IOCAP_SAFE_APPEND) != 0)
    {
        _ = memcpy(zHeader, &aJournalMagic, aJournalMagic.len);
        put32bits(zHeader + aJournalMagic.len, 0xffffffff);
    } else {
        _ = memset(zHeader, 0, aJournalMagic.len + 4);
    }

    if (pPager.journalMode != PAGER_JOURNALMODE_MEMORY) {
        sqlite3_randomness(@sizeOf(u32), &pPager.cksumInit);
    }
    put32bits(zHeader + aJournalMagic.len + 4, pPager.cksumInit);
    put32bits(zHeader + aJournalMagic.len + 8, pPager.dbOrigSize);
    put32bits(zHeader + aJournalMagic.len + 12, pPager.sectorSize);
    put32bits(zHeader + aJournalMagic.len + 16, @intCast(pPager.pageSize));

    _ = memset(zHeader + aJournalMagic.len + 20, 0, nHeader - (aJournalMagic.len + 20));

    nWrite = 0;
    while (rc == SQLITE_OK and nWrite < hsz_u32) : (nWrite += nHeader) {
        rc = sqlite3OsWrite(pPager.jfd, zHeader, @intCast(nHeader), pPager.journalOff);
        pPager.journalOff += nHeader;
    }
    return rc;
}

fn readJournalHdr(
    pPager: *Pager,
    isHot: c_int,
    journalSize: i64,
    pNRec: *u32,
    pDbSize: *u32,
) c_int {
    var rc: c_int = undefined;
    var aMagic: [8]u8 = undefined;
    var iHdrOff: i64 = undefined;

    pPager.journalOff = journalHdrOffset(pPager);
    if (pPager.journalOff + JOURNAL_HDR_SZ(pPager) > journalSize) {
        return SQLITE_DONE;
    }
    iHdrOff = pPager.journalOff;

    if (isHot != 0 or iHdrOff != pPager.journalHdr) {
        rc = sqlite3OsRead(pPager.jfd, &aMagic, 8, iHdrOff);
        if (rc != 0) return rc;
        if (memcmp(&aMagic, &aJournalMagic, 8) != 0) return SQLITE_DONE;
    }

    rc = read32bits(pPager.jfd, iHdrOff + 8, pNRec);
    if (rc != SQLITE_OK) return rc;
    rc = read32bits(pPager.jfd, iHdrOff + 12, &pPager.cksumInit);
    if (rc != SQLITE_OK) return rc;
    rc = read32bits(pPager.jfd, iHdrOff + 16, pDbSize);
    if (rc != SQLITE_OK) return rc;

    if (pPager.journalOff == 0) {
        var iPageSize: u32 = undefined;
        var iSectorSize: u32 = undefined;
        rc = read32bits(pPager.jfd, iHdrOff + 20, &iSectorSize);
        if (rc != SQLITE_OK) return rc;
        rc = read32bits(pPager.jfd, iHdrOff + 24, &iPageSize);
        if (rc != SQLITE_OK) return rc;

        if (iPageSize == 0) {
            iPageSize = @intCast(pPager.pageSize);
        }
        if (iPageSize < 512 or iSectorSize < 32 or
            iPageSize > SQLITE_MAX_PAGE_SIZE or iSectorSize > MAX_SECTOR_SIZE or
            ((iPageSize - 1) & iPageSize) != 0 or ((iSectorSize - 1) & iSectorSize) != 0)
        {
            return SQLITE_DONE;
        }

        rc = sqlite3PagerSetPagesize(pPager, &iPageSize, -1);
        pPager.sectorSize = iSectorSize;
    }

    pPager.journalOff += JOURNAL_HDR_SZ(pPager);
    return rc;
}

fn writeSuperJournal(pPager: *Pager, zSuper: ?[*:0]const u8) c_int {
    var rc: c_int = undefined;
    var nSuper: c_int = undefined;
    var iHdrOff: i64 = undefined;
    var jrnlSize: i64 = undefined;
    var cksum: u32 = 0;

    if (zSuper == null or pPager.journalMode == PAGER_JOURNALMODE_MEMORY or !isOpen(pPager.jfd)) {
        return SQLITE_OK;
    }
    const zS = zSuper.?;
    pPager.setSuper = 1;

    nSuper = 0;
    while (zS[@intCast(nSuper)] != 0) : (nSuper += 1) {
        cksum +%= zS[@intCast(nSuper)];
    }

    if (pPager.fullSync != 0) {
        pPager.journalOff = journalHdrOffset(pPager);
    }
    iHdrOff = pPager.journalOff;

    rc = write32bits(pPager.jfd, iHdrOff, PAGER_SJ_PGNO(pPager));
    if (rc != 0) return rc;
    rc = sqlite3OsWrite(pPager.jfd, zS, nSuper, iHdrOff + 4);
    if (rc != 0) return rc;
    rc = write32bits(pPager.jfd, iHdrOff + 4 + nSuper, @bitCast(nSuper));
    if (rc != 0) return rc;
    rc = write32bits(pPager.jfd, iHdrOff + 4 + nSuper + 4, cksum);
    if (rc != 0) return rc;
    rc = sqlite3OsWrite(pPager.jfd, &aJournalMagic, 8, iHdrOff + 4 + nSuper + 8);
    if (rc != 0) return rc;
    pPager.journalOff += (nSuper + 20);

    rc = sqlite3OsFileSize(pPager.jfd, &jrnlSize);
    if (rc == SQLITE_OK and jrnlSize > pPager.journalOff) {
        rc = sqlite3OsTruncate(pPager.jfd, pPager.journalOff);
    }
    return rc;
}

// ===================== cache reset / savepoint release =======================

fn pager_reset(pPager: *Pager) void {
    pPager.iDataVersion +%= 1;
    sqlite3BackupRestart(pPager.pBackup);
    sqlite3PcacheClear(pPager.pPCache);
}

fn releaseAllSavepoints(pPager: *Pager) void {
    var ii: c_int = 0;
    while (ii < pPager.nSavepoint) : (ii += 1) {
        sqlite3BitvecDestroy(pPager.aSavepoint.?[@intCast(ii)].pInSavepoint);
    }
    if (pPager.exclusiveMode == 0 or sqlite3JournalIsInMemory(pPager.sjfd) != 0) {
        sqlite3OsClose(pPager.sjfd);
    }
    sqlite3_free(pPager.aSavepoint);
    pPager.aSavepoint = null;
    pPager.nSavepoint = 0;
    pPager.nSubRec = 0;
}

fn addToSavepointBitvecs(pPager: *Pager, pgno: Pgno) c_int {
    var rc: c_int = SQLITE_OK;
    var ii: c_int = 0;
    while (ii < pPager.nSavepoint) : (ii += 1) {
        const p = &pPager.aSavepoint.?[@intCast(ii)];
        if (pgno <= p.nOrig) {
            rc |= sqlite3BitvecSet(p.pInSavepoint, pgno);
        }
    }
    return rc;
}

// ===================== unlock / error / end-transaction =======================

fn pager_unlock(pPager: *Pager) void {
    sqlite3BitvecDestroy(pPager.pInJournal);
    pPager.pInJournal = null;
    releaseAllSavepoints(pPager);

    if (pagerUseWal(pPager)) {
        if (pPager.eState == PAGER_ERROR) {
            _ = sqlite3WalEndWriteTransaction(pPager.pWal);
        }
        sqlite3WalEndReadTransaction(pPager.pWal);
        pPager.eState = PAGER_OPEN;
    } else if (pPager.exclusiveMode == 0) {
        const iDc: c_int = if (isOpen(pPager.fd)) sqlite3OsDeviceCharacteristics(pPager.fd) else 0;
        if (0 == (iDc & SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN) or 1 != (pPager.journalMode & 5)) {
            sqlite3OsClose(pPager.jfd);
        }
        const rc = pagerUnlockDb(pPager, NO_LOCK);
        if (rc != SQLITE_OK and pPager.eState == PAGER_ERROR) {
            pPager.eLock = UNKNOWN_LOCK;
        }
        pPager.eState = PAGER_OPEN;
    }

    if (pPager.errCode != 0) {
        if (pPager.tempFile == 0) {
            pager_reset(pPager);
            pPager.changeCountDone = 0;
            pPager.eState = PAGER_OPEN;
        } else {
            pPager.eState = if (isOpen(pPager.jfd)) PAGER_OPEN else PAGER_READER;
        }
        if (USEFETCH(pPager)) _ = sqlite3OsUnfetch(pPager.fd, 0, null);
        pPager.errCode = SQLITE_OK;
        setGetterMethod(pPager);
    }

    pPager.journalOff = 0;
    pPager.journalHdr = 0;
    pPager.setSuper = 0;
}

fn pager_error(pPager: *Pager, rc: c_int) c_int {
    const rc2 = rc & 0xff;
    if (rc2 == SQLITE_FULL or rc2 == SQLITE_IOERR) {
        pPager.errCode = rc;
        pPager.eState = PAGER_ERROR;
        setGetterMethod(pPager);
    }
    return rc;
}

fn pagerFlushOnCommit(pPager: *Pager, bCommit: c_int) c_int {
    if (pPager.tempFile == 0) return 1;
    if (bCommit == 0) return 0;
    if (!isOpen(pPager.fd)) return 0;
    return @intFromBool(sqlite3PCachePercentDirty(pPager.pPCache) >= 25);
}

fn pager_end_transaction(pPager: *Pager, hasSuper: c_int, bCommit: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    var rc2: c_int = SQLITE_OK;

    if (pPager.eState < PAGER_WRITER_LOCKED and pPager.eLock < RESERVED_LOCK) {
        return SQLITE_OK;
    }

    releaseAllSavepoints(pPager);
    if (isOpen(pPager.jfd)) {
        if (sqlite3JournalIsInMemory(pPager.jfd) != 0) {
            sqlite3OsClose(pPager.jfd);
        } else if (pPager.journalMode == PAGER_JOURNALMODE_TRUNCATE) {
            if (pPager.journalOff == 0) {
                rc = SQLITE_OK;
            } else {
                rc = sqlite3OsTruncate(pPager.jfd, 0);
                if (rc == SQLITE_OK and pPager.fullSync != 0) {
                    rc = sqlite3OsSync(pPager.jfd, pPager.syncFlags);
                }
            }
            pPager.journalOff = 0;
        } else if (pPager.journalMode == PAGER_JOURNALMODE_PERSIST or
            (pPager.exclusiveMode != 0 and pPager.journalMode < PAGER_JOURNALMODE_WAL))
        {
            rc = zeroJournalHdr(pPager, hasSuper | @as(c_int, pPager.tempFile));
            pPager.journalOff = 0;
        } else {
            const bDelete = pPager.tempFile == 0;
            sqlite3OsClose(pPager.jfd);
            if (bDelete) {
                rc = sqlite3OsDelete(pPager.pVfs.?, pPager.zJournal, pPager.extraSync);
            }
        }
    }

    sqlite3BitvecDestroy(pPager.pInJournal);
    pPager.pInJournal = null;
    pPager.nRec = 0;
    if (rc == SQLITE_OK) {
        if (MEMDB(pPager) or pagerFlushOnCommit(pPager, bCommit) != 0) {
            sqlite3PcacheCleanAll(pPager.pPCache);
        } else {
            sqlite3PcacheClearWritable(pPager.pPCache);
        }
        sqlite3PcacheTruncate(pPager.pPCache, pPager.dbSize);
    }

    if (pagerUseWal(pPager)) {
        rc2 = sqlite3WalEndWriteTransaction(pPager.pWal);
    } else if (rc == SQLITE_OK and bCommit != 0 and pPager.dbFileSize > pPager.dbSize) {
        rc = pager_truncate(pPager, pPager.dbSize);
    }

    if (rc == SQLITE_OK and bCommit != 0) {
        rc = sqlite3OsFileControl(pPager.fd, SQLITE_FCNTL_COMMIT_PHASETWO, null);
        if (rc == SQLITE_NOTFOUND) rc = SQLITE_OK;
    }

    if (pPager.exclusiveMode == 0 and
        (!pagerUseWal(pPager) or sqlite3WalExclusiveMode(pPager.pWal, 0) != 0))
    {
        rc2 = pagerUnlockDb(pPager, SHARED_LOCK);
    }
    pPager.eState = PAGER_READER;
    pPager.setSuper = 0;

    return if (rc == SQLITE_OK) rc2 else rc;
}

fn pagerUnlockAndRollback(pPager: *Pager) void {
    if (pPager.eState != PAGER_ERROR and pPager.eState != PAGER_OPEN) {
        if (pPager.eState >= PAGER_WRITER_LOCKED) {
            sqlite3BeginBenignMalloc();
            _ = sqlite3PagerRollback(pPager);
            sqlite3EndBenignMalloc();
        } else if (pPager.exclusiveMode == 0) {
            _ = pager_end_transaction(pPager, 0, 0);
        }
    } else if (pPager.eState == PAGER_ERROR and
        pPager.journalMode == PAGER_JOURNALMODE_MEMORY and isOpen(pPager.jfd))
    {
        const errCode = pPager.errCode;
        const eLock = pPager.eLock;
        pPager.eState = PAGER_OPEN;
        pPager.errCode = SQLITE_OK;
        pPager.eLock = EXCLUSIVE_LOCK;
        _ = pager_playback(pPager, 1);
        pPager.errCode = errCode;
        pPager.eLock = eLock;
    }
    pager_unlock(pPager);
}

fn pager_cksum(pPager: *Pager, aData: [*]const u8) u32 {
    var cksum: u32 = pPager.cksumInit;
    var i: i64 = pPager.pageSize - 200;
    while (i > 0) {
        cksum +%= aData[@intCast(i)];
        i -= 200;
    }
    return cksum;
}

fn pager_playback_one_page(
    pPager: *Pager,
    pOffset: *i64,
    pDone: ?*Bitvec,
    isMainJrnl: c_int,
    isSavepnt: c_int,
) c_int {
    var rc: c_int = undefined;
    var pPg: ?*PgHdr = undefined;
    var pgno: Pgno = undefined;
    var cksum: u32 = undefined;
    const aData: [*]u8 = pPager.pTmpSpace.?;
    var isSynced: bool = undefined;

    const jfd = if (isMainJrnl != 0) pPager.jfd else pPager.sjfd;
    rc = read32bits(jfd, pOffset.*, &pgno);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3OsRead(jfd, aData, @intCast(pPager.pageSize), pOffset.* + 4);
    if (rc != SQLITE_OK) return rc;
    pOffset.* += pPager.pageSize + 4 + isMainJrnl * 4;

    if (pgno == 0 or pgno == PAGER_SJ_PGNO(pPager)) {
        return SQLITE_DONE;
    }
    if (pgno > pPager.dbSize or sqlite3BitvecTest(pDone, pgno) != 0) {
        return SQLITE_OK;
    }
    if (isMainJrnl != 0) {
        rc = read32bits(jfd, pOffset.* - 4, &cksum);
        if (rc != 0) return rc;
        if (isSavepnt == 0 and pager_cksum(pPager, aData) != cksum) {
            return SQLITE_DONE;
        }
    }

    if (pDone != null) {
        rc = sqlite3BitvecSet(pDone, pgno);
        if (rc != SQLITE_OK) return rc;
    }

    if (pgno == 1 and pPager.nReserve != aData[20]) {
        pPager.nReserve = @intCast(aData[20]);
    }

    if (pagerUseWal(pPager)) {
        pPg = null;
    } else {
        pPg = sqlite3PagerLookup(pPager, pgno);
    }

    if (isMainJrnl != 0) {
        isSynced = pPager.noSync != 0 or (pOffset.* <= pPager.journalHdr);
    } else {
        isSynced = (pPg == null or 0 == (pPg.?.flags & PGHDR_NEED_SYNC));
    }
    if (isOpen(pPager.fd) and
        (pPager.eState >= PAGER_WRITER_DBMOD or pPager.eState == PAGER_OPEN) and
        isSynced)
    {
        const ofst: i64 = (@as(i64, pgno) - 1) * pPager.pageSize;
        rc = sqlite3OsWrite(pPager.fd, aData, @intCast(pPager.pageSize), ofst);
        if (pgno > pPager.dbFileSize) {
            pPager.dbFileSize = pgno;
        }
        if (pPager.pBackup != null) {
            sqlite3BackupUpdate(pPager.pBackup, pgno, @ptrCast(aData));
        }
    } else if (isMainJrnl == 0 and pPg == null) {
        pPager.doNotSpill |= SPILLFLAG_ROLLBACK;
        rc = sqlite3PagerGet(pPager, pgno, &pPg, 1);
        pPager.doNotSpill &= ~SPILLFLAG_ROLLBACK;
        if (rc != SQLITE_OK) return rc;
        sqlite3PcacheMakeDirty(pPg.?);
    }
    if (pPg) |pg| {
        const pData = pg.pData.?;
        _ = memcpy(pData, aData, @intCast(pPager.pageSize));
        pPager.xReiniter.?(pg);
        if (pgno == 1) {
            const src: [*]const u8 = @ptrCast(pData);
            _ = memcpy(&pPager.dbFileVers, src + 24, pPager.dbFileVers.len);
        }
        sqlite3PcacheRelease(pg);
    }
    return rc;
}

fn pager_delsuper(pPager: *Pager, zSuper: ?[*:0]const u8) c_int {
    const pVfs = pPager.pVfs.?;
    var rc: c_int = undefined;
    var pSuper: ?*Sqlite3File = undefined;
    var pJournal: *Sqlite3File = undefined;
    var zSuperJournal: ?[*]u8 = null;
    var nSuperJournal: i64 = undefined;
    var zFree: ?[*]u8 = null;

    const blk = sqlite3MallocZero(2 * @as(u64, @intCast(pVfs.szOsFile)));
    if (blk == null) {
        rc = SQLITE_NOMEM;
        pJournal = undefined;
        pSuper = null;
    } else {
        pSuper = @ptrCast(@alignCast(blk.?));
        const flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_SUPER_JOURNAL;
        rc = sqlite3OsOpen(pVfs, zSuper, pSuper.?, flags, null);
        const base: [*]u8 = @ptrCast(blk.?);
        pJournal = @ptrCast(@alignCast(base + @as(usize, @intCast(pVfs.szOsFile))));
    }
    if (rc != SQLITE_OK) {
        // delsuper_out with pSuper possibly set
        return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
    }

    rc = sqlite3OsFileSize(pSuper.?, &nSuperJournal);
    if (rc != SQLITE_OK) return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
    zFree = @ptrCast(@alignCast(sqlite3Malloc(@intCast(4 + nSuperJournal + 2))));
    if (zFree == null) {
        rc = SQLITE_NOMEM;
        return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
    }
    zFree.?[0] = 0;
    zFree.?[1] = 0;
    zFree.?[2] = 0;
    zFree.?[3] = 0;
    zSuperJournal = zFree.? + 4;
    rc = sqlite3OsRead(pSuper.?, zSuperJournal.?, @intCast(nSuperJournal), 0);
    if (rc != SQLITE_OK) return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
    zSuperJournal.?[@intCast(nSuperJournal)] = 0;
    zSuperJournal.?[@intCast(nSuperJournal + 1)] = 0;

    var zJournal: [*]u8 = zSuperJournal.?;
    while ((@intFromPtr(zJournal) - @intFromPtr(zSuperJournal.?)) < nSuperJournal) {
        var exists: c_int = undefined;
        const zJ: [*:0]const u8 = @ptrCast(zJournal);
        rc = sqlite3OsAccess(pVfs, zJ, SQLITE_ACCESS_EXISTS, &exists);
        if (rc != SQLITE_OK) return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
        if (exists != 0) {
            var zSuperPtr: ?[*]u8 = null;
            const flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_SUPER_JOURNAL;
            rc = sqlite3OsOpen(pVfs, zJ, pJournal, flags, null);
            if (rc != SQLITE_OK) return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
            rc = readSuperJournal(pJournal, 1 + @as(u64, @intCast(pVfs.mxPathname)), &zSuperPtr);
            sqlite3OsClose(pJournal);
            if (rc != SQLITE_OK) return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
            const c = zSuperPtr != null and strcmp(@ptrCast(zSuperPtr.?), zSuper) == 0;
            freeSuperJournal(zSuperPtr);
            if (c) return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
        }
        zJournal += @intCast(sqlite3Strlen30(zJ) + 1);
    }

    sqlite3OsClose(pSuper.?);
    rc = sqlite3OsDelete(pVfs, zSuper, 0);
    return delsuperOut(pVfs, pSuper, pJournal, zFree, rc);
}

fn delsuperOut(pVfs: *Sqlite3Vfs, pSuper: ?*Sqlite3File, pJournal: *Sqlite3File, zFree: ?[*]u8, rc: c_int) c_int {
    _ = pVfs;
    _ = pJournal;
    sqlite3_free(zFree);
    if (pSuper) |ps| {
        sqlite3OsClose(ps);
        sqlite3_free(ps);
    }
    return rc;
}

fn pager_truncate(pPager: *Pager, nPage: Pgno) c_int {
    var rc: c_int = SQLITE_OK;
    if (isOpen(pPager.fd) and
        (pPager.eState >= PAGER_WRITER_DBMOD or pPager.eState == PAGER_OPEN))
    {
        var currentSize: i64 = undefined;
        var newSize: i64 = undefined;
        const szPage: i64 = pPager.pageSize;
        rc = sqlite3OsFileSize(pPager.fd, &currentSize);
        newSize = szPage * @as(i64, nPage);
        if (rc == SQLITE_OK and currentSize != newSize) {
            if (currentSize > newSize) {
                rc = sqlite3OsTruncate(pPager.fd, newSize);
            } else if ((currentSize + szPage) <= newSize) {
                const pTmp = pPager.pTmpSpace.?;
                _ = memset(pTmp, 0, @intCast(szPage));
                sqlite3OsFileControlHint(pPager.fd, SQLITE_FCNTL_SIZE_HINT, &newSize);
                rc = sqlite3OsWrite(pPager.fd, pTmp, @intCast(szPage), newSize - szPage);
            }
            if (rc == SQLITE_OK) {
                pPager.dbFileSize = nPage;
            }
        }
    }
    return rc;
}

export fn sqlite3SectorSize(pFile: *Sqlite3File) callconv(.c) c_int {
    var iRet = sqlite3OsSectorSize(pFile);
    if (iRet < 32) {
        iRet = 512;
    } else if (iRet > MAX_SECTOR_SIZE) {
        iRet = MAX_SECTOR_SIZE;
    }
    return iRet;
}

fn setSectorSize(pPager: *Pager) void {
    if (pPager.tempFile != 0 or
        (sqlite3OsDeviceCharacteristics(pPager.fd) & SQLITE_IOCAP_POWERSAFE_OVERWRITE) != 0)
    {
        pPager.sectorSize = 512;
    } else {
        pPager.sectorSize = @intCast(sqlite3SectorSize(pPager.fd));
    }
}

fn pager_playback(pPager: *Pager, isHot: c_int) c_int {
    const pVfs = pPager.pVfs.?;
    var szJ: i64 = undefined;
    var nRec: u32 = undefined;
    var mxPg: Pgno = 0;
    var rc: c_int = undefined;
    var res: c_int = 1;
    var zSuper: ?[*]u8 = null;
    var needPagerReset: c_int = undefined;
    var nPlayback: c_int = 0;
    var savedPageSize: u32 = @intCast(pPager.pageSize);

    rc = sqlite3OsFileSize(pPager.jfd, &szJ);
    if (rc != SQLITE_OK) {
        return playbackEnd(pPager, pVfs, rc, zSuper, isHot, nPlayback, &savedPageSize, res);
    }

    rc = readSuperJournal(pPager.jfd, 1 + @as(u64, @intCast(pPager.pVfs.?.mxPathname)), &zSuper);
    if (rc == SQLITE_OK and zSuper != null) {
        const zS: [*:0]const u8 = @ptrCast(zSuper.?);
        rc = sqlite3OsAccess(pVfs, zS, SQLITE_ACCESS_EXISTS, &res);
    }
    if (rc != SQLITE_OK or res == 0) {
        return playbackEnd(pPager, pVfs, rc, zSuper, isHot, nPlayback, &savedPageSize, res);
    }
    pPager.journalOff = 0;
    needPagerReset = isHot;

    while (true) {
        rc = readJournalHdr(pPager, isHot, szJ, &nRec, &mxPg);
        if (rc != SQLITE_OK) {
            if (rc == SQLITE_DONE) rc = SQLITE_OK;
            break;
        }

        if (nRec == 0xffffffff) {
            nRec = @intCast(@divTrunc(szJ - JOURNAL_HDR_SZ(pPager), JOURNAL_PG_SZ(pPager)));
        }

        if (nRec == 0 and isHot == 0 and
            pPager.journalHdr + JOURNAL_HDR_SZ(pPager) == pPager.journalOff)
        {
            nRec = @intCast(@divTrunc(szJ - pPager.journalOff, JOURNAL_PG_SZ(pPager)));
        }

        if (pPager.journalOff == JOURNAL_HDR_SZ(pPager)) {
            rc = pager_truncate(pPager, mxPg);
            if (rc != SQLITE_OK) break;
            pPager.dbSize = mxPg;
            if (pPager.mxPgno < mxPg) {
                pPager.mxPgno = mxPg;
            }
        }

        var u: u32 = 0;
        var brk = false;
        while (u < nRec) : (u += 1) {
            if (needPagerReset != 0) {
                pager_reset(pPager);
                needPagerReset = 0;
            }
            rc = pager_playback_one_page(pPager, &pPager.journalOff, null, 1, 0);
            if (rc == SQLITE_OK) {
                nPlayback += 1;
            } else {
                if (rc == SQLITE_DONE) {
                    pPager.journalOff = szJ;
                    brk = true;
                    break;
                } else if (rc == SQLITE_IOERR_SHORT_READ) {
                    rc = SQLITE_OK;
                    return playbackEnd(pPager, pVfs, rc, zSuper, isHot, nPlayback, &savedPageSize, res);
                } else {
                    return playbackEnd(pPager, pVfs, rc, zSuper, isHot, nPlayback, &savedPageSize, res);
                }
            }
        }
        if (brk) continue;
    }

    return playbackEnd(pPager, pVfs, rc, zSuper, isHot, nPlayback, &savedPageSize, res);
}

fn playbackEnd(
    pPager: *Pager,
    pVfs: *Sqlite3Vfs,
    rc_in: c_int,
    zSuper: ?[*]u8,
    isHot: c_int,
    nPlayback: c_int,
    savedPageSize: *u32,
    res: c_int,
) c_int {
    _ = pVfs;
    var rc = rc_in;
    if (rc == SQLITE_OK) {
        rc = sqlite3PagerSetPagesize(pPager, savedPageSize, -1);
    }

    pPager.changeCountDone = pPager.tempFile;

    if (rc == SQLITE_OK and
        (pPager.eState >= PAGER_WRITER_DBMOD or pPager.eState == PAGER_OPEN))
    {
        rc = sqlite3PagerSync(pPager, null);
    }
    if (rc == SQLITE_OK) {
        rc = pager_end_transaction(pPager, @intFromBool(zSuper != null), 0);
    }
    if (rc == SQLITE_OK and zSuper != null and res != 0) {
        rc = pager_delsuper(pPager, @ptrCast(zSuper.?));
    }
    if (isHot != 0 and nPlayback != 0) {
        sqlite3_log(SQLITE_NOTICE_RECOVER_ROLLBACK, "recovered %d pages from %s", nPlayback, pPager.zJournal);
    }

    freeSuperJournal(zSuper);
    setSectorSize(pPager);
    return rc;
}

// ===================== read db page / change counter =======================

fn readDbPage(pPg: *PgHdr) c_int {
    const pPager = pPg.pPager.?;
    var rc: c_int = SQLITE_OK;
    var iFrame: u32 = 0;

    if (pagerUseWal(pPager)) {
        rc = sqlite3WalFindFrame(pPager.pWal, pPg.pgno, &iFrame);
        if (rc != 0) return rc;
    }
    if (iFrame != 0) {
        rc = sqlite3WalReadFrame(pPager.pWal, iFrame, @intCast(pPager.pageSize), pPg.pData);
    } else {
        const iOffset: i64 = (@as(i64, pPg.pgno) - 1) * pPager.pageSize;
        rc = sqlite3OsRead(pPager.fd, pPg.pData, @intCast(pPager.pageSize), iOffset);
        if (rc == SQLITE_IOERR_SHORT_READ) {
            rc = SQLITE_OK;
        }
    }

    if (pPg.pgno == 1) {
        if (rc != 0) {
            _ = memset(&pPager.dbFileVers, 0xff, pPager.dbFileVers.len);
        } else {
            const data: [*]const u8 = @ptrCast(pPg.pData.?);
            _ = memcpy(&pPager.dbFileVers, data + 24, pPager.dbFileVers.len);
        }
    }
    if (config.sqlite_test) pPager.nRead += 1;
    return rc;
}

fn pager_write_changecounter(pPg: *PgHdr) void {
    const change_counter = sqlite3Get4byte(&pPg.pPager.?.dbFileVers[0]) +% 1;
    const data: [*]u8 = @ptrCast(pPg.pData.?);
    put32bits(data + 24, change_counter);
    put32bits(data + 92, change_counter);
    put32bits(data + 96, @bitCast(SQLITE_VERSION_NUMBER));
}

// ===================== WAL helpers =======================

fn pagerUndoCallback(pCtx: ?*anyopaque, iPg: Pgno) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pPager: *Pager = @ptrCast(@alignCast(pCtx.?));
    const pPg = sqlite3PagerLookup(pPager, iPg);
    if (pPg) |pg| {
        if (sqlite3PcachePageRefcount(pg) == 1) {
            sqlite3PcacheDrop(pg);
        } else {
            rc = readDbPage(pg);
            if (rc == SQLITE_OK) {
                pPager.xReiniter.?(pg);
            }
            sqlite3PagerUnrefNotNull(pg);
        }
    }
    sqlite3BackupRestart(pPager.pBackup);
    return rc;
}

fn pagerRollbackWal(pPager: *Pager) c_int {
    var rc: c_int = undefined;
    pPager.dbSize = pPager.dbOrigSize;
    rc = sqlite3WalUndo(pPager.pWal, pagerUndoCallback, @ptrCast(pPager));
    var pList = sqlite3PcacheDirtyList(pPager.pPCache);
    while (pList != null and rc == SQLITE_OK) {
        const pNext = pList.?.pDirty;
        rc = pagerUndoCallback(@ptrCast(pPager), pList.?.pgno);
        pList = pNext;
    }
    return rc;
}

fn pagerWalFrames(pPager: *Pager, pList_in: *PgHdr, nTruncate: Pgno, isCommit: c_int) c_int {
    var rc: c_int = undefined;
    var nList: c_int = undefined;
    var p: ?*PgHdr = undefined;
    var pList: *PgHdr = pList_in;

    if (isCommit != 0) {
        // Remove pages with pgno>nTruncate from the pDirty list (C's
        // pointer-to-pointer walk, reimplemented explicitly).
        nList = 0;
        var head: ?*PgHdr = pList;
        var cur: ?*PgHdr = pList;
        var prevLink: *?*PgHdr = &head;
        while (cur) |pg| {
            if (pg.pgno <= nTruncate) {
                prevLink.* = pg;
                prevLink = &pg.pDirty;
                nList += 1;
            }
            cur = pg.pDirty;
        }
        prevLink.* = null;
        pList = head.?;
    } else {
        nList = 1;
    }
    pPager.aStat[PAGER_STAT_WRITE] +%= @intCast(nList);

    if (pList.pgno == 1) pager_write_changecounter(pList);
    rc = sqlite3WalFrames(pPager.pWal, @intCast(pPager.pageSize), pList, nTruncate, isCommit, pPager.walSyncFlags);
    if (rc == SQLITE_OK and pPager.pBackup != null) {
        p = pList;
        while (p) |pg| {
            const d: [*]const u8 = @ptrCast(pg.pData.?);
            sqlite3BackupUpdate(pPager.pBackup, pg.pgno, @ptrCast(d));
            p = pg.pDirty;
        }
    }
    return rc;
}

fn pagerBeginReadTransaction(pPager: *Pager) c_int {
    var rc: c_int = undefined;
    var changed: c_int = 0;

    sqlite3WalEndReadTransaction(pPager.pWal);
    rc = sqlite3WalBeginReadTransaction(pPager.pWal, &changed);
    if (rc != SQLITE_OK or changed != 0) {
        pager_reset(pPager);
        if (USEFETCH(pPager)) _ = sqlite3OsUnfetch(pPager.fd, 0, null);
    }
    return rc;
}

fn pagerPagecount(pPager: *Pager, pnPage: *Pgno) c_int {
    var nPage: Pgno = sqlite3WalDbsize(pPager.pWal);

    if (nPage == 0 and isOpen(pPager.fd)) {
        var n: i64 = 0;
        const rc = sqlite3OsFileSize(pPager.fd, &n);
        if (rc != SQLITE_OK) return rc;
        nPage = @intCast(@divTrunc(n + pPager.pageSize - 1, pPager.pageSize));
    }

    if (nPage > pPager.mxPgno) {
        pPager.mxPgno = nPage;
    }
    pnPage.* = nPage;
    return SQLITE_OK;
}

fn pagerOpenWalIfPresent(pPager: *Pager) c_int {
    var rc: c_int = SQLITE_OK;
    if (pPager.tempFile == 0) {
        var isWal: c_int = undefined;
        rc = sqlite3OsAccess(pPager.pVfs.?, pPager.zWal, SQLITE_ACCESS_EXISTS, &isWal);
        if (rc == SQLITE_OK) {
            if (isWal != 0) {
                var nPage: Pgno = undefined;
                rc = pagerPagecount(pPager, &nPage);
                if (rc != 0) return rc;
                if (nPage == 0) {
                    rc = sqlite3OsDelete(pPager.pVfs.?, pPager.zWal, 0);
                } else {
                    rc = sqlite3PagerOpenWal(pPager, null);
                }
            } else if (pPager.journalMode == PAGER_JOURNALMODE_WAL) {
                pPager.journalMode = PAGER_JOURNALMODE_DELETE;
            }
        }
    }
    return rc;
}

fn pagerPlaybackSavepoint(pPager: *Pager, pSavepoint: ?*PagerSavepoint) c_int {
    var szJ: i64 = undefined;
    var iHdrOff: i64 = undefined;
    var rc: c_int = SQLITE_OK;
    var pDone: ?*Bitvec = null;

    if (pSavepoint) |sp| {
        pDone = sqlite3BitvecCreate(sp.nOrig);
        if (pDone == null) {
            return SQLITE_NOMEM;
        }
    }

    pPager.dbSize = if (pSavepoint) |sp| sp.nOrig else pPager.dbOrigSize;
    pPager.changeCountDone = pPager.tempFile;

    if (pSavepoint == null and pagerUseWal(pPager)) {
        return pagerRollbackWal(pPager);
    }

    szJ = pPager.journalOff;

    if (pSavepoint != null and !pagerUseWal(pPager)) {
        const sp = pSavepoint.?;
        iHdrOff = if (sp.iHdrOffset != 0) sp.iHdrOffset else szJ;
        pPager.journalOff = sp.iOffset;
        while (rc == SQLITE_OK and pPager.journalOff < iHdrOff) {
            rc = pager_playback_one_page(pPager, &pPager.journalOff, pDone, 1, 1);
        }
    } else {
        pPager.journalOff = 0;
    }

    while (rc == SQLITE_OK and pPager.journalOff < szJ) {
        var ii: u32 = undefined;
        var nJRec: u32 = 0;
        var dummy: u32 = undefined;
        rc = readJournalHdr(pPager, 0, szJ, &nJRec, &dummy);

        if (nJRec == 0 and pPager.journalHdr + JOURNAL_HDR_SZ(pPager) == pPager.journalOff) {
            nJRec = @intCast(@divTrunc(szJ - pPager.journalOff, JOURNAL_PG_SZ(pPager)));
        }
        ii = 0;
        while (rc == SQLITE_OK and ii < nJRec and pPager.journalOff < szJ) : (ii += 1) {
            rc = pager_playback_one_page(pPager, &pPager.journalOff, pDone, 1, 1);
        }
    }

    if (pSavepoint) |sp| {
        var ii: u32 = undefined;
        var offset: i64 = @as(i64, sp.iSubRec) * (4 + pPager.pageSize);

        if (pagerUseWal(pPager)) {
            rc = sqlite3WalSavepointUndo(pPager.pWal, &sp.aWalData);
        }
        ii = sp.iSubRec;
        while (rc == SQLITE_OK and ii < pPager.nSubRec) : (ii += 1) {
            rc = pager_playback_one_page(pPager, &offset, pDone, 0, 1);
        }
    }

    sqlite3BitvecDestroy(pDone);
    if (rc == SQLITE_OK) {
        pPager.journalOff = szJ;
    }
    return rc;
}

export fn sqlite3PagerSetCachesize(pPager: *Pager, mxPage: c_int) callconv(.c) void {
    sqlite3PcacheSetCachesize(pPager.pPCache, mxPage);
}

export fn sqlite3PagerSetSpillsize(pPager: *Pager, mxPage: c_int) callconv(.c) c_int {
    return sqlite3PcacheSetSpillsize(pPager.pPCache, mxPage);
}

fn pagerFixMaplimit(pPager: *Pager) void {
    const fd = pPager.fd;
    if (isOpen(fd) and fd.pMethods.?.iVersion >= 3) {
        var sz: i64 = pPager.szMmap;
        pPager.bUseFetch = @intFromBool(sz > 0);
        setGetterMethod(pPager);
        sqlite3OsFileControlHint(pPager.fd, SQLITE_FCNTL_MMAP_SIZE, &sz);
    }
}

export fn sqlite3PagerSetMmapLimit(pPager: *Pager, szMmap: i64) callconv(.c) void {
    pPager.szMmap = szMmap;
    pagerFixMaplimit(pPager);
}

export fn sqlite3PagerShrink(pPager: *Pager) callconv(.c) void {
    sqlite3PcacheShrink(pPager.pPCache);
}

export fn sqlite3PagerSetFlags(pPager: *Pager, pgFlags: c_uint) callconv(.c) void {
    const level = pgFlags & PAGER_SYNCHRONOUS_MASK;
    if (pPager.tempFile != 0 or level == PAGER_SYNCHRONOUS_OFF) {
        pPager.noSync = 1;
        pPager.fullSync = 0;
        pPager.extraSync = 0;
    } else {
        pPager.noSync = 0;
        pPager.fullSync = @intFromBool(level >= PAGER_SYNCHRONOUS_FULL);
        if (level == PAGER_SYNCHRONOUS_EXTRA) {
            pPager.extraSync = 1;
        } else {
            pPager.extraSync = 0;
        }
    }
    if (pPager.noSync != 0) {
        pPager.syncFlags = 0;
    } else if (pgFlags & PAGER_FULLFSYNC != 0) {
        pPager.syncFlags = SQLITE_SYNC_FULL;
    } else {
        pPager.syncFlags = SQLITE_SYNC_NORMAL;
    }
    pPager.walSyncFlags = pPager.syncFlags << 2;
    if (pPager.fullSync != 0) {
        pPager.walSyncFlags |= pPager.syncFlags;
    }
    if ((pgFlags & PAGER_CKPT_FULLFSYNC) != 0 and pPager.noSync == 0) {
        pPager.walSyncFlags |= (SQLITE_SYNC_FULL << 2);
    }
    if (pgFlags & PAGER_CACHESPILL != 0) {
        pPager.doNotSpill &= ~SPILLFLAG_OFF;
    } else {
        pPager.doNotSpill |= SPILLFLAG_OFF;
    }
}

fn pagerOpentemp(pPager: *Pager, pFile: *Sqlite3File, vfsFlags_in: c_int) c_int {
    if (config.sqlite_test) opentemp_count += 1;
    const vfsFlags = vfsFlags_in | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
        SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_DELETEONCLOSE;
    const rc = sqlite3OsOpen(pPager.pVfs.?, null, pFile, vfsFlags, null);
    return rc;
}

export fn sqlite3PagerSetBusyHandler(
    pPager: *Pager,
    xBusyHandler: ?*const fn (?*anyopaque) callconv(.c) c_int,
    pBusyHandlerArg: ?*anyopaque,
) callconv(.c) void {
    pPager.xBusyHandler = xBusyHandler;
    pPager.pBusyHandlerArg = pBusyHandlerArg;
    const ap: *?*anyopaque = @ptrCast(&pPager.xBusyHandler);
    sqlite3OsFileControlHint(pPager.fd, SQLITE_FCNTL_BUSYHANDLER, @ptrCast(ap));
}

export fn sqlite3PagerSetPagesize(pPager: *Pager, pPageSize: *u32, nReserve_in: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var nReserve = nReserve_in;
    const pageSize = pPageSize.*;
    if ((pPager.memDb == 0 or pPager.dbSize == 0) and
        sqlite3PcacheRefCount(pPager.pPCache) == 0 and
        pageSize != 0 and pageSize != @as(u32, @intCast(pPager.pageSize)))
    {
        var pNew: ?[*]u8 = null;
        var nByte: i64 = 0;

        if (pPager.eState > PAGER_OPEN and isOpen(pPager.fd)) {
            rc = sqlite3OsFileSize(pPager.fd, &nByte);
        }
        if (rc == SQLITE_OK) {
            pNew = @ptrCast(sqlite3PageMalloc(@intCast(pageSize + 8)));
            if (pNew == null) {
                rc = SQLITE_NOMEM;
            } else {
                _ = memset(pNew.? + pageSize, 0, 8);
            }
        }

        if (rc == SQLITE_OK) {
            pager_reset(pPager);
            rc = sqlite3PcacheSetPageSize(pPager.pPCache, @intCast(pageSize));
        }
        if (rc == SQLITE_OK) {
            sqlite3PageFree(pPager.pTmpSpace);
            pPager.pTmpSpace = pNew;
            pPager.dbSize = @intCast(@divTrunc(nByte + pageSize - 1, pageSize));
            pPager.pageSize = pageSize;
            pPager.lckPgno = @as(Pgno, @intCast(@divTrunc(pendingByte(), @as(i64, pageSize)))) + 1;
        } else {
            sqlite3PageFree(pNew);
        }
    }

    pPageSize.* = @intCast(pPager.pageSize);
    if (rc == SQLITE_OK) {
        if (nReserve < 0) nReserve = pPager.nReserve;
        pPager.nReserve = @intCast(nReserve);
        pagerFixMaplimit(pPager);
    }
    return rc;
}

export fn sqlite3PagerTempSpace(pPager: *Pager) callconv(.c) ?*anyopaque {
    return pPager.pTmpSpace;
}

export fn sqlite3PagerMaxPageCount(pPager: *Pager, mxPage: Pgno) callconv(.c) Pgno {
    if (mxPage > 0) {
        pPager.mxPgno = mxPage;
    }
    return pPager.mxPgno;
}

export fn sqlite3PagerReadFileheader(pPager: *Pager, N: c_int, pDest: [*]u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    _ = memset(pDest, 0, @intCast(N));
    if (isOpen(pPager.fd)) {
        rc = sqlite3OsRead(pPager.fd, pDest, N, 0);
        if (rc == SQLITE_IOERR_SHORT_READ) {
            rc = SQLITE_OK;
        }
    }
    return rc;
}

export fn sqlite3PagerPagecount(pPager: *Pager, pnPage: *c_int) callconv(.c) void {
    pnPage.* = @intCast(pPager.dbSize);
}

fn pager_wait_on_lock(pPager: *Pager, locktype: u8) c_int {
    var rc: c_int = undefined;
    while (true) {
        rc = pagerLockDb(pPager, locktype);
        if (!(rc == SQLITE_BUSY and pPager.xBusyHandler.?(pPager.pBusyHandlerArg) != 0)) break;
    }
    return rc;
}

export fn sqlite3PagerTruncateImage(pPager: *Pager, nPage: Pgno) callconv(.c) void {
    pPager.dbSize = nPage;
}

fn pagerSyncHotJournal(pPager: *Pager) c_int {
    var rc: c_int = SQLITE_OK;
    if (pPager.noSync == 0) {
        rc = sqlite3OsSync(pPager.jfd, SQLITE_SYNC_NORMAL);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3OsFileSize(pPager.jfd, &pPager.journalHdr);
    }
    return rc;
}

fn pagerAcquireMapPage(pPager: *Pager, pgno: Pgno, pData: ?*anyopaque, ppPage: *?*PgHdr) c_int {
    var p: *PgHdr = undefined;
    if (pPager.pMmapFreelist) |fl| {
        p = fl;
        ppPage.* = p;
        pPager.pMmapFreelist = p.pDirty;
        p.pDirty = null;
        _ = memset(p.pExtra, 0, 8);
    } else {
        const blk = sqlite3MallocZero(@sizeOf(PgHdr) + pPager.nExtra);
        if (blk == null) {
            _ = sqlite3OsUnfetch(pPager.fd, @as(i64, pgno - 1) * pPager.pageSize, pData);
            return SQLITE_NOMEM;
        }
        p = @ptrCast(@alignCast(blk.?));
        ppPage.* = p;
        const base: [*]u8 = @ptrCast(blk.?);
        p.pExtra = @ptrCast(base + @sizeOf(PgHdr));
        p.flags = PGHDR_MMAP;
        p.nRef = 1;
        p.pPager = pPager;
    }

    p.pgno = pgno;
    p.pData = pData;
    pPager.nMmapOut += 1;
    return SQLITE_OK;
}

fn pagerReleaseMapPage(pPg: *PgHdr) void {
    const pPager = pPg.pPager.?;
    pPager.nMmapOut -= 1;
    pPg.pDirty = pPager.pMmapFreelist;
    pPager.pMmapFreelist = pPg;
    _ = sqlite3OsUnfetch(pPager.fd, @as(i64, pPg.pgno - 1) * pPager.pageSize, pPg.pData);
}

fn pagerFreeMapHdrs(pPager: *Pager) void {
    var p = pPager.pMmapFreelist;
    while (p) |pg| {
        const pNext = pg.pDirty;
        sqlite3_free(pg);
        p = pNext;
    }
}

fn databaseIsUnmoved(pPager: *Pager) c_int {
    var bHasMoved: c_int = 0;
    if (pPager.tempFile != 0) return SQLITE_OK;
    if (pPager.dbSize == 0) return SQLITE_OK;
    var rc = sqlite3OsFileControl(pPager.fd, SQLITE_FCNTL_HAS_MOVED, &bHasMoved);
    if (rc == SQLITE_NOTFOUND) {
        rc = SQLITE_OK;
    } else if (rc == SQLITE_OK and bHasMoved != 0) {
        rc = SQLITE_READONLY_DBMOVED;
    }
    return rc;
}

export fn sqlite3PagerClose(pPager: *Pager, db: ?*Sqlite3) callconv(.c) c_int {
    const pTmp = pPager.pTmpSpace;
    disableSimulatedIoErrors();
    sqlite3BeginBenignMalloc();
    pagerFreeMapHdrs(pPager);
    pPager.exclusiveMode = 0;
    {
        var a: ?[*]u8 = null;
        if (db != null and 0 == (dbFlags(db.?) & SQLITE_NoCkptOnClose) and
            SQLITE_OK == databaseIsUnmoved(pPager))
        {
            a = pTmp;
        }
        _ = sqlite3WalClose(pPager.pWal, db, pPager.walSyncFlags, @intCast(pPager.pageSize), a);
        pPager.pWal = null;
    }
    pager_reset(pPager);
    if (MEMDB(pPager)) {
        pager_unlock(pPager);
    } else {
        if (isOpen(pPager.jfd)) {
            _ = pager_error(pPager, pagerSyncHotJournal(pPager));
        }
        pagerUnlockAndRollback(pPager);
    }
    sqlite3EndBenignMalloc();
    enableSimulatedIoErrors();
    sqlite3OsClose(pPager.jfd);
    sqlite3OsClose(pPager.fd);
    sqlite3PageFree(pTmp);
    sqlite3PcacheClose(pPager.pPCache);
    sqlite3_free(pPager);
    return SQLITE_OK;
}

/// db->flags read at its ground-truth offset (sqlite3_flags, config-invariant).
inline fn dbFlags(db: *Sqlite3) u64 {
    const base: [*]const u8 = @ptrCast(db);
    const p: *align(1) const u64 = @ptrCast(base + L.sqlite3_flags);
    return p.*;
}

export fn sqlite3PagerRef(pPg: *PgHdr) callconv(.c) void {
    sqlite3PcacheRef(pPg);
}

fn syncJournal(pPager: *Pager, newHdr: c_int) c_int {
    var rc: c_int = undefined;

    rc = sqlite3PagerExclusiveLock(pPager);
    if (rc != SQLITE_OK) return rc;

    if (pPager.noSync == 0) {
        if (isOpen(pPager.jfd) and pPager.journalMode != PAGER_JOURNALMODE_MEMORY) {
            const iDc = sqlite3OsDeviceCharacteristics(pPager.fd);
            if (0 == (iDc & SQLITE_IOCAP_SAFE_APPEND)) {
                var iNextHdrOffset: i64 = undefined;
                var aMagic: [8]u8 = undefined;
                var zHeader: [aJournalMagic.len + 4]u8 = undefined;

                _ = memcpy(&zHeader, &aJournalMagic, aJournalMagic.len);
                put32bits(@as([*]u8, &zHeader) + aJournalMagic.len, @bitCast(pPager.nRec));

                iNextHdrOffset = journalHdrOffset(pPager);
                rc = sqlite3OsRead(pPager.jfd, &aMagic, 8, iNextHdrOffset);
                if (rc == SQLITE_OK and 0 == memcmp(&aMagic, &aJournalMagic, 8)) {
                    const zerobyte: u8 = 0;
                    rc = sqlite3OsWrite(pPager.jfd, &zerobyte, 1, iNextHdrOffset);
                }
                if (rc != SQLITE_OK and rc != SQLITE_IOERR_SHORT_READ) {
                    return rc;
                }

                if (pPager.fullSync != 0 and 0 == (iDc & SQLITE_IOCAP_SEQUENTIAL)) {
                    rc = sqlite3OsSync(pPager.jfd, pPager.syncFlags);
                    if (rc != SQLITE_OK) return rc;
                }
                rc = sqlite3OsWrite(pPager.jfd, &zHeader, zHeader.len, pPager.journalHdr);
                if (rc != SQLITE_OK) return rc;
            }
            if (0 == (iDc & SQLITE_IOCAP_SEQUENTIAL)) {
                const extra: c_int = if (pPager.syncFlags == SQLITE_SYNC_FULL) SQLITE_SYNC_DATAONLY else 0;
                rc = sqlite3OsSync(pPager.jfd, @as(c_int, pPager.syncFlags) | extra);
                if (rc != SQLITE_OK) return rc;
            }

            pPager.journalHdr = pPager.journalOff;
            if (newHdr != 0 and 0 == (iDc & SQLITE_IOCAP_SAFE_APPEND)) {
                pPager.nRec = 0;
                rc = writeJournalHdr(pPager);
                if (rc != SQLITE_OK) return rc;
            }
        } else {
            pPager.journalHdr = pPager.journalOff;
        }
    }

    sqlite3PcacheClearSyncFlags(pPager.pPCache);
    pPager.eState = PAGER_WRITER_DBMOD;
    return SQLITE_OK;
}

fn pager_write_pagelist(pPager: *Pager, pList_in: ?*PgHdr) c_int {
    var rc: c_int = SQLITE_OK;
    var pList = pList_in;

    if (!isOpen(pPager.fd)) {
        rc = pagerOpentemp(pPager, pPager.fd, @bitCast(pPager.vfsFlags));
    }

    if (rc == SQLITE_OK and
        pPager.dbHintSize < pPager.dbSize and
        (pList.?.pDirty != null or pList.?.pgno > pPager.dbHintSize))
    {
        var szFile: i64 = pPager.pageSize * @as(i64, pPager.dbSize);
        sqlite3OsFileControlHint(pPager.fd, SQLITE_FCNTL_SIZE_HINT, &szFile);
        pPager.dbHintSize = pPager.dbSize;
    }

    while (rc == SQLITE_OK and pList != null) {
        const pg = pList.?;
        const pgno = pg.pgno;

        if (pgno <= pPager.dbSize and 0 == (pg.flags & PGHDR_DONT_WRITE)) {
            const offset: i64 = (@as(i64, pgno) - 1) * pPager.pageSize;
            if (pg.pgno == 1) pager_write_changecounter(pg);
            const pData = pg.pData.?;
            rc = sqlite3OsWrite(pPager.fd, pData, @intCast(pPager.pageSize), offset);
            if (pgno == 1) {
                const d: [*]const u8 = @ptrCast(pData);
                _ = memcpy(&pPager.dbFileVers, d + 24, pPager.dbFileVers.len);
            }
            if (pgno > pPager.dbFileSize) {
                pPager.dbFileSize = pgno;
            }
            pPager.aStat[PAGER_STAT_WRITE] +%= 1;
            sqlite3BackupUpdate(pPager.pBackup, pgno, @ptrCast(pg.pData.?));
        }
        pList = pg.pDirty;
    }
    return rc;
}

fn openSubJournal(pPager: *Pager) c_int {
    var rc: c_int = SQLITE_OK;
    if (!isOpen(pPager.sjfd)) {
        const flags = SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_READWRITE |
            SQLITE_OPEN_CREATE | SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_DELETEONCLOSE;
        var nStmtSpillVal = nStmtSpill();
        if (pPager.journalMode == PAGER_JOURNALMODE_MEMORY or pPager.subjInMemory != 0) {
            nStmtSpillVal = -1;
        }
        rc = sqlite3JournalOpen(pPager.pVfs.?, null, pPager.sjfd, flags, nStmtSpillVal);
    }
    return rc;
}

fn subjournalPage(pPg: *PgHdr) c_int {
    var rc: c_int = SQLITE_OK;
    const pPager = pPg.pPager.?;
    if (pPager.journalMode != PAGER_JOURNALMODE_OFF) {
        rc = openSubJournal(pPager);
        if (rc == SQLITE_OK) {
            const pData = pPg.pData;
            const offset: i64 = @as(i64, pPager.nSubRec) * (4 + pPager.pageSize);
            rc = write32bits(pPager.sjfd, offset, pPg.pgno);
            if (rc == SQLITE_OK) {
                rc = sqlite3OsWrite(pPager.sjfd, pData, @intCast(pPager.pageSize), offset + 4);
            }
        }
    }
    if (rc == SQLITE_OK) {
        pPager.nSubRec += 1;
        rc = addToSavepointBitvecs(pPager, pPg.pgno);
    }
    return rc;
}

fn subjournalPageIfRequired(pPg: *PgHdr) c_int {
    if (subjRequiresPage(pPg) != 0) {
        return subjournalPage(pPg);
    } else {
        return SQLITE_OK;
    }
}

fn pagerStress(p: ?*anyopaque, pPg_opt: ?*PgHdr) callconv(.c) c_int {
    const pPager: *Pager = @ptrCast(@alignCast(p.?));
    const pPg = pPg_opt.?;
    var rc: c_int = SQLITE_OK;

    if (pPager.errCode != 0) return SQLITE_OK;
    if (pPager.doNotSpill != 0 and
        ((pPager.doNotSpill & (SPILLFLAG_ROLLBACK | SPILLFLAG_OFF)) != 0 or
            (pPg.flags & PGHDR_NEED_SYNC) != 0))
    {
        return SQLITE_OK;
    }

    pPager.aStat[PAGER_STAT_SPILL] +%= 1;
    pPg.pDirty = null;
    if (pagerUseWal(pPager)) {
        rc = subjournalPageIfRequired(pPg);
        if (rc == SQLITE_OK) {
            rc = pagerWalFrames(pPager, pPg, 0, 0);
        }
    } else {
        if (pPg.flags & PGHDR_NEED_SYNC != 0 or pPager.eState == PAGER_WRITER_CACHEMOD) {
            rc = syncJournal(pPager, 1);
        }
        if (rc == SQLITE_OK) {
            rc = pager_write_pagelist(pPager, pPg);
        }
    }

    if (rc == SQLITE_OK) {
        sqlite3PcacheMakeClean(pPg);
    }
    return pager_error(pPager, rc);
}

export fn sqlite3PagerFlush(pPager: *Pager) callconv(.c) c_int {
    var rc = pPager.errCode;
    if (!MEMDB(pPager)) {
        var pList = sqlite3PcacheDirtyList(pPager.pPCache);
        while (rc == SQLITE_OK and pList != null) {
            const pNext = pList.?.pDirty;
            if (pList.?.nRef == 0) {
                rc = pagerStress(@ptrCast(pPager), pList.?);
            }
            pList = pNext;
        }
    }
    return rc;
}

export fn sqlite3PagerOpen(
    pVfs: *Sqlite3Vfs,
    ppPager: *?*Pager,
    zFilename_in: ?[*:0]const u8,
    nExtra_in: c_int,
    flags: c_int,
    vfsFlags_in: c_int,
    xReinit: ?*const fn (*PgHdr) callconv(.c) void,
) callconv(.c) c_int {
    var zFilename = zFilename_in;
    var vfsFlags = vfsFlags_in;
    var nExtra = nExtra_in;
    var pPager: *Pager = undefined;
    var rc: c_int = SQLITE_OK;
    var tempFile: c_int = 0;
    var memDb: c_int = 0;
    var memJM: c_int = 0;
    var readOnly: c_int = 0;
    var zPathname: ?[*]u8 = null;
    var nPathname: c_int = 0;
    const useJournal: c_int = @intFromBool((flags & PAGER_OMIT_JOURNAL) == 0);
    const pcacheSize = sqlite3PcacheSize();
    var szPageDflt: u32 = SQLITE_DEFAULT_PAGE_SIZE;
    var zUri: ?[*:0]const u8 = null;
    var nUriByte: c_int = 1;

    const journalFileSize: c_int = @intCast(ROUND8(usize, @intCast(sqlite3JournalSize(pVfs))));

    ppPager.* = null;

    if (flags & PAGER_MEMORY != 0) {
        memDb = 1;
        if (zFilename != null and zFilename.?[0] != 0) {
            zPathname = sqlite3DbStrDup(null, zFilename);
            if (zPathname == null) return SQLITE_NOMEM;
            nPathname = sqlite3Strlen30(@ptrCast(zPathname.?));
            zFilename = null;
        }
    }

    if (zFilename != null and zFilename.?[0] != 0) {
        nPathname = pVfs.mxPathname + 1;
        zPathname = @ptrCast(sqlite3DbMallocRaw(null, 2 * @as(u64, @intCast(nPathname))));
        if (zPathname == null) {
            return SQLITE_NOMEM;
        }
        zPathname.?[0] = 0;
        rc = sqlite3OsFullPathname(pVfs, zFilename, nPathname, zPathname.?);
        if (rc != SQLITE_OK) {
            if (rc == SQLITE_OK_SYMLINK) {
                if (vfsFlags & SQLITE_OPEN_NOFOLLOW != 0) {
                    rc = SQLITE_CANTOPEN_SYMLINK;
                } else {
                    rc = SQLITE_OK;
                }
            }
        }
        nPathname = sqlite3Strlen30(@ptrCast(zPathname.?));
        const fnLen = sqlite3Strlen30(zFilename);
        var z: [*:0]const u8 = @ptrCast(zFilename.? + @as(usize, @intCast(fnLen)) + 1);
        zUri = z;
        while (z[0] != 0) {
            z = @ptrCast(z + strlen(z) + 1);
            z = @ptrCast(z + strlen(z) + 1);
        }
        nUriByte = @intCast(@intFromPtr(z + 1) - @intFromPtr(zUri.?));
        if (rc == SQLITE_OK and nPathname + 8 > pVfs.mxPathname) {
            rc = SQLITE_CANTOPEN;
        }
        if (rc != SQLITE_OK) {
            sqlite3DbFree(null, zPathname);
            return rc;
        }
    }

    const totalSize: u64 =
        ROUND8(usize, @sizeOf(Pager)) +
        ROUND8(usize, @intCast(pcacheSize)) +
        ROUND8(usize, @intCast(pVfs.szOsFile)) +
        @as(u64, @intCast(journalFileSize)) * 2 +
        SQLITE_PTRSIZE +
        4 +
        @as(u64, @intCast(nPathname)) + 1 +
        @as(u64, @intCast(nUriByte)) +
        @as(u64, @intCast(nPathname)) + 8 + 1 +
        @as(u64, @intCast(nPathname)) + 4 + 1 +
        3;
    const blk = sqlite3MallocZero(totalSize);
    if (blk == null) {
        sqlite3DbFree(null, zPathname);
        return SQLITE_NOMEM;
    }
    var pPtr: [*]u8 = @ptrCast(blk.?);
    pPager = @ptrCast(@alignCast(pPtr));
    pPtr += ROUND8(usize, @sizeOf(Pager));
    pPager.pPCache = @ptrCast(pPtr);
    pPtr += ROUND8(usize, @intCast(pcacheSize));
    pPager.fd = @ptrCast(@alignCast(pPtr));
    pPtr += ROUND8(usize, @intCast(pVfs.szOsFile));
    pPager.sjfd = @ptrCast(@alignCast(pPtr));
    pPtr += @intCast(journalFileSize);
    pPager.jfd = @ptrCast(@alignCast(pPtr));
    pPtr += @intCast(journalFileSize);
    var pPagerPtr = pPager;
    _ = memcpy(pPtr, @as(*anyopaque, @ptrCast(&pPagerPtr)), SQLITE_PTRSIZE);
    pPtr += SQLITE_PTRSIZE;

    pPtr += 4; // skip zero prefix
    pPager.zFilename = @ptrCast(pPtr);
    if (nPathname > 0) {
        _ = memcpy(pPtr, zPathname.?, @intCast(nPathname));
        pPtr += @as(usize, @intCast(nPathname)) + 1;
        if (zUri) |uri| {
            _ = memcpy(pPtr, uri, @intCast(nUriByte));
            pPtr += @intCast(nUriByte);
        } else {
            pPtr += 1;
        }
    }

    if (nPathname > 0) {
        pPager.zJournal = @ptrCast(pPtr);
        _ = memcpy(pPtr, zPathname.?, @intCast(nPathname));
        pPtr += @intCast(nPathname);
        _ = memcpy(pPtr, "-journal", 8);
        pPtr += 8 + 1;
    } else {
        pPager.zJournal = null;
    }

    if (nPathname > 0) {
        pPager.zWal = @ptrCast(pPtr);
        _ = memcpy(pPtr, zPathname.?, @intCast(nPathname));
        pPtr += @intCast(nPathname);
        _ = memcpy(pPtr, "-wal", 4);
        pPtr += 4 + 1;
    } else {
        pPager.zWal = null;
    }

    if (nPathname != 0) sqlite3DbFree(null, zPathname);
    pPager.pVfs = pVfs;
    pPager.vfsFlags = @bitCast(vfsFlags);

    var didTempFile = false;
    if (zFilename != null and zFilename.?[0] != 0) {
        var fout: c_int = 0;
        rc = sqlite3OsOpen(pVfs, pPager.zFilename, pPager.fd, vfsFlags, &fout);
        memJM = @intFromBool((fout & SQLITE_OPEN_MEMORY) != 0);
        pPager.memVfs = @intCast(memJM);
        readOnly = @intFromBool((fout & SQLITE_OPEN_READONLY) != 0);

        if (rc == SQLITE_OK) {
            const iDc = sqlite3OsDeviceCharacteristics(pPager.fd);
            if (readOnly == 0) {
                setSectorSize(pPager);
                if (szPageDflt < pPager.sectorSize) {
                    if (pPager.sectorSize > SQLITE_MAX_DEFAULT_PAGE_SIZE) {
                        szPageDflt = SQLITE_MAX_DEFAULT_PAGE_SIZE;
                    } else {
                        szPageDflt = pPager.sectorSize;
                    }
                }
            }
            pPager.noLock = @intCast(sqlite3_uri_boolean(pPager.zFilename, "nolock", 0));
            if ((iDc & SQLITE_IOCAP_IMMUTABLE) != 0 or
                sqlite3_uri_boolean(pPager.zFilename, "immutable", 0) != 0)
            {
                vfsFlags |= SQLITE_OPEN_READONLY;
                didTempFile = true;
            }
        }
    } else {
        didTempFile = true;
    }

    if (didTempFile) {
        // act_like_temp_file:
        tempFile = 1;
        pPager.eState = PAGER_READER;
        pPager.eLock = EXCLUSIVE_LOCK;
        pPager.noLock = 1;
        readOnly = vfsFlags & SQLITE_OPEN_READONLY;
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3PagerSetPagesize(pPager, &szPageDflt, -1);
    }

    if (rc == SQLITE_OK) {
        nExtra = @intCast(ROUND8(usize, @intCast(nExtra)));
        rc = sqlite3PcacheOpen(@intCast(szPageDflt), nExtra, @intFromBool(memDb == 0), if (memDb == 0) pagerStress else null, @ptrCast(pPager), pPager.pPCache);
    }

    if (rc != SQLITE_OK) {
        sqlite3OsClose(pPager.fd);
        sqlite3PageFree(pPager.pTmpSpace);
        sqlite3_free(pPager);
        return rc;
    }

    pPager.useJournal = @intCast(useJournal);
    pPager.mxPgno = SQLITE_MAX_PAGE_COUNT;
    pPager.tempFile = @intCast(tempFile);
    pPager.exclusiveMode = @intCast(tempFile);
    pPager.changeCountDone = pPager.tempFile;
    pPager.memDb = @intCast(memDb);
    pPager.readOnly = @intCast(readOnly);
    sqlite3PagerSetFlags(pPager, (SQLITE_DEFAULT_SYNCHRONOUS + 1) | PAGER_CACHESPILL);
    pPager.nExtra = @intCast(nExtra);
    pPager.journalSizeLimit = SQLITE_DEFAULT_JOURNAL_SIZE_LIMIT;
    setSectorSize(pPager);
    if (useJournal == 0) {
        pPager.journalMode = PAGER_JOURNALMODE_OFF;
    } else if (memDb != 0 or memJM != 0) {
        pPager.journalMode = PAGER_JOURNALMODE_MEMORY;
    }
    pPager.xReiniter = xReinit;
    setGetterMethod(pPager);

    ppPager.* = pPager;
    return SQLITE_OK;
}

export fn sqlite3_database_file_object(zName_in: [*:0]const u8) callconv(.c) *Sqlite3File {
    var zName: [*]const u8 = @constCast(zName_in);
    while (true) {
        const m1 = (zName - 1)[0];
        const m2 = (zName - 2)[0];
        const m3 = (zName - 3)[0];
        const m4 = (zName - 4)[0];
        if (m1 == 0 and m2 == 0 and m3 == 0 and m4 == 0) break;
        zName -= 1;
    }
    const p = zName - 4 - SQLITE_PTRSIZE;
    const pPager: *Pager = @as(*align(1) *Pager, @ptrCast(@constCast(p))).*;
    return pPager.fd;
}

fn hasHotJournal(pPager: *Pager, pExists: *c_int) c_int {
    const pVfs = pPager.pVfs.?;
    var rc: c_int = SQLITE_OK;
    var exists: c_int = 1;
    const jrnlOpen: c_int = @intFromBool(isOpen(pPager.jfd));

    pExists.* = 0;
    if (jrnlOpen == 0) {
        rc = sqlite3OsAccess(pVfs, pPager.zJournal, SQLITE_ACCESS_EXISTS, &exists);
    }
    if (rc == SQLITE_OK and exists != 0) {
        var locked: c_int = 0;
        rc = sqlite3OsCheckReservedLock(pPager.fd, &locked);
        if (rc == SQLITE_OK and locked == 0) {
            var nPage: Pgno = undefined;
            rc = pagerPagecount(pPager, &nPage);
            if (rc == SQLITE_OK) {
                if (nPage == 0 and jrnlOpen == 0) {
                    sqlite3BeginBenignMalloc();
                    if (pagerLockDb(pPager, RESERVED_LOCK) == SQLITE_OK) {
                        _ = sqlite3OsDelete(pVfs, pPager.zJournal, 0);
                        if (pPager.exclusiveMode == 0) _ = pagerUnlockDb(pPager, SHARED_LOCK);
                    }
                    sqlite3EndBenignMalloc();
                } else {
                    if (jrnlOpen == 0) {
                        const f = SQLITE_OPEN_READONLY | SQLITE_OPEN_MAIN_JOURNAL;
                        rc = sqlite3OsOpen(pVfs, pPager.zJournal, pPager.jfd, f, null);
                    }
                    if (rc == SQLITE_OK) {
                        var first: u8 = 0;
                        rc = sqlite3OsRead(pPager.jfd, &first, 1, 0);
                        if (rc == SQLITE_IOERR_SHORT_READ) {
                            rc = SQLITE_OK;
                        }
                        if (jrnlOpen == 0) {
                            sqlite3OsClose(pPager.jfd);
                        }
                        pExists.* = @intFromBool(first != 0);
                    } else if (rc == SQLITE_CANTOPEN) {
                        pExists.* = 1;
                        rc = SQLITE_OK;
                    }
                }
            }
        }
    }
    return rc;
}

export fn sqlite3PagerSharedLock(pPager: *Pager) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (!pagerUseWal(pPager) and pPager.eState == PAGER_OPEN) {
        var bHotJournal: c_int = 1;

        rc = pager_wait_on_lock(pPager, SHARED_LOCK);
        if (rc != SQLITE_OK) {
            return sharedFailed(pPager, rc);
        }

        if (pPager.eLock <= SHARED_LOCK) {
            rc = hasHotJournal(pPager, &bHotJournal);
        }
        if (rc != SQLITE_OK) {
            return sharedFailed(pPager, rc);
        }
        if (bHotJournal != 0) {
            if (pPager.readOnly != 0) {
                return sharedFailed(pPager, SQLITE_READONLY_ROLLBACK);
            }

            rc = pagerLockDb(pPager, EXCLUSIVE_LOCK);
            if (rc != SQLITE_OK) {
                return sharedFailed(pPager, rc);
            }

            if (!isOpen(pPager.jfd) and pPager.journalMode != PAGER_JOURNALMODE_OFF) {
                const pVfs = pPager.pVfs.?;
                var bExists: c_int = undefined;
                rc = sqlite3OsAccess(pVfs, pPager.zJournal, SQLITE_ACCESS_EXISTS, &bExists);
                if (rc == SQLITE_OK and bExists != 0) {
                    var fout: c_int = 0;
                    const f = SQLITE_OPEN_READWRITE | SQLITE_OPEN_MAIN_JOURNAL;
                    rc = sqlite3OsOpen(pVfs, pPager.zJournal, pPager.jfd, f, &fout);
                    if (rc == SQLITE_OK and fout & SQLITE_OPEN_READONLY != 0) {
                        rc = SQLITE_CANTOPEN;
                        sqlite3OsClose(pPager.jfd);
                    }
                }
            }

            if (isOpen(pPager.jfd)) {
                rc = pagerSyncHotJournal(pPager);
                if (rc == SQLITE_OK) {
                    rc = pager_playback(pPager, @intFromBool(pPager.tempFile == 0));
                    pPager.eState = PAGER_OPEN;
                }
            } else if (pPager.exclusiveMode == 0) {
                _ = pagerUnlockDb(pPager, SHARED_LOCK);
            }

            if (rc != SQLITE_OK) {
                _ = pager_error(pPager, rc);
                return sharedFailed(pPager, rc);
            }
        }

        if (pPager.tempFile == 0 and pPager.hasHeldSharedLock != 0) {
            var dbFileVers: [16]u8 = undefined;
            rc = sqlite3OsRead(pPager.fd, &dbFileVers, dbFileVers.len, 24);
            if (rc != SQLITE_OK) {
                if (rc != SQLITE_IOERR_SHORT_READ) {
                    return sharedFailed(pPager, rc);
                }
                _ = memset(&dbFileVers, 0, dbFileVers.len);
            }

            if (memcmp(&pPager.dbFileVers, &dbFileVers, dbFileVers.len) != 0) {
                pager_reset(pPager);
                if (USEFETCH(pPager)) {
                    _ = sqlite3OsUnfetch(pPager.fd, 0, null);
                }
            }
        }

        rc = pagerOpenWalIfPresent(pPager);
    }

    if (pagerUseWal(pPager)) {
        rc = pagerBeginReadTransaction(pPager);
    }

    if (pPager.tempFile == 0 and pPager.eState == PAGER_OPEN and rc == SQLITE_OK) {
        rc = pagerPagecount(pPager, &pPager.dbSize);
    }

    if (rc != SQLITE_OK) {
        pager_unlock(pPager);
    } else {
        pPager.eState = PAGER_READER;
        pPager.hasHeldSharedLock = 1;
    }
    return rc;
}

fn sharedFailed(pPager: *Pager, rc: c_int) c_int {
    pager_unlock(pPager);
    return rc;
}

fn pagerUnlockIfUnused(pPager: *Pager) void {
    if (sqlite3PcacheRefCount(pPager.pPCache) == 0) {
        pagerUnlockAndRollback(pPager);
    }
}

fn getPageNormal(pPager: *Pager, pgno: Pgno, ppPage: *?*PgHdr, flags: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var pPg: ?*PgHdr = undefined;
    var pBase: ?*Sqlite3PcachePage = undefined;

    if (pgno == 0) return SQLITE_CORRUPT;
    pBase = sqlite3PcacheFetch(pPager.pPCache, pgno, 3);
    if (pBase == null) {
        pPg = null;
        rc = sqlite3PcacheFetchStress(pPager.pPCache, pgno, &pBase);
        if (rc != SQLITE_OK) return acquireErr(pPager, pPg, ppPage, rc);
        if (pBase == null) {
            rc = SQLITE_NOMEM;
            return acquireErr(pPager, pPg, ppPage, rc);
        }
    }
    pPg = sqlite3PcacheFetchFinish(pPager.pPCache, pgno, pBase.?);
    ppPage.* = pPg;

    const noContent = (flags & PAGER_GET_NOCONTENT) != 0;
    if (pPg.?.pPager != null and !noContent) {
        pPager.aStat[PAGER_STAT_HIT] +%= 1;
        return SQLITE_OK;
    } else {
        if (pgno == PAGER_SJ_PGNO(pPager)) {
            rc = SQLITE_CORRUPT;
            return acquireErr(pPager, pPg, ppPage, rc);
        }

        pPg.?.pPager = pPager;

        if (!isOpen(pPager.fd) or pPager.dbSize < pgno or noContent) {
            if (pgno > pPager.mxPgno) {
                rc = SQLITE_FULL;
                if (pgno <= pPager.dbSize) {
                    sqlite3PcacheRelease(pPg.?);
                    pPg = null;
                }
                return acquireErr(pPager, pPg, ppPage, rc);
            }
            if (noContent) {
                sqlite3BeginBenignMalloc();
                if (pgno <= pPager.dbOrigSize) {
                    _ = sqlite3BitvecSet(pPager.pInJournal, pgno);
                }
                _ = addToSavepointBitvecs(pPager, pgno);
                sqlite3EndBenignMalloc();
            }
            _ = memset(pPg.?.pData, 0, @intCast(pPager.pageSize));
        } else {
            pPager.aStat[PAGER_STAT_MISS] +%= 1;
            rc = readDbPage(pPg.?);
            if (rc != SQLITE_OK) {
                return acquireErr(pPager, pPg, ppPage, rc);
            }
        }
    }
    return SQLITE_OK;
}

fn acquireErr(pPager: *Pager, pPg: ?*PgHdr, ppPage: *?*PgHdr, rc: c_int) c_int {
    if (pPg) |pg| {
        sqlite3PcacheDrop(pg);
    }
    pagerUnlockIfUnused(pPager);
    ppPage.* = null;
    return rc;
}

fn getPageMMap(pPager: *Pager, pgno: Pgno, ppPage: *?*PgHdr, flags: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var pPg: ?*PgHdr = null;
    var iFrame: u32 = 0;

    const bMmapOk = (pgno > 1 and
        (pPager.eState == PAGER_READER or (flags & PAGER_GET_READONLY) != 0));

    if (pgno <= 1 and pgno == 0) {
        return SQLITE_CORRUPT;
    }

    if (bMmapOk and pagerUseWal(pPager)) {
        rc = sqlite3WalFindFrame(pPager.pWal, pgno, &iFrame);
        if (rc != SQLITE_OK) {
            ppPage.* = null;
            return rc;
        }
    }
    if (bMmapOk and iFrame == 0) {
        var pData: ?*anyopaque = null;
        rc = sqlite3OsFetch(pPager.fd, @as(i64, pgno - 1) * pPager.pageSize, @intCast(pPager.pageSize), &pData);
        if (rc == SQLITE_OK and pData != null) {
            if (pPager.eState > PAGER_READER or pPager.tempFile != 0) {
                pPg = sqlite3PagerLookup(pPager, pgno);
            }
            if (pPg == null) {
                rc = pagerAcquireMapPage(pPager, pgno, pData, &pPg);
            } else {
                _ = sqlite3OsUnfetch(pPager.fd, @as(i64, pgno - 1) * pPager.pageSize, pData);
            }
            if (pPg) |pg| {
                ppPage.* = pg;
                return SQLITE_OK;
            }
        }
        if (rc != SQLITE_OK) {
            ppPage.* = null;
            return rc;
        }
    }
    return getPageNormal(pPager, pgno, ppPage, flags);
}

fn getPageError(pPager: *Pager, pgno: Pgno, ppPage: *?*PgHdr, flags: c_int) callconv(.c) c_int {
    _ = pgno;
    _ = flags;
    ppPage.* = null;
    return pPager.errCode;
}

export fn sqlite3PagerGet(pPager: *Pager, pgno: Pgno, ppPage: *?*PgHdr, flags: c_int) callconv(.c) c_int {
    return pPager.xGet.?(pPager, pgno, ppPage, flags);
}

export fn sqlite3PagerLookup(pPager: *Pager, pgno: Pgno) callconv(.c) ?*PgHdr {
    const pPage = sqlite3PcacheFetch(pPager.pPCache, pgno, 0);
    if (pPage == null) return null;
    return sqlite3PcacheFetchFinish(pPager.pPCache, pgno, pPage.?);
}

export fn sqlite3PagerUnrefNotNull(pPg: *PgHdr) callconv(.c) void {
    if (pPg.flags & PGHDR_MMAP != 0) {
        pagerReleaseMapPage(pPg);
    } else {
        sqlite3PcacheRelease(pPg);
    }
}

export fn sqlite3PagerUnref(pPg: ?*PgHdr) callconv(.c) void {
    if (pPg) |p| sqlite3PagerUnrefNotNull(p);
}

export fn sqlite3PagerUnrefPageOne(pPg: *PgHdr) callconv(.c) void {
    const pPager = pPg.pPager.?;
    sqlite3PcacheRelease(pPg);
    pagerUnlockIfUnused(pPager);
}

fn pager_open_journal(pPager: *Pager) c_int {
    var rc: c_int = SQLITE_OK;
    const pVfs = pPager.pVfs.?;

    if (pPager.errCode != 0) return pPager.errCode;

    if (!pagerUseWal(pPager) and pPager.journalMode != PAGER_JOURNALMODE_OFF) {
        pPager.pInJournal = sqlite3BitvecCreate(pPager.dbSize);
        if (pPager.pInJournal == null) {
            return SQLITE_NOMEM;
        }

        if (!isOpen(pPager.jfd)) {
            if (pPager.journalMode == PAGER_JOURNALMODE_MEMORY) {
                sqlite3MemJournalOpen(pPager.jfd);
            } else {
                var flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
                var nSpill: c_int = undefined;
                if (pPager.tempFile != 0) {
                    flags |= (SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_TEMP_JOURNAL);
                    flags |= SQLITE_OPEN_EXCLUSIVE;
                    nSpill = nStmtSpill();
                } else {
                    flags |= SQLITE_OPEN_MAIN_JOURNAL;
                    nSpill = jrnlBufferSize(pPager);
                }

                rc = databaseIsUnmoved(pPager);
                if (rc == SQLITE_OK) {
                    rc = sqlite3JournalOpen(pVfs, pPager.zJournal, pPager.jfd, flags, nSpill);
                }
            }
        }

        if (rc == SQLITE_OK) {
            pPager.nRec = 0;
            pPager.journalOff = 0;
            pPager.setSuper = 0;
            pPager.journalHdr = 0;
            rc = writeJournalHdr(pPager);
        }
    }

    if (rc != SQLITE_OK) {
        sqlite3BitvecDestroy(pPager.pInJournal);
        pPager.pInJournal = null;
        pPager.journalOff = 0;
    } else {
        pPager.eState = PAGER_WRITER_CACHEMOD;
    }
    return rc;
}

export fn sqlite3PagerBegin(pPager: *Pager, exFlag: c_int, subjInMemory: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPager.errCode != 0) return pPager.errCode;
    pPager.subjInMemory = @intCast(subjInMemory);

    if (pPager.eState == PAGER_READER) {
        if (pagerUseWal(pPager)) {
            if (pPager.exclusiveMode != 0 and sqlite3WalExclusiveMode(pPager.pWal, -1) != 0) {
                rc = pagerLockDb(pPager, EXCLUSIVE_LOCK);
                if (rc != SQLITE_OK) {
                    return rc;
                }
                _ = sqlite3WalExclusiveMode(pPager.pWal, 1);
            }
            rc = sqlite3WalBeginWriteTransaction(pPager.pWal);
        } else {
            rc = pagerLockDb(pPager, RESERVED_LOCK);
            if (rc == SQLITE_OK and exFlag != 0) {
                rc = pager_wait_on_lock(pPager, EXCLUSIVE_LOCK);
            }
        }

        if (rc == SQLITE_OK) {
            pPager.eState = PAGER_WRITER_LOCKED;
            pPager.dbHintSize = pPager.dbSize;
            pPager.dbFileSize = pPager.dbSize;
            pPager.dbOrigSize = pPager.dbSize;
            pPager.journalOff = 0;
        }
    }
    return rc;
}

fn pagerAddPageToRollbackJournal(pPg: *PgHdr) c_int {
    const pPager = pPg.pPager.?;
    var rc: c_int = undefined;
    var cksum: u32 = undefined;
    const iOff: i64 = pPager.journalOff;

    const pData2: [*]const u8 = @ptrCast(pPg.pData.?);
    cksum = pager_cksum(pPager, pData2);

    pPg.flags |= PGHDR_NEED_SYNC;

    rc = write32bits(pPager.jfd, iOff, pPg.pgno);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3OsWrite(pPager.jfd, pData2, @intCast(pPager.pageSize), iOff + 4);
    if (rc != SQLITE_OK) return rc;
    rc = write32bits(pPager.jfd, iOff + pPager.pageSize + 4, cksum);
    if (rc != SQLITE_OK) return rc;

    pPager.journalOff += 8 + pPager.pageSize;
    pPager.nRec += 1;
    rc = sqlite3BitvecSet(pPager.pInJournal, pPg.pgno);
    rc |= addToSavepointBitvecs(pPager, pPg.pgno);
    return rc;
}

fn pager_write(pPg: *PgHdr) c_int {
    const pPager = pPg.pPager.?;
    var rc: c_int = SQLITE_OK;

    if (pPager.eState == PAGER_WRITER_LOCKED) {
        rc = pager_open_journal(pPager);
        if (rc != SQLITE_OK) return rc;
    }

    sqlite3PcacheMakeDirty(pPg);

    if (pPager.pInJournal != null and
        sqlite3BitvecTestNotNull(pPager.pInJournal, pPg.pgno) == 0)
    {
        if (pPg.pgno <= pPager.dbOrigSize) {
            rc = pagerAddPageToRollbackJournal(pPg);
            if (rc != SQLITE_OK) {
                return rc;
            }
        } else {
            if (pPager.eState != PAGER_WRITER_DBMOD) {
                pPg.flags |= PGHDR_NEED_SYNC;
            }
        }
    }

    pPg.flags |= PGHDR_WRITEABLE;

    if (pPager.nSavepoint > 0) {
        rc = subjournalPageIfRequired(pPg);
    }

    if (pPager.dbSize < pPg.pgno) {
        pPager.dbSize = pPg.pgno;
    }
    return rc;
}

fn pagerWriteLargeSector(pPg: *PgHdr) c_int {
    var rc: c_int = SQLITE_OK;
    var nPageCount: Pgno = undefined;
    var pg1: Pgno = undefined;
    var nPage: c_int = 0;
    var ii: c_int = undefined;
    var needSync: c_int = 0;
    const pPager = pPg.pPager.?;
    const nPagePerSector: Pgno = @intCast(@divTrunc(pPager.sectorSize, @as(u32, @intCast(pPager.pageSize))));

    pPager.doNotSpill |= SPILLFLAG_NOSYNC;

    pg1 = ((pPg.pgno - 1) & ~(nPagePerSector - 1)) + 1;

    nPageCount = pPager.dbSize;
    if (pPg.pgno > nPageCount) {
        nPage = @intCast(pPg.pgno - pg1 + 1);
    } else if ((pg1 + nPagePerSector - 1) > nPageCount) {
        nPage = @intCast(nPageCount + 1 - pg1);
    } else {
        nPage = @intCast(nPagePerSector);
    }

    ii = 0;
    while (ii < nPage and rc == SQLITE_OK) : (ii += 1) {
        const pg: Pgno = pg1 + @as(Pgno, @intCast(ii));
        var pPage: ?*PgHdr = undefined;
        if (pg == pPg.pgno or sqlite3BitvecTest(pPager.pInJournal, pg) == 0) {
            if (pg != PAGER_SJ_PGNO(pPager)) {
                rc = sqlite3PagerGet(pPager, pg, &pPage, 0);
                if (rc == SQLITE_OK) {
                    rc = pager_write(pPage.?);
                    if (pPage.?.flags & PGHDR_NEED_SYNC != 0) {
                        needSync = 1;
                    }
                    sqlite3PagerUnrefNotNull(pPage.?);
                }
            }
        } else {
            pPage = sqlite3PagerLookup(pPager, pg);
            if (pPage) |pp| {
                if (pp.flags & PGHDR_NEED_SYNC != 0) {
                    needSync = 1;
                }
                sqlite3PagerUnrefNotNull(pp);
            }
        }
    }

    if (rc == SQLITE_OK and needSync != 0) {
        ii = 0;
        while (ii < nPage) : (ii += 1) {
            const pPage = sqlite3PagerLookup(pPager, pg1 + @as(Pgno, @intCast(ii)));
            if (pPage) |pp| {
                pp.flags |= PGHDR_NEED_SYNC;
                sqlite3PagerUnrefNotNull(pp);
            }
        }
    }

    pPager.doNotSpill &= ~SPILLFLAG_NOSYNC;
    return rc;
}

export fn sqlite3PagerWrite(pPg: *PgHdr) callconv(.c) c_int {
    const pPager = pPg.pPager.?;
    if ((pPg.flags & PGHDR_WRITEABLE) != 0 and pPager.dbSize >= pPg.pgno) {
        if (pPager.nSavepoint != 0) return subjournalPageIfRequired(pPg);
        return SQLITE_OK;
    } else if (pPager.errCode != 0) {
        return pPager.errCode;
    } else if (pPager.sectorSize > @as(u32, @intCast(pPager.pageSize))) {
        return pagerWriteLargeSector(pPg);
    } else {
        return pager_write(pPg);
    }
}

export fn sqlite3PagerDontWrite(pPg: *PgHdr) callconv(.c) void {
    const pPager = pPg.pPager.?;
    if (pPager.tempFile == 0 and (pPg.flags & PGHDR_DIRTY) != 0 and pPager.nSavepoint == 0) {
        pPg.flags |= PGHDR_DONT_WRITE;
        pPg.flags &= ~PGHDR_WRITEABLE;
    }
}

fn pager_incr_changecounter(pPager: *Pager, isDirectMode: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    _ = isDirectMode; // SQLITE_ENABLE_ATOMIC_WRITE off -> DIRECT_MODE 0

    if (pPager.changeCountDone == 0 and pPager.dbSize > 0) {
        var pPgHdr: ?*PgHdr = undefined;

        rc = sqlite3PagerGet(pPager, 1, &pPgHdr, 0);

        if (rc == SQLITE_OK) {
            rc = sqlite3PagerWrite(pPgHdr.?);
        }

        if (rc == SQLITE_OK) {
            pager_write_changecounter(pPgHdr.?);
            pPager.changeCountDone = 1;
        }

        sqlite3PagerUnref(pPgHdr);
    }
    return rc;
}

export fn sqlite3PagerSync(pPager: *Pager, zSuper: ?[*:0]const u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pArg: ?*anyopaque = @constCast(@ptrCast(zSuper));
    rc = sqlite3OsFileControl(pPager.fd, SQLITE_FCNTL_SYNC, pArg);
    if (rc == SQLITE_NOTFOUND) rc = SQLITE_OK;
    if (rc == SQLITE_OK and pPager.noSync == 0) {
        rc = sqlite3OsSync(pPager.fd, pPager.syncFlags);
    }
    return rc;
}

export fn sqlite3PagerExclusiveLock(pPager: *Pager) callconv(.c) c_int {
    var rc: c_int = pPager.errCode;
    if (rc == SQLITE_OK) {
        if (0 == @intFromBool(pagerUseWal(pPager))) {
            rc = pager_wait_on_lock(pPager, EXCLUSIVE_LOCK);
        }
    }
    return rc;
}

export fn sqlite3PagerCommitPhaseOne(pPager: *Pager, zSuper: ?[*:0]const u8, noSync: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPager.errCode != 0) return pPager.errCode;
    if (sqlite3FaultSim(400) != 0) return SQLITE_IOERR;

    if (pPager.eState < PAGER_WRITER_CACHEMOD) return SQLITE_OK;

    if (0 == pagerFlushOnCommit(pPager, 1)) {
        sqlite3BackupRestart(pPager.pBackup);
    } else {
        var pList: ?*PgHdr = undefined;
        if (pagerUseWal(pPager)) {
            var pPageOne: ?*PgHdr = null;
            pList = sqlite3PcacheDirtyList(pPager.pPCache);
            if (pList == null) {
                rc = sqlite3PagerGet(pPager, 1, &pPageOne, 0);
                pList = pPageOne;
                pList.?.pDirty = null;
            }
            if (pList) |pl| {
                rc = pagerWalFrames(pPager, pl, pPager.dbSize, 1);
            }
            sqlite3PagerUnref(pPageOne);
            if (rc == SQLITE_OK) {
                sqlite3PcacheCleanAll(pPager.pPCache);
            }
        } else {
            // SQLITE_ENABLE_ATOMIC_WRITE / BATCH_ATOMIC_WRITE off -> indirect mode.
            rc = pager_incr_changecounter(pPager, 0);
            if (rc != SQLITE_OK) return commitP1Exit(pPager, rc);

            rc = writeSuperJournal(pPager, zSuper);
            if (rc != SQLITE_OK) return commitP1Exit(pPager, rc);

            rc = syncJournal(pPager, 0);
            if (rc != SQLITE_OK) return commitP1Exit(pPager, rc);

            pList = sqlite3PcacheDirtyList(pPager.pPCache);
            rc = pager_write_pagelist(pPager, pList);
            if (rc != SQLITE_OK) {
                return commitP1Exit(pPager, rc);
            }
            sqlite3PcacheCleanAll(pPager.pPCache);

            if (pPager.dbSize > pPager.dbFileSize) {
                const nNew: Pgno = pPager.dbSize - @intFromBool(pPager.dbSize == PAGER_SJ_PGNO(pPager));
                rc = pager_truncate(pPager, nNew);
                if (rc != SQLITE_OK) return commitP1Exit(pPager, rc);
            }

            if (noSync == 0) {
                rc = sqlite3PagerSync(pPager, zSuper);
            }
        }
    }

    return commitP1Exit(pPager, rc);
}

fn commitP1Exit(pPager: *Pager, rc: c_int) c_int {
    if (rc == SQLITE_OK and !pagerUseWal(pPager)) {
        pPager.eState = PAGER_WRITER_FINISHED;
    }
    return rc;
}

export fn sqlite3PagerCommitPhaseTwo(pPager: *Pager) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPager.errCode != 0) return pPager.errCode;
    pPager.iDataVersion +%= 1;

    if (pPager.eState == PAGER_WRITER_LOCKED and
        pPager.exclusiveMode != 0 and
        pPager.journalMode == PAGER_JOURNALMODE_PERSIST)
    {
        pPager.eState = PAGER_READER;
        return SQLITE_OK;
    }

    rc = pager_end_transaction(pPager, pPager.setSuper, 1);
    return pager_error(pPager, rc);
}

export fn sqlite3PagerRollback(pPager: *Pager) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPager.eState == PAGER_ERROR) return pPager.errCode;
    if (pPager.eState <= PAGER_READER) return SQLITE_OK;

    if (pagerUseWal(pPager)) {
        rc = sqlite3PagerSavepoint(pPager, SAVEPOINT_ROLLBACK, -1);
        const rc2 = pager_end_transaction(pPager, pPager.setSuper, 0);
        if (rc == SQLITE_OK) rc = rc2;
    } else if (!isOpen(pPager.jfd) or pPager.eState == PAGER_WRITER_LOCKED) {
        const eState = pPager.eState;
        rc = pager_end_transaction(pPager, 0, 0);
        if (!MEMDB(pPager) and eState > PAGER_WRITER_LOCKED) {
            pPager.errCode = SQLITE_ABORT;
            pPager.eState = PAGER_ERROR;
            setGetterMethod(pPager);
            return rc;
        }
    } else {
        rc = pager_playback(pPager, 0);
    }

    return pager_error(pPager, rc);
}

export fn sqlite3PagerIsreadonly(pPager: *Pager) callconv(.c) u8 {
    return pPager.readOnly;
}

export fn sqlite3PagerMemUsed(pPager: *Pager) callconv(.c) c_int {
    const perPageSize: c_int = @as(c_int, @intCast(pPager.pageSize)) + pPager.nExtra +
        @as(c_int, @intCast(@sizeOf(PgHdr) + 5 * @sizeOf(*anyopaque)));
    return perPageSize * sqlite3PcachePagecount(pPager.pPCache) +
        sqlite3MallocSize(pPager) + @as(c_int, @intCast(pPager.pageSize));
}

export fn sqlite3PagerPageRefcount(pPage: *PgHdr) callconv(.c) c_int {
    return @intCast(sqlite3PcachePageRefcount(pPage));
}

export fn sqlite3PagerCacheStat(pPager: *Pager, eStat_in: c_int, reset: c_int, pnVal: *u64) callconv(.c) void {
    const eStat: usize = @intCast(eStat_in - SQLITE_DBSTATUS_CACHE_HIT);
    pnVal.* +%= pPager.aStat[eStat];
    if (reset != 0) {
        pPager.aStat[eStat] = 0;
    }
}

export fn sqlite3PagerIsMemdb(pPager: *Pager) callconv(.c) c_int {
    return @intFromBool(pPager.tempFile != 0 or pPager.memVfs != 0);
}

fn pagerOpenSavepoint(pPager: *Pager, nSavepoint: c_int) c_int {
    const rc: c_int = SQLITE_OK;
    const nCurrent = pPager.nSavepoint;
    var ii: c_int = undefined;

    const aNew: ?[*]PagerSavepoint = @ptrCast(@alignCast(sqlite3Realloc(@ptrCast(pPager.aSavepoint), @sizeOf(PagerSavepoint) * @as(u64, @intCast(nSavepoint)))));
    if (aNew == null) {
        return SQLITE_NOMEM;
    }
    _ = memset(&aNew.?[@intCast(nCurrent)], 0, @as(usize, @intCast(nSavepoint - nCurrent)) * @sizeOf(PagerSavepoint));
    pPager.aSavepoint = aNew;

    ii = nCurrent;
    while (ii < nSavepoint) : (ii += 1) {
        const idx: usize = @intCast(ii);
        aNew.?[idx].nOrig = pPager.dbSize;
        if (isOpen(pPager.jfd) and pPager.journalOff > 0) {
            aNew.?[idx].iOffset = pPager.journalOff;
        } else {
            aNew.?[idx].iOffset = JOURNAL_HDR_SZ(pPager);
        }
        aNew.?[idx].iSubRec = pPager.nSubRec;
        aNew.?[idx].pInSavepoint = sqlite3BitvecCreate(pPager.dbSize);
        aNew.?[idx].bTruncateOnRelease = 1;
        if (aNew.?[idx].pInSavepoint == null) {
            return SQLITE_NOMEM;
        }
        if (pagerUseWal(pPager)) {
            sqlite3WalSavepoint(pPager.pWal, &aNew.?[idx].aWalData);
        }
        pPager.nSavepoint = ii + 1;
    }
    return rc;
}

export fn sqlite3PagerOpenSavepoint(pPager: *Pager, nSavepoint: c_int) callconv(.c) c_int {
    if (nSavepoint > pPager.nSavepoint and pPager.useJournal != 0) {
        return pagerOpenSavepoint(pPager, nSavepoint);
    } else {
        return SQLITE_OK;
    }
}

export fn sqlite3PagerSavepoint(pPager: *Pager, op: c_int, iSavepoint: c_int) callconv(.c) c_int {
    var rc: c_int = pPager.errCode;

    if (rc == SQLITE_OK and iSavepoint < pPager.nSavepoint) {
        var ii: c_int = undefined;
        var nNew: c_int = undefined;

        nNew = iSavepoint + (if (op == SAVEPOINT_RELEASE) @as(c_int, 0) else 1);
        ii = nNew;
        while (ii < pPager.nSavepoint) : (ii += 1) {
            sqlite3BitvecDestroy(pPager.aSavepoint.?[@intCast(ii)].pInSavepoint);
        }
        pPager.nSavepoint = nNew;

        if (op == SAVEPOINT_RELEASE) {
            const pRel = &pPager.aSavepoint.?[@intCast(nNew)];
            if (pRel.bTruncateOnRelease != 0 and isOpen(pPager.sjfd)) {
                if (sqlite3JournalIsInMemory(pPager.sjfd) != 0) {
                    const sz: i64 = (pPager.pageSize + 4) * @as(i64, pRel.iSubRec);
                    rc = sqlite3OsTruncate(pPager.sjfd, sz);
                }
                pPager.nSubRec = pRel.iSubRec;
            }
        } else if (pagerUseWal(pPager) or isOpen(pPager.jfd)) {
            const pSavepoint: ?*PagerSavepoint = if (nNew == 0) null else &pPager.aSavepoint.?[@intCast(nNew - 1)];
            rc = pagerPlaybackSavepoint(pPager, pSavepoint);
        }
    }
    return rc;
}

const zFake = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };

export fn sqlite3PagerFilename(pPager: *const Pager, nullIfMemDb: c_int) callconv(.c) ?[*:0]const u8 {
    if (nullIfMemDb != 0 and (pPager.memDb != 0 or sqlite3IsMemdb(pPager.pVfs) != 0)) {
        return @ptrCast(&zFake[4]);
    } else {
        return pPager.zFilename;
    }
}

export fn sqlite3PagerVfs(pPager: *Pager) callconv(.c) *Sqlite3Vfs {
    return pPager.pVfs.?;
}

export fn sqlite3PagerFile(pPager: *Pager) callconv(.c) *Sqlite3File {
    return pPager.fd;
}

export fn sqlite3PagerJrnlFile(pPager: *Pager) callconv(.c) ?*Sqlite3File {
    return if (pPager.pWal != null) sqlite3WalFile(pPager.pWal) else pPager.jfd;
}

export fn sqlite3PagerJournalname(pPager: *Pager) callconv(.c) ?[*:0]const u8 {
    return pPager.zJournal;
}

export fn sqlite3PagerMovepage(pPager: *Pager, pPg: *PgHdr, pgno: Pgno, isCommit: c_int) callconv(.c) c_int {
    var pPgOld: ?*PgHdr = undefined;
    var needSyncPgno: Pgno = 0;
    var rc: c_int = undefined;
    var origPgno: Pgno = undefined;

    if (pPager.tempFile != 0) {
        rc = sqlite3PagerWrite(pPg);
        if (rc != 0) return rc;
    }

    if ((pPg.flags & PGHDR_DIRTY) != 0) {
        rc = subjournalPageIfRequired(pPg);
        if (rc != SQLITE_OK) return rc;
    }

    if ((pPg.flags & PGHDR_NEED_SYNC) != 0 and isCommit == 0) {
        needSyncPgno = pPg.pgno;
    }

    pPg.flags &= ~PGHDR_NEED_SYNC;
    pPgOld = sqlite3PagerLookup(pPager, pgno);
    if (pPgOld) |old| {
        if (old.nRef > 1) {
            sqlite3PagerUnrefNotNull(old);
            return SQLITE_CORRUPT;
        }
        pPg.flags |= (old.flags & PGHDR_NEED_SYNC);
        if (pPager.tempFile != 0) {
            sqlite3PcacheMove(old, pPager.dbSize + 1);
        } else {
            sqlite3PcacheDrop(old);
        }
    }

    origPgno = pPg.pgno;
    sqlite3PcacheMove(pPg, pgno);
    sqlite3PcacheMakeDirty(pPg);

    if (pPager.tempFile != 0 and pPgOld != null) {
        sqlite3PcacheMove(pPgOld.?, origPgno);
        sqlite3PagerUnrefNotNull(pPgOld.?);
    }

    if (needSyncPgno != 0) {
        var pPgHdr: ?*PgHdr = undefined;
        rc = sqlite3PagerGet(pPager, needSyncPgno, &pPgHdr, 0);
        if (rc != SQLITE_OK) {
            if (needSyncPgno <= pPager.dbOrigSize) {
                sqlite3BitvecClear(pPager.pInJournal, needSyncPgno, pPager.pTmpSpace);
            }
            return rc;
        }
        pPgHdr.?.flags |= PGHDR_NEED_SYNC;
        sqlite3PcacheMakeDirty(pPgHdr.?);
        sqlite3PagerUnrefNotNull(pPgHdr.?);
    }

    return SQLITE_OK;
}

export fn sqlite3PagerRekey(pPg: *PgHdr, iNew: Pgno, flags: u16) callconv(.c) void {
    pPg.flags = flags;
    sqlite3PcacheMove(pPg, iNew);
}

export fn sqlite3PagerGetData(pPg: *PgHdr) callconv(.c) ?*anyopaque {
    return pPg.pData;
}

export fn sqlite3PagerGetExtra(pPg: *PgHdr) callconv(.c) ?*anyopaque {
    return pPg.pExtra;
}

export fn sqlite3PagerLockingMode(pPager: *Pager, eMode: c_int) callconv(.c) c_int {
    if (eMode >= 0 and pPager.tempFile == 0 and sqlite3WalHeapMemory(pPager.pWal) == 0) {
        pPager.exclusiveMode = @intCast(eMode);
    }
    return @intCast(pPager.exclusiveMode);
}

export fn sqlite3PagerSetJournalMode(pPager: *Pager, eMode_in: c_int) callconv(.c) c_int {
    var eMode = eMode_in;
    const eOld = pPager.journalMode;

    if (MEMDB(pPager)) {
        if (eMode != PAGER_JOURNALMODE_MEMORY and eMode != PAGER_JOURNALMODE_OFF) {
            eMode = eOld;
        }
    }

    if (eMode != eOld) {
        pPager.journalMode = @intCast(eMode);

        if (pPager.exclusiveMode == 0 and (eOld & 5) == 1 and (eMode & 1) == 0) {
            sqlite3OsClose(pPager.jfd);
            if (pPager.eLock >= RESERVED_LOCK) {
                _ = sqlite3OsDelete(pPager.pVfs.?, pPager.zJournal, 0);
            } else {
                var rc: c_int = SQLITE_OK;
                const state = pPager.eState;
                if (state == PAGER_OPEN) {
                    rc = sqlite3PagerSharedLock(pPager);
                }
                if (pPager.eState == PAGER_READER) {
                    rc = pagerLockDb(pPager, RESERVED_LOCK);
                }
                if (rc == SQLITE_OK) {
                    _ = sqlite3OsDelete(pPager.pVfs.?, pPager.zJournal, 0);
                }
                if (rc == SQLITE_OK and state == PAGER_READER) {
                    _ = pagerUnlockDb(pPager, SHARED_LOCK);
                } else if (state == PAGER_OPEN) {
                    pager_unlock(pPager);
                }
            }
        } else if (eMode == PAGER_JOURNALMODE_OFF or eMode == PAGER_JOURNALMODE_MEMORY) {
            sqlite3OsClose(pPager.jfd);
        }
    }

    return @intCast(pPager.journalMode);
}

export fn sqlite3PagerGetJournalMode(pPager: *Pager) callconv(.c) c_int {
    return @intCast(pPager.journalMode);
}

export fn sqlite3PagerOkToChangeJournalMode(pPager: *Pager) callconv(.c) c_int {
    if (pPager.eState >= PAGER_WRITER_CACHEMOD) return 0;
    if (isOpen(pPager.jfd) and pPager.journalOff > 0) return 0;
    return 1;
}

export fn sqlite3PagerJournalSizeLimit(pPager: *Pager, iLimit: i64) callconv(.c) i64 {
    if (iLimit >= -1) {
        pPager.journalSizeLimit = iLimit;
        sqlite3WalLimit(pPager.pWal, iLimit);
    }
    return pPager.journalSizeLimit;
}

export fn sqlite3PagerBackupPtr(pPager: *Pager) callconv(.c) *?*Backup {
    return &pPager.pBackup;
}

export fn sqlite3PagerClearCache(pPager: *Pager) callconv(.c) void {
    if (pPager.tempFile == 0) pager_reset(pPager);
}

export fn sqlite3PagerDataVersion(pPager: *Pager) callconv(.c) u32 {
    return pPager.iDataVersion;
}

// SQLITE_DIRECT_OVERFLOW_READ (on by default)
export fn sqlite3PagerDirectReadOk(pPager: *Pager, pgno: Pgno) callconv(.c) c_int {
    if (pPager.fd.pMethods == null) return 0;
    if (sqlite3PCacheIsDirty(pPager.pPCache) != 0) return 0;
    if (pPager.pWal != null) {
        var iRead: u32 = 0;
        _ = sqlite3WalFindFrame(pPager.pWal, pgno, &iRead);
        if (iRead != 0) return 0;
    }
    if ((pPager.fd.pMethods.?.xDeviceCharacteristics.?(pPager.fd) & SQLITE_IOCAP_SUBPAGE_READ) == 0) {
        return 0;
    }
    return 1;
}

// ===================== WAL public API =======================

export fn sqlite3PagerCheckpoint(
    pPager: *Pager,
    db: ?*Sqlite3,
    eMode: c_int,
    pnLog: ?*c_int,
    pnCkpt: ?*c_int,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (pPager.pWal == null and pPager.journalMode == PAGER_JOURNALMODE_WAL) {
        _ = sqlite3_exec(db, "PRAGMA table_list", null, null, null);
    }
    if (pPager.pWal != null) {
        rc = sqlite3WalCheckpoint(
            pPager.pWal,
            db,
            eMode,
            if (eMode <= SQLITE_CHECKPOINT_PASSIVE) null else pPager.xBusyHandler,
            pPager.pBusyHandlerArg,
            pPager.walSyncFlags,
            @intCast(pPager.pageSize),
            @ptrCast(pPager.pTmpSpace),
            pnLog,
            pnCkpt,
        );
    }
    return rc;
}

export fn sqlite3PagerWalCallback(pPager: *Pager) callconv(.c) c_int {
    return sqlite3WalCallback(pPager.pWal);
}

export fn sqlite3PagerWalSupported(pPager: *Pager) callconv(.c) c_int {
    const pMethods = pPager.fd.pMethods.?;
    if (pPager.noLock != 0) return 0;
    return @intFromBool(pPager.exclusiveMode != 0 or (pMethods.iVersion >= 2 and pMethods.xShmMap != null));
}

fn pagerExclusiveLock(pPager: *Pager) c_int {
    var rc: c_int = undefined;
    const eOrigLock = pPager.eLock;
    rc = pagerLockDb(pPager, EXCLUSIVE_LOCK);
    if (rc != SQLITE_OK) {
        _ = pagerUnlockDb(pPager, eOrigLock);
    }
    return rc;
}

fn pagerOpenWal(pPager: *Pager) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPager.exclusiveMode != 0) {
        rc = pagerExclusiveLock(pPager);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3WalOpen(
            pPager.pVfs.?,
            pPager.fd,
            pPager.zWal,
            @intCast(pPager.exclusiveMode),
            pPager.journalSizeLimit,
            &pPager.pWal,
        );
    }
    pagerFixMaplimit(pPager);
    return rc;
}

export fn sqlite3PagerOpenWal(pPager: *Pager, pbOpen: ?*c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPager.tempFile == 0 and pPager.pWal == null) {
        if (sqlite3PagerWalSupported(pPager) == 0) return SQLITE_CANTOPEN;
        sqlite3OsClose(pPager.jfd);
        rc = pagerOpenWal(pPager);
        if (rc == SQLITE_OK) {
            pPager.journalMode = PAGER_JOURNALMODE_WAL;
            pPager.eState = PAGER_OPEN;
        }
    } else {
        pbOpen.?.* = 1;
    }
    return rc;
}

export fn sqlite3PagerCloseWal(pPager: *Pager, db: ?*Sqlite3) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPager.pWal == null) {
        var logexists: c_int = 0;
        rc = pagerLockDb(pPager, SHARED_LOCK);
        if (rc == SQLITE_OK) {
            rc = sqlite3OsAccess(pPager.pVfs.?, pPager.zWal, SQLITE_ACCESS_EXISTS, &logexists);
        }
        if (rc == SQLITE_OK and logexists != 0) {
            rc = pagerOpenWal(pPager);
        }
    }

    if (rc == SQLITE_OK and pPager.pWal != null) {
        rc = pagerExclusiveLock(pPager);
        if (rc == SQLITE_OK) {
            rc = sqlite3WalClose(pPager.pWal, db, pPager.walSyncFlags, @intCast(pPager.pageSize), @ptrCast(pPager.pTmpSpace));
            pPager.pWal = null;
            pagerFixMaplimit(pPager);
            if (rc != 0 and pPager.exclusiveMode == 0) _ = pagerUnlockDb(pPager, SHARED_LOCK);
        }
    }
    return rc;
}

// ===================== SQLITE_TEST / SQLITE_DEBUG instrumentation =======================
// These backing globals always exist; the symbols are exported only in the
// matching build config, mirroring the C `#ifdef SQLITE_TEST` / SQLITE_DEBUG.

// SQLITE_TEST globals (pager.c defines them under #ifdef SQLITE_TEST).
var pager_readdb_count: c_int = 0;
var pager_writedb_count: c_int = 0;
var pager_writej_count: c_int = 0;
var opentemp_count: c_int = 0;

// disable/enable_simulated_io_errors — SQLITE_TEST. They poke
// sqlite3_io_error_pending (provided by the Zig os.zig in the test build).
extern var sqlite3_io_error_pending: c_int;
var saved_cnt: c_int = 0;

fn disableSimulatedIoErrorsImpl() callconv(.c) void {
    saved_cnt = sqlite3_io_error_pending;
    sqlite3_io_error_pending = -1;
}
fn enableSimulatedIoErrorsImpl() callconv(.c) void {
    sqlite3_io_error_pending = saved_cnt;
}

/// In the non-test build these are no-ops (matching the C macros). In the test
/// build they delegate to the real impl. We avoid referencing the extern var
/// at all in the non-test build.
inline fn disableSimulatedIoErrors() void {
    if (config.sqlite_test) disableSimulatedIoErrorsImpl();
}
inline fn enableSimulatedIoErrors() void {
    if (config.sqlite_test) enableSimulatedIoErrorsImpl();
}

// SQLITE_TEST-only: int *sqlite3PagerStats(Pager*)
var stats_a: [11]c_int = undefined;
fn pagerStatsImpl(pPager: *Pager) callconv(.c) *[11]c_int {
    stats_a[0] = @intCast(sqlite3PcacheRefCount(pPager.pPCache));
    stats_a[1] = sqlite3PcachePagecount(pPager.pPCache);
    stats_a[2] = sqlite3PcacheGetCachesize(pPager.pPCache);
    stats_a[3] = if (pPager.eState == PAGER_OPEN) -1 else @intCast(pPager.dbSize);
    stats_a[4] = pPager.eState;
    stats_a[5] = pPager.errCode;
    stats_a[6] = @intCast(pPager.aStat[PAGER_STAT_HIT] & 0x7fffffff);
    stats_a[7] = @intCast(pPager.aStat[PAGER_STAT_MISS] & 0x7fffffff);
    stats_a[8] = 0;
    stats_a[9] = pPager.nRead;
    stats_a[10] = @intCast(pPager.aStat[PAGER_STAT_WRITE] & 0x7fffffff);
    return &stats_a;
}

// SQLITE_DEBUG-only: int sqlite3PagerRefcount(Pager*)
fn pagerRefcountImpl(pPager: *Pager) callconv(.c) c_int {
    return @intCast(sqlite3PcacheRefCount(pPager.pPCache));
}

// (!NDEBUG || SQLITE_TEST): Pgno sqlite3PagerPagenumber(DbPage*)
fn pagerPagenumberImpl(pPg: *PgHdr) callconv(.c) Pgno {
    return pPg.pgno;
}

// (!NDEBUG): int sqlite3PagerIswriteable(DbPage*)
fn pagerIswriteableImpl(pPg: *PgHdr) callconv(.c) c_int {
    return pPg.flags & PGHDR_WRITEABLE;
}

comptime {
    if (config.sqlite_test) {
        @export(&pager_readdb_count, .{ .name = "sqlite3_pager_readdb_count" });
        @export(&pager_writedb_count, .{ .name = "sqlite3_pager_writedb_count" });
        @export(&pager_writej_count, .{ .name = "sqlite3_pager_writej_count" });
        @export(&opentemp_count, .{ .name = "sqlite3_opentemp_count" });
        @export(&disableSimulatedIoErrorsImpl, .{ .name = "disable_simulated_io_errors" });
        @export(&enableSimulatedIoErrorsImpl, .{ .name = "enable_simulated_io_errors" });
        @export(&pagerStatsImpl, .{ .name = "sqlite3PagerStats" });
    }
    if (config.sqlite_debug) {
        @export(&pagerRefcountImpl, .{ .name = "sqlite3PagerRefcount" });
        @export(&pagerIswriteableImpl, .{ .name = "sqlite3PagerIswriteable" });
    }
    // sqlite3PagerPagenumber is compiled when (!NDEBUG || SQLITE_TEST),
    // i.e. SQLITE_DEBUG || SQLITE_TEST.
    if (config.sqlite_debug or config.sqlite_test) {
        @export(&pagerPagenumberImpl, .{ .name = "sqlite3PagerPagenumber" });
    }
}
