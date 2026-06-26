//! Zig port of SQLite's B-Tree subsystem (src/btree.c).
//!
//! This is the largest, most intricate module in SQLite (~11600 LOC): the
//! on-disk page format, cursors, balancing, cell insert/delete/overflow,
//! integrity_check, autovacuum ptrmap, and the shared-cache table-lock layer.
//!
//! Drop-in replacement: every external-linkage symbol that upstream btree.c
//! defines is exported below with C ABI. btmutex.c is a SEPARATE module: its
//! sqlite3BtreeEnter*/Leave*/HoldsMutex* are called here as `extern`.
//!
//! ── Struct mirrors ──────────────────────────────────────────────────────────
//! Btree, BtShared, BtCursor, MemPage, CellInfo, BtLock are defined in
//! btreeInt.h (internal to btree.c). Only Btree* / BtCursor* pointers cross the
//! ABI to still-C vdbe/backup, so we own the layout. We mirror each as a Zig
//! `extern struct` at the ground-truth field offsets (probed in BOTH the prod
//! `zig build` and the --dev/SQLITE_DEBUG testfixture configs) and assert the
//! layout at comptime. The ONLY config divergence is `Btree.nSeek` (a
//! SQLITE_DEBUG field): it shifts Btree.lock 48->56 and sizeof 72->80. Every
//! other struct (BtShared, BtCursor, MemPage, CellInfo, BtLock) is byte-
//! identical across configs.
//!
//! ── SQLITE_CORRUPT_BKPT ────────────────────────────────────────────────────
//! btree uses SQLITE_CORRUPT_BKPT / SQLITE_CORRUPT_PGNO / SQLITE_CORRUPT_PAGE
//! heavily. The *_BKPT macro logs (via sqlite3CorruptError) only under
//! SQLITE_DEBUG; in production it is the bare code. We gate the log call on
//! config.sqlite_debug and otherwise return the bare SQLITE_CORRUPT.

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ── Result codes (sqlite.h.in) ──────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_BUSY: c_int = 5;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_READONLY: c_int = 8;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_FULL: c_int = 13;
const SQLITE_EMPTY: c_int = 16;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_NOTADB: c_int = 26;
const SQLITE_ABORT: c_int = 4;
const SQLITE_DONE: c_int = 101;
const SQLITE_OK_SYMLINK: c_int = 0 | (6 << 8); // SQLITE_OK | (6<<8) = 256+0... actually (6<<8)|0
const SQLITE_ABORT_ROLLBACK: c_int = SQLITE_ABORT | (2 << 8); // 516
const SQLITE_BUSY_SNAPSHOT: c_int = SQLITE_BUSY | (2 << 8);
const SQLITE_BUSY_TIMEOUT: c_int = SQLITE_BUSY | (3 << 8);
const SQLITE_IOERR_NOMEM: c_int = SQLITE_IOERR | (12 << 8); // 3082
const SQLITE_CONSTRAINT_PINNED: c_int = SQLITE_CONSTRAINT | (11 << 8);
const SQLITE_LOCKED_SHAREDCACHE: c_int = SQLITE_LOCKED | (1 << 8);

// ── Transaction states (btreeInt.h, == SQLITE_TXN_*) ────────────────────────
const TRANS_NONE: u8 = 0;
const TRANS_READ: u8 = 1;
const TRANS_WRITE: u8 = 2;

// ── BtShared.btsFlags ───────────────────────────────────────────────────────
const BTS_READ_ONLY: u16 = 0x0001;
const BTS_PAGESIZE_FIXED: u16 = 0x0002;
const BTS_SECURE_DELETE: u16 = 0x0004;
const BTS_OVERWRITE: u16 = 0x0008;
const BTS_FAST_SECURE: u16 = 0x000c;
const BTS_INITIALLY_EMPTY: u16 = 0x0010;
const BTS_NO_WAL: u16 = 0x0020;
const BTS_EXCLUSIVE: u16 = 0x0040;
const BTS_PENDING: u16 = 0x0080;

// ── BtCursor.curFlags ───────────────────────────────────────────────────────
const BTCF_WriteFlag: u8 = 0x01;
const BTCF_ValidNKey: u8 = 0x02;
const BTCF_ValidOvfl: u8 = 0x04;
const BTCF_AtLast: u8 = 0x08;
const BTCF_Incrblob: u8 = 0x10;
const BTCF_Multiple: u8 = 0x20;
const BTCF_Pinned: u8 = 0x40;

// ── BtCursor.eState ─────────────────────────────────────────────────────────
const CURSOR_VALID: u8 = 0;
const CURSOR_INVALID: u8 = 1;
const CURSOR_SKIPNEXT: u8 = 2;
const CURSOR_REQUIRESEEK: u8 = 3;
const CURSOR_FAULT: u8 = 4;

// ── Page-type flags ─────────────────────────────────────────────────────────
const PTF_INTKEY: u8 = 0x01;
const PTF_ZERODATA: u8 = 0x02;
const PTF_LEAFDATA: u8 = 0x04;
const PTF_LEAF: u8 = 0x08;

// ── BtLock.eLock ────────────────────────────────────────────────────────────
const READ_LOCK: u8 = 1;
const WRITE_LOCK: u8 = 2;

// ── ptrmap entry types ──────────────────────────────────────────────────────
const PTRMAP_ROOTPAGE: u8 = 1;
const PTRMAP_FREEPAGE: u8 = 2;
const PTRMAP_OVERFLOW1: u8 = 3;
const PTRMAP_OVERFLOW2: u8 = 4;
const PTRMAP_BTREE: u8 = 5;

// ── btree.h public flags ────────────────────────────────────────────────────
const BTREE_INTKEY: c_int = 1;
const BTREE_BLOBKEY: c_int = 2;
const BTREE_MEMORY: c_int = 2;
const BTREE_SINGLE: c_int = 4;
const BTREE_UNORDERED: c_int = 8;
const BTREE_WRCSR: c_int = 0x00000004;
const BTREE_FORDELETE: c_int = 0x00000008;
const BTREE_SAVEPOSITION: u8 = 0x02;
const BTREE_AUXDELETE: u8 = 0x04;
const BTREE_APPEND: u8 = 0x08;
const BTREE_PREFORMAT: u8 = 0x80;
const BTREE_BULKLOAD: c_uint = 0x00000001;
const BTREE_SEEK_EQ: c_uint = 0x00000002;
const BTREE_LARGEST_ROOT_PAGE: c_int = 4;
const BTREE_DATA_VERSION: c_int = 15;
const BTREE_AUTOVACUUM_NONE: c_int = 0;
const BTREE_AUTOVACUUM_FULL: c_int = 1;
const BTREE_AUTOVACUUM_INCR: c_int = 2;

// allocateBtreePage eMode
const BTALLOC_ANY: u8 = 0;
const BTALLOC_EXACT: u8 = 1;
const BTALLOC_LE: u8 = 2;

// Pager flags (pager.h)
const PAGER_GET_NOCONTENT: c_int = 0x01;
const PAGER_GET_READONLY: c_int = 0x02;
const PAGER_JOURNALMODE_WAL: c_int = 5;
const PGHDR_DIRTY: u16 = 0x002;
const PGHDR_WRITEABLE: u16 = 0x004;

// savepoint ops (sqliteInt.h)
const SAVEPOINT_BEGIN: c_int = 0;
const SAVEPOINT_RELEASE: c_int = 1;
const SAVEPOINT_ROLLBACK: c_int = 2;

// sqlite3.flags bits (sqliteInt.h)
const SQLITE_ReadUncommit: u64 = 0x0000000400000000;
const SQLITE_CellSizeCk: u64 = 0x0000200000000000;
const SQLITE_ResetDatabase: u64 = 0x2000000000000000;

// schema flags
const DB_SchemaLoaded: u16 = 0x0001;

// misc constants
const SCHEMA_ROOT: u32 = 1; // root page of sqlite_schema
const BTCURSOR_MAX_DEPTH: c_int = 20;
const BT_MAX_LOCAL: u16 = 65501;
const SQLITE_MAX_PAGE_SIZE: u32 = 65536;
const SQLITE_DEFAULT_CACHE_SIZE: c_int = -2000;
const SQLITE_MAX_LENGTH: c_int = 1000000000;
const PENDING_BYTE: i64 = 0x40000000;
const LARGEST_INT64: i64 = std.math.maxInt(i64);

const SQLITE_FCNTL_PDB: c_int = 30;
const SQLITE_OPEN_MAIN_DB: c_int = 0x00000100;
const SQLITE_OPEN_TEMP_DB: c_int = 0x00000200;
const SQLITE_OPEN_MEMORY: c_int = 0x00000080;
const SQLITE_OPEN_URI: c_int = 0x00000040;
const SQLITE_OPEN_SHAREDCACHE: c_int = 0x00020000;

const SQLITE_MUTEX_STATIC_OPEN: c_int = 4;
const SQLITE_MUTEX_STATIC_MAIN: c_int = 2;
const SQLITE_MUTEX_FAST: c_int = 0;

const OPFLAG_PREFORMAT: u8 = 0x80;
const SQLITE_PRINTF_INTERNAL: u8 = 0x01;

const zMagicHeader = "SQLite format 3\x00";

// ── Forward type aliases (opaque to us) ─────────────────────────────────────
const sqlite3 = anyopaque;
const Pager = anyopaque;
const DbPage = anyopaque;
const Bitvec = anyopaque;
const Schema = anyopaque;
const sqlite3_vfs = anyopaque;
const sqlite3_file = anyopaque;
const sqlite3_mutex = anyopaque;
const KeyInfo = anyopaque;
const Mem = anyopaque;
const sqlite3_value = anyopaque;

// ── CellInfo (config-invariant) ─────────────────────────────────────────────
const CellInfo = extern struct {
    nKey: i64,
    pPayload: ?[*]u8,
    nPayload: u32,
    nLocal: u16,
    nSize: u16,
};

// ── BtLock (config-invariant) ───────────────────────────────────────────────
const BtLock = extern struct {
    pBtree: ?*Btree,
    iTable: u32,
    eLock: u8,
    pNext: ?*BtLock,
};

// xCellSize/xParseCell method types
const XCellSize = *const fn (?*MemPage, ?[*]u8) callconv(.c) u16;
const XParseCell = *const fn (?*MemPage, ?[*]u8, ?*CellInfo) callconv(.c) void;

// ── MemPage (config-invariant; sizeof=136) ──────────────────────────────────
const MemPage = extern struct {
    isInit: u8,
    intKey: u8,
    intKeyLeaf: u8,
    _pad0: u8,
    pgno: u32,
    leaf: u8,
    hdrOffset: u8,
    childPtrSize: u8,
    max1bytePayload: u8,
    nOverflow: u8,
    _pad1: u8,
    maxLocal: u16,
    minLocal: u16,
    cellOffset: u16,
    nFree: c_int,
    nCell: u16,
    maskPage: u16,
    aiOvfl: [4]u16,
    apOvfl: [4]?[*]u8,
    pBt: ?*BtShared,
    aData: ?[*]u8,
    aDataEnd: ?[*]u8,
    aCellIdx: ?[*]u8,
    aDataOfst: ?[*]u8,
    pDbPage: ?*DbPage,
    xCellSize: XCellSize,
    xParseCell: XParseCell,
};

// ── BtShared (config-invariant; sizeof=152) ─────────────────────────────────
const BtShared = extern struct {
    pPager: ?*Pager,
    db: ?*sqlite3,
    pCursor: ?*BtCursor,
    pPage1: ?*MemPage,
    openFlags: u8,
    autoVacuum: u8,
    incrVacuum: u8,
    bDoTruncate: u8,
    inTransaction: u8,
    max1bytePayload: u8,
    nReserveWanted: u8,
    _pad0: u8,
    btsFlags: u16,
    maxLocal: u16,
    minLocal: u16,
    maxLeaf: u16,
    minLeaf: u16,
    _pad1: u16,
    pageSize: u32,
    usableSize: u32,
    nTransaction: c_int,
    nPage: u32,
    pSchema: ?*anyopaque,
    xFreeSchema: ?*const fn (?*anyopaque) callconv(.c) void,
    mutex: ?*sqlite3_mutex,
    pHasContent: ?*Bitvec,
    nRef: c_int,
    _pad2: u32,
    pNext: ?*BtShared,
    pLock: ?*BtLock,
    pWriter: ?*Btree,
    pTmpSpace: ?[*]u8,
    nPreformatSize: c_int,
    _pad3: u32,
};

// ── Btree (config-DIVERGENT: nSeek present only under SQLITE_DEBUG) ──────────
const Btree = if (config.sqlite_debug) extern struct {
    db: ?*sqlite3,
    pBt: ?*BtShared,
    inTrans: u8,
    sharable: u8,
    locked: u8,
    hasIncrblobCur: u8,
    wantToLock: c_int,
    nBackup: c_int,
    iBDataVersion: u32,
    pNext: ?*Btree,
    pPrev: ?*Btree,
    nSeek: u64,
    lock: BtLock,
} else extern struct {
    db: ?*sqlite3,
    pBt: ?*BtShared,
    inTrans: u8,
    sharable: u8,
    locked: u8,
    hasIncrblobCur: u8,
    wantToLock: c_int,
    nBackup: c_int,
    iBDataVersion: u32,
    pNext: ?*Btree,
    pPrev: ?*Btree,
    lock: BtLock,
};

// ── BtCursor (config-invariant; sizeof=296) ─────────────────────────────────
const BtCursor = extern struct {
    eState: u8,
    curFlags: u8,
    curPagerFlags: u8,
    hints: u8,
    skipNext: c_int,
    pBtree: ?*Btree,
    aOverflow: ?[*]u32,
    pKey: ?*anyopaque,
    pBt: ?*BtShared,
    pNext: ?*BtCursor,
    info: CellInfo,
    nKey: i64,
    pgnoRoot: u32,
    iPage: i8,
    curIntKey: u8,
    ix: u16,
    aiIdx: [BTCURSOR_MAX_DEPTH - 1]u16,
    pKeyInfo: ?*KeyInfo,
    pPage: ?*MemPage,
    apPage: [BTCURSOR_MAX_DEPTH - 1]?*MemPage,
};

comptime {
    // MemPage
    std.debug.assert(@offsetOf(MemPage, "pgno") == 4);
    std.debug.assert(@offsetOf(MemPage, "leaf") == 8);
    std.debug.assert(@offsetOf(MemPage, "nOverflow") == 12);
    std.debug.assert(@offsetOf(MemPage, "maxLocal") == 14);
    std.debug.assert(@offsetOf(MemPage, "cellOffset") == 18);
    std.debug.assert(@offsetOf(MemPage, "nFree") == 20);
    std.debug.assert(@offsetOf(MemPage, "nCell") == 24);
    std.debug.assert(@offsetOf(MemPage, "aiOvfl") == 28);
    std.debug.assert(@offsetOf(MemPage, "apOvfl") == 40);
    std.debug.assert(@offsetOf(MemPage, "pBt") == 72);
    std.debug.assert(@offsetOf(MemPage, "aData") == 80);
    std.debug.assert(@offsetOf(MemPage, "pDbPage") == 112);
    std.debug.assert(@offsetOf(MemPage, "xParseCell") == 128);
    std.debug.assert(@sizeOf(MemPage) == 136);
    // BtShared
    std.debug.assert(@offsetOf(BtShared, "inTransaction") == 36);
    std.debug.assert(@offsetOf(BtShared, "btsFlags") == 40);
    std.debug.assert(@offsetOf(BtShared, "pageSize") == 52);
    std.debug.assert(@offsetOf(BtShared, "usableSize") == 56);
    std.debug.assert(@offsetOf(BtShared, "nPage") == 64);
    std.debug.assert(@offsetOf(BtShared, "mutex") == 88);
    std.debug.assert(@offsetOf(BtShared, "pHasContent") == 96);
    std.debug.assert(@offsetOf(BtShared, "pTmpSpace") == 136);
    std.debug.assert(@offsetOf(BtShared, "nPreformatSize") == 144);
    std.debug.assert(@sizeOf(BtShared) == 152);
    // Btree
    std.debug.assert(@offsetOf(Btree, "pBt") == 8);
    std.debug.assert(@offsetOf(Btree, "nBackup") == 24);
    std.debug.assert(@offsetOf(Btree, "lock") == (if (config.sqlite_debug) 56 else 48));
    std.debug.assert(@sizeOf(Btree) == (if (config.sqlite_debug) 80 else 72));
    // BtCursor
    std.debug.assert(@offsetOf(BtCursor, "skipNext") == 4);
    std.debug.assert(@offsetOf(BtCursor, "info") == 48);
    std.debug.assert(@offsetOf(BtCursor, "nKey") == 72);
    std.debug.assert(@offsetOf(BtCursor, "pgnoRoot") == 80);
    std.debug.assert(@offsetOf(BtCursor, "iPage") == 84);
    std.debug.assert(@offsetOf(BtCursor, "ix") == 86);
    std.debug.assert(@offsetOf(BtCursor, "aiIdx") == 88);
    std.debug.assert(@offsetOf(BtCursor, "pKeyInfo") == 128);
    std.debug.assert(@offsetOf(BtCursor, "pPage") == 136);
    std.debug.assert(@offsetOf(BtCursor, "apPage") == 144);
    std.debug.assert(@sizeOf(BtCursor) == 296);
    std.debug.assert(@sizeOf(CellInfo) == 24);
    std.debug.assert(@sizeOf(BtLock) == 24);
}

// ── BtreePayload (btree.h, public ABI in pX) ────────────────────────────────
const BtreePayload = extern struct {
    pKey: ?*const anyopaque,
    nKey: i64,
    pData: ?*const anyopaque,
    aMem: ?*sqlite3_value,
    nMem: u16,
    _pad: [2]u8,
    nData: c_int,
    nZero: c_int,
};

// ── UnpackedRecord (sqliteInt.h) — only leading fields touched ──────────────
const UnpackedRecord = extern struct {
    pKeyInfo: ?*KeyInfo,
    aMem: ?*Mem,
    u: extern union { z: ?[*]u8, i: i64 },
    n: c_int,
    nField: u16,
    default_rc: i8,
    errCode: u8,
    r1: i8,
    r2: i8,
    eqSeen: u8,
};
comptime {
    std.debug.assert(@offsetOf(UnpackedRecord, "nField") == 28);
    std.debug.assert(@offsetOf(UnpackedRecord, "errCode") == 31);
    std.debug.assert(@offsetOf(UnpackedRecord, "eqSeen") == 34);
}

const RecordCompare = *const fn (c_int, ?*const anyopaque, ?*UnpackedRecord) callconv(.c) c_int;

// CellArray — internal balance helper (NB=3)
const NB = 3;
const CellArray = extern struct {
    nCell: c_int,
    pRef: ?*MemPage,
    apCell: ?[*]?[*]u8,
    szCell: ?[*]u16,
    apEnd: [NB * 2]?[*]u8,
    ixNx: [NB * 2]c_int,
};

// ════════════════════════════════════════════════════════════════════════════
// Field-offset helpers for the opaque sqlite3 / Db / KeyInfo / Schema structs
// (all config-invariant). Read via c_layout where available, else probed lit.
// ════════════════════════════════════════════════════════════════════════════
const off_db_mutex: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const off_db_flags: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const off_db_aDb: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const off_db_nDb: usize = 40;
const off_db_szMmap: usize = 64;
const off_db_mallocFailed: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const off_db_nVdbeRead: usize = 212;
const off_db_pAutovacPagesArg: usize = 320;
const off_db_xAutovacPages: usize = 336;
const off_db_xProgress: usize = 544;
const off_db_pProgressArg: usize = 552;
const off_db_nProgressOps: usize = 560;
const off_db_busyHandler: usize = 664;
const off_db_nSavepoint: usize = 768;
const off_db_u1_isInterrupted: usize = 424;

const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
const off_Db_zDbSName: usize = 0;
const off_Db_pBt: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;

const off_KeyInfo_nAllField: usize = 8;
const off_KeyInfo_db: usize = 16;

const off_Schema_idxHash: usize = 32;
const off_Schema_schemaFlags: usize = 114;

inline fn fieldPtr(comptime T: type, base: ?*const anyopaque, off: usize) *align(1) T {
    const b: [*]u8 = @ptrCast(@constCast(base.?));
    return @ptrCast(b + off);
}
inline fn dbMutex(db: ?*sqlite3) ?*sqlite3_mutex {
    return fieldPtr(?*sqlite3_mutex, db, off_db_mutex).*;
}
inline fn dbFlags(db: ?*sqlite3) u64 {
    return fieldPtr(u64, db, off_db_flags).*;
}
inline fn dbFlagsPtr(db: ?*sqlite3) *align(1) u64 {
    return fieldPtr(u64, db, off_db_flags);
}
inline fn dbNDb(db: ?*sqlite3) c_int {
    return fieldPtr(c_int, db, off_db_nDb).*;
}
inline fn dbADb(db: ?*sqlite3) [*]u8 {
    return @ptrCast(fieldPtr(?*anyopaque, db, off_db_aDb).*.?);
}
/// db->aDb[i].pBt
inline fn dbADbPBt(db: ?*sqlite3, i: c_int) ?*Btree {
    const base = dbADb(db);
    const slot = base + @as(usize, @intCast(i)) * sizeof_Db + off_Db_pBt;
    return @as(*align(1) ?*Btree, @ptrCast(slot)).*;
}
inline fn dbInterrupted(db: ?*sqlite3) bool {
    const p: *align(1) volatile c_int = @ptrCast(@as([*]u8, @ptrCast(db.?)) + off_db_u1_isInterrupted);
    return p.* != 0;
}

// ════════════════════════════════════════════════════════════════════════════
// extern C globals + functions
// ════════════════════════════════════════════════════════════════════════════

// sqlite3GlobalConfig — internal name of the `Sqlite3Config sqlite3Config`
// global. Mutable global → `extern var`. We read leading bytes by offset.
extern var sqlite3Config: u8;
// sqlite3Config.sharedCacheEnabled / bCoreMutex offsets (probe-derived).
const off_Config_bCoreMutex: usize = 4;
const off_Config_sharedCacheEnabled: usize = 332;
inline fn cfgBCoreMutex() c_int {
    return @as(*align(1) c_int, @ptrCast(@as([*]u8, @ptrCast(&sqlite3Config)) + off_Config_bCoreMutex)).*;
}
inline fn cfgSharedCacheEnabledPtr() *align(1) c_int {
    return @ptrCast(@as([*]u8, @ptrCast(&sqlite3Config)) + off_Config_sharedCacheEnabled);
}

// PENDING_BYTE is the mutable global sqlite3PendingByte (SQLITE_OMIT_WSD off).
extern var sqlite3PendingByte: c_int;
inline fn pendingByte() i64 {
    return @as(i64, sqlite3PendingByte);
}

// ── btmutex.c (still C) ──────────────────────────────────────────────────────
extern fn sqlite3BtreeEnter(p: ?*Btree) void;
extern fn sqlite3BtreeLeave(p: ?*Btree) void;
extern fn sqlite3_mutex_enter(m: ?*sqlite3_mutex) void;
extern fn sqlite3_mutex_leave(m: ?*sqlite3_mutex) void;
extern fn sqlite3_mutex_free(m: ?*sqlite3_mutex) void;
extern fn sqlite3MutexAlloc(id: c_int) ?*sqlite3_mutex;
extern fn sqlite3_mutex_held(m: ?*sqlite3_mutex) c_int;

// ── malloc / util ────────────────────────────────────────────────────────────
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3MallocSize(p: ?*anyopaque) c_int;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3DbFree(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3DbMallocZero(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3PageMalloc(sz: c_int) ?*anyopaque;
extern fn sqlite3PageFree(p: ?*anyopaque) void;
// sqlite3StackAllocRaw/Free are MACROS (sqliteInt.h). Without SQLITE_USE_ALLOCA
// (off in both configs) they expand to sqlite3DbMallocRaw / sqlite3DbFree.
extern fn sqlite3DbMallocRaw(db: ?*sqlite3, n: u64) ?*anyopaque;
inline fn sqlite3StackAllocRaw(db: ?*sqlite3, n: u64) ?*anyopaque {
    return sqlite3DbMallocRaw(db, n);
}
inline fn sqlite3StackFree(db: ?*sqlite3, p: ?*anyopaque) void {
    sqlite3DbFree(db, p);
}
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3AbsInt32(x: c_int) c_int;
extern fn sqlite3Get4byte(p: ?[*]const u8) u32;
extern fn sqlite3Put4byte(p: ?[*]u8, v: u32) void;
extern fn sqlite3GetVarint(p: [*]const u8, v: *u64) u8;
extern fn sqlite3GetVarint32(p: [*]const u8, v: *u32) u8;
extern fn sqlite3PutVarint(p: [*]u8, v: u64) c_int;
extern fn sqlite3FaultSim(iTest: c_int) c_int;
extern fn sqlite3BeginBenignMalloc() void;
extern fn sqlite3EndBenignMalloc() void;
extern fn sqlite3_mprintf(z: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3ReportError(iErr: c_int, lineno: c_int, zType: [*:0]const u8) c_int;
extern fn sqlite3CorruptError(lineno: c_int) c_int;
extern fn sqlite3NomemError(lineno: c_int) c_int;
extern fn sqlite3MisuseError(lineno: c_int) c_int;
extern fn sqlite3InvokeBusyHandler(p: ?*anyopaque) c_int;
// sqlite3ConnectionBlocked is a no-op MACRO unless SQLITE_ENABLE_UNLOCK_NOTIFY
// or SQLITE_ENABLE_SETLK_TIMEOUT (both off in our build).
inline fn sqlite3ConnectionBlocked(db: ?*sqlite3, blocker: ?*sqlite3) void {
    _ = db;
    _ = blocker;
}
extern fn sqlite3WritableSchema(db: ?*sqlite3) c_int;
extern fn sqlite3TempInMemory(db: ?*sqlite3) c_int;
extern fn sqlite3MemSetArrayInt64(aMem: ?*sqlite3_value, iIdx: c_int, val: i64) void;
extern fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

// ── StrAccum (sqlite_str) helpers for integrity_check ───────────────────────
extern fn sqlite3StrAccumInit(p: ?*anyopaque, db: ?*sqlite3, zBase: ?[*]u8, n: c_int, mx: c_int) void;
extern fn sqlite3_str_append(p: ?*anyopaque, z: [*]const u8, n: c_int) void;
extern fn sqlite3_str_appendf(p: ?*anyopaque, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_str_vappendf(p: ?*anyopaque, zFormat: [*:0]const u8, ap: *std.builtin.VaList) void;
extern fn sqlite3_str_reset(p: ?*anyopaque) void;
extern fn sqlite3StrAccumFinish(p: ?*anyopaque) ?[*:0]u8;

// ── vdbe / record ────────────────────────────────────────────────────────────
extern fn sqlite3VdbeAllocUnpackedRecord(pKeyInfo: ?*KeyInfo) ?*UnpackedRecord;
extern fn sqlite3VdbeRecordUnpack(nKey: c_int, pKey: ?*const anyopaque, p: ?*UnpackedRecord) void;
extern fn sqlite3VdbeRecordCompare(nKey: c_int, pKey: ?*const anyopaque, p: ?*UnpackedRecord) c_int;
extern fn sqlite3VdbeFindCompare(p: ?*UnpackedRecord) RecordCompare;

// ── pager ────────────────────────────────────────────────────────────────────
extern fn sqlite3PagerOpen(pVfs: ?*sqlite3_vfs, ppPager: *?*Pager, zFilename: ?[*:0]const u8, nExtra: c_int, flags: c_int, vfsFlags: c_int, xReinit: ?*const fn (?*DbPage) callconv(.c) void) c_int;
extern fn sqlite3PagerClose(p: ?*Pager, db: ?*sqlite3) c_int;
extern fn sqlite3PagerReadFileheader(p: ?*Pager, n: c_int, dest: [*]u8) c_int;
extern fn sqlite3PagerSetBusyHandler(p: ?*Pager, x: ?*const fn (?*anyopaque) callconv(.c) c_int, arg: ?*anyopaque) void;
extern fn sqlite3PagerSetPagesize(p: ?*Pager, ps: *u32, nReserve: c_int) c_int;
extern fn sqlite3PagerSetMmapLimit(p: ?*Pager, sz: i64) void;
extern fn sqlite3PagerMaxPageCount(p: ?*Pager, mx: u32) u32;
extern fn sqlite3PagerSetCachesize(p: ?*Pager, mx: c_int) void;
extern fn sqlite3PagerSetSpillsize(p: ?*Pager, mx: c_int) c_int;
extern fn sqlite3PagerSetFlags(p: ?*Pager, fl: c_uint) void;
extern fn sqlite3PagerGetJournalMode(p: ?*Pager) c_int;
extern fn sqlite3PagerGet(p: ?*Pager, pgno: u32, pp: *?*DbPage, clr: c_int) c_int;
extern fn sqlite3PagerLookup(p: ?*Pager, pgno: u32) ?*DbPage;
extern fn sqlite3PagerRef(p: ?*DbPage) void;
extern fn sqlite3PagerUnref(p: ?*DbPage) void;
extern fn sqlite3PagerUnrefNotNull(p: ?*DbPage) void;
extern fn sqlite3PagerUnrefPageOne(p: ?*DbPage) void;
extern fn sqlite3PagerWrite(p: ?*DbPage) c_int;
extern fn sqlite3PagerDontWrite(p: ?*DbPage) void;
extern fn sqlite3PagerMovepage(p: ?*Pager, pg: ?*DbPage, pgno: u32, isCommit: c_int) c_int;
extern fn sqlite3PagerGetData(p: ?*DbPage) ?[*]u8;
extern fn sqlite3PagerGetExtra(p: ?*DbPage) ?*anyopaque;
extern fn sqlite3PagerPagecount(p: ?*Pager, n: *c_int) void;
extern fn sqlite3PagerPageRefcount(p: ?*DbPage) c_int;
extern fn sqlite3PagerSharedLock(p: ?*Pager) c_int;
extern fn sqlite3PagerIsreadonly(p: ?*Pager) u8;
extern fn sqlite3PagerTempSpace(p: ?*Pager) ?[*]u8;
extern fn sqlite3PagerRekey(p: ?*DbPage, pgno: u32, fl: u16) void;
extern fn sqlite3PagerBegin(p: ?*Pager, ex: c_int, x: c_int) c_int;
extern fn sqlite3PagerCommitPhaseOne(p: ?*Pager, zSuper: ?[*:0]const u8, noSync: c_int) c_int;
extern fn sqlite3PagerCommitPhaseTwo(p: ?*Pager) c_int;
extern fn sqlite3PagerRollback(p: ?*Pager) c_int;
extern fn sqlite3PagerOpenSavepoint(p: ?*Pager, n: c_int) c_int;
extern fn sqlite3PagerSavepoint(p: ?*Pager, op: c_int, iSavepoint: c_int) c_int;
extern fn sqlite3PagerCheckpoint(p: ?*Pager, db: ?*sqlite3, eMode: c_int, pnLog: ?*c_int, pnCkpt: ?*c_int) c_int;
extern fn sqlite3PagerOpenWal(p: ?*Pager, pisOpen: *c_int) c_int;
// sqlite3PagerWalWriteLock / sqlite3PagerWalDb are real only under
// SQLITE_ENABLE_SETLK_TIMEOUT (off). Otherwise they are macros:
//   sqlite3PagerWalWriteLock(y,z) => SQLITE_OK ;  sqlite3PagerWalDb(x,y) => no-op
inline fn sqlite3PagerWalWriteLock(p: ?*Pager, x: c_int) c_int {
    _ = p;
    _ = x;
    return SQLITE_OK;
}
inline fn sqlite3PagerWalDb(p: ?*Pager, db: ?*sqlite3) void {
    _ = p;
    _ = db;
}
extern fn sqlite3PagerDirectReadOk(p: ?*Pager, pgno: u32) c_int;
extern fn sqlite3PagerDataVersion(p: ?*Pager) u32;
extern fn sqlite3PagerRefcount(p: ?*Pager) c_int;
extern fn sqlite3PagerFilename(p: ?*const Pager, x: c_int) ?[*:0]const u8;
extern fn sqlite3PagerVfs(p: ?*Pager) ?*sqlite3_vfs;
extern fn sqlite3PagerFile(p: ?*Pager) ?*sqlite3_file;
extern fn sqlite3PagerJournalname(p: ?*Pager) ?[*:0]const u8;
extern fn sqlite3PagerClearCache(p: ?*Pager) void;
extern fn sqlite3PagerTruncateImage(p: ?*Pager, n: u32) void;
extern fn sqlite3PagerPagenumber(p: ?*DbPage) u32;
extern fn sqlite3PagerIswriteable(p: ?*DbPage) c_int;

// ── os ───────────────────────────────────────────────────────────────────────
extern fn sqlite3OsFullPathname(pVfs: ?*sqlite3_vfs, zPath: ?[*:0]const u8, n: c_int, zOut: ?[*]u8) c_int;
extern fn sqlite3OsRead(p: ?*sqlite3_file, buf: ?*anyopaque, amt: c_int, off: i64) c_int;
extern fn sqlite3OsFileControlHint(p: ?*sqlite3_file, op: c_int, arg: ?*anyopaque) void;

// ── bitvec ───────────────────────────────────────────────────────────────────
extern fn sqlite3BitvecCreate(n: u32) ?*Bitvec;
extern fn sqlite3BitvecDestroy(p: ?*Bitvec) void;
extern fn sqlite3BitvecSet(p: ?*Bitvec, i: u32) c_int;
extern fn sqlite3BitvecTestNotNull(p: ?*Bitvec, i: u32) c_int;
extern fn sqlite3BitvecSize(p: ?*Bitvec) u32;

// ════════════════════════════════════════════════════════════════════════════
// Inline helpers (macros)
// ════════════════════════════════════════════════════════════════════════════

inline fn get2byte(x: [*]const u8) c_int {
    return (@as(c_int, x[0]) << 8) | @as(c_int, x[1]);
}
inline fn put2byte(p: [*]u8, v: c_int) void {
    p[0] = @truncate(@as(c_uint, @bitCast(v)) >> 8);
    p[1] = @truncate(@as(c_uint, @bitCast(v)));
}
inline fn get2byteAligned(x: [*]const u8) c_int {
    return (@as(c_int, x[0]) << 8) | @as(c_int, x[1]);
}
inline fn get4byte(p: [*]const u8) u32 {
    return sqlite3Get4byte(p);
}
inline fn put4byte(p: [*]u8, v: u32) void {
    sqlite3Put4byte(p, v);
}
inline fn get2byteNotZero(x: [*]const u8) c_int {
    return (((get2byte(x) - 1) & 0xffff) + 1);
}

inline fn corrupt_bkpt(comptime line: c_int) c_int {
    if (config.sqlite_debug) {
        return sqlite3CorruptError(line);
    } else {
        return SQLITE_CORRUPT;
    }
}
inline fn corrupt_pgno(pgno: u32) c_int {
    _ = pgno;
    return corrupt_bkpt(0);
}
inline fn corrupt_page(p: *MemPage) c_int {
    if (config.sqlite_debug) {
        return corruptPageError(0, p);
    } else {
        return corrupt_pgno(p.pgno);
    }
}
inline fn nomem_bkpt() c_int {
    if (config.sqlite_debug) {
        return sqlite3NomemError(0);
    } else {
        return SQLITE_NOMEM;
    }
}

inline fn MIN(a: anytype, b: anytype) @TypeOf(a, b) {
    return if (a < b) a else b;
}
inline fn MAX(a: anytype, b: anytype) @TypeOf(a, b) {
    return if (a > b) a else b;
}

// PENDING_BYTE_PAGE(pBt) = (Pgno)((PENDING_BYTE/pBt->pageSize)+1)
inline fn PENDING_BYTE_PAGE(pBt: *BtShared) u32 {
    return @as(u32, @intCast(@divTrunc(pendingByte(), @as(i64, pBt.pageSize)))) +% 1;
}

// findCell(P,I): P->aData + (P->maskPage & get2byteAligned(&P->aCellIdx[2*I]))
inline fn findCell(p: *MemPage, i: c_int) [*]u8 {
    const off = @as(c_int, p.maskPage) & get2byteAligned(p.aCellIdx.? + @as(usize, @intCast(2 * i)));
    return p.aData.? + @as(usize, @intCast(off));
}
inline fn findCellPastPtr(p: *MemPage, i: c_int) [*]u8 {
    const off = @as(c_int, p.maskPage) & get2byteAligned(p.aCellIdx.? + @as(usize, @intCast(2 * i)));
    return p.aDataOfst.? + @as(usize, @intCast(off));
}

inline fn MX_CELL_SIZE(pBt: *BtShared) c_int {
    return @as(c_int, @intCast(pBt.pageSize)) - 8;
}
inline fn MX_CELL(pBt: *BtShared) c_int {
    return @divTrunc(@as(c_int, @intCast(pBt.pageSize)) - 8, 6);
}

// SQLITE_OVERFLOW(P,S,E): (uptr)S < (uptr)P && (uptr)E > (uptr)P
inline fn sqlite_overflow(P: [*]const u8, S: [*]const u8, E: [*]const u8) bool {
    const p = @intFromPtr(P);
    const s = @intFromPtr(S);
    const e = @intFromPtr(E);
    return s < p and e > p;
}
inline fn sqlite_within(p: [*]const u8, s: [*]const u8, e: [*]const u8) bool {
    const pp = @intFromPtr(p);
    return pp >= @intFromPtr(s) and pp < @intFromPtr(e);
}

// ISAUTOVACUUM(pBt)
inline fn isAutoVacuum(pBt: *BtShared) bool {
    return pBt.autoVacuum != 0;
}

// ════════════════════════════════════════════════════════════════════════════
// Shared-cache list global (file scope; SQLITE_TEST makes it visible). Mirror
// it as our own module global. (clients only call sqlite3_enable_shared_cache.)
// ════════════════════════════════════════════════════════════════════════════
var sqlite3SharedCacheList: ?*BtShared = null;
// Upstream makes this global non-static (externally visible) under the test
// build so test_btree.c (sqlite3BtreeSharedCacheReport) can reference it.
comptime {
    if (config.sqlite_test) @export(&sqlite3SharedCacheList, .{ .name = "sqlite3SharedCacheList" });
}

// corruptPageError is non-static (externally linked) under SQLITE_DEBUG, even
// though it has no external callers. Export it in the debug config to match.
comptime {
    if (config.sqlite_debug) {
        @export(&corruptPageError, .{ .name = "corruptPageError", .linkage = .strong });
    }
}
// Forward-declared corruptPageError (SQLITE_DEBUG only — used by SQLITE_CORRUPT_PAGE)
fn corruptPageError(lineno: c_int, p: *MemPage) callconv(.c) c_int {
    if (config.sqlite_debug) {
        sqlite3BeginBenignMalloc();
        const zMsg = sqlite3_mprintf("database corruption page %u of %s", p.pgno, sqlite3PagerFilename(p.pBt.?.pPager, 0));
        sqlite3EndBenignMalloc();
        if (zMsg) |z| {
            _ = sqlite3ReportError(SQLITE_CORRUPT, lineno, z);
        }
        sqlite3_free(zMsg);
        return sqlite3CorruptError(lineno);
    }
    return SQLITE_CORRUPT;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3_enable_shared_cache
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3_enable_shared_cache(enable: c_int) callconv(.c) c_int {
    cfgSharedCacheEnabledPtr().* = enable;
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3BtreeSeekCount (SQLITE_DEBUG only — has external testfixture callers)
// ════════════════════════════════════════════════════════════════════════════
comptime {
    if (config.sqlite_debug) {
        @export(&btreeSeekCount, .{ .name = "sqlite3BtreeSeekCount", .linkage = .strong });
    }
}
fn btreeSeekCount(pBt: *Btree) callconv(.c) u64 {
    if (config.sqlite_debug) {
        const n = pBt.nSeek;
        pBt.nSeek = 0;
        return n;
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// Shared-cache table-lock layer (SQLITE_OMIT_SHARED_CACHE is OFF)
// ════════════════════════════════════════════════════════════════════════════

fn querySharedCacheTableLock(p: *Btree, iTab: u32, eLock: u8) c_int {
    const pBt = p.pBt.?;
    // no-op if not sharable
    if (p.sharable == 0) return SQLITE_OK;
    // exclusive lock held by another connection?
    if (pBt.pWriter != p and (pBt.btsFlags & BTS_EXCLUSIVE) != 0) {
        sqlite3ConnectionBlocked(p.db, pBt.pWriter.?.db);
        return SQLITE_LOCKED_SHAREDCACHE;
    }
    var pIter = pBt.pLock;
    while (pIter) |it| : (pIter = it.pNext) {
        if (it.pBtree != p and it.iTable == iTab and it.eLock != eLock) {
            sqlite3ConnectionBlocked(p.db, it.pBtree.?.db);
            if (eLock == WRITE_LOCK) {
                pBt.btsFlags |= BTS_PENDING;
            }
            return SQLITE_LOCKED_SHAREDCACHE;
        }
    }
    return SQLITE_OK;
}

fn setSharedCacheTableLock(p: *Btree, iTable: u32, eLock: u8) c_int {
    const pBt = p.pBt.?;
    var pLock: ?*BtLock = null;
    // search for existing lock on this table
    var pIter = pBt.pLock;
    while (pIter) |it| : (pIter = it.pNext) {
        if (it.iTable == iTable and it.pBtree == p) {
            pLock = it;
            break;
        }
    }
    if (pLock == null) {
        const raw = sqlite3MallocZero(@sizeOf(BtLock));
        if (raw == null) return nomem_bkpt();
        const nl: *BtLock = @ptrCast(@alignCast(raw));
        nl.iTable = iTable;
        nl.pBtree = p;
        nl.pNext = pBt.pLock;
        pBt.pLock = nl;
        pLock = nl;
    }
    if (eLock > pLock.?.eLock) {
        pLock.?.eLock = eLock;
    }
    return SQLITE_OK;
}

fn clearAllSharedCacheTableLocks(p: *Btree) void {
    const pBt = p.pBt.?;
    var ppIter: *?*BtLock = &pBt.pLock;
    while (ppIter.*) |pLock| {
        if (pLock.pBtree == p) {
            ppIter.* = pLock.pNext;
            if (pLock.iTable != 1) {
                sqlite3_free(pLock);
            }
        } else {
            ppIter = &pLock.pNext;
        }
    }
    if (pBt.pWriter == p) {
        pBt.pWriter = null;
        pBt.btsFlags &= ~(BTS_EXCLUSIVE | BTS_PENDING);
    } else if (pBt.nTransaction == 2) {
        pBt.btsFlags &= ~BTS_PENDING;
    }
}

fn downgradeAllSharedCacheTableLocks(p: *Btree) void {
    const pBt = p.pBt.?;
    if (pBt.pWriter == p) {
        pBt.pWriter = null;
        pBt.btsFlags &= ~(BTS_EXCLUSIVE | BTS_PENDING);
        var pLock = pBt.pLock;
        while (pLock) |it| : (pLock = it.pNext) {
            it.eLock = READ_LOCK;
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// invalidate overflow / incrblob caches
// ════════════════════════════════════════════════════════════════════════════
inline fn invalidateOverflowCache(pCur: *BtCursor) void {
    pCur.curFlags &= ~BTCF_ValidOvfl;
}
fn invalidateAllOverflowCache(pBt: *BtShared) void {
    var p = pBt.pCursor;
    while (p) |c| : (p = c.pNext) {
        invalidateOverflowCache(c);
    }
}
fn invalidateIncrblobCursors(pBtree: *Btree, pgnoRoot: u32, iRow: i64, isClearTable: c_int) void {
    pBtree.hasIncrblobCur = 0;
    var p = pBtree.pBt.?.pCursor;
    while (p) |c| : (p = c.pNext) {
        if ((c.curFlags & BTCF_Incrblob) != 0) {
            pBtree.hasIncrblobCur = 1;
            if (c.pgnoRoot == pgnoRoot and (isClearTable != 0 or c.info.nKey == iRow)) {
                c.eState = CURSOR_INVALID;
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BtShared.pHasContent bitvec
// ════════════════════════════════════════════════════════════════════════════
fn btreeSetHasContent(pBt: *BtShared, pgno: u32) c_int {
    var rc: c_int = SQLITE_OK;
    if (pBt.pHasContent == null) {
        pBt.pHasContent = sqlite3BitvecCreate(pBt.nPage);
        if (pBt.pHasContent == null) {
            rc = nomem_bkpt();
        }
    }
    if (rc == SQLITE_OK and pgno <= sqlite3BitvecSize(pBt.pHasContent)) {
        rc = sqlite3BitvecSet(pBt.pHasContent, pgno);
    }
    return rc;
}
fn btreeGetHasContent(pBt: *BtShared, pgno: u32) bool {
    const p = pBt.pHasContent;
    return p != null and (pgno > sqlite3BitvecSize(p) or sqlite3BitvecTestNotNull(p, pgno) != 0);
}
fn btreeClearHasContent(pBt: *BtShared) void {
    sqlite3BitvecDestroy(pBt.pHasContent);
    pBt.pHasContent = null;
}

// ════════════════════════════════════════════════════════════════════════════
// Cursor page release / save / restore
// ════════════════════════════════════════════════════════════════════════════
fn btreeReleaseAllCursorPages(pCur: *BtCursor) void {
    if (pCur.iPage >= 0) {
        var i: c_int = 0;
        while (i < pCur.iPage) : (i += 1) {
            releasePageNotNull(pCur.apPage[@intCast(i)].?);
        }
        releasePageNotNull(pCur.pPage.?);
        pCur.iPage = -1;
    }
}

fn saveCursorKey(pCur: *BtCursor) c_int {
    var rc: c_int = SQLITE_OK;
    if (pCur.curIntKey != 0) {
        pCur.nKey = sqlite3BtreeIntegerKey(pCur);
    } else {
        pCur.nKey = sqlite3BtreePayloadSize(pCur);
        const pKey = sqlite3Malloc(@as(u64, @intCast(pCur.nKey)) + 9 + 8);
        if (pKey) |pk| {
            rc = sqlite3BtreePayload(pCur, 0, @intCast(pCur.nKey), pk);
            if (rc == SQLITE_OK) {
                const bp: [*]u8 = @ptrCast(pk);
                @memset(bp[@intCast(pCur.nKey) .. @as(usize, @intCast(pCur.nKey)) + 9 + 8], 0);
                pCur.pKey = pk;
            } else {
                sqlite3_free(pk);
            }
        } else {
            rc = nomem_bkpt();
        }
    }
    return rc;
}

fn saveCursorPosition(pCur: *BtCursor) c_int {
    if ((pCur.curFlags & BTCF_Pinned) != 0) {
        return SQLITE_CONSTRAINT_PINNED;
    }
    if (pCur.eState == CURSOR_SKIPNEXT) {
        pCur.eState = CURSOR_VALID;
    } else {
        pCur.skipNext = 0;
    }
    const rc = saveCursorKey(pCur);
    if (rc == SQLITE_OK) {
        btreeReleaseAllCursorPages(pCur);
        pCur.eState = CURSOR_REQUIRESEEK;
    }
    pCur.curFlags &= ~(BTCF_ValidNKey | BTCF_ValidOvfl | BTCF_AtLast);
    return rc;
}

fn saveAllCursors(pBt: *BtShared, iRoot: u32, pExcept: ?*BtCursor) c_int {
    var p = pBt.pCursor;
    while (p) |c| : (p = c.pNext) {
        if (c != pExcept and (iRoot == 0 or c.pgnoRoot == iRoot)) break;
    }
    if (p != null) return saveCursorsOnList(p.?, iRoot, pExcept);
    if (pExcept) |e| e.curFlags &= ~BTCF_Multiple;
    return SQLITE_OK;
}

fn saveCursorsOnList(p_in: *BtCursor, iRoot: u32, pExcept: ?*BtCursor) c_int {
    var p: ?*BtCursor = p_in;
    while (p) |c| {
        if (c != pExcept and (iRoot == 0 or c.pgnoRoot == iRoot)) {
            if (c.eState == CURSOR_VALID or c.eState == CURSOR_SKIPNEXT) {
                const rc = saveCursorPosition(c);
                if (rc != SQLITE_OK) return rc;
            } else {
                btreeReleaseAllCursorPages(c);
            }
        }
        p = c.pNext;
    }
    return SQLITE_OK;
}

export fn sqlite3BtreeClearCursor(pCur: *BtCursor) callconv(.c) void {
    sqlite3_free(pCur.pKey);
    pCur.pKey = null;
    pCur.eState = CURSOR_INVALID;
}

fn btreeMoveto(pCur: *BtCursor, pKey: ?*const anyopaque, nKey: i64, bias: c_int, pRes: *c_int) c_int {
    var rc: c_int = undefined;
    if (pKey) |key| {
        const pKeyInfo = pCur.pKeyInfo;
        const pIdxKeyOpt = sqlite3VdbeAllocUnpackedRecord(pKeyInfo);
        if (pIdxKeyOpt == null) return nomem_bkpt();
        const pIdxKey = pIdxKeyOpt.?;
        sqlite3VdbeRecordUnpack(@intCast(nKey), key, pIdxKey);
        if (pIdxKey.nField == 0 or pIdxKey.nField > fieldPtr(u16, pKeyInfo, off_KeyInfo_nAllField).*) {
            rc = corrupt_bkpt(@src().line);
        } else {
            rc = sqlite3BtreeIndexMoveto(pCur, pIdxKey, pRes);
        }
        const kiDb = fieldPtr(?*sqlite3, pKeyInfo, off_KeyInfo_db).*;
        sqlite3DbFree(kiDb, pIdxKey);
    } else {
        rc = sqlite3BtreeTableMoveto(pCur, nKey, bias, pRes);
    }
    return rc;
}

fn btreeRestoreCursorPosition(pCur: *BtCursor) c_int {
    var rc: c_int = undefined;
    var skipNext: c_int = 0;
    if (pCur.eState == CURSOR_FAULT) {
        return pCur.skipNext;
    }
    pCur.eState = CURSOR_INVALID;
    if (sqlite3FaultSim(410) != 0) {
        rc = SQLITE_IOERR;
    } else {
        rc = btreeMoveto(pCur, pCur.pKey, pCur.nKey, 0, &skipNext);
    }
    if (rc == SQLITE_OK) {
        sqlite3_free(pCur.pKey);
        pCur.pKey = null;
        if (skipNext != 0) pCur.skipNext = skipNext;
        if (pCur.skipNext != 0 and pCur.eState == CURSOR_VALID) {
            pCur.eState = CURSOR_SKIPNEXT;
        }
    }
    return rc;
}

inline fn restoreCursorPosition(p: *BtCursor) c_int {
    if (p.eState >= CURSOR_REQUIRESEEK) return btreeRestoreCursorPosition(p);
    return SQLITE_OK;
}

export fn sqlite3BtreeCursorHasMoved(pCur: *BtCursor) callconv(.c) c_int {
    return @intFromBool(CURSOR_VALID != pCur.eState);
}

var fakeCursor: u8 align(8) = CURSOR_VALID;
export fn sqlite3BtreeFakeValidCursor() callconv(.c) *BtCursor {
    return @ptrCast(@alignCast(&fakeCursor));
}

export fn sqlite3BtreeCursorRestore(pCur: *BtCursor, pDifferentRow: *c_int) callconv(.c) c_int {
    const rc = restoreCursorPosition(pCur);
    if (rc != 0) {
        pDifferentRow.* = 1;
        return rc;
    }
    if (pCur.eState != CURSOR_VALID) {
        pDifferentRow.* = 1;
    } else {
        pDifferentRow.* = 0;
    }
    return SQLITE_OK;
}

export fn sqlite3BtreeCursorHintFlags(pCur: *BtCursor, x: c_uint) callconv(.c) void {
    pCur.hints = @truncate(x);
}

// ════════════════════════════════════════════════════════════════════════════
// Pointer map (autovacuum)
// ════════════════════════════════════════════════════════════════════════════
fn ptrmapPageno(pBt: *BtShared, pgno: u32) u32 {
    if (pgno < 2) return 0;
    const nPagesPerMapPage = (pBt.usableSize / 5) + 1;
    const iPtrMap = (pgno - 2) / nPagesPerMapPage;
    var ret = (iPtrMap * nPagesPerMapPage) + 2;
    if (ret == PENDING_BYTE_PAGE(pBt)) {
        ret += 1;
    }
    return ret;
}
inline fn PTRMAP_PAGENO(pBt: *BtShared, pgno: u32) u32 {
    return ptrmapPageno(pBt, pgno);
}
inline fn PTRMAP_PTROFFSET(pgptrmap: u32, pgno: u32) c_int {
    return @as(c_int, @intCast(5 *% (pgno -% pgptrmap -% 1)));
}
inline fn PTRMAP_ISPAGE(pBt: *BtShared, pgno: u32) bool {
    return PTRMAP_PAGENO(pBt, pgno) == pgno;
}

fn ptrmapPut(pBt: *BtShared, key: u32, eType: u8, parent: u32, pRC: *c_int) void {
    if (pRC.* != 0) return;
    if (key == 0) {
        pRC.* = corrupt_bkpt(@src().line);
        return;
    }
    const iPtrmap = PTRMAP_PAGENO(pBt, key);
    var pDbPage: ?*DbPage = null;
    var rc = sqlite3PagerGet(pBt.pPager, iPtrmap, &pDbPage, 0);
    if (rc != SQLITE_OK) {
        pRC.* = rc;
        return;
    }
    const extra: [*]u8 = @ptrCast(sqlite3PagerGetExtra(pDbPage).?);
    if (extra[0] != 0) {
        pRC.* = corrupt_bkpt(@src().line);
        sqlite3PagerUnref(pDbPage);
        return;
    }
    const offset = PTRMAP_PTROFFSET(iPtrmap, key);
    if (offset < 0) {
        pRC.* = corrupt_bkpt(@src().line);
        sqlite3PagerUnref(pDbPage);
        return;
    }
    const pPtrmap = sqlite3PagerGetData(pDbPage).?;
    const uoff: usize = @intCast(offset);
    if (eType != pPtrmap[uoff] or get4byte(pPtrmap + uoff + 1) != parent) {
        rc = sqlite3PagerWrite(pDbPage);
        pRC.* = rc;
        if (rc == SQLITE_OK) {
            pPtrmap[uoff] = eType;
            put4byte(pPtrmap + uoff + 1, parent);
        }
    }
    sqlite3PagerUnref(pDbPage);
}

fn ptrmapGet(pBt: *BtShared, key: u32, pEType: *u8, pPgno: ?*u32) c_int {
    const iPtrmap = PTRMAP_PAGENO(pBt, key);
    var pDbPage: ?*DbPage = null;
    const rc = sqlite3PagerGet(pBt.pPager, iPtrmap, &pDbPage, 0);
    if (rc != 0) return rc;
    const pPtrmap = sqlite3PagerGetData(pDbPage).?;
    const offset = PTRMAP_PTROFFSET(iPtrmap, key);
    if (offset < 0) {
        sqlite3PagerUnref(pDbPage);
        return corrupt_bkpt(@src().line);
    }
    const uoff: usize = @intCast(offset);
    pEType.* = pPtrmap[uoff];
    if (pPgno) |pp| pp.* = get4byte(pPtrmap + uoff + 1);
    sqlite3PagerUnref(pDbPage);
    if (pEType.* < 1 or pEType.* > 5) return corrupt_pgno(iPtrmap);
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// Cell parsing
// ════════════════════════════════════════════════════════════════════════════
fn btreeParseCellAdjustSizeForOverflow(pPage: *MemPage, pCell: [*]u8, pInfo: *CellInfo) callconv(.c) void {
    const minLocal: c_int = pPage.minLocal;
    const maxLocal: c_int = pPage.maxLocal;
    const surplus = minLocal + @as(c_int, @intCast(@mod(@as(i64, pInfo.nPayload) - minLocal, @as(i64, pPage.pBt.?.usableSize - 4))));
    if (surplus <= maxLocal) {
        pInfo.nLocal = @intCast(surplus);
    } else {
        pInfo.nLocal = @intCast(minLocal);
    }
    const cellDelta: usize = @intFromPtr(pInfo.pPayload.? + pInfo.nLocal) - @intFromPtr(pCell);
    pInfo.nSize = @truncate(cellDelta + 4);
}

fn btreePayloadToLocal(pPage: *MemPage, nPayload: i64) c_int {
    const maxLocal: c_int = pPage.maxLocal;
    if (nPayload <= maxLocal) {
        return @intCast(nPayload);
    }
    const minLocal: c_int = pPage.minLocal;
    const surplus = minLocal + @as(c_int, @intCast(@mod(nPayload - minLocal, @as(i64, pPage.pBt.?.usableSize - 4))));
    return if (surplus <= maxLocal) surplus else minLocal;
}

fn btreeParseCellPtrNoPayload(pPage: ?*MemPage, pCell: ?[*]u8, pInfo: ?*CellInfo) callconv(.c) void {
    _ = pPage;
    const info = pInfo.?;
    info.nSize = 4 + sqlite3GetVarint(pCell.? + 4, @ptrCast(&info.nKey));
    info.nPayload = 0;
    info.nLocal = 0;
    info.pPayload = null;
}

fn btreeParseCellPtr(pPage: ?*MemPage, pCell: ?[*]u8, pInfo: ?*CellInfo) callconv(.c) void {
    const page = pPage.?;
    const info = pInfo.?;
    var pIter: [*]u8 = pCell.?;
    var nPayload: u64 = pIter[0];
    if (nPayload >= 0x80) {
        const pEnd = pIter + 8;
        nPayload &= 0x7f;
        while (true) {
            pIter += 1;
            nPayload = (nPayload << 7) | (pIter[0] & 0x7f);
            if (!(pIter[0] >= 0x80 and @intFromPtr(pIter) < @intFromPtr(pEnd))) break;
        }
        nPayload &= 0xffffffff;
    }
    pIter += 1;

    var iKey: u64 = pIter[0];
    if (iKey >= 0x80) {
        var x: u8 = undefined;
        pIter += 1;
        x = pIter[0];
        iKey = (iKey << 7) ^ x;
        if (x >= 0x80) {
            pIter += 1;
            x = pIter[0];
            iKey = (iKey << 7) ^ x;
            if (x >= 0x80) {
                pIter += 1;
                x = pIter[0];
                iKey = (iKey << 7) ^ 0x10204000 ^ x;
                if (x >= 0x80) {
                    pIter += 1;
                    x = pIter[0];
                    iKey = (iKey << 7) ^ 0x4000 ^ x;
                    if (x >= 0x80) {
                        pIter += 1;
                        x = pIter[0];
                        iKey = (iKey << 7) ^ 0x4000 ^ x;
                        if (x >= 0x80) {
                            pIter += 1;
                            x = pIter[0];
                            iKey = (iKey << 7) ^ 0x4000 ^ x;
                            if (x >= 0x80) {
                                pIter += 1;
                                x = pIter[0];
                                iKey = (iKey << 7) ^ 0x4000 ^ x;
                                if (x >= 0x80) {
                                    pIter += 1;
                                    iKey = (iKey << 8) ^ 0x8000 ^ pIter[0];
                                }
                            }
                        }
                    }
                }
            } else {
                iKey ^= 0x204000;
            }
        } else {
            iKey ^= 0x4000;
        }
    }
    pIter += 1;

    info.nKey = @bitCast(iKey);
    info.nPayload = @truncate(nPayload);
    info.pPayload = pIter;
    if (nPayload <= page.maxLocal) {
        info.nSize = @as(u16, @truncate(nPayload)) +% @as(u16, @truncate(@intFromPtr(pIter) - @intFromPtr(pCell.?)));
        if (info.nSize < 4) info.nSize = 4;
        info.nLocal = @truncate(nPayload);
    } else {
        btreeParseCellAdjustSizeForOverflow(page, pCell.?, info);
    }
}

fn btreeParseCellPtrIndex(pPage: ?*MemPage, pCell: ?[*]u8, pInfo: ?*CellInfo) callconv(.c) void {
    const page = pPage.?;
    const info = pInfo.?;
    var pIter: [*]u8 = pCell.? + page.childPtrSize;
    var nPayload: u32 = pIter[0];
    if (nPayload >= 0x80) {
        const pEnd = pIter + 8;
        nPayload &= 0x7f;
        while (true) {
            pIter += 1;
            nPayload = (nPayload << 7) | (pIter[0] & 0x7f);
            if (!(pIter[0] >= 0x80 and @intFromPtr(pIter) < @intFromPtr(pEnd))) break;
        }
    }
    pIter += 1;
    info.nKey = nPayload;
    info.nPayload = nPayload;
    info.pPayload = pIter;
    if (nPayload <= page.maxLocal) {
        info.nSize = @as(u16, @truncate(nPayload)) +% @as(u16, @truncate(@intFromPtr(pIter) - @intFromPtr(pCell.?)));
        if (info.nSize < 4) info.nSize = 4;
        info.nLocal = @truncate(nPayload);
    } else {
        btreeParseCellAdjustSizeForOverflow(page, pCell.?, info);
    }
}

inline fn btreeParseCell(pPage: *MemPage, iCell: c_int, pInfo: *CellInfo) void {
    pPage.xParseCell(pPage, findCell(pPage, iCell), pInfo);
}

// ── xCellSize implementations ───────────────────────────────────────────────
fn cellSizePtr(pPage: ?*MemPage, pCell: ?[*]u8) callconv(.c) u16 {
    const page = pPage.?;
    const cell = pCell.?;
    var pIter: [*]u8 = cell + 4;
    var nSize: u32 = pIter[0];
    if (nSize >= 0x80) {
        const pEnd = cell + 4 + 8;
        nSize &= 0x7f;
        while (true) {
            pIter += 1;
            nSize = (nSize << 7) | (pIter[0] & 0x7f);
            if (!(pIter[0] >= 0x80 and @intFromPtr(pIter) < @intFromPtr(pEnd))) break;
        }
    }
    pIter += 1;
    if (nSize <= page.maxLocal) {
        nSize += @truncate(@intFromPtr(pIter) - @intFromPtr(cell));
    } else {
        const minLocal: c_int = page.minLocal;
        nSize = @intCast(minLocal + @as(c_int, @intCast(@mod(@as(i64, nSize) - minLocal, @as(i64, page.pBt.?.usableSize - 4)))));
        if (nSize > page.maxLocal) {
            nSize = @intCast(minLocal);
        }
        nSize += 4 + @as(u16, @truncate(@intFromPtr(pIter) - @intFromPtr(cell)));
    }
    return @truncate(nSize);
}

fn cellSizePtrIdxLeaf(pPage: ?*MemPage, pCell: ?[*]u8) callconv(.c) u16 {
    const page = pPage.?;
    const cell = pCell.?;
    var pIter: [*]u8 = cell;
    var nSize: u32 = pIter[0];
    if (nSize >= 0x80) {
        const pEnd = cell + 8;
        nSize &= 0x7f;
        while (true) {
            pIter += 1;
            nSize = (nSize << 7) | (pIter[0] & 0x7f);
            if (!(pIter[0] >= 0x80 and @intFromPtr(pIter) < @intFromPtr(pEnd))) break;
        }
    }
    pIter += 1;
    if (nSize <= page.maxLocal) {
        nSize += @truncate(@intFromPtr(pIter) - @intFromPtr(cell));
        if (nSize < 4) nSize = 4;
    } else {
        const minLocal: c_int = page.minLocal;
        nSize = @intCast(minLocal + @as(c_int, @intCast(@mod(@as(i64, nSize) - minLocal, @as(i64, page.pBt.?.usableSize - 4)))));
        if (nSize > page.maxLocal) {
            nSize = @intCast(minLocal);
        }
        nSize += 4 + @as(u16, @truncate(@intFromPtr(pIter) - @intFromPtr(cell)));
    }
    return @truncate(nSize);
}

fn cellSizePtrNoPayload(pPage: ?*MemPage, pCell: ?[*]u8) callconv(.c) u16 {
    _ = pPage;
    const cell = pCell.?;
    var pIter: [*]u8 = cell + 4;
    const pEnd = pIter + 9;
    while (true) {
        const b = pIter[0];
        pIter += 1;
        if (!((b & 0x80) != 0 and @intFromPtr(pIter) < @intFromPtr(pEnd))) break;
    }
    return @truncate(@intFromPtr(pIter) - @intFromPtr(cell));
}

fn cellSizePtrTableLeaf(pPage: ?*MemPage, pCell: ?[*]u8) callconv(.c) u16 {
    const page = pPage.?;
    const cell = pCell.?;
    var pIter: [*]u8 = cell;
    var nSize: u32 = pIter[0];
    if (nSize >= 0x80) {
        const pEnd = cell + 8;
        nSize &= 0x7f;
        while (true) {
            pIter += 1;
            nSize = (nSize << 7) | (pIter[0] & 0x7f);
            if (!(pIter[0] >= 0x80 and @intFromPtr(pIter) < @intFromPtr(pEnd))) break;
        }
    }
    pIter += 1;
    // skip the 64-bit integer key (up to 9 bytes)
    var cnt: u8 = 0;
    while (cnt < 8) : (cnt += 1) {
        const b = pIter[0];
        pIter += 1;
        if ((b & 0x80) == 0) break;
    } else {
        pIter += 1;
    }
    if (nSize <= page.maxLocal) {
        nSize += @truncate(@intFromPtr(pIter) - @intFromPtr(cell));
        if (nSize < 4) nSize = 4;
    } else {
        const minLocal: c_int = page.minLocal;
        nSize = @intCast(minLocal + @as(c_int, @intCast(@mod(@as(i64, nSize) - minLocal, @as(i64, page.pBt.?.usableSize - 4)))));
        if (nSize > page.maxLocal) {
            nSize = @intCast(minLocal);
        }
        nSize += 4 + @as(u16, @truncate(@intFromPtr(pIter) - @intFromPtr(cell)));
    }
    return @truncate(nSize);
}

fn ptrmapPutOvflPtr(pPage: *MemPage, pSrc: *MemPage, pCell: [*]u8, pRC: *c_int) void {
    if (pRC.* != 0) return;
    var info: CellInfo = undefined;
    pPage.xParseCell(pPage, pCell, &info);
    if (info.nLocal < info.nPayload) {
        if (sqlite_overflow(pSrc.aDataEnd.?, pCell, pCell + info.nLocal)) {
            pRC.* = corrupt_bkpt(@src().line);
            return;
        }
        const ovfl = get4byte(pCell + info.nSize - 4);
        ptrmapPut(pPage.pBt.?, ovfl, PTRMAP_OVERFLOW1, pPage.pgno, pRC);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Page defragment / allocate / free space
// ════════════════════════════════════════════════════════════════════════════
fn defragmentPage(pPage: *MemPage, nMaxFrag: c_int) c_int {
    const data = pPage.aData.?;
    const hdr: c_int = pPage.hdrOffset;
    const cellOffset: c_int = pPage.cellOffset;
    const nCell: c_int = pPage.nCell;
    const usableSize: c_int = @intCast(pPage.pBt.?.usableSize);
    const iCellFirst = cellOffset + 2 * nCell;
    var cbrk: c_int = undefined;

    if (@as(c_int, data[@intCast(hdr + 7)]) <= nMaxFrag) {
        const iFree = get2byte(data + @as(usize, @intCast(hdr + 1)));
        if (iFree > usableSize - 4) return corrupt_page(pPage);
        if (iFree != 0) {
            const iFree2 = get2byte(data + @as(usize, @intCast(iFree)));
            if (iFree2 > usableSize - 4) return corrupt_page(pPage);
            if (iFree2 == 0 or (data[@intCast(iFree2)] == 0 and data[@intCast(iFree2 + 1)] == 0)) {
                const pEnd = data + @as(usize, @intCast(cellOffset + nCell * 2));
                var sz2: c_int = 0;
                var sz = get2byte(data + @as(usize, @intCast(iFree + 2)));
                const top = get2byte(data + @as(usize, @intCast(hdr + 5)));
                if (top >= iFree) {
                    return corrupt_page(pPage);
                }
                if (iFree2 != 0) {
                    if (iFree + sz > iFree2) return corrupt_page(pPage);
                    sz2 = get2byte(data + @as(usize, @intCast(iFree2 + 2)));
                    if (iFree2 + sz2 > usableSize) return corrupt_page(pPage);
                    const dst = data + @as(usize, @intCast(iFree + sz + sz2));
                    const src = data + @as(usize, @intCast(iFree + sz));
                    const n: usize = @intCast(iFree2 - (iFree + sz));
                    std.mem.copyBackwards(u8, dst[0..n], src[0..n]);
                    sz += sz2;
                } else if (iFree + sz > usableSize) {
                    return corrupt_page(pPage);
                }
                cbrk = top + sz;
                const dst = data + @as(usize, @intCast(cbrk));
                const src = data + @as(usize, @intCast(top));
                const n: usize = @intCast(iFree - top);
                std.mem.copyBackwards(u8, dst[0..n], src[0..n]);
                var pAddr = data + @as(usize, @intCast(cellOffset));
                while (@intFromPtr(pAddr) < @intFromPtr(pEnd)) : (pAddr += 2) {
                    const pc = get2byte(pAddr);
                    if (pc < iFree) {
                        put2byte(pAddr, pc + sz);
                    } else if (pc < iFree2) {
                        put2byte(pAddr, pc + sz2);
                    }
                }
                return defragment_out(pPage, data, hdr, cbrk, iCellFirst);
            }
        }
    }

    cbrk = usableSize;
    const iCellLast = usableSize - 4;
    const iCellStart = get2byte(data + @as(usize, @intCast(hdr + 5)));
    if (nCell > 0) {
        const temp = sqlite3PagerTempSpace(pPage.pBt.?.pPager).?;
        @memcpy(temp[0..@intCast(usableSize)], data[0..@intCast(usableSize)]);
        const src = temp;
        var i: c_int = 0;
        while (i < nCell) : (i += 1) {
            const pAddr = data + @as(usize, @intCast(cellOffset + i * 2));
            const pc = get2byte(pAddr);
            if (pc > iCellLast) {
                return corrupt_page(pPage);
            }
            const size: c_int = pPage.xCellSize(pPage, src + @as(usize, @intCast(pc)));
            cbrk -= size;
            if (cbrk < iCellStart or pc + size > usableSize) {
                return corrupt_page(pPage);
            }
            put2byte(pAddr, cbrk);
            const d = data + @as(usize, @intCast(cbrk));
            const s = src + @as(usize, @intCast(pc));
            @memcpy(d[0..@intCast(size)], s[0..@intCast(size)]);
        }
    }
    data[@intCast(hdr + 7)] = 0;
    return defragment_out(pPage, data, hdr, cbrk, iCellFirst);
}
fn defragment_out(pPage: *MemPage, data: [*]u8, hdr: c_int, cbrk: c_int, iCellFirst: c_int) c_int {
    if (@as(c_int, data[@intCast(hdr + 7)]) + cbrk - iCellFirst != pPage.nFree) {
        return corrupt_page(pPage);
    }
    put2byte(data + @as(usize, @intCast(hdr + 5)), cbrk);
    data[@intCast(hdr + 1)] = 0;
    data[@intCast(hdr + 2)] = 0;
    const z = data + @as(usize, @intCast(iCellFirst));
    @memset(z[0..@intCast(cbrk - iCellFirst)], 0);
    return SQLITE_OK;
}

fn pageFindSlot(pPg: *MemPage, nByte: c_int, pRc: *c_int) ?[*]u8 {
    const hdr: c_int = pPg.hdrOffset;
    const aData = pPg.aData.?;
    var iAddr: c_int = hdr + 1;
    var pc = get2byte(aData + @as(usize, @intCast(iAddr)));
    const maxPC: c_int = @as(c_int, @intCast(pPg.pBt.?.usableSize)) - nByte;
    while (pc <= maxPC) {
        const size = get2byte(aData + @as(usize, @intCast(pc + 2)));
        const x = size - nByte;
        if (x >= 0) {
            if (x < 4) {
                if (aData[@intCast(hdr + 7)] > 57) return null;
                const dst = aData + @as(usize, @intCast(iAddr));
                const src = aData + @as(usize, @intCast(pc));
                @memcpy(dst[0..2], src[0..2]);
                aData[@intCast(hdr + 7)] +%= @truncate(@as(c_uint, @bitCast(x)));
                return aData + @as(usize, @intCast(pc));
            } else if (x + pc > maxPC) {
                pRc.* = corrupt_page(pPg);
                return null;
            } else {
                put2byte(aData + @as(usize, @intCast(pc + 2)), x);
            }
            return aData + @as(usize, @intCast(pc + x));
        }
        iAddr = pc;
        pc = get2byte(aData + @as(usize, @intCast(pc)));
        if (pc <= iAddr) {
            if (pc != 0) {
                pRc.* = corrupt_page(pPg);
            }
            return null;
        }
    }
    if (pc > maxPC + nByte - 4) {
        pRc.* = corrupt_page(pPg);
    }
    return null;
}

fn allocateSpace(pPage: *MemPage, nByte: c_int, pIdx: *c_int) c_int {
    const hdr: c_int = pPage.hdrOffset;
    const data = pPage.aData.?;
    var rc: c_int = SQLITE_OK;
    const gap = @as(c_int, pPage.cellOffset) + 2 * @as(c_int, pPage.nCell);
    var top = get2byte(data + @as(usize, @intCast(hdr + 5)));
    if (gap > top) {
        if (top == 0 and pPage.pBt.?.usableSize == 65536) {
            top = 65536;
        } else {
            return corrupt_page(pPage);
        }
    } else if (top > @as(c_int, @intCast(pPage.pBt.?.usableSize))) {
        return corrupt_page(pPage);
    }
    if ((data[@intCast(hdr + 2)] != 0 or data[@intCast(hdr + 1)] != 0) and gap + 2 <= top) {
        const pSpace = pageFindSlot(pPage, nByte, &rc);
        if (pSpace) |sp| {
            const g2: c_int = @intCast(@intFromPtr(sp) - @intFromPtr(data));
            pIdx.* = g2;
            if (g2 <= gap) {
                return corrupt_page(pPage);
            } else {
                return SQLITE_OK;
            }
        } else if (rc != 0) {
            return rc;
        }
    }
    if (gap + 2 + nByte > top) {
        rc = defragmentPage(pPage, MIN(@as(c_int, 4), pPage.nFree - (2 + nByte)));
        if (rc != 0) return rc;
        top = get2byteNotZero(data + @as(usize, @intCast(hdr + 5)));
    }
    top -= nByte;
    put2byte(data + @as(usize, @intCast(hdr + 5)), top);
    pIdx.* = top;
    return SQLITE_OK;
}

fn freeSpace(pPage: *MemPage, iStart_in: c_int, iSize_in: c_int) c_int {
    var iStart = iStart_in;
    var iSize = iSize_in;
    var iPtr: c_int = undefined;
    var iFreeBlk: c_int = undefined;
    var nFrag: c_int = 0;
    const iOrigSize = iSize;
    var iEnd = iStart + iSize;
    const data = pPage.aData.?;
    const hdr: c_int = pPage.hdrOffset;
    const usable: c_int = @intCast(pPage.pBt.?.usableSize);

    iPtr = hdr + 1;
    if (data[@intCast(iPtr + 1)] == 0 and data[@intCast(iPtr)] == 0) {
        iFreeBlk = 0;
    } else {
        while (true) {
            iFreeBlk = get2byte(data + @as(usize, @intCast(iPtr)));
            if (!(iFreeBlk < iStart)) break;
            if (iFreeBlk <= iPtr) {
                if (iFreeBlk == 0) break;
                return corrupt_page(pPage);
            }
            iPtr = iFreeBlk;
        }
        if (iFreeBlk > usable - 4) {
            return corrupt_page(pPage);
        }
        if (iFreeBlk != 0 and iEnd + 3 >= iFreeBlk) {
            nFrag = iFreeBlk - iEnd;
            if (iEnd > iFreeBlk) return corrupt_page(pPage);
            iEnd = iFreeBlk + get2byte(data + @as(usize, @intCast(iFreeBlk + 2)));
            if (iEnd > usable) {
                return corrupt_page(pPage);
            }
            iSize = iEnd - iStart;
            iFreeBlk = get2byte(data + @as(usize, @intCast(iFreeBlk)));
        }
        if (iPtr > hdr + 1) {
            const iPtrEnd = iPtr + get2byte(data + @as(usize, @intCast(iPtr + 2)));
            if (iPtrEnd + 3 >= iStart) {
                if (iPtrEnd > iStart) return corrupt_page(pPage);
                nFrag += iStart - iPtrEnd;
                iSize = iEnd - iPtr;
                iStart = iPtr;
            }
        }
        if (nFrag > data[@intCast(hdr + 7)]) return corrupt_page(pPage);
        data[@intCast(hdr + 7)] -%= @truncate(@as(c_uint, @bitCast(nFrag)));
    }
    const x = get2byte(data + @as(usize, @intCast(hdr + 5)));
    if ((pPage.pBt.?.btsFlags & BTS_FAST_SECURE) != 0) {
        const z = data + @as(usize, @intCast(iStart));
        @memset(z[0..@intCast(iSize)], 0);
    }
    if (iStart <= x) {
        if (iStart < x) return corrupt_page(pPage);
        if (iPtr != hdr + 1) return corrupt_page(pPage);
        put2byte(data + @as(usize, @intCast(hdr + 1)), iFreeBlk);
        put2byte(data + @as(usize, @intCast(hdr + 5)), iEnd);
    } else {
        put2byte(data + @as(usize, @intCast(iPtr)), iStart);
        put2byte(data + @as(usize, @intCast(iStart)), iFreeBlk);
        put2byte(data + @as(usize, @intCast(iStart + 2)), iSize);
    }
    pPage.nFree += iOrigSize;
    return SQLITE_OK;
}

fn decodeFlags(pPage: *MemPage, flagByte: c_int) c_int {
    const pBt = pPage.pBt.?;
    pPage.max1bytePayload = pBt.max1bytePayload;
    if (flagByte >= (PTF_ZERODATA | PTF_LEAF)) {
        pPage.childPtrSize = 0;
        pPage.leaf = 1;
        if (flagByte == (PTF_LEAFDATA | PTF_INTKEY | PTF_LEAF)) {
            pPage.intKeyLeaf = 1;
            pPage.xCellSize = cellSizePtrTableLeaf;
            pPage.xParseCell = btreeParseCellPtr;
            pPage.intKey = 1;
            pPage.maxLocal = pBt.maxLeaf;
            pPage.minLocal = pBt.minLeaf;
        } else if (flagByte == (PTF_ZERODATA | PTF_LEAF)) {
            pPage.intKey = 0;
            pPage.intKeyLeaf = 0;
            pPage.xCellSize = cellSizePtrIdxLeaf;
            pPage.xParseCell = btreeParseCellPtrIndex;
            pPage.maxLocal = pBt.maxLocal;
            pPage.minLocal = pBt.minLocal;
        } else {
            pPage.intKey = 0;
            pPage.intKeyLeaf = 0;
            pPage.xCellSize = cellSizePtrIdxLeaf;
            pPage.xParseCell = btreeParseCellPtrIndex;
            return corrupt_page(pPage);
        }
    } else {
        pPage.childPtrSize = 4;
        pPage.leaf = 0;
        if (flagByte == PTF_ZERODATA) {
            pPage.intKey = 0;
            pPage.intKeyLeaf = 0;
            pPage.xCellSize = cellSizePtr;
            pPage.xParseCell = btreeParseCellPtrIndex;
            pPage.maxLocal = pBt.maxLocal;
            pPage.minLocal = pBt.minLocal;
        } else if (flagByte == (PTF_LEAFDATA | PTF_INTKEY)) {
            pPage.intKeyLeaf = 0;
            pPage.xCellSize = cellSizePtrNoPayload;
            pPage.xParseCell = btreeParseCellPtrNoPayload;
            pPage.intKey = 1;
            pPage.maxLocal = pBt.maxLeaf;
            pPage.minLocal = pBt.minLeaf;
        } else {
            pPage.intKey = 0;
            pPage.intKeyLeaf = 0;
            pPage.xCellSize = cellSizePtr;
            pPage.xParseCell = btreeParseCellPtrIndex;
            return corrupt_page(pPage);
        }
    }
    return SQLITE_OK;
}

fn btreeComputeFreeSpace(pPage: *MemPage) c_int {
    const usableSize: c_int = @intCast(pPage.pBt.?.usableSize);
    const hdr: c_int = pPage.hdrOffset;
    const data = pPage.aData.?;
    const top = get2byteNotZero(data + @as(usize, @intCast(hdr + 5)));
    const iCellFirst = hdr + 8 + @as(c_int, pPage.childPtrSize) + 2 * @as(c_int, pPage.nCell);
    const iCellLast = usableSize - 4;
    var pc = get2byte(data + @as(usize, @intCast(hdr + 1)));
    var nFree: c_int = @as(c_int, data[@intCast(hdr + 7)]) + top;
    if (pc > 0) {
        var next: u32 = undefined;
        var size: u32 = undefined;
        if (pc < top) {
            return corrupt_page(pPage);
        }
        while (true) {
            if (pc > iCellLast) {
                return corrupt_page(pPage);
            }
            next = @intCast(get2byte(data + @as(usize, @intCast(pc))));
            size = @intCast(get2byte(data + @as(usize, @intCast(pc + 2))));
            nFree = nFree + @as(c_int, @intCast(size));
            if (next <= @as(u32, @intCast(pc)) + size + 3) break;
            pc = @intCast(next);
        }
        if (next > 0) {
            return corrupt_page(pPage);
        }
        if (@as(u32, @intCast(pc)) + size > @as(u32, @intCast(usableSize))) {
            return corrupt_page(pPage);
        }
    }
    if (nFree > usableSize or nFree < iCellFirst) {
        return corrupt_page(pPage);
    }
    pPage.nFree = nFree - iCellFirst;
    return SQLITE_OK;
}

fn btreeCellSizeCheck(pPage: *MemPage) c_int {
    const iCellFirst = @as(c_int, pPage.cellOffset) + 2 * @as(c_int, pPage.nCell);
    const usableSize: c_int = @intCast(pPage.pBt.?.usableSize);
    var iCellLast = usableSize - 4;
    const data = pPage.aData.?;
    const cellOffset: c_int = pPage.cellOffset;
    if (pPage.leaf == 0) iCellLast -= 1;
    var i: c_int = 0;
    while (i < pPage.nCell) : (i += 1) {
        const pc = get2byteAligned(data + @as(usize, @intCast(cellOffset + i * 2)));
        if (pc < iCellFirst or pc > iCellLast) {
            return corrupt_page(pPage);
        }
        const sz: c_int = pPage.xCellSize(pPage, data + @as(usize, @intCast(pc)));
        if (pc + sz > usableSize) {
            return corrupt_page(pPage);
        }
    }
    return SQLITE_OK;
}

fn btreeInitPage(pPage: *MemPage) c_int {
    const pBt = pPage.pBt.?;
    const data = pPage.aData.? + pPage.hdrOffset;
    if (decodeFlags(pPage, data[0]) != 0) {
        return corrupt_page(pPage);
    }
    pPage.maskPage = @truncate(pBt.pageSize - 1);
    pPage.nOverflow = 0;
    pPage.cellOffset = @truncate(@as(u32, pPage.hdrOffset) + 8 + pPage.childPtrSize);
    pPage.aCellIdx = data + @as(usize, pPage.childPtrSize) + 8;
    pPage.aDataEnd = pPage.aData.? + pBt.pageSize;
    pPage.aDataOfst = pPage.aData.? + pPage.childPtrSize;
    pPage.nCell = @intCast(get2byte(data + 3));
    if (pPage.nCell > MX_CELL(pBt)) {
        return corrupt_page(pPage);
    }
    pPage.nFree = -1;
    pPage.isInit = 1;
    if ((dbFlags(pBt.db) & SQLITE_CellSizeCk) != 0) {
        return btreeCellSizeCheck(pPage);
    }
    return SQLITE_OK;
}

fn zeroPage(pPage: *MemPage, flagsByte: c_int) void {
    const data = pPage.aData.?;
    const pBt = pPage.pBt.?;
    const hdr: c_int = pPage.hdrOffset;
    if ((pBt.btsFlags & BTS_FAST_SECURE) != 0) {
        const z = data + @as(usize, @intCast(hdr));
        @memset(z[0..@intCast(@as(c_int, @intCast(pBt.usableSize)) - hdr)], 0);
    }
    data[@intCast(hdr)] = @truncate(@as(c_uint, @bitCast(flagsByte)));
    const first = hdr + (if ((flagsByte & PTF_LEAF) == 0) @as(c_int, 12) else 8);
    @memset((data + @as(usize, @intCast(hdr + 1)))[0..4], 0);
    data[@intCast(hdr + 7)] = 0;
    put2byte(data + @as(usize, @intCast(hdr + 5)), @intCast(pBt.usableSize));
    pPage.nFree = @as(c_int, @intCast(pBt.usableSize)) - first;
    _ = decodeFlags(pPage, flagsByte);
    pPage.cellOffset = @intCast(first);
    pPage.aDataEnd = data + pBt.pageSize;
    pPage.aCellIdx = data + @as(usize, @intCast(first));
    pPage.aDataOfst = data + @as(usize, pPage.childPtrSize);
    pPage.nOverflow = 0;
    pPage.maskPage = @truncate(pBt.pageSize - 1);
    pPage.nCell = 0;
    pPage.isInit = 1;
}

fn btreePageFromDbPage(pDbPage: *DbPage, pgno: u32, pBt: *BtShared) *MemPage {
    const pPage: *MemPage = @ptrCast(@alignCast(sqlite3PagerGetExtra(pDbPage).?));
    if (pgno != pPage.pgno) {
        pPage.aData = sqlite3PagerGetData(pDbPage);
        pPage.pDbPage = pDbPage;
        pPage.pBt = pBt;
        pPage.pgno = pgno;
        pPage.hdrOffset = if (pgno == 1) 100 else 0;
    }
    return pPage;
}

fn btreeGetPage(pBt: *BtShared, pgno: u32, ppPage: *?*MemPage, fl: c_int) c_int {
    var pDbPage: ?*DbPage = null;
    const rc = sqlite3PagerGet(pBt.pPager, pgno, &pDbPage, fl);
    if (rc != 0) return rc;
    ppPage.* = btreePageFromDbPage(pDbPage.?, pgno, pBt);
    return SQLITE_OK;
}

fn btreePageLookup(pBt: *BtShared, pgno: u32) ?*MemPage {
    const pDbPage = sqlite3PagerLookup(pBt.pPager, pgno);
    if (pDbPage) |dp| {
        return btreePageFromDbPage(dp, pgno, pBt);
    }
    return null;
}

fn btreePagecount(pBt: *BtShared) u32 {
    return pBt.nPage;
}

export fn sqlite3BtreeLastPage(p: *Btree) callconv(.c) u32 {
    return btreePagecount(p.pBt.?);
}

fn getAndInitPage(pBt: *BtShared, pgno: u32, ppPage: *?*MemPage, bReadOnly: c_int) c_int {
    var pDbPage: ?*DbPage = null;
    if (pgno > btreePagecount(pBt)) {
        ppPage.* = null;
        return corrupt_bkpt(@src().line);
    }
    var rc = sqlite3PagerGet(pBt.pPager, pgno, &pDbPage, bReadOnly);
    if (rc != 0) {
        ppPage.* = null;
        return rc;
    }
    const pPage: *MemPage = @ptrCast(@alignCast(sqlite3PagerGetExtra(pDbPage).?));
    if (pPage.isInit == 0) {
        _ = btreePageFromDbPage(pDbPage.?, pgno, pBt);
        rc = btreeInitPage(pPage);
        if (rc != SQLITE_OK) {
            releasePage(pPage);
            ppPage.* = null;
            return rc;
        }
    }
    ppPage.* = pPage;
    return SQLITE_OK;
}

fn releasePageNotNull(pPage: *MemPage) void {
    sqlite3PagerUnrefNotNull(pPage.pDbPage);
}
fn releasePage(pPage: ?*MemPage) void {
    if (pPage) |p| releasePageNotNull(p);
}
fn releasePageOne(pPage: *MemPage) void {
    sqlite3PagerUnrefPageOne(pPage.pDbPage);
}

fn btreeGetUnusedPage(pBt: *BtShared, pgno: u32, ppPage: *?*MemPage, fl: c_int) c_int {
    const rc = btreeGetPage(pBt, pgno, ppPage, fl);
    if (rc == SQLITE_OK) {
        if (sqlite3PagerPageRefcount(ppPage.*.?.pDbPage) > 1) {
            releasePage(ppPage.*);
            ppPage.* = null;
            return corrupt_bkpt(@src().line);
        }
        ppPage.*.?.isInit = 0;
    } else {
        ppPage.* = null;
    }
    return rc;
}

fn pageReinit(pData: ?*DbPage) callconv(.c) void {
    const pPage: *MemPage = @ptrCast(@alignCast(sqlite3PagerGetExtra(pData).?));
    if (pPage.isInit != 0) {
        pPage.isInit = 0;
        if (sqlite3PagerPageRefcount(pData) > 1) {
            _ = btreeInitPage(pPage);
        }
    }
}

fn btreeInvokeBusyHandler(pArg: ?*anyopaque) callconv(.c) c_int {
    const pBt: *BtShared = @ptrCast(@alignCast(pArg.?));
    const bh = @as([*]u8, @ptrCast(pBt.db.?)) + off_db_busyHandler;
    return sqlite3InvokeBusyHandler(@ptrCast(bh));
}

// ════════════════════════════════════════════════════════════════════════════
// Open / Close
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3BtreeOpen(
    pVfs: ?*sqlite3_vfs,
    zFilename: ?[*:0]const u8,
    db: ?*sqlite3,
    ppBtree: *?*Btree,
    flags_in: c_int,
    vfsFlags_in: c_int,
) callconv(.c) c_int {
    var pBt: ?*BtShared = null;
    var p: *Btree = undefined;
    var mutexOpen: ?*sqlite3_mutex = null;
    var rc: c_int = SQLITE_OK;
    var nReserve: u8 = undefined;
    var zDbHeader: [100]u8 = undefined;
    var flags = flags_in;
    var vfsFlags = vfsFlags_in;

    const isTempDb = zFilename == null or zFilename.?[0] == 0;
    const isMemdb = (zFilename != null and strcmp(zFilename.?, ":memory:") == 0) or
        (isTempDb and sqlite3TempInMemory(db) != 0) or
        (vfsFlags & SQLITE_OPEN_MEMORY) != 0;

    if (isMemdb) {
        flags |= BTREE_MEMORY;
    }
    if ((vfsFlags & SQLITE_OPEN_MAIN_DB) != 0 and (isMemdb or isTempDb)) {
        vfsFlags = (vfsFlags & ~@as(c_int, SQLITE_OPEN_MAIN_DB)) | SQLITE_OPEN_TEMP_DB;
    }
    const praw = sqlite3MallocZero(@sizeOf(Btree));
    if (praw == null) {
        return nomem_bkpt();
    }
    p = @ptrCast(@alignCast(praw));
    p.inTrans = TRANS_NONE;
    p.db = db;
    p.lock.pBtree = p;
    p.lock.iTable = 1;

    // shared-cache: try to find an existing BtShared
    if (isTempDb == false and (isMemdb == false or (vfsFlags & SQLITE_OPEN_URI) != 0)) {
        if ((vfsFlags & SQLITE_OPEN_SHAREDCACHE) != 0) {
            const nFilename = sqlite3Strlen30(zFilename) + 1;
            const nFullPathname = pagerVfsMxPathname(pVfs) + 1;
            const zFullPathnameRaw = sqlite3Malloc(@intCast(MAX(nFullPathname, nFilename)));
            p.sharable = 1;
            if (zFullPathnameRaw == null) {
                sqlite3_free(p);
                return nomem_bkpt();
            }
            const zFullPathname: [*]u8 = @ptrCast(zFullPathnameRaw);
            if (isMemdb) {
                @memcpy(zFullPathname[0..@intCast(nFilename)], @as([*]const u8, @ptrCast(zFilename.?))[0..@intCast(nFilename)]);
            } else {
                rc = sqlite3OsFullPathname(pVfs, zFilename, nFullPathname, zFullPathname);
                if (rc != 0) {
                    if (rc == SQLITE_OK_SYMLINK) {
                        rc = SQLITE_OK;
                    } else {
                        sqlite3_free(zFullPathname);
                        sqlite3_free(p);
                        return rc;
                    }
                }
            }
            mutexOpen = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_OPEN);
            sqlite3_mutex_enter(mutexOpen);
            const mutexShared = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
            sqlite3_mutex_enter(mutexShared);
            var it = sqlite3SharedCacheList;
            while (it) |bt| : (it = bt.pNext) {
                if (strcmp(@ptrCast(zFullPathname), sqlite3PagerFilename(bt.pPager, 0).?) == 0 and
                    sqlite3PagerVfs(bt.pPager) == pVfs)
                {
                    var iDb = dbNDb(db) - 1;
                    while (iDb >= 0) : (iDb -= 1) {
                        const pExisting = dbADbPBt(db, iDb);
                        if (pExisting != null and pExisting.?.pBt == bt) {
                            sqlite3_mutex_leave(mutexShared);
                            sqlite3_mutex_leave(mutexOpen);
                            sqlite3_free(zFullPathname);
                            sqlite3_free(p);
                            return SQLITE_CONSTRAINT;
                        }
                    }
                    p.pBt = bt;
                    bt.nRef += 1;
                    pBt = bt;
                    break;
                }
            }
            sqlite3_mutex_leave(mutexShared);
            sqlite3_free(zFullPathname);
        } else if (config.sqlite_debug) {
            // In debug mode, mark all persistent databases sharable.
            p.sharable = 1;
        }
    }

    if (pBt == null) {
        @memset(zDbHeader[16..24], 0);
        const btraw = sqlite3MallocZero(@sizeOf(BtShared));
        if (btraw == null) {
            rc = nomem_bkpt();
            return openOut(&rc, p, pBt, ppBtree, mutexOpen);
        }
        pBt = @ptrCast(@alignCast(btraw));
        rc = sqlite3PagerOpen(pVfs, &pBt.?.pPager, zFilename, @sizeOf(MemPage), flags, vfsFlags, pageReinit);
        if (rc == SQLITE_OK) {
            sqlite3PagerSetMmapLimit(pBt.?.pPager, fieldPtr(i64, db, off_db_szMmap).*);
            rc = sqlite3PagerReadFileheader(pBt.?.pPager, @sizeOf(@TypeOf(zDbHeader)), &zDbHeader);
        }
        if (rc != SQLITE_OK) {
            return openOut(&rc, p, pBt, ppBtree, mutexOpen);
        }
        pBt.?.openFlags = @truncate(@as(c_uint, @bitCast(flags)));
        pBt.?.db = db;
        sqlite3PagerSetBusyHandler(pBt.?.pPager, btreeInvokeBusyHandler, pBt);
        p.pBt = pBt;
        pBt.?.pCursor = null;
        pBt.?.pPage1 = null;
        if (sqlite3PagerIsreadonly(pBt.?.pPager) != 0) pBt.?.btsFlags |= BTS_READ_ONLY;
        pBt.?.pageSize = (@as(u32, zDbHeader[16]) << 8) | (@as(u32, zDbHeader[17]) << 16);
        if (pBt.?.pageSize < 512 or pBt.?.pageSize > SQLITE_MAX_PAGE_SIZE or
            ((pBt.?.pageSize - 1) & pBt.?.pageSize) != 0)
        {
            pBt.?.pageSize = 0;
            if (zFilename != null and !isMemdb) {
                pBt.?.autoVacuum = if (SQLITE_DEFAULT_AUTOVACUUM != 0) 1 else 0;
                pBt.?.incrVacuum = if (SQLITE_DEFAULT_AUTOVACUUM == 2) 1 else 0;
            }
            nReserve = 0;
        } else {
            nReserve = zDbHeader[20];
            pBt.?.btsFlags |= BTS_PAGESIZE_FIXED;
            pBt.?.autoVacuum = if (get4byte(zDbHeader[36 + 4 * 4 ..].ptr) != 0) 1 else 0;
            pBt.?.incrVacuum = if (get4byte(zDbHeader[36 + 7 * 4 ..].ptr) != 0) 1 else 0;
        }
        rc = sqlite3PagerSetPagesize(pBt.?.pPager, &pBt.?.pageSize, nReserve);
        if (rc != 0) return openOut(&rc, p, pBt, ppBtree, mutexOpen);
        pBt.?.usableSize = pBt.?.pageSize - nReserve;

        // shared-cache: add to list
        pBt.?.nRef = 1;
        if (p.sharable != 0) {
            const mutexShared = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
            if (cfgBCoreMutex() != 0) {
                pBt.?.mutex = sqlite3MutexAlloc(SQLITE_MUTEX_FAST);
                if (pBt.?.mutex == null) {
                    rc = nomem_bkpt();
                    return openOut(&rc, p, pBt, ppBtree, mutexOpen);
                }
            }
            sqlite3_mutex_enter(mutexShared);
            pBt.?.pNext = sqlite3SharedCacheList;
            sqlite3SharedCacheList = pBt;
            sqlite3_mutex_leave(mutexShared);
        }
    }

    // link the new Btree into the connection's sharable-Btree list (sorted by pBt)
    if (p.sharable != 0) {
        var i: c_int = 0;
        while (i < dbNDb(db)) : (i += 1) {
            const pSibInit = dbADbPBt(db, i);
            if (pSibInit != null and pSibInit.?.sharable != 0) {
                var pSib = pSibInit.?;
                while (pSib.pPrev) |pp| {
                    pSib = pp;
                }
                if (@intFromPtr(p.pBt) < @intFromPtr(pSib.pBt)) {
                    p.pNext = pSib;
                    p.pPrev = null;
                    pSib.pPrev = p;
                } else {
                    while (pSib.pNext != null and @intFromPtr(pSib.pNext.?.pBt) < @intFromPtr(p.pBt)) {
                        pSib = pSib.pNext.?;
                    }
                    p.pNext = pSib.pNext;
                    p.pPrev = pSib;
                    if (p.pNext) |pn| {
                        pn.pPrev = p;
                    }
                    pSib.pNext = p;
                }
                break;
            }
        }
    }
    ppBtree.* = p;
    return openOut(&rc, p, pBt, ppBtree, mutexOpen);
}

fn openOut(rc: *c_int, p: *Btree, pBt: ?*BtShared, ppBtree: *?*Btree, mutexOpen: ?*sqlite3_mutex) c_int {
    if (rc.* != SQLITE_OK) {
        if (pBt != null and pBt.?.pPager != null) {
            _ = sqlite3PagerClose(pBt.?.pPager, null);
        }
        sqlite3_free(pBt);
        sqlite3_free(p);
        ppBtree.* = null;
    } else {
        ppBtree.* = p;
        if (sqlite3BtreeSchema(p, 0, null) == null) {
            _ = sqlite3BtreeSetCacheSize(p, SQLITE_DEFAULT_CACHE_SIZE);
        }
        const pFile = sqlite3PagerFile(pBt.?.pPager).?;
        if (fileMethods(pFile) != null) {
            sqlite3OsFileControlHint(pFile, SQLITE_FCNTL_PDB, @ptrCast(&pBt.?.db));
        }
    }
    if (mutexOpen) |mo| {
        sqlite3_mutex_leave(mo);
    }
    return rc.*;
}

// sqlite3_vfs.mxPathname is at offset 8 (iVersion:int@0, szOsFile:int@4, mxPathname:int@8).
inline fn pagerVfsMxPathname(pVfs: ?*sqlite3_vfs) c_int {
    return fieldPtr(c_int, pVfs, 8).*;
}
inline fn fileMethods(pFile: ?*sqlite3_file) ?*anyopaque {
    return fieldPtr(?*anyopaque, pFile, 0).*;
}

const SQLITE_DEFAULT_AUTOVACUUM: c_int = 0;

fn removeFromSharingList(pBt: *BtShared) c_int {
    const pMainMtx = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
    var removed: c_int = 0;
    sqlite3_mutex_enter(pMainMtx);
    pBt.nRef -= 1;
    if (pBt.nRef <= 0) {
        if (sqlite3SharedCacheList == pBt) {
            sqlite3SharedCacheList = pBt.pNext;
        } else {
            var pList = sqlite3SharedCacheList;
            while (pList != null and pList.?.pNext != pBt) {
                pList = pList.?.pNext;
            }
            if (pList) |pl| {
                pl.pNext = pBt.pNext;
            }
        }
        sqlite3_mutex_free(pBt.mutex);
        removed = 1;
    }
    sqlite3_mutex_leave(pMainMtx);
    return removed;
}

fn allocateTempSpace(pBt: *BtShared) c_int {
    pBt.pTmpSpace = @ptrCast(sqlite3PageMalloc(@intCast(pBt.pageSize)));
    if (pBt.pTmpSpace == null) {
        const pCur = pBt.pCursor.?;
        pBt.pCursor = pCur.pNext;
        @memset(std.mem.asBytes(pCur), 0);
        return nomem_bkpt();
    }
    @memset(pBt.pTmpSpace.?[0..8], 0);
    pBt.pTmpSpace.? += 4;
    return SQLITE_OK;
}

fn freeTempSpace(pBt: *BtShared) void {
    if (pBt.pTmpSpace) |ts| {
        pBt.pTmpSpace = ts - 4;
        sqlite3PageFree(pBt.pTmpSpace);
        pBt.pTmpSpace = null;
    }
}

export fn sqlite3BtreeClose(p: *Btree) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    _ = sqlite3BtreeRollback(p, SQLITE_OK, 0);
    sqlite3BtreeLeave(p);
    if (p.sharable == 0 or removeFromSharingList(pBt) != 0) {
        _ = sqlite3PagerClose(pBt.pPager, p.db);
        if (pBt.xFreeSchema != null and pBt.pSchema != null) {
            pBt.xFreeSchema.?(pBt.pSchema);
        }
        sqlite3DbFree(null, pBt.pSchema);
        freeTempSpace(pBt);
        sqlite3_free(pBt);
    }
    if (p.pPrev) |pp| pp.pNext = p.pNext;
    if (p.pNext) |pn| pn.pPrev = p.pPrev;
    sqlite3_free(p);
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// Cache size / page size / pager-flags / autovacuum getters/setters
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3BtreeSetCacheSize(p: *Btree, mxPage: c_int) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    sqlite3PagerSetCachesize(pBt.pPager, mxPage);
    sqlite3BtreeLeave(p);
    return SQLITE_OK;
}

export fn sqlite3BtreeSetSpillSize(p: *Btree, mxPage: c_int) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    const res = sqlite3PagerSetSpillsize(pBt.pPager, mxPage);
    sqlite3BtreeLeave(p);
    return res;
}

export fn sqlite3BtreeSetMmapLimit(p: *Btree, szMmap: i64) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    sqlite3PagerSetMmapLimit(pBt.pPager, szMmap);
    sqlite3BtreeLeave(p);
    return SQLITE_OK;
}

export fn sqlite3BtreeSetPagerFlags(p: *Btree, pgFlags: c_uint) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    sqlite3PagerSetFlags(pBt.pPager, pgFlags);
    sqlite3BtreeLeave(p);
    return SQLITE_OK;
}

export fn sqlite3BtreeSetPageSize(p: *Btree, pageSize_in: c_int, nReserve_in: c_int, iFix: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var pageSize = pageSize_in;
    var nReserve = nReserve_in;
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    pBt.nReserveWanted = @truncate(@as(c_uint, @bitCast(nReserve)));
    const x = @as(c_int, @bitCast(pBt.pageSize)) - @as(c_int, @bitCast(pBt.usableSize));
    if (x == nReserve and (pageSize == 0 or @as(u32, @bitCast(pageSize)) == pBt.pageSize)) {
        sqlite3BtreeLeave(p);
        return SQLITE_OK;
    }
    if (nReserve < x) nReserve = x;
    if ((pBt.btsFlags & BTS_PAGESIZE_FIXED) != 0) {
        sqlite3BtreeLeave(p);
        return SQLITE_READONLY;
    }
    if (pageSize >= 512 and pageSize <= @as(c_int, @intCast(SQLITE_MAX_PAGE_SIZE)) and ((pageSize - 1) & pageSize) == 0) {
        if (nReserve > 32 and pageSize == 512) pageSize = 1024;
        pBt.pageSize = @bitCast(pageSize);
        freeTempSpace(pBt);
    }
    rc = sqlite3PagerSetPagesize(pBt.pPager, &pBt.pageSize, nReserve);
    pBt.usableSize = pBt.pageSize - @as(u32, @intCast(@as(u8, @truncate(@as(c_uint, @bitCast(nReserve))))));
    if (iFix != 0) pBt.btsFlags |= BTS_PAGESIZE_FIXED;
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeGetPageSize(p: *Btree) callconv(.c) c_int {
    return @intCast(p.pBt.?.pageSize);
}

export fn sqlite3BtreeGetReserveNoMutex(p: *Btree) callconv(.c) c_int {
    return @as(c_int, @intCast(p.pBt.?.pageSize)) - @as(c_int, @intCast(p.pBt.?.usableSize));
}

export fn sqlite3BtreeGetRequestedReserve(p: *Btree) callconv(.c) c_int {
    sqlite3BtreeEnter(p);
    const n1: c_int = p.pBt.?.nReserveWanted;
    const n2 = sqlite3BtreeGetReserveNoMutex(p);
    sqlite3BtreeLeave(p);
    return if (n1 > n2) n1 else n2;
}

export fn sqlite3BtreeMaxPageCount(p: *Btree, mxPage: u32) callconv(.c) u32 {
    sqlite3BtreeEnter(p);
    const n = sqlite3PagerMaxPageCount(p.pBt.?.pPager, mxPage);
    sqlite3BtreeLeave(p);
    return n;
}

export fn sqlite3BtreeSecureDelete(p: ?*Btree, newFlag: c_int) callconv(.c) c_int {
    if (p == null) return 0;
    sqlite3BtreeEnter(p.?);
    if (newFlag >= 0) {
        p.?.pBt.?.btsFlags &= ~BTS_FAST_SECURE;
        p.?.pBt.?.btsFlags |= @as(u16, @truncate(@as(c_uint, @bitCast(BTS_SECURE_DELETE * newFlag))));
    }
    const b = (p.?.pBt.?.btsFlags & BTS_FAST_SECURE) / BTS_SECURE_DELETE;
    sqlite3BtreeLeave(p.?);
    return @intCast(b);
}

export fn sqlite3BtreeSetAutoVacuum(p: *Btree, autoVacuum: c_int) callconv(.c) c_int {
    const pBt = p.pBt.?;
    var rc: c_int = SQLITE_OK;
    const av: u8 = @truncate(@as(c_uint, @bitCast(autoVacuum)));
    sqlite3BtreeEnter(p);
    if ((pBt.btsFlags & BTS_PAGESIZE_FIXED) != 0 and (@as(u8, if (av != 0) 1 else 0)) != pBt.autoVacuum) {
        rc = SQLITE_READONLY;
    } else {
        pBt.autoVacuum = if (av != 0) 1 else 0;
        pBt.incrVacuum = if (av == 2) 1 else 0;
    }
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeGetAutoVacuum(p: *Btree) callconv(.c) c_int {
    sqlite3BtreeEnter(p);
    const rc: c_int = if (p.pBt.?.autoVacuum == 0)
        BTREE_AUTOVACUUM_NONE
    else if (p.pBt.?.incrVacuum == 0)
        BTREE_AUTOVACUUM_FULL
    else
        BTREE_AUTOVACUUM_INCR;
    sqlite3BtreeLeave(p);
    return rc;
}

// setDefaultSyncFlag is a no-op in this build (DEFAULT_SYNCHRONOUS==WAL_SYNCHRONOUS).
inline fn setDefaultSyncFlag(pBt: *BtShared, safety_level: u8) void {
    _ = pBt;
    _ = safety_level;
}

// ════════════════════════════════════════════════════════════════════════════
// lockBtree / newDatabase / NewDb
// ════════════════════════════════════════════════════════════════════════════
fn lockBtree(pBt: *BtShared) c_int {
    var rc: c_int = undefined;
    var pPage1: ?*MemPage = null;
    var nPage: u32 = undefined;
    var nPageFile: u32 = 0;

    rc = sqlite3PagerSharedLock(pBt.pPager);
    if (rc != SQLITE_OK) return rc;
    rc = btreeGetPage(pBt, 1, &pPage1, 0);
    if (rc != SQLITE_OK) return rc;
    const p1data = pPage1.?.aData.?;

    nPage = get4byte(p1data + 28);
    sqlite3PagerPagecount(pBt.pPager, @ptrCast(&nPageFile));
    if (nPage == 0 or memcmp(p1data + 24, p1data + 92, 4) != 0) {
        nPage = nPageFile;
    }
    if ((dbFlags(pBt.db) & SQLITE_ResetDatabase) != 0) {
        nPage = 0;
    }
    if (nPage > 0) {
        var pageSize: u32 = undefined;
        var usableSize: u32 = undefined;
        const page1 = p1data;
        rc = SQLITE_NOTADB;
        if (memcmp(page1, zMagicHeader.ptr, 16) != 0) {
            return lockBtreeFail(pBt, pPage1.?, rc);
        }
        if (page1[18] > 2) {
            pBt.btsFlags |= BTS_READ_ONLY;
        }
        if (page1[19] > 2) {
            return lockBtreeFail(pBt, pPage1.?, rc);
        }
        if (page1[19] == 2 and (pBt.btsFlags & BTS_NO_WAL) == 0) {
            var isOpen: c_int = 0;
            rc = sqlite3PagerOpenWal(pBt.pPager, &isOpen);
            if (rc != SQLITE_OK) {
                return lockBtreeFail(pBt, pPage1.?, rc);
            } else {
                setDefaultSyncFlag(pBt, 3);
                if (isOpen == 0) {
                    releasePageOne(pPage1.?);
                    return SQLITE_OK;
                }
            }
            rc = SQLITE_NOTADB;
        } else {
            setDefaultSyncFlag(pBt, 3);
        }
        if (memcmp(page1 + 21, "\x40\x20\x20", 3) != 0) {
            return lockBtreeFail(pBt, pPage1.?, rc);
        }
        pageSize = (@as(u32, page1[16]) << 8) | (@as(u32, page1[17]) << 16);
        if (((pageSize - 1) & pageSize) != 0 or pageSize > SQLITE_MAX_PAGE_SIZE or pageSize <= 256) {
            return lockBtreeFail(pBt, pPage1.?, rc);
        }
        usableSize = pageSize - page1[20];
        if (pageSize != pBt.pageSize) {
            releasePageOne(pPage1.?);
            pBt.usableSize = usableSize;
            pBt.pageSize = pageSize;
            pBt.btsFlags |= BTS_PAGESIZE_FIXED;
            freeTempSpace(pBt);
            rc = sqlite3PagerSetPagesize(pBt.pPager, &pBt.pageSize, @intCast(pageSize - usableSize));
            return rc;
        }
        if (nPage > nPageFile) {
            if (sqlite3WritableSchema(pBt.db) == 0) {
                rc = corrupt_bkpt(@src().line);
                return lockBtreeFail(pBt, pPage1.?, rc);
            } else {
                nPage = nPageFile;
            }
        }
        if (usableSize < 480) {
            return lockBtreeFail(pBt, pPage1.?, rc);
        }
        pBt.btsFlags |= BTS_PAGESIZE_FIXED;
        pBt.pageSize = pageSize;
        pBt.usableSize = usableSize;
        pBt.autoVacuum = if (get4byte(page1 + 36 + 4 * 4) != 0) 1 else 0;
        pBt.incrVacuum = if (get4byte(page1 + 36 + 7 * 4) != 0) 1 else 0;
    }

    pBt.maxLocal = @truncate(((pBt.usableSize - 12) * 64 / 255) - 23);
    pBt.minLocal = @truncate(((pBt.usableSize - 12) * 32 / 255) - 23);
    pBt.maxLeaf = @truncate(pBt.usableSize - 35);
    pBt.minLeaf = @truncate(((pBt.usableSize - 12) * 32 / 255) - 23);
    if (pBt.maxLocal > 127) {
        pBt.max1bytePayload = 127;
    } else {
        pBt.max1bytePayload = @truncate(pBt.maxLocal);
    }
    pBt.pPage1 = pPage1;
    pBt.nPage = nPage;
    return SQLITE_OK;
}
fn lockBtreeFail(pBt: *BtShared, pPage1: *MemPage, rc: c_int) c_int {
    releasePageOne(pPage1);
    pBt.pPage1 = null;
    return rc;
}

fn countValidCursors(pBt: *BtShared, wrOnly: c_int) c_int {
    var r: c_int = 0;
    var pCur = pBt.pCursor;
    while (pCur) |c| : (pCur = c.pNext) {
        if ((wrOnly == 0 or (c.curFlags & BTCF_WriteFlag) != 0) and c.eState != CURSOR_FAULT) r += 1;
    }
    return r;
}

fn unlockBtreeIfUnused(pBt: *BtShared) void {
    if (pBt.inTransaction == TRANS_NONE and pBt.pPage1 != null) {
        const pPage1 = pBt.pPage1.?;
        pBt.pPage1 = null;
        releasePageOne(pPage1);
    }
}

fn newDatabase(pBt: *BtShared) c_int {
    if (pBt.nPage > 0) {
        return SQLITE_OK;
    }
    const pP1 = pBt.pPage1.?;
    const data = pP1.aData.?;
    const rc = sqlite3PagerWrite(pP1.pDbPage);
    if (rc != 0) return rc;
    @memcpy(data[0..16], zMagicHeader[0..16]);
    data[16] = @truncate((pBt.pageSize >> 8) & 0xff);
    data[17] = @truncate((pBt.pageSize >> 16) & 0xff);
    data[18] = 1;
    data[19] = 1;
    data[20] = @truncate(pBt.pageSize - pBt.usableSize);
    data[21] = 64;
    data[22] = 32;
    data[23] = 32;
    @memset((data + 24)[0 .. 100 - 24], 0);
    zeroPage(pP1, PTF_INTKEY | PTF_LEAF | PTF_LEAFDATA);
    pBt.btsFlags |= BTS_PAGESIZE_FIXED;
    put4byte(data + 36 + 4 * 4, pBt.autoVacuum);
    put4byte(data + 36 + 7 * 4, pBt.incrVacuum);
    pBt.nPage = 1;
    data[31] = 1;
    return SQLITE_OK;
}

export fn sqlite3BtreeNewDb(p: *Btree) callconv(.c) c_int {
    sqlite3BtreeEnter(p);
    p.pBt.?.nPage = 0;
    const rc = newDatabase(p.pBt.?);
    sqlite3BtreeLeave(p);
    return rc;
}

// ════════════════════════════════════════════════════════════════════════════
// Begin transaction
// ════════════════════════════════════════════════════════════════════════════
fn btreeBeginTrans(p: *Btree, wrflag: c_int, pSchemaVersion: ?*c_int) c_int {
    const pBt = p.pBt.?;
    const pPager = pBt.pPager;
    var rc: c_int = SQLITE_OK;

    sqlite3BtreeEnter(p);

    if (p.inTrans == TRANS_WRITE or (p.inTrans == TRANS_READ and wrflag == 0)) {
        return transBegun(p, rc, wrflag, pSchemaVersion);
    }

    if ((dbFlags(p.db) & SQLITE_ResetDatabase) != 0 and sqlite3PagerIsreadonly(pPager) == 0) {
        pBt.btsFlags &= ~BTS_READ_ONLY;
    }

    if ((pBt.btsFlags & BTS_READ_ONLY) != 0 and wrflag != 0) {
        rc = SQLITE_READONLY;
        return transBegun(p, rc, wrflag, pSchemaVersion);
    }

    {
        var pBlock: ?*sqlite3 = null;
        if ((wrflag != 0 and pBt.inTransaction == TRANS_WRITE) or (pBt.btsFlags & BTS_PENDING) != 0) {
            pBlock = pBt.pWriter.?.db;
        } else if (wrflag > 1) {
            var pIter = pBt.pLock;
            while (pIter) |it| : (pIter = it.pNext) {
                if (it.pBtree != p) {
                    pBlock = it.pBtree.?.db;
                    break;
                }
            }
        }
        if (pBlock) |blk| {
            sqlite3ConnectionBlocked(p.db, blk);
            rc = SQLITE_LOCKED_SHAREDCACHE;
            return transBegun(p, rc, wrflag, pSchemaVersion);
        }
    }

    rc = querySharedCacheTableLock(p, SCHEMA_ROOT, READ_LOCK);
    if (rc != SQLITE_OK) return transBegun(p, rc, wrflag, pSchemaVersion);

    pBt.btsFlags &= ~BTS_INITIALLY_EMPTY;
    if (pBt.nPage == 0) pBt.btsFlags |= BTS_INITIALLY_EMPTY;
    while (true) {
        sqlite3PagerWalDb(pPager, p.db);
        while (pBt.pPage1 == null) {
            rc = lockBtree(pBt);
            if (rc != SQLITE_OK) break;
        }
        if (rc == SQLITE_OK and wrflag != 0) {
            if ((pBt.btsFlags & BTS_READ_ONLY) != 0) {
                rc = SQLITE_READONLY;
            } else {
                rc = sqlite3PagerBegin(pPager, @intFromBool(wrflag > 1), sqlite3TempInMemory(p.db));
                if (rc == SQLITE_OK) {
                    rc = newDatabase(pBt);
                } else if (rc == SQLITE_BUSY_SNAPSHOT and pBt.inTransaction == TRANS_NONE) {
                    rc = SQLITE_BUSY;
                }
            }
        }
        if (rc != SQLITE_OK) {
            _ = sqlite3PagerWalWriteLock(pPager, 0);
            unlockBtreeIfUnused(pBt);
        }
        if (!((rc & 0xFF) == SQLITE_BUSY and pBt.inTransaction == TRANS_NONE and btreeInvokeBusyHandler(pBt) != 0)) break;
    }
    sqlite3PagerWalDb(pPager, null);

    if (rc == SQLITE_OK) {
        if (p.inTrans == TRANS_NONE) {
            pBt.nTransaction += 1;
            if (p.sharable != 0) {
                p.lock.eLock = READ_LOCK;
                p.lock.pNext = pBt.pLock;
                pBt.pLock = &p.lock;
            }
        }
        p.inTrans = if (wrflag != 0) TRANS_WRITE else TRANS_READ;
        if (p.inTrans > pBt.inTransaction) {
            pBt.inTransaction = p.inTrans;
        }
        if (wrflag != 0) {
            const pPage1 = pBt.pPage1.?;
            pBt.pWriter = p;
            pBt.btsFlags &= ~BTS_EXCLUSIVE;
            if (wrflag > 1) pBt.btsFlags |= BTS_EXCLUSIVE;
            if (pBt.nPage != get4byte(pPage1.aData.? + 28)) {
                rc = sqlite3PagerWrite(pPage1.pDbPage);
                if (rc == SQLITE_OK) {
                    put4byte(pPage1.aData.? + 28, pBt.nPage);
                }
            }
        }
    }
    return transBegun(p, rc, wrflag, pSchemaVersion);
}

fn transBegun(p: *Btree, rc_in: c_int, wrflag: c_int, pSchemaVersion: ?*c_int) c_int {
    var rc = rc_in;
    if (rc == SQLITE_OK) {
        if (pSchemaVersion) |sv| {
            sv.* = @bitCast(get4byte(p.pBt.?.pPage1.?.aData.? + 40));
        }
        if (wrflag != 0) {
            rc = sqlite3PagerOpenSavepoint(p.pBt.?.pPager, dbNSavepoint(p.db));
        }
    }
    sqlite3BtreeLeave(p);
    return rc;
}

inline fn dbNSavepoint(db: ?*sqlite3) c_int {
    return fieldPtr(c_int, db, off_db_nSavepoint).*;
}

export fn sqlite3BtreeBeginTrans(p: *Btree, wrflag: c_int, pSchemaVersion: ?*c_int) callconv(.c) c_int {
    if (p.sharable != 0 or p.inTrans == TRANS_NONE or (p.inTrans == TRANS_READ and wrflag != 0)) {
        return btreeBeginTrans(p, wrflag, pSchemaVersion);
    }
    const pBt = p.pBt.?;
    if (pSchemaVersion) |sv| {
        sv.* = @bitCast(get4byte(pBt.pPage1.?.aData.? + 40));
    }
    if (wrflag != 0) {
        return sqlite3PagerOpenSavepoint(pBt.pPager, dbNSavepoint(p.db));
    } else {
        return SQLITE_OK;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Autovacuum: ptrmap children, relocate, incremental vacuum, commit
// ════════════════════════════════════════════════════════════════════════════
fn setChildPtrmaps(pPage: *MemPage) c_int {
    const pBt = pPage.pBt.?;
    const pgno = pPage.pgno;
    var rc: c_int = if (pPage.isInit != 0) SQLITE_OK else btreeInitPage(pPage);
    if (rc != SQLITE_OK) return rc;
    const nCell: c_int = pPage.nCell;
    var i: c_int = 0;
    while (i < nCell) : (i += 1) {
        const pCell = findCell(pPage, i);
        ptrmapPutOvflPtr(pPage, pPage, pCell, &rc);
        if (pPage.leaf == 0) {
            const childPgno = get4byte(pCell);
            ptrmapPut(pBt, childPgno, PTRMAP_BTREE, pgno, &rc);
        }
    }
    if (pPage.leaf == 0) {
        const childPgno = get4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8);
        ptrmapPut(pBt, childPgno, PTRMAP_BTREE, pgno, &rc);
    }
    return rc;
}

fn modifyPagePointer(pPage: *MemPage, iFrom: u32, iTo: u32, eType: u8) c_int {
    if (eType == PTRMAP_OVERFLOW2) {
        if (get4byte(pPage.aData.?) != iFrom) {
            return corrupt_page(pPage);
        }
        put4byte(pPage.aData.?, iTo);
    } else {
        const rc: c_int = if (pPage.isInit != 0) SQLITE_OK else btreeInitPage(pPage);
        if (rc != 0) return rc;
        const nCell: c_int = pPage.nCell;
        var i: c_int = 0;
        while (i < nCell) : (i += 1) {
            const pCell = findCell(pPage, i);
            if (eType == PTRMAP_OVERFLOW1) {
                var info: CellInfo = undefined;
                pPage.xParseCell(pPage, pCell, &info);
                if (info.nLocal < info.nPayload) {
                    if (@intFromPtr(pCell + info.nSize) > @intFromPtr(pPage.aData.?) + pPage.pBt.?.usableSize) {
                        return corrupt_page(pPage);
                    }
                    if (iFrom == get4byte(pCell + info.nSize - 4)) {
                        put4byte(pCell + info.nSize - 4, iTo);
                        break;
                    }
                }
            } else {
                if (@intFromPtr(pCell + 4) > @intFromPtr(pPage.aData.?) + pPage.pBt.?.usableSize) {
                    return corrupt_page(pPage);
                }
                if (get4byte(pCell) == iFrom) {
                    put4byte(pCell, iTo);
                    break;
                }
            }
        }
        if (i == nCell) {
            if (eType != PTRMAP_BTREE or get4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8) != iFrom) {
                return corrupt_page(pPage);
            }
            put4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8, iTo);
        }
    }
    return SQLITE_OK;
}

fn relocatePage(pBt: *BtShared, pDbPage: *MemPage, eType: u8, iPtrPage: u32, iFreePage: u32, isCommit: c_int) c_int {
    const iDbPage = pDbPage.pgno;
    const pPager = pBt.pPager;
    var rc: c_int = undefined;
    if (iDbPage < 3) return corrupt_bkpt(@src().line);
    rc = sqlite3PagerMovepage(pPager, pDbPage.pDbPage, iFreePage, isCommit);
    if (rc != SQLITE_OK) {
        return rc;
    }
    pDbPage.pgno = iFreePage;

    if (eType == PTRMAP_BTREE or eType == PTRMAP_ROOTPAGE) {
        rc = setChildPtrmaps(pDbPage);
        if (rc != SQLITE_OK) {
            return rc;
        }
    } else {
        const nextOvfl = get4byte(pDbPage.aData.?);
        if (nextOvfl != 0) {
            ptrmapPut(pBt, nextOvfl, PTRMAP_OVERFLOW2, iFreePage, &rc);
            if (rc != SQLITE_OK) {
                return rc;
            }
        }
    }

    if (eType != PTRMAP_ROOTPAGE) {
        var pPtrPage: ?*MemPage = null;
        rc = btreeGetPage(pBt, iPtrPage, &pPtrPage, 0);
        if (rc != SQLITE_OK) {
            return rc;
        }
        rc = sqlite3PagerWrite(pPtrPage.?.pDbPage);
        if (rc != SQLITE_OK) {
            releasePage(pPtrPage);
            return rc;
        }
        rc = modifyPagePointer(pPtrPage.?, iDbPage, iFreePage, eType);
        releasePage(pPtrPage);
        if (rc == SQLITE_OK) {
            ptrmapPut(pBt, iFreePage, eType, iPtrPage, &rc);
        }
    }
    return rc;
}

fn incrVacuumStep(pBt: *BtShared, nFin: u32, iLastPg_in: u32, bCommit: c_int) c_int {
    var iLastPg = iLastPg_in;
    var rc: c_int = undefined;

    if (!PTRMAP_ISPAGE(pBt, iLastPg) and iLastPg != PENDING_BYTE_PAGE(pBt)) {
        var eType: u8 = undefined;
        var iPtrPage: u32 = undefined;

        const nFreeList = get4byte(pBt.pPage1.?.aData.? + 36);
        if (nFreeList == 0) {
            return SQLITE_DONE;
        }
        rc = ptrmapGet(pBt, iLastPg, &eType, &iPtrPage);
        if (rc != SQLITE_OK) {
            return rc;
        }
        if (eType == PTRMAP_ROOTPAGE) {
            return corrupt_bkpt(@src().line);
        }
        if (eType == PTRMAP_FREEPAGE) {
            if (bCommit == 0) {
                var iFreePg: u32 = undefined;
                var pFreePg: ?*MemPage = null;
                rc = allocateBtreePage(pBt, &pFreePg, &iFreePg, iLastPg, BTALLOC_EXACT);
                if (rc != SQLITE_OK) {
                    return rc;
                }
                releasePage(pFreePg);
            }
        } else {
            var iFreePg: u32 = undefined;
            var pLastPg: ?*MemPage = null;
            var eMode: u8 = BTALLOC_ANY;
            var iNear: u32 = 0;
            rc = btreeGetPage(pBt, iLastPg, &pLastPg, 0);
            if (rc != SQLITE_OK) {
                return rc;
            }
            if (bCommit == 0) {
                eMode = BTALLOC_LE;
                iNear = nFin;
            }
            while (true) {
                var pFreePg: ?*MemPage = null;
                const dbSize = btreePagecount(pBt);
                rc = allocateBtreePage(pBt, &pFreePg, &iFreePg, iNear, eMode);
                if (rc != SQLITE_OK) {
                    releasePage(pLastPg);
                    return rc;
                }
                releasePage(pFreePg);
                if (iFreePg > dbSize) {
                    releasePage(pLastPg);
                    return corrupt_bkpt(@src().line);
                }
                if (!(bCommit != 0 and iFreePg > nFin)) break;
            }
            rc = relocatePage(pBt, pLastPg.?, eType, iPtrPage, iFreePg, bCommit);
            releasePage(pLastPg);
            if (rc != SQLITE_OK) {
                return rc;
            }
        }
    }

    if (bCommit == 0) {
        while (true) {
            iLastPg -= 1;
            if (!(iLastPg == PENDING_BYTE_PAGE(pBt) or PTRMAP_ISPAGE(pBt, iLastPg))) break;
        }
        pBt.bDoTruncate = 1;
        pBt.nPage = iLastPg;
    }
    return SQLITE_OK;
}

fn finalDbSize(pBt: *BtShared, nOrig: u32, nFree: u32) u32 {
    const nEntry = pBt.usableSize / 5;
    const nPtrmap = (nFree -% nOrig +% PTRMAP_PAGENO(pBt, nOrig) +% nEntry) / nEntry;
    var nFin = nOrig -% nFree -% nPtrmap;
    if (nOrig > PENDING_BYTE_PAGE(pBt) and nFin < PENDING_BYTE_PAGE(pBt)) {
        nFin -= 1;
    }
    while (PTRMAP_ISPAGE(pBt, nFin) or nFin == PENDING_BYTE_PAGE(pBt)) {
        nFin -= 1;
    }
    return nFin;
}

export fn sqlite3BtreeIncrVacuum(p: *Btree) callconv(.c) c_int {
    var rc: c_int = undefined;
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    if (pBt.autoVacuum == 0) {
        rc = SQLITE_DONE;
    } else {
        const nOrig = btreePagecount(pBt);
        const nFree = get4byte(pBt.pPage1.?.aData.? + 36);
        const nFin = finalDbSize(pBt, nOrig, nFree);
        if (nOrig < nFin or nFree >= nOrig) {
            rc = corrupt_bkpt(@src().line);
        } else if (nFree > 0) {
            rc = saveAllCursors(pBt, 0, null);
            if (rc == SQLITE_OK) {
                invalidateAllOverflowCache(pBt);
                rc = incrVacuumStep(pBt, nFin, nOrig, 0);
            }
            if (rc == SQLITE_OK) {
                rc = sqlite3PagerWrite(pBt.pPage1.?.pDbPage);
                put4byte(pBt.pPage1.?.aData.? + 28, pBt.nPage);
            }
        } else {
            rc = SQLITE_DONE;
        }
    }
    sqlite3BtreeLeave(p);
    return rc;
}

fn autoVacuumCommit(p: *Btree) c_int {
    var rc: c_int = SQLITE_OK;
    const pBt = p.pBt.?;
    const pPager = pBt.pPager;
    invalidateAllOverflowCache(pBt);
    if (pBt.incrVacuum == 0) {
        var nVac: u32 = undefined;
        const nOrig = btreePagecount(pBt);
        if (PTRMAP_ISPAGE(pBt, nOrig) or nOrig == PENDING_BYTE_PAGE(pBt)) {
            return corrupt_bkpt(@src().line);
        }
        const nFree = get4byte(pBt.pPage1.?.aData.? + 36);
        const db = p.db;
        const xAutovacPages = fieldPtr(?*const fn (?*anyopaque, ?[*:0]const u8, u32, u32, u32) callconv(.c) u32, db, off_db_xAutovacPages).*;
        if (xAutovacPages) |cb| {
            var iDb: c_int = 0;
            while (iDb < dbNDb(db)) : (iDb += 1) {
                if (dbADbPBt(db, iDb) == p) break;
            }
            const zDbSName = @as(*align(1) ?[*:0]const u8, @ptrCast(dbADb(db) + @as(usize, @intCast(iDb)) * sizeof_Db + off_Db_zDbSName)).*;
            const pArg = fieldPtr(?*anyopaque, db, off_db_pAutovacPagesArg).*;
            nVac = cb(pArg, zDbSName, nOrig, nFree, pBt.pageSize);
            if (nVac > nFree) nVac = nFree;
            if (nVac == 0) {
                return SQLITE_OK;
            }
        } else {
            nVac = nFree;
        }
        const nFin = finalDbSize(pBt, nOrig, nVac);
        if (nFin > nOrig) return corrupt_bkpt(@src().line);
        if (nFin < nOrig) {
            rc = saveAllCursors(pBt, 0, null);
        }
        var iFree = nOrig;
        while (iFree > nFin and rc == SQLITE_OK) : (iFree -= 1) {
            rc = incrVacuumStep(pBt, nFin, iFree, @intFromBool(nVac == nFree));
        }
        if ((rc == SQLITE_DONE or rc == SQLITE_OK) and nFree > 0) {
            rc = sqlite3PagerWrite(pBt.pPage1.?.pDbPage);
            if (nVac == nFree) {
                put4byte(pBt.pPage1.?.aData.? + 32, 0);
                put4byte(pBt.pPage1.?.aData.? + 36, 0);
            }
            put4byte(pBt.pPage1.?.aData.? + 28, nFin);
            pBt.bDoTruncate = 1;
            pBt.nPage = nFin;
        }
        if (rc != SQLITE_OK) {
            _ = sqlite3PagerRollback(pPager);
        }
    }
    return rc;
}

// ════════════════════════════════════════════════════════════════════════════
// Commit / Rollback / Savepoint / TripAllCursors
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3BtreeCommitPhaseOne(p: *Btree, zSuperJrnl: ?[*:0]const u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (p.inTrans == TRANS_WRITE) {
        const pBt = p.pBt.?;
        sqlite3BtreeEnter(p);
        if (pBt.autoVacuum != 0) {
            rc = autoVacuumCommit(p);
            if (rc != SQLITE_OK) {
                sqlite3BtreeLeave(p);
                return rc;
            }
        }
        if (pBt.bDoTruncate != 0) {
            sqlite3PagerTruncateImage(pBt.pPager, pBt.nPage);
        }
        rc = sqlite3PagerCommitPhaseOne(pBt.pPager, zSuperJrnl, 0);
        sqlite3BtreeLeave(p);
    }
    return rc;
}

fn btreeEndTransaction(p: *Btree) void {
    const pBt = p.pBt.?;
    const db = p.db;
    pBt.bDoTruncate = 0;
    if (p.inTrans > TRANS_NONE and dbNVdbeRead(db) > 1) {
        downgradeAllSharedCacheTableLocks(p);
        p.inTrans = TRANS_READ;
    } else {
        if (p.inTrans != TRANS_NONE) {
            clearAllSharedCacheTableLocks(p);
            pBt.nTransaction -= 1;
            if (pBt.nTransaction == 0) {
                pBt.inTransaction = TRANS_NONE;
            }
        }
        p.inTrans = TRANS_NONE;
        unlockBtreeIfUnused(pBt);
    }
}
inline fn dbNVdbeRead(db: ?*sqlite3) c_int {
    return fieldPtr(c_int, db, off_db_nVdbeRead).*;
}

export fn sqlite3BtreeCommitPhaseTwo(p: *Btree, bCleanup: c_int) callconv(.c) c_int {
    if (p.inTrans == TRANS_NONE) return SQLITE_OK;
    sqlite3BtreeEnter(p);
    if (p.inTrans == TRANS_WRITE) {
        const pBt = p.pBt.?;
        const rc = sqlite3PagerCommitPhaseTwo(pBt.pPager);
        if (rc != SQLITE_OK and bCleanup == 0) {
            sqlite3BtreeLeave(p);
            return rc;
        }
        p.iBDataVersion -%= 1;
        pBt.inTransaction = TRANS_READ;
        btreeClearHasContent(pBt);
    }
    btreeEndTransaction(p);
    sqlite3BtreeLeave(p);
    return SQLITE_OK;
}

export fn sqlite3BtreeCommit(p: *Btree) callconv(.c) c_int {
    sqlite3BtreeEnter(p);
    var rc = sqlite3BtreeCommitPhaseOne(p, null);
    if (rc == SQLITE_OK) {
        rc = sqlite3BtreeCommitPhaseTwo(p, 0);
    }
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeTripAllCursors(pBtree: ?*Btree, errCode: c_int, writeOnly: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (pBtree) |bt| {
        sqlite3BtreeEnter(bt);
        var p = bt.pBt.?.pCursor;
        while (p) |c| : (p = c.pNext) {
            if (writeOnly != 0 and (c.curFlags & BTCF_WriteFlag) == 0) {
                if (c.eState == CURSOR_VALID or c.eState == CURSOR_SKIPNEXT) {
                    rc = saveCursorPosition(c);
                    if (rc != SQLITE_OK) {
                        _ = sqlite3BtreeTripAllCursors(bt, rc, 0);
                        break;
                    }
                }
            } else {
                sqlite3BtreeClearCursor(c);
                c.eState = CURSOR_FAULT;
                c.skipNext = errCode;
            }
            btreeReleaseAllCursorPages(c);
        }
        sqlite3BtreeLeave(bt);
    }
    return rc;
}

fn btreeSetNPage(pBt: *BtShared, pPage1: *MemPage) void {
    var nPage = get4byte(pPage1.aData.? + 28);
    if (nPage == 0) sqlite3PagerPagecount(pBt.pPager, @ptrCast(&nPage));
    pBt.nPage = nPage;
}

export fn sqlite3BtreeRollback(p: *Btree, tripCode_in: c_int, writeOnly_in: c_int) callconv(.c) c_int {
    var rc: c_int = undefined;
    var tripCode = tripCode_in;
    var writeOnly = writeOnly_in;
    const pBt = p.pBt.?;
    var pPage1: ?*MemPage = null;
    sqlite3BtreeEnter(p);
    if (tripCode == SQLITE_OK) {
        rc = saveAllCursors(pBt, 0, null);
        tripCode = rc;
        if (rc != 0) writeOnly = 0;
    } else {
        rc = SQLITE_OK;
    }
    if (tripCode != 0) {
        const rc2 = sqlite3BtreeTripAllCursors(p, tripCode, writeOnly);
        if (rc2 != SQLITE_OK) rc = rc2;
    }
    if (p.inTrans == TRANS_WRITE) {
        const rc2 = sqlite3PagerRollback(pBt.pPager);
        if (rc2 != SQLITE_OK) {
            rc = rc2;
        }
        if (btreeGetPage(pBt, 1, &pPage1, 0) == SQLITE_OK) {
            btreeSetNPage(pBt, pPage1.?);
            releasePageOne(pPage1.?);
        }
        pBt.inTransaction = TRANS_READ;
        btreeClearHasContent(pBt);
    }
    btreeEndTransaction(p);
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeBeginStmt(p: *Btree, iStatement: c_int) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    const rc = sqlite3PagerOpenSavepoint(pBt.pPager, iStatement);
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeSavepoint(p: ?*Btree, op: c_int, iSavepoint: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (p != null and p.?.inTrans == TRANS_WRITE) {
        const pBt = p.?.pBt.?;
        sqlite3BtreeEnter(p.?);
        if (op == SAVEPOINT_ROLLBACK) {
            rc = saveAllCursors(pBt, 0, null);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3PagerSavepoint(pBt.pPager, op, iSavepoint);
        }
        if (rc == SQLITE_OK) {
            if (iSavepoint < 0 and (pBt.btsFlags & BTS_INITIALLY_EMPTY) != 0) {
                pBt.nPage = 0;
            }
            rc = newDatabase(pBt);
            btreeSetNPage(pBt, pBt.pPage1.?);
        }
        sqlite3BtreeLeave(p.?);
    }
    return rc;
}

// ════════════════════════════════════════════════════════════════════════════
// Cursor open / close / accessors
// ════════════════════════════════════════════════════════════════════════════
fn btreeCursor(p: *Btree, iTable_in: u32, wrFlag: c_int, pKeyInfo: ?*KeyInfo, pCur: *BtCursor) c_int {
    const pBt = p.pBt.?;
    var iTable = iTable_in;

    if (iTable <= 1) {
        if (iTable < 1) {
            return corrupt_bkpt(@src().line);
        } else if (btreePagecount(pBt) == 0) {
            iTable = 0;
        }
    }

    pCur.pgnoRoot = iTable;
    pCur.iPage = -1;
    pCur.pKeyInfo = pKeyInfo;
    pCur.pBtree = p;
    pCur.pBt = pBt;
    pCur.curFlags = 0;
    var pX = pBt.pCursor;
    while (pX) |x| : (pX = x.pNext) {
        if (x.pgnoRoot == iTable) {
            x.curFlags |= BTCF_Multiple;
            pCur.curFlags = BTCF_Multiple;
        }
    }
    pCur.eState = CURSOR_INVALID;
    pCur.pNext = pBt.pCursor;
    pBt.pCursor = pCur;
    if (wrFlag != 0) {
        pCur.curFlags |= BTCF_WriteFlag;
        pCur.curPagerFlags = 0;
        if (pBt.pTmpSpace == null) return allocateTempSpace(pBt);
    } else {
        pCur.curPagerFlags = PAGER_GET_READONLY;
    }
    return SQLITE_OK;
}

fn btreeCursorWithLock(p: *Btree, iTable: u32, wrFlag: c_int, pKeyInfo: ?*KeyInfo, pCur: *BtCursor) c_int {
    sqlite3BtreeEnter(p);
    const rc = btreeCursor(p, iTable, wrFlag, pKeyInfo, pCur);
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeCursor(p: *Btree, iTable: u32, wrFlag: c_int, pKeyInfo: ?*KeyInfo, pCur: *BtCursor) callconv(.c) c_int {
    if (p.sharable != 0) {
        return btreeCursorWithLock(p, iTable, wrFlag, pKeyInfo, pCur);
    } else {
        return btreeCursor(p, iTable, wrFlag, pKeyInfo, pCur);
    }
}

export fn sqlite3BtreeCursorSize() callconv(.c) c_int {
    return (@sizeOf(BtCursor) + 7) & ~@as(c_int, 7);
}

comptime {
    if (config.sqlite_debug) {
        @export(&btreeClosesWithCursor, .{ .name = "sqlite3BtreeClosesWithCursor", .linkage = .strong });
    }
}
fn btreeClosesWithCursor(pBtree: *Btree, pCur: *BtCursor) callconv(.c) c_int {
    const pBt = pBtree.pBt.?;
    if ((pBt.openFlags & BTREE_SINGLE) == 0) return 0;
    if (pBt.pCursor != pCur) return 0;
    if (pCur.pNext != null) return 0;
    if (pCur.pBtree != pBtree) return 0;
    return 1;
}

export fn sqlite3BtreeCursorZero(p: *BtCursor) callconv(.c) void {
    // memset to offsetof(BtCursor, pBt) == 32
    @memset(@as([*]u8, @ptrCast(p))[0..32], 0);
}

export fn sqlite3BtreeCloseCursor(pCur: *BtCursor) callconv(.c) c_int {
    const pBtree = pCur.pBtree;
    if (pBtree) |bt| {
        const pBt = pCur.pBt.?;
        sqlite3BtreeEnter(bt);
        if (pBt.pCursor == pCur) {
            pBt.pCursor = pCur.pNext;
        } else {
            var pPrev = pBt.pCursor;
            while (pPrev) |pp| {
                if (pp.pNext == pCur) {
                    pp.pNext = pCur.pNext;
                    break;
                }
                pPrev = pp.pNext;
            }
        }
        btreeReleaseAllCursorPages(pCur);
        unlockBtreeIfUnused(pBt);
        sqlite3_free(pCur.aOverflow);
        sqlite3_free(pCur.pKey);
        if ((pBt.openFlags & BTREE_SINGLE) != 0 and pBt.pCursor == null) {
            _ = sqlite3BtreeClose(bt);
        } else {
            sqlite3BtreeLeave(bt);
        }
        pCur.pBtree = null;
    }
    return SQLITE_OK;
}

// sqlite3BtreeCursorIsValid is guarded by `#ifndef NDEBUG`. The production lib
// here is built with NDEBUG (the C btree.c object does not export it), while the
// --dev testfixture (SQLITE_DEBUG, no NDEBUG) does. Gate it on config.sqlite_debug.
comptime {
    if (config.sqlite_debug) {
        @export(&btreeCursorIsValid, .{ .name = "sqlite3BtreeCursorIsValid", .linkage = .strong });
    }
}
fn btreeCursorIsValid(pCur: ?*BtCursor) callconv(.c) c_int {
    return @intFromBool(pCur != null and pCur.?.eState == CURSOR_VALID);
}
export fn sqlite3BtreeCursorIsValidNN(pCur: *BtCursor) callconv(.c) c_int {
    return @intFromBool(pCur.eState == CURSOR_VALID);
}

// ── getCellInfo ─────────────────────────────────────────────────────────────
fn getCellInfo(pCur: *BtCursor) void {
    if (pCur.info.nSize == 0) {
        pCur.curFlags |= BTCF_ValidNKey;
        btreeParseCell(pCur.pPage.?, pCur.ix, &pCur.info);
    }
}

export fn sqlite3BtreeIntegerKey(pCur: *BtCursor) callconv(.c) i64 {
    getCellInfo(pCur);
    return pCur.info.nKey;
}

export fn sqlite3BtreeCursorPin(pCur: *BtCursor) callconv(.c) void {
    pCur.curFlags |= BTCF_Pinned;
}
export fn sqlite3BtreeCursorUnpin(pCur: *BtCursor) callconv(.c) void {
    pCur.curFlags &= ~BTCF_Pinned;
}

export fn sqlite3BtreeOffset(pCur: *BtCursor) callconv(.c) i64 {
    getCellInfo(pCur);
    return @as(i64, pCur.pBt.?.pageSize) * (@as(i64, pCur.pPage.?.pgno) - 1) +
        @as(i64, @intCast(@intFromPtr(pCur.info.pPayload.?) - @intFromPtr(pCur.pPage.?.aData.?)));
}

export fn sqlite3BtreePayloadSize(pCur: *BtCursor) callconv(.c) u32 {
    getCellInfo(pCur);
    return pCur.info.nPayload;
}

export fn sqlite3BtreeMaxRecordSize(pCur: *BtCursor) callconv(.c) i64 {
    return @as(i64, pCur.pBt.?.pageSize) * @as(i64, pCur.pBt.?.nPage);
}

// ── overflow page chasing ───────────────────────────────────────────────────
fn getOverflowPage(pBt: *BtShared, ovfl: u32, ppPage: ?*?*MemPage, pPgnoNext: *u32) c_int {
    var next: u32 = 0;
    var pPage: ?*MemPage = null;
    var rc: c_int = SQLITE_OK;

    if (pBt.autoVacuum != 0) {
        var iGuess = ovfl + 1;
        var eType: u8 = undefined;
        var pgno: u32 = undefined;
        while (PTRMAP_ISPAGE(pBt, iGuess) or iGuess == PENDING_BYTE_PAGE(pBt)) {
            iGuess += 1;
        }
        if (iGuess <= btreePagecount(pBt)) {
            rc = ptrmapGet(pBt, iGuess, &eType, &pgno);
            if (rc == SQLITE_OK and eType == PTRMAP_OVERFLOW2 and pgno == ovfl) {
                next = iGuess;
                rc = SQLITE_DONE;
            }
        }
    }

    if (rc == SQLITE_OK) {
        rc = btreeGetPage(pBt, ovfl, &pPage, if (ppPage == null) PAGER_GET_READONLY else 0);
        if (rc == SQLITE_OK) {
            next = get4byte(pPage.?.aData.?);
        }
    }

    pPgnoNext.* = next;
    if (ppPage) |pp| {
        pp.* = pPage;
    } else {
        releasePage(pPage);
    }
    return if (rc == SQLITE_DONE) SQLITE_OK else rc;
}

fn copyPayload(pPayload: *anyopaque, pBuf: *anyopaque, nByte: c_int, eOp: c_int, pDbPage: *DbPage) c_int {
    if (eOp != 0) {
        const rc = sqlite3PagerWrite(pDbPage);
        if (rc != SQLITE_OK) {
            return rc;
        }
        const d: [*]u8 = @ptrCast(pPayload);
        const s: [*]const u8 = @ptrCast(pBuf);
        @memcpy(d[0..@intCast(nByte)], s[0..@intCast(nByte)]);
    } else {
        const d: [*]u8 = @ptrCast(pBuf);
        const s: [*]const u8 = @ptrCast(pPayload);
        @memcpy(d[0..@intCast(nByte)], s[0..@intCast(nByte)]);
    }
    return SQLITE_OK;
}

fn accessPayload(pCur: *BtCursor, offset_in: u32, amt_in: u32, pBuf_in: [*]u8, eOp: c_int) c_int {
    var offset = offset_in;
    var amt = amt_in;
    var pBuf = pBuf_in;
    var rc: c_int = SQLITE_OK;
    var iIdx: c_int = 0;
    const pPage = pCur.pPage.?;
    const pBt = pCur.pBt.?;

    if (pCur.ix >= pPage.nCell) {
        return corrupt_page(pPage);
    }
    getCellInfo(pCur);
    var aPayload = pCur.info.pPayload.?;

    if ((@intFromPtr(aPayload) - @intFromPtr(pPage.aData.?)) > (pBt.usableSize - pCur.info.nLocal)) {
        return corrupt_page(pPage);
    }

    if (offset < pCur.info.nLocal) {
        var a = amt;
        if (a + offset > pCur.info.nLocal) {
            a = pCur.info.nLocal - offset;
        }
        rc = copyPayload(aPayload + offset, pBuf, @intCast(a), eOp, pPage.pDbPage.?);
        offset = 0;
        pBuf += a;
        amt -= a;
    } else {
        offset -= pCur.info.nLocal;
    }

    if (rc == SQLITE_OK and amt > 0) {
        const ovflSize = pBt.usableSize - 4;
        var nextPage = get4byte(aPayload + pCur.info.nLocal);

        if ((pCur.curFlags & BTCF_ValidOvfl) == 0) {
            var nOvfl: i64 = pCur.info.nPayload;
            nOvfl = @divTrunc(nOvfl - pCur.info.nLocal + ovflSize - 1, ovflSize);
            if (pCur.aOverflow == null or nOvfl * @sizeOf(u32) > sqlite3MallocSize(pCur.aOverflow)) {
                var aNew: ?*anyopaque = undefined;
                if (sqlite3FaultSim(413) != 0) {
                    aNew = null;
                } else {
                    aNew = sqlite3Realloc(pCur.aOverflow, @intCast(nOvfl * 2 * @sizeOf(u32)));
                }
                if (aNew == null) {
                    return nomem_bkpt();
                } else {
                    pCur.aOverflow = @ptrCast(@alignCast(aNew));
                }
            }
            @memset(pCur.aOverflow.?[0..@intCast(nOvfl)], 0);
            pCur.curFlags |= BTCF_ValidOvfl;
        } else {
            if (pCur.aOverflow.?[offset / ovflSize] != 0) {
                iIdx = @intCast(offset / ovflSize);
                nextPage = pCur.aOverflow.?[@intCast(iIdx)];
                offset = (offset % ovflSize);
            }
        }

        while (nextPage != 0) {
            if (nextPage > pBt.nPage) return corrupt_bkpt(@src().line);
            pCur.aOverflow.?[@intCast(iIdx)] = nextPage;

            if (offset >= ovflSize) {
                if (pCur.aOverflow.?[@intCast(iIdx + 1)] != 0) {
                    nextPage = pCur.aOverflow.?[@intCast(iIdx + 1)];
                } else {
                    rc = getOverflowPage(pBt, nextPage, null, &nextPage);
                }
                offset -= ovflSize;
            } else {
                var a = amt;
                if (a + offset > ovflSize) {
                    a = ovflSize - offset;
                }
                {
                    var pDbPage: ?*DbPage = null;
                    rc = sqlite3PagerGet(pBt.pPager, nextPage, &pDbPage, if (eOp == 0) PAGER_GET_READONLY else 0);
                    if (rc == SQLITE_OK) {
                        if (eOp != 0 and sqlite3PagerPageRefcount(pDbPage) != 1 and sqlite3FaultSim(411) == SQLITE_OK) {
                            sqlite3PagerUnref(pDbPage);
                            return corrupt_page(pPage);
                        }
                        aPayload = sqlite3PagerGetData(pDbPage).?;
                        nextPage = get4byte(aPayload);
                        rc = copyPayload(aPayload + offset + 4, pBuf, @intCast(a), eOp, pDbPage.?);
                        sqlite3PagerUnref(pDbPage);
                        offset = 0;
                    }
                }
                amt -= a;
                if (amt == 0) return rc;
                pBuf += a;
            }
            if (rc != 0) break;
            iIdx += 1;
        }
    }

    if (rc == SQLITE_OK and amt > 0) {
        return corrupt_page(pPage);
    }
    return rc;
}

export fn sqlite3BtreePayload(pCur: *BtCursor, offset: u32, amt: u32, pBuf: ?*anyopaque) callconv(.c) c_int {
    return accessPayload(pCur, offset, amt, @ptrCast(pBuf.?), 0);
}

fn accessPayloadChecked(pCur: *BtCursor, offset: u32, amt: u32, pBuf: *anyopaque) c_int {
    if (pCur.eState == CURSOR_INVALID) {
        return SQLITE_ABORT;
    }
    const rc = btreeRestoreCursorPosition(pCur);
    return if (rc != 0) rc else accessPayload(pCur, offset, amt, @ptrCast(pBuf), 0);
}

export fn sqlite3BtreePayloadChecked(pCur: *BtCursor, offset: u32, amt: u32, pBuf: ?*anyopaque) callconv(.c) c_int {
    if (pCur.eState == CURSOR_VALID) {
        return accessPayload(pCur, offset, amt, @ptrCast(pBuf.?), 0);
    } else {
        return accessPayloadChecked(pCur, offset, amt, pBuf.?);
    }
}

fn fetchPayload(pCur: *BtCursor, pAmt: *u32) ?*const anyopaque {
    var amt: c_int = pCur.info.nLocal;
    if (amt > @as(c_int, @intCast(@intFromPtr(pCur.pPage.?.aDataEnd.?) - @intFromPtr(pCur.info.pPayload.?)))) {
        amt = MAX(@as(c_int, 0), @as(c_int, @intCast(@intFromPtr(pCur.pPage.?.aDataEnd.?) - @intFromPtr(pCur.info.pPayload.?))));
    }
    pAmt.* = @intCast(amt);
    return pCur.info.pPayload;
}

export fn sqlite3BtreePayloadFetch(pCur: *BtCursor, pAmt: *u32) callconv(.c) ?*const anyopaque {
    return fetchPayload(pCur, pAmt);
}

// ════════════════════════════════════════════════════════════════════════════
// Cursor navigation
// ════════════════════════════════════════════════════════════════════════════
fn moveToChild(pCur: *BtCursor, newPgno: u32) c_int {
    if (pCur.iPage >= (BTCURSOR_MAX_DEPTH - 1)) {
        return corrupt_bkpt(@src().line);
    }
    pCur.info.nSize = 0;
    pCur.curFlags &= ~(BTCF_ValidNKey | BTCF_ValidOvfl);
    pCur.aiIdx[@intCast(pCur.iPage)] = pCur.ix;
    pCur.apPage[@intCast(pCur.iPage)] = pCur.pPage;
    pCur.ix = 0;
    pCur.iPage += 1;
    var rc = getAndInitPage(pCur.pBt.?, newPgno, &pCur.pPage, pCur.curPagerFlags);
    if (rc == SQLITE_OK and (pCur.pPage.?.nCell < 1 or pCur.pPage.?.intKey != pCur.curIntKey)) {
        releasePage(pCur.pPage);
        rc = corrupt_pgno(newPgno);
    }
    if (rc != 0) {
        pCur.iPage -= 1;
        pCur.pPage = pCur.apPage[@intCast(pCur.iPage)];
    }
    return rc;
}

fn moveToParent(pCur: *BtCursor) void {
    pCur.info.nSize = 0;
    pCur.curFlags &= ~(BTCF_ValidNKey | BTCF_ValidOvfl);
    pCur.ix = pCur.aiIdx[@intCast(pCur.iPage - 1)];
    const pLeaf = pCur.pPage.?;
    pCur.iPage -= 1;
    pCur.pPage = pCur.apPage[@intCast(pCur.iPage)];
    releasePageNotNull(pLeaf);
}

fn moveToRoot(pCur: *BtCursor) c_int {
    var pRoot: *MemPage = undefined;
    var rc: c_int = SQLITE_OK;

    if (pCur.iPage >= 0) {
        if (pCur.iPage != 0) {
            releasePageNotNull(pCur.pPage.?);
            while (true) {
                pCur.iPage -= 1;
                if (pCur.iPage == 0) break;
                releasePageNotNull(pCur.apPage[@intCast(pCur.iPage)].?);
            }
            pCur.pPage = pCur.apPage[0];
            pRoot = pCur.pPage.?;
            return moveToRootSkipInit(pCur, pRoot);
        }
    } else if (pCur.pgnoRoot == 0) {
        pCur.eState = CURSOR_INVALID;
        return SQLITE_EMPTY;
    } else {
        if (pCur.eState >= CURSOR_REQUIRESEEK) {
            if (pCur.eState == CURSOR_FAULT) {
                return pCur.skipNext;
            }
            sqlite3BtreeClearCursor(pCur);
        }
        rc = getAndInitPage(pCur.pBt.?, pCur.pgnoRoot, &pCur.pPage, pCur.curPagerFlags);
        if (rc != SQLITE_OK) {
            pCur.eState = CURSOR_INVALID;
            return rc;
        }
        pCur.iPage = 0;
        pCur.curIntKey = pCur.pPage.?.intKey;
    }
    pRoot = pCur.pPage.?;

    if (pRoot.isInit == 0 or (@intFromBool(pCur.pKeyInfo == null) != pRoot.intKey)) {
        return corrupt_page(pCur.pPage.?);
    }
    return moveToRootSkipInit(pCur, pRoot);
}
fn moveToRootSkipInit(pCur: *BtCursor, pRoot: *MemPage) c_int {
    pCur.ix = 0;
    pCur.info.nSize = 0;
    pCur.curFlags &= ~(BTCF_AtLast | BTCF_ValidNKey | BTCF_ValidOvfl);
    if (pRoot.nCell > 0) {
        pCur.eState = CURSOR_VALID;
    } else if (pRoot.leaf == 0) {
        if (pRoot.pgno != 1) return corrupt_bkpt(@src().line);
        const subpage = get4byte(pRoot.aData.? + @as(usize, pRoot.hdrOffset) + 8);
        pCur.eState = CURSOR_VALID;
        return moveToChild(pCur, subpage);
    } else {
        pCur.eState = CURSOR_INVALID;
        return SQLITE_EMPTY;
    }
    return SQLITE_OK;
}

fn moveToLeftmost(pCur: *BtCursor) c_int {
    var rc: c_int = SQLITE_OK;
    while (rc == SQLITE_OK) {
        const pPage = pCur.pPage.?;
        if (pPage.leaf != 0) break;
        const pgno = get4byte(findCell(pPage, pCur.ix));
        rc = moveToChild(pCur, pgno);
    }
    return rc;
}

fn moveToRightmost(pCur: *BtCursor) c_int {
    var rc: c_int = SQLITE_OK;
    var pPage = pCur.pPage.?;
    while (pPage.leaf == 0) {
        const pgno = get4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8);
        pCur.ix = pPage.nCell;
        rc = moveToChild(pCur, pgno);
        if (rc != 0) return rc;
        pPage = pCur.pPage.?;
    }
    pCur.ix = pPage.nCell - 1;
    return SQLITE_OK;
}

export fn sqlite3BtreeFirst(pCur: *BtCursor, pRes: *c_int) callconv(.c) c_int {
    var rc = moveToRoot(pCur);
    if (rc == SQLITE_OK) {
        pRes.* = 0;
        rc = moveToLeftmost(pCur);
    } else if (rc == SQLITE_EMPTY) {
        pRes.* = 1;
        rc = SQLITE_OK;
    }
    return rc;
}

export fn sqlite3BtreeIsEmpty(pCur: *BtCursor, pRes: *c_int) callconv(.c) c_int {
    if (pCur.eState == CURSOR_VALID) {
        pRes.* = 0;
        return SQLITE_OK;
    }
    var rc = moveToRoot(pCur);
    if (rc == SQLITE_EMPTY) {
        pRes.* = 1;
        rc = SQLITE_OK;
    } else {
        pRes.* = 0;
    }
    return rc;
}

fn btreeLast(pCur: *BtCursor, pRes: *c_int) c_int {
    var rc = moveToRoot(pCur);
    if (rc == SQLITE_OK) {
        pRes.* = 0;
        rc = moveToRightmost(pCur);
        if (rc == SQLITE_OK) {
            pCur.curFlags |= BTCF_AtLast;
        } else {
            pCur.curFlags &= ~BTCF_AtLast;
        }
    } else if (rc == SQLITE_EMPTY) {
        pRes.* = 1;
        rc = SQLITE_OK;
    }
    return rc;
}

export fn sqlite3BtreeLast(pCur: *BtCursor, pRes: *c_int) callconv(.c) c_int {
    if (CURSOR_VALID == pCur.eState and (pCur.curFlags & BTCF_AtLast) != 0) {
        pRes.* = 0;
        return SQLITE_OK;
    }
    return btreeLast(pCur, pRes);
}

export fn sqlite3BtreeTableMoveto(pCur: *BtCursor, intKey: i64, biasRight: c_int, pRes: *c_int) callconv(.c) c_int {
    var rc: c_int = undefined;

    if (pCur.eState == CURSOR_VALID and (pCur.curFlags & BTCF_ValidNKey) != 0) {
        if (pCur.info.nKey == intKey) {
            pRes.* = 0;
            return SQLITE_OK;
        }
        if (pCur.info.nKey < intKey) {
            if ((pCur.curFlags & BTCF_AtLast) != 0) {
                pRes.* = -1;
                return SQLITE_OK;
            }
            if (pCur.info.nKey + 1 == intKey) {
                pRes.* = 0;
                rc = sqlite3BtreeNext(pCur, 0);
                if (rc == SQLITE_OK) {
                    getCellInfo(pCur);
                    if (pCur.info.nKey == intKey) {
                        return SQLITE_OK;
                    }
                } else if (rc != SQLITE_DONE) {
                    return rc;
                }
            }
        }
    }

    if (config.sqlite_debug) {
        pCur.pBtree.?.nSeek += 1;
    }

    rc = moveToRoot(pCur);
    if (rc != 0) {
        if (rc == SQLITE_EMPTY) {
            pRes.* = -1;
            return SQLITE_OK;
        }
        return rc;
    }

    while (true) {
        var lwr: c_int = 0;
        var upr: c_int = undefined;
        var idx: c_int = undefined;
        var c: c_int = undefined;
        var chldPg: u32 = undefined;
        const pPage = pCur.pPage.?;
        var pCell: [*]u8 = undefined;

        upr = @as(c_int, pPage.nCell) - 1;
        idx = upr >> @intCast(1 - biasRight);
        var done = false;
        while (true) {
            var nCellKey: i64 = undefined;
            pCell = findCellPastPtr(pPage, idx);
            if (pPage.intKeyLeaf != 0) {
                // C: while( 0x80 <= *(pCell++) ){ if(pCell>=aDataEnd) corrupt; }
                // (post-increment: pCell ends one past the payload-size varint.)
                while (true) {
                    const b0 = pCell[0];
                    pCell += 1;
                    if (!(0x80 <= b0)) break;
                    if (@intFromPtr(pCell) >= @intFromPtr(pPage.aDataEnd.?)) {
                        return corrupt_page(pPage);
                    }
                }
            }
            // For intkey interior pages, findCellPastPtr already points pCell at
            // the key varint (aDataOfst skips the 4-byte child pointer).
            _ = sqlite3GetVarint(pCell, @ptrCast(&nCellKey));
            if (nCellKey < intKey) {
                lwr = idx + 1;
                if (lwr > upr) {
                    c = -1;
                    break;
                }
            } else if (nCellKey > intKey) {
                upr = idx - 1;
                if (lwr > upr) {
                    c = 1;
                    break;
                }
            } else {
                pCur.ix = @intCast(idx);
                if (pPage.leaf == 0) {
                    lwr = idx;
                    done = true;
                    break;
                } else {
                    pCur.curFlags |= BTCF_ValidNKey;
                    pCur.info.nKey = nCellKey;
                    pCur.info.nSize = 0;
                    pRes.* = 0;
                    return SQLITE_OK;
                }
            }
            idx = (lwr + upr) >> 1;
        }
        if (!done) {
            if (pPage.leaf != 0) {
                pCur.ix = @intCast(idx);
                pRes.* = c;
                rc = SQLITE_OK;
                pCur.info.nSize = 0;
                return rc;
            }
        }
        // moveto_table_next_layer:
        if (lwr >= pPage.nCell) {
            chldPg = get4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8);
        } else {
            chldPg = get4byte(findCell(pPage, lwr));
        }
        pCur.ix = @intCast(lwr);
        rc = moveToChild(pCur, chldPg);
        if (rc != 0) break;
    }
    pCur.info.nSize = 0;
    return rc;
}

fn indexCellCompare(pPage: *MemPage, idx: c_int, pIdxKey: *UnpackedRecord, xRecordCompare: RecordCompare) c_int {
    const pCell = findCellPastPtr(pPage, idx);
    var nCell: c_int = pCell[0];
    var c: c_int = undefined;
    if (nCell <= pPage.max1bytePayload) {
        c = xRecordCompare(nCell, @ptrCast(pCell + 1), pIdxKey);
    } else if ((pCell[1] & 0x80) == 0 and (blk: {
        nCell = ((nCell & 0x7f) << 7) + pCell[1];
        break :blk nCell <= pPage.maxLocal;
    })) {
        c = xRecordCompare(nCell, @ptrCast(pCell + 2), pIdxKey);
    } else {
        c = 99;
    }
    return c;
}

fn cursorOnLastPage(pCur: *BtCursor) bool {
    var i: c_int = 0;
    while (i < pCur.iPage) : (i += 1) {
        const pPage = pCur.apPage[@intCast(i)].?;
        if (pCur.aiIdx[@intCast(i)] < pPage.nCell) return false;
    }
    return true;
}

export fn sqlite3BtreeIndexMoveto(pCur: *BtCursor, pIdxKey: *UnpackedRecord, pRes: *c_int) callconv(.c) c_int {
    var rc: c_int = undefined;

    if (config.sqlite_debug) {
        pCur.pBtree.?.nSeek += 1;
    }

    const xRecordCompare = sqlite3VdbeFindCompare(pIdxKey);
    pIdxKey.errCode = 0;

    if (pCur.eState == CURSOR_VALID and pCur.pPage.?.leaf != 0 and cursorOnLastPage(pCur)) {
        var c: c_int = undefined;
        if (pCur.ix == pCur.pPage.?.nCell - 1) {
            c = indexCellCompare(pCur.pPage.?, pCur.ix, pIdxKey, xRecordCompare);
            if (c <= 0 and pIdxKey.errCode == SQLITE_OK) {
                pRes.* = c;
                return SQLITE_OK;
            }
        }
        if (pCur.iPage > 0 and indexCellCompare(pCur.pPage.?, 0, pIdxKey, xRecordCompare) <= 0 and pIdxKey.errCode == SQLITE_OK) {
            pCur.curFlags &= ~(BTCF_ValidOvfl | BTCF_AtLast);
            if (pCur.pPage.?.isInit == 0) {
                return corrupt_bkpt(@src().line);
            }
            return indexMovetoLoop(pCur, pIdxKey, pRes, xRecordCompare);
        }
        pIdxKey.errCode = SQLITE_OK;
    }

    rc = moveToRoot(pCur);
    if (rc != 0) {
        if (rc == SQLITE_EMPTY) {
            pRes.* = -1;
            return SQLITE_OK;
        }
        return rc;
    }
    return indexMovetoLoop(pCur, pIdxKey, pRes, xRecordCompare);
}

fn indexMovetoLoop(pCur: *BtCursor, pIdxKey: *UnpackedRecord, pRes: *c_int, xRecordCompare: RecordCompare) c_int {
    var rc: c_int = undefined;
    while (true) {
        var lwr: c_int = 0;
        var upr: c_int = undefined;
        var idx: c_int = undefined;
        var c: c_int = undefined;
        var chldPg: u32 = undefined;
        const pPage = pCur.pPage.?;
        var pCell: [*]u8 = undefined;

        upr = @as(c_int, pPage.nCell) - 1;
        idx = upr >> 1;
        while (true) {
            var nCell: c_int = undefined;
            pCell = findCellPastPtr(pPage, idx);
            nCell = pCell[0];
            if (nCell <= pPage.max1bytePayload) {
                c = xRecordCompare(nCell, @ptrCast(pCell + 1), pIdxKey);
            } else if ((pCell[1] & 0x80) == 0 and (blk: {
                nCell = ((nCell & 0x7f) << 7) + pCell[1];
                break :blk nCell <= pPage.maxLocal;
            })) {
                c = xRecordCompare(nCell, @ptrCast(pCell + 2), pIdxKey);
            } else {
                const nOverrun: c_int = 18;
                const pCellBody = pCell - pPage.childPtrSize;
                pPage.xParseCell(pPage, pCellBody, &pCur.info);
                nCell = @intCast(pCur.info.nKey);
                if (nCell < 2 or @as(u32, @intCast(@divTrunc(nCell, @as(c_int, @intCast(pCur.pBt.?.usableSize))))) > pCur.pBt.?.nPage) {
                    rc = corrupt_page(pPage);
                    pRes.* = pRes.*;
                    return finishIndexMoveto(pCur, rc);
                }
                const pCellKey = sqlite3Malloc(@as(u64, @intCast(nCell)) + @as(u64, @intCast(nOverrun)));
                if (pCellKey == null) {
                    return finishIndexMoveto(pCur, nomem_bkpt());
                }
                pCur.ix = @intCast(idx);
                rc = accessPayload(pCur, 0, @intCast(nCell), @ptrCast(pCellKey), 0);
                @memset(@as([*]u8, @ptrCast(pCellKey))[@intCast(nCell) .. @as(usize, @intCast(nCell)) + @as(usize, @intCast(nOverrun))], 0);
                pCur.curFlags &= ~BTCF_ValidOvfl;
                if (rc != 0) {
                    sqlite3_free(pCellKey);
                    return finishIndexMoveto(pCur, rc);
                }
                c = sqlite3VdbeRecordCompare(nCell, pCellKey, pIdxKey);
                sqlite3_free(pCellKey);
            }
            if (c < 0) {
                lwr = idx + 1;
            } else if (c > 0) {
                upr = idx - 1;
            } else {
                pRes.* = 0;
                rc = SQLITE_OK;
                pCur.ix = @intCast(idx);
                if (pIdxKey.errCode != 0) rc = corrupt_bkpt(@src().line);
                return finishIndexMoveto(pCur, rc);
            }
            if (lwr > upr) break;
            idx = (lwr + upr) >> 1;
        }
        if (pPage.leaf != 0) {
            pCur.ix = @intCast(idx);
            pRes.* = c;
            rc = SQLITE_OK;
            return finishIndexMoveto(pCur, rc);
        }
        if (lwr >= pPage.nCell) {
            chldPg = get4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8);
        } else {
            chldPg = get4byte(findCell(pPage, lwr));
        }

        // inlined moveToChild
        pCur.info.nSize = 0;
        pCur.curFlags &= ~(BTCF_ValidNKey | BTCF_ValidOvfl);
        if (pCur.iPage >= (BTCURSOR_MAX_DEPTH - 1)) {
            return corrupt_bkpt(@src().line);
        }
        pCur.aiIdx[@intCast(pCur.iPage)] = @intCast(lwr);
        pCur.apPage[@intCast(pCur.iPage)] = pCur.pPage;
        pCur.ix = 0;
        pCur.iPage += 1;
        rc = getAndInitPage(pCur.pBt.?, chldPg, &pCur.pPage, pCur.curPagerFlags);
        if (rc == SQLITE_OK and (pCur.pPage.?.nCell < 1 or pCur.pPage.?.intKey != pCur.curIntKey)) {
            releasePage(pCur.pPage);
            rc = corrupt_pgno(chldPg);
        }
        if (rc != 0) {
            pCur.iPage -= 1;
            pCur.pPage = pCur.apPage[@intCast(pCur.iPage)];
            break;
        }
    }
    return finishIndexMoveto(pCur, rc);
}
fn finishIndexMoveto(pCur: *BtCursor, rc: c_int) c_int {
    pCur.info.nSize = 0;
    return rc;
}

export fn sqlite3BtreeEof(pCur: *BtCursor) callconv(.c) c_int {
    return @intFromBool(CURSOR_VALID != pCur.eState);
}

export fn sqlite3BtreeRowCountEst(pCur: *BtCursor) callconv(.c) i64 {
    if (pCur.eState != CURSOR_VALID) return 0;
    if (pCur.pPage.?.leaf == 0) return -1;
    var n: i64 = pCur.pPage.?.nCell;
    var i: u8 = 0;
    while (i < pCur.iPage) : (i += 1) {
        n *= @as(i64, pCur.apPage[i].?.nCell) + 1;
    }
    return n;
}

// ── Next ────────────────────────────────────────────────────────────────────
fn btreeNext(pCur: *BtCursor) c_int {
    var rc: c_int = undefined;
    if (pCur.eState != CURSOR_VALID) {
        rc = restoreCursorPosition(pCur);
        if (rc != SQLITE_OK) {
            return rc;
        }
        if (CURSOR_INVALID == pCur.eState) {
            return SQLITE_DONE;
        }
        if (pCur.eState == CURSOR_SKIPNEXT) {
            pCur.eState = CURSOR_VALID;
            if (pCur.skipNext > 0) return SQLITE_OK;
        }
    }

    var pPage = pCur.pPage.?;
    pCur.ix += 1;
    const idx = pCur.ix;
    if (sqlite3FaultSim(412) != 0) pPage.isInit = 0;
    if (pPage.isInit == 0) {
        return corrupt_bkpt(@src().line);
    }

    if (idx >= pPage.nCell) {
        if (pPage.leaf == 0) {
            rc = moveToChild(pCur, get4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8));
            if (rc != 0) return rc;
            return moveToLeftmost(pCur);
        }
        while (true) {
            if (pCur.iPage == 0) {
                pCur.eState = CURSOR_INVALID;
                return SQLITE_DONE;
            }
            moveToParent(pCur);
            pPage = pCur.pPage.?;
            if (!(pCur.ix >= pPage.nCell)) break;
        }
        if (pPage.intKey != 0) {
            return sqlite3BtreeNext(pCur, 0);
        } else {
            return SQLITE_OK;
        }
    }
    if (pPage.leaf != 0) {
        return SQLITE_OK;
    } else {
        return moveToLeftmost(pCur);
    }
}

export fn sqlite3BtreeNext(pCur: *BtCursor, flags_arg: c_int) callconv(.c) c_int {
    _ = flags_arg;
    pCur.info.nSize = 0;
    pCur.curFlags &= ~(BTCF_ValidNKey | BTCF_ValidOvfl);
    if (pCur.eState != CURSOR_VALID) return btreeNext(pCur);
    const pPage = pCur.pPage.?;
    pCur.ix += 1;
    if (pCur.ix >= pPage.nCell) {
        pCur.ix -= 1;
        return btreeNext(pCur);
    }
    if (pPage.leaf != 0) {
        return SQLITE_OK;
    } else {
        return moveToLeftmost(pCur);
    }
}

// ── Previous ────────────────────────────────────────────────────────────────
fn btreePrevious(pCur: *BtCursor) c_int {
    var rc: c_int = undefined;
    if (pCur.eState != CURSOR_VALID) {
        rc = restoreCursorPosition(pCur);
        if (rc != SQLITE_OK) {
            return rc;
        }
        if (CURSOR_INVALID == pCur.eState) {
            return SQLITE_DONE;
        }
        if (CURSOR_SKIPNEXT == pCur.eState) {
            pCur.eState = CURSOR_VALID;
            if (pCur.skipNext < 0) return SQLITE_OK;
        }
    }

    var pPage = pCur.pPage.?;
    if (sqlite3FaultSim(412) != 0) pPage.isInit = 0;
    if (pPage.isInit == 0) {
        return corrupt_bkpt(@src().line);
    }
    if (pPage.leaf == 0) {
        const idx = pCur.ix;
        rc = moveToChild(pCur, get4byte(findCell(pPage, idx)));
        if (rc != 0) return rc;
        rc = moveToRightmost(pCur);
    } else {
        while (pCur.ix == 0) {
            if (pCur.iPage == 0) {
                pCur.eState = CURSOR_INVALID;
                return SQLITE_DONE;
            }
            moveToParent(pCur);
        }
        pCur.ix -= 1;
        pPage = pCur.pPage.?;
        if (pPage.intKey != 0 and pPage.leaf == 0) {
            rc = sqlite3BtreePrevious(pCur, 0);
        } else {
            rc = SQLITE_OK;
        }
    }
    return rc;
}

export fn sqlite3BtreePrevious(pCur: *BtCursor, flags_arg: c_int) callconv(.c) c_int {
    _ = flags_arg;
    pCur.curFlags &= ~(BTCF_AtLast | BTCF_ValidOvfl | BTCF_ValidNKey);
    pCur.info.nSize = 0;
    if (pCur.eState != CURSOR_VALID or pCur.ix == 0 or pCur.pPage.?.leaf == 0) {
        return btreePrevious(pCur);
    }
    pCur.ix -= 1;
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// Page allocation / free / overflow clearing
// ════════════════════════════════════════════════════════════════════════════
fn allocateBtreePage(pBt: *BtShared, ppPage: *?*MemPage, pPgno: *u32, nearby: u32, eMode: u8) c_int {
    const pPage1 = pBt.pPage1.?;
    var rc: c_int = undefined;
    var pTrunk: ?*MemPage = null;
    var pPrevTrunk: ?*MemPage = null;
    const mxPage = btreePagecount(pBt);

    const n = get4byte(pPage1.aData.? + 36);
    if (n >= mxPage) {
        return corrupt_bkpt(@src().line);
    }
    if (n > 0) {
        var searchList: u8 = 0;
        var nSearch: u32 = 0;

        if (eMode == BTALLOC_EXACT) {
            if (nearby <= mxPage) {
                var eType: u8 = undefined;
                rc = ptrmapGet(pBt, nearby, &eType, null);
                if (rc != 0) return rc;
                if (eType == PTRMAP_FREEPAGE) {
                    searchList = 1;
                }
            }
        } else if (eMode == BTALLOC_LE) {
            searchList = 1;
        }

        rc = sqlite3PagerWrite(pPage1.pDbPage);
        if (rc != 0) return rc;
        put4byte(pPage1.aData.? + 36, n - 1);

        while (true) {
            pPrevTrunk = pTrunk;
            var iTrunk: u32 = undefined;
            if (pPrevTrunk) |pt| {
                iTrunk = get4byte(pt.aData.?);
            } else {
                iTrunk = get4byte(pPage1.aData.? + 32);
            }
            if (iTrunk > mxPage or blk: {
                nSearch += 1;
                break :blk nSearch > n;
            }) {
                rc = corrupt_pgno(if (pPrevTrunk) |pt| pt.pgno else 1);
            } else {
                rc = btreeGetUnusedPage(pBt, iTrunk, &pTrunk, 0);
            }
            if (rc != 0) {
                pTrunk = null;
                return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
            }

            const k = get4byte(pTrunk.?.aData.? + 4);
            if (k == 0 and searchList == 0) {
                rc = sqlite3PagerWrite(pTrunk.?.pDbPage);
                if (rc != 0) {
                    return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                }
                pPgno.* = iTrunk;
                @memcpy((pPage1.aData.? + 32)[0..4], (pTrunk.?.aData.?)[0..4]);
                ppPage.* = pTrunk;
                pTrunk = null;
            } else if (k > (pBt.usableSize / 4 - 2)) {
                rc = corrupt_pgno(iTrunk);
                return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
            } else if (searchList != 0 and (nearby == iTrunk or (iTrunk < nearby and eMode == BTALLOC_LE))) {
                pPgno.* = iTrunk;
                ppPage.* = pTrunk;
                searchList = 0;
                rc = sqlite3PagerWrite(pTrunk.?.pDbPage);
                if (rc != 0) {
                    return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                }
                if (k == 0) {
                    if (pPrevTrunk == null) {
                        @memcpy((pPage1.aData.? + 32)[0..4], (pTrunk.?.aData.?)[0..4]);
                    } else {
                        rc = sqlite3PagerWrite(pPrevTrunk.?.pDbPage);
                        if (rc != SQLITE_OK) {
                            return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                        }
                        @memcpy((pPrevTrunk.?.aData.?)[0..4], (pTrunk.?.aData.?)[0..4]);
                    }
                } else {
                    var pNewTrunk: ?*MemPage = null;
                    const iNewTrunk = get4byte(pTrunk.?.aData.? + 8);
                    if (iNewTrunk > mxPage) {
                        rc = corrupt_pgno(iTrunk);
                        return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                    }
                    rc = btreeGetUnusedPage(pBt, iNewTrunk, &pNewTrunk, 0);
                    if (rc != SQLITE_OK) {
                        return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                    }
                    rc = sqlite3PagerWrite(pNewTrunk.?.pDbPage);
                    if (rc != SQLITE_OK) {
                        releasePage(pNewTrunk);
                        return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                    }
                    @memcpy((pNewTrunk.?.aData.?)[0..4], (pTrunk.?.aData.?)[0..4]);
                    put4byte(pNewTrunk.?.aData.? + 4, k - 1);
                    @memcpy((pNewTrunk.?.aData.? + 8)[0..@intCast((k - 1) * 4)], (pTrunk.?.aData.? + 12)[0..@intCast((k - 1) * 4)]);
                    releasePage(pNewTrunk);
                    if (pPrevTrunk == null) {
                        put4byte(pPage1.aData.? + 32, iNewTrunk);
                    } else {
                        rc = sqlite3PagerWrite(pPrevTrunk.?.pDbPage);
                        if (rc != 0) {
                            return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                        }
                        put4byte(pPrevTrunk.?.aData.?, iNewTrunk);
                    }
                }
                pTrunk = null;
            } else if (k > 0) {
                var closest: u32 = undefined;
                var iPage: u32 = undefined;
                const aData = pTrunk.?.aData.?;
                if (nearby > 0) {
                    closest = 0;
                    if (eMode == BTALLOC_LE) {
                        var i: u32 = 0;
                        while (i < k) : (i += 1) {
                            iPage = get4byte(aData + 8 + i * 4);
                            if (iPage <= nearby) {
                                closest = i;
                                break;
                            }
                        }
                    } else {
                        var dist = sqlite3AbsInt32(@bitCast(get4byte(aData + 8) -% nearby));
                        var i: u32 = 1;
                        while (i < k) : (i += 1) {
                            const d2 = sqlite3AbsInt32(@bitCast(get4byte(aData + 8 + i * 4) -% nearby));
                            if (d2 < dist) {
                                closest = i;
                                dist = d2;
                            }
                        }
                    }
                } else {
                    closest = 0;
                }

                iPage = get4byte(aData + 8 + closest * 4);
                if (iPage > mxPage or iPage < 2) {
                    rc = corrupt_pgno(iTrunk);
                    return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                }
                if (searchList == 0 or (iPage == nearby or (iPage < nearby and eMode == BTALLOC_LE))) {
                    pPgno.* = iPage;
                    rc = sqlite3PagerWrite(pTrunk.?.pDbPage);
                    if (rc != 0) return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
                    if (closest < k - 1) {
                        @memcpy((aData + 8 + closest * 4)[0..4], (aData + 4 + k * 4)[0..4]);
                    }
                    put4byte(aData + 4, k - 1);
                    const noContent: c_int = if (!btreeGetHasContent(pBt, pPgno.*)) PAGER_GET_NOCONTENT else 0;
                    rc = btreeGetUnusedPage(pBt, pPgno.*, ppPage, noContent);
                    if (rc == SQLITE_OK) {
                        rc = sqlite3PagerWrite(ppPage.*.?.pDbPage);
                        if (rc != SQLITE_OK) {
                            releasePage(ppPage.*);
                            ppPage.* = null;
                        }
                    }
                    searchList = 0;
                }
            }
            releasePage(pPrevTrunk);
            pPrevTrunk = null;
            if (searchList == 0) break;
        }
    } else {
        const bNoContent: c_int = if (pBt.bDoTruncate == 0) PAGER_GET_NOCONTENT else 0;
        rc = sqlite3PagerWrite(pBt.pPage1.?.pDbPage);
        if (rc != 0) return rc;
        pBt.nPage += 1;
        if (pBt.nPage == PENDING_BYTE_PAGE(pBt)) pBt.nPage += 1;

        if (pBt.autoVacuum != 0 and PTRMAP_ISPAGE(pBt, pBt.nPage)) {
            var pPg: ?*MemPage = null;
            rc = btreeGetUnusedPage(pBt, pBt.nPage, &pPg, bNoContent);
            if (rc == SQLITE_OK) {
                rc = sqlite3PagerWrite(pPg.?.pDbPage);
                releasePage(pPg);
            }
            if (rc != 0) return rc;
            pBt.nPage += 1;
            if (pBt.nPage == PENDING_BYTE_PAGE(pBt)) pBt.nPage += 1;
        }
        put4byte(pBt.pPage1.?.aData.? + 28, pBt.nPage);
        pPgno.* = pBt.nPage;

        rc = btreeGetUnusedPage(pBt, pPgno.*, ppPage, bNoContent);
        if (rc != 0) return rc;
        rc = sqlite3PagerWrite(ppPage.*.?.pDbPage);
        if (rc != SQLITE_OK) {
            releasePage(ppPage.*);
            ppPage.* = null;
        }
    }
    return endAllocatePage(pBt, ppPage, pTrunk, pPrevTrunk, rc);
}
fn endAllocatePage(pBt: *BtShared, ppPage: *?*MemPage, pTrunk: ?*MemPage, pPrevTrunk: ?*MemPage, rc: c_int) c_int {
    _ = pBt;
    _ = ppPage;
    releasePage(pTrunk);
    releasePage(pPrevTrunk);
    return rc;
}

fn freePage2(pBt: *BtShared, pMemPage: ?*MemPage, iPage: u32) c_int {
    var pTrunk: ?*MemPage = null;
    var iTrunk: u32 = 0;
    const pPage1 = pBt.pPage1.?;
    var pPage: ?*MemPage = null;
    var rc: c_int = undefined;

    if (iPage < 2 or iPage > pBt.nPage) {
        return corrupt_bkpt(@src().line);
    }
    if (pMemPage) |mp| {
        pPage = mp;
        sqlite3PagerRef(pPage.?.pDbPage);
    } else {
        pPage = btreePageLookup(pBt, iPage);
    }

    rc = sqlite3PagerWrite(pPage1.pDbPage);
    if (rc != 0) return freepageOut(pPage, pTrunk, rc);
    const nFree = get4byte(pPage1.aData.? + 36);
    put4byte(pPage1.aData.? + 36, nFree + 1);

    if ((pBt.btsFlags & BTS_SECURE_DELETE) != 0) {
        if ((pPage == null and blk: {
            rc = btreeGetPage(pBt, iPage, &pPage, 0);
            break :blk rc != 0;
        }) or (blk2: {
            rc = sqlite3PagerWrite(pPage.?.pDbPage);
            break :blk2 rc != 0;
        })) {
            return freepageOut(pPage, pTrunk, rc);
        }
        @memset(pPage.?.aData.?[0..pPage.?.pBt.?.pageSize], 0);
    }

    if (isAutoVacuum(pBt)) {
        ptrmapPut(pBt, iPage, PTRMAP_FREEPAGE, 0, &rc);
        if (rc != 0) return freepageOut(pPage, pTrunk, rc);
    }

    if (nFree != 0) {
        iTrunk = get4byte(pPage1.aData.? + 32);
        if (iTrunk > btreePagecount(pBt)) {
            rc = corrupt_bkpt(@src().line);
            return freepageOut(pPage, pTrunk, rc);
        }
        rc = btreeGetPage(pBt, iTrunk, &pTrunk, 0);
        if (rc != SQLITE_OK) {
            return freepageOut(pPage, pTrunk, rc);
        }
        const nLeaf = get4byte(pTrunk.?.aData.? + 4);
        if (nLeaf > pBt.usableSize / 4 - 2) {
            rc = corrupt_bkpt(@src().line);
            return freepageOut(pPage, pTrunk, rc);
        }
        if (nLeaf < pBt.usableSize / 4 - 8) {
            rc = sqlite3PagerWrite(pTrunk.?.pDbPage);
            if (rc == SQLITE_OK) {
                put4byte(pTrunk.?.aData.? + 4, nLeaf + 1);
                put4byte(pTrunk.?.aData.? + 8 + nLeaf * 4, iPage);
                if (pPage != null and (pBt.btsFlags & BTS_SECURE_DELETE) == 0) {
                    sqlite3PagerDontWrite(pPage.?.pDbPage);
                }
                rc = btreeSetHasContent(pBt, iPage);
            }
            return freepageOut(pPage, pTrunk, rc);
        }
    }

    if (pPage == null) {
        rc = btreeGetPage(pBt, iPage, &pPage, 0);
        if (rc != SQLITE_OK) {
            return freepageOut(pPage, pTrunk, rc);
        }
    }
    rc = sqlite3PagerWrite(pPage.?.pDbPage);
    if (rc != SQLITE_OK) {
        return freepageOut(pPage, pTrunk, rc);
    }
    put4byte(pPage.?.aData.?, iTrunk);
    put4byte(pPage.?.aData.? + 4, 0);
    put4byte(pPage1.aData.? + 32, iPage);
    return freepageOut(pPage, pTrunk, rc);
}
fn freepageOut(pPage: ?*MemPage, pTrunk: ?*MemPage, rc: c_int) c_int {
    if (pPage) |pp| {
        pp.isInit = 0;
    }
    releasePage(pPage);
    releasePage(pTrunk);
    return rc;
}
fn freePage(pPage: *MemPage, pRC: *c_int) void {
    if (pRC.* == SQLITE_OK) {
        pRC.* = freePage2(pPage.pBt.?, pPage, pPage.pgno);
    }
}

fn clearCellOverflow(pPage: *MemPage, pCell: [*]u8, pInfo: *CellInfo) c_int {
    if (@intFromPtr(pCell + pInfo.nSize) > @intFromPtr(pPage.aDataEnd.?)) {
        return corrupt_page(pPage);
    }
    var ovflPgno = get4byte(pCell + pInfo.nSize - 4);
    const pBt = pPage.pBt.?;
    const ovflPageSize = pBt.usableSize - 4;
    var nOvfl: c_int = @intCast(@divTrunc(pInfo.nPayload - pInfo.nLocal + ovflPageSize - 1, ovflPageSize));
    while (nOvfl != 0) {
        nOvfl -= 1;
        var iNext: u32 = 0;
        var pOvfl: ?*MemPage = null;
        if (ovflPgno < 2 or ovflPgno > btreePagecount(pBt)) {
            return corrupt_bkpt(@src().line);
        }
        if (nOvfl != 0) {
            const rc = getOverflowPage(pBt, ovflPgno, &pOvfl, &iNext);
            if (rc != 0) return rc;
        }

        var rc: c_int = undefined;
        if (pOvfl != null or (blk: {
            pOvfl = btreePageLookup(pBt, ovflPgno);
            break :blk pOvfl != null;
        })) {
            if (sqlite3PagerPageRefcount(pOvfl.?.pDbPage) != 1) {
                rc = corrupt_bkpt(@src().line);
            } else {
                rc = freePage2(pBt, pOvfl, ovflPgno);
            }
        } else {
            rc = freePage2(pBt, pOvfl, ovflPgno);
        }

        if (pOvfl) |ov| {
            sqlite3PagerUnref(ov.pDbPage);
        }
        if (rc != 0) return rc;
        ovflPgno = iNext;
    }
    return SQLITE_OK;
}

inline fn btreeClearCell(pPage: *MemPage, pCell: [*]u8, sInfo: *CellInfo) c_int {
    pPage.xParseCell(pPage, pCell, sInfo);
    if (sInfo.nLocal != sInfo.nPayload) {
        return clearCellOverflow(pPage, pCell, sInfo);
    }
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// fillInCell / dropCell / insertCell
// ════════════════════════════════════════════════════════════════════════════
fn fillInCell(pPage: *MemPage, pCell: [*]u8, pX: *const BtreePayload, pnSize: *c_int) c_int {
    var nPayload: c_int = undefined;
    var pSrc: ?[*]const u8 = undefined;
    var nSrc: c_int = undefined;
    var n: c_int = undefined;
    var rc: c_int = undefined;
    var mn: c_int = undefined;
    var spaceLeft: c_int = undefined;
    var pToRelease: ?*MemPage = null;
    var pPrior: [*]u8 = undefined;
    var pPayload: [*]u8 = undefined;
    var pgnoOvfl: u32 = 0;
    var nHeader: c_int = undefined;

    nHeader = pPage.childPtrSize;
    if (pPage.intKey != 0) {
        nPayload = pX.nData + pX.nZero;
        pSrc = @ptrCast(pX.pData);
        nSrc = pX.nData;
        nHeader += @intCast(putVarint32(pCell + @as(usize, @intCast(nHeader)), nPayload));
        nHeader += sqlite3PutVarint(pCell + @as(usize, @intCast(nHeader)), @bitCast(pX.nKey));
    } else {
        nSrc = @intCast(pX.nKey);
        nPayload = nSrc;
        pSrc = @ptrCast(pX.pKey);
        nHeader += @intCast(putVarint32(pCell + @as(usize, @intCast(nHeader)), nPayload));
    }

    pPayload = pCell + @as(usize, @intCast(nHeader));
    if (nPayload <= pPage.maxLocal) {
        n = nHeader + nPayload;
        if (n < 4) {
            n = 4;
            pPayload[@intCast(nPayload)] = 0;
        }
        pnSize.* = n;
        if (nSrc > 0) @memcpy(pPayload[0..@intCast(nSrc)], pSrc.?[0..@intCast(nSrc)]);
        @memset((pPayload + @as(usize, @intCast(nSrc)))[0..@intCast(nPayload - nSrc)], 0);
        return SQLITE_OK;
    }

    mn = pPage.minLocal;
    n = mn + @as(c_int, @intCast(@mod(@as(i64, nPayload) - mn, @as(i64, pPage.pBt.?.usableSize - 4))));
    if (n > pPage.maxLocal) n = mn;
    spaceLeft = n;
    pnSize.* = n + nHeader + 4;
    pPrior = pCell + @as(usize, @intCast(nHeader + n));
    pToRelease = null;
    pgnoOvfl = 0;
    const pBt = pPage.pBt.?;

    while (true) {
        n = nPayload;
        if (n > spaceLeft) n = spaceLeft;

        if (nSrc >= n) {
            @memcpy(pPayload[0..@intCast(n)], pSrc.?[0..@intCast(n)]);
        } else if (nSrc > 0) {
            n = nSrc;
            @memcpy(pPayload[0..@intCast(n)], pSrc.?[0..@intCast(n)]);
        } else {
            @memset(pPayload[0..@intCast(n)], 0);
        }
        nPayload -= n;
        if (nPayload <= 0) break;
        pPayload += @as(usize, @intCast(n));
        pSrc.? += @as(usize, @intCast(n));
        nSrc -= n;
        spaceLeft -= n;
        if (spaceLeft == 0) {
            var pOvfl: ?*MemPage = null;
            const pgnoPtrmap = pgnoOvfl;
            if (pBt.autoVacuum != 0) {
                while (true) {
                    pgnoOvfl += 1;
                    if (!(PTRMAP_ISPAGE(pBt, pgnoOvfl) or pgnoOvfl == PENDING_BYTE_PAGE(pBt))) break;
                }
            }
            rc = allocateBtreePage(pBt, &pOvfl, &pgnoOvfl, pgnoOvfl, 0);
            if (pBt.autoVacuum != 0 and rc == SQLITE_OK) {
                const eType: u8 = if (pgnoPtrmap != 0) PTRMAP_OVERFLOW2 else PTRMAP_OVERFLOW1;
                ptrmapPut(pBt, pgnoOvfl, eType, pgnoPtrmap, &rc);
                if (rc != 0) {
                    releasePage(pOvfl);
                }
            }
            if (rc != 0) {
                releasePage(pToRelease);
                return rc;
            }

            put4byte(pPrior, pgnoOvfl);
            releasePage(pToRelease);
            pToRelease = pOvfl;
            pPrior = pOvfl.?.aData.?;
            put4byte(pPrior, 0);
            pPayload = pOvfl.?.aData.? + 4;
            spaceLeft = @intCast(pBt.usableSize - 4);
        }
    }
    releasePage(pToRelease);
    return SQLITE_OK;
}

inline fn putVarint32(p: [*]u8, v: c_int) c_int {
    if ((@as(c_uint, @bitCast(v)) & ~@as(c_uint, 0x7f)) == 0) {
        p[0] = @truncate(@as(c_uint, @bitCast(v)));
        return 1;
    }
    return sqlite3PutVarint(p, @as(u64, @intCast(@as(u32, @bitCast(v)))));
}

fn dropCell(pPage: *MemPage, idx: c_int, sz: c_int, pRC: *c_int) void {
    if (pRC.* != 0) return;
    const data = pPage.aData.?;
    const ptr = pPage.aCellIdx.? + @as(usize, @intCast(2 * idx));
    const pc: u32 = @intCast(get2byte(ptr));
    const hdr: c_int = pPage.hdrOffset;
    if (pc + @as(u32, @intCast(sz)) > pPage.pBt.?.usableSize) {
        pRC.* = corrupt_bkpt(@src().line);
        return;
    }
    const rc = freeSpace(pPage, @intCast(pc), sz);
    if (rc != 0) {
        pRC.* = rc;
        return;
    }
    pPage.nCell -= 1;
    if (pPage.nCell == 0) {
        @memset((data + @as(usize, @intCast(hdr + 1)))[0..4], 0);
        data[@intCast(hdr + 7)] = 0;
        put2byte(data + @as(usize, @intCast(hdr + 5)), @intCast(pPage.pBt.?.usableSize));
        pPage.nFree = @as(c_int, @intCast(pPage.pBt.?.usableSize)) - pPage.hdrOffset - pPage.childPtrSize - 8;
    } else {
        const cnt: usize = @intCast(2 * (@as(c_int, pPage.nCell) - idx));
        std.mem.copyForwards(u8, ptr[0..cnt], (ptr + 2)[0..cnt]);
        put2byte(data + @as(usize, @intCast(hdr + 3)), pPage.nCell);
        pPage.nFree += 2;
    }
}

fn insertCell(pPage: *MemPage, i: c_int, pCell_in: [*]u8, sz: c_int, pTemp: ?[*]u8, iChild: u32) c_int {
    var idx: c_int = 0;
    var j: c_int = undefined;
    var data: [*]u8 = undefined;
    var pIns: [*]u8 = undefined;
    var pCell = pCell_in;
    if (pPage.nOverflow != 0 or sz + 2 > pPage.nFree) {
        if (pTemp) |t| {
            @memcpy(t[0..@intCast(sz)], pCell[0..@intCast(sz)]);
            pCell = t;
        }
        put4byte(pCell, iChild);
        j = pPage.nOverflow;
        pPage.nOverflow += 1;
        pPage.apOvfl[@intCast(j)] = pCell;
        pPage.aiOvfl[@intCast(j)] = @intCast(i);
    } else {
        const rc0 = sqlite3PagerWrite(pPage.pDbPage);
        if (rc0 != SQLITE_OK) {
            return rc0;
        }
        data = pPage.aData.?;
        const rc = allocateSpace(pPage, sz, &idx);
        if (rc != 0) {
            return rc;
        }
        pPage.nFree -= (2 + sz);
        @memcpy((data + @as(usize, @intCast(idx + 4)))[0..@intCast(sz - 4)], (pCell + 4)[0..@intCast(sz - 4)]);
        put4byte(data + @as(usize, @intCast(idx)), iChild);
        pIns = pPage.aCellIdx.? + @as(usize, @intCast(i * 2));
        const cnt: usize = @intCast(2 * (@as(c_int, pPage.nCell) - i));
        std.mem.copyBackwards(u8, (pIns + 2)[0..cnt], pIns[0..cnt]);
        put2byte(pIns, idx);
        pPage.nCell += 1;
        data[@intCast(pPage.hdrOffset + 4)] +%= 1;
        if (data[@intCast(pPage.hdrOffset + 4)] == 0) data[@intCast(pPage.hdrOffset + 3)] += 1;
        if (pPage.pBt.?.autoVacuum != 0) {
            var rc2: c_int = SQLITE_OK;
            ptrmapPutOvflPtr(pPage, pPage, pCell, &rc2);
            if (rc2 != 0) return rc2;
        }
    }
    return SQLITE_OK;
}

fn insertCellFast(pPage: *MemPage, i: c_int, pCell: [*]u8, sz: c_int) c_int {
    var idx: c_int = 0;
    var j: c_int = undefined;
    var data: [*]u8 = undefined;
    var pIns: [*]u8 = undefined;
    if (sz + 2 > pPage.nFree) {
        j = pPage.nOverflow;
        pPage.nOverflow += 1;
        pPage.apOvfl[@intCast(j)] = pCell;
        pPage.aiOvfl[@intCast(j)] = @intCast(i);
    } else {
        const rc0 = sqlite3PagerWrite(pPage.pDbPage);
        if (rc0 != SQLITE_OK) {
            return rc0;
        }
        data = pPage.aData.?;
        const rc = allocateSpace(pPage, sz, &idx);
        if (rc != 0) {
            return rc;
        }
        pPage.nFree -= (2 + sz);
        @memcpy((data + @as(usize, @intCast(idx)))[0..@intCast(sz)], pCell[0..@intCast(sz)]);
        pIns = pPage.aCellIdx.? + @as(usize, @intCast(i * 2));
        const cnt: usize = @intCast(2 * (@as(c_int, pPage.nCell) - i));
        std.mem.copyBackwards(u8, (pIns + 2)[0..cnt], pIns[0..cnt]);
        put2byte(pIns, idx);
        pPage.nCell += 1;
        data[@intCast(pPage.hdrOffset + 4)] +%= 1;
        if (data[@intCast(pPage.hdrOffset + 4)] == 0) data[@intCast(pPage.hdrOffset + 3)] += 1;
        if (pPage.pBt.?.autoVacuum != 0) {
            var rc2: c_int = SQLITE_OK;
            ptrmapPutOvflPtr(pPage, pPage, pCell, &rc2);
            if (rc2 != 0) return rc2;
        }
    }
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// CellArray / balance machinery
// ════════════════════════════════════════════════════════════════════════════
fn populateCellCache(p: *CellArray, idx_in: c_int, N_in: c_int) void {
    const pRef = p.pRef.?;
    const szCell = p.szCell.?;
    var idx = idx_in;
    var N = N_in;
    while (N > 0) {
        if (szCell[@intCast(idx)] == 0) {
            szCell[@intCast(idx)] = pRef.xCellSize(pRef, p.apCell.?[@intCast(idx)]);
        }
        idx += 1;
        N -= 1;
    }
}
fn computeCellSize(p: *CellArray, N: c_int) u16 {
    p.szCell.?[@intCast(N)] = p.pRef.?.xCellSize(p.pRef, p.apCell.?[@intCast(N)]);
    return p.szCell.?[@intCast(N)];
}
inline fn cachedCellSize(p: *CellArray, N: c_int) u16 {
    if (p.szCell.?[@intCast(N)] != 0) return p.szCell.?[@intCast(N)];
    return computeCellSize(p, N);
}

fn rebuildPage(pCArray: *CellArray, iFirst: c_int, nCell: c_int, pPg: *MemPage) c_int {
    const hdr: c_int = pPg.hdrOffset;
    const aData = pPg.aData.?;
    const usableSize: c_int = @intCast(pPg.pBt.?.usableSize);
    const pEnd = aData + @as(usize, @intCast(usableSize));
    var i = iFirst;
    const iEnd = i + nCell;
    var pCellptr = pPg.aCellIdx.?;
    const pTmp = sqlite3PagerTempSpace(pPg.pBt.?.pPager).?;
    var pData: [*]u8 = undefined;
    var k: c_int = 0;
    var pSrcEnd: [*]u8 = undefined;

    var j: u32 = @intCast(get2byte(aData + @as(usize, @intCast(hdr + 5))));
    if (j > usableSize) j = 0;
    @memcpy((pTmp + j)[0..@intCast(usableSize - @as(c_int, @intCast(j)))], (aData + j)[0..@intCast(usableSize - @as(c_int, @intCast(j)))]);

    k = 0;
    while (pCArray.ixNx[@intCast(k)] <= i) k += 1;
    pSrcEnd = pCArray.apEnd[@intCast(k)].?;

    pData = pEnd;
    while (true) {
        var pCell = pCArray.apCell.?[@intCast(i)].?;
        const sz = pCArray.szCell.?[@intCast(i)];
        if (sqlite_within(pCell, aData + j, pEnd)) {
            if (@intFromPtr(pCell + sz) > @intFromPtr(pEnd)) return corrupt_bkpt(@src().line);
            pCell = pTmp + (@intFromPtr(pCell) - @intFromPtr(aData));
        } else if (@intFromPtr(pCell + sz) > @intFromPtr(pSrcEnd) and @intFromPtr(pCell) < @intFromPtr(pSrcEnd)) {
            return corrupt_bkpt(@src().line);
        }

        pData -= @as(usize, sz);
        put2byte(pCellptr, @intCast(@intFromPtr(pData) - @intFromPtr(aData)));
        pCellptr += 2;
        if (@intFromPtr(pData) < @intFromPtr(pCellptr)) return corrupt_bkpt(@src().line);
        std.mem.copyForwards(u8, pData[0..sz], pCell[0..sz]);
        i += 1;
        if (i >= iEnd) break;
        if (pCArray.ixNx[@intCast(k)] <= i) {
            k += 1;
            pSrcEnd = pCArray.apEnd[@intCast(k)].?;
        }
    }

    pPg.nCell = @intCast(nCell);
    pPg.nOverflow = 0;
    put2byte(aData + @as(usize, @intCast(hdr + 1)), 0);
    put2byte(aData + @as(usize, @intCast(hdr + 3)), pPg.nCell);
    put2byte(aData + @as(usize, @intCast(hdr + 5)), @intCast(@intFromPtr(pData) - @intFromPtr(aData)));
    aData[@intCast(hdr + 7)] = 0x00;
    return SQLITE_OK;
}

fn pageInsertArray(pPg: *MemPage, pBegin: [*]u8, ppData: *[*]u8, pCellptr_in: [*]u8, iFirst: c_int, nCell: c_int, pCArray: *CellArray) c_int {
    var i = iFirst;
    const aData = pPg.aData.?;
    var pData = ppData.*;
    const iEnd = iFirst + nCell;
    var k: c_int = 0;
    var pEnd: [*]u8 = undefined;
    var pCellptr = pCellptr_in;
    if (iEnd <= iFirst) return 0;
    k = 0;
    while (pCArray.ixNx[@intCast(k)] <= i) k += 1;
    pEnd = pCArray.apEnd[@intCast(k)].?;
    while (true) {
        var rc: c_int = undefined;
        var pSlot: [*]u8 = undefined;
        const sz: c_int = pCArray.szCell.?[@intCast(i)];
        if ((aData[1] == 0 and aData[2] == 0) or blk: {
            const ps = pageFindSlot(pPg, sz, &rc);
            if (ps) |p| {
                pSlot = p;
                break :blk false;
            }
            break :blk true;
        }) {
            if (@as(c_int, @intCast(@intFromPtr(pData) - @intFromPtr(pBegin))) < sz) return 1;
            pData -= @as(usize, @intCast(sz));
            pSlot = pData;
        }
        if (@intFromPtr(pCArray.apCell.?[@intCast(i)].? + @as(usize, @intCast(sz))) > @intFromPtr(pEnd) and
            @intFromPtr(pCArray.apCell.?[@intCast(i)].?) < @intFromPtr(pEnd))
        {
            return 1;
        }
        std.mem.copyForwards(u8, pSlot[0..@intCast(sz)], pCArray.apCell.?[@intCast(i)].?[0..@intCast(sz)]);
        put2byte(pCellptr, @intCast(@intFromPtr(pSlot) - @intFromPtr(aData)));
        pCellptr += 2;
        i += 1;
        if (i >= iEnd) break;
        if (pCArray.ixNx[@intCast(k)] <= i) {
            k += 1;
            pEnd = pCArray.apEnd[@intCast(k)].?;
        }
    }
    ppData.* = pData;
    return 0;
}

fn pageFreeArray(pPg: *MemPage, iFirst: c_int, nCell: c_int, pCArray: *CellArray) c_int {
    const aData = pPg.aData.?;
    const pEnd = aData + pPg.pBt.?.usableSize;
    const pStart = aData + @as(usize, @intCast(pPg.hdrOffset + 8 + pPg.childPtrSize));
    var nRet: c_int = 0;
    const iEnd = iFirst + nCell;
    var nFree: c_int = 0;
    var aOfst: [10]c_int = undefined;
    var aAfter: [10]c_int = undefined;

    var i = iFirst;
    while (i < iEnd) : (i += 1) {
        const pCell = pCArray.apCell.?[@intCast(i)].?;
        if (sqlite_within(pCell, pStart, pEnd)) {
            const sz: c_int = pCArray.szCell.?[@intCast(i)];
            const iOfst: c_int = @intCast(@as(u16, @truncate(@intFromPtr(pCell) - @intFromPtr(aData))));
            const iAfter = iOfst + sz;
            var j: c_int = 0;
            while (j < nFree) : (j += 1) {
                if (aOfst[@intCast(j)] == iAfter) {
                    aOfst[@intCast(j)] = iOfst;
                    break;
                } else if (aAfter[@intCast(j)] == iOfst) {
                    aAfter[@intCast(j)] = iAfter;
                    break;
                }
            }
            if (j >= nFree) {
                if (nFree >= 10) {
                    var jj: c_int = 0;
                    while (jj < nFree) : (jj += 1) {
                        _ = freeSpace(pPg, aOfst[@intCast(jj)], aAfter[@intCast(jj)] - aOfst[@intCast(jj)]);
                    }
                    nFree = 0;
                }
                aOfst[@intCast(nFree)] = iOfst;
                aAfter[@intCast(nFree)] = iAfter;
                if (@intFromPtr(aData + @as(usize, @intCast(iAfter))) > @intFromPtr(pEnd)) return 0;
                nFree += 1;
            }
            nRet += 1;
        }
    }
    var j: c_int = 0;
    while (j < nFree) : (j += 1) {
        _ = freeSpace(pPg, aOfst[@intCast(j)], aAfter[@intCast(j)] - aOfst[@intCast(j)]);
    }
    return nRet;
}

fn editPage(pPg: *MemPage, iOld: c_int, iNew: c_int, nNew: c_int, pCArray: *CellArray) c_int {
    const aData = pPg.aData.?;
    const hdr: c_int = pPg.hdrOffset;
    const pBegin = pPg.aCellIdx.? + @as(usize, @intCast(nNew * 2));
    var nCell: c_int = pPg.nCell;
    var pData: [*]u8 = undefined;
    var pCellptr: [*]u8 = undefined;
    var i: c_int = undefined;
    const iOldEnd = iOld + @as(c_int, pPg.nCell) + @as(c_int, pPg.nOverflow);
    const iNewEnd = iNew + nNew;

    if (iOld < iNew) {
        const nShift = pageFreeArray(pPg, iOld, iNew - iOld, pCArray);
        if (nShift > nCell) return corrupt_bkpt(@src().line);
        std.mem.copyForwards(u8, pPg.aCellIdx.?[0..@intCast(nCell * 2)], (pPg.aCellIdx.? + @as(usize, @intCast(nShift * 2)))[0..@intCast(nCell * 2)]);
        nCell -= nShift;
    }
    if (iNewEnd < iOldEnd) {
        const nTail = pageFreeArray(pPg, iNewEnd, iOldEnd - iNewEnd, pCArray);
        nCell -= nTail;
    }

    pData = aData + @as(usize, @intCast(get2byte(aData + @as(usize, @intCast(hdr + 5)))));
    if (@intFromPtr(pData) < @intFromPtr(pBegin)) return editpageFail(pPg, iNew, nNew, pCArray);
    if (@intFromPtr(pData) > @intFromPtr(pPg.aDataEnd.?)) return editpageFail(pPg, iNew, nNew, pCArray);

    if (iNew < iOld) {
        const nAdd = MIN(nNew, iOld - iNew);
        pCellptr = pPg.aCellIdx.?;
        std.mem.copyBackwards(u8, (pCellptr + @as(usize, @intCast(nAdd * 2)))[0..@intCast(nCell * 2)], pCellptr[0..@intCast(nCell * 2)]);
        if (pageInsertArray(pPg, pBegin, &pData, pCellptr, iNew, nAdd, pCArray) != 0) return editpageFail(pPg, iNew, nNew, pCArray);
        nCell += nAdd;
    }

    i = 0;
    while (i < pPg.nOverflow) : (i += 1) {
        const iCell = (iOld + pPg.aiOvfl[@intCast(i)]) - iNew;
        if (iCell >= 0 and iCell < nNew) {
            pCellptr = pPg.aCellIdx.? + @as(usize, @intCast(iCell * 2));
            if (nCell > iCell) {
                std.mem.copyBackwards(u8, (pCellptr + 2)[0..@intCast((nCell - iCell) * 2)], pCellptr[0..@intCast((nCell - iCell) * 2)]);
            }
            nCell += 1;
            _ = cachedCellSize(pCArray, iCell + iNew);
            if (pageInsertArray(pPg, pBegin, &pData, pCellptr, iCell + iNew, 1, pCArray) != 0) return editpageFail(pPg, iNew, nNew, pCArray);
        }
    }

    pCellptr = pPg.aCellIdx.? + @as(usize, @intCast(nCell * 2));
    if (pageInsertArray(pPg, pBegin, &pData, pCellptr, iNew + nCell, nNew - nCell, pCArray) != 0) {
        return editpageFail(pPg, iNew, nNew, pCArray);
    }

    pPg.nCell = @intCast(nNew);
    pPg.nOverflow = 0;
    put2byte(aData + @as(usize, @intCast(hdr + 3)), pPg.nCell);
    put2byte(aData + @as(usize, @intCast(hdr + 5)), @intCast(@intFromPtr(pData) - @intFromPtr(aData)));
    return SQLITE_OK;
}
fn editpageFail(pPg: *MemPage, iNew: c_int, nNew: c_int, pCArray: *CellArray) c_int {
    if (nNew < 1) return corrupt_bkpt(@src().line);
    populateCellCache(pCArray, iNew, nNew);
    return rebuildPage(pCArray, iNew, nNew, pPg);
}

fn balance_quick(pParent: *MemPage, pPage: *MemPage, pSpace: [*]u8) c_int {
    const pBt = pPage.pBt.?;
    var pNew: ?*MemPage = null;
    var rc: c_int = undefined;
    var pgnoNew: u32 = undefined;

    if (pPage.nCell == 0) return corrupt_bkpt(@src().line);

    rc = allocateBtreePage(pBt, &pNew, &pgnoNew, 0, 0);
    if (rc == SQLITE_OK) {
        var pOut = pSpace + 4;
        var pCell = pPage.apOvfl[0].?;
        var szCell = pPage.xCellSize(pPage, pCell);
        var pStop: [*]u8 = undefined;
        var b: CellArray = undefined;

        zeroPage(pNew.?, PTF_INTKEY | PTF_LEAFDATA | PTF_LEAF);
        b.nCell = 1;
        b.pRef = pPage;
        b.apCell = @ptrCast(&pCell);
        b.szCell = @ptrCast(&szCell);
        b.apEnd[0] = pPage.aDataEnd;
        b.ixNx[0] = 2;
        b.ixNx[NB * 2 - 1] = 0x7fffffff;
        rc = rebuildPage(&b, 0, 1, pNew.?);
        if (rc != 0) {
            releasePage(pNew);
            return rc;
        }
        pNew.?.nFree = @as(c_int, @intCast(pBt.usableSize)) - @as(c_int, pNew.?.cellOffset) - 2 - szCell;

        if (isAutoVacuum(pBt)) {
            ptrmapPut(pBt, pgnoNew, PTRMAP_BTREE, pParent.pgno, &rc);
            if (szCell > pNew.?.minLocal) {
                ptrmapPutOvflPtr(pNew.?, pNew.?, pCell, &rc);
            }
        }

        pCell = findCell(pPage, pPage.nCell - 1);
        // C: pStop=&pCell[9]; while( (*(pCell++)&0x80) && pCell<pStop );
        pStop = pCell + 9;
        while (true) {
            const b0 = pCell[0];
            pCell += 1;
            if (!((b0 & 0x80) != 0 and @intFromPtr(pCell) < @intFromPtr(pStop))) break;
        }
        // C: pStop=&pCell[9]; while( ((*(pOut++)=*(pCell++))&0x80) && pCell<pStop );
        pStop = pCell + 9;
        while (true) {
            const b0 = pCell[0];
            pOut[0] = b0;
            pOut += 1;
            pCell += 1;
            if (!((b0 & 0x80) != 0 and @intFromPtr(pCell) < @intFromPtr(pStop))) break;
        }

        if (rc == SQLITE_OK) {
            rc = insertCell(pParent, pParent.nCell, pSpace, @intCast(@intFromPtr(pOut) - @intFromPtr(pSpace)), null, pPage.pgno);
        }
        put4byte(pParent.aData.? + @as(usize, pParent.hdrOffset) + 8, pgnoNew);
        releasePage(pNew);
    }
    return rc;
}

fn copyNodeContent(pFrom: *MemPage, pTo: *MemPage, pRC: *c_int) void {
    if (pRC.* != SQLITE_OK) return;
    const pBt = pFrom.pBt.?;
    const aFrom = pFrom.aData.?;
    const aTo = pTo.aData.?;
    const iFromHdr: c_int = pFrom.hdrOffset;
    const iToHdr: c_int = if (pTo.pgno == 1) 100 else 0;
    var rc: c_int = undefined;

    const iData = get2byte(aFrom + @as(usize, @intCast(iFromHdr + 5)));
    @memcpy((aTo + @as(usize, @intCast(iData)))[0..@intCast(@as(c_int, @intCast(pBt.usableSize)) - iData)], (aFrom + @as(usize, @intCast(iData)))[0..@intCast(@as(c_int, @intCast(pBt.usableSize)) - iData)]);
    const nHdrCopy: c_int = @as(c_int, pFrom.cellOffset) + 2 * @as(c_int, pFrom.nCell);
    @memcpy((aTo + @as(usize, @intCast(iToHdr)))[0..@intCast(nHdrCopy)], (aFrom + @as(usize, @intCast(iFromHdr)))[0..@intCast(nHdrCopy)]);

    pTo.isInit = 0;
    rc = btreeInitPage(pTo);
    if (rc == SQLITE_OK) rc = btreeComputeFreeSpace(pTo);
    if (rc != SQLITE_OK) {
        pRC.* = rc;
        return;
    }
    if (isAutoVacuum(pBt)) {
        pRC.* = setChildPtrmaps(pTo);
    }
}

fn balance_nonroot(pParent: *MemPage, iParentIdx: c_int, aOvflSpace: ?[*]u8, isRoot: c_int, bBulk: c_int) c_int {
    var nMaxCells: c_int = 0;
    var nNew: c_int = 0;
    var nOld: c_int = undefined;
    var i: c_int = undefined;
    var j: c_int = undefined;
    var k: c_int = undefined;
    var nxDiv: c_int = undefined;
    var rc: c_int = SQLITE_OK;
    var leafCorrection: u16 = undefined;
    var leafData: c_int = undefined;
    var usableSpace: c_int = undefined;
    var pageFlags: c_int = undefined;
    var iSpace1: c_int = 0;
    var iOvflSpace: c_int = 0;
    var apOld: [NB]?*MemPage = undefined;
    var apNew: [NB + 2]?*MemPage = @splat(null);
    var pRight: [*]u8 = undefined;
    var apDiv: [NB - 1]?[*]u8 = undefined;
    var cntNew: [NB + 2]c_int = undefined;
    var cntOld: [NB + 2]c_int = undefined;
    var szNew: [NB + 2]c_int = undefined;
    var aSpace1: [*]u8 = undefined;
    var pgno: u32 = undefined;
    var abDone: [NB + 2]u8 = @splat(0);
    var aPgno: [NB + 2]u32 = undefined;
    var b: CellArray = undefined;

    @memset(std.mem.asBytes(&b)[0 .. @sizeOf(CellArray) - @sizeOf(@TypeOf(b.ixNx))], 0);
    b.ixNx[NB * 2 - 1] = 0x7fffffff;
    const pBt = pParent.pBt.?;

    if (aOvflSpace == null) {
        return nomem_bkpt();
    }

    i = @as(c_int, pParent.nOverflow) + @as(c_int, pParent.nCell);
    if (i < 2) {
        nxDiv = 0;
    } else {
        if (iParentIdx == 0) {
            nxDiv = 0;
        } else if (iParentIdx == i) {
            nxDiv = i - 2 + bBulk;
        } else {
            nxDiv = iParentIdx - 1;
        }
        i = 2 - bBulk;
    }
    nOld = i + 1;
    if ((i + nxDiv - pParent.nOverflow) == pParent.nCell) {
        pRight = pParent.aData.? + @as(usize, pParent.hdrOffset) + 8;
    } else {
        pRight = findCell(pParent, i + nxDiv - pParent.nOverflow);
    }
    pgno = get4byte(pRight);
    while (true) {
        if (rc == SQLITE_OK) {
            rc = getAndInitPage(pBt, pgno, &apOld[@intCast(i)], 0);
        }
        if (rc != 0) {
            @memset(apOld[0..@intCast(i + 1)], null);
            return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
        }
        if (apOld[@intCast(i)].?.nFree < 0) {
            rc = btreeComputeFreeSpace(apOld[@intCast(i)].?);
            if (rc != 0) {
                @memset(apOld[0..@intCast(i)], null);
                return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
            }
        }
        nMaxCells += @as(c_int, apOld[@intCast(i)].?.nCell) + 4;
        const ii = i;
        i -= 1;
        if (ii == 0) break;

        if (pParent.nOverflow != 0 and i + nxDiv == pParent.aiOvfl[0]) {
            apDiv[@intCast(i)] = pParent.apOvfl[0];
            pgno = get4byte(apDiv[@intCast(i)].?);
            szNew[@intCast(i)] = pParent.xCellSize(pParent, apDiv[@intCast(i)].?);
            pParent.nOverflow = 0;
        } else {
            apDiv[@intCast(i)] = findCell(pParent, i + nxDiv - pParent.nOverflow);
            pgno = get4byte(apDiv[@intCast(i)].?);
            szNew[@intCast(i)] = pParent.xCellSize(pParent, apDiv[@intCast(i)].?);

            if ((pBt.btsFlags & BTS_FAST_SECURE) != 0) {
                const iOff: c_int = @intCast(@intFromPtr(apDiv[@intCast(i)].?) - @intFromPtr(pParent.aData.?));
                if ((iOff + szNew[@intCast(i)]) <= @as(c_int, @intCast(pBt.usableSize))) {
                    @memcpy((aOvflSpace.? + @as(usize, @intCast(iOff)))[0..@intCast(szNew[@intCast(i)])], apDiv[@intCast(i)].?[0..@intCast(szNew[@intCast(i)])]);
                    apDiv[@intCast(i)] = aOvflSpace.? + (@intFromPtr(apDiv[@intCast(i)].?) - @intFromPtr(pParent.aData.?));
                }
            }
            dropCell(pParent, i + nxDiv - pParent.nOverflow, szNew[@intCast(i)], &rc);
        }
    }

    nMaxCells = (nMaxCells + 3) & ~@as(c_int, 3);

    const szScratch: u64 = @as(u64, @intCast(nMaxCells)) * @sizeOf(?*u8) + @as(u64, @intCast(nMaxCells)) * @sizeOf(u16) + pBt.pageSize;
    b.apCell = @ptrCast(@alignCast(sqlite3StackAllocRaw(null, szScratch)));
    if (b.apCell == null) {
        rc = nomem_bkpt();
        return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
    }
    b.szCell = @ptrCast(@alignCast(&b.apCell.?[@intCast(nMaxCells)]));
    aSpace1 = @ptrCast(&b.szCell.?[@intCast(nMaxCells)]);

    b.pRef = apOld[0];
    leafCorrection = @as(u16, b.pRef.?.leaf) * 4;
    leafData = b.pRef.?.intKeyLeaf;
    i = 0;
    while (i < nOld) : (i += 1) {
        const pOld = apOld[@intCast(i)].?;
        var limit: c_int = pOld.nCell;
        const aData = pOld.aData.?;
        const maskPage = pOld.maskPage;
        var piCell = aData + pOld.cellOffset;

        if (pOld.aData.?[0] != apOld[0].?.aData.?[0]) {
            rc = corrupt_page(pOld);
            return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
        }

        @memset(b.szCell.?[@intCast(b.nCell) .. @intCast(b.nCell + limit + pOld.nOverflow)], 0);
        if (pOld.nOverflow > 0) {
            if (limit < pOld.aiOvfl[0]) {
                rc = corrupt_page(pOld);
                return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
            }
            limit = pOld.aiOvfl[0];
            j = 0;
            while (j < limit) : (j += 1) {
                b.apCell.?[@intCast(b.nCell)] = aData + @as(usize, @intCast(maskPage & get2byteAligned(piCell)));
                piCell += 2;
                b.nCell += 1;
            }
            k = 0;
            while (k < pOld.nOverflow) : (k += 1) {
                b.apCell.?[@intCast(b.nCell)] = pOld.apOvfl[@intCast(k)];
                b.nCell += 1;
            }
        }
        const piEnd = aData + @as(usize, @intCast(@as(c_int, pOld.cellOffset) + 2 * @as(c_int, pOld.nCell)));
        while (@intFromPtr(piCell) < @intFromPtr(piEnd)) {
            b.apCell.?[@intCast(b.nCell)] = aData + @as(usize, @intCast(maskPage & get2byteAligned(piCell)));
            piCell += 2;
            b.nCell += 1;
        }

        cntOld[@intCast(i)] = b.nCell;
        if (i < nOld - 1 and leafData == 0) {
            const sz: u16 = @intCast(szNew[@intCast(i)]);
            const pTemp = aSpace1 + @as(usize, @intCast(iSpace1));
            iSpace1 += sz;
            b.szCell.?[@intCast(b.nCell)] = sz;
            @memcpy(pTemp[0..sz], apDiv[@intCast(i)].?[0..sz]);
            b.apCell.?[@intCast(b.nCell)] = pTemp + leafCorrection;
            b.szCell.?[@intCast(b.nCell)] = b.szCell.?[@intCast(b.nCell)] - leafCorrection;
            if (pOld.leaf == 0) {
                @memcpy(b.apCell.?[@intCast(b.nCell)].?[0..4], (pOld.aData.? + 8)[0..4]);
            } else {
                while (b.szCell.?[@intCast(b.nCell)] < 4) {
                    aSpace1[@intCast(iSpace1)] = 0x00;
                    iSpace1 += 1;
                    b.szCell.?[@intCast(b.nCell)] += 1;
                }
            }
            b.nCell += 1;
        }
    }

    usableSpace = @as(c_int, @intCast(pBt.usableSize)) - 12 + leafCorrection;
    i = 0;
    k = 0;
    while (i < nOld) : ({
        i += 1;
        k += 1;
    }) {
        const p = apOld[@intCast(i)].?;
        b.apEnd[@intCast(k)] = p.aDataEnd;
        b.ixNx[@intCast(k)] = cntOld[@intCast(i)];
        if (k != 0 and b.ixNx[@intCast(k)] == b.ixNx[@intCast(k - 1)]) {
            k -= 1;
        }
        if (leafData == 0) {
            k += 1;
            b.apEnd[@intCast(k)] = pParent.aDataEnd;
            b.ixNx[@intCast(k)] = cntOld[@intCast(i)] + 1;
        }
        szNew[@intCast(i)] = usableSpace - p.nFree;
        j = 0;
        while (j < p.nOverflow) : (j += 1) {
            szNew[@intCast(i)] += 2 + p.xCellSize(p, p.apOvfl[@intCast(j)]);
        }
        cntNew[@intCast(i)] = cntOld[@intCast(i)];
    }
    k = nOld;
    i = 0;
    while (i < k) : (i += 1) {
        var sz: c_int = undefined;
        while (szNew[@intCast(i)] > usableSpace) {
            if (i + 1 >= k) {
                k = i + 2;
                if (k > NB + 2) {
                    rc = corrupt_bkpt(@src().line);
                    return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
                }
                szNew[@intCast(k - 1)] = 0;
                cntNew[@intCast(k - 1)] = b.nCell;
            }
            sz = 2 + cachedCellSize(&b, cntNew[@intCast(i)] - 1);
            szNew[@intCast(i)] -= sz;
            if (leafData == 0) {
                if (cntNew[@intCast(i)] < b.nCell) {
                    sz = 2 + cachedCellSize(&b, cntNew[@intCast(i)]);
                } else {
                    sz = 0;
                }
            }
            szNew[@intCast(i + 1)] += sz;
            cntNew[@intCast(i)] -= 1;
        }
        while (cntNew[@intCast(i)] < b.nCell) {
            sz = 2 + cachedCellSize(&b, cntNew[@intCast(i)]);
            if (szNew[@intCast(i)] + sz > usableSpace) break;
            szNew[@intCast(i)] += sz;
            cntNew[@intCast(i)] += 1;
            if (leafData == 0) {
                if (cntNew[@intCast(i)] < b.nCell) {
                    sz = 2 + cachedCellSize(&b, cntNew[@intCast(i)]);
                } else {
                    sz = 0;
                }
            }
            szNew[@intCast(i + 1)] -= sz;
        }
        if (cntNew[@intCast(i)] >= b.nCell) {
            k = i + 1;
        } else if (cntNew[@intCast(i)] <= (if (i > 0) cntNew[@intCast(i - 1)] else 0)) {
            rc = corrupt_bkpt(@src().line);
            return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
        }
    }

    i = k - 1;
    while (i > 0) : (i -= 1) {
        var szRight = szNew[@intCast(i)];
        var szLeft = szNew[@intCast(i - 1)];
        var r = cntNew[@intCast(i - 1)] - 1;
        var d = r + 1 - leafData;
        _ = cachedCellSize(&b, d);
        while (true) {
            const szR = cachedCellSize(&b, r);
            const szD = b.szCell.?[@intCast(d)];
            if (szRight != 0 and (bBulk != 0 or szRight + szD + 2 > szLeft - (szR + (if (i == k - 1) @as(c_int, 0) else 2)))) {
                break;
            }
            szRight += szD + 2;
            szLeft -= szR + 2;
            cntNew[@intCast(i - 1)] = r;
            r -= 1;
            d -= 1;
            if (!(r >= 0)) break;
        }
        szNew[@intCast(i)] = szRight;
        szNew[@intCast(i - 1)] = szLeft;
        if (cntNew[@intCast(i - 1)] <= (if (i > 1) cntNew[@intCast(i - 2)] else 0)) {
            rc = corrupt_bkpt(@src().line);
            return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
        }
    }

    pageFlags = apOld[0].?.aData.?[0];
    i = 0;
    while (i < k) : (i += 1) {
        var pNew: *MemPage = undefined;
        if (i < nOld) {
            pNew = apOld[@intCast(i)].?;
            apNew[@intCast(i)] = pNew;
            apOld[@intCast(i)] = null;
            rc = sqlite3PagerWrite(pNew.pDbPage);
            nNew += 1;
            if (sqlite3PagerPageRefcount(pNew.pDbPage) != 1 + @as(c_int, @intFromBool(i == (iParentIdx - nxDiv))) and rc == SQLITE_OK) {
                rc = corrupt_bkpt(@src().line);
            }
            if (rc != 0) return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
        } else {
            var pNewOpt: ?*MemPage = null;
            rc = allocateBtreePage(pBt, &pNewOpt, &pgno, (if (bBulk != 0) @as(u32, 1) else pgno), 0);
            if (rc != 0) return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
            pNew = pNewOpt.?;
            zeroPage(pNew, pageFlags);
            apNew[@intCast(i)] = pNew;
            nNew += 1;
            cntOld[@intCast(i)] = b.nCell;

            if (isAutoVacuum(pBt)) {
                ptrmapPut(pBt, pNew.pgno, PTRMAP_BTREE, pParent.pgno, &rc);
                if (rc != SQLITE_OK) {
                    return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
                }
            }
        }
    }

    i = 0;
    while (i < nNew) : (i += 1) {
        aPgno[@intCast(i)] = apNew[@intCast(i)].?.pgno;
    }
    i = 0;
    while (i < nNew - 1) : (i += 1) {
        var iB = i;
        j = i + 1;
        while (j < nNew) : (j += 1) {
            if (apNew[@intCast(j)].?.pgno < apNew[@intCast(iB)].?.pgno) iB = j;
        }
        if (iB != i) {
            const pgnoA = apNew[@intCast(i)].?.pgno;
            const pgnoB = apNew[@intCast(iB)].?.pgno;
            const pgnoTemp: u32 = @intCast(@divTrunc(PENDING_BYTE, @as(i64, pBt.pageSize)) + 1);
            const fgA = pgHdrFlags(apNew[@intCast(i)].?.pDbPage);
            const fgB = pgHdrFlags(apNew[@intCast(iB)].?.pDbPage);
            sqlite3PagerRekey(apNew[@intCast(i)].?.pDbPage, pgnoTemp, fgB);
            sqlite3PagerRekey(apNew[@intCast(iB)].?.pDbPage, pgnoA, fgA);
            sqlite3PagerRekey(apNew[@intCast(i)].?.pDbPage, pgnoB, fgB);
            apNew[@intCast(i)].?.pgno = pgnoB;
            apNew[@intCast(iB)].?.pgno = pgnoA;
        }
    }

    put4byte(pRight, apNew[@intCast(nNew - 1)].?.pgno);

    if ((pageFlags & PTF_LEAF) == 0 and nOld != nNew) {
        var pOld: *MemPage = undefined;
        if (nNew > nOld) {
            pOld = apNew[@intCast(nOld - 1)].?;
        } else {
            pOld = apOld[@intCast(nOld - 1)].?;
        }
        @memcpy((apNew[@intCast(nNew - 1)].?.aData.? + 8)[0..4], (pOld.aData.? + 8)[0..4]);
    }

    if (isAutoVacuum(pBt)) {
        var pOld = apNew[0].?;
        var pNew = pOld;
        var cntOldNext: c_int = @as(c_int, pNew.nCell) + @as(c_int, pNew.nOverflow);
        var iNew: c_int = 0;
        var iOld: c_int = 0;
        i = 0;
        while (i < b.nCell) : (i += 1) {
            const pCell = b.apCell.?[@intCast(i)].?;
            while (i == cntOldNext) {
                iOld += 1;
                pOld = if (iOld < nNew) apNew[@intCast(iOld)].? else apOld[@intCast(iOld)].?;
                cntOldNext += @as(c_int, pOld.nCell) + @as(c_int, pOld.nOverflow) + (1 - leafData);
            }
            if (i == cntNew[@intCast(iNew)]) {
                iNew += 1;
                pNew = apNew[@intCast(iNew)].?;
                if (leafData == 0) continue;
            }

            if (iOld >= nNew or pNew.pgno != aPgno[@intCast(iOld)] or !sqlite_within(pCell, pOld.aData.?, pOld.aDataEnd.?)) {
                if (leafCorrection == 0) {
                    ptrmapPut(pBt, get4byte(pCell), PTRMAP_BTREE, pNew.pgno, &rc);
                }
                if (cachedCellSize(&b, i) > pNew.minLocal) {
                    ptrmapPutOvflPtr(pNew, pOld, pCell, &rc);
                }
                if (rc != 0) return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
            }
        }
    }

    i = 0;
    while (i < nNew - 1) : (i += 1) {
        var pCell: [*]u8 = undefined;
        var pTemp: ?[*]u8 = undefined;
        var sz: c_int = undefined;
        var pSrcEnd: [*]u8 = undefined;
        const pNew = apNew[@intCast(i)].?;
        j = cntNew[@intCast(i)];

        pCell = b.apCell.?[@intCast(j)].?;
        sz = b.szCell.?[@intCast(j)] + leafCorrection;
        pTemp = aOvflSpace.? + @as(usize, @intCast(iOvflSpace));
        if (pNew.leaf == 0) {
            @memcpy((pNew.aData.? + 8)[0..4], pCell[0..4]);
        } else if (leafData != 0) {
            var info: CellInfo = undefined;
            j -= 1;
            pNew.xParseCell(pNew, b.apCell.?[@intCast(j)].?, &info);
            pCell = pTemp.?;
            sz = 4 + sqlite3PutVarint(pCell + 4, @bitCast(info.nKey));
            pTemp = null;
        } else {
            pCell -= 4;
            if (b.szCell.?[@intCast(j)] == 4) {
                sz = pParent.xCellSize(pParent, pCell);
            }
        }
        iOvflSpace += sz;
        k = 0;
        while (b.ixNx[@intCast(k)] <= j) k += 1;
        pSrcEnd = b.apEnd[@intCast(k)].?;
        if (sqlite_overflow(pSrcEnd, pCell, pCell + @as(usize, @intCast(sz)))) {
            rc = corrupt_bkpt(@src().line);
            return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
        }
        rc = insertCell(pParent, nxDiv + i, pCell, sz, pTemp, pNew.pgno);
        if (rc != SQLITE_OK) return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
    }

    i = 1 - nNew;
    while (i < nNew) : (i += 1) {
        const iPg = if (i < 0) -i else i;
        if (abDone[@intCast(iPg)] != 0) continue;
        if (i >= 0 or cntOld[@intCast(iPg - 1)] >= cntNew[@intCast(iPg - 1)]) {
            var iNew: c_int = undefined;
            var iOld: c_int = undefined;
            var nNewCell: c_int = undefined;
            if (iPg == 0) {
                iNew = 0;
                iOld = 0;
                nNewCell = cntNew[0];
            } else {
                iOld = if (iPg < nOld) (cntOld[@intCast(iPg - 1)] + (1 - leafData)) else b.nCell;
                iNew = cntNew[@intCast(iPg - 1)] + (1 - leafData);
                nNewCell = cntNew[@intCast(iPg)] - iNew;
            }
            rc = editPage(apNew[@intCast(iPg)].?, iOld, iNew, nNewCell, &b);
            if (rc != 0) return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
            abDone[@intCast(iPg)] += 1;
            apNew[@intCast(iPg)].?.nFree = usableSpace - szNew[@intCast(iPg)];
        }
    }

    if (isRoot != 0 and pParent.nCell == 0 and pParent.hdrOffset <= apNew[0].?.nFree) {
        rc = defragmentPage(apNew[0].?, -1);
        copyNodeContent(apNew[0].?, pParent, &rc);
        freePage(apNew[0].?, &rc);
    } else if (isAutoVacuum(pBt) and leafCorrection == 0) {
        i = 0;
        while (i < nNew) : (i += 1) {
            const key = get4byte(apNew[@intCast(i)].?.aData.? + 8);
            ptrmapPut(pBt, key, PTRMAP_BTREE, apNew[@intCast(i)].?.pgno, &rc);
        }
    }

    i = nNew;
    while (i < nOld) : (i += 1) {
        freePage(apOld[@intCast(i)].?, &rc);
    }

    return balanceCleanup(&b, &apOld, &apNew, nOld, nNew, rc);
}

fn balanceCleanup(b: *CellArray, apOld: []?*MemPage, apNew: []?*MemPage, nOld: c_int, nNew: c_int, rc: c_int) c_int {
    sqlite3StackFree(null, @ptrCast(b.apCell));
    var i: c_int = 0;
    while (i < nOld) : (i += 1) {
        releasePage(apOld[@intCast(i)]);
    }
    i = 0;
    while (i < nNew) : (i += 1) {
        releasePage(apNew[@intCast(i)]);
    }
    return rc;
}

inline fn pgHdrFlags(pDbPage: ?*DbPage) u16 {
    return fieldPtr(u16, pDbPage, 52).*;
}

fn balance_deeper(pRoot: *MemPage, ppChild: *?*MemPage) c_int {
    var pChild: ?*MemPage = null;
    var pgnoChild: u32 = 0;
    const pBt = pRoot.pBt.?;

    var rc = sqlite3PagerWrite(pRoot.pDbPage);
    if (rc == SQLITE_OK) {
        rc = allocateBtreePage(pBt, &pChild, &pgnoChild, pRoot.pgno, 0);
        copyNodeContent(pRoot, pChild orelse {
            ppChild.* = null;
            releasePage(pChild);
            return rc;
        }, &rc);
        if (isAutoVacuum(pBt)) {
            ptrmapPut(pBt, pgnoChild, PTRMAP_BTREE, pRoot.pgno, &rc);
        }
    }
    if (rc != 0) {
        ppChild.* = null;
        releasePage(pChild);
        return rc;
    }

    const ch = pChild.?;
    @memcpy(std.mem.sliceAsBytes(ch.aiOvfl[0..pRoot.nOverflow]), std.mem.sliceAsBytes(pRoot.aiOvfl[0..pRoot.nOverflow]));
    @memcpy(std.mem.sliceAsBytes(ch.apOvfl[0..pRoot.nOverflow]), std.mem.sliceAsBytes(pRoot.apOvfl[0..pRoot.nOverflow]));
    ch.nOverflow = pRoot.nOverflow;

    zeroPage(pRoot, ch.aData.?[0] & ~PTF_LEAF);
    put4byte(pRoot.aData.? + @as(usize, pRoot.hdrOffset) + 8, pgnoChild);

    ppChild.* = pChild;
    return SQLITE_OK;
}

fn anotherValidCursor(pCur: *BtCursor) c_int {
    var pOther = pCur.pBt.?.pCursor;
    while (pOther) |o| : (pOther = o.pNext) {
        if (o != pCur and o.eState == CURSOR_VALID and o.pPage == pCur.pPage) {
            return corrupt_page(pCur.pPage.?);
        }
    }
    return SQLITE_OK;
}

fn balance(pCur: *BtCursor) c_int {
    var rc: c_int = SQLITE_OK;
    var aBalanceQuickSpace: [13]u8 = undefined;
    var pFree: ?[*]u8 = null;

    while (true) {
        const iPage = pCur.iPage;
        const pPage = pCur.pPage.?;

        if (pPage.nFree < 0 and btreeComputeFreeSpace(pPage) != 0) break;
        if (pPage.nOverflow == 0 and pPage.nFree * 3 <= @as(c_int, @intCast(pCur.pBt.?.usableSize)) * 2) {
            break;
        } else if (iPage == 0) {
            if (pPage.nOverflow != 0 and blk: {
                rc = anotherValidCursor(pCur);
                break :blk rc == SQLITE_OK;
            }) {
                rc = balance_deeper(pPage, &pCur.apPage[1]);
                if (rc == SQLITE_OK) {
                    pCur.iPage = 1;
                    pCur.ix = 0;
                    pCur.aiIdx[0] = 0;
                    pCur.apPage[0] = pPage;
                    pCur.pPage = pCur.apPage[1];
                }
            } else {
                break;
            }
        } else if (sqlite3PagerPageRefcount(pPage.pDbPage) > 1) {
            rc = corrupt_page(pPage);
        } else {
            const pParent = pCur.apPage[@intCast(iPage - 1)].?;
            const iIdx = pCur.aiIdx[@intCast(iPage - 1)];
            rc = sqlite3PagerWrite(pParent.pDbPage);
            if (rc == SQLITE_OK and pParent.nFree < 0) {
                rc = btreeComputeFreeSpace(pParent);
            }
            if (rc == SQLITE_OK) {
                if (pPage.intKeyLeaf != 0 and pPage.nOverflow == 1 and pPage.aiOvfl[0] == pPage.nCell and pParent.pgno != 1 and pParent.nCell == iIdx) {
                    rc = balance_quick(pParent, pPage, &aBalanceQuickSpace);
                } else {
                    const pSpace = @as([*]u8, @ptrCast(sqlite3PageMalloc(@intCast(pCur.pBt.?.pageSize)).?));
                    rc = balance_nonroot(pParent, iIdx, pSpace, @intFromBool(iPage == 1), @intFromBool((pCur.hints & BTREE_BULKLOAD) != 0));
                    if (pFree) |pf| {
                        sqlite3PageFree(pf);
                    }
                    pFree = pSpace;
                }
            }
            pPage.nOverflow = 0;
            releasePage(pPage);
            pCur.iPage -= 1;
            pCur.pPage = pCur.apPage[@intCast(pCur.iPage)];
        }
        if (!(rc == SQLITE_OK)) break;
    }

    if (pFree) |pf| {
        sqlite3PageFree(pf);
    }
    return rc;
}

// ════════════════════════════════════════════════════════════════════════════
// Overwrite / Insert / TransferRow / Delete
// ════════════════════════════════════════════════════════════════════════════
fn btreeOverwriteContent(pPage: *MemPage, pDest: [*]u8, pX: *const BtreePayload, iOffset: c_int, iAmt_in: c_int) c_int {
    var iAmt = iAmt_in;
    const nData = pX.nData - iOffset;
    if (nData <= 0) {
        var i: c_int = 0;
        while (i < iAmt and pDest[@intCast(i)] == 0) : (i += 1) {}
        if (i < iAmt) {
            const rc = sqlite3PagerWrite(pPage.pDbPage);
            if (rc != 0) return rc;
            @memset((pDest + @as(usize, @intCast(i)))[0..@intCast(iAmt - i)], 0);
        }
    } else {
        if (nData < iAmt) {
            const rc = btreeOverwriteContent(pPage, pDest + @as(usize, @intCast(nData)), pX, iOffset + nData, iAmt - nData);
            if (rc != 0) return rc;
            iAmt = nData;
        }
        const src: [*]const u8 = @as([*]const u8, @ptrCast(pX.pData)) + @as(usize, @intCast(iOffset));
        if (memcmp(pDest, src, @intCast(iAmt)) != 0) {
            const rc = sqlite3PagerWrite(pPage.pDbPage);
            if (rc != 0) return rc;
            std.mem.copyForwards(u8, pDest[0..@intCast(iAmt)], src[0..@intCast(iAmt)]);
        }
    }
    return SQLITE_OK;
}

fn btreeOverwriteOverflowCell(pCur: *BtCursor, pX: *const BtreePayload) c_int {
    const nTotal = pX.nData + pX.nZero;
    var rc: c_int = undefined;
    const pPage0 = pCur.pPage.?;

    rc = btreeOverwriteContent(pPage0, pCur.info.pPayload.?, pX, 0, pCur.info.nLocal);
    if (rc != 0) return rc;

    var iOffset: c_int = pCur.info.nLocal;
    var ovflPgno = get4byte(pCur.info.pPayload.? + @as(usize, @intCast(iOffset)));
    const pBt = pPage0.pBt.?;
    var ovflPageSize = pBt.usableSize - 4;
    while (true) {
        var pPageOpt: ?*MemPage = null;
        rc = btreeGetPage(pBt, ovflPgno, &pPageOpt, 0);
        if (rc != 0) return rc;
        const pPage = pPageOpt.?;
        if (sqlite3PagerPageRefcount(pPage.pDbPage) != 1 or pPage.isInit != 0) {
            rc = corrupt_page(pPage);
        } else {
            if (iOffset + @as(c_int, @intCast(ovflPageSize)) < nTotal) {
                ovflPgno = get4byte(pPage.aData.?);
            } else {
                ovflPageSize = @intCast(nTotal - iOffset);
            }
            rc = btreeOverwriteContent(pPage, pPage.aData.? + 4, pX, iOffset, @intCast(ovflPageSize));
        }
        sqlite3PagerUnref(pPage.pDbPage);
        if (rc != 0) return rc;
        iOffset += @intCast(ovflPageSize);
        if (!(iOffset < nTotal)) break;
    }
    return SQLITE_OK;
}

fn btreeOverwriteCell(pCur: *BtCursor, pX: *const BtreePayload) c_int {
    const nTotal = pX.nData + pX.nZero;
    const pPage = pCur.pPage.?;
    if (@intFromPtr(pCur.info.pPayload.? + pCur.info.nLocal) > @intFromPtr(pPage.aDataEnd.?) or
        @intFromPtr(pCur.info.pPayload.?) < @intFromPtr(pPage.aData.? + pPage.cellOffset))
    {
        return corrupt_page(pPage);
    }
    if (pCur.info.nLocal == nTotal) {
        return btreeOverwriteContent(pPage, pCur.info.pPayload.?, pX, 0, pCur.info.nLocal);
    } else {
        return btreeOverwriteOverflowCell(pCur, pX);
    }
}

export fn sqlite3BtreeInsert(pCur: *BtCursor, pX: *const BtreePayload, flags_arg: c_int, seekResult: c_int) callconv(.c) c_int {
    var rc: c_int = undefined;
    var loc = seekResult;
    var szNew: c_int = 0;
    var idx: c_int = undefined;
    var pPage: *MemPage = undefined;
    const p = pCur.pBtree.?;
    var oldCell: [*]u8 = undefined;
    var newCell: [*]u8 = undefined;

    if ((pCur.curFlags & BTCF_Multiple) != 0) {
        rc = saveAllCursors(p.pBt.?, pCur.pgnoRoot, pCur);
        if (rc != 0) return rc;
        if (loc != 0 and pCur.iPage < 0) {
            return corrupt_pgno(pCur.pgnoRoot);
        }
    }

    if (pCur.eState >= CURSOR_REQUIRESEEK) {
        rc = moveToRoot(pCur);
        if (rc != 0 and rc != SQLITE_EMPTY) return rc;
    }

    if (pCur.pKeyInfo == null) {
        if (p.hasIncrblobCur != 0) {
            invalidateIncrblobCursors(p, pCur.pgnoRoot, pX.nKey, 0);
        }
        if ((pCur.curFlags & BTCF_ValidNKey) != 0 and pX.nKey == pCur.info.nKey) {
            if (pCur.info.nSize != 0 and pCur.info.nPayload == @as(u32, @bitCast(pX.nData)) +% @as(u32, @bitCast(pX.nZero))) {
                return btreeOverwriteCell(pCur, pX);
            }
        } else if (loc == 0) {
            rc = sqlite3BtreeTableMoveto(pCur, pX.nKey, @intFromBool((flags_arg & BTREE_APPEND) != 0), &loc);
            if (rc != 0) return rc;
        }
    } else {
        if (loc == 0 and (flags_arg & BTREE_SAVEPOSITION) == 0) {
            if (pX.nMem != 0) {
                var r: UnpackedRecord = undefined;
                r.pKeyInfo = pCur.pKeyInfo;
                r.aMem = @ptrCast(pX.aMem);
                r.nField = pX.nMem;
                r.default_rc = 0;
                r.eqSeen = 0;
                rc = sqlite3BtreeIndexMoveto(pCur, &r, &loc);
            } else {
                rc = btreeMoveto(pCur, pX.pKey, pX.nKey, @intFromBool((flags_arg & BTREE_APPEND) != 0), &loc);
            }
            if (rc != 0) return rc;
        }
        if (loc == 0) {
            getCellInfo(pCur);
            if (pCur.info.nKey == pX.nKey) {
                var x2: BtreePayload = undefined;
                x2.pData = pX.pKey;
                x2.nData = @intCast(pX.nKey);
                x2.nZero = 0;
                return btreeOverwriteCell(pCur, &x2);
            }
        }
    }

    pPage = pCur.pPage.?;
    if (pPage.nFree < 0) {
        if (pCur.eState > CURSOR_INVALID) {
            rc = corrupt_page(pPage);
        } else {
            rc = btreeComputeFreeSpace(pPage);
        }
        if (rc != 0) return rc;
    }

    newCell = p.pBt.?.pTmpSpace.?;
    if ((flags_arg & BTREE_PREFORMAT) != 0) {
        rc = SQLITE_OK;
        szNew = p.pBt.?.nPreformatSize;
        if (szNew < 4) {
            szNew = 4;
            newCell[3] = 0;
        }
        if (isAutoVacuum(p.pBt.?) and szNew > pPage.maxLocal) {
            var info: CellInfo = undefined;
            pPage.xParseCell(pPage, newCell, &info);
            if (info.nPayload != info.nLocal) {
                const ovfl = get4byte(newCell + @as(usize, @intCast(szNew - 4)));
                ptrmapPut(p.pBt.?, ovfl, PTRMAP_OVERFLOW1, pPage.pgno, &rc);
                if (rc != 0) return rc;
            }
        }
    } else {
        rc = fillInCell(pPage, newCell, pX, &szNew);
        if (rc != 0) return rc;
    }
    idx = pCur.ix;
    pCur.info.nSize = 0;
    if (loc == 0) {
        var info: CellInfo = undefined;
        if (idx >= pPage.nCell) {
            return corrupt_page(pPage);
        }
        rc = sqlite3PagerWrite(pPage.pDbPage);
        if (rc != 0) {
            return rc;
        }
        oldCell = findCell(pPage, idx);
        if (pPage.leaf == 0) {
            @memcpy(newCell[0..4], oldCell[0..4]);
        }
        rc = btreeClearCell(pPage, oldCell, &info);
        invalidateOverflowCache(pCur);
        if (info.nSize == szNew and info.nLocal == info.nPayload and (!isAutoVacuum(p.pBt.?) or szNew < pPage.minLocal)) {
            if (@intFromPtr(oldCell) < @intFromPtr(pPage.aData.? + pPage.hdrOffset + 10)) {
                return corrupt_page(pPage);
            }
            if (@intFromPtr(oldCell + @as(usize, @intCast(szNew))) > @intFromPtr(pPage.aDataEnd.?)) {
                return corrupt_page(pPage);
            }
            @memcpy(oldCell[0..@intCast(szNew)], newCell[0..@intCast(szNew)]);
            return SQLITE_OK;
        }
        dropCell(pPage, idx, info.nSize, &rc);
        if (rc != 0) return rc;
    } else if (loc < 0 and pPage.nCell > 0) {
        pCur.ix += 1;
        idx = pCur.ix;
        pCur.curFlags &= ~(BTCF_ValidNKey | BTCF_ValidOvfl);
    }
    rc = insertCellFast(pPage, idx, newCell, szNew);

    if (pPage.nOverflow != 0) {
        pCur.curFlags &= ~(BTCF_ValidNKey | BTCF_ValidOvfl);
        rc = balance(pCur);
        pCur.pPage.?.nOverflow = 0;
        pCur.eState = CURSOR_INVALID;
        if ((flags_arg & BTREE_SAVEPOSITION) != 0 and rc == SQLITE_OK) {
            btreeReleaseAllCursorPages(pCur);
            if (pCur.pKeyInfo != null) {
                pCur.pKey = sqlite3Malloc(@intCast(pX.nKey));
                if (pCur.pKey == null) {
                    rc = SQLITE_NOMEM;
                } else {
                    @memcpy(@as([*]u8, @ptrCast(pCur.pKey.?))[0..@intCast(pX.nKey)], @as([*]const u8, @ptrCast(pX.pKey.?))[0..@intCast(pX.nKey)]);
                }
            }
            pCur.eState = CURSOR_REQUIRESEEK;
            pCur.nKey = pX.nKey;
        }
    }
    return rc;
}

export fn sqlite3BtreeTransferRow(pDest: *BtCursor, pSrc: *BtCursor, iKey: i64) callconv(.c) c_int {
    const pBt = pDest.pBt.?;
    var aOut = pBt.pTmpSpace.?;
    var aIn: [*]const u8 = undefined;
    var nIn: u32 = undefined;
    var nRem: u32 = undefined;

    getCellInfo(pSrc);
    if (pSrc.info.nPayload < 0x80) {
        aOut[0] = @truncate(pSrc.info.nPayload);
        aOut += 1;
    } else {
        aOut += @as(usize, @intCast(sqlite3PutVarint(aOut, pSrc.info.nPayload)));
    }
    if (pDest.pKeyInfo == null) aOut += @as(usize, @intCast(sqlite3PutVarint(aOut, @bitCast(iKey))));
    nIn = pSrc.info.nLocal;
    aIn = pSrc.info.pPayload.?;
    if (@intFromPtr(aIn + nIn) > @intFromPtr(pSrc.pPage.?.aDataEnd.?)) {
        return corrupt_page(pSrc.pPage.?);
    }
    nRem = pSrc.info.nPayload;
    if (nIn == nRem and nIn < pDest.pPage.?.maxLocal) {
        @memcpy(aOut[0..nIn], aIn[0..nIn]);
        pBt.nPreformatSize = @as(c_int, @intCast(nIn)) + @as(c_int, @intCast(@intFromPtr(aOut) - @intFromPtr(pBt.pTmpSpace.?)));
        return SQLITE_OK;
    } else {
        var rc: c_int = SQLITE_OK;
        const pSrcPager = pSrc.pBt.?.pPager;
        var pPgnoOut: ?[*]u8 = null;
        var ovflIn: u32 = 0;
        var pPageIn: ?*DbPage = null;
        var pPageOut: ?*MemPage = null;
        var nOut: u32 = undefined;

        nOut = @intCast(btreePayloadToLocal(pDest.pPage.?, pSrc.info.nPayload));
        pBt.nPreformatSize = @as(c_int, @intCast(nOut)) + @as(c_int, @intCast(@intFromPtr(aOut) - @intFromPtr(pBt.pTmpSpace.?)));
        if (nOut < pSrc.info.nPayload) {
            pPgnoOut = aOut + @as(usize, nOut);
            pBt.nPreformatSize += 4;
        }

        if (nRem > nIn) {
            if (@intFromPtr(aIn + nIn + 4) > @intFromPtr(pSrc.pPage.?.aDataEnd.?)) {
                return corrupt_page(pSrc.pPage.?);
            }
            ovflIn = get4byte(pSrc.info.pPayload.? + nIn);
        }

        while (true) {
            nRem -= nOut;
            while (true) {
                if (nIn > 0) {
                    const nCopy = MIN(nOut, nIn);
                    @memcpy(aOut[0..nCopy], aIn[0..nCopy]);
                    nOut -= nCopy;
                    nIn -= nCopy;
                    aOut += nCopy;
                    aIn += nCopy;
                }
                if (nOut > 0) {
                    sqlite3PagerUnref(pPageIn);
                    pPageIn = null;
                    rc = sqlite3PagerGet(pSrcPager, ovflIn, &pPageIn, PAGER_GET_READONLY);
                    if (rc == SQLITE_OK) {
                        aIn = sqlite3PagerGetData(pPageIn).?;
                        ovflIn = get4byte(aIn);
                        aIn += 4;
                        nIn = pSrc.pBt.?.usableSize - 4;
                    }
                }
                if (!(rc == SQLITE_OK and nOut > 0)) break;
            }

            if (rc == SQLITE_OK and nRem > 0 and pPgnoOut != null) {
                var pgnoNew: u32 = 0;
                var pNew: ?*MemPage = null;
                rc = allocateBtreePage(pBt, &pNew, &pgnoNew, 0, 0);
                put4byte(pPgnoOut.?, pgnoNew);
                if (isAutoVacuum(pBt) and pPageOut != null) {
                    ptrmapPut(pBt, pgnoNew, PTRMAP_OVERFLOW2, pPageOut.?.pgno, &rc);
                }
                releasePage(pPageOut);
                pPageOut = pNew;
                if (pPageOut) |po| {
                    pPgnoOut = po.aData.?;
                    put4byte(pPgnoOut.?, 0);
                    aOut = pPgnoOut.? + 4;
                    nOut = MIN(pBt.usableSize - 4, nRem);
                }
            }
            if (!(nRem > 0 and rc == SQLITE_OK)) break;
        }

        releasePage(pPageOut);
        sqlite3PagerUnref(pPageIn);
        return rc;
    }
}

export fn sqlite3BtreeDelete(pCur: *BtCursor, flags_arg: u8) callconv(.c) c_int {
    const p = pCur.pBtree.?;
    const pBt = p.pBt.?;
    var rc: c_int = undefined;
    var pPage: *MemPage = undefined;
    var pCell: [*]u8 = undefined;
    var iCellIdx: c_int = undefined;
    var iCellDepth: c_int = undefined;
    var info: CellInfo = undefined;
    var bPreserve: u8 = undefined;

    if (pCur.eState != CURSOR_VALID) {
        if (pCur.eState >= CURSOR_REQUIRESEEK) {
            rc = btreeRestoreCursorPosition(pCur);
            if (rc != 0 or pCur.eState != CURSOR_VALID) return rc;
        } else {
            return corrupt_pgno(pCur.pgnoRoot);
        }
    }

    iCellDepth = pCur.iPage;
    iCellIdx = pCur.ix;
    pPage = pCur.pPage.?;
    if (pPage.nCell <= iCellIdx) {
        return corrupt_page(pPage);
    }
    pCell = findCell(pPage, iCellIdx);
    if (pPage.nFree < 0 and btreeComputeFreeSpace(pPage) != 0) {
        return corrupt_page(pPage);
    }
    if (@intFromPtr(pCell) < @intFromPtr(pPage.aCellIdx.? + pPage.nCell)) {
        return corrupt_page(pPage);
    }

    bPreserve = @intFromBool((flags_arg & BTREE_SAVEPOSITION) != 0);
    if (bPreserve != 0) {
        if (pPage.leaf == 0 or (pPage.nFree + pPage.xCellSize(pPage, pCell) + 2) > @as(c_int, @intCast(pBt.usableSize * 2 / 3)) or pPage.nCell == 1) {
            rc = saveCursorKey(pCur);
            if (rc != 0) return rc;
        } else {
            bPreserve = 2;
        }
    }

    if (pPage.leaf == 0) {
        rc = sqlite3BtreePrevious(pCur, 0);
        if (rc != 0) return rc;
    }

    if ((pCur.curFlags & BTCF_Multiple) != 0) {
        rc = saveAllCursors(pBt, pCur.pgnoRoot, pCur);
        if (rc != 0) return rc;
    }

    if (pCur.pKeyInfo == null and p.hasIncrblobCur != 0) {
        invalidateIncrblobCursors(p, pCur.pgnoRoot, pCur.info.nKey, 0);
    }

    rc = sqlite3PagerWrite(pPage.pDbPage);
    if (rc != 0) return rc;
    rc = btreeClearCell(pPage, pCell, &info);
    dropCell(pPage, iCellIdx, info.nSize, &rc);
    if (rc != 0) return rc;

    if (pPage.leaf == 0) {
        const pLeaf = pCur.pPage.?;
        var nCell: c_int = undefined;
        var n: u32 = undefined;
        var pTmp: [*]u8 = undefined;

        if (pLeaf.nFree < 0) {
            rc = btreeComputeFreeSpace(pLeaf);
            if (rc != 0) return rc;
        }
        if (iCellDepth < pCur.iPage - 1) {
            n = pCur.apPage[@intCast(iCellDepth + 1)].?.pgno;
        } else {
            n = pCur.pPage.?.pgno;
        }
        pCell = findCell(pLeaf, pLeaf.nCell - 1);
        if (@intFromPtr(pCell) < @intFromPtr(pLeaf.aData.? + 4)) return corrupt_page(pLeaf);
        nCell = pLeaf.xCellSize(pLeaf, pCell);
        pTmp = pBt.pTmpSpace.?;
        rc = sqlite3PagerWrite(pLeaf.pDbPage);
        if (rc == SQLITE_OK) {
            rc = insertCell(pPage, iCellIdx, pCell - 4, nCell + 4, pTmp, n);
        }
        dropCell(pLeaf, pLeaf.nCell - 1, nCell, &rc);
        if (rc != 0) return rc;
    }

    if (pCur.pPage.?.nFree * 3 <= @as(c_int, @intCast(pCur.pBt.?.usableSize)) * 2) {
        rc = SQLITE_OK;
    } else {
        rc = balance(pCur);
    }
    if (rc == SQLITE_OK and pCur.iPage > iCellDepth) {
        releasePageNotNull(pCur.pPage.?);
        pCur.iPage -= 1;
        while (pCur.iPage > iCellDepth) {
            releasePage(pCur.apPage[@intCast(pCur.iPage)]);
            pCur.iPage -= 1;
        }
        pCur.pPage = pCur.apPage[@intCast(pCur.iPage)];
        rc = balance(pCur);
    }

    if (rc == SQLITE_OK) {
        if (bPreserve > 1) {
            pCur.eState = CURSOR_SKIPNEXT;
            if (iCellIdx >= pPage.nCell) {
                pCur.skipNext = -1;
                pCur.ix = pPage.nCell - 1;
            } else {
                pCur.skipNext = 1;
            }
        } else {
            rc = moveToRoot(pCur);
            if (bPreserve != 0) {
                btreeReleaseAllCursorPages(pCur);
                pCur.eState = CURSOR_REQUIRESEEK;
            }
            if (rc == SQLITE_EMPTY) rc = SQLITE_OK;
        }
    }
    return rc;
}

// ════════════════════════════════════════════════════════════════════════════
// CreateTable / ClearTable / DropTable
// ════════════════════════════════════════════════════════════════════════════
fn btreeCreateTable(p: *Btree, piTable: *u32, createTabFlags: c_int) c_int {
    const pBt = p.pBt.?;
    var pRoot: *MemPage = undefined;
    var pgnoRoot: u32 = undefined;
    var rc: c_int = undefined;
    var ptfFlags: c_int = undefined;

    if (pBt.autoVacuum != 0) {
        var pgnoMove: u32 = undefined;
        var pPageMove: ?*MemPage = null;

        invalidateAllOverflowCache(pBt);
        sqlite3BtreeGetMeta(p, BTREE_LARGEST_ROOT_PAGE, &pgnoRoot);
        if (pgnoRoot > btreePagecount(pBt)) {
            return corrupt_pgno(pgnoRoot);
        }
        pgnoRoot += 1;
        while (pgnoRoot == PTRMAP_PAGENO(pBt, pgnoRoot) or pgnoRoot == PENDING_BYTE_PAGE(pBt)) {
            pgnoRoot += 1;
        }

        rc = allocateBtreePage(pBt, &pPageMove, &pgnoMove, pgnoRoot, BTALLOC_EXACT);
        if (rc != SQLITE_OK) {
            return rc;
        }

        if (pgnoMove != pgnoRoot) {
            var eType: u8 = 0;
            var iPtrPage: u32 = 0;
            var pRootOpt: ?*MemPage = null;

            rc = saveAllCursors(pBt, 0, null);
            releasePage(pPageMove);
            if (rc != SQLITE_OK) {
                return rc;
            }
            rc = btreeGetPage(pBt, pgnoRoot, &pRootOpt, 0);
            if (rc != SQLITE_OK) {
                return rc;
            }
            pRoot = pRootOpt.?;
            rc = ptrmapGet(pBt, pgnoRoot, &eType, &iPtrPage);
            if (eType == PTRMAP_ROOTPAGE or eType == PTRMAP_FREEPAGE) {
                rc = corrupt_pgno(pgnoRoot);
            }
            if (rc != SQLITE_OK) {
                releasePage(pRoot);
                return rc;
            }
            rc = relocatePage(pBt, pRoot, eType, iPtrPage, pgnoMove, 0);
            releasePage(pRoot);
            if (rc != SQLITE_OK) {
                return rc;
            }
            pRootOpt = null;
            rc = btreeGetPage(pBt, pgnoRoot, &pRootOpt, 0);
            if (rc != SQLITE_OK) {
                return rc;
            }
            pRoot = pRootOpt.?;
            rc = sqlite3PagerWrite(pRoot.pDbPage);
            if (rc != SQLITE_OK) {
                releasePage(pRoot);
                return rc;
            }
        } else {
            pRoot = pPageMove.?;
        }

        ptrmapPut(pBt, pgnoRoot, PTRMAP_ROOTPAGE, 0, &rc);
        if (rc != 0) {
            releasePage(pRoot);
            return rc;
        }

        rc = sqlite3BtreeUpdateMeta(p, 4, pgnoRoot);
        if (rc != 0) {
            releasePage(pRoot);
            return rc;
        }
    } else {
        var pRootOpt: ?*MemPage = null;
        rc = allocateBtreePage(pBt, &pRootOpt, &pgnoRoot, 1, 0);
        if (rc != 0) return rc;
        pRoot = pRootOpt.?;
    }

    if ((createTabFlags & BTREE_INTKEY) != 0) {
        ptfFlags = PTF_INTKEY | PTF_LEAFDATA | PTF_LEAF;
    } else {
        ptfFlags = PTF_ZERODATA | PTF_LEAF;
    }
    zeroPage(pRoot, ptfFlags);
    sqlite3PagerUnref(pRoot.pDbPage);
    piTable.* = pgnoRoot;
    return SQLITE_OK;
}

export fn sqlite3BtreeCreateTable(p: *Btree, piTable: *u32, flags_arg: c_int) callconv(.c) c_int {
    sqlite3BtreeEnter(p);
    const rc = btreeCreateTable(p, piTable, flags_arg);
    sqlite3BtreeLeave(p);
    return rc;
}

fn clearDatabasePage(pBt: *BtShared, pgno: u32, freePageFlag: c_int, pnChange_in: ?*i64) c_int {
    var pnChange = pnChange_in;
    var pPage: ?*MemPage = null;
    var rc: c_int = undefined;
    var pCell: [*]u8 = undefined;
    var hdr: c_int = undefined;
    var info: CellInfo = undefined;

    if (pgno > btreePagecount(pBt)) {
        return corrupt_pgno(pgno);
    }
    rc = getAndInitPage(pBt, pgno, &pPage, 0);
    if (rc != 0) return rc;
    if ((pBt.openFlags & BTREE_SINGLE) == 0 and sqlite3PagerPageRefcount(pPage.?.pDbPage) != (1 + @as(c_int, @intFromBool(pgno == 1)))) {
        rc = corrupt_page(pPage.?);
        return clearOut(pPage, rc);
    }
    hdr = pPage.?.hdrOffset;
    var i: c_int = 0;
    while (i < pPage.?.nCell) : (i += 1) {
        pCell = findCell(pPage.?, i);
        if (pPage.?.leaf == 0) {
            rc = clearDatabasePage(pBt, get4byte(pCell), 1, pnChange);
            if (rc != 0) return clearOut(pPage, rc);
        }
        rc = btreeClearCell(pPage.?, pCell, &info);
        if (rc != 0) return clearOut(pPage, rc);
    }
    if (pPage.?.leaf == 0) {
        rc = clearDatabasePage(pBt, get4byte(pPage.?.aData.? + @as(usize, @intCast(hdr + 8))), 1, pnChange);
        if (rc != 0) return clearOut(pPage, rc);
        if (pPage.?.intKey != 0) pnChange = null;
    }
    if (pnChange) |pc| {
        pc.* += pPage.?.nCell;
    }
    if (freePageFlag != 0) {
        freePage(pPage.?, &rc);
    } else {
        rc = sqlite3PagerWrite(pPage.?.pDbPage);
        if (rc == 0) {
            zeroPage(pPage.?, pPage.?.aData.?[@intCast(hdr)] | PTF_LEAF);
        }
    }
    return clearOut(pPage, rc);
}
fn clearOut(pPage: ?*MemPage, rc: c_int) c_int {
    releasePage(pPage);
    return rc;
}

export fn sqlite3BtreeClearTable(p: *Btree, iTable: c_int, pnChange: ?*i64) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    var rc = saveAllCursors(pBt, @intCast(iTable), null);
    if (rc == SQLITE_OK) {
        if (p.hasIncrblobCur != 0) {
            invalidateIncrblobCursors(p, @intCast(iTable), 0, 1);
        }
        rc = clearDatabasePage(pBt, @intCast(iTable), 0, pnChange);
    }
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeClearTableOfCursor(pCur: *BtCursor) callconv(.c) c_int {
    return sqlite3BtreeClearTable(pCur.pBtree.?, @intCast(pCur.pgnoRoot), null);
}

fn btreeDropTable(p: *Btree, iTable: u32, piMoved: *c_int) c_int {
    var pPage: ?*MemPage = null;
    const pBt = p.pBt.?;
    var rc: c_int = undefined;

    if (iTable > btreePagecount(pBt)) {
        return corrupt_pgno(iTable);
    }

    rc = sqlite3BtreeClearTable(p, @intCast(iTable), null);
    if (rc != 0) return rc;
    rc = btreeGetPage(pBt, iTable, &pPage, 0);
    if (rc != 0) {
        releasePage(pPage);
        return rc;
    }

    piMoved.* = 0;

    if (pBt.autoVacuum != 0) {
        var maxRootPgno: u32 = undefined;
        sqlite3BtreeGetMeta(p, BTREE_LARGEST_ROOT_PAGE, &maxRootPgno);

        if (iTable == maxRootPgno) {
            freePage(pPage.?, &rc);
            releasePage(pPage);
            if (rc != SQLITE_OK) {
                return rc;
            }
        } else {
            var pMove: ?*MemPage = null;
            releasePage(pPage);
            rc = btreeGetPage(pBt, maxRootPgno, &pMove, 0);
            if (rc != SQLITE_OK) {
                return rc;
            }
            rc = relocatePage(pBt, pMove.?, PTRMAP_ROOTPAGE, 0, iTable, 0);
            releasePage(pMove);
            if (rc != SQLITE_OK) {
                return rc;
            }
            pMove = null;
            rc = btreeGetPage(pBt, maxRootPgno, &pMove, 0);
            freePage(pMove.?, &rc);
            releasePage(pMove);
            if (rc != SQLITE_OK) {
                return rc;
            }
            piMoved.* = @intCast(maxRootPgno);
        }

        maxRootPgno -= 1;
        while (maxRootPgno == PENDING_BYTE_PAGE(pBt) or PTRMAP_ISPAGE(pBt, maxRootPgno)) {
            maxRootPgno -= 1;
        }
        rc = sqlite3BtreeUpdateMeta(p, 4, maxRootPgno);
    } else {
        freePage(pPage.?, &rc);
        releasePage(pPage);
    }
    return rc;
}

export fn sqlite3BtreeDropTable(p: *Btree, iTable: c_int, piMoved: *c_int) callconv(.c) c_int {
    sqlite3BtreeEnter(p);
    const rc = btreeDropTable(p, @intCast(iTable), piMoved);
    sqlite3BtreeLeave(p);
    return rc;
}

// ════════════════════════════════════════════════════════════════════════════
// GetMeta / UpdateMeta / Count / Pager
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3BtreeGetMeta(p: *Btree, idx: c_int, pMeta: *u32) callconv(.c) void {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    if (idx == BTREE_DATA_VERSION) {
        pMeta.* = sqlite3PagerDataVersion(pBt.pPager) +% p.iBDataVersion;
    } else {
        pMeta.* = get4byte(pBt.pPage1.?.aData.? + @as(usize, @intCast(36 + idx * 4)));
    }
    sqlite3BtreeLeave(p);
}

export fn sqlite3BtreeUpdateMeta(p: *Btree, idx: c_int, iMeta: u32) callconv(.c) c_int {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    const pP1 = pBt.pPage1.?.aData.?;
    const rc = sqlite3PagerWrite(pBt.pPage1.?.pDbPage);
    if (rc == SQLITE_OK) {
        put4byte(pP1 + @as(usize, @intCast(36 + idx * 4)), iMeta);
        if (idx == 7) { // BTREE_INCR_VACUUM
            pBt.incrVacuum = @truncate(iMeta);
        }
    }
    sqlite3BtreeLeave(p);
    return rc;
}

export fn sqlite3BtreeCount(db: ?*sqlite3, pCur: *BtCursor, pnEntry: *i64) callconv(.c) c_int {
    var nEntry: i64 = 0;
    var rc = moveToRoot(pCur);
    if (rc == SQLITE_EMPTY) {
        pnEntry.* = 0;
        return SQLITE_OK;
    }

    while (rc == SQLITE_OK and !dbInterrupted(db)) {
        var iIdx: c_int = undefined;
        var pPage = pCur.pPage.?;
        if (pPage.leaf != 0 or pPage.intKey == 0) {
            nEntry += pPage.nCell;
        }
        if (pPage.leaf != 0) {
            while (true) {
                if (pCur.iPage == 0) {
                    pnEntry.* = nEntry;
                    return moveToRoot(pCur);
                }
                moveToParent(pCur);
                if (!(pCur.ix >= pCur.pPage.?.nCell)) break;
            }
            pCur.ix += 1;
            pPage = pCur.pPage.?;
        }
        iIdx = pCur.ix;
        if (iIdx == pPage.nCell) {
            rc = moveToChild(pCur, get4byte(pPage.aData.? + @as(usize, pPage.hdrOffset) + 8));
        } else {
            rc = moveToChild(pCur, get4byte(findCell(pPage, iIdx)));
        }
    }
    return rc;
}

export fn sqlite3BtreePager(p: *Btree) callconv(.c) ?*Pager {
    return p.pBt.?.pPager;
}

// ════════════════════════════════════════════════════════════════════════════
// Integrity check
// ════════════════════════════════════════════════════════════════════════════
const IntegrityCk = extern struct {
    pBt: ?*BtShared,
    pPager: ?*Pager,
    aPgRef: ?[*]u8,
    nCkPage: u32,
    mxErr: c_int,
    nErr: c_int,
    rc: c_int,
    nStep: u32,
    zPfx: ?[*:0]const u8,
    v0: u32,
    v1: u32,
    v2: c_int,
    errMsg: StrAccumBuf,
    heap: ?[*]u32,
    db: ?*sqlite3,
    nRow: i64,
};
// StrAccum is mirrored only by size; we operate on it via the sqlite3_str_* API.
const StrAccumBuf = extern struct {
    raw: [sizeof_StrAccum]u8 align(8),
};
const sizeof_StrAccum: usize = 32;

fn checkOom(pCheck: *IntegrityCk) void {
    pCheck.rc = SQLITE_NOMEM;
    pCheck.mxErr = 0;
    if (pCheck.nErr == 0) pCheck.nErr += 1;
}

fn checkProgress(pCheck: *IntegrityCk) void {
    const db = pCheck.db;
    if (dbInterrupted(db)) {
        pCheck.rc = SQLITE_INTERRUPT;
        pCheck.nErr += 1;
        pCheck.mxErr = 0;
    }
    const xProgress = fieldPtr(?*const fn (?*anyopaque) callconv(.c) c_int, db, off_db_xProgress).*;
    if (xProgress) |cb| {
        const nProgressOps = fieldPtr(c_uint, db, off_db_nProgressOps).*;
        pCheck.nStep += 1;
        if ((pCheck.nStep % nProgressOps) == 0) {
            const pArg = fieldPtr(?*anyopaque, db, off_db_pProgressArg).*;
            if (cb(pArg) != 0) {
                pCheck.rc = SQLITE_INTERRUPT;
                pCheck.nErr += 1;
                pCheck.mxErr = 0;
            }
        }
    }
}

fn checkAppendMsg(pCheck: *IntegrityCk, zFormat: [*:0]const u8, ...) callconv(.c) void {
    checkProgress(pCheck);
    if (pCheck.mxErr == 0) return;
    pCheck.mxErr -= 1;
    pCheck.nErr += 1;
    const pAccum: *anyopaque = @ptrCast(&pCheck.errMsg);
    if (strAccumNChar(pAccum) != 0) {
        sqlite3_str_append(pAccum, "\n", 1);
    }
    if (pCheck.zPfx) |pfx| {
        sqlite3_str_appendf(pAccum, pfx, pCheck.v0, pCheck.v1, pCheck.v2);
    }
    var ap = @cVaStart();
    sqlite3_str_vappendf(pAccum, zFormat, &ap);
    @cVaEnd(&ap);
    if (strAccumAccError(pAccum) == SQLITE_NOMEM) {
        checkOom(pCheck);
    }
}
// StrAccum field offsets (config-invariant): nChar(u32)@24, accError(u8)@28,
// printfFlags(u8)@29. Probed in vendored sqliteInt.h.
inline fn strAccumNChar(p: *anyopaque) u32 {
    return fieldPtr(u32, p, 24).*;
}
inline fn strAccumAccError(p: *anyopaque) c_int {
    return fieldPtr(u8, p, 28).*;
}

fn getPageReferenced(pCheck: *IntegrityCk, iPg: u32) bool {
    return (pCheck.aPgRef.?[iPg / 8] & (@as(u8, 1) << @intCast(iPg & 0x07))) != 0;
}
fn setPageReferenced(pCheck: *IntegrityCk, iPg: u32) void {
    pCheck.aPgRef.?[iPg / 8] |= (@as(u8, 1) << @intCast(iPg & 0x07));
}

fn checkRef(pCheck: *IntegrityCk, iPage: u32) bool {
    if (iPage > pCheck.nCkPage or iPage == 0) {
        checkAppendMsg(pCheck, "invalid page number %u", iPage);
        return true;
    }
    if (getPageReferenced(pCheck, iPage)) {
        checkAppendMsg(pCheck, "2nd reference to page %u", iPage);
        return true;
    }
    setPageReferenced(pCheck, iPage);
    return false;
}

fn checkPtrmap(pCheck: *IntegrityCk, iChild: u32, eType: u8, iParent: u32) void {
    var ePtrmapType: u8 = undefined;
    var iPtrmapParent: u32 = undefined;
    const rc = ptrmapGet(pCheck.pBt.?, iChild, &ePtrmapType, &iPtrmapParent);
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_NOMEM or rc == SQLITE_IOERR_NOMEM) checkOom(pCheck);
        checkAppendMsg(pCheck, "Failed to read ptrmap key=%u", iChild);
        return;
    }
    if (ePtrmapType != eType or iPtrmapParent != iParent) {
        checkAppendMsg(pCheck, "Bad ptr map entry key=%u expected=(%u,%u) got=(%u,%u)", iChild, eType, iParent, ePtrmapType, iPtrmapParent);
    }
}

fn checkList(pCheck: *IntegrityCk, isFreeList: c_int, iPage_in: u32, N_in: u32) void {
    var iPage = iPage_in;
    var N = N_in;
    const expected = N;
    const nErrAtStart = pCheck.nErr;
    while (iPage != 0 and pCheck.mxErr != 0) {
        var pOvflPage: ?*DbPage = null;
        if (checkRef(pCheck, iPage)) break;
        N -%= 1;
        if (sqlite3PagerGet(pCheck.pPager, iPage, &pOvflPage, 0) != 0) {
            checkAppendMsg(pCheck, "failed to get page %u", iPage);
            break;
        }
        const pOvflData = sqlite3PagerGetData(pOvflPage).?;
        if (isFreeList != 0) {
            const n = get4byte(pOvflData + 4);
            if (pCheck.pBt.?.autoVacuum != 0) {
                checkPtrmap(pCheck, iPage, PTRMAP_FREEPAGE, 0);
            }
            if (n > pCheck.pBt.?.usableSize / 4 - 2) {
                checkAppendMsg(pCheck, "freelist leaf count too big on page %u", iPage);
                N -%= 1;
            } else {
                var i: u32 = 0;
                while (i < n) : (i += 1) {
                    const iFreePage = get4byte(pOvflData + 8 + i * 4);
                    if (pCheck.pBt.?.autoVacuum != 0) {
                        checkPtrmap(pCheck, iFreePage, PTRMAP_FREEPAGE, 0);
                    }
                    _ = checkRef(pCheck, iFreePage);
                }
                N -%= n;
            }
        } else {
            if (pCheck.pBt.?.autoVacuum != 0 and N > 0) {
                const i = get4byte(pOvflData);
                checkPtrmap(pCheck, i, PTRMAP_OVERFLOW2, iPage);
            }
        }
        iPage = get4byte(pOvflData);
        sqlite3PagerUnref(pOvflPage);
    }
    if (N != 0 and nErrAtStart == pCheck.nErr) {
        checkAppendMsg(pCheck, "%s is %u but should be %u", if (isFreeList != 0) @as([*:0]const u8, "size") else "overflow list length", expected -% N, expected);
    }
}

fn btreeHeapInsert(aHeap: [*]u32, x_in: u32) void {
    var x = x_in;
    aHeap[0] += 1;
    var i = aHeap[0];
    aHeap[i] = x;
    var j = i / 2;
    while (j > 0 and aHeap[j] > aHeap[i]) {
        x = aHeap[j];
        aHeap[j] = aHeap[i];
        aHeap[i] = x;
        i = j;
        j = i / 2;
    }
}
fn btreeHeapPull(aHeap: [*]u32, pOut: *u32) bool {
    const x = aHeap[0];
    if (x == 0) return false;
    pOut.* = aHeap[1];
    aHeap[1] = aHeap[x];
    aHeap[x] = 0xffffffff;
    aHeap[0] -= 1;
    var i: u32 = 1;
    var j = i * 2;
    while (j <= aHeap[0]) {
        if (aHeap[j] > aHeap[j + 1]) j += 1;
        if (aHeap[i] < aHeap[j]) break;
        const t = aHeap[i];
        aHeap[i] = aHeap[j];
        aHeap[j] = t;
        i = j;
        j = i * 2;
    }
    return true;
}

fn checkTreePage(pCheck: *IntegrityCk, iPage: u32, piMinKey: *i64, maxKey_in: i64) c_int {
    var maxKey = maxKey_in;
    var pPage: ?*MemPage = null;
    var i: c_int = undefined;
    var rc: c_int = undefined;
    var depth: c_int = -1;
    var d2: c_int = undefined;
    var pgno: c_int = undefined;
    var nFrag: c_int = undefined;
    var hdr: c_int = undefined;
    var cellStart: c_int = undefined;
    var nCell: c_int = undefined;
    var doCoverageCheck: c_int = 1;
    var keyCanBeEqual: c_int = 1;
    var data: [*]u8 = undefined;
    var pCell: [*]u8 = undefined;
    var pCellIdx: [*]u8 = undefined;
    var pc: u32 = undefined;
    var usableSize: u32 = undefined;
    var contentOffset: u32 = undefined;
    var heap: ?[*]u32 = null;
    var x: u32 = undefined;
    var prev: u32 = 0;
    const saved_zPfx = pCheck.zPfx;
    const saved_v1 = pCheck.v1;
    const saved_v2 = pCheck.v2;
    var savedIsInit: u8 = 0;

    checkProgress(pCheck);
    if (pCheck.mxErr == 0) return checkTreeEnd(pCheck, pPage, doCoverageCheck, savedIsInit, saved_zPfx, saved_v1, saved_v2, depth);
    const pBt = pCheck.pBt.?;
    usableSize = pBt.usableSize;
    if (iPage == 0) return 0;
    if (checkRef(pCheck, iPage)) return 0;
    pCheck.zPfx = "Tree %u page %u: ";
    pCheck.v1 = iPage;
    rc = btreeGetPage(pBt, iPage, &pPage, 0);
    if (rc != 0) {
        checkAppendMsg(pCheck, "unable to get the page. error code=%d", rc);
        if (rc == SQLITE_IOERR_NOMEM) pCheck.rc = SQLITE_NOMEM;
        return checkTreeEnd(pCheck, pPage, doCoverageCheck, savedIsInit, saved_zPfx, saved_v1, saved_v2, depth);
    }

    savedIsInit = pPage.?.isInit;
    pPage.?.isInit = 0;
    rc = btreeInitPage(pPage.?);
    if (rc != 0) {
        checkAppendMsg(pCheck, "btreeInitPage() returns error code %d", rc);
        return checkTreeEnd(pCheck, pPage, doCoverageCheck, savedIsInit, saved_zPfx, saved_v1, saved_v2, depth);
    }
    rc = btreeComputeFreeSpace(pPage.?);
    if (rc != 0) {
        checkAppendMsg(pCheck, "free space corruption", rc);
        return checkTreeEnd(pCheck, pPage, doCoverageCheck, savedIsInit, saved_zPfx, saved_v1, saved_v2, depth);
    }
    data = pPage.?.aData.?;
    hdr = pPage.?.hdrOffset;

    pCheck.zPfx = "Tree %u page %u cell %u: ";
    contentOffset = @intCast(get2byteNotZero(data + @as(usize, @intCast(hdr + 5))));

    nCell = get2byte(data + @as(usize, @intCast(hdr + 3)));
    if (pPage.?.leaf != 0 or pPage.?.intKey == 0) {
        pCheck.nRow += nCell;
    }

    cellStart = hdr + 12 - 4 * pPage.?.leaf;
    pCellIdx = data + @as(usize, @intCast(cellStart + 2 * (nCell - 1)));

    if (pPage.?.leaf == 0) {
        pgno = @bitCast(get4byte(data + @as(usize, @intCast(hdr + 8))));
        if (pBt.autoVacuum != 0) {
            pCheck.zPfx = "Tree %u page %u right child: ";
            checkPtrmap(pCheck, @bitCast(pgno), PTRMAP_BTREE, iPage);
        }
        depth = checkTreePage(pCheck, @bitCast(pgno), &maxKey, maxKey);
        keyCanBeEqual = 0;
    } else {
        heap = pCheck.heap;
        heap.?[0] = 0;
    }

    i = nCell - 1;
    while (i >= 0 and pCheck.mxErr != 0) : (i -= 1) {
        var info: CellInfo = undefined;
        pCheck.v2 = i;
        pc = @intCast(get2byteAligned(pCellIdx));
        pCellIdx -= 2;
        if (pc < contentOffset or pc > usableSize - 4) {
            checkAppendMsg(pCheck, "Offset %u out of range %u..%u", pc, contentOffset, usableSize - 4);
            doCoverageCheck = 0;
            continue;
        }
        pCell = data + @as(usize, @intCast(pc));
        pPage.?.xParseCell(pPage.?, pCell, &info);
        if (pc + info.nSize > usableSize) {
            checkAppendMsg(pCheck, "Extends off end of page");
            doCoverageCheck = 0;
            continue;
        }
        if (info.nPayload != 0 and info.pPayload.?[0] < 2) {
            checkAppendMsg(pCheck, "Bad cell header size");
            doCoverageCheck = 0;
            continue;
        }

        if (pPage.?.intKey != 0) {
            if (if (keyCanBeEqual != 0) (info.nKey > maxKey) else (info.nKey >= maxKey)) {
                checkAppendMsg(pCheck, "Rowid %lld out of order", info.nKey);
            }
            maxKey = info.nKey;
            keyCanBeEqual = 0;
        }

        if (info.nPayload > info.nLocal) {
            const nPage = (info.nPayload - info.nLocal + usableSize - 5) / (usableSize - 4);
            const pgnoOvfl = get4byte(pCell + info.nSize - 4);
            if (pBt.autoVacuum != 0) {
                checkPtrmap(pCheck, pgnoOvfl, PTRMAP_OVERFLOW1, iPage);
            }
            checkList(pCheck, 0, pgnoOvfl, nPage);
        }

        if (pPage.?.leaf == 0) {
            pgno = @bitCast(get4byte(pCell));
            if (pBt.autoVacuum != 0) {
                checkPtrmap(pCheck, @bitCast(pgno), PTRMAP_BTREE, iPage);
            }
            d2 = checkTreePage(pCheck, @bitCast(pgno), &maxKey, maxKey);
            keyCanBeEqual = 0;
            if (d2 != depth) {
                checkAppendMsg(pCheck, "Child page depth differs");
                depth = d2;
            }
        } else {
            btreeHeapInsert(heap.?, (pc << 16) | (pc + info.nSize - 1));
        }
    }
    piMinKey.* = maxKey;

    pCheck.zPfx = null;
    if (doCoverageCheck != 0 and pCheck.mxErr > 0) {
        if (pPage.?.leaf == 0) {
            heap = pCheck.heap;
            heap.?[0] = 0;
            i = nCell - 1;
            while (i >= 0) : (i -= 1) {
                pc = @intCast(get2byteAligned(data + @as(usize, @intCast(cellStart + i * 2))));
                const size: u32 = pPage.?.xCellSize(pPage.?, data + @as(usize, @intCast(pc)));
                btreeHeapInsert(heap.?, (pc << 16) | (pc + size - 1));
            }
        }
        i = get2byte(data + @as(usize, @intCast(hdr + 1)));
        while (i > 0) {
            const size = get2byte(data + @as(usize, @intCast(i + 2)));
            btreeHeapInsert(heap.?, (@as(u32, @intCast(i)) << 16) | @as(u32, @intCast(i + size - 1)));
            const j = get2byte(data + @as(usize, @intCast(i)));
            i = j;
        }
        nFrag = 0;
        prev = contentOffset - 1;
        while (btreeHeapPull(heap.?, &x)) {
            if ((prev & 0xffff) >= (x >> 16)) {
                checkAppendMsg(pCheck, "Multiple uses for byte %u of page %u", x >> 16, iPage);
                break;
            } else {
                nFrag += @as(c_int, @intCast(x >> 16)) - @as(c_int, @intCast(prev & 0xffff)) - 1;
                prev = x;
            }
        }
        nFrag += @as(c_int, @intCast(usableSize)) - @as(c_int, @intCast(prev & 0xffff)) - 1;
        if (heap.?[0] == 0 and nFrag != data[@intCast(hdr + 7)]) {
            checkAppendMsg(pCheck, "Fragmentation of %u bytes reported as %u on page %u", nFrag, data[@intCast(hdr + 7)], iPage);
        }
    }

    return checkTreeEnd(pCheck, pPage, doCoverageCheck, savedIsInit, saved_zPfx, saved_v1, saved_v2, depth);
}
fn checkTreeEnd(pCheck: *IntegrityCk, pPage: ?*MemPage, doCoverageCheck: c_int, savedIsInit: u8, saved_zPfx: ?[*:0]const u8, saved_v1: u32, saved_v2: c_int, depth: c_int) c_int {
    if (doCoverageCheck == 0 and pPage != null) pPage.?.isInit = savedIsInit;
    releasePage(pPage);
    pCheck.zPfx = saved_zPfx;
    pCheck.v1 = saved_v1;
    pCheck.v2 = saved_v2;
    return depth + 1;
}

export fn sqlite3BtreeIntegrityCheck(
    db: ?*sqlite3,
    p: *Btree,
    aRoot: [*]u32,
    aCnt: ?*sqlite3_value,
    nRoot: c_int,
    mxErr: c_int,
    pnErr: *c_int,
    pzOut: *?[*:0]u8,
) callconv(.c) c_int {
    var i: u32 = undefined;
    var sCheck: IntegrityCk = undefined;
    const pBt = p.pBt.?;
    const savedDbFlags = dbFlags(pBt.db);
    var zErr: [100]u8 = undefined;
    var bPartial: c_int = 0;
    var bCkFreelist: c_int = 1;

    if (aRoot[0] == 0) {
        bPartial = 1;
        if (aRoot[1] != 1) bCkFreelist = 0;
    }

    sqlite3BtreeEnter(p);
    @memset(std.mem.asBytes(&sCheck), 0);
    sCheck.db = db;
    sCheck.pBt = pBt;
    sCheck.pPager = pBt.pPager;
    sCheck.nCkPage = btreePagecount(pBt);
    sCheck.mxErr = mxErr;
    sqlite3StrAccumInit(@ptrCast(&sCheck.errMsg), null, &zErr, @sizeOf(@TypeOf(zErr)), SQLITE_MAX_LENGTH);
    // errMsg.printfFlags = SQLITE_PRINTF_INTERNAL (byte at offset 29)
    fieldPtr(u8, @as(*anyopaque, @ptrCast(&sCheck.errMsg)), 29).* = SQLITE_PRINTF_INTERNAL;
    if (sCheck.nCkPage == 0) {
        return integrityCkCleanup(&sCheck, p, pnErr, pzOut);
    }

    sCheck.aPgRef = @ptrCast(sqlite3MallocZero((sCheck.nCkPage / 8) + 1));
    if (sCheck.aPgRef == null) {
        checkOom(&sCheck);
        return integrityCkCleanup(&sCheck, p, pnErr, pzOut);
    }
    sCheck.heap = @ptrCast(@alignCast(sqlite3PageMalloc(@intCast(pBt.pageSize))));
    if (sCheck.heap == null) {
        checkOom(&sCheck);
        return integrityCkCleanup(&sCheck, p, pnErr, pzOut);
    }

    i = PENDING_BYTE_PAGE(pBt);
    if (i <= sCheck.nCkPage) setPageReferenced(&sCheck, i);

    if (bCkFreelist != 0) {
        sCheck.zPfx = "Freelist: ";
        checkList(&sCheck, 1, get4byte(pBt.pPage1.?.aData.? + 32), get4byte(pBt.pPage1.?.aData.? + 36));
        sCheck.zPfx = null;
    }

    if (bPartial == 0) {
        if (pBt.autoVacuum != 0) {
            var mx: u32 = 0;
            i = 0;
            while (i < nRoot) : (i += 1) {
                if (mx < aRoot[i]) mx = aRoot[i];
            }
            const mxInHdr = get4byte(pBt.pPage1.?.aData.? + 52);
            if (mx != mxInHdr) {
                checkAppendMsg(&sCheck, "max rootpage (%u) disagrees with header (%u)", mx, mxInHdr);
            }
        } else if (get4byte(pBt.pPage1.?.aData.? + 64) != 0) {
            checkAppendMsg(&sCheck, "incremental_vacuum enabled with a max rootpage of zero");
        }
    }
    dbFlagsPtr(pBt.db).* &= ~SQLITE_CellSizeCk;
    i = 0;
    while (i < nRoot and sCheck.mxErr != 0) : (i += 1) {
        sCheck.nRow = 0;
        if (aRoot[i] != 0) {
            var notUsed: i64 = undefined;
            if (pBt.autoVacuum != 0 and aRoot[i] > 1 and bPartial == 0) {
                checkPtrmap(&sCheck, aRoot[i], PTRMAP_ROOTPAGE, 0);
            }
            sCheck.v0 = aRoot[i];
            _ = checkTreePage(&sCheck, aRoot[i], &notUsed, LARGEST_INT64);
        }
        sqlite3MemSetArrayInt64(aCnt, @intCast(i), sCheck.nRow);
    }
    dbFlagsPtr(pBt.db).* = savedDbFlags;

    if (bPartial == 0) {
        i = 1;
        while (i <= sCheck.nCkPage and sCheck.mxErr != 0) : (i += 1) {
            if (!getPageReferenced(&sCheck, i) and (PTRMAP_PAGENO(pBt, i) != i or pBt.autoVacuum == 0)) {
                checkAppendMsg(&sCheck, "Page %u: never used", i);
            }
            if (getPageReferenced(&sCheck, i) and (PTRMAP_PAGENO(pBt, i) == i and pBt.autoVacuum != 0)) {
                checkAppendMsg(&sCheck, "Page %u: pointer map referenced", i);
            }
        }
    }

    return integrityCkCleanup(&sCheck, p, pnErr, pzOut);
}
fn integrityCkCleanup(sCheck: *IntegrityCk, p: *Btree, pnErr: *c_int, pzOut: *?[*:0]u8) c_int {
    sqlite3PageFree(sCheck.heap);
    sqlite3_free(sCheck.aPgRef);
    pnErr.* = sCheck.nErr;
    if (sCheck.nErr == 0) {
        sqlite3_str_reset(@ptrCast(&sCheck.errMsg));
        pzOut.* = null;
    } else {
        pzOut.* = sqlite3StrAccumFinish(@ptrCast(&sCheck.errMsg));
    }
    sqlite3BtreeLeave(p);
    return sCheck.rc;
}

// ════════════════════════════════════════════════════════════════════════════
// Misc tail accessors
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3BtreeGetFilename(p: *Btree) callconv(.c) ?[*:0]const u8 {
    return sqlite3PagerFilename(p.pBt.?.pPager, 1);
}
export fn sqlite3BtreeGetJournalname(p: *Btree) callconv(.c) ?[*:0]const u8 {
    return sqlite3PagerJournalname(p.pBt.?.pPager);
}
export fn sqlite3BtreeTxnState(p: ?*Btree) callconv(.c) c_int {
    return if (p) |bt| bt.inTrans else 0;
}
export fn sqlite3BtreeCheckpoint(p: ?*Btree, eMode: c_int, pnLog: ?*c_int, pnCkpt: ?*c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (p) |bt| {
        const pBt = bt.pBt.?;
        sqlite3BtreeEnter(bt);
        if (pBt.inTransaction != TRANS_NONE) {
            rc = SQLITE_LOCKED;
        } else {
            rc = sqlite3PagerCheckpoint(pBt.pPager, bt.db, eMode, pnLog, pnCkpt);
        }
        sqlite3BtreeLeave(bt);
    }
    return rc;
}
export fn sqlite3BtreeIsInBackup(p: *Btree) callconv(.c) c_int {
    return @intFromBool(p.nBackup != 0);
}
export fn sqlite3BtreeSchema(p: *Btree, nBytes: c_int, xFree: ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) ?*anyopaque {
    const pBt = p.pBt.?;
    sqlite3BtreeEnter(p);
    if (pBt.pSchema == null and nBytes != 0) {
        pBt.pSchema = sqlite3DbMallocZero(null, @intCast(nBytes));
        pBt.xFreeSchema = xFree;
    }
    sqlite3BtreeLeave(p);
    return pBt.pSchema;
}
export fn sqlite3BtreeSchemaLocked(p: *Btree) callconv(.c) c_int {
    sqlite3BtreeEnter(p);
    const rc = querySharedCacheTableLock(p, SCHEMA_ROOT, READ_LOCK);
    sqlite3BtreeLeave(p);
    return rc;
}
export fn sqlite3BtreeLockTable(p: *Btree, iTab: c_int, isWriteLock: u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (p.sharable != 0) {
        const lockType = READ_LOCK + isWriteLock;
        sqlite3BtreeEnter(p);
        rc = querySharedCacheTableLock(p, @intCast(iTab), lockType);
        if (rc == SQLITE_OK) {
            rc = setSharedCacheTableLock(p, @intCast(iTab), lockType);
        }
        sqlite3BtreeLeave(p);
    }
    return rc;
}
export fn sqlite3BtreePutData(pCsr: *BtCursor, offset: u32, amt: u32, z: ?*anyopaque) callconv(.c) c_int {
    const rc = restoreCursorPosition(pCsr);
    if (rc != SQLITE_OK) {
        return rc;
    }
    if (pCsr.eState != CURSOR_VALID) {
        return SQLITE_ABORT;
    }
    _ = saveAllCursors(pCsr.pBt.?, pCsr.pgnoRoot, pCsr);
    if ((pCsr.curFlags & BTCF_WriteFlag) == 0) {
        return SQLITE_READONLY;
    }
    return accessPayload(pCsr, offset, amt, @ptrCast(z.?), 1);
}
export fn sqlite3BtreeIncrblobCursor(pCur: *BtCursor) callconv(.c) void {
    pCur.curFlags |= BTCF_Incrblob;
    pCur.pBtree.?.hasIncrblobCur = 1;
}
export fn sqlite3BtreeSetVersion(pBtree: *Btree, iVersion: c_int) callconv(.c) c_int {
    const pBt = pBtree.pBt.?;
    pBt.btsFlags &= ~BTS_NO_WAL;
    if (iVersion == 1) pBt.btsFlags |= BTS_NO_WAL;
    var rc = sqlite3BtreeBeginTrans(pBtree, 0, null);
    if (rc == SQLITE_OK) {
        const aData = pBt.pPage1.?.aData.?;
        if (aData[18] != @as(u8, @intCast(iVersion)) or aData[19] != @as(u8, @intCast(iVersion))) {
            rc = sqlite3BtreeBeginTrans(pBtree, 2, null);
            if (rc == SQLITE_OK) {
                rc = sqlite3PagerWrite(pBt.pPage1.?.pDbPage);
                if (rc == SQLITE_OK) {
                    aData[18] = @intCast(iVersion);
                    aData[19] = @intCast(iVersion);
                }
            }
        }
    }
    pBt.btsFlags &= ~BTS_NO_WAL;
    return rc;
}
export fn sqlite3BtreeCursorHasHint(pCsr: *BtCursor, mask: c_uint) callconv(.c) c_int {
    return @intFromBool((pCsr.hints & mask) != 0);
}
export fn sqlite3BtreeIsReadonly(p: *Btree) callconv(.c) c_int {
    return @intFromBool((p.pBt.?.btsFlags & BTS_READ_ONLY) != 0);
}
export fn sqlite3HeaderSizeBtree() callconv(.c) c_int {
    return (@sizeOf(MemPage) + 7) & ~@as(c_int, 7);
}
export fn sqlite3BtreeClearCache(p: *Btree) callconv(.c) void {
    const pBt = p.pBt.?;
    if (pBt.inTransaction == TRANS_NONE) {
        sqlite3PagerClearCache(pBt.pPager);
    }
}
export fn sqlite3BtreeSharable(p: *Btree) callconv(.c) c_int {
    return p.sharable;
}
export fn sqlite3BtreeConnectionCount(p: *Btree) callconv(.c) c_int {
    return p.pBt.?.nRef;
}
