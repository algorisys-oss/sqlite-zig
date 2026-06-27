//! Zig port of SQLite's in-memory VFS (src/memdb.c).
//!
//! Implements the "memdb" VFS — the backend for shared in-memory databases
//! (`file:/name?vfs=memdb`) and the storage that `sqlite3_serialize()` /
//! `sqlite3_deserialize()` operate on. A database is held as one contiguous
//! block of heap memory.
//!
//! Compiled unconditionally in this build (SQLITE_OMIT_DESERIALIZE is not
//! defined). SQLITE_THREADSAFE=1 and SQLITE_MUTEX_OMIT is off, so the
//! memdbEnter/Leave helpers take a real per-store mutex. SQLITE_ENABLE_API_ARMOR
//! is off, so the safety-check guards in sqlite3_serialize/_deserialize are
//! compiled out — matching the C build.
//!
//! Coupling:
//!   * Public sqlite3.h ABI: sqlite3_vfs / sqlite3_file / sqlite3_io_methods.
//!     The MemVfs (`sqlite3_vfs`) and the io-methods table are replicated
//!     field-for-field, in the same order and with the same iVersion, as the
//!     C statics.
//!   * MemStore / MemFile are private to this module (no other TU reads them),
//!     so they are plain Zig extern structs — no c_layout offsets required.
//!   * Internal sqlite3 / Db fields (mutex, aDb[].zDbSName/.pBt, init.iDb,
//!     init.reopenMemdb bitfield) are read at ground-truth offsets via c_layout.
//!   * sqlite3GlobalConfig.mxMemdbSize is read at its ground-truth offset.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ── Result codes / constants (from sqlite.h.in) ────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_BUSY: c_int = 5;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_READONLY: c_int = 8;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_NOTFOUND: c_int = 12;
const SQLITE_FULL: c_int = 13;
const SQLITE_MISUSE: c_int = 21;
const SQLITE_IOERR: c_int = 10;
const SQLITE_IOERR_SHORT_READ: c_int = SQLITE_IOERR | (2 << 8);
const SQLITE_IOERR_WRITE: c_int = SQLITE_IOERR | (3 << 8);
const SQLITE_IOERR_NOMEM: c_int = SQLITE_IOERR | (12 << 8);

const SQLITE_LOCK_NONE: c_int = 0;
const SQLITE_LOCK_SHARED: c_int = 1;
const SQLITE_LOCK_RESERVED: c_int = 2;
const SQLITE_LOCK_PENDING: c_int = 3;
const SQLITE_LOCK_EXCLUSIVE: c_int = 4;

const SQLITE_OPEN_MEMORY: c_int = 0x00000080;

const SQLITE_IOCAP_ATOMIC: c_int = 0x00000001;
const SQLITE_IOCAP_SAFE_APPEND: c_int = 0x00000200;
const SQLITE_IOCAP_SEQUENTIAL: c_int = 0x00000400;
const SQLITE_IOCAP_POWERSAFE_OVERWRITE: c_int = 0x00001000;

const SQLITE_MUTEX_FAST: c_int = 0;
const SQLITE_MUTEX_STATIC_VFS1: c_int = 11;

const SQLITE_FCNTL_FILE_POINTER: c_int = 7;
const SQLITE_FCNTL_VFSNAME: c_int = 12;
const SQLITE_FCNTL_SIZE_LIMIT: c_int = 36;

const SQLITE_SERIALIZE_NOCOPY: c_uint = 0x001;
const SQLITE_DESERIALIZE_FREEONCLOSE: c_uint = 1;
const SQLITE_DESERIALIZE_RESIZEABLE: c_uint = 2;
const SQLITE_DESERIALIZE_READONLY: c_uint = 4;

const VoidFn = ?*const fn () callconv(.c) void;

// ── Public ABI structs (sqlite3.h) ─────────────────────────────────────────
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
    xFetch: ?*const fn (*Sqlite3File, i64, c_int, ?*anyopaque) callconv(.c) c_int,
    xUnfetch: ?*const fn (*Sqlite3File, i64, ?*anyopaque) callconv(.c) c_int,
};

const Sqlite3File = extern struct {
    pMethods: ?*const IoMethods,
};

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
    xDlOpen: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8) callconv(.c) ?*anyopaque,
    xDlError: ?*const fn (*Sqlite3Vfs, c_int, [*]u8) callconv(.c) void,
    xDlSym: ?*const fn (*Sqlite3Vfs, ?*anyopaque, ?[*:0]const u8) callconv(.c) VoidFn,
    xDlClose: ?*const fn (*Sqlite3Vfs, ?*anyopaque) callconv(.c) void,
    xRandomness: ?*const fn (*Sqlite3Vfs, c_int, [*]u8) callconv(.c) c_int,
    xSleep: ?*const fn (*Sqlite3Vfs, c_int) callconv(.c) c_int,
    xCurrentTime: ?*const fn (*Sqlite3Vfs, *f64) callconv(.c) c_int,
    xGetLastError: ?*const fn (*Sqlite3Vfs, c_int, ?[*]u8) callconv(.c) c_int,
    xCurrentTimeInt64: ?*const fn (*Sqlite3Vfs, *i64) callconv(.c) c_int,
    xSetSystemCall: ?*anyopaque,
    xGetSystemCall: ?*anyopaque,
    xNextSystemCall: ?*anyopaque,
};

// ── Private memdb objects ──────────────────────────────────────────────────
const MemStore = extern struct {
    sz: i64, // Size of the file
    szAlloc: i64, // Space allocated to aData
    szMax: i64, // Maximum allowed size of the file
    aData: ?[*]u8, // content of the file
    pMutex: ?*anyopaque, // Used by shared stores only
    nMmap: c_int, // Number of memory mapped pages
    mFlags: c_uint, // Flags
    nRdLock: c_int, // Number of readers
    nWrLock: c_int, // Number of writers. (Always 0 or 1)
    nRef: c_int, // Number of users of this MemStore
    zFName: ?[*:0]u8, // The filename for shared stores
};

const MemFile = extern struct {
    base: Sqlite3File, // IO methods
    pStore: *MemStore, // The storage
    eLock: c_int, // Most recent lock against this file
};

const MemFS = extern struct {
    nMemStore: c_int, // Number of shared MemStore objects
    apMemStore: ?[*]*MemStore, // Array of all shared MemStore objects
};

// File-scope shared-store registry. Mutated under SQLITE_MUTEX_STATIC_VFS1.
var memdb_g: MemFS = .{ .nMemStore = 0, .apMemStore = null };

// ── External C helpers (resolved at link time) ─────────────────────────────
extern fn sqlite3MutexAlloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_alloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3_mutex_free(m: ?*anyopaque) void;
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, buf: [*]u8, fmt: [*:0]const u8, ...) [*:0]u8;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn sqlite3_vfs_find(zVfs: ?[*:0]const u8) ?*Sqlite3Vfs;
extern fn sqlite3_vfs_register(pVfs: *Sqlite3Vfs, makeDflt: c_int) c_int;

extern fn sqlite3FindDbName(db: ?*anyopaque, zName: [*:0]const u8) c_int;
extern fn sqlite3_file_control(db: ?*anyopaque, zDbName: ?[*:0]const u8, op: c_int, pArg: ?*anyopaque) c_int;
extern fn sqlite3BtreeGetPageSize(pBt: ?*anyopaque) c_int;
extern fn sqlite3BtreePager(pBt: ?*anyopaque) ?*anyopaque;
extern fn sqlite3PagerGet(pPager: ?*anyopaque, pgno: u32, ppPage: *?*anyopaque, clrFlag: c_int) c_int;
extern fn sqlite3PagerGetData(pPage: ?*anyopaque) ?*anyopaque;
extern fn sqlite3PagerUnref(pPage: ?*anyopaque) void;

extern fn sqlite3_prepare_v2(db: ?*anyopaque, zSql: ?[*]const u8, nByte: c_int, ppStmt: *?*anyopaque, pzTail: ?*?[*]const u8) c_int;
extern fn sqlite3_step(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_reset(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_finalize(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_column_int(pStmt: ?*anyopaque, iCol: c_int) c_int;
extern fn sqlite3_column_int64(pStmt: ?*anyopaque, iCol: c_int) i64;
extern fn sqlite3_exec(db: ?*anyopaque, zSql: [*:0]const u8, cb: ?*anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;

const SQLITE_ROW: c_int = 100;

/// `sqlite3Config` global (SQLITE_OMIT_WSD off, so the `sqlite3GlobalConfig`
/// macro resolves to the literal `sqlite3Config`) — read mxMemdbSize at its
/// ground-truth offset. MUTABLE global, so `extern var` (PROGRESS optimizer-CSE note).
extern var sqlite3Config: u8;
inline fn mxMemdbSize() i64 {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    const p: *align(1) const i64 = @ptrCast(base + L.Sqlite3Config_mxMemdbSize);
    return p.*;
}

// ── sqlite3 / Db field accessors (ground-truth offsets via c_layout) ───────
inline fn byteBase(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rdPtr(comptime T: type, p: ?*anyopaque, off: usize) T {
    const q: *align(1) const T = @ptrCast(byteBase(p) + off);
    return q.*;
}
inline fn wrPtr(comptime T: type, p: ?*anyopaque, off: usize, v: T) void {
    const q: *align(1) T = @ptrCast(byteBase(p) + off);
    q.* = v;
}

/// db->mutex
inline fn dbMutex(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, L.sqlite3_mutex);
}
/// &db->aDb[iDb] — base pointer of the Db array element.
inline fn dbAt(db: ?*anyopaque, iDb: c_int) ?*anyopaque {
    const aDb = rdPtr(?*anyopaque, db, L.sqlite3_aDb) orelse return null;
    const p: [*]u8 = @ptrCast(aDb);
    return p + @as(usize, @intCast(iDb)) * L.sizeof_Db;
}
/// db->aDb[iDb].zDbSName
inline fn dbZDbSName(db: ?*anyopaque, iDb: c_int) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, dbAt(db, iDb), L.Db_zDbSName);
}
/// db->aDb[iDb].pBt
inline fn dbPBt(db: ?*anyopaque, iDb: c_int) ?*anyopaque {
    return rdPtr(?*anyopaque, dbAt(db, iDb), L.Db_pBt);
}
/// db->init.iDb
inline fn setInitIDb(db: ?*anyopaque, v: u8) void {
    byteBase(db)[L.sqlite3_init_iDb] = v;
}
/// db->init.reopenMemdb — bit 0x08 of the init bitfield byte (after iDb, busy):
/// orphanTrigger:1 (0x01), imposterTable:2 (0x06), reopenMemdb:1 (0x08).
inline fn setInitReopenMemdb(db: ?*anyopaque, on: bool) void {
    const b = byteBase(db) + L.sqlite3_init_bitbyte;
    if (on) {
        b[0] |= 0x08;
    } else {
        b[0] &= ~@as(u8, 0x08);
    }
}

// ── memdbEnter / memdbLeave ────────────────────────────────────────────────
// SQLITE_THREADSAFE=1, so these are the real-mutex variants.
inline fn memdbEnter(p: *MemStore) void {
    sqlite3_mutex_enter(p.pMutex);
}
inline fn memdbLeave(p: *MemStore) void {
    sqlite3_mutex_leave(p.pMutex);
}

// ── MemFile method table ───────────────────────────────────────────────────
const memdb_io_methods: IoMethods = .{
    .iVersion = 3,
    .xClose = memdbClose,
    .xRead = memdbRead,
    .xWrite = memdbWrite,
    .xTruncate = memdbTruncate,
    .xSync = memdbSync,
    .xFileSize = memdbFileSize,
    .xLock = memdbLock,
    .xUnlock = memdbUnlock,
    .xCheckReservedLock = null,
    .xFileControl = memdbFileControl,
    .xSectorSize = null,
    .xDeviceCharacteristics = memdbDeviceCharacteristics,
    .xShmMap = null,
    .xShmLock = null,
    .xShmBarrier = null,
    .xShmUnmap = null,
    .xFetch = memdbFetch,
    .xUnfetch = memdbUnfetch,
};

// ── MemVfs ─────────────────────────────────────────────────────────────────
// Mutated at registration (szOsFile, pAppData), so `var`, not `const`.
var memdb_vfs: Sqlite3Vfs = .{
    .iVersion = 2,
    .szOsFile = 0, // set when registered
    .mxPathname = 1024,
    .pNext = null,
    .zName = "memdb",
    .pAppData = null, // set when registered
    .xOpen = memdbOpen,
    .xDelete = null,
    .xAccess = memdbAccess,
    .xFullPathname = memdbFullPathname,
    .xDlOpen = memdbDlOpen,
    .xDlError = memdbDlError,
    .xDlSym = memdbDlSym,
    .xDlClose = memdbDlClose,
    .xRandomness = memdbRandomness,
    .xSleep = memdbSleep,
    .xCurrentTime = null,
    .xGetLastError = memdbGetLastError,
    .xCurrentTimeInt64 = memdbCurrentTimeInt64,
    .xSetSystemCall = null,
    .xGetSystemCall = null,
    .xNextSystemCall = null,
};

inline fn origVfs(p: *Sqlite3Vfs) *Sqlite3Vfs {
    return @ptrCast(@alignCast(p.pAppData.?));
}

inline fn asMemFile(pFile: *Sqlite3File) *MemFile {
    return @ptrCast(pFile);
}

// ── MemFile methods ────────────────────────────────────────────────────────

fn memdbClose(pFile: *Sqlite3File) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    if (p.zFName != null) {
        const pVfsMutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_VFS1);
        sqlite3_mutex_enter(pVfsMutex);
        var i: c_int = 0;
        const ap = memdb_g.apMemStore;
        while (i < memdb_g.nMemStore) : (i += 1) {
            if (ap.?[@intCast(i)] == p) {
                memdbEnter(p);
                if (p.nRef == 1) {
                    memdb_g.nMemStore -= 1;
                    ap.?[@intCast(i)] = ap.?[@intCast(memdb_g.nMemStore)];
                    if (memdb_g.nMemStore == 0) {
                        sqlite3_free(@ptrCast(memdb_g.apMemStore));
                        memdb_g.apMemStore = null;
                    }
                }
                break;
            }
        }
        sqlite3_mutex_leave(pVfsMutex);
    } else {
        memdbEnter(p);
    }
    p.nRef -= 1;
    if (p.nRef <= 0) {
        if ((p.mFlags & SQLITE_DESERIALIZE_FREEONCLOSE) != 0) {
            sqlite3_free(p.aData);
        }
        memdbLeave(p);
        sqlite3_mutex_free(p.pMutex);
        sqlite3_free(p);
    } else {
        memdbLeave(p);
    }
    return SQLITE_OK;
}

fn memdbRead(pFile: *Sqlite3File, zBuf: ?*anyopaque, iAmt: c_int, iOfst: i64) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    const out: [*]u8 = @ptrCast(zBuf.?);
    const amt: usize = @intCast(iAmt);
    memdbEnter(p);
    if (iOfst + iAmt > p.sz) {
        @memset(out[0..amt], 0);
        if (iOfst < p.sz) {
            const n: usize = @intCast(p.sz - iOfst);
            @memcpy(out[0..n], p.aData.?[@intCast(iOfst)..][0..n]);
        }
        memdbLeave(p);
        return SQLITE_IOERR_SHORT_READ;
    }
    @memcpy(out[0..amt], p.aData.?[@intCast(iOfst)..][0..amt]);
    memdbLeave(p);
    return SQLITE_OK;
}

/// Try to enlarge the memory allocation to hold at least newSz bytes.
fn memdbEnlarge(p: *MemStore, newSz_in: i64) c_int {
    var newSz = newSz_in;
    if ((p.mFlags & SQLITE_DESERIALIZE_RESIZEABLE) == 0 or p.nMmap > 0) {
        return SQLITE_FULL;
    }
    if (newSz > p.szMax) {
        return SQLITE_FULL;
    }
    newSz *= 2;
    if (newSz > p.szMax) newSz = p.szMax;
    const pNew = sqlite3Realloc(p.aData, @intCast(newSz));
    if (pNew == null) return SQLITE_IOERR_NOMEM;
    p.aData = @ptrCast(pNew);
    p.szAlloc = newSz;
    return SQLITE_OK;
}

fn memdbWrite(pFile: *Sqlite3File, z: ?*const anyopaque, iAmt: c_int, iOfst: i64) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    memdbEnter(p);
    if ((p.mFlags & SQLITE_DESERIALIZE_READONLY) != 0) {
        // Can't happen: memdbLock() returns SQLITE_READONLY first.
        memdbLeave(p);
        return SQLITE_IOERR_WRITE;
    }
    if (iOfst + iAmt > p.sz) {
        if (iOfst + iAmt > p.szAlloc) {
            const rc = memdbEnlarge(p, iOfst + iAmt);
            if (rc != SQLITE_OK) {
                memdbLeave(p);
                return rc;
            }
        }
        if (iOfst > p.sz) {
            const n: usize = @intCast(iOfst - p.sz);
            @memset(p.aData.?[@intCast(p.sz)..][0..n], 0);
        }
        p.sz = iOfst + iAmt;
    }
    const src: [*]const u8 = @ptrCast(z.?);
    const amt: usize = @intCast(iAmt);
    @memcpy(p.aData.?[@intCast(iOfst)..][0..amt], src[0..amt]);
    memdbLeave(p);
    return SQLITE_OK;
}

fn memdbTruncate(pFile: *Sqlite3File, size: i64) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    var rc: c_int = SQLITE_OK;
    memdbEnter(p);
    if (size > p.sz) {
        // This can only happen with a corrupt wal mode db
        rc = SQLITE_CORRUPT;
    } else {
        p.sz = size;
    }
    memdbLeave(p);
    return rc;
}

fn memdbSync(pFile: *Sqlite3File, flags: c_int) callconv(.c) c_int {
    _ = pFile;
    _ = flags;
    return SQLITE_OK;
}

fn memdbFileSize(pFile: *Sqlite3File, pSize: *i64) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    memdbEnter(p);
    pSize.* = p.sz;
    memdbLeave(p);
    return SQLITE_OK;
}

fn memdbLock(pFile: *Sqlite3File, eLock: c_int) callconv(.c) c_int {
    const pThis = asMemFile(pFile);
    const p = pThis.pStore;
    var rc: c_int = SQLITE_OK;
    if (eLock <= pThis.eLock) return SQLITE_OK;
    memdbEnter(p);

    if (config.sqlite_debug) {
        std.debug.assert(p.nWrLock == 0 or p.nWrLock == 1);
        std.debug.assert(pThis.eLock <= SQLITE_LOCK_SHARED or p.nWrLock == 1);
        std.debug.assert(pThis.eLock == SQLITE_LOCK_NONE or p.nRdLock >= 1);
    }

    if (eLock > SQLITE_LOCK_SHARED and (p.mFlags & SQLITE_DESERIALIZE_READONLY) != 0) {
        rc = SQLITE_READONLY;
    } else switch (eLock) {
        SQLITE_LOCK_SHARED => {
            if (config.sqlite_debug) std.debug.assert(pThis.eLock == SQLITE_LOCK_NONE);
            if (p.nWrLock > 0) {
                rc = SQLITE_BUSY;
            } else {
                p.nRdLock += 1;
            }
        },
        SQLITE_LOCK_RESERVED, SQLITE_LOCK_PENDING => {
            if (config.sqlite_debug) std.debug.assert(pThis.eLock >= SQLITE_LOCK_SHARED);
            if (pThis.eLock == SQLITE_LOCK_SHARED) {
                if (p.nWrLock > 0) {
                    rc = SQLITE_BUSY;
                } else {
                    p.nWrLock = 1;
                }
            }
        },
        else => {
            if (config.sqlite_debug) {
                std.debug.assert(eLock == SQLITE_LOCK_EXCLUSIVE);
                std.debug.assert(pThis.eLock >= SQLITE_LOCK_SHARED);
            }
            if (p.nRdLock > 1) {
                rc = SQLITE_BUSY;
            } else if (pThis.eLock == SQLITE_LOCK_SHARED) {
                p.nWrLock = 1;
            }
        },
    }
    if (rc == SQLITE_OK) pThis.eLock = eLock;
    memdbLeave(p);
    return rc;
}

fn memdbUnlock(pFile: *Sqlite3File, eLock: c_int) callconv(.c) c_int {
    const pThis = asMemFile(pFile);
    const p = pThis.pStore;
    if (eLock >= pThis.eLock) return SQLITE_OK;
    memdbEnter(p);

    if (config.sqlite_debug) {
        std.debug.assert(eLock == SQLITE_LOCK_SHARED or eLock == SQLITE_LOCK_NONE);
    }
    if (eLock == SQLITE_LOCK_SHARED) {
        if (pThis.eLock > SQLITE_LOCK_SHARED) {
            p.nWrLock -= 1;
        }
    } else {
        if (pThis.eLock > SQLITE_LOCK_SHARED) {
            p.nWrLock -= 1;
        }
        p.nRdLock -= 1;
    }

    pThis.eLock = eLock;
    memdbLeave(p);
    return SQLITE_OK;
}

fn memdbFileControl(pFile: *Sqlite3File, op: c_int, pArg: ?*anyopaque) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    var rc: c_int = SQLITE_NOTFOUND;
    memdbEnter(p);
    if (op == SQLITE_FCNTL_VFSNAME) {
        const out: *?[*:0]u8 = @ptrCast(@alignCast(pArg.?));
        out.* = sqlite3_mprintf("memdb(%p,%lld)", p.aData, p.sz);
        rc = SQLITE_OK;
    }
    if (op == SQLITE_FCNTL_SIZE_LIMIT) {
        const arg: *i64 = @ptrCast(@alignCast(pArg.?));
        var iLimit: i64 = arg.*;
        if (iLimit < p.sz) {
            if (iLimit < 0) {
                iLimit = p.szMax;
            } else {
                iLimit = p.sz;
            }
        }
        p.szMax = iLimit;
        arg.* = iLimit;
        rc = SQLITE_OK;
    }
    memdbLeave(p);
    return rc;
}

fn memdbDeviceCharacteristics(pFile: *Sqlite3File) callconv(.c) c_int {
    _ = pFile;
    return SQLITE_IOCAP_ATOMIC |
        SQLITE_IOCAP_POWERSAFE_OVERWRITE |
        SQLITE_IOCAP_SAFE_APPEND |
        SQLITE_IOCAP_SEQUENTIAL;
}

fn memdbFetch(pFile: *Sqlite3File, iOfst: i64, iAmt: c_int, pp: ?*anyopaque) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    const out: *?*anyopaque = @ptrCast(@alignCast(pp.?));
    memdbEnter(p);
    if (iOfst + iAmt > p.sz or (p.mFlags & SQLITE_DESERIALIZE_RESIZEABLE) != 0) {
        out.* = null;
    } else {
        p.nMmap += 1;
        out.* = @ptrCast(p.aData.?[@intCast(iOfst)..]);
    }
    memdbLeave(p);
    return SQLITE_OK;
}

fn memdbUnfetch(pFile: *Sqlite3File, iOfst: i64, pPage: ?*anyopaque) callconv(.c) c_int {
    const p = asMemFile(pFile).pStore;
    _ = iOfst;
    _ = pPage;
    memdbEnter(p);
    p.nMmap -= 1;
    memdbLeave(p);
    return SQLITE_OK;
}

// ── MemVfs methods ─────────────────────────────────────────────────────────

fn memdbOpen(
    pVfs: *Sqlite3Vfs,
    zName_in: ?[*:0]const u8,
    pFd: *Sqlite3File,
    flags: c_int,
    pOutFlags: ?*c_int,
) callconv(.c) c_int {
    _ = pVfs;
    const pFile = asMemFile(pFd);
    var p: ?*MemStore = null;
    const zName = zName_in;

    @memset(@as([*]u8, @ptrCast(pFile))[0..@sizeOf(MemFile)], 0);
    const szName = sqlite3Strlen30(zName);
    if (szName > 1 and zName != null and (zName.?[0] == '/' or zName.?[0] == '\\')) {
        const pVfsMutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_VFS1);
        sqlite3_mutex_enter(pVfsMutex);
        var i: c_int = 0;
        while (i < memdb_g.nMemStore) : (i += 1) {
            const cur = memdb_g.apMemStore.?[@intCast(i)];
            if (strcmp(cur.zFName.?, zName.?) == 0) {
                p = cur;
                break;
            }
        }
        if (p == null) {
            const np: ?*MemStore = @ptrCast(@alignCast(sqlite3Malloc(@sizeOf(MemStore) + @as(u64, @intCast(szName)) + 3)));
            if (np == null) {
                sqlite3_mutex_leave(pVfsMutex);
                return SQLITE_NOMEM;
            }
            const apNew: ?[*]*MemStore = @ptrCast(@alignCast(sqlite3Realloc(
                @ptrCast(memdb_g.apMemStore),
                @sizeOf(*MemStore) * (1 + @as(u64, @intCast(memdb_g.nMemStore))),
            )));
            if (apNew == null) {
                sqlite3_free(np);
                sqlite3_mutex_leave(pVfsMutex);
                return SQLITE_NOMEM;
            }
            apNew.?[@intCast(memdb_g.nMemStore)] = np.?;
            memdb_g.nMemStore += 1;
            memdb_g.apMemStore = apNew;
            @memset(@as([*]u8, @ptrCast(np.?))[0..@sizeOf(MemStore)], 0);
            const ps = np.?;
            ps.mFlags = SQLITE_DESERIALIZE_RESIZEABLE | SQLITE_DESERIALIZE_FREEONCLOSE;
            ps.szMax = mxMemdbSize();
            // zFName points just past the MemStore (the +szName+3 tail).
            const fnamePtr: [*]u8 = @as([*]u8, @ptrCast(np.?)) + @sizeOf(MemStore);
            ps.zFName = @ptrCast(fnamePtr);
            @memcpy(fnamePtr[0..@intCast(szName + 1)], @as([*]const u8, @ptrCast(zName.?))[0..@intCast(szName + 1)]);
            ps.pMutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
            if (ps.pMutex == null) {
                memdb_g.nMemStore -= 1;
                sqlite3_free(np);
                sqlite3_mutex_leave(pVfsMutex);
                return SQLITE_NOMEM;
            }
            ps.nRef = 1;
            memdbEnter(ps);
            p = ps;
        } else {
            memdbEnter(p.?);
            p.?.nRef += 1;
        }
        sqlite3_mutex_leave(pVfsMutex);
    } else {
        const np: ?*MemStore = @ptrCast(@alignCast(sqlite3Malloc(@sizeOf(MemStore))));
        if (np == null) {
            return SQLITE_NOMEM;
        }
        @memset(@as([*]u8, @ptrCast(np.?))[0..@sizeOf(MemStore)], 0);
        np.?.mFlags = SQLITE_DESERIALIZE_RESIZEABLE | SQLITE_DESERIALIZE_FREEONCLOSE;
        np.?.szMax = mxMemdbSize();
        p = np;
    }
    pFile.pStore = p.?;
    if (pOutFlags) |of| {
        of.* = flags | SQLITE_OPEN_MEMORY;
    }
    pFd.pMethods = &memdb_io_methods;
    memdbLeave(p.?);
    return SQLITE_OK;
}

fn memdbAccess(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8, flags: c_int, pResOut: *c_int) callconv(.c) c_int {
    _ = pVfs;
    _ = zPath;
    _ = flags;
    pResOut.* = 0;
    return SQLITE_OK;
}

fn memdbFullPathname(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8, nOut: c_int, zOut: [*]u8) callconv(.c) c_int {
    _ = pVfs;
    _ = sqlite3_snprintf(nOut, zOut, "%s", zPath.?);
    return SQLITE_OK;
}

fn memdbDlOpen(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const o = origVfs(pVfs);
    return o.xDlOpen.?(o, zPath);
}

fn memdbDlError(pVfs: *Sqlite3Vfs, nByte: c_int, zErrMsg: [*]u8) callconv(.c) void {
    const o = origVfs(pVfs);
    o.xDlError.?(o, nByte, zErrMsg);
}

fn memdbDlSym(pVfs: *Sqlite3Vfs, p: ?*anyopaque, zSym: ?[*:0]const u8) callconv(.c) VoidFn {
    const o = origVfs(pVfs);
    return o.xDlSym.?(o, p, zSym);
}

fn memdbDlClose(pVfs: *Sqlite3Vfs, pHandle: ?*anyopaque) callconv(.c) void {
    const o = origVfs(pVfs);
    o.xDlClose.?(o, pHandle);
}

fn memdbRandomness(pVfs: *Sqlite3Vfs, nByte: c_int, zBufOut: [*]u8) callconv(.c) c_int {
    const o = origVfs(pVfs);
    return o.xRandomness.?(o, nByte, zBufOut);
}

fn memdbSleep(pVfs: *Sqlite3Vfs, nMicro: c_int) callconv(.c) c_int {
    const o = origVfs(pVfs);
    return o.xSleep.?(o, nMicro);
}

fn memdbGetLastError(pVfs: *Sqlite3Vfs, a: c_int, b: ?[*]u8) callconv(.c) c_int {
    const o = origVfs(pVfs);
    return o.xGetLastError.?(o, a, b);
}

fn memdbCurrentTimeInt64(pVfs: *Sqlite3Vfs, p: *i64) callconv(.c) c_int {
    const o = origVfs(pVfs);
    return o.xCurrentTimeInt64.?(o, p);
}

/// Translate a database connection pointer and schema name into a MemFile.
fn memdbFromDbSchema(db: ?*anyopaque, zSchema: ?[*:0]const u8) ?*MemFile {
    var p: ?*MemFile = null;
    const rc = sqlite3_file_control(db, zSchema, SQLITE_FCNTL_FILE_POINTER, @ptrCast(&p));
    if (rc != 0) return null;
    const pf = p orelse return null;
    if (pf.base.pMethods != &memdb_io_methods) return null;
    const pStore = pf.pStore;
    memdbEnter(pStore);
    var ret: ?*MemFile = pf;
    if (pStore.zFName != null) ret = null;
    memdbLeave(pStore);
    return ret;
}

// ── Public API: sqlite3_serialize / sqlite3_deserialize ────────────────────

export fn sqlite3_serialize(
    db: ?*anyopaque,
    zSchema_in: ?[*:0]const u8,
    piSize: ?*i64,
    mFlags: c_uint,
) callconv(.c) ?[*]u8 {
    // SQLITE_ENABLE_API_ARMOR is off — no safety check here.
    var zSchema = zSchema_in;
    if (zSchema == null) zSchema = dbZDbSName(db, 0);
    const p = memdbFromDbSchema(db, zSchema);
    const iDb = sqlite3FindDbName(db, zSchema.?);
    if (piSize) |ps| ps.* = -1;
    if (iDb < 0) return null;
    if (p) |pf| {
        const pStore = pf.pStore;
        if (config.sqlite_debug) std.debug.assert(pStore.pMutex == null);
        if (piSize) |ps| ps.* = pStore.sz;
        var pOut: ?[*]u8 = null;
        if ((mFlags & SQLITE_SERIALIZE_NOCOPY) != 0) {
            pOut = pStore.aData;
        } else {
            pOut = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(pStore.sz))));
            if (pOut) |o| {
                const n: usize = @intCast(pStore.sz);
                @memcpy(o[0..n], pStore.aData.?[0..n]);
            }
        }
        return pOut;
    }
    const pBt = dbPBt(db, iDb) orelse return null;
    const szPage: i64 = sqlite3BtreeGetPageSize(pBt);
    const zSql = sqlite3_mprintf("PRAGMA \"%w\".page_count", zSchema.?);
    var pStmt: ?*anyopaque = null;
    var rc: c_int = if (zSql != null) sqlite3_prepare_v2(db, @ptrCast(zSql), -1, &pStmt, null) else SQLITE_NOMEM;
    sqlite3_free(zSql);
    if (rc != 0) return null;
    var pOut: ?[*]u8 = null;
    rc = sqlite3_step(pStmt);
    if (rc != SQLITE_ROW) {
        pOut = null;
    } else {
        var sz: i64 = sqlite3_column_int64(pStmt, 0) * szPage;
        if (sz == 0) {
            _ = sqlite3_reset(pStmt);
            _ = sqlite3_exec(db, "BEGIN IMMEDIATE; COMMIT;", null, null, null);
            rc = sqlite3_step(pStmt);
            if (rc == SQLITE_ROW) {
                sz = sqlite3_column_int64(pStmt, 0) * szPage;
            }
        }
        if (piSize) |ps| ps.* = sz;
        if ((mFlags & SQLITE_SERIALIZE_NOCOPY) != 0) {
            pOut = null;
        } else {
            pOut = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(sz))));
            if (pOut) |o| {
                const nPage = sqlite3_column_int(pStmt, 0);
                const pPager = sqlite3BtreePager(pBt);
                var pgno: c_int = 1;
                while (pgno <= nPage) : (pgno += 1) {
                    var pPage: ?*anyopaque = null;
                    const pTo = o + @as(usize, @intCast(szPage)) * @as(usize, @intCast(pgno - 1));
                    rc = sqlite3PagerGet(pPager, @intCast(pgno), &pPage, 0);
                    if (rc == SQLITE_OK) {
                        const data: [*]const u8 = @ptrCast(sqlite3PagerGetData(pPage).?);
                        @memcpy(pTo[0..@intCast(szPage)], data[0..@intCast(szPage)]);
                    } else {
                        @memset(pTo[0..@intCast(szPage)], 0);
                    }
                    sqlite3PagerUnref(pPage);
                }
            }
        }
    }
    _ = sqlite3_finalize(pStmt);
    return pOut;
}

export fn sqlite3_deserialize(
    db: ?*anyopaque,
    zSchema_in: ?[*:0]const u8,
    pData_in: ?[*]u8,
    szDb: i64,
    szBuf: i64,
    mFlags: c_uint,
) callconv(.c) c_int {
    // SQLITE_ENABLE_API_ARMOR is off — no safety check here.
    var pData = pData_in;
    var rc: c_int = SQLITE_OK;

    sqlite3_mutex_enter(dbMutex(db));
    var zSchema = zSchema_in;
    if (zSchema == null) zSchema = dbZDbSName(db, 0);
    const iDb = sqlite3FindDbName(db, zSchema.?);
    // testcase( iDb==1 );
    if (iDb < 2 and iDb != 0) {
        rc = SQLITE_ERROR;
    } else {
        const zSql = sqlite3_mprintf("ATTACH x AS %Q", zSchema.?);
        var pStmt: ?*anyopaque = null;
        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3_prepare_v2(db, @ptrCast(zSql), -1, &pStmt, null);
            sqlite3_free(zSql);
        }
        if (rc == 0) {
            setInitIDb(db, @truncate(@as(u32, @bitCast(iDb))));
            setInitReopenMemdb(db, true);
            _ = sqlite3_step(pStmt);
            setInitReopenMemdb(db, false);
            rc = sqlite3_finalize(pStmt);
            if (rc == SQLITE_OK) {
                const p = memdbFromDbSchema(db, zSchema);
                if (p == null) {
                    rc = SQLITE_ERROR;
                } else {
                    const pStore = p.?.pStore;
                    pStore.aData = pData;
                    pData = null;
                    pStore.sz = szDb;
                    pStore.szAlloc = szBuf;
                    pStore.szMax = szBuf;
                    if (pStore.szMax < mxMemdbSize()) {
                        pStore.szMax = mxMemdbSize();
                    }
                    pStore.mFlags = mFlags;
                    rc = SQLITE_OK;
                }
            }
        }
    }

    // end_deserialize:
    if (pData != null and (mFlags & SQLITE_DESERIALIZE_FREEONCLOSE) != 0) {
        sqlite3_free(pData);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

/// Return true if the VFS is the memvfs.
export fn sqlite3IsMemdb(pVfs: ?*const Sqlite3Vfs) callconv(.c) c_int {
    return @intFromBool(pVfs == &memdb_vfs);
}

/// Called when the extension is loaded — registers the memdb VFS.
export fn sqlite3MemdbInit() callconv(.c) c_int {
    const pLower = sqlite3_vfs_find(null) orelse return SQLITE_ERROR;
    var sz: c_uint = @bitCast(pLower.szOsFile);
    memdb_vfs.pAppData = pLower;
    // Only reachable on Windows x86 with SQLITE_MAX_MMAP_SIZE=0; left in to be safe.
    if (sz < @sizeOf(MemFile)) sz = @sizeOf(MemFile);
    memdb_vfs.szOsFile = @bitCast(sz);
    return sqlite3_vfs_register(&memdb_vfs, 0);
}
