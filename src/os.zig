//! Zig port of SQLite's architecture-independent OS interface (src/os.c).
//!
//! Drop-in replacement for the `sqlite3Os*` convenience wrappers around the
//! `sqlite3_file`/`sqlite3_vfs` method tables, plus the VFS registry
//! (`sqlite3_vfs_find`/`register`/`unregister`). These are thin dispatchers; the
//! real I/O lives in os_unix.c (still C), reached through the public method
//! pointers.
//!
//! Coupling is to the **public** sqlite3.h ABI (sqlite3_file / sqlite3_io_methods
//! / sqlite3_vfs) plus one internal field, `sqlite3Config.iPrngSeed`, read at its
//! ground-truth (config-invariant) offset. The SQLITE_TEST fault-injection state
//! (the `sqlite3_io_error_*` counters and `DO_OS_MALLOC_TEST`) is gated on
//! `config.sqlite_test`, so it exists/runs only in the testfixture build —
//! exactly as the C -DSQLITE_TEST does.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT
const SQLITE_NOTFOUND: c_int = 12;
const SQLITE_IOERR_NOMEM: c_int = 10 | (12 << 8); // SQLITE_IOERR_NOMEM_BKPT
const SQLITE_LOCK_SHARED: c_int = 1;
const SQLITE_LOCK_EXCLUSIVE: c_int = 4;
const SQLITE_DEFAULT_SECTOR_SIZE: c_int = 4096;
const SQLITE_MUTEX_STATIC_MAIN: c_int = 2;
const SQLITE_FCNTL_COMMIT_PHASETWO: c_int = 22;
const SQLITE_FCNTL_LOCK_TIMEOUT: c_int = 34;
const SQLITE_FCNTL_CKPT_DONE: c_int = 37;
const SQLITE_FCNTL_CKPT_START: c_int = 39;

const VoidFn = ?*const fn () callconv(.c) void;

// --- Public ABI structs (sqlite3.h) ---

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
    // v3 methods — never called here.
    xSetSystemCall: ?*const anyopaque,
    xGetSystemCall: ?*const anyopaque,
    xNextSystemCall: ?*const anyopaque,
};

// --- C helpers resolved at link time ---
extern fn sqlite3_initialize() c_int;
extern fn sqlite3MutexAlloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3JournalIsInMemory(p: *Sqlite3File) c_int;
extern fn sqlite3RealToI64(r: f64) i64;
extern fn sqlite3_os_init() c_int;
extern fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;

/// `sqlite3Config` global; we read only `iPrngSeed` (config-invariant offset).
extern var sqlite3Config: u8;  // mutable global — see pcache.zig note
inline fn prngSeed() u32 {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    const p4: *const [4]u8 = @ptrCast(base + L.Sqlite3Config_iPrngSeed);
    return std.mem.readInt(u32, p4, .little);
}

// --- SQLITE_TEST instrumentation (only in the testfixture build) ---
// Backing storage always exists; the symbols are exported only when
// config.sqlite_test, matching C's -DSQLITE_TEST. os_unix.c / the TCL harness
// reference these by name in that build.
var io_error_hit: c_int = 0;
var io_error_hardhit: c_int = 0;
var io_error_pending: c_int = 0;
var io_error_persist: c_int = 0;
var io_error_benign: c_int = 0;
var diskfull_pending: c_int = 0;
var diskfull: c_int = 0;
var open_file_count: c_int = 0;
var memdebug_vfs_oom_test: c_int = 1;

comptime {
    if (config.sqlite_test) {
        @export(&io_error_hit, .{ .name = "sqlite3_io_error_hit" });
        @export(&io_error_hardhit, .{ .name = "sqlite3_io_error_hardhit" });
        @export(&io_error_pending, .{ .name = "sqlite3_io_error_pending" });
        @export(&io_error_persist, .{ .name = "sqlite3_io_error_persist" });
        @export(&io_error_benign, .{ .name = "sqlite3_io_error_benign" });
        @export(&diskfull_pending, .{ .name = "sqlite3_diskfull_pending" });
        @export(&diskfull, .{ .name = "sqlite3_diskfull" });
        @export(&open_file_count, .{ .name = "sqlite3_open_file_count" });
        @export(&memdebug_vfs_oom_test, .{ .name = "sqlite3_memdebug_vfs_oom_test" });
    }
}

/// DO_OS_MALLOC_TEST: in the testfixture build, optionally inject an OOM before
/// a VFS call so the failure paths get exercised. Returns an error code to
/// propagate, or null to continue. Compiles away entirely in production.
inline fn doOsMallocTest(x: ?*Sqlite3File) ?c_int {
    if (!config.sqlite_test) return null;
    if (memdebug_vfs_oom_test != 0 and (x == null or sqlite3JournalIsInMemory(x.?) == 0)) {
        const p = sqlite3Malloc(10);
        if (p == null) return SQLITE_IOERR_NOMEM;
        sqlite3_free(p);
    }
    return null;
}

// --- sqlite3_file method wrappers ---

export fn sqlite3OsClose(pId: *Sqlite3File) callconv(.c) void {
    if (pId.pMethods) |m| {
        _ = m.xClose.?(pId);
        pId.pMethods = null;
    }
}
export fn sqlite3OsRead(id: *Sqlite3File, pBuf: ?*anyopaque, amt: c_int, offset: i64) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return id.pMethods.?.xRead.?(id, pBuf, amt, offset);
}
export fn sqlite3OsWrite(id: *Sqlite3File, pBuf: ?*const anyopaque, amt: c_int, offset: i64) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return id.pMethods.?.xWrite.?(id, pBuf, amt, offset);
}
export fn sqlite3OsTruncate(id: *Sqlite3File, size: i64) callconv(.c) c_int {
    return id.pMethods.?.xTruncate.?(id, size);
}
export fn sqlite3OsSync(id: *Sqlite3File, flags: c_int) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return if (flags != 0) id.pMethods.?.xSync.?(id, flags) else SQLITE_OK;
}
export fn sqlite3OsFileSize(id: *Sqlite3File, pSize: *i64) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return id.pMethods.?.xFileSize.?(id, pSize);
}
export fn sqlite3OsLock(id: *Sqlite3File, lockType: c_int) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return id.pMethods.?.xLock.?(id, lockType);
}
export fn sqlite3OsUnlock(id: *Sqlite3File, lockType: c_int) callconv(.c) c_int {
    return id.pMethods.?.xUnlock.?(id, lockType);
}
export fn sqlite3OsCheckReservedLock(id: *Sqlite3File, pResOut: *c_int) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return id.pMethods.?.xCheckReservedLock.?(id, pResOut);
}
export fn sqlite3OsFileControl(id: *Sqlite3File, op: c_int, pArg: ?*anyopaque) callconv(.c) c_int {
    if (id.pMethods == null) return SQLITE_NOTFOUND;
    if (config.sqlite_test) {
        if (op != SQLITE_FCNTL_COMMIT_PHASETWO and op != SQLITE_FCNTL_LOCK_TIMEOUT and
            op != SQLITE_FCNTL_CKPT_DONE and op != SQLITE_FCNTL_CKPT_START)
        {
            if (doOsMallocTest(id)) |rc| return rc;
        }
    }
    return id.pMethods.?.xFileControl.?(id, op, pArg);
}
export fn sqlite3OsFileControlHint(id: *Sqlite3File, op: c_int, pArg: ?*anyopaque) callconv(.c) void {
    if (id.pMethods) |m| _ = m.xFileControl.?(id, op, pArg);
}
export fn sqlite3OsSectorSize(id: *Sqlite3File) callconv(.c) c_int {
    if (id.pMethods.?.xSectorSize) |f| return f(id);
    return SQLITE_DEFAULT_SECTOR_SIZE;
}
export fn sqlite3OsDeviceCharacteristics(id: *Sqlite3File) callconv(.c) c_int {
    return id.pMethods.?.xDeviceCharacteristics.?(id);
}
export fn sqlite3OsShmLock(id: *Sqlite3File, offset: c_int, n: c_int, flags: c_int) callconv(.c) c_int {
    return id.pMethods.?.xShmLock.?(id, offset, n, flags);
}
export fn sqlite3OsShmBarrier(id: *Sqlite3File) callconv(.c) void {
    id.pMethods.?.xShmBarrier.?(id);
}
export fn sqlite3OsShmUnmap(id: *Sqlite3File, deleteFlag: c_int) callconv(.c) c_int {
    return id.pMethods.?.xShmUnmap.?(id, deleteFlag);
}
export fn sqlite3OsShmMap(id: *Sqlite3File, iPage: c_int, pgsz: c_int, bExtend: c_int, pp: ?*anyopaque) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return id.pMethods.?.xShmMap.?(id, iPage, pgsz, bExtend, pp);
}
// SQLITE_MAX_MMAP_SIZE > 0 on this target, so xFetch/xUnfetch dispatch for real.
export fn sqlite3OsFetch(id: *Sqlite3File, iOff: i64, iAmt: c_int, pp: ?*anyopaque) callconv(.c) c_int {
    if (doOsMallocTest(id)) |rc| return rc;
    return id.pMethods.?.xFetch.?(id, iOff, iAmt, pp);
}
export fn sqlite3OsUnfetch(id: *Sqlite3File, iOff: i64, p: ?*anyopaque) callconv(.c) c_int {
    return id.pMethods.?.xUnfetch.?(id, iOff, p);
}

// --- sqlite3_vfs method wrappers ---

export fn sqlite3OsOpen(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8, pFile: *Sqlite3File, flags: c_int, pFlagsOut: ?*c_int) callconv(.c) c_int {
    if (doOsMallocTest(null)) |rc| return rc;
    // 0x1087f7f masks the SQLITE_OPEN_ flags valid to pass down to the VFS.
    return pVfs.xOpen.?(pVfs, zPath, pFile, flags & 0x1087f7f, pFlagsOut);
}
export fn sqlite3OsDelete(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8, dirSync: c_int) callconv(.c) c_int {
    if (doOsMallocTest(null)) |rc| return rc;
    return if (pVfs.xDelete) |f| f(pVfs, zPath, dirSync) else SQLITE_OK;
}
export fn sqlite3OsAccess(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8, flags: c_int, pResOut: *c_int) callconv(.c) c_int {
    if (doOsMallocTest(null)) |rc| return rc;
    return pVfs.xAccess.?(pVfs, zPath, flags, pResOut);
}
export fn sqlite3OsFullPathname(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8, nPathOut: c_int, zPathOut: [*]u8) callconv(.c) c_int {
    if (doOsMallocTest(null)) |rc| return rc;
    zPathOut[0] = 0;
    return pVfs.xFullPathname.?(pVfs, zPath, nPathOut, zPathOut);
}
export fn sqlite3OsDlOpen(pVfs: *Sqlite3Vfs, zPath: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    return pVfs.xDlOpen.?(pVfs, zPath);
}
export fn sqlite3OsDlError(pVfs: *Sqlite3Vfs, nByte: c_int, zBufOut: [*]u8) callconv(.c) void {
    pVfs.xDlError.?(pVfs, nByte, zBufOut);
}
export fn sqlite3OsDlSym(pVfs: *Sqlite3Vfs, pHdle: ?*anyopaque, zSym: ?[*:0]const u8) callconv(.c) VoidFn {
    return pVfs.xDlSym.?(pVfs, pHdle, zSym);
}
export fn sqlite3OsDlClose(pVfs: *Sqlite3Vfs, pHandle: ?*anyopaque) callconv(.c) void {
    pVfs.xDlClose.?(pVfs, pHandle);
}
export fn sqlite3OsRandomness(pVfs: *Sqlite3Vfs, nByte_in: c_int, zBufOut: [*]u8) callconv(.c) c_int {
    const seed = prngSeed();
    if (seed != 0) {
        var nByte = nByte_in;
        @memset(zBufOut[0..@intCast(nByte)], 0);
        if (nByte > @as(c_int, @sizeOf(c_uint))) nByte = @sizeOf(c_uint);
        const sb = std.mem.asBytes(&seed);
        @memcpy(zBufOut[0..@intCast(nByte)], sb[0..@intCast(nByte)]);
        return SQLITE_OK;
    }
    return pVfs.xRandomness.?(pVfs, nByte_in, zBufOut);
}
export fn sqlite3OsSleep(pVfs: *Sqlite3Vfs, nMicro: c_int) callconv(.c) c_int {
    return pVfs.xSleep.?(pVfs, nMicro);
}
export fn sqlite3OsGetLastError(pVfs: *Sqlite3Vfs) callconv(.c) c_int {
    return if (pVfs.xGetLastError) |f| f(pVfs, 0, null) else 0;
}
export fn sqlite3OsCurrentTimeInt64(pVfs: *Sqlite3Vfs, pTimeOut: *i64) callconv(.c) c_int {
    if (pVfs.iVersion >= 2 and pVfs.xCurrentTimeInt64 != null) {
        return pVfs.xCurrentTimeInt64.?(pVfs, pTimeOut);
    }
    var r: f64 = undefined;
    const rc = pVfs.xCurrentTime.?(pVfs, &r);
    pTimeOut.* = sqlite3RealToI64(r * 86400000.0);
    return rc;
}

export fn sqlite3OsOpenMalloc(pVfs: *Sqlite3Vfs, zFile: ?[*:0]const u8, ppFile: *?*Sqlite3File, flags: c_int, pOutFlags: ?*c_int) callconv(.c) c_int {
    const pFile: ?*Sqlite3File = @ptrCast(@alignCast(sqlite3MallocZero(@intCast(pVfs.szOsFile))));
    if (pFile) |f| {
        const rc = sqlite3OsOpen(pVfs, zFile, f, flags, pOutFlags);
        if (rc != SQLITE_OK) {
            sqlite3_free(f);
            ppFile.* = null;
        } else {
            ppFile.* = f;
        }
        return rc;
    }
    ppFile.* = null;
    return SQLITE_NOMEM;
}
export fn sqlite3OsCloseFree(pFile: *Sqlite3File) callconv(.c) void {
    sqlite3OsClose(pFile);
    sqlite3_free(pFile);
}

/// Wrapper around sqlite3_os_init() that can simulate a malloc failure.
export fn sqlite3OsInit() callconv(.c) c_int {
    const p = sqlite3_malloc(10);
    if (p == null) return SQLITE_NOMEM;
    sqlite3_free(p);
    return sqlite3_os_init();
}

// --- VFS registry ---
var vfsList: ?*Sqlite3Vfs = null;

export fn sqlite3_vfs_find(zVfs: ?[*:0]const u8) callconv(.c) ?*Sqlite3Vfs {
    // SQLITE_OMIT_AUTOINIT is off.
    if (sqlite3_initialize() != 0) return null;
    const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
    sqlite3_mutex_enter(mutex);
    var pVfs = vfsList;
    while (pVfs) |v| {
        if (zVfs == null) break;
        if (strcmp(zVfs.?, v.zName.?) == 0) break;
        pVfs = v.pNext;
    }
    sqlite3_mutex_leave(mutex);
    return pVfs;
}

fn vfsUnlink(pVfs: ?*Sqlite3Vfs) void {
    const target = pVfs orelse return; // pVfs==0 is a no-op, matching C
    if (vfsList == target) {
        vfsList = target.pNext;
    } else if (vfsList) |first| {
        var p = first;
        while (p.pNext != null and p.pNext != target) p = p.pNext.?;
        if (p.pNext == target) p.pNext = target.pNext;
    }
}

export fn sqlite3_vfs_register(pVfs_in: ?*Sqlite3Vfs, makeDflt: c_int) callconv(.c) c_int {
    const rc = sqlite3_initialize();
    if (rc != 0) return rc;
    // SQLITE_ENABLE_API_ARMOR is off, so (as in C) pVfs is assumed non-null here.
    const pVfs = pVfs_in.?;
    const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
    sqlite3_mutex_enter(mutex);
    vfsUnlink(pVfs);
    if (makeDflt != 0 or vfsList == null) {
        pVfs.pNext = vfsList;
        vfsList = pVfs;
    } else {
        pVfs.pNext = vfsList.?.pNext;
        vfsList.?.pNext = pVfs;
    }
    sqlite3_mutex_leave(mutex);
    return SQLITE_OK;
}

export fn sqlite3_vfs_unregister(pVfs: ?*Sqlite3Vfs) callconv(.c) c_int {
    const rc = sqlite3_initialize();
    if (rc != 0) return rc;
    const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
    sqlite3_mutex_enter(mutex);
    vfsUnlink(pVfs);
    sqlite3_mutex_leave(mutex);
    return SQLITE_OK;
}
