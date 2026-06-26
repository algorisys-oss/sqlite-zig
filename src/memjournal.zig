//! Zig port of SQLite's in-memory rollback journal (src/memjournal.c).
//!
//! Drop-in replacement exporting `sqlite3JournalOpen`, `sqlite3MemJournalOpen`,
//! `sqlite3JournalIsInMemory`, `sqlite3JournalSize`. Implements a `sqlite3_file`
//! subclass that buffers journal content in a linked list of fixed-size chunks
//! and (when a positive spill threshold is exceeded) flushes to a real file via
//! the underlying VFS.
//!
//! Coupling is config-invariant: the `MemJournal`/`FileChunk`/`FilePoint`
//! structs are opaque (defined only here — callers hold a `sqlite3_file*`), and
//! everything else is the **public** sqlite3.h ABI (`sqlite3_file`,
//! `sqlite3_io_methods`, `sqlite3_vfs`) plus the `sqlite3Os*` wrappers. So the
//! one Zig object is correct in both the production and testfixture builds.
//!
//! `sqlite3JournalCreate` is gated behind SQLITE_ENABLE_ATOMIC_WRITE /
//! BATCH_ATOMIC_WRITE, which are off in both this project's builds, so it (and
//! its callers in pager.c) are not compiled — we do not export it.

const std = @import("std");

const SQLITE_OK: c_int = 0;
const SQLITE_IOERR_SHORT_READ: c_int = 10 | (2 << 8); // 522
const SQLITE_IOERR_NOMEM: c_int = 10 | (12 << 8); // 3082 (SQLITE_IOERR_NOMEM_BKPT in prod)
const MEMJOURNAL_DFLT_FILECHUNKSIZE: c_int = 1024;

// --- Public ABI structs (sqlite3.h) ---

const Sqlite3File = extern struct {
    pMethods: ?*const IoMethods,
};

/// Prefix of sqlite3_vfs — we only read `szOsFile` (offset 4). The pointer
/// always refers to a full sqlite3_vfs, and we never take its sizeof, so a
/// prefix mirror is safe.
const Sqlite3Vfs = extern struct {
    iVersion: c_int,
    szOsFile: c_int,
};

const IoMethods = extern struct {
    iVersion: c_int,
    xClose: ?*const fn (*Sqlite3File) callconv(.c) c_int,
    xRead: ?*const fn (*Sqlite3File, ?*anyopaque, c_int, i64) callconv(.c) c_int,
    xWrite: ?*const fn (*Sqlite3File, ?*const anyopaque, c_int, i64) callconv(.c) c_int,
    xTruncate: ?*const fn (*Sqlite3File, i64) callconv(.c) c_int,
    xSync: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xFileSize: ?*const fn (*Sqlite3File, *i64) callconv(.c) c_int,
    // Remaining v1/v2/v3 methods are unused by the in-memory journal (the pager
    // never locks/shm/fetches a journal file), so they stay null.
    xLock: ?*const anyopaque,
    xUnlock: ?*const anyopaque,
    xCheckReservedLock: ?*const anyopaque,
    xFileControl: ?*const anyopaque,
    xSectorSize: ?*const anyopaque,
    xDeviceCharacteristics: ?*const anyopaque,
    xShmMap: ?*const anyopaque,
    xShmLock: ?*const anyopaque,
    xShmBarrier: ?*const anyopaque,
    xShmUnmap: ?*const anyopaque,
    xFetch: ?*const anyopaque,
    xUnfetch: ?*const anyopaque,
};

// --- Internal (opaque) structures ---

const FileChunk = extern struct {
    pNext: ?*FileChunk,
    zChunk: [8]u8, // actually nChunkSize bytes; allocated via fileChunkSize()
};

const FilePoint = extern struct {
    iOffset: i64,
    pChunk: ?*FileChunk,
};

const MemJournal = extern struct {
    pMethod: ?*const IoMethods, // parent class — MUST BE FIRST
    nChunkSize: c_int,
    nSpill: c_int,
    pFirst: ?*FileChunk,
    endpoint: FilePoint,
    readpoint: FilePoint,
    flags: c_int,
    pVfs: ?*anyopaque, // sqlite3_vfs*
    zJournal: ?[*:0]const u8,
};

comptime {
    std.debug.assert(@sizeOf(FileChunk) == 16);
    std.debug.assert(MEMJOURNAL_DFLT_FILECHUNKSIZE == fileChunkSize(8 + MEMJOURNAL_DFLT_FILECHUNKSIZE - @sizeOf(FileChunk)));
}

/// Bytes to allocate per FileChunk for a given chunk size.
inline fn fileChunkSize(nChunkSize: c_int) c_int {
    return @as(c_int, @sizeOf(FileChunk)) + (nChunkSize - 8);
}

/// View a FileChunk's payload as an unbounded byte pointer (the real allocation
/// is nChunkSize bytes, larger than the declared zChunk[8]).
inline fn chunkBytes(p: *FileChunk) [*]u8 {
    return @ptrCast(&p.zChunk);
}

// --- C helpers resolved at link time ---
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3OsOpen(pVfs: ?*anyopaque, zName: ?[*:0]const u8, pFile: *Sqlite3File, flags: c_int, pFlagsOut: ?*c_int) c_int;
extern fn sqlite3OsWrite(pFile: *Sqlite3File, buf: ?*const anyopaque, amt: c_int, offset: i64) c_int;
extern fn sqlite3OsClose(pFile: *Sqlite3File) void;

/// xRead: read from the in-memory journal.
fn memjrnlRead(pJfd: *Sqlite3File, zBuf: ?*anyopaque, iAmt: c_int, iOfst: i64) callconv(.c) c_int {
    const p: *MemJournal = @ptrCast(pJfd);
    var zOut: [*]u8 = @ptrCast(zBuf.?);
    var nRead = iAmt;
    var pChunk: ?*FileChunk = undefined;

    if (@as(i64, iAmt) + iOfst > p.endpoint.iOffset) {
        return SQLITE_IOERR_SHORT_READ;
    }
    if (p.readpoint.iOffset != iOfst or iOfst == 0) {
        var iOff: i64 = 0;
        pChunk = p.pFirst;
        while (pChunk != null and (iOff + @as(i64, p.nChunkSize)) <= iOfst) {
            iOff += @as(i64, p.nChunkSize);
            pChunk = pChunk.?.pNext;
        }
    } else {
        pChunk = p.readpoint.pChunk;
    }

    var iChunkOffset: c_int = @intCast(@mod(iOfst, @as(i64, p.nChunkSize)));
    while (true) {
        const iSpace = p.nChunkSize - iChunkOffset;
        const nCopy = @min(nRead, p.nChunkSize - iChunkOffset);
        const src = chunkBytes(pChunk.?) + @as(usize, @intCast(iChunkOffset));
        const n: usize = @intCast(nCopy);
        @memcpy(zOut[0..n], src[0..n]);
        zOut += n;
        nRead -= iSpace;
        iChunkOffset = 0;
        if (nRead < 0) break;
        pChunk = pChunk.?.pNext;
        if (pChunk == null) break;
        if (nRead <= 0) break;
    }
    p.readpoint.iOffset = if (pChunk != null) iOfst + iAmt else 0;
    p.readpoint.pChunk = pChunk;
    return SQLITE_OK;
}

/// Free the chunk list headed at pFirst.
fn memjrnlFreeChunks(pFirst: ?*FileChunk) void {
    var pIter = pFirst;
    while (pIter) |it| {
        const pNext = it.pNext;
        sqlite3_free(it);
        pIter = pNext;
    }
}

/// Flush in-memory content to a real on-disk file.
fn memjrnlCreateFile(p: *MemJournal) c_int {
    const pReal: *Sqlite3File = @ptrCast(p);
    const copy = p.*;

    p.* = std.mem.zeroes(MemJournal);
    var rc = sqlite3OsOpen(copy.pVfs, copy.zJournal, pReal, copy.flags, null);
    if (rc == SQLITE_OK) {
        var nChunk = copy.nChunkSize;
        var iOff: i64 = 0;
        var pIter = copy.pFirst;
        while (pIter) |it| {
            if (iOff + @as(i64, nChunk) > copy.endpoint.iOffset) {
                nChunk = @intCast(copy.endpoint.iOffset - iOff);
            }
            rc = sqlite3OsWrite(pReal, chunkBytes(it), nChunk, iOff);
            if (rc != 0) break;
            iOff += @as(i64, nChunk);
            pIter = it.pNext;
        }
        if (rc == SQLITE_OK) {
            memjrnlFreeChunks(copy.pFirst);
        }
    }
    if (rc != SQLITE_OK) {
        // Restore the in-memory journal so the pager can still roll back.
        sqlite3OsClose(pReal);
        p.* = copy;
    }
    return rc;
}

/// xWrite: append to the in-memory journal (spilling to disk if configured).
fn memjrnlWrite(pJfd: *Sqlite3File, zBuf: ?*const anyopaque, iAmt: c_int, iOfst: i64) callconv(.c) c_int {
    const p: *MemJournal = @ptrCast(pJfd);
    var nWrite = iAmt;
    var zWrite: [*]const u8 = @ptrCast(zBuf.?);

    if (p.nSpill > 0 and (@as(i64, iAmt) + iOfst) > @as(i64, p.nSpill)) {
        var rc = memjrnlCreateFile(p);
        if (rc == SQLITE_OK) {
            rc = sqlite3OsWrite(pJfd, zBuf, iAmt, iOfst);
        }
        return rc;
    }

    // Otherwise the write is stored in memory. Journals are append-only except
    // for the atomic-write optimization rewriting the first bytes.
    if (iOfst > 0 and iOfst != p.endpoint.iOffset) {
        _ = memjrnlTruncate(pJfd, iOfst);
    }
    if (iOfst == 0 and p.pFirst != null) {
        const n: usize = @intCast(iAmt);
        @memcpy(chunkBytes(p.pFirst.?)[0..n], zWrite[0..n]);
    } else {
        while (nWrite > 0) {
            var pChunk = p.endpoint.pChunk;
            const iChunkOffset: c_int = @intCast(@mod(p.endpoint.iOffset, @as(i64, p.nChunkSize)));
            const iSpace = @min(nWrite, p.nChunkSize - iChunkOffset);

            if (iChunkOffset == 0) {
                // A new chunk is required to extend the file.
                const pNew: *FileChunk = @ptrCast(@alignCast(sqlite3_malloc(fileChunkSize(p.nChunkSize)) orelse return SQLITE_IOERR_NOMEM));
                pNew.pNext = null;
                if (pChunk) |pc| {
                    pc.pNext = pNew;
                } else {
                    p.pFirst = pNew;
                }
                pChunk = pNew;
                p.endpoint.pChunk = pNew;
            }

            const dst = chunkBytes(pChunk.?) + @as(usize, @intCast(iChunkOffset));
            const n: usize = @intCast(iSpace);
            @memcpy(dst[0..n], zWrite[0..n]);
            zWrite += n;
            nWrite -= iSpace;
            p.endpoint.iOffset += @as(i64, iSpace);
        }
    }
    return SQLITE_OK;
}

/// xTruncate: shrink the in-memory file to `size` bytes.
fn memjrnlTruncate(pJfd: *Sqlite3File, size: i64) callconv(.c) c_int {
    const p: *MemJournal = @ptrCast(pJfd);
    if (size < p.endpoint.iOffset) {
        var pIter: ?*FileChunk = null;
        if (size == 0) {
            memjrnlFreeChunks(p.pFirst);
            p.pFirst = null;
        } else {
            var iOff: i64 = p.nChunkSize;
            pIter = p.pFirst;
            while (pIter != null and iOff < size) {
                iOff += @as(i64, p.nChunkSize);
                pIter = pIter.?.pNext;
            }
            if (pIter) |it| {
                memjrnlFreeChunks(it.pNext);
                it.pNext = null;
            }
        }
        p.endpoint.pChunk = pIter;
        p.endpoint.iOffset = size;
        p.readpoint.pChunk = null;
        p.readpoint.iOffset = 0;
    }
    return SQLITE_OK;
}

/// xClose: free the in-memory chunks.
fn memjrnlClose(pJfd: *Sqlite3File) callconv(.c) c_int {
    const p: *MemJournal = @ptrCast(pJfd);
    memjrnlFreeChunks(p.pFirst);
    return SQLITE_OK;
}

/// xSync: a no-op for an in-memory journal.
fn memjrnlSync(pJfd: *Sqlite3File, flags: c_int) callconv(.c) c_int {
    _ = pJfd;
    _ = flags;
    return SQLITE_OK;
}

/// xFileSize: report the in-memory file size.
fn memjrnlFileSize(pJfd: *Sqlite3File, pSize: *i64) callconv(.c) c_int {
    const p: *MemJournal = @ptrCast(pJfd);
    pSize.* = p.endpoint.iOffset;
    return SQLITE_OK;
}

const MemJournalMethods: IoMethods = .{
    .iVersion = 1,
    .xClose = &memjrnlClose,
    .xRead = &memjrnlRead,
    .xWrite = &memjrnlWrite,
    .xTruncate = &memjrnlTruncate,
    .xSync = &memjrnlSync,
    .xFileSize = &memjrnlFileSize,
    .xLock = null,
    .xUnlock = null,
    .xCheckReservedLock = null,
    .xFileControl = null,
    .xSectorSize = null,
    .xDeviceCharacteristics = null,
    .xShmMap = null,
    .xShmLock = null,
    .xShmBarrier = null,
    .xShmUnmap = null,
    .xFetch = null,
    .xUnfetch = null,
};

/// Open a journal file. nSpill==0 → always a real VFS file; nSpill<0 → always
/// in memory; nSpill>0 → in memory until it grows past nSpill, then spilled.
export fn sqlite3JournalOpen(
    pVfs: ?*anyopaque,
    zName: ?[*:0]const u8,
    pJfd: *Sqlite3File,
    flags: c_int,
    nSpill: c_int,
) callconv(.c) c_int {
    const p: *MemJournal = @ptrCast(pJfd);
    p.* = std.mem.zeroes(MemJournal);
    if (nSpill == 0) {
        return sqlite3OsOpen(pVfs, zName, pJfd, flags, null);
    }
    if (nSpill > 0) {
        p.nChunkSize = nSpill;
    } else {
        p.nChunkSize = 8 + MEMJOURNAL_DFLT_FILECHUNKSIZE - @as(c_int, @sizeOf(FileChunk));
    }
    pJfd.pMethods = &MemJournalMethods;
    p.nSpill = nSpill;
    p.flags = flags;
    p.zJournal = zName;
    p.pVfs = pVfs;
    return SQLITE_OK;
}

/// Open a purely in-memory journal.
export fn sqlite3MemJournalOpen(pJfd: *Sqlite3File) callconv(.c) void {
    _ = sqlite3JournalOpen(null, null, pJfd, 0, -1);
}

/// Return true if the journal file is currently held entirely in memory.
export fn sqlite3JournalIsInMemory(p: *Sqlite3File) callconv(.c) c_int {
    return @intFromBool(p.pMethods == @as(?*const IoMethods, &MemJournalMethods));
}

/// Bytes needed for a journal file handle backed by VFS pVfs.
export fn sqlite3JournalSize(pVfs: *Sqlite3Vfs) callconv(.c) c_int {
    return @max(pVfs.szOsFile, @as(c_int, @sizeOf(MemJournal)));
}
