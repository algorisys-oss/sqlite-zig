//! Zig port of SQLite's VdbeSorter (src/vdbesort.c).
//!
//! The external merge-sort engine used by ORDER BY / GROUP BY that cannot be
//! satisfied from an index, and by CREATE INDEX. Records arrive via
//! sqlite3VdbeSorterWrite() in OP_MakeRecord format; once the in-memory budget
//! is exceeded they are sorted and spilled to a temp file as a "Packed Memory
//! Array" (PMA). On Rewind() any remaining memory is flushed, and the PMAs are
//! merged incrementally (the MergeEngine / IncrMerger tree) as keys are pulled
//! through Next()/Rowkey()/Compare().
//!
//! This build has SQLITE_MAX_WORKER_THREADS==8 (THREADSAFE=1, TEMP_STORE!=3) in
//! BOTH the production library and the --dev testfixture, so the multi-threaded
//! paths are compiled in and ported faithfully (worker threads are still only
//! used at runtime when "PRAGMA threads=N>0" is set and the connection allows
//! it — see sqlite3VdbeSorterInit). threads.c is already ported.
//!
//! Internal structs (VdbeSorter, SortSubtask, PmaReader, MergeEngine,
//! IncrMerger, SorterFile, SorterList, PmaWriter, SorterRecord) are file-local
//! to vdbesort.c, so they are replicated here as Zig `extern struct`s. Their
//! sizeof/offsets were probed under BOTH config flag sets and are identical
//! (they hold no config-divergent core struct inline), so a single layout
//! serves both builds. The few external-struct accesses that ARE
//! config-divergent (VdbeCursor.uc / .pKeyInfo, sizeof(Mem)) are config-gated.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const DEBUG = config.sqlite_debug;

// ===========================================================================
// Result codes
// ===========================================================================
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_IOERR: c_int = 10;
const SQLITE_DONE: c_int = 101;
const SQLITE_IOERR_READ: c_int = SQLITE_IOERR | (1 << 8);
const SQLITE_IOERR_ACCESS: c_int = SQLITE_IOERR | (13 << 8);
const SQLITE_IOERR_SHORT_READ: c_int = SQLITE_IOERR | (2 << 8);

// In this build SQLITE_NOMEM_BKPT == SQLITE_NOMEM (the SQLITE_DEBUG bkpt is a
// bookkeeping no-op around the same value; we return the value).
const SQLITE_NOMEM_BKPT: c_int = SQLITE_NOMEM;

// ===========================================================================
// Compile-time constants (probed identical in both configs)
// ===========================================================================
const SQLITE_MAX_WORKER_THREADS: c_int = 8;
const SQLITE_MAX_MMAP_SIZE: i64 = 2147418112;
const SQLITE_LIMIT_WORKER_THREADS: usize = 11;
const SQLITE_MAX_PMASZ: i64 = 1 << 29; // 512 MiB

const SORTER_MAX_MERGE_COUNT: c_int = 16;

const SORTER_TYPE_INTEGER: u8 = 0x01;
const SORTER_TYPE_TEXT: u8 = 0x02;

const INCRINIT_NORMAL: c_int = 0;
const INCRINIT_TASK: c_int = 1;
const INCRINIT_ROOT: c_int = 2;

const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

// MEM flags
const MEM_Null: u16 = 0x0001;
const MEM_Blob: u16 = 0x0010;
const MEM_Zero: u16 = 0x0400;
const MEM_TypeMask: u16 = 0x0dbf;

// File-control opcodes
const SQLITE_FCNTL_SIZE_HINT: c_int = 5;
const SQLITE_FCNTL_CHUNK_SIZE: c_int = 6;
const SQLITE_FCNTL_MMAP_SIZE: c_int = 18;

// Open flags
const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
const SQLITE_OPEN_CREATE: c_int = 0x00000004;
const SQLITE_OPEN_DELETEONCLOSE: c_int = 0x00000008;
const SQLITE_OPEN_EXCLUSIVE: c_int = 0x00000010;
const SQLITE_OPEN_TEMP_JOURNAL: c_int = 0x00001000;

// ===========================================================================
// Opaque C types we only ever hold as pointers.
// ===========================================================================
const sqlite3 = anyopaque;
const sqlite3_file = anyopaque;
const sqlite3_vfs = anyopaque;
const KeyInfo = anyopaque;
const UnpackedRecord = anyopaque;
const VdbeCursor = anyopaque;
const Mem = anyopaque;
const Btree = anyopaque;
const SQLiteThread = anyopaque;

// ===========================================================================
// Internal struct layouts (file-local in vdbesort.c — config-invariant).
// ===========================================================================
const SorterCompare = ?*const fn (*SortSubtask, *c_int, ?*const anyopaque, c_int, ?*const anyopaque, c_int) callconv(.c) c_int;

const SorterFile = extern struct {
    pFd: ?*sqlite3_file = null,
    iEof: i64 = 0,
};

const SorterList = extern struct {
    pList: ?*SorterRecord = null,
    aMemory: ?[*]u8 = null,
    szPMA: i64 = 0,
};

const MergeEngine = extern struct {
    nTree: c_int = 0,
    pTask: ?*SortSubtask = null,
    aTree: ?[*]c_int = null,
    aReadr: ?[*]PmaReader = null,
};

const SortSubtask = extern struct {
    pThread: ?*SQLiteThread = null,
    bDone: c_int = 0,
    nPMA: c_int = 0,
    pSorter: ?*VdbeSorter = null,
    pUnpacked: ?*UnpackedRecord = null,
    list: SorterList = .{},
    xCompare: SorterCompare = null,
    file: SorterFile = .{},
    file2: SorterFile = .{},
    nSpill: u64 = 0,
};

// VdbeSorter has a flexible aTask[] tail; declared without it so we can take
// &aTask[i] via taskAt(). sizeof(header) == offsetof(VdbeSorter, aTask) == 96.
const VdbeSorter = extern struct {
    mnPmaSize: c_int = 0,
    mxPmaSize: c_int = 0,
    mxKeysize: c_int = 0,
    pgsz: c_int = 0,
    pReader: ?*PmaReader = null,
    pMerger: ?*MergeEngine = null,
    db: ?*sqlite3 = null,
    pKeyInfo: ?*KeyInfo = null,
    pUnpacked: ?*UnpackedRecord = null,
    list: SorterList = .{},
    iMemory: c_int = 0,
    nMemory: c_int = 0,
    bUsePMA: u8 = 0,
    bUseThreads: u8 = 0,
    iPrev: u8 = 0,
    nTask: u8 = 0,
    typeMask: u8 = 0,
    // aTask: SortSubtask[FLEXARRAY] follows here at offset 96
};
const SZ_VDBESORTER_HDR: usize = 96; // offsetof(VdbeSorter, aTask)

const PmaReader = extern struct {
    iReadOff: i64 = 0,
    iEof: i64 = 0,
    nAlloc: c_int = 0,
    nKey: c_int = 0,
    pFd: ?*sqlite3_file = null,
    aAlloc: ?[*]u8 = null,
    aKey: ?[*]u8 = null,
    aBuffer: ?[*]u8 = null,
    nBuffer: c_int = 0,
    aMap: ?[*]u8 = null,
    pIncr: ?*IncrMerger = null,
};

const IncrMerger = extern struct {
    pTask: ?*SortSubtask = null,
    pMerger: ?*MergeEngine = null,
    iStartOff: i64 = 0,
    mxSz: c_int = 0,
    bEof: c_int = 0,
    bUseThread: c_int = 0,
    aFile: [2]SorterFile = .{ .{}, .{} },
};

const PmaWriter = extern struct {
    eFWErr: c_int = 0,
    aBuffer: ?[*]u8 = null,
    nBuffer: c_int = 0,
    iBufStart: c_int = 0,
    iBufEnd: c_int = 0,
    iWriteOff: i64 = 0,
    pFd: ?*sqlite3_file = null,
    nPmaSpill: u64 = 0,
};

const SorterRecord = extern struct {
    nVal: c_int = 0,
    // union { SorterRecord *pNext; int iNext; } u  — 8 bytes at offset 8
    u: extern union {
        pNext: ?*SorterRecord,
        iNext: c_int,
    } = .{ .pNext = null },
    // record data immediately follows this 16-byte header
};

comptime {
    std.debug.assert(@sizeOf(SorterFile) == 16);
    std.debug.assert(@sizeOf(SorterList) == 24);
    std.debug.assert(@sizeOf(MergeEngine) == 32);
    std.debug.assert(@sizeOf(SortSubtask) == 104);
    std.debug.assert(@offsetOf(SortSubtask, "xCompare") == 56);
    std.debug.assert(@offsetOf(SortSubtask, "file") == 64);
    std.debug.assert(@offsetOf(SortSubtask, "file2") == 80);
    std.debug.assert(@offsetOf(SortSubtask, "nSpill") == 96);
    std.debug.assert(@sizeOf(VdbeSorter) == SZ_VDBESORTER_HDR);
    std.debug.assert(@offsetOf(VdbeSorter, "list") == 56);
    std.debug.assert(@offsetOf(VdbeSorter, "iMemory") == 80);
    std.debug.assert(@offsetOf(VdbeSorter, "typeMask") == 92);
    std.debug.assert(@sizeOf(PmaReader) == 80);
    std.debug.assert(@offsetOf(PmaReader, "pFd") == 24);
    std.debug.assert(@offsetOf(PmaReader, "pIncr") == 72);
    std.debug.assert(@sizeOf(IncrMerger) == 72);
    std.debug.assert(@offsetOf(IncrMerger, "aFile") == 40);
    std.debug.assert(@sizeOf(PmaWriter) == 56);
    std.debug.assert(@offsetOf(PmaWriter, "iWriteOff") == 32);
    std.debug.assert(@sizeOf(SorterRecord) == 16);
    std.debug.assert(@offsetOf(SorterRecord, "u") == 8);
}

// SZ_VDBESORTER(N): bytes for a VdbeSorter with N subtasks.
inline fn SZ_VDBESORTER(n: usize) usize {
    return SZ_VDBESORTER_HDR + n * @sizeOf(SortSubtask);
}

// &pSorter->aTask[i]
inline fn taskAt(p: *VdbeSorter, i: usize) *SortSubtask {
    const base: [*]u8 = @ptrCast(p);
    return @ptrCast(@alignCast(base + SZ_VDBESORTER_HDR + i * @sizeOf(SortSubtask)));
}

// SRVAL(p): pointer to the record bytes following the SorterRecord header.
inline fn SRVAL(p: *SorterRecord) [*]u8 {
    const base: [*]u8 = @ptrCast(p);
    return base + @sizeOf(SorterRecord);
}

// ===========================================================================
// Config-divergent / ground-truth external offsets.
// ===========================================================================
fn off(comptime name: []const u8, prod: usize, dbg: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else if (DEBUG) dbg else prod;
}

// VdbeCursor.uc union (pSorter is its first member) and .pKeyInfo: shift under
// SQLITE_DEBUG. sizeof(Mem) likewise.
const VdbeCursor_uc = off("VdbeCursor_uc", 40, 48);
const VdbeCursor_pKeyInfo = off("VdbeCursor_pKeyInfo", 48, 56);
const sizeof_Mem = off("sizeof_Mem", 56, 72);

// Mem fields (config-invariant)
const Mem_z: usize = 8;
const Mem_n: usize = 16;
const Mem_flags: usize = 20;

// sqlite3 fields
const sqlite3_pVfs = off("sqlite3_pVfs", 0, 0);
const sqlite3_pDfltColl = off("sqlite3_pDfltColl", 16, 16);
const sqlite3_aDb = off("sqlite3_aDb", 32, 32);
const sqlite3_aLimit = off("sqlite3_aLimit", 136, 136);
const sqlite3_nMaxSorterMmap = off("sqlite3_nMaxSorterMmap", 188, 188);
const sqlite3_nSpill = off("sqlite3_nSpill", 808, 808);

// KeyInfo fields
const KeyInfo_nKeyField = off("KeyInfo_nKeyField", 6, 6);
const KeyInfo_nAllField = off("KeyInfo_nAllField", 8, 8);
const KeyInfo_db = off("KeyInfo_db", 16, 16);
const KeyInfo_aSortFlags = off("KeyInfo_aSortFlags", 24, 24);
const KeyInfo_aColl = off("KeyInfo_aColl", 32, 32);

// SZ_KEYINFO(N) = offsetof(KeyInfo, aColl) + N*sizeof(CollSeq*)
inline fn SZ_KEYINFO(n: usize) usize {
    return KeyInfo_aColl + n * @sizeOf(usize);
}

// UnpackedRecord fields
const UnpackedRecord_nField = off("UnpackedRecord_nField", 28, 28);
const UnpackedRecord_aMem = off("UnpackedRecord_aMem", 8, 8);
const UnpackedRecord_errCode = off("UnpackedRecord_errCode", 31, 31);

// Db fields
const Db_pBt = off("Db_pBt", 8, 8);
const Db_pSchema = off("Db_pSchema", 24, 24);
const sizeof_Db = off("sizeof_Db", 32, 32);

// Schema
const Schema_cache_size = off("Schema_cache_size", 116, 116);

// Sqlite3Config
const Sqlite3Config_bCoreMutex = off("Sqlite3Config_bCoreMutex", 4, 4);
const Sqlite3Config_bSmallMalloc = off("Sqlite3Config_bSmallMalloc", 8, 8);
const Sqlite3Config_szPma = off("Sqlite3Config_szPma", 336, 336);

// ===========================================================================
// Typed field accessors over opaque base pointers.
// ===========================================================================
inline fn rd(comptime T: type, base: ?*const anyopaque, o: usize) T {
    const p: [*]const u8 = @ptrCast(base.?);
    return @as(*const T, @ptrCast(@alignCast(p + o))).*;
}
inline fn rdU8(base: ?*const anyopaque, o: usize) u8 {
    const p: [*]const u8 = @ptrCast(base.?);
    return p[o];
}
inline fn wrU8(base: ?*anyopaque, o: usize, v: u8) void {
    const p: [*]u8 = @ptrCast(base.?);
    p[o] = v;
}
inline fn wrU16(base: ?*anyopaque, o: usize, v: u16) void {
    const p: [*]u8 = @ptrCast(base.?);
    @as(*u16, @ptrCast(@alignCast(p + o))).* = v;
}

// ===========================================================================
// Extern C functions.
// ===========================================================================
extern var sqlite3Config: extern struct { _pad: u8 align(8) }; // address only; fields read via offset
extern fn sqlite3Malloc(n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3MallocZero(n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3MallocSize(p: ?*const anyopaque) callconv(.c) c_int;
extern fn sqlite3DbMallocZero(db: ?*sqlite3, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*sqlite3, p: ?*anyopaque) callconv(.c) void;

extern fn sqlite3PutVarint(p: [*]u8, v: u64) callconv(.c) c_int;
extern fn sqlite3GetVarint(p: [*]const u8, v: *u64) callconv(.c) u8;
extern fn sqlite3GetVarint32(p: [*]const u8, v: *u32) callconv(.c) u8;
extern fn sqlite3VarintLen(v: u64) callconv(.c) c_int;

extern fn sqlite3FaultSim(n: c_int) callconv(.c) c_int;
extern fn sqlite3HeapNearlyFull() callconv(.c) c_int;
extern fn sqlite3TempInMemory(db: ?*const sqlite3) callconv(.c) c_int;

extern fn sqlite3BtreeEnter(p: ?*Btree) callconv(.c) void;
extern fn sqlite3BtreeLeave(p: ?*Btree) callconv(.c) void;
extern fn sqlite3BtreeGetPageSize(p: ?*Btree) callconv(.c) c_int;

extern fn sqlite3VdbeRecordUnpack(nKey: c_int, pKey: ?*const anyopaque, p: ?*UnpackedRecord) callconv(.c) void;
extern fn sqlite3VdbeRecordCompare(nKey: c_int, pKey: ?*const anyopaque, p: ?*UnpackedRecord) callconv(.c) c_int;
extern fn sqlite3VdbeRecordCompareWithSkip(nKey: c_int, pKey: ?*const anyopaque, p: ?*UnpackedRecord, skip: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAllocUnpackedRecord(p: ?*KeyInfo) callconv(.c) ?*UnpackedRecord;
extern fn sqlite3VdbeMemClearAndResize(p: ?*Mem, n: c_int) callconv(.c) c_int;

extern fn sqlite3OsRead(f: ?*sqlite3_file, p: ?*anyopaque, amt: c_int, offset: i64) callconv(.c) c_int;
extern fn sqlite3OsWrite(f: ?*sqlite3_file, p: ?*const anyopaque, amt: c_int, offset: i64) callconv(.c) c_int;
extern fn sqlite3OsFetch(f: ?*sqlite3_file, off2: i64, amt: c_int, pp: *?*anyopaque) callconv(.c) c_int;
extern fn sqlite3OsUnfetch(f: ?*sqlite3_file, off2: i64, p: ?*anyopaque) callconv(.c) c_int;
extern fn sqlite3OsFileControlHint(f: ?*sqlite3_file, op: c_int, p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3OsOpenMalloc(pVfs: ?*sqlite3_vfs, zName: ?[*:0]const u8, ppFd: *?*sqlite3_file, flags: c_int, pOutFlags: ?*c_int) callconv(.c) c_int;
extern fn sqlite3OsCloseFree(f: ?*sqlite3_file) callconv(.c) void;

extern fn sqlite3ThreadCreate(pp: *?*SQLiteThread, xTask: *const fn (?*anyopaque) callconv(.c) ?*anyopaque, pIn: ?*anyopaque) callconv(.c) c_int;
extern fn sqlite3ThreadJoin(p: ?*SQLiteThread, pRet: *?*anyopaque) callconv(.c) c_int;

extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) callconv(.c) c_int;

// ===========================================================================
// Small helpers.
// ===========================================================================
inline fn MAXi(a: i64, b: i64) i64 {
    return if (a > b) a else b;
}
inline fn MINi(a: i64, b: i64) i64 {
    return if (a < b) a else b;
}

// sqlite3_io_methods.iVersion is the first field of *pMethods; pMethods is the
// first field of sqlite3_file.
inline fn osVersion(pFd: ?*sqlite3_file) c_int {
    const pMethods = rd(?*const anyopaque, pFd, 0);
    return rd(c_int, pMethods, 0);
}

inline fn cfgU8(o: usize) u8 {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    return base[o];
}
inline fn cfgU32(o: usize) u32 {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    return @as(*const u32, @ptrCast(@alignCast(base + o))).*;
}

// SQLITE_INT_TO_PTR / SQLITE_PTR_TO_INT
inline fn intToPtr(rc: c_int) ?*anyopaque {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, rc))));
}
inline fn ptrToInt(p: ?*anyopaque) c_int {
    return @truncate(@as(isize, @bitCast(@intFromPtr(p))));
}

// getVarint32NR: returns the value (the macro discards the byte count).
inline fn getVarint32NR(a: [*]const u8) u32 {
    var v: u32 = a[0];
    if (v >= 0x80) {
        _ = sqlite3GetVarint32(a, &v);
    }
    return v;
}

// db->aDb[i]
inline fn dbEnt(db: ?*sqlite3, i: c_int) ?*anyopaque {
    const aDb = rd(?*anyopaque, db, sqlite3_aDb);
    const base: [*]u8 = @ptrCast(aDb.?);
    return base + @as(usize, @intCast(i)) * sizeof_Db;
}
// db->aLimit[idx]
inline fn dbLimit(db: ?*sqlite3, idx: usize) c_int {
    const base: [*]const u8 = @ptrCast(db.?);
    const p: [*]const c_int = @ptrCast(@alignCast(base + sqlite3_aLimit));
    return p[idx];
}
// pCsr->uc.pSorter accessors
inline fn setUcPSorter(pCsr: ?*VdbeCursor, v: ?*anyopaque) void {
    const base: [*]u8 = @ptrCast(pCsr.?);
    @as(*?*anyopaque, @ptrCast(@alignCast(base + VdbeCursor_uc))).* = v;
}
inline fn getUcPSorter(pCsr: ?*const VdbeCursor) ?*VdbeSorter {
    const base: [*]const u8 = @ptrCast(pCsr.?);
    return @as(*const ?*VdbeSorter, @ptrCast(@alignCast(base + VdbeCursor_uc))).*;
}
// db->nSpill += v
inline fn addNSpill(db: ?*sqlite3, v: u64) void {
    const base: [*]u8 = @ptrCast(db.?);
    const p: *u64 = @ptrCast(@alignCast(base + sqlite3_nSpill));
    p.* +%= v;
}

// KeyInfo accessors
inline fn keyInfoOf(pTask: *SortSubtask) ?*KeyInfo {
    return pTask.pSorter.?.pKeyInfo;
}
inline fn kiNKeyField(ki: ?*KeyInfo) u16 {
    return rd(u16, ki, KeyInfo_nKeyField);
}
inline fn kiSortFlag0(ki: ?*KeyInfo) u8 {
    const aSortFlags = rd(?[*]u8, ki, KeyInfo_aSortFlags);
    return aSortFlags.?[0];
}

// ===========================================================================
// PmaReader
// ===========================================================================

fn vdbePmaReaderClear(pReadr: *PmaReader) void {
    sqlite3_free(pReadr.aAlloc);
    sqlite3_free(pReadr.aBuffer);
    if (pReadr.aMap) |m| _ = sqlite3OsUnfetch(pReadr.pFd, 0, m);
    vdbeIncrFree(pReadr.pIncr);
    @memset(std.mem.asBytes(pReadr), 0);
}

fn vdbePmaReadBlob(p: *PmaReader, nByte: c_int, ppOut: *[*]u8) c_int {
    if (p.aMap) |map| {
        ppOut.* = map + @as(usize, @intCast(p.iReadOff));
        p.iReadOff += nByte;
        return SQLITE_OK;
    }

    std.debug.assert(p.aBuffer != null);

    const iBuf: c_int = @intCast(@mod(p.iReadOff, p.nBuffer));
    if (iBuf == 0) {
        var nRead: c_int = undefined;
        if ((p.iEof - p.iReadOff) > @as(i64, p.nBuffer)) {
            nRead = p.nBuffer;
        } else {
            nRead = @intCast(p.iEof - p.iReadOff);
        }
        std.debug.assert(nRead > 0);
        const rc = sqlite3OsRead(p.pFd, p.aBuffer, nRead, p.iReadOff);
        std.debug.assert(rc != SQLITE_IOERR_SHORT_READ);
        if (rc != SQLITE_OK) return rc;
    }
    const nAvail: c_int = p.nBuffer - iBuf;

    if (nByte <= nAvail) {
        ppOut.* = p.aBuffer.? + @as(usize, @intCast(iBuf));
        p.iReadOff += nByte;
    } else {
        // Requested data not all in buffer; copy into p->aAlloc[].
        if (p.nAlloc < nByte) {
            var nNew: i64 = MAXi(128, 2 * @as(i64, p.nAlloc));
            while (nByte > nNew) nNew = nNew * 2;
            const aNew = sqlite3Realloc(p.aAlloc, @intCast(nNew));
            if (aNew == null) return SQLITE_NOMEM_BKPT;
            p.nAlloc = @intCast(nNew);
            p.aAlloc = @ptrCast(aNew);
        }

        @memcpy(
            p.aAlloc.?[0..@intCast(nAvail)],
            (p.aBuffer.? + @as(usize, @intCast(iBuf)))[0..@intCast(nAvail)],
        );
        p.iReadOff += nAvail;
        var nRem: c_int = nByte - nAvail;

        while (nRem > 0) {
            var aNext: [*]u8 = undefined;
            var nCopy: c_int = nRem;
            if (nRem > p.nBuffer) nCopy = p.nBuffer;
            const rc = vdbePmaReadBlob(p, nCopy, &aNext);
            if (rc != SQLITE_OK) return rc;
            std.debug.assert(aNext != p.aAlloc.?);
            @memcpy(
                (p.aAlloc.? + @as(usize, @intCast(nByte - nRem)))[0..@intCast(nCopy)],
                aNext[0..@intCast(nCopy)],
            );
            nRem -= nCopy;
        }

        ppOut.* = p.aAlloc.?;
    }

    return SQLITE_OK;
}

fn vdbePmaReadVarint(p: *PmaReader, pnOut: *u64) c_int {
    if (p.aMap) |map| {
        p.iReadOff += sqlite3GetVarint(map + @as(usize, @intCast(p.iReadOff)), pnOut);
    } else {
        const iBuf: c_int = @intCast(@mod(p.iReadOff, p.nBuffer));
        if (iBuf != 0 and (p.nBuffer - iBuf) >= 9) {
            p.iReadOff += sqlite3GetVarint(p.aBuffer.? + @as(usize, @intCast(iBuf)), pnOut);
        } else {
            var aVarint: [16]u8 = undefined;
            var i: usize = 0;
            while (true) {
                var a: [*]u8 = undefined;
                const rc = vdbePmaReadBlob(p, 1, &a);
                if (rc != SQLITE_OK) return rc;
                aVarint[(i) & 0xf] = a[0];
                i += 1;
                if ((a[0] & 0x80) == 0) break;
            }
            _ = sqlite3GetVarint(&aVarint, pnOut);
        }
    }
    return SQLITE_OK;
}

fn vdbeSorterMapFile(pTask: *SortSubtask, pFile: *SorterFile, pp: *?[*]u8) c_int {
    var rc: c_int = SQLITE_OK;
    const db = pTask.pSorter.?.db;
    const nMax: i64 = rd(c_int, db, sqlite3_nMaxSorterMmap);
    if (pFile.iEof <= nMax) {
        const pFd = pFile.pFd;
        if (osVersion(pFd) >= 3) {
            var p: ?*anyopaque = null;
            rc = sqlite3OsFetch(pFd, 0, @intCast(pFile.iEof), &p);
            pp.* = @ptrCast(p);
        }
    }
    return rc;
}

fn vdbePmaReaderSeek(pTask: *SortSubtask, pReadr: *PmaReader, pFile: *SorterFile, iOff: i64) c_int {
    var rc: c_int = SQLITE_OK;

    std.debug.assert(pReadr.pIncr == null or pReadr.pIncr.?.bEof == 0);

    if (sqlite3FaultSim(201) != 0) return SQLITE_IOERR_READ;
    if (pReadr.aMap) |m| {
        _ = sqlite3OsUnfetch(pReadr.pFd, 0, m);
        pReadr.aMap = null;
    }
    pReadr.iReadOff = iOff;
    pReadr.iEof = pFile.iEof;
    pReadr.pFd = pFile.pFd;

    var aMap: ?[*]u8 = null;
    rc = vdbeSorterMapFile(pTask, pFile, &aMap);
    pReadr.aMap = aMap;
    if (rc == SQLITE_OK and pReadr.aMap == null) {
        const pgsz: c_int = pTask.pSorter.?.pgsz;
        const iBuf: c_int = @intCast(@mod(pReadr.iReadOff, pgsz));
        if (pReadr.aBuffer == null) {
            pReadr.aBuffer = @ptrCast(sqlite3Malloc(@intCast(pgsz)));
            if (pReadr.aBuffer == null) rc = SQLITE_NOMEM_BKPT;
            pReadr.nBuffer = pgsz;
        }
        if (rc == SQLITE_OK and iBuf != 0) {
            var nRead: c_int = pgsz - iBuf;
            if ((pReadr.iReadOff + nRead) > pReadr.iEof) {
                nRead = @intCast(pReadr.iEof - pReadr.iReadOff);
            }
            rc = sqlite3OsRead(pReadr.pFd, pReadr.aBuffer.? + @as(usize, @intCast(iBuf)), nRead, pReadr.iReadOff);
        }
    }

    return rc;
}

fn vdbePmaReaderNext(pReadr: *PmaReader) c_int {
    var rc: c_int = SQLITE_OK;
    var nRec: u64 = 0;

    if (pReadr.iReadOff >= pReadr.iEof) {
        const pIncr = pReadr.pIncr;
        var bEof: bool = true;
        if (pIncr) |incr| {
            rc = vdbeIncrSwap(incr);
            if (rc == SQLITE_OK and incr.bEof == 0) {
                rc = vdbePmaReaderSeek(incr.pTask.?, pReadr, &incr.aFile[0], incr.iStartOff);
                bEof = false;
            }
        }

        if (bEof) {
            vdbePmaReaderClear(pReadr);
            return rc;
        }
    }

    if (rc == SQLITE_OK) {
        rc = vdbePmaReadVarint(pReadr, &nRec);
    }
    if (rc == SQLITE_OK) {
        pReadr.nKey = @intCast(nRec);
        var aKey: [*]u8 = undefined;
        rc = vdbePmaReadBlob(pReadr, @intCast(nRec), &aKey);
        pReadr.aKey = aKey;
    }

    return rc;
}

fn vdbePmaReaderInit(pTask: *SortSubtask, pFile: *SorterFile, iStart: i64, pReadr: *PmaReader, pnByte: *i64) c_int {
    std.debug.assert(pFile.iEof > iStart);
    std.debug.assert(pReadr.aAlloc == null and pReadr.nAlloc == 0);
    std.debug.assert(pReadr.aBuffer == null);
    std.debug.assert(pReadr.aMap == null);

    var rc = vdbePmaReaderSeek(pTask, pReadr, pFile, iStart);
    if (rc == SQLITE_OK) {
        var nByte: u64 = 0;
        rc = vdbePmaReadVarint(pReadr, &nByte);
        pReadr.iEof = pReadr.iReadOff + @as(i64, @intCast(nByte));
        pnByte.* += @intCast(nByte);
    }
    if (rc == SQLITE_OK) {
        rc = vdbePmaReaderNext(pReadr);
    }
    return rc;
}

// ===========================================================================
// Comparators
// ===========================================================================

fn vdbeSorterCompareTail(
    pTask: *SortSubtask,
    pbKey2Cached: *c_int,
    pKey1: ?*const anyopaque,
    nKey1: c_int,
    pKey2: ?*const anyopaque,
    nKey2: c_int,
) callconv(.c) c_int {
    const r2 = pTask.pUnpacked;
    if (pbKey2Cached.* == 0) {
        sqlite3VdbeRecordUnpack(nKey2, pKey2, r2);
        pbKey2Cached.* = 1;
    }
    return sqlite3VdbeRecordCompareWithSkip(nKey1, pKey1, r2, 1);
}

fn vdbeSorterCompare(
    pTask: *SortSubtask,
    pbKey2Cached: *c_int,
    pKey1: ?*const anyopaque,
    nKey1: c_int,
    pKey2: ?*const anyopaque,
    nKey2: c_int,
) callconv(.c) c_int {
    const r2 = pTask.pUnpacked;
    if (pbKey2Cached.* == 0) {
        sqlite3VdbeRecordUnpack(nKey2, pKey2, r2);
        pbKey2Cached.* = 1;
    }
    return sqlite3VdbeRecordCompare(nKey1, pKey1, r2);
}

fn vdbeSorterCompareText(
    pTask: *SortSubtask,
    pbKey2Cached: *c_int,
    pKey1: ?*const anyopaque,
    nKey1: c_int,
    pKey2: ?*const anyopaque,
    nKey2: c_int,
) callconv(.c) c_int {
    const p1: [*]const u8 = @ptrCast(pKey1.?);
    const p2: [*]const u8 = @ptrCast(pKey2.?);
    const v1: [*]const u8 = p1 + p1[0];
    const v2: [*]const u8 = p2 + p2[0];

    const n1: u32 = getVarint32NR(p1 + 1);
    const n2: u32 = getVarint32NR(p2 + 1);

    const minN: u32 = if (n1 < n2) n1 else n2;
    const cmpLen: usize = @intCast(@divTrunc(@as(i64, minN) - 13, 2));
    var res: c_int = memcmp(v1, v2, cmpLen);
    if (res == 0) {
        res = @as(c_int, @bitCast(n1)) - @as(c_int, @bitCast(n2));
    }

    if (res == 0) {
        const ki = keyInfoOf(pTask);
        if (kiNKeyField(ki) > 1) {
            res = vdbeSorterCompareTail(pTask, pbKey2Cached, pKey1, nKey1, pKey2, nKey2);
        }
    } else {
        const ki = keyInfoOf(pTask);
        std.debug.assert((kiSortFlag0(ki) & KEYINFO_ORDER_BIGNULL) == 0);
        if (kiSortFlag0(ki) != 0) {
            res = res * -1;
        }
    }

    return res;
}

fn vdbeSorterCompareInt(
    pTask: *SortSubtask,
    pbKey2Cached: *c_int,
    pKey1: ?*const anyopaque,
    nKey1: c_int,
    pKey2: ?*const anyopaque,
    nKey2: c_int,
) callconv(.c) c_int {
    const p1: [*]const u8 = @ptrCast(pKey1.?);
    const p2: [*]const u8 = @ptrCast(pKey2.?);
    const s1: c_int = p1[1];
    const s2: c_int = p2[1];
    const v1: [*]const u8 = p1 + p1[0];
    const v2: [*]const u8 = p2 + p2[0];
    var res: c_int = undefined;

    std.debug.assert((s1 > 0 and s1 < 7) or s1 == 8 or s1 == 9);
    std.debug.assert((s2 > 0 and s2 < 7) or s2 == 8 or s2 == 9);

    if (s1 == s2) {
        const aLen = [_]u8{ 0, 1, 2, 3, 4, 6, 8, 0, 0, 0 };
        const n: u8 = aLen[@intCast(s1)];
        res = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            res = @as(c_int, v1[i]) - @as(c_int, v2[i]);
            if (res != 0) {
                if (((v1[0] ^ v2[0]) & 0x80) != 0) {
                    res = if ((v1[0] & 0x80) != 0) -1 else 1;
                }
                break;
            }
        }
    } else if (s1 > 7 and s2 > 7) {
        res = s1 - s2;
    } else {
        if (s2 > 7) {
            res = 1;
        } else if (s1 > 7) {
            res = -1;
        } else {
            res = s1 - s2;
        }
        std.debug.assert(res != 0);

        if (res > 0) {
            if ((v1[0] & 0x80) != 0) res = -1;
        } else {
            if ((v2[0] & 0x80) != 0) res = 1;
        }
    }

    const ki = keyInfoOf(pTask);
    std.debug.assert(rd(?[*]u8, ki, KeyInfo_aSortFlags) != null);
    if (res == 0) {
        if (kiNKeyField(ki) > 1) {
            res = vdbeSorterCompareTail(pTask, pbKey2Cached, pKey1, nKey1, pKey2, nKey2);
        }
    } else if (kiSortFlag0(ki) != 0) {
        std.debug.assert((kiSortFlag0(ki) & KEYINFO_ORDER_BIGNULL) == 0);
        res = res * -1;
    }

    return res;
}

// ===========================================================================
// sqlite3VdbeSorterInit
// ===========================================================================
export fn sqlite3VdbeSorterInit(db: ?*sqlite3, nField: c_int, pCsr: ?*VdbeCursor) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    var nWorker: c_int = 0;
    if (SQLITE_MAX_WORKER_THREADS > 0) {
        if (sqlite3TempInMemory(db) != 0 or cfgU8(Sqlite3Config_bCoreMutex) == 0) {
            nWorker = 0;
        } else {
            nWorker = dbLimit(db, SQLITE_LIMIT_WORKER_THREADS);
        }
        if (SQLITE_MAX_WORKER_THREADS >= SORTER_MAX_MERGE_COUNT) {
            if (nWorker >= SORTER_MAX_MERGE_COUNT) {
                nWorker = SORTER_MAX_MERGE_COUNT - 1;
            }
        }
    }

    const pCsrKeyInfo = rd(?*KeyInfo, pCsr, VdbeCursor_pKeyInfo);
    const nAllField = rd(u16, pCsrKeyInfo, KeyInfo_nAllField);
    const szKeyInfo: usize = SZ_KEYINFO(nAllField);
    const sz: usize = SZ_VDBESORTER(@intCast(nWorker + 1));

    const pSorterRaw = sqlite3DbMallocZero(db, @intCast(sz + szKeyInfo));
    setUcPSorter(pCsr, pSorterRaw);
    if (pSorterRaw == null) {
        rc = SQLITE_NOMEM_BKPT;
    } else {
        const pSorter: *VdbeSorter = @ptrCast(@alignCast(pSorterRaw));
        const pBt = rd(?*Btree, dbEnt(db, 0), Db_pBt);
        // pKeyInfo = (KeyInfo*)((u8*)pSorter + sz)
        const pKeyInfoBytes: [*]u8 = @as([*]u8, @ptrCast(pSorterRaw)) + sz;
        const pKeyInfo: ?*KeyInfo = @ptrCast(pKeyInfoBytes);
        pSorter.pKeyInfo = pKeyInfo;
        @memcpy(pKeyInfoBytes[0..szKeyInfo], @as([*]const u8, @ptrCast(pCsrKeyInfo.?))[0..szKeyInfo]);
        // pKeyInfo->db = 0
        @as(*?*anyopaque, @ptrCast(@alignCast(pKeyInfoBytes + KeyInfo_db))).* = null;
        if (nField != 0 and nWorker == 0) {
            // pKeyInfo->nKeyField = nField
            @as(*u16, @ptrCast(@alignCast(pKeyInfoBytes + KeyInfo_nKeyField))).* = @intCast(nField);
        }

        sqlite3BtreeEnter(pBt);
        const pgsz: c_int = sqlite3BtreeGetPageSize(pBt);
        pSorter.pgsz = pgsz;
        sqlite3BtreeLeave(pBt);

        pSorter.nTask = @intCast(nWorker + 1);
        pSorter.iPrev = @bitCast(@as(i8, @truncate(nWorker - 1)));
        pSorter.bUseThreads = if (pSorter.nTask > 1) 1 else 0;
        pSorter.db = db;
        {
            var i: usize = 0;
            while (i < pSorter.nTask) : (i += 1) {
                taskAt(pSorter, i).pSorter = pSorter;
            }
        }

        if (sqlite3TempInMemory(db) == 0) {
            const szPma: u32 = cfgU32(Sqlite3Config_szPma);
            pSorter.mnPmaSize = @intCast(szPma * @as(u32, @intCast(pgsz)));

            // mxCache = db->aDb[0].pSchema->cache_size
            const pSchema = rd(?*anyopaque, dbEnt(db, 0), Db_pSchema);
            var mxCache: i64 = rd(c_int, pSchema, Schema_cache_size);
            if (mxCache < 0) {
                mxCache = mxCache * -1024;
            } else {
                mxCache = mxCache * pgsz;
            }
            mxCache = MINi(mxCache, SQLITE_MAX_PMASZ);
            pSorter.mxPmaSize = @intCast(MAXi(pSorter.mnPmaSize, @as(i64, @as(c_int, @intCast(mxCache)))));

            if (cfgU8(Sqlite3Config_bSmallMalloc) == 0) {
                std.debug.assert(pSorter.iMemory == 0);
                pSorter.nMemory = pgsz;
                pSorter.list.aMemory = @ptrCast(sqlite3Malloc(@intCast(pgsz)));
                if (pSorter.list.aMemory == null) rc = SQLITE_NOMEM_BKPT;
            }
        }

        // typeMask
        const aColl0 = rd(?*anyopaque, pKeyInfo, KeyInfo_aColl); // aColl is inline array; aColl[0]
        const pDfltColl = rd(?*anyopaque, db, sqlite3_pDfltColl);
        const aSortFlags = rd(?[*]u8, pKeyInfo, KeyInfo_aSortFlags);
        if (nAllField < 13 and
            (aColl0 == null or aColl0 == pDfltColl) and
            (aSortFlags.?[0] & KEYINFO_ORDER_BIGNULL) == 0)
        {
            pSorter.typeMask = SORTER_TYPE_INTEGER | SORTER_TYPE_TEXT;
        }
    }

    return rc;
}

// ===========================================================================
// Free helpers / cleanup
// ===========================================================================

fn vdbeSorterRecordFree(db: ?*sqlite3, pRecord: ?*SorterRecord) void {
    var p = pRecord;
    while (p) |pp| {
        const pNext = pp.u.pNext;
        sqlite3DbFree(db, pp);
        p = pNext;
    }
}

fn vdbeSortSubtaskCleanup(db: ?*sqlite3, pTask: *SortSubtask) void {
    sqlite3DbFree(db, pTask.pUnpacked);
    if (SQLITE_MAX_WORKER_THREADS > 0 and pTask.list.aMemory != null) {
        sqlite3_free(pTask.list.aMemory);
    } else {
        std.debug.assert(pTask.list.aMemory == null);
        vdbeSorterRecordFree(null, pTask.list.pList);
    }
    if (pTask.file.pFd) |fd| sqlite3OsCloseFree(fd);
    if (pTask.file2.pFd) |fd| sqlite3OsCloseFree(fd);
    @memset(std.mem.asBytes(pTask), 0);
}

// ===========================================================================
// Worker-thread helpers (SQLITE_MAX_WORKER_THREADS>0)
// ===========================================================================

fn vdbeSorterJoinThread(pTask: *SortSubtask) c_int {
    var rc: c_int = SQLITE_OK;
    if (pTask.pThread != null) {
        var pRet: ?*anyopaque = intToPtr(SQLITE_ERROR);
        _ = sqlite3ThreadJoin(pTask.pThread, &pRet);
        rc = ptrToInt(pRet);
        std.debug.assert(pTask.bDone == 1);
        pTask.bDone = 0;
        pTask.pThread = null;
    }
    return rc;
}

fn vdbeSorterCreateThread(pTask: *SortSubtask, xTask: *const fn (?*anyopaque) callconv(.c) ?*anyopaque, pIn: ?*anyopaque) c_int {
    std.debug.assert(pTask.pThread == null and pTask.bDone == 0);
    return sqlite3ThreadCreate(&pTask.pThread, xTask, pIn);
}

fn vdbeSorterJoinAll(pSorter: *VdbeSorter, rcin: c_int) c_int {
    var rc: c_int = rcin;
    var i: c_int = @as(c_int, pSorter.nTask) - 1;
    while (i >= 0) : (i -= 1) {
        const rc2 = vdbeSorterJoinThread(taskAt(pSorter, @intCast(i)));
        if (rc == SQLITE_OK) rc = rc2;
    }
    return rc;
}

// ===========================================================================
// MergeEngine alloc/free
// ===========================================================================

fn vdbeMergeEngineNew(nReader: c_int) ?*MergeEngine {
    var N: c_int = 2;
    std.debug.assert(nReader <= SORTER_MAX_MERGE_COUNT);
    while (N < nReader) N += N;

    const nByte: i64 = @as(i64, @sizeOf(MergeEngine)) + @as(i64, N) * (@as(i64, @sizeOf(c_int)) + @as(i64, @sizeOf(PmaReader)));

    const pNewRaw = if (sqlite3FaultSim(100) != 0) null else sqlite3MallocZero(@intCast(nByte));
    if (pNewRaw) |raw| {
        const pNew: *MergeEngine = @ptrCast(@alignCast(raw));
        pNew.nTree = N;
        pNew.pTask = null;
        // aReadr = (PmaReader*)&pNew[1]
        const after: [*]u8 = @as([*]u8, @ptrCast(raw)) + @sizeOf(MergeEngine);
        pNew.aReadr = @ptrCast(@alignCast(after));
        // aTree = (int*)&aReadr[N]
        const afterReadr: [*]u8 = after + @as(usize, @intCast(N)) * @sizeOf(PmaReader);
        pNew.aTree = @ptrCast(@alignCast(afterReadr));
        return pNew;
    }
    return null;
}

fn vdbeMergeEngineFree(pMerger: ?*MergeEngine) void {
    if (pMerger) |m| {
        var i: c_int = 0;
        while (i < m.nTree) : (i += 1) {
            vdbePmaReaderClear(&m.aReadr.?[@intCast(i)]);
        }
        sqlite3_free(m);
    }
}

fn vdbeIncrFree(pIncr: ?*IncrMerger) void {
    if (pIncr) |incr| {
        if (SQLITE_MAX_WORKER_THREADS > 0 and incr.bUseThread != 0) {
            _ = vdbeSorterJoinThread(incr.pTask.?);
            if (incr.aFile[0].pFd) |fd| sqlite3OsCloseFree(fd);
            if (incr.aFile[1].pFd) |fd| sqlite3OsCloseFree(fd);
        }
        vdbeMergeEngineFree(incr.pMerger);
        sqlite3_free(incr);
    }
}

// ===========================================================================
// sqlite3VdbeSorterReset / Close
// ===========================================================================
export fn sqlite3VdbeSorterReset(db: ?*sqlite3, pSorter: ?*VdbeSorter) callconv(.c) void {
    const ps = pSorter.?;
    _ = vdbeSorterJoinAll(ps, SQLITE_OK);
    std.debug.assert(ps.bUseThreads != 0 or ps.pReader == null);
    if (SQLITE_MAX_WORKER_THREADS > 0 and ps.pReader != null) {
        vdbePmaReaderClear(ps.pReader.?);
        sqlite3DbFree(db, ps.pReader);
        ps.pReader = null;
    }
    vdbeMergeEngineFree(ps.pMerger);
    ps.pMerger = null;
    {
        var i: usize = 0;
        while (i < ps.nTask) : (i += 1) {
            const pTask = taskAt(ps, i);
            vdbeSortSubtaskCleanup(db, pTask);
            pTask.pSorter = ps;
        }
    }
    if (ps.list.aMemory == null) {
        vdbeSorterRecordFree(null, ps.list.pList);
    }
    ps.list.pList = null;
    ps.list.szPMA = 0;
    ps.bUsePMA = 0;
    ps.iMemory = 0;
    ps.mxKeysize = 0;
    sqlite3DbFree(db, ps.pUnpacked);
    ps.pUnpacked = null;
}

export fn sqlite3VdbeSorterClose(db: ?*sqlite3, pCsr: ?*VdbeCursor) callconv(.c) void {
    const pSorter = getUcPSorter(pCsr);
    if (pSorter) |ps| {
        var ii: usize = 0;
        var total: u64 = 0;
        while (ii < ps.nTask) : (ii += 1) {
            total += taskAt(ps, ii).nSpill;
        }
        addNSpill(db, total);
        sqlite3VdbeSorterReset(db, ps);
        sqlite3_free(ps.list.aMemory);
        sqlite3DbFree(db, ps);
        setUcPSorter(pCsr, null);
    }
}

// ===========================================================================
// vdbeSorterExtendFile / OpenTempFile  (SQLITE_MAX_MMAP_SIZE>0 here)
// ===========================================================================

fn vdbeSorterExtendFile(db: ?*sqlite3, pFd: ?*sqlite3_file, nByte: i64) void {
    const nMax: i64 = rd(c_int, db, sqlite3_nMaxSorterMmap);
    if (nByte <= nMax and osVersion(pFd) >= 3) {
        var p: ?*anyopaque = null;
        var chunksize: c_int = 4 * 1024;
        sqlite3OsFileControlHint(pFd, SQLITE_FCNTL_CHUNK_SIZE, &chunksize);
        var nb: i64 = nByte;
        sqlite3OsFileControlHint(pFd, SQLITE_FCNTL_SIZE_HINT, &nb);
        _ = sqlite3OsFetch(pFd, 0, @intCast(nByte), &p);
        if (p != null) _ = sqlite3OsUnfetch(pFd, 0, p);
    }
}

fn vdbeSorterOpenTempFile(db: ?*sqlite3, nExtend: i64, ppFd: *?*sqlite3_file) c_int {
    if (sqlite3FaultSim(202) != 0) return SQLITE_IOERR_ACCESS;
    var rc: c_int = 0;
    const pVfs = rd(?*sqlite3_vfs, db, sqlite3_pVfs);
    rc = sqlite3OsOpenMalloc(pVfs, null, ppFd, SQLITE_OPEN_TEMP_JOURNAL |
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
        SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_DELETEONCLOSE, &rc);
    if (rc == SQLITE_OK) {
        var max: i64 = SQLITE_MAX_MMAP_SIZE;
        sqlite3OsFileControlHint(ppFd.*, SQLITE_FCNTL_MMAP_SIZE, &max);
        if (nExtend > 0) {
            vdbeSorterExtendFile(db, ppFd.*, nExtend);
        }
    }
    return rc;
}

fn vdbeSortAllocUnpacked(pTask: *SortSubtask) c_int {
    if (pTask.pUnpacked == null) {
        const u = sqlite3VdbeAllocUnpackedRecord(pTask.pSorter.?.pKeyInfo);
        pTask.pUnpacked = u;
        if (u == null) return SQLITE_NOMEM_BKPT;
        const nKeyField = kiNKeyField(pTask.pSorter.?.pKeyInfo);
        wrU16(u, UnpackedRecord_nField, nKeyField);
        wrU8(u, UnpackedRecord_errCode, 0);
    }
    return SQLITE_OK;
}

// ===========================================================================
// Merge sort of the in-memory list
// ===========================================================================

fn vdbeSorterMerge(pTask: *SortSubtask, p1in: *SorterRecord, p2in: *SorterRecord) *SorterRecord {
    var pFinal: ?*SorterRecord = null;
    var pp: *?*SorterRecord = &pFinal;
    var bCached: c_int = 0;
    var p1: ?*SorterRecord = p1in;
    var p2: ?*SorterRecord = p2in;

    while (true) {
        const res = pTask.xCompare.?(
            pTask,
            &bCached,
            SRVAL(p1.?),
            p1.?.nVal,
            SRVAL(p2.?),
            p2.?.nVal,
        );

        if (res <= 0) {
            pp.* = p1;
            pp = &p1.?.u.pNext;
            p1 = p1.?.u.pNext;
            if (p1 == null) {
                pp.* = p2;
                break;
            }
        } else {
            pp.* = p2;
            pp = &p2.?.u.pNext;
            p2 = p2.?.u.pNext;
            bCached = 0;
            if (p2 == null) {
                pp.* = p1;
                break;
            }
        }
    }
    return pFinal.?;
}

fn vdbeSorterGetCompare(p: *VdbeSorter) SorterCompare {
    if (p.typeMask == SORTER_TYPE_INTEGER) {
        return vdbeSorterCompareInt;
    } else if (p.typeMask == SORTER_TYPE_TEXT) {
        return vdbeSorterCompareText;
    }
    return vdbeSorterCompare;
}

fn vdbeSorterSort(pTask: *SortSubtask, pList: *SorterList) c_int {
    var aSlot: [64]?*SorterRecord = undefined;

    const rc0 = vdbeSortAllocUnpacked(pTask);
    if (rc0 != SQLITE_OK) return rc0;

    var p: ?*SorterRecord = pList.pList;
    pTask.xCompare = vdbeSorterGetCompare(pTask.pSorter.?);
    @memset(&aSlot, null);

    while (p) |pp| {
        var pNext: ?*SorterRecord = undefined;
        if (pList.aMemory) |mem| {
            if (@intFromPtr(pp) == @intFromPtr(mem)) {
                pNext = null;
            } else {
                pNext = @ptrCast(@alignCast(mem + @as(usize, @intCast(pp.u.iNext))));
            }
        } else {
            pNext = pp.u.pNext;
        }

        pp.u.pNext = null;
        var cur: *SorterRecord = pp;
        var i: usize = 0;
        while (aSlot[i] != null) : (i += 1) {
            cur = vdbeSorterMerge(pTask, cur, aSlot[i].?);
            std.debug.assert(i < aSlot.len);
            aSlot[i] = null;
        }
        aSlot[i] = cur;
        p = pNext;
    }

    var pres: ?*SorterRecord = null;
    var i: usize = 0;
    while (i < aSlot.len) : (i += 1) {
        if (aSlot[i] == null) continue;
        pres = if (pres) |r| vdbeSorterMerge(pTask, r, aSlot[i].?) else aSlot[i];
    }
    pList.pList = pres;

    return rdU8(pTask.pUnpacked, UnpackedRecord_errCode);
}

// ===========================================================================
// PmaWriter
// ===========================================================================

fn vdbePmaWriterInit(pFd: ?*sqlite3_file, p: *PmaWriter, nBuf: c_int, iStart: i64) void {
    @memset(std.mem.asBytes(p), 0);
    p.aBuffer = @ptrCast(sqlite3Malloc(@intCast(nBuf)));
    if (p.aBuffer == null) {
        p.eFWErr = SQLITE_NOMEM_BKPT;
    } else {
        p.iBufStart = @intCast(@mod(iStart, nBuf));
        p.iBufEnd = p.iBufStart;
        p.iWriteOff = iStart - p.iBufStart;
        p.nBuffer = nBuf;
        p.pFd = pFd;
    }
}

fn vdbePmaWriteBlob(p: *PmaWriter, pData: [*]const u8, nData: c_int) void {
    var nRem: c_int = nData;
    while (nRem > 0 and p.eFWErr == 0) {
        var nCopy: c_int = nRem;
        if (nCopy > (p.nBuffer - p.iBufEnd)) {
            nCopy = p.nBuffer - p.iBufEnd;
        }

        @memcpy(
            (p.aBuffer.? + @as(usize, @intCast(p.iBufEnd)))[0..@intCast(nCopy)],
            (pData + @as(usize, @intCast(nData - nRem)))[0..@intCast(nCopy)],
        );
        p.iBufEnd += nCopy;
        if (p.iBufEnd == p.nBuffer) {
            p.eFWErr = sqlite3OsWrite(
                p.pFd,
                p.aBuffer.? + @as(usize, @intCast(p.iBufStart)),
                p.iBufEnd - p.iBufStart,
                p.iWriteOff + p.iBufStart,
            );
            p.nPmaSpill += @intCast(p.iBufEnd - p.iBufStart);
            p.iBufStart = 0;
            p.iBufEnd = 0;
            p.iWriteOff += p.nBuffer;
        }
        std.debug.assert(p.iBufEnd < p.nBuffer);
        nRem -= nCopy;
    }
}

fn vdbePmaWriterFinish(p: *PmaWriter, piEof: *i64, pnSpill: *u64) c_int {
    if (p.eFWErr == 0 and p.aBuffer != null and p.iBufEnd > p.iBufStart) {
        p.eFWErr = sqlite3OsWrite(
            p.pFd,
            p.aBuffer.? + @as(usize, @intCast(p.iBufStart)),
            p.iBufEnd - p.iBufStart,
            p.iWriteOff + p.iBufStart,
        );
        p.nPmaSpill += @intCast(p.iBufEnd - p.iBufStart);
    }
    piEof.* = p.iWriteOff + p.iBufEnd;
    pnSpill.* += p.nPmaSpill;
    sqlite3_free(p.aBuffer);
    const rc = p.eFWErr;
    @memset(std.mem.asBytes(p), 0);
    return rc;
}

fn vdbePmaWriteVarint(p: *PmaWriter, iVal: u64) void {
    var aByte: [10]u8 = undefined;
    const nByte = sqlite3PutVarint(&aByte, iVal);
    vdbePmaWriteBlob(p, &aByte, nByte);
}

fn vdbeSorterListToPMA(pTask: *SortSubtask, pList: *SorterList) c_int {
    const db = pTask.pSorter.?.db;
    var rc: c_int = SQLITE_OK;
    var writer: PmaWriter = undefined;

    @memset(std.mem.asBytes(&writer), 0);
    std.debug.assert(pList.szPMA > 0);

    if (pTask.file.pFd == null) {
        rc = vdbeSorterOpenTempFile(db, 0, &pTask.file.pFd);
        std.debug.assert(rc != SQLITE_OK or pTask.file.pFd != null);
    }

    if (rc == SQLITE_OK) {
        vdbeSorterExtendFile(db, pTask.file.pFd, pTask.file.iEof + pList.szPMA + 9);
    }

    if (rc == SQLITE_OK) {
        rc = vdbeSorterSort(pTask, pList);
    }

    if (rc == SQLITE_OK) {
        vdbePmaWriterInit(pTask.file.pFd, &writer, pTask.pSorter.?.pgsz, pTask.file.iEof);
        pTask.nPMA += 1;
        vdbePmaWriteVarint(&writer, @intCast(pList.szPMA));
        var p: ?*SorterRecord = pList.pList;
        while (p) |pp| {
            const pNext = pp.u.pNext;
            vdbePmaWriteVarint(&writer, @intCast(pp.nVal));
            vdbePmaWriteBlob(&writer, SRVAL(pp), pp.nVal);
            if (pList.aMemory == null) sqlite3_free(pp);
            p = pNext;
        }
        pList.pList = p;
        rc = vdbePmaWriterFinish(&writer, &pTask.file.iEof, &pTask.nSpill);
    }

    std.debug.assert(rc != SQLITE_OK or pList.pList == null);
    return rc;
}

// ===========================================================================
// MergeEngine step
// ===========================================================================

fn vdbeMergeEngineStep(pMerger: *MergeEngine, pbEof: *c_int) c_int {
    const iPrev: c_int = pMerger.aTree.?[1];
    const pTask = pMerger.pTask.?;

    const rc = vdbePmaReaderNext(&pMerger.aReadr.?[@intCast(iPrev)]);

    if (rc == SQLITE_OK) {
        var bCached: c_int = 0;
        var pReadr1: *PmaReader = &pMerger.aReadr.?[@intCast(iPrev & 0xFFFE)];
        var pReadr2: *PmaReader = &pMerger.aReadr.?[@intCast(iPrev | 0x0001)];

        const aReadrBase = @intFromPtr(pMerger.aReadr.?);

        var i: c_int = @divTrunc(pMerger.nTree + iPrev, 2);
        while (i > 0) : (i = @divTrunc(i, 2)) {
            var iRes: c_int = undefined;
            if (pReadr1.pFd == null) {
                iRes = 1;
            } else if (pReadr2.pFd == null) {
                iRes = -1;
            } else {
                iRes = pTask.xCompare.?(pTask, &bCached, pReadr1.aKey, pReadr1.nKey, pReadr2.aKey, pReadr2.nKey);
            }

            if (iRes < 0 or (iRes == 0 and @intFromPtr(pReadr1) < @intFromPtr(pReadr2))) {
                pMerger.aTree.?[@intCast(i)] = @intCast((@intFromPtr(pReadr1) - aReadrBase) / @sizeOf(PmaReader));
                pReadr2 = &pMerger.aReadr.?[@intCast(pMerger.aTree.?[@intCast(i ^ 0x0001)])];
                bCached = 0;
            } else {
                if (pReadr1.pFd != null) bCached = 0;
                pMerger.aTree.?[@intCast(i)] = @intCast((@intFromPtr(pReadr2) - aReadrBase) / @sizeOf(PmaReader));
                pReadr1 = &pMerger.aReadr.?[@intCast(pMerger.aTree.?[@intCast(i ^ 0x0001)])];
            }
        }
        pbEof.* = if (pMerger.aReadr.?[@intCast(pMerger.aTree.?[1])].pFd == null) 1 else 0;
    }

    if (rc == SQLITE_OK) {
        return rdU8(pTask.pUnpacked, UnpackedRecord_errCode);
    }
    return rc;
}

// ===========================================================================
// Worker thread entry points
// ===========================================================================

fn vdbeSorterFlushThread(pCtx: ?*anyopaque) callconv(.c) ?*anyopaque {
    const pTask: *SortSubtask = @ptrCast(@alignCast(pCtx));
    std.debug.assert(pTask.bDone == 0);
    const rc = vdbeSorterListToPMA(pTask, &pTask.list);
    pTask.bDone = 1;
    return intToPtr(rc);
}

fn vdbeSorterFlushPMA(pSorter: *VdbeSorter) c_int {
    var rc: c_int = SQLITE_OK;
    var pTask: ?*SortSubtask = null;
    const nWorker: c_int = @as(c_int, pSorter.nTask) - 1;

    pSorter.bUsePMA = 1;

    if (SQLITE_MAX_WORKER_THREADS == 0) {
        return vdbeSorterListToPMA(taskAt(pSorter, 0), &pSorter.list);
    }

    var i: c_int = 0;
    while (i < nWorker) : (i += 1) {
        const iTest: c_int = @mod(@as(c_int, pSorter.iPrev) + i + 1, nWorker);
        pTask = taskAt(pSorter, @intCast(iTest));
        if (pTask.?.bDone != 0) {
            rc = vdbeSorterJoinThread(pTask.?);
        }
        if (rc != SQLITE_OK or pTask.?.pThread == null) break;
    }

    if (rc == SQLITE_OK) {
        if (i == nWorker) {
            rc = vdbeSorterListToPMA(taskAt(pSorter, @intCast(nWorker)), &pSorter.list);
        } else {
            const t = pTask.?;
            std.debug.assert(t.pThread == null and t.bDone == 0);
            std.debug.assert(t.list.pList == null);
            std.debug.assert(t.list.aMemory == null or pSorter.list.aMemory != null);

            const aMem = t.list.aMemory;
            const pCtx: ?*anyopaque = @ptrCast(t);
            pSorter.iPrev = @intCast((@intFromPtr(t) - @intFromPtr(taskAt(pSorter, 0))) / @sizeOf(SortSubtask));
            t.list = pSorter.list;
            pSorter.list.pList = null;
            pSorter.list.szPMA = 0;
            if (aMem) |m| {
                pSorter.list.aMemory = m;
                pSorter.nMemory = sqlite3MallocSize(m);
            } else if (pSorter.list.aMemory != null) {
                pSorter.list.aMemory = @ptrCast(sqlite3Malloc(@intCast(pSorter.nMemory)));
                if (pSorter.list.aMemory == null) return SQLITE_NOMEM_BKPT;
            }

            rc = vdbeSorterCreateThread(t, vdbeSorterFlushThread, pCtx);
        }
    }

    return rc;
}

// ===========================================================================
// sqlite3VdbeSorterWrite
// ===========================================================================
export fn sqlite3VdbeSorterWrite(pCsr: ?*const VdbeCursor, pVal: ?*Mem) callconv(.c) c_int {
    const pSorter = getUcPSorter(pCsr).?;
    var rc: c_int = SQLITE_OK;
    var pNew: *SorterRecord = undefined;

    const valZ = rd([*]u8, pVal, Mem_z);
    const valN = rd(c_int, pVal, Mem_n);

    // getVarint32NR((const u8*)&pVal->z[1], t)
    const t: u32 = getVarint32NR(valZ + 1);
    if (t > 0 and t < 10 and t != 7) {
        pSorter.typeMask &= SORTER_TYPE_INTEGER;
    } else if (t > 10 and (t & 0x01) != 0) {
        pSorter.typeMask &= SORTER_TYPE_TEXT;
    } else {
        pSorter.typeMask = 0;
    }

    const nReq: i64 = @as(i64, valN) + @sizeOf(SorterRecord);
    const nPMA: i64 = @as(i64, valN) + sqlite3VarintLen(@intCast(valN));

    if (pSorter.mxPmaSize != 0) {
        var bFlush: bool = false;
        if (pSorter.list.aMemory != null) {
            bFlush = pSorter.iMemory != 0 and (@as(i64, pSorter.iMemory) + nReq) > pSorter.mxPmaSize;
        } else {
            bFlush = (pSorter.list.szPMA > pSorter.mxPmaSize) or
                (pSorter.list.szPMA > pSorter.mnPmaSize and sqlite3HeapNearlyFull() != 0);
        }
        if (bFlush) {
            rc = vdbeSorterFlushPMA(pSorter);
            pSorter.list.szPMA = 0;
            pSorter.iMemory = 0;
            std.debug.assert(rc != SQLITE_OK or pSorter.list.pList == null);
        }
    }

    pSorter.list.szPMA += nPMA;
    if (nPMA > pSorter.mxKeysize) {
        pSorter.mxKeysize = @intCast(nPMA);
    }

    if (pSorter.list.aMemory != null) {
        const nMin: c_int = pSorter.iMemory + @as(c_int, @intCast(nReq));

        if (nMin > pSorter.nMemory) {
            var nNew: i64 = 2 * @as(i64, pSorter.nMemory);
            var iListOff: i64 = -1;
            if (pSorter.list.pList) |pl| {
                iListOff = @as(i64, @intCast(@intFromPtr(pl) - @intFromPtr(pSorter.list.aMemory.?)));
            }
            while (nNew < nMin) nNew = nNew * 2;
            if (nNew > pSorter.mxPmaSize) nNew = pSorter.mxPmaSize;
            if (nNew < nMin) nNew = nMin;
            const aNew = sqlite3Realloc(pSorter.list.aMemory, @intCast(nNew));
            if (aNew == null) return SQLITE_NOMEM_BKPT;
            const aNewP: [*]u8 = @ptrCast(aNew);
            if (iListOff >= 0) {
                pSorter.list.pList = @ptrCast(@alignCast(aNewP + @as(usize, @intCast(iListOff))));
            }
            pSorter.list.aMemory = aNewP;
            pSorter.nMemory = @intCast(nNew);
        }

        pNew = @ptrCast(@alignCast(pSorter.list.aMemory.? + @as(usize, @intCast(pSorter.iMemory))));
        pSorter.iMemory += @intCast((nReq + 7) & ~@as(i64, 7)); // ROUND8
        if (pSorter.list.pList) |pl| {
            pNew.u.iNext = @intCast(@as(i64, @intCast(@intFromPtr(pl) - @intFromPtr(pSorter.list.aMemory.?))));
        }
    } else {
        const raw = sqlite3Malloc(@intCast(nReq));
        if (raw == null) return SQLITE_NOMEM_BKPT;
        pNew = @ptrCast(@alignCast(raw));
        pNew.u.pNext = pSorter.list.pList;
    }

    @memcpy(SRVAL(pNew)[0..@intCast(valN)], valZ[0..@intCast(valN)]);
    pNew.nVal = valN;
    pSorter.list.pList = pNew;

    return rc;
}

// ===========================================================================
// IncrMerger
// ===========================================================================

fn vdbeIncrPopulate(pIncr: *IncrMerger) c_int {
    var rc: c_int = SQLITE_OK;
    const iStart: i64 = pIncr.iStartOff;
    const pOut: *SorterFile = &pIncr.aFile[1];
    const pTask = pIncr.pTask.?;
    const pMerger = pIncr.pMerger.?;
    var writer: PmaWriter = undefined;
    std.debug.assert(pIncr.bEof == 0);

    vdbePmaWriterInit(pOut.pFd, &writer, pTask.pSorter.?.pgsz, iStart);
    while (rc == SQLITE_OK) {
        var dummy: c_int = undefined;
        const pReader: *PmaReader = &pMerger.aReadr.?[@intCast(pMerger.aTree.?[1])];
        const nKey: c_int = pReader.nKey;
        const iEof: i64 = writer.iWriteOff + writer.iBufEnd;

        if (pReader.pFd == null) break;
        if ((iEof + nKey + sqlite3VarintLen(@intCast(nKey))) > (iStart + pIncr.mxSz)) break;

        vdbePmaWriteVarint(&writer, @intCast(nKey));
        vdbePmaWriteBlob(&writer, pReader.aKey.?, nKey);
        std.debug.assert(pIncr.pMerger.?.pTask == pTask);
        rc = vdbeMergeEngineStep(pIncr.pMerger.?, &dummy);
    }

    const rc2 = vdbePmaWriterFinish(&writer, &pOut.iEof, &pTask.nSpill);
    if (rc == SQLITE_OK) rc = rc2;
    return rc;
}

fn vdbeIncrPopulateThread(pCtx: ?*anyopaque) callconv(.c) ?*anyopaque {
    const pIncr: *IncrMerger = @ptrCast(@alignCast(pCtx));
    const pRet = intToPtr(vdbeIncrPopulate(pIncr));
    pIncr.pTask.?.bDone = 1;
    return pRet;
}

fn vdbeIncrBgPopulate(pIncr: *IncrMerger) c_int {
    std.debug.assert(pIncr.bUseThread != 0);
    return vdbeSorterCreateThread(pIncr.pTask.?, vdbeIncrPopulateThread, @ptrCast(pIncr));
}

fn vdbeIncrSwap(pIncr: *IncrMerger) c_int {
    var rc: c_int = SQLITE_OK;

    if (SQLITE_MAX_WORKER_THREADS > 0 and pIncr.bUseThread != 0) {
        rc = vdbeSorterJoinThread(pIncr.pTask.?);

        if (rc == SQLITE_OK) {
            const f0 = pIncr.aFile[0];
            pIncr.aFile[0] = pIncr.aFile[1];
            pIncr.aFile[1] = f0;
        }

        if (rc == SQLITE_OK) {
            if (pIncr.aFile[0].iEof == pIncr.iStartOff) {
                pIncr.bEof = 1;
            } else {
                rc = vdbeIncrBgPopulate(pIncr);
            }
        }
    } else {
        rc = vdbeIncrPopulate(pIncr);
        pIncr.aFile[0] = pIncr.aFile[1];
        if (pIncr.aFile[0].iEof == pIncr.iStartOff) {
            pIncr.bEof = 1;
        }
    }

    return rc;
}

fn vdbeIncrMergerNew(pTask: *SortSubtask, pMerger: *MergeEngine, ppOut: *?*IncrMerger) c_int {
    var rc: c_int = SQLITE_OK;
    const raw = if (sqlite3FaultSim(100) != 0) null else sqlite3MallocZero(@sizeOf(IncrMerger));
    ppOut.* = @ptrCast(@alignCast(raw));
    if (raw) |r| {
        const pIncr: *IncrMerger = @ptrCast(@alignCast(r));
        pIncr.pMerger = pMerger;
        pIncr.pTask = pTask;
        pIncr.mxSz = @intCast(MAXi(
            @as(i64, pTask.pSorter.?.mxKeysize) + 9,
            @divTrunc(@as(i64, pTask.pSorter.?.mxPmaSize), 2),
        ));
        pTask.file2.iEof += pIncr.mxSz;
    } else {
        vdbeMergeEngineFree(pMerger);
        rc = SQLITE_NOMEM_BKPT;
    }
    std.debug.assert(ppOut.* != null or rc != SQLITE_OK);
    return rc;
}

fn vdbeIncrMergerSetThreads(pIncr: *IncrMerger) void {
    pIncr.bUseThread = 1;
    pIncr.pTask.?.file2.iEof -= pIncr.mxSz;
}

fn vdbeMergeEngineCompare(pMerger: *MergeEngine, iOut: c_int) void {
    var idx1: c_int = undefined;
    var idx2: c_int = undefined;
    var iRes: c_int = undefined;

    std.debug.assert(iOut < pMerger.nTree and iOut > 0);

    if (iOut >= @divTrunc(pMerger.nTree, 2)) {
        idx1 = (iOut - @divTrunc(pMerger.nTree, 2)) * 2;
        idx2 = idx1 + 1;
    } else {
        idx1 = pMerger.aTree.?[@intCast(iOut * 2)];
        idx2 = pMerger.aTree.?[@intCast(iOut * 2 + 1)];
    }

    const p1: *PmaReader = &pMerger.aReadr.?[@intCast(idx1)];
    const p2: *PmaReader = &pMerger.aReadr.?[@intCast(idx2)];

    if (p1.pFd == null) {
        iRes = idx2;
    } else if (p2.pFd == null) {
        iRes = idx1;
    } else {
        const pTask = pMerger.pTask.?;
        var bCached: c_int = 0;
        std.debug.assert(pTask.pUnpacked != null);
        const res = pTask.xCompare.?(pTask, &bCached, p1.aKey, p1.nKey, p2.aKey, p2.nKey);
        iRes = if (res <= 0) idx1 else idx2;
    }

    pMerger.aTree.?[@intCast(iOut)] = iRes;
}

fn vdbeMergeEngineInit(pTask: *SortSubtask, pMerger: *MergeEngine, eMode: c_int) c_int {
    var rc: c_int = SQLITE_OK;

    std.debug.assert(SQLITE_MAX_WORKER_THREADS > 0 or eMode == INCRINIT_NORMAL);
    std.debug.assert(pMerger.pTask == null);
    pMerger.pTask = pTask;

    const nTree: c_int = pMerger.nTree;
    var i: c_int = 0;
    while (i < nTree) : (i += 1) {
        if (SQLITE_MAX_WORKER_THREADS > 0 and eMode == INCRINIT_ROOT) {
            rc = vdbePmaReaderNext(&pMerger.aReadr.?[@intCast(nTree - i - 1)]);
        } else {
            rc = vdbePmaReaderIncrInit(&pMerger.aReadr.?[@intCast(i)], INCRINIT_NORMAL);
        }
        if (rc != SQLITE_OK) return rc;
    }

    i = pMerger.nTree - 1;
    while (i > 0) : (i -= 1) {
        vdbeMergeEngineCompare(pMerger, i);
    }
    return rdU8(pTask.pUnpacked, UnpackedRecord_errCode);
}

fn vdbePmaReaderIncrMergeInit(pReadr: *PmaReader, eMode: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    const pIncr = pReadr.pIncr.?;
    const pTask = pIncr.pTask.?;
    const db = pTask.pSorter.?.db;

    std.debug.assert(SQLITE_MAX_WORKER_THREADS > 0 or eMode == INCRINIT_NORMAL);

    rc = vdbeMergeEngineInit(pTask, pIncr.pMerger.?, eMode);

    if (rc == SQLITE_OK) {
        const mxSz: c_int = pIncr.mxSz;
        if (SQLITE_MAX_WORKER_THREADS > 0 and pIncr.bUseThread != 0) {
            rc = vdbeSorterOpenTempFile(db, mxSz, &pIncr.aFile[0].pFd);
            if (rc == SQLITE_OK) {
                rc = vdbeSorterOpenTempFile(db, mxSz, &pIncr.aFile[1].pFd);
            }
        } else {
            if (pTask.file2.pFd == null) {
                std.debug.assert(pTask.file2.iEof > 0);
                rc = vdbeSorterOpenTempFile(db, pTask.file2.iEof, &pTask.file2.pFd);
                pTask.file2.iEof = 0;
            }
            if (rc == SQLITE_OK) {
                pIncr.aFile[1].pFd = pTask.file2.pFd;
                pIncr.iStartOff = pTask.file2.iEof;
                pTask.file2.iEof += mxSz;
            }
        }
    }

    if (SQLITE_MAX_WORKER_THREADS > 0 and rc == SQLITE_OK and pIncr.bUseThread != 0) {
        std.debug.assert(eMode == INCRINIT_ROOT or eMode == INCRINIT_TASK);
        rc = vdbeIncrPopulate(pIncr);
    }

    if (rc == SQLITE_OK and (SQLITE_MAX_WORKER_THREADS == 0 or eMode != INCRINIT_TASK)) {
        rc = vdbePmaReaderNext(pReadr);
    }

    return rc;
}

fn vdbePmaReaderBgIncrInit(pCtx: ?*anyopaque) callconv(.c) ?*anyopaque {
    const pReader: *PmaReader = @ptrCast(@alignCast(pCtx));
    const pRet = intToPtr(vdbePmaReaderIncrMergeInit(pReader, INCRINIT_TASK));
    pReader.pIncr.?.pTask.?.bDone = 1;
    return pRet;
}

fn vdbePmaReaderIncrInit(pReadr: *PmaReader, eMode: c_int) c_int {
    const pIncr = pReadr.pIncr;
    var rc: c_int = SQLITE_OK;
    if (pIncr) |incr| {
        if (SQLITE_MAX_WORKER_THREADS > 0) {
            std.debug.assert(incr.bUseThread == 0 or eMode == INCRINIT_TASK);
            if (incr.bUseThread != 0) {
                rc = vdbeSorterCreateThread(incr.pTask.?, vdbePmaReaderBgIncrInit, @ptrCast(pReadr));
                return rc;
            }
        }
        rc = vdbePmaReaderIncrMergeInit(pReadr, eMode);
    }
    return rc;
}

fn vdbeMergeEngineLevel0(pTask: *SortSubtask, nPMA: c_int, piOffset: *i64, ppOut: *?*MergeEngine) c_int {
    var iOff: i64 = piOffset.*;
    var rc: c_int = SQLITE_OK;

    const pNew = vdbeMergeEngineNew(nPMA);
    ppOut.* = pNew;
    if (pNew == null) rc = SQLITE_NOMEM_BKPT;

    var i: c_int = 0;
    while (i < nPMA and rc == SQLITE_OK) : (i += 1) {
        var nDummy: i64 = 0;
        const pReadr: *PmaReader = &pNew.?.aReadr.?[@intCast(i)];
        rc = vdbePmaReaderInit(pTask, &pTask.file, iOff, pReadr, &nDummy);
        iOff = pReadr.iEof;
    }

    if (rc != SQLITE_OK) {
        vdbeMergeEngineFree(pNew);
        ppOut.* = null;
    }
    piOffset.* = iOff;
    return rc;
}

fn vdbeSorterTreeDepth(nPMA: c_int) c_int {
    var nDepth: c_int = 0;
    var nDiv: i64 = SORTER_MAX_MERGE_COUNT;
    while (nDiv < @as(i64, nPMA)) {
        nDiv = nDiv * SORTER_MAX_MERGE_COUNT;
        nDepth += 1;
    }
    return nDepth;
}

fn vdbeSorterAddToTree(pTask: *SortSubtask, nDepth: c_int, iSeq: c_int, pRoot: *MergeEngine, pLeaf: *MergeEngine) c_int {
    var nDiv: c_int = 1;
    var p: *MergeEngine = pRoot;
    var pIncr: ?*IncrMerger = null;

    var rc = vdbeIncrMergerNew(pTask, pLeaf, &pIncr);

    var i: c_int = 1;
    while (i < nDepth) : (i += 1) {
        nDiv = nDiv * SORTER_MAX_MERGE_COUNT;
    }

    i = 1;
    while (i < nDepth and rc == SQLITE_OK) : (i += 1) {
        const iIter: c_int = @mod(@divTrunc(iSeq, nDiv), SORTER_MAX_MERGE_COUNT);
        const pReadr: *PmaReader = &p.aReadr.?[@intCast(iIter)];

        if (pReadr.pIncr == null) {
            const pNew = vdbeMergeEngineNew(SORTER_MAX_MERGE_COUNT);
            if (pNew == null) {
                rc = SQLITE_NOMEM_BKPT;
            } else {
                rc = vdbeIncrMergerNew(pTask, pNew.?, &pReadr.pIncr);
            }
        }
        if (rc == SQLITE_OK) {
            p = pReadr.pIncr.?.pMerger.?;
            nDiv = @divTrunc(nDiv, SORTER_MAX_MERGE_COUNT);
        }
    }

    if (rc == SQLITE_OK) {
        p.aReadr.?[@intCast(@mod(iSeq, SORTER_MAX_MERGE_COUNT))].pIncr = pIncr;
    } else {
        vdbeIncrFree(pIncr);
    }
    return rc;
}

fn vdbeSorterMergeTreeBuild(pSorter: *VdbeSorter, ppOut: *?*MergeEngine) c_int {
    var pMain: ?*MergeEngine = null;
    var rc: c_int = SQLITE_OK;

    if (SQLITE_MAX_WORKER_THREADS > 0) {
        std.debug.assert(pSorter.bUseThreads != 0 or pSorter.nTask == 1);
        if (pSorter.nTask > 1) {
            pMain = vdbeMergeEngineNew(@intCast(pSorter.nTask));
            if (pMain == null) rc = SQLITE_NOMEM_BKPT;
        }
    }

    var iTask: c_int = 0;
    while (rc == SQLITE_OK and iTask < pSorter.nTask) : (iTask += 1) {
        const pTask = taskAt(pSorter, @intCast(iTask));
        std.debug.assert(pTask.nPMA > 0 or SQLITE_MAX_WORKER_THREADS > 0);
        if (SQLITE_MAX_WORKER_THREADS == 0 or pTask.nPMA != 0) {
            var pRoot: ?*MergeEngine = null;
            const nDepth: c_int = vdbeSorterTreeDepth(pTask.nPMA);
            var iReadOff: i64 = 0;

            if (pTask.nPMA <= SORTER_MAX_MERGE_COUNT) {
                rc = vdbeMergeEngineLevel0(pTask, pTask.nPMA, &iReadOff, &pRoot);
            } else {
                var iSeq: c_int = 0;
                pRoot = vdbeMergeEngineNew(SORTER_MAX_MERGE_COUNT);
                if (pRoot == null) rc = SQLITE_NOMEM_BKPT;
                var i: c_int = 0;
                while (i < pTask.nPMA and rc == SQLITE_OK) : (i += SORTER_MAX_MERGE_COUNT) {
                    var pMerger: ?*MergeEngine = null;
                    const nReader: c_int = @intCast(MINi(@as(i64, pTask.nPMA - i), SORTER_MAX_MERGE_COUNT));
                    rc = vdbeMergeEngineLevel0(pTask, nReader, &iReadOff, &pMerger);
                    if (rc == SQLITE_OK) {
                        rc = vdbeSorterAddToTree(pTask, nDepth, iSeq, pRoot.?, pMerger.?);
                        iSeq += 1;
                    }
                }
            }

            if (rc == SQLITE_OK) {
                if (SQLITE_MAX_WORKER_THREADS > 0 and pMain != null) {
                    rc = vdbeIncrMergerNew(pTask, pRoot.?, &pMain.?.aReadr.?[@intCast(iTask)].pIncr);
                } else {
                    std.debug.assert(pMain == null);
                    pMain = pRoot;
                }
            } else {
                vdbeMergeEngineFree(pRoot);
            }
        }
    }

    if (rc != SQLITE_OK) {
        vdbeMergeEngineFree(pMain);
        pMain = null;
    }
    ppOut.* = pMain;
    return rc;
}

fn vdbeSorterSetupMerge(pSorter: *VdbeSorter) c_int {
    const pTask0 = taskAt(pSorter, 0);
    var pMain: ?*MergeEngine = null;
    const db = pTask0.pSorter.?.db;

    if (SQLITE_MAX_WORKER_THREADS > 0) {
        const xCompare = vdbeSorterGetCompare(pSorter);
        var i: usize = 0;
        while (i < pSorter.nTask) : (i += 1) {
            taskAt(pSorter, i).xCompare = xCompare;
        }
    }

    var rc = vdbeSorterMergeTreeBuild(pSorter, &pMain);
    if (rc == SQLITE_OK) {
        if (SQLITE_MAX_WORKER_THREADS > 0 and pSorter.bUseThreads != 0) {
            std.debug.assert(pSorter.nTask > 1);
            var pReadr: ?*PmaReader = null;
            const pLast = taskAt(pSorter, @as(usize, pSorter.nTask) - 1);
            rc = vdbeSortAllocUnpacked(pLast);
            if (rc == SQLITE_OK) {
                pReadr = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @sizeOf(PmaReader))));
                pSorter.pReader = pReadr;
                if (pReadr == null) rc = SQLITE_NOMEM_BKPT;
            }
            if (rc == SQLITE_OK) {
                rc = vdbeIncrMergerNew(pLast, pMain.?, &pReadr.?.pIncr);
                if (rc == SQLITE_OK) {
                    vdbeIncrMergerSetThreads(pReadr.?.pIncr.?);
                    var iTask: c_int = 0;
                    while (iTask < @as(c_int, pSorter.nTask) - 1) : (iTask += 1) {
                        if (pMain.?.aReadr.?[@intCast(iTask)].pIncr) |pIncr| {
                            vdbeIncrMergerSetThreads(pIncr);
                            std.debug.assert(pIncr.pTask != pLast);
                        }
                    }
                    iTask = 0;
                    while (rc == SQLITE_OK and iTask < pSorter.nTask) : (iTask += 1) {
                        const p = &pMain.?.aReadr.?[@intCast(iTask)];
                        std.debug.assert(p.pIncr == null or
                            (p.pIncr.?.pTask == taskAt(pSorter, @intCast(iTask)) and
                                (iTask != @as(c_int, pSorter.nTask) - 1 or p.pIncr.?.bUseThread == 0)));
                        rc = vdbePmaReaderIncrInit(p, INCRINIT_TASK);
                    }
                }
                pMain = null;
            }
            if (rc == SQLITE_OK) {
                rc = vdbePmaReaderIncrMergeInit(pReadr.?, INCRINIT_ROOT);
            }
        } else {
            rc = vdbeMergeEngineInit(pTask0, pMain.?, INCRINIT_NORMAL);
            pSorter.pMerger = pMain;
            pMain = null;
        }
    }

    if (rc != SQLITE_OK) {
        vdbeMergeEngineFree(pMain);
    }
    return rc;
}

// ===========================================================================
// sqlite3VdbeSorterRewind / Next / Rowkey / Compare
// ===========================================================================
export fn sqlite3VdbeSorterRewind(pCsr: ?*const VdbeCursor, pbEof: *c_int) callconv(.c) c_int {
    const pSorter = getUcPSorter(pCsr).?;
    var rc: c_int = SQLITE_OK;

    if (pSorter.bUsePMA == 0) {
        if (pSorter.list.pList != null) {
            pbEof.* = 0;
            rc = vdbeSorterSort(taskAt(pSorter, 0), &pSorter.list);
        } else {
            pbEof.* = 1;
        }
        return rc;
    }

    std.debug.assert(pSorter.list.pList != null);
    rc = vdbeSorterFlushPMA(pSorter);

    rc = vdbeSorterJoinAll(pSorter, rc);

    std.debug.assert(pSorter.pReader == null);
    if (rc == SQLITE_OK) {
        rc = vdbeSorterSetupMerge(pSorter);
        pbEof.* = 0;
    }

    return rc;
}

export fn sqlite3VdbeSorterNext(db: ?*sqlite3, pCsr: ?*const VdbeCursor) callconv(.c) c_int {
    const pSorter = getUcPSorter(pCsr).?;
    var rc: c_int = undefined;

    std.debug.assert(pSorter.bUsePMA != 0 or (pSorter.pReader == null and pSorter.pMerger == null));
    if (pSorter.bUsePMA != 0) {
        std.debug.assert(pSorter.pReader == null or pSorter.pMerger == null);
        if (SQLITE_MAX_WORKER_THREADS > 0 and pSorter.bUseThreads != 0) {
            rc = vdbePmaReaderNext(pSorter.pReader.?);
            if (rc == SQLITE_OK and pSorter.pReader.?.pFd == null) rc = SQLITE_DONE;
        } else {
            var res: c_int = 0;
            std.debug.assert(pSorter.pMerger != null);
            rc = vdbeMergeEngineStep(pSorter.pMerger.?, &res);
            if (rc == SQLITE_OK and res != 0) rc = SQLITE_DONE;
        }
    } else {
        const pFree = pSorter.list.pList.?;
        pSorter.list.pList = pFree.u.pNext;
        pFree.u.pNext = null;
        if (pSorter.list.aMemory == null) vdbeSorterRecordFree(db, pFree);
        rc = if (pSorter.list.pList != null) SQLITE_OK else SQLITE_DONE;
    }
    return rc;
}

fn vdbeSorterRowkey(pSorter: *VdbeSorter, pnKey: *c_int) [*]u8 {
    if (pSorter.bUsePMA != 0) {
        var pReader: *PmaReader = undefined;
        if (SQLITE_MAX_WORKER_THREADS > 0 and pSorter.bUseThreads != 0) {
            pReader = pSorter.pReader.?;
        } else {
            pReader = &pSorter.pMerger.?.aReadr.?[@intCast(pSorter.pMerger.?.aTree.?[1])];
        }
        pnKey.* = pReader.nKey;
        return pReader.aKey.?;
    } else {
        pnKey.* = pSorter.list.pList.?.nVal;
        return SRVAL(pSorter.list.pList.?);
    }
}

export fn sqlite3VdbeSorterRowkey(pCsr: ?*const VdbeCursor, pOut: ?*Mem) callconv(.c) c_int {
    const pSorter = getUcPSorter(pCsr).?;
    var nKey: c_int = undefined;
    const pKey = vdbeSorterRowkey(pSorter, &nKey);
    if (sqlite3VdbeMemClearAndResize(pOut, nKey) != 0) {
        return SQLITE_NOMEM_BKPT;
    }
    // pOut->n = nKey
    wrMemN(pOut, nKey);
    memSetTypeFlagBlob(pOut);
    const outZ = rd([*]u8, pOut, Mem_z);
    @memcpy(outZ[0..@intCast(nKey)], pKey[0..@intCast(nKey)]);
    return SQLITE_OK;
}

inline fn wrMemN(pMem: ?*Mem, n: c_int) void {
    const base: [*]u8 = @ptrCast(pMem.?);
    @as(*c_int, @ptrCast(@alignCast(base + Mem_n))).* = n;
}
inline fn memSetTypeFlagBlob(pMem: ?*Mem) void {
    const base: [*]u8 = @ptrCast(pMem.?);
    const pFlags: *u16 = @ptrCast(@alignCast(base + Mem_flags));
    pFlags.* = (pFlags.* & ~(MEM_TypeMask | MEM_Zero)) | MEM_Blob;
}

export fn sqlite3VdbeSorterCompare(pCsr: ?*const VdbeCursor, pVal: ?*Mem, nKeyCol: c_int, pRes: *c_int) callconv(.c) c_int {
    const pSorter = getUcPSorter(pCsr).?;
    const pKeyInfo = rd(?*KeyInfo, pCsr, VdbeCursor_pKeyInfo);

    var r2 = pSorter.pUnpacked;
    if (r2 == null) {
        r2 = sqlite3VdbeAllocUnpackedRecord(pKeyInfo);
        pSorter.pUnpacked = r2;
        if (r2 == null) return SQLITE_NOMEM_BKPT;
        wrU16(r2, UnpackedRecord_nField, @intCast(nKeyCol));
    }
    std.debug.assert(rd(u16, r2, UnpackedRecord_nField) == nKeyCol);

    var nKey: c_int = undefined;
    const pKey = vdbeSorterRowkey(pSorter, &nKey);
    sqlite3VdbeRecordUnpack(nKey, pKey, r2);

    // for i in 0..nKeyCol: if r2->aMem[i].flags & MEM_Null { *pRes=-1; return OK }
    const aMem = rd(?*anyopaque, r2, UnpackedRecord_aMem);
    var i: c_int = 0;
    while (i < nKeyCol) : (i += 1) {
        const pMemI: [*]u8 = @as([*]u8, @ptrCast(aMem.?)) + @as(usize, @intCast(i)) * sizeof_Mem;
        const flags = @as(*const u16, @ptrCast(@alignCast(pMemI + Mem_flags))).*;
        if ((flags & MEM_Null) != 0) {
            pRes.* = -1;
            return SQLITE_OK;
        }
    }

    const valN = rd(c_int, pVal, Mem_n);
    const valZ = rd(?*const anyopaque, pVal, Mem_z);
    pRes.* = sqlite3VdbeRecordCompare(valN, valZ, r2);
    return SQLITE_OK;
}
