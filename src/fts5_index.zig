//! Zig port of the fts5_index.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 9608-19169 == ext/fts5/fts5_index.c).
//!
//! Low-level access to the FTS index stored in the database file. This module
//! implements all read and write access to the %_data and %_idx shadow tables:
//! the on-disk segment b-tree, doclist/poslist encoding, segment readers and
//! writers, the multi-way merge, prefix indexes, the structure record, the
//! page-based segment format, integrity-check, optimize/merge and the
//! fts5_decode()/fts5_structure() debug UDFs.
//!
//! Imports the shared foundation (fts5_int.zig) for the cross-section types and
//! constants. Every struct named in the C source that never crosses a section
//! boundary by value (Fts5Data / Fts5Structure* / Fts5SegIter / Fts5Iter /
//! Fts5DlidxIter / Fts5PageWriter / Fts5SegWriter / ...) is section-private and
//! is defined here as an `extern struct` mirroring the C layout byte-for-byte.
//!
//! The on-disk binary format is byte-exact: varints via the fts5_varint.c
//! codec, big-endian page headers/idx page numbers via the fts5GetU*/fts5PutU*
//! helpers, the position-list/rowid delta encodings reproduced shift-for-shift.

const std = @import("std");
const config = @import("config");
const int = @import("fts5_int.zig");

// ===========================================================================
// Scalar aliases (fts5Int.h).
// ===========================================================================
const u8_t = u8;
const u16_t = u16;
const u32_t = u32;
const u64_t = u64;
const i16_t = i16;
const i64_t = i64;

// ===========================================================================
// Shared foundation types / constants.
// ===========================================================================
const Fts5Config = int.Fts5Config;
const Fts5Buffer = int.Fts5Buffer;
const Fts5Colset = int.Fts5Colset;
const Fts5IndexIter = int.Fts5IndexIter;
const Fts5PoslistReader = int.Fts5PoslistReader;
const Fts5PoslistWriter = int.Fts5PoslistWriter;
const Fts5Hash = int.Fts5Hash;
const Fts5Index = int.Fts5Index; // opaque foundation handle; concrete below as Fts5IndexS
const sqlite3 = int.sqlite3;
const sqlite3_stmt = int.sqlite3_stmt;
const sqlite3_blob = int.sqlite3_blob;
const sqlite3_context = int.sqlite3_context;
const sqlite3_value = int.sqlite3_value;
const sqlite3_vtab = int.sqlite3_vtab;
const sqlite3_vtab_cursor = int.sqlite3_vtab_cursor;
const sqlite3_index_info = int.sqlite3_index_info;
const sqlite3_module = int.sqlite3_module;
const colsetCol = int.colsetCol;

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_ERROR = int.SQLITE_ERROR;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_CORRUPT = int.SQLITE_CORRUPT;
const SQLITE_CORRUPT_VTAB = int.SQLITE_CORRUPT_VTAB;
const SQLITE_ABORT = int.SQLITE_ABORT;
const SQLITE_RANGE = int.SQLITE_RANGE;
const SQLITE_ROW = int.SQLITE_ROW;
const SQLITE_DONE = int.SQLITE_DONE;
const SQLITE_INTEGER = int.SQLITE_INTEGER;
const SQLITE_BLOB = int.SQLITE_BLOB;
const SQLITE_NULL = int.SQLITE_NULL;
const SQLITE_UTF8 = int.SQLITE_UTF8;

const FTS5_DETAIL_NONE = int.FTS5_DETAIL_NONE;
const FTS5_DETAIL_FULL = int.FTS5_DETAIL_FULL;
const FTS5_DETAIL_COLUMNS = int.FTS5_DETAIL_COLUMNS;
const FTS5_MAX_PREFIX_INDEXES = int.FTS5_MAX_PREFIX_INDEXES;
const FTS5_MAX_SEGMENT = int.FTS5_MAX_SEGMENT;
const FTS5_CURRENT_VERSION = int.FTS5_CURRENT_VERSION;
const FTS5_CURRENT_VERSION_SECUREDELETE = int.FTS5_CURRENT_VERSION_SECUREDELETE;
const FTS5_CONTENT_NORMAL = int.FTS5_CONTENT_NORMAL;
const FTS5_CONTENT_NONE = int.FTS5_CONTENT_NONE;

const FTS5INDEX_QUERY_PREFIX = int.FTS5INDEX_QUERY_PREFIX;
const FTS5INDEX_QUERY_DESC = int.FTS5INDEX_QUERY_DESC;
const FTS5INDEX_QUERY_TEST_NOIDX = int.FTS5INDEX_QUERY_TEST_NOIDX;
const FTS5INDEX_QUERY_SCAN = int.FTS5INDEX_QUERY_SCAN;
const FTS5INDEX_QUERY_SKIPEMPTY = int.FTS5INDEX_QUERY_SKIPEMPTY;
const FTS5INDEX_QUERY_NOOUTPUT = int.FTS5INDEX_QUERY_NOOUTPUT;
const FTS5INDEX_QUERY_SKIPHASH = int.FTS5INDEX_QUERY_SKIPHASH;
const FTS5INDEX_QUERY_NOTOKENDATA = int.FTS5INDEX_QUERY_NOTOKENDATA;
const FTS5INDEX_QUERY_SCANONETERM = int.FTS5INDEX_QUERY_SCANONETERM;

const LARGEST_INT64 = int.LARGEST_INT64;
const SMALLEST_INT64 = int.SMALLEST_INT64;

const FTS5_POS2COLUMN = int.FTS5_POS2COLUMN;
const FTS5_POS2OFFSET = int.FTS5_POS2OFFSET;

// SQLITE_FTS5_DETAIL helpers
const SQLITE_PREPARE_PERSISTENT: c_int = 0x01;
const SQLITE_PREPARE_NO_VTAB: c_int = 0x04;

// fts5_index.c local #defines
const FTS5_OPT_WORK_UNIT: c_int = 1000;
const FTS5_WORK_UNIT: c_int = 64;
const FTS5_MIN_DLIDX_SIZE: c_int = 4;
const FTS5_MAIN_PREFIX: u8 = '0';
const FTS5_MAX_LEVEL: c_int = 64;
const FTS5_STRUCTURE_V2 = "\xFF\x00\x00\x01"; // 4 bytes

const FTS5_AVERAGES_ROWID: i64 = 1;
const FTS5_STRUCTURE_ROWID: i64 = 10;

// %_data rowid bit layout
const FTS5_DATA_ID_B: u6 = 16; // Max seg id number 65535
const FTS5_DATA_DLI_B: u6 = 1; // Doclist-index flag (1 bit)
const FTS5_DATA_HEIGHT_B: u6 = 5; // Max dlidx tree height of 32
const FTS5_DATA_PAGE_B: u6 = 31; // Max page number of 2147483648

const FTS5_DATA_ZERO_PADDING: c_int = 8;
const FTS5_DATA_PADDING: usize = 20;

const FTS5_CORRUPT = SQLITE_CORRUPT_VTAB;

// Core sqlite3 result code used by fts5AllocateSegid (sqlite3.h).
const SQLITE_FULL: c_int = 13;

const FTS5_SEGITER_ONETERM: c_int = 0x01;
const FTS5_SEGITER_REVERSE: c_int = 0x02;

// fts5_dri(segid,dlidx,height,pgno): the %_data rowid encoding.
inline fn fts5_dri(segid: i64, dlidx: i64, height: i64, pgno: i64) i64 {
    return (segid << (FTS5_DATA_PAGE_B + FTS5_DATA_HEIGHT_B + FTS5_DATA_DLI_B)) +%
        (dlidx << (FTS5_DATA_PAGE_B + FTS5_DATA_HEIGHT_B)) +%
        (height << (FTS5_DATA_PAGE_B)) +%
        (pgno);
}
inline fn FTS5_SEGMENT_ROWID(segid: c_int, pgno: c_int) i64 {
    return fts5_dri(@intCast(segid), 0, 0, @intCast(pgno));
}
inline fn FTS5_DLIDX_ROWID(segid: c_int, height: c_int, pgno: c_int) i64 {
    return fts5_dri(@intCast(segid), 1, @intCast(height), @intCast(pgno));
}
inline fn FTS5_TOMBSTONE_ROWID(segid: c_int, ipg: c_int) i64 {
    return fts5_dri(@as(i64, @intCast(segid)) + (1 << 16), 0, 0, @intCast(ipg));
}

inline fn MIN(comptime T: type, a: T, b: T) T {
    return if (a < b) a else b;
}
inline fn MAX(comptime T: type, a: T, b: T) T {
    return if (a > b) a else b;
}

// ===========================================================================
// Section-private structs (mirror fts5_index.c byte-for-byte).
// ===========================================================================

/// struct Fts5Data { u8 *p; int nn; int szLeaf; }.
const Fts5Data = extern struct {
    p: ?[*]u8, // Pointer to buffer containing record
    nn: c_int, // Size of record in bytes
    szLeaf: c_int, // Size of leaf without page-index
};

/// struct Fts5Index — the concrete layout behind int.Fts5Index (opaque).
const Fts5IndexS = extern struct {
    pConfig: ?*Fts5Config, // Virtual table configuration
    zDataTbl: ?[*:0]u8, // Name of %_data table
    nWorkUnit: c_int, // Leaf pages in a "unit" of work

    pHash: ?*Fts5Hash, // Hash table for in-memory data
    nPendingData: c_int, // Current bytes of pending data
    iWriteRowid: i64, // Rowid for current doc being written
    bDelete: c_int, // Current write is a delete
    nContentlessDelete: c_int, // Number of contentless delete ops
    nPendingRow: c_int, // Number of INSERT in hash table

    rc: c_int, // Current error code
    flushRc: c_int,

    pReader: ?*sqlite3_blob, // RO incr-blob open on %_data table
    pWriter: ?*sqlite3_stmt, // "INSERT ... %_data VALUES(?,?)"
    pDeleter: ?*sqlite3_stmt, // "DELETE FROM %_data ... id>=? AND id<=?"
    pIdxWriter: ?*sqlite3_stmt, // "INSERT ... %_idx VALUES(?,?,?,?)"
    pIdxDeleter: ?*sqlite3_stmt, // "DELETE FROM %_idx WHERE segid=?"
    pIdxSelect: ?*sqlite3_stmt,
    pIdxNextSelect: ?*sqlite3_stmt,
    nRead: c_int, // Total number of blocks read

    pDeleteFromIdx: ?*sqlite3_stmt,

    pDataVersion: ?*sqlite3_stmt,
    iStructVersion: i64, // data_version when pStruct read
    pStruct: ?*Fts5Structure, // Current db structure (or NULL)
};

/// struct Fts5DoclistIter.
const Fts5DoclistIter = extern struct {
    aEof: ?[*]u8, // Pointer to 1 byte past end of doclist
    iRowid: i64,
    aPoslist: ?[*]u8, // ==0 at EOF
    nPoslist: c_int,
    nSize: c_int,
};

/// struct Fts5StructureSegment.
const Fts5StructureSegment = extern struct {
    iSegid: c_int, // Segment id
    pgnoFirst: c_int, // First leaf page number in segment
    pgnoLast: c_int, // Last leaf page number in segment
    // contentlessdelete=1 tables only:
    iOrigin1: u64,
    iOrigin2: u64,
    nPgTombstone: c_int, // Number of tombstone hash table pages
    nEntryTombstone: u64, // Number of tombstone entries that "count"
    nEntry: u64, // Number of rows in this segment
};

/// struct Fts5StructureLevel.
const Fts5StructureLevel = extern struct {
    nMerge: c_int, // Number of segments in incr-merge
    nSeg: c_int, // Total number of segments on level
    aSeg: ?[*]Fts5StructureSegment, // Array; aSeg[0] is oldest
};

/// struct Fts5Structure — aLevel is a flexible array member.
const Fts5Structure = extern struct {
    nRef: c_int, // Object reference count
    nWriteCounter: u64, // Total leaves written to level 0
    nOriginCntr: u64, // Origin value for next top-level segment
    nSegment: c_int, // Total segments in this structure
    nLevel: c_int, // Number of levels in this index
    aLevel: [0]Fts5StructureLevel, // FLEXARRAY
};
/// SZ_FTS5STRUCTURE(N) == offsetof(aLevel) + N*sizeof(level).
inline fn SZ_FTS5STRUCTURE(n: c_int) i64 {
    return @as(i64, @intCast(@offsetOf(Fts5Structure, "aLevel"))) +
        @as(i64, @intCast(n)) * @sizeOf(Fts5StructureLevel);
}
inline fn structLevel(p: *Fts5Structure, i: c_int) *Fts5StructureLevel {
    const a: [*]Fts5StructureLevel = @ptrCast(&p.aLevel);
    return &a[@intCast(i)];
}

/// struct Fts5PageWriter.
const Fts5PageWriter = extern struct {
    pgno: c_int, // Page number for this page
    iPrevPgidx: c_int, // Previous value written into pgidx
    buf: Fts5Buffer, // Buffer containing leaf data
    pgidx: Fts5Buffer, // Buffer containing page-index
    term: Fts5Buffer, // Buffer containing previous term on page
};
/// struct Fts5DlidxWriter.
const Fts5DlidxWriter = extern struct {
    pgno: c_int, // Page number for this page
    bPrevValid: c_int, // True if iPrev is valid
    iPrev: i64, // Previous rowid value written to page
    buf: Fts5Buffer, // Buffer containing page data
};
/// struct Fts5SegWriter.
const Fts5SegWriter = extern struct {
    iSegid: c_int, // Segid to write to
    writer: Fts5PageWriter, // PageWriter object
    iPrevRowid: i64, // Previous rowid written to current leaf
    bFirstRowidInDoclist: u8, // True if next rowid is first in doclist
    bFirstRowidInPage: u8, // True if next rowid is first in page
    bFirstTermInPage: u8, // True if next term will be first in leaf
    nLeafWritten: c_int, // Number of leaf pages written
    nEmpty: c_int, // Number of contiguous term-less nodes

    nDlidx: c_int, // Allocated size of aDlidx[] array
    aDlidx: ?[*]Fts5DlidxWriter, // Array of Fts5DlidxWriter objects

    btterm: Fts5Buffer, // Next term to insert into %_idx table
    iBtPage: c_int, // Page number corresponding to btterm
};

/// struct Fts5CResult.
const Fts5CResult = extern struct {
    iFirst: u16, // aSeg[] index of firstest iterator
    bTermEq: u8, // True if the terms are equal
};

/// struct Fts5SegIter. xNext is a function pointer.
const Fts5SegIter = extern struct {
    pSeg: ?*Fts5StructureSegment, // Segment to iterate through
    flags: c_int, // Mask of configuration flags
    iLeafPgno: c_int, // Current leaf page number
    pLeaf: ?*Fts5Data, // Current leaf data
    pNextLeaf: ?*Fts5Data, // Leaf page (iLeafPgno+1)
    iLeafOffset: i64, // Byte offset within current leaf
    pTombArray: ?*Fts5TombstoneArray, // Array of tombstone pages

    xNext: ?*const fn (?*Fts5IndexS, ?*Fts5SegIter, ?*c_int) callconv(.c) void,

    iTermLeafPgno: c_int,
    iTermLeafOffset: c_int,

    iPgidxOff: c_int, // Next offset in pgidx
    iEndofDoclist: c_int,

    iRowidOffset: c_int, // Current entry in aRowidOffset[]
    nRowidOffset: c_int, // Allocated size of aRowidOffset[] array
    aRowidOffset: ?[*]c_int, // Array of offset to rowid fields

    pDlidx: ?*Fts5DlidxIter, // If there is a doclist-index

    term: Fts5Buffer, // Current term
    iRowid: i64, // Current rowid
    nPos: c_int, // Number of bytes in current position list
    bDel: u8, // True if the delete flag is set
};

/// struct Fts5TombstoneArray — apTombstone is a flexible array member.
const Fts5TombstoneArray = extern struct {
    nRef: c_int, // Number of pointers to this object
    nTombstone: c_int,
    apTombstone: [0]?*Fts5Data, // FLEXARRAY
};
inline fn SZ_FTS5TOMBSTONEARRAY(n: i64) i64 {
    return @as(i64, @intCast(@offsetOf(Fts5TombstoneArray, "apTombstone"))) +
        n * @sizeOf(?*Fts5Data);
}
inline fn tombstonePtr(p: *Fts5TombstoneArray, i: c_int) *?*Fts5Data {
    const a: [*]?*Fts5Data = @ptrCast(&p.apTombstone);
    return &a[@intCast(i)];
}

/// struct Fts5Iter — aSeg is a flexible array member. xSetOutputs is a fn ptr.
const Fts5Iter = extern struct {
    base: Fts5IndexIter, // Base class containing output vars
    pTokenDataIter: ?*Fts5TokenDataIter,

    pIndex: ?*Fts5IndexS, // Index that owns this iterator
    poslist: Fts5Buffer, // Buffer containing current poslist
    pColset: ?*Fts5Colset, // Restrict matches to these columns

    xSetOutputs: ?*const fn (?*Fts5Iter, ?*Fts5SegIter) callconv(.c) void,

    nSeg: c_int, // Size of aSeg[] array
    bRev: c_int, // True to iterate in reverse order
    bSkipEmpty: u8, // True to skip deleted entries

    iSwitchRowid: i64, // Firstest rowid of other than aFirst[1]
    aFirst: ?[*]Fts5CResult, // Current merge state
    aSeg: [0]Fts5SegIter, // FLEXARRAY
};
inline fn SZ_FTS5ITER(n: i64) i64 {
    return @as(i64, @intCast(@offsetOf(Fts5Iter, "aSeg"))) + n * @sizeOf(Fts5SegIter);
}
inline fn iterSeg(p: *Fts5Iter, i: c_int) *Fts5SegIter {
    const a: [*]Fts5SegIter = @ptrCast(&p.aSeg);
    return &a[@intCast(i)];
}

/// struct Fts5DlidxLvl.
const Fts5DlidxLvl = extern struct {
    pData: ?*Fts5Data, // Data for current page of this level
    iOff: c_int, // Current offset into pData
    bEof: c_int, // At EOF already
    iFirstOff: c_int, // Used by reverse iterators
    iLeafPgno: c_int, // Page number of current leaf page
    iRowid: i64, // First rowid on leaf iLeafPgno
};
/// struct Fts5DlidxIter — aLvl is a flexible array member.
const Fts5DlidxIter = extern struct {
    nLvl: c_int,
    iSegid: c_int,
    aLvl: [0]Fts5DlidxLvl, // FLEXARRAY
};
inline fn SZ_FTS5DLIDXITER(n: i64) i64 {
    return @as(i64, @intCast(@offsetOf(Fts5DlidxIter, "aLvl"))) + n * @sizeOf(Fts5DlidxLvl);
}
inline fn dlidxLvl(p: *Fts5DlidxIter, i: c_int) *Fts5DlidxLvl {
    const a: [*]Fts5DlidxLvl = @ptrCast(&p.aLvl);
    return &a[@intCast(i)];
}

/// struct Fts5TokenDataMap.
const Fts5TokenDataMap = extern struct {
    iRowid: i64, // Row this token is located in
    iPos: i64, // Position of token
    iIter: c_int, // Iterator token was read from
    nByte: c_int, // Length of token in bytes (or 0)
};

/// struct Fts5TokenDataIter — apIter is a flexible array member.
const Fts5TokenDataIter = extern struct {
    nMapAlloc: i64, // Allocated size of aMap[] in entries
    nMap: i64, // Number of valid entries in aMap[]
    aMap: ?[*]Fts5TokenDataMap, // Array of (rowid+pos -> token) mappings

    // The following are used for prefix-queries only.
    terms: Fts5Buffer,

    // The following are used for other full-token tokendata queries only.
    nIter: i64,
    nIterAlloc: i64,
    aPoslistReader: ?[*]Fts5PoslistReader,
    aPoslistToIter: ?[*]c_int,
    apIter: [0]?*Fts5Iter, // FLEXARRAY
};
// SZ_FTS5TOKENDATAITER(N) == offsetof(apIter) + N*sizeof(Fts5Iter).
// NOTE: the C macro multiplies by sizeof(Fts5Iter) (the full struct), not by
// the pointer size — an intentional over-allocation. Mirror it exactly.
inline fn SZ_FTS5TOKENDATAITER(n: i64) i64 {
    return @as(i64, @intCast(@offsetOf(Fts5TokenDataIter, "apIter"))) + n * @sizeOf(Fts5Iter);
}
inline fn tokenDataIterApIter(p: *Fts5TokenDataIter, i: c_int) *?*Fts5Iter {
    const a: [*]?*Fts5Iter = @ptrCast(&p.apIter);
    return &a[@intCast(i)];
}

// ===========================================================================
// Big-endian byte helpers (fts5_index.c fts5GetU*/fts5PutU*).
// ===========================================================================
inline fn fts5PutU16(aOut: [*]u8, iVal: u16) void {
    aOut[0] = @truncate(iVal >> 8);
    aOut[1] = @truncate(iVal & 0xFF);
}
inline fn fts5GetU16(aIn: [*]const u8) u16 {
    return (@as(u16, aIn[0]) << 8) +% aIn[1];
}
inline fn fts5GetU64(a: [*]const u8) u64 {
    return (@as(u64, a[0]) << 56) +%
        (@as(u64, a[1]) << 48) +%
        (@as(u64, a[2]) << 40) +%
        (@as(u64, a[3]) << 32) +%
        (@as(u64, a[4]) << 24) +%
        (@as(u64, a[5]) << 16) +%
        (@as(u64, a[6]) << 8) +%
        (@as(u64, a[7]) << 0);
}
inline fn fts5GetU32(a: [*]const u8) u32 {
    return (@as(u32, a[0]) << 24) +%
        (@as(u32, a[1]) << 16) +%
        (@as(u32, a[2]) << 8) +%
        (@as(u32, a[3]) << 0);
}
inline fn fts5PutU64(a: [*]u8, iVal: u64) void {
    a[0] = @truncate((iVal >> 56) & 0xFF);
    a[1] = @truncate((iVal >> 48) & 0xFF);
    a[2] = @truncate((iVal >> 40) & 0xFF);
    a[3] = @truncate((iVal >> 32) & 0xFF);
    a[4] = @truncate((iVal >> 24) & 0xFF);
    a[5] = @truncate((iVal >> 16) & 0xFF);
    a[6] = @truncate((iVal >> 8) & 0xFF);
    a[7] = @truncate((iVal >> 0) & 0xFF);
}
inline fn fts5PutU32(a: [*]u8, iVal: u32) void {
    a[0] = @truncate((iVal >> 24) & 0xFF);
    a[1] = @truncate((iVal >> 16) & 0xFF);
    a[2] = @truncate((iVal >> 8) & 0xFF);
    a[3] = @truncate((iVal >> 0) & 0xFF);
}

// fts5GetVarint32(a,b): b = varint(a), returns bytes read. b is a c_int/u32 lvalue.
inline fn fts5GetVarint32Into(comptime T: type, a: [*]const u8, b: *T) c_int {
    var v: u32 = undefined;
    const n = sqlite3Fts5GetVarint32(a, &v);
    b.* = if (T == u32) v else @bitCast(v);
    return n;
}
// fts5GetVarint(a,&v): returns bytes read (u8 in C).
inline fn fts5GetVarint(a: [*]const u8, v: *u64) c_int {
    return sqlite3Fts5GetVarint(a, v);
}
// fts5FastGetVarint32(a, iOff, nVal): nVal=(a)[iOff++]; if high bit set, full varint.
inline fn fts5FastGetVarint32(comptime T: type, a: [*]const u8, iOff: *c_int, nVal: *T) void {
    const first = a[@intCast(iOff.*)];
    iOff.* += 1;
    if (first & 0x80 != 0) {
        iOff.* -= 1;
        var v: u32 = undefined;
        iOff.* += sqlite3Fts5GetVarint32(a + @as(usize, @intCast(iOff.*)), &v);
        nVal.* = if (T == u32) v else @bitCast(v);
    } else {
        nVal.* = if (T == u32) @as(u32, first) else @intCast(first);
    }
}

// fts5Memcmp(s1,s2,n): ((n)<=0 ? 0 : memcmp(s1,s2,n)).
inline fn fts5Memcmp(s1: ?[*]const u8, s2: ?[*]const u8, n: c_int) c_int {
    if (n <= 0) return 0;
    return memcmp(s1, s2, @intCast(n));
}

// fts5BufferSafeAppendBlob/Varint macros (assert elided in release).
inline fn fts5BufferSafeAppendBlob(pBuf: *Fts5Buffer, pBlob: [*]const u8, nBlob: c_int) void {
    _ = memcpy(pBuf.p.? + @as(usize, @intCast(pBuf.n)), pBlob, @intCast(nBlob));
    pBuf.n += nBlob;
}
inline fn fts5BufferSafeAppendVarint(pBuf: *Fts5Buffer, iVal: i64) void {
    pBuf.n += sqlite3Fts5PutVarint(pBuf.p.? + @as(usize, @intCast(pBuf.n)), @bitCast(iVal));
}

// fts5Int.h macro wrappers (centralised; one definition for the whole file).
inline fn fts5BufferZero(pBuf: *Fts5Buffer) void {
    sqlite3Fts5BufferZero(pBuf);
}
inline fn fts5BufferFree(pBuf: *Fts5Buffer) void {
    sqlite3Fts5BufferFree(pBuf);
}
inline fn fts5BufferSet(pRc: *c_int, pBuf: *Fts5Buffer, nData: c_int, pData: ?[*]const u8) void {
    sqlite3Fts5BufferSet(pRc, pBuf, nData, pData.?);
}
inline fn fts5BufferAppendBlob(pRc: *c_int, pBuf: *Fts5Buffer, nData: c_int, pData: ?[*]const u8) void {
    sqlite3Fts5BufferAppendBlob(pRc, pBuf, @bitCast(nData), pData.?);
}
inline fn fts5BufferAppendVarint(pRc: *c_int, pBuf: *Fts5Buffer, iVal: i64) void {
    sqlite3Fts5BufferAppendVarint(pRc, pBuf, iVal);
}
// fts5BufferCompare (fts5_index.c 808-815): memcmp with prefix-is-lesser.
fn fts5BufferCompare(pLeftIn: ?*Fts5Buffer, pRightIn: ?*Fts5Buffer) c_int {
    const pLeft = pLeftIn.?;
    const pRight = pRightIn.?;
    const nCmp = MIN(c_int, pLeft.n, pRight.n);
    const res = fts5Memcmp(pLeft.p, pRight.p, nCmp);
    return if (res == 0) (pLeft.n - pRight.n) else res;
}

// fts5BufferGrow(pRc,pBuf,nn): returns 1 (true) on OOM.
inline fn fts5BufferGrow(pRc: *c_int, pBuf: *Fts5Buffer, nn: c_int) bool {
    if (@as(u32, @bitCast(pBuf.n)) +% @as(u32, @bitCast(nn)) <= @as(u32, @bitCast(pBuf.nSpace))) {
        return false;
    }
    return sqlite3Fts5BufferSize(pRc, pBuf, @bitCast(nn +% pBuf.n)) != 0;
}

// ASSERT_SZLEAF_OK / fts5LeafIsTermless / fts5LeafTermOff / fts5LeafFirstRowidOff
inline fn fts5LeafIsTermless(x: *Fts5Data) bool {
    return x.szLeaf >= x.nn;
}
inline fn fts5LeafTermOff(x: *Fts5Data, i: c_int) u16 {
    return fts5GetU16(x.p.? + @as(usize, @intCast(x.szLeaf + i * 2)));
}
inline fn fts5LeafFirstRowidOff(x: *Fts5Data) u16 {
    return fts5GetU16(x.p.?);
}

inline fn fts5IdxMalloc(p: *Fts5IndexS, nByte: i64) ?*anyopaque {
    return sqlite3Fts5MallocZero(&p.rc, nByte);
}

inline fn fts5SegmentSize(pSeg: *Fts5StructureSegment) c_int {
    return 1 + pSeg.pgnoLast - pSeg.pgnoFirst;
}

// fts5IndexSkipVarint(a, iOff): advance *iOff past one varint (max 9 bytes).
// C macro: { int iEnd = iOff+9; while( (a[iOff++] & 0x80) && iOff<iEnd ); }
inline fn fts5IndexSkipVarint(a: [*]const u8, iOff: *c_int) void {
    const iEnd: c_int = iOff.* + 9;
    while (true) {
        const b = a[@intCast(iOff.*)];
        iOff.* += 1;
        if (!((b & 0x80) != 0 and iOff.* < iEnd)) break;
    }
}

inline fn fts5LeafFirstTermOff(pLeaf: *Fts5Data) c_int {
    var ret: c_int = undefined;
    _ = fts5GetVarint32Into(c_int, pLeaf.p.? + @as(usize, @intCast(pLeaf.szLeaf)), &ret);
    return ret;
}

// ===========================================================================
// Corruption helpers (fts5IndexCorrupt*). Each sets p->rc = FTS5_CORRUPT,
// records an error message and returns SQLITE_CORRUPT_VTAB.
// ===========================================================================
fn fts5IndexCorruptRowid(pIdx: *Fts5IndexS, iRowid: i64) c_int {
    pIdx.rc = FTS5_CORRUPT;
    sqlite3Fts5ConfigErrmsg(
        pIdx.pConfig.?,
        "fts5: corruption found reading blob %lld from table \"%s\"",
        iRowid,
        @as(*Fts5Config, @ptrCast(@alignCast(pIdx.pConfig.?))).zName,
    );
    return SQLITE_CORRUPT_VTAB;
}
fn fts5IndexCorruptIter(pIdx: *Fts5IndexS, pIter: *Fts5SegIter) c_int {
    pIdx.rc = FTS5_CORRUPT;
    sqlite3Fts5ConfigErrmsg(
        pIdx.pConfig.?,
        "fts5: corruption on page %d, segment %d, table \"%s\"",
        pIter.iLeafPgno,
        pIter.pSeg.?.iSegid,
        @as(*Fts5Config, @ptrCast(@alignCast(pIdx.pConfig.?))).zName,
    );
    return SQLITE_CORRUPT_VTAB;
}
fn fts5IndexCorruptIdx(pIdx: *Fts5IndexS) c_int {
    pIdx.rc = FTS5_CORRUPT;
    sqlite3Fts5ConfigErrmsg(
        pIdx.pConfig.?,
        "fts5: corruption in table \"%s\"",
        @as(*Fts5Config, @ptrCast(@alignCast(pIdx.pConfig.?))).zName,
    );
    return SQLITE_CORRUPT_VTAB;
}

// ===========================================================================
// extern: sibling fts5 sections (resolved at link time within the FTS5 object).
// ===========================================================================
extern fn sqlite3Fts5PutVarint(p: [*]u8, v: u64) callconv(.c) c_int;
extern fn sqlite3Fts5GetVarint(p: [*]const u8, v: *u64) callconv(.c) c_int;
extern fn sqlite3Fts5GetVarint32(p: [*]const u8, v: *u32) callconv(.c) c_int;
extern fn sqlite3Fts5GetVarintLen(iVal: u32) callconv(.c) c_int;

extern fn sqlite3Fts5BufferSize(pRc: *c_int, pBuf: *Fts5Buffer, nByte: u32) callconv(.c) c_int;
extern fn sqlite3Fts5BufferAppendVarint(pRc: *c_int, pBuf: *Fts5Buffer, iVal: i64) callconv(.c) void;
extern fn sqlite3Fts5BufferAppendBlob(pRc: *c_int, pBuf: *Fts5Buffer, nData: u32, pData: [*]const u8) callconv(.c) void;
extern fn sqlite3Fts5BufferAppendString(pRc: *c_int, pBuf: *Fts5Buffer, zStr: [*:0]const u8) callconv(.c) void;
extern fn sqlite3Fts5BufferAppendPrintf(pRc: *c_int, pBuf: *Fts5Buffer, zFmt: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3Fts5BufferFree(pBuf: *Fts5Buffer) callconv(.c) void;
extern fn sqlite3Fts5BufferZero(pBuf: *Fts5Buffer) callconv(.c) void;
extern fn sqlite3Fts5BufferSet(pRc: *c_int, pBuf: *Fts5Buffer, nData: c_int, pData: ?[*]const u8) callconv(.c) void;
extern fn sqlite3Fts5Put32(aBuf: [*]u8, iVal: c_int) callconv(.c) void;
extern fn sqlite3Fts5Get32(aBuf: [*]const u8) callconv(.c) c_int;
extern fn sqlite3Fts5MallocZero(pRc: *c_int, nByte: i64) callconv(.c) ?*anyopaque;
extern fn sqlite3Fts5Mprintf(pRc: *c_int, zFmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5PoslistNext64(a: ?[*]const u8, n: c_int, pi: *c_int, piOff: *i64) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistReaderInit(a: ?[*]const u8, n: c_int, pIter: *Fts5PoslistReader) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistReaderNext(pIter: *Fts5PoslistReader) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistSafeAppend(pBuf: *Fts5Buffer, piPrev: *i64, iPos: i64) callconv(.c) void;

extern fn sqlite3Fts5HashNew(pConfig: *Fts5Config, pp: *?*Fts5Hash, pnSize: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5HashFree(p: ?*Fts5Hash) callconv(.c) void;
extern fn sqlite3Fts5HashWrite(p: *Fts5Hash, iRowid: i64, iCol: c_int, iPos: c_int, b: u8, pToken: [*]const u8, nToken: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5HashClear(p: *Fts5Hash) callconv(.c) void;
extern fn sqlite3Fts5HashIsEmpty(p: *Fts5Hash) callconv(.c) c_int;
extern fn sqlite3Fts5HashQuery(p: *Fts5Hash, nPre: c_int, pTerm: [*]const u8, nTerm: c_int, ppOut: *?*const anyopaque, pn: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5HashScanInit(p: *Fts5Hash, pTerm: ?[*]const u8, nTerm: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5HashScanNext(p: *Fts5Hash) callconv(.c) void;
extern fn sqlite3Fts5HashScanEof(p: *Fts5Hash) callconv(.c) c_int;
extern fn sqlite3Fts5HashScanEntry(p: *Fts5Hash, pzTerm: *?[*:0]const u8, pnTerm: *c_int, ppDoclist: *?[*]const u8, pnDoclist: *c_int) callconv(.c) void;

extern fn sqlite3Fts5ConfigErrmsg(pConfig: *Fts5Config, zFmt: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3Fts5ConfigLoad(pConfig: *Fts5Config, iCookie: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5CreateTable(pConfig: *Fts5Config, zPost: [*:0]const u8, zDefn: [*:0]const u8, bWithout: c_int, pzErr: *?[*:0]u8) callconv(.c) c_int;

// ===========================================================================
// extern: core sqlite3 API (resolved at link time).
// ===========================================================================
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_stricmp(a: [*:0]const u8, b: [*:0]const u8) c_int;

extern fn sqlite3_blob_open(db: ?*sqlite3, zDb: [*:0]const u8, zTable: [*:0]const u8, zColumn: [*:0]const u8, iRow: i64, flags: c_int, ppBlob: *?*sqlite3_blob) c_int;
extern fn sqlite3_blob_reopen(pBlob: *sqlite3_blob, iRow: i64) c_int;
extern fn sqlite3_blob_close(pBlob: *sqlite3_blob) c_int;
extern fn sqlite3_blob_bytes(pBlob: *sqlite3_blob) c_int;
extern fn sqlite3_blob_read(pBlob: *sqlite3_blob, z: ?*anyopaque, n: c_int, iOffset: c_int) c_int;
extern fn sqlite3_blob_write(pBlob: *sqlite3_blob, z: ?*const anyopaque, n: c_int, iOffset: c_int) c_int;

extern fn sqlite3_prepare_v3(db: ?*sqlite3, zSql: [*]const u8, nByte: c_int, prepFlags: c_uint, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_bind_int(pStmt: ?*sqlite3_stmt, i: c_int, v: c_int) c_int;
extern fn sqlite3_bind_int64(pStmt: ?*sqlite3_stmt, i: c_int, v: i64) c_int;
extern fn sqlite3_bind_blob(pStmt: ?*sqlite3_stmt, i: c_int, v: ?*const anyopaque, n: c_int, d: int.DestructorFn) c_int;
extern fn sqlite3_bind_null(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_int(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, i: c_int) i64;
extern fn sqlite3_column_blob(pStmt: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_bytes(pStmt: ?*sqlite3_stmt, i: c_int) c_int;

extern fn sqlite3_value_int(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(v: ?*sqlite3_value) i64;
extern fn sqlite3_value_blob(v: ?*sqlite3_value) ?*const anyopaque;
extern fn sqlite3_value_text(v: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_bytes(v: ?*sqlite3_value) c_int;

extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*]const u8, n: c_int, d: int.DestructorFn) void;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: [*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(ctx: ?*sqlite3_context, code: c_int) void;

extern fn sqlite3_create_function(db: ?*sqlite3, zName: [*:0]const u8, nArg: c_int, eTextRep: c_int, pApp: ?*anyopaque, xFunc: ?*const fn (?*sqlite3_context, c_int, [*]?*sqlite3_value) callconv(.c) void, xStep: ?*const anyopaque, xFinal: ?*const anyopaque) c_int;
extern fn sqlite3_create_module(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pClientData: ?*anyopaque) c_int;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_user_data(ctx: ?*sqlite3_context) ?*anyopaque;

// libc
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memmove(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn strlen(s: [*:0]const u8) usize;


// ============================ CHUNK 1 ============================
// Close the read-only blob handle, if it is open.
fn fts5IndexCloseReader(p: *Fts5IndexS) void {
    if (p.pReader) |pReader| {
        p.pReader = null;
        const rc = sqlite3_blob_close(pReader);
        if (p.rc == SQLITE_OK) p.rc = rc;
    }
}

// Retrieve a record from the %_data table. On error returns NULL and leaves an
// error in the Fts5Index object.
fn fts5DataRead(p: *Fts5IndexS, iRowid: i64) ?*Fts5Data {
    var pRet: ?*Fts5Data = null;
    if (p.rc == SQLITE_OK) {
        var rc: c_int = SQLITE_OK;

        if (p.pReader) |pBlob| {
            // This call may return SQLITE_ABORT if there has been a savepoint
            // rollback since it was last used. In this case a new blob handle
            // is required.
            p.pReader = null;
            rc = sqlite3_blob_reopen(pBlob, iRowid);
            p.pReader = pBlob;
            if (rc != SQLITE_OK) {
                fts5IndexCloseReader(p);
            }
            if (rc == SQLITE_ABORT) rc = SQLITE_OK;
        }

        // If the blob handle is not open at this point, open it and seek to the
        // requested entry.
        if (p.pReader == null and rc == SQLITE_OK) {
            const pConfig = p.pConfig.?;
            rc = sqlite3_blob_open(
                pConfig.db,
                pConfig.zDb.?,
                p.zDataTbl.?,
                "block",
                iRowid,
                0,
                &p.pReader,
            );
        }

        // If either of the sqlite3_blob_open() or sqlite3_blob_reopen() calls
        // above returned SQLITE_ERROR, return SQLITE_CORRUPT_VTAB instead.
        if (rc == SQLITE_ERROR) rc = fts5IndexCorruptRowid(p, iRowid);

        if (rc == SQLITE_OK) {
            var aOut: ?[*]u8 = null; // Read blob data into this buffer
            const nByte: i64 = sqlite3_blob_bytes(p.pReader.?);
            const szData: i64 = (@as(i64, @sizeOf(Fts5Data)) + 7) & ~@as(i64, 7);
            const nAlloc: i64 = szData + nByte + @as(i64, @intCast(FTS5_DATA_PADDING));
            pRet = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nAlloc))));
            if (pRet) |pr| {
                pr.nn = @intCast(nByte);
                const pbase: [*]u8 = @ptrCast(pr);
                pr.p = pbase + @as(usize, @intCast(szData));
                aOut = pr.p;
            } else {
                rc = SQLITE_NOMEM;
            }

            if (rc == SQLITE_OK) {
                rc = sqlite3_blob_read(p.pReader.?, aOut, @intCast(nByte), 0);
            }
            if (rc != SQLITE_OK) {
                sqlite3_free(pRet);
                pRet = null;
            } else {
                const pr = pRet.?;
                const pp = pr.p.?;
                // TODO1: Fix this
                pp[@intCast(nByte)] = 0x00;
                pp[@intCast(nByte + 1)] = 0x00;
                pr.szLeaf = fts5GetU16(pp + 2);
            }
        }
        p.rc = rc;
        p.nRead += 1;
    }

    return pRet;
}

// Release a reference to a data record returned by fts5DataRead().
fn fts5DataRelease(pData: ?*Fts5Data) void {
    sqlite3_free(pData);
}

fn fts5LeafRead(p: *Fts5IndexS, iRowid: i64) ?*Fts5Data {
    var pRet = fts5DataRead(p, iRowid);
    if (pRet) |pr| {
        if (pr.szLeaf < 4 or pr.szLeaf > pr.nn) {
            _ = fts5IndexCorruptRowid(p, iRowid);
            fts5DataRelease(pRet);
            pRet = null;
        }
    }
    return pRet;
}

fn fts5IndexPrepareStmt(
    p: *Fts5IndexS,
    ppStmt: *?*sqlite3_stmt,
    zSql: ?[*:0]u8,
) c_int {
    if (p.rc == SQLITE_OK) {
        if (zSql) |z| {
            const rc = sqlite3_prepare_v3(
                p.pConfig.?.db,
                z,
                -1,
                @as(c_uint, @bitCast(SQLITE_PREPARE_PERSISTENT | SQLITE_PREPARE_NO_VTAB)),
                ppStmt,
                null,
            );
            // If this prepare() call fails with SQLITE_ERROR, then one of the
            // %_idx or %_data tables has been removed or modified. Call this
            // corruption.
            p.rc = if (rc == SQLITE_ERROR) SQLITE_CORRUPT else rc;
        } else {
            p.rc = SQLITE_NOMEM;
        }
    }
    sqlite3_free(zSql);
    return p.rc;
}

// INSERT OR REPLACE a record into the %_data table.
fn fts5DataWrite(p: *Fts5IndexS, iRowid: i64, pDataIn: ?[*]const u8, nData: c_int) void {
    const pData = pDataIn.?;
    if (p.rc != SQLITE_OK) return;

    if (p.pWriter == null) {
        const pConfig = p.pConfig.?;
        _ = fts5IndexPrepareStmt(p, &p.pWriter, sqlite3_mprintf(
            "REPLACE INTO '%q'.'%q_data'(id, block) VALUES(?,?)",
            pConfig.zDb,
            pConfig.zName,
        ));
        if (p.rc != 0) return;
    }

    _ = sqlite3_bind_int64(p.pWriter, 1, iRowid);
    _ = sqlite3_bind_blob(p.pWriter, 2, pData, nData, int.SQLITE_STATIC);
    _ = sqlite3_step(p.pWriter);
    p.rc = sqlite3_reset(p.pWriter);
    _ = sqlite3_bind_null(p.pWriter, 2);
}

// DELETE FROM %_data WHERE id BETWEEN $iFirst AND $iLast
fn fts5DataDelete(p: *Fts5IndexS, iFirst: i64, iLast: i64) void {
    if (p.rc != SQLITE_OK) return;

    if (p.pDeleter == null) {
        const pConfig = p.pConfig.?;
        const zSql = sqlite3_mprintf(
            "DELETE FROM '%q'.'%q_data' WHERE id>=? AND id<=?",
            pConfig.zDb,
            pConfig.zName,
        );
        if (fts5IndexPrepareStmt(p, &p.pDeleter, zSql) != 0) return;
    }

    _ = sqlite3_bind_int64(p.pDeleter, 1, iFirst);
    _ = sqlite3_bind_int64(p.pDeleter, 2, iLast);
    _ = sqlite3_step(p.pDeleter);
    p.rc = sqlite3_reset(p.pDeleter);
}

// Remove all records associated with segment iSegid.
fn fts5DataRemoveSegment(p: *Fts5IndexS, pSeg: *Fts5StructureSegment) void {
    const iSegid: c_int = pSeg.iSegid;
    const iFirst: i64 = FTS5_SEGMENT_ROWID(iSegid, 0);
    const iLast: i64 = FTS5_SEGMENT_ROWID(iSegid + 1, 0) - 1;
    fts5DataDelete(p, iFirst, iLast);

    if (pSeg.nPgTombstone != 0) {
        const iTomb1: i64 = FTS5_TOMBSTONE_ROWID(iSegid, 0);
        const iTomb2: i64 = FTS5_TOMBSTONE_ROWID(iSegid, pSeg.nPgTombstone - 1);
        fts5DataDelete(p, iTomb1, iTomb2);
    }
    if (p.pIdxDeleter == null) {
        const pConfig = p.pConfig.?;
        _ = fts5IndexPrepareStmt(p, &p.pIdxDeleter, sqlite3_mprintf(
            "DELETE FROM '%q'.'%q_idx' WHERE segid=?",
            pConfig.zDb,
            pConfig.zName,
        ));
    }
    if (p.rc == SQLITE_OK) {
        _ = sqlite3_bind_int(p.pIdxDeleter, 1, iSegid);
        _ = sqlite3_step(p.pIdxDeleter);
        p.rc = sqlite3_reset(p.pIdxDeleter);
    }
}

// Release a reference to an Fts5Structure object returned by an earlier call to
// fts5StructureRead() or fts5StructureDecode().
fn fts5StructureRelease(pStruct: ?*Fts5Structure) void {
    if (pStruct) |ps| {
        ps.nRef -= 1;
        if (0 >= ps.nRef) {
            var i: c_int = 0;
            while (i < ps.nLevel) : (i += 1) {
                sqlite3_free(structLevel(ps, i).aSeg);
            }
            sqlite3_free(ps);
        }
    }
}

fn fts5StructureRef(pStruct: *Fts5Structure) void {
    pStruct.nRef += 1;
}

export fn sqlite3Fts5StructureRef(p: *Fts5IndexS) callconv(.c) ?*anyopaque {
    fts5StructureRef(p.pStruct.?);
    return @ptrCast(p.pStruct);
}
export fn sqlite3Fts5StructureRelease(p: ?*anyopaque) callconv(.c) void {
    if (p) |ptr| {
        fts5StructureRelease(@ptrCast(@alignCast(ptr)));
    }
}
export fn sqlite3Fts5StructureTest(p: *Fts5IndexS, pStruct: ?*anyopaque) callconv(.c) c_int {
    if (@as(?*Fts5Structure, p.pStruct) != @as(?*Fts5Structure, @ptrCast(@alignCast(pStruct)))) {
        return SQLITE_ABORT;
    }
    return SQLITE_OK;
}

// ============================ CHUNK 2 ============================
// ===========================================================================
// fts5StructureMakeWritable — ensure structure object (*pp) is writable.
// ===========================================================================
fn fts5StructureMakeWritable(pRc: *c_int, pp: *?*Fts5Structure) void {
    const p = pp.*.?;
    if (pRc.* == SQLITE_OK and p.nRef > 1) {
        var nByte: i64 = SZ_FTS5STRUCTURE(p.nLevel);
        const pNew: ?*Fts5Structure = @ptrCast(@alignCast(sqlite3Fts5MallocZero(pRc, nByte)));
        if (pNew) |pn| {
            _ = memcpy(pn, p, @intCast(nByte));
            var i: c_int = 0;
            while (i < p.nLevel) : (i += 1) structLevel(pn, i).aSeg = null;
            i = 0;
            while (i < p.nLevel) : (i += 1) {
                const pLvl = structLevel(pn, i);
                nByte = @as(i64, @sizeOf(Fts5StructureSegment)) * structLevel(pn, i).nSeg;
                pLvl.aSeg = @ptrCast(@alignCast(sqlite3Fts5MallocZero(pRc, nByte)));
                if (pLvl.aSeg == null) {
                    var j: c_int = 0;
                    while (j < p.nLevel) : (j += 1) {
                        sqlite3_free(structLevel(pn, j).aSeg);
                    }
                    sqlite3_free(pn);
                    return;
                }
                _ = memcpy(pLvl.aSeg, structLevel(p, i).aSeg, @intCast(nByte));
            }
            p.nRef -= 1;
            pn.nRef = 1;
        }
        pp.* = pNew;
    }
}

// ===========================================================================
// fts5StructureDecode — deserialize the serialized structure record.
// ===========================================================================
fn fts5StructureDecode(
    pData: [*]const u8,
    nData: c_int,
    piCookie: ?*c_int,
    ppOut: *?*Fts5Structure,
) c_int {
    var rc: c_int = SQLITE_OK;
    var i: c_int = 0;
    var iLvl: c_int = undefined;
    var nLevel: c_int = 0;
    var nSegment: c_int = 0;
    var nByte: i64 = undefined;
    var pRet: ?*Fts5Structure = null;
    var bStructureV2: c_int = 0;
    var nOriginCntr: u64 = 0;

    // Grab the cookie value
    if (piCookie) |pc| pc.* = sqlite3Fts5Get32(pData);
    i = 4;

    // Check if this is a V2 structure record. Set bStructureV2 if it is.
    if (0 == memcmp(pData + @as(usize, @intCast(i)), FTS5_STRUCTURE_V2.ptr, 4)) {
        i += 4;
        bStructureV2 = 1;
    }

    // Read the total number of levels and segments.
    i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &nLevel);
    i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &nSegment);
    if (nLevel > FTS5_MAX_SEGMENT or nLevel < 0 or
        nSegment > FTS5_MAX_SEGMENT or nSegment < 0)
    {
        return FTS5_CORRUPT;
    }
    nByte = SZ_FTS5STRUCTURE(nLevel);
    pRet = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));

    if (pRet) |ret| {
        ret.nRef = 1;
        ret.nLevel = nLevel;
        ret.nSegment = nSegment;
        i += sqlite3Fts5GetVarint(pData + @as(usize, @intCast(i)), &ret.nWriteCounter);

        iLvl = 0;
        while (rc == SQLITE_OK and iLvl < nLevel) : (iLvl += 1) {
            const pLvl = structLevel(ret, iLvl);
            var nTotal: c_int = 0;
            var iSeg: c_int = undefined;

            if (i >= nData) {
                rc = FTS5_CORRUPT;
            } else {
                i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &pLvl.nMerge);
                i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &nTotal);
                if (nTotal < pLvl.nMerge) rc = FTS5_CORRUPT;
                pLvl.aSeg = @ptrCast(@alignCast(sqlite3Fts5MallocZero(
                    &rc,
                    @as(i64, nTotal) * @sizeOf(Fts5StructureSegment),
                )));
                nSegment -= nTotal;
            }

            if (rc == SQLITE_OK) {
                pLvl.nSeg = nTotal;
                iSeg = 0;
                while (iSeg < nTotal) : (iSeg += 1) {
                    const pSeg = &pLvl.aSeg.?[@intCast(iSeg)];
                    if (i >= nData) {
                        rc = FTS5_CORRUPT;
                        break;
                    }
                    i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &pSeg.iSegid);
                    i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &pSeg.pgnoFirst);
                    i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &pSeg.pgnoLast);
                    if (bStructureV2 != 0) {
                        i += fts5GetVarint(pData + @as(usize, @intCast(i)), &pSeg.iOrigin1);
                        i += fts5GetVarint(pData + @as(usize, @intCast(i)), &pSeg.iOrigin2);
                        i += fts5GetVarint32Into(c_int, pData + @as(usize, @intCast(i)), &pSeg.nPgTombstone);
                        i += fts5GetVarint(pData + @as(usize, @intCast(i)), &pSeg.nEntryTombstone);
                        i += fts5GetVarint(pData + @as(usize, @intCast(i)), &pSeg.nEntry);
                        nOriginCntr = MAX(u64, nOriginCntr, pSeg.iOrigin2);
                    }
                    if (pSeg.pgnoLast < pSeg.pgnoFirst) {
                        rc = FTS5_CORRUPT;
                        break;
                    }
                }
                if (iLvl > 0 and structLevel(ret, iLvl - 1).nMerge != 0 and nTotal == 0) rc = FTS5_CORRUPT;
                if (iLvl == nLevel - 1 and pLvl.nMerge != 0) rc = FTS5_CORRUPT;
            }
        }
        if (nSegment != 0 and rc == SQLITE_OK) rc = FTS5_CORRUPT;
        if (bStructureV2 != 0) {
            ret.nOriginCntr = nOriginCntr + 1;
        }

        if (rc != SQLITE_OK) {
            fts5StructureRelease(ret);
            pRet = null;
        }
    }

    ppOut.* = pRet;
    return rc;
}

// ===========================================================================
// fts5StructureAddLevel — add a level to the aLevel[] array.
// ===========================================================================
fn fts5StructureAddLevel(pRc: *c_int, ppStruct: *?*Fts5Structure) void {
    fts5StructureMakeWritable(pRc, ppStruct);
    if (pRc.* == SQLITE_OK) {
        var pStruct = ppStruct.*.?;
        const nLevel = pStruct.nLevel;
        const nByte: i64 = SZ_FTS5STRUCTURE(nLevel + 2);

        const pNew: ?*Fts5Structure = @ptrCast(@alignCast(sqlite3_realloc64(pStruct, @intCast(nByte))));
        if (pNew) |pn| {
            pStruct = pn;
            _ = memset(structLevel(pStruct, nLevel), 0, @sizeOf(Fts5StructureLevel));
            pStruct.nLevel += 1;
            ppStruct.* = pStruct;
        } else {
            pRc.* = SQLITE_NOMEM;
        }
    }
}

// ===========================================================================
// fts5StructureExtendLevel — make room for nExtra more segments on level iLvl.
// ===========================================================================
fn fts5StructureExtendLevel(
    pRc: *c_int,
    pStruct: *Fts5Structure,
    iLvl: c_int,
    nExtra: c_int,
    bInsert: c_int,
) void {
    if (pRc.* == SQLITE_OK) {
        const pLvl = structLevel(pStruct, iLvl);
        const nByte: i64 = @as(i64, pLvl.nSeg + nExtra) * @sizeOf(Fts5StructureSegment);
        const aNew: ?[*]Fts5StructureSegment = @ptrCast(@alignCast(sqlite3_realloc64(pLvl.aSeg, @intCast(nByte))));
        if (aNew) |an| {
            if (bInsert == 0) {
                _ = memset(&an[@intCast(pLvl.nSeg)], 0, @as(usize, @sizeOf(Fts5StructureSegment)) * @as(usize, @intCast(nExtra)));
            } else {
                const nMove: usize = @as(usize, @intCast(pLvl.nSeg)) * @sizeOf(Fts5StructureSegment);
                _ = memmove(&an[@intCast(nExtra)], an, nMove);
                _ = memset(an, 0, @as(usize, @sizeOf(Fts5StructureSegment)) * @as(usize, @intCast(nExtra)));
            }
            pLvl.aSeg = an;
        } else {
            pRc.* = SQLITE_NOMEM;
        }
    }
}

// ===========================================================================
// fts5StructureReadUncached — read+deserialize the structure record (no cache).
// ===========================================================================
fn fts5StructureReadUncached(p: *Fts5IndexS) ?*Fts5Structure {
    var pRet: ?*Fts5Structure = null;
    const pConfig = p.pConfig.?;
    var iCookie: c_int = undefined;

    const pData = fts5DataRead(p, FTS5_STRUCTURE_ROWID);
    if (p.rc == SQLITE_OK) {
        const pd = pData.?;
        // TODO: Do we need this if the leaf-index is appended? Probably...
        _ = memset(pd.p.? + @as(usize, @intCast(pd.nn)), 0, FTS5_DATA_PADDING);
        p.rc = fts5StructureDecode(pd.p.?, pd.nn, &iCookie, &pRet);
        if (p.rc == SQLITE_OK) {
            if (pConfig.pgsz == 0 or pConfig.iCookie != iCookie) {
                p.rc = sqlite3Fts5ConfigLoad(pConfig, iCookie);
            }
        } else if (p.rc == SQLITE_CORRUPT_VTAB) {
            sqlite3Fts5ConfigErrmsg(
                p.pConfig.?,
                "fts5: corrupt structure record for table \"%s\"",
                p.pConfig.?.zName,
            );
        }
        fts5DataRelease(pData);
        if (p.rc != SQLITE_OK) {
            fts5StructureRelease(pRet);
            pRet = null;
        }
    }

    return pRet;
}

// ===========================================================================
// fts5IndexDataVersion — return PRAGMA data_version value.
// ===========================================================================
fn fts5IndexDataVersion(p: *Fts5IndexS) i64 {
    var iVersion: i64 = 0;

    if (p.rc == SQLITE_OK) {
        if (p.pDataVersion == null) {
            p.rc = fts5IndexPrepareStmt(
                p,
                &p.pDataVersion,
                sqlite3_mprintf("PRAGMA %Q.data_version", p.pConfig.?.zDb),
            );
            if (p.rc != 0) return 0;
        }

        if (SQLITE_ROW == sqlite3_step(p.pDataVersion)) {
            iVersion = sqlite3_column_int64(p.pDataVersion, 0);
        }
        p.rc = sqlite3_reset(p.pDataVersion);
    }

    return iVersion;
}

// ===========================================================================
// fts5StructureRead — read+deserialize the structure record (cached).
// ===========================================================================
fn fts5StructureRead(p: *Fts5IndexS) ?*Fts5Structure {
    if (p.pStruct == null) {
        p.iStructVersion = fts5IndexDataVersion(p);
        if (p.rc == SQLITE_OK) {
            p.pStruct = fts5StructureReadUncached(p);
        }
    }

    if (p.rc != SQLITE_OK) return null;
    fts5StructureRef(p.pStruct.?);
    return p.pStruct;
}

// ===========================================================================
// fts5StructureInvalidate — drop the cached structure record.
// ===========================================================================
fn fts5StructureInvalidate(p: *Fts5IndexS) void {
    if (p.pStruct) |ps| {
        fts5StructureRelease(ps);
        p.pStruct = null;
    }
}

// ===========================================================================
// fts5StructureCountSegments — total segments (assert-only helper in C).
// ===========================================================================
fn fts5StructureCountSegments(pStruct: ?*Fts5Structure) c_int {
    var nSegment: c_int = 0;
    if (pStruct) |ps| {
        var iLvl: c_int = 0;
        while (iLvl < ps.nLevel) : (iLvl += 1) {
            nSegment += structLevel(ps, iLvl).nSeg;
        }
    }
    return nSegment;
}

// ===========================================================================
// fts5StructureWrite — serialize and store the structure record.
// ===========================================================================
fn fts5StructureWrite(p: *Fts5IndexS, pStruct: *Fts5Structure) void {
    if (p.rc == SQLITE_OK) {
        var buf: Fts5Buffer = undefined;
        var iLvl: c_int = undefined;
        var iCookie: c_int = undefined;
        const nHdr: c_int = if (pStruct.nOriginCntr > 0) (4 + 4 + 9 + 9 + 9) else (4 + 9 + 9);

        _ = memset(&buf, 0, @sizeOf(Fts5Buffer));

        // Append the current configuration cookie
        iCookie = p.pConfig.?.iCookie;
        if (iCookie < 0) iCookie = 0;

        if (0 == sqlite3Fts5BufferSize(&p.rc, &buf, @intCast(nHdr))) {
            sqlite3Fts5Put32(buf.p.?, iCookie);
            buf.n = 4;
            if (pStruct.nOriginCntr > 0) {
                fts5BufferSafeAppendBlob(&buf, FTS5_STRUCTURE_V2.ptr, 4);
            }
            fts5BufferSafeAppendVarint(&buf, pStruct.nLevel);
            fts5BufferSafeAppendVarint(&buf, pStruct.nSegment);
            fts5BufferSafeAppendVarint(&buf, @bitCast(pStruct.nWriteCounter));
        }

        iLvl = 0;
        while (iLvl < pStruct.nLevel) : (iLvl += 1) {
            var iSeg: c_int = undefined;
            const pLvl = structLevel(pStruct, iLvl);
            sqlite3Fts5BufferAppendVarint(&p.rc, &buf, pLvl.nMerge);
            sqlite3Fts5BufferAppendVarint(&p.rc, &buf, pLvl.nSeg);

            iSeg = 0;
            while (iSeg < pLvl.nSeg) : (iSeg += 1) {
                const pSeg = &pLvl.aSeg.?[@intCast(iSeg)];
                sqlite3Fts5BufferAppendVarint(&p.rc, &buf, pSeg.iSegid);
                sqlite3Fts5BufferAppendVarint(&p.rc, &buf, pSeg.pgnoFirst);
                sqlite3Fts5BufferAppendVarint(&p.rc, &buf, pSeg.pgnoLast);
                if (pStruct.nOriginCntr > 0) {
                    sqlite3Fts5BufferAppendVarint(&p.rc, &buf, @bitCast(pSeg.iOrigin1));
                    sqlite3Fts5BufferAppendVarint(&p.rc, &buf, @bitCast(pSeg.iOrigin2));
                    sqlite3Fts5BufferAppendVarint(&p.rc, &buf, pSeg.nPgTombstone);
                    sqlite3Fts5BufferAppendVarint(&p.rc, &buf, @bitCast(pSeg.nEntryTombstone));
                    sqlite3Fts5BufferAppendVarint(&p.rc, &buf, @bitCast(pSeg.nEntry));
                }
            }
        }

        fts5DataWrite(p, FTS5_STRUCTURE_ROWID, buf.p.?, buf.n);
        sqlite3Fts5BufferFree(&buf);
    }
}

// (fts5SegmentSize is already defined in the scaffold — skipped.)

// ===========================================================================
// fts5StructurePromoteTo — promote as many segments as possible to iPromote.
// ===========================================================================
fn fts5StructurePromoteTo(
    p: *Fts5IndexS,
    iPromote: c_int,
    szPromote: c_int,
    pStruct: *Fts5Structure,
) void {
    var il: c_int = undefined;
    var is: c_int = undefined;
    const pOut = structLevel(pStruct, iPromote);

    if (pOut.nMerge == 0) {
        il = iPromote + 1;
        while (il < pStruct.nLevel) : (il += 1) {
            const pLvl = structLevel(pStruct, il);
            if (pLvl.nMerge != 0) return;
            is = pLvl.nSeg - 1;
            while (is >= 0) : (is -= 1) {
                const sz = fts5SegmentSize(&pLvl.aSeg.?[@intCast(is)]);
                if (sz > szPromote) return;
                fts5StructureExtendLevel(&p.rc, pStruct, iPromote, 1, 1);
                if (p.rc != 0) return;
                _ = memcpy(pOut.aSeg, &pLvl.aSeg.?[@intCast(is)], @sizeOf(Fts5StructureSegment));
                pOut.nSeg += 1;
                pLvl.nSeg -= 1;
            }
        }
    }
}

// ===========================================================================
// fts5StructurePromote — decide whether to promote a newly-written segment.
// ===========================================================================
fn fts5StructurePromote(
    p: *Fts5IndexS,
    iLvl: c_int,
    pStruct: *Fts5Structure,
) void {
    if (p.rc == SQLITE_OK) {
        var iTst: c_int = undefined;
        var iPromote: c_int = -1;
        var szPromote: c_int = 0;
        var pSeg: *Fts5StructureSegment = undefined;
        var szSeg: c_int = undefined;
        const nSeg = structLevel(pStruct, iLvl).nSeg;

        if (nSeg == 0) return;
        pSeg = &structLevel(pStruct, iLvl).aSeg.?[@intCast(structLevel(pStruct, iLvl).nSeg - 1)];
        szSeg = (1 + pSeg.pgnoLast - pSeg.pgnoFirst);

        // Check for condition (a)
        iTst = iLvl - 1;
        while (iTst >= 0 and structLevel(pStruct, iTst).nSeg == 0) : (iTst -= 1) {}
        if (iTst >= 0) {
            var i: c_int = 0;
            var szMax: c_int = 0;
            const pTst = structLevel(pStruct, iTst);
            while (i < pTst.nSeg) : (i += 1) {
                const sz = pTst.aSeg.?[@intCast(i)].pgnoLast - pTst.aSeg.?[@intCast(i)].pgnoFirst + 1;
                if (sz > szMax) szMax = sz;
            }
            if (szMax >= szSeg) {
                // Condition (a) is true. Promote newest segment on iLvl to iTst.
                iPromote = iTst;
                szPromote = szMax;
            }
        }

        // If (a) not met, assume (b). PromoteTo() is a no-op if it isn't.
        if (iPromote < 0) {
            iPromote = iLvl;
            szPromote = szSeg;
        }
        fts5StructurePromoteTo(p, iPromote, szPromote, pStruct);
    }
}

// ============================ CHUNK 3 ============================
// ===========================================================================
// fts5_index.c lines 1583-2545: doclist-index iterators + per-segment iterator
// core. Sibling-chunk fns referenced by name (resolved at file scope):
//   fts5DataRead, fts5DataRelease, fts5LeafRead (c1/c2).
// ===========================================================================

// Advance the iterator passed as the only argument. If the end of the
// doclist-index page is reached, return non-zero.
fn fts5DlidxLvlNext(pLvl: *Fts5DlidxLvl) c_int {
    const pData = pLvl.pData.?;

    if (pLvl.iOff == 0) {
        // assert( pLvl->bEof==0 );
        pLvl.iOff = 1;
        pLvl.iOff += fts5GetVarint32Into(c_int, pData.p.? + 1, &pLvl.iLeafPgno);
        var u: u64 = undefined;
        pLvl.iOff += fts5GetVarint(pData.p.? + @as(usize, @intCast(pLvl.iOff)), &u);
        pLvl.iRowid = @bitCast(u);
        pLvl.iFirstOff = pLvl.iOff;
    } else {
        var iOff: c_int = pLvl.iOff;
        while (iOff < pData.nn) : (iOff += 1) {
            if (pData.p.?[@intCast(iOff)] != 0) break;
        }

        if (iOff < pData.nn) {
            var iVal: u64 = 0;
            pLvl.iLeafPgno += (iOff - pLvl.iOff) + 1;
            iOff += fts5GetVarint(pData.p.? + @as(usize, @intCast(iOff)), &iVal);
            pLvl.iRowid +%= @bitCast(iVal);
            pLvl.iOff = iOff;
        } else {
            pLvl.bEof = 1;
        }
    }

    return pLvl.bEof;
}

// Advance the iterator passed as the only argument.
fn fts5DlidxIterNextR(p: *Fts5IndexS, pIter: *Fts5DlidxIter, iLvl: c_int) c_int {
    const pLvl = dlidxLvl(pIter, iLvl);

    // assert( iLvl<pIter->nLvl );
    if (fts5DlidxLvlNext(pLvl) != 0) {
        if ((iLvl + 1) < pIter.nLvl) {
            _ = fts5DlidxIterNextR(p, pIter, iLvl + 1);
            const pLvl1 = dlidxLvl(pIter, iLvl + 1); // pLvl[1]
            if (pLvl1.bEof == 0) {
                fts5DataRelease(pLvl.pData);
                _ = memset(pLvl, 0, @sizeOf(Fts5DlidxLvl));
                pLvl.pData = fts5DataRead(p, FTS5_DLIDX_ROWID(pIter.iSegid, iLvl, pLvl1.iLeafPgno));
                if (pLvl.pData != null) _ = fts5DlidxLvlNext(pLvl);
            }
        }
    }

    return dlidxLvl(pIter, 0).bEof;
}
fn fts5DlidxIterNext(p: *Fts5IndexS, pIterIn: ?*Fts5DlidxIter) c_int {
    const pIter = pIterIn.?;
    return fts5DlidxIterNextR(p, pIter, 0);
}

// Set up the iterator so it points to the first rowid in the doclist-index.
fn fts5DlidxIterFirst(pIter: *Fts5DlidxIter) c_int {
    var i: c_int = 0;
    while (i < pIter.nLvl) : (i += 1) {
        _ = fts5DlidxLvlNext(dlidxLvl(pIter, i));
    }
    return dlidxLvl(pIter, 0).bEof;
}

fn fts5DlidxIterEof(p: *Fts5IndexS, pIterIn: ?*Fts5DlidxIter) c_int {
    const pIter = pIterIn.?;
    return @intFromBool(p.rc != SQLITE_OK or dlidxLvl(pIter, 0).bEof != 0);
}

fn fts5DlidxIterLast(p: *Fts5IndexS, pIter: *Fts5DlidxIter) void {
    var i: c_int = pIter.nLvl - 1;

    // Advance each level to the last entry on the last page
    while (p.rc == SQLITE_OK and i >= 0) : (i -= 1) {
        const pLvl = dlidxLvl(pIter, i);
        while (fts5DlidxLvlNext(pLvl) == 0) {}
        pLvl.bEof = 0;

        if (i > 0) {
            const pChild = dlidxLvl(pIter, i - 1); // pLvl[-1]
            fts5DataRelease(pChild.pData);
            _ = memset(pChild, 0, @sizeOf(Fts5DlidxLvl));
            pChild.pData = fts5DataRead(p, FTS5_DLIDX_ROWID(pIter.iSegid, i - 1, pLvl.iLeafPgno));
        }
    }
}

// Move the iterator passed as the only argument to the previous entry.
fn fts5DlidxLvlPrev(pLvl: *Fts5DlidxLvl) c_int {
    const iOff: c_int = pLvl.iOff;

    // assert( pLvl->bEof==0 );
    if (iOff <= pLvl.iFirstOff) {
        pLvl.bEof = 1;
    } else {
        const a = pLvl.pData.?.p.?;
        const nn = pLvl.pData.?.nn;

        pLvl.iOff = 0;
        _ = fts5DlidxLvlNext(pLvl);
        while (true) {
            var nZero: c_int = 0;
            var ii: c_int = pLvl.iOff;
            var delta: u64 = 0;

            while (ii < nn and a[@intCast(ii)] == 0) {
                nZero += 1;
                ii += 1;
            }
            ii += sqlite3Fts5GetVarint(a + @as(usize, @intCast(ii)), &delta);

            if (ii >= iOff) break;
            pLvl.iLeafPgno += nZero + 1;
            pLvl.iRowid +%= @bitCast(delta);
            pLvl.iOff = ii;
        }
    }

    return pLvl.bEof;
}

fn fts5DlidxIterPrevR(p: *Fts5IndexS, pIter: *Fts5DlidxIter, iLvl: c_int) c_int {
    const pLvl = dlidxLvl(pIter, iLvl);

    // assert( iLvl<pIter->nLvl );
    if (fts5DlidxLvlPrev(pLvl) != 0) {
        if ((iLvl + 1) < pIter.nLvl) {
            _ = fts5DlidxIterPrevR(p, pIter, iLvl + 1);
            const pLvl1 = dlidxLvl(pIter, iLvl + 1); // pLvl[1]
            if (pLvl1.bEof == 0) {
                fts5DataRelease(pLvl.pData);
                _ = memset(pLvl, 0, @sizeOf(Fts5DlidxLvl));
                pLvl.pData = fts5DataRead(p, FTS5_DLIDX_ROWID(pIter.iSegid, iLvl, pLvl1.iLeafPgno));
                if (pLvl.pData != null) {
                    while (fts5DlidxLvlNext(pLvl) == 0) {}
                    pLvl.bEof = 0;
                }
            }
        }
    }

    return dlidxLvl(pIter, 0).bEof;
}
fn fts5DlidxIterPrev(p: *Fts5IndexS, pIterIn: ?*Fts5DlidxIter) c_int {
    const pIter = pIterIn.?;
    return fts5DlidxIterPrevR(p, pIter, 0);
}

// Free a doclist-index iterator object allocated by fts5DlidxIterInit().
fn fts5DlidxIterFree(pIter: ?*Fts5DlidxIter) void {
    if (pIter) |pi| {
        var i: c_int = 0;
        while (i < pi.nLvl) : (i += 1) {
            fts5DataRelease(dlidxLvl(pi, i).pData);
        }
        sqlite3_free(pi);
    }
}

fn fts5DlidxIterInit(
    p: *Fts5IndexS, // Fts5 Backend to iterate within
    bRev: c_int, // True for ORDER BY ASC
    iSegid: c_int, // Segment id
    iLeafPg: c_int, // Leaf page number to load dlidx for
) ?*Fts5DlidxIter {
    var pIter: ?*Fts5DlidxIter = null;
    var i: c_int = 0;
    var bDone: c_int = 0;

    while (p.rc == SQLITE_OK and bDone == 0) : (i += 1) {
        const nByte: i64 = SZ_FTS5DLIDXITER(i + 1);
        const pNew: ?*Fts5DlidxIter = @ptrCast(@alignCast(sqlite3_realloc64(pIter, @intCast(nByte))));
        if (pNew == null) {
            p.rc = SQLITE_NOMEM;
        } else {
            const iRowid: i64 = FTS5_DLIDX_ROWID(iSegid, i, iLeafPg);
            const pLvl = dlidxLvl(pNew.?, i);
            pIter = pNew;
            _ = memset(pLvl, 0, @sizeOf(Fts5DlidxLvl));
            pLvl.pData = fts5DataRead(p, iRowid);
            if (pLvl.pData != null and (pLvl.pData.?.p.?[0] & 0x0001) == 0) {
                bDone = 1;
            }
            pIter.?.nLvl = i + 1;
        }
    }

    if (p.rc == SQLITE_OK) {
        pIter.?.iSegid = iSegid;
        if (bRev == 0) {
            _ = fts5DlidxIterFirst(pIter.?);
        } else {
            fts5DlidxIterLast(p, pIter.?);
        }
    }

    if (p.rc != SQLITE_OK) {
        fts5DlidxIterFree(pIter);
        pIter = null;
    }

    return pIter;
}

fn fts5DlidxIterRowid(pIterIn: ?*Fts5DlidxIter) i64 {
    const pIter = pIterIn.?;
    return dlidxLvl(pIter, 0).iRowid;
}
fn fts5DlidxIterPgno(pIterIn: ?*Fts5DlidxIter) c_int {
    const pIter = pIterIn.?;
    return dlidxLvl(pIter, 0).iLeafPgno;
}

// Load the next leaf page into the segment iterator.
fn fts5SegIterNextPage(
    p: *Fts5IndexS, // FTS5 backend object
    pIter: *Fts5SegIter, // Iterator to advance to next page
) void {
    const pSeg = pIter.pSeg.?;
    fts5DataRelease(pIter.pLeaf);
    pIter.iLeafPgno += 1;
    if (pIter.pNextLeaf != null) {
        pIter.pLeaf = pIter.pNextLeaf;
        pIter.pNextLeaf = null;
    } else if (pIter.iLeafPgno <= pSeg.pgnoLast) {
        pIter.pLeaf = fts5LeafRead(p, FTS5_SEGMENT_ROWID(pSeg.iSegid, pIter.iLeafPgno));
    } else {
        pIter.pLeaf = null;
    }
    const pLeaf = pIter.pLeaf;

    if (pLeaf) |pl| {
        pIter.iPgidxOff = pl.szLeaf;
        if (fts5LeafIsTermless(pl)) {
            pIter.iEndofDoclist = pl.nn + 1;
        } else {
            pIter.iPgidxOff += fts5GetVarint32Into(
                c_int,
                pl.p.? + @as(usize, @intCast(pIter.iPgidxOff)),
                &pIter.iEndofDoclist,
            );
        }
    }
}

// Read a position-list-size varint. Set *pnSz to the poslist byte count and
// *pbDel to the delete flag. Returns the number of bytes read.
fn fts5GetPoslistSize(p: [*]const u8, pnSz: *c_int, pbDel: *c_int) c_int {
    var nSz: c_int = undefined;
    var n: c_int = 0;
    fts5FastGetVarint32(c_int, p, &n, &nSz);
    // assert_nc( nSz>=0 );
    pnSz.* = @divTrunc(nSz, 2);
    pbDel.* = nSz & 0x0001;
    return n;
}

// Read the position-list size field at Fts5SegIter.iLeafOffset into nPos/bDel,
// leaving iLeafOffset at the first byte of position-list content.
fn fts5SegIterLoadNPos(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    if (p.rc == SQLITE_OK) {
        var iOff: c_int = @intCast(pIter.iLeafOffset); // Offset to read at
        if (p.pConfig.?.eDetail == FTS5_DETAIL_NONE) {
            const iEod: c_int = MIN(c_int, pIter.iEndofDoclist, pIter.pLeaf.?.szLeaf);
            pIter.bDel = 0;
            pIter.nPos = 1;
            if (iOff < iEod and pIter.pLeaf.?.p.?[@intCast(iOff)] == 0) {
                pIter.bDel = 1;
                iOff += 1;
                if (iOff < iEod and pIter.pLeaf.?.p.?[@intCast(iOff)] == 0) {
                    pIter.nPos = 1;
                    iOff += 1;
                } else {
                    pIter.nPos = 0;
                }
            }
        } else {
            var nSz: c_int = undefined;
            fts5FastGetVarint32(c_int, pIter.pLeaf.?.p.?, &iOff, &nSz);
            pIter.bDel = @intCast(nSz & 0x0001);
            pIter.nPos = nSz >> 1;
            // assert_nc( pIter->nPos>=0 );
        }
        pIter.iLeafOffset = iOff;
    }
}

fn fts5SegIterLoadRowid(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    var a = pIter.pLeaf.?.p.?; // Buffer to read data from
    var iOff: i64 = pIter.iLeafOffset;

    while (iOff >= pIter.pLeaf.?.szLeaf) {
        fts5SegIterNextPage(p, pIter);
        if (pIter.pLeaf == null) {
            if (p.rc == SQLITE_OK) _ = fts5IndexCorruptIter(p, pIter);
            return;
        }
        iOff = 4;
        a = pIter.pLeaf.?.p.?;
    }
    var u: u64 = undefined;
    iOff += sqlite3Fts5GetVarint(a + @as(usize, @intCast(iOff)), &u);
    pIter.iRowid = @bitCast(u);
    pIter.iLeafOffset = iOff;
}

// Read the term whose nSuffix field starts at Fts5SegIter.iLeafOffset. nKeep is
// the nPrefix value (0 for the first term). Populates Fts5SegIter.term and rowid.
fn fts5SegIterLoadTerm(p: *Fts5IndexS, pIter: *Fts5SegIter, nKeep_in: c_int) void {
    const a = pIter.pLeaf.?.p.?; // Buffer to read data from
    var iOff: i64 = pIter.iLeafOffset; // Offset to read at
    var nNew: c_int = undefined; // Bytes of new data

    iOff += fts5GetVarint32Into(c_int, a + @as(usize, @intCast(iOff)), &nNew);
    if (iOff + nNew > pIter.pLeaf.?.szLeaf or nKeep_in > pIter.term.n or nNew == 0) {
        _ = fts5IndexCorruptIter(p, pIter);
        return;
    }
    pIter.term.n = nKeep_in;
    sqlite3Fts5BufferAppendBlob(&p.rc, &pIter.term, @intCast(nNew), a + @as(usize, @intCast(iOff)));
    // assert( pIter->term.n<=pIter->term.nSpace );
    iOff += nNew;
    pIter.iTermLeafOffset = @intCast(iOff);
    pIter.iTermLeafPgno = pIter.iLeafPgno;
    pIter.iLeafOffset = iOff;

    if (pIter.iPgidxOff >= pIter.pLeaf.?.nn) {
        pIter.iEndofDoclist = pIter.pLeaf.?.nn + 1;
    } else {
        var nExtra: c_int = undefined;
        pIter.iPgidxOff += fts5GetVarint32Into(c_int, a + @as(usize, @intCast(pIter.iPgidxOff)), &nExtra);
        pIter.iEndofDoclist += nExtra;
    }

    fts5SegIterLoadRowid(p, pIter);
}

fn fts5SegIterSetNext(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    if (pIter.flags & FTS5_SEGITER_REVERSE != 0) {
        pIter.xNext = &fts5SegIterNext_Reverse;
    } else if (p.pConfig.?.eDetail == FTS5_DETAIL_NONE) {
        pIter.xNext = &fts5SegIterNext_None;
    } else {
        pIter.xNext = &fts5SegIterNext;
    }
}

// Allocate a tombstone hash page array object (pIter->pTombArray).
fn fts5SegIterAllocTombstone(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    const nTomb: i64 = @intCast(pIter.pSeg.?.nPgTombstone);
    if (nTomb > 0) {
        const nByte: i64 = SZ_FTS5TOMBSTONEARRAY(nTomb + 1);
        const pNew: ?*Fts5TombstoneArray = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&p.rc, nByte)));
        if (pNew) |pn| {
            pn.nTombstone = @intCast(nTomb);
            pn.nRef = 1;
            pIter.pTombArray = pn;
        }
    }
}

// Initialize pIter to iterate through the entries in segment pSeg, leaving it
// pointing at the first entry.
fn fts5SegIterInit(
    p: *Fts5IndexS, // FTS index object
    pSeg: *Fts5StructureSegment, // Description of segment
    pIter: *Fts5SegIter, // Object to populate
) void {
    if (pSeg.pgnoFirst == 0) {
        // Segment trimmed to empty during incremental merge; leave iterator empty.
        // assert( pIter->pLeaf==0 );
        return;
    }

    if (p.rc == SQLITE_OK) {
        _ = memset(pIter, 0, @sizeOf(Fts5SegIter));
        fts5SegIterSetNext(p, pIter);
        pIter.pSeg = pSeg;
        pIter.iLeafPgno = pSeg.pgnoFirst - 1;
        while (true) {
            fts5SegIterNextPage(p, pIter);
            if (!(p.rc == SQLITE_OK and pIter.pLeaf != null and pIter.pLeaf.?.nn == 4)) break;
        }
    }

    if (p.rc == SQLITE_OK and pIter.pLeaf != null) {
        pIter.iLeafOffset = 4;
        pIter.iPgidxOff = pIter.pLeaf.?.szLeaf + 1;
        fts5SegIterLoadTerm(p, pIter, 0);
        fts5SegIterLoadNPos(p, pIter);
        fts5SegIterAllocTombstone(p, pIter);
    }
}

// Advance a FTS5INDEX_QUERY_DESC iterator to the last relevant rowid on the
// current page, initializing aRowidOffset[]/iRowidOffset as needed.
fn fts5SegIterReverseInitPage(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    const eDetail = p.pConfig.?.eDetail;
    var n: c_int = pIter.pLeaf.?.szLeaf;
    var i: c_int = @intCast(pIter.iLeafOffset);
    const a = pIter.pLeaf.?.p.?;
    var iRowidOffset: c_int = 0;

    if (n > pIter.iEndofDoclist) {
        n = pIter.iEndofDoclist;
    }

    while (true) {
        var iDelta: u64 = 0;

        if (i >= n) break;
        if (eDetail == FTS5_DETAIL_NONE) {
            // todo
            if (i < n and a[@intCast(i)] == 0) {
                i += 1;
                if (i < n and a[@intCast(i)] == 0) i += 1;
            }
        } else {
            var nPos: c_int = undefined;
            var bDummy: c_int = undefined;
            i += fts5GetPoslistSize(a + @as(usize, @intCast(i)), &nPos, &bDummy);
            i += nPos;
        }
        if (i >= n) break;
        i += fts5GetVarint(a + @as(usize, @intCast(i)), &iDelta);
        pIter.iRowid +%= @bitCast(iDelta);

        // If necessary, grow the pIter->aRowidOffset[] array.
        if (iRowidOffset >= pIter.nRowidOffset) {
            const nNew: i64 = @as(i64, pIter.nRowidOffset) + 8;
            const aNew: ?[*]c_int = @ptrCast(@alignCast(sqlite3_realloc64(
                pIter.aRowidOffset,
                @intCast(nNew * @sizeOf(c_int)),
            )));
            if (aNew == null) {
                p.rc = SQLITE_NOMEM;
                break;
            }
            pIter.aRowidOffset = aNew;
            pIter.nRowidOffset = @intCast(nNew);
        }

        pIter.aRowidOffset.?[@intCast(iRowidOffset)] = @intCast(pIter.iLeafOffset);
        iRowidOffset += 1;
        pIter.iLeafOffset = i;
    }
    pIter.iRowidOffset = iRowidOffset;
    fts5SegIterLoadNPos(p, pIter);
}

fn fts5SegIterReverseNewPage(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    // assert( pIter->flags & FTS5_SEGITER_REVERSE );
    // assert( pIter->flags & FTS5_SEGITER_ONETERM );

    fts5DataRelease(pIter.pLeaf);
    pIter.pLeaf = null;
    while (p.rc == SQLITE_OK and pIter.iLeafPgno > pIter.iTermLeafPgno) {
        pIter.iLeafPgno -= 1;
        const pNew = fts5LeafRead(p, FTS5_SEGMENT_ROWID(pIter.pSeg.?.iSegid, pIter.iLeafPgno));
        if (pNew) |pn| {
            // iTermLeafOffset may equal szLeaf if the term is the last thing on
            // the page - i.e. the first rowid is on the following page. Then
            // leave pIter->pLeaf==0; this iterator is at EOF.
            if (pIter.iLeafPgno == pIter.iTermLeafPgno) {
                // assert( pIter->pLeaf==0 );
                if (pIter.iTermLeafOffset < pn.szLeaf) {
                    pIter.pLeaf = pn;
                    pIter.iLeafOffset = pIter.iTermLeafOffset;
                }
            } else {
                const iRowidOff = fts5LeafFirstRowidOff(pn);
                if (iRowidOff != 0) {
                    if (iRowidOff >= pn.szLeaf) {
                        _ = fts5IndexCorruptIter(p, pIter);
                    } else {
                        pIter.pLeaf = pn;
                        pIter.iLeafOffset = iRowidOff;
                    }
                }
            }

            if (pIter.pLeaf != null) {
                const aa = pIter.pLeaf.?.p.? + @as(usize, @intCast(pIter.iLeafOffset));
                var u: u64 = undefined;
                pIter.iLeafOffset += fts5GetVarint(aa, &u);
                pIter.iRowid = @bitCast(u);
                break;
            } else {
                fts5DataRelease(pn);
            }
        }
    }

    if (pIter.pLeaf != null) {
        pIter.iEndofDoclist = pIter.pLeaf.?.nn + 1;
        fts5SegIterReverseInitPage(p, pIter);
    }
}

// Return true if the iterator currently points to a delete marker (an entry
// with a 0-byte position-list).
fn fts5MultiIterIsEmpty(p: *Fts5IndexS, pIterIn: ?*Fts5Iter) c_int {
    const pIter = pIterIn.?;
    const aFirst = pIter.aFirst.?;
    const pSeg = iterSeg(pIter, @intCast(aFirst[1].iFirst));
    return @intFromBool(p.rc == SQLITE_OK and pSeg.pLeaf != null and pSeg.nPos == 0);
}

// Advance iterator pIter to the next entry. Reverse-iterator version.
fn fts5SegIterNext_Reverse(
    p_: ?*Fts5IndexS, // FTS5 backend object
    pIter_: ?*Fts5SegIter, // Iterator to advance
    pbUnused: ?*c_int, // Unused
) callconv(.c) void {
    _ = pbUnused;
    const p = p_.?;
    const pIter = pIter_.?;
    // assert( pIter->flags & FTS5_SEGITER_REVERSE );
    // assert( pIter->pNextLeaf==0 );

    if (pIter.iRowidOffset > 0) {
        const a = pIter.pLeaf.?.p.?;
        var iOff: c_int = undefined;
        var iDelta: u64 = undefined;

        pIter.iRowidOffset -= 1;
        pIter.iLeafOffset = pIter.aRowidOffset.?[@intCast(pIter.iRowidOffset)];
        fts5SegIterLoadNPos(p, pIter);
        iOff = @intCast(pIter.iLeafOffset);
        if (p.pConfig.?.eDetail != FTS5_DETAIL_NONE) {
            iOff += pIter.nPos;
        }
        _ = fts5GetVarint(a + @as(usize, @intCast(iOff)), &iDelta);
        pIter.iRowid -%= @bitCast(iDelta);
    } else {
        fts5SegIterReverseNewPage(p, pIter);
    }
}

// Advance iterator pIter to the next entry. detail=none non-reverse version.
fn fts5SegIterNext_None(
    p_: ?*Fts5IndexS, // FTS5 backend object
    pIter_: ?*Fts5SegIter, // Iterator to advance
    pbNewTerm: ?*c_int, // OUT: Set for new term
) callconv(.c) void {
    const p = p_.?;
    const pIter = pIter_.?;
    var iOff: c_int = undefined;

    // assert( p->rc==SQLITE_OK );
    // assert( (pIter->flags & FTS5_SEGITER_REVERSE)==0 );
    // assert( p->pConfig->eDetail==FTS5_DETAIL_NONE );

    iOff = @intCast(pIter.iLeafOffset);

    // Next entry is on the next page
    while (pIter.pSeg != null and iOff >= pIter.pLeaf.?.szLeaf) {
        fts5SegIterNextPage(p, pIter);
        if (p.rc != SQLITE_OK or pIter.pLeaf == null) return;
        pIter.iRowid = 0;
        iOff = 4;
    }

    if (iOff < pIter.iEndofDoclist) {
        // Next entry is on the current page
        var iDelta: u64 = undefined;
        iOff += sqlite3Fts5GetVarint(pIter.pLeaf.?.p.? + @as(usize, @intCast(iOff)), &iDelta);
        pIter.iLeafOffset = iOff;
        pIter.iRowid +%= @bitCast(iDelta);
    } else if ((pIter.flags & FTS5_SEGITER_ONETERM) == 0) {
        if (pIter.pSeg != null) {
            var nKeep: c_int = 0;
            if (iOff != fts5LeafFirstTermOff(pIter.pLeaf.?)) {
                iOff += fts5GetVarint32Into(c_int, pIter.pLeaf.?.p.? + @as(usize, @intCast(iOff)), &nKeep);
            }
            pIter.iLeafOffset = iOff;
            fts5SegIterLoadTerm(p, pIter, nKeep);
        } else {
            var pList: ?[*]const u8 = null;
            var zTerm: ?[*:0]const u8 = null;
            var nTerm: c_int = 0;
            var nList: c_int = undefined;
            sqlite3Fts5HashScanNext(p.pHash.?);
            sqlite3Fts5HashScanEntry(p.pHash.?, &zTerm, &nTerm, &pList, &nList);
            if (pList == null) {
                fts5DataRelease(pIter.pLeaf);
                pIter.pLeaf = null;
                return;
            }
            pIter.pLeaf.?.p = @constCast(pList);
            pIter.pLeaf.?.nn = nList;
            pIter.pLeaf.?.szLeaf = nList;
            pIter.iEndofDoclist = nList;
            sqlite3Fts5BufferSet(&p.rc, &pIter.term, nTerm, @ptrCast(zTerm));
            var u: u64 = undefined;
            pIter.iLeafOffset = fts5GetVarint(pList.?, &u);
            pIter.iRowid = @bitCast(u);
        }

        if (pbNewTerm) |pb| pb.* = 1;
    } else {
        fts5DataRelease(pIter.pLeaf);
        pIter.pLeaf = null;
        return;
    }

    fts5SegIterLoadNPos(p, pIter);
}

// Advance iterator pIter to the next entry. (Default detail=full forward.)
fn fts5SegIterNext(
    p_: ?*Fts5IndexS, // FTS5 backend object
    pIter_: ?*Fts5SegIter, // Iterator to advance
    pbNewTerm: ?*c_int, // OUT: Set for new term
) callconv(.c) void {
    const p = p_.?;
    const pIter = pIter_.?;
    var pLeaf = pIter.pLeaf;
    var iOff: c_int = undefined;
    var bNewTerm: c_int = 0;
    var nKeep: c_int = 0;
    var a: [*]u8 = undefined;
    var n: c_int = undefined;

    // assert( pbNewTerm==0 || *pbNewTerm==0 );
    // assert( p->pConfig->eDetail!=FTS5_DETAIL_NONE );

    // Search for the end of the position list within the current page.
    a = pLeaf.?.p.?;
    n = pLeaf.?.szLeaf;

    iOff = @as(c_int, @intCast(pIter.iLeafOffset)) + pIter.nPos;

    if (iOff < n) {
        // The next entry is on the current page.
        if (iOff >= pIter.iEndofDoclist) {
            bNewTerm = 1;
            if (iOff != fts5LeafFirstTermOff(pLeaf.?)) {
                iOff += fts5GetVarint32Into(c_int, a + @as(usize, @intCast(iOff)), &nKeep);
            }
        } else {
            var iDelta: u64 = undefined;
            iOff += sqlite3Fts5GetVarint(a + @as(usize, @intCast(iOff)), &iDelta);
            pIter.iRowid +%= @bitCast(iDelta);
        }
        pIter.iLeafOffset = iOff;
    } else if (pIter.pSeg == null) {
        var pList: ?[*]const u8 = null;
        var zTerm: ?[*:0]const u8 = null;
        var nTerm: c_int = 0;
        var nList: c_int = 0;
        // assert( (pIter->flags & FTS5_SEGITER_ONETERM) || pbNewTerm );
        if (0 == (pIter.flags & FTS5_SEGITER_ONETERM)) {
            sqlite3Fts5HashScanNext(p.pHash.?);
            sqlite3Fts5HashScanEntry(p.pHash.?, &zTerm, &nTerm, &pList, &nList);
        }
        if (pList == null) {
            fts5DataRelease(pIter.pLeaf);
            pIter.pLeaf = null;
        } else {
            pIter.pLeaf.?.p = @constCast(pList);
            pIter.pLeaf.?.nn = nList;
            pIter.pLeaf.?.szLeaf = nList;
            pIter.iEndofDoclist = nList + 1;
            sqlite3Fts5BufferSet(&p.rc, &pIter.term, nTerm, @ptrCast(zTerm));
            var u: u64 = undefined;
            pIter.iLeafOffset = fts5GetVarint(pList.?, &u);
            pIter.iRowid = @bitCast(u);
            pbNewTerm.?.* = 1;
        }
    } else {
        iOff = 0;
        // Next entry is not on the current page
        while (iOff == 0) {
            fts5SegIterNextPage(p, pIter);
            pLeaf = pIter.pLeaf;
            if (pLeaf == null) break;
            iOff = fts5LeafFirstRowidOff(pLeaf.?);
            if (iOff != 0 and iOff < pLeaf.?.szLeaf) {
                var u: u64 = undefined;
                iOff += sqlite3Fts5GetVarint(pLeaf.?.p.? + @as(usize, @intCast(iOff)), &u);
                pIter.iRowid = @bitCast(u);
                pIter.iLeafOffset = iOff;

                if (pLeaf.?.nn > pLeaf.?.szLeaf) {
                    pIter.iPgidxOff = pLeaf.?.szLeaf + fts5GetVarint32Into(
                        c_int,
                        pLeaf.?.p.? + @as(usize, @intCast(pLeaf.?.szLeaf)),
                        &pIter.iEndofDoclist,
                    );
                }
            } else if (pLeaf.?.nn > pLeaf.?.szLeaf) {
                pIter.iPgidxOff = pLeaf.?.szLeaf + fts5GetVarint32Into(
                    c_int,
                    pLeaf.?.p.? + @as(usize, @intCast(pLeaf.?.szLeaf)),
                    &iOff,
                );
                pIter.iLeafOffset = iOff;
                pIter.iEndofDoclist = iOff;
                bNewTerm = 1;
            }
            // assert_nc( iOff<pLeaf->szLeaf );
            if (iOff > pLeaf.?.szLeaf) {
                _ = fts5IndexCorruptIter(p, pIter);
                return;
            }
        }
    }

    // Check if the iterator is now at EOF. If so, return early.
    if (pIter.pLeaf != null) {
        if (bNewTerm != 0) {
            if (pIter.flags & FTS5_SEGITER_ONETERM != 0) {
                fts5DataRelease(pIter.pLeaf);
                pIter.pLeaf = null;
            } else {
                fts5SegIterLoadTerm(p, pIter, nKeep);
                fts5SegIterLoadNPos(p, pIter);
                if (pbNewTerm) |pb| pb.* = 1;
            }
        } else {
            // Equivalent of fts5SegIterLoadNPos(), inlined for performance.
            var nSz: c_int = undefined;
            var off: c_int = @intCast(pIter.iLeafOffset);
            fts5FastGetVarint32(c_int, pIter.pLeaf.?.p.?, &off, &nSz);
            pIter.iLeafOffset = off;
            pIter.bDel = @intCast(nSz & 0x0001);
            pIter.nPos = nSz >> 1;
        }
    }
}

// Set the iterator (currently pointing at the first rowid in a doclist) up to
// iterate in reverse order through the doclist.
fn fts5SegIterReverse(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    const pDlidx = pIter.pDlidx;
    var pLast: ?*Fts5Data = null;
    var pgnoLast: c_int = 0;

    if (pDlidx != null and p.pConfig.?.iVersion == FTS5_CURRENT_VERSION) {
        const iSegid = pIter.pSeg.?.iSegid;
        pgnoLast = fts5DlidxIterPgno(pDlidx.?);
        pLast = fts5LeafRead(p, FTS5_SEGMENT_ROWID(iSegid, pgnoLast));
    } else {
        const pLeaf = pIter.pLeaf.?; // Current leaf data

        // Back iLeafOffset up to the start of the position-list size field.
        var iPoslist: c_int = undefined;
        if (pIter.iTermLeafPgno == pIter.iLeafPgno) {
            iPoslist = pIter.iTermLeafOffset;
        } else {
            iPoslist = 4;
        }
        fts5IndexSkipVarint(pLeaf.p.?, &iPoslist);
        pIter.iLeafOffset = iPoslist;

        // The largest rowid for the current term may not be on the current
        // page. Search forward to find the page containing the last rowid.
        if (pIter.iEndofDoclist >= pLeaf.szLeaf) {
            const pSeg = pIter.pSeg.?;
            var pgno: c_int = pIter.iLeafPgno + 1;
            while (p.rc == 0 and pgno <= pSeg.pgnoLast) : (pgno += 1) {
                const iAbs: i64 = FTS5_SEGMENT_ROWID(pSeg.iSegid, pgno);
                const pNew = fts5LeafRead(p, iAbs);
                if (pNew) |pn| {
                    const iRowid = fts5LeafFirstRowidOff(pn);
                    const bTermless = fts5LeafIsTermless(pn);
                    if (iRowid != 0) {
                        // SWAPVAL(Fts5Data*, pNew, pLast)
                        const tmp = pLast;
                        pLast = pn;
                        // pNew now holds old pLast for release below
                        fts5DataRelease(tmp);
                        pgnoLast = pgno;
                    } else {
                        fts5DataRelease(pn);
                    }
                    if (bTermless == false) break;
                }
            }
        }
    }

    // If pLast is NULL the last rowid lies on the page the iterator already
    // indicates. Otherwise pLast is the page containing the last rowid; set up
    // the iterator to point at the first rowid on that page.
    if (pLast) |pl| {
        fts5DataRelease(pIter.pLeaf);
        pIter.pLeaf = pl;
        pIter.iLeafPgno = pgnoLast;
        if (p.rc == SQLITE_OK) {
            var iOff = fts5LeafFirstRowidOff(pl);
            if (iOff > pl.szLeaf) {
                _ = fts5IndexCorruptIter(p, pIter);
                return;
            }
            var u: u64 = undefined;
            iOff += @intCast(fts5GetVarint(pl.p.? + @as(usize, @intCast(iOff)), &u));
            pIter.iRowid = @bitCast(u);
            pIter.iLeafOffset = iOff;

            if (fts5LeafIsTermless(pl)) {
                pIter.iEndofDoclist = pl.nn + 1;
            } else {
                pIter.iEndofDoclist = fts5LeafFirstTermOff(pl);
            }
        }
    }

    fts5SegIterReverseInitPage(p, pIter);
}

// If the current term is the last term on the current page, load its
// doclist-index from disk and initialize an iterator at pIter->pDlidx.
fn fts5SegIterLoadDlidx(p: *Fts5IndexS, pIter: *Fts5SegIter) void {
    const iSeg = pIter.pSeg.?.iSegid;
    const bRev = (pIter.flags & FTS5_SEGITER_REVERSE);
    const pLeaf = pIter.pLeaf.?; // Current leaf data

    // assert( pIter->flags & FTS5_SEGITER_ONETERM );
    // assert( pIter->pDlidx==0 );

    // If the current doclist ends on this page the doclist-index belongs to a
    // different term; return early without loading it.
    if (pIter.iTermLeafPgno == pIter.iLeafPgno and pIter.iEndofDoclist < pLeaf.szLeaf) {
        return;
    }

    pIter.pDlidx = fts5DlidxIterInit(p, bRev, iSeg, pIter.iTermLeafPgno);
}

// ============================ CHUNK 4 ============================

// ---------------------------------------------------------------------------
// fts5LeafSeek — binary/term seek within a leaf page (byte-exact pgidx walk).
// ---------------------------------------------------------------------------
fn fts5LeafSeek(
    p: *Fts5IndexS,
    bGe: c_int,
    pIter: *Fts5SegIter,
    pTerm: [*]const u8,
    nTerm: c_int,
) void {
    var iOff: u32 = undefined;
    var a: [*]const u8 = pIter.pLeaf.?.p.?;
    var n: u32 = @intCast(pIter.pLeaf.?.nn);

    var nMatch: u32 = 0;
    var nKeep: u32 = 0;
    var nNew: u32 = 0;
    var iTermOff: u32 = undefined;
    var iPgidx: u32 = undefined; // Current offset in pgidx
    var bEndOfPage: c_int = 0;

    // assert( p->rc==SQLITE_OK );

    iPgidx = @intCast(pIter.pLeaf.?.szLeaf);
    iPgidx += @intCast(fts5GetVarint32Into(u32, a + iPgidx, &iTermOff));
    iOff = iTermOff;
    if (iOff > n) {
        _ = fts5IndexCorruptIter(p, pIter);
        return;
    }

    // Labeled blocks model the C gotos:
    //   goto search_failed  -> break :failed
    //   goto search_success -> break :success (the outer block; tail follows)
    success: {
        failed: {
            while (true) {
                // Figure out how many new bytes are in this term
                {
                    var iOffI: c_int = @bitCast(iOff);
                    fts5FastGetVarint32(u32, a, &iOffI, &nNew);
                    iOff = @bitCast(iOffI);
                }
                if (nKeep < nMatch) {
                    break :failed;
                }
                if ((iOff + nNew) > n) {
                    _ = fts5IndexCorruptIter(p, pIter);
                    return;
                }

                // assert( nKeep>=nMatch );
                if (nKeep == nMatch) {
                    var nCmp: u32 = undefined;
                    var i: u32 = undefined;
                    nCmp = @min(nNew, @as(u32, @bitCast(nTerm)) -% nMatch);
                    i = 0;
                    while (i < nCmp) : (i += 1) {
                        if (a[iOff + i] != pTerm[nMatch + i]) break;
                    }
                    nMatch += i;

                    if (@as(u32, @bitCast(nTerm)) == nMatch) {
                        if (i == nNew) {
                            break :success;
                        } else {
                            break :failed;
                        }
                    } else if (i < nNew and a[iOff + i] > pTerm[nMatch]) {
                        break :failed;
                    }
                }

                if (iPgidx >= n) {
                    bEndOfPage = 1;
                    break :failed;
                }

                iPgidx += @intCast(fts5GetVarint32Into(u32, a + iPgidx, &nKeep));
                iTermOff += nKeep;
                iOff = iTermOff;

                if (iOff >= n) {
                    _ = fts5IndexCorruptIter(p, pIter);
                    return;
                }

                // Read the nKeep field of the next term.
                {
                    var iOffI: c_int = @bitCast(iOff);
                    fts5FastGetVarint32(u32, a, &iOffI, &nKeep);
                    iOff = @bitCast(iOffI);
                }
            }
        } // :failed -- both `break :failed` and the bEndOfPage break land here

        // search_failed: (must run AFTER the failed block so `break :failed`
        // reaches it -- in C this is the `search_failed:` label that goto jumps
        // to, then FALLS THROUGH into search_success. `break :success` skips it.)
        if (bGe == 0) {
            fts5DataRelease(pIter.pLeaf);
            pIter.pLeaf = null;
            return;
        } else if (bEndOfPage != 0) {
            while (true) {
                fts5SegIterNextPage(p, pIter);
                if (pIter.pLeaf == null) return;
                a = pIter.pLeaf.?.p.?;
                if (!fts5LeafIsTermless(pIter.pLeaf.?)) {
                    iPgidx = @intCast(pIter.pLeaf.?.szLeaf);
                    iPgidx += @intCast(fts5GetVarint32Into(u32, pIter.pLeaf.?.p.? + iPgidx, &iOff));
                    if (iOff < 4 or @as(i64, iOff) >= pIter.pLeaf.?.szLeaf) {
                        _ = fts5IndexCorruptIter(p, pIter);
                        return;
                    } else {
                        nKeep = 0;
                        iTermOff = iOff;
                        n = @intCast(pIter.pLeaf.?.nn);
                        iOff += @intCast(fts5GetVarint32Into(u32, a + iOff, &nNew));
                        break;
                    }
                }
            }
        }
        // fall through to search_success
    } // :success -- `break :success` lands here, skipping search_failed

    // search_success:
    if (@as(i64, iOff) + nNew > n or nNew < 1) {
        _ = fts5IndexCorruptIter(p, pIter);
        return;
    }
    pIter.iLeafOffset = @as(i64, iOff) + nNew;
    pIter.iTermLeafOffset = @intCast(pIter.iLeafOffset);
    pIter.iTermLeafPgno = pIter.iLeafPgno;

    fts5BufferSet(&p.rc, &pIter.term, @bitCast(nKeep), pTerm);
    fts5BufferAppendBlob(&p.rc, &pIter.term, @bitCast(nNew), a + iOff);

    if (iPgidx >= n) {
        pIter.iEndofDoclist = pIter.pLeaf.?.nn + 1;
    } else {
        var nExtra: c_int = undefined;
        iPgidx += @intCast(fts5GetVarint32Into(c_int, a + iPgidx, &nExtra));
        pIter.iEndofDoclist = @as(c_int, @bitCast(iTermOff)) + nExtra;
    }
    pIter.iPgidxOff = @bitCast(iPgidx);

    fts5SegIterLoadRowid(p, pIter);
    fts5SegIterLoadNPos(p, pIter);
}

// ---------------------------------------------------------------------------
fn fts5IdxSelectStmt(p: *Fts5IndexS) ?*sqlite3_stmt {
    if (p.pIdxSelect == null) {
        const pConfig: *Fts5Config = p.pConfig.?;
        _ = fts5IndexPrepareStmt(p, &p.pIdxSelect, sqlite3_mprintf(
            "SELECT pgno FROM '%q'.'%q_idx' WHERE " ++
                "segid=? AND term<=? ORDER BY term DESC LIMIT 1",
            pConfig.zDb,
            pConfig.zName,
        ));
    }
    return p.pIdxSelect;
}

// ---------------------------------------------------------------------------
fn fts5SegIterSeekInit(
    p: *Fts5IndexS,
    pTerm: [*]const u8,
    nTerm: c_int,
    flags: c_int,
    pSeg: *Fts5StructureSegment,
    pIter: *Fts5SegIter,
) void {
    var iPg: c_int = 1;
    const bGe: c_int = (flags & FTS5INDEX_QUERY_SCAN);
    var bDlidx: c_int = 0; // True if there is a doclist-index
    var pIdxSelect: ?*sqlite3_stmt = null;

    _ = memset(pIter, 0, @sizeOf(Fts5SegIter));
    pIter.pSeg = pSeg;

    // Set iPg to the leaf page number that may contain term (pTerm/nTerm).
    pIdxSelect = fts5IdxSelectStmt(p);
    if (p.rc != 0) return;
    _ = sqlite3_bind_int(pIdxSelect, 1, pSeg.iSegid);
    _ = sqlite3_bind_blob(pIdxSelect, 2, pTerm, nTerm, int.SQLITE_STATIC);
    if (SQLITE_ROW == sqlite3_step(pIdxSelect)) {
        const val: i64 = sqlite3_column_int(pIdxSelect, 0);
        iPg = @intCast(val >> 1);
        bDlidx = @intCast(val & 0x0001);
    }
    p.rc = sqlite3_reset(pIdxSelect);
    _ = sqlite3_bind_null(pIdxSelect, 2);

    if (iPg < pSeg.pgnoFirst) {
        iPg = pSeg.pgnoFirst;
        bDlidx = 0;
    }

    pIter.iLeafPgno = iPg - 1;
    fts5SegIterNextPage(p, pIter);

    if (pIter.pLeaf != null) {
        fts5LeafSeek(p, bGe, pIter, pTerm, nTerm);
    }

    if (p.rc == SQLITE_OK and (bGe == 0 or (flags & FTS5INDEX_QUERY_SCANONETERM) != 0)) {
        pIter.flags |= FTS5_SEGITER_ONETERM;
        if (pIter.pLeaf != null) {
            if (flags & FTS5INDEX_QUERY_DESC != 0) {
                pIter.flags |= FTS5_SEGITER_REVERSE;
            }
            if (bDlidx != 0) {
                fts5SegIterLoadDlidx(p, pIter);
            }
            if (flags & FTS5INDEX_QUERY_DESC != 0) {
                fts5SegIterReverse(p, pIter);
            }
        }
    }

    fts5SegIterSetNext(p, pIter);
    if (0 == (flags & FTS5INDEX_QUERY_SCANONETERM)) {
        fts5SegIterAllocTombstone(p, pIter);
    }
    // assert_nc(...) dropped.
}

// ---------------------------------------------------------------------------
fn fts5IdxNextStmt(p: *Fts5IndexS) ?*sqlite3_stmt {
    if (p.pIdxNextSelect == null) {
        const pConfig: *Fts5Config = p.pConfig.?;
        _ = fts5IndexPrepareStmt(p, &p.pIdxNextSelect, sqlite3_mprintf(
            "SELECT pgno FROM '%q'.'%q_idx' WHERE " ++
                "segid=? AND term>? ORDER BY term ASC LIMIT 1",
            pConfig.zDb,
            pConfig.zName,
        ));
    }
    return p.pIdxNextSelect;
}

// ---------------------------------------------------------------------------
fn fts5SegIterNextInit(
    p: *Fts5IndexS,
    pTerm: [*]const u8,
    nTerm: c_int,
    pSeg: *Fts5StructureSegment,
    pIter: *Fts5SegIter,
) void {
    var iPg: c_int = -1; // Page of segment to open
    var bDlidx: c_int = 0;
    var pSel: ?*sqlite3_stmt = null; // SELECT to find iPg

    pSel = fts5IdxNextStmt(p);
    if (pSel != null) {
        // assert( p->rc==SQLITE_OK );
        _ = sqlite3_bind_int(pSel, 1, pSeg.iSegid);
        _ = sqlite3_bind_blob(pSel, 2, pTerm, nTerm, int.SQLITE_STATIC);

        if (sqlite3_step(pSel) == SQLITE_ROW) {
            const val: i64 = sqlite3_column_int64(pSel, 0);
            iPg = @intCast(val >> 1);
            bDlidx = @intCast(val & 0x0001);
        }
        p.rc = sqlite3_reset(pSel);
        _ = sqlite3_bind_null(pSel, 2);
        if (p.rc != 0) return;
    }

    _ = memset(pIter, 0, @sizeOf(Fts5SegIter));
    pIter.pSeg = pSeg;
    pIter.flags |= FTS5_SEGITER_ONETERM;
    if (iPg >= 0) {
        pIter.iLeafPgno = iPg - 1;
        fts5SegIterNextPage(p, pIter);
        fts5SegIterSetNext(p, pIter);
    }
    if (pIter.pLeaf != null) {
        const a: [*]const u8 = pIter.pLeaf.?.p.?;
        var iTermOff: c_int = 0;

        pIter.iPgidxOff = pIter.pLeaf.?.szLeaf;
        pIter.iPgidxOff += fts5GetVarint32Into(c_int, a + @as(usize, @intCast(pIter.iPgidxOff)), &iTermOff);
        pIter.iLeafOffset = iTermOff;
        fts5SegIterLoadTerm(p, pIter, 0);
        fts5SegIterLoadNPos(p, pIter);
        if (bDlidx != 0) fts5SegIterLoadDlidx(p, pIter);
        // assert(...) dropped.
    }
}

// ---------------------------------------------------------------------------
fn fts5SegIterHashInit(
    p: *Fts5IndexS,
    pTerm: ?[*]const u8,
    nTerm: c_int,
    flags: c_int,
    pIter: *Fts5SegIter,
) void {
    var nList: c_int = 0;
    var z: ?[*]const u8 = null;
    var n: c_int = 0;
    var pLeaf: ?*Fts5Data = null;

    // assert( p->pHash ); assert( p->rc==SQLITE_OK );

    if (pTerm == null or (flags & FTS5INDEX_QUERY_SCAN) != 0) {
        var pList: ?[*]const u8 = null;

        p.rc = sqlite3Fts5HashScanInit(p.pHash.?, pTerm, nTerm);
        {
            var zTerm: ?[*:0]const u8 = null;
            sqlite3Fts5HashScanEntry(p.pHash.?, &zTerm, &n, &pList, &nList);
            z = @ptrCast(zTerm);
        }
        if (pList != null) {
            pLeaf = @ptrCast(@alignCast(fts5IdxMalloc(p, @sizeOf(Fts5Data))));
            if (pLeaf != null) {
                pLeaf.?.p = @constCast(pList);
            }
        }

        // Clearing bDelete avoids appending to size-filled poslists.
        p.bDelete = 0;
    } else {
        var pp: ?*const anyopaque = null;
        p.rc = sqlite3Fts5HashQuery(p.pHash.?, @sizeOf(Fts5Data), pTerm.?, nTerm, &pp, &nList);
        pLeaf = @ptrCast(@alignCast(@constCast(pp)));
        if (pLeaf != null) {
            // pLeaf->p = (u8*)&pLeaf[1];
            const base: [*]Fts5Data = @ptrCast(pLeaf.?);
            pLeaf.?.p = @ptrCast(&base[1]);
        }
        z = pTerm;
        n = nTerm;
        pIter.flags |= FTS5_SEGITER_ONETERM;
    }

    if (pLeaf != null) {
        sqlite3Fts5BufferSet(&p.rc, &pIter.term, n, z.?);
        pLeaf.?.nn = nList;
        pLeaf.?.szLeaf = nList;
        pIter.pLeaf = pLeaf;
        pIter.iLeafOffset = fts5GetVarint(pLeaf.?.p.?, @ptrCast(&pIter.iRowid));
        pIter.iEndofDoclist = pLeaf.?.nn;

        if (flags & FTS5INDEX_QUERY_DESC != 0) {
            pIter.flags |= FTS5_SEGITER_REVERSE;
            fts5SegIterReverseInitPage(p, pIter);
        } else {
            fts5SegIterLoadNPos(p, pIter);
        }
    }

    fts5SegIterSetNext(p, pIter);
}

// ---------------------------------------------------------------------------
fn fts5IndexFreeArray(ap: ?[*]?*Fts5Data, n: c_int) void {
    if (ap) |a| {
        var ii: c_int = 0;
        while (ii < n) : (ii += 1) {
            fts5DataRelease(a[@intCast(ii)]);
        }
        sqlite3_free(@ptrCast(a));
    }
}

// ---------------------------------------------------------------------------
fn fts5TombstoneArrayDelete(p: ?*Fts5TombstoneArray) void {
    if (p) |pArr| {
        pArr.nRef -= 1;
        if (pArr.nRef <= 0) {
            var ii: c_int = 0;
            while (ii < pArr.nTombstone) : (ii += 1) {
                fts5DataRelease(tombstonePtr(pArr, ii).*);
            }
            sqlite3_free(pArr);
        }
    }
}

// ---------------------------------------------------------------------------
fn fts5SegIterClear(pIter: *Fts5SegIter) void {
    fts5BufferFree(&pIter.term);
    fts5DataRelease(pIter.pLeaf);
    fts5DataRelease(pIter.pNextLeaf);
    fts5TombstoneArrayDelete(pIter.pTombArray);
    fts5DlidxIterFree(pIter.pDlidx);
    sqlite3_free(pIter.aRowidOffset);
    _ = memset(pIter, 0, @sizeOf(Fts5SegIter));
}

// ---------------------------------------------------------------------------
// SQLITE_DEBUG-only assert helper, ported as a normal fn.
fn fts5AssertComparisonResult(
    pIter: *Fts5Iter,
    p1: *Fts5SegIter,
    p2: *Fts5SegIter,
    pRes: *Fts5CResult,
) void {
    const segBase: [*]Fts5SegIter = @ptrCast(&pIter.aSeg);
    const iA1: c_int = @intCast((@intFromPtr(p1) - @intFromPtr(segBase)) / @sizeOf(Fts5SegIter));
    const iA2: c_int = @intCast((@intFromPtr(p2) - @intFromPtr(segBase)) / @sizeOf(Fts5SegIter));

    if (p1.pLeaf != null or p2.pLeaf != null) {
        if (p1.pLeaf == null) {
            std.debug.assert(pRes.iFirst == iA2);
        } else if (p2.pLeaf == null) {
            std.debug.assert(pRes.iFirst == iA1);
        } else {
            const nMin: c_int = MIN(c_int, p1.term.n, p2.term.n);
            var res: c_int = fts5Memcmp(p1.term.p, p2.term.p, nMin);
            if (res == 0) res = p1.term.n - p2.term.n;

            if (res == 0) {
                std.debug.assert(pRes.bTermEq == 1);
                std.debug.assert(p1.iRowid != p2.iRowid);
                res = if ((@intFromBool(p1.iRowid > p2.iRowid)) == pIter.bRev) -1 else 1;
            } else {
                std.debug.assert(pRes.bTermEq == 0);
            }

            if (res < 0) {
                std.debug.assert(pRes.iFirst == iA1);
            } else {
                std.debug.assert(pRes.iFirst == iA2);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SQLITE_DEBUG-only assert helper, ported as a normal fn.
fn fts5AssertMultiIterSetup(p: *Fts5IndexS, pIter: *Fts5Iter) void {
    if (p.rc == SQLITE_OK) {
        const pFirst: *Fts5SegIter = iterSeg(pIter, @intCast(pIter.aFirst.?[1].iFirst));
        var i: c_int = 0;

        std.debug.assert((pFirst.pLeaf == null) == (pIter.base.bEof != 0));

        // Check that pIter->iSwitchRowid is set correctly.
        i = 0;
        while (i < pIter.nSeg) : (i += 1) {
            const p1: *Fts5SegIter = iterSeg(pIter, i);
            std.debug.assert(p1 == pFirst or
                p1.pLeaf == null or
                fts5BufferCompare(&pFirst.term, &p1.term) != 0 or
                p1.iRowid == pIter.iSwitchRowid or
                (@intFromBool(p1.iRowid < pIter.iSwitchRowid) == pIter.bRev));
        }

        i = 0;
        while (i < pIter.nSeg) : (i += 2) {
            const p1: *Fts5SegIter = iterSeg(pIter, i);
            const p2: *Fts5SegIter = iterSeg(pIter, i + 1);
            const pRes: *Fts5CResult = &pIter.aFirst.?[@intCast(@divTrunc(pIter.nSeg + i, 2))];
            fts5AssertComparisonResult(pIter, p1, p2, pRes);
        }

        i = 1;
        while (i < @divTrunc(pIter.nSeg, 2)) : (i += 2) {
            const p1: *Fts5SegIter = iterSeg(pIter, pIter.aFirst.?[@intCast(i * 2)].iFirst);
            const p2: *Fts5SegIter = iterSeg(pIter, pIter.aFirst.?[@intCast(i * 2 + 1)].iFirst);
            const pRes: *Fts5CResult = &pIter.aFirst.?[@intCast(i)];
            fts5AssertComparisonResult(pIter, p1, p2, pRes);
        }
    }
}

// ---------------------------------------------------------------------------
fn fts5MultiIterDoCompare(pIter: *Fts5Iter, iOut: c_int) c_int {
    var iA1: c_int = undefined; // Index of left-hand Fts5SegIter
    var iA2: c_int = undefined; // Index of right-hand Fts5SegIter
    var iRes: c_int = undefined;
    var p1: *Fts5SegIter = undefined;
    var p2: *Fts5SegIter = undefined;
    const pRes: *Fts5CResult = &pIter.aFirst.?[@intCast(iOut)];

    // assert( iOut<pIter->nSeg && iOut>0 );

    if (iOut >= @divTrunc(pIter.nSeg, 2)) {
        iA1 = (iOut - @divTrunc(pIter.nSeg, 2)) * 2;
        iA2 = iA1 + 1;
    } else {
        iA1 = pIter.aFirst.?[@intCast(iOut * 2)].iFirst;
        iA2 = pIter.aFirst.?[@intCast(iOut * 2 + 1)].iFirst;
    }
    p1 = iterSeg(pIter, iA1);
    p2 = iterSeg(pIter, iA2);

    pRes.bTermEq = 0;
    if (p1.pLeaf == null) { // If p1 is at EOF
        iRes = iA2;
    } else if (p2.pLeaf == null) { // If p2 is at EOF
        iRes = iA1;
    } else {
        var res: c_int = fts5BufferCompare(&p1.term, &p2.term);
        if (res == 0) {
            // assert_nc( iA2>iA1 ); assert_nc( iA2!=0 );
            pRes.bTermEq = 1;
            if (p1.iRowid == p2.iRowid) {
                return iA2;
            }
            res = if (@intFromBool(p1.iRowid > p2.iRowid) == pIter.bRev) -1 else 1;
        }
        // assert( res!=0 );
        if (res < 0) {
            iRes = iA1;
        } else {
            iRes = iA2;
        }
    }

    pRes.iFirst = @intCast(iRes);
    return 0;
}

// ---------------------------------------------------------------------------
fn fts5SegIterGotoPage(
    p: *Fts5IndexS,
    pIter: *Fts5SegIter,
    iLeafPgno: c_int,
) void {
    // assert( iLeafPgno>pIter->iLeafPgno );

    if (iLeafPgno > pIter.pSeg.?.pgnoLast) {
        _ = fts5IndexCorruptIdx(p);
    } else {
        fts5DataRelease(pIter.pNextLeaf);
        pIter.pNextLeaf = null;
        pIter.iLeafPgno = iLeafPgno - 1;

        while (p.rc == SQLITE_OK) {
            fts5SegIterNextPage(p, pIter);
            if (pIter.pLeaf == null) break;
            var iOff: c_int = fts5LeafFirstRowidOff(pIter.pLeaf.?);
            if (iOff > 0) {
                const a: [*]u8 = pIter.pLeaf.?.p.?;
                const nn: c_int = pIter.pLeaf.?.szLeaf;
                if (iOff < 4 or iOff >= nn) {
                    _ = fts5IndexCorruptIdx(p);
                } else {
                    iOff += fts5GetVarint(a + @as(usize, @intCast(iOff)), @ptrCast(&pIter.iRowid));
                    pIter.iLeafOffset = iOff;
                    fts5SegIterLoadNPos(p, pIter);
                }
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
fn fts5SegIterNextFrom(
    p: *Fts5IndexS,
    pIter: *Fts5SegIter,
    iMatch: i64,
) void {
    const bRev: c_int = (pIter.flags & FTS5_SEGITER_REVERSE);
    const pDlidx: ?*Fts5DlidxIter = pIter.pDlidx;
    var iLeafPgno: c_int = pIter.iLeafPgno;
    var bMove: c_int = 1;

    // asserts dropped.

    if (bRev == 0) {
        while (fts5DlidxIterEof(p, pDlidx) == 0 and iMatch > fts5DlidxIterRowid(pDlidx)) {
            iLeafPgno = fts5DlidxIterPgno(pDlidx);
            _ = fts5DlidxIterNext(p, pDlidx);
        }
        if (iLeafPgno > pIter.iLeafPgno) {
            fts5SegIterGotoPage(p, pIter, iLeafPgno);
            bMove = 0;
        }
    } else {
        while (fts5DlidxIterEof(p, pDlidx) == 0 and iMatch < fts5DlidxIterRowid(pDlidx)) {
            _ = fts5DlidxIterPrev(p, pDlidx);
        }
        iLeafPgno = fts5DlidxIterPgno(pDlidx);

        if (iLeafPgno < pIter.iLeafPgno) {
            pIter.iLeafPgno = iLeafPgno + 1;
            fts5SegIterReverseNewPage(p, pIter);
            bMove = 0;
        }
    }

    while (true) {
        if (bMove != 0 and p.rc == SQLITE_OK) pIter.xNext.?(p, pIter, null);
        if (pIter.pLeaf == null) break;
        if (bRev == 0 and pIter.iRowid >= iMatch) break;
        if (bRev != 0 and pIter.iRowid <= iMatch) break;
        bMove = 1;
        if (p.rc != SQLITE_OK) break;
    }
}

// ---------------------------------------------------------------------------
fn fts5MultiIterFree(pIter: ?*Fts5Iter) void {
    if (pIter) |it| {
        var i: c_int = 0;
        while (i < it.nSeg) : (i += 1) {
            fts5SegIterClear(iterSeg(it, i));
        }
        fts5BufferFree(&it.poslist);
        sqlite3_free(it);
    }
}

// ---------------------------------------------------------------------------
fn fts5MultiIterAdvanced(
    p: *Fts5IndexS,
    pIter: *Fts5Iter,
    iChanged: c_int,
    iMinset: c_int,
) void {
    var i: c_int = @divTrunc(pIter.nSeg + iChanged, 2);
    while (i >= iMinset and p.rc == SQLITE_OK) : (i = @divTrunc(i, 2)) {
        const iEq: c_int = fts5MultiIterDoCompare(pIter, i);
        if (iEq != 0) {
            const pSeg: *Fts5SegIter = iterSeg(pIter, iEq);
            // assert( p->rc==SQLITE_OK );
            pSeg.xNext.?(p, pSeg, null);
            i = pIter.nSeg + iEq;
        }
    }
}

// ---------------------------------------------------------------------------
fn fts5MultiIterAdvanceRowid(
    pIter: *Fts5Iter,
    iChanged: c_int,
    ppFirst: *?*Fts5SegIter,
) c_int {
    var pNew: *Fts5SegIter = iterSeg(pIter, iChanged);

    if (pNew.iRowid == pIter.iSwitchRowid or
        (@intFromBool(pNew.iRowid < pIter.iSwitchRowid) == pIter.bRev))
    {
        var pOther: *Fts5SegIter = iterSeg(pIter, iChanged ^ 0x0001);
        pIter.iSwitchRowid = if (pIter.bRev != 0) SMALLEST_INT64 else LARGEST_INT64;
        var i: c_int = @divTrunc(pIter.nSeg + iChanged, 2);
        while (true) : (i = @divTrunc(i, 2)) {
            const pRes: *Fts5CResult = &pIter.aFirst.?[@intCast(i)];

            // assert( pNew->pLeaf ); assert( pRes->bTermEq==0 || pOther->pLeaf );

            if (pRes.bTermEq != 0) {
                if (pNew.iRowid == pOther.iRowid) {
                    return 1;
                } else if (@intFromBool(pOther.iRowid > pNew.iRowid) == pIter.bRev) {
                    pIter.iSwitchRowid = pOther.iRowid;
                    pNew = pOther;
                } else if (@intFromBool(pOther.iRowid > pIter.iSwitchRowid) == pIter.bRev) {
                    pIter.iSwitchRowid = pOther.iRowid;
                }
            }
            const segBase: [*]Fts5SegIter = @ptrCast(&pIter.aSeg);
            pRes.iFirst = @intCast((@intFromPtr(pNew) - @intFromPtr(segBase)) / @sizeOf(Fts5SegIter));
            if (i == 1) break;

            pOther = iterSeg(pIter, pIter.aFirst.?[@intCast(i ^ 0x0001)].iFirst);
        }
    }

    ppFirst.* = pNew;
    return 0;
}

// ---------------------------------------------------------------------------
fn fts5MultiIterSetEof(pIter: *Fts5Iter) void {
    const pSeg: *Fts5SegIter = iterSeg(pIter, pIter.aFirst.?[1].iFirst);
    pIter.base.bEof = @intFromBool(pSeg.pLeaf == null);
    pIter.iSwitchRowid = pSeg.iRowid;
}

// ---------------------------------------------------------------------------
// TOMBSTONE_KEYSIZE(pPg) == (pPg->p[0]==4 ? 4 : 8)
inline fn TOMBSTONE_KEYSIZE(pPg: *Fts5Data) c_int {
    return if (pPg.p.?[0] == 4) 4 else 8;
}
// TOMBSTONE_NSLOT(pPg) == (pPg->nn>16) ? ((pPg->nn-8)/KEYSIZE) : 1
inline fn TOMBSTONE_NSLOT(pPg: *Fts5Data) c_int {
    return if (pPg.nn > 16) @divTrunc(pPg.nn - 8, TOMBSTONE_KEYSIZE(pPg)) else 1;
}

fn fts5IndexTombstoneQuery(
    pHash: *Fts5Data,
    nHashTable: c_int,
    iRowid: u64,
) c_int {
    const szKey: c_int = TOMBSTONE_KEYSIZE(pHash);
    const nSlot: c_int = TOMBSTONE_NSLOT(pHash);
    var iSlot: c_int = @intCast((iRowid / @as(u64, @intCast(nHashTable))) % @as(u64, @intCast(nSlot)));
    var nCollide: c_int = nSlot;

    if (iRowid == 0) {
        return pHash.p.?[1];
    } else if (szKey == 4) {
        const aSlot: [*]u32 = @ptrCast(@alignCast(pHash.p.? + 8));
        while (aSlot[@intCast(iSlot)] != 0) {
            if (fts5GetU32(@ptrCast(&aSlot[@intCast(iSlot)])) == iRowid) return 1;
            const old = nCollide;
            nCollide -= 1;
            if (old == 0) break;
            iSlot = @mod(iSlot + 1, nSlot);
        }
    } else {
        const aSlot: [*]u64 = @ptrCast(@alignCast(pHash.p.? + 8));
        while (aSlot[@intCast(iSlot)] != 0) {
            if (fts5GetU64(@ptrCast(&aSlot[@intCast(iSlot)])) == iRowid) return 1;
            const old = nCollide;
            nCollide -= 1;
            if (old == 0) break;
            iSlot = @mod(iSlot + 1, nSlot);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
fn fts5MultiIterIsDeleted(pIter: *Fts5Iter) c_int {
    const iFirst: c_int = pIter.aFirst.?[1].iFirst;
    const pSeg: *Fts5SegIter = iterSeg(pIter, iFirst);
    const pArray: ?*Fts5TombstoneArray = pSeg.pTombArray;

    if (pSeg.pLeaf != null and pArray != null) {
        const pArr = pArray.?;
        // Figure out which page the rowid might be present on.
        const iPg: c_int = @intCast(@as(u64, @bitCast(pSeg.iRowid)) % @as(u64, @intCast(pArr.nTombstone)));
        // assert( iPg>=0 );

        // Load tombstone hash page iPg if not yet loaded.
        if (tombstonePtr(pArr, iPg).* == null) {
            tombstonePtr(pArr, iPg).* = fts5DataRead(
                pIter.pIndex.?,
                FTS5_TOMBSTONE_ROWID(pSeg.pSeg.?.iSegid, iPg),
            );
            if (tombstonePtr(pArr, iPg).* == null) return 0;
        }

        return fts5IndexTombstoneQuery(
            tombstonePtr(pArr, iPg).*.?,
            pArr.nTombstone,
            @bitCast(pSeg.iRowid),
        );
    }

    return 0;
}

// ---------------------------------------------------------------------------
fn fts5MultiIterNext(
    p: *Fts5IndexS,
    pIterIn: ?*Fts5Iter,
    bFrom: c_int,
    iFrom: i64,
) void {
    const pIter = pIterIn.?;
    var bUseFrom: c_int = bFrom;
    // assert( pIter->base.bEof==0 );
    while (p.rc == SQLITE_OK) {
        const iFirst: c_int = pIter.aFirst.?[1].iFirst;
        var bNewTerm: c_int = 0;
        var pSeg: *Fts5SegIter = iterSeg(pIter, iFirst);
        if (bUseFrom != 0 and pSeg.pDlidx != null) {
            fts5SegIterNextFrom(p, pSeg, iFrom);
        } else {
            pSeg.xNext.?(p, pSeg, &bNewTerm);
        }

        var pSegPtr: ?*Fts5SegIter = pSeg;
        if (pSeg.pLeaf == null or bNewTerm != 0 or
            fts5MultiIterAdvanceRowid(pIter, iFirst, &pSegPtr) != 0)
        {
            pSeg = pSegPtr.?;
            fts5MultiIterAdvanced(p, pIter, iFirst, 1);
            fts5MultiIterSetEof(pIter);
            pSeg = iterSeg(pIter, pIter.aFirst.?[1].iFirst);
            if (pSeg.pLeaf == null) return;
        } else {
            pSeg = pSegPtr.?;
        }

        fts5AssertMultiIterSetup(p, pIter);
        if ((pIter.bSkipEmpty == 0 or pSeg.nPos != 0) and
            0 == fts5MultiIterIsDeleted(pIter))
        {
            pIter.xSetOutputs.?(pIter, pSeg);
            return;
        }
        bUseFrom = 0;
    }
}

// ---------------------------------------------------------------------------
fn fts5MultiIterNext2(
    p: *Fts5IndexS,
    pIter: *Fts5Iter,
    pbNewTerm: *c_int,
) void {
    // assert( pIter->bSkipEmpty );
    if (p.rc == SQLITE_OK) {
        pbNewTerm.* = 0;
        while (true) {
            const iFirst: c_int = pIter.aFirst.?[1].iFirst;
            var pSeg: *Fts5SegIter = iterSeg(pIter, iFirst);
            var bNewTerm: c_int = 0;

            pSeg.xNext.?(p, pSeg, &bNewTerm);
            var pSegPtr: ?*Fts5SegIter = pSeg;
            if (pSeg.pLeaf == null or bNewTerm != 0 or
                fts5MultiIterAdvanceRowid(pIter, iFirst, &pSegPtr) != 0)
            {
                pSeg = pSegPtr.?;
                fts5MultiIterAdvanced(p, pIter, iFirst, 1);
                fts5MultiIterSetEof(pIter);
                pbNewTerm.* = 1;
            } else {
                pSeg = pSegPtr.?;
            }
            fts5AssertMultiIterSetup(p, pIter);

            if (!((fts5MultiIterIsEmpty(p, pIter) != 0 or fts5MultiIterIsDeleted(pIter) != 0) and
                (p.rc == SQLITE_OK))) break;
        }
    }
}

// ---------------------------------------------------------------------------
fn fts5IterSetOutputs_Noop(pUnused1: ?*Fts5Iter, pUnused2: ?*Fts5SegIter) callconv(.c) void {
    _ = pUnused1;
    _ = pUnused2;
}

// ============================ CHUNK 5 ============================
// ===========================================================================
// Chunk c5: fts5_index.c lines ~3447-4204 (fts5MultiIterAlloc .. fts5PrefixCompress)
// ===========================================================================

// xChunk callback type for fts5ChunkIterate:
//   void (*)(Fts5Index*, void*, const u8*, int)
const Fts5ChunkCb = ?*const fn (?*Fts5IndexS, ?*anyopaque, ?[*]const u8, c_int) callconv(.c) void;

// PoslistCallbackCtx / PoslistOffsetsCtx (file-private context structs).
const PoslistCallbackCtx = extern struct {
    pBuf: ?*Fts5Buffer, // Append to this buffer
    pColset: ?*Fts5Colset, // Restrict matches to this column
    eState: c_int, // See above
};
const PoslistOffsetsCtx = extern struct {
    pBuf: ?*Fts5Buffer, // Append to this buffer
    pColset: ?*Fts5Colset, // Restrict matches to this column
    iRead: c_int,
    iWrite: c_int,
};

fn fts5MultiIterAlloc(p: *Fts5IndexS, nSeg: c_int) ?*Fts5Iter {
    var nSlot: i64 = 2; // Power of two >= nSeg
    while (nSlot < nSeg) : (nSlot = nSlot * 2) {}

    const pNew: ?*Fts5Iter = @ptrCast(@alignCast(fts5IdxMalloc(
        p,
        SZ_FTS5ITER(nSlot) + // pNew + pNew->aSeg[]
            @as(i64, @sizeOf(Fts5CResult)) * nSlot, // pNew->aFirst[]
    )));
    if (pNew) |pn| {
        pn.nSeg = @intCast(nSlot);
        // pNew->aFirst = (Fts5CResult*)&pNew->aSeg[nSlot];
        pn.aFirst = @ptrCast(@alignCast(iterSeg(pn, @intCast(nSlot))));
        pn.pIndex = p;
        pn.xSetOutputs = &fts5IterSetOutputs_Noop;
    }
    return pNew;
}

fn fts5PoslistCallback(
    pUnused: ?*Fts5IndexS,
    pContext: ?*anyopaque,
    pChunk: ?[*]const u8,
    nChunk: c_int,
) callconv(.c) void {
    _ = pUnused;
    if (nChunk > 0) {
        fts5BufferSafeAppendBlob(@ptrCast(@alignCast(pContext)), pChunk.?, nChunk);
    }
}

// TODO: Make this more efficient!
fn fts5IndexColsetTest(pColset: *Fts5Colset, iCol: c_int) c_int {
    var i: c_int = 0;
    while (i < pColset.nCol) : (i += 1) {
        if (colsetCol(pColset, i).* == iCol) return 1;
    }
    return 0;
}

fn fts5PoslistOffsetsCallback(
    pUnused: ?*Fts5IndexS,
    pContext: ?*anyopaque,
    pChunk: ?[*]const u8,
    nChunk: c_int,
) callconv(.c) void {
    _ = pUnused;
    const pCtx: *PoslistOffsetsCtx = @ptrCast(@alignCast(pContext));
    if (nChunk > 0) {
        const a = pChunk.?;
        var i: c_int = 0;
        while (i < nChunk) {
            var iVal: c_int = undefined;
            i += fts5GetVarint32Into(c_int, a + @as(usize, @intCast(i)), &iVal);
            iVal += pCtx.iRead - 2;
            pCtx.iRead = iVal;
            if (fts5IndexColsetTest(pCtx.pColset.?, iVal) != 0) {
                fts5BufferSafeAppendVarint(pCtx.pBuf.?, iVal + 2 - pCtx.iWrite);
                pCtx.iWrite = iVal;
            }
        }
    }
}

fn fts5PoslistFilterCallback(
    pUnused: ?*Fts5IndexS,
    pContext: ?*anyopaque,
    pChunk: ?[*]const u8,
    nChunk: c_int,
) callconv(.c) void {
    _ = pUnused;
    const pCtx: *PoslistCallbackCtx = @ptrCast(@alignCast(pContext));
    if (nChunk > 0) {
        const a = pChunk.?;
        // Search through to find the first varint with value 1. This is the
        // start of the next columns hits.
        var i: c_int = 0;
        var iStart: c_int = 0;

        if (pCtx.eState == 2) {
            var iCol: c_int = undefined;
            fts5FastGetVarint32(c_int, a, &i, &iCol);
            if (fts5IndexColsetTest(pCtx.pColset.?, iCol) != 0) {
                pCtx.eState = 1;
                fts5BufferSafeAppendVarint(pCtx.pBuf.?, 1);
            } else {
                pCtx.eState = 0;
            }
        }

        while (true) {
            while (i < nChunk and a[@intCast(i)] != 0x01) {
                fts5IndexSkipVarint(a, &i);
            }
            if (pCtx.eState != 0) {
                fts5BufferSafeAppendBlob(pCtx.pBuf.?, a + @as(usize, @intCast(iStart)), i - iStart);
            }
            if (i < nChunk) {
                iStart = i;
                i += 1;
                if (i >= nChunk) {
                    pCtx.eState = 2;
                } else {
                    var iCol: c_int = undefined;
                    fts5FastGetVarint32(c_int, a, &i, &iCol);
                    pCtx.eState = fts5IndexColsetTest(pCtx.pColset.?, iCol);
                    if (pCtx.eState != 0) {
                        fts5BufferSafeAppendBlob(pCtx.pBuf.?, a + @as(usize, @intCast(iStart)), i - iStart);
                        iStart = i;
                    }
                }
            }
            if (!(i < nChunk)) break;
        }
    }
}

fn fts5ChunkIterate(
    p: *Fts5IndexS, // Index object
    pSeg: *Fts5SegIter, // Poslist of this iterator
    pCtx: ?*anyopaque, // Context pointer for xChunk callback
    xChunk: Fts5ChunkCb,
) void {
    var nRem: c_int = pSeg.nPos; // Number of bytes still to come
    var pData: ?*Fts5Data = null;
    var pChunk: ?[*]u8 = pSeg.pLeaf.?.p.? + @as(usize, @intCast(pSeg.iLeafOffset));
    var nChunk: c_int = MIN(c_int, nRem, pSeg.pLeaf.?.szLeaf - @as(c_int, @intCast(pSeg.iLeafOffset)));
    var pgno: c_int = pSeg.iLeafPgno;
    var pgnoSave: c_int = 0;

    // This function does not work with detail=none databases.

    if ((pSeg.flags & FTS5_SEGITER_REVERSE) == 0) {
        pgnoSave = pgno + 1;
    }

    while (true) {
        xChunk.?(p, pCtx, pChunk, nChunk);
        nRem -= nChunk;
        fts5DataRelease(pData);
        if (nRem <= 0) {
            break;
        } else if (pSeg.pSeg == null) {
            _ = fts5IndexCorruptIdx(p);
            return;
        } else {
            pgno += 1;
            pData = fts5LeafRead(p, FTS5_SEGMENT_ROWID(pSeg.pSeg.?.iSegid, pgno));
            if (pData == null) break;
            pChunk = pData.?.p.? + 4;
            nChunk = MIN(c_int, nRem, pData.?.szLeaf - 4);
            if (pgno == pgnoSave) {
                pSeg.pNextLeaf = pData;
                pData = null;
            }
        }
    }
}

// Iterator pIter currently points to a valid entry (not EOF). This function
// appends the position list data for the current entry to buffer pBuf.
fn fts5SegiterPoslist(
    p: *Fts5IndexS,
    pSeg: *Fts5SegIter,
    pColset: ?*Fts5Colset,
    pBuf: *Fts5Buffer,
) void {
    if (false == fts5BufferGrow(&p.rc, pBuf, pSeg.nPos + FTS5_DATA_ZERO_PADDING)) {
        @memset((pBuf.p.? + @as(usize, @intCast(pBuf.n + pSeg.nPos)))[0..@intCast(FTS5_DATA_ZERO_PADDING)], 0);
        if (pColset == null) {
            fts5ChunkIterate(p, pSeg, @ptrCast(pBuf), &fts5PoslistCallback);
        } else {
            if (p.pConfig.?.eDetail == FTS5_DETAIL_FULL) {
                var sCtx: PoslistCallbackCtx = undefined;
                sCtx.pBuf = pBuf;
                sCtx.pColset = pColset;
                sCtx.eState = fts5IndexColsetTest(pColset.?, 0);
                fts5ChunkIterate(p, pSeg, @ptrCast(&sCtx), &fts5PoslistFilterCallback);
            } else {
                var sCtx: PoslistOffsetsCtx = std.mem.zeroes(PoslistOffsetsCtx);
                sCtx.pBuf = pBuf;
                sCtx.pColset = pColset;
                fts5ChunkIterate(p, pSeg, @ptrCast(&sCtx), &fts5PoslistOffsetsCallback);
            }
        }
    }
}

// Parameter pPos points to a buffer containing a position list, size nPos.
// This function filters it according to pColset (which must be non-NULL) and
// sets pIter->base.pData/nData to point to the new position list.
fn fts5IndexExtractColset(
    pRc: *c_int,
    pColset: *Fts5Colset, // Colset to filter on
    pPos: [*]const u8,
    nPos: c_int, // Position list
    pIter: *Fts5Iter,
) void {
    if (pRc.* == SQLITE_OK) {
        var p: [*]const u8 = pPos;
        var aCopy: [*]const u8 = p;
        const pEnd: [*]const u8 = pPos + @as(usize, @intCast(nPos)); // One byte past end
        var i: c_int = 0;
        var iCurrent: c_int = 0;

        if (pColset.nCol > 1 and sqlite3Fts5BufferSize(pRc, &pIter.poslist, @bitCast(nPos)) != 0) {
            return;
        }

        while (true) {
            while (colsetCol(pColset, i).* < iCurrent) {
                i += 1;
                if (i == pColset.nCol) {
                    pIter.base.pData = pIter.poslist.p;
                    pIter.base.nData = pIter.poslist.n;
                    return;
                }
            }

            // Advance pointer p until it points to pEnd or an 0x01 byte that is
            // not part of a varint.
            while (@intFromPtr(p) < @intFromPtr(pEnd) and p[0] != 0x01) {
                while (@intFromPtr(p) < @intFromPtr(pEnd)) {
                    const b = p[0];
                    p += 1;
                    if ((b & 0x80) == 0) break;
                }
            }

            if (colsetCol(pColset, i).* == iCurrent) {
                if (pColset.nCol == 1) {
                    pIter.base.pData = @constCast(aCopy);
                    pIter.base.nData = @intCast(@intFromPtr(p) - @intFromPtr(aCopy));
                    return;
                }
                fts5BufferSafeAppendBlob(&pIter.poslist, aCopy, @intCast(@intFromPtr(p) - @intFromPtr(aCopy)));
            }
            if (@intFromPtr(p) >= @intFromPtr(pEnd)) {
                pIter.base.pData = pIter.poslist.p;
                pIter.base.nData = pIter.poslist.n;
                return;
            }
            aCopy = p;
            p += 1;
            iCurrent = p[0];
            p += 1;
            if ((iCurrent & 0x80) != 0) {
                p -= 1;
                p += @intCast(fts5GetVarint32Into(c_int, p, &iCurrent));
            }
        }
    }
}

// xSetOutputs callback used by detail=none tables.
fn fts5IterSetOutputs_None(pIter: ?*Fts5Iter, pSeg: ?*Fts5SegIter) callconv(.c) void {
    pIter.?.base.iRowid = pSeg.?.iRowid;
    pIter.?.base.nData = pSeg.?.nPos;
}

// xSetOutputs callback used by detail=full and detail=col tables when no column
// filters are specified.
fn fts5IterSetOutputs_Nocolset(pIter: ?*Fts5Iter, pSeg: ?*Fts5SegIter) callconv(.c) void {
    const pi = pIter.?;
    const ps = pSeg.?;
    pi.base.iRowid = ps.iRowid;
    pi.base.nData = ps.nPos;

    if (ps.iLeafOffset + ps.nPos <= ps.pLeaf.?.szLeaf) {
        // All data is stored on the current page. Populate the output variables
        // to point into the body of the page object.
        pi.base.pData = ps.pLeaf.?.p.? + @as(usize, @intCast(ps.iLeafOffset));
    } else {
        // The data is distributed over two or more pages. Copy it into the
        // Fts5Iter.poslist buffer and then set the output pointer to it.
        sqlite3Fts5BufferZero(&pi.poslist);
        fts5SegiterPoslist(pi.pIndex.?, ps, null, &pi.poslist);
        pi.base.pData = pi.poslist.p;
    }
}

// xSetOutputs callback used when the Fts5Colset object has nCol==0 (match
// against no columns at all).
fn fts5IterSetOutputs_ZeroColset(pIter: ?*Fts5Iter, pSeg: ?*Fts5SegIter) callconv(.c) void {
    _ = pSeg;
    pIter.?.base.nData = 0;
}

// xSetOutputs callback used by detail=col when there is a column filter and
// there are 100 or more columns. Also a fallback from fts5IterSetOutputs_Col100.
fn fts5IterSetOutputs_Col(pIter: ?*Fts5Iter, pSeg: ?*Fts5SegIter) callconv(.c) void {
    const pi = pIter.?;
    const ps = pSeg.?;
    sqlite3Fts5BufferZero(&pi.poslist);
    fts5SegiterPoslist(pi.pIndex.?, ps, pi.pColset, &pi.poslist);
    pi.base.iRowid = ps.iRowid;
    pi.base.pData = pi.poslist.p;
    pi.base.nData = pi.poslist.n;
}

// xSetOutputs callback used when: detail=col, there is a column filter, and the
// table contains 100 or fewer columns (so column numbers are single-byte
// varints).
fn fts5IterSetOutputs_Col100(pIter: ?*Fts5Iter, pSeg: ?*Fts5SegIter) callconv(.c) void {
    const pi = pIter.?;
    const ps = pSeg.?;

    if (ps.iLeafOffset + ps.nPos > ps.pLeaf.?.szLeaf or
        ps.nPos > pi.pIndex.?.pConfig.?.nCol)
    {
        fts5IterSetOutputs_Col(pIter, pSeg);
    } else {
        var a: [*]u8 = ps.pLeaf.?.p.? + @as(usize, @intCast(ps.iLeafOffset));
        const pEnd: [*]u8 = a + @as(usize, @intCast(ps.nPos));
        var iPrev: c_int = 0;
        var aiCol: [*]c_int = @ptrCast(colsetCol(pi.pColset.?, 0));
        const aiColEnd: [*]c_int = aiCol + @as(usize, @intCast(pi.pColset.?.nCol));

        const aOutBase: [*]u8 = pi.poslist.p.?;
        var aOut: [*]u8 = aOutBase;
        var iPrevOut: c_int = 0;

        pi.base.iRowid = ps.iRowid;

        outer: while (@intFromPtr(a) < @intFromPtr(pEnd)) {
            // iPrev += (int)a++[0] - 2;
            iPrev += @as(c_int, a[0]) - 2;
            a += 1;
            while (aiCol[0] < iPrev) {
                aiCol += 1;
                if (aiCol == aiColEnd) break :outer;
            }
            if (aiCol[0] == iPrev) {
                aOut[0] = @truncate(@as(u32, @bitCast((iPrev - iPrevOut) + 2)));
                aOut += 1;
                iPrevOut = iPrev;
            }
        }

        // setoutputs_col_out:
        pi.base.pData = aOutBase;
        pi.base.nData = @intCast(@intFromPtr(aOut) - @intFromPtr(aOutBase));
    }
}

// xSetOutputs callback used by detail=full when there is a column filter.
fn fts5IterSetOutputs_Full(pIter: ?*Fts5Iter, pSeg: ?*Fts5SegIter) callconv(.c) void {
    const pi = pIter.?;
    const ps = pSeg.?;
    const pColset = pi.pColset;
    pi.base.iRowid = ps.iRowid;

    if (ps.iLeafOffset + ps.nPos <= ps.pLeaf.?.szLeaf) {
        // All data is stored on the current page.
        const a: [*]const u8 = ps.pLeaf.?.p.? + @as(usize, @intCast(ps.iLeafOffset));
        const pRc: *c_int = &pi.pIndex.?.rc;
        sqlite3Fts5BufferZero(&pi.poslist);
        fts5IndexExtractColset(pRc, pColset.?, a, ps.nPos, pi);
    } else {
        // The data is distributed over two or more pages.
        sqlite3Fts5BufferZero(&pi.poslist);
        fts5SegiterPoslist(pi.pIndex.?, ps, pColset, &pi.poslist);
        pi.base.pData = pi.poslist.p;
        pi.base.nData = pi.poslist.n;
    }
}

fn fts5IterSetOutputCb(pRc: *c_int, pIterIn: ?*Fts5Iter) void {
    const pIter = pIterIn.?;
    if (pRc.* == SQLITE_OK) {
        const pConfig = pIter.pIndex.?.pConfig.?;
        if (pConfig.eDetail == FTS5_DETAIL_NONE) {
            pIter.xSetOutputs = &fts5IterSetOutputs_None;
        } else if (pIter.pColset == null) {
            pIter.xSetOutputs = &fts5IterSetOutputs_Nocolset;
        } else if (pIter.pColset.?.nCol == 0) {
            pIter.xSetOutputs = &fts5IterSetOutputs_ZeroColset;
        } else if (pConfig.eDetail == FTS5_DETAIL_FULL) {
            pIter.xSetOutputs = &fts5IterSetOutputs_Full;
        } else {
            if (pConfig.nCol <= 100) {
                pIter.xSetOutputs = &fts5IterSetOutputs_Col100;
                _ = sqlite3Fts5BufferSize(pRc, &pIter.poslist, @bitCast(pConfig.nCol));
            } else {
                pIter.xSetOutputs = &fts5IterSetOutputs_Col;
            }
        }
    }
}

// All the component segment-iterators of pIter have been set up. This finishes
// setup for iterator pIter itself.
fn fts5MultiIterFinishSetup(p: *Fts5IndexS, pIter: *Fts5Iter) void {
    var iIter: c_int = pIter.nSeg - 1;
    while (iIter > 0) : (iIter -= 1) {
        const iEq = fts5MultiIterDoCompare(pIter, iIter);
        if (iEq != 0) {
            const pSeg = iterSeg(pIter, iEq);
            if (p.rc == SQLITE_OK) pSeg.xNext.?(p, pSeg, null);
            fts5MultiIterAdvanced(p, pIter, iEq, iIter);
        }
    }
    fts5MultiIterSetEof(pIter);

    if ((pIter.bSkipEmpty != 0 and fts5MultiIterIsEmpty(p, pIter) != 0) or
        fts5MultiIterIsDeleted(pIter) != 0)
    {
        fts5MultiIterNext(p, pIter, 0, 0);
    } else if (pIter.base.bEof == 0) {
        const pSeg = iterSeg(pIter, pIter.aFirst.?[1].iFirst);
        pIter.xSetOutputs.?(pIter, pSeg);
    }
}

// Allocate a new Fts5Iter object iterating data in structure pStruct.
fn fts5MultiIterNew(
    p: *Fts5IndexS,
    pStructIn: ?*Fts5Structure,
    flags: c_int,
    pColset: ?*Fts5Colset,
    pTerm: ?[*]const u8,
    nTerm: c_int,
    iLevel: c_int,
    nSegment: c_int,
    ppOut: *?*Fts5Iter,
) void {
    var nSeg: c_int = 0; // Number of segment-iters in use
    var iIter: c_int = 0;
    var iSeg: c_int = undefined;
    var pLvl: [*]Fts5StructureLevel = undefined;
    var pNew: ?*Fts5Iter = undefined;
    const pStruct = pStructIn orelse {
        ppOut.* = null;
        return;
    };

    // Allocate space for the new multi-seg-iterator.
    if (p.rc == SQLITE_OK) {
        if (iLevel < 0) {
            nSeg = pStruct.nSegment;
            nSeg += @intFromBool(p.pHash != null and 0 == (flags & FTS5INDEX_QUERY_SKIPHASH));
        } else {
            nSeg = MIN(c_int, structLevel(pStruct, iLevel).nSeg, nSegment);
        }
    }
    pNew = fts5MultiIterAlloc(p, nSeg);
    ppOut.* = pNew;
    if (pNew == null) {
        // goto fts5MultiIterNew_post_check;
        return;
    }
    const pn = pNew.?;
    pn.bRev = @intFromBool(0 != (flags & FTS5INDEX_QUERY_DESC));
    pn.bSkipEmpty = @intFromBool(0 != (flags & FTS5INDEX_QUERY_SKIPEMPTY));
    pn.pColset = pColset;
    if ((flags & FTS5INDEX_QUERY_NOOUTPUT) == 0) {
        fts5IterSetOutputCb(&p.rc, pn);
    }

    // Initialize each of the component segment iterators.
    if (p.rc == SQLITE_OK) {
        if (iLevel < 0) {
            const pEnd: [*]Fts5StructureLevel = @as([*]Fts5StructureLevel, @ptrCast(&pStruct.aLevel)) +
                @as(usize, @intCast(pStruct.nLevel));
            if (p.pHash != null and 0 == (flags & FTS5INDEX_QUERY_SKIPHASH)) {
                // Add a segment iterator for the current contents of the hash table.
                const pIter = iterSeg(pn, iIter);
                iIter += 1;
                fts5SegIterHashInit(p, pTerm, nTerm, flags, pIter);
            }
            pLvl = @ptrCast(&pStruct.aLevel);
            while (@intFromPtr(pLvl) < @intFromPtr(pEnd)) : (pLvl += 1) {
                iSeg = pLvl[0].nSeg - 1;
                while (iSeg >= 0) : (iSeg -= 1) {
                    const pSeg = &pLvl[0].aSeg.?[@intCast(iSeg)];
                    const pIter = iterSeg(pn, iIter);
                    iIter += 1;
                    if (pTerm == null) {
                        fts5SegIterInit(p, pSeg, pIter);
                    } else {
                        fts5SegIterSeekInit(p, pTerm.?, nTerm, flags, pSeg, pIter);
                    }
                }
            }
        } else {
            const lvl = structLevel(pStruct, iLevel);
            iSeg = nSeg - 1;
            while (iSeg >= 0) : (iSeg -= 1) {
                const pIter = iterSeg(pn, iIter);
                iIter += 1;
                fts5SegIterInit(p, &lvl.aSeg.?[@intCast(iSeg)], pIter);
            }
        }
    }

    // If successful, each component iterator now points to the first entry in
    // its segment; initialize the aFirst[] array. Else free and NULL output.
    if (p.rc == SQLITE_OK) {
        fts5MultiIterFinishSetup(p, pn);
    } else {
        fts5MultiIterFree(pn);
        ppOut.* = null;
    }
}

// Create an Fts5Iter that iterates through the doclist provided as the second
// argument.
fn fts5MultiIterNew2(
    p: *Fts5IndexS,
    pDataIn: ?*Fts5Data,
    bDesc: c_int,
    ppOut: *?*Fts5Iter,
) void {
    var pData = pDataIn;
    const pNew = fts5MultiIterAlloc(p, 2);
    if (pNew) |pn| {
        const pIter = iterSeg(pn, 1);
        pIter.flags = FTS5_SEGITER_ONETERM;
        if (pData.?.szLeaf > 0) {
            pIter.pLeaf = pData;
            var u: u64 = undefined;
            pIter.iLeafOffset = fts5GetVarint(pData.?.p.?, &u);
            pIter.iRowid = @bitCast(u);
            pIter.iEndofDoclist = pData.?.nn;
            pn.aFirst.?[1].iFirst = 1;
            if (bDesc != 0) {
                pn.bRev = 1;
                pIter.flags |= FTS5_SEGITER_REVERSE;
                fts5SegIterReverseInitPage(p, pIter);
            } else {
                fts5SegIterLoadNPos(p, pIter);
            }
            pData = null;
        } else {
            pn.base.bEof = 1;
        }
        fts5SegIterSetNext(p, pIter);

        ppOut.* = pn;
    }

    fts5DataRelease(pData);
}

// Return true if the iterator is at EOF or an error has occurred.
fn fts5MultiIterEof(p: *Fts5IndexS, pIterIn: ?*Fts5Iter) c_int {
    const pIter = pIterIn.?;
    return @intFromBool(p.rc != 0 or pIter.base.bEof != 0);
}

// Return the rowid of the entry that the iterator currently points to.
fn fts5MultiIterRowid(pIterIn: ?*Fts5Iter) i64 {
    const pIter = pIterIn.?;
    return iterSeg(pIter, pIter.aFirst.?[1].iFirst).iRowid;
}

// Move the iterator to the next entry at or following iMatch.
fn fts5MultiIterNextFrom(p: *Fts5IndexS, pIterIn: ?*Fts5Iter, iMatch: i64) void {
    const pIter = pIterIn.?;
    while (true) {
        fts5MultiIterNext(p, pIter, 1, iMatch);
        if (fts5MultiIterEof(p, pIter) != 0) break;
        const iRowid = fts5MultiIterRowid(pIter);
        if (pIter.bRev == 0 and iRowid >= iMatch) break;
        if (pIter.bRev != 0 and iRowid <= iMatch) break;
    }
}

// Return a pointer to a buffer containing the term for the current entry.
fn fts5MultiIterTerm(pIterIn: ?*Fts5Iter, pn: *c_int) ?[*]const u8 {
    const pIter = pIterIn.?;
    const pp = iterSeg(pIter, pIter.aFirst.?[1].iFirst);
    pn.* = pp.term.n;
    return pp.term.p;
}

// Allocate a new segment-id for the structure pStruct. Between 1 and 65335
// inclusive and unused. If none free, SQLITE_FULL is returned. No-op (returns 0)
// if an error has already occurred.
fn fts5AllocateSegid(p: *Fts5IndexS, pStruct: *Fts5Structure) c_int {
    var iSegid: c_int = 0;

    if (p.rc == SQLITE_OK) {
        if (pStruct.nSegment >= FTS5_MAX_SEGMENT) {
            p.rc = SQLITE_FULL;
        } else {
            // aUsed[(FTS5_MAX_SEGMENT+31)/32] bitmask of used segids.
            var aUsed: [(@as(usize, @intCast(FTS5_MAX_SEGMENT)) + 31) / 32]u32 = undefined;
            var iLvl: c_int = undefined;
            var iSeg: c_int = undefined;
            var i: c_int = undefined;
            var mask: u32 = undefined;
            @memset(aUsed[0..], 0);
            iLvl = 0;
            while (iLvl < pStruct.nLevel) : (iLvl += 1) {
                const lvl = structLevel(pStruct, iLvl);
                iSeg = 0;
                while (iSeg < lvl.nSeg) : (iSeg += 1) {
                    const iId: c_int = lvl.aSeg.?[@intCast(iSeg)].iSegid;
                    if (iId <= FTS5_MAX_SEGMENT and iId > 0) {
                        aUsed[@intCast(@divTrunc(iId - 1, 32))] |=
                            @as(u32, 1) << @intCast(@mod(iId - 1, 32));
                    }
                }
            }

            i = 0;
            while (aUsed[@intCast(i)] == 0xFFFFFFFF) : (i += 1) {}
            mask = aUsed[@intCast(i)];
            iSegid = 0;
            while ((mask & (@as(u32, 1) << @intCast(iSegid))) != 0) : (iSegid += 1) {}
            iSegid += 1 + i * 32;
        }
    }

    return iSegid;
}

// Discard all data currently cached in the hash-tables.
fn fts5IndexDiscardData(p: *Fts5IndexS) void {
    if (p.pHash) |pHash| {
        sqlite3Fts5HashClear(pHash);
        p.nPendingData = 0;
        p.nPendingRow = 0;
        p.flushRc = SQLITE_OK;
    }
    p.nContentlessDelete = 0;
}

// Return the size of the prefix, in bytes, that buffer (pNew/unknown) shares
// with buffer (pOld/nOld). pNew is guaranteed greater than pOld.
fn fts5PrefixCompress(nOld: c_int, pOldIn: ?[*]const u8, pNewIn: ?[*]const u8) c_int {
    const pOld = pOldIn.?;
    const pNew = pNewIn.?;
    var i: c_int = 0;
    while (i < nOld) : (i += 1) {
        if (pOld[@intCast(i)] != pNew[@intCast(i)]) break;
    }
    return i;
}

// ============================ CHUNK 6 ============================

inline fn ALWAYS(x: bool) bool {
    return x;
}

fn fts5WriteDlidxClear(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    bFlush: c_int, // If true, write dlidx to disk
) void {
    var i: c_int = 0;
    const aDlidx = pWriter.aDlidx.?;
    while (i < pWriter.nDlidx) : (i += 1) {
        const pDlidx = &aDlidx[@intCast(i)];
        if (pDlidx.buf.n == 0) break;
        if (bFlush != 0) {
            fts5DataWrite(
                p,
                FTS5_DLIDX_ROWID(pWriter.iSegid, i, pDlidx.pgno),
                pDlidx.buf.p,
                pDlidx.buf.n,
            );
        }
        sqlite3Fts5BufferZero(&pDlidx.buf);
        pDlidx.bPrevValid = 0;
    }
}

fn fts5WriteDlidxGrow(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    nLvl: c_int,
) c_int {
    if (p.rc == SQLITE_OK and nLvl >= pWriter.nDlidx) {
        const aDlidx: ?[*]Fts5DlidxWriter = @ptrCast(@alignCast(sqlite3_realloc64(
            pWriter.aDlidx,
            @as(u64, @sizeOf(Fts5DlidxWriter)) * @as(u64, @intCast(nLvl)),
        )));
        if (aDlidx == null) {
            p.rc = SQLITE_NOMEM;
        } else {
            const nByte: usize = @sizeOf(Fts5DlidxWriter) * @as(usize, @intCast(nLvl - pWriter.nDlidx));
            _ = memset(&aDlidx.?[@intCast(pWriter.nDlidx)], 0, nByte);
            pWriter.aDlidx = aDlidx;
            pWriter.nDlidx = nLvl;
        }
    }
    return p.rc;
}

fn fts5WriteFlushDlidx(p: *Fts5IndexS, pWriter: *Fts5SegWriter) c_int {
    var bFlag: c_int = 0;
    if (pWriter.aDlidx.?[0].buf.n > 0 and pWriter.nEmpty >= FTS5_MIN_DLIDX_SIZE) {
        bFlag = 1;
    }
    fts5WriteDlidxClear(p, pWriter, bFlag);
    pWriter.nEmpty = 0;
    return bFlag;
}

fn fts5WriteFlushBtree(p: *Fts5IndexS, pWriter: *Fts5SegWriter) void {
    var bFlag: c_int = undefined;
    if (pWriter.iBtPage == 0) return;
    bFlag = fts5WriteFlushDlidx(p, pWriter);

    if (p.rc == SQLITE_OK) {
        const z: [*]const u8 = if (pWriter.btterm.n > 0) pWriter.btterm.p.? else "";
        // sqlite3_bind_int(p->pIdxWriter,1,..) already done in fts5WriteInit().
        _ = sqlite3_bind_blob(p.pIdxWriter, 2, z, pWriter.btterm.n, int.SQLITE_STATIC);
        _ = sqlite3_bind_int64(p.pIdxWriter, 3, @as(i64, bFlag) + (@as(i64, pWriter.iBtPage) << 1));
        _ = sqlite3_step(p.pIdxWriter);
        p.rc = sqlite3_reset(p.pIdxWriter);
        _ = sqlite3_bind_null(p.pIdxWriter, 2);
    }
    pWriter.iBtPage = 0;
}

fn fts5WriteBtreeTerm(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    nTerm: c_int,
    pTerm: ?[*]const u8, // First term on new page
) void {
    fts5WriteFlushBtree(p, pWriter);
    if (p.rc == SQLITE_OK) {
        fts5BufferSet(&p.rc, &pWriter.btterm, nTerm, pTerm);
        pWriter.iBtPage = pWriter.writer.pgno;
    }
}

fn fts5WriteBtreeNoTerm(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
) void {
    if (pWriter.bFirstRowidInPage != 0 and pWriter.aDlidx.?[0].buf.n > 0) {
        const pDlidx = &pWriter.aDlidx.?[0];
        sqlite3Fts5BufferAppendVarint(&p.rc, &pDlidx.buf, 0);
    }
    pWriter.nEmpty += 1;
}

fn fts5DlidxExtractFirstRowid(pBuf: *Fts5Buffer) i64 {
    var iRowid: i64 = undefined;
    var iOff: c_int = undefined;

    iOff = 1 + fts5GetVarint(pBuf.p.? + 1, @ptrCast(&iRowid));
    _ = fts5GetVarint(pBuf.p.? + @as(usize, @intCast(iOff)), @ptrCast(&iRowid));
    return iRowid;
}

fn fts5WriteDlidxAppend(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    iRowid: i64,
) void {
    var i: c_int = 0;
    var bDone: c_int = 0;

    while (p.rc == SQLITE_OK and bDone == 0) : (i += 1) {
        var iVal: i64 = undefined;
        var pDlidx = &pWriter.aDlidx.?[@intCast(i)];

        if (pDlidx.buf.n >= p.pConfig.?.pgsz) {
            pDlidx.buf.p.?[0] = 0x01; // Not the root node
            fts5DataWrite(
                p,
                FTS5_DLIDX_ROWID(pWriter.iSegid, i, pDlidx.pgno),
                pDlidx.buf.p,
                pDlidx.buf.n,
            );
            _ = fts5WriteDlidxGrow(p, pWriter, i + 2);
            pDlidx = &pWriter.aDlidx.?[@intCast(i)];
            const pDlidx1 = &pWriter.aDlidx.?[@intCast(i + 1)];
            if (p.rc == SQLITE_OK and pDlidx1.buf.n == 0) {
                const iFirst = fts5DlidxExtractFirstRowid(&pDlidx.buf);

                // This was the root node. Push its first rowid to the new root.
                pDlidx1.pgno = pDlidx.pgno;
                sqlite3Fts5BufferAppendVarint(&p.rc, &pDlidx1.buf, 0);
                sqlite3Fts5BufferAppendVarint(&p.rc, &pDlidx1.buf, pDlidx.pgno);
                sqlite3Fts5BufferAppendVarint(&p.rc, &pDlidx1.buf, iFirst);
                pDlidx1.bPrevValid = 1;
                pDlidx1.iPrev = iFirst;
            }

            sqlite3Fts5BufferZero(&pDlidx.buf);
            pDlidx.bPrevValid = 0;
            pDlidx.pgno += 1;
        } else {
            bDone = 1;
        }

        if (pDlidx.bPrevValid != 0) {
            iVal = @bitCast(@as(u64, @bitCast(iRowid)) -% @as(u64, @bitCast(pDlidx.iPrev)));
        } else {
            const iPgno: i64 = if (i == 0) pWriter.writer.pgno else pWriter.aDlidx.?[@intCast(i - 1)].pgno;
            sqlite3Fts5BufferAppendVarint(&p.rc, &pDlidx.buf, @intFromBool(bDone == 0));
            sqlite3Fts5BufferAppendVarint(&p.rc, &pDlidx.buf, iPgno);
            iVal = iRowid;
        }

        sqlite3Fts5BufferAppendVarint(&p.rc, &pDlidx.buf, iVal);
        pDlidx.bPrevValid = 1;
        pDlidx.iPrev = iRowid;
    }
}

fn fts5WriteFlushLeaf(p: *Fts5IndexS, pWriter: *Fts5SegWriter) void {
    const zero = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const pPage = &pWriter.writer;
    var iRowid: i64 = undefined;

    // Set the szLeaf header field.
    fts5PutU16(pPage.buf.p.? + 2, @intCast(pPage.buf.n));

    if (pWriter.bFirstTermInPage != 0) {
        // No term was written to this page.
        fts5WriteBtreeNoTerm(p, pWriter);
    } else {
        // Append the pgidx to the page buffer.
        fts5BufferAppendBlob(&p.rc, &pPage.buf, pPage.pgidx.n, pPage.pgidx.p);
    }

    // Write the page out to disk
    iRowid = FTS5_SEGMENT_ROWID(pWriter.iSegid, pPage.pgno);
    fts5DataWrite(p, iRowid, pPage.buf.p, pPage.buf.n);

    // Initialize the next page.
    fts5BufferZero(&pPage.buf);
    fts5BufferZero(&pPage.pgidx);
    fts5BufferAppendBlob(&p.rc, &pPage.buf, 4, &zero);
    pPage.iPrevPgidx = 0;
    pPage.pgno += 1;

    pWriter.nLeafWritten += 1;

    pWriter.bFirstTermInPage = 1;
    pWriter.bFirstRowidInPage = 1;
}

fn fts5WriteAppendTerm(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    nTerm: c_int,
    pTerm: ?[*]const u8,
) void {
    var nPrefix: c_int = undefined;
    var pPage = &pWriter.writer;
    const pPgidx = &pWriter.writer.pgidx;
    const nMin = MIN(c_int, pPage.term.n, nTerm);

    // If the current leaf page is full, flush it to disk.
    if ((pPage.buf.n + pPgidx.n + nTerm + 2) >= p.pConfig.?.pgsz) {
        if (pPage.buf.n > 4) {
            fts5WriteFlushLeaf(p, pWriter);
            if (p.rc != SQLITE_OK) return;
        }
        _ = fts5BufferGrow(&p.rc, &pPage.buf, nTerm + @as(c_int, @intCast(FTS5_DATA_PADDING)));
    }

    // TODO1: Updating pgidx here.
    pPgidx.n += sqlite3Fts5PutVarint(
        pPgidx.p.? + @as(usize, @intCast(pPgidx.n)),
        @bitCast(@as(i64, pPage.buf.n - pPage.iPrevPgidx)),
    );
    pPage.iPrevPgidx = pPage.buf.n;

    if (pWriter.bFirstTermInPage != 0) {
        nPrefix = 0;
        if (pPage.pgno != 1) {
            // First term on a non-leftmost leaf: add a term to the b-tree
            // hierarchy that is larger than the largest term already written
            // and <= this term.
            var n: c_int = nTerm;
            if (pPage.term.n != 0) {
                n = 1 + fts5PrefixCompress(nMin, pPage.term.p, pTerm);
            }
            fts5WriteBtreeTerm(p, pWriter, n, pTerm);
            if (p.rc != SQLITE_OK) return;
            pPage = &pWriter.writer;
        }
    } else {
        nPrefix = fts5PrefixCompress(nMin, pPage.term.p, pTerm);
        fts5BufferAppendVarint(&p.rc, &pPage.buf, nPrefix);
    }

    // Append the number of bytes of new data, then the term data itself.
    fts5BufferAppendVarint(&p.rc, &pPage.buf, nTerm - nPrefix);
    fts5BufferAppendBlob(&p.rc, &pPage.buf, nTerm - nPrefix, pTerm.? + @as(usize, @intCast(nPrefix)));

    // Update the Fts5PageWriter.term field.
    fts5BufferSet(&p.rc, &pPage.term, nTerm, pTerm);
    pWriter.bFirstTermInPage = 0;

    pWriter.bFirstRowidInPage = 0;
    pWriter.bFirstRowidInDoclist = 1;

    pWriter.aDlidx.?[0].pgno = pPage.pgno;
}

fn fts5WriteAppendRowid(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    iRowid: i64,
) void {
    if (p.rc == SQLITE_OK) {
        const pPage = &pWriter.writer;

        if ((pPage.buf.n + pPage.pgidx.n) >= p.pConfig.?.pgsz) {
            fts5WriteFlushLeaf(p, pWriter);
        }

        // First rowid on the page: set rowid-pointer in page-header and append
        // a value to the dlidx buffer in case a doclist-index is required.
        if (pWriter.bFirstRowidInPage != 0) {
            fts5PutU16(pPage.buf.p.?, @intCast(pPage.buf.n));
            fts5WriteDlidxAppend(p, pWriter, iRowid);
        }

        // Write the rowid.
        if (pWriter.bFirstRowidInDoclist != 0 or pWriter.bFirstRowidInPage != 0) {
            fts5BufferAppendVarint(&p.rc, &pPage.buf, iRowid);
        } else {
            fts5BufferAppendVarint(
                &p.rc,
                &pPage.buf,
                @bitCast(@as(u64, @bitCast(iRowid)) -% @as(u64, @bitCast(pWriter.iPrevRowid))),
            );
        }
        pWriter.iPrevRowid = iRowid;
        pWriter.bFirstRowidInDoclist = 0;
        pWriter.bFirstRowidInPage = 0;
    }
}

fn fts5WriteAppendPoslistData(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    aData: ?[*]const u8,
    nData: c_int,
) void {
    const pPage = &pWriter.writer;
    var a = aData.?;
    var n = nData;

    while (p.rc == SQLITE_OK and
        (pPage.buf.n + pPage.pgidx.n + n) >= p.pConfig.?.pgsz)
    {
        const nReq = p.pConfig.?.pgsz - pPage.buf.n - pPage.pgidx.n;
        var nCopy: c_int = 0;
        while (nCopy < nReq) {
            var dummy: i64 = undefined;
            nCopy += fts5GetVarint(a + @as(usize, @intCast(nCopy)), @ptrCast(&dummy));
        }
        fts5BufferAppendBlob(&p.rc, &pPage.buf, nCopy, a);
        a += @as(usize, @intCast(nCopy));
        n -= nCopy;
        fts5WriteFlushLeaf(p, pWriter);
    }
    if (n > 0) {
        fts5BufferAppendBlob(&p.rc, &pPage.buf, n, a);
    }
}

fn fts5WriteFinish(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    pnLeaf: *c_int, // OUT: Number of leaf pages in b-tree
) void {
    var i: c_int = 0;
    const pLeaf = &pWriter.writer;
    if (p.rc == SQLITE_OK) {
        if (pLeaf.buf.n > 4) {
            fts5WriteFlushLeaf(p, pWriter);
        }
        pnLeaf.* = pLeaf.pgno - 1;
        if (pLeaf.pgno > 1) {
            fts5WriteFlushBtree(p, pWriter);
        }
    }
    fts5BufferFree(&pLeaf.term);
    fts5BufferFree(&pLeaf.buf);
    fts5BufferFree(&pLeaf.pgidx);
    fts5BufferFree(&pWriter.btterm);

    while (i < pWriter.nDlidx) : (i += 1) {
        sqlite3Fts5BufferFree(&pWriter.aDlidx.?[@intCast(i)].buf);
    }
    sqlite3_free(pWriter.aDlidx);
}

fn fts5WriteInit(
    p: *Fts5IndexS,
    pWriter: *Fts5SegWriter,
    iSegid: c_int,
) void {
    const nBuffer: c_int = p.pConfig.?.pgsz + @as(c_int, @intCast(FTS5_DATA_PADDING));

    _ = memset(pWriter, 0, @sizeOf(Fts5SegWriter));
    pWriter.iSegid = iSegid;

    _ = fts5WriteDlidxGrow(p, pWriter, 1);
    pWriter.writer.pgno = 1;
    pWriter.bFirstTermInPage = 1;
    pWriter.iBtPage = 1;

    // Grow the two buffers to pgsz + padding bytes in size.
    _ = sqlite3Fts5BufferSize(&p.rc, &pWriter.writer.pgidx, @bitCast(nBuffer));
    _ = sqlite3Fts5BufferSize(&p.rc, &pWriter.writer.buf, @bitCast(nBuffer));

    if (p.pIdxWriter == null) {
        const pConfig = p.pConfig.?;
        _ = fts5IndexPrepareStmt(p, &p.pIdxWriter, sqlite3_mprintf(
            "INSERT INTO '%q'.'%q_idx'(segid,term,pgno) VALUES(?,?,?)",
            pConfig.zDb,
            pConfig.zName,
        ));
    }

    if (p.rc == SQLITE_OK) {
        // Initialize the 4-byte leaf-page header to 0x00.
        _ = memset(pWriter.writer.buf.p, 0, 4);
        pWriter.writer.buf.n = 4;

        // Bind the current output segment id to the index-writer.
        _ = sqlite3_bind_int(p.pIdxWriter, 1, pWriter.iSegid);
    }
}

fn fts5TrimSegments(p: *Fts5IndexS, pIter: *Fts5Iter) void {
    var i: c_int = 0;
    var buf: Fts5Buffer = undefined;
    _ = memset(&buf, 0, @sizeOf(Fts5Buffer));
    while (i < pIter.nSeg and p.rc == SQLITE_OK) : (i += 1) {
        const pSeg = iterSeg(pIter, i);
        if (pSeg.pSeg == null) {
            // no-op
        } else if (pSeg.pLeaf == null) {
            // All keys transferred to the output. Mark segment empty.
            pSeg.pSeg.?.pgnoLast = 0;
            pSeg.pSeg.?.pgnoFirst = 0;
        } else {
            const iOff = pSeg.iTermLeafOffset; // Offset on new first leaf page
            const iId = pSeg.pSeg.?.iSegid;
            const aHdr = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

            const iLeafRowid = FTS5_SEGMENT_ROWID(iId, pSeg.iTermLeafPgno);
            const pData = fts5LeafRead(p, iLeafRowid);
            if (pData) |pD| {
                if (iOff > pD.szLeaf) {
                    // Can occur if pages overlap (one page in >1 segment).
                    _ = fts5IndexCorruptRowid(p, iLeafRowid);
                } else {
                    fts5BufferZero(&buf);
                    _ = fts5BufferGrow(&p.rc, &buf, pD.nn);
                    fts5BufferAppendBlob(&p.rc, &buf, @intCast(aHdr.len), &aHdr);
                    fts5BufferAppendVarint(&p.rc, &buf, pSeg.term.n);
                    fts5BufferAppendBlob(&p.rc, &buf, pSeg.term.n, pSeg.term.p);
                    fts5BufferAppendBlob(&p.rc, &buf, pD.szLeaf - iOff, pD.p.? + @as(usize, @intCast(iOff)));
                    if (p.rc == SQLITE_OK) {
                        // Set the szLeaf field
                        fts5PutU16(buf.p.? + 2, @intCast(buf.n));
                    }

                    // Set up the new page-index array
                    fts5BufferAppendVarint(&p.rc, &buf, 4);
                    if (pSeg.iLeafPgno == pSeg.iTermLeafPgno and
                        pSeg.iEndofDoclist < pD.szLeaf and
                        pSeg.iPgidxOff <= pD.nn)
                    {
                        const nDiff = pD.szLeaf - pSeg.iEndofDoclist;
                        fts5BufferAppendVarint(&p.rc, &buf, buf.n - 1 - nDiff - 4);
                        fts5BufferAppendBlob(
                            &p.rc,
                            &buf,
                            pD.nn - pSeg.iPgidxOff,
                            pD.p.? + @as(usize, @intCast(pSeg.iPgidxOff)),
                        );
                    }

                    pSeg.pSeg.?.pgnoFirst = pSeg.iTermLeafPgno;
                    fts5DataDelete(p, FTS5_SEGMENT_ROWID(iId, 1), iLeafRowid);
                    fts5DataWrite(p, iLeafRowid, buf.p, buf.n);
                }
                fts5DataRelease(pD);
            }
        }
    }
    fts5BufferFree(&buf);
}

fn fts5MergeChunkCallback(
    p: ?*Fts5IndexS,
    pCtx: ?*anyopaque,
    pChunk: ?[*]const u8,
    nChunk: c_int,
) callconv(.c) void {
    const pWriter: *Fts5SegWriter = @ptrCast(@alignCast(pCtx.?));
    fts5WriteAppendPoslistData(p.?, pWriter, pChunk, nChunk);
}

fn fts5IndexMergeLevel(
    p: *Fts5IndexS,
    ppStruct: *?*Fts5Structure, // IN/OUT: Structure of index
    iLvl: c_int, // Level to read input from
    pnRem: ?*c_int, // Write up to this many output leaves
) void {
    var pStruct = ppStruct.*.?;
    var pLvl = structLevel(pStruct, iLvl);
    var pLvlOut: *Fts5StructureLevel = undefined;
    var pIter: ?*Fts5Iter = null;
    const nRem: c_int = if (pnRem) |r| r.* else 0;
    var nInput: c_int = undefined;
    var writer: Fts5SegWriter = undefined;
    var pSeg: *Fts5StructureSegment = undefined;
    var term: Fts5Buffer = undefined;
    var bOldest: c_int = undefined;
    const eDetail = p.pConfig.?.eDetail;
    const flags = FTS5INDEX_QUERY_NOOUTPUT;
    var bTermWritten: c_int = 0;

    _ = memset(&writer, 0, @sizeOf(Fts5SegWriter));
    _ = memset(&term, 0, @sizeOf(Fts5Buffer));
    if (pLvl.nMerge != 0) {
        pLvlOut = structLevel(pStruct, iLvl + 1);
        nInput = pLvl.nMerge;
        pSeg = &pLvlOut.aSeg.?[@intCast(pLvlOut.nSeg - 1)];

        fts5WriteInit(p, &writer, pSeg.iSegid);
        writer.writer.pgno = pSeg.pgnoLast + 1;
        writer.iBtPage = 0;
    } else {
        const iSegid = fts5AllocateSegid(p, pStruct);

        // Extend the Fts5Structure so the output segment exists.
        if (iLvl == pStruct.nLevel - 1) {
            fts5StructureAddLevel(&p.rc, ppStruct);
            pStruct = ppStruct.*.?;
        }
        fts5StructureExtendLevel(&p.rc, pStruct, iLvl + 1, 1, 0);
        if (p.rc != 0) return;
        pLvl = structLevel(pStruct, iLvl);
        pLvlOut = structLevel(pStruct, iLvl + 1);

        fts5WriteInit(p, &writer, iSegid);

        // Add the new segment to the output level
        pSeg = &pLvlOut.aSeg.?[@intCast(pLvlOut.nSeg)];
        pLvlOut.nSeg += 1;
        pSeg.pgnoFirst = 1;
        pSeg.iSegid = iSegid;
        pStruct.nSegment += 1;

        // Read input from all segments in the input level
        nInput = pLvl.nSeg;

        // Set the range of origins for the output segment.
        if (pStruct.nOriginCntr > 0) {
            pSeg.iOrigin1 = pLvl.aSeg.?[0].iOrigin1;
            pSeg.iOrigin2 = pLvl.aSeg.?[@intCast(pLvl.nSeg - 1)].iOrigin2;
        }
    }
    bOldest = @intFromBool(pLvlOut.nSeg == 1 and pStruct.nLevel == iLvl + 2);

    fts5MultiIterNew(p, pStruct, flags, null, null, 0, iLvl, nInput, &pIter);
    while (fts5MultiIterEof(p, pIter) == 0) : (fts5MultiIterNext(p, pIter, 0, 0)) {
        const pSegIter = iterSeg(pIter.?, pIter.?.aFirst.?[1].iFirst);
        var nPos: c_int = undefined;
        var nTerm: c_int = undefined;
        var pTerm: ?[*]const u8 = undefined;

        pTerm = fts5MultiIterTerm(pIter, &nTerm);
        if (nTerm != term.n or fts5Memcmp(pTerm, term.p, nTerm) != 0) {
            if (pnRem != null and writer.nLeafWritten > nRem) {
                break;
            }
            fts5BufferSet(&p.rc, &term, nTerm, pTerm);
            bTermWritten = 0;
        }

        // Check for key annihilation.
        if (pSegIter.nPos == 0 and (bOldest != 0 or pSegIter.bDel == 0)) continue;

        if (p.rc == SQLITE_OK and bTermWritten == 0) {
            // New term: append a term to the output segment.
            fts5WriteAppendTerm(p, &writer, nTerm, pTerm);
            bTermWritten = 1;
        }

        // Append the rowid to the output (WRITEPOSLISTSIZE)
        fts5WriteAppendRowid(p, &writer, fts5MultiIterRowid(pIter));

        if (eDetail == FTS5_DETAIL_NONE) {
            if (pSegIter.bDel != 0) {
                fts5BufferAppendVarint(&p.rc, &writer.writer.buf, 0);
                if (pSegIter.nPos > 0) {
                    fts5BufferAppendVarint(&p.rc, &writer.writer.buf, 0);
                }
            }
        } else {
            // Append the position-list data to the output
            nPos = pSegIter.nPos * 2 + pSegIter.bDel;
            fts5BufferAppendVarint(&p.rc, &writer.writer.buf, nPos);
            fts5ChunkIterate(p, pSegIter, @ptrCast(&writer), &fts5MergeChunkCallback);
        }
    }

    // Flush the last leaf page to disk. Set output b-tree height and last
    // leaf page number at the same time.
    fts5WriteFinish(p, &writer, &pSeg.pgnoLast);

    if (fts5MultiIterEof(p, pIter) != 0) {
        var ii: c_int = 0;

        // Remove the redundant segments from the %_data table
        while (ii < nInput) : (ii += 1) {
            const pOld = &pLvl.aSeg.?[@intCast(ii)];
            pSeg.nEntry += (pOld.nEntry - pOld.nEntryTombstone);
            fts5DataRemoveSegment(p, pOld);
        }

        // Remove the redundant segments from the input level
        if (pLvl.nSeg != nInput) {
            const nMove: usize = @as(usize, @intCast(pLvl.nSeg - nInput)) * @sizeOf(Fts5StructureSegment);
            _ = memmove(pLvl.aSeg.?, &pLvl.aSeg.?[@intCast(nInput)], nMove);
        }
        pStruct.nSegment -= nInput;
        pLvl.nSeg -= nInput;
        pLvl.nMerge = 0;
        if (pSeg.pgnoLast == 0) {
            pLvlOut.nSeg -= 1;
            pStruct.nSegment -= 1;
        }
    } else {
        fts5TrimSegments(p, pIter.?);
        pLvl.nMerge = nInput;
    }

    fts5MultiIterFree(pIter);
    fts5BufferFree(&term);
    if (pnRem) |r| r.* -= writer.nLeafWritten;
}

fn fts5IndexFindDeleteMerge(p: *Fts5IndexS, pStruct: *Fts5Structure) c_int {
    const pConfig = p.pConfig.?;
    var iRet: c_int = -1;
    if (pConfig.bContentlessDelete != 0 and pConfig.nDeleteMerge > 0) {
        var ii: c_int = 0;
        var nBest: c_int = 0;

        while (ii < pStruct.nLevel) : (ii += 1) {
            const pLvl = structLevel(pStruct, ii);
            var nEntry: i64 = 0;
            var nTomb: i64 = 0;
            var iSeg: c_int = 0;
            while (iSeg < pLvl.nSeg) : (iSeg += 1) {
                nEntry += @bitCast(pLvl.aSeg.?[@intCast(iSeg)].nEntry);
                nTomb += @bitCast(pLvl.aSeg.?[@intCast(iSeg)].nEntryTombstone);
            }
            if (nEntry > 0) {
                const nPercent: c_int = @intCast(@divTrunc(nTomb * 100, nEntry));
                if (nPercent >= pConfig.nDeleteMerge and nPercent > nBest) {
                    iRet = ii;
                    nBest = nPercent;
                }
            }

            // If pLvl is already the input level to an ongoing merge, stop.
            if (pLvl.nMerge != 0) break;
        }
    }
    return iRet;
}

fn fts5IndexMerge(
    p: *Fts5IndexS,
    ppStruct: *?*Fts5Structure, // IN/OUT: Current structure of index
    nPg: c_int, // Pages of work to do
    nMinIn: c_int, // Minimum number of segments to merge
) c_int {
    var nRem = nPg;
    var bRet: c_int = 0;
    var nMin = nMinIn;
    var pStruct: ?*Fts5Structure = ppStruct.*;
    while (nRem > 0 and p.rc == SQLITE_OK) {
        var iLvl: c_int = 0;
        var iBestLvl: c_int = 0;
        var nBest: c_int = 0;

        // Set iBestLvl to the level to read input segments from, or -1 if none.
        while (iLvl < pStruct.?.nLevel) : (iLvl += 1) {
            const pLvl = structLevel(pStruct.?, iLvl);
            if (pLvl.nMerge != 0) {
                if (pLvl.nMerge > nBest) {
                    iBestLvl = iLvl;
                    nBest = nMin;
                }
                break;
            }
            if (pLvl.nSeg > nBest) {
                nBest = pLvl.nSeg;
                iBestLvl = iLvl;
            }
        }
        if (nBest < nMin) {
            iBestLvl = fts5IndexFindDeleteMerge(p, pStruct.?);
        }

        if (iBestLvl < 0) break;
        bRet = 1;
        fts5IndexMergeLevel(p, &pStruct, iBestLvl, &nRem);
        if (p.rc == SQLITE_OK and structLevel(pStruct.?, iBestLvl).nMerge == 0) {
            fts5StructurePromote(p, iBestLvl + 1, pStruct.?);
        }

        if (nMin == 1) nMin = 2;
    }
    ppStruct.* = pStruct;
    return bRet;
}

fn fts5IndexAutomerge(
    p: *Fts5IndexS,
    ppStruct: *?*Fts5Structure, // IN/OUT: Current structure of index
    nLeaf: c_int, // Number of output leaves just written
) void {
    if (p.rc == SQLITE_OK and p.pConfig.?.nAutomerge > 0 and ALWAYS(ppStruct.* != null)) {
        const pStruct = ppStruct.*.?;
        var nWrite: u64 = undefined;
        var nWork: c_int = undefined;
        var nRem: c_int = undefined;

        // Update the write-counter. While doing so, set nWork.
        nWrite = pStruct.nWriteCounter;
        nWork = @intCast(((nWrite + @as(u64, @intCast(nLeaf))) / @as(u64, @intCast(p.nWorkUnit))) -
            (nWrite / @as(u64, @intCast(p.nWorkUnit))));
        pStruct.nWriteCounter += @intCast(nLeaf);
        nRem = p.nWorkUnit * nWork * pStruct.nLevel;

        _ = fts5IndexMerge(p, ppStruct, nRem, p.pConfig.?.nAutomerge);
    }
}

fn fts5IndexCrisismerge(
    p: *Fts5IndexS,
    ppStruct: *?*Fts5Structure, // IN/OUT: Current structure of index
) void {
    const nCrisis = p.pConfig.?.nCrisisMerge;
    var pStruct = ppStruct.*;
    if (pStruct != null and pStruct.?.nLevel > 0) {
        var iLvl: c_int = 0;
        while (p.rc == SQLITE_OK and structLevel(pStruct.?, iLvl).nSeg >= nCrisis) {
            fts5IndexMergeLevel(p, &pStruct, iLvl, null);
            fts5StructurePromote(p, iLvl + 1, pStruct.?);
            iLvl += 1;
        }
        ppStruct.* = pStruct;
    }
}

fn fts5IndexReturn(p: *Fts5IndexS) c_int {
    const rc = p.rc;
    p.rc = SQLITE_OK;
    return rc;
}

/// Close the read-only blob handle, if it is open.
export fn sqlite3Fts5IndexCloseReader(p: *Fts5IndexS) callconv(.c) void {
    fts5IndexCloseReader(p);
    _ = fts5IndexReturn(p);
}

// ============================ CHUNK 7 ============================
const FTS5_DATA_ZERO_PADDING_USZ: usize = @intCast(FTS5_DATA_ZERO_PADDING);


// ===========================================================================
// fts5PoslistPrefix
// ===========================================================================
fn fts5PoslistPrefix(aBuf: [*]const u8, nMax: c_int) c_int {
    var ret: c_int = undefined;
    var dummy: u32 = undefined;
    ret = sqlite3Fts5GetVarint32(aBuf, &dummy);
    if (ret < nMax) {
        while (true) {
            const i = sqlite3Fts5GetVarint32(aBuf + @as(usize, @intCast(ret)), &dummy);
            if ((ret + i) > nMax) break;
            ret += i;
        }
    }
    return ret;
}

// ===========================================================================
// fts5SecureDeleteIdxEntry
// ===========================================================================
fn fts5SecureDeleteIdxEntry(p: *Fts5IndexS, iSegid: c_int, iPgno: c_int) void {
    if (iPgno != 1) {
        if (p.pDeleteFromIdx == null) {
            const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));
            _ = fts5IndexPrepareStmt(p, &p.pDeleteFromIdx, sqlite3_mprintf(
                "DELETE FROM '%q'.'%q_idx' WHERE (segid, (pgno/2)) = (?1, ?2)",
                pConfig.zDb,
                pConfig.zName,
            ));
        }
        if (p.rc == SQLITE_OK) {
            _ = sqlite3_bind_int(p.pDeleteFromIdx, 1, iSegid);
            _ = sqlite3_bind_int(p.pDeleteFromIdx, 2, iPgno);
            _ = sqlite3_step(p.pDeleteFromIdx);
            p.rc = sqlite3_reset(p.pDeleteFromIdx);
        }
    }
}

// ===========================================================================
// fts5SecureDeleteOverflow
// ===========================================================================
fn fts5SecureDeleteOverflow(
    p: *Fts5IndexS,
    pSeg: *Fts5StructureSegment,
    iPgno: c_int,
    pbLastInDoclist: *c_int,
) void {
    const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));
    const bDetailNone: c_int = @intFromBool(pConfig.eDetail == FTS5_DETAIL_NONE);
    var pgno: c_int = undefined;
    var pLeaf: ?*Fts5Data = null;

    pbLastInDoclist.* = 1;
    pgno = iPgno;
    while (p.rc == SQLITE_OK and pgno <= pSeg.pgnoLast) : (pgno += 1) {
        const iRowid: i64 = FTS5_SEGMENT_ROWID(pSeg.iSegid, pgno);
        var iNext: c_int = 0;
        var aPg: [*]u8 = undefined;

        pLeaf = fts5DataRead(p, iRowid);
        if (pLeaf == null) break;
        aPg = pLeaf.?.p.?;

        iNext = @intCast(fts5GetU16(aPg));
        if (iNext != 0) {
            pbLastInDoclist.* = 0;
        }
        if (iNext == 0 and pLeaf.?.szLeaf != pLeaf.?.nn) {
            _ = fts5GetVarint32Into(c_int, aPg + @as(usize, @intCast(pLeaf.?.szLeaf)), &iNext);
        }

        if (iNext == 0) {
            // The page contains no terms or rowids. Replace it with an empty
            // page and move on to the right-hand peer.
            const aEmpty = [_]u8{ 0x00, 0x00, 0x00, 0x04 };
            if (bDetailNone == 0) fts5DataWrite(p, iRowid, &aEmpty, aEmpty.len);
            fts5DataRelease(pLeaf);
            pLeaf = null;
        } else if (bDetailNone != 0) {
            break;
        } else if (iNext >= pLeaf.?.szLeaf or pLeaf.?.nn < pLeaf.?.szLeaf or iNext < 4) {
            _ = fts5IndexCorruptRowid(p, iRowid);
            break;
        } else {
            const nShift = iNext - 4;
            var nPg: c_int = undefined;

            var nIdx: c_int = 0;
            var aIdx: ?[*]u8 = null;

            // Unless the current page footer is 0 bytes in size, allocate and
            // populate a buffer containing the new page footer.
            if (pLeaf.?.nn > pLeaf.?.szLeaf) {
                var iFirst: c_int = 0;
                var iA1: c_int = pLeaf.?.szLeaf;
                var iA2: c_int = 0;

                iA1 += fts5GetVarint32Into(c_int, aPg + @as(usize, @intCast(iA1)), &iFirst);
                if (iFirst < iNext) {
                    _ = fts5IndexCorruptRowid(p, iRowid);
                    break;
                }
                aIdx = @ptrCast(sqlite3Fts5MallocZero(&p.rc, (pLeaf.?.nn - pLeaf.?.szLeaf) + 2));
                if (aIdx == null) break;
                iA2 = sqlite3Fts5PutVarint(aIdx.?, @bitCast(@as(i64, iFirst - nShift)));
                if (iA1 < pLeaf.?.nn) {
                    _ = memcpy(aIdx.? + @as(usize, @intCast(iA2)), aPg + @as(usize, @intCast(iA1)), @intCast(pLeaf.?.nn - iA1));
                    iA2 += (pLeaf.?.nn - iA1);
                }
                nIdx = iA2;
            }

            // Modify the contents of buffer aPg[]. Set nPg to the new size.
            nPg = pLeaf.?.szLeaf - nShift;
            _ = memmove(aPg + 4, aPg + @as(usize, @intCast(4 + nShift)), @intCast(nPg - 4));
            fts5PutU16(aPg + 2, @intCast(nPg));
            if (fts5GetU16(aPg) != 0) fts5PutU16(aPg, 4);
            if (nIdx > 0) {
                _ = memcpy(aPg + @as(usize, @intCast(nPg)), aIdx.?, @intCast(nIdx));
                nPg += nIdx;
            }
            sqlite3_free(aIdx);

            // Write the new page to disk and exit the loop.
            fts5DataWrite(p, iRowid, aPg, nPg);
            break;
        }
    }
    fts5DataRelease(pLeaf);
}

// ===========================================================================
// fts5DoSecureDelete
// ===========================================================================
fn fts5DoSecureDelete(p: *Fts5IndexS, pSeg: *Fts5SegIter) void {
    const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));
    const bDetailNone: c_int = @intFromBool(pConfig.eDetail == FTS5_DETAIL_NONE);
    const iSegid = pSeg.pSeg.?.iSegid;
    const aPg: [*]u8 = pSeg.pLeaf.?.p.?;
    var nPg = pSeg.pLeaf.?.nn;
    var iPgIdx = pSeg.pLeaf.?.szLeaf; // Offset of page footer

    var iDelta: u64 = 0;
    var iNextOff: c_int = 0;
    var iOff: c_int = 0;
    var nIdx: c_int = 0;
    var aIdx: ?[*]u8 = null;
    var bLastInDoclist: c_int = 0;
    var iIdx: c_int = 0;
    var iStart: c_int = 0;
    var iDelKeyOff: c_int = 0; // Offset of deleted key, if any

    nIdx = nPg - iPgIdx;
    aIdx = @ptrCast(sqlite3Fts5MallocZero(&p.rc, @as(i64, nIdx) + 16));
    if (p.rc != 0) return;
    _ = memcpy(aIdx.?, aPg + @as(usize, @intCast(iPgIdx)), @intCast(nIdx));

    // Set iStart, iDelta, iNextOff (see C comment for the meaning).
    {
        var iSOP: c_int = undefined; // Start-Of-Position-list
        if (pSeg.iLeafPgno == pSeg.iTermLeafPgno) {
            iStart = pSeg.iTermLeafOffset;
        } else {
            iStart = @intCast(fts5GetU16(aPg));
        }
        if (iStart > nPg) {
            _ = fts5IndexCorruptIdx(p);
            sqlite3_free(aIdx);
            return;
        }

        iSOP = iStart + fts5GetVarint(aPg + @as(usize, @intCast(iStart)), &iDelta);

        if (bDetailNone != 0) {
            while (iSOP < pSeg.iLeafOffset) {
                if (aPg[@intCast(iSOP)] == 0x00) iSOP += 1;
                if (aPg[@intCast(iSOP)] == 0x00) iSOP += 1;
                iStart = iSOP;
                iSOP = iStart + fts5GetVarint(aPg + @as(usize, @intCast(iStart)), &iDelta);
            }

            iNextOff = iSOP;
            if (iNextOff < pSeg.iEndofDoclist and aPg[@intCast(iNextOff)] == 0x00) iNextOff += 1;
            if (iNextOff < pSeg.iEndofDoclist and aPg[@intCast(iNextOff)] == 0x00) iNextOff += 1;
        } else {
            var nPos: c_int = 0;
            iSOP += fts5GetVarint32Into(c_int, aPg + @as(usize, @intCast(iSOP)), &nPos);
            while (iSOP < pSeg.iLeafOffset) {
                iStart = iSOP + @divTrunc(nPos, 2);
                iSOP = iStart + fts5GetVarint(aPg + @as(usize, @intCast(iStart)), &iDelta);
                iSOP += fts5GetVarint32Into(c_int, aPg + @as(usize, @intCast(iSOP)), &nPos);
            }
            iNextOff = iSOP + pSeg.nPos;
        }
    }

    iOff = iStart;

    // If the position-list for the entry being removed flows over past the
    // end of this page, delete the portion on the next page and beyond.
    if (iNextOff >= iPgIdx) {
        const pgno = pSeg.iLeafPgno + 1;
        fts5SecureDeleteOverflow(p, pSeg.pSeg.?, pgno, &bLastInDoclist);
        iNextOff = iPgIdx;
    }

    if (pSeg.bDel == 0) {
        if (iNextOff != iPgIdx) {
            // Loop through the page-footer. If iNextOff equals the offset of a
            // key on this page, the entry is the last in its doclist.
            var iKeyOff: c_int = 0;
            iIdx = 0;
            while (iIdx < nIdx) {
                var iVal: u32 = 0;
                iIdx += fts5GetVarint32Into(u32, aIdx.? + @as(usize, @intCast(iIdx)), &iVal);
                iKeyOff += @bitCast(iVal);
                if (iKeyOff == iNextOff) {
                    bLastInDoclist = 1;
                }
            }
        }

        // If this is (a) the first rowid on a page and (b) is not followed by
        // another position list on the same page, set the "first-rowid" field
        // of the header to 0.
        if (@as(c_int, @intCast(fts5GetU16(aPg))) == iStart and (bLastInDoclist != 0 or iNextOff == iPgIdx)) {
            fts5PutU16(aPg, 0);
        }
    }

    if (pSeg.bDel != 0) {
        iOff += sqlite3Fts5PutVarint(aPg + @as(usize, @intCast(iOff)), iDelta);
        aPg[@intCast(iOff)] = 0x01;
        iOff += 1;
    } else if (bLastInDoclist == 0) {
        if (iNextOff != iPgIdx) {
            var iNextDelta: u64 = 0;
            iNextOff += fts5GetVarint(aPg + @as(usize, @intCast(iNextOff)), &iNextDelta);
            iOff += sqlite3Fts5PutVarint(aPg + @as(usize, @intCast(iOff)), iDelta +% iNextDelta);
        }
    } else if (pSeg.iLeafPgno == pSeg.iTermLeafPgno and iStart == pSeg.iTermLeafOffset) {
        // The entry being removed was the only position list in its doclist.
        // Therefore the term needs to be removed as well.
        var iKey: c_int = 0;
        var iKeyOff: c_int = 0;

        // Set iKeyOff to the offset of the term that will be removed - the
        // last offset in the footer that is not greater than iStart.
        iIdx = 0;
        while (iIdx < nIdx) : (iKey += 1) {
            var iVal: u32 = 0;
            iIdx += fts5GetVarint32Into(u32, aIdx.? + @as(usize, @intCast(iIdx)), &iVal);
            if ((@as(u32, @bitCast(iKeyOff)) +% iVal) > @as(u32, @bitCast(iStart))) break;
            iKeyOff += @bitCast(iVal);
        }

        // Set iDelKeyOff to the value of the footer entry to remove.
        iOff = iKeyOff;
        iDelKeyOff = iOff;

        if (iNextOff != iPgIdx) {
            // This is the only position-list associated with the term, and
            // there is another term following it on this page. So the
            // subsequent term needs to be moved to replace the term associated
            // with the entry being removed.
            var nPrefix: u64 = 0;
            var nSuffix: u64 = 0;
            var nPrefix2: u64 = 0;
            var nSuffix2: u64 = 0;

            iDelKeyOff = iNextOff;
            iNextOff += fts5GetVarint(aPg + @as(usize, @intCast(iNextOff)), &nPrefix2);
            iNextOff += fts5GetVarint(aPg + @as(usize, @intCast(iNextOff)), &nSuffix2);

            if (iKey != 1) {
                iKeyOff += fts5GetVarint(aPg + @as(usize, @intCast(iKeyOff)), &nPrefix);
            }
            iKeyOff += fts5GetVarint(aPg + @as(usize, @intCast(iKeyOff)), &nSuffix);

            nPrefix = MIN(u64, nPrefix, nPrefix2);
            nSuffix = (nPrefix2 + nSuffix2) - nPrefix;

            if ((@as(u64, @intCast(iKeyOff)) + nSuffix) > @as(u64, @intCast(iPgIdx)) or
                (@as(u64, @intCast(iNextOff)) + nSuffix2) > @as(u64, @intCast(iPgIdx)))
            {
                _ = fts5IndexCorruptIdx(p);
            } else {
                if (iKey != 1) {
                    iOff += sqlite3Fts5PutVarint(aPg + @as(usize, @intCast(iOff)), nPrefix);
                }
                iOff += sqlite3Fts5PutVarint(aPg + @as(usize, @intCast(iOff)), nSuffix);
                if (nPrefix2 > @as(u64, @intCast(pSeg.term.n))) {
                    _ = fts5IndexCorruptIdx(p);
                } else if (nPrefix2 > nPrefix) {
                    _ = memcpy(
                        aPg + @as(usize, @intCast(iOff)),
                        pSeg.term.p.? + @as(usize, @intCast(nPrefix)),
                        @intCast(nPrefix2 - nPrefix),
                    );
                    iOff += @intCast(nPrefix2 - nPrefix);
                }
                _ = memmove(aPg + @as(usize, @intCast(iOff)), aPg + @as(usize, @intCast(iNextOff)), @intCast(nSuffix2));
                iOff += @intCast(nSuffix2);
                iNextOff += @intCast(nSuffix2);
            }
        }
    } else if (iStart == 4) {
        var iPgno: c_int = undefined;

        // The entry being removed may be the only position list in its doclist.
        iPgno = pSeg.iLeafPgno - 1;
        while (iPgno > pSeg.iTermLeafPgno) : (iPgno -= 1) {
            const pPg = fts5DataRead(p, FTS5_SEGMENT_ROWID(iSegid, iPgno));
            const bEmpty: c_int = @intFromBool(pPg != null and pPg.?.nn == 4);
            fts5DataRelease(pPg);
            if (bEmpty == 0) break;
        }

        if (iPgno == pSeg.iTermLeafPgno) {
            const iId = FTS5_SEGMENT_ROWID(iSegid, pSeg.iTermLeafPgno);
            const pTerm = fts5DataRead(p, iId);
            if (pTerm != null and pTerm.?.szLeaf == pSeg.iTermLeafOffset) {
                const aTermIdx = pTerm.?.p.? + @as(usize, @intCast(pTerm.?.szLeaf));
                var nTermIdx = pTerm.?.nn - pTerm.?.szLeaf;
                var iTermIdx: c_int = 0;
                var iTermOff: i64 = 0;

                while (true) {
                    var iVal: u32 = 0;
                    const nByte = fts5GetVarint32Into(u32, aTermIdx + @as(usize, @intCast(iTermIdx)), &iVal);
                    iTermOff += @intCast(iVal);
                    if ((iTermIdx + nByte) >= nTermIdx) break;
                    iTermIdx += nByte;
                }
                nTermIdx = iTermIdx;

                if (iTermOff > pTerm.?.szLeaf) {
                    _ = fts5IndexCorruptIdx(p);
                } else {
                    _ = memmove(
                        pTerm.?.p.? + @as(usize, @intCast(iTermOff)),
                        pTerm.?.p.? + @as(usize, @intCast(pTerm.?.szLeaf)),
                        @intCast(nTermIdx),
                    );
                    fts5PutU16(pTerm.?.p.? + 2, @intCast(iTermOff));
                    fts5DataWrite(p, iId, pTerm.?.p.?, @intCast(iTermOff + nTermIdx));
                    if (nTermIdx == 0) {
                        fts5SecureDeleteIdxEntry(p, iSegid, pSeg.iTermLeafPgno);
                    }
                }
            }
            fts5DataRelease(pTerm);
        }
    }

    // Final edits to the leaf page before writing it back to disk.
    if (p.rc == SQLITE_OK) {
        const nMove = nPg - iNextOff; // Number of bytes to move
        const nShift = iNextOff - iOff; // Distance to move them

        var iPrevKeyOut: c_int = 0;
        var iKeyIn: c_int = 0;

        if (nMove > 0) {
            _ = memmove(aPg + @as(usize, @intCast(iOff)), aPg + @as(usize, @intCast(iNextOff)), @intCast(nMove));
        }
        iPgIdx -= nShift;
        nPg = iPgIdx;
        fts5PutU16(aPg + 2, @intCast(iPgIdx));

        iIdx = 0;
        while (iIdx < nIdx) {
            var iVal: u32 = 0;
            iIdx += fts5GetVarint32Into(u32, aIdx.? + @as(usize, @intCast(iIdx)), &iVal);
            iKeyIn += @bitCast(iVal);
            if (iKeyIn != iDelKeyOff) {
                const iKeyOut = iKeyIn - (if (iKeyIn > iOff) nShift else 0);
                nPg += sqlite3Fts5PutVarint(aPg + @as(usize, @intCast(nPg)), @bitCast(@as(i64, iKeyOut - iPrevKeyOut)));
                iPrevKeyOut = iKeyOut;
            }
        }

        if (iPgIdx == nPg and nIdx > 0 and pSeg.iLeafPgno != 1) {
            fts5SecureDeleteIdxEntry(p, iSegid, pSeg.iLeafPgno);
        }

        fts5DataWrite(p, FTS5_SEGMENT_ROWID(iSegid, pSeg.iLeafPgno), aPg, nPg);
    }
    sqlite3_free(aIdx);
}

// ===========================================================================
// fts5FlushSecureDelete
// ===========================================================================
fn fts5FlushSecureDelete(
    p: *Fts5IndexS,
    pStruct: *Fts5Structure,
    zTerm: [*]const u8,
    nTerm: c_int,
    iRowid: i64,
) c_int {
    const f = FTS5INDEX_QUERY_SKIPHASH;
    var pIter: ?*Fts5Iter = null; // Used to find term instance

    const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));

    // If the version number has not been set to SECUREDELETE, do so now.
    if (pConfig.iVersion != FTS5_CURRENT_VERSION_SECUREDELETE) {
        var pStmt: ?*sqlite3_stmt = null;
        _ = fts5IndexPrepareStmt(p, &pStmt, sqlite3_mprintf(
            "REPLACE INTO %Q.'%q_config' VALUES ('version', %d)",
            pConfig.zDb,
            pConfig.zName,
            FTS5_CURRENT_VERSION_SECUREDELETE,
        ));
        if (p.rc == SQLITE_OK) {
            _ = sqlite3_step(pStmt);
            const rc = sqlite3_finalize(pStmt);
            if (p.rc == SQLITE_OK) p.rc = rc;
            pConfig.iCookie += 1;
            pConfig.iVersion = FTS5_CURRENT_VERSION_SECUREDELETE;
        }
    }

    fts5MultiIterNew(p, pStruct, f, null, zTerm, nTerm, -1, 0, &pIter);
    if (fts5MultiIterEof(p, pIter.?) == 0) {
        const iThis = fts5MultiIterRowid(pIter.?);
        if (iThis < iRowid) {
            fts5MultiIterNextFrom(p, pIter.?, iRowid);
        }

        if (p.rc == SQLITE_OK and
            fts5MultiIterEof(p, pIter.?) == 0 and
            iRowid == fts5MultiIterRowid(pIter.?))
        {
            const pSeg = iterSeg(pIter.?, @intCast(pIter.?.aFirst.?[1].iFirst));
            fts5DoSecureDelete(p, pSeg);
        }
    }

    fts5MultiIterFree(pIter);
    return p.rc;
}

// ===========================================================================
// fts5FlushOneHash
// ===========================================================================
fn fts5FlushOneHash(p: *Fts5IndexS) void {
    const pHash = p.pHash.?;
    var pStruct: ?*Fts5Structure = undefined;
    var iSegid: c_int = undefined;
    var pgnoLast: c_int = 0; // Last leaf page number in segment

    // Obtain a reference to the index structure and allocate a new segment-id.
    pStruct = fts5StructureRead(p);
    fts5StructureInvalidate(p);

    if (sqlite3Fts5HashIsEmpty(pHash) == 0) {
        iSegid = fts5AllocateSegid(p, pStruct.?);
        if (iSegid != 0) {
            const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));
            const pgsz = pConfig.pgsz;
            const eDetail = pConfig.eDetail;
            const bSecureDelete = pConfig.bSecureDelete;
            var pSeg: *Fts5StructureSegment = undefined; // New segment within pStruct

            var writer: Fts5SegWriter = undefined;
            fts5WriteInit(p, &writer, iSegid);

            const pBufR = &writer.writer.buf;
            const pPgidxR = &writer.writer.pgidx;

            // Begin scanning through hash table entries.
            if (p.rc == SQLITE_OK) {
                p.rc = sqlite3Fts5HashScanInit(pHash, null, 0);
            }
            while (p.rc == SQLITE_OK and 0 == sqlite3Fts5HashScanEof(pHash)) {
                var zTerm: ?[*:0]const u8 = undefined; // Buffer containing term
                var nTerm: c_int = undefined; // Size of zTerm in bytes
                var pDoclist: ?[*]const u8 = undefined; // Pointer to doclist for this term
                var nDoclist: c_int = undefined; // Size of doclist in bytes

                // Get the term and doclist for this entry.
                sqlite3Fts5HashScanEntry(pHash, &zTerm, &nTerm, &pDoclist, &nDoclist);
                if (bSecureDelete == 0) {
                    fts5WriteAppendTerm(p, &writer, nTerm, @ptrCast(zTerm.?));
                    if (p.rc != SQLITE_OK) break;
                }

                if (bSecureDelete == 0 and pgsz >= (pBufR.n + pPgidxR.n + nDoclist + 1)) {
                    // The entire doclist will fit on the current leaf.
                    fts5BufferSafeAppendBlob(pBufR, pDoclist.?, nDoclist);
                } else {
                    var bTermWritten: c_int = @intFromBool(bSecureDelete == 0);
                    var iRowid: i64 = 0;
                    var iPrev: i64 = 0;
                    var iOff: c_int = 0;

                    // The doclist will not fit on this leaf. Iterate through the
                    // poslists that make up the current doclist.
                    while (p.rc == SQLITE_OK and iOff < nDoclist) {
                        var iDelta: u64 = 0;
                        iOff += fts5GetVarint(pDoclist.? + @as(usize, @intCast(iOff)), &iDelta);
                        iRowid +%= @bitCast(iDelta);

                        // If in secure delete mode, and this entry is a delete,
                        // edit the existing segments directly.
                        if (bSecureDelete != 0) {
                            if (eDetail == FTS5_DETAIL_NONE) {
                                if (iOff < nDoclist and pDoclist.?[@intCast(iOff)] == 0x00 and
                                    fts5FlushSecureDelete(p, pStruct.?, @ptrCast(zTerm.?), nTerm, iRowid) == 0)
                                {
                                    iOff += 1;
                                    if (iOff < nDoclist and pDoclist.?[@intCast(iOff)] == 0x00) {
                                        iOff += 1;
                                        nDoclist = 0;
                                    } else {
                                        continue;
                                    }
                                }
                            } else if ((pDoclist.?[@intCast(iOff)] & 0x01) != 0 and
                                fts5FlushSecureDelete(p, pStruct.?, @ptrCast(zTerm.?), nTerm, iRowid) == 0)
                            {
                                if (p.rc != SQLITE_OK or pDoclist.?[@intCast(iOff)] == 0x01) {
                                    iOff += 1;
                                    continue;
                                }
                            }
                        }

                        if (p.rc == SQLITE_OK and bTermWritten == 0) {
                            fts5WriteAppendTerm(p, &writer, nTerm, @ptrCast(zTerm.?));
                            bTermWritten = 1;
                        }

                        if (writer.bFirstRowidInPage != 0) {
                            fts5PutU16(pBufR.p.?, @intCast(pBufR.n)); // first rowid on page
                            pBufR.n += sqlite3Fts5PutVarint(pBufR.p.? + @as(usize, @intCast(pBufR.n)), @bitCast(iRowid));
                            writer.bFirstRowidInPage = 0;
                            fts5WriteDlidxAppend(p, &writer, iRowid);
                        } else {
                            const iRowidDelta: u64 = @as(u64, @bitCast(iRowid)) -% @as(u64, @bitCast(iPrev));
                            pBufR.n += sqlite3Fts5PutVarint(pBufR.p.? + @as(usize, @intCast(pBufR.n)), iRowidDelta);
                        }
                        if (p.rc != SQLITE_OK) break;
                        iPrev = iRowid;

                        if (eDetail == FTS5_DETAIL_NONE) {
                            if (iOff < nDoclist and pDoclist.?[@intCast(iOff)] == 0) {
                                pBufR.p.?[@intCast(pBufR.n)] = 0;
                                pBufR.n += 1;
                                iOff += 1;
                                if (iOff < nDoclist and pDoclist.?[@intCast(iOff)] == 0) {
                                    pBufR.p.?[@intCast(pBufR.n)] = 0;
                                    pBufR.n += 1;
                                    iOff += 1;
                                }
                            }
                            if ((pBufR.n + pPgidxR.n) >= pgsz) {
                                fts5WriteFlushLeaf(p, &writer);
                            }
                        } else {
                            var bDel: c_int = 0;
                            var nPos: c_int = 0;
                            var nCopy = fts5GetPoslistSize(pDoclist.? + @as(usize, @intCast(iOff)), &nPos, &bDel);
                            if (bDel != 0 and bSecureDelete != 0) {
                                fts5BufferAppendVarint(&p.rc, pBufR, nPos * 2);
                                iOff += nCopy;
                                nCopy = nPos;
                            } else {
                                nCopy += nPos;
                            }
                            if ((pBufR.n + pPgidxR.n + nCopy) <= pgsz) {
                                // The entire poslist fits on the current leaf.
                                fts5BufferSafeAppendBlob(pBufR, pDoclist.? + @as(usize, @intCast(iOff)), nCopy);
                            } else {
                                // Break the poslist into sections; each varint
                                // must be stored contiguously.
                                const pPoslist = pDoclist.? + @as(usize, @intCast(iOff));
                                var iPos: c_int = 0;
                                while (p.rc == SQLITE_OK) {
                                    const nSpace = pgsz - pBufR.n - pPgidxR.n;
                                    var n: c_int = 0;
                                    if ((nCopy - iPos) <= nSpace) {
                                        n = nCopy - iPos;
                                    } else {
                                        n = fts5PoslistPrefix(pPoslist + @as(usize, @intCast(iPos)), nSpace);
                                    }
                                    fts5BufferSafeAppendBlob(pBufR, pPoslist + @as(usize, @intCast(iPos)), n);
                                    iPos += n;
                                    if ((pBufR.n + pPgidxR.n) >= pgsz) {
                                        fts5WriteFlushLeaf(p, &writer);
                                    }
                                    if (iPos >= nCopy) break;
                                }
                            }
                            iOff += nCopy;
                        }
                    }
                }

                if (p.rc == SQLITE_OK) sqlite3Fts5HashScanNext(pHash);
            }
            var pgnoLastTmp: c_int = pgnoLast;
            fts5WriteFinish(p, &writer, &pgnoLastTmp);
            pgnoLast = pgnoLastTmp;

            if (pgnoLast > 0) {
                // Update the Fts5Structure. It is written back to the database
                // by the fts5StructureRelease() call below.
                if (pStruct.?.nLevel == 0) {
                    fts5StructureAddLevel(&p.rc, &pStruct);
                }
                fts5StructureExtendLevel(&p.rc, pStruct.?, 0, 1, 0);
                if (p.rc == SQLITE_OK) {
                    const lvl0 = structLevel(pStruct.?, 0);
                    pSeg = &lvl0.aSeg.?[@intCast(lvl0.nSeg)];
                    lvl0.nSeg += 1;
                    pSeg.iSegid = iSegid;
                    pSeg.pgnoFirst = 1;
                    pSeg.pgnoLast = pgnoLast;
                    if (pStruct.?.nOriginCntr > 0) {
                        pSeg.iOrigin1 = pStruct.?.nOriginCntr;
                        pSeg.iOrigin2 = pStruct.?.nOriginCntr;
                        pSeg.nEntry = @intCast(p.nPendingRow);
                        pStruct.?.nOriginCntr += 1;
                    }
                    pStruct.?.nSegment += 1;
                }
                fts5StructurePromote(p, 0, pStruct.?);
            }
        }
    }

    fts5IndexAutomerge(p, &pStruct, pgnoLast + p.nContentlessDelete);
    fts5IndexCrisismerge(p, &pStruct);
    fts5StructureWrite(p, pStruct.?);
    fts5StructureRelease(pStruct);
}

// ===========================================================================
// fts5IndexFlush
// ===========================================================================
fn fts5IndexFlush(p: *Fts5IndexS) void {
    // Unless it is empty, flush the hash table to disk.
    if (p.flushRc != 0) {
        p.rc = p.flushRc;
        return;
    }
    if (p.nPendingData != 0 or p.nContentlessDelete != 0) {
        fts5FlushOneHash(p);
        if (p.rc == SQLITE_OK) {
            sqlite3Fts5HashClear(p.pHash.?);
            p.nPendingData = 0;
            p.nPendingRow = 0;
            p.nContentlessDelete = 0;
        } else if (p.nPendingData != 0 or p.nContentlessDelete != 0) {
            p.flushRc = p.rc;
        }
    }
}

// ===========================================================================
// fts5IndexOptimizeStruct
// ===========================================================================
fn fts5IndexOptimizeStruct(p: *Fts5IndexS, pStruct: *Fts5Structure) ?*Fts5Structure {
    var pNew: ?*Fts5Structure = null;
    var nByte: i64 = SZ_FTS5STRUCTURE(1);
    const nSeg = pStruct.nSegment;
    var i: c_int = undefined;

    // Figure out if this structure requires optimization (see C comment).
    if (nSeg == 0) return null;
    i = 0;
    while (i < pStruct.nLevel) : (i += 1) {
        const lvl = structLevel(pStruct, i);
        const nThis = lvl.nSeg;
        const nMerge = lvl.nMerge;
        if (nThis > 0 and (nThis == nSeg or (nThis == nSeg - 1 and nMerge == nThis))) {
            if (nSeg == 1 and nThis == 1 and lvl.aSeg.?[0].nPgTombstone == 0) {
                return null;
            }
            fts5StructureRef(pStruct);
            return pStruct;
        }
    }

    nByte += (@as(i64, pStruct.nLevel) + 1) * @sizeOf(Fts5StructureLevel);
    pNew = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&p.rc, nByte)));

    if (pNew != null) {
        var pLvl: *Fts5StructureLevel = undefined;
        nByte = @as(i64, nSeg) * @sizeOf(Fts5StructureSegment);
        pNew.?.nLevel = MIN(c_int, pStruct.nLevel + 1, FTS5_MAX_LEVEL);
        pNew.?.nRef = 1;
        pNew.?.nWriteCounter = pStruct.nWriteCounter;
        pNew.?.nOriginCntr = pStruct.nOriginCntr;
        pLvl = structLevel(pNew.?, pNew.?.nLevel - 1);
        pLvl.aSeg = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&p.rc, nByte)));
        if (pLvl.aSeg != null) {
            var iLvl: c_int = undefined;
            var iSeg: c_int = undefined;
            var iSegOut: c_int = 0;
            // Iterate through all segments, oldest to newest.
            iLvl = pStruct.nLevel - 1;
            while (iLvl >= 0) : (iLvl -= 1) {
                const src = structLevel(pStruct, iLvl);
                iSeg = 0;
                while (iSeg < src.nSeg) : (iSeg += 1) {
                    pLvl.aSeg.?[@intCast(iSegOut)] = src.aSeg.?[@intCast(iSeg)];
                    iSegOut += 1;
                }
            }
            pLvl.nSeg = nSeg;
            pNew.?.nSegment = nSeg;
        } else {
            sqlite3_free(pNew);
            pNew = null;
        }
    }

    return pNew;
}

// ===========================================================================
// sqlite3Fts5IndexOptimize  (EXPORTED)
// ===========================================================================
export fn sqlite3Fts5IndexOptimize(p: *Fts5IndexS) callconv(.c) c_int {
    var pStruct: ?*Fts5Structure = undefined;
    var pNew: ?*Fts5Structure = null;

    fts5IndexFlush(p);
    pStruct = fts5StructureRead(p);
    fts5StructureInvalidate(p);

    if (pStruct != null) {
        pNew = fts5IndexOptimizeStruct(p, pStruct.?);
    }
    fts5StructureRelease(pStruct);

    if (pNew != null) {
        var iLvl: c_int = 0;
        while (structLevel(pNew.?, iLvl).nSeg == 0) : (iLvl += 1) {}
        while (p.rc == SQLITE_OK and structLevel(pNew.?, iLvl).nSeg > 0) {
            var nRem: c_int = FTS5_OPT_WORK_UNIT;
            fts5IndexMergeLevel(p, &pNew, iLvl, &nRem);
        }

        fts5StructureWrite(p, pNew.?);
        fts5StructureRelease(pNew);
    }

    return fts5IndexReturn(p);
}

// ===========================================================================
// sqlite3Fts5IndexMerge  (EXPORTED)
// ===========================================================================
export fn sqlite3Fts5IndexMerge(p: *Fts5IndexS, nMergeIn: c_int) callconv(.c) c_int {
    var nMerge = nMergeIn;
    var pStruct: ?*Fts5Structure = null;

    fts5IndexFlush(p);
    pStruct = fts5StructureRead(p);
    if (pStruct != null) {
        const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));
        var nMin = pConfig.nUsermerge;
        fts5StructureInvalidate(p);
        if (nMerge < 0) {
            const pNew = fts5IndexOptimizeStruct(p, pStruct.?);
            fts5StructureRelease(pStruct);
            pStruct = pNew;
            nMin = 1;
            nMerge = if (nMerge == int.SMALLEST_INT32) int.LARGEST_INT32 else (nMerge * -1);
        }
        if (pStruct != null and pStruct.?.nLevel != 0) {
            if (fts5IndexMerge(p, &pStruct, nMerge, nMin) != 0) {
                fts5StructureWrite(p, pStruct.?);
            }
        }
        fts5StructureRelease(pStruct);
    }
    return fts5IndexReturn(p);
}

// ===========================================================================
// fts5AppendRowid
// ===========================================================================
fn fts5AppendRowid(p: *Fts5IndexS, iDelta: u64, pUnused: ?*Fts5Iter, pBuf: *Fts5Buffer) void {
    _ = pUnused;
    fts5BufferAppendVarint(&p.rc, pBuf, @bitCast(iDelta));
}

// ===========================================================================
// fts5AppendPoslist
// ===========================================================================
fn fts5AppendPoslist(p: *Fts5IndexS, iDelta: u64, pMultiIn: ?*Fts5Iter, pBuf: *Fts5Buffer) void {
    const pMulti = pMultiIn.?;
    const nData = pMulti.base.nData;
    const nByte = nData + 9 + 9 + FTS5_DATA_ZERO_PADDING;
    if (p.rc == SQLITE_OK and false == fts5BufferGrow(&p.rc, pBuf, nByte)) {
        fts5BufferSafeAppendVarint(pBuf, @bitCast(iDelta));
        fts5BufferSafeAppendVarint(pBuf, nData * 2);
        fts5BufferSafeAppendBlob(pBuf, pMulti.base.pData.?, nData);
        _ = memset(pBuf.p.? + @as(usize, @intCast(pBuf.n)), 0, FTS5_DATA_ZERO_PADDING_USZ);
    }
}

// ===========================================================================
// fts5DoclistIterNext
// ===========================================================================
fn fts5DoclistIterNext(pIter: *Fts5DoclistIter) void {
    const pp: ?[*]u8 = if (pIter.aPoslist) |a|
        a + @as(usize, @intCast(pIter.nSize + pIter.nPoslist))
    else
        null;

    if (pp != null and @intFromPtr(pp.?) >= @intFromPtr(pIter.aEof.?)) {
        pIter.aPoslist = null;
    } else if (pp) |pcur| {
        var iDelta: u64 = undefined;

        const pq = pcur + @as(usize, @intCast(fts5GetVarint(pcur, &iDelta)));
        pIter.iRowid +%= @bitCast(iDelta);

        // Read position list size.
        if (pq[0] & 0x80 != 0) {
            var nPos: c_int = undefined;
            pIter.nSize = fts5GetVarint32Into(c_int, pq, &nPos);
            pIter.nPoslist = (nPos >> 1);
        } else {
            pIter.nPoslist = @as(c_int, @intCast(pq[0])) >> 1;
            pIter.nSize = 1;
        }

        pIter.aPoslist = pq;
        if (@intFromPtr(pq + @as(usize, @intCast(pIter.nPoslist))) > @intFromPtr(pIter.aEof.?)) {
            pIter.aPoslist = null;
        }
    }
}

// ===========================================================================
// fts5DoclistIterInit
// ===========================================================================
fn fts5DoclistIterInit(pBuf: *Fts5Buffer, pIter: *Fts5DoclistIter) void {
    @memset(@as([*]u8, @ptrCast(pIter))[0..@sizeOf(Fts5DoclistIter)], 0);
    if (pBuf.n > 0) {
        pIter.aPoslist = pBuf.p;
        pIter.aEof = pBuf.p.? + @as(usize, @intCast(pBuf.n));
        fts5DoclistIterNext(pIter);
    }
}

// ===========================================================================
// fts5BufferSwap
// ===========================================================================
fn fts5BufferSwap(p1: *Fts5Buffer, p2: *Fts5Buffer) void {
    const tmp = p1.*;
    p1.* = p2.*;
    p2.* = tmp;
}

// ===========================================================================
// fts5NextRowid
// ===========================================================================
fn fts5NextRowid(pBuf: *Fts5Buffer, piOff: *c_int, piRowid: *i64) void {
    const i = piOff.*;
    if (i >= pBuf.n) {
        piOff.* = -1;
    } else {
        var iVal: u64 = undefined;
        piOff.* = i + sqlite3Fts5GetVarint(pBuf.p.? + @as(usize, @intCast(i)), &iVal);
        piRowid.* +%= @bitCast(iVal);
    }
}

// ===========================================================================
// fts5MergeRowidLists
// ===========================================================================
fn fts5MergeRowidLists(p: *Fts5IndexS, p1: *Fts5Buffer, nBuf: c_int, aBuf: [*]Fts5Buffer) void {
    _ = nBuf;
    var iA1: c_int = 0;
    var iA2: c_int = 0;
    var iRowid1: i64 = 0;
    var iRowid2: i64 = 0;
    var iOut: i64 = 0;
    const p2 = &aBuf[0];
    var out: Fts5Buffer = std.mem.zeroes(Fts5Buffer);

    _ = sqlite3Fts5BufferSize(&p.rc, &out, @bitCast(p1.n + p2.n));
    if (p.rc != 0) return;

    fts5NextRowid(p1, &iA1, &iRowid1);
    fts5NextRowid(p2, &iA2, &iRowid2);
    while (iA1 >= 0 or iA2 >= 0) {
        if (iA1 >= 0 and (iA2 < 0 or iRowid1 < iRowid2)) {
            fts5BufferSafeAppendVarint(&out, iRowid1 - iOut);
            iOut = iRowid1;
            fts5NextRowid(p1, &iA1, &iRowid1);
        } else {
            fts5BufferSafeAppendVarint(&out, iRowid2 - iOut);
            iOut = iRowid2;
            if (iA1 >= 0 and iRowid1 == iRowid2) {
                fts5NextRowid(p1, &iA1, &iRowid1);
            }
            fts5NextRowid(p2, &iA2, &iRowid2);
        }
    }

    fts5BufferSwap(&out, p1);
    fts5BufferFree(&out);
}

// ===========================================================================
// PrefixMerger (chunk-local struct).
// ===========================================================================
const PrefixMerger = extern struct {
    iter: Fts5DoclistIter, // Doclist iterator
    iPos: i64, // For iterating through a position list
    iOff: c_int,
    aPos: ?[*]u8,
    pNext: ?*PrefixMerger, // Next in docid/poslist order
};

inline fn fts5PrefixMergerNextPosition(pm: *PrefixMerger) void {
    _ = sqlite3Fts5PoslistNext64(pm.aPos, pm.iter.nPoslist, &pm.iOff, &pm.iPos);
}

// ===========================================================================
// fts5PrefixMergerInsertByRowid
// ===========================================================================
fn fts5PrefixMergerInsertByRowid(ppHead: *?*PrefixMerger, pm: *PrefixMerger) void {
    if (pm.iter.aPoslist != null) {
        var pp: *?*PrefixMerger = ppHead;
        while (pp.* != null and pm.iter.iRowid > pp.*.?.iter.iRowid) {
            pp = &pp.*.?.pNext;
        }
        pm.pNext = pp.*;
        pp.* = pm;
    }
}

// ===========================================================================
// fts5PrefixMergerInsertByPosition
// ===========================================================================
fn fts5PrefixMergerInsertByPosition(ppHead: *?*PrefixMerger, pm: *PrefixMerger) void {
    if (pm.iPos >= 0) {
        var pp: *?*PrefixMerger = ppHead;
        while (pp.* != null and pm.iPos > pp.*.?.iPos) {
            pp = &pp.*.?.pNext;
        }
        pm.pNext = pp.*;
        pp.* = pm;
    }
}

// ===========================================================================
// fts5MergePrefixLists
// ===========================================================================
fn fts5MergePrefixLists(p: *Fts5IndexS, p1: *Fts5Buffer, nBuf: c_int, aBuf: [*]Fts5Buffer) void {
    const nMergeNlist: usize = @intCast(FTS5_MERGE_NLIST);
    var aMerger: [nMergeNlist]PrefixMerger = undefined;
    var pHead: ?*PrefixMerger = null;
    var i: c_int = undefined;
    var nOut: c_int = 0;
    var out: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    var tmp: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    var iLastRowid: i64 = 0;

    // Initialize a doclist-iterator for each input buffer.
    @memset(@as([*]u8, @ptrCast(&aMerger))[0 .. @sizeOf(PrefixMerger) * @as(usize, @intCast(nBuf + 1))], 0);
    pHead = &aMerger[@intCast(nBuf)];
    fts5DoclistIterInit(p1, &pHead.?.iter);
    i = 0;
    while (i < nBuf) : (i += 1) {
        fts5DoclistIterInit(&aBuf[@intCast(i)], &aMerger[@intCast(i)].iter);
        fts5PrefixMergerInsertByRowid(&pHead, &aMerger[@intCast(i)]);
        nOut += aBuf[@intCast(i)].n;
    }
    if (nOut == 0) return;
    nOut += p1.n + 9 + 10 * nBuf;

    if (sqlite3Fts5BufferSize(&p.rc, &out, @bitCast(nOut)) != 0) return;

    while (pHead != null) {
        // fts5MergeAppendDocid macro, inlined.
        fts5BufferSafeAppendVarint(&out, @bitCast(@as(u64, @bitCast(pHead.?.iter.iRowid)) -% @as(u64, @bitCast(iLastRowid))));
        iLastRowid = pHead.?.iter.iRowid;

        if (pHead.?.pNext != null and iLastRowid == pHead.?.pNext.?.iter.iRowid) {
            // Merge data from two or more poslists.
            var iPrev: i64 = 0;
            var nTmp: c_int = FTS5_DATA_ZERO_PADDING;
            var nMerge: c_int = 0;
            var pSave: ?*PrefixMerger = pHead;
            var pThis: ?*PrefixMerger = null;
            var nTail: c_int = 0;

            pHead = null;
            while (pSave != null and pSave.?.iter.iRowid == iLastRowid) {
                const pNext = pSave.?.pNext;
                pSave.?.iOff = 0;
                pSave.?.iPos = 0;
                pSave.?.aPos = pSave.?.iter.aPoslist.? + @as(usize, @intCast(pSave.?.iter.nSize));
                fts5PrefixMergerNextPosition(pSave.?);
                nTmp += pSave.?.iter.nPoslist + 10;
                nMerge += 1;
                fts5PrefixMergerInsertByPosition(&pHead, pSave.?);
                pSave = pNext;
            }

            if (pHead == null or pHead.?.pNext == null) {
                _ = fts5IndexCorruptIdx(p);
                break;
            }

            if (sqlite3Fts5BufferSize(&p.rc, &tmp, @bitCast(nTmp + nMerge * 10)) != 0) {
                break;
            }
            fts5BufferZero(&tmp);

            pThis = pHead;
            pHead = pThis.?.pNext;
            sqlite3Fts5PoslistSafeAppend(&tmp, &iPrev, pThis.?.iPos);
            fts5PrefixMergerNextPosition(pThis.?);
            fts5PrefixMergerInsertByPosition(&pHead, pThis.?);

            while (pHead.?.pNext != null) {
                pThis = pHead;
                if (pThis.?.iPos != iPrev) {
                    sqlite3Fts5PoslistSafeAppend(&tmp, &iPrev, pThis.?.iPos);
                }
                fts5PrefixMergerNextPosition(pThis.?);
                pHead = pThis.?.pNext;
                fts5PrefixMergerInsertByPosition(&pHead, pThis.?);
            }

            if (pHead.?.iPos != iPrev) {
                sqlite3Fts5PoslistSafeAppend(&tmp, &iPrev, pHead.?.iPos);
            }
            nTail = pHead.?.iter.nPoslist - pHead.?.iOff;

            // WRITEPOSLISTSIZE
            if (tmp.n + nTail > nTmp - FTS5_DATA_ZERO_PADDING) {
                if (p.rc == SQLITE_OK) _ = fts5IndexCorruptIdx(p);
                break;
            }
            fts5BufferSafeAppendVarint(&out, @as(i64, tmp.n + nTail) * 2);
            fts5BufferSafeAppendBlob(&out, tmp.p.?, tmp.n);
            if (nTail > 0) {
                fts5BufferSafeAppendBlob(&out, pHead.?.aPos.? + @as(usize, @intCast(pHead.?.iOff)), nTail);
            }

            pHead = pSave;
            i = 0;
            while (i < nBuf + 1) : (i += 1) {
                const pX = &aMerger[@intCast(i)];
                if (pX.iter.aPoslist != null and pX.iter.iRowid == iLastRowid) {
                    fts5DoclistIterNext(&pX.iter);
                    fts5PrefixMergerInsertByRowid(&pHead, pX);
                }
            }
        } else {
            // Copy poslist from pHead to output.
            const pThis = pHead.?;
            const pI = &pThis.iter;
            fts5BufferSafeAppendBlob(&out, pI.aPoslist.?, pI.nPoslist + pI.nSize);
            fts5DoclistIterNext(pI);
            pHead = pThis.pNext;
            fts5PrefixMergerInsertByRowid(&pHead, pThis);
        }
    }

    fts5BufferFree(p1);
    fts5BufferFree(&tmp);
    _ = memset(out.p.? + @as(usize, @intCast(out.n)), 0, FTS5_DATA_ZERO_PADDING_USZ);
    p1.* = out;
}

// ============================ CHUNK 8 ============================
// ===========================================================================
// CHUNK 8: fts5_index.c lines ~6339-7398 (visit/tokendata, write, open/close).
// ===========================================================================

const FTS5_MERGE_NLIST: c_int = 16; // local #define from fts5_index.c

/// struct TokendataSetupCtx.
const TokendataSetupCtx = extern struct {
    pT: ?*Fts5TokenDataIter, // Object being populated with mappings
    iTermOff: c_int, // Offset of current term in terms.p[]
    nTermByte: c_int, // Size of current term in bytes
};

/// struct PrefixSetupCtx.
const PrefixSetupCtx = extern struct {
    xMerge: ?*const fn (*Fts5IndexS, *Fts5Buffer, c_int, [*]Fts5Buffer) void,
    xAppend: ?*const fn (*Fts5IndexS, u64, ?*Fts5Iter, *Fts5Buffer) void,
    iLastRowid: i64,
    nMerge: c_int,
    aBuf: ?[*]Fts5Buffer,
    nBuf: c_int,
    doclist: Fts5Buffer,
    pTokendata: ?*TokendataSetupCtx,
};

// ===========================================================================
// fts5VisitEntries() — gather entries from the index, invoking xVisit per term.
// ===========================================================================
fn fts5VisitEntries(
    p: *Fts5IndexS,
    pColset: ?*Fts5Colset,
    pToken: [*]u8,
    nToken: c_int,
    bPrefix: c_int,
    xVisit: *const fn (*Fts5IndexS, ?*anyopaque, *Fts5Iter, ?[*]const u8, c_int) void,
    pCtx: ?*anyopaque,
) c_int {
    const flags: c_int = (if (bPrefix != 0) FTS5INDEX_QUERY_SCAN else 0) |
        FTS5INDEX_QUERY_SKIPEMPTY |
        FTS5INDEX_QUERY_NOOUTPUT;
    var p1: ?*Fts5Iter = null;
    var bNewTerm: c_int = 1;
    const pStruct = fts5StructureRead(p);

    fts5MultiIterNew(p, pStruct, flags, pColset, pToken, nToken, -1, 0, &p1);
    fts5IterSetOutputCb(&p.rc, p1);
    while (fts5MultiIterEof(p, p1.?) == 0) : (fts5MultiIterNext2(p, p1.?, &bNewTerm)) {
        const iter = p1.?;
        const pSeg: *Fts5SegIter = iterSeg(iter, iter.aFirst.?[1].iFirst);
        var nNew: c_int = 0;
        var pNew: ?[*]const u8 = null;

        iter.xSetOutputs.?(iter, pSeg);
        if (p.rc != 0) break;

        if (bNewTerm != 0) {
            nNew = pSeg.term.n;
            pNew = pSeg.term.p;
            if (nNew < nToken or memcmp(pToken, pNew, @intCast(nToken)) != 0) break;
        }

        xVisit(p, pCtx, iter, pNew, nNew);
    }
    fts5MultiIterFree(p1);

    fts5StructureRelease(pStruct);
    return p.rc;
}

// ===========================================================================
// fts5TokendataMerge — merge two sorted Fts5TokenDataMap arrays into aOut.
// ===========================================================================
fn fts5TokendataMerge(
    a1: [*]Fts5TokenDataMap,
    n1: c_int,
    a2: [*]Fts5TokenDataMap,
    n2: c_int,
    aOut: [*]Fts5TokenDataMap,
) void {
    var iA1: c_int = 0;
    var iA2: c_int = 0;

    while (iA1 < n1 or iA2 < n2) {
        const pOut: *Fts5TokenDataMap = &aOut[@intCast(iA1 + iA2)];
        if (iA2 >= n2 or (iA1 < n1 and (a1[@intCast(iA1)].iRowid < a2[@intCast(iA2)].iRowid or
            (a1[@intCast(iA1)].iRowid == a2[@intCast(iA2)].iRowid and a1[@intCast(iA1)].iPos <= a2[@intCast(iA2)].iPos)))) {
            _ = memcpy(pOut, &a1[@intCast(iA1)], @sizeOf(Fts5TokenDataMap));
            iA1 += 1;
        } else {
            _ = memcpy(pOut, &a2[@intCast(iA2)], @sizeOf(Fts5TokenDataMap));
            iA2 += 1;
        }
    }
}

// ===========================================================================
// fts5TokendataIterAppendMap — append (rowid,pos)->token mapping to pT->aMap.
// ===========================================================================
fn fts5TokendataIterAppendMap(
    p: *Fts5IndexS,
    pT: *Fts5TokenDataIter,
    iIter: c_int,
    nByte: c_int,
    iRowid: i64,
    iPos: i64,
) void {
    if (p.rc == SQLITE_OK) {
        if (pT.nMap == pT.nMapAlloc) {
            const nNew: i64 = if (pT.nMapAlloc != 0) pT.nMapAlloc * 2 else 64;
            const nAlloc: i64 = nNew * @sizeOf(Fts5TokenDataMap);
            const aNew: ?[*]Fts5TokenDataMap = @ptrCast(@alignCast(sqlite3_realloc64(pT.aMap, @bitCast(nAlloc))));
            if (aNew == null) {
                p.rc = SQLITE_NOMEM;
                return;
            }
            pT.aMap = aNew;
            pT.nMapAlloc = nNew;
        }

        const m: *Fts5TokenDataMap = &pT.aMap.?[@intCast(pT.nMap)];
        m.iRowid = iRowid;
        m.iPos = iPos;
        m.iIter = iIter;
        m.nByte = nByte;
        pT.nMap += 1;
    }
}

// ===========================================================================
// fts5TokendataIterSortMap — bottom-up merge sort of pT->aMap.
// ===========================================================================
fn fts5TokendataIterSortMap(p: *Fts5IndexS, pT: *Fts5TokenDataIter) void {
    const nByte: i64 = pT.nMap * @sizeOf(Fts5TokenDataMap);

    const aTmp: ?[*]Fts5TokenDataMap = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&p.rc, nByte)));
    if (aTmp) |tmp| {
        var a1: [*]Fts5TokenDataMap = pT.aMap.?;
        var a2: [*]Fts5TokenDataMap = tmp;

        var nHalf: i64 = 1;
        while (nHalf < pT.nMap) : (nHalf = nHalf * 2) {
            var iA1: c_int = 0;
            while (iA1 < pT.nMap) : (iA1 += @intCast(nHalf * 2)) {
                const n1: c_int = MIN(c_int, @intCast(nHalf), @as(c_int, @intCast(pT.nMap)) - iA1);
                const n2: c_int = MIN(c_int, @intCast(nHalf), @as(c_int, @intCast(pT.nMap)) - iA1 - n1);
                fts5TokendataMerge(a1 + @as(usize, @intCast(iA1)), n1, a1 + @as(usize, @intCast(iA1 + n1)), n2, a2 + @as(usize, @intCast(iA1)));
            }
            const t = a1;
            a1 = a2;
            a2 = t;
        }

        if (a1 != pT.aMap.?) {
            _ = memcpy(pT.aMap.?, a1, @intCast(pT.nMap * @sizeOf(Fts5TokenDataMap)));
        }
        sqlite3_free(tmp);
    }
}

// ===========================================================================
// fts5TokendataIterDelete — free an Fts5TokenDataIter and contents.
// ===========================================================================
fn fts5TokendataIterDelete(pSet: ?*Fts5TokenDataIter) void {
    if (pSet) |s| {
        var ii: c_int = 0;
        while (ii < s.nIter) : (ii += 1) {
            fts5MultiIterFree(tokenDataIterApIter(s, ii).*);
        }
        sqlite3Fts5BufferFree(&s.terms);
        sqlite3_free(s.aPoslistReader);
        sqlite3_free(s.aMap);
        sqlite3_free(s);
    }
}

// ===========================================================================
// prefixIterSetupTokendataCb — fts5VisitEntries callback collecting token map.
// ===========================================================================
fn prefixIterSetupTokendataCb(
    p: *Fts5IndexS,
    pCtx: ?*anyopaque,
    p1: *Fts5Iter,
    pNew: ?[*]const u8,
    nNew: c_int,
) void {
    const pSetup: *TokendataSetupCtx = @ptrCast(@alignCast(pCtx.?));
    var iPosOff: c_int = 0;
    var iPos: i64 = 0;

    if (pNew) |np| {
        pSetup.nTermByte = nNew - 1;
        pSetup.iTermOff = pSetup.pT.?.terms.n;
        sqlite3Fts5BufferAppendBlob(&p.rc, &pSetup.pT.?.terms, @intCast(nNew - 1), np + 1);
    }

    while (sqlite3Fts5PoslistNext64(p1.base.pData, p1.base.nData, &iPosOff, &iPos) == 0) {
        fts5TokendataIterAppendMap(
            p,
            pSetup.pT.?,
            pSetup.iTermOff,
            pSetup.nTermByte,
            p1.base.iRowid,
            iPos,
        );
    }
}

// ===========================================================================
// prefixIterSetupCb — fts5VisitEntries callback used by fts5SetupPrefixIter.
// ===========================================================================
fn prefixIterSetupCb(
    p: *Fts5IndexS,
    pCtx: ?*anyopaque,
    p1: *Fts5Iter,
    pNew: ?[*]const u8,
    nNew: c_int,
) void {
    const pSetup: *PrefixSetupCtx = @ptrCast(@alignCast(pCtx.?));
    const nMerge = pSetup.nMerge;

    if (p1.base.nData > 0) {
        if (p1.base.iRowid <= pSetup.iLastRowid and pSetup.doclist.n > 0) {
            var i: c_int = 0;
            while (p.rc == SQLITE_OK and pSetup.doclist.n != 0) : (i += 1) {
                const iA1 = i * nMerge;
                var iStore: c_int = iA1;
                while (iStore < iA1 + nMerge) : (iStore += 1) {
                    if (pSetup.aBuf.?[@intCast(iStore)].n == 0) {
                        fts5BufferSwap(&pSetup.doclist, &pSetup.aBuf.?[@intCast(iStore)]);
                        sqlite3Fts5BufferZero(&pSetup.doclist);
                        break;
                    }
                }
                if (iStore == iA1 + nMerge) {
                    pSetup.xMerge.?(p, &pSetup.doclist, nMerge, pSetup.aBuf.? + @as(usize, @intCast(iA1)));
                    iStore = iA1;
                    while (iStore < iA1 + nMerge) : (iStore += 1) {
                        sqlite3Fts5BufferZero(&pSetup.aBuf.?[@intCast(iStore)]);
                    }
                }
            }
            pSetup.iLastRowid = 0;
        }

        pSetup.xAppend.?(
            p,
            @as(u64, @bitCast(p1.base.iRowid)) -% @as(u64, @bitCast(pSetup.iLastRowid)),
            p1,
            &pSetup.doclist,
        );
        pSetup.iLastRowid = p1.base.iRowid;
    }

    if (pSetup.pTokendata) |ptd| {
        prefixIterSetupTokendataCb(p, @ptrCast(ptd), p1, pNew, nNew);
    }
}

// ===========================================================================
// fts5SetupPrefixIter — build a merged iterator over a prefix index.
// ===========================================================================
fn fts5SetupPrefixIter(
    p: *Fts5IndexS,
    bDesc: c_int,
    iIdx: c_int,
    pToken: [*]u8,
    nToken: c_int,
    pColset: ?*Fts5Colset,
    ppIter: *?*Fts5Iter,
) void {
    var pStruct: ?*Fts5Structure = undefined;
    var s: PrefixSetupCtx = undefined;
    var s2: TokendataSetupCtx = undefined;

    @memset(@as([*]u8, @ptrCast(&s))[0..@sizeOf(PrefixSetupCtx)], 0);
    @memset(@as([*]u8, @ptrCast(&s2))[0..@sizeOf(TokendataSetupCtx)], 0);

    s.nMerge = 1;
    s.iLastRowid = 0;
    s.nBuf = 32;
    if (iIdx == 0 and
        p.pConfig.?.eDetail == FTS5_DETAIL_FULL and
        p.pConfig.?.bPrefixInsttoken != 0)
    {
        s.pTokendata = &s2;
        s2.pT = @ptrCast(@alignCast(fts5IdxMalloc(p, SZ_FTS5TOKENDATAITER(1))));
    }

    if (p.pConfig.?.eDetail == FTS5_DETAIL_NONE) {
        s.xMerge = &fts5MergeRowidLists;
        s.xAppend = &fts5AppendRowid;
    } else {
        s.nMerge = FTS5_MERGE_NLIST - 1;
        s.nBuf = s.nMerge * 8; // Sufficient to merge (16^8)==(2^32) lists
        s.xMerge = &fts5MergePrefixLists;
        s.xAppend = &fts5AppendPoslist;
    }

    s.aBuf = @ptrCast(@alignCast(fts5IdxMalloc(p, @sizeOf(Fts5Buffer) * @as(i64, s.nBuf))));
    pStruct = fts5StructureRead(p);

    if (p.rc == SQLITE_OK) {
        const pCtx: ?*anyopaque = @ptrCast(&s);
        var i: c_int = undefined;
        var pData: ?*Fts5Data = undefined;

        // If iIdx is non-zero, it is a prefix-index for prefixes 1 char longer
        // than the prefix being queried. Extract the prefix itself from the
        // main term index here.
        if (iIdx != 0) {
            pToken[0] = FTS5_MAIN_PREFIX;
            _ = fts5VisitEntries(p, pColset, pToken, nToken, 0, &prefixIterSetupCb, pCtx);
        }

        pToken[0] = FTS5_MAIN_PREFIX +% @as(u8, @intCast(iIdx));
        _ = fts5VisitEntries(p, pColset, pToken, nToken, 1, &prefixIterSetupCb, pCtx);

        i = 0;
        while (i < s.nBuf) : (i += s.nMerge) {
            var iFree: c_int = undefined;
            if (p.rc == SQLITE_OK) {
                s.xMerge.?(p, &s.doclist, s.nMerge, s.aBuf.? + @as(usize, @intCast(i)));
            }
            iFree = i;
            while (iFree < i + s.nMerge) : (iFree += 1) {
                sqlite3Fts5BufferFree(&s.aBuf.?[@intCast(iFree)]);
            }
        }

        pData = @ptrCast(@alignCast(fts5IdxMalloc(p, @as(i64, @sizeOf(Fts5Data)) +
            @as(i64, s.doclist.n) + FTS5_DATA_ZERO_PADDING)));
        if (pData) |pd| {
            const aData: [*]Fts5Data = @ptrCast(pd);
            pd.p = @ptrCast(&aData[1]);
            pd.nn = s.doclist.n;
            pd.szLeaf = s.doclist.n;
            if (s.doclist.n != 0) _ = memcpy(pd.p, s.doclist.p, @intCast(s.doclist.n));
            fts5MultiIterNew2(p, pd, bDesc, ppIter);
        }

        if (p.rc == SQLITE_OK and s.pTokendata != null) {
            fts5TokendataIterSortMap(p, s2.pT.?);
            ppIter.*.?.pTokenDataIter = s2.pT;
            s2.pT = null;
        }
    }

    fts5TokendataIterDelete(s2.pT);
    sqlite3Fts5BufferFree(&s.doclist);
    fts5StructureRelease(pStruct);
    sqlite3_free(s.aBuf);
}

// ===========================================================================
// sqlite3Fts5IndexBeginWrite — begin write for document iRowid.
// ===========================================================================
export fn sqlite3Fts5IndexBeginWrite(p: *Fts5IndexS, bDelete: c_int, iRowid: i64) callconv(.c) c_int {
    // Allocate the hash table if it has not already been allocated
    if (p.pHash == null) {
        p.rc = sqlite3Fts5HashNew(p.pConfig.?, &p.pHash, &p.nPendingData);
    }

    // Flush the hash table to disk if required
    if (iRowid < p.iWriteRowid or
        (iRowid == p.iWriteRowid and p.bDelete == 0) or
        (p.nPendingData > p.pConfig.?.nHashSize))
    {
        fts5IndexFlush(p);
    }

    p.iWriteRowid = iRowid;
    p.bDelete = bDelete;
    if (bDelete == 0) {
        p.nPendingRow += 1;
    }
    return fts5IndexReturn(p);
}

// ===========================================================================
// sqlite3Fts5IndexSync — commit data to disk.
// ===========================================================================
export fn sqlite3Fts5IndexSync(p: *Fts5IndexS) callconv(.c) c_int {
    fts5IndexFlush(p);
    fts5IndexCloseReader(p);
    return fts5IndexReturn(p);
}

// ===========================================================================
// sqlite3Fts5IndexRollback — discard in-memory data and caches.
// ===========================================================================
export fn sqlite3Fts5IndexRollback(p: *Fts5IndexS) callconv(.c) c_int {
    fts5IndexCloseReader(p);
    fts5IndexDiscardData(p);
    fts5StructureInvalidate(p);
    return fts5IndexReturn(p);
}

// ===========================================================================
// sqlite3Fts5IndexReinit — populate an empty %_data table with initial state.
// ===========================================================================
export fn sqlite3Fts5IndexReinit(p: *Fts5IndexS) callconv(.c) c_int {
    // union { Fts5Structure sFts; u8 tmpSpace[SZ_FTS5STRUCTURE(1)]; } uFts;
    var tmpSpace: [@intCast(SZ_FTS5STRUCTURE(1))]u8 align(@alignOf(Fts5Structure)) = undefined;
    fts5StructureInvalidate(p);
    fts5IndexDiscardData(p);
    const pTmp: *Fts5Structure = @ptrCast(@alignCast(&tmpSpace));
    @memset(tmpSpace[0..], 0);
    if (p.pConfig.?.bContentlessDelete != 0) {
        pTmp.nOriginCntr = 1;
    }
    fts5DataWrite(p, FTS5_AVERAGES_ROWID, "", 0);
    fts5StructureWrite(p, pTmp);
    return fts5IndexReturn(p);
}

// ===========================================================================
// sqlite3Fts5IndexOpen — open (and optionally create) the %_data/%_idx tables.
// ===========================================================================
export fn sqlite3Fts5IndexOpen(
    pConfig: *Fts5Config,
    bCreate: c_int,
    pp: *?*Fts5IndexS,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const p: ?*Fts5IndexS = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5IndexS))));

    pp.* = p;
    if (rc == SQLITE_OK) {
        const pi = p.?;
        pi.pConfig = pConfig;
        pi.nWorkUnit = FTS5_WORK_UNIT;
        pi.zDataTbl = sqlite3Fts5Mprintf(&rc, "%s_data", pConfig.zName);
        if (pi.zDataTbl != null and bCreate != 0) {
            rc = sqlite3Fts5CreateTable(
                pConfig,
                "data",
                "id INTEGER PRIMARY KEY, block BLOB",
                0,
                pzErr,
            );
            if (rc == SQLITE_OK) {
                rc = sqlite3Fts5CreateTable(
                    pConfig,
                    "idx",
                    "segid, term, pgno, PRIMARY KEY(segid, term)",
                    1,
                    pzErr,
                );
            }
            if (rc == SQLITE_OK) {
                rc = sqlite3Fts5IndexReinit(pi);
            }
        }
    }

    if (rc != 0) {
        _ = sqlite3Fts5IndexClose(p.?);
        pp.* = null;
    }
    return rc;
}

// ===========================================================================
// sqlite3Fts5IndexClose — close a handle opened by sqlite3Fts5IndexOpen().
// ===========================================================================
export fn sqlite3Fts5IndexClose(p: ?*Fts5IndexS) callconv(.c) c_int {
    const rc: c_int = SQLITE_OK;
    if (p) |pi| {
        fts5StructureInvalidate(pi);
        _ = sqlite3_finalize(pi.pWriter);
        _ = sqlite3_finalize(pi.pDeleter);
        _ = sqlite3_finalize(pi.pIdxWriter);
        _ = sqlite3_finalize(pi.pIdxDeleter);
        _ = sqlite3_finalize(pi.pIdxSelect);
        _ = sqlite3_finalize(pi.pIdxNextSelect);
        _ = sqlite3_finalize(pi.pDataVersion);
        _ = sqlite3_finalize(pi.pDeleteFromIdx);
        sqlite3Fts5HashFree(pi.pHash);
        sqlite3_free(pi.zDataTbl);
        sqlite3_free(pi);
    }
    return rc;
}

// ===========================================================================
// sqlite3Fts5IndexCharlenToBytelen — byte length of the nChar-char prefix.
// ===========================================================================
export fn sqlite3Fts5IndexCharlenToBytelen(
    p: [*]const u8,
    nByte: c_int,
    nChar: c_int,
) callconv(.c) c_int {
    var n: c_int = 0;
    var i: c_int = 0;
    while (i < nChar) : (i += 1) {
        if (n >= nByte) return 0; // fewer than nChar chars
        const c = p[@intCast(n)];
        n += 1;
        if (c >= 0xc0) {
            if (n >= nByte) return 0;
            while ((p[@intCast(n)] & 0xc0) == 0x80) {
                n += 1;
                if (n >= nByte) {
                    if (i + 1 == nChar) break;
                    return 0;
                }
            }
        }
    }
    return n;
}

// ===========================================================================
// fts5IndexCharlen — number of unicode characters in a UTF-8 string.
// ===========================================================================
fn fts5IndexCharlen(pIn: [*]const u8, nIn: c_int) c_int {
    var nChar: c_int = 0;
    var i: c_int = 0;
    while (i < nIn) {
        const c = pIn[@intCast(i)];
        i += 1;
        if (c >= 0xc0) {
            while (i < nIn and (pIn[@intCast(i)] & 0xc0) == 0x80) i += 1;
        }
        nChar += 1;
    }
    return nChar;
}

// ===========================================================================
// sqlite3Fts5IndexWrite — insert/remove a token to/from the index hash.
// ===========================================================================
export fn sqlite3Fts5IndexWrite(
    p: *Fts5IndexS,
    iCol: c_int,
    iPos: c_int,
    pToken: [*]const u8,
    nToken: c_int,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pConfig: *Fts5Config = p.pConfig.?;

    // Add the entry to the main terms index.
    rc = sqlite3Fts5HashWrite(
        p.pHash.?,
        p.iWriteRowid,
        iCol,
        iPos,
        FTS5_MAIN_PREFIX,
        pToken,
        nToken,
    );

    var i: c_int = 0;
    while (i < pConfig.nPrefix and rc == SQLITE_OK) : (i += 1) {
        const nChar: c_int = pConfig.aPrefix.?[@intCast(i)];
        const nByte: c_int = sqlite3Fts5IndexCharlenToBytelen(pToken, nToken, nChar);
        if (nByte != 0) {
            rc = sqlite3Fts5HashWrite(
                p.pHash.?,
                p.iWriteRowid,
                iCol,
                iPos,
                FTS5_MAIN_PREFIX +% @as(u8, @intCast(i + 1)),
                pToken,
                nByte,
            );
        }
    }

    return rc;
}

// ===========================================================================
// fts5IsTokendataPrefix — does pBuf match the token pToken/nToken?
// ===========================================================================
fn fts5IsTokendataPrefix(
    pBuf: *Fts5Buffer,
    pToken: [*]const u8,
    nToken: c_int,
) c_int {
    return @intFromBool(pBuf.n >= nToken and
        0 == memcmp(pBuf.p, pToken, @intCast(nToken)) and
        (pBuf.n == nToken or pBuf.p.?[@intCast(nToken)] == 0x00));
}

// ===========================================================================
// fts5SegIterSetEOF — force a segment-iterator to EOF.
// ===========================================================================
fn fts5SegIterSetEOF(pSeg: *Fts5SegIter) void {
    fts5DataRelease(pSeg.pLeaf);
    pSeg.pLeaf = null;
}

// ===========================================================================
// fts5IterClose — close an Fts5IndexIter (cast of Fts5Iter).
// ===========================================================================
fn fts5IterClose(pIndexIter: ?*Fts5IndexIter) void {
    if (pIndexIter) |ii| {
        const pIter: *Fts5Iter = @ptrCast(@alignCast(ii));
        const pIndex = pIter.pIndex.?;
        fts5TokendataIterDelete(pIter.pTokenDataIter);
        fts5MultiIterFree(pIter);
        fts5IndexCloseReader(pIndex);
    }
}

// ===========================================================================
// fts5AppendTokendataIter — append pAppend to pIn, growing as needed.
// ===========================================================================
fn fts5AppendTokendataIter(
    p: *Fts5IndexS,
    pIn: ?*Fts5TokenDataIter,
    pAppend: *Fts5Iter,
) ?*Fts5TokenDataIter {
    var pRet: ?*Fts5TokenDataIter = pIn;

    if (p.rc == SQLITE_OK) {
        if (pIn == null or pIn.?.nIter == pIn.?.nIterAlloc) {
            const nAlloc: i64 = if (pIn) |pi| pi.nIterAlloc * 2 else 16;
            const nByte: i64 = SZ_FTS5TOKENDATAITER(nAlloc + 1);
            const pNew: ?*Fts5TokenDataIter = @ptrCast(@alignCast(sqlite3_realloc64(pIn, @bitCast(nByte))));

            if (pNew == null) {
                p.rc = SQLITE_NOMEM;
            } else {
                if (pIn == null) @memset(@as([*]u8, @ptrCast(pNew.?))[0..@intCast(nByte)], 0);
                pRet = pNew;
                pNew.?.nIterAlloc = nAlloc;
            }
        }
    }
    if (p.rc != 0) {
        fts5IterClose(@ptrCast(@alignCast(pAppend)));
    } else {
        const r = pRet.?;
        tokenDataIterApIter(r, @intCast(r.nIter)).* = pAppend;
        r.nIter += 1;
    }

    return pRet;
}

// ===========================================================================
// fts5IterSetOutputsTokendata — set output vars for a tokendata=1 iterator.
// ===========================================================================
fn fts5IterSetOutputsTokendata(pIter: *Fts5Iter) void {
    var ii: c_int = 0;
    var nHit: c_int = 0;
    var iRowid: i64 = SMALLEST_INT64;
    var iMin: c_int = 0;

    const pT: *Fts5TokenDataIter = pIter.pTokenDataIter.?;

    pIter.base.nData = 0;
    pIter.base.pData = null;

    ii = 0;
    while (ii < pT.nIter) : (ii += 1) {
        const p: *Fts5Iter = tokenDataIterApIter(pT, ii).*.?;
        if (p.base.bEof == 0) {
            if (nHit == 0 or p.base.iRowid < iRowid) {
                iRowid = p.base.iRowid;
                nHit = 1;
                pIter.base.pData = p.base.pData;
                pIter.base.nData = p.base.nData;
                iMin = ii;
            } else if (p.base.iRowid == iRowid) {
                nHit += 1;
            }
        }
    }

    if (nHit == 0) {
        pIter.base.bEof = 1;
    } else {
        const eDetail = pIter.pIndex.?.pConfig.?.eDetail;
        pIter.base.bEof = 0;
        pIter.base.iRowid = iRowid;

        if (nHit == 1 and eDetail == FTS5_DETAIL_FULL) {
            fts5TokendataIterAppendMap(pIter.pIndex.?, pT, iMin, 0, iRowid, -1);
        } else if (nHit > 1 and eDetail != FTS5_DETAIL_NONE) {
            var nReader: c_int = 0;
            var nByte: c_int = 0;
            var iPrev: i64 = 0;

            // Allocate array of iterators if not already allocated.
            if (pT.aPoslistReader == null) {
                pT.aPoslistReader = @ptrCast(@alignCast(sqlite3Fts5MallocZero(
                    &pIter.pIndex.?.rc,
                    pT.nIter * (@as(i64, @sizeOf(Fts5PoslistReader)) + @sizeOf(c_int)),
                )));
                if (pT.aPoslistReader == null) return;
                pT.aPoslistToIter = @ptrCast(@alignCast(&pT.aPoslistReader.?[@intCast(pT.nIter)]));
            }

            // Populate an iterator for each poslist that will be merged.
            ii = 0;
            while (ii < pT.nIter) : (ii += 1) {
                const p: *Fts5Iter = tokenDataIterApIter(pT, ii).*.?;
                if (iRowid == p.base.iRowid) {
                    pT.aPoslistToIter.?[@intCast(nReader)] = ii;
                    _ = sqlite3Fts5PoslistReaderInit(
                        p.base.pData,
                        p.base.nData,
                        &pT.aPoslistReader.?[@intCast(nReader)],
                    );
                    nReader += 1;
                    nByte += p.base.nData;
                }
            }

            // Ensure the output buffer is large enough.
            if (fts5BufferGrow(&pIter.pIndex.?.rc, &pIter.poslist, nByte + nHit * 10)) {
                return;
            }

            // Ensure the token-mapping is large enough.
            if (eDetail == FTS5_DETAIL_FULL and pT.nMapAlloc < (pT.nMap + nByte)) {
                const nNew: i64 = (pT.nMapAlloc + nByte) * 2;
                const aNew: ?[*]Fts5TokenDataMap = @ptrCast(@alignCast(sqlite3_realloc64(
                    pT.aMap,
                    @bitCast(nNew * @sizeOf(Fts5TokenDataMap)),
                )));
                if (aNew == null) {
                    pIter.pIndex.?.rc = SQLITE_NOMEM;
                    return;
                }
                pT.aMap = aNew;
                pT.nMapAlloc = nNew;
            }

            pIter.poslist.n = 0;

            while (true) {
                var iMinPos: i64 = LARGEST_INT64;

                // Find smallest position.
                iMin = 0;
                ii = 0;
                while (ii < nReader) : (ii += 1) {
                    const pReader: *Fts5PoslistReader = &pT.aPoslistReader.?[@intCast(ii)];
                    if (pReader.bEof == 0) {
                        if (pReader.iPos < iMinPos) {
                            iMinPos = pReader.iPos;
                            iMin = ii;
                        }
                    }
                }

                // If all readers were at EOF, break.
                if (iMinPos == LARGEST_INT64) break;

                sqlite3Fts5PoslistSafeAppend(&pIter.poslist, &iPrev, iMinPos);
                _ = sqlite3Fts5PoslistReaderNext(&pT.aPoslistReader.?[@intCast(iMin)]);

                if (eDetail == FTS5_DETAIL_FULL) {
                    const m: *Fts5TokenDataMap = &pT.aMap.?[@intCast(pT.nMap)];
                    m.iPos = iMinPos;
                    m.iIter = pT.aPoslistToIter.?[@intCast(iMin)];
                    m.iRowid = iRowid;
                    pT.nMap += 1;
                }
            }

            pIter.base.pData = pIter.poslist.p;
            pIter.base.nData = pIter.poslist.n;
        }
    }
}

// ===========================================================================
// fts5TokendataIterNext — advance a tokendata=1 iterator (optionally seek).
// ===========================================================================
fn fts5TokendataIterNext(pIter: *Fts5Iter, bFrom: c_int, iFrom: i64) void {
    var ii: c_int = 0;
    const pT: *Fts5TokenDataIter = pIter.pTokenDataIter.?;
    const pIndex = pIter.pIndex.?;

    while (ii < pT.nIter) : (ii += 1) {
        const p: *Fts5Iter = tokenDataIterApIter(pT, ii).*.?;
        if (p.base.bEof == 0 and
            (p.base.iRowid == pIter.base.iRowid or (bFrom != 0 and p.base.iRowid < iFrom)))
        {
            fts5MultiIterNext(pIndex, p, bFrom, iFrom);
            while (bFrom != 0 and p.base.bEof == 0 and
                p.base.iRowid < iFrom and
                pIndex.rc == SQLITE_OK)
            {
                fts5MultiIterNext(pIndex, p, 0, 0);
            }
        }
    }

    if (pIndex.rc == SQLITE_OK) {
        fts5IterSetOutputsTokendata(pIter);
    }
}

// ===========================================================================
// fts5TokendataSetTermIfEof — copy pTerm into aSeg[0].term if pIter at EOF.
// ===========================================================================
fn fts5TokendataSetTermIfEof(pIter: ?*Fts5Iter, pTerm: *Fts5Buffer) void {
    if (pIter) |it| {
        if (iterSeg(it, 0).pLeaf == null) {
            fts5BufferSet(&it.pIndex.?.rc, &iterSeg(it, 0).term, pTerm.n, pTerm.p.?);
        }
    }
}

// ===========================================================================
// fts5SetupTokendataIter — set up an iterator for a non-prefix tokendata query.
// ===========================================================================
fn fts5SetupTokendataIter(
    p: *Fts5IndexS,
    pToken: [*]const u8,
    nToken: c_int,
    pColset: ?*Fts5Colset,
) ?*Fts5Iter {
    var pRet: ?*Fts5Iter = null;
    var pSet: ?*Fts5TokenDataIter = null;
    var pStruct: ?*Fts5Structure = null;
    const flags: c_int = FTS5INDEX_QUERY_SCANONETERM | FTS5INDEX_QUERY_SCAN;

    var bSeek: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    var pSmall: ?*Fts5Buffer = null;

    fts5IndexFlush(p);
    pStruct = fts5StructureRead(p);

    while (p.rc == SQLITE_OK) {
        const pPrev: ?*Fts5Iter = if (pSet) |ps| tokenDataIterApIter(ps, @intCast(ps.nIter - 1)).* else null;
        var pNew: ?*Fts5Iter = null;
        var pNewIter: ?*Fts5SegIter = null;
        var pPrevIter: ?*Fts5SegIter = null;

        var iLvl: c_int = undefined;
        var iSeg: c_int = undefined;
        var ii: c_int = undefined;

        pNew = fts5MultiIterAlloc(p, pStruct.?.nSegment);
        if (pSmall) |sm| {
            fts5BufferSet(&p.rc, &bSeek, sm.n, sm.p.?);
            sqlite3Fts5BufferAppendBlob(&p.rc, &bSeek, 1, "\x00");
        } else {
            fts5BufferSet(&p.rc, &bSeek, nToken, pToken);
        }
        if (p.rc != 0) {
            fts5IterClose(@ptrCast(@alignCast(pNew)));
            break;
        }

        pNewIter = iterSeg(pNew.?, 0);
        pPrevIter = if (pPrev) |pp| iterSeg(pp, 0) else null;
        iLvl = 0;
        while (iLvl < pStruct.?.nLevel) : (iLvl += 1) {
            const pLvl = structLevel(pStruct.?, iLvl);
            iSeg = pLvl.nSeg - 1;
            while (iSeg >= 0) : (iSeg -= 1) {
                const pSeg: *Fts5StructureSegment = &pLvl.aSeg.?[@intCast(iSeg)];
                var bDone: c_int = 0;

                if (pPrevIter != null) {
                    if (fts5BufferCompare(pSmall, &pPrevIter.?.term) != 0) {
                        _ = memcpy(pNewIter.?, pPrevIter.?, @sizeOf(Fts5SegIter));
                        @memset(@as([*]u8, @ptrCast(pPrevIter.?))[0..@sizeOf(Fts5SegIter)], 0);
                        bDone = 1;
                    } else if (pPrevIter.?.iEndofDoclist > pPrevIter.?.pLeaf.?.szLeaf) {
                        fts5SegIterNextInit(p, bSeek.p.?, bSeek.n - 1, pSeg, pNewIter.?);
                        bDone = 1;
                    }
                }

                if (bDone == 0) {
                    fts5SegIterSeekInit(p, bSeek.p.?, bSeek.n, flags, pSeg, pNewIter.?);
                }

                if (pPrevIter != null) {
                    if (pPrevIter.?.pTombArray != null) {
                        pNewIter.?.pTombArray = pPrevIter.?.pTombArray;
                        pNewIter.?.pTombArray.?.nRef += 1;
                    }
                } else {
                    fts5SegIterAllocTombstone(p, pNewIter.?);
                }

                pNewIter = @ptrCast(&@as([*]Fts5SegIter, @ptrCast(pNewIter.?))[1]);
                if (pPrevIter != null) pPrevIter = @ptrCast(&@as([*]Fts5SegIter, @ptrCast(pPrevIter.?))[1]);
                if (p.rc != 0) break;
            }
        }
        fts5TokendataSetTermIfEof(pPrev, pSmall.?);

        pNew.?.bSkipEmpty = 1;
        pNew.?.pColset = pColset;
        fts5IterSetOutputCb(&p.rc, pNew);

        // Find the smallest term any segment-iterator points to. Iterator pNew
        // is used for that term. Any iterator pointing to a non-matching term
        // is set to EOF.
        pSmall = null;
        ii = 0;
        while (ii < pNew.?.nSeg) : (ii += 1) {
            const pII: *Fts5SegIter = iterSeg(pNew.?, ii);
            if (0 == fts5IsTokendataPrefix(&pII.term, pToken, nToken)) {
                fts5SegIterSetEOF(pII);
            }
            if (pII.pLeaf != null and (pSmall == null or fts5BufferCompare(pSmall, &pII.term) > 0)) {
                pSmall = &pII.term;
            }
        }

        // If pSmall is still NULL, the new iterator matches no query terms.
        // Delete it and break - all required iterators have been collected.
        if (pSmall == null) {
            fts5IterClose(@ptrCast(@alignCast(pNew)));
            break;
        }

        // Append this iterator to the set and continue.
        pSet = fts5AppendTokendataIter(p, pSet, pNew.?);
    }

    if (p.rc == SQLITE_OK and pSet != null) {
        var ii: c_int = 0;
        while (ii < pSet.?.nIter) : (ii += 1) {
            const pIter: *Fts5Iter = tokenDataIterApIter(pSet.?, ii).*.?;
            var iSeg: c_int = 0;
            while (iSeg < pIter.nSeg) : (iSeg += 1) {
                iterSeg(pIter, iSeg).flags |= FTS5_SEGITER_ONETERM;
            }
            fts5MultiIterFinishSetup(p, pIter);
        }
    }

    if (p.rc == SQLITE_OK) {
        pRet = fts5MultiIterAlloc(p, 0);
    }
    if (pRet) |r| {
        r.nSeg = 0;
        r.pTokenDataIter = pSet;
        if (pSet != null) {
            fts5IterSetOutputsTokendata(r);
        } else {
            r.base.bEof = 1;
        }
    } else {
        fts5TokendataIterDelete(pSet);
    }

    fts5StructureRelease(pStruct);
    sqlite3Fts5BufferFree(&bSeek);
    return pRet;
}

// ============================ CHUNK 9 ============================
// ===========================================================================
// sqlite3Fts5IndexQuery and friends.
// ===========================================================================

export fn sqlite3Fts5IndexQuery(
    p: *Fts5IndexS,
    pToken: ?[*]const u8,
    nToken: c_int,
    flags: c_int,
    pColset: ?*Fts5Colset,
    ppIter: *?*Fts5IndexIter,
) callconv(.c) c_int {
    const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));
    var pRet: ?*Fts5Iter = null;
    var buf: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };

    if (sqlite3Fts5BufferSize(&p.rc, &buf, @bitCast(nToken + 1)) == 0) {
        var iIdx: c_int = 0; // Index to search
        var iPrefixIdx: c_int = 0; // +1 prefix index
        var bTokendata: c_int = pConfig.bTokendata;
        if (nToken > 0) _ = memcpy(buf.p.? + 1, pToken, @intCast(nToken));

        // The NOTOKENDATA flag is set when each token in a tokendata=1 table
        // should be treated individually, instead of merging all those with
        // a common prefix into a single entry.
        if (flags & (FTS5INDEX_QUERY_NOTOKENDATA | FTS5INDEX_QUERY_SCAN) != 0) {
            bTokendata = 0;
        }

        // Figure out which index to search and set iIdx accordingly.
        var bDoneIdx = false;
        if (config.sqlite_debug) {
            if (pConfig.bPrefixIndex == 0 or (flags & FTS5INDEX_QUERY_TEST_NOIDX) != 0) {
                iIdx = 1 + pConfig.nPrefix;
                bDoneIdx = true;
            }
        }
        if (!bDoneIdx) {
            if (flags & FTS5INDEX_QUERY_PREFIX != 0) {
                const nChar = fts5IndexCharlen(pToken.?, nToken);
                iIdx = 1;
                while (iIdx <= pConfig.nPrefix) : (iIdx += 1) {
                    const nIdxChar = pConfig.aPrefix.?[@intCast(iIdx - 1)];
                    if (nIdxChar == nChar) break;
                    if (nIdxChar == nChar + 1) iPrefixIdx = iIdx;
                }
            }
        }

        if (bTokendata != 0 and iIdx == 0) {
            buf.p.?[0] = FTS5_MAIN_PREFIX;
            pRet = fts5SetupTokendataIter(p, buf.p.?, nToken + 1, pColset);
        } else if (iIdx <= pConfig.nPrefix) {
            // Straight index lookup
            const pStruct = fts5StructureRead(p);
            buf.p.?[0] = @intCast(@as(c_int, FTS5_MAIN_PREFIX) + iIdx);
            if (pStruct) |ps| {
                fts5MultiIterNew(
                    p,
                    ps,
                    flags | FTS5INDEX_QUERY_SKIPEMPTY,
                    pColset,
                    buf.p,
                    nToken + 1,
                    -1,
                    0,
                    &pRet,
                );
                fts5StructureRelease(ps);
            }
        } else {
            // Scan multiple terms in the main index for a prefix query.
            const bDesc: c_int = @intFromBool((flags & FTS5INDEX_QUERY_DESC) != 0);
            fts5SetupPrefixIter(p, bDesc, iPrefixIdx, buf.p.?, nToken + 1, pColset, &pRet);
            if (pRet == null) {
                // assert( p->rc!=SQLITE_OK );
            } else {
                const pr = pRet.?;
                fts5IterSetOutputCb(&p.rc, pr);
                if (p.rc == SQLITE_OK) {
                    const pSeg: *Fts5SegIter = iterSeg(pr, pr.aFirst.?[1].iFirst);
                    if (pSeg.pLeaf != null) pr.xSetOutputs.?(pr, pSeg);
                }
            }
        }

        if (p.rc != 0) {
            fts5IterClose(@ptrCast(pRet));
            pRet = null;
            fts5IndexCloseReader(p);
        }

        ppIter.* = @ptrCast(pRet);
        sqlite3Fts5BufferFree(&buf);
    }
    return fts5IndexReturn(p);
}

// Move to the next matching rowid.
export fn sqlite3Fts5IterNext(pIndexIter: *Fts5IndexIter) callconv(.c) c_int {
    const pIter: *Fts5Iter = @ptrCast(@alignCast(pIndexIter));
    if (pIter.nSeg == 0) {
        fts5TokendataIterNext(pIter, 0, 0);
    } else {
        fts5MultiIterNext(pIter.pIndex.?, pIter, 0, 0);
    }
    return fts5IndexReturn(pIter.pIndex.?);
}

// Move to the next matching term/rowid. Used by the fts5vocab module.
export fn sqlite3Fts5IterNextScan(pIndexIter: *Fts5IndexIter) callconv(.c) c_int {
    const pIter: *Fts5Iter = @ptrCast(@alignCast(pIndexIter));
    const p = pIter.pIndex.?;

    fts5MultiIterNext(p, pIter, 0, 0);
    if (p.rc == SQLITE_OK) {
        const pSeg: *Fts5SegIter = iterSeg(pIter, pIter.aFirst.?[1].iFirst);
        if (pSeg.pLeaf != null and pSeg.term.p.?[0] != FTS5_MAIN_PREFIX) {
            fts5DataRelease(pSeg.pLeaf);
            pSeg.pLeaf = null;
            pIter.base.bEof = 1;
        }
    }

    return fts5IndexReturn(pIter.pIndex.?);
}

// Move to the next matching rowid that occurs at or after iMatch.
export fn sqlite3Fts5IterNextFrom(pIndexIter: *Fts5IndexIter, iMatch: i64) callconv(.c) c_int {
    const pIter: *Fts5Iter = @ptrCast(@alignCast(pIndexIter));
    if (pIter.nSeg == 0) {
        fts5TokendataIterNext(pIter, 1, iMatch);
    } else {
        fts5MultiIterNextFrom(pIter.pIndex.?, pIter, iMatch);
    }
    return fts5IndexReturn(pIter.pIndex.?);
}

// Return the current term.
export fn sqlite3Fts5IterTerm(pIndexIter: *Fts5IndexIter, pn: *c_int) callconv(.c) ?[*]const u8 {
    var n: c_int = undefined;
    const z = fts5MultiIterTerm(@ptrCast(@alignCast(pIndexIter)), &n);
    pn.* = n - 1;
    return if (z) |zz| zz + 1 else null;
}

// pIter is a prefix query. Populate pIter->pTokenDataIter with an
// Fts5TokenDataIter object containing mappings for all rows matched.
fn fts5SetupPrefixIterTokendata(
    pIter: *Fts5Iter,
    pToken: ?[*]const u8,
    nToken: c_int,
) c_int {
    const p = pIter.pIndex.?;
    var token: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    var ctx: TokendataSetupCtx = undefined;

    _ = memset(&ctx, 0, @sizeOf(TokendataSetupCtx));

    _ = fts5BufferGrow(&p.rc, &token, nToken + 1);
    ctx.pT = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&p.rc, SZ_FTS5TOKENDATAITER(1))));

    if (p.rc == SQLITE_OK) {
        // Fill in the token prefix to search for
        token.p.?[0] = FTS5_MAIN_PREFIX;
        if (nToken > 0) _ = memcpy(token.p.? + 1, pToken, @intCast(nToken));
        token.n = nToken + 1;

        _ = fts5VisitEntries(p, null, token.p.?, token.n, 1, &prefixIterSetupTokendataCb, @ptrCast(&ctx));

        fts5TokendataIterSortMap(p, ctx.pT.?);
    }

    if (p.rc == SQLITE_OK) {
        pIter.pTokenDataIter = ctx.pT;
    } else {
        fts5TokendataIterDelete(ctx.pT);
    }
    sqlite3Fts5BufferFree(&token);

    return fts5IndexReturn(p);
}

// Used by xInstToken() to access the token at offset iOff, column iCol of row
// iRowid. Returned via *ppOut and *pnOut.
export fn sqlite3Fts5IterToken(
    pIndexIter: *Fts5IndexIter,
    pToken: ?[*]const u8,
    nToken: c_int,
    iRowid: i64,
    iCol: c_int,
    iOff: c_int,
    ppOut: *?[*]const u8,
    pnOut: *c_int,
) callconv(.c) c_int {
    const pIter: *Fts5Iter = @ptrCast(@alignCast(pIndexIter));
    var pT: ?*Fts5TokenDataIter = pIter.pTokenDataIter;
    const iPos: i64 = (@as(i64, iCol) << 32) + iOff;
    var aMap: ?[*]Fts5TokenDataMap = null;
    var iLo: c_int = 0;
    var iHi: c_int = 0;
    var iTest: c_int = 0;

    if (pT == null) {
        const rc = fts5SetupPrefixIterTokendata(pIter, pToken, nToken);
        if (rc != SQLITE_OK) return rc;
        pT = pIter.pTokenDataIter;
    }

    iHi = @intCast(pT.?.nMap);
    aMap = pT.?.aMap;

    while (iHi > iLo) {
        iTest = @divTrunc(iLo + iHi, 2);

        if (aMap.?[@intCast(iTest)].iRowid < iRowid) {
            iLo = iTest + 1;
        } else if (aMap.?[@intCast(iTest)].iRowid > iRowid) {
            iHi = iTest;
        } else {
            if (aMap.?[@intCast(iTest)].iPos < iPos) {
                if (aMap.?[@intCast(iTest)].iPos < 0) {
                    break;
                }
                iLo = iTest + 1;
            } else if (aMap.?[@intCast(iTest)].iPos > iPos) {
                iHi = iTest;
            } else {
                break;
            }
        }
    }

    if (iHi > iLo) {
        if (pIter.nSeg == 0) {
            const pMap: *Fts5Iter = tokenDataIterApIter(pT.?, aMap.?[@intCast(iTest)].iIter).*.?;
            ppOut.* = iterSeg(pMap, 0).term.p.? + 1;
            pnOut.* = iterSeg(pMap, 0).term.n - 1;
        } else {
            const pm: *Fts5TokenDataMap = &aMap.?[@intCast(iTest)];
            ppOut.* = pT.?.terms.p.? + @as(usize, @intCast(pm.iIter));
            pnOut.* = aMap.?[@intCast(iTest)].nByte;
        }
    }

    return SQLITE_OK;
}

// Clear any existing entries from the token-map associated with the iterator.
export fn sqlite3Fts5IndexIterClearTokendata(pIndexIter: ?*Fts5IndexIter) callconv(.c) void {
    const pIter: ?*Fts5Iter = @ptrCast(@alignCast(pIndexIter));
    if (pIter) |it| {
        if (it.pTokenDataIter != null and
            (it.nSeg == 0 or @as(*Fts5Config, @ptrCast(@alignCast(it.pIndex.?.pConfig.?))).eDetail != FTS5_DETAIL_FULL))
        {
            it.pTokenDataIter.?.nMap = 0;
        }
    }
}

// Set a token-mapping for the iterator. Used in detail=column or detail=none
// mode when a token is requested using the xInstToken() API.
export fn sqlite3Fts5IndexIterWriteTokendata(
    pIndexIter: *Fts5IndexIter,
    pToken: ?[*]const u8,
    nToken: c_int,
    iRowid: i64,
    iCol: c_int,
    iOff: c_int,
) callconv(.c) c_int {
    const pIter: *Fts5Iter = @ptrCast(@alignCast(pIndexIter));
    var pT: ?*Fts5TokenDataIter = pIter.pTokenDataIter;
    const p = pIter.pIndex.?;
    const iPos: i64 = (@as(i64, iCol) << 32) + iOff;

    if (pIter.nSeg > 0) {
        // This is a prefix term iterator.
        if (pT == null) {
            pT = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&p.rc, SZ_FTS5TOKENDATAITER(1))));
            pIter.pTokenDataIter = pT;
        }
        if (pT) |t| {
            fts5TokendataIterAppendMap(p, t, @intCast(t.terms.n), nToken, iRowid, iPos);
            sqlite3Fts5BufferAppendBlob(&p.rc, &t.terms, @bitCast(nToken), pToken.?);
        }
    } else {
        const t = pT.?;
        var ii: c_int = 0;
        while (ii < @as(c_int, @intCast(t.nIter))) : (ii += 1) {
            const pTerm: *Fts5Buffer = &iterSeg(tokenDataIterApIter(t, ii).*.?, 0).term;
            if (nToken == pTerm.n - 1 and memcmp(pToken, pTerm.p.? + 1, @intCast(nToken)) == 0) break;
        }
        if (ii < @as(c_int, @intCast(t.nIter))) {
            fts5TokendataIterAppendMap(p, t, ii, 0, iRowid, iPos);
        }
    }
    return fts5IndexReturn(p);
}

// Close an iterator opened by sqlite3Fts5IndexQuery().
export fn sqlite3Fts5IterClose(pIndexIter: ?*Fts5IndexIter) callconv(.c) void {
    if (pIndexIter) |pii| {
        const pIndex = @as(*Fts5Iter, @ptrCast(@alignCast(pii))).pIndex.?;
        fts5IterClose(pii);
        _ = fts5IndexReturn(pIndex);
    }
}

// Read and decode the "averages" record from the database.
export fn sqlite3Fts5IndexGetAverages(p: *Fts5IndexS, pnRow: *i64, anSize: [*]i64) callconv(.c) c_int {
    const nCol: c_int = @as(*Fts5Config, @ptrCast(@alignCast(p.pConfig.?))).nCol;

    pnRow.* = 0;
    _ = memset(anSize, 0, @sizeOf(i64) * @as(usize, @intCast(nCol)));
    const pData = fts5DataRead(p, FTS5_AVERAGES_ROWID);
    if (p.rc == SQLITE_OK and pData.?.nn != 0) {
        const pd = pData.?;
        var i: c_int = 0;
        i += fts5GetVarint(pd.p.? + @as(usize, @intCast(i)), @ptrCast(pnRow));
        var iCol: c_int = 0;
        while (i < pd.nn and iCol < nCol) : (iCol += 1) {
            i += fts5GetVarint(pd.p.? + @as(usize, @intCast(i)), @ptrCast(&anSize[@intCast(iCol)]));
        }
    }

    fts5DataRelease(pData);
    return fts5IndexReturn(p);
}

// Replace the current "averages" record with the contents of the buffer.
export fn sqlite3Fts5IndexSetAverages(p: *Fts5IndexS, pData: [*]const u8, nData: c_int) callconv(.c) c_int {
    fts5DataWrite(p, FTS5_AVERAGES_ROWID, pData, nData);
    return fts5IndexReturn(p);
}

// Return the total number of blocks this module has read from %_data.
export fn sqlite3Fts5IndexReads(p: *Fts5IndexS) callconv(.c) c_int {
    return p.nRead;
}

// Set the 32-bit cookie value stored at the start of all structure records.
export fn sqlite3Fts5IndexSetCookie(p: *Fts5IndexS, iNew: c_int) callconv(.c) c_int {
    const pConfig: *Fts5Config = @ptrCast(@alignCast(p.pConfig.?));
    var aCookie: [4]u8 = undefined;
    var pBlob: ?*sqlite3_blob = null;

    sqlite3Fts5Put32(&aCookie, iNew);

    var rc = sqlite3_blob_open(
        pConfig.db,
        pConfig.zDb.?,
        p.zDataTbl.?,
        "block",
        FTS5_STRUCTURE_ROWID,
        1,
        &pBlob,
    );
    if (rc == SQLITE_OK) {
        _ = sqlite3_blob_write(pBlob.?, &aCookie, 4, 0);
        rc = sqlite3_blob_close(pBlob.?);
    }

    return rc;
}

export fn sqlite3Fts5IndexLoadConfig(p: *Fts5IndexS) callconv(.c) c_int {
    const pStruct = fts5StructureRead(p);
    fts5StructureRelease(pStruct);
    return fts5IndexReturn(p);
}

// Retrieve the origin value used for the segment currently being accumulated.
export fn sqlite3Fts5IndexGetOrigin(p: *Fts5IndexS, piOrigin: *i64) callconv(.c) c_int {
    const pStruct = fts5StructureRead(p);
    if (pStruct) |ps| {
        piOrigin.* = @bitCast(ps.nOriginCntr);
        fts5StructureRelease(ps);
    }
    return fts5IndexReturn(p);
}

// ============================ CHUNK 10 ============================
// ===========================================================================
// Tombstone hash table (fts5_index.c 7850-8165).
// ===========================================================================

fn fts5IndexTombstoneAddToPage(
    pPg: *Fts5Data,
    bForce: c_int,
    nPg: c_int,
    iRowid: u64,
) c_int {
    const szKey: c_int = TOMBSTONE_KEYSIZE(pPg);
    const nSlot: c_int = TOMBSTONE_NSLOT(pPg);
    const nElem: u32 = fts5GetU32(pPg.p.? + 4);
    // iSlot = (iRowid / nPg) % nSlot
    var iSlot: c_int = @intCast((iRowid / @as(u64, @intCast(nPg))) % @as(u64, @intCast(nSlot)));
    var nCollide: c_int = nSlot;

    if (szKey == 4 and iRowid > 0xFFFFFFFF) return 2;
    if (iRowid == 0) {
        pPg.p.?[1] = 0x01;
        return 0;
    }

    if (bForce == 0 and nElem >= @as(u32, @intCast(@divTrunc(nSlot, 2)))) {
        return 1;
    }

    fts5PutU32(pPg.p.? + 4, nElem + 1);
    if (szKey == 4) {
        const aSlot: [*]u8 = pPg.p.? + 8; // u32 slots, big-endian via fts5Get/PutU32
        while (fts5GetU32(aSlot + @as(usize, @intCast(iSlot)) * 4) != 0) {
            iSlot = @rem(iSlot + 1, nSlot);
            const old = nCollide;
            nCollide -= 1;
            if (old == 0) return 0;
        }
        fts5PutU32(aSlot + @as(usize, @intCast(iSlot)) * 4, @truncate(iRowid));
    } else {
        const aSlot: [*]u8 = pPg.p.? + 8; // u64 slots
        while (fts5GetU64(aSlot + @as(usize, @intCast(iSlot)) * 8) != 0) {
            iSlot = @rem(iSlot + 1, nSlot);
            const old = nCollide;
            nCollide -= 1;
            if (old == 0) return 0;
        }
        fts5PutU64(aSlot + @as(usize, @intCast(iSlot)) * 8, iRowid);
    }

    return 0;
}

fn fts5IndexTombstoneRehash(
    p: *Fts5IndexS,
    pSeg: *Fts5StructureSegment,
    pData1: ?*Fts5Data,
    iPg1: c_int,
    szKey: c_int,
    nOut: c_int,
    apOut: [*]?*Fts5Data,
) c_int {
    var ii: c_int = 0;
    var res: c_int = 0;

    // Initialize the headers of all the output pages
    ii = 0;
    while (ii < nOut) : (ii += 1) {
        const pg = apOut[@intCast(ii)].?;
        pg.p.?[0] = @intCast(szKey);
        fts5PutU32(pg.p.? + 4, 0);
    }

    // Loop through the current pages of the hash table.
    ii = 0;
    while (res == 0 and ii < pSeg.nPgTombstone) : (ii += 1) {
        var pData: ?*Fts5Data = null;
        var pFree: ?*Fts5Data = null;

        if (iPg1 == ii) {
            pData = pData1;
        } else {
            pData = fts5DataRead(p, FTS5_TOMBSTONE_ROWID(pSeg.iSegid, ii));
            pFree = pData;
        }

        if (pData) |pd| {
            const szKeyIn: c_int = TOMBSTONE_KEYSIZE(pd);
            const nSlotIn: c_int = @divTrunc(pd.nn - 8, szKeyIn);
            var iIn: c_int = 0;
            while (iIn < nSlotIn) : (iIn += 1) {
                var iVal: u64 = 0;

                // Read the value from slot iIn of the input page into iVal.
                if (szKeyIn == 4) {
                    const aSlot: [*]u8 = pd.p.? + 8;
                    const v = fts5GetU32(aSlot + @as(usize, @intCast(iIn)) * 4);
                    if (v != 0) iVal = v;
                } else {
                    const aSlot: [*]u8 = pd.p.? + 8;
                    const v = fts5GetU64(aSlot + @as(usize, @intCast(iIn)) * 8);
                    if (v != 0) iVal = v;
                }

                // If iVal is not 0, insert it into the new hash table
                if (iVal != 0) {
                    const pPg = apOut[@intCast(iVal % @as(u64, @intCast(nOut)))].?;
                    res = fts5IndexTombstoneAddToPage(pPg, 0, nOut, iVal);
                    if (res != 0) break;
                }
            }

            // If this is page 0 of the old hash, copy the rowid-0-flag across.
            if (ii == 0) {
                apOut[0].?.p.?[1] = pd.p.?[1];
            }
        }
        fts5DataRelease(pFree);
    }

    return res;
}

fn fts5IndexTombstoneRebuild(
    p: *Fts5IndexS,
    pSeg: *Fts5StructureSegment,
    pData1: ?*Fts5Data,
    iPg1: c_int,
    szKey: c_int,
    pnOut: *c_int,
    papOut: *?[*]?*Fts5Data,
) void {
    const MINSLOT: c_int = 32;
    const nSlotPerPage: c_int = MAX(c_int, MINSLOT, @divTrunc(p.pConfig.?.pgsz - 8, szKey));
    var nSlot: i64 = 0;
    var nOut: i64 = 0;

    if (pSeg.nPgTombstone == 0) {
        // Case 1.
        nOut = 1;
        nSlot = MINSLOT;
    } else if (pSeg.nPgTombstone == 1) {
        // Case 2.
        const nElem: u32 = fts5GetU32(pData1.?.p.? + 4);
        if (nElem > (@as(u32, @bitCast(nSlotPerPage)) / 4)) {
            nOut = 0;
        } else {
            nOut = 1;
            nSlot = MAX(i64, @as(i64, @intCast(nElem)) * 4, MINSLOT);
        }
    }
    if (nOut == 0) {
        // Case 3.
        nOut = @as(i64, @intCast(pSeg.nPgTombstone)) * 2 + 1;
        nSlot = nSlotPerPage;
    }

    // Allocate the required array and output pages
    while (true) {
        var res: c_int = 0;
        var ii: i64 = 0;
        var szPage: i64 = 0;
        var apOut: ?[*]?*Fts5Data = null;

        // Allocate space for the new hash table
        apOut = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&p.rc, @sizeOf(?*Fts5Data) * nOut)));
        szPage = 8 + nSlot * szKey;
        ii = 0;
        while (ii < nOut) : (ii += 1) {
            const pNew: ?*Fts5Data = @ptrCast(@alignCast(sqlite3Fts5MallocZero(
                &p.rc,
                @sizeOf(Fts5Data) + szPage,
            )));
            if (pNew) |pn| {
                pn.nn = @intCast(szPage);
                // pNew->p = (u8*)&pNew[1];
                const base: [*]Fts5Data = @ptrCast(pn);
                pn.p = @ptrCast(base + 1);
                apOut.?[@intCast(ii)] = pn;
            }
        }

        // Rebuild the hash table.
        if (p.rc == SQLITE_OK) {
            res = fts5IndexTombstoneRehash(p, pSeg, pData1, iPg1, szKey, @intCast(nOut), apOut.?);
        }
        if (res == 0) {
            if (p.rc != 0) {
                fts5IndexFreeArray(apOut, @intCast(nOut));
                apOut = null;
                nOut = 0;
            }
            pnOut.* = @intCast(nOut);
            papOut.* = apOut;
            break;
        }

        // Could not rebuild the hash table. Free all buffers and retry larger.
        fts5IndexFreeArray(apOut, @intCast(nOut));
        nSlot = nSlotPerPage;
        nOut = nOut * 2 + 1;
    }
}

fn fts5IndexTombstoneAdd(
    p: *Fts5IndexS,
    pSeg: *Fts5StructureSegment,
    iRowid: u64,
) void {
    var pPg: ?*Fts5Data = null;
    var iPg: c_int = -1;
    var szKey: c_int = 0;
    var nHash: c_int = 0;
    var apHash: ?[*]?*Fts5Data = null;

    p.nContentlessDelete += 1;

    if (pSeg.nPgTombstone > 0) {
        iPg = @intCast(iRowid % @as(u64, @intCast(pSeg.nPgTombstone)));
        pPg = fts5DataRead(p, FTS5_TOMBSTONE_ROWID(pSeg.iSegid, iPg));
        if (pPg == null) {
            return;
        }

        if (0 == fts5IndexTombstoneAddToPage(pPg.?, 0, pSeg.nPgTombstone, iRowid)) {
            fts5DataWrite(p, FTS5_TOMBSTONE_ROWID(pSeg.iSegid, iPg), pPg.?.p.?, pPg.?.nn);
            fts5DataRelease(pPg);
            return;
        }
    }

    // Have to rebuild the hash table. First figure out the key-size (4 or 8).
    szKey = if (pPg) |pg| TOMBSTONE_KEYSIZE(pg) else 4;
    if (iRowid > 0xFFFFFFFF) szKey = 8;

    // Rebuild the hash table
    fts5IndexTombstoneRebuild(p, pSeg, pPg, iPg, szKey, &nHash, &apHash);

    // If all has succeeded, write the new rowid into one of the new hash
    // table pages, then write them all out to disk.
    if (nHash != 0) {
        var ii: c_int = 0;
        _ = fts5IndexTombstoneAddToPage(apHash.?[@intCast(iRowid % @as(u64, @intCast(nHash)))].?, 1, nHash, iRowid);
        ii = 0;
        while (ii < nHash) : (ii += 1) {
            const iTombstoneRowid = FTS5_TOMBSTONE_ROWID(pSeg.iSegid, ii);
            const pg = apHash.?[@intCast(ii)].?;
            fts5DataWrite(p, iTombstoneRowid, pg.p.?, pg.nn);
        }
        pSeg.nPgTombstone = nHash;
        fts5StructureWrite(p, p.pStruct.?);
    }

    fts5DataRelease(pPg);
    fts5IndexFreeArray(apHash, nHash);
}

export fn sqlite3Fts5IndexContentlessDelete(p: *Fts5IndexS, iOrigin: i64, iRowid: i64) callconv(.c) c_int {
    const pStruct = fts5StructureRead(p);
    if (pStruct) |ps| {
        var bFound: c_int = 0;
        var iLvl: c_int = ps.nLevel - 1;
        while (iLvl >= 0) : (iLvl -= 1) {
            var iSeg: c_int = structLevel(ps, iLvl).nSeg - 1;
            while (iSeg >= 0) : (iSeg -= 1) {
                const pSeg = &structLevel(ps, iLvl).aSeg.?[@intCast(iSeg)];
                if (pSeg.iOrigin1 <= @as(u64, @bitCast(iOrigin)) and pSeg.iOrigin2 >= @as(u64, @bitCast(iOrigin))) {
                    if (bFound == 0) {
                        pSeg.nEntryTombstone += 1;
                        bFound = 1;
                    }
                    fts5IndexTombstoneAdd(p, pSeg, @bitCast(iRowid));
                }
            }
        }
        fts5StructureRelease(ps);
    }
    return fts5IndexReturn(p);
}

// ===========================================================================
// Integrity-check (fts5_index.c 8176-8753).
// ===========================================================================

export fn sqlite3Fts5IndexEntryCksum(
    iRowid: i64,
    iCol: c_int,
    iPos: c_int,
    iIdx: c_int,
    pTerm: [*]const u8,
    nTerm: c_int,
) callconv(.c) u64 {
    var ret: u64 = @bitCast(iRowid);
    ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, iCol)));
    ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, iPos)));
    if (iIdx >= 0) {
        ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, FTS5_MAIN_PREFIX) + @as(i64, iIdx)));
    }
    var i: c_int = 0;
    while (i < nTerm) : (i += 1) {
        // C: ret += (ret<<3) + pTerm[i], pTerm is `const char*`. On the usual
        // targets `char` is signed, so a byte >=0x80 sign-extends. Match that
        // exactly: (u64)(i64)(i8)byte.
        const sb: i8 = @bitCast(pTerm[@intCast(i)]);
        ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, sb)));
    }
    return ret;
}

// Minimal layout view of Fts5Hash (fts5_hash.c) to read .nEntry.
const Fts5HashLayout = extern struct {
    eDetail: c_int,
    pnByte: ?*c_int,
    nEntry: c_int,
};

// fts5TestDlidxReverse — internal debug self-test (SQLITE_DEBUG only).
fn fts5TestDlidxReverse(p: *Fts5IndexS, iSegid: c_int, iLeaf: c_int) void {
    var pDlidx: ?*Fts5DlidxIter = null;
    var cksum1: u64 = 13;
    var cksum2: u64 = 13;

    pDlidx = fts5DlidxIterInit(p, 0, iSegid, iLeaf);
    while (fts5DlidxIterEof(p, pDlidx) == 0) : (_ = fts5DlidxIterNext(p, pDlidx.?)) {
        const iRowid: i64 = fts5DlidxIterRowid(pDlidx.?);
        const pgno: c_int = fts5DlidxIterPgno(pDlidx.?);
        cksum1 +%= @as(u64, @bitCast(iRowid +% (@as(i64, pgno) << 32)));
    }
    fts5DlidxIterFree(pDlidx);
    pDlidx = null;

    pDlidx = fts5DlidxIterInit(p, 1, iSegid, iLeaf);
    while (fts5DlidxIterEof(p, pDlidx) == 0) : (_ = fts5DlidxIterPrev(p, pDlidx.?)) {
        const iRowid: i64 = fts5DlidxIterRowid(pDlidx.?);
        const pgno: c_int = fts5DlidxIterPgno(pDlidx.?);
        cksum2 +%= @as(u64, @bitCast(iRowid +% (@as(i64, pgno) << 32)));
    }
    fts5DlidxIterFree(pDlidx);
    pDlidx = null;

    if (p.rc == SQLITE_OK and cksum1 != cksum2) p.rc = FTS5_CORRUPT;
}

fn fts5QueryCksum(
    p: *Fts5IndexS,
    iIdx: c_int,
    z: [*]const u8,
    n: c_int,
    flags: c_int,
    pCksum: *u64,
) c_int {
    const eDetail: c_int = p.pConfig.?.eDetail;
    var cksum: u64 = pCksum.*;
    var pIter: ?*Fts5IndexIter = null;
    var rc: c_int = sqlite3Fts5IndexQuery(
        p,
        z,
        n,
        (flags | FTS5INDEX_QUERY_NOTOKENDATA),
        null,
        &pIter,
    );

    while (rc == SQLITE_OK and pIter != null and 0 == int.sqlite3Fts5IterEof(pIter.?)) {
        const rowid: i64 = pIter.?.iRowid;

        if (eDetail == FTS5_DETAIL_NONE) {
            cksum ^= sqlite3Fts5IndexEntryCksum(rowid, 0, 0, iIdx, z, n);
        } else {
            var sReader: Fts5PoslistReader = undefined;
            _ = sqlite3Fts5PoslistReaderInit(pIter.?.pData, pIter.?.nData, &sReader);
            while (sReader.bEof == 0) : (_ = sqlite3Fts5PoslistReaderNext(&sReader)) {
                const iCol: c_int = FTS5_POS2COLUMN(sReader.iPos);
                const iOff: c_int = FTS5_POS2OFFSET(sReader.iPos);
                cksum ^= sqlite3Fts5IndexEntryCksum(rowid, iCol, iOff, iIdx, z, n);
            }
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3Fts5IterNext(pIter.?);
        }
    }
    fts5IterClose(pIter);

    pCksum.* = cksum;
    return rc;
}

fn fts5TestUtf8(z: [*]const u8, n: c_int) c_int {
    var i: c_int = 0;
    while (i < n) {
        if ((z[@intCast(i)] & 0x80) == 0x00) {
            i += 1;
        } else if ((z[@intCast(i)] & 0xE0) == 0xC0) {
            if (i + 1 >= n or (z[@intCast(i + 1)] & 0xC0) != 0x80) return 1;
            i += 2;
        } else if ((z[@intCast(i)] & 0xF0) == 0xE0) {
            if (i + 2 >= n or (z[@intCast(i + 1)] & 0xC0) != 0x80 or (z[@intCast(i + 2)] & 0xC0) != 0x80) return 1;
            i += 3;
        } else if ((z[@intCast(i)] & 0xF8) == 0xF0) {
            if (i + 3 >= n or (z[@intCast(i + 1)] & 0xC0) != 0x80 or (z[@intCast(i + 2)] & 0xC0) != 0x80) return 1;
            if ((z[@intCast(i + 2)] & 0xC0) != 0x80) return 1;
            i += 3;
        } else {
            return 1;
        }
    }
    return 0;
}

fn fts5TestTerm(
    p: *Fts5IndexS,
    pPrev: *Fts5Buffer,
    z: ?[*]const u8,
    n: c_int,
    expected: u64,
    pCksum: *u64,
    pbFail: *c_int,
) void {
    var rc: c_int = p.rc;
    if (pPrev.n == 0) {
        sqlite3Fts5BufferSet(&rc, pPrev, n, z.?);
    } else if (pbFail.* == 0 and rc == SQLITE_OK and
        (pPrev.n != n or memcmp(pPrev.p, z, @intCast(n)) != 0) and
        (p.pHash == null or @as(*Fts5HashLayout, @ptrCast(@alignCast(p.pHash.?))).nEntry == 0))
    {
        var cksum3: u64 = pCksum.*;
        const zTerm: [*]const u8 = pPrev.p.? + 1; // term sans prefix-byte
        const nTerm: c_int = pPrev.n - 1;
        const iIdx: c_int = @as(c_int, pPrev.p.?[0]) - FTS5_MAIN_PREFIX;
        const flags: c_int = if (iIdx == 0) 0 else FTS5INDEX_QUERY_PREFIX;
        var ck1: u64 = 0;
        var ck2: u64 = 0;

        rc = fts5QueryCksum(p, iIdx, zTerm, nTerm, flags, &ck1);
        if (rc == SQLITE_OK) {
            const f = flags | FTS5INDEX_QUERY_DESC;
            rc = fts5QueryCksum(p, iIdx, zTerm, nTerm, f, &ck2);
        }
        if (rc == SQLITE_OK and ck1 != ck2) rc = FTS5_CORRUPT;

        if (p.nPendingData == 0 and 0 == fts5TestUtf8(zTerm, nTerm)) {
            if (iIdx > 0 and rc == SQLITE_OK) {
                const f = flags | FTS5INDEX_QUERY_TEST_NOIDX;
                ck2 = 0;
                rc = fts5QueryCksum(p, iIdx, zTerm, nTerm, f, &ck2);
                if (rc == SQLITE_OK and ck1 != ck2) rc = FTS5_CORRUPT;
            }
            if (iIdx > 0 and rc == SQLITE_OK) {
                const f = flags | FTS5INDEX_QUERY_TEST_NOIDX | FTS5INDEX_QUERY_DESC;
                ck2 = 0;
                rc = fts5QueryCksum(p, iIdx, zTerm, nTerm, f, &ck2);
                if (rc == SQLITE_OK and ck1 != ck2) rc = FTS5_CORRUPT;
            }
        }

        cksum3 ^= ck1;
        sqlite3Fts5BufferSet(&rc, pPrev, n, z);

        if (rc == SQLITE_OK and cksum3 != expected) {
            pbFail.* = 1;
        }
        pCksum.* = cksum3;
    }
    p.rc = rc;
}

fn fts5IndexIntegrityCheckEmpty(
    p: *Fts5IndexS,
    pSeg: *Fts5StructureSegment,
    iFirst: c_int,
    iNoRowid: c_int,
    iLast: c_int,
) void {
    var i: c_int = iFirst;
    while (p.rc == SQLITE_OK and i <= iLast) : (i += 1) {
        const pLeaf = fts5DataRead(p, FTS5_SEGMENT_ROWID(pSeg.iSegid, i));
        if (pLeaf) |pl| {
            if (!fts5LeafIsTermless(pl) or
                (i >= iNoRowid and 0 != fts5LeafFirstRowidOff(pl)))
            {
                _ = fts5IndexCorruptRowid(p, FTS5_SEGMENT_ROWID(pSeg.iSegid, i));
            }
        }
        fts5DataRelease(pLeaf);
    }
}

fn fts5IntegrityCheckPgidx(p: *Fts5IndexS, iRowid: i64, pLeaf: *Fts5Data) void {
    var iTermOff: i64 = 0;
    var ii: c_int = 0;

    var buf1: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    var buf2: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };

    ii = pLeaf.szLeaf;
    while (ii < pLeaf.nn and p.rc == SQLITE_OK) {
        var res: c_int = undefined;
        var iOff: i64 = undefined;
        var nIncr: c_int = undefined;

        ii += fts5GetVarint32Into(c_int, pLeaf.p.? + @as(usize, @intCast(ii)), &nIncr);
        iTermOff += nIncr;
        iOff = iTermOff;

        if (iOff >= pLeaf.szLeaf) {
            _ = fts5IndexCorruptRowid(p, iRowid);
        } else if (iTermOff == nIncr) {
            var nByte: c_int = undefined;
            iOff += fts5GetVarint32Into(c_int, pLeaf.p.? + @as(usize, @intCast(iOff)), &nByte);
            if ((iOff + nByte) > pLeaf.szLeaf) {
                _ = fts5IndexCorruptRowid(p, iRowid);
            } else {
                sqlite3Fts5BufferSet(&p.rc, &buf1, nByte, pLeaf.p.? + @as(usize, @intCast(iOff)));
            }
        } else {
            var nKeep: c_int = undefined;
            var nByte: c_int = undefined;
            iOff += fts5GetVarint32Into(c_int, pLeaf.p.? + @as(usize, @intCast(iOff)), &nKeep);
            iOff += fts5GetVarint32Into(c_int, pLeaf.p.? + @as(usize, @intCast(iOff)), &nByte);
            if (nKeep > buf1.n or (iOff + nByte) > pLeaf.szLeaf) {
                _ = fts5IndexCorruptRowid(p, iRowid);
            } else {
                buf1.n = nKeep;
                sqlite3Fts5BufferAppendBlob(&p.rc, &buf1, @intCast(nByte), pLeaf.p.? + @as(usize, @intCast(iOff)));
            }

            if (p.rc == SQLITE_OK) {
                res = fts5BufferCompare(&buf1, &buf2);
                if (res <= 0) _ = fts5IndexCorruptRowid(p, iRowid);
            }
        }
        sqlite3Fts5BufferSet(&p.rc, &buf2, buf1.n, buf1.p.?);
    }

    sqlite3Fts5BufferFree(&buf1);
    sqlite3Fts5BufferFree(&buf2);
}

fn fts5IndexIntegrityCheckSegment(
    p: *Fts5IndexS,
    pSeg: *Fts5StructureSegment,
) void {
    const pConfig: *Fts5Config = p.pConfig.?;
    const bSecureDelete: c_int = @intFromBool(pConfig.iVersion == FTS5_CURRENT_VERSION_SECUREDELETE);
    var pStmt: ?*sqlite3_stmt = null;
    var rc2: c_int = undefined;
    var iIdxPrevLeaf: c_int = pSeg.pgnoFirst - 1;
    var iDlidxPrevLeaf: c_int = pSeg.pgnoLast;

    if (pSeg.pgnoFirst == 0) return;

    _ = fts5IndexPrepareStmt(p, &pStmt, sqlite3_mprintf(
        "SELECT segid, term, (pgno>>1), (pgno&1) FROM %Q.'%q_idx' WHERE segid=%d " ++
            "ORDER BY 1, 2",
        pConfig.zDb,
        pConfig.zName,
        pSeg.iSegid,
    ));

    // Iterate through the b-tree hierarchy.
    while (p.rc == SQLITE_OK and SQLITE_ROW == sqlite3_step(pStmt)) {
        var iRow: i64 = undefined;
        var pLeaf: ?*Fts5Data = undefined;

        const zIdxTerm: ?[*]const u8 = @ptrCast(sqlite3_column_blob(pStmt, 1));
        const nIdxTerm: c_int = sqlite3_column_bytes(pStmt, 1);
        const iIdxLeaf: c_int = sqlite3_column_int(pStmt, 2);
        const bIdxDlidx: c_int = sqlite3_column_int(pStmt, 3);

        // If the leaf has already been trimmed from the segment, ignore it.
        if (iIdxLeaf < pSeg.pgnoFirst) continue;
        iRow = FTS5_SEGMENT_ROWID(pSeg.iSegid, iIdxLeaf);
        pLeaf = fts5LeafRead(p, iRow);
        if (pLeaf == null) break;

        if (pLeaf.?.nn <= pLeaf.?.szLeaf) {
            if (nIdxTerm == 0 and
                pConfig.iVersion == FTS5_CURRENT_VERSION_SECUREDELETE and
                pLeaf.?.nn == pLeaf.?.szLeaf and
                pLeaf.?.nn == 4)
            {
                // special case - first page keeps its %_idx entry even when
                // all terms are removed by secure-delete.
            } else {
                _ = fts5IndexCorruptRowid(p, iRow);
            }
        } else {
            var iOff: c_int = undefined;
            var iRowidOff: c_int = undefined;
            var nTerm: c_int = undefined;
            var res: c_int = undefined;

            iOff = fts5LeafFirstTermOff(pLeaf.?);
            iRowidOff = fts5LeafFirstRowidOff(pLeaf.?);
            if (iRowidOff >= iOff or iOff >= pLeaf.?.szLeaf) {
                _ = fts5IndexCorruptRowid(p, iRow);
            } else {
                iOff += fts5GetVarint32Into(c_int, pLeaf.?.p.? + @as(usize, @intCast(iOff)), &nTerm);
                res = fts5Memcmp(pLeaf.?.p.? + @as(usize, @intCast(iOff)), zIdxTerm, MIN(c_int, nTerm, nIdxTerm));
                if (res == 0) res = nTerm - nIdxTerm;
                if (res < 0) _ = fts5IndexCorruptRowid(p, iRow);
            }

            fts5IntegrityCheckPgidx(p, iRow, pLeaf.?);
        }
        fts5DataRelease(pLeaf);
        if (p.rc != 0) break;

        // Now check that the iter.nEmpty leaves following the current leaf
        // (a) exist and (b) contain no terms.
        fts5IndexIntegrityCheckEmpty(
            p,
            pSeg,
            iIdxPrevLeaf + 1,
            iDlidxPrevLeaf + 1,
            iIdxLeaf - 1,
        );
        if (p.rc != 0) break;

        // If there is a doclist-index, check that it looks right.
        if (bIdxDlidx != 0) {
            var pDlidx: ?*Fts5DlidxIter = null;
            var iPrevLeaf: c_int = iIdxLeaf;
            const iSegid: c_int = pSeg.iSegid;
            var iPg: c_int = 0;
            var iKey: i64 = undefined;

            pDlidx = fts5DlidxIterInit(p, 0, iSegid, iIdxLeaf);
            while (fts5DlidxIterEof(p, pDlidx) == 0) : (_ = fts5DlidxIterNext(p, pDlidx.?)) {

                // Check any rowid-less pages that occur before the current leaf.
                iPg = iPrevLeaf + 1;
                while (iPg < fts5DlidxIterPgno(pDlidx.?)) : (iPg += 1) {
                    iKey = FTS5_SEGMENT_ROWID(iSegid, iPg);
                    pLeaf = fts5LeafRead(p, iKey);
                    if (pLeaf) |pl| {
                        if (fts5LeafFirstRowidOff(pl) != 0) _ = fts5IndexCorruptRowid(p, iKey);
                        fts5DataRelease(pLeaf);
                    }
                }
                iPrevLeaf = fts5DlidxIterPgno(pDlidx.?);

                // Check that the leaf indicated by the iterator really does
                // contain the rowid suggested by the same.
                iKey = FTS5_SEGMENT_ROWID(iSegid, iPrevLeaf);
                pLeaf = fts5LeafRead(p, iKey);
                if (pLeaf) |pl| {
                    var iRowid: i64 = undefined;
                    const iRowidOff: c_int = fts5LeafFirstRowidOff(pl);
                    if (iRowidOff >= pl.szLeaf) {
                        _ = fts5IndexCorruptRowid(p, iKey);
                    } else if (bSecureDelete == 0 or iRowidOff > 0) {
                        const iDlRowid: i64 = fts5DlidxIterRowid(pDlidx.?);
                        var u: u64 = undefined;
                        _ = fts5GetVarint(pl.p.? + @as(usize, @intCast(iRowidOff)), &u);
                        iRowid = @bitCast(u);
                        if (iRowid < iDlRowid or (bSecureDelete == 0 and iRowid != iDlRowid)) {
                            _ = fts5IndexCorruptRowid(p, iKey);
                        }
                    }
                    fts5DataRelease(pLeaf);
                }
            }

            iDlidxPrevLeaf = iPg;
            fts5DlidxIterFree(pDlidx);
            fts5TestDlidxReverse(p, iSegid, iIdxLeaf);
        } else {
            iDlidxPrevLeaf = pSeg.pgnoLast;
            // TODO: Check there is no doclist index
        }

        iIdxPrevLeaf = iIdxLeaf;
    }

    rc2 = sqlite3_finalize(pStmt);
    if (p.rc == SQLITE_OK) p.rc = rc2;
}

export fn sqlite3Fts5IndexIntegrityCheck(p: *Fts5IndexS, cksum: u64, bUseCksum: c_int) callconv(.c) c_int {
    const eDetail: c_int = p.pConfig.?.eDetail;
    var cksum2: u64 = 0;
    var poslist: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    var pIter: ?*Fts5Iter = undefined;
    var pStruct: ?*Fts5Structure = undefined;
    var iLvl: c_int = undefined;
    var iSeg: c_int = undefined;

    // Used by extra internal tests (SQLITE_DEBUG).
    var cksum3: u64 = 0;
    var term: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    var bTestFail: c_int = 0;

    const flags: c_int = FTS5INDEX_QUERY_NOOUTPUT;

    // Load the FTS index structure
    pStruct = fts5StructureRead(p);
    if (pStruct == null) {
        return fts5IndexReturn(p);
    }

    // Check that the internal nodes of each segment match the leaves
    iLvl = 0;
    while (iLvl < pStruct.?.nLevel) : (iLvl += 1) {
        iSeg = 0;
        while (iSeg < structLevel(pStruct.?, iLvl).nSeg) : (iSeg += 1) {
            const pSeg = &structLevel(pStruct.?, iLvl).aSeg.?[@intCast(iSeg)];
            fts5IndexIntegrityCheckSegment(p, pSeg);
        }
    }

    fts5MultiIterNew(p, pStruct.?, flags, null, null, 0, -1, 0, &pIter);
    while (fts5MultiIterEof(p, pIter.?) == 0) : (fts5MultiIterNext(p, pIter.?, 0, 0)) {
        var n: c_int = undefined;
        var iPos: i64 = 0;
        var iOff: c_int = 0;
        const iRowid: i64 = fts5MultiIterRowid(pIter.?);
        const z: ?[*]const u8 = fts5MultiIterTerm(pIter.?, &n);

        // If this is a new term, query for it. Update cksum3 with the results.
        fts5TestTerm(p, &term, z, n, cksum2, &cksum3, &bTestFail);
        if (p.rc != 0) break;

        if (eDetail == FTS5_DETAIL_NONE) {
            if (0 == fts5MultiIterIsEmpty(p, pIter.?)) {
                cksum2 ^= sqlite3Fts5IndexEntryCksum(iRowid, 0, 0, -1, z.?, n);
            }
        } else {
            poslist.n = 0;
            const pFirst = iterSeg(pIter.?, pIter.?.aFirst.?[1].iFirst);
            fts5SegiterPoslist(p, pFirst, null, &poslist);
            sqlite3Fts5BufferAppendBlob(&p.rc, &poslist, 4, "\x00\x00\x00\x00");
            while (0 == sqlite3Fts5PoslistNext64(poslist.p, poslist.n, &iOff, &iPos)) {
                const iCol: c_int = FTS5_POS2COLUMN(iPos);
                const iTokOff: c_int = FTS5_POS2OFFSET(iPos);
                cksum2 ^= sqlite3Fts5IndexEntryCksum(iRowid, iCol, iTokOff, -1, z.?, n);
            }
        }
    }
    fts5TestTerm(p, &term, null, 0, cksum2, &cksum3, &bTestFail);

    fts5MultiIterFree(pIter);
    if (p.rc == SQLITE_OK and bUseCksum != 0 and cksum != cksum2) {
        p.rc = FTS5_CORRUPT;
        sqlite3Fts5ConfigErrmsg(
            p.pConfig.?,
            "fts5: checksum mismatch for table \"%s\"",
            p.pConfig.?.zName,
        );
    }
    if (p.rc == SQLITE_OK and bTestFail != 0) {
        p.rc = FTS5_CORRUPT;
    }
    sqlite3Fts5BufferFree(&term);

    fts5StructureRelease(pStruct);
    sqlite3Fts5BufferFree(&poslist);
    return fts5IndexReturn(p);
}

// ===========================================================================
// fts5_decode() debug scalar function (fts5_index.c 8754-9560).
// ===========================================================================

fn fts5DecodeRowid(
    iRowidIn: i64,
    pbTombstone: *c_int,
    piSegid: *c_int,
    pbDlidx: *c_int,
    piHeight: *c_int,
    piPgno: *c_int,
) void {
    var iRowid: i64 = iRowidIn;
    piPgno.* = @intCast(iRowid & ((@as(i64, 1) << FTS5_DATA_PAGE_B) - 1));
    iRowid >>= FTS5_DATA_PAGE_B;

    piHeight.* = @intCast(iRowid & ((@as(i64, 1) << FTS5_DATA_HEIGHT_B) - 1));
    iRowid >>= FTS5_DATA_HEIGHT_B;

    pbDlidx.* = @intCast(iRowid & 0x0001);
    iRowid >>= FTS5_DATA_DLI_B;

    piSegid.* = @intCast(iRowid & ((@as(i64, 1) << FTS5_DATA_ID_B) - 1));
    iRowid >>= FTS5_DATA_ID_B;

    pbTombstone.* = @intCast(iRowid & 0x0001);
}

fn fts5DebugRowid(pRc: *c_int, pBuf: *Fts5Buffer, iKey: i64) void {
    var iSegid: c_int = undefined;
    var iHeight: c_int = undefined;
    var iPgno: c_int = undefined;
    var bDlidx: c_int = undefined;
    var bTomb: c_int = undefined;
    fts5DecodeRowid(iKey, &bTomb, &iSegid, &bDlidx, &iHeight, &iPgno);

    if (iSegid == 0) {
        if (iKey == FTS5_AVERAGES_ROWID) {
            sqlite3Fts5BufferAppendPrintf(pRc, pBuf, "{averages} ");
        } else {
            sqlite3Fts5BufferAppendPrintf(pRc, pBuf, "{structure}");
        }
    } else {
        sqlite3Fts5BufferAppendPrintf(
            pRc,
            pBuf,
            "{%s%ssegid=%d h=%d pgno=%d}",
            if (bDlidx != 0) @as([*:0]const u8, "dlidx ") else @as([*:0]const u8, ""),
            if (bTomb != 0) @as([*:0]const u8, "tombstone ") else @as([*:0]const u8, ""),
            iSegid,
            iHeight,
            iPgno,
        );
    }
}

fn fts5DebugStructure(pRc: *c_int, pBuf: *Fts5Buffer, p: *Fts5Structure) void {
    var iLvl: c_int = 0;
    while (iLvl < p.nLevel) : (iLvl += 1) {
        const pLvl = structLevel(p, iLvl);
        sqlite3Fts5BufferAppendPrintf(
            pRc,
            pBuf,
            " {lvl=%d nMerge=%d nSeg=%d",
            iLvl,
            pLvl.nMerge,
            pLvl.nSeg,
        );
        var iSeg: c_int = 0;
        while (iSeg < pLvl.nSeg) : (iSeg += 1) {
            const pSeg = &pLvl.aSeg.?[@intCast(iSeg)];
            sqlite3Fts5BufferAppendPrintf(
                pRc,
                pBuf,
                " {id=%d leaves=%d..%d",
                pSeg.iSegid,
                pSeg.pgnoFirst,
                pSeg.pgnoLast,
            );
            if (pSeg.iOrigin1 > 0) {
                sqlite3Fts5BufferAppendPrintf(
                    pRc,
                    pBuf,
                    " origin=%lld..%lld",
                    pSeg.iOrigin1,
                    pSeg.iOrigin2,
                );
            }
            sqlite3Fts5BufferAppendPrintf(pRc, pBuf, "}");
        }
        sqlite3Fts5BufferAppendPrintf(pRc, pBuf, "}");
    }
}

fn fts5DecodeStructure(pRc: *c_int, pBuf: *Fts5Buffer, pBlob: [*]const u8, nBlob: c_int) void {
    var p: ?*Fts5Structure = null;
    const rc: c_int = fts5StructureDecode(pBlob, nBlob, null, &p);
    if (rc != SQLITE_OK) {
        pRc.* = rc;
        return;
    }
    fts5DebugStructure(pRc, pBuf, p.?);
    fts5StructureRelease(p);
}

fn fts5DecodeAverages(pRc: *c_int, pBuf: *Fts5Buffer, pBlob: [*]const u8, nBlob: c_int) void {
    var i: c_int = 0;
    var zSpace: [*:0]const u8 = "";
    while (i < nBlob) {
        var iVal: u64 = undefined;
        i += sqlite3Fts5GetVarint(pBlob + @as(usize, @intCast(i)), &iVal);
        sqlite3Fts5BufferAppendPrintf(pRc, pBuf, "%s%d", zSpace, @as(c_int, @bitCast(@as(u32, @truncate(iVal)))));
        zSpace = " ";
    }
}

fn fts5DecodePoslist(pRc: *c_int, pBuf: *Fts5Buffer, a: [*]const u8, n: c_int) c_int {
    var iOff: c_int = 0;
    while (iOff < n) {
        var iVal: c_int = undefined;
        iOff += fts5GetVarint32Into(c_int, a + @as(usize, @intCast(iOff)), &iVal);
        sqlite3Fts5BufferAppendPrintf(pRc, pBuf, " %d", iVal);
    }
    return iOff;
}

fn fts5DecodeDoclist(pRc: *c_int, pBuf: *Fts5Buffer, a: [*]const u8, n: c_int) c_int {
    var iDocid: i64 = 0;
    var iOff: c_int = 0;

    if (n > 0) {
        var u: u64 = undefined;
        iOff = sqlite3Fts5GetVarint(a, &u);
        iDocid = @bitCast(u);
        sqlite3Fts5BufferAppendPrintf(pRc, pBuf, " id=%lld", iDocid);
    }
    while (iOff < n) {
        var nPos: c_int = undefined;
        var bDel: c_int = undefined;
        iOff += fts5GetPoslistSize(a + @as(usize, @intCast(iOff)), &nPos, &bDel);
        sqlite3Fts5BufferAppendPrintf(pRc, pBuf, " nPos=%d%s", nPos, if (bDel != 0) @as([*:0]const u8, "*") else @as([*:0]const u8, ""));
        iOff += fts5DecodePoslist(pRc, pBuf, a + @as(usize, @intCast(iOff)), MIN(c_int, n - iOff, nPos));
        if (iOff < n) {
            var u: u64 = undefined;
            iOff += sqlite3Fts5GetVarint(a + @as(usize, @intCast(iOff)), &u);
            iDocid +%= @bitCast(u);
            sqlite3Fts5BufferAppendPrintf(pRc, pBuf, " id=%lld", iDocid);
        }
    }

    return iOff;
}

fn fts5DecodeRowidList(pRc: *c_int, pBuf: *Fts5Buffer, pData: [*]const u8, nData: c_int) void {
    var i: c_int = 0;
    var iRowid: i64 = 0;

    while (i < nData) {
        var zApp: [*:0]const u8 = "";
        var iVal: u64 = undefined;
        i += sqlite3Fts5GetVarint(pData + @as(usize, @intCast(i)), &iVal);
        iRowid +%= @bitCast(iVal);

        if (i < nData and pData[@intCast(i)] == 0x00) {
            i += 1;
            if (i < nData and pData[@intCast(i)] == 0x00) {
                i += 1;
                zApp = "+";
            } else {
                zApp = "*";
            }
        }

        sqlite3Fts5BufferAppendPrintf(pRc, pBuf, " %lld%s", iRowid, zApp);
    }
}

fn fts5BufferAppendTerm(pRc: *c_int, pBuf: *Fts5Buffer, pTerm: *Fts5Buffer) void {
    var ii: c_int = 0;
    _ = fts5BufferGrow(pRc, pBuf, pTerm.n * 2 + 1);
    if (pRc.* == SQLITE_OK) {
        ii = 0;
        while (ii < pTerm.n) : (ii += 1) {
            if (pTerm.p.?[@intCast(ii)] == 0x00) {
                pBuf.p.?[@intCast(pBuf.n)] = '\\';
                pBuf.n += 1;
                pBuf.p.?[@intCast(pBuf.n)] = '0';
                pBuf.n += 1;
            } else {
                pBuf.p.?[@intCast(pBuf.n)] = pTerm.p.?[@intCast(ii)];
                pBuf.n += 1;
            }
        }
        pBuf.p.?[@intCast(pBuf.n)] = 0x00;
    }
}

fn fts5DecodeFunction(
    pCtx: ?*sqlite3_context,
    nArg: c_int,
    apVal: [*]?*sqlite3_value,
) callconv(.c) void {
    var iRowid: i64 = undefined;
    var iSegid: c_int = undefined;
    var iHeight: c_int = undefined;
    var iPgno: c_int = undefined;
    var bDlidx: c_int = undefined;
    var bTomb: c_int = undefined;
    var aBlob: ?[*]const u8 = undefined;
    var n: c_int = undefined;
    var a: ?[*]u8 = null;
    var s: Fts5Buffer = undefined;
    var rc: c_int = SQLITE_OK;
    var nSpace: i64 = 0;
    const eDetailNone: c_int = @intFromBool(sqlite3_user_data(pCtx) != null);

    _ = nArg;
    _ = memset(&s, 0, @sizeOf(Fts5Buffer));
    iRowid = sqlite3_value_int64(apVal[0]);

    n = sqlite3_value_bytes(apVal[1]);
    aBlob = @ptrCast(sqlite3_value_blob(apVal[1]));
    nSpace = @as(i64, n) + FTS5_DATA_ZERO_PADDING;
    a = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nSpace)));

    decode_out: {
        if (a == null) break :decode_out;
        if (n > 0) _ = memcpy(a, aBlob, @intCast(n));

        fts5DecodeRowid(iRowid, &bTomb, &iSegid, &bDlidx, &iHeight, &iPgno);

        fts5DebugRowid(&rc, &s, iRowid);
        if (bDlidx != 0) {
            var dlidx: Fts5Data = undefined;
            var lvl: Fts5DlidxLvl = undefined;

            dlidx.p = a;
            dlidx.nn = n;

            _ = memset(&lvl, 0, @sizeOf(Fts5DlidxLvl));
            lvl.pData = &dlidx;
            lvl.iLeafPgno = iPgno;

            _ = fts5DlidxLvlNext(&lvl);
            while (lvl.bEof == 0) : (_ = fts5DlidxLvlNext(&lvl)) {
                sqlite3Fts5BufferAppendPrintf(&rc, &s, " %d(%lld)", lvl.iLeafPgno, lvl.iRowid);
            }
        } else if (bTomb != 0) {
            const nElem: u32 = fts5GetU32(a.? + 4);
            const szKey: c_int = if (aBlob.?[0] == 4 or aBlob.?[0] == 8) @as(c_int, aBlob.?[0]) else 8;
            const nSlot: c_int = @divTrunc(n - 8, szKey);
            var ii: c_int = 0;
            sqlite3Fts5BufferAppendPrintf(&rc, &s, " nElem=%d", @as(c_int, @bitCast(nElem)));
            if (aBlob.?[1] != 0) {
                sqlite3Fts5BufferAppendPrintf(&rc, &s, " 0");
            }
            ii = 0;
            while (ii < nSlot) : (ii += 1) {
                var iVal: u64 = 0;
                if (szKey == 4) {
                    const aSlot: [*]const u8 = aBlob.? + 8;
                    if (fts5GetU32(aSlot + @as(usize, @intCast(ii)) * 4) != 0) {
                        iVal = fts5GetU32(aSlot + @as(usize, @intCast(ii)) * 4);
                    }
                } else {
                    const aSlot: [*]const u8 = aBlob.? + 8;
                    if (fts5GetU64(aSlot + @as(usize, @intCast(ii)) * 8) != 0) {
                        iVal = fts5GetU64(aSlot + @as(usize, @intCast(ii)) * 8);
                    }
                }
                if (iVal != 0) {
                    sqlite3Fts5BufferAppendPrintf(&rc, &s, " %lld", @as(i64, @bitCast(iVal)));
                }
            }
        } else if (iSegid == 0) {
            if (iRowid == FTS5_AVERAGES_ROWID) {
                fts5DecodeAverages(&rc, &s, a.?, n);
            } else {
                fts5DecodeStructure(&rc, &s, a.?, n);
            }
        } else if (eDetailNone != 0) {
            var term: Fts5Buffer = undefined;
            var szLeaf: c_int = fts5GetU16(a.? + 2);
            var iPgidxOff: c_int = szLeaf;
            var iTermOff: c_int = undefined;
            var nKeep: c_int = 0;
            var iOff: c_int = undefined;

            _ = memset(&term, 0, @sizeOf(Fts5Buffer));

            // Decode any entries that occur before the first term.
            if (szLeaf < n) {
                iPgidxOff += fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iPgidxOff)), &iTermOff);
            } else {
                iTermOff = szLeaf;
            }
            fts5DecodeRowidList(&rc, &s, a.? + 4, iTermOff - 4);

            iOff = iTermOff;
            while (iOff < szLeaf and rc == SQLITE_OK) {
                var nAppend: c_int = undefined;

                // Read the term data for the next term
                iOff += fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iOff)), &nAppend);
                term.n = nKeep;
                sqlite3Fts5BufferAppendBlob(&rc, &term, @intCast(nAppend), a.? + @as(usize, @intCast(iOff)));
                sqlite3Fts5BufferAppendPrintf(&rc, &s, " term=");
                fts5BufferAppendTerm(&rc, &s, &term);
                iOff += nAppend;

                // Figure out where the doclist for this term ends
                if (iPgidxOff < n) {
                    var nIncr: c_int = undefined;
                    iPgidxOff += fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iPgidxOff)), &nIncr);
                    iTermOff += nIncr;
                } else {
                    iTermOff = szLeaf;
                }
                if (iTermOff > szLeaf) {
                    rc = FTS5_CORRUPT;
                } else {
                    fts5DecodeRowidList(&rc, &s, a.? + @as(usize, @intCast(iOff)), iTermOff - iOff);
                }
                iOff = iTermOff;
                if (iOff < szLeaf) {
                    iOff += fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iOff)), &nKeep);
                }
            }
            _ = &szLeaf;

            sqlite3Fts5BufferFree(&term);
        } else {
            var term: Fts5Buffer = undefined;
            var szLeaf: c_int = undefined;
            var iPgidxOff: c_int = undefined;
            var iPgidxPrev: c_int = 0;
            var iTermOff: c_int = 0;
            var iRowidOff: c_int = 0;
            var iOff: c_int = undefined;
            var nDoclist: c_int = undefined;

            _ = memset(&term, 0, @sizeOf(Fts5Buffer));

            if (n < 4) {
                sqlite3Fts5BufferSet(&rc, &s, 7, "corrupt");
                break :decode_out;
            } else {
                iRowidOff = fts5GetU16(a.? + 0);
                szLeaf = fts5GetU16(a.? + 2);
                iPgidxOff = szLeaf;
                if (iPgidxOff < n) {
                    _ = fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iPgidxOff)), &iTermOff);
                } else if (iPgidxOff > n) {
                    rc = FTS5_CORRUPT;
                    break :decode_out;
                }
            }

            // Decode the position list tail at the start of the page
            if (iRowidOff != 0) {
                iOff = iRowidOff;
            } else if (iTermOff != 0) {
                iOff = iTermOff;
            } else {
                iOff = szLeaf;
            }
            if (iOff > n) {
                rc = FTS5_CORRUPT;
                break :decode_out;
            }
            _ = fts5DecodePoslist(&rc, &s, a.? + 4, iOff - 4);

            // Decode any more doclist data that appears before the first term.
            nDoclist = (if (iTermOff != 0) iTermOff else szLeaf) - iOff;
            if (nDoclist + iOff > n) {
                rc = FTS5_CORRUPT;
                break :decode_out;
            }
            _ = fts5DecodeDoclist(&rc, &s, a.? + @as(usize, @intCast(iOff)), nDoclist);

            while (iPgidxOff < n and rc == SQLITE_OK) {
                const bFirst: c_int = @intFromBool(iPgidxOff == szLeaf);
                var nByte: c_int = undefined;
                var iEnd: c_int = undefined;

                iPgidxOff += fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iPgidxOff)), &nByte);
                iPgidxPrev += nByte;
                iOff = iPgidxPrev;

                if (iPgidxOff < n) {
                    _ = fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iPgidxOff)), &nByte);
                    iEnd = iPgidxPrev + nByte;
                } else {
                    iEnd = szLeaf;
                }
                if (iEnd > szLeaf) {
                    rc = FTS5_CORRUPT;
                    break;
                }

                if (bFirst == 0) {
                    iOff += fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iOff)), &nByte);
                    if (nByte > term.n) {
                        rc = FTS5_CORRUPT;
                        break;
                    }
                    term.n = nByte;
                }
                iOff += fts5GetVarint32Into(c_int, a.? + @as(usize, @intCast(iOff)), &nByte);
                if (iOff + nByte > n) {
                    rc = FTS5_CORRUPT;
                    break;
                }
                sqlite3Fts5BufferAppendBlob(&rc, &term, @intCast(nByte), a.? + @as(usize, @intCast(iOff)));
                iOff += nByte;

                sqlite3Fts5BufferAppendPrintf(&rc, &s, " term=");
                fts5BufferAppendTerm(&rc, &s, &term);
                iOff += fts5DecodeDoclist(&rc, &s, a.? + @as(usize, @intCast(iOff)), iEnd - iOff);
            }

            sqlite3Fts5BufferFree(&term);
        }
    }

    sqlite3_free(a);
    if (rc == SQLITE_OK) {
        sqlite3_result_text(pCtx, s.p, s.n, int.SQLITE_TRANSIENT);
    } else {
        sqlite3_result_error_code(pCtx, rc);
    }
    sqlite3Fts5BufferFree(&s);
}

fn fts5RowidFunction(
    pCtx: ?*sqlite3_context,
    nArg: c_int,
    apVal: [*]?*sqlite3_value,
) callconv(.c) void {
    if (nArg == 0) {
        sqlite3_result_error(pCtx, "should be: fts5_rowid(subject, ....)", -1);
    } else {
        const zArg: [*:0]const u8 = sqlite3_value_text(apVal[0]).?;
        if (0 == sqlite3_stricmp(zArg, "segment")) {
            if (nArg != 3) {
                sqlite3_result_error(pCtx, "should be: fts5_rowid('segment', segid, pgno))", -1);
            } else {
                const segid: c_int = sqlite3_value_int(apVal[1]);
                const pgno: c_int = sqlite3_value_int(apVal[2]);
                const iRowid: i64 = FTS5_SEGMENT_ROWID(segid, pgno);
                sqlite3_result_int64(pCtx, iRowid);
            }
        } else {
            sqlite3_result_error(pCtx, "first arg to fts5_rowid() must be 'segment'", -1);
        }
    }
}

// ===========================================================================
// fts5_structure() eponymous table-valued function (fts5_index.c 9382-9560).
// ===========================================================================

const Fts5StructVtab = extern struct {
    base: sqlite3_vtab,
};

const Fts5StructVcsr = extern struct {
    base: sqlite3_vtab_cursor,
    pStruct: ?*Fts5Structure,
    iLevel: c_int,
    iSeg: c_int,
    iRowid: c_int,
};

fn fts5structConnectMethod(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    _ = pAux;
    _ = argc;
    _ = argv;
    _ = pzErr;
    var pNew: ?*Fts5StructVtab = null;
    var rc: c_int = SQLITE_OK;

    rc = sqlite3_declare_vtab(db, "CREATE TABLE xyz(" ++
        "level, segment, merge, segid, leaf1, leaf2, loc1, loc2, " ++
        "npgtombstone, nentrytombstone, nentry, struct HIDDEN);");
    if (rc == SQLITE_OK) {
        pNew = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5StructVtab))));
    }

    ppVtab.* = @ptrCast(pNew);
    return rc;
}

fn fts5structBestIndexMethod(tab: *sqlite3_vtab, pIdxInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = tab;
    var i: c_int = 0;
    var rc: c_int = int.SQLITE_CONSTRAINT;
    pIdxInfo.estimatedCost = @as(f64, 100);
    pIdxInfo.estimatedRows = 100;
    pIdxInfo.idxNum = 0;
    const aConstraint = pIdxInfo.aConstraint.?;
    const aUsage = pIdxInfo.aConstraintUsage.?;
    while (i < pIdxInfo.nConstraint) : (i += 1) {
        const p = &aConstraint[@intCast(i)];
        if (p.usable == 0) continue;
        if (p.op == int.SQLITE_INDEX_CONSTRAINT_EQ and p.iColumn == 11) {
            rc = SQLITE_OK;
            aUsage[@intCast(i)].omit = 1;
            aUsage[@intCast(i)].argvIndex = 1;
            break;
        }
    }
    return rc;
}

fn fts5structDisconnectMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const p: *Fts5StructVtab = @ptrCast(@alignCast(pVtab));
    sqlite3_free(p);
    return SQLITE_OK;
}

fn fts5structOpenMethod(p: *sqlite3_vtab, ppCsr: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    _ = p;
    var rc: c_int = SQLITE_OK;
    const pNew: ?*Fts5StructVcsr = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5StructVcsr))));
    ppCsr.* = @ptrCast(pNew);
    return SQLITE_OK;
}

fn fts5structCloseMethod(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5StructVcsr = @ptrCast(@alignCast(cur));
    fts5StructureRelease(pCsr.pStruct);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

fn fts5structNextMethod(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5StructVcsr = @ptrCast(@alignCast(cur));
    const p: *Fts5Structure = pCsr.pStruct.?;

    pCsr.iSeg += 1;
    pCsr.iRowid += 1;
    while (pCsr.iLevel < p.nLevel and pCsr.iSeg >= structLevel(p, pCsr.iLevel).nSeg) {
        pCsr.iLevel += 1;
        pCsr.iSeg = 0;
    }
    if (pCsr.iLevel >= p.nLevel) {
        fts5StructureRelease(pCsr.pStruct);
        pCsr.pStruct = null;
    }
    return SQLITE_OK;
}

fn fts5structEofMethod(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5StructVcsr = @ptrCast(@alignCast(cur));
    return @intFromBool(pCsr.pStruct == null);
}

fn fts5structRowidMethod(cur: *sqlite3_vtab_cursor, piRowid: *i64) callconv(.c) c_int {
    const pCsr: *Fts5StructVcsr = @ptrCast(@alignCast(cur));
    piRowid.* = pCsr.iRowid;
    return SQLITE_OK;
}

fn fts5structColumnMethod(cur: *sqlite3_vtab_cursor, ctx: ?*sqlite3_context, i: c_int) callconv(.c) c_int {
    const pCsr: *Fts5StructVcsr = @ptrCast(@alignCast(cur));
    const p: *Fts5Structure = pCsr.pStruct.?;
    const pSeg = &structLevel(p, pCsr.iLevel).aSeg.?[@intCast(pCsr.iSeg)];

    switch (i) {
        0 => sqlite3_result_int(ctx, pCsr.iLevel), // level
        1 => sqlite3_result_int(ctx, pCsr.iSeg), // segment
        2 => sqlite3_result_int(ctx, @intFromBool(pCsr.iSeg < structLevel(p, pCsr.iLevel).nMerge)), // merge
        3 => sqlite3_result_int(ctx, pSeg.iSegid), // segid
        4 => sqlite3_result_int(ctx, pSeg.pgnoFirst), // leaf1
        5 => sqlite3_result_int(ctx, pSeg.pgnoLast), // leaf2
        6 => sqlite3_result_int64(ctx, @bitCast(pSeg.iOrigin1)), // origin1
        7 => sqlite3_result_int64(ctx, @bitCast(pSeg.iOrigin2)), // origin2
        8 => sqlite3_result_int(ctx, pSeg.nPgTombstone), // npgtombstone
        9 => sqlite3_result_int64(ctx, @bitCast(pSeg.nEntryTombstone)), // nentrytombstone
        10 => sqlite3_result_int64(ctx, @bitCast(pSeg.nEntry)), // nentry
        else => {},
    }
    return SQLITE_OK;
}

fn fts5structFilterMethod(
    pVtabCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = idxNum;
    _ = idxStr;
    _ = argc;
    const pCsr: *Fts5StructVcsr = @ptrCast(@alignCast(pVtabCursor));
    var rc: c_int = SQLITE_OK;

    var aBlob: ?[*]const u8 = null;
    var nBlob: c_int = 0;

    fts5StructureRelease(pCsr.pStruct);
    pCsr.pStruct = null;

    nBlob = sqlite3_value_bytes(argv.?[0]);
    aBlob = @ptrCast(sqlite3_value_blob(argv.?[0]));
    rc = fts5StructureDecode(aBlob.?, nBlob, null, &pCsr.pStruct);
    if (rc == SQLITE_OK) {
        pCsr.iLevel = 0;
        pCsr.iRowid = 0;
        pCsr.iSeg = -1;
        rc = fts5structNextMethod(pVtabCursor);
    }

    return rc;
}

// The fts5_structure eponymous vtab module (fts5_index.c 9540-9560).
const fts5structure_module: sqlite3_module = .{
    .iVersion = 0,
    .xCreate = null,
    .xConnect = fts5structConnectMethod,
    .xBestIndex = fts5structBestIndexMethod,
    .xDisconnect = fts5structDisconnectMethod,
    .xDestroy = null,
    .xOpen = fts5structOpenMethod,
    .xClose = fts5structCloseMethod,
    .xFilter = fts5structFilterMethod,
    .xNext = fts5structNextMethod,
    .xEof = fts5structEofMethod,
    .xColumn = fts5structColumnMethod,
    .xRowid = fts5structRowidMethod,
    .xUpdate = null,
    .xBegin = null,
    .xSync = null,
    .xCommit = null,
    .xRollback = null,
    .xFindFunction = null,
    .xRename = null,
    .xSavepoint = null,
    .xRelease = null,
    .xRollbackTo = null,
    .xShadowName = null,
    .xIntegrity = null,
};

export fn sqlite3Fts5IndexInit(db: ?*sqlite3) callconv(.c) c_int {
    var rc: c_int = sqlite3_create_function(
        db,
        "fts5_decode",
        2,
        SQLITE_UTF8,
        null,
        fts5DecodeFunction,
        null,
        null,
    );

    if (rc == SQLITE_OK) {
        rc = sqlite3_create_function(
            db,
            "fts5_decode_none",
            2,
            SQLITE_UTF8,
            @ptrCast(db),
            fts5DecodeFunction,
            null,
            null,
        );
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_create_function(
            db,
            "fts5_rowid",
            -1,
            SQLITE_UTF8,
            null,
            fts5RowidFunction,
            null,
            null,
        );
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_create_module(db, "fts5_structure", &fts5structure_module, null);
    }
    return rc;
}

export fn sqlite3Fts5IndexReset(p: *Fts5IndexS) callconv(.c) c_int {
    if (fts5IndexDataVersion(p) != p.iStructVersion) {
        fts5StructureInvalidate(p);
    }
    return fts5IndexReturn(p);
}

comptime {
    _ = int;
    _ = std;
    _ = config;
}
