//! Zig port of SQLite's FTS3/FTS4 index writer + segment merger
//! (ext/fts3/fts3_write.c).
//!
//! This translation unit implements the write-side of the FTS3/FTS4 extension:
//!
//!   * sqlite3Fts3UpdateMethod — the xUpdate() implementation (INSERT / UPDATE /
//!     DELETE on an fts3/fts4 table, plus the "special" command inserts
//!     rebuild/optimize/integrity-check/merge=/automerge=/flush).
//!   * The pending-terms hash tables (one per index) and their flush to disk.
//!   * The segment b-tree readers (Fts3SegReader / Fts3MultiSegReader) used by
//!     both this file and the query code in fts3.zig: SegReaderNew/Free/Pending,
//!     SegReaderStart/Step/Finish, MsrIncrStart/Next/Restart/Ovfl.
//!   * Segment writers (SegmentWriter) + the interior-node tree builder.
//!   * Incremental merge (sqlite3Fts3Incrmerge) and full optimize, plus the
//!     appendable-segment IncrmergeWriter / NodeReader machinery.
//!   * Doclist merging, %_stat doctotal maintenance, deferred tokens, and the
//!     integrity-check checksum machinery.
//!
//! Compiled because SQLITE_ENABLE_FTS4 (=> SQLITE_ENABLE_FTS3) is enabled.
//!
//! ABI coupling
//! ------------
//! Like its just-ported sibling fts3.zig, this file shares a large set of
//! structs from fts3Int.h (Fts3Table / Fts3Cursor / Fts3SegReader /
//! Fts3MultiSegReader / Fts3SegFilter / Fts3PhraseToken / Fts3DeferredToken /
//! Fts3Hash) with the still-C TUs (fts3_expr.c / fts3_snippet.c /
//! fts3_tokenizer.c) and the ported fts3.zig. Each shared struct is mirrored
//! here as an `extern struct`, field-for-field and byte-for-byte identical to
//! fts3.zig (which mirrors them the same way). `Fts3Table`'s trailing fields
//! exist only under SQLITE_DEBUG / SQLITE_TEST; they are config-gated via
//! `@import("config")` so sizeof() and the field offsets agree in both the
//! production and `--dev` builds.  No tools/offsets.c entry is needed: we
//! control the layout by mirroring it.
//!
//! Structs that are PRIVATE to fts3_write.c (PendingList, SegmentNode,
//! SegmentWriter, IncrmergeWriter, NodeWriter, NodeReader, Blob, Fts3SegReader
//! body) are defined here too, with internal layout — only fts3_write.c
//! touches them.

const std = @import("std");
const config = @import("config");

// ---------------------------------------------------------------------------
// Result codes (sqlite3.h)
// ---------------------------------------------------------------------------
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_AUTH: c_int = 23;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_MISMATCH: c_int = 20;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_CORRUPT_VTAB: c_int = SQLITE_CORRUPT | (1 << 8);

// Value/column types (sqlite3.h)
const SQLITE_INTEGER: c_int = 1;
const SQLITE_BLOB: c_int = 4;
const SQLITE_NULL: c_int = 5;

// On-conflict mode (sqlite3.h)
const SQLITE_REPLACE: c_int = 5;

// sqlite3_prepare_v3 flags (sqlite3.h)
const SQLITE_PREPARE_PERSISTENT: c_int = 0x01;
const SQLITE_PREPARE_NO_VTAB: c_int = 0x04;
const SQLITE_PREPARE_FROM_DDL: c_int = 0x20;

// ---------------------------------------------------------------------------
// Destructor sentinels (sqlite3.h): SQLITE_STATIC==0, SQLITE_TRANSIENT==-1.
// ---------------------------------------------------------------------------
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;

// ---------------------------------------------------------------------------
// fts3Int.h constants
// ---------------------------------------------------------------------------
const FTS3_VARINT_MAX: c_int = 10;
const FTS3_MAX_PENDING_DATA: c_int = 1 * 1024 * 1024;
const FTS3_MERGE_COUNT: c_int = 16;
const FTS3_SEGDIR_MAXLEVEL: c_int = 1024;

// fts3_write.c-local constants
const FTS_MAX_APPENDABLE_HEIGHT: c_int = 16;
const FTS3_NODE_PADDING: c_int = FTS3_VARINT_MAX * 2; // 20
const FTS3_NODE_CHUNKSIZE: c_int = 4 * 1024;
const FTS3_NODE_CHUNK_THRESHOLD: c_int = FTS3_NODE_CHUNKSIZE * 4;

// %_stat row ids (fts3_write.c)
const FTS_STAT_DOCTOTAL: c_int = 0;
const FTS_STAT_INCRMERGEHINT: c_int = 1;
const FTS_STAT_AUTOINCRMERGE: c_int = 2;

// SegReader special level values & filter flags (fts3Int.h)
const FTS3_SEGCURSOR_PENDING: c_int = -1;
const FTS3_SEGCURSOR_ALL: c_int = -2;
const FTS3_SEGMENT_REQUIRE_POS: c_int = 0x00000001;
const FTS3_SEGMENT_IGNORE_EMPTY: c_int = 0x00000002;
const FTS3_SEGMENT_COLUMN_FILTER: c_int = 0x00000004;
const FTS3_SEGMENT_PREFIX: c_int = 0x00000008;
const FTS3_SEGMENT_SCAN: c_int = 0x00000010;
const FTS3_SEGMENT_FIRST: c_int = 0x00000020;

// Largest/smallest 64-bit integers (fts3Int.h)
const LARGEST_INT64: i64 = 0x7fffffffffffffff;
const SMALLEST_INT64: i64 = -0x8000000000000000;

// SQL_XXX statement indices (fts3_write.c). Must match aStmt[] ordering.
const SQL_DELETE_CONTENT: c_int = 0;
const SQL_IS_EMPTY: c_int = 1;
const SQL_DELETE_ALL_CONTENT: c_int = 2;
const SQL_DELETE_ALL_SEGMENTS: c_int = 3;
const SQL_DELETE_ALL_SEGDIR: c_int = 4;
const SQL_DELETE_ALL_DOCSIZE: c_int = 5;
const SQL_DELETE_ALL_STAT: c_int = 6;
const SQL_SELECT_CONTENT_BY_ROWID: c_int = 7;
const SQL_NEXT_SEGMENT_INDEX: c_int = 8;
const SQL_INSERT_SEGMENTS: c_int = 9;
const SQL_NEXT_SEGMENTS_ID: c_int = 10;
const SQL_INSERT_SEGDIR: c_int = 11;
const SQL_SELECT_LEVEL: c_int = 12;
const SQL_SELECT_LEVEL_RANGE: c_int = 13;
const SQL_SELECT_LEVEL_COUNT: c_int = 14;
const SQL_SELECT_SEGDIR_MAX_LEVEL: c_int = 15;
const SQL_DELETE_SEGDIR_LEVEL: c_int = 16;
const SQL_DELETE_SEGMENTS_RANGE: c_int = 17;
const SQL_CONTENT_INSERT: c_int = 18;
const SQL_DELETE_DOCSIZE: c_int = 19;
const SQL_REPLACE_DOCSIZE: c_int = 20;
const SQL_SELECT_DOCSIZE: c_int = 21;
const SQL_SELECT_STAT: c_int = 22;
const SQL_REPLACE_STAT: c_int = 23;
const SQL_SELECT_ALL_PREFIX_LEVEL: c_int = 24;
const SQL_DELETE_ALL_TERMS_SEGDIR: c_int = 25;
const SQL_DELETE_SEGDIR_RANGE: c_int = 26;
const SQL_SELECT_ALL_LANGID: c_int = 27;
const SQL_FIND_MERGE_LEVEL: c_int = 28;
const SQL_MAX_LEAF_NODE_ESTIMATE: c_int = 29;
const SQL_DELETE_SEGDIR_ENTRY: c_int = 30;
const SQL_SHIFT_SEGDIR_ENTRY: c_int = 31;
const SQL_SELECT_SEGDIR: c_int = 32;
const SQL_CHOMP_SEGDIR: c_int = 33;
const SQL_SEGMENT_IS_APPENDABLE: c_int = 34;
const SQL_SELECT_INDEXES: c_int = 35;
const SQL_SELECT_MXLEVEL: c_int = 36;
const SQL_SELECT_LEVEL_RANGE2: c_int = 37;
const SQL_UPDATE_LEVEL_IDX: c_int = 38;
const SQL_UPDATE_LEVEL: c_int = 39;

const NSTMT: usize = 40;

// ---------------------------------------------------------------------------
// Public ABI opaque handles (sqlite3.h)
// ---------------------------------------------------------------------------
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_value = anyopaque;
const sqlite3_blob = anyopaque;

// ---------------------------------------------------------------------------
// Public ABI structs (sqlite3.h) — only the bits this file touches.
// ---------------------------------------------------------------------------
const sqlite3_module = opaque {};

const sqlite3_vtab = extern struct {
    pModule: ?*const sqlite3_module,
    nRef: c_int,
    zErrMsg: ?[*:0]u8,
};

const sqlite3_vtab_cursor = extern struct {
    pVtab: ?*sqlite3_vtab,
};

// ---------------------------------------------------------------------------
// Tokenizer module (fts3_tokenizer.h)
// ---------------------------------------------------------------------------
const sqlite3_tokenizer = extern struct {
    pModule: ?*const sqlite3_tokenizer_module,
};

const sqlite3_tokenizer_cursor = extern struct {
    pTokenizer: ?*sqlite3_tokenizer,
};

const XNextFn = ?*const fn (?*sqlite3_tokenizer_cursor, *?[*]const u8, *c_int, *c_int, *c_int, *c_int) callconv(.c) c_int;
const XCloseFn = ?*const fn (?*sqlite3_tokenizer_cursor) callconv(.c) c_int;

const sqlite3_tokenizer_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const anyopaque,
    xDestroy: ?*const anyopaque,
    xOpen: ?*const anyopaque,
    xClose: XCloseFn,
    xNext: XNextFn,
    xLanguageid: ?*const anyopaque,
};

// ---------------------------------------------------------------------------
// Fts3Hash (fts3_hash.h) — mirrored byte-for-byte (matches fts3.zig).
// ---------------------------------------------------------------------------
const Fts3HashElem = extern struct {
    next: ?*Fts3HashElem,
    prev: ?*Fts3HashElem,
    data: ?*anyopaque,
    pKey: ?*anyopaque,
    nKey: c_int,
};
const struct_fts3ht = opaque {};
const Fts3Hash = extern struct {
    keyClass: u8, // char
    copyKey: u8, // char
    count: c_int,
    first: ?*Fts3HashElem,
    htsize: c_int,
    ht: ?*struct_fts3ht,
};

// fts3_hash.h macros
inline fn fts3HashFirst(h: *Fts3Hash) ?*Fts3HashElem {
    return h.first;
}
inline fn fts3HashNext(e: *Fts3HashElem) ?*Fts3HashElem {
    return e.next;
}
inline fn fts3HashData(e: *Fts3HashElem) ?*anyopaque {
    return e.data;
}
inline fn fts3HashKey(e: *Fts3HashElem) ?*anyopaque {
    return e.pKey;
}
inline fn fts3HashKeysize(e: *Fts3HashElem) c_int {
    return e.nKey;
}

// ---------------------------------------------------------------------------
// ABI-SHARED fts3 structs (fts3Int.h). Mirror fts3.zig exactly.
// ---------------------------------------------------------------------------

/// fts3Int.h: struct Fts3Index { int nPrefix; Fts3Hash hPending; }.
const Fts3Index = extern struct {
    nPrefix: c_int,
    hPending: Fts3Hash,
};

const Fts3Table = extern struct {
    base: sqlite3_vtab,
    db: ?*sqlite3,
    zDb: ?[*:0]const u8,
    zName: ?[*:0]const u8,
    nColumn: c_int,
    azColumn: ?[*]?[*:0]u8,
    abNotindexed: ?[*]u8,
    pTokenizer: ?*sqlite3_tokenizer,
    zContentTbl: ?[*:0]u8,
    zLanguageid: ?[*:0]u8,
    nAutoincrmerge: c_int,
    nLeafAdd: u32,
    bLock: c_int,

    aStmt: [40]?*sqlite3_stmt,
    pSeekStmt: ?*sqlite3_stmt,

    zReadExprlist: ?[*:0]u8,
    zWriteExprlist: ?[*:0]u8,

    nNodeSize: c_int,
    bFts4: u8,
    bHasStat: u8,
    bHasDocsize: u8,
    bDescIdx: u8,
    bIgnoreSavepoint: u8,
    nPgsz: c_int,
    zSegmentsTbl: ?[*:0]u8,
    pSegments: ?*sqlite3_blob,
    iSavepoint: c_int,

    nIndex: c_int,
    aIndex: ?[*]Fts3Index,
    nMaxPendingData: c_int,
    nPendingData: c_int,
    iPrevDocid: i64,
    iPrevLangid: c_int,
    bPrevDelete: c_int,

    // Trailing fields gated by build config (testfixture only).
    inTransaction: if (config.sqlite_debug) c_int else void =
        if (config.sqlite_debug) 0 else {},
    mxSavepoint: if (config.sqlite_debug) c_int else void =
        if (config.sqlite_debug) 0 else {},
    bNoIncrDoclist: if (config.sqlite_debug or config.sqlite_test) c_int else void =
        if (config.sqlite_debug or config.sqlite_test) 0 else {},
    nMergeCount: if (config.sqlite_debug or config.sqlite_test) c_int else void =
        if (config.sqlite_debug or config.sqlite_test) 0 else {},
};

const MatchinfoBuffer = opaque {};

const Fts3Cursor = extern struct {
    base: sqlite3_vtab_cursor,
    eSearch: i16,
    isEof: u8,
    isRequireSeek: u8,
    bSeekStmt: u8,
    pStmt: ?*sqlite3_stmt,
    pExpr: ?*anyopaque,
    iLangid: c_int,
    nPhrase: c_int,
    pDeferred: ?*Fts3DeferredToken,
    iPrevId: i64,
    pNextId: ?[*]u8,
    aDoclist: ?[*]u8,
    nDoclist: c_int,
    bDesc: u8,
    eEvalmode: c_int,
    nRowAvg: c_int,
    nDoc: i64,
    iMinDocid: i64,
    iMaxDocid: i64,
    isMatchinfoNeeded: c_int,
    pMIBuffer: ?*MatchinfoBuffer,
};

/// fts3Int.h: struct Fts3PhraseToken (shared with fts3_expr.c / fts3.zig).
const Fts3PhraseToken = extern struct {
    z: ?[*]u8,
    n: c_int,
    isPrefix: c_int,
    bFirst: c_int,
    pDeferred: ?*Fts3DeferredToken,
    pSegcsr: ?*Fts3MultiSegReader,
};

const Fts3SegFilter = extern struct {
    zTerm: ?[*:0]const u8,
    nTerm: c_int,
    iCol: c_int,
    flags: c_int,
};

const Fts3MultiSegReader = extern struct {
    apSegment: ?[*]?*Fts3SegReader,
    nSegment: c_int,
    nAdvance: c_int,
    pFilter: ?*Fts3SegFilter,
    aBuffer: ?[*]u8,
    nBuffer: i64,

    iColFilter: c_int,
    bRestart: c_int,

    nCost: c_int,
    bLookup: c_int,

    zTerm: ?[*]u8,
    nTerm: c_int,
    aDoclist: ?[*]u8,
    nDoclist: c_int,
};

// ---------------------------------------------------------------------------
// fts3_write.c-PRIVATE structs (only this file touches them; internal layout).
// ---------------------------------------------------------------------------

const PendingList = extern struct {
    nData: i64,
    aData: ?[*]u8,
    nSpace: i64,
    iLastDocid: i64,
    iLastCol: i64,
    iLastPos: i64,
};

/// fts3Int.h: struct Fts3DeferredToken (the body is fts3_write.c-private, but
/// it is typedef'd in fts3Int.h; pCsr->pDeferred is walked from fts3.zig as an
/// opaque pointer, so the body layout is ours).
const Fts3DeferredToken = extern struct {
    pToken: ?*Fts3PhraseToken,
    iCol: c_int,
    pNext: ?*Fts3DeferredToken,
    pList: ?*PendingList,
};

const Fts3SegReader = extern struct {
    iIdx: c_int, // Index within level, or 0x7FFFFFFF for PT
    bLookup: u8,
    rootOnly: u8,

    iStartBlock: i64,
    iLeafEndBlock: i64,
    iEndBlock: i64,
    iCurrentBlock: i64,

    aNode: ?[*]u8,
    nNode: c_int,
    nPopulate: c_int,
    pBlob: ?*sqlite3_blob,

    ppNextElem: ?[*]?*Fts3HashElem,

    nTerm: c_int,
    zTerm: ?[*]u8,
    nTermAlloc: c_int,
    aDoclist: ?[*]u8,
    nDoclist: c_int,

    pOffsetList: ?[*]u8,
    nOffsetList: c_int,
    iDocid: i64,
};

inline fn fts3SegReaderIsPending(p: *Fts3SegReader) bool {
    return p.ppNextElem != null;
}
inline fn fts3SegReaderIsRootOnly(p: *Fts3SegReader) bool {
    return p.rootOnly != 0;
}

const SegmentNode = extern struct {
    pParent: ?*SegmentNode,
    pRight: ?*SegmentNode,
    pLeftmost: ?*SegmentNode,
    nEntry: c_int,
    zTerm: ?[*]u8,
    nTerm: c_int,
    nMalloc: c_int,
    zMalloc: ?[*]u8,
    nData: c_int,
    aData: ?[*]u8,
};

const SegmentWriter = extern struct {
    pTree: ?*SegmentNode,
    iFirst: i64,
    iFree: i64,
    zTerm: ?[*]u8,
    nTerm: c_int,
    nMalloc: c_int,
    zMalloc: ?[*]u8,
    nSize: c_int,
    nData: c_int,
    aData: ?[*]u8,
    nLeafData: i64,
};

const Blob = extern struct {
    a: ?[*]u8,
    n: c_int,
    nAlloc: c_int,
};

const NodeWriter = extern struct {
    iBlock: i64,
    key: Blob,
    block: Blob,
};

const IncrmergeWriter = extern struct {
    nLeafEst: i64,
    nWork: i64,
    iAbsLevel: i64,
    iIdx: c_int,
    iStart: i64,
    iEnd: i64,
    nLeafData: i64,
    bNoLeafData: u8,
    aNodeWriter: [16]NodeWriter,
};

const NodeReader = extern struct {
    aNode: ?[*]const u8,
    nNode: c_int,
    iOff: c_int,

    iChild: i64,
    term: Blob,
    aDoclist: ?[*]const u8,
    nDoclist: c_int,
};

// ---------------------------------------------------------------------------
// libc + public sqlite3 API resolved at link time
// ---------------------------------------------------------------------------
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn qsort(base: ?*anyopaque, nmemb: usize, size: usize, cmp: *const fn (?*const anyopaque, ?*const anyopaque) callconv(.c) c_int) void;
extern fn atoi(s: [*:0]const u8) c_int;

extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_strnicmp(a: [*:0]const u8, b: [*:0]const u8, n: c_int) c_int;

extern fn sqlite3_exec(db: ?*sqlite3, sql: [*:0]const u8, cb: ?*anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_prepare_v3(db: ?*sqlite3, sql: [*:0]const u8, n: c_int, f: c_uint, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;

extern fn sqlite3_bind_int(pStmt: ?*sqlite3_stmt, i: c_int, v: c_int) c_int;
extern fn sqlite3_bind_int64(pStmt: ?*sqlite3_stmt, i: c_int, v: i64) c_int;
extern fn sqlite3_bind_null(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_bind_value(pStmt: ?*sqlite3_stmt, i: c_int, v: ?*sqlite3_value) c_int;
extern fn sqlite3_bind_blob(pStmt: ?*sqlite3_stmt, i: c_int, z: ?*const anyopaque, n: c_int, xDel: DestructorFn) c_int;
extern fn sqlite3_bind_text(pStmt: ?*sqlite3_stmt, i: c_int, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) c_int;
extern fn sqlite3_bind_parameter_count(pStmt: ?*sqlite3_stmt) c_int;

extern fn sqlite3_column_int(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, i: c_int) i64;
extern fn sqlite3_column_type(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_bytes(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_blob(pStmt: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_text(pStmt: ?*sqlite3_stmt, i: c_int) ?[*:0]const u8;

extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_int(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(p: ?*sqlite3_value) i64;
extern fn sqlite3_value_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_bytes(p: ?*sqlite3_value) c_int;

extern fn sqlite3_last_insert_rowid(db: ?*sqlite3) i64;
extern fn sqlite3_vtab_on_conflict(db: ?*sqlite3) c_int;

extern fn sqlite3_blob_open(db: ?*sqlite3, zDb: ?[*:0]const u8, zTable: ?[*:0]const u8, zCol: ?[*:0]const u8, iRow: i64, flags: c_int, ppBlob: *?*sqlite3_blob) c_int;
extern fn sqlite3_blob_reopen(pBlob: ?*sqlite3_blob, iRow: i64) c_int;
extern fn sqlite3_blob_read(pBlob: ?*sqlite3_blob, z: ?*anyopaque, n: c_int, iOffset: c_int) c_int;
extern fn sqlite3_blob_bytes(pBlob: ?*sqlite3_blob) c_int;
extern fn sqlite3_blob_close(pBlob: ?*sqlite3_blob) c_int;

// fts3_hash.c
extern fn sqlite3Fts3HashFind(h: *Fts3Hash, pKey: ?*const anyopaque, nKey: c_int) ?*anyopaque;
extern fn sqlite3Fts3HashFindElem(h: *Fts3Hash, pKey: ?*const anyopaque, nKey: c_int) ?*Fts3HashElem;
extern fn sqlite3Fts3HashInsert(h: *Fts3Hash, pKey: ?*const anyopaque, nKey: c_int, pData: ?*anyopaque) ?*anyopaque;
extern fn sqlite3Fts3HashClear(h: *Fts3Hash) void;

// fts3.zig (ported sibling): varint codec + query helpers used here.
extern fn sqlite3Fts3PutVarint(p: [*]u8, v: i64) c_int;
extern fn sqlite3Fts3GetVarint(p: [*]const u8, v: *i64) c_int;
extern fn sqlite3Fts3GetVarintU(p: [*]const u8, v: *u64) c_int;
extern fn sqlite3Fts3GetVarint32(p: [*]const u8, pi: *c_int) c_int;
extern fn sqlite3Fts3VarintLen(v: u64) c_int;
extern fn sqlite3Fts3SegReaderCursor(p: *Fts3Table, iLangid: c_int, iIndex: c_int, iLevel: c_int, zTerm: ?[*]const u8, nTerm: c_int, isPrefix: c_int, isScan: c_int, pCsr: *Fts3MultiSegReader) c_int;
extern fn sqlite3Fts3DoclistPrev(bDescIdx: c_int, aDoclist: [*]u8, nDoclist: c_int, ppIter: *?[*]u8, piDocid: *i64, pnList: *c_int, pbEof: *u8) void;
extern fn sqlite3Fts3FirstFilter(iDelta: i64, pList: [*]u8, nList: c_int, aOut: [*]u8) c_int;

// fts3_tokenizer.c
extern fn sqlite3Fts3OpenTokenizer(pTokenizer: *sqlite3_tokenizer, iLangid: c_int, zInput: ?[*:0]const u8, nBytes: c_int, ppCsr: *?*sqlite3_tokenizer_cursor) c_int;

// In SQLITE_DEBUG builds the corruption code is routed through this function
// (defined in fts3.zig). Mirror that so the returned code matches in both
// configs.
extern fn sqlite3Fts3Corrupt() c_int;

inline fn FTS_CORRUPT_VTAB() c_int {
    if (config.sqlite_debug) {
        return sqlite3Fts3Corrupt();
    }
    return SQLITE_CORRUPT_VTAB;
}

/// fts3Int.h MergeCount(P) macro: nMergeCount field in DEBUG/TEST builds, the
/// constant FTS3_MERGE_COUNT otherwise.
inline fn MergeCount(p: *Fts3Table) c_int {
    if (config.sqlite_debug or config.sqlite_test) {
        return p.nMergeCount;
    }
    return FTS3_MERGE_COUNT;
}

inline fn imin(a: anytype, b: @TypeOf(a)) @TypeOf(a) {
    return if (a < b) a else b;
}
inline fn imax(a: anytype, b: @TypeOf(a)) @TypeOf(a) {
    return if (a > b) a else b;
}

/// fts3GetVarint32 macro: 1-byte fast path or fall to sqlite3Fts3GetVarint32.
inline fn fts3GetVarint32(p: [*]const u8, piVal: *c_int) c_int {
    if ((p[0] & 0x80) != 0) {
        return sqlite3Fts3GetVarint32(p, piVal);
    }
    piVal.* = p[0];
    return 1;
}

// ===========================================================================
// Prepared statements
// ===========================================================================

/// Wrapper around sqlite3_prepare_v3() that always sets SQLITE_PREPARE_FROM_DDL.
export fn sqlite3Fts3PrepareStmt(
    p: *Fts3Table,
    zSql: [*:0]const u8,
    bPersist: c_int,
    bAllowVtab: c_int,
    pp: *?*sqlite3_stmt,
) callconv(.c) c_int {
    var f: c_int = SQLITE_PREPARE_FROM_DDL;
    if (bAllowVtab == 0) f |= SQLITE_PREPARE_NO_VTAB;
    if (bPersist != 0) f |= SQLITE_PREPARE_PERSISTENT;
    return sqlite3_prepare_v3(p.db, zSql, -1, @bitCast(f), pp, null);
}

const azSql = [_][*:0]const u8{
    "DELETE FROM %Q.'%q_content' WHERE rowid = ?",
    "SELECT NOT EXISTS(SELECT docid FROM %Q.'%q_content' WHERE rowid!=?)",
    "DELETE FROM %Q.'%q_content'",
    "DELETE FROM %Q.'%q_segments'",
    "DELETE FROM %Q.'%q_segdir'",
    "DELETE FROM %Q.'%q_docsize'",
    "DELETE FROM %Q.'%q_stat'",
    "SELECT %s WHERE rowid=?",
    "SELECT (SELECT max(idx) FROM %Q.'%q_segdir' WHERE level = ?) + 1",
    "REPLACE INTO %Q.'%q_segments'(blockid, block) VALUES(?, ?)",
    "SELECT coalesce((SELECT max(blockid) FROM %Q.'%q_segments') + 1, 1)",
    "REPLACE INTO %Q.'%q_segdir' VALUES(?,?,?,?,?,?)",
    "SELECT idx, start_block, leaves_end_block, end_block, root " ++
        "FROM %Q.'%q_segdir' WHERE level = ? ORDER BY idx ASC",
    "SELECT idx, start_block, leaves_end_block, end_block, root " ++
        "FROM %Q.'%q_segdir' WHERE level BETWEEN ? AND ?" ++
        "ORDER BY level DESC, idx ASC",
    "SELECT count(*) FROM %Q.'%q_segdir' WHERE level = ?",
    "SELECT max(level) FROM %Q.'%q_segdir' WHERE level BETWEEN ? AND ?",
    "DELETE FROM %Q.'%q_segdir' WHERE level = ?",
    "DELETE FROM %Q.'%q_segments' WHERE blockid BETWEEN ? AND ?",
    "INSERT INTO %Q.'%q_content' VALUES(%s)",
    "DELETE FROM %Q.'%q_docsize' WHERE docid = ?",
    "REPLACE INTO %Q.'%q_docsize' VALUES(?,?)",
    "SELECT size FROM %Q.'%q_docsize' WHERE docid=?",
    "SELECT value FROM %Q.'%q_stat' WHERE id=?",
    "REPLACE INTO %Q.'%q_stat' VALUES(?,?)",
    "",
    "",
    "DELETE FROM %Q.'%q_segdir' WHERE level BETWEEN ? AND ?",
    "SELECT ? UNION SELECT level / (1024 * ?) FROM %Q.'%q_segdir'",
    "SELECT level, count(*) AS cnt FROM %Q.'%q_segdir' " ++
        "  GROUP BY level HAVING cnt>=?" ++
        "  ORDER BY (level %% 1024) ASC, 2 DESC LIMIT 1",
    "SELECT 2 * total(1 + leaves_end_block - start_block) " ++
        "  FROM (SELECT * FROM %Q.'%q_segdir' " ++
        "        WHERE level = ? ORDER BY idx ASC LIMIT ?" ++
        "  )",
    "DELETE FROM %Q.'%q_segdir' WHERE level = ? AND idx = ?",
    "UPDATE %Q.'%q_segdir' SET idx = ? WHERE level=? AND idx=?",
    "SELECT idx, start_block, leaves_end_block, end_block, root " ++
        "FROM %Q.'%q_segdir' WHERE level = ? AND idx = ?",
    "UPDATE %Q.'%q_segdir' SET start_block = ?, root = ?" ++
        "WHERE level = ? AND idx = ?",
    "SELECT 1 FROM %Q.'%q_segments' WHERE blockid=? AND block IS NULL",
    "SELECT idx FROM %Q.'%q_segdir' WHERE level=? ORDER BY 1 ASC",
    "SELECT max( level %% 1024 ) FROM %Q.'%q_segdir'",
    "SELECT level, idx, end_block " ++
        "FROM %Q.'%q_segdir' WHERE level BETWEEN ? AND ? " ++
        "ORDER BY level DESC, idx ASC",
    "UPDATE OR FAIL %Q.'%q_segdir' SET level=-1,idx=? " ++
        "WHERE level=? AND idx=?",
    "UPDATE OR FAIL %Q.'%q_segdir' SET level=? WHERE level=-1",
};

/// Obtain (and cache) the prepared statement identified by eStmt, binding apVal
/// if non-NULL.
fn fts3SqlStmt(
    p: *Fts3Table,
    eStmt: c_int,
    pp: *?*sqlite3_stmt,
    apVal: ?[*]?*sqlite3_value,
) c_int {
    var rc: c_int = SQLITE_OK;
    const idx: usize = @intCast(eStmt);
    var pStmt = p.aStmt[idx];
    if (pStmt == null) {
        var bAllowVtab: c_int = 0;
        var zSql: ?[*:0]u8 = undefined;
        if (eStmt == SQL_CONTENT_INSERT) {
            zSql = sqlite3_mprintf(azSql[idx], p.zDb.?, p.zName.?, p.zWriteExprlist);
        } else if (eStmt == SQL_SELECT_CONTENT_BY_ROWID) {
            bAllowVtab = 1;
            zSql = sqlite3_mprintf(azSql[idx], p.zReadExprlist);
        } else {
            zSql = sqlite3_mprintf(azSql[idx], p.zDb.?, p.zName.?);
        }
        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3Fts3PrepareStmt(p, zSql.?, 1, bAllowVtab, &pStmt);
            sqlite3_free(zSql);
            p.aStmt[idx] = pStmt;
        }
    }
    if (apVal) |av| {
        const nParam = sqlite3_bind_parameter_count(pStmt);
        var i: c_int = 0;
        while (rc == SQLITE_OK and i < nParam) : (i += 1) {
            rc = sqlite3_bind_value(pStmt, i + 1, av[@intCast(i)]);
        }
    }
    pp.* = pStmt;
    return rc;
}

fn fts3SelectDocsize(pTab: *Fts3Table, iDocid: i64, ppStmt: *?*sqlite3_stmt) c_int {
    var pStmt: ?*sqlite3_stmt = null;
    var rc = fts3SqlStmt(pTab, SQL_SELECT_DOCSIZE, &pStmt, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pStmt, 1, iDocid);
        rc = sqlite3_step(pStmt);
        if (rc != SQLITE_ROW or sqlite3_column_type(pStmt, 0) != SQLITE_BLOB) {
            rc = sqlite3_reset(pStmt);
            if (rc == SQLITE_OK) rc = FTS_CORRUPT_VTAB();
            pStmt = null;
        } else {
            rc = SQLITE_OK;
        }
    }
    ppStmt.* = pStmt;
    return rc;
}

export fn sqlite3Fts3SelectDoctotal(pTab: *Fts3Table, ppStmt: *?*sqlite3_stmt) callconv(.c) c_int {
    var pStmt: ?*sqlite3_stmt = null;
    const rc = fts3SqlStmt(pTab, SQL_SELECT_STAT, &pStmt, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int(pStmt, 1, FTS_STAT_DOCTOTAL);
        if (sqlite3_step(pStmt) != SQLITE_ROW or sqlite3_column_type(pStmt, 0) != SQLITE_BLOB) {
            var rc2 = sqlite3_reset(pStmt);
            if (rc2 == SQLITE_OK) rc2 = FTS_CORRUPT_VTAB();
            pStmt = null;
            ppStmt.* = pStmt;
            return rc2;
        }
    }
    ppStmt.* = pStmt;
    return rc;
}

export fn sqlite3Fts3SelectDocsize(pTab: *Fts3Table, iDocid: i64, ppStmt: *?*sqlite3_stmt) callconv(.c) c_int {
    return fts3SelectDocsize(pTab, iDocid, ppStmt);
}

/// Run statement eStmt with bound apVal. No-op if *pRC.
fn fts3SqlExec(pRC: *c_int, p: *Fts3Table, eStmt: c_int, apVal: ?[*]?*sqlite3_value) void {
    if (pRC.* != 0) return;
    var pStmt: ?*sqlite3_stmt = undefined;
    var rc = fts3SqlStmt(p, eStmt, &pStmt, apVal);
    if (rc == SQLITE_OK) {
        _ = sqlite3_step(pStmt);
        rc = sqlite3_reset(pStmt);
    }
    pRC.* = rc;
}

/// Acquire an exclusive shared-cache table-lock on %_segdir.
fn fts3Writelock(p: *Fts3Table) c_int {
    var rc: c_int = SQLITE_OK;
    if (p.nPendingData == 0) {
        var pStmt: ?*sqlite3_stmt = undefined;
        rc = fts3SqlStmt(p, SQL_DELETE_SEGDIR_LEVEL, &pStmt, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_null(pStmt, 1);
            _ = sqlite3_step(pStmt);
            rc = sqlite3_reset(pStmt);
        }
    }
    return rc;
}

/// Convert (langid, index, level) to the encoded 64-bit absolute level.
fn getAbsoluteLevel(p: *Fts3Table, iLangid: c_int, iIndex: c_int, iLevel: c_int) i64 {
    const iBase: i64 = (@as(i64, iLangid) * p.nIndex + iIndex) * FTS3_SEGDIR_MAXLEVEL;
    return iBase + iLevel;
}

export fn sqlite3Fts3AllSegdirs(
    p: *Fts3Table,
    iLangid: c_int,
    iIndex: c_int,
    iLevel: c_int,
    ppStmt: *?*sqlite3_stmt,
) callconv(.c) c_int {
    var rc: c_int = undefined;
    var pStmt: ?*sqlite3_stmt = null;

    if (iLevel < 0) {
        rc = fts3SqlStmt(p, SQL_SELECT_LEVEL_RANGE, &pStmt, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pStmt, 1, getAbsoluteLevel(p, iLangid, iIndex, 0));
            _ = sqlite3_bind_int64(pStmt, 2, getAbsoluteLevel(p, iLangid, iIndex, FTS3_SEGDIR_MAXLEVEL - 1));
        }
    } else {
        rc = fts3SqlStmt(p, SQL_SELECT_LEVEL, &pStmt, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pStmt, 1, getAbsoluteLevel(p, iLangid, iIndex, iLevel));
        }
    }
    ppStmt.* = pStmt;
    return rc;
}

// ===========================================================================
// PendingList — incrementally-built doclist buffer (fts3_write.c private).
// ===========================================================================

fn pendingDataPtr(p: *PendingList) [*]u8 {
    // p->aData == (char*)&p[1]
    const base: [*]u8 = @ptrCast(p);
    return base + @sizeOf(PendingList);
}

/// Append a single varint to a PendingList buffer (allocating it if needed).
fn fts3PendingListAppendVarint(pp: *?*PendingList, i: i64) c_int {
    var p = pp.*;
    if (p == null) {
        p = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(PendingList) + 100) orelse return SQLITE_NOMEM));
        p.?.nSpace = 100;
        p.?.aData = pendingDataPtr(p.?);
        p.?.nData = 0;
    } else if (p.?.nData + FTS3_VARINT_MAX + 1 > p.?.nSpace) {
        const nNew: i64 = p.?.nSpace * 2;
        const pNew: ?*PendingList = @ptrCast(@alignCast(sqlite3_realloc64(p, @intCast(@as(i64, @sizeOf(PendingList)) + nNew))));
        if (pNew == null) {
            sqlite3_free(pp.*);
            pp.* = null;
            return SQLITE_NOMEM;
        }
        p = pNew;
        p.?.nSpace = nNew;
        p.?.aData = pendingDataPtr(p.?);
    }

    const aData = p.?.aData.?;
    const n: usize = @intCast(p.?.nData);
    p.?.nData += sqlite3Fts3PutVarint(aData + n, i);
    aData[@intCast(p.?.nData)] = 0;
    pp.* = p;
    return SQLITE_OK;
}

/// Add a docid/column/position entry to a PendingList. Returns 1 if realloced.
fn fts3PendingListAppend(
    pp: *?*PendingList,
    iDocid: i64,
    iCol: i64,
    iPos: i64,
    pRc: *c_int,
) c_int {
    var p = pp.*;
    var rc: c_int = SQLITE_OK;

    if (p == null or p.?.iLastDocid != iDocid) {
        const prevLast: u64 = if (p) |pp2| @bitCast(pp2.iLastDocid) else 0;
        const iDelta: u64 = @as(u64, @bitCast(iDocid)) -% prevLast;
        if (p) |pp2| {
            pp2.nData += 1;
        }
        rc = fts3PendingListAppendVarint(&p, @bitCast(iDelta));
        if (rc != SQLITE_OK) {
            pRc.* = rc;
            if (p != pp.*) {
                pp.* = p;
                return 1;
            }
            return 0;
        }
        p.?.iLastCol = -1;
        p.?.iLastPos = 0;
        p.?.iLastDocid = iDocid;
    }
    if (iCol > 0 and p.?.iLastCol != iCol) {
        rc = fts3PendingListAppendVarint(&p, 1);
        if (rc == SQLITE_OK) rc = fts3PendingListAppendVarint(&p, iCol);
        if (rc != SQLITE_OK) {
            pRc.* = rc;
            if (p != pp.*) {
                pp.* = p;
                return 1;
            }
            return 0;
        }
        p.?.iLastCol = iCol;
        p.?.iLastPos = 0;
    }
    if (iCol >= 0) {
        rc = fts3PendingListAppendVarint(&p, 2 + iPos - p.?.iLastPos);
        if (rc == SQLITE_OK) {
            p.?.iLastPos = iPos;
        }
    }

    pRc.* = rc;
    if (p != pp.*) {
        pp.* = p;
        return 1;
    }
    return 0;
}

fn fts3PendingListDelete(pList: ?*PendingList) void {
    sqlite3_free(pList);
}

/// Add an entry to one of the pending-terms hash tables.
fn fts3PendingTermsAddOne(
    p: *Fts3Table,
    iCol: c_int,
    iPos: c_int,
    pHash: *Fts3Hash,
    zToken: [*]const u8,
    nToken: c_int,
) c_int {
    var rc: c_int = SQLITE_OK;
    var pList: ?*PendingList = @ptrCast(@alignCast(sqlite3Fts3HashFind(pHash, zToken, nToken)));
    if (pList) |pl| {
        p.nPendingData -= @intCast(pl.nData + nToken + @sizeOf(Fts3HashElem));
    }
    if (fts3PendingListAppend(&pList, p.iPrevDocid, iCol, iPos, &rc) != 0) {
        if (pList == @as(?*PendingList, @ptrCast(@alignCast(sqlite3Fts3HashInsert(pHash, zToken, nToken, pList))))) {
            // Malloc failed while inserting the new entry.
            sqlite3_free(pList);
            rc = SQLITE_NOMEM;
        }
    }
    if (rc == SQLITE_OK) {
        p.nPendingData += @intCast(pList.?.nData + nToken + @sizeOf(Fts3HashElem));
    }
    return rc;
}

/// Tokenize zText and add all tokens to the pending-terms hash tables.
fn fts3PendingTermsAdd(
    p: *Fts3Table,
    iLangid: c_int,
    zText: ?[*:0]const u8,
    iCol: c_int,
    pnWord: *u32,
) c_int {
    var iStart: c_int = 0;
    var iEnd: c_int = 0;
    var iPos: c_int = 0;
    var nWord: c_int = 0;
    var zToken: ?[*]const u8 = undefined;
    var nToken: c_int = 0;

    const pTokenizer = p.pTokenizer.?;
    const pModule = pTokenizer.pModule.?;

    if (zText == null) {
        pnWord.* = 0;
        return SQLITE_OK;
    }

    var pCsr: ?*sqlite3_tokenizer_cursor = undefined;
    var rc = sqlite3Fts3OpenTokenizer(pTokenizer, iLangid, zText, -1, &pCsr);
    if (rc != SQLITE_OK) return rc;

    const xNext = pModule.xNext.?;
    while (rc == SQLITE_OK) {
        rc = xNext(pCsr, &zToken, &nToken, &iStart, &iEnd, &iPos);
        if (rc != SQLITE_OK) break;
        if (iPos >= nWord) nWord = iPos + 1;

        if (iPos < 0 or zToken == null or nToken <= 0) {
            rc = SQLITE_ERROR;
            break;
        }

        rc = fts3PendingTermsAddOne(p, iCol, iPos, &p.aIndex.?[0].hPending, zToken.?, nToken);

        var i: c_int = 1;
        while (rc == SQLITE_OK and i < p.nIndex) : (i += 1) {
            const pIndex = &p.aIndex.?[@intCast(i)];
            if (nToken < pIndex.nPrefix) continue;
            rc = fts3PendingTermsAddOne(p, iCol, iPos, &pIndex.hPending, zToken.?, pIndex.nPrefix);
        }
    }

    _ = pModule.xClose.?(pCsr);
    pnWord.* += @bitCast(nWord);
    return if (rc == SQLITE_DONE) SQLITE_OK else rc;
}

/// Begin adding terms for the document with docid iDocid.
fn fts3PendingTermsDocid(p: *Fts3Table, bDelete: c_int, iLangid: c_int, iDocid: i64) c_int {
    if (iDocid < p.iPrevDocid or
        (iDocid == p.iPrevDocid and p.bPrevDelete == 0) or
        p.iPrevLangid != iLangid or
        p.nPendingData > p.nMaxPendingData)
    {
        const rc = sqlite3Fts3PendingTermsFlush(p);
        if (rc != SQLITE_OK) return rc;
    }
    p.iPrevDocid = iDocid;
    p.iPrevLangid = iLangid;
    p.bPrevDelete = bDelete;
    return SQLITE_OK;
}

export fn sqlite3Fts3PendingTermsClear(p: *Fts3Table) callconv(.c) void {
    var i: c_int = 0;
    while (i < p.nIndex) : (i += 1) {
        const pHash = &p.aIndex.?[@intCast(i)].hPending;
        var pElem = fts3HashFirst(pHash);
        while (pElem) |e| : (pElem = fts3HashNext(e)) {
            const pList: ?*PendingList = @ptrCast(@alignCast(fts3HashData(e)));
            fts3PendingListDelete(pList);
        }
        sqlite3Fts3HashClear(pHash);
    }
    p.nPendingData = 0;
}

// ===========================================================================
// Insert / delete of %_content rows + terms.
// ===========================================================================

fn fts3InsertTerms(p: *Fts3Table, iLangid: c_int, apVal: [*]?*sqlite3_value, aSz: [*]u32) c_int {
    var i: c_int = 2;
    while (i < p.nColumn + 2) : (i += 1) {
        const iCol = i - 2;
        if (p.abNotindexed.?[@intCast(iCol)] == 0) {
            const zText = sqlite3_value_text(apVal[@intCast(i)]);
            const rc = fts3PendingTermsAdd(p, iLangid, zText, iCol, &aSz[@intCast(iCol)]);
            if (rc != SQLITE_OK) return rc;
            aSz[@intCast(p.nColumn)] +%= @bitCast(sqlite3_value_bytes(apVal[@intCast(i)]));
        }
    }
    return SQLITE_OK;
}

fn fts3InsertData(p: *Fts3Table, apVal: [*]?*sqlite3_value, piDocid: *i64) c_int {
    var rc: c_int = undefined;
    var pContentInsert: ?*sqlite3_stmt = undefined;

    if (p.zContentTbl != null) {
        var pRowid = apVal[@intCast(p.nColumn + 3)];
        if (sqlite3_value_type(pRowid) == SQLITE_NULL) {
            pRowid = apVal[1];
        }
        if (sqlite3_value_type(pRowid) != SQLITE_INTEGER) {
            return SQLITE_CONSTRAINT;
        }
        piDocid.* = sqlite3_value_int64(pRowid);
        return SQLITE_OK;
    }

    rc = fts3SqlStmt(p, SQL_CONTENT_INSERT, &pContentInsert, apVal + 1);
    if (rc == SQLITE_OK and p.zLanguageid != null) {
        rc = sqlite3_bind_int(pContentInsert, p.nColumn + 2, sqlite3_value_int(apVal[@intCast(p.nColumn + 4)]));
    }
    if (rc != SQLITE_OK) return rc;

    if (SQLITE_NULL != sqlite3_value_type(apVal[@intCast(3 + p.nColumn)])) {
        if (SQLITE_NULL == sqlite3_value_type(apVal[0]) and SQLITE_NULL != sqlite3_value_type(apVal[1])) {
            return SQLITE_ERROR;
        }
        rc = sqlite3_bind_value(pContentInsert, 1, apVal[@intCast(3 + p.nColumn)]);
        if (rc != SQLITE_OK) return rc;
    }

    _ = sqlite3_step(pContentInsert);
    rc = sqlite3_reset(pContentInsert);

    piDocid.* = sqlite3_last_insert_rowid(p.db);
    return rc;
}

fn fts3DeleteAll(p: *Fts3Table, bContent: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    sqlite3Fts3PendingTermsClear(p);

    if (bContent != 0) fts3SqlExec(&rc, p, SQL_DELETE_ALL_CONTENT, null);
    fts3SqlExec(&rc, p, SQL_DELETE_ALL_SEGMENTS, null);
    fts3SqlExec(&rc, p, SQL_DELETE_ALL_SEGDIR, null);
    if (p.bHasDocsize != 0) {
        fts3SqlExec(&rc, p, SQL_DELETE_ALL_DOCSIZE, null);
    }
    if (p.bHasStat != 0) {
        fts3SqlExec(&rc, p, SQL_DELETE_ALL_STAT, null);
    }
    return rc;
}

fn langidFromSelect(p: *Fts3Table, pSelect: ?*sqlite3_stmt) c_int {
    var iLangid: c_int = 0;
    if (p.zLanguageid != null) iLangid = sqlite3_column_int(pSelect, p.nColumn + 1);
    return iLangid;
}

fn fts3DeleteTerms(pRC: *c_int, p: *Fts3Table, pRowid: *?*sqlite3_value, aSz: [*]u32, pbFound: *c_int) void {
    if (pRC.* != 0) return;
    var pSelect: ?*sqlite3_stmt = undefined;
    var rc = fts3SqlStmt(p, SQL_SELECT_CONTENT_BY_ROWID, &pSelect, @ptrCast(pRowid));
    if (rc == SQLITE_OK) {
        if (SQLITE_ROW == sqlite3_step(pSelect)) {
            const iLangid = langidFromSelect(p, pSelect);
            const iDocid = sqlite3_column_int64(pSelect, 0);
            rc = fts3PendingTermsDocid(p, 1, iLangid, iDocid);
            var i: c_int = 1;
            while (rc == SQLITE_OK and i <= p.nColumn) : (i += 1) {
                const iCol = i - 1;
                if (p.abNotindexed.?[@intCast(iCol)] == 0) {
                    const zText = sqlite3_column_text(pSelect, i);
                    rc = fts3PendingTermsAdd(p, iLangid, zText, -1, &aSz[@intCast(iCol)]);
                    aSz[@intCast(p.nColumn)] +%= @bitCast(sqlite3_column_bytes(pSelect, i));
                }
            }
            if (rc != SQLITE_OK) {
                _ = sqlite3_reset(pSelect);
                pRC.* = rc;
                return;
            }
            pbFound.* = 1;
        }
        rc = sqlite3_reset(pSelect);
    } else {
        _ = sqlite3_reset(pSelect);
    }
    pRC.* = rc;
}

/// This function allocates a new level iLevel index in the segdir table.
fn fts3AllocateSegdirIdx(p: *Fts3Table, iLangid: c_int, iIndex: c_int, iLevel: c_int, piIdx: *c_int) c_int {
    var pNextIdx: ?*sqlite3_stmt = undefined;
    var iNext: c_int = 0;

    var rc = fts3SqlStmt(p, SQL_NEXT_SEGMENT_INDEX, &pNextIdx, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pNextIdx, 1, getAbsoluteLevel(p, iLangid, iIndex, iLevel));
        if (SQLITE_ROW == sqlite3_step(pNextIdx)) {
            iNext = sqlite3_column_int(pNextIdx, 0);
        }
        rc = sqlite3_reset(pNextIdx);
    }

    if (rc == SQLITE_OK) {
        if (iNext >= MergeCount(p)) {
            rc = fts3SegmentMerge(p, iLangid, iIndex, iLevel);
            piIdx.* = 0;
        } else {
            piIdx.* = iNext;
        }
    }
    return rc;
}

// ===========================================================================
// %_segments block reader.
// ===========================================================================

export fn sqlite3Fts3ReadBlock(
    p: *Fts3Table,
    iBlockid: i64,
    paBlob: ?*?[*]u8,
    pnBlob: *c_int,
    pnLoad: ?*c_int,
) callconv(.c) c_int {
    var rc: c_int = undefined;

    if (p.pSegments != null) {
        rc = sqlite3_blob_reopen(p.pSegments, iBlockid);
    } else {
        if (p.zSegmentsTbl == null) {
            p.zSegmentsTbl = sqlite3_mprintf("%s_segments", p.zName.?);
            if (p.zSegmentsTbl == null) return SQLITE_NOMEM;
        }
        rc = sqlite3_blob_open(p.db, p.zDb, p.zSegmentsTbl, "block", iBlockid, 0, &p.pSegments);
    }

    if (rc == SQLITE_OK) {
        var nByte = sqlite3_blob_bytes(p.pSegments);
        pnBlob.* = nByte;
        if (paBlob) |pab| {
            var aByte: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @intCast(nByte)) + @as(u64, @intCast(FTS3_NODE_PADDING)))));
            if (aByte == null) {
                rc = SQLITE_NOMEM;
            } else {
                if (pnLoad != null and nByte > FTS3_NODE_CHUNK_THRESHOLD) {
                    nByte = FTS3_NODE_CHUNKSIZE;
                    pnLoad.?.* = nByte;
                }
                rc = sqlite3_blob_read(p.pSegments, aByte, nByte, 0);
                _ = memset(aByte.? + @as(usize, @intCast(nByte)), 0, @intCast(FTS3_NODE_PADDING));
                if (rc != SQLITE_OK) {
                    sqlite3_free(aByte);
                    aByte = null;
                }
            }
            pab.* = aByte;
        }
    } else if (rc == SQLITE_ERROR) {
        rc = FTS_CORRUPT_VTAB();
    }
    return rc;
}

export fn sqlite3Fts3SegmentsClose(p: *Fts3Table) callconv(.c) void {
    _ = sqlite3_blob_close(p.pSegments);
    p.pSegments = null;
}

// ===========================================================================
// Fts3SegReader iteration.
// ===========================================================================

fn fts3SegReaderIncrRead(pReader: *Fts3SegReader) c_int {
    const nRead = imin(pReader.nNode - pReader.nPopulate, FTS3_NODE_CHUNKSIZE);
    const rc = sqlite3_blob_read(
        pReader.pBlob,
        pReader.aNode.? + @as(usize, @intCast(pReader.nPopulate)),
        nRead,
        pReader.nPopulate,
    );
    if (rc == SQLITE_OK) {
        pReader.nPopulate += nRead;
        _ = memset(pReader.aNode.? + @as(usize, @intCast(pReader.nPopulate)), 0, @intCast(FTS3_NODE_PADDING));
        if (pReader.nPopulate == pReader.nNode) {
            _ = sqlite3_blob_close(pReader.pBlob);
            pReader.pBlob = null;
            pReader.nPopulate = 0;
        }
    }
    return rc;
}

fn fts3SegReaderRequire(pReader: *Fts3SegReader, pFrom: [*]u8, nByte: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    while (pReader.pBlob != null and rc == SQLITE_OK and
        (@as(c_int, @intCast(@intFromPtr(pFrom) - @intFromPtr(pReader.aNode.?))) + nByte) > pReader.nPopulate)
    {
        rc = fts3SegReaderIncrRead(pReader);
    }
    return rc;
}

fn fts3SegReaderSetEof(pSeg: *Fts3SegReader) void {
    if (!fts3SegReaderIsRootOnly(pSeg)) {
        sqlite3_free(pSeg.aNode);
        _ = sqlite3_blob_close(pSeg.pBlob);
        pSeg.pBlob = null;
    }
    pSeg.aNode = null;
}

fn fts3SegReaderNext(p: *Fts3Table, pReader: *Fts3SegReader, bIncr: c_int) c_int {
    var rc: c_int = undefined;
    var pNext: ?[*]u8 = undefined;
    var nPrefix: c_int = undefined;
    var nSuffix: c_int = undefined;

    if (pReader.aDoclist == null) {
        pNext = pReader.aNode;
    } else {
        pNext = pReader.aDoclist.? + @as(usize, @intCast(pReader.nDoclist));
    }

    const nodeEnd = if (pReader.aNode) |an| an + @as(usize, @intCast(pReader.nNode)) else null;
    if (pNext == null or (nodeEnd != null and @intFromPtr(pNext.?) >= @intFromPtr(nodeEnd.?))) {
        if (fts3SegReaderIsPending(pReader)) {
            const pElem = pReader.ppNextElem.?[0];
            sqlite3_free(pReader.aNode);
            pReader.aNode = null;
            if (pElem) |e| {
                const pList: *PendingList = @ptrCast(@alignCast(fts3HashData(e).?));
                const nCopy: c_int = @intCast(pList.nData + 1);

                const nTerm = fts3HashKeysize(e);
                if ((nTerm + 1) > pReader.nTermAlloc) {
                    sqlite3_free(pReader.zTerm);
                    pReader.zTerm = @ptrCast(@alignCast(sqlite3_malloc64(@intCast((@as(i64, nTerm) + 1) * 2)) orelse return SQLITE_NOMEM));
                    pReader.nTermAlloc = (nTerm + 1) * 2;
                }
                _ = memcpy(pReader.zTerm.?, fts3HashKey(e), @intCast(nTerm));
                pReader.zTerm.?[@intCast(nTerm)] = 0;
                pReader.nTerm = nTerm;

                const aCopy: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nCopy)) orelse return SQLITE_NOMEM));
                _ = memcpy(aCopy, pList.aData, @intCast(nCopy));
                pReader.nNode = nCopy;
                pReader.nDoclist = nCopy;
                pReader.aNode = aCopy;
                pReader.aDoclist = aCopy;
                pReader.ppNextElem.? += 1;
            }
            return SQLITE_OK;
        }

        fts3SegReaderSetEof(pReader);

        if (pReader.iCurrentBlock >= pReader.iLeafEndBlock) {
            return SQLITE_OK;
        }

        pReader.iCurrentBlock += 1;
        rc = sqlite3Fts3ReadBlock(p, pReader.iCurrentBlock, &pReader.aNode, &pReader.nNode, if (bIncr != 0) &pReader.nPopulate else null);
        if (rc != SQLITE_OK) return rc;
        if (bIncr != 0 and pReader.nPopulate < pReader.nNode) {
            pReader.pBlob = p.pSegments;
            p.pSegments = null;
        }
        pNext = pReader.aNode;
    }

    rc = fts3SegReaderRequire(pReader, pNext.?, FTS3_VARINT_MAX * 2);
    if (rc != SQLITE_OK) return rc;

    pNext.? += @intCast(fts3GetVarint32(pNext.?, &nPrefix));
    pNext.? += @intCast(fts3GetVarint32(pNext.?, &nSuffix));
    if (nSuffix <= 0 or
        (@as(c_int, @intCast(@intFromPtr(pReader.aNode.? + @as(usize, @intCast(pReader.nNode))) - @intFromPtr(pNext.?)))) < nSuffix or
        nPrefix > pReader.nTerm)
    {
        return FTS_CORRUPT_VTAB();
    }

    if (@as(i64, nPrefix) + nSuffix > @as(i64, pReader.nTermAlloc)) {
        const nNew: i64 = (@as(i64, nPrefix) + nSuffix) * 2;
        const zNew: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(pReader.zTerm, @intCast(nNew))));
        if (zNew == null) return SQLITE_NOMEM;
        pReader.zTerm = zNew;
        pReader.nTermAlloc = @intCast(nNew);
    }

    rc = fts3SegReaderRequire(pReader, pNext.?, nSuffix + FTS3_VARINT_MAX);
    if (rc != SQLITE_OK) return rc;

    _ = memcpy(pReader.zTerm.? + @as(usize, @intCast(nPrefix)), pNext.?, @intCast(nSuffix));
    pReader.nTerm = nPrefix + nSuffix;
    pNext.? += @intCast(nSuffix);
    pNext.? += @intCast(fts3GetVarint32(pNext.?, &pReader.nDoclist));
    pReader.aDoclist = pNext;
    pReader.pOffsetList = null;

    const doclistOff: c_int = @intCast(@intFromPtr(pReader.aDoclist.?) - @intFromPtr(pReader.aNode.?));
    if (pReader.nDoclist > pReader.nNode - doclistOff or
        (pReader.nPopulate == 0 and pReader.aDoclist.?[@intCast(pReader.nDoclist - 1)] != 0) or
        pReader.nDoclist == 0)
    {
        return FTS_CORRUPT_VTAB();
    }
    return SQLITE_OK;
}

fn fts3SegReaderFirstDocid(pTab: *Fts3Table, pReader: *Fts3SegReader) c_int {
    var rc: c_int = SQLITE_OK;
    if (pTab.bDescIdx != 0 and fts3SegReaderIsPending(pReader)) {
        var bEof: u8 = 0;
        pReader.iDocid = 0;
        pReader.nOffsetList = 0;
        sqlite3Fts3DoclistPrev(0, pReader.aDoclist.?, pReader.nDoclist, &pReader.pOffsetList, &pReader.iDocid, &pReader.nOffsetList, &bEof);
    } else {
        rc = fts3SegReaderRequire(pReader, pReader.aDoclist.?, FTS3_VARINT_MAX);
        if (rc == SQLITE_OK) {
            const n = sqlite3Fts3GetVarint(pReader.aDoclist.?, &pReader.iDocid);
            pReader.pOffsetList = pReader.aDoclist.? + @as(usize, @intCast(n));
        }
    }
    return rc;
}

fn fts3SegReaderNextDocid(
    pTab: *Fts3Table,
    pReader: *Fts3SegReader,
    ppOffsetList: ?*?[*]u8,
    pnOffsetList: ?*c_int,
) c_int {
    var rc: c_int = SQLITE_OK;
    var p = pReader.pOffsetList.?;
    var c: u8 = 0;

    if (pTab.bDescIdx != 0 and fts3SegReaderIsPending(pReader)) {
        var bEof: u8 = 0;
        if (ppOffsetList) |pol| {
            pol.* = pReader.pOffsetList;
            pnOffsetList.?.* = pReader.nOffsetList - 1;
        }
        var pp: ?[*]u8 = p;
        sqlite3Fts3DoclistPrev(0, pReader.aDoclist.?, pReader.nDoclist, &pp, &pReader.iDocid, &pReader.nOffsetList, &bEof);
        if (bEof != 0) {
            pReader.pOffsetList = null;
        } else {
            pReader.pOffsetList = pp;
        }
    } else {
        const pEnd = pReader.aDoclist.? + @as(usize, @intCast(pReader.nDoclist));

        while (true) {
            while ((p[0] | c) != 0) {
                c = p[0] & 0x80;
                p += 1;
            }
            if (pReader.pBlob == null or @intFromPtr(p) < @intFromPtr(pReader.aNode.? + @as(usize, @intCast(pReader.nPopulate)))) break;
            rc = fts3SegReaderIncrRead(pReader);
            if (rc != SQLITE_OK) return rc;
        }
        p += 1;

        if (ppOffsetList) |pol| {
            pol.* = pReader.pOffsetList;
            pnOffsetList.?.* = @intCast(@intFromPtr(p) - @intFromPtr(pReader.pOffsetList.?) - 1);
        }

        while (@intFromPtr(p) < @intFromPtr(pEnd) and p[0] == 0) p += 1;

        if (@intFromPtr(p) >= @intFromPtr(pEnd)) {
            pReader.pOffsetList = null;
        } else {
            rc = fts3SegReaderRequire(pReader, p, FTS3_VARINT_MAX);
            if (rc == SQLITE_OK) {
                var iDelta: u64 = undefined;
                pReader.pOffsetList = p + @as(usize, @intCast(sqlite3Fts3GetVarintU(p, &iDelta)));
                if (pTab.bDescIdx != 0) {
                    pReader.iDocid = @bitCast(@as(u64, @bitCast(pReader.iDocid)) -% iDelta);
                } else {
                    pReader.iDocid = @bitCast(@as(u64, @bitCast(pReader.iDocid)) +% iDelta);
                }
            }
        }
    }
    return rc;
}

export fn sqlite3Fts3MsrOvfl(pCsr: *Fts3Cursor, pMsr: *Fts3MultiSegReader, pnOvfl: *c_int) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab));
    var nOvfl: c_int = 0;
    var rc: c_int = SQLITE_OK;
    const pgsz = p.nPgsz;

    var ii: c_int = 0;
    while (rc == SQLITE_OK and ii < pMsr.nSegment) : (ii += 1) {
        const pReader = pMsr.apSegment.?[@intCast(ii)].?;
        if (!fts3SegReaderIsPending(pReader) and !fts3SegReaderIsRootOnly(pReader)) {
            var jj = pReader.iStartBlock;
            while (jj <= pReader.iLeafEndBlock) : (jj += 1) {
                var nBlob: c_int = undefined;
                rc = sqlite3Fts3ReadBlock(p, jj, null, &nBlob, null);
                if (rc != SQLITE_OK) break;
                if ((nBlob + 35) > pgsz) {
                    nOvfl += @divTrunc(nBlob + 34, pgsz);
                }
            }
        }
    }
    pnOvfl.* = nOvfl;
    return rc;
}

export fn sqlite3Fts3SegReaderFree(pReader: ?*Fts3SegReader) callconv(.c) void {
    if (pReader) |pr| {
        sqlite3_free(pr.zTerm);
        if (!fts3SegReaderIsRootOnly(pr)) {
            sqlite3_free(pr.aNode);
        }
        _ = sqlite3_blob_close(pr.pBlob);
    }
    sqlite3_free(pReader);
}

export fn sqlite3Fts3SegReaderNew(
    iAge: c_int,
    bLookup: c_int,
    iStartLeaf: i64,
    iEndLeaf: i64,
    iEndBlock: i64,
    zRoot: ?[*]const u8,
    nRoot: c_int,
    ppReader: *?*Fts3SegReader,
) callconv(.c) c_int {
    var nExtra: c_int = 0;

    if (iStartLeaf == 0) {
        if (iEndLeaf != 0) return FTS_CORRUPT_VTAB();
        nExtra = nRoot + FTS3_NODE_PADDING;
    }

    const pReader: *Fts3SegReader = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts3SegReader) + @as(u64, @intCast(nExtra))) orelse return SQLITE_NOMEM));
    _ = memset(pReader, 0, @sizeOf(Fts3SegReader));
    pReader.iIdx = iAge;
    pReader.bLookup = if (bLookup != 0) 1 else 0;
    pReader.iStartBlock = iStartLeaf;
    pReader.iLeafEndBlock = iEndLeaf;
    pReader.iEndBlock = iEndBlock;

    if (nExtra != 0) {
        const base: [*]u8 = @ptrCast(pReader);
        pReader.aNode = base + @sizeOf(Fts3SegReader);
        pReader.rootOnly = 1;
        pReader.nNode = nRoot;
        if (nRoot != 0) _ = memcpy(pReader.aNode.?, zRoot, @intCast(nRoot));
        _ = memset(pReader.aNode.? + @as(usize, @intCast(nRoot)), 0, @intCast(FTS3_NODE_PADDING));
    } else {
        pReader.iCurrentBlock = iStartLeaf - 1;
    }
    ppReader.* = pReader;
    return SQLITE_OK;
}

fn fts3CompareElemByTerm(lhs: ?*const anyopaque, rhs: ?*const anyopaque) callconv(.c) c_int {
    const e1: *Fts3HashElem = @ptrCast(@alignCast(@as(*const ?*Fts3HashElem, @ptrCast(@alignCast(lhs))).*));
    const e2: *Fts3HashElem = @ptrCast(@alignCast(@as(*const ?*Fts3HashElem, @ptrCast(@alignCast(rhs))).*));
    const z1 = fts3HashKey(e1);
    const z2 = fts3HashKey(e2);
    const n1 = fts3HashKeysize(e1);
    const n2 = fts3HashKeysize(e2);
    const n = if (n1 < n2) n1 else n2;
    var c = memcmp(z1, z2, @intCast(n));
    if (c == 0) {
        c = n1 - n2;
    }
    return c;
}

export fn sqlite3Fts3SegReaderPending(
    p: *Fts3Table,
    iIndex: c_int,
    zTerm: ?[*]const u8,
    nTerm: c_int,
    bPrefix: c_int,
    ppReader: *?*Fts3SegReader,
) callconv(.c) c_int {
    var pReader: ?*Fts3SegReader = null;
    var pE: ?*Fts3HashElem = undefined;
    var aElem: ?[*]?*Fts3HashElem = null;
    var nElem: c_int = 0;
    var rc: c_int = SQLITE_OK;

    const pHash = &p.aIndex.?[@intCast(iIndex)].hPending;

    // A single-element scratch holding the address of pE for the else-branch.
    var pEScratch: ?*Fts3HashElem = null;

    if (bPrefix != 0) {
        var nAlloc: c_int = 0;
        pE = fts3HashFirst(pHash);
        while (pE) |e| : (pE = fts3HashNext(e)) {
            const zKey: [*]const u8 = @ptrCast(fts3HashKey(e));
            const nKey = fts3HashKeysize(e);
            if (nTerm == 0 or (nKey >= nTerm and 0 == memcmp(zKey, zTerm, @intCast(nTerm)))) {
                if (nElem == nAlloc) {
                    nAlloc += 16;
                    const aElem2: ?[*]?*Fts3HashElem = @ptrCast(@alignCast(sqlite3_realloc64(@ptrCast(aElem), @intCast(@as(i64, nAlloc) * @sizeOf(?*Fts3HashElem)))));
                    if (aElem2 == null) {
                        rc = SQLITE_NOMEM;
                        nElem = 0;
                        break;
                    }
                    aElem = aElem2;
                }
                aElem.?[@intCast(nElem)] = e;
                nElem += 1;
            }
        }
        if (nElem > 1) {
            qsort(@ptrCast(aElem.?), @intCast(nElem), @sizeOf(?*Fts3HashElem), fts3CompareElemByTerm);
        }
    } else {
        pEScratch = sqlite3Fts3HashFindElem(pHash, zTerm, nTerm);
        if (pEScratch != null) {
            aElem = @ptrCast(&pEScratch);
            nElem = 1;
        }
    }

    if (nElem > 0) {
        const nByte: i64 = @sizeOf(Fts3SegReader) + @as(i64, (nElem + 1)) * @sizeOf(?*Fts3HashElem);
        pReader = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
        if (pReader == null) {
            rc = SQLITE_NOMEM;
        } else {
            _ = memset(pReader, 0, @intCast(nByte));
            pReader.?.iIdx = 0x7FFFFFFF;
            const base: [*]u8 = @ptrCast(pReader);
            pReader.?.ppNextElem = @ptrCast(@alignCast(base + @sizeOf(Fts3SegReader)));
            _ = memcpy(@ptrCast(pReader.?.ppNextElem), @ptrCast(aElem), @intCast(@as(i64, nElem) * @sizeOf(?*Fts3HashElem)));
        }
    }

    if (bPrefix != 0) {
        sqlite3_free(@ptrCast(aElem));
    }
    ppReader.* = pReader;
    return rc;
}

// ===========================================================================
// SegReader comparison + sort.
// ===========================================================================

fn fts3SegReaderCmp(pLhs: *Fts3SegReader, pRhs: *Fts3SegReader) c_int {
    var rc: c_int = undefined;
    if (pLhs.aNode != null and pRhs.aNode != null) {
        const rc2 = pLhs.nTerm - pRhs.nTerm;
        if (rc2 < 0) {
            rc = memcmp(pLhs.zTerm, pRhs.zTerm, @intCast(pLhs.nTerm));
        } else {
            rc = memcmp(pLhs.zTerm, pRhs.zTerm, @intCast(pRhs.nTerm));
        }
        if (rc == 0) rc = rc2;
    } else {
        rc = @as(c_int, @intFromBool(pLhs.aNode == null)) - @as(c_int, @intFromBool(pRhs.aNode == null));
    }
    if (rc == 0) {
        rc = pRhs.iIdx - pLhs.iIdx;
    }
    return rc;
}

fn fts3SegReaderDoclistCmp(pLhs: *Fts3SegReader, pRhs: *Fts3SegReader) c_int {
    var rc: c_int = @as(c_int, @intFromBool(pLhs.pOffsetList == null)) - @as(c_int, @intFromBool(pRhs.pOffsetList == null));
    if (rc == 0) {
        if (pLhs.iDocid == pRhs.iDocid) {
            rc = pRhs.iIdx - pLhs.iIdx;
        } else {
            rc = if (pLhs.iDocid > pRhs.iDocid) 1 else -1;
        }
    }
    return rc;
}

fn fts3SegReaderDoclistCmpRev(pLhs: *Fts3SegReader, pRhs: *Fts3SegReader) c_int {
    var rc: c_int = @as(c_int, @intFromBool(pLhs.pOffsetList == null)) - @as(c_int, @intFromBool(pRhs.pOffsetList == null));
    if (rc == 0) {
        if (pLhs.iDocid == pRhs.iDocid) {
            rc = pRhs.iIdx - pLhs.iIdx;
        } else {
            rc = if (pLhs.iDocid < pRhs.iDocid) 1 else -1;
        }
    }
    return rc;
}

fn fts3SegReaderTermCmp(pSeg: *Fts3SegReader, zTerm: [*]const u8, nTerm: c_int) c_int {
    var res: c_int = 0;
    if (pSeg.aNode != null) {
        if (pSeg.nTerm > nTerm) {
            res = memcmp(pSeg.zTerm, zTerm, @intCast(nTerm));
        } else {
            res = memcmp(pSeg.zTerm, zTerm, @intCast(pSeg.nTerm));
        }
        if (res == 0) {
            res = pSeg.nTerm - nTerm;
        }
    }
    return res;
}

const CmpFn = *const fn (*Fts3SegReader, *Fts3SegReader) c_int;

fn fts3SegReaderSort(apSegment: [*]?*Fts3SegReader, nSegment: c_int, nSuspect_in: c_int, xCmp: CmpFn) void {
    var nSuspect = nSuspect_in;
    if (nSuspect == nSegment) nSuspect -= 1;
    var i: c_int = nSuspect - 1;
    while (i >= 0) : (i -= 1) {
        var j: c_int = i;
        while (j < (nSegment - 1)) : (j += 1) {
            if (xCmp(apSegment[@intCast(j)].?, apSegment[@intCast(j + 1)].?) < 0) break;
            const pTmp = apSegment[@intCast(j + 1)];
            apSegment[@intCast(j + 1)] = apSegment[@intCast(j)];
            apSegment[@intCast(j)] = pTmp;
        }
    }
}

// ===========================================================================
// Segment writer (leaf + interior node tree).
// ===========================================================================

fn fts3WriteSegment(p: *Fts3Table, iBlock: i64, z: ?[*]u8, n: c_int) c_int {
    var pStmt: ?*sqlite3_stmt = undefined;
    var rc = fts3SqlStmt(p, SQL_INSERT_SEGMENTS, &pStmt, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pStmt, 1, iBlock);
        _ = sqlite3_bind_blob(pStmt, 2, z, n, SQLITE_STATIC);
        _ = sqlite3_step(pStmt);
        rc = sqlite3_reset(pStmt);
        _ = sqlite3_bind_null(pStmt, 2);
    }
    return rc;
}

export fn sqlite3Fts3MaxLevel(p: *Fts3Table, pnMax: *c_int) callconv(.c) c_int {
    var mxLevel: c_int = 0;
    var pStmt: ?*sqlite3_stmt = null;
    var rc = fts3SqlStmt(p, SQL_SELECT_MXLEVEL, &pStmt, null);
    if (rc == SQLITE_OK) {
        if (SQLITE_ROW == sqlite3_step(pStmt)) {
            mxLevel = sqlite3_column_int(pStmt, 0);
        }
        rc = sqlite3_reset(pStmt);
    }
    pnMax.* = mxLevel;
    return rc;
}

fn fts3WriteSegdir(
    p: *Fts3Table,
    iLevel: i64,
    iIdx: c_int,
    iStartBlock: i64,
    iLeafEndBlock: i64,
    iEndBlock: i64,
    nLeafData: i64,
    zRoot: ?[*]u8,
    nRoot: c_int,
) c_int {
    var pStmt: ?*sqlite3_stmt = undefined;
    var rc = fts3SqlStmt(p, SQL_INSERT_SEGDIR, &pStmt, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pStmt, 1, iLevel);
        _ = sqlite3_bind_int(pStmt, 2, iIdx);
        _ = sqlite3_bind_int64(pStmt, 3, iStartBlock);
        _ = sqlite3_bind_int64(pStmt, 4, iLeafEndBlock);
        if (nLeafData == 0) {
            _ = sqlite3_bind_int64(pStmt, 5, iEndBlock);
        } else {
            const zEnd = sqlite3_mprintf("%lld %lld", iEndBlock, nLeafData);
            if (zEnd == null) return SQLITE_NOMEM;
            _ = sqlite3_bind_text(pStmt, 5, zEnd, -1, sqliteFreeDtor);
        }
        _ = sqlite3_bind_blob(pStmt, 6, zRoot, nRoot, SQLITE_STATIC);
        _ = sqlite3_step(pStmt);
        rc = sqlite3_reset(pStmt);
        _ = sqlite3_bind_null(pStmt, 6);
    }
    return rc;
}

// sqlite3_free as a destructor function pointer (matches `sqlite3_free` arg).
const sqliteFreeDtor: DestructorFn = sqlite3_free;

fn fts3PrefixCompress(zPrev: ?[*]const u8, nPrev: c_int, zNext: [*]const u8, nNext: c_int) c_int {
    var n: c_int = 0;
    while (n < nPrev and n < nNext and zPrev.?[@intCast(n)] == zNext[@intCast(n)]) : (n += 1) {}
    return n;
}

fn fts3NodeAddTerm(p: *Fts3Table, ppTree: *?*SegmentNode, isCopyTerm: c_int, zTerm: [*]const u8, nTerm: c_int) c_int {
    const pTree = ppTree.*;
    var rc: c_int = undefined;

    if (pTree) |pt| {
        var nData = pt.nData;
        var nReq = nData;
        const nPrefix = fts3PrefixCompress(pt.zTerm, pt.nTerm, zTerm, nTerm);
        const nSuffix = nTerm - nPrefix;
        if (nSuffix <= 0) return FTS_CORRUPT_VTAB();

        nReq += sqlite3Fts3VarintLen(@intCast(nPrefix)) + sqlite3Fts3VarintLen(@intCast(nSuffix)) + nSuffix;
        if (nReq <= p.nNodeSize or pt.zTerm == null) {
            if (nReq > p.nNodeSize) {
                pt.aData = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nReq)) orelse return SQLITE_NOMEM));
            }
            if (pt.zTerm != null) {
                nData += sqlite3Fts3PutVarint(pt.aData.? + @as(usize, @intCast(nData)), @intCast(nPrefix));
            }
            nData += sqlite3Fts3PutVarint(pt.aData.? + @as(usize, @intCast(nData)), @intCast(nSuffix));
            _ = memcpy(pt.aData.? + @as(usize, @intCast(nData)), zTerm + @as(usize, @intCast(nPrefix)), @intCast(nSuffix));
            pt.nData = nData + nSuffix;
            pt.nEntry += 1;

            if (isCopyTerm != 0) {
                if (pt.nMalloc < nTerm) {
                    const zNew: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(pt.zMalloc, @intCast(@as(i64, nTerm) * 2))));
                    if (zNew == null) return SQLITE_NOMEM;
                    pt.nMalloc = nTerm * 2;
                    pt.zMalloc = zNew;
                }
                pt.zTerm = pt.zMalloc;
                _ = memcpy(pt.zTerm.?, zTerm, @intCast(nTerm));
                pt.nTerm = nTerm;
            } else {
                pt.zTerm = @constCast(zTerm);
                pt.nTerm = nTerm;
            }
            return SQLITE_OK;
        }
    }

    const pNew: *SegmentNode = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(SegmentNode) + @as(u64, @intCast(p.nNodeSize))) orelse return SQLITE_NOMEM));
    _ = memset(pNew, 0, @sizeOf(SegmentNode));
    pNew.nData = 1 + FTS3_VARINT_MAX;
    const base: [*]u8 = @ptrCast(pNew);
    pNew.aData = base + @sizeOf(SegmentNode);

    if (pTree) |pt| {
        var pParent = pt.pParent;
        rc = fts3NodeAddTerm(p, &pParent, isCopyTerm, zTerm, nTerm);
        if (pt.pParent == null) {
            pt.pParent = pParent;
        }
        pt.pRight = pNew;
        pNew.pLeftmost = pt.pLeftmost;
        pNew.pParent = pParent;
        pNew.zMalloc = pt.zMalloc;
        pNew.nMalloc = pt.nMalloc;
        pt.zMalloc = null;
    } else {
        pNew.pLeftmost = pNew;
        var pNewLocal: ?*SegmentNode = pNew;
        rc = fts3NodeAddTerm(p, &pNewLocal, isCopyTerm, zTerm, nTerm);
    }

    ppTree.* = pNew;
    return rc;
}

fn fts3TreeFinishNode(pTree: *SegmentNode, iHeight: c_int, iLeftChild: i64) c_int {
    const nStart = FTS3_VARINT_MAX - sqlite3Fts3VarintLen(@bitCast(iLeftChild));
    pTree.aData.?[@intCast(nStart)] = @intCast(iHeight);
    _ = sqlite3Fts3PutVarint(pTree.aData.? + @as(usize, @intCast(nStart + 1)), iLeftChild);
    return nStart;
}

fn fts3NodeWrite(
    p: *Fts3Table,
    pTree: *SegmentNode,
    iHeight: c_int,
    iLeaf: i64,
    iFree: i64,
    piLast: *i64,
    paRoot: *?[*]u8,
    pnRoot: *c_int,
) c_int {
    var rc: c_int = SQLITE_OK;

    if (pTree.pParent == null) {
        const nStart = fts3TreeFinishNode(pTree, iHeight, iLeaf);
        piLast.* = iFree - 1;
        pnRoot.* = pTree.nData - nStart;
        paRoot.* = pTree.aData.? + @as(usize, @intCast(nStart));
    } else {
        var iNextFree = iFree;
        var iNextLeaf = iLeaf;
        var pIter: ?*SegmentNode = pTree.pLeftmost;
        while (pIter != null and rc == SQLITE_OK) : (pIter = pIter.?.pRight) {
            const pit = pIter.?;
            const nStart = fts3TreeFinishNode(pit, iHeight, iNextLeaf);
            const nWrite = pit.nData - nStart;
            rc = fts3WriteSegment(p, iNextFree, pit.aData.? + @as(usize, @intCast(nStart)), nWrite);
            iNextFree += 1;
            iNextLeaf += (pit.nEntry + 1);
        }
        if (rc == SQLITE_OK) {
            rc = fts3NodeWrite(p, pTree.pParent.?, iHeight + 1, iFree, iNextFree, piLast, paRoot, pnRoot);
        }
    }
    return rc;
}

fn fts3NodeFree(pTree: ?*SegmentNode) void {
    if (pTree) |pt| {
        var p: ?*SegmentNode = pt.pLeftmost;
        fts3NodeFree(p.?.pParent);
        while (p) |pp| {
            const pRight = pp.pRight;
            const base: [*]u8 = @ptrCast(pp);
            if (pp.aData != @as(?[*]u8, base + @sizeOf(SegmentNode))) {
                sqlite3_free(pp.aData);
            }
            sqlite3_free(pp.zMalloc);
            sqlite3_free(pp);
            p = pRight;
        }
    }
}

fn fts3SegWriterAdd(
    p: *Fts3Table,
    ppWriter: *?*SegmentWriter,
    isCopyTerm: c_int,
    zTerm: [*]const u8,
    nTerm: c_int,
    aDoclist: [*]const u8,
    nDoclist: c_int,
) c_int {
    var nPrefix: c_int = undefined;
    var nSuffix: c_int = undefined;
    var nReq: i64 = undefined;
    var nData: c_int = undefined;
    var pWriter = ppWriter.*;

    if (pWriter == null) {
        pWriter = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(SegmentWriter)) orelse return SQLITE_NOMEM));
        _ = memset(pWriter, 0, @sizeOf(SegmentWriter));
        ppWriter.* = pWriter;

        pWriter.?.aData = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(p.nNodeSize)) orelse return SQLITE_NOMEM));
        pWriter.?.nSize = p.nNodeSize;

        var pStmt: ?*sqlite3_stmt = undefined;
        var rc = fts3SqlStmt(p, SQL_NEXT_SEGMENTS_ID, &pStmt, null);
        if (rc != SQLITE_OK) return rc;
        if (SQLITE_ROW == sqlite3_step(pStmt)) {
            pWriter.?.iFree = sqlite3_column_int64(pStmt, 0);
            pWriter.?.iFirst = pWriter.?.iFree;
        }
        rc = sqlite3_reset(pStmt);
        if (rc != SQLITE_OK) return rc;
    }
    const w = pWriter.?;
    nData = w.nData;

    nPrefix = fts3PrefixCompress(w.zTerm, w.nTerm, zTerm, nTerm);
    nSuffix = nTerm - nPrefix;
    if (nSuffix <= 0) return FTS_CORRUPT_VTAB();

    nReq = sqlite3Fts3VarintLen(@intCast(nPrefix)) +
        sqlite3Fts3VarintLen(@intCast(nSuffix)) +
        nSuffix +
        sqlite3Fts3VarintLen(@intCast(nDoclist)) +
        nDoclist;

    if (nData > 0 and nData + nReq > p.nNodeSize) {
        if (w.iFree == LARGEST_INT64) return FTS_CORRUPT_VTAB();
        var rc = fts3WriteSegment(p, w.iFree, w.aData, nData);
        w.iFree += 1;
        if (rc != SQLITE_OK) return rc;
        p.nLeafAdd +%= 1;

        rc = fts3NodeAddTerm(p, &w.pTree, isCopyTerm, zTerm, nPrefix + 1);
        if (rc != SQLITE_OK) return rc;

        nData = 0;
        w.nTerm = 0;

        nPrefix = 0;
        nSuffix = nTerm;
        nReq = 1 +
            sqlite3Fts3VarintLen(@intCast(nTerm)) +
            nTerm +
            sqlite3Fts3VarintLen(@intCast(nDoclist)) +
            nDoclist;
    }

    w.nLeafData += nReq;

    if (nReq > w.nSize) {
        const aNew: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(w.aData, @intCast(nReq))));
        if (aNew == null) return SQLITE_NOMEM;
        w.aData = aNew;
        w.nSize = @intCast(nReq);
    }

    nData += sqlite3Fts3PutVarint(w.aData.? + @as(usize, @intCast(nData)), @intCast(nPrefix));
    nData += sqlite3Fts3PutVarint(w.aData.? + @as(usize, @intCast(nData)), @intCast(nSuffix));
    _ = memcpy(w.aData.? + @as(usize, @intCast(nData)), zTerm + @as(usize, @intCast(nPrefix)), @intCast(nSuffix));
    nData += nSuffix;
    nData += sqlite3Fts3PutVarint(w.aData.? + @as(usize, @intCast(nData)), @intCast(nDoclist));
    _ = memcpy(w.aData.? + @as(usize, @intCast(nData)), aDoclist, @intCast(nDoclist));
    w.nData = nData + nDoclist;

    if (isCopyTerm != 0) {
        if (nTerm > w.nMalloc) {
            const zNew: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(w.zMalloc, @intCast(@as(i64, nTerm) * 2))));
            if (zNew == null) return SQLITE_NOMEM;
            w.nMalloc = nTerm * 2;
            w.zMalloc = zNew;
            w.zTerm = zNew;
        }
        _ = memcpy(w.zTerm.?, zTerm, @intCast(nTerm));
    } else {
        w.zTerm = @constCast(zTerm);
    }
    w.nTerm = nTerm;

    return SQLITE_OK;
}

fn fts3SegWriterFlush(p: *Fts3Table, pWriter: *SegmentWriter, iLevel: i64, iIdx: c_int) c_int {
    var rc: c_int = undefined;
    if (pWriter.pTree != null) {
        var iLast: i64 = 0;
        var zRoot: ?[*]u8 = null;
        var nRoot: c_int = 0;

        const iLastLeaf = pWriter.iFree;
        rc = fts3WriteSegment(p, pWriter.iFree, pWriter.aData, pWriter.nData);
        pWriter.iFree += 1;
        if (rc == SQLITE_OK) {
            rc = fts3NodeWrite(p, pWriter.pTree.?, 1, pWriter.iFirst, pWriter.iFree, &iLast, &zRoot, &nRoot);
        }
        if (rc == SQLITE_OK) {
            rc = fts3WriteSegdir(p, iLevel, iIdx, pWriter.iFirst, iLastLeaf, iLast, pWriter.nLeafData, zRoot, nRoot);
        }
    } else {
        rc = fts3WriteSegdir(p, iLevel, iIdx, 0, 0, 0, pWriter.nLeafData, pWriter.aData, pWriter.nData);
    }
    p.nLeafAdd +%= 1;
    return rc;
}

fn fts3SegWriterFree(pWriter: ?*SegmentWriter) void {
    if (pWriter) |w| {
        sqlite3_free(w.aData);
        sqlite3_free(w.zMalloc);
        fts3NodeFree(w.pTree);
        sqlite3_free(w);
    }
}

// ===========================================================================
// Merge-driving helpers.
// ===========================================================================

fn fts3IsEmpty(p: *Fts3Table, pRowid: *?*sqlite3_value, pisEmpty: *c_int) c_int {
    var rc: c_int = undefined;
    if (p.zContentTbl != null) {
        pisEmpty.* = 0;
        rc = SQLITE_OK;
    } else {
        var pStmt: ?*sqlite3_stmt = undefined;
        rc = fts3SqlStmt(p, SQL_IS_EMPTY, &pStmt, @ptrCast(pRowid));
        if (rc == SQLITE_OK) {
            if (SQLITE_ROW == sqlite3_step(pStmt)) {
                pisEmpty.* = sqlite3_column_int(pStmt, 0);
            }
            rc = sqlite3_reset(pStmt);
        }
    }
    return rc;
}

fn fts3SegmentMaxLevel(p: *Fts3Table, iLangid: c_int, iIndex: c_int, pnMax: *i64) c_int {
    var pStmt: ?*sqlite3_stmt = undefined;
    const rc = fts3SqlStmt(p, SQL_SELECT_SEGDIR_MAX_LEVEL, &pStmt, null);
    if (rc != SQLITE_OK) return rc;
    _ = sqlite3_bind_int64(pStmt, 1, getAbsoluteLevel(p, iLangid, iIndex, 0));
    _ = sqlite3_bind_int64(pStmt, 2, getAbsoluteLevel(p, iLangid, iIndex, FTS3_SEGDIR_MAXLEVEL - 1));
    if (SQLITE_ROW == sqlite3_step(pStmt)) {
        pnMax.* = sqlite3_column_int64(pStmt, 0);
    }
    return sqlite3_reset(pStmt);
}

fn fts3SegmentIsMaxLevel(p: *Fts3Table, iAbsLevel: i64, pbMax: *c_int) c_int {
    var pStmt: ?*sqlite3_stmt = undefined;
    const rc = fts3SqlStmt(p, SQL_SELECT_SEGDIR_MAX_LEVEL, &pStmt, null);
    if (rc != SQLITE_OK) return rc;
    _ = sqlite3_bind_int64(pStmt, 1, iAbsLevel + 1);
    _ = sqlite3_bind_int64(pStmt, 2, @bitCast((@as(u64, @bitCast(iAbsLevel)) / @as(u64, @intCast(FTS3_SEGDIR_MAXLEVEL)) + 1) * @as(u64, @intCast(FTS3_SEGDIR_MAXLEVEL))));

    pbMax.* = 0;
    if (SQLITE_ROW == sqlite3_step(pStmt)) {
        pbMax.* = @intFromBool(sqlite3_column_type(pStmt, 0) == SQLITE_NULL);
    }
    return sqlite3_reset(pStmt);
}

fn fts3DeleteSegment(p: *Fts3Table, pSeg: *Fts3SegReader) c_int {
    var rc: c_int = SQLITE_OK;
    if (pSeg.iStartBlock != 0) {
        var pDelete: ?*sqlite3_stmt = undefined;
        rc = fts3SqlStmt(p, SQL_DELETE_SEGMENTS_RANGE, &pDelete, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pDelete, 1, pSeg.iStartBlock);
            _ = sqlite3_bind_int64(pDelete, 2, pSeg.iEndBlock);
            _ = sqlite3_step(pDelete);
            rc = sqlite3_reset(pDelete);
        }
    }
    return rc;
}

fn fts3DeleteSegdir(
    p: *Fts3Table,
    iLangid: c_int,
    iIndex: c_int,
    iLevel: c_int,
    apSegment: [*]?*Fts3SegReader,
    nReader: c_int,
) c_int {
    var rc: c_int = SQLITE_OK;
    var pDelete: ?*sqlite3_stmt = null;

    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nReader) : (i += 1) {
        rc = fts3DeleteSegment(p, apSegment[@intCast(i)].?);
    }
    if (rc != SQLITE_OK) return rc;

    if (iLevel == FTS3_SEGCURSOR_ALL) {
        rc = fts3SqlStmt(p, SQL_DELETE_SEGDIR_RANGE, &pDelete, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pDelete, 1, getAbsoluteLevel(p, iLangid, iIndex, 0));
            _ = sqlite3_bind_int64(pDelete, 2, getAbsoluteLevel(p, iLangid, iIndex, FTS3_SEGDIR_MAXLEVEL - 1));
        }
    } else {
        rc = fts3SqlStmt(p, SQL_DELETE_SEGDIR_LEVEL, &pDelete, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pDelete, 1, getAbsoluteLevel(p, iLangid, iIndex, iLevel));
        }
    }

    if (rc == SQLITE_OK) {
        _ = sqlite3_step(pDelete);
        rc = sqlite3_reset(pDelete);
    }
    return rc;
}

fn fts3ColumnFilter(iCol: c_int, bZero: c_int, ppList: *?[*]u8, pnList: *c_int) void {
    var pList = ppList.*.?;
    var nList = pnList.*;
    const pEnd = pList + @as(usize, @intCast(nList));
    var iCurrent: c_int = 0;
    var p = pList;

    while (true) {
        var c: u8 = 0;
        while (@intFromPtr(p) < @intFromPtr(pEnd) and ((c | p[0]) & 0xFE) != 0) {
            c = p[0] & 0x80;
            p += 1;
        }
        if (iCol == iCurrent) {
            nList = @intCast(@intFromPtr(p) - @intFromPtr(pList));
            break;
        }
        nList -= @intCast(@intFromPtr(p) - @intFromPtr(pList));
        pList = p;
        if (nList <= 0) {
            break;
        }
        p = pList + 1;
        p += @intCast(fts3GetVarint32(p, &iCurrent));
    }

    if (bZero != 0 and (@as(isize, @intCast(@intFromPtr(pEnd) - @intFromPtr(pList + @as(usize, @intCast(nList)))))) > 0) {
        _ = memset(pList + @as(usize, @intCast(nList)), 0, @intCast(@intFromPtr(pEnd) - @intFromPtr(pList + @as(usize, @intCast(nList)))));
    }
    ppList.* = pList;
    pnList.* = nList;
}

fn fts3MsrBufferData(pMsr: *Fts3MultiSegReader, pList: [*]u8, nList: i64) c_int {
    if ((nList + FTS3_NODE_PADDING) > pMsr.nBuffer) {
        const nNew = nList * 2 + FTS3_NODE_PADDING;
        const pNew: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(pMsr.aBuffer, @intCast(nNew))));
        if (pNew == null) return SQLITE_NOMEM;
        pMsr.aBuffer = pNew;
        pMsr.nBuffer = nNew;
    }
    _ = memcpy(pMsr.aBuffer, pList, @intCast(nList));
    _ = memset(pMsr.aBuffer.? + @as(usize, @intCast(nList)), 0, @intCast(FTS3_NODE_PADDING));
    return SQLITE_OK;
}

export fn sqlite3Fts3MsrIncrNext(
    p: *Fts3Table,
    pMsr: *Fts3MultiSegReader,
    piDocid: *i64,
    paPoslist: *?[*]u8,
    pnPoslist: *c_int,
) callconv(.c) c_int {
    const nMerge = pMsr.nAdvance;
    const apSegment = pMsr.apSegment.?;
    const xCmp: CmpFn = if (p.bDescIdx != 0) fts3SegReaderDoclistCmpRev else fts3SegReaderDoclistCmp;

    if (nMerge == 0) {
        paPoslist.* = null;
        return SQLITE_OK;
    }

    while (true) {
        const pSeg = pMsr.apSegment.?[0].?;
        if (pSeg.pOffsetList == null) {
            paPoslist.* = null;
            break;
        } else {
            const iDocid = apSegment[0].?.iDocid;
            var pList: ?[*]u8 = undefined;
            var nList: c_int = undefined;
            var rc = fts3SegReaderNextDocid(p, apSegment[0].?, &pList, &nList);
            var j: c_int = 1;
            while (rc == SQLITE_OK and j < nMerge and apSegment[@intCast(j)].?.pOffsetList != null and apSegment[@intCast(j)].?.iDocid == iDocid) {
                rc = fts3SegReaderNextDocid(p, apSegment[@intCast(j)].?, null, null);
                j += 1;
            }
            if (rc != SQLITE_OK) return rc;
            fts3SegReaderSort(pMsr.apSegment.?, nMerge, j, xCmp);

            if (nList > 0 and fts3SegReaderIsPending(apSegment[0].?)) {
                rc = fts3MsrBufferData(pMsr, pList.?, @as(i64, nList) + 1);
                if (rc != SQLITE_OK) return rc;
                pList = pMsr.aBuffer;
            }

            if (pMsr.iColFilter >= 0) {
                fts3ColumnFilter(pMsr.iColFilter, 1, &pList, &nList);
            }

            if (nList > 0) {
                paPoslist.* = pList;
                piDocid.* = iDocid;
                pnPoslist.* = nList;
                break;
            }
        }
    }
    return SQLITE_OK;
}

fn fts3SegReaderStart(p: *Fts3Table, pCsr: *Fts3MultiSegReader, zTerm: ?[*]const u8, nTerm: c_int) c_int {
    const nSeg = pCsr.nSegment;

    var i: c_int = 0;
    while (pCsr.bRestart == 0 and i < pCsr.nSegment) : (i += 1) {
        var res: c_int = 0;
        const pSeg = pCsr.apSegment.?[@intCast(i)].?;
        while (true) {
            const rc = fts3SegReaderNext(p, pSeg, 0);
            if (rc != SQLITE_OK) return rc;
            if (zTerm == null) break;
            res = fts3SegReaderTermCmp(pSeg, zTerm.?, nTerm);
            if (res >= 0) break;
        }
        if (pSeg.bLookup != 0 and res != 0) {
            fts3SegReaderSetEof(pSeg);
        }
    }
    fts3SegReaderSort(pCsr.apSegment.?, nSeg, nSeg, fts3SegReaderCmp);
    return SQLITE_OK;
}

export fn sqlite3Fts3SegReaderStart(p: *Fts3Table, pCsr: *Fts3MultiSegReader, pFilter: *Fts3SegFilter) callconv(.c) c_int {
    pCsr.pFilter = pFilter;
    return fts3SegReaderStart(p, pCsr, pFilter.zTerm, pFilter.nTerm);
}

export fn sqlite3Fts3MsrIncrStart(
    p: *Fts3Table,
    pCsr: *Fts3MultiSegReader,
    iCol: c_int,
    zTerm: ?[*]const u8,
    nTerm: c_int,
) callconv(.c) c_int {
    const nSegment = pCsr.nSegment;
    const xCmp: CmpFn = if (p.bDescIdx != 0) fts3SegReaderDoclistCmpRev else fts3SegReaderDoclistCmp;

    var rc = fts3SegReaderStart(p, pCsr, zTerm, nTerm);
    if (rc != SQLITE_OK) return rc;

    var i: c_int = 0;
    while (i < nSegment) : (i += 1) {
        const pSeg = pCsr.apSegment.?[@intCast(i)].?;
        if (pSeg.aNode == null or fts3SegReaderTermCmp(pSeg, zTerm.?, nTerm) != 0) {
            break;
        }
    }
    pCsr.nAdvance = i;

    i = 0;
    while (i < pCsr.nAdvance) : (i += 1) {
        rc = fts3SegReaderFirstDocid(p, pCsr.apSegment.?[@intCast(i)].?);
        if (rc != SQLITE_OK) return rc;
    }
    fts3SegReaderSort(pCsr.apSegment.?, i, i, xCmp);

    pCsr.iColFilter = iCol;
    return SQLITE_OK;
}

export fn sqlite3Fts3MsrIncrRestart(pCsr: *Fts3MultiSegReader) callconv(.c) c_int {
    pCsr.nAdvance = 0;
    pCsr.bRestart = 1;
    var i: c_int = 0;
    while (i < pCsr.nSegment) : (i += 1) {
        pCsr.apSegment.?[@intCast(i)].?.pOffsetList = null;
        pCsr.apSegment.?[@intCast(i)].?.nOffsetList = 0;
        pCsr.apSegment.?[@intCast(i)].?.iDocid = 0;
    }
    return SQLITE_OK;
}

fn fts3GrowSegReaderBuffer(pCsr: *Fts3MultiSegReader, nReq: i64) c_int {
    if (nReq > pCsr.nBuffer) {
        pCsr.nBuffer = nReq * 2;
        const aNew: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(pCsr.aBuffer, @intCast(pCsr.nBuffer))));
        if (aNew == null) return SQLITE_NOMEM;
        pCsr.aBuffer = aNew;
    }
    return SQLITE_OK;
}

export fn sqlite3Fts3SegReaderStep(p: *Fts3Table, pCsr: *Fts3MultiSegReader) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    const isIgnoreEmpty = (pCsr.pFilter.?.flags & FTS3_SEGMENT_IGNORE_EMPTY);
    const isRequirePos = (pCsr.pFilter.?.flags & FTS3_SEGMENT_REQUIRE_POS);
    const isColFilter = (pCsr.pFilter.?.flags & FTS3_SEGMENT_COLUMN_FILTER);
    const isPrefix = (pCsr.pFilter.?.flags & FTS3_SEGMENT_PREFIX);
    const isScan = (pCsr.pFilter.?.flags & FTS3_SEGMENT_SCAN);
    const isFirst = (pCsr.pFilter.?.flags & FTS3_SEGMENT_FIRST);

    const apSegment = pCsr.apSegment.?;
    const nSegment = pCsr.nSegment;
    const pFilter = pCsr.pFilter.?;
    const xCmp: CmpFn = if (p.bDescIdx != 0) fts3SegReaderDoclistCmpRev else fts3SegReaderDoclistCmp;

    if (pCsr.nSegment == 0) return SQLITE_OK;

    while (true) {
        var nMerge: c_int = undefined;
        var i: c_int = 0;

        i = 0;
        while (i < pCsr.nAdvance) : (i += 1) {
            const pSeg = apSegment[@intCast(i)].?;
            if (pSeg.bLookup != 0) {
                fts3SegReaderSetEof(pSeg);
            } else {
                rc = fts3SegReaderNext(p, pSeg, 0);
            }
            if (rc != SQLITE_OK) return rc;
        }
        fts3SegReaderSort(apSegment, nSegment, pCsr.nAdvance, fts3SegReaderCmp);
        pCsr.nAdvance = 0;

        if (apSegment[0].?.aNode == null) break;

        pCsr.nTerm = apSegment[0].?.nTerm;
        pCsr.zTerm = apSegment[0].?.zTerm;

        if (pFilter.zTerm != null and isScan == 0) {
            if (pCsr.nTerm < pFilter.nTerm or
                (isPrefix == 0 and pCsr.nTerm > pFilter.nTerm) or
                memcmp(pCsr.zTerm, pFilter.zTerm, @intCast(pFilter.nTerm)) != 0)
            {
                break;
            }
        }

        nMerge = 1;
        while (nMerge < nSegment and apSegment[@intCast(nMerge)].?.aNode != null and
            apSegment[@intCast(nMerge)].?.nTerm == pCsr.nTerm and
            0 == memcmp(pCsr.zTerm, apSegment[@intCast(nMerge)].?.zTerm, @intCast(pCsr.nTerm)))
        {
            nMerge += 1;
        }

        if (nMerge == 1 and isIgnoreEmpty == 0 and isFirst == 0 and
            (p.bDescIdx == 0 or fts3SegReaderIsPending(apSegment[0].?) == false))
        {
            pCsr.nDoclist = apSegment[0].?.nDoclist;
            if (fts3SegReaderIsPending(apSegment[0].?)) {
                rc = fts3MsrBufferData(pCsr, apSegment[0].?.aDoclist.?, @intCast(pCsr.nDoclist));
                pCsr.aDoclist = pCsr.aBuffer;
            } else {
                pCsr.aDoclist = apSegment[0].?.aDoclist;
            }
            if (rc == SQLITE_OK) rc = SQLITE_ROW;
        } else {
            var nDoclist: c_int = 0;
            var iPrev: i64 = 0;

            i = 0;
            while (i < nMerge) : (i += 1) {
                _ = fts3SegReaderFirstDocid(p, apSegment[@intCast(i)].?);
            }
            fts3SegReaderSort(apSegment, nMerge, nMerge, xCmp);
            while (apSegment[0].?.pOffsetList != null) {
                var pList: ?[*]u8 = null;
                var nList: c_int = 0;
                const iDocid = apSegment[0].?.iDocid;
                _ = fts3SegReaderNextDocid(p, apSegment[0].?, &pList, &nList);
                var j: c_int = 1;
                while (j < nMerge and apSegment[@intCast(j)].?.pOffsetList != null and apSegment[@intCast(j)].?.iDocid == iDocid) {
                    _ = fts3SegReaderNextDocid(p, apSegment[@intCast(j)].?, null, null);
                    j += 1;
                }

                if (isColFilter != 0) {
                    fts3ColumnFilter(pFilter.iCol, 0, &pList, &nList);
                }

                if (isIgnoreEmpty == 0 or nList > 0) {
                    var iDelta: i64 = undefined;
                    if (p.bDescIdx != 0 and nDoclist > 0) {
                        if (iPrev <= iDocid) return FTS_CORRUPT_VTAB();
                        iDelta = @bitCast(@as(u64, @bitCast(iPrev)) -% @as(u64, @bitCast(iDocid)));
                    } else {
                        if (nDoclist > 0 and iPrev >= iDocid) return FTS_CORRUPT_VTAB();
                        iDelta = @bitCast(@as(u64, @bitCast(iDocid)) -% @as(u64, @bitCast(iPrev)));
                    }

                    const nByte = sqlite3Fts3VarintLen(@bitCast(iDelta)) + (if (isRequirePos != 0) nList + 1 else 0);

                    rc = fts3GrowSegReaderBuffer(pCsr, @as(i64, nByte) + nDoclist + FTS3_NODE_PADDING);
                    if (rc != 0) return rc;

                    if (isFirst != 0) {
                        const a = pCsr.aBuffer.? + @as(usize, @intCast(nDoclist));
                        const nWrite = sqlite3Fts3FirstFilter(iDelta, pList.?, nList, a);
                        if (nWrite != 0) {
                            iPrev = iDocid;
                            nDoclist += nWrite;
                        }
                    } else {
                        nDoclist += sqlite3Fts3PutVarint(pCsr.aBuffer.? + @as(usize, @intCast(nDoclist)), iDelta);
                        iPrev = iDocid;
                        if (isRequirePos != 0) {
                            _ = memcpy(pCsr.aBuffer.? + @as(usize, @intCast(nDoclist)), pList, @intCast(nList));
                            nDoclist += nList;
                            pCsr.aBuffer.?[@intCast(nDoclist)] = 0;
                            nDoclist += 1;
                        }
                    }
                }

                fts3SegReaderSort(apSegment, nMerge, j, xCmp);
            }
            if (nDoclist > 0) {
                rc = fts3GrowSegReaderBuffer(pCsr, @as(i64, nDoclist) + FTS3_NODE_PADDING);
                if (rc != 0) return rc;
                _ = memset(pCsr.aBuffer.? + @as(usize, @intCast(nDoclist)), 0, @intCast(FTS3_NODE_PADDING));
                pCsr.aDoclist = pCsr.aBuffer;
                pCsr.nDoclist = nDoclist;
                rc = SQLITE_ROW;
            }
        }
        pCsr.nAdvance = nMerge;

        if (rc != SQLITE_OK) break;
    }
    return rc;
}

export fn sqlite3Fts3SegReaderFinish(pCsr: *Fts3MultiSegReader) callconv(.c) void {
    if (pCsr.apSegment != null or pCsr.aBuffer != null or pCsr.nSegment != 0) {
        var i: c_int = 0;
        while (i < pCsr.nSegment) : (i += 1) {
            sqlite3Fts3SegReaderFree(pCsr.apSegment.?[@intCast(i)]);
        }
        sqlite3_free(@ptrCast(pCsr.apSegment));
        sqlite3_free(pCsr.aBuffer);

        pCsr.nSegment = 0;
        pCsr.apSegment = null;
        pCsr.aBuffer = null;
    }
}

// ===========================================================================
// Segment merge + pending-terms flush.
// ===========================================================================

fn fts3ReadEndBlockField(pStmt: ?*sqlite3_stmt, iCol: c_int, piEndBlock: *i64, pnByte: *i64) void {
    const zText = sqlite3_column_text(pStmt, iCol);
    if (zText) |zt| {
        var i: usize = 0;
        var iMul: i64 = 1;
        var iVal: u64 = 0;
        while (zt[i] >= '0' and zt[i] <= '9') : (i += 1) {
            iVal = iVal *% 10 +% (zt[i] - '0');
        }
        piEndBlock.* = @bitCast(iVal);
        while (zt[i] == ' ') i += 1;
        iVal = 0;
        if (zt[i] == '-') {
            i += 1;
            iMul = -1;
        }
        while (zt[i] >= '0' and zt[i] <= '9') : (i += 1) {
            iVal = iVal *% 10 +% (zt[i] - '0');
        }
        if (@as(i64, @bitCast(iVal)) == SMALLEST_INT64) iMul = 1;
        pnByte.* = @as(i64, @bitCast(iVal)) *% iMul;
    }
}

fn fts3PromoteSegments(p: *Fts3Table, iAbsLevel: i64, nByte: i64) c_int {
    var pRange: ?*sqlite3_stmt = undefined;
    var rc = fts3SqlStmt(p, SQL_SELECT_LEVEL_RANGE2, &pRange, null);

    if (rc == SQLITE_OK) {
        var bOk: c_int = 0;
        const iLast: i64 = (@divTrunc(iAbsLevel, FTS3_SEGDIR_MAXLEVEL) + 1) * FTS3_SEGDIR_MAXLEVEL - 1;
        const nLimit: i64 = @divTrunc(nByte * 3, 2);

        _ = sqlite3_bind_int64(pRange, 1, iAbsLevel + 1);
        _ = sqlite3_bind_int64(pRange, 2, iLast);
        while (SQLITE_ROW == sqlite3_step(pRange)) {
            var nSize: i64 = 0;
            var dummy: i64 = undefined;
            fts3ReadEndBlockField(pRange, 2, &dummy, &nSize);
            if (nSize <= 0 or nSize > nLimit) {
                bOk = 0;
                break;
            }
            bOk = 1;
        }
        rc = sqlite3_reset(pRange);

        if (bOk != 0) {
            var iIdx: c_int = 0;
            var pUpdate1: ?*sqlite3_stmt = null;
            var pUpdate2: ?*sqlite3_stmt = null;

            if (rc == SQLITE_OK) {
                rc = fts3SqlStmt(p, SQL_UPDATE_LEVEL_IDX, &pUpdate1, null);
            }
            if (rc == SQLITE_OK) {
                rc = fts3SqlStmt(p, SQL_UPDATE_LEVEL, &pUpdate2, null);
            }

            if (rc == SQLITE_OK) {
                _ = sqlite3_bind_int64(pRange, 1, iAbsLevel);
                while (SQLITE_ROW == sqlite3_step(pRange)) {
                    _ = sqlite3_bind_int(pUpdate1, 1, iIdx);
                    iIdx += 1;
                    _ = sqlite3_bind_int(pUpdate1, 2, sqlite3_column_int(pRange, 0));
                    _ = sqlite3_bind_int(pUpdate1, 3, sqlite3_column_int(pRange, 1));
                    _ = sqlite3_step(pUpdate1);
                    rc = sqlite3_reset(pUpdate1);
                    if (rc != SQLITE_OK) {
                        _ = sqlite3_reset(pRange);
                        break;
                    }
                }
            }
            if (rc == SQLITE_OK) {
                rc = sqlite3_reset(pRange);
            }

            if (rc == SQLITE_OK) {
                _ = sqlite3_bind_int64(pUpdate2, 1, iAbsLevel);
                _ = sqlite3_step(pUpdate2);
                rc = sqlite3_reset(pUpdate2);
            }
        }
    }
    return rc;
}

fn fts3SegmentMerge(p: *Fts3Table, iLangid: c_int, iIndex: c_int, iLevel: c_int) c_int {
    var iIdx: c_int = 0;
    var iNewLevel: i64 = 0;
    var pWriter: ?*SegmentWriter = null;
    var filter: Fts3SegFilter = undefined;
    var csr: Fts3MultiSegReader = undefined;
    var bIgnoreEmpty: c_int = 0;
    var iMaxLevel: i64 = 0;

    var rc = sqlite3Fts3SegReaderCursor(p, iLangid, iIndex, iLevel, null, 0, 1, 0, &csr);
    if (rc != SQLITE_OK or csr.nSegment == 0) {
        fts3SegWriterFree(pWriter);
        sqlite3Fts3SegReaderFinish(&csr);
        return rc;
    }

    if (iLevel != FTS3_SEGCURSOR_PENDING) {
        rc = fts3SegmentMaxLevel(p, iLangid, iIndex, &iMaxLevel);
        if (rc != SQLITE_OK) {
            fts3SegWriterFree(pWriter);
            sqlite3Fts3SegReaderFinish(&csr);
            return rc;
        }
    }

    if (iLevel == FTS3_SEGCURSOR_ALL) {
        if (csr.nSegment == 1 and false == fts3SegReaderIsPending(csr.apSegment.?[0].?)) {
            fts3SegWriterFree(pWriter);
            sqlite3Fts3SegReaderFinish(&csr);
            return SQLITE_DONE;
        }
        iNewLevel = iMaxLevel;
        bIgnoreEmpty = 1;
    } else {
        iNewLevel = getAbsoluteLevel(p, iLangid, iIndex, iLevel + 1);
        rc = fts3AllocateSegdirIdx(p, iLangid, iIndex, iLevel + 1, &iIdx);
        bIgnoreEmpty = @intFromBool((iLevel != FTS3_SEGCURSOR_PENDING) and (iNewLevel > iMaxLevel));
    }
    if (rc != SQLITE_OK) {
        fts3SegWriterFree(pWriter);
        sqlite3Fts3SegReaderFinish(&csr);
        return rc;
    }

    _ = memset(&filter, 0, @sizeOf(Fts3SegFilter));
    filter.flags = FTS3_SEGMENT_REQUIRE_POS;
    filter.flags |= (if (bIgnoreEmpty != 0) FTS3_SEGMENT_IGNORE_EMPTY else 0);

    rc = sqlite3Fts3SegReaderStart(p, &csr, &filter);
    while (SQLITE_OK == rc) {
        rc = sqlite3Fts3SegReaderStep(p, &csr);
        if (rc != SQLITE_ROW) break;
        rc = fts3SegWriterAdd(p, &pWriter, 1, csr.zTerm.?, csr.nTerm, csr.aDoclist.?, csr.nDoclist);
    }
    if (rc != SQLITE_OK) {
        fts3SegWriterFree(pWriter);
        sqlite3Fts3SegReaderFinish(&csr);
        return rc;
    }

    if (iLevel != FTS3_SEGCURSOR_PENDING) {
        rc = fts3DeleteSegdir(p, iLangid, iIndex, iLevel, csr.apSegment.?, csr.nSegment);
        if (rc != SQLITE_OK) {
            fts3SegWriterFree(pWriter);
            sqlite3Fts3SegReaderFinish(&csr);
            return rc;
        }
    }
    if (pWriter) |w| {
        rc = fts3SegWriterFlush(p, w, iNewLevel, iIdx);
        if (rc == SQLITE_OK) {
            if (iLevel == FTS3_SEGCURSOR_PENDING or iNewLevel < iMaxLevel) {
                rc = fts3PromoteSegments(p, iNewLevel, w.nLeafData);
            }
        }
    }

    fts3SegWriterFree(pWriter);
    sqlite3Fts3SegReaderFinish(&csr);
    return rc;
}

export fn sqlite3Fts3PendingTermsFlush(p: *Fts3Table) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < p.nIndex) : (i += 1) {
        rc = fts3SegmentMerge(p, p.iPrevLangid, i, FTS3_SEGCURSOR_PENDING);
        if (rc == SQLITE_DONE) rc = SQLITE_OK;
    }

    if (rc == SQLITE_OK and p.bHasStat != 0 and p.nAutoincrmerge == 0xff and p.nLeafAdd > 0) {
        var pStmt: ?*sqlite3_stmt = null;
        rc = fts3SqlStmt(p, SQL_SELECT_STAT, &pStmt, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int(pStmt, 1, FTS_STAT_AUTOINCRMERGE);
            rc = sqlite3_step(pStmt);
            if (rc == SQLITE_ROW) {
                p.nAutoincrmerge = sqlite3_column_int(pStmt, 0);
                if (p.nAutoincrmerge == 1) p.nAutoincrmerge = 8;
            } else if (rc == SQLITE_DONE) {
                p.nAutoincrmerge = 0;
            }
            rc = sqlite3_reset(pStmt);
        }
    }

    if (rc == SQLITE_OK) {
        sqlite3Fts3PendingTermsClear(p);
    }
    return rc;
}

fn fts3EncodeIntArray(N: c_int, a: [*]u32, zBuf: [*]u8, pNBuf: *c_int) void {
    var j: c_int = 0;
    var i: c_int = 0;
    while (i < N) : (i += 1) {
        j += sqlite3Fts3PutVarint(zBuf + @as(usize, @intCast(j)), @intCast(a[@intCast(i)]));
    }
    pNBuf.* = j;
}

fn fts3DecodeIntArray(N: c_int, a: [*]u32, zBuf: [*]const u8, nBuf: c_int) void {
    var i: c_int = 0;
    if (nBuf != 0 and (zBuf[@intCast(nBuf - 1)] & 0x80) == 0) {
        var j: c_int = 0;
        while (i < N and j < nBuf) : (i += 1) {
            var x: i64 = undefined;
            j += sqlite3Fts3GetVarint(zBuf + @as(usize, @intCast(j)), &x);
            a[@intCast(i)] = @truncate(@as(u64, @bitCast(x)));
        }
    }
    while (i < N) : (i += 1) {
        a[@intCast(i)] = 0;
    }
}

fn fts3InsertDocsize(pRC: *c_int, p: *Fts3Table, aSz: [*]u32) void {
    if (pRC.* != 0) return;
    const pBlob: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(10 * @as(i64, p.nColumn)))));
    if (pBlob == null) {
        pRC.* = SQLITE_NOMEM;
        return;
    }
    var nBlob: c_int = undefined;
    fts3EncodeIntArray(p.nColumn, aSz, pBlob.?, &nBlob);
    var pStmt: ?*sqlite3_stmt = undefined;
    const rc = fts3SqlStmt(p, SQL_REPLACE_DOCSIZE, &pStmt, null);
    if (rc != 0) {
        sqlite3_free(pBlob);
        pRC.* = rc;
        return;
    }
    _ = sqlite3_bind_int64(pStmt, 1, p.iPrevDocid);
    _ = sqlite3_bind_blob(pStmt, 2, pBlob, nBlob, sqliteFreeDtor);
    _ = sqlite3_step(pStmt);
    pRC.* = sqlite3_reset(pStmt);
}

fn fts3UpdateDocTotals(pRC: *c_int, p: *Fts3Table, aSzIns: [*]u32, aSzDel: [*]u32, nChng: c_int) void {
    if (pRC.* != 0) return;
    const nStat: c_int = p.nColumn + 2;

    const a: ?[*]u32 = @ptrCast(@alignCast(sqlite3_malloc64(@intCast((@sizeOf(u32) + 10) * @as(i64, nStat)))));
    if (a == null) {
        pRC.* = SQLITE_NOMEM;
        return;
    }
    const pBlob: [*]u8 = @ptrCast(a.? + @as(usize, @intCast(nStat)));
    var pStmt: ?*sqlite3_stmt = undefined;
    var rc = fts3SqlStmt(p, SQL_SELECT_STAT, &pStmt, null);
    if (rc != 0) {
        sqlite3_free(a);
        pRC.* = rc;
        return;
    }
    _ = sqlite3_bind_int(pStmt, 1, FTS_STAT_DOCTOTAL);
    if (sqlite3_step(pStmt) == SQLITE_ROW) {
        fts3DecodeIntArray(nStat, a.?, @ptrCast(sqlite3_column_blob(pStmt, 0)), sqlite3_column_bytes(pStmt, 0));
    } else {
        _ = memset(a, 0, @sizeOf(u32) * @as(usize, @intCast(nStat)));
    }
    rc = sqlite3_reset(pStmt);
    if (rc != SQLITE_OK) {
        sqlite3_free(a);
        pRC.* = rc;
        return;
    }
    if (nChng < 0 and a.?[0] < @as(u32, @intCast(-nChng))) {
        a.?[0] = 0;
    } else {
        a.?[0] +%= @bitCast(nChng);
    }
    var i: c_int = 0;
    while (i < p.nColumn + 1) : (i += 1) {
        var x = a.?[@intCast(i + 1)];
        if (x +% aSzIns[@intCast(i)] < aSzDel[@intCast(i)]) {
            x = 0;
        } else {
            x = x +% aSzIns[@intCast(i)] -% aSzDel[@intCast(i)];
        }
        a.?[@intCast(i + 1)] = x;
    }
    var nBlob: c_int = undefined;
    fts3EncodeIntArray(nStat, a.?, pBlob, &nBlob);
    rc = fts3SqlStmt(p, SQL_REPLACE_STAT, &pStmt, null);
    if (rc != 0) {
        sqlite3_free(a);
        pRC.* = rc;
        return;
    }
    _ = sqlite3_bind_int(pStmt, 1, FTS_STAT_DOCTOTAL);
    _ = sqlite3_bind_blob(pStmt, 2, pBlob, nBlob, SQLITE_STATIC);
    _ = sqlite3_step(pStmt);
    pRC.* = sqlite3_reset(pStmt);
    _ = sqlite3_bind_null(pStmt, 2);
    sqlite3_free(a);
}

// ===========================================================================
// Optimize / rebuild.
// ===========================================================================

fn fts3DoOptimize(p: *Fts3Table, bReturnDone: c_int) c_int {
    var bSeenDone: c_int = 0;
    var pAllLangid: ?*sqlite3_stmt = null;

    var rc = sqlite3Fts3PendingTermsFlush(p);
    if (rc == SQLITE_OK) {
        rc = fts3SqlStmt(p, SQL_SELECT_ALL_LANGID, &pAllLangid, null);
    }
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int(pAllLangid, 1, p.iPrevLangid);
        _ = sqlite3_bind_int(pAllLangid, 2, p.nIndex);
        while (sqlite3_step(pAllLangid) == SQLITE_ROW) {
            const iLangid = sqlite3_column_int(pAllLangid, 0);
            var i: c_int = 0;
            while (rc == SQLITE_OK and i < p.nIndex) : (i += 1) {
                rc = fts3SegmentMerge(p, iLangid, i, FTS3_SEGCURSOR_ALL);
                if (rc == SQLITE_DONE) {
                    bSeenDone = 1;
                    rc = SQLITE_OK;
                }
            }
        }
        const rc2 = sqlite3_reset(pAllLangid);
        if (rc == SQLITE_OK) rc = rc2;
    }

    sqlite3Fts3SegmentsClose(p);

    return if (rc == SQLITE_OK and bReturnDone != 0 and bSeenDone != 0) SQLITE_DONE else rc;
}

fn fts3DoRebuild(p: *Fts3Table) c_int {
    var rc = fts3DeleteAll(p, 0);
    if (rc == SQLITE_OK) {
        var aSz: ?[*]u32 = null;
        var aSzIns: [*]u32 = undefined;
        var aSzDel: [*]u32 = undefined;
        var pStmt: ?*sqlite3_stmt = null;
        var nEntry: c_int = 0;

        const zSql = sqlite3_mprintf("SELECT %s", p.zReadExprlist);
        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3Fts3PrepareStmt(p, zSql.?, 0, 1, &pStmt);
            sqlite3_free(zSql);
        }

        if (rc == SQLITE_OK) {
            const nByte: i64 = @sizeOf(u32) * (@as(i64, p.nColumn) + 1) * 3;
            aSz = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
            if (aSz == null) {
                rc = SQLITE_NOMEM;
            } else {
                _ = memset(aSz, 0, @intCast(nByte));
                aSzIns = aSz.? + @as(usize, @intCast(p.nColumn + 1));
                aSzDel = aSzIns + @as(usize, @intCast(p.nColumn + 1));
            }
        }

        while (rc == SQLITE_OK and SQLITE_ROW == sqlite3_step(pStmt)) {
            const iLangid = langidFromSelect(p, pStmt);
            rc = fts3PendingTermsDocid(p, 0, iLangid, sqlite3_column_int64(pStmt, 0));
            _ = memset(aSz, 0, @sizeOf(u32) * @as(usize, @intCast(p.nColumn + 1)));
            var iCol: c_int = 0;
            while (rc == SQLITE_OK and iCol < p.nColumn) : (iCol += 1) {
                if (p.abNotindexed.?[@intCast(iCol)] == 0) {
                    const z = sqlite3_column_text(pStmt, iCol + 1);
                    rc = fts3PendingTermsAdd(p, iLangid, z, iCol, &aSz.?[@intCast(iCol)]);
                    aSz.?[@intCast(p.nColumn)] +%= @bitCast(sqlite3_column_bytes(pStmt, iCol + 1));
                }
            }
            if (p.bHasDocsize != 0) {
                fts3InsertDocsize(&rc, p, aSz.?);
            }
            if (rc != SQLITE_OK) {
                _ = sqlite3_finalize(pStmt);
                pStmt = null;
            } else {
                nEntry += 1;
                iCol = 0;
                while (iCol <= p.nColumn) : (iCol += 1) {
                    aSzIns[@intCast(iCol)] +%= aSz.?[@intCast(iCol)];
                }
            }
        }
        if (p.bFts4 != 0) {
            fts3UpdateDocTotals(&rc, p, aSzIns, aSzDel, nEntry);
        }
        sqlite3_free(aSz);

        if (pStmt != null) {
            const rc2 = sqlite3_finalize(pStmt);
            if (rc == SQLITE_OK) {
                rc = rc2;
            }
        }
    }
    return rc;
}

fn fts3IncrmergeCsr(p: *Fts3Table, iAbsLevel: i64, nSeg: c_int, pCsr: *Fts3MultiSegReader) c_int {
    var rc: c_int = undefined;
    var pStmt: ?*sqlite3_stmt = null;

    _ = memset(pCsr, 0, @sizeOf(Fts3MultiSegReader));
    const nByte: i64 = @sizeOf(?*Fts3SegReader) * @as(i64, nSeg);
    pCsr.apSegment = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));

    if (pCsr.apSegment == null) {
        rc = SQLITE_NOMEM;
    } else {
        _ = memset(@ptrCast(pCsr.apSegment), 0, @intCast(nByte));
        rc = fts3SqlStmt(p, SQL_SELECT_LEVEL, &pStmt, null);
    }
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pStmt, 1, iAbsLevel);
        var i: c_int = 0;
        while (rc == SQLITE_OK and sqlite3_step(pStmt) == SQLITE_ROW and i < nSeg) : (i += 1) {
            rc = sqlite3Fts3SegReaderNew(
                i,
                0,
                sqlite3_column_int64(pStmt, 1),
                sqlite3_column_int64(pStmt, 2),
                sqlite3_column_int64(pStmt, 3),
                @ptrCast(sqlite3_column_blob(pStmt, 4)),
                sqlite3_column_bytes(pStmt, 4),
                &pCsr.apSegment.?[@intCast(i)],
            );
            pCsr.nSegment += 1;
        }
        const rc2 = sqlite3_reset(pStmt);
        if (rc == SQLITE_OK) rc = rc2;
    }
    return rc;
}

// ===========================================================================
// Incremental merge: appendable segment writer + node reader.
// ===========================================================================

fn blobGrowBuffer(pBlob: *Blob, nMin: c_int, pRc: *c_int) void {
    if (pRc.* == SQLITE_OK and nMin > pBlob.nAlloc) {
        const nAlloc = nMin;
        const a: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(pBlob.a, @intCast(nAlloc))));
        if (a != null) {
            pBlob.nAlloc = nAlloc;
            pBlob.a = a;
        } else {
            pRc.* = SQLITE_NOMEM;
        }
    }
}

fn nodeReaderNext(p: *NodeReader) c_int {
    const bFirst = (p.term.n == 0);
    var nPrefix: c_int = 0;
    var nSuffix: c_int = 0;
    var rc: c_int = SQLITE_OK;

    if (p.iChild != 0 and bFirst == false) p.iChild += 1;
    if (p.iOff >= p.nNode) {
        p.aNode = null;
    } else {
        if (bFirst == false) {
            p.iOff += fts3GetVarint32(p.aNode.? + @as(usize, @intCast(p.iOff)), &nPrefix);
        }
        p.iOff += fts3GetVarint32(p.aNode.? + @as(usize, @intCast(p.iOff)), &nSuffix);

        if (nPrefix > p.term.n or nSuffix > p.nNode - p.iOff or nSuffix == 0) {
            return FTS_CORRUPT_VTAB();
        }
        blobGrowBuffer(&p.term, nPrefix + nSuffix, &rc);
        if (rc == SQLITE_OK and p.term.a != null) {
            _ = memcpy(p.term.a.? + @as(usize, @intCast(nPrefix)), p.aNode.? + @as(usize, @intCast(p.iOff)), @intCast(nSuffix));
            p.term.n = nPrefix + nSuffix;
            p.iOff += nSuffix;
            if (p.iChild == 0) {
                p.iOff += fts3GetVarint32(p.aNode.? + @as(usize, @intCast(p.iOff)), &p.nDoclist);
                if ((p.nNode - p.iOff) < p.nDoclist) {
                    return FTS_CORRUPT_VTAB();
                }
                p.aDoclist = p.aNode.? + @as(usize, @intCast(p.iOff));
                p.iOff += p.nDoclist;
            }
        }
    }
    return rc;
}

fn nodeReaderRelease(p: *NodeReader) void {
    sqlite3_free(p.term.a);
}

fn nodeReaderInit(p: *NodeReader, aNode: ?[*]const u8, nNode: c_int) c_int {
    _ = memset(p, 0, @sizeOf(NodeReader));
    p.aNode = aNode;
    p.nNode = nNode;

    if (aNode != null and aNode.?[0] != 0) {
        p.iOff = 1 + sqlite3Fts3GetVarint(aNode.? + 1, &p.iChild);
    } else {
        p.iOff = 1;
    }

    return if (aNode != null) nodeReaderNext(p) else SQLITE_OK;
}

fn fts3IncrmergePush(p: *Fts3Table, pWriter: *IncrmergeWriter, zTerm: [*]const u8, nTerm: c_int) c_int {
    var iPtr = pWriter.aNodeWriter[0].iBlock;
    var iLayer: c_int = 1;
    while (iLayer < FTS_MAX_APPENDABLE_HEIGHT) : (iLayer += 1) {
        var iNextPtr: i64 = 0;
        const pNode = &pWriter.aNodeWriter[@intCast(iLayer)];
        var rc: c_int = SQLITE_OK;

        const nPrefix = fts3PrefixCompress(pNode.key.a, pNode.key.n, zTerm, nTerm);
        const nSuffix = nTerm - nPrefix;
        if (nSuffix <= 0) return FTS_CORRUPT_VTAB();
        var nSpace = sqlite3Fts3VarintLen(@intCast(nPrefix));
        nSpace += sqlite3Fts3VarintLen(@intCast(nSuffix)) + nSuffix;

        if (pNode.key.n == 0 or (pNode.block.n + nSpace) <= p.nNodeSize) {
            const pBlk = &pNode.block;
            if (pBlk.n == 0) {
                blobGrowBuffer(pBlk, p.nNodeSize, &rc);
                if (rc == SQLITE_OK) {
                    pBlk.a.?[0] = @intCast(iLayer);
                    pBlk.n = 1 + sqlite3Fts3PutVarint(pBlk.a.? + 1, iPtr);
                }
            }
            blobGrowBuffer(pBlk, pBlk.n + nSpace, &rc);
            blobGrowBuffer(&pNode.key, nTerm, &rc);

            if (rc == SQLITE_OK) {
                if (pNode.key.n != 0) {
                    pBlk.n += sqlite3Fts3PutVarint(pBlk.a.? + @as(usize, @intCast(pBlk.n)), @intCast(nPrefix));
                }
                pBlk.n += sqlite3Fts3PutVarint(pBlk.a.? + @as(usize, @intCast(pBlk.n)), @intCast(nSuffix));
                _ = memcpy(pBlk.a.? + @as(usize, @intCast(pBlk.n)), zTerm + @as(usize, @intCast(nPrefix)), @intCast(nSuffix));
                pBlk.n += nSuffix;

                _ = memcpy(pNode.key.a.?, zTerm, @intCast(nTerm));
                pNode.key.n = nTerm;
            }
        } else {
            rc = fts3WriteSegment(p, pNode.iBlock, pNode.block.a, pNode.block.n);
            pNode.block.a.?[0] = @intCast(iLayer);
            pNode.block.n = 1 + sqlite3Fts3PutVarint(pNode.block.a.? + 1, iPtr + 1);

            iNextPtr = pNode.iBlock;
            pNode.iBlock += 1;
            pNode.key.n = 0;
        }

        if (rc != SQLITE_OK or iNextPtr == 0) return rc;
        iPtr = iNextPtr;
    }
    return 0;
}

fn fts3AppendToNode(
    pNode: *Blob,
    pPrev: *Blob,
    zTerm: [*]const u8,
    nTerm: c_int,
    aDoclist: ?[*]const u8,
    nDoclist: c_int,
) c_int {
    var rc: c_int = SQLITE_OK;
    const bFirst = (pPrev.n == 0);

    blobGrowBuffer(pPrev, nTerm, &rc);
    if (rc != SQLITE_OK) return rc;

    const nPrefix = fts3PrefixCompress(pPrev.a, pPrev.n, zTerm, nTerm);
    const nSuffix = nTerm - nPrefix;
    if (nSuffix <= 0) return FTS_CORRUPT_VTAB();
    _ = memcpy(pPrev.a.?, zTerm, @intCast(nTerm));
    pPrev.n = nTerm;

    if (bFirst == false) {
        pNode.n += sqlite3Fts3PutVarint(pNode.a.? + @as(usize, @intCast(pNode.n)), @intCast(nPrefix));
    }
    pNode.n += sqlite3Fts3PutVarint(pNode.a.? + @as(usize, @intCast(pNode.n)), @intCast(nSuffix));
    _ = memcpy(pNode.a.? + @as(usize, @intCast(pNode.n)), zTerm + @as(usize, @intCast(nPrefix)), @intCast(nSuffix));
    pNode.n += nSuffix;

    if (aDoclist != null) {
        pNode.n += sqlite3Fts3PutVarint(pNode.a.? + @as(usize, @intCast(pNode.n)), @intCast(nDoclist));
        _ = memcpy(pNode.a.? + @as(usize, @intCast(pNode.n)), aDoclist, @intCast(nDoclist));
        pNode.n += nDoclist;
    }

    return SQLITE_OK;
}

fn fts3IncrmergeAppend(p: *Fts3Table, pWriter: *IncrmergeWriter, pCsr: *Fts3MultiSegReader) c_int {
    const zTerm = pCsr.zTerm.?;
    const nTerm = pCsr.nTerm;
    const aDoclist = pCsr.aDoclist.?;
    const nDoclist = pCsr.nDoclist;
    var rc: c_int = SQLITE_OK;

    const pLeaf = &pWriter.aNodeWriter[0];
    var nPrefix = fts3PrefixCompress(pLeaf.key.a, pLeaf.key.n, zTerm, nTerm);
    var nSuffix = nTerm - nPrefix;
    if (nSuffix <= 0) return FTS_CORRUPT_VTAB();

    var nSpace = sqlite3Fts3VarintLen(@intCast(nPrefix));
    nSpace += sqlite3Fts3VarintLen(@intCast(nSuffix)) + nSuffix;
    nSpace += sqlite3Fts3VarintLen(@intCast(nDoclist)) + nDoclist;

    if (pLeaf.block.n > 0 and (pLeaf.block.n + nSpace) > p.nNodeSize and pLeaf.iBlock < (pWriter.iStart + pWriter.nLeafEst)) {
        rc = fts3WriteSegment(p, pLeaf.iBlock, pLeaf.block.a, pLeaf.block.n);
        pWriter.nWork += 1;

        if (rc == SQLITE_OK) {
            rc = fts3IncrmergePush(p, pWriter, zTerm, nPrefix + 1);
        }

        pLeaf.iBlock += 1;
        pLeaf.key.n = 0;
        pLeaf.block.n = 0;

        nSuffix = nTerm;
        nSpace = 1;
        nSpace += sqlite3Fts3VarintLen(@intCast(nSuffix)) + nSuffix;
        nSpace += sqlite3Fts3VarintLen(@intCast(nDoclist)) + nDoclist;
        nPrefix = 0;
    }

    pWriter.nLeafData += nSpace;
    blobGrowBuffer(&pLeaf.block, pLeaf.block.n + nSpace, &rc);
    if (rc == SQLITE_OK) {
        if (pLeaf.block.n == 0) {
            pLeaf.block.n = 1;
            pLeaf.block.a.?[0] = 0;
        }
        rc = fts3AppendToNode(&pLeaf.block, &pLeaf.key, zTerm, nTerm, aDoclist, nDoclist);
    }

    return rc;
}

fn fts3IncrmergeRelease(p: *Fts3Table, pWriter: *IncrmergeWriter, pRc: *c_int) void {
    var rc = pRc.*;
    var iRoot: c_int = FTS_MAX_APPENDABLE_HEIGHT - 1;
    while (iRoot >= 0) : (iRoot -= 1) {
        const pNode = &pWriter.aNodeWriter[@intCast(iRoot)];
        if (pNode.block.n > 0) break;
        sqlite3_free(pNode.block.a);
        sqlite3_free(pNode.key.a);
    }

    if (iRoot < 0) return;

    if (iRoot == 0) {
        const pBlock = &pWriter.aNodeWriter[1].block;
        blobGrowBuffer(pBlock, 1 + FTS3_VARINT_MAX, &rc);
        if (rc == SQLITE_OK) {
            pBlock.a.?[0] = 0x01;
            pBlock.n = 1 + sqlite3Fts3PutVarint(pBlock.a.? + 1, pWriter.aNodeWriter[0].iBlock);
        }
        iRoot = 1;
    }
    const pRoot = &pWriter.aNodeWriter[@intCast(iRoot)];

    var i: c_int = 0;
    while (i < iRoot) : (i += 1) {
        const pNode = &pWriter.aNodeWriter[@intCast(i)];
        if (pNode.block.n > 0 and rc == SQLITE_OK) {
            rc = fts3WriteSegment(p, pNode.iBlock, pNode.block.a, pNode.block.n);
        }
        sqlite3_free(pNode.block.a);
        sqlite3_free(pNode.key.a);
    }

    if (rc == SQLITE_OK) {
        rc = fts3WriteSegdir(
            p,
            pWriter.iAbsLevel + 1,
            pWriter.iIdx,
            pWriter.iStart,
            pWriter.aNodeWriter[0].iBlock,
            pWriter.iEnd,
            if (pWriter.bNoLeafData == 0) pWriter.nLeafData else 0,
            pRoot.block.a,
            pRoot.block.n,
        );
    }
    sqlite3_free(pRoot.block.a);
    sqlite3_free(pRoot.key.a);

    pRc.* = rc;
}

fn fts3TermCmp(zLhs: ?[*]const u8, nLhs: c_int, zRhs: ?[*]const u8, nRhs: c_int) c_int {
    const nCmp = imin(nLhs, nRhs);
    var res: c_int = undefined;
    if (nCmp != 0 and zLhs != null and zRhs != null) {
        res = memcmp(zLhs, zRhs, @intCast(nCmp));
    } else {
        res = 0;
    }
    if (res == 0) res = nLhs - nRhs;
    return res;
}

fn fts3IsAppendable(p: *Fts3Table, iEnd: i64, pbRes: *c_int) c_int {
    var bRes: c_int = 0;
    var pCheck: ?*sqlite3_stmt = null;
    const rc = fts3SqlStmt(p, SQL_SEGMENT_IS_APPENDABLE, &pCheck, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pCheck, 1, iEnd);
        if (SQLITE_ROW == sqlite3_step(pCheck)) bRes = 1;
        const rc2 = sqlite3_reset(pCheck);
        pbRes.* = bRes;
        return rc2;
    }
    pbRes.* = bRes;
    return rc;
}

fn fts3IncrmergeLoad(
    p: *Fts3Table,
    iAbsLevel: i64,
    iIdx: c_int,
    zKey: [*]const u8,
    nKey: c_int,
    pWriter: *IncrmergeWriter,
) c_int {
    var pSelect: ?*sqlite3_stmt = null;
    var rc = fts3SqlStmt(p, SQL_SELECT_SEGDIR, &pSelect, null);
    if (rc == SQLITE_OK) {
        var iStart: i64 = 0;
        var iLeafEnd: i64 = 0;
        var iEnd: i64 = 0;
        var aRoot: ?[*]const u8 = null;
        var nRoot: c_int = 0;
        var bAppendable: c_int = 0;

        _ = sqlite3_bind_int64(pSelect, 1, iAbsLevel + 1);
        _ = sqlite3_bind_int(pSelect, 2, iIdx);
        if (sqlite3_step(pSelect) == SQLITE_ROW) {
            iStart = sqlite3_column_int64(pSelect, 1);
            iLeafEnd = sqlite3_column_int64(pSelect, 2);
            fts3ReadEndBlockField(pSelect, 3, &iEnd, &pWriter.nLeafData);
            if (pWriter.nLeafData < 0) {
                pWriter.nLeafData = pWriter.nLeafData * -1;
            }
            pWriter.bNoLeafData = @intFromBool(pWriter.nLeafData == 0);
            nRoot = sqlite3_column_bytes(pSelect, 4);
            aRoot = @ptrCast(sqlite3_column_blob(pSelect, 4));
            if (aRoot == null) {
                _ = sqlite3_reset(pSelect);
                return if (nRoot != 0) SQLITE_NOMEM else FTS_CORRUPT_VTAB();
            }
        } else {
            return sqlite3_reset(pSelect);
        }

        rc = fts3IsAppendable(p, iEnd, &bAppendable);

        if (rc == SQLITE_OK and bAppendable != 0) {
            var aLeaf: ?[*]u8 = null;
            var nLeaf: c_int = 0;

            rc = sqlite3Fts3ReadBlock(p, iLeafEnd, &aLeaf, &nLeaf, null);
            if (rc == SQLITE_OK) {
                var reader: NodeReader = undefined;
                rc = nodeReaderInit(&reader, aLeaf, nLeaf);
                while (rc == SQLITE_OK and reader.aNode != null) {
                    rc = nodeReaderNext(&reader);
                }
                if (fts3TermCmp(zKey, nKey, reader.term.a, reader.term.n) <= 0) {
                    bAppendable = 0;
                }
                nodeReaderRelease(&reader);
            }
            sqlite3_free(aLeaf);
        }

        if (rc == SQLITE_OK and bAppendable != 0) {
            const nHeight: c_int = aRoot.?[0];
            if (nHeight < 1 or nHeight >= FTS_MAX_APPENDABLE_HEIGHT) {
                _ = sqlite3_reset(pSelect);
                return FTS_CORRUPT_VTAB();
            }

            pWriter.nLeafEst = @divTrunc((iEnd - iStart) + 1, FTS_MAX_APPENDABLE_HEIGHT);
            pWriter.iStart = iStart;
            pWriter.iEnd = iEnd;
            pWriter.iAbsLevel = iAbsLevel;
            pWriter.iIdx = iIdx;

            var i: c_int = nHeight + 1;
            while (i < FTS_MAX_APPENDABLE_HEIGHT) : (i += 1) {
                pWriter.aNodeWriter[@intCast(i)].iBlock = pWriter.iStart + i * pWriter.nLeafEst;
            }

            var pNode = &pWriter.aNodeWriter[@intCast(nHeight)];
            pNode.iBlock = pWriter.iStart + pWriter.nLeafEst * nHeight;
            blobGrowBuffer(&pNode.block, imax(nRoot, p.nNodeSize) + FTS3_NODE_PADDING, &rc);
            if (rc == SQLITE_OK) {
                _ = memcpy(pNode.block.a.?, aRoot, @intCast(nRoot));
                pNode.block.n = nRoot;
                _ = memset(pNode.block.a.? + @as(usize, @intCast(nRoot)), 0, @intCast(FTS3_NODE_PADDING));
            }

            i = nHeight;
            while (i >= 0 and rc == SQLITE_OK) : (i -= 1) {
                var reader: NodeReader = undefined;
                _ = memset(&reader, 0, @sizeOf(NodeReader));
                pNode = &pWriter.aNodeWriter[@intCast(i)];

                if (pNode.block.a != null) {
                    rc = nodeReaderInit(&reader, pNode.block.a, pNode.block.n);
                    while (reader.aNode != null and rc == SQLITE_OK) rc = nodeReaderNext(&reader);
                    blobGrowBuffer(&pNode.key, reader.term.n, &rc);
                    if (rc == SQLITE_OK) {
                        if (reader.term.n > 0) {
                            _ = memcpy(pNode.key.a.?, reader.term.a, @intCast(reader.term.n));
                        }
                        pNode.key.n = reader.term.n;
                        if (i > 0) {
                            var aBlock: ?[*]u8 = null;
                            var nBlock: c_int = 0;
                            pNode = &pWriter.aNodeWriter[@intCast(i - 1)];
                            pNode.iBlock = reader.iChild;
                            rc = sqlite3Fts3ReadBlock(p, reader.iChild, &aBlock, &nBlock, null);
                            blobGrowBuffer(&pNode.block, imax(nBlock, p.nNodeSize) + FTS3_NODE_PADDING, &rc);
                            if (rc == SQLITE_OK) {
                                _ = memcpy(pNode.block.a.?, aBlock, @intCast(nBlock));
                                pNode.block.n = nBlock;
                                _ = memset(pNode.block.a.? + @as(usize, @intCast(nBlock)), 0, @intCast(FTS3_NODE_PADDING));
                            }
                            sqlite3_free(aBlock);
                        }
                    }
                }
                nodeReaderRelease(&reader);
            }
        }

        const rc2 = sqlite3_reset(pSelect);
        if (rc == SQLITE_OK) rc = rc2;
    }
    return rc;
}

fn fts3IncrmergeOutputIdx(p: *Fts3Table, iAbsLevel: i64, piIdx: *c_int) c_int {
    var pOutputIdx: ?*sqlite3_stmt = null;
    var rc = fts3SqlStmt(p, SQL_NEXT_SEGMENT_INDEX, &pOutputIdx, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pOutputIdx, 1, iAbsLevel + 1);
        _ = sqlite3_step(pOutputIdx);
        piIdx.* = sqlite3_column_int(pOutputIdx, 0);
        rc = sqlite3_reset(pOutputIdx);
    }
    return rc;
}

fn fts3IncrmergeWriter(p: *Fts3Table, iAbsLevel: i64, iIdx: c_int, pCsr: *Fts3MultiSegReader, pWriter: *IncrmergeWriter) c_int {
    var nLeafEst: i64 = 0;
    var pLeafEst: ?*sqlite3_stmt = null;
    var pFirstBlock: ?*sqlite3_stmt = null;

    var rc = fts3SqlStmt(p, SQL_MAX_LEAF_NODE_ESTIMATE, &pLeafEst, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pLeafEst, 1, iAbsLevel);
        _ = sqlite3_bind_int64(pLeafEst, 2, pCsr.nSegment);
        if (SQLITE_ROW == sqlite3_step(pLeafEst)) {
            nLeafEst = sqlite3_column_int64(pLeafEst, 0);
        }
        rc = sqlite3_reset(pLeafEst);
    }
    if (rc != SQLITE_OK) return rc;

    rc = fts3SqlStmt(p, SQL_NEXT_SEGMENTS_ID, &pFirstBlock, null);
    if (rc == SQLITE_OK) {
        if (SQLITE_ROW == sqlite3_step(pFirstBlock)) {
            pWriter.iStart = sqlite3_column_int64(pFirstBlock, 0);
            pWriter.iEnd = pWriter.iStart - 1;
            pWriter.iEnd += nLeafEst * FTS_MAX_APPENDABLE_HEIGHT;
        }
        rc = sqlite3_reset(pFirstBlock);
    }
    if (rc != SQLITE_OK) return rc;

    rc = fts3WriteSegment(p, pWriter.iEnd, null, 0);
    if (rc != SQLITE_OK) return rc;

    pWriter.iAbsLevel = iAbsLevel;
    pWriter.nLeafEst = nLeafEst;
    pWriter.iIdx = iIdx;

    var i: c_int = 0;
    while (i < FTS_MAX_APPENDABLE_HEIGHT) : (i += 1) {
        pWriter.aNodeWriter[@intCast(i)].iBlock = pWriter.iStart + i * pWriter.nLeafEst;
    }
    return SQLITE_OK;
}

fn fts3RemoveSegdirEntry(p: *Fts3Table, iAbsLevel: i64, iIdx: c_int) c_int {
    var pDelete: ?*sqlite3_stmt = null;
    var rc = fts3SqlStmt(p, SQL_DELETE_SEGDIR_ENTRY, &pDelete, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pDelete, 1, iAbsLevel);
        _ = sqlite3_bind_int(pDelete, 2, iIdx);
        _ = sqlite3_step(pDelete);
        rc = sqlite3_reset(pDelete);
    }
    return rc;
}

fn fts3RepackSegdirLevel(p: *Fts3Table, iAbsLevel: i64) c_int {
    var aIdx: ?[*]c_int = null;
    var nIdx: c_int = 0;
    var nAlloc: c_int = 0;
    var pSelect: ?*sqlite3_stmt = null;
    var pUpdate: ?*sqlite3_stmt = null;

    var rc = fts3SqlStmt(p, SQL_SELECT_INDEXES, &pSelect, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pSelect, 1, iAbsLevel);
        while (SQLITE_ROW == sqlite3_step(pSelect)) {
            if (nIdx >= nAlloc) {
                nAlloc += 16;
                const aNew: ?[*]c_int = @ptrCast(@alignCast(sqlite3_realloc64(aIdx, @intCast(@as(i64, nAlloc) * @sizeOf(c_int)))));
                if (aNew == null) {
                    rc = SQLITE_NOMEM;
                    break;
                }
                aIdx = aNew;
            }
            aIdx.?[@intCast(nIdx)] = sqlite3_column_int(pSelect, 0);
            nIdx += 1;
        }
        const rc2 = sqlite3_reset(pSelect);
        if (rc == SQLITE_OK) rc = rc2;
    }

    if (rc == SQLITE_OK) {
        rc = fts3SqlStmt(p, SQL_SHIFT_SEGDIR_ENTRY, &pUpdate, null);
    }
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pUpdate, 2, iAbsLevel);
    }

    p.bIgnoreSavepoint = 1;
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nIdx) : (i += 1) {
        if (aIdx.?[@intCast(i)] != i) {
            _ = sqlite3_bind_int(pUpdate, 3, aIdx.?[@intCast(i)]);
            _ = sqlite3_bind_int(pUpdate, 1, i);
            _ = sqlite3_step(pUpdate);
            rc = sqlite3_reset(pUpdate);
        }
    }
    p.bIgnoreSavepoint = 0;

    sqlite3_free(aIdx);
    return rc;
}

fn fts3StartNode(pNode: *Blob, iHeight: c_int, iChild: i64) void {
    pNode.a.?[0] = @intCast(iHeight);
    if (iChild != 0) {
        pNode.n = 1 + sqlite3Fts3PutVarint(pNode.a.? + 1, iChild);
    } else {
        pNode.n = 1;
    }
}

fn fts3TruncateNode(aNode: [*]const u8, nNode: c_int, pNew: *Blob, zTerm: [*]const u8, nTerm: c_int, piBlock: *i64) c_int {
    var reader: NodeReader = undefined;
    var prev: Blob = .{ .a = null, .n = 0, .nAlloc = 0 };
    var rc: c_int = SQLITE_OK;

    if (nNode < 1) return FTS_CORRUPT_VTAB();
    const bLeaf = (aNode[0] == 0);

    blobGrowBuffer(pNew, nNode, &rc);
    if (rc != SQLITE_OK) return rc;
    pNew.n = 0;

    rc = nodeReaderInit(&reader, aNode, nNode);
    while (rc == SQLITE_OK and reader.aNode != null) : (rc = nodeReaderNext(&reader)) {
        if (pNew.n == 0) {
            const res = fts3TermCmp(reader.term.a, reader.term.n, zTerm, nTerm);
            if (res < 0 or (bLeaf == false and res == 0)) continue;
            fts3StartNode(pNew, @as(c_int, aNode[0]), reader.iChild);
            piBlock.* = reader.iChild;
        }
        rc = fts3AppendToNode(pNew, &prev, reader.term.a.?, reader.term.n, reader.aDoclist, reader.nDoclist);
        if (rc != SQLITE_OK) break;
    }
    if (pNew.n == 0) {
        fts3StartNode(pNew, @as(c_int, aNode[0]), reader.iChild);
        piBlock.* = reader.iChild;
    }

    nodeReaderRelease(&reader);
    sqlite3_free(prev.a);
    return rc;
}

fn fts3TruncateSegment(p: *Fts3Table, iAbsLevel: i64, iIdx: c_int, zTerm: [*]const u8, nTerm: c_int) c_int {
    var root: Blob = .{ .a = null, .n = 0, .nAlloc = 0 };
    var block: Blob = .{ .a = null, .n = 0, .nAlloc = 0 };
    var iBlock: i64 = 0;
    var iNewStart: i64 = 0;
    var iOldStart: i64 = 0;
    var pFetch: ?*sqlite3_stmt = null;

    var rc = fts3SqlStmt(p, SQL_SELECT_SEGDIR, &pFetch, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pFetch, 1, iAbsLevel);
        _ = sqlite3_bind_int(pFetch, 2, iIdx);
        if (SQLITE_ROW == sqlite3_step(pFetch)) {
            const aRoot: [*]const u8 = @ptrCast(sqlite3_column_blob(pFetch, 4));
            const nRoot = sqlite3_column_bytes(pFetch, 4);
            iOldStart = sqlite3_column_int64(pFetch, 1);
            rc = fts3TruncateNode(aRoot, nRoot, &root, zTerm, nTerm, &iBlock);
        }
        const rc2 = sqlite3_reset(pFetch);
        if (rc == SQLITE_OK) rc = rc2;
    }

    while (rc == SQLITE_OK and iBlock != 0) {
        var aBlock: ?[*]u8 = null;
        var nBlock: c_int = 0;
        iNewStart = iBlock;

        rc = sqlite3Fts3ReadBlock(p, iBlock, &aBlock, &nBlock, null);
        if (rc == SQLITE_OK) {
            rc = fts3TruncateNode(aBlock.?, nBlock, &block, zTerm, nTerm, &iBlock);
        }
        if (rc == SQLITE_OK) {
            rc = fts3WriteSegment(p, iNewStart, block.a, block.n);
        }
        sqlite3_free(aBlock);
    }

    if (rc == SQLITE_OK and iNewStart != 0) {
        var pDel: ?*sqlite3_stmt = null;
        rc = fts3SqlStmt(p, SQL_DELETE_SEGMENTS_RANGE, &pDel, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pDel, 1, iOldStart);
            _ = sqlite3_bind_int64(pDel, 2, iNewStart - 1);
            _ = sqlite3_step(pDel);
            rc = sqlite3_reset(pDel);
        }
    }

    if (rc == SQLITE_OK) {
        var pChomp: ?*sqlite3_stmt = null;
        rc = fts3SqlStmt(p, SQL_CHOMP_SEGDIR, &pChomp, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pChomp, 1, iNewStart);
            _ = sqlite3_bind_blob(pChomp, 2, root.a, root.n, SQLITE_STATIC);
            _ = sqlite3_bind_int64(pChomp, 3, iAbsLevel);
            _ = sqlite3_bind_int(pChomp, 4, iIdx);
            _ = sqlite3_step(pChomp);
            rc = sqlite3_reset(pChomp);
            _ = sqlite3_bind_null(pChomp, 2);
        }
    }

    sqlite3_free(root.a);
    sqlite3_free(block.a);
    return rc;
}

fn fts3IncrmergeChomp(p: *Fts3Table, iAbsLevel: i64, pCsr: *Fts3MultiSegReader, pnRem: *c_int) c_int {
    var nRem: c_int = 0;
    var rc: c_int = SQLITE_OK;

    var i: c_int = pCsr.nSegment - 1;
    while (i >= 0 and rc == SQLITE_OK) : (i -= 1) {
        var pSeg: ?*Fts3SegReader = null;
        var j: c_int = 0;
        while (j < pCsr.nSegment) : (j += 1) {
            pSeg = pCsr.apSegment.?[@intCast(j)];
            if (pSeg.?.iIdx == i) break;
        }

        if (pSeg.?.aNode == null) {
            rc = fts3DeleteSegment(p, pSeg.?);
            if (rc == SQLITE_OK) {
                rc = fts3RemoveSegdirEntry(p, iAbsLevel, pSeg.?.iIdx);
            }
            pnRem.* = 0;
        } else {
            const zTerm = pSeg.?.zTerm.?;
            const nTerm = pSeg.?.nTerm;
            rc = fts3TruncateSegment(p, iAbsLevel, pSeg.?.iIdx, zTerm, nTerm);
            nRem += 1;
        }
    }

    if (rc == SQLITE_OK and nRem != pCsr.nSegment) {
        rc = fts3RepackSegdirLevel(p, iAbsLevel);
    }

    pnRem.* = nRem;
    return rc;
}

fn fts3IncrmergeHintStore(p: *Fts3Table, pHint: *Blob) c_int {
    var pReplace: ?*sqlite3_stmt = null;
    var rc = fts3SqlStmt(p, SQL_REPLACE_STAT, &pReplace, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int(pReplace, 1, FTS_STAT_INCRMERGEHINT);
        _ = sqlite3_bind_blob(pReplace, 2, pHint.a, pHint.n, SQLITE_STATIC);
        _ = sqlite3_step(pReplace);
        rc = sqlite3_reset(pReplace);
        _ = sqlite3_bind_null(pReplace, 2);
    }
    return rc;
}

fn fts3IncrmergeHintLoad(p: *Fts3Table, pHint: *Blob) c_int {
    var pSelect: ?*sqlite3_stmt = null;
    pHint.n = 0;
    var rc = fts3SqlStmt(p, SQL_SELECT_STAT, &pSelect, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int(pSelect, 1, FTS_STAT_INCRMERGEHINT);
        if (SQLITE_ROW == sqlite3_step(pSelect)) {
            const aHint = sqlite3_column_blob(pSelect, 0);
            const nHint = sqlite3_column_bytes(pSelect, 0);
            if (aHint != null) {
                blobGrowBuffer(pHint, nHint, &rc);
                if (rc == SQLITE_OK) {
                    if (pHint.a != null) _ = memcpy(pHint.a.?, aHint, @intCast(nHint));
                    pHint.n = nHint;
                }
            }
        }
        const rc2 = sqlite3_reset(pSelect);
        if (rc == SQLITE_OK) rc = rc2;
    }
    return rc;
}

fn fts3IncrmergeHintPush(pHint: *Blob, iAbsLevel: i64, nInput: c_int, pRc: *c_int) void {
    blobGrowBuffer(pHint, pHint.n + 2 * FTS3_VARINT_MAX, pRc);
    if (pRc.* == SQLITE_OK) {
        pHint.n += sqlite3Fts3PutVarint(pHint.a.? + @as(usize, @intCast(pHint.n)), iAbsLevel);
        pHint.n += sqlite3Fts3PutVarint(pHint.a.? + @as(usize, @intCast(pHint.n)), @intCast(nInput));
    }
}

fn fts3IncrmergeHintPop(pHint: *Blob, piAbsLevel: *i64, pnInput: *c_int) c_int {
    const nHint = pHint.n;
    var i: c_int = pHint.n - 1;
    if ((pHint.a.?[@intCast(i)] & 0x80) != 0) return FTS_CORRUPT_VTAB();
    while (i > 0 and (pHint.a.?[@intCast(i - 1)] & 0x80) != 0) i -= 1;
    if (i == 0) return FTS_CORRUPT_VTAB();
    i -= 1;
    while (i > 0 and (pHint.a.?[@intCast(i - 1)] & 0x80) != 0) i -= 1;

    pHint.n = i;
    i += sqlite3Fts3GetVarint(pHint.a.? + @as(usize, @intCast(i)), piAbsLevel);
    i += fts3GetVarint32(pHint.a.? + @as(usize, @intCast(i)), pnInput);
    if (i != nHint) return FTS_CORRUPT_VTAB();

    return SQLITE_OK;
}

// sqlite3Fts3CreateStatTable is exported by fts3.zig (the ported sibling).
extern fn sqlite3Fts3CreateStatTable(pRc: *c_int, p: *Fts3Table) void;

export fn sqlite3Fts3Incrmerge(p: *Fts3Table, nMerge: c_int, nMin: c_int) callconv(.c) c_int {
    var nRem = nMerge;
    var nSeg: c_int = 0;
    var hint: Blob = .{ .a = null, .n = 0, .nAlloc = 0 };
    var bDirtyHint: c_int = 0;

    const nAlloc: c_int = @sizeOf(Fts3MultiSegReader) + @sizeOf(Fts3SegFilter) + @sizeOf(IncrmergeWriter);
    const pWriter: ?*IncrmergeWriter = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nAlloc))));
    if (pWriter == null) return SQLITE_NOMEM;
    const wBase: [*]u8 = @ptrCast(pWriter);
    const pFilter: *Fts3SegFilter = @ptrCast(@alignCast(wBase + @sizeOf(IncrmergeWriter)));
    const fBase: [*]u8 = @ptrCast(pFilter);
    const pCsr: *Fts3MultiSegReader = @ptrCast(@alignCast(fBase + @sizeOf(Fts3SegFilter)));

    var rc = fts3IncrmergeHintLoad(p, &hint);
    while (rc == SQLITE_OK and nRem > 0) {
        const nMod: i64 = FTS3_SEGDIR_MAXLEVEL * @as(i64, p.nIndex);
        var pFindLevel: ?*sqlite3_stmt = null;
        var bUseHint: c_int = 0;
        var iIdx: c_int = 0;
        var iAbsLevel: i64 = 0;

        rc = fts3SqlStmt(p, SQL_FIND_MERGE_LEVEL, &pFindLevel, null);
        _ = sqlite3_bind_int(pFindLevel, 1, imax(@as(c_int, 2), nMin));
        if (sqlite3_step(pFindLevel) == SQLITE_ROW) {
            iAbsLevel = sqlite3_column_int64(pFindLevel, 0);
            nSeg = sqlite3_column_int(pFindLevel, 1);
        } else {
            nSeg = -1;
        }
        rc = sqlite3_reset(pFindLevel);

        if (rc == SQLITE_OK and hint.n != 0) {
            const nHint = hint.n;
            var iHintAbsLevel: i64 = 0;
            var nHintSeg: c_int = 0;

            rc = fts3IncrmergeHintPop(&hint, &iHintAbsLevel, &nHintSeg);
            if (nSeg < 0 or @rem(iAbsLevel, nMod) >= @rem(iHintAbsLevel, nMod)) {
                iAbsLevel = iHintAbsLevel;
                nSeg = imin(imax(nMin, nSeg), nHintSeg);
                bUseHint = 1;
                bDirtyHint = 1;
            } else {
                hint.n = nHint;
            }
        }

        if (nSeg <= 0) break;

        if (iAbsLevel < 0 or iAbsLevel > (nMod << 32)) {
            rc = FTS_CORRUPT_VTAB();
            break;
        }

        _ = memset(pWriter, 0, @intCast(nAlloc));
        pFilter.flags = FTS3_SEGMENT_REQUIRE_POS;

        if (rc == SQLITE_OK) {
            rc = fts3IncrmergeOutputIdx(p, iAbsLevel, &iIdx);
            if (iIdx == 0 or (bUseHint != 0 and iIdx == 1)) {
                var bIgnore: c_int = 0;
                rc = fts3SegmentIsMaxLevel(p, iAbsLevel + 1, &bIgnore);
                if (bIgnore != 0) {
                    pFilter.flags |= FTS3_SEGMENT_IGNORE_EMPTY;
                }
            }
        }

        if (rc == SQLITE_OK) {
            rc = fts3IncrmergeCsr(p, iAbsLevel, nSeg, pCsr);
        }
        if (SQLITE_OK == rc and pCsr.nSegment == nSeg) {
            rc = sqlite3Fts3SegReaderStart(p, pCsr, pFilter);
            if (rc == SQLITE_OK) {
                var bEmpty: c_int = 0;
                rc = sqlite3Fts3SegReaderStep(p, pCsr);
                if (rc == SQLITE_OK) {
                    bEmpty = 1;
                } else if (rc != SQLITE_ROW) {
                    sqlite3Fts3SegReaderFinish(pCsr);
                    break;
                }
                if (bUseHint != 0 and iIdx > 0) {
                    const zKey = pCsr.zTerm;
                    const nKey = pCsr.nTerm;
                    rc = fts3IncrmergeLoad(p, iAbsLevel, iIdx - 1, zKey.?, nKey, pWriter.?);
                } else {
                    rc = fts3IncrmergeWriter(p, iAbsLevel, iIdx, pCsr, pWriter.?);
                }

                if (rc == SQLITE_OK and pWriter.?.nLeafEst != 0) {
                    if (bEmpty == 0) {
                        while (true) {
                            rc = fts3IncrmergeAppend(p, pWriter.?, pCsr);
                            if (rc == SQLITE_OK) rc = sqlite3Fts3SegReaderStep(p, pCsr);
                            if (pWriter.?.nWork >= nRem and rc == SQLITE_ROW) rc = SQLITE_OK;
                            if (rc != SQLITE_ROW) break;
                        }
                    }

                    if (rc == SQLITE_OK) {
                        nRem -= @intCast(1 + pWriter.?.nWork);
                        rc = fts3IncrmergeChomp(p, iAbsLevel, pCsr, &nSeg);
                        if (nSeg != 0) {
                            bDirtyHint = 1;
                            fts3IncrmergeHintPush(&hint, iAbsLevel, nSeg, &rc);
                        }
                    }
                }

                if (nSeg != 0) {
                    pWriter.?.nLeafData = pWriter.?.nLeafData * -1;
                }
                fts3IncrmergeRelease(p, pWriter.?, &rc);
                if (nSeg == 0 and pWriter.?.bNoLeafData == 0) {
                    _ = fts3PromoteSegments(p, iAbsLevel + 1, pWriter.?.nLeafData);
                }
            }
        }

        sqlite3Fts3SegReaderFinish(pCsr);
    }

    if (bDirtyHint != 0 and rc == SQLITE_OK) {
        rc = fts3IncrmergeHintStore(p, &hint);
    }

    sqlite3_free(pWriter);
    sqlite3_free(hint.a);
    return rc;
}

fn fts3Getint(pz: *[*:0]const u8) c_int {
    var z = pz.*;
    var i: c_int = 0;
    while (z[0] >= '0' and z[0] <= '9' and i < 214748363) {
        i = 10 * i + (z[0] - '0');
        z += 1;
    }
    pz.* = z;
    return i;
}

fn fts3DoIncrmerge(p: *Fts3Table, zParam: [*:0]const u8) c_int {
    var nMin: c_int = @divTrunc(MergeCount(p), 2);
    var nMerge: c_int = 0;
    var z = zParam;

    nMerge = fts3Getint(&z);

    if (z[0] == ',' and z[1] != 0) {
        z += 1;
        nMin = fts3Getint(&z);
    }

    if (z[0] != 0 or nMin < 2) {
        return SQLITE_ERROR;
    }
    var rc: c_int = SQLITE_OK;
    if (p.bHasStat == 0) {
        sqlite3Fts3CreateStatTable(&rc, p);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts3Incrmerge(p, nMerge, nMin);
    }
    sqlite3Fts3SegmentsClose(p);
    return rc;
}

fn fts3DoAutoincrmerge(p: *Fts3Table, zParam: [*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    var pStmt: ?*sqlite3_stmt = null;
    var z = zParam;
    p.nAutoincrmerge = fts3Getint(&z);
    if (p.nAutoincrmerge == 1 or p.nAutoincrmerge > MergeCount(p)) {
        p.nAutoincrmerge = 8;
    }
    if (p.bHasStat == 0) {
        sqlite3Fts3CreateStatTable(&rc, p);
        if (rc != 0) return rc;
    }
    rc = fts3SqlStmt(p, SQL_REPLACE_STAT, &pStmt, null);
    if (rc != 0) return rc;
    _ = sqlite3_bind_int(pStmt, 1, FTS_STAT_AUTOINCRMERGE);
    _ = sqlite3_bind_int(pStmt, 2, p.nAutoincrmerge);
    _ = sqlite3_step(pStmt);
    rc = sqlite3_reset(pStmt);
    return rc;
}

fn fts3ChecksumEntry(zTerm: [*]const u8, nTerm: c_int, iLangid: c_int, iIndex: c_int, iDocid: i64, iCol: c_int, iPos: c_int) u64 {
    var ret: u64 = @bitCast(iDocid);
    ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, iLangid)));
    ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, iIndex)));
    ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, iCol)));
    ret +%= (ret << 3) +% @as(u64, @bitCast(@as(i64, iPos)));
    var i: c_int = 0;
    while (i < nTerm) : (i += 1) {
        // C: ret += (ret<<3) + zTerm[i]; zTerm is `char` (signed) -> sign-extend.
        const sb: i64 = @as(i8, @bitCast(zTerm[@intCast(i)]));
        ret +%= (ret << 3) +% @as(u64, @bitCast(sb));
    }
    return ret;
}

fn fts3ChecksumIndex(p: *Fts3Table, iLangid: c_int, iIndex: c_int, pRc: *c_int) u64 {
    var filter: Fts3SegFilter = undefined;
    var csr: Fts3MultiSegReader = undefined;
    var cksum: u64 = 0;

    if (pRc.* != 0) return 0;

    _ = memset(&filter, 0, @sizeOf(Fts3SegFilter));
    _ = memset(&csr, 0, @sizeOf(Fts3MultiSegReader));
    filter.flags = FTS3_SEGMENT_REQUIRE_POS | FTS3_SEGMENT_IGNORE_EMPTY;
    filter.flags |= FTS3_SEGMENT_SCAN;

    var rc = sqlite3Fts3SegReaderCursor(p, iLangid, iIndex, FTS3_SEGCURSOR_ALL, null, 0, 0, 1, &csr);
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts3SegReaderStart(p, &csr, &filter);
    }

    if (rc == SQLITE_OK) {
        while (true) {
            rc = sqlite3Fts3SegReaderStep(p, &csr);
            if (rc != SQLITE_ROW) break;
            var pCsr = csr.aDoclist.?;
            const pEnd = pCsr + @as(usize, @intCast(csr.nDoclist));

            var iDocid: i64 = 0;
            var iCol: i64 = 0;
            var iPos: u64 = 0;

            pCsr += @intCast(sqlite3Fts3GetVarint(pCsr, &iDocid));
            while (@intFromPtr(pCsr) < @intFromPtr(pEnd)) {
                var iVal: u64 = 0;
                pCsr += @intCast(sqlite3Fts3GetVarintU(pCsr, &iVal));
                if (@intFromPtr(pCsr) < @intFromPtr(pEnd)) {
                    if (iVal == 0 or iVal == 1) {
                        iCol = 0;
                        iPos = 0;
                        if (iVal != 0) {
                            pCsr += @intCast(sqlite3Fts3GetVarint(pCsr, &iCol));
                        } else {
                            pCsr += @intCast(sqlite3Fts3GetVarintU(pCsr, &iVal));
                            if (p.bDescIdx != 0) {
                                iDocid = @bitCast(@as(u64, @bitCast(iDocid)) -% iVal);
                            } else {
                                iDocid = @bitCast(@as(u64, @bitCast(iDocid)) +% iVal);
                            }
                        }
                    } else {
                        iPos +%= (iVal - 2);
                        cksum = cksum ^ fts3ChecksumEntry(csr.zTerm.?, csr.nTerm, iLangid, iIndex, iDocid, @intCast(iCol), @intCast(@as(i64, @bitCast(iPos))));
                    }
                }
            }
        }
    }
    sqlite3Fts3SegReaderFinish(&csr);

    pRc.* = rc;
    return cksum;
}

export fn sqlite3Fts3IntegrityCheck(p: *Fts3Table, pbOk: *c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var cksum1: u64 = 0;
    var cksum2: u64 = 0;
    var pAllLangid: ?*sqlite3_stmt = null;

    rc = fts3SqlStmt(p, SQL_SELECT_ALL_LANGID, &pAllLangid, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int(pAllLangid, 1, p.iPrevLangid);
        _ = sqlite3_bind_int(pAllLangid, 2, p.nIndex);
        while (rc == SQLITE_OK and sqlite3_step(pAllLangid) == SQLITE_ROW) {
            const iLangid = sqlite3_column_int(pAllLangid, 0);
            var i: c_int = 0;
            while (i < p.nIndex) : (i += 1) {
                cksum1 = cksum1 ^ fts3ChecksumIndex(p, iLangid, i, &rc);
            }
        }
        const rc2 = sqlite3_reset(pAllLangid);
        if (rc == SQLITE_OK) rc = rc2;
    }

    if (rc == SQLITE_OK) {
        const pModule = p.pTokenizer.?.pModule.?;
        var pStmt: ?*sqlite3_stmt = null;

        const zSql = sqlite3_mprintf("SELECT %s", p.zReadExprlist);
        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3Fts3PrepareStmt(p, zSql.?, 0, 1, &pStmt);
            sqlite3_free(zSql);
        }

        while (rc == SQLITE_OK and SQLITE_ROW == sqlite3_step(pStmt)) {
            const iDocid = sqlite3_column_int64(pStmt, 0);
            const iLang = langidFromSelect(p, pStmt);
            var iCol: c_int = 0;

            while (rc == SQLITE_OK and iCol < p.nColumn) : (iCol += 1) {
                if (p.abNotindexed.?[@intCast(iCol)] == 0) {
                    const zText = sqlite3_column_text(pStmt, iCol + 1);
                    var pT: ?*sqlite3_tokenizer_cursor = null;

                    rc = sqlite3Fts3OpenTokenizer(p.pTokenizer.?, iLang, zText, -1, &pT);
                    while (rc == SQLITE_OK) {
                        var zToken: ?[*]const u8 = undefined;
                        var nToken: c_int = 0;
                        var iDum1: c_int = 0;
                        var iDum2: c_int = 0;
                        var iPos: c_int = 0;

                        rc = pModule.xNext.?(pT, &zToken, &nToken, &iDum1, &iDum2, &iPos);
                        if (rc == SQLITE_OK) {
                            cksum2 = cksum2 ^ fts3ChecksumEntry(zToken.?, nToken, iLang, 0, iDocid, iCol, iPos);
                            var i: c_int = 1;
                            while (i < p.nIndex) : (i += 1) {
                                if (p.aIndex.?[@intCast(i)].nPrefix <= nToken) {
                                    cksum2 = cksum2 ^ fts3ChecksumEntry(zToken.?, p.aIndex.?[@intCast(i)].nPrefix, iLang, i, iDocid, iCol, iPos);
                                }
                            }
                        }
                    }
                    if (pT != null) _ = pModule.xClose.?(pT);
                    if (rc == SQLITE_DONE) rc = SQLITE_OK;
                }
            }
        }

        _ = sqlite3_finalize(pStmt);
    }

    if (rc == SQLITE_CORRUPT_VTAB) {
        rc = SQLITE_OK;
        pbOk.* = 0;
    } else {
        pbOk.* = @intFromBool(rc == SQLITE_OK and cksum1 == cksum2);
    }
    return rc;
}

fn fts3DoIntegrityCheck(p: *Fts3Table) c_int {
    var bOk: c_int = 0;
    var rc = sqlite3Fts3IntegrityCheck(p, &bOk);
    if (rc == SQLITE_OK and bOk == 0) rc = FTS_CORRUPT_VTAB();
    return rc;
}

fn fts3SpecialInsert(p: *Fts3Table, pVal: ?*sqlite3_value) c_int {
    var rc: c_int = SQLITE_ERROR;
    const zVal = sqlite3_value_text(pVal);
    const nVal = sqlite3_value_bytes(pVal);

    if (zVal == null) {
        return SQLITE_NOMEM;
    } else if (nVal == 8 and 0 == sqlite3_strnicmp(zVal.?, "optimize", 8)) {
        rc = fts3DoOptimize(p, 0);
    } else if (nVal == 7 and 0 == sqlite3_strnicmp(zVal.?, "rebuild", 7)) {
        rc = fts3DoRebuild(p);
    } else if (nVal == 15 and 0 == sqlite3_strnicmp(zVal.?, "integrity-check", 15)) {
        rc = fts3DoIntegrityCheck(p);
    } else if (nVal > 6 and 0 == sqlite3_strnicmp(zVal.?, "merge=", 6)) {
        rc = fts3DoIncrmerge(p, zVal.? + 6);
    } else if (nVal > 10 and 0 == sqlite3_strnicmp(zVal.?, "automerge=", 10)) {
        rc = fts3DoAutoincrmerge(p, zVal.? + 10);
    } else if (nVal == 5 and 0 == sqlite3_strnicmp(zVal.?, "flush", 5)) {
        rc = sqlite3Fts3PendingTermsFlush(p);
    } else if (config.sqlite_debug or config.sqlite_test) {
        var v: c_int = undefined;
        if (nVal > 9 and 0 == sqlite3_strnicmp(zVal.?, "nodesize=", 9)) {
            v = atoi(zVal.? + 9);
            if (v >= 24 and v <= p.nPgsz - 35) p.nNodeSize = v;
            rc = SQLITE_OK;
        } else if (nVal > 11 and 0 == sqlite3_strnicmp(zVal.?, "maxpending=", 11)) {
            v = atoi(zVal.? + 11);
            if (v >= 64 and v <= FTS3_MAX_PENDING_DATA) p.nMaxPendingData = v;
            rc = SQLITE_OK;
        } else if (nVal > 21 and 0 == sqlite3_strnicmp(zVal.?, "test-no-incr-doclist=", 21)) {
            if (config.sqlite_debug or config.sqlite_test) p.bNoIncrDoclist = atoi(zVal.? + 21);
            rc = SQLITE_OK;
        } else if (nVal > 11 and 0 == sqlite3_strnicmp(zVal.?, "mergecount=", 11)) {
            v = atoi(zVal.? + 11);
            if (v >= 4 and v <= FTS3_MERGE_COUNT and (v & 1) == 0) {
                if (config.sqlite_debug or config.sqlite_test) p.nMergeCount = v;
            }
            rc = SQLITE_OK;
        }
    }
    return rc;
}

// ===========================================================================
// Deferred tokens (SQLITE_DISABLE_FTS4_DEFERRED is NOT defined in this build).
// ===========================================================================

export fn sqlite3Fts3FreeDeferredDoclists(pCsr: *Fts3Cursor) callconv(.c) void {
    var pDef = pCsr.pDeferred;
    while (pDef) |pd| : (pDef = pd.pNext) {
        fts3PendingListDelete(pd.pList);
        pd.pList = null;
    }
}

export fn sqlite3Fts3FreeDeferredTokens(pCsr: *Fts3Cursor) callconv(.c) void {
    var pDef = pCsr.pDeferred;
    while (pDef) |pd| {
        const pNext = pd.pNext;
        fts3PendingListDelete(pd.pList);
        sqlite3_free(pd);
        pDef = pNext;
    }
    pCsr.pDeferred = null;
}

export fn sqlite3Fts3CacheDeferredDoclists(pCsr: *Fts3Cursor) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (pCsr.pDeferred != null) {
        const p: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab));
        const pT = p.pTokenizer.?;
        const pModule = pT.pModule.?;

        const iDocid = sqlite3_column_int64(pCsr.pStmt, 0);

        var i: c_int = 0;
        while (i < p.nColumn and rc == SQLITE_OK) : (i += 1) {
            if (p.abNotindexed.?[@intCast(i)] == 0) {
                const zText = sqlite3_column_text(pCsr.pStmt, i + 1);
                var pTC: ?*sqlite3_tokenizer_cursor = null;

                rc = sqlite3Fts3OpenTokenizer(pT, pCsr.iLangid, zText, -1, &pTC);
                while (rc == SQLITE_OK) {
                    var zToken: ?[*]const u8 = undefined;
                    var nToken: c_int = 0;
                    var iDum1: c_int = 0;
                    var iDum2: c_int = 0;
                    var iPos: c_int = 0;

                    rc = pModule.xNext.?(pTC, &zToken, &nToken, &iDum1, &iDum2, &iPos);
                    var pDef = pCsr.pDeferred;
                    while (pDef != null and rc == SQLITE_OK) : (pDef = pDef.?.pNext) {
                        const pPT = pDef.?.pToken.?;
                        if ((pDef.?.iCol >= p.nColumn or pDef.?.iCol == i) and
                            (pPT.bFirst == 0 or iPos == 0) and
                            (pPT.n == nToken or (pPT.isPrefix != 0 and pPT.n < nToken)) and
                            (0 == memcmp(zToken, pPT.z, @intCast(pPT.n))))
                        {
                            _ = fts3PendingListAppend(&pDef.?.pList, iDocid, i, iPos, &rc);
                        }
                    }
                }
                if (pTC != null) _ = pModule.xClose.?(pTC);
                if (rc == SQLITE_DONE) rc = SQLITE_OK;
            }
        }

        var pDef = pCsr.pDeferred;
        while (pDef != null and rc == SQLITE_OK) : (pDef = pDef.?.pNext) {
            if (pDef.?.pList != null) {
                rc = fts3PendingListAppendVarint(&pDef.?.pList, 0);
            }
        }
    }
    return rc;
}

export fn sqlite3Fts3DeferredTokenList(p: *Fts3DeferredToken, ppData: *?[*]u8, pnData: *c_int) callconv(.c) c_int {
    ppData.* = null;
    pnData.* = 0;

    if (p.pList == null) {
        return SQLITE_OK;
    }

    const pRet: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(p.pList.?.nData))));
    if (pRet == null) return SQLITE_NOMEM;

    var dummy: i64 = undefined;
    const nSkip = sqlite3Fts3GetVarint(p.pList.?.aData.?, &dummy);
    pnData.* = @as(c_int, @intCast(p.pList.?.nData)) - nSkip;
    ppData.* = pRet;

    _ = memcpy(pRet, p.pList.?.aData.? + @as(usize, @intCast(nSkip)), @intCast(pnData.*));
    return SQLITE_OK;
}

export fn sqlite3Fts3DeferToken(pCsr: *Fts3Cursor, pToken: *Fts3PhraseToken, iCol: c_int) callconv(.c) c_int {
    const pDeferred: *Fts3DeferredToken = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts3DeferredToken)) orelse return SQLITE_NOMEM));
    _ = memset(pDeferred, 0, @sizeOf(Fts3DeferredToken));
    pDeferred.pToken = pToken;
    pDeferred.pNext = pCsr.pDeferred;
    pDeferred.iCol = iCol;
    pCsr.pDeferred = pDeferred;

    pToken.pDeferred = pDeferred;
    return SQLITE_OK;
}

// ===========================================================================
// xUpdate.
// ===========================================================================

fn fts3DeleteByRowid(p: *Fts3Table, pRowid: *?*sqlite3_value, pnChng: *c_int, aSzDel: [*]u32) c_int {
    var rc: c_int = SQLITE_OK;
    var bFound: c_int = 0;

    fts3DeleteTerms(&rc, p, pRowid, aSzDel, &bFound);
    if (bFound != 0 and rc == SQLITE_OK) {
        var isEmpty: c_int = 0;
        rc = fts3IsEmpty(p, pRowid, &isEmpty);
        if (rc == SQLITE_OK) {
            if (isEmpty != 0) {
                rc = fts3DeleteAll(p, 1);
                pnChng.* = 0;
                _ = memset(aSzDel, 0, @sizeOf(u32) * @as(usize, @intCast((p.nColumn + 1) * 2)));
            } else {
                pnChng.* -= 1;
                if (p.zContentTbl == null) {
                    fts3SqlExec(&rc, p, SQL_DELETE_CONTENT, @ptrCast(pRowid));
                }
                if (p.bHasDocsize != 0) {
                    fts3SqlExec(&rc, p, SQL_DELETE_DOCSIZE, @ptrCast(pRowid));
                }
            }
        }
    }
    return rc;
}

export fn sqlite3Fts3UpdateMethod(
    pVtab: *sqlite3_vtab,
    nArg: c_int,
    apVal: ?[*]?*sqlite3_value,
    pRowid: *i64,
) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    var rc: c_int = SQLITE_OK;
    var aSzIns: [*]u32 = undefined;
    var aSzDel: ?[*]u32 = null;
    var nChng: c_int = 0;
    var bInsertDone: c_int = 0;
    const av = apVal.?;

    if (nArg > 1 and
        sqlite3_value_type(av[0]) == SQLITE_NULL and
        sqlite3_value_type(av[@intCast(p.nColumn + 2)]) != SQLITE_NULL)
    {
        rc = fts3SpecialInsert(p, av[@intCast(p.nColumn + 2)]);
        sqlite3_free(aSzDel);
        sqlite3Fts3SegmentsClose(p);
        return rc;
    }

    if (nArg > 1 and sqlite3_value_int(av[@intCast(2 + p.nColumn + 2)]) < 0) {
        sqlite3_free(aSzDel);
        sqlite3Fts3SegmentsClose(p);
        return SQLITE_CONSTRAINT;
    }

    aSzDel = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(@sizeOf(u32) * (@as(i64, p.nColumn) + 1) * 2))));
    if (aSzDel == null) {
        sqlite3Fts3SegmentsClose(p);
        return SQLITE_NOMEM;
    }
    aSzIns = aSzDel.? + @as(usize, @intCast(p.nColumn + 1));
    _ = memset(aSzDel, 0, @sizeOf(u32) * @as(usize, @intCast((p.nColumn + 1) * 2)));

    rc = fts3Writelock(p);
    if (rc != SQLITE_OK) {
        sqlite3_free(aSzDel);
        sqlite3Fts3SegmentsClose(p);
        return rc;
    }

    if (nArg > 1 and p.zContentTbl == null) {
        var pNewRowid = av[@intCast(3 + p.nColumn)];
        if (sqlite3_value_type(pNewRowid) == SQLITE_NULL) {
            pNewRowid = av[1];
        }

        if (sqlite3_value_type(pNewRowid) != SQLITE_NULL and
            (sqlite3_value_type(av[0]) == SQLITE_NULL or
                sqlite3_value_int64(av[0]) != sqlite3_value_int64(pNewRowid)))
        {
            if (sqlite3_vtab_on_conflict(p.db) == SQLITE_REPLACE) {
                var pnr = pNewRowid;
                rc = fts3DeleteByRowid(p, &pnr, &nChng, aSzDel.?);
            } else {
                rc = fts3InsertData(p, av, pRowid);
                bInsertDone = 1;
            }
        }
    }
    if (rc != SQLITE_OK) {
        sqlite3_free(aSzDel);
        sqlite3Fts3SegmentsClose(p);
        return rc;
    }

    if (sqlite3_value_type(av[0]) != SQLITE_NULL) {
        var p0 = av[0];
        rc = fts3DeleteByRowid(p, &p0, &nChng, aSzDel.?);
    }

    if (nArg > 1 and rc == SQLITE_OK) {
        const iLangid = sqlite3_value_int(av[@intCast(2 + p.nColumn + 2)]);
        if (bInsertDone == 0) {
            rc = fts3InsertData(p, av, pRowid);
            if (rc == SQLITE_CONSTRAINT and p.zContentTbl == null) {
                rc = FTS_CORRUPT_VTAB();
            }
        }
        if (rc == SQLITE_OK) {
            rc = fts3PendingTermsDocid(p, 0, iLangid, pRowid.*);
        }
        if (rc == SQLITE_OK) {
            rc = fts3InsertTerms(p, iLangid, av, aSzIns);
        }
        if (p.bHasDocsize != 0) {
            fts3InsertDocsize(&rc, p, aSzIns);
        }
        nChng += 1;
    }

    if (p.bFts4 != 0) {
        fts3UpdateDocTotals(&rc, p, aSzIns, aSzDel.?, nChng);
    }

    sqlite3_free(aSzDel);
    sqlite3Fts3SegmentsClose(p);
    return rc;
}

export fn sqlite3Fts3Optimize(p: *Fts3Table) callconv(.c) c_int {
    var rc = sqlite3_exec(p.db, "SAVEPOINT fts3", null, null, null);
    if (rc == SQLITE_OK) {
        rc = fts3DoOptimize(p, 1);
        if (rc == SQLITE_OK or rc == SQLITE_DONE) {
            const rc2 = sqlite3_exec(p.db, "RELEASE fts3", null, null, null);
            if (rc2 != SQLITE_OK) rc = rc2;
        } else {
            _ = sqlite3_exec(p.db, "ROLLBACK TO fts3", null, null, null);
            _ = sqlite3_exec(p.db, "RELEASE fts3", null, null, null);
        }
    }
    sqlite3Fts3SegmentsClose(p);
    return rc;
}
