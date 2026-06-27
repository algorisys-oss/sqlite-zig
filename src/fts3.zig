//! Zig port of SQLite's FTS3/FTS4 full-text-search virtual table core
//! (ext/fts3/fts3.c).
//!
//! This is the central translation unit of the FTS3/FTS4 extension. It
//! implements:
//!
//!   * The `fts3` sqlite3_module (xCreate/xConnect/xBestIndex/xOpen/xClose/
//!     xFilter/xNext/xEof/xColumn/xRowid/xUpdate/xSync/xBegin/xCommit/
//!     xRollback/xFindFunction/xRename/xSavepoint/xRelease/xRollbackTo/
//!     xShadowName/xIntegrity), registered for both "fts3" and "fts4".
//!   * The FTS3 varint codec (sqlite3Fts3PutVarint / GetVarint / GetVarintU /
//!     GetVarint32 / VarintLen / GetVarintBounded), shared with the still-C
//!     sibling TUs (fts3_write.c / fts3_expr.c / fts3_snippet.c / etc).
//!   * The doclist / position-list merge primitives and segment-reader cursor
//!     construction used by query evaluation.
//!   * The full-text query evaluator (fts3EvalStart / fts3EvalNext and the
//!     phrase / NEAR / deferred-token machinery).
//!   * sqlite3Fts3Init, which registers the vtab modules, the fts4aux module,
//!     the fts3_tokenizer hash table and the overloaded snippet()/offsets()/
//!     matchinfo()/optimize() SQL functions.
//!
//! Drop-in replacement for the C TU: it exports every non-static symbol the C
//! file defines, so the still-C sibling FTS3 TUs link against the Zig versions.
//! Compiled because SQLITE_ENABLE_FTS4 (=> SQLITE_ENABLE_FTS3) is enabled.
//!
//! ABI coupling
//! ------------
//! fts3.c shares a large set of structs from fts3Int.h with the still-C
//! fts3_write.c / fts3_expr.c / fts3_snippet.c / fts3_tokenizer.c TUs. Pointers
//! into Fts3Table / Fts3Cursor / Fts3Expr / Fts3Phrase / Fts3PhraseToken /
//! Fts3Doclist / Fts3MultiSegReader / Fts3SegFilter / Fts3Hash are passed back
//! and forth across the boundary, so each is mirrored here as an `extern
//! struct` field-for-field from fts3Int.h (and fts3_hash.h / fts3_tokenizer.h).
//!
//! `Fts3Table` has trailing fields that exist only under the testfixture build
//! (SQLITE_DEBUG / SQLITE_TEST). Those are config-gated via `@import("config")`
//! (sqlite_debug / sqlite_test) so that sizeof() and the field offsets the C
//! helpers reference agree in both the production and `--dev` builds. Because
//! every field this module reads directly is a leading, config-invariant field,
//! no tools/offsets.c / c_layout entry is required: we control the layout by
//! mirroring it.

const std = @import("std");
const config = @import("config");

// ---------------------------------------------------------------------------
// Result codes (sqlite3.h)
// ---------------------------------------------------------------------------
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_AUTH: c_int = 23;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_CORRUPT_VTAB: c_int = SQLITE_CORRUPT | (1 << 8); // SQLITE_CORRUPT | (1<<8)

// Value types (sqlite3.h)
const SQLITE_INTEGER: c_int = 1;
const SQLITE_NULL: c_int = 5;

// ---------------------------------------------------------------------------
// Constraint operators / index flags / vtab config (sqlite3.h)
// ---------------------------------------------------------------------------
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_INDEX_CONSTRAINT_GT: u8 = 4;
const SQLITE_INDEX_CONSTRAINT_LE: u8 = 8;
const SQLITE_INDEX_CONSTRAINT_LT: u8 = 16;
const SQLITE_INDEX_CONSTRAINT_GE: u8 = 32;
const SQLITE_INDEX_CONSTRAINT_MATCH: u8 = 64;
const SQLITE_INDEX_SCAN_UNIQUE: c_int = 0x00000001;
const SQLITE_VTAB_CONSTRAINT_SUPPORT: c_int = 1;
const SQLITE_VTAB_INNOCUOUS: c_int = 2;

// ---------------------------------------------------------------------------
// Destructor sentinels (sqlite3.h): SQLITE_STATIC==0, SQLITE_TRANSIENT==-1.
// ---------------------------------------------------------------------------
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// ---------------------------------------------------------------------------
// fts3Int.h constants
// ---------------------------------------------------------------------------
const FTS3_VARINT_MAX: c_int = 10;
const FTS3_BUFFER_PADDING: c_int = 8;
const FTS3_MAX_PENDING_DATA: c_int = 1 * 1024 * 1024;
const FTS3_MERGE_COUNT: c_int = 16;
const FTS3_SEGDIR_MAXLEVEL: c_int = 1024;
const FTS3_HASH_STRING: c_int = 1;
const FTS3_MAX_BTREE_HEIGHT: c_int = 48; // fts3.c local
const MAX_INCR_PHRASE_TOKENS: c_int = 4;

// Position/column list terminators (fts3Int.h)
const POS_COLUMN: c_int = 1;
const POS_END: c_int = 0;

// SegReader special level values & filter flags (fts3Int.h)
const FTS3_SEGCURSOR_PENDING: c_int = -1;
const FTS3_SEGCURSOR_ALL: c_int = -2;
const FTS3_SEGMENT_REQUIRE_POS: c_int = 0x00000001;
const FTS3_SEGMENT_IGNORE_EMPTY: c_int = 0x00000002;
const FTS3_SEGMENT_COLUMN_FILTER: c_int = 0x00000004;
const FTS3_SEGMENT_PREFIX: c_int = 0x00000008;
const FTS3_SEGMENT_SCAN: c_int = 0x00000010;
const FTS3_SEGMENT_FIRST: c_int = 0x00000020;

// Fts3Cursor.eSearch / idxNum query plan values (fts3Int.h)
const FTS3_FULLSCAN_SEARCH: c_int = 0;
const FTS3_DOCID_SEARCH: c_int = 1;
const FTS3_FULLTEXT_SEARCH: c_int = 2;
const FTS3_HAVE_LANGID: c_int = 0x00010000;
const FTS3_HAVE_DOCID_GE: c_int = 0x00020000;
const FTS3_HAVE_DOCID_LE: c_int = 0x00040000;

// Fts3Expr.eType values (fts3Int.h)
const FTSQUERY_NEAR: c_int = 1;
const FTSQUERY_NOT: c_int = 2;
const FTSQUERY_AND: c_int = 3;
const FTSQUERY_OR: c_int = 4;
const FTSQUERY_PHRASE: c_int = 5;

// Largest/smallest 64-bit integers (fts3Int.h)
const LARGEST_INT64: i64 = 0x7fffffffffffffff;
const SMALLEST_INT64: i64 = -0x8000000000000000;
const POSITION_LIST_END: i64 = LARGEST_INT64;

// ---------------------------------------------------------------------------
// Public ABI opaque handles (sqlite3.h)
// ---------------------------------------------------------------------------
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;
const sqlite3_blob = anyopaque;
const sqlite3_api_routines = anyopaque;

// ---------------------------------------------------------------------------
// Public ABI structs (sqlite3.h)
// ---------------------------------------------------------------------------
const sqlite3_vtab = extern struct {
    pModule: ?*const sqlite3_module,
    nRef: c_int,
    zErrMsg: ?[*:0]u8,
};

const sqlite3_vtab_cursor = extern struct {
    pVtab: ?*sqlite3_vtab,
};

const sqlite3_index_constraint = extern struct {
    iColumn: c_int,
    op: u8,
    usable: u8,
    iTermOffset: c_int,
};

const sqlite3_index_orderby = extern struct {
    iColumn: c_int,
    desc: u8,
};

const sqlite3_index_constraint_usage = extern struct {
    argvIndex: c_int,
    omit: u8,
};

const sqlite3_index_info = extern struct {
    nConstraint: c_int,
    aConstraint: ?[*]sqlite3_index_constraint,
    nOrderBy: c_int,
    aOrderBy: ?[*]sqlite3_index_orderby,
    aConstraintUsage: ?[*]sqlite3_index_constraint_usage,
    idxNum: c_int,
    idxStr: ?[*:0]u8,
    needToFreeIdxStr: c_int,
    orderByConsumed: c_int,
    estimatedCost: f64,
    estimatedRows: i64,
    idxFlags: c_int,
    colUsed: u64,
};

/// The virtual table method table — PUBLIC ABI. Must match sqlite3_module field
/// for field, iVersion 4 (matches the C fts3Module).
const ModFn0 = ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int;
const sqlite3_module = extern struct {
    iVersion: c_int,
    xCreate: ModFn0,
    xConnect: ModFn0,
    xBestIndex: ?*const fn (*sqlite3_vtab, *sqlite3_index_info) callconv(.c) c_int,
    xDisconnect: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xDestroy: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xOpen: ?*const fn (*sqlite3_vtab, *?*sqlite3_vtab_cursor) callconv(.c) c_int,
    xClose: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xFilter: ?*const fn (*sqlite3_vtab_cursor, c_int, ?[*:0]const u8, c_int, ?[*]?*sqlite3_value) callconv(.c) c_int,
    xNext: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xEof: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xColumn: ?*const fn (*sqlite3_vtab_cursor, ?*sqlite3_context, c_int) callconv(.c) c_int,
    xRowid: ?*const fn (*sqlite3_vtab_cursor, *i64) callconv(.c) c_int,
    xUpdate: ?*const fn (*sqlite3_vtab, c_int, ?[*]?*sqlite3_value, *i64) callconv(.c) c_int,
    xBegin: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xSync: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xCommit: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xRollback: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xFindFunction: ?*const fn (*sqlite3_vtab, c_int, [*:0]const u8, *?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void, *?*anyopaque) callconv(.c) c_int,
    xRename: ?*const fn (*sqlite3_vtab, [*:0]const u8) callconv(.c) c_int,
    xSavepoint: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xRelease: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xRollbackTo: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xShadowName: ?*const fn ([*:0]const u8) callconv(.c) c_int,
    xIntegrity: ?*const fn (*sqlite3_vtab, [*:0]const u8, [*:0]const u8, c_int, *?[*:0]u8) callconv(.c) c_int,
};

// ---------------------------------------------------------------------------
// Tokenizer module (fts3_tokenizer.h) — only pModule->xDestroy is touched here.
// ---------------------------------------------------------------------------
const sqlite3_tokenizer_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const anyopaque,
    xDestroy: ?*const fn (*sqlite3_tokenizer) callconv(.c) c_int,
    xOpen: ?*const anyopaque,
    xClose: ?*const anyopaque,
    xNext: ?*const anyopaque,
    xLanguageid: ?*const anyopaque,
};

const sqlite3_tokenizer = extern struct {
    pModule: ?*const sqlite3_tokenizer_module,
};

// ---------------------------------------------------------------------------
// Fts3Hash (fts3_hash.h) — mirrored so it can be embedded in Fts3HashWrapper.
// ---------------------------------------------------------------------------
const Fts3HashElem = opaque {};
const struct_fts3ht = opaque {};
const Fts3Hash = extern struct {
    keyClass: u8, // char
    copyKey: u8, // char
    count: c_int,
    first: ?*Fts3HashElem,
    htsize: c_int,
    ht: ?*struct_fts3ht,
};

/// fts3.c-local wrapper: a refcounted hash table holding the tokenizers.
const Fts3HashWrapper = extern struct {
    hash: Fts3Hash,
    nRef: c_int,
};

// ---------------------------------------------------------------------------
// ABI-SHARED fts3 structs (fts3Int.h)
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

    // Trailing fields gated by build config (testfixture only). See module
    // docstring. SQLITE_COVERAGE_TEST is not set in this build.
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
    pExpr: ?*Fts3Expr,
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

const Fts3DeferredToken = opaque {};
const Fts3SegReader = opaque {};

const Fts3Doclist = extern struct {
    aAll: ?[*]u8,
    nAll: c_int,
    pNextDocid: ?[*]u8,
    iDocid: i64,
    bFreeList: c_int,
    pList: ?[*]u8,
    nList: c_int,
};

const Fts3PhraseToken = extern struct {
    z: ?[*]u8,
    n: c_int,
    isPrefix: c_int,
    bFirst: c_int,
    pDeferred: ?*Fts3DeferredToken,
    pSegcsr: ?*Fts3MultiSegReader,
};

/// Fts3Phrase has a flexible array member `aToken[]` at the end. It is only
/// ever pointer-referenced here (allocated by fts3_expr.c), so the trailing
/// array is represented as a 0-length array; `aToken[i]` is reached by pointer
/// arithmetic from the field.
const Fts3Phrase = extern struct {
    doclist: Fts3Doclist,
    bIncr: c_int,
    iDoclistToken: c_int,
    pOrPoslist: ?[*]u8,
    iOrDocid: i64,
    nToken: c_int,
    iColumn: c_int,
    aToken: [0]Fts3PhraseToken,
};

const Fts3Expr = extern struct {
    eType: c_int,
    nNear: c_int,
    pParent: ?*Fts3Expr,
    pLeft: ?*Fts3Expr,
    pRight: ?*Fts3Expr,
    pPhrase: ?*Fts3Phrase,
    iDocid: i64,
    bEof: u8,
    bStart: u8,
    bDeferred: u8,
    iPhrase: c_int,
    aMI: ?[*]u32,
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

// Helper to access an aToken[i] slot of an Fts3Phrase by pointer arithmetic.
inline fn phraseToken(p: *Fts3Phrase, i: c_int) *Fts3PhraseToken {
    const base: [*]Fts3PhraseToken = @ptrCast(&p.aToken);
    return &base[@intCast(i)];
}

// ---------------------------------------------------------------------------
// libc + public sqlite3 API resolved at link time
// ---------------------------------------------------------------------------
extern fn strlen(s: [*:0]const u8) usize;
extern fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *std.builtin.VaList) ?[*:0]u8;
extern fn sqlite3_strnicmp(a: [*:0]const u8, b: [*:0]const u8, n: c_int) c_int;
extern fn sqlite3_stricmp(a: [*:0]const u8, b: [*:0]const u8) c_int;

extern fn sqlite3_exec(db: ?*sqlite3, sql: [*:0]const u8, cb: ?*anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_prepare(db: ?*sqlite3, sql: [*:0]const u8, n: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_bind_int64(pStmt: ?*sqlite3_stmt, i: c_int, v: i64) c_int;
extern fn sqlite3_bind_value(pStmt: ?*sqlite3_stmt, i: c_int, v: ?*sqlite3_value) c_int;
extern fn sqlite3_column_int(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, i: c_int) i64;
extern fn sqlite3_column_count(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_name(pStmt: ?*sqlite3_stmt, i: c_int) ?[*:0]const u8;
extern fn sqlite3_column_bytes(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_blob(pStmt: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_value(pStmt: ?*sqlite3_stmt, i: c_int) ?*sqlite3_value;
extern fn sqlite3_data_count(pStmt: ?*sqlite3_stmt) c_int;

extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_create_module_v2(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pAux: ?*anyopaque, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3_overload_function(db: ?*sqlite3, zName: [*:0]const u8, nArg: c_int) c_int;
extern fn sqlite3_vtab_config(db: ?*sqlite3, op: c_int, ...) c_int;

extern fn sqlite3_last_insert_rowid(db: ?*sqlite3) i64;
extern fn sqlite3_set_last_insert_rowid(db: ?*sqlite3, v: i64) void;
extern fn sqlite3_table_column_metadata(db: ?*sqlite3, zDb: ?[*:0]const u8, zTbl: ?[*:0]const u8, zCol: ?[*:0]const u8, pzDataType: ?*?[*:0]const u8, pzCollSeq: ?*?[*:0]const u8, pNotNull: ?*c_int, pPrimaryKey: ?*c_int, pAutoinc: ?*c_int) c_int;
extern fn sqlite3_libversion_number() c_int;
extern fn sqlite3_errmsg(db: ?*sqlite3) ?[*:0]const u8;
extern fn sqlite3_errstr(rc: c_int) ?[*:0]const u8;

extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_int(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(p: ?*sqlite3_value) i64;
extern fn sqlite3_value_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_numeric_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_pointer(p: ?*sqlite3_value, zT: [*:0]const u8) ?*anyopaque;

extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_result_value(ctx: ?*sqlite3_context, v: ?*sqlite3_value) void;
extern fn sqlite3_result_pointer(ctx: ?*sqlite3_context, p: ?*anyopaque, zT: [*:0]const u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: [*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(ctx: ?*sqlite3_context, rc: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*sqlite3_context) void;

// ---------------------------------------------------------------------------
// Internal helpers from still-C fts3 sibling TUs, resolved at link time.
//   * fts3_hash.c    : sqlite3Fts3Hash{Init,Insert,Find,Clear}
//   * fts3_write.c   : segment readers / pending terms / update / optimize ...
//   * fts3_expr.c    : ExprParse / ExprFree / ExprIterate / MallocZero
//   * fts3_snippet.c : Snippet / Offsets / Matchinfo / MIBufferFree
//   * fts3_tokenizer*: NextToken / InitTokenizer / InitHashTable / IsIdChar /
//                      OpenTokenizer / InitTok
//   * tokenizers     : SimpleTokenizerModule / PorterTokenizerModule /
//                      UnicodeTokenizer
//   * fts3_aux.c     : sqlite3Fts3InitAux
// ---------------------------------------------------------------------------
extern fn sqlite3Fts3HashInit(pNew: *Fts3Hash, keyClass: u8, copyKey: u8) void;
extern fn sqlite3Fts3HashInsert(h: *Fts3Hash, pKey: ?*const anyopaque, nKey: c_int, pData: ?*anyopaque) ?*anyopaque;
extern fn sqlite3Fts3HashClear(h: *Fts3Hash) void;

/// fts3_hash.h: `#define fts3HashCount(H) ((H)->count)`.
inline fn fts3HashCount(h: *Fts3Hash) c_int {
    return h.count;
}

// fts3_write.c
extern fn sqlite3Fts3UpdateMethod(pVtab: *sqlite3_vtab, nArg: c_int, apVal: ?[*]?*sqlite3_value, pRowid: *i64) c_int;
extern fn sqlite3Fts3PendingTermsFlush(p: *Fts3Table) c_int;
extern fn sqlite3Fts3PendingTermsClear(p: *Fts3Table) void;
extern fn sqlite3Fts3Optimize(p: *Fts3Table) c_int;
extern fn sqlite3Fts3SegReaderNew(iAge: c_int, bLookup: c_int, iStartLeaf: i64, iEndLeaf: i64, iEndBlock: i64, zRoot: ?[*]const u8, nRoot: c_int, ppOut: *?*Fts3SegReader) c_int;
extern fn sqlite3Fts3SegReaderPending(p: *Fts3Table, iIndex: c_int, zTerm: ?[*]const u8, nTerm: c_int, bPrefix: c_int, ppOut: *?*Fts3SegReader) c_int;
extern fn sqlite3Fts3SegReaderFree(p: ?*Fts3SegReader) void;
extern fn sqlite3Fts3AllSegdirs(p: *Fts3Table, iLangid: c_int, iIndex: c_int, iLevel: c_int, ppStmt: *?*sqlite3_stmt) c_int;
extern fn sqlite3Fts3ReadBlock(p: *Fts3Table, iBlock: i64, paBlob: *?[*]u8, pnBlob: *c_int, pnLoad: ?*c_int) c_int;
extern fn sqlite3Fts3SelectDoctotal(p: *Fts3Table, ppStmt: *?*sqlite3_stmt) c_int;
extern fn sqlite3Fts3MaxLevel(p: *Fts3Table, pnMax: *c_int) c_int;
extern fn sqlite3Fts3SegmentsClose(p: *Fts3Table) void;
extern fn sqlite3Fts3SegReaderStart(p: *Fts3Table, pCsr: *Fts3MultiSegReader, pFilter: *Fts3SegFilter) c_int;
extern fn sqlite3Fts3SegReaderStep(p: *Fts3Table, pCsr: *Fts3MultiSegReader) c_int;
extern fn sqlite3Fts3SegReaderFinish(pCsr: *Fts3MultiSegReader) void;
extern fn sqlite3Fts3Incrmerge(p: *Fts3Table, nMerge: c_int, nMin: c_int) c_int;
extern fn sqlite3Fts3PrepareStmt(p: *Fts3Table, zSql: [*:0]const u8, bPersist: c_int, bAllowVtab: c_int, pp: *?*sqlite3_stmt) c_int;
extern fn sqlite3Fts3MsrIncrStart(p: *Fts3Table, pCsr: *Fts3MultiSegReader, iCol: c_int, zTerm: ?[*]const u8, nTerm: c_int) c_int;
extern fn sqlite3Fts3MsrIncrNext(p: *Fts3Table, pCsr: *Fts3MultiSegReader, piDocid: *i64, paPoslist: *?[*]u8, pnList: *c_int) c_int;
extern fn sqlite3Fts3MsrOvfl(pCsr: *Fts3Cursor, pSegcsr: ?*Fts3MultiSegReader, pnOvfl: *c_int) c_int;
extern fn sqlite3Fts3MsrIncrRestart(pCsr: *Fts3MultiSegReader) c_int;
extern fn sqlite3Fts3IntegrityCheck(p: *Fts3Table, pbOk: *c_int) c_int;

// fts3 deferred tokens (fts3_write.c, guarded by SQLITE_DISABLE_FTS4_DEFERRED in C;
// that macro is NOT defined in this build, so the functions exist).
extern fn sqlite3Fts3FreeDeferredTokens(pCsr: *Fts3Cursor) void;
extern fn sqlite3Fts3DeferToken(pCsr: *Fts3Cursor, pTok: *Fts3PhraseToken, iCol: c_int) c_int;
extern fn sqlite3Fts3CacheDeferredDoclists(pCsr: *Fts3Cursor) c_int;
extern fn sqlite3Fts3FreeDeferredDoclists(pCsr: *Fts3Cursor) void;
extern fn sqlite3Fts3DeferredTokenList(pDeferred: *Fts3DeferredToken, ppList: *?[*]u8, pnList: *c_int) c_int;

// fts3_expr.c
extern fn sqlite3Fts3ExprParse(pTokenizer: ?*sqlite3_tokenizer, iLangid: c_int, azCol: ?[*]?[*:0]u8, bFts4: u8, nCol: c_int, iDefaultCol: c_int, z: ?[*:0]const u8, n: c_int, ppExpr: *?*Fts3Expr, pzErr: *?[*:0]u8) c_int;
extern fn sqlite3Fts3ExprFree(p: ?*Fts3Expr) void;
extern fn sqlite3Fts3ExprIterate(pExpr: *Fts3Expr, x: *const fn (*Fts3Expr, c_int, ?*anyopaque) callconv(.c) c_int, pCtx: ?*anyopaque) c_int;
extern fn sqlite3Fts3MallocZero(nByte: i64) ?*anyopaque;

// fts3_snippet.c
extern fn sqlite3Fts3Offsets(pCtx: ?*sqlite3_context, pCsr: *Fts3Cursor) void;
extern fn sqlite3Fts3Snippet(pCtx: ?*sqlite3_context, pCsr: *Fts3Cursor, zStart: ?[*:0]const u8, zEnd: ?[*:0]const u8, zEllipsis: ?[*:0]const u8, iCol: c_int, nToken: c_int) void;
extern fn sqlite3Fts3Matchinfo(pCtx: ?*sqlite3_context, pCsr: *Fts3Cursor, zArg: ?[*:0]const u8) void;
extern fn sqlite3Fts3MIBufferFree(p: ?*MatchinfoBuffer) void;

// fts3_tokenizer.c
extern fn sqlite3Fts3NextToken(z: [*:0]const u8, pn: *c_int) ?[*]const u8;
extern fn sqlite3Fts3InitHashTable(db: ?*sqlite3, pHash: *Fts3Hash, zName: [*:0]const u8) c_int;
extern fn sqlite3Fts3InitTokenizer(pHash: *Fts3Hash, zArg: [*:0]const u8, ppTok: *?*sqlite3_tokenizer, pzErr: *?[*:0]u8) c_int;
extern fn sqlite3Fts3IsIdChar(c: u8) c_int;
extern fn sqlite3Fts3InitTok(db: ?*sqlite3, pHash: ?*anyopaque, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) c_int;

// tokenizers
extern fn sqlite3Fts3SimpleTokenizerModule(ppModule: *?*const sqlite3_tokenizer_module) void;
extern fn sqlite3Fts3PorterTokenizerModule(ppModule: *?*const sqlite3_tokenizer_module) void;
extern fn sqlite3Fts3UnicodeTokenizer(ppModule: *?*const sqlite3_tokenizer_module) void;

// fts3_aux.c
extern fn sqlite3Fts3InitAux(db: ?*sqlite3) c_int;

// ===========================================================================
// FTS_CORRUPT_VTAB. In SQLITE_DEBUG builds the C code routes corruption codes
// through sqlite3Fts3Corrupt() (defined in this file). We mirror that so the
// returned code matches in both configs.
// ===========================================================================
inline fn FTS_CORRUPT_VTAB() c_int {
    if (config.sqlite_debug) {
        return sqlite3Fts3Corrupt();
    }
    return SQLITE_CORRUPT_VTAB;
}

// In SQLITE_DEBUG builds, this global gates the assert_fts3_nc() macro; it is a
// mutable global shared with the sibling TUs. We define it here (matching the C
// `int sqlite3_fts3_may_be_corrupt = 1;`). Since asserts are dropped in Zig, the
// variable is otherwise unused here, but exporting it keeps the symbol present
// for the still-C siblings that reference it.
pub export var sqlite3_fts3_may_be_corrupt: c_int = if (config.sqlite_debug) 1 else 0;

// ===========================================================================
// Varint codec (sqlite3Fts3PutVarint / GetVarint*).  Byte-exact with C.
// ===========================================================================

/// Write a 64-bit varint to p. Returns number of bytes written (1..10).
export fn sqlite3Fts3PutVarint(p: [*]u8, v: i64) callconv(.c) c_int {
    var vu: u64 = @bitCast(v);
    var i: usize = 0;
    while (true) {
        p[i] = @intCast((vu & 0x7f) | 0x80);
        i += 1;
        vu >>= 7;
        if (vu == 0) break;
    }
    p[i - 1] &= 0x7f; // turn off high bit in final byte
    return @intCast(i);
}

/// Read an unsigned 64-bit varint from pBuf. Returns the number of bytes read.
export fn sqlite3Fts3GetVarintU(pBuf: [*]const u8, v: *u64) callconv(.c) c_int {
    var p: [*]const u8 = pBuf;
    const pStart = pBuf;
    var a: u32 = undefined;
    var b: u64 = undefined;

    // GETVARINT_INIT(a, p, 0, 0x00, 0x80, *v, 1)
    a = p[0];
    p += 1;
    if ((a & 0x80) == 0) {
        v.* = a;
        return 1;
    }
    // GETVARINT_STEP(a, p, 7, 0x7F, 0x4000, *v, 2)
    a = (a & 0x7F) | (@as(u32, p[0]) << 7);
    p += 1;
    if ((a & 0x4000) == 0) {
        v.* = a;
        return 2;
    }
    // GETVARINT_STEP(a, p, 14, 0x3FFF, 0x200000, *v, 3)
    a = (a & 0x3FFF) | (@as(u32, p[0]) << 14);
    p += 1;
    if ((a & 0x200000) == 0) {
        v.* = a;
        return 3;
    }
    // GETVARINT_STEP(a, p, 21, 0x1FFFFF, 0x10000000, *v, 4)
    a = (a & 0x1FFFFF) | (@as(u32, p[0]) << 21);
    p += 1;
    if ((a & 0x10000000) == 0) {
        v.* = a;
        return 4;
    }
    b = (a & 0x0FFFFFFF);

    var shift: u6 = 28;
    while (true) {
        const c: u64 = p[0];
        p += 1;
        b += (c & 0x7F) << shift;
        if ((c & 0x80) == 0) break;
        if (shift >= 63) break;
        shift += 7;
    }
    v.* = b;
    return @intCast(@intFromPtr(p) - @intFromPtr(pStart));
}

/// Read a signed 64-bit varint. Returns the number of bytes read.
export fn sqlite3Fts3GetVarint(pBuf: [*]const u8, v: *i64) callconv(.c) c_int {
    return sqlite3Fts3GetVarintU(pBuf, @ptrCast(v));
}

/// Read a 64-bit varint not extending past pEnd[-1].
export fn sqlite3Fts3GetVarintBounded(pBuf: [*]const u8, pEnd: [*]const u8, v: *i64) callconv(.c) c_int {
    var p: [*]const u8 = pBuf;
    const pStart = pBuf;
    const pX = pEnd;
    var b: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        const c: u64 = if (@intFromPtr(p) < @intFromPtr(pX)) p[0] else 0;
        p += 1;
        b += (c & 0x7F) << shift;
        if ((c & 0x80) == 0) break;
        if (shift >= 63) break;
        shift += 7;
    }
    v.* = @bitCast(b);
    return @intCast(@intFromPtr(p) - @intFromPtr(pStart));
}

/// Read a varint truncated to a non-negative 32-bit int. Always returns >=1.
export fn sqlite3Fts3GetVarint32(p: [*]const u8, pi: *c_int) callconv(.c) c_int {
    var ptr: [*]const u8 = p;
    var a: u32 = undefined;

    // GETVARINT_INIT(a, ptr, 0, 0x00, 0x80, *pi, 1)
    a = ptr[0];
    ptr += 1;
    if ((a & 0x80) == 0) {
        pi.* = @intCast(a);
        return 1;
    }
    // GETVARINT_STEP(a, ptr, 7, 0x7F, 0x4000, *pi, 2)
    a = (a & 0x7F) | (@as(u32, ptr[0]) << 7);
    ptr += 1;
    if ((a & 0x4000) == 0) {
        pi.* = @intCast(a);
        return 2;
    }
    // GETVARINT_STEP(a, ptr, 14, 0x3FFF, 0x200000, *pi, 3)
    a = (a & 0x3FFF) | (@as(u32, ptr[0]) << 14);
    ptr += 1;
    if ((a & 0x200000) == 0) {
        pi.* = @intCast(a);
        return 3;
    }
    // GETVARINT_STEP(a, ptr, 21, 0x1FFFFF, 0x10000000, *pi, 4)
    a = (a & 0x1FFFFF) | (@as(u32, ptr[0]) << 21);
    ptr += 1;
    if ((a & 0x10000000) == 0) {
        pi.* = @intCast(a);
        return 4;
    }
    a = (a & 0x0FFFFFFF);
    pi.* = @bitCast(a | (@as(u32, ptr[0] & 0x07) << 28));
    return 5;
}

/// fts3GetVarint32 macro: 1-byte fast path or fall to sqlite3Fts3GetVarint32.
inline fn fts3GetVarint32(p: [*]const u8, piVal: *c_int) c_int {
    if ((p[0] & 0x80) != 0) {
        return sqlite3Fts3GetVarint32(p, piVal);
    }
    piVal.* = p[0];
    return 1;
}

/// Number of bytes required to encode v as a varint.
export fn sqlite3Fts3VarintLen(v_in: u64) callconv(.c) c_int {
    var v = v_in;
    var i: c_int = 0;
    while (true) {
        i += 1;
        v >>= 7;
        if (v == 0) break;
    }
    return i;
}

/// In-place SQL-style dequote. No-op if z does not begin with a quote.
export fn sqlite3Fts3Dequote(z: [*:0]u8) callconv(.c) void {
    var quote = z[0];
    if (quote == '[' or quote == '\'' or quote == '"' or quote == '`') {
        var iIn: usize = 1;
        var iOut: usize = 0;
        if (quote == '[') quote = ']';
        while (z[iIn] != 0) {
            if (z[iIn] == quote) {
                if (z[iIn + 1] != quote) break;
                z[iOut] = quote;
                iOut += 1;
                iIn += 2;
            } else {
                z[iOut] = z[iIn];
                iOut += 1;
                iIn += 1;
            }
        }
        z[iOut] = 0;
    }
}

// ===========================================================================
// Delta-varint doclist helpers (static in C).
// ===========================================================================

/// Read a varint at *pp, advance *pp, and add the value to *pVal.
fn fts3GetDeltaVarint(pp: *[*]u8, pVal: *i64) void {
    var iVal: i64 = undefined;
    pp.* += @intCast(sqlite3Fts3GetVarint(pp.*, &iVal));
    pVal.* += iVal;
}

/// *pp points just past a varint; rewind to its start, decode it into *pVal.
fn fts3GetReverseVarint(pp: *[*]u8, pStart: [*]u8, pVal: *i64) void {
    var iVal: i64 = undefined;
    var p: [*]u8 = pp.* - 2;
    while (@intFromPtr(p) >= @intFromPtr(pStart) and (p[0] & 0x80) != 0) : (p -= 1) {}
    p += 1;
    pp.* = p;
    _ = sqlite3Fts3GetVarint(p, &iVal);
    pVal.* = iVal;
}

// ===========================================================================
// vtab xDisconnect / xDestroy and SQL helpers.
// ===========================================================================

/// xDisconnect() virtual table method.
fn fts3DisconnectMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    // assert( p->nPendingData==0 ); assert( p->pSegments==0 );

    _ = sqlite3_finalize(p.pSeekStmt);
    for (&p.aStmt) |stmt| {
        _ = sqlite3_finalize(stmt);
    }
    sqlite3_free(p.zSegmentsTbl);
    sqlite3_free(p.zReadExprlist);
    sqlite3_free(p.zWriteExprlist);
    sqlite3_free(p.zContentTbl);
    sqlite3_free(p.zLanguageid);

    // Invoke the tokenizer destructor to free the tokenizer.
    const tok = p.pTokenizer.?;
    _ = tok.pModule.?.xDestroy.?(tok);

    sqlite3_free(p);
    return SQLITE_OK;
}

/// Write an error message into *pzErr (variadic).
export fn sqlite3Fts3ErrMsg(pzErr: *?[*:0]u8, zFormat: [*:0]const u8, ...) callconv(.c) void {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    sqlite3_free(pzErr.*);
    pzErr.* = sqlite3_vmprintf(zFormat, &ap);
}

/// Construct SQL from a printf format and run it. No-op if *pRc!=0.
fn fts3DbExec(pRc: *c_int, db: ?*sqlite3, zFormat: [*:0]const u8, ...) callconv(.c) void {
    if (pRc.* != 0) return;
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const zSql = sqlite3_vmprintf(zFormat, &ap);
    if (zSql == null) {
        pRc.* = SQLITE_NOMEM;
    } else {
        pRc.* = sqlite3_exec(db, zSql.?, null, null, null);
        sqlite3_free(zSql);
    }
}

/// xDestroy() virtual table method.
fn fts3DestroyMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    var rc: c_int = SQLITE_OK;
    const zDb = p.zDb.?;
    const db = p.db;

    fts3DbExec(
        &rc,
        db,
        "DROP TABLE IF EXISTS %Q.'%q_segments';" ++
            "DROP TABLE IF EXISTS %Q.'%q_segdir';" ++
            "DROP TABLE IF EXISTS %Q.'%q_docsize';" ++
            "DROP TABLE IF EXISTS %Q.'%q_stat';" ++
            "%s DROP TABLE IF EXISTS %Q.'%q_content';",
        zDb,
        p.zName.?,
        zDb,
        p.zName.?,
        zDb,
        p.zName.?,
        zDb,
        p.zName.?,
        @as([*:0]const u8, if (p.zContentTbl != null) "--" else ""),
        zDb,
        p.zName.?,
    );

    return if (rc == SQLITE_OK) fts3DisconnectMethod(pVtab) else rc;
}

/// Declare the vtab schema. No-op if *pRc!=SQLITE_OK.
fn fts3DeclareVtab(pRc: *c_int, p: *Fts3Table) void {
    if (pRc.* == SQLITE_OK) {
        var rc: c_int = undefined;
        const zLanguageid: [*:0]const u8 = if (p.zLanguageid) |z| z else "__langid";
        _ = sqlite3_vtab_config(p.db, SQLITE_VTAB_CONSTRAINT_SUPPORT, @as(c_int, 1));
        _ = sqlite3_vtab_config(p.db, SQLITE_VTAB_INNOCUOUS);

        // Create a list of user columns for the virtual table.
        var zCols = sqlite3_mprintf("%Q, ", p.azColumn.?[0]);
        var i: c_int = 1;
        while (zCols != null and i < p.nColumn) : (i += 1) {
            zCols = sqlite3_mprintf("%z%Q, ", zCols.?, p.azColumn.?[@intCast(i)]);
        }

        const zSql = sqlite3_mprintf(
            "CREATE TABLE x(%s %Q HIDDEN, docid HIDDEN, %Q HIDDEN)",
            if (zCols) |z| z else @as([*:0]const u8, ""),
            p.zName.?,
            zLanguageid,
        );
        if (zCols == null or zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3_declare_vtab(p.db, zSql.?);
        }

        sqlite3_free(zSql);
        sqlite3_free(zCols);
        pRc.* = rc;
    }
}

/// Create the %_stat table if it does not already exist.
export fn sqlite3Fts3CreateStatTable(pRc: *c_int, p: *Fts3Table) callconv(.c) void {
    fts3DbExec(
        pRc,
        p.db,
        "CREATE TABLE IF NOT EXISTS %Q.'%q_stat'" ++
            "(id INTEGER PRIMARY KEY, value BLOB);",
        p.zDb.?,
        p.zName.?,
    );
    if (pRc.* == SQLITE_OK) p.bHasStat = 1;
}

/// Create the backing store tables required by the FTS table.
fn fts3CreateTables(p: *Fts3Table) c_int {
    var rc: c_int = SQLITE_OK;
    var i: c_int = undefined;
    const db = p.db;

    if (p.zContentTbl == null) {
        const zLanguageid = p.zLanguageid;
        var zContentCols = sqlite3_mprintf("docid INTEGER PRIMARY KEY");
        i = 0;
        while (zContentCols != null and i < p.nColumn) : (i += 1) {
            const z = p.azColumn.?[@intCast(i)].?;
            zContentCols = sqlite3_mprintf("%z, 'c%d%q'", zContentCols.?, i, z);
        }
        if (zLanguageid != null and zContentCols != null) {
            zContentCols = sqlite3_mprintf("%z, langid", zContentCols.?, zLanguageid.?);
        }
        if (zContentCols == null) rc = SQLITE_NOMEM;

        fts3DbExec(&rc, db, "CREATE TABLE %Q.'%q_content'(%s)", p.zDb.?, p.zName.?, if (zContentCols) |z| z else @as([*:0]const u8, ""));
        sqlite3_free(zContentCols);
    }

    fts3DbExec(&rc, db, "CREATE TABLE %Q.'%q_segments'(blockid INTEGER PRIMARY KEY, block BLOB);", p.zDb.?, p.zName.?);
    fts3DbExec(
        &rc,
        db,
        "CREATE TABLE %Q.'%q_segdir'(" ++
            "level INTEGER," ++
            "idx INTEGER," ++
            "start_block INTEGER," ++
            "leaves_end_block INTEGER," ++
            "end_block INTEGER," ++
            "root BLOB," ++
            "PRIMARY KEY(level, idx)" ++
            ");",
        p.zDb.?,
        p.zName.?,
    );
    if (p.bHasDocsize != 0) {
        fts3DbExec(&rc, db, "CREATE TABLE %Q.'%q_docsize'(docid INTEGER PRIMARY KEY, size BLOB);", p.zDb.?, p.zName.?);
    }
    // assert( p->bHasStat==p->bFts4 );
    if (p.bHasStat != 0) {
        sqlite3Fts3CreateStatTable(&rc, p);
    }
    return rc;
}

/// Store the database page-size in p->nPgsz. No-op if *pRc!=SQLITE_OK.
fn fts3DatabasePageSize(pRc: *c_int, p: *Fts3Table) void {
    if (pRc.* == SQLITE_OK) {
        var rc: c_int = undefined;
        var pStmt: ?*sqlite3_stmt = undefined;
        const zSql = sqlite3_mprintf("PRAGMA %Q.page_size", p.zDb.?);
        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3_prepare(p.db, zSql.?, -1, &pStmt, null);
            if (rc == SQLITE_OK) {
                _ = sqlite3_step(pStmt);
                p.nPgsz = sqlite3_column_int(pStmt, 0);
                rc = sqlite3_finalize(pStmt);
            } else if (rc == SQLITE_AUTH) {
                p.nPgsz = 1024;
                rc = SQLITE_OK;
            }
        }
        sqlite3_free(zSql);
        pRc.* = rc;
    }
}

/// Detect a "<key>=<value>" special FTS4 column spec. Returns 1 if special.
fn fts3IsSpecialColumn(z: [*:0]const u8, pnKey: *c_int, pzValue: *?[*:0]u8) c_int {
    var zCsr: [*:0]const u8 = z;
    while (zCsr[0] != '=') {
        if (zCsr[0] == 0) return 0;
        zCsr += 1;
    }
    pnKey.* = @intCast(@intFromPtr(zCsr) - @intFromPtr(z));
    const zValue = sqlite3_mprintf("%s", zCsr + 1);
    if (zValue) |zv| {
        sqlite3Fts3Dequote(zv);
    }
    pzValue.* = zValue;
    return 1;
}

/// Append printf output to an existing string buffer (variadic). No-op if *pRc.
fn fts3Appendf(pRc: *c_int, pz: *?[*:0]u8, zFormat: [*:0]const u8, ...) callconv(.c) void {
    if (pRc.* == SQLITE_OK) {
        var ap = @cVaStart();
        defer @cVaEnd(&ap);
        var z = sqlite3_vmprintf(zFormat, &ap);
        if (z != null and pz.* != null) {
            const z2 = sqlite3_mprintf("%s%s", pz.*.?, z.?);
            sqlite3_free(z);
            z = z2;
        }
        if (z == null) pRc.* = SQLITE_NOMEM;
        sqlite3_free(pz.*);
        pz.* = z;
    }
}

/// Return a copy of zInput enclosed in double-quotes with quotes escaped.
fn fts3QuoteId(zInput: [*:0]const u8) ?[*:0]u8 {
    const nRet: i64 = 2 + @as(i64, @intCast(strlen(zInput))) * 2 + 1;
    const zRet: ?[*:0]u8 = @ptrCast(sqlite3_malloc64(@intCast(nRet)));
    if (zRet) |zr| {
        var z: [*]u8 = zr;
        z[0] = '"';
        z += 1;
        var i: usize = 0;
        while (zInput[i] != 0) : (i += 1) {
            if (zInput[i] == '"') {
                z[0] = '"';
                z += 1;
            }
            z[0] = zInput[i];
            z += 1;
        }
        z[0] = '"';
        z += 1;
        z[0] = 0;
    }
    return zRet;
}

/// Build the SELECT expression-list + FROM clause for reading %_content.
fn fts3ReadExprList(p: *Fts3Table, zFunc: ?[*:0]const u8, pRc: *c_int) ?[*:0]u8 {
    var zRet: ?[*:0]u8 = null;
    var zFree: ?[*:0]u8 = null;
    var zFunction: [*:0]const u8 = undefined;
    var i: c_int = undefined;

    if (p.zContentTbl == null) {
        if (zFunc == null) {
            zFunction = "";
        } else {
            zFree = fts3QuoteId(zFunc.?);
            zFunction = if (zFree) |z| z else @as([*:0]const u8, "");
        }
        fts3Appendf(pRc, &zRet, "docid");
        i = 0;
        while (i < p.nColumn) : (i += 1) {
            fts3Appendf(pRc, &zRet, ",%s(x.'c%d%q')", zFunction, i, p.azColumn.?[@intCast(i)].?);
        }
        if (p.zLanguageid != null) {
            fts3Appendf(pRc, &zRet, ", x.%Q", @as([*:0]const u8, "langid"));
        }
        sqlite3_free(zFree);
    } else {
        fts3Appendf(pRc, &zRet, "rowid");
        i = 0;
        while (i < p.nColumn) : (i += 1) {
            fts3Appendf(pRc, &zRet, ", x.'%q'", p.azColumn.?[@intCast(i)].?);
        }
        if (p.zLanguageid) |zl| {
            fts3Appendf(pRc, &zRet, ", x.%Q", zl);
        }
    }
    fts3Appendf(
        pRc,
        &zRet,
        " FROM '%q'.'%q%s' AS x",
        p.zDb.?,
        if (p.zContentTbl) |z| z else p.zName.?,
        @as([*:0]const u8, if (p.zContentTbl != null) "" else "_content"),
    );
    return zRet;
}

/// Build "?, zip(?), ..." list of bound parameters for %_content writes.
fn fts3WriteExprList(p: *Fts3Table, zFunc: ?[*:0]const u8, pRc: *c_int) ?[*:0]u8 {
    var zRet: ?[*:0]u8 = null;
    var zFree: ?[*:0]u8 = null;
    var zFunction: [*:0]const u8 = undefined;
    if (zFunc == null) {
        zFunction = "";
    } else {
        zFree = fts3QuoteId(zFunc.?);
        zFunction = if (zFree) |z| z else @as([*:0]const u8, "");
    }
    fts3Appendf(pRc, &zRet, "?");
    var i: c_int = 0;
    while (i < p.nColumn) : (i += 1) {
        fts3Appendf(pRc, &zRet, ",%s(?)", zFunction);
    }
    if (p.zLanguageid != null) {
        fts3Appendf(pRc, &zRet, ", ?");
    }
    sqlite3_free(zFree);
    return zRet;
}

/// Decode a positive integer from utf-8 text. Returns bytes consumed, -1 on ovfl.
export fn sqlite3Fts3ReadInt(z: [*:0]const u8, pnOut: *c_int) callconv(.c) c_int {
    var iVal: u64 = 0;
    var i: c_int = 0;
    while (z[@intCast(i)] >= '0' and z[@intCast(i)] <= '9') : (i += 1) {
        iVal = iVal * 10 + (z[@intCast(i)] - '0');
        if (iVal > 0x7FFFFFFF) return -1;
    }
    pnOut.* = @intCast(iVal);
    return i;
}

/// Parse a non-negative integer at *pp, advancing *pp. SQLITE_OK / SQLITE_ERROR.
fn fts3GobbleInt(pp: *[*:0]const u8, pnOut: *c_int) c_int {
    const MAX_NPREFIX: c_int = 10000000;
    var nInt: c_int = 0;
    const nByte = sqlite3Fts3ReadInt(pp.*, &nInt);
    if (nInt > MAX_NPREFIX) {
        nInt = 0;
    }
    if (nByte == 0) {
        return SQLITE_ERROR;
    }
    pnOut.* = nInt;
    pp.* += @intCast(nByte);
    return SQLITE_OK;
}

/// Parse the "prefix=ABC" parameter into an array of Fts3Index structs.
fn fts3PrefixParameter(zParam: ?[*:0]const u8, pnIndex: *c_int, apIndex: *?[*]Fts3Index) c_int {
    var nIndex: c_int = 1;

    if (zParam != null and zParam.?[0] != 0) {
        nIndex += 1;
        var p: [*:0]const u8 = zParam.?;
        while (p[0] != 0) : (p += 1) {
            if (p[0] == ',') nIndex += 1;
        }
    }

    const aIndex: ?[*]Fts3Index = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts3Index) * @as(u64, @intCast(nIndex)))));
    apIndex.* = aIndex;
    if (aIndex == null) {
        return SQLITE_NOMEM;
    }
    @memset(std.mem.sliceAsBytes(aIndex.?[0..@intCast(nIndex)]), 0);

    if (zParam) |zp| {
        var p: [*:0]const u8 = zp;
        var i: c_int = 1;
        while (i < nIndex) : (i += 1) {
            var nPrefix: c_int = 0;
            if (fts3GobbleInt(&p, &nPrefix) != 0) return SQLITE_ERROR;
            // assert( nPrefix>=0 );
            if (nPrefix == 0) {
                nIndex -= 1;
                i -= 1;
            } else {
                aIndex.?[@intCast(i)].nPrefix = nPrefix;
            }
            p += 1;
        }
    }

    pnIndex.* = nIndex;
    return SQLITE_OK;
}

/// Determine columns of a content=xxx table.
fn fts3ContentColumns(
    db: ?*sqlite3,
    zDb: [*:0]const u8,
    zTbl: [*:0]const u8,
    pazCol: *?[*]?[*:0]const u8,
    pnCol: *c_int,
    pnStr: *c_int,
    pzErr: *?[*:0]u8,
) c_int {
    var rc: c_int = SQLITE_OK;
    var pStmt: ?*sqlite3_stmt = null;

    const zSql = sqlite3_mprintf("SELECT * FROM %Q.%Q", zDb, zTbl);
    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else {
        rc = sqlite3_prepare(db, zSql.?, -1, &pStmt, null);
        if (rc != SQLITE_OK) {
            sqlite3Fts3ErrMsg(pzErr, "%s", sqlite3_errmsg(db).?);
        }
    }
    sqlite3_free(zSql);

    if (rc == SQLITE_OK) {
        var nStr: i64 = 0;
        var i: c_int = undefined;
        const nCol = sqlite3_column_count(pStmt);
        i = 0;
        while (i < nCol) : (i += 1) {
            const zCol = sqlite3_column_name(pStmt, i).?;
            nStr += @as(i64, @intCast(strlen(zCol))) + 1;
        }

        const azCol: ?[*]?[*:0]const u8 = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @sizeOf(usize)) * @as(u64, @intCast(nCol)) + @as(u64, @intCast(nStr)))));
        if (azCol == null) {
            rc = SQLITE_NOMEM;
        } else {
            var p: [*]u8 = @ptrCast(@alignCast(&azCol.?[@intCast(nCol)]));
            i = 0;
            while (i < nCol) : (i += 1) {
                const zCol = sqlite3_column_name(pStmt, i).?;
                const n: usize = strlen(zCol) + 1;
                _ = memcpy(p, zCol, n);
                azCol.?[@intCast(i)] = @ptrCast(p);
                p += n;
            }
        }
        _ = sqlite3_finalize(pStmt);

        pnCol.* = nCol;
        pnStr.* = @intCast(nStr);
        pazCol.* = azCol;
    }

    return rc;
}

// ===========================================================================
// fts3InitVtab + connect/create methods.
// ===========================================================================

const Fts4Option = struct {
    zOpt: [*:0]const u8,
    nOpt: c_int,
};

fn fts3InitVtab(
    isCreate: c_int,
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: [*]const ?[*:0]const u8,
    ppVTab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) c_int {
    const pHash: *Fts3Hash = &(@as(*Fts3HashWrapper, @ptrCast(@alignCast(pAux.?))).hash);
    var p: ?*Fts3Table = null;
    var rc: c_int = SQLITE_OK;
    var i: c_int = undefined;
    var nByte: i64 = undefined;
    var iCol: c_int = undefined;
    var nString: c_int = 0;
    var nCol: c_int = 0;
    var zCsr: [*]u8 = undefined;
    const isFts4: c_int = @intFromBool(argv[0].?[3] == '4');
    var pTokenizer: ?*sqlite3_tokenizer = null;

    var nIndex: c_int = 0;
    var aIndex: ?[*]Fts3Index = null;

    var bNoDocsize: c_int = 0;
    var bDescIdx: c_int = 0;
    var zPrefix: ?[*:0]u8 = null;
    var zCompress: ?[*:0]u8 = null;
    var zUncompress: ?[*:0]u8 = null;
    var zContent: ?[*:0]u8 = null;
    var zLanguageid: ?[*:0]u8 = null;
    var azNotindexed: ?[*]?[*:0]u8 = null;
    var nNotindexed: c_int = 0;

    const nDb: c_int = @intCast(strlen(argv[1].?) + 1);
    const nName: c_int = @intCast(strlen(argv[2].?) + 1);

    nByte = @as(i64, @sizeOf(usize)) * @as(i64, argc - 2);
    var aCol: ?[*]?[*:0]const u8 = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
    if (aCol != null) {
        @memset(std.mem.sliceAsBytes(aCol.?[0..@intCast(argc - 2)]), 0);
        azNotindexed = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
    }
    if (azNotindexed != null) {
        @memset(std.mem.sliceAsBytes(azNotindexed.?[0..@intCast(argc - 2)]), 0);
    }
    if (aCol == null or azNotindexed == null) {
        rc = SQLITE_NOMEM;
        return fts3InitOut(p, pTokenizer, &rc, zPrefix, aIndex, zCompress, zUncompress, zContent, zLanguageid, azNotindexed, nNotindexed, aCol, ppVTab);
    }

    // Loop over module arguments.
    i = 3;
    while (rc == SQLITE_OK and i < argc) : (i += 1) {
        const z: [*:0]const u8 = argv[@intCast(i)].?;
        var nKey: c_int = undefined;
        var zVal: ?[*:0]u8 = undefined;

        if (pTokenizer == null and strlen(z) > 8 and sqlite3_strnicmp(z, "tokenize", 8) == 0 and sqlite3Fts3IsIdChar(z[8]) == 0) {
            rc = sqlite3Fts3InitTokenizer(pHash, @ptrCast(z + 9), &pTokenizer, pzErr);
        } else if (isFts4 != 0 and fts3IsSpecialColumn(z, &nKey, &zVal) != 0) {
            const aFts4Opt = [_]Fts4Option{
                .{ .zOpt = "matchinfo", .nOpt = 9 },
                .{ .zOpt = "prefix", .nOpt = 6 },
                .{ .zOpt = "compress", .nOpt = 8 },
                .{ .zOpt = "uncompress", .nOpt = 10 },
                .{ .zOpt = "order", .nOpt = 5 },
                .{ .zOpt = "content", .nOpt = 7 },
                .{ .zOpt = "languageid", .nOpt = 10 },
                .{ .zOpt = "notindexed", .nOpt = 10 },
            };
            if (zVal == null) {
                rc = SQLITE_NOMEM;
            } else {
                var iOpt: usize = 0;
                while (iOpt < aFts4Opt.len) : (iOpt += 1) {
                    const pOp = &aFts4Opt[iOpt];
                    if (nKey == pOp.nOpt and sqlite3_strnicmp(z, pOp.zOpt, pOp.nOpt) == 0) break;
                }
                switch (iOpt) {
                    0 => { // MATCHINFO
                        if (strlen(zVal.?) != 4 or sqlite3_strnicmp(zVal.?, "fts3", 4) != 0) {
                            sqlite3Fts3ErrMsg(pzErr, "unrecognized matchinfo: %s", zVal.?);
                            rc = SQLITE_ERROR;
                        }
                        bNoDocsize = 1;
                    },
                    1 => { // PREFIX
                        sqlite3_free(zPrefix);
                        zPrefix = zVal;
                        zVal = null;
                    },
                    2 => { // COMPRESS
                        sqlite3_free(zCompress);
                        zCompress = zVal;
                        zVal = null;
                    },
                    3 => { // UNCOMPRESS
                        sqlite3_free(zUncompress);
                        zUncompress = zVal;
                        zVal = null;
                    },
                    4 => { // ORDER
                        if ((strlen(zVal.?) != 3 or sqlite3_strnicmp(zVal.?, "asc", 3) != 0) and (strlen(zVal.?) != 4 or sqlite3_strnicmp(zVal.?, "desc", 4) != 0)) {
                            sqlite3Fts3ErrMsg(pzErr, "unrecognized order: %s", zVal.?);
                            rc = SQLITE_ERROR;
                        }
                        bDescIdx = @intFromBool(zVal.?[0] == 'd' or zVal.?[0] == 'D');
                    },
                    5 => { // CONTENT
                        sqlite3_free(zContent);
                        zContent = zVal;
                        zVal = null;
                    },
                    6 => { // LANGUAGEID
                        sqlite3_free(zLanguageid);
                        zLanguageid = zVal;
                        zVal = null;
                    },
                    7 => { // NOTINDEXED
                        azNotindexed.?[@intCast(nNotindexed)] = zVal;
                        nNotindexed += 1;
                        zVal = null;
                    },
                    else => {
                        sqlite3Fts3ErrMsg(pzErr, "unrecognized parameter: %s", z);
                        rc = SQLITE_ERROR;
                    },
                }
                sqlite3_free(zVal);
            }
        } else {
            // A column name.
            nString += @intCast(strlen(z) + 1);
            aCol.?[@intCast(nCol)] = z;
            nCol += 1;
        }
    }

    // content=xxx handling.
    if (rc == SQLITE_OK and zContent != null) {
        sqlite3_free(zCompress);
        sqlite3_free(zUncompress);
        zCompress = null;
        zUncompress = null;
        if (nCol == 0) {
            sqlite3_free(@ptrCast(aCol));
            aCol = null;
            rc = fts3ContentColumns(db, argv[1].?, zContent.?, &aCol, &nCol, &nString, pzErr);

            if (rc == SQLITE_OK and zLanguageid != null) {
                var j: c_int = 0;
                while (j < nCol) : (j += 1) {
                    if (sqlite3_stricmp(zLanguageid.?, aCol.?[@intCast(j)].?) == 0) {
                        var k: c_int = j;
                        while (k < nCol) : (k += 1) aCol.?[@intCast(k)] = aCol.?[@intCast(k + 1)];
                        nCol -= 1;
                        break;
                    }
                }
            }
        }
    }
    if (rc != SQLITE_OK) return fts3InitOut(p, pTokenizer, &rc, zPrefix, aIndex, zCompress, zUncompress, zContent, zLanguageid, azNotindexed, nNotindexed, aCol, ppVTab);

    if (nCol == 0) {
        aCol.?[0] = "content";
        nString = 8;
        nCol = 1;
    }

    if (pTokenizer == null) {
        rc = sqlite3Fts3InitTokenizer(pHash, "simple", &pTokenizer, pzErr);
        if (rc != SQLITE_OK) return fts3InitOut(p, pTokenizer, &rc, zPrefix, aIndex, zCompress, zUncompress, zContent, zLanguageid, azNotindexed, nNotindexed, aCol, ppVTab);
    }

    rc = fts3PrefixParameter(zPrefix, &nIndex, &aIndex);
    if (rc == SQLITE_ERROR) {
        sqlite3Fts3ErrMsg(pzErr, "error parsing prefix parameter: %s", zPrefix.?);
    }
    if (rc != SQLITE_OK) return fts3InitOut(p, pTokenizer, &rc, zPrefix, aIndex, zCompress, zUncompress, zContent, zLanguageid, azNotindexed, nNotindexed, aCol, ppVTab);

    // Allocate and populate the Fts3Table structure.
    nByte = @as(i64, @sizeOf(Fts3Table)) +
        @as(i64, nCol) * @as(i64, @sizeOf(usize)) +
        @as(i64, nIndex) * @as(i64, @sizeOf(Fts3Index)) +
        @as(i64, nCol) * 1 +
        @as(i64, nName) +
        @as(i64, nDb) +
        @as(i64, nString);
    p = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
    if (p == null) {
        rc = SQLITE_NOMEM;
        return fts3InitOut(p, pTokenizer, &rc, zPrefix, aIndex, zCompress, zUncompress, zContent, zLanguageid, azNotindexed, nNotindexed, aCol, ppVTab);
    }
    const pT = p.?;
    @memset(@as([*]u8, @ptrCast(pT))[0..@intCast(nByte)], 0);
    pT.db = db;
    pT.nColumn = nCol;
    pT.nPendingData = 0;
    // azColumn = (char**)&p[1]
    pT.azColumn = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pT)) + @sizeOf(Fts3Table)));
    pT.pTokenizer = pTokenizer;
    pT.nMaxPendingData = FTS3_MAX_PENDING_DATA;
    pT.bHasDocsize = @intFromBool(isFts4 != 0 and bNoDocsize == 0);
    pT.bHasStat = @intCast(isFts4);
    pT.bFts4 = @intCast(isFts4);
    pT.bDescIdx = @intCast(bDescIdx);
    pT.nAutoincrmerge = 0xff;
    pT.zContentTbl = zContent;
    pT.zLanguageid = zLanguageid;
    zContent = null;
    zLanguageid = null;
    if (config.sqlite_debug) {
        pT.inTransaction = -1;
        pT.mxSavepoint = -1;
    }

    // aIndex = (struct Fts3Index*)&p->azColumn[nCol]
    pT.aIndex = @ptrCast(@alignCast(@as([*]?[*:0]u8, @ptrCast(pT.azColumn.?)) + @as(usize, @intCast(nCol))));
    _ = memcpy(pT.aIndex, aIndex, @as(usize, @sizeOf(Fts3Index)) * @as(usize, @intCast(nIndex)));
    pT.nIndex = nIndex;
    i = 0;
    while (i < nIndex) : (i += 1) {
        sqlite3Fts3HashInit(&pT.aIndex.?[@intCast(i)].hPending, FTS3_HASH_STRING, 1);
    }
    // abNotindexed = (u8*)&p->aIndex[nIndex]
    pT.abNotindexed = @ptrCast(@as([*]Fts3Index, @ptrCast(pT.aIndex.?)) + @as(usize, @intCast(nIndex)));

    // zName / zDb.
    zCsr = @ptrCast(pT.abNotindexed.? + @as(usize, @intCast(nCol)));
    pT.zName = @ptrCast(zCsr);
    _ = memcpy(zCsr, argv[2].?, @intCast(nName));
    zCsr += @intCast(nName);
    pT.zDb = @ptrCast(zCsr);
    _ = memcpy(zCsr, argv[1].?, @intCast(nDb));
    zCsr += @intCast(nDb);

    // azColumn array.
    iCol = 0;
    while (iCol < nCol) : (iCol += 1) {
        var n: c_int = 0;
        const z = sqlite3Fts3NextToken(aCol.?[@intCast(iCol)].?, &n);
        if (n > 0) {
            _ = memcpy(zCsr, z, @intCast(n));
        }
        zCsr[@intCast(n)] = 0;
        sqlite3Fts3Dequote(@ptrCast(zCsr));
        pT.azColumn.?[@intCast(iCol)] = @ptrCast(zCsr);
        zCsr += @intCast(n + 1);
    }

    // abNotindexed array.
    iCol = 0;
    while (iCol < nCol) : (iCol += 1) {
        const n: c_int = @intCast(strlen(pT.azColumn.?[@intCast(iCol)].?));
        i = 0;
        while (i < nNotindexed) : (i += 1) {
            const zNot = azNotindexed.?[@intCast(i)];
            if (zNot != null and n == @as(c_int, @intCast(strlen(zNot.?))) and sqlite3_strnicmp(pT.azColumn.?[@intCast(iCol)].?, zNot.?, n) == 0) {
                pT.abNotindexed.?[@intCast(iCol)] = 1;
                sqlite3_free(zNot);
                azNotindexed.?[@intCast(i)] = null;
            }
        }
    }
    i = 0;
    while (i < nNotindexed) : (i += 1) {
        if (azNotindexed.?[@intCast(i)]) |zNot| {
            sqlite3Fts3ErrMsg(pzErr, "no such column: %s", zNot);
            rc = SQLITE_ERROR;
        }
    }

    if (rc == SQLITE_OK and (zCompress == null) != (zUncompress == null)) {
        const zMiss: [*:0]const u8 = if (zCompress == null) "compress" else "uncompress";
        rc = SQLITE_ERROR;
        sqlite3Fts3ErrMsg(pzErr, "missing %s parameter in fts4 constructor", zMiss);
    }
    pT.zReadExprlist = fts3ReadExprList(pT, zUncompress, &rc);
    pT.zWriteExprlist = fts3WriteExprList(pT, zCompress, &rc);
    if (rc != SQLITE_OK) return fts3InitOut(p, pTokenizer, &rc, zPrefix, aIndex, zCompress, zUncompress, zContent, zLanguageid, azNotindexed, nNotindexed, aCol, ppVTab);

    if (isCreate != 0) {
        rc = fts3CreateTables(pT);
    }

    if (isFts4 == 0 and isCreate == 0) {
        pT.bHasStat = 2;
    }

    fts3DatabasePageSize(&rc, pT);
    pT.nNodeSize = pT.nPgsz - 35;

    if (config.sqlite_debug or config.sqlite_test) {
        pT.nMergeCount = FTS3_MERGE_COUNT;
    }

    fts3DeclareVtab(&rc, pT);

    return fts3InitOut(p, pTokenizer, &rc, zPrefix, aIndex, zCompress, zUncompress, zContent, zLanguageid, azNotindexed, nNotindexed, aCol, ppVTab);
}

/// Common cleanup tail (the `fts3_init_out:` label in C).
fn fts3InitOut(
    p: ?*Fts3Table,
    pTokenizer: ?*sqlite3_tokenizer,
    pRc: *c_int,
    zPrefix: ?[*:0]u8,
    aIndex: ?[*]Fts3Index,
    zCompress: ?[*:0]u8,
    zUncompress: ?[*:0]u8,
    zContent: ?[*:0]u8,
    zLanguageid: ?[*:0]u8,
    azNotindexed: ?[*]?[*:0]u8,
    nNotindexed: c_int,
    aCol: ?[*]?[*:0]const u8,
    ppVTab: *?*sqlite3_vtab,
) c_int {
    const rc = pRc.*;
    sqlite3_free(zPrefix);
    sqlite3_free(aIndex);
    sqlite3_free(zCompress);
    sqlite3_free(zUncompress);
    sqlite3_free(zContent);
    sqlite3_free(zLanguageid);
    var i: c_int = 0;
    while (i < nNotindexed) : (i += 1) sqlite3_free(azNotindexed.?[@intCast(i)]);
    sqlite3_free(@ptrCast(aCol));
    sqlite3_free(@ptrCast(azNotindexed));
    if (rc != SQLITE_OK) {
        if (p) |pp| {
            _ = fts3DisconnectMethod(@ptrCast(pp));
        } else if (pTokenizer) |tok| {
            _ = tok.pModule.?.xDestroy.?(tok);
        }
    } else {
        ppVTab.* = @ptrCast(&p.?.base);
    }
    return rc;
}

fn fts3ConnectMethod(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return fts3InitVtab(0, db, pAux, argc, argv.?, ppVtab, pzErr);
}
fn fts3CreateMethod(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return fts3InitVtab(1, db, pAux, argc, argv.?, ppVtab, pzErr);
}

// ===========================================================================
// xBestIndex and helpers.
// ===========================================================================

fn fts3SetEstimatedRows(pIdxInfo: *sqlite3_index_info, nRow: i64) void {
    if (sqlite3_libversion_number() >= 3008002) {
        pIdxInfo.estimatedRows = nRow;
    }
}

fn fts3SetUniqueFlag(pIdxInfo: *sqlite3_index_info) void {
    if (sqlite3_libversion_number() >= 3008012) {
        pIdxInfo.idxFlags |= SQLITE_INDEX_SCAN_UNIQUE;
    }
}

fn fts3BestIndexMethod(pVTab: *sqlite3_vtab, pInfo: *sqlite3_index_info) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pVTab));
    var i: c_int = undefined;
    var iCons: c_int = -1;
    var iLangidCons: c_int = -1;
    var iDocidGe: c_int = -1;
    var iDocidLe: c_int = -1;
    var iIdx: c_int = undefined;

    if (p.bLock != 0) {
        return SQLITE_ERROR;
    }

    pInfo.idxNum = FTS3_FULLSCAN_SEARCH;
    pInfo.estimatedCost = 5000000;
    const aConstraint = pInfo.aConstraint.?;
    i = 0;
    while (i < pInfo.nConstraint) : (i += 1) {
        const pCons = &aConstraint[@intCast(i)];
        if (pCons.usable == 0) {
            if (pCons.op == SQLITE_INDEX_CONSTRAINT_MATCH) {
                pInfo.idxNum = FTS3_FULLSCAN_SEARCH;
                pInfo.estimatedCost = 1e50;
                fts3SetEstimatedRows(pInfo, @as(i64, 1) << 50);
                return SQLITE_OK;
            }
            continue;
        }

        const bDocid: bool = (pCons.iColumn < 0 or pCons.iColumn == p.nColumn + 1);

        if (iCons < 0 and pCons.op == SQLITE_INDEX_CONSTRAINT_EQ and bDocid) {
            pInfo.idxNum = FTS3_DOCID_SEARCH;
            pInfo.estimatedCost = 1.0;
            iCons = i;
        }

        if (pCons.op == SQLITE_INDEX_CONSTRAINT_MATCH and pCons.iColumn >= 0 and pCons.iColumn <= p.nColumn) {
            pInfo.idxNum = FTS3_FULLTEXT_SEARCH + pCons.iColumn;
            pInfo.estimatedCost = 2.0;
            iCons = i;
        }

        if (pCons.op == SQLITE_INDEX_CONSTRAINT_EQ and pCons.iColumn == p.nColumn + 2) {
            iLangidCons = i;
        }

        if (bDocid) {
            switch (pCons.op) {
                SQLITE_INDEX_CONSTRAINT_GE, SQLITE_INDEX_CONSTRAINT_GT => iDocidGe = i,
                SQLITE_INDEX_CONSTRAINT_LE, SQLITE_INDEX_CONSTRAINT_LT => iDocidLe = i,
                else => {},
            }
        }
    }

    if (pInfo.idxNum == FTS3_DOCID_SEARCH) fts3SetUniqueFlag(pInfo);

    const aUsage = pInfo.aConstraintUsage.?;
    iIdx = 1;
    if (iCons >= 0) {
        aUsage[@intCast(iCons)].argvIndex = iIdx;
        iIdx += 1;
        aUsage[@intCast(iCons)].omit = 1;
    }
    if (iLangidCons >= 0) {
        pInfo.idxNum |= FTS3_HAVE_LANGID;
        aUsage[@intCast(iLangidCons)].argvIndex = iIdx;
        iIdx += 1;
    }
    if (iDocidGe >= 0) {
        pInfo.idxNum |= FTS3_HAVE_DOCID_GE;
        aUsage[@intCast(iDocidGe)].argvIndex = iIdx;
        iIdx += 1;
    }
    if (iDocidLe >= 0) {
        pInfo.idxNum |= FTS3_HAVE_DOCID_LE;
        aUsage[@intCast(iDocidLe)].argvIndex = iIdx;
        iIdx += 1;
    }

    if (pInfo.nOrderBy == 1) {
        const pOrder = &pInfo.aOrderBy.?[0];
        if (pOrder.iColumn < 0 or pOrder.iColumn == p.nColumn + 1) {
            if (pOrder.desc != 0) {
                pInfo.idxStr = @constCast("DESC");
            } else {
                pInfo.idxStr = @constCast("ASC");
            }
            pInfo.orderByConsumed = 1;
        }
    }

    return SQLITE_OK;
}

// ===========================================================================
// xOpen / xClose / cursor seek.
// ===========================================================================

fn fts3OpenMethod(pVTab: *sqlite3_vtab, ppCsr: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    _ = pVTab;
    const raw = sqlite3_malloc(@sizeOf(Fts3Cursor)) orelse return SQLITE_NOMEM;
    const pCsr: *Fts3Cursor = @ptrCast(@alignCast(raw));
    @memset(@as([*]u8, @ptrCast(pCsr))[0..@sizeOf(Fts3Cursor)], 0);
    ppCsr.* = &pCsr.base;
    return SQLITE_OK;
}

fn fts3CursorFinalizeStmt(pCsr: *Fts3Cursor) void {
    if (pCsr.bSeekStmt != 0) {
        const p: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
        if (p.pSeekStmt == null) {
            p.pSeekStmt = pCsr.pStmt;
            _ = sqlite3_reset(pCsr.pStmt);
            pCsr.pStmt = null;
        }
        pCsr.bSeekStmt = 0;
    }
    _ = sqlite3_finalize(pCsr.pStmt);
}

fn fts3ClearCursor(pCsr: *Fts3Cursor) void {
    fts3CursorFinalizeStmt(pCsr);
    sqlite3Fts3FreeDeferredTokens(pCsr);
    sqlite3_free(pCsr.aDoclist);
    sqlite3Fts3MIBufferFree(pCsr.pMIBuffer);
    sqlite3Fts3ExprFree(pCsr.pExpr);
    // memset(&(&pCsr->base)[1], 0, sizeof(Fts3Cursor)-sizeof(sqlite3_vtab_cursor));
    const off = @sizeOf(sqlite3_vtab_cursor);
    @memset(@as([*]u8, @ptrCast(pCsr))[off..@sizeOf(Fts3Cursor)], 0);
}

fn fts3CloseMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts3Cursor = @ptrCast(@alignCast(pCursor));
    fts3ClearCursor(pCsr);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

fn fts3CursorSeekStmt(pCsr: *Fts3Cursor) c_int {
    var rc: c_int = SQLITE_OK;
    if (pCsr.pStmt == null) {
        const p: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
        if (p.pSeekStmt) |seek| {
            pCsr.pStmt = seek;
            p.pSeekStmt = null;
        } else {
            const zSql = sqlite3_mprintf("SELECT %s WHERE rowid = ?", p.zReadExprlist.?);
            if (zSql == null) return SQLITE_NOMEM;
            p.bLock += 1;
            rc = sqlite3Fts3PrepareStmt(p, zSql.?, 1, 1, &pCsr.pStmt);
            p.bLock -= 1;
            sqlite3_free(zSql);
        }
        if (rc == SQLITE_OK) pCsr.bSeekStmt = 1;
    }
    return rc;
}

fn fts3CursorSeek(pContext: ?*sqlite3_context, pCsr: *Fts3Cursor) c_int {
    var rc: c_int = SQLITE_OK;
    if (pCsr.isRequireSeek != 0) {
        rc = fts3CursorSeekStmt(pCsr);
        if (rc == SQLITE_OK) {
            const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
            pTab.bLock += 1;
            _ = sqlite3_bind_int64(pCsr.pStmt, 1, pCsr.iPrevId);
            pCsr.isRequireSeek = 0;
            if (SQLITE_ROW == sqlite3_step(pCsr.pStmt)) {
                pTab.bLock -= 1;
                return SQLITE_OK;
            } else {
                pTab.bLock -= 1;
                rc = sqlite3_reset(pCsr.pStmt);
                const pT2: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
                if (rc == SQLITE_OK and pT2.zContentTbl == null) {
                    rc = FTS_CORRUPT_VTAB();
                    pCsr.isEof = 1;
                }
            }
        }
    }

    if (rc != SQLITE_OK and pContext != null) {
        sqlite3_result_error_code(pContext, rc);
    }
    return rc;
}

// ===========================================================================
// Segment b-tree interior node scanning.
// ===========================================================================

fn fts3ScanInteriorNode(zTerm: [*]const u8, nTerm: c_int, zNode: [*]const u8, nNode: c_int, piFirst_in: ?*i64, piLast_in: ?*i64) c_int {
    var piFirst = piFirst_in;
    var piLast = piLast_in;
    var rc: c_int = SQLITE_OK;
    var zCsr: [*]const u8 = zNode;
    const zEnd: [*]const u8 = zNode + @as(usize, @intCast(nNode));
    var zBuffer: ?[*]u8 = null;
    var nAlloc: i64 = 0;
    var isFirstTerm: bool = true;
    var iChild: u64 = undefined;
    var nBuffer: c_int = 0;

    zCsr += @intCast(sqlite3Fts3GetVarintU(zCsr, &iChild));
    zCsr += @intCast(sqlite3Fts3GetVarintU(zCsr, &iChild));
    if (@intFromPtr(zCsr) > @intFromPtr(zEnd)) {
        return FTS_CORRUPT_VTAB();
    }

    while (@intFromPtr(zCsr) < @intFromPtr(zEnd) and (piFirst != null or piLast != null)) {
        var cmp: c_int = undefined;
        var nSuffix: c_int = undefined;
        var nPrefix: c_int = 0;

        if (!isFirstTerm) {
            zCsr += @intCast(fts3GetVarint32(zCsr, &nPrefix));
            if (nPrefix > nBuffer) {
                rc = FTS_CORRUPT_VTAB();
                break;
            }
        }
        isFirstTerm = false;
        zCsr += @intCast(fts3GetVarint32(zCsr, &nSuffix));

        if (nPrefix > @as(c_int, @intCast(@intFromPtr(zCsr) - @intFromPtr(zNode))) or nSuffix > @as(c_int, @intCast(@intFromPtr(zEnd) - @intFromPtr(zCsr))) or nSuffix == 0) {
            rc = FTS_CORRUPT_VTAB();
            break;
        }
        if (@as(i64, nPrefix) + nSuffix > nAlloc) {
            nAlloc = (@as(i64, nPrefix) + nSuffix) * 2;
            const zNew: ?[*]u8 = @ptrCast(sqlite3_realloc64(zBuffer, @intCast(nAlloc)));
            if (zNew == null) {
                rc = SQLITE_NOMEM;
                break;
            }
            zBuffer = zNew;
        }
        _ = memcpy(zBuffer.? + @as(usize, @intCast(nPrefix)), zCsr, @intCast(nSuffix));
        nBuffer = nPrefix + nSuffix;
        zCsr += @intCast(nSuffix);

        cmp = memcmp(zTerm, zBuffer.?, @intCast(if (nBuffer > nTerm) nTerm else nBuffer));
        if (piFirst != null and (cmp < 0 or (cmp == 0 and nBuffer > nTerm))) {
            piFirst.?.* = @bitCast(iChild);
            piFirst = null;
        }

        if (piLast != null and cmp < 0) {
            piLast.?.* = @bitCast(iChild);
            piLast = null;
        }

        iChild += 1;
    }

    if (piFirst) |pf| pf.* = @bitCast(iChild);
    if (piLast) |pl| pl.* = @bitCast(iChild);

    sqlite3_free(zBuffer);
    return rc;
}

fn fts3SelectLeaf(p: *Fts3Table, zTerm: [*]const u8, nTerm: c_int, zNode: [*]const u8, nNode: c_int, piLeaf_in: ?*i64, piLeaf2: ?*i64) c_int {
    var piLeaf = piLeaf_in;
    var rc: c_int = SQLITE_OK;
    var iHeight: c_int = undefined;

    _ = fts3GetVarint32(zNode, &iHeight);
    if (iHeight > FTS3_MAX_BTREE_HEIGHT) {
        rc = FTS_CORRUPT_VTAB();
    } else {
        rc = fts3ScanInteriorNode(zTerm, nTerm, zNode, nNode, piLeaf, piLeaf2);
    }

    if (rc == SQLITE_OK and iHeight > 1) {
        var zBlob: ?[*]u8 = null;
        var nBlob: c_int = 0;

        if (piLeaf != null and piLeaf2 != null and (piLeaf.?.* != piLeaf2.?.*)) {
            rc = sqlite3Fts3ReadBlock(p, piLeaf.?.*, &zBlob, &nBlob, null);
            if (rc == SQLITE_OK) {
                rc = fts3SelectLeaf(p, zTerm, nTerm, zBlob.?, nBlob, piLeaf, null);
            }
            sqlite3_free(zBlob);
            piLeaf = null;
            zBlob = null;
        }

        if (rc == SQLITE_OK) {
            const iBlk = if (piLeaf) |pl| pl.* else piLeaf2.?.*;
            rc = sqlite3Fts3ReadBlock(p, iBlk, &zBlob, &nBlob, null);
        }
        if (rc == SQLITE_OK) {
            var iNewHeight: c_int = 0;
            _ = fts3GetVarint32(zBlob.?, &iNewHeight);
            if (iNewHeight >= iHeight) {
                rc = FTS_CORRUPT_VTAB();
            } else {
                rc = fts3SelectLeaf(p, zTerm, nTerm, zBlob.?, nBlob, piLeaf, piLeaf2);
            }
        }
        sqlite3_free(zBlob);
    }

    return rc;
}

// ===========================================================================
// Position-list / doclist primitives.
// ===========================================================================

fn fts3PutDeltaVarint(pp: *[*]u8, piPrev: *i64, iVal: i64) void {
    if (iVal - piPrev.* >= 0) {
        pp.* += @intCast(sqlite3Fts3PutVarint(pp.*, iVal - piPrev.*));
        piPrev.* = iVal;
    }
}

fn fts3PoslistCopy(pp: ?*[*]u8, ppPoslist: *[*]u8) void {
    var pEnd: [*]u8 = ppPoslist.*;
    var c: u8 = 0;

    while ((pEnd[0] | c) != 0) {
        c = pEnd[0] & 0x80;
        pEnd += 1;
    }
    pEnd += 1; // advance past POS_END terminator

    if (pp) |p_out| {
        const n: usize = @intFromPtr(pEnd) - @intFromPtr(ppPoslist.*);
        var p = p_out.*;
        _ = memcpy(p, ppPoslist.*, n);
        p += n;
        p_out.* = p;
    }
    ppPoslist.* = pEnd;
}

fn fts3ColumnlistCopy(pp: ?*[*]u8, ppPoslist: *[*]u8) void {
    var pEnd: [*]u8 = ppPoslist.*;
    var c: u8 = 0;

    while ((0xFE & (pEnd[0] | c)) != 0) {
        c = pEnd[0] & 0x80;
        pEnd += 1;
    }
    if (pp) |p_out| {
        const n: usize = @intFromPtr(pEnd) - @intFromPtr(ppPoslist.*);
        var p = p_out.*;
        _ = memcpy(p, ppPoslist.*, n);
        p += n;
        p_out.* = p;
    }
    ppPoslist.* = pEnd;
}

fn fts3ReadNextPos(pp: *[*]u8, pi: *i64) void {
    if ((pp.*[0] & 0xFE) != 0) {
        var iVal: c_int = undefined;
        pp.* += @intCast(fts3GetVarint32(pp.*, &iVal));
        pi.* += iVal;
        pi.* -= 2;
    } else {
        pi.* = POSITION_LIST_END;
    }
}

fn fts3PutColNumber(pp: *[*]u8, iCol: c_int) c_int {
    var n: c_int = 0;
    if (iCol != 0) {
        var p: [*]u8 = pp.*;
        n = 1 + sqlite3Fts3PutVarint(p + 1, iCol);
        p[0] = 0x01;
        pp.* = p + @as(usize, @intCast(n));
    }
    return n;
}

fn fts3PoslistMerge(pp: *[*]u8, pp1: *[*]u8, pp2: *[*]u8) c_int {
    var p: [*]u8 = pp.*;
    var p1: [*]u8 = pp1.*;
    var p2: [*]u8 = pp2.*;

    while (p1[0] != 0 or p2[0] != 0) {
        var iCol1: c_int = undefined;
        var iCol2: c_int = undefined;

        if (p1[0] == POS_COLUMN) {
            _ = fts3GetVarint32(p1 + 1, &iCol1);
            if (iCol1 == 0) return FTS_CORRUPT_VTAB();
        } else if (p1[0] == POS_END) {
            iCol1 = 0x7fffffff;
        } else iCol1 = 0;

        if (p2[0] == POS_COLUMN) {
            _ = fts3GetVarint32(p2 + 1, &iCol2);
            if (iCol2 == 0) return FTS_CORRUPT_VTAB();
        } else if (p2[0] == POS_END) {
            iCol2 = 0x7fffffff;
        } else iCol2 = 0;

        if (iCol1 == iCol2) {
            var iv1: i64 = 0;
            var iv2: i64 = 0;
            var iPrev: i64 = 0;
            const n = fts3PutColNumber(&p, iCol1);
            p1 += @intCast(n);
            p2 += @intCast(n);

            fts3GetDeltaVarint(&p1, &iv1);
            fts3GetDeltaVarint(&p2, &iv2);
            if (iv1 < 2 or iv2 < 2) {
                break;
            }
            while (true) {
                fts3PutDeltaVarint(&p, &iPrev, if (iv1 < iv2) iv1 else iv2);
                iPrev -= 2;
                if (iv1 == iv2) {
                    fts3ReadNextPos(&p1, &iv1);
                    fts3ReadNextPos(&p2, &iv2);
                } else if (iv1 < iv2) {
                    fts3ReadNextPos(&p1, &iv1);
                } else {
                    fts3ReadNextPos(&p2, &iv2);
                }
                if (iv1 == POSITION_LIST_END and iv2 == POSITION_LIST_END) break;
            }
        } else if (iCol1 < iCol2) {
            p1 += @intCast(fts3PutColNumber(&p, iCol1));
            fts3ColumnlistCopy(&p, &p1);
        } else {
            p2 += @intCast(fts3PutColNumber(&p, iCol2));
            fts3ColumnlistCopy(&p, &p2);
        }
    }

    p[0] = POS_END;
    p += 1;
    pp.* = p;
    pp1.* = p1 + 1;
    pp2.* = p2 + 1;
    return SQLITE_OK;
}

fn fts3PoslistPhraseMerge(pp: *[*]u8, nToken: c_int, isSaveLeft: c_int, isExact: c_int, pp1: *[*]u8, pp2: *[*]u8) c_int {
    var p: [*]u8 = pp.*;
    var p1: [*]u8 = pp1.*;
    var p2: [*]u8 = pp2.*;
    var iCol1: c_int = 0;
    var iCol2: c_int = 0;

    if (p1[0] == POS_COLUMN) {
        p1 += 1;
        p1 += @intCast(fts3GetVarint32(p1, &iCol1));
        if (iCol1 == 0) return 0;
    }
    if (p2[0] == POS_COLUMN) {
        p2 += 1;
        p2 += @intCast(fts3GetVarint32(p2, &iCol2));
        if (iCol2 == 0) return 0;
    }

    while (true) {
        if (iCol1 == iCol2) {
            var pSave: ?[*]u8 = p;
            var iPrev: i64 = 0;
            var iPos1: i64 = 0;
            var iPos2: i64 = 0;

            if (iCol1 != 0) {
                p[0] = POS_COLUMN;
                p += 1;
                p += @intCast(sqlite3Fts3PutVarint(p, iCol1));
            }

            fts3GetDeltaVarint(&p1, &iPos1);
            iPos1 -= 2;
            fts3GetDeltaVarint(&p2, &iPos2);
            iPos2 -= 2;
            if (iPos1 < 0 or iPos2 < 0) break;

            while (true) {
                if (iPos2 == iPos1 + nToken or (isExact == 0 and iPos2 > iPos1 and iPos2 <= iPos1 + nToken)) {
                    const iSave: i64 = if (isSaveLeft != 0) iPos1 else iPos2;
                    fts3PutDeltaVarint(&p, &iPrev, iSave + 2);
                    iPrev -= 2;
                    pSave = null;
                }
                if ((isSaveLeft == 0 and iPos2 <= (iPos1 + nToken)) or iPos2 <= iPos1) {
                    if ((p2[0] & 0xFE) == 0) break;
                    fts3GetDeltaVarint(&p2, &iPos2);
                    iPos2 -= 2;
                } else {
                    if ((p1[0] & 0xFE) == 0) break;
                    fts3GetDeltaVarint(&p1, &iPos1);
                    iPos1 -= 2;
                }
            }

            if (pSave) |ps| {
                p = ps;
            }

            fts3ColumnlistCopy(null, &p1);
            fts3ColumnlistCopy(null, &p2);
            if (0 == p1[0] or 0 == p2[0]) break;

            p1 += 1;
            p1 += @intCast(fts3GetVarint32(p1, &iCol1));
            p2 += 1;
            p2 += @intCast(fts3GetVarint32(p2, &iCol2));
        } else if (iCol1 < iCol2) {
            fts3ColumnlistCopy(null, &p1);
            if (0 == p1[0]) break;
            p1 += 1;
            p1 += @intCast(fts3GetVarint32(p1, &iCol1));
        } else {
            fts3ColumnlistCopy(null, &p2);
            if (0 == p2[0]) break;
            p2 += 1;
            p2 += @intCast(fts3GetVarint32(p2, &iCol2));
        }
    }

    fts3PoslistCopy(null, &p2);
    fts3PoslistCopy(null, &p1);
    pp1.* = p1;
    pp2.* = p2;
    if (@intFromPtr(pp.*) == @intFromPtr(p)) {
        return 0;
    }
    p[0] = 0x00;
    p += 1;
    pp.* = p;
    return 1;
}

fn fts3PoslistNearMerge(pp: *[*]u8, aTmp: [*]u8, nRight: c_int, nLeft: c_int, pp1: *[*]u8, pp2: *[*]u8) c_int {
    const p1: [*]u8 = pp1.*;
    const p2: [*]u8 = pp2.*;

    var pTmp1: [*]u8 = aTmp;
    var pTmp2: [*]u8 = undefined;
    var aTmp2: [*]u8 = undefined;
    var res: c_int = 1;

    _ = fts3PoslistPhraseMerge(&pTmp1, nRight, 0, 0, pp1, pp2);
    aTmp2 = pTmp1;
    pTmp2 = pTmp1;
    pp1.* = p1;
    pp2.* = p2;
    _ = fts3PoslistPhraseMerge(&pTmp2, nLeft, 1, 0, pp2, pp1);
    if (@intFromPtr(pTmp1) != @intFromPtr(aTmp) and @intFromPtr(pTmp2) != @intFromPtr(aTmp2)) {
        var a1: [*]u8 = aTmp;
        var a2: [*]u8 = aTmp2;
        _ = fts3PoslistMerge(pp, &a1, &a2);
    } else if (@intFromPtr(pTmp1) != @intFromPtr(aTmp)) {
        var a1: [*]u8 = aTmp;
        fts3PoslistCopy(pp, &a1);
    } else if (@intFromPtr(pTmp2) != @intFromPtr(aTmp2)) {
        var a2: [*]u8 = aTmp2;
        fts3PoslistCopy(pp, &a2);
    } else {
        res = 0;
    }

    return res;
}

// TermSelect: pair-wise doclist merge accumulator (16 buffers).
const TermSelect = extern struct {
    aaOutput: [16]?[*]u8,
    anOutput: [16]c_int,
};

fn fts3GetDeltaVarint3(pp: *?[*]u8, pEnd: [*]u8, bDescIdx: c_int, pVal: *i64) void {
    if (@intFromPtr(pp.*.?) >= @intFromPtr(pEnd)) {
        pp.* = null;
    } else {
        var iVal: u64 = undefined;
        pp.*.? += @intCast(sqlite3Fts3GetVarintU(pp.*.?, &iVal));
        if (bDescIdx != 0) {
            pVal.* = @bitCast(@as(u64, @bitCast(pVal.*)) -% iVal);
        } else {
            pVal.* = @bitCast(@as(u64, @bitCast(pVal.*)) +% iVal);
        }
    }
}

fn fts3PutDeltaVarint3(pp: *[*]u8, bDescIdx: c_int, piPrev: *i64, pbFirst: *c_int, iVal: i64) void {
    var iWrite: u64 = undefined;
    if (bDescIdx == 0 or pbFirst.* == 0) {
        iWrite = @as(u64, @bitCast(iVal)) -% @as(u64, @bitCast(piPrev.*));
    } else {
        iWrite = @as(u64, @bitCast(piPrev.*)) -% @as(u64, @bitCast(iVal));
    }
    pp.* += @intCast(sqlite3Fts3PutVarint(pp.*, @bitCast(iWrite)));
    piPrev.* = iVal;
    pbFirst.* = 1;
}

// DOCID_CMP(iv1,iv2): (bDescDoclist?-1:1) * (iv1>iv2 ? 1 : (iv1==iv2?0:-1))
inline fn docidCmp(bDescDoclist: c_int, iv1: i64, iv2: i64) i64 {
    const m: i64 = if (bDescDoclist != 0) -1 else 1;
    const s: i64 = if (iv1 > iv2) 1 else (if (iv1 == iv2) 0 else -1);
    return m * s;
}

fn fts3DoclistOrMerge(bDescDoclist: c_int, a1: [*]u8, n1: c_int, a2: [*]u8, n2: c_int, paOut: *?[*]u8, pnOut: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    var iv1: i64 = 0;
    var iv2: i64 = 0;
    var iPrev: i64 = 0;
    const pEnd1: [*]u8 = a1 + @as(usize, @intCast(n1));
    const pEnd2: [*]u8 = a2 + @as(usize, @intCast(n2));
    var p1: ?[*]u8 = a1;
    var p2: ?[*]u8 = a2;
    var p: [*]u8 = undefined;
    var aOut: ?[*]u8 = undefined;
    var bFirstOut: c_int = 0;

    paOut.* = null;
    pnOut.* = 0;

    aOut = @ptrCast(sqlite3_malloc64(@intCast(@as(i64, n1) + n2 + FTS3_VARINT_MAX - 1 + FTS3_BUFFER_PADDING)));
    if (aOut == null) return SQLITE_NOMEM;

    p = aOut.?;
    fts3GetDeltaVarint3(&p1, pEnd1, 0, &iv1);
    fts3GetDeltaVarint3(&p2, pEnd2, 0, &iv2);
    while (p1 != null or p2 != null) {
        const iDiff = docidCmp(bDescDoclist, iv1, iv2);

        if (p2 != null and p1 != null and iDiff == 0) {
            fts3PutDeltaVarint3(&p, bDescDoclist, &iPrev, &bFirstOut, iv1);
            var pp1 = p1.?;
            var pp2 = p2.?;
            rc = fts3PoslistMerge(&p, &pp1, &pp2);
            p1 = pp1;
            p2 = pp2;
            if (rc != 0) break;
            fts3GetDeltaVarint3(&p1, pEnd1, bDescDoclist, &iv1);
            fts3GetDeltaVarint3(&p2, pEnd2, bDescDoclist, &iv2);
        } else if (p2 == null or (p1 != null and iDiff < 0)) {
            fts3PutDeltaVarint3(&p, bDescDoclist, &iPrev, &bFirstOut, iv1);
            var pp1 = p1.?;
            fts3PoslistCopy(&p, &pp1);
            p1 = pp1;
            fts3GetDeltaVarint3(&p1, pEnd1, bDescDoclist, &iv1);
        } else {
            fts3PutDeltaVarint3(&p, bDescDoclist, &iPrev, &bFirstOut, iv2);
            var pp2 = p2.?;
            fts3PoslistCopy(&p, &pp2);
            p2 = pp2;
            fts3GetDeltaVarint3(&p2, pEnd2, bDescDoclist, &iv2);
        }
    }

    if (rc != SQLITE_OK) {
        sqlite3_free(aOut);
        aOut = null;
        p = undefined;
    } else {
        @memset((aOut.? + (@intFromPtr(p) - @intFromPtr(aOut.?)))[0..@intCast(FTS3_BUFFER_PADDING)], 0);
        pnOut.* = @intCast(@intFromPtr(p) - @intFromPtr(aOut.?));
    }
    paOut.* = aOut;
    return rc;
}

fn fts3DoclistPhraseMerge(bDescDoclist: c_int, nDist: c_int, aLeft: [*]u8, nLeft: c_int, paRight: *[*]u8, pnRight: *c_int) c_int {
    var iv1: i64 = 0;
    var iv2: i64 = 0;
    var iPrev: i64 = 0;
    const aRight: [*]u8 = paRight.*;
    const pEnd1: [*]u8 = aLeft + @as(usize, @intCast(nLeft));
    const pEnd2: [*]u8 = aRight + @as(usize, @intCast(pnRight.*));
    var p1: ?[*]u8 = aLeft;
    var p2: ?[*]u8 = aRight;
    var p: [*]u8 = undefined;
    var bFirstOut: c_int = 0;
    var aOut: [*]u8 = undefined;

    if (bDescDoclist != 0) {
        const a: ?[*]u8 = @ptrCast(sqlite3_malloc64(@intCast(@as(i64, pnRight.*) + FTS3_VARINT_MAX)));
        if (a == null) return SQLITE_NOMEM;
        aOut = a.?;
    } else {
        aOut = aRight;
    }
    p = aOut;

    fts3GetDeltaVarint3(&p1, pEnd1, 0, &iv1);
    fts3GetDeltaVarint3(&p2, pEnd2, 0, &iv2);

    while (p1 != null and p2 != null) {
        const iDiff = docidCmp(bDescDoclist, iv1, iv2);
        if (iDiff == 0) {
            const pSave = p;
            const iPrevSave = iPrev;
            const bFirstOutSave = bFirstOut;

            fts3PutDeltaVarint3(&p, bDescDoclist, &iPrev, &bFirstOut, iv1);
            var pp1 = p1.?;
            var pp2 = p2.?;
            if (0 == fts3PoslistPhraseMerge(&p, nDist, 0, 1, &pp1, &pp2)) {
                p = pSave;
                iPrev = iPrevSave;
                bFirstOut = bFirstOutSave;
            }
            p1 = pp1;
            p2 = pp2;
            fts3GetDeltaVarint3(&p1, pEnd1, bDescDoclist, &iv1);
            fts3GetDeltaVarint3(&p2, pEnd2, bDescDoclist, &iv2);
        } else if (iDiff < 0) {
            var pp1 = p1.?;
            fts3PoslistCopy(null, &pp1);
            p1 = pp1;
            fts3GetDeltaVarint3(&p1, pEnd1, bDescDoclist, &iv1);
        } else {
            var pp2 = p2.?;
            fts3PoslistCopy(null, &pp2);
            p2 = pp2;
            fts3GetDeltaVarint3(&p2, pEnd2, bDescDoclist, &iv2);
        }
    }

    pnRight.* = @intCast(@intFromPtr(p) - @intFromPtr(aOut));
    if (bDescDoclist != 0) {
        sqlite3_free(aRight);
        paRight.* = aOut;
    }

    return SQLITE_OK;
}

/// Position-list filter: emit only the position-0 entries. Returns bytes written.
export fn sqlite3Fts3FirstFilter(iDelta: i64, pList: [*]u8, nList: c_int, pOut: [*]u8) callconv(.c) c_int {
    var nOut: c_int = 0;
    var bWritten: c_int = 0;
    var p: [*]u8 = pList;
    const pEnd: [*]u8 = pList + @as(usize, @intCast(nList));

    if (p[0] != 0x01) {
        if (p[0] == 0x02) {
            nOut += sqlite3Fts3PutVarint(pOut + @as(usize, @intCast(nOut)), iDelta);
            pOut[@intCast(nOut)] = 0x02;
            nOut += 1;
            bWritten = 1;
        }
        fts3ColumnlistCopy(null, &p);
    }

    while (@intFromPtr(p) < @intFromPtr(pEnd)) {
        var iCol: i64 = undefined;
        p += 1;
        p += @intCast(sqlite3Fts3GetVarint(p, &iCol));
        if (p[0] == 0x02) {
            if (bWritten == 0) {
                nOut += sqlite3Fts3PutVarint(pOut + @as(usize, @intCast(nOut)), iDelta);
                bWritten = 1;
            }
            pOut[@intCast(nOut)] = 0x01;
            nOut += 1;
            nOut += sqlite3Fts3PutVarint(pOut + @as(usize, @intCast(nOut)), iCol);
            pOut[@intCast(nOut)] = 0x02;
            nOut += 1;
        }
        fts3ColumnlistCopy(null, &p);
    }
    if (bWritten != 0) {
        pOut[@intCast(nOut)] = 0x00;
        nOut += 1;
    }

    return nOut;
}

// ===========================================================================
// Segment-reader cursor construction and term selection.
// ===========================================================================

fn fts3TermSelectFinishMerge(p: *Fts3Table, pTS: *TermSelect) c_int {
    var aOut: ?[*]u8 = null;
    var nOut: c_int = 0;
    var i: usize = 0;

    while (i < pTS.aaOutput.len) : (i += 1) {
        if (pTS.aaOutput[i]) |buf| {
            if (aOut == null) {
                aOut = buf;
                nOut = pTS.anOutput[i];
                pTS.aaOutput[i] = null;
            } else {
                var nNew: c_int = undefined;
                var aNew: ?[*]u8 = undefined;
                const rc = fts3DoclistOrMerge(p.bDescIdx, buf, pTS.anOutput[i], aOut.?, nOut, &aNew, &nNew);
                if (rc != SQLITE_OK) {
                    sqlite3_free(aOut);
                    return rc;
                }
                sqlite3_free(pTS.aaOutput[i]);
                sqlite3_free(aOut);
                pTS.aaOutput[i] = null;
                aOut = aNew;
                nOut = nNew;
            }
        }
    }

    pTS.aaOutput[0] = aOut;
    pTS.anOutput[0] = nOut;
    return SQLITE_OK;
}

fn fts3TermSelectMerge(p: *Fts3Table, pTS: *TermSelect, aDoclist: [*]u8, nDoclist: c_int) c_int {
    if (pTS.aaOutput[0] == null) {
        pTS.aaOutput[0] = @ptrCast(sqlite3_malloc64(@intCast(@as(i64, nDoclist) + FTS3_VARINT_MAX + 1)));
        pTS.anOutput[0] = nDoclist;
        if (pTS.aaOutput[0]) |out| {
            _ = memcpy(out, aDoclist, @intCast(nDoclist));
            @memset((out + @as(usize, @intCast(nDoclist)))[0..@intCast(FTS3_VARINT_MAX)], 0);
        } else {
            return SQLITE_NOMEM;
        }
    } else {
        var aMerge: ?[*]u8 = aDoclist;
        var nMerge: c_int = nDoclist;
        var iOut: usize = 0;

        while (iOut < pTS.aaOutput.len) : (iOut += 1) {
            if (pTS.aaOutput[iOut] == null) {
                pTS.aaOutput[iOut] = aMerge;
                pTS.anOutput[iOut] = nMerge;
                break;
            } else {
                var aNew: ?[*]u8 = undefined;
                var nNew: c_int = undefined;
                const rc = fts3DoclistOrMerge(p.bDescIdx, aMerge.?, nMerge, pTS.aaOutput[iOut].?, pTS.anOutput[iOut], &aNew, &nNew);
                if (rc != SQLITE_OK) {
                    if (@intFromPtr(aMerge) != @intFromPtr(aDoclist)) sqlite3_free(aMerge);
                    return rc;
                }

                if (@intFromPtr(aMerge) != @intFromPtr(aDoclist)) sqlite3_free(aMerge);
                sqlite3_free(pTS.aaOutput[iOut]);
                pTS.aaOutput[iOut] = null;

                aMerge = aNew;
                nMerge = nNew;
                if ((iOut + 1) == pTS.aaOutput.len) {
                    pTS.aaOutput[iOut] = aMerge;
                    pTS.anOutput[iOut] = nMerge;
                }
            }
        }
    }
    return SQLITE_OK;
}

fn fts3SegReaderCursorAppend(pCsr: *Fts3MultiSegReader, pNew: *Fts3SegReader) c_int {
    if (@rem(pCsr.nSegment, 16) == 0) {
        const nByte: i64 = (@as(i64, pCsr.nSegment) + 16) * @sizeOf(usize);
        const apNew: ?[*]?*Fts3SegReader = @ptrCast(@alignCast(sqlite3_realloc64(@ptrCast(pCsr.apSegment), @intCast(nByte))));
        if (apNew == null) {
            sqlite3Fts3SegReaderFree(pNew);
            return SQLITE_NOMEM;
        }
        pCsr.apSegment = apNew;
    }
    pCsr.apSegment.?[@intCast(pCsr.nSegment)] = pNew;
    pCsr.nSegment += 1;
    return SQLITE_OK;
}

fn fts3SegReaderCursor(p: *Fts3Table, iLangid: c_int, iIndex: c_int, iLevel: c_int, zTerm: ?[*]const u8, nTerm: c_int, isPrefix: c_int, isScan: c_int, pCsr: *Fts3MultiSegReader) c_int {
    var rc: c_int = SQLITE_OK;
    var pStmt: ?*sqlite3_stmt = null;
    var rc2: c_int = undefined;

    if (iLevel < 0 and p.aIndex != null and p.iPrevLangid == iLangid) {
        var pSeg: ?*Fts3SegReader = null;
        rc = sqlite3Fts3SegReaderPending(p, iIndex, zTerm, nTerm, @intFromBool(isPrefix != 0 or isScan != 0), &pSeg);
        if (rc == SQLITE_OK and pSeg != null) {
            rc = fts3SegReaderCursorAppend(pCsr, pSeg.?);
        }
    }

    if (iLevel != FTS3_SEGCURSOR_PENDING) {
        if (rc == SQLITE_OK) {
            rc = sqlite3Fts3AllSegdirs(p, iLangid, iIndex, iLevel, &pStmt);
        }

        while (rc == SQLITE_OK and SQLITE_ROW == (blk: {
            rc = sqlite3_step(pStmt);
            break :blk rc;
        })) {
            var pSeg: ?*Fts3SegReader = null;

            var iStartBlock: i64 = sqlite3_column_int64(pStmt, 1);
            var iLeavesEndBlock: i64 = sqlite3_column_int64(pStmt, 2);
            const iEndBlock: i64 = sqlite3_column_int64(pStmt, 3);
            const nRoot: c_int = sqlite3_column_bytes(pStmt, 4);
            const zRoot: ?[*]const u8 = @ptrCast(sqlite3_column_blob(pStmt, 4));

            if (iStartBlock != 0 and zTerm != null and zRoot != null) {
                const pi: ?*i64 = if (isPrefix != 0) &iLeavesEndBlock else null;
                rc = fts3SelectLeaf(p, zTerm.?, nTerm, zRoot.?, nRoot, &iStartBlock, pi);
                if (rc != SQLITE_OK) {
                    rc2 = sqlite3_reset(pStmt);
                    if (rc == SQLITE_DONE) rc = rc2;
                    return rc;
                }
                if (isPrefix == 0 and isScan == 0) iLeavesEndBlock = iStartBlock;
            }

            rc = sqlite3Fts3SegReaderNew(pCsr.nSegment + 1, @intFromBool(isPrefix == 0 and isScan == 0), iStartBlock, iLeavesEndBlock, iEndBlock, zRoot, nRoot, &pSeg);
            if (rc != SQLITE_OK) {
                rc2 = sqlite3_reset(pStmt);
                if (rc == SQLITE_DONE) rc = rc2;
                return rc;
            }
            rc = fts3SegReaderCursorAppend(pCsr, pSeg.?);
        }
    }

    rc2 = sqlite3_reset(pStmt);
    if (rc == SQLITE_DONE) rc = rc2;
    return rc;
}

export fn sqlite3Fts3SegReaderCursor(p: *Fts3Table, iLangid: c_int, iIndex: c_int, iLevel: c_int, zTerm: ?[*]const u8, nTerm: c_int, isPrefix: c_int, isScan: c_int, pCsr: *Fts3MultiSegReader) callconv(.c) c_int {
    @memset(@as([*]u8, @ptrCast(pCsr))[0..@sizeOf(Fts3MultiSegReader)], 0);
    return fts3SegReaderCursor(p, iLangid, iIndex, iLevel, zTerm, nTerm, isPrefix, isScan, pCsr);
}

fn fts3SegReaderCursorAddZero(p: *Fts3Table, iLangid: c_int, zTerm: ?[*]const u8, nTerm: c_int, pCsr: *Fts3MultiSegReader) c_int {
    return fts3SegReaderCursor(p, iLangid, 0, FTS3_SEGCURSOR_ALL, zTerm, nTerm, 0, 0, pCsr);
}

fn fts3TermSegReaderCursor(pCsr: *Fts3Cursor, zTerm: ?[*]const u8, nTerm: c_int, isPrefix: c_int, ppSegcsr: *?*Fts3MultiSegReader) c_int {
    var rc: c_int = SQLITE_NOMEM;
    const pSegcsr: ?*Fts3MultiSegReader = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(Fts3MultiSegReader))));
    if (pSegcsr) |seg| {
        var i: c_int = undefined;
        var bFound: c_int = 0;
        const p: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));

        if (isPrefix != 0) {
            i = 1;
            while (bFound == 0 and i < p.nIndex) : (i += 1) {
                if (p.aIndex.?[@intCast(i)].nPrefix == nTerm) {
                    bFound = 1;
                    rc = sqlite3Fts3SegReaderCursor(p, pCsr.iLangid, i, FTS3_SEGCURSOR_ALL, zTerm, nTerm, 0, 0, seg);
                    seg.bLookup = 1;
                }
            }

            i = 1;
            while (bFound == 0 and i < p.nIndex) : (i += 1) {
                if (p.aIndex.?[@intCast(i)].nPrefix == nTerm + 1) {
                    bFound = 1;
                    rc = sqlite3Fts3SegReaderCursor(p, pCsr.iLangid, i, FTS3_SEGCURSOR_ALL, zTerm, nTerm, 1, 0, seg);
                    if (rc == SQLITE_OK) {
                        rc = fts3SegReaderCursorAddZero(p, pCsr.iLangid, zTerm, nTerm, seg);
                    }
                }
            }
        }

        if (bFound == 0) {
            rc = sqlite3Fts3SegReaderCursor(p, pCsr.iLangid, 0, FTS3_SEGCURSOR_ALL, zTerm, nTerm, isPrefix, 0, seg);
            seg.bLookup = @intFromBool(isPrefix == 0);
        }
    }

    ppSegcsr.* = pSegcsr;
    return rc;
}

fn fts3SegReaderCursorFree(pSegcsr: ?*Fts3MultiSegReader) void {
    sqlite3Fts3SegReaderFinish(pSegcsr.?);
    sqlite3_free(pSegcsr);
}

fn fts3TermSelect(p: *Fts3Table, pTok: *Fts3PhraseToken, iColumn: c_int, pnOut: *c_int, ppOut: *?[*]u8) c_int {
    var rc: c_int = undefined;
    const pSegcsr: *Fts3MultiSegReader = pTok.pSegcsr.?;
    var tsc: TermSelect = undefined;
    var filter: Fts3SegFilter = undefined;

    @memset(@as([*]u8, @ptrCast(&tsc))[0..@sizeOf(TermSelect)], 0);

    filter.flags = FTS3_SEGMENT_IGNORE_EMPTY | FTS3_SEGMENT_REQUIRE_POS |
        (if (pTok.isPrefix != 0) FTS3_SEGMENT_PREFIX else 0) |
        (if (pTok.bFirst != 0) FTS3_SEGMENT_FIRST else 0) |
        (if (iColumn < p.nColumn) FTS3_SEGMENT_COLUMN_FILTER else 0);
    filter.iCol = iColumn;
    filter.zTerm = @ptrCast(pTok.z);
    filter.nTerm = pTok.n;

    rc = sqlite3Fts3SegReaderStart(p, pSegcsr, &filter);
    while (SQLITE_OK == rc and SQLITE_ROW == (blk: {
        rc = sqlite3Fts3SegReaderStep(p, pSegcsr);
        break :blk rc;
    })) {
        rc = fts3TermSelectMerge(p, &tsc, pSegcsr.aDoclist.?, pSegcsr.nDoclist);
    }

    if (rc == SQLITE_OK) {
        rc = fts3TermSelectFinishMerge(p, &tsc);
    }
    if (rc == SQLITE_OK) {
        ppOut.* = tsc.aaOutput[0];
        pnOut.* = tsc.anOutput[0];
    } else {
        var i: usize = 0;
        while (i < tsc.aaOutput.len) : (i += 1) {
            sqlite3_free(tsc.aaOutput[i]);
        }
    }

    fts3SegReaderCursorFree(pSegcsr);
    pTok.pSegcsr = null;
    return rc;
}

fn fts3DoclistCountDocids(aList: ?[*]u8, nList: c_int) c_int {
    var nDoc: c_int = 0;
    if (aList) |al| {
        const aEnd: [*]u8 = al + @as(usize, @intCast(nList));
        var p: [*]u8 = al;
        while (@intFromPtr(p) < @intFromPtr(aEnd)) {
            nDoc += 1;
            // C: while( (*p++)&0x80 );  — post-increment past the docid varint.
            while (true) {
                const b = p[0];
                p += 1;
                if ((b & 0x80) == 0) break;
            }
            fts3PoslistCopy(null, &p);
        }
    }
    return nDoc;
}

// ===========================================================================
// Cursor xNext / xFilter / xEof / xRowid / xColumn and write methods.
// ===========================================================================

fn fts3NextMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    var rc: c_int = undefined;
    const pCsr: *Fts3Cursor = @ptrCast(@alignCast(pCursor));
    if (pCsr.eSearch == FTS3_DOCID_SEARCH or pCsr.eSearch == FTS3_FULLSCAN_SEARCH) {
        const pTab: *Fts3Table = @ptrCast(@alignCast(pCursor.pVtab.?));
        pTab.bLock += 1;
        if (SQLITE_ROW != sqlite3_step(pCsr.pStmt)) {
            pCsr.isEof = 1;
            rc = sqlite3_reset(pCsr.pStmt);
        } else {
            pCsr.iPrevId = sqlite3_column_int64(pCsr.pStmt, 0);
            rc = SQLITE_OK;
        }
        pTab.bLock -= 1;
    } else {
        rc = fts3EvalNext(pCsr);
    }
    return rc;
}

fn fts3DocidRange(pVal: ?*sqlite3_value, iDefault: i64) i64 {
    if (pVal) |v| {
        const eType = sqlite3_value_numeric_type(v);
        if (eType == SQLITE_INTEGER) {
            return sqlite3_value_int64(v);
        }
    }
    return iDefault;
}

fn fts3FilterMethod(pCursor: *sqlite3_vtab_cursor, idxNum: c_int, idxStr: ?[*:0]const u8, nVal: c_int, apVal: ?[*]?*sqlite3_value) callconv(.c) c_int {
    _ = nVal;
    var rc: c_int = SQLITE_OK;
    var zSql: ?[*:0]u8 = undefined;
    var eSearch: c_int = undefined;
    const p: *Fts3Table = @ptrCast(@alignCast(pCursor.pVtab.?));
    const pCsr: *Fts3Cursor = @ptrCast(@alignCast(pCursor));

    var pCons: ?*sqlite3_value = null;
    var pLangid: ?*sqlite3_value = null;
    var pDocidGe: ?*sqlite3_value = null;
    var pDocidLe: ?*sqlite3_value = null;
    var iIdx: c_int = undefined;

    if (p.bLock != 0) {
        return SQLITE_ERROR;
    }

    const av = apVal.?;
    eSearch = idxNum & 0x0000FFFF;

    iIdx = 0;
    if (eSearch != FTS3_FULLSCAN_SEARCH) {
        pCons = av[@intCast(iIdx)];
        iIdx += 1;
    }
    if (idxNum & FTS3_HAVE_LANGID != 0) {
        pLangid = av[@intCast(iIdx)];
        iIdx += 1;
    }
    if (idxNum & FTS3_HAVE_DOCID_GE != 0) {
        pDocidGe = av[@intCast(iIdx)];
        iIdx += 1;
    }
    if (idxNum & FTS3_HAVE_DOCID_LE != 0) {
        pDocidLe = av[@intCast(iIdx)];
        iIdx += 1;
    }

    fts3ClearCursor(pCsr);

    pCsr.iMinDocid = fts3DocidRange(pDocidGe, SMALLEST_INT64);
    pCsr.iMaxDocid = fts3DocidRange(pDocidLe, LARGEST_INT64);

    if (idxStr) |s| {
        pCsr.bDesc = @intFromBool(s[0] == 'D');
    } else {
        pCsr.bDesc = p.bDescIdx;
    }
    pCsr.eSearch = @intCast(eSearch);

    if (eSearch != FTS3_DOCID_SEARCH and eSearch != FTS3_FULLSCAN_SEARCH) {
        const iCol = eSearch - FTS3_FULLTEXT_SEARCH;
        const zQuery: ?[*:0]const u8 = sqlite3_value_text(pCons);

        if (zQuery == null and sqlite3_value_type(pCons) != SQLITE_NULL) {
            return SQLITE_NOMEM;
        }

        pCsr.iLangid = 0;
        if (pLangid) |pl| pCsr.iLangid = sqlite3_value_int(pl);

        rc = sqlite3Fts3ExprParse(p.pTokenizer, pCsr.iLangid, p.azColumn, p.bFts4, p.nColumn, iCol, zQuery, -1, &pCsr.pExpr, &p.base.zErrMsg);
        if (rc != SQLITE_OK) {
            return rc;
        }

        rc = fts3EvalStart(pCsr);
        sqlite3Fts3SegmentsClose(p);
        if (rc != SQLITE_OK) return rc;
        pCsr.pNextId = pCsr.aDoclist;
        pCsr.iPrevId = 0;
    }

    if (eSearch == FTS3_FULLSCAN_SEARCH) {
        if (pDocidGe != null or pDocidLe != null) {
            zSql = sqlite3_mprintf("SELECT %s WHERE rowid BETWEEN %lld AND %lld ORDER BY rowid %s", p.zReadExprlist.?, pCsr.iMinDocid, pCsr.iMaxDocid, @as([*:0]const u8, if (pCsr.bDesc != 0) "DESC" else "ASC"));
        } else {
            zSql = sqlite3_mprintf("SELECT %s ORDER BY rowid %s", p.zReadExprlist.?, @as([*:0]const u8, if (pCsr.bDesc != 0) "DESC" else "ASC"));
        }
        if (zSql) |s| {
            p.bLock += 1;
            rc = sqlite3Fts3PrepareStmt(p, s, 1, 1, &pCsr.pStmt);
            p.bLock -= 1;
            sqlite3_free(zSql);
        } else {
            rc = SQLITE_NOMEM;
        }
    } else if (eSearch == FTS3_DOCID_SEARCH) {
        rc = fts3CursorSeekStmt(pCsr);
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_value(pCsr.pStmt, 1, pCons);
        }
    }
    if (rc != SQLITE_OK) return rc;

    return fts3NextMethod(pCursor);
}

fn fts3EofMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts3Cursor = @ptrCast(@alignCast(pCursor));
    if (pCsr.isEof != 0) {
        fts3ClearCursor(pCsr);
        pCsr.isEof = 1;
    }
    return pCsr.isEof;
}

fn fts3RowidMethod(pCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *Fts3Cursor = @ptrCast(@alignCast(pCursor));
    pRowid.* = pCsr.iPrevId;
    return SQLITE_OK;
}

fn fts3ColumnMethod(pCursor: *sqlite3_vtab_cursor, pCtx: ?*sqlite3_context, iCol_in: c_int) callconv(.c) c_int {
    var iCol = iCol_in;
    var rc: c_int = SQLITE_OK;
    const pCsr: *Fts3Cursor = @ptrCast(@alignCast(pCursor));
    const p: *Fts3Table = @ptrCast(@alignCast(pCursor.pVtab.?));

    switch (iCol - p.nColumn) {
        0 => {
            // The special 'table-name' column.
            sqlite3_result_pointer(pCtx, pCsr, "fts3cursor", null);
        },
        1 => {
            sqlite3_result_int64(pCtx, pCsr.iPrevId);
        },
        2 => {
            if (pCsr.pExpr != null) {
                sqlite3_result_int64(pCtx, pCsr.iLangid);
            } else if (p.zLanguageid == null) {
                sqlite3_result_int(pCtx, 0);
            } else {
                iCol = p.nColumn;
                // deliberate fall-through to default.
                rc = fts3ColumnDefault(pCsr, p, pCtx, iCol);
            }
        },
        else => {
            rc = fts3ColumnDefault(pCsr, p, pCtx, iCol);
        },
    }

    return rc;
}

/// The `default:` case of fts3ColumnMethod (reached directly, or by the
/// fall-through from case 2 when iCol is reset to p->nColumn).
inline fn fts3ColumnDefault(pCsr: *Fts3Cursor, p: *Fts3Table, pCtx: ?*sqlite3_context, iCol: c_int) c_int {
    _ = p;
    const rc = fts3CursorSeek(null, pCsr);
    if (rc == SQLITE_OK and sqlite3_data_count(pCsr.pStmt) - 1 > iCol) {
        sqlite3_result_value(pCtx, sqlite3_column_value(pCsr.pStmt, iCol + 1));
    }
    return rc;
}

fn fts3UpdateMethod(pVtab: *sqlite3_vtab, nArg: c_int, apVal: ?[*]?*sqlite3_value, pRowid: *i64) callconv(.c) c_int {
    return sqlite3Fts3UpdateMethod(pVtab, nArg, apVal, pRowid);
}

fn fts3SyncMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const nMinMerge: u32 = 64;
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    var rc: c_int = undefined;
    const iLastRowid: i64 = sqlite3_last_insert_rowid(p.db);

    rc = sqlite3Fts3PendingTermsFlush(p);
    if (rc == SQLITE_OK and p.nLeafAdd > (nMinMerge / 16) and p.nAutoincrmerge != 0 and p.nAutoincrmerge != 0xff) {
        var mxLevel: c_int = 0;
        var A: c_int = undefined;
        rc = sqlite3Fts3MaxLevel(p, &mxLevel);
        A = @as(c_int, @bitCast(p.nLeafAdd)) * mxLevel;
        A += @divTrunc(A, 2);
        if (A > @as(c_int, @intCast(nMinMerge))) rc = sqlite3Fts3Incrmerge(p, A, p.nAutoincrmerge);
    }
    sqlite3Fts3SegmentsClose(p);
    sqlite3_set_last_insert_rowid(p.db, iLastRowid);
    return rc;
}

fn fts3SetHasStat(p: *Fts3Table) c_int {
    var rc: c_int = SQLITE_OK;
    if (p.bHasStat == 2) {
        const zTbl = sqlite3_mprintf("%s_stat", p.zName.?);
        if (zTbl) |zt| {
            const res = sqlite3_table_column_metadata(p.db, p.zDb, zt, null, null, null, null, null, null);
            sqlite3_free(zTbl);
            p.bHasStat = @intFromBool(res == SQLITE_OK);
        } else {
            rc = SQLITE_NOMEM;
        }
    }
    return rc;
}

fn fts3BeginMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    var rc: c_int = undefined;
    p.nLeafAdd = 0;
    rc = fts3SetHasStat(p);
    if (config.sqlite_debug) {
        if (rc == SQLITE_OK) {
            p.inTransaction = 1;
            p.mxSavepoint = -1;
        }
    }
    return rc;
}

fn fts3CommitMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    if (config.sqlite_debug) {
        const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
        p.inTransaction = 0;
        p.mxSavepoint = -1;
    }
    return SQLITE_OK;
}

fn fts3RollbackMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    sqlite3Fts3PendingTermsClear(p);
    if (config.sqlite_debug) {
        p.inTransaction = 0;
        p.mxSavepoint = -1;
    }
    return SQLITE_OK;
}

fn fts3ReversePoslist(pStart: [*]u8, ppPoslist: *[*]u8) void {
    var p: [*]u8 = ppPoslist.* - 2;
    var c: u8 = 0;

    // Skip backwards past any trailing 0x00 bytes added by NearTrim().
    while (@intFromPtr(p) > @intFromPtr(pStart)) {
        c = p[0];
        p -= 1;
        if (c != 0) break;
    }

    // Search backwards for a varint with value zero.
    while (@intFromPtr(p) > @intFromPtr(pStart) and (((p[0] & 0x80) | c) != 0)) {
        c = p[0];
        p -= 1;
    }

    if (@intFromPtr(p) > @intFromPtr(pStart) or (c == 0 and @intFromPtr(ppPoslist.*) > @intFromPtr(p + 2))) {
        p = p + 2;
    }
    while ((p[0] & 0x80) != 0) {
        p += 1;
    }
    ppPoslist.* = p;
}

// ===========================================================================
// Overloaded SQL functions (snippet/offsets/optimize/matchinfo) and method
// callbacks for xFindFunction / xRename / xSavepoint / xRelease / xRollbackTo /
// xShadowName / xIntegrity.
// ===========================================================================

fn fts3FunctionArg(pContext: ?*sqlite3_context, zFunc: [*:0]const u8, pVal: ?*sqlite3_value, ppCsr: *?*Fts3Cursor) c_int {
    var rc: c_int = undefined;
    ppCsr.* = @ptrCast(@alignCast(sqlite3_value_pointer(pVal, "fts3cursor")));
    if (ppCsr.* != null) {
        rc = SQLITE_OK;
    } else {
        const zErr = sqlite3_mprintf("illegal first argument to %s", zFunc);
        sqlite3_result_error(pContext, if (zErr) |z| z else @as([*:0]const u8, ""), -1);
        sqlite3_free(zErr);
        rc = SQLITE_ERROR;
    }
    return rc;
}

fn fts3SnippetFunc(pContext: ?*sqlite3_context, nVal: c_int, apVal: ?[*]?*sqlite3_value) callconv(.c) void {
    var pCsr: ?*Fts3Cursor = undefined;
    var zStart: ?[*:0]const u8 = "<b>";
    var zEnd: ?[*:0]const u8 = "</b>";
    var zEllipsis: ?[*:0]const u8 = "<b>...</b>";
    var iCol: c_int = -1;
    var nToken: c_int = 15;
    const av = apVal.?;

    if (nVal > 6) {
        sqlite3_result_error(pContext, "wrong number of arguments to function snippet()", -1);
        return;
    }
    if (fts3FunctionArg(pContext, "snippet", av[0], &pCsr) != 0) return;

    switch (nVal) {
        6 => {
            nToken = sqlite3_value_int(av[5]);
            iCol = sqlite3_value_int(av[4]);
            zEllipsis = sqlite3_value_text(av[3]);
            zEnd = sqlite3_value_text(av[2]);
            zStart = sqlite3_value_text(av[1]);
        },
        5 => {
            iCol = sqlite3_value_int(av[4]);
            zEllipsis = sqlite3_value_text(av[3]);
            zEnd = sqlite3_value_text(av[2]);
            zStart = sqlite3_value_text(av[1]);
        },
        4 => {
            zEllipsis = sqlite3_value_text(av[3]);
            zEnd = sqlite3_value_text(av[2]);
            zStart = sqlite3_value_text(av[1]);
        },
        3 => {
            zEnd = sqlite3_value_text(av[2]);
            zStart = sqlite3_value_text(av[1]);
        },
        2 => {
            zStart = sqlite3_value_text(av[1]);
        },
        else => {},
    }
    if (zEllipsis == null or zEnd == null or zStart == null) {
        sqlite3_result_error_nomem(pContext);
    } else if (nToken == 0) {
        sqlite3_result_text(pContext, "", -1, SQLITE_STATIC);
    } else if (SQLITE_OK == fts3CursorSeek(pContext, pCsr.?)) {
        sqlite3Fts3Snippet(pContext, pCsr.?, zStart, zEnd, zEllipsis, iCol, nToken);
    }
}

fn fts3OffsetsFunc(pContext: ?*sqlite3_context, nVal: c_int, apVal: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = nVal;
    var pCsr: ?*Fts3Cursor = undefined;
    if (fts3FunctionArg(pContext, "offsets", apVal.?[0], &pCsr) != 0) return;
    if (SQLITE_OK == fts3CursorSeek(pContext, pCsr.?)) {
        sqlite3Fts3Offsets(pContext, pCsr.?);
    }
}

fn fts3OptimizeFunc(pContext: ?*sqlite3_context, nVal: c_int, apVal: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = nVal;
    var pCursor: ?*Fts3Cursor = undefined;
    if (fts3FunctionArg(pContext, "optimize", apVal.?[0], &pCursor) != 0) return;
    const p: *Fts3Table = @ptrCast(@alignCast(pCursor.?.base.pVtab.?));

    const rc = sqlite3Fts3Optimize(p);

    switch (rc) {
        SQLITE_OK => sqlite3_result_text(pContext, "Index optimized", -1, SQLITE_STATIC),
        SQLITE_DONE => sqlite3_result_text(pContext, "Index already optimal", -1, SQLITE_STATIC),
        else => sqlite3_result_error_code(pContext, rc),
    }
}

fn fts3MatchinfoFunc(pContext: ?*sqlite3_context, nVal: c_int, apVal: ?[*]?*sqlite3_value) callconv(.c) void {
    var pCsr: ?*Fts3Cursor = undefined;
    if (SQLITE_OK == fts3FunctionArg(pContext, "matchinfo", apVal.?[0], &pCsr)) {
        var zArg: ?[*:0]const u8 = null;
        if (nVal > 1) {
            zArg = sqlite3_value_text(apVal.?[1]);
        }
        sqlite3Fts3Matchinfo(pContext, pCsr.?, zArg);
    }
}

const OverloadFn = ?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void;
const Overloaded = struct {
    zName: [*:0]const u8,
    xFunc: OverloadFn,
};

fn fts3FindFunctionMethod(
    pVtab: *sqlite3_vtab,
    nArg: c_int,
    zName: [*:0]const u8,
    pxFunc: *?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void,
    ppArg: *?*anyopaque,
) callconv(.c) c_int {
    _ = pVtab;
    _ = nArg;
    _ = ppArg;
    const aOverload = [_]Overloaded{
        .{ .zName = "snippet", .xFunc = &fts3SnippetFunc },
        .{ .zName = "offsets", .xFunc = &fts3OffsetsFunc },
        .{ .zName = "optimize", .xFunc = &fts3OptimizeFunc },
        .{ .zName = "matchinfo", .xFunc = &fts3MatchinfoFunc },
    };
    var i: usize = 0;
    while (i < aOverload.len) : (i += 1) {
        if (strcmp(zName, aOverload[i].zName) == 0) {
            pxFunc.* = aOverload[i].xFunc;
            return 1;
        }
    }
    return 0;
}

fn fts3RenameMethod(pVtab: *sqlite3_vtab, zName: [*:0]const u8) callconv(.c) c_int {
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    const db = p.db;
    var rc: c_int = undefined;

    rc = fts3SetHasStat(p);
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts3PendingTermsFlush(p);
    }

    p.bIgnoreSavepoint = 1;

    if (p.zContentTbl == null) {
        fts3DbExec(&rc, db, "ALTER TABLE %Q.'%q_content'  RENAME TO '%q_content';", p.zDb.?, p.zName.?, zName);
    }

    if (p.bHasDocsize != 0) {
        fts3DbExec(&rc, db, "ALTER TABLE %Q.'%q_docsize'  RENAME TO '%q_docsize';", p.zDb.?, p.zName.?, zName);
    }
    if (p.bHasStat != 0) {
        fts3DbExec(&rc, db, "ALTER TABLE %Q.'%q_stat'  RENAME TO '%q_stat';", p.zDb.?, p.zName.?, zName);
    }
    fts3DbExec(&rc, db, "ALTER TABLE %Q.'%q_segments' RENAME TO '%q_segments';", p.zDb.?, p.zName.?, zName);
    fts3DbExec(&rc, db, "ALTER TABLE %Q.'%q_segdir'   RENAME TO '%q_segdir';", p.zDb.?, p.zName.?, zName);

    p.bIgnoreSavepoint = 0;
    return rc;
}

fn fts3SavepointMethod(pVtab: *sqlite3_vtab, iSavepoint: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pTab: *Fts3Table = @ptrCast(@alignCast(pVtab));
    if (config.sqlite_debug) {
        pTab.mxSavepoint = iSavepoint;
    }

    if (pTab.bIgnoreSavepoint == 0) {
        if (fts3HashCount(&pTab.aIndex.?[0].hPending) > 0) {
            const zSql = sqlite3_mprintf("INSERT INTO %Q.%Q(%Q) VALUES('flush')", pTab.zDb.?, pTab.zName.?, pTab.zName.?);
            if (zSql) |zs| {
                pTab.bIgnoreSavepoint = 1;
                rc = sqlite3_exec(pTab.db, zs, null, null, null);
                pTab.bIgnoreSavepoint = 0;
                sqlite3_free(zSql);
            } else {
                rc = SQLITE_NOMEM;
            }
        }
        if (rc == SQLITE_OK) {
            pTab.iSavepoint = iSavepoint + 1;
        }
    }
    return rc;
}

fn fts3ReleaseMethod(pVtab: *sqlite3_vtab, iSavepoint: c_int) callconv(.c) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pVtab));
    if (config.sqlite_debug) {
        pTab.mxSavepoint = iSavepoint - 1;
    }
    pTab.iSavepoint = iSavepoint;
    return SQLITE_OK;
}

fn fts3RollbackToMethod(pVtab: *sqlite3_vtab, iSavepoint: c_int) callconv(.c) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pVtab));
    if (config.sqlite_debug) {
        pTab.mxSavepoint = iSavepoint;
    }
    if ((iSavepoint + 1) <= pTab.iSavepoint) {
        sqlite3Fts3PendingTermsClear(pTab);
    }
    return SQLITE_OK;
}

fn fts3ShadowName(zName: [*:0]const u8) callconv(.c) c_int {
    const azName = [_][*:0]const u8{ "content", "docsize", "segdir", "segments", "stat" };
    var i: usize = 0;
    while (i < azName.len) : (i += 1) {
        if (sqlite3_stricmp(zName, azName[i]) == 0) return 1;
    }
    return 0;
}

fn fts3IntegrityMethod(pVtab: *sqlite3_vtab, zSchema: [*:0]const u8, zTabname: [*:0]const u8, isQuick: c_int, pzErr: *?[*:0]u8) callconv(.c) c_int {
    _ = isQuick;
    const p: *Fts3Table = @ptrCast(@alignCast(pVtab));
    var rc: c_int = SQLITE_OK;
    var bOk: c_int = 0;

    rc = sqlite3Fts3IntegrityCheck(p, &bOk);
    if (rc == SQLITE_ERROR or (rc & 0xFF) == SQLITE_CORRUPT) {
        pzErr.* = sqlite3_mprintf("unable to validate the inverted index for FTS%d table %s.%s: %s", @as(c_int, if (p.bFts4 != 0) 4 else 3), zSchema, zTabname, sqlite3_errstr(rc).?);
        if (pzErr.* != null) rc = SQLITE_OK;
    } else if (rc == SQLITE_OK and bOk == 0) {
        pzErr.* = sqlite3_mprintf("malformed inverted index for FTS%d table %s.%s", @as(c_int, if (p.bFts4 != 0) 4 else 3), zSchema, zTabname);
        if (pzErr.* == null) rc = SQLITE_NOMEM;
    }
    sqlite3Fts3SegmentsClose(p);
    return rc;
}

// ===========================================================================
// The fts3 sqlite3_module (iVersion 4).
// ===========================================================================
const fts3Module: sqlite3_module = .{
    .iVersion = 4,
    .xCreate = &fts3CreateMethod,
    .xConnect = &fts3ConnectMethod,
    .xBestIndex = &fts3BestIndexMethod,
    .xDisconnect = &fts3DisconnectMethod,
    .xDestroy = &fts3DestroyMethod,
    .xOpen = &fts3OpenMethod,
    .xClose = &fts3CloseMethod,
    .xFilter = &fts3FilterMethod,
    .xNext = &fts3NextMethod,
    .xEof = &fts3EofMethod,
    .xColumn = &fts3ColumnMethod,
    .xRowid = &fts3RowidMethod,
    .xUpdate = &fts3UpdateMethod,
    .xBegin = &fts3BeginMethod,
    .xSync = &fts3SyncMethod,
    .xCommit = &fts3CommitMethod,
    .xRollback = &fts3RollbackMethod,
    .xFindFunction = &fts3FindFunctionMethod,
    .xRename = &fts3RenameMethod,
    .xSavepoint = &fts3SavepointMethod,
    .xRelease = &fts3ReleaseMethod,
    .xRollbackTo = &fts3RollbackToMethod,
    .xShadowName = &fts3ShadowName,
    .xIntegrity = &fts3IntegrityMethod,
};

/// Module destructor: drop a reference to the tokenizer hash wrapper.
fn hashDestroy(pv: ?*anyopaque) callconv(.c) void {
    const pHash: *Fts3HashWrapper = @ptrCast(@alignCast(pv.?));
    pHash.nRef -= 1;
    if (pHash.nRef <= 0) {
        sqlite3Fts3HashClear(&pHash.hash);
        sqlite3_free(pHash);
    }
}

// ===========================================================================
// sqlite3Fts3Init — register modules, aux module, tokenizer hash and
// overloaded scalar functions.
// ===========================================================================
export fn sqlite3Fts3Init(db: ?*sqlite3) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var pHash: ?*Fts3HashWrapper = null;
    var pSimple: ?*const sqlite3_tokenizer_module = null;
    var pPorter: ?*const sqlite3_tokenizer_module = null;
    var pUnicode: ?*const sqlite3_tokenizer_module = null;

    sqlite3Fts3UnicodeTokenizer(&pUnicode);

    rc = sqlite3Fts3InitAux(db);
    if (rc != SQLITE_OK) return rc;

    sqlite3Fts3SimpleTokenizerModule(&pSimple);
    sqlite3Fts3PorterTokenizerModule(&pPorter);

    pHash = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(Fts3HashWrapper))));
    if (pHash == null) {
        rc = SQLITE_NOMEM;
    } else {
        sqlite3Fts3HashInit(&pHash.?.hash, FTS3_HASH_STRING, 1);
        pHash.?.nRef = 0;
    }

    if (rc == SQLITE_OK) {
        if (sqlite3Fts3HashInsert(&pHash.?.hash, "simple", 7, @ptrCast(@constCast(pSimple))) != null or
            sqlite3Fts3HashInsert(&pHash.?.hash, "porter", 7, @ptrCast(@constCast(pPorter))) != null or
            sqlite3Fts3HashInsert(&pHash.?.hash, "unicode61", 10, @ptrCast(@constCast(pUnicode))) != null)
        {
            rc = SQLITE_NOMEM;
        }
    }

    if (SQLITE_OK == rc and
        SQLITE_OK == (blk: {
            rc = sqlite3Fts3InitHashTable(db, &pHash.?.hash, "fts3_tokenizer");
            break :blk rc;
        }) and
        SQLITE_OK == (blk: {
            rc = sqlite3_overload_function(db, "snippet", -1);
            break :blk rc;
        }) and
        SQLITE_OK == (blk: {
            rc = sqlite3_overload_function(db, "offsets", 1);
            break :blk rc;
        }) and
        SQLITE_OK == (blk: {
            rc = sqlite3_overload_function(db, "matchinfo", 1);
            break :blk rc;
        }) and
        SQLITE_OK == (blk: {
            rc = sqlite3_overload_function(db, "matchinfo", 2);
            break :blk rc;
        }) and
        SQLITE_OK == (blk: {
            rc = sqlite3_overload_function(db, "optimize", 1);
            break :blk rc;
        }))
    {
        pHash.?.nRef += 1;
        rc = sqlite3_create_module_v2(db, "fts3", &fts3Module, @ptrCast(pHash), &hashDestroy);
        if (rc == SQLITE_OK) {
            pHash.?.nRef += 1;
            rc = sqlite3_create_module_v2(db, "fts4", &fts3Module, @ptrCast(pHash), &hashDestroy);
        }
        if (rc == SQLITE_OK) {
            pHash.?.nRef += 1;
            rc = sqlite3Fts3InitTok(db, @ptrCast(pHash), &hashDestroy);
        }
        return rc;
    }

    if (pHash) |ph| {
        sqlite3Fts3HashClear(&ph.hash);
        sqlite3_free(pHash);
    }
    return rc;
}

// ===========================================================================
// Query evaluator (fts3Eval*) — phrase / NEAR / deferred-token machinery.
// ===========================================================================

fn fts3EvalAllocateReaders(pCsr: *Fts3Cursor, pExpr: ?*Fts3Expr, pnToken: *c_int, pnOr: *c_int, pRc: *c_int) void {
    if (pExpr != null and SQLITE_OK == pRc.*) {
        const e = pExpr.?;
        if (e.eType == FTSQUERY_PHRASE) {
            const ph = e.pPhrase.?;
            const nToken = ph.nToken;
            pnToken.* += nToken;
            var i: c_int = 0;
            while (i < nToken) : (i += 1) {
                const pToken = phraseToken(ph, i);
                const rc = fts3TermSegReaderCursor(pCsr, pToken.z, pToken.n, pToken.isPrefix, &pToken.pSegcsr);
                if (rc != SQLITE_OK) {
                    pRc.* = rc;
                    return;
                }
            }
            ph.iDoclistToken = -1;
        } else {
            pnOr.* += @intFromBool(e.eType == FTSQUERY_OR);
            fts3EvalAllocateReaders(pCsr, e.pLeft, pnToken, pnOr, pRc);
            fts3EvalAllocateReaders(pCsr, e.pRight, pnToken, pnOr, pRc);
        }
    }
}

fn fts3EvalPhraseMergeToken(pTab: *Fts3Table, p: *Fts3Phrase, iToken: c_int, pList: ?[*]u8, nList: c_int) c_int {
    var rc: c_int = SQLITE_OK;

    if (pList == null) {
        sqlite3_free(p.doclist.aAll);
        p.doclist.aAll = null;
        p.doclist.nAll = 0;
    } else if (p.iDoclistToken < 0) {
        p.doclist.aAll = pList;
        p.doclist.nAll = nList;
    } else if (p.doclist.aAll == null) {
        sqlite3_free(pList);
    } else {
        var pLeft: [*]u8 = undefined;
        var pRight: [*]u8 = undefined;
        var nLeft: c_int = undefined;
        var nRight: c_int = undefined;
        var nDiff: c_int = undefined;

        if (p.iDoclistToken < iToken) {
            pLeft = p.doclist.aAll.?;
            nLeft = p.doclist.nAll;
            pRight = pList.?;
            nRight = nList;
            nDiff = iToken - p.iDoclistToken;
        } else {
            pRight = p.doclist.aAll.?;
            nRight = p.doclist.nAll;
            pLeft = pList.?;
            nLeft = nList;
            nDiff = p.iDoclistToken - iToken;
        }

        var pRightV: [*]u8 = pRight;
        rc = fts3DoclistPhraseMerge(pTab.bDescIdx, nDiff, pLeft, nLeft, &pRightV, &nRight);
        sqlite3_free(pLeft);
        p.doclist.aAll = pRightV;
        p.doclist.nAll = nRight;
    }

    if (iToken > p.iDoclistToken) p.iDoclistToken = iToken;
    return rc;
}

fn fts3EvalPhraseLoad(pCsr: *Fts3Cursor, p: *Fts3Phrase) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var rc: c_int = SQLITE_OK;
    var iToken: c_int = 0;
    while (rc == SQLITE_OK and iToken < p.nToken) : (iToken += 1) {
        const pToken = phraseToken(p, iToken);
        if (pToken.pSegcsr != null) {
            var nThis: c_int = 0;
            var pThis: ?[*]u8 = null;
            rc = fts3TermSelect(pTab, pToken, p.iColumn, &nThis, &pThis);
            if (rc == SQLITE_OK) {
                rc = fts3EvalPhraseMergeToken(pTab, p, iToken, pThis, nThis);
            }
        }
    }
    return rc;
}

// SQLITE_DISABLE_FTS4_DEFERRED is NOT defined in this build.
fn fts3EvalDeferredPhrase(pCsr: *Fts3Cursor, pPhrase: *Fts3Phrase) c_int {
    var iToken: c_int = 0;
    var aPoslist: ?[*]u8 = null;
    var nPoslist: c_int = 0;
    var iPrev: c_int = -1;
    const aFree: ?[*]u8 = if (pPhrase.doclist.bFreeList != 0) pPhrase.doclist.pList else null;

    while (iToken < pPhrase.nToken) : (iToken += 1) {
        const pToken = phraseToken(pPhrase, iToken);
        const pDeferred = pToken.pDeferred;

        if (pDeferred) |def| {
            var pList: ?[*]u8 = undefined;
            var nList: c_int = undefined;
            const rc = sqlite3Fts3DeferredTokenList(def, &pList, &nList);
            if (rc != SQLITE_OK) return rc;

            if (pList == null) {
                sqlite3_free(aPoslist);
                sqlite3_free(aFree);
                pPhrase.doclist.pList = null;
                pPhrase.doclist.nList = 0;
                return SQLITE_OK;
            } else if (aPoslist == null) {
                aPoslist = pList;
                nPoslist = nList;
            } else {
                var aOut: [*]u8 = pList.?;
                var p1: [*]u8 = aPoslist.?;
                var p2: [*]u8 = aOut;

                _ = fts3PoslistPhraseMerge(&aOut, iToken - iPrev, 0, 1, &p1, &p2);
                sqlite3_free(aPoslist);
                aPoslist = pList;
                nPoslist = @intCast(@intFromPtr(aOut) - @intFromPtr(aPoslist.?));
                if (nPoslist == 0) {
                    sqlite3_free(aPoslist);
                    sqlite3_free(aFree);
                    pPhrase.doclist.pList = null;
                    pPhrase.doclist.nList = 0;
                    return SQLITE_OK;
                }
            }
            iPrev = iToken;
        }
    }

    if (iPrev >= 0) {
        const nMaxUndeferred = pPhrase.iDoclistToken;
        if (nMaxUndeferred < 0) {
            pPhrase.doclist.pList = aPoslist;
            pPhrase.doclist.nList = nPoslist;
            pPhrase.doclist.iDocid = pCsr.iPrevId;
            pPhrase.doclist.bFreeList = 1;
        } else {
            var nDistance: c_int = undefined;
            var p1: [*]u8 = undefined;
            var p2: [*]u8 = undefined;
            var aOut: [*]u8 = undefined;

            if (nMaxUndeferred > iPrev) {
                p1 = aPoslist.?;
                p2 = pPhrase.doclist.pList.?;
                nDistance = nMaxUndeferred - iPrev;
            } else {
                p1 = pPhrase.doclist.pList.?;
                p2 = aPoslist.?;
                nDistance = iPrev - nMaxUndeferred;
            }

            const aOutOpt: ?[*]u8 = @ptrCast(sqlite3Fts3MallocZero(@as(i64, nPoslist) + FTS3_BUFFER_PADDING));
            if (aOutOpt == null) {
                sqlite3_free(aPoslist);
                return SQLITE_NOMEM;
            }
            aOut = aOutOpt.?;

            pPhrase.doclist.pList = aOut;
            if (fts3PoslistPhraseMerge(&aOut, nDistance, 0, 1, &p1, &p2) != 0) {
                pPhrase.doclist.bFreeList = 1;
                pPhrase.doclist.nList = @intCast(@intFromPtr(aOut) - @intFromPtr(pPhrase.doclist.pList.?));
            } else {
                sqlite3_free(aOut);
                pPhrase.doclist.pList = null;
                pPhrase.doclist.nList = 0;
            }
            sqlite3_free(aPoslist);
        }
    }

    if (@intFromPtr(pPhrase.doclist.pList) != @intFromPtr(aFree)) sqlite3_free(aFree);
    return SQLITE_OK;
}

fn fts3EvalPhraseStart(pCsr: *Fts3Cursor, bOptOk: c_int, p: *Fts3Phrase) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var rc: c_int = SQLITE_OK;
    var i: c_int = undefined;

    var bHaveIncr: c_int = 0;
    var bIncrOk: c_int = @intFromBool(bOptOk != 0 and
        pCsr.bDesc == pTab.bDescIdx and
        p.nToken <= MAX_INCR_PHRASE_TOKENS and p.nToken > 0 and
        (if (config.sqlite_debug or config.sqlite_test) (pTab.bNoIncrDoclist == 0) else true));
    i = 0;
    while (bIncrOk == 1 and i < p.nToken) : (i += 1) {
        const pToken = phraseToken(p, i);
        if (pToken.bFirst != 0 or (pToken.pSegcsr != null and pToken.pSegcsr.?.bLookup == 0)) {
            bIncrOk = 0;
        }
        if (pToken.pSegcsr != null) bHaveIncr = 1;
    }

    if (bIncrOk != 0 and bHaveIncr != 0) {
        const iCol: c_int = if (p.iColumn >= pTab.nColumn) -1 else p.iColumn;
        i = 0;
        while (rc == SQLITE_OK and i < p.nToken) : (i += 1) {
            const pToken = phraseToken(p, i);
            if (pToken.pSegcsr) |seg| {
                rc = sqlite3Fts3MsrIncrStart(pTab, seg, iCol, pToken.z, pToken.n);
            }
        }
        p.bIncr = 1;
    } else {
        rc = fts3EvalPhraseLoad(pCsr, p);
        p.bIncr = 0;
    }

    return rc;
}

export fn sqlite3Fts3DoclistPrev(bDescIdx: c_int, aDoclist: [*]u8, nDoclist: c_int, ppIter: *?[*]u8, piDocid: *i64, pnList: *c_int, pbEof: *u8) callconv(.c) void {
    var p: ?[*]u8 = ppIter.*;

    if (p == null) {
        var iDocid: i64 = 0;
        var pNext: ?[*]u8 = null;
        var pDocid: [*]u8 = aDoclist;
        const pEnd: [*]u8 = aDoclist + @as(usize, @intCast(nDoclist));
        var iMul: i64 = 1;

        while (@intFromPtr(pDocid) < @intFromPtr(pEnd)) {
            var iDelta: i64 = undefined;
            pDocid += @intCast(sqlite3Fts3GetVarint(pDocid, &iDelta));
            iDocid += (iMul * iDelta);
            pNext = pDocid;
            fts3PoslistCopy(null, &pDocid);
            while (@intFromPtr(pDocid) < @intFromPtr(pEnd) and pDocid[0] == 0) pDocid += 1;
            iMul = if (bDescIdx != 0) -1 else 1;
        }

        pnList.* = @intCast(@intFromPtr(pEnd) - @intFromPtr(pNext.?));
        ppIter.* = pNext;
        piDocid.* = iDocid;
    } else {
        const iMul: i64 = if (bDescIdx != 0) -1 else 1;
        var iDelta: i64 = undefined;
        var pv = p.?;
        fts3GetReverseVarint(&pv, aDoclist, &iDelta);
        p = pv;
        piDocid.* -= (iMul * iDelta);

        if (@intFromPtr(p.?) == @intFromPtr(aDoclist)) {
            pbEof.* = 1;
        } else {
            const pSave = p.?;
            var pv2 = p.?;
            fts3ReversePoslist(aDoclist, &pv2);
            p = pv2;
            pnList.* = @intCast(@intFromPtr(pSave) - @intFromPtr(p.?));
        }
        ppIter.* = p;
    }
}

export fn sqlite3Fts3DoclistNext(bDescIdx: c_int, aDoclist: [*]u8, nDoclist: c_int, ppIter: *?[*]u8, piDocid: *i64, pbEof: *u8) callconv(.c) void {
    var p: ?[*]u8 = ppIter.*;
    const pEnd: [*]u8 = aDoclist + @as(usize, @intCast(nDoclist));

    if (p == null) {
        var pv: [*]u8 = aDoclist;
        pv += @intCast(sqlite3Fts3GetVarint(pv, piDocid));
        p = pv;
    } else {
        var pv = p.?;
        fts3PoslistCopy(null, &pv);
        while (@intFromPtr(pv) < @intFromPtr(pEnd) and pv[0] == 0) pv += 1;
        if (@intFromPtr(pv) >= @intFromPtr(pEnd)) {
            pbEof.* = 1;
        } else {
            var iVar: i64 = undefined;
            pv += @intCast(sqlite3Fts3GetVarint(pv, &iVar));
            piDocid.* += (@as(i64, if (bDescIdx != 0) -1 else 1) * iVar);
        }
        p = pv;
    }

    ppIter.* = p;
}

fn fts3EvalDlPhraseNext(pTab: *Fts3Table, pDL: *Fts3Doclist, pbEof: *u8) void {
    var pIter: ?[*]u8 = undefined;
    var pEnd: [*]u8 = undefined;

    if (pDL.pNextDocid) |nx| {
        pIter = nx;
    } else {
        pIter = pDL.aAll;
    }

    pEnd = pDL.aAll.? + @as(usize, @intCast(pDL.nAll));
    if (pIter == null or @intFromPtr(pIter.?) >= @intFromPtr(pEnd)) {
        pbEof.* = 1;
    } else {
        var iDelta: i64 = undefined;
        var pv = pIter.?;
        pv += @intCast(sqlite3Fts3GetVarint(pv, &iDelta));
        if (pTab.bDescIdx == 0 or pDL.pNextDocid == null) {
            pDL.iDocid += iDelta;
        } else {
            pDL.iDocid -= iDelta;
        }
        pDL.pList = pv;
        fts3PoslistCopy(null, &pv);
        pDL.nList = @intCast(@intFromPtr(pv) - @intFromPtr(pDL.pList.?));

        while (@intFromPtr(pv) < @intFromPtr(pEnd) and pv[0] == 0) pv += 1;

        pDL.pNextDocid = pv;
        pbEof.* = 0;
    }
}

const TokenDoclist = extern struct {
    bIgnore: c_int,
    iDocid: i64,
    pList: ?[*]u8,
    nList: c_int,
};

fn incrPhraseTokenNext(pTab: *Fts3Table, pPhrase: *Fts3Phrase, iToken: c_int, p: *TokenDoclist, pbEof: *u8) c_int {
    var rc: c_int = SQLITE_OK;

    if (pPhrase.iDoclistToken == iToken) {
        fts3EvalDlPhraseNext(pTab, &pPhrase.doclist, pbEof);
        p.pList = pPhrase.doclist.pList;
        p.nList = pPhrase.doclist.nList;
        p.iDocid = pPhrase.doclist.iDocid;
    } else {
        const pToken = phraseToken(pPhrase, iToken);
        if (pToken.pSegcsr) |seg| {
            rc = sqlite3Fts3MsrIncrNext(pTab, seg, &p.iDocid, &p.pList, &p.nList);
            if (p.pList == null) pbEof.* = 1;
        } else {
            p.bIgnore = 1;
        }
    }

    return rc;
}

fn fts3EvalIncrPhraseNext(pCsr: *Fts3Cursor, p: *Fts3Phrase, pbEof: *u8) c_int {
    var rc: c_int = SQLITE_OK;
    const pDL = &p.doclist;
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var bEof: u8 = 0;

    if (p.nToken == 1) {
        rc = sqlite3Fts3MsrIncrNext(pTab, phraseToken(p, 0).pSegcsr.?, &pDL.iDocid, &pDL.pList, &pDL.nList);
        if (pDL.pList == null) bEof = 1;
    } else {
        const bDescDoclist = pCsr.bDesc;
        var a: [MAX_INCR_PHRASE_TOKENS]TokenDoclist = undefined;
        @memset(@as([*]u8, @ptrCast(&a))[0..@sizeOf(@TypeOf(a))], 0);

        while (bEof == 0) {
            var bMaxSet: c_int = 0;
            var iMax: i64 = 0;
            var i: c_int = undefined;

            i = 0;
            while (rc == SQLITE_OK and i < p.nToken and bEof == 0) : (i += 1) {
                rc = incrPhraseTokenNext(pTab, p, i, &a[@intCast(i)], &bEof);
                if (a[@intCast(i)].bIgnore == 0 and (bMaxSet == 0 or docidCmp(bDescDoclist, iMax, a[@intCast(i)].iDocid) < 0)) {
                    iMax = a[@intCast(i)].iDocid;
                    bMaxSet = 1;
                }
            }

            i = 0;
            while (i < p.nToken) : (i += 1) {
                while (rc == SQLITE_OK and bEof == 0 and a[@intCast(i)].bIgnore == 0 and docidCmp(bDescDoclist, a[@intCast(i)].iDocid, iMax) < 0) {
                    rc = incrPhraseTokenNext(pTab, p, i, &a[@intCast(i)], &bEof);
                    if (docidCmp(bDescDoclist, a[@intCast(i)].iDocid, iMax) > 0) {
                        iMax = a[@intCast(i)].iDocid;
                        i = 0;
                    }
                }
            }

            if (bEof == 0) {
                var nList: c_int = 0;
                const nByte: c_int = a[@intCast(p.nToken - 1)].nList;
                const aDoclistOpt: ?[*]u8 = @ptrCast(sqlite3_malloc64(@intCast(@as(i64, nByte) + FTS3_BUFFER_PADDING)));
                if (aDoclistOpt == null) return SQLITE_NOMEM;
                const aDoclist = aDoclistOpt.?;
                _ = memcpy(aDoclist, a[@intCast(p.nToken - 1)].pList, @intCast(nByte + 1));
                @memset((aDoclist + @as(usize, @intCast(nByte)))[0..@intCast(FTS3_BUFFER_PADDING)], 0);

                var ix: c_int = 0;
                while (ix < (p.nToken - 1)) : (ix += 1) {
                    if (a[@intCast(ix)].bIgnore == 0) {
                        var pL: [*]u8 = a[@intCast(ix)].pList.?;
                        var pR: [*]u8 = aDoclist;
                        var pOut: [*]u8 = aDoclist;
                        const nDist = p.nToken - 1 - ix;
                        const res = fts3PoslistPhraseMerge(&pOut, nDist, 0, 1, &pL, &pR);
                        if (res == 0) break;
                        nList = @intCast(@intFromPtr(pOut) - @intFromPtr(aDoclist));
                    }
                }
                if (ix == (p.nToken - 1)) {
                    pDL.iDocid = iMax;
                    pDL.pList = aDoclist;
                    pDL.nList = nList;
                    pDL.bFreeList = 1;
                    break;
                }
                sqlite3_free(aDoclist);
            }
        }
    }

    pbEof.* = bEof;
    return rc;
}

fn fts3EvalPhraseNext(pCsr: *Fts3Cursor, p: *Fts3Phrase, pbEof: *u8) c_int {
    var rc: c_int = SQLITE_OK;
    const pDL = &p.doclist;
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));

    if (p.bIncr != 0) {
        rc = fts3EvalIncrPhraseNext(pCsr, p, pbEof);
    } else if (pCsr.bDesc != pTab.bDescIdx and pDL.nAll != 0) {
        sqlite3Fts3DoclistPrev(pTab.bDescIdx, pDL.aAll.?, pDL.nAll, &pDL.pNextDocid, &pDL.iDocid, &pDL.nList, pbEof);
        pDL.pList = pDL.pNextDocid;
    } else {
        fts3EvalDlPhraseNext(pTab, pDL, pbEof);
    }

    return rc;
}

fn fts3EvalStartReaders(pCsr: *Fts3Cursor, pExpr: ?*Fts3Expr, pRc: *c_int) void {
    if (pExpr != null and SQLITE_OK == pRc.*) {
        const e = pExpr.?;
        if (e.eType == FTSQUERY_PHRASE) {
            const nToken = e.pPhrase.?.nToken;
            if (nToken != 0) {
                var i: c_int = 0;
                while (i < nToken) : (i += 1) {
                    if (phraseToken(e.pPhrase.?, i).pDeferred == null) break;
                }
                e.bDeferred = @intFromBool(i == nToken);
            }
            pRc.* = fts3EvalPhraseStart(pCsr, 1, e.pPhrase.?);
        } else {
            fts3EvalStartReaders(pCsr, e.pLeft, pRc);
            fts3EvalStartReaders(pCsr, e.pRight, pRc);
            e.bDeferred = @intFromBool(e.pLeft.?.bDeferred != 0 and e.pRight.?.bDeferred != 0);
        }
    }
}

const Fts3TokenAndCost = extern struct {
    pPhrase: ?*Fts3Phrase,
    iToken: c_int,
    pToken: ?*Fts3PhraseToken,
    pRoot: ?*Fts3Expr,
    nOvfl: c_int,
    iCol: c_int,
};

fn fts3EvalTokenCosts(pCsr: *Fts3Cursor, pRoot_in: ?*Fts3Expr, pExpr: *Fts3Expr, ppTC: *[*]Fts3TokenAndCost, ppOr: *[*]?*Fts3Expr, pRc: *c_int) void {
    var pRoot = pRoot_in;
    if (pRc.* == SQLITE_OK) {
        if (pExpr.eType == FTSQUERY_PHRASE) {
            const pPhrase = pExpr.pPhrase.?;
            var i: c_int = 0;
            while (pRc.* == SQLITE_OK and i < pPhrase.nToken) : (i += 1) {
                const pTC = &ppTC.*[0];
                ppTC.* += 1;
                pTC.pPhrase = pPhrase;
                pTC.iToken = i;
                pTC.pRoot = pRoot;
                pTC.pToken = phraseToken(pPhrase, i);
                pTC.iCol = pPhrase.iColumn;
                pRc.* = sqlite3Fts3MsrOvfl(pCsr, pTC.pToken.?.pSegcsr, &pTC.nOvfl);
            }
        } else if (pExpr.eType != FTSQUERY_NOT) {
            if (pExpr.eType == FTSQUERY_OR) {
                pRoot = pExpr.pLeft;
                ppOr.*[0] = pRoot;
                ppOr.* += 1;
            }
            fts3EvalTokenCosts(pCsr, pRoot, pExpr.pLeft.?, ppTC, ppOr, pRc);
            if (pExpr.eType == FTSQUERY_OR) {
                pRoot = pExpr.pRight;
                ppOr.*[0] = pRoot;
                ppOr.* += 1;
            }
            fts3EvalTokenCosts(pCsr, pRoot, pExpr.pRight.?, ppTC, ppOr, pRc);
        }
    }
}

fn fts3EvalAverageDocsize(pCsr: *Fts3Cursor, pnPage: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (pCsr.nRowAvg == 0) {
        const p: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
        var pStmt: ?*sqlite3_stmt = undefined;
        var nDoc: i64 = 0;
        var nByte: i64 = 0;

        rc = sqlite3Fts3SelectDoctotal(p, &pStmt);
        if (rc != SQLITE_OK) return rc;
        const aOpt: ?[*]const u8 = @ptrCast(sqlite3_column_blob(pStmt, 0));
        if (aOpt) |a0| {
            var a: [*]const u8 = a0;
            const pEnd: [*]const u8 = a0 + @as(usize, @intCast(sqlite3_column_bytes(pStmt, 0)));
            a += @intCast(sqlite3Fts3GetVarintBounded(a, pEnd, &nDoc));
            while (@intFromPtr(a) < @intFromPtr(pEnd)) {
                a += @intCast(sqlite3Fts3GetVarintBounded(a, pEnd, &nByte));
            }
        }
        if (nDoc == 0 or nByte == 0) {
            _ = sqlite3_reset(pStmt);
            return FTS_CORRUPT_VTAB();
        }

        pCsr.nDoc = nDoc;
        pCsr.nRowAvg = @intCast(@divTrunc(@divTrunc(nByte, nDoc) + p.nPgsz, p.nPgsz));
        rc = sqlite3_reset(pStmt);
    }

    pnPage.* = pCsr.nRowAvg;
    return rc;
}

fn fts3EvalSelectDeferred(pCsr: *Fts3Cursor, pRoot: ?*Fts3Expr, aTC: [*]Fts3TokenAndCost, nTC: c_int) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var nDocSize: c_int = 0;
    var rc: c_int = SQLITE_OK;
    var ii: c_int = undefined;
    var nOvfl: c_int = 0;
    var nToken: c_int = 0;
    var nMinEst: c_int = 0;
    var nLoad4: c_int = 1;

    if (pTab.zContentTbl != null) {
        return SQLITE_OK;
    }

    ii = 0;
    while (ii < nTC) : (ii += 1) {
        if (aTC[@intCast(ii)].pRoot == pRoot) {
            nOvfl += aTC[@intCast(ii)].nOvfl;
            nToken += 1;
        }
    }
    if (nOvfl == 0 or nToken < 2) return SQLITE_OK;

    rc = fts3EvalAverageDocsize(pCsr, &nDocSize);

    ii = 0;
    while (ii < nToken and rc == SQLITE_OK) : (ii += 1) {
        var iTC: c_int = undefined;
        var pTC: ?*Fts3TokenAndCost = null;

        iTC = 0;
        while (iTC < nTC) : (iTC += 1) {
            if (aTC[@intCast(iTC)].pToken != null and aTC[@intCast(iTC)].pRoot == pRoot and (pTC == null or aTC[@intCast(iTC)].nOvfl < pTC.?.nOvfl)) {
                pTC = &aTC[@intCast(iTC)];
            }
        }

        if (ii != 0 and pTC.?.nOvfl >= @divTrunc(nMinEst + @divTrunc(nLoad4, 4) - 1, @divTrunc(nLoad4, 4)) * nDocSize) {
            const pToken = pTC.?.pToken.?;
            rc = sqlite3Fts3DeferToken(pCsr, pToken, pTC.?.iCol);
            fts3SegReaderCursorFree(pToken.pSegcsr);
            pToken.pSegcsr = null;
        } else {
            if (ii < 12) nLoad4 = nLoad4 * 4;

            if (ii == 0 or (pTC.?.pPhrase.?.nToken > 1 and ii != nToken - 1)) {
                const pToken = pTC.?.pToken.?;
                var nList: c_int = 0;
                var pList: ?[*]u8 = null;
                rc = fts3TermSelect(pTab, pToken, pTC.?.iCol, &nList, &pList);
                if (rc == SQLITE_OK) {
                    rc = fts3EvalPhraseMergeToken(pTab, pTC.?.pPhrase.?, pTC.?.iToken, pList, nList);
                }
                if (rc == SQLITE_OK) {
                    const nCount = fts3DoclistCountDocids(pTC.?.pPhrase.?.doclist.aAll, pTC.?.pPhrase.?.doclist.nAll);
                    if (ii == 0 or nCount < nMinEst) nMinEst = nCount;
                }
            }
        }
        pTC.?.pToken = null;
    }

    return rc;
}

fn fts3EvalStart(pCsr: *Fts3Cursor) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var rc: c_int = SQLITE_OK;
    var nToken: c_int = 0;
    var nOr: c_int = 0;

    fts3EvalAllocateReaders(pCsr, pCsr.pExpr, &nToken, &nOr, &rc);

    // SQLITE_DISABLE_FTS4_DEFERRED is NOT defined in this build.
    if (rc == SQLITE_OK and nToken > 1 and pTab.bFts4 != 0) {
        const aTC: ?[*]Fts3TokenAndCost = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(@as(i64, @sizeOf(Fts3TokenAndCost)) * nToken + @as(i64, @sizeOf(usize)) * nOr * 2))));

        if (aTC == null) {
            rc = SQLITE_NOMEM;
        } else {
            const apOr: [*]?*Fts3Expr = @ptrCast(@alignCast(&aTC.?[@intCast(nToken)]));
            var ii: c_int = undefined;
            var pTC: [*]Fts3TokenAndCost = aTC.?;
            var ppOr: [*]?*Fts3Expr = apOr;

            fts3EvalTokenCosts(pCsr, null, pCsr.pExpr.?, &pTC, &ppOr, &rc);
            nToken = @intCast((@intFromPtr(pTC) - @intFromPtr(aTC.?)) / @sizeOf(Fts3TokenAndCost));
            nOr = @intCast((@intFromPtr(ppOr) - @intFromPtr(apOr)) / @sizeOf(usize));

            if (rc == SQLITE_OK) {
                rc = fts3EvalSelectDeferred(pCsr, null, aTC.?, nToken);
                ii = 0;
                while (rc == SQLITE_OK and ii < nOr) : (ii += 1) {
                    rc = fts3EvalSelectDeferred(pCsr, apOr[@intCast(ii)], aTC.?, nToken);
                }
            }

            sqlite3_free(aTC);
        }
    }

    fts3EvalStartReaders(pCsr, pCsr.pExpr, &rc);
    return rc;
}

fn fts3EvalInvalidatePoslist(pPhrase: *Fts3Phrase) void {
    if (pPhrase.doclist.bFreeList != 0) {
        sqlite3_free(pPhrase.doclist.pList);
    }
    pPhrase.doclist.pList = null;
    pPhrase.doclist.nList = 0;
    pPhrase.doclist.bFreeList = 0;
}

fn fts3EvalNearTrim(nNear: c_int, aTmp: [*]u8, paPoslist: *[*]u8, pnToken: *c_int, pPhrase: *Fts3Phrase) c_int {
    const nParam1 = nNear + pPhrase.nToken;
    const nParam2 = nNear + pnToken.*;
    var nNew: c_int = undefined;
    var p2: [*]u8 = undefined;
    var pOut: [*]u8 = undefined;
    var res: c_int = undefined;

    pOut = pPhrase.doclist.pList.?;
    p2 = pOut;
    res = fts3PoslistNearMerge(&pOut, aTmp, nParam1, nParam2, paPoslist, &p2);
    if (res != 0) {
        nNew = @as(c_int, @intCast(@intFromPtr(pOut) - @intFromPtr(pPhrase.doclist.pList.?))) - 1;
        if (nNew >= 0 and nNew <= pPhrase.doclist.nList) {
            @memset((pPhrase.doclist.pList.? + @as(usize, @intCast(nNew)))[0..@intCast(pPhrase.doclist.nList - nNew)], 0);
            pPhrase.doclist.nList = nNew;
        }
        paPoslist.* = pPhrase.doclist.pList.?;
        pnToken.* = pPhrase.nToken;
    }

    return res;
}

fn fts3EvalNextRow(pCsr: *Fts3Cursor, pExpr: *Fts3Expr, pRc: *c_int) void {
    if (pRc.* == SQLITE_OK and pExpr.bEof == 0) {
        const bDescDoclist = pCsr.bDesc;
        pExpr.bStart = 1;

        switch (pExpr.eType) {
            FTSQUERY_NEAR, FTSQUERY_AND => {
                const pLeft = pExpr.pLeft.?;
                const pRight = pExpr.pRight.?;

                if (pLeft.bDeferred != 0) {
                    fts3EvalNextRow(pCsr, pRight, pRc);
                    pExpr.iDocid = pRight.iDocid;
                    pExpr.bEof = pRight.bEof;
                } else if (pRight.bDeferred != 0) {
                    fts3EvalNextRow(pCsr, pLeft, pRc);
                    pExpr.iDocid = pLeft.iDocid;
                    pExpr.bEof = pLeft.bEof;
                } else {
                    fts3EvalNextRow(pCsr, pLeft, pRc);
                    fts3EvalNextRow(pCsr, pRight, pRc);
                    while (pLeft.bEof == 0 and pRight.bEof == 0 and pRc.* == SQLITE_OK) {
                        const iDiff = docidCmp(bDescDoclist, pLeft.iDocid, pRight.iDocid);
                        if (iDiff == 0) break;
                        if (iDiff < 0) {
                            fts3EvalNextRow(pCsr, pLeft, pRc);
                        } else {
                            fts3EvalNextRow(pCsr, pRight, pRc);
                        }
                    }
                    pExpr.iDocid = pLeft.iDocid;
                    pExpr.bEof = @intFromBool(pLeft.bEof != 0 or pRight.bEof != 0);
                    if (pExpr.eType == FTSQUERY_NEAR and pExpr.bEof != 0) {
                        if (pRight.pPhrase.?.doclist.aAll != null) {
                            const pDl = &pRight.pPhrase.?.doclist;
                            while (pRc.* == SQLITE_OK and pRight.bEof == 0) {
                                _ = memset(pDl.pList, 0, @intCast(pDl.nList));
                                fts3EvalNextRow(pCsr, pRight, pRc);
                            }
                        }
                        if (pLeft.pPhrase != null and pLeft.pPhrase.?.doclist.aAll != null) {
                            const pDl = &pLeft.pPhrase.?.doclist;
                            while (pRc.* == SQLITE_OK and pLeft.bEof == 0) {
                                _ = memset(pDl.pList, 0, @intCast(pDl.nList));
                                fts3EvalNextRow(pCsr, pLeft, pRc);
                            }
                        }
                        pRight.bEof = 1;
                        pLeft.bEof = 1;
                    }
                }
            },

            FTSQUERY_OR => {
                const pLeft = pExpr.pLeft.?;
                const pRight = pExpr.pRight.?;
                var iCmp = docidCmp(bDescDoclist, pLeft.iDocid, pRight.iDocid);

                if (pRight.bEof != 0 or (pLeft.bEof == 0 and iCmp < 0)) {
                    fts3EvalNextRow(pCsr, pLeft, pRc);
                } else if (pLeft.bEof != 0 or iCmp > 0) {
                    fts3EvalNextRow(pCsr, pRight, pRc);
                } else {
                    fts3EvalNextRow(pCsr, pLeft, pRc);
                    fts3EvalNextRow(pCsr, pRight, pRc);
                }

                pExpr.bEof = @intFromBool(pLeft.bEof != 0 and pRight.bEof != 0);
                iCmp = docidCmp(bDescDoclist, pLeft.iDocid, pRight.iDocid);
                if (pRight.bEof != 0 or (pLeft.bEof == 0 and iCmp < 0)) {
                    pExpr.iDocid = pLeft.iDocid;
                } else {
                    pExpr.iDocid = pRight.iDocid;
                }
            },

            FTSQUERY_NOT => {
                const pLeft = pExpr.pLeft.?;
                const pRight = pExpr.pRight.?;

                if (pRight.bStart == 0) {
                    fts3EvalNextRow(pCsr, pRight, pRc);
                }

                fts3EvalNextRow(pCsr, pLeft, pRc);
                if (pLeft.bEof == 0) {
                    while (pRc.* == 0 and pRight.bEof == 0 and docidCmp(bDescDoclist, pLeft.iDocid, pRight.iDocid) > 0) {
                        fts3EvalNextRow(pCsr, pRight, pRc);
                    }
                }
                pExpr.iDocid = pLeft.iDocid;
                pExpr.bEof = pLeft.bEof;
            },

            else => {
                const pPhrase = pExpr.pPhrase.?;
                fts3EvalInvalidatePoslist(pPhrase);
                pRc.* = fts3EvalPhraseNext(pCsr, pPhrase, &pExpr.bEof);
                pExpr.iDocid = pPhrase.doclist.iDocid;
            },
        }
    }
}

fn fts3EvalNearTest(pExpr: *Fts3Expr, pRc: *c_int) c_int {
    var res: c_int = 1;

    if (pRc.* == SQLITE_OK and pExpr.eType == FTSQUERY_NEAR and (pExpr.pParent == null or pExpr.pParent.?.eType != FTSQUERY_NEAR)) {
        var p: *Fts3Expr = pExpr;
        var nTmp: i64 = 0;

        while (p.pLeft != null) : (p = p.pLeft.?) {
            nTmp += p.pRight.?.pPhrase.?.doclist.nList;
        }
        nTmp += p.pPhrase.?.doclist.nList;
        const aTmpOpt: ?[*]u8 = @ptrCast(sqlite3_malloc64(@intCast(nTmp * 2 + FTS3_VARINT_MAX)));
        if (aTmpOpt == null) {
            pRc.* = SQLITE_NOMEM;
            res = 0;
        } else {
            const aTmp = aTmpOpt.?;
            var aPoslist: [*]u8 = p.pPhrase.?.doclist.pList.?;
            var nToken: c_int = p.pPhrase.?.nToken;

            var pp: ?*Fts3Expr = p.pParent;
            while (res != 0 and pp != null and pp.?.eType == FTSQUERY_NEAR) : (pp = pp.?.pParent) {
                const pPhrase = pp.?.pRight.?.pPhrase.?;
                const nNear = pp.?.nNear;
                var ap = aPoslist;
                res = fts3EvalNearTrim(nNear, aTmp, &ap, &nToken, pPhrase);
                aPoslist = ap;
            }

            aPoslist = pExpr.pRight.?.pPhrase.?.doclist.pList.?;
            nToken = pExpr.pRight.?.pPhrase.?.nToken;
            var p2: ?*Fts3Expr = pExpr.pLeft;
            while (p2 != null and res != 0) : (p2 = p2.?.pLeft) {
                const nNear = p2.?.pParent.?.nNear;
                const pPhrase: *Fts3Phrase = if (p2.?.eType == FTSQUERY_NEAR) p2.?.pRight.?.pPhrase.? else p2.?.pPhrase.?;
                var ap = aPoslist;
                res = fts3EvalNearTrim(nNear, aTmp, &ap, &nToken, pPhrase);
                aPoslist = ap;
            }
        }

        sqlite3_free(aTmpOpt);
    }

    return res;
}

fn fts3EvalTestExpr(pCsr: *Fts3Cursor, pExpr: *Fts3Expr, pRc: *c_int) c_int {
    var bHit: c_int = 1;
    if (pRc.* == SQLITE_OK) {
        switch (pExpr.eType) {
            FTSQUERY_NEAR, FTSQUERY_AND => {
                bHit = @intFromBool(fts3EvalTestExpr(pCsr, pExpr.pLeft.?, pRc) != 0 and
                    fts3EvalTestExpr(pCsr, pExpr.pRight.?, pRc) != 0 and
                    fts3EvalNearTest(pExpr, pRc) != 0);

                if (bHit == 0 and pExpr.eType == FTSQUERY_NEAR and (pExpr.pParent == null or pExpr.pParent.?.eType != FTSQUERY_NEAR)) {
                    var p: *Fts3Expr = pExpr;
                    while (p.pPhrase == null) : (p = p.pLeft.?) {
                        if (p.pRight.?.iDocid == pCsr.iPrevId) {
                            fts3EvalInvalidatePoslist(p.pRight.?.pPhrase.?);
                        }
                    }
                    if (p.iDocid == pCsr.iPrevId) {
                        fts3EvalInvalidatePoslist(p.pPhrase.?);
                    }
                }
            },

            FTSQUERY_OR => {
                const bHit1 = fts3EvalTestExpr(pCsr, pExpr.pLeft.?, pRc);
                const bHit2 = fts3EvalTestExpr(pCsr, pExpr.pRight.?, pRc);
                bHit = @intFromBool(bHit1 != 0 or bHit2 != 0);
            },

            FTSQUERY_NOT => {
                bHit = @intFromBool(fts3EvalTestExpr(pCsr, pExpr.pLeft.?, pRc) != 0 and
                    fts3EvalTestExpr(pCsr, pExpr.pRight.?, pRc) == 0);
            },

            else => {
                // SQLITE_DISABLE_FTS4_DEFERRED is NOT defined.
                if (pCsr.pDeferred != null and (pExpr.bDeferred != 0 or (pExpr.iDocid == pCsr.iPrevId and pExpr.pPhrase.?.doclist.pList != null))) {
                    const pPhrase = pExpr.pPhrase.?;
                    if (pExpr.bDeferred != 0) {
                        fts3EvalInvalidatePoslist(pPhrase);
                    }
                    pRc.* = fts3EvalDeferredPhrase(pCsr, pPhrase);
                    bHit = @intFromBool(pPhrase.doclist.pList != null);
                    pExpr.iDocid = pCsr.iPrevId;
                } else {
                    bHit = @intFromBool(pExpr.bEof == 0 and pExpr.iDocid == pCsr.iPrevId and pExpr.pPhrase.?.doclist.nList > 0);
                }
            },
        }
    }
    return bHit;
}

export fn sqlite3Fts3EvalTestDeferred(pCsr: *Fts3Cursor, pRc: *c_int) callconv(.c) c_int {
    var rc: c_int = pRc.*;
    var bMiss: c_int = 0;
    if (rc == SQLITE_OK) {
        if (pCsr.pDeferred != null) {
            rc = fts3CursorSeek(null, pCsr);
            if (rc == SQLITE_OK) {
                rc = sqlite3Fts3CacheDeferredDoclists(pCsr);
            }
        }
        bMiss = @intFromBool(0 == fts3EvalTestExpr(pCsr, pCsr.pExpr.?, &rc));
        sqlite3Fts3FreeDeferredDoclists(pCsr);
        pRc.* = rc;
    }
    return @intFromBool(rc == SQLITE_OK and bMiss != 0);
}

fn fts3EvalNext(pCsr: *Fts3Cursor) c_int {
    var rc: c_int = SQLITE_OK;
    const pExpr = pCsr.pExpr;
    if (pExpr == null) {
        pCsr.isEof = 1;
    } else {
        const e = pExpr.?;
        while (true) {
            if (pCsr.isRequireSeek == 0) {
                _ = sqlite3_reset(pCsr.pStmt);
            }
            fts3EvalNextRow(pCsr, e, &rc);
            pCsr.isEof = e.bEof;
            pCsr.isRequireSeek = 1;
            pCsr.isMatchinfoNeeded = 1;
            pCsr.iPrevId = e.iDocid;
            if (!(pCsr.isEof == 0 and sqlite3Fts3EvalTestDeferred(pCsr, &rc) != 0)) break;
        }
    }

    if (rc == SQLITE_OK and ((pCsr.bDesc == 0 and pCsr.iPrevId > pCsr.iMaxDocid) or (pCsr.bDesc != 0 and pCsr.iPrevId < pCsr.iMinDocid))) {
        pCsr.isEof = 1;
    }

    return rc;
}

fn fts3EvalRestart(pCsr: *Fts3Cursor, pExpr: ?*Fts3Expr, pRc: *c_int) void {
    if (pExpr != null and pRc.* == SQLITE_OK) {
        const e = pExpr.?;
        const pPhrase = e.pPhrase;

        if (pPhrase) |ph| {
            fts3EvalInvalidatePoslist(ph);
            if (ph.bIncr != 0) {
                var i: c_int = 0;
                while (i < ph.nToken) : (i += 1) {
                    const pToken = phraseToken(ph, i);
                    if (pToken.pSegcsr) |seg| {
                        _ = sqlite3Fts3MsrIncrRestart(seg);
                    }
                }
                pRc.* = fts3EvalPhraseStart(pCsr, 0, ph);
            }
            ph.doclist.pNextDocid = null;
            ph.doclist.iDocid = 0;
            ph.pOrPoslist = null;
        }

        e.iDocid = 0;
        e.bEof = 0;
        e.bStart = 0;

        fts3EvalRestart(pCsr, e.pLeft, pRc);
        fts3EvalRestart(pCsr, e.pRight, pRc);
    }
}

export fn sqlite3Fts3MsrCancel(pCsr: *Fts3Cursor, pExpr: *Fts3Expr) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (pExpr.bEof == 0) {
        const iDocid = pExpr.iDocid;
        fts3EvalRestart(pCsr, pExpr, &rc);
        while (rc == SQLITE_OK and pExpr.iDocid != iDocid) {
            fts3EvalNextRow(pCsr, pExpr, &rc);
            if (pExpr.bEof != 0) rc = FTS_CORRUPT_VTAB();
        }
    }
    return rc;
}

fn fts3EvalUpdateCounts(pExpr: ?*Fts3Expr, nCol: c_int) void {
    if (pExpr) |e| {
        const pPhrase = e.pPhrase;
        if (pPhrase != null and pPhrase.?.doclist.pList != null) {
            var iCol: c_int = 0;
            var p: [*]u8 = pPhrase.?.doclist.pList.?;

            while (true) {
                var c: u8 = 0;
                var iCnt: c_int = 0;
                while ((0xFE & (p[0] | c)) != 0) {
                    if ((c & 0x80) == 0) iCnt += 1;
                    c = p[0] & 0x80;
                    p += 1;
                }

                e.aMI.?[@intCast(iCol * 3 + 1)] += @intCast(iCnt);
                e.aMI.?[@intCast(iCol * 3 + 2)] += @intFromBool(iCnt > 0);
                if (p[0] == 0x00) break;
                p += 1;
                p += @intCast(fts3GetVarint32(p, &iCol));
                if (iCol >= nCol) break;
            }
        }

        fts3EvalUpdateCounts(e.pLeft, nCol);
        fts3EvalUpdateCounts(e.pRight, nCol);
    }
}

fn fts3AllocateMSI(pExpr: *Fts3Expr, iPhrase: c_int, pCtx: ?*anyopaque) callconv(.c) c_int {
    _ = iPhrase;
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCtx.?));
    if (pExpr.aMI == null) {
        pExpr.aMI = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(@as(i64, pTab.nColumn) * 3 * @sizeOf(u32)))));
        if (pExpr.aMI == null) return SQLITE_NOMEM;
    }
    @memset(@as([*]u8, @ptrCast(pExpr.aMI.?))[0..@intCast(@as(usize, @intCast(pTab.nColumn)) * 3 * @sizeOf(u32))], 0);
    return SQLITE_OK;
}

fn fts3EvalGatherStats(pCsr: *Fts3Cursor, pExpr: *Fts3Expr) c_int {
    var rc: c_int = SQLITE_OK;

    if (pExpr.aMI == null) {
        const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
        var pRoot: *Fts3Expr = undefined;

        const iPrevId = pCsr.iPrevId;
        var iDocid: i64 = undefined;
        var bEof: u8 = undefined;

        pRoot = pExpr;
        while (pRoot.pParent != null and (pRoot.pParent.?.eType == FTSQUERY_NEAR or pRoot.bDeferred != 0)) {
            pRoot = pRoot.pParent.?;
        }
        iDocid = pRoot.iDocid;
        bEof = pRoot.bEof;

        rc = sqlite3Fts3ExprIterate(pRoot, &fts3AllocateMSI, @ptrCast(pTab));
        if (rc != SQLITE_OK) return rc;
        fts3EvalRestart(pCsr, pRoot, &rc);

        while (pCsr.isEof == 0 and rc == SQLITE_OK) {
            while (true) {
                if (pCsr.isRequireSeek == 0) _ = sqlite3_reset(pCsr.pStmt);

                fts3EvalNextRow(pCsr, pRoot, &rc);
                pCsr.isEof = pRoot.bEof;
                pCsr.isRequireSeek = 1;
                pCsr.isMatchinfoNeeded = 1;
                pCsr.iPrevId = pRoot.iDocid;
                if (!(pCsr.isEof == 0 and pRoot.eType == FTSQUERY_NEAR and sqlite3Fts3EvalTestDeferred(pCsr, &rc) != 0)) break;
            }

            if (rc == SQLITE_OK and pCsr.isEof == 0) {
                fts3EvalUpdateCounts(pRoot, pTab.nColumn);
            }
        }

        pCsr.isEof = 0;
        pCsr.iPrevId = iPrevId;

        if (bEof != 0) {
            pRoot.bEof = bEof;
        } else {
            fts3EvalRestart(pCsr, pRoot, &rc);
            while (true) {
                fts3EvalNextRow(pCsr, pRoot, &rc);
                if (pRoot.bEof != 0) rc = FTS_CORRUPT_VTAB();
                if (!(pRoot.iDocid != iDocid and rc == SQLITE_OK)) break;
            }
        }
    }
    return rc;
}

export fn sqlite3Fts3EvalPhraseStats(pCsr: *Fts3Cursor, pExpr: *Fts3Expr, aiOut: [*]u32) callconv(.c) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var rc: c_int = SQLITE_OK;
    var iCol: c_int = undefined;

    if (pExpr.bDeferred != 0 and pExpr.pParent.?.eType != FTSQUERY_NEAR) {
        iCol = 0;
        while (iCol < pTab.nColumn) : (iCol += 1) {
            aiOut[@intCast(iCol * 3 + 1)] = @intCast(pCsr.nDoc);
            aiOut[@intCast(iCol * 3 + 2)] = @intCast(pCsr.nDoc);
        }
    } else {
        rc = fts3EvalGatherStats(pCsr, pExpr);
        if (rc == SQLITE_OK) {
            iCol = 0;
            while (iCol < pTab.nColumn) : (iCol += 1) {
                aiOut[@intCast(iCol * 3 + 1)] = pExpr.aMI.?[@intCast(iCol * 3 + 1)];
                aiOut[@intCast(iCol * 3 + 2)] = pExpr.aMI.?[@intCast(iCol * 3 + 2)];
            }
        }
    }

    return rc;
}

export fn sqlite3Fts3EvalPhrasePoslist(pCsr: *Fts3Cursor, pExpr: *Fts3Expr, iCol: c_int, ppOut: *?[*]u8) callconv(.c) c_int {
    const pPhrase = pExpr.pPhrase.?;
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var pIter: ?[*]u8 = undefined;
    var iThis: c_int = undefined;
    var iDocid: i64 = undefined;

    ppOut.* = null;
    if (pPhrase.iColumn < pTab.nColumn and pPhrase.iColumn != iCol) {
        return SQLITE_OK;
    }

    iDocid = pExpr.iDocid;
    pIter = pPhrase.doclist.pList;
    if (iDocid != pCsr.iPrevId or pExpr.bEof != 0) {
        var rc: c_int = SQLITE_OK;
        const bDescDoclist = pTab.bDescIdx;
        var bOr: c_int = 0;
        var bTreeEof: u8 = 0;
        var p: ?*Fts3Expr = undefined;
        var pNear: *Fts3Expr = undefined;
        var pRun: *Fts3Expr = undefined;
        var bMatch: c_int = undefined;

        pNear = pExpr;
        p = pExpr.pParent;
        while (p != null) : (p = p.?.pParent) {
            if (p.?.eType == FTSQUERY_OR) bOr = 1;
            if (p.?.eType == FTSQUERY_NEAR) pNear = p.?;
            if (p.?.bEof != 0) bTreeEof = 1;
        }
        if (bOr == 0) return SQLITE_OK;
        pRun = pNear;
        while (pRun.bDeferred != 0) {
            pRun = pRun.pParent.?;
        }

        if (pPhrase.bIncr != 0) {
            const bEofSave = pRun.bEof;
            fts3EvalRestart(pCsr, pRun, &rc);
            while (rc == SQLITE_OK and pRun.bEof == 0) {
                fts3EvalNextRow(pCsr, pRun, &rc);
                if (bEofSave == 0 and pRun.iDocid == iDocid) break;
            }
            if (rc == SQLITE_OK and pRun.bEof != bEofSave) {
                rc = FTS_CORRUPT_VTAB();
            }
        }
        if (bTreeEof != 0) {
            while (rc == SQLITE_OK and pRun.bEof == 0) {
                fts3EvalNextRow(pCsr, pRun, &rc);
            }
        }
        if (rc != SQLITE_OK) return rc;

        bMatch = 1;
        p = pNear;
        while (p != null) : (p = p.?.pLeft) {
            var bEof: u8 = 0;
            var pTest: *Fts3Expr = p.?;
            if (pTest.eType == FTSQUERY_NEAR) pTest = pTest.pRight.?;
            const pPh = pTest.pPhrase.?;

            pIter = pPh.pOrPoslist;
            iDocid = pPh.iOrDocid;
            if (pCsr.bDesc == bDescDoclist) {
                bEof = @intFromBool(pPh.doclist.nAll == 0 or (@intFromPtr(pIter) >= @intFromPtr(pPh.doclist.aAll.? + @as(usize, @intCast(pPh.doclist.nAll)))));
                while ((pIter == null or docidCmp(bDescDoclist, iDocid, pCsr.iPrevId) < 0) and bEof == 0) {
                    sqlite3Fts3DoclistNext(bDescDoclist, pPh.doclist.aAll.?, pPh.doclist.nAll, &pIter, &iDocid, &bEof);
                }
            } else {
                bEof = @intFromBool(pPh.doclist.nAll == 0 or (pIter != null and @intFromPtr(pIter) <= @intFromPtr(pPh.doclist.aAll)));
                while ((pIter == null or docidCmp(bDescDoclist, iDocid, pCsr.iPrevId) > 0) and bEof == 0) {
                    var dummy: c_int = undefined;
                    sqlite3Fts3DoclistPrev(bDescDoclist, pPh.doclist.aAll.?, pPh.doclist.nAll, &pIter, &iDocid, &dummy, &bEof);
                }
            }
            pPh.pOrPoslist = pIter;
            pPh.iOrDocid = iDocid;
            if (bEof != 0 or iDocid != pCsr.iPrevId) bMatch = 0;
        }

        if (bMatch != 0) {
            pIter = pPhrase.pOrPoslist;
        } else {
            pIter = null;
        }
    }
    if (pIter == null) return SQLITE_OK;

    if (pIter.?[0] == 0x01) {
        var pv = pIter.?;
        pv += 1;
        pv += @intCast(fts3GetVarint32(pv, &iThis));
        pIter = pv;
    } else {
        iThis = 0;
    }
    while (iThis < iCol) {
        var pv = pIter.?;
        fts3ColumnlistCopy(null, &pv);
        if (pv[0] == 0x00) {
            return SQLITE_OK;
        }
        pv += 1;
        pv += @intCast(fts3GetVarint32(pv, &iThis));
        pIter = pv;
    }
    if (pIter.?[0] == 0x00) {
        pIter = null;
    }

    ppOut.* = if (iCol == iThis) pIter else null;
    return SQLITE_OK;
}

export fn sqlite3Fts3EvalPhraseCleanup(pPhrase: ?*Fts3Phrase) callconv(.c) void {
    if (pPhrase) |ph| {
        sqlite3_free(ph.doclist.aAll);
        fts3EvalInvalidatePoslist(ph);
        @memset(@as([*]u8, @ptrCast(&ph.doclist))[0..@sizeOf(Fts3Doclist)], 0);
        var i: c_int = 0;
        while (i < ph.nToken) : (i += 1) {
            fts3SegReaderCursorFree(phraseToken(ph, i).pSegcsr);
            phraseToken(ph, i).pSegcsr = null;
        }
    }
}

// Return SQLITE_CORRUPT_VTAB. Only present in SQLITE_DEBUG builds.
export fn sqlite3Fts3Corrupt() callconv(.c) c_int {
    return SQLITE_CORRUPT_VTAB;
}

// ===========================================================================
// Loadable-extension entry point (built when not part of the core; in this
// build SQLITE_CORE is defined for fts3, so this is compiled out in C — keep
// it out here too).
// ===========================================================================
