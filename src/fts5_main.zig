//! Zig port of the fts5_main.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 19170-23071).
//!
//! The fts5 virtual-table module itself: the sqlite3_module (iVersion 4)
//! method table, the fts5() API entry point, the auxiliary-function plumbing
//! (Fts5ExtensionApi impl), and sqlite3Fts5Init — the ONE symbol the SQLite
//! core registers. Everything else here is `static` in C and so becomes a
//! private Zig fn; only sqlite3Fts5Init is `export`ed.
//!
//! Section-private structs (Fts5Global, Fts5FullTable, Fts5Cursor, Fts5Sorter,
//! Fts5Auxiliary, Fts5TokenizerModule, Fts5Auxdata, Fts5VtoVTokenizer) are
//! defined locally — the foundation exposes the cross-section ones as opaque{}.
//!
//! The sqlite3_module / fts5_api / Fts5ExtensionApi method tables are built
//! from the foundation's `extern struct` definitions so field order + iVersion
//! match the C tables byte-for-byte.

const int = @import("fts5_int.zig");
const config = @import("config");

const Fts5Config = int.Fts5Config;
const Fts5Index = int.Fts5Index;
const Fts5Storage = int.Fts5Storage;
const Fts5Expr = int.Fts5Expr;
const Fts5PoslistPopulator = int.Fts5PoslistPopulator;
const Fts5Table = int.Fts5Table;
const Fts5Buffer = int.Fts5Buffer;
const Fts5PoslistReader = int.Fts5PoslistReader;
const Fts5Colset = int.Fts5Colset;
const Fts5TokenizerConfig = int.Fts5TokenizerConfig;
const Fts5Context = int.Fts5Context;
const Fts5Tokenizer = int.Fts5Tokenizer;
const Fts5PhraseIter = int.Fts5PhraseIter;
const Fts5ExtensionApi = int.Fts5ExtensionApi;
const fts5_extension_function = int.fts5_extension_function;
const fts5_api = int.fts5_api;
const fts5_tokenizer = int.fts5_tokenizer;
const fts5_tokenizer_v2 = int.fts5_tokenizer_v2;
const sqlite3 = int.sqlite3;
const sqlite3_stmt = int.sqlite3_stmt;
const sqlite3_value = int.sqlite3_value;
const sqlite3_context = int.sqlite3_context;
const sqlite3_vtab = int.sqlite3_vtab;
const sqlite3_vtab_cursor = int.sqlite3_vtab_cursor;
const sqlite3_index_info = int.sqlite3_index_info;
const sqlite3_index_constraint = int.sqlite3_index_constraint;
const sqlite3_module = int.sqlite3_module;

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_ERROR = int.SQLITE_ERROR;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_CONSTRAINT = int.SQLITE_CONSTRAINT;
const SQLITE_MISMATCH = int.SQLITE_MISMATCH;
const SQLITE_RANGE = int.SQLITE_RANGE;
const SQLITE_ROW = int.SQLITE_ROW;
const SQLITE_DONE = int.SQLITE_DONE;
const SQLITE_ABORT = int.SQLITE_ABORT;
const SQLITE_INTEGER = int.SQLITE_INTEGER;
const SQLITE_NULL = int.SQLITE_NULL;
const SQLITE_BLOB = int.SQLITE_BLOB;
const SQLITE_CORRUPT = int.SQLITE_CORRUPT;

// FTS5_CORRUPT macro == SQLITE_CORRUPT_VTAB.
const FTS5_CORRUPT = int.SQLITE_CORRUPT_VTAB;

// SQLITE_REPLACE conflict mode (sqlite3.h).
const SQLITE_REPLACE: c_int = 5;

const SQLITE_UTF8 = int.SQLITE_UTF8;
const SQLITE_DETERMINISTIC = int.SQLITE_DETERMINISTIC;
const SQLITE_INNOCUOUS = int.SQLITE_INNOCUOUS;
const SQLITE_SUBTYPE: c_int = 0x000100000;
const SQLITE_RESULT_SUBTYPE: c_int = 0x001000000;

const SQLITE_INDEX_CONSTRAINT_EQ = int.SQLITE_INDEX_CONSTRAINT_EQ;
const SQLITE_INDEX_CONSTRAINT_LT = int.SQLITE_INDEX_CONSTRAINT_LT;
const SQLITE_INDEX_CONSTRAINT_LE = int.SQLITE_INDEX_CONSTRAINT_LE;
const SQLITE_INDEX_CONSTRAINT_GT = int.SQLITE_INDEX_CONSTRAINT_GT;
const SQLITE_INDEX_CONSTRAINT_GE = int.SQLITE_INDEX_CONSTRAINT_GE;
const SQLITE_INDEX_CONSTRAINT_MATCH = int.SQLITE_INDEX_CONSTRAINT_MATCH;
const SQLITE_INDEX_CONSTRAINT_LIKE = int.SQLITE_INDEX_CONSTRAINT_LIKE;
const SQLITE_INDEX_CONSTRAINT_GLOB = int.SQLITE_INDEX_CONSTRAINT_GLOB;
const SQLITE_INDEX_SCAN_UNIQUE = int.SQLITE_INDEX_SCAN_UNIQUE;

const SQLITE_VTAB_CONSTRAINT_SUPPORT = int.SQLITE_VTAB_CONSTRAINT_SUPPORT;
const SQLITE_VTAB_INNOCUOUS = int.SQLITE_VTAB_INNOCUOUS;

const SQLITE_STATIC = int.SQLITE_STATIC;
const SQLITE_TRANSIENT = int.SQLITE_TRANSIENT;

const FTS5_CONTENT_NORMAL = int.FTS5_CONTENT_NORMAL;
const FTS5_CONTENT_NONE = int.FTS5_CONTENT_NONE;
const FTS5_CONTENT_EXTERNAL = int.FTS5_CONTENT_EXTERNAL;
const FTS5_CONTENT_UNINDEXED = int.FTS5_CONTENT_UNINDEXED;

const FTS5_DETAIL_FULL = int.FTS5_DETAIL_FULL;
const FTS5_DETAIL_COLUMNS = int.FTS5_DETAIL_COLUMNS;

const FTS5_PATTERN_LIKE = int.FTS5_PATTERN_LIKE;
const FTS5_PATTERN_GLOB = int.FTS5_PATTERN_GLOB;

const FTS5_TOKENIZE_AUX = int.FTS5_TOKENIZE_AUX;
const FTS5_TOKEN_COLOCATED = int.FTS5_TOKEN_COLOCATED;

const FTS5_STMT_SCAN_ASC = int.FTS5_STMT_SCAN_ASC;
const FTS5_STMT_SCAN_DESC = int.FTS5_STMT_SCAN_DESC;
const FTS5_STMT_LOOKUP = int.FTS5_STMT_LOOKUP;

const FTS5_DEFAULT_RANK = int.FTS5_DEFAULT_RANK;
const LARGEST_INT64 = int.LARGEST_INT64;
const SMALLEST_INT64 = int.SMALLEST_INT64;

const FTS5_POS2COLUMN = int.FTS5_POS2COLUMN;
const FTS5_POS2OFFSET = int.FTS5_POS2OFFSET;

// fts5_main.c xBestIndex idxNum bits.
const FTS5_BI_MATCH: c_int = 0x0001;
const FTS5_BI_RANK: c_int = 0x0002;
const FTS5_BI_ROWID_EQ: c_int = 0x0004;
const FTS5_BI_ROWID_LE: c_int = 0x0008;
const FTS5_BI_ROWID_GE: c_int = 0x0010;
const FTS5_BI_ORDER_RANK: c_int = 0x0020;
const FTS5_BI_ORDER_ROWID: c_int = 0x0040;
const FTS5_BI_ORDER_DESC: c_int = 0x0080;

// Query plans.
const FTS5_PLAN_MATCH: c_int = 1;
const FTS5_PLAN_SOURCE: c_int = 2;
const FTS5_PLAN_SPECIAL: c_int = 3;
const FTS5_PLAN_SORTED_MATCH: c_int = 4;
const FTS5_PLAN_SCAN: c_int = 5;
const FTS5_PLAN_ROWID: c_int = 6;

// Fts5Cursor.csrflags.
const FTS5CSR_EOF: c_int = 0x01;
const FTS5CSR_REQUIRE_CONTENT: c_int = 0x02;
const FTS5CSR_REQUIRE_DOCSIZE: c_int = 0x04;
const FTS5CSR_REQUIRE_INST: c_int = 0x08;
const FTS5CSR_FREE_ZRANK: c_int = 0x10;
const FTS5CSR_REQUIRE_RESEEK: c_int = 0x20;
const FTS5CSR_REQUIRE_POSLIST: c_int = 0x40;

const FTS5_INSTTOKEN_SUBTYPE: c_int = 73;

// Transaction-state op codes (SQLITE_DEBUG only).
const FTS5_BEGIN: c_int = 1;
const FTS5_SYNC: c_int = 2;
const FTS5_COMMIT: c_int = 3;
const FTS5_ROLLBACK: c_int = 4;
const FTS5_SAVEPOINT: c_int = 5;
const FTS5_RELEASE: c_int = 6;
const FTS5_ROLLBACKTO: c_int = 7;

inline fn CsrFlagSet(pCsr: *Fts5Cursor, flag: c_int) void {
    pCsr.csrflags |= flag;
}
inline fn CsrFlagClear(pCsr: *Fts5Cursor, flag: c_int) void {
    pCsr.csrflags &= ~flag;
}
inline fn CsrFlagTest(pCsr: *Fts5Cursor, flag: c_int) c_int {
    return pCsr.csrflags & flag;
}
inline fn BitFlagTest(x: c_int, y: c_int) bool {
    return (x & y) != 0;
}

// ---------------------------------------------------------------------------
// libc + public sqlite3 API
// ---------------------------------------------------------------------------
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn strlen(s: [*:0]const u8) usize;

extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *anyopaque) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, buf: [*]u8, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_stricmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn sqlite3_strnicmp(a: [*:0]const u8, b: [*:0]const u8, n: c_int) c_int;
extern fn sqlite3_errmsg(db: ?*sqlite3) ?[*:0]const u8;
extern fn sqlite3_errstr(rc: c_int) ?[*:0]const u8;
extern fn sqlite3_randomness(n: c_int, p: ?*anyopaque) void;
extern fn sqlite3_libversion_number() c_int;

extern fn sqlite3_prepare_v3(db: ?*sqlite3, sql: [*:0]const u8, n: c_int, prepFlags: c_uint, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_count(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, i: c_int) i64;
extern fn sqlite3_column_bytes(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_blob(pStmt: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_text(pStmt: ?*sqlite3_stmt, i: c_int) ?[*:0]const u8;
extern fn sqlite3_column_value(pStmt: ?*sqlite3_stmt, i: c_int) ?*sqlite3_value;
extern fn sqlite3_bind_int64(pStmt: ?*sqlite3_stmt, i: c_int, v: i64) c_int;
extern fn sqlite3_bind_value(pStmt: ?*sqlite3_stmt, i: c_int, v: ?*sqlite3_value) c_int;

extern fn sqlite3_value_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_numeric_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(p: ?*sqlite3_value) i64;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_blob(p: ?*sqlite3_value) ?*const anyopaque;
extern fn sqlite3_value_bytes(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_nochange(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_subtype(p: ?*sqlite3_value) c_uint;
extern fn sqlite3_value_pointer(p: ?*sqlite3_value, t: [*:0]const u8) ?*anyopaque;

extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*]const u8, n: c_int, xDel: int.DestructorFn) void;
extern fn sqlite3_result_blob(ctx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: int.DestructorFn) void;
extern fn sqlite3_result_value(ctx: ?*sqlite3_context, v: ?*sqlite3_value) void;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*sqlite3_context) void;
extern fn sqlite3_result_subtype(ctx: ?*sqlite3_context, t: c_uint) void;

extern fn sqlite3_user_data(ctx: ?*sqlite3_context) ?*anyopaque;
extern fn sqlite3_vtab_nochange(ctx: ?*sqlite3_context) c_int;
extern fn sqlite3_vtab_config(db: ?*sqlite3, op: c_int, ...) c_int;
extern fn sqlite3_vtab_on_conflict(db: ?*sqlite3) c_int;
extern fn sqlite3_overload_function(db: ?*sqlite3, zName: [*:0]const u8, nArg: c_int) c_int;
extern fn sqlite3_create_module_v2(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pAux: ?*anyopaque, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3_create_function(db: ?*sqlite3, zName: [*:0]const u8, nArg: c_int, eTextRep: c_int, pApp: ?*anyopaque, xFunc: ?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void, xStep: ?*anyopaque, xFinal: ?*anyopaque) c_int;

// fts5_index.c xToken callback type used in tokenize.
const XTokenCb = ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int;

// ---------------------------------------------------------------------------
// sibling section: fts5_buffer.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5BufferAppendVarint(pRc: *c_int, pBuf: *Fts5Buffer, iVal: i64) callconv(.c) void;
// pData may be null when nData==0 (an empty poslist); C no-ops in that case.
extern fn sqlite3Fts5BufferAppendBlob(pRc: *c_int, pBuf: *Fts5Buffer, nData: u32, pData: ?[*]const u8) callconv(.c) void;
extern fn sqlite3Fts5Mprintf(pRc: *c_int, zFmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5MallocZero(pRc: *c_int, nByte: i64) callconv(.c) ?*anyopaque;
extern fn sqlite3Fts5GetVarint32(p: [*]const u8, v: *u32) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistReaderInit(a: ?[*]const u8, n: c_int, pIter: *Fts5PoslistReader) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistReaderNext(pIter: *Fts5PoslistReader) callconv(.c) c_int;

// ---------------------------------------------------------------------------
// sibling section: fts5_index.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5IndexOpen(pConfig: *Fts5Config, bCreate: c_int, pp: *?*Fts5Index, pzErr: *?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3Fts5IndexClose(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexLoadConfig(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexReads(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexCloseReader(p: ?*Fts5Index) callconv(.c) void;
extern fn sqlite3Fts5IndexInit(db: ?*sqlite3) callconv(.c) c_int;

// ---------------------------------------------------------------------------
// sibling section: fts5_storage.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5StorageOpen(pConfig: *Fts5Config, pIndex: ?*Fts5Index, bCreate: c_int, pp: *?*Fts5Storage, pzErr: *?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3Fts5StorageClose(p: ?*Fts5Storage) callconv(.c) c_int;
extern fn sqlite3Fts5StorageRename(p: *Fts5Storage, zName: [*:0]const u8) callconv(.c) c_int;
extern fn sqlite3Fts5DropAll(pConfig: *Fts5Config) callconv(.c) c_int;
extern fn sqlite3Fts5StorageDelete(p: *Fts5Storage, iDel: i64, apVal: ?[*]?*sqlite3_value, bSaveRow: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5StorageContentInsert(p: *Fts5Storage, bReplace: c_int, apVal: [*]?*sqlite3_value, piRowid: *i64) callconv(.c) c_int;
extern fn sqlite3Fts5StorageIndexInsert(p: *Fts5Storage, apVal: [*]?*sqlite3_value, iRowid: i64) callconv(.c) c_int;
extern fn sqlite3Fts5StorageIntegrity(p: *Fts5Storage, iArg: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5StorageStmt(p: *Fts5Storage, eStmt: c_int, pp: *?*sqlite3_stmt, pzErrMsg: ?*?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3Fts5StorageStmtRelease(p: *Fts5Storage, eStmt: c_int, pStmt: ?*sqlite3_stmt) callconv(.c) void;
extern fn sqlite3Fts5StorageDocsize(p: *Fts5Storage, iRowid: i64, aCol: [*]c_int) callconv(.c) c_int;
extern fn sqlite3Fts5StorageSize(p: *Fts5Storage, iCol: c_int, pnToken: *i64) callconv(.c) c_int;
extern fn sqlite3Fts5StorageRowCount(p: *Fts5Storage, pnRow: *i64) callconv(.c) c_int;
extern fn sqlite3Fts5StorageSync(p: *Fts5Storage) callconv(.c) c_int;
extern fn sqlite3Fts5StorageRollback(p: *Fts5Storage) callconv(.c) c_int;
extern fn sqlite3Fts5StorageConfigValue(p: *Fts5Storage, z: [*:0]const u8, pVal: ?*sqlite3_value, iVal: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5StorageDeleteAll(p: *Fts5Storage) callconv(.c) c_int;
extern fn sqlite3Fts5StorageRebuild(p: *Fts5Storage) callconv(.c) c_int;
extern fn sqlite3Fts5StorageOptimize(p: *Fts5Storage) callconv(.c) c_int;
extern fn sqlite3Fts5StorageMerge(p: *Fts5Storage, nMerge: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5StorageReset(p: *Fts5Storage) callconv(.c) c_int;
extern fn sqlite3Fts5StorageReleaseDeleteRow(p: *Fts5Storage) callconv(.c) void;
extern fn sqlite3Fts5StorageFindDeleteRow(p: *Fts5Storage, iDel: i64) callconv(.c) c_int;

// ---------------------------------------------------------------------------
// sibling section: fts5_config.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5ConfigParse(pGlobal: *Fts5Global, db: ?*sqlite3, nArg: c_int, azArg: [*]const ?[*:0]const u8, pp: *?*Fts5Config, pzErr: *?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3Fts5ConfigFree(p: ?*Fts5Config) callconv(.c) void;
extern fn sqlite3Fts5ConfigDeclareVtab(pConfig: *Fts5Config) callconv(.c) c_int;
extern fn sqlite3Fts5Tokenize(pConfig: *Fts5Config, flags: c_int, pText: ?[*]const u8, nText: c_int, pCtx: ?*anyopaque, xToken: XTokenCb) callconv(.c) c_int;
extern fn sqlite3Fts5ConfigLoad(p: *Fts5Config, iCookie: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ConfigSetValue(p: *Fts5Config, z: [*:0]const u8, pVal: ?*sqlite3_value, pbBaddir: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ConfigParseRank(z: [*:0]const u8, pzRank: *?[*:0]u8, pzRankArgs: *?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3Fts5ConfigErrmsg(pConfig: *Fts5Config, zFmt: [*:0]const u8, ...) callconv(.c) void;

// ---------------------------------------------------------------------------
// sibling section: fts5_expr.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5ExprNew(pConfig: *Fts5Config, bPhraseToAnd: c_int, iCol: c_int, zExpr: [*:0]const u8, ppNew: *?*Fts5Expr, pzErr: *?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3Fts5ExprPattern(pConfig: *Fts5Config, bGlob: c_int, iCol: c_int, zText: [*:0]const u8, pp: *?*Fts5Expr) callconv(.c) c_int;
extern fn sqlite3Fts5ExprFirst(p: ?*Fts5Expr, pIdx: ?*Fts5Index, iMin: i64, iMax: i64, bDesc: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ExprNext(p: ?*Fts5Expr, iMax: i64) callconv(.c) c_int;
extern fn sqlite3Fts5ExprEof(p: ?*Fts5Expr) callconv(.c) c_int;
extern fn sqlite3Fts5ExprRowid(p: ?*Fts5Expr) callconv(.c) i64;
extern fn sqlite3Fts5ExprFree(p: ?*Fts5Expr) callconv(.c) void;
extern fn sqlite3Fts5ExprAnd(pp1: *?*Fts5Expr, p2: ?*Fts5Expr) callconv(.c) c_int;
extern fn sqlite3Fts5ExprInit(pGlobal: *Fts5Global, db: ?*sqlite3) callconv(.c) c_int;
extern fn sqlite3Fts5ExprPhraseCount(p: ?*Fts5Expr) callconv(.c) c_int;
extern fn sqlite3Fts5ExprPhraseSize(p: ?*Fts5Expr, iPhrase: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ExprPoslist(p: ?*Fts5Expr, iPhrase: c_int, pp: *?[*]const u8) callconv(.c) c_int;
extern fn sqlite3Fts5ExprClearPoslists(p: ?*Fts5Expr, bLive: c_int) callconv(.c) ?*Fts5PoslistPopulator;
extern fn sqlite3Fts5ExprPopulatePoslists(pConfig: *Fts5Config, p: ?*Fts5Expr, aPopulator: ?*Fts5PoslistPopulator, iCol: c_int, z: ?[*]const u8, n: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ExprCheckPoslists(p: ?*Fts5Expr, iRowid: i64) callconv(.c) void;
extern fn sqlite3Fts5ExprClonePhrase(p: ?*Fts5Expr, iPhrase: c_int, pp: *?*Fts5Expr) callconv(.c) c_int;
extern fn sqlite3Fts5ExprPhraseCollist(p: ?*Fts5Expr, iPhrase: c_int, pp: *?[*]const u8, pn: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ExprQueryToken(p: ?*Fts5Expr, iPhrase: c_int, iToken: c_int, ppOut: *?[*]const u8, pnOut: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ExprInstToken(p: ?*Fts5Expr, iRowid: i64, iPhrase: c_int, iCol: c_int, iOff: c_int, iToken: c_int, ppOut: *?[*]const u8, pnOut: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ExprClearTokens(p: ?*Fts5Expr) callconv(.c) void;

// ---------------------------------------------------------------------------
// sibling sections: fts5_aux.c / fts5_tokenizer.c / fts5_vocab.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5AuxInit(pApi: *fts5_api) callconv(.c) c_int;
extern fn sqlite3Fts5TokenizerInit(pApi: *fts5_api) callconv(.c) c_int;
extern fn sqlite3Fts5TokenizerPattern(xCreate: ?*const fn (?*anyopaque, ?[*]const ?[*:0]const u8, c_int, *?*Fts5Tokenizer) callconv(.c) c_int, pTok: ?*Fts5Tokenizer) callconv(.c) c_int;
extern fn sqlite3Fts5TokenizerPreload(p: *Fts5TokenizerConfig) callconv(.c) c_int;
extern fn sqlite3Fts5VocabInit(pGlobal: *Fts5Global, db: ?*sqlite3) callconv(.c) c_int;

// ===========================================================================
// Section-private structs.
// ===========================================================================

/// fts5_main.c 19238-19241: transaction state (SQLITE_DEBUG only).
const Fts5TransactionState = extern struct {
    eState: c_int,
    iSavepoint: c_int,
};

/// fts5_main.c 19248-19257: per-connection global context. `api` first so
/// (fts5_api*)pGlobal aliases pGlobal->api.
const Fts5Global = extern struct {
    api: fts5_api,
    db: ?*sqlite3,
    iNextId: i64,
    pAux: ?*Fts5Auxiliary,
    pTok: ?*Fts5TokenizerModule,
    pDfltTok: ?*Fts5TokenizerModule,
    pCsr: ?*Fts5Cursor,
    aLocaleHdr: [4]u32,
};

const FTS5_LOCALE_HDR_SIZE: c_int = @sizeOf(@FieldType(Fts5Global, "aLocaleHdr"));

/// fts5_main.c 19273-19280: a registered auxiliary function.
const Fts5Auxiliary = extern struct {
    pGlobal: ?*Fts5Global,
    zFunc: ?[*:0]u8,
    pUserData: ?*anyopaque,
    xFunc: fts5_extension_function,
    xDestroy: ?*const fn (?*anyopaque) callconv(.c) void,
    pNext: ?*Fts5Auxiliary,
};

/// fts5_main.c 19302-19310: a registered tokenizer module.
const Fts5TokenizerModule = extern struct {
    zName: ?[*:0]u8,
    pUserData: ?*anyopaque,
    bV2Native: c_int,
    x1: fts5_tokenizer,
    x2: fts5_tokenizer_v2,
    xDestroy: ?*const fn (?*anyopaque) callconv(.c) void,
    pNext: ?*Fts5TokenizerModule,
};

/// fts5_main.c 19312-19322: the fts5 vtab (subclasses Fts5Table). The trailing
/// `ts` field exists only under SQLITE_DEBUG, so it is config-gated to keep
/// sizeof()/offsets identical in production and --dev builds.
const Fts5FullTable = extern struct {
    p: Fts5Table,
    pStorage: ?*Fts5Storage,
    pGlobal: ?*Fts5Global,
    pSortCsr: ?*Fts5Cursor,
    iSavepoint: c_int,
    ts: if (config.sqlite_debug) Fts5TransactionState else void =
        if (config.sqlite_debug) .{ .eState = 0, .iSavepoint = 0 } else {},
};

/// fts5_main.c 19338-19344: sorter for "ORDER BY rank" queries. aIdx[] is a
/// flexible array member; reached by pointer arithmetic.
const Fts5Sorter = extern struct {
    pStmt: ?*sqlite3_stmt,
    iRowid: i64,
    aPoslist: ?[*]const u8,
    nIdx: c_int,
    aIdx: [0]c_int,
};
/// SZ_FTS5SORTER(N) == offsetof(Fts5Sorter,nIdx)+((N+2)/2)*sizeof(i64).
inline fn SZ_FTS5SORTER(n: c_int) i64 {
    return @as(i64, @offsetOf(Fts5Sorter, "nIdx")) + @divTrunc(@as(i64, n) + 2, 2) * @sizeOf(i64);
}
inline fn sorterIdx(p: *Fts5Sorter, i: c_int) *c_int {
    const a: [*]c_int = @ptrCast(&p.aIdx);
    return &a[@intCast(i)];
}

/// fts5_main.c 19368-19402: vtab cursor. Everything from `ePlan` onwards is
/// zeroed on cursor reset (see the memset idiom in fts5FreeCursorComponents).
const Fts5Cursor = extern struct {
    base: sqlite3_vtab_cursor,
    pNext: ?*Fts5Cursor,
    aColumnSize: ?[*]c_int,
    iCsrId: i64,

    // Zero from this point onwards on cursor reset.
    ePlan: c_int,
    bDesc: c_int,
    iFirstRowid: i64,
    iLastRowid: i64,
    pStmt: ?*sqlite3_stmt,
    pExpr: ?*Fts5Expr,
    pSorter: ?*Fts5Sorter,
    csrflags: c_int,
    iSpecial: i64,

    zRank: ?[*:0]u8,
    zRankArgs: ?[*:0]u8,
    pRank: ?*Fts5Auxiliary,
    nRankArg: c_int,
    apRankArg: ?[*]?*sqlite3_value,
    pRankArgStmt: ?*sqlite3_stmt,

    pAux: ?*Fts5Auxiliary,
    pAuxdata: ?*Fts5Auxdata,

    aInstIter: ?[*]Fts5PoslistReader,
    nInstAlloc: c_int,
    nInstCount: c_int,
    aInst: ?[*]c_int,
};

/// fts5_main.c 19440-19445: saved auxiliary data.
const Fts5Auxdata = extern struct {
    pAux: ?*Fts5Auxiliary,
    pPtr: ?*anyopaque,
    xDelete: ?*const fn (?*anyopaque) callconv(.c) void,
    pNext: ?*Fts5Auxdata,
};

/// fts5_main.c 22468-22474: wrapper tokenizer instance.
const Fts5VtoVTokenizer = extern struct {
    bV2Native: c_int,
    x1: fts5_tokenizer,
    x2: fts5_tokenizer_v2,
    pReal: ?*Fts5Tokenizer,
};

// Offset of `ePlan` within Fts5Cursor — used by the partial-reset memset.
const ePlanOffset: usize = @offsetOf(Fts5Cursor, "ePlan");

inline fn resetCursorTail(pCsr: *Fts5Cursor) void {
    const base: [*]u8 = @ptrCast(pCsr);
    _ = memset(base + ePlanOffset, 0, @sizeOf(Fts5Cursor) - ePlanOffset);
}

inline fn FTS5_LOCALE_HDR(pConfig: *Fts5Config) [*]const u8 {
    const pg: *Fts5Global = @ptrCast(@alignCast(pConfig.pGlobal.?));
    return @ptrCast(&pg.aLocaleHdr);
}

// ===========================================================================
// Transaction-state assertion bookkeeping (SQLITE_DEBUG only — no-op else).
// ===========================================================================
inline fn fts5CheckTransactionState(p: *Fts5FullTable, op: c_int, iSavepoint: c_int) void {
    if (!config.sqlite_debug) return;
    switch (op) {
        FTS5_BEGIN => {
            p.ts.eState = 1;
            p.ts.iSavepoint = -1;
        },
        FTS5_SYNC => {
            p.ts.eState = 2;
        },
        FTS5_COMMIT => {
            p.ts.eState = 0;
        },
        FTS5_ROLLBACK => {
            p.ts.eState = 0;
        },
        FTS5_SAVEPOINT => {
            p.ts.iSavepoint = iSavepoint;
        },
        FTS5_RELEASE => {
            p.ts.iSavepoint = iSavepoint - 1;
        },
        FTS5_ROLLBACKTO => {
            p.ts.iSavepoint = iSavepoint;
        },
        else => {},
    }
}

/// fts5_main.c 19512-19518: true if pTab is a contentless table.
fn fts5IsContentless(pTab: *Fts5FullTable, bIncludeUnindexed: c_int) c_int {
    const eContent = pTab.p.pConfig.?.eContent;
    return @intFromBool(eContent == FTS5_CONTENT_NONE or
        (bIncludeUnindexed != 0 and eContent == FTS5_CONTENT_UNINDEXED));
}

/// fts5_main.c 19523-19530: free a vtab handle.
fn fts5FreeVtab(pTab: ?*Fts5FullTable) void {
    if (pTab) |pt| {
        _ = sqlite3Fts5IndexClose(pt.p.pIndex);
        _ = sqlite3Fts5StorageClose(pt.pStorage);
        sqlite3Fts5ConfigFree(pt.p.pConfig);
        sqlite3_free(pt);
    }
}

fn fts5DisconnectMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    fts5FreeVtab(@ptrCast(pVtab));
    return SQLITE_OK;
}

fn fts5DestroyMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pTab: *Fts5Table = @ptrCast(pVtab);
    const rc = sqlite3Fts5DropAll(pTab.pConfig.?);
    if (rc == SQLITE_OK) {
        fts5FreeVtab(@ptrCast(pVtab));
    }
    return rc;
}

/// fts5_main.c 19563-19631: shared xConnect/xCreate implementation.
fn fts5InitVtab(
    bCreate: c_int,
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVTab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) c_int {
    const pGlobal: *Fts5Global = @ptrCast(@alignCast(pAux.?));
    var rc: c_int = SQLITE_OK;
    var pConfig: ?*Fts5Config = null;

    const pTab: ?*Fts5FullTable = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5FullTable))));
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5ConfigParse(pGlobal, db, argc, argv.?, &pConfig, pzErr);
    }
    if (rc == SQLITE_OK) {
        const pt = pTab.?;
        const pc = pConfig.?;
        pc.pzErrmsg = pzErr;
        pt.p.pConfig = pConfig;
        pt.pGlobal = pGlobal;
        if (bCreate != 0 or sqlite3Fts5TokenizerPreload(&pc.t) != 0) {
            rc = sqlite3Fts5LoadTokenizer(pc);
        }
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5IndexOpen(pConfig.?, bCreate, &pTab.?.p.pIndex, pzErr);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5StorageOpen(pConfig.?, pTab.?.p.pIndex, bCreate, &pTab.?.pStorage, pzErr);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5ConfigDeclareVtab(pConfig.?);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5ConfigLoad(pTab.?.p.pConfig.?, pTab.?.p.pConfig.?.iCookie - 1);
    }

    if (rc == SQLITE_OK and pConfig.?.eContent == FTS5_CONTENT_NORMAL) {
        rc = sqlite3_vtab_config(db, SQLITE_VTAB_CONSTRAINT_SUPPORT, @as(c_int, 1));
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);
    }

    if (pConfig) |pc| pc.pzErrmsg = null;
    if (rc != SQLITE_OK) {
        fts5FreeVtab(pTab);
        ppVTab.* = null;
    } else {
        if (bCreate != 0) {
            fts5CheckTransactionState(pTab.?, FTS5_BEGIN, 0);
        }
        ppVTab.* = @ptrCast(pTab);
    }
    return rc;
}

fn fts5ConnectMethod(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return fts5InitVtab(0, db, pAux, argc, argv, ppVtab, pzErr);
}
fn fts5CreateMethod(db: ?*sqlite3, pAux: ?*anyopaque, argc: c_int, argv: ?[*]const ?[*:0]const u8, ppVtab: *?*sqlite3_vtab, pzErr: *?[*:0]u8) callconv(.c) c_int {
    return fts5InitVtab(1, db, pAux, argc, argv, ppVtab, pzErr);
}

fn fts5SetUniqueFlag(pIdxInfo: *sqlite3_index_info) void {
    pIdxInfo.idxFlags |= SQLITE_INDEX_SCAN_UNIQUE;
}

fn fts5SetEstimatedRows(pIdxInfo: *sqlite3_index_info, nRow: i64) void {
    pIdxInfo.estimatedRows = if (nRow > 1) nRow else 1;
}

fn fts5UsePatternMatch(pConfig: *Fts5Config, p: *sqlite3_index_constraint) c_int {
    if (pConfig.t.ePattern == FTS5_PATTERN_GLOB and p.op == SQLITE_INDEX_CONSTRAINT_GLOB) {
        return 1;
    }
    if (pConfig.t.ePattern == FTS5_PATTERN_LIKE and
        (p.op == SQLITE_INDEX_CONSTRAINT_LIKE or p.op == SQLITE_INDEX_CONSTRAINT_GLOB))
    {
        return 1;
    }
    return 0;
}

/// fts5_main.c 19784-19941: xBestIndex.
fn fts5BestIndexMethod(pVTab: *sqlite3_vtab, pInfo: *sqlite3_index_info) callconv(.c) c_int {
    const pTab: *Fts5Table = @ptrCast(pVTab);
    const pConfig = pTab.pConfig.?;
    const nCol = pConfig.nCol;
    var idxFlags: c_int = 0;
    var i: c_int = 0;

    var iIdxStr: c_int = 0;
    var iCons: c_int = 0;

    var bSeenEq: c_int = 0;
    var bSeenGt: c_int = 0;
    var bSeenLt: c_int = 0;
    var nSeenMatch: c_int = 0;
    var bSeenRank: c_int = 0;

    if (pConfig.bLock != 0) {
        pTab.base.zErrMsg = sqlite3_mprintf("recursively defined fts5 content table");
        return SQLITE_ERROR;
    }

    // NB: `idxStr` is deliberately a mutable base pointer. pInfo.idxStr keeps
    // the ORIGINAL base; the L/G pattern branch below advances this local
    // `idxStr` (not iIdxStr) exactly as upstream does — a genuine fts5 quirk.
    var idxStr: [*]u8 = @ptrCast(sqlite3_malloc64(@as(u64, @intCast(@as(i64, pInfo.nConstraint) * 8 + 1))) orelse return SQLITE_NOMEM);
    pInfo.idxStr = @ptrCast(idxStr);
    pInfo.needToFreeIdxStr = 1;

    const aConstraint = pInfo.aConstraint.?;
    const aUsage = pInfo.aConstraintUsage.?;

    i = 0;
    while (i < pInfo.nConstraint) : (i += 1) {
        const p = &aConstraint[@intCast(i)];
        const iCol = p.iColumn;
        if (p.op == SQLITE_INDEX_CONSTRAINT_MATCH or
            (p.op == SQLITE_INDEX_CONSTRAINT_EQ and iCol >= nCol))
        {
            if (p.usable == 0 or iCol < 0) {
                idxStr[@intCast(iIdxStr)] = 0;
                return SQLITE_CONSTRAINT;
            } else {
                if (iCol == nCol + 1) {
                    if (bSeenRank != 0) continue;
                    idxStr[@intCast(iIdxStr)] = 'r';
                    iIdxStr += 1;
                    bSeenRank = 1;
                } else {
                    nSeenMatch += 1;
                    idxStr[@intCast(iIdxStr)] = 'M';
                    iIdxStr += 1;
                    _ = sqlite3_snprintf(6, idxStr + @as(usize, @intCast(iIdxStr)), "%d", iCol);
                    iIdxStr += @intCast(strlen(@ptrCast(idxStr + @as(usize, @intCast(iIdxStr)))));
                }
                iCons += 1;
                aUsage[@intCast(i)].argvIndex = iCons;
                aUsage[@intCast(i)].omit = 1;
            }
        } else if (p.usable != 0) {
            if (iCol >= 0 and iCol < nCol and fts5UsePatternMatch(pConfig, p) != 0) {
                idxStr[@intCast(iIdxStr)] = if (p.op == FTS5_PATTERN_LIKE) @as(u8, 'L') else @as(u8, 'G');
                iIdxStr += 1;
                _ = sqlite3_snprintf(6, idxStr + @as(usize, @intCast(iIdxStr)), "%d", iCol);
                // Upstream advances the BASE pointer here (not iIdxStr) — faithful.
                idxStr += strlen(@ptrCast(idxStr + @as(usize, @intCast(iIdxStr))));
                iCons += 1;
                aUsage[@intCast(i)].argvIndex = iCons;
                nSeenMatch += 1;
            } else if (bSeenEq == 0 and p.op == SQLITE_INDEX_CONSTRAINT_EQ and iCol < 0) {
                idxStr[@intCast(iIdxStr)] = '=';
                iIdxStr += 1;
                bSeenEq = 1;
                iCons += 1;
                aUsage[@intCast(i)].argvIndex = iCons;
                aUsage[@intCast(i)].omit = 1;
            }
        }
    }

    if (bSeenEq == 0) {
        i = 0;
        while (i < pInfo.nConstraint) : (i += 1) {
            const p = &aConstraint[@intCast(i)];
            if (p.iColumn < 0 and p.usable != 0) {
                const op = p.op;
                if (op == SQLITE_INDEX_CONSTRAINT_LT or op == SQLITE_INDEX_CONSTRAINT_LE) {
                    if (bSeenLt != 0) continue;
                    idxStr[@intCast(iIdxStr)] = '<';
                    iIdxStr += 1;
                    iCons += 1;
                    aUsage[@intCast(i)].argvIndex = iCons;
                    bSeenLt = 1;
                } else if (op == SQLITE_INDEX_CONSTRAINT_GT or op == SQLITE_INDEX_CONSTRAINT_GE) {
                    if (bSeenGt != 0) continue;
                    idxStr[@intCast(iIdxStr)] = '>';
                    iIdxStr += 1;
                    iCons += 1;
                    aUsage[@intCast(i)].argvIndex = iCons;
                    bSeenGt = 1;
                }
            }
        }
    }
    idxStr[@intCast(iIdxStr)] = 0;

    // ORDER BY handling.
    if (pInfo.nOrderBy == 1) {
        const aOrderBy = pInfo.aOrderBy.?;
        const iSort = aOrderBy[0].iColumn;
        if (iSort == (pConfig.nCol + 1) and nSeenMatch > 0) {
            idxFlags |= FTS5_BI_ORDER_RANK;
        } else if (iSort == -1 and (aOrderBy[0].desc == 0 or pConfig.bTokendata == 0)) {
            idxFlags |= FTS5_BI_ORDER_ROWID;
        }
        if (BitFlagTest(idxFlags, FTS5_BI_ORDER_RANK | FTS5_BI_ORDER_ROWID)) {
            pInfo.orderByConsumed = 1;
            if (aOrderBy[0].desc != 0) {
                idxFlags |= FTS5_BI_ORDER_DESC;
            }
        }
    }

    // Estimated cost.
    if (bSeenEq != 0) {
        pInfo.estimatedCost = if (nSeenMatch != 0) 25000.0 else 25.0;
        fts5SetEstimatedRows(pInfo, 1);
        fts5SetUniqueFlag(pInfo);
    } else {
        var nEstRows: i64 = undefined;
        if (nSeenMatch != 0) {
            if (bSeenLt != 0 and bSeenGt != 0) {
                pInfo.estimatedCost = 50000.0;
            } else if (bSeenLt != 0 or bSeenGt != 0) {
                pInfo.estimatedCost = 37500.0;
            } else {
                pInfo.estimatedCost = 50000.0;
            }
            nEstRows = @intFromFloat(pInfo.estimatedCost / 40.0);
            i = 1;
            while (i < nSeenMatch) : (i += 1) {
                pInfo.estimatedCost *= 2.5;
                nEstRows = @divTrunc(nEstRows, 2);
            }
        } else {
            if (bSeenLt != 0 and bSeenGt != 0) {
                pInfo.estimatedCost = 750000.0;
            } else if (bSeenLt != 0 or bSeenGt != 0) {
                pInfo.estimatedCost = 2250000.0;
            } else {
                pInfo.estimatedCost = 3000000.0;
            }
            nEstRows = @intFromFloat(pInfo.estimatedCost / 4.0);
        }
        fts5SetEstimatedRows(pInfo, nEstRows);
    }

    pInfo.idxNum = idxFlags;
    return SQLITE_OK;
}

fn fts5NewTransaction(pTab: *Fts5FullTable) c_int {
    var pCsr = pTab.pGlobal.?.pCsr;
    while (pCsr) |pc| : (pCsr = pc.pNext) {
        if (pc.base.pVtab == @as(?*sqlite3_vtab, @ptrCast(pTab))) return SQLITE_OK;
    }
    return sqlite3Fts5StorageReset(pTab.pStorage.?);
}

/// fts5_main.c 19954-19978: xOpen.
fn fts5OpenMethod(pVTab: *sqlite3_vtab, ppCsr: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVTab);
    const pConfig = pTab.p.pConfig.?;
    var pCsr: ?*Fts5Cursor = null;
    var rc: c_int = undefined;

    rc = fts5NewTransaction(pTab);
    if (rc == SQLITE_OK) {
        const nByte: i64 = @as(i64, @sizeOf(Fts5Cursor)) + @as(i64, pConfig.nCol) * @sizeOf(c_int);
        pCsr = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
        if (pCsr) |pc| {
            const pGlobal = pTab.pGlobal.?;
            _ = memset(pc, 0, @intCast(nByte));
            pc.aColumnSize = @ptrCast(@as([*]Fts5Cursor, @ptrCast(pc)) + 1);
            pc.pNext = pGlobal.pCsr;
            pGlobal.pCsr = pc;
            pGlobal.iNextId += 1;
            pc.iCsrId = pGlobal.iNextId;
        } else {
            rc = SQLITE_NOMEM;
        }
    }
    ppCsr.* = @ptrCast(pCsr);
    return rc;
}

fn fts5StmtType(pCsr: *Fts5Cursor) c_int {
    if (pCsr.ePlan == FTS5_PLAN_SCAN) {
        return if (pCsr.bDesc != 0) FTS5_STMT_SCAN_DESC else FTS5_STMT_SCAN_ASC;
    }
    return FTS5_STMT_LOOKUP;
}

fn fts5CsrNewrow(pCsr: *Fts5Cursor) void {
    CsrFlagSet(pCsr, FTS5CSR_REQUIRE_CONTENT | FTS5CSR_REQUIRE_DOCSIZE | FTS5CSR_REQUIRE_INST | FTS5CSR_REQUIRE_POSLIST);
}

fn fts5FreeCursorComponents(pCsr: *Fts5Cursor) void {
    const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);

    sqlite3_free(pCsr.aInstIter);
    sqlite3_free(pCsr.aInst);
    if (pCsr.pStmt) |_| {
        const eStmt = fts5StmtType(pCsr);
        sqlite3Fts5StorageStmtRelease(pTab.pStorage.?, eStmt, pCsr.pStmt);
    }
    if (pCsr.pSorter) |pSorter| {
        _ = sqlite3_finalize(pSorter.pStmt);
        sqlite3_free(pSorter);
    }

    if (pCsr.ePlan != FTS5_PLAN_SOURCE) {
        sqlite3Fts5ExprFree(pCsr.pExpr);
    }

    var pData = pCsr.pAuxdata;
    while (pData) |pd| {
        const pNext = pd.pNext;
        if (pd.xDelete) |xd| xd(pd.pPtr);
        sqlite3_free(pd);
        pData = pNext;
    }

    _ = sqlite3_finalize(pCsr.pRankArgStmt);
    sqlite3_free(@ptrCast(pCsr.apRankArg));

    if (CsrFlagTest(pCsr, FTS5CSR_FREE_ZRANK) != 0) {
        sqlite3_free(pCsr.zRank);
        sqlite3_free(pCsr.zRankArgs);
    }

    sqlite3Fts5IndexCloseReader(pTab.p.pIndex);
    resetCursorTail(pCsr);
}

/// fts5_main.c 20045-20059: xClose.
fn fts5CloseMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pCursor.pVtab.?);
    const pCsr: *Fts5Cursor = @ptrCast(pCursor);

    fts5FreeCursorComponents(pCsr);
    // Remove the cursor from the Fts5Global.pCsr list.
    var pp = &pTab.pGlobal.?.pCsr;
    while (pp.* != pCsr) : (pp = &pp.*.?.pNext) {}
    pp.* = pCsr.pNext;

    sqlite3_free(pCsr);
    return SQLITE_OK;
}

fn fts5SorterNext(pCsr: *Fts5Cursor) c_int {
    const pSorter = pCsr.pSorter.?;
    var rc: c_int = undefined;

    rc = sqlite3_step(pSorter.pStmt);
    if (rc == SQLITE_DONE) {
        rc = SQLITE_OK;
        CsrFlagSet(pCsr, FTS5CSR_EOF | FTS5CSR_REQUIRE_CONTENT);
    } else if (rc == SQLITE_ROW) {
        rc = SQLITE_OK;

        pSorter.iRowid = sqlite3_column_int64(pSorter.pStmt, 0);
        const nBlob = sqlite3_column_bytes(pSorter.pStmt, 1);
        const aBlob: [*]const u8 = @ptrCast(sqlite3_column_blob(pSorter.pStmt, 1));
        var a = aBlob;

        if (nBlob > 0) {
            var iOff: c_int = 0;
            var i: c_int = 0;
            while (i < (pSorter.nIdx - 1)) : (i += 1) {
                var iVal: u32 = undefined;
                a += @intCast(sqlite3Fts5GetVarint32(a, &iVal));
                iOff += @bitCast(iVal);
                sorterIdx(pSorter, i).* = iOff;
            }
            sorterIdx(pSorter, i).* = @intCast(@intFromPtr(aBlob + @as(usize, @intCast(nBlob))) - @intFromPtr(a));
            pSorter.aPoslist = a;
        }

        fts5CsrNewrow(pCsr);
    }

    return rc;
}

fn fts5TripCursors(pTab: *Fts5FullTable) void {
    var pCsr = pTab.pGlobal.?.pCsr;
    while (pCsr) |pc| : (pCsr = pc.pNext) {
        if (pc.ePlan == FTS5_PLAN_MATCH and pc.base.pVtab == @as(?*sqlite3_vtab, @ptrCast(pTab))) {
            CsrFlagSet(pc, FTS5CSR_REQUIRE_RESEEK);
        }
    }
}

fn fts5CursorReseek(pCsr: *Fts5Cursor, pbSkip: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (CsrFlagTest(pCsr, FTS5CSR_REQUIRE_RESEEK) != 0) {
        const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);
        const bDesc = pCsr.bDesc;
        const iRowid = sqlite3Fts5ExprRowid(pCsr.pExpr);

        rc = sqlite3Fts5ExprFirst(pCsr.pExpr, pTab.p.pIndex, iRowid, pCsr.iLastRowid, bDesc);
        if (rc == SQLITE_OK and iRowid != sqlite3Fts5ExprRowid(pCsr.pExpr)) {
            pbSkip.* = 1;
        }

        CsrFlagClear(pCsr, FTS5CSR_REQUIRE_RESEEK);
        fts5CsrNewrow(pCsr);
        if (sqlite3Fts5ExprEof(pCsr.pExpr) != 0) {
            CsrFlagSet(pCsr, FTS5CSR_EOF);
            pbSkip.* = 1;
        }
    }
    return rc;
}

/// fts5_main.c 20161-20222: xNext.
fn fts5NextMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(pCursor);
    var rc: c_int = undefined;

    if (pCsr.ePlan == FTS5_PLAN_MATCH and
        @as(*Fts5Table, @ptrCast(pCursor.pVtab.?)).pConfig.?.bTokendata != 0)
    {
        sqlite3Fts5ExprClearTokens(pCsr.pExpr);
    }

    if (pCsr.ePlan < 3) {
        var bSkip: c_int = 0;
        rc = fts5CursorReseek(pCsr, &bSkip);
        if (rc != 0 or bSkip != 0) return rc;
        rc = sqlite3Fts5ExprNext(pCsr.pExpr, pCsr.iLastRowid);
        CsrFlagSet(pCsr, sqlite3Fts5ExprEof(pCsr.pExpr));
        fts5CsrNewrow(pCsr);
    } else {
        switch (pCsr.ePlan) {
            FTS5_PLAN_SPECIAL => {
                CsrFlagSet(pCsr, FTS5CSR_EOF);
                rc = SQLITE_OK;
            },
            FTS5_PLAN_SORTED_MATCH => {
                rc = fts5SorterNext(pCsr);
            },
            else => {
                const pConfig = @as(*Fts5Table, @ptrCast(pCursor.pVtab.?)).pConfig.?;
                pConfig.bLock += 1;
                rc = sqlite3_step(pCsr.pStmt);
                pConfig.bLock -= 1;
                if (rc != SQLITE_ROW) {
                    CsrFlagSet(pCsr, FTS5CSR_EOF);
                    rc = sqlite3_reset(pCsr.pStmt);
                    if (rc != SQLITE_OK) {
                        pCursor.pVtab.?.zErrMsg = sqlite3_mprintf("%s", sqlite3_errmsg(pConfig.db));
                    }
                } else {
                    rc = SQLITE_OK;
                    CsrFlagSet(pCsr, FTS5CSR_REQUIRE_DOCSIZE);
                }
            },
        }
    }

    return rc;
}

fn fts5PrepareStatement(ppStmt: *?*sqlite3_stmt, pConfig: *Fts5Config, zFmt: [*:0]const u8, ...) callconv(.c) c_int {
    var pRet: ?*sqlite3_stmt = null;
    var rc: c_int = undefined;

    var ap = @cVaStart();
    const zSql = sqlite3_vmprintf(zFmt, @ptrCast(&ap));
    @cVaEnd(&ap);
    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else {
        rc = sqlite3_prepare_v3(pConfig.db, zSql.?, -1, 0x01, &pRet, null); // SQLITE_PREPARE_PERSISTENT
        if (rc != SQLITE_OK) {
            sqlite3Fts5ConfigErrmsg(pConfig, "%s", sqlite3_errmsg(pConfig.db));
        }
        sqlite3_free(zSql);
    }

    ppStmt.* = pRet;
    return rc;
}

fn fts5CursorFirstSorted(pTab: *Fts5FullTable, pCsr: *Fts5Cursor, bDesc: c_int) c_int {
    const pConfig = pTab.p.pConfig.?;
    var rc: c_int = undefined;
    const zRank = pCsr.zRank;
    const zRankArgs = pCsr.zRankArgs;

    const nPhrase = sqlite3Fts5ExprPhraseCount(pCsr.pExpr);
    const nByte = SZ_FTS5SORTER(nPhrase);
    const pSorter: ?*Fts5Sorter = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
    if (pSorter == null) return SQLITE_NOMEM;
    const ps = pSorter.?;
    _ = memset(ps, 0, @intCast(nByte));
    ps.nIdx = nPhrase;

    rc = fts5PrepareStatement(&ps.pStmt, pConfig, "SELECT rowid, rank FROM %Q.%Q ORDER BY %s(\"%w\"%s%s) %s", pConfig.zDb, pConfig.zName, zRank, pConfig.zName, if (zRankArgs != null) @as([*:0]const u8, ", ") else @as([*:0]const u8, ""), if (zRankArgs) |z| @as([*:0]const u8, z) else @as([*:0]const u8, ""), if (bDesc != 0) @as([*:0]const u8, "DESC") else @as([*:0]const u8, "ASC"));

    pCsr.pSorter = ps;
    if (rc == SQLITE_OK) {
        pTab.pSortCsr = pCsr;
        rc = fts5SorterNext(pCsr);
        pTab.pSortCsr = null;
    }

    if (rc != SQLITE_OK) {
        _ = sqlite3_finalize(ps.pStmt);
        sqlite3_free(ps);
        pCsr.pSorter = null;
    }

    return rc;
}

fn fts5CursorFirst(pTab: *Fts5FullTable, pCsr: *Fts5Cursor, bDesc: c_int) c_int {
    const pExpr = pCsr.pExpr;
    const rc = sqlite3Fts5ExprFirst(pExpr, pTab.p.pIndex, pCsr.iFirstRowid, pCsr.iLastRowid, bDesc);
    if (sqlite3Fts5ExprEof(pExpr) != 0) {
        CsrFlagSet(pCsr, FTS5CSR_EOF);
    }
    fts5CsrNewrow(pCsr);
    return rc;
}

/// fts5_main.c 20325-20353: process a "special" (`*...`) query.
fn fts5SpecialMatch(pTab: *Fts5FullTable, pCsr: *Fts5Cursor, zQuery: [*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    var z = zQuery;
    var n: c_int = 0;

    while (z[0] == ' ') z += 1;
    while (z[@intCast(n)] != 0 and z[@intCast(n)] != ' ') n += 1;

    pCsr.ePlan = FTS5_PLAN_SPECIAL;

    if (n == 5 and 0 == sqlite3_strnicmp("reads", z, n)) {
        pCsr.iSpecial = sqlite3Fts5IndexReads(pTab.p.pIndex);
    } else if (n == 2 and 0 == sqlite3_strnicmp("id", z, n)) {
        pCsr.iSpecial = pCsr.iCsrId;
    } else {
        pTab.p.base.zErrMsg = sqlite3_mprintf("unknown special query: %.*s", n, z);
        rc = SQLITE_ERROR;
    }

    return rc;
}

fn fts5FindAuxiliary(pTab: *Fts5FullTable, zName: [*:0]const u8) ?*Fts5Auxiliary {
    var pAux = pTab.pGlobal.?.pAux;
    while (pAux) |pa| : (pAux = pa.pNext) {
        if (sqlite3_stricmp(zName, pa.zFunc.?) == 0) return pa;
    }
    return null;
}

fn fts5FindRankFunction(pCsr: *Fts5Cursor) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);
    const pConfig = pTab.p.pConfig.?;
    var rc: c_int = SQLITE_OK;
    var pAux: ?*Fts5Auxiliary = null;
    const zRank = pCsr.zRank.?;
    const zRankArgs = pCsr.zRankArgs;

    if (zRankArgs) |zra| {
        const zSql = sqlite3Fts5Mprintf(&rc, "SELECT %s", zra);
        if (zSql) |zs| {
            var pStmt: ?*sqlite3_stmt = null;
            rc = sqlite3_prepare_v3(pConfig.db, zs, -1, 0x01, &pStmt, null);
            sqlite3_free(zs);
            if (rc == SQLITE_OK) {
                if (SQLITE_ROW == sqlite3_step(pStmt)) {
                    pCsr.nRankArg = sqlite3_column_count(pStmt);
                    const nByte: i64 = @as(i64, @sizeOf(?*sqlite3_value)) * pCsr.nRankArg;
                    pCsr.apRankArg = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
                    if (rc == SQLITE_OK) {
                        var i: c_int = 0;
                        while (i < pCsr.nRankArg) : (i += 1) {
                            pCsr.apRankArg.?[@intCast(i)] = sqlite3_column_value(pStmt, i);
                        }
                    }
                    pCsr.pRankArgStmt = pStmt;
                } else {
                    rc = sqlite3_finalize(pStmt);
                }
            }
        }
    }

    if (rc == SQLITE_OK) {
        pAux = fts5FindAuxiliary(pTab, zRank);
        if (pAux == null) {
            pTab.p.base.zErrMsg = sqlite3_mprintf("no such function: %s", zRank);
            rc = SQLITE_ERROR;
        }
    }

    pCsr.pRank = pAux;
    return rc;
}

fn fts5CursorParseRank(pConfig: *Fts5Config, pCsr: *Fts5Cursor, pRank: ?*sqlite3_value) c_int {
    var rc: c_int = SQLITE_OK;
    if (pRank) |pr| {
        const z = sqlite3_value_text(pr);
        var zRank: ?[*:0]u8 = null;
        var zRankArgs: ?[*:0]u8 = null;

        if (z == null) {
            if (sqlite3_value_type(pr) == SQLITE_NULL) rc = SQLITE_ERROR;
        } else {
            rc = sqlite3Fts5ConfigParseRank(z.?, &zRank, &zRankArgs);
        }
        if (rc == SQLITE_OK) {
            pCsr.zRank = zRank;
            pCsr.zRankArgs = zRankArgs;
            CsrFlagSet(pCsr, FTS5CSR_FREE_ZRANK);
        } else if (rc == SQLITE_ERROR) {
            pCsr.base.pVtab.?.zErrMsg = sqlite3_mprintf("parse error in rank function: %s", z);
        }
    } else {
        if (pConfig.zRank) |zr| {
            pCsr.zRank = zr;
            pCsr.zRankArgs = pConfig.zRankArgs;
        } else {
            pCsr.zRank = @constCast(FTS5_DEFAULT_RANK);
            pCsr.zRankArgs = null;
        }
    }
    return rc;
}

fn fts5GetRowidLimit(pVal: ?*sqlite3_value, iDefault: i64) i64 {
    if (pVal) |pv| {
        const eType = sqlite3_value_numeric_type(pv);
        if (eType == SQLITE_INTEGER) {
            return sqlite3_value_int64(pv);
        }
    }
    return iDefault;
}

fn fts5SetVtabError(p: *Fts5FullTable, zFormat: [*:0]const u8, ...) callconv(.c) void {
    var ap = @cVaStart();
    sqlite3_free(p.p.base.zErrMsg);
    p.p.base.zErrMsg = sqlite3_vmprintf(zFormat, @ptrCast(&ap));
    @cVaEnd(&ap);
}

/// fts5_main.c 20487-20495.
export fn sqlite3Fts5SetLocale(pConfig: *Fts5Config, zLocale: ?[*]const u8, nLocale: c_int) callconv(.c) void {
    const pT = &pConfig.t;
    pT.pLocale = zLocale;
    pT.nLocale = nLocale;
}

/// fts5_main.c 20500-20502.
export fn sqlite3Fts5ClearLocale(pConfig: *Fts5Config) callconv(.c) void {
    sqlite3Fts5SetLocale(pConfig, null, 0);
}

/// fts5_main.c 20508-20526: true if pVal is an fts5_locale() value.
export fn sqlite3Fts5IsLocaleValue(pConfig: *Fts5Config, pVal: ?*sqlite3_value) callconv(.c) c_int {
    var ret: c_int = 0;
    if (sqlite3_value_type(pVal) == SQLITE_BLOB) {
        const pBlob: ?[*]const u8 = @ptrCast(sqlite3_value_blob(pVal));
        const nBlob = sqlite3_value_bytes(pVal);
        if (nBlob > FTS5_LOCALE_HDR_SIZE and
            0 == memcmp(pBlob, FTS5_LOCALE_HDR(pConfig), @intCast(FTS5_LOCALE_HDR_SIZE)))
        {
            ret = 1;
        }
    }
    return ret;
}

/// fts5_main.c 20541-20566: decode an fts5_locale() value.
export fn sqlite3Fts5DecodeLocaleValue(
    pVal: ?*sqlite3_value,
    ppText: *?[*]const u8,
    pnText: *c_int,
    ppLoc: *?[*]const u8,
    pnLoc: *c_int,
) callconv(.c) c_int {
    const p: [*]const u8 = @ptrCast(sqlite3_value_blob(pVal));
    const n = sqlite3_value_bytes(pVal);
    var nLoc: c_int = FTS5_LOCALE_HDR_SIZE;

    while (p[@intCast(nLoc)] != 0) : (nLoc += 1) {
        if (nLoc == (n - 1)) {
            return SQLITE_MISMATCH;
        }
    }
    ppLoc.* = p + @as(usize, @intCast(FTS5_LOCALE_HDR_SIZE));
    pnLoc.* = nLoc - FTS5_LOCALE_HDR_SIZE;

    ppText.* = p + @as(usize, @intCast(nLoc + 1));
    pnText.* = n - nLoc - 1;
    return SQLITE_OK;
}

/// fts5_main.c 20581-20606: extract MATCH expression text (handle locale).
fn fts5ExtractExprText(pConfig: *Fts5Config, pVal: ?*sqlite3_value, pzText: *?[*:0]u8, pbFreeAndReset: *c_int) c_int {
    var rc: c_int = SQLITE_OK;

    if (sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
        var pText: ?[*]const u8 = null;
        var nText: c_int = 0;
        var pLoc: ?[*]const u8 = null;
        var nLoc: c_int = 0;
        rc = sqlite3Fts5DecodeLocaleValue(pVal, &pText, &nText, &pLoc, &nLoc);
        pzText.* = sqlite3Fts5Mprintf(&rc, "%.*s", nText, pText);
        if (rc == SQLITE_OK) {
            sqlite3Fts5SetLocale(pConfig, pLoc, nLoc);
        }
        pbFreeAndReset.* = 1;
    } else {
        pzText.* = @constCast(sqlite3_value_text(pVal));
        pbFreeAndReset.* = 0;
    }

    return rc;
}

/// fts5_main.c 20620-20820: xFilter.
fn fts5FilterMethod(
    pCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr0: ?[*:0]const u8,
    nVal: c_int,
    apVal0: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pCursor.pVtab.?);
    const pConfig = pTab.p.pConfig.?;
    const pCsr: *Fts5Cursor = @ptrCast(pCursor);
    var rc: c_int = SQLITE_OK;
    var bDesc: c_int = undefined;
    var bOrderByRank: c_int = undefined;
    var pRank: ?*sqlite3_value = null;
    var pRowidEq: ?*sqlite3_value = null;
    var pRowidLe: ?*sqlite3_value = null;
    var pRowidGe: ?*sqlite3_value = null;
    var iCol: c_int = undefined;
    const pzErrmsg = pConfig.pzErrmsg;
    const bPrefixInsttoken = pConfig.bPrefixInsttoken;
    var i: c_int = 0;
    var iIdxStr: c_int = 0;
    var pExpr: ?*Fts5Expr = null;

    const idxStr = idxStr0.?;
    const apVal = apVal0.?;

    if (pCsr.ePlan != 0) {
        fts5FreeCursorComponents(pCsr);
        resetCursorTail(pCsr);
    }

    pConfig.pzErrmsg = &pTab.p.base.zErrMsg;

    // Decode the arguments.
    i = 0;
    while (i < nVal) : (i += 1) {
        const c = idxStr[@intCast(iIdxStr)];
        iIdxStr += 1;
        switch (c) {
            'r' => {
                pRank = apVal[@intCast(i)];
            },
            'M' => {
                var zText: ?[*:0]const u8 = null;
                var bFreeAndReset: c_int = 0;
                var bInternal: c_int = 0;

                var zT: ?[*:0]u8 = null;
                rc = fts5ExtractExprText(pConfig, apVal[@intCast(i)], &zT, &bFreeAndReset);
                if (rc != SQLITE_OK) {
                    return fts5FilterOut(pConfig, pzErrmsg, bPrefixInsttoken, pExpr, rc);
                }
                zText = zT;
                if (zText == null) zText = "";
                if (sqlite3_value_subtype(apVal[@intCast(i)]) == FTS5_INSTTOKEN_SUBTYPE) {
                    pConfig.bPrefixInsttoken = 1;
                }

                iCol = 0;
                while (true) {
                    iCol = iCol * 10 + (idxStr[@intCast(iIdxStr)] - '0');
                    iIdxStr += 1;
                    if (!(idxStr[@intCast(iIdxStr)] >= '0' and idxStr[@intCast(iIdxStr)] <= '9')) break;
                }

                if (zText.?[0] == '*') {
                    rc = fts5SpecialMatch(pTab, pCsr, zText.? + 1);
                    bInternal = 1;
                } else {
                    rc = sqlite3Fts5ExprNew(pConfig, 0, iCol, zText.?, &pExpr, &pTab.p.base.zErrMsg);
                    if (rc == SQLITE_OK) {
                        rc = sqlite3Fts5ExprAnd(&pCsr.pExpr, pExpr);
                        pExpr = null;
                    }
                }

                if (bFreeAndReset != 0) {
                    sqlite3_free(zT);
                    sqlite3Fts5ClearLocale(pConfig);
                }

                if (bInternal != 0 or rc != SQLITE_OK) {
                    return fts5FilterOut(pConfig, pzErrmsg, bPrefixInsttoken, pExpr, rc);
                }
            },
            'L', 'G' => {
                const bGlob: c_int = @intFromBool(idxStr[@intCast(iIdxStr - 1)] == 'G');
                const zText = sqlite3_value_text(apVal[@intCast(i)]);
                iCol = 0;
                while (true) {
                    iCol = iCol * 10 + (idxStr[@intCast(iIdxStr)] - '0');
                    iIdxStr += 1;
                    if (!(idxStr[@intCast(iIdxStr)] >= '0' and idxStr[@intCast(iIdxStr)] <= '9')) break;
                }
                if (zText) |zt| {
                    rc = sqlite3Fts5ExprPattern(pConfig, bGlob, iCol, zt, &pExpr);
                }
                if (rc == SQLITE_OK) {
                    rc = sqlite3Fts5ExprAnd(&pCsr.pExpr, pExpr);
                    pExpr = null;
                }
                if (rc != SQLITE_OK) {
                    return fts5FilterOut(pConfig, pzErrmsg, bPrefixInsttoken, pExpr, rc);
                }
            },
            '=' => {
                pRowidEq = apVal[@intCast(i)];
            },
            '<' => {
                pRowidLe = apVal[@intCast(i)];
            },
            else => { // '>'
                pRowidGe = apVal[@intCast(i)];
            },
        }
    }
    bOrderByRank = if ((idxNum & FTS5_BI_ORDER_RANK) != 0) 1 else 0;
    bDesc = if ((idxNum & FTS5_BI_ORDER_DESC) != 0) 1 else 0;
    pCsr.bDesc = bDesc;

    if (pRowidEq != null) {
        pRowidLe = pRowidEq;
        pRowidGe = pRowidEq;
    }
    if (bDesc != 0) {
        pCsr.iFirstRowid = fts5GetRowidLimit(pRowidLe, LARGEST_INT64);
        pCsr.iLastRowid = fts5GetRowidLimit(pRowidGe, SMALLEST_INT64);
    } else {
        pCsr.iLastRowid = fts5GetRowidLimit(pRowidLe, LARGEST_INT64);
        pCsr.iFirstRowid = fts5GetRowidLimit(pRowidGe, SMALLEST_INT64);
    }

    rc = sqlite3Fts5IndexLoadConfig(pTab.p.pIndex);
    if (rc != SQLITE_OK) return fts5FilterOut(pConfig, pzErrmsg, bPrefixInsttoken, pExpr, rc);

    if (pTab.pSortCsr) |pSortCsr| {
        if (pSortCsr.bDesc != 0) {
            pCsr.iLastRowid = pSortCsr.iFirstRowid;
            pCsr.iFirstRowid = pSortCsr.iLastRowid;
        } else {
            pCsr.iLastRowid = pSortCsr.iLastRowid;
            pCsr.iFirstRowid = pSortCsr.iFirstRowid;
        }
        pCsr.ePlan = FTS5_PLAN_SOURCE;
        pCsr.pExpr = pSortCsr.pExpr;
        rc = fts5CursorFirst(pTab, pCsr, bDesc);
    } else if (pCsr.pExpr != null) {
        rc = fts5CursorParseRank(pConfig, pCsr, pRank);
        if (rc == SQLITE_OK) {
            if (bOrderByRank != 0) {
                pCsr.ePlan = FTS5_PLAN_SORTED_MATCH;
                rc = fts5CursorFirstSorted(pTab, pCsr, bDesc);
            } else {
                pCsr.ePlan = FTS5_PLAN_MATCH;
                rc = fts5CursorFirst(pTab, pCsr, bDesc);
            }
        }
    } else if (pConfig.zContent == null) {
        fts5SetVtabError(pTab, "%s: table does not support scanning", pConfig.zName);
        rc = SQLITE_ERROR;
    } else {
        pCsr.ePlan = if (pRowidEq != null) FTS5_PLAN_ROWID else FTS5_PLAN_SCAN;
        rc = sqlite3Fts5StorageStmt(pTab.pStorage.?, fts5StmtType(pCsr), &pCsr.pStmt, &pTab.p.base.zErrMsg);
        if (rc == SQLITE_OK) {
            if (pRowidEq != null) {
                _ = sqlite3_bind_value(pCsr.pStmt, 1, pRowidEq);
            } else {
                _ = sqlite3_bind_int64(pCsr.pStmt, 1, pCsr.iFirstRowid);
                _ = sqlite3_bind_int64(pCsr.pStmt, 2, pCsr.iLastRowid);
            }
            rc = fts5NextMethod(pCursor);
        }
    }

    return fts5FilterOut(pConfig, pzErrmsg, bPrefixInsttoken, pExpr, rc);
}

/// The `filter_out:` cleanup tail of fts5FilterMethod, factored out because Zig
/// has no goto. Frees pExpr, restores pConfig fields, returns rc.
fn fts5FilterOut(pConfig: *Fts5Config, pzErrmsg: ?*?[*:0]u8, bPrefixInsttoken: c_int, pExpr: ?*Fts5Expr, rc: c_int) c_int {
    sqlite3Fts5ExprFree(pExpr);
    pConfig.pzErrmsg = pzErrmsg;
    pConfig.bPrefixInsttoken = bPrefixInsttoken;
    return rc;
}

fn fts5EofMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(pCursor);
    return if (CsrFlagTest(pCsr, FTS5CSR_EOF) != 0) 1 else 0;
}

fn fts5CursorRowid(pCsr: *Fts5Cursor) i64 {
    if (pCsr.pSorter) |pSorter| {
        return pSorter.iRowid;
    } else if (pCsr.ePlan >= FTS5_PLAN_SCAN) {
        return sqlite3_column_int64(pCsr.pStmt, 0);
    } else {
        return sqlite3Fts5ExprRowid(pCsr.pExpr);
    }
}

fn fts5RowidMethod(pCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(pCursor);
    const ePlan = pCsr.ePlan;

    if (ePlan == FTS5_PLAN_SPECIAL) {
        pRowid.* = 0;
    } else {
        pRowid.* = fts5CursorRowid(pCsr);
    }
    return SQLITE_OK;
}

/// fts5_main.c 20878-20920: seek the cursor's content statement.
fn fts5SeekCursor(pCsr: *Fts5Cursor, bErrormsg: c_int) c_int {
    var rc: c_int = SQLITE_OK;

    if (pCsr.pStmt == null) {
        const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);
        const eStmt = fts5StmtType(pCsr);
        rc = sqlite3Fts5StorageStmt(pTab.pStorage.?, eStmt, &pCsr.pStmt, if (bErrormsg != 0) &pTab.p.base.zErrMsg else null);
    }

    if (rc == SQLITE_OK and CsrFlagTest(pCsr, FTS5CSR_REQUIRE_CONTENT) != 0) {
        const pTab: *Fts5Table = @ptrCast(pCsr.base.pVtab.?);
        _ = sqlite3_reset(pCsr.pStmt);
        _ = sqlite3_bind_int64(pCsr.pStmt, 1, fts5CursorRowid(pCsr));
        pTab.pConfig.?.bLock += 1;
        rc = sqlite3_step(pCsr.pStmt);
        pTab.pConfig.?.bLock -= 1;
        if (rc == SQLITE_ROW) {
            rc = SQLITE_OK;
            CsrFlagClear(pCsr, FTS5CSR_REQUIRE_CONTENT);
        } else {
            rc = sqlite3_reset(pCsr.pStmt);
            if (rc == SQLITE_OK) {
                rc = FTS5_CORRUPT;
                fts5SetVtabError(@ptrCast(pTab), "fts5: missing row %lld from content table %s", fts5CursorRowid(pCsr), pTab.pConfig.?.zContent);
            } else if (pTab.pConfig.?.pzErrmsg != null) {
                fts5SetVtabError(@ptrCast(pTab), "%s", sqlite3_errmsg(pTab.pConfig.?.db));
            }
        }
    }
    return rc;
}

/// fts5_main.c 20937-21005: FTS INSERT-command dispatch (delete-all/rebuild/…).
fn fts5SpecialInsert(pTab: *Fts5FullTable, zCmd: [*:0]const u8, pVal: ?*sqlite3_value) c_int {
    const pConfig = pTab.p.pConfig.?;
    var rc: c_int = SQLITE_OK;
    var bError: c_int = 0;
    var bLoadConfig: c_int = 0;

    if (0 == sqlite3_stricmp("delete-all", zCmd)) {
        if (pConfig.eContent == FTS5_CONTENT_NORMAL) {
            fts5SetVtabError(pTab, "'delete-all' may only be used with a contentless or external content fts5 table");
            rc = SQLITE_ERROR;
        } else {
            rc = sqlite3Fts5StorageDeleteAll(pTab.pStorage.?);
        }
        bLoadConfig = 1;
    } else if (0 == sqlite3_stricmp("rebuild", zCmd)) {
        if (fts5IsContentless(pTab, 1) != 0) {
            fts5SetVtabError(pTab, "'rebuild' may not be used with a contentless fts5 table");
            rc = SQLITE_ERROR;
        } else {
            rc = sqlite3Fts5StorageRebuild(pTab.pStorage.?);
        }
        bLoadConfig = 1;
    } else if (0 == sqlite3_stricmp("optimize", zCmd)) {
        rc = sqlite3Fts5StorageOptimize(pTab.pStorage.?);
    } else if (0 == sqlite3_stricmp("merge", zCmd)) {
        const nMerge = sqlite3_value_int(pVal);
        rc = sqlite3Fts5StorageMerge(pTab.pStorage.?, nMerge);
    } else if (0 == sqlite3_stricmp("integrity-check", zCmd)) {
        const iArg = sqlite3_value_int(pVal);
        rc = sqlite3Fts5StorageIntegrity(pTab.pStorage.?, iArg);
    } else if (config.sqlite_debug and 0 == sqlite3_stricmp("prefix-index", zCmd)) {
        if (config.sqlite_debug) pConfig.bPrefixIndex = sqlite3_value_int(pVal);
    } else if (0 == sqlite3_stricmp("flush", zCmd)) {
        rc = sqlite3Fts5FlushToDisk(&pTab.p);
    } else {
        rc = sqlite3Fts5FlushToDisk(&pTab.p);
        if (rc == SQLITE_OK) {
            rc = sqlite3Fts5IndexLoadConfig(pTab.p.pIndex);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3Fts5ConfigSetValue(pTab.p.pConfig.?, zCmd, pVal, &bError);
        }
        if (rc == SQLITE_OK) {
            if (bError != 0) {
                rc = SQLITE_ERROR;
            } else {
                rc = sqlite3Fts5StorageConfigValue(pTab.pStorage.?, zCmd, pVal, 0);
            }
        }
    }

    if (rc == SQLITE_OK and bLoadConfig != 0) {
        pTab.p.pConfig.?.iCookie -= 1;
        rc = sqlite3Fts5IndexLoadConfig(pTab.p.pIndex);
    }

    return rc;
}

fn fts5SpecialDelete(pTab: *Fts5FullTable, apVal: [*]?*sqlite3_value) c_int {
    var rc: c_int = SQLITE_OK;
    const eType1 = sqlite3_value_type(apVal[1]);
    if (eType1 == SQLITE_INTEGER) {
        const iDel = sqlite3_value_int64(apVal[1]);
        rc = sqlite3Fts5StorageDelete(pTab.pStorage.?, iDel, apVal + 2, 0);
    }
    return rc;
}

fn fts5StorageInsert(pRc: *c_int, pTab: *Fts5FullTable, apVal: [*]?*sqlite3_value, piRowid: *i64) void {
    var rc = pRc.*;
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5StorageContentInsert(pTab.pStorage.?, 0, apVal, piRowid);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5StorageIndexInsert(pTab.pStorage.?, apVal, piRowid.*);
    }
    pRc.* = rc;
}

/// fts5_main.c 21059-21095: validate a contentless-table UPDATE.
fn fts5ContentlessUpdate(pConfig: *Fts5Config, apVal: [*]?*sqlite3_value, bRowidModified: c_int, pbContent: *c_int) c_int {
    var bSeenIndex: c_int = 0;
    var bSeenIndexNC: c_int = 0;
    var rc: c_int = SQLITE_OK;

    var ii: c_int = 0;
    while (ii < pConfig.nCol) : (ii += 1) {
        if (pConfig.abUnindexed.?[@intCast(ii)] == 0) {
            if (sqlite3_value_nochange(apVal[@intCast(ii)]) != 0) {
                bSeenIndexNC += 1;
            } else {
                bSeenIndex += 1;
            }
        }
    }

    if (bSeenIndex == 0 and bRowidModified == 0) {
        pbContent.* = 1;
    } else {
        if (bSeenIndexNC != 0 or pConfig.bContentlessDelete == 0) {
            rc = SQLITE_ERROR;
            sqlite3Fts5ConfigErrmsg(pConfig, if (pConfig.bContentlessDelete != 0)
                @as([*:0]const u8, "%s a subset of columns on fts5 contentless-delete table: %s")
            else
                @as([*:0]const u8, "%s contentless fts5 table: %s"), @as([*:0]const u8, "cannot UPDATE"), pConfig.zName);
        }
    }

    return rc;
}

/// fts5_main.c 21111-21282: xUpdate.
fn fts5UpdateMethod(pVtab: *sqlite3_vtab, nArg: c_int, apVal0: ?[*]?*sqlite3_value, pRowid: *i64) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    const pConfig = pTab.p.pConfig.?;
    const apVal = apVal0.?;
    var eType0: c_int = undefined;
    var rc: c_int = SQLITE_OK;

    if (pConfig.pgsz == 0) {
        rc = sqlite3Fts5ConfigLoad(pTab.p.pConfig.?, pTab.p.pConfig.?.iCookie);
        if (rc != SQLITE_OK) return rc;
    }

    pTab.p.pConfig.?.pzErrmsg = &pTab.p.base.zErrMsg;

    fts5TripCursors(pTab);

    eType0 = sqlite3_value_type(apVal[0]);
    if (eType0 == SQLITE_NULL and
        sqlite3_value_type(apVal[@intCast(2 + pConfig.nCol)]) != SQLITE_NULL)
    {
        // A "special" INSERT op.
        const z = sqlite3_value_text(apVal[@intCast(2 + pConfig.nCol)]).?;
        if (pConfig.eContent != FTS5_CONTENT_NORMAL and 0 == sqlite3_stricmp("delete", z)) {
            if (pConfig.bContentlessDelete != 0) {
                fts5SetVtabError(pTab, "'delete' may not be used with a contentless_delete=1 table");
                rc = SQLITE_ERROR;
            } else {
                rc = fts5SpecialDelete(pTab, apVal);
            }
        } else {
            rc = fts5SpecialInsert(pTab, z, apVal[@intCast(2 + pConfig.nCol + 1)]);
        }
    } else {
        var eConflict: c_int = SQLITE_ABORT;
        if (pConfig.eContent == FTS5_CONTENT_NORMAL or pConfig.bContentlessDelete != 0) {
            eConflict = sqlite3_vtab_on_conflict(pConfig.db);
        }

        // DELETE
        if (nArg == 1) {
            if (fts5IsContentless(pTab, 1) != 0 and pConfig.bContentlessDelete == 0) {
                fts5SetVtabError(pTab, "cannot DELETE from contentless fts5 table: %s", pConfig.zName);
                rc = SQLITE_ERROR;
            } else {
                const iDel = sqlite3_value_int64(apVal[0]);
                rc = sqlite3Fts5StorageDelete(pTab.pStorage.?, iDel, null, 0);
            }
        }

        // INSERT or UPDATE
        else {
            const eType1 = sqlite3_value_numeric_type(apVal[1]);

            if (pConfig.bLocale == 0) {
                var ii: c_int = 0;
                while (ii < pConfig.nCol) : (ii += 1) {
                    const pVal = apVal[@intCast(ii + 2)];
                    if (sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
                        fts5SetVtabError(pTab, "fts5_locale() requires locale=1");
                        rc = SQLITE_MISMATCH;
                        return fts5UpdateOut(pTab, rc);
                    }
                }
            }

            if (eType0 != SQLITE_INTEGER) {
                // INSERT
                if (eConflict == SQLITE_REPLACE and eType1 == SQLITE_INTEGER) {
                    const iNew = sqlite3_value_int64(apVal[1]);
                    rc = sqlite3Fts5StorageDelete(pTab.pStorage.?, iNew, null, 0);
                }
                fts5StorageInsert(&rc, pTab, apVal, pRowid);
            }

            // UPDATE
            else {
                const pStorage = pTab.pStorage.?;
                const iOld = sqlite3_value_int64(apVal[0]);
                const iNew = sqlite3_value_int64(apVal[1]);
                var bContent: c_int = 0;

                if (fts5IsContentless(pTab, 1) != 0) {
                    rc = fts5ContentlessUpdate(pConfig, apVal + 2, @intFromBool(iOld != iNew), &bContent);
                    if (rc != SQLITE_OK) return fts5UpdateOut(pTab, rc);
                }

                if (eType1 != SQLITE_INTEGER) {
                    rc = SQLITE_MISMATCH;
                } else if (iOld != iNew) {
                    if (eConflict == SQLITE_REPLACE) {
                        rc = sqlite3Fts5StorageDelete(pStorage, iOld, null, 1);
                        if (rc == SQLITE_OK) {
                            rc = sqlite3Fts5StorageDelete(pStorage, iNew, null, 0);
                        }
                        fts5StorageInsert(&rc, pTab, apVal, pRowid);
                    } else {
                        rc = sqlite3Fts5StorageFindDeleteRow(pStorage, iOld);
                        if (rc == SQLITE_OK) {
                            rc = sqlite3Fts5StorageContentInsert(pStorage, 0, apVal, pRowid);
                        }
                        if (rc == SQLITE_OK) {
                            rc = sqlite3Fts5StorageDelete(pStorage, iOld, null, 0);
                        }
                        if (rc == SQLITE_OK) {
                            rc = sqlite3Fts5StorageIndexInsert(pStorage, apVal, pRowid.*);
                        }
                    }
                } else if (bContent != 0) {
                    rc = sqlite3Fts5StorageFindDeleteRow(pStorage, iOld);
                    if (rc == SQLITE_OK) {
                        rc = sqlite3Fts5StorageContentInsert(pStorage, 1, apVal, pRowid);
                    }
                } else {
                    rc = sqlite3Fts5StorageDelete(pStorage, iOld, null, 1);
                    fts5StorageInsert(&rc, pTab, apVal, pRowid);
                }
                sqlite3Fts5StorageReleaseDeleteRow(pStorage);
            }
        }
    }

    return fts5UpdateOut(pTab, rc);
}

/// The `update_out:` cleanup tail of fts5UpdateMethod (Zig has no goto).
fn fts5UpdateOut(pTab: *Fts5FullTable, rc: c_int) c_int {
    sqlite3Fts5IndexCloseReader(pTab.p.pIndex);
    pTab.p.pConfig.?.pzErrmsg = null;
    return rc;
}

fn fts5SyncMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    fts5CheckTransactionState(pTab, FTS5_SYNC, 0);
    pTab.p.pConfig.?.pzErrmsg = &pTab.p.base.zErrMsg;
    const rc = sqlite3Fts5FlushToDisk(&pTab.p);
    pTab.p.pConfig.?.pzErrmsg = null;
    return rc;
}

fn fts5BeginMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const rc = fts5NewTransaction(@ptrCast(pVtab));
    if (rc == SQLITE_OK) {
        fts5CheckTransactionState(@ptrCast(pVtab), FTS5_BEGIN, 0);
    }
    return rc;
}

fn fts5CommitMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    fts5CheckTransactionState(@ptrCast(pVtab), FTS5_COMMIT, 0);
    return SQLITE_OK;
}

fn fts5RollbackMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    fts5CheckTransactionState(pTab, FTS5_ROLLBACK, 0);
    const rc = sqlite3Fts5StorageRollback(pTab.pStorage.?);
    pTab.p.pConfig.?.pgsz = 0;
    return rc;
}

fn fts5ApiUserData(pCtx: ?*Fts5Context) callconv(.c) ?*anyopaque {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    return pCsr.pAux.?.pUserData;
}

fn fts5ApiColumnCount(pCtx: ?*Fts5Context) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    return @as(*Fts5Table, @ptrCast(pCsr.base.pVtab.?)).pConfig.?.nCol;
}

fn fts5ApiColumnTotalSize(pCtx: ?*Fts5Context, iCol: c_int, pnToken: *i64) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);
    return sqlite3Fts5StorageSize(pTab.pStorage.?, iCol, pnToken);
}

fn fts5ApiRowCount(pCtx: ?*Fts5Context, pnRow: *i64) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);
    return sqlite3Fts5StorageRowCount(pTab.pStorage.?, pnRow);
}

fn fts5ApiTokenize_v2(
    pCtx: ?*Fts5Context,
    pText: ?[*]const u8,
    nText: c_int,
    pLoc: ?[*]const u8,
    nLoc: c_int,
    pUserData: ?*anyopaque,
    xToken: XTokenCb,
) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pTab: *Fts5Table = @ptrCast(pCsr.base.pVtab.?);
    var rc: c_int = SQLITE_OK;

    sqlite3Fts5SetLocale(pTab.pConfig.?, pLoc, nLoc);
    rc = sqlite3Fts5Tokenize(pTab.pConfig.?, FTS5_TOKENIZE_AUX, pText, nText, pUserData, xToken);
    sqlite3Fts5SetLocale(pTab.pConfig.?, null, 0);

    return rc;
}

fn fts5ApiTokenize(pCtx: ?*Fts5Context, pText: ?[*]const u8, nText: c_int, pUserData: ?*anyopaque, xToken: XTokenCb) callconv(.c) c_int {
    return fts5ApiTokenize_v2(pCtx, pText, nText, null, 0, pUserData, xToken);
}

fn fts5ApiPhraseCount(pCtx: ?*Fts5Context) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    return sqlite3Fts5ExprPhraseCount(pCsr.pExpr);
}

fn fts5ApiPhraseSize(pCtx: ?*Fts5Context, iPhrase: c_int) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    return sqlite3Fts5ExprPhraseSize(pCsr.pExpr, iPhrase);
}

/// fts5_main.c 21420-21447: read text value of column iCol (handle locale).
fn fts5TextFromStmt(pConfig: *Fts5Config, pStmt: ?*sqlite3_stmt, iCol: c_int, ppText: *?[*]const u8, pnText: *c_int) c_int {
    const pVal = sqlite3_column_value(pStmt, iCol + 1);
    var pLoc: ?[*]const u8 = null;
    var nLoc: c_int = 0;
    var rc: c_int = SQLITE_OK;

    if (pConfig.bLocale != 0 and pConfig.eContent == FTS5_CONTENT_EXTERNAL and sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
        rc = sqlite3Fts5DecodeLocaleValue(pVal, ppText, pnText, &pLoc, &nLoc);
    } else {
        ppText.* = @ptrCast(sqlite3_value_text(pVal));
        pnText.* = sqlite3_value_bytes(pVal);
        if (pConfig.bLocale != 0 and pConfig.eContent == FTS5_CONTENT_NORMAL) {
            pLoc = @ptrCast(sqlite3_column_text(pStmt, iCol + 1 + pConfig.nCol));
            nLoc = sqlite3_column_bytes(pStmt, iCol + 1 + pConfig.nCol);
        }
    }
    sqlite3Fts5SetLocale(pConfig, pLoc, nLoc);
    return rc;
}

fn fts5ApiColumnText(pCtx: ?*Fts5Context, iCol: c_int, pz: *?[*]const u8, pn: *c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pTab: *Fts5Table = @ptrCast(pCsr.base.pVtab.?);

    if (iCol < 0 or iCol >= pTab.pConfig.?.nCol) {
        rc = SQLITE_RANGE;
    } else if (fts5IsContentless(@ptrCast(pCsr.base.pVtab.?), 0) != 0) {
        pz.* = null;
        pn.* = 0;
    } else {
        rc = fts5SeekCursor(pCsr, 0);
        if (rc == SQLITE_OK) {
            rc = fts5TextFromStmt(pTab.pConfig.?, pCsr.pStmt, iCol, pz, pn);
            sqlite3Fts5ClearLocale(pTab.pConfig.?);
        }
    }
    return rc;
}

/// fts5_main.c 21482-21545: obtain the position list for phrase iPhrase.
fn fts5CsrPoslist(pCsr: *Fts5Cursor, iPhrase: c_int, pa: *?[*]const u8, pn: *c_int) c_int {
    const pConfig = @as(*Fts5Table, @ptrCast(pCsr.base.pVtab.?)).pConfig.?;
    var rc: c_int = SQLITE_OK;
    const bLive: c_int = @intFromBool(pCsr.pSorter == null);

    if (iPhrase < 0 or iPhrase >= sqlite3Fts5ExprPhraseCount(pCsr.pExpr)) {
        rc = SQLITE_RANGE;
    } else if (pConfig.eDetail != FTS5_DETAIL_FULL and fts5IsContentless(@ptrCast(pCsr.base.pVtab.?), 1) != 0) {
        pa.* = null;
        pn.* = 0;
        return SQLITE_OK;
    } else if (CsrFlagTest(pCsr, FTS5CSR_REQUIRE_POSLIST) != 0) {
        if (pConfig.eDetail != FTS5_DETAIL_FULL) {
            const aPopulator = sqlite3Fts5ExprClearPoslists(pCsr.pExpr, bLive);
            if (aPopulator == null) rc = SQLITE_NOMEM;
            if (rc == SQLITE_OK) {
                rc = fts5SeekCursor(pCsr, 0);
            }
            var i: c_int = 0;
            while (i < pConfig.nCol and rc == SQLITE_OK) : (i += 1) {
                var z: ?[*]const u8 = null;
                var n: c_int = 0;
                rc = fts5TextFromStmt(pConfig, pCsr.pStmt, i, &z, &n);
                if (rc == SQLITE_OK) {
                    rc = sqlite3Fts5ExprPopulatePoslists(pConfig, pCsr.pExpr, aPopulator, i, z, n);
                }
                sqlite3Fts5ClearLocale(pConfig);
            }
            sqlite3_free(aPopulator);

            if (pCsr.pSorter) |pSorter| {
                sqlite3Fts5ExprCheckPoslists(pCsr.pExpr, pSorter.iRowid);
            }
        }
        CsrFlagClear(pCsr, FTS5CSR_REQUIRE_POSLIST);
    }

    if (rc == SQLITE_OK) {
        if (pCsr.pSorter != null and pConfig.eDetail == FTS5_DETAIL_FULL) {
            const pSorter = pCsr.pSorter.?;
            const iFirst: c_int = if (iPhrase == 0) 0 else sorterIdx(pSorter, iPhrase - 1).*;
            pn.* = sorterIdx(pSorter, iPhrase).* - iFirst;
            pa.* = pSorter.aPoslist.? + @as(usize, @intCast(iFirst));
        } else {
            pn.* = sqlite3Fts5ExprPoslist(pCsr.pExpr, iPhrase, pa);
        }
    } else {
        pa.* = null;
        pn.* = 0;
    }

    return rc;
}

/// fts5_main.c 21552-21625: populate the cursor's instance cache.
fn fts5CacheInstArray(pCsr: *Fts5Cursor) c_int {
    var rc: c_int = SQLITE_OK;
    const nCol = @as(*Fts5Table, @ptrCast(pCsr.base.pVtab.?)).pConfig.?.nCol;

    const nIter = sqlite3Fts5ExprPhraseCount(pCsr.pExpr);
    if (pCsr.aInstIter == null) {
        const nByte: i64 = @as(i64, @sizeOf(Fts5PoslistReader)) * nIter;
        pCsr.aInstIter = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
    }
    const aIter = pCsr.aInstIter;

    if (aIter) |ai| {
        var nInst: c_int = 0;
        var i: c_int = 0;

        i = 0;
        while (i < nIter and rc == SQLITE_OK) : (i += 1) {
            var a: ?[*]const u8 = null;
            var n: c_int = 0;
            rc = fts5CsrPoslist(pCsr, i, &a, &n);
            if (rc == SQLITE_OK) {
                _ = sqlite3Fts5PoslistReaderInit(a, n, &ai[@intCast(i)]);
            }
        }

        if (rc == SQLITE_OK) {
            while (true) {
                var iBest: c_int = -1;
                i = 0;
                while (i < nIter) : (i += 1) {
                    if (ai[@intCast(i)].bEof == 0 and
                        (iBest < 0 or ai[@intCast(i)].iPos < ai[@intCast(iBest)].iPos))
                    {
                        iBest = i;
                    }
                }
                if (iBest < 0) break;

                nInst += 1;
                if (nInst >= pCsr.nInstAlloc) {
                    const nNewSize: c_int = if (pCsr.nInstAlloc != 0) pCsr.nInstAlloc * 2 else 32;
                    const aInst: ?[*]c_int = @ptrCast(@alignCast(sqlite3_realloc64(pCsr.aInst, @intCast(@as(i64, nNewSize) * @sizeOf(c_int) * 3))));
                    if (aInst) |ain| {
                        pCsr.aInst = ain;
                        pCsr.nInstAlloc = nNewSize;
                    } else {
                        nInst -= 1;
                        rc = SQLITE_NOMEM;
                        break;
                    }
                }

                const aInst = pCsr.aInst.? + @as(usize, @intCast(3 * (nInst - 1)));
                aInst[0] = iBest;
                aInst[1] = FTS5_POS2COLUMN(ai[@intCast(iBest)].iPos);
                aInst[2] = FTS5_POS2OFFSET(ai[@intCast(iBest)].iPos);
                if (aInst[1] >= nCol) {
                    rc = FTS5_CORRUPT;
                    break;
                }
                _ = sqlite3Fts5PoslistReaderNext(&ai[@intCast(iBest)]);
            }
        }

        pCsr.nInstCount = nInst;
        CsrFlagClear(pCsr, FTS5CSR_REQUIRE_INST);
    }
    return rc;
}

fn fts5ApiInstCount(pCtx: ?*Fts5Context, pnInst: *c_int) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    var rc: c_int = SQLITE_OK;
    if (CsrFlagTest(pCsr, FTS5CSR_REQUIRE_INST) == 0 or blk: {
        rc = fts5CacheInstArray(pCsr);
        break :blk rc == SQLITE_OK;
    }) {
        pnInst.* = pCsr.nInstCount;
    }
    return rc;
}

fn fts5ApiInst(pCtx: ?*Fts5Context, iIdx: c_int, piPhrase: *c_int, piCol: *c_int, piOff: *c_int) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    var rc: c_int = SQLITE_OK;
    if (CsrFlagTest(pCsr, FTS5CSR_REQUIRE_INST) == 0 or blk: {
        rc = fts5CacheInstArray(pCsr);
        break :blk rc == SQLITE_OK;
    }) {
        if (iIdx < 0 or iIdx >= pCsr.nInstCount) {
            rc = SQLITE_RANGE;
        } else {
            piPhrase.* = pCsr.aInst.?[@intCast(iIdx * 3)];
            piCol.* = pCsr.aInst.?[@intCast(iIdx * 3 + 1)];
            piOff.* = pCsr.aInst.?[@intCast(iIdx * 3 + 2)];
        }
    }
    return rc;
}

fn fts5ApiRowid(pCtx: ?*Fts5Context) callconv(.c) i64 {
    return fts5CursorRowid(@ptrCast(@alignCast(pCtx.?)));
}

fn fts5ColumnSizeCb(pContext: ?*anyopaque, tflags: c_int, pUnused: ?[*]const u8, nUnused: c_int, iUnused1: c_int, iUnused2: c_int) callconv(.c) c_int {
    _ = pUnused;
    _ = nUnused;
    _ = iUnused1;
    _ = iUnused2;
    const pCnt: *c_int = @ptrCast(@alignCast(pContext.?));
    if ((tflags & FTS5_TOKEN_COLOCATED) == 0) {
        pCnt.* += 1;
    }
    return SQLITE_OK;
}

fn fts5ApiColumnSize(pCtx: ?*Fts5Context, iCol: c_int, pnToken: *c_int) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);
    const pConfig = pTab.p.pConfig.?;
    var rc: c_int = SQLITE_OK;

    if (CsrFlagTest(pCsr, FTS5CSR_REQUIRE_DOCSIZE) != 0) {
        if (pConfig.bColumnsize != 0) {
            const iRowid = fts5CursorRowid(pCsr);
            rc = sqlite3Fts5StorageDocsize(pTab.pStorage.?, iRowid, pCsr.aColumnSize.?);
        } else if (pConfig.zContent == null or pConfig.eContent == FTS5_CONTENT_UNINDEXED) {
            var i: c_int = 0;
            while (i < pConfig.nCol) : (i += 1) {
                if (pConfig.abUnindexed.?[@intCast(i)] == 0) {
                    pCsr.aColumnSize.?[@intCast(i)] = -1;
                }
            }
        } else {
            rc = fts5SeekCursor(pCsr, 0);
            var i: c_int = 0;
            while (rc == SQLITE_OK and i < pConfig.nCol) : (i += 1) {
                if (pConfig.abUnindexed.?[@intCast(i)] == 0) {
                    var z: ?[*]const u8 = null;
                    var n: c_int = 0;
                    pCsr.aColumnSize.?[@intCast(i)] = 0;
                    rc = fts5TextFromStmt(pConfig, pCsr.pStmt, i, &z, &n);
                    if (rc == SQLITE_OK) {
                        rc = sqlite3Fts5Tokenize(pConfig, FTS5_TOKENIZE_AUX, z, n, @ptrCast(&pCsr.aColumnSize.?[@intCast(i)]), fts5ColumnSizeCb);
                    }
                    sqlite3Fts5ClearLocale(pConfig);
                }
            }
        }
        CsrFlagClear(pCsr, FTS5CSR_REQUIRE_DOCSIZE);
    }
    if (iCol < 0) {
        var i: c_int = 0;
        pnToken.* = 0;
        while (i < pConfig.nCol) : (i += 1) {
            pnToken.* += pCsr.aColumnSize.?[@intCast(i)];
        }
    } else if (iCol < pConfig.nCol) {
        pnToken.* = pCsr.aColumnSize.?[@intCast(iCol)];
    } else {
        pnToken.* = 0;
        rc = SQLITE_RANGE;
    }
    return rc;
}

fn fts5ApiSetAuxdata(pCtx: ?*Fts5Context, pPtr: ?*anyopaque, xDelete: ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));

    var pData = pCsr.pAuxdata;
    while (pData) |pd| : (pData = pd.pNext) {
        if (pd.pAux == pCsr.pAux) break;
    }

    if (pData) |pd| {
        if (pd.xDelete) |xd| {
            xd(pd.pPtr);
        }
    } else {
        var rc: c_int = SQLITE_OK;
        const pNew: ?*Fts5Auxdata = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5Auxdata))));
        if (pNew == null) {
            if (xDelete) |xd| xd(pPtr);
            return rc;
        }
        pData = pNew;
        pData.?.pAux = pCsr.pAux;
        pData.?.pNext = pCsr.pAuxdata;
        pCsr.pAuxdata = pData;
    }

    pData.?.xDelete = xDelete;
    pData.?.pPtr = pPtr;
    return SQLITE_OK;
}

fn fts5ApiGetAuxdata(pCtx: ?*Fts5Context, bClear: c_int) callconv(.c) ?*anyopaque {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    var pRet: ?*anyopaque = null;

    var pData = pCsr.pAuxdata;
    while (pData) |pd| : (pData = pd.pNext) {
        if (pd.pAux == pCsr.pAux) break;
    }

    if (pData) |pd| {
        pRet = pd.pPtr;
        if (bClear != 0) {
            pd.pPtr = null;
            pd.xDelete = null;
        }
    }

    return pRet;
}

fn fts5ApiPhraseNext(pCtx: ?*Fts5Context, pIter: *Fts5PhraseIter, piCol: *c_int, piOff: *c_int) callconv(.c) void {
    if (@intFromPtr(pIter.a) >= @intFromPtr(pIter.b)) {
        piCol.* = -1;
        piOff.* = -1;
    } else {
        var iVal: u32 = undefined;
        pIter.a = pIter.a.? + @as(usize, @intCast(sqlite3Fts5GetVarint32(pIter.a.?, &iVal)));
        if (iVal == 1) {
            const nCol = @as(*Fts5Table, @ptrCast(@as(*Fts5Cursor, @ptrCast(@alignCast(pCtx.?))).base.pVtab.?)).pConfig.?.nCol;
            pIter.a = pIter.a.? + @as(usize, @intCast(sqlite3Fts5GetVarint32(pIter.a.?, &iVal)));
            piCol.* = if (@as(c_int, @bitCast(iVal)) >= nCol) nCol - 1 else @bitCast(iVal);
            piOff.* = 0;
            pIter.a = pIter.a.? + @as(usize, @intCast(sqlite3Fts5GetVarint32(pIter.a.?, &iVal)));
        }
        piOff.* += @as(c_int, @bitCast(iVal)) - 2;
    }
}

fn fts5ApiPhraseFirst(pCtx: ?*Fts5Context, iPhrase: c_int, pIter: *Fts5PhraseIter, piCol: *c_int, piOff: *c_int) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    var n: c_int = 0;
    var a: ?[*]const u8 = null;
    const rc = fts5CsrPoslist(pCsr, iPhrase, &a, &n);
    pIter.a = a;
    if (rc == SQLITE_OK) {
        pIter.b = if (pIter.a != null) pIter.a.? + @as(usize, @intCast(n)) else null;
        piCol.* = 0;
        piOff.* = 0;
        fts5ApiPhraseNext(pCtx, pIter, piCol, piOff);
    }
    return rc;
}

fn fts5ApiPhraseNextColumn(pCtx: ?*Fts5Context, pIter: *Fts5PhraseIter, piCol: *c_int) callconv(.c) void {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pConfig = @as(*Fts5Table, @ptrCast(pCsr.base.pVtab.?)).pConfig.?;

    if (pConfig.eDetail == FTS5_DETAIL_COLUMNS) {
        if (@intFromPtr(pIter.a) >= @intFromPtr(pIter.b)) {
            piCol.* = -1;
        } else {
            var iIncr: u32 = undefined;
            pIter.a = pIter.a.? + @as(usize, @intCast(sqlite3Fts5GetVarint32(pIter.a.?, &iIncr)));
            piCol.* += @as(c_int, @bitCast(iIncr)) - 2;
        }
    } else {
        while (true) {
            var dummy: u32 = undefined;
            if (@intFromPtr(pIter.a) >= @intFromPtr(pIter.b)) {
                piCol.* = -1;
                return;
            }
            if (pIter.a.?[0] == 0x01) break;
            pIter.a = pIter.a.? + @as(usize, @intCast(sqlite3Fts5GetVarint32(pIter.a.?, &dummy)));
        }
        var col: u32 = undefined;
        const adv = sqlite3Fts5GetVarint32(pIter.a.? + 1, &col);
        piCol.* = @bitCast(col);
        pIter.a = pIter.a.? + @as(usize, @intCast(1 + adv));
    }
}

fn fts5ApiPhraseFirstColumn(pCtx: ?*Fts5Context, iPhrase: c_int, pIter: *Fts5PhraseIter, piCol: *c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pConfig = @as(*Fts5Table, @ptrCast(pCsr.base.pVtab.?)).pConfig.?;

    if (pConfig.eDetail == FTS5_DETAIL_COLUMNS) {
        var n: c_int = 0;
        if (pCsr.pSorter) |pSorter| {
            const iFirst: c_int = if (iPhrase == 0) 0 else sorterIdx(pSorter, iPhrase - 1).*;
            n = sorterIdx(pSorter, iPhrase).* - iFirst;
            pIter.a = pSorter.aPoslist.? + @as(usize, @intCast(iFirst));
        } else {
            var a: ?[*]const u8 = null;
            rc = sqlite3Fts5ExprPhraseCollist(pCsr.pExpr, iPhrase, &a, &n);
            pIter.a = a;
        }
        if (rc == SQLITE_OK) {
            pIter.b = if (pIter.a != null) pIter.a.? + @as(usize, @intCast(n)) else null;
            piCol.* = 0;
            fts5ApiPhraseNextColumn(pCtx, pIter, piCol);
        }
    } else {
        var n: c_int = 0;
        var a: ?[*]const u8 = null;
        rc = fts5CsrPoslist(pCsr, iPhrase, &a, &n);
        pIter.a = a;
        if (rc == SQLITE_OK) {
            pIter.b = if (pIter.a != null) pIter.a.? + @as(usize, @intCast(n)) else null;
            if (n <= 0) {
                piCol.* = -1;
            } else if (pIter.a.?[0] == 0x01) {
                var col: u32 = undefined;
                const adv = sqlite3Fts5GetVarint32(pIter.a.? + 1, &col);
                piCol.* = @bitCast(col);
                pIter.a = pIter.a.? + @as(usize, @intCast(1 + adv));
            } else {
                piCol.* = 0;
            }
        }
    }

    return rc;
}

fn fts5ApiQueryToken(pCtx: ?*Fts5Context, iPhrase: c_int, iToken: c_int, ppOut: *?[*]const u8, pnOut: *c_int) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    return sqlite3Fts5ExprQueryToken(pCsr.pExpr, iPhrase, iToken, ppOut, pnOut);
}

fn fts5ApiInstToken(pCtx: ?*Fts5Context, iIdx: c_int, iToken: c_int, ppOut: *?[*]const u8, pnOut: *c_int) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    var rc: c_int = SQLITE_OK;
    if (CsrFlagTest(pCsr, FTS5CSR_REQUIRE_INST) == 0 or blk: {
        rc = fts5CacheInstArray(pCsr);
        break :blk rc == SQLITE_OK;
    }) {
        if (iIdx < 0 or iIdx >= pCsr.nInstCount) {
            rc = SQLITE_RANGE;
        } else {
            const iPhrase = pCsr.aInst.?[@intCast(iIdx * 3)];
            const iCol = pCsr.aInst.?[@intCast(iIdx * 3 + 1)];
            const iOff = pCsr.aInst.?[@intCast(iIdx * 3 + 2)];
            const iRowid = fts5CursorRowid(pCsr);
            rc = sqlite3Fts5ExprInstToken(pCsr.pExpr, iRowid, iPhrase, iCol, iOff, iToken, ppOut, pnOut);
        }
    }
    return rc;
}

/// fts5_main.c 21961-21996: xColumnLocale.
fn fts5ApiColumnLocale(pCtx: ?*Fts5Context, iCol: c_int, pzLocale: *?[*]const u8, pnLocale: *c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pConfig = @as(*Fts5Table, @ptrCast(pCsr.base.pVtab.?)).pConfig.?;

    pzLocale.* = null;
    pnLocale.* = 0;

    if (iCol < 0 or iCol >= pConfig.nCol) {
        rc = SQLITE_RANGE;
    } else if (pConfig.abUnindexed.?[@intCast(iCol)] == 0 and
        0 == fts5IsContentless(@ptrCast(pCsr.base.pVtab.?), 1) and
        pConfig.bLocale != 0)
    {
        rc = fts5SeekCursor(pCsr, 0);
        if (rc == SQLITE_OK) {
            var zDummy: ?[*]const u8 = null;
            var nDummy: c_int = 0;
            rc = fts5TextFromStmt(pConfig, pCsr.pStmt, iCol, &zDummy, &nDummy);
            if (rc == SQLITE_OK) {
                pzLocale.* = pConfig.t.pLocale;
                pnLocale.* = pConfig.t.nLocale;
            }
            sqlite3Fts5ClearLocale(pConfig);
        }
    }

    return rc;
}

/// fts5_main.c 21998-22023: the Fts5ExtensionApi method table (iVersion 4).
const sFts5Api = Fts5ExtensionApi{
    .iVersion = 4,
    .xUserData = fts5ApiUserData,
    .xColumnCount = fts5ApiColumnCount,
    .xRowCount = fts5ApiRowCount,
    .xColumnTotalSize = fts5ApiColumnTotalSize,
    .xTokenize = fts5ApiTokenize,
    .xPhraseCount = fts5ApiPhraseCount,
    .xPhraseSize = fts5ApiPhraseSize,
    .xInstCount = fts5ApiInstCount,
    .xInst = fts5ApiInst,
    .xRowid = fts5ApiRowid,
    .xColumnText = fts5ApiColumnText,
    .xColumnSize = fts5ApiColumnSize,
    .xQueryPhrase = fts5ApiQueryPhrase,
    .xSetAuxdata = fts5ApiSetAuxdata,
    .xGetAuxdata = fts5ApiGetAuxdata,
    .xPhraseFirst = fts5ApiPhraseFirst,
    .xPhraseNext = fts5ApiPhraseNext,
    .xPhraseFirstColumn = fts5ApiPhraseFirstColumn,
    .xPhraseNextColumn = fts5ApiPhraseNextColumn,
    .xQueryToken = fts5ApiQueryToken,
    .xInstToken = fts5ApiInstToken,
    .xColumnLocale = fts5ApiColumnLocale,
    .xTokenize_v2 = fts5ApiTokenize_v2,
};

const QueryPhraseCb = ?*const fn (?*const Fts5ExtensionApi, ?*Fts5Context, ?*anyopaque) callconv(.c) c_int;

/// fts5_main.c 22028-22063: xQueryPhrase.
fn fts5ApiQueryPhrase(pCtx: ?*Fts5Context, iPhrase: c_int, pUserData: ?*anyopaque, xCallback: QueryPhraseCb) callconv(.c) c_int {
    const pCsr: *Fts5Cursor = @ptrCast(@alignCast(pCtx.?));
    const pTab: *Fts5FullTable = @ptrCast(pCsr.base.pVtab.?);
    var rc: c_int = undefined;
    var pNew: ?*Fts5Cursor = null;

    rc = fts5OpenMethod(pCsr.base.pVtab.?, @ptrCast(&pNew));
    if (rc == SQLITE_OK) {
        const pn = pNew.?;
        pn.ePlan = FTS5_PLAN_MATCH;
        pn.iFirstRowid = SMALLEST_INT64;
        pn.iLastRowid = LARGEST_INT64;
        pn.base.pVtab = @ptrCast(pTab);
        rc = sqlite3Fts5ExprClonePhrase(pCsr.pExpr, iPhrase, &pn.pExpr);
    }

    if (rc == SQLITE_OK) {
        rc = fts5CursorFirst(pTab, pNew.?, 0);
        while (rc == SQLITE_OK and CsrFlagTest(pNew.?, FTS5CSR_EOF) == 0) {
            rc = xCallback.?(&sFts5Api, @ptrCast(pNew), pUserData);
            if (rc != SQLITE_OK) {
                if (rc == SQLITE_DONE) rc = SQLITE_OK;
                break;
            }
            rc = fts5NextMethod(@ptrCast(pNew));
        }
    }

    _ = fts5CloseMethod(@ptrCast(pNew));
    return rc;
}

fn fts5ApiInvoke(pAux: *Fts5Auxiliary, pCsr: *Fts5Cursor, context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) void {
    pCsr.pAux = pAux;
    pAux.xFunc.?(&sFts5Api, @ptrCast(pCsr), context, argc, argv);
    pCsr.pAux = null;
}

fn fts5CursorFromCsrid(pGlobal: *Fts5Global, iCsrId: i64) ?*Fts5Cursor {
    var pCsr = pGlobal.pCsr;
    while (pCsr) |pc| : (pCsr = pc.pNext) {
        if (pc.iCsrId == iCsrId) return pc;
    }
    return null;
}

fn fts5ResultError(pCtx: ?*sqlite3_context, zFmt: [*:0]const u8, ...) callconv(.c) void {
    var ap = @cVaStart();
    const zErr = sqlite3_vmprintf(zFmt, @ptrCast(&ap));
    @cVaEnd(&ap);
    sqlite3_result_error(pCtx, zErr, -1);
    sqlite3_free(zErr);
}

fn fts5ApiCallback(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    const pAux: *Fts5Auxiliary = @ptrCast(@alignCast(sqlite3_user_data(context).?));
    const iCsrId = sqlite3_value_int64(argv.?[0]);

    const pCsr = fts5CursorFromCsrid(pAux.pGlobal.?, iCsrId);
    if (pCsr == null or (pCsr.?.ePlan == 0 or pCsr.?.ePlan == FTS5_PLAN_SPECIAL)) {
        fts5ResultError(context, "no such cursor: %lld", iCsrId);
    } else {
        const pTab = pCsr.?.base.pVtab.?;
        fts5ApiInvoke(pAux, pCsr.?, context, argc - 1, argv.? + 1);
        sqlite3_free(pTab.zErrMsg);
        pTab.zErrMsg = null;
    }
}

/// fts5_main.c 22132-22142: map a cursor id to its Fts5Table.
export fn sqlite3Fts5TableFromCsrid(pGlobal: *Fts5Global, iCsrId: i64) callconv(.c) ?*Fts5Table {
    const pCsr = fts5CursorFromCsrid(pGlobal, iCsrId);
    if (pCsr) |pc| {
        return @ptrCast(pc.base.pVtab.?);
    }
    return null;
}

/// fts5_main.c 22159-22210: build a "position-list blob" for the rank column.
fn fts5PoslistBlob(pCtx: ?*sqlite3_context, pCsr: *Fts5Cursor) c_int {
    var rc: c_int = SQLITE_OK;
    const nPhrase = sqlite3Fts5ExprPhraseCount(pCsr.pExpr);
    var val: Fts5Buffer = undefined;
    _ = memset(&val, 0, @sizeOf(Fts5Buffer));

    switch (@as(*Fts5Table, @ptrCast(pCsr.base.pVtab.?)).pConfig.?.eDetail) {
        FTS5_DETAIL_FULL => {
            var i: c_int = 0;
            while (i < (nPhrase - 1)) : (i += 1) {
                var dummy: ?[*]const u8 = null;
                const nByte = sqlite3Fts5ExprPoslist(pCsr.pExpr, i, &dummy);
                sqlite3Fts5BufferAppendVarint(&rc, &val, nByte);
            }
            i = 0;
            while (i < nPhrase) : (i += 1) {
                var pPoslist: ?[*]const u8 = null;
                const nPoslist = sqlite3Fts5ExprPoslist(pCsr.pExpr, i, &pPoslist);
                sqlite3Fts5BufferAppendBlob(&rc, &val, @bitCast(nPoslist), pPoslist);
            }
        },
        FTS5_DETAIL_COLUMNS => {
            var i: c_int = 0;
            while (rc == SQLITE_OK and i < (nPhrase - 1)) : (i += 1) {
                var dummy: ?[*]const u8 = null;
                var nByte: c_int = undefined;
                rc = sqlite3Fts5ExprPhraseCollist(pCsr.pExpr, i, &dummy, &nByte);
                sqlite3Fts5BufferAppendVarint(&rc, &val, nByte);
            }
            i = 0;
            while (rc == SQLITE_OK and i < nPhrase) : (i += 1) {
                var pPoslist: ?[*]const u8 = null;
                var nPoslist: c_int = undefined;
                rc = sqlite3Fts5ExprPhraseCollist(pCsr.pExpr, i, &pPoslist, &nPoslist);
                sqlite3Fts5BufferAppendBlob(&rc, &val, @bitCast(nPoslist), pPoslist);
            }
        },
        else => {},
    }

    sqlite3_result_blob(pCtx, val.p, val.n, sqlite3_free_dtor);
    return rc;
}

// sqlite3_free as a destructor-typed function pointer (its arg is ?*anyopaque).
const sqlite3_free_dtor: int.DestructorFn = @ptrCast(&sqlite3_free);

/// fts5_main.c 22216-22280: xColumn.
fn fts5ColumnMethod(pCursor: *sqlite3_vtab_cursor, pCtx: ?*sqlite3_context, iCol: c_int) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pCursor.pVtab.?);
    const pConfig = pTab.p.pConfig.?;
    const pCsr: *Fts5Cursor = @ptrCast(pCursor);
    var rc: c_int = SQLITE_OK;

    if (pCsr.ePlan == FTS5_PLAN_SPECIAL) {
        if (iCol == pConfig.nCol) {
            sqlite3_result_int64(pCtx, pCsr.iSpecial);
        }
    } else if (iCol == pConfig.nCol) {
        sqlite3_result_int64(pCtx, pCsr.iCsrId);
    } else if (iCol == pConfig.nCol + 1) {
        // The "rank" column.
        if (pCsr.ePlan == FTS5_PLAN_SOURCE) {
            _ = fts5PoslistBlob(pCtx, pCsr);
        } else if (pCsr.ePlan == FTS5_PLAN_MATCH or pCsr.ePlan == FTS5_PLAN_SORTED_MATCH) {
            if (pCsr.pRank != null or SQLITE_OK == blk: {
                rc = fts5FindRankFunction(pCsr);
                break :blk rc;
            }) {
                fts5ApiInvoke(pCsr.pRank.?, pCsr, pCtx, pCsr.nRankArg, pCsr.apRankArg);
            }
        }
    } else {
        if (sqlite3_vtab_nochange(pCtx) == 0 and pConfig.eContent != FTS5_CONTENT_NONE) {
            pConfig.pzErrmsg = &pTab.p.base.zErrMsg;
            rc = fts5SeekCursor(pCsr, 1);
            if (rc == SQLITE_OK) {
                const pVal = sqlite3_column_value(pCsr.pStmt, iCol + 1);
                if (pConfig.bLocale != 0 and pConfig.eContent == FTS5_CONTENT_EXTERNAL and sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
                    var z: ?[*]const u8 = null;
                    var n: c_int = 0;
                    rc = fts5TextFromStmt(pConfig, pCsr.pStmt, iCol, &z, &n);
                    if (rc == SQLITE_OK) {
                        sqlite3_result_text(pCtx, z, n, SQLITE_TRANSIENT);
                    }
                    sqlite3Fts5ClearLocale(pConfig);
                } else {
                    sqlite3_result_value(pCtx, pVal);
                }
            }
            pConfig.pzErrmsg = null;
        }
    }

    return rc;
}

const FindFnPtr = ?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void;

fn fts5FindFunctionMethod(pVtab: *sqlite3_vtab, nUnused: c_int, zName: [*:0]const u8, pxFunc: *FindFnPtr, ppArg: *?*anyopaque) callconv(.c) c_int {
    _ = nUnused;
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    const pAux = fts5FindAuxiliary(pTab, zName);
    if (pAux) |pa| {
        pxFunc.* = fts5ApiCallback;
        ppArg.* = @ptrCast(pa);
        return 1;
    }
    return 0;
}

fn fts5RenameMethod(pVtab: *sqlite3_vtab, zName: [*:0]const u8) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    return sqlite3Fts5StorageRename(pTab.pStorage.?, zName);
}

/// fts5_main.c 22322-22325.
export fn sqlite3Fts5FlushToDisk(pTab: *Fts5Table) callconv(.c) c_int {
    fts5TripCursors(@ptrCast(pTab));
    return sqlite3Fts5StorageSync(@as(*Fts5FullTable, @ptrCast(pTab)).pStorage.?);
}

fn fts5SavepointMethod(pVtab: *sqlite3_vtab, iSavepoint: c_int) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    fts5CheckTransactionState(pTab, FTS5_SAVEPOINT, iSavepoint);
    const rc = sqlite3Fts5FlushToDisk(@ptrCast(pVtab));
    if (rc == SQLITE_OK) {
        pTab.iSavepoint = iSavepoint + 1;
    }
    return rc;
}

fn fts5ReleaseMethod(pVtab: *sqlite3_vtab, iSavepoint: c_int) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    var rc: c_int = SQLITE_OK;
    fts5CheckTransactionState(pTab, FTS5_RELEASE, iSavepoint);
    if ((iSavepoint + 1) < pTab.iSavepoint) {
        rc = sqlite3Fts5FlushToDisk(&pTab.p);
        if (rc == SQLITE_OK) {
            pTab.iSavepoint = iSavepoint;
        }
    }
    return rc;
}

fn fts5RollbackToMethod(pVtab: *sqlite3_vtab, iSavepoint: c_int) callconv(.c) c_int {
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    var rc: c_int = SQLITE_OK;
    fts5CheckTransactionState(pTab, FTS5_ROLLBACKTO, iSavepoint);
    fts5TripCursors(pTab);
    if ((iSavepoint + 1) <= pTab.iSavepoint) {
        pTab.p.pConfig.?.pgsz = 0;
        rc = sqlite3Fts5StorageRollback(pTab.pStorage.?);
    }
    return rc;
}

/// fts5_main.c 22382-22415: fts5_api.xCreateFunction.
fn fts5CreateAux(pApi: *fts5_api, zName: [*:0]const u8, pUserData: ?*anyopaque, xFunc: fts5_extension_function, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int {
    const pGlobal: *Fts5Global = @ptrCast(pApi);
    var rc = sqlite3_overload_function(pGlobal.db, zName, -1);
    if (rc == SQLITE_OK) {
        const nName: i64 = @as(i64, @intCast(strlen(zName))) + 1;
        const nByte: i64 = @as(i64, @sizeOf(Fts5Auxiliary)) + nName;
        const pAux: ?*Fts5Auxiliary = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
        if (pAux) |pa| {
            _ = memset(pa, 0, @intCast(nByte));
            pa.zFunc = @ptrCast(@as([*]Fts5Auxiliary, @ptrCast(pa)) + 1);
            _ = memcpy(pa.zFunc, zName, @intCast(nName));
            pa.pGlobal = pGlobal;
            pa.pUserData = pUserData;
            pa.xFunc = xFunc;
            pa.xDestroy = xDestroy;
            pa.pNext = pGlobal.pAux;
            pGlobal.pAux = pa;
        } else {
            rc = SQLITE_NOMEM;
        }
    }
    return rc;
}

/// fts5_main.c 22432-22460: allocate a new Fts5TokenizerModule.
fn fts5NewTokenizerModule(pGlobal: *Fts5Global, zName: [*:0]const u8, pUserData: ?*anyopaque, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void, ppNew: *?*Fts5TokenizerModule) c_int {
    var rc: c_int = SQLITE_OK;
    const nName: i64 = @as(i64, @intCast(strlen(zName))) + 1;
    const nByte: i64 = @as(i64, @sizeOf(Fts5TokenizerModule)) + nName;
    const pNew: ?*Fts5TokenizerModule = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
    ppNew.* = pNew;
    if (pNew) |pn| {
        pn.zName = @ptrCast(@as([*]Fts5TokenizerModule, @ptrCast(pn)) + 1);
        _ = memcpy(pn.zName, zName, @intCast(nName));
        pn.pUserData = pUserData;
        pn.xDestroy = xDestroy;
        pn.pNext = pGlobal.pTok;
        pGlobal.pTok = pn;
        if (pn.pNext == null) {
            pGlobal.pDfltTok = pn;
        }
    }
    return rc;
}

fn fts5VtoVCreate(pCtx: ?*anyopaque, azArg: ?[*]const ?[*:0]const u8, nArg: c_int, ppOut: *?*Fts5Tokenizer) callconv(.c) c_int {
    const pMod: *Fts5TokenizerModule = @ptrCast(@alignCast(pCtx.?));
    var rc: c_int = SQLITE_OK;

    const pNew: ?*Fts5VtoVTokenizer = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5VtoVTokenizer))));
    if (rc == SQLITE_OK) {
        const pn = pNew.?;
        pn.x1 = pMod.x1;
        pn.x2 = pMod.x2;
        pn.bV2Native = pMod.bV2Native;
        if (pMod.bV2Native != 0) {
            rc = pMod.x2.xCreate.?(pMod.pUserData, azArg, nArg, &pn.pReal);
        } else {
            rc = pMod.x1.xCreate.?(pMod.pUserData, azArg, nArg, &pn.pReal);
        }
        if (rc != SQLITE_OK) {
            sqlite3_free(pn);
            ppOut.* = null;
            return rc;
        }
    }

    ppOut.* = @ptrCast(pNew);
    return rc;
}

fn fts5VtoVDelete(pTok: ?*Fts5Tokenizer) callconv(.c) void {
    const p: ?*Fts5VtoVTokenizer = @ptrCast(@alignCast(pTok));
    if (p) |pp| {
        if (pp.bV2Native != 0) {
            pp.x2.xDelete.?(pp.pReal);
        } else {
            pp.x1.xDelete.?(pp.pReal);
        }
        sqlite3_free(pp);
    }
}

fn fts5V1toV2Tokenize(pTok: ?*Fts5Tokenizer, pCtx: ?*anyopaque, flags: c_int, pText: ?[*]const u8, nText: c_int, xToken: int.Fts5TokenCb) callconv(.c) c_int {
    const p: *Fts5VtoVTokenizer = @ptrCast(@alignCast(pTok.?));
    return p.x2.xTokenize.?(p.pReal, pCtx, flags, pText, nText, null, 0, xToken);
}

fn fts5V2toV1Tokenize(pTok: ?*Fts5Tokenizer, pCtx: ?*anyopaque, flags: c_int, pText: ?[*]const u8, nText: c_int, pLocale: ?[*]const u8, nLocale: c_int, xToken: int.Fts5TokenCb) callconv(.c) c_int {
    _ = pLocale;
    _ = nLocale;
    const p: *Fts5VtoVTokenizer = @ptrCast(@alignCast(pTok.?));
    return p.x1.xTokenize.?(p.pReal, pCtx, flags, pText, nText, xToken);
}

fn fts5CreateTokenizer_v2(pApi: *fts5_api, zName: [*:0]const u8, pUserData: ?*anyopaque, pTokenizer: *fts5_tokenizer_v2, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int {
    const pGlobal: *Fts5Global = @ptrCast(pApi);
    var rc: c_int = SQLITE_OK;

    if (pTokenizer.iVersion > 2) {
        rc = SQLITE_ERROR;
    } else {
        var pNew: ?*Fts5TokenizerModule = null;
        rc = fts5NewTokenizerModule(pGlobal, zName, pUserData, xDestroy, &pNew);
        if (pNew) |pn| {
            pn.x2 = pTokenizer.*;
            pn.bV2Native = 1;
            pn.x1.xCreate = fts5VtoVCreate;
            pn.x1.xTokenize = fts5V1toV2Tokenize;
            pn.x1.xDelete = fts5VtoVDelete;
        }
    }
    return rc;
}

fn fts5CreateTokenizer(pApi: *fts5_api, zName: [*:0]const u8, pUserData: ?*anyopaque, pTokenizer: *fts5_tokenizer, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int {
    var pNew: ?*Fts5TokenizerModule = null;
    const rc = fts5NewTokenizerModule(@ptrCast(pApi), zName, pUserData, xDestroy, &pNew);
    if (pNew) |pn| {
        pn.x1 = pTokenizer.*;
        pn.x2.xCreate = fts5VtoVCreate;
        pn.x2.xTokenize = fts5V2toV1Tokenize;
        pn.x2.xDelete = fts5VtoVDelete;
    }
    return rc;
}

fn fts5LocateTokenizer(pGlobal: *Fts5Global, zName: ?[*:0]const u8) ?*Fts5TokenizerModule {
    if (zName == null) {
        return pGlobal.pDfltTok;
    }
    var pMod = pGlobal.pTok;
    while (pMod) |pm| : (pMod = pm.pNext) {
        if (sqlite3_stricmp(zName.?, pm.zName.?) == 0) return pm;
    }
    return null;
}

fn fts5FindTokenizer_v2(pApi: *fts5_api, zName: [*:0]const u8, ppUserData: *?*anyopaque, ppTokenizer: *?*fts5_tokenizer_v2) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pMod = fts5LocateTokenizer(@ptrCast(pApi), zName);
    if (pMod) |pm| {
        if (pm.bV2Native != 0) {
            ppUserData.* = pm.pUserData;
        } else {
            ppUserData.* = @ptrCast(pm);
        }
        ppTokenizer.* = &pm.x2;
    } else {
        ppTokenizer.* = null;
        ppUserData.* = null;
        rc = SQLITE_ERROR;
    }
    return rc;
}

fn fts5FindTokenizer(pApi: *fts5_api, zName: [*:0]const u8, ppUserData: *?*anyopaque, pTokenizer: *fts5_tokenizer) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pMod = fts5LocateTokenizer(@ptrCast(pApi), zName);
    if (pMod) |pm| {
        if (pm.bV2Native == 0) {
            ppUserData.* = pm.pUserData;
        } else {
            ppUserData.* = @ptrCast(pm);
        }
        pTokenizer.* = pm.x1;
    } else {
        _ = memset(pTokenizer, 0, @sizeOf(fts5_tokenizer));
        ppUserData.* = null;
        rc = SQLITE_ERROR;
    }
    return rc;
}

const XCreateFn = ?*const fn (?*anyopaque, ?[*]const ?[*:0]const u8, c_int, *?*Fts5Tokenizer) callconv(.c) c_int;

/// fts5_main.c 22699-22742: instantiate the configured tokenizer.
export fn sqlite3Fts5LoadTokenizer(pConfig: *Fts5Config) callconv(.c) c_int {
    const azArg = pConfig.t.azArg;
    const nArg = pConfig.t.nArg;
    var rc: c_int = SQLITE_OK;

    const pGlobalLocal: *Fts5Global = @ptrCast(@alignCast(pConfig.pGlobal.?));
    const pMod = fts5LocateTokenizer(pGlobalLocal, if (nArg == 0) null else azArg.?[0]);
    if (pMod == null) {
        rc = SQLITE_ERROR;
        sqlite3Fts5ConfigErrmsg(pConfig, "no such tokenizer: %s", azArg.?[0].?);
    } else {
        const pm = pMod.?;
        var xCreate: XCreateFn = null;
        if (pm.bV2Native != 0) {
            xCreate = pm.x2.xCreate;
            pConfig.t.pApi2 = &pm.x2;
        } else {
            pConfig.t.pApi1 = &pm.x1;
            xCreate = pm.x1.xCreate;
        }

        rc = xCreate.?(pm.pUserData, if (azArg != null) azArg.? + 1 else null, if (nArg != 0) nArg - 1 else 0, &pConfig.t.pTok);

        if (rc != SQLITE_OK) {
            if (rc != SQLITE_NOMEM) {
                sqlite3Fts5ConfigErrmsg(pConfig, "error in tokenizer constructor");
            }
        } else if (pm.bV2Native == 0) {
            pConfig.t.ePattern = sqlite3Fts5TokenizerPattern(pm.x1.xCreate, pConfig.t.pTok);
        }
    }

    if (rc != SQLITE_OK) {
        pConfig.t.pApi1 = null;
        pConfig.t.pApi2 = null;
        pConfig.t.pTok = null;
    }

    return rc;
}

fn fts5ModuleDestroy(pCtx: ?*anyopaque) callconv(.c) void {
    const pGlobal: *Fts5Global = @ptrCast(@alignCast(pCtx.?));

    var pAux = pGlobal.pAux;
    while (pAux) |pa| {
        const pNextAux = pa.pNext;
        if (pa.xDestroy) |xd| xd(pa.pUserData);
        sqlite3_free(pa);
        pAux = pNextAux;
    }

    var pTok = pGlobal.pTok;
    while (pTok) |pt| {
        const pNextTok = pt.pNext;
        if (pt.xDestroy) |xd| xd(pt.pUserData);
        sqlite3_free(pt);
        pTok = pNextTok;
    }

    sqlite3_free(pGlobal);
}

fn fts5Fts5Func(pCtx: ?*sqlite3_context, nArg: c_int, apArg: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = nArg;
    const pGlobal: *Fts5Global = @ptrCast(@alignCast(sqlite3_user_data(pCtx).?));
    const ppApi: ?*?*fts5_api = @ptrCast(@alignCast(sqlite3_value_pointer(apArg.?[0], "fts5_api_ptr")));
    if (ppApi) |pp| pp.* = &pGlobal.api;
}

fn fts5SourceIdFunc(pCtx: ?*sqlite3_context, nArg: c_int, apUnused: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = nArg;
    _ = apUnused;
    sqlite3_result_text(pCtx, "fts5: 2026-06-24 14:17:52 395cbed103af08e3a4fafd9a3041205535e019d4aeb58b46c4a7e4f3bca545c9", -1, SQLITE_TRANSIENT);
}

/// fts5_main.c 22814-22859: fts5_locale(LOCALE, TEXT).
fn fts5LocaleFunc(pCtx: ?*sqlite3_context, nArg: c_int, apArg: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = nArg;
    const args = apArg.?;
    const zLocale = sqlite3_value_text(args[0]);
    const nLocale: i64 = sqlite3_value_bytes(args[0]);
    const zText = sqlite3_value_text(args[1]);
    const nText: i64 = sqlite3_value_bytes(args[1]);

    if (zLocale == null or zLocale.?[0] == 0) {
        sqlite3_result_text(pCtx, zText, @intCast(nText), SQLITE_TRANSIENT);
    } else {
        const p: *Fts5Global = @ptrCast(@alignCast(sqlite3_user_data(pCtx).?));
        const nBlob: i64 = FTS5_LOCALE_HDR_SIZE + nLocale + 1 + nText;
        const pBlob: ?[*]u8 = @ptrCast(sqlite3_malloc64(@bitCast(nBlob)));
        if (pBlob == null) {
            sqlite3_result_error_nomem(pCtx);
            return;
        }

        var pCsr = pBlob.?;
        _ = memcpy(pCsr, @as([*]const u8, @ptrCast(&p.aLocaleHdr)), @intCast(FTS5_LOCALE_HDR_SIZE));
        pCsr += @as(usize, @intCast(FTS5_LOCALE_HDR_SIZE));
        _ = memcpy(pCsr, zLocale, @intCast(nLocale));
        pCsr += @as(usize, @intCast(nLocale));
        pCsr[0] = 0x00;
        pCsr += 1;
        if (zText) |zt| _ = memcpy(pCsr, zt, @intCast(nText));

        sqlite3_result_blob(pCtx, pBlob, @intCast(nBlob), sqlite3_free_dtor);
    }
}

fn fts5InsttokenFunc(pCtx: ?*sqlite3_context, nArg: c_int, apArg: ?[*]?*sqlite3_value) callconv(.c) void {
    _ = nArg;
    sqlite3_result_value(pCtx, apArg.?[0]);
    sqlite3_result_subtype(pCtx, @intCast(FTS5_INSTTOKEN_SUBTYPE));
}

fn fts5ShadowName(zName: [*:0]const u8) callconv(.c) c_int {
    const azName = [_][*:0]const u8{ "config", "content", "data", "docsize", "idx" };
    for (azName) |z| {
        if (sqlite3_stricmp(zName, z) == 0) return 1;
    }
    return 0;
}

/// fts5_main.c 22895-22927: xIntegrity.
fn fts5IntegrityMethod(pVtab: *sqlite3_vtab, zSchema: [*:0]const u8, zTabname: [*:0]const u8, isQuick: c_int, pzErr: *?[*:0]u8) callconv(.c) c_int {
    _ = isQuick;
    const pTab: *Fts5FullTable = @ptrCast(pVtab);
    var rc: c_int = undefined;

    pTab.p.pConfig.?.pzErrmsg = pzErr;
    rc = sqlite3Fts5StorageIntegrity(pTab.pStorage.?, 0);
    if (pzErr.* == null and rc != SQLITE_OK) {
        if ((rc & 0xff) == SQLITE_CORRUPT) {
            pzErr.* = sqlite3_mprintf("malformed inverted index for FTS5 table %s.%s", zSchema, zTabname);
            rc = if (pzErr.* != null) SQLITE_OK else SQLITE_NOMEM;
        } else {
            pzErr.* = sqlite3_mprintf("unable to validate the inverted index for FTS5 table %s.%s: %s", zSchema, zTabname, sqlite3_errstr(rc));
        }
    } else if ((rc & 0xff) == SQLITE_CORRUPT) {
        rc = SQLITE_OK;
    }
    sqlite3Fts5IndexCloseReader(pTab.p.pIndex);
    pTab.p.pConfig.?.pzErrmsg = null;

    return rc;
}

/// fts5_main.c 22929-23029: the sqlite3_module table (iVersion 4) + module
/// registration + UDF setup.
const fts5Mod = sqlite3_module{
    .iVersion = 4,
    .xCreate = fts5CreateMethod,
    .xConnect = fts5ConnectMethod,
    .xBestIndex = fts5BestIndexMethod,
    .xDisconnect = fts5DisconnectMethod,
    .xDestroy = fts5DestroyMethod,
    .xOpen = fts5OpenMethod,
    .xClose = fts5CloseMethod,
    .xFilter = fts5FilterMethod,
    .xNext = fts5NextMethod,
    .xEof = fts5EofMethod,
    .xColumn = fts5ColumnMethod,
    .xRowid = fts5RowidMethod,
    .xUpdate = fts5UpdateMethod,
    .xBegin = fts5BeginMethod,
    .xSync = fts5SyncMethod,
    .xCommit = fts5CommitMethod,
    .xRollback = fts5RollbackMethod,
    .xFindFunction = fts5FindFunctionMethod,
    .xRename = fts5RenameMethod,
    .xSavepoint = fts5SavepointMethod,
    .xRelease = fts5ReleaseMethod,
    .xRollbackTo = fts5RollbackToMethod,
    .xShadowName = fts5ShadowName,
    .xIntegrity = fts5IntegrityMethod,
};

fn fts5Init(db: ?*sqlite3) c_int {
    var rc: c_int = undefined;
    const pGlobal: ?*Fts5Global = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts5Global))));
    if (pGlobal == null) {
        rc = SQLITE_NOMEM;
    } else {
        const pg = pGlobal.?;
        const p: ?*anyopaque = @ptrCast(pg);
        _ = memset(pg, 0, @sizeOf(Fts5Global));
        pg.db = db;
        pg.api.iVersion = 3;
        pg.api.xCreateFunction = fts5CreateAux;
        pg.api.xCreateTokenizer = fts5CreateTokenizer;
        pg.api.xFindTokenizer = fts5FindTokenizer;
        pg.api.xCreateTokenizer_v2 = fts5CreateTokenizer_v2;
        pg.api.xFindTokenizer_v2 = fts5FindTokenizer_v2;

        sqlite3_randomness(@sizeOf(@FieldType(Fts5Global, "aLocaleHdr")), &pg.aLocaleHdr);
        pg.aLocaleHdr[0] ^= 0xF924976D;
        pg.aLocaleHdr[1] ^= 0x16596E13;
        pg.aLocaleHdr[2] ^= 0x7C80BEAA;
        pg.aLocaleHdr[3] ^= 0x9B03A67F;

        rc = sqlite3_create_module_v2(db, "fts5", &fts5Mod, p, fts5ModuleDestroy);
        if (rc == SQLITE_OK) rc = sqlite3Fts5IndexInit(db);
        if (rc == SQLITE_OK) rc = sqlite3Fts5ExprInit(pg, db);
        if (rc == SQLITE_OK) rc = sqlite3Fts5AuxInit(&pg.api);
        if (rc == SQLITE_OK) rc = sqlite3Fts5TokenizerInit(&pg.api);
        if (rc == SQLITE_OK) rc = sqlite3Fts5VocabInit(pg, db);
        if (rc == SQLITE_OK) {
            rc = sqlite3_create_function(db, "fts5", 1, SQLITE_UTF8, p, fts5Fts5Func, null, null);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_create_function(db, "fts5_source_id", 0, SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS, p, fts5SourceIdFunc, null, null);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_create_function(db, "fts5_locale", 2, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_RESULT_SUBTYPE | SQLITE_SUBTYPE, p, fts5LocaleFunc, null, null);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_create_function(db, "fts5_insttoken", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_RESULT_SUBTYPE, p, fts5InsttokenFunc, null, null);
        }
    }

    return rc;
}

/// The one symbol the SQLite core registers (SQLITE_CORE build).
export fn sqlite3Fts5Init(db: ?*sqlite3) callconv(.c) c_int {
    return fts5Init(db);
}

comptime {
    _ = int;
    _ = config;
}
