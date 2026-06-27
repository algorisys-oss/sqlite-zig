//! Shared FOUNDATION for the Zig port of SQLite's FTS5 extension.
//!
//! The vendored `vendor/tsrc/fts5.c` is a 28k-line amalgamation of the entire
//! FTS5 extension (ext/fts5/*). We port it as a SINGLE Zig object built from
//! this shared foundation plus one Zig sub-file per amalgamation section
//! (fts5_varint, fts5_buffer, fts5_hash, fts5_unicode2, fts5_tokenize,
//! fts5_config, fts5_aux, fts5_vocab, fts5_expr, fts5_index, fts5_storage,
//! fts5_main). All of them `@import("fts5_int.zig")` so there is exactly ONE
//! definition of every shared type and constant — the whole point of the
//! foundation. The Lemon parser (fts5parse.c) stays C.
//!
//! This file exports NO C-ABI symbols. It is pure shared types, constants and
//! raw-memory helpers, mirroring `fts5Int.h` (the cross-section internal
//! header, amalgamation lines 794-1753) and the public `fts5.h` ABI (lines
//! 38-792), byte-for-byte as Zig `extern struct`s.
//!
//! Section-private structs (Fts5Index internals, Fts5Expr/Fts5ExprNode/…,
//! Fts5Cursor, Fts5FullTable, Fts5Global, Fts5Hash, Fts5Storage, …) are NOT
//! defined here as concrete layouts: they live entirely within a single
//! section and only ever cross a section boundary BY POINTER. They are exposed
//! here as `opaque{}` handles. The section that owns a struct defines its real
//! layout privately (or, if a future section needs field access across the
//! boundary, the concrete `extern struct` is promoted into this file).

const std = @import("std");
const config = @import("config");

// ===========================================================================
// Scalar type aliases — FTS5 uses these names throughout (fts5Int.h 821-826).
//   typedef unsigned char  u8;  unsigned int u32;  unsigned short u16;
//   typedef short i16;          sqlite3_int64 i64;  sqlite3_uint64 u64;
// FTS5 rowids and positions are i64.
// ===========================================================================
pub const u8_t = u8;
pub const u16_t = u16;
pub const u32_t = u32;
pub const u64_t = u64;
pub const i16_t = i16;
pub const i64_t = i64;
pub const c_int_t = c_int;

// ===========================================================================
// Result codes / value types / constraint ops (sqlite3.h)
// ===========================================================================
pub const SQLITE_OK: c_int = 0;
pub const SQLITE_ERROR: c_int = 1;
pub const SQLITE_INTERNAL: c_int = 2;
pub const SQLITE_NOMEM: c_int = 7;
pub const SQLITE_READONLY: c_int = 8;
pub const SQLITE_CONSTRAINT: c_int = 19;
pub const SQLITE_MISMATCH: c_int = 20;
pub const SQLITE_RANGE: c_int = 25;
pub const SQLITE_ROW: c_int = 100;
pub const SQLITE_DONE: c_int = 101;
pub const SQLITE_ABORT: c_int = 4;
pub const SQLITE_BUSY: c_int = 5;
pub const SQLITE_CORRUPT: c_int = 11;
pub const SQLITE_NOTFOUND: c_int = 12;
pub const SQLITE_CORRUPT_VTAB: c_int = SQLITE_CORRUPT | (1 << 8);
pub const SQLITE_CONSTRAINT_VTAB: c_int = SQLITE_CONSTRAINT | (9 << 8);

// Value types (sqlite3.h)
pub const SQLITE_INTEGER: c_int = 1;
pub const SQLITE_FLOAT: c_int = 2;
pub const SQLITE_TEXT: c_int = 3;
pub const SQLITE_BLOB: c_int = 4;
pub const SQLITE_NULL: c_int = 5;

// Text encodings / function flags (sqlite3.h)
pub const SQLITE_UTF8: c_int = 1;
pub const SQLITE_DETERMINISTIC: c_int = 0x000000800;
pub const SQLITE_INNOCUOUS: c_int = 0x000200000;

// Constraint operators (sqlite3.h)
pub const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
pub const SQLITE_INDEX_CONSTRAINT_GT: u8 = 4;
pub const SQLITE_INDEX_CONSTRAINT_LE: u8 = 8;
pub const SQLITE_INDEX_CONSTRAINT_LT: u8 = 16;
pub const SQLITE_INDEX_CONSTRAINT_GE: u8 = 32;
pub const SQLITE_INDEX_CONSTRAINT_MATCH: u8 = 64;
pub const SQLITE_INDEX_CONSTRAINT_LIKE: u8 = 65;
pub const SQLITE_INDEX_CONSTRAINT_GLOB: u8 = 66;
pub const SQLITE_INDEX_CONSTRAINT_LIMIT: u8 = 73;
pub const SQLITE_INDEX_CONSTRAINT_OFFSET: u8 = 74;
pub const SQLITE_INDEX_SCAN_UNIQUE: c_int = 0x00000001;

// xVtab config ops (sqlite3.h)
pub const SQLITE_VTAB_CONSTRAINT_SUPPORT: c_int = 1;
pub const SQLITE_VTAB_INNOCUOUS: c_int = 2;
pub const SQLITE_VTAB_DIRECTONLY: c_int = 3;

// Destructor sentinels: SQLITE_STATIC==0, SQLITE_TRANSIENT==-1 (sqlite3.h)
pub const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
pub const SQLITE_STATIC: DestructorFn = null;
pub const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// ===========================================================================
// Public ABI opaque handles (sqlite3.h)
// ===========================================================================
pub const sqlite3 = anyopaque;
pub const sqlite3_stmt = anyopaque;
pub const sqlite3_context = anyopaque;
pub const sqlite3_value = anyopaque;
pub const sqlite3_blob = anyopaque;
pub const sqlite3_api_routines = anyopaque;
pub const sqlite3_int64 = i64;
pub const sqlite3_uint64 = u64;

// ===========================================================================
// Public ABI structs (sqlite3.h) — sqlite3_vtab / cursor / index_info / module
// ===========================================================================
pub const sqlite3_vtab = extern struct {
    pModule: ?*const sqlite3_module,
    nRef: c_int,
    zErrMsg: ?[*:0]u8,
};

pub const sqlite3_vtab_cursor = extern struct {
    pVtab: ?*sqlite3_vtab,
};

pub const sqlite3_index_constraint = extern struct {
    iColumn: c_int,
    op: u8,
    usable: u8,
    iTermOffset: c_int,
};

pub const sqlite3_index_orderby = extern struct {
    iColumn: c_int,
    desc: u8,
};

pub const sqlite3_index_constraint_usage = extern struct {
    argvIndex: c_int,
    omit: u8,
};

pub const sqlite3_index_info = extern struct {
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

/// sqlite3_module, iVersion 4 (matches the C fts5 module table field-for-field).
pub const ModFn0 = ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int;
pub const sqlite3_module = extern struct {
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

// ===========================================================================
// Public FTS5 extension ABI (fts5.h 38-792)
// ===========================================================================
pub const Fts5Context = anyopaque;
pub const Fts5Tokenizer = anyopaque;

/// fts5.h: struct Fts5PhraseIter { const unsigned char *a, *b; }.
pub const Fts5PhraseIter = extern struct {
    a: ?[*]const u8,
    b: ?[*]const u8,
};

pub const fts5_extension_function = ?*const fn (
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    pCtx: ?*sqlite3_context,
    nVal: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) void;

/// fts5.h: struct Fts5ExtensionApi (iVersion 4). Method-table, field-for-field.
pub const Fts5ExtensionApi = extern struct {
    iVersion: c_int,
    xUserData: ?*const fn (?*Fts5Context) callconv(.c) ?*anyopaque,
    xColumnCount: ?*const fn (?*Fts5Context) callconv(.c) c_int,
    xRowCount: ?*const fn (?*Fts5Context, *i64) callconv(.c) c_int,
    xColumnTotalSize: ?*const fn (?*Fts5Context, c_int, *i64) callconv(.c) c_int,
    xTokenize: ?*const fn (?*Fts5Context, ?[*]const u8, c_int, ?*anyopaque, ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int) callconv(.c) c_int,
    xPhraseCount: ?*const fn (?*Fts5Context) callconv(.c) c_int,
    xPhraseSize: ?*const fn (?*Fts5Context, c_int) callconv(.c) c_int,
    xInstCount: ?*const fn (?*Fts5Context, *c_int) callconv(.c) c_int,
    xInst: ?*const fn (?*Fts5Context, c_int, *c_int, *c_int, *c_int) callconv(.c) c_int,
    xRowid: ?*const fn (?*Fts5Context) callconv(.c) i64,
    xColumnText: ?*const fn (?*Fts5Context, c_int, *?[*]const u8, *c_int) callconv(.c) c_int,
    xColumnSize: ?*const fn (?*Fts5Context, c_int, *c_int) callconv(.c) c_int,
    xQueryPhrase: ?*const fn (?*Fts5Context, c_int, ?*anyopaque, ?*const fn (?*const Fts5ExtensionApi, ?*Fts5Context, ?*anyopaque) callconv(.c) c_int) callconv(.c) c_int,
    xSetAuxdata: ?*const fn (?*Fts5Context, ?*anyopaque, ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int,
    xGetAuxdata: ?*const fn (?*Fts5Context, c_int) callconv(.c) ?*anyopaque,
    xPhraseFirst: ?*const fn (?*Fts5Context, c_int, *Fts5PhraseIter, *c_int, *c_int) callconv(.c) c_int,
    xPhraseNext: ?*const fn (?*Fts5Context, *Fts5PhraseIter, *c_int, *c_int) callconv(.c) void,
    xPhraseFirstColumn: ?*const fn (?*Fts5Context, c_int, *Fts5PhraseIter, *c_int) callconv(.c) c_int,
    xPhraseNextColumn: ?*const fn (?*Fts5Context, *Fts5PhraseIter, *c_int) callconv(.c) void,
    // iVersion>=3
    xQueryToken: ?*const fn (?*Fts5Context, c_int, c_int, *?[*]const u8, *c_int) callconv(.c) c_int,
    xInstToken: ?*const fn (?*Fts5Context, c_int, c_int, *?[*]const u8, *c_int) callconv(.c) c_int,
    // iVersion>=4
    xColumnLocale: ?*const fn (?*Fts5Context, c_int, *?[*]const u8, *c_int) callconv(.c) c_int,
    xTokenize_v2: ?*const fn (?*Fts5Context, ?[*]const u8, c_int, ?[*]const u8, c_int, ?*anyopaque, ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int) callconv(.c) c_int,
};

/// fts5.h: callback signature shared by fts5_tokenizer{,_v2}.xTokenize().
pub const Fts5TokenCb = ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int;

/// fts5.h: struct fts5_tokenizer_v2 (iVersion 2).
pub const fts5_tokenizer_v2 = extern struct {
    iVersion: c_int,
    xCreate: ?*const fn (?*anyopaque, ?[*]const ?[*:0]const u8, c_int, *?*Fts5Tokenizer) callconv(.c) c_int,
    xDelete: ?*const fn (?*Fts5Tokenizer) callconv(.c) void,
    xTokenize: ?*const fn (?*Fts5Tokenizer, ?*anyopaque, c_int, ?[*]const u8, c_int, ?[*]const u8, c_int, Fts5TokenCb) callconv(.c) c_int,
};

/// fts5.h: struct fts5_tokenizer (legacy, no iVersion, no locale arg).
pub const fts5_tokenizer = extern struct {
    xCreate: ?*const fn (?*anyopaque, ?[*]const ?[*:0]const u8, c_int, *?*Fts5Tokenizer) callconv(.c) c_int,
    xDelete: ?*const fn (?*Fts5Tokenizer) callconv(.c) void,
    xTokenize: ?*const fn (?*Fts5Tokenizer, ?*anyopaque, c_int, ?[*]const u8, c_int, Fts5TokenCb) callconv(.c) c_int,
};

/// fts5.h: struct fts5_api (iVersion 3).
pub const fts5_api = extern struct {
    iVersion: c_int,
    xCreateTokenizer: ?*const fn (*fts5_api, [*:0]const u8, ?*anyopaque, *fts5_tokenizer, ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int,
    xFindTokenizer: ?*const fn (*fts5_api, [*:0]const u8, *?*anyopaque, *fts5_tokenizer) callconv(.c) c_int,
    xCreateFunction: ?*const fn (*fts5_api, [*:0]const u8, ?*anyopaque, fts5_extension_function, ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int,
    // iVersion>=3
    xCreateTokenizer_v2: ?*const fn (*fts5_api, [*:0]const u8, ?*anyopaque, *fts5_tokenizer_v2, ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int,
    xFindTokenizer_v2: ?*const fn (*fts5_api, [*:0]const u8, *?*anyopaque, *?*fts5_tokenizer_v2) callconv(.c) c_int,
};

// Flags for fts5_tokenizer.xTokenize() (fts5.h 718-721)
pub const FTS5_TOKENIZE_QUERY: c_int = 0x0001;
pub const FTS5_TOKENIZE_PREFIX: c_int = 0x0002;
pub const FTS5_TOKENIZE_DOCUMENT: c_int = 0x0004;
pub const FTS5_TOKENIZE_AUX: c_int = 0x0008;

// Flag the tokenizer passes back to its xToken callback (fts5.h 725)
pub const FTS5_TOKEN_COLOCATED: c_int = 0x0001;

// ===========================================================================
// fts5Int.h constants (794-1753)
// ===========================================================================

// 64-bit min/max (fts5Int.h 854-855)
pub const LARGEST_INT64: i64 = 0x7fffffffffffffff;
pub const SMALLEST_INT64: i64 = -0x8000000000000000;
// 32-bit min/max (fts5Int.h 883-884)
pub const LARGEST_INT32: c_int = 0x7fffffff;
pub const SMALLEST_INT32: c_int = -0x7fffffff - 1;

pub const FTS5_MAX_TOKEN_SIZE: c_int = 32768; // fts5Int.h 889
pub const FTS5_MAX_PREFIX_INDEXES: c_int = 31; // fts5Int.h 896
pub const FTS5_MAX_SEGMENT: c_int = 2000; // fts5Int.h 901
pub const FTS5_DEFAULT_NEARDIST: c_int = 10; // fts5Int.h 903
pub const FTS5_DEFAULT_RANK = "bm25"; // fts5Int.h 904
pub const FTS5_RANK_NAME = "rank"; // fts5Int.h 907
pub const FTS5_ROWID_NAME = "rowid"; // fts5Int.h 908

// %_config 'version' values (fts5Int.h 1071-1072)
pub const FTS5_CURRENT_VERSION: c_int = 4;
pub const FTS5_CURRENT_VERSION_SECUREDELETE: c_int = 5;

// FTS5_CONTENT_* (fts5Int.h 1074-1077)
pub const FTS5_CONTENT_NORMAL: c_int = 0;
pub const FTS5_CONTENT_NONE: c_int = 1;
pub const FTS5_CONTENT_EXTERNAL: c_int = 2;
pub const FTS5_CONTENT_UNINDEXED: c_int = 3;

// FTS5_DETAIL_* (fts5Int.h 1079-1081)
pub const FTS5_DETAIL_FULL: c_int = 0;
pub const FTS5_DETAIL_NONE: c_int = 1;
pub const FTS5_DETAIL_COLUMNS: c_int = 2;

// FTS5_PATTERN_* (fts5Int.h 1083-1085)
pub const FTS5_PATTERN_NONE: c_int = 0;
pub const FTS5_PATTERN_LIKE: c_int = 65; // == SQLITE_INDEX_CONSTRAINT_LIKE
pub const FTS5_PATTERN_GLOB: c_int = 66; // == SQLITE_INDEX_CONSTRAINT_GLOB

// Poslist position <-> (col,off) packing (fts5Int.h 1158-1159)
pub inline fn FTS5_POS2COLUMN(iPos: i64) c_int {
    return @intCast((iPos >> 32) & 0x7FFFFFFF);
}
pub inline fn FTS5_POS2OFFSET(iPos: i64) c_int {
    return @intCast(iPos & 0x7FFFFFFF);
}

// IndexQuery() flags (fts5Int.h 1231-1243)
pub const FTS5INDEX_QUERY_PREFIX: c_int = 0x0001;
pub const FTS5INDEX_QUERY_DESC: c_int = 0x0002;
pub const FTS5INDEX_QUERY_TEST_NOIDX: c_int = 0x0004;
pub const FTS5INDEX_QUERY_SCAN: c_int = 0x0008;
pub const FTS5INDEX_QUERY_SKIPEMPTY: c_int = 0x0010;
pub const FTS5INDEX_QUERY_NOOUTPUT: c_int = 0x0020;
pub const FTS5INDEX_QUERY_SKIPHASH: c_int = 0x0040;
pub const FTS5INDEX_QUERY_NOTOKENDATA: c_int = 0x0080;
pub const FTS5INDEX_QUERY_SCANONETERM: c_int = 0x0100;

// fts5_storage.c statement ids (fts5Int.h 1530-1532)
pub const FTS5_STMT_SCAN_ASC: c_int = 0;
pub const FTS5_STMT_SCAN_DESC: c_int = 1;
pub const FTS5_STMT_LOOKUP: c_int = 2;

// fts5parse.h token / parse-op codes (amalgamation 1756-1771). Also the
// Fts5ExprNode.eType values used throughout fts5_expr.c (FTS5_EOF==0 is a
// fts5_expr.c local, included for completeness).
pub const FTS5_EOF: c_int = 0;
pub const FTS5_OR: c_int = 1;
pub const FTS5_AND: c_int = 2;
pub const FTS5_NOT: c_int = 3;
pub const FTS5_TERM: c_int = 4;
pub const FTS5_COLON: c_int = 5;
pub const FTS5_MINUS: c_int = 6;
pub const FTS5_LCP: c_int = 7;
pub const FTS5_RCP: c_int = 8;
pub const FTS5_STRING: c_int = 9;
pub const FTS5_LP: c_int = 10;
pub const FTS5_RP: c_int = 11;
pub const FTS5_CARET: c_int = 12;
pub const FTS5_COMMA: c_int = 13;
pub const FTS5_PLUS: c_int = 14;
pub const FTS5_STAR: c_int = 15;

// SQLITE_FTS5_MAX_EXPR_DEPTH default (fts5_expr.c 5749)
pub const SQLITE_FTS5_MAX_EXPR_DEPTH: c_int = 256;

// ===========================================================================
// Shared fts5Int.h structs (truly cross-section: passed by value or used by
// field across the section boundaries). Mirrored byte-for-byte.
// ===========================================================================

/// fts5Int.h 954-957: struct Fts5Colset { int nCol; int aiCol[FLEXARRAY]; }.
/// aiCol is a flexible array member; reached by pointer arithmetic via
/// colsetCol(). Allocation size is SZ_FTS5COLSET(N) (see helper below).
pub const Fts5Colset = extern struct {
    nCol: c_int,
    aiCol: [0]c_int,
};
/// fts5Int.h 960: SZ_FTS5COLSET(N) == sizeof(i64)*((N+2)/2).
pub inline fn SZ_FTS5COLSET(n: c_int) usize {
    return @sizeOf(i64) * @as(usize, @intCast(@divTrunc(n + 2, 2)));
}
pub inline fn colsetCol(p: *Fts5Colset, i: c_int) *c_int {
    const a: [*]c_int = @ptrCast(&p.aiCol);
    return &a[@intCast(i)];
}

/// fts5Int.h 970-979: struct Fts5TokenizerConfig.
pub const Fts5TokenizerConfig = extern struct {
    pTok: ?*Fts5Tokenizer,
    pApi2: ?*fts5_tokenizer_v2,
    pApi1: ?*fts5_tokenizer,
    azArg: ?[*]const ?[*:0]const u8,
    nArg: c_int,
    ePattern: c_int, // FTS5_PATTERN_* constant
    pLocale: ?[*]const u8,
    nLocale: c_int,
};

/// fts5Int.h 1022-1066: struct Fts5Config. The CREATE-VIRTUAL-TABLE/%_config
/// state object — referenced by every section (config/expr/index/storage/main/
/// tokenize/vocab). The trailing `bPrefixIndex` field exists only under
/// SQLITE_DEBUG, so it is config-gated to keep sizeof() and offsets identical
/// in production and `--dev` builds.
pub const Fts5Config = extern struct {
    db: ?*sqlite3,
    pGlobal: ?*Fts5Global,
    zDb: ?[*:0]u8,
    zName: ?[*:0]u8,
    nCol: c_int,
    azCol: ?[*]?[*:0]u8,
    abUnindexed: ?[*]u8,
    nPrefix: c_int,
    aPrefix: ?[*]c_int,
    eContent: c_int,
    bContentlessDelete: c_int,
    bContentlessUnindexed: c_int,
    zContent: ?[*:0]u8,
    zContentRowid: ?[*:0]u8,
    bColumnsize: c_int,
    bTokendata: c_int,
    bLocale: c_int,
    eDetail: c_int,
    zContentExprlist: ?[*:0]u8,
    t: Fts5TokenizerConfig,
    bLock: c_int,

    // Values loaded from the %_config table
    iVersion: c_int,
    iCookie: c_int,
    pgsz: c_int,
    nAutomerge: c_int,
    nCrisisMerge: c_int,
    nUsermerge: c_int,
    nHashSize: c_int,
    zRank: ?[*:0]u8,
    zRankArgs: ?[*:0]u8,
    bSecureDelete: c_int,
    nDeleteMerge: c_int,
    bPrefixInsttoken: c_int,

    pzErrmsg: ?*?[*:0]u8,

    // SQLITE_DEBUG-only trailing field.
    bPrefixIndex: if (config.sqlite_debug) c_int else void =
        if (config.sqlite_debug) 0 else {},
};

/// fts5Int.h 1126-1130: struct Fts5Buffer { u8 *p; int n; int nSpace; }.
/// The incremental string/blob builder used pervasively.
pub const Fts5Buffer = extern struct {
    p: ?[*]u8,
    n: c_int,
    nSpace: c_int,
};

/// fts5Int.h 1162-1173: struct Fts5PoslistReader.
pub const Fts5PoslistReader = extern struct {
    a: ?[*]const u8, // poslist buffer
    n: c_int, // size of a[]
    i: c_int, // current offset in a[]
    bFlag: u8, // client use
    bEof: u8, // set at EOF
    iPos: i64, // (iCol<<32) + iPos
};

/// fts5Int.h 1181-1183: struct Fts5PoslistWriter { i64 iPrev; }.
pub const Fts5PoslistWriter = extern struct {
    iPrev: i64,
};

/// fts5Int.h 1219-1224: struct Fts5IndexIter. The PUBLIC face of an index
/// iterator — fts5_expr.c reads iRowid/pData/nData/bEof directly, so the
/// layout is shared even though fts5_index.c owns a larger private subclass.
pub const Fts5IndexIter = extern struct {
    iRowid: i64,
    pData: ?[*]const u8,
    nData: c_int,
    bEof: u8,
};
pub inline fn sqlite3Fts5IterEof(p: *Fts5IndexIter) c_int {
    return p.bEof;
}

/// fts5Int.h 1444-1448: struct Fts5Table (the vtab base, shared by main/
/// storage/vocab). fts5_main.c subclasses this as Fts5FullTable.
pub const Fts5Table = extern struct {
    base: sqlite3_vtab,
    pConfig: ?*Fts5Config,
    pIndex: ?*Fts5Index,
};

/// fts5Int.h 1587-1590: struct Fts5Token { const char *p; int n; }. Passed BY
/// VALUE into the parser (sqlite3Fts5Parser), so byte-exactness matters.
pub const Fts5Token = extern struct {
    p: ?[*]const u8, // token text (not nul-terminated)
    n: c_int, // size of p in bytes
};

// ===========================================================================
// Section-private struct handles. These structs are defined concretely inside
// the section that owns them; across boundaries they are only held by pointer.
// Declared opaque here so any section can name `?*int.Fts5Xxx`. If a future
// section needs field-level access across the boundary, promote the concrete
// `extern struct` into this file.
// ===========================================================================
pub const Fts5Global = opaque {}; // fts5_main.c
pub const Fts5Index = opaque {}; // fts5_index.c
pub const Fts5Hash = opaque {}; // fts5_hash.c
pub const Fts5Storage = opaque {}; // fts5_storage.c
pub const Fts5Expr = opaque {}; // fts5_expr.c
pub const Fts5ExprNode = opaque {}; // fts5_expr.c
pub const Fts5ExprPhrase = opaque {}; // fts5_expr.c
pub const Fts5ExprTerm = opaque {}; // fts5_expr.c
pub const Fts5ExprNearset = opaque {}; // fts5_expr.c
pub const Fts5Parse = opaque {}; // fts5_expr.c / fts5parse.c
pub const Fts5PoslistPopulator = opaque {}; // fts5_expr.c
pub const Fts5Cursor = opaque {}; // fts5_main.c
pub const Fts5FullTable = opaque {}; // fts5_main.c
pub const Fts5Sorter = opaque {}; // fts5_main.c
pub const Fts5Auxiliary = opaque {}; // fts5_main.c
pub const Fts5TokenizerModule = opaque {}; // fts5_main.c
pub const Fts5TokenDataIter = opaque {}; // fts5_index.c
pub const Fts5Termset = opaque {}; // fts5_buffer.c (apHash[512] of entries)

// ===========================================================================
// Raw-memory helpers (copied from src/fts3.zig / src/insert.zig idiom). Used
// by section files that read/write fields of a struct whose offset is pinned
// at a constant rather than via a Zig field. Since the whole FTS5 family is
// Zig and shares these mirrors, field access is normally direct; these are
// here for the rare pinned-offset case and for parity with the FTS3 idiom.
// ===========================================================================
pub inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
pub inline fn rd(comptime T: type, p: ?*anyopaque, offs: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + offs);
    return q.*;
}
pub inline fn wr(comptime T: type, p: ?*anyopaque, offs: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + offs);
    q.* = v;
}
/// Pointer to the byte at `offs` within `p`.
pub inline fn fieldPtr(p: ?*anyopaque, offs: usize) [*]u8 {
    return base(p) + offs;
}
/// Read a pointer-sized value at `offs` within `p`.
pub inline fn rdp(comptime T: type, p: ?*anyopaque, offs: usize) ?*T {
    return @ptrCast(@alignCast(base(p) + offs));
}
/// Resolve a struct-field byte offset: use the c_layout value if present,
/// else the supplied fallback. (FTS5 mirrors layout directly, so callers
/// typically pass @offsetOf(...) as the fallback.)
pub fn off(comptime name: []const u8, comptime fallback: usize) usize {
    const L = @import("c_layout.zig").c;
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}
