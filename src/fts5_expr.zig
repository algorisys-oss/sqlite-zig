//! Zig port of the fts5_expr.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 5728-9015).
//!
//! The FTS5 MATCH-expression engine: it tokenizes a query string, drives the
//! Lemon parser (fts5parse) through the sqlite3Fts5Parse* builder callbacks to
//! assemble an expression tree (Fts5Expr / Fts5ExprNode / Fts5ExprNearset /
//! Fts5ExprPhrase / Fts5ExprTerm), then evaluates that tree against an
//! fts5_index iterator (sqlite3Fts5Index*), producing matching rowids and
//! per-phrase position lists.
//!
//! The Fts5Expr family is section-PRIVATE: fts5_int.zig exposes the structs as
//! opaque handles (other sections only hold pointers), so the concrete layouts
//! are defined here, byte-for-byte with the C structs (5774-5887). Shared
//! layouts (Fts5Token, Fts5Colset, Fts5Buffer, Fts5IndexIter, Fts5PoslistReader/
//! Writer, Fts5Config) come from the foundation.
//!
//! Cross-object wiring:
//!   * sqlite3Fts5Parse* builders are EXPORTED — the (Zig) fts5parse engine and
//!     the fts5_main/index/storage/vocab sections call them.
//!   * sqlite3Fts5Expr*    are EXPORTED — fts5_main/storage/vocab call them.
//!   * the parser entry points (sqlite3Fts5Parser/Alloc/Free/Fallback/Trace) are
//!     EXTERN — defined by fts5parse.zig.
//!   * sqlite3Fts5Index* / Config* / Tokenize / Unicode* / buffer + poslist
//!     helpers are EXTERN — defined by their own sections.

const int = @import("fts5_int.zig");
const std = @import("std");

const Fts5Config = int.Fts5Config;
const Fts5Token = int.Fts5Token;
const Fts5Colset = int.Fts5Colset;
const Fts5Buffer = int.Fts5Buffer;
const Fts5IndexIter = int.Fts5IndexIter;
const Fts5PoslistReader = int.Fts5PoslistReader;
const Fts5PoslistWriter = int.Fts5PoslistWriter;
const Fts5Index = int.Fts5Index;
const Fts5Global = int.Fts5Global;

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_ERROR = int.SQLITE_ERROR;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_RANGE = int.SQLITE_RANGE;
const SQLITE_UTF8 = int.SQLITE_UTF8;

// Token / node-type codes (fts5_int.zig).
const FTS5_EOF = int.FTS5_EOF;
const FTS5_OR = int.FTS5_OR;
const FTS5_AND = int.FTS5_AND;
const FTS5_NOT = int.FTS5_NOT;
const FTS5_TERM = int.FTS5_TERM;
const FTS5_STRING = int.FTS5_STRING;
const FTS5_LP = int.FTS5_LP;
const FTS5_RP = int.FTS5_RP;
const FTS5_LCP = int.FTS5_LCP;
const FTS5_RCP = int.FTS5_RCP;
const FTS5_COLON = int.FTS5_COLON;
const FTS5_COMMA = int.FTS5_COMMA;
const FTS5_PLUS = int.FTS5_PLUS;
const FTS5_STAR = int.FTS5_STAR;
const FTS5_MINUS = int.FTS5_MINUS;
const FTS5_CARET = int.FTS5_CARET;

const FTS5_TOKEN_COLOCATED = int.FTS5_TOKEN_COLOCATED;
const FTS5_TOKENIZE_QUERY = int.FTS5_TOKENIZE_QUERY;
const FTS5_TOKENIZE_PREFIX = int.FTS5_TOKENIZE_PREFIX;
const FTS5_TOKENIZE_DOCUMENT = int.FTS5_TOKENIZE_DOCUMENT;
const FTS5_MAX_TOKEN_SIZE = int.FTS5_MAX_TOKEN_SIZE;
const FTS5_DEFAULT_NEARDIST = int.FTS5_DEFAULT_NEARDIST;
const FTS5INDEX_QUERY_PREFIX = int.FTS5INDEX_QUERY_PREFIX;
const FTS5INDEX_QUERY_DESC = int.FTS5INDEX_QUERY_DESC;
const FTS5_DETAIL_FULL = int.FTS5_DETAIL_FULL;
const FTS5_DETAIL_NONE = int.FTS5_DETAIL_NONE;
const SQLITE_FTS5_MAX_EXPR_DEPTH = int.SQLITE_FTS5_MAX_EXPR_DEPTH;

// fts5_expr.c 5757: FTS5_LARGEST_INT64 == 0xffffffff | (0x7fffffff << 32).
const FTS5_LARGEST_INT64: i64 = @bitCast(@as(u64, 0xffffffff) | (@as(u64, 0x7fffffff) << 32));
// fts5_expr.c 6426: FTS5_LOOKAHEAD_EOF == ((i64)1) << 62.
const FTS5_LOOKAHEAD_EOF: i64 = @as(i64, 1) << 62;

inline fn FTS5_POS2OFFSET(iPos: i64) c_int {
    return int.FTS5_POS2OFFSET(iPos);
}
inline fn MAX(a: c_int, b: c_int) c_int {
    return if (a > b) a else b;
}

// ===========================================================================
// libc + public sqlite3 API (resolved at link time)
// ===========================================================================
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memmove(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn strlen(s: [*:0]const u8) usize;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *anyopaque) ?[*:0]u8;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_stricmp(a: [*:0]const u8, b: [*:0]const u8) c_int;

// public sqlite3 funcs used only in the SQLITE_TEST/DEBUG block
extern fn sqlite3_context_db_handle(ctx: ?*anyopaque) ?*anyopaque;
extern fn sqlite3_user_data(ctx: ?*anyopaque) ?*anyopaque;
extern fn sqlite3_value_text(v: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3_value_int(v: ?*anyopaque) c_int;
extern fn sqlite3_result_text(ctx: ?*anyopaque, z: ?[*:0]const u8, n: c_int, d: int.DestructorFn) void;
extern fn sqlite3_result_int(ctx: ?*anyopaque, v: c_int) void;
extern fn sqlite3_result_error(ctx: ?*anyopaque, z: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(ctx: ?*anyopaque, rc: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*anyopaque) void;
extern fn sqlite3_create_function(db: ?*anyopaque, z: [*:0]const u8, n: c_int, e: c_int, p: ?*anyopaque, x: ?*const fn (?*anyopaque, c_int, ?[*]?*anyopaque) callconv(.c) void, xs: ?*anyopaque, xf: ?*anyopaque) c_int;

// ===========================================================================
// sibling sections (extern). Signatures mirror fts5Int.h.
// ===========================================================================
// fts5parse.zig (the Lemon engine)
const MallocProc = ?*const fn (u64) callconv(.c) ?*anyopaque;
const FreeProc = ?*const fn (?*anyopaque) callconv(.c) void;
extern fn sqlite3Fts5ParserAlloc(mallocProc: MallocProc) callconv(.c) ?*anyopaque;
extern fn sqlite3Fts5ParserFree(p: ?*anyopaque, freeProc: FreeProc) callconv(.c) void;
extern fn sqlite3Fts5Parser(p: ?*anyopaque, major: c_int, minor: Fts5Token, pParse: ?*Fts5Parse) callconv(.c) void;
extern fn sqlite3Fts5ParserFallback(iToken: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5ParserTrace(TraceFILE: ?*anyopaque, zTracePrompt: ?[*:0]u8) callconv(.c) void;

// fts5_buffer.c / fts5_varint.c
extern fn sqlite3Fts5BufferSet(pRc: *c_int, pBuf: *Fts5Buffer, nData: c_int, pData: [*]const u8) callconv(.c) void;
extern fn sqlite3Fts5BufferFree(pBuf: *Fts5Buffer) callconv(.c) void;
extern fn sqlite3Fts5BufferZero(pBuf: *Fts5Buffer) callconv(.c) void;
extern fn sqlite3Fts5PoslistReaderInit(a: ?[*]const u8, n: c_int, pIter: *Fts5PoslistReader) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistReaderNext(pIter: *Fts5PoslistReader) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistWriterAppend(pBuf: *Fts5Buffer, pWriter: *Fts5PoslistWriter, iPos: i64) callconv(.c) c_int;
extern fn sqlite3Fts5PoslistSafeAppend(pBuf: *Fts5Buffer, piPrev: *i64, iPos: i64) callconv(.c) void;
extern fn sqlite3Fts5PoslistNext64(a: ?[*]const u8, n: c_int, pi: *c_int, piOff: *i64) callconv(.c) c_int;
extern fn sqlite3Fts5MallocZero(pRc: *c_int, nByte: i64) callconv(.c) ?*anyopaque;
extern fn sqlite3Fts5Strndup(pRc: *c_int, pIn: [*]const u8, nIn: c_int) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5IsBareword(t: u8) callconv(.c) c_int;

// fts5_config.c / fts5_tokenize.c / fts5_unicode2.c
extern fn sqlite3Fts5Dequote(z: [*:0]u8) callconv(.c) void;
const TokenCb = ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int;
extern fn sqlite3Fts5Tokenize(pConfig: ?*Fts5Config, flags: c_int, pText: ?[*]const u8, nText: c_int, pCtx: ?*anyopaque, xToken: TokenCb) callconv(.c) c_int;
extern fn sqlite3Fts5ConfigParse(g: ?*Fts5Global, db: ?*anyopaque, n: c_int, azArg: ?[*]const ?[*:0]const u8, pp: *?*Fts5Config, pzErr: *?[*:0]u8) callconv(.c) c_int;
extern fn sqlite3Fts5ConfigFree(p: ?*Fts5Config) callconv(.c) void;
extern fn sqlite3Fts5UnicodeCatParse(z: [*:0]const u8, a: [*]u8) callconv(.c) c_int;
extern fn sqlite3Fts5UnicodeCategory(iCode: u32) callconv(.c) c_int;
extern fn sqlite3Fts5UnicodeFold(c: c_int, bRemoveDiacritic: c_int) callconv(.c) c_int;

// fts5_index.c
extern fn sqlite3Fts5IndexQuery(p: ?*Fts5Index, pToken: ?[*]const u8, nToken: c_int, flags: c_int, pColset: ?*Fts5Colset, ppIter: *?*Fts5IndexIter) callconv(.c) c_int;
extern fn sqlite3Fts5IterNext(p: ?*Fts5IndexIter) callconv(.c) c_int;
extern fn sqlite3Fts5IterNextFrom(p: ?*Fts5IndexIter, iMatch: i64) callconv(.c) c_int;
extern fn sqlite3Fts5IterClose(p: ?*Fts5IndexIter) callconv(.c) void;
extern fn sqlite3Fts5IterToken(p: ?*Fts5IndexIter, pToken: ?[*]const u8, nToken: c_int, iRowid: i64, iCol: c_int, iOff: c_int, ppOut: *?[*]const u8, pnOut: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5IndexIterClearTokendata(p: ?*Fts5IndexIter) callconv(.c) void;
extern fn sqlite3Fts5IndexIterWriteTokendata(p: ?*Fts5IndexIter, pToken: ?[*]const u8, nToken: c_int, iRowid: i64, iCol: c_int, iOff: c_int) callconv(.c) c_int;

// sqlite3Fts5IterEof(x) == ((x)->bEof) — inline.
inline fn sqlite3Fts5IterEof(p: ?*Fts5IndexIter) c_int {
    return p.?.bEof;
}

// ===========================================================================
// Section-private struct layouts (fts5_expr.c 5774-5887). Defined here; the
// foundation exposes Fts5Expr / Fts5ExprNode / Fts5ExprPhrase / Fts5ExprTerm /
// Fts5ExprNearset / Fts5Parse / Fts5PoslistPopulator as opaque{}.
// ===========================================================================

/// 5774-5781: struct Fts5Expr.
const Fts5Expr = extern struct {
    pIndex: ?*Fts5Index,
    pConfig: ?*Fts5Config,
    pRoot: ?*Fts5ExprNode,
    bDesc: c_int, // iterate in descending rowid order
    nPhrase: c_int, // number of phrases in expression
    apExprPhrase: ?[*]?*Fts5ExprPhrase, // pointers to phrase objects
};

/// xNext method type (5809).
const XNextFn = ?*const fn (?*Fts5Expr, ?*Fts5ExprNode, c_int, i64) callconv(.c) c_int;

/// 5802-5818: struct Fts5ExprNode { ...; Fts5ExprNode *apChild[FLEXARRAY]; }.
const Fts5ExprNode = extern struct {
    eType: c_int, // node type
    bEof: c_int, // true at EOF
    bNomatch: c_int, // true if entry is not a match
    iHeight: c_int, // distance to tree leaf nodes
    xNext: XNextFn, // next method for this node
    iRowid: i64, // current rowid
    pNear: ?*Fts5ExprNearset, // for FTS5_STRING - cluster of phrases
    nChild: c_int, // number of child nodes
    apChild: [0]?*Fts5ExprNode, // array of child nodes (flexible)
};
/// 5821-5822: SZ_FTS5EXPRNODE(N) == offsetof(apChild) + N*sizeof(ptr).
inline fn SZ_FTS5EXPRNODE(n: c_int) i64 {
    return @intCast(@offsetOf(Fts5ExprNode, "apChild") + @as(usize, @intCast(n)) * @sizeOf(?*Fts5ExprNode));
}
inline fn nodeChild(p: *Fts5ExprNode, i: c_int) *?*Fts5ExprNode {
    const a: [*]?*Fts5ExprNode = @ptrCast(&p.apChild);
    return &a[@intCast(i)];
}
/// 5824: Fts5NodeIsString(p) == (eType==FTS5_TERM || eType==FTS5_STRING).
inline fn Fts5NodeIsString(p: *Fts5ExprNode) bool {
    return p.eType == FTS5_TERM or p.eType == FTS5_STRING;
}

/// 5836-5844: struct Fts5ExprTerm.
const Fts5ExprTerm = extern struct {
    bPrefix: u8, // true for a prefix term
    bFirst: u8, // true if token must be first in column
    pTerm: ?[*:0]u8, // term data
    nQueryTerm: c_int, // effective size of term in bytes
    nFullTerm: c_int, // size of term in bytes incl. tokendata
    pIter: ?*Fts5IndexIter, // iterator for this term
    pSynonym: ?*Fts5ExprTerm, // first in list of synonyms
};

/// 5850-5855: struct Fts5ExprPhrase { ...; Fts5ExprTerm aTerm[FLEXARRAY]; }.
const Fts5ExprPhrase = extern struct {
    pNode: ?*Fts5ExprNode, // FTS5_STRING node this phrase is part of
    poslist: Fts5Buffer, // current position list
    nTerm: c_int, // number of entries in aTerm[]
    aTerm: [0]Fts5ExprTerm, // terms that make up this phrase (flexible)
};
/// 5858-5859: SZ_FTS5EXPRPHRASE(N).
inline fn SZ_FTS5EXPRPHRASE(n: c_int) i64 {
    return @intCast(@offsetOf(Fts5ExprPhrase, "aTerm") + @as(usize, @intCast(n)) * @sizeOf(Fts5ExprTerm));
}
inline fn phraseTerm(p: *Fts5ExprPhrase, i: c_int) *Fts5ExprTerm {
    const a: [*]Fts5ExprTerm = @ptrCast(&p.aTerm);
    return &a[@intCast(i)];
}

/// 5865-5870: struct Fts5ExprNearset { ...; Fts5ExprPhrase *apPhrase[FLEXARRAY]; }.
const Fts5ExprNearset = extern struct {
    nNear: c_int, // NEAR parameter
    pColset: ?*Fts5Colset, // columns to search (NULL -> all)
    nPhrase: c_int, // number of entries in apPhrase[]
    apPhrase: [0]?*Fts5ExprPhrase, // array of phrase pointers (flexible)
};
/// 5873-5874: SZ_FTS5EXPRNEARSET(N).
inline fn SZ_FTS5EXPRNEARSET(n: c_int) i64 {
    return @intCast(@offsetOf(Fts5ExprNearset, "apPhrase") + @as(usize, @intCast(n)) * @sizeOf(?*Fts5ExprPhrase));
}
inline fn nearPhrase(p: *Fts5ExprNearset, i: c_int) *?*Fts5ExprPhrase {
    const a: [*]?*Fts5ExprPhrase = @ptrCast(&p.apPhrase);
    return &a[@intCast(i)];
}

/// 5879-5887: struct Fts5Parse (the %extra_argument carried by the parser).
const Fts5Parse = extern struct {
    pConfig: ?*Fts5Config,
    zErr: ?[*:0]u8,
    rc: c_int,
    nPhrase: c_int, // size of apPhrase array
    apPhrase: ?[*]?*Fts5ExprPhrase, // array of all phrases
    pExpr: ?*Fts5ExprNode, // result of a successful parse
    bPhraseToAnd: c_int, // convert "a+b" to "a AND b"
};

// Colset flexible-array accessor (foundation Fts5Colset).
inline fn colsetCol(p: *Fts5Colset, i: c_int) *c_int {
    return int.colsetCol(p, i);
}
inline fn SZ_FTS5COLSET(n: c_int) i64 {
    return @intCast(int.SZ_FTS5COLSET(n));
}

// Buffer macro shims (fts5Int.h 350-354).
inline fn fts5BufferZero(p: *Fts5Buffer) void {
    sqlite3Fts5BufferZero(p);
}
inline fn fts5BufferFree(p: *Fts5Buffer) void {
    sqlite3Fts5BufferFree(p);
}
inline fn fts5BufferSet(pRc: *c_int, p: *Fts5Buffer, n: c_int, d: [*]const u8) void {
    sqlite3Fts5BufferSet(pRc, p, n, d);
}

// ===========================================================================
// sqlite3Fts5ParseError (5914-5923). Latches the first error into pParse.
// EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseError(pParse: *Fts5Parse, zFmt: [*:0]const u8, ...) callconv(.c) void {
    if (pParse.rc == SQLITE_OK) {
        var ap = @cVaStart();
        pParse.zErr = sqlite3_vmprintf(zFmt, @ptrCast(&ap));
        @cVaEnd(&ap);
        pParse.rc = SQLITE_ERROR;
    } else {
        var ap = @cVaStart();
        @cVaEnd(&ap);
    }
}

// 5925-5927.
fn fts5ExprIsspace(t: u8) bool {
    return t == ' ' or t == '\t' or t == '\n' or t == '\r';
}

// ===========================================================================
// fts5ExprGetToken (5932-5994): read the first token at *pz.
// ===========================================================================
fn fts5ExprGetToken(pParse: *Fts5Parse, pz: *[*:0]const u8, pToken: *Fts5Token) c_int {
    var z: [*:0]const u8 = pz.*;
    var tok: c_int = undefined;

    while (fts5ExprIsspace(z[0])) z += 1;

    pToken.p = z;
    pToken.n = 1;
    switch (z[0]) {
        '(' => tok = FTS5_LP,
        ')' => tok = FTS5_RP,
        '{' => tok = FTS5_LCP,
        '}' => tok = FTS5_RCP,
        ':' => tok = FTS5_COLON,
        ',' => tok = FTS5_COMMA,
        '+' => tok = FTS5_PLUS,
        '*' => tok = FTS5_STAR,
        '-' => tok = FTS5_MINUS,
        '^' => tok = FTS5_CARET,
        0 => tok = FTS5_EOF,
        '"' => {
            tok = FTS5_STRING;
            var z2: [*:0]const u8 = z + 1;
            while (true) {
                if (z2[0] == '"') {
                    z2 += 1;
                    if (z2[0] != '"') break;
                }
                if (z2[0] == 0) {
                    sqlite3Fts5ParseError(pParse, "unterminated string");
                    return FTS5_EOF;
                }
                z2 += 1;
            }
            pToken.n = @intCast(@intFromPtr(z2) - @intFromPtr(z));
        },
        else => {
            if (sqlite3Fts5IsBareword(z[0]) == 0) {
                sqlite3Fts5ParseError(pParse, "fts5: syntax error near \"%.1s\"", z);
                return FTS5_EOF;
            }
            tok = FTS5_STRING;
            var z2: [*:0]const u8 = z + 1;
            while (sqlite3Fts5IsBareword(z2[0]) != 0) z2 += 1;
            pToken.n = @intCast(@intFromPtr(z2) - @intFromPtr(z));
            if (pToken.n == 2 and memcmp(pToken.p, "OR", 2) == 0) tok = FTS5_OR;
            if (pToken.n == 3 and memcmp(pToken.p, "NOT", 3) == 0) tok = FTS5_NOT;
            if (pToken.n == 3 and memcmp(pToken.p, "AND", 3) == 0) tok = FTS5_AND;
        },
    }

    pz.* = @ptrCast(pToken.p.? + @as(usize, @intCast(pToken.n)));
    return tok;
}

// 5996-5997.
fn fts5ParseAlloc(t: u64) callconv(.c) ?*anyopaque {
    return sqlite3_malloc64(t);
}
fn fts5ParseFree(p: ?*anyopaque) callconv(.c) void {
    sqlite3_free(p);
}

// ===========================================================================
// sqlite3Fts5ExprNew (5999-6069). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprNew(
    pConfig: *Fts5Config,
    bPhraseToAnd: c_int,
    iCol: c_int,
    zExpr: [*:0]const u8,
    ppNew: *?*Fts5Expr,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var sParse: Fts5Parse = undefined;
    var token: Fts5Token = undefined;
    var z: [*:0]const u8 = zExpr;
    var t: c_int = undefined;

    ppNew.* = null;
    pzErr.* = null;
    _ = memset(&sParse, 0, @sizeOf(Fts5Parse));
    sParse.bPhraseToAnd = bPhraseToAnd;
    const pEngine = sqlite3Fts5ParserAlloc(fts5ParseAlloc);
    if (pEngine == null) return SQLITE_NOMEM;
    sParse.pConfig = pConfig;

    while (true) {
        t = fts5ExprGetToken(&sParse, &z, &token);
        sqlite3Fts5Parser(pEngine, t, token, &sParse);
        if (!(sParse.rc == SQLITE_OK and t != FTS5_EOF)) break;
    }
    sqlite3Fts5ParserFree(pEngine, fts5ParseFree);

    // Apply implicit column filter if the LHS was a user column.
    if (sParse.rc == SQLITE_OK and iCol < pConfig.nCol) {
        const n = SZ_FTS5COLSET(1);
        const pColset: ?*Fts5Colset = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&sParse.rc, n)));
        if (pColset) |pc| {
            pc.nCol = 1;
            colsetCol(pc, 0).* = iCol;
            sqlite3Fts5ParseSetColset(&sParse, sParse.pExpr, pc);
        }
    }

    if (sParse.rc == SQLITE_OK) {
        const pNew: ?*Fts5Expr = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts5Expr))));
        ppNew.* = pNew;
        if (pNew == null) {
            sParse.rc = SQLITE_NOMEM;
            sqlite3Fts5ParseNodeFree(sParse.pExpr);
        } else {
            pNew.?.pRoot = sParse.pExpr;
            pNew.?.pIndex = null;
            pNew.?.pConfig = pConfig;
            pNew.?.apExprPhrase = sParse.apPhrase;
            pNew.?.nPhrase = sParse.nPhrase;
            pNew.?.bDesc = 0;
            sParse.apPhrase = null;
        }
    } else {
        sqlite3Fts5ParseNodeFree(sParse.pExpr);
    }

    sqlite3_free(@ptrCast(sParse.apPhrase));
    if (pzErr.* == null) {
        pzErr.* = sParse.zErr;
    } else {
        sqlite3_free(sParse.zErr);
    }
    return sParse.rc;
}

// 6075-6082.
fn fts5ExprCountChar(z: [*]const u8, nByte: c_int) c_int {
    var nRet: c_int = 0;
    var ii: c_int = 0;
    while (ii < nByte) : (ii += 1) {
        if ((z[@intCast(ii)] & 0xC0) != 0x80) nRet += 1;
    }
    return nRet;
}

// ===========================================================================
// sqlite3Fts5ExprPattern (6092-6158): trigram LIKE/GLOB -> MATCH. EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprPattern(
    pConfig: *Fts5Config,
    bGlob: c_int,
    iCol0: c_int,
    zText: [*:0]const u8,
    pp: *?*Fts5Expr,
) callconv(.c) c_int {
    var iCol = iCol0;
    const nText: i64 = @intCast(strlen(zText));
    const zExpr: ?[*]u8 = @ptrCast(sqlite3_malloc64(@as(u64, @bitCast(nText * 4 + 1))));
    var rc: c_int = SQLITE_OK;

    if (zExpr == null) {
        rc = SQLITE_NOMEM;
    } else {
        const ze = zExpr.?;
        var aSpec: [3]u8 = undefined;
        var iOut: c_int = 0;
        var i: i64 = 0;
        var iFirst: i64 = 0;

        if (bGlob == 0) {
            aSpec[0] = '_';
            aSpec[1] = '%';
            aSpec[2] = 0;
        } else {
            aSpec[0] = '*';
            aSpec[1] = '?';
            aSpec[2] = '[';
        }

        while (i <= nText) {
            if (i == nText or
                zText[@intCast(i)] == aSpec[0] or zText[@intCast(i)] == aSpec[1] or zText[@intCast(i)] == aSpec[2])
            {
                if (fts5ExprCountChar(zText + @as(usize, @intCast(iFirst)), @intCast(i - iFirst)) >= 3) {
                    var jj: i64 = iFirst;
                    ze[@intCast(iOut)] = '"';
                    iOut += 1;
                    while (jj < i) : (jj += 1) {
                        ze[@intCast(iOut)] = zText[@intCast(jj)];
                        iOut += 1;
                        if (zText[@intCast(jj)] == '"') {
                            ze[@intCast(iOut)] = '"';
                            iOut += 1;
                        }
                    }
                    ze[@intCast(iOut)] = '"';
                    iOut += 1;
                    ze[@intCast(iOut)] = ' ';
                    iOut += 1;
                }
                if (zText[@intCast(i)] == aSpec[2]) {
                    i += 2;
                    if (zText[@intCast(i - 1)] == '^') i += 1;
                    while (i < nText and zText[@intCast(i)] != ']') i += 1;
                }
                iFirst = i + 1;
            }
            i += 1;
        }
        if (iOut > 0) {
            var bAnd: c_int = 0;
            if (pConfig.eDetail != FTS5_DETAIL_FULL) {
                bAnd = 1;
                if (pConfig.eDetail == FTS5_DETAIL_NONE) {
                    iCol = pConfig.nCol;
                }
            }
            ze[@intCast(iOut)] = 0;
            rc = sqlite3Fts5ExprNew(pConfig, bAnd, iCol, @ptrCast(ze), pp, pConfig.pzErrmsg.?);
        } else {
            pp.* = null;
        }
        sqlite3_free(zExpr);
    }

    return rc;
}

// ===========================================================================
// sqlite3Fts5ParseNodeFree (6163-6172). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseNodeFree(p: ?*Fts5ExprNode) callconv(.c) void {
    if (p) |node| {
        var i: c_int = 0;
        while (i < node.nChild) : (i += 1) {
            sqlite3Fts5ParseNodeFree(nodeChild(node, i).*);
        }
        sqlite3Fts5ParseNearsetFree(node.pNear);
        sqlite3_free(node);
    }
}

// ===========================================================================
// sqlite3Fts5ExprFree (6177-6183). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprFree(p: ?*Fts5Expr) callconv(.c) void {
    if (p) |e| {
        sqlite3Fts5ParseNodeFree(e.pRoot);
        sqlite3_free(@ptrCast(e.apExprPhrase));
        sqlite3_free(e);
    }
}

// ===========================================================================
// sqlite3Fts5ExprAnd (6185-6219). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprAnd(pp1: *?*Fts5Expr, p2: ?*Fts5Expr) callconv(.c) c_int {
    var sParse: Fts5Parse = undefined;
    _ = memset(&sParse, 0, @sizeOf(Fts5Parse));

    if (pp1.* != null and p2 != null) {
        const p1 = pp1.*.?;
        const pp2 = p2.?;
        const nPhrase = p1.nPhrase + pp2.nPhrase;

        p1.pRoot = sqlite3Fts5ParseNode(&sParse, FTS5_AND, p1.pRoot, pp2.pRoot, null);
        pp2.pRoot = null;

        if (sParse.rc == SQLITE_OK) {
            const ap: ?[*]?*Fts5ExprPhrase = @ptrCast(@alignCast(sqlite3_realloc64(
                @ptrCast(p1.apExprPhrase),
                @as(u64, @intCast(nPhrase)) * @sizeOf(?*Fts5ExprPhrase),
            )));
            if (ap == null) {
                sParse.rc = SQLITE_NOMEM;
            } else {
                const apr = ap.?;
                _ = memmove(@ptrCast(&apr[@intCast(pp2.nPhrase)]), @ptrCast(apr), @as(usize, @intCast(p1.nPhrase)) * @sizeOf(?*Fts5ExprPhrase));
                var i: c_int = 0;
                while (i < pp2.nPhrase) : (i += 1) {
                    apr[@intCast(i)] = pp2.apExprPhrase.?[@intCast(i)];
                }
                p1.nPhrase = nPhrase;
                p1.apExprPhrase = ap;
            }
        }
        sqlite3_free(@ptrCast(pp2.apExprPhrase));
        sqlite3_free(pp2);
    } else if (p2 != null) {
        pp1.* = p2;
    }

    return sParse.rc;
}

// ===========================================================================
// fts5ExprSynonymRowid (6225-6245).
// ===========================================================================
fn fts5ExprSynonymRowid(pTerm: *Fts5ExprTerm, bDesc: c_int, pbEof: ?*c_int) i64 {
    var iRet: i64 = 0;
    var bRetValid: c_int = 0;
    var p: ?*Fts5ExprTerm = pTerm;
    while (p) |pp| : (p = pp.pSynonym) {
        if (0 == sqlite3Fts5IterEof(pp.pIter)) {
            const iRowid = pp.pIter.?.iRowid;
            if (bRetValid == 0 or (bDesc != @intFromBool(iRowid < iRet))) {
                iRet = iRowid;
                bRetValid = 1;
            }
        }
    }
    if (pbEof != null and bRetValid == 0) pbEof.?.* = 1;
    return iRet;
}

// ===========================================================================
// fts5ExprSynonymList (6250-6319).
// ===========================================================================
fn fts5ExprSynonymList(
    pTerm: *Fts5ExprTerm,
    iRowid: i64,
    pBuf: *Fts5Buffer,
    pa: *?[*]u8,
    pn: *c_int,
) c_int {
    var aStatic: [4]Fts5PoslistReader = undefined;
    var aIter: [*]Fts5PoslistReader = &aStatic;
    var nIter: c_int = 0;
    var nAlloc: c_int = 4;
    var rc: c_int = SQLITE_OK;

    var p: ?*Fts5ExprTerm = pTerm;
    while (p) |pp| : (p = pp.pSynonym) {
        const pIter = pp.pIter;
        if (sqlite3Fts5IterEof(pIter) == 0 and pIter.?.iRowid == iRowid) {
            if (pIter.?.nData == 0) continue;
            if (nIter == nAlloc) {
                const nByte: i64 = @sizeOf(Fts5PoslistReader) * @as(i64, nAlloc) * 2;
                const aNew: ?[*]Fts5PoslistReader = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
                if (aNew == null) {
                    rc = SQLITE_NOMEM;
                    if (aIter != @as([*]Fts5PoslistReader, &aStatic)) sqlite3_free(aIter);
                    return rc;
                }
                _ = memcpy(aNew, aIter, @sizeOf(Fts5PoslistReader) * @as(usize, @intCast(nIter)));
                nAlloc = nAlloc * 2;
                if (aIter != @as([*]Fts5PoslistReader, &aStatic)) sqlite3_free(aIter);
                aIter = aNew.?;
            }
            _ = sqlite3Fts5PoslistReaderInit(pIter.?.pData, pIter.?.nData, &aIter[@intCast(nIter)]);
            nIter += 1;
        }
    }

    if (nIter == 1) {
        pa.* = @constCast(aIter[0].a);
        pn.* = aIter[0].n;
    } else {
        var writer: Fts5PoslistWriter = .{ .iPrev = 0 };
        var iPrev: i64 = -1;
        fts5BufferZero(pBuf);
        while (true) {
            var iMin: i64 = FTS5_LARGEST_INT64;
            var i: c_int = 0;
            while (i < nIter) : (i += 1) {
                if (aIter[@intCast(i)].bEof == 0) {
                    if (aIter[@intCast(i)].iPos == iPrev) {
                        if (sqlite3Fts5PoslistReaderNext(&aIter[@intCast(i)]) != 0) continue;
                    }
                    if (aIter[@intCast(i)].iPos < iMin) {
                        iMin = aIter[@intCast(i)].iPos;
                    }
                }
            }
            if (iMin == FTS5_LARGEST_INT64 or rc != SQLITE_OK) break;
            rc = sqlite3Fts5PoslistWriterAppend(pBuf, &writer, iMin);
            iPrev = iMin;
        }
        if (rc == SQLITE_OK) {
            pa.* = pBuf.p;
            pn.* = pBuf.n;
        }
    }

    if (aIter != @as([*]Fts5PoslistReader, &aStatic)) sqlite3_free(aIter);
    return rc;
}

// ===========================================================================
// fts5ExprPhraseIsMatch (6333-6415).
// ===========================================================================
fn fts5ExprPhraseIsMatch(pNode: *Fts5ExprNode, pPhrase: *Fts5ExprPhrase, pbMatch: *c_int) c_int {
    var writer: Fts5PoslistWriter = .{ .iPrev = 0 };
    var aStatic: [4]Fts5PoslistReader = undefined;
    var aIter: [*]Fts5PoslistReader = &aStatic;
    var rc: c_int = SQLITE_OK;
    const bFirst: c_int = phraseTerm(pPhrase, 0).bFirst;

    fts5BufferZero(&pPhrase.poslist);

    if (pPhrase.nTerm > aStatic.len) {
        const nByte: i64 = @sizeOf(Fts5PoslistReader) * @as(i64, pPhrase.nTerm);
        const a: ?[*]Fts5PoslistReader = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
        if (a == null) return SQLITE_NOMEM;
        aIter = a.?;
    }
    _ = memset(aIter, 0, @sizeOf(Fts5PoslistReader) * @as(usize, @intCast(pPhrase.nTerm)));

    // Per-term iterator init.
    var i: c_int = 0;
    init_loop: {
        while (i < pPhrase.nTerm) : (i += 1) {
            const pTerm = phraseTerm(pPhrase, i);
            var n: c_int = 0;
            var bFlag: c_int = 0;
            var a: ?[*]u8 = null;
            if (pTerm.pSynonym != null) {
                var buf: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
                rc = fts5ExprSynonymList(pTerm, pNode.iRowid, &buf, &a, &n);
                if (rc != 0) {
                    sqlite3_free(a);
                    break :init_loop;
                }
                if (a == buf.p) bFlag = 1;
            } else {
                a = @constCast(pTerm.pIter.?.pData);
                n = pTerm.pIter.?.nData;
            }
            _ = sqlite3Fts5PoslistReaderInit(a, n, &aIter[@intCast(i)]);
            aIter[@intCast(i)].bFlag = @intCast(bFlag);
            if (aIter[@intCast(i)].bEof != 0) break :init_loop;
        }

        // Main merge loop.
        while (true) {
            var bMatch: c_int = undefined;
            var iPos: i64 = aIter[0].iPos;
            while (true) {
                bMatch = 1;
                var k: c_int = 0;
                while (k < pPhrase.nTerm) : (k += 1) {
                    const pPos = &aIter[@intCast(k)];
                    const iAdj: i64 = iPos + k;
                    if (pPos.iPos != iAdj) {
                        bMatch = 0;
                        while (pPos.iPos < iAdj) {
                            if (sqlite3Fts5PoslistReaderNext(pPos) != 0) break :init_loop;
                        }
                        if (pPos.iPos > iAdj) iPos = pPos.iPos - k;
                    }
                }
                if (bMatch != 0) break;
            }

            if (bFirst == 0 or FTS5_POS2OFFSET(iPos) == 0) {
                rc = sqlite3Fts5PoslistWriterAppend(&pPhrase.poslist, &writer, iPos);
                if (rc != SQLITE_OK) break :init_loop;
            }

            var k: c_int = 0;
            while (k < pPhrase.nTerm) : (k += 1) {
                if (sqlite3Fts5PoslistReaderNext(&aIter[@intCast(k)]) != 0) break :init_loop;
            }
        }
    }

    // ismatch_out:
    pbMatch.* = @intFromBool(pPhrase.poslist.n > 0);
    var k: c_int = 0;
    while (k < pPhrase.nTerm) : (k += 1) {
        if (aIter[@intCast(k)].bFlag != 0) sqlite3_free(@constCast(aIter[@intCast(k)].a));
    }
    if (aIter != @as([*]Fts5PoslistReader, &aStatic)) sqlite3_free(aIter);
    return rc;
}

// ===========================================================================
// Fts5LookaheadReader (6417-6445).
// ===========================================================================
const Fts5LookaheadReader = extern struct {
    a: ?[*]const u8,
    n: c_int,
    i: c_int,
    iPos: i64,
    iLookahead: i64,
};

fn fts5LookaheadReaderNext(p: *Fts5LookaheadReader) c_int {
    p.iPos = p.iLookahead;
    if (sqlite3Fts5PoslistNext64(p.a, p.n, &p.i, &p.iLookahead) != 0) {
        p.iLookahead = FTS5_LOOKAHEAD_EOF;
    }
    return @intFromBool(p.iPos == FTS5_LOOKAHEAD_EOF);
}

fn fts5LookaheadReaderInit(a: ?[*]const u8, n: c_int, p: *Fts5LookaheadReader) c_int {
    _ = memset(p, 0, @sizeOf(Fts5LookaheadReader));
    p.a = a;
    p.n = n;
    _ = fts5LookaheadReaderNext(p);
    return fts5LookaheadReaderNext(p);
}

const Fts5NearTrimmer = extern struct {
    reader: Fts5LookaheadReader,
    writer: Fts5PoslistWriter,
    pOut: ?*Fts5Buffer,
};

// ===========================================================================
// fts5ExprNearIsMatch (6471-6559).
// ===========================================================================
fn fts5ExprNearIsMatch(pRc: *c_int, pNear: *Fts5ExprNearset) c_int {
    var aStatic: [4]Fts5NearTrimmer = undefined;
    var a: [*]Fts5NearTrimmer = &aStatic;
    var i: c_int = undefined;
    var rc: c_int = pRc.*;
    var bMatch: c_int = undefined;

    if (pNear.nPhrase > aStatic.len) {
        const nByte: i64 = @sizeOf(Fts5NearTrimmer) * @as(i64, pNear.nPhrase);
        a = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
    } else {
        _ = memset(&aStatic, 0, @sizeOf(@TypeOf(aStatic)));
    }
    if (rc != SQLITE_OK) {
        pRc.* = rc;
        return 0;
    }

    i = 0;
    while (i < pNear.nPhrase) : (i += 1) {
        const pPoslist = &nearPhrase(pNear, i).*.?.poslist;
        _ = fts5LookaheadReaderInit(pPoslist.p, pPoslist.n, &a[@intCast(i)].reader);
        pPoslist.n = 0;
        a[@intCast(i)].pOut = pPoslist;
    }

    ismatch: {
        while (true) {
            var iAdv: c_int = undefined;
            var iMin: i64 = undefined;
            var iMax: i64 = a[0].reader.iPos;
            while (true) {
                bMatch = 1;
                i = 0;
                while (i < pNear.nPhrase) : (i += 1) {
                    const pPos = &a[@intCast(i)].reader;
                    iMin = iMax - nearPhrase(pNear, i).*.?.nTerm - pNear.nNear;
                    if (pPos.iPos < iMin or pPos.iPos > iMax) {
                        bMatch = 0;
                        while (pPos.iPos < iMin) {
                            if (fts5LookaheadReaderNext(pPos) != 0) break :ismatch;
                        }
                        if (pPos.iPos > iMax) iMax = pPos.iPos;
                    }
                }
                if (bMatch != 0) break;
            }

            i = 0;
            while (i < pNear.nPhrase) : (i += 1) {
                const iPos: i64 = a[@intCast(i)].reader.iPos;
                const pWriter = &a[@intCast(i)].writer;
                if (a[@intCast(i)].pOut.?.n == 0 or iPos != pWriter.iPrev) {
                    sqlite3Fts5PoslistSafeAppend(a[@intCast(i)].pOut.?, &pWriter.iPrev, iPos);
                }
            }

            iAdv = 0;
            iMin = a[0].reader.iLookahead;
            i = 0;
            while (i < pNear.nPhrase) : (i += 1) {
                if (a[@intCast(i)].reader.iLookahead < iMin) {
                    iMin = a[@intCast(i)].reader.iLookahead;
                    iAdv = i;
                }
            }
            if (fts5LookaheadReaderNext(&a[@intCast(iAdv)].reader) != 0) break :ismatch;
        }
    }

    // ismatch_out:
    const bRet: c_int = @intFromBool(a[0].pOut.?.n > 0);
    pRc.* = rc;
    if (a != @as([*]Fts5NearTrimmer, &aStatic)) sqlite3_free(a);
    return bRet;
}

// ===========================================================================
// fts5ExprAdvanceto (6570-6594).
// ===========================================================================
fn fts5ExprAdvanceto(pIter: *Fts5IndexIter, bDesc: c_int, piLast: *i64, pRc: *c_int, pbEof: *c_int) c_int {
    var iLast = piLast.*;
    var iRowid = pIter.iRowid;
    if ((bDesc == 0 and iLast > iRowid) or (bDesc != 0 and iLast < iRowid)) {
        const rc = sqlite3Fts5IterNextFrom(pIter, iLast);
        if (rc != 0 or sqlite3Fts5IterEof(pIter) != 0) {
            pRc.* = rc;
            pbEof.* = 1;
            return 1;
        }
        iRowid = pIter.iRowid;
    }
    iLast = iRowid;
    piLast.* = iLast;
    return 0;
}

// ===========================================================================
// fts5ExprSynonymAdvanceto (6596-6623).
// ===========================================================================
fn fts5ExprSynonymAdvanceto(pTerm: *Fts5ExprTerm, bDesc: c_int, piLast: *i64, pRc: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    const iLast = piLast.*;
    var bEof: c_int = 0;

    var p: ?*Fts5ExprTerm = pTerm;
    while (rc == SQLITE_OK and p != null) : (p = p.?.pSynonym) {
        if (sqlite3Fts5IterEof(p.?.pIter) == 0) {
            const iRowid = p.?.pIter.?.iRowid;
            if ((bDesc == 0 and iLast > iRowid) or (bDesc != 0 and iLast < iRowid)) {
                rc = sqlite3Fts5IterNextFrom(p.?.pIter, iLast);
            }
        }
    }

    if (rc != SQLITE_OK) {
        pRc.* = rc;
        bEof = 1;
    } else {
        piLast.* = fts5ExprSynonymRowid(pTerm, bDesc, &bEof);
    }
    return bEof;
}

// ===========================================================================
// fts5ExprNearTest (6626-6673).
// ===========================================================================
fn fts5ExprNearTest(pRc: *c_int, pExpr: *Fts5Expr, pNode: *Fts5ExprNode) c_int {
    const pNear = pNode.pNear.?;
    var rc: c_int = pRc.*;

    if (pExpr.pConfig.?.eDetail != FTS5_DETAIL_FULL) {
        const pPhrase = nearPhrase(pNear, 0).*.?;
        pPhrase.poslist.n = 0;
        var pTerm: ?*Fts5ExprTerm = phraseTerm(pPhrase, 0);
        while (pTerm) |pt| : (pTerm = pt.pSynonym) {
            const pIter = pt.pIter;
            if (sqlite3Fts5IterEof(pIter) == 0) {
                if (pIter.?.iRowid == pNode.iRowid and pIter.?.nData > 0) {
                    pPhrase.poslist.n = 1;
                }
            }
        }
        return pPhrase.poslist.n;
    } else {
        var i: c_int = 0;
        while (rc == SQLITE_OK and i < pNear.nPhrase) : (i += 1) {
            const pPhrase = nearPhrase(pNear, i).*.?;
            if (pPhrase.nTerm > 1 or phraseTerm(pPhrase, 0).pSynonym != null or
                pNear.pColset != null or phraseTerm(pPhrase, 0).bFirst != 0)
            {
                var bMatch: c_int = 0;
                rc = fts5ExprPhraseIsMatch(pNode, pPhrase, &bMatch);
                if (bMatch == 0) break;
            } else {
                const pIter = phraseTerm(pPhrase, 0).pIter.?;
                fts5BufferSet(&rc, &pPhrase.poslist, pIter.nData, pIter.pData.?);
            }
        }

        pRc.* = rc;
        if (i == pNear.nPhrase and (i == 1 or fts5ExprNearIsMatch(pRc, pNear) != 0)) {
            return 1;
        }
        return 0;
    }
}

// ===========================================================================
// fts5ExprNearInitAll (6685-6735).
// ===========================================================================
fn fts5ExprNearInitAll(pExpr: *Fts5Expr, pNode: *Fts5ExprNode) c_int {
    const pNear = pNode.pNear.?;
    var i: c_int = 0;
    while (i < pNear.nPhrase) : (i += 1) {
        const pPhrase = nearPhrase(pNear, i).*.?;
        if (pPhrase.nTerm == 0) {
            pNode.bEof = 1;
            return SQLITE_OK;
        } else {
            var j: c_int = 0;
            while (j < pPhrase.nTerm) : (j += 1) {
                const pTerm = phraseTerm(pPhrase, j);
                var bHit: c_int = 0;

                var p: ?*Fts5ExprTerm = pTerm;
                while (p) |pp| : (p = pp.pSynonym) {
                    if (pp.pIter != null) {
                        sqlite3Fts5IterClose(pp.pIter);
                        pp.pIter = null;
                    }
                    const rc = sqlite3Fts5IndexQuery(
                        pExpr.pIndex,
                        pp.pTerm,
                        pp.nQueryTerm,
                        (if (pTerm.bPrefix != 0) FTS5INDEX_QUERY_PREFIX else 0) |
                            (if (pExpr.bDesc != 0) FTS5INDEX_QUERY_DESC else 0),
                        pNear.pColset,
                        &pp.pIter,
                    );
                    if (rc != SQLITE_OK) return rc;
                    if (0 == sqlite3Fts5IterEof(pp.pIter)) {
                        bHit = 1;
                    }
                }

                if (bHit == 0) {
                    pNode.bEof = 1;
                    return SQLITE_OK;
                }
            }
        }
    }

    pNode.bEof = 0;
    return SQLITE_OK;
}

// ===========================================================================
// fts5RowidCmp (6747-6760).
// ===========================================================================
fn fts5RowidCmp(pExpr: *Fts5Expr, iLhs: i64, iRhs: i64) c_int {
    if (pExpr.bDesc == 0) {
        if (iLhs < iRhs) return -1;
        return @intFromBool(iLhs > iRhs);
    } else {
        if (iLhs > iRhs) return -1;
        return @intFromBool(iLhs < iRhs);
    }
}

fn fts5ExprSetEof(pNode: *Fts5ExprNode) void {
    pNode.bEof = 1;
    pNode.bNomatch = 0;
    var i: c_int = 0;
    while (i < pNode.nChild) : (i += 1) {
        fts5ExprSetEof(nodeChild(pNode, i).*.?);
    }
}

fn fts5ExprNodeZeroPoslist(pNode: *Fts5ExprNode) void {
    if (pNode.eType == FTS5_STRING or pNode.eType == FTS5_TERM) {
        const pNear = pNode.pNear.?;
        var i: c_int = 0;
        while (i < pNear.nPhrase) : (i += 1) {
            nearPhrase(pNear, i).*.?.poslist.n = 0;
        }
    } else {
        var i: c_int = 0;
        while (i < pNode.nChild) : (i += 1) {
            fts5ExprNodeZeroPoslist(nodeChild(pNode, i).*.?);
        }
    }
}

// ===========================================================================
// fts5NodeCompare (6801-6809).
// ===========================================================================
fn fts5NodeCompare(pExpr: *Fts5Expr, p1: *Fts5ExprNode, p2: *Fts5ExprNode) c_int {
    if (p2.bEof != 0) return -1;
    if (p1.bEof != 0) return 1;
    return fts5RowidCmp(pExpr, p1.iRowid, p2.iRowid);
}

// fts5ExprNodeNext macro (5830): (b)->xNext((a),(b),(c),(d)).
inline fn fts5ExprNodeNext(a: *Fts5Expr, b: *Fts5ExprNode, c: c_int, d: i64) c_int {
    return b.xNext.?(a, b, c, d);
}

// ===========================================================================
// fts5ExprNodeTest_STRING (6822-6883).
// ===========================================================================
fn fts5ExprNodeTest_STRING(pExpr: *Fts5Expr, pNode: *Fts5ExprNode) c_int {
    const pNear = pNode.pNear.?;
    const pLeft = nearPhrase(pNear, 0).*.?;
    var rc: c_int = SQLITE_OK;
    var iLast: i64 = undefined;
    var bMatch: c_int = undefined;
    const bDesc = pExpr.bDesc;

    if (phraseTerm(pLeft, 0).pSynonym != null) {
        iLast = fts5ExprSynonymRowid(phraseTerm(pLeft, 0), bDesc, null);
    } else {
        iLast = phraseTerm(pLeft, 0).pIter.?.iRowid;
    }

    while (true) {
        bMatch = 1;
        var i: c_int = 0;
        while (i < pNear.nPhrase) : (i += 1) {
            const pPhrase = nearPhrase(pNear, i).*.?;
            var j: c_int = 0;
            while (j < pPhrase.nTerm) : (j += 1) {
                const pTerm = phraseTerm(pPhrase, j);
                if (pTerm.pSynonym != null) {
                    const iRowid = fts5ExprSynonymRowid(pTerm, bDesc, null);
                    if (iRowid == iLast) continue;
                    bMatch = 0;
                    if (fts5ExprSynonymAdvanceto(pTerm, bDesc, &iLast, &rc) != 0) {
                        pNode.bNomatch = 0;
                        pNode.bEof = 1;
                        return rc;
                    }
                } else {
                    const pIter = phraseTerm(pPhrase, j).pIter.?;
                    if (pIter.iRowid == iLast) continue;
                    bMatch = 0;
                    if (fts5ExprAdvanceto(pIter, bDesc, &iLast, &rc, &pNode.bEof) != 0) {
                        return rc;
                    }
                }
            }
        }
        if (bMatch != 0) break;
    }

    pNode.iRowid = iLast;
    pNode.bNomatch = @intFromBool((0 == fts5ExprNearTest(&rc, pExpr, pNode)) and rc == SQLITE_OK);

    return rc;
}

// ===========================================================================
// fts5ExprNodeNext_STRING (6892-6954).
// ===========================================================================
fn fts5ExprNodeNext_STRING(pExpr: ?*Fts5Expr, pNode: ?*Fts5ExprNode, bFromValid: c_int, iFrom: i64) callconv(.c) c_int {
    const pE = pExpr.?;
    const pN = pNode.?;
    const pTerm = phraseTerm(nearPhrase(pN.pNear.?, 0).*.?, 0);
    var rc: c_int = SQLITE_OK;

    pN.bNomatch = 0;
    if (pTerm.pSynonym != null) {
        var bEof: c_int = 1;

        const iRowid = fts5ExprSynonymRowid(pTerm, pE.bDesc, null);

        var p: ?*Fts5ExprTerm = pTerm;
        while (p) |pp| : (p = pp.pSynonym) {
            if (sqlite3Fts5IterEof(pp.pIter) == 0) {
                const ii = pp.pIter.?.iRowid;
                if (ii == iRowid or
                    (bFromValid != 0 and ii != iFrom and @intFromBool(ii > iFrom) == pE.bDesc))
                {
                    if (bFromValid != 0) {
                        rc = sqlite3Fts5IterNextFrom(pp.pIter, iFrom);
                    } else {
                        rc = sqlite3Fts5IterNext(pp.pIter);
                    }
                    if (rc != SQLITE_OK) break;
                    if (sqlite3Fts5IterEof(pp.pIter) == 0) {
                        bEof = 0;
                    }
                } else {
                    bEof = 0;
                }
            }
        }

        pN.bEof = @intFromBool(rc != 0 or bEof != 0);
    } else {
        const pIter = pTerm.pIter;
        if (bFromValid != 0) {
            rc = sqlite3Fts5IterNextFrom(pIter, iFrom);
        } else {
            rc = sqlite3Fts5IterNext(pIter);
        }
        pN.bEof = @intFromBool(rc != 0 or sqlite3Fts5IterEof(pIter) != 0);
    }

    if (pN.bEof == 0) {
        rc = fts5ExprNodeTest_STRING(pE, pN);
    }

    return rc;
}

// ===========================================================================
// fts5ExprNodeTest_TERM (6957-6980).
// ===========================================================================
fn fts5ExprNodeTest_TERM(pExpr: *Fts5Expr, pNode: *Fts5ExprNode) c_int {
    const pPhrase = nearPhrase(pNode.pNear.?, 0).*.?;
    const pIter = phraseTerm(pPhrase, 0).pIter.?;

    pPhrase.poslist.n = pIter.nData;
    if (pExpr.pConfig.?.eDetail == FTS5_DETAIL_FULL) {
        pPhrase.poslist.p = @constCast(pIter.pData);
    }
    pNode.iRowid = pIter.iRowid;
    pNode.bNomatch = @intFromBool(pPhrase.poslist.n == 0);
    return SQLITE_OK;
}

// ===========================================================================
// fts5ExprNodeNext_TERM (6985-7007).
// ===========================================================================
fn fts5ExprNodeNext_TERM(pExpr: ?*Fts5Expr, pNode: ?*Fts5ExprNode, bFromValid: c_int, iFrom: i64) callconv(.c) c_int {
    const pN = pNode.?;
    const pIter = phraseTerm(nearPhrase(pN.pNear.?, 0).*.?, 0).pIter;

    var rc: c_int = undefined;
    if (bFromValid != 0) {
        rc = sqlite3Fts5IterNextFrom(pIter, iFrom);
    } else {
        rc = sqlite3Fts5IterNext(pIter);
    }
    if (rc == SQLITE_OK and sqlite3Fts5IterEof(pIter) == 0) {
        rc = fts5ExprNodeTest_TERM(pExpr.?, pN);
    } else {
        pN.bEof = 1;
        pN.bNomatch = 0;
    }
    return rc;
}

// ===========================================================================
// fts5ExprNodeTest_OR / Next_OR (7009-7055).
// ===========================================================================
fn fts5ExprNodeTest_OR(pExpr: *Fts5Expr, pNode: *Fts5ExprNode) void {
    var pNext = nodeChild(pNode, 0).*.?;
    var i: c_int = 1;
    while (i < pNode.nChild) : (i += 1) {
        const pChild = nodeChild(pNode, i).*.?;
        const cmp = fts5NodeCompare(pExpr, pNext, pChild);
        if (cmp > 0 or (cmp == 0 and pChild.bNomatch == 0)) {
            pNext = pChild;
        }
    }
    pNode.iRowid = pNext.iRowid;
    pNode.bEof = pNext.bEof;
    pNode.bNomatch = pNext.bNomatch;
}

fn fts5ExprNodeNext_OR(pExpr: ?*Fts5Expr, pNode: ?*Fts5ExprNode, bFromValid: c_int, iFrom: i64) callconv(.c) c_int {
    const pE = pExpr.?;
    const pN = pNode.?;
    const iLast = pN.iRowid;
    var i: c_int = 0;
    while (i < pN.nChild) : (i += 1) {
        const p1 = nodeChild(pN, i).*.?;
        if (p1.bEof == 0) {
            if ((p1.iRowid == iLast) or
                (bFromValid != 0 and fts5RowidCmp(pE, p1.iRowid, iFrom) < 0))
            {
                const rc = fts5ExprNodeNext(pE, p1, bFromValid, iFrom);
                if (rc != SQLITE_OK) {
                    pN.bNomatch = 0;
                    return rc;
                }
            }
        }
    }
    fts5ExprNodeTest_OR(pE, pN);
    return SQLITE_OK;
}

// ===========================================================================
// fts5ExprNodeTest_AND / Next_AND (7060-7125).
// ===========================================================================
fn fts5ExprNodeTest_AND(pExpr: *Fts5Expr, pAnd: *Fts5ExprNode) c_int {
    var iLast = pAnd.iRowid;
    var bMatch: c_int = undefined;

    while (true) {
        pAnd.bNomatch = 0;
        bMatch = 1;
        var iChild: c_int = 0;
        while (iChild < pAnd.nChild) : (iChild += 1) {
            const pChild = nodeChild(pAnd, iChild).*.?;
            const cmp = fts5RowidCmp(pExpr, iLast, pChild.iRowid);
            if (cmp > 0) {
                const rc = fts5ExprNodeNext(pExpr, pChild, 1, iLast);
                if (rc != SQLITE_OK) {
                    pAnd.bNomatch = 0;
                    return rc;
                }
            }

            if (pChild.bEof != 0) {
                fts5ExprSetEof(pAnd);
                bMatch = 1;
                break;
            } else if (iLast != pChild.iRowid) {
                bMatch = 0;
                iLast = pChild.iRowid;
            }

            if (pChild.bNomatch != 0) {
                pAnd.bNomatch = 1;
            }
        }
        if (bMatch != 0) break;
    }

    if (pAnd.bNomatch != 0 and pAnd != pExpr.pRoot.?) {
        fts5ExprNodeZeroPoslist(pAnd);
    }
    pAnd.iRowid = iLast;
    return SQLITE_OK;
}

fn fts5ExprNodeNext_AND(pExpr: ?*Fts5Expr, pNode: ?*Fts5ExprNode, bFromValid: c_int, iFrom: i64) callconv(.c) c_int {
    const pE = pExpr.?;
    const pN = pNode.?;
    var rc = fts5ExprNodeNext(pE, nodeChild(pN, 0).*.?, bFromValid, iFrom);
    if (rc == SQLITE_OK) {
        rc = fts5ExprNodeTest_AND(pE, pN);
    } else {
        pN.bNomatch = 0;
    }
    return rc;
}

// ===========================================================================
// fts5ExprNodeTest_NOT / Next_NOT (7127-7169).
// ===========================================================================
fn fts5ExprNodeTest_NOT(pExpr: *Fts5Expr, pNode: *Fts5ExprNode) c_int {
    var rc: c_int = SQLITE_OK;
    const p1 = nodeChild(pNode, 0).*.?;
    const p2 = nodeChild(pNode, 1).*.?;

    while (rc == SQLITE_OK and p1.bEof == 0) {
        var cmp = fts5NodeCompare(pExpr, p1, p2);
        if (cmp > 0) {
            rc = fts5ExprNodeNext(pExpr, p2, 1, p1.iRowid);
            cmp = fts5NodeCompare(pExpr, p1, p2);
        }
        if (cmp != 0 or p2.bNomatch != 0) break;
        rc = fts5ExprNodeNext(pExpr, p1, 0, 0);
    }
    pNode.bEof = p1.bEof;
    pNode.bNomatch = p1.bNomatch;
    pNode.iRowid = p1.iRowid;
    if (p1.bEof != 0) {
        fts5ExprNodeZeroPoslist(p2);
    }
    return rc;
}

fn fts5ExprNodeNext_NOT(pExpr: ?*Fts5Expr, pNode: ?*Fts5ExprNode, bFromValid: c_int, iFrom: i64) callconv(.c) c_int {
    const pE = pExpr.?;
    const pN = pNode.?;
    var rc = fts5ExprNodeNext(pE, nodeChild(pN, 0).*.?, bFromValid, iFrom);
    if (rc == SQLITE_OK) {
        rc = fts5ExprNodeTest_NOT(pE, pN);
    }
    if (rc != SQLITE_OK) {
        pN.bNomatch = 0;
    }
    return rc;
}

// ===========================================================================
// fts5ExprNodeTest (7176-7211).
// ===========================================================================
fn fts5ExprNodeTest(pExpr: *Fts5Expr, pNode: *Fts5ExprNode) c_int {
    var rc: c_int = SQLITE_OK;
    if (pNode.bEof == 0) {
        switch (pNode.eType) {
            FTS5_STRING => rc = fts5ExprNodeTest_STRING(pExpr, pNode),
            FTS5_TERM => rc = fts5ExprNodeTest_TERM(pExpr, pNode),
            FTS5_AND => rc = fts5ExprNodeTest_AND(pExpr, pNode),
            FTS5_OR => fts5ExprNodeTest_OR(pExpr, pNode),
            else => rc = fts5ExprNodeTest_NOT(pExpr, pNode), // FTS5_NOT
        }
    }
    return rc;
}

// ===========================================================================
// fts5ExprNodeFirst (7221-7262).
// ===========================================================================
fn fts5ExprNodeFirst(pExpr: *Fts5Expr, pNode: *Fts5ExprNode) c_int {
    var rc: c_int = SQLITE_OK;
    pNode.bEof = 0;
    pNode.bNomatch = 0;

    if (Fts5NodeIsString(pNode)) {
        rc = fts5ExprNearInitAll(pExpr, pNode);
    } else if (pNode.xNext == null) {
        pNode.bEof = 1;
    } else {
        var nEof: c_int = 0;
        var i: c_int = 0;
        while (i < pNode.nChild and rc == SQLITE_OK) : (i += 1) {
            const pChild = nodeChild(pNode, i).*.?;
            rc = fts5ExprNodeFirst(pExpr, nodeChild(pNode, i).*.?);
            nEof += pChild.bEof;
        }
        pNode.iRowid = nodeChild(pNode, 0).*.?.iRowid;

        switch (pNode.eType) {
            FTS5_AND => {
                if (nEof > 0) fts5ExprSetEof(pNode);
            },
            FTS5_OR => {
                if (pNode.nChild == nEof) fts5ExprSetEof(pNode);
            },
            else => { // FTS5_NOT
                pNode.bEof = nodeChild(pNode, 0).*.?.bEof;
            },
        }
    }

    if (rc == SQLITE_OK) {
        rc = fts5ExprNodeTest(pExpr, pNode);
    }
    return rc;
}

// ===========================================================================
// sqlite3Fts5ExprFirst (7280-7312). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprFirst(p: *Fts5Expr, pIdx: ?*Fts5Index, iFirst: i64, iLast: i64, bDesc: c_int) callconv(.c) c_int {
    const pRoot = p.pRoot.?;
    var rc: c_int = undefined;

    p.pIndex = pIdx;
    p.bDesc = bDesc;
    rc = fts5ExprNodeFirst(p, pRoot);

    if (rc == SQLITE_OK and 0 == pRoot.bEof and fts5RowidCmp(p, pRoot.iRowid, iFirst) < 0) {
        rc = fts5ExprNodeNext(p, pRoot, 1, iFirst);
    }

    while (pRoot.bNomatch != 0 and rc == SQLITE_OK) {
        rc = fts5ExprNodeNext(p, pRoot, 0, 0);
    }
    if (fts5RowidCmp(p, pRoot.iRowid, iLast) > 0) {
        pRoot.bEof = 1;
    }
    return rc;
}

// ===========================================================================
// sqlite3Fts5ExprNext (7320-7332). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprNext(p: *Fts5Expr, iLast: i64) callconv(.c) c_int {
    var rc: c_int = undefined;
    const pRoot = p.pRoot.?;
    while (true) {
        rc = fts5ExprNodeNext(p, pRoot, 0, 0);
        if (pRoot.bNomatch == 0) break;
    }
    if (fts5RowidCmp(p, pRoot.iRowid, iLast) > 0) {
        pRoot.bEof = 1;
    }
    return rc;
}

// ===========================================================================
// sqlite3Fts5ExprEof / Rowid (7334-7340). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprEof(p: *Fts5Expr) callconv(.c) c_int {
    return p.pRoot.?.bEof;
}
export fn sqlite3Fts5ExprRowid(p: *Fts5Expr) callconv(.c) i64 {
    return p.pRoot.?.iRowid;
}

// 7342-7346.
fn fts5ParseStringFromToken(pToken: *Fts5Token, pz: *?[*:0]u8) c_int {
    var rc: c_int = SQLITE_OK;
    pz.* = sqlite3Fts5Strndup(&rc, pToken.p.?, pToken.n);
    return rc;
}

// ===========================================================================
// fts5ExprPhraseFree (7351-7370).
// ===========================================================================
fn fts5ExprPhraseFree(pPhrase: ?*Fts5ExprPhrase) void {
    if (pPhrase) |pp| {
        var i: c_int = 0;
        while (i < pp.nTerm) : (i += 1) {
            const pTerm = phraseTerm(pp, i);
            sqlite3_free(pTerm.pTerm);
            sqlite3Fts5IterClose(pTerm.pIter);
            var pSyn: ?*Fts5ExprTerm = pTerm.pSynonym;
            while (pSyn) |ps| {
                const pNext = ps.pSynonym;
                sqlite3Fts5IterClose(ps.pIter);
                // The Fts5Buffer trailing the synonym Fts5ExprTerm.
                const pBuf: *Fts5Buffer = @ptrCast(@alignCast(@as([*]Fts5ExprTerm, @ptrCast(ps)) + 1));
                fts5BufferFree(pBuf);
                sqlite3_free(ps);
                pSyn = pNext;
            }
        }
        if (pp.poslist.nSpace > 0) fts5BufferFree(&pp.poslist);
        sqlite3_free(pp);
    }
}

// ===========================================================================
// sqlite3Fts5ParseSetCaret (7376-7380). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseSetCaret(pPhrase: ?*Fts5ExprPhrase) callconv(.c) void {
    if (pPhrase != null and pPhrase.?.nTerm != 0) {
        phraseTerm(pPhrase.?, 0).bFirst = 1;
    }
}

// ===========================================================================
// sqlite3Fts5ParseNearset (7390-7448). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseNearset(pParse: *Fts5Parse, pNear: ?*Fts5ExprNearset, pPhrase0: ?*Fts5ExprPhrase) callconv(.c) ?*Fts5ExprNearset {
    const SZALLOC: c_int = 8;
    var pRet: ?*Fts5ExprNearset = null;
    var pPhrase = pPhrase0;

    if (pParse.rc == SQLITE_OK) {
        if (pNear == null) {
            const nByte = SZ_FTS5EXPRNEARSET(SZALLOC + 1);
            pRet = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
            if (pRet == null) {
                pParse.rc = SQLITE_NOMEM;
            } else {
                _ = memset(pRet, 0, @intCast(nByte));
            }
        } else if (@mod(pNear.?.nPhrase, SZALLOC) == 0) {
            const nNew = pNear.?.nPhrase + SZALLOC;
            const nByte = SZ_FTS5EXPRNEARSET(nNew + 1);
            pRet = @ptrCast(@alignCast(sqlite3_realloc64(pNear, @bitCast(nByte))));
            if (pRet == null) {
                pParse.rc = SQLITE_NOMEM;
            }
        } else {
            pRet = pNear;
        }
    }

    if (pRet == null) {
        sqlite3Fts5ParseNearsetFree(pNear);
        sqlite3Fts5ParsePhraseFree(pPhrase);
    } else {
        const pr = pRet.?;
        if (pr.nPhrase > 0) {
            const pLast = nearPhrase(pr, pr.nPhrase - 1).*.?;
            if (pPhrase.?.nTerm == 0) {
                fts5ExprPhraseFree(pPhrase);
                pr.nPhrase -= 1;
                pParse.nPhrase -= 1;
                pPhrase = pLast;
            } else if (pLast.nTerm == 0) {
                fts5ExprPhraseFree(pLast);
                pParse.apPhrase.?[@intCast(pParse.nPhrase - 2)] = pPhrase;
                pParse.nPhrase -= 1;
                pr.nPhrase -= 1;
            }
        }
        nearPhrase(pr, pr.nPhrase).* = pPhrase;
        pr.nPhrase += 1;
    }
    return pRet;
}

// ===========================================================================
// TokenCtx (7450-7455) + fts5ParseTokenize (7460-7527).
// ===========================================================================
const TokenCtx = extern struct {
    pPhrase: ?*Fts5ExprPhrase,
    pConfig: ?*Fts5Config,
    rc: c_int,
};

fn fts5ParseTokenize(
    pContext: ?*anyopaque,
    tflags: c_int,
    pToken: ?[*]const u8,
    nToken0: c_int,
    iUnused1: c_int,
    iUnused2: c_int,
) callconv(.c) c_int {
    _ = iUnused1;
    _ = iUnused2;
    var rc: c_int = SQLITE_OK;
    const SZALLOC: c_int = 8;
    const pCtx: *TokenCtx = @ptrCast(@alignCast(pContext.?));
    var pPhrase = pCtx.pPhrase;
    var nToken = nToken0;

    if (pCtx.rc != SQLITE_OK) return pCtx.rc;
    if (nToken > FTS5_MAX_TOKEN_SIZE) nToken = FTS5_MAX_TOKEN_SIZE;

    if (pPhrase != null and pPhrase.?.nTerm > 0 and (tflags & FTS5_TOKEN_COLOCATED) != 0) {
        const nByte: i64 = @sizeOf(Fts5ExprTerm) + @sizeOf(Fts5Buffer) + nToken + 1;
        const pSyn: ?*Fts5ExprTerm = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
        if (pSyn == null) {
            rc = SQLITE_NOMEM;
        } else {
            const ps = pSyn.?;
            _ = memset(ps, 0, @intCast(nByte));
            const pTermData: [*]u8 = @as([*]u8, @ptrCast(ps)) + @sizeOf(Fts5ExprTerm) + @sizeOf(Fts5Buffer);
            ps.pTerm = @ptrCast(pTermData);
            ps.nFullTerm = nToken;
            ps.nQueryTerm = nToken;
            _ = memcpy(pTermData, pToken, @intCast(nToken));
            if (pCtx.pConfig.?.bTokendata != 0) {
                ps.nQueryTerm = @intCast(strlen(ps.pTerm.?));
            }
            const pLastTerm = phraseTerm(pPhrase.?, pPhrase.?.nTerm - 1);
            ps.pSynonym = pLastTerm.pSynonym;
            pLastTerm.pSynonym = ps;
        }
    } else {
        if (pPhrase == null or @mod(pPhrase.?.nTerm, SZALLOC) == 0) {
            const nNew = SZALLOC + (if (pPhrase != null) pPhrase.?.nTerm else 0);
            const pNew: ?*Fts5ExprPhrase = @ptrCast(@alignCast(sqlite3_realloc64(
                pPhrase,
                @bitCast(SZ_FTS5EXPRPHRASE(nNew + 1)),
            )));
            if (pNew == null) {
                rc = SQLITE_NOMEM;
            } else {
                if (pPhrase == null) _ = memset(pNew, 0, @intCast(SZ_FTS5EXPRPHRASE(1)));
                pPhrase = pNew;
                pCtx.pPhrase = pNew;
                pNew.?.nTerm = nNew - SZALLOC;
            }
        }

        if (rc == SQLITE_OK) {
            const pTerm = phraseTerm(pPhrase.?, pPhrase.?.nTerm);
            pPhrase.?.nTerm += 1;
            _ = memset(pTerm, 0, @sizeOf(Fts5ExprTerm));
            pTerm.pTerm = sqlite3Fts5Strndup(&rc, pToken.?, nToken);
            pTerm.nFullTerm = nToken;
            pTerm.nQueryTerm = nToken;
            if (pCtx.pConfig.?.bTokendata != 0 and rc == SQLITE_OK) {
                pTerm.nQueryTerm = @intCast(strlen(pTerm.pTerm.?));
            }
        }
    }

    pCtx.rc = rc;
    return rc;
}

// ===========================================================================
// sqlite3Fts5ParsePhraseFree / NearsetFree / Finished (7533-7554). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParsePhraseFree(pPhrase: ?*Fts5ExprPhrase) callconv(.c) void {
    fts5ExprPhraseFree(pPhrase);
}

export fn sqlite3Fts5ParseNearsetFree(pNear: ?*Fts5ExprNearset) callconv(.c) void {
    if (pNear) |pn| {
        var i: c_int = 0;
        while (i < pn.nPhrase) : (i += 1) {
            fts5ExprPhraseFree(nearPhrase(pn, i).*);
        }
        sqlite3_free(pn.pColset);
        sqlite3_free(pn);
    }
}

export fn sqlite3Fts5ParseFinished(pParse: *Fts5Parse, p: ?*Fts5ExprNode) callconv(.c) void {
    pParse.pExpr = p;
}

// ===========================================================================
// parseGrowPhraseArray (7556-7568).
// ===========================================================================
fn parseGrowPhraseArray(pParse: *Fts5Parse) c_int {
    if (@mod(pParse.nPhrase, 8) == 0) {
        const nByte: i64 = @sizeOf(?*Fts5ExprPhrase) * @as(i64, pParse.nPhrase + 8);
        const apNew: ?[*]?*Fts5ExprPhrase = @ptrCast(@alignCast(sqlite3_realloc64(@ptrCast(pParse.apPhrase), @bitCast(nByte))));
        if (apNew == null) {
            pParse.rc = SQLITE_NOMEM;
            return SQLITE_NOMEM;
        }
        pParse.apPhrase = apNew;
    }
    return SQLITE_OK;
}

// ===========================================================================
// sqlite3Fts5ParseTerm (7575-7625). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseTerm(pParse: *Fts5Parse, pAppend: ?*Fts5ExprPhrase, pToken: *Fts5Token, bPrefix: c_int) callconv(.c) ?*Fts5ExprPhrase {
    const pConfig = pParse.pConfig.?;
    var sCtx: TokenCtx = undefined;
    var rc: c_int = undefined;
    var z: ?[*:0]u8 = null;

    _ = memset(&sCtx, 0, @sizeOf(TokenCtx));
    sCtx.pPhrase = pAppend;
    sCtx.pConfig = pConfig;

    rc = fts5ParseStringFromToken(pToken, &z);
    if (rc == SQLITE_OK) {
        const flags = FTS5_TOKENIZE_QUERY | (if (bPrefix != 0) FTS5_TOKENIZE_PREFIX else 0);
        sqlite3Fts5Dequote(z.?);
        const n: c_int = @intCast(strlen(z.?));
        rc = sqlite3Fts5Tokenize(pConfig, flags, z, n, &sCtx, fts5ParseTokenize);
    }
    sqlite3_free(z);
    if (rc != 0 or blk: {
        rc = sCtx.rc;
        break :blk rc != 0;
    }) {
        pParse.rc = rc;
        fts5ExprPhraseFree(sCtx.pPhrase);
        sCtx.pPhrase = null;
    } else {
        if (pAppend == null) {
            if (parseGrowPhraseArray(pParse) != 0) {
                fts5ExprPhraseFree(sCtx.pPhrase);
                return null;
            }
            pParse.nPhrase += 1;
        }

        if (sCtx.pPhrase == null) {
            sCtx.pPhrase = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&pParse.rc, SZ_FTS5EXPRPHRASE(1))));
        } else if (sCtx.pPhrase.?.nTerm != 0) {
            phraseTerm(sCtx.pPhrase.?, sCtx.pPhrase.?.nTerm - 1).bPrefix = @intCast(bPrefix);
        }
        pParse.apPhrase.?[@intCast(pParse.nPhrase - 1)] = sCtx.pPhrase;
    }

    return sCtx.pPhrase;
}

// ===========================================================================
// sqlite3Fts5ExprClonePhrase (7631-7722). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprClonePhrase(pExpr: ?*Fts5Expr, iPhrase: c_int, ppNew: *?*Fts5Expr) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var pOrig: ?*Fts5ExprPhrase = null;
    var pNew: ?*Fts5Expr = null;
    var sCtx: TokenCtx = .{ .pPhrase = null, .pConfig = null, .rc = 0 };

    if (pExpr == null or iPhrase < 0 or iPhrase >= pExpr.?.nPhrase) {
        rc = SQLITE_RANGE;
    } else {
        pOrig = pExpr.?.apExprPhrase.?[@intCast(iPhrase)];
        pNew = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5Expr))));
    }
    if (rc == SQLITE_OK) {
        pNew.?.apExprPhrase = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(?*Fts5ExprPhrase))));
    }
    if (rc == SQLITE_OK) {
        pNew.?.pRoot = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, SZ_FTS5EXPRNODE(1))));
    }
    if (rc == SQLITE_OK) {
        pNew.?.pRoot.?.pNear = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, SZ_FTS5EXPRNEARSET(2))));
    }
    if (rc == SQLITE_OK and pOrig != null) {
        const pColsetOrig = pOrig.?.pNode.?.pNear.?.pColset;
        if (pColsetOrig) |pco| {
            const nByte = SZ_FTS5COLSET(pco.nCol);
            const pColset: ?*Fts5Colset = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
            if (pColset) |pc| {
                _ = memcpy(pc, pco, @intCast(nByte));
            }
            pNew.?.pRoot.?.pNear.?.pColset = pColset;
        }
    }

    if (rc == SQLITE_OK) {
        if (pOrig.?.nTerm != 0) {
            sCtx.pConfig = pExpr.?.pConfig;
            var i: c_int = 0;
            while (rc == SQLITE_OK and i < pOrig.?.nTerm) : (i += 1) {
                var tflags: c_int = 0;
                var p: ?*Fts5ExprTerm = phraseTerm(pOrig.?, i);
                while (p != null and rc == SQLITE_OK) : (p = p.?.pSynonym) {
                    rc = fts5ParseTokenize(@ptrCast(&sCtx), tflags, p.?.pTerm, p.?.nFullTerm, 0, 0);
                    tflags = FTS5_TOKEN_COLOCATED;
                }
                if (rc == SQLITE_OK) {
                    phraseTerm(sCtx.pPhrase.?, i).bPrefix = phraseTerm(pOrig.?, i).bPrefix;
                    phraseTerm(sCtx.pPhrase.?, i).bFirst = phraseTerm(pOrig.?, i).bFirst;
                }
            }
        } else {
            sCtx.pPhrase = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, SZ_FTS5EXPRPHRASE(1))));
        }
    }

    if (rc == SQLITE_OK and sCtx.pPhrase != null) {
        pNew.?.pIndex = pExpr.?.pIndex;
        pNew.?.pConfig = pExpr.?.pConfig;
        pNew.?.nPhrase = 1;
        pNew.?.apExprPhrase.?[0] = sCtx.pPhrase;
        nearPhrase(pNew.?.pRoot.?.pNear.?, 0).* = sCtx.pPhrase;
        pNew.?.pRoot.?.pNear.?.nPhrase = 1;
        sCtx.pPhrase.?.pNode = pNew.?.pRoot;

        if (pOrig.?.nTerm == 1 and phraseTerm(pOrig.?, 0).pSynonym == null and phraseTerm(pOrig.?, 0).bFirst == 0) {
            pNew.?.pRoot.?.eType = FTS5_TERM;
            pNew.?.pRoot.?.xNext = fts5ExprNodeNext_TERM;
        } else {
            pNew.?.pRoot.?.eType = FTS5_STRING;
            pNew.?.pRoot.?.xNext = fts5ExprNodeNext_STRING;
        }
    } else {
        sqlite3Fts5ExprFree(pNew);
        fts5ExprPhraseFree(sCtx.pPhrase);
        pNew = null;
    }

    ppNew.* = pNew;
    return rc;
}

// ===========================================================================
// sqlite3Fts5ParseNear (7730-7736). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseNear(pParse: *Fts5Parse, pTok: *Fts5Token) callconv(.c) void {
    if (pTok.n != 4 or memcmp("NEAR", pTok.p, 4) != 0) {
        sqlite3Fts5ParseError(pParse, "fts5: syntax error near \"%.*s\"", pTok.n, pTok.p);
    }
}

// ===========================================================================
// sqlite3Fts5ParseSetDistance (7738-7763). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseSetDistance(pParse: *Fts5Parse, pNear: ?*Fts5ExprNearset, p: *Fts5Token) callconv(.c) void {
    if (pNear) |pn| {
        var nNear: c_int = 0;
        if (p.n != 0) {
            var i: c_int = 0;
            while (i < p.n) : (i += 1) {
                const c: u8 = p.p.?[@intCast(i)];
                if (c < '0' or c > '9') {
                    sqlite3Fts5ParseError(pParse, "expected integer, got \"%.*s\"", p.n, p.p);
                    return;
                }
                if (nNear < 214748363) nNear = nNear * 10 + @as(c_int, p.p.?[@intCast(i)] - '0');
            }
        } else {
            nNear = FTS5_DEFAULT_NEARDIST;
        }
        pn.nNear = nNear;
    }
}

// ===========================================================================
// fts5ParseColset (7774-7808).
// ===========================================================================
fn fts5ParseColset(pParse: *Fts5Parse, p: ?*Fts5Colset, iCol: c_int) ?*Fts5Colset {
    const nCol: c_int = if (p) |pp| pp.nCol else 0;
    const pNew: ?*Fts5Colset = @ptrCast(@alignCast(sqlite3_realloc64(p, @bitCast(SZ_FTS5COLSET(nCol + 1)))));
    if (pNew == null) {
        pParse.rc = SQLITE_NOMEM;
    } else {
        const pn = pNew.?;
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            if (colsetCol(pn, i).* == iCol) return pNew;
            if (colsetCol(pn, i).* > iCol) break;
        }
        var j: c_int = nCol;
        while (j > i) : (j -= 1) {
            colsetCol(pn, j).* = colsetCol(pn, j - 1).*;
        }
        colsetCol(pn, i).* = iCol;
        pn.nCol = nCol + 1;
    }
    return pNew;
}

// ===========================================================================
// sqlite3Fts5ParseColsetInvert (7815-7836). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseColsetInvert(pParse: *Fts5Parse, p: *Fts5Colset) callconv(.c) ?*Fts5Colset {
    const nCol: c_int = pParse.pConfig.?.nCol;
    const pRet: ?*Fts5Colset = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&pParse.rc, SZ_FTS5COLSET(nCol + 1))));
    if (pRet) |pr| {
        var iOld: c_int = 0;
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            if (iOld >= p.nCol or colsetCol(p, iOld).* != i) {
                colsetCol(pr, pr.nCol).* = i;
                pr.nCol += 1;
            } else {
                iOld += 1;
            }
        }
    }
    sqlite3_free(p);
    return pRet;
}

// ===========================================================================
// sqlite3Fts5ParseColset (7838-7868). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseColset(pParse: *Fts5Parse, pColset: ?*Fts5Colset, p: *Fts5Token) callconv(.c) ?*Fts5Colset {
    var pRet: ?*Fts5Colset = null;
    var iCol: c_int = undefined;

    const z: ?[*:0]u8 = sqlite3Fts5Strndup(&pParse.rc, p.p.?, p.n);
    if (pParse.rc == SQLITE_OK) {
        const pConfig = pParse.pConfig.?;
        sqlite3Fts5Dequote(z.?);
        iCol = 0;
        while (iCol < pConfig.nCol) : (iCol += 1) {
            if (0 == sqlite3_stricmp(pConfig.azCol.?[@intCast(iCol)].?, z.?)) break;
        }
        if (iCol == pConfig.nCol) {
            sqlite3Fts5ParseError(pParse, "no such column: %s", z);
        } else {
            pRet = fts5ParseColset(pParse, pColset, iCol);
        }
        sqlite3_free(z);
    }

    if (pRet == null) {
        sqlite3_free(pColset);
    }

    return pRet;
}

// ===========================================================================
// fts5CloneColset (7878-7890).
// ===========================================================================
fn fts5CloneColset(pRc: *c_int, pOrig: ?*Fts5Colset) ?*Fts5Colset {
    var pRet: ?*Fts5Colset = null;
    if (pOrig) |po| {
        const nByte = SZ_FTS5COLSET(po.nCol);
        pRet = @ptrCast(@alignCast(sqlite3Fts5MallocZero(pRc, nByte)));
        if (pRet) |pr| {
            _ = memcpy(pr, po, @intCast(nByte));
        }
    }
    return pRet;
}

// ===========================================================================
// fts5MergeColset (7895-7913).
// ===========================================================================
fn fts5MergeColset(pColset: *Fts5Colset, pMerge: *Fts5Colset) void {
    var iIn: c_int = 0;
    var iMerge: c_int = 0;
    var iOut: c_int = 0;

    while (iIn < pColset.nCol and iMerge < pMerge.nCol) {
        const iDiff = colsetCol(pColset, iIn).* - colsetCol(pMerge, iMerge).*;
        if (iDiff == 0) {
            colsetCol(pColset, iOut).* = colsetCol(pMerge, iMerge).*;
            iOut += 1;
            iMerge += 1;
            iIn += 1;
        } else if (iDiff > 0) {
            iMerge += 1;
        } else {
            iIn += 1;
        }
    }
    pColset.nCol = iOut;
}

// ===========================================================================
// fts5ParseSetColset (7921-7954).
// ===========================================================================
fn fts5ParseSetColset(pParse: *Fts5Parse, pNode: *Fts5ExprNode, pColset: *Fts5Colset, ppFree: *?*Fts5Colset) void {
    if (pParse.rc == SQLITE_OK) {
        if (pNode.eType == FTS5_STRING or pNode.eType == FTS5_TERM) {
            const pNear = pNode.pNear.?;
            if (pNear.pColset != null) {
                fts5MergeColset(pNear.pColset.?, pColset);
                if (pNear.pColset.?.nCol == 0) {
                    pNode.eType = FTS5_EOF;
                    pNode.xNext = null;
                }
            } else if (ppFree.* != null) {
                pNear.pColset = pColset;
                ppFree.* = null;
            } else {
                pNear.pColset = fts5CloneColset(&pParse.rc, pColset);
            }
        } else {
            var i: c_int = 0;
            while (i < pNode.nChild) : (i += 1) {
                fts5ParseSetColset(pParse, nodeChild(pNode, i).*.?, pColset, ppFree);
            }
        }
    }
}

// ===========================================================================
// sqlite3Fts5ParseSetColset (7959-7973). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseSetColset(pParse: *Fts5Parse, pExpr: ?*Fts5ExprNode, pColset: ?*Fts5Colset) callconv(.c) void {
    var pFree: ?*Fts5Colset = pColset;
    if (pParse.pConfig.?.eDetail == FTS5_DETAIL_NONE) {
        sqlite3Fts5ParseError(pParse, "fts5: column queries are not supported (detail=none)");
    } else {
        fts5ParseSetColset(pParse, pExpr.?, pColset.?, &pFree);
    }
    sqlite3_free(pFree);
}

// ===========================================================================
// fts5ExprAssignXNext (7975-8006).
// ===========================================================================
fn fts5ExprAssignXNext(pNode: *Fts5ExprNode) void {
    switch (pNode.eType) {
        FTS5_STRING => {
            const pNear = pNode.pNear.?;
            if (pNear.nPhrase == 1 and nearPhrase(pNear, 0).*.?.nTerm == 1 and
                phraseTerm(nearPhrase(pNear, 0).*.?, 0).pSynonym == null and
                phraseTerm(nearPhrase(pNear, 0).*.?, 0).bFirst == 0)
            {
                pNode.eType = FTS5_TERM;
                pNode.xNext = fts5ExprNodeNext_TERM;
            } else {
                pNode.xNext = fts5ExprNodeNext_STRING;
            }
        },
        FTS5_OR => {
            pNode.xNext = fts5ExprNodeNext_OR;
        },
        FTS5_AND => {
            pNode.xNext = fts5ExprNodeNext_AND;
        },
        else => { // FTS5_NOT
            pNode.xNext = fts5ExprNodeNext_NOT;
        },
    }
}

// ===========================================================================
// fts5ExprAddChildren (8011-8024).
// ===========================================================================
fn fts5ExprAddChildren(p: *Fts5ExprNode, pSub: *Fts5ExprNode) void {
    var ii = p.nChild;
    if (p.eType != FTS5_NOT and pSub.eType == p.eType) {
        const nByte: usize = @sizeOf(?*Fts5ExprNode) * @as(usize, @intCast(pSub.nChild));
        _ = memcpy(@ptrCast(nodeChild(p, p.nChild)), @ptrCast(nodeChild(pSub, 0)), nByte);
        p.nChild += pSub.nChild;
        sqlite3_free(pSub);
    } else {
        nodeChild(p, p.nChild).* = pSub;
        p.nChild += 1;
    }
    while (ii < p.nChild) : (ii += 1) {
        p.iHeight = MAX(p.iHeight, nodeChild(p, ii).*.?.iHeight + 1);
    }
}

// ===========================================================================
// fts5ParsePhraseToAnd (8037-8088).
// ===========================================================================
fn fts5ParsePhraseToAnd(pParse: *Fts5Parse, pNear: *Fts5ExprNearset) ?*Fts5ExprNode {
    const nTerm = nearPhrase(pNear, 0).*.?.nTerm;
    const nByte = SZ_FTS5EXPRNODE(nTerm + 1);
    const pRet: ?*Fts5ExprNode = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&pParse.rc, nByte)));
    if (pRet) |pr| {
        pr.eType = FTS5_AND;
        pr.nChild = nTerm;
        pr.iHeight = 1;
        fts5ExprAssignXNext(pr);
        pParse.nPhrase -= 1;
        var ii: c_int = 0;
        while (ii < nTerm) : (ii += 1) {
            const pPhrase: ?*Fts5ExprPhrase = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&pParse.rc, SZ_FTS5EXPRPHRASE(1))));
            if (pPhrase) |pp| {
                if (parseGrowPhraseArray(pParse) != 0) {
                    fts5ExprPhraseFree(pPhrase);
                } else {
                    const pTermSrc = phraseTerm(nearPhrase(pNear, 0).*.?, ii);
                    const pTo = phraseTerm(pp, 0);
                    pParse.apPhrase.?[@intCast(pParse.nPhrase)] = pPhrase;
                    pParse.nPhrase += 1;
                    pp.nTerm = 1;
                    pTo.pTerm = sqlite3Fts5Strndup(&pParse.rc, pTermSrc.pTerm.?, pTermSrc.nFullTerm);
                    pTo.nQueryTerm = pTermSrc.nQueryTerm;
                    pTo.nFullTerm = pTermSrc.nFullTerm;
                    nodeChild(pr, ii).* = sqlite3Fts5ParseNode(
                        pParse,
                        FTS5_STRING,
                        null,
                        null,
                        sqlite3Fts5ParseNearset(pParse, null, pPhrase),
                    );
                }
            }
        }

        if (pParse.rc != 0) {
            sqlite3Fts5ParseNodeFree(pRet);
            return null;
        } else {
            sqlite3Fts5ParseNearsetFree(pNear);
        }
    }

    return pRet;
}

// ===========================================================================
// sqlite3Fts5ParseNode (8094-8186). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseNode(
    pParse: *Fts5Parse,
    eType: c_int,
    pLeft0: ?*Fts5ExprNode,
    pRight0: ?*Fts5ExprNode,
    pNear0: ?*Fts5ExprNearset,
) callconv(.c) ?*Fts5ExprNode {
    var pLeft = pLeft0;
    var pRight = pRight0;
    var pNear = pNear0;
    var pRet: ?*Fts5ExprNode = null;

    if (pParse.rc == SQLITE_OK) {
        var nChild: c_int = 0;

        if (eType == FTS5_STRING and pNear == null) return null;
        if (eType != FTS5_STRING and pLeft == null) return pRight;
        if (eType != FTS5_STRING and pRight == null) return pLeft;

        if (eType == FTS5_STRING and pParse.bPhraseToAnd != 0 and nearPhrase(pNear.?, 0).*.?.nTerm > 1) {
            pRet = fts5ParsePhraseToAnd(pParse, pNear.?);
        } else {
            if (eType == FTS5_NOT) {
                nChild = 2;
            } else if (eType == FTS5_AND or eType == FTS5_OR) {
                nChild = 2;
                if (pLeft.?.eType == eType) nChild += pLeft.?.nChild - 1;
                if (pRight.?.eType == eType) nChild += pRight.?.nChild - 1;
            }

            const nByte = SZ_FTS5EXPRNODE(nChild);
            pRet = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&pParse.rc, nByte)));

            if (pRet) |pr| {
                pr.eType = eType;
                pr.pNear = pNear;
                fts5ExprAssignXNext(pr);
                if (eType == FTS5_STRING) {
                    var iPhrase: c_int = 0;
                    while (iPhrase < pNear.?.nPhrase) : (iPhrase += 1) {
                        nearPhrase(pNear.?, iPhrase).*.?.pNode = pr;
                        if (nearPhrase(pNear.?, iPhrase).*.?.nTerm == 0) {
                            pr.xNext = null;
                            pr.eType = FTS5_EOF;
                        }
                    }

                    if (pParse.pConfig.?.eDetail != FTS5_DETAIL_FULL) {
                        const pPhrase = nearPhrase(pNear.?, 0).*.?;
                        if (pNear.?.nPhrase != 1 or pPhrase.nTerm > 1 or
                            (pPhrase.nTerm > 0 and phraseTerm(pPhrase, 0).bFirst != 0))
                        {
                            sqlite3Fts5ParseError(
                                pParse,
                                "fts5: %s queries are not supported (detail!=full)",
                                if (pNear.?.nPhrase == 1) @as([*:0]const u8, "phrase") else @as([*:0]const u8, "NEAR"),
                            );
                            sqlite3Fts5ParseNodeFree(pRet);
                            pRet = null;
                            pNear = null;
                        }
                    }
                } else {
                    fts5ExprAddChildren(pr, pLeft.?);
                    fts5ExprAddChildren(pr, pRight.?);
                    pLeft = null;
                    pRight = null;
                    if (pr.iHeight > SQLITE_FTS5_MAX_EXPR_DEPTH) {
                        sqlite3Fts5ParseError(
                            pParse,
                            "fts5 expression tree is too large (maximum depth %d)",
                            SQLITE_FTS5_MAX_EXPR_DEPTH,
                        );
                        sqlite3Fts5ParseNodeFree(pRet);
                        pRet = null;
                    }
                }
            }
        }
    }

    if (pRet == null) {
        sqlite3Fts5ParseNodeFree(pLeft);
        sqlite3Fts5ParseNodeFree(pRight);
        sqlite3Fts5ParseNearsetFree(pNear);
    }
    return pRet;
}

// ===========================================================================
// sqlite3Fts5ParseImplicitAnd (8188-8253). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ParseImplicitAnd(pParse: *Fts5Parse, pLeft: ?*Fts5ExprNode, pRight: ?*Fts5ExprNode) callconv(.c) ?*Fts5ExprNode {
    var pRet: ?*Fts5ExprNode = null;
    var pPrev: *Fts5ExprNode = undefined;

    if (pParse.rc != 0) {
        sqlite3Fts5ParseNodeFree(pLeft);
        sqlite3Fts5ParseNodeFree(pRight);
    } else {
        const pl = pLeft.?;
        const pr = pRight.?;

        if (pl.eType == FTS5_AND) {
            pPrev = nodeChild(pl, pl.nChild - 1).*.?;
        } else {
            pPrev = pl;
        }

        if (pr.eType == FTS5_EOF) {
            sqlite3Fts5ParseNodeFree(pRight);
            pRet = pLeft;
            pParse.nPhrase -= 1;
        } else if (pPrev.eType == FTS5_EOF) {
            var ap: [*]?*Fts5ExprPhrase = undefined;

            if (pPrev == pl) {
                pRet = pRight;
            } else {
                nodeChild(pl, pl.nChild - 1).* = pRight;
                pRet = pLeft;
            }

            ap = @ptrCast(&pParse.apPhrase.?[@intCast(pParse.nPhrase - 1 - pr.pNear.?.nPhrase)]);
            _ = memmove(@ptrCast(&ap[1]), @ptrCast(ap), @sizeOf(?*Fts5ExprPhrase) * @as(usize, @intCast(pr.pNear.?.nPhrase)));
            pParse.nPhrase -= 1;

            sqlite3Fts5ParseNodeFree(pPrev);
        } else {
            pRet = sqlite3Fts5ParseNode(pParse, FTS5_AND, pLeft, pRight, null);
        }
    }

    return pRet;
}

// ===========================================================================
// sqlite3Fts5ExprInit (8633-8665): register debug UDFs. In production
// (no SQLITE_TEST / SQLITE_FTS5_DEBUG) this is just a no-op that references
// the parser trace/fallback symbols so they are retained. EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprInit(pGlobal: ?*Fts5Global, db: ?*anyopaque) callconv(.c) c_int {
    _ = pGlobal;
    _ = db;
    const rc: c_int = SQLITE_OK;
    // Reference the parser trace/fallback so they are not dropped (mirrors the
    // C "(void)sqlite3Fts5ParserTrace; (void)sqlite3Fts5ParserFallback;").
    _ = &sqlite3Fts5ParserTrace;
    _ = &sqlite3Fts5ParserFallback;
    return rc;
}

// ===========================================================================
// sqlite3Fts5ExprPhraseCount / PhraseSize / Poslist (8670-8698). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprPhraseCount(pExpr: ?*Fts5Expr) callconv(.c) c_int {
    return if (pExpr) |e| e.nPhrase else 0;
}

export fn sqlite3Fts5ExprPhraseSize(pExpr: *Fts5Expr, iPhrase: c_int) callconv(.c) c_int {
    if (iPhrase < 0 or iPhrase >= pExpr.nPhrase) return 0;
    return pExpr.apExprPhrase.?[@intCast(iPhrase)].?.nTerm;
}

export fn sqlite3Fts5ExprPoslist(pExpr: *Fts5Expr, iPhrase: c_int, pa: *?[*]const u8) callconv(.c) c_int {
    const pPhrase = pExpr.apExprPhrase.?[@intCast(iPhrase)].?;
    const pNode = pPhrase.pNode.?;
    var nRet: c_int = undefined;
    if (pNode.bEof == 0 and pNode.iRowid == pExpr.pRoot.?.iRowid) {
        pa.* = pPhrase.poslist.p;
        nRet = pPhrase.poslist.n;
    } else {
        pa.* = null;
        nRet = 0;
    }
    return nRet;
}

// ===========================================================================
// Fts5PoslistPopulator (8700-8704) — section-private; opaque in foundation.
// ===========================================================================
const Fts5PoslistPopulator = extern struct {
    writer: Fts5PoslistWriter,
    bOk: c_int, // true if ok to populate
    bMiss: c_int,
};

// ===========================================================================
// sqlite3Fts5ExprClearPoslists (8715-8735). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprClearPoslists(pExpr: *Fts5Expr, bLive: c_int) callconv(.c) ?*Fts5PoslistPopulator {
    const pRet: ?*Fts5PoslistPopulator = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts5PoslistPopulator) * @as(u64, @intCast(pExpr.nPhrase)))));
    if (pRet) |pr| {
        _ = memset(pr, 0, @sizeOf(Fts5PoslistPopulator) * @as(usize, @intCast(pExpr.nPhrase)));
        const arr: [*]Fts5PoslistPopulator = @ptrCast(pr);
        var i: c_int = 0;
        while (i < pExpr.nPhrase) : (i += 1) {
            const pBuf = &pExpr.apExprPhrase.?[@intCast(i)].?.poslist;
            const pNode = pExpr.apExprPhrase.?[@intCast(i)].?.pNode.?;
            if (bLive != 0 and (pBuf.n == 0 or pNode.iRowid != pExpr.pRoot.?.iRowid or pNode.bEof != 0)) {
                arr[@intCast(i)].bMiss = 1;
            } else {
                pBuf.n = 0;
            }
        }
    }
    return pRet;
}

// ===========================================================================
// Fts5ExprCtx (8737-8742) + helpers + PopulatePoslists (8747-8840).
// ===========================================================================
const Fts5ExprCtx = extern struct {
    pExpr: ?*Fts5Expr,
    aPopulator: ?[*]Fts5PoslistPopulator,
    iOff: i64,
};

fn fts5ExprColsetTest(pColset: *Fts5Colset, iCol: c_int) c_int {
    var i: c_int = 0;
    while (i < pColset.nCol) : (i += 1) {
        if (colsetCol(pColset, i).* == iCol) return 1;
    }
    return 0;
}

fn fts5QueryTerm(pToken: [*]const u8, nToken: c_int) c_int {
    var ii: c_int = 0;
    while (ii < nToken and pToken[@intCast(ii)] != 0) : (ii += 1) {}
    return ii;
}

fn fts5ExprPopulatePoslistsCb(
    pCtx: ?*anyopaque,
    tflags: c_int,
    pToken: ?[*]const u8,
    nToken: c_int,
    iUnused1: c_int,
    iUnused2: c_int,
) callconv(.c) c_int {
    _ = iUnused1;
    _ = iUnused2;
    const p: *Fts5ExprCtx = @ptrCast(@alignCast(pCtx.?));
    const pExpr = p.pExpr.?;
    var nQuery = nToken;
    const iRowid = pExpr.pRoot.?.iRowid;

    if (nQuery > FTS5_MAX_TOKEN_SIZE) nQuery = FTS5_MAX_TOKEN_SIZE;
    if (pExpr.pConfig.?.bTokendata != 0) {
        nQuery = fts5QueryTerm(pToken.?, nQuery);
    }
    if ((tflags & FTS5_TOKEN_COLOCATED) == 0) p.iOff += 1;
    var i: c_int = 0;
    while (i < pExpr.nPhrase) : (i += 1) {
        if (p.aPopulator.?[@intCast(i)].bOk == 0) continue;
        var pT: ?*Fts5ExprTerm = phraseTerm(pExpr.apExprPhrase.?[@intCast(i)].?, 0);
        while (pT) |pt| : (pT = pt.pSynonym) {
            if ((pt.nQueryTerm == nQuery or (pt.nQueryTerm < nQuery and pt.bPrefix != 0)) and
                memcmp(pt.pTerm, pToken, @intCast(pt.nQueryTerm)) == 0)
            {
                var rc = sqlite3Fts5PoslistWriterAppend(
                    &pExpr.apExprPhrase.?[@intCast(i)].?.poslist,
                    &p.aPopulator.?[@intCast(i)].writer,
                    p.iOff,
                );
                if (rc == SQLITE_OK and (pExpr.pConfig.?.bTokendata != 0 or pt.bPrefix != 0)) {
                    const iCol: c_int = @intCast(p.iOff >> 32);
                    const iTokOff: c_int = @intCast(p.iOff & 0x7FFFFFFF);
                    rc = sqlite3Fts5IndexIterWriteTokendata(pt.pIter, pToken, nToken, iRowid, iCol, iTokOff);
                }
                if (rc != 0) return rc;
                break;
            }
        }
    }
    return SQLITE_OK;
}

export fn sqlite3Fts5ExprPopulatePoslists(
    pConfig: ?*Fts5Config,
    pExpr: *Fts5Expr,
    aPopulator: ?[*]Fts5PoslistPopulator,
    iCol: c_int,
    z: ?[*]const u8,
    n: c_int,
) callconv(.c) c_int {
    var sCtx: Fts5ExprCtx = undefined;
    sCtx.pExpr = pExpr;
    sCtx.aPopulator = aPopulator;
    sCtx.iOff = (@as(i64, iCol) << 32) - 1;

    var i: c_int = 0;
    while (i < pExpr.nPhrase) : (i += 1) {
        const pNode = pExpr.apExprPhrase.?[@intCast(i)].?.pNode.?;
        const pColset = pNode.pNear.?.pColset;
        if ((pColset != null and 0 == fts5ExprColsetTest(pColset.?, iCol)) or aPopulator.?[@intCast(i)].bMiss != 0) {
            aPopulator.?[@intCast(i)].bOk = 0;
        } else {
            aPopulator.?[@intCast(i)].bOk = 1;
        }
    }

    return sqlite3Fts5Tokenize(pConfig, FTS5_TOKENIZE_DOCUMENT, z, n, &sCtx, fts5ExprPopulatePoslistsCb);
}

// ===========================================================================
// fts5ExprClearPoslists / CheckPoslists (8842-8900).
// ===========================================================================
fn fts5ExprClearPoslists(pNode: *Fts5ExprNode) void {
    if (pNode.eType == FTS5_TERM or pNode.eType == FTS5_STRING) {
        nearPhrase(pNode.pNear.?, 0).*.?.poslist.n = 0;
    } else {
        var i: c_int = 0;
        while (i < pNode.nChild) : (i += 1) {
            fts5ExprClearPoslists(nodeChild(pNode, i).*.?);
        }
    }
}

fn fts5ExprCheckPoslists(pNode: *Fts5ExprNode, iRowid: i64) c_int {
    pNode.iRowid = iRowid;
    pNode.bEof = 0;
    switch (pNode.eType) {
        0, FTS5_TERM, FTS5_STRING => {
            return @intFromBool(nearPhrase(pNode.pNear.?, 0).*.?.poslist.n > 0);
        },
        FTS5_AND => {
            var i: c_int = 0;
            while (i < pNode.nChild) : (i += 1) {
                if (fts5ExprCheckPoslists(nodeChild(pNode, i).*.?, iRowid) == 0) {
                    fts5ExprClearPoslists(pNode);
                    return 0;
                }
            }
        },
        FTS5_OR => {
            var bRet: c_int = 0;
            var i: c_int = 0;
            while (i < pNode.nChild) : (i += 1) {
                if (fts5ExprCheckPoslists(nodeChild(pNode, i).*.?, iRowid) != 0) {
                    bRet = 1;
                }
            }
            return bRet;
        },
        else => { // FTS5_NOT
            if (0 == fts5ExprCheckPoslists(nodeChild(pNode, 0).*.?, iRowid) or
                0 != fts5ExprCheckPoslists(nodeChild(pNode, 1).*.?, iRowid))
            {
                fts5ExprClearPoslists(pNode);
                return 0;
            }
        },
    }
    return 1;
}

export fn sqlite3Fts5ExprCheckPoslists(pExpr: *Fts5Expr, iRowid: i64) callconv(.c) void {
    _ = fts5ExprCheckPoslists(pExpr.pRoot.?, iRowid);
}

// ===========================================================================
// sqlite3Fts5ExprPhraseCollist (8905-8938). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprPhraseCollist(pExpr: *Fts5Expr, iPhrase: c_int, ppCollist: *?[*]const u8, pnCollist: *c_int) callconv(.c) c_int {
    const pPhrase = pExpr.apExprPhrase.?[@intCast(iPhrase)].?;
    const pNode = pPhrase.pNode.?;
    var rc: c_int = SQLITE_OK;

    if (pNode.bEof == 0 and pNode.iRowid == pExpr.pRoot.?.iRowid and pPhrase.poslist.n > 0) {
        const pTerm = phraseTerm(pPhrase, 0);
        if (pTerm.pSynonym != null) {
            const pBuf: *Fts5Buffer = @ptrCast(@alignCast(@as([*]Fts5ExprTerm, @ptrCast(pTerm.pSynonym.?)) + 1));
            var pa: ?[*]u8 = null;
            rc = fts5ExprSynonymList(pTerm, pNode.iRowid, pBuf, &pa, pnCollist);
            ppCollist.* = pa;
        } else {
            ppCollist.* = phraseTerm(pPhrase, 0).pIter.?.pData;
            pnCollist.* = phraseTerm(pPhrase, 0).pIter.?.nData;
        }
    } else {
        ppCollist.* = null;
        pnCollist.* = 0;
    }

    return rc;
}

// ===========================================================================
// sqlite3Fts5ExprQueryToken (8943-8963). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprQueryToken(pExpr: *Fts5Expr, iPhrase: c_int, iToken: c_int, ppOut: *?[*]const u8, pnOut: *c_int) callconv(.c) c_int {
    if (iPhrase < 0 or iPhrase >= pExpr.nPhrase) {
        return SQLITE_RANGE;
    }
    const pPhrase = pExpr.apExprPhrase.?[@intCast(iPhrase)].?;
    if (iToken < 0 or iToken >= pPhrase.nTerm) {
        return SQLITE_RANGE;
    }

    ppOut.* = phraseTerm(pPhrase, iToken).pTerm;
    pnOut.* = phraseTerm(pPhrase, iToken).nFullTerm;
    return SQLITE_OK;
}

// ===========================================================================
// sqlite3Fts5ExprInstToken (8968-9000). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprInstToken(
    pExpr: *Fts5Expr,
    iRowid: i64,
    iPhrase: c_int,
    iCol: c_int,
    iOff: c_int,
    iToken: c_int,
    ppOut: *?[*]const u8,
    pnOut: *c_int,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (iPhrase < 0 or iPhrase >= pExpr.nPhrase) {
        return SQLITE_RANGE;
    }
    const pPhrase = pExpr.apExprPhrase.?[@intCast(iPhrase)].?;
    if (iToken < 0 or iToken >= pPhrase.nTerm) {
        return SQLITE_RANGE;
    }
    const pTerm = phraseTerm(pPhrase, iToken);
    if (pExpr.pConfig.?.bTokendata != 0 or pTerm.bPrefix != 0) {
        rc = sqlite3Fts5IterToken(pTerm.pIter, pTerm.pTerm, pTerm.nQueryTerm, iRowid, iCol, iOff + iToken, ppOut, pnOut);
    } else {
        ppOut.* = pTerm.pTerm;
        pnOut.* = pTerm.nFullTerm;
    }
    return rc;
}

// ===========================================================================
// sqlite3Fts5ExprClearTokens (9006-9014). EXPORTED.
// ===========================================================================
export fn sqlite3Fts5ExprClearTokens(pExpr: *Fts5Expr) callconv(.c) void {
    var ii: c_int = 0;
    while (ii < pExpr.nPhrase) : (ii += 1) {
        var pT: ?*Fts5ExprTerm = phraseTerm(pExpr.apExprPhrase.?[@intCast(ii)].?, 0);
        while (pT) |pt| : (pT = pt.pSynonym) {
            sqlite3Fts5IndexIterClearTokendata(pt.pIter);
        }
    }
}

comptime {
    _ = int;
    _ = std;
    // Reference the test-only / unicode externs so the file is self-consistent
    // even though the SQLITE_TEST/DEBUG fts5_expr() UDF block is not ported here
    // (it is debug-only; not required for the engine to function).
    _ = sqlite3_mprintf;
    _ = sqlite3_context_db_handle;
    _ = sqlite3_user_data;
    _ = sqlite3_value_text;
    _ = sqlite3_value_int;
    _ = sqlite3_result_text;
    _ = sqlite3_result_int;
    _ = sqlite3_result_error;
    _ = sqlite3_result_error_code;
    _ = sqlite3_result_error_nomem;
    _ = sqlite3_create_function;
    _ = sqlite3Fts5ConfigParse;
    _ = sqlite3Fts5ConfigFree;
    _ = sqlite3Fts5UnicodeCatParse;
    _ = sqlite3Fts5UnicodeCategory;
    _ = sqlite3Fts5UnicodeFold;
    _ = sqlite3Fts5ParserFallback;
    _ = sqlite3Fts5ParserTrace;
}
