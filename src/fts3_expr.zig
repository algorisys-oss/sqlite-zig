//! Zig port of SQLite's FTS3 MATCH-query expression parser (ext/fts3/fts3_expr.c).
//!
//! This module implements the hand-coded operator-precedence parser for fts3
//! query strings (the right-hand argument to the MATCH operator). It turns a
//! string such as `'a OR b NEAR c "phrase"'` into a tree of `Fts3Expr` nodes
//! (PHRASE / NEAR / NOT / AND / OR), then rebalances and depth-checks the tree.
//!
//! Drop-in replacement for the C TU: it exports every non-static symbol the C
//! file defines, so the now-Zig fts3.zig and still-C fts3_snippet.c link
//! against the Zig versions. Compiled because SQLITE_ENABLE_FTS3 is enabled.
//!
//! Exports (always):
//!   * sqlite3Fts3MallocZero
//!   * sqlite3Fts3OpenTokenizer
//!   * sqlite3Fts3ExprParse
//!   * sqlite3Fts3ExprFree
//! Exports (SQLITE_TEST only, gated on config.sqlite_test):
//!   * sqlite3_fts3_enable_parentheses  (mutable global; toggles new/old syntax)
//!   * sqlite3Fts3ExprInitTestInterface (registers fts3_exprtest[_rebalance])
//!
//! NOTE: sqlite3Fts3ExprIterate is NOT here — despite being declared in
//! fts3Int.h, it is defined in fts3_snippet.c, not fts3_expr.c.
//!
//! ABI coupling
//! ------------
//! Pointers to Fts3Expr / Fts3Phrase / Fts3PhraseToken / Fts3Table /
//! sqlite3_tokenizer / sqlite3_tokenizer_cursor cross the boundary to/from the
//! Zig fts3.zig and the still-C fts3_snippet.c / fts3_tokenizer.c TUs. Each is
//! mirrored here as an `extern struct` field-for-field, copied exactly from the
//! sibling src/fts3.zig (and fts3_tokenizer.h). No tools/offsets.c entry is
//! required: every field touched is a leading, config-invariant field, and the
//! SZ_FTS3PHRASE size math uses @offsetOf on the mirrored layout.

const std = @import("std");
const config = @import("config");

// ---------------------------------------------------------------------------
// Result codes (sqlite3.h)
// ---------------------------------------------------------------------------
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_TOOBIG: c_int = 18;
const SQLITE_DONE: c_int = 101;

// Text encodings (sqlite3.h) — for sqlite3_create_function.
const SQLITE_UTF8: c_int = 1;

// Destructor sentinels (sqlite3.h): SQLITE_STATIC==0, SQLITE_TRANSIENT==-1.
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// ---------------------------------------------------------------------------
// fts3Int.h constants
// ---------------------------------------------------------------------------
// Fts3Expr.eType values (fts3Int.h) — identical to src/fts3.zig.
const FTSQUERY_NEAR: c_int = 1;
const FTSQUERY_NOT: c_int = 2;
const FTSQUERY_AND: c_int = 3;
const FTSQUERY_OR: c_int = 4;
const FTSQUERY_PHRASE: c_int = 5;

// Default span for NEAR operators (#define SQLITE_FTS3_DEFAULT_NEAR_PARAM 10).
const SQLITE_FTS3_DEFAULT_NEAR_PARAM: c_int = 10;

// Maximum balanced expression-tree depth (fts3Int.h: #ifndef ... 12).
const SQLITE_FTS3_MAX_EXPR_DEPTH: c_int = 12;

// ---------------------------------------------------------------------------
// sqlite3_fts3_enable_parentheses.
//
// In a SQLITE_TEST build this is a mutable global initialized to 0, exported so
// the testfixture can toggle old/new syntax at runtime. Otherwise it is a
// compile-time constant: 1 if SQLITE_ENABLE_FTS3_PARENTHESIS is defined, else 0.
// This build does NOT define SQLITE_ENABLE_FTS3_PARENTHESIS, so the non-test
// value is 0.
// ---------------------------------------------------------------------------
const ENABLE_FTS3_PARENTHESIS = false; // SQLITE_ENABLE_FTS3_PARENTHESIS undefined

pub export var sqlite3_fts3_enable_parentheses: c_int = if (config.sqlite_test)
    0
else if (ENABLE_FTS3_PARENTHESIS) 1 else 0;

/// Current value of the enable_parentheses switch. In a test build this reads
/// the mutable global; otherwise it is a comptime constant (so dead branches
/// fold away exactly as the C preprocessor does).
inline fn enableParen() bool {
    if (config.sqlite_test) {
        return sqlite3_fts3_enable_parentheses != 0;
    }
    return ENABLE_FTS3_PARENTHESIS;
}

// ---------------------------------------------------------------------------
// Public ABI opaque handles (sqlite3.h)
// ---------------------------------------------------------------------------
const sqlite3 = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;

// ---------------------------------------------------------------------------
// Tokenizer module (fts3_tokenizer.h). Field order and fn-ptr signatures copied
// exactly from src/fts3_porter.zig. xOpen/xNext/xClose/xLanguageid are all
// called here, so they carry their full prototypes.
// ---------------------------------------------------------------------------
const sqlite3_tokenizer_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const fn (c_int, [*]const [*:0]const u8, *?*sqlite3_tokenizer) callconv(.c) c_int,
    xDestroy: ?*const fn (*sqlite3_tokenizer) callconv(.c) c_int,
    xOpen: ?*const fn (*sqlite3_tokenizer, ?[*]const u8, c_int, *?*sqlite3_tokenizer_cursor) callconv(.c) c_int,
    xClose: ?*const fn (*sqlite3_tokenizer_cursor) callconv(.c) c_int,
    xNext: ?*const fn (*sqlite3_tokenizer_cursor, *?[*]const u8, *c_int, *c_int, *c_int, *c_int) callconv(.c) c_int,
    xLanguageid: ?*const fn (*sqlite3_tokenizer_cursor, c_int) callconv(.c) c_int,
};

const sqlite3_tokenizer = extern struct {
    pModule: ?*const sqlite3_tokenizer_module,
};

const sqlite3_tokenizer_cursor = extern struct {
    pTokenizer: ?*sqlite3_tokenizer,
};

// ---------------------------------------------------------------------------
// Fts3Hash (fts3_hash.h) — only passed by pointer here (test interface).
// ---------------------------------------------------------------------------
const Fts3Hash = opaque {};

// ---------------------------------------------------------------------------
// ABI-SHARED fts3 structs (fts3Int.h), mirrored exactly from src/fts3.zig.
// ---------------------------------------------------------------------------
const Fts3DeferredToken = opaque {};
const Fts3SegReader = opaque {};
const MatchinfoBuffer = opaque {};

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

/// Fts3Phrase has a flexible array member `aToken[]`. Represented as a 0-length
/// trailing array; aToken[i] reached via pointer arithmetic. SZ_FTS3PHRASE(N)
/// below uses @offsetOf("aToken") for byte-exact allocation sizing.
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

/// fts3Int.h: SZ_FTS3PHRASE(N) = offsetof(Fts3Phrase,aToken)+N*sizeof(Fts3PhraseToken)
inline fn SZ_FTS3PHRASE(n: i64) i64 {
    return @as(i64, @intCast(@offsetOf(Fts3Phrase, "aToken"))) +
        n * @as(i64, @intCast(@sizeOf(Fts3PhraseToken)));
}

/// Access aToken[i] of an Fts3Phrase by pointer arithmetic (flexible array).
inline fn phraseToken(p: *Fts3Phrase, i: c_int) *Fts3PhraseToken {
    const base: [*]Fts3PhraseToken = @ptrCast(&p.aToken);
    return &base[@intCast(i)];
}

// ---------------------------------------------------------------------------
// libc + public sqlite3 API resolved at link time.
// ---------------------------------------------------------------------------
extern fn strlen(s: [*:0]const u8) usize;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_strnicmp(a: [*:0]const u8, b: [*:0]const u8, n: c_int) c_int;
extern fn sqlite3_create_function(db: ?*sqlite3, zFunc: [*:0]const u8, nArg: c_int, eTextRep: c_int, pApp: ?*anyopaque, xFunc: ?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void, xStep: ?*anyopaque, xFinal: ?*anyopaque) c_int;

extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_bytes(p: ?*sqlite3_value) c_int;
extern fn sqlite3_user_data(ctx: ?*sqlite3_context) ?*anyopaque;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: [*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: ?*sqlite3_context) void;

// ---------------------------------------------------------------------------
// Internal helpers from sibling fts3 TUs, resolved at link time.
//   * fts3.zig         : sqlite3Fts3ReadInt, sqlite3Fts3ErrMsg
//   * fts3_write.c     : sqlite3Fts3EvalPhraseCleanup
//   * fts3_tokenizer.c : sqlite3Fts3InitTokenizer (test interface only)
// ---------------------------------------------------------------------------
extern fn sqlite3Fts3ReadInt(z: [*:0]const u8, pnOut: *c_int) c_int;
extern fn sqlite3Fts3ErrMsg(pzErr: *?[*:0]u8, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3Fts3EvalPhraseCleanup(p: ?*Fts3Phrase) void;
extern fn sqlite3Fts3InitTokenizer(pHash: *Fts3Hash, zArg: [*:0]const u8, ppTok: *?*sqlite3_tokenizer, pzErr: *?[*:0]u8) c_int;

// ===========================================================================
// ParseContext — the parser's working state (file-local; struct ParseContext).
// ===========================================================================
const ParseContext = extern struct {
    pTokenizer: ?*sqlite3_tokenizer, // Tokenizer module
    iLangid: c_int, // Language id used with tokenizer
    azCol: ?[*]?[*:0]const u8, // Array of column names for fts3 table
    bFts4: c_int, // True to allow FTS4-only syntax
    nCol: c_int, // Number of entries in azCol[]
    iDefaultCol: c_int, // Default column to query
    isNot: c_int, // True if getNextNode() sees a unary -
    pCtx: ?*sqlite3_context, // Write error message here
    nNest: c_int, // Number of nested brackets
};

// ===========================================================================
// Helpers
// ===========================================================================

/// Equivalent of the standard isspace(), safe for any char value.
fn fts3isspace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0b or c == 0x0c;
}

/// Allocate nByte bytes, zero them, and return a pointer. NULL on OOM.
pub export fn sqlite3Fts3MallocZero(nByte: i64) callconv(.c) ?*anyopaque {
    const pRet = sqlite3_malloc64(@intCast(nByte));
    if (pRet) |p| {
        _ = memset(p, 0, @intCast(nByte));
    }
    return pRet;
}

/// Open a tokenizer cursor for buffer z[0..n] with language id iLangid.
pub export fn sqlite3Fts3OpenTokenizer(
    pTokenizer: *sqlite3_tokenizer,
    iLangid: c_int,
    z: [*]const u8,
    n: c_int,
    ppCsr: *?*sqlite3_tokenizer_cursor,
) callconv(.c) c_int {
    const pModule = pTokenizer.pModule.?;
    var pCsr: ?*sqlite3_tokenizer_cursor = null;

    var rc = pModule.xOpen.?(pTokenizer, z, n, &pCsr);
    // assert( rc==SQLITE_OK || pCsr==0 );
    if (rc == SQLITE_OK) {
        pCsr.?.pTokenizer = pTokenizer;
        if (pModule.iVersion >= 1) {
            rc = pModule.xLanguageid.?(pCsr.?, iLangid);
            if (rc != SQLITE_OK) {
                _ = pModule.xClose.?(pCsr.?);
                pCsr = null;
            }
        }
    }
    ppCsr.* = pCsr;
    return rc;
}

/// Search z[0..n] for a '"' (or '(' / ')' when parentheses enabled). Returns the
/// index of the first such char, or -1 if none.
fn findBarredChar(z: [*]const u8, n: c_int) c_int {
    const paren = enableParen();
    var ii: c_int = 0;
    while (ii < n) : (ii += 1) {
        const c = z[@intCast(ii)];
        if (c == '"' or (paren and (c == '(' or c == ')'))) {
            return ii;
        }
    }
    return -1;
}

/// Extract the next token from z[0..n], producing an FTSQUERY_PHRASE node of one
/// token. *ppExpr is set to 0 at end of buffer. *pnConsumed = bytes consumed.
fn getNextToken(
    pParse: *ParseContext,
    iCol: c_int,
    z: [*]const u8,
    n: c_int,
    ppExpr: *?*Fts3Expr,
    pnConsumed: *c_int,
) c_int {
    const pTokenizer = pParse.pTokenizer.?;
    const pModule = pTokenizer.pModule.?;
    var pCursor: ?*sqlite3_tokenizer_cursor = undefined;
    var pRet: ?*Fts3Expr = null;

    pnConsumed.* = n;
    var rc = sqlite3Fts3OpenTokenizer(pTokenizer, pParse.iLangid, z, n, &pCursor);
    if (rc == SQLITE_OK) {
        var zToken: ?[*]const u8 = undefined;
        var nToken: c_int = 0;
        var iStart: c_int = 0;
        var iEnd: c_int = 0;
        var iPosition: c_int = 0;

        rc = pModule.xNext.?(pCursor.?, &zToken, &nToken, &iStart, &iEnd, &iPosition);
        if (rc == SQLITE_OK) {
            // Check the tokenization did not gobble up any " (or paren) chars.
            const iBarred = findBarredChar(z, iEnd);
            if (iBarred >= 0) {
                _ = pModule.xClose.?(pCursor.?);
                return getNextToken(pParse, iCol, z, iBarred, ppExpr, pnConsumed);
            }

            const nByte: i64 = @as(i64, @intCast(@sizeOf(Fts3Expr))) + SZ_FTS3PHRASE(1) + nToken;
            pRet = @ptrCast(@alignCast(sqlite3Fts3MallocZero(nByte)));
            if (pRet == null) {
                rc = SQLITE_NOMEM;
            } else {
                const p = pRet.?;
                p.eType = FTSQUERY_PHRASE;
                // pPhrase = (Fts3Phrase *)&pRet[1]
                const pPhrase: *Fts3Phrase = @ptrCast(@alignCast(@as([*]Fts3Expr, @ptrCast(p)) + 1));
                p.pPhrase = pPhrase;
                pPhrase.nToken = 1;
                pPhrase.iColumn = iCol;
                const tok0 = phraseToken(pPhrase, 0);
                tok0.n = nToken;
                // aToken[0].z = (char*)&aToken[1]
                tok0.z = @ptrCast(phraseToken(pPhrase, 1));
                _ = memcpy(tok0.z, zToken, @intCast(nToken));

                if (iEnd < n and z[@intCast(iEnd)] == '*') {
                    tok0.isPrefix = 1;
                    iEnd += 1;
                }

                while (true) {
                    if (!enableParen() and iStart > 0 and z[@intCast(iStart - 1)] == '-') {
                        pParse.isNot = 1;
                        iStart -= 1;
                    } else if (pParse.bFts4 != 0 and iStart > 0 and z[@intCast(iStart - 1)] == '^') {
                        tok0.bFirst = 1;
                        iStart -= 1;
                    } else {
                        break;
                    }
                }
            }
            pnConsumed.* = iEnd;
        } else if (n != 0 and rc == SQLITE_DONE) {
            const iBarred = findBarredChar(z, n);
            if (iBarred >= 0) {
                pnConsumed.* = iBarred;
            }
            rc = SQLITE_OK;
        }

        _ = pModule.xClose.?(pCursor.?);
    }

    ppExpr.* = pRet;
    return rc;
}

/// Enlarge a memory allocation. Frees the original on OOM.
fn fts3ReallocOrFree(pOrig: ?*anyopaque, nNew: i64) ?*anyopaque {
    const pRet = sqlite3_realloc64(pOrig, @intCast(nNew));
    if (pRet == null) {
        sqlite3_free(pOrig);
    }
    return pRet;
}

/// Tokenize the entire buffer zInput[0..nInput] (a quoted string) into a single
/// FTSQUERY_PHRASE node containing all tokens.
fn getNextString(
    pParse: *ParseContext,
    zInput: [*]const u8,
    nInput: c_int,
    ppExpr: *?*Fts3Expr,
) c_int {
    const pTokenizer = pParse.pTokenizer.?;
    const pModule = pTokenizer.pModule.?;
    var p: ?*Fts3Expr = null;
    var pCursor: ?*sqlite3_tokenizer_cursor = null;
    var zTemp: ?[*]u8 = null;
    var nTemp: i64 = 0;

    const nSpace: i64 = @as(i64, @intCast(@sizeOf(Fts3Expr))) + SZ_FTS3PHRASE(1);
    var nToken: c_int = 0;

    var rc = sqlite3Fts3OpenTokenizer(pTokenizer, pParse.iLangid, zInput, nInput, &pCursor);
    if (rc == SQLITE_OK) {
        var ii: c_int = 0;
        while (rc == SQLITE_OK) : (ii += 1) {
            var zByte: ?[*]const u8 = undefined;
            var nByte: c_int = 0;
            var iBegin: c_int = 0;
            var iEnd: c_int = 0;
            var iPos: c_int = 0;
            rc = pModule.xNext.?(pCursor.?, &zByte, &nByte, &iBegin, &iEnd, &iPos);
            if (rc == SQLITE_OK) {
                p = @ptrCast(@alignCast(fts3ReallocOrFree(p, nSpace + ii * @as(i64, @intCast(@sizeOf(Fts3PhraseToken))))));
                zTemp = @ptrCast(fts3ReallocOrFree(zTemp, nTemp + nByte));
                if (zTemp == null or p == null) {
                    rc = SQLITE_NOMEM;
                    break;
                }

                // assert( nToken==ii );
                // pToken = &((Fts3Phrase *)(&p[1]))->aToken[ii]
                const pPhrase: *Fts3Phrase = @ptrCast(@alignCast(@as([*]Fts3Expr, @ptrCast(p.?)) + 1));
                const pToken = phraseToken(pPhrase, ii);
                _ = memset(pToken, 0, @sizeOf(Fts3PhraseToken));

                _ = memcpy(zTemp.? + @as(usize, @intCast(nTemp)), zByte, @intCast(nByte));
                nTemp += nByte;

                pToken.n = nByte;
                pToken.isPrefix = @intFromBool(iEnd < nInput and zInput[@intCast(iEnd)] == '*');
                pToken.bFirst = @intFromBool(iBegin > 0 and zInput[@intCast(iBegin - 1)] == '^');
                nToken = ii + 1;
            }
        }
    }

    if (rc == SQLITE_DONE) {
        p = @ptrCast(@alignCast(fts3ReallocOrFree(p, nSpace + nToken * @as(i64, @intCast(@sizeOf(Fts3PhraseToken))) + nTemp)));
        if (p == null) {
            rc = SQLITE_NOMEM;
        } else {
            const pp = p.?;
            const pPhrase: *Fts3Phrase = @ptrCast(@alignCast(@as([*]Fts3Expr, @ptrCast(pp)) + 1));
            // memset(p, 0, (char *)&(((Fts3Phrase*)&p[1])->aToken[0]) - (char *)p)
            const zeroLen: usize = @as(usize, @intCast(@sizeOf(Fts3Expr))) + @offsetOf(Fts3Phrase, "aToken");
            _ = memset(pp, 0, zeroLen);
            pp.eType = FTSQUERY_PHRASE;
            pp.pPhrase = pPhrase;
            pPhrase.iColumn = pParse.iDefaultCol;
            pPhrase.nToken = nToken;

            // zBuf = (char *)&p->pPhrase->aToken[nToken]
            var zBuf: [*]u8 = @ptrCast(phraseToken(pPhrase, nToken));
            // assert( nTemp==0 || zTemp );
            if (zTemp) |zt| {
                _ = memcpy(zBuf, zt, @intCast(nTemp));
            }

            var jj: c_int = 0;
            while (jj < pPhrase.nToken) : (jj += 1) {
                const tok = phraseToken(pPhrase, jj);
                tok.z = zBuf;
                zBuf += @intCast(tok.n);
            }
            rc = SQLITE_OK;
        }
    }

    if (pCursor) |c| {
        _ = pModule.xClose.?(c);
    }
    sqlite3_free(zTemp);
    if (rc != SQLITE_OK) {
        sqlite3_free(p);
        p = null;
    }
    ppExpr.* = p;
    return rc;
}

const Fts3Keyword = extern struct {
    z: [*:0]const u8, // Keyword text (address-is-data)
    n: u8, // Length of the keyword
    parenOnly: u8, // Only valid in paren mode
    eType: u8, // Keyword code
};

const aKeyword = [_]Fts3Keyword{
    .{ .z = "OR", .n = 2, .parenOnly = 0, .eType = @intCast(FTSQUERY_OR) },
    .{ .z = "AND", .n = 3, .parenOnly = 1, .eType = @intCast(FTSQUERY_AND) },
    .{ .z = "NOT", .n = 3, .parenOnly = 1, .eType = @intCast(FTSQUERY_NOT) },
    .{ .z = "NEAR", .n = 4, .parenOnly = 0, .eType = @intCast(FTSQUERY_NEAR) },
};

/// Read the next node from z[0..n]. *ppExpr set to an allocated node, or 0 at
/// end of buffer (SQLITE_DONE). Returns SQLITE_OK / NOMEM / ERROR.
fn getNextNode(
    pParse: *ParseContext,
    z: [*]const u8,
    n: c_int,
    ppExpr: *?*Fts3Expr,
    pnConsumed: *c_int,
) c_int {
    var ii: c_int = undefined;
    var iCol: c_int = undefined;
    var iColLen: c_int = undefined;
    var rc: c_int = undefined;
    var pRet: ?*Fts3Expr = null;

    var zInput: [*]const u8 = z;
    var nInput: c_int = n;

    pParse.isNot = 0;

    // Skip leading whitespace.
    while (nInput > 0 and fts3isspace(zInput[0])) {
        nInput -= 1;
        zInput += 1;
    }
    if (nInput == 0) {
        return SQLITE_DONE;
    }

    // See if we are dealing with a keyword.
    const paren = enableParen();
    ii = 0;
    while (ii < aKeyword.len) : (ii += 1) {
        const pKey = &aKeyword[@intCast(ii)];

        // (pKey->parenOnly & ~sqlite3_fts3_enable_parentheses)!=0  => skip
        const enMask: u8 = if (paren) 1 else 0;
        if ((pKey.parenOnly & ~enMask) != 0) {
            continue;
        }

        if (nInput >= pKey.n and 0 == memcmp(zInput, pKey.z, pKey.n)) {
            var nNear: c_int = SQLITE_FTS3_DEFAULT_NEAR_PARAM;
            var nKey: c_int = pKey.n;

            // If this is "NEAR", check for an explicit nearness "/<digits>".
            if (pKey.eType == @as(u8, @intCast(FTSQUERY_NEAR))) {
                // assert( nKey==4 );
                if (zInput[4] == '/' and zInput[5] >= '0' and zInput[5] <= '9') {
                    nKey += 1 + sqlite3Fts3ReadInt(@ptrCast(zInput + @as(usize, @intCast(nKey + 1))), &nNear);
                    if (nNear >= 1000000000) nNear = 1000000000;
                }
            }

            // For this to be a keyword, the next byte must be whitespace,
            // '(' / ')' / '"', or EOF.
            const cNext = zInput[@intCast(nKey)];
            if (fts3isspace(cNext) or cNext == '"' or cNext == '(' or cNext == ')' or cNext == 0) {
                pRet = @ptrCast(@alignCast(sqlite3Fts3MallocZero(@sizeOf(Fts3Expr))));
                if (pRet == null) {
                    return SQLITE_NOMEM;
                }
                pRet.?.eType = pKey.eType;
                pRet.?.nNear = nNear;
                ppExpr.* = pRet;
                pnConsumed.* = @intCast((@intFromPtr(zInput) - @intFromPtr(z)) + @as(usize, @intCast(nKey)));
                return SQLITE_OK;
            }
            // Not actually a keyword (e.g. "ORacle"). Continue.
        }
    }

    // See if we are dealing with a quoted phrase.
    if (zInput[0] == '"') {
        ii = 1;
        while (ii < nInput and zInput[@intCast(ii)] != '"') : (ii += 1) {}
        pnConsumed.* = @intCast((@intFromPtr(zInput) - @intFromPtr(z)) + @as(usize, @intCast(ii + 1)));
        if (ii == nInput) {
            return SQLITE_ERROR;
        }
        return getNextString(pParse, zInput + 1, ii - 1, ppExpr);
    }

    if (paren) {
        if (zInput[0] == '(') {
            var nConsumed: c_int = 0;
            pParse.nNest += 1;
            // SQLITE_MAX_EXPR_DEPTH is not defined in this build => limit 1000.
            if (pParse.nNest > 1000) return SQLITE_ERROR;
            rc = fts3ExprParse(pParse, zInput + 1, nInput - 1, ppExpr, &nConsumed);
            pnConsumed.* = @as(c_int, @intCast(@intFromPtr(zInput) - @intFromPtr(z))) + 1 + nConsumed;
            return rc;
        } else if (zInput[0] == ')') {
            pParse.nNest -= 1;
            pnConsumed.* = @intCast((@intFromPtr(zInput) - @intFromPtr(z)) + 1);
            ppExpr.* = null;
            return SQLITE_DONE;
        }
    }

    // Regular token. Figure out any explicit column specifier "col:".
    iCol = pParse.iDefaultCol;
    iColLen = 0;
    ii = 0;
    while (ii < pParse.nCol) : (ii += 1) {
        const zStr = pParse.azCol.?[@intCast(ii)].?;
        const nStr: c_int = @intCast(strlen(zStr));
        if (nInput > nStr and zInput[@intCast(nStr)] == ':' and
            sqlite3_strnicmp(zStr, @ptrCast(zInput), nStr) == 0)
        {
            iCol = ii;
            iColLen = @intCast((@intFromPtr(zInput) - @intFromPtr(z)) + @as(usize, @intCast(nStr)) + 1);
            break;
        }
    }
    rc = getNextToken(pParse, iCol, z + @as(usize, @intCast(iColLen)), n - iColLen, ppExpr, pnConsumed);
    pnConsumed.* += iColLen;
    return rc;
}

/// Precedence of a binary-operator node. Lower = binds tighter.
fn opPrecedence(p: *Fts3Expr) c_int {
    // assert( p->eType!=FTSQUERY_PHRASE );
    if (enableParen()) {
        return p.eType;
    } else if (p.eType == FTSQUERY_NEAR) {
        return 1;
    } else if (p.eType == FTSQUERY_OR) {
        return 2;
    }
    // assert( p->eType==FTSQUERY_AND );
    return 3;
}

/// Insert binary operator pNew into the tree rooted at *ppHead, splicing it in
/// per relative precedence of pNew vs the path up from pPrev.
fn insertBinaryOperator(
    ppHead: *?*Fts3Expr,
    pPrev: *Fts3Expr,
    pNew: *Fts3Expr,
) void {
    var pSplit: *Fts3Expr = pPrev;
    while (pSplit.pParent != null and opPrecedence(pSplit.pParent.?) <= opPrecedence(pNew)) {
        pSplit = pSplit.pParent.?;
    }

    if (pSplit.pParent) |parent| {
        // assert( pSplit->pParent->pRight==pSplit );
        parent.pRight = pNew;
        pNew.pParent = parent;
    } else {
        ppHead.* = pNew;
    }
    pNew.pLeft = pSplit;
    pSplit.pParent = pNew;
}

/// Parse the fts3 query in z[0..n]. Returns at end of buffer or an unmatched ')'.
fn fts3ExprParse(
    pParse: *ParseContext,
    z: [*]const u8,
    n: c_int,
    ppExpr: *?*Fts3Expr,
    pnConsumed: *c_int,
) c_int {
    var pRet: ?*Fts3Expr = null;
    var pPrev: ?*Fts3Expr = null;
    var pNotBranch: ?*Fts3Expr = null; // Only used in legacy parse mode
    var nIn: c_int = n;
    var zIn: [*]const u8 = z;
    var rc: c_int = SQLITE_OK;
    var isRequirePhrase: c_int = 1;

    while (rc == SQLITE_OK) {
        var p: ?*Fts3Expr = null;
        var nByte: c_int = 0;

        rc = getNextNode(pParse, zIn, nIn, &p, &nByte);
        // assert( nByte>0 || (rc!=SQLITE_OK && p==0) );
        if (rc == SQLITE_OK) {
            if (p) |pp| {
                var isPhrase: bool = undefined;

                if (!enableParen() and pp.eType == FTSQUERY_PHRASE and pParse.isNot != 0) {
                    // Create an implicit NOT operator.
                    const pNot: ?*Fts3Expr = @ptrCast(@alignCast(sqlite3Fts3MallocZero(@sizeOf(Fts3Expr))));
                    if (pNot == null) {
                        sqlite3Fts3ExprFree(pp);
                        rc = SQLITE_NOMEM;
                        break;
                    }
                    pNot.?.eType = FTSQUERY_NOT;
                    pNot.?.pRight = pp;
                    pp.pParent = pNot;
                    if (pNotBranch) |nb| {
                        pNot.?.pLeft = nb;
                        nb.pParent = pNot;
                    }
                    pNotBranch = pNot;
                    p = pPrev;
                } else {
                    const eType = pp.eType;
                    isPhrase = (eType == FTSQUERY_PHRASE or pp.pLeft != null);

                    // A phrase or bracketed expression is required here.
                    if (!isPhrase and isRequirePhrase != 0) {
                        sqlite3Fts3ExprFree(pp);
                        rc = SQLITE_ERROR;
                        break;
                    }

                    if (isPhrase and isRequirePhrase == 0) {
                        // Insert an implicit AND operator.
                        // assert( pRet && pPrev );
                        const pAnd: ?*Fts3Expr = @ptrCast(@alignCast(sqlite3Fts3MallocZero(@sizeOf(Fts3Expr))));
                        if (pAnd == null) {
                            sqlite3Fts3ExprFree(pp);
                            rc = SQLITE_NOMEM;
                            break;
                        }
                        pAnd.?.eType = FTSQUERY_AND;
                        insertBinaryOperator(&pRet, pPrev.?, pAnd.?);
                        pPrev = pAnd;
                    }

                    // Catch a NEAR with a non-phrase operand on either side.
                    if (pPrev) |pv| {
                        if ((eType == FTSQUERY_NEAR and !isPhrase and pv.eType != FTSQUERY_PHRASE) or
                            (eType != FTSQUERY_PHRASE and isPhrase and pv.eType == FTSQUERY_NEAR))
                        {
                            sqlite3Fts3ExprFree(pp);
                            rc = SQLITE_ERROR;
                            break;
                        }
                    }

                    if (isPhrase) {
                        if (pRet != null) {
                            // assert( pPrev && pPrev->pLeft && pPrev->pRight==0 );
                            pPrev.?.pRight = pp;
                            pp.pParent = pPrev;
                        } else {
                            pRet = pp;
                        }
                    } else {
                        insertBinaryOperator(&pRet, pPrev.?, pp);
                    }
                    isRequirePhrase = @intFromBool(!isPhrase);
                }
                pPrev = p;
            }
            // assert( nByte>0 );
        }
        // assert( rc!=SQLITE_OK || (nByte>0 && nByte<=nIn) );
        nIn -= nByte;
        zIn += @intCast(nByte);
    }

    if (rc == SQLITE_DONE and pRet != null and isRequirePhrase != 0) {
        rc = SQLITE_ERROR;
    }

    if (rc == SQLITE_DONE) {
        rc = SQLITE_OK;
        if (!enableParen() and pNotBranch != null) {
            if (pRet == null) {
                rc = SQLITE_ERROR;
            } else {
                var pIter: *Fts3Expr = pNotBranch.?;
                while (pIter.pLeft) |l| {
                    pIter = l;
                }
                pIter.pLeft = pRet;
                pRet.?.pParent = pIter;
                pRet = pNotBranch;
            }
        }
    }
    pnConsumed.* = n - nIn;

    if (rc != SQLITE_OK) {
        sqlite3Fts3ExprFree(pRet);
        sqlite3Fts3ExprFree(pNotBranch);
        pRet = null;
    }
    ppExpr.* = pRet;
    return rc;
}

/// SQLITE_ERROR/SQLITE_TOOBIG if the tree depth exceeds nMaxDepth.
fn fts3ExprCheckDepth(p: ?*Fts3Expr, nMaxDepth: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (p) |pp| {
        if (nMaxDepth < 0) {
            rc = SQLITE_TOOBIG;
        } else {
            rc = fts3ExprCheckDepth(pp.pLeft, nMaxDepth - 1);
            if (rc == SQLITE_OK) {
                rc = fts3ExprCheckDepth(pp.pRight, nMaxDepth - 1);
            }
        }
    }
    return rc;
}

/// Rebalance the tree at (*pp) into an equivalent, more balanced form, in place.
/// On error, frees (*pp). nMaxDepth bounds the balanced sub-tree depth.
fn fts3ExprBalance(pp: *?*Fts3Expr, nMaxDepth: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    var pRoot: ?*Fts3Expr = pp.*;
    var pFree: ?*Fts3Expr = null; // List of free nodes, linked by pParent.
    const eType = pRoot.?.eType;

    if (nMaxDepth == 0) {
        rc = SQLITE_ERROR;
    }

    if (rc == SQLITE_OK) {
        if (eType == FTSQUERY_AND or eType == FTSQUERY_OR) {
            var apLeaf: ?[*]?*Fts3Expr = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @intCast(@sizeOf(?*Fts3Expr))) * @as(u64, @intCast(nMaxDepth)))));
            if (apLeaf == null) {
                rc = SQLITE_NOMEM;
            } else {
                _ = memset(@ptrCast(apLeaf), 0, @as(usize, @intCast(@sizeOf(?*Fts3Expr))) * @as(usize, @intCast(nMaxDepth)));
            }

            if (rc == SQLITE_OK) {
                var i: c_int = undefined;
                var p: ?*Fts3Expr = undefined;

                // Set p to the left-most leaf in the tree of eType nodes.
                p = pRoot;
                while (p.?.eType == eType) : (p = p.?.pLeft) {
                    // assert( p->pParent==0 || p->pParent->pLeft==p );
                    // assert( p->pLeft && p->pRight );
                }

                // Once per leaf in the tree of eType nodes.
                while (true) {
                    var iLvl: c_int = undefined;
                    const pParent: ?*Fts3Expr = p.?.pParent;

                    // assert( pParent==0 || pParent->pLeft==p );
                    p.?.pParent = null;
                    if (pParent) |par| {
                        par.pLeft = null;
                    } else {
                        pRoot = null;
                    }
                    rc = fts3ExprBalance(&p, nMaxDepth - 1);
                    if (rc != SQLITE_OK) break;

                    iLvl = 0;
                    while (p != null and iLvl < nMaxDepth) : (iLvl += 1) {
                        if (apLeaf.?[@intCast(iLvl)] == null) {
                            apLeaf.?[@intCast(iLvl)] = p;
                            p = null;
                        } else {
                            // assert( pFree );
                            pFree.?.pLeft = apLeaf.?[@intCast(iLvl)];
                            pFree.?.pRight = p;
                            pFree.?.pLeft.?.pParent = pFree;
                            pFree.?.pRight.?.pParent = pFree;

                            p = pFree;
                            pFree = pFree.?.pParent;
                            p.?.pParent = null;
                            apLeaf.?[@intCast(iLvl)] = null;
                        }
                    }
                    if (p != null) {
                        sqlite3Fts3ExprFree(p);
                        rc = SQLITE_TOOBIG;
                        break;
                    }

                    // If that was the last leaf, break.
                    if (pParent == null) break;

                    // Set p to the next leaf in the tree of eType nodes.
                    p = pParent.?.pRight;
                    while (p.?.eType == eType) : (p = p.?.pLeft) {}

                    // Remove pParent from the original tree.
                    // assert( pParent->pParent==0 || pParent->pParent->pLeft==pParent );
                    pParent.?.pRight.?.pParent = pParent.?.pParent;
                    if (pParent.?.pParent) |gp| {
                        gp.pLeft = pParent.?.pRight;
                    } else {
                        // assert( pParent==pRoot );
                        pRoot = pParent.?.pRight;
                    }

                    // Link pParent into the free node list.
                    pParent.?.pParent = pFree;
                    pFree = pParent;
                }

                if (rc == SQLITE_OK) {
                    p = null;
                    i = 0;
                    while (i < nMaxDepth) : (i += 1) {
                        if (apLeaf.?[@intCast(i)]) |leaf| {
                            if (p == null) {
                                p = leaf;
                                p.?.pParent = null;
                            } else {
                                // assert( pFree!=0 );
                                pFree.?.pRight = p;
                                pFree.?.pLeft = leaf;
                                pFree.?.pLeft.?.pParent = pFree;
                                pFree.?.pRight.?.pParent = pFree;

                                p = pFree;
                                pFree = pFree.?.pParent;
                                p.?.pParent = null;
                            }
                        }
                    }
                    pRoot = p;
                } else {
                    // Error: delete apLeaf[] contents and the pFree list.
                    i = 0;
                    while (i < nMaxDepth) : (i += 1) {
                        sqlite3Fts3ExprFree(apLeaf.?[@intCast(i)]);
                    }
                    while (pFree) |pDel| {
                        pFree = pDel.pParent;
                        sqlite3_free(pDel);
                    }
                }

                // assert( pFree==0 );
                sqlite3_free(@ptrCast(apLeaf));
            }
        } else if (eType == FTSQUERY_NOT) {
            var pLeft: ?*Fts3Expr = pRoot.?.pLeft;
            var pRight: ?*Fts3Expr = pRoot.?.pRight;

            pRoot.?.pLeft = null;
            pRoot.?.pRight = null;
            pLeft.?.pParent = null;
            pRight.?.pParent = null;

            rc = fts3ExprBalance(&pLeft, nMaxDepth - 1);
            if (rc == SQLITE_OK) {
                rc = fts3ExprBalance(&pRight, nMaxDepth - 1);
            }

            if (rc != SQLITE_OK) {
                sqlite3Fts3ExprFree(pRight);
                sqlite3Fts3ExprFree(pLeft);
            } else {
                // assert( pLeft && pRight );
                pRoot.?.pLeft = pLeft;
                pLeft.?.pParent = pRoot;
                pRoot.?.pRight = pRight;
                pRight.?.pParent = pRoot;
            }
        }
    }

    if (rc != SQLITE_OK) {
        sqlite3Fts3ExprFree(pRoot);
        pRoot = null;
    }
    pp.* = pRoot;
    return rc;
}

/// Like sqlite3Fts3ExprParse but: no rebalance, no depth check, and *ppExpr may
/// be left non-null even on failure (caller must free it).
fn fts3ExprParseUnbalanced(
    pTokenizer: *sqlite3_tokenizer,
    iLangid: c_int,
    azCol: ?[*]?[*:0]const u8,
    bFts4: c_int,
    nCol: c_int,
    iDefaultCol: c_int,
    z: ?[*:0]const u8,
    n_in: c_int,
    ppExpr: *?*Fts3Expr,
) c_int {
    var nParsed: c_int = undefined;
    var n: c_int = n_in;
    var sParse: ParseContext = std.mem.zeroes(ParseContext);

    sParse.pTokenizer = pTokenizer;
    sParse.iLangid = iLangid;
    sParse.azCol = azCol;
    sParse.nCol = nCol;
    sParse.iDefaultCol = iDefaultCol;
    sParse.bFts4 = bFts4;
    if (z == null) {
        ppExpr.* = null;
        return SQLITE_OK;
    }
    if (n < 0) {
        n = @intCast(strlen(z.?));
    }
    const rc = fts3ExprParse(&sParse, z.?, n, ppExpr, &nParsed);
    // assert( rc==SQLITE_OK || *ppExpr==0 );

    // Check for mismatched parenthesis.
    if (rc == SQLITE_OK and sParse.nNest != 0) {
        return SQLITE_ERROR;
    }

    return rc;
}

/// Parse the fts3 query expression in z[0..n] into a tree of Fts3Expr nodes.
/// On success *ppExpr is the root and SQLITE_OK is returned. n<0 => z is a
/// nul-terminated string. Rebalances and depth-checks the tree.
pub export fn sqlite3Fts3ExprParse(
    pTokenizer: *sqlite3_tokenizer,
    iLangid: c_int,
    azCol: ?[*]?[*:0]const u8,
    bFts4: c_int,
    nCol: c_int,
    iDefaultCol: c_int,
    z: ?[*:0]const u8,
    n: c_int,
    ppExpr: *?*Fts3Expr,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var rc = fts3ExprParseUnbalanced(
        pTokenizer,
        iLangid,
        azCol,
        bFts4,
        nCol,
        iDefaultCol,
        z,
        n,
        ppExpr,
    );

    // Rebalance the expression, then check its depth.
    if (rc == SQLITE_OK and ppExpr.* != null) {
        rc = fts3ExprBalance(ppExpr, SQLITE_FTS3_MAX_EXPR_DEPTH);
        if (rc == SQLITE_OK) {
            rc = fts3ExprCheckDepth(ppExpr.*, SQLITE_FTS3_MAX_EXPR_DEPTH);
        }
    }

    if (rc != SQLITE_OK) {
        sqlite3Fts3ExprFree(ppExpr.*);
        ppExpr.* = null;
        if (rc == SQLITE_TOOBIG) {
            sqlite3Fts3ErrMsg(
                pzErr,
                "FTS expression tree is too large (maximum depth %d)",
                SQLITE_FTS3_MAX_EXPR_DEPTH,
            );
            rc = SQLITE_ERROR;
        } else if (rc == SQLITE_ERROR) {
            sqlite3Fts3ErrMsg(pzErr, "malformed MATCH expression: [%s]", z orelse @as([*:0]const u8, ""));
        }
    }

    return rc;
}

/// Free a single node of an expression tree.
fn fts3FreeExprNode(p: *Fts3Expr) void {
    // assert( p->eType==FTSQUERY_PHRASE || p->pPhrase==0 );
    sqlite3Fts3EvalPhraseCleanup(p.pPhrase);
    sqlite3_free(p.aMI);
    sqlite3_free(p);
}

/// Free a parsed fts3 query expression. Iterative (not recursive) to avoid stack
/// overflow on deep trees.
pub export fn sqlite3Fts3ExprFree(pDel: ?*Fts3Expr) callconv(.c) void {
    // assert( pDel==0 || pDel->pParent==0 );
    var p: ?*Fts3Expr = pDel;
    while (p) |pp| {
        if (pp.pLeft == null and pp.pRight == null) break;
        // assert( p->pParent==0 || p==p->pParent->pRight || p==p->pParent->pLeft );
        p = if (pp.pLeft) |l| l else pp.pRight;
    }
    while (p) |pp| {
        const pParent = pp.pParent;
        fts3FreeExprNode(pp);
        if (pParent != null and pp == pParent.?.pLeft and pParent.?.pRight != null) {
            var q: ?*Fts3Expr = pParent.?.pRight;
            while (q) |qq| {
                if (qq.pLeft == null and qq.pRight == null) break;
                // assert( q==q->pParent->pRight || q==q->pParent->pLeft );
                q = if (qq.pLeft) |l| l else qq.pRight;
            }
            p = q;
        } else {
            p = pParent;
        }
    }
}

// ===========================================================================
// Test code (SQLITE_TEST only). Gated on config.sqlite_test.
// ===========================================================================

/// Text representation of an expression tree. Buffer from sqlite3_malloc;
/// caller frees. If zBuf is non-null it is prepended (and freed). NULL on OOM.
fn exprToString(pExpr: ?*Fts3Expr, zBufIn: ?[*:0]u8) ?[*:0]u8 {
    var zBuf = zBufIn;
    if (pExpr == null) {
        return sqlite3_mprintf("");
    }
    const pe = pExpr.?;
    switch (pe.eType) {
        FTSQUERY_PHRASE => {
            const pPhrase = pe.pPhrase.?;
            zBuf = sqlite3_mprintf("%zPHRASE %d 0", zBuf orelse @as([*:0]u8, @ptrCast(@constCast(""))), pPhrase.iColumn);
            var i: c_int = 0;
            while (zBuf != null and i < pPhrase.nToken) : (i += 1) {
                const tok = phraseToken(pPhrase, i);
                zBuf = sqlite3_mprintf(
                    "%z %.*s%s",
                    zBuf.?,
                    tok.n,
                    tok.z,
                    @as([*:0]const u8, if (tok.isPrefix != 0) "+" else ""),
                );
            }
            return zBuf;
        },
        FTSQUERY_NEAR => {
            zBuf = sqlite3_mprintf("%zNEAR/%d ", zBuf orelse @as([*:0]u8, @ptrCast(@constCast(""))), pe.nNear);
        },
        FTSQUERY_NOT => {
            zBuf = sqlite3_mprintf("%zNOT ", zBuf orelse @as([*:0]u8, @ptrCast(@constCast(""))));
        },
        FTSQUERY_AND => {
            zBuf = sqlite3_mprintf("%zAND ", zBuf orelse @as([*:0]u8, @ptrCast(@constCast(""))));
        },
        FTSQUERY_OR => {
            zBuf = sqlite3_mprintf("%zOR ", zBuf orelse @as([*:0]u8, @ptrCast(@constCast(""))));
        },
        else => {},
    }

    if (zBuf != null) zBuf = sqlite3_mprintf("%z{", zBuf.?);
    if (zBuf != null) zBuf = exprToString(pe.pLeft, zBuf);
    if (zBuf != null) zBuf = sqlite3_mprintf("%z} {", zBuf.?);
    if (zBuf != null) zBuf = exprToString(pe.pRight, zBuf);
    if (zBuf != null) zBuf = sqlite3_mprintf("%z}", zBuf.?);

    return zBuf;
}

fn fts3ExprTestCommon(
    bRebalance: c_int,
    context: ?*sqlite3_context,
    argc: c_int,
    argv: [*]?*sqlite3_value,
) void {
    var pTokenizer: ?*sqlite3_tokenizer = null;
    var rc: c_int = undefined;
    var azCol: ?[*]?[*:0]const u8 = null;
    var pExpr: ?*Fts3Expr = undefined;
    var zBuf: ?[*:0]u8 = null;
    const pHash: *Fts3Hash = @ptrCast(sqlite3_user_data(context).?);
    var zErr: ?[*:0]u8 = null;

    if (argc < 3) {
        sqlite3_result_error(context, "Usage: fts3_exprtest(tokenizer, expr, col1, ...", -1);
        return;
    }

    const zTokenizer = sqlite3_value_text(argv[0]).?;
    rc = sqlite3Fts3InitTokenizer(pHash, zTokenizer, &pTokenizer, &zErr);
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_NOMEM) {
            sqlite3_result_error_nomem(context);
        } else {
            sqlite3_result_error(context, zErr.?, -1);
        }
        sqlite3_free(zErr);
        return;
    }

    const zExpr = sqlite3_value_text(argv[1]);
    const nExpr = sqlite3_value_bytes(argv[1]);
    const nCol = argc - 2;
    azCol = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @intCast(nCol)) * @sizeOf(?[*:0]const u8))));
    if (azCol == null) {
        sqlite3_result_error_nomem(context);
        // goto exprtest_out
        if (pTokenizer) |tk| {
            rc = tk.pModule.?.xDestroy.?(tk);
        }
        sqlite3_free(@ptrCast(azCol));
        return;
    }
    var ii: c_int = 0;
    while (ii < nCol) : (ii += 1) {
        azCol.?[@intCast(ii)] = sqlite3_value_text(argv[@intCast(ii + 2)]);
    }

    if (bRebalance != 0) {
        var zDummy: ?[*:0]u8 = null;
        rc = sqlite3Fts3ExprParse(pTokenizer.?, 0, azCol, 0, nCol, nCol, zExpr, nExpr, &pExpr, &zDummy);
        // assert( rc==SQLITE_OK || pExpr==0 );
        sqlite3_free(zDummy);
    } else {
        rc = fts3ExprParseUnbalanced(pTokenizer.?, 0, azCol, 0, nCol, nCol, zExpr, nExpr, &pExpr);
    }

    if (rc != SQLITE_OK and rc != SQLITE_NOMEM) {
        sqlite3_result_error(context, "Error parsing expression", -1);
    } else if (rc == SQLITE_NOMEM or blk: {
        zBuf = exprToString(pExpr, null);
        break :blk zBuf == null;
    }) {
        sqlite3_result_error_nomem(context);
    } else {
        sqlite3_result_text(context, zBuf, -1, SQLITE_TRANSIENT);
        sqlite3_free(zBuf);
    }

    sqlite3Fts3ExprFree(pExpr);

    // exprtest_out:
    if (pTokenizer) |tk| {
        rc = tk.pModule.?.xDestroy.?(tk);
    }
    sqlite3_free(@ptrCast(azCol));
}

fn fts3ExprTest(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    fts3ExprTestCommon(0, context, argc, argv.?);
}
fn fts3ExprTestRebalance(context: ?*sqlite3_context, argc: c_int, argv: ?[*]?*sqlite3_value) callconv(.c) void {
    fts3ExprTestCommon(1, context, argc, argv.?);
}

/// Register the query-expression parser test functions fts3_exprtest() and
/// fts3_exprtest_rebalance() with database connection db. (SQLITE_TEST only.)
pub export fn sqlite3Fts3ExprInitTestInterface(db: ?*sqlite3, pHash: *Fts3Hash) callconv(.c) c_int {
    var rc = sqlite3_create_function(
        db,
        "fts3_exprtest",
        -1,
        SQLITE_UTF8,
        @ptrCast(pHash),
        fts3ExprTest,
        null,
        null,
    );
    if (rc == SQLITE_OK) {
        rc = sqlite3_create_function(
            db,
            "fts3_exprtest_rebalance",
            -1,
            SQLITE_UTF8,
            @ptrCast(pHash),
            fts3ExprTestRebalance,
            null,
            null,
        );
    }
    return rc;
}

// Reference the test-only exports so they are emitted only in test builds and
// elided otherwise (keeps non-test builds free of unused-symbol noise while
// guaranteeing the symbols exist for the testfixture build).
comptime {
    if (config.sqlite_test) {
        _ = &sqlite3Fts3ExprInitTestInterface;
        _ = &sqlite3_fts3_enable_parentheses;
    }
}
