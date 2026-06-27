//! Zig port of SQLite's FTS3 query-output functions (ext/fts3/fts3_snippet.c).
//!
//! Implements the user-visible auxiliary functions of FTS3/FTS4:
//!   * snippet()   -> sqlite3Fts3Snippet
//!   * offsets()   -> sqlite3Fts3Offsets
//!   * matchinfo() -> sqlite3Fts3Matchinfo
//! plus the phrase-tree walker sqlite3Fts3ExprIterate (declared in fts3Int.h
//! but *defined here*, used by the now-Zig fts3.zig / fts3_expr.zig), and the
//! MatchinfoBuffer lifecycle helper sqlite3Fts3MIBufferFree.
//!
//! Drop-in replacement for the C TU: it exports every non-static symbol the C
//! file defines, so the sibling fts3.zig / fts3_write.zig link against these.
//! Compiled because SQLITE_ENABLE_FTS3 is enabled.
//!
//! Exports:
//!   * sqlite3Fts3ExprIterate
//!   * sqlite3Fts3MIBufferFree
//!   * sqlite3Fts3Snippet
//!   * sqlite3Fts3Offsets
//!   * sqlite3Fts3Matchinfo
//!
//! ABI coupling
//! ------------
//! Fts3Table / Fts3Cursor / Fts3Expr / Fts3Phrase / Fts3Doclist /
//! sqlite3_tokenizer{,_module,_cursor} cross the boundary to/from fts3.zig,
//! fts3_write.zig and the still-C tokenizer TUs. Each is mirrored here as an
//! `extern struct` copied field-for-field from the sibling src/fts3.zig and
//! src/fts3_expr.zig. MatchinfoBuffer / StrBuffer / the snippet-iterator
//! structs are file-local. No tools/offsets.c entry is required: every shared
//! field touched is a leading, config-invariant field, and the Fts3Table
//! trailing testfixture-only fields are reproduced exactly with the same
//! config gates as fts3.zig.

const std = @import("std");
const config = @import("config");

// ---------------------------------------------------------------------------
// Result codes (sqlite3.h)
// ---------------------------------------------------------------------------
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_CORRUPT_VTAB: c_int = SQLITE_CORRUPT | (1 << 8);
const SQLITE_DONE: c_int = 101;

// sqlite3_column_type() return codes (sqlite3.h).
const SQLITE_NULL: c_int = 5;

// Destructor sentinels (sqlite3.h): SQLITE_STATIC==0, SQLITE_TRANSIENT==-1.
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;

// ---------------------------------------------------------------------------
// fts3Int.h constants
// ---------------------------------------------------------------------------
// Fts3Expr.eType values (fts3Int.h).
const FTSQUERY_NEAR: c_int = 1;
const FTSQUERY_NOT: c_int = 2;
const FTSQUERY_AND: c_int = 3;
const FTSQUERY_OR: c_int = 4;
const FTSQUERY_PHRASE: c_int = 5;

// Characters that may appear in the second argument to matchinfo() (fts3Int.h /
// the #defines at the top of fts3_snippet.c). These are *byte* values.
const FTS3_MATCHINFO_NPHRASE: u8 = 'p'; // 1 value
const FTS3_MATCHINFO_NCOL: u8 = 'c'; // 1 value
const FTS3_MATCHINFO_NDOC: u8 = 'n'; // 1 value
const FTS3_MATCHINFO_AVGLENGTH: u8 = 'a'; // nCol values
const FTS3_MATCHINFO_LENGTH: u8 = 'l'; // nCol values
const FTS3_MATCHINFO_LCS: u8 = 's'; // nCol values
const FTS3_MATCHINFO_HITS: u8 = 'x'; // 3*nCol*nPhrase values
const FTS3_MATCHINFO_LHITS: u8 = 'y'; // nCol*nPhrase values
const FTS3_MATCHINFO_LHITS_BM: u8 = 'b'; // nCol*nPhrase values

// Default value for the second argument to matchinfo().
const FTS3_MATCHINFO_DEFAULT: [*:0]const u8 = "pcx";

// ---------------------------------------------------------------------------
// Public ABI opaque handles (sqlite3.h)
// ---------------------------------------------------------------------------
const sqlite3 = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_blob = anyopaque;

// ---------------------------------------------------------------------------
// Tokenizer module (fts3_tokenizer.h). Field order / fn-ptr signatures copied
// exactly from src/fts3_expr.zig. xNext/xClose are called here, so they carry
// their full prototypes.
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
// Public ABI virtual-table base structs (sqlite3.h), mirrored from src/fts3.zig.
// Only the leading members touched here (pVtab / nColumn etc.) matter.
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
// ABI-SHARED fts3 structs (fts3Int.h), mirrored exactly from src/fts3.zig and
// src/fts3_expr.zig.
// ---------------------------------------------------------------------------
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

/// Fts3Phrase has a flexible array member `aToken[]`. Represented as a 0-length
/// trailing array; aToken[i] reached via pointer arithmetic.
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

const Fts3Index = extern struct {
    nPrefix: c_int,
    hPending: Fts3Hash,
};

const Fts3HashElem = opaque {};
const struct_fts3ht = opaque {};
const Fts3Hash = extern struct {
    keyClass: u8,
    copyKey: u8,
    count: c_int,
    first: ?*Fts3HashElem,
    htsize: c_int,
    ht: ?*struct_fts3ht,
};

/// MatchinfoBuffer — file-local in C; mirrored as opaque to fts3.zig but here we
/// need full layout. Has a flexible array member aMI[]; represented as 0-length
/// trailing array reached by pointer arithmetic.
const MatchinfoBuffer = extern struct {
    aRef: [3]u8,
    nElem: c_int,
    bGlobal: c_int, // Set if global data is loaded
    zMatchinfo: ?[*:0]u8,
    aMI: [0]u32,
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

    // Trailing fields gated by build config (testfixture only). Reproduced with
    // the same gates as src/fts3.zig.
    inTransaction: if (config.sqlite_debug) c_int else void =
        if (config.sqlite_debug) 0 else {},
    mxSavepoint: if (config.sqlite_debug) c_int else void =
        if (config.sqlite_debug) 0 else {},
    bNoIncrDoclist: if (config.sqlite_debug or config.sqlite_test) c_int else void =
        if (config.sqlite_debug or config.sqlite_test) 0 else {},
    nMergeCount: if (config.sqlite_debug or config.sqlite_test) c_int else void =
        if (config.sqlite_debug or config.sqlite_test) 0 else {},
};

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

// ---------------------------------------------------------------------------
// libc resolved at link time.
// ---------------------------------------------------------------------------
extern fn strlen(s: [*:0]const u8) usize;
extern fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;

// ---------------------------------------------------------------------------
// Public sqlite3 API resolved at link time (sqlite3.h).
// ---------------------------------------------------------------------------
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_snprintf(n: c_int, z: [*]u8, fmt: [*:0]const u8, ...) [*:0]u8;

extern fn sqlite3_reset(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_data_count(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_text(pStmt: ?*sqlite3_stmt, i: c_int) ?[*:0]const u8;
extern fn sqlite3_column_bytes(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_blob(pStmt: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_type(pStmt: ?*sqlite3_stmt, i: c_int) c_int;

extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_blob(ctx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: [*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(ctx: ?*sqlite3_context, rc: c_int) void;

// ---------------------------------------------------------------------------
// Internal helpers from sibling fts3 TUs, resolved at link time.
//   * fts3.zig       : varint codec, MallocZero, OpenTokenizer, ErrMsg,
//                      ExprIterate is HERE (not extern), SegmentsClose,
//                      EvalPhrasePoslist/Stats/TestDeferred, MsrCancel, Corrupt,
//                      SelectDoctotal
//   * fts3_write.zig : SelectDocsize, SelectDoctotal (re-exported via fts3.zig)
// ---------------------------------------------------------------------------
extern fn sqlite3Fts3MallocZero(nByte: i64) ?*anyopaque;
extern fn sqlite3Fts3OpenTokenizer(pTokenizer: *sqlite3_tokenizer, iLangid: c_int, z: [*]const u8, n: c_int, ppCsr: *?*sqlite3_tokenizer_cursor) c_int;
extern fn sqlite3Fts3ErrMsg(pzErr: *?[*:0]u8, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3Fts3SegmentsClose(p: *Fts3Table) void;

extern fn sqlite3Fts3GetVarint(pBuf: [*]const u8, v: *i64) c_int;
extern fn sqlite3Fts3GetVarint32(p: [*]const u8, pi: *c_int) c_int;
extern fn sqlite3Fts3GetVarintBounded(pBuf: [*]const u8, pEnd: [*]const u8, v: *i64) c_int;

extern fn sqlite3Fts3EvalPhrasePoslist(pCsr: *Fts3Cursor, pExpr: *Fts3Expr, iCol: c_int, ppOut: *?[*]u8) c_int;
extern fn sqlite3Fts3EvalPhraseStats(pCsr: *Fts3Cursor, pExpr: *Fts3Expr, aiOut: [*]u32) c_int;
extern fn sqlite3Fts3EvalTestDeferred(pCsr: *Fts3Cursor, pRc: *c_int) c_int;
extern fn sqlite3Fts3MsrCancel(pCsr: *Fts3Cursor, pExpr: *Fts3Expr) c_int;
extern fn sqlite3Fts3Corrupt() c_int;

extern fn sqlite3Fts3SelectDoctotal(pTab: *Fts3Table, ppStmt: *?*sqlite3_stmt) c_int;
extern fn sqlite3Fts3SelectDocsize(pTab: *Fts3Table, iDocid: i64, ppStmt: *?*sqlite3_stmt) c_int;

// ===========================================================================
// Macros expressed inline
// ===========================================================================

/// fts3Int.h: FTS_CORRUPT_VTAB. In SQLITE_DEBUG builds the C code routes
/// corruption codes through sqlite3Fts3Corrupt(); otherwise it is a constant.
inline fn FTS_CORRUPT_VTAB() c_int {
    if (config.sqlite_debug) {
        return sqlite3Fts3Corrupt();
    }
    return SQLITE_CORRUPT_VTAB;
}

/// fts3GetVarint32() macro (sqlite3Fts3Int.h): 1-byte fast path or fall to
/// sqlite3Fts3GetVarint32().
inline fn fts3GetVarint32(p: [*]const u8, piVal: *c_int) c_int {
    if ((p[0] & 0x80) != 0) {
        return sqlite3Fts3GetVarint32(p, piVal);
    }
    piVal.* = p[0];
    return 1;
}

/// sqliteInt.h NEVER(X): in non-debug, X (assumed false here). Used by
/// fts3LcsIteratorAdvance for the NEVER(pIter==0) guard.
inline fn NEVER(x: bool) bool {
    return x;
}

/// SZ_MATCHINFOBUFFER(N) = offsetof(MatchinfoBuffer,aMI)+(((N)+1)/2)*sizeof(u64)
inline fn SZ_MATCHINFOBUFFER(n: i64) i64 {
    return @as(i64, @intCast(@offsetOf(MatchinfoBuffer, "aMI"))) +
        @divTrunc(n + 1, 2) * @as(i64, @sizeOf(u64));
}

/// &p->aMI[i] for a MatchinfoBuffer (flexible array access).
inline fn miBufAMI(p: *MatchinfoBuffer) [*]u32 {
    return @ptrCast(&p.aMI);
}

// ===========================================================================
// Position-list helper
// ===========================================================================

/// This function is used to help iterate through a position-list. When called,
/// *pp points to the start of an element and *piPos contains the previous entry.
/// Afterwards *piPos holds the next element value and *pp is advanced.
fn fts3GetDeltaPosition(pp: *[*]u8, piPos: *i64) void {
    var iVal: c_int = 0;
    pp.* += @intCast(fts3GetVarint32(pp.*, &iVal));
    piPos.* += (iVal - 2);
}

// ===========================================================================
// Start of MatchinfoBuffer code.
// ===========================================================================

/// Allocate a two-slot MatchinfoBuffer object.
fn fts3MIBufferNew(nElem: i64, zMatchinfo: [*:0]const u8) ?*MatchinfoBuffer {
    const nByte: i64 = @as(i64, @sizeOf(u32)) * (2 * nElem + 1) + SZ_MATCHINFOBUFFER(1);
    const nStr: i64 = @intCast(strlen(zMatchinfo));

    const pRet: ?*MatchinfoBuffer = @ptrCast(@alignCast(sqlite3Fts3MallocZero(nByte + nStr + 1)));
    if (pRet) |p| {
        const aMI = miBufAMI(p);
        // aMI[0] = (u8*)(&aMI[1]) - (u8*)p
        aMI[0] = @intCast(@intFromPtr(&aMI[1]) - @intFromPtr(p));
        // aMI[1+nElem] = aMI[0] + sizeof(u32)*(nElem+1)
        aMI[@intCast(1 + nElem)] = aMI[0] +% @as(u32, @intCast(@sizeOf(u32) * (nElem + 1)));
        p.nElem = @intCast(nElem);
        // zMatchinfo = ((char*)p) + nByte
        p.zMatchinfo = @ptrCast(@as([*]u8, @ptrCast(p)) + @as(usize, @intCast(nByte)));
        _ = memcpy(p.zMatchinfo, zMatchinfo, @intCast(nStr + 1));
        p.aRef[0] = 1;
    }

    return pRet;
}

fn fts3MIBufferFree(pIn: ?*anyopaque) callconv(.c) void {
    const p: [*]u32 = @ptrCast(@alignCast(pIn.?));
    // pBuf = (MatchinfoBuffer*)((u8*)p - ((u32*)p)[-1])
    const off: usize = (p - 1)[0];
    const pBuf: *MatchinfoBuffer = @ptrCast(@alignCast(@as([*]u8, @ptrCast(p)) - off));
    const aMI = miBufAMI(pBuf);

    // assert( (u32*)p==&pBuf->aMI[1] || (u32*)p==&pBuf->aMI[pBuf->nElem+2] );
    if (p == @as([*]u32, @ptrCast(&aMI[1]))) {
        pBuf.aRef[1] = 0;
    } else {
        pBuf.aRef[2] = 0;
    }

    if (pBuf.aRef[0] == 0 and pBuf.aRef[1] == 0 and pBuf.aRef[2] == 0) {
        sqlite3_free(pBuf);
    }
}

/// Reserve one of the two pre-allocated u32 buffers (or malloc a fresh one).
/// Returns the destructor for the returned buffer and sets paOut.
fn fts3MIBufferAlloc(p: *MatchinfoBuffer, paOut: *?[*]u32) DestructorFn {
    var xRet: DestructorFn = null;
    var aOut: ?[*]u32 = null;
    const aMI = miBufAMI(p);

    if (p.aRef[1] == 0) {
        p.aRef[1] = 1;
        aOut = @ptrCast(&aMI[1]);
        xRet = fts3MIBufferFree;
    } else if (p.aRef[2] == 0) {
        p.aRef[2] = 1;
        aOut = @ptrCast(&aMI[@intCast(p.nElem + 2)]);
        xRet = fts3MIBufferFree;
    } else {
        aOut = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, @intCast(p.nElem)) * @sizeOf(u32))));
        if (aOut) |a| {
            xRet = sqlite3_free;
            if (p.bGlobal != 0) {
                _ = memcpy(a, &aMI[1], @as(usize, @intCast(p.nElem)) * @sizeOf(u32));
            }
        }
    }

    paOut.* = aOut;
    return xRet;
}

fn fts3MIBufferSetGlobal(p: *MatchinfoBuffer) void {
    const aMI = miBufAMI(p);
    p.bGlobal = 1;
    _ = memcpy(&aMI[@intCast(2 + p.nElem)], &aMI[1], @as(usize, @intCast(p.nElem)) * @sizeOf(u32));
}

/// Free a MatchinfoBuffer object allocated using fts3MIBufferNew().
pub export fn sqlite3Fts3MIBufferFree(p: ?*MatchinfoBuffer) callconv(.c) void {
    if (p) |pBuf| {
        // assert( pBuf->aRef[0]==1 );
        pBuf.aRef[0] = 0;
        if (pBuf.aRef[0] == 0 and pBuf.aRef[1] == 0 and pBuf.aRef[2] == 0) {
            sqlite3_free(pBuf);
        }
    }
}

// ===========================================================================
// Snippet iterator types (file-local)
// ===========================================================================
const SnippetIter = extern struct {
    pCsr: *Fts3Cursor,
    iCol: c_int,
    nSnippet: c_int,
    nPhrase: c_int,
    aPhrase: ?[*]SnippetPhrase,
    iCurrent: c_int,
};

const SnippetPhrase = extern struct {
    nToken: c_int,
    pList: ?[*]u8,
    iHead: i64,
    pHead: ?[*]u8,
    iTail: i64,
    pTail: ?[*]u8,
};

const SnippetFragment = extern struct {
    iCol: c_int,
    iPos: c_int,
    covered: u64,
    hlmask: u64,
};

const StrBuffer = extern struct {
    z: ?[*]u8,
    n: c_int,
    nAlloc: c_int,
};

const MatchInfo = extern struct {
    pCursor: *Fts3Cursor,
    nCol: c_int,
    nPhrase: c_int,
    nDoc: i64,
    flag: u8,
    aMatchinfo: ?[*]u32,
};

const LoadDoclistCtx = extern struct {
    pCsr: ?*Fts3Cursor,
    nPhrase: c_int,
    nToken: c_int,
};

// ===========================================================================
// sqlite3Fts3ExprIterate
// ===========================================================================

const ExprCb = *const fn (*Fts3Expr, c_int, ?*anyopaque) callconv(.c) c_int;

/// Helper for sqlite3Fts3ExprIterate().
fn fts3ExprIterate2(pExpr: *Fts3Expr, piPhrase: *c_int, x: ExprCb, pCtx: ?*anyopaque) c_int {
    var rc: c_int = undefined;
    const eType = pExpr.eType;

    if (eType != FTSQUERY_PHRASE) {
        // assert( pExpr->pLeft && pExpr->pRight );
        rc = fts3ExprIterate2(pExpr.pLeft.?, piPhrase, x, pCtx);
        if (rc == SQLITE_OK and eType != FTSQUERY_NOT) {
            rc = fts3ExprIterate2(pExpr.pRight.?, piPhrase, x, pCtx);
        }
    } else {
        rc = x(pExpr, piPhrase.*, pCtx);
        piPhrase.* += 1;
    }
    return rc;
}

/// Iterate through all phrase nodes in an FTS3 query, except those on the
/// right-hand side of a NOT operator. Invokes x() for each eligible phrase.
pub export fn sqlite3Fts3ExprIterate(pExpr: *Fts3Expr, x: ExprCb, pCtx: ?*anyopaque) callconv(.c) c_int {
    var iPhrase: c_int = 0;
    return fts3ExprIterate2(pExpr, &iPhrase, x, pCtx);
}

// ===========================================================================
// Doclist loading / phrase counting
// ===========================================================================

fn fts3ExprLoadDoclistsCb(pExpr: *Fts3Expr, iPhrase: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    _ = iPhrase;
    const pPhrase = pExpr.pPhrase.?;
    const p: *LoadDoclistCtx = @ptrCast(@alignCast(ctx.?));
    p.nPhrase += 1;
    p.nToken += pPhrase.nToken;
    return SQLITE_OK;
}

/// Load the doclists for each phrase in the query associated with pCsr.
fn fts3ExprLoadDoclists(pCsr: *Fts3Cursor, pnPhrase: ?*c_int, pnToken: ?*c_int) c_int {
    var sCtx: LoadDoclistCtx = .{ .pCsr = null, .nPhrase = 0, .nToken = 0 };
    sCtx.pCsr = pCsr;
    const rc = sqlite3Fts3ExprIterate(pCsr.pExpr.?, fts3ExprLoadDoclistsCb, @ptrCast(&sCtx));
    if (pnPhrase) |pp| pp.* = sCtx.nPhrase;
    if (pnToken) |pt| pt.* = sCtx.nToken;
    return rc;
}

fn fts3ExprPhraseCountCb(pExpr: *Fts3Expr, iPhrase: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    const p: *c_int = @ptrCast(@alignCast(ctx.?));
    p.* += 1;
    pExpr.iPhrase = iPhrase;
    return SQLITE_OK;
}

fn fts3ExprPhraseCount(pExpr: *Fts3Expr) c_int {
    var nPhrase: c_int = 0;
    _ = sqlite3Fts3ExprIterate(pExpr, fts3ExprPhraseCountCb, @ptrCast(&nPhrase));
    return nPhrase;
}

/// Advance the position-list iterator so it points to the first element with a
/// value >= iNext.
fn fts3SnippetAdvance(ppIter: *?[*]u8, piIter: *i64, iNext: c_int) void {
    if (ppIter.*) |_| {
        var pIter: [*]u8 = ppIter.*.?;
        var iIter = piIter.*;

        while (iIter < iNext) {
            if (0 == (pIter[0] & 0xFE)) {
                iIter = -1;
                ppIter.* = null;
                piIter.* = iIter;
                return;
            }
            fts3GetDeltaPosition(&pIter, &iIter);
        }

        piIter.* = iIter;
        ppIter.* = pIter;
    }
}

/// Advance the snippet iterator to the next candidate snippet. Returns 1 at EOF.
fn fts3SnippetNextCandidate(pIter: *SnippetIter) c_int {
    var i: c_int = 0;
    const aPhrase = pIter.aPhrase.?;

    if (pIter.iCurrent < 0) {
        pIter.iCurrent = 0;
        i = 0;
        while (i < pIter.nPhrase) : (i += 1) {
            const pPhrase = &aPhrase[@intCast(i)];
            fts3SnippetAdvance(&pPhrase.pHead, &pPhrase.iHead, pIter.nSnippet);
        }
    } else {
        var iEnd: c_int = 0x7FFFFFFF;

        i = 0;
        while (i < pIter.nPhrase) : (i += 1) {
            const pPhrase = &aPhrase[@intCast(i)];
            if (pPhrase.pHead != null and pPhrase.iHead < iEnd) {
                iEnd = @intCast(pPhrase.iHead);
            }
        }
        if (iEnd == 0x7FFFFFFF) {
            return 1;
        }

        // assert( pIter->nSnippet>=0 );
        const iStart = iEnd - pIter.nSnippet + 1;
        pIter.iCurrent = iStart;
        i = 0;
        while (i < pIter.nPhrase) : (i += 1) {
            const pPhrase = &aPhrase[@intCast(i)];
            fts3SnippetAdvance(&pPhrase.pHead, &pPhrase.iHead, iEnd + 1);
            fts3SnippetAdvance(&pPhrase.pTail, &pPhrase.iTail, iStart);
        }
    }

    return 0;
}

/// Retrieve information about the current candidate snippet of pIter.
fn fts3SnippetDetails(
    pIter: *SnippetIter,
    mCovered: u64,
    piToken: *c_int,
    piScore: *c_int,
    pmCover: *u64,
    pmHighlight: *u64,
) void {
    const iStart = pIter.iCurrent;
    var iScore: c_int = 0;
    var i: c_int = 0;
    var mCover: u64 = 0;
    var mHighlight: u64 = 0;
    const aPhrase = pIter.aPhrase.?;

    while (i < pIter.nPhrase) : (i += 1) {
        const pPhrase = &aPhrase[@intCast(i)];
        if (pPhrase.pTail) |_| {
            var pCsr: [*]u8 = pPhrase.pTail.?;
            var iCsr = pPhrase.iTail;

            while (iCsr < (iStart + pIter.nSnippet) and iCsr >= iStart) {
                var j: c_int = 0;
                const mPhrase: u64 = @as(u64, 1) << @intCast(@mod(i, 64));
                const mPos: u64 = @as(u64, 1) << @intCast(iCsr - iStart);
                // assert( iCsr>=iStart && (iCsr - iStart)<=64 );
                if ((mCover | mCovered) & mPhrase != 0) {
                    iScore += 1;
                } else {
                    iScore += 1000;
                }
                mCover |= mPhrase;

                j = 0;
                while (j < pPhrase.nToken and j < pIter.nSnippet) : (j += 1) {
                    mHighlight |= (mPos >> @intCast(j));
                }

                if (0 == (pCsr[0] & 0x0FE)) break;
                fts3GetDeltaPosition(&pCsr, &iCsr);
            }
        }
    }

    piToken.* = iStart;
    piScore.* = iScore;
    pmCover.* = mCover;
    pmHighlight.* = mHighlight;
}

/// sqlite3Fts3ExprIterate() callback used by fts3BestSnippet(). Populates one
/// element of SnippetIter.aPhrase[].
fn fts3SnippetFindPositions(pExpr: *Fts3Expr, iPhrase: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    const p: *SnippetIter = @ptrCast(@alignCast(ctx.?));
    const pPhrase = &p.aPhrase.?[@intCast(iPhrase)];
    var pCsr: ?[*]u8 = undefined;

    pPhrase.nToken = pExpr.pPhrase.?.nToken;
    var rc = sqlite3Fts3EvalPhrasePoslist(p.pCsr, pExpr, p.iCol, &pCsr);
    // assert( rc==SQLITE_OK || pCsr==0 );
    if (pCsr) |_| {
        var iFirst: i64 = 0;
        pPhrase.pList = pCsr;
        var pc: [*]u8 = pCsr.?;
        fts3GetDeltaPosition(&pc, &iFirst);
        if (iFirst < 0) {
            rc = FTS_CORRUPT_VTAB();
        } else {
            pPhrase.pHead = pc;
            pPhrase.pTail = pc;
            pPhrase.iHead = iFirst;
            pPhrase.iTail = iFirst;
        }
    }

    return rc;
}

/// Select the fragment of nFragment contiguous tokens from column iCol that is
/// the "best" snippet, scoring by phrase coverage.
fn fts3BestSnippet(
    nSnippet: c_int,
    pCsr: *Fts3Cursor,
    iCol: c_int,
    mCovered: u64,
    pmSeen: *u64,
    pFragment: *SnippetFragment,
    piScore: *c_int,
) c_int {
    var nList: c_int = undefined;
    var sIter: SnippetIter = std.mem.zeroes(SnippetIter);
    var iBestScore: c_int = -1;
    var i: c_int = undefined;

    // Iterate phrases to count them; the callback also loads the doclists.
    var rc = fts3ExprLoadDoclists(pCsr, &nList, null);
    if (rc != SQLITE_OK) {
        return rc;
    }

    const nByte: i64 = @as(i64, @sizeOf(SnippetPhrase)) * nList;
    sIter.aPhrase = @ptrCast(@alignCast(sqlite3Fts3MallocZero(nByte)));
    if (sIter.aPhrase == null) {
        return SQLITE_NOMEM;
    }

    sIter.pCsr = pCsr;
    sIter.iCol = iCol;
    sIter.nSnippet = nSnippet;
    sIter.nPhrase = nList;
    sIter.iCurrent = -1;
    rc = sqlite3Fts3ExprIterate(pCsr.pExpr.?, fts3SnippetFindPositions, @ptrCast(&sIter));
    if (rc == SQLITE_OK) {
        i = 0;
        while (i < nList) : (i += 1) {
            if (sIter.aPhrase.?[@intCast(i)].pHead != null) {
                pmSeen.* |= @as(u64, 1) << @intCast(@mod(i, 64));
            }
        }

        pFragment.iCol = iCol;
        while (fts3SnippetNextCandidate(&sIter) == 0) {
            var iPos: c_int = undefined;
            var iScore: c_int = undefined;
            var mCover: u64 = undefined;
            var mHighlite: u64 = undefined;
            fts3SnippetDetails(&sIter, mCovered, &iPos, &iScore, &mCover, &mHighlite);
            // assert( iScore>=0 );
            if (iScore > iBestScore) {
                pFragment.iPos = iPos;
                pFragment.hlmask = mHighlite;
                pFragment.covered = mCover;
                iBestScore = iScore;
            }
        }

        piScore.* = iBestScore;
    }
    sqlite3_free(@ptrCast(sIter.aPhrase));
    return rc;
}

/// Append a string to the string-buffer. If nAppend<0, strlen() is used.
fn fts3StringAppend(pStr: *StrBuffer, zAppend: [*]const u8, nAppendIn: c_int) c_int {
    var nAppend = nAppendIn;
    if (nAppend < 0) {
        nAppend = @intCast(strlen(@ptrCast(zAppend)));
    }

    if (pStr.n + nAppend + 1 >= pStr.nAlloc) {
        const nAlloc: i64 = @as(i64, pStr.nAlloc) + @as(i64, nAppend) + 100;
        const zNew: ?[*]u8 = @ptrCast(sqlite3_realloc64(pStr.z, @intCast(nAlloc)));
        if (zNew == null) {
            return SQLITE_NOMEM;
        }
        pStr.z = zNew;
        pStr.nAlloc = @intCast(nAlloc);
    }
    // assert( pStr->z!=0 && (pStr->nAlloc >= pStr->n+nAppend+1) );

    _ = memcpy(pStr.z.? + @as(usize, @intCast(pStr.n)), zAppend, @intCast(nAppend));
    pStr.n += nAppend;
    pStr.z.?[@intCast(pStr.n)] = 0;

    return SQLITE_OK;
}

/// "Shift" the snippet start forward so highlights are roughly centered.
fn fts3SnippetShift(
    pTab: *Fts3Table,
    iLangid: c_int,
    nSnippet: c_int,
    zDoc: [*]const u8,
    nDoc: c_int,
    piPos: *c_int,
    pHlmask: *u64,
) c_int {
    const hlmask = pHlmask.*;

    if (hlmask != 0) {
        var nLeft: c_int = 0;
        var nRight: c_int = 0;

        while ((hlmask & (@as(u64, 1) << @intCast(nLeft))) == 0) : (nLeft += 1) {}
        while ((hlmask & (@as(u64, 1) << @intCast(nSnippet - 1 - nRight))) == 0) : (nRight += 1) {}
        // assert( (nSnippet-1-nRight)<=63 && (nSnippet-1-nRight)>=0 );
        const nDesired = @divTrunc(nLeft - nRight, 2);

        if (nDesired > 0) {
            var iCurrent: c_int = 0;
            const pMod = pTab.pTokenizer.?.pModule.?;
            var pC: ?*sqlite3_tokenizer_cursor = undefined;

            var rc = sqlite3Fts3OpenTokenizer(pTab.pTokenizer.?, iLangid, zDoc, nDoc, &pC);
            if (rc != SQLITE_OK) {
                return rc;
            }
            while (rc == SQLITE_OK and iCurrent < (nSnippet + nDesired)) {
                var ZDUMMY: ?[*]const u8 = undefined;
                var DUMMY1: c_int = 0;
                var DUMMY2: c_int = 0;
                var DUMMY3: c_int = 0;
                rc = pMod.xNext.?(pC.?, &ZDUMMY, &DUMMY1, &DUMMY2, &DUMMY3, &iCurrent);
            }
            _ = pMod.xClose.?(pC.?);
            if (rc != SQLITE_OK and rc != SQLITE_DONE) {
                return rc;
            }

            const nShift = @as(c_int, @intFromBool(rc == SQLITE_DONE)) + iCurrent - nSnippet;
            // assert( nShift<=nDesired );
            if (nShift > 0) {
                piPos.* += nShift;
                pHlmask.* = hlmask >> @intCast(nShift);
            }
        }
    }
    return SQLITE_OK;
}

/// Extract the snippet text for pFragment from pCsr and append it to pOut.
fn fts3SnippetText(
    pCsr: *Fts3Cursor,
    pFragment: *SnippetFragment,
    iFragment: c_int,
    isLast: c_int,
    nSnippet: c_int,
    zOpen: [*:0]const u8,
    zClose: [*:0]const u8,
    zEllipsis: [*:0]const u8,
    pOut: *StrBuffer,
) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var iCurrent: c_int = 0;
    var iEnd: c_int = 0;
    var isShiftDone: bool = false;
    var iPos: c_int = pFragment.iPos;
    var hlmask: u64 = pFragment.hlmask;
    const iCol: c_int = pFragment.iCol + 1;

    const zDoc = sqlite3_column_text(pCsr.pStmt, iCol);
    if (zDoc == null) {
        if (sqlite3_column_type(pCsr.pStmt, iCol) != SQLITE_NULL) {
            return SQLITE_NOMEM;
        }
        return SQLITE_OK;
    }
    const nDoc = sqlite3_column_bytes(pCsr.pStmt, iCol);

    const pMod = pTab.pTokenizer.?.pModule.?;
    var pC: ?*sqlite3_tokenizer_cursor = undefined;
    var rc = sqlite3Fts3OpenTokenizer(pTab.pTokenizer.?, pCsr.iLangid, @ptrCast(zDoc.?), nDoc, &pC);
    if (rc != SQLITE_OK) {
        return rc;
    }

    const zDocP: [*]const u8 = @ptrCast(zDoc.?);

    while (rc == SQLITE_OK) {
        var ZDUMMY: ?[*]const u8 = undefined;
        var DUMMY1: c_int = -1;
        var iBegin: c_int = 0;
        var iFin: c_int = 0;
        var isHighlight: bool = false;

        rc = pMod.xNext.?(pC.?, &ZDUMMY, &DUMMY1, &iBegin, &iFin, &iCurrent);
        if (rc != SQLITE_OK) {
            if (rc == SQLITE_DONE) {
                rc = fts3StringAppend(pOut, zDocP + @as(usize, @intCast(iEnd)), -1);
            }
            break;
        }
        if (iCurrent < iPos) {
            continue;
        }

        if (!isShiftDone) {
            const n = nDoc - iBegin;
            rc = fts3SnippetShift(
                pTab,
                pCsr.iLangid,
                nSnippet,
                zDocP + @as(usize, @intCast(iBegin)),
                n,
                &iPos,
                &hlmask,
            );
            isShiftDone = true;

            if (rc == SQLITE_OK) {
                if (iPos > 0 or iFragment > 0) {
                    rc = fts3StringAppend(pOut, zEllipsis, -1);
                } else if (iBegin != 0) {
                    rc = fts3StringAppend(pOut, zDocP, iBegin);
                }
            }
            if (rc != SQLITE_OK or iCurrent < iPos) continue;
        }

        if (iCurrent >= (iPos + nSnippet)) {
            if (isLast != 0) {
                rc = fts3StringAppend(pOut, zEllipsis, -1);
            }
            break;
        }

        isHighlight = (hlmask & (@as(u64, 1) << @intCast(iCurrent - iPos))) != 0;

        if (iCurrent > iPos) rc = fts3StringAppend(pOut, zDocP + @as(usize, @intCast(iEnd)), iBegin - iEnd);
        if (rc == SQLITE_OK and isHighlight) rc = fts3StringAppend(pOut, zOpen, -1);
        if (rc == SQLITE_OK) rc = fts3StringAppend(pOut, zDocP + @as(usize, @intCast(iBegin)), iFin - iBegin);
        if (rc == SQLITE_OK and isHighlight) rc = fts3StringAppend(pOut, zClose, -1);

        iEnd = iFin;
    }

    _ = pMod.xClose.?(pC.?);
    return rc;
}

/// Count the entries in a column-list. *ppCollist is advanced to the first byte
/// past the list (the 0x00 or 0x01 terminator). Returns the count.
fn fts3ColumnlistCount(ppCollist: *[*]u8) c_int {
    var pEnd: [*]u8 = ppCollist.*;
    var c: u8 = 0;
    var nEntry: c_int = 0;

    while (0xFE & (pEnd[0] | c) != 0) {
        c = pEnd[0] & 0x80;
        pEnd += 1;
        if (c == 0) nEntry += 1;
    }

    ppCollist.* = pEnd;
    return nEntry;
}

// ===========================================================================
// matchinfo() machinery
// ===========================================================================

/// Gather 'y' or 'b' data for a single phrase.
fn fts3ExprLHits(pExpr: *Fts3Expr, p: *MatchInfo) c_int {
    const pTab: *Fts3Table = @ptrCast(@alignCast(p.pCursor.base.pVtab.?));
    var iStart: c_int = undefined;
    const pPhrase = pExpr.pPhrase.?;
    var pIter: ?[*]u8 = pPhrase.doclist.pList;
    var iCol: c_int = 0;

    // assert( p->flag==FTS3_MATCHINFO_LHITS_BM || p->flag==FTS3_MATCHINFO_LHITS );
    if (p.flag == FTS3_MATCHINFO_LHITS) {
        iStart = pExpr.iPhrase * p.nCol;
    } else {
        iStart = pExpr.iPhrase * @divTrunc(p.nCol + 31, 32);
    }

    if (pIter != null) while (true) {
        var pit: [*]u8 = pIter.?;
        const nHit = fts3ColumnlistCount(&pit);
        if (pPhrase.iColumn >= pTab.nColumn or pPhrase.iColumn == iCol) {
            if (p.flag == FTS3_MATCHINFO_LHITS) {
                p.aMatchinfo.?[@intCast(iStart + iCol)] = @intCast(nHit);
            } else if (nHit != 0) {
                p.aMatchinfo.?[@intCast(iStart + @divTrunc(iCol, 32))] |= (@as(u32, 1) << @intCast(iCol & 0x1F));
            }
        }
        // assert( *pIter==0x00 || *pIter==0x01 );
        if (pit[0] != 0x01) {
            pIter = pit;
            break;
        }
        pit += 1;
        pit += @intCast(fts3GetVarint32(pit, &iCol));
        pIter = pit;
        if (iCol >= p.nCol) return FTS_CORRUPT_VTAB();
    };
    return SQLITE_OK;
}

/// Gather the results for matchinfo directives 'y' and 'b'.
fn fts3ExprLHitGather(pExpr: *Fts3Expr, p: *MatchInfo) c_int {
    var rc: c_int = SQLITE_OK;
    // assert( (pExpr->pLeft==0)==(pExpr->pRight==0) );
    if (pExpr.bEof == 0 and pExpr.iDocid == p.pCursor.iPrevId) {
        if (pExpr.pLeft) |pl| {
            rc = fts3ExprLHitGather(pl, p);
            if (rc == SQLITE_OK) rc = fts3ExprLHitGather(pExpr.pRight.?, p);
        } else {
            rc = fts3ExprLHits(pExpr, p);
        }
    }
    return rc;
}

/// Collect the "global" elements of an FTS3_MATCHINFO_HITS matchinfo array.
fn fts3ExprGlobalHitsCb(pExpr: *Fts3Expr, iPhrase: c_int, pCtx: ?*anyopaque) callconv(.c) c_int {
    const p: *MatchInfo = @ptrCast(@alignCast(pCtx.?));
    return sqlite3Fts3EvalPhraseStats(
        p.pCursor,
        pExpr,
        p.aMatchinfo.? + @as(usize, @intCast(3 * iPhrase * p.nCol)),
    );
}

/// Collect the "local" part of the FTS3_MATCHINFO_HITS array.
fn fts3ExprLocalHitsCb(pExpr: *Fts3Expr, iPhrase: c_int, pCtx: ?*anyopaque) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const p: *MatchInfo = @ptrCast(@alignCast(pCtx.?));
    const iStart = iPhrase * p.nCol * 3;
    var i: c_int = 0;

    while (i < p.nCol and rc == SQLITE_OK) : (i += 1) {
        var pCsr: ?[*]u8 = undefined;
        rc = sqlite3Fts3EvalPhrasePoslist(p.pCursor, pExpr, i, &pCsr);
        if (pCsr) |_| {
            var pc: [*]u8 = pCsr.?;
            p.aMatchinfo.?[@intCast(iStart + i * 3)] = @intCast(fts3ColumnlistCount(&pc));
        } else {
            p.aMatchinfo.?[@intCast(iStart + i * 3)] = 0;
        }
    }

    return rc;
}

fn fts3MatchinfoCheck(pTab: *Fts3Table, cArg: u8, pzErr: *?[*:0]u8) c_int {
    if ((cArg == FTS3_MATCHINFO_NPHRASE) or
        (cArg == FTS3_MATCHINFO_NCOL) or
        (cArg == FTS3_MATCHINFO_NDOC and pTab.bFts4 != 0) or
        (cArg == FTS3_MATCHINFO_AVGLENGTH and pTab.bFts4 != 0) or
        (cArg == FTS3_MATCHINFO_LENGTH and pTab.bHasDocsize != 0) or
        (cArg == FTS3_MATCHINFO_LCS) or
        (cArg == FTS3_MATCHINFO_HITS) or
        (cArg == FTS3_MATCHINFO_LHITS) or
        (cArg == FTS3_MATCHINFO_LHITS_BM))
    {
        return SQLITE_OK;
    }
    sqlite3Fts3ErrMsg(pzErr, "unrecognized matchinfo request: %c", @as(c_int, cArg));
    return SQLITE_ERROR;
}

fn fts3MatchinfoSize(pInfo: *MatchInfo, cArg: u8) i64 {
    var nVal: i64 = undefined;

    switch (cArg) {
        FTS3_MATCHINFO_NDOC, FTS3_MATCHINFO_NPHRASE, FTS3_MATCHINFO_NCOL => {
            nVal = 1;
        },
        FTS3_MATCHINFO_AVGLENGTH, FTS3_MATCHINFO_LENGTH, FTS3_MATCHINFO_LCS => {
            nVal = pInfo.nCol;
        },
        FTS3_MATCHINFO_LHITS => {
            nVal = @as(i64, pInfo.nCol) * pInfo.nPhrase;
        },
        FTS3_MATCHINFO_LHITS_BM => {
            nVal = @as(i64, pInfo.nPhrase) * @divTrunc(pInfo.nCol + 31, 32);
        },
        else => {
            // assert( cArg==FTS3_MATCHINFO_HITS );
            nVal = @as(i64, pInfo.nCol) * pInfo.nPhrase * 3;
        },
    }

    return nVal;
}

fn fts3MatchinfoSelectDoctotal(
    pTab: *Fts3Table,
    ppStmt: *?*sqlite3_stmt,
    pnDoc: *i64,
    paLen: ?*?[*]const u8,
    ppEnd: ?*?[*]const u8,
) c_int {
    if (ppStmt.* == null) {
        const rc = sqlite3Fts3SelectDoctotal(pTab, ppStmt);
        if (rc != SQLITE_OK) return rc;
    }
    const pStmt = ppStmt.*;
    // assert( sqlite3_data_count(pStmt)==1 );

    const n = sqlite3_column_bytes(pStmt, 0);
    const a: ?[*]const u8 = @ptrCast(sqlite3_column_blob(pStmt, 0));
    if (a == null) {
        return FTS_CORRUPT_VTAB();
    }
    var ap: [*]const u8 = a.?;
    const pEnd: [*]const u8 = ap + @as(usize, @intCast(n));
    var nDoc: i64 = 0;
    ap += @intCast(sqlite3Fts3GetVarintBounded(ap, pEnd, &nDoc));
    if (nDoc <= 0 or @intFromPtr(ap) > @intFromPtr(pEnd)) {
        return FTS_CORRUPT_VTAB();
    }
    pnDoc.* = nDoc;

    if (paLen) |pl| pl.* = ap;
    if (ppEnd) |pe| pe.* = pEnd;
    return SQLITE_OK;
}

const LcsIterator = extern struct {
    pExpr: ?*Fts3Expr,
    iPosOffset: c_int,
    pRead: ?[*]u8,
    iPos: c_int,
};

fn fts3MatchinfoLcsCb(pExpr: *Fts3Expr, iPhrase: c_int, pCtx: ?*anyopaque) callconv(.c) c_int {
    const aIter: [*]LcsIterator = @ptrCast(@alignCast(pCtx.?));
    aIter[@intCast(iPhrase)].pExpr = pExpr;
    return SQLITE_OK;
}

/// Advance the LCS iterator. Returns 1 at EOF / start of next column's list.
fn fts3LcsIteratorAdvance(pIter: *LcsIterator) c_int {
    var rc: c_int = 0;

    if (NEVER(false)) return 1; // NEVER(pIter==0): pIter is non-null here.
    var pRead: ?[*]u8 = pIter.pRead;
    var iRead: i64 = 0;
    var pr: [*]u8 = pRead.?;
    pr += @intCast(sqlite3Fts3GetVarint(pr, &iRead));
    if (iRead == 0 or iRead == 1) {
        pRead = null;
        rc = 1;
    } else {
        pIter.iPos += @intCast(iRead - 2);
        pRead = pr;
    }

    pIter.pRead = pRead;
    return rc;
}

/// Implements the FTS3_MATCHINFO_LCS matchinfo() flag.
fn fts3MatchinfoLcs(pCsr: *Fts3Cursor, pInfo: *MatchInfo) c_int {
    var i: c_int = undefined;
    var iCol: c_int = undefined;
    var nToken: c_int = 0;
    var rc: c_int = SQLITE_OK;

    const aIter: ?[*]LcsIterator = @ptrCast(@alignCast(sqlite3Fts3MallocZero(@as(i64, @sizeOf(LcsIterator)) * pCsr.nPhrase)));
    if (aIter == null) return SQLITE_NOMEM;
    const aIt = aIter.?;
    _ = sqlite3Fts3ExprIterate(pCsr.pExpr.?, fts3MatchinfoLcsCb, @ptrCast(aIt));

    i = 0;
    while (i < pInfo.nPhrase) : (i += 1) {
        const pIter = &aIt[@intCast(i)];
        nToken -= pIter.pExpr.?.pPhrase.?.nToken;
        pIter.iPosOffset = nToken;
    }

    iCol = 0;
    lcs_out: while (iCol < pInfo.nCol) : (iCol += 1) {
        var nLcs: c_int = 0;
        var nLive: c_int = 0;

        i = 0;
        while (i < pInfo.nPhrase) : (i += 1) {
            const pIt = &aIt[@intCast(i)];
            rc = sqlite3Fts3EvalPhrasePoslist(pCsr, pIt.pExpr.?, iCol, &pIt.pRead);
            if (rc != SQLITE_OK) break :lcs_out;
            if (pIt.pRead != null) {
                pIt.iPos = pIt.iPosOffset;
                _ = fts3LcsIteratorAdvance(pIt);
                if (pIt.pRead == null) {
                    rc = FTS_CORRUPT_VTAB();
                    break :lcs_out;
                }
                nLive += 1;
            }
        }

        while (nLive > 0) {
            var pAdv: ?*LcsIterator = null;
            var nThisLcs: c_int = 0;

            i = 0;
            while (i < pInfo.nPhrase) : (i += 1) {
                const pIter = &aIt[@intCast(i)];
                if (pIter.pRead == null) {
                    nThisLcs = 0;
                } else {
                    if (pAdv == null or pIter.iPos < pAdv.?.iPos) {
                        pAdv = pIter;
                    }
                    // pIter[-1] : previous element in the array.
                    if (nThisLcs == 0 or pIter.iPos == (aIt + @as(usize, @intCast(i)) - 1)[0].iPos) {
                        nThisLcs += 1;
                    } else {
                        nThisLcs = 1;
                    }
                    if (nThisLcs > nLcs) nLcs = nThisLcs;
                }
            }
            if (fts3LcsIteratorAdvance(pAdv.?) != 0) nLive -= 1;
        }

        pInfo.aMatchinfo.?[@intCast(iCol)] = @intCast(nLcs);
    }

    sqlite3_free(@ptrCast(aIter));
    return rc;
}

/// Populate pInfo->aMatchinfo[] per the format string zArg.
fn fts3MatchinfoValues(pCsr: *Fts3Cursor, bGlobal: c_int, pInfo: *MatchInfo, zArg: [*:0]const u8) c_int {
    var rc: c_int = SQLITE_OK;
    var i: c_int = 0;
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var pSelect: ?*sqlite3_stmt = null;

    while (rc == SQLITE_OK and zArg[@intCast(i)] != 0) : (i += 1) {
        pInfo.flag = zArg[@intCast(i)];
        switch (zArg[@intCast(i)]) {
            FTS3_MATCHINFO_NPHRASE => {
                if (bGlobal != 0) pInfo.aMatchinfo.?[0] = @intCast(pInfo.nPhrase);
            },

            FTS3_MATCHINFO_NCOL => {
                if (bGlobal != 0) pInfo.aMatchinfo.?[0] = @intCast(pInfo.nCol);
            },

            FTS3_MATCHINFO_NDOC => {
                if (bGlobal != 0) {
                    var nDoc: i64 = 0;
                    rc = fts3MatchinfoSelectDoctotal(pTab, &pSelect, &nDoc, null, null);
                    pInfo.aMatchinfo.?[0] = @intCast(@as(u32, @truncate(@as(u64, @bitCast(nDoc)))));
                }
            },

            FTS3_MATCHINFO_AVGLENGTH => {
                if (bGlobal != 0) {
                    var nDoc: i64 = undefined;
                    var a: ?[*]const u8 = undefined;
                    var pEnd: ?[*]const u8 = undefined;

                    rc = fts3MatchinfoSelectDoctotal(pTab, &pSelect, &nDoc, &a, &pEnd);
                    if (rc == SQLITE_OK) {
                        var iCol: c_int = 0;
                        var ap: [*]const u8 = a.?;
                        while (iCol < pInfo.nCol) : (iCol += 1) {
                            var nToken: i64 = 0;
                            ap += @intCast(sqlite3Fts3GetVarint(ap, &nToken));
                            if (@intFromPtr(ap) > @intFromPtr(pEnd.?)) {
                                rc = SQLITE_CORRUPT_VTAB;
                                break;
                            }
                            // iVal = (u32)(((u32)(nToken&0xffffffff)+nDoc/2)/nDoc)
                            const nTok32: u32 = @truncate(@as(u64, @bitCast(nToken)) & 0xffffffff);
                            const iVal: u32 = @intCast(@divTrunc(@as(i64, nTok32) + @divTrunc(nDoc, 2), nDoc));
                            pInfo.aMatchinfo.?[@intCast(iCol)] = iVal;
                        }
                    }
                }
            },

            FTS3_MATCHINFO_LENGTH => {
                var pSelectDocsize: ?*sqlite3_stmt = null;
                rc = sqlite3Fts3SelectDocsize(pTab, pCsr.iPrevId, &pSelectDocsize);
                if (rc == SQLITE_OK) {
                    var iCol: c_int = 0;
                    var a: [*]const u8 = @ptrCast(sqlite3_column_blob(pSelectDocsize, 0).?);
                    const pEnd: [*]const u8 = a + @as(usize, @intCast(sqlite3_column_bytes(pSelectDocsize, 0)));
                    while (iCol < pInfo.nCol) : (iCol += 1) {
                        var nToken: i64 = 0;
                        a += @intCast(sqlite3Fts3GetVarintBounded(a, pEnd, &nToken));
                        if (@intFromPtr(a) > @intFromPtr(pEnd)) {
                            rc = SQLITE_CORRUPT_VTAB;
                            break;
                        }
                        pInfo.aMatchinfo.?[@intCast(iCol)] = @intCast(nToken);
                    }
                }
                _ = sqlite3_reset(pSelectDocsize);
            },

            FTS3_MATCHINFO_LCS => {
                rc = fts3ExprLoadDoclists(pCsr, null, null);
                if (rc == SQLITE_OK) {
                    rc = fts3MatchinfoLcs(pCsr, pInfo);
                }
            },

            FTS3_MATCHINFO_LHITS_BM, FTS3_MATCHINFO_LHITS => {
                const nZero: i64 = fts3MatchinfoSize(pInfo, zArg[@intCast(i)]) * @sizeOf(u32);
                _ = memset(pInfo.aMatchinfo, 0, @intCast(nZero));
                rc = fts3ExprLHitGather(pCsr.pExpr.?, pInfo);
            },

            else => {
                // assert( zArg[i]==FTS3_MATCHINFO_HITS );
                const pExpr = pCsr.pExpr.?;
                rc = fts3ExprLoadDoclists(pCsr, null, null);
                if (rc != SQLITE_OK) break;
                if (bGlobal != 0) {
                    if (pCsr.pDeferred != null) {
                        rc = fts3MatchinfoSelectDoctotal(pTab, &pSelect, &pInfo.nDoc, null, null);
                        if (rc != SQLITE_OK) break;
                    }
                    rc = sqlite3Fts3ExprIterate(pExpr, fts3ExprGlobalHitsCb, @ptrCast(pInfo));
                    _ = sqlite3Fts3EvalTestDeferred(pCsr, &rc);
                    if (rc != SQLITE_OK) break;
                }
                _ = sqlite3Fts3ExprIterate(pExpr, fts3ExprLocalHitsCb, @ptrCast(pInfo));
            },
        }

        pInfo.aMatchinfo.? += @intCast(fts3MatchinfoSize(pInfo, zArg[@intCast(i)]));
    }

    _ = sqlite3_reset(pSelect);
    return rc;
}

/// Populate pCsr->pMIBuffer with data for the current row.
fn fts3GetMatchinfo(pCtx: ?*sqlite3_context, pCsr: *Fts3Cursor, zArg: [*:0]const u8) void {
    var sInfo: MatchInfo = std.mem.zeroes(MatchInfo);
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var rc: c_int = SQLITE_OK;
    var bGlobal: c_int = 0;

    var aOut: ?[*]u32 = null;
    var xDestroyOut: DestructorFn = null;

    sInfo.pCursor = pCsr;
    sInfo.nCol = pTab.nColumn;

    // Discard cached matchinfo() if the format string differs.
    if (pCsr.pMIBuffer != null and strcmp(pCsr.pMIBuffer.?.zMatchinfo.?, zArg) != 0) {
        sqlite3Fts3MIBufferFree(pCsr.pMIBuffer);
        pCsr.pMIBuffer = null;
    }

    if (pCsr.pMIBuffer == null) {
        var nMatchinfo: i64 = 0;
        var i: c_int = 0;

        pCsr.nPhrase = fts3ExprPhraseCount(pCsr.pExpr.?);
        sInfo.nPhrase = pCsr.nPhrase;

        i = 0;
        while (zArg[@intCast(i)] != 0) : (i += 1) {
            var zErr: ?[*:0]u8 = null;
            if (fts3MatchinfoCheck(pTab, zArg[@intCast(i)], &zErr) != 0) {
                sqlite3_result_error(pCtx, zErr.?, -1);
                sqlite3_free(zErr);
                return;
            }
            nMatchinfo += fts3MatchinfoSize(&sInfo, zArg[@intCast(i)]);
        }

        pCsr.pMIBuffer = fts3MIBufferNew(nMatchinfo, zArg);
        if (pCsr.pMIBuffer == null) rc = SQLITE_NOMEM;

        pCsr.isMatchinfoNeeded = 1;
        bGlobal = 1;
    }

    if (rc == SQLITE_OK) {
        xDestroyOut = fts3MIBufferAlloc(pCsr.pMIBuffer.?, &aOut);
        if (xDestroyOut == null) {
            rc = SQLITE_NOMEM;
        }
    }

    if (rc == SQLITE_OK) {
        sInfo.aMatchinfo = aOut;
        sInfo.nPhrase = pCsr.nPhrase;
        rc = fts3MatchinfoValues(pCsr, bGlobal, &sInfo, zArg);
        if (bGlobal != 0) {
            fts3MIBufferSetGlobal(pCsr.pMIBuffer.?);
        }
    }

    if (rc != SQLITE_OK) {
        sqlite3_result_error_code(pCtx, rc);
        if (xDestroyOut) |x| x(aOut);
    } else {
        const n: c_int = pCsr.pMIBuffer.?.nElem * @sizeOf(u32);
        sqlite3_result_blob(pCtx, aOut, n, xDestroyOut);
    }
}

// ===========================================================================
// snippet()
// ===========================================================================

/// Implementation of snippet() function.
pub export fn sqlite3Fts3Snippet(
    pCtx: ?*sqlite3_context,
    pCsr: *Fts3Cursor,
    zStart: ?[*:0]const u8,
    zEnd: ?[*:0]const u8,
    zEllipsis: ?[*:0]const u8,
    iCol: c_int,
    nTokenIn: c_int,
) callconv(.c) void {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    var rc: c_int = SQLITE_OK;
    var i: c_int = undefined;
    var res: StrBuffer = .{ .z = null, .n = 0, .nAlloc = 0 };

    var nSnippet: c_int = 0;
    var aSnippet: [4]SnippetFragment = undefined;
    var nFToken: c_int = -1;
    var nToken = nTokenIn;

    if (pCsr.pExpr == null) {
        sqlite3_result_text(pCtx, "", 0, SQLITE_STATIC);
        return;
    }

    // Limit the snippet length to 64 tokens.
    if (nToken < -64) nToken = -64;
    if (nToken > 64) nToken = 64;

    nSnippet = 1;
    while (true) : (nSnippet += 1) {
        var iSnip: c_int = undefined;
        var mCovered: u64 = 0;
        var mSeen: u64 = 0;

        if (nToken >= 0) {
            nFToken = @divTrunc(nToken + nSnippet - 1, nSnippet);
        } else {
            nFToken = -1 * nToken;
        }

        iSnip = 0;
        while (iSnip < nSnippet) : (iSnip += 1) {
            var iBestScore: c_int = -1;
            var iRead: c_int = 0;
            const pFragment = &aSnippet[@intCast(iSnip)];

            _ = memset(pFragment, 0, @sizeOf(SnippetFragment));

            while (iRead < pTab.nColumn) : (iRead += 1) {
                var sF: SnippetFragment = .{ .iCol = 0, .iPos = 0, .covered = 0, .hlmask = 0 };
                var iS: c_int = 0;
                if (iCol >= 0 and iRead != iCol) continue;

                rc = fts3BestSnippet(nFToken, pCsr, iRead, mCovered, &mSeen, &sF, &iS);
                if (rc != SQLITE_OK) {
                    snippetOut(pTab, pCtx, rc, &res);
                    return;
                }
                if (iS > iBestScore) {
                    pFragment.* = sF;
                    iBestScore = iS;
                }
            }

            mCovered |= pFragment.covered;
        }

        // assert( (mCovered&mSeen)==mCovered );
        if (mSeen == mCovered or nSnippet == aSnippet.len) break;
    }

    // assert( nFToken>0 );

    i = 0;
    while (i < nSnippet and rc == SQLITE_OK) : (i += 1) {
        rc = fts3SnippetText(
            pCsr,
            &aSnippet[@intCast(i)],
            i,
            @intFromBool(i == nSnippet - 1),
            nFToken,
            zStart.?,
            zEnd.?,
            zEllipsis.?,
            &res,
        );
    }

    snippetOut(pTab, pCtx, rc, &res);
}

/// snippet_out: label body of sqlite3Fts3Snippet — close segments and emit.
fn snippetOut(pTab: *Fts3Table, pCtx: ?*sqlite3_context, rc: c_int, res: *StrBuffer) void {
    sqlite3Fts3SegmentsClose(pTab);
    if (rc != SQLITE_OK) {
        sqlite3_result_error_code(pCtx, rc);
        sqlite3_free(res.z);
    } else {
        sqlite3_result_text(pCtx, @ptrCast(res.z), -1, sqlite3_free);
    }
}

// ===========================================================================
// offsets()
// ===========================================================================

const TermOffset = extern struct {
    pList: ?[*]u8,
    iPos: i64,
    iOff: i64,
};

const TermOffsetCtx = extern struct {
    pCsr: ?*Fts3Cursor,
    iCol: c_int,
    iTerm: c_int,
    iDocid: i64,
    aTerm: ?[*]TermOffset,
};

/// sqlite3Fts3ExprIterate() callback used by sqlite3Fts3Offsets().
fn fts3ExprTermOffsetInit(pExpr: *Fts3Expr, iPhrase: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    _ = iPhrase;
    const p: *TermOffsetCtx = @ptrCast(@alignCast(ctx.?));
    var iPos: i64 = 0;

    var pList: ?[*]u8 = undefined;
    const rc = sqlite3Fts3EvalPhrasePoslist(p.pCsr.?, pExpr, p.iCol, &pList);
    const nTerm = pExpr.pPhrase.?.nToken;
    if (pList) |_| {
        var pl: [*]u8 = pList.?;
        fts3GetDeltaPosition(&pl, &iPos);
        // assert_fts3_nc( iPos>=0 );
        pList = pl;
    }

    var iTerm: c_int = 0;
    while (iTerm < nTerm) : (iTerm += 1) {
        const pT = &p.aTerm.?[@intCast(p.iTerm)];
        p.iTerm += 1;
        pT.iOff = nTerm - iTerm - 1;
        pT.pList = pList;
        pT.iPos = iPos;
    }

    return rc;
}

/// If pExpr is a phrase expression using an MSR query, restart it as a regular
/// non-incremental query.
fn fts3ExprRestartIfCb(pExpr: *Fts3Expr, iPhrase: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    _ = iPhrase;
    const p: *TermOffsetCtx = @ptrCast(@alignCast(ctx.?));
    var rc: c_int = SQLITE_OK;
    if (pExpr.pPhrase != null and pExpr.pPhrase.?.bIncr != 0) {
        rc = sqlite3Fts3MsrCancel(p.pCsr.?, pExpr);
        pExpr.pPhrase.?.bIncr = 0;
    }
    return rc;
}

/// Implementation of offsets() function.
pub export fn sqlite3Fts3Offsets(pCtx: ?*sqlite3_context, pCsr: *Fts3Cursor) callconv(.c) void {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    const pMod = pTab.pTokenizer.?.pModule.?;
    var rc: c_int = undefined;
    var nToken: c_int = undefined;
    var iCol: c_int = undefined;
    var res: StrBuffer = .{ .z = null, .n = 0, .nAlloc = 0 };
    var sCtx: TermOffsetCtx = std.mem.zeroes(TermOffsetCtx);

    if (pCsr.pExpr == null) {
        sqlite3_result_text(pCtx, "", 0, SQLITE_STATIC);
        return;
    }

    // assert( pCsr->isRequireSeek==0 );

    rc = fts3ExprLoadDoclists(pCsr, null, &nToken);
    if (rc != SQLITE_OK) return offsetsOut(pTab, pCtx, rc, &sCtx, &res);

    sCtx.aTerm = @ptrCast(@alignCast(sqlite3Fts3MallocZero(@as(i64, @sizeOf(TermOffset)) * nToken)));
    if (sCtx.aTerm == null) {
        rc = SQLITE_NOMEM;
        return offsetsOut(pTab, pCtx, rc, &sCtx, &res);
    }
    sCtx.iDocid = pCsr.iPrevId;
    sCtx.pCsr = pCsr;

    rc = sqlite3Fts3ExprIterate(pCsr.pExpr.?, fts3ExprRestartIfCb, @ptrCast(&sCtx));
    if (rc != SQLITE_OK) return offsetsOut(pTab, pCtx, rc, &sCtx, &res);

    iCol = 0;
    while (iCol < pTab.nColumn) : (iCol += 1) {
        var pC: ?*sqlite3_tokenizer_cursor = undefined;
        var ZDUMMY: ?[*]const u8 = undefined;
        var NDUMMY: c_int = 0;
        var iStart: c_int = 0;
        var iEnd: c_int = 0;
        var iCurrent: c_int = 0;

        sCtx.iCol = iCol;
        sCtx.iTerm = 0;
        rc = sqlite3Fts3ExprIterate(pCsr.pExpr.?, fts3ExprTermOffsetInit, @ptrCast(&sCtx));
        if (rc != SQLITE_OK) return offsetsOut(pTab, pCtx, rc, &sCtx, &res);

        const zDoc = sqlite3_column_text(pCsr.pStmt, iCol + 1);
        const nDoc = sqlite3_column_bytes(pCsr.pStmt, iCol + 1);
        if (zDoc == null) {
            if (sqlite3_column_type(pCsr.pStmt, iCol + 1) == SQLITE_NULL) {
                continue;
            }
            rc = SQLITE_NOMEM;
            return offsetsOut(pTab, pCtx, rc, &sCtx, &res);
        }

        rc = sqlite3Fts3OpenTokenizer(pTab.pTokenizer.?, pCsr.iLangid, @ptrCast(zDoc.?), nDoc, &pC);
        if (rc != SQLITE_OK) return offsetsOut(pTab, pCtx, rc, &sCtx, &res);

        rc = pMod.xNext.?(pC.?, &ZDUMMY, &NDUMMY, &iStart, &iEnd, &iCurrent);
        while (rc == SQLITE_OK) {
            var ii: c_int = 0;
            var iMinPos: c_int = 0x7FFFFFFF;
            var pTerm: ?*TermOffset = null;

            ii = 0;
            while (ii < nToken) : (ii += 1) {
                const pT = &sCtx.aTerm.?[@intCast(ii)];
                if (pT.pList != null and (pT.iPos - pT.iOff) < iMinPos) {
                    iMinPos = @intCast(pT.iPos - pT.iOff);
                    pTerm = pT;
                }
            }

            if (pTerm == null) {
                rc = SQLITE_DONE;
            } else {
                // assert_fts3_nc( iCurrent<=iMinPos );
                if (0 == (0xFE & pTerm.?.pList.?[0])) {
                    pTerm.?.pList = null;
                } else {
                    var pl: [*]u8 = pTerm.?.pList.?;
                    fts3GetDeltaPosition(&pl, &pTerm.?.iPos);
                    pTerm.?.pList = pl;
                }
                while (rc == SQLITE_OK and iCurrent < iMinPos) {
                    rc = pMod.xNext.?(pC.?, &ZDUMMY, &NDUMMY, &iStart, &iEnd, &iCurrent);
                }
                if (rc == SQLITE_OK) {
                    var aBuffer: [64]u8 = undefined;
                    const iTermIdx: isize = @divExact(@as(isize, @bitCast(@intFromPtr(pTerm.?) -% @intFromPtr(sCtx.aTerm.?))), @sizeOf(TermOffset));
                    _ = sqlite3_snprintf(@sizeOf(@TypeOf(aBuffer)), &aBuffer, "%d %d %d %d ", iCol, @as(c_int, @intCast(iTermIdx)), iStart, iEnd - iStart);
                    rc = fts3StringAppend(&res, &aBuffer, -1);
                } else if (rc == SQLITE_DONE and pTab.zContentTbl == null) {
                    rc = FTS_CORRUPT_VTAB();
                }
            }
        }
        if (rc == SQLITE_DONE) {
            rc = SQLITE_OK;
        }

        _ = pMod.xClose.?(pC.?);
        if (rc != SQLITE_OK) return offsetsOut(pTab, pCtx, rc, &sCtx, &res);
    }

    offsetsOut(pTab, pCtx, rc, &sCtx, &res);
}

/// offsets_out: shared cleanup/emit tail of sqlite3Fts3Offsets.
fn offsetsOut(pTab: *Fts3Table, pCtx: ?*sqlite3_context, rc: c_int, sCtx: *TermOffsetCtx, res: *StrBuffer) void {
    sqlite3_free(@ptrCast(sCtx.aTerm));
    // assert( rc!=SQLITE_DONE );
    sqlite3Fts3SegmentsClose(pTab);
    if (rc != SQLITE_OK) {
        sqlite3_result_error_code(pCtx, rc);
        sqlite3_free(res.z);
    } else {
        sqlite3_result_text(pCtx, @ptrCast(res.z), res.n - 1, sqlite3_free);
    }
}

// ===========================================================================
// matchinfo()
// ===========================================================================

/// Implementation of matchinfo() function.
pub export fn sqlite3Fts3Matchinfo(pContext: ?*sqlite3_context, pCsr: *Fts3Cursor, zArg: ?[*:0]const u8) callconv(.c) void {
    const pTab: *Fts3Table = @ptrCast(@alignCast(pCsr.base.pVtab.?));
    const zFormat: [*:0]const u8 = if (zArg) |z| z else FTS3_MATCHINFO_DEFAULT;

    if (pCsr.pExpr == null) {
        sqlite3_result_blob(pContext, "", 0, SQLITE_STATIC);
        return;
    } else {
        fts3GetMatchinfo(pContext, pCsr, zFormat);
        sqlite3Fts3SegmentsClose(pTab);
    }
}
