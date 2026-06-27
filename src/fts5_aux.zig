//! Zig port of the fts5_aux.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 3365-4187).
//!
//! The built-in FTS5 auxiliary SQL functions: highlight(), snippet(), bm25()
//! and fts5_get_locale(). Each is driven through the Fts5ExtensionApi method
//! table (foundation: fts5_int.zig) supplied by fts5_main.c at call time.
//! sqlite3Fts5AuxInit registers all four with the fts5_api.
//!
//! The bm25 scoring uses the exact IEEE-754 f64 BM25 formula from the C
//! (log/k1/b constants preserved). All struct types in this section are
//! private to it and defined locally.

const int = @import("fts5_int.zig");

const Fts5ExtensionApi = int.Fts5ExtensionApi;
const Fts5Context = int.Fts5Context;
const fts5_api = int.fts5_api;
const fts5_extension_function = int.fts5_extension_function;
const sqlite3_context = int.sqlite3_context;
const sqlite3_value = int.sqlite3_value;
const config = @import("config");

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_RANGE = int.SQLITE_RANGE;
const SQLITE_INTEGER = int.SQLITE_INTEGER;
const SQLITE_STATIC = int.SQLITE_STATIC;
const SQLITE_TRANSIENT = int.SQLITE_TRANSIENT;
const FTS5_TOKEN_COLOCATED = int.FTS5_TOKEN_COLOCATED;
const SQLITE_CORRUPT_VTAB = int.SQLITE_CORRUPT_VTAB;

// FTS5_CORRUPT: under SQLITE_DEBUG it is sqlite3Fts5Corrupt() (fts5_main.c),
// else the constant SQLITE_CORRUPT_VTAB (fts5.c 910-915).
extern fn sqlite3Fts5Corrupt() callconv(.c) c_int;
inline fn FTS5_CORRUPT() c_int {
    return if (config.sqlite_debug) sqlite3Fts5Corrupt() else SQLITE_CORRUPT_VTAB;
}

// --- libc -------------------------------------------------------------------
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn strlen(s: [*:0]const u8) usize;
extern fn log(x: f64) f64;

// --- public sqlite3 API -----------------------------------------------------
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_value_int(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(p: ?*sqlite3_value) i64;
extern fn sqlite3_value_double(p: ?*sqlite3_value) f64;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_numeric_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_result_error(p: ?*sqlite3_context, z: [*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(p: ?*sqlite3_context, rc: c_int) void;
extern fn sqlite3_result_text(p: ?*sqlite3_context, z: ?[*]const u8, n: c_int, d: int.DestructorFn) void;
extern fn sqlite3_result_double(p: ?*sqlite3_context, v: f64) void;

// xQueryPhrase callback type (Fts5ExtensionApi.xQueryPhrase).
const QueryPhraseCb = ?*const fn (?*const Fts5ExtensionApi, ?*Fts5Context, ?*anyopaque) callconv(.c) c_int;
// Tokenizer xToken callback (xTokenize / xTokenize_v2).
const TokenizeCb = ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int;

// Helpers to mirror C's MIN/MAX macros.
inline fn MIN(comptime T: type, x: T, y: T) T {
    return if (x < y) x else y;
}
inline fn MAX(comptime T: type, x: T, y: T) T {
    return if (x > y) x else y;
}

// ===========================================================================
// CInstIter (3403-3470): coalesced phrase-instance iterator.
// ===========================================================================
const CInstIter = extern struct {
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    iCol: c_int,
    iInst: c_int,
    nInst: c_int,
    iStart: c_int,
    iEnd: c_int,
};

fn fts5CInstIterNext(pIter: *CInstIter) c_int {
    var rc: c_int = SQLITE_OK;
    pIter.iStart = -1;
    pIter.iEnd = -1;

    while (rc == SQLITE_OK and pIter.iInst < pIter.nInst) {
        var ip: c_int = undefined;
        var ic: c_int = undefined;
        var io: c_int = undefined;
        rc = pIter.pApi.?.xInst.?(pIter.pFts, pIter.iInst, &ip, &ic, &io);
        if (rc == SQLITE_OK) {
            if (ic == pIter.iCol) {
                const iEnd = io - 1 + pIter.pApi.?.xPhraseSize.?(pIter.pFts, ip);
                if (pIter.iStart < 0) {
                    pIter.iStart = io;
                    pIter.iEnd = iEnd;
                } else if (io <= pIter.iEnd) {
                    if (iEnd > pIter.iEnd) pIter.iEnd = iEnd;
                } else {
                    break;
                }
            }
            pIter.iInst += 1;
        }
    }

    return rc;
}

fn fts5CInstIterInit(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    iCol: c_int,
    pIter: *CInstIter,
) c_int {
    _ = memset(pIter, 0, @sizeOf(CInstIter));
    pIter.pApi = pApi;
    pIter.pFts = pFts;
    pIter.iCol = iCol;
    var rc = pApi.?.xInstCount.?(pFts, &pIter.nInst);

    if (rc == SQLITE_OK) {
        rc = fts5CInstIterNext(pIter);
    }

    return rc;
}

// ===========================================================================
// highlight() (3473-3652)
// ===========================================================================
const HighlightContext = extern struct {
    iRangeStart: c_int,
    iRangeEnd: c_int,
    zOpen: ?[*:0]const u8,
    zClose: ?[*:0]const u8,
    zIn: ?[*:0]const u8,
    nIn: c_int,

    iter: CInstIter,
    iPos: c_int,
    iOff: c_int,
    bOpen: c_int,
    zOut: ?[*:0]u8,
};

fn fts5HighlightAppend(pRc: *c_int, p: *HighlightContext, z: ?[*]const u8, n0: c_int) void {
    var n = n0;
    if (pRc.* == SQLITE_OK and z != null) {
        if (n < 0) n = @intCast(strlen(@ptrCast(z.?)));
        p.zOut = sqlite3_mprintf("%z%.*s", p.zOut, n, z);
        if (p.zOut == null) pRc.* = SQLITE_NOMEM;
    }
}

fn fts5HighlightCb(
    pContext: ?*anyopaque,
    tflags: c_int,
    pToken: ?[*]const u8,
    nToken: c_int,
    iStartOff: c_int,
    iEndOff: c_int,
) callconv(.c) c_int {
    _ = pToken;
    _ = nToken;
    const p: *HighlightContext = @ptrCast(@alignCast(pContext.?));
    var rc: c_int = SQLITE_OK;

    if (tflags & FTS5_TOKEN_COLOCATED != 0) return SQLITE_OK;
    const iPos = p.iPos;
    p.iPos += 1;

    if (p.iRangeEnd >= 0) {
        if (iPos < p.iRangeStart or iPos > p.iRangeEnd) return SQLITE_OK;
        if (p.iRangeStart != 0 and iPos == p.iRangeStart) p.iOff = iStartOff;
    }

    // If open, this token not part of the current phrase, and its start is past
    // what's copied, close the highlight.
    if (p.bOpen != 0 and
        (iPos <= p.iter.iStart or p.iter.iStart < 0) and
        iStartOff > p.iOff)
    {
        fts5HighlightAppend(&rc, p, p.zClose, -1);
        p.bOpen = 0;
    }

    // Start of a new phrase with highlight not open.
    if (iPos == p.iter.iStart and p.bOpen == 0) {
        fts5HighlightAppend(&rc, p, addOff(p.zIn, p.iOff), iStartOff - p.iOff);
        fts5HighlightAppend(&rc, p, p.zOpen, -1);
        p.iOff = iStartOff;
        p.bOpen = 1;
    }

    if (iPos == p.iter.iEnd) {
        if (p.bOpen == 0) {
            fts5HighlightAppend(&rc, p, p.zOpen, -1);
            p.bOpen = 1;
        }
        fts5HighlightAppend(&rc, p, addOff(p.zIn, p.iOff), iEndOff - p.iOff);
        p.iOff = iEndOff;

        if (rc == SQLITE_OK) {
            rc = fts5CInstIterNext(&p.iter);
        }
    }

    if (iPos == p.iRangeEnd) {
        if (p.bOpen != 0) {
            if (p.iter.iStart >= 0 and iPos >= p.iter.iStart) {
                fts5HighlightAppend(&rc, p, addOff(p.zIn, p.iOff), iEndOff - p.iOff);
                p.iOff = iEndOff;
            }
            fts5HighlightAppend(&rc, p, p.zClose, -1);
            p.bOpen = 0;
        }
        fts5HighlightAppend(&rc, p, addOff(p.zIn, p.iOff), iEndOff - p.iOff);
        p.iOff = iEndOff;
    }

    return rc;
}

// &p->zIn[off] with a nullable base.
inline fn addOff(z: ?[*:0]const u8, off: c_int) ?[*]const u8 {
    return if (z) |zz| @as([*]const u8, @ptrCast(zz)) + @as(usize, @intCast(off)) else null;
}

fn fts5HighlightFunction(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    pCtx: ?*sqlite3_context,
    nVal: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) void {
    var ctx: HighlightContext = undefined;
    var rc: c_int = undefined;

    if (nVal != 3) {
        sqlite3_result_error(pCtx, "wrong number of arguments to function highlight()", -1);
        return;
    }

    const iCol = sqlite3_value_int(apVal.?[0]);
    _ = memset(&ctx, 0, @sizeOf(HighlightContext));
    ctx.zOpen = sqlite3_value_text(apVal.?[1]);
    ctx.zClose = sqlite3_value_text(apVal.?[2]);
    ctx.iRangeEnd = -1;
    rc = pApi.?.xColumnText.?(pFts, iCol, @ptrCast(&ctx.zIn), &ctx.nIn);
    if (rc == SQLITE_RANGE) {
        sqlite3_result_text(pCtx, "", -1, SQLITE_STATIC);
        rc = SQLITE_OK;
    } else if (ctx.zIn != null) {
        var pLoc: ?[*:0]const u8 = null;
        var nLoc: c_int = 0;
        if (rc == SQLITE_OK) {
            rc = fts5CInstIterInit(pApi, pFts, iCol, &ctx.iter);
        }
        if (rc == SQLITE_OK) {
            rc = pApi.?.xColumnLocale.?(pFts, iCol, @ptrCast(&pLoc), &nLoc);
        }
        if (rc == SQLITE_OK) {
            rc = pApi.?.xTokenize_v2.?(pFts, @ptrCast(ctx.zIn), ctx.nIn, @ptrCast(pLoc), nLoc, @ptrCast(&ctx), fts5HighlightCb);
        }
        if (ctx.bOpen != 0) {
            fts5HighlightAppend(&rc, &ctx, ctx.zClose, -1);
        }
        fts5HighlightAppend(&rc, &ctx, addOff(ctx.zIn, ctx.iOff), ctx.nIn - ctx.iOff);

        if (rc == SQLITE_OK) {
            sqlite3_result_text(pCtx, @ptrCast(ctx.zOut), -1, SQLITE_TRANSIENT);
        }
        sqlite3_free(ctx.zOut);
    }
    if (rc != SQLITE_OK) {
        sqlite3_result_error_code(pCtx, rc);
    }
}

// ===========================================================================
// snippet() supporting structures (3658-3950)
// ===========================================================================
const Fts5SFinder = extern struct {
    iPos: c_int,
    nFirstAlloc: c_int,
    nFirst: c_int,
    aFirst: ?[*]c_int,
    zDoc: ?[*:0]const u8,
};

fn fts5SentenceFinderAdd(p: *Fts5SFinder, iAdd: c_int) c_int {
    if (p.nFirstAlloc == p.nFirst) {
        const nNew: c_int = if (p.nFirstAlloc != 0) p.nFirstAlloc * 2 else 64;
        const aNew: ?[*]c_int = @ptrCast(@alignCast(sqlite3_realloc64(p.aFirst, @as(u64, @intCast(nNew)) * @sizeOf(c_int))));
        if (aNew == null) return SQLITE_NOMEM;
        p.aFirst = aNew;
        p.nFirstAlloc = nNew;
    }
    p.aFirst.?[@intCast(p.nFirst)] = iAdd;
    p.nFirst += 1;
    return SQLITE_OK;
}

fn fts5SentenceFinderCb(
    pContext: ?*anyopaque,
    tflags: c_int,
    pToken: ?[*]const u8,
    nToken: c_int,
    iStartOff: c_int,
    iEndOff: c_int,
) callconv(.c) c_int {
    _ = pToken;
    _ = nToken;
    _ = iEndOff;
    var rc: c_int = SQLITE_OK;

    if ((tflags & FTS5_TOKEN_COLOCATED) == 0) {
        const p: *Fts5SFinder = @ptrCast(@alignCast(pContext.?));
        if (p.iPos > 0) {
            var c: u8 = 0;
            var i: c_int = iStartOff - 1;
            while (i >= 0) : (i -= 1) {
                c = p.zDoc.?[@intCast(i)];
                if (c != ' ' and c != '\t' and c != '\n' and c != '\r') break;
            }
            if (i != iStartOff - 1 and (c == '.' or c == ':')) {
                rc = fts5SentenceFinderAdd(p, p.iPos);
            }
        } else {
            rc = fts5SentenceFinderAdd(p, 0);
        }
        p.iPos += 1;
    }
    return rc;
}

fn fts5SnippetScore(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    nDocsize: c_int,
    aSeen: [*]u8,
    iCol: c_int,
    iPos: c_int,
    nToken: c_int,
    pnScore: *c_int,
    piPos: ?*c_int,
) c_int {
    var ip: c_int = 0;
    var ic: c_int = 0;
    var iOff: c_int = 0;
    var iFirst: c_int = -1;
    var nInst: c_int = undefined;
    var nScore: c_int = 0;
    var iLast: c_int = 0;
    const iEnd: i64 = @as(i64, iPos) + nToken;

    var rc = pApi.?.xInstCount.?(pFts, &nInst);
    var i: c_int = 0;
    while (i < nInst and rc == SQLITE_OK) : (i += 1) {
        rc = pApi.?.xInst.?(pFts, i, &ip, &ic, &iOff);
        if (rc == SQLITE_OK and ic == iCol and iOff >= iPos and iOff < iEnd) {
            nScore += if (aSeen[@intCast(ip)] != 0) 1 else 1000;
            aSeen[@intCast(ip)] = 1;
            if (iFirst < 0) iFirst = iOff;
            iLast = iOff + pApi.?.xPhraseSize.?(pFts, ip);
        }
    }

    pnScore.* = nScore;
    if (piPos) |pp| {
        var iAdj: i64 = iFirst - @divTrunc(nToken - (iLast - iFirst), 2);
        if ((iAdj + nToken) > nDocsize) iAdj = nDocsize - nToken;
        if (iAdj < 0) iAdj = 0;
        pp.* = @intCast(iAdj);
    }

    return rc;
}

fn fts5ValueToText(pVal: ?*sqlite3_value) [*:0]const u8 {
    const zRet = sqlite3_value_text(pVal);
    return if (zRet) |z| z else "";
}

fn fts5SnippetFunction(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    pCtx: ?*sqlite3_context,
    nVal: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) void {
    var ctx: HighlightContext = undefined;
    var rc: c_int = SQLITE_OK;
    var nInst: c_int = 0;
    var iBestStart: c_int = 0;
    var nBestScore: c_int = 0;
    var nColSize: c_int = 0;
    var sFinder: Fts5SFinder = undefined;

    if (nVal != 5) {
        sqlite3_result_error(pCtx, "wrong number of arguments to function snippet()", -1);
        return;
    }

    const nCol = pApi.?.xColumnCount.?(pFts);
    _ = memset(&ctx, 0, @sizeOf(HighlightContext));
    const iCol = sqlite3_value_int(apVal.?[0]);
    ctx.zOpen = fts5ValueToText(apVal.?[1]);
    ctx.zClose = fts5ValueToText(apVal.?[2]);
    ctx.iRangeEnd = -1;
    const zEllips = fts5ValueToText(apVal.?[3]);
    const nToken: c_int = @intCast(MIN(i64, MAX(i64, sqlite3_value_int64(apVal.?[4]), 0), 64));

    var iBestCol: c_int = if (iCol >= 0) iCol else 0;
    const nPhrase = pApi.?.xPhraseCount.?(pFts);
    const aSeen: ?[*]u8 = @ptrCast(sqlite3_malloc64(@intCast(nPhrase)));
    if (aSeen == null) {
        rc = SQLITE_NOMEM;
    }
    if (rc == SQLITE_OK) {
        rc = pApi.?.xInstCount.?(pFts, &nInst);
    }

    _ = memset(&sFinder, 0, @sizeOf(Fts5SFinder));
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        if (iCol < 0 or iCol == i) {
            var pLoc: ?[*:0]const u8 = null;
            var nLoc: c_int = 0;
            var nDoc: c_int = undefined;
            var nDocsize: c_int = undefined;
            sFinder.iPos = 0;
            sFinder.nFirst = 0;
            rc = pApi.?.xColumnText.?(pFts, i, @ptrCast(&sFinder.zDoc), &nDoc);
            if (rc != SQLITE_OK) break;
            rc = pApi.?.xColumnLocale.?(pFts, i, @ptrCast(&pLoc), &nLoc);
            if (rc != SQLITE_OK) break;
            rc = pApi.?.xTokenize_v2.?(pFts, @ptrCast(sFinder.zDoc), nDoc, @ptrCast(pLoc), nLoc, @ptrCast(&sFinder), fts5SentenceFinderCb);
            if (rc != SQLITE_OK) break;
            rc = pApi.?.xColumnSize.?(pFts, i, &nDocsize);
            if (rc != SQLITE_OK) break;

            var ii: c_int = 0;
            while (rc == SQLITE_OK and ii < nInst) : (ii += 1) {
                var ip: c_int = undefined;
                var ic: c_int = undefined;
                var io: c_int = undefined;
                var iAdj: c_int = undefined;
                var nScore: c_int = undefined;

                rc = pApi.?.xInst.?(pFts, ii, &ip, &ic, &io);
                if (ic != i) continue;
                if (io > nDocsize) rc = FTS5_CORRUPT();
                if (rc != SQLITE_OK) continue;
                _ = memset(aSeen, 0, @intCast(nPhrase));
                rc = fts5SnippetScore(pApi, pFts, nDocsize, aSeen.?, i, io, nToken, &nScore, &iAdj);
                if (rc == SQLITE_OK and nScore > nBestScore) {
                    nBestScore = nScore;
                    iBestCol = i;
                    iBestStart = iAdj;
                    nColSize = nDocsize;
                }

                if (rc == SQLITE_OK and sFinder.nFirst != 0 and nDocsize > nToken) {
                    var jj: c_int = 0;
                    while (jj < (sFinder.nFirst - 1)) : (jj += 1) {
                        if (sFinder.aFirst.?[@intCast(jj + 1)] > io) break;
                    }

                    if (sFinder.aFirst.?[@intCast(jj)] < io) {
                        _ = memset(aSeen, 0, @intCast(nPhrase));
                        rc = fts5SnippetScore(pApi, pFts, nDocsize, aSeen.?, i, sFinder.aFirst.?[@intCast(jj)], nToken, &nScore, null);

                        nScore += if (sFinder.aFirst.?[@intCast(jj)] == 0) @as(c_int, 120) else 100;
                        if (rc == SQLITE_OK and nScore > nBestScore) {
                            nBestScore = nScore;
                            iBestCol = i;
                            iBestStart = sFinder.aFirst.?[@intCast(jj)];
                            nColSize = nDocsize;
                        }
                    }
                }
            }
        }
    }

    if (rc == SQLITE_OK) {
        rc = pApi.?.xColumnText.?(pFts, iBestCol, @ptrCast(&ctx.zIn), &ctx.nIn);
    }
    if (rc == SQLITE_OK and nColSize == 0) {
        rc = pApi.?.xColumnSize.?(pFts, iBestCol, &nColSize);
    }
    if (ctx.zIn != null) {
        var pLoc: ?[*:0]const u8 = null;
        var nLoc: c_int = 0;

        if (rc == SQLITE_OK) {
            rc = fts5CInstIterInit(pApi, pFts, iBestCol, &ctx.iter);
        }

        ctx.iRangeStart = iBestStart;
        ctx.iRangeEnd = iBestStart + nToken - 1;

        if (iBestStart > 0) {
            fts5HighlightAppend(&rc, &ctx, zEllips, -1);
        }

        // Advance ctx.iter to the first coalesced instance at/following iBestStart.
        while (ctx.iter.iStart >= 0 and ctx.iter.iStart < iBestStart and rc == SQLITE_OK) {
            rc = fts5CInstIterNext(&ctx.iter);
        }

        if (rc == SQLITE_OK) {
            rc = pApi.?.xColumnLocale.?(pFts, iBestCol, @ptrCast(&pLoc), &nLoc);
        }
        if (rc == SQLITE_OK) {
            rc = pApi.?.xTokenize_v2.?(pFts, @ptrCast(ctx.zIn), ctx.nIn, @ptrCast(pLoc), nLoc, @ptrCast(&ctx), fts5HighlightCb);
        }
        if (ctx.bOpen != 0) {
            fts5HighlightAppend(&rc, &ctx, ctx.zClose, -1);
        }
        if (ctx.iRangeEnd >= (nColSize - 1)) {
            fts5HighlightAppend(&rc, &ctx, addOff(ctx.zIn, ctx.iOff), ctx.nIn - ctx.iOff);
        } else {
            fts5HighlightAppend(&rc, &ctx, zEllips, -1);
        }
    }
    if (rc == SQLITE_OK) {
        sqlite3_result_text(pCtx, @ptrCast(ctx.zOut), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_error_code(pCtx, rc);
    }
    sqlite3_free(ctx.zOut);
    sqlite3_free(aSeen);
    sqlite3_free(sFinder.aFirst);
}

// ===========================================================================
// bm25() (3955-4112)
// ===========================================================================
const Fts5Bm25Data = extern struct {
    nPhrase: c_int,
    avgdl: f64,
    aIDF: ?[*]f64,
    aFreq: ?[*]f64,
};

fn fts5CountCb(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    pUserData: ?*anyopaque,
) callconv(.c) c_int {
    _ = pApi;
    _ = pFts;
    const pn: *i64 = @ptrCast(@alignCast(pUserData.?));
    pn.* += 1;
    return SQLITE_OK;
}

fn fts5Bm25GetData(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    ppData: *?*Fts5Bm25Data,
) c_int {
    var rc: c_int = SQLITE_OK;
    var p: ?*Fts5Bm25Data = @ptrCast(@alignCast(pApi.?.xGetAuxdata.?(pFts, 0)));
    if (p == null) {
        var nRow: i64 = 0;
        var nToken: i64 = 0;

        const nPhrase = pApi.?.xPhraseCount.?(pFts);
        const nByte: i64 = @sizeOf(Fts5Bm25Data) + @as(i64, nPhrase) * 2 * @sizeOf(f64);
        p = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte))));
        if (p == null) {
            rc = SQLITE_NOMEM;
        } else {
            const pp = p.?;
            _ = memset(pp, 0, @intCast(nByte));
            pp.nPhrase = nPhrase;
            // aIDF = (double*)&p[1]; aFreq = &aIDF[nPhrase].
            const aIDF: [*]f64 = @ptrCast(@as([*]Fts5Bm25Data, @ptrCast(pp)) + 1);
            pp.aIDF = aIDF;
            pp.aFreq = aIDF + @as(usize, @intCast(nPhrase));
        }

        if (rc == SQLITE_OK) rc = pApi.?.xRowCount.?(pFts, &nRow);
        if (rc == SQLITE_OK) rc = pApi.?.xColumnTotalSize.?(pFts, -1, &nToken);
        if (rc == SQLITE_OK) p.?.avgdl = @as(f64, @floatFromInt(nToken)) / @as(f64, @floatFromInt(nRow));

        var i: c_int = 0;
        while (rc == SQLITE_OK and i < nPhrase) : (i += 1) {
            var nHit: i64 = 0;
            rc = pApi.?.xQueryPhrase.?(pFts, i, @ptrCast(&nHit), fts5CountCb);
            if (rc == SQLITE_OK) {
                // IDF = log( (N - nHit + 0.5) / (nHit + 0.5) ); min 1e-6.
                var idf = log((@as(f64, @floatFromInt(nRow)) - @as(f64, @floatFromInt(nHit)) + 0.5) /
                    (@as(f64, @floatFromInt(nHit)) + 0.5));
                if (idf <= 0.0) idf = 1e-6;
                p.?.aIDF.?[@intCast(i)] = idf;
            }
        }

        if (rc != SQLITE_OK) {
            sqlite3_free(p);
        } else {
            rc = pApi.?.xSetAuxdata.?(pFts, p, sqlite3_free);
        }
        if (rc != SQLITE_OK) p = null;
    }
    ppData.* = p;
    return rc;
}

fn fts5Bm25Function(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    pCtx: ?*sqlite3_context,
    nVal: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) void {
    const k1: f64 = 1.2;
    const b: f64 = 0.75;
    var score: f64 = 0.0;
    var pData: ?*Fts5Bm25Data = undefined;
    var nInst: c_int = 0;
    var D: f64 = 0.0;
    var aFreq: ?[*]f64 = null;

    var rc = fts5Bm25GetData(pApi, pFts, &pData);
    if (rc == SQLITE_OK) {
        aFreq = pData.?.aFreq;
        _ = memset(aFreq, 0, @sizeOf(f64) * @as(usize, @intCast(pData.?.nPhrase)));
        rc = pApi.?.xInstCount.?(pFts, &nInst);
    }
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nInst) : (i += 1) {
        var ip: c_int = undefined;
        var ic: c_int = undefined;
        var io: c_int = undefined;
        rc = pApi.?.xInst.?(pFts, i, &ip, &ic, &io);
        if (rc == SQLITE_OK) {
            const w: f64 = if (nVal > ic) sqlite3_value_double(apVal.?[@intCast(ic)]) else 1.0;
            aFreq.?[@intCast(ip)] += w;
        }
    }

    // Total size of the current row in tokens.
    if (rc == SQLITE_OK) {
        var nTok: c_int = undefined;
        rc = pApi.?.xColumnSize.?(pFts, -1, &nTok);
        D = @floatFromInt(nTok);
    }

    if (rc == SQLITE_OK) {
        i = 0;
        while (i < pData.?.nPhrase) : (i += 1) {
            score += pData.?.aIDF.?[@intCast(i)] * ((aFreq.?[@intCast(i)] * (k1 + 1.0)) /
                (aFreq.?[@intCast(i)] + k1 * (1 - b + b * D / pData.?.avgdl)));
        }
        sqlite3_result_double(pCtx, -1.0 * score);
    } else {
        sqlite3_result_error_code(pCtx, rc);
    }
}

// ===========================================================================
// fts5_get_locale() (4114-4158)
// ===========================================================================
fn fts5GetLocaleFunction(
    pApi: ?*const Fts5ExtensionApi,
    pFts: ?*Fts5Context,
    pCtx: ?*sqlite3_context,
    nVal: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) void {
    var zLocale: ?[*:0]const u8 = null;
    var nLocale: c_int = 0;

    if (nVal != 1) {
        sqlite3_result_error(pCtx, "wrong number of arguments to function fts5_get_locale()", -1);
        return;
    }

    const eType = sqlite3_value_numeric_type(apVal.?[0]);
    if (eType != SQLITE_INTEGER) {
        sqlite3_result_error(pCtx, "non-integer argument passed to function fts5_get_locale()", -1);
        return;
    }

    const iCol = sqlite3_value_int(apVal.?[0]);
    if (iCol < 0 or iCol >= pApi.?.xColumnCount.?(pFts)) {
        sqlite3_result_error_code(pCtx, SQLITE_RANGE);
        return;
    }

    const rc = pApi.?.xColumnLocale.?(pFts, iCol, @ptrCast(&zLocale), &nLocale);
    if (rc != SQLITE_OK) {
        sqlite3_result_error_code(pCtx, rc);
        return;
    }

    sqlite3_result_text(pCtx, @ptrCast(zLocale), nLocale, SQLITE_TRANSIENT);
}

/// fts5_aux.c 4161-4187: register all built-in auxiliary functions. EXPORTED.
export fn sqlite3Fts5AuxInit(pApi: *fts5_api) callconv(.c) c_int {
    const Builtin = struct {
        zFunc: [*:0]const u8,
        pUserData: ?*anyopaque,
        xFunc: fts5_extension_function,
        xDestroy: ?*const fn (?*anyopaque) callconv(.c) void,
    };
    const aBuiltin = [_]Builtin{
        .{ .zFunc = "snippet", .pUserData = null, .xFunc = fts5SnippetFunction, .xDestroy = null },
        .{ .zFunc = "highlight", .pUserData = null, .xFunc = fts5HighlightFunction, .xDestroy = null },
        .{ .zFunc = "bm25", .pUserData = null, .xFunc = fts5Bm25Function, .xDestroy = null },
        .{ .zFunc = "fts5_get_locale", .pUserData = null, .xFunc = fts5GetLocaleFunction, .xDestroy = null },
    };

    var rc: c_int = SQLITE_OK;
    var i: usize = 0;
    while (rc == SQLITE_OK and i < aBuiltin.len) : (i += 1) {
        rc = pApi.xCreateFunction.?(pApi, aBuiltin[i].zFunc, aBuiltin[i].pUserData, aBuiltin[i].xFunc, aBuiltin[i].xDestroy);
    }

    return rc;
}

comptime {
    _ = int;
}
