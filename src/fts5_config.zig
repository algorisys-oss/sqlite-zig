//! Zig port of the fts5_config.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 4601-5727).
//!
//! The Fts5Config object: it parses the CREATE VIRTUAL TABLE argument vector
//! (column list + prefix/tokenize/content/detail/... directives), declares the
//! vtab schema to SQLite, loads/sets %_config-table key/value attributes
//! (pgsz/automerge/rank/secure-delete/...), parses the rank() specification,
//! and tokenizes text through the configured tokenizer.
//!
//! The Fts5Config / Fts5TokenizerConfig layouts live in the shared foundation
//! (fts5_int.zig); every other section reaches them only by pointer. Sibling-
//! section symbols (Fts5Buffer*, Fts5MallocZero/Strndup/Mprintf from
//! fts5_buffer.c, Fts5IsBareword, the tokenizer loader from fts5_main.c) are
//! resolved at link time via `extern fn` within the single FTS5 object.

const int = @import("fts5_int.zig");
const config = @import("config");

const Fts5Config = int.Fts5Config;
const Fts5Buffer = int.Fts5Buffer;
const Fts5Global = int.Fts5Global;
const fts5_tokenizer = int.fts5_tokenizer;
const fts5_tokenizer_v2 = int.fts5_tokenizer_v2;
const Fts5Tokenizer = int.Fts5Tokenizer;
const sqlite3 = int.sqlite3;
const sqlite3_value = int.sqlite3_value;
const sqlite3_stmt = int.sqlite3_stmt;

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_ERROR = int.SQLITE_ERROR;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_ROW = int.SQLITE_ROW;
const SQLITE_INTEGER = int.SQLITE_INTEGER;

const FTS5_MAX_PREFIX_INDEXES = int.FTS5_MAX_PREFIX_INDEXES;
const FTS5_MAX_SEGMENT = int.FTS5_MAX_SEGMENT;
const FTS5_RANK_NAME = int.FTS5_RANK_NAME;
const FTS5_ROWID_NAME = int.FTS5_ROWID_NAME;
const FTS5_CONTENT_NORMAL = int.FTS5_CONTENT_NORMAL;
const FTS5_CONTENT_NONE = int.FTS5_CONTENT_NONE;
const FTS5_CONTENT_EXTERNAL = int.FTS5_CONTENT_EXTERNAL;
const FTS5_CONTENT_UNINDEXED = int.FTS5_CONTENT_UNINDEXED;
const FTS5_DETAIL_FULL = int.FTS5_DETAIL_FULL;
const FTS5_DETAIL_NONE = int.FTS5_DETAIL_NONE;
const FTS5_DETAIL_COLUMNS = int.FTS5_DETAIL_COLUMNS;
const FTS5_CURRENT_VERSION = int.FTS5_CURRENT_VERSION;
const FTS5_CURRENT_VERSION_SECUREDELETE = int.FTS5_CURRENT_VERSION_SECUREDELETE;

// fts5_config.c #defines (lines 20-29).
const FTS5_DEFAULT_PAGE_SIZE: c_int = 4050;
const FTS5_DEFAULT_AUTOMERGE: c_int = 4;
const FTS5_DEFAULT_USERMERGE: c_int = 4;
const FTS5_DEFAULT_CRISISMERGE: c_int = 16;
const FTS5_DEFAULT_HASHSIZE: c_int = 1024 * 1024;
const FTS5_DEFAULT_DELETE_AUTOMERGE: c_int = 10; // default 10%
const FTS5_MAX_PAGE_SIZE: c_int = 64 * 1024;

// --- libc -------------------------------------------------------------------
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn strlen(s: [*:0]const u8) usize;

// --- public sqlite3 API -----------------------------------------------------
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *anyopaque) ?[*:0]u8;
extern fn sqlite3_stricmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn sqlite3_strnicmp(a: [*:0]const u8, b: [*:0]const u8, n: c_int) c_int;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSql: [*:0]const u8) c_int;
extern fn sqlite3_prepare_v2(db: ?*sqlite3, zSql: [*:0]const u8, nByte: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_finalize(p: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_text(p: ?*sqlite3_stmt, i: c_int) ?[*:0]const u8;
extern fn sqlite3_column_value(p: ?*sqlite3_stmt, i: c_int) ?*sqlite3_value;
extern fn sqlite3_value_int(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_numeric_type(p: ?*sqlite3_value) c_int;

// --- sibling section: fts5_buffer.c -----------------------------------------
extern fn sqlite3Fts5MallocZero(pRc: *c_int, nByte: i64) callconv(.c) ?*anyopaque;
extern fn sqlite3Fts5Strndup(pRc: *c_int, pIn: [*]const u8, nIn: c_int) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5Mprintf(pRc: *c_int, zFmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5BufferAppendPrintf(pRc: *c_int, pBuf: *Fts5Buffer, zFmt: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3Fts5IsBareword(t: u8) callconv(.c) c_int;

// --- sibling section: fts5_main.c -------------------------------------------
extern fn sqlite3Fts5LoadTokenizer(pConfig: *Fts5Config) callconv(.c) c_int;

// xToken callback type used by sqlite3Fts5Tokenize().
const XTokenFn = ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int;

// ===========================================================================
// Small character classifiers (fts5_config.c 31-66). Inlined; note these test
// `char` (signed on this platform) so values >=0x80 are negative and fall out
// of all the ranges, matching the C exactly.
// ===========================================================================
inline fn fts5_iswhitespace(x: u8) bool {
    return x == ' ';
}
inline fn fts5_isopenquote(x: u8) bool {
    return x == '"' or x == '\'' or x == '[' or x == '`';
}
inline fn fts5_isdigit(a: u8) bool {
    return a >= '0' and a <= '9';
}

/// fts5_config.c 44-50: skip leading whitespace.
fn fts5ConfigSkipWhitespace(pIn: ?[*:0]const u8) ?[*:0]const u8 {
    var p = pIn;
    if (p) |pp0| {
        var pp = pp0;
        while (fts5_iswhitespace(pp[0])) pp += 1;
        p = pp;
    }
    return p;
}

/// fts5_config.c 57-62: skip a run of bareword characters; NULL if none.
fn fts5ConfigSkipBareword(pIn: [*:0]const u8) ?[*:0]const u8 {
    var p: [*:0]const u8 = pIn;
    while (sqlite3Fts5IsBareword(p[0]) != 0) p += 1;
    if (p == pIn) return null;
    return p;
}

/// fts5_config.c 70-131: skip one SQL literal (null/blob/string/number).
fn fts5ConfigSkipLiteral(pIn: [*:0]const u8) ?[*:0]const u8 {
    var p: ?[*:0]const u8 = pIn;
    const c0 = pIn[0];
    switch (c0) {
        'n', 'N' => {
            if (sqlite3_strnicmp("null", pIn, 4) == 0) {
                p = pIn + 4;
            } else {
                p = null;
            }
        },
        'x', 'X' => {
            var pp = pIn + 1;
            if (pp[0] == '\'') {
                pp += 1;
                while ((pp[0] >= 'a' and pp[0] <= 'f') or
                    (pp[0] >= 'A' and pp[0] <= 'F') or
                    (pp[0] >= '0' and pp[0] <= '9'))
                {
                    pp += 1;
                }
                if (pp[0] == '\'' and 0 == (@intFromPtr(pp) - @intFromPtr(pIn)) % 2) {
                    p = pp + 1;
                } else {
                    p = null;
                }
            } else {
                p = null;
            }
        },
        '\'' => {
            var pp: ?[*:0]const u8 = pIn + 1;
            while (pp) |q0| {
                var q = q0;
                if (q[0] == '\'') {
                    q += 1;
                    if (q[0] != '\'') {
                        pp = q;
                        break;
                    }
                }
                q += 1;
                if (q[0] == 0) {
                    pp = null;
                    break;
                }
                pp = q;
            }
            p = pp;
        },
        else => {
            // maybe a number
            var pp = pIn;
            if (pp[0] == '+' or pp[0] == '-') pp += 1;
            while (fts5_isdigit(pp[0])) pp += 1;
            if (pp[0] == '.' and fts5_isdigit(pp[1])) {
                pp += 2;
                while (fts5_isdigit(pp[0])) pp += 1;
            }
            if (pp == pIn) {
                p = null;
            } else {
                p = pp;
            }
        },
    }
    return p;
}

/// fts5_config.c 146-176: dequote z[] in place. Returns byte offset of the
/// character following the close quote, or -1 if no close quote found.
fn fts5Dequote(z: [*]u8) c_int {
    var q = z[0];
    var iIn: c_int = 1;
    var iOut: c_int = 0;

    // q == '[' | '\'' | '"' | '`'
    if (q == '[') q = ']';

    while (z[@intCast(iIn)] != 0) {
        if (z[@intCast(iIn)] == q) {
            if (z[@intCast(iIn + 1)] != q) {
                // close quote
                iIn += 1;
                break;
            } else {
                iIn += 2;
                z[@intCast(iOut)] = q;
                iOut += 1;
            }
        } else {
            z[@intCast(iOut)] = z[@intCast(iIn)];
            iOut += 1;
            iIn += 1;
        }
    }

    z[@intCast(iOut)] = 0;
    return iIn;
}

/// fts5_config.c 191-199: dequote an SQL-quoted string in place (no-op if not
/// quoted). EXPORTED — called from fts5_main.c.
export fn sqlite3Fts5Dequote(z: [*]u8) callconv(.c) void {
    const quote = z[0];
    if (quote == '[' or quote == '\'' or quote == '"' or quote == '`') {
        _ = fts5Dequote(z);
    }
}

// ===========================================================================
// Fts5Enum: name->value lookup table for the detail= directive (202-226).
// ===========================================================================
const Fts5Enum = extern struct {
    zName: ?[*:0]const u8,
    eVal: c_int,
};

fn fts5ConfigSetEnum(aEnum: [*]const Fts5Enum, zEnum: [*:0]const u8, peVal: *c_int) c_int {
    const nEnum: c_int = @intCast(strlen(zEnum));
    var iVal: c_int = -1;
    var i: usize = 0;
    while (aEnum[i].zName) |zName| : (i += 1) {
        if (sqlite3_strnicmp(zName, zEnum, nEnum) == 0) {
            if (iVal >= 0) return SQLITE_ERROR;
            iVal = aEnum[i].eVal;
        }
    }
    peVal.* = iVal;
    return if (iVal < 0) SQLITE_ERROR else SQLITE_OK;
}

// ===========================================================================
// fts5ConfigParseSpecial (237-431): parse one "key=value" CREATE option.
// ===========================================================================
fn fts5ConfigParseSpecial(
    pConfig: *Fts5Config,
    zCmd: [*:0]const u8,
    zArg: [*:0]const u8,
    pzErr: *?[*:0]u8,
) c_int {
    var rc: c_int = SQLITE_OK;
    const nCmd: c_int = @intCast(strlen(zCmd));

    if (sqlite3_strnicmp("prefix", zCmd, nCmd) == 0) {
        const nByte: c_int = @sizeOf(c_int) * FTS5_MAX_PREFIX_INDEXES;
        var bFirst: c_int = 1;
        if (pConfig.aPrefix == null) {
            pConfig.aPrefix = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
            if (rc != 0) return rc;
        }

        var p: [*:0]const u8 = zArg;
        while (true) {
            var nPre: c_int = 0;

            while (p[0] == ' ') p += 1;
            if (bFirst == 0 and p[0] == ',') {
                p += 1;
                while (p[0] == ' ') p += 1;
            } else if (p[0] == 0) {
                break;
            }
            if (p[0] < '0' or p[0] > '9') {
                pzErr.* = sqlite3_mprintf("malformed prefix=... directive");
                rc = SQLITE_ERROR;
                break;
            }

            if (pConfig.nPrefix == FTS5_MAX_PREFIX_INDEXES) {
                pzErr.* = sqlite3_mprintf("too many prefix indexes (max %d)", FTS5_MAX_PREFIX_INDEXES);
                rc = SQLITE_ERROR;
                break;
            }

            while (p[0] >= '0' and p[0] <= '9' and nPre < 1000) {
                nPre = nPre * 10 + (p[0] - '0');
                p += 1;
            }

            if (nPre <= 0 or nPre >= 1000) {
                pzErr.* = sqlite3_mprintf("prefix length out of range (max 999)");
                rc = SQLITE_ERROR;
                break;
            }

            pConfig.aPrefix.?[@intCast(pConfig.nPrefix)] = nPre;
            pConfig.nPrefix += 1;
            bFirst = 0;
        }
        return rc;
    }

    if (sqlite3_strnicmp("tokenize", zCmd, nCmd) == 0) {
        var p: ?[*:0]const u8 = zArg;
        var nArg: i64 = @as(i64, @intCast(strlen(zArg))) + 1;
        var azArg: ?[*]?[*:0]u8 = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, (@sizeOf(usize) + 2) * nArg)));

        if (azArg) |aa| {
            // pSpace points to the byte region after the nArg pointers.
            var pSpace: [*]u8 = @ptrCast(&aa[@intCast(nArg)]);
            if (pConfig.t.azArg != null) {
                pzErr.* = sqlite3_mprintf("multiple tokenize=... directives");
                rc = SQLITE_ERROR;
            } else {
                nArg = 0;
                while (p != null and p.?[0] != 0) : (nArg += 1) {
                    const p2 = fts5ConfigSkipWhitespace(p).?;
                    if (p2[0] == '\'') {
                        p = fts5ConfigSkipLiteral(p2);
                    } else {
                        p = fts5ConfigSkipBareword(p2);
                    }
                    if (p) |pp| {
                        const n: usize = @intFromPtr(pp) - @intFromPtr(p2);
                        _ = memcpy(pSpace, p2, n);
                        aa[@intCast(nArg)] = @ptrCast(pSpace);
                        sqlite3Fts5Dequote(pSpace);
                        pSpace += n + 1;
                        p = fts5ConfigSkipWhitespace(pp);
                    }
                }
                if (p == null) {
                    pzErr.* = sqlite3_mprintf("parse error in tokenize directive");
                    rc = SQLITE_ERROR;
                } else {
                    pConfig.t.azArg = @ptrCast(azArg);
                    pConfig.t.nArg = @intCast(nArg);
                    azArg = null;
                }
            }
        }
        sqlite3_free(@ptrCast(azArg));
        return rc;
    }

    if (sqlite3_strnicmp("content", zCmd, nCmd) == 0) {
        if (pConfig.eContent != FTS5_CONTENT_NORMAL) {
            pzErr.* = sqlite3_mprintf("multiple content=... directives");
            rc = SQLITE_ERROR;
        } else {
            if (zArg[0] != 0) {
                pConfig.eContent = FTS5_CONTENT_EXTERNAL;
                pConfig.zContent = sqlite3Fts5Mprintf(&rc, "%Q.%Q", pConfig.zDb, zArg);
            } else {
                pConfig.eContent = FTS5_CONTENT_NONE;
            }
        }
        return rc;
    }

    if (sqlite3_strnicmp("contentless_delete", zCmd, nCmd) == 0) {
        if ((zArg[0] != '0' and zArg[0] != '1') or zArg[1] != 0) {
            pzErr.* = sqlite3_mprintf("malformed contentless_delete=... directive");
            rc = SQLITE_ERROR;
        } else {
            pConfig.bContentlessDelete = @intFromBool(zArg[0] == '1');
        }
        return rc;
    }

    if (sqlite3_strnicmp("contentless_unindexed", zCmd, nCmd) == 0) {
        if ((zArg[0] != '0' and zArg[0] != '1') or zArg[1] != 0) {
            pzErr.* = sqlite3_mprintf("malformed contentless_delete=... directive");
            rc = SQLITE_ERROR;
        } else {
            pConfig.bContentlessUnindexed = @intFromBool(zArg[0] == '1');
        }
        return rc;
    }

    if (sqlite3_strnicmp("content_rowid", zCmd, nCmd) == 0) {
        if (pConfig.zContentRowid != null) {
            pzErr.* = sqlite3_mprintf("multiple content_rowid=... directives");
            rc = SQLITE_ERROR;
        } else {
            pConfig.zContentRowid = sqlite3Fts5Strndup(&rc, zArg, -1);
        }
        return rc;
    }

    if (sqlite3_strnicmp("columnsize", zCmd, nCmd) == 0) {
        if ((zArg[0] != '0' and zArg[0] != '1') or zArg[1] != 0) {
            pzErr.* = sqlite3_mprintf("malformed columnsize=... directive");
            rc = SQLITE_ERROR;
        } else {
            pConfig.bColumnsize = @intFromBool(zArg[0] == '1');
        }
        return rc;
    }

    if (sqlite3_strnicmp("locale", zCmd, nCmd) == 0) {
        if ((zArg[0] != '0' and zArg[0] != '1') or zArg[1] != 0) {
            pzErr.* = sqlite3_mprintf("malformed locale=... directive");
            rc = SQLITE_ERROR;
        } else {
            pConfig.bLocale = @intFromBool(zArg[0] == '1');
        }
        return rc;
    }

    if (sqlite3_strnicmp("detail", zCmd, nCmd) == 0) {
        const aDetail = [_]Fts5Enum{
            .{ .zName = "none", .eVal = FTS5_DETAIL_NONE },
            .{ .zName = "full", .eVal = FTS5_DETAIL_FULL },
            .{ .zName = "columns", .eVal = FTS5_DETAIL_COLUMNS },
            .{ .zName = null, .eVal = 0 },
        };
        rc = fts5ConfigSetEnum(&aDetail, zArg, &pConfig.eDetail);
        if (rc != 0) {
            pzErr.* = sqlite3_mprintf("malformed detail=... directive");
        }
        return rc;
    }

    if (sqlite3_strnicmp("tokendata", zCmd, nCmd) == 0) {
        if ((zArg[0] != '0' and zArg[0] != '1') or zArg[1] != 0) {
            pzErr.* = sqlite3_mprintf("malformed tokendata=... directive");
            rc = SQLITE_ERROR;
        } else {
            pConfig.bTokendata = @intFromBool(zArg[0] == '1');
        }
        return rc;
    }

    pzErr.* = sqlite3_mprintf("unrecognized option: \"%.*s\"", nCmd, zCmd);
    return SQLITE_ERROR;
}

/// fts5_config.c 448-486: gobble one bareword/quoted word; produce a dequoted
/// malloc'd copy in *pzOut. Returns the position past the word, or NULL on
/// parse error (close-quote not found).
fn fts5ConfigGobbleWord(
    pRc: *c_int,
    zIn: [*:0]const u8,
    pzOut: *?[*:0]u8,
    pbQuoted: *c_int,
) ?[*:0]const u8 {
    var zRet: ?[*:0]const u8 = null;

    const nIn: i64 = @intCast(strlen(zIn));
    const zOut: ?[*]u8 = @ptrCast(sqlite3_malloc64(@intCast(nIn + 1)));

    pbQuoted.* = 0;
    pzOut.* = null;

    if (zOut) |zo| {
        _ = memcpy(zo, zIn, @intCast(nIn + 1));
        if (fts5_isopenquote(zo[0])) {
            const ii = fts5Dequote(zo);
            zRet = zIn + @as(usize, @intCast(ii));
            pbQuoted.* = 1;
        } else {
            zRet = fts5ConfigSkipBareword(zIn);
            if (zRet) |zr| {
                zo[@intFromPtr(zr) - @intFromPtr(zIn)] = 0;
            }
        }
    } else {
        pRc.* = SQLITE_NOMEM;
    }

    if (zRet == null) {
        sqlite3_free(zOut);
    } else {
        pzOut.* = @ptrCast(zOut);
    }

    return zRet;
}

fn fts5ConfigParseColumn(
    p: *Fts5Config,
    zCol: [*:0]u8,
    zArg: ?[*:0]u8,
    pzErr: *?[*:0]u8,
    pbUnindexed: *c_int,
) c_int {
    var rc: c_int = SQLITE_OK;
    if (0 == sqlite3_stricmp(zCol, FTS5_RANK_NAME) or
        0 == sqlite3_stricmp(zCol, FTS5_ROWID_NAME))
    {
        pzErr.* = sqlite3_mprintf("reserved fts5 column name: %s", zCol);
        rc = SQLITE_ERROR;
    } else if (zArg) |za| {
        if (0 == sqlite3_stricmp(za, "unindexed")) {
            p.abUnindexed.?[@intCast(p.nCol)] = 1;
            pbUnindexed.* = 1;
        } else {
            pzErr.* = sqlite3_mprintf("unrecognized column option: %s", za);
            rc = SQLITE_ERROR;
        }
    }

    p.azCol.?[@intCast(p.nCol)] = zCol;
    p.nCol += 1;
    return rc;
}

/// fts5_config.c 518-552: build the Fts5Config.zContentExprlist string.
fn fts5ConfigMakeExprlist(p: *Fts5Config) c_int {
    var rc: c_int = SQLITE_OK;
    var buf: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };

    sqlite3Fts5BufferAppendPrintf(&rc, &buf, "T.%Q", p.zContentRowid);
    if (p.eContent != FTS5_CONTENT_NONE) {
        var i: c_int = 0;
        while (i < p.nCol) : (i += 1) {
            if (p.eContent == FTS5_CONTENT_EXTERNAL) {
                sqlite3Fts5BufferAppendPrintf(&rc, &buf, ", T.%Q", p.azCol.?[@intCast(i)]);
            } else if (p.eContent == FTS5_CONTENT_NORMAL or p.abUnindexed.?[@intCast(i)] != 0) {
                sqlite3Fts5BufferAppendPrintf(&rc, &buf, ", T.c%d", i);
            } else {
                sqlite3Fts5BufferAppendPrintf(&rc, &buf, ", NULL");
            }
        }
    }
    if (p.eContent == FTS5_CONTENT_NORMAL and p.bLocale != 0) {
        var i: c_int = 0;
        while (i < p.nCol) : (i += 1) {
            if (p.abUnindexed.?[@intCast(i)] == 0) {
                sqlite3Fts5BufferAppendPrintf(&rc, &buf, ", T.l%d", i);
            } else {
                sqlite3Fts5BufferAppendPrintf(&rc, &buf, ", NULL");
            }
        }
    }

    p.zContentExprlist = @ptrCast(buf.p);
    return rc;
}

/// fts5_config.c 566-719: parse the CREATE VIRTUAL TABLE argument vector into a
/// new Fts5Config. EXPORTED. *ppOut is the new object (NULL on error).
export fn sqlite3Fts5ConfigParse(
    pGlobal: ?*Fts5Global,
    db: ?*sqlite3,
    nArg: c_int,
    azArg: [*]const ?[*:0]const u8,
    ppOut: *?*Fts5Config,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var bUnindexed: c_int = 0;

    const pRet: ?*Fts5Config = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts5Config))));
    ppOut.* = pRet;
    if (pRet == null) return SQLITE_NOMEM;
    const p = pRet.?;
    _ = memset(p, 0, @sizeOf(Fts5Config));
    p.pGlobal = pGlobal;
    p.db = db;
    p.iCookie = -1;

    const nByte: i64 = @as(i64, nArg) * (@sizeOf(usize) + @sizeOf(u8));
    p.azCol = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, nByte)));
    p.abUnindexed = if (p.azCol) |ac| @ptrCast(&ac[@intCast(nArg)]) else null;
    p.zDb = sqlite3Fts5Strndup(&rc, @ptrCast(azArg[1].?), -1);
    p.zName = sqlite3Fts5Strndup(&rc, @ptrCast(azArg[2].?), -1);
    p.bColumnsize = 1;
    p.eDetail = FTS5_DETAIL_FULL;
    if (config.sqlite_debug) {
        p.bPrefixIndex = 1;
    }
    if (rc == SQLITE_OK and sqlite3_stricmp(p.zName.?, FTS5_RANK_NAME) == 0) {
        pzErr.* = sqlite3_mprintf("reserved fts5 table name: %s", p.zName);
        rc = SQLITE_ERROR;
    }

    var i: c_int = 3;
    while (rc == SQLITE_OK and i < nArg) : (i += 1) {
        const zOrig = azArg[@intCast(i)].?;
        var z: ?[*:0]const u8 = undefined;
        var zOne: ?[*:0]u8 = null;
        var zTwo: ?[*:0]u8 = null;
        var bOption: c_int = 0;
        var bMustBeCol: c_int = 0;

        z = fts5ConfigGobbleWord(&rc, zOrig, &zOne, &bMustBeCol);
        z = fts5ConfigSkipWhitespace(z);
        if (z != null and z.?[0] == '=') {
            bOption = 1;
            z = z.? + 1;
            if (bMustBeCol != 0) z = null;
        }
        z = fts5ConfigSkipWhitespace(z);
        if (z != null and z.?[0] != 0) {
            var bDummy: c_int = undefined;
            z = fts5ConfigGobbleWord(&rc, z.?, &zTwo, &bDummy);
            if (z != null and z.?[0] != 0) z = null;
        }

        if (rc == SQLITE_OK) {
            if (z == null) {
                pzErr.* = sqlite3_mprintf("parse error in \"%s\"", zOrig);
                rc = SQLITE_ERROR;
            } else {
                if (bOption != 0) {
                    // ALWAYS(zOne) — zOne is non-null here; assert under debug.
                    if (config.sqlite_debug and zOne == null) unreachable;
                    rc = fts5ConfigParseSpecial(
                        p,
                        if (zOne) |z1| z1 else "",
                        if (zTwo) |z2| z2 else "",
                        pzErr,
                    );
                } else {
                    rc = fts5ConfigParseColumn(p, zOne.?, zTwo, pzErr, &bUnindexed);
                    zOne = null;
                }
            }
        }

        sqlite3_free(zOne);
        sqlite3_free(zTwo);
    }

    // contentless_delete=1 requires a contentless table.
    if (rc == SQLITE_OK and p.bContentlessDelete != 0 and p.eContent != FTS5_CONTENT_NONE) {
        pzErr.* = sqlite3_mprintf("contentless_delete=1 requires a contentless table");
        rc = SQLITE_ERROR;
    }

    // contentless_delete=1 is incompatible with columnsize=0.
    if (rc == SQLITE_OK and p.bContentlessDelete != 0 and p.bColumnsize == 0) {
        pzErr.* = sqlite3_mprintf("contentless_delete=1 is incompatible with columnsize=0");
        rc = SQLITE_ERROR;
    }

    // contentless_unindexed=1 requires a contentless table.
    if (rc == SQLITE_OK and p.bContentlessUnindexed != 0 and p.eContent != FTS5_CONTENT_NONE) {
        pzErr.* = sqlite3_mprintf("contentless_unindexed=1 requires a contentless table");
        rc = SQLITE_ERROR;
    }

    // If no content option was specified, fill in defaults.
    if (rc == SQLITE_OK and p.zContent == null) {
        var zTail: ?[*:0]const u8 = null;
        if (p.eContent == FTS5_CONTENT_NORMAL) {
            zTail = "content";
        } else if (bUnindexed != 0 and p.bContentlessUnindexed != 0) {
            p.eContent = FTS5_CONTENT_UNINDEXED;
            zTail = "content";
        } else if (p.bColumnsize != 0) {
            zTail = "docsize";
        }

        if (zTail) |zt| {
            p.zContent = sqlite3Fts5Mprintf(&rc, "%Q.'%q_%s'", p.zDb, p.zName, zt);
        }
    }

    if (rc == SQLITE_OK and p.zContentRowid == null) {
        p.zContentRowid = sqlite3Fts5Strndup(&rc, "rowid", -1);
    }

    if (rc == SQLITE_OK) {
        rc = fts5ConfigMakeExprlist(p);
    }

    if (rc != SQLITE_OK) {
        sqlite3Fts5ConfigFree(pRet);
        ppOut.* = null;
    }
    return rc;
}

/// fts5_config.c 724-749: free the configuration object. EXPORTED.
export fn sqlite3Fts5ConfigFree(pConfig: ?*Fts5Config) callconv(.c) void {
    if (pConfig) |p| {
        if (p.t.pTok != null) {
            if (p.t.pApi1) |a1| {
                a1.xDelete.?(p.t.pTok);
            } else {
                p.t.pApi2.?.xDelete.?(p.t.pTok);
            }
        }
        sqlite3_free(@ptrCast(@constCast(p.t.azArg)));
        sqlite3_free(p.zDb);
        sqlite3_free(p.zName);
        var i: c_int = 0;
        while (i < p.nCol) : (i += 1) {
            sqlite3_free(p.azCol.?[@intCast(i)]);
        }
        sqlite3_free(@ptrCast(p.azCol));
        sqlite3_free(@ptrCast(p.aPrefix));
        sqlite3_free(p.zRank);
        sqlite3_free(p.zRankArgs);
        sqlite3_free(p.zContent);
        sqlite3_free(p.zContentRowid);
        sqlite3_free(p.zContentExprlist);
        sqlite3_free(p);
    }
}

/// fts5_config.c 756-777: sqlite3_declare_vtab() based on the config. EXPORTED.
export fn sqlite3Fts5ConfigDeclareVtab(pConfig: *Fts5Config) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    var zSql: ?[*:0]u8 = sqlite3Fts5Mprintf(&rc, "CREATE TABLE x(");
    var i: c_int = 0;
    while (zSql != null and i < pConfig.nCol) : (i += 1) {
        const zSep: [*:0]const u8 = if (i == 0) "" else ", ";
        zSql = sqlite3Fts5Mprintf(&rc, "%z%s%Q", zSql, zSep, pConfig.azCol.?[@intCast(i)]);
    }
    zSql = sqlite3Fts5Mprintf(&rc, "%z, %Q HIDDEN, %s HIDDEN)", zSql, pConfig.zName, FTS5_RANK_NAME);

    if (zSql) |zs| {
        rc = sqlite3_declare_vtab(pConfig.db, zs);
        sqlite3_free(zs);
    }

    return rc;
}

/// fts5_config.c 802-827: tokenize text via the configured tokenizer. EXPORTED.
export fn sqlite3Fts5Tokenize(
    pConfig: *Fts5Config,
    flags: c_int,
    pText: ?[*]const u8,
    nText: c_int,
    pCtx: ?*anyopaque,
    xToken: XTokenFn,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (pText != null) {
        if (pConfig.t.pTok == null) {
            rc = sqlite3Fts5LoadTokenizer(pConfig);
        }
        if (rc == SQLITE_OK) {
            if (pConfig.t.pApi1) |a1| {
                rc = a1.xTokenize.?(pConfig.t.pTok, pCtx, flags, pText, nText, xToken);
            } else {
                rc = pConfig.t.pApi2.?.xTokenize.?(
                    pConfig.t.pTok,
                    pCtx,
                    flags,
                    pText,
                    nText,
                    pConfig.t.pLocale,
                    pConfig.t.nLocale,
                    xToken,
                );
            }
        }
    }
    return rc;
}

/// fts5_config.c 835-851: skip a comma-separated literal list up to ')'.
fn fts5ConfigSkipArgs(pIn: ?[*:0]const u8) ?[*:0]const u8 {
    var p = pIn;
    while (true) {
        p = fts5ConfigSkipWhitespace(p);
        p = if (p) |pp| fts5ConfigSkipLiteral(pp) else null;
        p = fts5ConfigSkipWhitespace(p);
        if (p == null or p.?[0] == ')') break;
        if (p.?[0] != ',') {
            p = null;
            break;
        }
        p = p.? + 1;
    }
    return p;
}

/// fts5_config.c 862-919: parse a rank() function specification. EXPORTED.
export fn sqlite3Fts5ConfigParseRank(
    zIn: ?[*:0]const u8,
    pzRank: *?[*:0]u8,
    pzRankArgs: *?[*:0]u8,
) callconv(.c) c_int {
    var p = zIn;
    var zRank: ?[*:0]u8 = null;
    var zRankArgs: ?[*:0]u8 = null;
    var rc: c_int = SQLITE_OK;

    pzRank.* = null;
    pzRankArgs.* = null;

    if (p == null) {
        rc = SQLITE_ERROR;
    } else {
        p = fts5ConfigSkipWhitespace(p);
        const pRank = p.?;
        p = fts5ConfigSkipBareword(p.?);

        if (p) |pp| {
            const n: usize = @intFromPtr(pp) - @intFromPtr(pRank);
            zRank = @ptrCast(sqlite3Fts5MallocZero(&rc, @as(i64, @intCast(1 + n))));
            if (zRank) |zr| _ = memcpy(zr, pRank, n);
        } else {
            rc = SQLITE_ERROR;
        }

        if (rc == SQLITE_OK) {
            p = fts5ConfigSkipWhitespace(p);
            if (p.?[0] != '(') rc = SQLITE_ERROR;
            p = p.? + 1;
        }
        if (rc == SQLITE_OK) {
            p = fts5ConfigSkipWhitespace(p);
            const pArgs = p.?;
            if (p.?[0] != ')') {
                p = fts5ConfigSkipArgs(p);
                if (p == null) {
                    rc = SQLITE_ERROR;
                } else {
                    const n: usize = @intFromPtr(p.?) - @intFromPtr(pArgs);
                    zRankArgs = @ptrCast(sqlite3Fts5MallocZero(&rc, @as(i64, @intCast(1 + n))));
                    if (zRankArgs) |zra| _ = memcpy(zra, pArgs, n);
                }
            }
        }
    }

    if (rc != SQLITE_OK) {
        sqlite3_free(zRank);
    } else {
        pzRank.* = zRank;
        pzRankArgs.* = zRankArgs;
    }
    return rc;
}

/// fts5_config.c 921-1047: set one %_config attribute. EXPORTED.
export fn sqlite3Fts5ConfigSetValue(
    pConfig: *Fts5Config,
    zKey: [*:0]const u8,
    pVal: ?*sqlite3_value,
    pbBadkey: *c_int,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (0 == sqlite3_stricmp(zKey, "pgsz")) {
        var pgsz: c_int = 0;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            pgsz = sqlite3_value_int(pVal);
        }
        if (pgsz < 32 or pgsz > FTS5_MAX_PAGE_SIZE) {
            pbBadkey.* = 1;
        } else {
            pConfig.pgsz = pgsz;
        }
    } else if (0 == sqlite3_stricmp(zKey, "hashsize")) {
        var nHashSize: c_int = -1;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            nHashSize = sqlite3_value_int(pVal);
        }
        if (nHashSize <= 0) {
            pbBadkey.* = 1;
        } else {
            pConfig.nHashSize = nHashSize;
        }
    } else if (0 == sqlite3_stricmp(zKey, "automerge")) {
        var nAutomerge: c_int = -1;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            nAutomerge = sqlite3_value_int(pVal);
        }
        if (nAutomerge < 0 or nAutomerge > 64) {
            pbBadkey.* = 1;
        } else {
            if (nAutomerge == 1) nAutomerge = FTS5_DEFAULT_AUTOMERGE;
            pConfig.nAutomerge = nAutomerge;
        }
    } else if (0 == sqlite3_stricmp(zKey, "usermerge")) {
        var nUsermerge: c_int = -1;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            nUsermerge = sqlite3_value_int(pVal);
        }
        if (nUsermerge < 2 or nUsermerge > 16) {
            pbBadkey.* = 1;
        } else {
            pConfig.nUsermerge = nUsermerge;
        }
    } else if (0 == sqlite3_stricmp(zKey, "crisismerge")) {
        var nCrisisMerge: c_int = -1;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            nCrisisMerge = sqlite3_value_int(pVal);
        }
        if (nCrisisMerge < 0) {
            pbBadkey.* = 1;
        } else {
            if (nCrisisMerge <= 1) nCrisisMerge = FTS5_DEFAULT_CRISISMERGE;
            if (nCrisisMerge >= FTS5_MAX_SEGMENT) nCrisisMerge = FTS5_MAX_SEGMENT - 1;
            pConfig.nCrisisMerge = nCrisisMerge;
        }
    } else if (0 == sqlite3_stricmp(zKey, "deletemerge")) {
        var nVal: c_int = -1;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            nVal = sqlite3_value_int(pVal);
        } else {
            pbBadkey.* = 1;
        }
        if (nVal < 0) nVal = FTS5_DEFAULT_DELETE_AUTOMERGE;
        if (nVal > 100) nVal = 0;
        pConfig.nDeleteMerge = nVal;
    } else if (0 == sqlite3_stricmp(zKey, "rank")) {
        const zIn = sqlite3_value_text(pVal);
        var zRank: ?[*:0]u8 = undefined;
        var zRankArgs: ?[*:0]u8 = undefined;
        rc = sqlite3Fts5ConfigParseRank(zIn, &zRank, &zRankArgs);
        if (rc == SQLITE_OK) {
            sqlite3_free(pConfig.zRank);
            sqlite3_free(pConfig.zRankArgs);
            pConfig.zRank = zRank;
            pConfig.zRankArgs = zRankArgs;
        } else if (rc == SQLITE_ERROR) {
            rc = SQLITE_OK;
            pbBadkey.* = 1;
        }
    } else if (0 == sqlite3_stricmp(zKey, "secure-delete")) {
        var bVal: c_int = -1;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            bVal = sqlite3_value_int(pVal);
        }
        if (bVal < 0) {
            pbBadkey.* = 1;
        } else {
            pConfig.bSecureDelete = if (bVal != 0) 1 else 0;
        }
    } else if (0 == sqlite3_stricmp(zKey, "insttoken")) {
        var bVal: c_int = -1;
        if (SQLITE_INTEGER == sqlite3_value_numeric_type(pVal)) {
            bVal = sqlite3_value_int(pVal);
        }
        if (bVal < 0) {
            pbBadkey.* = 1;
        } else {
            pConfig.bPrefixInsttoken = if (bVal != 0) 1 else 0;
        }
    } else {
        pbBadkey.* = 1;
    }
    return rc;
}

/// fts5_config.c 1052-1105: load %_config table into memory. EXPORTED.
export fn sqlite3Fts5ConfigLoad(pConfig: *Fts5Config, iCookie: c_int) callconv(.c) c_int {
    const zSelect: [*:0]const u8 = "SELECT k, v FROM %Q.'%q_config'";
    var p: ?*sqlite3_stmt = null;
    var rc: c_int = SQLITE_OK;
    var iVersion: c_int = 0;

    // Default values.
    pConfig.pgsz = FTS5_DEFAULT_PAGE_SIZE;
    pConfig.nAutomerge = FTS5_DEFAULT_AUTOMERGE;
    pConfig.nUsermerge = FTS5_DEFAULT_USERMERGE;
    pConfig.nCrisisMerge = FTS5_DEFAULT_CRISISMERGE;
    pConfig.nHashSize = FTS5_DEFAULT_HASHSIZE;
    pConfig.nDeleteMerge = FTS5_DEFAULT_DELETE_AUTOMERGE;

    const zSql = sqlite3Fts5Mprintf(&rc, zSelect, pConfig.zDb, pConfig.zName);
    if (zSql) |zs| {
        rc = sqlite3_prepare_v2(pConfig.db, zs, -1, &p, null);
        sqlite3_free(zs);
    }

    if (rc == SQLITE_OK) {
        while (SQLITE_ROW == sqlite3_step(p)) {
            const zK = sqlite3_column_text(p, 0).?;
            const pVal = sqlite3_column_value(p, 1);
            if (0 == sqlite3_stricmp(zK, "version")) {
                iVersion = sqlite3_value_int(pVal);
            } else {
                var bDummy: c_int = 0;
                _ = sqlite3Fts5ConfigSetValue(pConfig, zK, pVal, &bDummy);
            }
        }
        rc = sqlite3_finalize(p);
    }

    if (rc == SQLITE_OK and
        iVersion != FTS5_CURRENT_VERSION and
        iVersion != FTS5_CURRENT_VERSION_SECUREDELETE)
    {
        rc = SQLITE_ERROR;
        sqlite3Fts5ConfigErrmsg(
            pConfig,
            "invalid fts5 file format (found %d, expected %d or %d) - run 'rebuild'",
            iVersion,
            FTS5_CURRENT_VERSION,
            FTS5_CURRENT_VERSION_SECUREDELETE,
        );
    } else {
        pConfig.iVersion = iVersion;
    }

    if (rc == SQLITE_OK) {
        pConfig.iCookie = iCookie;
    }
    return rc;
}

/// fts5_config.c 1112-1126: set *pConfig->pzErrmsg to a formatted message.
/// EXPORTED (variadic).
export fn sqlite3Fts5ConfigErrmsg(pConfig: *Fts5Config, zFmt: [*:0]const u8, ...) callconv(.c) void {
    var ap = @cVaStart();
    const zMsg = sqlite3_vmprintf(zFmt, @ptrCast(&ap));
    @cVaEnd(&ap);
    if (pConfig.pzErrmsg) |pp| {
        pp.* = zMsg;
    } else {
        sqlite3_free(zMsg);
    }
}

comptime {
    _ = int;
}
