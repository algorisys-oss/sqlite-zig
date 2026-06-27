//! Zig port of the fts5_tokenize.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 24601-26098).
//!
//! The four built-in FTS5 tokenizers — "ascii", "unicode61", "porter" and
//! "trigram" — plus the registry helpers (sqlite3Fts5TokenizerInit and the
//! Pattern/Preload predicates used by the LIKE/GLOB optimizer).
//!
//! "porter" wraps a base tokenizer via the v2 (locale-aware) fn-ptr table;
//! the other three use the legacy fts5_tokenizer table. Both tables and their
//! callback signatures come from the foundation (fts5_int.zig). The Unicode
//! category/fold/diacritic helpers live in the fts5_unicode2.c section and are
//! resolved at link time via `extern fn`.

const int = @import("fts5_int.zig");

const Fts5Tokenizer = int.Fts5Tokenizer;
const fts5_tokenizer = int.fts5_tokenizer;
const fts5_tokenizer_v2 = int.fts5_tokenizer_v2;
const fts5_api = int.fts5_api;
const Fts5TokenizerConfig = int.Fts5TokenizerConfig;

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_ERROR = int.SQLITE_ERROR;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_DONE = int.SQLITE_DONE;

const FTS5_PATTERN_NONE = int.FTS5_PATTERN_NONE;
const FTS5_PATTERN_LIKE = int.FTS5_PATTERN_LIKE;
const FTS5_PATTERN_GLOB = int.FTS5_PATTERN_GLOB;

// Values for eRemoveDiacritic (must match fts5_unicode2.c internals).
const FTS5_REMOVE_DIACRITICS_NONE: c_int = 0;
const FTS5_REMOVE_DIACRITICS_SIMPLE: c_int = 1;
const FTS5_REMOVE_DIACRITICS_COMPLEX: c_int = 2;

// porter stemmer: tokens larger than this pass through unstemmed.
const FTS5_PORTER_MAX_TOKEN: c_int = 64;

// --- libc -------------------------------------------------------------------
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memmove(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn strlen(s: [*:0]const u8) usize;

// --- public sqlite3 API -----------------------------------------------------
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_stricmp(a: [*:0]const u8, b: [*:0]const u8) c_int;

// --- sibling section: fts5_unicode2.c ---------------------------------------
extern fn sqlite3Fts5UnicodeIsdiacritic(c: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5UnicodeFold(c: c_int, eRemoveDiacritic: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5UnicodeCatParse(zCat: [*:0]const u8, aArray: [*]u8) callconv(.c) c_int;
extern fn sqlite3Fts5UnicodeCategory(iCode: u32) callconv(.c) c_int;
extern fn sqlite3Fts5UnicodeAscii(aArray: [*]u8, aAscii: [*]u8) callconv(.c) void;

// xToken callback signatures.
const XToken1 = ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int;

// ===========================================================================
// READ_UTF8 / WRITE_UTF8 / FTS5_SKIP_UTF8 — ported from the C macros (24798..).
// ===========================================================================
const sqlite3Utf8Trans1 = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00,
};

/// READ_UTF8(zIn, zTerm, c): advance *zIn past one codepoint, store into c.*.
inline fn readUtf8(zIn: *[*]const u8, zTerm: [*]const u8, c: *u32) void {
    var cc: u32 = zIn.*[0];
    zIn.* += 1;
    if (cc >= 0xc0) {
        cc = sqlite3Utf8Trans1[cc - 0xc0];
        while (@intFromPtr(zIn.*) < @intFromPtr(zTerm) and (zIn.*[0] & 0xc0) == 0x80) {
            cc = (cc << 6) +% (0x3f & zIn.*[0]);
            zIn.* += 1;
        }
        if (cc < 0x80 or (cc & 0xFFFFF800) == 0xD800 or (cc & 0xFFFFFFFE) == 0xFFFE) {
            cc = 0xFFFD;
        }
    }
    c.* = cc;
}

/// WRITE_UTF8(zOut, c): write codepoint c into *zOut, advancing it.
inline fn writeUtf8(zOut: *[*]u8, c: u32) void {
    if (c < 0x00080) {
        zOut.*[0] = @truncate(c & 0xFF);
        zOut.* += 1;
    } else if (c < 0x00800) {
        zOut.*[0] = @truncate(0xC0 + ((c >> 6) & 0x1F));
        zOut.*[1] = @truncate(0x80 + (c & 0x3F));
        zOut.* += 2;
    } else if (c < 0x10000) {
        zOut.*[0] = @truncate(0xE0 + ((c >> 12) & 0x0F));
        zOut.*[1] = @truncate(0x80 + ((c >> 6) & 0x3F));
        zOut.*[2] = @truncate(0x80 + (c & 0x3F));
        zOut.* += 3;
    } else {
        zOut.*[0] = @truncate(0xF0 + ((c >> 18) & 0x07));
        zOut.*[1] = @truncate(0x80 + ((c >> 12) & 0x3F));
        zOut.*[2] = @truncate(0x80 + ((c >> 6) & 0x3F));
        zOut.*[3] = @truncate(0x80 + (c & 0x3F));
        zOut.* += 4;
    }
}

/// FTS5_SKIP_UTF8(zIn): advance *zIn past one codepoint.
inline fn skipUtf8(zIn: *[*]const u8) void {
    const c = zIn.*[0];
    zIn.* += 1;
    if (c >= 0xc0) {
        while ((zIn.*[0] & 0xc0) == 0x80) zIn.* += 1;
    }
}

// ===========================================================================
// ascii tokenizer (24618-24773)
// ===========================================================================
const aAsciiTokenChar = [128]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x00..0x0F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x10..0x1F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x20..0x2F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 0x30..0x3F
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x40..0x4F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // 0x50..0x5F
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x60..0x6F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // 0x70..0x7F
};

const AsciiTokenizer = extern struct {
    aTokenChar: [128]u8,
};

fn fts5AsciiAddExceptions(p: *AsciiTokenizer, zArg: [*:0]const u8, bTokenChars: c_int) void {
    var i: usize = 0;
    while (zArg[i] != 0) : (i += 1) {
        if ((zArg[i] & 0x80) == 0) {
            p.aTokenChar[zArg[i]] = @intCast(bTokenChars);
        }
    }
}

fn fts5AsciiDelete(p: ?*Fts5Tokenizer) callconv(.c) void {
    sqlite3_free(p);
}

fn fts5AsciiCreate(
    pUnused: ?*anyopaque,
    azArg: ?[*]const ?[*:0]const u8,
    nArg: c_int,
    ppOut: *?*Fts5Tokenizer,
) callconv(.c) c_int {
    _ = pUnused;
    var rc: c_int = SQLITE_OK;
    var p: ?*AsciiTokenizer = null;
    if (@mod(nArg, 2) != 0) {
        rc = SQLITE_ERROR;
    } else {
        p = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(AsciiTokenizer))));
        if (p == null) {
            rc = SQLITE_NOMEM;
        } else {
            const pt = p.?;
            _ = memset(pt, 0, @sizeOf(AsciiTokenizer));
            _ = memcpy(&pt.aTokenChar, &aAsciiTokenChar, aAsciiTokenChar.len);
            var i: c_int = 0;
            while (rc == SQLITE_OK and i < nArg) : (i += 2) {
                const zArg = azArg.?[@intCast(i + 1)].?;
                if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "tokenchars")) {
                    fts5AsciiAddExceptions(pt, zArg, 1);
                } else if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "separators")) {
                    fts5AsciiAddExceptions(pt, zArg, 0);
                } else {
                    rc = SQLITE_ERROR;
                }
            }
            if (rc != SQLITE_OK) {
                fts5AsciiDelete(@ptrCast(p));
                p = null;
            }
        }
    }
    ppOut.* = @ptrCast(p);
    return rc;
}

fn asciiFold(aOut: [*]u8, aIn: [*]const u8, nByte: c_int) void {
    var i: usize = 0;
    while (i < @as(usize, @intCast(nByte))) : (i += 1) {
        var c = aIn[i];
        if (c >= 'A' and c <= 'Z') c += 32;
        aOut[i] = c;
    }
}

fn fts5AsciiTokenize(
    pTokenizer: ?*Fts5Tokenizer,
    pCtx: ?*anyopaque,
    iUnused: c_int,
    pText: ?[*]const u8,
    nText: c_int,
    xToken: XToken1,
) callconv(.c) c_int {
    _ = iUnused;
    const p: *AsciiTokenizer = @ptrCast(@alignCast(pTokenizer.?));
    var rc: c_int = SQLITE_OK;
    var ie: c_int = undefined;
    var is: c_int = 0;

    var aFold: [64]u8 = undefined;
    var nFold: c_int = aFold.len;
    var pFold: [*]u8 = &aFold;
    const a = &p.aTokenChar;
    const text = pText.?;

    while (is < nText and rc == SQLITE_OK) {
        // Skip leading divider characters.
        while (is < nText and ((text[@intCast(is)] & 0x80) == 0 and a[text[@intCast(is)]] == 0)) {
            is += 1;
        }
        if (is == nText) break;

        // Count token characters.
        ie = is + 1;
        while (ie < nText and ((text[@intCast(ie)] & 0x80) != 0 or a[text[@intCast(ie)]] != 0)) {
            ie += 1;
        }

        // Fold to lower case.
        const nByte = ie - is;
        if (nByte > nFold) {
            if (pFold != @as([*]u8, &aFold)) sqlite3_free(pFold);
            pFold = @ptrCast(sqlite3_malloc64(@as(u64, @intCast(nByte)) * 2));
            if (@intFromPtr(pFold) == 0) {
                rc = SQLITE_NOMEM;
                break;
            }
            nFold = nByte * 2;
        }
        asciiFold(pFold, text + @as(usize, @intCast(is)), nByte);

        rc = xToken.?(pCtx, 0, pFold, nByte, is, ie);
        is = ie + 1;
    }

    if (pFold != @as([*]u8, &aFold)) sqlite3_free(pFold);
    if (rc == SQLITE_DONE) rc = SQLITE_OK;
    return rc;
}

// ===========================================================================
// unicode61 tokenizer (24776-25145)
// ===========================================================================
const Unicode61Tokenizer = extern struct {
    aTokenChar: [128]u8, // ASCII range token characters
    aFold: ?[*]u8, // Buffer to fold text into
    nFold: c_int, // Size of aFold[] in bytes
    eRemoveDiacritic: c_int, // remove_diacritics setting
    nException: c_int,
    aiException: ?[*]c_int,
    aCategory: [32]u8, // True for token char categories
};

fn fts5UnicodeAddExceptions(p: *Unicode61Tokenizer, z: [*:0]const u8, bTokenChars: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    const n: c_int = @intCast(strlen(z));

    if (n > 0) {
        const aNew: ?[*]c_int = @ptrCast(@alignCast(sqlite3_realloc64(
            p.aiException,
            @as(u64, @intCast(n + p.nException)) * @sizeOf(c_int),
        )));
        if (aNew) |an| {
            var nNew = p.nException;
            var zCsr: [*]const u8 = @ptrCast(z);
            const zTerm: [*]const u8 = @as([*]const u8, @ptrCast(z)) + @as(usize, @intCast(n));
            while (@intFromPtr(zCsr) < @intFromPtr(zTerm)) {
                var iCode: u32 = undefined;
                readUtf8(&zCsr, zTerm, &iCode);
                if (iCode < 128) {
                    p.aTokenChar[@intCast(iCode)] = @intCast(bTokenChars);
                } else {
                    const bToken = p.aCategory[@intCast(sqlite3Fts5UnicodeCategory(iCode))];
                    if (bToken != bTokenChars and sqlite3Fts5UnicodeIsdiacritic(@intCast(iCode)) == 0) {
                        var i: c_int = 0;
                        while (i < nNew) : (i += 1) {
                            if (@as(u32, @bitCast(an[@intCast(i)])) > iCode) break;
                        }
                        _ = memmove(
                            &an[@intCast(i + 1)],
                            &an[@intCast(i)],
                            @as(usize, @intCast(nNew - i)) * @sizeOf(c_int),
                        );
                        an[@intCast(i)] = @bitCast(iCode);
                        nNew += 1;
                    }
                }
            }
            p.aiException = aNew;
            p.nException = nNew;
        } else {
            rc = SQLITE_NOMEM;
        }
    }

    return rc;
}

fn fts5UnicodeIsException(p: *Unicode61Tokenizer, iCode: c_int) c_int {
    if (p.nException > 0) {
        const a = p.aiException.?;
        var iLo: c_int = 0;
        var iHi: c_int = p.nException - 1;
        while (iHi >= iLo) {
            const iTest = @divTrunc(iHi + iLo, 2);
            if (iCode == a[@intCast(iTest)]) {
                return 1;
            } else if (iCode > a[@intCast(iTest)]) {
                iLo = iTest + 1;
            } else {
                iHi = iTest - 1;
            }
        }
    }
    return 0;
}

fn fts5UnicodeDelete(pTok: ?*Fts5Tokenizer) callconv(.c) void {
    if (pTok) |pt| {
        const p: *Unicode61Tokenizer = @ptrCast(@alignCast(pt));
        sqlite3_free(p.aiException);
        sqlite3_free(p.aFold);
        sqlite3_free(p);
    }
}

fn unicodeSetCategories(p: *Unicode61Tokenizer, zCat: [*:0]const u8) c_int {
    var z: [*:0]const u8 = zCat;
    while (z[0] != 0) {
        while (z[0] == ' ' or z[0] == '\t') z += 1;
        if (z[0] != 0 and sqlite3Fts5UnicodeCatParse(z, &p.aCategory) != 0) {
            return SQLITE_ERROR;
        }
        while (z[0] != ' ' and z[0] != '\t' and z[0] != 0) z += 1;
    }
    sqlite3Fts5UnicodeAscii(&p.aCategory, &p.aTokenChar);
    return SQLITE_OK;
}

fn fts5UnicodeCreate(
    pUnused: ?*anyopaque,
    azArg: ?[*]const ?[*:0]const u8,
    nArg: c_int,
    ppOut: *?*Fts5Tokenizer,
) callconv(.c) c_int {
    _ = pUnused;
    var rc: c_int = SQLITE_OK;
    var p: ?*Unicode61Tokenizer = null;

    if (@mod(nArg, 2) != 0) {
        rc = SQLITE_ERROR;
    } else {
        p = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Unicode61Tokenizer))));
        if (p) |pt| {
            var zCat: [*:0]const u8 = "L* N* Co";
            _ = memset(pt, 0, @sizeOf(Unicode61Tokenizer));

            pt.eRemoveDiacritic = FTS5_REMOVE_DIACRITICS_SIMPLE;
            pt.nFold = 64;
            pt.aFold = @ptrCast(sqlite3_malloc64(@as(u64, @intCast(pt.nFold)) * @sizeOf(u8)));
            if (pt.aFold == null) {
                rc = SQLITE_NOMEM;
            }

            // Search for a "categories" argument.
            var i: c_int = 0;
            while (rc == SQLITE_OK and i < nArg) : (i += 2) {
                if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "categories")) {
                    zCat = azArg.?[@intCast(i + 1)].?;
                }
            }
            if (rc == SQLITE_OK) {
                rc = unicodeSetCategories(pt, zCat);
            }

            i = 0;
            while (rc == SQLITE_OK and i < nArg) : (i += 2) {
                const zArg = azArg.?[@intCast(i + 1)].?;
                if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "remove_diacritics")) {
                    if ((zArg[0] != '0' and zArg[0] != '1' and zArg[0] != '2') or zArg[1] != 0) {
                        rc = SQLITE_ERROR;
                    } else {
                        pt.eRemoveDiacritic = zArg[0] - '0';
                    }
                } else if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "tokenchars")) {
                    rc = fts5UnicodeAddExceptions(pt, zArg, 1);
                } else if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "separators")) {
                    rc = fts5UnicodeAddExceptions(pt, zArg, 0);
                } else if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "categories")) {
                    // no-op
                } else {
                    rc = SQLITE_ERROR;
                }
            }
        } else {
            rc = SQLITE_NOMEM;
        }
        if (rc != SQLITE_OK) {
            fts5UnicodeDelete(@ptrCast(p));
            p = null;
        }
        ppOut.* = @ptrCast(p);
    }
    return rc;
}

fn fts5UnicodeIsAlnum(p: *Unicode61Tokenizer, iCode: c_int) c_int {
    return (p.aCategory[@intCast(sqlite3Fts5UnicodeCategory(@bitCast(iCode)))] ^
        @as(u8, @intCast(fts5UnicodeIsException(p, iCode))));
}

fn fts5UnicodeTokenize(
    pTokenizer: ?*Fts5Tokenizer,
    pCtx: ?*anyopaque,
    iUnused: c_int,
    pText: ?[*]const u8,
    nText: c_int,
    xToken: XToken1,
) callconv(.c) c_int {
    _ = iUnused;
    const p: *Unicode61Tokenizer = @ptrCast(@alignCast(pTokenizer.?));
    var rc: c_int = SQLITE_OK;
    const a = &p.aTokenChar;
    const text: [*]const u8 = pText.?;

    const zTerm: [*]const u8 = text + @as(usize, @intCast(nText));
    var zCsr: [*]const u8 = text;

    // Output buffer.
    var aFold: [*]u8 = p.aFold.?;
    var nFold: c_int = p.nFold;
    var pEnd: [*]const u8 = aFold + @as(usize, @intCast(nFold - 6));

    // Each iteration gobbles a run of separators then the next token. The C
    // uses `goto non_ascii_tokenchar` / `ascii_tokenchar` to jump from the
    // separator-skip loop INTO the tokenchars loop. We model those two jump
    // targets with the `entry` enum: on the first pass through the tokenchars
    // loop we run the matching label body before the normal loop logic.
    const Entry = enum { none, non_ascii, ascii };
    while (rc == SQLITE_OK) {
        var iCode: u32 = undefined;
        var zOut: [*]u8 = aFold;
        var is: c_int = undefined;
        var ie: c_int = undefined;
        var entry: Entry = .none;

        // Skip separator characters.
        while (true) {
            if (@intFromPtr(zCsr) >= @intFromPtr(zTerm)) {
                if (rc == SQLITE_DONE) rc = SQLITE_OK;
                return rc;
            }
            if (zCsr[0] & 0x80 != 0) {
                is = @intCast(@intFromPtr(zCsr) - @intFromPtr(text));
                readUtf8(&zCsr, zTerm, &iCode);
                if (fts5UnicodeIsAlnum(p, @bitCast(iCode)) != 0) {
                    entry = .non_ascii;
                    break;
                }
            } else {
                if (a[zCsr[0]] != 0) {
                    is = @intCast(@intFromPtr(zCsr) - @intFromPtr(text));
                    entry = .ascii;
                    break;
                }
                zCsr += 1;
            }
        }

        // Run through the tokenchars, folding into the output buffer.
        // `first` flags the loop iteration entered via a goto label.
        var first = true;
        while (first or @intFromPtr(zCsr) < @intFromPtr(zTerm)) {
            if (!first or entry == .none) {
                first = false;
                // Grow the output buffer to fit the largest possible utf-8 char.
                if (@intFromPtr(zOut) > @intFromPtr(pEnd)) {
                    const aNew: ?[*]u8 = @ptrCast(sqlite3_malloc64(@as(u64, @intCast(nFold)) * 2));
                    if (aNew == null) {
                        rc = SQLITE_NOMEM;
                        if (rc == SQLITE_DONE) rc = SQLITE_OK;
                        return rc;
                    }
                    const newFold = aNew.?;
                    zOut = newFold + (@intFromPtr(zOut) - @intFromPtr(p.aFold.?));
                    _ = memcpy(newFold, p.aFold, @intCast(nFold));
                    sqlite3_free(p.aFold);
                    p.aFold = newFold;
                    aFold = newFold;
                    nFold = nFold * 2;
                    p.nFold = nFold;
                    pEnd = newFold + @as(usize, @intCast(nFold - 6));
                }

                if (zCsr[0] & 0x80 != 0) {
                    // A non-ascii character.
                    readUtf8(&zCsr, zTerm, &iCode);
                    if (fts5UnicodeIsAlnum(p, @bitCast(iCode)) != 0 or sqlite3Fts5UnicodeIsdiacritic(@bitCast(iCode)) != 0) {
                        // non_ascii_tokenchar label
                        iCode = @bitCast(sqlite3Fts5UnicodeFold(@bitCast(iCode), p.eRemoveDiacritic));
                        if (iCode != 0) writeUtf8(&zOut, iCode);
                    } else {
                        break;
                    }
                } else if (a[zCsr[0]] == 0) {
                    // ascii separator: end of token.
                    break;
                } else {
                    // ascii_tokenchar label
                    if (zCsr[0] >= 'A' and zCsr[0] <= 'Z') {
                        zOut[0] = zCsr[0] + 32;
                    } else {
                        zOut[0] = zCsr[0];
                    }
                    zOut += 1;
                    zCsr += 1;
                }
            } else if (entry == .non_ascii) {
                first = false;
                // non_ascii_tokenchar label (jumped to from separator loop)
                iCode = @bitCast(sqlite3Fts5UnicodeFold(@bitCast(iCode), p.eRemoveDiacritic));
                if (iCode != 0) writeUtf8(&zOut, iCode);
            } else {
                first = false;
                // ascii_tokenchar label (jumped to from separator loop)
                if (zCsr[0] >= 'A' and zCsr[0] <= 'Z') {
                    zOut[0] = zCsr[0] + 32;
                } else {
                    zOut[0] = zCsr[0];
                }
                zOut += 1;
                zCsr += 1;
            }
            entry = .none;
            ie = @intCast(@intFromPtr(zCsr) - @intFromPtr(text));
        }

        rc = xToken.?(pCtx, 0, aFold, @intCast(@intFromPtr(zOut) - @intFromPtr(aFold)), is, ie);
    }

    if (rc == SQLITE_DONE) rc = SQLITE_OK;
    return rc;
}

// ===========================================================================
// porter stemmer (25148-25920)
// ===========================================================================
const PorterTokenizer = extern struct {
    tokenizer_v2: fts5_tokenizer_v2, // Parent tokenizer module
    pTokenizer: ?*Fts5Tokenizer, // Parent tokenizer instance
    aBuf: [FTS5_PORTER_MAX_TOKEN + 64]u8,
};

const XToken2 = ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int;

const PorterContext = extern struct {
    pCtx: ?*anyopaque,
    xToken: XToken2,
    aBuf: ?[*]u8,
};

fn fts5PorterDelete(pTok: ?*Fts5Tokenizer) callconv(.c) void {
    if (pTok) |pt| {
        const p: *PorterTokenizer = @ptrCast(@alignCast(pt));
        if (p.pTokenizer) |inner| {
            p.tokenizer_v2.xDelete.?(inner);
        }
        sqlite3_free(p);
    }
}

fn fts5PorterCreate(
    pCtx: ?*anyopaque,
    azArg0: ?[*]const ?[*:0]const u8,
    nArg0: c_int,
    ppOut: *?*Fts5Tokenizer,
) callconv(.c) c_int {
    const pApi: *fts5_api = @ptrCast(@alignCast(pCtx.?));
    var rc: c_int = SQLITE_OK;
    var pUserdata: ?*anyopaque = null;
    var zBase: [*:0]const u8 = "unicode61";
    var pV2: ?*fts5_tokenizer_v2 = null;
    var azArg = azArg0;
    var nArg = nArg0;

    while (nArg > 0) {
        if (sqlite3_stricmp(azArg.?[0].?, "porter") == 0) {
            nArg -= 1;
            azArg = azArg.? + 1;
        } else {
            zBase = azArg.?[0].?;
            break;
        }
    }

    const pRet: ?*PorterTokenizer = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(PorterTokenizer))));
    if (pRet) |pr| {
        _ = memset(pr, 0, @sizeOf(PorterTokenizer));
        rc = pApi.xFindTokenizer_v2.?(pApi, zBase, &pUserdata, &pV2);
    } else {
        rc = SQLITE_NOMEM;
    }
    if (rc == SQLITE_OK) {
        const pr = pRet.?;
        const nArg2: c_int = if (nArg > 0) nArg - 1 else 0;
        const az2: ?[*]const ?[*:0]const u8 = if (nArg2 != 0) azArg.? + 1 else null;
        _ = memcpy(&pr.tokenizer_v2, pV2, @sizeOf(fts5_tokenizer_v2));
        rc = pr.tokenizer_v2.xCreate.?(pUserdata, az2, nArg2, &pr.pTokenizer);
    }

    if (rc != SQLITE_OK) {
        fts5PorterDelete(@ptrCast(pRet));
        ppOut.* = null;
    } else {
        ppOut.* = @ptrCast(pRet);
    }
    return rc;
}

fn fts5PorterIsVowel(c: u8, bYIsVowel: bool) bool {
    return (c == 'a' or c == 'e' or c == 'i' or c == 'o' or c == 'u' or (bYIsVowel and c == 'y'));
}

fn fts5PorterGobbleVC(zStem: [*]const u8, nStem: c_int, bPrevCons: bool) c_int {
    var bCons = bPrevCons;
    var i: c_int = 0;

    // Scan for a vowel.
    while (i < nStem) : (i += 1) {
        bCons = !fts5PorterIsVowel(zStem[@intCast(i)], bCons);
        if (bCons == false) break;
    }

    // Scan for a consonant.
    i += 1;
    while (i < nStem) : (i += 1) {
        bCons = !fts5PorterIsVowel(zStem[@intCast(i)], bCons);
        if (bCons) return i + 1;
    }
    return 0;
}

/// porter rule condition: (m > 0)
fn fts5Porter_MGt0(zStem: [*]const u8, nStem: c_int) bool {
    return fts5PorterGobbleVC(zStem, nStem, false) != 0;
}

/// porter rule condition: (m > 1)
fn fts5Porter_MGt1(zStem: [*]const u8, nStem: c_int) bool {
    const n = fts5PorterGobbleVC(zStem, nStem, false);
    if (n != 0 and fts5PorterGobbleVC(zStem + @as(usize, @intCast(n)), nStem - n, true) != 0) {
        return true;
    }
    return false;
}

/// porter rule condition: (m = 1)
fn fts5Porter_MEq1(zStem: [*]const u8, nStem: c_int) bool {
    const n = fts5PorterGobbleVC(zStem, nStem, false);
    if (n != 0 and 0 == fts5PorterGobbleVC(zStem + @as(usize, @intCast(n)), nStem - n, true)) {
        return true;
    }
    return false;
}

/// porter rule condition: (*o)
fn fts5Porter_Ostar(zStem: [*]const u8, nStem: c_int) bool {
    if (zStem[@intCast(nStem - 1)] == 'w' or zStem[@intCast(nStem - 1)] == 'x' or zStem[@intCast(nStem - 1)] == 'y') {
        return false;
    } else {
        var mask: c_int = 0;
        var bCons = false;
        var i: c_int = 0;
        while (i < nStem) : (i += 1) {
            bCons = !fts5PorterIsVowel(zStem[@intCast(i)], bCons);
            mask = ((mask << 1) + @as(c_int, @intFromBool(bCons))) & 0x0007;
        }
        return (mask == 0x0005);
    }
}

/// porter rule condition: (m > 1 and (*S or *T))
fn fts5Porter_MGt1_and_S_or_T(zStem: [*]const u8, nStem: c_int) bool {
    return (zStem[@intCast(nStem - 1)] == 's' or zStem[@intCast(nStem - 1)] == 't') and
        fts5Porter_MGt1(zStem, nStem);
}

/// porter rule condition: (*v*)
fn fts5Porter_Vowel(zStem: [*]const u8, nStem: c_int) bool {
    var i: c_int = 0;
    while (i < nStem) : (i += 1) {
        if (fts5PorterIsVowel(zStem[@intCast(i)], i > 0)) {
            return true;
        }
    }
    return false;
}

// --- GENERATED CODE (mkportersteps.tcl) -------------------------------------
// aBuf is char*; comparisons use memcmp. Helper: compare suffix.
inline fn sfx(aBuf: [*]const u8, nBuf: c_int, comptime s: []const u8) bool {
    return nBuf > s.len and 0 == memcmpZ(aBuf + @as(usize, @intCast(nBuf)) - s.len, s);
}
inline fn memcmpZ(a: [*]const u8, comptime s: []const u8) c_int {
    inline for (s, 0..) |ch, k| {
        if (a[k] != ch) return 1;
    }
    return 0;
}
inline fn cpy(aBuf: [*]u8, at: c_int, comptime s: []const u8) void {
    inline for (s, 0..) |ch, k| {
        aBuf[@as(usize, @intCast(at)) + k] = ch;
    }
}

fn fts5PorterStep4(aBuf: [*]u8, pnBuf: *c_int) c_int {
    const ret: c_int = 0;
    const nBuf = pnBuf.*;
    switch (aBuf[@intCast(nBuf - 2)]) {
        'a' => {
            if (sfx(aBuf, nBuf, "al")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 2)) pnBuf.* = nBuf - 2;
            }
        },
        'c' => {
            if (sfx(aBuf, nBuf, "ance")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 4)) pnBuf.* = nBuf - 4;
            } else if (sfx(aBuf, nBuf, "ence")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 4)) pnBuf.* = nBuf - 4;
            }
        },
        'e' => {
            if (sfx(aBuf, nBuf, "er")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 2)) pnBuf.* = nBuf - 2;
            }
        },
        'i' => {
            if (sfx(aBuf, nBuf, "ic")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 2)) pnBuf.* = nBuf - 2;
            }
        },
        'l' => {
            if (sfx(aBuf, nBuf, "able")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 4)) pnBuf.* = nBuf - 4;
            } else if (sfx(aBuf, nBuf, "ible")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 4)) pnBuf.* = nBuf - 4;
            }
        },
        'n' => {
            if (sfx(aBuf, nBuf, "ant")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            } else if (sfx(aBuf, nBuf, "ement")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 5)) pnBuf.* = nBuf - 5;
            } else if (sfx(aBuf, nBuf, "ment")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 4)) pnBuf.* = nBuf - 4;
            } else if (sfx(aBuf, nBuf, "ent")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            }
        },
        'o' => {
            if (sfx(aBuf, nBuf, "ion")) {
                if (fts5Porter_MGt1_and_S_or_T(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            } else if (sfx(aBuf, nBuf, "ou")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 2)) pnBuf.* = nBuf - 2;
            }
        },
        's' => {
            if (sfx(aBuf, nBuf, "ism")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            }
        },
        't' => {
            if (sfx(aBuf, nBuf, "ate")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            } else if (sfx(aBuf, nBuf, "iti")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            }
        },
        'u' => {
            if (sfx(aBuf, nBuf, "ous")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            }
        },
        'v' => {
            if (sfx(aBuf, nBuf, "ive")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            }
        },
        'z' => {
            if (sfx(aBuf, nBuf, "ize")) {
                if (fts5Porter_MGt1(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            }
        },
        else => {},
    }
    return ret;
}

fn fts5PorterStep1B2(aBuf: [*]u8, pnBuf: *c_int) c_int {
    var ret: c_int = 0;
    const nBuf = pnBuf.*;
    switch (aBuf[@intCast(nBuf - 2)]) {
        'a' => {
            if (sfx(aBuf, nBuf, "at")) {
                cpy(aBuf, nBuf - 2, "ate");
                pnBuf.* = nBuf - 2 + 3;
                ret = 1;
            }
        },
        'b' => {
            if (sfx(aBuf, nBuf, "bl")) {
                cpy(aBuf, nBuf - 2, "ble");
                pnBuf.* = nBuf - 2 + 3;
                ret = 1;
            }
        },
        'i' => {
            if (sfx(aBuf, nBuf, "iz")) {
                cpy(aBuf, nBuf - 2, "ize");
                pnBuf.* = nBuf - 2 + 3;
                ret = 1;
            }
        },
        else => {},
    }
    return ret;
}

fn fts5PorterStep2(aBuf: [*]u8, pnBuf: *c_int) c_int {
    const ret: c_int = 0;
    const nBuf = pnBuf.*;
    switch (aBuf[@intCast(nBuf - 2)]) {
        'a' => {
            if (sfx(aBuf, nBuf, "ational")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 7)) {
                    cpy(aBuf, nBuf - 7, "ate");
                    pnBuf.* = nBuf - 7 + 3;
                }
            } else if (sfx(aBuf, nBuf, "tional")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 6)) {
                    cpy(aBuf, nBuf - 6, "tion");
                    pnBuf.* = nBuf - 6 + 4;
                }
            }
        },
        'c' => {
            if (sfx(aBuf, nBuf, "enci")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) {
                    cpy(aBuf, nBuf - 4, "ence");
                    pnBuf.* = nBuf - 4 + 4;
                }
            } else if (sfx(aBuf, nBuf, "anci")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) {
                    cpy(aBuf, nBuf - 4, "ance");
                    pnBuf.* = nBuf - 4 + 4;
                }
            }
        },
        'e' => {
            if (sfx(aBuf, nBuf, "izer")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) {
                    cpy(aBuf, nBuf - 4, "ize");
                    pnBuf.* = nBuf - 4 + 3;
                }
            }
        },
        'g' => {
            if (sfx(aBuf, nBuf, "logi")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) {
                    cpy(aBuf, nBuf - 4, "log");
                    pnBuf.* = nBuf - 4 + 3;
                }
            }
        },
        'l' => {
            if (sfx(aBuf, nBuf, "bli")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 3)) {
                    cpy(aBuf, nBuf - 3, "ble");
                    pnBuf.* = nBuf - 3 + 3;
                }
            } else if (sfx(aBuf, nBuf, "alli")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) {
                    cpy(aBuf, nBuf - 4, "al");
                    pnBuf.* = nBuf - 4 + 2;
                }
            } else if (sfx(aBuf, nBuf, "entli")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "ent");
                    pnBuf.* = nBuf - 5 + 3;
                }
            } else if (sfx(aBuf, nBuf, "eli")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 3)) {
                    cpy(aBuf, nBuf - 3, "e");
                    pnBuf.* = nBuf - 3 + 1;
                }
            } else if (sfx(aBuf, nBuf, "ousli")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "ous");
                    pnBuf.* = nBuf - 5 + 3;
                }
            }
        },
        'o' => {
            if (sfx(aBuf, nBuf, "ization")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 7)) {
                    cpy(aBuf, nBuf - 7, "ize");
                    pnBuf.* = nBuf - 7 + 3;
                }
            } else if (sfx(aBuf, nBuf, "ation")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "ate");
                    pnBuf.* = nBuf - 5 + 3;
                }
            } else if (sfx(aBuf, nBuf, "ator")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) {
                    cpy(aBuf, nBuf - 4, "ate");
                    pnBuf.* = nBuf - 4 + 3;
                }
            }
        },
        's' => {
            if (sfx(aBuf, nBuf, "alism")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "al");
                    pnBuf.* = nBuf - 5 + 2;
                }
            } else if (sfx(aBuf, nBuf, "iveness")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 7)) {
                    cpy(aBuf, nBuf - 7, "ive");
                    pnBuf.* = nBuf - 7 + 3;
                }
            } else if (sfx(aBuf, nBuf, "fulness")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 7)) {
                    cpy(aBuf, nBuf - 7, "ful");
                    pnBuf.* = nBuf - 7 + 3;
                }
            } else if (sfx(aBuf, nBuf, "ousness")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 7)) {
                    cpy(aBuf, nBuf - 7, "ous");
                    pnBuf.* = nBuf - 7 + 3;
                }
            }
        },
        't' => {
            if (sfx(aBuf, nBuf, "aliti")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "al");
                    pnBuf.* = nBuf - 5 + 2;
                }
            } else if (sfx(aBuf, nBuf, "iviti")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "ive");
                    pnBuf.* = nBuf - 5 + 3;
                }
            } else if (sfx(aBuf, nBuf, "biliti")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 6)) {
                    cpy(aBuf, nBuf - 6, "ble");
                    pnBuf.* = nBuf - 6 + 3;
                }
            }
        },
        else => {},
    }
    return ret;
}

fn fts5PorterStep3(aBuf: [*]u8, pnBuf: *c_int) c_int {
    const ret: c_int = 0;
    const nBuf = pnBuf.*;
    switch (aBuf[@intCast(nBuf - 2)]) {
        'a' => {
            if (sfx(aBuf, nBuf, "ical")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) {
                    cpy(aBuf, nBuf - 4, "ic");
                    pnBuf.* = nBuf - 4 + 2;
                }
            }
        },
        's' => {
            if (sfx(aBuf, nBuf, "ness")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 4)) pnBuf.* = nBuf - 4;
            }
        },
        't' => {
            if (sfx(aBuf, nBuf, "icate")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "ic");
                    pnBuf.* = nBuf - 5 + 2;
                }
            } else if (sfx(aBuf, nBuf, "iciti")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "ic");
                    pnBuf.* = nBuf - 5 + 2;
                }
            }
        },
        'u' => {
            if (sfx(aBuf, nBuf, "ful")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 3)) pnBuf.* = nBuf - 3;
            }
        },
        'v' => {
            if (sfx(aBuf, nBuf, "ative")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) pnBuf.* = nBuf - 5;
            }
        },
        'z' => {
            if (sfx(aBuf, nBuf, "alize")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 5)) {
                    cpy(aBuf, nBuf - 5, "al");
                    pnBuf.* = nBuf - 5 + 2;
                }
            }
        },
        else => {},
    }
    return ret;
}

fn fts5PorterStep1B(aBuf: [*]u8, pnBuf: *c_int) c_int {
    var ret: c_int = 0;
    const nBuf = pnBuf.*;
    switch (aBuf[@intCast(nBuf - 2)]) {
        'e' => {
            if (sfx(aBuf, nBuf, "eed")) {
                if (fts5Porter_MGt0(aBuf, nBuf - 3)) {
                    cpy(aBuf, nBuf - 3, "ee");
                    pnBuf.* = nBuf - 3 + 2;
                }
            } else if (sfx(aBuf, nBuf, "ed")) {
                if (fts5Porter_Vowel(aBuf, nBuf - 2)) {
                    pnBuf.* = nBuf - 2;
                    ret = 1;
                }
            }
        },
        'n' => {
            if (sfx(aBuf, nBuf, "ing")) {
                if (fts5Porter_Vowel(aBuf, nBuf - 3)) {
                    pnBuf.* = nBuf - 3;
                    ret = 1;
                }
            }
        },
        else => {},
    }
    return ret;
}
// --- end GENERATED CODE -----------------------------------------------------

fn fts5PorterStep1A(aBuf: [*]u8, pnBuf: *c_int) void {
    const nBuf = pnBuf.*;
    if (aBuf[@intCast(nBuf - 1)] == 's') {
        if (aBuf[@intCast(nBuf - 2)] == 'e') {
            if ((nBuf > 4 and aBuf[@intCast(nBuf - 4)] == 's' and aBuf[@intCast(nBuf - 3)] == 's') or
                (nBuf > 3 and aBuf[@intCast(nBuf - 3)] == 'i'))
            {
                pnBuf.* = nBuf - 2;
            } else {
                pnBuf.* = nBuf - 1;
            }
        } else if (aBuf[@intCast(nBuf - 2)] != 's') {
            pnBuf.* = nBuf - 1;
        }
    }
}

fn fts5PorterCb(
    pCtx: ?*anyopaque,
    tflags: c_int,
    pToken: ?[*]const u8,
    nToken: c_int,
    iStart: c_int,
    iEnd: c_int,
) callconv(.c) c_int {
    const p: *PorterContext = @ptrCast(@alignCast(pCtx.?));

    if (nToken > FTS5_PORTER_MAX_TOKEN or nToken < 3) {
        return p.xToken.?(p.pCtx, tflags, pToken, nToken, iStart, iEnd);
    }
    const aBuf = p.aBuf.?;
    var nBuf = nToken;
    _ = memcpy(aBuf, pToken, @intCast(nBuf));

    // Step 1.
    fts5PorterStep1A(aBuf, &nBuf);
    if (fts5PorterStep1B(aBuf, &nBuf) != 0) {
        if (fts5PorterStep1B2(aBuf, &nBuf) == 0) {
            const c = aBuf[@intCast(nBuf - 1)];
            if (fts5PorterIsVowel(c, false) == false and
                c != 'l' and c != 's' and c != 'z' and c == aBuf[@intCast(nBuf - 2)])
            {
                nBuf -= 1;
            } else if (fts5Porter_MEq1(aBuf, nBuf) and fts5Porter_Ostar(aBuf, nBuf)) {
                aBuf[@intCast(nBuf)] = 'e';
                nBuf += 1;
            }
        }
    }

    // Step 1C.
    if (aBuf[@intCast(nBuf - 1)] == 'y' and fts5Porter_Vowel(aBuf, nBuf - 1)) {
        aBuf[@intCast(nBuf - 1)] = 'i';
    }

    // Steps 2 through 4.
    _ = fts5PorterStep2(aBuf, &nBuf);
    _ = fts5PorterStep3(aBuf, &nBuf);
    _ = fts5PorterStep4(aBuf, &nBuf);

    // Step 5a.
    if (aBuf[@intCast(nBuf - 1)] == 'e') {
        if (fts5Porter_MGt1(aBuf, nBuf - 1) or
            (fts5Porter_MEq1(aBuf, nBuf - 1) and !fts5Porter_Ostar(aBuf, nBuf - 1)))
        {
            nBuf -= 1;
        }
    }

    // Step 5b.
    if (nBuf > 1 and aBuf[@intCast(nBuf - 1)] == 'l' and
        aBuf[@intCast(nBuf - 2)] == 'l' and fts5Porter_MGt1(aBuf, nBuf - 1))
    {
        nBuf -= 1;
    }

    return p.xToken.?(p.pCtx, tflags, aBuf, nBuf, iStart, iEnd);
}

// v2 (locale-aware) tokenize callback type.
const XTokenizeV2 = ?*const fn (?*Fts5Tokenizer, ?*anyopaque, c_int, ?[*]const u8, c_int, ?[*]const u8, c_int, XToken1) callconv(.c) c_int;

fn fts5PorterTokenize(
    pTokenizer: ?*Fts5Tokenizer,
    pCtx: ?*anyopaque,
    flags: c_int,
    pText: ?[*]const u8,
    nText: c_int,
    pLoc: ?[*]const u8,
    nLoc: c_int,
    xToken: XToken1,
) callconv(.c) c_int {
    const p: *PorterTokenizer = @ptrCast(@alignCast(pTokenizer.?));
    var sCtx: PorterContext = undefined;
    sCtx.xToken = xToken;
    sCtx.pCtx = pCtx;
    sCtx.aBuf = &p.aBuf;
    return p.tokenizer_v2.xTokenize.?(
        p.pTokenizer,
        @ptrCast(&sCtx),
        flags,
        pText,
        nText,
        pLoc,
        nLoc,
        fts5PorterCb,
    );
}

// ===========================================================================
// trigram tokenizer (25923-26033)
// ===========================================================================
const TrigramTokenizer = extern struct {
    bFold: c_int, // True to fold to lower-case
    iFoldParam: c_int, // Parameter to pass to Fts5UnicodeFold()
};

fn fts5TriDelete(p: ?*Fts5Tokenizer) callconv(.c) void {
    sqlite3_free(p);
}

fn fts5TriCreate(
    pUnused: ?*anyopaque,
    azArg: ?[*]const ?[*:0]const u8,
    nArg: c_int,
    ppOut: *?*Fts5Tokenizer,
) callconv(.c) c_int {
    _ = pUnused;
    var rc: c_int = SQLITE_OK;
    var pNew: ?*TrigramTokenizer = null;
    if (@mod(nArg, 2) != 0) {
        rc = SQLITE_ERROR;
    } else {
        pNew = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(TrigramTokenizer))));
        if (pNew == null) {
            rc = SQLITE_NOMEM;
        } else {
            const pn = pNew.?;
            pn.bFold = 1;
            pn.iFoldParam = 0;

            var i: c_int = 0;
            while (rc == SQLITE_OK and i < nArg) : (i += 2) {
                const zArg = azArg.?[@intCast(i + 1)].?;
                if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "case_sensitive")) {
                    if ((zArg[0] != '0' and zArg[0] != '1') or zArg[1] != 0) {
                        rc = SQLITE_ERROR;
                    } else {
                        pn.bFold = @intFromBool(zArg[0] == '0');
                    }
                } else if (0 == sqlite3_stricmp(azArg.?[@intCast(i)].?, "remove_diacritics")) {
                    if ((zArg[0] != '0' and zArg[0] != '1' and zArg[0] != '2') or zArg[1] != 0) {
                        rc = SQLITE_ERROR;
                    } else {
                        pn.iFoldParam = if (zArg[0] != '0') 2 else 0;
                    }
                } else {
                    rc = SQLITE_ERROR;
                }
            }

            if (pn.iFoldParam != 0 and pn.bFold == 0) {
                rc = SQLITE_ERROR;
            }

            if (rc != SQLITE_OK) {
                fts5TriDelete(@ptrCast(pNew));
                pNew = null;
            }
        }
    }
    ppOut.* = @ptrCast(pNew);
    return rc;
}

fn fts5TriTokenize(
    pTok: ?*Fts5Tokenizer,
    pCtx: ?*anyopaque,
    unusedFlags: c_int,
    pText: ?[*]const u8,
    nText: c_int,
    xToken: XToken1,
) callconv(.c) c_int {
    _ = unusedFlags;
    const p: *TrigramTokenizer = @ptrCast(@alignCast(pTok.?));
    var rc: c_int = SQLITE_OK;
    var aBuf: [32]u8 = undefined;
    var zOut: [*]u8 = &aBuf;
    var ii: usize = 0;
    const text: ?[*]const u8 = pText;
    var zIn: [*]const u8 = if (text) |t| t else undefined;
    const zEof: [*]const u8 = if (text) |t| t + @as(usize, @intCast(nText)) else undefined;
    var iCode: u32 = 0;
    var aStart: [3]c_int = undefined;

    // Populate aBuf[] with the first trigram's characters.
    ii = 0;
    while (ii < 3) : (ii += 1) {
        while (true) {
            aStart[ii] = @intCast(@intFromPtr(zIn) - @intFromPtr(text.?));
            if (@intFromPtr(zIn) >= @intFromPtr(zEof)) return SQLITE_OK;
            readUtf8(&zIn, zEof, &iCode);
            if (p.bFold != 0) iCode = @bitCast(sqlite3Fts5UnicodeFold(@bitCast(iCode), p.iFoldParam));
            if (iCode != 0) break;
        }
        writeUtf8(&zOut, iCode);
    }

    while (true) {
        var iNext: c_int = undefined;

        // Read characters up until the first non-diacritic.
        while (true) {
            iNext = @intCast(@intFromPtr(zIn) - @intFromPtr(text.?));
            if (@intFromPtr(zIn) >= @intFromPtr(zEof)) {
                iCode = 0;
                break;
            }
            readUtf8(&zIn, zEof, &iCode);
            if (p.bFold != 0) iCode = @bitCast(sqlite3Fts5UnicodeFold(@bitCast(iCode), p.iFoldParam));
            if (iCode != 0) break;
        }

        // Pass the current trigram back to fts5.
        rc = xToken.?(pCtx, 0, &aBuf, @intCast(@intFromPtr(zOut) - @intFromPtr(@as([*]u8, &aBuf))), aStart[0], iNext);
        if (iCode == 0 or rc != SQLITE_OK) break;

        // Remove the first character from aBuf[]; append codepoint iCode.
        var z1: [*]const u8 = &aBuf;
        skipUtf8(&z1);
        const nShift = @intFromPtr(z1) - @intFromPtr(@as([*]const u8, &aBuf));
        _ = memmove(&aBuf, z1, @intFromPtr(zOut) - @intFromPtr(z1));
        zOut -= nShift;
        writeUtf8(&zOut, iCode);

        // Update aStart[].
        aStart[0] = aStart[1];
        aStart[1] = aStart[2];
        aStart[2] = iNext;
    }

    return rc;
}

// ===========================================================================
// Registry helpers (26035-26097)
// ===========================================================================

const XCreateFn = ?*const fn (?*anyopaque, ?[*]const ?[*:0]const u8, c_int, *?*Fts5Tokenizer) callconv(.c) c_int;

/// fts5_tokenize.c 1435-1446: pattern style supported by a tokenizer. EXPORTED.
export fn sqlite3Fts5TokenizerPattern(
    xCreate: XCreateFn,
    pTok: ?*Fts5Tokenizer,
) callconv(.c) c_int {
    if (xCreate == @as(XCreateFn, fts5TriCreate)) {
        const p: *TrigramTokenizer = @ptrCast(@alignCast(pTok.?));
        if (p.iFoldParam == 0) {
            return if (p.bFold != 0) FTS5_PATTERN_LIKE else FTS5_PATTERN_GLOB;
        }
    }
    return FTS5_PATTERN_NONE;
}

/// fts5_tokenize.c 1453-1455: true if the configured tokenizer is "trigram".
/// EXPORTED.
export fn sqlite3Fts5TokenizerPreload(p: *Fts5TokenizerConfig) callconv(.c) c_int {
    return @intFromBool(p.nArg >= 1 and 0 == sqlite3_stricmp(p.azArg.?[0].?, "trigram"));
}

/// fts5_tokenize.c 1461-1497: register all built-in tokenizers. EXPORTED.
export fn sqlite3Fts5TokenizerInit(pApi: *fts5_api) callconv(.c) c_int {
    const BuiltinTokenizer = struct {
        zName: [*:0]const u8,
        x: fts5_tokenizer,
    };
    var aBuiltin = [_]BuiltinTokenizer{
        .{ .zName = "unicode61", .x = .{ .xCreate = fts5UnicodeCreate, .xDelete = fts5UnicodeDelete, .xTokenize = fts5UnicodeTokenize } },
        .{ .zName = "ascii", .x = .{ .xCreate = fts5AsciiCreate, .xDelete = fts5AsciiDelete, .xTokenize = fts5AsciiTokenize } },
        .{ .zName = "trigram", .x = .{ .xCreate = fts5TriCreate, .xDelete = fts5TriDelete, .xTokenize = fts5TriTokenize } },
    };

    var rc: c_int = SQLITE_OK;
    var i: usize = 0;
    while (rc == SQLITE_OK and i < aBuiltin.len) : (i += 1) {
        rc = pApi.xCreateTokenizer.?(pApi, aBuiltin[i].zName, @ptrCast(pApi), &aBuiltin[i].x, null);
    }
    if (rc == SQLITE_OK) {
        var sPorter = fts5_tokenizer_v2{
            .iVersion = 2,
            .xCreate = fts5PorterCreate,
            .xDelete = fts5PorterDelete,
            .xTokenize = fts5PorterTokenize,
        };
        rc = pApi.xCreateTokenizer_v2.?(pApi, "porter", @ptrCast(pApi), &sPorter, null);
    }
    return rc;
}

comptime {
    _ = int;
}
