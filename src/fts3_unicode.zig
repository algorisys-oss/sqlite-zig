//! Zig port of SQLite's FTS3 "unicode" (unicode61) tokenizer (ext/fts3/fts3_unicode.c).
//!
//! Drop-in replacement exporting the single external symbol
//! `sqlite3Fts3UnicodeTokenizer`, the getter fts3.c calls to obtain this
//! tokenizer's `sqlite3_tokenizer_module` vtable. The tokenizer normalizes input
//! UTF-8 text into case-folded, optionally diacritic-stripped tokens, honoring
//! the `tokenchars=`, `separators=`, and `remove_diacritics=0|1|2` arguments.
//!
//! The Unicode *data* functions — `sqlite3FtsUnicodeFold`,
//! `sqlite3FtsUnicodeIsalnum`, `sqlite3FtsUnicodeIsdiacritic` — live in the
//! companion fts3_unicode2.c (generated case-fold/category tables) which stays in
//! C for now and is reached here as `extern fn`.
//!
//! Coupling taxonomy: the public ABI types `sqlite3_tokenizer_module`,
//! `sqlite3_tokenizer`, and `sqlite3_tokenizer_cursor` (from fts3_tokenizer.h)
//! are mirrored as `extern struct` because the module vtable and the `base`
//! prefixes are read across the boundary by fts3.c. The `unicode_tokenizer` and
//! `unicode_cursor` structs are *private* to this module — only this file
//! allocates and dereferences them — so they are plain internal `extern struct`s
//! (no sizeof assert, no c_layout offset needed).
//!
//! Config-invariant: no `@import("config")`. The only build switches gating the
//! C file (SQLITE_DISABLE_FTS3_UNICODE off; SQLITE_ENABLE_FTS3 on) are constant
//! across both this project's builds, and the C `assert()`s compile away in
//! production exactly as the Zig `assert`s do in ReleaseFast — neither has an
//! externally visible effect. Couplings are pure function calls plus the
//! malloc/free/realloc allocators; no internal struct layout is touched.

const std = @import("std");

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_DONE: c_int = 101;

// --- Public ABI types (fts3_tokenizer.h) ---

/// `struct sqlite3_tokenizer` — base of every tokenizer instance.
const Sqlite3Tokenizer = extern struct {
    pModule: ?*const Sqlite3TokenizerModule,
};

/// `struct sqlite3_tokenizer_cursor` — base of every tokenizer cursor.
const Sqlite3TokenizerCursor = extern struct {
    pTokenizer: ?*Sqlite3Tokenizer,
};

/// `struct sqlite3_tokenizer_module` — the tokenizer vtable.
const Sqlite3TokenizerModule = extern struct {
    iVersion: c_int,
    xCreate: ?*const fn (c_int, ?[*]const ?[*:0]const u8, *?*Sqlite3Tokenizer) callconv(.c) c_int,
    xDestroy: ?*const fn (?*Sqlite3Tokenizer) callconv(.c) c_int,
    xOpen: ?*const fn (?*Sqlite3Tokenizer, ?[*]const u8, c_int, *?*Sqlite3TokenizerCursor) callconv(.c) c_int,
    xClose: ?*const fn (?*Sqlite3TokenizerCursor) callconv(.c) c_int,
    xNext: ?*const fn (?*Sqlite3TokenizerCursor, *?[*]const u8, *c_int, *c_int, *c_int, *c_int) callconv(.c) c_int,
    xLanguageid: ?*const fn (?*Sqlite3TokenizerCursor, c_int) callconv(.c) c_int,
};

// --- Private module/cursor instances (this file owns the layout) ---

const UnicodeTokenizer = extern struct {
    base: Sqlite3Tokenizer,
    eRemoveDiacritic: c_int,
    nException: c_int,
    aiException: ?[*]c_int,
};

const UnicodeCursor = extern struct {
    base: Sqlite3TokenizerCursor,
    aInput: ?[*]const u8, // Input text being tokenized
    nInput: c_int, // Size of aInput[] in bytes
    iOff: c_int, // Current offset within aInput[]
    iToken: c_int, // Index of next token to be returned
    zToken: ?[*]u8, // storage for current token
    nAlloc: c_int, // space allocated at zToken
};

// --- C helpers resolved at link time ---

// From fts3_unicode2.c (stays in C): the Unicode case-fold / category tables.
extern fn sqlite3FtsUnicodeFold(c: c_int, eRemoveDiacritic: c_int) c_int;
extern fn sqlite3FtsUnicodeIsalnum(c: c_int) c_int;
extern fn sqlite3FtsUnicodeIsdiacritic(c: c_int) c_int;

// Public SQLite allocators / libc.
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn strlen(s: [*:0]const u8) usize;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

// --- READ_UTF8 / WRITE_UTF8 (copied from utf.c, as in the C source) ---

/// First-byte translation table for 2..4 byte UTF-8 sequences (utf.c).
const utf8Trans1 = [64]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00,
};

/// READ_UTF8: decode one codepoint starting at `z.*`, advancing `z.*` past the
/// bytes consumed (never past `zTerm`). Matches utf.c's macro, including the
/// surrogate / non-character fold to U+FFFD. All arithmetic is on `u32` and
/// wraps exactly as the C unsigned-int math does.
inline fn readUtf8(z: *[*]const u8, zTerm: [*]const u8) u32 {
    var c: u32 = z.*[0];
    z.* += 1;
    if (c >= 0xc0) {
        c = utf8Trans1[c - 0xc0];
        while (@intFromPtr(z.*) != @intFromPtr(zTerm) and (z.*[0] & 0xc0) == 0x80) {
            c = (c *% 64) +% (0x3f & @as(u32, z.*[0]));
            z.* += 1;
        }
        if (c < 0x80 or (c & 0xFFFFF800) == 0xD800 or (c & 0xFFFFFFFE) == 0xFFFE) {
            c = 0xFFFD;
        }
    }
    return c;
}

/// WRITE_UTF8: encode codepoint `c` to UTF-8 at `zOut.*`, advancing the pointer.
/// Mirrors the utf.c macro; `(u8)` casts become `@truncate`.
inline fn writeUtf8(zOut: *[*]u8, c: u32) void {
    if (c < 0x00080) {
        zOut.*[0] = @truncate(c & 0xFF);
        zOut.* += 1;
    } else if (c < 0x00800) {
        zOut.*[0] = 0xC0 +% @as(u8, @truncate((c >> 6) & 0x1F));
        zOut.*[1] = 0x80 +% @as(u8, @truncate(c & 0x3F));
        zOut.* += 2;
    } else if (c < 0x10000) {
        zOut.*[0] = 0xE0 +% @as(u8, @truncate((c >> 12) & 0x0F));
        zOut.*[1] = 0x80 +% @as(u8, @truncate((c >> 6) & 0x3F));
        zOut.*[2] = 0x80 +% @as(u8, @truncate(c & 0x3F));
        zOut.* += 3;
    } else {
        zOut.*[0] = 0xF0 +% @as(u8, @truncate((c >> 18) & 0x07));
        zOut.*[1] = 0x80 +% @as(u8, @truncate((c >> 12) & 0x3F));
        zOut.*[2] = 0x80 +% @as(u8, @truncate((c >> 6) & 0x3F));
        zOut.*[3] = 0x80 +% @as(u8, @truncate(c & 0x3F));
        zOut.* += 4;
    }
}

// --- Tokenizer methods ---

/// Destroy a tokenizer allocated by unicodeCreate().
fn unicodeDestroy(pTokenizer: ?*Sqlite3Tokenizer) callconv(.c) c_int {
    if (pTokenizer) |pt| {
        const p: *UnicodeTokenizer = @ptrCast(@alignCast(pt));
        sqlite3_free(@ptrCast(p.aiException));
        sqlite3_free(@ptrCast(p));
    }
    return SQLITE_OK;
}

/// As part of a tokenchars= or separators= option, register the codepoints in
/// zIn/nIn whose default Isalnum() classification must be flipped. Diacritics are
/// silently ignored. Exceptions are kept sorted in aiException[].
fn unicodeAddExceptions(
    p: *UnicodeTokenizer,
    bAlnum: c_int, // Replace Isalnum() return value with this
    zIn: [*]const u8,
    nIn: c_int,
) c_int {
    var z: [*]const u8 = zIn;
    const zTerm: [*]const u8 = zIn + @as(usize, @intCast(nIn));
    var nEntry: c_int = 0;

    std.debug.assert(bAlnum == 0 or bAlnum == 1);

    while (@intFromPtr(z) < @intFromPtr(zTerm)) {
        const iCode: u32 = readUtf8(&z, zTerm);
        std.debug.assert((sqlite3FtsUnicodeIsalnum(@bitCast(iCode)) & @as(c_int, @bitCast(@as(u32, 0xFFFFFFFE)))) == 0);
        if (sqlite3FtsUnicodeIsalnum(@bitCast(iCode)) != bAlnum and
            sqlite3FtsUnicodeIsdiacritic(@bitCast(iCode)) == 0)
        {
            nEntry += 1;
        }
    }

    if (nEntry != 0) {
        const aNew: ?[*]c_int = @ptrCast(@alignCast(sqlite3_realloc64(
            @ptrCast(p.aiException),
            @as(u64, @intCast(p.nException + nEntry)) * @sizeOf(c_int),
        )));
        if (aNew == null) return SQLITE_NOMEM;
        const a = aNew.?;
        var nNew: c_int = p.nException;

        z = zIn;
        while (@intFromPtr(z) < @intFromPtr(zTerm)) {
            const iCode: u32 = readUtf8(&z, zTerm);
            if (sqlite3FtsUnicodeIsalnum(@bitCast(iCode)) != bAlnum and
                sqlite3FtsUnicodeIsdiacritic(@bitCast(iCode)) == 0)
            {
                const code: c_int = @bitCast(iCode);
                var i: c_int = 0;
                while (i < nNew and a[@intCast(i)] < code) : (i += 1) {}
                var j: c_int = nNew;
                while (j > i) : (j -= 1) a[@intCast(j)] = a[@intCast(j - 1)];
                a[@intCast(i)] = code;
                nNew += 1;
            }
        }
        p.aiException = a;
        p.nException = nNew;
    }

    return SQLITE_OK;
}

/// Return true if the p->aiException[] array contains the value iCode.
fn unicodeIsException(p: *UnicodeTokenizer, iCode: c_int) c_int {
    if (p.nException > 0) {
        const a = p.aiException.?;
        var iLo: c_int = 0;
        var iHi: c_int = p.nException - 1;
        while (iHi >= iLo) {
            const iTest = @divTrunc(iHi + iLo, 2);
            const v = a[@intCast(iTest)];
            if (iCode == v) {
                return 1;
            } else if (iCode > v) {
                iLo = iTest + 1;
            } else {
                iHi = iTest - 1;
            }
        }
    }
    return 0;
}

/// Return true if, for tokenization, codepoint iCode is a token character.
fn unicodeIsAlnum(p: *UnicodeTokenizer, iCode: c_int) c_int {
    std.debug.assert((sqlite3FtsUnicodeIsalnum(iCode) & @as(c_int, @bitCast(@as(u32, 0xFFFFFFFE)))) == 0);
    return sqlite3FtsUnicodeIsalnum(iCode) ^ unicodeIsException(p, iCode);
}

/// Create a new tokenizer instance.
fn unicodeCreate(
    nArg: c_int,
    azArg: ?[*]const ?[*:0]const u8,
    pp: *?*Sqlite3Tokenizer,
) callconv(.c) c_int {
    const pNew: ?*UnicodeTokenizer = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(UnicodeTokenizer))));
    if (pNew == null) return SQLITE_NOMEM;
    const t = pNew.?;
    @memset(std.mem.asBytes(t), 0);
    t.eRemoveDiacritic = 1;

    var rc: c_int = SQLITE_OK;
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nArg) : (i += 1) {
        const z: [*:0]const u8 = azArg.?[@intCast(i)].?;
        const n: c_int = @intCast(strlen(z));

        if (n == 19 and memcmp("remove_diacritics=1", z, 19) == 0) {
            t.eRemoveDiacritic = 1;
        } else if (n == 19 and memcmp("remove_diacritics=0", z, 19) == 0) {
            t.eRemoveDiacritic = 0;
        } else if (n == 19 and memcmp("remove_diacritics=2", z, 19) == 0) {
            t.eRemoveDiacritic = 2;
        } else if (n >= 11 and memcmp("tokenchars=", z, 11) == 0) {
            rc = unicodeAddExceptions(t, 1, z + 11, n - 11);
        } else if (n >= 11 and memcmp("separators=", z, 11) == 0) {
            rc = unicodeAddExceptions(t, 0, z + 11, n - 11);
        } else {
            rc = SQLITE_ERROR; // Unrecognized argument
        }
    }

    if (rc != SQLITE_OK) {
        _ = unicodeDestroy(@ptrCast(t));
        pp.* = null;
        return rc;
    }
    pp.* = @ptrCast(t);
    return rc;
}

/// Prepare to begin tokenizing the input string aInput[0..nInput-1].
fn unicodeOpen(
    p: ?*Sqlite3Tokenizer,
    aInput: ?[*]const u8,
    nInput: c_int,
    pp: *?*Sqlite3TokenizerCursor,
) callconv(.c) c_int {
    _ = p; // UNUSED_PARAMETER
    const pCsr: ?*UnicodeCursor = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(UnicodeCursor))));
    if (pCsr == null) return SQLITE_NOMEM;
    const c = pCsr.?;
    @memset(std.mem.asBytes(c), 0);

    if (aInput == null) {
        c.nInput = 0;
        c.aInput = @ptrCast(@constCast(""));
    } else if (nInput < 0) {
        c.aInput = aInput;
        c.nInput = @intCast(strlen(@ptrCast(aInput.?)));
    } else {
        c.aInput = aInput;
        c.nInput = nInput;
    }

    pp.* = &c.base;
    return SQLITE_OK;
}

/// Close a tokenization cursor previously opened by unicodeOpen().
fn unicodeClose(pCursor: ?*Sqlite3TokenizerCursor) callconv(.c) c_int {
    const pCsr: *UnicodeCursor = @ptrCast(@alignCast(pCursor.?));
    sqlite3_free(@ptrCast(pCsr.zToken));
    sqlite3_free(@ptrCast(pCsr));
    return SQLITE_OK;
}

/// Extract the next token from a tokenization cursor.
fn unicodeNext(
    pC: ?*Sqlite3TokenizerCursor,
    paToken: *?[*]const u8,
    pnToken: *c_int,
    piStart: *c_int,
    piEnd: *c_int,
    piPos: *c_int,
) callconv(.c) c_int {
    const pCsr: *UnicodeCursor = @ptrCast(@alignCast(pC.?));
    const p: *UnicodeTokenizer = @ptrCast(@alignCast(pCsr.base.pTokenizer.?));
    var iCode: u32 = 0;
    const aInput = pCsr.aInput.?;
    var z: [*]const u8 = aInput + @as(usize, @intCast(pCsr.iOff));
    var zStart: [*]const u8 = z;
    var zEnd: [*]const u8 = z;
    const zTerm: [*]const u8 = aInput + @as(usize, @intCast(pCsr.nInput));

    // Scan past any delimiter characters before the start of the next token.
    while (@intFromPtr(z) < @intFromPtr(zTerm)) {
        iCode = readUtf8(&z, zTerm);
        if (unicodeIsAlnum(p, @bitCast(iCode)) != 0) break;
        zStart = z;
    }
    if (@intFromPtr(zStart) >= @intFromPtr(zTerm)) return SQLITE_DONE;

    var zOut: [*]u8 = pCsr.zToken orelse undefined;
    while (true) {
        // Grow the output buffer if required.
        if (@as(isize, @intCast(@intFromPtr(zOut) -% @intFromPtr(pCsr.zToken orelse zOut))) >= (pCsr.nAlloc - 4)) {
            const off: usize = @intFromPtr(zOut) - @intFromPtr(pCsr.zToken orelse zOut);
            const zNew: ?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(
                @ptrCast(pCsr.zToken),
                @intCast(pCsr.nAlloc + 64),
            )));
            if (zNew == null) return SQLITE_NOMEM;
            zOut = zNew.? + off;
            pCsr.zToken = zNew;
            pCsr.nAlloc += 64;
        }

        // Write the folded case of the last character read to the output.
        zEnd = z;
        const iOut = sqlite3FtsUnicodeFold(@bitCast(iCode), p.eRemoveDiacritic);
        if (iOut != 0) {
            writeUtf8(&zOut, @bitCast(iOut));
        }

        // If the cursor is not at EOF, read the next character.
        if (@intFromPtr(z) >= @intFromPtr(zTerm)) break;
        iCode = readUtf8(&z, zTerm);

        if (!(unicodeIsAlnum(p, @bitCast(iCode)) != 0 or
            sqlite3FtsUnicodeIsdiacritic(@bitCast(iCode)) != 0)) break;
    }

    // Set the output variables and return.
    const base = @intFromPtr(aInput);
    pCsr.iOff = @intCast(@intFromPtr(z) - base);
    paToken.* = pCsr.zToken;
    pnToken.* = @intCast(@intFromPtr(zOut) - @intFromPtr(pCsr.zToken.?));
    piStart.* = @intCast(@intFromPtr(zStart) - base);
    piEnd.* = @intCast(@intFromPtr(zEnd) - base);
    piPos.* = pCsr.iToken;
    pCsr.iToken += 1;
    return SQLITE_OK;
}

/// The static vtable for the unicode tokenizer (C's file-scope `module`).
const module = Sqlite3TokenizerModule{
    .iVersion = 0,
    .xCreate = unicodeCreate,
    .xDestroy = unicodeDestroy,
    .xOpen = unicodeOpen,
    .xClose = unicodeClose,
    .xNext = unicodeNext,
    .xLanguageid = null,
};

/// Set *ppModule to the sqlite3_tokenizer_module for the unicode tokenizer.
/// This is the only externally referenced symbol (fts3.c calls it).
export fn sqlite3Fts3UnicodeTokenizer(ppModule: *?*const Sqlite3TokenizerModule) callconv(.c) void {
    ppModule.* = &module;
}

// --- Self-contained tests (no C externs needed) ---

test "readUtf8 ASCII and multibyte" {
    // ASCII 'A'
    {
        const s = "A";
        var z: [*]const u8 = s.ptr;
        const cp = readUtf8(&z, s.ptr + s.len);
        try std.testing.expectEqual(@as(u32, 'A'), cp);
        try std.testing.expectEqual(@intFromPtr(s.ptr) + 1, @intFromPtr(z));
    }
    // U+00E9 'é' = C3 A9
    {
        const s = [_]u8{ 0xC3, 0xA9 };
        var z: [*]const u8 = &s;
        const cp = readUtf8(&z, @as([*]const u8, &s) + s.len);
        try std.testing.expectEqual(@as(u32, 0xE9), cp);
    }
    // U+20AC '€' = E2 82 AC
    {
        const s = [_]u8{ 0xE2, 0x82, 0xAC };
        var z: [*]const u8 = &s;
        const cp = readUtf8(&z, @as([*]const u8, &s) + s.len);
        try std.testing.expectEqual(@as(u32, 0x20AC), cp);
    }
    // Lone surrogate range folds to U+FFFD: ED A0 80 -> U+D800
    {
        const s = [_]u8{ 0xED, 0xA0, 0x80 };
        var z: [*]const u8 = &s;
        const cp = readUtf8(&z, @as([*]const u8, &s) + s.len);
        try std.testing.expectEqual(@as(u32, 0xFFFD), cp);
    }
}

test "writeUtf8 round-trips through readUtf8" {
    const cases = [_]u32{ 0x41, 0xE9, 0x20AC, 0x1F600 };
    for (cases) |cp| {
        var buf: [4]u8 = undefined;
        var w: [*]u8 = &buf;
        writeUtf8(&w, cp);
        const n = @intFromPtr(w) - @intFromPtr(@as([*]u8, &buf));
        var r: [*]const u8 = &buf;
        const got = readUtf8(&r, @as([*]const u8, &buf) + n);
        try std.testing.expectEqual(cp, got);
    }
}
