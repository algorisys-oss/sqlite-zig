//! Zig port of SQLite's FTS3 Porter-stemmer tokenizer (ext/fts3/fts3_porter.c).
//!
//! Drop-in replacement exporting the one non-static symbol of the C file,
//! `sqlite3Fts3PorterTokenizerModule` (called from fts3.c to register the
//! "porter" tokenizer). Everything else in the C file is `static`: the
//! tokenizer vtable callbacks (porterCreate/Destroy/Open/Close/Next), the
//! Porter stemming algorithm, and the lookup tables. They are kept as private
//! Zig functions and reached only through the exported module's function
//! pointers, exactly as in C.
//!
//! Coupling:
//!   * The tokenizer vtable types (sqlite3_tokenizer_module / _tokenizer /
//!     _tokenizer_cursor) are PUBLIC ABI, declared in fts3_tokenizer.h. They are
//!     mirrored field-for-field as `extern struct`s below. The derived
//!     porter_tokenizer / porter_tokenizer_cursor structs are private to this
//!     module (only allocation sizeof matters across the boundary), so they are
//!     plain `extern struct`s embedding the public base as their first field.
//!   * The only C helpers called are the public memory allocators
//!     (sqlite3_malloc / sqlite3_free / sqlite3_realloc64), resolved at link
//!     time.
//!
//! Config-invariant: this module touches no SQLITE_DEBUG-conditional struct
//! fields and gates no behavior on SQLITE_TEST/SQLITE_DEBUG. The C file's debug
//! `assert(x>='a'&&x<='z')` calls are pure assertions (no side effects) and are
//! simply dropped, matching production behavior. The single `.o` is therefore
//! correct in both the production `zig build` and the `--dev` testfixture
//! builds, so `@import("config")` is not needed.

const std = @import("std");

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_DONE: c_int = 101;

// --- Public ABI structs (fts3_tokenizer.h) ---

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

// --- Module-private derived structs ---

/// Class derived from sqlite3_tokenizer.
const porter_tokenizer = extern struct {
    base: sqlite3_tokenizer,
};

/// Class derived from sqlite3_tokenizer_cursor.
const porter_tokenizer_cursor = extern struct {
    base: sqlite3_tokenizer_cursor,
    zInput: ?[*]const u8, // input we are tokenizing
    nInput: c_int, // size of the input
    iOffset: c_int, // current position in zInput
    iToken: c_int, // index of next token to be returned
    zToken: ?[*]u8, // storage for current token
    nAllocated: c_int, // space allocated to zToken buffer
};

// --- C helpers resolved at link time ---
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn strlen(s: [*:0]const u8) usize;

// --- Tokenizer vtable callbacks (static in C) ---

/// Create a new tokenizer instance.
fn porterCreate(
    argc: c_int,
    argv: [*]const [*:0]const u8,
    ppTokenizer: *?*sqlite3_tokenizer,
) callconv(.c) c_int {
    _ = argc;
    _ = argv;
    const t: ?*porter_tokenizer = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(porter_tokenizer))));
    const tp = t orelse return SQLITE_NOMEM;
    @memset(std.mem.asBytes(tp), 0);
    ppTokenizer.* = &tp.base;
    return SQLITE_OK;
}

/// Destroy a tokenizer.
fn porterDestroy(pTokenizer: *sqlite3_tokenizer) callconv(.c) c_int {
    sqlite3_free(pTokenizer);
    return SQLITE_OK;
}

/// Prepare to begin tokenizing a particular string.
fn porterOpen(
    pTokenizer: *sqlite3_tokenizer,
    zInput: ?[*]const u8,
    nInput: c_int,
    ppCursor: *?*sqlite3_tokenizer_cursor,
) callconv(.c) c_int {
    _ = pTokenizer;
    const c: ?*porter_tokenizer_cursor = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(porter_tokenizer_cursor))));
    const cp = c orelse return SQLITE_NOMEM;

    cp.zInput = zInput;
    if (zInput == null) {
        cp.nInput = 0;
    } else if (nInput < 0) {
        cp.nInput = @intCast(strlen(@ptrCast(zInput.?)));
    } else {
        cp.nInput = nInput;
    }
    cp.iOffset = 0; // start tokenizing at the beginning
    cp.iToken = 0;
    cp.zToken = null; // no space allocated, yet.
    cp.nAllocated = 0;

    ppCursor.* = &cp.base;
    return SQLITE_OK;
}

/// Close a tokenization cursor previously opened by porterOpen().
fn porterClose(pCursor: *sqlite3_tokenizer_cursor) callconv(.c) c_int {
    const c: *porter_tokenizer_cursor = @ptrCast(@alignCast(pCursor));
    sqlite3_free(c.zToken);
    sqlite3_free(c);
    return SQLITE_OK;
}

// --- Porter stemming algorithm (all static in C) ---

/// Vowel or consonant classification table, indexed by letter - 'a'.
/// 0 = vowel, 1 = consonant, 2 = 'y' (context-dependent).
const cType = [26]u8{
    0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 2, 1,
};

/// True if the first character of z is a consonant per Porter's rules.
/// (z[] is in reverse order; 'y' is a consonant unless followed by a vowel.)
fn isConsonant(z: [*]const u8) c_int {
    const x = z[0];
    if (x == 0) return 0;
    const j = cType[x - 'a'];
    if (j < 2) return j;
    return if (z[1] == 0 or isVowel(z + 1) != 0) 1 else 0;
}

/// True if the first character of z is a vowel per Porter's rules.
fn isVowel(z: [*]const u8) c_int {
    const x = z[0];
    if (x == 0) return 0;
    const j = cType[x - 'a'];
    if (j < 2) return 1 - j;
    return isConsonant(z + 1);
}

/// Return true if z (reversed) contains at least one consonant followed by a
/// vowel — i.e. its Porter m-value is 1 or more.
fn m_gt_0(z_in: [*]const u8) callconv(.c) c_int {
    var z = z_in;
    while (isVowel(z) != 0) z += 1;
    if (z[0] == 0) return 0;
    while (isConsonant(z) != 0) z += 1;
    return @intFromBool(z[0] != 0);
}

/// Like m_gt_0 but true only when the m-value is exactly 1.
fn m_eq_1(z_in: [*]const u8) callconv(.c) c_int {
    var z = z_in;
    while (isVowel(z) != 0) z += 1;
    if (z[0] == 0) return 0;
    while (isConsonant(z) != 0) z += 1;
    if (z[0] == 0) return 0;
    while (isVowel(z) != 0) z += 1;
    if (z[0] == 0) return 1;
    while (isConsonant(z) != 0) z += 1;
    return @intFromBool(z[0] == 0);
}

/// Like m_gt_0 but true only when the m-value is greater than 1.
fn m_gt_1(z_in: [*]const u8) callconv(.c) c_int {
    var z = z_in;
    while (isVowel(z) != 0) z += 1;
    if (z[0] == 0) return 0;
    while (isConsonant(z) != 0) z += 1;
    if (z[0] == 0) return 0;
    while (isVowel(z) != 0) z += 1;
    if (z[0] == 0) return 0;
    while (isConsonant(z) != 0) z += 1;
    return @intFromBool(z[0] != 0);
}

/// Return true if there is a vowel anywhere within z.
fn hasVowel(z_in: [*]const u8) callconv(.c) c_int {
    var z = z_in;
    while (isConsonant(z) != 0) z += 1;
    return @intFromBool(z[0] != 0);
}

/// Return true if the word ends in a double consonant (z[] is reversed, so we
/// look at the first two characters).
fn doubleConsonant(z: [*]const u8) c_int {
    return @intFromBool(isConsonant(z) != 0 and z[0] == z[1]);
}

/// Return true if the word ends with consonant-vowel-consonant where the final
/// consonant is not 'w', 'x' or 'y' (z[] is reversed).
fn star_oh(z: [*]const u8) c_int {
    return @intFromBool(
        isConsonant(z) != 0 and
            z[0] != 'w' and z[0] != 'x' and z[0] != 'y' and
            isVowel(z + 1) != 0 and
            isConsonant(z + 2) != 0,
    );
}

/// If the word ends with zFrom (reversed) and xCond holds for the stem before
/// it, replace the ending with zTo (forward order). Returns true if zFrom
/// matched (even when xCond failed and no substitution occurred).
fn stem(
    pz: *[*]u8,
    zFrom_in: [*:0]const u8,
    zTo_in: [*:0]const u8,
    xCond: ?*const fn ([*]const u8) callconv(.c) c_int,
) c_int {
    var z = pz.*;
    var zFrom = zFrom_in;
    while (zFrom[0] != 0 and zFrom[0] == z[0]) {
        z += 1;
        zFrom += 1;
    }
    if (zFrom[0] != 0) return 0;
    if (xCond) |cond| {
        if (cond(z) == 0) return 1;
    }
    var zTo = zTo_in;
    while (zTo[0] != 0) {
        z -= 1;
        z[0] = zTo[0];
        zTo += 1;
    }
    pz.* = z;
    return 1;
}

/// Fallback stemmer: copy zIn to zOut with US-ASCII case folding. Long words
/// are truncated to a few bytes from each end (3 if digits present, else 10).
fn copy_stemmer(zIn: [*]const u8, nIn: c_int, zOut: [*]u8, pnOut: *c_int) void {
    var i: c_int = 0;
    var hasDigit: c_int = 0;
    while (i < nIn) : (i += 1) {
        const c = zIn[@intCast(i)];
        if (c >= 'A' and c <= 'Z') {
            zOut[@intCast(i)] = c - 'A' + 'a';
        } else {
            if (c >= '0' and c <= '9') hasDigit = 1;
            zOut[@intCast(i)] = c;
        }
    }
    const mx: c_int = if (hasDigit != 0) 3 else 10;
    if (nIn > mx * 2) {
        var j: c_int = mx;
        i = nIn - mx;
        while (i < nIn) : (i += 1) {
            zOut[@intCast(j)] = zOut[@intCast(i)];
            j += 1;
        }
        i = j;
    }
    zOut[@intCast(i)] = 0;
    pnOut.* = i;
}

/// Stem the input word zIn[0..nIn-1] into zOut, writing its length to *pnOut.
/// US-ASCII upper-case is folded to lower; non-[A-Za-z] words and words too
/// short/long fall back to copy_stemmer. Stemming never lengthens the word.
fn porter_stemmer(zIn: [*]const u8, nIn: c_int, zOut: [*]u8, pnOut: *c_int) void {
    var zReverse: [28]u8 = undefined;
    var i: c_int = undefined;
    var j: c_int = undefined;

    if (nIn < 3 or nIn >= @as(c_int, @intCast(zReverse.len)) - 7) {
        // Too big or too small for the porter stemmer; fall back.
        copy_stemmer(zIn, nIn, zOut, pnOut);
        return;
    }

    i = 0;
    j = @as(c_int, @intCast(zReverse.len)) - 6;
    while (i < nIn) : ({
        i += 1;
        j -= 1;
    }) {
        const c = zIn[@intCast(i)];
        if (c >= 'A' and c <= 'Z') {
            zReverse[@intCast(j)] = c + 'a' - 'A';
        } else if (c >= 'a' and c <= 'z') {
            zReverse[@intCast(j)] = c;
        } else {
            // A character not in [a-zA-Z] -> fall back to the copy stemmer.
            copy_stemmer(zIn, nIn, zOut, pnOut);
            return;
        }
    }
    @memset(zReverse[zReverse.len - 5 ..][0..5], 0);
    var z: [*]u8 = zReverse[@intCast(j + 1)..].ptr;

    // Step 1a
    if (z[0] == 's') {
        if (stem(&z, "sess", "ss", null) == 0 and
            stem(&z, "sei", "i", null) == 0 and
            stem(&z, "ss", "ss", null) == 0)
        {
            z += 1;
        }
    }

    // Step 1b
    const z2 = z;
    if (stem(&z, "dee", "ee", m_gt_0) != 0) {
        // Do nothing. The work was all in the test.
    } else if ((stem(&z, "gni", "", hasVowel) != 0 or stem(&z, "de", "", hasVowel) != 0) and z != z2) {
        if (stem(&z, "ta", "ate", null) != 0 or
            stem(&z, "lb", "ble", null) != 0 or
            stem(&z, "zi", "ize", null) != 0)
        {
            // Do nothing. The work was all in the test.
        } else if (doubleConsonant(z) != 0 and (z[0] != 'l' and z[0] != 's' and z[0] != 'z')) {
            z += 1;
        } else if (m_eq_1(z) != 0 and star_oh(z) != 0) {
            z -= 1;
            z[0] = 'e';
        }
    }

    // Step 1c
    if (z[0] == 'y' and hasVowel(z + 1) != 0) {
        z[0] = 'i';
    }

    // Step 2
    switch (z[1]) {
        'a' => {
            if (stem(&z, "lanoita", "ate", m_gt_0) == 0) {
                _ = stem(&z, "lanoit", "tion", m_gt_0);
            }
        },
        'c' => {
            if (stem(&z, "icne", "ence", m_gt_0) == 0) {
                _ = stem(&z, "icna", "ance", m_gt_0);
            }
        },
        'e' => {
            _ = stem(&z, "rezi", "ize", m_gt_0);
        },
        'g' => {
            _ = stem(&z, "igol", "log", m_gt_0);
        },
        'l' => {
            if (stem(&z, "ilb", "ble", m_gt_0) == 0 and
                stem(&z, "illa", "al", m_gt_0) == 0 and
                stem(&z, "iltne", "ent", m_gt_0) == 0 and
                stem(&z, "ile", "e", m_gt_0) == 0)
            {
                _ = stem(&z, "ilsuo", "ous", m_gt_0);
            }
        },
        'o' => {
            if (stem(&z, "noitazi", "ize", m_gt_0) == 0 and
                stem(&z, "noita", "ate", m_gt_0) == 0)
            {
                _ = stem(&z, "rota", "ate", m_gt_0);
            }
        },
        's' => {
            if (stem(&z, "msila", "al", m_gt_0) == 0 and
                stem(&z, "ssenevi", "ive", m_gt_0) == 0 and
                stem(&z, "ssenluf", "ful", m_gt_0) == 0)
            {
                _ = stem(&z, "ssensuo", "ous", m_gt_0);
            }
        },
        't' => {
            if (stem(&z, "itila", "al", m_gt_0) == 0 and
                stem(&z, "itivi", "ive", m_gt_0) == 0)
            {
                _ = stem(&z, "itilib", "ble", m_gt_0);
            }
        },
        else => {},
    }

    // Step 3
    switch (z[0]) {
        'e' => {
            if (stem(&z, "etaci", "ic", m_gt_0) == 0 and
                stem(&z, "evita", "", m_gt_0) == 0)
            {
                _ = stem(&z, "ezila", "al", m_gt_0);
            }
        },
        'i' => {
            _ = stem(&z, "itici", "ic", m_gt_0);
        },
        'l' => {
            if (stem(&z, "laci", "ic", m_gt_0) == 0) {
                _ = stem(&z, "luf", "", m_gt_0);
            }
        },
        's' => {
            _ = stem(&z, "ssen", "", m_gt_0);
        },
        else => {},
    }

    // Step 4
    switch (z[1]) {
        'a' => {
            if (z[0] == 'l' and m_gt_1(z + 2) != 0) z += 2;
        },
        'c' => {
            if (z[0] == 'e' and z[2] == 'n' and (z[3] == 'a' or z[3] == 'e') and m_gt_1(z + 4) != 0) z += 4;
        },
        'e' => {
            if (z[0] == 'r' and m_gt_1(z + 2) != 0) z += 2;
        },
        'i' => {
            if (z[0] == 'c' and m_gt_1(z + 2) != 0) z += 2;
        },
        'l' => {
            if (z[0] == 'e' and z[2] == 'b' and (z[3] == 'a' or z[3] == 'i') and m_gt_1(z + 4) != 0) z += 4;
        },
        'n' => {
            if (z[0] == 't') {
                if (z[2] == 'a') {
                    if (m_gt_1(z + 3) != 0) z += 3;
                } else if (z[2] == 'e') {
                    if (stem(&z, "tneme", "", m_gt_1) == 0 and
                        stem(&z, "tnem", "", m_gt_1) == 0)
                    {
                        _ = stem(&z, "tne", "", m_gt_1);
                    }
                }
            }
        },
        'o' => {
            if (z[0] == 'u') {
                if (m_gt_1(z + 2) != 0) z += 2;
            } else if (z[3] == 's' or z[3] == 't') {
                _ = stem(&z, "noi", "", m_gt_1);
            }
        },
        's' => {
            if (z[0] == 'm' and z[2] == 'i' and m_gt_1(z + 3) != 0) z += 3;
        },
        't' => {
            if (stem(&z, "eta", "", m_gt_1) == 0) {
                _ = stem(&z, "iti", "", m_gt_1);
            }
        },
        'u' => {
            if (z[0] == 's' and z[2] == 'o' and m_gt_1(z + 3) != 0) z += 3;
        },
        'v', 'z' => {
            if (z[0] == 'e' and z[2] == 'i' and m_gt_1(z + 3) != 0) z += 3;
        },
        else => {},
    }

    // Step 5a
    if (z[0] == 'e') {
        if (m_gt_1(z + 1) != 0) {
            z += 1;
        } else if (m_eq_1(z + 1) != 0 and star_oh(z + 1) == 0) {
            z += 1;
        }
    }

    // Step 5b
    if (m_gt_1(z) != 0 and z[0] == 'l' and z[1] == 'l') {
        z += 1;
    }

    // z[] is now the stemmed word in reverse order. Flip it back to forward
    // order and return.
    i = @intCast(strlen(@ptrCast(z)));
    pnOut.* = i;
    zOut[@intCast(i)] = 0;
    while (z[0] != 0) {
        i -= 1;
        zOut[@intCast(i)] = z[0];
        z += 1;
    }
}

/// Token-character table indexed by (byte - 0x30); covers 0x30..0x7f.
/// Any byte >= 0x80 (UTF) is always a token character; delimiters are <= 0x7f.
const porterIdChar = [_]u8{
    //  x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 xA xB xC xD xE xF
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 3x
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4x
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // 5x
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6x
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // 7x
};

/// isDelim(C): true if byte C is a token delimiter.
inline fn isDelim(ch: u8) bool {
    return (ch & 0x80) == 0 and (ch < 0x30 or porterIdChar[ch - 0x30] == 0);
}

/// Extract the next token from a cursor opened by porterOpen().
fn porterNext(
    pCursor: *sqlite3_tokenizer_cursor,
    pzToken: *?[*]const u8,
    pnBytes: *c_int,
    piStartOffset: *c_int,
    piEndOffset: *c_int,
    piPosition: *c_int,
) callconv(.c) c_int {
    const c: *porter_tokenizer_cursor = @ptrCast(@alignCast(pCursor));
    const z = c.zInput.?;

    while (c.iOffset < c.nInput) {
        // Scan past delimiter characters.
        while (c.iOffset < c.nInput and isDelim(z[@intCast(c.iOffset)])) {
            c.iOffset += 1;
        }

        // Count non-delimiter characters.
        const iStartOffset = c.iOffset;
        while (c.iOffset < c.nInput and !isDelim(z[@intCast(c.iOffset)])) {
            c.iOffset += 1;
        }

        if (c.iOffset > iStartOffset) {
            const n = c.iOffset - iStartOffset;
            if (n > c.nAllocated) {
                c.nAllocated = n + 20;
                const pNew = sqlite3_realloc64(c.zToken, @intCast(c.nAllocated));
                if (pNew == null) return SQLITE_NOMEM;
                c.zToken = @ptrCast(pNew);
            }
            porter_stemmer(z + @as(usize, @intCast(iStartOffset)), n, c.zToken.?, pnBytes);
            pzToken.* = c.zToken;
            piStartOffset.* = iStartOffset;
            piEndOffset.* = c.iOffset;
            piPosition.* = c.iToken;
            c.iToken += 1;
            return SQLITE_OK;
        }
    }
    return SQLITE_DONE;
}

/// The set of routines that implement the porter-stemmer tokenizer.
const porterTokenizerModule = sqlite3_tokenizer_module{
    .iVersion = 0,
    .xCreate = porterCreate,
    .xDestroy = porterDestroy,
    .xOpen = porterOpen,
    .xClose = porterClose,
    .xNext = porterNext,
    .xLanguageid = null,
};

/// Return a pointer to the porter tokenizer module in *ppModule.
export fn sqlite3Fts3PorterTokenizerModule(
    ppModule: *?*const sqlite3_tokenizer_module,
) callconv(.c) void {
    ppModule.* = &porterTokenizerModule;
}

// --- Standalone Zig test of the stemming algorithm ---
// porter_stemmer/copy_stemmer touch no C externs, so they run without the C
// engine. Expected outputs are the canonical Porter-stemmer results (and the
// length/digit truncation rules of the fallback copy_stemmer).
test "porter_stemmer known words" {
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        // Classic Porter reductions.
        .{ .in = "caresses", .out = "caress" },
        .{ .in = "ponies", .out = "poni" },
        .{ .in = "cats", .out = "cat" },
        .{ .in = "agreed", .out = "agre" },
        .{ .in = "feed", .out = "feed" },
        .{ .in = "plastered", .out = "plaster" },
        .{ .in = "happy", .out = "happi" },
        .{ .in = "relational", .out = "relat" },
        .{ .in = "conditional", .out = "condit" },
        .{ .in = "rational", .out = "ration" },
        .{ .in = "vietnamization", .out = "vietnam" },
        .{ .in = "predication", .out = "predic" },
        .{ .in = "operator", .out = "oper" },
        .{ .in = "feudalism", .out = "feudal" },
        .{ .in = "hopefulness", .out = "hope" },
        .{ .in = "formaliti", .out = "formal" },
        .{ .in = "sensitiviti", .out = "sensit" },
        .{ .in = "triplicate", .out = "triplic" },
        .{ .in = "electriciti", .out = "electr" },
        .{ .in = "hopeful", .out = "hope" },
        .{ .in = "goodness", .out = "good" },
        .{ .in = "revival", .out = "reviv" },
        .{ .in = "allowance", .out = "allow" },
        .{ .in = "adjustment", .out = "adjust" },
        .{ .in = "homologou", .out = "homolog" },
        .{ .in = "effective", .out = "effect" },
        .{ .in = "bowdlerize", .out = "bowdler" },
        .{ .in = "probate", .out = "probat" },
        .{ .in = "controll", .out = "control" },
        .{ .in = "roll", .out = "roll" },
        // US-ASCII case folding (upper-case is lowered before stemming).
        .{ .in = "CATS", .out = "cat" },
        // Too short for the porter stemmer: copy_stemmer just folds case.
        .{ .in = "at", .out = "at" },
    };

    for (cases) |tc| {
        var buf: [64]u8 = undefined;
        var nOut: c_int = undefined;
        porter_stemmer(tc.in.ptr, @intCast(tc.in.len), &buf, &nOut);
        const got = buf[0..@intCast(nOut)];
        try std.testing.expectEqualStrings(tc.out, got);
    }
}

test "copy_stemmer digit and length truncation" {
    // A long word with a digit keeps 3 bytes from each end.
    {
        const in = "abcdefgh1ijklmnop"; // 17 bytes, has a digit -> mx=3, nIn>6
        var buf: [64]u8 = undefined;
        var nOut: c_int = undefined;
        porter_stemmer(in.ptr, @intCast(in.len), &buf, &nOut);
        // first 3 bytes + last 3 bytes
        try std.testing.expectEqualStrings("abcnop", buf[0..@intCast(nOut)]);
    }
    // A word containing a non-alpha (apostrophe) goes through copy_stemmer with
    // case folding only.
    {
        const in = "Don't";
        var buf: [64]u8 = undefined;
        var nOut: c_int = undefined;
        porter_stemmer(in.ptr, @intCast(in.len), &buf, &nOut);
        try std.testing.expectEqualStrings("don't", buf[0..@intCast(nOut)]);
    }
}
