//! Zig port of SQLite's FTS3 "simple" tokenizer (ext/fts3/fts3_tokenizer1.c).
//!
//! Drop-in replacement exporting the single non-static symbol
//! `sqlite3Fts3SimpleTokenizerModule`, which hands FTS3 a pointer to this
//! module's `sqlite3_tokenizer_module` vtable. The vtable callbacks
//! (create/destroy/open/close/next) are private to this object — FTS3 reaches
//! them only through the function pointers in the module — so they are kept
//! as ordinary (non-exported) Zig functions with C calling convention.
//!
//! Coupling taxonomy:
//!   - PUBLIC ABI vtable types (`sqlite3_tokenizer_module` / `sqlite3_tokenizer`
//!     / `sqlite3_tokenizer_cursor`, from ext/fts3/fts3_tokenizer.h) are mirrored
//!     field-for-field as `extern struct`; FTS3 C reads `pModule`/`pTokenizer`
//!     and the module's method pointers, so layout must match exactly.
//!   - The `simple_tokenizer` / `simple_tokenizer_cursor` derived structs are
//!     *internal* — defined and allocated/freed only here, FTS3 holds only the
//!     embedded `base` via an opaque pointer — so their layout is private and we
//!     model them as the idiomatic Zig structs with `base` at offset 0.
//!   - Only public `sqlite3_*` allocation helpers and libc are called.
//!
//! Config-invariant: the C source has no SQLITE_TEST / SQLITE_DEBUG conditionals
//! and touches no debug-conditional struct fields, so this one object is correct
//! in both the production `zig build` and the `--dev` testfixture builds. No
//! `@import("config")` needed.
//!
//! Build config assumed (true in both builds): FTS3 enabled (SQLITE_ENABLE_FTS3),
//! ASCII byte semantics (the tokenizer is byte-oriented, UTF-8 delimiters are
//! explicitly rejected upstream).

const std = @import("std");
const builtin = @import("builtin");

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_DONE: c_int = 101;

// --- C helpers resolved at link time ---
// In `zig test` there are no C objects to link against, so satisfy the
// allocator/libc surface with std.c-backed stubs; the production and
// testfixture builds bind the real SQLite/libc symbols by name via @extern.
const sqlite3_malloc = if (builtin.is_test) testMalloc else clib.sqlite3_malloc;
const sqlite3_realloc64 = if (builtin.is_test) testRealloc64 else clib.sqlite3_realloc64;
const sqlite3_free = if (builtin.is_test) testFree else clib.sqlite3_free;
const strlen = if (builtin.is_test) testStrlen else clib.strlen;

const clib = struct {
    const sqlite3_malloc: *const fn (c_int) callconv(.c) ?*anyopaque = @extern(*const fn (c_int) callconv(.c) ?*anyopaque, .{ .name = "sqlite3_malloc" });
    const sqlite3_realloc64: *const fn (?*anyopaque, u64) callconv(.c) ?*anyopaque = @extern(*const fn (?*anyopaque, u64) callconv(.c) ?*anyopaque, .{ .name = "sqlite3_realloc64" });
    const sqlite3_free: *const fn (?*anyopaque) callconv(.c) void = @extern(*const fn (?*anyopaque) callconv(.c) void, .{ .name = "sqlite3_free" });
    const strlen: *const fn ([*:0]const u8) callconv(.c) usize = @extern(*const fn ([*:0]const u8) callconv(.c) usize, .{ .name = "strlen" });
};

fn testMalloc(n: c_int) ?*anyopaque {
    return std.c.malloc(@intCast(n));
}
fn testRealloc64(p: ?*anyopaque, n: u64) ?*anyopaque {
    return std.c.realloc(p, @intCast(n));
}
fn testFree(p: ?*anyopaque) void {
    std.c.free(p);
}
fn testStrlen(s: [*:0]const u8) usize {
    return std.mem.len(s);
}

// --- PUBLIC ABI vtable types (ext/fts3/fts3_tokenizer.h) ---

const sqlite3_tokenizer = extern struct {
    pModule: ?*const sqlite3_tokenizer_module,
    // Implementations append fields after this; FTS3 never reads them.
};

const sqlite3_tokenizer_cursor = extern struct {
    pTokenizer: ?*sqlite3_tokenizer,
    // Implementations append fields after this; FTS3 never reads them.
};

const sqlite3_tokenizer_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const fn (argc: c_int, argv: ?[*]const ?[*:0]const u8, ppTokenizer: *?*sqlite3_tokenizer) callconv(.c) c_int,
    xDestroy: ?*const fn (pTokenizer: ?*sqlite3_tokenizer) callconv(.c) c_int,
    xOpen: ?*const fn (pTokenizer: ?*sqlite3_tokenizer, pInput: ?[*]const u8, nBytes: c_int, ppCursor: *?*sqlite3_tokenizer_cursor) callconv(.c) c_int,
    xClose: ?*const fn (pCursor: ?*sqlite3_tokenizer_cursor) callconv(.c) c_int,
    xNext: ?*const fn (pCursor: ?*sqlite3_tokenizer_cursor, ppToken: *?[*]const u8, pnBytes: *c_int, piStartOffset: *c_int, piEndOffset: *c_int, piPosition: *c_int) callconv(.c) c_int,
    xLanguageid: ?*const fn (pCsr: ?*sqlite3_tokenizer_cursor, iLangid: c_int) callconv(.c) c_int,
};

// --- Internal derived structs (private layout; `base` first at offset 0) ---

const simple_tokenizer = extern struct {
    base: sqlite3_tokenizer,
    delim: [128]i8, // flag ASCII delimiters (non-zero == delimiter)
};

const simple_tokenizer_cursor = extern struct {
    base: sqlite3_tokenizer_cursor,
    pInput: ?[*]const u8, // input we are tokenizing
    nBytes: c_int, // size of the input
    iOffset: c_int, // current position in pInput
    iToken: c_int, // index of next token to be returned
    pToken: ?[*]u8, // storage for current token
    nTokenAllocated: c_int, // space allocated to pToken buffer
};

inline fn simpleDelim(t: *const simple_tokenizer, c: u8) bool {
    return c < 0x80 and t.delim[c] != 0;
}

inline fn fts3_isalnum(x: c_int) bool {
    return (x >= '0' and x <= '9') or (x >= 'A' and x <= 'Z') or (x >= 'a' and x <= 'z');
}

/// Create a new tokenizer instance.
fn simpleCreate(argc: c_int, argv: ?[*]const ?[*:0]const u8, ppTokenizer: *?*sqlite3_tokenizer) callconv(.c) c_int {
    const t: *simple_tokenizer = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(simple_tokenizer)) orelse return SQLITE_NOMEM));
    @memset(std.mem.asBytes(t), 0);

    // TODO(shess, upstream): delimiters must remain stable run-to-run.
    if (argc > 1) {
        const arg1 = argv.?[1].?;
        const n = strlen(arg1);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const ch: u8 = arg1[i];
            // UTF-8 delimiters are explicitly unsupported.
            if (ch >= 0x80) {
                sqlite3_free(t);
                return SQLITE_ERROR;
            }
            t.delim[ch] = 1;
        }
    } else {
        // Mark non-alphanumeric ASCII characters as delimiters.
        var i: c_int = 1;
        while (i < 0x80) : (i += 1) {
            t.delim[@intCast(i)] = if (!fts3_isalnum(i)) -1 else 0;
        }
    }

    ppTokenizer.* = &t.base;
    return SQLITE_OK;
}

/// Destroy a tokenizer.
fn simpleDestroy(pTokenizer: ?*sqlite3_tokenizer) callconv(.c) c_int {
    sqlite3_free(pTokenizer);
    return SQLITE_OK;
}

/// Prepare to begin tokenizing a particular string.
fn simpleOpen(pTokenizer: ?*sqlite3_tokenizer, pInput: ?[*]const u8, nBytes: c_int, ppCursor: *?*sqlite3_tokenizer_cursor) callconv(.c) c_int {
    _ = pTokenizer; // UNUSED_PARAMETER

    const c: *simple_tokenizer_cursor = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(simple_tokenizer_cursor)) orelse return SQLITE_NOMEM));

    c.pInput = pInput;
    if (pInput == null) {
        c.nBytes = 0;
    } else if (nBytes < 0) {
        c.nBytes = @intCast(strlen(@ptrCast(pInput.?)));
    } else {
        c.nBytes = nBytes;
    }
    c.iOffset = 0; // start tokenizing at the beginning
    c.iToken = 0;
    c.pToken = null; // no space allocated, yet
    c.nTokenAllocated = 0;

    ppCursor.* = &c.base;
    return SQLITE_OK;
}

/// Close a tokenization cursor previously opened by simpleOpen().
fn simpleClose(pCursor: ?*sqlite3_tokenizer_cursor) callconv(.c) c_int {
    const c: *simple_tokenizer_cursor = @ptrCast(@alignCast(pCursor.?));
    sqlite3_free(c.pToken);
    sqlite3_free(c);
    return SQLITE_OK;
}

/// Extract the next token from a tokenization cursor.
fn simpleNext(
    pCursor: ?*sqlite3_tokenizer_cursor,
    ppToken: *?[*]const u8,
    pnBytes: *c_int,
    piStartOffset: *c_int,
    piEndOffset: *c_int,
    piPosition: *c_int,
) callconv(.c) c_int {
    const c: *simple_tokenizer_cursor = @ptrCast(@alignCast(pCursor.?));
    const t: *const simple_tokenizer = @ptrCast(@alignCast(pCursor.?.pTokenizer.?));
    const p = c.pInput.?;

    while (c.iOffset < c.nBytes) {
        // Scan past delimiter characters.
        while (c.iOffset < c.nBytes and simpleDelim(t, p[@intCast(c.iOffset)])) {
            c.iOffset += 1;
        }

        // Count non-delimiter characters.
        const iStartOffset = c.iOffset;
        while (c.iOffset < c.nBytes and !simpleDelim(t, p[@intCast(c.iOffset)])) {
            c.iOffset += 1;
        }

        if (c.iOffset > iStartOffset) {
            const n = c.iOffset - iStartOffset;
            if (n > c.nTokenAllocated) {
                c.nTokenAllocated = n + 20;
                const pNew = sqlite3_realloc64(c.pToken, @intCast(c.nTokenAllocated)) orelse return SQLITE_NOMEM;
                c.pToken = @ptrCast(@alignCast(pNew));
            }
            const tok = c.pToken.?;
            var i: c_int = 0;
            while (i < n) : (i += 1) {
                // TODO(shess, upstream): UTF-8 case-insensitivity.
                const ch: u8 = p[@intCast(iStartOffset + i)];
                tok[@intCast(i)] = if (ch >= 'A' and ch <= 'Z') ch - 'A' + 'a' else ch;
            }
            ppToken.* = tok;
            pnBytes.* = n;
            piStartOffset.* = iStartOffset;
            piEndOffset.* = c.iOffset;
            piPosition.* = c.iToken;
            c.iToken += 1;

            return SQLITE_OK;
        }
    }
    return SQLITE_DONE;
}

/// The set of routines that implement the simple tokenizer.
const simpleTokenizerModule = sqlite3_tokenizer_module{
    .iVersion = 0,
    .xCreate = simpleCreate,
    .xDestroy = simpleDestroy,
    .xOpen = simpleOpen,
    .xClose = simpleClose,
    .xNext = simpleNext,
    .xLanguageid = null,
};

/// Allocate a new simple tokenizer. Returns a pointer to the module vtable.
export fn sqlite3Fts3SimpleTokenizerModule(ppModule: *?*const sqlite3_tokenizer_module) callconv(.c) void {
    ppModule.* = &simpleTokenizerModule;
}

// --- Direct test of the tokenization logic (no C engine required) ---
//
// The tokenizer's behavior is entirely: (1) which bytes are delimiters and
// (2) ASCII case-folding of token bytes. This test rebuilds the default
// delimiter table exactly as simpleCreate's else-branch, asserts the
// classification, then walks a sample string applying the same scan + fold loop
// simpleNext uses, asserting the resulting tokens and their start/end offsets.
// (The allocator stubs above let `zig test -lc` link standalone, with no C
// SQLite objects present.)
test "default delimiter classification and case folding" {
    // Build the default delimiter table exactly as simpleCreate's else-branch.
    var delim: [128]i8 = @splat(0);
    var i: c_int = 1;
    while (i < 0x80) : (i += 1) {
        delim[@intCast(i)] = if (!fts3_isalnum(i)) -1 else 0;
    }
    var t = simple_tokenizer{ .base = .{ .pModule = null }, .delim = delim };

    // Alphanumerics are NOT delimiters; punctuation/space ARE.
    try std.testing.expect(!simpleDelim(&t, 'a'));
    try std.testing.expect(!simpleDelim(&t, 'Z'));
    try std.testing.expect(!simpleDelim(&t, '0'));
    try std.testing.expect(simpleDelim(&t, ' '));
    try std.testing.expect(simpleDelim(&t, ','));
    try std.testing.expect(simpleDelim(&t, '.'));
    // NUL (index 0) stays a non-delimiter (loop starts at 1), matching C.
    try std.testing.expect(!simpleDelim(&t, 0));
    // High bytes (>=0x80) are never delimiters.
    try std.testing.expect(!simpleDelim(&t, 0x80));
    try std.testing.expect(!simpleDelim(&t, 0xFF));

    // Tokenize "Hello, World!" by hand using the same classification + folding
    // simpleNext applies, asserting tokens/offsets.
    const input = "Hello, World!";
    const Tok = struct { text: []const u8, start: c_int, end: c_int };
    const expected = [_]Tok{
        .{ .text = "hello", .start = 0, .end = 5 },
        .{ .text = "world", .start = 7, .end = 12 },
    };
    var off: c_int = 0;
    const nB: c_int = input.len;
    var found: usize = 0;
    while (off < nB) {
        while (off < nB and simpleDelim(&t, input[@intCast(off)])) off += 1;
        const startOff = off;
        while (off < nB and !simpleDelim(&t, input[@intCast(off)])) off += 1;
        if (off > startOff) {
            const n: usize = @intCast(off - startOff);
            var buf: [16]u8 = undefined;
            var k: usize = 0;
            while (k < n) : (k += 1) {
                const raw: u8 = input[@as(usize, @intCast(startOff)) + k];
                buf[k] = if (raw >= 'A' and raw <= 'Z') raw - 'A' + 'a' else raw;
            }
            try std.testing.expect(found < expected.len);
            try std.testing.expectEqualStrings(expected[found].text, buf[0..n]);
            try std.testing.expectEqual(expected[found].start, startOff);
            try std.testing.expectEqual(expected[found].end, off);
            found += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), found);
}
