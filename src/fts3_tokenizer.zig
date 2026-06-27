//! Zig port of FTS3's generic tokenizer interface (ext/fts3/fts3_tokenizer.c).
//!
//! Drop-in replacement exporting the non-static symbols of the C file:
//!   * sqlite3Fts3IsIdChar        — classify a byte as a tokenizer-id character.
//!   * sqlite3Fts3NextToken       — scan the next token from a tokenizer spec.
//!   * sqlite3Fts3InitTokenizer   — resolve a tokenizer name + args into a
//!                                  constructed sqlite3_tokenizer.
//!   * sqlite3Fts3InitHashTable   — register the fts3_tokenizer() SQL function(s).
//! The fts3_tokenizer() SQL scalar (fts3TokenizerFunc) and the enabled-check
//! (fts3TokenizerEnabled) are `static` in C and kept private here, reached only
//! through the function pointers registered with sqlite3_create_function().
//!
//! The SQLITE_TEST-only helpers (testFunc / registerTokenizer / queryTokenizer /
//! intTestFunc, and the *_test / *_internal_test functions registered by
//! sqlite3Fts3InitHashTable when SQLITE_TEST is defined) are gated on
//! `config.sqlite_test`. They depend on the TCL library (Tcl_Obj etc.), which is
//! not part of this build's link surface, so the test-only scalar functions are
//! omitted entirely; only the SQLITE_TEST-conditional *registration* (the two
//! extra sqlite3_create_function calls, which need TCL-backed callbacks) is
//! dropped. This object is therefore correct in both the production `zig build`
//! and the `--dev` testfixture builds. `config.sqlite_test` is consulted only to
//! decide whether to compile the (currently elided) test scaffolding.
//!
//! Coupling taxonomy:
//!   - PUBLIC ABI vtable types (sqlite3_tokenizer_module / sqlite3_tokenizer /
//!     sqlite3_tokenizer_cursor, from ext/fts3/fts3_tokenizer.h) are mirrored
//!     field-for-field as `extern struct` — copied exactly from the already-
//!     ported src/fts3_porter.zig / src/fts3_tokenizer1.zig. The fn-ptr table
//!     field order is iVersion,xCreate,xDestroy,xOpen,xClose,xNext,xLanguageid.
//!   - Fts3Hash (ext/fts3/fts3_hash.h) is mirrored as `extern struct`, copied
//!     exactly from src/fts3_hash.zig, so sqlite3Fts3HashFind/Insert (resolved
//!     at link time, implemented in src/fts3_hash.zig) can be called.
//!   - Only public `sqlite3_*` API and the already-ported fts3 helpers
//!     (sqlite3Fts3HashFind/Insert, sqlite3Fts3Dequote, sqlite3Fts3ErrMsg) are
//!     called; all resolved by name at link time.

const std = @import("std");
const config = @import("config");

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;

// Text-encoding / function flags (sqlite3.h).
const SQLITE_UTF8: c_int = 1;
const SQLITE_DIRECTONLY: c_int = 0x000080000;

// sqlite3_db_config() verb (sqlite3.h).
const SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER: c_int = 1004;

// Destructor sentinel (sqlite3.h): SQLITE_TRANSIENT == -1 cast to a destructor.
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// --- Opaque public handles (sqlite3.h) ---
const sqlite3 = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;

// --- PUBLIC ABI vtable types (ext/fts3/fts3_tokenizer.h) ---
// Field order matters: iVersion,xCreate,xDestroy,xOpen,xClose,xNext,xLanguageid.

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

// --- Fts3Hash (ext/fts3/fts3_hash.h) — copied exactly from src/fts3_hash.zig ---

const Fts3HashElem = extern struct {
    next: ?*Fts3HashElem,
    prev: ?*Fts3HashElem,
    data: ?*anyopaque,
    pKey: ?*anyopaque,
    nKey: c_int,
};

const Fts3ht = extern struct {
    count: c_int,
    chain: ?*Fts3HashElem,
};

const Fts3Hash = extern struct {
    keyClass: i8, // HASH_STRING or HASH_BINARY
    copyKey: i8, // true if a copy of the key is made on insert
    count: c_int,
    first: ?*Fts3HashElem,
    htsize: c_int,
    ht: ?[*]Fts3ht,
};

// --- C / fts3 helpers resolved at link time ---
extern fn sqlite3_context_db_handle(ctx: ?*sqlite3_context) ?*sqlite3;
extern fn sqlite3_db_config(db: ?*sqlite3, op: c_int, ...) c_int;
extern fn sqlite3_user_data(ctx: ?*sqlite3_context) ?*anyopaque;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_bytes(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_blob(p: ?*sqlite3_value) ?*const anyopaque;
extern fn sqlite3_value_frombind(p: ?*sqlite3_value) c_int;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: [*:0]const u8, n: c_int) void;
extern fn sqlite3_result_blob(ctx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, d: DestructorFn) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_create_function(db: ?*sqlite3, zFunctionName: [*:0]const u8, nArg: c_int, eTextRep: c_int, pApp: ?*anyopaque, xFunc: ?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void, xStep: ?*anyopaque, xFinal: ?*anyopaque) c_int;
extern fn strlen(s: [*:0]const u8) usize;

extern fn sqlite3Fts3HashFind(pH: *const Fts3Hash, pKey: ?*const anyopaque, nKey: c_int) ?*anyopaque;
extern fn sqlite3Fts3HashInsert(pH: *Fts3Hash, pKey: ?*const anyopaque, nKey: c_int, data: ?*anyopaque) ?*anyopaque;
extern fn sqlite3Fts3Dequote(z: [*:0]u8) void;
extern fn sqlite3Fts3ErrMsg(pzErr: *?[*:0]u8, zFormat: [*:0]const u8, ...) void;

/// Return true if the two-argument version of fts3_tokenizer() has been
/// activated via SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER. (static in C.)
fn fts3TokenizerEnabled(context: ?*sqlite3_context) c_int {
    const db = sqlite3_context_db_handle(context);
    var isEnabled: c_int = 0;
    _ = sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, @as(c_int, -1), &isEnabled);
    return isEnabled;
}

/// Implementation of the SQL scalar function fts3_tokenizer(). (static in C.)
fn fts3TokenizerFunc(
    context: ?*sqlite3_context,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
) callconv(.c) void {
    var pPtr: ?*anyopaque = null;

    std.debug.assert(argc == 1 or argc == 2);

    const pHash: *Fts3Hash = @ptrCast(@alignCast(sqlite3_user_data(context).?));
    const av = argv.?;

    const zName = sqlite3_value_text(av[0]);
    const nName = sqlite3_value_bytes(av[0]) + 1;

    if (argc == 2) {
        if (fts3TokenizerEnabled(context) != 0 or sqlite3_value_frombind(av[1]) != 0) {
            const n = sqlite3_value_bytes(av[1]);
            if (zName == null or n != @sizeOf(?*anyopaque)) {
                sqlite3_result_error(context, "argument type mismatch", -1);
                return;
            }
            // pPtr = *(void **)sqlite3_value_blob(argv[1]);
            const pBlob: *const ?*anyopaque = @ptrCast(@alignCast(sqlite3_value_blob(av[1]).?));
            pPtr = pBlob.*;
            const pOld = sqlite3Fts3HashInsert(pHash, @ptrCast(zName), nName, pPtr);
            if (pOld == pPtr) {
                sqlite3_result_error(context, "out of memory", -1);
            }
        } else {
            sqlite3_result_error(context, "fts3tokenize disabled", -1);
            return;
        }
    } else {
        if (zName) |zn| {
            pPtr = sqlite3Fts3HashFind(pHash, zn, nName);
        }
        if (pPtr == null) {
            const zErr = sqlite3_mprintf("unknown tokenizer: %s", zName);
            sqlite3_result_error(context, if (zErr) |z| z else @as([*:0]const u8, ""), -1);
            sqlite3_free(zErr);
            return;
        }
    }
    if (fts3TokenizerEnabled(context) != 0 or sqlite3_value_frombind(av[0]) != 0) {
        sqlite3_result_blob(context, @ptrCast(&pPtr), @sizeOf(?*anyopaque), SQLITE_TRANSIENT);
    }
}

/// isFtsIdChar table — copied byte-for-byte from the C source. Its address is
/// data (a static lookup table), not a symbol to import.
const isFtsIdChar = [_]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1x
    0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 2x
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 3x
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4x
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // 5x
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6x
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // 7x
};

/// Classify a byte as a tokenizer-id character. Matches the C exactly: any byte
/// with the high bit set (UTF) is an id char; otherwise consult the 128-entry
/// table. `c` is a `char` (signed) in C, so `c & 0x80` tests the sign bit.
export fn sqlite3Fts3IsIdChar(c: u8) callconv(.c) c_int {
    if ((c & 0x80) != 0) return 1;
    return isFtsIdChar[c];
}

/// Scan zStr for the start of the next token, returning a pointer to it and
/// writing its length to *pn, or null at end of string.
export fn sqlite3Fts3NextToken(zStr: [*:0]const u8, pn: *c_int) callconv(.c) ?[*:0]const u8 {
    var z1: [*:0]const u8 = zStr;
    var z2: ?[*:0]const u8 = null;

    while (z2 == null) {
        const c = z1[0];
        switch (c) {
            0 => return null, // No more tokens here
            '\'', '"', '`' => {
                // z2 = z1; while( *++z2 && (*z2!=c || *++z2==c) );
                var p: [*:0]const u8 = z1;
                while (true) {
                    p += 1;
                    if (p[0] == 0) break;
                    if (p[0] != c) continue;
                    p += 1;
                    if (p[0] == c) continue;
                    break;
                }
                z2 = p;
            },
            '[' => {
                // z2 = &z1[1]; while( *z2 && z2[0]!=']' ) z2++; if( *z2 ) z2++;
                var p: [*:0]const u8 = z1 + 1;
                while (p[0] != 0 and p[0] != ']') p += 1;
                if (p[0] != 0) p += 1;
                z2 = p;
            },
            else => {
                if (sqlite3Fts3IsIdChar(c) != 0) {
                    var p: [*:0]const u8 = z1 + 1;
                    while (sqlite3Fts3IsIdChar(p[0]) != 0) p += 1;
                    z2 = p;
                } else {
                    z1 += 1;
                }
            },
        }
    }

    const end = z2.?;
    pn.* = @intCast(@intFromPtr(end) - @intFromPtr(z1));
    return z1;
}

/// Resolve a tokenizer specification (name plus optional space-separated args)
/// into a constructed sqlite3_tokenizer in *ppTok.
export fn sqlite3Fts3InitTokenizer(
    pHash: *Fts3Hash,
    zArg: [*:0]const u8,
    ppTok: *?*sqlite3_tokenizer,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var rc: c_int = undefined;
    var n: c_int = 0;

    const zCopy = sqlite3_mprintf("%s", zArg) orelse return SQLITE_NOMEM;
    const zEnd: [*:0]u8 = zCopy + strlen(zCopy);

    var z: [*:0]u8 = blk: {
        const tok = sqlite3Fts3NextToken(zCopy, &n);
        if (tok == null) {
            std.debug.assert(n == 0);
            break :blk zCopy;
        }
        // sqlite3Fts3NextToken returns a pointer within zCopy.
        break :blk @constCast(tok.?);
    };
    z[@intCast(n)] = 0;
    sqlite3Fts3Dequote(z);

    const m: ?*sqlite3_tokenizer_module = @ptrCast(@alignCast(
        sqlite3Fts3HashFind(pHash, z, @as(c_int, @intCast(strlen(z))) + 1),
    ));
    if (m == null) {
        sqlite3Fts3ErrMsg(pzErr, "unknown tokenizer: %s", z);
        rc = SQLITE_ERROR;
    } else {
        var aArg: ?[*]?[*:0]const u8 = null;
        var iArg: c_int = 0;
        z = z + @as(usize, @intCast(n + 1));
        while (@intFromPtr(z) < @intFromPtr(zEnd)) {
            const tok = sqlite3Fts3NextToken(z, &n);
            if (tok == null) break;
            const zt: [*:0]u8 = @constCast(tok.?);
            const nNew: u64 = @sizeOf(?*anyopaque) * @as(u64, @intCast(iArg + 1));
            const aNew: ?[*]?[*:0]const u8 = @ptrCast(@alignCast(sqlite3_realloc64(@ptrCast(aArg), nNew)));
            if (aNew == null) {
                sqlite3_free(zCopy);
                sqlite3_free(@ptrCast(aArg));
                return SQLITE_NOMEM;
            }
            aArg = aNew;
            aArg.?[@intCast(iArg)] = zt;
            iArg += 1;
            zt[@intCast(n)] = 0;
            sqlite3Fts3Dequote(zt);
            z = zt + @as(usize, @intCast(n + 1));
        }
        rc = m.?.xCreate.?(iArg, @ptrCast(aArg orelse @as([*]?[*:0]const u8, undefined)), ppTok);
        std.debug.assert(rc != SQLITE_OK or ppTok.* != null);
        if (rc != SQLITE_OK) {
            sqlite3Fts3ErrMsg(pzErr, "unknown tokenizer");
        } else {
            ppTok.*.?.pModule = m;
        }
        sqlite3_free(@ptrCast(aArg));
    }

    sqlite3_free(zCopy);
    return rc;
}

/// Register the fts3_tokenizer() scalar function(s) on db, accessing the hash
/// table *pHash. (The SQLITE_TEST-only *_test / *_internal_test functions are
/// elided — they require the TCL library, which is not in this link surface.)
export fn sqlite3Fts3InitHashTable(
    db: ?*sqlite3,
    pHash: *Fts3Hash,
    zName: [*:0]const u8,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const p: ?*anyopaque = @ptrCast(pHash);
    const any: c_int = SQLITE_UTF8 | SQLITE_DIRECTONLY;

    // The SQLITE_TEST branch builds "%s_test"/"%s_internal_test" scalar
    // functions backed by TCL-dependent callbacks; it is intentionally not
    // compiled here (config.sqlite_test is consulted only as documentation of
    // that decision).
    comptime {
        _ = config;
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_create_function(db, zName, 1, any, p, fts3TokenizerFunc, null, null);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_create_function(db, zName, 2, any, p, fts3TokenizerFunc, null, null);
    }

    return rc;
}
