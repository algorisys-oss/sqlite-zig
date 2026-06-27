//! Zig port of the "fts3tokenize" eponymous virtual table
//! (ext/fts3/fts3_tokenize_vtab.c).
//!
//! Drop-in replacement exporting the single non-static symbol of the C file:
//!   * sqlite3Fts3InitTok — register the "fts3tokenize" module on a connection.
//! Everything else is `static` in C: the xConnect/xCreate, xDisconnect/xDestroy,
//! xBestIndex, xOpen/xClose, xFilter, xNext, xEof, xColumn, xRowid callbacks and
//! the fts3tokQueryTokenizer/fts3tokDequoteArray/fts3tokResetCursor helpers.
//! They are kept private and reached only through the sqlite3_module function
//! pointers, exactly as in C.
//!
//! Coupling taxonomy:
//!   - PUBLIC ABI vtable types (sqlite3_module / sqlite3_vtab /
//!     sqlite3_vtab_cursor / sqlite3_index_info, from sqlite3.h) and the FTS3
//!     tokenizer types (sqlite3_tokenizer_module / _tokenizer / _tokenizer_cursor,
//!     from fts3_tokenizer.h) are mirrored field-for-field as `extern struct`,
//!     copied exactly from the already-ported src/fts3.zig and
//!     src/fts3_porter.zig. The sqlite3_module field order / iVersion must match.
//!   - Fts3Hash (fts3_hash.h) is mirrored as `extern struct`, copied exactly from
//!     src/fts3_hash.zig, so sqlite3Fts3HashFind (link-time, in src/fts3_hash.zig)
//!     can be called.
//!   - The Fts3tokTable / Fts3tokCursor derived structs are *internal* — only
//!     sizeof matters across the boundary — so they embed the public base first.
//!   - Only public `sqlite3_*` API and already-ported fts3 helpers
//!     (sqlite3Fts3HashFind, sqlite3Fts3Dequote, sqlite3Fts3ErrMsg) are called.
//!
//! Config-invariant: the only SQLITE_DEBUG-conditional code in the C source is a
//! pure `assert()` (no side effects), which is dropped. No build-config-dependent
//! struct field is touched, so this one object is correct in both the production
//! `zig build` and the `--dev` testfixture builds; `@import("config")` is unused.

const std = @import("std");

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_DONE: c_int = 101;

const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;

// Destructor sentinel (sqlite3.h): SQLITE_TRANSIENT == -1 cast to a destructor.
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// --- Opaque public handles (sqlite3.h) ---
const sqlite3 = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;

// --- PUBLIC ABI structs (sqlite3.h) — copied exactly from src/fts3.zig ---

const sqlite3_vtab = extern struct {
    pModule: ?*const sqlite3_module,
    nRef: c_int,
    zErrMsg: ?[*:0]u8,
};

const sqlite3_vtab_cursor = extern struct {
    pVtab: ?*sqlite3_vtab,
};

const sqlite3_index_constraint = extern struct {
    iColumn: c_int,
    op: u8,
    usable: u8,
    iTermOffset: c_int,
};

const sqlite3_index_orderby = extern struct {
    iColumn: c_int,
    desc: u8,
};

const sqlite3_index_constraint_usage = extern struct {
    argvIndex: c_int,
    omit: u8,
};

const sqlite3_index_info = extern struct {
    nConstraint: c_int,
    aConstraint: ?[*]sqlite3_index_constraint,
    nOrderBy: c_int,
    aOrderBy: ?[*]sqlite3_index_orderby,
    aConstraintUsage: ?[*]sqlite3_index_constraint_usage,
    idxNum: c_int,
    idxStr: ?[*:0]u8,
    needToFreeIdxStr: c_int,
    orderByConsumed: c_int,
    estimatedCost: f64,
    estimatedRows: i64,
    idxFlags: c_int,
    colUsed: u64,
};

/// The virtual table method table — PUBLIC ABI. Must match sqlite3_module field
/// for field. fts3tok uses iVersion 0.
const ModFn0 = ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int;
const sqlite3_module = extern struct {
    iVersion: c_int,
    xCreate: ModFn0,
    xConnect: ModFn0,
    xBestIndex: ?*const fn (*sqlite3_vtab, *sqlite3_index_info) callconv(.c) c_int,
    xDisconnect: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xDestroy: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xOpen: ?*const fn (*sqlite3_vtab, *?*sqlite3_vtab_cursor) callconv(.c) c_int,
    xClose: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xFilter: ?*const fn (*sqlite3_vtab_cursor, c_int, ?[*:0]const u8, c_int, ?[*]?*sqlite3_value) callconv(.c) c_int,
    xNext: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xEof: ?*const fn (*sqlite3_vtab_cursor) callconv(.c) c_int,
    xColumn: ?*const fn (*sqlite3_vtab_cursor, ?*sqlite3_context, c_int) callconv(.c) c_int,
    xRowid: ?*const fn (*sqlite3_vtab_cursor, *i64) callconv(.c) c_int,
    xUpdate: ?*const fn (*sqlite3_vtab, c_int, ?[*]?*sqlite3_value, *i64) callconv(.c) c_int,
    xBegin: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xSync: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xCommit: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xRollback: ?*const fn (*sqlite3_vtab) callconv(.c) c_int,
    xFindFunction: ?*const fn (*sqlite3_vtab, c_int, [*:0]const u8, *?*const fn (?*sqlite3_context, c_int, ?[*]?*sqlite3_value) callconv(.c) void, *?*anyopaque) callconv(.c) c_int,
    xRename: ?*const fn (*sqlite3_vtab, [*:0]const u8) callconv(.c) c_int,
    xSavepoint: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xRelease: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xRollbackTo: ?*const fn (*sqlite3_vtab, c_int) callconv(.c) c_int,
    xShadowName: ?*const fn ([*:0]const u8) callconv(.c) c_int,
    xIntegrity: ?*const fn (*sqlite3_vtab, [*:0]const u8, [*:0]const u8, c_int, *?[*:0]u8) callconv(.c) c_int,
};

// --- PUBLIC ABI tokenizer types (fts3_tokenizer.h) — copied from fts3_porter.zig ---

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

// --- Fts3Hash (fts3_hash.h) — copied exactly from src/fts3_hash.zig ---

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
    keyClass: i8,
    copyKey: i8,
    count: c_int,
    first: ?*Fts3HashElem,
    htsize: c_int,
    ht: ?[*]Fts3ht,
};

// --- Module-private derived structs ---

/// Virtual table structure. (struct Fts3tokTable)
const Fts3tokTable = extern struct {
    base: sqlite3_vtab, // Base class used by SQLite core
    pMod: ?*const sqlite3_tokenizer_module,
    pTok: ?*sqlite3_tokenizer,
};

/// Virtual table cursor structure. (struct Fts3tokCursor)
const Fts3tokCursor = extern struct {
    base: sqlite3_vtab_cursor, // Base class used by SQLite core
    zInput: ?[*]u8, // Input string
    pCsr: ?*sqlite3_tokenizer_cursor, // Cursor to iterate through zInput
    iRowid: c_int, // Current 'rowid' value
    zToken: ?[*]const u8, // Current 'token' value
    nToken: c_int, // Size of zToken in bytes
    iStart: c_int, // Current 'start' value
    iEnd: c_int, // Current 'end' value
    iPos: c_int, // Current 'pos' value
};

// --- C / fts3 helpers resolved at link time ---
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_create_module_v2(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pAux: ?*anyopaque, xDestroy: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_bytes(p: ?*sqlite3_value) c_int;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*]const u8, n: c_int, d: DestructorFn) void;
extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn strlen(s: [*:0]const u8) usize;

extern fn sqlite3Fts3HashFind(pH: *const Fts3Hash, pKey: ?*const anyopaque, nKey: c_int) ?*anyopaque;
extern fn sqlite3Fts3Dequote(z: [*:0]u8) void;
extern fn sqlite3Fts3ErrMsg(pzErr: *?[*:0]u8, zFormat: [*:0]const u8, ...) void;

/// Query FTS for the tokenizer implementation named zName. (static in C.)
fn fts3tokQueryTokenizer(
    pHash: *Fts3Hash,
    zName: [*:0]const u8,
    pp: *?*const sqlite3_tokenizer_module,
    pzErr: *?[*:0]u8,
) c_int {
    const nName: c_int = @intCast(strlen(zName));
    const p: ?*sqlite3_tokenizer_module = @ptrCast(@alignCast(
        sqlite3Fts3HashFind(pHash, zName, nName + 1),
    ));
    if (p == null) {
        sqlite3Fts3ErrMsg(pzErr, "unknown tokenizer: %s", zName);
        return SQLITE_ERROR;
    }
    pp.* = p;
    return SQLITE_OK;
}

/// Copy argv[] into a single allocation and dequote each string. (static in C.)
fn fts3tokDequoteArray(
    argc: c_int,
    argv: [*]const [*:0]const u8,
    pazDequote: *?[*]?[*:0]u8,
) c_int {
    var rc: c_int = SQLITE_OK;
    if (argc == 0) {
        pazDequote.* = null;
    } else {
        var nByte: c_int = 0;
        var i: c_int = 0;
        while (i < argc) : (i += 1) {
            nByte += @as(c_int, @intCast(strlen(argv[@intCast(i)]) + 1));
        }

        const total: u64 = @sizeOf(?*anyopaque) * @as(u64, @intCast(argc)) + @as(u64, @intCast(nByte));
        const azDequote: ?[*]?[*:0]u8 = @ptrCast(@alignCast(sqlite3_malloc64(total)));
        pazDequote.* = azDequote;
        if (azDequote == null) {
            rc = SQLITE_NOMEM;
        } else {
            // pSpace = (char *)&azDequote[argc];
            var pSpace: [*]u8 = @ptrCast(&azDequote.?[@intCast(argc)]);
            i = 0;
            while (i < argc) : (i += 1) {
                const n: usize = strlen(argv[@intCast(i)]);
                azDequote.?[@intCast(i)] = @ptrCast(pSpace);
                _ = memcpy(pSpace, argv[@intCast(i)], n + 1);
                sqlite3Fts3Dequote(@ptrCast(pSpace));
                pSpace += (n + 1);
            }
        }
    }
    return rc;
}

/// Schema of the tokenizer table. (#define FTS3_TOK_SCHEMA, inline)
const FTS3_TOK_SCHEMA = "CREATE TABLE x(input, token, start, end, position)";

/// xConnect == xCreate: both build a transient table. (static in C.)
fn fts3tokConnectMethod(
    db: ?*sqlite3,
    pHash: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var pTab: ?*Fts3tokTable = null;
    var pMod: ?*const sqlite3_tokenizer_module = null;
    var pTok: ?*sqlite3_tokenizer = null;
    var azDequote: ?[*]?[*:0]u8 = null;

    var rc = sqlite3_declare_vtab(db, FTS3_TOK_SCHEMA);
    if (rc != SQLITE_OK) return rc;

    const nDequote = argc - 3;
    // &argv[3] — argv entries are non-null nul-terminated strings here.
    const argv3: [*]const [*:0]const u8 = @ptrCast(argv.? + 3);
    rc = fts3tokDequoteArray(nDequote, argv3, &azDequote);

    if (rc == SQLITE_OK) {
        const zModule: [*:0]const u8 = if (nDequote < 1) "simple" else azDequote.?[0].?;
        rc = fts3tokQueryTokenizer(@ptrCast(@alignCast(pHash.?)), zModule, &pMod, pzErr);
    }

    std.debug.assert((rc == SQLITE_OK) == (pMod != null));
    if (rc == SQLITE_OK) {
        const azArg: [*]const [*:0]const u8 = if (nDequote > 1)
            @ptrCast(&azDequote.?[1])
        else
            @as([*]const [*:0]const u8, undefined);
        rc = pMod.?.xCreate.?(if (nDequote > 1) nDequote - 1 else 0, azArg, &pTok);
    }

    if (rc == SQLITE_OK) {
        pTab = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(Fts3tokTable))));
        if (pTab == null) {
            rc = SQLITE_NOMEM;
        }
    }

    if (rc == SQLITE_OK) {
        _ = memset(pTab, 0, @sizeOf(Fts3tokTable));
        pTab.?.pMod = pMod;
        pTab.?.pTok = pTok;
        ppVtab.* = &pTab.?.base;
    } else {
        if (pTok) |t| {
            _ = pMod.?.xDestroy.?(t);
        }
    }

    sqlite3_free(@ptrCast(azDequote));
    return rc;
}

/// xDisconnect == xDestroy. (static in C.)
fn fts3tokDisconnectMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const pTab: *Fts3tokTable = @ptrCast(@alignCast(pVtab));
    _ = pTab.pMod.?.xDestroy.?(pTab.pTok.?);
    sqlite3_free(pTab);
    return SQLITE_OK;
}

/// xBestIndex - look for an `input = ?` constraint. (static in C.)
fn fts3tokBestIndexMethod(pVTab: *sqlite3_vtab, pInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = pVTab;
    var i: c_int = 0;
    const aConstraint = pInfo.aConstraint.?;
    const aConstraintUsage = pInfo.aConstraintUsage.?;
    while (i < pInfo.nConstraint) : (i += 1) {
        const con = &aConstraint[@intCast(i)];
        if (con.usable != 0 and con.iColumn == 0 and con.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            pInfo.idxNum = 1;
            aConstraintUsage[@intCast(i)].argvIndex = 1;
            aConstraintUsage[@intCast(i)].omit = 1;
            pInfo.estimatedCost = 1;
            return SQLITE_OK;
        }
    }

    pInfo.idxNum = 0;
    std.debug.assert(pInfo.estimatedCost > 1000000.0);

    return SQLITE_OK;
}

/// xOpen - Open a cursor. (static in C.)
fn fts3tokOpenMethod(pVTab: *sqlite3_vtab, ppCsr: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    _ = pVTab;
    const pCsr: ?*Fts3tokCursor = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(Fts3tokCursor))));
    if (pCsr == null) {
        return SQLITE_NOMEM;
    }
    _ = memset(pCsr, 0, @sizeOf(Fts3tokCursor));

    ppCsr.* = @ptrCast(&pCsr.?.base);
    return SQLITE_OK;
}

/// Reset the tokenizer cursor as if just returned by fts3tokOpenMethod. (static)
fn fts3tokResetCursor(pCsr: *Fts3tokCursor) void {
    if (pCsr.pCsr) |csr| {
        const pTab: *Fts3tokTable = @ptrCast(@alignCast(pCsr.base.pVtab.?));
        _ = pTab.pMod.?.xClose.?(csr);
        pCsr.pCsr = null;
    }
    sqlite3_free(@ptrCast(pCsr.zInput));
    pCsr.zInput = null;
    pCsr.zToken = null;
    pCsr.nToken = 0;
    pCsr.iStart = 0;
    pCsr.iEnd = 0;
    pCsr.iPos = 0;
    pCsr.iRowid = 0;
}

/// xClose - Close a cursor. (static in C.)
fn fts3tokCloseMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts3tokCursor = @ptrCast(@alignCast(pCursor));
    fts3tokResetCursor(pCsr);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

/// xNext - Advance the cursor to the next row, if any. (static in C.)
fn fts3tokNextMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts3tokCursor = @ptrCast(@alignCast(pCursor));
    const pTab: *Fts3tokTable = @ptrCast(@alignCast(pCursor.pVtab.?));

    pCsr.iRowid += 1;
    var rc = pTab.pMod.?.xNext.?(
        pCsr.pCsr.?,
        &pCsr.zToken,
        &pCsr.nToken,
        &pCsr.iStart,
        &pCsr.iEnd,
        &pCsr.iPos,
    );

    if (rc != SQLITE_OK) {
        fts3tokResetCursor(pCsr);
        if (rc == SQLITE_DONE) rc = SQLITE_OK;
    }

    return rc;
}

/// xFilter - Initialize a cursor to point at the start of its data. (static.)
fn fts3tokFilterMethod(
    pCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    nVal: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_ERROR;
    const pCsr: *Fts3tokCursor = @ptrCast(@alignCast(pCursor));
    const pTab: *Fts3tokTable = @ptrCast(@alignCast(pCursor.pVtab.?));
    _ = idxStr;
    _ = nVal;

    fts3tokResetCursor(pCsr);
    if (idxNum == 1) {
        const av = apVal.?;
        const zByte = sqlite3_value_text(av[0]);
        const nByte: i64 = sqlite3_value_bytes(av[0]);
        pCsr.zInput = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nByte + 1))));
        if (pCsr.zInput == null) {
            rc = SQLITE_NOMEM;
        } else {
            if (nByte > 0) _ = memcpy(pCsr.zInput, zByte, @intCast(nByte));
            pCsr.zInput.?[@intCast(nByte)] = 0;
            rc = pTab.pMod.?.xOpen.?(pTab.pTok.?, pCsr.zInput, @intCast(nByte), &pCsr.pCsr);
            if (rc == SQLITE_OK) {
                pCsr.pCsr.?.pTokenizer = pTab.pTok;
            }
        }
    }

    if (rc != SQLITE_OK) return rc;
    return fts3tokNextMethod(pCursor);
}

/// xEof - Return true if the cursor is at EOF. (static in C.)
fn fts3tokEofMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts3tokCursor = @ptrCast(@alignCast(pCursor));
    return @intFromBool(pCsr.zToken == null);
}

/// xColumn - Return a column value. (static in C.)
fn fts3tokColumnMethod(
    pCursor: *sqlite3_vtab_cursor,
    pCtx: ?*sqlite3_context,
    iCol: c_int,
) callconv(.c) c_int {
    const pCsr: *Fts3tokCursor = @ptrCast(@alignCast(pCursor));

    // CREATE TABLE x(input, token, start, end, position)
    switch (iCol) {
        0 => sqlite3_result_text(pCtx, pCsr.zInput, -1, SQLITE_TRANSIENT),
        1 => sqlite3_result_text(pCtx, pCsr.zToken, pCsr.nToken, SQLITE_TRANSIENT),
        2 => sqlite3_result_int(pCtx, pCsr.iStart),
        3 => sqlite3_result_int(pCtx, pCsr.iEnd),
        else => {
            std.debug.assert(iCol == 4);
            sqlite3_result_int(pCtx, pCsr.iPos);
        },
    }
    return SQLITE_OK;
}

/// xRowid - Return the current rowid for the cursor. (static in C.)
fn fts3tokRowidMethod(pCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *Fts3tokCursor = @ptrCast(@alignCast(pCursor));
    pRowid.* = @intCast(pCsr.iRowid);
    return SQLITE_OK;
}

/// The fts3tokenize module table — PUBLIC ABI, iVersion 0. Field order matches
/// the C `static const sqlite3_module fts3tok_module` exactly.
const fts3tok_module = sqlite3_module{
    .iVersion = 0,
    .xCreate = fts3tokConnectMethod,
    .xConnect = fts3tokConnectMethod,
    .xBestIndex = fts3tokBestIndexMethod,
    .xDisconnect = fts3tokDisconnectMethod,
    .xDestroy = fts3tokDisconnectMethod,
    .xOpen = fts3tokOpenMethod,
    .xClose = fts3tokCloseMethod,
    .xFilter = fts3tokFilterMethod,
    .xNext = fts3tokNextMethod,
    .xEof = fts3tokEofMethod,
    .xColumn = fts3tokColumnMethod,
    .xRowid = fts3tokRowidMethod,
    .xUpdate = null,
    .xBegin = null,
    .xSync = null,
    .xCommit = null,
    .xRollback = null,
    .xFindFunction = null,
    .xRename = null,
    .xSavepoint = null,
    .xRelease = null,
    .xRollbackTo = null,
    .xShadowName = null,
    .xIntegrity = null,
};

/// Register the fts3tokenize module with database connection db.
export fn sqlite3Fts3InitTok(
    db: ?*sqlite3,
    pHash: *Fts3Hash,
    xDestroy: ?*const fn (?*anyopaque) callconv(.c) void,
) callconv(.c) c_int {
    return sqlite3_create_module_v2(
        db,
        "fts3tokenize",
        &fts3tok_module,
        @ptrCast(pHash),
        xDestroy,
    );
}
