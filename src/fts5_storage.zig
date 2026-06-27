//! Zig port of the fts5_storage.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 23072-24600).
//!
//! The %_content / %_docsize / %_config shadow-table storage layer. This is the
//! glue that maps the user-visible FTS5 rows onto the shadow tables and drives
//! the fts5_index.c segment b-tree on insert/delete/rebuild. The Fts5Storage
//! object holds the cached "averages" totals plus a small cache of prepared
//! statements (aStmt[12]).
//!
//! Section-private structs (Fts5Storage, Fts5InsertCtx, Fts5IntegrityCtx) are
//! defined locally — the foundation exposes Fts5Storage as `opaque{}` so other
//! sections only ever hold an `?*Fts5Storage`.
//!
//! Pattern: `const int = @import("fts5_int.zig")` for shared types/constants;
//! `export fn <CName>(...) callconv(.c)` for the sqlite3Fts5Storage* symbols the
//! core/main expect; `extern fn` for siblings (fts5_index, fts5_config, the
//! locale helpers in fts5_main) and the core sqlite3_* API.

const int = @import("fts5_int.zig");
const config = @import("config");

const Fts5Config = int.Fts5Config;
const Fts5Index = int.Fts5Index;
const Fts5Buffer = int.Fts5Buffer;
const Fts5Termset = int.Fts5Termset;
const sqlite3 = int.sqlite3;
const sqlite3_stmt = int.sqlite3_stmt;
const sqlite3_value = int.sqlite3_value;

const SQLITE_OK = int.SQLITE_OK;
const SQLITE_ERROR = int.SQLITE_ERROR;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const SQLITE_CORRUPT = int.SQLITE_CORRUPT;
const SQLITE_MISMATCH = int.SQLITE_MISMATCH;
const SQLITE_RANGE = int.SQLITE_RANGE;
const SQLITE_ROW = int.SQLITE_ROW;
const SQLITE_INTEGER = int.SQLITE_INTEGER;
const SQLITE_TEXT = int.SQLITE_TEXT;

// FTS5_CORRUPT is the macro `#define FTS5_CORRUPT SQLITE_CORRUPT_VTAB` (the
// SQLITE_DEBUG variant just wraps a function that returns the same value).
const FTS5_CORRUPT = int.SQLITE_CORRUPT_VTAB;

// Statement-cache constants (fts5Int.h + fts5_storage.c top).
const FTS5_STMT_SCAN_ASC = int.FTS5_STMT_SCAN_ASC; // 0
const FTS5_STMT_SCAN_DESC = int.FTS5_STMT_SCAN_DESC; // 1
const FTS5_STMT_LOOKUP = int.FTS5_STMT_LOOKUP; // 2
const FTS5_STMT_LOOKUP2: c_int = 3;
const FTS5_STMT_INSERT_CONTENT: c_int = 4;
const FTS5_STMT_REPLACE_CONTENT: c_int = 5;
const FTS5_STMT_DELETE_CONTENT: c_int = 6;
const FTS5_STMT_REPLACE_DOCSIZE: c_int = 7;
const FTS5_STMT_DELETE_DOCSIZE: c_int = 8;
const FTS5_STMT_LOOKUP_DOCSIZE: c_int = 9;
const FTS5_STMT_REPLACE_CONFIG: c_int = 10;
const FTS5_STMT_SCAN: c_int = 11;

const FTS5_CONTENT_NORMAL = int.FTS5_CONTENT_NORMAL;
const FTS5_CONTENT_NONE = int.FTS5_CONTENT_NONE;
const FTS5_CONTENT_EXTERNAL = int.FTS5_CONTENT_EXTERNAL;
const FTS5_CONTENT_UNINDEXED = int.FTS5_CONTENT_UNINDEXED;

const FTS5_DETAIL_FULL = int.FTS5_DETAIL_FULL;
const FTS5_DETAIL_NONE = int.FTS5_DETAIL_NONE;
const FTS5_DETAIL_COLUMNS = int.FTS5_DETAIL_COLUMNS;

const FTS5_CURRENT_VERSION = int.FTS5_CURRENT_VERSION;
const FTS5_MAX_TOKEN_SIZE = int.FTS5_MAX_TOKEN_SIZE;
const FTS5_TOKENIZE_DOCUMENT = int.FTS5_TOKENIZE_DOCUMENT;
const FTS5_TOKEN_COLOCATED = int.FTS5_TOKEN_COLOCATED;

// sqlite3_prepare_v3 flags (sqlite3.h).
const SQLITE_PREPARE_PERSISTENT: c_int = 0x01;
const SQLITE_PREPARE_NO_VTAB: c_int = 0x04;

// Destructor sentinels: SQLITE_STATIC==0(null), SQLITE_TRANSIENT==-1.
const SQLITE_STATIC = int.SQLITE_STATIC;
const SQLITE_TRANSIENT = int.SQLITE_TRANSIENT;

const ArraySize: c_int = 12; // ArraySize(p->aStmt)

// ---------------------------------------------------------------------------
// libc + public sqlite3 API (resolved at link time)
// ---------------------------------------------------------------------------
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_exec(db: ?*sqlite3, sql: [*:0]const u8, cb: ?*anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *anyopaque) ?[*:0]u8;
extern fn sqlite3_errmsg(db: ?*sqlite3) ?[*:0]const u8;

extern fn sqlite3_prepare_v2(db: ?*sqlite3, sql: [*:0]const u8, n: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_prepare_v3(db: ?*sqlite3, sql: [*:0]const u8, n: c_int, prepFlags: c_uint, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_reset(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_step(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_clear_bindings(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_last_insert_rowid(db: ?*sqlite3) i64;
extern fn sqlite3_set_last_insert_rowid(db: ?*sqlite3, v: i64) void;

extern fn sqlite3_bind_int(pStmt: ?*sqlite3_stmt, i: c_int, v: c_int) c_int;
extern fn sqlite3_bind_int64(pStmt: ?*sqlite3_stmt, i: c_int, v: i64) c_int;
extern fn sqlite3_bind_null(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_bind_value(pStmt: ?*sqlite3_stmt, i: c_int, v: ?*sqlite3_value) c_int;
extern fn sqlite3_bind_text(pStmt: ?*sqlite3_stmt, i: c_int, z: ?[*]const u8, n: c_int, xDel: int.DestructorFn) c_int;
extern fn sqlite3_bind_blob(pStmt: ?*sqlite3_stmt, i: c_int, z: ?*const anyopaque, n: c_int, xDel: int.DestructorFn) c_int;

extern fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, i: c_int) i64;
extern fn sqlite3_column_bytes(pStmt: ?*sqlite3_stmt, i: c_int) c_int;
extern fn sqlite3_column_blob(pStmt: ?*sqlite3_stmt, i: c_int) ?*const anyopaque;
extern fn sqlite3_column_text(pStmt: ?*sqlite3_stmt, i: c_int) ?[*:0]const u8;
extern fn sqlite3_column_value(pStmt: ?*sqlite3_stmt, i: c_int) ?*sqlite3_value;

extern fn sqlite3_value_type(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_int64(p: ?*sqlite3_value) i64;
extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_bytes(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_nochange(p: ?*sqlite3_value) c_int;
extern fn sqlite3_value_dup(p: ?*const sqlite3_value) ?*sqlite3_value;
extern fn sqlite3_value_free(p: ?*sqlite3_value) void;

extern fn sqlite3_str_new(db: ?*sqlite3) ?*anyopaque;
extern fn sqlite3_str_appendf(p: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_str_finish(p: ?*anyopaque) ?[*:0]u8;

// ---------------------------------------------------------------------------
// sibling section: fts5_buffer.c (already ported)
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5BufferAppendVarint(pRc: *c_int, pBuf: *Fts5Buffer, iVal: i64) callconv(.c) void;
extern fn sqlite3Fts5BufferZero(pBuf: *Fts5Buffer) callconv(.c) void;
extern fn sqlite3Fts5Mprintf(pRc: *c_int, zFmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3Fts5GetVarint32(p: [*]const u8, v: *u32) callconv(.c) c_int;
extern fn sqlite3Fts5TermsetNew(pp: *?*Fts5Termset) callconv(.c) c_int;
extern fn sqlite3Fts5TermsetAdd(p: ?*Fts5Termset, iIdx: c_int, pTerm: [*]const u8, nTerm: c_int, pbPresent: *c_int) callconv(.c) c_int;
extern fn sqlite3Fts5TermsetFree(p: ?*Fts5Termset) callconv(.c) void;

// ---------------------------------------------------------------------------
// sibling section: fts5_index.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5IndexBeginWrite(p: ?*Fts5Index, bDelete: c_int, iDocid: i64) callconv(.c) c_int;
extern fn sqlite3Fts5IndexWrite(p: ?*Fts5Index, iCol: c_int, iPos: c_int, pToken: [*]const u8, nToken: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5IndexGetAverages(p: ?*Fts5Index, pnRow: *i64, anSize: [*]i64) callconv(.c) c_int;
extern fn sqlite3Fts5IndexSetAverages(p: ?*Fts5Index, a: [*]const u8, n: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5IndexReinit(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexOptimize(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexMerge(p: ?*Fts5Index, nMerge: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5IndexReset(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexSync(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexRollback(p: ?*Fts5Index) callconv(.c) c_int;
extern fn sqlite3Fts5IndexSetCookie(p: ?*Fts5Index, iCookie: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5IndexGetOrigin(p: ?*Fts5Index, piOrigin: *i64) callconv(.c) c_int;
extern fn sqlite3Fts5IndexContentlessDelete(p: ?*Fts5Index, iOrigin: i64, iRowid: i64) callconv(.c) c_int;
extern fn sqlite3Fts5IndexIntegrityCheck(p: ?*Fts5Index, cksum: u64, bUseCksum: c_int) callconv(.c) c_int;
extern fn sqlite3Fts5IndexEntryCksum(iRowid: i64, iCol: c_int, iPos: c_int, iIdx: c_int, pTerm: [*]const u8, nTerm: c_int) callconv(.c) u64;
extern fn sqlite3Fts5IndexCharlenToBytelen(p: [*]const u8, nByte: c_int, nChar: c_int) callconv(.c) c_int;

// ---------------------------------------------------------------------------
// sibling section: fts5_config.c
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5Tokenize(
    pConfig: *Fts5Config,
    flags: c_int,
    pText: ?[*]const u8,
    nText: c_int,
    pCtx: ?*anyopaque,
    xToken: ?*const fn (?*anyopaque, c_int, ?[*]const u8, c_int, c_int, c_int) callconv(.c) c_int,
) callconv(.c) c_int;

// ---------------------------------------------------------------------------
// sibling section: fts5_main.c (locale helpers)
// ---------------------------------------------------------------------------
extern fn sqlite3Fts5SetLocale(pConfig: *Fts5Config, zLocale: ?[*]const u8, nLocale: c_int) callconv(.c) void;
extern fn sqlite3Fts5ClearLocale(pConfig: *Fts5Config) callconv(.c) void;
extern fn sqlite3Fts5IsLocaleValue(pConfig: *Fts5Config, pVal: ?*sqlite3_value) callconv(.c) c_int;
extern fn sqlite3Fts5DecodeLocaleValue(
    pVal: ?*sqlite3_value,
    ppText: *?[*]const u8,
    pnText: *c_int,
    ppLoc: *?[*]const u8,
    pnLoc: *c_int,
) callconv(.c) c_int;

// ===========================================================================
// Section-private structs.
// ===========================================================================

/// fts5_storage.c 23117-23125: struct Fts5Storage. The `aStmt[12]` and the
/// trailing aTotalSize[] flexible allocation make this a fixed-prefix object;
/// aTotalSize points immediately after the struct (set up in Open).
const Fts5Storage = extern struct {
    pConfig: ?*Fts5Config,
    pIndex: ?*Fts5Index,
    bTotalsValid: c_int, // True if nTotalRow/aTotalSize[] are valid
    nTotalRow: i64, // Total number of rows in FTS table
    aTotalSize: ?[*]i64, // Total sizes of each column
    pSavedRow: ?*sqlite3_stmt,
    aStmt: [12]?*sqlite3_stmt,
};

/// fts5_storage.c 23509-23514: tokenization callback context for inserts.
const Fts5InsertCtx = extern struct {
    pStorage: ?*Fts5Storage,
    iCol: c_int,
    szCol: c_int, // Size of column value in tokens
};

/// fts5_storage.c 24201-24209: integrity-check tokenization context.
const Fts5IntegrityCtx = extern struct {
    iRowid: i64,
    iCol: c_int,
    szCol: c_int,
    cksum: u64,
    pTermset: ?*Fts5Termset,
    pConfig: ?*Fts5Config,
};

// ===========================================================================
// fts5StorageGetStmt (23154-23291): prepare (and cache) statement eStmt.
// ===========================================================================
fn fts5StorageGetStmt(
    p: *Fts5Storage,
    eStmt: c_int,
    ppStmt: *?*sqlite3_stmt,
    pzErrMsg: ?*?[*:0]u8,
) c_int {
    var rc: c_int = SQLITE_OK;

    const azStmt = [_][*:0]const u8{
        "SELECT %s FROM %s T WHERE T.%Q >= ? AND T.%Q <= ? ORDER BY T.%Q ASC",
        "SELECT %s FROM %s T WHERE T.%Q <= ? AND T.%Q >= ? ORDER BY T.%Q DESC",
        "SELECT %s FROM %s T WHERE T.%Q=?", // LOOKUP
        "SELECT %s FROM %s T WHERE T.%Q=?", // LOOKUP2

        "INSERT INTO %Q.'%q_content' VALUES(%s)", // INSERT_CONTENT
        "REPLACE INTO %Q.'%q_content' VALUES(%s)", // REPLACE_CONTENT
        "DELETE FROM %Q.'%q_content' WHERE id=?", // DELETE_CONTENT
        "REPLACE INTO %Q.'%q_docsize' VALUES(?,?%s)", // REPLACE_DOCSIZE
        "DELETE FROM %Q.'%q_docsize' WHERE id=?", // DELETE_DOCSIZE

        "SELECT sz%s FROM %Q.'%q_docsize' WHERE id=?", // LOOKUP_DOCSIZE

        "REPLACE INTO %Q.'%q_config' VALUES(?,?)", // REPLACE_CONFIG
        "SELECT %s FROM %s AS T", // SCAN
    };

    const eu: usize = @intCast(eStmt);
    if (p.aStmt[eu] == null) {
        const pC = p.pConfig.?;
        var zSql: ?[*:0]u8 = null;

        switch (eStmt) {
            FTS5_STMT_SCAN => {
                zSql = sqlite3_mprintf(azStmt[eu], pC.zContentExprlist, pC.zContent);
            },
            FTS5_STMT_SCAN_ASC, FTS5_STMT_SCAN_DESC => {
                zSql = sqlite3_mprintf(azStmt[eu], pC.zContentExprlist, pC.zContent, pC.zContentRowid, pC.zContentRowid, pC.zContentRowid);
            },
            FTS5_STMT_LOOKUP, FTS5_STMT_LOOKUP2 => {
                zSql = sqlite3_mprintf(azStmt[eu], pC.zContentExprlist, pC.zContent, pC.zContentRowid);
            },
            FTS5_STMT_INSERT_CONTENT, FTS5_STMT_REPLACE_CONTENT => {
                var zBind: ?[*:0]u8 = null;
                var i: c_int = 0;

                // Bindings for the "c*" columns.
                while (rc == SQLITE_OK and i < (pC.nCol + 1)) : (i += 1) {
                    if (i == 0 or pC.eContent == FTS5_CONTENT_NORMAL or pC.abUnindexed.?[@intCast(i - 1)] != 0) {
                        zBind = sqlite3Fts5Mprintf(&rc, "%z%s?%d", zBind, if (zBind != null) @as([*:0]const u8, ",") else @as([*:0]const u8, ""), i + 1);
                    }
                }

                // Bindings for any "l*" columns.
                if (pC.bLocale != 0 and pC.eContent == FTS5_CONTENT_NORMAL) {
                    i = 0;
                    while (rc == SQLITE_OK and i < pC.nCol) : (i += 1) {
                        if (pC.abUnindexed.?[@intCast(i)] == 0) {
                            zBind = sqlite3Fts5Mprintf(&rc, "%z,?%d", zBind, pC.nCol + i + 2);
                        }
                    }
                }

                zSql = sqlite3Fts5Mprintf(&rc, azStmt[eu], pC.zDb, pC.zName, zBind);
                sqlite3_free(zBind);
            },
            FTS5_STMT_REPLACE_DOCSIZE => {
                zSql = sqlite3_mprintf(azStmt[eu], pC.zDb, pC.zName, if (pC.bContentlessDelete != 0) @as([*:0]const u8, ",?") else @as([*:0]const u8, ""));
            },
            FTS5_STMT_LOOKUP_DOCSIZE => {
                zSql = sqlite3_mprintf(azStmt[eu], if (pC.bContentlessDelete != 0) @as([*:0]const u8, ",origin") else @as([*:0]const u8, ""), pC.zDb, pC.zName);
            },
            else => {
                zSql = sqlite3_mprintf(azStmt[eu], pC.zDb, pC.zName);
            },
        }

        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            var f: c_uint = SQLITE_PREPARE_PERSISTENT;
            if (eStmt > FTS5_STMT_LOOKUP2) f |= @intCast(SQLITE_PREPARE_NO_VTAB);
            p.pConfig.?.bLock += 1;
            rc = sqlite3_prepare_v3(pC.db, zSql.?, -1, f, &p.aStmt[eu], null);
            p.pConfig.?.bLock -= 1;
            sqlite3_free(zSql);
            if (rc != SQLITE_OK) {
                if (pzErrMsg) |pe| {
                    pe.* = sqlite3_mprintf("%s", sqlite3_errmsg(pC.db));
                }
            }
            if (rc == SQLITE_ERROR and eStmt > FTS5_STMT_LOOKUP2 and eStmt < FTS5_STMT_SCAN) {
                // One of the internal tables is missing: counts as corruption.
                rc = SQLITE_CORRUPT;
            }
        }
    }

    ppStmt.* = p.aStmt[eu];
    _ = sqlite3_reset(ppStmt.*);
    return rc;
}

// ===========================================================================
// fts5ExecPrintf (23294-23316): vmprintf + exec helper.
// ===========================================================================
fn fts5ExecPrintf(db: ?*sqlite3, pzErr: ?*?[*:0]u8, zFormat: [*:0]const u8, ...) callconv(.c) c_int {
    var rc: c_int = undefined;
    var ap = @cVaStart();
    const zSql = sqlite3_vmprintf(zFormat, @ptrCast(&ap));
    @cVaEnd(&ap);

    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else {
        rc = sqlite3_exec(db, zSql.?, null, null, pzErr);
        sqlite3_free(zSql);
    }
    return rc;
}

/// fts5_storage.c 23322-23344: drop all shadow tables.
export fn sqlite3Fts5DropAll(pConfig: *Fts5Config) callconv(.c) c_int {
    var rc = fts5ExecPrintf(pConfig.db, null, "DROP TABLE IF EXISTS %Q.'%q_data';" ++
        "DROP TABLE IF EXISTS %Q.'%q_idx';" ++
        "DROP TABLE IF EXISTS %Q.'%q_config';", pConfig.zDb, pConfig.zName, pConfig.zDb, pConfig.zName, pConfig.zDb, pConfig.zName);
    if (rc == SQLITE_OK and pConfig.bColumnsize != 0) {
        rc = fts5ExecPrintf(pConfig.db, null, "DROP TABLE IF EXISTS %Q.'%q_docsize';", pConfig.zDb, pConfig.zName);
    }
    if (rc == SQLITE_OK and pConfig.eContent == FTS5_CONTENT_NORMAL) {
        rc = fts5ExecPrintf(pConfig.db, null, "DROP TABLE IF EXISTS %Q.'%q_content';", pConfig.zDb, pConfig.zName);
    }
    return rc;
}

fn fts5StorageRenameOne(pConfig: *Fts5Config, pRc: *c_int, zTail: [*:0]const u8, zName: [*:0]const u8) void {
    if (pRc.* == SQLITE_OK) {
        pRc.* = fts5ExecPrintf(pConfig.db, null, "ALTER TABLE %Q.'%q_%s' RENAME TO '%q_%s';", pConfig.zDb, pConfig.zName, zTail, zName, zTail);
    }
}

/// fts5_storage.c 23360-23374: rename all shadow tables.
export fn sqlite3Fts5StorageRename(pStorage: *Fts5Storage, zName: [*:0]const u8) callconv(.c) c_int {
    const pConfig = pStorage.pConfig.?;
    var rc = sqlite3Fts5StorageSync(pStorage);

    fts5StorageRenameOne(pConfig, &rc, "data", zName);
    fts5StorageRenameOne(pConfig, &rc, "idx", zName);
    fts5StorageRenameOne(pConfig, &rc, "config", zName);
    if (pConfig.bColumnsize != 0) {
        fts5StorageRenameOne(pConfig, &rc, "docsize", zName);
    }
    if (pConfig.eContent == FTS5_CONTENT_NORMAL) {
        fts5StorageRenameOne(pConfig, &rc, "content", zName);
    }
    return rc;
}

/// fts5_storage.c 23380-23406: create one shadow table.
export fn sqlite3Fts5CreateTable(
    pConfig: *Fts5Config,
    zPost: [*:0]const u8,
    zDefn: [*:0]const u8,
    bWithout: c_int,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var zErr: ?[*:0]u8 = null;
    const rc = fts5ExecPrintf(pConfig.db, &zErr, "CREATE TABLE %Q.'%q_%q'(%s)%s", pConfig.zDb, pConfig.zName, zPost, zDefn, if (bWithout != 0) @as([*:0]const u8, " WITHOUT ROWID") else @as([*:0]const u8, ""));
    if (zErr) |ze| {
        pzErr.* = sqlite3_mprintf("fts5: error creating shadow table %q_%s: %s", pConfig.zName, zPost, ze);
        sqlite3_free(ze);
    }
    return rc;
}

/// fts5_storage.c 23415-23489: open (and optionally create) the storage layer.
export fn sqlite3Fts5StorageOpen(
    pConfig: *Fts5Config,
    pIndex: ?*Fts5Index,
    bCreate: c_int,
    pp: *?*Fts5Storage,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    const nByte: i64 = @as(i64, @sizeOf(Fts5Storage)) + @as(i64, pConfig.nCol) * @sizeOf(i64);
    const p: ?*Fts5Storage = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
    pp.* = p;
    if (p == null) return SQLITE_NOMEM;
    const ps = p.?;

    _ = memset(ps, 0, @intCast(nByte));
    // aTotalSize = (i64*)&p[1]
    ps.aTotalSize = @ptrCast(@as([*]Fts5Storage, @ptrCast(ps)) + 1);
    ps.pConfig = pConfig;
    ps.pIndex = pIndex;

    if (bCreate != 0) {
        if (pConfig.eContent == FTS5_CONTENT_NORMAL or pConfig.eContent == FTS5_CONTENT_UNINDEXED) {
            var i: c_int = 0;
            const pDefn = sqlite3_str_new(pConfig.db);

            sqlite3_str_appendf(pDefn, "id INTEGER PRIMARY KEY");
            i = 0;
            while (i < pConfig.nCol) : (i += 1) {
                if (pConfig.eContent == FTS5_CONTENT_NORMAL or pConfig.abUnindexed.?[@intCast(i)] != 0) {
                    sqlite3_str_appendf(pDefn, ", c%d", i);
                }
            }
            if (pConfig.bLocale != 0) {
                i = 0;
                while (i < pConfig.nCol) : (i += 1) {
                    if (pConfig.abUnindexed.?[@intCast(i)] == 0) {
                        sqlite3_str_appendf(pDefn, ", l%d", i);
                    }
                }
            }
            const zDefn = sqlite3_str_finish(pDefn);

            if (zDefn) |zd| {
                rc = sqlite3Fts5CreateTable(pConfig, "content", zd, 0, pzErr);
                sqlite3_free(zd);
            } else {
                rc = SQLITE_NOMEM;
            }
        }

        if (rc == SQLITE_OK and pConfig.bColumnsize != 0) {
            const zCols: [*:0]const u8 = if (pConfig.bContentlessDelete != 0)
                "id INTEGER PRIMARY KEY, sz BLOB, origin INTEGER"
            else
                "id INTEGER PRIMARY KEY, sz BLOB";
            rc = sqlite3Fts5CreateTable(pConfig, "docsize", zCols, 0, pzErr);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3Fts5CreateTable(pConfig, "config", "k PRIMARY KEY, v", 1, pzErr);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3Fts5StorageConfigValue(ps, "version", null, FTS5_CURRENT_VERSION);
        }
    }

    if (rc != SQLITE_OK) {
        _ = sqlite3Fts5StorageClose(ps);
        pp.* = null;
    }
    return rc;
}

/// fts5_storage.c 23494-23507: close a storage handle.
export fn sqlite3Fts5StorageClose(p: ?*Fts5Storage) callconv(.c) c_int {
    const rc: c_int = SQLITE_OK;
    if (p) |ps| {
        var i: usize = 0;
        while (i < @as(usize, @intCast(ArraySize))) : (i += 1) {
            _ = sqlite3_finalize(ps.aStmt[i]);
        }
        sqlite3_free(ps);
    }
    return rc;
}

/// fts5_storage.c 23519-23535: insert-callback for the tokenizer.
fn fts5StorageInsertCallback(
    pContext: ?*anyopaque,
    tflags: c_int,
    pToken: ?[*]const u8,
    nToken0: c_int,
    iUnused1: c_int,
    iUnused2: c_int,
) callconv(.c) c_int {
    _ = iUnused1;
    _ = iUnused2;
    const pCtx: *Fts5InsertCtx = @ptrCast(@alignCast(pContext.?));
    const pIdx = pCtx.pStorage.?.pIndex;
    var nToken = nToken0;
    if (nToken > FTS5_MAX_TOKEN_SIZE) nToken = FTS5_MAX_TOKEN_SIZE;
    if ((tflags & FTS5_TOKEN_COLOCATED) == 0 or pCtx.szCol == 0) {
        pCtx.szCol += 1;
    }
    return sqlite3Fts5IndexWrite(pIdx, pCtx.iCol, pCtx.szCol - 1, pToken.?, nToken);
}

/// fts5_storage.c 23547-23563: seek to a row to delete (UPDATE rowid change).
export fn sqlite3Fts5StorageFindDeleteRow(p: *Fts5Storage, iDel: i64) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var pSeek: ?*sqlite3_stmt = null;

    rc = fts5StorageGetStmt(p, FTS5_STMT_LOOKUP + 1, &pSeek, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pSeek, 1, iDel);
        if (sqlite3_step(pSeek) != SQLITE_ROW) {
            rc = sqlite3_reset(pSeek);
        } else {
            p.pSavedRow = pSeek;
        }
    }
    return rc;
}

/// fts5_storage.c 23575-23676: add delete-markers for the row at iDel.
fn fts5StorageDeleteFromIndex(
    p: *Fts5Storage,
    iDel: i64,
    apVal: ?[*]?*sqlite3_value,
    bSaveRow: c_int,
) c_int {
    const pConfig = p.pConfig.?;
    var pSeek: ?*sqlite3_stmt = null;
    var rc: c_int = SQLITE_OK;
    var ctx: Fts5InsertCtx = undefined;

    if (apVal == null) {
        if (p.pSavedRow != null and bSaveRow != 0) {
            pSeek = p.pSavedRow;
            p.pSavedRow = null;
        } else {
            rc = fts5StorageGetStmt(p, FTS5_STMT_LOOKUP + bSaveRow, &pSeek, null);
            if (rc != SQLITE_OK) return rc;
            _ = sqlite3_bind_int64(pSeek, 1, iDel);
            if (sqlite3_step(pSeek) != SQLITE_ROW) {
                return sqlite3_reset(pSeek);
            }
        }
    }

    ctx.pStorage = p;
    ctx.iCol = -1;
    var iCol: c_int = 1;
    while (rc == SQLITE_OK and iCol <= pConfig.nCol) : (iCol += 1) {
        if (pConfig.abUnindexed.?[@intCast(iCol - 1)] == 0) {
            var pVal: ?*sqlite3_value = null;
            var pFree: ?*sqlite3_value = null;
            var pText: ?[*]const u8 = null;
            var nText: c_int = 0;
            var pLoc: ?[*]const u8 = null;
            var nLoc: c_int = 0;

            if (pSeek) |ps| {
                pVal = sqlite3_column_value(ps, iCol);
            } else {
                pVal = apVal.?[@intCast(iCol - 1)];
            }

            if (pConfig.bLocale != 0 and sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
                rc = sqlite3Fts5DecodeLocaleValue(pVal, &pText, &nText, &pLoc, &nLoc);
            } else {
                if (sqlite3_value_type(pVal) != SQLITE_TEXT) {
                    pVal = sqlite3_value_dup(pVal);
                    pFree = pVal;
                    if (pVal == null) {
                        rc = SQLITE_NOMEM;
                    }
                }
                if (rc == SQLITE_OK) {
                    pText = @ptrCast(sqlite3_value_text(pVal));
                    nText = sqlite3_value_bytes(pVal);
                    if (pConfig.bLocale != 0 and pSeek != null) {
                        pLoc = @ptrCast(sqlite3_column_text(pSeek, iCol + pConfig.nCol));
                        nLoc = sqlite3_column_bytes(pSeek, iCol + pConfig.nCol);
                    }
                }
            }

            if (rc == SQLITE_OK) {
                sqlite3Fts5SetLocale(pConfig, pLoc, nLoc);
                ctx.szCol = 0;
                rc = sqlite3Fts5Tokenize(pConfig, FTS5_TOKENIZE_DOCUMENT, pText, nText, @ptrCast(&ctx), fts5StorageInsertCallback);
                p.aTotalSize.?[@intCast(iCol - 1)] -= @as(i64, ctx.szCol);
                if (rc == SQLITE_OK and p.aTotalSize.?[@intCast(iCol - 1)] < 0) {
                    rc = FTS5_CORRUPT;
                }
                sqlite3Fts5ClearLocale(pConfig);
            }
            sqlite3_value_free(pFree);
        }
    }
    if (rc == SQLITE_OK and p.nTotalRow < 1) {
        rc = FTS5_CORRUPT;
    } else {
        p.nTotalRow -= 1;
    }

    if (rc == SQLITE_OK and bSaveRow != 0) {
        p.pSavedRow = pSeek;
    } else {
        const rc2 = sqlite3_reset(pSeek);
        if (rc == SQLITE_OK) rc = rc2;
    }
    return rc;
}

/// fts5_storage.c 23683-23689: reset and clear pSavedRow.
export fn sqlite3Fts5StorageReleaseDeleteRow(pStorage: *Fts5Storage) callconv(.c) void {
    _ = sqlite3_reset(pStorage.pSavedRow);
    pStorage.pSavedRow = null;
}

/// fts5_storage.c 23697-23723: contentless_delete=1 tombstone insert.
fn fts5StorageContentlessDelete(p: *Fts5Storage, iDel: i64) c_int {
    var iOrigin: i64 = 0;
    var pLookup: ?*sqlite3_stmt = null;
    var rc: c_int = SQLITE_OK;

    rc = fts5StorageGetStmt(p, FTS5_STMT_LOOKUP_DOCSIZE, &pLookup, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_int64(pLookup, 1, iDel);
        if (SQLITE_ROW == sqlite3_step(pLookup)) {
            iOrigin = sqlite3_column_int64(pLookup, 1);
        }
        rc = sqlite3_reset(pLookup);
    }

    if (rc == SQLITE_OK and iOrigin != 0) {
        rc = sqlite3Fts5IndexContentlessDelete(p.pIndex, iOrigin, iDel);
    }
    return rc;
}

/// fts5_storage.c 23733-23758: write a %_docsize record.
fn fts5StorageInsertDocsize(p: *Fts5Storage, iRowid: i64, pBuf: *Fts5Buffer) c_int {
    var rc: c_int = SQLITE_OK;
    if (p.pConfig.?.bColumnsize != 0) {
        var pReplace: ?*sqlite3_stmt = null;
        rc = fts5StorageGetStmt(p, FTS5_STMT_REPLACE_DOCSIZE, &pReplace, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pReplace, 1, iRowid);
            if (p.pConfig.?.bContentlessDelete != 0) {
                var iOrigin: i64 = 0;
                rc = sqlite3Fts5IndexGetOrigin(p.pIndex, &iOrigin);
                _ = sqlite3_bind_int64(pReplace, 3, iOrigin);
            }
        }
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_blob(pReplace, 2, pBuf.p, pBuf.n, SQLITE_STATIC);
            _ = sqlite3_step(pReplace);
            rc = sqlite3_reset(pReplace);
            _ = sqlite3_bind_null(pReplace, 2);
        }
    }
    return rc;
}

/// fts5_storage.c 23770-23777: load the "averages" totals record.
fn fts5StorageLoadTotals(p: *Fts5Storage, bCache: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    if (p.bTotalsValid == 0) {
        rc = sqlite3Fts5IndexGetAverages(p.pIndex, &p.nTotalRow, p.aTotalSize.?);
        p.bTotalsValid = bCache;
    }
    return rc;
}

/// fts5_storage.c 23786-23803: store the "averages" totals record.
fn fts5StorageSaveTotals(p: *Fts5Storage) c_int {
    const nCol = p.pConfig.?.nCol;
    var rc: c_int = SQLITE_OK;
    var buf: Fts5Buffer = undefined;
    _ = memset(&buf, 0, @sizeOf(Fts5Buffer));

    sqlite3Fts5BufferAppendVarint(&rc, &buf, p.nTotalRow);
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        sqlite3Fts5BufferAppendVarint(&rc, &buf, p.aTotalSize.?[@intCast(i)]);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5IndexSetAverages(p.pIndex, buf.p.?, buf.n);
    }
    sqlite3_free(buf.p);
    return rc;
}

/// fts5_storage.c 23808-23865: remove a row from the FTS table.
export fn sqlite3Fts5StorageDelete(
    p: *Fts5Storage,
    iDel: i64,
    apVal: ?[*]?*sqlite3_value,
    bSaveRow: c_int,
) callconv(.c) c_int {
    const pConfig = p.pConfig.?;
    var rc: c_int = undefined;
    var pDel: ?*sqlite3_stmt = null;

    rc = fts5StorageLoadTotals(p, 1);

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5IndexBeginWrite(p.pIndex, 1, iDel);
    }

    if (rc == SQLITE_OK) {
        if (pConfig.bContentlessDelete != 0) {
            rc = fts5StorageContentlessDelete(p, iDel);
            if (rc == SQLITE_OK and bSaveRow != 0 and pConfig.eContent == FTS5_CONTENT_UNINDEXED) {
                rc = sqlite3Fts5StorageFindDeleteRow(p, iDel);
            }
        } else {
            rc = fts5StorageDeleteFromIndex(p, iDel, apVal, bSaveRow);
        }
    }

    // Delete the %_docsize record.
    if (rc == SQLITE_OK and pConfig.bColumnsize != 0) {
        rc = fts5StorageGetStmt(p, FTS5_STMT_DELETE_DOCSIZE, &pDel, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pDel, 1, iDel);
            _ = sqlite3_step(pDel);
            rc = sqlite3_reset(pDel);
        }
    }

    // Delete the %_content record.
    if (pConfig.eContent == FTS5_CONTENT_NORMAL or pConfig.eContent == FTS5_CONTENT_UNINDEXED) {
        if (rc == SQLITE_OK) {
            rc = fts5StorageGetStmt(p, FTS5_STMT_DELETE_CONTENT, &pDel, null);
        }
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_int64(pDel, 1, iDel);
            _ = sqlite3_step(pDel);
            rc = sqlite3_reset(pDel);
        }
    }

    return rc;
}

/// fts5_storage.c 23870-23904: delete all entries in the FTS5 index.
export fn sqlite3Fts5StorageDeleteAll(p: *Fts5Storage) callconv(.c) c_int {
    const pConfig = p.pConfig.?;
    var rc: c_int = undefined;

    p.bTotalsValid = 0;

    rc = fts5ExecPrintf(pConfig.db, null, "DELETE FROM %Q.'%q_data';" ++
        "DELETE FROM %Q.'%q_idx';", pConfig.zDb, pConfig.zName, pConfig.zDb, pConfig.zName);
    if (rc == SQLITE_OK and pConfig.bColumnsize != 0) {
        rc = fts5ExecPrintf(pConfig.db, null, "DELETE FROM %Q.'%q_docsize';", pConfig.zDb, pConfig.zName);
    }

    if (rc == SQLITE_OK and pConfig.eContent == FTS5_CONTENT_UNINDEXED) {
        rc = fts5ExecPrintf(pConfig.db, null, "DELETE FROM %Q.'%q_content';", pConfig.zDb, pConfig.zName);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5IndexReinit(p.pIndex);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5StorageConfigValue(p, "version", null, FTS5_CURRENT_VERSION);
    }
    return rc;
}

/// fts5_storage.c 23906-23981: rebuild the FTS index from the %_content table.
export fn sqlite3Fts5StorageRebuild(p: *Fts5Storage) callconv(.c) c_int {
    var buf: Fts5Buffer = .{ .p = null, .n = 0, .nSpace = 0 };
    const pConfig = p.pConfig.?;
    var pScan: ?*sqlite3_stmt = null;
    var ctx: Fts5InsertCtx = undefined;
    var rc: c_int = undefined;

    _ = memset(&ctx, 0, @sizeOf(Fts5InsertCtx));
    ctx.pStorage = p;
    rc = sqlite3Fts5StorageDeleteAll(p);
    if (rc == SQLITE_OK) {
        rc = fts5StorageLoadTotals(p, 1);
    }

    if (rc == SQLITE_OK) {
        rc = fts5StorageGetStmt(p, FTS5_STMT_SCAN, &pScan, pConfig.pzErrmsg);
    }

    while (rc == SQLITE_OK and SQLITE_ROW == sqlite3_step(pScan)) {
        const iRowid = sqlite3_column_int64(pScan, 0);

        sqlite3Fts5BufferZero(&buf);
        rc = sqlite3Fts5IndexBeginWrite(p.pIndex, 0, iRowid);
        ctx.iCol = 0;
        while (rc == SQLITE_OK and ctx.iCol < pConfig.nCol) : (ctx.iCol += 1) {
            ctx.szCol = 0;
            if (pConfig.abUnindexed.?[@intCast(ctx.iCol)] == 0) {
                var nText: c_int = 0;
                var pText: ?[*]const u8 = null;
                var nLoc: c_int = 0;
                var pLoc: ?[*]const u8 = null;

                const pVal = sqlite3_column_value(pScan, ctx.iCol + 1);
                if (pConfig.eContent == FTS5_CONTENT_EXTERNAL and sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
                    rc = sqlite3Fts5DecodeLocaleValue(pVal, &pText, &nText, &pLoc, &nLoc);
                } else {
                    pText = @ptrCast(sqlite3_value_text(pVal));
                    nText = sqlite3_value_bytes(pVal);
                    if (pConfig.bLocale != 0) {
                        const iCol = ctx.iCol + 1 + pConfig.nCol;
                        pLoc = @ptrCast(sqlite3_column_text(pScan, iCol));
                        nLoc = sqlite3_column_bytes(pScan, iCol);
                    }
                }

                if (rc == SQLITE_OK) {
                    sqlite3Fts5SetLocale(pConfig, pLoc, nLoc);
                    rc = sqlite3Fts5Tokenize(pConfig, FTS5_TOKENIZE_DOCUMENT, pText, nText, @ptrCast(&ctx), fts5StorageInsertCallback);
                    sqlite3Fts5ClearLocale(pConfig);
                }
            }
            sqlite3Fts5BufferAppendVarint(&rc, &buf, ctx.szCol);
            p.aTotalSize.?[@intCast(ctx.iCol)] += @as(i64, ctx.szCol);
        }
        p.nTotalRow += 1;

        if (rc == SQLITE_OK) {
            rc = fts5StorageInsertDocsize(p, iRowid, &buf);
        }
    }
    sqlite3_free(buf.p);
    const rc2 = sqlite3_reset(pScan);
    if (rc == SQLITE_OK) rc = rc2;

    if (rc == SQLITE_OK) {
        rc = fts5StorageSaveTotals(p);
    }
    return rc;
}

/// fts5_storage.c 23983-23985.
export fn sqlite3Fts5StorageOptimize(p: *Fts5Storage) callconv(.c) c_int {
    return sqlite3Fts5IndexOptimize(p.pIndex);
}

/// fts5_storage.c 23987-23989.
export fn sqlite3Fts5StorageMerge(p: *Fts5Storage, nMerge: c_int) callconv(.c) c_int {
    return sqlite3Fts5IndexMerge(p.pIndex, nMerge);
}

/// fts5_storage.c 23991-23993.
export fn sqlite3Fts5StorageReset(p: *Fts5Storage) callconv(.c) c_int {
    return sqlite3Fts5IndexReset(p.pIndex);
}

/// fts5_storage.c 24004-24020: allocate a new rowid for external-content.
fn fts5StorageNewRowid(p: *Fts5Storage, piRowid: *i64) c_int {
    var rc: c_int = SQLITE_MISMATCH;
    if (p.pConfig.?.bColumnsize != 0) {
        var pReplace: ?*sqlite3_stmt = null;
        rc = fts5StorageGetStmt(p, FTS5_STMT_REPLACE_DOCSIZE, &pReplace, null);
        if (rc == SQLITE_OK) {
            _ = sqlite3_bind_null(pReplace, 1);
            _ = sqlite3_bind_null(pReplace, 2);
            _ = sqlite3_step(pReplace);
            rc = sqlite3_reset(pReplace);
        }
        if (rc == SQLITE_OK) {
            piRowid.* = sqlite3_last_insert_rowid(p.pConfig.?.db);
        }
    }
    return rc;
}

/// fts5_storage.c 24025-24101: insert a row into the FTS content table.
export fn sqlite3Fts5StorageContentInsert(
    p: *Fts5Storage,
    bReplace: c_int,
    apVal: [*]?*sqlite3_value,
    piRowid: *i64,
) callconv(.c) c_int {
    const pConfig = p.pConfig.?;
    var rc: c_int = SQLITE_OK;

    if (pConfig.eContent != FTS5_CONTENT_NORMAL and pConfig.eContent != FTS5_CONTENT_UNINDEXED) {
        if (sqlite3_value_type(apVal[1]) == SQLITE_INTEGER) {
            piRowid.* = sqlite3_value_int64(apVal[1]);
        } else {
            rc = fts5StorageNewRowid(p, piRowid);
        }
    } else {
        var pInsert: ?*sqlite3_stmt = null;

        rc = fts5StorageGetStmt(p, FTS5_STMT_INSERT_CONTENT + bReplace, &pInsert, null);
        if (pInsert != null) _ = sqlite3_clear_bindings(pInsert);

        // Bind the rowid value.
        _ = sqlite3_bind_value(pInsert, 1, apVal[1]);

        var i: c_int = 2;
        while (rc == SQLITE_OK and i <= pConfig.nCol + 1) : (i += 1) {
            const bUnindexed = pConfig.abUnindexed.?[@intCast(i - 2)];
            if (pConfig.eContent == FTS5_CONTENT_NORMAL or bUnindexed != 0) {
                var pVal = apVal[@intCast(i)];

                if (sqlite3_value_nochange(pVal) != 0 and p.pSavedRow != null) {
                    pVal = sqlite3_column_value(p.pSavedRow, i - 1);
                    if (pConfig.bLocale != 0 and bUnindexed == 0) {
                        _ = sqlite3_bind_value(pInsert, pConfig.nCol + i, sqlite3_column_value(p.pSavedRow, pConfig.nCol + i - 1));
                    }
                } else if (sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
                    var pText: ?[*]const u8 = null;
                    var pLoc: ?[*]const u8 = null;
                    var nText: c_int = 0;
                    var nLoc: c_int = 0;

                    rc = sqlite3Fts5DecodeLocaleValue(pVal, &pText, &nText, &pLoc, &nLoc);
                    if (rc == SQLITE_OK) {
                        _ = sqlite3_bind_text(pInsert, i, pText, nText, SQLITE_TRANSIENT);
                        if (bUnindexed == 0) {
                            const iLoc = pConfig.nCol + i;
                            _ = sqlite3_bind_text(pInsert, iLoc, pLoc, nLoc, SQLITE_TRANSIENT);
                        }
                    }
                    continue;
                }

                rc = sqlite3_bind_value(pInsert, i, pVal);
            }
        }
        if (rc == SQLITE_OK) {
            _ = sqlite3_step(pInsert);
            rc = sqlite3_reset(pInsert);
        }
        piRowid.* = sqlite3_last_insert_rowid(pConfig.db);
    }

    return rc;
}

/// fts5_storage.c 24106-24171: insert into the FTS index + %_docsize.
export fn sqlite3Fts5StorageIndexInsert(
    p: *Fts5Storage,
    apVal: [*]?*sqlite3_value,
    iRowid: i64,
) callconv(.c) c_int {
    const pConfig = p.pConfig.?;
    var rc: c_int = SQLITE_OK;
    var ctx: Fts5InsertCtx = undefined;
    var buf: Fts5Buffer = undefined;

    _ = memset(&buf, 0, @sizeOf(Fts5Buffer));
    ctx.pStorage = p;
    rc = fts5StorageLoadTotals(p, 1);

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5IndexBeginWrite(p.pIndex, 0, iRowid);
    }
    ctx.iCol = 0;
    while (rc == SQLITE_OK and ctx.iCol < pConfig.nCol) : (ctx.iCol += 1) {
        ctx.szCol = 0;
        if (pConfig.abUnindexed.?[@intCast(ctx.iCol)] == 0) {
            var nText: c_int = 0;
            var pText: ?[*]const u8 = null;
            var nLoc: c_int = 0;
            var pLoc: ?[*]const u8 = null;

            var pVal = apVal[@intCast(ctx.iCol + 2)];
            if (p.pSavedRow != null and sqlite3_value_nochange(pVal) != 0) {
                pVal = sqlite3_column_value(p.pSavedRow, ctx.iCol + 1);
                if (pConfig.eContent == FTS5_CONTENT_NORMAL and pConfig.bLocale != 0) {
                    const iCol = ctx.iCol + 1 + pConfig.nCol;
                    pLoc = @ptrCast(sqlite3_column_text(p.pSavedRow, iCol));
                    nLoc = sqlite3_column_bytes(p.pSavedRow, iCol);
                }
            } else {
                pVal = apVal[@intCast(ctx.iCol + 2)];
            }

            if (pConfig.bLocale != 0 and sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
                rc = sqlite3Fts5DecodeLocaleValue(pVal, &pText, &nText, &pLoc, &nLoc);
            } else {
                pText = @ptrCast(sqlite3_value_text(pVal));
                nText = sqlite3_value_bytes(pVal);
            }

            if (rc == SQLITE_OK) {
                sqlite3Fts5SetLocale(pConfig, pLoc, nLoc);
                rc = sqlite3Fts5Tokenize(pConfig, FTS5_TOKENIZE_DOCUMENT, pText, nText, @ptrCast(&ctx), fts5StorageInsertCallback);
                sqlite3Fts5ClearLocale(pConfig);
            }
        }
        sqlite3Fts5BufferAppendVarint(&rc, &buf, ctx.szCol);
        p.aTotalSize.?[@intCast(ctx.iCol)] += @as(i64, ctx.szCol);
    }
    p.nTotalRow += 1;

    if (rc == SQLITE_OK) {
        rc = fts5StorageInsertDocsize(p, iRowid, &buf);
    }
    sqlite3_free(buf.p);

    return rc;
}

/// fts5_storage.c 24173-24196: SELECT count(*) FROM a shadow table.
fn fts5StorageCount(p: *Fts5Storage, zSuffix: [*:0]const u8, pnRow: *i64) c_int {
    const pConfig = p.pConfig.?;
    var rc: c_int = undefined;

    const zSql = sqlite3_mprintf("SELECT count(*) FROM %Q.'%q_%s'", pConfig.zDb, pConfig.zName, zSuffix);
    if (zSql == null) {
        rc = SQLITE_NOMEM;
    } else {
        var pCnt: ?*sqlite3_stmt = null;
        rc = sqlite3_prepare_v2(pConfig.db, zSql.?, -1, &pCnt, null);
        if (rc == SQLITE_OK) {
            if (SQLITE_ROW == sqlite3_step(pCnt)) {
                pnRow.* = sqlite3_column_int64(pCnt, 0);
            }
            rc = sqlite3_finalize(pCnt);
        }
    }

    sqlite3_free(zSql);
    return rc;
}

/// fts5_storage.c 24215-24277: integrity-check tokenization callback.
fn fts5StorageIntegrityCallback(
    pContext: ?*anyopaque,
    tflags: c_int,
    pToken: ?[*]const u8,
    nToken0: c_int,
    iUnused1: c_int,
    iUnused2: c_int,
) callconv(.c) c_int {
    _ = iUnused1;
    _ = iUnused2;
    const pCtx: *Fts5IntegrityCtx = @ptrCast(@alignCast(pContext.?));
    const pTermset = pCtx.pTermset;
    var bPresent: c_int = undefined;
    var rc: c_int = SQLITE_OK;
    var iPos: c_int = undefined;
    var iCol: c_int = undefined;
    var nToken = nToken0;

    if (nToken > FTS5_MAX_TOKEN_SIZE) nToken = FTS5_MAX_TOKEN_SIZE;

    if ((tflags & FTS5_TOKEN_COLOCATED) == 0 or pCtx.szCol == 0) {
        pCtx.szCol += 1;
    }

    switch (pCtx.pConfig.?.eDetail) {
        FTS5_DETAIL_FULL => {
            iPos = pCtx.szCol - 1;
            iCol = pCtx.iCol;
        },
        FTS5_DETAIL_COLUMNS => {
            iPos = pCtx.iCol;
            iCol = 0;
        },
        else => {
            iPos = 0;
            iCol = 0;
        },
    }

    rc = sqlite3Fts5TermsetAdd(pTermset, 0, pToken.?, nToken, &bPresent);
    if (rc == SQLITE_OK and bPresent == 0) {
        pCtx.cksum ^= sqlite3Fts5IndexEntryCksum(pCtx.iRowid, iCol, iPos, 0, pToken.?, nToken);
    }

    var ii: c_int = 0;
    while (rc == SQLITE_OK and ii < pCtx.pConfig.?.nPrefix) : (ii += 1) {
        const nChar = pCtx.pConfig.?.aPrefix.?[@intCast(ii)];
        const nByte = sqlite3Fts5IndexCharlenToBytelen(pToken.?, nToken, nChar);
        if (nByte != 0) {
            rc = sqlite3Fts5TermsetAdd(pTermset, ii + 1, pToken.?, nByte, &bPresent);
            if (bPresent == 0) {
                pCtx.cksum ^= sqlite3Fts5IndexEntryCksum(pCtx.iRowid, iCol, iPos, ii + 1, pToken.?, nByte);
            }
        }
    }

    return rc;
}

/// fts5_storage.c 24285-24419: integrity check against %_content.
export fn sqlite3Fts5StorageIntegrity(p: *Fts5Storage, iArg: c_int) callconv(.c) c_int {
    const pConfig = p.pConfig.?;
    var rc: c_int = SQLITE_OK;
    var ctx: Fts5IntegrityCtx = undefined;
    var pScan: ?*sqlite3_stmt = undefined;

    _ = memset(&ctx, 0, @sizeOf(Fts5IntegrityCtx));
    ctx.pConfig = p.pConfig;
    const nColU: usize = @intCast(pConfig.nCol);
    const aTotalSize: ?[*]i64 = @ptrCast(@alignCast(sqlite3_malloc64(@as(u64, nColU) * (@sizeOf(c_int) + @sizeOf(i64)))));
    if (aTotalSize == null) return SQLITE_NOMEM;
    const aColSize: [*]c_int = @ptrCast(@alignCast(aTotalSize.? + nColU));
    _ = memset(aTotalSize, 0, @sizeOf(i64) * nColU);

    const bUseCksum: c_int = @intFromBool(pConfig.eContent == FTS5_CONTENT_NORMAL or
        (pConfig.eContent == FTS5_CONTENT_EXTERNAL and iArg != 0));
    if (bUseCksum != 0) {
        rc = fts5StorageGetStmt(p, FTS5_STMT_SCAN, &pScan, null);
        if (rc == SQLITE_OK) {
            while (SQLITE_ROW == sqlite3_step(pScan)) {
                ctx.iRowid = sqlite3_column_int64(pScan, 0);
                ctx.szCol = 0;
                if (pConfig.bColumnsize != 0) {
                    rc = sqlite3Fts5StorageDocsize(p, ctx.iRowid, aColSize);
                }
                if (rc == SQLITE_OK and pConfig.eDetail == FTS5_DETAIL_NONE) {
                    rc = sqlite3Fts5TermsetNew(&ctx.pTermset);
                }
                var i: c_int = 0;
                while (rc == SQLITE_OK and i < pConfig.nCol) : (i += 1) {
                    if (pConfig.abUnindexed.?[@intCast(i)] == 0) {
                        var pText: ?[*]const u8 = null;
                        var nText: c_int = 0;
                        var pLoc: ?[*]const u8 = null;
                        var nLoc: c_int = 0;
                        const pVal = sqlite3_column_value(pScan, i + 1);

                        if (pConfig.eContent == FTS5_CONTENT_EXTERNAL and sqlite3Fts5IsLocaleValue(pConfig, pVal) != 0) {
                            rc = sqlite3Fts5DecodeLocaleValue(pVal, &pText, &nText, &pLoc, &nLoc);
                        } else {
                            if (pConfig.eContent == FTS5_CONTENT_NORMAL and pConfig.bLocale != 0) {
                                const iCol = i + 1 + pConfig.nCol;
                                pLoc = @ptrCast(sqlite3_column_text(pScan, iCol));
                                nLoc = sqlite3_column_bytes(pScan, iCol);
                            }
                            pText = @ptrCast(sqlite3_value_text(pVal));
                            nText = sqlite3_value_bytes(pVal);
                        }

                        ctx.iCol = i;
                        ctx.szCol = 0;

                        if (rc == SQLITE_OK and pConfig.eDetail == FTS5_DETAIL_COLUMNS) {
                            rc = sqlite3Fts5TermsetNew(&ctx.pTermset);
                        }

                        if (rc == SQLITE_OK) {
                            sqlite3Fts5SetLocale(pConfig, pLoc, nLoc);
                            rc = sqlite3Fts5Tokenize(pConfig, FTS5_TOKENIZE_DOCUMENT, pText, nText, @ptrCast(&ctx), fts5StorageIntegrityCallback);
                            sqlite3Fts5ClearLocale(pConfig);
                        }

                        if (rc == SQLITE_OK and pConfig.bColumnsize != 0 and ctx.szCol != aColSize[@intCast(i)]) {
                            rc = FTS5_CORRUPT;
                        }
                        aTotalSize.?[@intCast(i)] += ctx.szCol;
                        if (pConfig.eDetail == FTS5_DETAIL_COLUMNS) {
                            sqlite3Fts5TermsetFree(ctx.pTermset);
                            ctx.pTermset = null;
                        }
                    }
                }
                sqlite3Fts5TermsetFree(ctx.pTermset);
                ctx.pTermset = null;

                if (rc != SQLITE_OK) break;
            }
            const rc2 = sqlite3_reset(pScan);
            if (rc == SQLITE_OK) rc = rc2;
        }

        // Test that the "totals" record looks Ok.
        if (rc == SQLITE_OK) {
            rc = fts5StorageLoadTotals(p, 0);
            var i: c_int = 0;
            while (rc == SQLITE_OK and i < pConfig.nCol) : (i += 1) {
                if (p.aTotalSize.?[@intCast(i)] != aTotalSize.?[@intCast(i)]) rc = FTS5_CORRUPT;
            }
        }

        // Check %_content / %_docsize row counts.
        if (rc == SQLITE_OK and pConfig.eContent == FTS5_CONTENT_NORMAL) {
            var nRow: i64 = 0;
            rc = fts5StorageCount(p, "content", &nRow);
            if (rc == SQLITE_OK and nRow != p.nTotalRow) rc = FTS5_CORRUPT;
        }
        if (rc == SQLITE_OK and pConfig.bColumnsize != 0) {
            var nRow: i64 = 0;
            rc = fts5StorageCount(p, "docsize", &nRow);
            if (rc == SQLITE_OK and nRow != p.nTotalRow) rc = FTS5_CORRUPT;
        }
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5IndexIntegrityCheck(p.pIndex, ctx.cksum, bUseCksum);
    }

    sqlite3_free(aTotalSize);
    return rc;
}

/// fts5_storage.c 24425-24442: obtain a content-table read statement.
export fn sqlite3Fts5StorageStmt(
    p: *Fts5Storage,
    eStmt: c_int,
    pp: *?*sqlite3_stmt,
    pzErrMsg: ?*?[*:0]u8,
) callconv(.c) c_int {
    const rc = fts5StorageGetStmt(p, eStmt, pp, pzErrMsg);
    if (rc == SQLITE_OK) {
        p.aStmt[@intCast(eStmt)] = null;
    }
    return rc;
}

/// fts5_storage.c 24449-24464: release a statement obtained via StorageStmt().
export fn sqlite3Fts5StorageStmtRelease(
    p: *Fts5Storage,
    eStmt: c_int,
    pStmt: ?*sqlite3_stmt,
) callconv(.c) void {
    if (p.aStmt[@intCast(eStmt)] == null) {
        _ = sqlite3_reset(pStmt);
        p.aStmt[@intCast(eStmt)] = pStmt;
    } else {
        _ = sqlite3_finalize(pStmt);
    }
}

/// fts5_storage.c 24466-24477: decode the %_docsize varint array.
fn fts5StorageDecodeSizeArray(aCol: [*]c_int, nCol: c_int, aBlob: [*]const u8, nBlob: c_int) c_int {
    var iOff: c_int = 0;
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        if (iOff >= nBlob) return 1;
        var v: u32 = undefined;
        iOff += sqlite3Fts5GetVarint32(aBlob + @as(usize, @intCast(iOff)), &v);
        aCol[@intCast(i)] = @bitCast(v);
    }
    return @intFromBool(iOff != nBlob);
}

/// fts5_storage.c 24487-24514: read the %_docsize record for iRowid.
export fn sqlite3Fts5StorageDocsize(p: *Fts5Storage, iRowid: i64, aCol: [*]c_int) callconv(.c) c_int {
    const nCol = p.pConfig.?.nCol;
    var pLookup: ?*sqlite3_stmt = null;
    var rc: c_int = undefined;

    rc = fts5StorageGetStmt(p, FTS5_STMT_LOOKUP_DOCSIZE, &pLookup, null);
    if (pLookup) |pl| {
        var bCorrupt: c_int = 1;
        _ = sqlite3_bind_int64(pl, 1, iRowid);
        if (SQLITE_ROW == sqlite3_step(pl)) {
            const aBlob: [*]const u8 = @ptrCast(sqlite3_column_blob(pl, 0));
            const nBlob = sqlite3_column_bytes(pl, 0);
            if (0 == fts5StorageDecodeSizeArray(aCol, nCol, aBlob, nBlob)) {
                bCorrupt = 0;
            }
        }
        rc = sqlite3_reset(pl);
        if (bCorrupt != 0 and rc == SQLITE_OK) {
            rc = FTS5_CORRUPT;
        }
    }
    return rc;
}

/// fts5_storage.c 24516-24532: total token count for column iCol (-1 for all).
export fn sqlite3Fts5StorageSize(p: *Fts5Storage, iCol: c_int, pnToken: *i64) callconv(.c) c_int {
    var rc = fts5StorageLoadTotals(p, 0);
    if (rc == SQLITE_OK) {
        pnToken.* = 0;
        if (iCol < 0) {
            var i: c_int = 0;
            while (i < p.pConfig.?.nCol) : (i += 1) {
                pnToken.* += p.aTotalSize.?[@intCast(i)];
            }
        } else if (iCol < p.pConfig.?.nCol) {
            pnToken.* = p.aTotalSize.?[@intCast(iCol)];
        } else {
            rc = SQLITE_RANGE;
        }
    }
    return rc;
}

/// fts5_storage.c 24534-24546: total row count.
export fn sqlite3Fts5StorageRowCount(p: *Fts5Storage, pnRow: *i64) callconv(.c) c_int {
    var rc = fts5StorageLoadTotals(p, 0);
    if (rc == SQLITE_OK) {
        pnRow.* = p.nTotalRow;
        if (p.nTotalRow <= 0) rc = FTS5_CORRUPT;
    }
    return rc;
}

/// fts5_storage.c 24551-24565: flush in-memory data to disk.
export fn sqlite3Fts5StorageSync(p: *Fts5Storage) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const iLastRowid = sqlite3_last_insert_rowid(p.pConfig.?.db);
    if (p.bTotalsValid != 0) {
        rc = fts5StorageSaveTotals(p);
        if (rc == SQLITE_OK) {
            p.bTotalsValid = 0;
        }
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts5IndexSync(p.pIndex);
    }
    sqlite3_set_last_insert_rowid(p.pConfig.?.db, iLastRowid);
    return rc;
}

/// fts5_storage.c 24567-24570: rollback.
export fn sqlite3Fts5StorageRollback(p: *Fts5Storage) callconv(.c) c_int {
    p.bTotalsValid = 0;
    return sqlite3Fts5IndexRollback(p.pIndex);
}

/// fts5_storage.c 24572-24599: write a single %_config attribute.
export fn sqlite3Fts5StorageConfigValue(
    p: *Fts5Storage,
    z: [*:0]const u8,
    pVal: ?*sqlite3_value,
    iVal: c_int,
) callconv(.c) c_int {
    var pReplace: ?*sqlite3_stmt = null;
    var rc = fts5StorageGetStmt(p, FTS5_STMT_REPLACE_CONFIG, &pReplace, null);
    if (rc == SQLITE_OK) {
        _ = sqlite3_bind_text(pReplace, 1, z, -1, SQLITE_STATIC);
        if (pVal) |pv| {
            _ = sqlite3_bind_value(pReplace, 2, pv);
        } else {
            _ = sqlite3_bind_int(pReplace, 2, iVal);
        }
        _ = sqlite3_step(pReplace);
        rc = sqlite3_reset(pReplace);
        _ = sqlite3_bind_null(pReplace, 1);
    }
    if (rc == SQLITE_OK and pVal != null) {
        const iNew = p.pConfig.?.iCookie + 1;
        rc = sqlite3Fts5IndexSetCookie(p.pIndex, iNew);
        if (rc == SQLITE_OK) {
            p.pConfig.?.iCookie = iNew;
        }
    }
    return rc;
}

comptime {
    _ = int;
    _ = config;
}
