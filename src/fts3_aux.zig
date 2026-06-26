//! Zig port of SQLite's FTS3/4 "fts4aux" auxiliary virtual table
//! (ext/fts3/fts3_aux.c).
//!
//! `fts4aux` is an eponymous-ish read-only virtual table that exposes the
//! per-term / per-column document and occurrence statistics of an FTS3/FTS4
//! table:
//!
//!     CREATE VIRTUAL TABLE t USING fts4aux(fts4-table[, db]);
//!     -- schema: x(term, col, documents, occurrences, languageid HIDDEN)
//!
//! Drop-in replacement for the C translation unit. The ONLY external-linkage
//! symbol upstream `fts3_aux.c` defines is `sqlite3Fts3InitAux` (every method is
//! `static`), so that is the only `export fn` here. The module is compiled
//! because SQLITE_ENABLE_FTS3 is enabled (build.zig sets -DSQLITE_ENABLE_FTS4,
//! which implies FTS3).
//!
//! ABI coupling
//! ------------
//! Two classes of struct are touched:
//!
//!   * This module's OWN structs — `Fts3auxTable`, `Fts3auxCursor`,
//!     `Fts3auxColstats`. These are private to the .c (allocated and
//!     pointer-passed, never inspected by other TUs), so we control their
//!     layout. `base` is first in each so the C-style subclassing
//!     (vtab*<->table*, cursor*<->Fts3auxCursor*) is sound.
//!
//!   * ABI-SHARED fts3 structs — `Fts3Table`, `Fts3MultiSegReader`,
//!     `Fts3SegFilter`. fts3_aux ALLOCATES an `Fts3Table` (inline, right after
//!     the `Fts3auxTable`) and hands pointers into it to still-C fts3 TUs
//!     (fts3_write.c's sqlite3Fts3SegReader* etc.). We therefore mirror these
//!     `extern struct` field-for-field from fts3Int.h. We only read/write the
//!     handful of fields fts3_aux itself uses and let the C helpers own the
//!     rest; correctness requires only that the SIZE and the offsets of the
//!     fields the C helpers read match.
//!
//! `Fts3Table` is the one config-divergent struct: it has trailing fields that
//! exist only under SQLITE_DEBUG / SQLITE_TEST (the --dev testfixture build).
//! Because the C code allocates `sizeof(Fts3Table)` bytes and the C helpers in
//! the still-C fts3 TUs reference those trailing fields, the Zig mirror must
//! reproduce them under the same configuration. We gate them with
//! `@import("config")` (`sqlite_debug` / `sqlite_test`), exactly as the C `-D`
//! flags do, so the size matches in both the production and testfixture builds.
//! No c_layout / tools/offsets.c entry is needed: every field we touch is a
//! leading field whose offset is config-invariant, and we never index into the
//! opaque `sqlite3` connection.
//!
//! Validated end-to-end by the engine via the upstream fts3aux tests
//! (test/fts3aux*.test) rather than a Zig unit test: every path needs a live
//! FTS3 table, segment readers, and the VDBE, so there is nothing
//! self-contained to exercise here.

const std = @import("std");
const config = @import("config");

// --- Result codes (sqlite3.h) ---
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_ROW: c_int = 100;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CORRUPT_VTAB: c_int = 11 | (1 << 8); // SQLITE_CORRUPT | (1<<8)

// --- Constraint operators (sqlite3.h) ---
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_INDEX_CONSTRAINT_GT: u8 = 4;
const SQLITE_INDEX_CONSTRAINT_LE: u8 = 8;
const SQLITE_INDEX_CONSTRAINT_LT: u8 = 16;
const SQLITE_INDEX_CONSTRAINT_GE: u8 = 32;

// --- Destructor sentinels (sqlite3.h): SQLITE_STATIC==0, SQLITE_TRANSIENT==-1.
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;
const SQLITE_TRANSIENT: DestructorFn = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// --- fts3 segment / filter flags (fts3Int.h) ---
const FTS3_SEGCURSOR_ALL: c_int = -2;
const FTS3_SEGMENT_REQUIRE_POS: c_int = 0x00000001;
const FTS3_SEGMENT_IGNORE_EMPTY: c_int = 0x00000002;
const FTS3_SEGMENT_SCAN: c_int = 0x00000010;

// --- idxNum strategy bits (fts3_aux.c) ---
const FTS4AUX_EQ_CONSTRAINT: c_int = 1;
const FTS4AUX_GE_CONSTRAINT: c_int = 2;
const FTS4AUX_LE_CONSTRAINT: c_int = 4;

const FTS3_AUX_SCHEMA =
    "CREATE TABLE x(term, col, documents, occurrences, languageid HIDDEN)";

// --- Public ABI opaque handles (sqlite3.h) ---
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;
const sqlite3_blob = anyopaque;
const sqlite3_tokenizer = anyopaque;

// --- Scalar typedefs mirroring fts3Int.h / sqliteInt.h ---
const u8_t = u8;
const u32_t = u32;
const i64_t = i64;

// --- Public ABI structs (sqlite3.h) ---

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
    // Inputs
    nConstraint: c_int,
    aConstraint: ?[*]sqlite3_index_constraint,
    nOrderBy: c_int,
    aOrderBy: ?[*]sqlite3_index_orderby,
    // Outputs
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
/// for field (mirrored exactly as in src/carray.zig).
const sqlite3_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int,
    xConnect: ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int,
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
    xUpdate: ?*const anyopaque,
    xBegin: ?*const anyopaque,
    xSync: ?*const anyopaque,
    xCommit: ?*const anyopaque,
    xRollback: ?*const anyopaque,
    xFindFunction: ?*const anyopaque,
    xRename: ?*const anyopaque,
    // version 2+
    xSavepoint: ?*const anyopaque,
    xRelease: ?*const anyopaque,
    xRollbackTo: ?*const anyopaque,
    // version 3+
    xShadowName: ?*const anyopaque,
    // version 4+
    xIntegrity: ?*const anyopaque,
};

// --- ABI-SHARED fts3 structs (fts3Int.h) ---
//
// These must match the C layout exactly because pointers into them are handed
// to still-C fts3 TUs. We only TOUCH the leading/named fields fts3_aux uses; the
// remainder exist to make sizeof() and the C helpers' field offsets correct.

/// fts3Int.h: struct Fts3Index (only ever referenced via a pointer in
/// Fts3Table, so its presence below is for documentation; layout irrelevant to
/// Fts3Table's size). Mirrored opaque via pointer.
const Fts3Index = opaque {};

const Fts3Table = extern struct {
    base: sqlite3_vtab, // Base class used by SQLite core
    db: ?*sqlite3, // The database connection
    zDb: ?[*:0]const u8, // logical database name
    zName: ?[*:0]const u8, // virtual table name
    nColumn: c_int, // number of named columns in virtual table
    azColumn: ?[*]?[*:0]u8, // column names. malloced
    abNotindexed: ?[*]u8, // True for 'notindexed' columns
    pTokenizer: ?*sqlite3_tokenizer, // tokenizer for inserts and queries
    zContentTbl: ?[*:0]u8, // content=xxx option, or NULL
    zLanguageid: ?[*:0]u8, // languageid=xxx option, or NULL
    nAutoincrmerge: c_int, // Value configured by 'automerge'
    nLeafAdd: u32_t, // Number of leaf blocks added this trans
    bLock: c_int, // Used to prevent recursive content= tbls

    // Precompiled statements used by the implementation.
    aStmt: [40]?*sqlite3_stmt,
    pSeekStmt: ?*sqlite3_stmt, // Cache for fts3CursorSeekStmt()

    zReadExprlist: ?[*:0]u8,
    zWriteExprlist: ?[*:0]u8,

    nNodeSize: c_int, // Soft limit for node size
    bFts4: u8_t, // True for FTS4, false for FTS3
    bHasStat: u8_t, // True if %_stat table exists (2==unknown)
    bHasDocsize: u8_t, // True if %_docsize table exists
    bDescIdx: u8_t, // True if doclists are in reverse order
    bIgnoreSavepoint: u8_t, // True to ignore xSavepoint invocations
    nPgsz: c_int, // Page size for host database
    zSegmentsTbl: ?[*:0]u8, // Name of %_segments table
    pSegments: ?*sqlite3_blob, // Blob handle open on %_segments table
    iSavepoint: c_int,

    nIndex: c_int, // Size of aIndex[]
    aIndex: ?*Fts3Index, // array of per-index pending-term hash tables
    nMaxPendingData: c_int, // Max pending data before flush to disk
    nPendingData: c_int, // Current bytes of pending data
    iPrevDocid: i64_t, // Docid of most recently inserted document
    iPrevLangid: c_int, // Langid of recently inserted document
    bPrevDelete: c_int, // True if last operation was a delete

    // Trailing fields gated by build configuration. These exist ONLY in the
    // --dev testfixture build (SQLITE_DEBUG / SQLITE_COVERAGE_TEST and
    // SQLITE_DEBUG / SQLITE_TEST). They must be present iff the C fts3 TUs were
    // compiled with the same flags, so that sizeof() and the offsets the C
    // helpers use agree. SQLITE_COVERAGE_TEST is not set in this build, so the
    // first block tracks sqlite_debug; the second tracks sqlite_debug ||
    // sqlite_test.
    inTransaction: if (config.sqlite_debug) c_int else void =
        if (config.sqlite_debug) 0 else {},
    mxSavepoint: if (config.sqlite_debug) c_int else void =
        if (config.sqlite_debug) 0 else {},
    bNoIncrDoclist: if (config.sqlite_debug or config.sqlite_test) c_int else void =
        if (config.sqlite_debug or config.sqlite_test) 0 else {},
    nMergeCount: if (config.sqlite_debug or config.sqlite_test) c_int else void =
        if (config.sqlite_debug or config.sqlite_test) 0 else {},
};

const Fts3SegFilter = extern struct {
    zTerm: ?[*:0]const u8,
    nTerm: c_int,
    iCol: c_int,
    flags: c_int,
};

const Fts3MultiSegReader = extern struct {
    // Used internally by sqlite3Fts3SegReaderXXX() calls
    apSegment: ?*anyopaque, // Array of Fts3SegReader objects
    nSegment: c_int,
    nAdvance: c_int,
    pFilter: ?*Fts3SegFilter,
    aBuffer: ?[*]u8,
    nBuffer: i64_t,

    iColFilter: c_int,
    bRestart: c_int,

    // Used by fts3.c only.
    nCost: c_int,
    bLookup: c_int,

    // Output values. Valid only after Fts3SegReaderStep() returns SQLITE_ROW.
    zTerm: ?[*]u8, // Pointer to term buffer
    nTerm: c_int, // Size of zTerm in bytes
    aDoclist: ?[*]u8, // Pointer to doclist buffer
    nDoclist: c_int, // Size of aDoclist[] in bytes
};

// --- This module's OWN (private-layout) structs ---

const Fts3auxColstats = extern struct {
    nDoc: i64_t, // 'documents' values for current csr row
    nOcc: i64_t, // 'occurrences' values for current csr row
};

const Fts3auxTable = extern struct {
    base: sqlite3_vtab, // Base class used by SQLite core (must be first)
    pFts3Tab: ?*Fts3Table,
};

const Fts3auxCursor = extern struct {
    base: sqlite3_vtab_cursor, // Base class used by SQLite core (must be first)
    csr: Fts3MultiSegReader, // Must be right after "base"
    filter: Fts3SegFilter,
    zStop: ?[*:0]u8,
    nStop: c_int, // Byte-length of string zStop
    iLangid: c_int, // Language id to query
    isEof: c_int, // True if cursor is at EOF
    iRowid: i64_t, // Current rowid

    iCol: c_int, // Current value of 'col' column
    nStat: c_int, // Size of aStat[] array
    aStat: ?[*]Fts3auxColstats,
};

// --- Public sqlite3 API resolved at link time ---
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_strnicmp(a: [*:0]const u8, b: [*:0]const u8, n: c_int) c_int;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_create_module(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pAux: ?*anyopaque) c_int;

extern fn sqlite3_value_text(p: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_int(p: ?*sqlite3_value) c_int;

extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;
extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_int64(ctx: ?*sqlite3_context, v: i64) void;

// --- Internal fts3 helpers resolved at link time (still-C fts3 TUs) ---
extern fn sqlite3Fts3Dequote(z: [*:0]u8) void;
extern fn sqlite3Fts3ErrMsg(pzErr: *?[*:0]u8, fmt: [*:0]const u8, ...) void;
extern fn sqlite3Fts3SegmentsClose(p: *Fts3Table) void;
extern fn sqlite3Fts3SegReaderFinish(pCsr: *Fts3MultiSegReader) void;
extern fn sqlite3Fts3GetVarint(p: [*]const u8, v: *i64) c_int;
extern fn sqlite3Fts3SegReaderStep(p: *Fts3Table, pCsr: *Fts3MultiSegReader) c_int;
extern fn sqlite3Fts3SegReaderCursor(
    p: *Fts3Table,
    iLangid: c_int,
    iIndex: c_int,
    iLevel: c_int,
    zTerm: ?[*:0]const u8,
    nTerm: c_int,
    isPrefix: c_int,
    isScan: c_int,
    pCsr: *Fts3MultiSegReader,
) c_int;
extern fn sqlite3Fts3SegReaderStart(p: *Fts3Table, pCsr: *Fts3MultiSegReader, pFilter: *Fts3SegFilter) c_int;

extern fn strlen(s: [*:0]const u8) usize;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

/// xConnect / xCreate. fts4aux has no persistent representation so the two are
/// identical. Allocates the Fts3auxTable with an inline Fts3Table and the two
/// name strings packed after it, exactly as the C code does.
fn fts3auxConnectMethod(
    db: ?*sqlite3,
    pUnused: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    _ = pUnused;
    const av = argv.?;

    // The user invokes this in one of two forms:
    //   CREATE VIRTUAL TABLE xxx USING fts4aux(fts4-table);
    //   CREATE VIRTUAL TABLE xxx USING fts4aux(fts4-table-db, fts4-table);
    if (argc != 4 and argc != 5) return badArgs(pzErr);

    var zDb: [*:0]const u8 = av[1].?;
    var nDb: c_int = @intCast(strlen(zDb));
    var zFts3: [*:0]const u8 = undefined;
    if (argc == 5) {
        if (nDb == 4 and sqlite3_strnicmp("temp", zDb, 4) == 0) {
            zDb = av[3].?;
            nDb = @intCast(strlen(zDb));
            zFts3 = av[4].?;
        } else {
            return badArgs(pzErr);
        }
    } else {
        zFts3 = av[3].?;
    }
    const nFts3: c_int = @intCast(strlen(zFts3));

    const rc = sqlite3_declare_vtab(db, FTS3_AUX_SCHEMA);
    if (rc != SQLITE_OK) return rc;

    const nByte: u64 = @sizeOf(Fts3auxTable) + @sizeOf(Fts3Table) +
        @as(u64, @intCast(nDb)) + @as(u64, @intCast(nFts3)) + 2;
    const raw = sqlite3_malloc64(nByte) orelse return SQLITE_NOMEM;
    const bytes: [*]u8 = @ptrCast(raw);
    @memset(bytes[0..@intCast(nByte)], 0);

    const p: *Fts3auxTable = @ptrCast(@alignCast(raw));
    // pFts3Tab = (Fts3Table *)&p[1];
    const pFts3: *Fts3Table = @ptrCast(@alignCast(bytes + @sizeOf(Fts3auxTable)));
    p.pFts3Tab = pFts3;

    // zDb = (char *)&pFts3[1];   zName = &zDb[nDb+1];
    const strBase: [*]u8 = bytes + @sizeOf(Fts3auxTable) + @sizeOf(Fts3Table);
    const pzDb: [*:0]u8 = @ptrCast(strBase);
    const pzName: [*:0]u8 = @ptrCast(strBase + @as(usize, @intCast(nDb)) + 1);
    pFts3.zDb = pzDb;
    pFts3.zName = pzName;
    pFts3.db = db;
    pFts3.nIndex = 1;

    @memcpy(pzDb[0..@intCast(nDb)], zDb[0..@intCast(nDb)]);
    @memcpy(pzName[0..@intCast(nFts3)], zFts3[0..@intCast(nFts3)]);
    sqlite3Fts3Dequote(pzName);

    ppVtab.* = @ptrCast(p);
    return SQLITE_OK;
}

inline fn badArgs(pzErr: *?[*:0]u8) c_int {
    sqlite3Fts3ErrMsg(pzErr, "invalid arguments to fts4aux constructor");
    return SQLITE_ERROR;
}

/// xDisconnect / xDestroy.
fn fts3auxDisconnectMethod(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    const p: *Fts3auxTable = @ptrCast(@alignCast(pVtab));
    const pFts3 = p.pFts3Tab.?;
    // Free any prepared statements held.
    for (&pFts3.aStmt) |stmt| {
        _ = sqlite3_finalize(stmt);
    }
    sqlite3_free(pFts3.zSegmentsTbl);
    sqlite3_free(p);
    return SQLITE_OK;
}

/// xBestIndex - Analyze a WHERE and ORDER BY clause.
fn fts3auxBestIndexMethod(pVTab: *sqlite3_vtab, pInfo: *sqlite3_index_info) callconv(.c) c_int {
    _ = pVTab;
    var iEq: c_int = -1;
    var iGe: c_int = -1;
    var iLe: c_int = -1;
    var iLangid: c_int = -1;
    var iNext: c_int = 1; // Next free argvIndex value

    // This vtab delivers always results in "ORDER BY term ASC" order.
    if (pInfo.nOrderBy == 1 and pInfo.aOrderBy.?[0].iColumn == 0 and pInfo.aOrderBy.?[0].desc == 0) {
        pInfo.orderByConsumed = 1;
    }

    // Equality / range constraints on "term" (col 0), equality on "languageid"
    // (col 4).
    const aConstraint = pInfo.aConstraint.?;
    var i: c_int = 0;
    while (i < pInfo.nConstraint) : (i += 1) {
        const con = &aConstraint[@intCast(i)];
        if (con.usable != 0) {
            const op = con.op;
            const iCol = con.iColumn;
            if (iCol == 0) {
                if (op == SQLITE_INDEX_CONSTRAINT_EQ) iEq = i;
                if (op == SQLITE_INDEX_CONSTRAINT_LT) iLe = i;
                if (op == SQLITE_INDEX_CONSTRAINT_LE) iLe = i;
                if (op == SQLITE_INDEX_CONSTRAINT_GT) iGe = i;
                if (op == SQLITE_INDEX_CONSTRAINT_GE) iGe = i;
            }
            if (iCol == 4) {
                if (op == SQLITE_INDEX_CONSTRAINT_EQ) iLangid = i;
            }
        }
    }

    const aUsage = pInfo.aConstraintUsage.?;
    if (iEq >= 0) {
        pInfo.idxNum = FTS4AUX_EQ_CONSTRAINT;
        aUsage[@intCast(iEq)].argvIndex = iNext;
        iNext += 1;
        pInfo.estimatedCost = 5;
    } else {
        pInfo.idxNum = 0;
        pInfo.estimatedCost = 20000;
        if (iGe >= 0) {
            pInfo.idxNum += FTS4AUX_GE_CONSTRAINT;
            aUsage[@intCast(iGe)].argvIndex = iNext;
            iNext += 1;
            pInfo.estimatedCost /= 2;
        }
        if (iLe >= 0) {
            pInfo.idxNum += FTS4AUX_LE_CONSTRAINT;
            aUsage[@intCast(iLe)].argvIndex = iNext;
            iNext += 1;
            pInfo.estimatedCost /= 2;
        }
    }
    if (iLangid >= 0) {
        aUsage[@intCast(iLangid)].argvIndex = iNext;
        iNext += 1;
        pInfo.estimatedCost -= 1;
    }

    return SQLITE_OK;
}

/// xOpen - Open a cursor.
fn fts3auxOpenMethod(pVTab: *sqlite3_vtab, ppCsr: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    _ = pVTab;
    const raw = sqlite3_malloc(@sizeOf(Fts3auxCursor)) orelse return SQLITE_NOMEM;
    const pCsr: *Fts3auxCursor = @ptrCast(@alignCast(raw));
    pCsr.* = std.mem.zeroes(Fts3auxCursor);
    ppCsr.* = &pCsr.base;
    return SQLITE_OK;
}

/// xClose - Close a cursor.
fn fts3auxCloseMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pTab: *Fts3auxTable = @ptrCast(@alignCast(pCursor.pVtab.?));
    const pFts3 = pTab.pFts3Tab.?;
    const pCsr: *Fts3auxCursor = @ptrCast(@alignCast(pCursor));

    sqlite3Fts3SegmentsClose(pFts3);
    sqlite3Fts3SegReaderFinish(&pCsr.csr);
    sqlite3_free(@constCast(@ptrCast(pCsr.filter.zTerm)));
    sqlite3_free(pCsr.zStop);
    sqlite3_free(pCsr.aStat);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

fn fts3auxGrowStatArray(pCsr: *Fts3auxCursor, nSize: c_int) c_int {
    if (nSize > pCsr.nStat) {
        const aNew: ?[*]Fts3auxColstats = @ptrCast(@alignCast(sqlite3_realloc64(
            pCsr.aStat,
            @sizeOf(Fts3auxColstats) * @as(u64, @intCast(nSize)),
        )));
        if (aNew == null) return SQLITE_NOMEM;
        const a = aNew.?;
        const oldN: usize = @intCast(pCsr.nStat);
        const newN: usize = @intCast(nSize);
        @memset(std.mem.sliceAsBytes(a[oldN..newN]), 0);
        pCsr.aStat = a;
        pCsr.nStat = nSize;
    }
    return SQLITE_OK;
}

/// xNext - Advance the cursor to the next row, if any.
fn fts3auxNextMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts3auxCursor = @ptrCast(@alignCast(pCursor));
    const pTab: *Fts3auxTable = @ptrCast(@alignCast(pCursor.pVtab.?));
    const pFts3 = pTab.pFts3Tab.?;
    var rc: c_int = SQLITE_OK;

    // Increment our pretend rowid value.
    pCsr.iRowid += 1;

    {
        pCsr.iCol += 1;
        while (pCsr.iCol < pCsr.nStat) : (pCsr.iCol += 1) {
            if (pCsr.aStat.?[@intCast(pCsr.iCol)].nDoc > 0) return SQLITE_OK;
        }
    }

    rc = sqlite3Fts3SegReaderStep(pFts3, &pCsr.csr);
    if (rc == SQLITE_ROW) {
        var i: c_int = 0;
        const nDoclist = pCsr.csr.nDoclist;
        const aDoclist = pCsr.csr.aDoclist.?;
        var iCol: c_int = 0;
        var eState: c_int = 0;

        if (pCsr.zStop) |zStop| {
            const n: c_int = if (pCsr.nStop < pCsr.csr.nTerm) pCsr.nStop else pCsr.csr.nTerm;
            const mc = memcmp(zStop, pCsr.csr.zTerm.?, @intCast(n));
            if (mc < 0 or (mc == 0 and pCsr.csr.nTerm > pCsr.nStop)) {
                pCsr.isEof = 1;
                return SQLITE_OK;
            }
        }

        if (fts3auxGrowStatArray(pCsr, 2) != 0) return SQLITE_NOMEM;
        @memset(std.mem.sliceAsBytes(pCsr.aStat.?[0..@intCast(pCsr.nStat)]), 0);
        iCol = 0;
        rc = SQLITE_OK;

        while (i < nDoclist) {
            var v: i64 = 0;
            i += sqlite3Fts3GetVarint(aDoclist + @as(usize, @intCast(i)), &v);
            switch (eState) {
                // State 0. The integer just read was a docid.
                0 => {
                    pCsr.aStat.?[0].nDoc += 1;
                    eState = 1;
                    iCol = 0;
                },
                // State 1. Expecting either a 1 (column number follows) or the
                // start of a position list for column 0. Differs from state 2
                // only in that a value not 0/1 also bumps column 0's nDoc.
                1 => {
                    // assert(iCol==0)
                    if (v > 1) {
                        pCsr.aStat.?[1].nDoc += 1;
                    }
                    eState = 2;
                    // deliberate fall-through to state 2
                    if (v == 0) {
                        eState = 0;
                    } else if (v == 1) {
                        eState = 3;
                    } else {
                        pCsr.aStat.?[@intCast(iCol + 1)].nOcc += 1;
                        pCsr.aStat.?[0].nOcc += 1;
                    }
                },
                2 => {
                    if (v == 0) { // 0x00. Next integer will be a docid.
                        eState = 0;
                    } else if (v == 1) { // 0x01. Next integer will be a column number.
                        eState = 3;
                    } else { // 2 or greater. A position.
                        pCsr.aStat.?[@intCast(iCol + 1)].nOcc += 1;
                        pCsr.aStat.?[0].nOcc += 1;
                    }
                },
                // State 3. The integer just read is a column number.
                else => {
                    // assert(eState==3)
                    iCol = @intCast(v);
                    if (iCol < 1 or iCol > (pFts3.nColumn + 1)) {
                        rc = SQLITE_CORRUPT_VTAB;
                        break;
                    }
                    if (fts3auxGrowStatArray(pCsr, iCol + 2) != 0) return SQLITE_NOMEM;
                    pCsr.aStat.?[@intCast(iCol + 1)].nDoc += 1;
                    eState = 2;
                },
            }
        }

        pCsr.iCol = 0;
    } else {
        pCsr.isEof = 1;
    }
    return rc;
}

/// xFilter - Initialize a cursor to point at the start of its data.
fn fts3auxFilterMethod(
    pCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    nVal: c_int,
    apVal: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = idxStr;
    const pCsr: *Fts3auxCursor = @ptrCast(@alignCast(pCursor));
    const pTab: *Fts3auxTable = @ptrCast(@alignCast(pCursor.pVtab.?));
    const pFts3 = pTab.pFts3Tab.?;
    var rc: c_int = undefined;
    var isScan: c_int = 0;
    var iLangVal: c_int = 0; // Language id to query

    var iEq: c_int = -1; // Index of term=? value in apVal
    var iGe: c_int = -1; // Index of term>=? value in apVal
    var iLe: c_int = -1; // Index of term<=? value in apVal
    var iLangid: c_int = -1; // Index of languageid=? value in apVal
    var iNext: c_int = 0;

    const av = apVal.?;

    if (idxNum == FTS4AUX_EQ_CONSTRAINT) {
        iEq = iNext;
        iNext += 1;
    } else {
        isScan = 1;
        if (idxNum & FTS4AUX_GE_CONSTRAINT != 0) {
            iGe = iNext;
            iNext += 1;
        }
        if (idxNum & FTS4AUX_LE_CONSTRAINT != 0) {
            iLe = iNext;
            iNext += 1;
        }
    }
    if (iNext < nVal) {
        iLangid = iNext;
        iNext += 1;
    }

    // In case this cursor is being reused, close and zero it.
    sqlite3Fts3SegReaderFinish(&pCsr.csr);
    sqlite3_free(@constCast(@ptrCast(pCsr.filter.zTerm)));
    sqlite3_free(pCsr.aStat);
    sqlite3_free(pCsr.zStop);
    // memset(&pCsr->csr, 0, ((u8*)&pCsr[1]) - (u8*)&pCsr->csr);
    {
        const csrOff = @offsetOf(Fts3auxCursor, "csr");
        const base: [*]u8 = @ptrCast(pCsr);
        @memset(base[csrOff..@sizeOf(Fts3auxCursor)], 0);
    }

    pCsr.filter.flags = FTS3_SEGMENT_REQUIRE_POS | FTS3_SEGMENT_IGNORE_EMPTY;
    if (isScan != 0) pCsr.filter.flags |= FTS3_SEGMENT_SCAN;

    if (iEq >= 0 or iGe >= 0) {
        const zStr = sqlite3_value_text(av[0]);
        // assert((iEq==0 && iGe==-1) || (iEq==-1 && iGe==0))
        if (zStr) |z| {
            pCsr.filter.zTerm = sqlite3_mprintf("%s", z);
            if (pCsr.filter.zTerm == null) return SQLITE_NOMEM;
            pCsr.filter.nTerm = @intCast(strlen(pCsr.filter.zTerm.?));
        }
    }

    if (iLe >= 0) {
        pCsr.zStop = sqlite3_mprintf("%s", sqlite3_value_text(av[@intCast(iLe)]));
        if (pCsr.zStop == null) return SQLITE_NOMEM;
        pCsr.nStop = @intCast(strlen(pCsr.zStop.?));
    }

    if (iLangid >= 0) {
        iLangVal = sqlite3_value_int(av[@intCast(iLangid)]);
        // Negative languageid -> 0 (see upstream comment).
        if (iLangVal < 0) iLangVal = 0;
    }
    pCsr.iLangid = iLangVal;

    rc = sqlite3Fts3SegReaderCursor(pFts3, iLangVal, 0, FTS3_SEGCURSOR_ALL, pCsr.filter.zTerm, pCsr.filter.nTerm, 0, isScan, &pCsr.csr);
    if (rc == SQLITE_OK) {
        rc = sqlite3Fts3SegReaderStart(pFts3, &pCsr.csr, &pCsr.filter);
    }

    if (rc == SQLITE_OK) rc = fts3auxNextMethod(pCursor);
    return rc;
}

/// xEof - Return true if the cursor is at EOF, or false otherwise.
fn fts3auxEofMethod(pCursor: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *Fts3auxCursor = @ptrCast(@alignCast(pCursor));
    return pCsr.isEof;
}

/// xColumn - Return a column value.
fn fts3auxColumnMethod(pCursor: *sqlite3_vtab_cursor, pCtx: ?*sqlite3_context, iCol: c_int) callconv(.c) c_int {
    const p: *Fts3auxCursor = @ptrCast(@alignCast(pCursor));
    // assert(p->isEof==0)
    switch (iCol) {
        0 => { // term
            sqlite3_result_text(pCtx, @ptrCast(p.csr.zTerm), p.csr.nTerm, SQLITE_TRANSIENT);
        },
        1 => { // col
            if (p.iCol != 0) {
                sqlite3_result_int(pCtx, p.iCol - 1);
            } else {
                sqlite3_result_text(pCtx, "*", -1, SQLITE_STATIC);
            }
        },
        2 => { // documents
            sqlite3_result_int64(pCtx, p.aStat.?[@intCast(p.iCol)].nDoc);
        },
        3 => { // occurrences
            sqlite3_result_int64(pCtx, p.aStat.?[@intCast(p.iCol)].nOcc);
        },
        else => { // languageid (iCol==4)
            sqlite3_result_int(pCtx, p.iLangid);
        },
    }
    return SQLITE_OK;
}

/// xRowid - Return the current rowid for the cursor.
fn fts3auxRowidMethod(pCursor: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCsr: *Fts3auxCursor = @ptrCast(@alignCast(pCursor));
    pRowid.* = pCsr.iRowid;
    return SQLITE_OK;
}

const fts3aux_module: sqlite3_module = .{
    .iVersion = 0,
    .xCreate = &fts3auxConnectMethod,
    .xConnect = &fts3auxConnectMethod,
    .xBestIndex = &fts3auxBestIndexMethod,
    .xDisconnect = &fts3auxDisconnectMethod,
    .xDestroy = &fts3auxDisconnectMethod,
    .xOpen = &fts3auxOpenMethod,
    .xClose = &fts3auxCloseMethod,
    .xFilter = &fts3auxFilterMethod,
    .xNext = &fts3auxNextMethod,
    .xEof = &fts3auxEofMethod,
    .xColumn = &fts3auxColumnMethod,
    .xRowid = &fts3auxRowidMethod,
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

/// Register the fts3aux module with database connection db. Returns SQLITE_OK if
/// successful or an error code if sqlite3_create_module() fails.
export fn sqlite3Fts3InitAux(db: ?*sqlite3) callconv(.c) c_int {
    return sqlite3_create_module(db, "fts4aux", &fts3aux_module, null);
}
