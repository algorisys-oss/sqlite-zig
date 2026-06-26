//! Zig port of SQLite's bytecode introspection virtual tables (src/vdbevtab.c).
//!
//! Implements the `bytecode()` and `tables_used()` eponymous table-valued
//! functions, which expose the VDBE bytecode of a prepared statement as rows.
//! Drop-in replacement exporting the single internal entry point
//! `sqlite3VdbeBytecodeVtabInit` (called from main.c's built-in-extension
//! table). Compiled because SQLITE_ENABLE_BYTECODE_VTAB is defined in BOTH this
//! project's `zig build` (build.zig sqlite_flags) and the `--dev` testfixture
//! (TESTFIXTURE_FLAGS). SQLITE_OMIT_VIRTUALTABLE is OFF in both, so the full
//! implementation (not the `#elif` stub) is the one we port.
//!
//! ---------------------------------------------------------------------------
//! Config divergence and ground-truth offsets
//! ---------------------------------------------------------------------------
//! This module reaches into several internal core structs (Op/VdbeOp, sqlite3,
//! Db, Schema, Hash, HashElem, Table, Index) to render the bytecode rows. Those
//! structs CAN differ in layout between the production library config and the
//! SQLITE_DEBUG testfixture config. However, every field this module reads was
//! verified (via a probe compiled in both configs) to sit at an IDENTICAL
//! offset in both, because the only config-divergent (SQLITE_DEBUG-only)
//! members of these structs fall *after* the fields we touch. So all the
//! offsets below are config-INVARIANT; they are still routed through
//! @import("c_layout.zig") with a comptime probe-number fallback (the printf.zig
//! / vdbetrace.zig idiom) so that if the orchestrator adds them to
//! tools/offsets.c they get authoritative values, and otherwise the verified
//! probe numbers are used.
//!
//! Two compile-time feature flags drive which `case` arms are emitted:
//!   * SQLITE_ENABLE_EXPLAIN_COMMENTS: ON in BOTH configs. In `zig build` it is
//!     passed explicitly (build.zig). In the testfixture it is implied: SQLite's
//!     sqliteInt.h does `#if !defined(...EXPLAIN_COMMENTS) && defined(DEBUG)
//!     => define EXPLAIN_COMMENTS`. So case 7 ("comment") always renders a real
//!     comment via sqlite3VdbeDisplayComment(). We therefore always emit it.
//!   * SQLITE_ENABLE_STMT_SCANSTATUS: OFF in BOTH configs (absent from build.zig
//!     and from the --dev OPT_FEATURE_FLAGS / TESTFIXTURE_FLAGS). So Op carries
//!     no nExec/nCycle members, and cases 9/10 (nexec/ncycle) return int 0 —
//!     matching the C `#else` arm. We hardcode that arm.
//!
//! ---------------------------------------------------------------------------
//! Structs we own vs structs we mirror
//! ---------------------------------------------------------------------------
//! bytecodevtab / bytecodevtab_cursor are THIS module's own structs (C-style
//! subclassing: base class first), so we control their layout. We mirror them as
//! `extern struct` so the sqlite3_malloc() sizes match the C byte-for-byte. The
//! cursor embeds a `Mem sub` whose size is config-divergent (56 prod / 72 tf);
//! we size it with a trailing padding array driven by L.sizeof_Mem and never
//! interpret its bytes from Zig — it is only ever handed to the C
//! sqlite3VdbeMem* helpers and to sqlite3VdbeNextOpcode.
//!
//! The public ABI structs (sqlite3_vtab, sqlite3_module, sqlite3_index_info,
//! ...) are mirrored exactly as in src/stmt.zig / src/carray.zig.
//!
//! No standalone Zig unit test is feasible: every path needs a live connection,
//! a compiled Vdbe, the schema hashes and the VDBE display helpers. Validated
//! end-to-end through the engine (upstream test/bytecodevtab.test under the
//! testfixture).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// --- Result codes / type codes (sqlite3.h) ---
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_TEXT: c_int = 3;

// --- xBestIndex constraint op codes (sqlite3.h) ---
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_INDEX_CONSTRAINT_ISNULL: u8 = 71;

// --- Opcodes (opcodes.h) ---
const OP_Init: u8 = 8;
const OP_OpenWrite: u8 = 116;

// --- Destructor sentinels (sqlite3.h) ---
const DestructorFn = ?*const fn (?*anyopaque) callconv(.c) void;
const SQLITE_STATIC: DestructorFn = null;

// --- Public ABI opaque handles ---
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_value = anyopaque;

// ===========================================================================
// Public ABI structs (sqlite3.h) — mirrored exactly (cf. src/stmt.zig).
// ===========================================================================

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

// ===========================================================================
// Ground-truth offsets (config-INVARIANT; verified in both configs).
// c_layout fallback idiom (cf. printf.zig / vdbetrace.zig).
// ===========================================================================

// struct VdbeOp (a.k.a. Op) — opcode(u8)@0, p4type(i8)@1, p5(u16)@2,
// p1(int)@4, p2(int)@8, p3(int)@12, p4(union ptr)@16. sizeof==32 (with
// EXPLAIN_COMMENTS's zComment trailing; SCANSTATUS off).
const Op_opcode: usize = if (@hasDecl(L, "VdbeOp_opcode")) L.VdbeOp_opcode else 0;
const Op_p5: usize = if (@hasDecl(L, "VdbeOp_p5")) L.VdbeOp_p5 else 2;
const Op_p1: usize = if (@hasDecl(L, "VdbeOp_p1")) L.VdbeOp_p1 else 4;
const Op_p2: usize = if (@hasDecl(L, "VdbeOp_p2")) L.VdbeOp_p2 else 8;
const Op_p3: usize = if (@hasDecl(L, "VdbeOp_p3")) L.VdbeOp_p3 else 12;
const Op_p4: usize = if (@hasDecl(L, "VdbeOp_p4")) L.VdbeOp_p4 else 16;
const sizeof_Op: usize = if (@hasDecl(L, "sizeof_VdbeOp")) L.sizeof_VdbeOp else 32;

// struct sqlite3: aDb (Db*) @ 32. (config-invariant for this field)
const sqlite3_aDb: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;

// struct Db: zDbSName(char*)@0, pSchema(Schema*)@24, sizeof==32.
const Db_zDbSName: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pSchema: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

// struct Schema: tblHash@8, idxHash@32 (each is a Hash).
const Schema_tblHash: usize = if (@hasDecl(L, "Schema_tblHash")) L.Schema_tblHash else 8;
const Schema_idxHash: usize = if (@hasDecl(L, "Schema_idxHash")) L.Schema_idxHash else 32;

// struct Hash: first(HashElem*)@8.
const Hash_first: usize = if (@hasDecl(L, "Hash_first")) L.Hash_first else 8;

// struct HashElem: next(HashElem*)@0, data(void*)@16.
const HashElem_next: usize = if (@hasDecl(L, "HashElem_next")) L.HashElem_next else 0;
const HashElem_data: usize = if (@hasDecl(L, "HashElem_data")) L.HashElem_data else 16;

// struct Table: zName(char*)@0, tnum(Pgno=u32)@40, eTabType(u8)@63.
const Table_zName: usize = if (@hasDecl(L, "Table_zName")) L.Table_zName else 0;
const Table_tnum: usize = if (@hasDecl(L, "Table_tnum")) L.Table_tnum else 40;
const Table_eTabType: usize = if (@hasDecl(L, "Table_eTabType")) L.Table_eTabType else 63;

// struct Index: zName(char*)@0, tnum(Pgno=u32)@88.
const Index_zName: usize = if (@hasDecl(L, "Index_zName")) L.Index_zName else 0;
const Index_tnum: usize = if (@hasDecl(L, "Index_tnum")) L.Index_tnum else 88;

// Table.eTabType allowed value (sqliteInt.h): TABTYP_VTAB==1.
const TABTYP_VTAB: u8 = 1;

// ---- typed field readers over opaque pointers ----
inline fn fieldPtr(comptime T: type, base: ?*const anyopaque, off: usize) *const T {
    const p: [*]const u8 = @ptrCast(base.?);
    return @ptrCast(@alignCast(p + off));
}
inline fn rdU8(base: ?*const anyopaque, off: usize) u8 {
    const p: [*]const u8 = @ptrCast(base.?);
    return p[off];
}
inline fn rdInt(base: ?*const anyopaque, off: usize) c_int {
    return fieldPtr(c_int, base, off).*;
}
inline fn rdU32(base: ?*const anyopaque, off: usize) u32 {
    return fieldPtr(u32, base, off).*;
}
inline fn rdPtr(base: ?*const anyopaque, off: usize) ?*anyopaque {
    return fieldPtr(?*anyopaque, base, off).*;
}

// ===========================================================================
// This module's own structs (we own their layout). `Mem sub` is sized via a
// raw byte buffer so its config-divergent sizeof is honored.
// ===========================================================================

const Mem_bytes = L.sizeof_Mem; // 56 prod / 72 tf
const MemBuf = extern struct { raw: [Mem_bytes]u8 align(8) };

const bytecodevtab = extern struct {
    base: sqlite3_vtab, // Base class - must be first
    db: ?*sqlite3, // Database connection
    bTablesUsed: c_int, // 2 for tables_used(); 0 for bytecode()
};

const bytecodevtab_cursor = extern struct {
    base: sqlite3_vtab_cursor, // Base class - must be first
    pStmt: ?*sqlite3_stmt, // The statement whose bytecode is displayed
    iRowid: c_int, // The rowid of the output table
    iAddr: c_int, // Address
    needFinalize: c_int, // Cursor owns pStmt and must finalize it
    showSubprograms: c_int, // Provide a listing of subprograms
    aOp: ?*anyopaque, // Op* — operand array
    zP4: ?[*:0]u8, // Rendered P4 value
    zType: ?[*:0]const u8, // tables_used.type
    zSchema: ?[*:0]const u8, // tables_used.schema
    zName: ?[*:0]const u8, // tables_used.name
    sub: MemBuf, // Mem — subprograms
};

// ===========================================================================
// External C symbols resolved at link time.
// ===========================================================================

// Public API
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_declare_vtab(db: ?*sqlite3, zSQL: [*:0]const u8) c_int;
extern fn sqlite3_create_module(db: ?*sqlite3, zName: [*:0]const u8, p: *const sqlite3_module, pClientData: ?*anyopaque) c_int;
extern fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_prepare_v2(db: ?*sqlite3, zSql: [*]const u8, nByte: c_int, ppStmt: *?*sqlite3_stmt, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_value_type(v: ?*sqlite3_value) c_int;
extern fn sqlite3_value_text(v: ?*sqlite3_value) ?[*:0]const u8;
extern fn sqlite3_value_pointer(v: ?*sqlite3_value, zType: [*:0]const u8) ?*anyopaque;
extern fn sqlite3_result_int(ctx: ?*sqlite3_context, v: c_int) void;
extern fn sqlite3_result_text(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int, xDel: DestructorFn) void;

// Internal helpers (vdbeInt.h / hash.h)
extern fn sqlite3VdbeMemInit(p: *MemBuf, db: ?*sqlite3, flags: u16) void;
extern fn sqlite3VdbeMemRelease(p: *MemBuf) void;
extern fn sqlite3VdbeMemSetNull(p: *MemBuf) void;
extern fn sqlite3VdbeNextOpcode(
    p: ?*anyopaque, // Vdbe*
    pSub: ?*MemBuf, // Mem*
    bTablesUsed: c_int,
    piRowid: *c_int,
    piAddr: *c_int,
    paOp: *?*anyopaque, // Op**
) c_int;
extern fn sqlite3VdbeDisplayP4(db: ?*sqlite3, pOp: ?*anyopaque) ?[*:0]u8;
extern fn sqlite3VdbeDisplayComment(db: ?*sqlite3, pOp: ?*anyopaque, zP4: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3OpcodeName(opcode: c_int) ?[*:0]const u8;

// `sqlite3_free` reused as the xDel destructor for the comment text result.
const freeDestructor: DestructorFn = @ptrCast(&sqlite3_free);

// ===========================================================================
// vtab methods
// ===========================================================================

/// Create a new bytecode()/tables_used() table-valued function.
fn bytecodevtabConnect(
    db: ?*sqlite3,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?[*]const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    _ = argc;
    _ = argv;
    _ = pzErr;
    const isTabUsed: c_int = @intFromBool(pAux != null);

    const azSchema = [2][*:0]const u8{
        // bytecode() schema
        "CREATE TABLE x(" ++
            "addr INT," ++
            "opcode TEXT," ++
            "p1 INT," ++
            "p2 INT," ++
            "p3 INT," ++
            "p4 TEXT," ++
            "p5 INT," ++
            "comment TEXT," ++
            "subprog TEXT," ++
            "nexec INT," ++
            "ncycle INT," ++
            "stmt HIDDEN" ++
            ");",
        // tables_used() schema
        "CREATE TABLE x(" ++
            "type TEXT," ++
            "schema TEXT," ++
            "name TEXT," ++
            "wr INT," ++
            "subprog TEXT," ++
            "stmt HIDDEN" ++
            ");",
    };

    const rc = sqlite3_declare_vtab(db, azSchema[@intCast(isTabUsed)]);
    if (rc == SQLITE_OK) {
        const pNew: ?*bytecodevtab = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(bytecodevtab))));
        ppVtab.* = @ptrCast(pNew);
        if (pNew == null) return SQLITE_NOMEM;
        pNew.?.* = std.mem.zeroes(bytecodevtab);
        pNew.?.db = db;
        pNew.?.bTablesUsed = isTabUsed * 2;
    }
    return rc;
}

/// Destructor for bytecodevtab objects.
fn bytecodevtabDisconnect(pVtab: *sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

/// Constructor for a new bytecodevtab_cursor object.
fn bytecodevtabOpen(p: *sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pVTab: *bytecodevtab = @ptrCast(@alignCast(p));
    const pCur: ?*bytecodevtab_cursor = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(bytecodevtab_cursor))));
    if (pCur == null) return SQLITE_NOMEM;
    pCur.?.* = std.mem.zeroes(bytecodevtab_cursor);
    sqlite3VdbeMemInit(&pCur.?.sub, pVTab.db, 1);
    ppCursor.* = &pCur.?.base;
    return SQLITE_OK;
}

/// Clear all internal content from a bytecodevtab cursor.
fn bytecodevtabCursorClear(pCur: *bytecodevtab_cursor) void {
    sqlite3_free(pCur.zP4);
    pCur.zP4 = null;
    sqlite3VdbeMemRelease(&pCur.sub);
    sqlite3VdbeMemSetNull(&pCur.sub);
    if (pCur.needFinalize != 0) {
        _ = sqlite3_finalize(pCur.pStmt);
    }
    pCur.pStmt = null;
    pCur.needFinalize = 0;
    pCur.zType = null;
    pCur.zSchema = null;
    pCur.zName = null;
}

/// Destructor for a bytecodevtab_cursor.
fn bytecodevtabClose(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: *bytecodevtab_cursor = @ptrCast(@alignCast(cur));
    bytecodevtabCursorClear(pCur);
    sqlite3_free(cur);
    return SQLITE_OK;
}

/// Advance a bytecodevtab_cursor to its next row of output.
fn bytecodevtabNext(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: *bytecodevtab_cursor = @ptrCast(@alignCast(cur));
    const pTab: *bytecodevtab = @ptrCast(@alignCast(cur.pVtab.?));
    if (pCur.zP4 != null) {
        sqlite3_free(pCur.zP4);
        pCur.zP4 = null;
    }
    if (pCur.zName != null) {
        pCur.zName = null;
        pCur.zType = null;
        pCur.zSchema = null;
    }
    const rc = sqlite3VdbeNextOpcode(
        pCur.pStmt, // (Vdbe*)pCur->pStmt
        if (pCur.showSubprograms != 0) &pCur.sub else null,
        pTab.bTablesUsed,
        &pCur.iRowid,
        &pCur.iAddr,
        &pCur.aOp,
    );
    if (rc != SQLITE_OK) {
        sqlite3VdbeMemSetNull(&pCur.sub);
        pCur.aOp = null;
    }
    return SQLITE_OK;
}

/// True once the cursor has moved off the last row of output.
fn bytecodevtabEof(cur: *sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCur: *bytecodevtab_cursor = @ptrCast(@alignCast(cur));
    return @intFromBool(pCur.aOp == null);
}

/// Return values of columns for the current row.
fn bytecodevtabColumn(
    cur: *sqlite3_vtab_cursor,
    ctx: ?*sqlite3_context,
    i_in: c_int,
) callconv(.c) c_int {
    const pCur: *bytecodevtab_cursor = @ptrCast(@alignCast(cur));
    const pVTab: *bytecodevtab = @ptrCast(@alignCast(cur.pVtab.?));
    var i = i_in;

    // pOp = pCur->aOp + pCur->iAddr  (Op* pointer arithmetic, stride sizeof(Op))
    const aOpBase: [*]u8 = @ptrCast(pCur.aOp.?);
    const pOp: ?*anyopaque = aOpBase + @as(usize, @intCast(pCur.iAddr)) * sizeof_Op;

    if (pVTab.bTablesUsed != 0) {
        if (i == 4) {
            i = 8;
        } else {
            if (i <= 2 and pCur.zType == null) {
                const iDb = rdInt(pOp, Op_p3);
                const iRoot: u32 = @bitCast(rdInt(pOp, Op_p2)); // Pgno
                const db = pVTab.db;
                // pSchema = db->aDb[iDb].pSchema
                const aDb = rdPtr(db, sqlite3_aDb).?;
                const dbEnt: [*]u8 = @ptrCast(aDb);
                const dbRow: ?*anyopaque = dbEnt + @as(usize, @intCast(iDb)) * sizeof_Db;
                const pSchema = rdPtr(dbRow, Db_pSchema);
                pCur.zSchema = @ptrCast(rdPtr(dbRow, Db_zDbSName));

                // Walk tblHash looking for a non-virtual table whose tnum==iRoot.
                var k = rdPtr(@as(?*anyopaque, @ptrCast(@as([*]u8, @ptrCast(pSchema.?)) + Schema_tblHash)), Hash_first);
                while (k != null) : (k = rdPtr(k, HashElem_next)) {
                    const pTab = rdPtr(k, HashElem_data); // Table*
                    const eTabType = rdU8(pTab, Table_eTabType);
                    const isVirtual = eTabType == TABTYP_VTAB;
                    if (!isVirtual and rdU32(pTab, Table_tnum) == iRoot) {
                        pCur.zName = @ptrCast(rdPtr(pTab, Table_zName));
                        pCur.zType = "table";
                        break;
                    }
                }
                if (pCur.zName == null) {
                    var ki = rdPtr(@as(?*anyopaque, @ptrCast(@as([*]u8, @ptrCast(pSchema.?)) + Schema_idxHash)), Hash_first);
                    while (ki != null) : (ki = rdPtr(ki, HashElem_next)) {
                        const pIdx = rdPtr(ki, HashElem_data); // Index*
                        if (rdU32(pIdx, Index_tnum) == iRoot) {
                            pCur.zName = @ptrCast(rdPtr(pIdx, Index_zName));
                            pCur.zType = "index";
                        }
                    }
                }
            }
            i += 20;
        }
    }

    switch (i) {
        0 => sqlite3_result_int(ctx, pCur.iAddr), // addr
        1 => sqlite3_result_text(ctx, sqlite3OpcodeName(rdU8(pOp, Op_opcode)), -1, SQLITE_STATIC), // opcode
        2 => sqlite3_result_int(ctx, rdInt(pOp, Op_p1)), // p1
        3 => sqlite3_result_int(ctx, rdInt(pOp, Op_p2)), // p2
        4 => sqlite3_result_int(ctx, rdInt(pOp, Op_p3)), // p3
        5, 7 => { // p4 / comment
            if (pCur.zP4 == null) {
                pCur.zP4 = sqlite3VdbeDisplayP4(pVTab.db, pOp);
            }
            if (i == 5) {
                sqlite3_result_text(ctx, pCur.zP4, -1, SQLITE_STATIC);
            } else {
                // SQLITE_ENABLE_EXPLAIN_COMMENTS is ON in both configs.
                const zCom = sqlite3VdbeDisplayComment(pVTab.db, pOp, pCur.zP4);
                sqlite3_result_text(ctx, zCom, -1, freeDestructor);
            }
        },
        6 => sqlite3_result_int(ctx, @as(u16, @intCast(rdU16(pOp, Op_p5)))), // p5
        8 => { // subprog
            // aOp[0].opcode==OP_Init; aOp[0].p4.z is the "-- ..." subprog tag.
            const p4z: ?[*:0]const u8 = @ptrCast(rdPtr(pCur.aOp, Op_p4));
            if (pCur.iRowid == pCur.iAddr + 1) {
                // Result is NULL for the main program.
            } else if (p4z != null) {
                const base: [*]const u8 = @ptrCast(p4z.?);
                sqlite3_result_text(ctx, @ptrCast(base + 3), -1, SQLITE_STATIC);
            } else {
                sqlite3_result_text(ctx, "(FK)", 4, SQLITE_STATIC);
            }
        },
        // SQLITE_ENABLE_STMT_SCANSTATUS is OFF in both configs: nexec/ncycle = 0.
        9, 10 => sqlite3_result_int(ctx, 0), // nexec / ncycle
        20 => sqlite3_result_text(ctx, pCur.zType, -1, SQLITE_STATIC), // tables_used.type
        21 => sqlite3_result_text(ctx, pCur.zSchema, -1, SQLITE_STATIC), // tables_used.schema
        22 => sqlite3_result_text(ctx, pCur.zName, -1, SQLITE_STATIC), // tables_used.name
        23 => sqlite3_result_int(ctx, @intFromBool(rdU8(pOp, Op_opcode) == OP_OpenWrite)), // tables_used.wr
        else => {},
    }
    return SQLITE_OK;
}

inline fn rdU16(base: ?*const anyopaque, off: usize) u16 {
    return fieldPtr(u16, base, off).*;
}

/// Return the rowid for the current row (same as the output value's position).
fn bytecodevtabRowid(cur: *sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int {
    const pCur: *bytecodevtab_cursor = @ptrCast(@alignCast(cur));
    pRowid.* = pCur.iRowid;
    return SQLITE_OK;
}

/// Initialize a cursor.
///   idxNum==0  -> show all subprograms
///   idxNum==1  -> only the main bytecode, omit subprograms
fn bytecodevtabFilter(
    pVtabCursor: *sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?[*]?*sqlite3_value,
) callconv(.c) c_int {
    _ = idxStr;
    _ = argc;
    const pCur: *bytecodevtab_cursor = @ptrCast(@alignCast(pVtabCursor));
    const pVTab: *bytecodevtab = @ptrCast(@alignCast(pVtabCursor.pVtab.?));
    var rc: c_int = SQLITE_OK;

    bytecodevtabCursorClear(pCur);
    pCur.iRowid = 0;
    pCur.iAddr = 0;
    pCur.showSubprograms = @intFromBool(idxNum == 0);
    const arg0 = argv.?[0];
    if (sqlite3_value_type(arg0) == SQLITE_TEXT) {
        const zSql = sqlite3_value_text(arg0);
        if (zSql == null) {
            rc = SQLITE_NOMEM;
        } else {
            rc = sqlite3_prepare_v2(pVTab.db, zSql.?, -1, &pCur.pStmt, null);
            pCur.needFinalize = 1;
        }
    } else {
        pCur.pStmt = sqlite3_value_pointer(arg0, "stmt-pointer");
    }
    if (pCur.pStmt == null) {
        const fname: [*:0]const u8 = if (pVTab.bTablesUsed != 0) "tables_used" else "bytecode";
        pVTab.base.zErrMsg = sqlite3_mprintf(
            "argument to %s() is not a valid SQL statement",
            fname,
        );
        rc = SQLITE_ERROR;
    } else {
        _ = bytecodevtabNext(pVtabCursor);
    }
    return rc;
}

/// Require a single stmt=? constraint, passed through into xFilter; otherwise
/// return SQLITE_CONSTRAINT.
fn bytecodevtabBestIndex(
    tab: *sqlite3_vtab,
    pIdxInfo: *sqlite3_index_info,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_CONSTRAINT;
    const pVTab: *bytecodevtab = @ptrCast(@alignCast(tab));
    const iBaseCol: c_int = if (pVTab.bTablesUsed != 0) 4 else 10;
    pIdxInfo.estimatedCost = 100.0;
    pIdxInfo.estimatedRows = 100;
    pIdxInfo.idxNum = 0;
    const aCons = pIdxInfo.aConstraint.?;
    const aUse = pIdxInfo.aConstraintUsage.?;
    var i: c_int = 0;
    while (i < pIdxInfo.nConstraint) : (i += 1) {
        const p = &aCons[@intCast(i)];
        if (p.usable == 0) continue;
        if (p.op == SQLITE_INDEX_CONSTRAINT_EQ and p.iColumn == iBaseCol + 1) {
            rc = SQLITE_OK;
            aUse[@intCast(i)].omit = 1;
            aUse[@intCast(i)].argvIndex = 1;
        }
        if (p.op == SQLITE_INDEX_CONSTRAINT_ISNULL and p.iColumn == iBaseCol) {
            aUse[@intCast(i)].omit = 1;
            pIdxInfo.idxNum = 1;
        }
    }
    return rc;
}

/// The virtual-table method table. Mirrors the C `bytecodevtabModule`.
const bytecodevtabModule: sqlite3_module = .{
    .iVersion = 0,
    .xCreate = null,
    .xConnect = &bytecodevtabConnect,
    .xBestIndex = &bytecodevtabBestIndex,
    .xDisconnect = &bytecodevtabDisconnect,
    .xDestroy = null,
    .xOpen = &bytecodevtabOpen,
    .xClose = &bytecodevtabClose,
    .xFilter = &bytecodevtabFilter,
    .xNext = &bytecodevtabNext,
    .xEof = &bytecodevtabEof,
    .xColumn = &bytecodevtabColumn,
    .xRowid = &bytecodevtabRowid,
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

/// Register the `bytecode` and `tables_used` eponymous modules on `db`.
/// Called from main.c's built-in-extension table. The internal entry point.
export fn sqlite3VdbeBytecodeVtabInit(db: ?*sqlite3) callconv(.c) c_int {
    var rc = sqlite3_create_module(db, "bytecode", &bytecodevtabModule, null);
    if (rc == SQLITE_OK) {
        // pClientData = &db (non-NULL) selects the tables_used() schema.
        rc = sqlite3_create_module(db, "tables_used", &bytecodevtabModule, @ptrCast(db));
    }
    return rc;
}
