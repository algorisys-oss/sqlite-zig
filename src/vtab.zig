//! Zig port of SQLite's src/vtab.c — virtual-table object management.
//!
//! Whole-file C->Zig swap. Exports (callconv(.c)) every external-linkage symbol
//! that upstream vtab.c defines, matching the prototypes in sqliteInt.h /
//! sqlite3.h:
//!
//!   Public API (sqlite3.h):
//!     sqlite3_create_module, sqlite3_create_module_v2, sqlite3_drop_modules,
//!     sqlite3_declare_vtab, sqlite3_vtab_on_conflict, sqlite3_vtab_config
//!   Internal API (sqliteInt.h):
//!     sqlite3VtabCreateModule, sqlite3VtabModuleUnref, sqlite3VtabLock,
//!     sqlite3GetVTable, sqlite3VtabUnlock, sqlite3VtabDisconnect,
//!     sqlite3VtabUnlockList, sqlite3VtabClear, sqlite3VtabBeginParse,
//!     sqlite3VtabFinishParse, sqlite3VtabArgInit, sqlite3VtabArgExtend,
//!     sqlite3VtabCallConnect, sqlite3VtabCallCreate, sqlite3VtabCallDestroy,
//!     sqlite3VtabSync, sqlite3VtabRollback, sqlite3VtabCommit,
//!     sqlite3VtabBegin, sqlite3VtabSavepoint, sqlite3VtabOverloadFunction,
//!     sqlite3VtabMakeWritable, sqlite3VtabEponymousTableInit,
//!     sqlite3VtabEponymousTableClear
//!
//! The file-scope `struct VtabCtx` is OPAQUE (forward-declared only in
//! sqliteInt.h — its body lives in vtab.c), so we OWN its layout; we mirror it
//! as an extern struct. The static helpers (createModule, vtabDisconnectAll,
//! addModuleArgument, addArgumentToVtab, vtabCallConstructor, growVTrans,
//! addToVTrans, callFinaliser) are private to this module and not exported.
//!
//! ---------------------------------------------------------------------------
//! Config / build assumptions (true in BOTH this project's builds)
//! ---------------------------------------------------------------------------
//!   * SQLITE_OMIT_VIRTUALTABLE OFF       -> full implementation compiled.
//!   * SQLITE_ENABLE_API_ARMOR  OFF       -> the SafetyCheck early-returns are
//!     NOT compiled (absent from build.zig sqlite_flags and the --dev flags).
//!   * SQLITE_OMIT_AUTHORIZATION OFF      -> the second auth check in
//!     sqlite3VtabBeginParse IS compiled.
//!   * SQLITE_OMIT_SHARED_CACHE OFF       -> sqlite3SchemaMutexHeld is a real fn
//!     (only used inside asserts, which compile out except under SQLITE_DEBUG).
//!   * Little-endian x86-64.
//!
//! ---------------------------------------------------------------------------
//! Struct coupling / ground-truth offsets
//! ---------------------------------------------------------------------------
//! This module reaches into many internal core structs (sqlite3, Module, VTable,
//! Table incl. its `u.vtab` union, Parse incl. bitfields, Token, Column, Index,
//! Db). Every offset/size below was probe-verified (a throwaway offsetof program
//! compiled under BOTH the production library flags and the --dev testfixture
//! flags). With ONE exception they are IDENTICAL across the two configs and are
//! routed through @import("c_layout.zig") with a probe-number fallback (the
//! callback.zig / vdbevtab.zig idiom).
//!
//! THE ONE CONFIG-DIVERGENT OFFSET: Parse.disableTriggers is a `bft` bit-field.
//! Under SQLITE_DEBUG the Parse struct gains two leading u8 members (ifNotExists,
//! isCreate), shifting the bit-field byte from 39 (prod) to 42 (tf). Everything
//! after `int nRangeReg` realigns identically (sizeof(Parse)==416 in both, and
//! pNewTable/sNameToken/sArg/nMem/nVtabLock/u1.cr.regRowid are all invariant).
//! We therefore pick the disableTriggers byte via @import("config").sqlite_debug.
//!
//! No standalone Zig unit test is feasible: every path needs a live connection,
//! a parser, a Vdbe, module hash tables, and registered vtab modules. Validated
//! through the engine via the TCL suite (vtab*, fts3/fts4, rtree, the table-
//! valued/eponymous vtabs carray/stmt/bytecode, and every CREATE VIRTUAL TABLE).

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ─── Result / error codes (sqlite3.h) ──────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_MISUSE: c_int = 21;
// SQLITE_NOMEM_BKPT / SQLITE_MISUSE_BKPT are plain codes in non-debug; in the
// testfixture they additionally call sqlite3ReportError, but the *value* is the
// same and the bookkeeping is best-effort. We use the plain values.
const SQLITE_NOMEM_BKPT: c_int = SQLITE_NOMEM;
const SQLITE_MISUSE_BKPT: c_int = SQLITE_MISUSE;

// ─── enums / flags from sqliteInt.h (probe-verified, config-invariant) ──────
const TABTYP_VTAB: u8 = 1;

const SQLITE_VTABRISK_Normal: u8 = 1;
const SQLITE_VTABRISK_Low: u8 = 0;
const SQLITE_VTABRISK_High: u8 = 2;

const SQLITE_VTAB_CONSTRAINT_SUPPORT: c_int = 1;
const SQLITE_VTAB_INNOCUOUS: c_int = 2;
const SQLITE_VTAB_DIRECTONLY: c_int = 3;
const SQLITE_VTAB_USES_ALL_SCHEMAS: c_int = 4;

const SQLITE_LIMIT_COLUMN: c_int = 2;

const PARSE_MODE_NORMAL: u8 = 0;
const PARSE_MODE_DECLARE_VTAB: u8 = 1;

const TK_CREATE: c_int = 17;
const TK_TABLE: c_int = 16;
const TK_SPACE: c_int = 184;
const TK_COMMENT: c_int = 185;
const TK_COLUMN: c_int = 168;

const OP_Expire: c_int = 168;
const OP_VCreate: c_int = 173;

const TF_HasHidden: u32 = 0x2;
const TF_OOOHidden: u32 = 0x400;
const TF_Eponymous: u32 = 0x8000;
const TF_Ephemeral: u32 = 0x4000;
const TF_WithoutRowid: u32 = 0x80;
const TF_NoVisibleRowid: u32 = 0x200;
const COLFLAG_HIDDEN: u16 = 0x2;

const SQLITE_FUNC_EPHEM: u32 = 0x10;

// ON CONFLICT codes (sqlite3.h) — the aMap[] in sqlite3_vtab_on_conflict.
const SQLITE_ROLLBACK: u8 = 1;
const SQLITE_ABORT: u8 = 2;
const SQLITE_FAIL: u8 = 3;
const SQLITE_IGNORE: u8 = 4;
const SQLITE_REPLACE: u8 = 5;

// SAVEPOINT op codes (sqliteInt.h).
const SAVEPOINT_BEGIN: c_int = 0;
const SAVEPOINT_RELEASE: c_int = 1;
const SAVEPOINT_ROLLBACK: c_int = 2;

// sqlite3.flags bit.
const SQLITE_Defensive: u64 = 0x10000000;

// sqlite3_module offsets of the xRollback / xCommit method pointers (used by
// callFinaliser's `offsetof(sqlite3_module, ...)` arithmetic).
const SQLITE_MODULE_xCommit_off: usize = 128;
const SQLITE_MODULE_xRollback_off: usize = 136;

// ─── opaque public/ABI handles ──────────────────────────────────────────────
const sqlite3 = anyopaque;
const Vdbe = anyopaque;
const sqlite3_vtab = anyopaque;
const sqlite3_module = anyopaque;

// ─── Ground-truth offsets (callback.zig idiom) ──────────────────────────────
// All config-INVARIANT except Parse_disableTriggers_byte (see header note).

// struct sqlite3
const sqlite3_mutex_off: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_nSchemaLock_off: usize = if (@hasDecl(L, "sqlite3_nSchemaLock")) L.sqlite3_nSchemaLock else 72;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_vtabOnConflict_off: usize = if (@hasDecl(L, "sqlite3_vtabOnConflict")) L.sqlite3_vtabOnConflict else 108;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_aLimit_off: usize = if (@hasDecl(L, "sqlite3_aLimit")) L.sqlite3_aLimit else 136;
const sqlite3_initBusy_off: usize = if (@hasDecl(L, "sqlite3_initBusy")) L.sqlite3_initBusy else 197;
const sqlite3_nVTrans_off: usize = if (@hasDecl(L, "sqlite3_nVTrans")) L.sqlite3_nVTrans else 564;
const sqlite3_aModule_off: usize = if (@hasDecl(L, "sqlite3_aModule")) L.sqlite3_aModule else 568;
const sqlite3_aVTrans_off: usize = if (@hasDecl(L, "sqlite3_aVTrans")) L.sqlite3_aVTrans else 600;
const sqlite3_pVtabCtx_off: usize = if (@hasDecl(L, "sqlite3_pVtabCtx")) L.sqlite3_pVtabCtx else 576;
const sqlite3_pDisconnect_off: usize = if (@hasDecl(L, "sqlite3_pDisconnect")) L.sqlite3_pDisconnect else 608;
const sqlite3_nSavepoint_off: usize = if (@hasDecl(L, "sqlite3_nSavepoint")) L.sqlite3_nSavepoint else 768;
const sqlite3_nStatement_off: usize = if (@hasDecl(L, "sqlite3_nStatement")) L.sqlite3_nStatement else 772;
const sqlite3_pnBytesFreed_off: usize = if (@hasDecl(L, "sqlite3_pnBytesFreed")) L.sqlite3_pnBytesFreed else 792;

const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pSchema_off: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;

// struct Parse (config-invariant except disableTriggers, handled separately)
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_rc_off: usize = if (@hasDecl(L, "Parse_rc")) L.Parse_rc else 24;
const Parse_pVdbe_off: usize = 16;
const Parse_nQueryLoop_off: usize = 28;
const Parse_zErrMsg_off: usize = if (@hasDecl(L, "Parse_zErrMsg")) L.Parse_zErrMsg else 8;
const Parse_nMem_off: usize = 60;
const Parse_pToplevel_off: usize = if (@hasDecl(L, "Parse_pToplevel")) L.Parse_pToplevel else 136;
const Parse_sNameToken_off: usize = 208;
const Parse_u1_cr_regRowid_off: usize = 236;
const Parse_eParseMode_off: usize = 300;
const Parse_nVtabLock_off: usize = 304;
const Parse_pNewTable_off: usize = if (@hasDecl(L, "Parse_pNewTable")) L.Parse_pNewTable else 344;
const Parse_sArg_off: usize = 376;
const Parse_apVtabLock_off: usize = if (@hasDecl(L, "Parse_apVtabLock")) L.Parse_apVtabLock else 392;
const sizeof_Parse: usize = if (@hasDecl(L, "sizeof_Parse")) L.sizeof_Parse else 416;
// The ONE divergent offset: disableTriggers bit-field byte. mask 0x01.
const Parse_disableTriggers_byte: usize = if (@hasDecl(L, "Parse_disableTriggers_byte"))
    L.Parse_disableTriggers_byte
else if (config.sqlite_debug) 42 else 39;
const Parse_disableTriggers_mask: u8 = 0x01;

// struct Token: z@0, n@8.
const Token_z_off: usize = 0;
const Token_n_off: usize = 8;

// struct Table
const Table_zName_off: usize = if (@hasDecl(L, "Table_zName")) L.Table_zName else 0;
const Table_aCol_off: usize = 8;
const Table_pIndex_off: usize = 16;
const Table_tnum_off: usize = if (@hasDecl(L, "Table_tnum")) L.Table_tnum else 40;
const Table_nTabRef_off: usize = 44;
const Table_tabFlags_off: usize = 48;
const Table_iPKey_off: usize = 52;
const Table_nCol_off: usize = 54;
const Table_nNVCol_off: usize = 56;
const Table_eTabType_off: usize = if (@hasDecl(L, "Table_eTabType")) L.Table_eTabType else 63;
const Table_pSchema_off: usize = 96;
const Table_u_vtab_nArg_off: usize = 64;
const Table_u_vtab_azArg_off: usize = 72;
const Table_u_vtab_p_off: usize = 80;
const Table_u_tab_pDfltList_off: usize = 80;

// struct Column: stride 16, colFlags@14.
const sizeof_Column: usize = 16;
const Column_colFlags_off: usize = if (@hasDecl(L, "Column_colFlags")) L.Column_colFlags else 14;

// struct Index
const Index_pTable_off: usize = 24;
const Index_pNext_off: usize = 40;
const Index_nKeyCol_off: usize = 94;

// struct Module
const Module_pModule_off: usize = 0;
const Module_zName_off: usize = 8;
const Module_nRefModule_off: usize = 16;
const Module_pAux_off: usize = 24;
const Module_xDestroy_off: usize = 32;
const Module_pEpoTab_off: usize = 40;
const sizeof_Module: usize = 48;

// struct VTable
const VTable_db_off: usize = 0;
const VTable_pMod_off: usize = 8;
const VTable_pVtab_off: usize = 16;
const VTable_nRef_off: usize = 24;
const VTable_bConstraint_off: usize = 28;
const VTable_bAllSchemas_off: usize = 29;
const VTable_eVtabRisk_off: usize = 30;
const VTable_iSavepoint_off: usize = 32;
const VTable_pNext_off: usize = 40;
const sizeof_VTable: usize = 48;

// ─── typed field readers/writers over opaque pointers ───────────────────────
inline fn base(p: ?*const anyopaque) [*]u8 {
    return @ptrCast(@constCast(p.?));
}
inline fn fieldPtr(comptime T: type, p: ?*const anyopaque, off: usize) *align(1) T {
    return @ptrCast(base(p) + off);
}
inline fn rd(comptime T: type, p: ?*const anyopaque, off: usize) T {
    return fieldPtr(T, p, off).*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, off: usize, v: T) void {
    fieldPtr(T, p, off).* = v;
}
inline fn rdPtr(p: ?*const anyopaque, off: usize) ?*anyopaque {
    return fieldPtr(?*anyopaque, p, off).*;
}
inline fn wrPtr(p: ?*anyopaque, off: usize, v: ?*anyopaque) void {
    fieldPtr(?*anyopaque, p, off).* = v;
}

// ─── ABI struct mirrors we OWN (opaque in headers) ──────────────────────────
// struct VtabCtx is forward-declared only in sqliteInt.h; vtab.c defines it.
const VtabCtx = extern struct {
    pVTable: ?*anyopaque, // VTable*
    pTab: ?*anyopaque, // Table*
    pPrior: ?*VtabCtx,
    bDeclared: c_int,
};

// ─── extern C helpers (resolved at link time) ───────────────────────────────
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3_free(p: ?*anyopaque) void;

extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3OomFault(db: ?*sqlite3) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3DbMallocZero(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbStrDup(db: ?*sqlite3, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbStrNDup(db: ?*sqlite3, z: ?[*]const u8, n: u64) ?[*:0]u8;
extern fn sqlite3DbRealloc(db: ?*sqlite3, p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3Realloc(p: ?*anyopaque, n: u64) ?*anyopaque;

extern fn sqlite3HashInsert(h: ?*anyopaque, pKey: ?[*:0]const u8, pData: ?*anyopaque) ?*anyopaque;
extern fn sqlite3HashFind(h: ?*const anyopaque, pKey: ?[*:0]const u8) ?*anyopaque;

extern fn sqlite3ApiExit(db: ?*sqlite3, rc: c_int) c_int;
extern fn sqlite3Error(db: ?*sqlite3, rc: c_int) void;
extern fn sqlite3ErrorWithMsg(db: ?*sqlite3, rc: c_int, fmt: ?[*:0]const u8, ...) void;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: ?[*:0]const u8, ...) void;
extern fn sqlite3MPrintf(db: ?*sqlite3, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3NestedParse(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;

extern fn sqlite3SafetyCheckOk(db: ?*sqlite3) c_int;

extern fn sqlite3StartTable(pParse: ?*anyopaque, pName1: ?*anyopaque, pName2: ?*anyopaque, isTemp: c_int, isView: c_int, isVirtual: c_int, noErr: c_int) void;
extern fn sqlite3NameFromToken(db: ?*sqlite3, pToken: ?*const anyopaque) ?[*:0]u8;
extern fn sqlite3SchemaToIndex(db: ?*sqlite3, pSchema: ?*anyopaque) c_int;
extern fn sqlite3AuthCheck(pParse: ?*anyopaque, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;
extern fn sqlite3MayAbort(pParse: ?*anyopaque) void;
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*Vdbe;
extern fn sqlite3ChangeCookie(pParse: ?*anyopaque, iDb: c_int) void;
extern fn sqlite3VdbeAddOp0(p: ?*Vdbe, op: c_int) c_int;
extern fn sqlite3VdbeAddOp2(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeLoadString(p: ?*Vdbe, iDest: c_int, z: ?[*:0]const u8) c_int;
extern fn sqlite3VdbeAddParseSchemaOp(p: ?*Vdbe, iDb: c_int, zWhere: ?[*:0]u8, p5: u16) void;
extern fn sqlite3MarkAllShadowTablesOf(db: ?*sqlite3, pTab: ?*anyopaque) void;
extern fn sqlite3DeleteTable(db: ?*sqlite3, pTab: ?*anyopaque) void;
extern fn sqlite3FindTable(db: ?*sqlite3, zName: ?[*:0]const u8, zDbase: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3ColumnType(pCol: ?*anyopaque, zDflt: ?[*:0]const u8) ?[*:0]u8;
// C `sqlite3StrNICmp` is a macro aliasing the public sqlite3_strnicmp (no real
// symbol of the former exists); call the exported one from util.zig.
extern fn sqlite3_strnicmp(a: ?[*]const u8, b: ?[*]const u8, n: c_int) c_int;
extern fn sqlite3GetToken(z: ?[*]const u8, pTok: *c_int) i64;
extern fn sqlite3ParseObjectInit(pParse: ?*anyopaque, db: ?*sqlite3) void;
extern fn sqlite3ParseObjectReset(pParse: ?*anyopaque) void;
extern fn sqlite3RunParser(pParse: ?*anyopaque, zSql: [*:0]const u8) c_int;
extern fn sqlite3ExprListDelete(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3PrimaryKeyIndex(pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeFinalize(p: ?*Vdbe) c_int;
extern fn sqlite3VtabImportErrmsg(p: ?*Vdbe, pVtab: ?*sqlite3_vtab) void;

extern fn memcpy(noalias d: ?*anyopaque, noalias s: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(d: ?*anyopaque, ch: c_int, n: usize) ?*anyopaque;
extern fn strcmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;

// ─── sqlite3 field accessors ────────────────────────────────────────────────
inline fn dbMutex(db: ?*sqlite3) ?*anyopaque {
    return rdPtr(db, sqlite3_mutex_off);
}
inline fn dbAModule(db: ?*sqlite3) ?*anyopaque {
    return @ptrCast(base(db) + sqlite3_aModule_off);
}
inline fn dbPVtabCtx(db: ?*sqlite3) ?*VtabCtx {
    return @ptrCast(@alignCast(rdPtr(db, sqlite3_pVtabCtx_off)));
}
inline fn dbSetPVtabCtx(db: ?*sqlite3, v: ?*VtabCtx) void {
    wrPtr(db, sqlite3_pVtabCtx_off, @ptrCast(v));
}
inline fn dbAVTrans(db: ?*sqlite3) ?[*]?*anyopaque {
    return @ptrCast(@alignCast(rdPtr(db, sqlite3_aVTrans_off)));
}
inline fn dbSetAVTrans(db: ?*sqlite3, v: ?*anyopaque) void {
    wrPtr(db, sqlite3_aVTrans_off, v);
}
inline fn dbNVTrans(db: ?*sqlite3) c_int {
    return rd(c_int, db, sqlite3_nVTrans_off);
}
inline fn dbSetNVTrans(db: ?*sqlite3, v: c_int) void {
    wr(c_int, db, sqlite3_nVTrans_off, v);
}
inline fn dbPDisconnect(db: ?*sqlite3) ?*anyopaque {
    return rdPtr(db, sqlite3_pDisconnect_off);
}
inline fn dbSetPDisconnect(db: ?*sqlite3, v: ?*anyopaque) void {
    wrPtr(db, sqlite3_pDisconnect_off, v);
}
inline fn dbMallocFailed(db: ?*sqlite3) u8 {
    return base(db)[sqlite3_mallocFailed_off];
}
inline fn dbVtabOnConflict(db: ?*sqlite3) u8 {
    return base(db)[sqlite3_vtabOnConflict_off];
}
inline fn dbInitBusy(db: ?*sqlite3) u8 {
    return base(db)[sqlite3_initBusy_off];
}
inline fn dbSetInitBusy(db: ?*sqlite3, v: u8) void {
    base(db)[sqlite3_initBusy_off] = v;
}
inline fn dbNSchemaLock(db: ?*sqlite3) u32 {
    return rd(u32, db, sqlite3_nSchemaLock_off);
}
inline fn dbSetNSchemaLock(db: ?*sqlite3, v: u32) void {
    wr(u32, db, sqlite3_nSchemaLock_off, v);
}
inline fn dbNStatement(db: ?*sqlite3) c_int {
    return rd(c_int, db, sqlite3_nStatement_off);
}
inline fn dbNSavepoint(db: ?*sqlite3) c_int {
    return rd(c_int, db, sqlite3_nSavepoint_off);
}
inline fn dbPnBytesFreed(db: ?*sqlite3) ?*anyopaque {
    return rdPtr(db, sqlite3_pnBytesFreed_off);
}
inline fn dbFlags(db: ?*sqlite3) u64 {
    return rd(u64, db, sqlite3_flags_off);
}
inline fn dbSetFlags(db: ?*sqlite3, v: u64) void {
    wr(u64, db, sqlite3_flags_off, v);
}
inline fn dbLimitColumn(db: ?*sqlite3) c_int {
    // aLimit[SQLITE_LIMIT_COLUMN]
    return rd(c_int, db, sqlite3_aLimit_off + @as(usize, @intCast(SQLITE_LIMIT_COLUMN)) * @sizeOf(c_int));
}
/// db->aDb[iDb].zDbSName
inline fn dbZDbSName(db: ?*sqlite3, iDb: c_int) ?[*:0]const u8 {
    const aDb = rdPtr(db, sqlite3_aDb_off).?;
    const row: [*]u8 = @as([*]u8, @ptrCast(aDb)) + @as(usize, @intCast(iDb)) * sizeof_Db;
    return @ptrCast(rdPtr(row, Db_zDbSName_off));
}
/// db->aDb[iDb].pSchema
inline fn dbSchema(db: ?*sqlite3, iDb: c_int) ?*anyopaque {
    const aDb = rdPtr(db, sqlite3_aDb_off).?;
    const row: [*]u8 = @as([*]u8, @ptrCast(aDb)) + @as(usize, @intCast(iDb)) * sizeof_Db;
    return rdPtr(row, Db_pSchema_off);
}

// VtabInSync(db): (db->nVTrans>0 && db->aVTrans==0)
inline fn vtabInSync(db: ?*sqlite3) bool {
    return dbNVTrans(db) > 0 and dbAVTrans(db) == null;
}

// ─── Module field accessors ─────────────────────────────────────────────────
inline fn modPModule(pMod: ?*anyopaque) ?*const sqlite3_module {
    return @ptrCast(rdPtr(pMod, Module_pModule_off));
}
inline fn modZName(pMod: ?*anyopaque) ?[*:0]const u8 {
    return @ptrCast(rdPtr(pMod, Module_zName_off));
}
inline fn modNRefModule(pMod: ?*anyopaque) c_int {
    return rd(c_int, pMod, Module_nRefModule_off);
}
inline fn modSetNRefModule(pMod: ?*anyopaque, v: c_int) void {
    wr(c_int, pMod, Module_nRefModule_off, v);
}
inline fn modPAux(pMod: ?*anyopaque) ?*anyopaque {
    return rdPtr(pMod, Module_pAux_off);
}
inline fn modXDestroy(pMod: ?*anyopaque) ?*const fn (?*anyopaque) callconv(.c) void {
    return @ptrCast(rdPtr(pMod, Module_xDestroy_off));
}
inline fn modPEpoTab(pMod: ?*anyopaque) ?*anyopaque {
    return rdPtr(pMod, Module_pEpoTab_off);
}
inline fn modSetPEpoTab(pMod: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(pMod, Module_pEpoTab_off, v);
}

// ─── sqlite3_module method-pointer accessors (public ABI struct) ────────────
// Each method ptr is a fn pointer; layout matches src/vdbevtab.zig mirror.
const XConstructor = ?*const fn (?*sqlite3, ?*anyopaque, c_int, ?[*]const ?[*:0]const u8, *?*sqlite3_vtab, *?[*:0]u8) callconv(.c) c_int;
const XVtabInt = ?*const fn (?*sqlite3_vtab) callconv(.c) c_int;
const XVtabIntInt = ?*const fn (?*sqlite3_vtab, c_int) callconv(.c) c_int;
const XFindFunction = ?*const fn (?*sqlite3_vtab, c_int, ?[*:0]const u8, *?*anyopaque, *?*anyopaque) callconv(.c) c_int;

// Offsets within sqlite3_module (probe: sizeof 200; pointers at 8-byte stride).
// iVersion@0, xCreate@8, xConnect@16, xBestIndex@24, xDisconnect@32, xDestroy@40,
// xOpen@48, xClose@56, xFilter@64, xNext@72, xEof@80, xColumn@88, xRowid@96,
// xUpdate@104, xBegin@112, xSync@120, xCommit@128, xRollback@136,
// xFindFunction@144, xRename@152, xSavepoint@160, xRelease@168, xRollbackTo@176,
// xShadowName@184, xIntegrity@192.
const MOD_iVersion: usize = 0;
const MOD_xCreate: usize = 8;
const MOD_xConnect: usize = 16;
const MOD_xDisconnect: usize = 32;
const MOD_xDestroy: usize = 40;
const MOD_xUpdate: usize = 104;
const MOD_xBegin: usize = 112;
const MOD_xSync: usize = 120;
const MOD_xFindFunction: usize = 144;
const MOD_xSavepoint: usize = 160;
const MOD_xRelease: usize = 168;
const MOD_xRollbackTo: usize = 176;

inline fn modIVersion(p: ?*const sqlite3_module) c_int {
    return rd(c_int, p, MOD_iVersion);
}
inline fn modPtrAt(p: ?*const sqlite3_module, off: usize) ?*anyopaque {
    return rdPtr(p, off);
}

// ─── VTable field accessors ─────────────────────────────────────────────────
inline fn vtDb(p: ?*anyopaque) ?*sqlite3 {
    return @ptrCast(rdPtr(p, VTable_db_off));
}
inline fn vtPMod(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(p, VTable_pMod_off);
}
inline fn vtSetPMod(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, VTable_pMod_off, v);
}
inline fn vtPVtab(p: ?*anyopaque) ?*sqlite3_vtab {
    return @ptrCast(rdPtr(p, VTable_pVtab_off));
}
inline fn vtSetPVtab(p: ?*anyopaque, v: ?*sqlite3_vtab) void {
    wrPtr(p, VTable_pVtab_off, @ptrCast(v));
}
inline fn vtNRef(p: ?*anyopaque) c_int {
    return rd(c_int, p, VTable_nRef_off);
}
inline fn vtSetNRef(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, VTable_nRef_off, v);
}
inline fn vtSetDb(p: ?*anyopaque, v: ?*sqlite3) void {
    wrPtr(p, VTable_db_off, @ptrCast(v));
}
inline fn vtSetEVtabRisk(p: ?*anyopaque, v: u8) void {
    base(p)[VTable_eVtabRisk_off] = v;
}
inline fn vtSetBConstraint(p: ?*anyopaque, v: u8) void {
    base(p)[VTable_bConstraint_off] = v;
}
inline fn vtSetBAllSchemas(p: ?*anyopaque, v: u8) void {
    base(p)[VTable_bAllSchemas_off] = v;
}
inline fn vtISavepoint(p: ?*anyopaque) c_int {
    return rd(c_int, p, VTable_iSavepoint_off);
}
inline fn vtSetISavepoint(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, VTable_iSavepoint_off, v);
}
inline fn vtPNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(p, VTable_pNext_off);
}
inline fn vtSetPNext(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, VTable_pNext_off, v);
}

// ─── Table field accessors ──────────────────────────────────────────────────
inline fn tabZName(p: ?*anyopaque) ?[*:0]const u8 {
    return @ptrCast(rdPtr(p, Table_zName_off));
}
inline fn tabETabType(p: ?*anyopaque) u8 {
    return base(p)[Table_eTabType_off];
}
inline fn tabSetETabType(p: ?*anyopaque, v: u8) void {
    base(p)[Table_eTabType_off] = v;
}
inline fn isVirtual(p: ?*anyopaque) bool {
    return tabETabType(p) == TABTYP_VTAB;
}
inline fn tabPSchema(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(p, Table_pSchema_off);
}
inline fn tabSetPSchema(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Table_pSchema_off, v);
}
inline fn tabNTabRef(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_nTabRef_off);
}
inline fn tabSetNTabRef(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Table_nTabRef_off, v);
}
inline fn tabTabFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tabFlags_off);
}
inline fn tabSetTabFlags(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Table_tabFlags_off, v);
}
inline fn tabNCol(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_nCol_off);
}
inline fn tabSetNCol(p: ?*anyopaque, v: i16) void {
    wr(i16, p, Table_nCol_off, v);
}
inline fn tabSetNNVCol(p: ?*anyopaque, v: i16) void {
    wr(i16, p, Table_nNVCol_off, v);
}
inline fn tabSetIPKey(p: ?*anyopaque, v: i16) void {
    wr(i16, p, Table_iPKey_off, v);
}
inline fn tabACol(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(p, Table_aCol_off);
}
inline fn tabSetACol(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Table_aCol_off, v);
}
inline fn tabPIndex(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(p, Table_pIndex_off);
}
inline fn tabSetPIndex(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Table_pIndex_off, v);
}
inline fn tabSetZName(p: ?*anyopaque, v: ?[*:0]u8) void {
    wrPtr(p, Table_zName_off, @ptrCast(v));
}
// u.vtab accessors
inline fn tabVtabNArg(p: ?*anyopaque) c_int {
    return rd(c_int, p, Table_u_vtab_nArg_off);
}
inline fn tabSetVtabNArg(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Table_u_vtab_nArg_off, v);
}
inline fn tabVtabAzArg(p: ?*anyopaque) ?[*]?[*:0]u8 {
    return @ptrCast(@alignCast(rdPtr(p, Table_u_vtab_azArg_off)));
}
inline fn tabSetVtabAzArg(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Table_u_vtab_azArg_off, v);
}
inline fn tabVtabP(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(p, Table_u_vtab_p_off);
}
inline fn tabSetVtabP(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Table_u_vtab_p_off, v);
}
inline fn tabVtabPPtr(p: ?*anyopaque) *align(1) ?*anyopaque {
    return fieldPtr(?*anyopaque, p, Table_u_vtab_p_off);
}

// ─── Parse field accessors ──────────────────────────────────────────────────
inline fn parseDb(p: ?*anyopaque) ?*sqlite3 {
    return @ptrCast(rdPtr(p, Parse_db_off));
}
inline fn parseSetRc(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Parse_rc_off, v);
}
inline fn parsePNewTable(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(p, Parse_pNewTable_off);
}
inline fn parseSetPNewTable(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Parse_pNewTable_off, v);
}
inline fn parsePToplevel(p: ?*anyopaque) ?*anyopaque {
    // sqlite3ParseToplevel(p): p->pToplevel ? p->pToplevel : p
    const t = rdPtr(p, Parse_pToplevel_off);
    return if (t != null) t else p;
}
inline fn parseNVtabLock(p: ?*anyopaque) c_int {
    return rd(c_int, p, Parse_nVtabLock_off);
}
inline fn parseSetNVtabLock(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Parse_nVtabLock_off, v);
}
inline fn parseApVtabLock(p: ?*anyopaque) ?[*]?*anyopaque {
    return @ptrCast(@alignCast(rdPtr(p, Parse_apVtabLock_off)));
}
inline fn parseSetApVtabLock(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Parse_apVtabLock_off, v);
}
inline fn parseNMem(p: ?*anyopaque) c_int {
    return rd(c_int, p, Parse_nMem_off);
}
inline fn parseSetNMem(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Parse_nMem_off, v);
}
inline fn parseZErrMsg(p: ?*anyopaque) ?[*:0]u8 {
    return @ptrCast(rdPtr(p, Parse_zErrMsg_off));
}
inline fn parsePVdbe(p: ?*anyopaque) ?*Vdbe {
    return @ptrCast(rdPtr(p, Parse_pVdbe_off));
}
inline fn parseSetEParseMode(p: ?*anyopaque, v: u8) void {
    base(p)[Parse_eParseMode_off] = v;
}
inline fn parseSetDisableTriggers(p: ?*anyopaque, on: bool) void {
    const b = &base(p)[Parse_disableTriggers_byte];
    if (on) b.* |= Parse_disableTriggers_mask else b.* &= ~Parse_disableTriggers_mask;
}
inline fn parseSetNQueryLoop(p: ?*anyopaque, v: i16) void {
    wr(i16, p, Parse_nQueryLoop_off, v);
}
inline fn parseU1CrRegRowid(p: ?*anyopaque) c_int {
    return rd(c_int, p, Parse_u1_cr_regRowid_off);
}
// sNameToken: a Token { z, n } at Parse_sNameToken_off.
inline fn parseSNameTokenZ(p: ?*anyopaque) ?[*]const u8 {
    return @ptrCast(rdPtr(p, Parse_sNameToken_off + Token_z_off));
}
inline fn parseSetSNameTokenN(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Parse_sNameToken_off + Token_n_off, v);
}
inline fn parseSNameTokenPtr(p: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(p) + Parse_sNameToken_off);
}
// sArg: a Token { z, n } at Parse_sArg_off.
inline fn parseSArgZ(p: ?*anyopaque) ?[*]const u8 {
    return @ptrCast(rdPtr(p, Parse_sArg_off + Token_z_off));
}
inline fn parseSArgN(p: ?*anyopaque) c_int {
    return rd(c_int, p, Parse_sArg_off + Token_n_off);
}
inline fn parseSetSArgZ(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(p, Parse_sArg_off + Token_z_off, v);
}
inline fn parseSetSArgN(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Parse_sArg_off + Token_n_off, v);
}

// ─── Token field accessors ──────────────────────────────────────────────────
inline fn tokZ(p: ?*const anyopaque) ?[*]const u8 {
    return @ptrCast(rdPtr(p, Token_z_off));
}
inline fn tokN(p: ?*const anyopaque) c_int {
    return rd(c_int, p, Token_n_off);
}

// ===========================================================================
// sqlite3VtabCreateModule
// ===========================================================================
export fn sqlite3VtabCreateModule(
    db: ?*sqlite3,
    zName: ?[*:0]const u8,
    pModule: ?*const sqlite3_module,
    pAux: ?*anyopaque,
    xDestroy: ?*const fn (?*anyopaque) callconv(.c) void,
) callconv(.c) ?*anyopaque {
    var pMod: ?*anyopaque = null;
    var zCopy: ?[*:0]const u8 = undefined;
    if (pModule == null) {
        zCopy = zName;
        pMod = null;
    } else {
        const nName: usize = @intCast(sqlite3Strlen30(zName));
        pMod = sqlite3Malloc(@as(u64, sizeof_Module) + nName + 1);
        if (pMod == null) {
            _ = sqlite3OomFault(db);
            return null;
        }
        // zCopy = (char*)(&pMod[1])  (immediately after the Module struct)
        const zCopyPtr: [*]u8 = base(pMod) + sizeof_Module;
        _ = memcpy(zCopyPtr, zName, nName + 1);
        zCopy = @ptrCast(zCopyPtr);
        wrPtr(pMod, Module_zName_off, @ptrCast(@constCast(zCopy)));
        wrPtr(pMod, Module_pModule_off, @constCast(@ptrCast(pModule)));
        wrPtr(pMod, Module_pAux_off, pAux);
        wrPtr(pMod, Module_xDestroy_off, @constCast(@ptrCast(xDestroy)));
        wrPtr(pMod, Module_pEpoTab_off, null);
        modSetNRefModule(pMod, 1);
    }
    const pDel = sqlite3HashInsert(dbAModule(db), zCopy, pMod);
    if (pDel != null) {
        if (pDel == pMod) {
            _ = sqlite3OomFault(db);
            sqlite3DbFree(db, pDel);
            pMod = null;
        } else {
            sqlite3VtabEponymousTableClear(db, pDel);
            sqlite3VtabModuleUnref(db, pDel);
        }
    }
    return pMod;
}

// ===========================================================================
// createModule (static) + the public create_module APIs
// ===========================================================================
fn createModule(
    db: ?*sqlite3,
    zName: ?[*:0]const u8,
    pModule: ?*const sqlite3_module,
    pAux: ?*anyopaque,
    xDestroy: ?*const fn (?*anyopaque) callconv(.c) void,
) c_int {
    var rc: c_int = SQLITE_OK;
    sqlite3_mutex_enter(dbMutex(db));
    _ = sqlite3VtabCreateModule(db, zName, pModule, pAux, xDestroy);
    rc = sqlite3ApiExit(db, rc);
    if (rc != SQLITE_OK) {
        if (xDestroy) |xd| xd(pAux);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

export fn sqlite3_create_module(
    db: ?*sqlite3,
    zName: ?[*:0]const u8,
    pModule: ?*const sqlite3_module,
    pAux: ?*anyopaque,
) callconv(.c) c_int {
    // SQLITE_ENABLE_API_ARMOR is OFF in both configs.
    return createModule(db, zName, pModule, pAux, null);
}

export fn sqlite3_create_module_v2(
    db: ?*sqlite3,
    zName: ?[*:0]const u8,
    pModule: ?*const sqlite3_module,
    pAux: ?*anyopaque,
    xDestroy: ?*const fn (?*anyopaque) callconv(.c) void,
) callconv(.c) c_int {
    return createModule(db, zName, pModule, pAux, xDestroy);
}

export fn sqlite3_drop_modules(db: ?*sqlite3, azNames: ?[*]?[*:0]const u8) callconv(.c) c_int {
    // Iterate the aModule hash. We reuse the public hash iteration via the
    // struct layout: Hash.first @ +8, HashElem.next @ +0, HashElem.data @ +16.
    const Hash_first_off: usize = if (@hasDecl(L, "Hash_first")) L.Hash_first else 8;
    const HashElem_next_off: usize = if (@hasDecl(L, "HashElem_next")) L.HashElem_next else 0;
    const HashElem_data_off: usize = if (@hasDecl(L, "HashElem_data")) L.HashElem_data else 16;

    // Walk: pThis = sqliteHashFirst(&db->aModule)
    var p = rdPtr(dbAModule(db), Hash_first_off);
    while (p != null) {
        const pMod = rdPtr(p, HashElem_data_off);
        const pNext = rdPtr(p, HashElem_next_off);
        var skip = false;
        if (azNames) |names| {
            var ii: usize = 0;
            while (names[ii] != null and strcmp(names[ii], modZName(pMod)) != 0) : (ii += 1) {}
            if (names[ii] != null) skip = true;
        }
        if (!skip) {
            _ = createModule(db, modZName(pMod), null, null, null);
        }
        p = pNext;
    }
    return SQLITE_OK;
}

// ===========================================================================
// sqlite3VtabModuleUnref
// ===========================================================================
export fn sqlite3VtabModuleUnref(db: ?*sqlite3, pMod: ?*anyopaque) callconv(.c) void {
    std.debug.assert(modNRefModule(pMod) > 0);
    modSetNRefModule(pMod, modNRefModule(pMod) - 1);
    if (modNRefModule(pMod) == 0) {
        if (modXDestroy(pMod)) |xd| {
            xd(modPAux(pMod));
        }
        std.debug.assert(modPEpoTab(pMod) == null);
        sqlite3DbFree(db, pMod);
    }
}

// ===========================================================================
// sqlite3VtabLock
// ===========================================================================
export fn sqlite3VtabLock(pVTab: ?*anyopaque) callconv(.c) void {
    vtSetNRef(pVTab, vtNRef(pVTab) + 1);
}

// ===========================================================================
// sqlite3GetVTable
// ===========================================================================
export fn sqlite3GetVTable(db: ?*sqlite3, pTab: ?*anyopaque) callconv(.c) ?*anyopaque {
    std.debug.assert(isVirtual(pTab));
    var pVtab = tabVtabP(pTab);
    while (pVtab != null and vtDb(pVtab) != db) {
        pVtab = vtPNext(pVtab);
    }
    return pVtab;
}

// ===========================================================================
// sqlite3VtabUnlock
// ===========================================================================
export fn sqlite3VtabUnlock(pVTab: ?*anyopaque) callconv(.c) void {
    const db = vtDb(pVTab);
    std.debug.assert(db != null);
    std.debug.assert(vtNRef(pVTab) > 0);
    vtSetNRef(pVTab, vtNRef(pVTab) - 1);
    if (vtNRef(pVTab) == 0) {
        const p = vtPVtab(pVTab);
        if (p) |pv| {
            // p->pModule->xDisconnect(p)
            const pModule = rdPtr(pv, 0); // sqlite3_vtab.pModule @ 0
            const xDisconnect: XVtabInt = @ptrCast(rdPtr(pModule, MOD_xDisconnect));
            _ = xDisconnect.?(pv);
        }
        sqlite3VtabModuleUnref(vtDb(pVTab), vtPMod(pVTab));
        sqlite3DbFree(db, pVTab);
    }
}

// ===========================================================================
// vtabDisconnectAll (static)
// ===========================================================================
fn vtabDisconnectAll(db: ?*sqlite3, p: ?*anyopaque) ?*anyopaque {
    var pRet: ?*anyopaque = null;
    std.debug.assert(isVirtual(p));
    var pVTable = tabVtabP(p);
    tabSetVtabP(p, null);

    while (pVTable != null) {
        const db2 = vtDb(pVTable);
        const pNext = vtPNext(pVTable);
        std.debug.assert(db2 != null);
        if (db2 == db) {
            pRet = pVTable;
            tabSetVtabP(p, pRet);
            vtSetPNext(pRet, null);
        } else {
            vtSetPNext(pVTable, dbPDisconnect(db2));
            dbSetPDisconnect(db2, pVTable);
        }
        pVTable = pNext;
    }
    std.debug.assert(db == null or pRet != null);
    return pRet;
}

// ===========================================================================
// sqlite3VtabDisconnect
// ===========================================================================
export fn sqlite3VtabDisconnect(db: ?*sqlite3, p: ?*anyopaque) callconv(.c) void {
    std.debug.assert(isVirtual(p));
    var ppVTab: *align(1) ?*anyopaque = tabVtabPPtr(p);
    while (ppVTab.* != null) {
        const cur = ppVTab.*;
        if (vtDb(cur) == db) {
            ppVTab.* = vtPNext(cur);
            sqlite3VtabUnlock(cur);
            break;
        }
        ppVTab = fieldPtr(?*anyopaque, cur, VTable_pNext_off);
    }
}

// ===========================================================================
// sqlite3VtabUnlockList
// ===========================================================================
export fn sqlite3VtabUnlockList(db: ?*sqlite3) callconv(.c) void {
    var p = dbPDisconnect(db);
    if (p != null) {
        dbSetPDisconnect(db, null);
        while (true) {
            const pNext = vtPNext(p);
            sqlite3VtabUnlock(p);
            p = pNext;
            if (p == null) break;
        }
    }
}

// ===========================================================================
// sqlite3VtabClear
// ===========================================================================
export fn sqlite3VtabClear(db: ?*sqlite3, p: ?*anyopaque) callconv(.c) void {
    std.debug.assert(isVirtual(p));
    std.debug.assert(db != null);
    if (dbPnBytesFreed(db) == null) {
        _ = vtabDisconnectAll(null, p);
    }
    if (tabVtabAzArg(p)) |azArg| {
        const n = tabVtabNArg(p);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            if (i != 1) sqlite3DbFree(db, azArg[@intCast(i)]);
        }
        sqlite3DbFree(db, @ptrCast(azArg));
    }
}

// ===========================================================================
// addModuleArgument (static)
// ===========================================================================
fn addModuleArgument(pParse: ?*anyopaque, pTable: ?*anyopaque, zArg: ?[*:0]u8) void {
    const db = parseDb(pParse);
    std.debug.assert(isVirtual(pTable));
    const nArg = tabVtabNArg(pTable);
    const nBytes: i64 = @as(i64, @sizeOf(usize)) * (2 + nArg);
    if (nArg + 3 >= dbLimitColumn(db)) {
        sqlite3ErrorMsg(pParse, "too many columns on %s", tabZName(pTable));
    }
    const azModuleArg = sqlite3DbRealloc(db, @ptrCast(tabVtabAzArg(pTable)), @intCast(nBytes));
    if (azModuleArg == null) {
        sqlite3DbFree(db, @ptrCast(zArg));
    } else {
        const arr: [*]?[*:0]u8 = @ptrCast(@alignCast(azModuleArg.?));
        const i = nArg;
        tabSetVtabNArg(pTable, nArg + 1);
        arr[@intCast(i)] = zArg;
        arr[@intCast(i + 1)] = null;
        tabSetVtabAzArg(pTable, azModuleArg);
    }
}

// ===========================================================================
// sqlite3VtabBeginParse
// ===========================================================================
export fn sqlite3VtabBeginParse(
    pParse: ?*anyopaque,
    pName1: ?*anyopaque,
    pName2: ?*anyopaque,
    pModuleName: ?*anyopaque,
    ifNotExists: c_int,
) callconv(.c) void {
    sqlite3StartTable(pParse, pName1, pName2, 0, 0, 1, ifNotExists);
    const pTable = parsePNewTable(pParse);
    if (pTable == null) return;
    std.debug.assert(tabPIndex(pTable) == null);
    tabSetETabType(pTable, TABTYP_VTAB);

    const db = parseDb(pParse);
    std.debug.assert(tabVtabNArg(pTable) == 0);
    addModuleArgument(pParse, pTable, sqlite3NameFromToken(db, pModuleName));
    addModuleArgument(pParse, pTable, null);
    addModuleArgument(pParse, pTable, sqlite3DbStrDup(db, tabZName(pTable)));

    // pParse->sNameToken.n = (int)(&pModuleName->z[pModuleName->n] - sNameToken.z)
    const modZ = tokZ(pModuleName).?;
    const modN: usize = @intCast(tokN(pModuleName));
    const nameZ = parseSNameTokenZ(pParse).?;
    const newN: c_int = @intCast(@intFromPtr(modZ + modN) - @intFromPtr(nameZ));
    parseSetSNameTokenN(pParse, newN);

    // SQLITE_OMIT_AUTHORIZATION is OFF -> second auth check.
    if (tabVtabAzArg(pTable)) |azArg| {
        const iDb = sqlite3SchemaToIndex(db, tabPSchema(pTable));
        std.debug.assert(iDb >= 0);
        const SQLITE_CREATE_VTABLE: c_int = 29;
        _ = sqlite3AuthCheck(pParse, SQLITE_CREATE_VTABLE, tabZName(pTable), @ptrCast(azArg[0]), dbZDbSName(db, iDb));
    }
}

// ===========================================================================
// addArgumentToVtab (static)
// ===========================================================================
fn addArgumentToVtab(pParse: ?*anyopaque) void {
    if (parseSArgZ(pParse) != null and parsePNewTable(pParse) != null) {
        const z = parseSArgZ(pParse);
        const n = parseSArgN(pParse);
        const db = parseDb(pParse);
        addModuleArgument(pParse, parsePNewTable(pParse), sqlite3DbStrNDup(db, z, @intCast(n)));
    }
}

// ===========================================================================
// sqlite3VtabFinishParse
// ===========================================================================
export fn sqlite3VtabFinishParse(pParse: ?*anyopaque, pEnd: ?*anyopaque) callconv(.c) void {
    const pTab = parsePNewTable(pParse);
    const db = parseDb(pParse);
    if (pTab == null) return;
    std.debug.assert(isVirtual(pTab));
    addArgumentToVtab(pParse);
    parseSetSArgZ(pParse, null);
    if (tabVtabNArg(pTab) < 1) return;

    if (dbInitBusy(db) == 0) {
        sqlite3MayAbort(pParse);

        // Complete text of the CREATE VIRTUAL TABLE statement.
        if (pEnd) |pe| {
            // sNameToken.n = (int)(pEnd->z - sNameToken.z) + pEnd->n
            const endZ = tokZ(pe).?;
            const nameZ = parseSNameTokenZ(pParse).?;
            const v: c_int = @as(c_int, @intCast(@intFromPtr(endZ) - @intFromPtr(nameZ))) + tokN(pe);
            parseSetSNameTokenN(pParse, v);
        }
        const zStmt = sqlite3MPrintf(db, "CREATE VIRTUAL TABLE %T", parseSNameTokenPtr(pParse));

        const iDb = sqlite3SchemaToIndex(db, tabPSchema(pTab));
        sqlite3NestedParse(pParse,
            \\UPDATE %Q.sqlite_master SET type='table', name=%Q, tbl_name=%Q, rootpage=0, sql=%Q WHERE rowid=#%d
        , dbZDbSName(db, iDb), tabZName(pTab), tabZName(pTab), zStmt, parseU1CrRegRowid(pParse));
        const v = sqlite3GetVdbe(pParse);
        sqlite3ChangeCookie(pParse, iDb);

        _ = sqlite3VdbeAddOp0(v, OP_Expire);
        const zWhere = sqlite3MPrintf(db, "name=%Q AND sql=%Q", tabZName(pTab), zStmt);
        sqlite3VdbeAddParseSchemaOp(v, iDb, zWhere, 0);
        sqlite3DbFree(db, @ptrCast(zStmt));

        const iReg = parseNMem(pParse) + 1;
        parseSetNMem(pParse, iReg);
        _ = sqlite3VdbeLoadString(v, iReg, tabZName(pTab));
        _ = sqlite3VdbeAddOp2(v, OP_VCreate, iDb, iReg);
    } else {
        // Reread the schema: create the in-memory record.
        const pSchema = tabPSchema(pTab);
        const zName = tabZName(pTab);
        std.debug.assert(zName != null);
        sqlite3MarkAllShadowTablesOf(db, pTab);
        // pOld = sqlite3HashInsert(&pSchema->tblHash, zName, pTab)
        const Schema_tblHash_off: usize = if (@hasDecl(L, "Schema_tblHash")) L.Schema_tblHash else 8;
        const tblHash: ?*anyopaque = @ptrCast(base(pSchema) + Schema_tblHash_off);
        const pOld = sqlite3HashInsert(tblHash, zName, pTab);
        if (pOld != null) {
            _ = sqlite3OomFault(db);
            std.debug.assert(pTab == pOld);
            return;
        }
        parseSetPNewTable(pParse, null);
    }
}

// ===========================================================================
// sqlite3VtabArgInit
// ===========================================================================
export fn sqlite3VtabArgInit(pParse: ?*anyopaque) callconv(.c) void {
    addArgumentToVtab(pParse);
    parseSetSArgZ(pParse, null);
    parseSetSArgN(pParse, 0);
}

// ===========================================================================
// sqlite3VtabArgExtend
// ===========================================================================
export fn sqlite3VtabArgExtend(pParse: ?*anyopaque, p: ?*anyopaque) callconv(.c) void {
    // pArg = &pParse->sArg
    if (parseSArgZ(pParse) == null) {
        parseSetSArgZ(pParse, @ptrCast(@constCast(tokZ(p))));
        parseSetSArgN(pParse, tokN(p));
    } else {
        const pz = tokZ(p).?;
        const pn: usize = @intCast(tokN(p));
        const argZ = parseSArgZ(pParse).?;
        std.debug.assert(@intFromPtr(argZ) <= @intFromPtr(pz));
        const v: c_int = @intCast(@intFromPtr(pz + pn) - @intFromPtr(argZ));
        parseSetSArgN(pParse, v);
    }
}

// ===========================================================================
// vtabCallConstructor (static)
// ===========================================================================
fn vtabCallConstructor(
    db: ?*sqlite3,
    pTab: ?*anyopaque,
    pMod: ?*anyopaque,
    xConstruct: XConstructor,
    pzErr: *?[*:0]u8,
) c_int {
    var sCtx: VtabCtx = undefined;
    var rc: c_int = undefined;
    const nArg = tabVtabNArg(pTab);
    var zErr: ?[*:0]u8 = null;

    std.debug.assert(isVirtual(pTab));
    const azArg: ?[*]const ?[*:0]const u8 = @ptrCast(tabVtabAzArg(pTab));

    // Check not already being initialized.
    var pCtx = dbPVtabCtx(db);
    while (pCtx) |pc| {
        if (pc.pTab == pTab) {
            pzErr.* = sqlite3MPrintf(db, "vtable constructor called recursively: %s", tabZName(pTab));
            return SQLITE_LOCKED;
        }
        pCtx = pc.pPrior;
    }

    const zModuleName = sqlite3DbStrDup(db, tabZName(pTab));
    if (zModuleName == null) {
        return SQLITE_NOMEM_BKPT;
    }

    const pVTable = sqlite3MallocZero(sizeof_VTable);
    if (pVTable == null) {
        _ = sqlite3OomFault(db);
        sqlite3DbFree(db, @ptrCast(zModuleName));
        return SQLITE_NOMEM_BKPT;
    }
    vtSetDb(pVTable, db);
    vtSetPMod(pVTable, pMod);
    vtSetEVtabRisk(pVTable, SQLITE_VTABRISK_Normal);

    const iDb = sqlite3SchemaToIndex(db, tabPSchema(pTab));
    // pTab->u.vtab.azArg[1] = db->aDb[iDb].zDbSName
    const azArgMut = tabVtabAzArg(pTab).?;
    azArgMut[1] = @ptrCast(@constCast(dbZDbSName(db, iDb)));

    std.debug.assert(xConstruct != null);
    sCtx.pTab = pTab;
    sCtx.pVTable = pVTable;
    sCtx.pPrior = dbPVtabCtx(db);
    sCtx.bDeclared = 0;
    dbSetPVtabCtx(db, &sCtx);
    tabSetNTabRef(pTab, tabNTabRef(pTab) + 1);
    var pVtabOut: ?*sqlite3_vtab = null;
    rc = xConstruct.?(db, modPAux(pMod), nArg, azArg, &pVtabOut, &zErr);
    vtSetPVtab(pVTable, pVtabOut);
    std.debug.assert(pTab != null);
    sqlite3DeleteTable(db, pTab);
    dbSetPVtabCtx(db, sCtx.pPrior);
    if (rc == SQLITE_NOMEM) _ = sqlite3OomFault(db);
    std.debug.assert(sCtx.pTab == pTab);

    if (rc != SQLITE_OK) {
        if (zErr == null) {
            pzErr.* = sqlite3MPrintf(db, "vtable constructor failed: %s", zModuleName);
        } else {
            pzErr.* = sqlite3MPrintf(db, "%s", zErr);
            sqlite3_free(@ptrCast(zErr));
        }
        sqlite3DbFree(db, pVTable);
    } else if (vtPVtab(pVTable) != null) { // ALWAYS()
        const pv = vtPVtab(pVTable).?;
        // memset(pVTable->pVtab, 0, sizeof(sqlite3_vtab))  (pModule+nRef+zErrMsg = 24)
        _ = memset(pv, 0, 24);
        // pVTable->pVtab->pModule = pMod->pModule
        wrPtr(pv, 0, @constCast(@ptrCast(modPModule(pMod))));
        modSetNRefModule(pMod, modNRefModule(pMod) + 1);
        vtSetNRef(pVTable, 1);
        if (sCtx.bDeclared == 0) {
            pzErr.* = sqlite3MPrintf(db, "vtable constructor did not declare schema: %s", zModuleName);
            sqlite3VtabUnlock(pVTable);
            rc = SQLITE_ERROR;
        } else {
            // Link into pTab->u.vtab.p; scan columns for "hidden".
            var oooHidden: u32 = 0;
            vtSetPNext(pVTable, tabVtabP(pTab));
            tabSetVtabP(pTab, pVTable);

            const nCol: c_int = tabNCol(pTab);
            const aCol = tabACol(pTab);
            var iCol: c_int = 0;
            while (iCol < nCol) : (iCol += 1) {
                const pCol: ?*anyopaque = @ptrCast(@as([*]u8, @ptrCast(aCol.?)) + @as(usize, @intCast(iCol)) * sizeof_Column);
                const zType = sqlite3ColumnType(pCol, "");
                var i: usize = 0;
                const nType: usize = @intCast(sqlite3Strlen30(@ptrCast(zType)));
                const zt = zType.?;
                while (i < nType) : (i += 1) {
                    if (0 == sqlite3_strnicmp("hidden", zt + i, 6) and
                        (i == 0 or zt[i - 1] == ' ') and
                        (zt[i + 6] == 0 or zt[i + 6] == ' '))
                    {
                        break;
                    }
                }
                if (i < nType) {
                    const nDel: usize = 6 + (if (zt[i + 6] != 0) @as(usize, 1) else 0);
                    var j: usize = i;
                    while (j + nDel <= nType) : (j += 1) {
                        zt[j] = zt[j + nDel];
                    }
                    if (zt[i] == 0 and i > 0) {
                        std.debug.assert(zt[i - 1] == ' ');
                        zt[i - 1] = 0;
                    }
                    // pTab->aCol[iCol].colFlags |= COLFLAG_HIDDEN
                    const cf = fieldPtr(u16, pCol, Column_colFlags_off);
                    cf.* |= COLFLAG_HIDDEN;
                    tabSetTabFlags(pTab, tabTabFlags(pTab) | TF_HasHidden);
                    oooHidden = TF_OOOHidden;
                } else {
                    tabSetTabFlags(pTab, tabTabFlags(pTab) | oooHidden);
                }
            }
        }
    }

    sqlite3DbFree(db, @ptrCast(zModuleName));
    return rc;
}

// ===========================================================================
// sqlite3VtabCallConnect
// ===========================================================================
export fn sqlite3VtabCallConnect(pParse: ?*anyopaque, pTab: ?*anyopaque) callconv(.c) c_int {
    const db = parseDb(pParse);
    var rc: c_int = undefined;

    std.debug.assert(pTab != null);
    std.debug.assert(isVirtual(pTab));
    if (sqlite3GetVTable(db, pTab) != null) {
        return SQLITE_OK;
    }

    // Locate the module.
    const azArg = tabVtabAzArg(pTab).?;
    const zMod = azArg[0];
    const pMod = sqlite3HashFind(dbAModule(db), @ptrCast(zMod));

    if (pMod == null) {
        const zModule = azArg[0];
        sqlite3ErrorMsg(pParse, "no such module: %s", @as(?[*:0]const u8, @ptrCast(zModule)));
        rc = SQLITE_ERROR;
    } else {
        var zErr: ?[*:0]u8 = null;
        const xConnect: XConstructor = @ptrCast(modPtrAt(modPModule(pMod), MOD_xConnect));
        rc = vtabCallConstructor(db, pTab, pMod, xConnect, &zErr);
        if (rc != SQLITE_OK) {
            sqlite3ErrorMsg(pParse, "%s", zErr);
            parseSetRc(pParse, rc);
        }
        sqlite3DbFree(db, @ptrCast(zErr));
    }
    return rc;
}

// ===========================================================================
// growVTrans (static) / addToVTrans (static)
// ===========================================================================
fn growVTrans(db: ?*sqlite3) c_int {
    const ARRAY_INCR: c_int = 5;
    const n = dbNVTrans(db);
    if (@rem(n, ARRAY_INCR) == 0) {
        const nBytes: i64 = @as(i64, @sizeOf(usize)) * (@as(i64, n) + ARRAY_INCR);
        const aVTrans = sqlite3DbRealloc(db, @ptrCast(dbAVTrans(db)), @intCast(nBytes));
        if (aVTrans == null) {
            return SQLITE_NOMEM_BKPT;
        }
        const arr: [*]u8 = @ptrCast(aVTrans.?);
        _ = memset(arr + @as(usize, @intCast(n)) * @sizeOf(usize), 0, @sizeOf(usize) * @as(usize, @intCast(ARRAY_INCR)));
        dbSetAVTrans(db, aVTrans);
    }
    return SQLITE_OK;
}

fn addToVTrans(db: ?*sqlite3, pVTab: ?*anyopaque) void {
    const n = dbNVTrans(db);
    dbAVTrans(db).?[@intCast(n)] = pVTab;
    dbSetNVTrans(db, n + 1);
    sqlite3VtabLock(pVTab);
}

// ===========================================================================
// sqlite3VtabCallCreate
// ===========================================================================
export fn sqlite3VtabCallCreate(db: ?*sqlite3, iDb: c_int, zTab: ?[*:0]const u8, pzErr: *?[*:0]u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pTab = sqlite3FindTable(db, zTab, dbZDbSName(db, iDb));
    std.debug.assert(pTab != null and isVirtual(pTab) and tabVtabP(pTab) == null);

    const azArg = tabVtabAzArg(pTab).?;
    const zMod = azArg[0];
    const pMod = sqlite3HashFind(dbAModule(db), @ptrCast(zMod));

    const xCreate: XConstructor = if (pMod != null) @ptrCast(modPtrAt(modPModule(pMod), MOD_xCreate)) else null;
    const xDestroy: ?*anyopaque = if (pMod != null) modPtrAt(modPModule(pMod), MOD_xDestroy) else null;
    if (pMod == null or xCreate == null or xDestroy == null) {
        pzErr.* = sqlite3MPrintf(db, "no such module: %s", @as(?[*:0]const u8, @ptrCast(zMod)));
        rc = SQLITE_ERROR;
    } else {
        rc = vtabCallConstructor(db, pTab, pMod, xCreate, pzErr);
    }

    if (rc == SQLITE_OK and sqlite3GetVTable(db, pTab) != null) { // ALWAYS()
        rc = growVTrans(db);
        if (rc == SQLITE_OK) {
            addToVTrans(db, sqlite3GetVTable(db, pTab));
        }
    }
    return rc;
}

// ===========================================================================
// sqlite3_declare_vtab
// ===========================================================================
export fn sqlite3_declare_vtab(db: ?*sqlite3, zCreateTable: ?[*:0]const u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const aKeyword = [_]c_int{ TK_CREATE, TK_TABLE, 0 };

    // SQLITE_ENABLE_API_ARMOR is OFF.

    // Verify the first two keywords are CREATE TABLE.
    var z: [*]const u8 = @ptrCast(zCreateTable.?);
    var ki: usize = 0;
    while (aKeyword[ki] != 0) : (ki += 1) {
        var tokenType: c_int = 0;
        while (true) {
            z += @intCast(sqlite3GetToken(z, &tokenType));
            if (tokenType != TK_SPACE and tokenType != TK_COMMENT) break;
        }
        if (tokenType != aKeyword[ki]) {
            sqlite3ErrorWithMsg(db, SQLITE_ERROR, "syntax error");
            return SQLITE_ERROR;
        }
    }

    sqlite3_mutex_enter(dbMutex(db));
    const pCtx = dbPVtabCtx(db);
    if (pCtx == null or pCtx.?.bDeclared != 0) {
        sqlite3Error(db, SQLITE_MISUSE_BKPT);
        sqlite3_mutex_leave(dbMutex(db));
        return SQLITE_MISUSE_BKPT;
    }

    const pTab = pCtx.?.pTab;
    std.debug.assert(isVirtual(pTab));

    // sParse — a stack Parse object.
    var sParseBuf: [sizeof_Parse]u8 align(16) = undefined;
    const sParse: ?*anyopaque = @ptrCast(&sParseBuf);
    sqlite3ParseObjectInit(sParse, db);
    parseSetEParseMode(sParse, PARSE_MODE_DECLARE_VTAB);
    parseSetDisableTriggers(sParse, true);
    std.debug.assert(dbInitBusy(db) == 0);
    const initBusy = dbInitBusy(db);
    dbSetInitBusy(db, 0);
    parseSetNQueryLoop(sParse, 1);
    if (SQLITE_OK == sqlite3RunParser(sParse, zCreateTable.?)) {
        const pNew = parsePNewTable(sParse);
        std.debug.assert(pNew != null);
        std.debug.assert(dbMallocFailed(db) == 0);
        std.debug.assert(parseZErrMsg(sParse) == null);
        if (tabACol(pTab) == null) {
            // pTab->aCol = pNew->aCol
            tabSetACol(pTab, tabACol(pNew));
            // sqlite3ExprListDelete(db, pNew->u.tab.pDfltList)
            sqlite3ExprListDelete(db, rdPtr(pNew, Table_u_tab_pDfltList_off));
            const ncol = tabNCol(pNew);
            tabSetNNVCol(pTab, ncol);
            tabSetNCol(pTab, ncol);
            // pTab->tabFlags |= pNew->tabFlags & (TF_WithoutRowid|TF_NoVisibleRowid)
            tabSetTabFlags(pTab, tabTabFlags(pTab) | (tabTabFlags(pNew) & (TF_WithoutRowid | TF_NoVisibleRowid)));
            tabSetNCol(pNew, 0);
            tabSetACol(pNew, null);
            std.debug.assert(tabPIndex(pTab) == null);
            // WITHOUT ROWID vtab restriction.
            const hasRowid = (tabTabFlags(pNew) & TF_WithoutRowid) == 0;
            if (!hasRowid) {
                const xUpdate = modPtrAt(modPModule(vtPMod(pCtx.?.pVTable)), MOD_xUpdate);
                if (xUpdate != null) {
                    const pPk = sqlite3PrimaryKeyIndex(pNew);
                    if (rd(u16, pPk, Index_nKeyCol_off) != 1) {
                        rc = SQLITE_ERROR;
                    }
                }
            }
            const pIdx = tabPIndex(pNew);
            if (pIdx != null) {
                std.debug.assert(rdPtr(pIdx, Index_pNext_off) == null);
                tabSetPIndex(pTab, pIdx);
                tabSetPIndex(pNew, null);
                // pIdx->pTable = pTab
                wrPtr(pIdx, Index_pTable_off, pTab);
            }
        }
        pCtx.?.bDeclared = 1;
    } else {
        const zErrMsg = parseZErrMsg(sParse);
        if (zErrMsg != null) {
            sqlite3ErrorWithMsg(db, SQLITE_ERROR, "%s", zErrMsg);
        } else {
            sqlite3ErrorWithMsg(db, SQLITE_ERROR, null);
        }
        sqlite3DbFree(db, @ptrCast(zErrMsg));
        rc = SQLITE_ERROR;
    }
    parseSetEParseMode(sParse, PARSE_MODE_NORMAL);

    if (parsePVdbe(sParse)) |pv| {
        _ = sqlite3VdbeFinalize(pv);
    }
    sqlite3DeleteTable(db, parsePNewTable(sParse));
    sqlite3ParseObjectReset(sParse);
    dbSetInitBusy(db, initBusy);

    std.debug.assert((rc & 0xff) == rc);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

// ===========================================================================
// sqlite3VtabCallDestroy
// ===========================================================================
export fn sqlite3VtabCallDestroy(db: ?*sqlite3, iDb: c_int, zTab: ?[*:0]const u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pTab = sqlite3FindTable(db, zTab, dbZDbSName(db, iDb));
    if (pTab != null and isVirtual(pTab) and tabVtabP(pTab) != null) { // ALWAYS chain
        // Refuse if any instance is locked.
        var p = tabVtabP(pTab);
        while (p) |pp| {
            std.debug.assert(vtPVtab(pp) != null);
            // p->pVtab->nRef  (sqlite3_vtab.nRef @ +8)
            const nRef = rd(c_int, vtPVtab(pp), 8);
            if (nRef > 0) {
                return SQLITE_LOCKED;
            }
            p = vtPNext(pp);
        }
        const pd = vtabDisconnectAll(db, pTab).?;
        var xDestroy: XVtabInt = @ptrCast(modPtrAt(modPModule(vtPMod(pd)), MOD_xDestroy));
        if (xDestroy == null) {
            xDestroy = @ptrCast(modPtrAt(modPModule(vtPMod(pd)), MOD_xDisconnect));
        }
        std.debug.assert(xDestroy != null);
        tabSetNTabRef(pTab, tabNTabRef(pTab) + 1);
        rc = xDestroy.?(vtPVtab(pd));
        if (rc == SQLITE_OK) {
            std.debug.assert(tabVtabP(pTab) == pd and vtPNext(pd) == null);
            vtSetPVtab(pd, null);
            tabSetVtabP(pTab, null);
            sqlite3VtabUnlock(pd);
        }
        sqlite3DeleteTable(db, pTab);
    }
    return rc;
}

// ===========================================================================
// callFinaliser (static)
// ===========================================================================
fn callFinaliser(db: ?*sqlite3, offset: usize) void {
    if (dbAVTrans(db)) |aVTrans| {
        dbSetAVTrans(db, null);
        const n = dbNVTrans(db);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            const pVTab = aVTrans[@intCast(i)];
            const p = vtPVtab(pVTab);
            if (p) |pv| {
                // x = *(fn**)((char*)p->pModule + offset)
                const pModule = rdPtr(pv, 0);
                const x: XVtabInt = @ptrCast(rdPtr(pModule, offset));
                if (x != null) _ = x.?(pv);
            }
            vtSetISavepoint(pVTab, 0);
            sqlite3VtabUnlock(pVTab);
        }
        sqlite3DbFree(db, @ptrCast(aVTrans));
        dbSetNVTrans(db, 0);
    }
}

// ===========================================================================
// sqlite3VtabSync
// ===========================================================================
export fn sqlite3VtabSync(db: ?*sqlite3, p: ?*Vdbe) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const aVTrans = dbAVTrans(db);
    dbSetAVTrans(db, null);
    const n = dbNVTrans(db);
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < n) : (i += 1) {
        const pVtab = vtPVtab(aVTrans.?[@intCast(i)]);
        if (pVtab) |pv| {
            const pModule = rdPtr(pv, 0);
            const x: XVtabInt = @ptrCast(rdPtr(pModule, MOD_xSync));
            if (x != null) {
                rc = x.?(pv);
                sqlite3VtabImportErrmsg(p, pv);
            }
        }
    }
    dbSetAVTrans(db, @ptrCast(aVTrans));
    return rc;
}

// ===========================================================================
// sqlite3VtabRollback / sqlite3VtabCommit
// ===========================================================================
export fn sqlite3VtabRollback(db: ?*sqlite3) callconv(.c) c_int {
    callFinaliser(db, SQLITE_MODULE_xRollback_off);
    return SQLITE_OK;
}

export fn sqlite3VtabCommit(db: ?*sqlite3) callconv(.c) c_int {
    callFinaliser(db, SQLITE_MODULE_xCommit_off);
    return SQLITE_OK;
}

// ===========================================================================
// sqlite3VtabBegin
// ===========================================================================
export fn sqlite3VtabBegin(db: ?*sqlite3, pVTab: ?*anyopaque) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (vtabInSync(db)) {
        return SQLITE_LOCKED;
    }
    if (pVTab == null) {
        return SQLITE_OK;
    }
    // pModule = pVTab->pVtab->pModule
    const pVtab = vtPVtab(pVTab).?;
    const pModule = rdPtr(pVtab, 0);

    const xBegin: XVtabInt = @ptrCast(rdPtr(pModule, MOD_xBegin));
    if (xBegin != null) {
        const n = dbNVTrans(db);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            if (dbAVTrans(db).?[@intCast(i)] == pVTab) {
                return SQLITE_OK;
            }
        }
        rc = growVTrans(db);
        if (rc == SQLITE_OK) {
            rc = xBegin.?(pVtab);
            if (rc == SQLITE_OK) {
                const iSvpt = dbNStatement(db) + dbNSavepoint(db);
                addToVTrans(db, pVTab);
                const xSavepoint: XVtabIntInt = @ptrCast(rdPtr(pModule, MOD_xSavepoint));
                if (iSvpt != 0 and xSavepoint != null) {
                    vtSetISavepoint(pVTab, iSvpt);
                    rc = xSavepoint.?(pVtab, iSvpt - 1);
                }
            }
        }
    }
    return rc;
}

// ===========================================================================
// sqlite3VtabSavepoint
// ===========================================================================
export fn sqlite3VtabSavepoint(db: ?*sqlite3, op: c_int, iSavepoint: c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    std.debug.assert(op == SAVEPOINT_RELEASE or op == SAVEPOINT_ROLLBACK or op == SAVEPOINT_BEGIN);
    std.debug.assert(iSavepoint >= -1);
    if (dbAVTrans(db)) |aVTrans| {
        const n = dbNVTrans(db);
        var i: c_int = 0;
        while (rc == SQLITE_OK and i < n) : (i += 1) {
            const pVTab = aVTrans[@intCast(i)];
            const pMod = modPModule(vtPMod(pVTab));
            if (vtPVtab(pVTab) != null and modIVersion(pMod) >= 2) {
                var xMethod: XVtabIntInt = undefined;
                sqlite3VtabLock(pVTab);
                switch (op) {
                    SAVEPOINT_BEGIN => {
                        xMethod = @ptrCast(modPtrAt(pMod, MOD_xSavepoint));
                        vtSetISavepoint(pVTab, iSavepoint + 1);
                    },
                    SAVEPOINT_ROLLBACK => {
                        xMethod = @ptrCast(modPtrAt(pMod, MOD_xRollbackTo));
                    },
                    else => {
                        xMethod = @ptrCast(modPtrAt(pMod, MOD_xRelease));
                    },
                }
                if (xMethod != null and vtISavepoint(pVTab) > iSavepoint) {
                    const savedFlags = dbFlags(db) & SQLITE_Defensive;
                    dbSetFlags(db, dbFlags(db) & ~SQLITE_Defensive);
                    rc = xMethod.?(vtPVtab(pVTab), iSavepoint);
                    dbSetFlags(db, dbFlags(db) | savedFlags);
                }
                sqlite3VtabUnlock(pVTab);
            }
        }
    }
    return rc;
}

// ===========================================================================
// sqlite3VtabOverloadFunction
// ===========================================================================
// Expr / FuncDef field offsets used here (config-invariant).
const Expr_op_off: usize = 0;
const Expr_y_pTab_off: usize = 64; // Expr.y.pTab (the y union) — probe-verified, config-invariant
const FuncDef_funcFlags_off: usize = 4;
const FuncDef_xSFunc_off: usize = 24;
const FuncDef_pUserData_off: usize = 8;
const FuncDef_zName_off: usize = 56;
const sizeof_FuncDef: usize = 72;

export fn sqlite3VtabOverloadFunction(
    db: ?*sqlite3,
    pDef: ?*anyopaque,
    nArg: c_int,
    pExpr: ?*anyopaque,
) callconv(.c) ?*anyopaque {
    var xSFunc: ?*anyopaque = null;
    var pArg: ?*anyopaque = null;
    var rc: c_int = 0;

    if (pExpr == null) return pDef; // NEVER()
    // pExpr->op != TK_COLUMN
    if (base(pExpr)[Expr_op_off] != @as(u8, @intCast(TK_COLUMN))) return pDef;
    // pTab = pExpr->y.pTab
    const pTab = rdPtr(pExpr, Expr_y_pTab_off);
    if (pTab == null) return pDef; // NEVER()
    if (!isVirtual(pTab)) return pDef;
    const pVtab = vtPVtab(sqlite3GetVTable(db, pTab)).?;
    const pMod = rdPtr(pVtab, 0); // sqlite3_vtab.pModule
    const xFindFunction: XFindFunction = @ptrCast(rdPtr(pMod, MOD_xFindFunction));
    if (xFindFunction == null) return pDef;

    const zName: ?[*:0]const u8 = @ptrCast(rdPtr(pDef, FuncDef_zName_off));
    rc = xFindFunction.?(pVtab, nArg, zName, &xSFunc, &pArg);
    if (rc == 0) {
        return pDef;
    }

    // Create a new ephemeral FuncDef.
    const nName: u64 = @intCast(sqlite3Strlen30(zName) + 1);
    const pNew = sqlite3DbMallocZero(db, sizeof_FuncDef + nName);
    if (pNew == null) {
        return pDef;
    }
    // *pNew = *pDef
    _ = memcpy(pNew, pDef, sizeof_FuncDef);
    // pNew->zName = (const char*)&pNew[1]
    const after: [*]u8 = base(pNew) + sizeof_FuncDef;
    wrPtr(pNew, FuncDef_zName_off, @ptrCast(after));
    _ = memcpy(after, zName, @intCast(nName));
    wrPtr(pNew, FuncDef_xSFunc_off, xSFunc);
    wrPtr(pNew, FuncDef_pUserData_off, pArg);
    // pNew->funcFlags |= SQLITE_FUNC_EPHEM
    const ff = fieldPtr(u32, pNew, FuncDef_funcFlags_off);
    ff.* |= SQLITE_FUNC_EPHEM;
    return pNew;
}

// ===========================================================================
// sqlite3VtabMakeWritable
// ===========================================================================
export fn sqlite3VtabMakeWritable(pParse: ?*anyopaque, pTab: ?*anyopaque) callconv(.c) void {
    const pToplevel = parsePToplevel(pParse);
    std.debug.assert(isVirtual(pTab));
    const nLock = parseNVtabLock(pToplevel);
    const apLock = parseApVtabLock(pToplevel);
    var i: c_int = 0;
    while (i < nLock) : (i += 1) {
        if (pTab == apLock.?[@intCast(i)]) return;
    }
    const n: usize = @intCast(@as(c_int, nLock + 1) * @sizeOf(usize));
    const apVtabLock = sqlite3Realloc(@ptrCast(apLock), n);
    if (apVtabLock != null) {
        parseSetApVtabLock(pToplevel, apVtabLock);
        const arr: [*]?*anyopaque = @ptrCast(@alignCast(apVtabLock.?));
        arr[@intCast(nLock)] = pTab;
        parseSetNVtabLock(pToplevel, nLock + 1);
    } else {
        _ = sqlite3OomFault(parseDb(pToplevel));
    }
}

// ===========================================================================
// sqlite3VtabEponymousTableInit
// ===========================================================================
export fn sqlite3VtabEponymousTableInit(pParse: ?*anyopaque, pMod: ?*anyopaque) callconv(.c) c_int {
    const pModule = modPModule(pMod);
    var zErr: ?[*:0]u8 = null;
    const db = parseDb(pParse);

    if (modPEpoTab(pMod) != null) return 1;
    const xCreate = modPtrAt(pModule, MOD_xCreate);
    const xConnect = modPtrAt(pModule, MOD_xConnect);
    if (xCreate != null and xCreate != xConnect) return 0;

    const pTab = sqlite3DbMallocZero(db, sizeOfTable());
    if (pTab == null) return 0;
    tabSetZName(pTab, sqlite3DbStrDup(db, modZName(pMod)));
    if (tabZName(pTab) == null) {
        sqlite3DbFree(db, pTab);
        return 0;
    }
    modSetPEpoTab(pMod, pTab);
    tabSetNTabRef(pTab, 1);
    tabSetETabType(pTab, TABTYP_VTAB);
    tabSetPSchema(pTab, dbSchema(db, 0));
    std.debug.assert(tabVtabNArg(pTab) == 0);
    tabSetIPKey(pTab, -1);
    tabSetTabFlags(pTab, tabTabFlags(pTab) | TF_Eponymous);
    addModuleArgument(pParse, pTab, sqlite3DbStrDup(db, tabZName(pTab)));
    addModuleArgument(pParse, pTab, null);
    addModuleArgument(pParse, pTab, sqlite3DbStrDup(db, tabZName(pTab)));
    dbSetNSchemaLock(db, dbNSchemaLock(db) + 1);
    const xConnectFn: XConstructor = @ptrCast(xConnect);
    const rc = vtabCallConstructor(db, pTab, pMod, xConnectFn, &zErr);
    dbSetNSchemaLock(db, dbNSchemaLock(db) - 1);
    if (rc != 0) {
        sqlite3ErrorMsg(pParse, "%s", zErr);
        parseSetRc(pParse, rc);
        sqlite3DbFree(db, @ptrCast(zErr));
        sqlite3VtabEponymousTableClear(db, pMod);
    }
    return 1;
}

// sizeof(struct Table) — config-invariant; probe value. Falls back to 112.
fn sizeOfTable() u64 {
    return if (@hasDecl(L, "sizeof_Table")) L.sizeof_Table else 120;
}

// ===========================================================================
// sqlite3VtabEponymousTableClear
// ===========================================================================
export fn sqlite3VtabEponymousTableClear(db: ?*sqlite3, pMod: ?*anyopaque) callconv(.c) void {
    const pTab = modPEpoTab(pMod);
    if (pTab != null) {
        tabSetTabFlags(pTab, tabTabFlags(pTab) | TF_Ephemeral);
        sqlite3DeleteTable(db, pTab);
        modSetPEpoTab(pMod, null);
    }
}

// ===========================================================================
// sqlite3_vtab_on_conflict
// ===========================================================================
export fn sqlite3_vtab_on_conflict(db: ?*sqlite3) callconv(.c) c_int {
    const aMap = [_]u8{ SQLITE_ROLLBACK, SQLITE_ABORT, SQLITE_FAIL, SQLITE_IGNORE, SQLITE_REPLACE };
    // SQLITE_ENABLE_API_ARMOR is OFF.
    const v = dbVtabOnConflict(db);
    std.debug.assert(v >= 1 and v <= 5);
    return @intCast(aMap[v - 1]);
}

// ===========================================================================
// sqlite3_vtab_config (variadic)
// ===========================================================================
export fn sqlite3_vtab_config(db: ?*sqlite3, op: c_int, ...) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    // SQLITE_ENABLE_API_ARMOR is OFF.
    sqlite3_mutex_enter(dbMutex(db));
    const p = dbPVtabCtx(db);
    if (p == null) {
        rc = SQLITE_MISUSE_BKPT;
    } else {
        std.debug.assert(p.?.pTab == null or isVirtual(p.?.pTab));
        var ap = @cVaStart();
        switch (op) {
            SQLITE_VTAB_CONSTRAINT_SUPPORT => {
                const v: c_int = @cVaArg(&ap, c_int);
                vtSetBConstraint(p.?.pVTable, @truncate(@as(u32, @bitCast(v))));
            },
            SQLITE_VTAB_INNOCUOUS => {
                vtSetEVtabRisk(p.?.pVTable, SQLITE_VTABRISK_Low);
            },
            SQLITE_VTAB_DIRECTONLY => {
                vtSetEVtabRisk(p.?.pVTable, SQLITE_VTABRISK_High);
            },
            SQLITE_VTAB_USES_ALL_SCHEMAS => {
                vtSetBAllSchemas(p.?.pVTable, 1);
            },
            else => {
                rc = SQLITE_MISUSE_BKPT;
            },
        }
        @cVaEnd(&ap);
    }
    if (rc != SQLITE_OK) sqlite3Error(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

// p.?.pVTable accessor — VtabCtx.pVTable is a VTable*.
// (Used by sqlite3_vtab_config; expressed via the VtabCtx mirror.)

comptime {
    // sanity: VtabCtx mirror size matches the C struct (4 ptr-ish fields).
    std.debug.assert(@sizeOf(VtabCtx) == 32);
    std.debug.assert(@offsetOf(VtabCtx, "pTab") == 8);
    std.debug.assert(@offsetOf(VtabCtx, "pPrior") == 16);
    std.debug.assert(@offsetOf(VtabCtx, "bDeclared") == 24);
}
