//! Zig port of SQLite's src/prepare.c — the sqlite3_prepare() family and the
//! routines that load the database schema from disk.
//!
//! Exported (non-static) symbols — the complete external set of prepare.c,
//! matching the prototypes in sqliteInt.h / vdbe.h / sqlite.h:
//!   - sqlite3IndexHasDuplicateRootPage
//!   - sqlite3InitCallback
//!   - sqlite3InitOne
//!   - sqlite3Init
//!   - sqlite3ReadSchema
//!   - sqlite3SchemaToIndex
//!   - sqlite3ParseObjectReset
//!   - sqlite3ParserAddCleanup
//!   - sqlite3ParseObjectInit
//!   - sqlite3Reprepare
//!   - sqlite3_prepare        sqlite3_prepare_v2     sqlite3_prepare_v3
//!   - sqlite3_prepare16      sqlite3_prepare16_v2   sqlite3_prepare16_v3
//! The static helpers (corruptSchema, sqlite3Prepare, sqlite3LockAndPrepare,
//! schemaIsValid, sqlite3Prepare16) are private to this module.
//!
//! ─── Struct coupling ──────────────────────────────────────────────────────
//! This module reads/writes a large number of internal `sqlite3`, `Parse`,
//! `Db`, `Schema`, and `Vdbe` fields. Every offset used here was probe-verified
//! (tools/offsets.c-style offsetof program) in BOTH the production library
//! config and the `--dev` testfixture (SQLITE_DEBUG + SQLITE_TEST) config:
//!
//!   * Every `sqlite3` field used (pVdbe, nDb, mDbFlags, flags, errCode, enc,
//!     mallocFailed, eOpenState, aDb, aLimit, pParse, mutex, busyHandler,
//!     noSharedCache, init.{newTnum,iDb,busy,orphanTrigger,azInit},
//!     lookaside.{bDisable,sz,szTrue}, xAuth, pDisconnect) has an IDENTICAL
//!     offset in both configs.
//!   * Every `Parse` field used (db, zErrMsg, pVdbe, rc, nQueryLoop, nested,
//!     disableLookaside, prepFlags, nTableLock, pTriggerPrg, pCleanup, aLabel,
//!     pConstExpr, pOuterParse, explain, pReprepare, zTail) has an IDENTICAL
//!     offset in both configs.
//!   * Db (zDbSName, pBt, pSchema) and Schema (schema_cookie, iGeneration,
//!     schemaFlags, enc, file_format, cache_size) are config-invariant.
//!
//!   * EXCEPTION — Parse.checkSchema is a 1-bit BITFIELD whose containing byte
//!     DIFFERS between configs because the SQLITE_DEBUG-only bytes
//!     (earlyCleanup, ifNotExists, isCreate) precede the bitfield group:
//!         prod: byte 40  (bit 0x01)
//!         tf  : byte 43  (bit 0x01)
//!     handled via a config-selected offset (parse_checkSchema_byte).
//!
//! ─── Config assumptions (true in both this project's builds) ───────────────
//!   * SQLITE_OMIT_UTF16        OFF → prepare16 family compiled.
//!   * SQLITE_OMIT_AUTHORIZATION OFF → xAuth save/restore in sqlite3InitOne.
//!   * SQLITE_OMIT_VIRTUALTABLE OFF → pDisconnect handling in sqlite3Prepare.
//!   * SQLITE_OMIT_ANALYZE      OFF → sqlite3AnalysisLoad called.
//!   * SQLITE_OMIT_SHARED_CACHE OFF → nTableLock/aTableLock freed in reset.
//!   * SQLITE_OMIT_DEPRECATED   OFF → cache_size computed from meta in InitOne.
//!   * SQLITE_OMIT_TEMPDB       OFF → SCHEMA_TABLE(1) == "sqlite_temp_master".
//!   * SQLITE_ENABLE_API_ARMOR  OFF → the ppStmt==0 armor checks are omitted.
//!   * Little-endian x86-64.
//!
//! No standalone Zig unit test is feasible — every path couples to the live
//! connection, parser, btree and VDBE. Validated through the engine by the TCL
//! suite (every prepare/schema-load path exercises this module).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── Result codes ───────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_SCHEMA: c_int = 17;
const SQLITE_TOOBIG: c_int = 18;
const SQLITE_DONE: c_int = 101;
const SQLITE_ERROR_RETRY: c_int = SQLITE_ERROR | (2 << 8); // 513
const SQLITE_IOERR_NOMEM: c_int = SQLITE_IOERR | (12 << 8);

// ─── Text encodings ─────────────────────────────────────────────────────────
const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_UTF16NATIVE: u8 = SQLITE_UTF16LE; // little-endian x86-64

// ─── prepFlags ──────────────────────────────────────────────────────────────
const SQLITE_PREPARE_PERSISTENT: u32 = 0x01;
const SQLITE_PREPARE_MASK: u32 = 0x3f;
const SQLITE_PREPARE_SAVESQL: u32 = 0x80;

// ─── sqlite3.flags bits ─────────────────────────────────────────────────────
const SQLITE_WriteSchema: u64 = 0x00000001;
const SQLITE_LegacyFileFmt: u64 = 0x00000002;
const SQLITE_ResetDatabase: u64 = 0x02000000;
const SQLITE_NoSchemaError: u64 = 0x08000000;

// ─── sqlite3.mDbFlags bits ──────────────────────────────────────────────────
const DBFLAG_SchemaChange: u32 = 0x0001;
const DBFLAG_EncodingFixed: u32 = 0x0040;

// ─── Schema.schemaFlags bits ────────────────────────────────────────────────
const DB_SchemaLoaded: u16 = 0x0001;

// ─── InitData.mInitFlags bits ───────────────────────────────────────────────
const INITFLAG_AlterMask: u32 = 0x0007;
const INITFLAG_AlterAdd: u32 = 0x0003;

// ─── Btree meta indices / txn / file-format ─────────────────────────────────
const BTREE_SCHEMA_VERSION: c_int = 1;
const BTREE_FILE_FORMAT: c_int = 2;
const BTREE_DEFAULT_CACHE_SIZE: c_int = 3;
const BTREE_TEXT_ENCODING: c_int = 5;
const SQLITE_TXN_NONE: c_int = 0;
const SQLITE_MAX_FILE_FORMAT: u8 = 4;
const SQLITE_DEFAULT_CACHE_SIZE: c_int = -2000;

const SQLITE_LIMIT_SQL_LENGTH: usize = 1;
const SQLITE_MAX_PREPARE_RETRY: c_int = 25;

// ─── Sqlite3Config.bExtraSchemaChecks ───────────────────────────────────────
// Offset 9 in both configs (bJsonSelfcheck, the only DEBUG field that could
// shift it, sits AFTER it).
const Config_bExtraSchemaChecks_off: usize = 9;

// ═══ ground-truth offsets ═══════════════════════════════════════════════════
// Reuse c_layout entries where present, else the probe-verified fallback. All
// of these (except Parse.checkSchema below) are identical in prod and tf.

const sqlite3_pVdbe_off: usize = if (@hasDecl(L, "sqlite3_pVdbe")) L.sqlite3_pVdbe else 8;
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_mDbFlags_off: usize = if (@hasDecl(L, "sqlite3_mDbFlags")) L.sqlite3_mDbFlags else 44;
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_errCode_off: usize = if (@hasDecl(L, "sqlite3_errCode")) L.sqlite3_errCode else 80;
const sqlite3_enc_off: usize = if (@hasDecl(L, "sqlite3_enc")) L.sqlite3_enc else 100;
const sqlite3_noSharedCache_off: usize = if (@hasDecl(L, "sqlite3_noSharedCache")) L.sqlite3_noSharedCache else 111;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_aLimit_off: usize = if (@hasDecl(L, "sqlite3_aLimit")) L.sqlite3_aLimit else 136;
const sqlite3_pParse_off: usize = if (@hasDecl(L, "sqlite3_pParse")) L.sqlite3_pParse else 344;
const sqlite3_mutex_off: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const sqlite3_busyHandler_off: usize = if (@hasDecl(L, "sqlite3_busyHandler")) L.sqlite3_busyHandler else 664;
const sqlite3_xAuth_off: usize = if (@hasDecl(L, "sqlite3_xAuth")) L.sqlite3_xAuth else 528;
const sqlite3_pDisconnect_off: usize = if (@hasDecl(L, "sqlite3_pDisconnect")) L.sqlite3_pDisconnect else 608;

// init sub-struct (sqlite3.init is at offset 192; fields synthesized)
const sqlite3_init_newTnum_off: usize = if (@hasDecl(L, "sqlite3_init_newTnum")) L.sqlite3_init_newTnum else 192;
const sqlite3_init_iDb_off: usize = if (@hasDecl(L, "sqlite3_init_iDb")) L.sqlite3_init_iDb else 196;
const sqlite3_initBusy_off: usize = if (@hasDecl(L, "sqlite3_initBusy")) L.sqlite3_initBusy else 197;
// orphanTrigger is bit 0x01 of the byte right after busy (offset 198).
const sqlite3_init_bitbyte_off: usize = if (@hasDecl(L, "sqlite3_init_bitbyte")) L.sqlite3_init_bitbyte else 198;
const sqlite3_init_azInit_off: usize = if (@hasDecl(L, "sqlite3_init_azInit")) L.sqlite3_init_azInit else 200;

// lookaside sub-struct (sqlite3.lookaside at 432)
const sqlite3_lookaside_bDisable_off: usize = if (@hasDecl(L, "sqlite3_lookaside_bDisable")) L.sqlite3_lookaside_bDisable else 432;
const sqlite3_lookaside_sz_off: usize = if (@hasDecl(L, "sqlite3_lookaside_sz")) L.sqlite3_lookaside_sz else 436;
const sqlite3_lookaside_szTrue_off: usize = if (@hasDecl(L, "sqlite3_lookaside_szTrue")) L.sqlite3_lookaside_szTrue else 438;

// busyHandler.nBusy lives 16 bytes into BusyHandler.
const BusyHandler_nBusy_off: usize = 16;

// Parse fields
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_zErrMsg_off: usize = if (@hasDecl(L, "Parse_zErrMsg")) L.Parse_zErrMsg else 8;
const Parse_pVdbe_off: usize = if (@hasDecl(L, "Parse_pVdbe")) L.Parse_pVdbe else 16;
const Parse_rc_off: usize = if (@hasDecl(L, "Parse_rc")) L.Parse_rc else 24;
const Parse_nQueryLoop_off: usize = if (@hasDecl(L, "Parse_nQueryLoop")) L.Parse_nQueryLoop else 28;
const Parse_nested_off: usize = if (@hasDecl(L, "Parse_nested")) L.Parse_nested else 30;
const Parse_disableLookaside_off: usize = if (@hasDecl(L, "Parse_disableLookaside")) L.Parse_disableLookaside else 33;
const Parse_prepFlags_off: usize = if (@hasDecl(L, "Parse_prepFlags")) L.Parse_prepFlags else 34;
const Parse_nTableLock_off: usize = if (@hasDecl(L, "Parse_nTableLock")) L.Parse_nTableLock else 132;
const Parse_aTableLock_off: usize = if (@hasDecl(L, "Parse_aTableLock")) L.Parse_aTableLock else 192;
const Parse_pTriggerPrg_off: usize = if (@hasDecl(L, "Parse_pTriggerPrg")) L.Parse_pTriggerPrg else 152;
const Parse_pCleanup_off: usize = if (@hasDecl(L, "Parse_pCleanup")) L.Parse_pCleanup else 160;
const Parse_aLabel_off: usize = if (@hasDecl(L, "Parse_aLabel")) L.Parse_aLabel else 80;
const Parse_pConstExpr_off: usize = if (@hasDecl(L, "Parse_pConstExpr")) L.Parse_pConstExpr else 88;
const Parse_pOuterParse_off: usize = if (@hasDecl(L, "Parse_pOuterParse")) L.Parse_pOuterParse else 200;
const Parse_explain_off: usize = if (@hasDecl(L, "Parse_explain")) L.Parse_explain else 299;
const Parse_pReprepare_off: usize = if (@hasDecl(L, "Parse_pReprepare")) L.Parse_pReprepare else 328;
const Parse_zTail_off: usize = if (@hasDecl(L, "Parse_zTail")) L.Parse_zTail else 336;

// Parse.checkSchema BITFIELD — DIFFERS between configs (bit 0x01 within byte).
const Parse_checkSchema_byte: usize = if (@hasDecl(L, "Parse_checkSchema_byte"))
    L.Parse_checkSchema_byte
else if (config.sqlite_debug) 43 else 40;
const PARSE_CHECKSCHEMA_BIT: u8 = 0x01;

// Db / Schema
const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pBt_off: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;
const Db_pSchema_off: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

const Schema_schema_cookie_off: usize = 0;
const Schema_iGeneration_off: usize = 4;
const Schema_file_format_off: usize = 112;
const Schema_enc_off: usize = 113;
const Schema_schemaFlags_off: usize = if (@hasDecl(L, "Schema_schemaFlags")) L.Schema_schemaFlags else 114;
const Schema_cache_size_off: usize = 116;

// ═══ sqlite3 field accessors ════════════════════════════════════════════════
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rdPtr(comptime T: type, p: ?*anyopaque, off: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + off);
    return q.*;
}
inline fn wrPtr(comptime T: type, p: ?*anyopaque, off: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + off);
    q.* = v;
}

inline fn dbPVdbe(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_pVdbe_off);
}
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rdPtr(c_int, db, sqlite3_nDb_off);
}
inline fn dbMDbFlags(db: ?*anyopaque) u32 {
    return rdPtr(u32, db, sqlite3_mDbFlags_off);
}
inline fn dbSetMDbFlags(db: ?*anyopaque, v: u32) void {
    wrPtr(u32, db, sqlite3_mDbFlags_off, v);
}
inline fn dbFlags(db: ?*anyopaque) u64 {
    return rdPtr(u64, db, sqlite3_flags_off);
}
inline fn dbSetFlags(db: ?*anyopaque, v: u64) void {
    wrPtr(u64, db, sqlite3_flags_off, v);
}
inline fn dbErrCode(db: ?*anyopaque) c_int {
    return rdPtr(c_int, db, sqlite3_errCode_off);
}
inline fn dbSetErrCode(db: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, db, sqlite3_errCode_off, v);
}
inline fn dbEnc(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_enc_off];
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}
inline fn dbNoSharedCache(db: ?*anyopaque) bool {
    return base(db)[sqlite3_noSharedCache_off] != 0;
}
inline fn dbADb(db: ?*anyopaque) [*]u8 {
    // aDb is a `Db*` pointer field; dereference to the array base.
    return @ptrCast(rdPtr(?*anyopaque, db, sqlite3_aDb_off).?);
}
// Pointer to Db[i]
inline fn dbAt(db: ?*anyopaque, i: c_int) [*]u8 {
    return dbADb(db) + (@as(usize, @intCast(i)) * sizeof_Db);
}
inline fn dbAtZName(db: ?*anyopaque, i: c_int) ?[*:0]const u8 {
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(dbAt(db, i) + Db_zDbSName_off);
    return q.*;
}
inline fn dbAtPBt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const q: *align(1) const ?*anyopaque = @ptrCast(dbAt(db, i) + Db_pBt_off);
    return q.*;
}
inline fn dbAtPSchema(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const q: *align(1) const ?*anyopaque = @ptrCast(dbAt(db, i) + Db_pSchema_off);
    return q.*;
}
inline fn dbALimit(db: ?*anyopaque, lim: usize) c_int {
    const q: *align(1) const c_int = @ptrCast(base(db) + sqlite3_aLimit_off + lim * @sizeOf(c_int));
    return q.*;
}
inline fn dbMutex(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_mutex_off);
}
inline fn dbXAuth(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_xAuth_off);
}
inline fn dbSetXAuth(db: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, db, sqlite3_xAuth_off, v);
}
inline fn dbPDisconnect(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_pDisconnect_off);
}
inline fn dbBusyHandlerNBusyPtr(db: ?*anyopaque) *align(1) c_int {
    return @ptrCast(base(db) + sqlite3_busyHandler_off + BusyHandler_nBusy_off);
}

// init.*
inline fn initIDb(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_init_iDb_off];
}
inline fn setInitIDb(db: ?*anyopaque, v: u8) void {
    base(db)[sqlite3_init_iDb_off] = v;
}
inline fn initBusy(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_initBusy_off];
}
inline fn setInitBusy(db: ?*anyopaque, v: u8) void {
    base(db)[sqlite3_initBusy_off] = v;
}
inline fn initNewTnumPtr(db: ?*anyopaque) *align(1) u32 {
    return @ptrCast(base(db) + sqlite3_init_newTnum_off);
}
inline fn setInitOrphanTrigger(db: ?*anyopaque, on: bool) void {
    const b = base(db) + sqlite3_init_bitbyte_off;
    if (on) {
        b[0] |= 0x01;
    } else {
        b[0] &= ~@as(u8, 0x01);
    }
}
inline fn initOrphanTrigger(db: ?*anyopaque) bool {
    return (base(db)[sqlite3_init_bitbyte_off] & 0x01) != 0;
}
inline fn setInitAzInit(db: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, db, sqlite3_init_azInit_off, v);
}

// lookaside
inline fn laBDisable(db: ?*anyopaque) u32 {
    return rdPtr(u32, db, sqlite3_lookaside_bDisable_off);
}
inline fn setLaBDisable(db: ?*anyopaque, v: u32) void {
    wrPtr(u32, db, sqlite3_lookaside_bDisable_off, v);
}
inline fn setLaSz(db: ?*anyopaque, v: u16) void {
    wrPtr(u16, db, sqlite3_lookaside_sz_off, v);
}
inline fn laSzTrue(db: ?*anyopaque) u16 {
    return rdPtr(u16, db, sqlite3_lookaside_szTrue_off);
}

// ═══ Parse field accessors ══════════════════════════════════════════════════
inline fn pDb(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_db_off);
}
inline fn pSetDb(pParse: ?*anyopaque, db: ?*anyopaque) void {
    wrPtr(?*anyopaque, pParse, Parse_db_off, db);
}
inline fn pZErrMsg(pParse: ?*anyopaque) ?[*:0]u8 {
    return rdPtr(?[*:0]u8, pParse, Parse_zErrMsg_off);
}
inline fn pZErrMsgPtr(pParse: ?*anyopaque) *align(1) ?*anyopaque {
    return @ptrCast(base(pParse) + Parse_zErrMsg_off);
}
inline fn pPVdbe(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_pVdbe_off);
}
inline fn pRc(pParse: ?*anyopaque) c_int {
    return rdPtr(c_int, pParse, Parse_rc_off);
}
inline fn pSetRc(pParse: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, pParse, Parse_rc_off, v);
}
inline fn pNQueryLoop(pParse: ?*anyopaque) i16 {
    return rdPtr(i16, pParse, Parse_nQueryLoop_off);
}
inline fn pNErr(pParse: ?*anyopaque) c_int {
    return rdPtr(c_int, pParse, c_layout_Parse_nErr);
}
inline fn pSetNErr(pParse: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, pParse, c_layout_Parse_nErr, v);
}
const c_layout_Parse_nErr: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;

inline fn pNested(pParse: ?*anyopaque) u8 {
    return base(pParse)[Parse_nested_off];
}
inline fn pDisableLookaside(pParse: ?*anyopaque) u8 {
    return base(pParse)[Parse_disableLookaside_off];
}
inline fn pSetDisableLookaside(pParse: ?*anyopaque, v: u8) void {
    base(pParse)[Parse_disableLookaside_off] = v;
}
inline fn pSetPrepFlags(pParse: ?*anyopaque, v: u8) void {
    base(pParse)[Parse_prepFlags_off] = v;
}
inline fn pNTableLock(pParse: ?*anyopaque) c_int {
    return rdPtr(c_int, pParse, Parse_nTableLock_off);
}
inline fn pATableLock(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_aTableLock_off);
}
inline fn pPTriggerPrg(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_pTriggerPrg_off);
}
inline fn pSetPTriggerPrg(pParse: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pParse, Parse_pTriggerPrg_off, v);
}
inline fn pPCleanup(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_pCleanup_off);
}
inline fn pSetPCleanup(pParse: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pParse, Parse_pCleanup_off, v);
}
inline fn pALabel(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_aLabel_off);
}
inline fn pPConstExpr(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_pConstExpr_off);
}
inline fn pPOuterParse(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_pOuterParse_off);
}
inline fn pSetPOuterParse(pParse: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pParse, Parse_pOuterParse_off, v);
}
inline fn pSetExplain(pParse: ?*anyopaque, v: u8) void {
    base(pParse)[Parse_explain_off] = v;
}
inline fn pPReprepare(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_pReprepare_off);
}
inline fn pSetPReprepare(pParse: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pParse, Parse_pReprepare_off, v);
}
inline fn pZTail(pParse: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, pParse, Parse_zTail_off);
}
inline fn pSetZTail(pParse: ?*anyopaque, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, pParse, Parse_zTail_off, v);
}
inline fn pCheckSchema(pParse: ?*anyopaque) bool {
    return (base(pParse)[Parse_checkSchema_byte] & PARSE_CHECKSCHEMA_BIT) != 0;
}
inline fn pSetCheckSchema(pParse: ?*anyopaque, on: bool) void {
    const b = &base(pParse)[Parse_checkSchema_byte];
    if (on) {
        b.* |= PARSE_CHECKSCHEMA_BIT;
    } else {
        b.* &= ~PARSE_CHECKSCHEMA_BIT;
    }
}

// PARSE_HDR / PARSE_TAIL regions (config-invariant offsets).
const PARSE_HDR_off: usize = Parse_zErrMsg_off; // 8
const PARSE_HDR_SZ: usize = if (@hasDecl(L, "PARSE_HDR_SZ")) L.PARSE_HDR_SZ else 160;
const PARSE_RECURSE_SZ: usize = if (@hasDecl(L, "PARSE_RECURSE_SZ")) L.PARSE_RECURSE_SZ else 280;
const sizeof_Parse: usize = if (@hasDecl(L, "sizeof_Parse")) L.sizeof_Parse else 416;
const PARSE_TAIL_SZ: usize = sizeof_Parse - PARSE_RECURSE_SZ; // 136

// Zero the two init regions of a Parse object (mirrors the C inlined memset).
inline fn parseZeroRegions(pParse: ?*anyopaque) void {
    const b = base(pParse);
    @memset(b[PARSE_HDR_off .. PARSE_HDR_off + PARSE_HDR_SZ], 0);
    @memset(b[PARSE_RECURSE_SZ .. PARSE_RECURSE_SZ + PARSE_TAIL_SZ], 0);
}

// ═══ Index / Schema field offsets (config-invariant) ════════════════════════
// prepare.c touches Index.{pTable, pNext, tnum} and Table.pIndex.
const Index_pTable_off: usize = if (@hasDecl(L, "Index_pTable")) L.Index_pTable else 24;
const Index_pNext_off: usize = if (@hasDecl(L, "Index_pNext")) L.Index_pNext else 40;
const Index_tnum_off: usize = if (@hasDecl(L, "Index_tnum")) L.Index_tnum else 88;
const Table_pIndex_off: usize = if (@hasDecl(L, "Table_pIndex")) L.Table_pIndex else 16;

inline fn idxPTable(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Index_pTable_off);
}
inline fn idxPNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Index_pNext_off);
}
inline fn idxTnum(p: ?*anyopaque) u32 {
    return rdPtr(u32, p, Index_tnum_off);
}
inline fn idxTnumPtr(p: ?*anyopaque) *align(1) u32 {
    return @ptrCast(base(p) + Index_tnum_off);
}
inline fn tabPIndex(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Table_pIndex_off);
}

// Schema accessors
inline fn schemaSetCookie(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, Schema_schema_cookie_off, v);
}
inline fn schemaCookie(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, Schema_schema_cookie_off);
}
inline fn schemaSetEnc(p: ?*anyopaque, v: u8) void {
    base(p)[Schema_enc_off] = v;
}
inline fn schemaFileFormat(p: ?*anyopaque) u8 {
    return base(p)[Schema_file_format_off];
}
inline fn schemaSetFileFormat(p: ?*anyopaque, v: u8) void {
    base(p)[Schema_file_format_off] = v;
}
inline fn schemaCacheSize(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, Schema_cache_size_off);
}
inline fn schemaSetCacheSize(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, Schema_cache_size_off, v);
}
inline fn schemaFlags(p: ?*anyopaque) u16 {
    return rdPtr(u16, p, Schema_schemaFlags_off);
}
inline fn schemaSetFlags(p: ?*anyopaque, v: u16) void {
    wrPtr(u16, p, Schema_schemaFlags_off, v);
}

// DbHasProperty / DbSetProperty against db->aDb[i].pSchema->schemaFlags
inline fn dbHasProperty(db: ?*anyopaque, i: c_int, prop: u16) bool {
    const sch = dbAtPSchema(db, i);
    return (schemaFlags(sch) & prop) == prop;
}
inline fn dbSetProperty(db: ?*anyopaque, i: c_int, prop: u16) void {
    const sch = dbAtPSchema(db, i);
    schemaSetFlags(sch, schemaFlags(sch) | prop);
}

// ═══ InitData (local struct passed to sqlite3InitCallback) ═══════════════════
// Layout-invariant (Pgno == u32). Mirrored exactly.
const InitData = extern struct {
    db: ?*anyopaque, // sqlite3 *
    pzErrMsg: ?*align(1) ?[*:0]u8, // char **
    iDb: c_int,
    rc: c_int,
    mInitFlags: u32,
    nInitRow: u32,
    mxPage: u32, // Pgno
};

// ═══ extern globals ══════════════════════════════════════════════════════════
extern const sqlite3UpperToLower: [256]u8;
// `const char *sqlite3StdType[]` — an array of string pointers. We only need a
// valid pointer-array address to assign to db->init.azInit; bind the symbol and
// take its address.
extern const sqlite3StdType: ?*anyopaque;
// `struct Sqlite3Config sqlite3Config` — read bExtraSchemaChecks. SQLITE_WSD ->
// real global object. Mutable in general; we only read here, but declare as a
// byte we address into.
extern const sqlite3Config: u8;
inline fn configBExtraSchemaChecks() bool {
    const p: [*]const u8 = @ptrCast(&sqlite3Config);
    return p[Config_bExtraSchemaChecks_off] != 0;
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ════════════════
// Memory / string
extern fn sqlite3MPrintf(db: ?*anyopaque, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbNNFreeNN(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*:0]const u8, n: u64) ?[*:0]u8;
extern fn sqlite3SetString(pz: *align(1) ?*anyopaque, db: ?*anyopaque, z: ?[*:0]const u8) void;

// error / misc (exported by util.zig / others — declared extern, resolved by linker)
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3Error(db: ?*anyopaque, code: c_int) void;
extern fn sqlite3ErrorClear(db: ?*anyopaque) void;
extern fn sqlite3ErrorWithMsg(db: ?*anyopaque, code: c_int, fmt: [*:0]const u8, ...) void;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3ErrStr(rc: c_int) ?[*:0]const u8;
extern fn sqlite3ApiExit(db: ?*anyopaque, rc: c_int) c_int;
extern fn sqlite3FaultSim(iTest: c_int) c_int;
extern fn sqlite3GetUInt32(z: ?[*:0]const u8, pI: *align(1) u32) c_int;
extern fn sqlite3AbsInt32(x: c_int) c_int;
extern fn sqlite3CorruptError(line: c_int) c_int;
extern fn sqlite3MisuseError(line: c_int) c_int;
extern fn sqlite3NomemError(line: c_int) c_int;
extern fn sqlite3SafetyCheckOk(db: ?*anyopaque) c_int;

// schema / catalog
extern fn sqlite3FindIndex(db: ?*anyopaque, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3ResetAllSchemasOfConnection(db: ?*anyopaque) void;
extern fn sqlite3ResetOneSchema(db: ?*anyopaque, iDb: c_int) void;
extern fn sqlite3AnalysisLoad(db: ?*anyopaque, iDb: c_int) void;
extern fn sqlite3CommitInternalChanges(db: ?*anyopaque) void;
extern fn sqlite3SetTextEncoding(db: ?*anyopaque, enc: u8) void;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3VtabUnlockList(db: ?*anyopaque) void;

// parser glue
extern fn sqlite3RunParser(pParse: ?*anyopaque, zSql: ?[*:0]const u8) c_int;

// btree
extern fn sqlite3BtreeEnter(p: ?*anyopaque) void;
extern fn sqlite3BtreeLeave(p: ?*anyopaque) void;
extern fn sqlite3BtreeEnterAll(db: ?*anyopaque) void;
extern fn sqlite3BtreeLeaveAll(db: ?*anyopaque) void;
extern fn sqlite3BtreeTxnState(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeBeginTrans(p: ?*anyopaque, wrflag: c_int, pSchemaVersion: ?*c_int) c_int;
extern fn sqlite3BtreeGetMeta(p: ?*anyopaque, idx: c_int, pValue: *u32) void;
extern fn sqlite3BtreeLastPage(p: ?*anyopaque) u32;
extern fn sqlite3BtreeCommit(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeSchemaLocked(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeSetCacheSize(p: ?*anyopaque, mxPage: c_int) void;

// vdbe
extern fn sqlite3VdbeSetSql(p: ?*anyopaque, z: ?[*:0]const u8, n: c_int, prepFlags: u8) void;
extern fn sqlite3VdbeFinalize(p: ?*anyopaque) c_int;
extern fn sqlite3VdbeSwap(a: ?*anyopaque, b: ?*anyopaque) void;
extern fn sqlite3VdbeResetStepResult(p: ?*anyopaque) void;
extern fn sqlite3VdbeDb(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbePrepareFlags(p: ?*anyopaque) u8;

// public C-API (other VDBE-aux / main modules)
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;
extern fn sqlite3_finalize(pStmt: ?*anyopaque) c_int;
extern fn sqlite3_exec(db: ?*anyopaque, zSql: ?[*:0]const u8, cb: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_errmsg(db: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3_sql(pStmt: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3_stmt_isexplain(pStmt: ?*anyopaque) c_int;
extern fn sqlite3TransferBindings(pFrom: ?*anyopaque, pTo: ?*anyopaque) c_int;

// UTF16 helpers
extern fn sqlite3Utf16to8(db: ?*anyopaque, z: ?*const anyopaque, nByte: c_int, enc: u8) ?[*:0]u8;
extern fn sqlite3Utf8CharLen(pData: ?[*]const u8, nByte: c_int) c_int;
extern fn sqlite3Utf16ByteLen(pData: ?*const anyopaque, nByte: c_int, nChar: c_int) c_int;

// cleanup callback type (ParseCleanup.xCleanup)
const XCleanup = ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void;

// ParseCleanup struct: { ParseCleanup *pNext; void *pPtr; void(*xCleanup)(sqlite3*,void*); }
const ParseCleanup = extern struct {
    pNext: ?*ParseCleanup,
    pPtr: ?*anyopaque,
    xCleanup: XCleanup,
};
// TriggerPrg: only pNext is touched. NOTE: pTrigger is the first field (off 0);
// pNext sits at off 8. Reading off 0 corrupts the cleanup walk and crashes.
const TriggerPrg_pNext_off: usize = if (@hasDecl(L, "TriggerPrg_pNext")) L.TriggerPrg_pNext else 8;
inline fn triggerPrgNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerPrg_pNext_off);
}

// ─── SCHEMA_TABLE(iDb) ──────────────────────────────────────────────────────
// OMIT_TEMPDB is 0, so iDb==1 -> "sqlite_temp_master", else "sqlite_master".
inline fn schemaTableName(iDb: c_int) [*:0]const u8 {
    return if (iDb == 1) "sqlite_temp_master" else "sqlite_master";
}

// ═══ corruptSchema (static) ══════════════════════════════════════════════════
fn corruptSchema(pData: *InitData, azObj: [*]?[*:0]const u8, zExtra: ?[*:0]const u8) void {
    const db = pData.db;
    if (dbMallocFailed(db)) {
        pData.rc = SQLITE_NOMEM_BKPT();
    } else if (pData.pzErrMsg.?.* != null) {
        // An error message has already been generated; do not overwrite it.
    } else if ((pData.mInitFlags & INITFLAG_AlterMask) != 0) {
        const azAlterType = [_][*:0]const u8{
            "rename",
            "drop column",
            "add column",
            "drop constraint",
        };
        const idx: usize = @intCast((pData.mInitFlags & INITFLAG_AlterMask) - 1);
        pData.pzErrMsg.?.* = sqlite3MPrintf(
            db,
            "error in %s %s after %s: %s",
            azObj[0],
            azObj[1],
            azAlterType[idx],
            zExtra,
        );
        pData.rc = SQLITE_ERROR;
    } else if ((dbFlags(db) & SQLITE_WriteSchema) != 0) {
        pData.rc = SQLITE_CORRUPT_BKPT();
    } else {
        const zObj: ?[*:0]const u8 = if (azObj[1]) |o| o else "?";
        var z = sqlite3MPrintf(db, "malformed database schema (%s)", zObj);
        if (zExtra) |zx| {
            if (zx[0] != 0) {
                z = sqlite3MPrintf(db, "%z - %s", z, zx);
            }
        }
        pData.pzErrMsg.?.* = z;
        pData.rc = SQLITE_CORRUPT_BKPT();
    }
}

// SQLITE_*_BKPT helpers. C: only under SQLITE_DEBUG/API_ARMOR do these expand to
// sqlite3*Error(__LINE__) (defined in malloc.c only in those configs); otherwise
// they are the bare result code. Gate on config so the production build does not
// reference the (then-undefined) error symbols. (API_ARMOR is off here, so the
// gate is exactly sqlite_debug.)
inline fn SQLITE_NOMEM_BKPT() c_int {
    return if (config.sqlite_debug) sqlite3NomemError(0) else SQLITE_NOMEM;
}
inline fn SQLITE_CORRUPT_BKPT() c_int {
    return if (config.sqlite_debug) sqlite3CorruptError(0) else SQLITE_CORRUPT;
}
inline fn SQLITE_MISUSE_BKPT() c_int {
    return if (config.sqlite_debug) sqlite3MisuseError(0) else 21; // SQLITE_MISUSE
}

// ═══ sqlite3IndexHasDuplicateRootPage ════════════════════════════════════════
export fn sqlite3IndexHasDuplicateRootPage(pIndex: ?*anyopaque) callconv(.c) c_int {
    const tab = idxPTable(pIndex);
    var p = tabPIndex(tab);
    const target = idxTnum(pIndex);
    while (p) |pp| {
        if (idxTnum(pp) == target and pp != pIndex) return 1;
        p = idxPNext(pp);
    }
    return 0;
}

// ═══ sqlite3InitCallback ═════════════════════════════════════════════════════
export fn sqlite3InitCallback(pInit: ?*anyopaque, argc: c_int, argv: ?[*]?[*:0]const u8, notUsed: ?[*]?[*:0]const u8) callconv(.c) c_int {
    _ = argc;
    _ = notUsed;
    const pData: *InitData = @ptrCast(@alignCast(pInit.?));
    const db = pData.db;
    const iDb = pData.iDb;

    dbSetMDbFlags(db, dbMDbFlags(db) | DBFLAG_EncodingFixed);
    if (argv == null) return 0; // EMPTY_RESULT_CALLBACKS
    const av = argv.?;
    pData.nInitRow +%= 1;
    if (dbMallocFailed(db)) {
        corruptSchema(pData, av, null);
        return 1;
    }

    if (av[3] == null) {
        corruptSchema(pData, av, null);
    } else if (av[4] != null and
        sqlite3UpperToLower[av[4].?[0]] == 'c' and
        sqlite3UpperToLower[av[4].?[1]] == 'r')
    {
        // Call the parser to process a CREATE TABLE/INDEX/VIEW. Because
        // db->init.busy is set, no VDBE code is generated.
        const saved_iDb = initIDb(db);
        var pStmt: ?*anyopaque = null;
        setInitIDb(db, @intCast(iDb));
        if (sqlite3GetUInt32(av[3], initNewTnumPtr(db)) == 0 or
            (initNewTnumPtr(db).* > pData.mxPage and pData.mxPage > 0))
        {
            if (configBExtraSchemaChecks()) {
                corruptSchema(pData, av, "invalid rootpage");
            }
        }
        setInitOrphanTrigger(db, false);
        setInitAzInit(db, @ptrCast(av));
        _ = sqlite3Prepare(db, av[4], -1, 0, null, &pStmt, null);
        const rc = dbErrCode(db);
        setInitIDb(db, saved_iDb);
        if (rc != SQLITE_OK) {
            if (initOrphanTrigger(db)) {
                // orphan TEMP trigger; iDb==1 expected.
            } else {
                if (rc > pData.rc) pData.rc = rc;
                if (rc == SQLITE_NOMEM) {
                    _ = sqlite3OomFault(db);
                } else if (rc != SQLITE_INTERRUPT and (rc & 0xFF) != SQLITE_LOCKED) {
                    corruptSchema(pData, av, sqlite3_errmsg(db));
                }
            }
        }
        setInitAzInit(db, @ptrCast(@constCast(&sqlite3StdType)));
        _ = sqlite3_finalize(pStmt);
    } else if (av[1] == null or (av[4] != null and av[4].?[0] != 0)) {
        corruptSchema(pData, av, null);
    } else {
        // Blank SQL column => index created for PK/UNIQUE in a CREATE TABLE.
        // Just record the root page number for that index.
        const pIndex = sqlite3FindIndex(db, av[1], dbAtZName(db, iDb));
        if (pIndex == null) {
            corruptSchema(pData, av, "orphan index");
        } else if (sqlite3GetUInt32(av[3], idxTnumPtr(pIndex)) == 0 or
            idxTnum(pIndex) < 2 or
            idxTnum(pIndex) > pData.mxPage or
            sqlite3IndexHasDuplicateRootPage(pIndex) != 0)
        {
            if (configBExtraSchemaChecks()) {
                corruptSchema(pData, av, "invalid rootpage");
            }
        }
    }
    return 0;
}

// ═══ sqlite3InitOne ══════════════════════════════════════════════════════════
export fn sqlite3InitOne(db: ?*anyopaque, iDb: c_int, pzErrMsg: ?*align(1) ?[*:0]u8, mFlags: u32) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var i: c_int = undefined;
    var meta: [5]u32 = undefined;
    var initData: InitData = undefined;
    var openedTransaction: bool = false;
    const mask: u32 = (dbMDbFlags(db) & DBFLAG_EncodingFixed) | ~DBFLAG_EncodingFixed;

    // init.busy = 1 + ((mFlags & INITFLAG_AlterAdd)!=0). INITFLAG_AlterAdd==3.
    setInitBusy(db, @as(u8, 1) + @intFromBool((mFlags & INITFLAG_AlterAdd) != 0));

    const zSchemaTabName = schemaTableName(iDb);
    var azArg = [_]?[*:0]const u8{
        "table",
        zSchemaTabName,
        zSchemaTabName,
        "1",
        "CREATE TABLE x(type text,name text,tbl_name text,rootpage int,sql text)",
        null,
    };
    initData.db = db;
    initData.iDb = iDb;
    initData.rc = SQLITE_OK;
    initData.pzErrMsg = pzErrMsg;
    initData.mInitFlags = mFlags;
    initData.nInitRow = 0;
    initData.mxPage = 0;
    _ = sqlite3InitCallback(&initData, 5, @ptrCast(&azArg), null);
    dbSetMDbFlags(db, dbMDbFlags(db) & mask);
    if (initData.rc != 0) {
        rc = initData.rc;
        return errorOut(db, iDb, rc);
    }

    const pBt = dbAtPBt(db, iDb);
    if (pBt == null) {
        // assert iDb==1
        dbSetProperty(db, 1, DB_SchemaLoaded);
        rc = SQLITE_OK;
        return errorOut(db, iDb, rc);
    }

    sqlite3BtreeEnter(pBt);
    if (sqlite3BtreeTxnState(pBt) == SQLITE_TXN_NONE) {
        rc = sqlite3BtreeBeginTrans(pBt, 0, null);
        if (rc != SQLITE_OK) {
            sqlite3SetString(@ptrCast(pzErrMsg), db, sqlite3ErrStr(rc));
            return initoneErrorOut(db, iDb, pBt, openedTransaction, rc);
        }
        openedTransaction = true;
    }

    // Get the database meta information (meta[0..4] => idx 1..5).
    i = 0;
    while (i < 5) : (i += 1) {
        sqlite3BtreeGetMeta(pBt, i + 1, &meta[@intCast(i)]);
    }
    if ((dbFlags(db) & SQLITE_ResetDatabase) != 0) {
        @memset(std.mem.asBytes(&meta), 0);
    }
    const pSchema = dbAtPSchema(db, iDb);
    schemaSetCookie(pSchema, @bitCast(meta[@intCast(BTREE_SCHEMA_VERSION - 1)]));

    // Text encoding check.
    if (meta[@intCast(BTREE_TEXT_ENCODING - 1)] != 0) {
        if (iDb == 0 and (dbMDbFlags(db) & DBFLAG_EncodingFixed) == 0) {
            var encoding: u8 = @truncate(meta[@intCast(BTREE_TEXT_ENCODING - 1)] & 3);
            if (encoding == 0) encoding = SQLITE_UTF8;
            sqlite3SetTextEncoding(db, encoding);
        } else {
            if ((meta[@intCast(BTREE_TEXT_ENCODING - 1)] & 3) != dbEnc(db)) {
                sqlite3SetString(@ptrCast(pzErrMsg), db, "attached databases must use the same text encoding as main database");
                rc = SQLITE_ERROR;
                return initoneErrorOut(db, iDb, pBt, openedTransaction, rc);
            }
        }
    }
    schemaSetEnc(pSchema, dbEnc(db));

    if (schemaCacheSize(pSchema) == 0) {
        var size = sqlite3AbsInt32(@bitCast(meta[@intCast(BTREE_DEFAULT_CACHE_SIZE - 1)]));
        if (size == 0) size = SQLITE_DEFAULT_CACHE_SIZE;
        schemaSetCacheSize(pSchema, size);
        sqlite3BtreeSetCacheSize(pBt, schemaCacheSize(pSchema));
    }

    schemaSetFileFormat(pSchema, @truncate(meta[@intCast(BTREE_FILE_FORMAT - 1)]));
    if (schemaFileFormat(pSchema) == 0) {
        schemaSetFileFormat(pSchema, 1);
    }
    if (schemaFileFormat(pSchema) > SQLITE_MAX_FILE_FORMAT) {
        sqlite3SetString(@ptrCast(pzErrMsg), db, "unsupported file format");
        rc = SQLITE_ERROR;
        return initoneErrorOut(db, iDb, pBt, openedTransaction, rc);
    }

    if (iDb == 0 and meta[@intCast(BTREE_FILE_FORMAT - 1)] >= 4) {
        dbSetFlags(db, dbFlags(db) & ~SQLITE_LegacyFileFmt);
    }

    // Read the schema information out of the schema tables.
    initData.mxPage = sqlite3BtreeLastPage(pBt);
    {
        const zSql = sqlite3MPrintf(db, "SELECT*FROM\"%w\".%s ORDER BY rowid", dbAtZName(db, iDb), zSchemaTabName);
        const xAuth = dbXAuth(db);
        dbSetXAuth(db, null);
        rc = sqlite3_exec(db, zSql, @ptrCast(&sqlite3InitCallback), &initData, null);
        dbSetXAuth(db, xAuth);
        if (rc == SQLITE_OK) rc = initData.rc;
        sqlite3DbFree(db, @ptrCast(zSql));
        if (rc == SQLITE_OK) {
            sqlite3AnalysisLoad(db, iDb);
        }
    }
    if (dbMallocFailed(db)) {
        rc = SQLITE_NOMEM_BKPT();
        sqlite3ResetAllSchemasOfConnection(db);
    } else if (rc == SQLITE_OK or ((dbFlags(db) & SQLITE_NoSchemaError) != 0 and rc != SQLITE_NOMEM)) {
        dbSetProperty(db, iDb, DB_SchemaLoaded);
        rc = SQLITE_OK;
    }

    return initoneErrorOut(db, iDb, pBt, openedTransaction, rc);
}

// initone_error_out: label
fn initoneErrorOut(db: ?*anyopaque, iDb: c_int, pBt: ?*anyopaque, openedTransaction: bool, rc: c_int) c_int {
    if (openedTransaction) {
        _ = sqlite3BtreeCommit(pBt);
    }
    sqlite3BtreeLeave(pBt);
    return errorOut(db, iDb, rc);
}

// error_out: label
fn errorOut(db: ?*anyopaque, iDb: c_int, rc: c_int) c_int {
    if (rc != 0) {
        if (rc == SQLITE_NOMEM or rc == SQLITE_IOERR_NOMEM) {
            _ = sqlite3OomFault(db);
        }
        sqlite3ResetOneSchema(db, iDb);
    }
    setInitBusy(db, 0);
    return rc;
}

// ═══ sqlite3Init ═════════════════════════════════════════════════════════════
export fn sqlite3Init(db: ?*anyopaque, pzErrMsg: ?*align(1) ?[*:0]u8) callconv(.c) c_int {
    var rc: c_int = undefined;
    const commit_internal = (dbMDbFlags(db) & DBFLAG_SchemaChange) == 0;

    // ENC(db) = SCHEMA_ENC(db) -> db->enc = db->aDb[0].pSchema->enc
    const mainSchema = dbAtPSchema(db, 0);
    base(db)[sqlite3_enc_off] = base(mainSchema)[Schema_enc_off];

    if (!dbHasProperty(db, 0, DB_SchemaLoaded)) {
        rc = sqlite3InitOne(db, 0, pzErrMsg, 0);
        if (rc != 0) return rc;
    }
    var i: c_int = dbNDb(db) - 1;
    while (i > 0) : (i -= 1) {
        if (!dbHasProperty(db, i, DB_SchemaLoaded)) {
            rc = sqlite3InitOne(db, i, pzErrMsg, 0);
            if (rc != 0) return rc;
        }
    }
    if (commit_internal) {
        sqlite3CommitInternalChanges(db);
    }
    return SQLITE_OK;
}

// ═══ sqlite3ReadSchema ═══════════════════════════════════════════════════════
export fn sqlite3ReadSchema(pParse: ?*anyopaque) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const db = pDb(pParse);
    if (initBusy(db) == 0) {
        rc = sqlite3Init(db, @ptrCast(pZErrMsgPtr(pParse)));
        if (rc != SQLITE_OK) {
            pSetRc(pParse, rc);
            pSetNErr(pParse, pNErr(pParse) + 1);
        } else if (dbNoSharedCache(db)) {
            // mDbFlags |= DBFLAG_SchemaKnownOk
            dbSetMDbFlags(db, dbMDbFlags(db) | 0x0010);
        }
    }
    return rc;
}

// ═══ schemaIsValid (static) ══════════════════════════════════════════════════
fn schemaIsValid(pParse: ?*anyopaque) void {
    const db = pDb(pParse);
    var iDb: c_int = 0;
    const n = dbNDb(db);
    while (iDb < n) : (iDb += 1) {
        var openedTransaction: bool = false;
        const pBt = dbAtPBt(db, iDb);
        if (pBt == null) continue;

        if (sqlite3BtreeTxnState(pBt) == SQLITE_TXN_NONE) {
            const rc = sqlite3BtreeBeginTrans(pBt, 0, null);
            if (rc == SQLITE_NOMEM or rc == SQLITE_IOERR_NOMEM) {
                _ = sqlite3OomFault(db);
                pSetRc(pParse, SQLITE_NOMEM);
            }
            if (rc != SQLITE_OK) return;
            openedTransaction = true;
        }

        var cookie: u32 = undefined;
        sqlite3BtreeGetMeta(pBt, BTREE_SCHEMA_VERSION, &cookie);
        const sch = dbAtPSchema(db, iDb);
        if (@as(c_int, @bitCast(cookie)) != schemaCookie(sch)) {
            if (dbHasProperty(db, iDb, DB_SchemaLoaded)) pSetRc(pParse, SQLITE_SCHEMA);
            sqlite3ResetOneSchema(db, iDb);
        }

        if (openedTransaction) {
            _ = sqlite3BtreeCommit(pBt);
        }
    }
}

// ═══ sqlite3SchemaToIndex ════════════════════════════════════════════════════
export fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) callconv(.c) c_int {
    var i: c_int = -32768;
    if (pSchema != null) {
        i = 0;
        while (true) : (i += 1) {
            if (dbAtPSchema(db, i) == pSchema) break;
        }
    }
    return i;
}

// ═══ sqlite3ParseObjectReset ═════════════════════════════════════════════════
export fn sqlite3ParseObjectReset(pParse: ?*anyopaque) callconv(.c) void {
    const db = pDb(pParse);
    if (pNTableLock(pParse) != 0) sqlite3DbNNFreeNN(db, pATableLock(pParse));
    while (pPCleanup(pParse)) |pc| {
        const pCleanup: *ParseCleanup = @ptrCast(@alignCast(pc));
        pSetPCleanup(pParse, @ptrCast(pCleanup.pNext));
        if (pCleanup.xCleanup) |xc| xc(db, pCleanup.pPtr);
        sqlite3DbNNFreeNN(db, pc);
    }
    if (pALabel(pParse)) |lbl| sqlite3DbNNFreeNN(db, lbl);
    if (pPConstExpr(pParse)) |pce| {
        sqlite3ExprListDelete(db, pce);
    }
    // db->lookaside.bDisable -= pParse->disableLookaside
    const dis: u32 = pDisableLookaside(pParse);
    setLaBDisable(db, laBDisable(db) -% dis);
    // db->lookaside.sz = bDisable ? 0 : szTrue
    setLaSz(db, if (laBDisable(db) != 0) 0 else laSzTrue(db));
    // db->pParse = pParse->pOuterParse
    wrPtr(?*anyopaque, db, sqlite3_pParse_off, pPOuterParse(pParse));
}

// ═══ sqlite3ParserAddCleanup ═════════════════════════════════════════════════
export fn sqlite3ParserAddCleanup(pParse: ?*anyopaque, xCleanup: XCleanup, pPtrIn: ?*anyopaque) callconv(.c) ?*anyopaque {
    var pPtr = pPtrIn;
    const db = pDb(pParse);
    var pCleanup: ?*ParseCleanup = null;
    if (sqlite3FaultSim(300) != 0) {
        pCleanup = null;
        _ = sqlite3OomFault(db);
    } else {
        pCleanup = @ptrCast(@alignCast(sqlite3DbMallocRaw(db, @sizeOf(ParseCleanup))));
    }
    if (pCleanup) |pc| {
        pc.pNext = @ptrCast(@alignCast(pPCleanup(pParse)));
        pSetPCleanup(pParse, @ptrCast(pc));
        pc.pPtr = pPtr;
        pc.xCleanup = xCleanup;
    } else {
        if (xCleanup) |xc| xc(db, pPtr);
        pPtr = null;
    }
    return pPtr;
}

// ═══ sqlite3ParseObjectInit ══════════════════════════════════════════════════
export fn sqlite3ParseObjectInit(pParse: ?*anyopaque, db: ?*anyopaque) callconv(.c) void {
    parseZeroRegions(pParse);
    pSetPOuterParse(pParse, rdPtr(?*anyopaque, db, sqlite3_pParse_off));
    wrPtr(?*anyopaque, db, sqlite3_pParse_off, pParse);
    pSetDb(pParse, db);
    if (dbMallocFailed(db)) sqlite3ErrorMsg(pParse, "out of memory");
}

// ═══ sqlite3Prepare (static) ═════════════════════════════════════════════════
fn sqlite3Prepare(
    db: ?*anyopaque,
    zSql: ?[*:0]const u8,
    nBytes: c_int,
    prepFlags: u32,
    pReprepare: ?*anyopaque,
    ppStmt: *?*anyopaque,
    pzTail: ?*?[*:0]const u8,
) c_int {
    var rc: c_int = SQLITE_OK;
    // sParse: a Parse-sized aligned buffer.
    var sParseBuf: [sizeof_Parse]u8 align(16) = undefined;
    const sParse: ?*anyopaque = @ptrCast(&sParseBuf);

    // sqlite3ParseObjectInit inlined for performance (matches C).
    parseZeroRegions(sParse);
    pSetPOuterParse(sParse, rdPtr(?*anyopaque, db, sqlite3_pParse_off));
    wrPtr(?*anyopaque, db, sqlite3_pParse_off, sParse);
    pSetDb(sParse, db);
    if (pReprepare) |pr| {
        pSetPReprepare(sParse, pr);
        pSetExplain(sParse, @intCast(sqlite3_stmt_isexplain(pr)));
    }
    // assert ppStmt && *ppStmt==0
    if (dbMallocFailed(db)) {
        sqlite3ErrorMsg(sParse, "out of memory");
        rc = SQLITE_NOMEM;
        dbSetErrCode(db, SQLITE_NOMEM);
        return endPrepare(db, sParse, rc);
    }

    // For a long-term prepared statement, avoid lookaside memory.
    if ((prepFlags & SQLITE_PREPARE_PERSISTENT) != 0) {
        pSetDisableLookaside(sParse, pDisableLookaside(sParse) + 1);
        // DisableLookaside: db->lookaside.bDisable++; db->lookaside.sz=0
        setLaBDisable(db, laBDisable(db) + 1);
        setLaSz(db, 0);
    }
    pSetPrepFlags(sParse, @truncate(prepFlags & 0xff));

    // Verify a read lock is obtainable on all database schemas.
    if (!dbNoSharedCache(db)) {
        var i: c_int = 0;
        const n = dbNDb(db);
        while (i < n) : (i += 1) {
            const pBt = dbAtPBt(db, i);
            if (pBt != null) {
                rc = sqlite3BtreeSchemaLocked(pBt);
                if (rc != 0) {
                    const zDb = dbAtZName(db, i);
                    sqlite3ErrorWithMsg(db, rc, "database schema is locked: %s", zDb);
                    return endPrepare(db, sParse, rc);
                }
            }
        }
    }

    if (dbPDisconnect(db) != null) sqlite3VtabUnlockList(db);

    if (nBytes >= 0 and (nBytes == 0 or zSql.?[@intCast(nBytes - 1)] != 0)) {
        const mxLen = dbALimit(db, SQLITE_LIMIT_SQL_LENGTH);
        if (nBytes > mxLen) {
            sqlite3ErrorWithMsg(db, SQLITE_TOOBIG, "statement too long");
            rc = sqlite3ApiExit(db, SQLITE_TOOBIG);
            return endPrepare(db, sParse, rc);
        }
        const zSqlCopy = sqlite3DbStrNDup(db, zSql, @intCast(nBytes));
        if (zSqlCopy) |copy| {
            _ = sqlite3RunParser(sParse, copy);
            // sParse.zTail = &zSql[sParse.zTail - zSqlCopy]
            const tail = pZTail(sParse);
            const offset = @intFromPtr(tail.?) - @intFromPtr(copy);
            pSetZTail(sParse, @ptrCast(zSql.? + offset));
            sqlite3DbFree(db, @ptrCast(copy));
        } else {
            pSetZTail(sParse, @ptrCast(zSql.? + @as(usize, @intCast(nBytes))));
        }
    } else {
        _ = sqlite3RunParser(sParse, zSql);
    }
    // assert 0==sParse.nQueryLoop
    _ = pNQueryLoop(sParse);

    if (pzTail) |pt| {
        pt.* = pZTail(sParse);
    }

    if (initBusy(db) == 0) {
        const tail = pZTail(sParse);
        const n: c_int = @intCast(@intFromPtr(tail.?) - @intFromPtr(zSql.?));
        sqlite3VdbeSetSql(pPVdbe(sParse), zSql, n, @truncate(prepFlags));
    }
    if (dbMallocFailed(db)) {
        pSetRc(sParse, SQLITE_NOMEM_BKPT());
        pSetCheckSchema(sParse, false);
    }
    if (pRc(sParse) != SQLITE_OK and pRc(sParse) != SQLITE_DONE) {
        if (pCheckSchema(sParse) and initBusy(db) == 0) {
            schemaIsValid(sParse);
        }
        if (pPVdbe(sParse)) |v| {
            _ = sqlite3VdbeFinalize(v);
        }
        // assert 0 == *ppStmt
        rc = pRc(sParse);
        if (pZErrMsg(sParse)) |em| {
            sqlite3ErrorWithMsg(db, rc, "%s", em);
            sqlite3DbFree(db, @ptrCast(em));
        } else {
            sqlite3Error(db, rc);
        }
    } else {
        // assert sParse.zErrMsg==0
        ppStmt.* = pPVdbe(sParse);
        rc = SQLITE_OK;
        sqlite3ErrorClear(db);
    }

    // Delete any TriggerPrg structures allocated while parsing.
    while (pPTriggerPrg(sParse)) |pt| {
        pSetPTriggerPrg(sParse, triggerPrgNext(pt));
        sqlite3DbFree(db, pt);
    }

    return endPrepare(db, sParse, rc);
}

// end_prepare: label
fn endPrepare(db: ?*anyopaque, sParse: ?*anyopaque, rc: c_int) c_int {
    _ = db;
    sqlite3ParseObjectReset(sParse);
    return rc;
}

// ═══ sqlite3LockAndPrepare (static) ══════════════════════════════════════════
fn sqlite3LockAndPrepare(
    db: ?*anyopaque,
    zSql: ?[*:0]const u8,
    nBytes: c_int,
    prepFlags: u32,
    pOld: ?*anyopaque,
    ppStmt: *?*anyopaque,
    pzTail: ?*?[*:0]const u8,
) c_int {
    var rc: c_int = undefined;
    var cnt: c_int = 0;

    ppStmt.* = null;
    if (sqlite3SafetyCheckOk(db) == 0 or zSql == null) {
        return SQLITE_MISUSE_BKPT();
    }
    sqlite3_mutex_enter(dbMutex(db));
    sqlite3BtreeEnterAll(db);
    while (true) {
        // Make multiple attempts until success or a permanent error.
        rc = sqlite3Prepare(db, zSql, nBytes, prepFlags, pOld, ppStmt, pzTail);
        if (rc == SQLITE_OK or dbMallocFailed(db)) break;
        cnt += 1;
        const retry = (rc == SQLITE_ERROR_RETRY and cnt <= SQLITE_MAX_PREPARE_RETRY);
        var schemaRetry = false;
        if (rc == SQLITE_SCHEMA) {
            sqlite3ResetOneSchema(db, -1);
            schemaRetry = (cnt == 1);
        }
        if (!(retry or schemaRetry)) break;
    }
    sqlite3BtreeLeaveAll(db);
    rc = sqlite3ApiExit(db, rc);
    dbBusyHandlerNBusyPtr(db).* = 0;
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

// ═══ sqlite3Reprepare ════════════════════════════════════════════════════════
export fn sqlite3Reprepare(p: ?*anyopaque) callconv(.c) c_int {
    var pNew: ?*anyopaque = null;
    const zSql = sqlite3_sql(p);
    const db = sqlite3VdbeDb(p);
    const prepFlags = sqlite3VdbePrepareFlags(p);
    const rc = sqlite3LockAndPrepare(db, zSql, -1, prepFlags, p, &pNew, null);
    if (rc != 0) {
        if (rc == SQLITE_NOMEM) {
            _ = sqlite3OomFault(db);
        }
        return rc;
    }
    sqlite3VdbeSwap(pNew, p);
    _ = sqlite3TransferBindings(pNew, p);
    sqlite3VdbeResetStepResult(pNew);
    _ = sqlite3VdbeFinalize(pNew);
    return SQLITE_OK;
}

// ═══ Official prepare APIs (UTF-8) ═══════════════════════════════════════════
export fn sqlite3_prepare(
    db: ?*anyopaque,
    zSql: ?[*:0]const u8,
    nBytes: c_int,
    ppStmt: *?*anyopaque,
    pzTail: ?*?[*:0]const u8,
) callconv(.c) c_int {
    return sqlite3LockAndPrepare(db, zSql, nBytes, 0, null, ppStmt, pzTail);
}

export fn sqlite3_prepare_v2(
    db: ?*anyopaque,
    zSql: ?[*:0]const u8,
    nBytes: c_int,
    ppStmt: *?*anyopaque,
    pzTail: ?*?[*:0]const u8,
) callconv(.c) c_int {
    return sqlite3LockAndPrepare(db, zSql, nBytes, SQLITE_PREPARE_SAVESQL, null, ppStmt, pzTail);
}

export fn sqlite3_prepare_v3(
    db: ?*anyopaque,
    zSql: ?[*:0]const u8,
    nBytes: c_int,
    prepFlags: c_uint,
    ppStmt: *?*anyopaque,
    pzTail: ?*?[*:0]const u8,
) callconv(.c) c_int {
    return sqlite3LockAndPrepare(db, zSql, nBytes, SQLITE_PREPARE_SAVESQL | (@as(u32, prepFlags) & SQLITE_PREPARE_MASK), null, ppStmt, pzTail);
}

// ═══ UTF-16 prepare path ═════════════════════════════════════════════════════
fn sqlite3Prepare16(
    db: ?*anyopaque,
    zSql: ?*const anyopaque,
    nBytesIn: c_int,
    prepFlags: u32,
    ppStmt: *?*anyopaque,
    pzTail: ?*?*const anyopaque,
) c_int {
    var zTail8: ?[*:0]const u8 = null;
    var rc: c_int = SQLITE_OK;
    var nBytes = nBytesIn;

    ppStmt.* = null;
    if (sqlite3SafetyCheckOk(db) == 0 or zSql == null) {
        return SQLITE_MISUSE_BKPT();
    }

    // Determine the byte length (up to first U+0000 or nBytes).
    const z: [*]const u8 = @ptrCast(zSql.?);
    if (nBytes >= 0) {
        var sz: c_int = 0;
        while (sz < nBytes and (z[@intCast(sz)] != 0 or z[@intCast(sz + 1)] != 0)) : (sz += 2) {}
        nBytes = sz;
    } else {
        var sz: c_int = 0;
        while (z[@intCast(sz)] != 0 or z[@intCast(sz + 1)] != 0) : (sz += 2) {}
        nBytes = sz;
    }

    sqlite3_mutex_enter(dbMutex(db));
    const zSql8 = sqlite3Utf16to8(db, zSql, nBytes, SQLITE_UTF16NATIVE);
    if (zSql8) |s8| {
        rc = sqlite3LockAndPrepare(db, s8, -1, prepFlags, null, ppStmt, &zTail8);
    }

    if (zTail8 != null and pzTail != null) {
        const s8 = zSql8.?;
        const parsedBytes: c_int = @intCast(@intFromPtr(zTail8.?) - @intFromPtr(s8));
        const chars_parsed = sqlite3Utf8CharLen(s8, parsedBytes);
        const byteLen = sqlite3Utf16ByteLen(zSql, nBytes, chars_parsed);
        pzTail.?.* = @ptrCast(z + @as(usize, @intCast(byteLen)));
    }
    sqlite3DbFree(db, @ptrCast(zSql8));
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

export fn sqlite3_prepare16(
    db: ?*anyopaque,
    zSql: ?*const anyopaque,
    nBytes: c_int,
    ppStmt: *?*anyopaque,
    pzTail: ?*?*const anyopaque,
) callconv(.c) c_int {
    return sqlite3Prepare16(db, zSql, nBytes & ~@as(c_int, 1), 0, ppStmt, pzTail);
}

export fn sqlite3_prepare16_v2(
    db: ?*anyopaque,
    zSql: ?*const anyopaque,
    nBytes: c_int,
    ppStmt: *?*anyopaque,
    pzTail: ?*?*const anyopaque,
) callconv(.c) c_int {
    return sqlite3Prepare16(db, zSql, nBytes & ~@as(c_int, 1), SQLITE_PREPARE_SAVESQL, ppStmt, pzTail);
}

export fn sqlite3_prepare16_v3(
    db: ?*anyopaque,
    zSql: ?*const anyopaque,
    nBytes: c_int,
    prepFlags: c_uint,
    ppStmt: *?*anyopaque,
    pzTail: ?*?*const anyopaque,
) callconv(.c) c_int {
    return sqlite3Prepare16(db, zSql, nBytes & ~@as(c_int, 1), SQLITE_PREPARE_SAVESQL | (@as(u32, prepFlags) & SQLITE_PREPARE_MASK), ppStmt, pzTail);
}

comptime {
    // Layout sanity for the local structs we mirror directly.
    std.debug.assert(@sizeOf(InitData) == 40);
    std.debug.assert(@offsetOf(InitData, "iDb") == 16);
    std.debug.assert(@offsetOf(InitData, "rc") == 20);
    std.debug.assert(@offsetOf(InitData, "mxPage") == 32);
    std.debug.assert(@sizeOf(ParseCleanup) == 24);
}
