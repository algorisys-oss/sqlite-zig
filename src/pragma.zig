//! Zig port of SQLite's src/pragma.c — the PRAGMA command implementation.
//!
//! Exported (C-ABI) symbols:
//!   - sqlite3GetBoolean(z, dflt) -> u8           (used widely by other modules)
//!   - sqlite3JournalModename(eMode) -> ?[*:0]u8  (journal mode name table)
//!   - sqlite3Pragma(pParse, pId1, pId2, pValue, minusFlag)  (the giant fn)
//!   - sqlite3PragmaVtabRegister(db, zName) -> Module*        (eponymous vtab)
//!
//! All static C helpers (getSafetyLevel, getLockingMode, getAutoVacuum,
//! getTempStore, invalidateTempStorage, changeTempStorage,
//! setPragmaResultColumnNames, returnSingleInt, returnSingleText,
//! setAllPagerFlags, actionName, pragmaLocate, pragmaFunclistLine,
//! integrityCheckResultRow, tableSkipIntegrityCheck, and the pragmaVtab*
//! module methods) become private Zig fns.
//!
//! ── Generated tables ──────────────────────────────────────────────────────
//! aPragmaName[] and pragCName[] are reproduced from the auto-generated
//! pragma.h (tool/mkpragmatab.tcl) and were verified against the C-compiled
//! pragma.h for BOTH build configs.  The table is config-divergent:
//!   production library : 66 entries
//!   --dev testfixture  : 75 entries (9 extra SQLITE_DEBUG-only pragmas:
//!       lock_status, parser_trace, sql_trace, stats, vdbe_addoptrace,
//!       vdbe_debug, vdbe_eqp, vdbe_listing, vdbe_trace)
//! We build both and select via `config.sqlite_debug`.  pragCName[] (57
//! entries) is identical for both configs.  The table is sorted by name and
//! pragmaLocate() binary-searches it, so order is preserved exactly.
//!
//! ── Bitfield byte reads (NOT in c_layout, probed; config-invariant) ───────
//!   Column+8  : notNull = byte & 0x0F ; eCType = byte >> 4
//!   Index+99  : idxType = byte & 0x03 ; hasStat1 = (byte & 0x80)!=0
//!   Parse bft : okConstFactor is bit 0x80 of the bft group byte
//!               (offset 39 prod / 42 tf — matches build.zig discipline)
//!
//! Config: SQLITE_OMIT_* all OFF; SQLITE_OS_WIN OFF; SQLITE_ENABLE_LOCKING_STYLE
//! 0 (linux); SQLITE_ENABLE_CEROD OFF; SQLITE_MAX_MMAP_SIZE>0;
//! SQLITE_OMIT_DEPRECATED OFF; SQLITE_OMIT_WSD OFF.  Public domain (SQLite).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers (verbatim from build.zig) ────────────────────────────
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, offs: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + offs);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, offs: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + offs);
    q.* = v;
}
inline fn fieldPtr(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return @ptrCast(base(p) + offs);
}
inline fn rdp(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return rd(?*anyopaque, p, offs);
}
fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

const Cptr = ?*anyopaque;

// ─── struct field offsets ────────────────────────────────────────────────────
// sqlite3
const sqlite3_pVfs = off("sqlite3_pVfs", 0);
const sqlite3_aDb = off("sqlite3_aDb", 32);
const sqlite3_nDb = off("sqlite3_nDb", 40);
const sqlite3_mDbFlags = off("sqlite3_mDbFlags", 44);
const sqlite3_flags = off("sqlite3_flags", 48);
const sqlite3_szMmap = off("sqlite3_szMmap", 64);
const sqlite3_enc = off("sqlite3_enc", 100);
const sqlite3_autoCommit = off("sqlite3_autoCommit", 101);
const sqlite3_temp_store = off("sqlite3_temp_store", 102);
const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103);
const sqlite3_dfltLockMode: usize = 105; // u8 (not in L)
const sqlite3_nextAutovac: usize = 106; // u8 (not in L)
const sqlite3_nextPagesize = off("sqlite3_nextPagesize", 116);
const sqlite3_aLimit = off("sqlite3_aLimit", 136);
const sqlite3_pParse = off("sqlite3_pParse", 344);
const sqlite3_xWalCallback = off("sqlite3_xWalCallback", 376);
const sqlite3_pWalArg = off("sqlite3_pWalArg", 384);
const sqlite3_aModule = off("sqlite3_aModule", 568);
const sqlite3_aCollSeq = off("sqlite3_aCollSeq", 640);
const sqlite3_aFunc = off("sqlite3_aFunc", 616);
const sqlite3_busyHandler = off("sqlite3_busyHandler", 664);
const sqlite3_nAnalysisLimit = off("sqlite3_nAnalysisLimit", 760);
const sqlite3_busyTimeout = off("sqlite3_busyTimeout", 764);
const sqlite3_nDeferredCons = off("sqlite3_nDeferredCons", 776);
const sqlite3_nDeferredImmCons = off("sqlite3_nDeferredImmCons", 784);
// BusyHandler {ptr,ptr,int nBusy} -> nBusy at +16
const BusyHandler_nBusy: usize = 16;

// Db (sizeof 32)
const sizeof_Db = off("sizeof_Db", 32);
const Db_zDbSName = off("Db_zDbSName", 0);
const Db_pBt = off("Db_pBt", 8);
const Db_safety_level = off("Db_safety_level", 16);
const Db_bSyncSet: usize = 17; // u8 bSyncSet:1 byte
const Db_pSchema = off("Db_pSchema", 24);

// Schema
const Schema_tblHash = off("Schema_tblHash", 8);
const Schema_cache_size = off("Schema_cache_size", 116);
const Schema_enc = off("Schema_enc", 113);

// Table
const Table_zName = off("Table_zName", 0);
const Table_aCol = off("Table_aCol", 8);
const Table_pIndex = off("Table_pIndex", 16);
const Table_pCheck = off("Table_pCheck", 32);
const Table_tnum = off("Table_tnum", 40);
const Table_nTabRef = off("Table_nTabRef", 44);
const Table_tabFlags = off("Table_tabFlags", 48);
const Table_iPKey = off("Table_iPKey", 52);
const Table_nCol = off("Table_nCol", 54);
const Table_nRowLogEst = off("Table_nRowLogEst", 58);
const Table_szTabRow = off("Table_szTabRow", 60);
const Table_eTabType = off("Table_eTabType", 63);
const Table_u = off("Table_u", 64);
const Table_u_tab_pFKey = off("Table_u_tab_pFKey", 72);
const Table_u_vtab_azArg = off("Table_u_vtab_azArg", 72);
const Table_u_vtab_p = off("Table_u_vtab_p", 80);
const Table_pSchema = off("Table_pSchema", 96);
const sizeof_Column = off("sizeof_Column", 16);

// Column (sizeof 16)
const Column_zCnName = off("Column_zCnName", 0);
const Column_bft_byte: usize = 8; // notNull(low nibble) | eCType(high nibble)
const Column_affinity = off("Column_affinity", 9);
const Column_iDflt = off("Column_iDflt", 12);
const Column_colFlags = off("Column_colFlags", 14);

// Index (sizeof 112)
const Index_zName = off("Index_zName", 0);
const Index_aiColumn = off("Index_aiColumn", 8);
const Index_aiRowLogEst = off("Index_aiRowLogEst", 16);
const Index_pTable = off("Index_pTable", 24);
const Index_pNext = off("Index_pNext", 40);
const Index_pSchema = off("Index_pSchema", 48);
const Index_aSortOrder = off("Index_aSortOrder", 56);
const Index_azColl = off("Index_azColl", 64);
const Index_pPartIdxWhere = off("Index_pPartIdxWhere", 72);
const Index_tnum = off("Index_tnum", 88);
const Index_szIdxRow = off("Index_szIdxRow", 92);
const Index_nKeyCol = off("Index_nKeyCol", 94);
const Index_nColumn = off("Index_nColumn", 96);
const Index_onError = off("Index_onError", 98);
const Index_bits_byte: usize = 99; // idxType:2(0x03) ... hasStat1:1(0x80)

// FuncDef
const FuncDef_nArg = off("FuncDef_nArg", 0);
const FuncDef_pNext = off("FuncDef_pNext", 16); // same-name synonym chain
const FuncDef_funcFlags = off("FuncDef_funcFlags", 4);
const FuncDef_xSFunc = off("FuncDef_xSFunc", 24);
const FuncDef_xFinalize = off("FuncDef_xFinalize", 32);
const FuncDef_xValue = off("FuncDef_xValue", 40);
const FuncDef_zName = off("FuncDef_zName", 56);
const FuncDef_u = off("FuncDef_u", 64); // u.pHash is first member

// CollSeq / Module
const CollSeq_zName = off("CollSeq_zName", 0);
const Module_zName = off("Module_zName", 8);

// FKey
const FKey_zTo = off("FKey_zTo", 16);
const FKey_pNextFrom = off("FKey_pNextFrom", 8);
const FKey_nCol = off("FKey_nCol", 40);
const FKey_aAction = off("FKey_aAction", 45);
const FKey_aCol = off("FKey_aCol", 64);
const sizeof_sColMap = off("sizeof_sColMap", 16);
const sColMap_iFrom = off("sColMap_iFrom", 0);
const sColMap_zCol = off("sColMap_zCol", 8);

// Parse
const Parse_db = off("Parse_db", 0);
const Parse_rc = off("Parse_rc", 24);
const Parse_nErr = off("Parse_nErr", 52);
const Parse_nTab = off("Parse_nTab", 56);
const Parse_nMem = off("Parse_nMem", 60);
const Parse_iSelfTab = off("Parse_iSelfTab", 64);
// Parse bft group byte (okConstFactor bit 0x80) — 39 prod / 42 tf.
const Parse_bft_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_okConstFactor: u8 = 0x80;

// Token
const Token_z: usize = 0;
const Token_n: usize = 8;

// VdbeOp
const sizeof_VdbeOp = off("sizeof_VdbeOp", 32);
const VdbeOp_opcode_off = off("VdbeOp_opcode", 0);
const VdbeOp_p4type_off = off("VdbeOp_p4type", 1);
const VdbeOp_p5_off = off("VdbeOp_p5", 2);
const VdbeOp_p1_off = off("VdbeOp_p1", 4);
const VdbeOp_p2_off = off("VdbeOp_p2", 8);
const VdbeOp_p3_off = off("VdbeOp_p3", 12);
const VdbeOp_p4_off = off("VdbeOp_p4", 16);

// Hash (sqliteHashFirst -> first; HashElem next/data)
const Hash_first = off("Hash_first", 16);
const HashElem_next = off("HashElem_next", 0);
const HashElem_data = off("HashElem_data", 16);

// ─── opcode / constant values (from consts_prod.txt; verified invariant) ─────
const OP_Int64: c_int = 74;
const OP_ResultRow: c_int = 86;
const OP_Transaction: c_int = 2;
const OP_ReadCookie: c_int = 101;
const OP_IfPos: c_int = 61;
const OP_Integer: c_int = 73;
const OP_Subtract: c_int = 108;
const OP_Noop: c_int = 189;
const OP_SetCookie: c_int = 102;
const OP_Pagecount: c_int = 180;
const OP_MaxPgcnt: c_int = 181;
const OP_JournalMode: c_int = 4;
const OP_If: c_int = 16;
const OP_Halt: c_int = 72;
const OP_IncrVacuum: c_int = 64;
const OP_AddImm: c_int = 88;
const OP_Expire: c_int = 168;
const OP_Null: c_int = 77;
const OP_Rewind: c_int = 36;
const OP_Next: c_int = 40;
const OP_IntegrityCk: c_int = 157;
const OP_IsNull: c_int = 51;
const OP_String8: c_int = 118;
const OP_Concat: c_int = 112;
const OP_Eq: c_int = 54;
const OP_Ne: c_int = 53;
const OP_Column: c_int = 96;
const OP_IdxGT: c_int = 42;
const OP_IdxRowid: c_int = 144;
const OP_IsType: c_int = 18;
const OP_NotNull: c_int = 52;
const OP_Affinity: c_int = 98;
const OP_Goto: c_int = 9;
const OP_Found: c_int = 29;
const OP_IFindKey: c_int = 47;
const OP_SeekRowid: c_int = 30;
const OP_Rowid: c_int = 137;
const OP_VCheck: c_int = 176;
const OP_Checkpoint: c_int = 3;
const OP_SqlExec: c_int = 150;
const OP_IfSizeBetween: c_int = 33;
const OP_IfNotZero: c_int = 62;
const OP_OpenRead: c_int = 114;
const OP_OpenWrite: c_int = 116;

const P4_INT64: c_int = -14;
const P4_INTARRAY: c_int = -15;
const P4_DYNAMIC: c_int = -7;
const P4_STATIC: c_int = -1;
const P4_INDEX: c_int = -6;
const P4_TABLEREF: c_int = -17;

const BTREE_DEFAULT_CACHE_SIZE: c_int = 3;
const BTREE_LARGEST_ROOT_PAGE: c_int = 4;
const BTREE_INCR_VACUUM: c_int = 7;
const BTREE_SCHEMA_VERSION: c_int = 1;
const SQLITE_DEFAULT_CACHE_SIZE: c_int = -2000;

const PAGER_LOCKINGMODE_QUERY: c_int = -1;
const PAGER_LOCKINGMODE_NORMAL: c_int = 0;
const PAGER_LOCKINGMODE_EXCLUSIVE: c_int = 1;
const PAGER_JOURNALMODE_QUERY: c_int = -1;
const PAGER_JOURNALMODE_OFF: c_int = 2;
const PAGER_SYNCHRONOUS_MASK: c_int = 7;
const PAGER_FLAGS_MASK: u64 = 56;

const SQLITE_CacheSpill: u64 = 32;
const SQLITE_Defensive: u64 = 268435456;
const SQLITE_ForeignKeys: u64 = 16384;
const SQLITE_WriteSchema: u64 = 1;
const SQLITE_DeferFKs: u64 = 524288;
const SQLITE_IgnoreChecks: u64 = 512;

const BTREE_AUTOVACUUM_NONE: c_int = 0;
const BTREE_AUTOVACUUM_FULL: c_int = 1;
const BTREE_AUTOVACUUM_INCR: c_int = 2;

const SQLITE_CHECKPOINT_PASSIVE: c_int = 0;
const SQLITE_CHECKPOINT_FULL: c_int = 1;
const SQLITE_CHECKPOINT_RESTART: c_int = 2;
const SQLITE_CHECKPOINT_TRUNCATE: c_int = 3;
const SQLITE_CHECKPOINT_NOOP: c_int = -1;
const SQLITE_MAX_DB: c_int = 12;

const SQLITE_LIMIT_WORKER_THREADS: c_int = 11;
const SQLITE_LIMIT_SQL_LENGTH: usize = 1;
const SQLITE_FUNC_HASH_SZ: usize = 23;
const SQLITE_FUNC_INTERNAL: u32 = 262144;
const SQLITE_FUNC_ENCMASK: u32 = 3;
const SQLITE_DETERMINISTIC: u32 = 2048;
const SQLITE_DIRECTONLY: u32 = 524288;
const SQLITE_SUBTYPE: u32 = 1048576;
const SQLITE_INNOCUOUS: u32 = 2097152;

const DBFLAG_InternalFunc: u32 = 32;
const DBFLAG_EncodingFixed: u32 = 64;
const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_UTF16BE: u8 = 3;
const SQLITE_UTF16NATIVE: u8 = 2;

const COLFLAG_NOINSERT: u16 = 98;
const COLFLAG_VIRTUAL: u16 = 32;
const COLFLAG_STORED: u16 = 64;
const COLFLAG_HIDDEN: u16 = 2;
const COLFLAG_PRIMKEY: u16 = 1;

const TF_Imposter: u32 = 131072;
const TF_Shadow: u32 = 4096;
const TF_WithoutRowid: u32 = 128;
const TF_Strict: u32 = 65536;
const TF_MaybeReanalyze: u32 = 256;

const OE_None: u8 = 0;
const OE_SetNull: u8 = 8;
const OE_SetDflt: u8 = 9;
const OE_Cascade: u8 = 10;
const OE_Restrict: u8 = 7;
const OE_Abort: c_int = 2;

const SQLITE_AFF_BLOB: u8 = 65;
const SQLITE_AFF_TEXT: u8 = 66;
const SQLITE_AFF_NUMERIC: u8 = 67;
const COLTYPE_ANY: u8 = 1;
const SQLITE_NULL: c_int = 5;
const LOCATE_NOERR: c_int = 2;
const XN_ROWID: i16 = -1;
const SQLITE_JUMPIFNULL: c_int = 16;
const SQLITE_PREPARE_DONT_LOG: c_uint = 16;
const SQLITE_MUTEX_STATIC_TEMPDIR: c_int = 11;
const SQLITE_ACCESS_READWRITE: c_int = 1;
const SQLITE_INDEX_CONSTRAINT_EQ: u8 = 2;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_TXN_NONE: c_int = 0;
const SQLITE_TEMP_STORE: c_int = 1;

const SQLITE_PRAGMA: c_int = 19;
const SQLITE_FCNTL_PRAGMA: c_int = 14;
const SQLITE_FCNTL_MMAP_SIZE: c_int = 18;
const SQLITE_FCNTL_LOCKSTATE: c_int = 1;
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOTFOUND: c_int = 12;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_ROW: c_int = 100;
const COLNAME_NAME: c_int = 0;
const SQLITE_STATIC: ?*anyopaque = @ptrFromInt(0);
const SQLITE_TRANSIENT: ?*anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const SQLITE_INTEGRITY_CHECK_ERROR_MAX: c_int = 100;
const SQLITE_DEFAULT_OPTIMIZE_LIMIT: c_int = 2000;

// PragFlg bits
const PragFlg_NeedSchema: u8 = 0x01;
const PragFlg_NoColumns: u8 = 0x02;
const PragFlg_NoColumns1: u8 = 0x04;
const PragFlg_ReadOnly: u8 = 0x08;
const PragFlg_Result0: u8 = 0x10;
const PragFlg_Result1: u8 = 0x20;
const PragFlg_SchemaOpt: u8 = 0x40;
const PragFlg_SchemaReq: u8 = 0x80;

// PragTyp values (from pragma.h). BUSY_TIMEOUT is the default case.
const PragTyp_BUSY_TIMEOUT: u8 = 5;
const PragTyp_DEFAULT_CACHE_SIZE: u8 = 13;
const PragTyp_PAGE_SIZE: u8 = 31;
const PragTyp_SECURE_DELETE: u8 = 33;
const PragTyp_PAGE_COUNT: u8 = 27;
const PragTyp_LOCKING_MODE: u8 = 26;
const PragTyp_JOURNAL_MODE: u8 = 23;
const PragTyp_JOURNAL_SIZE_LIMIT: u8 = 24;
const PragTyp_AUTO_VACUUM: u8 = 3;
const PragTyp_INCREMENTAL_VACUUM: u8 = 19;
const PragTyp_CACHE_SIZE: u8 = 6;
const PragTyp_CACHE_SPILL: u8 = 7;
const PragTyp_MMAP_SIZE: u8 = 28;
const PragTyp_TEMP_STORE: u8 = 39;
const PragTyp_TEMP_STORE_DIRECTORY: u8 = 40;
const PragTyp_SYNCHRONOUS: u8 = 36;
const PragTyp_FLAG: u8 = 4;
const PragTyp_TABLE_INFO: u8 = 37;
const PragTyp_TABLE_LIST: u8 = 38;
const PragTyp_STATS: u8 = 45;
const PragTyp_INDEX_INFO: u8 = 20;
const PragTyp_INDEX_LIST: u8 = 21;
const PragTyp_DATABASE_LIST: u8 = 12;
const PragTyp_COLLATION_LIST: u8 = 9;
const PragTyp_FUNCTION_LIST: u8 = 17;
const PragTyp_MODULE_LIST: u8 = 29;
const PragTyp_PRAGMA_LIST: u8 = 32;
const PragTyp_FOREIGN_KEY_LIST: u8 = 16;
const PragTyp_FOREIGN_KEY_CHECK: u8 = 15;
const PragTyp_CASE_SENSITIVE_LIKE: u8 = 8;
const PragTyp_INTEGRITY_CHECK: u8 = 22;
const PragTyp_ENCODING: u8 = 14;
const PragTyp_HEADER_VALUE: u8 = 2;
const PragTyp_COMPILE_OPTIONS: u8 = 10;
const PragTyp_WAL_CHECKPOINT: u8 = 43;
const PragTyp_WAL_AUTOCHECKPOINT: u8 = 42;
const PragTyp_SHRINK_MEMORY: u8 = 34;
const PragTyp_OPTIMIZE: u8 = 30;
const PragTyp_SOFT_HEAP_LIMIT: u8 = 35;
const PragTyp_HARD_HEAP_LIMIT: u8 = 18;
const PragTyp_THREADS: u8 = 41;
const PragTyp_ANALYSIS_LIMIT: u8 = 1;
const PragTyp_LOCK_STATUS: u8 = 44;

// ─── extern symbols ──────────────────────────────────────────────────────────
extern const sqlite3StrBINARY: u8; // char[] — its address is the data
extern const sqlite3StdType: [6][*:0]const u8;
extern const sqlite3CtypeMap: [256]u8;
extern var sqlite3_temp_directory: ?[*:0]u8;
extern var sqlite3BuiltinFunctions: u8; // FuncDefHash; .a is array of FuncDef*
extern var sqlite3Config: u8; // Sqlite3Config (sqlite3GlobalConfig is a macro alias); .szMmap field
extern fn sqlite3WalDefaultHook() callconv(.c) void; // address compared only

inline fn sqlite3Isdigit(x: u8) bool {
    return (sqlite3CtypeMap[x] & 0x04) != 0;
}
inline fn sqlite3Tolower(x: u8) u8 {
    return sqlite3UpperToLower[x];
}
extern const sqlite3UpperToLower: [256]u8;

// VDBE assembly
extern fn sqlite3GetVdbe(pParse: Cptr) callconv(.c) Cptr;
extern fn sqlite3VdbeRunOnlyOnce(p: Cptr) callconv(.c) void;
extern fn sqlite3VdbeAddOp0(p: Cptr, op: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp1(p: Cptr, op: c_int, p1: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp2(p: Cptr, op: c_int, p1: c_int, p2: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp3(p: Cptr, op: c_int, p1: c_int, p2: c_int, p3: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp4(p: Cptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: ?[*]const u8, p4type: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp4Int(p: Cptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp4Dup8(p: Cptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: ?[*]const u8, p4type: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOpList(p: Cptr, nOp: c_int, aOp: ?*const anyopaque, iLineno: c_int) callconv(.c) Cptr;
extern fn sqlite3VdbeChangeP3(p: Cptr, addr: c_int, p3: c_int) callconv(.c) void;
extern fn sqlite3VdbeChangeP4(p: Cptr, addr: c_int, zP4: ?[*]const u8, n: c_int) callconv(.c) void;
extern fn sqlite3VdbeChangeP5(p: Cptr, p5: u16) callconv(.c) void;
extern fn sqlite3VdbeJumpHere(p: Cptr, addr: c_int) callconv(.c) void;
extern fn sqlite3VdbeGoto(p: Cptr, addr: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeMakeLabel(pParse: Cptr) callconv(.c) c_int;
extern fn sqlite3VdbeResolveLabel(p: Cptr, x: c_int) callconv(.c) void;
extern fn sqlite3VdbeCurrentAddr(p: Cptr) callconv(.c) c_int;
extern fn sqlite3VdbeGetOp(p: Cptr, addr: c_int) callconv(.c) Cptr;
extern fn sqlite3VdbeLoadString(p: Cptr, iDest: c_int, zStr: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3VdbeMultiLoad(p: Cptr, iDest: c_int, zTypes: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3VdbeSetNumCols(p: Cptr, nResColumn: c_int) callconv(.c) void;
extern fn sqlite3VdbeSetColName(p: Cptr, idx: c_int, var_: c_int, name: ?[*:0]const u8, x: ?*anyopaque) callconv(.c) void;
extern fn sqlite3VdbeUsesBtree(p: Cptr, i: c_int) callconv(.c) void;
// These are real functions only under SQLITE_DEBUG; in production they are
// no-op macros, so the symbols do not exist. Reference them only under config,
// so the production link never names the symbol.
inline fn sqlite3VdbeVerifyNoMallocRequired(p: Cptr, n: c_int) void {
    if (config.sqlite_debug) {
        const f = @extern(*const fn (Cptr, c_int) callconv(.c) void, .{ .name = "sqlite3VdbeVerifyNoMallocRequired" });
        f(p, n);
    }
}
inline fn sqlite3VdbeVerifyNoResultRow(p: Cptr) void {
    if (config.sqlite_debug) {
        const f = @extern(*const fn (Cptr) callconv(.c) void, .{ .name = "sqlite3VdbeVerifyNoResultRow" });
        f(p);
    }
}
extern fn sqlite3VdbeReusable(p: Cptr) callconv(.c) void;
extern fn sqlite3VdbeAppendP4(p: Cptr, pP4: ?*anyopaque, p4type: c_int) callconv(.c) void;
extern fn sqlite3VdbeSetP4KeyInfo(pParse: Cptr, pIdx: Cptr) callconv(.c) void;
extern fn sqlite3VdbeTypeofColumn(p: Cptr, reg: c_int) callconv(.c) void;

// Parse / schema helpers
extern fn sqlite3TwoPartName(pParse: Cptr, p1: Cptr, p2: Cptr, ppId: *Cptr) callconv(.c) c_int;
extern fn sqlite3OpenTempDatabase(pParse: Cptr) callconv(.c) c_int;
extern fn sqlite3NameFromToken(db: Cptr, p: Cptr) callconv(.c) ?[*:0]u8;
extern fn sqlite3MPrintf(db: Cptr, fmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3AuthCheck(pParse: Cptr, code: c_int, a: ?[*:0]const u8, b: ?[*:0]const u8, c: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3ReadSchema(pParse: Cptr) callconv(.c) c_int;
extern fn sqlite3CodeVerifySchema(pParse: Cptr, iDb: c_int) callconv(.c) void;
extern fn sqlite3CodeVerifyNamedSchema(pParse: Cptr, zDb: ?[*:0]const u8) callconv(.c) void;
extern fn sqlite3BeginWriteOperation(pParse: Cptr, setStatement: c_int, iDb: c_int) callconv(.c) void;
extern fn sqlite3LocateTable(pParse: Cptr, flags: u32, zName: ?[*:0]const u8, zDbase: ?[*:0]const u8) callconv(.c) Cptr;
extern fn sqlite3FindTable(db: Cptr, zName: ?[*:0]const u8, zDatabase: ?[*:0]const u8) callconv(.c) Cptr;
extern fn sqlite3FindIndex(db: Cptr, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) callconv(.c) Cptr;
extern fn sqlite3PrimaryKeyIndex(pTab: Cptr) callconv(.c) Cptr;
extern fn sqlite3ViewGetColumnNames(pParse: Cptr, pTab: Cptr) callconv(.c) c_int;
extern fn sqlite3SchemaToIndex(db: Cptr, p: Cptr) callconv(.c) c_int;
extern fn sqlite3TableLock(pParse: Cptr, iDb: c_int, iTab: u32, isWriteLock: u8, zName: ?[*:0]const u8) callconv(.c) void;
extern fn sqlite3OpenTable(pParse: Cptr, iCur: c_int, iDb: c_int, pTab: Cptr, op: c_int) callconv(.c) void;
extern fn sqlite3OpenTableAndIndices(pParse: Cptr, pTab: Cptr, op: c_int, p5: u8, iBase: c_int, aToOpen: ?[*]u8, piDataCur: *c_int, piIdxCur: *c_int) callconv(.c) c_int;
extern fn sqlite3TouchRegister(pParse: Cptr, iReg: c_int) callconv(.c) void;
extern fn sqlite3GetTempReg(pParse: Cptr) callconv(.c) c_int;
extern fn sqlite3GetTempRange(pParse: Cptr, nReg: c_int) callconv(.c) c_int;
extern fn sqlite3ReleaseTempRange(pParse: Cptr, iReg: c_int, nReg: c_int) callconv(.c) void;
extern fn sqlite3ClearTempRegCache(pParse: Cptr) callconv(.c) void;
extern fn sqlite3ColumnExpr(pTab: Cptr, pCol: Cptr) callconv(.c) Cptr;
extern fn sqlite3ColumnType(pCol: Cptr, def: [*:0]const u8) callconv(.c) ?[*:0]const u8;
extern fn sqlite3ColumnDefault(v: Cptr, pTab: Cptr, i: c_int, iReg: c_int) callconv(.c) void;
extern fn sqlite3TableColumnToStorage(pTab: Cptr, iCol: i16) callconv(.c) c_int;
extern fn sqlite3TableColumnToIndex(pIdx: Cptr, iCol: i16) callconv(.c) i16;
extern fn sqlite3ExprCodeGetColumnOfTable(v: Cptr, pTab: Cptr, iCur: c_int, iCol: c_int, regOut: c_int) callconv(.c) void;
extern fn sqlite3ExprCodeLoadIndexColumn(pParse: Cptr, pIdx: Cptr, iCur: c_int, iIdxCol: c_int, regOut: c_int) callconv(.c) void;
extern fn sqlite3GenerateIndexKey(pParse: Cptr, pIdx: Cptr, iCur: c_int, regOut: c_int, prefixOnly: c_int, piPartIdxLabel: *c_int, pPrior: Cptr, regPrior: c_int) callconv(.c) c_int;
extern fn sqlite3ResolvePartIdxLabel(pParse: Cptr, label: c_int) callconv(.c) void;
extern fn sqlite3ExprListDup(db: Cptr, p: Cptr, flags: c_int) callconv(.c) Cptr;
extern fn sqlite3ExprListDelete(db: Cptr, p: Cptr) callconv(.c) void;
extern fn sqlite3ExprIfTrue(pParse: Cptr, pExpr: Cptr, dest: c_int, jumpIfNull: c_int) callconv(.c) void;
extern fn sqlite3ExprIfFalse(pParse: Cptr, pExpr: Cptr, dest: c_int, jumpIfNull: c_int) callconv(.c) void;
extern fn sqlite3IndexAffinityStr(db: Cptr, pIdx: Cptr) callconv(.c) ?[*:0]const u8;
extern fn sqlite3FkLocateIndex(pParse: Cptr, pParent: Cptr, pFKey: Cptr, ppIdx: *Cptr, paiCol: ?*?*c_int) callconv(.c) c_int;
extern fn sqlite3PreferredTableName(zName: ?[*:0]const u8) callconv(.c) ?[*:0]const u8;
extern fn sqlite3RegisterLikeFunctions(db: Cptr, caseSensitive: c_int) callconv(.c) void;
extern fn sqlite3ValueFromExpr(db: Cptr, pExpr: Cptr, enc: u8, aff: u8, ppVal: *Cptr) callconv(.c) c_int;
extern fn sqlite3ValueFree(v: Cptr) callconv(.c) void;
extern fn sqlite3_value_type(v: Cptr) callconv(.c) c_int;
extern fn sqlite3SetTextEncoding(db: Cptr, enc: u8) callconv(.c) void;

// misc utility
extern fn sqlite3_file_control(db: Cptr, zDbName: ?[*:0]const u8, op: c_int, pArg: ?*anyopaque) callconv(.c) c_int;
extern fn sqlite3ErrorMsg(pParse: Cptr, fmt: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3ErrStr(rc: c_int) callconv(.c) ?[*:0]const u8;
extern fn sqlite3OomFault(db: Cptr) callconv(.c) void;
extern fn sqlite3ResetAllSchemasOfConnection(db: Cptr) callconv(.c) void;
extern fn sqlite3DbFree(db: Cptr, p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3_free(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3_malloc(n: c_int) callconv(.c) ?*anyopaque;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3DbMallocRawNN(db: Cptr, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3Atoi(z: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3AbsInt32(x: c_int) callconv(.c) c_int;
extern fn sqlite3GetInt32(z: ?[*:0]const u8, p: *c_int) callconv(.c) c_int;
extern fn sqlite3DecOrHexToI64(z: ?[*:0]const u8, p: *i64) callconv(.c) c_int;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) callconv(.c) c_int;

// Btree / Pager
extern fn sqlite3BtreeSetPagerFlags(p: Cptr, flags: c_uint) callconv(.c) void;
extern fn sqlite3BtreeGetPageSize(p: Cptr) callconv(.c) c_int;
extern fn sqlite3BtreeSetPageSize(p: Cptr, pageSize: c_int, nReserve: c_int, fix: c_int) callconv(.c) c_int;
extern fn sqlite3BtreeSecureDelete(p: Cptr, newFlag: c_int) callconv(.c) c_int;
extern fn sqlite3BtreeGetAutoVacuum(p: Cptr) callconv(.c) c_int;
extern fn sqlite3BtreeSetAutoVacuum(p: Cptr, autoVacuum: c_int) callconv(.c) c_int;
extern fn sqlite3BtreeSetCacheSize(p: Cptr, mxPage: c_int) callconv(.c) void;
extern fn sqlite3BtreeSetSpillSize(p: Cptr, mxPage: c_int) callconv(.c) c_int;
extern fn sqlite3BtreeSetMmapLimit(p: Cptr, szMmap: i64) callconv(.c) c_int;
extern fn sqlite3BtreeGetFilename(p: Cptr) callconv(.c) ?[*:0]const u8;
extern fn sqlite3BtreePager(p: Cptr) callconv(.c) Cptr;
extern fn sqlite3BtreeTxnState(p: Cptr) callconv(.c) c_int;
extern fn sqlite3BtreeClose(p: Cptr) callconv(.c) c_int;
extern fn sqlite3PagerLockingMode(pPager: Cptr, eMode: c_int) callconv(.c) c_int;
extern fn sqlite3PagerJournalSizeLimit(pPager: Cptr, iLimit: i64) callconv(.c) i64;
extern fn sqlite3OsAccess(pVfs: Cptr, zPath: ?[*:0]const u8, flags: c_int, pResOut: *c_int) callconv(.c) c_int;

// public API
extern fn sqlite3_prepare_v2(db: Cptr, zSql: ?[*]const u8, nByte: c_int, ppStmt: *Cptr, pzTail: ?*?[*]const u8) callconv(.c) c_int;
extern fn sqlite3_prepare_v3(db: Cptr, zSql: ?[*]const u8, nByte: c_int, prepFlags: c_uint, ppStmt: *Cptr, pzTail: ?*?[*]const u8) callconv(.c) c_int;
extern fn sqlite3_finalize(pStmt: Cptr) callconv(.c) c_int;
extern fn sqlite3_step(pStmt: Cptr) callconv(.c) c_int;
extern fn sqlite3_column_value(pStmt: Cptr, i: c_int) callconv(.c) Cptr;
extern fn sqlite3_result_value(ctx: Cptr, pValue: Cptr) callconv(.c) void;
extern fn sqlite3_result_text(ctx: Cptr, z: ?[*]const u8, n: c_int, xDel: ?*anyopaque) callconv(.c) void;
extern fn sqlite3_value_text(pVal: Cptr) callconv(.c) ?[*]const u8;
extern fn sqlite3_busy_timeout(db: Cptr, ms: c_int) callconv(.c) c_int;
extern fn sqlite3_wal_autocheckpoint(db: Cptr, N: c_int) callconv(.c) c_int;
extern fn sqlite3_db_release_memory(db: Cptr) callconv(.c) c_int;
extern fn sqlite3_soft_heap_limit64(N: i64) callconv(.c) i64;
extern fn sqlite3_hard_heap_limit64(N: i64) callconv(.c) i64;
extern fn sqlite3_limit(db: Cptr, id: c_int, newVal: c_int) callconv(.c) c_int;
extern fn sqlite3_compileoption_get(N: c_int) callconv(.c) ?[*:0]const u8;
extern fn sqlite3_declare_vtab(db: Cptr, zSQL: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3_errmsg(db: Cptr) callconv(.c) ?[*:0]const u8;
extern fn sqlite3_mutex_enter(p: Cptr) callconv(.c) void;
extern fn sqlite3_mutex_leave(p: Cptr) callconv(.c) void;
extern fn sqlite3MutexAlloc(id: c_int) callconv(.c) Cptr;
extern fn sqlite3VtabCreateModule(db: Cptr, zName: ?[*:0]const u8, pModule: ?*const anyopaque, pAux: ?*anyopaque, xDestroy: ?*anyopaque) callconv(.c) Cptr;
extern fn sqlite3HashFind(h: Cptr, key: ?[*:0]const u8) callconv(.c) ?*anyopaque;
extern fn sqlite3StrAccumInit(p: Cptr, db: Cptr, zBase: ?[*]u8, n: c_int, mx: c_int) callconv(.c) void;
extern fn sqlite3StrAccumFinish(p: Cptr) callconv(.c) ?[*:0]u8;
extern fn sqlite3_str_append(p: Cptr, z: [*]const u8, n: c_int) callconv(.c) void;
extern fn sqlite3_str_appendall(p: Cptr, z: ?[*:0]const u8) callconv(.c) void;
extern fn sqlite3_str_appendf(p: Cptr, fmt: [*:0]const u8, ...) callconv(.c) void;

// ─── field accessors ─────────────────────────────────────────────────────────
inline fn dbAt(db: Cptr, i: c_int) ?*anyopaque {
    const aDb = rdp(db, sqlite3_aDb);
    return @ptrCast(base(aDb) + @as(usize, @intCast(i)) * sizeof_Db);
}
inline fn hashFirst(pHash: ?*anyopaque) ?*anyopaque {
    return rdp(pHash, Hash_first);
}
inline fn hashNext(elem: ?*anyopaque) ?*anyopaque {
    return rdp(elem, HashElem_next);
}
inline fn hashData(elem: ?*anyopaque) ?*anyopaque {
    return rdp(elem, HashElem_data);
}
inline fn colAt(pTab: Cptr, i: usize) ?*anyopaque {
    const aCol = rdp(pTab, Table_aCol);
    return @ptrCast(base(aCol) + i * sizeof_Column);
}
inline fn colNotNull(pCol: Cptr) u8 {
    return base(pCol)[Column_bft_byte] & 0x0F;
}
inline fn colECType(pCol: Cptr) u8 {
    return base(pCol)[Column_bft_byte] >> 4;
}
inline fn idxType(pIdx: Cptr) u8 {
    return base(pIdx)[Index_bits_byte] & 0x03;
}
inline fn idxHasStat1(pIdx: Cptr) bool {
    return (base(pIdx)[Index_bits_byte] & 0x80) != 0;
}
inline fn tabFlags(pTab: Cptr) u32 {
    return rd(u32, pTab, Table_tabFlags);
}
inline fn hasRowid(pTab: Cptr) bool {
    return (tabFlags(pTab) & TF_WithoutRowid) == 0;
}
const TABTYP_NORM: u8 = 0;
const TABTYP_VTAB: u8 = 1;
const TABTYP_VIEW: u8 = 2;
inline fn eTabType(pTab: Cptr) u8 {
    return rd(u8, pTab, Table_eTabType);
}
inline fn isOrdinaryTable(pTab: Cptr) bool {
    return eTabType(pTab) == TABTYP_NORM;
}
inline fn isVirtual(pTab: Cptr) bool {
    return eTabType(pTab) == TABTYP_VTAB;
}
inline fn isView(pTab: Cptr) bool {
    return eTabType(pTab) == TABTYP_VIEW;
}
inline fn isUniqueIndex(pIdx: Cptr) bool {
    return rd(u8, pIdx, Index_onError) != OE_None;
}
inline fn isPrimaryKeyIndex(pIdx: Cptr) bool {
    return idxType(pIdx) == 2; // SQLITE_IDXTYPE_PRIMARYKEY
}
inline fn tokenZ(t: Cptr) ?[*]const u8 {
    return @ptrCast(rdp(t, Token_z));
}
inline fn tokenN(t: Cptr) u32 {
    return rd(u32, t, Token_n);
}
inline fn encOf(db: Cptr) u8 {
    return rd(u8, db, sqlite3_enc);
}

// VdbeOp helpers
inline fn opAt(aOp: ?*anyopaque, i: usize) ?*anyopaque {
    return @ptrCast(base(aOp) + i * sizeof_VdbeOp);
}
inline fn opSetP1(op: ?*anyopaque, v: c_int) void {
    wr(c_int, op, VdbeOp_p1_off, v);
}
inline fn opSetP2(op: ?*anyopaque, v: c_int) void {
    wr(c_int, op, VdbeOp_p2_off, v);
}
inline fn opSetP3(op: ?*anyopaque, v: c_int) void {
    wr(c_int, op, VdbeOp_p3_off, v);
}
inline fn opSetP5(op: ?*anyopaque, v: u16) void {
    wr(u16, op, VdbeOp_p5_off, v);
}
inline fn opSetOpcode(op: ?*anyopaque, v: u8) void {
    base(op)[VdbeOp_opcode_off] = v;
}
inline fn opOpcode(op: ?*anyopaque) u8 {
    return base(op)[VdbeOp_opcode_off];
}
inline fn opSetP4z(op: ?*anyopaque, z: ?[*:0]const u8) void {
    wr(?*anyopaque, op, VdbeOp_p4_off, @constCast(@ptrCast(z)));
}
inline fn opSetP4type(op: ?*anyopaque, t: i8) void {
    wr(i8, op, VdbeOp_p4type_off, t);
}

// ════════════════════════════════════════════════════════════════════════════
//  PragmaName table + pragCName (reproduced from generated pragma.h)
// ════════════════════════════════════════════════════════════════════════════
const PragmaName = extern struct {
    zName: [*:0]const u8,
    ePragTyp: u8,
    mPragFlg: u8,
    iPragCName: u8,
    nPragCName: u8,
    iArg: u64,
};

inline fn pn(name: [*:0]const u8, typ: u8, flg: u8, cn: u8, ncn: u8, arg: u64) PragmaName {
    return .{ .zName = name, .ePragTyp = typ, .mPragFlg = flg, .iPragCName = cn, .nPragCName = ncn, .iArg = arg };
}

const pragCName = [_][*:0]const u8{
    "id",        "seq",     "table",   "from",     "to", // 0..4
    "on_update", "on_delete", "match",            // 5..7
    "cid",       "name",    "type",    "notnull",  "dflt_value", "pk", "hidden", // 8..14
    "name",      "builtin", "type",    "enc",      "narg", "flags", // 15..20
    "schema",    "name",    "type",    "ncol",     "wr", "strict", // 21..26
    "seqno",     "cid",     "name",    "desc",     "coll", "key", // 27..32
    "seq",       "name",    "unique",  "origin",   "partial", // 33..37
    "tbl",       "idx",     "wdth",    "hght",     "flgs", // 38..42
    "table",     "rowid",   "parent",  "fkid", // 43..46
    "busy",      "log",     "checkpointed", // 47..49
    "seq",       "name",    "file", // 50..52
    "database",  "status", // 53..54
    "cache_size", // 55
    "timeout", // 56
};

// Production library: 66 entries (no SQLITE_DEBUG pragmas).
const _aPragmaName_prod = [_]PragmaName{
    pn("analysis_limit", 1, 16, 0, 0, 0),
    pn("application_id", 2, 20, 0, 0, 8),
    pn("auto_vacuum", 3, 149, 0, 0, 0),
    pn("automatic_index", 4, 20, 0, 0, 32768),
    pn("busy_timeout", 5, 16, 56, 1, 0),
    pn("cache_size", 6, 149, 0, 0, 0),
    pn("cache_spill", 7, 148, 0, 0, 0),
    pn("case_sensitive_like", 8, 2, 0, 0, 0),
    pn("cell_size_check", 4, 20, 0, 0, 2097152),
    pn("checkpoint_fullfsync", 4, 20, 0, 0, 16),
    pn("collation_list", 9, 16, 33, 2, 0),
    pn("compile_options", 10, 16, 0, 0, 0),
    pn("count_changes", 4, 20, 0, 0, 4294967296),
    pn("data_version", 2, 24, 0, 0, 15),
    pn("database_list", 12, 16, 50, 3, 0),
    pn("default_cache_size", 13, 149, 55, 1, 0),
    pn("defer_foreign_keys", 4, 20, 0, 0, 524288),
    pn("empty_result_callbacks", 4, 20, 0, 0, 256),
    pn("encoding", 14, 20, 0, 0, 0),
    pn("foreign_key_check", 15, 113, 43, 4, 0),
    pn("foreign_key_list", 16, 97, 0, 8, 0),
    pn("foreign_keys", 4, 20, 0, 0, 16384),
    pn("freelist_count", 2, 24, 0, 0, 0),
    pn("full_column_names", 4, 20, 0, 0, 4),
    pn("fullfsync", 4, 20, 0, 0, 8),
    pn("function_list", 17, 16, 15, 6, 0),
    pn("hard_heap_limit", 18, 16, 0, 0, 0),
    pn("ignore_check_constraints", 4, 20, 0, 0, 512),
    pn("incremental_vacuum", 19, 3, 0, 0, 0),
    pn("index_info", 20, 97, 27, 3, 0),
    pn("index_list", 21, 97, 33, 5, 0),
    pn("index_xinfo", 20, 97, 27, 6, 1),
    pn("integrity_check", 22, 113, 0, 0, 0),
    pn("journal_mode", 23, 145, 0, 0, 0),
    pn("journal_size_limit", 24, 144, 0, 0, 0),
    pn("legacy_alter_table", 4, 20, 0, 0, 67108864),
    pn("locking_mode", 26, 144, 0, 0, 0),
    pn("max_page_count", 27, 145, 0, 0, 0),
    pn("mmap_size", 28, 0, 0, 0, 0),
    pn("module_list", 29, 16, 9, 1, 0),
    pn("optimize", 30, 33, 0, 0, 0),
    pn("page_count", 27, 145, 0, 0, 0),
    pn("page_size", 31, 148, 0, 0, 0),
    pn("pragma_list", 32, 16, 9, 1, 0),
    pn("query_only", 4, 20, 0, 0, 1048576),
    pn("quick_check", 22, 113, 0, 0, 0),
    pn("read_uncommitted", 4, 20, 0, 0, 17179869184),
    pn("recursive_triggers", 4, 20, 0, 0, 8192),
    pn("reverse_unordered_selects", 4, 20, 0, 0, 4096),
    pn("schema_version", 2, 20, 0, 0, 1),
    pn("secure_delete", 33, 16, 0, 0, 0),
    pn("short_column_names", 4, 20, 0, 0, 64),
    pn("shrink_memory", 34, 2, 0, 0, 0),
    pn("soft_heap_limit", 35, 16, 0, 0, 0),
    pn("synchronous", 36, 149, 0, 0, 0),
    pn("table_info", 37, 97, 8, 6, 0),
    pn("table_list", 38, 33, 21, 6, 0),
    pn("table_xinfo", 37, 97, 8, 7, 1),
    pn("temp_store", 39, 20, 0, 0, 0),
    pn("temp_store_directory", 40, 4, 0, 0, 0),
    pn("threads", 41, 16, 0, 0, 0),
    pn("trusted_schema", 4, 20, 0, 0, 128),
    pn("user_version", 2, 20, 0, 0, 6),
    pn("wal_autocheckpoint", 42, 0, 0, 0, 0),
    pn("wal_checkpoint", 43, 1, 47, 3, 0),
    pn("writable_schema", 4, 20, 0, 0, 134217729),
};

// Testfixture (--dev SQLITE_DEBUG): 75 entries; 9 extra DEBUG-only pragmas.
const _aPragmaName_tf = [_]PragmaName{
    pn("analysis_limit", 1, 16, 0, 0, 0),
    pn("application_id", 2, 20, 0, 0, 8),
    pn("auto_vacuum", 3, 149, 0, 0, 0),
    pn("automatic_index", 4, 20, 0, 0, 32768),
    pn("busy_timeout", 5, 16, 56, 1, 0),
    pn("cache_size", 6, 149, 0, 0, 0),
    pn("cache_spill", 7, 148, 0, 0, 0),
    pn("case_sensitive_like", 8, 2, 0, 0, 0),
    pn("cell_size_check", 4, 20, 0, 0, 2097152),
    pn("checkpoint_fullfsync", 4, 20, 0, 0, 16),
    pn("collation_list", 9, 16, 33, 2, 0),
    pn("compile_options", 10, 16, 0, 0, 0),
    pn("count_changes", 4, 20, 0, 0, 4294967296),
    pn("data_version", 2, 24, 0, 0, 15),
    pn("database_list", 12, 16, 50, 3, 0),
    pn("default_cache_size", 13, 149, 55, 1, 0),
    pn("defer_foreign_keys", 4, 20, 0, 0, 524288),
    pn("empty_result_callbacks", 4, 20, 0, 0, 256),
    pn("encoding", 14, 20, 0, 0, 0),
    pn("foreign_key_check", 15, 113, 43, 4, 0),
    pn("foreign_key_list", 16, 97, 0, 8, 0),
    pn("foreign_keys", 4, 20, 0, 0, 16384),
    pn("freelist_count", 2, 24, 0, 0, 0),
    pn("full_column_names", 4, 20, 0, 0, 4),
    pn("fullfsync", 4, 20, 0, 0, 8),
    pn("function_list", 17, 16, 15, 6, 0),
    pn("hard_heap_limit", 18, 16, 0, 0, 0),
    pn("ignore_check_constraints", 4, 20, 0, 0, 512),
    pn("incremental_vacuum", 19, 3, 0, 0, 0),
    pn("index_info", 20, 97, 27, 3, 0),
    pn("index_list", 21, 97, 33, 5, 0),
    pn("index_xinfo", 20, 97, 27, 6, 1),
    pn("integrity_check", 22, 113, 0, 0, 0),
    pn("journal_mode", 23, 145, 0, 0, 0),
    pn("journal_size_limit", 24, 144, 0, 0, 0),
    pn("legacy_alter_table", 4, 20, 0, 0, 67108864),
    pn("lock_status", 44, 16, 53, 2, 0),
    pn("locking_mode", 26, 144, 0, 0, 0),
    pn("max_page_count", 27, 145, 0, 0, 0),
    pn("mmap_size", 28, 0, 0, 0, 0),
    pn("module_list", 29, 16, 9, 1, 0),
    pn("optimize", 30, 33, 0, 0, 0),
    pn("page_count", 27, 145, 0, 0, 0),
    pn("page_size", 31, 148, 0, 0, 0),
    pn("parser_trace", 4, 20, 0, 0, 144115188075855872),
    pn("pragma_list", 32, 16, 9, 1, 0),
    pn("query_only", 4, 20, 0, 0, 1048576),
    pn("quick_check", 22, 113, 0, 0, 0),
    pn("read_uncommitted", 4, 20, 0, 0, 17179869184),
    pn("recursive_triggers", 4, 20, 0, 0, 8192),
    pn("reverse_unordered_selects", 4, 20, 0, 0, 4096),
    pn("schema_version", 2, 20, 0, 0, 1),
    pn("secure_delete", 33, 16, 0, 0, 0),
    pn("short_column_names", 4, 20, 0, 0, 64),
    pn("shrink_memory", 34, 2, 0, 0, 0),
    pn("soft_heap_limit", 35, 16, 0, 0, 0),
    pn("sql_trace", 4, 20, 0, 0, 4503599627370496),
    pn("stats", 45, 145, 38, 5, 0),
    pn("synchronous", 36, 149, 0, 0, 0),
    pn("table_info", 37, 97, 8, 6, 0),
    pn("table_list", 38, 33, 21, 6, 0),
    pn("table_xinfo", 37, 97, 8, 7, 1),
    pn("temp_store", 39, 20, 0, 0, 0),
    pn("temp_store_directory", 40, 4, 0, 0, 0),
    pn("threads", 41, 16, 0, 0, 0),
    pn("trusted_schema", 4, 20, 0, 0, 128),
    pn("user_version", 2, 20, 0, 0, 6),
    pn("vdbe_addoptrace", 4, 20, 0, 0, 36028797018963968),
    pn("vdbe_debug", 4, 20, 0, 0, 31525197391593472),
    pn("vdbe_eqp", 4, 20, 0, 0, 72057594037927936),
    pn("vdbe_listing", 4, 20, 0, 0, 9007199254740992),
    pn("vdbe_trace", 4, 20, 0, 0, 18014398509481984),
    pn("wal_autocheckpoint", 42, 0, 0, 0, 0),
    pn("wal_checkpoint", 43, 1, 47, 3, 0),
    pn("writable_schema", 4, 20, 0, 0, 134217729),
};

const aPragmaName = if (config.sqlite_debug) _aPragmaName_tf[0..] else _aPragmaName_prod[0..];

// ════════════════════════════════════════════════════════════════════════════
//  Static helpers
// ════════════════════════════════════════════════════════════════════════════

/// Interpret z as a safety level. 0=OFF, 1=ON/NORMAL, 2=FULL, 3=EXTRA.
fn getSafetyLevel(z: [*:0]const u8, omitFull: c_int, dflt: u8) u8 {
    const zText = "onoffalseyestruextrafull";
    const iOffset = [_]u8{ 0, 1, 2, 4, 9, 12, 15, 20 };
    const iLength = [_]u8{ 2, 2, 3, 5, 3, 4, 5, 4 };
    const iValue = [_]u8{ 1, 0, 0, 0, 1, 1, 3, 2 };
    if (sqlite3Isdigit(z[0])) {
        return @bitCast(@as(i8, @truncate(sqlite3Atoi(z))));
    }
    const n = sqlite3Strlen30(z);
    var i: usize = 0;
    while (i < iLength.len) : (i += 1) {
        if (@as(c_int, iLength[i]) == n and
            sqlite3_strnicmp(@ptrCast(zText.ptr + iOffset[i]), z, n) == 0 and
            (omitFull == 0 or iValue[i] <= 1))
        {
            return iValue[i];
        }
    }
    return dflt;
}

export fn sqlite3GetBoolean(z: ?[*:0]const u8, dflt: u8) callconv(.c) u8 {
    return @intFromBool(getSafetyLevel(z.?, 1, dflt) != 0);
}

fn getLockingMode(z: ?[*:0]const u8) c_int {
    if (z) |zz| {
        if (sqlite3_stricmp(zz, "exclusive") == 0) return PAGER_LOCKINGMODE_EXCLUSIVE;
        if (sqlite3_stricmp(zz, "normal") == 0) return PAGER_LOCKINGMODE_NORMAL;
    }
    return PAGER_LOCKINGMODE_QUERY;
}

fn getAutoVacuum(z: [*:0]const u8) c_int {
    if (sqlite3_stricmp(z, "none") == 0) return BTREE_AUTOVACUUM_NONE;
    if (sqlite3_stricmp(z, "full") == 0) return BTREE_AUTOVACUUM_FULL;
    if (sqlite3_stricmp(z, "incremental") == 0) return BTREE_AUTOVACUUM_INCR;
    const i = sqlite3Atoi(z);
    return if (i >= 0 and i <= 2) i else 0;
}

fn getTempStore(z: [*:0]const u8) c_int {
    if (z[0] >= '0' and z[0] <= '2') {
        return @as(c_int, z[0]) - '0';
    } else if (sqlite3_stricmp(z, "file") == 0) {
        return 1;
    } else if (sqlite3_stricmp(z, "memory") == 0) {
        return 2;
    } else {
        return 0;
    }
}

fn invalidateTempStorage(pParse: Cptr) c_int {
    const db = rdp(pParse, Parse_db);
    const pBt1 = rdp(dbAt(db, 1), Db_pBt);
    if (pBt1 != null) {
        if (rd(u8, db, sqlite3_autoCommit) == 0 or
            sqlite3BtreeTxnState(pBt1) != SQLITE_TXN_NONE)
        {
            sqlite3ErrorMsg(pParse, "temporary storage cannot be changed from within a transaction");
            return SQLITE_ERROR;
        }
        _ = sqlite3BtreeClose(pBt1);
        wr(?*anyopaque, dbAt(db, 1), Db_pBt, null);
        sqlite3ResetAllSchemasOfConnection(db);
    }
    return SQLITE_OK;
}

fn changeTempStorage(pParse: Cptr, zStorageType: [*:0]const u8) c_int {
    const ts = getTempStore(zStorageType);
    const db = rdp(pParse, Parse_db);
    if (rd(u8, db, sqlite3_temp_store) == ts) return SQLITE_OK;
    if (invalidateTempStorage(pParse) != SQLITE_OK) return SQLITE_ERROR;
    wr(u8, db, sqlite3_temp_store, @intCast(ts));
    return SQLITE_OK;
}

fn setPragmaResultColumnNames(v: Cptr, pPragma: *const PragmaName) void {
    const n = pPragma.nPragCName;
    sqlite3VdbeSetNumCols(v, if (n == 0) 1 else n);
    if (n == 0) {
        sqlite3VdbeSetColName(v, 0, COLNAME_NAME, pPragma.zName, SQLITE_STATIC);
    } else {
        var i: c_int = 0;
        var j: usize = pPragma.iPragCName;
        while (i < n) : ({
            i += 1;
            j += 1;
        }) {
            sqlite3VdbeSetColName(v, i, COLNAME_NAME, pragCName[j], SQLITE_STATIC);
        }
    }
}

fn returnSingleInt(v: Cptr, value: i64) void {
    var val = value;
    _ = sqlite3VdbeAddOp4Dup8(v, OP_Int64, 0, 1, 0, @ptrCast(&val), P4_INT64);
    _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
}

fn returnSingleText(v: Cptr, zValue: ?[*:0]const u8) void {
    if (zValue) |z| {
        _ = sqlite3VdbeLoadString(v, 1, z);
        _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    }
}

fn setAllPagerFlags(db: Cptr) void {
    if (rd(u8, db, sqlite3_autoCommit) != 0) {
        var n = rd(c_int, db, sqlite3_nDb);
        var i: c_int = 0;
        const flags = rd(u64, db, sqlite3_flags);
        while (n > 0) : (n -= 1) {
            const pDb = dbAt(db, i);
            const pBt = rdp(pDb, Db_pBt);
            if (pBt != null) {
                const safety: u64 = rd(u8, pDb, Db_safety_level);
                sqlite3BtreeSetPagerFlags(pBt, @intCast(safety | (flags & PAGER_FLAGS_MASK)));
            }
            i += 1;
        }
    }
}

fn actionName(action: u8) [*:0]const u8 {
    return switch (action) {
        OE_SetNull => "SET NULL",
        OE_SetDflt => "SET DEFAULT",
        OE_Cascade => "CASCADE",
        OE_Restrict => "RESTRICT",
        else => "NO ACTION", // OE_None
    };
}

export fn sqlite3JournalModename(eMode: c_int) callconv(.c) ?[*:0]const u8 {
    const azModeName = [_][*:0]const u8{ "delete", "persist", "off", "truncate", "memory", "wal" };
    if (eMode == azModeName.len) return null;
    if (eMode < 0 or eMode > azModeName.len) return null;
    return azModeName[@intCast(eMode)];
}

fn pragmaLocate(zName: [*:0]const u8) ?*const PragmaName {
    var lwr: c_int = 0;
    var upr: c_int = @as(c_int, @intCast(aPragmaName.len)) - 1;
    var mid: c_int = 0;
    while (lwr <= upr) {
        mid = @divTrunc(lwr + upr, 2);
        const rc = sqlite3_stricmp(zName, aPragmaName[@intCast(mid)].zName);
        if (rc == 0) break;
        if (rc < 0) {
            upr = mid - 1;
        } else {
            lwr = mid + 1;
        }
    }
    return if (lwr > upr) null else &aPragmaName[@intCast(mid)];
}

fn pragmaFunclistLine(v: Cptr, p0: ?*anyopaque, isBuiltin: c_int, showInternFuncs: c_int) void {
    var mask: u32 = SQLITE_DETERMINISTIC | SQLITE_DIRECTONLY | SQLITE_SUBTYPE |
        SQLITE_INNOCUOUS | SQLITE_FUNC_INTERNAL;
    if (showInternFuncs != 0) mask = 0xffffffff;
    const azEnc = [_]?[*:0]const u8{ null, "utf8", "utf16le", "utf16be" };
    var p = p0;
    // C walks the same-name synonym chain via p->pNext (off 16), NOT the
    // hash-bucket chain p->u.pHash (off 64).
    while (p != null) : (p = rd(?*anyopaque, p, FuncDef_pNext)) {
        const funcFlags = rd(u32, p, FuncDef_funcFlags);
        if (rdp(p, FuncDef_xSFunc) == null) continue;
        if ((funcFlags & SQLITE_FUNC_INTERNAL) != 0 and showInternFuncs == 0) continue;
        const zType: [*:0]const u8 = if (rdp(p, FuncDef_xValue) != null)
            "w"
        else if (rdp(p, FuncDef_xFinalize) != null)
            "a"
        else
            "s";
        sqlite3VdbeMultiLoad(v, 1, "sissii", rdp(p, FuncDef_zName), isBuiltin, zType, azEnc[funcFlags & SQLITE_FUNC_ENCMASK], @as(c_int, rd(i16, p, FuncDef_nArg)), (funcFlags & mask) ^ SQLITE_INNOCUOUS);
    }
}

fn integrityCheckResultRow(v: Cptr) c_int {
    _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 3, 1);
    const addr = sqlite3VdbeAddOp3(v, OP_IfPos, 1, sqlite3VdbeCurrentAddr(v) + 2, 1);
    _ = sqlite3VdbeAddOp0(v, OP_Halt);
    return addr;
}

fn tableSkipIntegrityCheck(pTab: Cptr, pObjTab: Cptr) bool {
    if (pObjTab != null) {
        return pTab != pObjTab;
    } else {
        return (tabFlags(pTab) & TF_Imposter) != 0;
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  sqlite3Pragma — the giant PRAGMA dispatcher
// ════════════════════════════════════════════════════════════════════════════

// VdbeOpList records are 4 bytes each: {u8 opcode; i8 p1; i8 p2; i8 p3}.
const getCacheSize = [_]i8{
    @bitCast(@as(u8, OP_Transaction)), 0, 0, 0, // 0
    @bitCast(@as(u8, OP_ReadCookie)),  0, 1, BTREE_DEFAULT_CACHE_SIZE, // 1
    @bitCast(@as(u8, OP_IfPos)),       1, 8, 0,
    @bitCast(@as(u8, OP_Integer)),     0, 2, 0,
    @bitCast(@as(u8, OP_Subtract)),    1, 2, 1,
    @bitCast(@as(u8, OP_IfPos)),       1, 8, 0,
    @bitCast(@as(u8, OP_Integer)),     0, 1, 0, // 6
    @bitCast(@as(u8, OP_Noop)),        0, 0, 0,
    @bitCast(@as(u8, OP_ResultRow)),   1, 1, 0,
};
const getCacheSize_n: c_int = 9;

const setMeta6 = [_]i8{
    @bitCast(@as(u8, OP_Transaction)), 0, 1, 0, // 0
    @bitCast(@as(u8, OP_ReadCookie)),  0, 1, BTREE_LARGEST_ROOT_PAGE,
    @bitCast(@as(u8, OP_If)),          1, 0, 0, // 2
    @bitCast(@as(u8, OP_Halt)),        SQLITE_OK, OE_Abort, 0, // 3
    @bitCast(@as(u8, OP_SetCookie)),   0, BTREE_INCR_VACUUM, 0, // 4
};
const setMeta6_n: c_int = 5;

const setCookie = [_]i8{
    @bitCast(@as(u8, OP_Transaction)), 0, 1, 0, // 0
    @bitCast(@as(u8, OP_SetCookie)),   0, 0, 0, // 1
};
const setCookie_n: c_int = 2;

const readCookie = [_]i8{
    @bitCast(@as(u8, OP_Transaction)), 0, 0, 0, // 0
    @bitCast(@as(u8, OP_ReadCookie)),  0, 1, 0, // 1
    @bitCast(@as(u8, OP_ResultRow)),   1, 1, 0,
};
const readCookie_n: c_int = 3;

const endCode = [_]i8{
    @bitCast(@as(u8, OP_AddImm)),    1, 0, 0, // 0
    @bitCast(@as(u8, OP_IfNotZero)), 1, 4, 0, // 1
    @bitCast(@as(u8, OP_String8)),   0, 3, 0, // 2
    @bitCast(@as(u8, OP_ResultRow)), 3, 1, 0, // 3
    @bitCast(@as(u8, OP_Halt)),      0, 0, 0, // 4
    @bitCast(@as(u8, OP_String8)),   0, 3, 0, // 5
    @bitCast(@as(u8, OP_Goto)),      0, 3, 0, // 6
};
const endCode_n: c_int = 7;

export fn sqlite3Pragma(
    pParse: ?*anyopaque,
    pId1: ?*anyopaque,
    pId2: ?*anyopaque,
    pValue: ?*anyopaque,
    minusFlag: c_int,
) callconv(.c) void {
    var zLeft: ?[*:0]u8 = null;
    var zRight: ?[*:0]u8 = null;
    var zDb: ?[*:0]const u8 = null;
    var pId: Cptr = null;
    var aFcntl = [_]?[*:0]u8{ null, null, null, null };
    var iDb: c_int = undefined;
    var rc: c_int = undefined;
    const db = rdp(pParse, Parse_db);
    const v = sqlite3GetVdbe(pParse);

    if (v == null) return;
    sqlite3VdbeRunOnlyOnce(v);
    wr(c_int, pParse, Parse_nMem, 2);

    iDb = sqlite3TwoPartName(pParse, pId1, pId2, &pId);
    if (iDb < 0) return;
    var pDb = dbAt(db, iDb);

    if (iDb == 1 and sqlite3OpenTempDatabase(pParse) != 0) {
        return;
    }

    zLeft = sqlite3NameFromToken(db, pId);
    if (zLeft == null) return;
    if (minusFlag != 0) {
        zRight = sqlite3MPrintf(db, "-%T", pValue);
    } else {
        zRight = sqlite3NameFromToken(db, pValue);
    }

    zDb = if (tokenN(pId2) > 0) @ptrCast(rdp(pDb, Db_zDbSName)) else null;
    if (sqlite3AuthCheck(pParse, SQLITE_PRAGMA, zLeft, zRight, zDb) != 0) {
        sqlite3DbFree(db, zLeft);
        sqlite3DbFree(db, zRight);
        return;
    }

    aFcntl[0] = null;
    aFcntl[1] = zLeft;
    aFcntl[2] = zRight;
    aFcntl[3] = null;
    // busyHandler is an EMBEDDED BusyHandler struct (not a pointer); take its
    // address and write nBusy within it.
    wr(c_int, fieldPtr(db, sqlite3_busyHandler), BusyHandler_nBusy, 0);
    rc = sqlite3_file_control(db, zDb, SQLITE_FCNTL_PRAGMA, @ptrCast(&aFcntl));
    if (rc == SQLITE_OK) {
        sqlite3VdbeSetNumCols(v, 1);
        sqlite3VdbeSetColName(v, 0, COLNAME_NAME, @ptrCast(aFcntl[0]), SQLITE_TRANSIENT);
        returnSingleText(v, @ptrCast(aFcntl[0]));
        sqlite3_free(aFcntl[0]);
        sqlite3DbFree(db, zLeft);
        sqlite3DbFree(db, zRight);
        return;
    }
    if (rc != SQLITE_NOTFOUND) {
        if (aFcntl[0] != null) {
            sqlite3ErrorMsg(pParse, "%s", aFcntl[0]);
            sqlite3_free(aFcntl[0]);
        }
        wr(c_int, pParse, Parse_nErr, rd(c_int, pParse, Parse_nErr) + 1);
        wr(c_int, pParse, Parse_rc, rc);
        sqlite3DbFree(db, zLeft);
        sqlite3DbFree(db, zRight);
        return;
    }

    const pPragma = pragmaLocate(zLeft.?) orelse {
        sqlite3DbFree(db, zLeft);
        sqlite3DbFree(db, zRight);
        return;
    };

    if ((pPragma.mPragFlg & PragFlg_NeedSchema) != 0) {
        if (sqlite3ReadSchema(pParse) != 0) {
            sqlite3DbFree(db, zLeft);
            sqlite3DbFree(db, zRight);
            return;
        }
    }

    if ((pPragma.mPragFlg & PragFlg_NoColumns) == 0 and
        ((pPragma.mPragFlg & PragFlg_NoColumns1) == 0 or zRight == null))
    {
        setPragmaResultColumnNames(v, pPragma);
    }

    // Dispatch.  Returns true to "goto pragma_out" immediately.
    if (dispatch(pParse, db, v, pPragma, &iDb, &pDb, zLeft, zRight, zDb, pId2, pValue, &rc)) {
        sqlite3DbFree(db, zLeft);
        sqlite3DbFree(db, zRight);
        return;
    }

    if ((pPragma.mPragFlg & PragFlg_NoColumns1) != 0 and zRight != null) {
        sqlite3VdbeVerifyNoResultRow(v);
    }

    sqlite3DbFree(db, zLeft);
    sqlite3DbFree(db, zRight);
}

/// Returns true if caller should goto pragma_out (early return).
fn dispatch(
    pParse: Cptr,
    db: Cptr,
    v: Cptr,
    pPragma: *const PragmaName,
    iDbP: *c_int,
    pDbP: *?*anyopaque,
    zLeft: ?[*:0]u8,
    zRight: ?[*:0]u8,
    zDbArg: ?[*:0]const u8,
    pId2: Cptr,
    pValue: Cptr,
    rcP: *c_int,
) bool {
    var iDb = iDbP.*;
    var pDb = pDbP.*;
    var zDb = zDbArg;
    switch (pPragma.ePragTyp) {
        PragTyp_DEFAULT_CACHE_SIZE => {
            sqlite3VdbeUsesBtree(v, iDb);
            if (zRight == null) {
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 2);
                sqlite3VdbeVerifyNoMallocRequired(v, getCacheSize_n);
                const aOp = sqlite3VdbeAddOpList(v, getCacheSize_n, @ptrCast(&getCacheSize), 0);
                if (aOp == null) return false;
                opSetP1(opAt(aOp, 0), iDb);
                opSetP1(opAt(aOp, 1), iDb);
                opSetP1(opAt(aOp, 6), SQLITE_DEFAULT_CACHE_SIZE);
            } else {
                const size = sqlite3AbsInt32(sqlite3Atoi(zRight));
                sqlite3BeginWriteOperation(pParse, 0, iDb);
                _ = sqlite3VdbeAddOp3(v, OP_SetCookie, iDb, BTREE_DEFAULT_CACHE_SIZE, size);
                const pSchema = rdp(pDb, Db_pSchema);
                wr(c_int, pSchema, Schema_cache_size, size);
                sqlite3BtreeSetCacheSize(rdp(pDb, Db_pBt), size);
            }
        },
        PragTyp_PAGE_SIZE => {
            const pBt = rdp(pDb, Db_pBt);
            if (zRight == null) {
                const size = sqlite3BtreeGetPageSize(pBt);
                returnSingleInt(v, size);
            } else {
                const np = sqlite3Atoi(zRight);
                wr(c_int, db, sqlite3_nextPagesize, np);
                if (SQLITE_NOMEM == sqlite3BtreeSetPageSize(pBt, np, 0, 0)) {
                    sqlite3OomFault(db);
                }
            }
        },
        PragTyp_SECURE_DELETE => {
            const pBt = rdp(pDb, Db_pBt);
            var b: c_int = -1;
            if (zRight) |zr| {
                if (sqlite3_stricmp(zr, "fast") == 0) {
                    b = 2;
                } else {
                    b = sqlite3GetBoolean(zr, 0);
                }
            }
            if (tokenN(pId2) == 0 and b >= 0) {
                var ii: c_int = 0;
                const ndb = rd(c_int, db, sqlite3_nDb);
                while (ii < ndb) : (ii += 1) {
                    _ = sqlite3BtreeSecureDelete(rdp(dbAt(db, ii), Db_pBt), b);
                }
            }
            b = sqlite3BtreeSecureDelete(pBt, b);
            returnSingleInt(v, b);
        },
        PragTyp_PAGE_COUNT => {
            sqlite3CodeVerifySchema(pParse, iDb);
            wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
            const iReg = rd(c_int, pParse, Parse_nMem);
            if (sqlite3Tolower(zLeft.?[0]) == 'p') {
                _ = sqlite3VdbeAddOp2(v, OP_Pagecount, iDb, iReg);
            } else {
                var x: i64 = 0;
                if (zRight != null and sqlite3DecOrHexToI64(zRight, &x) == 0) {
                    if (x < 0) x = 0 else if (x > 0xfffffffe) x = 0xfffffffe;
                } else {
                    x = 0;
                }
                _ = sqlite3VdbeAddOp3(v, OP_MaxPgcnt, iDb, iReg, @intCast(x));
            }
            _ = sqlite3VdbeAddOp2(v, OP_ResultRow, iReg, 1);
        },
        PragTyp_LOCKING_MODE => {
            var zRet: [*:0]const u8 = "normal";
            var eMode = getLockingMode(zRight);
            if (tokenN(pId2) == 0 and eMode == PAGER_LOCKINGMODE_QUERY) {
                eMode = rd(u8, db, sqlite3_dfltLockMode);
            } else {
                if (tokenN(pId2) == 0) {
                    var ii: c_int = 2;
                    const ndb = rd(c_int, db, sqlite3_nDb);
                    while (ii < ndb) : (ii += 1) {
                        const pPager = sqlite3BtreePager(rdp(dbAt(db, ii), Db_pBt));
                        _ = sqlite3PagerLockingMode(pPager, eMode);
                    }
                    wr(u8, db, sqlite3_dfltLockMode, @intCast(eMode));
                }
                const pPager = sqlite3BtreePager(rdp(pDb, Db_pBt));
                eMode = sqlite3PagerLockingMode(pPager, eMode);
            }
            if (eMode == PAGER_LOCKINGMODE_EXCLUSIVE) {
                zRet = "exclusive";
            }
            returnSingleText(v, zRet);
        },
        PragTyp_JOURNAL_MODE => {
            var eMode: c_int = undefined;
            if (zRight == null) {
                eMode = PAGER_JOURNALMODE_QUERY;
            } else {
                const n = sqlite3Strlen30(zRight);
                var zMode: ?[*:0]const u8 = undefined;
                eMode = 0;
                while (true) {
                    zMode = sqlite3JournalModename(eMode);
                    if (zMode == null) break;
                    if (sqlite3_strnicmp(zRight, zMode, n) == 0) break;
                    eMode += 1;
                }
                if (zMode == null) {
                    eMode = PAGER_JOURNALMODE_QUERY;
                }
                if (eMode == PAGER_JOURNALMODE_OFF and (rd(u64, db, sqlite3_flags) & SQLITE_Defensive) != 0) {
                    eMode = PAGER_JOURNALMODE_QUERY;
                }
            }
            if (eMode == PAGER_JOURNALMODE_QUERY and tokenN(pId2) == 0) {
                iDb = 0;
                wr(u32, pId2, Token_n, 1);
            }
            var ii: c_int = rd(c_int, db, sqlite3_nDb) - 1;
            while (ii >= 0) : (ii -= 1) {
                if (rdp(dbAt(db, ii), Db_pBt) != null and (ii == iDb or tokenN(pId2) == 0)) {
                    sqlite3VdbeUsesBtree(v, ii);
                    _ = sqlite3VdbeAddOp3(v, OP_JournalMode, ii, 1, eMode);
                }
            }
            _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
        },
        PragTyp_JOURNAL_SIZE_LIMIT => {
            const pPager = sqlite3BtreePager(rdp(pDb, Db_pBt));
            var iLimit: i64 = -2;
            if (zRight != null) {
                _ = sqlite3DecOrHexToI64(zRight, &iLimit);
                if (iLimit < -1) iLimit = -1;
            }
            iLimit = sqlite3PagerJournalSizeLimit(pPager, iLimit);
            returnSingleInt(v, iLimit);
        },
        PragTyp_AUTO_VACUUM => {
            const pBt = rdp(pDb, Db_pBt);
            if (zRight == null) {
                returnSingleInt(v, sqlite3BtreeGetAutoVacuum(pBt));
            } else {
                const eAuto = getAutoVacuum(zRight.?);
                wr(u8, db, sqlite3_nextAutovac, @intCast(eAuto));
                rcP.* = sqlite3BtreeSetAutoVacuum(pBt, eAuto);
                if (rcP.* == SQLITE_OK and (eAuto == 1 or eAuto == 2)) {
                    const iAddr = sqlite3VdbeCurrentAddr(v);
                    sqlite3VdbeVerifyNoMallocRequired(v, setMeta6_n);
                    const aOp = sqlite3VdbeAddOpList(v, setMeta6_n, @ptrCast(&setMeta6), 0);
                    if (aOp == null) return false;
                    opSetP1(opAt(aOp, 0), iDb);
                    opSetP1(opAt(aOp, 1), iDb);
                    opSetP2(opAt(aOp, 2), iAddr + 4);
                    opSetP1(opAt(aOp, 4), iDb);
                    opSetP3(opAt(aOp, 4), eAuto - 1);
                    sqlite3VdbeUsesBtree(v, iDb);
                }
            }
        },
        PragTyp_INCREMENTAL_VACUUM => {
            var iLimit: c_int = 0;
            if (zRight == null or sqlite3GetInt32(zRight, &iLimit) == 0 or iLimit <= 0) {
                iLimit = 0x7fffffff;
            }
            sqlite3BeginWriteOperation(pParse, 0, iDb);
            _ = sqlite3VdbeAddOp2(v, OP_Integer, iLimit, 1);
            const addr = sqlite3VdbeAddOp1(v, OP_IncrVacuum, iDb);
            _ = sqlite3VdbeAddOp1(v, OP_ResultRow, 1);
            _ = sqlite3VdbeAddOp2(v, OP_AddImm, 1, -1);
            _ = sqlite3VdbeAddOp2(v, OP_IfPos, 1, addr);
            sqlite3VdbeJumpHere(v, addr);
        },
        PragTyp_CACHE_SIZE => {
            if (zRight == null) {
                returnSingleInt(v, rd(c_int, rdp(pDb, Db_pSchema), Schema_cache_size));
            } else {
                const size = sqlite3Atoi(zRight);
                wr(c_int, rdp(pDb, Db_pSchema), Schema_cache_size, size);
                sqlite3BtreeSetCacheSize(rdp(pDb, Db_pBt), size);
            }
        },
        PragTyp_CACHE_SPILL => {
            if (zRight == null) {
                const flags = rd(u64, db, sqlite3_flags);
                const val: i64 = if ((flags & SQLITE_CacheSpill) == 0) 0 else sqlite3BtreeSetSpillSize(rdp(pDb, Db_pBt), 0);
                returnSingleInt(v, val);
            } else {
                var size: c_int = 1;
                if (sqlite3GetInt32(zRight, &size) != 0) {
                    _ = sqlite3BtreeSetSpillSize(rdp(pDb, Db_pBt), size);
                }
                var flags = rd(u64, db, sqlite3_flags);
                if (sqlite3GetBoolean(zRight, @intFromBool(size != 0)) != 0) {
                    flags |= SQLITE_CacheSpill;
                } else {
                    flags &= ~SQLITE_CacheSpill;
                }
                wr(u64, db, sqlite3_flags, flags);
                setAllPagerFlags(db);
            }
        },
        PragTyp_MMAP_SIZE => {
            var sz: i64 = undefined;
            if (zRight != null) {
                _ = sqlite3DecOrHexToI64(zRight, &sz);
                if (sz < 0) sz = rd(i64, &sqlite3Config, sqlite3GlobalConfig_szMmap);
                if (tokenN(pId2) == 0) wr(i64, db, sqlite3_szMmap, sz);
                var ii: c_int = rd(c_int, db, sqlite3_nDb) - 1;
                while (ii >= 0) : (ii -= 1) {
                    if (rdp(dbAt(db, ii), Db_pBt) != null and (ii == iDb or tokenN(pId2) == 0)) {
                        _ = sqlite3BtreeSetMmapLimit(rdp(dbAt(db, ii), Db_pBt), sz);
                    }
                }
            }
            sz = -1;
            rcP.* = sqlite3_file_control(db, zDb, SQLITE_FCNTL_MMAP_SIZE, &sz);
            if (rcP.* == SQLITE_OK) {
                returnSingleInt(v, sz);
            } else if (rcP.* != SQLITE_NOTFOUND) {
                wr(c_int, pParse, Parse_nErr, rd(c_int, pParse, Parse_nErr) + 1);
                wr(c_int, pParse, Parse_rc, rcP.*);
            }
        },
        PragTyp_TEMP_STORE => {
            if (zRight == null) {
                returnSingleInt(v, rd(u8, db, sqlite3_temp_store));
            } else {
                _ = changeTempStorage(pParse, zRight.?);
            }
        },
        PragTyp_TEMP_STORE_DIRECTORY => {
            sqlite3_mutex_enter(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_TEMPDIR));
            if (zRight == null) {
                returnSingleText(v, sqlite3_temp_directory);
            } else {
                if (zRight.?[0] != 0) {
                    var res: c_int = 0;
                    rcP.* = sqlite3OsAccess(rdp(db, sqlite3_pVfs), zRight, SQLITE_ACCESS_READWRITE, &res);
                    if (rcP.* != SQLITE_OK or res == 0) {
                        sqlite3ErrorMsg(pParse, "not a writable directory");
                        sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_TEMPDIR));
                        return true;
                    }
                }
                const tstore = rd(u8, db, sqlite3_temp_store);
                if (SQLITE_TEMP_STORE == 0 or
                    (SQLITE_TEMP_STORE == 1 and tstore <= 1) or
                    (SQLITE_TEMP_STORE == 2 and tstore == 1))
                {
                    _ = invalidateTempStorage(pParse);
                }
                sqlite3_free(sqlite3_temp_directory);
                if (zRight.?[0] != 0) {
                    sqlite3_temp_directory = sqlite3_mprintf("%s", zRight);
                } else {
                    sqlite3_temp_directory = null;
                }
            }
            sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_TEMPDIR));
        },
        PragTyp_SYNCHRONOUS => {
            if (zRight == null) {
                returnSingleInt(v, @as(i64, rd(u8, pDb, Db_safety_level)) - 1);
            } else {
                if (rd(u8, db, sqlite3_autoCommit) == 0) {
                    sqlite3ErrorMsg(pParse, "Safety level may not be changed inside a transaction");
                } else if (iDb != 1) {
                    var iLevel = (@as(c_int, getSafetyLevel(zRight.?, 0, 1)) + 1) & PAGER_SYNCHRONOUS_MASK;
                    if (iLevel == 0) iLevel = 1;
                    wr(u8, pDb, Db_safety_level, @intCast(iLevel));
                    base(pDb)[Db_bSyncSet] = 1;
                    setAllPagerFlags(db);
                }
            }
        },
        PragTyp_FLAG => {
            if (zRight == null) {
                setPragmaResultColumnNames(v, pPragma);
                returnSingleInt(v, @intFromBool((rd(u64, db, sqlite3_flags) & pPragma.iArg) != 0));
            } else {
                var mask: u64 = pPragma.iArg;
                if (rd(u8, db, sqlite3_autoCommit) == 0) {
                    mask &= ~SQLITE_ForeignKeys;
                }
                var flags = rd(u64, db, sqlite3_flags);
                if (sqlite3GetBoolean(zRight, 0) != 0) {
                    if ((mask & SQLITE_WriteSchema) == 0 or (flags & SQLITE_Defensive) == 0) {
                        flags |= mask;
                        wr(u64, db, sqlite3_flags, flags);
                    }
                } else {
                    flags &= ~mask;
                    wr(u64, db, sqlite3_flags, flags);
                    if (mask == SQLITE_DeferFKs) {
                        wr(i64, db, sqlite3_nDeferredImmCons, 0);
                        wr(i64, db, sqlite3_nDeferredCons, 0);
                    }
                    if ((mask & SQLITE_WriteSchema) != 0 and sqlite3_stricmp(zRight, "reset") == 0) {
                        sqlite3ResetAllSchemasOfConnection(db);
                    }
                }
                _ = sqlite3VdbeAddOp0(v, OP_Expire);
                setAllPagerFlags(db);
            }
        },
        else => return dispatch2(pParse, db, v, pPragma, &iDb, &pDb, zLeft, zRight, &zDb, pId2, pValue, rcP),
    }
    iDbP.* = iDb;
    pDbP.* = pDb;
    return false;
}

const sqlite3GlobalConfig_szMmap: usize = off("Sqlite3Config_szMmap", 296); // config-invariant

fn dispatch2(
    pParse: Cptr,
    db: Cptr,
    v: Cptr,
    pPragma: *const PragmaName,
    iDbP: *c_int,
    pDbP: *?*anyopaque,
    zLeft: ?[*:0]u8,
    zRight: ?[*:0]u8,
    zDbP: *?[*:0]const u8,
    pId2: Cptr,
    pValue: Cptr,
    rcP: *c_int,
) bool {
    _ = rcP;
    var iDb = iDbP.*;
    var zDb = zDbP.*;
    switch (pPragma.ePragTyp) {
        PragTyp_TABLE_INFO => {
            if (zRight != null) {
                sqlite3CodeVerifyNamedSchema(pParse, zDb);
                const pTab = sqlite3LocateTable(pParse, @intCast(LOCATE_NOERR), zRight, zDb);
                if (pTab != null) {
                    var nHidden: c_int = 0;
                    const pPk = sqlite3PrimaryKeyIndex(pTab);
                    wr(c_int, pParse, Parse_nMem, 7);
                    _ = sqlite3ViewGetColumnNames(pParse, pTab);
                    const nCol: c_int = rd(i16, pTab, Table_nCol);
                    var i: c_int = 0;
                    while (i < nCol) : (i += 1) {
                        const pCol = colAt(pTab, @intCast(i));
                        var isHidden: c_int = 0;
                        const cf = rd(u16, pCol, Column_colFlags);
                        if (cf & COLFLAG_NOINSERT != 0) {
                            if (pPragma.iArg == 0) {
                                nHidden += 1;
                                continue;
                            }
                            if (cf & COLFLAG_VIRTUAL != 0) {
                                isHidden = 2;
                            } else if (cf & COLFLAG_STORED != 0) {
                                isHidden = 3;
                            } else {
                                isHidden = 1;
                            }
                        }
                        var k: c_int = 0;
                        if ((cf & COLFLAG_PRIMKEY) == 0) {
                            k = 0;
                        } else if (pPk == null) {
                            k = 1;
                        } else {
                            const aiColumn = rdp(pPk, Index_aiColumn);
                            k = 1;
                            while (k <= nCol and rd(i16, aiColumn, @as(usize, @intCast(k - 1)) * 2) != i) : (k += 1) {}
                        }
                        const pColExpr = sqlite3ColumnExpr(pTab, pCol);
                        const zDflt: ?*anyopaque = if (isHidden >= 2 or pColExpr == null) null else rdp(pColExpr, 8); // Expr.u.zToken at off 8
                        sqlite3VdbeMultiLoad(v, 1, if (pPragma.iArg != 0) "issisii" else "issisi", i - nHidden, rdp(pCol, Column_zCnName), sqlite3ColumnType(pCol, ""), @as(c_int, if (colNotNull(pCol) != 0) 1 else 0), zDflt, k, isHidden);
                    }
                }
            }
        },
        PragTyp_TABLE_LIST => {
            wr(c_int, pParse, Parse_nMem, 6);
            sqlite3CodeVerifyNamedSchema(pParse, zDb);
            var ii: c_int = 0;
            const ndb = rd(c_int, db, sqlite3_nDb);
            while (ii < ndb) : (ii += 1) {
                if (zDb != null and sqlite3_stricmp(zDb, @ptrCast(rdp(dbAt(db, ii), Db_zDbSName))) != 0) continue;
                var pHash = fieldPtr(rdp(dbAt(db, ii), Db_pSchema), Schema_tblHash);
                // Ensure Table.nCol initialized for views/vtabs (restart on disrupt).
                var initNCol = hashCount(pHash);
                while (initNCol != 0) : (initNCol -= 1) {
                    var kk = hashFirst(pHash);
                    while (true) {
                        if (kk == null) {
                            initNCol = 1; // becomes 0 after decrement
                            break;
                        }
                        const pTab = hashData(kk);
                        if (rd(i16, pTab, Table_nCol) == 0) {
                            const zSql = sqlite3MPrintf(db, "SELECT*FROM\"%w\"", rdp(pTab, Table_zName));
                            if (zSql != null) {
                                var pDummy: Cptr = null;
                                _ = sqlite3_prepare_v3(db, @ptrCast(zSql), -1, SQLITE_PREPARE_DONT_LOG, &pDummy, null);
                                _ = sqlite3_finalize(pDummy);
                                sqlite3DbFree(db, zSql);
                            }
                            if (rd(u8, db, sqlite3_mallocFailed) != 0) {
                                const pP = rdp(db, sqlite3_pParse);
                                sqlite3ErrorMsg(pP, "out of memory");
                                wr(c_int, pP, Parse_rc, SQLITE_NOMEM);
                            }
                            pHash = fieldPtr(rdp(dbAt(db, ii), Db_pSchema), Schema_tblHash);
                            break;
                        }
                        kk = hashNext(kk);
                    }
                }
                var k = hashFirst(pHash);
                while (k != null) : (k = hashNext(k)) {
                    const pTab = hashData(k);
                    if (zRight != null and sqlite3_stricmp(zRight, @ptrCast(rdp(pTab, Table_zName))) != 0) continue;
                    const zType: [*:0]const u8 = if (isView(pTab))
                        "view"
                    else if (isVirtual(pTab))
                        "virtual"
                    else if (tabFlags(pTab) & TF_Shadow != 0)
                        "shadow"
                    else
                        "table";
                    sqlite3VdbeMultiLoad(v, 1, "sssiii", rdp(dbAt(db, ii), Db_zDbSName), sqlite3PreferredTableName(@ptrCast(rdp(pTab, Table_zName))), zType, @as(c_int, rd(i16, pTab, Table_nCol)), @as(c_int, @intFromBool((tabFlags(pTab) & TF_WithoutRowid) != 0)), @as(c_int, @intFromBool((tabFlags(pTab) & TF_Strict) != 0)));
                }
            }
        },
        PragTyp_STATS => {
            // SQLITE_DEBUG-only; only reachable in testfixture config.
            wr(c_int, pParse, Parse_nMem, 5);
            sqlite3CodeVerifySchema(pParse, iDb);
            var it = hashFirst(fieldPtr(rdp(pDbP.*, Db_pSchema), Schema_tblHash));
            while (it != null) : (it = hashNext(it)) {
                const pTab = hashData(it);
                sqlite3VdbeMultiLoad(v, 1, "ssiii", sqlite3PreferredTableName(@ptrCast(rdp(pTab, Table_zName))), @as(c_int, 0), @as(c_int, rd(i16, pTab, Table_szTabRow)), @as(c_int, rd(i16, pTab, Table_nRowLogEst)), tabFlags(pTab));
                var pIdx = rdp(pTab, Table_pIndex);
                while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
                    sqlite3VdbeMultiLoad(v, 2, "siiiX", rdp(pIdx, Index_zName), @as(c_int, rd(i16, pIdx, Index_szIdxRow)), @as(c_int, rd(i16, rdp(pIdx, Index_aiRowLogEst), 0)), @as(c_int, @intFromBool(idxHasStat1(pIdx))));
                    _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 5);
                }
            }
        },
        PragTyp_INDEX_INFO => {
            if (zRight != null) {
                var pIdx = sqlite3FindIndex(db, zRight, zDb);
                if (pIdx == null) {
                    const pTab0 = sqlite3LocateTable(pParse, @intCast(LOCATE_NOERR), zRight, zDb);
                    if (pTab0 != null and !hasRowid(pTab0)) {
                        pIdx = sqlite3PrimaryKeyIndex(pTab0);
                    }
                }
                if (pIdx != null) {
                    const iIdxDb = sqlite3SchemaToIndex(db, rdp(pIdx, Index_pSchema));
                    var mx: c_int = undefined;
                    if (pPragma.iArg != 0) {
                        mx = rd(u16, pIdx, Index_nColumn);
                        wr(c_int, pParse, Parse_nMem, 6);
                    } else {
                        mx = rd(u16, pIdx, Index_nKeyCol);
                        wr(c_int, pParse, Parse_nMem, 3);
                    }
                    const pTab = rdp(pIdx, Index_pTable);
                    sqlite3CodeVerifySchema(pParse, iIdxDb);
                    var i: c_int = 0;
                    const aiColumn = rdp(pIdx, Index_aiColumn);
                    while (i < mx) : (i += 1) {
                        const cnum = rd(i16, aiColumn, @as(usize, @intCast(i)) * 2);
                        const zcn: ?*anyopaque = if (cnum < 0) null else rdp(colAt(pTab, @intCast(cnum)), Column_zCnName);
                        sqlite3VdbeMultiLoad(v, 1, "iisX", i, @as(c_int, cnum), zcn);
                        if (pPragma.iArg != 0) {
                            const aSort = rdp(pIdx, Index_aSortOrder);
                            const azColl = rdp(pIdx, Index_azColl);
                            sqlite3VdbeMultiLoad(v, 4, "isiX", @as(c_int, rd(u8, aSort, @intCast(i))), rd(?*anyopaque, azColl, @as(usize, @intCast(i)) * 8), @as(c_int, @intFromBool(i < @as(c_int, rd(u16, pIdx, Index_nKeyCol)))));
                        }
                        _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 1, rd(c_int, pParse, Parse_nMem));
                    }
                }
            }
        },
        PragTyp_INDEX_LIST => {
            if (zRight != null) {
                const pTab = sqlite3FindTable(db, zRight, zDb);
                if (pTab != null) {
                    const iTabDb = sqlite3SchemaToIndex(db, rdp(pTab, Table_pSchema));
                    wr(c_int, pParse, Parse_nMem, 5);
                    sqlite3CodeVerifySchema(pParse, iTabDb);
                    const azOrigin = [_][*:0]const u8{ "c", "u", "pk" };
                    var pIdx = rdp(pTab, Table_pIndex);
                    var i: c_int = 0;
                    while (pIdx != null) : ({
                        pIdx = rdp(pIdx, Index_pNext);
                        i += 1;
                    }) {
                        sqlite3VdbeMultiLoad(v, 1, "isisi", i, rdp(pIdx, Index_zName), @as(c_int, @intFromBool(isUniqueIndex(pIdx))), azOrigin[idxType(pIdx)], @as(c_int, @intFromBool(rdp(pIdx, Index_pPartIdxWhere) != null)));
                    }
                }
            }
        },
        PragTyp_DATABASE_LIST => {
            wr(c_int, pParse, Parse_nMem, 3);
            var i: c_int = 0;
            const ndb = rd(c_int, db, sqlite3_nDb);
            while (i < ndb) : (i += 1) {
                const pBt = rdp(dbAt(db, i), Db_pBt);
                if (pBt == null) continue;
                sqlite3VdbeMultiLoad(v, 1, "iss", i, rdp(dbAt(db, i), Db_zDbSName), sqlite3BtreeGetFilename(pBt));
            }
        },
        PragTyp_COLLATION_LIST => {
            wr(c_int, pParse, Parse_nMem, 2);
            var i: c_int = 0;
            var p = hashFirst(fieldPtr(db, sqlite3_aCollSeq));
            while (p != null) : (p = hashNext(p)) {
                const pColl = hashData(p);
                sqlite3VdbeMultiLoad(v, 1, "is", i, rdp(pColl, CollSeq_zName));
                i += 1;
            }
        },
        PragTyp_FUNCTION_LIST => {
            const showInternFunc = @intFromBool((rd(u32, db, sqlite3_mDbFlags) & DBFLAG_InternalFunc) != 0);
            wr(c_int, pParse, Parse_nMem, 6);
            // sqlite3BuiltinFunctions.a[i] — FuncDefHash.a is the first member.
            var i: usize = 0;
            while (i < SQLITE_FUNC_HASH_SZ) : (i += 1) {
                var p = rd(?*anyopaque, &sqlite3BuiltinFunctions, i * 8);
                while (p != null) : (p = rd(?*anyopaque, p, FuncDef_u)) {
                    pragmaFunclistLine(v, p, 1, showInternFunc);
                }
            }
            var j = hashFirst(fieldPtr(db, sqlite3_aFunc));
            while (j != null) : (j = hashNext(j)) {
                pragmaFunclistLine(v, hashData(j), 0, showInternFunc);
            }
        },
        PragTyp_MODULE_LIST => {
            wr(c_int, pParse, Parse_nMem, 1);
            var j = hashFirst(fieldPtr(db, sqlite3_aModule));
            while (j != null) : (j = hashNext(j)) {
                const pMod = hashData(j);
                sqlite3VdbeMultiLoad(v, 1, "s", rdp(pMod, Module_zName));
            }
        },
        PragTyp_PRAGMA_LIST => {
            var i: usize = 0;
            while (i < aPragmaName.len) : (i += 1) {
                sqlite3VdbeMultiLoad(v, 1, "s", aPragmaName[i].zName);
            }
        },
        PragTyp_FOREIGN_KEY_LIST => {
            if (zRight != null) {
                const pTab = sqlite3FindTable(db, zRight, zDb);
                if (pTab != null and isOrdinaryTable(pTab)) {
                    var pFK = rdp(pTab, Table_u_tab_pFKey); // u.tab.pFKey (embedded union)
                    if (pFK != null) {
                        const iTabDb = sqlite3SchemaToIndex(db, rdp(pTab, Table_pSchema));
                        var i: c_int = 0;
                        wr(c_int, pParse, Parse_nMem, 8);
                        sqlite3CodeVerifySchema(pParse, iTabDb);
                        while (pFK != null) {
                            const nFkCol: c_int = rd(c_int, pFK, FKey_nCol);
                            var jj: c_int = 0;
                            while (jj < nFkCol) : (jj += 1) {
                                const aCol = fieldPtr(pFK, FKey_aCol);
                                const colItem = base(aCol) + @as(usize, @intCast(jj)) * sizeof_sColMap;
                                const iFrom = rd(c_int, @ptrCast(colItem), sColMap_iFrom);
                                const zCol = rd(?*anyopaque, @ptrCast(colItem), sColMap_zCol);
                                const aAction = fieldPtr(pFK, FKey_aAction);
                                sqlite3VdbeMultiLoad(v, 1, "iissssss", i, jj, rdp(pFK, FKey_zTo), rdp(colAt(pTab, @intCast(iFrom)), Column_zCnName), zCol, actionName(base(aAction)[1]), actionName(base(aAction)[0]), @as([*:0]const u8, "NONE"));
                            }
                            i += 1;
                            pFK = rdp(pFK, FKey_pNextFrom);
                        }
                    }
                }
            }
        },
        PragTyp_FOREIGN_KEY_CHECK => {
            foreignKeyCheck(pParse, db, v, &iDb, &zDb, zRight);
        },
        PragTyp_CASE_SENSITIVE_LIKE => {
            if (zRight != null) {
                sqlite3RegisterLikeFunctions(db, sqlite3GetBoolean(zRight, 0));
            }
        },
        PragTyp_INTEGRITY_CHECK => {
            integrityCheck(pParse, db, v, pPragma, iDb, zLeft, zRight, zDb, pId2, pValue);
        },
        PragTyp_ENCODING => {
            if (encodingPragma(pParse, db, v, zRight)) return true;
        },
        PragTyp_HEADER_VALUE => {
            const iCookie: c_int = @intCast(pPragma.iArg);
            sqlite3VdbeUsesBtree(v, iDb);
            if (zRight != null and (pPragma.mPragFlg & PragFlg_ReadOnly) == 0) {
                sqlite3VdbeVerifyNoMallocRequired(v, setCookie_n);
                const aOp = sqlite3VdbeAddOpList(v, setCookie_n, @ptrCast(&setCookie), 0);
                if (aOp == null) return false;
                opSetP1(opAt(aOp, 0), iDb);
                opSetP1(opAt(aOp, 1), iDb);
                opSetP2(opAt(aOp, 1), iCookie);
                opSetP3(opAt(aOp, 1), sqlite3Atoi(zRight));
                opSetP5(opAt(aOp, 1), 1);
                if (iCookie == BTREE_SCHEMA_VERSION and (rd(u64, db, sqlite3_flags) & SQLITE_Defensive) != 0) {
                    opSetOpcode(opAt(aOp, 1), @intCast(OP_Noop));
                }
            } else {
                sqlite3VdbeVerifyNoMallocRequired(v, readCookie_n);
                const aOp = sqlite3VdbeAddOpList(v, readCookie_n, @ptrCast(&readCookie), 0);
                if (aOp == null) return false;
                opSetP1(opAt(aOp, 0), iDb);
                opSetP1(opAt(aOp, 1), iDb);
                opSetP3(opAt(aOp, 1), iCookie);
                sqlite3VdbeReusable(v);
            }
        },
        PragTyp_COMPILE_OPTIONS => {
            wr(c_int, pParse, Parse_nMem, 1);
            var i: c_int = 0;
            while (true) {
                const zOpt = sqlite3_compileoption_get(i);
                i += 1;
                if (zOpt == null) break;
                _ = sqlite3VdbeLoadString(v, 1, zOpt);
                _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
            }
            sqlite3VdbeReusable(v);
        },
        PragTyp_WAL_CHECKPOINT => {
            const iBt: c_int = if (tokenZ(pId2) != null) iDb else SQLITE_MAX_DB;
            var eMode: c_int = SQLITE_CHECKPOINT_PASSIVE;
            if (zRight) |zr| {
                if (sqlite3_stricmp(zr, "full") == 0) {
                    eMode = SQLITE_CHECKPOINT_FULL;
                } else if (sqlite3_stricmp(zr, "restart") == 0) {
                    eMode = SQLITE_CHECKPOINT_RESTART;
                } else if (sqlite3_stricmp(zr, "truncate") == 0) {
                    eMode = SQLITE_CHECKPOINT_TRUNCATE;
                } else if (sqlite3_stricmp(zr, "noop") == 0) {
                    eMode = SQLITE_CHECKPOINT_NOOP;
                }
            }
            wr(c_int, pParse, Parse_nMem, 3);
            _ = sqlite3VdbeAddOp3(v, OP_Checkpoint, iBt, eMode, 1);
            _ = sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 3);
        },
        PragTyp_WAL_AUTOCHECKPOINT => {
            if (zRight != null) {
                _ = sqlite3_wal_autocheckpoint(db, sqlite3Atoi(zRight));
            }
            const isDefault = @intFromPtr(rdp(db, sqlite3_xWalCallback)) == @intFromPtr(&sqlite3WalDefaultHook);
            const val: i64 = if (isDefault) @as(c_int, @truncate(@as(isize, @bitCast(@intFromPtr(rdp(db, sqlite3_pWalArg)))))) else 0;
            returnSingleInt(v, val);
        },
        PragTyp_SHRINK_MEMORY => {
            _ = sqlite3_db_release_memory(db);
        },
        PragTyp_OPTIMIZE => {
            optimizePragma(pParse, db, v, iDb, zDb, zRight);
        },
        PragTyp_SOFT_HEAP_LIMIT => {
            var n: i64 = undefined;
            if (zRight != null and sqlite3DecOrHexToI64(zRight, &n) == SQLITE_OK) {
                _ = sqlite3_soft_heap_limit64(n);
            }
            returnSingleInt(v, sqlite3_soft_heap_limit64(-1));
        },
        PragTyp_HARD_HEAP_LIMIT => {
            var n: i64 = undefined;
            if (zRight != null and sqlite3DecOrHexToI64(zRight, &n) == SQLITE_OK) {
                const iPrior = sqlite3_hard_heap_limit64(-1);
                if (n > 0 and (iPrior == 0 or iPrior > n)) _ = sqlite3_hard_heap_limit64(n);
            }
            returnSingleInt(v, sqlite3_hard_heap_limit64(-1));
        },
        PragTyp_THREADS => {
            var n: i64 = undefined;
            if (zRight != null and sqlite3DecOrHexToI64(zRight, &n) == SQLITE_OK and n >= 0) {
                _ = sqlite3_limit(db, SQLITE_LIMIT_WORKER_THREADS, @intCast(n & 0x7fffffff));
            }
            returnSingleInt(v, sqlite3_limit(db, SQLITE_LIMIT_WORKER_THREADS, -1));
        },
        PragTyp_ANALYSIS_LIMIT => {
            var n: i64 = undefined;
            if (zRight != null and sqlite3DecOrHexToI64(zRight, &n) == SQLITE_OK and n >= 0) {
                wr(c_int, db, sqlite3_nAnalysisLimit, @intCast(n & 0x7fffffff));
            }
            returnSingleInt(v, rd(c_int, db, sqlite3_nAnalysisLimit));
        },
        PragTyp_LOCK_STATUS => {
            // SQLITE_DEBUG/SQLITE_TEST only.
            const azLockName = [_][*:0]const u8{ "unlocked", "shared", "reserved", "pending", "exclusive" };
            wr(c_int, pParse, Parse_nMem, 2);
            var i: c_int = 0;
            const ndb = rd(c_int, db, sqlite3_nDb);
            while (i < ndb) : (i += 1) {
                var zState: [*:0]const u8 = "unknown";
                if (rdp(dbAt(db, i), Db_zDbSName) == null) continue;
                const pBt = rdp(dbAt(db, i), Db_pBt);
                if (pBt == null or sqlite3BtreePager(pBt) == null) {
                    zState = "closed";
                } else {
                    var j: c_int = 0;
                    const zn: ?[*:0]const u8 = if (i != 0) @ptrCast(rdp(dbAt(db, i), Db_zDbSName)) else null;
                    if (sqlite3_file_control(db, zn, SQLITE_FCNTL_LOCKSTATE, &j) == SQLITE_OK) {
                        zState = azLockName[@intCast(j)];
                    }
                }
                sqlite3VdbeMultiLoad(v, 1, "ss", rdp(dbAt(db, i), Db_zDbSName), zState);
            }
        },
        else => {
            // PragTyp_BUSY_TIMEOUT (the C `default:` case)
            if (zRight != null) {
                _ = sqlite3_busy_timeout(db, sqlite3Atoi(zRight));
            }
            returnSingleInt(v, rd(c_int, db, sqlite3_busyTimeout));
        },
    }
    iDbP.* = iDb;
    zDbP.* = zDb;
    return false;
}

inline fn hashCount(pHash: ?*anyopaque) c_int {
    // Hash.count is the u32 just before .first (at off 8) — actually count@? Use
    // sqliteHashCount macro = (H)->count. Hash {u32 htsize; u32 count; HashElem*first; ...}
    return @intCast(rd(u32, pHash, Hash_count));
}
const Hash_count: usize = off("Hash_count", 4);

fn foreignKeyCheck(pParse: Cptr, db: Cptr, v: Cptr, iDbP: *c_int, zDbP: *?[*:0]const u8, zRight: ?[*:0]u8) void {
    var iDb = iDbP.*;
    var zDb = zDbP.*;
    const regResult = rd(c_int, pParse, Parse_nMem) + 1;
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 4);
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
    const regRow = rd(c_int, pParse, Parse_nMem);
    var k = hashFirst(fieldPtr(rdp(dbAt(db, iDb), Db_pSchema), Schema_tblHash));
    while (k != null) {
        var pTab: Cptr = undefined;
        if (zRight != null) {
            pTab = sqlite3LocateTable(pParse, 0, zRight, zDb);
            k = null;
        } else {
            pTab = hashData(k);
            k = hashNext(k);
        }
        if (pTab == null or !isOrdinaryTable(pTab) or rdp(pTab, Table_u_tab_pFKey) == null) continue;
        iDb = sqlite3SchemaToIndex(db, rdp(pTab, Table_pSchema));
        zDb = @ptrCast(rdp(dbAt(db, iDb), Db_zDbSName));
        sqlite3CodeVerifySchema(pParse, iDb);
        sqlite3TableLock(pParse, iDb, rd(u32, pTab, Table_tnum), 0, @ptrCast(rdp(pTab, Table_zName)));
        sqlite3TouchRegister(pParse, @as(c_int, rd(i16, pTab, Table_nCol)) + regRow);
        sqlite3OpenTable(pParse, 0, iDb, pTab, OP_OpenRead);
        _ = sqlite3VdbeLoadString(v, regResult, @ptrCast(rdp(pTab, Table_zName)));
        // First loop: open parent indexes/tables.
        var i: c_int = 1;
        var pFK = rdp(pTab, Table_u_tab_pFKey);
        var broke = false;
        while (pFK != null) : ({
            pFK = rdp(pFK, FKey_pNextFrom);
            i += 1;
        }) {
            const pParent = sqlite3FindTable(db, @ptrCast(rdp(pFK, FKey_zTo)), zDb);
            if (pParent == null) continue;
            var pIdx: Cptr = null;
            sqlite3TableLock(pParse, iDb, rd(u32, pParent, Table_tnum), 0, @ptrCast(rdp(pParent, Table_zName)));
            const x = sqlite3FkLocateIndex(pParse, pParent, pFK, &pIdx, null);
            if (x == 0) {
                if (pIdx == null) {
                    sqlite3OpenTable(pParse, i, iDb, pParent, OP_OpenRead);
                } else {
                    _ = sqlite3VdbeAddOp3(v, OP_OpenRead, i, @intCast(rd(u32, pIdx, Index_tnum)), iDb);
                    sqlite3VdbeSetP4KeyInfo(pParse, pIdx);
                }
            } else {
                k = null;
                broke = true;
                break;
            }
        }
        if (broke and pFK != null) break;
        if (pFK != null) break;
        if (rd(c_int, pParse, Parse_nTab) < i) wr(c_int, pParse, Parse_nTab, i);
        const addrTop = sqlite3VdbeAddOp1(v, OP_Rewind, 0);
        // Second loop: check each FK.
        i = 1;
        pFK = rdp(pTab, Table_u_tab_pFKey);
        while (pFK != null) : ({
            pFK = rdp(pFK, FKey_pNextFrom);
            i += 1;
        }) {
            const pParent = sqlite3FindTable(db, @ptrCast(rdp(pFK, FKey_zTo)), zDb);
            var pIdx: Cptr = null;
            var aiCols: ?*c_int = null;
            if (pParent != null) {
                _ = sqlite3FkLocateIndex(pParse, pParent, pFK, &pIdx, &aiCols);
            }
            const addrOk = sqlite3VdbeMakeLabel(pParse);
            const nFkCol: c_int = rd(c_int, pFK, FKey_nCol);
            sqlite3TouchRegister(pParse, regRow + nFkCol);
            var j: c_int = 0;
            while (j < nFkCol) : (j += 1) {
                const iCol: c_int = if (aiCols) |ac|
                    (@as([*]c_int, @ptrCast(ac)) + @as(usize, @intCast(j)))[0]
                else
                    rd(c_int, @ptrCast(base(fieldPtr(pFK, FKey_aCol)) + @as(usize, @intCast(j)) * sizeof_sColMap), sColMap_iFrom);
                sqlite3ExprCodeGetColumnOfTable(v, pTab, 0, iCol, regRow + j);
                _ = sqlite3VdbeAddOp2(v, OP_IsNull, regRow + j, addrOk);
            }
            if (pIdx != null) {
                _ = sqlite3VdbeAddOp4(v, OP_Affinity, regRow, nFkCol, 0, @ptrCast(sqlite3IndexAffinityStr(db, pIdx)), nFkCol);
                _ = sqlite3VdbeAddOp4Int(v, OP_Found, i, addrOk, regRow, nFkCol);
            } else if (pParent != null) {
                const jmp = sqlite3VdbeCurrentAddr(v) + 2;
                _ = sqlite3VdbeAddOp3(v, OP_SeekRowid, i, jmp, regRow);
                _ = sqlite3VdbeGoto(v, addrOk);
            }
            if (hasRowid(pTab)) {
                _ = sqlite3VdbeAddOp2(v, OP_Rowid, 0, regResult + 1);
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_Null, 0, regResult + 1);
            }
            sqlite3VdbeMultiLoad(v, regResult + 2, "siX", rdp(pFK, FKey_zTo), i - 1);
            _ = sqlite3VdbeAddOp2(v, OP_ResultRow, regResult, 4);
            sqlite3VdbeResolveLabel(v, addrOk);
            sqlite3DbFree(db, aiCols);
        }
        _ = sqlite3VdbeAddOp2(v, OP_Next, 0, addrTop + 1);
        sqlite3VdbeJumpHere(v, addrTop);
    }
    iDbP.* = iDb;
    zDbP.* = zDb;
}

fn encodingPragma(pParse: Cptr, db: Cptr, v: Cptr, zRight: ?[*:0]u8) bool {
    const EncName = struct { zName: [*:0]const u8, enc: u8 };
    const encnames = [_]EncName{
        .{ .zName = "UTF8", .enc = SQLITE_UTF8 },
        .{ .zName = "UTF-8", .enc = SQLITE_UTF8 },
        .{ .zName = "UTF-16le", .enc = SQLITE_UTF16LE },
        .{ .zName = "UTF-16be", .enc = SQLITE_UTF16BE },
        .{ .zName = "UTF16le", .enc = SQLITE_UTF16LE },
        .{ .zName = "UTF16be", .enc = SQLITE_UTF16BE },
        .{ .zName = "UTF-16", .enc = 0 },
        .{ .zName = "UTF16", .enc = 0 },
    };
    if (zRight == null) {
        if (sqlite3ReadSchema(pParse) != 0) return true;
        returnSingleText(v, encnames[encOf(db)].zName);
    } else {
        if ((rd(u32, db, sqlite3_mDbFlags) & DBFLAG_EncodingFixed) == 0) {
            var matched = false;
            for (encnames) |pEnc| {
                if (sqlite3_stricmp(zRight, pEnc.zName) == 0) {
                    const enc: u8 = if (pEnc.enc != 0) pEnc.enc else SQLITE_UTF16NATIVE;
                    // SCHEMA_ENC(db) = db->aDb[0].pSchema->enc
                    wr(u8, rdp(dbAt(db, 0), Db_pSchema), Schema_enc, enc);
                    sqlite3SetTextEncoding(db, enc);
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                sqlite3ErrorMsg(pParse, "unsupported encoding: %s", zRight);
            }
        }
    }
    return false;
}

fn optimizePragma(pParse: Cptr, db: Cptr, v: Cptr, iDb0: c_int, zDb: ?[*:0]const u8, zRight: ?[*:0]u8) void {
    var iDb = iDb0;
    var opMask: u32 = undefined;
    if (zRight != null) {
        opMask = @bitCast(sqlite3Atoi(zRight));
        if ((opMask & 0x02) == 0) return;
    } else {
        opMask = 0xfffe;
    }
    var nLimit: c_int = undefined;
    if ((opMask & 0x10) == 0) {
        nLimit = 0;
    } else if (rd(c_int, db, sqlite3_nAnalysisLimit) > 0 and rd(c_int, db, sqlite3_nAnalysisLimit) < SQLITE_DEFAULT_OPTIMIZE_LIMIT) {
        nLimit = 0;
    } else {
        nLimit = SQLITE_DEFAULT_OPTIMIZE_LIMIT;
    }
    const iTabCur = rd(c_int, pParse, Parse_nTab);
    wr(c_int, pParse, Parse_nTab, iTabCur + 1);
    var nCheck: c_int = 0;
    var nBtree: c_int = 0;
    const iDbLast: c_int = if (zDb != null) iDb else rd(c_int, db, sqlite3_nDb) - 1;
    while (iDb <= iDbLast) : (iDb += 1) {
        if (iDb == 1) continue;
        sqlite3CodeVerifySchema(pParse, iDb);
        const pSchema = rdp(dbAt(db, iDb), Db_pSchema);
        var k = hashFirst(fieldPtr(pSchema, Schema_tblHash));
        while (k != null) : (k = hashNext(k)) {
            const pTab = hashData(k);
            if (!isOrdinaryTable(pTab)) continue;
            if (sqlite3_strnicmp(@ptrCast(rdp(pTab, Table_zName)), "sqlite_", 7) == 0) continue;
            var szThreshold: i16 = rd(i16, pTab, Table_nRowLogEst);
            var nIndex: c_int = 0;
            var pIdx = rdp(pTab, Table_pIndex);
            while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
                nIndex += 1;
                if (!idxHasStat1(pIdx)) szThreshold = -1;
            }
            if ((tabFlags(pTab) & TF_MaybeReanalyze) != 0) {
                // analyze
            } else if (opMask & 0x10000 != 0) {
                // analyze
            } else if (rdp(pTab, Table_pIndex) != null and szThreshold < 0) {
                // analyze
            } else {
                continue;
            }
            nCheck += 1;
            if (nCheck == 2) {
                sqlite3BeginWriteOperation(pParse, 0, iDb);
            }
            nBtree += nIndex + 1;
            sqlite3OpenTable(pParse, iTabCur, iDb, pTab, OP_OpenRead);
            if (szThreshold >= 0) {
                const iRange: c_int = 33;
                _ = sqlite3VdbeAddOp4Int(v, OP_IfSizeBetween, iTabCur, sqlite3VdbeCurrentAddr(v) + 2 + @as(c_int, @intCast(opMask & 1)), if (szThreshold >= iRange) szThreshold - iRange else -1, szThreshold + iRange);
            } else {
                _ = sqlite3VdbeAddOp2(v, OP_Rewind, iTabCur, sqlite3VdbeCurrentAddr(v) + 2 + @as(c_int, @intCast(opMask & 1)));
            }
            const zSubSql = sqlite3MPrintf(db, "ANALYZE \"%w\".\"%w\"", rdp(dbAt(db, iDb), Db_zDbSName), rdp(pTab, Table_zName));
            if (opMask & 0x01 != 0) {
                const r1 = sqlite3GetTempReg(pParse);
                _ = sqlite3VdbeAddOp4(v, OP_String8, 0, r1, 0, @ptrCast(zSubSql), P4_DYNAMIC);
                _ = sqlite3VdbeAddOp2(v, OP_ResultRow, r1, 1);
            } else {
                _ = sqlite3VdbeAddOp4(v, OP_SqlExec, if (nLimit != 0) 0x02 else 0, nLimit, 0, @ptrCast(zSubSql), P4_DYNAMIC);
            }
        }
    }
    _ = sqlite3VdbeAddOp0(v, OP_Expire);
    if (rd(u8, db, sqlite3_mallocFailed) == 0 and nLimit > 0 and nBtree > 100) {
        nLimit = @divTrunc(100 * nLimit, nBtree);
        if (nLimit < 100) nLimit = 100;
        const aOp = sqlite3VdbeGetOp(v, 0);
        const iEnd = sqlite3VdbeCurrentAddr(v);
        var iAddr: c_int = 0;
        while (iAddr < iEnd) : (iAddr += 1) {
            const op = opAt(aOp, @intCast(iAddr));
            if (opOpcode(op) == OP_SqlExec) opSetP2(op, nLimit);
        }
    }
}

fn integrityCheck(pParse: Cptr, db: Cptr, v: Cptr, pPragma: *const PragmaName, iDb0: c_int, zLeft: ?[*:0]u8, zRight: ?[*:0]u8, zDb0: ?[*:0]const u8, pId2: Cptr, pValue: Cptr) void {
    _ = pPragma;
    _ = zDb0;
    var iDb = iDb0;
    var pObjTab: Cptr = null;
    const isQuick = (sqlite3Tolower(zLeft.?[0]) == 'q');
    if (tokenZ(pId2) == null) iDb = -1;
    wr(c_int, pParse, Parse_nMem, 6);
    var mxErr: c_int = SQLITE_INTEGRITY_CHECK_ERROR_MAX;
    if (zRight != null) {
        if (sqlite3GetInt32(@ptrCast(tokenZ(pValue)), &mxErr) != 0) {
            if (mxErr <= 0) mxErr = SQLITE_INTEGRITY_CHECK_ERROR_MAX;
        } else {
            pObjTab = sqlite3LocateTable(pParse, 0, zRight, if (iDb >= 0) @ptrCast(rdp(dbAt(db, iDb), Db_zDbSName)) else null);
        }
    }
    _ = sqlite3VdbeAddOp2(v, OP_Integer, mxErr - 1, 1);

    var i: c_int = 0;
    const ndb = rd(c_int, db, sqlite3_nDb);
    while (i < ndb) : (i += 1) {
        if (iDb >= 0 and i != iDb) continue;
        sqlite3CodeVerifySchema(pParse, i);
        // tag-20230327-1: pParse->okConstFactor = 0;
        base(pParse)[Parse_bft_byte] &= ~BFT_okConstFactor;

        const pTbls = fieldPtr(rdp(dbAt(db, i), Db_pSchema), Schema_tblHash);
        var cnt: c_int = 0;
        var x = hashFirst(pTbls);
        while (x != null) : (x = hashNext(x)) {
            const pTab = hashData(x);
            if (tableSkipIntegrityCheck(pTab, pObjTab)) continue;
            if (hasRowid(pTab)) cnt += 1;
            var pIdx = rdp(pTab, Table_pIndex);
            while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) cnt += 1;
        }
        if (cnt == 0) continue;
        if (pObjTab != null) cnt += 1;
        const aRoot: ?[*]c_int = @ptrCast(@alignCast(sqlite3DbMallocRawNN(db, @as(u64, @intCast(@sizeOf(c_int))) * @as(u64, @intCast(cnt + 1)))));
        if (aRoot == null) break;
        cnt = 0;
        if (pObjTab != null) {
            cnt += 1;
            aRoot.?[@intCast(cnt)] = 0;
        }
        x = hashFirst(pTbls);
        while (x != null) : (x = hashNext(x)) {
            const pTab = hashData(x);
            if (tableSkipIntegrityCheck(pTab, pObjTab)) continue;
            if (hasRowid(pTab)) {
                cnt += 1;
                aRoot.?[@intCast(cnt)] = @intCast(rd(u32, pTab, Table_tnum));
            }
            var pIdx = rdp(pTab, Table_pIndex);
            while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
                cnt += 1;
                aRoot.?[@intCast(cnt)] = @intCast(rd(u32, pIdx, Index_tnum));
            }
        }
        aRoot.?[0] = cnt;

        sqlite3TouchRegister(pParse, 8 + cnt);
        _ = sqlite3VdbeAddOp3(v, OP_Null, 0, 8, 8 + cnt);
        sqlite3ClearTempRegCache(pParse);
        _ = sqlite3VdbeAddOp4(v, OP_IntegrityCk, 1, cnt, 8, @ptrCast(aRoot), P4_INTARRAY);
        sqlite3VdbeChangeP5(v, @intCast(i));
        var addr = sqlite3VdbeAddOp1(v, OP_IsNull, 2);
        _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(sqlite3MPrintf(db, "*** in database %s ***\n", rdp(dbAt(db, i), Db_zDbSName))), P4_DYNAMIC);
        _ = sqlite3VdbeAddOp3(v, OP_Concat, 2, 3, 3);
        _ = integrityCheckResultRow(v);
        sqlite3VdbeJumpHere(v, addr);

        // Check index entry counts.
        cnt = if (pObjTab != null) 1 else 0;
        _ = sqlite3VdbeLoadString(v, 2, "wrong # of entries in index ");
        x = hashFirst(pTbls);
        while (x != null) : (x = hashNext(x)) {
            const pTab = hashData(x);
            if (tableSkipIntegrityCheck(pTab, pObjTab)) continue;
            var iTab: c_int = 0;
            if (hasRowid(pTab)) {
                iTab = cnt;
                cnt += 1;
            } else {
                iTab = cnt;
                var pIdx = rdp(pTab, Table_pIndex);
                while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
                    if (isPrimaryKeyIndex(pIdx)) break;
                    iTab += 1;
                }
            }
            var pIdx = rdp(pTab, Table_pIndex);
            while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
                if (rdp(pIdx, Index_pPartIdxWhere) == null) {
                    addr = sqlite3VdbeAddOp3(v, OP_Eq, 8 + cnt, 0, 8 + iTab);
                    _ = sqlite3VdbeLoadString(v, 4, @ptrCast(rdp(pIdx, Index_zName)));
                    _ = sqlite3VdbeAddOp3(v, OP_Concat, 4, 2, 3);
                    _ = integrityCheckResultRow(v);
                    sqlite3VdbeJumpHere(v, addr);
                }
                cnt += 1;
            }
        }

        // Per-table validation.
        integrityCheckTables(pParse, db, v, pTbls, pObjTab, isQuick);

        // Virtual-table xIntegrity pass.
        x = hashFirst(pTbls);
        while (x != null) : (x = hashNext(x)) {
            const pTab = hashData(x);
            if (tableSkipIntegrityCheck(pTab, pObjTab)) continue;
            if (isOrdinaryTable(pTab)) continue;
            if (!isVirtual(pTab)) continue;
            if (rd(i16, pTab, Table_nCol) <= 0) {
                const azArg = rdp(pTab, Table_u_vtab_azArg);
                const zMod: ?[*:0]const u8 = @ptrCast(rd(?*anyopaque, azArg, 0));
                if (sqlite3HashFind(fieldPtr(db, sqlite3_aModule), zMod) == null) continue;
            }
            _ = sqlite3ViewGetColumnNames(pParse, pTab);
            const pVtabP = rdp(pTab, Table_u_vtab_p);
            if (pVtabP == null) continue;
            const pVTab = rdp(pVtabP, VTable_pVtab); // VTable.pVtab
            if (pVTab == null) continue;
            const pModule = rdp(pVTab, 0); // sqlite3_vtab.pModule is first member
            if (pModule == null) continue;
            if (rd(c_int, pModule, 0) < 4) continue; // iVersion
            if (rd(?*anyopaque, pModule, Module_xIntegrity) == null) continue;
            _ = sqlite3VdbeAddOp3(v, OP_VCheck, i, 3, @intFromBool(isQuick));
            wr(u32, pTab, Table_nTabRef, rd(u32, pTab, Table_nTabRef) + 1);
            sqlite3VdbeAppendP4(v, pTab, P4_TABLEREF);
            const a1 = sqlite3VdbeAddOp1(v, OP_IsNull, 3);
            _ = integrityCheckResultRow(v);
            sqlite3VdbeJumpHere(v, a1);
        }
    }
    const aOp = sqlite3VdbeAddOpList(v, endCode_n, @ptrCast(&endCode), 0);
    if (aOp != null) {
        opSetP2(opAt(aOp, 0), 1 - mxErr);
        opSetP4type(opAt(aOp, 2), @intCast(P4_STATIC));
        opSetP4z(opAt(aOp, 2), "ok");
        opSetP4type(opAt(aOp, 5), @intCast(P4_STATIC));
        opSetP4z(opAt(aOp, 5), sqlite3ErrStr(SQLITE_CORRUPT));
    }
    sqlite3VdbeChangeP3(v, 0, sqlite3VdbeCurrentAddr(v) - 2);
}

// sqlite3_module.xIntegrity offset: iVersion(int 0) + 23 fn ptrs.  xIntegrity
// is the last (23rd) method.  offset = 8 (iVersion+pad) + 22*8 = 184.
const Module_xIntegrity: usize = 192; // sqlite3_module.xIntegrity (probed via offsetof)
const VTable_pVtab: usize = off("VTable_pVtab", 16); // probed: VTable.pVtab at 16

fn integrityCheckTables(pParse: Cptr, db: Cptr, v: Cptr, pTbls: ?*anyopaque, pObjTab: Cptr, isQuick: bool) void {
    const aStdTypeMask = [_]u8{ 0x1f, 0x18, 0x11, 0x11, 0x13, 0x14 };
    var x = hashFirst(pTbls);
    while (x != null) : (x = hashNext(x)) {
        const pTab = hashData(x);
        var pPrior: Cptr = null;
        var r1: c_int = -1;
        if (tableSkipIntegrityCheck(pTab, pObjTab)) continue;
        if (!isOrdinaryTable(pTab)) continue;
        var pPk: Cptr = null;
        var r2: c_int = 0;
        if (isQuick or hasRowid(pTab)) {
            pPk = null;
            r2 = 0;
        } else {
            pPk = sqlite3PrimaryKeyIndex(pTab);
            r2 = sqlite3GetTempRange(pParse, rd(u16, pPk, Index_nKeyCol));
            _ = sqlite3VdbeAddOp3(v, OP_Null, 1, r2, r2 + @as(c_int, rd(u16, pPk, Index_nKeyCol)) - 1);
        }
        var iDataCur: c_int = undefined;
        var iIdxCur: c_int = undefined;
        _ = sqlite3OpenTableAndIndices(pParse, pTab, OP_OpenRead, 0, 1, null, &iDataCur, &iIdxCur);
        _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, 7);
        var j: c_int = 0;
        var pIdx = rdp(pTab, Table_pIndex);
        while (pIdx != null) : ({
            pIdx = rdp(pIdx, Index_pNext);
            j += 1;
        }) {
            _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, 8 + j);
        }
        _ = sqlite3VdbeAddOp2(v, OP_Rewind, iDataCur, 0);
        const loopTop = sqlite3VdbeAddOp2(v, OP_AddImm, 7, 1);

        const nCol: c_int = rd(i16, pTab, Table_nCol);
        var mxCol: c_int = undefined;
        if (hasRowid(pTab)) {
            mxCol = -1;
            j = 0;
            while (j < nCol) : (j += 1) {
                if ((rd(u16, colAt(pTab, @intCast(j)), Column_colFlags) & COLFLAG_VIRTUAL) == 0) mxCol += 1;
            }
            if (mxCol == @as(c_int, rd(i16, pTab, Table_iPKey))) mxCol -= 1;
        } else {
            mxCol = @as(c_int, rd(u16, sqlite3PrimaryKeyIndex(pTab), Index_nColumn)) - 1;
        }
        if (mxCol >= 0) {
            _ = sqlite3VdbeAddOp3(v, OP_Column, iDataCur, mxCol, 3);
            sqlite3VdbeTypeofColumn(v, 3);
        }

        if (!isQuick) {
            if (pPk != null) {
                const a1 = sqlite3VdbeAddOp4Int(v, OP_IdxGT, iDataCur, 0, r2, rd(u16, pPk, Index_nKeyCol));
                _ = sqlite3VdbeAddOp1(v, OP_IsNull, r2);
                const zErr = sqlite3MPrintf(db, "row not in PRIMARY KEY order for %s", rdp(pTab, Table_zName));
                _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(zErr), P4_DYNAMIC);
                _ = integrityCheckResultRow(v);
                sqlite3VdbeJumpHere(v, a1);
                sqlite3VdbeJumpHere(v, a1 + 1);
                j = 0;
                while (j < @as(c_int, rd(u16, pPk, Index_nKeyCol))) : (j += 1) {
                    sqlite3ExprCodeLoadIndexColumn(pParse, pPk, iDataCur, j, r2 + j);
                }
            }
        }

        const bStrict = (tabFlags(pTab) & TF_Strict) != 0;
        j = 0;
        while (j < nCol) : (j += 1) {
            const pCol = colAt(pTab, @intCast(j));
            var p1: c_int = undefined;
            var p3: c_int = undefined;
            var p4: c_int = SQLITE_NULL;
            if (j == @as(c_int, rd(i16, pTab, Table_iPKey))) continue;
            const aff = rd(i8, pCol, Column_affinity);
            const doTypeCheck = if (bStrict) (colECType(pCol) > COLTYPE_ANY) else (aff > @as(i8, @bitCast(SQLITE_AFF_BLOB)));
            if (colNotNull(pCol) == 0 and !doTypeCheck) continue;

            if ((rd(u16, pCol, Column_colFlags) & COLFLAG_VIRTUAL) != 0) {
                sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, j, 3);
                p1 = -1;
                p3 = 3;
            } else {
                if (rd(u16, pCol, Column_iDflt) != 0) {
                    var pDfltValue: Cptr = null;
                    _ = sqlite3ValueFromExpr(db, sqlite3ColumnExpr(pTab, pCol), encOf(db), @bitCast(aff), &pDfltValue);
                    if (pDfltValue != null) {
                        p4 = sqlite3_value_type(pDfltValue);
                        sqlite3ValueFree(pDfltValue);
                    }
                }
                p1 = iDataCur;
                if (!hasRowid(pTab)) {
                    p3 = sqlite3TableColumnToIndex(sqlite3PrimaryKeyIndex(pTab), @intCast(j));
                } else {
                    p3 = sqlite3TableColumnToStorage(pTab, @intCast(j));
                }
            }

            const labelError = sqlite3VdbeMakeLabel(pParse);
            const labelOk = sqlite3VdbeMakeLabel(pParse);
            if (colNotNull(pCol) != 0) {
                var jmp3: c_int = undefined;
                const jmp2 = sqlite3VdbeAddOp4Int(v, OP_IsType, p1, labelOk, p3, p4);
                if (p1 < 0) {
                    sqlite3VdbeChangeP5(v, 0x0f);
                    jmp3 = jmp2;
                } else {
                    sqlite3VdbeChangeP5(v, 0x0d);
                    _ = sqlite3VdbeAddOp3(v, OP_Column, p1, p3, 3);
                    sqlite3ColumnDefault(v, pTab, j, 3);
                    jmp3 = sqlite3VdbeAddOp2(v, OP_NotNull, 3, labelOk);
                }
                const zErr = sqlite3MPrintf(db, "NULL value in %s.%s", rdp(pTab, Table_zName), rdp(pCol, Column_zCnName));
                _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(zErr), P4_DYNAMIC);
                if (doTypeCheck) {
                    _ = sqlite3VdbeGoto(v, labelError);
                    sqlite3VdbeJumpHere(v, jmp2);
                    sqlite3VdbeJumpHere(v, jmp3);
                }
            }
            if (bStrict and doTypeCheck) {
                _ = sqlite3VdbeAddOp4Int(v, OP_IsType, p1, labelOk, p3, p4);
                sqlite3VdbeChangeP5(v, aStdTypeMask[colECType(pCol) - 1]);
                const zErr = sqlite3MPrintf(db, "non-%s value in %s.%s", sqlite3StdType[colECType(pCol) - 1], rdp(pTab, Table_zName), rdp(colAt(pTab, @intCast(j)), Column_zCnName));
                _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(zErr), P4_DYNAMIC);
            } else if (!bStrict and aff == @as(i8, @bitCast(SQLITE_AFF_TEXT))) {
                _ = sqlite3VdbeAddOp4Int(v, OP_IsType, p1, labelOk, p3, p4);
                sqlite3VdbeChangeP5(v, 0x1c);
                const zErr = sqlite3MPrintf(db, "NUMERIC value in %s.%s", rdp(pTab, Table_zName), rdp(colAt(pTab, @intCast(j)), Column_zCnName));
                _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(zErr), P4_DYNAMIC);
            } else if (!bStrict and aff >= @as(i8, @bitCast(SQLITE_AFF_NUMERIC))) {
                _ = sqlite3VdbeAddOp4Int(v, OP_IsType, p1, labelOk, p3, p4);
                sqlite3VdbeChangeP5(v, 0x1b);
                if (p1 >= 0) {
                    sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, j, 3);
                }
                _ = sqlite3VdbeAddOp4(v, OP_Affinity, 3, 1, 0, "C", P4_STATIC);
                _ = sqlite3VdbeAddOp4Int(v, OP_IsType, -1, labelOk, 3, p4);
                sqlite3VdbeChangeP5(v, 0x1c);
                const zErr = sqlite3MPrintf(db, "TEXT value in %s.%s", rdp(pTab, Table_zName), rdp(colAt(pTab, @intCast(j)), Column_zCnName));
                _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(zErr), P4_DYNAMIC);
            }
            sqlite3VdbeResolveLabel(v, labelError);
            _ = integrityCheckResultRow(v);
            sqlite3VdbeResolveLabel(v, labelOk);
        }

        // CHECK constraints.
        if (rdp(pTab, Table_pCheck) != null and (rd(u64, db, sqlite3_flags) & SQLITE_IgnoreChecks) == 0) {
            const pCheck = sqlite3ExprListDup(db, rdp(pTab, Table_pCheck), 0);
            if (rd(u8, db, sqlite3_mallocFailed) == 0) {
                const addrCkFault = sqlite3VdbeMakeLabel(pParse);
                const addrCkOk = sqlite3VdbeMakeLabel(pParse);
                wr(c_int, pParse, Parse_iSelfTab, iDataCur + 1);
                const nExpr: c_int = rd(c_int, pCheck, 0); // ExprList.nExpr at 0
                const elA = fieldPtr(pCheck, 8); // ExprList.a at 8
                var kk: c_int = nExpr - 1;
                while (kk > 0) : (kk -= 1) {
                    sqlite3ExprIfFalse(pParse, exprListItemExpr(elA, kk), addrCkFault, 0);
                }
                sqlite3ExprIfTrue(pParse, exprListItemExpr(elA, 0), addrCkOk, SQLITE_JUMPIFNULL);
                sqlite3VdbeResolveLabel(v, addrCkFault);
                wr(c_int, pParse, Parse_iSelfTab, 0);
                const zErr = sqlite3MPrintf(db, "CHECK constraint failed in %s", rdp(pTab, Table_zName));
                _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(zErr), P4_DYNAMIC);
                _ = integrityCheckResultRow(v);
                sqlite3VdbeResolveLabel(v, addrCkOk);
            }
            sqlite3ExprListDelete(db, pCheck);
        }

        if (!isQuick) {
            integrityCheckIndexes(pParse, db, v, pTab, pPk, iDataCur, iIdxCur, &pPrior, &r1);
        }
        _ = sqlite3VdbeAddOp2(v, OP_Next, iDataCur, loopTop);
        sqlite3VdbeJumpHere(v, loopTop - 1);
        if (pPk != null) {
            sqlite3ReleaseTempRange(pParse, r2, rd(u16, pPk, Index_nKeyCol));
        }
    }
}

// ExprList.a[i].pExpr — item stride 32, pExpr at off 0.
const sizeof_ExprList_item: usize = off("sizeof_ExprList_item", 32);
inline fn exprListItemExpr(elA: ?*anyopaque, i: c_int) ?*anyopaque {
    return rd(?*anyopaque, @ptrCast(base(elA) + @as(usize, @intCast(i)) * sizeof_ExprList_item), 0);
}

fn integrityCheckIndexes(pParse: Cptr, db: Cptr, v: Cptr, pTab: Cptr, pPk: Cptr, iDataCur: c_int, iIdxCur: c_int, pPriorP: *Cptr, r1P: *c_int) void {
    var j: c_int = 0;
    var pIdx = rdp(pTab, Table_pIndex);
    while (pIdx != null) : ({
        pIdx = rdp(pIdx, Index_pNext);
        j += 1;
    }) {
        const ckUniq = sqlite3VdbeMakeLabel(pParse);
        if (pPk == pIdx) continue;
        var jmp3: c_int = undefined;
        r1P.* = sqlite3GenerateIndexKey(pParse, pIdx, iDataCur, 0, 0, &jmp3, pPriorP.*, r1P.*);
        pPriorP.* = pIdx;
        const nColumn: c_int = rd(u16, pIdx, Index_nColumn);
        _ = sqlite3VdbeAddOp2(v, OP_AddImm, 8 + j, 1);
        _ = sqlite3VdbeAddOp4Int(v, OP_Found, iIdxCur + j, ckUniq, r1P.*, nColumn);
        const jmp2 = sqlite3VdbeAddOp3(v, OP_IFindKey, iIdxCur + j, ckUniq, r1P.*);
        sqlite3VdbeChangeP4(v, -1, @ptrCast(pIdx), P4_INDEX);
        _ = sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, @ptrCast(sqlite3MPrintf(db, "index %s stores an imprecise floating-point value for row ", rdp(pIdx, Index_zName))), P4_DYNAMIC);
        _ = sqlite3VdbeAddOp3(v, OP_Concat, 7, 3, 3);
        _ = integrityCheckResultRow(v);
        _ = sqlite3VdbeAddOp2(v, OP_Goto, 0, ckUniq);

        sqlite3VdbeJumpHere(v, jmp2);
        _ = sqlite3VdbeLoadString(v, 3, "row ");
        _ = sqlite3VdbeAddOp3(v, OP_Concat, 7, 3, 3);
        _ = sqlite3VdbeLoadString(v, 4, " missing from index ");
        _ = sqlite3VdbeAddOp3(v, OP_Concat, 4, 3, 3);
        const jmp5 = sqlite3VdbeLoadString(v, 4, @ptrCast(rdp(pIdx, Index_zName)));
        _ = sqlite3VdbeAddOp3(v, OP_Concat, 4, 3, 3);
        const jmp4 = integrityCheckResultRow(v);
        sqlite3VdbeResolveLabel(v, ckUniq);

        if (hasRowid(pTab)) {
            _ = sqlite3VdbeAddOp2(v, OP_IdxRowid, iIdxCur + j, 3);
            const jmp7 = sqlite3VdbeAddOp3(v, OP_Eq, 3, 0, r1P.* + nColumn - 1);
            _ = sqlite3VdbeLoadString(v, 3, "rowid not at end-of-record for row ");
            _ = sqlite3VdbeAddOp3(v, OP_Concat, 7, 3, 3);
            _ = sqlite3VdbeLoadString(v, 4, " of index ");
            _ = sqlite3VdbeGoto(v, jmp5 - 1);
            sqlite3VdbeJumpHere(v, jmp7);
        }

        // Non-BINARY collations must hold exact text.
        var label6: c_int = 0;
        const nKeyCol: c_int = rd(u16, pIdx, Index_nKeyCol);
        const azColl = rdp(pIdx, Index_azColl);
        const binPtr: ?*anyopaque = @ptrCast(@constCast(&sqlite3StrBINARY));
        var kk: c_int = 0;
        while (kk < nKeyCol) : (kk += 1) {
            if (rd(?*anyopaque, azColl, @as(usize, @intCast(kk)) * 8) == binPtr) continue;
            if (label6 == 0) label6 = sqlite3VdbeMakeLabel(pParse);
            _ = sqlite3VdbeAddOp3(v, OP_Column, iIdxCur + j, kk, 3);
            _ = sqlite3VdbeAddOp3(v, OP_Ne, 3, label6, r1P.* + kk);
        }
        if (label6 != 0) {
            const jmp6 = sqlite3VdbeAddOp0(v, OP_Goto);
            sqlite3VdbeResolveLabel(v, label6);
            _ = sqlite3VdbeLoadString(v, 3, "row ");
            _ = sqlite3VdbeAddOp3(v, OP_Concat, 7, 3, 3);
            _ = sqlite3VdbeLoadString(v, 4, " values differ from index ");
            _ = sqlite3VdbeGoto(v, jmp5 - 1);
            sqlite3VdbeJumpHere(v, jmp6);
        }

        if (isUniqueIndex(pIdx)) {
            const uniqOk = sqlite3VdbeMakeLabel(pParse);
            const aiColumn = rdp(pIdx, Index_aiColumn);
            kk = 0;
            while (kk < nKeyCol) : (kk += 1) {
                const iCol = rd(i16, aiColumn, @as(usize, @intCast(kk)) * 2);
                if (iCol >= 0 and colNotNull(colAt(pTab, @intCast(iCol))) != 0) continue;
                _ = sqlite3VdbeAddOp2(v, OP_IsNull, r1P.* + kk, uniqOk);
            }
            const jmp6 = sqlite3VdbeAddOp1(v, OP_Next, iIdxCur + j);
            _ = sqlite3VdbeGoto(v, uniqOk);
            sqlite3VdbeJumpHere(v, jmp6);
            _ = sqlite3VdbeAddOp4Int(v, OP_IdxGT, iIdxCur + j, uniqOk, r1P.*, nKeyCol);
            _ = sqlite3VdbeLoadString(v, 3, "non-unique entry in index ");
            _ = sqlite3VdbeGoto(v, jmp5);
            sqlite3VdbeResolveLabel(v, uniqOk);
        }
        sqlite3VdbeJumpHere(v, jmp4);
        sqlite3ResolvePartIdxLabel(pParse, jmp3);
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Eponymous virtual table that runs a pragma
// ════════════════════════════════════════════════════════════════════════════

// sqlite3_vtab = { const sqlite3_module *pModule; int nRef; char *zErrMsg } (24)
const sqlite3_vtab = extern struct {
    pModule: ?*const anyopaque,
    nRef: c_int,
    zErrMsg: ?[*:0]u8,
};
// sqlite3_vtab_cursor = { sqlite3_vtab *pVtab } (8)
const sqlite3_vtab_cursor = extern struct {
    pVtab: ?*sqlite3_vtab,
};

const PragmaVtab = extern struct {
    base: sqlite3_vtab,
    db: ?*anyopaque,
    pName: ?*const PragmaName,
    nHidden: u8,
    iHidden: u8,
};
const PragmaVtabCursor = extern struct {
    base: sqlite3_vtab_cursor,
    pPragma: ?*anyopaque,
    iRowid: i64,
    azArg: [2]?[*:0]u8,
};

// sqlite3_index_info field offsets we need (xBestIndex).
const IdxInfo_nConstraint = off("sqlite3_index_info_nConstraint", 0);
const IdxInfo_aConstraint = off("sqlite3_index_info_aConstraint", 8);
const IdxInfo_aConstraintUsage = off("sqlite3_index_info_aConstraintUsage", 32);
const IdxInfo_estimatedCost = off("sqlite3_index_info_estimatedCost", 64);
const IdxInfo_estimatedRows = off("sqlite3_index_info_estimatedRows", 72);
// struct sqlite3_index_constraint { int iColumn; unsigned char op; unsigned char usable; int iTermOffset } = 12 bytes
const sizeof_idx_constraint: usize = 12;
const idx_constraint_iColumn: usize = 0;
const idx_constraint_op: usize = 4;
const idx_constraint_usable: usize = 5;
// struct sqlite3_index_constraint_usage { int argvIndex; unsigned char omit } = 8 bytes
const sizeof_idx_usage: usize = 8;
const idx_usage_argvIndex: usize = 0;
const idx_usage_omit: usize = 4;

fn pragmaVtabConnect(
    db: ?*anyopaque,
    pAux: ?*anyopaque,
    argc: c_int,
    argv: ?*const ?[*:0]const u8,
    ppVtab: *?*sqlite3_vtab,
    pzErr: *?[*:0]u8,
) callconv(.c) c_int {
    _ = argc;
    _ = argv;
    const pPragma: *const PragmaName = @ptrCast(@alignCast(pAux.?));
    var acc: [64]u8 = undefined; // StrAccum struct (we only pass &acc to C)
    var zBuf: [200]u8 = undefined;
    var cSep: u8 = '(';
    sqlite3StrAccumInit(@ptrCast(&acc), null, &zBuf, zBuf.len, 0);
    sqlite3_str_appendall(@ptrCast(&acc), "CREATE TABLE x");
    var i: c_int = 0;
    var jcn: usize = pPragma.iPragCName;
    while (i < pPragma.nPragCName) : ({
        i += 1;
        jcn += 1;
    }) {
        sqlite3_str_appendf(@ptrCast(&acc), "%c\"%s\"", @as(c_int, cSep), pragCName[jcn]);
        cSep = ',';
    }
    if (i == 0) {
        sqlite3_str_appendf(@ptrCast(&acc), "(\"%s\"", pPragma.zName);
        i += 1;
    }
    var jh: c_int = 0;
    if (pPragma.mPragFlg & PragFlg_Result1 != 0) {
        sqlite3_str_appendall(@ptrCast(&acc), ",arg HIDDEN");
        jh += 1;
    }
    if (pPragma.mPragFlg & (PragFlg_SchemaOpt | PragFlg_SchemaReq) != 0) {
        sqlite3_str_appendall(@ptrCast(&acc), ",schema HIDDEN");
        jh += 1;
    }
    sqlite3_str_append(@ptrCast(&acc), ")", 1);
    _ = sqlite3StrAccumFinish(@ptrCast(&acc));
    const rc = sqlite3_declare_vtab(db, @ptrCast(&zBuf));
    var pTab: ?*PragmaVtab = null;
    var rrc = rc;
    if (rc == SQLITE_OK) {
        pTab = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(PragmaVtab))));
        if (pTab == null) {
            rrc = SQLITE_NOMEM;
        } else {
            @memset(@as([*]u8, @ptrCast(pTab))[0..@sizeOf(PragmaVtab)], 0);
            pTab.?.pName = pPragma;
            pTab.?.db = db;
            pTab.?.iHidden = @intCast(i);
            pTab.?.nHidden = @intCast(jh);
        }
    } else {
        pzErr.* = sqlite3_mprintf("%s", sqlite3_errmsg(db));
    }
    ppVtab.* = @ptrCast(pTab);
    return rrc;
}

fn pragmaVtabDisconnect(pVtab: ?*sqlite3_vtab) callconv(.c) c_int {
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

fn pragmaVtabBestIndex(tab: ?*sqlite3_vtab, pIdxInfo: ?*anyopaque) callconv(.c) c_int {
    const pTab: *PragmaVtab = @ptrCast(@alignCast(tab.?));
    wr(f64, pIdxInfo, IdxInfo_estimatedCost, 1.0);
    if (pTab.nHidden == 0) return SQLITE_OK;
    const nConstraint = rd(c_int, pIdxInfo, IdxInfo_nConstraint);
    const aConstraint = rdp(pIdxInfo, IdxInfo_aConstraint);
    var seen = [_]c_int{ 0, 0 };
    var i: c_int = 0;
    while (i < nConstraint) : (i += 1) {
        const pc = base(aConstraint) + @as(usize, @intCast(i)) * sizeof_idx_constraint;
        const iColumn = rd(c_int, @ptrCast(pc), idx_constraint_iColumn);
        const op = base(@ptrCast(pc))[idx_constraint_op];
        const usable = base(@ptrCast(pc))[idx_constraint_usable];
        if (iColumn < pTab.iHidden) continue;
        if (op != SQLITE_INDEX_CONSTRAINT_EQ) continue;
        if (usable == 0) return SQLITE_CONSTRAINT;
        const jj = iColumn - pTab.iHidden;
        seen[@intCast(jj)] = i + 1;
    }
    if (seen[0] == 0) {
        wr(f64, pIdxInfo, IdxInfo_estimatedCost, 2147483647.0);
        wr(i64, pIdxInfo, IdxInfo_estimatedRows, 2147483647);
        return SQLITE_OK;
    }
    const aUsage = rdp(pIdxInfo, IdxInfo_aConstraintUsage);
    var jj: c_int = seen[0] - 1;
    var pu = base(aUsage) + @as(usize, @intCast(jj)) * sizeof_idx_usage;
    wr(c_int, @ptrCast(pu), idx_usage_argvIndex, 1);
    base(@ptrCast(pu))[idx_usage_omit] = 1;
    wr(f64, pIdxInfo, IdxInfo_estimatedCost, 20.0);
    wr(i64, pIdxInfo, IdxInfo_estimatedRows, 20);
    if (seen[1] != 0) {
        jj = seen[1] - 1;
        pu = base(aUsage) + @as(usize, @intCast(jj)) * sizeof_idx_usage;
        wr(c_int, @ptrCast(pu), idx_usage_argvIndex, 2);
        base(@ptrCast(pu))[idx_usage_omit] = 1;
    }
    return SQLITE_OK;
}

fn pragmaVtabOpen(pVtab: ?*sqlite3_vtab, ppCursor: *?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: ?*PragmaVtabCursor = @ptrCast(@alignCast(sqlite3_malloc(@sizeOf(PragmaVtabCursor))));
    if (pCsr == null) return SQLITE_NOMEM;
    @memset(@as([*]u8, @ptrCast(pCsr))[0..@sizeOf(PragmaVtabCursor)], 0);
    pCsr.?.base.pVtab = pVtab;
    ppCursor.* = @ptrCast(pCsr);
    return SQLITE_OK;
}

fn pragmaVtabCursorClear(pCsr: *PragmaVtabCursor) void {
    _ = sqlite3_finalize(pCsr.pPragma);
    pCsr.pPragma = null;
    pCsr.iRowid = 0;
    var i: usize = 0;
    while (i < pCsr.azArg.len) : (i += 1) {
        sqlite3_free(pCsr.azArg[i]);
        pCsr.azArg[i] = null;
    }
}

fn pragmaVtabClose(cur: ?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *PragmaVtabCursor = @ptrCast(@alignCast(cur.?));
    pragmaVtabCursorClear(pCsr);
    sqlite3_free(pCsr);
    return SQLITE_OK;
}

fn pragmaVtabNext(pVtabCursor: ?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *PragmaVtabCursor = @ptrCast(@alignCast(pVtabCursor.?));
    var rc: c_int = SQLITE_OK;
    pCsr.iRowid += 1;
    if (SQLITE_ROW != sqlite3_step(pCsr.pPragma)) {
        rc = sqlite3_finalize(pCsr.pPragma);
        pCsr.pPragma = null;
        pragmaVtabCursorClear(pCsr);
    }
    return rc;
}

fn pragmaVtabFilter(
    pVtabCursor: ?*sqlite3_vtab_cursor,
    idxNum: c_int,
    idxStr: ?[*:0]const u8,
    argc: c_int,
    argv: ?*?*anyopaque,
) callconv(.c) c_int {
    _ = idxNum;
    _ = idxStr;
    const pCsr: *PragmaVtabCursor = @ptrCast(@alignCast(pVtabCursor.?));
    const pTab: *PragmaVtab = @ptrCast(@alignCast(pVtabCursor.?.pVtab.?));
    var acc: [64]u8 = undefined;
    pragmaVtabCursorClear(pCsr);
    var jj: usize = if ((pTab.pName.?.mPragFlg & PragFlg_Result1) != 0) 0 else 1;
    const av: [*]?*anyopaque = @ptrCast(argv.?);
    var i: c_int = 0;
    while (i < argc) : ({
        i += 1;
        jj += 1;
    }) {
        const zText = sqlite3_value_text(av[@intCast(i)]);
        if (zText != null) {
            pCsr.azArg[jj] = sqlite3_mprintf("%s", zText);
            if (pCsr.azArg[jj] == null) return SQLITE_NOMEM;
        }
    }
    const aLimit = fieldPtr(pTab.db, sqlite3_aLimit);
    const sqlLimit = rd(c_int, aLimit, SQLITE_LIMIT_SQL_LENGTH * @sizeOf(c_int));
    sqlite3StrAccumInit(@ptrCast(&acc), null, null, 0, sqlLimit);
    sqlite3_str_appendall(@ptrCast(&acc), "PRAGMA ");
    if (pCsr.azArg[1] != null) {
        sqlite3_str_appendf(@ptrCast(&acc), "%Q.", pCsr.azArg[1]);
    }
    sqlite3_str_appendall(@ptrCast(&acc), pTab.pName.?.zName);
    if (pCsr.azArg[0] != null) {
        sqlite3_str_appendf(@ptrCast(&acc), "=%Q", pCsr.azArg[0]);
    }
    const zSql = sqlite3StrAccumFinish(@ptrCast(&acc));
    if (zSql == null) return SQLITE_NOMEM;
    const rc = sqlite3_prepare_v2(pTab.db, @ptrCast(zSql), -1, &pCsr.pPragma, null);
    sqlite3_free(zSql);
    if (rc != SQLITE_OK) {
        pTab.base.zErrMsg = sqlite3_mprintf("%s", sqlite3_errmsg(pTab.db));
        return rc;
    }
    return pragmaVtabNext(pVtabCursor);
}

fn pragmaVtabEof(pVtabCursor: ?*sqlite3_vtab_cursor) callconv(.c) c_int {
    const pCsr: *PragmaVtabCursor = @ptrCast(@alignCast(pVtabCursor.?));
    return @intFromBool(pCsr.pPragma == null);
}

fn pragmaVtabColumn(pVtabCursor: ?*sqlite3_vtab_cursor, ctx: ?*anyopaque, i: c_int) callconv(.c) c_int {
    const pCsr: *PragmaVtabCursor = @ptrCast(@alignCast(pVtabCursor.?));
    const pTab: *PragmaVtab = @ptrCast(@alignCast(pVtabCursor.?.pVtab.?));
    if (i < pTab.iHidden) {
        sqlite3_result_value(ctx, sqlite3_column_value(pCsr.pPragma, i));
    } else {
        sqlite3_result_text(ctx, @ptrCast(pCsr.azArg[@intCast(i - pTab.iHidden)]), -1, @ptrCast(SQLITE_TRANSIENT));
    }
    return SQLITE_OK;
}

fn pragmaVtabRowid(pVtabCursor: ?*sqlite3_vtab_cursor, p: *i64) callconv(.c) c_int {
    const pCsr: *PragmaVtabCursor = @ptrCast(@alignCast(pVtabCursor.?));
    p.* = pCsr.iRowid;
    return SQLITE_OK;
}

const sqlite3_module = extern struct {
    iVersion: c_int,
    xCreate: ?*const anyopaque,
    xConnect: ?*const anyopaque,
    xBestIndex: ?*const anyopaque,
    xDisconnect: ?*const anyopaque,
    xDestroy: ?*const anyopaque,
    xOpen: ?*const anyopaque,
    xClose: ?*const anyopaque,
    xFilter: ?*const anyopaque,
    xNext: ?*const anyopaque,
    xEof: ?*const anyopaque,
    xColumn: ?*const anyopaque,
    xRowid: ?*const anyopaque,
    xUpdate: ?*const anyopaque,
    xBegin: ?*const anyopaque,
    xSync: ?*const anyopaque,
    xCommit: ?*const anyopaque,
    xRollback: ?*const anyopaque,
    xFindFunction: ?*const anyopaque,
    xRename: ?*const anyopaque,
    xSavepoint: ?*const anyopaque,
    xRelease: ?*const anyopaque,
    xRollbackTo: ?*const anyopaque,
    xShadowName: ?*const anyopaque,
    xIntegrity: ?*const anyopaque,
};

const pragmaVtabModule = sqlite3_module{
    .iVersion = 0,
    .xCreate = null,
    .xConnect = @ptrCast(&pragmaVtabConnect),
    .xBestIndex = @ptrCast(&pragmaVtabBestIndex),
    .xDisconnect = @ptrCast(&pragmaVtabDisconnect),
    .xDestroy = null,
    .xOpen = @ptrCast(&pragmaVtabOpen),
    .xClose = @ptrCast(&pragmaVtabClose),
    .xFilter = @ptrCast(&pragmaVtabFilter),
    .xNext = @ptrCast(&pragmaVtabNext),
    .xEof = @ptrCast(&pragmaVtabEof),
    .xColumn = @ptrCast(&pragmaVtabColumn),
    .xRowid = @ptrCast(&pragmaVtabRowid),
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

export fn sqlite3PragmaVtabRegister(db: ?*anyopaque, zName: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const pName = pragmaLocate(@ptrCast(@as([*]const u8, @ptrCast(zName.?)) + 7)) orelse return null;
    if ((pName.mPragFlg & (PragFlg_Result0 | PragFlg_Result1)) == 0) return null;
    return sqlite3VtabCreateModule(db, zName, &pragmaVtabModule, @constCast(@ptrCast(pName)), null);
}
