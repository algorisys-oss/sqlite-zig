//! Zig port of SQLite's src/main.c — the library/connection control surface.
//!
//! This is the programmer-interface module: library init/shutdown, global and
//! per-connection configuration, open/close, error reporting, busy/progress
//! handlers, function/collation registration, trace/profile/commit/rollback/
//! update/wal/autovacuum hooks, interrupt, limits, URI parsing, filename
//! helpers, file-control, and the (non-UNTESTABLE) sqlite3_test_control.
//!
//! Every non-static symbol of main.c is exported here with the same C ABI.
//! All internal-struct field reads/writes go through probe-verified offsets
//! (config-invariant across the production and --dev testfixture builds unless
//! noted). See the orchestrator report for the full new-offset list.
//!
//! Config assumptions (true in both this project's builds — see build.zig):
//!   * SQLITE_THREADSAFE=1, SQLITE_ENABLE_PREUPDATE_HOOK on, MEMSYS5 on.
//!   * SQLITE_ENABLE_API_ARMOR        OFF → armor guards omitted.
//!   * SQLITE_OMIT_WSD                OFF → sqlite3GlobalConfig == sqlite3Config.
//!   * SQLITE_OMIT_DEPRECATED         OFF → trace/profile/global_recover present.
//!   * SQLITE_OMIT_UTF16              OFF → *16 family present.
//!   * SQLITE_OMIT_WAL                OFF → wal hooks/checkpoint present.
//!   * SQLITE_OMIT_TRACE             OFF.
//!   * SQLITE_UNTESTABLE             OFF → full sqlite3_test_control body.
//!   * SQLITE_ENABLE_SNAPSHOT        OFF → snapshot funcs omitted.
//!   * SQLITE_ENABLE_SETLK_TIMEOUT   OFF → setlk_timeout is a near no-op.
//!   * SQLITE_ENABLE_SQLLOG          OFF.
//!   * SQLITE_ENABLE_MEMSYS3         OFF, MEMSYS5 ON → CONFIG_HEAP present.
//!   * SQLITE_TEMP_STORE == 1.
//!   * Little-endian x86-64.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

const VaList = std.builtin.VaList;

// ═══════════════════════════════════════════════════════════════════════════
// Result codes (sqlite3.h)
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_PERM: c_int = 3;
const SQLITE_BUSY: c_int = 5;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_READONLY: c_int = 8;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_NOTFOUND: c_int = 12;
const SQLITE_CANTOPEN: c_int = 14;
const SQLITE_MISUSE: c_int = 21;
const SQLITE_RANGE: c_int = 25;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_ABORT_ROLLBACK: c_int = SQLITE_ABORT | (2 << 8); // 516
const SQLITE_ABORT: c_int = 4;
const SQLITE_IOERR_NOMEM: c_int = SQLITE_IOERR | (12 << 8);

// SQLITE_*_BKPT: in production these are plain constants; under SQLITE_DEBUG the
// NOMEM variant routes through sqlite3NomemError(). MISUSE/CORRUPT always route
// through the (always-defined) error helpers in this very module.
inline fn nomemBkpt() c_int {
    if (config.sqlite_debug) return sqlite3NomemError(0);
    return SQLITE_NOMEM;
}
inline fn misuseBkpt() c_int {
    return sqlite3MisuseError(0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Text encodings / function flags
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_UTF8: c_int = 1;
const SQLITE_UTF16LE: c_int = 2;
const SQLITE_UTF16BE: c_int = 3;
const SQLITE_UTF16: c_int = 4;
const SQLITE_ANY: c_int = 5;
const SQLITE_UTF16_ALIGNED: c_int = 8;
const SQLITE_UTF16NATIVE: c_int = SQLITE_UTF16LE; // little-endian

const SQLITE_DETERMINISTIC: c_int = 0x000000800;
const SQLITE_DIRECTONLY: c_int = 0x000080000;
const SQLITE_SUBTYPE: c_int = 0x000100000;
const SQLITE_INNOCUOUS: c_int = 0x000200000;
const SQLITE_RESULT_SUBTYPE: c_int = 0x001000000;
const SQLITE_SELFORDER1: c_int = 0x002000000;

const SQLITE_FUNC_ENCMASK: u32 = 0x0003;
const SQLITE_FUNC_UNSAFE: c_int = 0x00200000;

const SQLITE_MAX_FUNCTION_ARG: c_int = 1000;

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3.flags bits (sqliteInt.h). HI(x) == (u64)x << 32.
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_WriteSchema: u64 = 0x00000001;
const SQLITE_LegacyFileFmt: u64 = 0x00000002;
const SQLITE_CkptFullFSync: u64 = 0x00000010;
const SQLITE_CacheSpill: u64 = 0x00000020;
const SQLITE_ShortColNames: u64 = 0x00000040;
const SQLITE_TrustedSchema: u64 = 0x00000080;
const SQLITE_StmtScanStatus: u64 = 0x00000400;
const SQLITE_NoCkptOnClose: u64 = 0x00000800;
const SQLITE_ReverseOrder: u64 = 0x00001000;
const SQLITE_RecTriggers: u64 = 0x00002000;
const SQLITE_ForeignKeys: u64 = 0x00004000;
const SQLITE_AutoIndex: u64 = 0x00008000;
const SQLITE_LoadExtension: u64 = 0x00010000;
const SQLITE_EnableTrigger: u64 = 0x00040000;
const SQLITE_DeferFKs: u64 = 0x00080000;
const SQLITE_CellSizeCk: u64 = 0x00200000;
const SQLITE_Fts3Tokenizer: u64 = 0x00400000;
const SQLITE_EnableQPSG: u64 = 0x00800000;
const SQLITE_TriggerEQP: u64 = 0x01000000;
const SQLITE_ResetDatabase: u64 = 0x02000000;
const SQLITE_LegacyAlter: u64 = 0x04000000;
const SQLITE_NoSchemaError: u64 = 0x08000000;
const SQLITE_Defensive: u64 = 0x10000000;
const SQLITE_DqsDDL: u64 = 0x20000000;
const SQLITE_DqsDML: u64 = 0x40000000;
const SQLITE_EnableView: u64 = 0x80000000;
const SQLITE_CorruptRdOnly: u64 = @as(u64, 0x00002) << 32;
const SQLITE_FkNoAction: u64 = @as(u64, 0x00008) << 32;
const SQLITE_AttachCreate: u64 = @as(u64, 0x00010) << 32;
const SQLITE_AttachWrite: u64 = @as(u64, 0x00020) << 32;
const SQLITE_Comments: u64 = @as(u64, 0x00040) << 32;

const DBFLAG_SchemaChange: u32 = 0x0001;
const DBFLAG_InternalFunc: u32 = 0x0020;

const TF_Autoincrement: u32 = 0x00000008;
const COLFLAG_PRIMKEY: u16 = 0x0001;

// ═══════════════════════════════════════════════════════════════════════════
// OPEN flags
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_OPEN_READONLY: c_uint = 0x00000001;
const SQLITE_OPEN_READWRITE: c_uint = 0x00000002;
const SQLITE_OPEN_CREATE: c_uint = 0x00000004;
const SQLITE_OPEN_DELETEONCLOSE: c_uint = 0x00000008;
const SQLITE_OPEN_EXCLUSIVE: c_uint = 0x00000010;
const SQLITE_OPEN_URI: c_uint = 0x00000040;
const SQLITE_OPEN_MEMORY: c_uint = 0x00000080;
const SQLITE_OPEN_MAIN_DB: c_uint = 0x00000100;
const SQLITE_OPEN_TEMP_DB: c_uint = 0x00000200;
const SQLITE_OPEN_TRANSIENT_DB: c_uint = 0x00000400;
const SQLITE_OPEN_MAIN_JOURNAL: c_uint = 0x00000800;
const SQLITE_OPEN_TEMP_JOURNAL: c_uint = 0x00001000;
const SQLITE_OPEN_SUBJOURNAL: c_uint = 0x00002000;
const SQLITE_OPEN_SUPER_JOURNAL: c_uint = 0x00004000;
const SQLITE_OPEN_NOMUTEX: c_uint = 0x00008000;
const SQLITE_OPEN_FULLMUTEX: c_uint = 0x00010000;
const SQLITE_OPEN_SHAREDCACHE: c_uint = 0x00020000;
const SQLITE_OPEN_PRIVATECACHE: c_uint = 0x00040000;
const SQLITE_OPEN_WAL: c_uint = 0x00080000;
const SQLITE_OPEN_EXRESCODE: c_uint = 0x02000000;

// ═══════════════════════════════════════════════════════════════════════════
// LIMITs
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_LIMIT_LENGTH: c_int = 0;
const SQLITE_LIMIT_WORKER_THREADS: c_int = 11;
const SQLITE_N_LIMIT: c_int = 13;
const SQLITE_MIN_LENGTH: c_int = 0;

const aHardLimit = [_]c_int{
    1000000000, // LENGTH
    1000000000, // SQL_LENGTH
    2000, // COLUMN
    1000, // EXPR_DEPTH
    500, // COMPOUND_SELECT
    250000000, // VDBE_OP
    1000, // FUNCTION_ARG
    10, // ATTACHED
    50000, // LIKE_PATTERN_LENGTH
    32766, // VARIABLE_NUMBER
    1000, // TRIGGER_DEPTH
    8, // WORKER_THREADS
    2500, // PARSER_DEPTH
};

// ═══════════════════════════════════════════════════════════════════════════
// CONFIG / DBCONFIG opcodes
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_CONFIG_SINGLETHREAD: c_int = 1;
const SQLITE_CONFIG_MULTITHREAD: c_int = 2;
const SQLITE_CONFIG_SERIALIZED: c_int = 3;
const SQLITE_CONFIG_MALLOC: c_int = 4;
const SQLITE_CONFIG_GETMALLOC: c_int = 5;
const SQLITE_CONFIG_PAGECACHE: c_int = 7;
const SQLITE_CONFIG_HEAP: c_int = 8;
const SQLITE_CONFIG_MEMSTATUS: c_int = 9;
const SQLITE_CONFIG_MUTEX: c_int = 10;
const SQLITE_CONFIG_GETMUTEX: c_int = 11;
const SQLITE_CONFIG_LOOKASIDE: c_int = 13;
const SQLITE_CONFIG_PCACHE: c_int = 14;
const SQLITE_CONFIG_GETPCACHE: c_int = 15;
const SQLITE_CONFIG_LOG: c_int = 16;
const SQLITE_CONFIG_URI: c_int = 17;
const SQLITE_CONFIG_PCACHE2: c_int = 18;
const SQLITE_CONFIG_GETPCACHE2: c_int = 19;
const SQLITE_CONFIG_COVERING_INDEX_SCAN: c_int = 20;
const SQLITE_CONFIG_MMAP_SIZE: c_int = 22;
const SQLITE_CONFIG_PCACHE_HDRSZ: c_int = 24;
const SQLITE_CONFIG_PMASZ: c_int = 25;
const SQLITE_CONFIG_STMTJRNL_SPILL: c_int = 26;
const SQLITE_CONFIG_SMALL_MALLOC: c_int = 27;
const SQLITE_CONFIG_MEMDB_MAXSIZE: c_int = 29;
const SQLITE_CONFIG_ROWID_IN_VIEW: c_int = 30;

const SQLITE_DBCONFIG_MAINDBNAME: c_int = 1000;
const SQLITE_DBCONFIG_LOOKASIDE: c_int = 1001;
const SQLITE_DBCONFIG_ENABLE_FKEY: c_int = 1002;
const SQLITE_DBCONFIG_ENABLE_TRIGGER: c_int = 1003;
const SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER: c_int = 1004;
const SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION: c_int = 1005;
const SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE: c_int = 1006;
const SQLITE_DBCONFIG_ENABLE_QPSG: c_int = 1007;
const SQLITE_DBCONFIG_TRIGGER_EQP: c_int = 1008;
const SQLITE_DBCONFIG_RESET_DATABASE: c_int = 1009;
const SQLITE_DBCONFIG_DEFENSIVE: c_int = 1010;
const SQLITE_DBCONFIG_WRITABLE_SCHEMA: c_int = 1011;
const SQLITE_DBCONFIG_LEGACY_ALTER_TABLE: c_int = 1012;
const SQLITE_DBCONFIG_DQS_DML: c_int = 1013;
const SQLITE_DBCONFIG_DQS_DDL: c_int = 1014;
const SQLITE_DBCONFIG_ENABLE_VIEW: c_int = 1015;
const SQLITE_DBCONFIG_LEGACY_FILE_FORMAT: c_int = 1016;
const SQLITE_DBCONFIG_TRUSTED_SCHEMA: c_int = 1017;
const SQLITE_DBCONFIG_STMT_SCANSTATUS: c_int = 1018;
const SQLITE_DBCONFIG_REVERSE_SCANORDER: c_int = 1019;
const SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE: c_int = 1020;
const SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE: c_int = 1021;
const SQLITE_DBCONFIG_ENABLE_COMMENTS: c_int = 1022;
const SQLITE_DBCONFIG_FP_DIGITS: c_int = 1023;

// ═══════════════════════════════════════════════════════════════════════════
// Trace / checkpoint / txn / state / misc
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_TRACE_CLOSE: u32 = 0x08;
const SQLITE_TRACE_LEGACY: u32 = 0x40; // SQLITE_OMIT_DEPRECATED off
const SQLITE_TRACE_XPROFILE: u32 = 0x80;
const SQLITE_TRACE_NONLEGACY_MASK: u32 = 0x0f;

const SQLITE_CHECKPOINT_NOOP: c_int = -1;
const SQLITE_CHECKPOINT_PASSIVE: c_int = 0;
const SQLITE_CHECKPOINT_TRUNCATE: c_int = 3;

const SQLITE_TXN_NONE: c_int = 0;
const SQLITE_TXN_WRITE: c_int = 2;

const SQLITE_STATE_OPEN: u8 = 0x76;
const SQLITE_STATE_CLOSED: u8 = 0xce;
const SQLITE_STATE_SICK: u8 = 0xba;
const SQLITE_STATE_BUSY: u8 = 0x6d;
const SQLITE_STATE_ERROR: u8 = 0xd5;
const SQLITE_STATE_ZOMBIE: u8 = 0xa7;

const SQLITE_MAX_DB: c_int = 12; // MAX_ATTACHED(10)+2
const SQLITE_DEFAULT_SYNCHRONOUS: c_int = 2;
const PAGER_SYNCHRONOUS_OFF: c_int = 1;
const SQLITE_DEFAULT_WORKER_THREADS: c_int = 0;
const SQLITE_DEFAULT_WAL_AUTOCHECKPOINT: c_int = 1000;
const SQLITE_MAX_MMAP_SIZE: i64 = 2147418112;
const SQLITE_DEFAULT_MMAP_SIZE: i64 = 0;

// FCNTL op codes
const SQLITE_FCNTL_FILE_POINTER: c_int = 7;
const SQLITE_FCNTL_VFS_POINTER: c_int = 27;
const SQLITE_FCNTL_JOURNAL_POINTER: c_int = 28;
const SQLITE_FCNTL_DATA_VERSION: c_int = 35;
const SQLITE_FCNTL_RESERVE_BYTES: c_int = 38;
const SQLITE_FCNTL_RESET_CACHE: c_int = 42;

// TEST_CONTROL op codes
const TC_PRNG_SAVE: c_int = 5;
const TC_PRNG_RESTORE: c_int = 6;
const TC_FK_NO_ACTION: c_int = 7;
const TC_BITVEC_TEST: c_int = 8;
const TC_FAULT_INSTALL: c_int = 9;
const TC_BENIGN_MALLOC_HOOKS: c_int = 10;
const TC_PENDING_BYTE: c_int = 11;
const TC_ASSERT: c_int = 12;
const TC_ALWAYS: c_int = 13;
const TC_JSON_SELFCHECK: c_int = 14;
const TC_OPTIMIZATIONS: c_int = 15;
const TC_GETOPT: c_int = 16;
const TC_INTERNAL_FUNCTIONS: c_int = 17;
const TC_LOCALTIME_FAULT: c_int = 18;
const TC_ONCE_RESET_THRESHOLD: c_int = 19;
const TC_NEVER_CORRUPT: c_int = 20;
const TC_BYTEORDER: c_int = 22;
const TC_ISINIT: c_int = 23;
const TC_SORTER_MMAP: c_int = 24;
const TC_VDBE_COVERAGE: c_int = 21;
const TC_IMPOSTER: c_int = 25;
const TC_RESULT_INTREAL: c_int = 27;
const TC_PRNG_SEED: c_int = 28;
const TC_EXTRA_SCHEMA_CHECKS: c_int = 29;
const TC_SEEK_COUNT: c_int = 30;
const TC_TRACEFLAGS: c_int = 31;
const TC_LOGEST: c_int = 33;
const TC_ATOF: c_int = 34;

// ═══════════════════════════════════════════════════════════════════════════
// Mutex ids
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_MUTEX_RECURSIVE: c_int = 1;
const SQLITE_MUTEX_STATIC_MAIN: c_int = 2;

// ═══════════════════════════════════════════════════════════════════════════
// Version strings (sqlite3.h)
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_THREADSAFE_VAL: c_int = 1;

// ─── raw-memory helpers (idiom shared across ports) ─────────────────────────
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, o: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + o);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, o: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + o);
    q.* = v;
}
inline fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

// ═══════════════════════════════════════════════════════════════════════════
// Ground-truth struct offsets (config-invariant unless noted). Reuse c_layout
// where present, else the probe-verified fallback (prod==tf for all of these).
// ═══════════════════════════════════════════════════════════════════════════
// sqlite3 connection
const O_pVfs = off("sqlite3_pVfs", 0);
const O_pVdbe = off("sqlite3_pVdbe", 8);
const O_mutex = off("sqlite3_mutex", 24);
const O_aDb = off("sqlite3_aDb", 32);
const O_nDb = off("sqlite3_nDb", 40);
const O_mDbFlags = off("sqlite3_mDbFlags", 44);
const O_flags = off("sqlite3_flags", 48);
const O_lastRowid = off("sqlite3_lastRowid", 56);
const O_szMmap = off("sqlite3_szMmap", 64);
const O_openFlags = off("sqlite3_openFlags", 76);
const O_errCode = off("sqlite3_errCode", 80);
const O_errByteOffset = off("sqlite3_errByteOffset", 84);
const O_errMask = off("sqlite3_errMask", 88);
const O_iSysErrno = off("sqlite3_iSysErrno", 92);
const O_dbOptFlags = off("sqlite3_dbOptFlags", 96);
const O_enc = off("sqlite3_enc", 100);
const O_autoCommit = off("sqlite3_autoCommit", 101);
const O_temp_store = off("sqlite3_temp_store", 102);
const O_mallocFailed = off("sqlite3_mallocFailed", 103);
const O_dfltLockMode = off("sqlite3_dfltLockMode", 105);
const O_nextAutovac = off("sqlite3_nextAutovac", 106);
const O_isTransactionSavepoint = off("sqlite3_isTransactionSavepoint", 109);
const O_mTrace = off("sqlite3_mTrace", 110);
const O_nFpDigit = off("sqlite3_nFpDigit", 114);
const O_nextPagesize = off("sqlite3_nextPagesize", 116);
const O_nMaxSorterMmap = off("sqlite3_nMaxSorterMmap", 188);
const O_init = off("sqlite3_init", 192);
const O_init_newTnum = off("sqlite3_init_newTnum", 192);
const O_init_iDb = off("sqlite3_init_iDb", 196);
const O_init_busy = off("sqlite3_initBusy", 197);
const O_init_bitbyte = off("sqlite3_init_bitbyte", 198); // orphanTrigger:1,imposterTable:2
const O_init_azInit = off("sqlite3_init_azInit", 200);
const O_nVdbeActive = off("sqlite3_nVdbeActive", 208);
const O_trace = off("sqlite3_trace", 240);
const O_pTraceArg = off("sqlite3_pTraceArg", 248);
const O_xProfile = off("sqlite3_xProfile", 256);
const O_pProfileArg = off("sqlite3_pProfileArg", 264);
const O_pCommitArg = off("sqlite3_pCommitArg", 272);
const O_xCommitCallback = off("sqlite3_xCommitCallback", 280);
const O_pRollbackArg = off("sqlite3_pRollbackArg", 288);
const O_xRollbackCallback = off("sqlite3_xRollbackCallback", 296);
const O_pUpdateArg = off("sqlite3_pUpdateArg", 304);
const O_xUpdateCallback = off("sqlite3_xUpdateCallback", 312);
const O_pAutovacPagesArg = off("sqlite3_pAutovacPagesArg", 320);
const O_xAutovacDestr = off("sqlite3_xAutovacDestr", 328);
const O_xAutovacPages = off("sqlite3_xAutovacPages", 336);
const O_pPreUpdateArg = off("sqlite3_pPreUpdateArg", 352);
const O_xPreUpdateCallback = off("sqlite3_xPreUpdateCallback", 360);
const O_xWalCallback = off("sqlite3_xWalCallback", 376);
const O_pWalArg = off("sqlite3_pWalArg", 384);
const O_xCollNeeded = off("sqlite3_xCollNeeded", 392);
const O_xCollNeeded16 = off("sqlite3_xCollNeeded16", 400);
const O_pCollNeededArg = off("sqlite3_pCollNeededArg", 408);
const O_pErr = off("sqlite3_pErr", 416);
const O_u1 = off("sqlite3_u1", 424); // isInterrupted (volatile int)
const O_lookaside = off("sqlite3_lookaside", 432);
const O_aModule = off("sqlite3_aModule", 568);
const O_aFunc = off("sqlite3_aFunc", 616);
const O_aCollSeq = off("sqlite3_aCollSeq", 640);
const O_busyHandler = off("sqlite3_busyHandler", 664);
const O_aDbStatic = off("sqlite3_aDbStatic", 688);
const O_pSavepoint = off("sqlite3_pSavepoint", 752);
const O_busyTimeout = off("sqlite3_busyTimeout", 764);
const O_nSavepoint = off("sqlite3_nSavepoint", 768);
const O_nStatement = off("sqlite3_nStatement", 772);
const O_nDeferredCons = off("sqlite3_nDeferredCons", 776);
const O_nDeferredImmCons = off("sqlite3_nDeferredImmCons", 784);
const O_pDbData = off("sqlite3_pDbData", 800);

// BusyHandler
const BH_xBusyHandler = off("BusyHandler_xBusyHandler", 0);
const BH_pBusyArg = off("BusyHandler_pBusyArg", 8);
const BH_nBusy = off("BusyHandler_nBusy", 16);

// CollSeq
const CS_enc = off("CollSeq_enc", 8);
const CS_pUser = off("CollSeq_pUser", 16);
const CS_xCmp = off("CollSeq_xCmp", 24);
const CS_xDel = off("CollSeq_xDel", 32);
const sizeof_CollSeq = off("sizeof_CollSeq", 40);

// FuncDef
const FD_nArg = off("FuncDef_nArg", 0);
const FD_funcFlags = off("FuncDef_funcFlags", 4);
const FD_pUserData = off("FuncDef_pUserData", 8);
const FD_pNext = off("FuncDef_pNext", 16);
const FD_xSFunc = off("FuncDef_xSFunc", 24);
const FD_xFinalize = off("FuncDef_xFinalize", 32);
const FD_xValue = off("FuncDef_xValue", 40);
const FD_xInverse = off("FuncDef_xInverse", 48);
const FD_u = off("FuncDef_u", 64); // u.pDestructor

// FuncDestructor
const FDest_nRef = off("FuncDestructor_nRef", 0);
const FDest_xDestroy = off("FuncDestructor_xDestroy", 8);
const FDest_pUserData = off("FuncDestructor_pUserData", 16);

// Db
const Db_zDbSName = off("Db_zDbSName", 0);
const Db_pBt = off("Db_pBt", 8);
const Db_safety_level = off("Db_safety_level", 16);
const Db_pSchema = off("Db_pSchema", 24);
const sizeof_Db = off("sizeof_Db", 32);

// Savepoint
const SP_pNext = off("Savepoint_pNext", 24);

// DbClientData
const DCD_pNext = off("DbClientData_pNext", 0);
const DCD_pData = off("DbClientData_pData", 8);
const DCD_xDestructor = off("DbClientData_xDestructor", 16);
const DCD_zName = off("DbClientData_zName", 24);

// Table / Column / Schema / Module
const Tab_aCol = off("Table_aCol", 8);
const Tab_tabFlags = off("Table_tabFlags", 48);
const Tab_iPKey = off("Table_iPKey", 52);
const Tab_eTabType = off("Table_eTabType", 63);
const Col_colFlags = off("Column_colFlags", 14);
const sizeof_Column = off("sizeof_Column", 16);
const Col_notNull_byte = 8; // notNull:4 low nibble of byte 8
const Schema_schema_cookie = off("Schema_schema_cookie", 0);
const Schema_tblHash = off("Schema_tblHash", 8);
const Module_pEpoTab = off("Module_pEpoTab", 40);
const TABTYP_VTAB: u8 = 1;

// Hash / HashElem (mirror; for cross-walks in close)
const Hash_first = off("Hash_first", 8);
const HashElem_next = off("HashElem_next", 0);
const HashElem_data = off("HashElem_data", 16);

// Sqlite3Config fields
const C_bMemstat = off("Sqlite3Config_bMemstat", 0);
const C_bCoreMutex = off("Sqlite3Config_bCoreMutex", 4);
const C_bFullMutex = off("Sqlite3Config_bFullMutex", 5);
const C_bOpenUri = off("Sqlite3Config_bOpenUri", 6);
const C_bUseCis = off("Sqlite3Config_bUseCis", 7);
const C_bSmallMalloc = off("Sqlite3Config_bSmallMalloc", 8);
const C_bExtraSchemaChecks = off("Sqlite3Config_bExtraSchemaChecks", 9);
const C_neverCorrupt = off("Sqlite3Config_neverCorrupt", 16);
const C_szLookaside = off("Sqlite3Config_szLookaside", 20);
const C_nLookaside = off("Sqlite3Config_nLookaside", 24);
const C_nStmtSpill = off("Sqlite3Config_nStmtSpill", 28);
const C_m = off("Sqlite3Config_m", 32); // sqlite3_mem_methods (sizeof 64)
const C_mutex = off("Sqlite3Config_mutex", 96); // sqlite3_mutex_methods (sizeof 72)
const C_pcache2 = off("Sqlite3Config_pcache2", 168); // sqlite3_pcache_methods2 (sizeof 104)
const C_pHeap = off("Sqlite3Config_pHeap", 272);
const C_nHeap = off("Sqlite3Config_nHeap", 280);
const C_mnReq = off("Sqlite3Config_mnReq", 284);
const C_szMmap = off("Sqlite3Config_szMmap", 296);
const C_mxMmap = off("Sqlite3Config_mxMmap", 304);
const C_pPage = off("Sqlite3Config_pPage", 312);
const C_szPage = off("Sqlite3Config_szPage", 320);
const C_nPage = off("Sqlite3Config_nPage", 324);
const C_sharedCacheEnabled = off("Sqlite3Config_sharedCacheEnabled", 332);
const C_szPma = off("Sqlite3Config_szPma", 336);
const C_isInit = off("Sqlite3Config_isInit", 340);
const C_inProgress = off("Sqlite3Config_inProgress", 344);
const C_isMutexInit = off("Sqlite3Config_isMutexInit", 348);
const C_isMallocInit = off("Sqlite3Config_isMallocInit", 352);
const C_isPCacheInit = off("Sqlite3Config_isPCacheInit", 356);
const C_nRefInitMutex = off("Sqlite3Config_nRefInitMutex", 360);
const C_pInitMutex = off("Sqlite3Config_pInitMutex", 368);
const C_xLog = off("Sqlite3Config_xLog", 376);
const C_pLogArg = off("Sqlite3Config_pLogArg", 384);
const C_mxMemdbSize = off("Sqlite3Config_mxMemdbSize", 392);
const C_xTestCallback = off("Sqlite3Config_xTestCallback", 400);
const C_bLocaltimeFault = off("Sqlite3Config_bLocaltimeFault", 408);
const C_xAltLocaltime = off("Sqlite3Config_xAltLocaltime", 416);
const C_iOnceResetThreshold = off("Sqlite3Config_iOnceResetThreshold", 424);
const C_iPrngSeed = off("Sqlite3Config_iPrngSeed", 432);

// ═══════════════════════════════════════════════════════════════════════════
// Mutable C globals (extern var — see PROGRESS note on ReleaseSafe CSE).
// SQLITE_OMIT_WSD off ⇒ sqlite3GlobalConfig macro → the real `sqlite3Config`.
// ═══════════════════════════════════════════════════════════════════════════
extern var sqlite3Config: u8;
extern var sqlite3PendingByte: c_int;
extern var sqlite3TreeTrace: u32;
extern var sqlite3WhereTrace: u32;
extern var sqlite3BuiltinFunctions: u8; // FuncDefHash; zeroed at init
extern const sqlite3StrBINARY: u8; // char[]; address is the data
extern const sqlite3CtypeMap: u8; // const u8[256]; address is the data

// sqlite3Isxdigit is a macro: sqlite3CtypeMap[(u8)x] & 0x08  (SQLITE_ASCII on).
inline fn sqlite3Isxdigit(c: u8) c_int {
    const map: [*]const u8 = @ptrCast(&sqlite3CtypeMap);
    return map[c] & 0x08;
}
// sqlite3ConnectionClosed is a no-op macro (SQLITE_ENABLE_UNLOCK_NOTIFY off).
inline fn sqlite3ConnectionClosed(db: Ptr) void {
    _ = db;
}

// These globals are DEFINED by main.c (non-static) — own them here.
export const sqlite3_version: [7]u8 = "3.54.0\x00".*;
export var sqlite3_temp_directory: ?[*:0]u8 = null;
export var sqlite3_data_directory: ?[*:0]u8 = null;

inline fn cfg() [*]u8 {
    return @ptrCast(&sqlite3Config);
}
inline fn cfgRd(comptime T: type, o: usize) T {
    const q: *align(1) const T = @ptrCast(cfg() + o);
    return q.*;
}
inline fn cfgWr(comptime T: type, o: usize, v: T) void {
    const q: *align(1) T = @ptrCast(cfg() + o);
    q.* = v;
}

// ═══════════════════════════════════════════════════════════════════════════
// extern C ABI functions (resolved against not-yet-ported C, or other ports)
// ═══════════════════════════════════════════════════════════════════════════
const Ptr = ?*anyopaque;

// memory / strings / printf
extern fn sqlite3_malloc64(n: u64) Ptr;
extern fn sqlite3_free(p: Ptr) void;
extern fn sqlite3Malloc(n: u64) Ptr;
extern fn sqlite3MallocZero(n: u64) Ptr;
extern fn sqlite3MallocSize(p: Ptr) u64;
extern fn sqlite3DbFree(db: Ptr, p: Ptr) void;
extern fn sqlite3MPrintf(db: Ptr, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, buf: [*]u8, fmt: [*:0]const u8, ...) [*:0]u8;
extern fn sqlite3_log(iErrCode: c_int, fmt: [*:0]const u8, ...) void;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;
extern fn strlen(s: [*:0]const u8) usize;
extern fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn strncmp(a: [*:0]const u8, b: [*:0]const u8, n: usize) c_int;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, v: c_int, n: usize) ?*anyopaque;

// errors / api
extern fn sqlite3Error(db: Ptr, code: c_int) void;
extern fn sqlite3ErrorWithMsg(db: Ptr, code: c_int, fmt: ?[*:0]const u8, ...) void;
extern fn sqlite3ApiExit(db: Ptr, rc: c_int) c_int;
extern fn sqlite3OomFault(db: Ptr) Ptr;
extern fn sqlite3OomClear(db: Ptr) void;
extern fn sqlite3FaultSim(iTest: c_int) c_int;
extern fn sqlite3GetBoolean(z: ?[*:0]const u8, dflt: u8) c_int;
extern fn sqlite3DecOrHexToI64(z: ?[*:0]const u8, pOut: *i64) c_int;
extern fn sqlite3IsIdChar(c: u8) c_int;
extern fn sqlite3HexToInt(h: c_int) c_int;

// init / shutdown subsystems
extern fn sqlite3MutexInit() c_int;
extern fn sqlite3MutexEnd() c_int;
extern fn sqlite3MallocInit() c_int;
extern fn sqlite3MallocEnd() void;
extern fn sqlite3PcacheInitialize() c_int;
extern fn sqlite3PcacheShutdown() void;
extern fn sqlite3OsInit() c_int;
extern fn sqlite3MemdbInit() c_int;
extern fn sqlite3PCacheBufferSetup(p: Ptr, sz: c_int, n: c_int) void;
extern fn sqlite3RegisterBuiltinFunctions() void;
extern fn sqlite3PCacheSetDefault() void;
extern fn sqlite3MemSetDefault() void;
extern fn sqlite3MemGetMemsys5() Ptr; // returns sqlite3_mem_methods*
extern fn sqlite3HeaderSizeBtree() c_int;
extern fn sqlite3HeaderSizePcache() c_int;
extern fn sqlite3HeaderSizePcache1() c_int;
extern fn sqlite3_os_end() c_int;
extern fn sqlite3_reset_auto_extension() void;
extern fn sqlite3IsNaN(x: f64) c_int;
extern fn sqlite3MemoryBarrier() void;

// mutex
extern fn sqlite3_mutex_enter(p: Ptr) void;
extern fn sqlite3_mutex_leave(p: Ptr) void;
extern fn sqlite3_mutex_free(p: Ptr) void;
extern fn sqlite3MutexAlloc(id: c_int) Ptr;
extern fn sqlite3MutexWarnOnContention(p: Ptr) void;

// btree / pager
extern fn sqlite3BtreeEnter(p: Ptr) void;
extern fn sqlite3BtreeLeave(p: Ptr) void;
extern fn sqlite3BtreeEnterAll(db: Ptr) void;
extern fn sqlite3BtreeLeaveAll(db: Ptr) void;
extern fn sqlite3BtreePager(p: Ptr) Ptr;
extern fn sqlite3BtreeTxnState(p: Ptr) c_int;
extern fn sqlite3BtreeClose(p: Ptr) c_int;
extern fn sqlite3BtreeOpen(pVfs: Ptr, zFilename: ?[*:0]const u8, db: Ptr, ppBtree: *Ptr, flags: c_int, vfsFlags: c_int) c_int;
extern fn sqlite3BtreeBeginTrans(p: Ptr, wrflag: c_int, pSchemaVersion: ?*c_int) c_int;
extern fn sqlite3BtreeCommit(p: Ptr) c_int;
extern fn sqlite3BtreeRollback(p: Ptr, tripCode: c_int, writeOnly: c_int) c_int;
extern fn sqlite3BtreeIsInBackup(p: Ptr) c_int;
extern fn sqlite3BtreeCheckpoint(p: Ptr, eMode: c_int, pnLog: ?*c_int, pnCkpt: ?*c_int) c_int;
extern fn sqlite3BtreeGetFilename(p: Ptr) ?[*:0]const u8;
extern fn sqlite3BtreeIsReadonly(p: Ptr) c_int;
extern fn sqlite3BtreeGetRequestedReserve(p: Ptr) c_int;
extern fn sqlite3BtreeSetPageSize(p: Ptr, pageSize: c_int, nReserve: c_int, fix: c_int) c_int;
extern fn sqlite3BtreeClearCache(p: Ptr) void;
extern fn sqlite3PagerShrink(p: Ptr) void;
extern fn sqlite3PagerFlush(p: Ptr) c_int;
extern fn sqlite3PagerFile(p: Ptr) Ptr;
extern fn sqlite3PagerVfs(p: Ptr) Ptr;
extern fn sqlite3PagerJrnlFile(p: Ptr) Ptr;
extern fn sqlite3PagerDataVersion(p: Ptr) c_uint;
extern fn sqlite3OsFileControl(fd: Ptr, op: c_int, pArg: Ptr) c_int;
extern fn sqlite3OsSleep(pVfs: Ptr, microseconds: c_int) c_int;

// vfs / uri
extern fn sqlite3_vfs_find(zVfs: ?[*:0]const u8) Ptr;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;

// schema / functions / collation
extern fn sqlite3FindDbName(db: Ptr, zName: ?[*:0]const u8) c_int;
extern fn sqlite3FindFunction(db: Ptr, zName: ?[*:0]const u8, nArg: c_int, enc: u8, createFlag: u8) Ptr;
extern fn sqlite3FindCollSeq(db: Ptr, enc: u8, zName: ?[*:0]const u8, create: c_int) Ptr;
extern fn sqlite3HashFind(h: Ptr, key: ?[*:0]const u8) Ptr;
extern fn sqlite3HashInit(h: Ptr) void;
extern fn sqlite3HashClear(h: Ptr) void;
extern fn sqlite3ExpirePreparedStatements(db: Ptr, iCode: c_int) void;
extern fn sqlite3SetTextEncoding(db: Ptr, enc: u8) void;
extern fn sqlite3SchemaGet(db: Ptr, pBt: Ptr) Ptr;
extern fn sqlite3SchemaClear(p: Ptr) void;
extern fn sqlite3RegisterPerConnectionBuiltinFunctions(db: Ptr) void;
extern fn sqlite3AutoLoadExtensions(db: Ptr) void;
extern fn sqlite3CloseExtensions(db: Ptr) void;
extern fn sqlite3CollapseDatabaseArray(db: Ptr) void;
extern fn sqlite3ResetAllSchemasOfConnection(db: Ptr) void;
extern fn sqlite3Init(db: Ptr, pzErrMsg: *?[*:0]u8) c_int;
extern fn sqlite3FindTable(db: Ptr, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) Ptr;
extern fn sqlite3ColumnIndex(pTab: Ptr, zName: ?[*:0]const u8) c_int;
extern fn sqlite3IsRowid(z: ?[*:0]const u8) c_int;
extern fn sqlite3ColumnType(pCol: Ptr, zDflt: ?[*:0]const u8) ?[*:0]const u8;
extern fn sqlite3ColumnColl(pCol: Ptr) ?[*:0]const u8;

// vtab
extern fn sqlite3VtabDisconnect(db: Ptr, pTab: Ptr) void;
extern fn sqlite3VtabUnlockList(db: Ptr) void;
extern fn sqlite3VtabRollback(db: Ptr) c_int;
extern fn sqlite3VtabEponymousTableClear(db: Ptr, pMod: Ptr) void;
extern fn sqlite3VtabModuleUnref(db: Ptr, pMod: Ptr) void;

// value / utf
extern fn sqlite3ValueNew(db: Ptr) Ptr;
extern fn sqlite3ValueSetStr(v: Ptr, n: c_int, z: ?*const anyopaque, enc: u8, xDel: ?*const anyopaque) void;
extern fn sqlite3ValueText(v: Ptr, enc: u8) ?[*:0]const u8;
extern fn sqlite3ValueFree(v: Ptr) void;
extern fn sqlite3_value_text(v: Ptr) ?[*:0]const u8;
extern fn sqlite3_value_text16(v: Ptr) ?*const anyopaque;
extern fn sqlite3Utf16to8(db: Ptr, z: ?*const anyopaque, nByte: c_int, enc: u8) ?[*:0]u8;

// savepoint / benign / misc helpers
extern fn sqlite3BeginBenignMalloc() void;
extern fn sqlite3EndBenignMalloc() void;
extern fn sqlite3BenignMallocHooks(xBegin: Ptr, xEnd: Ptr) void;
extern fn sqlite3LookasideUsed(db: Ptr, pHighwater: ?*c_int) c_int;
extern fn sqlite3PrngSaveState() void;
extern fn sqlite3PrngRestoreState() void;
extern fn sqlite3_randomness(n: c_int, p: Ptr) void;
extern fn sqlite3ResultIntReal(pCtx: Ptr) void;
extern fn sqlite3_user_data(pCtx: Ptr) Ptr;
extern fn sqlite3_result_error(pCtx: Ptr, z: ?[*:0]const u8, n: c_int) void;

// LogEst / AtoF for test_control
extern fn sqlite3LogEstFromDouble(x: f64) i16;
extern fn sqlite3LogEstToInt(x: i16) u64;
extern fn sqlite3LogEst(x: u64) i16;
extern fn sqlite3AtoF(z: ?[*:0]const u8, pResult: *f64) c_int;
extern fn sqlite3AbsInt32(x: c_int) c_int;
extern fn sqlite3CompileOptions(pnOpt: *c_int) ?[*]const ?[*:0]const u8;

// bitvec test (UNTESTABLE off)
extern fn sqlite3BitvecBuiltinTest(sz: c_int, aProg: ?[*]c_int) c_int;

// public APIs implemented elsewhere that main.c calls

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3 connection field accessors
// ═══════════════════════════════════════════════════════════════════════════
inline fn dbMutex(db: Ptr) Ptr {
    return rd(Ptr, db, O_mutex);
}
inline fn dbNDb(db: Ptr) c_int {
    return rd(c_int, db, O_nDb);
}
inline fn dbFlags(db: Ptr) u64 {
    return rd(u64, db, O_flags);
}
inline fn dbSetFlags(db: Ptr, v: u64) void {
    wr(u64, db, O_flags, v);
}
inline fn dbMallocFailed(db: Ptr) bool {
    return base(db)[O_mallocFailed] != 0;
}
inline fn dbErrCode(db: Ptr) c_int {
    return rd(c_int, db, O_errCode);
}
inline fn dbErrMask(db: Ptr) c_int {
    return rd(c_int, db, O_errMask);
}
inline fn dbAtPtr(db: Ptr, i: c_int) [*]u8 {
    const aDb: [*]u8 = @ptrCast(rd(Ptr, db, O_aDb).?);
    return aDb + (@as(usize, @intCast(i)) * sizeof_Db);
}
inline fn dbAtPBt(db: Ptr, i: c_int) Ptr {
    const q: *align(1) const Ptr = @ptrCast(dbAtPtr(db, i) + Db_pBt);
    return q.*;
}
inline fn dbAtPSchema(db: Ptr, i: c_int) Ptr {
    const q: *align(1) const Ptr = @ptrCast(dbAtPtr(db, i) + Db_pSchema);
    return q.*;
}

// ═══════════════════════════════════════════════════════════════════════════
// Version
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_libversion() callconv(.c) ?[*:0]const u8 {
    return @ptrCast(&sqlite3_version);
}
const SQLITE_SOURCE_ID = "2026-06-24 14:17:52 395cbed103af08e3a4fafd9a3041205535e019d4aeb58b46c4a7e4f3bca545c9";
export fn sqlite3_sourceid() callconv(.c) ?[*:0]const u8 {
    return SQLITE_SOURCE_ID;
}
export fn sqlite3_libversion_number() callconv(.c) c_int {
    return SQLITE_VERSION_NUMBER;
}
const SQLITE_VERSION_NUMBER: c_int = 3054000;
export fn sqlite3_threadsafe() callconv(.c) c_int {
    return SQLITE_THREADSAFE_VAL;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_initialize / sqlite3_shutdown
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_initialize() callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;

    if (cfgRd(c_int, C_isInit) != 0) {
        sqlite3MemoryBarrier();
        return SQLITE_OK;
    }

    rc = sqlite3MutexInit();
    if (rc != 0) return rc;

    const pMainMtx = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
    sqlite3_mutex_enter(pMainMtx);
    cfgWr(c_int, C_isMutexInit, 1);
    if (cfgRd(c_int, C_isMallocInit) == 0) {
        rc = sqlite3MallocInit();
    }
    if (rc == SQLITE_OK) {
        cfgWr(c_int, C_isMallocInit, 1);
        if (cfgRd(Ptr, C_pInitMutex) == null) {
            cfgWr(Ptr, C_pInitMutex, sqlite3MutexAlloc(SQLITE_MUTEX_RECURSIVE));
            if (cfgRd(c_int, C_bCoreMutex) != 0 and cfgRd(Ptr, C_pInitMutex) == null) {
                rc = nomemBkpt();
            }
        }
    }
    if (rc == SQLITE_OK) {
        cfgWr(c_int, C_nRefInitMutex, cfgRd(c_int, C_nRefInitMutex) + 1);
    }
    sqlite3_mutex_leave(pMainMtx);

    if (rc != SQLITE_OK) return rc;

    sqlite3_mutex_enter(cfgRd(Ptr, C_pInitMutex));
    if (cfgRd(c_int, C_isInit) == 0 and cfgRd(c_int, C_inProgress) == 0) {
        cfgWr(c_int, C_inProgress, 1);
        // memset(&sqlite3BuiltinFunctions, 0, sizeof(...)); FuncDefHash == 23*8 bytes
        _ = memset(@ptrCast(&sqlite3BuiltinFunctions), 0, sizeof_FuncDefHash);
        sqlite3RegisterBuiltinFunctions();
        if (cfgRd(c_int, C_isPCacheInit) == 0) {
            rc = sqlite3PcacheInitialize();
        }
        if (rc == SQLITE_OK) {
            cfgWr(c_int, C_isPCacheInit, 1);
            rc = sqlite3OsInit();
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3MemdbInit();
        }
        if (rc == SQLITE_OK) {
            sqlite3PCacheBufferSetup(cfgRd(Ptr, C_pPage), cfgRd(c_int, C_szPage), cfgRd(c_int, C_nPage));
        }
        if (rc == SQLITE_OK) {
            sqlite3MemoryBarrier();
            cfgWr(c_int, C_isInit, 1);
        }
        cfgWr(c_int, C_inProgress, 0);
    }
    sqlite3_mutex_leave(cfgRd(Ptr, C_pInitMutex));

    sqlite3_mutex_enter(pMainMtx);
    cfgWr(c_int, C_nRefInitMutex, cfgRd(c_int, C_nRefInitMutex) - 1);
    if (cfgRd(c_int, C_nRefInitMutex) <= 0) {
        sqlite3_mutex_free(cfgRd(Ptr, C_pInitMutex));
        cfgWr(Ptr, C_pInitMutex, null);
    }
    sqlite3_mutex_leave(pMainMtx);

    if (config.sqlite_debug) {
        if (rc == SQLITE_OK) {
            const x: u64 = (@as(u64, 1) << 63) - 1;
            var y: f64 = undefined;
            _ = memcpy(@ptrCast(&y), @ptrCast(&x), 8);
            std.debug.assert(sqlite3IsNaN(y) != 0);
        }
    }
    return rc;
}
const sizeof_FuncDefHash: usize = 23 * 8; // FuncDef* a[23]

export fn sqlite3_shutdown() callconv(.c) c_int {
    if (cfgRd(c_int, C_isInit) != 0) {
        _ = sqlite3_os_end();
        sqlite3_reset_auto_extension();
        cfgWr(c_int, C_isInit, 0);
    }
    if (cfgRd(c_int, C_isPCacheInit) != 0) {
        sqlite3PcacheShutdown();
        cfgWr(c_int, C_isPCacheInit, 0);
    }
    if (cfgRd(c_int, C_isMallocInit) != 0) {
        sqlite3MallocEnd();
        cfgWr(c_int, C_isMallocInit, 0);
        sqlite3_data_directory = null;
        sqlite3_temp_directory = null;
    }
    if (cfgRd(c_int, C_isMutexInit) != 0) {
        _ = sqlite3MutexEnd();
        cfgWr(c_int, C_isMutexInit, 0);
    }
    return SQLITE_OK;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_config (variadic)
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_config(op: c_int, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var rc: c_int = SQLITE_OK;

    if (cfgRd(c_int, C_isInit) != 0) {
        // mAnytimeConfigOption = bit(LOG) | bit(PCACHE_HDRSZ)
        const mAnytime: u64 = (@as(u64, 1) << @intCast(SQLITE_CONFIG_LOG)) |
            (@as(u64, 1) << @intCast(SQLITE_CONFIG_PCACHE_HDRSZ));
        if (op < 0 or op > 63 or (mAnytime & (@as(u64, 1) << @intCast(op))) == 0) {
            return misuseBkpt();
        }
    }

    switch (op) {
        SQLITE_CONFIG_SINGLETHREAD => {
            cfgWr(u8, C_bCoreMutex, 0);
            cfgWr(u8, C_bFullMutex, 0);
        },
        SQLITE_CONFIG_MULTITHREAD => {
            cfgWr(u8, C_bCoreMutex, 1);
            cfgWr(u8, C_bFullMutex, 0);
        },
        SQLITE_CONFIG_SERIALIZED => {
            cfgWr(u8, C_bCoreMutex, 1);
            cfgWr(u8, C_bFullMutex, 1);
        },
        SQLITE_CONFIG_MUTEX => {
            const src = @cVaArg(&ap, Ptr);
            _ = memcpy(cfg() + C_mutex, src, sizeof_mutex_methods);
        },
        SQLITE_CONFIG_GETMUTEX => {
            const dst = @cVaArg(&ap, Ptr);
            _ = memcpy(dst, cfg() + C_mutex, sizeof_mutex_methods);
        },
        SQLITE_CONFIG_MALLOC => {
            const src = @cVaArg(&ap, Ptr);
            _ = memcpy(cfg() + C_m, src, sizeof_mem_methods);
        },
        SQLITE_CONFIG_GETMALLOC => {
            // if m.xMalloc==0 SetDefault
            const xMallocPtr: *align(1) const Ptr = @ptrCast(cfg() + C_m);
            if (xMallocPtr.* == null) sqlite3MemSetDefault();
            const dst = @cVaArg(&ap, Ptr);
            _ = memcpy(dst, cfg() + C_m, sizeof_mem_methods);
        },
        SQLITE_CONFIG_MEMSTATUS => {
            cfgWr(c_int, C_bMemstat, @cVaArg(&ap, c_int));
        },
        SQLITE_CONFIG_SMALL_MALLOC => {
            cfgWr(u8, C_bSmallMalloc, if (@cVaArg(&ap, c_int) != 0) 1 else 0);
        },
        SQLITE_CONFIG_PAGECACHE => {
            cfgWr(Ptr, C_pPage, @cVaArg(&ap, Ptr));
            cfgWr(c_int, C_szPage, @cVaArg(&ap, c_int));
            cfgWr(c_int, C_nPage, @cVaArg(&ap, c_int));
        },
        SQLITE_CONFIG_PCACHE_HDRSZ => {
            const p = @cVaArg(&ap, *c_int);
            p.* = sqlite3HeaderSizeBtree() + sqlite3HeaderSizePcache() + sqlite3HeaderSizePcache1();
        },
        SQLITE_CONFIG_PCACHE => {},
        SQLITE_CONFIG_GETPCACHE => {
            rc = SQLITE_ERROR;
        },
        SQLITE_CONFIG_PCACHE2 => {
            const src = @cVaArg(&ap, Ptr);
            _ = memcpy(cfg() + C_pcache2, src, sizeof_pcache_methods2);
        },
        SQLITE_CONFIG_GETPCACHE2 => {
            const xInitPtr: *align(1) const Ptr = @ptrCast(cfg() + C_pcache2);
            if (xInitPtr.* == null) sqlite3PCacheSetDefault();
            const dst = @cVaArg(&ap, Ptr);
            _ = memcpy(dst, cfg() + C_pcache2, sizeof_pcache_methods2);
        },
        SQLITE_CONFIG_HEAP => {
            // MEMSYS5 on, MEMSYS3 off
            cfgWr(Ptr, C_pHeap, @cVaArg(&ap, Ptr));
            cfgWr(c_int, C_nHeap, @cVaArg(&ap, c_int));
            cfgWr(c_int, C_mnReq, @cVaArg(&ap, c_int));
            if (cfgRd(c_int, C_mnReq) < 1) {
                cfgWr(c_int, C_mnReq, 1);
            } else if (cfgRd(c_int, C_mnReq) > (1 << 12)) {
                cfgWr(c_int, C_mnReq, 1 << 12);
            }
            if (cfgRd(Ptr, C_pHeap) == null) {
                _ = memset(cfg() + C_m, 0, sizeof_mem_methods);
            } else {
                const m5: Ptr = sqlite3MemGetMemsys5();
                _ = memcpy(cfg() + C_m, m5, sizeof_mem_methods);
            }
        },
        SQLITE_CONFIG_LOOKASIDE => {
            cfgWr(c_int, C_szLookaside, @cVaArg(&ap, c_int));
            cfgWr(c_int, C_nLookaside, @cVaArg(&ap, c_int));
        },
        SQLITE_CONFIG_LOG => {
            const xLog = @cVaArg(&ap, Ptr);
            const pLogArg = @cVaArg(&ap, Ptr);
            cfgWr(Ptr, C_xLog, xLog);
            cfgWr(Ptr, C_pLogArg, pLogArg);
        },
        SQLITE_CONFIG_URI => {
            cfgWr(u8, C_bOpenUri, @intCast(@cVaArg(&ap, c_int) & 0xff));
        },
        SQLITE_CONFIG_COVERING_INDEX_SCAN => {
            cfgWr(c_int, C_bUseCis, @cVaArg(&ap, c_int));
        },
        SQLITE_CONFIG_MMAP_SIZE => {
            var szMmap = @cVaArg(&ap, i64);
            var mxMmap = @cVaArg(&ap, i64);
            if (mxMmap < 0 or mxMmap > SQLITE_MAX_MMAP_SIZE) mxMmap = SQLITE_MAX_MMAP_SIZE;
            if (szMmap < 0) szMmap = SQLITE_DEFAULT_MMAP_SIZE;
            if (szMmap > mxMmap) szMmap = mxMmap;
            cfgWr(i64, C_mxMmap, mxMmap);
            cfgWr(i64, C_szMmap, szMmap);
        },
        SQLITE_CONFIG_PMASZ => {
            cfgWr(u32, C_szPma, @cVaArg(&ap, c_uint));
        },
        SQLITE_CONFIG_STMTJRNL_SPILL => {
            cfgWr(c_int, C_nStmtSpill, @cVaArg(&ap, c_int));
        },
        SQLITE_CONFIG_MEMDB_MAXSIZE => {
            cfgWr(i64, C_mxMemdbSize, @cVaArg(&ap, i64));
        },
        SQLITE_CONFIG_ROWID_IN_VIEW => {
            const pVal = @cVaArg(&ap, *c_int);
            // SQLITE_ALLOW_ROWID_IN_VIEW off
            pVal.* = 0;
        },
        else => {
            rc = SQLITE_ERROR;
        },
    }
    return rc;
}
const sizeof_mem_methods: usize = off("sizeof_mem_methods", 64);
const sizeof_mutex_methods: usize = off("sizeof_mutex_methods", 72);
const sizeof_pcache_methods2: usize = off("sizeof_pcache_methods2", 104);

// ═══════════════════════════════════════════════════════════════════════════
// setupLookaside (static)
// ═══════════════════════════════════════════════════════════════════════════
// Lookaside sub-struct offsets (relative to O_lookaside). Mirror Lookaside.
const LA_bDisable: usize = 0;
const LA_sz: usize = 4;
const LA_szTrue: usize = 6;
const LA_bMalloced: usize = 8;
const LA_nSlot: usize = 12;
const LA_pInit: usize = 32;
const LA_pFree: usize = 40;
const LA_pSmallInit: usize = 48;
const LA_pSmallFree: usize = 56;
const LA_pMiddle: usize = 64;
const LA_pStart: usize = 72;
const LA_pEnd: usize = 80;
const LA_pTrueEnd: usize = 88;
const LOOKASIDE_SMALL: i64 = 128;
const sizeof_LookasideSlot: c_int = 8;

inline fn laRd(comptime T: type, db: Ptr, rel: usize) T {
    return rd(T, db, O_lookaside + rel);
}
inline fn laWr(comptime T: type, db: Ptr, rel: usize, v: T) void {
    wr(T, db, O_lookaside + rel, v);
}

fn setupLookaside(db: Ptr, pBuf: Ptr, szIn: c_int, cntIn: c_int) c_int {
    var sz = szIn;
    var cnt = cntIn;
    if (sqlite3LookasideUsed(db, null) > 0) {
        return SQLITE_BUSY;
    }
    if (laRd(u8, db, LA_bMalloced) != 0) {
        sqlite3_free(laRd(Ptr, db, LA_pStart));
    }
    sz = sz & ~@as(c_int, 7); // ROUNDDOWN8
    if (sz <= sizeof_LookasideSlot) sz = 0;
    if (sz > 65528) sz = 65528;
    if (cnt < 1) cnt = 0;
    if (sz > 0 and cnt > @divTrunc(@as(c_int, 0x7fff0000), sz)) cnt = @divTrunc(@as(c_int, 0x7fff0000), sz);
    var szAlloc: i64 = @as(i64, sz) * @as(i64, cnt);
    var pStart: Ptr = undefined;
    if (szAlloc == 0) {
        sz = 0;
        pStart = null;
    } else if (pBuf == null) {
        sqlite3BeginBenignMalloc();
        pStart = sqlite3Malloc(@intCast(szAlloc));
        sqlite3EndBenignMalloc();
        if (pStart != null) szAlloc = @intCast(sqlite3MallocSize(pStart));
    } else {
        pStart = pBuf;
    }
    var nBig: i64 = undefined;
    var nSm: i64 = undefined;
    if (sz >= LOOKASIDE_SMALL * 3) {
        nBig = @divTrunc(szAlloc, (3 * LOOKASIDE_SMALL + sz));
        nSm = @divTrunc((szAlloc - @as(i64, sz) * nBig), LOOKASIDE_SMALL);
    } else if (sz >= LOOKASIDE_SMALL * 2) {
        nBig = @divTrunc(szAlloc, (LOOKASIDE_SMALL + sz));
        nSm = @divTrunc((szAlloc - @as(i64, sz) * nBig), LOOKASIDE_SMALL);
    } else if (sz > 0) {
        nBig = @divTrunc(szAlloc, sz);
        nSm = 0;
    } else {
        nBig = 0;
        nSm = 0;
    }
    laWr(Ptr, db, LA_pStart, pStart);
    laWr(Ptr, db, LA_pInit, null);
    laWr(Ptr, db, LA_pFree, null);
    laWr(u16, db, LA_sz, @truncate(@as(u32, @bitCast(sz))));
    laWr(u16, db, LA_szTrue, @truncate(@as(u32, @bitCast(sz))));
    if (pStart != null) {
        var p: [*]u8 = @ptrCast(pStart.?);
        var i: i64 = 0;
        while (i < nBig) : (i += 1) {
            // p->pNext = pInit; pInit = p; p = &p[sz]
            const pn: *align(1) Ptr = @ptrCast(p);
            pn.* = laRd(Ptr, db, LA_pInit);
            laWr(Ptr, db, LA_pInit, @ptrCast(p));
            p = p + @as(usize, @intCast(sz));
        }
        laWr(Ptr, db, LA_pSmallInit, null);
        laWr(Ptr, db, LA_pSmallFree, null);
        laWr(Ptr, db, LA_pMiddle, @ptrCast(p));
        i = 0;
        while (i < nSm) : (i += 1) {
            const pn: *align(1) Ptr = @ptrCast(p);
            pn.* = laRd(Ptr, db, LA_pSmallInit);
            laWr(Ptr, db, LA_pSmallInit, @ptrCast(p));
            p = p + @as(usize, @intCast(LOOKASIDE_SMALL));
        }
        laWr(Ptr, db, LA_pEnd, @ptrCast(p));
        laWr(u32, db, LA_bDisable, 0);
        laWr(u8, db, LA_bMalloced, if (pBuf == null) 1 else 0);
        laWr(u32, db, LA_nSlot, @intCast(nBig + nSm));
    } else {
        laWr(Ptr, db, LA_pStart, null);
        laWr(Ptr, db, LA_pSmallInit, null);
        laWr(Ptr, db, LA_pSmallFree, null);
        laWr(Ptr, db, LA_pMiddle, null);
        laWr(Ptr, db, LA_pEnd, null);
        laWr(u32, db, LA_bDisable, 1);
        laWr(u16, db, LA_sz, 0);
        laWr(u8, db, LA_bMalloced, 0);
        laWr(u32, db, LA_nSlot, 0);
    }
    laWr(Ptr, db, LA_pTrueEnd, laRd(Ptr, db, LA_pEnd));
    return SQLITE_OK;
}

// ─── Hash iteration helpers (Hash.first; HashElem.next/data) ────────────────
inline fn hashFirst(h: [*]u8) Ptr {
    const q: *align(1) const Ptr = @ptrCast(h + Hash_first);
    return q.*;
}
inline fn heNext(e: Ptr) Ptr {
    return rd(Ptr, e, HashElem_next);
}
inline fn heData(e: Ptr) Ptr {
    return rd(Ptr, e, HashElem_data);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_db_config (variadic)
// ═══════════════════════════════════════════════════════════════════════════
const FlagOp = struct { op: c_int, mask: u64 };
const aFlagOp = [_]FlagOp{
    .{ .op = SQLITE_DBCONFIG_ENABLE_FKEY, .mask = SQLITE_ForeignKeys },
    .{ .op = SQLITE_DBCONFIG_ENABLE_TRIGGER, .mask = SQLITE_EnableTrigger },
    .{ .op = SQLITE_DBCONFIG_ENABLE_VIEW, .mask = SQLITE_EnableView },
    .{ .op = SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, .mask = SQLITE_Fts3Tokenizer },
    .{ .op = SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, .mask = SQLITE_LoadExtension },
    .{ .op = SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, .mask = SQLITE_NoCkptOnClose },
    .{ .op = SQLITE_DBCONFIG_ENABLE_QPSG, .mask = SQLITE_EnableQPSG },
    .{ .op = SQLITE_DBCONFIG_TRIGGER_EQP, .mask = SQLITE_TriggerEQP },
    .{ .op = SQLITE_DBCONFIG_RESET_DATABASE, .mask = SQLITE_ResetDatabase },
    .{ .op = SQLITE_DBCONFIG_DEFENSIVE, .mask = SQLITE_Defensive },
    .{ .op = SQLITE_DBCONFIG_WRITABLE_SCHEMA, .mask = SQLITE_WriteSchema | SQLITE_NoSchemaError },
    .{ .op = SQLITE_DBCONFIG_LEGACY_ALTER_TABLE, .mask = SQLITE_LegacyAlter },
    .{ .op = SQLITE_DBCONFIG_DQS_DDL, .mask = SQLITE_DqsDDL },
    .{ .op = SQLITE_DBCONFIG_DQS_DML, .mask = SQLITE_DqsDML },
    .{ .op = SQLITE_DBCONFIG_LEGACY_FILE_FORMAT, .mask = SQLITE_LegacyFileFmt },
    .{ .op = SQLITE_DBCONFIG_TRUSTED_SCHEMA, .mask = SQLITE_TrustedSchema },
    .{ .op = SQLITE_DBCONFIG_STMT_SCANSTATUS, .mask = SQLITE_StmtScanStatus },
    .{ .op = SQLITE_DBCONFIG_REVERSE_SCANORDER, .mask = SQLITE_ReverseOrder },
    .{ .op = SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, .mask = SQLITE_AttachCreate },
    .{ .op = SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, .mask = SQLITE_AttachWrite },
    .{ .op = SQLITE_DBCONFIG_ENABLE_COMMENTS, .mask = SQLITE_Comments },
};

export fn sqlite3_db_config(db: Ptr, op: c_int, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var rc: c_int = undefined;
    sqlite3_mutex_enter(dbMutex(db));
    switch (op) {
        SQLITE_DBCONFIG_MAINDBNAME => {
            // db->aDb[0].zDbSName = va_arg(char*)
            const z = @cVaArg(&ap, Ptr);
            const p0: *align(1) Ptr = @ptrCast(dbAtPtr(db, 0) + Db_zDbSName);
            p0.* = z;
            rc = SQLITE_OK;
        },
        SQLITE_DBCONFIG_LOOKASIDE => {
            const pBuf = @cVaArg(&ap, Ptr);
            const sz = @cVaArg(&ap, c_int);
            const cnt = @cVaArg(&ap, c_int);
            rc = setupLookaside(db, pBuf, sz, cnt);
        },
        SQLITE_DBCONFIG_FP_DIGITS => {
            const nIn = @cVaArg(&ap, c_int);
            const pOut = @cVaArg(&ap, ?*c_int);
            if (nIn > 3 and nIn < 24) base(db)[O_nFpDigit] = @intCast(nIn);
            if (pOut) |po| po.* = base(db)[O_nFpDigit];
            rc = SQLITE_OK;
        },
        else => {
            rc = SQLITE_ERROR;
            for (aFlagOp) |fo| {
                if (fo.op == op) {
                    const onoff = @cVaArg(&ap, c_int);
                    const pRes = @cVaArg(&ap, ?*c_int);
                    const oldFlags = dbFlags(db);
                    if (onoff > 0) {
                        dbSetFlags(db, oldFlags | fo.mask);
                    } else if (onoff == 0) {
                        dbSetFlags(db, oldFlags & ~fo.mask);
                    }
                    if (oldFlags != dbFlags(db)) {
                        sqlite3ExpirePreparedStatements(db, 0);
                    }
                    if (pRes) |pr| pr.* = if ((dbFlags(db) & fo.mask) != 0) 1 else 0;
                    rc = SQLITE_OK;
                    break;
                }
            }
        },
    }
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

// ═══════════════════════════════════════════════════════════════════════════
// db mutex / release-memory / cacheflush
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_db_mutex(db: Ptr) callconv(.c) Ptr {
    return dbMutex(db);
}
export fn sqlite3_db_release_memory(db: Ptr) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    sqlite3BtreeEnterAll(db);
    var i: c_int = 0;
    while (i < dbNDb(db)) : (i += 1) {
        const pBt = dbAtPBt(db, i);
        if (pBt != null) {
            sqlite3PagerShrink(sqlite3BtreePager(pBt));
        }
    }
    sqlite3BtreeLeaveAll(db);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}
export fn sqlite3_db_cacheflush(db: Ptr) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var bSeenBusy: c_int = 0;
    sqlite3_mutex_enter(dbMutex(db));
    sqlite3BtreeEnterAll(db);
    var i: c_int = 0;
    while (rc == SQLITE_OK and i < dbNDb(db)) : (i += 1) {
        const pBt = dbAtPBt(db, i);
        if (pBt != null and sqlite3BtreeTxnState(pBt) == SQLITE_TXN_WRITE) {
            rc = sqlite3PagerFlush(sqlite3BtreePager(pBt));
            if (rc == SQLITE_BUSY) {
                bSeenBusy = 1;
                rc = SQLITE_OK;
            }
        }
    }
    sqlite3BtreeLeaveAll(db);
    sqlite3_mutex_leave(dbMutex(db));
    return if (rc == SQLITE_OK and bSeenBusy != 0) SQLITE_BUSY else rc;
}

// ═══════════════════════════════════════════════════════════════════════════
// Built-in collations
// ═══════════════════════════════════════════════════════════════════════════
fn binCollFunc(NotUsed: Ptr, nKey1: c_int, pKey1: ?*const anyopaque, nKey2: c_int, pKey2: ?*const anyopaque) callconv(.c) c_int {
    _ = NotUsed;
    const n = if (nKey1 < nKey2) nKey1 else nKey2;
    var rc = memcmp(pKey1, pKey2, @intCast(n));
    if (rc == 0) rc = nKey1 - nKey2;
    return rc;
}
fn rtrimCollFunc(pUser: Ptr, nKey1: c_int, pKey1: ?*const anyopaque, nKey2: c_int, pKey2: ?*const anyopaque) callconv(.c) c_int {
    const pK1: [*]const u8 = @ptrCast(pKey1.?);
    const pK2: [*]const u8 = @ptrCast(pKey2.?);
    var n1 = nKey1;
    var n2 = nKey2;
    while (n1 != 0 and pK1[@intCast(n1 - 1)] == ' ') n1 -= 1;
    while (n2 != 0 and pK2[@intCast(n2 - 1)] == ' ') n2 -= 1;
    return binCollFunc(pUser, n1, pKey1, n2, pKey2);
}
fn nocaseCollatingFunc(NotUsed: Ptr, nKey1: c_int, pKey1: ?*const anyopaque, nKey2: c_int, pKey2: ?*const anyopaque) callconv(.c) c_int {
    _ = NotUsed;
    const n = if (nKey1 < nKey2) nKey1 else nKey2;
    var r = sqlite3_strnicmp(@ptrCast(pKey1), @ptrCast(pKey2), n);
    if (r == 0) r = nKey1 - nKey2;
    return r;
}

// sqlite3IsBinary(const CollSeq *p): p==0 || p->xCmp==binCollFunc
export fn sqlite3IsBinary(p: Ptr) callconv(.c) c_int {
    if (p == null) return 1;
    const xCmp = rd(Ptr, p, CS_xCmp);
    return if (xCmp == @as(Ptr, @ptrCast(@constCast(&binCollFunc)))) 1 else 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// rowid / changes
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_last_insert_rowid(db: Ptr) callconv(.c) i64 {
    return rd(i64, db, O_lastRowid);
}
export fn sqlite3_set_last_insert_rowid(db: Ptr, iRowid: i64) callconv(.c) void {
    sqlite3_mutex_enter(dbMutex(db));
    wr(i64, db, O_lastRowid, iRowid);
    sqlite3_mutex_leave(dbMutex(db));
}
export fn sqlite3_changes64(db: Ptr) callconv(.c) i64 {
    return rd(i64, db, off("sqlite3_nChange", 120));
}
export fn sqlite3_changes(db: Ptr) callconv(.c) c_int {
    return @truncate(sqlite3_changes64(db));
}
export fn sqlite3_total_changes64(db: Ptr) callconv(.c) i64 {
    return rd(i64, db, off("sqlite3_nTotalChange", 128));
}
export fn sqlite3_total_changes(db: Ptr) callconv(.c) c_int {
    return @truncate(sqlite3_total_changes64(db));
}

// ═══════════════════════════════════════════════════════════════════════════
// Savepoints
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3CloseSavepoints(db: Ptr) callconv(.c) void {
    while (rd(Ptr, db, O_pSavepoint)) |pTmp| {
        wr(Ptr, db, O_pSavepoint, rd(Ptr, pTmp, SP_pNext));
        sqlite3DbFree(db, pTmp);
    }
    wr(c_int, db, O_nSavepoint, 0);
    wr(c_int, db, O_nStatement, 0);
    base(db)[O_isTransactionSavepoint] = 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// functionDestroy / disconnectAllVtab / connectionIsBusy
// ═══════════════════════════════════════════════════════════════════════════
fn functionDestroy(db: Ptr, p: Ptr) void {
    // pDestructor = p->u.pDestructor
    const pDestructor = rd(Ptr, p, FD_u);
    if (pDestructor) |pd| {
        const nref = rd(c_int, pd, FDest_nRef) - 1;
        wr(c_int, pd, FDest_nRef, nref);
        if (nref == 0) {
            const xDestroy: ?*const fn (Ptr) callconv(.c) void = @ptrCast(rd(Ptr, pd, FDest_xDestroy));
            if (xDestroy) |xd| xd(rd(Ptr, pd, FDest_pUserData));
            sqlite3DbFree(db, pd);
        }
    }
}

fn disconnectAllVtab(db: Ptr) void {
    sqlite3BtreeEnterAll(db);
    var i: c_int = 0;
    while (i < dbNDb(db)) : (i += 1) {
        const pSchema = dbAtPSchema(db, i);
        if (pSchema) |sch| {
            const tblHash: [*]u8 = base(sch) + Schema_tblHash;
            var p = hashFirst(tblHash);
            while (p) |pe| {
                const pTab = heData(pe);
                if (base(pTab)[Tab_eTabType] == TABTYP_VTAB) {
                    sqlite3VtabDisconnect(db, pTab);
                }
                p = heNext(pe);
            }
        }
    }
    var pm = hashFirst(base(db) + O_aModule);
    while (pm) |pe| {
        const pMod = heData(pe);
        const pEpoTab = rd(Ptr, pMod, Module_pEpoTab);
        if (pEpoTab != null) {
            sqlite3VtabDisconnect(db, pEpoTab);
        }
        pm = heNext(pe);
    }
    sqlite3VtabUnlockList(db);
    sqlite3BtreeLeaveAll(db);
}

fn connectionIsBusy(db: Ptr) c_int {
    if (rd(Ptr, db, O_pVdbe) != null) return 1;
    var j: c_int = 0;
    while (j < dbNDb(db)) : (j += 1) {
        const pBt = dbAtPBt(db, j);
        if (pBt != null and sqlite3BtreeIsInBackup(pBt) != 0) return 1;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Close
// ═══════════════════════════════════════════════════════════════════════════
fn sqlite3Close(db: Ptr, forceZombie: c_int) c_int {
    if (db == null) return SQLITE_OK;
    if (sqlite3SafetyCheckSickOrOk(db) == 0) {
        return misuseBkpt();
    }
    sqlite3_mutex_enter(dbMutex(db));
    if ((rd(u8, db, O_mTrace) & @as(u8, @truncate(SQLITE_TRACE_CLOSE))) != 0) {
        // db->trace.xV2(SQLITE_TRACE_CLOSE, db->pTraceArg, db, 0)
        const xV2: ?*const fn (u32, Ptr, Ptr, Ptr) callconv(.c) c_int = @ptrCast(rd(Ptr, db, O_trace));
        if (xV2) |f| _ = f(SQLITE_TRACE_CLOSE, rd(Ptr, db, O_pTraceArg), db, null);
    }
    disconnectAllVtab(db);
    _ = sqlite3VtabRollback(db);

    if (forceZombie == 0 and connectionIsBusy(db) != 0) {
        sqlite3ErrorWithMsg(db, SQLITE_BUSY, "unable to close due to unfinalized statements or unfinished backups");
        sqlite3_mutex_leave(dbMutex(db));
        return SQLITE_BUSY;
    }

    // free client data list
    while (rd(Ptr, db, O_pDbData)) |p| {
        wr(Ptr, db, O_pDbData, rd(Ptr, p, DCD_pNext));
        const xDestructor: ?*const fn (Ptr) callconv(.c) void = @ptrCast(rd(Ptr, p, DCD_xDestructor));
        if (xDestructor) |xd| xd(rd(Ptr, p, DCD_pData));
        sqlite3_free(p);
    }

    base(db)[off("sqlite3_eOpenState", 113)] = SQLITE_STATE_ZOMBIE;
    sqlite3LeaveMutexAndCloseZombie(db);
    return SQLITE_OK;
}

export fn sqlite3_close(db: Ptr) callconv(.c) c_int {
    return sqlite3Close(db, 0);
}
export fn sqlite3_close_v2(db: Ptr) callconv(.c) c_int {
    return sqlite3Close(db, 1);
}

export fn sqlite3_txn_state(db: Ptr, zSchema: ?[*:0]const u8) callconv(.c) c_int {
    var iTxn: c_int = -1;
    sqlite3_mutex_enter(dbMutex(db));
    var iDb: c_int = undefined;
    var nDb: c_int = undefined;
    if (zSchema != null) {
        iDb = sqlite3FindDbName(db, zSchema);
        nDb = iDb;
        if (iDb < 0) nDb -= 1;
    } else {
        iDb = 0;
        nDb = dbNDb(db) - 1;
    }
    while (iDb <= nDb) : (iDb += 1) {
        const pBt = dbAtPBt(db, iDb);
        const x: c_int = if (pBt != null) sqlite3BtreeTxnState(pBt) else SQLITE_TXN_NONE;
        if (x > iTxn) iTxn = x;
    }
    sqlite3_mutex_leave(dbMutex(db));
    return iTxn;
}

extern fn sqlite3SafetyCheckSickOrOk(db: Ptr) c_int;
extern fn sqlite3BtreeSchema(p: Ptr, nBytes: c_int, xFree: Ptr) Ptr;

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3LeaveMutexAndCloseZombie
// ═══════════════════════════════════════════════════════════════════════════
const O_eOpenState_ = off("sqlite3_eOpenState", 113);

export fn sqlite3LeaveMutexAndCloseZombie(db: Ptr) callconv(.c) void {
    if (base(db)[O_eOpenState_] != SQLITE_STATE_ZOMBIE or connectionIsBusy(db) != 0) {
        sqlite3_mutex_leave(dbMutex(db));
        return;
    }

    sqlite3RollbackAll(db, SQLITE_OK);
    sqlite3CloseSavepoints(db);

    var j: c_int = 0;
    while (j < dbNDb(db)) : (j += 1) {
        const pDb = dbAtPtr(db, j);
        const pBtPtr: *align(1) Ptr = @ptrCast(pDb + Db_pBt);
        if (pBtPtr.* != null) {
            _ = sqlite3BtreeClose(pBtPtr.*);
            pBtPtr.* = null;
            if (j != 1) {
                const pSchemaPtr: *align(1) Ptr = @ptrCast(pDb + Db_pSchema);
                pSchemaPtr.* = null;
            }
        }
    }
    // temp schema
    if (dbAtPSchema(db, 1)) |sch1| {
        sqlite3SchemaClear(sch1);
    }
    sqlite3VtabUnlockList(db);
    sqlite3CollapseDatabaseArray(db);
    sqlite3ConnectionClosed(db);

    // aFunc destructors
    var i = hashFirst(base(db) + O_aFunc);
    while (i) |ie| {
        var p = heData(ie);
        while (p) |pp| {
            functionDestroy(db, pp);
            const pNext = rd(Ptr, pp, FD_pNext);
            sqlite3DbFree(db, pp);
            p = pNext;
        }
        i = heNext(ie);
    }
    sqlite3HashClear(base(db) + O_aFunc);

    // aCollSeq destructors: each entry is CollSeq[3]
    var ic = hashFirst(base(db) + O_aCollSeq);
    while (ic) |ie| {
        const pColl = heData(ie);
        var k: usize = 0;
        while (k < 3) : (k += 1) {
            const collK: [*]u8 = base(pColl) + k * sizeof_CollSeq;
            const xDel: ?*const fn (Ptr) callconv(.c) void = @ptrCast(rd(Ptr, collK, CS_xDel));
            if (xDel) |xd| xd(rd(Ptr, collK, CS_pUser));
        }
        sqlite3DbFree(db, pColl);
        ic = heNext(ie);
    }
    sqlite3HashClear(base(db) + O_aCollSeq);

    // aModule
    var im = hashFirst(base(db) + O_aModule);
    while (im) |ie| {
        const pMod = heData(ie);
        sqlite3VtabEponymousTableClear(db, pMod);
        sqlite3VtabModuleUnref(db, pMod);
        im = heNext(ie);
    }
    sqlite3HashClear(base(db) + O_aModule);

    sqlite3Error(db, SQLITE_OK);
    sqlite3ValueFree(rd(Ptr, db, O_pErr));
    sqlite3CloseExtensions(db);

    base(db)[O_eOpenState_] = SQLITE_STATE_ERROR;

    sqlite3DbFree(db, dbAtPSchema(db, 1));
    // db->xAutovacDestr(db->pAutovacPagesArg)
    if (rd(Ptr, db, O_xAutovacDestr)) |xad| {
        const f: *const fn (Ptr) callconv(.c) void = @ptrCast(xad);
        f(rd(Ptr, db, O_pAutovacPagesArg));
    }
    sqlite3_mutex_leave(dbMutex(db));
    base(db)[O_eOpenState_] = SQLITE_STATE_CLOSED;
    sqlite3_mutex_free(dbMutex(db));
    if (laRd(u8, db, LA_bMalloced) != 0) {
        sqlite3_free(laRd(Ptr, db, LA_pStart));
    }
    sqlite3_free(db);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3RollbackAll
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3RollbackAll(db: Ptr, tripCode: c_int) callconv(.c) void {
    var inTrans: c_int = 0;
    sqlite3BeginBenignMalloc();
    sqlite3BtreeEnterAll(db);
    const schemaChange: bool = (rd(u32, db, O_mDbFlags) & DBFLAG_SchemaChange) != 0 and base(db)[O_init_busy] == 0;

    var i: c_int = 0;
    while (i < dbNDb(db)) : (i += 1) {
        const p = dbAtPBt(db, i);
        if (p != null) {
            if (sqlite3BtreeTxnState(p) == SQLITE_TXN_WRITE) inTrans = 1;
            _ = sqlite3BtreeRollback(p, tripCode, if (!schemaChange) 1 else 0);
        }
    }
    _ = sqlite3VtabRollback(db);
    sqlite3EndBenignMalloc();

    if (schemaChange) {
        sqlite3ExpirePreparedStatements(db, 0);
        sqlite3ResetAllSchemasOfConnection(db);
    }
    sqlite3BtreeLeaveAll(db);

    wr(c_int, db, O_nDeferredCons, 0);
    wr(c_int, db, O_nDeferredImmCons, 0);
    dbSetFlags(db, dbFlags(db) & ~(SQLITE_DeferFKs | SQLITE_CorruptRdOnly));

    // rollback hook
    if (rd(Ptr, db, O_xRollbackCallback)) |cb| {
        if (inTrans != 0 or base(db)[O_autoCommit] == 0) {
            const f: *const fn (Ptr) callconv(.c) void = @ptrCast(cb);
            f(rd(Ptr, db, O_pRollbackArg));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3ErrStr
// ═══════════════════════════════════════════════════════════════════════════
const aMsg = [_]?[*:0]const u8{
    "not an error", // OK
    "SQL logic error", // ERROR
    null, // INTERNAL
    "access permission denied", // PERM
    "query aborted", // ABORT
    "database is locked", // BUSY
    "database table is locked", // LOCKED
    "out of memory", // NOMEM
    "attempt to write a readonly database", // READONLY
    "interrupted", // INTERRUPT
    "disk I/O error", // IOERR
    "database disk image is malformed", // CORRUPT
    "unknown operation", // NOTFOUND
    "database or disk is full", // FULL
    "unable to open database file", // CANTOPEN
    "locking protocol", // PROTOCOL
    null, // EMPTY
    "database schema has changed", // SCHEMA
    "string or blob too big", // TOOBIG
    "constraint failed", // CONSTRAINT
    "datatype mismatch", // MISMATCH
    "bad parameter or other API misuse", // MISUSE
    null, // NOLFS (SQLITE_DISABLE_LFS off)
    "authorization denied", // AUTH
    null, // FORMAT
    "column index out of range", // RANGE
    "file is not a database", // NOTADB
    "notification message", // NOTICE
    "warning message", // WARNING
};

export fn sqlite3ErrStr(rc_in: c_int) callconv(.c) ?[*:0]const u8 {
    var rc = rc_in;
    var zErr: ?[*:0]const u8 = "unknown error";
    switch (rc) {
        SQLITE_ABORT_ROLLBACK => zErr = "abort due to ROLLBACK",
        SQLITE_ROW => zErr = "another row available",
        SQLITE_DONE => zErr = "no more rows available",
        else => {
            rc &= 0xff;
            if (rc >= 0 and rc < @as(c_int, @intCast(aMsg.len)) and aMsg[@intCast(rc)] != null) {
                zErr = aMsg[@intCast(rc)];
            }
        },
    }
    return zErr;
}

// ═══════════════════════════════════════════════════════════════════════════
// Default busy callback + InvokeBusyHandler
// ═══════════════════════════════════════════════════════════════════════════
const busyDelays = [_]u8{ 1, 2, 5, 10, 15, 20, 25, 25, 25, 50, 50, 100 };
const busyTotals = [_]u8{ 0, 1, 3, 8, 18, 33, 53, 78, 103, 128, 178, 228 };

fn sqliteDefaultBusyCallback(ptr: Ptr, count: c_int) callconv(.c) c_int {
    const db = ptr;
    const tmout = rd(c_int, db, O_busyTimeout);
    var delay: c_int = undefined;
    var prior: c_int = undefined;
    const NDELAY: c_int = busyDelays.len;
    if (count < NDELAY) {
        delay = busyDelays[@intCast(count)];
        prior = busyTotals[@intCast(count)];
    } else {
        delay = busyDelays[NDELAY - 1];
        prior = @as(c_int, busyTotals[NDELAY - 1]) + delay * (count - (NDELAY - 1));
    }
    if (prior + delay > tmout) {
        delay = tmout - prior;
        if (delay <= 0) return 0;
    }
    _ = sqlite3OsSleep(rd(Ptr, db, O_pVfs), delay * 1000);
    return 1;
}

export fn sqlite3InvokeBusyHandler(p: Ptr) callconv(.c) c_int {
    const xBusy: ?*const fn (Ptr, c_int) callconv(.c) c_int = @ptrCast(rd(Ptr, p, BH_xBusyHandler));
    const nBusy = rd(c_int, p, BH_nBusy);
    if (xBusy == null or nBusy < 0) return 0;
    const rc = xBusy.?(rd(Ptr, p, BH_pBusyArg), nBusy);
    if (rc == 0) {
        wr(c_int, p, BH_nBusy, -1);
    } else {
        wr(c_int, p, BH_nBusy, nBusy + 1);
    }
    return rc;
}

export fn sqlite3_busy_handler(db: Ptr, xBusy: Ptr, pArg: Ptr) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    const bh = base(db) + O_busyHandler;
    const x: *align(1) Ptr = @ptrCast(bh + BH_xBusyHandler);
    x.* = xBusy;
    const a: *align(1) Ptr = @ptrCast(bh + BH_pBusyArg);
    a.* = pArg;
    const n: *align(1) c_int = @ptrCast(bh + BH_nBusy);
    n.* = 0;
    wr(c_int, db, O_busyTimeout, 0);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

export fn sqlite3_progress_handler(db: Ptr, nOps: c_int, xProgress: Ptr, pArg: Ptr) callconv(.c) void {
    sqlite3_mutex_enter(dbMutex(db));
    if (nOps > 0) {
        wr(Ptr, db, off("sqlite3_xProgress", 544), xProgress);
        wr(c_uint, db, off("sqlite3_nProgressOps", 560), @intCast(nOps));
        wr(Ptr, db, off("sqlite3_pProgressArg", 552), pArg);
    } else {
        wr(Ptr, db, off("sqlite3_xProgress", 544), null);
        wr(c_uint, db, off("sqlite3_nProgressOps", 560), 0);
        wr(Ptr, db, off("sqlite3_pProgressArg", 552), null);
    }
    sqlite3_mutex_leave(dbMutex(db));
}

export fn sqlite3_busy_timeout(db: Ptr, ms: c_int) callconv(.c) c_int {
    if (ms > 0) {
        _ = sqlite3_busy_handler(db, @ptrCast(@constCast(&sqliteDefaultBusyCallback)), db);
        wr(c_int, db, O_busyTimeout, ms);
    } else {
        _ = sqlite3_busy_handler(db, null, null);
    }
    return SQLITE_OK;
}

export fn sqlite3_setlk_timeout(db: Ptr, ms: c_int, flags: c_int) callconv(.c) c_int {
    _ = db;
    _ = flags;
    if (ms < -1) return SQLITE_RANGE;
    // SQLITE_ENABLE_SETLK_TIMEOUT off → no further action
    return SQLITE_OK;
}

export fn sqlite3_interrupt(db: Ptr) callconv(.c) void {
    // AtomicStore(&db->u1.isInterrupted, 1)
    const p: *c_int = @alignCast(@ptrCast(base(db) + O_u1));
    @atomicStore(c_int, p, 1, .seq_cst);
}

export fn sqlite3_is_interrupted(db: Ptr) callconv(.c) c_int {
    const p: *c_int = @alignCast(@ptrCast(base(db) + O_u1));
    return if (@atomicLoad(c_int, p, .seq_cst) != 0) 1 else 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3CreateFunc + create_function family
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3CreateFunc(
    db: Ptr,
    zFunctionName: ?[*:0]const u8,
    nArg: c_int,
    encIn: c_int,
    pUserData: Ptr,
    xSFunc: Ptr,
    xStep: Ptr,
    xFinal: Ptr,
    xValue: Ptr,
    xInverse: Ptr,
    pDestructor: Ptr,
) callconv(.c) c_int {
    var enc = encIn;
    if (zFunctionName == null or (xSFunc != null and xFinal != null) or ((xFinal == null) != (xStep == null)) or ((xValue == null) != (xInverse == null)) or (nArg < -1 or nArg > SQLITE_MAX_FUNCTION_ARG) or (255 < sqlite3Strlen30(zFunctionName))) {
        return misuseBkpt();
    }

    var extraFlags = enc & (SQLITE_DETERMINISTIC | SQLITE_DIRECTONLY | SQLITE_SUBTYPE | SQLITE_INNOCUOUS | SQLITE_RESULT_SUBTYPE | SQLITE_SELFORDER1);
    enc &= @as(c_int, @intCast(SQLITE_FUNC_ENCMASK)) | SQLITE_ANY;
    extraFlags ^= SQLITE_FUNC_UNSAFE; // tag-20230109-1

    switch (enc) {
        SQLITE_UTF16 => enc = SQLITE_UTF16NATIVE,
        SQLITE_ANY => {
            var rc = sqlite3CreateFunc(db, zFunctionName, nArg, (SQLITE_UTF8 | extraFlags) ^ SQLITE_FUNC_UNSAFE, pUserData, xSFunc, xStep, xFinal, xValue, xInverse, pDestructor);
            if (rc == SQLITE_OK) {
                rc = sqlite3CreateFunc(db, zFunctionName, nArg, (SQLITE_UTF16LE | extraFlags) ^ SQLITE_FUNC_UNSAFE, pUserData, xSFunc, xStep, xFinal, xValue, xInverse, pDestructor);
            }
            if (rc != SQLITE_OK) return rc;
            enc = SQLITE_UTF16BE;
        },
        SQLITE_UTF8, SQLITE_UTF16LE, SQLITE_UTF16BE => {},
        else => enc = SQLITE_UTF8,
    }

    var p = sqlite3FindFunction(db, zFunctionName, nArg, @intCast(enc), 0);
    if (p != null and (rd(u32, p, FD_funcFlags) & SQLITE_FUNC_ENCMASK) == @as(u32, @intCast(enc)) and rd(i16, p, FD_nArg) == nArg) {
        if (rd(c_int, db, O_nVdbeActive) != 0) {
            sqlite3ErrorWithMsg(db, SQLITE_BUSY, "unable to delete/modify user-function due to active statements");
            return SQLITE_BUSY;
        } else {
            sqlite3ExpirePreparedStatements(db, 0);
        }
    } else if (xSFunc == null and xFinal == null) {
        return SQLITE_OK;
    }

    p = sqlite3FindFunction(db, zFunctionName, nArg, @intCast(enc), 1);
    if (p == null) {
        return nomemBkpt();
    }

    functionDestroy(db, p);
    if (pDestructor != null) {
        wr(c_int, pDestructor, FDest_nRef, rd(c_int, pDestructor, FDest_nRef) + 1);
    }
    wr(Ptr, p, FD_u, pDestructor); // p->u.pDestructor
    wr(u32, p, FD_funcFlags, (rd(u32, p, FD_funcFlags) & SQLITE_FUNC_ENCMASK) | @as(u32, @bitCast(extraFlags)));
    wr(Ptr, p, FD_xSFunc, if (xSFunc != null) xSFunc else xStep);
    wr(Ptr, p, FD_xFinalize, xFinal);
    wr(Ptr, p, FD_xValue, xValue);
    wr(Ptr, p, FD_xInverse, xInverse);
    wr(Ptr, p, FD_pUserData, pUserData);
    wr(i16, p, FD_nArg, @truncate(@as(c_int, nArg))); // (u16)nArg bit-truncate
    return SQLITE_OK;
}

fn createFunctionApi(
    db: Ptr,
    zFunc: ?[*:0]const u8,
    nArg: c_int,
    enc: c_int,
    p: Ptr,
    xSFunc: Ptr,
    xStep: Ptr,
    xFinal: Ptr,
    xValue: Ptr,
    xInverse: Ptr,
    xDestroy: ?*const fn (Ptr) callconv(.c) void,
) c_int {
    var rc: c_int = SQLITE_ERROR;
    var pArg: Ptr = null;
    sqlite3_mutex_enter(dbMutex(db));
    if (xDestroy) |xd| {
        pArg = sqlite3Malloc(sizeof_FuncDestructor);
        if (pArg == null) {
            _ = sqlite3OomFault(db);
            xd(p);
            rc = sqlite3ApiExit(db, rc);
            sqlite3_mutex_leave(dbMutex(db));
            return rc;
        }
        wr(c_int, pArg, FDest_nRef, 0);
        wr(Ptr, pArg, FDest_xDestroy, @ptrCast(@constCast(xd)));
        wr(Ptr, pArg, FDest_pUserData, p);
    }
    rc = sqlite3CreateFunc(db, zFunc, nArg, enc, p, xSFunc, xStep, xFinal, xValue, xInverse, pArg);
    if (pArg != null and rd(c_int, pArg, FDest_nRef) == 0) {
        if (xDestroy) |xd| xd(p);
        sqlite3_free(pArg);
    }
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}
const sizeof_FuncDestructor: u64 = 24;

export fn sqlite3_create_function(db: Ptr, zFunc: ?[*:0]const u8, nArg: c_int, enc: c_int, p: Ptr, xSFunc: Ptr, xStep: Ptr, xFinal: Ptr) callconv(.c) c_int {
    return createFunctionApi(db, zFunc, nArg, enc, p, xSFunc, xStep, xFinal, null, null, null);
}
export fn sqlite3_create_function_v2(db: Ptr, zFunc: ?[*:0]const u8, nArg: c_int, enc: c_int, p: Ptr, xSFunc: Ptr, xStep: Ptr, xFinal: Ptr, xDestroy: ?*const fn (Ptr) callconv(.c) void) callconv(.c) c_int {
    return createFunctionApi(db, zFunc, nArg, enc, p, xSFunc, xStep, xFinal, null, null, xDestroy);
}
export fn sqlite3_create_window_function(db: Ptr, zFunc: ?[*:0]const u8, nArg: c_int, enc: c_int, p: Ptr, xStep: Ptr, xFinal: Ptr, xValue: Ptr, xInverse: Ptr, xDestroy: ?*const fn (Ptr) callconv(.c) void) callconv(.c) c_int {
    return createFunctionApi(db, zFunc, nArg, enc, p, null, xStep, xFinal, xValue, xInverse, xDestroy);
}
export fn sqlite3_create_function16(db: Ptr, zFunctionName: ?*const anyopaque, nArg: c_int, eTextRep: c_int, p: Ptr, xSFunc: Ptr, xStep: Ptr, xFinal: Ptr) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    const zFunc8 = sqlite3Utf16to8(db, zFunctionName, -1, SQLITE_UTF16NATIVE);
    var rc = sqlite3CreateFunc(db, zFunc8, nArg, eTextRep, p, xSFunc, xStep, xFinal, null, null, null);
    sqlite3DbFree(db, zFunc8);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

fn sqlite3InvalidFunction(context: Ptr, n: c_int, argv: Ptr) callconv(.c) void {
    _ = n;
    _ = argv;
    const zName: ?[*:0]const u8 = @ptrCast(sqlite3_user_data(context));
    const zErr = sqlite3_mprintf("unable to use function %s in the requested context", zName);
    sqlite3_result_error(context, zErr, -1);
    sqlite3_free(zErr);
}

export fn sqlite3_overload_function(db: Ptr, zName: ?[*:0]const u8, nArg: c_int) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    const rc: c_int = if (sqlite3FindFunction(db, zName, nArg, @intCast(SQLITE_UTF8), 0) != null) 1 else 0;
    sqlite3_mutex_leave(dbMutex(db));
    if (rc != 0) return SQLITE_OK;
    const zCopy = sqlite3_mprintf("%s", zName);
    if (zCopy == null) return SQLITE_NOMEM;
    return sqlite3_create_function_v2(db, zName, nArg, SQLITE_UTF8, zCopy, @ptrCast(@constCast(&sqlite3InvalidFunction)), null, null, sqlite3_free);
}

// ═══════════════════════════════════════════════════════════════════════════
// trace / profile (SQLITE_OMIT_TRACE off; SQLITE_OMIT_DEPRECATED off)
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_trace(db: Ptr, xTrace: Ptr, pArg: Ptr) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    const pOld = rd(Ptr, db, O_pTraceArg);
    base(db)[O_mTrace] = if (xTrace != null) @truncate(SQLITE_TRACE_LEGACY) else 0;
    wr(Ptr, db, O_trace, xTrace); // trace.xLegacy
    wr(Ptr, db, O_pTraceArg, pArg);
    sqlite3_mutex_leave(dbMutex(db));
    return pOld;
}

export fn sqlite3_trace_v2(db: Ptr, mTrace_in: c_uint, xTrace: Ptr, pArg: Ptr) callconv(.c) c_int {
    var mTrace = mTrace_in;
    var xt = xTrace;
    sqlite3_mutex_enter(dbMutex(db));
    if (mTrace == 0) xt = null;
    if (xt == null) mTrace = 0;
    base(db)[O_mTrace] = @truncate(mTrace);
    wr(Ptr, db, O_trace, xt); // trace.xV2
    wr(Ptr, db, O_pTraceArg, pArg);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

export fn sqlite3_profile(db: Ptr, xProfile: Ptr, pArg: Ptr) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    const pOld = rd(Ptr, db, O_pProfileArg);
    wr(Ptr, db, O_xProfile, xProfile);
    wr(Ptr, db, O_pProfileArg, pArg);
    base(db)[O_mTrace] = @truncate(@as(u32, base(db)[O_mTrace]) & SQLITE_TRACE_NONLEGACY_MASK);
    if (rd(Ptr, db, O_xProfile) != null) {
        base(db)[O_mTrace] = @truncate(@as(u32, base(db)[O_mTrace]) | SQLITE_TRACE_XPROFILE);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return pOld;
}

// ═══════════════════════════════════════════════════════════════════════════
// commit / update / rollback / preupdate / autovacuum hooks
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_commit_hook(db: Ptr, xCallback: Ptr, pArg: Ptr) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    const pOld = rd(Ptr, db, O_pCommitArg);
    wr(Ptr, db, O_xCommitCallback, xCallback);
    wr(Ptr, db, O_pCommitArg, pArg);
    sqlite3_mutex_leave(dbMutex(db));
    return pOld;
}
export fn sqlite3_update_hook(db: Ptr, xCallback: Ptr, pArg: Ptr) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    const pRet = rd(Ptr, db, O_pUpdateArg);
    wr(Ptr, db, O_xUpdateCallback, xCallback);
    wr(Ptr, db, O_pUpdateArg, pArg);
    sqlite3_mutex_leave(dbMutex(db));
    return pRet;
}
export fn sqlite3_rollback_hook(db: Ptr, xCallback: Ptr, pArg: Ptr) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    const pRet = rd(Ptr, db, O_pRollbackArg);
    wr(Ptr, db, O_xRollbackCallback, xCallback);
    wr(Ptr, db, O_pRollbackArg, pArg);
    sqlite3_mutex_leave(dbMutex(db));
    return pRet;
}
export fn sqlite3_preupdate_hook(db: Ptr, xCallback: Ptr, pArg: Ptr) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    const pRet = rd(Ptr, db, O_pPreUpdateArg);
    wr(Ptr, db, O_xPreUpdateCallback, xCallback);
    wr(Ptr, db, O_pPreUpdateArg, pArg);
    sqlite3_mutex_leave(dbMutex(db));
    return pRet;
}
export fn sqlite3_autovacuum_pages(db: Ptr, xCallback: Ptr, pArg: Ptr, xDestructor: ?*const fn (Ptr) callconv(.c) void) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    if (rd(Ptr, db, O_xAutovacDestr)) |xad| {
        const f: *const fn (Ptr) callconv(.c) void = @ptrCast(xad);
        f(rd(Ptr, db, O_pAutovacPagesArg));
    }
    wr(Ptr, db, O_xAutovacPages, xCallback);
    wr(Ptr, db, O_pAutovacPagesArg, pArg);
    wr(Ptr, db, O_xAutovacDestr, if (xDestructor) |x| @ptrCast(@constCast(x)) else null);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

// ═══════════════════════════════════════════════════════════════════════════
// WAL hooks + checkpoint (SQLITE_OMIT_WAL off)
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3WalDefaultHook(pClientData: Ptr, db: Ptr, zDb: ?[*:0]const u8, nFrame: c_int) callconv(.c) c_int {
    const threshold: c_int = @truncate(@as(isize, @bitCast(@intFromPtr(pClientData))));
    if (nFrame >= threshold) {
        sqlite3BeginBenignMalloc();
        _ = sqlite3_wal_checkpoint(db, zDb);
        sqlite3EndBenignMalloc();
    }
    return SQLITE_OK;
}

export fn sqlite3_wal_autocheckpoint(db: Ptr, nFrame: c_int) callconv(.c) c_int {
    if (nFrame > 0) {
        _ = sqlite3_wal_hook(db, @ptrCast(@constCast(&sqlite3WalDefaultHook)), @ptrFromInt(@as(usize, @bitCast(@as(isize, nFrame)))));
    } else {
        _ = sqlite3_wal_hook(db, null, null);
    }
    return SQLITE_OK;
}

export fn sqlite3_wal_hook(db: Ptr, xCallback: Ptr, pArg: Ptr) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    const pRet = rd(Ptr, db, O_pWalArg);
    wr(Ptr, db, O_xWalCallback, xCallback);
    wr(Ptr, db, O_pWalArg, pArg);
    sqlite3_mutex_leave(dbMutex(db));
    return pRet;
}

export fn sqlite3_wal_checkpoint_v2(db: Ptr, zDb: ?[*:0]const u8, eMode: c_int, pnLog: ?*c_int, pnCkpt: ?*c_int) callconv(.c) c_int {
    if (pnLog) |p| p.* = -1;
    if (pnCkpt) |p| p.* = -1;
    if (eMode < SQLITE_CHECKPOINT_NOOP or eMode > SQLITE_CHECKPOINT_TRUNCATE) {
        return misuseBkpt();
    }
    sqlite3_mutex_enter(dbMutex(db));
    var iDb: c_int = undefined;
    if (zDb != null and zDb.?[0] != 0) {
        iDb = sqlite3FindDbName(db, zDb);
    } else {
        iDb = SQLITE_MAX_DB;
    }
    var rc: c_int = undefined;
    if (iDb < 0) {
        rc = SQLITE_ERROR;
        sqlite3ErrorWithMsg(db, SQLITE_ERROR, "unknown database: %s", zDb);
    } else {
        wr(c_int, base(db) + O_busyHandler, BH_nBusy, 0);
        rc = sqlite3Checkpoint(db, iDb, eMode, pnLog, pnCkpt);
        sqlite3Error(db, rc);
    }
    rc = sqlite3ApiExit(db, rc);
    if (rd(c_int, db, O_nVdbeActive) == 0) {
        const p: *c_int = @alignCast(@ptrCast(base(db) + O_u1));
        @atomicStore(c_int, p, 0, .seq_cst);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

export fn sqlite3_wal_checkpoint(db: Ptr, zDb: ?[*:0]const u8) callconv(.c) c_int {
    return sqlite3_wal_checkpoint_v2(db, zDb, SQLITE_CHECKPOINT_PASSIVE, null, null);
}

export fn sqlite3Checkpoint(db: Ptr, iDb: c_int, eMode: c_int, pnLog_in: ?*c_int, pnCkpt_in: ?*c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var bBusy: c_int = 0;
    var pnLog = pnLog_in;
    var pnCkpt = pnCkpt_in;
    var i: c_int = 0;
    while (i < dbNDb(db) and rc == SQLITE_OK) : (i += 1) {
        if (i == iDb or iDb == SQLITE_MAX_DB) {
            rc = sqlite3BtreeCheckpoint(dbAtPBt(db, i), eMode, pnLog, pnCkpt);
            pnLog = null;
            pnCkpt = null;
            if (rc == SQLITE_BUSY) {
                bBusy = 1;
                rc = SQLITE_OK;
            }
        }
    }
    return if (rc == SQLITE_OK and bBusy != 0) SQLITE_BUSY else rc;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3TempInMemory (SQLITE_TEMP_STORE==1)
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3TempInMemory(db: Ptr) callconv(.c) c_int {
    return if (base(db)[O_temp_store] == 2) 1 else 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// errmsg / errcode / error funcs
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_errmsg(db: Ptr) callconv(.c) ?[*:0]const u8 {
    if (db == null) return sqlite3ErrStr(nomemBkpt());
    if (sqlite3SafetyCheckSickOrOk(db) == 0) return sqlite3ErrStr(misuseBkpt());
    sqlite3_mutex_enter(dbMutex(db));
    var z: ?[*:0]const u8 = undefined;
    if (dbMallocFailed(db)) {
        z = sqlite3ErrStr(nomemBkpt());
    } else {
        z = if (dbErrCode(db) != 0) sqlite3_value_text(rd(Ptr, db, O_pErr)) else null;
        if (z == null) z = sqlite3ErrStr(dbErrCode(db));
    }
    sqlite3_mutex_leave(dbMutex(db));
    return z;
}

export fn sqlite3_set_errmsg(db: Ptr, errcode: c_int, zMsg: ?[*:0]const u8) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (sqlite3SafetyCheckOk(db) == 0) return misuseBkpt();
    sqlite3_mutex_enter(dbMutex(db));
    if (zMsg != null) {
        sqlite3ErrorWithMsg(db, errcode, "%s", zMsg);
    } else {
        sqlite3Error(db, errcode);
    }
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

export fn sqlite3_error_offset(db: Ptr) callconv(.c) c_int {
    var iOffset: c_int = -1;
    if (db != null and sqlite3SafetyCheckSickOrOk(db) != 0 and dbErrCode(db) != 0) {
        sqlite3_mutex_enter(dbMutex(db));
        iOffset = rd(c_int, db, O_errByteOffset);
        sqlite3_mutex_leave(dbMutex(db));
    }
    return iOffset;
}

const outOfMem16 = [_]u16{ 'o', 'u', 't', ' ', 'o', 'f', ' ', 'm', 'e', 'm', 'o', 'r', 'y', 0 };
const misuse16 = [_]u16{ 'b', 'a', 'd', ' ', 'p', 'a', 'r', 'a', 'm', 'e', 't', 'e', 'r', ' ', 'o', 'r', ' ', 'o', 't', 'h', 'e', 'r', ' ', 'A', 'P', 'I', ' ', 'm', 'i', 's', 'u', 's', 'e', 0 };

export fn sqlite3_errmsg16(db: Ptr) callconv(.c) ?*const anyopaque {
    if (db == null) return @ptrCast(&outOfMem16);
    if (sqlite3SafetyCheckSickOrOk(db) == 0) return @ptrCast(&misuse16);
    sqlite3_mutex_enter(dbMutex(db));
    var z: ?*const anyopaque = undefined;
    if (dbMallocFailed(db)) {
        z = @ptrCast(&outOfMem16);
    } else {
        z = sqlite3_value_text16(rd(Ptr, db, O_pErr));
        if (z == null) {
            sqlite3ErrorWithMsg(db, dbErrCode(db), sqlite3ErrStr(dbErrCode(db)));
            z = sqlite3_value_text16(rd(Ptr, db, O_pErr));
        }
        sqlite3OomClear(db);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return z;
}

export fn sqlite3_errcode(db: Ptr) callconv(.c) c_int {
    if (db != null and sqlite3SafetyCheckSickOrOk(db) == 0) return misuseBkpt();
    if (db == null or dbMallocFailed(db)) return nomemBkpt();
    return dbErrCode(db) & dbErrMask(db);
}
export fn sqlite3_extended_errcode(db: Ptr) callconv(.c) c_int {
    if (db != null and sqlite3SafetyCheckSickOrOk(db) == 0) return misuseBkpt();
    if (db == null or dbMallocFailed(db)) return nomemBkpt();
    return dbErrCode(db);
}
export fn sqlite3_system_errno(db: Ptr) callconv(.c) c_int {
    return if (db != null) rd(c_int, db, O_iSysErrno) else 0;
}
export fn sqlite3_errstr(rc: c_int) callconv(.c) ?[*:0]const u8 {
    return sqlite3ErrStr(rc);
}

extern fn sqlite3SafetyCheckOk(db: Ptr) c_int;

// ═══════════════════════════════════════════════════════════════════════════
// createCollation + collation APIs
// ═══════════════════════════════════════════════════════════════════════════
fn createCollation(db: Ptr, zName: ?[*:0]const u8, enc: u8, pCtx: Ptr, xCompare: Ptr, xDel: Ptr) c_int {
    var enc2: c_int = enc;
    if (enc2 == SQLITE_UTF16 or enc2 == SQLITE_UTF16_ALIGNED) {
        enc2 = SQLITE_UTF16NATIVE;
    }
    if (enc2 < SQLITE_UTF8 or enc2 > SQLITE_UTF16BE) {
        return misuseBkpt();
    }

    var pColl = sqlite3FindCollSeq(db, @intCast(enc2), zName, 0);
    if (pColl != null and rd(Ptr, pColl, CS_xCmp) != null) {
        if (rd(c_int, db, O_nVdbeActive) != 0) {
            sqlite3ErrorWithMsg(db, SQLITE_BUSY, "unable to delete/modify collation sequence due to active statements");
            return SQLITE_BUSY;
        }
        sqlite3ExpirePreparedStatements(db, 0);

        const collEnc = rd(u8, pColl, CS_enc);
        if ((collEnc & ~@as(u8, @intCast(SQLITE_UTF16_ALIGNED))) == @as(u8, @intCast(enc2))) {
            const aColl = sqlite3HashFind(base(db) + O_aCollSeq, zName);
            var j: usize = 0;
            while (j < 3) : (j += 1) {
                const p = base(aColl) + j * sizeof_CollSeq;
                if (rd(u8, p, CS_enc) == collEnc) {
                    const xd: ?*const fn (Ptr) callconv(.c) void = @ptrCast(rd(Ptr, p, CS_xDel));
                    if (xd) |f| f(rd(Ptr, p, CS_pUser));
                    wr(Ptr, p, CS_xCmp, null);
                }
            }
        }
    }

    pColl = sqlite3FindCollSeq(db, @intCast(enc2), zName, 1);
    if (pColl == null) return nomemBkpt();
    wr(Ptr, pColl, CS_xCmp, xCompare);
    wr(Ptr, pColl, CS_pUser, pCtx);
    wr(Ptr, pColl, CS_xDel, xDel);
    wr(u8, pColl, CS_enc, @intCast(enc2 | (@as(c_int, enc) & SQLITE_UTF16_ALIGNED)));
    sqlite3Error(db, SQLITE_OK);
    return SQLITE_OK;
}

export fn sqlite3_create_collation(db: Ptr, zName: ?[*:0]const u8, enc: c_int, pCtx: Ptr, xCompare: Ptr) callconv(.c) c_int {
    return sqlite3_create_collation_v2(db, zName, enc, pCtx, xCompare, null);
}
export fn sqlite3_create_collation_v2(db: Ptr, zName: ?[*:0]const u8, enc: c_int, pCtx: Ptr, xCompare: Ptr, xDel: Ptr) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    var rc = createCollation(db, zName, @intCast(enc), pCtx, xCompare, xDel);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}
export fn sqlite3_create_collation16(db: Ptr, zName: ?*const anyopaque, enc: c_int, pCtx: Ptr, xCompare: Ptr) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    sqlite3_mutex_enter(dbMutex(db));
    const zName8 = sqlite3Utf16to8(db, zName, -1, SQLITE_UTF16NATIVE);
    if (zName8 != null) {
        rc = createCollation(db, zName8, @intCast(enc), pCtx, xCompare, null);
        sqlite3DbFree(db, zName8);
    }
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}
export fn sqlite3_collation_needed(db: Ptr, pCollNeededArg: Ptr, xCollNeeded: Ptr) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    wr(Ptr, db, O_xCollNeeded, xCollNeeded);
    wr(Ptr, db, O_xCollNeeded16, null);
    wr(Ptr, db, O_pCollNeededArg, pCollNeededArg);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}
export fn sqlite3_collation_needed16(db: Ptr, pCollNeededArg: Ptr, xCollNeeded16: Ptr) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    wr(Ptr, db, O_xCollNeeded, null);
    wr(Ptr, db, O_xCollNeeded16, xCollNeeded16);
    wr(Ptr, db, O_pCollNeededArg, pCollNeededArg);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

// ═══════════════════════════════════════════════════════════════════════════
// client data
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_get_clientdata(db: Ptr, zName: ?[*:0]const u8) callconv(.c) Ptr {
    sqlite3_mutex_enter(dbMutex(db));
    var p = rd(Ptr, db, O_pDbData);
    while (p) |pp| {
        const pName: ?[*:0]const u8 = @ptrCast(base(pp) + DCD_zName);
        if (strcmp(pName.?, zName.?) == 0) {
            const pResult = rd(Ptr, pp, DCD_pData);
            sqlite3_mutex_leave(dbMutex(db));
            return pResult;
        }
        p = rd(Ptr, pp, DCD_pNext);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return null;
}

export fn sqlite3_set_clientdata(db: Ptr, zName: ?[*:0]const u8, pData: Ptr, xDestructor: ?*const fn (Ptr) callconv(.c) void) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    var pp: *align(1) Ptr = @ptrCast(base(db) + O_pDbData);
    var p = rd(Ptr, db, O_pDbData);
    while (p) |pcur| {
        const pName: ?[*:0]const u8 = @ptrCast(base(pcur) + DCD_zName);
        if (strcmp(pName.?, zName.?) == 0) break;
        pp = @ptrCast(base(pcur) + DCD_pNext);
        p = rd(Ptr, pcur, DCD_pNext);
    }
    if (p) |pcur| {
        const xd: ?*const fn (Ptr) callconv(.c) void = @ptrCast(rd(Ptr, pcur, DCD_xDestructor));
        if (xd) |f| f(rd(Ptr, pcur, DCD_pData));
        if (pData == null) {
            pp.* = rd(Ptr, pcur, DCD_pNext);
            sqlite3_free(pcur);
            sqlite3_mutex_leave(dbMutex(db));
            return SQLITE_OK;
        }
    } else if (pData == null) {
        sqlite3_mutex_leave(dbMutex(db));
        return SQLITE_OK;
    } else {
        const n = strlen(zName.?);
        const pnew = sqlite3_malloc64(24 + @as(u64, n) + 1); // SZ_DBCLIENTDATA(n+1)
        if (pnew == null) {
            if (xDestructor) |f| f(pData);
            sqlite3_mutex_leave(dbMutex(db));
            return SQLITE_NOMEM;
        }
        _ = memcpy(base(pnew) + DCD_zName, zName, n + 1);
        wr(Ptr, pnew, DCD_pNext, rd(Ptr, db, O_pDbData));
        wr(Ptr, db, O_pDbData, pnew);
        p = pnew;
    }
    wr(Ptr, p, DCD_pData, pData);
    wr(Ptr, p, DCD_xDestructor, if (xDestructor) |x| @ptrCast(@constCast(x)) else null);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

export fn sqlite3_global_recover() callconv(.c) c_int {
    return SQLITE_OK;
}

export fn sqlite3_get_autocommit(db: Ptr) callconv(.c) c_int {
    return base(db)[O_autoCommit];
}

// ═══════════════════════════════════════════════════════════════════════════
// Error reporting helpers (all always-defined non-static, except DEBUG ones)
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3ReportError(iErr: c_int, lineno: c_int, zType: ?[*:0]const u8) callconv(.c) c_int {
    sqlite3_log(iErr, "%s at line %d of [%.10s]", zType, lineno, @as([*:0]const u8, @ptrCast(sqlite3_sourceid().? + 20)));
    return iErr;
}
export fn sqlite3CorruptError(lineno: c_int) callconv(.c) c_int {
    return sqlite3ReportError(SQLITE_CORRUPT, lineno, "database corruption");
}
export fn sqlite3MisuseError(lineno: c_int) callconv(.c) c_int {
    return sqlite3ReportError(SQLITE_MISUSE, lineno, "misuse");
}
export fn sqlite3CantopenError(lineno: c_int) callconv(.c) c_int {
    return sqlite3ReportError(SQLITE_CANTOPEN, lineno, "cannot open file");
}

// SQLITE_DEBUG || SQLITE_ENABLE_CORRUPT_PGNO → sqlite3CorruptPgnoError
// SQLITE_DEBUG → sqlite3NomemError / sqlite3IoerrnomemError
fn corruptPgnoError(lineno: c_int, pgno: u32) callconv(.c) c_int {
    var zMsg: [100]u8 = undefined;
    _ = sqlite3_snprintf(100, &zMsg, "database corruption page %d", pgno);
    return sqlite3ReportError(SQLITE_CORRUPT, lineno, @ptrCast(&zMsg));
}
fn nomemError(lineno: c_int) callconv(.c) c_int {
    return sqlite3ReportError(SQLITE_NOMEM, lineno, "OOM");
}
fn ioerrnomemError(lineno: c_int) callconv(.c) c_int {
    return sqlite3ReportError(SQLITE_IOERR_NOMEM, lineno, "I/O OOM error");
}
comptime {
    if (config.sqlite_debug) {
        @export(&corruptPgnoError, .{ .name = "sqlite3CorruptPgnoError" });
        @export(&nomemError, .{ .name = "sqlite3NomemError" });
        @export(&ioerrnomemError, .{ .name = "sqlite3IoerrnomemError" });
    }
}
// In tf builds nomemBkpt() references sqlite3NomemError (the exported symbol).
extern fn sqlite3NomemError(lineno: c_int) c_int;

export fn sqlite3_thread_cleanup() callconv(.c) void {}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_limit
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_limit(db: Ptr, limitId: c_int, newLimit: c_int) callconv(.c) c_int {
    if (limitId < 0 or limitId >= SQLITE_N_LIMIT) return -1;
    const aLimit = off("sqlite3_aLimit", 136);
    const lp: *align(1) c_int = @ptrCast(base(db) + aLimit + @as(usize, @intCast(limitId)) * 4);
    const oldLimit = lp.*;
    var nl = newLimit;
    if (nl >= 0) {
        if (nl > aHardLimit[@intCast(limitId)]) {
            nl = aHardLimit[@intCast(limitId)];
        } else if (nl < SQLITE_MIN_LENGTH and limitId == SQLITE_LIMIT_LENGTH) {
            nl = SQLITE_MIN_LENGTH;
        }
        lp.* = nl;
    }
    return oldLimit;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_sleep / extended_result_codes
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_sleep(ms: c_int) callconv(.c) c_int {
    const pVfs = sqlite3_vfs_find(null);
    if (pVfs == null) return 0;
    return @divTrunc(sqlite3OsSleep(pVfs, if (ms < 0) 0 else 1000 * ms), 1000);
}

export fn sqlite3_extended_result_codes(db: Ptr, onoff: c_int) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    wr(c_int, db, O_errMask, if (onoff != 0) @bitCast(@as(u32, 0xffffffff)) else 0xff);
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_table_column_metadata
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_table_column_metadata(
    db: Ptr,
    zDbName: ?[*:0]const u8,
    zTableName: ?[*:0]const u8,
    zColumnName: ?[*:0]const u8,
    pzDataType: ?*?[*:0]const u8,
    pzCollSeq: ?*?[*:0]const u8,
    pNotNull: ?*c_int,
    pPrimaryKey: ?*c_int,
    pAutoinc: ?*c_int,
) callconv(.c) c_int {
    var zErrMsg: ?[*:0]u8 = null;
    var pTab: Ptr = null;
    var pCol: Ptr = null;
    var iCol: c_int = 0;
    var zDataType: ?[*:0]const u8 = null;
    var zCollSeq: ?[*:0]const u8 = null;
    var notnull: c_int = 0;
    var primarykey: c_int = 0;
    var autoinc: c_int = 0;

    sqlite3_mutex_enter(dbMutex(db));
    sqlite3BtreeEnterAll(db);
    var rc = sqlite3Init(db, &zErrMsg);
    if (rc != SQLITE_OK) {
        // error_out
    } else blk: {
        pTab = sqlite3FindTable(db, zTableName, zDbName);
        if (pTab == null or base(pTab)[Tab_eTabType] == TABTYP_VIEW) {
            pTab = null;
            break :blk;
        }
        if (zColumnName == null) {
            // existence-of-table only
        } else {
            iCol = sqlite3ColumnIndex(pTab, zColumnName);
            if (iCol >= 0) {
                pCol = colAt(pTab, iCol);
            } else {
                if (hasRowid(pTab) and sqlite3IsRowid(zColumnName) != 0) {
                    iCol = rd(i16, pTab, Tab_iPKey);
                    pCol = if (iCol >= 0) colAt(pTab, iCol) else null;
                } else {
                    pTab = null;
                    break :blk;
                }
            }
        }
        if (pCol != null) {
            zDataType = sqlite3ColumnType(pCol, null);
            zCollSeq = sqlite3ColumnColl(pCol);
            notnull = if ((base(pCol)[Col_notNull_byte] & 0x0f) != 0) 1 else 0;
            primarykey = if ((rd(u16, pCol, Col_colFlags) & COLFLAG_PRIMKEY) != 0) 1 else 0;
            autoinc = if (rd(i16, pTab, Tab_iPKey) == iCol and (rd(u32, pTab, Tab_tabFlags) & TF_Autoincrement) != 0) 1 else 0;
        } else {
            zDataType = "INTEGER";
            primarykey = 1;
        }
        if (zCollSeq == null) zCollSeq = @ptrCast(&sqlite3StrBINARY);
    }

    sqlite3BtreeLeaveAll(db);

    if (pzDataType) |p| p.* = zDataType;
    if (pzCollSeq) |p| p.* = zCollSeq;
    if (pNotNull) |p| p.* = notnull;
    if (pPrimaryKey) |p| p.* = primarykey;
    if (pAutoinc) |p| p.* = autoinc;

    if (rc == SQLITE_OK and pTab == null) {
        sqlite3DbFree(db, zErrMsg);
        zErrMsg = sqlite3MPrintf(db, "no such table column: %s.%s", zTableName, zColumnName);
        rc = SQLITE_ERROR;
    }
    sqlite3ErrorWithMsg(db, rc, if (zErrMsg != null) "%s" else null, zErrMsg);
    sqlite3DbFree(db, zErrMsg);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}
const TABTYP_VIEW: u8 = 2;
// Table.aCol is a Column* ; element i = aCol + i*sizeof(Column)
inline fn colAt(pTab: Ptr, i: c_int) Ptr {
    const aCol = rd(Ptr, pTab, Tab_aCol);
    return @ptrCast(base(aCol) + @as(usize, @intCast(i)) * sizeof_Column);
}
// HasRowid(X): (X->tabFlags & TF_WithoutRowid)==0
const TF_WithoutRowid: u32 = 0x00000080;
inline fn hasRowid(pTab: Ptr) bool {
    return (rd(u32, pTab, Tab_tabFlags) & TF_WithoutRowid) == 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_file_control
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_file_control(db: Ptr, zDbName: ?[*:0]const u8, op: c_int, pArg: Ptr) callconv(.c) c_int {
    var rc: c_int = SQLITE_ERROR;
    sqlite3_mutex_enter(dbMutex(db));
    const pBtree = sqlite3DbNameToBtree(db, zDbName);
    if (pBtree != null) {
        sqlite3BtreeEnter(pBtree);
        const pPager = sqlite3BtreePager(pBtree);
        const fd = sqlite3PagerFile(pPager);
        if (op == SQLITE_FCNTL_FILE_POINTER) {
            const p: *align(1) Ptr = @ptrCast(pArg.?);
            p.* = fd;
            rc = SQLITE_OK;
        } else if (op == SQLITE_FCNTL_VFS_POINTER) {
            const p: *align(1) Ptr = @ptrCast(pArg.?);
            p.* = sqlite3PagerVfs(pPager);
            rc = SQLITE_OK;
        } else if (op == SQLITE_FCNTL_JOURNAL_POINTER) {
            const p: *align(1) Ptr = @ptrCast(pArg.?);
            p.* = sqlite3PagerJrnlFile(pPager);
            rc = SQLITE_OK;
        } else if (op == SQLITE_FCNTL_DATA_VERSION) {
            const p: *align(1) c_uint = @ptrCast(pArg.?);
            p.* = sqlite3PagerDataVersion(pPager);
            rc = SQLITE_OK;
        } else if (op == SQLITE_FCNTL_RESERVE_BYTES) {
            const p: *align(1) c_int = @ptrCast(pArg.?);
            const iNew = p.*;
            p.* = sqlite3BtreeGetRequestedReserve(pBtree);
            if (iNew >= 0 and iNew <= 255) {
                _ = sqlite3BtreeSetPageSize(pBtree, 0, iNew, 0);
            }
            rc = SQLITE_OK;
        } else if (op == SQLITE_FCNTL_RESET_CACHE) {
            sqlite3BtreeClearCache(pBtree);
            rc = SQLITE_OK;
        } else {
            const nSave = rd(c_int, base(db) + O_busyHandler, BH_nBusy);
            rc = sqlite3OsFileControl(fd, op, pArg);
            wr(c_int, base(db) + O_busyHandler, BH_nBusy, nSave);
        }
        sqlite3BtreeLeave(pBtree);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3ParseUri
// ═══════════════════════════════════════════════════════════════════════════
const OpenMode = struct { z: ?[*:0]const u8, mode: c_uint };

export fn sqlite3ParseUri(
    zDefaultVfs: ?[*:0]const u8,
    zUri: [*:0]const u8,
    pFlags: *c_uint,
    ppVfs: *Ptr,
    pzFile: *?[*:0]u8,
    pzErrMsg: *?[*:0]u8,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var flags: c_uint = pFlags.*;
    var zVfs: ?[*:0]const u8 = zDefaultVfs;
    var zFile: ?[*]u8 = null;
    const nUri: i64 = @intCast(strlen(zUri));

    if (((flags & SQLITE_OPEN_URI) != 0 or @atomicLoad(u8, @as(*u8, @ptrCast(cfg() + C_bOpenUri)), .seq_cst) != 0) and nUri >= 5 and memcmp(zUri, "file:", 5) == 0) {
        var eState: c_int = 0;
        var iIn: i64 = 0;
        var iOut: i64 = 0;
        var nByte: u64 = @intCast(nUri + 8);

        flags |= SQLITE_OPEN_URI;

        iIn = 0;
        while (iIn < nUri) : (iIn += 1) {
            if (zUri[@intCast(iIn)] == '&') nByte += 1;
        }
        const zAlloc = sqlite3_malloc64(nByte);
        if (zAlloc == null) return nomemBkpt();
        var zf: [*]u8 = @ptrCast(zAlloc.?);
        _ = memset(zf, 0, 4);
        zf += 4;
        zFile = zf;

        iIn = 5;
        // Discard scheme/authority (SQLITE_ALLOW_URI_AUTHORITY off)
        if (zUri[5] == '/' and zUri[6] == '/') {
            iIn = 7;
            while (zUri[@intCast(iIn)] != 0 and zUri[@intCast(iIn)] != '/') iIn += 1;
            if (iIn != 7 and (iIn != 16 or memcmp("localhost", zUri + 7, 9) != 0)) {
                pzErrMsg.* = sqlite3_mprintf("invalid uri authority: %.*s", @as(c_int, @intCast(iIn - 7)), zUri + 7);
                rc = SQLITE_ERROR;
                return parseUriOut(rc, zFile, pFlags, pzFile, flags);
            }
        }

        var c: u8 = zUri[@intCast(iIn)];
        while (c != 0 and c != '#') : (c = zUri[@intCast(iIn)]) {
            iIn += 1;
            if (c == '%' and sqlite3Isxdigit(zUri[@intCast(iIn)]) != 0 and sqlite3Isxdigit(zUri[@intCast(iIn + 1)]) != 0) {
                var octet: c_int = sqlite3HexToInt(zUri[@intCast(iIn)]) << 4;
                iIn += 1;
                octet += sqlite3HexToInt(zUri[@intCast(iIn)]);
                iIn += 1;
                if (octet == 0) {
                    // %00: ignore remainder of current path/name/value (URI_00_ERROR off)
                    while (true) {
                        const cc = zUri[@intCast(iIn)];
                        if (cc == 0 or cc == '#') break;
                        if (eState == 0 and cc == '?') break;
                        if (eState == 1 and (cc == '=' or cc == '&')) break;
                        if (eState == 2 and cc == '&') break;
                        iIn += 1;
                    }
                    continue;
                }
                c = @intCast(octet);
            } else if (eState == 1 and (c == '&' or c == '=')) {
                if (zf[@intCast(iOut - 1)] == 0) {
                    while (zUri[@intCast(iIn)] != 0 and zUri[@intCast(iIn)] != '#' and zUri[@intCast(iIn - 1)] != '&') iIn += 1;
                    continue;
                }
                if (c == '&') {
                    zf[@intCast(iOut)] = 0;
                    iOut += 1;
                } else {
                    eState = 2;
                }
                c = 0;
            } else if ((eState == 0 and c == '?') or (eState == 2 and c == '&')) {
                c = 0;
                eState = 1;
            }
            zf[@intCast(iOut)] = c;
            iOut += 1;
        }
        if (eState == 1) {
            zf[@intCast(iOut)] = 0;
            iOut += 1;
        }
        _ = memset(zf + @as(usize, @intCast(iOut)), 0, 4);

        // interpret options
        var zOpt: [*]u8 = zf + (strlen(@ptrCast(zf)) + 1);
        while (zOpt[0] != 0) {
            const nOpt: i64 = @intCast(strlen(@ptrCast(zOpt)));
            const zVal: [*]u8 = zOpt + @as(usize, @intCast(nOpt + 1));
            const nVal: i64 = @intCast(strlen(@ptrCast(zVal)));

            if (nOpt == 3 and memcmp("vfs", zOpt, 3) == 0) {
                zVfs = @ptrCast(zVal);
            } else {
                var aMode: ?[]const OpenMode = null;
                var zModeType: ?[*:0]const u8 = null;
                var mask: c_uint = 0;
                var limit: c_uint = 0;
                if (nOpt == 5 and memcmp("cache", zOpt, 5) == 0) {
                    mask = SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_PRIVATECACHE;
                    aMode = &aCacheMode;
                    limit = mask;
                    zModeType = "cache";
                }
                if (nOpt == 4 and memcmp("mode", zOpt, 4) == 0) {
                    mask = SQLITE_OPEN_READONLY | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY;
                    aMode = &aOpenMode;
                    limit = mask & flags;
                    zModeType = "access";
                }
                if (aMode) |am| {
                    var mode: c_uint = 0;
                    for (am) |m| {
                        if (m.z == null) break;
                        const z = m.z.?;
                        if (nVal == @as(i64, @intCast(strlen(z))) and memcmp(zVal, z, @intCast(nVal)) == 0) {
                            mode = m.mode;
                            break;
                        }
                    }
                    if (mode == 0) {
                        pzErrMsg.* = sqlite3_mprintf("no such %s mode: %s", zModeType, zVal);
                        rc = SQLITE_ERROR;
                        return parseUriOut(rc, zFile, pFlags, pzFile, flags);
                    }
                    if ((mode & ~SQLITE_OPEN_MEMORY) > limit) {
                        pzErrMsg.* = sqlite3_mprintf("%s mode not allowed: %s", zModeType, zVal);
                        rc = SQLITE_PERM;
                        return parseUriOut(rc, zFile, pFlags, pzFile, flags);
                    }
                    flags = (flags & ~mask) | mode;
                }
            }
            zOpt = zVal + @as(usize, @intCast(nVal + 1));
        }
    } else {
        const zAlloc = sqlite3_malloc64(@intCast(nUri + 8));
        if (zAlloc == null) return nomemBkpt();
        var zf: [*]u8 = @ptrCast(zAlloc.?);
        _ = memset(zf, 0, 4);
        zf += 4;
        zFile = zf;
        if (nUri != 0) {
            _ = memcpy(zf, zUri, @intCast(nUri));
        }
        _ = memset(zf + @as(usize, @intCast(nUri)), 0, 4);
        flags &= ~SQLITE_OPEN_URI;
    }

    ppVfs.* = sqlite3_vfs_find(zVfs);
    if (ppVfs.* == null) {
        pzErrMsg.* = sqlite3_mprintf("no such vfs: %s", zVfs);
        rc = SQLITE_ERROR;
    }
    return parseUriOut(rc, zFile, pFlags, pzFile, flags);
}

const aCacheMode = [_]OpenMode{
    .{ .z = "shared", .mode = SQLITE_OPEN_SHAREDCACHE },
    .{ .z = "private", .mode = SQLITE_OPEN_PRIVATECACHE },
    .{ .z = null, .mode = 0 },
};
const aOpenMode = [_]OpenMode{
    .{ .z = "ro", .mode = SQLITE_OPEN_READONLY },
    .{ .z = "rw", .mode = SQLITE_OPEN_READWRITE },
    .{ .z = "rwc", .mode = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE },
    .{ .z = "memory", .mode = SQLITE_OPEN_MEMORY },
    .{ .z = null, .mode = 0 },
};

fn parseUriOut(rc: c_int, zFile: ?[*]u8, pFlags: *c_uint, pzFile: *?[*:0]u8, flags: c_uint) c_int {
    var zf = zFile;
    if (rc != SQLITE_OK) {
        if (zf) |z| sqlite3_free_filename(@ptrCast(z));
        zf = null;
    }
    pFlags.* = flags;
    pzFile.* = @ptrCast(zf);
    return rc;
}

fn uriParameter(zFilename_in: [*:0]const u8, zParam: [*:0]const u8) ?[*:0]const u8 {
    var zFilename = zFilename_in + @as(usize, @intCast(sqlite3Strlen30(zFilename_in) + 1));
    while (zFilename[0] != 0) {
        const x = strcmp(zFilename, zParam);
        zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
        if (x == 0) return zFilename;
        zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
    }
    return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// openDatabase + open family
// ═══════════════════════════════════════════════════════════════════════════
const Schema_enc_off: usize = off("Schema_enc", 113);
const Schema_schemaFlags_off: usize = off("Schema_schemaFlags", 114);
const DB_SchemaLoaded: u16 = 0x0001;

inline fn schemaEnc(db: Ptr) u8 {
    const sch = dbAtPSchema(db, 0);
    return base(sch)[Schema_enc_off];
}
inline fn setSchemaEnc(db: Ptr, v: u8) void {
    const sch = dbAtPSchema(db, 0);
    base(sch)[Schema_enc_off] = v;
}

const ExtInit = *const fn (Ptr) callconv(.c) c_int;
extern fn sqlite3Fts3Init(db: Ptr) c_int; // SQLITE_ENABLE_FTS3 (via FTS4) — was dropped
extern fn sqlite3Fts5Init(db: Ptr) c_int;
extern fn sqlite3RtreeInit(db: Ptr) c_int;
extern fn sqlite3DbpageRegister(db: Ptr) c_int;
extern fn sqlite3DbstatRegister(db: Ptr) c_int;
extern fn sqlite3StmtVtabInit(db: Ptr) c_int;
extern fn sqlite3VdbeBytecodeVtabInit(db: Ptr) c_int;
fn sqlite3TestExtInit(db: Ptr) callconv(.c) c_int {
    _ = db;
    return sqlite3FaultSim(500);
}
// Order matches C sqlite3BuiltinExtensions[] for this build's flags.
const sqlite3BuiltinExtensions = [_]ExtInit{
    sqlite3Fts3Init,
    sqlite3Fts5Init,
    sqlite3RtreeInit,
    sqlite3DbpageRegister,
    sqlite3DbstatRegister,
    sqlite3TestExtInit,
    sqlite3StmtVtabInit,
    sqlite3VdbeBytecodeVtabInit,
};

const sizeof_sqlite3: u64 = off("sizeof_sqlite3", 816);
extern const sqlite3StdType: u8; // const char *sqlite3StdType[]; any string-ptr array

// The built-in default flags ORed into db->flags at open (config-fixed subset).
// DQS=0 ⇒ neither DqsDML/DqsDDL; AutoIndex on; LegacyFileFmt on (DEFAULT_FILE_FORMAT<4);
// RecTriggers on (DEFAULT_RECURSIVE_TRIGGERS default 1).
const openDefaultFlags: u64 = SQLITE_ShortColNames | SQLITE_EnableTrigger |
    SQLITE_EnableView | SQLITE_CacheSpill | SQLITE_AttachCreate |
    SQLITE_AttachWrite | SQLITE_Comments | SQLITE_TrustedSchema |
    SQLITE_AutoIndex | SQLITE_LegacyFileFmt | SQLITE_RecTriggers;

fn openDatabase(zFilename_in: ?[*:0]const u8, ppDb: *Ptr, flags_in: c_uint, zVfs: ?[*:0]const u8) c_int {
    var zFilename = zFilename_in;
    var flags = flags_in;
    var rc: c_int = undefined;
    var isThreadsafe: c_int = undefined;
    var zOpen: ?[*:0]u8 = null;
    var zErrMsg: ?[*:0]u8 = null;
    var db: Ptr = null;

    ppDb.* = null;
    rc = sqlite3_initialize();
    if (rc != 0) return rc;

    if (cfgRd(u8, C_bCoreMutex) == 0) {
        isThreadsafe = 0;
    } else if ((flags & SQLITE_OPEN_NOMUTEX) != 0) {
        isThreadsafe = 0;
    } else if ((flags & SQLITE_OPEN_FULLMUTEX) != 0) {
        isThreadsafe = 1;
    } else {
        isThreadsafe = cfgRd(u8, C_bFullMutex);
    }

    if ((flags & SQLITE_OPEN_PRIVATECACHE) != 0) {
        flags &= ~SQLITE_OPEN_SHAREDCACHE;
    } else if (cfgRd(c_int, C_sharedCacheEnabled) != 0) {
        flags |= SQLITE_OPEN_SHAREDCACHE;
    }

    flags &= ~(SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_MAIN_DB |
        SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TRANSIENT_DB | SQLITE_OPEN_MAIN_JOURNAL |
        SQLITE_OPEN_TEMP_JOURNAL | SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL |
        SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_WAL);

    db = sqlite3MallocZero(sizeof_sqlite3);
    if (db == null) return finishOpen(db, ppDb, &zOpen, zFilename);
    if (isThreadsafe != 0) {
        wr(Ptr, db, O_mutex, sqlite3MutexAlloc(SQLITE_MUTEX_RECURSIVE));
        if (dbMutex(db) == null) {
            sqlite3_free(db);
            db = null;
            return finishOpen(db, ppDb, &zOpen, zFilename);
        }
    }
    sqlite3_mutex_enter(dbMutex(db));
    wr(c_int, db, O_errMask, if ((flags & SQLITE_OPEN_EXRESCODE) != 0) @bitCast(@as(u32, 0xffffffff)) else 0xff);
    wr(c_int, db, O_nDb, 2);
    base(db)[O_eOpenState_] = SQLITE_STATE_BUSY;
    wr(Ptr, db, O_aDb, @ptrCast(base(db) + O_aDbStatic));
    laWr(u32, db, LA_bDisable, 1);
    laWr(u16, db, LA_sz, 0);
    base(db)[O_nFpDigit] = 17;

    _ = memcpy(base(db) + off("sqlite3_aLimit", 136), &aHardLimit, @sizeOf(@TypeOf(aHardLimit)));
    {
        const lp: *align(1) c_int = @ptrCast(base(db) + off("sqlite3_aLimit", 136) + @as(usize, @intCast(SQLITE_LIMIT_WORKER_THREADS)) * 4);
        lp.* = SQLITE_DEFAULT_WORKER_THREADS;
    }
    base(db)[O_autoCommit] = 1;
    base(db)[O_nextAutovac] = @bitCast(@as(i8, -1));
    wr(i64, db, O_szMmap, cfgRd(i64, C_szMmap));
    wr(c_int, db, O_nextPagesize, 0);
    wr(Ptr, db, O_init_azInit, @ptrCast(@constCast(&sqlite3StdType)));

    dbSetFlags(db, dbFlags(db) | openDefaultFlags);

    sqlite3HashInit(base(db) + O_aCollSeq);
    sqlite3HashInit(base(db) + O_aModule);

    _ = createCollation(db, @ptrCast(&sqlite3StrBINARY), @intCast(SQLITE_UTF8), null, @ptrCast(@constCast(&binCollFunc)), null);
    _ = createCollation(db, @ptrCast(&sqlite3StrBINARY), @intCast(SQLITE_UTF16BE), null, @ptrCast(@constCast(&binCollFunc)), null);
    _ = createCollation(db, @ptrCast(&sqlite3StrBINARY), @intCast(SQLITE_UTF16LE), null, @ptrCast(@constCast(&binCollFunc)), null);
    _ = createCollation(db, "NOCASE", @intCast(SQLITE_UTF8), null, @ptrCast(@constCast(&nocaseCollatingFunc)), null);
    _ = createCollation(db, "RTRIM", @intCast(SQLITE_UTF8), null, @ptrCast(@constCast(&rtrimCollFunc)), null);
    if (dbMallocFailed(db)) return finishOpen(db, ppDb, &zOpen, zFilename);

    wr(c_uint, db, O_openFlags, flags);
    if (((@as(c_uint, 1) << @intCast(flags & 7)) & 0x46) == 0) {
        rc = misuseBkpt();
    } else {
        if (zFilename == null) zFilename = ":memory:";
        rc = sqlite3ParseUri(zVfs, zFilename.?, &flags, @alignCast(@ptrCast(base(db) + O_pVfs)), &zOpen, &zErrMsg);
    }
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_NOMEM) _ = sqlite3OomFault(db);
        sqlite3ErrorWithMsg(db, rc, if (zErrMsg != null) "%s" else null, zErrMsg);
        sqlite3_free(zErrMsg);
        return finishOpen(db, ppDb, &zOpen, zFilename);
    }

    rc = sqlite3BtreeOpen(rd(Ptr, db, O_pVfs), zOpen, db, @alignCast(@ptrCast(dbAtPtr(db, 0) + Db_pBt)), 0, @bitCast(flags | SQLITE_OPEN_MAIN_DB));
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_IOERR_NOMEM) rc = nomemBkpt();
        sqlite3Error(db, rc);
        return finishOpen(db, ppDb, &zOpen, zFilename);
    }
    sqlite3BtreeEnter(dbAtPBt(db, 0));
    {
        const p: *align(1) Ptr = @ptrCast(dbAtPtr(db, 0) + Db_pSchema);
        p.* = sqlite3SchemaGet(db, dbAtPBt(db, 0));
    }
    if (!dbMallocFailed(db)) {
        sqlite3SetTextEncoding(db, schemaEnc(db));
    }
    sqlite3BtreeLeave(dbAtPBt(db, 0));
    {
        const p: *align(1) Ptr = @ptrCast(dbAtPtr(db, 1) + Db_pSchema);
        p.* = sqlite3SchemaGet(db, null);
    }

    {
        const d0 = dbAtPtr(db, 0);
        const z0: *align(1) Ptr = @ptrCast(d0 + Db_zDbSName);
        z0.* = @ptrCast(@constCast("main"));
        d0[Db_safety_level] = @intCast(SQLITE_DEFAULT_SYNCHRONOUS + 1);
        const d1 = dbAtPtr(db, 1);
        const z1: *align(1) Ptr = @ptrCast(d1 + Db_zDbSName);
        z1.* = @ptrCast(@constCast("temp"));
        d1[Db_safety_level] = @intCast(PAGER_SYNCHRONOUS_OFF);
    }

    base(db)[O_eOpenState_] = SQLITE_STATE_OPEN;
    if (dbMallocFailed(db)) return finishOpen(db, ppDb, &zOpen, zFilename);

    sqlite3Error(db, SQLITE_OK);
    sqlite3RegisterPerConnectionBuiltinFunctions(db);
    rc = sqlite3_errcode(db);

    var i: usize = 0;
    while (rc == SQLITE_OK and i < sqlite3BuiltinExtensions.len) : (i += 1) {
        rc = sqlite3BuiltinExtensions[i](db);
    }
    if (rc == SQLITE_OK) {
        sqlite3AutoLoadExtensions(db);
        rc = sqlite3_errcode(db);
        if (rc != SQLITE_OK) return finishOpen(db, ppDb, &zOpen, zFilename);
    }

    if (rc != 0) sqlite3Error(db, rc);

    _ = setupLookaside(db, null, cfgRd(c_int, C_szLookaside), cfgRd(c_int, C_nLookaside));
    _ = sqlite3_wal_autocheckpoint(db, SQLITE_DEFAULT_WAL_AUTOCHECKPOINT);

    return finishOpen(db, ppDb, &zOpen, zFilename);
}

// Emulates the opendb_out: label.
fn finishOpen(db_in: Ptr, ppDb: *Ptr, zOpen: *?[*:0]u8, zFilename: ?[*:0]const u8) c_int {
    _ = zFilename;
    var db = db_in;
    if (db != null) {
        sqlite3_mutex_leave(dbMutex(db));
    }
    const rc = sqlite3_errcode(db);
    if ((rc & 0xff) == SQLITE_NOMEM) {
        _ = sqlite3_close(db);
        db = null;
    } else if (rc != SQLITE_OK) {
        base(db)[O_eOpenState_] = SQLITE_STATE_SICK;
    }
    ppDb.* = db;
    sqlite3_free_filename(@ptrCast(zOpen.*));
    return rc;
}



export fn sqlite3_open(zFilename: ?[*:0]const u8, ppDb: *Ptr) callconv(.c) c_int {
    return openDatabase(zFilename, ppDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, null);
}
export fn sqlite3_open_v2(filename: ?[*:0]const u8, ppDb: *Ptr, flags: c_int, zVfs: ?[*:0]const u8) callconv(.c) c_int {
    return openDatabase(filename, ppDb, @bitCast(flags), zVfs);
}
export fn sqlite3_open16(zFilename_in: ?*const anyopaque, ppDb: *Ptr) callconv(.c) c_int {
    var zFilename = zFilename_in;
    ppDb.* = null;
    var rc = sqlite3_initialize();
    if (rc != 0) return rc;
    if (zFilename == null) zFilename = @ptrCast("\x00\x00");
    const pVal = sqlite3ValueNew(null);
    sqlite3ValueSetStr(pVal, -1, zFilename, SQLITE_UTF16NATIVE, null); // SQLITE_STATIC == 0
    const zFilename8 = sqlite3ValueText(pVal, @intCast(SQLITE_UTF8));
    if (zFilename8 != null) {
        rc = openDatabase(zFilename8, ppDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, null);
        if (rc == SQLITE_OK and (rd(u16, dbAtPSchema(ppDb.*, 0), Schema_schemaFlags_off) & DB_SchemaLoaded) == 0) {
            setSchemaEnc(ppDb.*, SQLITE_UTF16NATIVE);
            base(ppDb.*)[O_enc] = SQLITE_UTF16NATIVE;
        }
    } else {
        rc = nomemBkpt();
    }
    sqlite3ValueFree(pVal);
    return rc & 0xff;
}

// ═══════════════════════════════════════════════════════════════════════════
// Filename helpers (databaseName / create_filename / free_filename / uri_*)
// ═══════════════════════════════════════════════════════════════════════════
fn databaseName(zName_in: [*:0]const u8) [*:0]const u8 {
    var z: [*]const u8 = @ptrCast(zName_in);
    // Scan backward to the byte following 4 consecutive 0x00 bytes.
    while ((z - 1)[0] != 0 or (z - 2)[0] != 0 or (z - 3)[0] != 0 or (z - 4)[0] != 0) {
        z -= 1;
    }
    return @ptrCast(z);
}
fn appendText(p: [*]u8, z: [*:0]const u8) [*]u8 {
    const n = strlen(z);
    _ = memcpy(p, z, n + 1);
    return p + n + 1;
}

export fn sqlite3_create_filename(zDatabase: [*:0]const u8, zJournal: [*:0]const u8, zWal: [*:0]const u8, nParam: c_int, azParam: [*]const [*:0]const u8) callconv(.c) ?[*:0]const u8 {
    var nByte: i64 = @intCast(strlen(zDatabase) + strlen(zJournal) + strlen(zWal) + 10);
    var i: usize = 0;
    while (i < @as(usize, @intCast(nParam * 2))) : (i += 1) {
        nByte += @intCast(strlen(azParam[i]) + 1);
    }
    const pResult = sqlite3_malloc64(@intCast(nByte));
    if (pResult == null) return null;
    var p: [*]u8 = @ptrCast(pResult.?);
    const pStart = p;
    _ = memset(p, 0, 4);
    p += 4;
    p = appendText(p, zDatabase);
    i = 0;
    while (i < @as(usize, @intCast(nParam * 2))) : (i += 1) {
        p = appendText(p, azParam[i]);
    }
    p[0] = 0;
    p += 1;
    p = appendText(p, zJournal);
    p = appendText(p, zWal);
    p[0] = 0;
    p += 1;
    p[0] = 0;
    p += 1;
    return @ptrCast(pStart + 4);
}

export fn sqlite3_free_filename(p: ?[*:0]const u8) callconv(.c) void {
    if (p == null) return;
    const z = databaseName(p.?);
    sqlite3_free(@ptrCast(@constCast(@as([*]const u8, @ptrCast(z)) - 4)));
}

export fn sqlite3_uri_parameter(zFilename: ?[*:0]const u8, zParam: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    if (zFilename == null or zParam == null) return null;
    return uriParameter(databaseName(zFilename.?), zParam.?);
}
export fn sqlite3_uri_key(zFilename_in: ?[*:0]const u8, N_in: c_int) callconv(.c) ?[*:0]const u8 {
    if (zFilename_in == null or N_in < 0) return null;
    var N = N_in;
    var zFilename = databaseName(zFilename_in.?);
    zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
    while (zFilename[0] != 0 and N > 0) {
        N -= 1;
        zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
        zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
    }
    return if (zFilename[0] != 0) zFilename else null;
}
export fn sqlite3_uri_boolean(zFilename: ?[*:0]const u8, zParam: ?[*:0]const u8, bDflt: c_int) callconv(.c) c_int {
    const z = sqlite3_uri_parameter(zFilename, zParam);
    const d: c_int = if (bDflt != 0) 1 else 0;
    return if (z != null) sqlite3GetBoolean(z, @intCast(d)) else d;
}
export fn sqlite3_uri_int64(zFilename: ?[*:0]const u8, zParam: ?[*:0]const u8, bDflt: i64) callconv(.c) i64 {
    const z = sqlite3_uri_parameter(zFilename, zParam);
    var v: i64 = undefined;
    if (z != null and sqlite3DecOrHexToI64(z, &v) == 0) {
        return v;
    }
    return bDflt;
}
export fn sqlite3_filename_database(zFilename: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    if (zFilename == null) return null;
    return databaseName(zFilename.?);
}
export fn sqlite3_filename_journal(zFilename_in: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    if (zFilename_in == null) return null;
    var zFilename = databaseName(zFilename_in.?);
    zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
    while (zFilename[0] != 0) {
        zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
        zFilename = zFilename + @as(usize, @intCast(sqlite3Strlen30(zFilename) + 1));
    }
    return zFilename + 1;
}
export fn sqlite3_filename_wal(zFilename_in: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    var zFilename = sqlite3_filename_journal(zFilename_in);
    if (zFilename) |z| {
        zFilename = z + @as(usize, @intCast(sqlite3Strlen30(z) + 1));
    }
    return zFilename;
}

// ═══════════════════════════════════════════════════════════════════════════
// DbNameToBtree / db_name / db_filename / db_readonly
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3DbNameToBtree(db: Ptr, zDbName: ?[*:0]const u8) callconv(.c) Ptr {
    const iDb: c_int = if (zDbName != null) sqlite3FindDbName(db, zDbName) else 0;
    return if (iDb < 0) null else dbAtPBt(db, iDb);
}
export fn sqlite3_db_name(db: Ptr, N: c_int) callconv(.c) ?[*:0]const u8 {
    if (N < 0 or N >= dbNDb(db)) {
        return null;
    } else {
        const q: *align(1) const ?[*:0]const u8 = @ptrCast(dbAtPtr(db, N) + Db_zDbSName);
        return q.*;
    }
}
export fn sqlite3_db_filename(db: Ptr, zDbName: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    const pBt = sqlite3DbNameToBtree(db, zDbName);
    return if (pBt != null) sqlite3BtreeGetFilename(pBt) else null;
}
export fn sqlite3_db_readonly(db: Ptr, zDbName: ?[*:0]const u8) callconv(.c) c_int {
    const pBt = sqlite3DbNameToBtree(db, zDbName);
    return if (pBt != null) sqlite3BtreeIsReadonly(pBt) else -1;
}

// ═══════════════════════════════════════════════════════════════════════════
// compileoption (SQLITE_OMIT_COMPILEOPTION_DIAGS off)
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3_compileoption_used(zOptName_in: ?[*:0]const u8) callconv(.c) c_int {
    var nOpt: c_int = undefined;
    const azCompileOpt = sqlite3CompileOptions(&nOpt);
    var zOptName = zOptName_in.?;
    if (sqlite3_strnicmp(zOptName, "SQLITE_", 7) == 0) zOptName = zOptName + 7;
    const n = sqlite3Strlen30(zOptName);
    var i: usize = 0;
    while (i < @as(usize, @intCast(nOpt))) : (i += 1) {
        const opt = azCompileOpt.?[i].?;
        if (sqlite3_strnicmp(zOptName, opt, n) == 0 and sqlite3IsIdChar(opt[@intCast(n)]) == 0) {
            return 1;
        }
    }
    return 0;
}
export fn sqlite3_compileoption_get(N: c_int) callconv(.c) ?[*:0]const u8 {
    var nOpt: c_int = undefined;
    const azCompileOpt = sqlite3CompileOptions(&nOpt);
    if (N >= 0 and N < nOpt) {
        return azCompileOpt.?[@intCast(N)];
    }
    return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3_test_control (SQLITE_UNTESTABLE off)
// ═══════════════════════════════════════════════════════════════════════════
const SQLITE_BYTEORDER: c_int = 1234;
const SQLITE_LITTLEENDIAN: c_int = 1;
const SQLITE_BIGENDIAN: c_int = 0;

export fn sqlite3_test_control(op: c_int, ...) callconv(.c) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var rc: c_int = 0;
    switch (op) {
        TC_PRNG_SAVE => sqlite3PrngSaveState(),
        TC_PRNG_RESTORE => sqlite3PrngRestoreState(),
        TC_PRNG_SEED => {
            var x = @cVaArg(&ap, c_int);
            const db = @cVaArg(&ap, Ptr);
            if (db != null) {
                const y = rd(c_int, dbAtPSchema(db, 0), Schema_schema_cookie);
                if (y != 0) x = y;
            }
            cfgWr(c_int, C_iPrngSeed, x);
            sqlite3_randomness(0, null);
        },
        TC_FK_NO_ACTION => {
            const db = @cVaArg(&ap, Ptr);
            const b = @cVaArg(&ap, c_int);
            if (b != 0) {
                dbSetFlags(db, dbFlags(db) | SQLITE_FkNoAction);
            } else {
                dbSetFlags(db, dbFlags(db) & ~SQLITE_FkNoAction);
            }
        },
        TC_BITVEC_TEST => {
            const sz = @cVaArg(&ap, c_int);
            const aProg = @cVaArg(&ap, ?[*]c_int);
            rc = sqlite3BitvecBuiltinTest(sz, aProg);
        },
        TC_FAULT_INSTALL => {
            cfgWr(Ptr, C_xTestCallback, @cVaArg(&ap, Ptr));
            rc = sqlite3FaultSim(0);
        },
        TC_BENIGN_MALLOC_HOOKS => {
            const xBegin = @cVaArg(&ap, Ptr);
            const xEnd = @cVaArg(&ap, Ptr);
            sqlite3BenignMallocHooks(xBegin, xEnd);
        },
        TC_PENDING_BYTE => {
            rc = sqlite3PendingByte;
            const newVal = @cVaArg(&ap, c_uint);
            if (newVal != 0) sqlite3PendingByte = @bitCast(newVal);
        },
        TC_ASSERT => {
            const x = @cVaArg(&ap, c_int);
            // assert(side-effects-ok): in DEBUG, assert fires on 0
            if (config.sqlite_debug) std.debug.assert(x != 0);
            rc = x;
        },
        TC_ALWAYS => {
            const x = @cVaArg(&ap, c_int);
            rc = if (x != 0) x else 0;
        },
        TC_BYTEORDER => {
            rc = SQLITE_BYTEORDER * 100 + SQLITE_LITTLEENDIAN * 10 + SQLITE_BIGENDIAN;
        },
        TC_OPTIMIZATIONS => {
            const db = @cVaArg(&ap, Ptr);
            wr(u32, db, O_dbOptFlags, @cVaArg(&ap, u32));
        },
        TC_GETOPT => {
            const db = @cVaArg(&ap, Ptr);
            const pN = @cVaArg(&ap, *c_int);
            pN.* = @bitCast(rd(u32, db, O_dbOptFlags));
        },
        TC_LOCALTIME_FAULT => {
            cfgWr(c_int, C_bLocaltimeFault, @cVaArg(&ap, c_int));
            if (cfgRd(c_int, C_bLocaltimeFault) == 2) {
                cfgWr(Ptr, C_xAltLocaltime, @cVaArg(&ap, Ptr));
            } else {
                cfgWr(Ptr, C_xAltLocaltime, null);
            }
        },
        TC_INTERNAL_FUNCTIONS => {
            const db = @cVaArg(&ap, Ptr);
            wr(u32, db, O_mDbFlags, rd(u32, db, O_mDbFlags) ^ DBFLAG_InternalFunc);
        },
        TC_NEVER_CORRUPT => {
            cfgWr(c_int, C_neverCorrupt, @cVaArg(&ap, c_int));
        },
        TC_EXTRA_SCHEMA_CHECKS => {
            cfgWr(c_int, C_bExtraSchemaChecks, @cVaArg(&ap, c_int));
        },
        TC_ONCE_RESET_THRESHOLD => {
            cfgWr(c_int, C_iOnceResetThreshold, @cVaArg(&ap, c_int));
        },
        TC_VDBE_COVERAGE => {
            // SQLITE_VDBE_COVERAGE off → consume nothing meaningful (no-op)
        },
        TC_SORTER_MMAP => {
            const db = @cVaArg(&ap, Ptr);
            wr(c_int, db, O_nMaxSorterMmap, @cVaArg(&ap, c_int));
        },
        TC_ISINIT => {
            if (cfgRd(c_int, C_isInit) == 0) rc = SQLITE_ERROR;
        },
        TC_IMPOSTER => {
            const db = @cVaArg(&ap, Ptr);
            sqlite3_mutex_enter(dbMutex(db));
            const iDb = sqlite3FindDbName(db, @cVaArg(&ap, ?[*:0]const u8));
            if (iDb >= 0) {
                base(db)[O_init_iDb] = @intCast(iDb);
                const im = @cVaArg(&ap, c_int);
                base(db)[O_init_busy] = @intCast(im & 0xff);
                // init.imposterTable :2 occupies bits 0x06 of init bitbyte
                const bb = base(db)[O_init_bitbyte];
                base(db)[O_init_bitbyte] = (bb & ~@as(u8, 0x06)) | (@as(u8, @intCast(im & 0x03)) << 1);
                const newTnum = @cVaArg(&ap, c_int);
                wr(u32, db, O_init_newTnum, @bitCast(newTnum));
                if (base(db)[O_init_busy] == 0 and newTnum > 0) {
                    sqlite3ResetAllSchemasOfConnection(db);
                }
            }
            sqlite3_mutex_leave(dbMutex(db));
        },
        TC_RESULT_INTREAL => {
            sqlite3ResultIntReal(@cVaArg(&ap, Ptr));
        },
        TC_SEEK_COUNT => {
            const db = @cVaArg(&ap, Ptr);
            const pn = @cVaArg(&ap, *u64);
            if (config.sqlite_debug) {
                const seekCount = @extern(*const fn (Ptr) callconv(.c) u64, .{ .name = "sqlite3BtreeSeekCount" });
                pn.* = seekCount(dbAtPBt(db, 0));
            } else {
                pn.* = 0;
            }
        },
        TC_TRACEFLAGS => {
            const opTrace = @cVaArg(&ap, c_int);
            const ptr = @cVaArg(&ap, *u32);
            switch (opTrace) {
                0 => ptr.* = sqlite3TreeTrace,
                1 => sqlite3TreeTrace = ptr.*,
                2 => ptr.* = sqlite3WhereTrace,
                3 => sqlite3WhereTrace = ptr.*,
                else => {},
            }
        },
        TC_LOGEST => {
            const rIn = @cVaArg(&ap, f64);
            const rLogEst = sqlite3LogEstFromDouble(rIn);
            const pI1 = @cVaArg(&ap, *c_int);
            const pU64 = @cVaArg(&ap, *u64);
            const pI2 = @cVaArg(&ap, *c_int);
            pI1.* = rLogEst;
            pU64.* = sqlite3LogEstToInt(rLogEst);
            pI2.* = sqlite3LogEst(pU64.*);
        },
        TC_ATOF => {
            const z = @cVaArg(&ap, ?[*:0]const u8);
            const pR = @cVaArg(&ap, *f64);
            rc = sqlite3AtoF(z, pR);
        },
        TC_JSON_SELFCHECK => {
            const pOnOff = @cVaArg(&ap, *c_int);
            if (config.sqlite_debug) {
                if (pOnOff.* < 0) {
                    pOnOff.* = cfgRd(u8, C_bJsonSelfcheck);
                } else {
                    cfgWr(u8, C_bJsonSelfcheck, @truncate(@as(u32, @bitCast(pOnOff.*)) & 0xff));
                }
            }
        },
        else => {},
    }
    return rc;
}
const C_bJsonSelfcheck: usize = off("Sqlite3Config_bJsonSelfcheck", 10);

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3ErrName — only present under SQLITE_NEED_ERR_NAME (== SQLITE_TEST here)
// ═══════════════════════════════════════════════════════════════════════════
fn errName(rc_in: c_int) callconv(.c) ?[*:0]const u8 {
    const origRc = rc_in;
    var rc = rc_in;
    var zName: ?[*:0]const u8 = null;
    var pass: c_int = 0;
    while (pass < 2 and zName == null) : (pass += 1) {
        switch (rc) {
        0 => zName = "SQLITE_OK",
        1 => zName = "SQLITE_ERROR",
        769 => zName = "SQLITE_ERROR_SNAPSHOT",
        513 => zName = "SQLITE_ERROR_RETRY",
        257 => zName = "SQLITE_ERROR_MISSING_COLLSEQ",
        2 => zName = "SQLITE_INTERNAL",
        3 => zName = "SQLITE_PERM",
        4 => zName = "SQLITE_ABORT",
        516 => zName = "SQLITE_ABORT_ROLLBACK",
        5 => zName = "SQLITE_BUSY",
        261 => zName = "SQLITE_BUSY_RECOVERY",
        517 => zName = "SQLITE_BUSY_SNAPSHOT",
        6 => zName = "SQLITE_LOCKED",
        262 => zName = "SQLITE_LOCKED_SHAREDCACHE",
        7 => zName = "SQLITE_NOMEM",
        8 => zName = "SQLITE_READONLY",
        264 => zName = "SQLITE_READONLY_RECOVERY",
        1288 => zName = "SQLITE_READONLY_CANTINIT",
        776 => zName = "SQLITE_READONLY_ROLLBACK",
        1032 => zName = "SQLITE_READONLY_DBMOVED",
        1544 => zName = "SQLITE_READONLY_DIRECTORY",
        9 => zName = "SQLITE_INTERRUPT",
        10 => zName = "SQLITE_IOERR",
        266 => zName = "SQLITE_IOERR_READ",
        522 => zName = "SQLITE_IOERR_SHORT_READ",
        778 => zName = "SQLITE_IOERR_WRITE",
        1034 => zName = "SQLITE_IOERR_FSYNC",
        1290 => zName = "SQLITE_IOERR_DIR_FSYNC",
        1546 => zName = "SQLITE_IOERR_TRUNCATE",
        1802 => zName = "SQLITE_IOERR_FSTAT",
        2058 => zName = "SQLITE_IOERR_UNLOCK",
        2314 => zName = "SQLITE_IOERR_RDLOCK",
        2570 => zName = "SQLITE_IOERR_DELETE",
        3082 => zName = "SQLITE_IOERR_NOMEM",
        3338 => zName = "SQLITE_IOERR_ACCESS",
        3594 => zName = "SQLITE_IOERR_CHECKRESERVEDLOCK",
        3850 => zName = "SQLITE_IOERR_LOCK",
        4106 => zName = "SQLITE_IOERR_CLOSE",
        4362 => zName = "SQLITE_IOERR_DIR_CLOSE",
        4618 => zName = "SQLITE_IOERR_SHMOPEN",
        4874 => zName = "SQLITE_IOERR_SHMSIZE",
        5130 => zName = "SQLITE_IOERR_SHMLOCK",
        5386 => zName = "SQLITE_IOERR_SHMMAP",
        5642 => zName = "SQLITE_IOERR_SEEK",
        5898 => zName = "SQLITE_IOERR_DELETE_NOENT",
        6154 => zName = "SQLITE_IOERR_MMAP",
        6410 => zName = "SQLITE_IOERR_GETTEMPPATH",
        6666 => zName = "SQLITE_IOERR_CONVPATH",
        11 => zName = "SQLITE_CORRUPT",
        267 => zName = "SQLITE_CORRUPT_VTAB",
        12 => zName = "SQLITE_NOTFOUND",
        13 => zName = "SQLITE_FULL",
        14 => zName = "SQLITE_CANTOPEN",
        270 => zName = "SQLITE_CANTOPEN_NOTEMPDIR",
        526 => zName = "SQLITE_CANTOPEN_ISDIR",
        782 => zName = "SQLITE_CANTOPEN_FULLPATH",
        1038 => zName = "SQLITE_CANTOPEN_CONVPATH",
        1550 => zName = "SQLITE_CANTOPEN_SYMLINK",
        15 => zName = "SQLITE_PROTOCOL",
        16 => zName = "SQLITE_EMPTY",
        17 => zName = "SQLITE_SCHEMA",
        18 => zName = "SQLITE_TOOBIG",
        19 => zName = "SQLITE_CONSTRAINT",
        2067 => zName = "SQLITE_CONSTRAINT_UNIQUE",
        1811 => zName = "SQLITE_CONSTRAINT_TRIGGER",
        787 => zName = "SQLITE_CONSTRAINT_FOREIGNKEY",
        275 => zName = "SQLITE_CONSTRAINT_CHECK",
        1555 => zName = "SQLITE_CONSTRAINT_PRIMARYKEY",
        1299 => zName = "SQLITE_CONSTRAINT_NOTNULL",
        531 => zName = "SQLITE_CONSTRAINT_COMMITHOOK",
        2323 => zName = "SQLITE_CONSTRAINT_VTAB",
        1043 => zName = "SQLITE_CONSTRAINT_FUNCTION",
        2579 => zName = "SQLITE_CONSTRAINT_ROWID",
        20 => zName = "SQLITE_MISMATCH",
        21 => zName = "SQLITE_MISUSE",
        22 => zName = "SQLITE_NOLFS",
        23 => zName = "SQLITE_AUTH",
        24 => zName = "SQLITE_FORMAT",
        25 => zName = "SQLITE_RANGE",
        26 => zName = "SQLITE_NOTADB",
        100 => zName = "SQLITE_ROW",
        27 => zName = "SQLITE_NOTICE",
        283 => zName = "SQLITE_NOTICE_RECOVER_WAL",
        539 => zName = "SQLITE_NOTICE_RECOVER_ROLLBACK",
        795 => zName = "SQLITE_NOTICE_RBU",
        28 => zName = "SQLITE_WARNING",
        284 => zName = "SQLITE_WARNING_AUTOINDEX",
        101 => zName = "SQLITE_DONE",            else => {},
        }
        rc &= 0xff;
    }
    if (zName == null) {
        const S = struct {
            threadlocal var zBuf: [50]u8 = undefined;
        };
        _ = sqlite3_snprintf(50, &S.zBuf, "SQLITE_UNKNOWN(%d)", origRc);
        zName = @ptrCast(&S.zBuf);
    }
    return zName;
}
comptime {
    if (config.sqlite_test) {
        @export(&errName, .{ .name = "sqlite3ErrName" });
    }
}
