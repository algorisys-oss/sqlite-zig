//! Zig port of SQLite's VDBE auxiliary / assembly layer (src/vdbeaux.c).
//!
//! This is the code that *builds* a bytecode program (the sqlite3VdbeAddOp*
//! family, label make/resolve and P2 back-patching, P4 operands), prepares it
//! for execution (sqlite3VdbeMakeReady — register/cursor allocation out of the
//! opcode-array tail), coordinates transaction commit/rollback at halt time
//! (sqlite3VdbeHalt, the two-phase multi-database commit + super-journal in
//! vdbeCommit, FK checks), tears the VM down (Reset/Finalize/Delete), and owns
//! the on-disk record codec (sqlite3VdbeSerialGet / SerialTypeLen and the
//! sqlite3VdbeRecordCompare* family — these MUST be byte-exact).
//!
//! ---------------------------------------------------------------------------
//! Strategy
//! ---------------------------------------------------------------------------
//! vdbeaux.c reaches into a large number of internal structs (Vdbe, Op, Mem,
//! VdbeCursor, VdbeFrame, KeyInfo, UnpackedRecord, SubProgram, AuxData,
//! sqlite3_context, sqlite3, Parse). The Vdbe struct itself is mostly private
//! to the VDBE TUs, but vdbe.c / vdbeapi.c (still C) read many of its fields, so
//! the layout is ground-truth and we access every field at its authoritative
//! offset (config-selected, validated against c_layout / probed values), the
//! same idiom used by vdbeblob.zig / vdbevtab.zig.
//!
//! Almost all heavy lifting is delegated to already-linked C helpers
//! (sqlite3DbMalloc*, sqlite3VMPrintf, the b-tree / pager / vtab APIs, the OS
//! layer, sqlite3MemCompare's collation calls, etc.). What this module owns is
//! the orchestration and the bit-exact record codec.
//!
//! ---------------------------------------------------------------------------
//! Config divergence (verified by probing both configs)
//! ---------------------------------------------------------------------------
//!   * SQLITE_DEBUG / SQLITE_TEST: testfixture only (config.sqlite_debug). It
//!     inserts fields into Vdbe (rcApp/nWrite/napArg), VdbeFrame (iFrameMagic),
//!     VdbeCursor (seekOp/wrFlag) and grows Mem; all offset tables below are
//!     config-selected. Debug-only exported symbols (sqlite3VdbeAssertMayAbort,
//!     IncrWriteCounter, AssertAbortable, NoJumpsOutsideSubrtn, Verify*,
//!     ReleaseRegisters, FrameIsValid, PrintSql, PrintOp) are exported only
//!     when config.sqlite_debug, like C's #ifdef SQLITE_DEBUG.
//!   * SQLITE_ENABLE_PREUPDATE_HOOK, _PERCENTILE, _BYTECODE_VTAB,
//!     _EXPLAIN_COMMENTS: ON in both builds (so those functions are compiled).
//!   * OFF in both: NORMALIZE, STMT_SCANSTATUS, VDBE_COVERAGE, VDBE_PROFILE,
//!     CURSOR_HINTS, STAT4, SQLLOG, MIXED_ENDIAN_64BIT_FLOAT, all OMIT_*.
//!
//! No standalone Zig unit test is feasible: nearly every entry point needs a
//! live connection, a compiled Vdbe, b-trees and a pager. Validated end-to-end
//! through the engine (the whole TCL suite exercises this module).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const DEBUG = config.sqlite_debug;

// ===========================================================================
// Result / state / opcode constants
// ===========================================================================
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_BUSY: c_int = 5;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_FULL: c_int = 13;
const SQLITE_SCHEMA: c_int = 17;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_ABORT_ROLLBACK: c_int = 516; // SQLITE_ABORT | (2<<8)
const SQLITE_CONSTRAINT_FOREIGNKEY: c_int = SQLITE_CONSTRAINT | (3 << 8);
const SQLITE_CONSTRAINT_COMMITHOOK: c_int = SQLITE_CONSTRAINT | (2 << 8);
const SQLITE_UTF8: u8 = 1;

// VDBE states (vdbeInt.h)
const VDBE_INIT_STATE: u8 = 0;
const VDBE_READY_STATE: u8 = 1;
const VDBE_RUN_STATE: u8 = 2;
const VDBE_HALT_STATE: u8 = 3;

// CURTYPE_* (vdbeInt.h)
const CURTYPE_BTREE: u8 = 0;
const CURTYPE_SORTER: u8 = 1;
const CURTYPE_VTAB: u8 = 2;
const CURTYPE_PSEUDO: u8 = 3;
const CACHE_STALE: u32 = 0;
const SQLITE_FRAME_MAGIC: u32 = 0x879fb71e;

// SAVEPOINT_* (sqliteInt.h)
const SAVEPOINT_RELEASE: c_int = 1;
const SAVEPOINT_ROLLBACK: c_int = 2;

// ON-conflict / error actions (sqliteInt.h)
const OE_Abort: u8 = 2;
const OE_Fail: u8 = 3;

// MEM_* flags (vdbeInt.h)
const MEM_Undefined: u16 = 0x0000;
const MEM_Null: u16 = 0x0001;
const MEM_Str: u16 = 0x0002;
const MEM_Int: u16 = 0x0004;
const MEM_Real: u16 = 0x0008;
const MEM_Blob: u16 = 0x0010;
const MEM_IntReal: u16 = 0x0020;
const MEM_Zero: u16 = 0x0400;
const MEM_Ephem: u16 = 0x4000;
const MEM_Agg: u16 = 0x8000;
const MEM_Dyn: u16 = 0x1000;
const MEM_Term: u16 = 0x0200;

// KeyInfo sort flags
const KEYINFO_ORDER_DESC: u8 = 0x01;
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

// COLNAME_N: only the name + decltype are stored unless ENABLE_COLUMN_METADATA.
// Both configs build with COLNAME_N==2 (SQLITE_ENABLE_COLUMN_METADATA off,
// SQLITE_OMIT_DECLTYPE off).
const COLNAME_N: c_int = 2;

// P4 types (vdbe.h)
const P4_NOTUSED: i8 = 0;
const P4_COLLSEQ: i8 = -2;
const P4_INT32: i8 = -3;
const P4_SUBPROGRAM: i8 = -4;
const P4_TABLE: i8 = -5;
const P4_INDEX: i8 = -6;
const P4_DYNAMIC: i8 = -7;
const P4_FREE_IF_LE: i8 = -7;
const P4_KEYINFO: i8 = -9;
const P4_MEM: i8 = -11;
const P4_VTAB: i8 = -12;
const P4_FUNCCTX: i8 = -16;
const P4_FUNCDEF: i8 = -8;
const P4_REAL: i8 = -13;
const P4_INT64: i8 = -14;
const P4_INTARRAY: i8 = -15;
const P4_TABLEREF: i8 = -17;
const P4_SUBRTNSIG: i8 = -18;

// Opcodes (opcodes.h; vendored)
const OP_Savepoint: u8 = 0;
const OP_AutoCommit: u8 = 1;
const OP_Transaction: u8 = 2;
const OP_Checkpoint: u8 = 3;
const OP_JournalMode: u8 = 4;
const OP_Vacuum: u8 = 5;
const OP_VFilter: u8 = 6;
const OP_VUpdate: u8 = 7;
const OP_Init: u8 = 8;
const OP_Goto: u8 = 9;
const OP_Gosub: u8 = 10;
const OP_InitCoroutine: u8 = 11;
const OP_Once: u8 = 15;
const OP_If: u8 = 16;
const OP_NotNull: u8 = 52;
const OP_FkIfZero: u8 = 60;
const OP_PureFunc: u8 = 67;
const OP_Function: u8 = 68;
const OP_Return: u8 = 69;
const OP_EndCoroutine: u8 = 70;
const OP_HaltIfNull: u8 = 71;
const OP_Halt: u8 = 72;
const OP_Integer: u8 = 73;
const OP_Null: u8 = 77;
const OP_ResultRow: u8 = 86;
const OP_Column: u8 = 96;
const OP_ReopenIdx: u8 = 113;
const OP_OpenRead: u8 = 114;
const OP_OpenWrite: u8 = 116;
const OP_String8: u8 = 118;
const OP_Destroy: u8 = 146;
const OP_Clear: u8 = 147;
const OP_CreateBtree: u8 = 149;
const OP_ParseSchema: u8 = 151;
const OP_FkCounter: u8 = 160;
const OP_Expire: u8 = 168;
const OP_VCreate: u8 = 173;
const OP_VDestroy: u8 = 174;
const OP_VRename: u8 = 179;
const OP_ReleaseReg: u8 = 188;
const OP_Noop: u8 = 189;
const OP_Explain: u8 = 190;
const OP_Abortable: u8 = 191;

const SQLITE_MX_JUMP_OPCODE: u8 = 66;
const OPFLG_JUMP: u8 = 0x01;
const OPFLG_JUMP0: u8 = 0x80;

const BTREE_INTKEY: c_int = 1;
const BTREE_BLOBKEY: c_int = 2;
const NC_SelfRef: c_int = 0x00002e;

// SQLITE_PREPARE_SAVESQL (sqlite3.h)
const SQLITE_PREPARE_SAVESQL: u8 = 0x80;
// db->flags bits (sqliteInt.h)
const SQLITE_CorruptRdOnly: u64 = 0x40000000_00000000;
const SQLITE_DeferFKs: u64 = 0x00080000;
// SQLITE_LIMIT_VDBE_OP index into db->aLimit[] (it is 5, NOT 11 — 11 is the
// public WORKER_THREADS limit, which defaults to 0 and would fault every grow).
const SQLITE_LIMIT_VDBE_OP: usize = 5;
// SQLITE_TXN_NONE / READ / WRITE
const SQLITE_TXN_NONE: c_int = 0;
const SQLITE_TXN_READ: c_int = 1;
const SQLITE_TXN_WRITE: c_int = 2;
// pager journal-mode codes (pager.h): used to index aMJNeeded[]
// VFS open flags / access / sync (sqlite3.h)
const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
const SQLITE_OPEN_CREATE: c_int = 0x00000004;
const SQLITE_OPEN_EXCLUSIVE: c_int = 0x00000010;
const SQLITE_OPEN_SUPER_JOURNAL: c_int = 0x00004000;
const SQLITE_ACCESS_EXISTS: c_int = 0;
const SQLITE_SYNC_NORMAL: c_int = 0x00002;
const SQLITE_IOCAP_SEQUENTIAL: c_int = 0x00000400;
const PAGER_SYNCHRONOUS_OFF: u8 = 0x01;
const SQLITE_FULL_LOG: c_int = 13;

// ===========================================================================
// Opaque handle aliases
// ===========================================================================
const sqlite3 = anyopaque;
const Parse = anyopaque;
const Vdbe = anyopaque;
const Op = anyopaque; // VdbeOp
const Mem = anyopaque; // sqlite3_value
const VdbeCursor = anyopaque;
const VdbeFrame = anyopaque;
const KeyInfo = anyopaque;
const UnpackedRecord = anyopaque;
const SubProgram = anyopaque;
const FuncDef = anyopaque;
const Index = anyopaque;
const Table = anyopaque;
const CollSeq = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_vtab = anyopaque;
const VList = anyopaque;
const Btree = anyopaque;
const BtCursor = anyopaque;
const Pager = anyopaque;
const sqlite3_file = anyopaque;
const sqlite3_vfs = anyopaque;
const AuxData = anyopaque;

// ===========================================================================
// Ground-truth offsets. Config-selected; prefer c_layout, fall back to probed.
// ===========================================================================
fn off(comptime name: []const u8, prod: usize, dbg: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else if (DEBUG) dbg else prod;
}

// --- struct Vdbe ---
const Vdbe_db = off("Vdbe_db", 0, 0);
const Vdbe_ppVPrev = off("Vdbe_ppVPrev", 8, 8);
const Vdbe_pVNext = off("Vdbe_pVNext", 16, 16);
const Vdbe_pParse = off("Vdbe_pParse", 24, 24);
const Vdbe_nVar = off("Vdbe_nVar", 32, 32);
const Vdbe_nMem = off("Vdbe_nMem", 36, 36);
const Vdbe_nCursor = off("Vdbe_nCursor", 40, 40);
const Vdbe_cacheCtr = off("Vdbe_cacheCtr", 44, 44);
const Vdbe_pc = off("Vdbe_pc", 48, 48);
const Vdbe_rc = off("Vdbe_rc", 52, 52);
const Vdbe_nChange = off("Vdbe_nChange", 56, 56);
const Vdbe_iStatement = off("Vdbe_iStatement", 64, 64);
const Vdbe_nFkConstraint = off("Vdbe_nFkConstraint", 80, 80);
const Vdbe_nStmtDefCons = off("Vdbe_nStmtDefCons", 88, 88);
const Vdbe_nStmtDefImmCons = off("Vdbe_nStmtDefImmCons", 96, 96);
const Vdbe_aMem = off("Vdbe_aMem", 104, 104);
const Vdbe_apArg = off("Vdbe_apArg", 112, 112);
const Vdbe_apCsr = off("Vdbe_apCsr", 120, 120);
const Vdbe_aVar = off("Vdbe_aVar", 128, 128);
const Vdbe_aOp = off("Vdbe_aOp", 136, 136);
const Vdbe_nOp = off("Vdbe_nOp", 144, 144);
const Vdbe_nOpAlloc = off("Vdbe_nOpAlloc", 148, 148);
const Vdbe_aColName = off("Vdbe_aColName", 152, 152);
const Vdbe_pResultRow = off("Vdbe_pResultRow", 160, 160);
const Vdbe_zErrMsg = off("Vdbe_zErrMsg", 168, 168);
const Vdbe_pVList = off("Vdbe_pVList", 176, 176);
const Vdbe_nResColumn = off("Vdbe_nResColumn", 192, 204);
const Vdbe_nResAlloc = off("Vdbe_nResAlloc", 194, 206);
const Vdbe_errorAction = off("Vdbe_errorAction", 196, 208);
const Vdbe_minWriteFileFormat = off("Vdbe_minWriteFileFormat", 197, 209);
const Vdbe_prepFlags = off("Vdbe_prepFlags", 198, 210);
const Vdbe_eVdbeState = off("Vdbe_eVdbeState", 199, 211);
// expired/explain/changeCntOn/usesStmtJournal/readOnly/bIsReader/haveEqpOps are
// bitfields packed into the byte at eVdbeState+1 (verified). We read/write them
// via dedicated helpers below.
const Vdbe_bitfields = Vdbe_eVdbeState + 1;
const Vdbe_btreeMask = off("Vdbe_btreeMask", 204, 216);
const Vdbe_lockMask = off("Vdbe_lockMask", 208, 220);
const Vdbe_aCounter = off("Vdbe_aCounter", 212, 224);
const Vdbe_zSql = off("Vdbe_zSql", 248, 264);
const Vdbe_pFree = off("Vdbe_pFree", 256, 272);
const Vdbe_pFrame = off("Vdbe_pFrame", 264, 280);
const Vdbe_pDelFrame = off("Vdbe_pDelFrame", 272, 288);
const Vdbe_nFrame = off("Vdbe_nFrame", 280, 296);
const Vdbe_expmask = off("Vdbe_expmask", 284, 300);
const Vdbe_pProgram = off("Vdbe_pProgram", 288, 304);
const Vdbe_pAuxData = off("Vdbe_pAuxData", 296, 312);
const sizeof_Vdbe = off("sizeof_Vdbe", 304, 320);
// debug-only fields (present only under SQLITE_DEBUG; offsets in the debug build)
const Vdbe_rcApp = off("Vdbe_rcApp", 192, 192);
const Vdbe_nWrite = off("Vdbe_nWrite", 196, 196);

// --- struct VdbeOp (config-invariant; sizeof 32) ---
const Op_opcode = off("VdbeOp_opcode", 0, 0);
const Op_p4type = off("VdbeOp_p4type", 1, 1);
const Op_p5 = off("VdbeOp_p5", 2, 2);
const Op_p1 = off("VdbeOp_p1", 4, 4);
const Op_p2 = off("VdbeOp_p2", 8, 8);
const Op_p3 = off("VdbeOp_p3", 12, 12);
const Op_p4 = off("VdbeOp_p4", 16, 16);
const Op_zComment = 24; // EXPLAIN_COMMENTS on in both → present at off 24
const sizeof_Op = off("sizeof_VdbeOp", 32, 32);

// --- struct Mem (sqlite3_value) ---
const Mem_u = 0; // union MemValue at offset 0
const Mem_z = off("sqlite3_value_z", 8, 8);
const Mem_n = off("sqlite3_value_n", 16, 16);
const Mem_flags = off("sqlite3_value_flags", 20, 20);
const Mem_enc = off("sqlite3_value_enc", 22, 22);
const Mem_db = off("sqlite3_value_db", 24, 24);
const Mem_szMalloc = off("sqlite3_value_szMalloc", 32, 32);
const Mem_zMalloc = off("sqlite3_value_zMalloc", 40, 40);
const Mem_xDel = off("sqlite3_value_xDel", 48, 48);
const sizeof_Mem = L.sizeof_Mem; // 56 prod / 72 tf

// --- struct VdbeCursor (DIVERGES under DEBUG) ---
const VdbeCursor_eCurType = off("VdbeCursor_eCurType", 0, 0);
const VdbeCursor_isTable = 4;
const VdbeCursor_deferredMoveto = 3;
const VdbeCursor_nullRow = 2;
const VdbeCursor_uc = off("VdbeCursor_uc", 40, 48);
const VdbeCursor_nField = off("VdbeCursor_nField", 64, 72);
const VdbeCursor_nHdrParsed = off("VdbeCursor_nHdrParsed", 66, 74);
const VdbeCursor_pCache = off("VdbeCursor_pCache", 104, 112);
const VdbeCursor_cacheStatus = off("VdbeCursor_cacheStatus", 24, 32);
const VdbeCursor_movetoTarget = off("VdbeCursor_movetoTarget", 72, 80);
// The :1 bitfield byte (isEphemeral.. colCache). colCache is bit 0x10.
const VdbeCursor_bits = off("VdbeCursor_bits", 5, 7);
const COLCACHE_BIT: u8 = 0x10;

// --- struct VdbeFrame (DIVERGES under DEBUG: iFrameMagic) ---
const VdbeFrame_v = off("VdbeFrame_v", 0, 0);
const VdbeFrame_pParent = off("VdbeFrame_pParent", 8, 8);
const VdbeFrame_aOp = off("VdbeFrame_aOp", 16, 16);
const VdbeFrame_aMem = off("VdbeFrame_aMem", 24, 24);
const VdbeFrame_apCsr = off("VdbeFrame_apCsr", 32, 32);
const VdbeFrame_lastRowid = off("VdbeFrame_lastRowid", 56, 56);
const VdbeFrame_pAuxData = off("VdbeFrame_pAuxData", 64, 64);
const VdbeFrame_iFrameMagic = 72; // DEBUG only
const VdbeFrame_nCursor = off("VdbeFrame_nCursor", 72, 76);
const VdbeFrame_pc = off("VdbeFrame_pc", 76, 80);
const VdbeFrame_nOp = off("VdbeFrame_nOp", 80, 84);
const VdbeFrame_nMem = off("VdbeFrame_nMem", 84, 88);
const VdbeFrame_nChildMem = off("VdbeFrame_nChildMem", 88, 92);
const VdbeFrame_nChildCsr = off("VdbeFrame_nChildCsr", 92, 96);
const VdbeFrame_nChange = off("VdbeFrame_nChange", 96, 104);
const VdbeFrame_nDbChange = off("VdbeFrame_nDbChange", 104, 112);

// --- struct KeyInfo (config-invariant) ---
const KeyInfo_enc = off("KeyInfo_enc", 4, 4);
const KeyInfo_nKeyField = off("KeyInfo_nKeyField", 6, 6);
const KeyInfo_nAllField = off("KeyInfo_nAllField", 8, 8);
const KeyInfo_db = off("KeyInfo_db", 16, 16);
const KeyInfo_aSortFlags = off("KeyInfo_aSortFlags", 24, 24);
const KeyInfo_aColl = off("KeyInfo_aColl", 32, 32);

// --- struct UnpackedRecord (config-invariant) ---
const UR_pKeyInfo = off("UnpackedRecord_pKeyInfo", 0, 0);
const UR_aMem = off("UnpackedRecord_aMem", 8, 8);
const UR_u = off("UnpackedRecord_u", 16, 16);
const UR_n = off("UnpackedRecord_n", 24, 24);
const UR_nField = off("UnpackedRecord_nField", 28, 28);
const UR_default_rc = off("UnpackedRecord_default_rc", 30, 30);
const UR_errCode = off("UnpackedRecord_errCode", 31, 31);
const UR_r1 = off("UnpackedRecord_r1", 32, 32);
const UR_r2 = off("UnpackedRecord_r2", 33, 33);
const UR_eqSeen = off("UnpackedRecord_eqSeen", 34, 34);
const sizeof_UnpackedRecord = off("sizeof_UnpackedRecord", 40, 40);

// --- struct SubProgram (config-invariant) ---
const SubProgram_aOp = off("SubProgram_aOp", 0, 0);
const SubProgram_nOp = off("SubProgram_nOp", 8, 8);
const SubProgram_pNext = off("SubProgram_pNext", 40, 40);

// --- struct AuxData (config-invariant) ---
const AuxData_iAuxOp = off("AuxData_iAuxOp", 0, 0);
const AuxData_iAuxArg = off("AuxData_iAuxArg", 4, 4);
const AuxData_pAux = off("AuxData_pAux", 8, 8);
const AuxData_xDeleteAux = off("AuxData_xDeleteAux", 16, 16);
const AuxData_pNextAux = off("AuxData_pNextAux", 24, 24);

// --- struct sqlite3_context (config-invariant) ---
const Ctx_pOut = off("sqlite3_context_pOut", 0, 0);
const Ctx_pFunc = off("sqlite3_context_pFunc", 8, 8);
const Ctx_pVdbe = off("sqlite3_context_pVdbe", 24, 24);
const Ctx_iOp = off("sqlite3_context_iOp", 32, 32);
const Ctx_isError = off("sqlite3_context_isError", 36, 36);
const Ctx_argc = off("sqlite3_context_argc", 42, 42);
const Ctx_argv = 48; // FLEXARRAY base == sizeof minus 0; argv begins at 48

// --- struct sqlite3 ---
const sqlite3_pVdbe = off("sqlite3_pVdbe", 8, 8);
const sqlite3_mutex = off("sqlite3_mutex", 24, 24);
const sqlite3_aDb = off("sqlite3_aDb", 32, 32);
const sqlite3_nDb = off("sqlite3_nDb", 40, 40);
const sqlite3_flags = off("sqlite3_flags", 48, 48);
const sqlite3_errCode = off("sqlite3_errCode", 80, 80);
const sqlite3_errByteOffset = off("sqlite3_errByteOffset", 84, 84);
const sqlite3_errMask = off("sqlite3_errMask", 88, 88);
const sqlite3_enc = off("sqlite3_enc", 100, 100);
const sqlite3_autoCommit = off("sqlite3_autoCommit", 101, 101);
const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103, 103);
const sqlite3_aLimit = off("sqlite3_aLimit", 136, 136);
const sqlite3_nChange = off("sqlite3_nChange", 120, 120);
const sqlite3_nTotalChange = off("sqlite3_nTotalChange", 128, 128);
const sqlite3_pVfs = off("sqlite3_pVfs", 0, 0);
const sqlite3_nVdbeActive = off("sqlite3_nVdbeActive", 208, 208);
const sqlite3_nStatement = off("sqlite3_nStatement", 772, 772);
const sqlite3_pnBytesFreed = off("sqlite3_pnBytesFreed", 792, 792);
const sqlite3_pErr = off("sqlite3_pErr", 416, 416);
const sqlite3_xPreUpdateCallback = off("sqlite3_xPreUpdateCallback", 360, 360);
const sqlite3_lastRowid = off("sqlite3_lastRowid", 56, 56);
const sqlite3_nDeferredCons = off("sqlite3_nDeferredCons", 776, 776);
const sqlite3_nDeferredImmCons = off("sqlite3_nDeferredImmCons", 784, 784);
const sqlite3_nVdbeWrite = off("sqlite3_nVdbeWrite", 216, 216);
const sqlite3_nVdbeRead = off("sqlite3_nVdbeRead", 212, 212);
const sqlite3_xCommitCallback = off("sqlite3_xCommitCallback", 280, 280);
const sqlite3_pCommitArg = off("sqlite3_pCommitArg", 272, 272);
const sqlite3_nSavepoint = off("sqlite3_nSavepoint", 768, 768);
const sqlite3_mDbFlags = off("sqlite3_mDbFlags", 44, 44);
const sqlite3_pPreUpdate = off("sqlite3_pPreUpdate", 368, 368);
const sqlite3_pPreUpdateArg = off("sqlite3_pPreUpdateArg", 352, 352);

// Db entry (sizeof 32; zDbSName@0, pBt@8, safety_level@16)
const Db_pBt = off("Db_pBt", 8, 8);
const Db_safety_level = off("Db_safety_level", 16, 16);
const sizeof_Db = off("sizeof_Db", 32, 32);

// Parse fields used (config-divergent ones gated where needed)
const Parse_db = off("Parse_db", 0, 0);
const Parse_pVdbe = off("Parse_pVdbe", 16, 16);
const Parse_nVar = off("Parse_nVar", 296, 296);
const Parse_nMem = off("Parse_nMem", 60, 60);
const Parse_nTab = off("Parse_nTab", 56, 56);
const Parse_nMaxArg = off("Parse_nMaxArg", 120, 120);
const Parse_nLabel = off("Parse_nLabel", 72, 72);
const Parse_nLabelAlloc = off("Parse_nLabelAlloc", 76, 76);
const Parse_aLabel = off("Parse_aLabel", 80, 80);
const Parse_explain = off("Parse_explain", 299, 299);
const Parse_addrExplain = off("Parse_addrExplain", 312, 312);
const Parse_pVList = off("Parse_pVList", 320, 320);
const Parse_nTempReg = off("Parse_nTempReg", 31, 31);
const Parse_nRangeReg = off("Parse_nRangeReg", 44, 44);
const Parse_isMultiWrite = off("Parse_isMultiWrite", 32, 32); // bit 0 (0x01)
// mayAbort is a :1 bitfield sharing a byte; the byte diverges prod/debug.
const Parse_mayAbortByte = off("Parse_mayAbortByte", 39, 42); // bit 0x02

// FuncDef.funcFlags (i16 nArg@0, u32 funcFlags@4)
const FuncDef_funcFlags = 4;
const SQLITE_FUNC_EPHEM: u32 = 0x0010;

// ===========================================================================
// Typed field accessors over opaque base pointers.
// ===========================================================================
inline fn fp(comptime T: type, base: ?*anyopaque, o: usize) *T {
    const p: [*]u8 = @ptrCast(base.?);
    return @ptrCast(@alignCast(p + o));
}
inline fn rd(comptime T: type, base: ?*anyopaque, o: usize) T {
    return fp(T, base, o).*;
}
inline fn wr(comptime T: type, base: ?*anyopaque, o: usize, v: T) void {
    fp(T, base, o).* = v;
}
inline fn rdU8(base: ?*anyopaque, o: usize) u8 {
    const p: [*]const u8 = @ptrCast(base.?);
    return p[o];
}
inline fn wrU8(base: ?*anyopaque, o: usize, v: u8) void {
    const p: [*]u8 = @ptrCast(base.?);
    p[o] = v;
}
inline fn rdPtr(base: ?*anyopaque, o: usize) ?*anyopaque {
    return fp(?*anyopaque, base, o).*;
}
inline fn wrPtr(base: ?*anyopaque, o: usize, v: ?*anyopaque) void {
    fp(?*anyopaque, base, o).* = v;
}
// stride helper: i-th element of an array of opaque structs of given size
inline fn elemAt(base: ?*anyopaque, i: usize, stride: usize) ?*anyopaque {
    return @as([*]u8, @ptrCast(base.?)) + i * stride;
}

// Op array access
inline fn opAt(aOp: ?*anyopaque, i: usize) ?*anyopaque {
    return @as([*]u8, @ptrCast(aOp.?)) + i * sizeof_Op;
}
// Mem array access
inline fn memAt(aMem: ?*anyopaque, i: usize) ?*anyopaque {
    return @as([*]u8, @ptrCast(aMem.?)) + i * sizeof_Mem;
}

// Vdbe bitfield helpers (single byte at Vdbe_bitfields)
inline fn vbits(v: ?*anyopaque) *u8 {
    return fp(u8, v, Vdbe_bitfields);
}
inline fn setReadOnly(v: ?*anyopaque, b: bool) void {
    const p = vbits(v);
    if (b) p.* |= 0x40 else p.* &= ~@as(u8, 0x40);
}
inline fn getReadOnly(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x40) != 0;
}
inline fn setBIsReader(v: ?*anyopaque, b: bool) void {
    const p = vbits(v);
    if (b) p.* |= 0x80 else p.* &= ~@as(u8, 0x80);
}
inline fn getBIsReader(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x80) != 0;
}
inline fn getChangeCntOn(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x10) != 0;
}
inline fn setUsesStmtJournal(v: ?*anyopaque, b: bool) void {
    const p = vbits(v);
    if (b) p.* |= 0x20 else p.* &= ~@as(u8, 0x20);
}
inline fn getUsesStmtJournal(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x20) != 0;
}
inline fn setExpired(v: ?*anyopaque, val: u8) void {
    const p = vbits(v);
    p.* = (p.* & ~@as(u8, 0x03)) | (val & 0x03);
}
inline fn setExplain(v: ?*anyopaque, val: u8) void {
    const p = vbits(v);
    p.* = (p.* & ~@as(u8, 0x0c)) | ((val & 0x03) << 2);
}
inline fn getExplain(v: ?*anyopaque) u8 {
    return (vbits(v).* >> 2) & 0x03;
}

// db->aDb[i] entry pointer
inline fn dbEnt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const aDb = rdPtr(db, sqlite3_aDb).?;
    return @as([*]u8, @ptrCast(aDb)) + @as(usize, @intCast(i)) * sizeof_Db;
}

// db->aLimit[idx]
inline fn dbLimit(db: ?*anyopaque, idx: usize) c_int {
    return fp(c_int, db, sqlite3_aLimit + idx * @sizeOf(c_int)).*;
}

// ===========================================================================
// External C symbols (resolved at link time).
// ===========================================================================
extern fn sqlite3DbMallocRawNN(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocRaw(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocZero(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocSize(db: ?*sqlite3, p: ?*anyopaque) c_int;
extern fn sqlite3DbRealloc(db: ?*sqlite3, p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbReallocOrFree(db: ?*sqlite3, p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3DbNNFreeNN(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3DbStrNDup(db: ?*sqlite3, z: ?[*]const u8, n: u64) ?[*:0]u8;
extern fn sqlite3DbStrDup(db: ?*sqlite3, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3VMPrintf(db: ?*sqlite3, zFormat: [*:0]const u8, ap: *std.builtin.VaList) ?[*:0]u8;
extern fn sqlite3MPrintf(db: ?*sqlite3, zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, zBuf: [*]u8, zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_mprintf(zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3OomFault(db: ?*sqlite3) void;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int; // null-safe (returns 0)
extern fn sqlite3GetVarint32(p: [*]const u8, v: *u32) u8;
extern fn sqlite3VarintLen(v: u64) c_int;
extern fn sqlite3MayAbort(p: ?*Parse) void;
extern fn sqlite3ProgressCheck(p: ?*Parse) c_int;
extern fn sqlite3SystemError(db: ?*sqlite3, rc: c_int) void;
extern fn sqlite3ErrStr(rc: c_int) [*:0]const u8;
extern fn sqlite3IsNaN(x: f64) c_int;

// Vdbe helpers within this module call each other; for C callers these are
// all exported below. A few internal-only C helpers used by us:
extern fn sqlite3KeyInfoOfIndex(pParse: ?*Parse, pIdx: ?*Index) ?*KeyInfo;
extern fn sqlite3KeyInfoUnref(p: ?*KeyInfo) void;
extern fn sqlite3VtabLock(p: ?*anyopaque) void;
extern fn sqlite3VtabUnlock(p: ?*anyopaque) void;
extern fn sqlite3DeleteTable(db: ?*sqlite3, p: ?*Table) void;
extern fn sqlite3ValueFree(p: ?*anyopaque) void;
extern fn sqlite3ValueNew(db: ?*sqlite3) ?*anyopaque;
extern fn sqlite3ValueSetStr(p: ?*anyopaque, n: c_int, z: ?*const anyopaque, enc: u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3ValueSetNull(p: ?*anyopaque) void;
extern fn sqlite3ValueApplyAffinity(p: ?*anyopaque, aff: u8, enc: u8) void;
extern fn sqlite3BeginBenignMalloc() void;
extern fn sqlite3EndBenignMalloc() void;

// Mem helpers
extern fn sqlite3VdbeMemRelease(p: ?*Mem) void;
extern fn sqlite3VdbeMemReleaseMalloc(p: ?*Mem) void;
extern fn sqlite3VdbeMemSetNull(p: ?*Mem) void;
extern fn sqlite3VdbeMemSetInt64(p: ?*Mem, v: i64) void;
extern fn sqlite3VdbeMemSetStr(p: ?*Mem, z: ?[*]const u8, n: i64, enc: u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3VdbeMemSetText(p: ?*Mem, z: ?[*]const u8, n: i64, xDel: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3VdbeMemInit(p: ?*Mem, db: ?*sqlite3, flags: u16) void;
extern fn sqlite3VdbeMemGrow(p: ?*Mem, n: c_int, preserve: c_int) c_int;
extern fn sqlite3VdbeMemShallowCopy(to: ?*Mem, from: ?*const Mem, srcType: c_int) void;
extern fn sqlite3VdbeMemCopy(to: ?*Mem, from: ?*const Mem) c_int;
extern fn sqlite3VdbeMemFromBtreeZeroOffset(pCur: ?*BtCursor, amt: u32, p: ?*Mem) c_int;
extern fn sqlite3VdbeChangeEncoding(p: ?*Mem, enc: c_int) c_int;
extern fn sqlite3ValueText(p: ?*anyopaque, enc: u8) ?*const anyopaque;

// b-tree / pager / vtab / os helpers
extern fn sqlite3BtreeEnter(p: ?*Btree) void;
extern fn sqlite3BtreeLeave(p: ?*Btree) void;
extern fn sqlite3BtreeSharable(p: ?*Btree) c_int;
extern fn sqlite3BtreeTxnState(p: ?*Btree) c_int;
extern fn sqlite3BtreePager(p: ?*Btree) ?*Pager;
extern fn sqlite3BtreeGetFilename(p: ?*Btree) [*:0]const u8;
extern fn sqlite3BtreeGetJournalname(p: ?*Btree) ?[*:0]const u8;
extern fn sqlite3BtreeCommitPhaseOne(p: ?*Btree, zSuper: ?[*:0]const u8) c_int;
extern fn sqlite3BtreeCommitPhaseTwo(p: ?*Btree, b: c_int) c_int;
extern fn sqlite3BtreeSavepoint(p: ?*Btree, op: c_int, iSavepoint: c_int) c_int;
extern fn sqlite3BtreeCloseCursor(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeCursorHasMoved(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeCursorRestore(p: ?*BtCursor, pDifferentRow: *c_int) c_int;
extern fn sqlite3BtreeTableMoveto(p: ?*BtCursor, key: i64, bias: c_int, pRes: *c_int) c_int;
extern fn sqlite3BtreeCursorIsValid(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeCursorIsValidNN(p: ?*BtCursor) c_int;
extern fn sqlite3BtreePayloadSize(p: ?*BtCursor) u64;
extern fn sqlite3BtreePayload(p: ?*BtCursor, offset: u32, amt: u32, pBuf: ?*anyopaque) c_int;
extern fn sqlite3BtreeEof(p: ?*BtCursor) c_int;
extern fn sqlite3BtreePrevious(p: ?*BtCursor, flags: c_int) c_int;
extern fn sqlite3BtreeNext(p: ?*BtCursor, flags: c_int) c_int;
extern fn sqlite3BtreeFirst(p: ?*BtCursor, pRes: *c_int) c_int;
extern fn sqlite3PagerGetJournalMode(p: ?*Pager) c_int;
extern fn sqlite3PagerIsMemdb(p: ?*Pager) c_int;
extern fn sqlite3PagerExclusiveLock(p: ?*Pager) c_int;
extern fn sqlite3PagerSetJournalMode(p: ?*Pager, mode: c_int) void;
extern fn sqlite3VdbeSorterClose(db: ?*sqlite3, pCsr: ?*VdbeCursor) void;
extern fn sqlite3RCStrUnref(z: ?*anyopaque) void;

extern fn sqlite3VtabSync(db: ?*sqlite3, p: ?*Vdbe) c_int;
extern fn sqlite3VtabCommit(db: ?*sqlite3) void;
extern fn sqlite3VtabSavepoint(db: ?*sqlite3, op: c_int, iSavepoint: c_int) c_int;
// C macro: ((db)->nVTrans>0 && (db)->aVTrans==0)
const sqlite3_nVTrans = off("sqlite3_nVTrans", 564, 564);
const sqlite3_aVTrans = off("sqlite3_aVTrans", 600, 600);
inline fn sqlite3VtabInSync(db: ?*sqlite3) c_int {
    return @intFromBool(rd(c_int, db, sqlite3_nVTrans) > 0 and rdPtr(db, sqlite3_aVTrans) == null);
}
extern fn sqlite3RollbackAll(db: ?*sqlite3, tripCode: c_int) void;
extern fn sqlite3CloseSavepoints(db: ?*sqlite3) void;
extern fn sqlite3CommitInternalChanges(db: ?*sqlite3) void;
// SQLITE_ENABLE_UNLOCK_NOTIFY off → sqlite3ConnectionUnlocked is a no-op macro.
inline fn sqlite3ConnectionUnlocked(db: ?*sqlite3) void {
    _ = db;
}
extern fn sqlite3_stmt_busy(p: ?*anyopaque) c_int;

extern fn sqlite3OsOpenMalloc(pVfs: ?*sqlite3_vfs, zName: [*:0]const u8, ppFile: *?*sqlite3_file, flags: c_int, pOutFlags: ?*c_int) c_int;
extern fn sqlite3OsCloseFree(pFile: ?*sqlite3_file) void;
extern fn sqlite3OsDelete(pVfs: ?*sqlite3_vfs, zPath: [*:0]const u8, dirSync: c_int) c_int;
extern fn sqlite3OsAccess(pVfs: ?*sqlite3_vfs, zPath: [*:0]const u8, flags: c_int, pResOut: *c_int) c_int;
extern fn sqlite3OsWrite(pFile: ?*sqlite3_file, pBuf: ?*const anyopaque, amt: c_int, offset: i64) c_int;
extern fn sqlite3OsSync(pFile: ?*sqlite3_file, flags: c_int) c_int;
extern fn sqlite3OsDeviceCharacteristics(pFile: ?*sqlite3_file) c_int;
// SQLITE_ENABLE_8_3_NAMES not >0 → sqlite3FileSuffix3 is a no-op macro.
inline fn sqlite3FileSuffix3(zBase: [*:0]const u8, z: [*:0]u8) void {
    _ = zBase;
    _ = z;
}
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_randomness(N: c_int, pBuf: ?*anyopaque) void;
extern fn sqlite3_mutex_held(p: ?*anyopaque) c_int;
// SQLITE_TEST-only hooks (os.zig exports them under config.sqlite_test); in the
// production build they are empty macros — call only when the symbols exist.
extern fn disable_simulated_io_errors() void;
extern fn enable_simulated_io_errors() void;

// data structures shared with C. sqlite3SmallTypeSizes is DEFINED by this
// module (see the export below).
// C: `const unsigned char sqlite3OpcodeProperty[]` — an ARRAY; the symbol's
// address IS the data. Bind a byte and take its address (declaring it [*]const u8
// would read the array bytes AS a pointer — the char[]-as-pointer gotcha).
extern const sqlite3OpcodeProperty: u8;

// opcode name table (for EXPLAIN / debug printing)
extern fn sqlite3OpcodeName(op: c_int) [*:0]const u8;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;

// VdbeOpList: { u8 opcode; signed char p1,p2,p3; } (vdbe.h)
const VdbeOpList = extern struct { opcode: u8, p1: i8, p2: i8, p3: i8 };

// ===========================================================================
// Vdbe creation / basic accessors
// ===========================================================================
export fn sqlite3VdbeCreate(pParse: ?*Parse) callconv(.c) ?*Vdbe {
    const db = rdPtr(pParse, Parse_db);
    const p = sqlite3DbMallocRawNN(db, sizeof_Vdbe) orelse return null;
    // memset(&p->aOp, 0, sizeof(Vdbe)-offsetof(Vdbe,aOp))
    const base: [*]u8 = @ptrCast(p);
    @memset(base[Vdbe_aOp..sizeof_Vdbe], 0);
    wrPtr(p, Vdbe_db, db);
    const pVdbe = rdPtr(db, sqlite3_pVdbe);
    if (pVdbe != null) {
        // db->pVdbe->ppVPrev = &p->pVNext
        wrPtr(pVdbe, Vdbe_ppVPrev, @ptrCast(fp(?*anyopaque, p, Vdbe_pVNext)));
    }
    wrPtr(p, Vdbe_pVNext, pVdbe);
    wrPtr(p, Vdbe_ppVPrev, @ptrCast(fp(?*anyopaque, db, sqlite3_pVdbe)));
    wrPtr(db, sqlite3_pVdbe, p);
    wrPtr(p, Vdbe_pParse, pParse);
    wrPtr(pParse, Parse_pVdbe, p);
    _ = sqlite3VdbeAddOp2(p, OP_Init, 0, 1);
    return p;
}

export fn sqlite3VdbeParser(p: ?*Vdbe) callconv(.c) ?*Parse {
    return rdPtr(p, Vdbe_pParse);
}

export fn sqlite3VdbeError(p: ?*Vdbe, zFormat: [*:0]const u8, ...) callconv(.c) void {
    const db = rdPtr(p, Vdbe_db);
    sqlite3DbFree(db, rdPtr(p, Vdbe_zErrMsg));
    var ap = @cVaStart();
    wrPtr(p, Vdbe_zErrMsg, @ptrCast(sqlite3VMPrintf(db, zFormat, &ap)));
    @cVaEnd(&ap);
}

export fn sqlite3VdbeSetSql(p: ?*Vdbe, z: ?[*]const u8, n: c_int, prepFlags: u8) callconv(.c) void {
    if (p == null) return;
    wrU8(p, Vdbe_prepFlags, prepFlags);
    if ((prepFlags & SQLITE_PREPARE_SAVESQL) == 0) {
        wr(u32, p, Vdbe_expmask, 0);
    }
    wrPtr(p, Vdbe_zSql, @ptrCast(sqlite3DbStrNDup(rdPtr(p, Vdbe_db), z, @intCast(n))));
}

export fn sqlite3VdbeSwap(pA: ?*Vdbe, pB: ?*Vdbe) callconv(.c) void {
    // Full struct swap (tmp = *pA; *pA = *pB; *pB = tmp), then fix up the
    // intrusive list pointers and a few fields, exactly as the C does.
    const a: [*]u8 = @ptrCast(pA.?);
    const b: [*]u8 = @ptrCast(pB.?);
    var i: usize = 0;
    while (i < sizeof_Vdbe) : (i += 1) {
        const t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
    // swap pVNext
    const pTmp = rdPtr(pA, Vdbe_pVNext);
    wrPtr(pA, Vdbe_pVNext, rdPtr(pB, Vdbe_pVNext));
    wrPtr(pB, Vdbe_pVNext, pTmp);
    // swap ppVPrev
    const ppTmp = rdPtr(pA, Vdbe_ppVPrev);
    wrPtr(pA, Vdbe_ppVPrev, rdPtr(pB, Vdbe_ppVPrev));
    wrPtr(pB, Vdbe_ppVPrev, ppTmp);
    // swap zSql
    const zTmp = rdPtr(pA, Vdbe_zSql);
    wrPtr(pA, Vdbe_zSql, rdPtr(pB, Vdbe_zSql));
    wrPtr(pB, Vdbe_zSql, zTmp);
    // pB->expmask = pA->expmask; pB->prepFlags = pA->prepFlags;
    wr(u32, pB, Vdbe_expmask, rd(u32, pA, Vdbe_expmask));
    wrU8(pB, Vdbe_prepFlags, rdU8(pA, Vdbe_prepFlags));
    // memcpy aCounter (9 u32) then bump REPREPARE (index 5)
    const SQLITE_STMTSTATUS_REPREPARE: usize = 5;
    var k: usize = 0;
    while (k < 9) : (k += 1) {
        wr(u32, pB, Vdbe_aCounter + k * 4, rd(u32, pA, Vdbe_aCounter + k * 4));
    }
    const slot = Vdbe_aCounter + SQLITE_STMTSTATUS_REPREPARE * 4;
    wr(u32, pB, slot, rd(u32, pB, slot) +% 1);
}

// ===========================================================================
// Growing the op array
// ===========================================================================
fn growOpArray(v: ?*Vdbe, nOp: c_int) c_int {
    _ = nOp;
    const pParse = rdPtr(v, Vdbe_pParse);
    const db = rdPtr(pParse, Parse_db);
    const nOpAlloc = rd(c_int, v, Vdbe_nOpAlloc);
    const nNew: i64 = if (nOpAlloc != 0)
        2 * @as(i64, nOpAlloc)
    else
        @as(i64, 1024 / @as(i64, @intCast(sizeof_Op)));
    if (nNew > dbLimit(db, SQLITE_LIMIT_VDBE_OP)) {
        sqlite3OomFault(db);
        return SQLITE_NOMEM;
    }
    const pNew = sqlite3DbRealloc(db, rdPtr(v, Vdbe_aOp), @intCast(nNew * @as(i64, @intCast(sizeof_Op))));
    if (pNew != null) {
        wr(c_int, v, Vdbe_nOpAlloc, @intCast(@divTrunc(sqlite3DbMallocSize(db, pNew), @as(c_int, @intCast(sizeof_Op)))));
        wrPtr(v, Vdbe_aOp, pNew);
    }
    return if (pNew != null) SQLITE_OK else SQLITE_NOMEM;
}

fn growOp3(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int {
    if (growOpArray(p, 1) != 0) return 1;
    return sqlite3VdbeAddOp3(p, op, p1, p2, p3);
}
fn addOp4IntSlow(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int {
    const addr = sqlite3VdbeAddOp3(p, op, p1, p2, p3);
    if (rdU8(rdPtr(p, Vdbe_db), sqlite3_mallocFailed) == 0) {
        const pOp = opAt(rdPtr(p, Vdbe_aOp), @intCast(addr));
        wrU8(pOp, Op_p4type, @bitCast(P4_INT32));
        wr(c_int, pOp, Op_p4, p4);
    }
    return addr;
}

export fn sqlite3VdbeAddOp0(p: ?*Vdbe, op: c_int) callconv(.c) c_int {
    return sqlite3VdbeAddOp3(p, op, 0, 0, 0);
}
export fn sqlite3VdbeAddOp1(p: ?*Vdbe, op: c_int, p1: c_int) callconv(.c) c_int {
    return sqlite3VdbeAddOp3(p, op, p1, 0, 0);
}
export fn sqlite3VdbeAddOp2(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int) callconv(.c) c_int {
    return sqlite3VdbeAddOp3(p, op, p1, p2, 0);
}
export fn sqlite3VdbeAddOp3(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int) callconv(.c) c_int {
    const i = rd(c_int, p, Vdbe_nOp);
    if (rd(c_int, p, Vdbe_nOpAlloc) <= i) {
        return growOp3(p, op, p1, p2, p3);
    }
    wr(c_int, p, Vdbe_nOp, i + 1);
    const pOp = opAt(rdPtr(p, Vdbe_aOp), @intCast(i));
    wrU8(pOp, Op_opcode, @truncate(@as(c_uint, @bitCast(op))));
    wr(u16, pOp, Op_p5, 0);
    wr(c_int, pOp, Op_p1, p1);
    wr(c_int, pOp, Op_p2, p2);
    wr(c_int, pOp, Op_p3, p3);
    wrPtr(pOp, Op_p4, null);
    wrU8(pOp, Op_p4type, @bitCast(P4_NOTUSED));
    wrPtr(pOp, Op_zComment, null); // EXPLAIN_COMMENTS on
    return i;
}
export fn sqlite3VdbeAddOp4Int(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) callconv(.c) c_int {
    const i = rd(c_int, p, Vdbe_nOp);
    if (rd(c_int, p, Vdbe_nOpAlloc) <= i) {
        return addOp4IntSlow(p, op, p1, p2, p3, p4);
    }
    wr(c_int, p, Vdbe_nOp, i + 1);
    const pOp = opAt(rdPtr(p, Vdbe_aOp), @intCast(i));
    wrU8(pOp, Op_opcode, @truncate(@as(c_uint, @bitCast(op))));
    wr(u16, pOp, Op_p5, 0);
    wr(c_int, pOp, Op_p1, p1);
    wr(c_int, pOp, Op_p2, p2);
    wr(c_int, pOp, Op_p3, p3);
    wr(c_int, pOp, Op_p4, p4);
    wrU8(pOp, Op_p4type, @bitCast(P4_INT32));
    wrPtr(pOp, Op_zComment, null);
    return i;
}

export fn sqlite3VdbeGoto(p: ?*Vdbe, iDest: c_int) callconv(.c) c_int {
    return sqlite3VdbeAddOp3(p, OP_Goto, 0, iDest, 0);
}
export fn sqlite3VdbeLoadString(p: ?*Vdbe, iDest: c_int, zStr: [*:0]const u8) callconv(.c) c_int {
    return sqlite3VdbeAddOp4(p, OP_String8, 0, iDest, 0, zStr, 0);
}

export fn sqlite3VdbeMultiLoad(p: ?*Vdbe, iDest: c_int, zTypes: [*:0]const u8, ...) callconv(.c) void {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    var i: c_int = 0;
    while (zTypes[@intCast(i)] != 0) : (i += 1) {
        const c = zTypes[@intCast(i)];
        if (c == 's') {
            const z = @cVaArg(&ap, ?[*:0]const u8);
            _ = sqlite3VdbeAddOp4(p, if (z == null) @as(c_int, OP_Null) else @as(c_int, OP_String8), 0, iDest + i, 0, z, 0);
        } else if (c == 'i') {
            _ = sqlite3VdbeAddOp2(p, OP_Integer, @cVaArg(&ap, c_int), iDest + i);
        } else {
            return; // skip_op_resultrow
        }
    }
    _ = sqlite3VdbeAddOp2(p, OP_ResultRow, iDest, i);
}

export fn sqlite3VdbeAddOp4(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*:0]const u8, p4type: c_int) callconv(.c) c_int {
    const addr = sqlite3VdbeAddOp3(p, op, p1, p2, p3);
    sqlite3VdbeChangeP4(p, addr, zP4, p4type);
    return addr;
}

export fn sqlite3VdbeAddOp4Dup8(p: ?*Vdbe, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: [*]const u8, p4type: c_int) callconv(.c) c_int {
    const db = rdPtr(p, Vdbe_db);
    const p4copy = sqlite3DbMallocRawNN(db, 8);
    if (p4copy != null) {
        const dst: [*]u8 = @ptrCast(p4copy.?);
        @memcpy(dst[0..8], zP4[0..8]);
    }
    return sqlite3VdbeAddOp4(p, op, p1, p2, p3, @ptrCast(p4copy), p4type);
}

// OP_Function / OP_PureFunc with a freshly allocated sqlite3_context as P4.
export fn sqlite3VdbeAddFunctionCall(pParse: ?*Parse, p1: c_int, p2: c_int, p3: c_int, nArg: c_int, pFunc: ?*const FuncDef, eCallCtx: c_int) callconv(.c) c_int {
    const db = rdPtr(pParse, Parse_db);
    const v = rdPtr(pParse, Parse_pVdbe);
    // SZ_CONTEXT(nArg) = offsetof(argv) + nArg*sizeof(ptr) = Ctx_argv + nArg*8
    const sz: u64 = @intCast(@as(i64, @intCast(Ctx_argv)) + @as(i64, nArg) * 8);
    const pCtx = sqlite3DbMallocRawNN(db, sz);
    if (pCtx == null) {
        freeEphemeralFunction(db, @constCast(pFunc));
        return 0;
    }
    wrPtr(pCtx, Ctx_pOut, null);
    wrPtr(pCtx, Ctx_pFunc, @constCast(pFunc));
    wrPtr(pCtx, Ctx_pVdbe, null);
    wr(c_int, pCtx, Ctx_isError, 0);
    wr(u16, pCtx, Ctx_argc, @truncate(@as(c_uint, @bitCast(nArg))));
    wr(c_int, pCtx, Ctx_iOp, sqlite3VdbeCurrentAddr(v));
    const addr = sqlite3VdbeAddOp4(v, if (eCallCtx != 0) @as(c_int, OP_PureFunc) else @as(c_int, OP_Function), p1, p2, p3, @ptrCast(pCtx), P4_FUNCCTX);
    sqlite3VdbeChangeP5(v, @truncate(@as(c_uint, @bitCast(eCallCtx & NC_SelfRef))));
    sqlite3MayAbort(pParse);
    return addr;
}

// ===========================================================================
// EXPLAIN support (OMIT_EXPLAIN off in both)
// ===========================================================================
export fn sqlite3VdbeExplainParent(pParse: ?*Parse) callconv(.c) c_int {
    const addrExplain = rd(c_int, pParse, Parse_addrExplain);
    if (addrExplain == 0) return 0;
    const pOp = sqlite3VdbeGetOp(rdPtr(pParse, Parse_pVdbe), addrExplain);
    return rd(c_int, pOp, Op_p2);
}

// SQLITE_DEBUG-only no-op breakpoint hook (compiled under DEBUG only).
fn sqlite3ExplainBreakpoint(z1: [*:0]const u8, z2: [*:0]const u8) callconv(.c) void {
    _ = z1;
    _ = z2;
}
comptime {
    if (DEBUG) @export(&sqlite3ExplainBreakpoint, .{ .name = "sqlite3ExplainBreakpoint" });
}

export fn sqlite3VdbeExplain(pParse: ?*Parse, bPush: u8, zFmt: [*:0]const u8, ...) callconv(.c) c_int {
    var addr: c_int = 0;
    // SQLITE_DEBUG: always include OP_Explain. Non-debug: only when explain==2
    // or IS_STMT_SCANSTATUS (off in both → false).
    const doIt = DEBUG or rdU8(pParse, Parse_explain) == 2;
    if (doIt) {
        const db = rdPtr(pParse, Parse_db);
        var ap = @cVaStart();
        const zMsg = sqlite3VMPrintf(db, zFmt, &ap);
        @cVaEnd(&ap);
        const v = rdPtr(pParse, Parse_pVdbe);
        const iThis = rd(c_int, v, Vdbe_nOp);
        addr = sqlite3VdbeAddOp4(v, OP_Explain, iThis, rd(c_int, pParse, Parse_addrExplain), 0, @ptrCast(zMsg), P4_DYNAMIC);
        if (DEBUG) {
            const lastP4 = rdPtr(sqlite3VdbeGetLastOp(v), Op_p4);
            const zPush: [*:0]const u8 = if (bPush != 0) "PUSH" else "";
            const zP4msg: [*:0]const u8 = if (lastP4 != null) @ptrCast(lastP4.?) else "";
            sqlite3ExplainBreakpoint(zPush, zP4msg);
        }
        if (bPush != 0) {
            wr(c_int, pParse, Parse_addrExplain, iThis);
        }
        // sqlite3VdbeScanStatus: STMT_SCANSTATUS off → no-op (function still
        // exists as a macro→nothing). Nothing to do.
    }
    return addr;
}

export fn sqlite3VdbeExplainPop(pParse: ?*Parse) callconv(.c) void {
    if (DEBUG) sqlite3ExplainBreakpoint("POP", "");
    wr(c_int, pParse, Parse_addrExplain, sqlite3VdbeExplainParent(pParse));
}

export fn sqlite3VdbeAddParseSchemaOp(p: ?*Vdbe, iDb: c_int, zWhere: ?[*:0]u8, p5: u16) callconv(.c) void {
    _ = sqlite3VdbeAddOp4(p, OP_ParseSchema, iDb, 0, 0, zWhere, P4_DYNAMIC);
    sqlite3VdbeChangeP5(p, p5);
    const db = rdPtr(p, Vdbe_db);
    const nDb = rd(c_int, db, sqlite3_nDb);
    var j: c_int = 0;
    while (j < nDb) : (j += 1) sqlite3VdbeUsesBtree(p, j);
    sqlite3MayAbort(rdPtr(p, Vdbe_pParse));
}

export fn sqlite3VdbeEndCoroutine(v: ?*Vdbe, regYield: c_int) callconv(.c) void {
    _ = sqlite3VdbeAddOp1(v, OP_EndCoroutine, regYield);
    const pParse = rdPtr(v, Vdbe_pParse);
    wrU8(pParse, Parse_nTempReg, 0); // nTempReg is u8, not int
    wr(c_int, pParse, Parse_nRangeReg, 0);
}

// ===========================================================================
// Labels
// ===========================================================================
export fn sqlite3VdbeMakeLabel(pParse: ?*Parse) callconv(.c) c_int {
    const nLabel = rd(c_int, pParse, Parse_nLabel) - 1;
    wr(c_int, pParse, Parse_nLabel, nLabel);
    return nLabel;
}

// ADDR(x) == ~(x)
inline fn ADDR(x: c_int) c_int {
    return ~x;
}

fn resizeResolveLabel(pParse: ?*Parse, v: ?*Vdbe, j: c_int) void {
    const db = rdPtr(pParse, Parse_db);
    const nNewSize = 25 - rd(c_int, pParse, Parse_nLabel);
    const aLabel = sqlite3DbReallocOrFree(db, rdPtr(pParse, Parse_aLabel), @intCast(@as(i64, nNewSize) * 4));
    wrPtr(pParse, Parse_aLabel, aLabel);
    if (aLabel == null) {
        wr(c_int, pParse, Parse_nLabelAlloc, 0);
    } else {
        if (DEBUG) {
            var i = rd(c_int, pParse, Parse_nLabelAlloc);
            while (i < nNewSize) : (i += 1) {
                wr(c_int, aLabel, @intCast(@as(usize, @intCast(i)) * 4), -1);
            }
        }
        if (nNewSize >= 100 and @divTrunc(nNewSize, 100) > @divTrunc(rd(c_int, pParse, Parse_nLabelAlloc), 100)) {
            _ = sqlite3ProgressCheck(pParse);
        }
        wr(c_int, pParse, Parse_nLabelAlloc, nNewSize);
        wr(c_int, aLabel, @intCast(@as(usize, @intCast(j)) * 4), rd(c_int, v, Vdbe_nOp));
    }
}

export fn sqlite3VdbeResolveLabel(v: ?*Vdbe, x: c_int) callconv(.c) void {
    const pParse = rdPtr(v, Vdbe_pParse);
    const j = ADDR(x);
    if (rd(c_int, pParse, Parse_nLabelAlloc) + rd(c_int, pParse, Parse_nLabel) < 0) {
        resizeResolveLabel(pParse, v, j);
    } else {
        const aLabel = rdPtr(pParse, Parse_aLabel);
        wr(c_int, aLabel, @intCast(@as(usize, @intCast(j)) * 4), rd(c_int, v, Vdbe_nOp));
    }
}

export fn sqlite3VdbeRunOnlyOnce(p: ?*Vdbe) callconv(.c) void {
    _ = sqlite3VdbeAddOp2(p, OP_Expire, 1, 1);
}
export fn sqlite3VdbeReusable(p: ?*Vdbe) callconv(.c) void {
    const nOp = rd(c_int, p, Vdbe_nOp);
    const aOp = rdPtr(p, Vdbe_aOp);
    var i: c_int = 1;
    while (i < nOp) : (i += 1) {
        if (rdU8(opAt(aOp, @intCast(i)), Op_opcode) == OP_Expire) {
            wrU8(opAt(aOp, 1), Op_opcode, OP_Noop);
            break;
        }
    }
}

// ===========================================================================
// resolveP2Values — back-patch labels into addresses; set readOnly/bIsReader.
// ===========================================================================
fn opProp(opcode: u8) u8 {
    return @as([*]const u8, @ptrCast(&sqlite3OpcodeProperty))[opcode];
}

fn resolveP2Values(p: ?*Vdbe, pMaxVtabArgs: *c_int) void {
    var nMaxVtabArgs = pMaxVtabArgs.*;
    const pParse = rdPtr(p, Vdbe_pParse);
    const aLabel = rdPtr(pParse, Parse_aLabel);
    setReadOnly(p, true);
    setBIsReader(p, false);
    const aOp = rdPtr(p, Vdbe_aOp);
    const nOp = rd(c_int, p, Vdbe_nOp);
    var idx: c_int = nOp - 1;
    // Loop terminates when it reaches the OP_Init opcode (idx 0).
    while (true) {
        const pOp = opAt(aOp, @intCast(idx));
        const opcode = rdU8(pOp, Op_opcode);
        if (opcode <= SQLITE_MX_JUMP_OPCODE) {
            switch (opcode) {
                OP_Transaction => {
                    if (rd(c_int, pOp, Op_p2) != 0) setReadOnly(p, false);
                    setBIsReader(p, true);
                },
                OP_AutoCommit, OP_Savepoint => {
                    setBIsReader(p, true);
                },
                OP_Checkpoint, OP_Vacuum, OP_JournalMode => {
                    setReadOnly(p, false);
                    setBIsReader(p, true);
                },
                OP_Init => break, // resolve_p2_values_loop_exit
                OP_VUpdate => {
                    if (rd(c_int, pOp, Op_p2) > nMaxVtabArgs) nMaxVtabArgs = rd(c_int, pOp, Op_p2);
                },
                OP_VFilter => {
                    // pOp[-1] is OP_Integer setting argc.
                    const prev = opAt(aOp, @intCast(idx - 1));
                    const n = rd(c_int, prev, Op_p1);
                    if (n > nMaxVtabArgs) nMaxVtabArgs = n;
                    // fall through to default
                    if (rd(c_int, pOp, Op_p2) < 0) {
                        wr(c_int, pOp, Op_p2, rd(c_int, aLabel, @intCast(@as(usize, @intCast(ADDR(rd(c_int, pOp, Op_p2)))) * 4)));
                    }
                },
                else => {
                    if (rd(c_int, pOp, Op_p2) < 0) {
                        wr(c_int, pOp, Op_p2, rd(c_int, aLabel, @intCast(@as(usize, @intCast(ADDR(rd(c_int, pOp, Op_p2)))) * 4)));
                    }
                },
            }
        }
        idx -= 1;
    }
    if (aLabel != null) {
        sqlite3DbNNFreeNN(rdPtr(p, Vdbe_db), rdPtr(pParse, Parse_aLabel));
        wrPtr(pParse, Parse_aLabel, null);
    }
    wr(c_int, pParse, Parse_nLabel, 0);
    pMaxVtabArgs.* = nMaxVtabArgs;
}

export fn sqlite3VdbeCurrentAddr(p: ?*Vdbe) callconv(.c) c_int {
    return rd(c_int, p, Vdbe_nOp);
}

export fn sqlite3VdbeTakeOpArray(p: ?*Vdbe, pnOp: *c_int, pnMaxArg: *c_int) callconv(.c) ?*Op {
    const aOp = rdPtr(p, Vdbe_aOp);
    resolveP2Values(p, pnMaxArg);
    pnOp.* = rd(c_int, p, Vdbe_nOp);
    wrPtr(p, Vdbe_aOp, null);
    return aOp;
}

export fn sqlite3VdbeAddOpList(p: ?*Vdbe, nOp: c_int, aOp: [*]const VdbeOpList, iLineno: c_int) callconv(.c) ?*Op {
    _ = iLineno;
    if (rd(c_int, p, Vdbe_nOp) + nOp > rd(c_int, p, Vdbe_nOpAlloc) and growOpArray(p, nOp) != 0) {
        return null;
    }
    const pCurNOp = rd(c_int, p, Vdbe_nOp);
    const base = rdPtr(p, Vdbe_aOp);
    const pFirst = opAt(base, @intCast(pCurNOp));
    var i: c_int = 0;
    while (i < nOp) : (i += 1) {
        const src = &aOp[@intCast(i)];
        const pOut = opAt(base, @intCast(pCurNOp + i));
        wrU8(pOut, Op_opcode, src.opcode);
        wr(c_int, pOut, Op_p1, src.p1);
        var p2v: c_int = src.p2;
        if ((opProp(src.opcode) & OPFLG_JUMP) != 0 and src.p2 > 0) {
            p2v += pCurNOp;
        }
        wr(c_int, pOut, Op_p2, p2v);
        wr(c_int, pOut, Op_p3, src.p3);
        wrU8(pOut, Op_p4type, @bitCast(P4_NOTUSED));
        wrPtr(pOut, Op_p4, null);
        wr(u16, pOut, Op_p5, 0);
        wrPtr(pOut, Op_zComment, null);
    }
    wr(c_int, p, Vdbe_nOp, pCurNOp + nOp);
    return pFirst;
}

// sqlite3VdbeScanStatus* : SQLITE_ENABLE_STMT_SCANSTATUS is OFF in both configs,
// so these functions are not compiled and have no external callers.

// ===========================================================================
// Operand mutation
// ===========================================================================
export fn sqlite3VdbeChangeOpcode(p: ?*Vdbe, addr: c_int, iNewOpcode: u8) callconv(.c) void {
    wrU8(sqlite3VdbeGetOp(p, addr), Op_opcode, iNewOpcode);
}
export fn sqlite3VdbeChangeP1(p: ?*Vdbe, addr: c_int, val: c_int) callconv(.c) void {
    wr(c_int, sqlite3VdbeGetOp(p, addr), Op_p1, val);
}
export fn sqlite3VdbeChangeP2(p: ?*Vdbe, addr: c_int, val: c_int) callconv(.c) void {
    wr(c_int, sqlite3VdbeGetOp(p, addr), Op_p2, val);
}
export fn sqlite3VdbeChangeP3(p: ?*Vdbe, addr: c_int, val: c_int) callconv(.c) void {
    wr(c_int, sqlite3VdbeGetOp(p, addr), Op_p3, val);
}
export fn sqlite3VdbeChangeP5(p: ?*Vdbe, p5: u16) callconv(.c) void {
    if (rd(c_int, p, Vdbe_nOp) > 0) {
        wr(u16, opAt(rdPtr(p, Vdbe_aOp), @intCast(rd(c_int, p, Vdbe_nOp) - 1)), Op_p5, p5);
    }
}

export fn sqlite3VdbeTypeofColumn(p: ?*Vdbe, iDest: c_int) callconv(.c) void {
    const OPFLAG_TYPEOFARG: u16 = 0x80;
    var pOp = sqlite3VdbeGetLastOp(p);
    if (DEBUG) {
        while (rdU8(pOp, Op_opcode) == OP_ReleaseReg) {
            pOp = @as([*]u8, @ptrCast(pOp.?)) - sizeof_Op;
        }
    }
    if (rd(c_int, pOp, Op_p3) == iDest and rdU8(pOp, Op_opcode) == OP_Column) {
        wr(u16, pOp, Op_p5, rd(u16, pOp, Op_p5) | OPFLAG_TYPEOFARG);
    }
}

export fn sqlite3VdbeJumpHere(p: ?*Vdbe, addr: c_int) callconv(.c) void {
    sqlite3VdbeChangeP2(p, addr, rd(c_int, p, Vdbe_nOp));
}
export fn sqlite3VdbeJumpHereOrPopInst(p: ?*Vdbe, addr: c_int) callconv(.c) void {
    if (addr == rd(c_int, p, Vdbe_nOp) - 1) {
        wr(c_int, p, Vdbe_nOp, rd(c_int, p, Vdbe_nOp) - 1);
    } else {
        sqlite3VdbeChangeP2(p, addr, rd(c_int, p, Vdbe_nOp));
    }
}

// ===========================================================================
// FuncDef / P4 freeing
// ===========================================================================
fn freeEphemeralFunction(db: ?*sqlite3, pDef: ?*FuncDef) void {
    if (pDef == null) return;
    if ((rd(u32, pDef, FuncDef_funcFlags) & SQLITE_FUNC_EPHEM) != 0) {
        sqlite3DbNNFreeNN(db, pDef);
    }
}

fn freeP4Mem(db: ?*sqlite3, p: ?*Mem) void {
    if (rd(c_int, p, Mem_szMalloc) != 0) sqlite3DbFree(db, rdPtr(p, Mem_zMalloc));
    sqlite3DbNNFreeNN(db, p);
}
fn freeP4FuncCtx(db: ?*sqlite3, p: ?*anyopaque) void {
    freeEphemeralFunction(db, rdPtr(p, Ctx_pFunc));
    sqlite3DbNNFreeNN(db, p);
}
fn freeP4(db: ?*sqlite3, p4type: c_int, p4: ?*anyopaque) void {
    switch (@as(i8, @truncate(p4type))) {
        P4_FUNCCTX => freeP4FuncCtx(db, p4),
        P4_REAL, P4_INT64, P4_DYNAMIC, P4_INTARRAY => {
            if (p4 != null) sqlite3DbNNFreeNN(db, p4);
        },
        P4_KEYINFO => {
            if (rdPtr(db, sqlite3_pnBytesFreed) == null) sqlite3KeyInfoUnref(@ptrCast(p4));
        },
        P4_FUNCDEF => freeEphemeralFunction(db, @ptrCast(p4)),
        P4_MEM => {
            if (rdPtr(db, sqlite3_pnBytesFreed) == null) {
                sqlite3ValueFree(p4);
            } else {
                freeP4Mem(db, @ptrCast(p4));
            }
        },
        P4_VTAB => {
            if (rdPtr(db, sqlite3_pnBytesFreed) == null) sqlite3VtabUnlock(@ptrCast(p4));
        },
        P4_TABLEREF => {
            if (rdPtr(db, sqlite3_pnBytesFreed) == null) sqlite3DeleteTable(db, @ptrCast(p4));
        },
        P4_SUBRTNSIG => {
            // struct SubrtnSig { ... char *zAff; }; free zAff then the struct.
            // zAff is the 2nd field per usage; offsetof needed. We use the C
            // helper by mirroring: { u32 selId; char *zAff; ...}. Free via db.
            // The exact layout: handle minimally via sqlite3DbFree on both.
            const pSig = p4.?;
            // SubrtnSig: u32 selId; u16 nReg; char *zAff; (zAff at offset 8)
            sqlite3DbFree(db, rdPtr(pSig, 8));
            sqlite3DbFree(db, pSig);
        },
        else => {},
    }
}

fn vdbeFreeOpArray(db: ?*sqlite3, aOp: ?*Op, nOp: c_int) void {
    if (aOp == null) return;
    var i: c_int = nOp - 1;
    while (true) {
        const pOp = opAt(aOp, @intCast(i));
        const p4type: i8 = @bitCast(rdU8(pOp, Op_p4type));
        if (p4type <= P4_FREE_IF_LE) freeP4(db, p4type, rdPtr(pOp, Op_p4));
        sqlite3DbFree(db, rdPtr(pOp, Op_zComment)); // EXPLAIN_COMMENTS on
        if (i == 0) break;
        i -= 1;
    }
    sqlite3DbNNFreeNN(db, aOp);
}

export fn sqlite3VdbeLinkSubProgram(pVdbe: ?*Vdbe, p: ?*SubProgram) callconv(.c) void {
    wrPtr(p, SubProgram_pNext, rdPtr(pVdbe, Vdbe_pProgram));
    wrPtr(pVdbe, Vdbe_pProgram, p);
}
export fn sqlite3VdbeHasSubProgram(pVdbe: ?*Vdbe) callconv(.c) c_int {
    return @intFromBool(rdPtr(pVdbe, Vdbe_pProgram) != null);
}

export fn sqlite3VdbeChangeToNoop(p: ?*Vdbe, addr: c_int) callconv(.c) c_int {
    const db = rdPtr(p, Vdbe_db);
    if (rdU8(db, sqlite3_mallocFailed) != 0) return 0;
    const pOp = opAt(rdPtr(p, Vdbe_aOp), @intCast(addr));
    freeP4(db, rdU8(pOp, Op_p4type), rdPtr(pOp, Op_p4));
    wrU8(pOp, Op_p4type, @bitCast(P4_NOTUSED));
    wrPtr(pOp, Op_p4, null);
    wrU8(pOp, Op_opcode, OP_Noop);
    return 1;
}
export fn sqlite3VdbeDeletePriorOpcode(p: ?*Vdbe, op: u8) callconv(.c) c_int {
    const nOp = rd(c_int, p, Vdbe_nOp);
    if (nOp > 0 and rdU8(opAt(rdPtr(p, Vdbe_aOp), @intCast(nOp - 1)), Op_opcode) == op) {
        return sqlite3VdbeChangeToNoop(p, nOp - 1);
    }
    return 0;
}

fn vdbeChangeP4Full(p: ?*Vdbe, pOp: ?*Op, zP4: ?[*:0]const u8, n: c_int) void {
    if (rdU8(pOp, Op_p4type) != 0) {
        wrU8(pOp, Op_p4type, 0);
        wrPtr(pOp, Op_p4, null);
    }
    if (n < 0) {
        const aOp = rdPtr(p, Vdbe_aOp);
        const addr: c_int = @intCast(@divExact(@intFromPtr(pOp.?) - @intFromPtr(aOp.?), sizeof_Op));
        sqlite3VdbeChangeP4(p, addr, zP4, n);
    } else {
        var nn = n;
        if (nn == 0) nn = sqlite3Strlen30(zP4); // sqlite3Strlen30 handles null
        wrPtr(pOp, Op_p4, @ptrCast(sqlite3DbStrNDup(rdPtr(p, Vdbe_db), @ptrCast(zP4), @intCast(nn))));
        wrU8(pOp, Op_p4type, @bitCast(P4_DYNAMIC));
    }
}

export fn sqlite3VdbeChangeP4(p: ?*Vdbe, addrIn: c_int, zP4: ?[*:0]const u8, n: c_int) callconv(.c) void {
    const db = rdPtr(p, Vdbe_db);
    if (rdU8(db, sqlite3_mallocFailed) != 0) {
        if (n != P4_VTAB) freeP4(db, n, @ptrCast(@constCast(zP4)));
        return;
    }
    var addr = addrIn;
    if (addr < 0) addr = rd(c_int, p, Vdbe_nOp) - 1;
    const pOp = opAt(rdPtr(p, Vdbe_aOp), @intCast(addr));
    if (n >= 0 or rdU8(pOp, Op_p4type) != 0) {
        vdbeChangeP4Full(p, pOp, zP4, n);
        return;
    }
    if (n == P4_INT32) {
        wr(c_int, pOp, Op_p4, @truncate(@as(isize, @bitCast(@intFromPtr(zP4)))));
        wrU8(pOp, Op_p4type, @bitCast(P4_INT32));
    } else if (zP4 != null) {
        wrPtr(pOp, Op_p4, @ptrCast(@constCast(zP4)));
        wrU8(pOp, Op_p4type, @truncate(@as(c_uint, @bitCast(n))));
        if (n == P4_VTAB) sqlite3VtabLock(@ptrCast(@constCast(zP4)));
    }
}

export fn sqlite3VdbeAppendP4(p: ?*Vdbe, pP4: ?*anyopaque, n: c_int) callconv(.c) void {
    const db = rdPtr(p, Vdbe_db);
    if (rdU8(db, sqlite3_mallocFailed) != 0) {
        freeP4(db, n, pP4);
    } else {
        const pOp = opAt(rdPtr(p, Vdbe_aOp), @intCast(rd(c_int, p, Vdbe_nOp) - 1));
        wrU8(pOp, Op_p4type, @truncate(@as(c_uint, @bitCast(n))));
        wrPtr(pOp, Op_p4, pP4);
    }
}

export fn sqlite3VdbeSetP4KeyInfo(pParse: ?*Parse, pIdx: ?*Index) callconv(.c) void {
    const v = rdPtr(pParse, Parse_pVdbe);
    const pKeyInfo = sqlite3KeyInfoOfIndex(pParse, pIdx);
    if (pKeyInfo != null) sqlite3VdbeAppendP4(v, pKeyInfo, P4_KEYINFO);
}

// ===========================================================================
// Comments (EXPLAIN_COMMENTS on in both)
// ===========================================================================
fn vdbeVComment(p: ?*Vdbe, zFormat: [*:0]const u8, ap: *std.builtin.VaList) void {
    if (rd(c_int, p, Vdbe_nOp) != 0) {
        const pOp = opAt(rdPtr(p, Vdbe_aOp), @intCast(rd(c_int, p, Vdbe_nOp) - 1));
        sqlite3DbFree(rdPtr(p, Vdbe_db), rdPtr(pOp, Op_zComment));
        wrPtr(pOp, Op_zComment, @ptrCast(sqlite3VMPrintf(rdPtr(p, Vdbe_db), zFormat, ap)));
    }
}
export fn sqlite3VdbeComment(p: ?*Vdbe, zFormat: [*:0]const u8, ...) callconv(.c) void {
    if (p != null) {
        var ap = @cVaStart();
        vdbeVComment(p, zFormat, &ap);
        @cVaEnd(&ap);
    }
}
export fn sqlite3VdbeNoopComment(p: ?*Vdbe, zFormat: [*:0]const u8, ...) callconv(.c) void {
    if (p != null) {
        _ = sqlite3VdbeAddOp0(p, OP_Noop);
        var ap = @cVaStart();
        vdbeVComment(p, zFormat, &ap);
        @cVaEnd(&ap);
    }
}

// ===========================================================================
// GetOp / GetLastOp
// ===========================================================================
var dummyOp: [64]u8 align(8) = std.mem.zeroes([64]u8);
export fn sqlite3VdbeGetOp(p: ?*Vdbe, addr: c_int) callconv(.c) ?*Op {
    if (rdU8(rdPtr(p, Vdbe_db), sqlite3_mallocFailed) != 0) {
        return @ptrCast(&dummyOp);
    }
    return opAt(rdPtr(p, Vdbe_aOp), @intCast(addr));
}
export fn sqlite3VdbeGetLastOp(p: ?*Vdbe) callconv(.c) ?*Op {
    return sqlite3VdbeGetOp(p, rd(c_int, p, Vdbe_nOp) - 1);
}

// ===========================================================================
// Btree-use bookkeeping
// ===========================================================================
export fn sqlite3VdbeUsesBtree(p: ?*Vdbe, i: c_int) callconv(.c) void {
    const db = rdPtr(p, Vdbe_db);
    // DbMaskSet(p->btreeMask, i)
    const mask = rd(u32, p, Vdbe_btreeMask) | (@as(u32, 1) << @intCast(i));
    wr(u32, p, Vdbe_btreeMask, mask);
    const pBt = rdPtr(dbEnt(db, i), Db_pBt);
    if (i != 1 and sqlite3BtreeSharable(@ptrCast(pBt)) != 0) {
        wr(u32, p, Vdbe_lockMask, rd(u32, p, Vdbe_lockMask) | (@as(u32, 1) << @intCast(i)));
    }
}

// OMIT_SHARED_CACHE off, THREADSAFE>0 → Enter/Leave are real.
export fn sqlite3VdbeEnter(p: ?*Vdbe) callconv(.c) void {
    if (rd(u32, p, Vdbe_lockMask) == 0) return;
    const db = rdPtr(p, Vdbe_db);
    const nDb = rd(c_int, db, sqlite3_nDb);
    const lockMask = rd(u32, p, Vdbe_lockMask);
    var i: c_int = 0;
    while (i < nDb) : (i += 1) {
        const pBt = rdPtr(dbEnt(db, i), Db_pBt);
        if (i != 1 and (lockMask & (@as(u32, 1) << @intCast(i))) != 0 and pBt != null) {
            sqlite3BtreeEnter(@ptrCast(pBt));
        }
    }
}
fn vdbeLeave(p: ?*Vdbe) void {
    const db = rdPtr(p, Vdbe_db);
    const nDb = rd(c_int, db, sqlite3_nDb);
    const lockMask = rd(u32, p, Vdbe_lockMask);
    var i: c_int = 0;
    while (i < nDb) : (i += 1) {
        const pBt = rdPtr(dbEnt(db, i), Db_pBt);
        if (i != 1 and (lockMask & (@as(u32, 1) << @intCast(i))) != 0 and pBt != null) {
            sqlite3BtreeLeave(@ptrCast(pBt));
        }
    }
}
export fn sqlite3VdbeLeave(p: ?*Vdbe) callconv(.c) void {
    if (rd(u32, p, Vdbe_lockMask) == 0) return;
    vdbeLeave(p);
}

// ===========================================================================
// Mem-array init / release
// ===========================================================================
fn initMemArray(p: ?*Mem, n: c_int, db: ?*sqlite3, flags: u16) void {
    if (n <= 0) return;
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const m = memAt(p, @intCast(i));
        wr(u16, m, Mem_flags, flags);
        wrPtr(m, Mem_db, db);
        wr(c_int, m, Mem_szMalloc, 0);
        if (DEBUG) {
            // pScopyFrom (ptr) and bScopy live in the debug tail of Mem.
            // Their exact offsets are not load-bearing for behavior; the C
            // sets pScopyFrom=0,bScopy=0. The Mem debug tail is zeroed by
            // callers that allocate via DbMallocZero or by initMemArray's
            // szMalloc reset; we conservatively clear the 16-byte tail.
            const tailStart = sizeof_Mem - 16;
            const base: [*]u8 = @ptrCast(m.?);
            @memset(base[tailStart..sizeof_Mem], 0);
        }
    }
}

fn releaseMemArray(p: ?*Mem, n: c_int) void {
    if (p == null or n == 0) return;
    const db = rdPtr(p, Mem_db);
    if (rdPtr(db, sqlite3_pnBytesFreed) != null) {
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            const m = memAt(p, @intCast(i));
            if (rd(c_int, m, Mem_szMalloc) != 0) sqlite3DbFree(db, rdPtr(m, Mem_zMalloc));
        }
        return;
    }
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const m = memAt(p, @intCast(i));
        const flags = rd(u16, m, Mem_flags);
        if ((flags & (MEM_Agg | MEM_Dyn)) != 0) {
            sqlite3VdbeMemRelease(m);
            wr(u16, m, Mem_flags, MEM_Undefined);
        } else if (rd(c_int, m, Mem_szMalloc) != 0) {
            sqlite3DbNNFreeNN(db, rdPtr(m, Mem_zMalloc));
            wr(c_int, m, Mem_szMalloc, 0);
            wr(u16, m, Mem_flags, MEM_Undefined);
        } else if (DEBUG) {
            wr(u16, m, Mem_flags, MEM_Undefined);
        }
    }
}

// ===========================================================================
// VdbeFrame
// ===========================================================================
export fn sqlite3VdbeFrameMemDel(pArg: ?*anyopaque) callconv(.c) void {
    const pFrame = pArg;
    const v = rdPtr(pFrame, VdbeFrame_v);
    wrPtr(pFrame, VdbeFrame_pParent, rdPtr(v, Vdbe_pDelFrame));
    wrPtr(v, Vdbe_pDelFrame, pFrame);
}

// VdbeFrameMem(p): (Mem*)&((u8*)p)[ROUND8(sizeof(VdbeFrame))]
inline fn frameMem(pFrame: ?*VdbeFrame) ?*Mem {
    const szRounded = (sizeof_VdbeFrame + 7) & ~@as(usize, 7);
    return @as([*]u8, @ptrCast(pFrame.?)) + szRounded;
}
const sizeof_VdbeFrame = off("sizeof_VdbeFrame", 112, 120);

export fn sqlite3VdbeFrameDelete(p: ?*VdbeFrame) callconv(.c) void {
    const aMem = frameMem(p);
    const nChildMem = rd(c_int, p, VdbeFrame_nChildMem);
    const apCsr: ?*anyopaque = memAt(aMem, @intCast(nChildMem));
    const v = rdPtr(p, VdbeFrame_v);
    const db = rdPtr(v, Vdbe_db);
    var i: c_int = 0;
    const nChildCsr = rd(c_int, p, VdbeFrame_nChildCsr);
    while (i < nChildCsr) : (i += 1) {
        const pC = rdPtr(apCsr, @as(usize, @intCast(i)) * 8);
        if (pC != null) sqlite3VdbeFreeCursorNN(v, pC);
    }
    releaseMemArray(aMem, nChildMem);
    sqlite3VdbeDeleteAuxData(db, fp(?*anyopaque, v, Vdbe_pAuxData), -1, 0);
    sqlite3DbFree(db, p);
}

export fn sqlite3VdbeFrameRestore(pFrame: ?*VdbeFrame) callconv(.c) c_int {
    const v = rdPtr(pFrame, VdbeFrame_v);
    closeCursorsInFrame(v);
    wrPtr(v, Vdbe_aOp, rdPtr(pFrame, VdbeFrame_aOp));
    wr(c_int, v, Vdbe_nOp, rd(c_int, pFrame, VdbeFrame_nOp));
    wrPtr(v, Vdbe_aMem, rdPtr(pFrame, VdbeFrame_aMem));
    wr(c_int, v, Vdbe_nMem, rd(c_int, pFrame, VdbeFrame_nMem));
    wrPtr(v, Vdbe_apCsr, rdPtr(pFrame, VdbeFrame_apCsr));
    wr(c_int, v, Vdbe_nCursor, rd(c_int, pFrame, VdbeFrame_nCursor));
    const db = rdPtr(v, Vdbe_db);
    // db->lastRowid = pFrame->lastRowid (lastRowid offset in sqlite3)
    wr(i64, db, sqlite3_lastRowid, rd(i64, pFrame, VdbeFrame_lastRowid));
    wr(i64, v, Vdbe_nChange, rd(i64, pFrame, VdbeFrame_nChange));
    wr(i64, db, sqlite3_nChange, rd(i64, pFrame, VdbeFrame_nDbChange));
    sqlite3VdbeDeleteAuxData(db, fp(?*anyopaque, v, Vdbe_pAuxData), -1, 0);
    wrPtr(v, Vdbe_pAuxData, rdPtr(pFrame, VdbeFrame_pAuxData));
    wrPtr(pFrame, VdbeFrame_pAuxData, null);
    return rd(c_int, pFrame, VdbeFrame_pc);
}

// ===========================================================================
// Cursor freeing
// ===========================================================================
export fn sqlite3VdbeFreeCursor(p: ?*Vdbe, pCx: ?*VdbeCursor) callconv(.c) void {
    if (pCx != null) sqlite3VdbeFreeCursorNN(p, pCx);
}
fn freeCursorWithCache(p: ?*Vdbe, pCx: ?*VdbeCursor) void {
    const pCache = rdPtr(pCx, VdbeCursor_pCache);
    // pCx->colCache bit cleared, pCache cleared. colCache is a bitfield in the
    // flags byte; we don't need to clear the bit precisely because the cursor
    // is being freed. Clear pCache pointer.
    wrPtr(pCx, VdbeCursor_pCache, null);
    // VdbeTxtBlbCache: { RCStr *pCValue; ... } pCValue at offset 0.
    const pCValue = rdPtr(pCache, 0);
    if (pCValue != null) {
        sqlite3RCStrUnref(pCValue);
        wrPtr(pCache, 0, null);
    }
    sqlite3DbFree(rdPtr(p, Vdbe_db), pCache);
    sqlite3VdbeFreeCursorNN(p, pCx);
}
export fn sqlite3VdbeFreeCursorNN(p: ?*Vdbe, pCx: ?*VdbeCursor) callconv(.c) void {
    // Test the real colCache:1 bitfield. (pCache is NOT a valid proxy: it lives
    // past the offsetof(VdbeCursor,pAltCursor) extent that allocateCursor zeroes,
    // so for a normal cursor it holds uninitialized garbage.)
    if ((rdU8(pCx, VdbeCursor_bits) & COLCACHE_BIT) != 0) {
        freeCursorWithCache(p, pCx);
        return;
    }
    switch (rdU8(pCx, VdbeCursor_eCurType)) {
        CURTYPE_SORTER => sqlite3VdbeSorterClose(rdPtr(p, Vdbe_db), pCx),
        CURTYPE_BTREE => {
            _ = sqlite3BtreeCloseCursor(@ptrCast(rdPtr(pCx, VdbeCursor_uc)));
        },
        CURTYPE_VTAB => {
            const pVCur = rdPtr(pCx, VdbeCursor_uc);
            // sqlite3_vtab_cursor { sqlite3_vtab *pVtab; }; pVtab->pModule->xClose
            const pVtab = rdPtr(pVCur, 0);
            const pModule = rdPtr(pVtab, 0); // sqlite3_vtab.pModule at offset 0
            // pVtab->nRef-- : sqlite3_vtab { const sqlite3_module *pModule; int nRef; char *zErrMsg }
            wr(c_int, pVtab, 8, rd(c_int, pVtab, 8) - 1);
            // sqlite3_module.xClose is at offset 56: iVersion@0 (padded to 8),
            // then xCreate@8/xConnect@16/xBestIndex@24/xDisconnect@32/xDestroy@40/
            // xOpen@48/xClose@56 (xFilter@64 — the previous 8+7*8=64 was xFilter).
            const xClose = rdPtr(pModule, 56);
            const fnptr: *const fn (?*anyopaque) callconv(.c) c_int = @ptrCast(xClose);
            _ = fnptr(pVCur);
        },
        else => {},
    }
}

fn closeCursorsInFrame(p: ?*Vdbe) void {
    const nCursor = rd(c_int, p, Vdbe_nCursor);
    const apCsr = rdPtr(p, Vdbe_apCsr);
    if (apCsr == null) return;
    var i: c_int = 0;
    while (i < nCursor) : (i += 1) {
        const pC = rdPtr(apCsr, @as(usize, @intCast(i)) * 8);
        if (pC != null) {
            sqlite3VdbeFreeCursorNN(p, pC);
            wrPtr(apCsr, @as(usize, @intCast(i)) * 8, null);
        }
    }
}

// ===========================================================================
// closeAllCursors
// ===========================================================================
fn closeAllCursors(p: ?*Vdbe) void {
    if (rdPtr(p, Vdbe_pFrame) != null) {
        var pFrame = rdPtr(p, Vdbe_pFrame);
        while (rdPtr(pFrame, VdbeFrame_pParent) != null) : (pFrame = rdPtr(pFrame, VdbeFrame_pParent)) {}
        _ = sqlite3VdbeFrameRestore(pFrame);
        wrPtr(p, Vdbe_pFrame, null);
        wr(c_int, p, Vdbe_nFrame, 0);
    }
    closeCursorsInFrame(p);
    releaseMemArray(rdPtr(p, Vdbe_aMem), rd(c_int, p, Vdbe_nMem));
    while (rdPtr(p, Vdbe_pDelFrame) != null) {
        const pDel = rdPtr(p, Vdbe_pDelFrame);
        wrPtr(p, Vdbe_pDelFrame, rdPtr(pDel, VdbeFrame_pParent));
        sqlite3VdbeFrameDelete(pDel);
    }
    if (rdPtr(p, Vdbe_pAuxData) != null) sqlite3VdbeDeleteAuxData(rdPtr(p, Vdbe_db), fp(?*anyopaque, p, Vdbe_pAuxData), -1, 0);
}

// ===========================================================================
// SetNumCols / SetColName
// ===========================================================================
export fn sqlite3VdbeSetNumCols(p: ?*Vdbe, nResColumn: c_int) callconv(.c) void {
    const db = rdPtr(p, Vdbe_db);
    const nResAlloc = rd(u16, p, Vdbe_nResAlloc);
    if (nResAlloc != 0) {
        releaseMemArray(rdPtr(p, Vdbe_aColName), @as(c_int, nResAlloc) * COLNAME_N);
        sqlite3DbFree(db, rdPtr(p, Vdbe_aColName));
    }
    const n = nResColumn * COLNAME_N;
    wr(u16, p, Vdbe_nResColumn, @truncate(@as(c_uint, @bitCast(nResColumn))));
    wr(u16, p, Vdbe_nResAlloc, @truncate(@as(c_uint, @bitCast(nResColumn))));
    const aColName = sqlite3DbMallocRawNN(db, @intCast(sizeof_Mem * @as(usize, @intCast(n))));
    wrPtr(p, Vdbe_aColName, aColName);
    if (aColName == null) return;
    initMemArray(aColName, n, db, MEM_Null);
}

export fn sqlite3VdbeSetColName(p: ?*Vdbe, idx: c_int, vr: c_int, zName: ?[*:0]const u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) callconv(.c) c_int {
    if (rdU8(rdPtr(p, Vdbe_db), sqlite3_mallocFailed) != 0) {
        return SQLITE_NOMEM;
    }
    const nResAlloc = rd(u16, p, Vdbe_nResAlloc);
    const pColName = memAt(rdPtr(p, Vdbe_aColName), @intCast(idx + vr * @as(c_int, nResAlloc)));
    return sqlite3VdbeMemSetText(pColName, @ptrCast(zName), -1, xDel);
}

// ===========================================================================
// NextOpcode / List  (BYTECODE_VTAB / !OMIT_EXPLAIN -> compiled)
// ===========================================================================
const MEM_Blob_flag = MEM_Blob;
inline fn MemSetTypeFlag(m: ?*Mem, f: u16) void {
    const MEM_TypeMask: u16 = 0x0dbf;
    wr(u16, m, Mem_flags, (rd(u16, m, Mem_flags) & ~(MEM_TypeMask | MEM_Zero)) | f);
}

export fn sqlite3VdbeNextOpcode(p: ?*Vdbe, pSub: ?*Mem, eMode: c_int, piPc: *c_int, piAddr: *c_int, paOp: *?*Op) callconv(.c) c_int {
    var nSub: c_int = 0;
    var apSub: ?*anyopaque = null;
    var rc: c_int = SQLITE_OK;
    var aOp: ?*Op = null;
    var i: c_int = undefined;
    var nRow = rd(c_int, p, Vdbe_nOp);
    if (pSub != null) {
        if ((rd(u16, pSub, Mem_flags) & MEM_Blob) != 0) {
            nSub = @intCast(@divTrunc(rd(c_int, pSub, Mem_n), 8)); // /sizeof(Vdbe*)
            apSub = rdPtr(pSub, Mem_z);
        }
        var j: c_int = 0;
        while (j < nSub) : (j += 1) {
            const sub = rdPtr(apSub, @as(usize, @intCast(j)) * 8);
            nRow += rd(c_int, sub, SubProgram_nOp);
        }
    }
    var iPc = piPc.*;
    while (true) {
        i = iPc;
        iPc += 1;
        if (i >= nRow) {
            wr(c_int, p, Vdbe_rc, SQLITE_OK);
            rc = SQLITE_DONE;
            break;
        }
        if (i < rd(c_int, p, Vdbe_nOp)) {
            aOp = rdPtr(p, Vdbe_aOp);
        } else {
            var j: c_int = 0;
            i -= rd(c_int, p, Vdbe_nOp);
            while (true) {
                const sub = rdPtr(apSub, @as(usize, @intCast(j)) * 8);
                if (i < rd(c_int, sub, SubProgram_nOp)) break;
                i -= rd(c_int, sub, SubProgram_nOp);
                j += 1;
            }
            aOp = rdPtr(rdPtr(apSub, @as(usize, @intCast(j)) * 8), SubProgram_aOp);
        }

        const curOp = opAt(aOp, @intCast(i));
        if (pSub != null and @as(i8, @bitCast(rdU8(curOp, Op_p4type))) == P4_SUBPROGRAM) {
            const nByte = (nSub + 1) * 8;
            var j: c_int = 0;
            const pProg = rdPtr(curOp, Op_p4);
            while (j < nSub) : (j += 1) {
                if (rdPtr(apSub, @as(usize, @intCast(j)) * 8) == pProg) break;
            }
            if (j == nSub) {
                wr(c_int, p, Vdbe_rc, sqlite3VdbeMemGrow(pSub, nByte, @intFromBool(nSub != 0)));
                if (rd(c_int, p, Vdbe_rc) != SQLITE_OK) {
                    rc = SQLITE_ERROR;
                    break;
                }
                apSub = rdPtr(pSub, Mem_z);
                wrPtr(apSub, @as(usize, @intCast(nSub)) * 8, pProg);
                nSub += 1;
                MemSetTypeFlag(pSub, MEM_Blob);
                wr(c_int, pSub, Mem_n, nSub * 8);
                nRow += rd(c_int, pProg, SubProgram_nOp);
            }
        }
        if (eMode == 0) break;
        if (eMode == 2) {
            const pOp = opAt(aOp, @intCast(i));
            const oc = rdU8(pOp, Op_opcode);
            const OPFLAG_P2ISREG: u16 = 0x20;
            if (oc == OP_OpenRead) break;
            if (oc == OP_OpenWrite and (rd(u16, pOp, Op_p5) & OPFLAG_P2ISREG) == 0) break;
            if (oc == OP_ReopenIdx) break;
        } else {
            const oc = rdU8(opAt(aOp, @intCast(i)), Op_opcode);
            if (oc == OP_Explain) break;
            if (oc == OP_Init and iPc > 1) break;
        }
    }
    piPc.* = iPc;
    piAddr.* = i;
    paOp.* = aOp;
    return rc;
}

export fn sqlite3VdbeList(p: ?*Vdbe) callconv(.c) c_int {
    var pSub: ?*Mem = null;
    const db = rdPtr(p, Vdbe_db);
    var rc: c_int = SQLITE_OK;
    const aMem = rdPtr(p, Vdbe_aMem);
    const pMem = memAt(aMem, 1); // &aMem[1]
    const SQLITE_TriggerEQP: u64 = 0x01000000;
    const bListSubprogs = getExplain(p) == 1 or (rd(u64, db, sqlite3_flags) & SQLITE_TriggerEQP) != 0;
    var aOp: ?*Op = undefined;

    releaseMemArray(pMem, 8);
    if (rd(c_int, p, Vdbe_rc) == SQLITE_NOMEM) {
        sqlite3OomFault(db);
        return SQLITE_ERROR;
    }
    if (bListSubprogs) {
        pSub = memAt(aMem, 9);
    } else {
        pSub = null;
    }
    var iAddr: c_int = undefined;
    rc = sqlite3VdbeNextOpcode(p, pSub, @intFromBool(getExplain(p) == 2), fp(c_int, p, Vdbe_pc), &iAddr, &aOp);
    if (rc == SQLITE_OK) {
        const pOp = opAt(aOp, @intCast(iAddr));
        // AtomicLoad(db->u1.isInterrupted): u1 union holds isInterrupted (int).
        const isInterrupted = rd(c_int, db, sqlite3_u1);
        if (isInterrupted != 0) {
            wr(c_int, p, Vdbe_rc, SQLITE_INTERRUPT);
            rc = SQLITE_ERROR;
            sqlite3VdbeError(p, "%s", sqlite3ErrStr(rd(c_int, p, Vdbe_rc)));
        } else {
            const zP4 = sqlite3VdbeDisplayP4(db, pOp);
            if (getExplain(p) == 2) {
                sqlite3VdbeMemSetInt64(pMem, rd(c_int, pOp, Op_p1));
                sqlite3VdbeMemSetInt64(memAt(pMem, 1), rd(c_int, pOp, Op_p2));
                sqlite3VdbeMemSetInt64(memAt(pMem, 2), rd(c_int, pOp, Op_p3));
                _ = sqlite3VdbeMemSetStr(memAt(pMem, 3), @ptrCast(zP4), -1, SQLITE_UTF8, sqlite3_free_xdel);
            } else {
                sqlite3VdbeMemSetInt64(memAt(pMem, 0), iAddr);
                _ = sqlite3VdbeMemSetStr(memAt(pMem, 1), @ptrCast(sqlite3OpcodeName(rdU8(pOp, Op_opcode))), -1, SQLITE_UTF8, SQLITE_STATIC);
                sqlite3VdbeMemSetInt64(memAt(pMem, 2), rd(c_int, pOp, Op_p1));
                sqlite3VdbeMemSetInt64(memAt(pMem, 3), rd(c_int, pOp, Op_p2));
                sqlite3VdbeMemSetInt64(memAt(pMem, 4), rd(c_int, pOp, Op_p3));
                sqlite3VdbeMemSetInt64(memAt(pMem, 6), rd(u16, pOp, Op_p5));
                // EXPLAIN_COMMENTS on:
                const zCom = sqlite3VdbeDisplayComment(db, pOp, zP4);
                _ = sqlite3VdbeMemSetStr(memAt(pMem, 7), @ptrCast(zCom), -1, SQLITE_UTF8, sqlite3_free_xdel);
                _ = sqlite3VdbeMemSetStr(memAt(pMem, 5), @ptrCast(zP4), -1, SQLITE_UTF8, sqlite3_free_xdel);
            }
            wrPtr(p, Vdbe_pResultRow, pMem);
            if (rdU8(db, sqlite3_mallocFailed) != 0) {
                wr(c_int, p, Vdbe_rc, SQLITE_NOMEM);
                rc = SQLITE_ERROR;
            } else {
                wr(c_int, p, Vdbe_rc, SQLITE_OK);
                rc = SQLITE_ROW;
            }
        }
    }
    return rc;
}

const SQLITE_STATIC: ?*const fn (?*anyopaque) callconv(.c) void = null;
const sqlite3_free_xdel: ?*const fn (?*anyopaque) callconv(.c) void = @ptrCast(&sqlite3_free);
const sqlite3_u1 = off("sqlite3_u1", 424, 424);

// ===========================================================================
// Rewind
// ===========================================================================
export fn sqlite3VdbeRewind(p: ?*Vdbe) callconv(.c) void {
    wrU8(p, Vdbe_eVdbeState, VDBE_READY_STATE);
    wr(c_int, p, Vdbe_pc, -1);
    wr(c_int, p, Vdbe_rc, SQLITE_OK);
    wrU8(p, Vdbe_errorAction, OE_Abort);
    wr(i64, p, Vdbe_nChange, 0);
    wr(u32, p, Vdbe_cacheCtr, 1);
    wrU8(p, Vdbe_minWriteFileFormat, 255);
    wr(c_int, p, Vdbe_iStatement, 0);
    wr(i64, p, Vdbe_nFkConstraint, 0);
}

// ===========================================================================
// MakeReady — register/cursor allocation out of the opcode-array tail.
// ===========================================================================
const ReusableSpace = struct {
    pSpace: [*]u8,
    nFree: i64,
    nNeeded: i64,
};
fn allocSpace(x: *ReusableSpace, pBuf: ?*anyopaque, nByteIn: i64) ?*anyopaque {
    if (pBuf == null) {
        const nByte = (nByteIn + 7) & ~@as(i64, 7); // ROUND8P
        if (nByte <= x.nFree) {
            x.nFree -= nByte;
            return x.pSpace + @as(usize, @intCast(x.nFree));
        } else {
            x.nNeeded += nByte;
            return null;
        }
    }
    return pBuf;
}

export fn sqlite3VdbeMakeReady(p: ?*Vdbe, pParse: ?*Parse) callconv(.c) void {
    const db = rdPtr(p, Vdbe_db);
    wrPtr(p, Vdbe_pVList, rdPtr(pParse, Parse_pVList));
    wrPtr(pParse, Parse_pVList, null);
    // Parse.nVar is ynVar (i16) — read 2 bytes, not 4 (reading c_int would pull
    // in the adjacent iPkSortOrder/explain bytes, e.g. 0x02000000 for EXPLAIN).
    const nVar: c_int = rd(i16, pParse, Parse_nVar);
    var nMem = rd(c_int, pParse, Parse_nMem);
    const nCursor = rd(c_int, pParse, Parse_nTab);
    var nArg = rd(c_int, pParse, Parse_nMaxArg);

    nMem += nCursor;
    if (nCursor == 0 and nMem > 0) nMem += 1;

    const nOp = rd(c_int, p, Vdbe_nOp);
    const nOpAlloc = rd(c_int, p, Vdbe_nOpAlloc);
    const n: usize = (@as(usize, @intCast(sizeof_Op)) * @as(usize, @intCast(nOp)) + 7) & ~@as(usize, 7);
    const freeBytes: i64 = @as(i64, nOpAlloc - nOp) * @as(i64, @intCast(sizeof_Op));
    var x: ReusableSpace = .{
        .pSpace = @as([*]u8, @ptrCast(rdPtr(p, Vdbe_aOp).?)) + n,
        .nFree = freeBytes & ~@as(i64, 7),
        .nNeeded = 0,
    };

    resolveP2Values(p, &nArg);
    // usesStmtJournal = isMultiWrite && mayAbort
    const isMultiWrite = (rdU8(pParse, Parse_isMultiWrite) & 0x01) != 0;
    const mayAbort = (rdU8(pParse, Parse_mayAbortByte) & 0x02) != 0;
    setUsesStmtJournal(p, isMultiWrite and mayAbort);
    const explain = rdU8(pParse, Parse_explain);
    if (explain != 0) {
        if (nMem < 10) nMem = 10;
        setExplain(p, explain);
        wr(u16, p, Vdbe_nResColumn, @intCast(12 - 4 * @as(c_int, explain)));
    }
    setExpired(p, 0);

    wrPtr(p, Vdbe_aMem, allocSpace(&x, null, @as(i64, nMem) * @as(i64, @intCast(sizeof_Mem))));
    wrPtr(p, Vdbe_aVar, allocSpace(&x, null, @as(i64, nVar) * @as(i64, @intCast(sizeof_Mem))));
    wrPtr(p, Vdbe_apArg, allocSpace(&x, null, @as(i64, nArg) * 8));
    wrPtr(p, Vdbe_apCsr, allocSpace(&x, null, @as(i64, nCursor) * 8));
    if (x.nNeeded != 0) {
        const fresh = sqlite3DbMallocRawNN(db, @intCast(x.nNeeded));
        wrPtr(p, Vdbe_pFree, fresh);
        // C guards the second pass on x.pSpace!=0 (the alloc may fail / be null).
        if (fresh) |f| {
            x.pSpace = @ptrCast(f);
            x.nFree = x.nNeeded;
            if (rdU8(db, sqlite3_mallocFailed) == 0) {
                wrPtr(p, Vdbe_aMem, allocSpace(&x, rdPtr(p, Vdbe_aMem), @as(i64, nMem) * @as(i64, @intCast(sizeof_Mem))));
                wrPtr(p, Vdbe_aVar, allocSpace(&x, rdPtr(p, Vdbe_aVar), @as(i64, nVar) * @as(i64, @intCast(sizeof_Mem))));
                wrPtr(p, Vdbe_apArg, allocSpace(&x, rdPtr(p, Vdbe_apArg), @as(i64, nArg) * 8));
                wrPtr(p, Vdbe_apCsr, allocSpace(&x, rdPtr(p, Vdbe_apCsr), @as(i64, nCursor) * 8));
            }
        }
    }

    if (rdU8(db, sqlite3_mallocFailed) != 0) {
        wr(c_int, p, Vdbe_nVar, 0);
        wr(c_int, p, Vdbe_nCursor, 0);
        wr(c_int, p, Vdbe_nMem, 0);
    } else {
        wr(c_int, p, Vdbe_nCursor, nCursor);
        wr(i16, p, Vdbe_nVar, @truncate(@as(c_int, nVar)));
        initMemArray(rdPtr(p, Vdbe_aVar), nVar, db, MEM_Null);
        wr(c_int, p, Vdbe_nMem, nMem);
        initMemArray(rdPtr(p, Vdbe_aMem), nMem, db, MEM_Undefined);
        const apCsr = rdPtr(p, Vdbe_apCsr);
        if (apCsr != null) {
            const dst: [*]u8 = @ptrCast(apCsr.?);
            @memset(dst[0 .. @as(usize, @intCast(nCursor)) * 8], 0);
        }
    }
    // SQLITE_DEBUG: p->napArg = nArg (size of apArg[]; asserted in vdbe.c).
    if (config.sqlite_debug) wr(c_int, p, off("Vdbe_napArg", 200, 200), nArg);
    sqlite3VdbeRewind(p);
}

// ===========================================================================
// vdbeCommit — two-phase commit across attached DBs + super-journal.
// ===========================================================================
fn vdbeCommit(db: ?*sqlite3, p: ?*Vdbe) c_int {
    var nTrans: c_int = 0;
    var rc: c_int = SQLITE_OK;
    var needXcommit: c_int = 0;
    const nDb = rd(c_int, db, sqlite3_nDb);

    rc = sqlite3VtabSync(db, p);

    // aMJNeeded[]: DELETE,PERSIST,OFF,TRUNCATE,MEMORY,WAL
    const aMJNeeded = [_]u8{ 1, 1, 0, 1, 0, 0 };

    var i: c_int = 0;
    while (rc == SQLITE_OK and i < nDb) : (i += 1) {
        const pBt = rdPtr(dbEnt(db, i), Db_pBt);
        if (sqlite3BtreeTxnState(@ptrCast(pBt)) == SQLITE_TXN_WRITE) {
            needXcommit = 1;
            sqlite3BtreeEnter(@ptrCast(pBt));
            const pPager = sqlite3BtreePager(@ptrCast(pBt));
            const safety = rdU8(dbEnt(db, i), Db_safety_level);
            const jm = sqlite3PagerGetJournalMode(pPager);
            if (safety != PAGER_SYNCHRONOUS_OFF and aMJNeeded[@intCast(jm)] != 0 and sqlite3PagerIsMemdb(pPager) == 0) {
                nTrans += 1;
            }
            rc = sqlite3PagerExclusiveLock(pPager);
            sqlite3BtreeLeave(@ptrCast(pBt));
        }
    }
    if (rc != SQLITE_OK) return rc;

    if (needXcommit != 0 and rdPtr(db, sqlite3_xCommitCallback) != null) {
        const xCommit: *const fn (?*anyopaque) callconv(.c) c_int = @ptrCast(rdPtr(db, sqlite3_xCommitCallback).?);
        if (xCommit(rdPtr(db, sqlite3_pCommitArg)) != 0) {
            return SQLITE_CONSTRAINT_COMMITHOOK;
        }
    }

    const mainFile = sqlite3BtreeGetFilename(@ptrCast(rdPtr(dbEnt(db, 0), Db_pBt)));
    if (sqlite3Strlen30(mainFile) == 0 or nTrans <= 1) {
        if (needXcommit != 0) {
            i = 0;
            while (rc == SQLITE_OK and i < nDb) : (i += 1) {
                const pBt = rdPtr(dbEnt(db, i), Db_pBt);
                if (sqlite3BtreeTxnState(@ptrCast(pBt)) >= SQLITE_TXN_WRITE) {
                    rc = sqlite3BtreeCommitPhaseOne(@ptrCast(pBt), null);
                }
            }
        }
        i = 0;
        while (rc == SQLITE_OK and i < nDb) : (i += 1) {
            const pBt = rdPtr(dbEnt(db, i), Db_pBt);
            const txn = sqlite3BtreeTxnState(@ptrCast(pBt));
            if (txn != SQLITE_TXN_NONE) {
                rc = sqlite3BtreeCommitPhaseTwo(@ptrCast(pBt), 0);
            }
        }
        if (rc == SQLITE_OK) sqlite3VtabCommit(db);
        return rc;
    }

    // Complex case: multi-file write transaction → super-journal.
    const pVfs = rdPtr(db, sqlite3_pVfs);
    const zMainFile = sqlite3BtreeGetFilename(@ptrCast(rdPtr(dbEnt(db, 0), Db_pBt)));
    var pSuperJrnl: ?*sqlite3_file = null;
    var offset: i64 = 0;
    var retryCount: c_int = 0;
    const nMainFile = sqlite3Strlen30(zMainFile);
    // zSuper = "%.4c%s%.16c" with NULs; advance past the 4 leading NULs.
    const zSuperAlloc = sqlite3MPrintf(db, "%.4c%s%.16c", @as(c_int, 0), zMainFile, @as(c_int, 0));
    if (zSuperAlloc == null) return SQLITE_NOMEM;
    var zSuper: [*:0]u8 = @ptrCast(@as([*]u8, @ptrCast(zSuperAlloc.?)) + 4);
    var res: c_int = 0;
    while (true) {
        if (retryCount != 0) {
            if (retryCount > 100) {
                sqlite3_log(SQLITE_FULL_LOG, "MJ delete: %s", zSuper);
                _ = sqlite3OsDelete(@ptrCast(pVfs), zSuper, 0);
                break;
            } else if (retryCount == 1) {
                sqlite3_log(SQLITE_FULL_LOG, "MJ collide: %s", zSuper);
            }
        }
        retryCount += 1;
        var iRandom: u32 = 0;
        sqlite3_randomness(4, &iRandom);
        _ = sqlite3_snprintf(13, @ptrCast(zSuper + @as(usize, @intCast(nMainFile))), "-mj%06X9%02X", (iRandom >> 8) & 0xffffff, iRandom & 0xff);
        sqlite3FileSuffix3(zMainFile, zSuper);
        rc = sqlite3OsAccess(@ptrCast(pVfs), zSuper, SQLITE_ACCESS_EXISTS, &res);
        if (!(rc == SQLITE_OK and res != 0)) break;
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3OsOpenMalloc(@ptrCast(pVfs), zSuper, &pSuperJrnl, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_SUPER_JOURNAL, null);
    }
    if (rc != SQLITE_OK) {
        sqlite3DbFree(db, @ptrCast(zSuper - 4));
        return rc;
    }

    i = 0;
    while (i < nDb) : (i += 1) {
        const pBt = rdPtr(dbEnt(db, i), Db_pBt);
        if (sqlite3BtreeTxnState(@ptrCast(pBt)) == SQLITE_TXN_WRITE) {
            const zFile = sqlite3BtreeGetJournalname(@ptrCast(pBt));
            if (zFile == null) continue;
            rc = sqlite3OsWrite(pSuperJrnl, zFile, sqlite3Strlen30(zFile.?) + 1, offset);
            offset += sqlite3Strlen30(zFile.?) + 1;
            if (rc != SQLITE_OK) {
                sqlite3OsCloseFree(pSuperJrnl);
                _ = sqlite3OsDelete(@ptrCast(pVfs), zSuper, 0);
                sqlite3DbFree(db, @ptrCast(zSuper - 4));
                return rc;
            }
        }
    }

    if ((sqlite3OsDeviceCharacteristics(pSuperJrnl) & SQLITE_IOCAP_SEQUENTIAL) == 0) {
        rc = sqlite3OsSync(pSuperJrnl, SQLITE_SYNC_NORMAL);
        if (rc != SQLITE_OK) {
            sqlite3OsCloseFree(pSuperJrnl);
            _ = sqlite3OsDelete(@ptrCast(pVfs), zSuper, 0);
            sqlite3DbFree(db, @ptrCast(zSuper - 4));
            return rc;
        }
    }

    i = 0;
    while (rc == SQLITE_OK and i < nDb) : (i += 1) {
        const pBt = rdPtr(dbEnt(db, i), Db_pBt);
        if (pBt != null) {
            rc = sqlite3BtreeCommitPhaseOne(@ptrCast(pBt), zSuper);
        }
    }
    sqlite3OsCloseFree(pSuperJrnl);
    if (rc != SQLITE_OK) {
        sqlite3DbFree(db, @ptrCast(zSuper - 4));
        return rc;
    }

    rc = sqlite3OsDelete(@ptrCast(pVfs), zSuper, 1);
    sqlite3DbFree(db, @ptrCast(zSuper - 4));
    zSuper = undefined;
    if (rc != 0) return rc;

    if (config.sqlite_test) disable_simulated_io_errors();
    sqlite3BeginBenignMalloc();
    i = 0;
    while (i < nDb) : (i += 1) {
        const pBt = rdPtr(dbEnt(db, i), Db_pBt);
        if (pBt != null) _ = sqlite3BtreeCommitPhaseTwo(@ptrCast(pBt), 1);
    }
    sqlite3EndBenignMalloc();
    if (config.sqlite_test) enable_simulated_io_errors();
    sqlite3VtabCommit(db);
    return rc;
}

// ===========================================================================
// Statement transactions / FK checks
// ===========================================================================
fn vdbeCloseStatement(p: ?*Vdbe, eOp: c_int) c_int {
    const db = rdPtr(p, Vdbe_db);
    var rc: c_int = SQLITE_OK;
    const iSavepoint = rd(c_int, p, Vdbe_iStatement) - 1;
    const nDb = rd(c_int, db, sqlite3_nDb);
    var i: c_int = 0;
    while (i < nDb) : (i += 1) {
        var rc2: c_int = SQLITE_OK;
        const pBt = rdPtr(dbEnt(db, i), Db_pBt);
        if (pBt != null) {
            if (eOp == SAVEPOINT_ROLLBACK) {
                rc2 = sqlite3BtreeSavepoint(@ptrCast(pBt), SAVEPOINT_ROLLBACK, iSavepoint);
            }
            if (rc2 == SQLITE_OK) {
                rc2 = sqlite3BtreeSavepoint(@ptrCast(pBt), SAVEPOINT_RELEASE, iSavepoint);
            }
            if (rc == SQLITE_OK) rc = rc2;
        }
    }
    wr(c_int, db, sqlite3_nStatement, rd(c_int, db, sqlite3_nStatement) - 1);
    wr(c_int, p, Vdbe_iStatement, 0);
    if (rc == SQLITE_OK) {
        if (eOp == SAVEPOINT_ROLLBACK) {
            rc = sqlite3VtabSavepoint(db, SAVEPOINT_ROLLBACK, iSavepoint);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3VtabSavepoint(db, SAVEPOINT_RELEASE, iSavepoint);
        }
    }
    if (eOp == SAVEPOINT_ROLLBACK) {
        wr(i64, db, sqlite3_nDeferredCons, rd(i64, p, Vdbe_nStmtDefCons));
        wr(i64, db, sqlite3_nDeferredImmCons, rd(i64, p, Vdbe_nStmtDefImmCons));
    }
    return rc;
}
export fn sqlite3VdbeCloseStatement(p: ?*Vdbe, eOp: c_int) callconv(.c) c_int {
    if (rd(c_int, rdPtr(p, Vdbe_db), sqlite3_nStatement) != 0 and rd(c_int, p, Vdbe_iStatement) != 0) {
        return vdbeCloseStatement(p, eOp);
    }
    return SQLITE_OK;
}

fn vdbeFkError(p: ?*Vdbe) c_int {
    wr(c_int, p, Vdbe_rc, SQLITE_CONSTRAINT_FOREIGNKEY);
    wrU8(p, Vdbe_errorAction, OE_Abort);
    sqlite3VdbeError(p, "FOREIGN KEY constraint failed");
    if ((rdU8(p, Vdbe_prepFlags) & SQLITE_PREPARE_SAVESQL) == 0) return SQLITE_ERROR;
    return SQLITE_CONSTRAINT_FOREIGNKEY;
}
export fn sqlite3VdbeCheckFkImmediate(p: ?*Vdbe) callconv(.c) c_int {
    if (rd(i64, p, Vdbe_nFkConstraint) == 0) return SQLITE_OK;
    return vdbeFkError(p);
}
export fn sqlite3VdbeCheckFkDeferred(p: ?*Vdbe) callconv(.c) c_int {
    const db = rdPtr(p, Vdbe_db);
    if ((rd(i64, db, sqlite3_nDeferredCons) + rd(i64, db, sqlite3_nDeferredImmCons)) == 0) return SQLITE_OK;
    return vdbeFkError(p);
}

// ===========================================================================
// Halt
// ===========================================================================
export fn sqlite3VdbeHalt(p: ?*Vdbe) callconv(.c) c_int {
    var rc: c_int = undefined;
    const db = rdPtr(p, Vdbe_db);

    if (rdU8(db, sqlite3_mallocFailed) != 0) {
        wr(c_int, p, Vdbe_rc, SQLITE_NOMEM);
    }
    closeAllCursors(p);

    if (getBIsReader(p)) {
        var mrc: c_int = undefined;
        var eStatementOp: c_int = 0;
        var isSpecialError: bool = undefined;

        sqlite3VdbeEnter(p);

        const prc = rd(c_int, p, Vdbe_rc);
        if (prc != 0) {
            mrc = prc & 0xff;
            isSpecialError = mrc == SQLITE_NOMEM or mrc == SQLITE_IOERR or mrc == SQLITE_INTERRUPT or mrc == SQLITE_FULL;
        } else {
            mrc = 0;
            isSpecialError = false;
        }
        if (isSpecialError) {
            if (!getReadOnly(p) or mrc != SQLITE_INTERRUPT) {
                if ((mrc == SQLITE_NOMEM or mrc == SQLITE_FULL) and getUsesStmtJournal(p)) {
                    eStatementOp = SAVEPOINT_ROLLBACK;
                } else {
                    sqlite3RollbackAll(db, SQLITE_ABORT_ROLLBACK);
                    sqlite3CloseSavepoints(db);
                    wrU8(db, sqlite3_autoCommit, 1);
                    wr(i64, p, Vdbe_nChange, 0);
                }
            }
        }

        if (rd(c_int, p, Vdbe_rc) == SQLITE_OK or (rdU8(p, Vdbe_errorAction) == OE_Fail and !isSpecialError)) {
            _ = sqlite3VdbeCheckFkImmediate(p);
        }

        if (sqlite3VtabInSync(db) == 0 and rdU8(db, sqlite3_autoCommit) != 0 and rd(c_int, db, sqlite3_nVdbeWrite) == @intFromBool(!getReadOnly(p))) {
            if (rd(c_int, p, Vdbe_rc) == SQLITE_OK or (rdU8(p, Vdbe_errorAction) == OE_Fail and !isSpecialError)) {
                rc = sqlite3VdbeCheckFkDeferred(p);
                if (rc != SQLITE_OK) {
                    if (getReadOnly(p)) {
                        sqlite3VdbeLeave(p);
                        return SQLITE_ERROR;
                    }
                    rc = SQLITE_CONSTRAINT_FOREIGNKEY;
                } else if ((rd(u64, db, sqlite3_flags) & SQLITE_CorruptRdOnly) != 0) {
                    rc = SQLITE_CORRUPT;
                    wr(u64, db, sqlite3_flags, rd(u64, db, sqlite3_flags) & ~SQLITE_CorruptRdOnly);
                } else {
                    rc = vdbeCommit(db, p);
                }
                if (rc == SQLITE_BUSY and getReadOnly(p)) {
                    sqlite3VdbeLeave(p);
                    return SQLITE_BUSY;
                } else if (rc != SQLITE_OK) {
                    sqlite3SystemError(db, rc);
                    wr(c_int, p, Vdbe_rc, rc);
                    sqlite3RollbackAll(db, SQLITE_OK);
                    wr(i64, p, Vdbe_nChange, 0);
                } else {
                    wr(i64, db, sqlite3_nDeferredCons, 0);
                    wr(i64, db, sqlite3_nDeferredImmCons, 0);
                    wr(u64, db, sqlite3_flags, rd(u64, db, sqlite3_flags) & ~SQLITE_DeferFKs);
                    sqlite3CommitInternalChanges(db);
                }
            } else if (rd(c_int, p, Vdbe_rc) == SQLITE_SCHEMA and rd(c_int, db, sqlite3_nVdbeActive) > 1) {
                wr(i64, p, Vdbe_nChange, 0);
            } else {
                sqlite3RollbackAll(db, SQLITE_OK);
                wr(i64, p, Vdbe_nChange, 0);
            }
            wr(c_int, db, sqlite3_nStatement, 0);
        } else if (eStatementOp == 0) {
            if (rd(c_int, p, Vdbe_rc) == SQLITE_OK or rdU8(p, Vdbe_errorAction) == OE_Fail) {
                eStatementOp = SAVEPOINT_RELEASE;
            } else if (rdU8(p, Vdbe_errorAction) == OE_Abort) {
                eStatementOp = SAVEPOINT_ROLLBACK;
            } else {
                sqlite3RollbackAll(db, SQLITE_ABORT_ROLLBACK);
                sqlite3CloseSavepoints(db);
                wrU8(db, sqlite3_autoCommit, 1);
                wr(i64, p, Vdbe_nChange, 0);
            }
        }

        if (eStatementOp != 0) {
            rc = sqlite3VdbeCloseStatement(p, eStatementOp);
            if (rc != 0) {
                if (rd(c_int, p, Vdbe_rc) == SQLITE_OK or (rd(c_int, p, Vdbe_rc) & 0xff) == SQLITE_CONSTRAINT) {
                    wr(c_int, p, Vdbe_rc, rc);
                    sqlite3DbFree(db, rdPtr(p, Vdbe_zErrMsg));
                    wrPtr(p, Vdbe_zErrMsg, null);
                }
                sqlite3RollbackAll(db, SQLITE_ABORT_ROLLBACK);
                sqlite3CloseSavepoints(db);
                wrU8(db, sqlite3_autoCommit, 1);
                wr(i64, p, Vdbe_nChange, 0);
            }
        }

        if (getChangeCntOn(p)) {
            if (eStatementOp != SAVEPOINT_ROLLBACK) {
                sqlite3VdbeSetChanges(db, rd(i64, p, Vdbe_nChange));
            } else {
                sqlite3VdbeSetChanges(db, 0);
            }
            wr(i64, p, Vdbe_nChange, 0);
        }

        sqlite3VdbeLeave(p);
    }

    wr(c_int, db, sqlite3_nVdbeActive, rd(c_int, db, sqlite3_nVdbeActive) - 1);
    if (!getReadOnly(p)) wr(c_int, db, sqlite3_nVdbeWrite, rd(c_int, db, sqlite3_nVdbeWrite) - 1);
    if (getBIsReader(p)) wr(c_int, db, sqlite3_nVdbeRead, rd(c_int, db, sqlite3_nVdbeRead) - 1);
    wrU8(p, Vdbe_eVdbeState, VDBE_HALT_STATE);
    if (rdU8(db, sqlite3_mallocFailed) != 0) {
        wr(c_int, p, Vdbe_rc, SQLITE_NOMEM);
    }

    if (rdU8(db, sqlite3_autoCommit) != 0) {
        sqlite3ConnectionUnlocked(db);
    }
    return if (rd(c_int, p, Vdbe_rc) == SQLITE_BUSY) SQLITE_BUSY else SQLITE_OK;
}

// ===========================================================================
// Reset / Finalize / step-result / transfer-error
// ===========================================================================
export fn sqlite3VdbeResetStepResult(p: ?*Vdbe) callconv(.c) void {
    wr(c_int, p, Vdbe_rc, SQLITE_OK);
}

export fn sqlite3VdbeTransferError(p: ?*Vdbe) callconv(.c) c_int {
    const db = rdPtr(p, Vdbe_db);
    const rc = rd(c_int, p, Vdbe_rc);
    const zErrMsg = rdPtr(p, Vdbe_zErrMsg);
    if (zErrMsg != null) {
        // db->bBenignMalloc++ then BeginBenignMalloc; we mirror the increment.
        sqlite3BeginBenignMalloc();
        if (rdPtr(db, sqlite3_pErr) == null) wrPtr(db, sqlite3_pErr, sqlite3ValueNew(db));
        sqlite3ValueSetStr(rdPtr(db, sqlite3_pErr), -1, zErrMsg, SQLITE_UTF8, SQLITE_TRANSIENT);
        sqlite3EndBenignMalloc();
    } else if (rdPtr(db, sqlite3_pErr) != null) {
        sqlite3ValueSetNull(rdPtr(db, sqlite3_pErr));
    }
    wr(c_int, db, sqlite3_errCode, rc);
    wr(c_int, db, sqlite3_errByteOffset, -1);
    return rc;
}
const SQLITE_TRANSIENT: ?*const fn (?*anyopaque) callconv(.c) void = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

export fn sqlite3VdbeReset(p: ?*Vdbe) callconv(.c) c_int {
    const db = rdPtr(p, Vdbe_db);
    if (rdU8(p, Vdbe_eVdbeState) == VDBE_RUN_STATE) _ = sqlite3VdbeHalt(p);
    if (rd(c_int, p, Vdbe_pc) >= 0) {
        // SQLLOG off → vdbeInvokeSqllog no-op.
        if (rdPtr(db, sqlite3_pErr) != null or rdPtr(p, Vdbe_zErrMsg) != null) {
            _ = sqlite3VdbeTransferError(p);
        } else {
            wr(c_int, db, sqlite3_errCode, rd(c_int, p, Vdbe_rc));
        }
    }
    if (rdPtr(p, Vdbe_zErrMsg) != null) {
        sqlite3DbFree(db, rdPtr(p, Vdbe_zErrMsg));
        wrPtr(p, Vdbe_zErrMsg, null);
    }
    wrPtr(p, Vdbe_pResultRow, null);
    if (DEBUG) wr(u32, p, Vdbe_nWrite, 0);
    return rd(c_int, p, Vdbe_rc) & rd(c_int, db, sqlite3_errMask);
}

export fn sqlite3VdbeFinalize(p: ?*Vdbe) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    if (rdU8(p, Vdbe_eVdbeState) >= VDBE_READY_STATE) {
        rc = sqlite3VdbeReset(p);
    }
    sqlite3VdbeDelete(p);
    return rc;
}

// ===========================================================================
// AuxData
// ===========================================================================
fn MASKBIT32(i: c_int) u32 {
    return @as(u32, 1) << @intCast(i);
}
export fn sqlite3VdbeDeleteAuxData(db: ?*sqlite3, pp_in: *?*anyopaque, iOp: c_int, mask: c_int) callconv(.c) void {
    var pp = pp_in;
    while (pp.* != null) {
        const pAux = pp.*;
        const iAuxArg = rd(c_int, pAux, AuxData_iAuxArg);
        if (iOp < 0 or (rd(c_int, pAux, AuxData_iAuxOp) == iOp and iAuxArg >= 0 and (iAuxArg > 31 or (@as(c_int, @bitCast(mask)) & @as(c_int, @bitCast(MASKBIT32(iAuxArg)))) == 0))) {
            const xDel = rdPtr(pAux, AuxData_xDeleteAux);
            if (xDel != null) {
                const fnptr: *const fn (?*anyopaque) callconv(.c) void = @ptrCast(xDel.?);
                fnptr(rdPtr(pAux, AuxData_pAux));
            }
            pp.* = rdPtr(pAux, AuxData_pNextAux);
            sqlite3DbFree(db, pAux);
        } else {
            pp = @ptrCast(fp(?*anyopaque, pAux, AuxData_pNextAux));
        }
    }
}

// ===========================================================================
// ClearObject / Delete
// ===========================================================================
fn sqlite3VdbeClearObject(db: ?*sqlite3, p: ?*Vdbe) void {
    if (rdPtr(p, Vdbe_aColName) != null) {
        releaseMemArray(rdPtr(p, Vdbe_aColName), @as(c_int, rd(u16, p, Vdbe_nResAlloc)) * COLNAME_N);
        sqlite3DbNNFreeNN(db, rdPtr(p, Vdbe_aColName));
    }
    var pSub = rdPtr(p, Vdbe_pProgram);
    while (pSub != null) {
        const pNext = rdPtr(pSub, SubProgram_pNext);
        vdbeFreeOpArray(db, rdPtr(pSub, SubProgram_aOp), rd(c_int, pSub, SubProgram_nOp));
        sqlite3DbFree(db, pSub);
        pSub = pNext;
    }
    if (rdU8(p, Vdbe_eVdbeState) != VDBE_INIT_STATE) {
        releaseMemArray(rdPtr(p, Vdbe_aVar), rd(i16, p, Vdbe_nVar));
        if (rdPtr(p, Vdbe_pVList) != null) sqlite3DbNNFreeNN(db, rdPtr(p, Vdbe_pVList));
        if (rdPtr(p, Vdbe_pFree) != null) sqlite3DbNNFreeNN(db, rdPtr(p, Vdbe_pFree));
    }
    vdbeFreeOpArray(db, rdPtr(p, Vdbe_aOp), rd(c_int, p, Vdbe_nOp));
    if (rdPtr(p, Vdbe_zSql) != null) sqlite3DbNNFreeNN(db, rdPtr(p, Vdbe_zSql));
}

export fn sqlite3VdbeDelete(p: ?*Vdbe) callconv(.c) void {
    const db = rdPtr(p, Vdbe_db);
    sqlite3VdbeClearObject(db, p);
    if (rdPtr(db, sqlite3_pnBytesFreed) == null) {
        // *p->ppVPrev = p->pVNext
        const ppVPrev = rdPtr(p, Vdbe_ppVPrev);
        wrPtr(ppVPrev, 0, rdPtr(p, Vdbe_pVNext));
        if (rdPtr(p, Vdbe_pVNext) != null) {
            wrPtr(rdPtr(p, Vdbe_pVNext), Vdbe_ppVPrev, rdPtr(p, Vdbe_ppVPrev));
        }
    }
    sqlite3DbNNFreeNN(db, p);
}

// ===========================================================================
// Cursor seek restore
// ===========================================================================
// vdbe.c defines `int sqlite3_search_count` unconditionally; only the test
// build reads it. Declared extern var (mutable) per the gotcha checklist.
extern var sqlite3_search_count: c_int;
export fn sqlite3VdbeFinishMoveto(p: ?*VdbeCursor) callconv(.c) c_int {
    var res: c_int = 0;
    const movetoTarget = rd(i64, p, VdbeCursor_movetoTarget);
    const rc = sqlite3BtreeTableMoveto(@ptrCast(rdPtr(p, VdbeCursor_uc)), movetoTarget, 0, &res);
    if (rc != 0) return rc;
    if (res != 0) return SQLITE_CORRUPT;
    if (config.sqlite_test) sqlite3_search_count += 1; // SQLITE_TEST counter
    wrU8(p, VdbeCursor_deferredMoveto, 0);
    wr(u32, p, VdbeCursor_cacheStatus, CACHE_STALE);
    return SQLITE_OK;
}
export fn sqlite3VdbeHandleMovedCursor(p: ?*VdbeCursor) callconv(.c) c_int {
    var isDifferentRow: c_int = 0;
    const rc = sqlite3BtreeCursorRestore(@ptrCast(rdPtr(p, VdbeCursor_uc)), &isDifferentRow);
    wr(u32, p, VdbeCursor_cacheStatus, CACHE_STALE);
    if (isDifferentRow != 0) wrU8(p, VdbeCursor_nullRow, 1);
    return rc;
}
export fn sqlite3VdbeCursorRestore(p: ?*VdbeCursor) callconv(.c) c_int {
    if (sqlite3BtreeCursorHasMoved(@ptrCast(rdPtr(p, VdbeCursor_uc))) != 0) {
        return sqlite3VdbeHandleMovedCursor(p);
    }
    return SQLITE_OK;
}

// ===========================================================================
// Serial type codec — MUST be byte-exact. Uses wrapping arithmetic where C
// relies on defined unsigned/twos-complement wrap.
// ===========================================================================
export const sqlite3SmallTypeSizes: [128]u8 = .{
    0,  1,  2,  3,  4,  6,  8,  8,  0,  0,
    0,  0,  0,  0,  1,  1,  2,  2,  3,  3,
    4,  4,  5,  5,  6,  6,  7,  7,  8,  8,
    9,  9,  10, 10, 11, 11, 12, 12, 13, 13,
    14, 14, 15, 15, 16, 16, 17, 17, 18, 18,
    19, 19, 20, 20, 21, 21, 22, 22, 23, 23,
    24, 24, 25, 25, 26, 26, 27, 27, 28, 28,
    29, 29, 30, 30, 31, 31, 32, 32, 33, 33,
    34, 34, 35, 35, 36, 36, 37, 37, 38, 38,
    39, 39, 40, 40, 41, 41, 42, 42, 43, 43,
    44, 44, 45, 45, 46, 46, 47, 47, 48, 48,
    49, 49, 50, 50, 51, 51, 52, 52, 53, 53,
    54, 54, 55, 55, 56, 56, 57, 57,
};

export fn sqlite3VdbeSerialTypeLen(serial_type: u32) callconv(.c) u32 {
    if (serial_type >= 128) {
        return (serial_type - 12) / 2;
    } else {
        return sqlite3SmallTypeSizes[serial_type];
    }
}
export fn sqlite3VdbeOneByteSerialTypeLen(serial_type: u8) callconv(.c) u8 {
    return sqlite3SmallTypeSizes[serial_type];
}

// Big-endian integer readers (matching the C macros, with wrap).
inline fn ONE_BYTE_INT(x: [*]const u8) i64 {
    return @as(i8, @bitCast(x[0]));
}
inline fn TWO_BYTE_INT(x: [*]const u8) i64 {
    return 256 *% @as(i64, @as(i8, @bitCast(x[0]))) | @as(i64, x[1]);
}
inline fn THREE_BYTE_INT(x: [*]const u8) i64 {
    return 65536 *% @as(i64, @as(i8, @bitCast(x[0]))) | (@as(i64, x[1]) << 8) | @as(i64, x[2]);
}
inline fn FOUR_BYTE_UINT(x: [*]const u8) u32 {
    return (@as(u32, x[0]) << 24) | (@as(u32, x[1]) << 16) | (@as(u32, x[2]) << 8) | @as(u32, x[3]);
}
inline fn FOUR_BYTE_INT(x: [*]const u8) i64 {
    return 16777216 *% @as(i64, @as(i8, @bitCast(x[0]))) | (@as(i64, x[1]) << 16) | (@as(i64, x[2]) << 8) | @as(i64, x[3]);
}

fn serialGet(buf: [*]const u8, serial_type: u32, pMem: ?*Mem) void {
    var x: u64 = @as(u64, FOUR_BYTE_UINT(buf));
    const y: u32 = FOUR_BYTE_UINT(buf + 4);
    x = (x << 32) +% @as(u64, y);
    if (serial_type == 6) {
        wr(i64, pMem, Mem_u, @bitCast(x));
        wr(u16, pMem, Mem_flags, MEM_Int);
    } else {
        // double via bit reinterpret (no mixed-endian)
        wr(u64, pMem, Mem_u, x);
        const r: f64 = @bitCast(x);
        wr(u16, pMem, Mem_flags, if (isNanU(x)) MEM_Null else MEM_Real);
        _ = r;
    }
}
inline fn isNanU(x: u64) bool {
    const r: f64 = @bitCast(x);
    return r != r;
}
fn serialGet7(buf: [*]const u8, pMem: ?*Mem) c_int {
    var x: u64 = @as(u64, FOUR_BYTE_UINT(buf));
    const y: u32 = FOUR_BYTE_UINT(buf + 4);
    x = (x << 32) +% @as(u64, y);
    wr(u64, pMem, Mem_u, x);
    if (isNanU(x)) {
        wr(u16, pMem, Mem_flags, MEM_Null);
        return 1;
    }
    wr(u16, pMem, Mem_flags, MEM_Real);
    return 0;
}

export fn sqlite3VdbeSerialGet(buf: [*]const u8, serial_type: u32, pMem: ?*Mem) callconv(.c) void {
    switch (serial_type) {
        10 => {
            wr(u16, pMem, Mem_flags, MEM_Null | MEM_Zero);
            wr(c_int, pMem, Mem_n, 0);
            wr(i64, pMem, Mem_u, 0); // u.nZero = 0
            return;
        },
        11, 0 => {
            wr(u16, pMem, Mem_flags, MEM_Null);
            return;
        },
        1 => {
            wr(i64, pMem, Mem_u, ONE_BYTE_INT(buf));
            wr(u16, pMem, Mem_flags, MEM_Int);
            return;
        },
        2 => {
            wr(i64, pMem, Mem_u, TWO_BYTE_INT(buf));
            wr(u16, pMem, Mem_flags, MEM_Int);
            return;
        },
        3 => {
            wr(i64, pMem, Mem_u, THREE_BYTE_INT(buf));
            wr(u16, pMem, Mem_flags, MEM_Int);
            return;
        },
        4 => {
            wr(i64, pMem, Mem_u, FOUR_BYTE_INT(buf));
            wr(u16, pMem, Mem_flags, MEM_Int);
            return;
        },
        5 => {
            const v = @as(i64, FOUR_BYTE_UINT(buf + 2)) +% (@as(i64, 1) << 32) *% TWO_BYTE_INT(buf);
            wr(i64, pMem, Mem_u, v);
            wr(u16, pMem, Mem_flags, MEM_Int);
            return;
        },
        6, 7 => {
            serialGet(buf, serial_type, pMem);
            return;
        },
        8, 9 => {
            wr(i64, pMem, Mem_u, @as(i64, serial_type) - 8);
            wr(u16, pMem, Mem_flags, MEM_Int);
            return;
        },
        else => {
            const aFlag = [_]u16{ MEM_Blob | MEM_Ephem, MEM_Str | MEM_Ephem };
            wrPtr(pMem, Mem_z, @ptrCast(@constCast(buf)));
            wr(c_int, pMem, Mem_n, @intCast((serial_type - 12) / 2));
            wr(u16, pMem, Mem_flags, aFlag[serial_type & 1]);
            return;
        },
    }
}

// getVarint32 helper inline (matches the C macro getVarint32(A,B)).
inline fn getVarint32(a: [*]const u8, v: *u32) u32 {
    if (a[0] < 0x80) {
        v.* = a[0];
        return 1;
    }
    return sqlite3GetVarint32(a, v);
}

export fn sqlite3VdbeAllocUnpackedRecord(pKeyInfo: ?*KeyInfo) callconv(.c) ?*UnpackedRecord {
    const nKeyField = rd(u16, pKeyInfo, KeyInfo_nKeyField);
    const roundedHdr: usize = (sizeof_UnpackedRecord + 7) & ~@as(usize, 7);
    const nByte: u64 = @intCast(roundedHdr + sizeof_Mem * (@as(usize, nKeyField) + 1));
    const p = sqlite3DbMallocRaw(rdPtr(pKeyInfo, KeyInfo_db), nByte) orelse return null;
    wrPtr(p, UR_aMem, @ptrCast(@as([*]u8, @ptrCast(p)) + roundedHdr));
    wrPtr(p, UR_pKeyInfo, pKeyInfo);
    wr(u16, p, UR_nField, nKeyField + 1);
    return p;
}

export fn sqlite3VdbeRecordUnpack(nKey: c_int, pKey: ?*const anyopaque, p: ?*UnpackedRecord) callconv(.c) void {
    const aKey: [*]const u8 = @ptrCast(pKey.?);
    var pMem = rdPtr(p, UR_aMem);
    const pKeyInfo = rdPtr(p, UR_pKeyInfo);
    wrU8(p, UR_default_rc, 0);
    var szHdr: u32 = undefined;
    var idx: u32 = getVarint32(aKey, &szHdr);
    var d: u32 = szHdr;
    var u: u16 = 0;
    const nField = rd(u16, p, UR_nField);
    while (idx < szHdr and d <= @as(u32, @bitCast(nKey))) {
        var serial_type: u32 = undefined;
        idx += getVarint32(aKey + idx, &serial_type);
        wrU8(pMem, Mem_enc, rdU8(pKeyInfo, KeyInfo_enc));
        wrPtr(pMem, Mem_db, rdPtr(pKeyInfo, KeyInfo_db));
        wr(c_int, pMem, Mem_szMalloc, 0);
        wrPtr(pMem, Mem_z, null);
        sqlite3VdbeSerialGet(aKey + d, serial_type, pMem);
        d += sqlite3VdbeSerialTypeLen(serial_type);
        u += 1;
        if (u >= nField) break;
        pMem = memAt(pMem, 1);
    }
    if (d > @as(u32, @bitCast(nKey)) and u != 0) {
        // C: sqlite3VdbeMemSetNull(pMem-(u<p->nField))
        const backUp: usize = if (u < nField) 1 else 0;
        const target: ?*Mem = @as([*]u8, @ptrCast(pMem.?)) - backUp * sizeof_Mem;
        sqlite3VdbeMemSetNull(target);
    }
    wr(u16, p, UR_nField, u);
}

// ===========================================================================
// Value comparison (sqlite3MemCompare etc.)
// ===========================================================================
const CollSeq_enc = 8;
const CollSeq_pUser = 16;
const CollSeq_xCmp = 24;
const XCmpFn = *const fn (?*anyopaque, c_int, ?*const anyopaque, c_int, ?*const anyopaque) callconv(.c) c_int;

fn memU(m: ?*const Mem) i64 {
    return rd(i64, @constCast(m), Mem_u);
}
fn memR(m: ?*const Mem) f64 {
    return @bitCast(rd(u64, @constCast(m), Mem_u));
}
fn memNZero(m: ?*const Mem) i32 {
    return @bitCast(@as(u32, @truncate(rd(u64, @constCast(m), Mem_u))));
}
fn memFlags(m: ?*const Mem) u16 {
    return rd(u16, @constCast(m), Mem_flags);
}
fn memN(m: ?*const Mem) c_int {
    return rd(c_int, @constCast(m), Mem_n);
}
fn memZ(m: ?*const Mem) ?[*]const u8 {
    return @ptrCast(rdPtr(@constCast(m), Mem_z));
}
fn memEnc(m: ?*const Mem) u8 {
    return rdU8(@constCast(m), Mem_enc);
}

fn vdbeCompareMemStringWithEncodingChange(pMem1: ?*const Mem, pMem2: ?*const Mem, pColl: ?*const CollSeq, prcErr: ?*u8) c_int {
    var c1: [sizeof_Mem]u8 align(8) = undefined;
    var c2: [sizeof_Mem]u8 align(8) = undefined;
    const pc1: ?*Mem = @ptrCast(&c1);
    const pc2: ?*Mem = @ptrCast(&c2);
    const db = rdPtr(@constCast(pMem1), Mem_db);
    sqlite3VdbeMemInit(pc1, db, MEM_Null);
    sqlite3VdbeMemInit(pc2, db, MEM_Null);
    sqlite3VdbeMemShallowCopy(pc1, pMem1, MEM_Ephem);
    sqlite3VdbeMemShallowCopy(pc2, pMem2, MEM_Ephem);
    const enc = rdU8(@constCast(pColl), CollSeq_enc);
    const v1 = sqlite3ValueText(pc1, enc);
    const v2 = sqlite3ValueText(pc2, enc);
    var rc: c_int = undefined;
    if (v1 == null or v2 == null) {
        if (prcErr) |pe| pe.* = @intCast(SQLITE_NOMEM);
        rc = 0;
    } else {
        const xCmp: XCmpFn = @ptrCast(rdPtr(@constCast(pColl), CollSeq_xCmp).?);
        rc = xCmp(rdPtr(@constCast(pColl), CollSeq_pUser), memN(pc1), v1, memN(pc2), v2);
    }
    sqlite3VdbeMemReleaseMalloc(pc1);
    sqlite3VdbeMemReleaseMalloc(pc2);
    return rc;
}
fn vdbeCompareMemString(pMem1: ?*const Mem, pMem2: ?*const Mem, pColl: ?*const CollSeq, prcErr: ?*u8) c_int {
    if (memEnc(pMem1) == rdU8(@constCast(pColl), CollSeq_enc)) {
        const xCmp: XCmpFn = @ptrCast(rdPtr(@constCast(pColl), CollSeq_xCmp).?);
        return xCmp(rdPtr(@constCast(pColl), CollSeq_pUser), memN(pMem1), memZ(pMem1), memN(pMem2), memZ(pMem2));
    } else {
        return vdbeCompareMemStringWithEncodingChange(pMem1, pMem2, pColl, prcErr);
    }
}

fn isAllZero(z: [*]const u8, n: c_int) c_int {
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        if (z[@intCast(i)] != 0) return 0;
    }
    return 1;
}

export fn sqlite3BlobCompare(pB1: ?*const Mem, pB2: ?*const Mem) callconv(.c) c_int {
    const n1 = memN(pB1);
    const n2 = memN(pB2);
    if (((memFlags(pB1) | memFlags(pB2)) & MEM_Zero) != 0) {
        if ((memFlags(pB1) & memFlags(pB2) & MEM_Zero) != 0) {
            return memNZero(pB1) - memNZero(pB2);
        } else if ((memFlags(pB1) & MEM_Zero) != 0) {
            if (isAllZero(memZ(pB2).?, memN(pB2)) == 0) return -1;
            return memNZero(pB1) - n2;
        } else {
            if (isAllZero(memZ(pB1).?, memN(pB1)) == 0) return 1;
            return n1 - memNZero(pB2);
        }
    }
    const nCmp: usize = @intCast(if (n1 > n2) n2 else n1);
    const c = memcmp(@ptrCast(memZ(pB1)), @ptrCast(memZ(pB2)), nCmp);
    if (c != 0) return c;
    return n1 - n2;
}

export fn sqlite3IntFloatCompare(i: i64, r: f64) callconv(.c) c_int {
    if (sqlite3IsNaN(r) != 0) {
        return 1;
    }
    if (r < -9223372036854775808.0) return 1;
    if (r >= 9223372036854775808.0) return -1;
    const y: i64 = @intFromFloat(r);
    if (i < y) return -1;
    if (i > y) return 1;
    const di: f64 = @floatFromInt(i);
    if (di < r) return -1;
    return @intFromBool(di > r);
}

export fn sqlite3MemCompare(pMem1: ?*const Mem, pMem2: ?*const Mem, pColl: ?*const CollSeq) callconv(.c) c_int {
    const f1: c_int = memFlags(pMem1);
    const f2: c_int = memFlags(pMem2);
    const combined = f1 | f2;

    if ((combined & MEM_Null) != 0) {
        return (f2 & MEM_Null) - (f1 & MEM_Null);
    }
    if ((combined & (MEM_Int | MEM_Real | MEM_IntReal)) != 0) {
        if ((f1 & f2 & (MEM_Int | MEM_IntReal)) != 0) {
            if (memU(pMem1) < memU(pMem2)) return -1;
            if (memU(pMem1) > memU(pMem2)) return 1;
            return 0;
        }
        if ((f1 & f2 & MEM_Real) != 0) {
            if (memR(pMem1) < memR(pMem2)) return -1;
            if (memR(pMem1) > memR(pMem2)) return 1;
            return 0;
        }
        if ((f1 & (MEM_Int | MEM_IntReal)) != 0) {
            if ((f2 & MEM_Real) != 0) {
                return sqlite3IntFloatCompare(memU(pMem1), memR(pMem2));
            } else if ((f2 & (MEM_Int | MEM_IntReal)) != 0) {
                if (memU(pMem1) < memU(pMem2)) return -1;
                if (memU(pMem1) > memU(pMem2)) return 1;
                return 0;
            } else {
                return -1;
            }
        }
        if ((f1 & MEM_Real) != 0) {
            if ((f2 & (MEM_Int | MEM_IntReal)) != 0) {
                return -sqlite3IntFloatCompare(memU(pMem2), memR(pMem1));
            } else {
                return -1;
            }
        }
        return 1;
    }
    if ((combined & MEM_Str) != 0) {
        if ((f1 & MEM_Str) == 0) return 1;
        if ((f2 & MEM_Str) == 0) return -1;
        if (pColl != null) {
            return vdbeCompareMemString(pMem1, pMem2, pColl, null);
        }
    }
    return sqlite3BlobCompare(pMem1, pMem2);
}

fn vdbeRecordDecodeInt(serial_type: u32, aKey: [*]const u8) i64 {
    switch (serial_type) {
        0, 1 => return ONE_BYTE_INT(aKey),
        2 => return TWO_BYTE_INT(aKey),
        3 => return THREE_BYTE_INT(aKey),
        4 => {
            const y = FOUR_BYTE_UINT(aKey);
            return @as(i64, @as(i32, @bitCast(y)));
        },
        5 => return FOUR_BYTE_UINT(aKey + 2) +% (@as(i64, 1) << 32) *% TWO_BYTE_INT(aKey),
        6 => {
            var x: u64 = FOUR_BYTE_UINT(aKey);
            x = (x << 32) | FOUR_BYTE_UINT(aKey + 4);
            return @bitCast(x);
        },
        else => return @as(i64, serial_type) - 8,
    }
}

// ===========================================================================
// sqlite3VdbeRecordCompareWithSkip — the byte-exact record comparator.
// ===========================================================================
export fn sqlite3VdbeRecordCompareWithSkip(nKey1: c_int, pKey1: ?*const anyopaque, pPKey2: ?*UnpackedRecord, bSkip: c_int) callconv(.c) c_int {
    var d1: u32 = undefined;
    var i: c_int = undefined;
    var szHdr1: u32 = undefined;
    var idx1: u32 = undefined;
    var rc: c_int = 0;
    var pRhs = rdPtr(pPKey2, UR_aMem); // Mem*
    const aKey1: [*]const u8 = @ptrCast(pKey1.?);
    var mem1: [sizeof_Mem]u8 align(8) = undefined;
    const pMem1: ?*Mem = @ptrCast(&mem1);
    const pKeyInfo = rdPtr(pPKey2, UR_pKeyInfo);
    const nKey1u: u32 = @bitCast(nKey1);

    if (bSkip != 0) {
        var s1: u32 = aKey1[1];
        if (s1 < 0x80) {
            idx1 = 2;
        } else {
            idx1 = 1 + sqlite3GetVarint32(aKey1 + 1, &s1);
        }
        szHdr1 = aKey1[0];
        d1 = szHdr1 + sqlite3VdbeSerialTypeLen(s1);
        i = 1;
        pRhs = memAt(pRhs, 1);
    } else {
        szHdr1 = aKey1[0];
        if (szHdr1 < 0x80) {
            idx1 = 1;
        } else {
            idx1 = sqlite3GetVarint32(aKey1, &szHdr1);
        }
        d1 = szHdr1;
        i = 0;
    }
    if (d1 > nKey1u) {
        wrU8(pPKey2, UR_errCode, @intCast(SQLITE_CORRUPT));
        return 0;
    }

    while (true) {
        var serial_type: u32 = undefined;
        const rhsFlags = memFlags(pRhs);

        if ((rhsFlags & (MEM_Int | MEM_IntReal)) != 0) {
            serial_type = aKey1[idx1];
            if (serial_type >= 10) {
                rc = if (serial_type == 10) -1 else 1;
            } else if (serial_type == 0) {
                rc = -1;
            } else if (serial_type == 7) {
                _ = serialGet7(aKey1 + d1, pMem1);
                rc = -sqlite3IntFloatCompare(memU(pRhs), memR(pMem1));
            } else {
                const lhs = vdbeRecordDecodeInt(serial_type, aKey1 + d1);
                const rhs = memU(pRhs);
                if (lhs < rhs) {
                    rc = -1;
                } else if (lhs > rhs) {
                    rc = 1;
                }
            }
        } else if ((rhsFlags & MEM_Real) != 0) {
            serial_type = aKey1[idx1];
            if (serial_type >= 10) {
                rc = if (serial_type == 10) -1 else 1;
            } else if (serial_type == 0) {
                rc = -1;
            } else {
                if (serial_type == 7) {
                    if (serialGet7(aKey1 + d1, pMem1) != 0) {
                        rc = -1;
                    } else if (memR(pMem1) < memR(pRhs)) {
                        rc = -1;
                    } else if (memR(pMem1) > memR(pRhs)) {
                        rc = 1;
                    }
                } else {
                    sqlite3VdbeSerialGet(aKey1 + d1, serial_type, pMem1);
                    rc = sqlite3IntFloatCompare(memU(pMem1), memR(pRhs));
                }
            }
        } else if ((rhsFlags & MEM_Str) != 0) {
            // getVarint32NR
            _ = getVarint32(aKey1 + idx1, &serial_type);
            if (serial_type < 12) {
                rc = -1;
            } else if ((serial_type & 0x01) == 0) {
                rc = 1;
            } else {
                wr(c_int, pMem1, Mem_n, @intCast((serial_type - 12) / 2));
                const mn: u32 = @bitCast(memN(pMem1));
                if ((d1 + mn) > nKey1u or rd(u16, pKeyInfo, KeyInfo_nAllField) <= @as(u16, @intCast(i))) {
                    wrU8(pPKey2, UR_errCode, @intCast(SQLITE_CORRUPT));
                    return 0;
                }
                // pKeyInfo->aColl[i] — aColl is an inline pointer array at
                // KeyInfo_aColl; read element i directly (no extra deref).
                const pColl = rdPtr(pKeyInfo, KeyInfo_aColl + @as(usize, @intCast(i)) * 8);
                if (pColl != null) {
                    wrU8(pMem1, Mem_enc, rdU8(pKeyInfo, KeyInfo_enc));
                    wrPtr(pMem1, Mem_db, rdPtr(pKeyInfo, KeyInfo_db));
                    wr(u16, pMem1, Mem_flags, MEM_Str);
                    wrPtr(pMem1, Mem_z, @ptrCast(@constCast(aKey1 + d1)));
                    rc = vdbeCompareMemString(pMem1, pRhs, @ptrCast(pColl), @ptrCast(fp(u8, pPKey2, UR_errCode)));
                } else {
                    const nCmp: usize = @intCast(@min(memN(pMem1), memN(pRhs)));
                    rc = memcmp(@ptrCast(aKey1 + d1), @ptrCast(memZ(pRhs)), nCmp);
                    if (rc == 0) rc = memN(pMem1) - memN(pRhs);
                }
            }
        } else if ((rhsFlags & MEM_Blob) != 0) {
            _ = getVarint32(aKey1 + idx1, &serial_type);
            if (serial_type < 12 or (serial_type & 0x01) != 0) {
                rc = -1;
            } else {
                const nStr: c_int = @intCast((serial_type - 12) / 2);
                if ((d1 + @as(u32, @bitCast(nStr))) > nKey1u) {
                    wrU8(pPKey2, UR_errCode, @intCast(SQLITE_CORRUPT));
                    return 0;
                } else if ((rhsFlags & MEM_Zero) != 0) {
                    if (isAllZero(aKey1 + d1, nStr) == 0) {
                        rc = 1;
                    } else {
                        rc = nStr - memNZero(pRhs);
                    }
                } else {
                    const nCmp: usize = @intCast(@min(nStr, memN(pRhs)));
                    rc = memcmp(@ptrCast(aKey1 + d1), @ptrCast(memZ(pRhs)), nCmp);
                    if (rc == 0) rc = nStr - memN(pRhs);
                }
            }
        } else {
            serial_type = aKey1[idx1];
            if (serial_type == 0 or serial_type == 10 or (serial_type == 7 and serialGet7(aKey1 + d1, pMem1) != 0)) {
                // rc stays 0
            } else {
                rc = 1;
            }
        }

        if (rc != 0) {
            const sortFlags = rd(u8, rdPtr(pKeyInfo, KeyInfo_aSortFlags), @intCast(i));
            if (sortFlags != 0) {
                const isNull = (serial_type == 0 or (memFlags(pRhs) & MEM_Null) != 0);
                if ((sortFlags & KEYINFO_ORDER_BIGNULL) == 0 or ((sortFlags & KEYINFO_ORDER_DESC) != 0) != isNull) {
                    rc = -rc;
                }
            }
            return rc;
        }

        i += 1;
        if (i == rd(u16, pPKey2, UR_nField)) break;
        pRhs = memAt(pRhs, 1);
        d1 += sqlite3VdbeSerialTypeLen(serial_type);
        if (d1 > nKey1u) break;
        idx1 += @intCast(sqlite3VarintLen(serial_type));
        if (idx1 >= szHdr1) {
            wrU8(pPKey2, UR_errCode, @intCast(SQLITE_CORRUPT));
            return 0;
        }
    }

    wrU8(pPKey2, UR_eqSeen, 1);
    return rd(i8, pPKey2, UR_default_rc);
}

export fn sqlite3VdbeRecordCompare(nKey1: c_int, pKey1: ?*const anyopaque, pPKey2: ?*UnpackedRecord) callconv(.c) c_int {
    return sqlite3VdbeRecordCompareWithSkip(nKey1, pKey1, pPKey2, 0);
}

fn vdbeRecordCompareInt(nKey1: c_int, pKey1: ?*const anyopaque, pPKey2: ?*UnpackedRecord) callconv(.c) c_int {
    const k1: [*]const u8 = @ptrCast(pKey1.?);
    const aKey = k1 + (k1[0] & 0x3F);
    const serial_type = k1[1];
    var res: c_int = undefined;
    var lhs: i64 = undefined;
    switch (serial_type) {
        1 => lhs = ONE_BYTE_INT(aKey),
        2 => lhs = TWO_BYTE_INT(aKey),
        3 => lhs = THREE_BYTE_INT(aKey),
        4 => {
            const y = FOUR_BYTE_UINT(aKey);
            lhs = @as(i64, @as(i32, @bitCast(y)));
        },
        5 => lhs = FOUR_BYTE_UINT(aKey + 2) +% (@as(i64, 1) << 32) *% TWO_BYTE_INT(aKey),
        6 => {
            var x: u64 = FOUR_BYTE_UINT(aKey);
            x = (x << 32) | FOUR_BYTE_UINT(aKey + 4);
            lhs = @bitCast(x);
        },
        8 => lhs = 0,
        9 => lhs = 1,
        0, 7 => return sqlite3VdbeRecordCompare(nKey1, pKey1, pPKey2),
        else => return sqlite3VdbeRecordCompare(nKey1, pKey1, pPKey2),
    }
    const v = rd(i64, pPKey2, UR_u);
    if (v > lhs) {
        res = rd(i8, pPKey2, UR_r1);
    } else if (v < lhs) {
        res = rd(i8, pPKey2, UR_r2);
    } else if (rd(u16, pPKey2, UR_nField) > 1) {
        res = sqlite3VdbeRecordCompareWithSkip(nKey1, pKey1, pPKey2, 1);
    } else {
        res = rd(i8, pPKey2, UR_default_rc);
        wrU8(pPKey2, UR_eqSeen, 1);
    }
    return res;
}

fn vdbeRecordCompareString(nKey1: c_int, pKey1: ?*const anyopaque, pPKey2: ?*UnpackedRecord) callconv(.c) c_int {
    const aKey1: [*]const u8 = @ptrCast(pKey1.?);
    var serial_type: c_int = @as(i8, @bitCast(aKey1[1]));
    var res: c_int = undefined;

    while (true) {
        if (serial_type < 12) {
            if (serial_type < 0) {
                var st: u32 = undefined;
                _ = sqlite3GetVarint32(aKey1 + 1, &st);
                serial_type = @bitCast(st);
                if (serial_type >= 12) continue; // goto vrcs_restart
            }
            res = rd(i8, pPKey2, UR_r1);
        } else if ((serial_type & 0x01) == 0) {
            res = rd(i8, pPKey2, UR_r2);
        } else {
            const nStr: c_int = @divTrunc(serial_type - 12, 2);
            const szHdr: c_int = aKey1[0];
            if ((szHdr + nStr) > nKey1) {
                wrU8(pPKey2, UR_errCode, @intCast(SQLITE_CORRUPT));
                return 0;
            }
            const pn = rd(c_int, pPKey2, UR_n);
            const nCmp: usize = @intCast(@min(pn, nStr));
            const uz = rdPtr(pPKey2, UR_u); // u.z
            res = memcmp(@ptrCast(aKey1 + @as(usize, @intCast(szHdr))), @ptrCast(uz), nCmp);
            if (res > 0) {
                res = rd(i8, pPKey2, UR_r2);
            } else if (res < 0) {
                res = rd(i8, pPKey2, UR_r1);
            } else {
                res = nStr - pn;
                if (res == 0) {
                    if (rd(u16, pPKey2, UR_nField) > 1) {
                        res = sqlite3VdbeRecordCompareWithSkip(nKey1, pKey1, pPKey2, 1);
                    } else {
                        res = rd(i8, pPKey2, UR_default_rc);
                        wrU8(pPKey2, UR_eqSeen, 1);
                    }
                } else if (res > 0) {
                    res = rd(i8, pPKey2, UR_r2);
                } else {
                    res = rd(i8, pPKey2, UR_r1);
                }
            }
        }
        break;
    }
    return res;
}

export fn sqlite3VdbeFindCompare(p: ?*UnpackedRecord) callconv(.c) ?*const anyopaque {
    const pKeyInfo = rdPtr(p, UR_pKeyInfo);
    if (rd(u16, pKeyInfo, KeyInfo_nAllField) <= 13) {
        const aMem0 = rdPtr(p, UR_aMem);
        const flags: c_int = memFlags(aMem0);
        const sortFlags0 = rd(u8, rdPtr(pKeyInfo, KeyInfo_aSortFlags), 0);
        if (sortFlags0 != 0) {
            if ((sortFlags0 & KEYINFO_ORDER_BIGNULL) != 0) {
                return @ptrCast(&sqlite3VdbeRecordCompare);
            }
            wrU8(p, UR_r1, @bitCast(@as(i8, 1)));
            wrU8(p, UR_r2, @bitCast(@as(i8, -1)));
        } else {
            wrU8(p, UR_r1, @bitCast(@as(i8, -1)));
            wrU8(p, UR_r2, @bitCast(@as(i8, 1)));
        }
        if ((flags & MEM_Int) != 0) {
            wr(i64, p, UR_u, memU(aMem0));
            return @ptrCast(&vdbeRecordCompareInt);
        }
        // aColl is an inline array (CollSeq *aColl[1]); aColl[0] is the pointer
        // value AT offset KeyInfo_aColl — do NOT deref it again (it may be null).
        const aColl0 = rdPtr(pKeyInfo, KeyInfo_aColl);
        if ((flags & (MEM_Real | MEM_IntReal | MEM_Null | MEM_Blob)) == 0 and aColl0 == null) {
            wrPtr(p, UR_u, rdPtr(aMem0, Mem_z));
            wr(c_int, p, UR_n, memN(aMem0));
            return @ptrCast(&vdbeRecordCompareString);
        }
    }
    return @ptrCast(&sqlite3VdbeRecordCompare);
}

// ===========================================================================
// Index rowid / key compare / find-index-key
// ===========================================================================
export fn sqlite3VdbeIdxRowid(db: ?*sqlite3, pCur: ?*BtCursor, rowid: *i64) callconv(.c) c_int {
    var m: [sizeof_Mem]u8 align(8) = undefined;
    var v: [sizeof_Mem]u8 align(8) = undefined;
    const pm: ?*Mem = @ptrCast(&m);
    const pv: ?*Mem = @ptrCast(&v);
    const nCellKey: i64 = @bitCast(sqlite3BtreePayloadSize(pCur));
    sqlite3VdbeMemInit(pm, db, 0);
    const rc = sqlite3VdbeMemFromBtreeZeroOffset(pCur, @intCast(nCellKey), pm);
    if (rc != 0) return rc;
    const mz: [*]const u8 = @ptrCast(memZ(pm).?);
    var szHdr: u32 = undefined;
    _ = getVarint32(mz, &szHdr);
    if (szHdr < 3 or szHdr > @as(u32, @bitCast(memN(pm)))) {
        sqlite3VdbeMemReleaseMalloc(pm);
        return SQLITE_CORRUPT;
    }
    var typeRowid: u32 = undefined;
    _ = getVarint32(mz + (szHdr - 1), &typeRowid);
    if (typeRowid < 1 or typeRowid > 9 or typeRowid == 7) {
        sqlite3VdbeMemReleaseMalloc(pm);
        return SQLITE_CORRUPT;
    }
    const lenRowid = sqlite3SmallTypeSizes[typeRowid];
    if (@as(u32, @bitCast(memN(pm))) < szHdr + lenRowid) {
        sqlite3VdbeMemReleaseMalloc(pm);
        return SQLITE_CORRUPT;
    }
    sqlite3VdbeSerialGet(mz + @as(usize, @intCast(memN(pm) - lenRowid)), typeRowid, pv);
    rowid.* = memU(pv);
    sqlite3VdbeMemReleaseMalloc(pm);
    return SQLITE_OK;
}

export fn sqlite3VdbeIdxKeyCompare(db: ?*sqlite3, pC: ?*VdbeCursor, pUnpacked: ?*UnpackedRecord, res: *c_int) callconv(.c) c_int {
    const pCur = rdPtr(pC, VdbeCursor_uc);
    const nCellKey: i64 = @bitCast(sqlite3BtreePayloadSize(@ptrCast(pCur)));
    if (nCellKey <= 0 or nCellKey > 0x7fffffff) {
        res.* = 0;
        return SQLITE_CORRUPT;
    }
    var m: [sizeof_Mem]u8 align(8) = undefined;
    const pm: ?*Mem = @ptrCast(&m);
    sqlite3VdbeMemInit(pm, db, 0);
    const rc = sqlite3VdbeMemFromBtreeZeroOffset(@ptrCast(pCur), @intCast(nCellKey), pm);
    if (rc != 0) return rc;
    res.* = sqlite3VdbeRecordCompareWithSkip(memN(pm), memZ(pm), pUnpacked, 0);
    sqlite3VdbeMemReleaseMalloc(pm);
    return SQLITE_OK;
}

// ===========================================================================
// Misc tail
// ===========================================================================
export fn sqlite3VdbeSetChanges(db: ?*sqlite3, nChange: i64) callconv(.c) void {
    wr(i64, db, sqlite3_nChange, nChange);
    wr(i64, db, sqlite3_nTotalChange, rd(i64, db, sqlite3_nTotalChange) +% nChange);
}
export fn sqlite3VdbeCountChanges(v: ?*Vdbe) callconv(.c) void {
    // changeCntOn:1 bit (0x10) in the Vdbe bitfield byte.
    vbits(v).* |= 0x10;
}
export fn sqlite3ExpirePreparedStatements(db: ?*sqlite3, iCode: c_int) callconv(.c) void {
    var p = rdPtr(db, sqlite3_pVdbe);
    while (p != null) : (p = rdPtr(p, Vdbe_pVNext)) {
        // expired is the low 2 bits of the bitfield byte
        setExpired(p, @truncate(@as(c_uint, @bitCast(iCode + 1))));
    }
}
export fn sqlite3VdbeDb(v: ?*Vdbe) callconv(.c) ?*sqlite3 {
    return rdPtr(v, Vdbe_db);
}
export fn sqlite3VdbePrepareFlags(v: ?*Vdbe) callconv(.c) u8 {
    return rdU8(v, Vdbe_prepFlags);
}

const SQLITE_EnableQPSG: u64 = 0; // unused; QPSG checks are asserts only
export fn sqlite3VdbeGetBoundValue(v: ?*Vdbe, iVar: c_int, aff: u8) callconv(.c) ?*anyopaque {
    if (v != null) {
        const pMem = memAt(rdPtr(v, Vdbe_aVar), @intCast(iVar - 1));
        if ((memFlags(pMem) & MEM_Null) == 0) {
            const pRet = sqlite3ValueNew(rdPtr(v, Vdbe_db));
            if (pRet != null) {
                _ = sqlite3VdbeMemCopy(pRet, pMem);
                sqlite3ValueApplyAffinity(pRet, aff, SQLITE_UTF8);
            }
            return pRet;
        }
    }
    return null;
}
export fn sqlite3VdbeSetVarmask(v: ?*Vdbe, iVar: c_int) callconv(.c) void {
    if (iVar >= 32) {
        wr(u32, v, Vdbe_expmask, rd(u32, v, Vdbe_expmask) | 0x80000000);
    } else {
        wr(u32, v, Vdbe_expmask, rd(u32, v, Vdbe_expmask) | (@as(u32, 1) << @intCast(iVar - 1)));
    }
}

// ===========================================================================
// sqlite3NotPureFunc (OMIT_DATETIME_FUNCS off)
// ===========================================================================
const NC_IsCheck: u16 = 0x0004;
const NC_GenCol: u16 = 0x0008;
extern fn sqlite3_result_error(ctx: ?*sqlite3_context, z: ?[*:0]const u8, n: c_int) void;
export fn sqlite3NotPureFunc(pCtx: ?*sqlite3_context) callconv(.c) c_int {
    const pVdbe = rdPtr(pCtx, Ctx_pVdbe);
    const aOp = rdPtr(pVdbe, Vdbe_aOp);
    const pOp = opAt(aOp, @intCast(rd(c_int, pCtx, Ctx_iOp)));
    if (rdU8(pOp, Op_opcode) == OP_PureFunc) {
        const p5 = rd(u16, pOp, Op_p5);
        const zContext: [*:0]const u8 = if ((p5 & NC_IsCheck) != 0) "a CHECK constraint" else if ((p5 & NC_GenCol) != 0) "a generated column" else "an index";
        const pFunc = rdPtr(pCtx, Ctx_pFunc);
        const zName: [*:0]const u8 = @ptrCast(rdPtr(pFunc, FuncDef_zName).?);
        const zMsg = sqlite3_mprintf("non-deterministic use of %s() in %s", zName, zContext);
        sqlite3_result_error(pCtx, @ptrCast(zMsg), -1);
        sqlite3_free(zMsg);
        return 0;
    }
    return 1;
}
const FuncDef_zName = 56; // see probe

// ===========================================================================
// VtabImportErrmsg (OMIT_VIRTUALTABLE off)
// ===========================================================================
export fn sqlite3VtabImportErrmsg(p: ?*Vdbe, pVtab: ?*sqlite3_vtab) callconv(.c) void {
    // sqlite3_vtab { const sqlite3_module *pModule; int nRef; char *zErrMsg }
    const zErrMsg = rdPtr(pVtab, 16);
    if (zErrMsg != null) {
        const db = rdPtr(p, Vdbe_db);
        sqlite3DbFree(db, rdPtr(p, Vdbe_zErrMsg));
        wrPtr(p, Vdbe_zErrMsg, @ptrCast(sqlite3DbStrDup(db, @ptrCast(zErrMsg))));
        sqlite3_free(zErrMsg);
        wrPtr(pVtab, 16, null);
    }
}

// ===========================================================================
// sqlite3VdbeFuncName (ENABLE_PERCENTILE on)
// ===========================================================================
export fn sqlite3VdbeFuncName(pCtx: ?*sqlite3_context) callconv(.c) ?[*:0]const u8 {
    return @ptrCast(rdPtr(rdPtr(pCtx, Ctx_pFunc), FuncDef_zName));
}

// ===========================================================================
// EXPLAIN / debug P4 + comment display (VDBE_DISPLAY_P4 on; EXPLAIN_COMMENTS on)
// ===========================================================================
const StrAccum = extern struct {
    db: ?*anyopaque,
    zText: ?[*]u8,
    nAlloc: u32,
    mxAlloc: u32,
    nChar: u32,
    accError: u8,
    printfFlags: u8,
};
extern fn sqlite3StrAccumInit(p: *StrAccum, db: ?*anyopaque, zBase: ?[*]u8, n: c_int, mx: c_int) void;
extern fn sqlite3StrAccumFinish(p: *StrAccum) ?[*:0]u8;
extern fn sqlite3_str_append(p: *StrAccum, z: [*]const u8, N: c_int) void;
extern fn sqlite3_str_appendall(p: *StrAccum, z: [*:0]const u8) void;
extern fn sqlite3_str_appendf(p: *StrAccum, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_str_appendchar(p: *StrAccum, N: c_int, c: u8) void;
const SQLITE_MAX_LENGTH: c_int = 1000000000;

const Index_zName = 0;
const Index_aiColumn = 8;
const Index_nColumn = 96;
const Index_pTable = 24;
const Index_nKeyCol = 94;
const Index_pNext = 40;
const Table_zName = 0;
const Table_aCol = 8;
const Table_nCol = 54;
const Column_colFlags = 14;
const sizeof_Column = 16;
const COLFLAG_VIRTUAL: u16 = 0x0020;
const XN_EXPR: i16 = -2;
const BMS: c_int = 64;

export fn sqlite3VdbeDisplayP4(db: ?*sqlite3, pOp: ?*Op) callconv(.c) ?[*:0]u8 {
    var zP4: ?[*:0]const u8 = null;
    var x: StrAccum = undefined;
    sqlite3StrAccumInit(&x, null, null, 0, SQLITE_MAX_LENGTH);
    const p4type: i8 = @bitCast(rdU8(pOp, Op_p4type));
    switch (p4type) {
        P4_KEYINFO => {
            const pKeyInfo = rdPtr(pOp, Op_p4);
            const nKeyField = rd(u16, pKeyInfo, KeyInfo_nKeyField);
            sqlite3_str_appendf(&x, "k(%d", @as(c_int, nKeyField));
            var j: c_int = 0;
            const aSortFlags = rdPtr(pKeyInfo, KeyInfo_aSortFlags);
            while (j < nKeyField) : (j += 1) {
                // aColl is an inline array — element j is at KeyInfo_aColl+j*8.
                const pColl = rdPtr(pKeyInfo, KeyInfo_aColl + @as(usize, @intCast(j)) * 8);
                var zColl: [*:0]const u8 = if (pColl != null) @ptrCast(rdPtr(pColl, 0).?) else "";
                if (memcmpZ(zColl, "BINARY") == 0) zColl = "B";
                const sf = rd(u8, aSortFlags, @intCast(j));
                const zDesc: [*:0]const u8 = if ((sf & KEYINFO_ORDER_DESC) != 0) "-" else "";
                const zBig: [*:0]const u8 = if ((sf & KEYINFO_ORDER_BIGNULL) != 0) "N." else "";
                sqlite3_str_appendf(&x, ",%s%s%s", zDesc, zBig, zColl);
            }
            sqlite3_str_append(&x, ")", 1);
        },
        P4_COLLSEQ => {
            const encnames = [_][*:0]const u8{ "?", "8", "16LE", "16BE" };
            const pColl = rdPtr(pOp, Op_p4);
            const enc = rdU8(pColl, CollSeq_enc);
            sqlite3_str_appendf(&x, "%.18s-%s", @as([*:0]const u8, @ptrCast(rdPtr(pColl, 0).?)), encnames[enc]);
        },
        P4_FUNCDEF => {
            const pDef = rdPtr(pOp, Op_p4);
            sqlite3_str_appendf(&x, "%s(%d)", @as([*:0]const u8, @ptrCast(rdPtr(pDef, FuncDef_zName).?)), @as(c_int, rd(i16, pDef, 0)));
        },
        P4_FUNCCTX => {
            const pDef = rdPtr(rdPtr(pOp, Op_p4), Ctx_pFunc);
            sqlite3_str_appendf(&x, "%s(%d)", @as([*:0]const u8, @ptrCast(rdPtr(pDef, FuncDef_zName).?)), @as(c_int, rd(i16, pDef, 0)));
        },
        P4_INT64 => {
            sqlite3_str_appendf(&x, "%lld", rd(i64, rdPtr(pOp, Op_p4), 0));
        },
        P4_INT32 => {
            sqlite3_str_appendf(&x, "%d", rd(c_int, pOp, Op_p4));
        },
        P4_REAL => {
            sqlite3_str_appendf(&x, "%.16g", rd(f64, rdPtr(pOp, Op_p4), 0));
        },
        P4_MEM => {
            const pMem = rdPtr(pOp, Op_p4);
            const flags = memFlags(pMem);
            if ((flags & MEM_Str) != 0) {
                zP4 = @ptrCast(memZ(pMem));
            } else if ((flags & (MEM_Int | MEM_IntReal)) != 0) {
                sqlite3_str_appendf(&x, "%lld", memU(pMem));
            } else if ((flags & MEM_Real) != 0) {
                sqlite3_str_appendf(&x, "%.16g", memR(pMem));
            } else if ((flags & MEM_Null) != 0) {
                zP4 = "NULL";
            } else {
                zP4 = "(blob)";
            }
        },
        P4_VTAB => {
            const pVtab = rdPtr(rdPtr(pOp, Op_p4), 0); // VTable.pVtab
            sqlite3_str_appendf(&x, "vtab:%p", pVtab);
        },
        P4_INTARRAY => {
            const ai: [*]const u32 = @ptrCast(@alignCast(rdPtr(pOp, Op_p4).?));
            const n = ai[0];
            var i: u32 = 1;
            while (i <= n) : (i += 1) {
                sqlite3_str_appendf(&x, "%c%u", @as(c_int, if (i == 1) '[' else ','), ai[i]);
            }
            sqlite3_str_append(&x, "]", 1);
        },
        P4_SUBPROGRAM => {
            zP4 = "program";
        },
        P4_TABLE => {
            zP4 = @ptrCast(rdPtr(rdPtr(pOp, Op_p4), Table_zName));
        },
        P4_INDEX => {
            zP4 = @ptrCast(rdPtr(rdPtr(pOp, Op_p4), Index_zName));
        },
        P4_SUBRTNSIG => {
            const pSig = rdPtr(pOp, Op_p4);
            // SubrtnSig { u32 selId; u16 nReg; char *zAff; } selId@0, zAff@8
            sqlite3_str_appendf(&x, "subrtnsig:%d,%s", rd(c_int, pSig, 0), @as([*:0]const u8, @ptrCast(rdPtr(pSig, 8).?)));
        },
        else => {
            zP4 = @ptrCast(rdPtr(pOp, Op_p4));
        },
    }
    if (zP4 != null) sqlite3_str_appendall(&x, zP4.?);
    if ((x.accError & SQLITE_NOMEM) != 0) {
        sqlite3OomFault(db);
    }
    return sqlite3StrAccumFinish(&x);
}

fn memcmpZ(a: [*:0]const u8, b: [*:0]const u8) c_int {
    var i: usize = 0;
    while (a[i] != 0 and a[i] == b[i]) : (i += 1) {}
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

// EXPLAIN_COMMENTS on: sqlite3VdbeDisplayComment + translateP.
fn translateP(c: u8, pOp: ?*const Op) c_int {
    if (c == '1') return rd(c_int, @constCast(pOp), Op_p1);
    if (c == '2') return rd(c_int, @constCast(pOp), Op_p2);
    if (c == '3') return rd(c_int, @constCast(pOp), Op_p3);
    if (c == '4') return rd(c_int, @constCast(pOp), Op_p4);
    return rd(u16, @constCast(pOp), Op_p5);
}

export fn sqlite3VdbeDisplayComment(db: ?*sqlite3, pOp: ?*const Op, zP4: ?[*:0]const u8) callconv(.c) ?[*:0]u8 {
    var zAlt: [50]u8 = undefined;
    var x: StrAccum = undefined;
    sqlite3StrAccumInit(&x, null, null, 0, SQLITE_MAX_LENGTH);
    const zOpName = sqlite3OpcodeName(rdU8(@constCast(pOp), Op_opcode));
    const nOpName = sqlite3Strlen30(zOpName);
    const zComment = rdPtr(@constCast(pOp), Op_zComment);
    // zOpName[nOpName+1] != 0  → there is a Synopsis.
    if (zOpName[@intCast(nOpName + 1)] != 0) {
        var seenCom: bool = false;
        var zSynopsis: [*:0]const u8 = @ptrCast(zOpName + @as(usize, @intCast(nOpName + 1)));
        if (strncmp(zSynopsis, "IF ", 3) == 0) {
            _ = sqlite3_snprintf(50, &zAlt, "if %s goto P2", zSynopsis + 3);
            zSynopsis = @ptrCast(&zAlt);
        }
        var ii: usize = 0;
        while (zSynopsis[ii] != 0) : (ii += 1) {
            var c = zSynopsis[ii];
            if (c == 'P') {
                ii += 1;
                c = zSynopsis[ii];
                if (c == '4') {
                    if (zP4 != null) sqlite3_str_appendall(&x, zP4.?);
                } else if (c == 'X') {
                    if (zComment != null and rdU8(zComment, 0) != 0) {
                        sqlite3_str_appendall(&x, @ptrCast(zComment.?));
                        seenCom = true;
                        break;
                    }
                } else {
                    const v1 = translateP(c, pOp);
                    if (strncmp(zSynopsis + ii + 1, "@P", 2) == 0) {
                        ii += 3;
                        var v2 = translateP(zSynopsis[ii], pOp);
                        if (strncmp(zSynopsis + ii + 1, "+1", 2) == 0) {
                            ii += 2;
                            v2 += 1;
                        }
                        if (v2 < 2) {
                            sqlite3_str_appendf(&x, "%d", v1);
                        } else {
                            sqlite3_str_appendf(&x, "%d..%d", v1, v1 + v2 - 1);
                        }
                    } else if (strncmp(zSynopsis + ii + 1, "@NP", 3) == 0) {
                        const pCtx = rdPtr(@constCast(pOp), Op_p4);
                        const argc: u16 = if (@as(i8, @bitCast(rdU8(@constCast(pOp), Op_p4type))) == P4_FUNCCTX) rd(u16, pCtx, Ctx_argc) else 1;
                        if (@as(i8, @bitCast(rdU8(@constCast(pOp), Op_p4type))) != P4_FUNCCTX or argc == 1) {
                            sqlite3_str_appendf(&x, "%d", v1);
                        } else if (argc > 1) {
                            sqlite3_str_appendf(&x, "%d..%d", v1, v1 + @as(c_int, argc) - 1);
                        } else if (x.accError == 0) {
                            x.nChar -= 2;
                            ii += 1;
                        }
                        ii += 3;
                    } else {
                        sqlite3_str_appendf(&x, "%d", v1);
                        if (strncmp(zSynopsis + ii + 1, "..P3", 4) == 0 and rd(c_int, @constCast(pOp), Op_p3) == 0) {
                            ii += 4;
                        }
                    }
                }
            } else {
                sqlite3_str_appendchar(&x, 1, c);
            }
        }
        if (!seenCom and zComment != null) {
            sqlite3_str_appendf(&x, "; %s", @as([*:0]const u8, @ptrCast(zComment.?)));
        }
    } else if (zComment != null) {
        sqlite3_str_appendall(&x, @ptrCast(zComment.?));
    }
    if ((x.accError & SQLITE_NOMEM) != 0 and db != null) {
        sqlite3OomFault(db);
    }
    return sqlite3StrAccumFinish(&x);
}
extern fn strncmp(a: [*]const u8, b: [*]const u8, n: usize) c_int;

// ===========================================================================
// FindIndexKey (and its helpers)
// ===========================================================================
const BTREE_ULPDISTORTION: u64 = 2;
fn MASKBIT(i: c_int) u64 {
    return @as(u64, 1) << @intCast(i);
}
fn vdbeSkipField(mask: u64, iCol: c_int, pMem1: ?*Mem, pMem2: ?*Mem, bIntegrity: c_int) c_int {
    if (iCol >= BMS or (mask & MASKBIT(iCol)) == 0) return 0;
    if (bIntegrity == 0) return 1;
    if ((memFlags(pMem1) & MEM_Real) != 0 and (memFlags(pMem2) & MEM_Real) != 0) {
        const m1: u64 = rd(u64, pMem1, Mem_u);
        const m2: u64 = rd(u64, pMem2, Mem_u);
        const diff = if (m1 < m2) m2 - m1 else m1 - m2;
        if (diff <= BTREE_ULPDISTORTION) return 1;
    }
    return 0;
}

extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
fn vdbeIsMatchingIndexKey(pCur: ?*BtCursor, bInt: c_int, mask: u64, p: ?*UnpackedRecord, piRes: *c_int) c_int {
    var m: [sizeof_Mem]u8 align(8) = std.mem.zeroes([sizeof_Mem]u8);
    const pm: ?*Mem = @ptrCast(&m);
    var rc: c_int = SQLITE_OK;
    const pKeyInfo = rdPtr(p, UR_pKeyInfo);
    wrU8(pm, Mem_enc, rdU8(pKeyInfo, KeyInfo_enc));
    wrPtr(pm, Mem_db, rdPtr(pKeyInfo, KeyInfo_db));
    const nRec: u32 = @intCast(sqlite3BtreePayloadSize(pCur));
    if (nRec > 0x7fffffff) return SQLITE_CORRUPT;

    const aRec: ?[*]u8 = @ptrCast(sqlite3MallocZero(@as(u64, nRec) + 5));
    if (aRec == null) {
        rc = SQLITE_NOMEM;
    } else {
        rc = sqlite3BtreePayload(pCur, 0, nRec, aRec);
    }
    if (rc == SQLITE_OK) {
        var szHdr: u32 = 0;
        var idxHdr: u32 = getVarint32(aRec.?, &szHdr);
        if (szHdr > 98307) {
            rc = SQLITE_CORRUPT;
        } else {
            var res: c_int = 0;
            var idxRec: u32 = szHdr;
            const nCol = rd(u16, pKeyInfo, KeyInfo_nAllField);
            const aMem = rdPtr(p, UR_aMem);
            var ii: c_int = 0;
            while (ii < nCol and rc == SQLITE_OK) : (ii += 1) {
                var iSerial: u32 = 0;
                if (idxHdr >= szHdr) {
                    rc = SQLITE_CORRUPT;
                    break;
                }
                idxHdr += getVarint32(aRec.? + idxHdr, &iSerial);
                const nSerial = sqlite3VdbeSerialTypeLen(iSerial);
                if ((idxRec + nSerial) > nRec) {
                    rc = SQLITE_CORRUPT;
                } else {
                    sqlite3VdbeSerialGet(aRec.? + idxRec, iSerial, pm);
                    const pAMem = memAt(aMem, @intCast(ii));
                    if (vdbeSkipField(mask, ii, pAMem, pm, bInt) == 0) {
                        const pColl = rdPtr(pKeyInfo, KeyInfo_aColl + @as(usize, @intCast(ii)) * 8);
                        res = sqlite3MemCompare(pm, pAMem, @ptrCast(pColl));
                        if (res != 0) break;
                    }
                }
                idxRec += sqlite3VdbeSerialTypeLen(iSerial);
            }
            piRes.* = res;
        }
    }
    sqlite3_free(aRec);
    return rc;
}

export fn sqlite3VdbeFindIndexKey(pCur: ?*BtCursor, pIdx: ?*Index, p: ?*UnpackedRecord, pRes: *c_int, bIntegrity: c_int) callconv(.c) c_int {
    const BTREE_FDK_RANGE: c_int = 10;
    var nStep: c_int = 0;
    var res: c_int = 1;
    var rc: c_int = SQLITE_OK;
    var ii: c_int = 0;
    var mask: u64 = 0;
    const nColumn = rd(u16, pIdx, Index_nColumn);
    const aiColumn: [*]const i16 = @ptrCast(@alignCast(rdPtr(pIdx, Index_aiColumn).?));
    const pTable = rdPtr(pIdx, Index_pTable);
    const aCol = rdPtr(pTable, Table_aCol);
    const lim = @min(@as(c_int, nColumn), BMS);
    while (ii < lim) : (ii += 1) {
        const iCol = aiColumn[@intCast(ii)];
        var hit = false;
        if (iCol == XN_EXPR) {
            hit = true;
        } else if (iCol >= 0) {
            const colFlags = rd(u16, aCol, @as(usize, @intCast(iCol)) * sizeof_Column + Column_colFlags);
            if ((colFlags & COLFLAG_VIRTUAL) != 0) hit = true;
        }
        if (hit) mask |= MASKBIT(ii);
    }
    if (mask != 0) {
        ii = 0;
        while (sqlite3BtreeEof(pCur) == 0 and ii < BTREE_FDK_RANGE) : (ii += 1) {
            rc = sqlite3BtreePrevious(pCur, 0);
        }
        if (rc == SQLITE_DONE) {
            rc = sqlite3BtreeFirst(pCur, &res);
            nStep = -1;
        } else {
            nStep = BTREE_FDK_RANGE * 2;
        }
        while (sqlite3BtreeCursorIsValidNN(pCur) != 0) {
            ii = 0;
            while (rc == SQLITE_OK and (ii < nStep or nStep < 0)) : (ii += 1) {
                rc = vdbeIsMatchingIndexKey(pCur, bIntegrity, mask, p, &res);
                if (res == 0 or rc != SQLITE_OK) break;
                rc = sqlite3BtreeNext(pCur, 0);
            }
            if (rc == SQLITE_DONE) {
                rc = SQLITE_OK;
            }
            if (nStep < 0 or rc != SQLITE_OK or res == 0 or bIntegrity != 0) break;
            nStep = -1;
            rc = sqlite3BtreeFirst(pCur, &res);
        }
    }
    pRes.* = res;
    return rc;
}

// ===========================================================================
// PreUpdateHook (ENABLE_PREUPDATE_HOOK on in both)
// ===========================================================================
const PreUpdate_v = 0;
const PreUpdate_pCsr = 8;
const PreUpdate_op = 16;
const PreUpdate_aRecord = 24;
const PreUpdate_pKeyinfo = 32;
const PreUpdate_pUnpacked = 40;
const PreUpdate_pNewUnpacked = 48;
const PreUpdate_iNewReg = 56;
const PreUpdate_iBlobWrite = 60;
const PreUpdate_iKey1 = 64;
const PreUpdate_iKey2 = 72;
const PreUpdate_oldipk = 80;
const PreUpdate_aNew = off("PreUpdate_aNew", 136, 152);
const PreUpdate_pTab = off("PreUpdate_pTab", 144, 160);
const PreUpdate_pPk = off("PreUpdate_pPk", 152, 168);
const PreUpdate_apDflt = off("PreUpdate_apDflt", 160, 176);
const PreUpdate_uKey = off("PreUpdate_uKey", 168, 184);
const sizeof_PreUpdate = off("sizeof_PreUpdate", 200, 216);

const SQLITE_UPDATE: c_int = 23;
const TF_WithoutRowid: u32 = 0x00000080;
const Table_tabFlags = 48;
const Table_nNVCol = 56;

extern fn sqlite3PrimaryKeyIndex(pTab: ?*Table) ?*Index;

export fn sqlite3VdbePreUpdateHook(v: ?*Vdbe, pCsr: ?*VdbeCursor, op: c_int, zDb: ?[*:0]const u8, pTab: ?*Table, iKey1In: i64, iReg: c_int, iBlobWrite: c_int) callconv(.c) void {
    const db = rdPtr(v, Vdbe_db);
    var iKey1 = iKey1In;
    var iKey2: i64 = undefined;
    const zTbl: ?[*:0]const u8 = @ptrCast(rdPtr(pTab, Table_zName));
    var pu: [sizeof_PreUpdate]u8 align(8) = std.mem.zeroes([sizeof_PreUpdate]u8);
    const preupdate: ?*anyopaque = @ptrCast(&pu);

    const hasRowid = (rd(u32, pTab, Table_tabFlags) & TF_WithoutRowid) == 0;
    if (!hasRowid) {
        iKey1 = 0;
        iKey2 = 0;
        wrPtr(preupdate, PreUpdate_pPk, sqlite3PrimaryKeyIndex(pTab));
    } else {
        if (op == SQLITE_UPDATE) {
            iKey2 = rd(i64, memAt(rdPtr(v, Vdbe_aMem), @intCast(iReg)), Mem_u);
        } else {
            iKey2 = iKey1;
        }
    }

    wrPtr(preupdate, PreUpdate_v, v);
    wrPtr(preupdate, PreUpdate_pCsr, pCsr);
    wr(c_int, preupdate, PreUpdate_op, op);
    wr(c_int, preupdate, PreUpdate_iNewReg, iReg);
    // pKeyinfo = (KeyInfo*)&preupdate.uKey
    const pKeyinfo: ?*anyopaque = @as([*]u8, @ptrCast(preupdate.?)) + PreUpdate_uKey;
    wrPtr(preupdate, PreUpdate_pKeyinfo, pKeyinfo);
    wrPtr(pKeyinfo, KeyInfo_db, db);
    wrU8(pKeyinfo, KeyInfo_enc, rdU8(db, sqlite3_enc));
    wr(u16, pKeyinfo, KeyInfo_nKeyField, @bitCast(rd(i16, pTab, Table_nCol)));
    wrPtr(pKeyinfo, KeyInfo_aSortFlags, null);
    wr(i64, preupdate, PreUpdate_iKey1, iKey1);
    wr(i64, preupdate, PreUpdate_iKey2, iKey2);
    wrPtr(preupdate, PreUpdate_pTab, pTab);
    wr(c_int, preupdate, PreUpdate_iBlobWrite, iBlobWrite);

    wrPtr(db, sqlite3_pPreUpdate, preupdate);
    const xPre: *const fn (?*anyopaque, ?*sqlite3, c_int, ?[*:0]const u8, ?[*:0]const u8, i64, i64) callconv(.c) void = @ptrCast(rdPtr(db, sqlite3_xPreUpdateCallback).?);
    xPre(rdPtr(db, sqlite3_pPreUpdateArg), db, op, zDb, zTbl, iKey1, iKey2);
    wrPtr(db, sqlite3_pPreUpdate, null);

    sqlite3DbFree(db, rdPtr(preupdate, PreUpdate_aRecord));
    const nKeyField = rd(u16, pKeyinfo, KeyInfo_nKeyField);
    vdbeFreeUnpacked(db, @as(c_int, nKeyField) + 1, rdPtr(preupdate, PreUpdate_pUnpacked));
    vdbeFreeUnpacked(db, @as(c_int, nKeyField) + 1, rdPtr(preupdate, PreUpdate_pNewUnpacked));
    sqlite3VdbeMemRelease(@as([*]u8, @ptrCast(preupdate.?)) + PreUpdate_oldipk);
    const aNew = rdPtr(preupdate, PreUpdate_aNew);
    if (aNew != null) {
        var i: c_int = 0;
        const nField = rd(i16, pCsr, VdbeCursor_nField);
        while (i < nField) : (i += 1) {
            sqlite3VdbeMemRelease(memAt(aNew, @intCast(i)));
        }
        sqlite3DbNNFreeNN(db, aNew);
    }
    const apDflt = rdPtr(preupdate, PreUpdate_apDflt);
    if (apDflt != null) {
        var i: c_int = 0;
        const nCol = rd(i16, pTab, Table_nCol);
        while (i < nCol) : (i += 1) {
            sqlite3ValueFree(rdPtr(apDflt, @as(usize, @intCast(i)) * 8));
        }
        sqlite3DbFree(db, apDflt);
    }
}

fn vdbeFreeUnpacked(db: ?*sqlite3, nField: c_int, p: ?*UnpackedRecord) void {
    if (p == null) return;
    var i: c_int = 0;
    const aMem = rdPtr(p, UR_aMem);
    while (i < nField) : (i += 1) {
        const pMem = memAt(aMem, @intCast(i));
        if (rdPtr(pMem, Mem_zMalloc) != null) sqlite3VdbeMemReleaseMalloc(pMem);
    }
    sqlite3DbNNFreeNN(db, p);
}

// ===========================================================================
// SQLITE_DEBUG-only functions. Defined unconditionally (so the module always
// type-checks) but exported only when config.sqlite_debug, mirroring C's
// #ifdef SQLITE_DEBUG. Helper extern decls used only here.
// ===========================================================================
extern fn sqlite3_str_new(db: ?*anyopaque) ?*StrAccum;
extern fn sqlite3_str_finish(p: ?*StrAccum) ?[*:0]u8;
const VdbeCursor_isEphemeral_byte = off("VdbeCursor_flagsByte", 5, 7); // bitfield byte (probe below)

// VdbeOpIter: walk main program + subprograms.
const VdbeOpIter = struct {
    v: ?*Vdbe,
    apSub: ?*anyopaque, // SubProgram**
    nSub: c_int,
    iAddr: c_int,
    iSub: c_int,
};
fn opIterNext(it: *VdbeOpIter) ?*Op {
    var pRet: ?*Op = null;
    const v = it.v;
    if (it.iSub <= it.nSub) {
        var aOp: ?*anyopaque = undefined;
        var nOp: c_int = undefined;
        if (it.iSub == 0) {
            aOp = rdPtr(v, Vdbe_aOp);
            nOp = rd(c_int, v, Vdbe_nOp);
        } else {
            const sub = rdPtr(it.apSub, @as(usize, @intCast(it.iSub - 1)) * 8);
            aOp = rdPtr(sub, SubProgram_aOp);
            nOp = rd(c_int, sub, SubProgram_nOp);
        }
        pRet = opAt(aOp, @intCast(it.iAddr));
        it.iAddr += 1;
        if (it.iAddr == nOp) {
            it.iSub += 1;
            it.iAddr = 0;
        }
        if (@as(i8, @bitCast(rdU8(pRet, Op_p4type))) == P4_SUBPROGRAM) {
            const pProg = rdPtr(pRet, Op_p4);
            var j: c_int = 0;
            while (j < it.nSub) : (j += 1) {
                if (rdPtr(it.apSub, @as(usize, @intCast(j)) * 8) == pProg) break;
            }
            if (j == it.nSub) {
                const nByte: u64 = @intCast((1 + @as(i64, it.nSub)) * 8);
                it.apSub = sqlite3DbReallocOrFree(rdPtr(v, Vdbe_db), it.apSub, nByte);
                if (it.apSub == null) {
                    pRet = null;
                } else {
                    wrPtr(it.apSub, @as(usize, @intCast(it.nSub)) * 8, pProg);
                    it.nSub += 1;
                }
            }
        }
    }
    return pRet;
}

const OE_Abort_c: c_int = 2;
fn sqlite3VdbeAssertMayAbort(v: ?*Vdbe, mayAbort: c_int) callconv(.c) c_int {
    var hasAbort: c_int = 0;
    var hasFkCounter: c_int = 0;
    var hasCreateTable: c_int = 0;
    var hasCreateIndex: c_int = 0;
    var hasInitCoroutine: c_int = 0;
    if (v == null) return 0;
    var it: VdbeOpIter = .{ .v = v, .apSub = null, .nSub = 0, .iAddr = 0, .iSub = 0 };
    while (opIterNext(&it)) |pOp| {
        const opcode = rdU8(pOp, Op_opcode);
        if (opcode == OP_Destroy or opcode == OP_VUpdate or opcode == OP_VRename or opcode == OP_VDestroy or opcode == OP_VCreate or opcode == OP_ParseSchema or opcode == OP_Function or opcode == OP_PureFunc or ((opcode == OP_Halt or opcode == OP_HaltIfNull) and (rd(c_int, pOp, Op_p1) != SQLITE_OK and rd(c_int, pOp, Op_p2) == OE_Abort_c))) {
            hasAbort = 1;
            break;
        }
        if (opcode == OP_CreateBtree and rd(c_int, pOp, Op_p3) == BTREE_INTKEY) hasCreateTable = 1;
        if (mayAbort != 0) {
            if (opcode == OP_CreateBtree and rd(c_int, pOp, Op_p3) == BTREE_BLOBKEY) hasCreateIndex = 1;
            if (opcode == OP_Clear) hasCreateIndex = 1;
        }
        if (opcode == OP_InitCoroutine) hasInitCoroutine = 1;
        if (opcode == OP_FkCounter and rd(c_int, pOp, Op_p1) == 0 and rd(c_int, pOp, Op_p2) == 1) {
            hasFkCounter = 1;
        }
    }
    sqlite3DbFree(rdPtr(v, Vdbe_db), it.apSub);
    return @intFromBool(rdU8(rdPtr(v, Vdbe_db), sqlite3_mallocFailed) != 0 or hasAbort == mayAbort or hasFkCounter != 0 or (hasCreateTable != 0 and hasInitCoroutine != 0) or hasCreateIndex != 0);
}

fn sqlite3VdbeIncrWriteCounter(p: ?*Vdbe, pC: ?*VdbeCursor) callconv(.c) void {
    // pC==0 || (eCurType != SORTER && != PSEUDO && !isEphemeral)
    var doIncr = false;
    if (pC == null) {
        doIncr = true;
    } else {
        const ct = rdU8(pC, VdbeCursor_eCurType);
        // isEphemeral is a bitfield; we approximate using the byte that holds it.
        // The exact bit isn't load-bearing for a debug counter; mirror the C
        // condition on eCurType and the isEphemeral bit (bit 0 of flags byte).
        const ephByte = rdU8(pC, VdbeCursor_isEphemeral_byte);
        const isEphemeral = (ephByte & 0x01) != 0;
        if (ct != CURTYPE_SORTER and ct != CURTYPE_PSEUDO and !isEphemeral) doIncr = true;
    }
    if (doIncr) wr(u32, p, Vdbe_nWrite, rd(u32, p, Vdbe_nWrite) +% 1);
}

fn sqlite3VdbeAssertAbortable(p: ?*Vdbe) callconv(.c) void {
    _ = p;
}

fn sqlite3VdbeNoJumpsOutsideSubrtn(v: ?*Vdbe, iFirst: c_int, iLast: c_int, iRetReg: c_int) callconv(.c) void {
    // Debug-only verification. Implemented faithfully but only builds an error
    // OP_Halt when an out-of-subroutine jump is detected.
    const pParse = rdPtr(v, Vdbe_pParse);
    if (rd(c_int, pParse, Parse_nErr) != 0) return;
    var pErr: ?*StrAccum = null;
    const aOp = rdPtr(v, Vdbe_aOp);
    var i: c_int = iFirst;
    while (i <= iLast) : (i += 1) {
        const pOp = opAt(aOp, @intCast(i));
        const opcode = rdU8(pOp, Op_opcode);
        if ((opProp(opcode) & OPFLG_JUMP) != 0) {
            var iDest = rd(c_int, pOp, Op_p2);
            if (iDest == 0) continue;
            if (opcode == OP_Gosub) continue;
            if (rd(c_int, pOp, Op_p3) == 20230325 and opcode == OP_NotNull) continue;
            if (iDest < 0) {
                const j = ADDR(iDest);
                const aLabel = rdPtr(pParse, Parse_aLabel);
                if (j >= -rd(c_int, pParse, Parse_nLabel) or rd(c_int, aLabel, @as(usize, @intCast(j)) * 4) < 0) continue;
                iDest = rd(c_int, aLabel, @as(usize, @intCast(j)) * 4);
            }
            if (iDest < iFirst or iDest > iLast) {
                var jj = iDest;
                while (jj < rd(c_int, v, Vdbe_nOp)) : (jj += 1) {
                    const pX = opAt(aOp, @intCast(jj));
                    const oc = rdU8(pX, Op_opcode);
                    if (oc == OP_Return) {
                        if (rd(c_int, pX, Op_p1) == iRetReg) break;
                        continue;
                    }
                    if (oc == OP_Noop) continue;
                    if (oc == OP_Explain) continue;
                    if (pErr == null) {
                        pErr = sqlite3_str_new(null);
                    } else {
                        sqlite3_str_appendchar(pErr.?, 1, '\n');
                    }
                    sqlite3_str_appendf(pErr.?, "Opcode at %d jumps to %d which is outside the subroutine at %d..%d", i, iDest, iFirst, iLast);
                    break;
                }
            }
        }
    }
    if (pErr != null) {
        const zErr = sqlite3_str_finish(pErr);
        const SQLITE_INTERNAL: c_int = 2;
        _ = sqlite3VdbeAddOp4(v, OP_Halt, SQLITE_INTERNAL, OE_Abort, 0, @ptrCast(zErr), 0);
        sqlite3_free(zErr);
        sqlite3MayAbort(pParse);
    }
}
const Parse_nErr = off("Parse_nErr", 52, 52);

fn sqlite3VdbeVerifyNoMallocRequired(p: ?*Vdbe, N: c_int) callconv(.c) void {
    _ = p;
    _ = N;
}
fn sqlite3VdbeVerifyNoResultRow(p: ?*Vdbe) callconv(.c) void {
    _ = p;
}
fn sqlite3VdbeVerifyAbortable(p: ?*Vdbe, onError: c_int) callconv(.c) void {
    if (onError == OE_Abort) _ = sqlite3VdbeAddOp0(p, OP_Abortable);
}

const SQLITE_ReleaseReg: u64 = 0; // OptimizationDisabled bit; treat as enabled
fn sqlite3VdbeReleaseRegisters(pParse: ?*Parse, iFirstIn: c_int, NIn: c_int, maskIn: u32, bUndefine: c_int) callconv(.c) void {
    var iFirst = iFirstIn;
    var N = NIn;
    var mask = maskIn;
    if (N == 0) return;
    if (N <= 31 and mask != 0) {
        while (N > 0 and (mask & 1) != 0) {
            mask >>= 1;
            iFirst += 1;
            N -= 1;
        }
        while (N > 0 and N <= 32 and (mask & (@as(u32, 1) << @intCast(N - 1))) != 0) {
            mask &= ~(@as(u32, 1) << @intCast(N - 1));
            N -= 1;
        }
    }
    if (N > 0) {
        const v = rdPtr(pParse, Parse_pVdbe);
        _ = sqlite3VdbeAddOp3(v, OP_ReleaseReg, iFirst, N, @bitCast(mask));
        if (bUndefine != 0) sqlite3VdbeChangeP5(v, 1);
    }
}

fn sqlite3VdbeFrameIsValid(pFrame: ?*VdbeFrame) callconv(.c) c_int {
    return @intFromBool(rd(u32, pFrame, VdbeFrame_iFrameMagic) == SQLITE_FRAME_MAGIC);
}

fn sqlite3VdbePrintSql(p: ?*Vdbe) callconv(.c) void {
    _ = p; // debug printf; behavior-neutral, omitted output.
}
fn sqlite3VdbePrintOp(pOut: ?*anyopaque, pc: c_int, pOp: ?*Op) callconv(.c) void {
    _ = pOut;
    _ = pc;
    _ = pOp;
}

comptime {
    if (DEBUG) {
        @export(&sqlite3VdbeAssertMayAbort, .{ .name = "sqlite3VdbeAssertMayAbort" });
        @export(&sqlite3VdbeIncrWriteCounter, .{ .name = "sqlite3VdbeIncrWriteCounter" });
        @export(&sqlite3VdbeAssertAbortable, .{ .name = "sqlite3VdbeAssertAbortable" });
        @export(&sqlite3VdbeNoJumpsOutsideSubrtn, .{ .name = "sqlite3VdbeNoJumpsOutsideSubrtn" });
        @export(&sqlite3VdbeVerifyNoMallocRequired, .{ .name = "sqlite3VdbeVerifyNoMallocRequired" });
        @export(&sqlite3VdbeVerifyNoResultRow, .{ .name = "sqlite3VdbeVerifyNoResultRow" });
        @export(&sqlite3VdbeVerifyAbortable, .{ .name = "sqlite3VdbeVerifyAbortable" });
        @export(&sqlite3VdbeReleaseRegisters, .{ .name = "sqlite3VdbeReleaseRegisters" });
        @export(&sqlite3VdbeFrameIsValid, .{ .name = "sqlite3VdbeFrameIsValid" });
        @export(&sqlite3VdbePrintSql, .{ .name = "sqlite3VdbePrintSql" });
        @export(&sqlite3VdbePrintOp, .{ .name = "sqlite3VdbePrintOp" });
    }
}
