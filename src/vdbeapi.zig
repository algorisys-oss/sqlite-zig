//! Zig port of SQLite's VDBE public API surface (src/vdbeapi.c).
//!
//! This is the outer-facing layer of the virtual machine: the functions an
//! application actually calls to drive a prepared statement.  It owns:
//!   * sqlite3_step()   — the schema-retry wrapper around sqlite3Step(), which
//!     in turn drives sqlite3VdbeExec() (the interpreter stays C in vdbe.c).
//!   * sqlite3_column_*  — pull values out of the current result row.
//!   * sqlite3_bind_*    — push values into host parameters before stepping.
//!   * sqlite3_value_*   — read accessors over a Mem/sqlite3_value (the subset
//!     that lives in vdbeapi.c, NOT the ones in vdbemem.c).
//!   * sqlite3_result_*  — the setters an application-defined SQL function uses
//!     to return its value via the sqlite3_context.
//!   * sqlite3_reset/finalize/clear_bindings — lifecycle.
//!   * sqlite3_stmt_*    — introspection (readonly/isexplain/busy/status/...).
//!   * the user-function context accessors (user_data, context_db_handle,
//!     aggregate_context, get/set_auxdata) and the ENABLE_PREUPDATE_HOOK and
//!     vtab_in / StmtCurrentTime helpers.
//!
//! ---------------------------------------------------------------------------
//! Config matrix (verified against build/gen make_tf.log + build.zig)
//! ---------------------------------------------------------------------------
//! Symbol set is IDENTICAL across the production `zig build` library and the
//! `--dev` testfixture:
//!   * SQLITE_ENABLE_PREUPDATE_HOOK ......... ON  in BOTH  → preupdate_* compiled
//!   * SQLITE_UNTESTABLE ................... OFF  in BOTH  → sqlite3ResultIntReal compiled
//!   * SQLITE_ENABLE_STMT_SCANSTATUS ....... OFF  in BOTH  → scanstatus_* NOT compiled
//!   * SQLITE_ENABLE_NORMALIZE ............. OFF  in BOTH  → normalized_sql NOT compiled
//!   * SQLITE_ENABLE_COLUMN_METADATA ...... OFF  in BOTH  → column_{db,table,origin}_name NOT compiled
//!   * SQLITE_ENABLE_API_ARMOR ............ OFF  in BOTH  → armor MISUSE branches dropped (as the C preprocessor does)
//!   * SQLITE_OMIT_{UTF16,TRACE,DEPRECATED,EXPLAIN,DECLTYPE,INCRBLOB} ... OFF → those paths live
//! Behavior-only divergences:
//!   * SQLITE_DEBUG ...... rcApp bookkeeping (result_error_code, sqlite3Step) — gated on config.sqlite_debug
//!   * SQLITE_STRICT_SUBTYPE ON in tf / OFF in prod — the result_subtype misuse
//!     guard.  We gate it on config.sqlite_debug as a proxy (the two flags move
//!     together across our two configs: tf has both, prod has neither).
//!
//! ---------------------------------------------------------------------------
//! Struct coupling
//! ---------------------------------------------------------------------------
//! Vdbe, Mem (== sqlite3_value), sqlite3, sqlite3_context, FuncDef, AuxData,
//! sqlite3_str, ValueList, PreUpdate are all read/written at ground-truth byte
//! offsets via c_layout (the `@hasDecl(L,...) else <probe>` idiom). The Vdbe
//! tail DIVERGES under SQLITE_DEBUG (rcApp/nWrite/napArg insert 12 bytes after
//! startTime), so every Vdbe field past startTime is config-selected. Mem and
//! sqlite3 and sqlite3_context offsets are config-invariant. All heavy lifting
//! (encoding conversion, Mem set/release, btree payload decode, the interpreter)
//! stays in already-linked C helpers.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ===========================================================================
// Opaque public handles
// ===========================================================================
const sqlite3 = anyopaque;
const sqlite3_stmt = anyopaque;
const sqlite3_value = anyopaque;
const sqlite3_context = anyopaque;
const sqlite3_str = anyopaque;
const Vdbe = anyopaque;
const Mem = anyopaque;
const FuncDef = anyopaque;
const BtCursor = anyopaque;

const XDelFn = ?*const fn (?*anyopaque) callconv(.c) void;

// ===========================================================================
// Result codes & constants (sqlite3.h, sqliteInt.h, vdbeInt.h)
// ===========================================================================
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_MISUSE: c_int = 21;
const SQLITE_RANGE: c_int = 25;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_TOOBIG: c_int = 18;
const SQLITE_SCHEMA: c_int = 17;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_BUSY: c_int = 5;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_CORRUPT: c_int = 11;

// datatype codes
const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;
const SQLITE_TEXT: c_int = 3;
const SQLITE_BLOB: c_int = 4;
const SQLITE_NULL: c_int = 5;

// preupdate / authorizer op codes
const SQLITE_INSERT: c_int = 18;
const SQLITE_UPDATE: c_int = 23;
const SQLITE_DELETE: c_int = 9;

// text encodings (sqlite3.h)
const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_UTF16BE: u8 = 3;
const SQLITE_UTF16: u8 = 4;
const SQLITE_UTF8_ZT: u8 = 16;
// x86-64 is little-endian → native UTF16 == LE.
const SQLITE_UTF16NATIVE: u8 = SQLITE_UTF16LE;

// sqlite3_str ownership transfer modes (sqlite3.h)
const SQLITE_COPY: c_int = 0;
const SQLITE_XFER: c_int = 1;
const SQLITE_FINISH: c_int = 2;

// Destructor sentinels: SQLITE_STATIC==0, SQLITE_TRANSIENT==(void*)-1,
// SQLITE_DYNAMIC==&sqlite3RowSetClear (an opaque function address).
const SQLITE_STATIC: XDelFn = null;
inline fn sqliteTransient() XDelFn {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
}

// sqlite3_stmt_status (sqlite3.h)
const SQLITE_STMTSTATUS_MEMUSED: c_int = 99;

// COLNAME_* (vdbe.h)
const COLNAME_NAME: c_int = 0;
const COLNAME_DECLTYPE: c_int = 1;

// VDBE state (vdbeInt.h)
const VDBE_READY_STATE: u8 = 1;
const VDBE_RUN_STATE: u8 = 2;
const VDBE_HALT_STATE: u8 = 3;

const SQLITE_MAX_SCHEMA_RETRY: c_int = 50;

// db->mTrace bits (sqlite3.h)
const SQLITE_TRACE_PROFILE: u32 = 0x02;
const SQLITE_TRACE_XPROFILE: u32 = 0x80;

// SQLITE_PREPARE_SAVESQL (sqlite3.h)
const SQLITE_PREPARE_SAVESQL: u8 = 0x80;

// MEM_* flags (vdbeInt.h)
const MEM_Null: u16 = 0x0001;
const MEM_Str: u16 = 0x0002;
const MEM_Int: u16 = 0x0004;
const MEM_Real: u16 = 0x0008;
const MEM_Blob: u16 = 0x0010;
const MEM_IntReal: u16 = 0x0020;
const MEM_AffMask: u16 = 0x003f;
const MEM_FromBind: u16 = 0x0040;
const MEM_Term: u16 = 0x0200;
const MEM_Zero: u16 = 0x0400;
const MEM_Subtype: u16 = 0x0800;
const MEM_TypeMask: u16 = 0x0dbf;
const MEM_Dyn: u16 = 0x1000;
const MEM_Static: u16 = 0x2000;
const MEM_Ephem: u16 = 0x4000;
const MEM_Agg: u16 = 0x8000;

// FuncDef.funcFlags (sqliteInt.h): SQLITE_RESULT_SUBTYPE.
const SQLITE_RESULT_SUBTYPE: u32 = 0x001000000;

// ===========================================================================
// Ground-truth offsets (c_layout fallback idiom; probed in both configs).
// ===========================================================================

// --- struct Mem (== sqlite3_value); CONFIG-INVARIANT for these fields ---
const sizeof_Mem: usize = L.sizeof_Mem; // 56 prod / 72 tf
const Mem_u: usize = 0; // union (r/i/nZero/zPType/pDef) at offset 0
const Mem_z: usize = if (@hasDecl(L, "sqlite3_value_z")) L.sqlite3_value_z else 8;
const Mem_n: usize = if (@hasDecl(L, "sqlite3_value_n")) L.sqlite3_value_n else 16;
const Mem_flags: usize = if (@hasDecl(L, "sqlite3_value_flags")) L.sqlite3_value_flags else 20;
const Mem_enc: usize = if (@hasDecl(L, "sqlite3_value_enc")) L.sqlite3_value_enc else 22;
const Mem_eSubtype: usize = if (@hasDecl(L, "sqlite3_value_eSubtype")) L.sqlite3_value_eSubtype else 23;
const Mem_db: usize = if (@hasDecl(L, "sqlite3_value_db")) L.sqlite3_value_db else 24;
// MEMCELLSIZE == offsetof(Mem,db).
const MEMCELLSIZE: usize = Mem_db;

// --- struct sqlite3 — all CONFIG-INVARIANT ---
const sqlite3_pVfs: usize = if (@hasDecl(L, "sqlite3_pVfs")) L.sqlite3_pVfs else 0;
const sqlite3_mutex: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const sqlite3_aDb: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_nDb: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_flags: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_errCode: usize = if (@hasDecl(L, "sqlite3_errCode")) L.sqlite3_errCode else 80;
const sqlite3_errMask: usize = if (@hasDecl(L, "sqlite3_errMask")) L.sqlite3_errMask else 88;
const sqlite3_enc: usize = if (@hasDecl(L, "sqlite3_enc")) L.sqlite3_enc else 100;
const sqlite3_autoCommit: usize = if (@hasDecl(L, "sqlite3_autoCommit")) L.sqlite3_autoCommit else 101;
const sqlite3_mallocFailed: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_mTrace: usize = if (@hasDecl(L, "sqlite3_mTrace")) L.sqlite3_mTrace else 110;
const sqlite3_aLimit: usize = if (@hasDecl(L, "sqlite3_aLimit")) L.sqlite3_aLimit else 136;
const sqlite3_init: usize = if (@hasDecl(L, "sqlite3_init")) L.sqlite3_init else 192;
const sqlite3_nVdbeActive: usize = if (@hasDecl(L, "sqlite3_nVdbeActive")) L.sqlite3_nVdbeActive else 208;
const sqlite3_nVdbeRead: usize = if (@hasDecl(L, "sqlite3_nVdbeRead")) L.sqlite3_nVdbeRead else 212;
const sqlite3_nVdbeWrite: usize = if (@hasDecl(L, "sqlite3_nVdbeWrite")) L.sqlite3_nVdbeWrite else 216;
const sqlite3_nVdbeExec: usize = if (@hasDecl(L, "sqlite3_nVdbeExec")) L.sqlite3_nVdbeExec else 220;
const sqlite3_pVdbe: usize = if (@hasDecl(L, "sqlite3_pVdbe")) L.sqlite3_pVdbe else 8;
const sqlite3_pErr: usize = if (@hasDecl(L, "sqlite3_pErr")) L.sqlite3_pErr else 416;
const sqlite3_u1: usize = if (@hasDecl(L, "sqlite3_u1")) L.sqlite3_u1 else 424;
const sqlite3_trace: usize = if (@hasDecl(L, "sqlite3_trace")) L.sqlite3_trace else 240;
const sqlite3_pTraceArg: usize = if (@hasDecl(L, "sqlite3_pTraceArg")) L.sqlite3_pTraceArg else 248;
const sqlite3_xProfile: usize = if (@hasDecl(L, "sqlite3_xProfile")) L.sqlite3_xProfile else 256;
const sqlite3_pProfileArg: usize = if (@hasDecl(L, "sqlite3_pProfileArg")) L.sqlite3_pProfileArg else 264;
const sqlite3_xWalCallback: usize = if (@hasDecl(L, "sqlite3_xWalCallback")) L.sqlite3_xWalCallback else 376;
const sqlite3_pWalArg: usize = if (@hasDecl(L, "sqlite3_pWalArg")) L.sqlite3_pWalArg else 384;
const sqlite3_nDeferredCons: usize = if (@hasDecl(L, "sqlite3_nDeferredCons")) L.sqlite3_nDeferredCons else 776;
const sqlite3_nDeferredImmCons: usize = if (@hasDecl(L, "sqlite3_nDeferredImmCons")) L.sqlite3_nDeferredImmCons else 784;
const sqlite3_pnBytesFreed: usize = if (@hasDecl(L, "sqlite3_pnBytesFreed")) L.sqlite3_pnBytesFreed else 792;
const sqlite3_lookaside: usize = if (@hasDecl(L, "sqlite3_lookaside")) L.sqlite3_lookaside else 432;
const sqlite3_xPreUpdateCallback: usize = if (@hasDecl(L, "sqlite3_xPreUpdateCallback")) L.sqlite3_xPreUpdateCallback else 360;
const sqlite3_pPreUpdate: usize = if (@hasDecl(L, "sqlite3_pPreUpdate")) L.sqlite3_pPreUpdate else 368;
// db->u1.isInterrupted (u1 union; AtomicStore writes an int here)
const sqlite3_isInterrupted: usize = sqlite3_u1;
// db->init.busy is a 1-bit bitfield in the byte at sqlite3.init (sqlite3InitInfo).
const sqlite3_initBusyByte: usize = sqlite3_init;
// SQLITE_LIMIT_LENGTH index into aLimit[].
const SQLITE_LIMIT_LENGTH: usize = 0;
// db->lookaside.pEnd / pStart / pTrueEnd — for SQLITE_STMTSTATUS_MEMUSED.
// Probed: lookaside@432, pStart@504, pEnd@512, pTrueEnd@520 (both configs).
const lookaside_pStart: usize = if (@hasDecl(L, "sqlite3_lookaside_pStart")) L.sqlite3_lookaside_pStart else sqlite3_lookaside + 72;
const lookaside_pEnd: usize = if (@hasDecl(L, "sqlite3_lookaside_pEnd")) L.sqlite3_lookaside_pEnd else sqlite3_lookaside + 80;
const lookaside_pTrueEnd: usize = if (@hasDecl(L, "sqlite3_lookaside_pTrueEnd")) L.sqlite3_lookaside_pTrueEnd else sqlite3_lookaside + 88;

// --- struct sqlite3_context — CONFIG-INVARIANT ---
const Ctx_pOut: usize = if (@hasDecl(L, "sqlite3_context_pOut")) L.sqlite3_context_pOut else 0;
const Ctx_pFunc: usize = if (@hasDecl(L, "sqlite3_context_pFunc")) L.sqlite3_context_pFunc else 8;
const Ctx_pMem: usize = if (@hasDecl(L, "sqlite3_context_pMem")) L.sqlite3_context_pMem else 16;
const Ctx_pVdbe: usize = if (@hasDecl(L, "sqlite3_context_pVdbe")) L.sqlite3_context_pVdbe else 24;
const Ctx_iOp: usize = if (@hasDecl(L, "sqlite3_context_iOp")) L.sqlite3_context_iOp else 32;
const Ctx_isError: usize = if (@hasDecl(L, "sqlite3_context_isError")) L.sqlite3_context_isError else 36;
const Ctx_enc: usize = if (@hasDecl(L, "sqlite3_context_enc")) L.sqlite3_context_enc else 40;

// --- struct FuncDef — CONFIG-INVARIANT ---
const FuncDef_funcFlags: usize = if (@hasDecl(L, "FuncDef_funcFlags")) L.FuncDef_funcFlags else 4;
const FuncDef_pUserData: usize = if (@hasDecl(L, "FuncDef_pUserData")) L.FuncDef_pUserData else 8;
const FuncDef_zName: usize = if (@hasDecl(L, "FuncDef_zName")) L.FuncDef_zName else 56;

// --- struct AuxData — CONFIG-INVARIANT (sizeof 32) ---
const sizeof_AuxData: usize = if (@hasDecl(L, "sizeof_AuxData")) L.sizeof_AuxData else 32;
const AuxData_iAuxOp: usize = if (@hasDecl(L, "AuxData_iAuxOp")) L.AuxData_iAuxOp else 0;
const AuxData_iAuxArg: usize = if (@hasDecl(L, "AuxData_iAuxArg")) L.AuxData_iAuxArg else 4;
const AuxData_pAux: usize = if (@hasDecl(L, "AuxData_pAux")) L.AuxData_pAux else 8;
const AuxData_xDeleteAux: usize = if (@hasDecl(L, "AuxData_xDeleteAux")) L.AuxData_xDeleteAux else 16;
const AuxData_pNextAux: usize = if (@hasDecl(L, "AuxData_pNextAux")) L.AuxData_pNextAux else 24;

// --- struct sqlite3_str — CONFIG-INVARIANT ---
const Str_db: usize = 0;
const Str_zText: usize = 8;
const Str_nAlloc: usize = 16;
const Str_mxAlloc: usize = 20;
const Str_nChar: usize = 24;
const Str_accError: usize = 28;
const Str_printfFlags: usize = 29;
const SQLITE_PRINTF_MALLOCED: u8 = 0x04;

// --- struct Vdbe — fields BEFORE the SQLITE_DEBUG tail are config-invariant;
//     fields AFTER startTime shift by 12 bytes under SQLITE_DEBUG. ---
const Vdbe_db: usize = if (@hasDecl(L, "Vdbe_db")) L.Vdbe_db else 0;
const Vdbe_pVNext: usize = if (@hasDecl(L, "Vdbe_pVNext")) L.Vdbe_pVNext else 16;
const Vdbe_nVar: usize = if (@hasDecl(L, "Vdbe_nVar")) L.Vdbe_nVar else 32;
const Vdbe_nMem: usize = if (@hasDecl(L, "Vdbe_nMem")) L.Vdbe_nMem else 36;
const Vdbe_pc: usize = if (@hasDecl(L, "Vdbe_pc")) L.Vdbe_pc else 48;
const Vdbe_rc: usize = if (@hasDecl(L, "Vdbe_rc")) L.Vdbe_rc else 52;
const Vdbe_iCurrentTime: usize = if (@hasDecl(L, "Vdbe_iCurrentTime")) L.Vdbe_iCurrentTime else 72;
const Vdbe_aMem: usize = if (@hasDecl(L, "Vdbe_aMem")) L.Vdbe_aMem else 104;
const Vdbe_apCsr: usize = if (@hasDecl(L, "Vdbe_apCsr")) L.Vdbe_apCsr else 120;
const Vdbe_aVar: usize = if (@hasDecl(L, "Vdbe_aVar")) L.Vdbe_aVar else 128;
const Vdbe_aOp: usize = if (@hasDecl(L, "Vdbe_aOp")) L.Vdbe_aOp else 136;
const Vdbe_nOp: usize = if (@hasDecl(L, "Vdbe_nOp")) L.Vdbe_nOp else 144;
const Vdbe_aColName: usize = if (@hasDecl(L, "Vdbe_aColName")) L.Vdbe_aColName else 152;
const Vdbe_pResultRow: usize = if (@hasDecl(L, "Vdbe_pResultRow")) L.Vdbe_pResultRow else 160;
const Vdbe_zErrMsg: usize = if (@hasDecl(L, "Vdbe_zErrMsg")) L.Vdbe_zErrMsg else 168;
const Vdbe_pVList: usize = if (@hasDecl(L, "Vdbe_pVList")) L.Vdbe_pVList else 176;
const Vdbe_startTime: usize = if (@hasDecl(L, "Vdbe_startTime")) L.Vdbe_startTime else 184;
// --- DIVERGENT tail (prod / tf) ---
const Vdbe_nResColumn: usize = if (@hasDecl(L, "Vdbe_nResColumn")) L.Vdbe_nResColumn else (if (config.sqlite_debug) 204 else 192);
const Vdbe_nResAlloc: usize = if (@hasDecl(L, "Vdbe_nResAlloc")) L.Vdbe_nResAlloc else (if (config.sqlite_debug) 206 else 194);
const Vdbe_errorAction: usize = if (@hasDecl(L, "Vdbe_errorAction")) L.Vdbe_errorAction else (if (config.sqlite_debug) 208 else 196);
const Vdbe_minWriteFileFormat: usize = if (@hasDecl(L, "Vdbe_minWriteFileFormat")) L.Vdbe_minWriteFileFormat else (if (config.sqlite_debug) 209 else 197);
const Vdbe_prepFlags: usize = if (@hasDecl(L, "Vdbe_prepFlags")) L.Vdbe_prepFlags else (if (config.sqlite_debug) 210 else 198);
const Vdbe_eVdbeState: usize = if (@hasDecl(L, "Vdbe_eVdbeState")) L.Vdbe_eVdbeState else (if (config.sqlite_debug) 211 else 199);
// the bitfield byte holding expired:2/explain:2/changeCntOn:1/usesStmtJournal:1/readOnly:1/bIsReader:1
const Vdbe_bits: usize = if (@hasDecl(L, "Vdbe_bits")) L.Vdbe_bits else (if (config.sqlite_debug) 212 else 200);
const Vdbe_expmask: usize = if (@hasDecl(L, "Vdbe_expmask")) L.Vdbe_expmask else (if (config.sqlite_debug) 300 else 284);
const Vdbe_aCounter: usize = if (@hasDecl(L, "Vdbe_aCounter")) L.Vdbe_aCounter else (if (config.sqlite_debug) 224 else 212);
const Vdbe_zSql: usize = if (@hasDecl(L, "Vdbe_zSql")) L.Vdbe_zSql else (if (config.sqlite_debug) 264 else 248);
const Vdbe_pAuxData: usize = if (@hasDecl(L, "Vdbe_pAuxData")) L.Vdbe_pAuxData else (if (config.sqlite_debug) 312 else 296);
const Vdbe_nFrame: usize = if (@hasDecl(L, "Vdbe_nFrame")) L.Vdbe_nFrame else (if (config.sqlite_debug) 296 else 280);
const Vdbe_pFrame: usize = if (@hasDecl(L, "Vdbe_pFrame")) L.Vdbe_pFrame else (if (config.sqlite_debug) 280 else 264);
// SQLITE_DEBUG-only field: Vdbe.rcApp (right after pVList, before nResColumn).
const Vdbe_rcApp: usize = if (@hasDecl(L, "Vdbe_rcApp")) L.Vdbe_rcApp else 192;

// Vdbe bitfield masks within Vdbe_bits.
const BIT_expired: u8 = 0x03; // bits 0-1
const BIT_explain_shift: u3 = 2; // bits 2-3 (value 0..2)
const BIT_explain_mask: u8 = 0x0c;
const BIT_readOnly: u8 = 0x40; // bit 6
const BIT_haveEqpOps: u8 = 0x01; // bit 0 of the NEXT byte

// --- struct ValueList — CONFIG-INVARIANT (pCsr@0, pOut@8) ---
const ValueList_pCsr: usize = 0;
const ValueList_pOut: usize = 8;

// ===========================================================================
// Typed field readers/writers over opaque base pointers.
// ===========================================================================
inline fn fieldPtr(comptime T: type, base: ?*const anyopaque, off: usize) *T {
    const p: [*]u8 = @ptrFromInt(@intFromPtr(base.?) + off);
    return @ptrCast(@alignCast(p));
}
inline fn rdU8(base: ?*const anyopaque, off: usize) u8 {
    const p: [*]const u8 = @ptrCast(base.?);
    return p[off];
}
inline fn rdU16(base: ?*const anyopaque, off: usize) u16 {
    return fieldPtr(u16, base, off).*;
}
inline fn rdInt(base: ?*const anyopaque, off: usize) c_int {
    return fieldPtr(c_int, base, off).*;
}
inline fn rdU32(base: ?*const anyopaque, off: usize) u32 {
    return fieldPtr(u32, base, off).*;
}
inline fn rdU64(base: ?*const anyopaque, off: usize) u64 {
    return fieldPtr(u64, base, off).*;
}
inline fn rdI64(base: ?*const anyopaque, off: usize) i64 {
    return fieldPtr(i64, base, off).*;
}
inline fn rdPtr(base: ?*const anyopaque, off: usize) ?*anyopaque {
    return fieldPtr(?*anyopaque, base, off).*;
}
inline fn wrU8(base: ?*anyopaque, off: usize, v: u8) void {
    const p: [*]u8 = @ptrCast(base.?);
    p[off] = v;
}
inline fn wrU16(base: ?*anyopaque, off: usize, v: u16) void {
    fieldPtr(u16, base, off).* = v;
}
inline fn wrInt(base: ?*anyopaque, off: usize, v: c_int) void {
    fieldPtr(c_int, base, off).* = v;
}
inline fn wrU32(base: ?*anyopaque, off: usize, v: u32) void {
    fieldPtr(u32, base, off).* = v;
}
inline fn wrPtr(base: ?*anyopaque, off: usize, v: ?*anyopaque) void {
    fieldPtr(?*anyopaque, base, off).* = v;
}

// Mem cell pointer arithmetic: aMem[i] is i*sizeof_Mem past aMem.
inline fn memAt(base: ?*anyopaque, i: usize) ?*anyopaque {
    return @ptrFromInt(@intFromPtr(base.?) + i * sizeof_Mem);
}

// db pointer of a Mem.
inline fn memDb(pMem: ?*anyopaque) ?*anyopaque {
    return rdPtr(pMem, Mem_db);
}

// ===========================================================================
// External C symbols resolved at link time.
// ===========================================================================
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_malloc(n: c_int) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_str_value(p: ?*sqlite3_str) ?[*:0]u8;
extern fn sqlite3_str_reset(p: ?*sqlite3_str) void;
extern fn sqlite3_str_free(p: ?*sqlite3_str) void;

// VDBE/Mem internal helpers (vdbeInt.h / sqliteInt.h)
extern fn sqlite3VdbeExec(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeList(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeReset(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeRewind(p: ?*Vdbe) void;
extern fn sqlite3VdbeDelete(p: ?*Vdbe) void;
extern fn sqlite3VdbeTransferError(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeExpandSql(p: ?*Vdbe, zRawSql: [*:0]const u8) ?[*:0]u8;
extern fn sqlite3Reprepare(p: ?*Vdbe) c_int;
extern fn sqlite3ApiExit(db: ?*sqlite3, rc: c_int) c_int;
extern fn sqlite3LeaveMutexAndCloseZombie(db: ?*sqlite3) void;
extern fn sqlite3Error(db: ?*sqlite3, rc: c_int) void;
extern fn sqlite3OomFault(db: ?*sqlite3) ?*anyopaque;
extern fn sqlite3OomClear(db: ?*sqlite3) void;
extern fn sqlite3ErrStr(rc: c_int) ?[*:0]const u8;
extern fn sqlite3DbFree(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3DbStrDup(db: ?*sqlite3, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3StrAccumInit(p: ?*sqlite3_str, db: ?*sqlite3, zBase: ?[*]u8, n: c_int, mx: c_int) void;
extern fn sqlite3OsCurrentTimeInt64(pVfs: ?*anyopaque, piNow: *i64) c_int;

extern fn sqlite3VdbeMemSetStr(pMem: ?*Mem, z: ?[*]const u8, n: i64, enc: u8, xDel: XDelFn) c_int;
extern fn sqlite3VdbeMemSetText(pMem: ?*Mem, z: ?[*]const u8, n: i64, xDel: XDelFn) c_int;
extern fn sqlite3VdbeMemSetInt64(pMem: ?*Mem, val: i64) void;
extern fn sqlite3VdbeMemSetDouble(pMem: ?*Mem, val: f64) void;
extern fn sqlite3VdbeMemSetNull(pMem: ?*Mem) void;
extern fn sqlite3VdbeMemSetPointer(pMem: ?*Mem, pPtr: ?*anyopaque, zPType: ?[*:0]const u8, xDestructor: XDelFn) void;
extern fn sqlite3VdbeMemSetZeroBlob(pMem: ?*Mem, n: c_int) void;
extern fn sqlite3VdbeMemRelease(p: ?*Mem) void;
extern fn sqlite3VdbeMemCopy(pTo: ?*Mem, pFrom: ?*const Mem) c_int;
extern fn sqlite3VdbeMemMove(pTo: ?*Mem, pFrom: ?*Mem) void;
extern fn sqlite3VdbeMemMakeWriteable(pMem: ?*Mem) c_int;
extern fn sqlite3VdbeMemClearAndResize(pMem: ?*Mem, n: c_int) c_int;
extern fn sqlite3VdbeMemZeroTerminateIfAble(pMem: ?*Mem) c_int;
extern fn sqlite3VdbeMemExpandBlob(pMem: ?*Mem) c_int;
extern fn sqlite3VdbeMemRealify(pMem: ?*Mem) c_int;
extern fn sqlite3VdbeChangeEncoding(pMem: ?*Mem, desiredEnc: c_int) c_int;
extern fn sqlite3VdbeMemTooBig(p: ?*Mem) c_int;
extern fn sqlite3VdbeIntValue(pMem: ?*const Mem) i64;
extern fn sqlite3VdbeRealValue(pMem: ?*Mem) f64;
extern fn sqlite3ValueText(pVal: ?*sqlite3_value, enc: u8) ?*const anyopaque;
extern fn sqlite3ValueBytes(pVal: ?*sqlite3_value, enc: u8) c_int;
extern fn sqlite3ValueFree(v: ?*sqlite3_value) void;
extern fn sqlite3VListNumToName(pVList: ?*anyopaque, iVal: c_int) ?[*:0]const u8;
extern fn sqlite3VListNameToNum(pVList: ?*anyopaque, zName: [*:0]const u8, nName: c_int) c_int;
extern fn sqlite3DbMallocZero(db: ?*sqlite3, n: u64) ?*anyopaque;

// ValueList / btree helpers for sqlite3_vtab_in_*.
extern fn sqlite3BtreeNext(pCur: ?*BtCursor, flags: c_int) c_int;
extern fn sqlite3BtreeFirst(pCur: ?*BtCursor, pRes: *c_int) c_int;
extern fn sqlite3BtreeEof(pCur: ?*BtCursor) c_int;
extern fn sqlite3BtreePayloadSize(pCur: ?*BtCursor) u32;
extern fn sqlite3VdbeMemFromBtreeZeroOffset(pCur: ?*BtCursor, amt: u32, pMem: ?*Mem) c_int;
extern fn sqlite3GetVarint32(p: [*]const u8, v: *u32) u8;
extern fn sqlite3VdbeSerialGet(buf: [*]const u8, serial_type: u32, pMem: ?*Mem) u32;

// preupdate helpers (ENABLE_PREUPDATE_HOOK on in both configs).
extern fn sqlite3VdbeAllocUnpackedRecord(pKeyInfo: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeRecordUnpack(nKey: c_int, pKey: ?*const anyopaque, p: ?*anyopaque) void;
extern fn sqlite3TableColumnToIndex(pIdx: ?*anyopaque, iCol: i16) c_int;
extern fn sqlite3TableColumnToStorage(pTab: ?*anyopaque, iCol: i16) c_int;
extern fn sqlite3DbMallocRaw(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3BtreePayload(pCur: ?*BtCursor, offset: u32, amt: u32, pBuf: ?*anyopaque) c_int;
extern fn sqlite3ValueFromExpr(db: ?*sqlite3, pExpr: ?*anyopaque, enc: u8, aff: u8, ppVal: *?*sqlite3_value) c_int;

// xV2 trace callback signature.
const XTraceV2 = *const fn (u32, ?*anyopaque, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
const XProfile = *const fn (?*anyopaque, ?[*:0]const u8, i64) callconv(.c) void;
const XWalCallback = *const fn (?*anyopaque, ?*sqlite3, ?[*:0]const u8, c_int) callconv(.c) c_int;

// ===========================================================================
// Helper predicates
// ===========================================================================
inline fn isSaveSql(p: ?*Vdbe) bool {
    return (rdU8(p, Vdbe_prepFlags) & SQLITE_PREPARE_SAVESQL) != 0;
}

// ExpandBlob(P): if MEM_Zero set, expand; else SQLITE_OK.
inline fn expandBlob(p: ?*Mem) c_int {
    if ((rdU16(p, Mem_flags) & MEM_Zero) != 0) return sqlite3VdbeMemExpandBlob(p);
    return SQLITE_OK;
}

// ===========================================================================
// vdbeSafety / vdbeSafetyNotNull
// ===========================================================================
fn vdbeSafety(p: ?*Vdbe) c_int {
    if (rdPtr(p, Vdbe_db) == null) {
        sqlite3_log(SQLITE_MISUSE, "API called with finalized prepared statement");
        return 1;
    }
    return 0;
}
fn vdbeSafetyNotNull(p: ?*Vdbe) c_int {
    if (p == null) {
        sqlite3_log(SQLITE_MISUSE, "API called with NULL prepared statement");
        return 1;
    }
    return vdbeSafety(p);
}

// ===========================================================================
// sqlite3_expired (deprecated; OMIT_DEPRECATED off)
// ===========================================================================
export fn sqlite3_expired(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    if (p == null) return 1;
    return @intFromBool((rdU8(p, Vdbe_bits) & BIT_expired) != 0);
}

// ===========================================================================
// Profile callback (OMIT_TRACE off)
// ===========================================================================
fn invokeProfileCallback(db: ?*sqlite3, p: ?*Vdbe) void {
    var iNow: i64 = 0;
    _ = sqlite3OsCurrentTimeInt64(rdPtr(db, sqlite3_pVfs), &iNow);
    const iElapse: i64 = (iNow -% rdI64(p, Vdbe_startTime)) *% 1000000;
    // OMIT_DEPRECATED off: legacy xProfile.
    const xProfile = rdPtr(db, sqlite3_xProfile);
    if (xProfile != null) {
        const f: XProfile = @ptrCast(xProfile);
        f(rdPtr(db, sqlite3_pProfileArg), @ptrCast(rdPtr(p, Vdbe_zSql)), iElapse);
    }
    if ((rdU8(db, sqlite3_mTrace) & SQLITE_TRACE_PROFILE) != 0) {
        // db->trace is a union; trace.xV2 occupies the same slot.
        const xV2 = rdPtr(db, sqlite3_trace);
        if (xV2 != null) {
            const f: XTraceV2 = @ptrCast(xV2);
            var elapseCopy: i64 = iElapse;
            _ = f(SQLITE_TRACE_PROFILE, rdPtr(db, sqlite3_pTraceArg), p, &elapseCopy);
        }
    }
    wrU64(p, Vdbe_startTime, 0);
}
inline fn wrU64(base: ?*anyopaque, off: usize, v: u64) void {
    fieldPtr(u64, base, off).* = v;
}
inline fn checkProfileCallback(db: ?*sqlite3, p: ?*Vdbe) void {
    if (rdI64(p, Vdbe_startTime) > 0) invokeProfileCallback(db, p);
}

// ===========================================================================
// sqlite3_finalize
// ===========================================================================
export fn sqlite3_finalize(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    if (pStmt == null) return SQLITE_OK;
    const v: ?*Vdbe = pStmt;
    const db = rdPtr(v, Vdbe_db);
    if (vdbeSafety(v) != 0) return SQLITE_MISUSE;
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
    checkProfileCallback(db, v);
    var rc = sqlite3VdbeReset(v);
    sqlite3VdbeDelete(v);
    rc = sqlite3ApiExit(db, rc);
    sqlite3LeaveMutexAndCloseZombie(db);
    return rc;
}

// ===========================================================================
// sqlite3_reset
// ===========================================================================
export fn sqlite3_reset(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    if (pStmt == null) return SQLITE_OK;
    const v: ?*Vdbe = pStmt;
    const db = rdPtr(v, Vdbe_db);
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
    checkProfileCallback(db, v);
    var rc = sqlite3VdbeReset(v);
    sqlite3VdbeRewind(v);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return rc;
}

// ===========================================================================
// sqlite3_clear_bindings
// ===========================================================================
export fn sqlite3_clear_bindings(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    const db = rdPtr(p, Vdbe_db);
    const mutex = rdPtr(db, sqlite3_mutex);
    sqlite3_mutex_enter(mutex);
    const aVar = rdPtr(p, Vdbe_aVar);
    const nVar: c_int = rdU16(p, Vdbe_nVar);
    var i: usize = 0;
    while (i < @as(usize, @intCast(nVar))) : (i += 1) {
        const pVar = memAt(aVar, i);
        sqlite3VdbeMemRelease(pVar);
        wrU16(pVar, Mem_flags, MEM_Null);
    }
    if (rdU32(p, Vdbe_expmask) != 0) {
        wrU8(p, Vdbe_bits, rdU8(p, Vdbe_bits) | 0x01); // expired = 1 (bits 0-1)
    }
    sqlite3_mutex_leave(mutex);
    return SQLITE_OK;
}

// ===========================================================================
// sqlite3_value_*  (the subset defined in vdbeapi.c)
// ===========================================================================
export fn sqlite3_value_blob(pVal: ?*sqlite3_value) callconv(.c) ?*const anyopaque {
    const p: ?*Mem = pVal;
    if ((rdU16(p, Mem_flags) & (MEM_Blob | MEM_Str)) != 0) {
        if (expandBlob(p) != SQLITE_OK) return null;
        wrU16(p, Mem_flags, rdU16(p, Mem_flags) | MEM_Blob);
        return if (rdInt(p, Mem_n) != 0) rdPtr(p, Mem_z) else null;
    }
    return sqlite3_value_text(pVal);
}
export fn sqlite3_value_bytes(pVal: ?*sqlite3_value) callconv(.c) c_int {
    return sqlite3ValueBytes(pVal, SQLITE_UTF8);
}
export fn sqlite3_value_bytes16(pVal: ?*sqlite3_value) callconv(.c) c_int {
    return sqlite3ValueBytes(pVal, SQLITE_UTF16NATIVE);
}
export fn sqlite3_value_double(pVal: ?*sqlite3_value) callconv(.c) f64 {
    return sqlite3VdbeRealValue(@ptrCast(pVal));
}
export fn sqlite3_value_int(pVal: ?*sqlite3_value) callconv(.c) c_int {
    return @truncate(sqlite3VdbeIntValue(@ptrCast(pVal)));
}
export fn sqlite3_value_int64(pVal: ?*sqlite3_value) callconv(.c) i64 {
    return sqlite3VdbeIntValue(@ptrCast(pVal));
}
export fn sqlite3_value_subtype(pVal: ?*sqlite3_value) callconv(.c) c_uint {
    const p: ?*Mem = pVal;
    return if ((rdU16(p, Mem_flags) & MEM_Subtype) != 0) rdU8(p, Mem_eSubtype) else 0;
}
export fn sqlite3_value_pointer(pVal: ?*sqlite3_value, zPType: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const p: ?*Mem = pVal;
    const fl = rdU16(p, Mem_flags);
    if ((fl & (MEM_TypeMask | MEM_Term | MEM_Subtype)) == (MEM_Null | MEM_Term | MEM_Subtype) and
        zPType != null and
        rdU8(p, Mem_eSubtype) == 'p')
    {
        // p->u.zPType is the union member; strcmp(p->u.zPType, zPType)==0
        const zStored: ?[*:0]const u8 = @ptrCast(rdPtr(p, Mem_u));
        if (zStored != null and strEq(zStored.?, zPType.?)) {
            return rdPtr(p, Mem_z);
        }
    }
    return null;
}
inline fn strEq(a: [*:0]const u8, b: [*:0]const u8) bool {
    var i: usize = 0;
    while (true) : (i += 1) {
        if (a[i] != b[i]) return false;
        if (a[i] == 0) return true;
    }
}
export fn sqlite3_value_text(pVal: ?*sqlite3_value) callconv(.c) ?[*:0]const u8 {
    return @ptrCast(sqlite3ValueText(pVal, SQLITE_UTF8));
}
export fn sqlite3_value_text16(pVal: ?*sqlite3_value) callconv(.c) ?*const anyopaque {
    return sqlite3ValueText(pVal, SQLITE_UTF16NATIVE);
}
export fn sqlite3_value_text16be(pVal: ?*sqlite3_value) callconv(.c) ?*const anyopaque {
    return sqlite3ValueText(pVal, SQLITE_UTF16BE);
}
export fn sqlite3_value_text16le(pVal: ?*sqlite3_value) callconv(.c) ?*const anyopaque {
    return sqlite3ValueText(pVal, SQLITE_UTF16LE);
}

// type lookup table (vdbeapi.c aType[]).
const value_type_table = blk: {
    var t: [64]u8 = undefined;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const fl: u16 = @intCast(i);
        // Reproduce the C aType[] by the same decode the DEBUG assert uses.
        if ((fl & MEM_Null) != 0) {
            t[i] = @intCast(SQLITE_NULL);
        } else if ((fl & (MEM_Real | MEM_IntReal)) != 0) {
            t[i] = @intCast(SQLITE_FLOAT);
        } else if ((fl & MEM_Int) != 0) {
            t[i] = @intCast(SQLITE_INTEGER);
        } else if ((fl & MEM_Str) != 0) {
            t[i] = @intCast(SQLITE_TEXT);
        } else {
            t[i] = @intCast(SQLITE_BLOB);
        }
    }
    break :blk t;
};
export fn sqlite3_value_type(pVal: ?*sqlite3_value) callconv(.c) c_int {
    const fl = rdU16(pVal, Mem_flags) & MEM_AffMask;
    return value_type_table[fl];
}
export fn sqlite3_value_encoding(pVal: ?*sqlite3_value) callconv(.c) c_int {
    return rdU8(pVal, Mem_enc);
}
export fn sqlite3_value_nochange(pVal: ?*sqlite3_value) callconv(.c) c_int {
    return @intFromBool((rdU16(pVal, Mem_flags) & (MEM_Null | MEM_Zero)) == (MEM_Null | MEM_Zero));
}
export fn sqlite3_value_frombind(pVal: ?*sqlite3_value) callconv(.c) c_int {
    return @intFromBool((rdU16(pVal, Mem_flags) & MEM_FromBind) != 0);
}
export fn sqlite3_value_dup(pOrig: ?*const sqlite3_value) callconv(.c) ?*sqlite3_value {
    if (pOrig == null) return null;
    const pNew: ?*anyopaque = sqlite3_malloc(@intCast(sizeof_Mem));
    if (pNew == null) return null;
    // memset(pNew,0,sizeof) then memcpy(pNew,pOrig,MEMCELLSIZE)
    const dst: [*]u8 = @ptrCast(pNew.?);
    @memset(dst[0..sizeof_Mem], 0);
    const src: [*]const u8 = @ptrCast(pOrig.?);
    @memcpy(dst[0..MEMCELLSIZE], src[0..MEMCELLSIZE]);
    // pNew->flags &= ~MEM_Dyn; pNew->db = 0;
    wrU16(pNew, Mem_flags, rdU16(pNew, Mem_flags) & ~MEM_Dyn);
    wrPtr(pNew, Mem_db, null);
    const fl = rdU16(pNew, Mem_flags);
    if ((fl & (MEM_Str | MEM_Blob)) != 0) {
        wrU16(pNew, Mem_flags, (rdU16(pNew, Mem_flags) & ~(MEM_Static | MEM_Dyn)) | MEM_Ephem);
        if (sqlite3VdbeMemMakeWriteable(@ptrCast(pNew)) != SQLITE_OK) {
            sqlite3ValueFree(@ptrCast(pNew));
            return null;
        }
    } else if ((fl & MEM_Null) != 0) {
        wrU16(pNew, Mem_flags, rdU16(pNew, Mem_flags) & ~(MEM_Term | MEM_Subtype));
    }
    return @ptrCast(pNew);
}
export fn sqlite3_value_free(pOld: ?*sqlite3_value) callconv(.c) void {
    sqlite3ValueFree(pOld);
}

// ===========================================================================
// sqlite3_result_*  (setters via sqlite3_context)
// ===========================================================================
fn setResultStrOrError(pCtx: ?*sqlite3_context, z: ?[*]const u8, n: c_int, enc: u8, xDel: XDelFn) void {
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    var rc: c_int = undefined;
    if (enc == SQLITE_UTF8) {
        rc = sqlite3VdbeMemSetText(pOut, z, n, xDel);
    } else if (enc == SQLITE_UTF8_ZT) {
        rc = sqlite3VdbeMemSetText(pOut, z, n, xDel);
        wrU16(pOut, Mem_flags, rdU16(pOut, Mem_flags) | MEM_Term);
    } else {
        rc = sqlite3VdbeMemSetStr(pOut, z, n, enc, xDel);
    }
    if (rc != 0) {
        if (rc == SQLITE_TOOBIG) {
            sqlite3_result_error_toobig(pCtx);
        } else {
            sqlite3_result_error_nomem(pCtx);
        }
        return;
    }
    _ = sqlite3VdbeChangeEncoding(pOut, rdU8(pCtx, Ctx_enc));
    if (sqlite3VdbeMemTooBig(pOut) != 0) {
        sqlite3_result_error_toobig(pCtx);
    }
}
fn invokeValueDestructor(p: ?*const anyopaque, xDel: XDelFn, pCtx: ?*sqlite3_context) c_int {
    if (xDel == null) {
        // noop
    } else if (xDel == sqliteTransient()) {
        // noop
    } else {
        xDel.?(@constCast(p));
    }
    // API_ARMOR off: pCtx is non-null.
    sqlite3_result_error_toobig(pCtx);
    return SQLITE_TOOBIG;
}
export fn sqlite3_result_blob(pCtx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: XDelFn) callconv(.c) void {
    setResultStrOrError(pCtx, @ptrCast(z), n, 0, xDel);
}
export fn sqlite3_result_blob64(pCtx: ?*sqlite3_context, z: ?*const anyopaque, n: u64, xDel: XDelFn) callconv(.c) void {
    if (n > 0x7fffffff) {
        _ = invokeValueDestructor(z, xDel, pCtx);
    } else {
        setResultStrOrError(pCtx, @ptrCast(z), @intCast(n), 0, xDel);
    }
}
export fn sqlite3_result_double(pCtx: ?*sqlite3_context, rVal: f64) callconv(.c) void {
    sqlite3VdbeMemSetDouble(rdPtr(pCtx, Ctx_pOut), rVal);
}
export fn sqlite3_result_error(pCtx: ?*sqlite3_context, z: ?[*]const u8, n: c_int) callconv(.c) void {
    wrInt(pCtx, Ctx_isError, SQLITE_ERROR);
    _ = sqlite3VdbeMemSetStr(rdPtr(pCtx, Ctx_pOut), z, n, SQLITE_UTF8, sqliteTransient());
}
export fn sqlite3_result_error16(pCtx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int) callconv(.c) void {
    wrInt(pCtx, Ctx_isError, SQLITE_ERROR);
    _ = sqlite3VdbeMemSetStr(rdPtr(pCtx, Ctx_pOut), @ptrCast(z), n, SQLITE_UTF16NATIVE, sqliteTransient());
}
export fn sqlite3_result_int(pCtx: ?*sqlite3_context, iVal: c_int) callconv(.c) void {
    sqlite3VdbeMemSetInt64(rdPtr(pCtx, Ctx_pOut), iVal);
}
export fn sqlite3_result_int64(pCtx: ?*sqlite3_context, iVal: i64) callconv(.c) void {
    sqlite3VdbeMemSetInt64(rdPtr(pCtx, Ctx_pOut), iVal);
}
export fn sqlite3_result_null(pCtx: ?*sqlite3_context) callconv(.c) void {
    sqlite3VdbeMemSetNull(rdPtr(pCtx, Ctx_pOut));
}
export fn sqlite3_result_pointer(pCtx: ?*sqlite3_context, pPtr: ?*anyopaque, zPType: ?[*:0]const u8, xDestructor: XDelFn) callconv(.c) void {
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    sqlite3VdbeMemRelease(pOut);
    wrU16(pOut, Mem_flags, MEM_Null);
    sqlite3VdbeMemSetPointer(pOut, pPtr, zPType, xDestructor);
}
export fn sqlite3_result_subtype(pCtx: ?*sqlite3_context, eSubtype: c_uint) callconv(.c) void {
    // SQLITE_STRICT_SUBTYPE on in tf (== config.sqlite_debug here), off in prod.
    if (config.sqlite_debug) {
        const pFunc = rdPtr(pCtx, Ctx_pFunc);
        if (pFunc != null and (rdU32(pFunc, FuncDef_funcFlags) & SQLITE_RESULT_SUBTYPE) == 0) {
            // misuse of sqlite3_result_subtype() by <name>()
            sqlite3_result_error(pCtx, "misuse of sqlite3_result_subtype()", -1);
            return;
        }
    }
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    wrU8(pOut, Mem_eSubtype, @truncate(eSubtype & 0xff));
    wrU16(pOut, Mem_flags, rdU16(pOut, Mem_flags) | MEM_Subtype);
}
export fn sqlite3_result_text(pCtx: ?*sqlite3_context, z: ?[*]const u8, n: c_int, xDel: XDelFn) callconv(.c) void {
    setResultStrOrError(pCtx, z, n, SQLITE_UTF8, xDel);
}
export fn sqlite3_result_text64(pCtx: ?*sqlite3_context, z: ?[*]const u8, nIn: u64, xDel: XDelFn, encIn: u8) callconv(.c) void {
    var enc = encIn;
    var n = nIn;
    if (enc != SQLITE_UTF8 and enc != SQLITE_UTF8_ZT) {
        if (enc == SQLITE_UTF16) enc = SQLITE_UTF16NATIVE;
        n &= ~@as(u64, 1);
    }
    if (n > 0x7fffffff) {
        _ = invokeValueDestructor(z, xDel, pCtx);
    } else {
        setResultStrOrError(pCtx, z, @intCast(n), enc, xDel);
        _ = sqlite3VdbeMemZeroTerminateIfAble(rdPtr(pCtx, Ctx_pOut));
    }
}
export fn sqlite3_result_text16(pCtx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: XDelFn) callconv(.c) void {
    setResultStrOrError(pCtx, @ptrCast(z), n & ~@as(c_int, 1), SQLITE_UTF16NATIVE, xDel);
}
export fn sqlite3_result_text16be(pCtx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: XDelFn) callconv(.c) void {
    setResultStrOrError(pCtx, @ptrCast(z), n & ~@as(c_int, 1), SQLITE_UTF16BE, xDel);
}
export fn sqlite3_result_text16le(pCtx: ?*sqlite3_context, z: ?*const anyopaque, n: c_int, xDel: XDelFn) callconv(.c) void {
    setResultStrOrError(pCtx, @ptrCast(z), n & ~@as(c_int, 1), SQLITE_UTF16LE, xDel);
}
export fn sqlite3_result_value(pCtx: ?*sqlite3_context, pValue: ?*sqlite3_value) callconv(.c) void {
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    _ = sqlite3VdbeMemCopy(pOut, @ptrCast(pValue));
    _ = sqlite3VdbeChangeEncoding(pOut, rdU8(pCtx, Ctx_enc));
    if (sqlite3VdbeMemTooBig(pOut) != 0) {
        sqlite3_result_error_toobig(pCtx);
    }
}
export fn sqlite3_result_zeroblob(pCtx: ?*sqlite3_context, n: c_int) callconv(.c) void {
    _ = sqlite3_result_zeroblob64(pCtx, if (n > 0) @intCast(n) else 0);
}
export fn sqlite3_result_zeroblob64(pCtx: ?*sqlite3_context, n: u64) callconv(.c) c_int {
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    const db = memDb(pOut);
    // aLimit is int[]; element SQLITE_LIMIT_LENGTH at sqlite3_aLimit (4-byte stride).
    const limit: c_int = rdInt(db, sqlite3_aLimit + SQLITE_LIMIT_LENGTH * 4);
    if (n > @as(u64, @intCast(limit))) {
        sqlite3_result_error_toobig(pCtx);
        return SQLITE_TOOBIG;
    }
    // OMIT_INCRBLOB off.
    sqlite3VdbeMemSetZeroBlob(pOut, @intCast(n));
    return SQLITE_OK;
}
export fn sqlite3_result_error_code(pCtx: ?*sqlite3_context, errCode: c_int) callconv(.c) void {
    wrInt(pCtx, Ctx_isError, if (errCode != 0) errCode else -1);
    if (config.sqlite_debug) {
        const pVdbe = rdPtr(pCtx, Ctx_pVdbe);
        if (pVdbe != null) wrInt(pVdbe, Vdbe_rcApp, errCode);
    }
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    if ((rdU16(pOut, Mem_flags) & MEM_Null) != 0) {
        setResultStrOrError(pCtx, @ptrCast(sqlite3ErrStr(errCode)), -1, SQLITE_UTF8, SQLITE_STATIC);
    }
}
export fn sqlite3_result_error_toobig(pCtx: ?*sqlite3_context) callconv(.c) void {
    wrInt(pCtx, Ctx_isError, SQLITE_TOOBIG);
    _ = sqlite3VdbeMemSetStr(rdPtr(pCtx, Ctx_pOut), "string or blob too big", -1, SQLITE_UTF8, SQLITE_STATIC);
}
export fn sqlite3_result_error_nomem(pCtx: ?*sqlite3_context) callconv(.c) void {
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    sqlite3VdbeMemSetNull(pOut);
    wrInt(pCtx, Ctx_isError, SQLITE_NOMEM);
    _ = sqlite3OomFault(memDb(pOut));
}
export fn sqlite3_result_str(pCtx: ?*sqlite3_context, pStr: ?*sqlite3_str, eOwn: c_int) callconv(.c) void {
    const accError = rdU8(pStr, Str_accError);
    if (accError == 0) {
        if (rdU32(pStr, Str_nChar) == 0) {
            setResultStrOrError(pCtx, "", 0, SQLITE_UTF8_ZT, SQLITE_STATIC);
            if (eOwn != 0) sqlite3_str_reset(pStr);
        } else {
            const zText = sqlite3_str_value(pStr);
            if (eOwn == SQLITE_COPY) {
                setResultStrOrError(pCtx, @ptrCast(zText), @intCast(rdU32(pStr, Str_nChar)), SQLITE_UTF8, sqliteTransient());
            } else {
                setResultStrOrError(pCtx, @ptrCast(zText), @intCast(rdU32(pStr, Str_nChar)), SQLITE_UTF8_ZT, sqliteDynamic());
            }
        }
    } else if (accError == SQLITE_NOMEM) {
        sqlite3_result_error_nomem(pCtx);
    } else {
        sqlite3_result_error_toobig(pCtx);
    }
    if (eOwn != 0) {
        if (rdU8(pStr, Str_accError) == 0) {
            sqlite3StrAccumInit(pStr, @ptrCast(rdPtr(pStr, Str_db)), null, 0, @bitCast(rdU32(pStr, Str_mxAlloc)));
        }
        if (eOwn == SQLITE_FINISH) {
            sqlite3_str_free(pStr);
        }
    }
}
// SQLITE_DYNAMIC == &sqlite3RowSetClear (an opaque destructor address).
extern fn sqlite3RowSetClear(p: ?*anyopaque) void;
inline fn sqliteDynamic() XDelFn {
    return @ptrCast(&sqlite3RowSetClear);
}

// SQLITE_UNTESTABLE off → sqlite3ResultIntReal compiled.
export fn sqlite3ResultIntReal(pCtx: ?*sqlite3_context) callconv(.c) void {
    const pOut: ?*Mem = rdPtr(pCtx, Ctx_pOut);
    if ((rdU16(pOut, Mem_flags) & MEM_Int) != 0) {
        wrU16(pOut, Mem_flags, (rdU16(pOut, Mem_flags) & ~MEM_Int) | MEM_IntReal);
    }
}

// ===========================================================================
// doWalCallbacks (OMIT_WAL off)
// ===========================================================================
extern fn sqlite3BtreeEnter(p: ?*anyopaque) void;
extern fn sqlite3BtreeLeave(p: ?*anyopaque) void;
extern fn sqlite3PagerWalCallback(pPager: ?*anyopaque) c_int;
extern fn sqlite3BtreePager(p: ?*anyopaque) ?*anyopaque;
// Db struct: aDb[i] = { zDbSName, pBt, ... }; pBt@8, zDbSName@0, sizeof 32.
const Db_zDbSName: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pBt: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
inline fn dbEnt(db: ?*sqlite3, i: usize) ?*anyopaque {
    const aDb = rdPtr(db, sqlite3_aDb).?;
    return @ptrFromInt(@intFromPtr(aDb) + i * sizeof_Db);
}
fn doWalCallbacks(db: ?*sqlite3) c_int {
    var rc: c_int = SQLITE_OK;
    const nDb: c_int = rdInt(db, sqlite3_nDb);
    var i: usize = 0;
    while (i < @as(usize, @intCast(nDb))) : (i += 1) {
        const ent = dbEnt(db, i);
        const pBt = rdPtr(ent, Db_pBt);
        if (pBt != null) {
            sqlite3BtreeEnter(pBt);
            const nEntry = sqlite3PagerWalCallback(sqlite3BtreePager(pBt));
            sqlite3BtreeLeave(pBt);
            const xWal = rdPtr(db, sqlite3_xWalCallback);
            if (nEntry > 0 and xWal != null and rc == SQLITE_OK) {
                const f: XWalCallback = @ptrCast(xWal);
                rc = f(rdPtr(db, sqlite3_pWalArg), db, @ptrCast(rdPtr(ent, Db_zDbSName)), nEntry);
            }
        }
    }
    return rc;
}

// ===========================================================================
// sqlite3Step — the inner step loop.
// ===========================================================================
fn sqlite3Step(p: ?*Vdbe) c_int {
    const db = rdPtr(p, Vdbe_db);
    var rc: c_int = undefined;

    if (rdU8(p, Vdbe_eVdbeState) != VDBE_RUN_STATE) {
        restart_step: while (true) {
            const st = rdU8(p, Vdbe_eVdbeState);
            if (st == VDBE_READY_STATE) {
                if ((rdU8(p, Vdbe_bits) & BIT_expired) != 0) {
                    wrInt(p, Vdbe_rc, SQLITE_SCHEMA);
                    rc = SQLITE_ERROR;
                    if (isSaveSql(p)) {
                        rc = sqlite3VdbeTransferError(p);
                    }
                    return endOfStep(p, db, rc);
                }
                if (rdInt(db, sqlite3_nVdbeActive) == 0) {
                    // AtomicStore(&db->u1.isInterrupted, 0)
                    @atomicStore(c_int, fieldPtr(c_int, db, sqlite3_isInterrupted), 0, .seq_cst);
                }
                // OMIT_TRACE off: capture start time if profiling.
                if ((rdU8(db, sqlite3_mTrace) & (SQLITE_TRACE_PROFILE | SQLITE_TRACE_XPROFILE)) != 0 and
                    (rdU8(db, sqlite3_initBusyByte) & 0x01) == 0 and
                    rdPtr(p, Vdbe_zSql) != null)
                {
                    var t: i64 = 0;
                    _ = sqlite3OsCurrentTimeInt64(rdPtr(db, sqlite3_pVfs), &t);
                    wrU64(p, Vdbe_startTime, @bitCast(t));
                }
                wrInt(db, sqlite3_nVdbeActive, rdInt(db, sqlite3_nVdbeActive) + 1);
                if ((rdU8(p, Vdbe_bits) & BIT_readOnly) == 0) {
                    wrInt(db, sqlite3_nVdbeWrite, rdInt(db, sqlite3_nVdbeWrite) + 1);
                }
                if ((rdU8(p, Vdbe_bits) & 0x80) != 0) { // bIsReader is bit 7
                    wrInt(db, sqlite3_nVdbeRead, rdInt(db, sqlite3_nVdbeRead) + 1);
                }
                wrInt(p, Vdbe_pc, 0);
                wrU8(p, Vdbe_eVdbeState, VDBE_RUN_STATE);
                break :restart_step;
            } else {
                // VDBE_HALT_STATE — auto-reset (OMIT_AUTORESET off).
                _ = sqlite3_reset(p);
                continue :restart_step;
            }
        }
    }

    if (config.sqlite_debug) {
        wrInt(p, Vdbe_rcApp, SQLITE_OK);
    }
    // OMIT_EXPLAIN off.
    if ((rdU8(p, Vdbe_bits) & BIT_explain_mask) != 0) {
        rc = sqlite3VdbeList(p);
    } else {
        wrInt(db, sqlite3_nVdbeExec, rdInt(db, sqlite3_nVdbeExec) + 1);
        rc = sqlite3VdbeExec(p);
        wrInt(db, sqlite3_nVdbeExec, rdInt(db, sqlite3_nVdbeExec) - 1);
    }

    if (rc == SQLITE_ROW) {
        wrInt(db, sqlite3_errCode, SQLITE_ROW);
        return SQLITE_ROW;
    } else {
        checkProfileCallback(db, p);
        wrPtr(p, Vdbe_pResultRow, null);
        if (rc == SQLITE_DONE and rdU8(db, sqlite3_autoCommit) != 0) {
            wrInt(p, Vdbe_rc, doWalCallbacks(db));
            if (rdInt(p, Vdbe_rc) != SQLITE_OK) {
                rc = SQLITE_ERROR;
            }
        } else if (rc != SQLITE_DONE and isSaveSql(p)) {
            rc = sqlite3VdbeTransferError(p);
        }
    }

    wrInt(db, sqlite3_errCode, rc);
    if (SQLITE_NOMEM == sqlite3ApiExit(rdPtr(p, Vdbe_db), rdInt(p, Vdbe_rc))) {
        wrInt(p, Vdbe_rc, SQLITE_NOMEM);
        if (isSaveSql(p)) rc = rdInt(p, Vdbe_rc);
    }
    return endOfStep(p, db, rc);
}
inline fn endOfStep(p: ?*Vdbe, db: ?*anyopaque, rc: c_int) c_int {
    _ = p;
    return rc & rdInt(db, sqlite3_errMask);
}

// ===========================================================================
// sqlite3_step — outer wrapper with schema-retry.
// ===========================================================================
export fn sqlite3_step(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const v: ?*Vdbe = pStmt;
    var cnt: c_int = 0;
    if (vdbeSafetyNotNull(v) != 0) return SQLITE_MISUSE;
    const db = rdPtr(v, Vdbe_db);
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
    while (true) {
        rc = sqlite3Step(v);
        if (rc != SQLITE_SCHEMA or cnt >= SQLITE_MAX_SCHEMA_RETRY) break;
        cnt += 1;
        const savedPc = rdInt(v, Vdbe_pc);
        rc = sqlite3Reprepare(v);
        if (rc != SQLITE_OK) {
            const zErr: ?[*:0]const u8 = @ptrCast(sqlite3ValueText(rdPtr(db, sqlite3_pErr), SQLITE_UTF8));
            sqlite3DbFree(db, rdPtr(v, Vdbe_zErrMsg));
            if (rdU8(db, sqlite3_mallocFailed) == 0) {
                wrPtr(v, Vdbe_zErrMsg, sqlite3DbStrDup(db, zErr));
                rc = sqlite3ApiExit(db, rc);
                wrInt(v, Vdbe_rc, rc);
            } else {
                wrPtr(v, Vdbe_zErrMsg, null);
                rc = SQLITE_NOMEM;
                wrInt(v, Vdbe_rc, SQLITE_NOMEM);
            }
            break;
        }
        _ = sqlite3_reset(pStmt);
        if (savedPc >= 0) {
            wrU8(v, Vdbe_minWriteFileFormat, 254);
        }
    }
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return rc;
}

// ===========================================================================
// User-function context accessors
// ===========================================================================
export fn sqlite3_user_data(p: ?*sqlite3_context) callconv(.c) ?*anyopaque {
    return rdPtr(rdPtr(p, Ctx_pFunc), FuncDef_pUserData);
}
export fn sqlite3_context_db_handle(p: ?*sqlite3_context) callconv(.c) ?*sqlite3 {
    return memDb(rdPtr(p, Ctx_pOut));
}
export fn sqlite3_vtab_nochange(p: ?*sqlite3_context) callconv(.c) c_int {
    return sqlite3_value_nochange(rdPtr(p, Ctx_pOut));
}

// ===========================================================================
// ValueList destructor + sqlite3_vtab_in_first / _next
// ===========================================================================
export fn sqlite3VdbeValueListFree(pToDelete: ?*anyopaque) callconv(.c) void {
    sqlite3_free(pToDelete);
}
fn valueFromValueList(pVal: ?*sqlite3_value, ppOut: *?*sqlite3_value, bNext: c_int) c_int {
    var rc: c_int = undefined;
    ppOut.* = null;
    if (pVal == null) return SQLITE_MISUSE;
    const fl = rdU16(pVal, Mem_flags);
    const xDel = rdPtr(pVal, Mem_xDel);
    if ((fl & MEM_Dyn) == 0 or @intFromPtr(xDel) != @intFromPtr(&sqlite3VdbeValueListFree)) {
        return SQLITE_ERROR;
    }
    const pRhs = rdPtr(pVal, Mem_z); // (ValueList*)pVal->z
    const pCsr: ?*BtCursor = @ptrCast(rdPtr(pRhs, ValueList_pCsr));
    if (bNext != 0) {
        rc = sqlite3BtreeNext(pCsr, 0);
    } else {
        var dummy: c_int = 0;
        rc = sqlite3BtreeFirst(pCsr, &dummy);
        if (sqlite3BtreeEof(pCsr) != 0) rc = SQLITE_DONE;
    }
    if (rc == SQLITE_OK) {
        var sMem: [128]u8 align(8) = undefined; // >= sizeof(Mem) in both configs (72 max)
        @memset(sMem[0..sizeof_Mem], 0);
        const pMem: ?*Mem = @ptrCast(&sMem);
        const sz = sqlite3BtreePayloadSize(pCsr);
        rc = sqlite3VdbeMemFromBtreeZeroOffset(pCsr, sz, pMem);
        if (rc == SQLITE_OK) {
            const zBuf: [*]const u8 = @ptrCast(rdPtr(pMem, Mem_z).?);
            var iSerial: u32 = 0;
            const adv = sqlite3GetVarint32(zBuf + 1, &iSerial);
            const iOff: usize = 1 + adv;
            const pOut: ?*Mem = @ptrCast(rdPtr(pRhs, ValueList_pOut));
            _ = sqlite3VdbeSerialGet(zBuf + iOff, iSerial, pOut);
            wrU8(pOut, Mem_enc, rdU8(memDb(pOut), sqlite3_enc));
            if ((rdU16(pOut, Mem_flags) & MEM_Ephem) != 0 and sqlite3VdbeMemMakeWriteable(pOut) != 0) {
                rc = SQLITE_NOMEM;
            } else {
                ppOut.* = @ptrCast(pOut);
            }
        }
        sqlite3VdbeMemRelease(pMem);
    }
    return rc;
}
const Mem_xDel: usize = if (@hasDecl(L, "sqlite3_value_xDel")) L.sqlite3_value_xDel else 48;
export fn sqlite3_vtab_in_first(pVal: ?*sqlite3_value, ppOut: *?*sqlite3_value) callconv(.c) c_int {
    return valueFromValueList(pVal, ppOut, 0);
}
export fn sqlite3_vtab_in_next(pVal: ?*sqlite3_value, ppOut: *?*sqlite3_value) callconv(.c) c_int {
    return valueFromValueList(pVal, ppOut, 1);
}

// ===========================================================================
// sqlite3StmtCurrentTime  (ENABLE_STAT4 off in both configs)
// ===========================================================================
export fn sqlite3StmtCurrentTime(p: ?*sqlite3_context) callconv(.c) i64 {
    const pVdbe = rdPtr(p, Ctx_pVdbe);
    const piTime: *i64 = fieldPtr(i64, pVdbe, Vdbe_iCurrentTime);
    if (piTime.* == 0) {
        const rc = sqlite3OsCurrentTimeInt64(rdPtr(memDb(rdPtr(p, Ctx_pOut)), sqlite3_pVfs), piTime);
        if (rc != 0) piTime.* = 0;
    }
    return piTime.*;
}

// ===========================================================================
// aggregate context
// ===========================================================================
fn createAggContext(p: ?*sqlite3_context, nByte: c_int) ?*anyopaque {
    const pMem: ?*Mem = rdPtr(p, Ctx_pMem);
    if (nByte <= 0) {
        sqlite3VdbeMemSetNull(pMem);
        wrPtr(pMem, Mem_z, null);
    } else {
        _ = sqlite3VdbeMemClearAndResize(pMem, nByte);
        wrU16(pMem, Mem_flags, MEM_Agg);
        wrPtr(pMem, Mem_u, rdPtr(p, Ctx_pFunc)); // pMem->u.pDef = p->pFunc
        const z = rdPtr(pMem, Mem_z);
        if (z != null) {
            const zb: [*]u8 = @ptrCast(z.?);
            @memset(zb[0..@intCast(nByte)], 0);
        }
    }
    return rdPtr(pMem, Mem_z);
}
export fn sqlite3_aggregate_context(p: ?*sqlite3_context, nByte: c_int) callconv(.c) ?*anyopaque {
    const pMem: ?*Mem = rdPtr(p, Ctx_pMem);
    if ((rdU16(pMem, Mem_flags) & MEM_Agg) == 0) {
        return createAggContext(p, nByte);
    }
    return rdPtr(pMem, Mem_z);
}

// ===========================================================================
// get/set auxdata
// ===========================================================================
export fn sqlite3_get_auxdata(pCtx: ?*sqlite3_context, iArg: c_int) callconv(.c) ?*anyopaque {
    const pVdbe = rdPtr(pCtx, Ctx_pVdbe);
    const iOp = rdInt(pCtx, Ctx_iOp);
    var pAuxData = rdPtr(pVdbe, Vdbe_pAuxData);
    while (pAuxData != null) : (pAuxData = rdPtr(pAuxData, AuxData_pNextAux)) {
        if (rdInt(pAuxData, AuxData_iAuxArg) == iArg and
            (rdInt(pAuxData, AuxData_iAuxOp) == iOp or iArg < 0))
        {
            return rdPtr(pAuxData, AuxData_pAux);
        }
    }
    return null;
}
export fn sqlite3_set_auxdata(pCtx: ?*sqlite3_context, iArg: c_int, pAux: ?*anyopaque, xDelete: XDelFn) callconv(.c) void {
    const pVdbe = rdPtr(pCtx, Ctx_pVdbe);
    const iOp = rdInt(pCtx, Ctx_iOp);
    var pAuxData = rdPtr(pVdbe, Vdbe_pAuxData);
    while (pAuxData != null) : (pAuxData = rdPtr(pAuxData, AuxData_pNextAux)) {
        if (rdInt(pAuxData, AuxData_iAuxArg) == iArg and
            (rdInt(pAuxData, AuxData_iAuxOp) == iOp or iArg < 0))
        {
            break;
        }
    }
    if (pAuxData == null) {
        pAuxData = sqlite3DbMallocZero(rdPtr(pVdbe, Vdbe_db), sizeof_AuxData);
        if (pAuxData == null) {
            if (xDelete) |xd| xd(pAux);
            return;
        }
        wrInt(pAuxData, AuxData_iAuxOp, iOp);
        wrInt(pAuxData, AuxData_iAuxArg, iArg);
        wrPtr(pAuxData, AuxData_pNextAux, rdPtr(pVdbe, Vdbe_pAuxData));
        wrPtr(pVdbe, Vdbe_pAuxData, pAuxData);
        if (rdInt(pCtx, Ctx_isError) == 0) wrInt(pCtx, Ctx_isError, -1);
    } else {
        const xOld: XDelFn = @ptrCast(rdPtr(pAuxData, AuxData_xDeleteAux));
        if (xOld) |xd| xd(rdPtr(pAuxData, AuxData_pAux));
    }
    wrPtr(pAuxData, AuxData_pAux, pAux);
    fieldPtr(XDelFn, pAuxData, AuxData_xDeleteAux).* = xDelete;
}

// ===========================================================================
// sqlite3_aggregate_count (deprecated; OMIT_DEPRECATED off)
// ===========================================================================
export fn sqlite3_aggregate_count(p: ?*sqlite3_context) callconv(.c) c_int {
    return rdInt(rdPtr(p, Ctx_pMem), Mem_n);
}

// ===========================================================================
// column count / data count
// ===========================================================================
export fn sqlite3_column_count(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const pVm: ?*Vdbe = pStmt;
    if (pVm == null) return 0;
    return rdU16(pVm, Vdbe_nResColumn);
}
export fn sqlite3_data_count(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const pVm: ?*Vdbe = pStmt;
    if (pVm == null or rdPtr(pVm, Vdbe_pResultRow) == null) return 0;
    return rdU16(pVm, Vdbe_nResColumn);
}

// ===========================================================================
// columnNullValue / columnMem / columnMallocFailure
// ===========================================================================
// A static NULL Mem. flags = MEM_Null, everything else 0. Sized to the larger
// (tf) layout so the address is valid in both configs.
var nullMemStorage: [128]u8 align(8) = blk: {
    var s: [128]u8 = undefined;
    var i: usize = 0;
    while (i < 128) : (i += 1) s[i] = 0;
    // flags (u16) at Mem_flags = MEM_Null
    s[Mem_flags] = @truncate(MEM_Null & 0xff);
    s[Mem_flags + 1] = @truncate((MEM_Null >> 8) & 0xff);
    break :blk s;
};
inline fn columnNullValue() ?*Mem {
    return @ptrCast(&nullMemStorage);
}
fn columnMem(pStmt: ?*sqlite3_stmt, i: c_int) ?*Mem {
    const pVm: ?*Vdbe = pStmt;
    if (pVm == null) return columnNullValue();
    sqlite3_mutex_enter(rdPtr(rdPtr(pVm, Vdbe_db), sqlite3_mutex));
    const pResultRow = rdPtr(pVm, Vdbe_pResultRow);
    const nRes: c_int = rdU16(pVm, Vdbe_nResColumn);
    if (pResultRow != null and i < nRes and i >= 0) {
        return @ptrCast(memAt(pResultRow, @intCast(i)));
    }
    sqlite3Error(rdPtr(pVm, Vdbe_db), SQLITE_RANGE);
    return columnNullValue();
}
fn columnMallocFailure(pStmt: ?*sqlite3_stmt) void {
    const p: ?*Vdbe = pStmt;
    if (p != null) {
        const db = rdPtr(p, Vdbe_db);
        wrInt(p, Vdbe_rc, sqlite3ApiExit(db, rdInt(p, Vdbe_rc)));
        sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    }
}

// ===========================================================================
// sqlite3_column_*
// ===========================================================================
export fn sqlite3_column_blob(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) ?*const anyopaque {
    const val = sqlite3_value_blob(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_bytes(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) c_int {
    const val = sqlite3_value_bytes(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_bytes16(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) c_int {
    const val = sqlite3_value_bytes16(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_double(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) f64 {
    const val = sqlite3_value_double(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_int(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) c_int {
    const val = sqlite3_value_int(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_int64(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) i64 {
    const val = sqlite3_value_int64(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_text(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) ?[*:0]const u8 {
    const val = sqlite3_value_text(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_value(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) ?*sqlite3_value {
    const pOut = columnMem(pStmt, i);
    if ((rdU16(pOut, Mem_flags) & MEM_Static) != 0) {
        wrU16(pOut, Mem_flags, (rdU16(pOut, Mem_flags) & ~MEM_Static) | MEM_Ephem);
    }
    columnMallocFailure(pStmt);
    return @ptrCast(pOut);
}
export fn sqlite3_column_text16(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) ?*const anyopaque {
    const val = sqlite3_value_text16(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return val;
}
export fn sqlite3_column_type(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) c_int {
    const iType = sqlite3_value_type(columnMem(pStmt, i));
    columnMallocFailure(pStmt);
    return iType;
}

// ===========================================================================
// Column names (EXPLAIN / EQP support tables + columnName)
// ===========================================================================
const azExplainColNames8 = [_][*:0]const u8{
    "addr", "opcode", "p1",      "p2",     "p3", "p4", "p5", "comment",
    "id",   "parent", "notused", "detail",
};
const azExplainColNames16data = [_]u16{
    'a', 'd', 'd', 'r', 0,
    'o', 'p', 'c', 'o', 'd',
    'e', 0,   'p', '1', 0,
    'p', '2', 0,   'p', '3',
    0,   'p', '4', 0,   'p',
    '5', 0,   'c', 'o', 'm',
    'm', 'e', 'n', 't', 0,
    'i', 'd', 0,   'p', 'a',
    'r', 'e', 'n', 't', 0,
    'n', 'o', 't', 'u', 's',
    'e', 'd', 0,   'd', 'e',
    't', 'a', 'i', 'l', 0,
};
const iExplainColNames16 = [_]u8{ 0, 5, 12, 15, 18, 21, 24, 27, 35, 38, 45, 53 };

fn columnName(pStmt: ?*sqlite3_stmt, Nin: c_int, useUtf16: c_int, useType: c_int) ?*const anyopaque {
    if (Nin < 0) return null;
    var N = Nin;
    var ret: ?*const anyopaque = null;
    const p: ?*Vdbe = pStmt;
    const db = rdPtr(p, Vdbe_db);
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));

    const explain: u8 = (rdU8(p, Vdbe_bits) & BIT_explain_mask) >> BIT_explain_shift;
    if (explain != 0) {
        if (useType > 0) {
            sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
            return null;
        }
        const n: c_int = if (explain == 1) 8 else 4;
        if (N >= n) {
            sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
            return null;
        }
        const idx: usize = @intCast(N + 8 * @as(c_int, explain) - 8);
        if (useUtf16 != 0) {
            const i = iExplainColNames16[idx];
            ret = @ptrCast(&azExplainColNames16data[i]);
        } else {
            ret = @ptrCast(azExplainColNames8[idx]);
        }
        sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
        return ret;
    }

    const n: c_int = rdU16(p, Vdbe_nResColumn);
    if (N < n) {
        const prior_mallocFailed = rdU8(db, sqlite3_mallocFailed);
        N += useType * n;
        const aColName = rdPtr(p, Vdbe_aColName);
        const pName = memAt(aColName, @intCast(N));
        if (useUtf16 != 0) {
            ret = sqlite3ValueText(pName, SQLITE_UTF16NATIVE);
        } else {
            ret = sqlite3ValueText(pName, SQLITE_UTF8);
        }
        if (rdU8(db, sqlite3_mallocFailed) > prior_mallocFailed) {
            sqlite3OomClear(db);
            ret = null;
        }
    }
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return ret;
}
export fn sqlite3_column_name(pStmt: ?*sqlite3_stmt, N: c_int) callconv(.c) ?[*:0]const u8 {
    return @ptrCast(columnName(pStmt, N, 0, COLNAME_NAME));
}
export fn sqlite3_column_name16(pStmt: ?*sqlite3_stmt, N: c_int) callconv(.c) ?*const anyopaque {
    return columnName(pStmt, N, 1, COLNAME_NAME);
}
// OMIT_DECLTYPE off.
export fn sqlite3_column_decltype(pStmt: ?*sqlite3_stmt, N: c_int) callconv(.c) ?[*:0]const u8 {
    return @ptrCast(columnName(pStmt, N, 0, COLNAME_DECLTYPE));
}
export fn sqlite3_column_decltype16(pStmt: ?*sqlite3_stmt, N: c_int) callconv(.c) ?*const anyopaque {
    return columnName(pStmt, N, 1, COLNAME_DECLTYPE);
}

// ===========================================================================
// sqlite3_bind_*
// ===========================================================================
fn vdbeUnbind(p: ?*Vdbe, i: c_uint) c_int {
    if (vdbeSafetyNotNull(p) != 0) return SQLITE_MISUSE;
    sqlite3_mutex_enter(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
    const db = rdPtr(p, Vdbe_db);
    if (rdU8(p, Vdbe_eVdbeState) != VDBE_READY_STATE) {
        sqlite3Error(db, SQLITE_MISUSE);
        sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
        sqlite3_log(SQLITE_MISUSE, "bind on a busy prepared statement: [%s]", @as(?[*:0]const u8, @ptrCast(rdPtr(p, Vdbe_zSql))) orelse "");
        return SQLITE_MISUSE;
    }
    const nVar: c_uint = rdU16(p, Vdbe_nVar);
    if (i >= nVar) {
        sqlite3Error(db, SQLITE_RANGE);
        sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
        return SQLITE_RANGE;
    }
    const pVar = memAt(rdPtr(p, Vdbe_aVar), i);
    sqlite3VdbeMemRelease(pVar);
    wrU16(pVar, Mem_flags, MEM_Null);
    wrInt(db, sqlite3_errCode, SQLITE_OK);
    const expmask = rdU32(p, Vdbe_expmask);
    if (expmask != 0) {
        const bit: u32 = if (i >= 31) 0x80000000 else (@as(u32, 1) << @intCast(i));
        if ((expmask & bit) != 0) {
            wrU8(p, Vdbe_bits, (rdU8(p, Vdbe_bits) & ~BIT_expired) | 0x01);
        }
    }
    return SQLITE_OK;
}

fn bindText(pStmt: ?*sqlite3_stmt, i: c_int, zData: ?*const anyopaque, nData: i64, xDel: XDelFn, encoding: u8) c_int {
    const p: ?*Vdbe = pStmt;
    var rc = vdbeUnbind(p, @bitCast(i - 1));
    if (rc == SQLITE_OK) {
        const db = rdPtr(p, Vdbe_db);
        if (zData != null) {
            const pVar = memAt(rdPtr(p, Vdbe_aVar), @intCast(i - 1));
            if (encoding == SQLITE_UTF8) {
                rc = sqlite3VdbeMemSetText(pVar, @ptrCast(zData), nData, xDel);
            } else if (encoding == SQLITE_UTF8_ZT) {
                rc = sqlite3VdbeMemSetText(pVar, @ptrCast(zData), nData, xDel);
                wrU16(pVar, Mem_flags, rdU16(pVar, Mem_flags) | MEM_Term);
            } else {
                rc = sqlite3VdbeMemSetStr(pVar, @ptrCast(zData), nData, encoding, xDel);
                if (encoding == 0) wrU8(pVar, Mem_enc, rdU8(db, sqlite3_enc));
            }
            if (rc == SQLITE_OK and encoding != 0) {
                rc = sqlite3VdbeChangeEncoding(pVar, rdU8(db, sqlite3_enc));
            }
            if (rc != 0) {
                sqlite3Error(db, rc);
                rc = sqlite3ApiExit(db, rc);
            }
        }
        sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    } else if (xDel != SQLITE_STATIC and xDel != sqliteTransient()) {
        xDel.?(@constCast(zData));
    }
    return rc;
}

export fn sqlite3_bind_blob(pStmt: ?*sqlite3_stmt, i: c_int, zData: ?*const anyopaque, nData: c_int, xDel: XDelFn) callconv(.c) c_int {
    return bindText(pStmt, i, zData, nData, xDel, 0);
}
export fn sqlite3_bind_blob64(pStmt: ?*sqlite3_stmt, i: c_int, zData: ?*const anyopaque, nData: u64, xDel: XDelFn) callconv(.c) c_int {
    return bindText(pStmt, i, zData, @bitCast(nData), xDel, 0);
}
export fn sqlite3_bind_double(pStmt: ?*sqlite3_stmt, i: c_int, rValue: f64) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    const rc = vdbeUnbind(p, @bitCast(i - 1));
    if (rc == SQLITE_OK) {
        sqlite3VdbeMemSetDouble(memAt(rdPtr(p, Vdbe_aVar), @intCast(i - 1)), rValue);
        sqlite3_mutex_leave(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
    }
    return rc;
}
export fn sqlite3_bind_int(p: ?*sqlite3_stmt, i: c_int, iValue: c_int) callconv(.c) c_int {
    return sqlite3_bind_int64(p, i, iValue);
}
export fn sqlite3_bind_int64(pStmt: ?*sqlite3_stmt, i: c_int, iValue: i64) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    const rc = vdbeUnbind(p, @bitCast(i - 1));
    if (rc == SQLITE_OK) {
        sqlite3VdbeMemSetInt64(memAt(rdPtr(p, Vdbe_aVar), @intCast(i - 1)), iValue);
        sqlite3_mutex_leave(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
    }
    return rc;
}
export fn sqlite3_bind_null(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    const rc = vdbeUnbind(p, @bitCast(i - 1));
    if (rc == SQLITE_OK) {
        sqlite3_mutex_leave(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
    }
    return rc;
}
export fn sqlite3_bind_pointer(pStmt: ?*sqlite3_stmt, i: c_int, pPtr: ?*anyopaque, zPTtype: ?[*:0]const u8, xDestructor: XDelFn) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    const rc = vdbeUnbind(p, @bitCast(i - 1));
    if (rc == SQLITE_OK) {
        sqlite3VdbeMemSetPointer(memAt(rdPtr(p, Vdbe_aVar), @intCast(i - 1)), pPtr, zPTtype, xDestructor);
        sqlite3_mutex_leave(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
    } else if (xDestructor) |xd| {
        xd(pPtr);
    }
    return rc;
}
export fn sqlite3_bind_text(pStmt: ?*sqlite3_stmt, i: c_int, zData: ?[*]const u8, nData: c_int, xDel: XDelFn) callconv(.c) c_int {
    return bindText(pStmt, i, zData, nData, xDel, SQLITE_UTF8);
}
export fn sqlite3_bind_text64(pStmt: ?*sqlite3_stmt, i: c_int, zData: ?[*]const u8, nDataIn: u64, xDel: XDelFn, encIn: u8) callconv(.c) c_int {
    var enc = encIn;
    var nData = nDataIn;
    if (enc != SQLITE_UTF8 and enc != SQLITE_UTF8_ZT) {
        if (enc == SQLITE_UTF16) enc = SQLITE_UTF16NATIVE;
        nData &= ~@as(u64, 1);
    }
    return bindText(pStmt, i, zData, @bitCast(nData), xDel, enc);
}
export fn sqlite3_bind_text16(pStmt: ?*sqlite3_stmt, i: c_int, zData: ?*const anyopaque, n: c_int, xDel: XDelFn) callconv(.c) c_int {
    return bindText(pStmt, i, zData, @as(i64, n) & ~@as(i64, 1), xDel, SQLITE_UTF16NATIVE);
}
export fn sqlite3_bind_value(pStmt: ?*sqlite3_stmt, i: c_int, pValue: ?*const sqlite3_value) callconv(.c) c_int {
    var rc: c_int = undefined;
    switch (sqlite3_value_type(@constCast(pValue))) {
        SQLITE_INTEGER => {
            rc = sqlite3_bind_int64(pStmt, i, rdI64(pValue, Mem_u));
        },
        SQLITE_FLOAT => {
            const fl = rdU16(pValue, Mem_flags);
            const r: f64 = if ((fl & MEM_Real) != 0) @bitCast(rdU64(pValue, Mem_u)) else @floatFromInt(rdI64(pValue, Mem_u));
            rc = sqlite3_bind_double(pStmt, i, r);
        },
        SQLITE_BLOB => {
            if ((rdU16(pValue, Mem_flags) & MEM_Zero) != 0) {
                rc = sqlite3_bind_zeroblob(pStmt, i, rdInt(pValue, Mem_u)); // u.nZero
            } else {
                rc = sqlite3_bind_blob(pStmt, i, rdPtr(pValue, Mem_z), rdInt(pValue, Mem_n), sqliteTransient());
            }
        },
        SQLITE_TEXT => {
            rc = bindText(pStmt, i, rdPtr(pValue, Mem_z), rdInt(pValue, Mem_n), sqliteTransient(), rdU8(pValue, Mem_enc));
        },
        else => {
            rc = sqlite3_bind_null(pStmt, i);
        },
    }
    return rc;
}
export fn sqlite3_bind_zeroblob(pStmt: ?*sqlite3_stmt, i: c_int, n: c_int) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    const rc = vdbeUnbind(p, @bitCast(i - 1));
    if (rc == SQLITE_OK) {
        // OMIT_INCRBLOB off.
        sqlite3VdbeMemSetZeroBlob(memAt(rdPtr(p, Vdbe_aVar), @intCast(i - 1)), n);
        sqlite3_mutex_leave(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
    }
    return rc;
}
export fn sqlite3_bind_zeroblob64(pStmt: ?*sqlite3_stmt, i: c_int, n: u64) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    const db = rdPtr(p, Vdbe_db);
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
    var rc: c_int = undefined;
    const limit: c_int = rdInt(db, sqlite3_aLimit + SQLITE_LIMIT_LENGTH * 4);
    if (n > @as(u64, @intCast(limit))) {
        rc = SQLITE_TOOBIG;
    } else {
        rc = sqlite3_bind_zeroblob(pStmt, i, @intCast(n));
    }
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return rc;
}

export fn sqlite3_bind_parameter_count(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const p: ?*Vdbe = pStmt;
    return if (p != null) rdU16(p, Vdbe_nVar) else 0;
}
export fn sqlite3_bind_parameter_name(pStmt: ?*sqlite3_stmt, i: c_int) callconv(.c) ?[*:0]const u8 {
    const p: ?*Vdbe = pStmt;
    if (p == null) return null;
    return sqlite3VListNumToName(rdPtr(p, Vdbe_pVList), i);
}
export fn sqlite3VdbeParameterIndex(p: ?*Vdbe, zName: ?[*:0]const u8, nName: c_int) callconv(.c) c_int {
    if (p == null or zName == null) return 0;
    return sqlite3VListNameToNum(rdPtr(p, Vdbe_pVList), zName.?, nName);
}
export fn sqlite3_bind_parameter_index(pStmt: ?*sqlite3_stmt, zName: ?[*:0]const u8) callconv(.c) c_int {
    return sqlite3VdbeParameterIndex(pStmt, zName, sqlite3Strlen30(zName));
}

export fn sqlite3TransferBindings(pFromStmt: ?*sqlite3_stmt, pToStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const pFrom: ?*Vdbe = pFromStmt;
    const pTo: ?*Vdbe = pToStmt;
    sqlite3_mutex_enter(rdPtr(rdPtr(pTo, Vdbe_db), sqlite3_mutex));
    const nVar: c_int = rdU16(pFrom, Vdbe_nVar);
    var i: usize = 0;
    while (i < @as(usize, @intCast(nVar))) : (i += 1) {
        sqlite3VdbeMemMove(memAt(rdPtr(pTo, Vdbe_aVar), i), memAt(rdPtr(pFrom, Vdbe_aVar), i));
    }
    sqlite3_mutex_leave(rdPtr(rdPtr(pTo, Vdbe_db), sqlite3_mutex));
    return SQLITE_OK;
}
// deprecated (OMIT_DEPRECATED off)
export fn sqlite3_transfer_bindings(pFromStmt: ?*sqlite3_stmt, pToStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const pFrom: ?*Vdbe = pFromStmt;
    const pTo: ?*Vdbe = pToStmt;
    if (rdU16(pFrom, Vdbe_nVar) != rdU16(pTo, Vdbe_nVar)) return SQLITE_ERROR;
    if (rdU32(pTo, Vdbe_expmask) != 0) wrU8(pTo, Vdbe_bits, (rdU8(pTo, Vdbe_bits) & ~BIT_expired) | 0x01);
    if (rdU32(pFrom, Vdbe_expmask) != 0) wrU8(pFrom, Vdbe_bits, (rdU8(pFrom, Vdbe_bits) & ~BIT_expired) | 0x01);
    return sqlite3TransferBindings(pFromStmt, pToStmt);
}

// ===========================================================================
// stmt introspection
// ===========================================================================
export fn sqlite3_db_handle(pStmt: ?*sqlite3_stmt) callconv(.c) ?*sqlite3 {
    return if (pStmt != null) rdPtr(@as(?*Vdbe, pStmt), Vdbe_db) else null;
}
export fn sqlite3_stmt_readonly(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    if (pStmt == null) return 1;
    return @intFromBool((rdU8(@as(?*Vdbe, pStmt), Vdbe_bits) & BIT_readOnly) != 0);
}
export fn sqlite3_stmt_isexplain(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    if (pStmt == null) return 0;
    return (rdU8(@as(?*Vdbe, pStmt), Vdbe_bits) & BIT_explain_mask) >> BIT_explain_shift;
}
export fn sqlite3_stmt_explain(pStmt: ?*sqlite3_stmt, eMode: c_int) callconv(.c) c_int {
    const v: ?*Vdbe = pStmt;
    var rc: c_int = undefined;
    const db = rdPtr(v, Vdbe_db);
    sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
    const curExplain: c_int = (rdU8(v, Vdbe_bits) & BIT_explain_mask) >> BIT_explain_shift;
    if (curExplain == eMode) {
        rc = SQLITE_OK;
    } else if (eMode < 0 or eMode > 2) {
        rc = SQLITE_ERROR;
    } else if (!isSaveSql(v)) {
        rc = SQLITE_ERROR;
    } else if (rdU8(v, Vdbe_eVdbeState) != VDBE_READY_STATE) {
        rc = SQLITE_BUSY;
    } else if (rdInt(v, Vdbe_nMem) >= 10 and (eMode != 2 or (rdU8(v, Vdbe_bits + 1) & BIT_haveEqpOps) != 0)) {
        setExplain(v, @intCast(eMode));
        rc = SQLITE_OK;
    } else {
        setExplain(v, @intCast(eMode));
        rc = sqlite3Reprepare(v);
        setHaveEqp(v, eMode == 2);
    }
    const explainNow: u8 = (rdU8(v, Vdbe_bits) & BIT_explain_mask) >> BIT_explain_shift;
    if (explainNow != 0) {
        wrU16(v, Vdbe_nResColumn, @intCast(12 - 4 * @as(c_int, explainNow)));
    } else {
        wrU16(v, Vdbe_nResColumn, rdU16(v, Vdbe_nResAlloc));
    }
    sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    return rc;
}
inline fn setExplain(v: ?*Vdbe, eMode: u2) void {
    const cur = rdU8(v, Vdbe_bits) & ~BIT_explain_mask;
    wrU8(v, Vdbe_bits, cur | (@as(u8, eMode) << BIT_explain_shift));
}
inline fn setHaveEqp(v: ?*Vdbe, on: bool) void {
    const b = rdU8(v, Vdbe_bits + 1) & ~BIT_haveEqpOps;
    wrU8(v, Vdbe_bits + 1, b | (if (on) BIT_haveEqpOps else 0));
}
export fn sqlite3_stmt_busy(pStmt: ?*sqlite3_stmt) callconv(.c) c_int {
    const v: ?*Vdbe = pStmt;
    return @intFromBool(v != null and rdU8(v, Vdbe_eVdbeState) == VDBE_RUN_STATE);
}
export fn sqlite3_next_stmt(pDb: ?*sqlite3, pStmt: ?*sqlite3_stmt) callconv(.c) ?*sqlite3_stmt {
    sqlite3_mutex_enter(rdPtr(pDb, sqlite3_mutex));
    var pNext: ?*anyopaque = undefined;
    if (pStmt == null) {
        pNext = rdPtr(pDb, sqlite3_pVdbe);
    } else {
        pNext = rdPtr(@as(?*Vdbe, pStmt), Vdbe_pVNext);
    }
    sqlite3_mutex_leave(rdPtr(pDb, sqlite3_mutex));
    return @ptrCast(pNext);
}
export fn sqlite3_stmt_status(pStmt: ?*sqlite3_stmt, op: c_int, resetFlag: c_int) callconv(.c) c_int {
    const pVdbe: ?*Vdbe = pStmt;
    var v: u32 = undefined;
    if (op == SQLITE_STMTSTATUS_MEMUSED) {
        const db = rdPtr(pVdbe, Vdbe_db);
        sqlite3_mutex_enter(rdPtr(db, sqlite3_mutex));
        v = 0;
        wrPtr(db, sqlite3_pnBytesFreed, @ptrCast(&v));
        wrPtr(db, lookaside_pEnd, rdPtr(db, lookaside_pStart));
        sqlite3VdbeDelete(pVdbe);
        wrPtr(db, sqlite3_pnBytesFreed, null);
        wrPtr(db, lookaside_pEnd, rdPtr(db, lookaside_pTrueEnd));
        sqlite3_mutex_leave(rdPtr(db, sqlite3_mutex));
    } else {
        const aCounter: [*]u32 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pVdbe.?)) + Vdbe_aCounter));
        v = aCounter[@intCast(op)];
        if (resetFlag != 0) aCounter[@intCast(op)] = 0;
    }
    return @bitCast(v);
}
export fn sqlite3_sql(pStmt: ?*sqlite3_stmt) callconv(.c) ?[*:0]const u8 {
    const p: ?*Vdbe = pStmt;
    return if (p != null) @ptrCast(rdPtr(p, Vdbe_zSql)) else null;
}
export fn sqlite3_expanded_sql(pStmt: ?*sqlite3_stmt) callconv(.c) ?[*:0]u8 {
    // OMIT_TRACE off.
    var z: ?[*:0]u8 = null;
    const zSql = sqlite3_sql(pStmt);
    if (zSql) |zs| {
        const p: ?*Vdbe = pStmt;
        sqlite3_mutex_enter(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
        z = sqlite3VdbeExpandSql(p, zs);
        sqlite3_mutex_leave(rdPtr(rdPtr(p, Vdbe_db), sqlite3_mutex));
    }
    return z;
}

// ===========================================================================
// Pre-update hook (ENABLE_PREUPDATE_HOOK on in both configs)
// ===========================================================================
// PreUpdate field offsets (from probe: vdbeInt.h struct PreUpdate). These are
// config-invariant (all members before any DEBUG-only field).
const PU_v: usize = 0;
const PU_pCsr: usize = 8;
const PU_op: usize = 16;
const PU_aRecord: usize = 24;
const PU_pKeyinfo: usize = 32;
const PU_pUnpacked: usize = 40;
const PU_pNewUnpacked: usize = 48;
const PU_iNewReg: usize = 56;
const PU_iBlobWrite: usize = 60;
const PU_iKey1: usize = 64;
const PU_iKey2: usize = 72;
const PU_oldipk: usize = 80; // Mem (inline)
const PU_aNew: usize = 80 + sizeof_Mem; // Mem* after the inline Mem
const PU_pTab: usize = PU_aNew + 8;
const PU_pPk: usize = PU_aNew + 16;
const PU_apDflt: usize = PU_aNew + 24;

// Helpers reaching into Table/Column/KeyInfo/UnpackedRecord/VdbeCursor/Index.
const KeyInfo_nKeyField: usize = if (@hasDecl(L, "KeyInfo_nKeyField")) L.KeyInfo_nKeyField else 6;
const Table_nCol: usize = if (@hasDecl(L, "Table_nCol")) L.Table_nCol else 54;
const Table_iPKey: usize = if (@hasDecl(L, "Table_iPKey")) L.Table_iPKey else 52;
const Table_aCol: usize = if (@hasDecl(L, "Table_aCol")) L.Table_aCol else 8;
const Table_u: usize = if (@hasDecl(L, "Table_u")) L.Table_u else 64;
const sizeof_Column: usize = if (@hasDecl(L, "sizeof_Column")) L.sizeof_Column else 16;
const Column_affinity: usize = if (@hasDecl(L, "Column_affinity")) L.Column_affinity else 9;
const Column_iDflt: usize = if (@hasDecl(L, "Column_iDflt")) L.Column_iDflt else 12;
const UnpackedRecord_nField: usize = if (@hasDecl(L, "UnpackedRecord_nField")) L.UnpackedRecord_nField else 28;
const UnpackedRecord_aMem: usize = if (@hasDecl(L, "UnpackedRecord_aMem")) L.UnpackedRecord_aMem else 8;
const VdbeCursor_nField: usize = if (@hasDecl(L, "VdbeCursor_nField")) L.VdbeCursor_nField else (if (config.sqlite_debug) 72 else 64);
const SQLITE_AFF_REAL: u8 = 0x45;

inline fn tableColAt(pTab: ?*anyopaque, iCol: c_int) ?*anyopaque {
    const aCol = rdPtr(pTab, Table_aCol).?;
    return @ptrFromInt(@intFromPtr(aCol) + @as(usize, @intCast(iCol)) * sizeof_Column);
}
inline fn unpackedMemAt(pUnpacked: ?*anyopaque, i: c_int) ?*anyopaque {
    const aMem = rdPtr(pUnpacked, UnpackedRecord_aMem).?;
    return @ptrFromInt(@intFromPtr(aMem) + @as(usize, @intCast(i)) * sizeof_Mem);
}

fn vdbeUnpackRecord(pKeyInfo: ?*anyopaque, nKey: c_int, pKey: ?*const anyopaque) ?*anyopaque {
    const pRet = sqlite3VdbeAllocUnpackedRecord(pKeyInfo);
    if (pRet != null) {
        const nKeyField: c_int = rdU16(pKeyInfo, KeyInfo_nKeyField);
        const aMem = rdPtr(pRet, UnpackedRecord_aMem).?;
        const bytes: usize = sizeof_Mem * @as(usize, @intCast(nKeyField + 1));
        const ab: [*]u8 = @ptrCast(aMem);
        @memset(ab[0..bytes], 0);
        sqlite3VdbeRecordUnpack(nKey, pKey, pRet);
    }
    return pRet;
}

export fn sqlite3_preupdate_old(db: ?*sqlite3, iIdx: c_int, ppValue: *?*sqlite3_value) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var iStore: c_int = 0;
    const p = rdPtr(db, sqlite3_pPreUpdate);
    if (p == null or rdInt(p, PU_op) == SQLITE_INSERT) {
        rc = SQLITE_MISUSE;
        return finishPreupdate(db, rc);
    }
    const pTab = rdPtr(p, PU_pTab);
    const pPk = rdPtr(p, PU_pPk);
    if (pPk != null) {
        iStore = sqlite3TableColumnToIndex(pPk, @intCast(iIdx));
    } else if (iIdx >= @as(c_int, rdU16(pTab, Table_nCol))) {
        rc = SQLITE_MISUSE;
        return finishPreupdate(db, rc);
    } else {
        iStore = sqlite3TableColumnToStorage(pTab, @intCast(iIdx));
    }
    const pCsr = rdPtr(p, PU_pCsr);
    if (iStore >= rdInt(pCsr, VdbeCursor_nField) or iStore < 0) {
        rc = SQLITE_RANGE;
        return finishPreupdate(db, rc);
    }

    if (iIdx == rdInt(pTab, Table_iPKey)) {
        const pMem: ?*Mem = @ptrFromInt(@intFromPtr(p.?) + PU_oldipk);
        ppValue.* = @ptrCast(pMem);
        sqlite3VdbeMemSetInt64(pMem, rdI64(p, PU_iKey1));
    } else {
        if (rdPtr(p, PU_pUnpacked) == null) {
            const pc = rdPtr(p, PU_pCsr);
            const nRec = sqlite3BtreePayloadSize(@ptrCast(rdPtr(pc, VdbeCursor_uc)));
            const aRec = sqlite3DbMallocRaw(db, nRec);
            if (aRec == null) return finishPreupdate(db, rc);
            rc = sqlite3BtreePayload(@ptrCast(rdPtr(pc, VdbeCursor_uc)), 0, nRec, aRec);
            if (rc == SQLITE_OK) {
                const up = vdbeUnpackRecord(rdPtr(p, PU_pKeyinfo), @bitCast(nRec), aRec);
                wrPtr(p, PU_pUnpacked, up);
                if (up == null) rc = SQLITE_NOMEM;
            }
            if (rc != SQLITE_OK) {
                sqlite3DbFree(db, aRec);
                return finishPreupdate(db, rc);
            }
            wrPtr(p, PU_aRecord, aRec);
        }
        const pUnpacked = rdPtr(p, PU_pUnpacked);
        var pMem = unpackedMemAt(pUnpacked, iStore);
        ppValue.* = @ptrCast(pMem);
        if (iStore >= rdInt(pUnpacked, UnpackedRecord_nField)) {
            const pCol = tableColAt(pTab, iIdx);
            if (rdU16(pCol, Column_iDflt) > 0) {
                if (rdPtr(p, PU_apDflt) == null) {
                    const nByte: u64 = 8 * @as(u64, @intCast(rdU16(pTab, Table_nCol)));
                    const apDflt = sqlite3DbMallocZero(db, nByte);
                    wrPtr(p, PU_apDflt, apDflt);
                    if (apDflt == null) return finishPreupdate(db, rc);
                }
                const apDflt: [*]?*sqlite3_value = @ptrCast(@alignCast(rdPtr(p, PU_apDflt).?));
                if (apDflt[@intCast(iIdx)] == null) {
                    var pVal: ?*sqlite3_value = null;
                    // pTab->u.tab.pDfltList->a[pCol->iDflt-1].pExpr
                    const pDflt = dfltExpr(pTab, rdU16(pCol, Column_iDflt));
                    rc = sqlite3ValueFromExpr(db, pDflt, rdU8(db, sqlite3_enc), rdU8(pCol, Column_affinity), &pVal);
                    if (rc == SQLITE_OK and pVal == null) rc = SQLITE_CORRUPT;
                    apDflt[@intCast(iIdx)] = pVal;
                }
                ppValue.* = apDflt[@intCast(iIdx)];
            } else {
                ppValue.* = @ptrCast(columnNullValue());
            }
        } else if (rdU8(tableColAt(pTab, iIdx), Column_affinity) == SQLITE_AFF_REAL) {
            if ((rdU16(pMem, Mem_flags) & (MEM_Int | MEM_IntReal)) != 0) {
                _ = sqlite3VdbeMemRealify(pMem);
            }
        }
        _ = &pMem;
    }
    return finishPreupdate(db, rc);
}
inline fn finishPreupdate(db: ?*sqlite3, rc: c_int) c_int {
    sqlite3Error(db, rc);
    return sqlite3ApiExit(db, rc);
}
// pTab->u.tab.pDfltList->a[iDflt-1].pExpr
const VdbeCursor_uc: usize = if (@hasDecl(L, "VdbeCursor_uc")) L.VdbeCursor_uc else (if (config.sqlite_debug) 48 else 40);
const ExprList_item_pExpr: usize = if (@hasDecl(L, "ExprList_item_pExpr")) L.ExprList_item_pExpr else 0;
const sizeof_ExprList_item: usize = if (@hasDecl(L, "sizeof_ExprList_item")) L.sizeof_ExprList_item else 24;
const ExprList_a: usize = if (@hasDecl(L, "ExprList_a")) L.ExprList_a else 8;
// u.tab.pDfltList is the 4th member of struct {addColOffset(int); FKey*; ExprList*; ...}
const Table_u_tab_pDfltList: usize = if (@hasDecl(L, "Table_u_tab_pDfltList")) L.Table_u_tab_pDfltList else (Table_u + 16);
inline fn dfltExpr(pTab: ?*anyopaque, iDflt: u16) ?*anyopaque {
    const pList = rdPtr(pTab, Table_u_tab_pDfltList).?;
    const aBase: usize = @intFromPtr(pList) + ExprList_a;
    const itemBase: usize = aBase + @as(usize, iDflt - 1) * sizeof_ExprList_item;
    return rdPtr(@as(?*anyopaque, @ptrFromInt(itemBase)), ExprList_item_pExpr);
}

export fn sqlite3_preupdate_count(db: ?*sqlite3) callconv(.c) c_int {
    const p = rdPtr(db, sqlite3_pPreUpdate);
    return if (p != null) @as(c_int, rdU16(rdPtr(p, PU_pKeyinfo), KeyInfo_nKeyField)) else 0;
}
export fn sqlite3_preupdate_depth(db: ?*sqlite3) callconv(.c) c_int {
    const p = rdPtr(db, sqlite3_pPreUpdate);
    return if (p != null) rdInt(rdPtr(p, PU_v), Vdbe_nFrame) else 0;
}
export fn sqlite3_preupdate_blobwrite(db: ?*sqlite3) callconv(.c) c_int {
    const p = rdPtr(db, sqlite3_pPreUpdate);
    return if (p != null) rdInt(p, PU_iBlobWrite) else -1;
}
export fn sqlite3_preupdate_new(db: ?*sqlite3, iIdx: c_int, ppValue: *?*sqlite3_value) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var iStore: c_int = 0;
    const p = rdPtr(db, sqlite3_pPreUpdate);
    if (p == null or rdInt(p, PU_op) == SQLITE_DELETE) {
        rc = SQLITE_MISUSE;
        return finishPreupdate(db, rc);
    }
    const pTab = rdPtr(p, PU_pTab);
    const pPk = rdPtr(p, PU_pPk);
    if (pPk != null and rdInt(p, PU_op) != SQLITE_UPDATE) {
        iStore = sqlite3TableColumnToIndex(pPk, @intCast(iIdx));
    } else if (iIdx >= @as(c_int, rdU16(pTab, Table_nCol))) {
        return finishPreupdate(db, SQLITE_MISUSE);
    } else {
        iStore = sqlite3TableColumnToStorage(pTab, @intCast(iIdx));
    }
    const pCsr = rdPtr(p, PU_pCsr);
    if (iStore >= rdInt(pCsr, VdbeCursor_nField) or iStore < 0) {
        rc = SQLITE_RANGE;
        return finishPreupdate(db, rc);
    }
    var pMem: ?*Mem = undefined;
    if (rdInt(p, PU_op) == SQLITE_INSERT) {
        var pUnpack = rdPtr(p, PU_pNewUnpacked);
        if (pUnpack == null) {
            const v = rdPtr(p, PU_v);
            const pData = vdbeAMemAt(v, rdInt(p, PU_iNewReg));
            rc = expandBlob(pData);
            if (rc != SQLITE_OK) return finishPreupdate(db, rc);
            pUnpack = vdbeUnpackRecord(rdPtr(p, PU_pKeyinfo), rdInt(pData, Mem_n), rdPtr(pData, Mem_z));
            if (pUnpack == null) return finishPreupdate(db, SQLITE_NOMEM);
            wrPtr(p, PU_pNewUnpacked, pUnpack);
        }
        pMem = unpackedMemAt(pUnpack, iStore);
        if (iIdx == rdInt(pTab, Table_iPKey)) {
            sqlite3VdbeMemSetInt64(pMem, rdI64(p, PU_iKey2));
        } else if (iStore >= rdInt(pUnpack, UnpackedRecord_nField)) {
            pMem = columnNullValue();
        }
    } else {
        if (rdPtr(p, PU_aNew) == null) {
            const bytes: u64 = sizeof_Mem * @as(u64, @intCast(rdInt(pCsr, VdbeCursor_nField)));
            const aNew = sqlite3DbMallocZero(db, bytes);
            if (aNew == null) return finishPreupdate(db, SQLITE_NOMEM);
            wrPtr(p, PU_aNew, aNew);
        }
        pMem = @ptrFromInt(@intFromPtr(rdPtr(p, PU_aNew).?) + @as(usize, @intCast(iStore)) * sizeof_Mem);
        if (rdU16(pMem, Mem_flags) == 0) {
            if (iIdx == rdInt(pTab, Table_iPKey)) {
                sqlite3VdbeMemSetInt64(pMem, rdI64(p, PU_iKey2));
            } else {
                const v = rdPtr(p, PU_v);
                rc = sqlite3VdbeMemCopy(pMem, vdbeAMemAt(v, rdInt(p, PU_iNewReg) + 1 + iStore));
                if (rc != SQLITE_OK) return finishPreupdate(db, rc);
            }
        }
    }
    ppValue.* = @ptrCast(pMem);
    return finishPreupdate(db, rc);
}
inline fn vdbeAMemAt(v: ?*anyopaque, i: c_int) ?*Mem {
    const aMem = rdPtr(v, Vdbe_aMem).?;
    return @ptrFromInt(@intFromPtr(aMem) + @as(usize, @intCast(i)) * sizeof_Mem);
}

// ===========================================================================
// Reference unused constants so they document invariants.
// ===========================================================================
comptime {
    std.debug.assert(Ctx_pOut == 0);
    std.debug.assert(VDBE_HALT_STATE == 3);
    std.debug.assert(MEM_TypeMask != 0);
    std.debug.assert(SQLITE_LOCKED != 0);
    std.debug.assert(SQLITE_CORRUPT != 0);
    std.debug.assert(Mem_eSubtype != 0);
    std.debug.assert(sqlite3_nDeferredCons != 0);
    std.debug.assert(sqlite3_nDeferredImmCons != 0);
    std.debug.assert(sqlite3_xPreUpdateCallback != 0);
}
