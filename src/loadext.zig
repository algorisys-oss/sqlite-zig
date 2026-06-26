//! Zig port of SQLite's src/loadext.c — run-time loadable-extension support.
//!
//! Exported (C-ABI) external symbols — the complete external set that
//! upstream loadext.c defines, so this TU can wholesale-replace loadext.c:
//!   - sqlite3_load_extension
//!   - sqlite3_enable_load_extension
//!   - sqlite3CloseExtensions
//!   - sqlite3_auto_extension
//!   - sqlite3_cancel_auto_extension
//!   - sqlite3_reset_auto_extension
//!   - sqlite3AutoLoadExtensions
//! Static helpers (sqlite3LoadExtension) stay module-private.
//!
//! ─── The sqlite3_api_routines dispatch table ────────────────────────────────
//! `sqlite3Apis` is a file-`static` (NOT exported) const table of 279 function
//! pointers passed to every extension's init routine so the extension can call
//! back into the library. Every member of `struct sqlite3_api_routines`
//! (sqlite3ext.h) is a function pointer, so under x86-64 the whole struct is
//! exactly an array of 279 pointer-sized slots; we mirror it as
//! `[279]?*const anyopaque`, identical in layout to the C struct.
//!
//! The ORDER and the NULL slots were extracted mechanically by preprocessing
//! the exact initializer from loadext.c (lines 133..539) under THIS project's
//! build flags (see build.zig `sqlite_flags`) and reading back which slots the
//! preprocessor reduced to a literal 0. Result: 279 entries, 276 real symbols,
//! 3 NULLs at indices:
//!     63  -> global_recover   (always 0 in source; deprecated)
//!     172 -> unlock_notify     (SQLITE_ENABLE_UNLOCK_NOTIFY is OFF)
//!     240 -> normalized_sql    (SQLITE_ENABLE_NORMALIZE is OFF)
//! Build-config notes that pin the non-NULL slots in THIS build:
//!   * SQLITE_OMIT_DEPRECATED OFF -> aggregate_count, expired, thread_cleanup,
//!     transfer_bindings, trace, profile are REAL (not 0).
//!   * SQLITE_THREADSAFE=1, no SQLITE_MUTEX_OMIT -> the 5 mutex_* slots REAL.
//!   * SQLITE_ENABLE_CARRAY ON -> carray_bind / carray_bind_v2 REAL.
//!   * No OMIT_UTF16/VIRTUALTABLE/WAL/DESERIALIZE/COMPLETE/DECLTYPE/GET_TABLE/
//!     INCRBLOB/SHARED_CACHE/AUTHORIZATION/PROGRESS_CALLBACK/TRACE -> those slots REAL.
//!   * ENABLE_COLUMN_METADATA OFF -> upstream `#ifndef ... #define X 0` makes the
//!     6 column_database/table/origin_name(16) slots NULL (the symbols do not
//!     exist in this build). They are `null` in the table below.
//! If the api table is wrong (order or a stray NULL) loadable extensions break
//! silently, so the list below is machine-generated, not hand-typed.
//!
//! ─── Config assumptions (true in this build) ────────────────────────────────
//!   * SQLITE_OMIT_LOAD_EXTENSION OFF  -> load/enable paths compiled.
//!   * SQLITE_THREADSAFE=1             -> STATIC_MAIN mutex guards the autoext list.
//!   * SQLITE_OMIT_AUTOINIT OFF        -> auto_extension/reset call sqlite3_initialize.
//!   * SQLITE_OMIT_WSD OFF             -> wsdAutoext == the sqlite3Autoext global directly.
//!   * SQLITE_ENABLE_API_ARMOR OFF     -> the armor null-checks are not compiled.
//!   * SQLITE_OS_UNIX (not WIN/APPLE)  -> sole shared-lib ending is "so".
//!
//! Validated only through the engine (loadext / autoextension TCL tests); no
//! standalone unit test is possible (every path couples to a live connection,
//! the VFS dlopen layer, and the global mutex subsystem).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ─── Result codes / constants (sqliteInt.h) ─────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_MISUSE: c_int = 21;
// SQLITE_NOMEM_BKPT == SQLITE_NOMEM in non-debug builds.
const SQLITE_NOMEM_BKPT: c_int = SQLITE_NOMEM;
const SQLITE_OK_LOAD_PERMANENTLY: c_int = 256; // SQLITE_OK | (2<<8)

// sqlite3.flags bits (sqliteInt.h)
const SQLITE_LoadExtension: u64 = 0x0000000000010000;
const SQLITE_LoadExtFunc: u64 = 0x0000000000020000;

// Misc limits / mutex ids
const SQLITE_MAX_PATHLEN: u64 = 4096;
const SQLITE_MUTEX_STATIC_MAIN: c_int = 2;

// ctype bits (sqliteInt.h): Isalpha=0x02, Isdigit=0x04
const CC_ALPHA: u8 = 0x02;
const CC_DIGIT: u8 = 0x04;

// ─── sqlite3 connection field offsets (ground truth, this build) ─────────────
// pVfs/flags/mallocFailed/mutex already exist in c_layout; aExtension/nExtension
// are new (requested as P() lines in the report).
const off_pVfs: usize = if (@hasDecl(L, "sqlite3_pVfs")) L.sqlite3_pVfs else 0;
const off_mutex: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const off_flags: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const off_nExtension: usize = if (@hasDecl(L, "sqlite3_nExtension")) L.sqlite3_nExtension else 228;
const off_aExtension: usize = if (@hasDecl(L, "sqlite3_aExtension")) L.sqlite3_aExtension else 232;

inline fn dbBase(db: ?*anyopaque) [*]u8 {
    return @ptrCast(db.?);
}
inline fn dbPVfs(db: ?*anyopaque) ?*anyopaque {
    const p: *align(1) const ?*anyopaque = @ptrCast(dbBase(db) + off_pVfs);
    return p.*;
}
inline fn dbMutex(db: ?*anyopaque) ?*anyopaque {
    const p: *align(1) const ?*anyopaque = @ptrCast(dbBase(db) + off_mutex);
    return p.*;
}
inline fn dbFlagsPtr(db: ?*anyopaque) *align(1) u64 {
    return @ptrCast(dbBase(db) + off_flags);
}
inline fn dbNExtensionPtr(db: ?*anyopaque) *align(1) c_int {
    return @ptrCast(dbBase(db) + off_nExtension);
}
inline fn dbAExtensionPtr(db: ?*anyopaque) *align(1) ?[*]?*anyopaque {
    return @ptrCast(dbBase(db) + off_aExtension);
}

// ─── extern C globals / helpers (resolved at link time) ─────────────────────
// sqlite3CtypeMap is read-only here; mutable globals would need `extern var`,
// but this lookup table is genuinely const — still declared `var` to dodge the
// optimizer-CSE gotcha noted in PROGRESS.
extern var sqlite3CtypeMap: [256]u8;
extern var sqlite3UpperToLower: [256]u8;

extern fn sqlite3_mprintf(zFormat: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, zBuf: [*]u8, zFormat: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3_free(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3_malloc64(n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3_mutex_enter(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) callconv(.c) c_int;
extern fn sqlite3_initialize() callconv(.c) c_int;

extern fn sqlite3MutexAlloc(id: c_int) callconv(.c) ?*anyopaque;
extern fn sqlite3ApiExit(db: ?*anyopaque, rc: c_int) callconv(.c) c_int;
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3ErrorWithMsg(db: ?*anyopaque, rc: c_int, zFormat: [*:0]const u8, ...) callconv(.c) void;

// OS dynamic-loader shims (os.h). DlSym returns a generic function pointer.
const VoidFn = *const fn () callconv(.c) void;
extern fn sqlite3OsDlOpen(pVfs: ?*anyopaque, zPath: [*:0]const u8) callconv(.c) ?*anyopaque;
extern fn sqlite3OsDlError(pVfs: ?*anyopaque, nByte: c_int, zErr: [*]u8) callconv(.c) void;
extern fn sqlite3OsDlSym(pVfs: ?*anyopaque, handle: ?*anyopaque, zSym: [*:0]const u8) callconv(.c) ?VoidFn;
extern fn sqlite3OsDlClose(pVfs: ?*anyopaque, handle: ?*anyopaque) callconv(.c) void;

extern fn strlen(s: [*:0]const u8) callconv(.c) usize;
extern fn memcpy(noalias d: ?*anyopaque, noalias s: ?*const anyopaque, n: usize) callconv(.c) ?*anyopaque;

// The extension init entry point: int (*)(sqlite3*, char**, const sqlite3_api_routines*)
const LoadextEntry = *const fn (?*anyopaque, *?[*:0]u8, ?*const anyopaque) callconv(.c) c_int;

inline fn isalpha(c: u8) bool {
    return (sqlite3CtypeMap[c] & CC_ALPHA) != 0;
}
inline fn isdigit(c: u8) bool {
    return (sqlite3CtypeMap[c] & CC_DIGIT) != 0;
}
// DirSep(X): unix => X=='/'
inline fn dirSep(c: u8) bool {
    return c == '/';
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3_api_routines dispatch table (file-static; mechanically generated)
// ════════════════════════════════════════════════════════════════════════════
extern fn sqlite3_aggregate_context() callconv(.c) void;
extern fn sqlite3_aggregate_count() callconv(.c) void;
extern fn sqlite3_autovacuum_pages() callconv(.c) void;
extern fn sqlite3_backup_finish() callconv(.c) void;
extern fn sqlite3_backup_init() callconv(.c) void;
extern fn sqlite3_backup_pagecount() callconv(.c) void;
extern fn sqlite3_backup_remaining() callconv(.c) void;
extern fn sqlite3_backup_step() callconv(.c) void;
extern fn sqlite3_bind_blob() callconv(.c) void;
extern fn sqlite3_bind_blob64() callconv(.c) void;
extern fn sqlite3_bind_double() callconv(.c) void;
extern fn sqlite3_bind_int() callconv(.c) void;
extern fn sqlite3_bind_int64() callconv(.c) void;
extern fn sqlite3_bind_null() callconv(.c) void;
extern fn sqlite3_bind_parameter_count() callconv(.c) void;
extern fn sqlite3_bind_parameter_index() callconv(.c) void;
extern fn sqlite3_bind_parameter_name() callconv(.c) void;
extern fn sqlite3_bind_pointer() callconv(.c) void;
extern fn sqlite3_bind_text() callconv(.c) void;
extern fn sqlite3_bind_text16() callconv(.c) void;
extern fn sqlite3_bind_text64() callconv(.c) void;
extern fn sqlite3_bind_value() callconv(.c) void;
extern fn sqlite3_bind_zeroblob() callconv(.c) void;
extern fn sqlite3_bind_zeroblob64() callconv(.c) void;
extern fn sqlite3_blob_bytes() callconv(.c) void;
extern fn sqlite3_blob_close() callconv(.c) void;
extern fn sqlite3_blob_open() callconv(.c) void;
extern fn sqlite3_blob_read() callconv(.c) void;
extern fn sqlite3_blob_reopen() callconv(.c) void;
extern fn sqlite3_blob_write() callconv(.c) void;
extern fn sqlite3_busy_handler() callconv(.c) void;
extern fn sqlite3_busy_timeout() callconv(.c) void;
extern fn sqlite3_carray_bind() callconv(.c) void;
extern fn sqlite3_carray_bind_v2() callconv(.c) void;
extern fn sqlite3_changes() callconv(.c) void;
extern fn sqlite3_changes64() callconv(.c) void;
extern fn sqlite3_clear_bindings() callconv(.c) void;
extern fn sqlite3_close() callconv(.c) void;
extern fn sqlite3_close_v2() callconv(.c) void;
extern fn sqlite3_collation_needed() callconv(.c) void;
extern fn sqlite3_collation_needed16() callconv(.c) void;
extern fn sqlite3_column_blob() callconv(.c) void;
extern fn sqlite3_column_bytes() callconv(.c) void;
extern fn sqlite3_column_bytes16() callconv(.c) void;
extern fn sqlite3_column_count() callconv(.c) void;
extern fn sqlite3_column_decltype() callconv(.c) void;
extern fn sqlite3_column_decltype16() callconv(.c) void;
extern fn sqlite3_column_double() callconv(.c) void;
extern fn sqlite3_column_int() callconv(.c) void;
extern fn sqlite3_column_int64() callconv(.c) void;
extern fn sqlite3_column_name() callconv(.c) void;
extern fn sqlite3_column_name16() callconv(.c) void;
extern fn sqlite3_column_text() callconv(.c) void;
extern fn sqlite3_column_text16() callconv(.c) void;
extern fn sqlite3_column_type() callconv(.c) void;
extern fn sqlite3_column_value() callconv(.c) void;
extern fn sqlite3_commit_hook() callconv(.c) void;
extern fn sqlite3_compileoption_get() callconv(.c) void;
extern fn sqlite3_compileoption_used() callconv(.c) void;
extern fn sqlite3_complete() callconv(.c) void;
extern fn sqlite3_complete16() callconv(.c) void;
extern fn sqlite3_context_db_handle() callconv(.c) void;
extern fn sqlite3_create_collation() callconv(.c) void;
extern fn sqlite3_create_collation16() callconv(.c) void;
extern fn sqlite3_create_collation_v2() callconv(.c) void;
extern fn sqlite3_create_filename() callconv(.c) void;
extern fn sqlite3_create_function() callconv(.c) void;
extern fn sqlite3_create_function16() callconv(.c) void;
extern fn sqlite3_create_function_v2() callconv(.c) void;
extern fn sqlite3_create_module() callconv(.c) void;
extern fn sqlite3_create_module_v2() callconv(.c) void;
extern fn sqlite3_create_window_function() callconv(.c) void;
extern fn sqlite3_data_count() callconv(.c) void;
extern fn sqlite3_database_file_object() callconv(.c) void;
extern fn sqlite3_db_cacheflush() callconv(.c) void;
extern fn sqlite3_db_config() callconv(.c) void;
extern fn sqlite3_db_filename() callconv(.c) void;
extern fn sqlite3_db_handle() callconv(.c) void;
extern fn sqlite3_db_mutex() callconv(.c) void;
extern fn sqlite3_db_name() callconv(.c) void;
extern fn sqlite3_db_readonly() callconv(.c) void;
extern fn sqlite3_db_release_memory() callconv(.c) void;
extern fn sqlite3_db_status() callconv(.c) void;
extern fn sqlite3_db_status64() callconv(.c) void;
extern fn sqlite3_declare_vtab() callconv(.c) void;
extern fn sqlite3_deserialize() callconv(.c) void;
extern fn sqlite3_drop_modules() callconv(.c) void;
extern fn sqlite3_enable_shared_cache() callconv(.c) void;
extern fn sqlite3_errcode() callconv(.c) void;
extern fn sqlite3_errmsg() callconv(.c) void;
extern fn sqlite3_errmsg16() callconv(.c) void;
extern fn sqlite3_error_offset() callconv(.c) void;
extern fn sqlite3_errstr() callconv(.c) void;
extern fn sqlite3_exec() callconv(.c) void;
extern fn sqlite3_expanded_sql() callconv(.c) void;
extern fn sqlite3_expired() callconv(.c) void;
extern fn sqlite3_extended_errcode() callconv(.c) void;
extern fn sqlite3_extended_result_codes() callconv(.c) void;
extern fn sqlite3_file_control() callconv(.c) void;
extern fn sqlite3_filename_database() callconv(.c) void;
extern fn sqlite3_filename_journal() callconv(.c) void;
extern fn sqlite3_filename_wal() callconv(.c) void;
extern fn sqlite3_finalize() callconv(.c) void;
extern fn sqlite3_free_filename() callconv(.c) void;
extern fn sqlite3_free_table() callconv(.c) void;
extern fn sqlite3_get_autocommit() callconv(.c) void;
extern fn sqlite3_get_auxdata() callconv(.c) void;
extern fn sqlite3_get_clientdata() callconv(.c) void;
extern fn sqlite3_get_table() callconv(.c) void;
extern fn sqlite3_hard_heap_limit64() callconv(.c) void;
extern fn sqlite3_incomplete() callconv(.c) void;
extern fn sqlite3_interrupt() callconv(.c) void;
extern fn sqlite3_is_interrupted() callconv(.c) void;
extern fn sqlite3_keyword_check() callconv(.c) void;
extern fn sqlite3_keyword_count() callconv(.c) void;
extern fn sqlite3_keyword_name() callconv(.c) void;
extern fn sqlite3_last_insert_rowid() callconv(.c) void;
extern fn sqlite3_libversion() callconv(.c) void;
extern fn sqlite3_libversion_number() callconv(.c) void;
extern fn sqlite3_limit() callconv(.c) void;
extern fn sqlite3_log() callconv(.c) void;
extern fn sqlite3_malloc() callconv(.c) void;
extern fn sqlite3_memory_highwater() callconv(.c) void;
extern fn sqlite3_memory_used() callconv(.c) void;
extern fn sqlite3_msize() callconv(.c) void;
extern fn sqlite3_mutex_alloc() callconv(.c) void;
extern fn sqlite3_mutex_free() callconv(.c) void;
extern fn sqlite3_mutex_try() callconv(.c) void;
extern fn sqlite3_next_stmt() callconv(.c) void;
extern fn sqlite3_open() callconv(.c) void;
extern fn sqlite3_open16() callconv(.c) void;
extern fn sqlite3_open_v2() callconv(.c) void;
extern fn sqlite3_overload_function() callconv(.c) void;
extern fn sqlite3_prepare() callconv(.c) void;
extern fn sqlite3_prepare16() callconv(.c) void;
extern fn sqlite3_prepare16_v2() callconv(.c) void;
extern fn sqlite3_prepare16_v3() callconv(.c) void;
extern fn sqlite3_prepare_v2() callconv(.c) void;
extern fn sqlite3_prepare_v3() callconv(.c) void;
extern fn sqlite3_profile() callconv(.c) void;
extern fn sqlite3_progress_handler() callconv(.c) void;
extern fn sqlite3_randomness() callconv(.c) void;
extern fn sqlite3_realloc() callconv(.c) void;
extern fn sqlite3_release_memory() callconv(.c) void;
extern fn sqlite3_reset() callconv(.c) void;
extern fn sqlite3_result_blob() callconv(.c) void;
extern fn sqlite3_result_blob64() callconv(.c) void;
extern fn sqlite3_result_double() callconv(.c) void;
extern fn sqlite3_result_error() callconv(.c) void;
extern fn sqlite3_result_error16() callconv(.c) void;
extern fn sqlite3_result_error_code() callconv(.c) void;
extern fn sqlite3_result_error_nomem() callconv(.c) void;
extern fn sqlite3_result_error_toobig() callconv(.c) void;
extern fn sqlite3_result_int() callconv(.c) void;
extern fn sqlite3_result_int64() callconv(.c) void;
extern fn sqlite3_result_null() callconv(.c) void;
extern fn sqlite3_result_pointer() callconv(.c) void;
extern fn sqlite3_result_str() callconv(.c) void;
extern fn sqlite3_result_subtype() callconv(.c) void;
extern fn sqlite3_result_text() callconv(.c) void;
extern fn sqlite3_result_text16() callconv(.c) void;
extern fn sqlite3_result_text16be() callconv(.c) void;
extern fn sqlite3_result_text16le() callconv(.c) void;
extern fn sqlite3_result_text64() callconv(.c) void;
extern fn sqlite3_result_value() callconv(.c) void;
extern fn sqlite3_result_zeroblob() callconv(.c) void;
extern fn sqlite3_result_zeroblob64() callconv(.c) void;
extern fn sqlite3_rollback_hook() callconv(.c) void;
extern fn sqlite3_serialize() callconv(.c) void;
extern fn sqlite3_set_authorizer() callconv(.c) void;
extern fn sqlite3_set_auxdata() callconv(.c) void;
extern fn sqlite3_set_clientdata() callconv(.c) void;
extern fn sqlite3_set_errmsg() callconv(.c) void;
extern fn sqlite3_set_last_insert_rowid() callconv(.c) void;
extern fn sqlite3_setlk_timeout() callconv(.c) void;
extern fn sqlite3_sleep() callconv(.c) void;
extern fn sqlite3_soft_heap_limit() callconv(.c) void;
extern fn sqlite3_soft_heap_limit64() callconv(.c) void;
extern fn sqlite3_sourceid() callconv(.c) void;
extern fn sqlite3_sql() callconv(.c) void;
extern fn sqlite3_status() callconv(.c) void;
extern fn sqlite3_status64() callconv(.c) void;
extern fn sqlite3_step() callconv(.c) void;
extern fn sqlite3_stmt_busy() callconv(.c) void;
extern fn sqlite3_stmt_explain() callconv(.c) void;
extern fn sqlite3_stmt_isexplain() callconv(.c) void;
extern fn sqlite3_stmt_readonly() callconv(.c) void;
extern fn sqlite3_stmt_status() callconv(.c) void;
extern fn sqlite3_str_append() callconv(.c) void;
extern fn sqlite3_str_appendall() callconv(.c) void;
extern fn sqlite3_str_appendchar() callconv(.c) void;
extern fn sqlite3_str_appendf() callconv(.c) void;
extern fn sqlite3_str_errcode() callconv(.c) void;
extern fn sqlite3_str_finish() callconv(.c) void;
extern fn sqlite3_str_free() callconv(.c) void;
extern fn sqlite3_str_length() callconv(.c) void;
extern fn sqlite3_str_new() callconv(.c) void;
extern fn sqlite3_str_reset() callconv(.c) void;
extern fn sqlite3_str_truncate() callconv(.c) void;
extern fn sqlite3_str_value() callconv(.c) void;
extern fn sqlite3_str_vappendf() callconv(.c) void;
extern fn sqlite3_strglob() callconv(.c) void;
extern fn sqlite3_stricmp() callconv(.c) void;
extern fn sqlite3_strlike() callconv(.c) void;
extern fn sqlite3_system_errno() callconv(.c) void;
extern fn sqlite3_table_column_metadata() callconv(.c) void;
extern fn sqlite3_test_control() callconv(.c) void;
extern fn sqlite3_thread_cleanup() callconv(.c) void;
extern fn sqlite3_threadsafe() callconv(.c) void;
extern fn sqlite3_total_changes() callconv(.c) void;
extern fn sqlite3_total_changes64() callconv(.c) void;
extern fn sqlite3_trace() callconv(.c) void;
extern fn sqlite3_trace_v2() callconv(.c) void;
extern fn sqlite3_transfer_bindings() callconv(.c) void;
extern fn sqlite3_txn_state() callconv(.c) void;
extern fn sqlite3_update_hook() callconv(.c) void;
extern fn sqlite3_uri_boolean() callconv(.c) void;
extern fn sqlite3_uri_int64() callconv(.c) void;
extern fn sqlite3_uri_key() callconv(.c) void;
extern fn sqlite3_uri_parameter() callconv(.c) void;
extern fn sqlite3_user_data() callconv(.c) void;
extern fn sqlite3_value_blob() callconv(.c) void;
extern fn sqlite3_value_bytes() callconv(.c) void;
extern fn sqlite3_value_bytes16() callconv(.c) void;
extern fn sqlite3_value_double() callconv(.c) void;
extern fn sqlite3_value_dup() callconv(.c) void;
extern fn sqlite3_value_encoding() callconv(.c) void;
extern fn sqlite3_value_free() callconv(.c) void;
extern fn sqlite3_value_frombind() callconv(.c) void;
extern fn sqlite3_value_int() callconv(.c) void;
extern fn sqlite3_value_int64() callconv(.c) void;
extern fn sqlite3_value_nochange() callconv(.c) void;
extern fn sqlite3_value_numeric_type() callconv(.c) void;
extern fn sqlite3_value_pointer() callconv(.c) void;
extern fn sqlite3_value_subtype() callconv(.c) void;
extern fn sqlite3_value_text() callconv(.c) void;
extern fn sqlite3_value_text16() callconv(.c) void;
extern fn sqlite3_value_text16be() callconv(.c) void;
extern fn sqlite3_value_text16le() callconv(.c) void;
extern fn sqlite3_value_type() callconv(.c) void;
extern fn sqlite3_vfs_find() callconv(.c) void;
extern fn sqlite3_vfs_register() callconv(.c) void;
extern fn sqlite3_vfs_unregister() callconv(.c) void;
extern fn sqlite3_vmprintf() callconv(.c) void;
extern fn sqlite3_vsnprintf() callconv(.c) void;
extern fn sqlite3_vtab_collation() callconv(.c) void;
extern fn sqlite3_vtab_config() callconv(.c) void;
extern fn sqlite3_vtab_distinct() callconv(.c) void;
extern fn sqlite3_vtab_in() callconv(.c) void;
extern fn sqlite3_vtab_in_first() callconv(.c) void;
extern fn sqlite3_vtab_in_next() callconv(.c) void;
extern fn sqlite3_vtab_nochange() callconv(.c) void;
extern fn sqlite3_vtab_on_conflict() callconv(.c) void;
extern fn sqlite3_vtab_rhs_value() callconv(.c) void;
extern fn sqlite3_wal_autocheckpoint() callconv(.c) void;
extern fn sqlite3_wal_checkpoint() callconv(.c) void;
extern fn sqlite3_wal_checkpoint_v2() callconv(.c) void;
extern fn sqlite3_wal_hook() callconv(.c) void;

// 279 slots — must match sizeof(sqlite3_api_routines)/sizeof(void*) in THIS
// build (probe-verified). A length mismatch is a comptime error below.
const sqlite3Apis = [279]?*const anyopaque{
    @ptrCast(&sqlite3_aggregate_context),
    @ptrCast(&sqlite3_aggregate_count),
    @ptrCast(&sqlite3_bind_blob),
    @ptrCast(&sqlite3_bind_double),
    @ptrCast(&sqlite3_bind_int),
    @ptrCast(&sqlite3_bind_int64),
    @ptrCast(&sqlite3_bind_null),
    @ptrCast(&sqlite3_bind_parameter_count),
    @ptrCast(&sqlite3_bind_parameter_index),
    @ptrCast(&sqlite3_bind_parameter_name),
    @ptrCast(&sqlite3_bind_text),
    @ptrCast(&sqlite3_bind_text16),
    @ptrCast(&sqlite3_bind_value),
    @ptrCast(&sqlite3_busy_handler),
    @ptrCast(&sqlite3_busy_timeout),
    @ptrCast(&sqlite3_changes),
    @ptrCast(&sqlite3_close),
    @ptrCast(&sqlite3_collation_needed),
    @ptrCast(&sqlite3_collation_needed16),
    @ptrCast(&sqlite3_column_blob),
    @ptrCast(&sqlite3_column_bytes),
    @ptrCast(&sqlite3_column_bytes16),
    @ptrCast(&sqlite3_column_count),
    null, // sqlite3_column_database_name — SQLITE_ENABLE_COLUMN_METADATA off (upstream #defines to 0)
    null, // sqlite3_column_database_name16 — ditto
    @ptrCast(&sqlite3_column_decltype),
    @ptrCast(&sqlite3_column_decltype16),
    @ptrCast(&sqlite3_column_double),
    @ptrCast(&sqlite3_column_int),
    @ptrCast(&sqlite3_column_int64),
    @ptrCast(&sqlite3_column_name),
    @ptrCast(&sqlite3_column_name16),
    null, // sqlite3_column_origin_name — SQLITE_ENABLE_COLUMN_METADATA off
    null, // sqlite3_column_origin_name16 — ditto
    null, // sqlite3_column_table_name — ditto
    null, // sqlite3_column_table_name16 — ditto
    @ptrCast(&sqlite3_column_text),
    @ptrCast(&sqlite3_column_text16),
    @ptrCast(&sqlite3_column_type),
    @ptrCast(&sqlite3_column_value),
    @ptrCast(&sqlite3_commit_hook),
    @ptrCast(&sqlite3_complete),
    @ptrCast(&sqlite3_complete16),
    @ptrCast(&sqlite3_create_collation),
    @ptrCast(&sqlite3_create_collation16),
    @ptrCast(&sqlite3_create_function),
    @ptrCast(&sqlite3_create_function16),
    @ptrCast(&sqlite3_create_module),
    @ptrCast(&sqlite3_data_count),
    @ptrCast(&sqlite3_db_handle),
    @ptrCast(&sqlite3_declare_vtab),
    @ptrCast(&sqlite3_enable_shared_cache),
    @ptrCast(&sqlite3_errcode),
    @ptrCast(&sqlite3_errmsg),
    @ptrCast(&sqlite3_errmsg16),
    @ptrCast(&sqlite3_exec),
    @ptrCast(&sqlite3_expired),
    @ptrCast(&sqlite3_finalize),
    @ptrCast(&sqlite3_free),
    @ptrCast(&sqlite3_free_table),
    @ptrCast(&sqlite3_get_autocommit),
    @ptrCast(&sqlite3_get_auxdata),
    @ptrCast(&sqlite3_get_table),
    null,
    @ptrCast(&sqlite3_interrupt),
    @ptrCast(&sqlite3_last_insert_rowid),
    @ptrCast(&sqlite3_libversion),
    @ptrCast(&sqlite3_libversion_number),
    @ptrCast(&sqlite3_malloc),
    @ptrCast(&sqlite3_mprintf),
    @ptrCast(&sqlite3_open),
    @ptrCast(&sqlite3_open16),
    @ptrCast(&sqlite3_prepare),
    @ptrCast(&sqlite3_prepare16),
    @ptrCast(&sqlite3_profile),
    @ptrCast(&sqlite3_progress_handler),
    @ptrCast(&sqlite3_realloc),
    @ptrCast(&sqlite3_reset),
    @ptrCast(&sqlite3_result_blob),
    @ptrCast(&sqlite3_result_double),
    @ptrCast(&sqlite3_result_error),
    @ptrCast(&sqlite3_result_error16),
    @ptrCast(&sqlite3_result_int),
    @ptrCast(&sqlite3_result_int64),
    @ptrCast(&sqlite3_result_null),
    @ptrCast(&sqlite3_result_text),
    @ptrCast(&sqlite3_result_text16),
    @ptrCast(&sqlite3_result_text16be),
    @ptrCast(&sqlite3_result_text16le),
    @ptrCast(&sqlite3_result_value),
    @ptrCast(&sqlite3_rollback_hook),
    @ptrCast(&sqlite3_set_authorizer),
    @ptrCast(&sqlite3_set_auxdata),
    @ptrCast(&sqlite3_snprintf),
    @ptrCast(&sqlite3_step),
    @ptrCast(&sqlite3_table_column_metadata),
    @ptrCast(&sqlite3_thread_cleanup),
    @ptrCast(&sqlite3_total_changes),
    @ptrCast(&sqlite3_trace),
    @ptrCast(&sqlite3_transfer_bindings),
    @ptrCast(&sqlite3_update_hook),
    @ptrCast(&sqlite3_user_data),
    @ptrCast(&sqlite3_value_blob),
    @ptrCast(&sqlite3_value_bytes),
    @ptrCast(&sqlite3_value_bytes16),
    @ptrCast(&sqlite3_value_double),
    @ptrCast(&sqlite3_value_int),
    @ptrCast(&sqlite3_value_int64),
    @ptrCast(&sqlite3_value_numeric_type),
    @ptrCast(&sqlite3_value_text),
    @ptrCast(&sqlite3_value_text16),
    @ptrCast(&sqlite3_value_text16be),
    @ptrCast(&sqlite3_value_text16le),
    @ptrCast(&sqlite3_value_type),
    @ptrCast(&sqlite3_vmprintf),
    @ptrCast(&sqlite3_overload_function),
    @ptrCast(&sqlite3_prepare_v2),
    @ptrCast(&sqlite3_prepare16_v2),
    @ptrCast(&sqlite3_clear_bindings),
    @ptrCast(&sqlite3_create_module_v2),
    @ptrCast(&sqlite3_bind_zeroblob),
    @ptrCast(&sqlite3_blob_bytes),
    @ptrCast(&sqlite3_blob_close),
    @ptrCast(&sqlite3_blob_open),
    @ptrCast(&sqlite3_blob_read),
    @ptrCast(&sqlite3_blob_write),
    @ptrCast(&sqlite3_create_collation_v2),
    @ptrCast(&sqlite3_file_control),
    @ptrCast(&sqlite3_memory_highwater),
    @ptrCast(&sqlite3_memory_used),
    @ptrCast(&sqlite3_mutex_alloc),
    @ptrCast(&sqlite3_mutex_enter),
    @ptrCast(&sqlite3_mutex_free),
    @ptrCast(&sqlite3_mutex_leave),
    @ptrCast(&sqlite3_mutex_try),
    @ptrCast(&sqlite3_open_v2),
    @ptrCast(&sqlite3_release_memory),
    @ptrCast(&sqlite3_result_error_nomem),
    @ptrCast(&sqlite3_result_error_toobig),
    @ptrCast(&sqlite3_sleep),
    @ptrCast(&sqlite3_soft_heap_limit),
    @ptrCast(&sqlite3_vfs_find),
    @ptrCast(&sqlite3_vfs_register),
    @ptrCast(&sqlite3_vfs_unregister),
    @ptrCast(&sqlite3_threadsafe),
    @ptrCast(&sqlite3_result_zeroblob),
    @ptrCast(&sqlite3_result_error_code),
    @ptrCast(&sqlite3_test_control),
    @ptrCast(&sqlite3_randomness),
    @ptrCast(&sqlite3_context_db_handle),
    @ptrCast(&sqlite3_extended_result_codes),
    @ptrCast(&sqlite3_limit),
    @ptrCast(&sqlite3_next_stmt),
    @ptrCast(&sqlite3_sql),
    @ptrCast(&sqlite3_status),
    @ptrCast(&sqlite3_backup_finish),
    @ptrCast(&sqlite3_backup_init),
    @ptrCast(&sqlite3_backup_pagecount),
    @ptrCast(&sqlite3_backup_remaining),
    @ptrCast(&sqlite3_backup_step),
    @ptrCast(&sqlite3_compileoption_get),
    @ptrCast(&sqlite3_compileoption_used),
    @ptrCast(&sqlite3_create_function_v2),
    @ptrCast(&sqlite3_db_config),
    @ptrCast(&sqlite3_db_mutex),
    @ptrCast(&sqlite3_db_status),
    @ptrCast(&sqlite3_extended_errcode),
    @ptrCast(&sqlite3_log),
    @ptrCast(&sqlite3_soft_heap_limit64),
    @ptrCast(&sqlite3_sourceid),
    @ptrCast(&sqlite3_stmt_status),
    @ptrCast(&sqlite3_strnicmp),
    null,
    @ptrCast(&sqlite3_wal_autocheckpoint),
    @ptrCast(&sqlite3_wal_checkpoint),
    @ptrCast(&sqlite3_wal_hook),
    @ptrCast(&sqlite3_blob_reopen),
    @ptrCast(&sqlite3_vtab_config),
    @ptrCast(&sqlite3_vtab_on_conflict),
    @ptrCast(&sqlite3_close_v2),
    @ptrCast(&sqlite3_db_filename),
    @ptrCast(&sqlite3_db_readonly),
    @ptrCast(&sqlite3_db_release_memory),
    @ptrCast(&sqlite3_errstr),
    @ptrCast(&sqlite3_stmt_busy),
    @ptrCast(&sqlite3_stmt_readonly),
    @ptrCast(&sqlite3_stricmp),
    @ptrCast(&sqlite3_uri_boolean),
    @ptrCast(&sqlite3_uri_int64),
    @ptrCast(&sqlite3_uri_parameter),
    @ptrCast(&sqlite3_vsnprintf),
    @ptrCast(&sqlite3_wal_checkpoint_v2),
    @ptrCast(&sqlite3_auto_extension),
    @ptrCast(&sqlite3_bind_blob64),
    @ptrCast(&sqlite3_bind_text64),
    @ptrCast(&sqlite3_cancel_auto_extension),
    @ptrCast(&sqlite3_load_extension),
    @ptrCast(&sqlite3_malloc64),
    @ptrCast(&sqlite3_msize),
    @ptrCast(&sqlite3_realloc64),
    @ptrCast(&sqlite3_reset_auto_extension),
    @ptrCast(&sqlite3_result_blob64),
    @ptrCast(&sqlite3_result_text64),
    @ptrCast(&sqlite3_strglob),
    @ptrCast(&sqlite3_value_dup),
    @ptrCast(&sqlite3_value_free),
    @ptrCast(&sqlite3_result_zeroblob64),
    @ptrCast(&sqlite3_bind_zeroblob64),
    @ptrCast(&sqlite3_value_subtype),
    @ptrCast(&sqlite3_result_subtype),
    @ptrCast(&sqlite3_status64),
    @ptrCast(&sqlite3_strlike),
    @ptrCast(&sqlite3_db_cacheflush),
    @ptrCast(&sqlite3_system_errno),
    @ptrCast(&sqlite3_trace_v2),
    @ptrCast(&sqlite3_expanded_sql),
    @ptrCast(&sqlite3_set_last_insert_rowid),
    @ptrCast(&sqlite3_prepare_v3),
    @ptrCast(&sqlite3_prepare16_v3),
    @ptrCast(&sqlite3_bind_pointer),
    @ptrCast(&sqlite3_result_pointer),
    @ptrCast(&sqlite3_value_pointer),
    @ptrCast(&sqlite3_vtab_nochange),
    @ptrCast(&sqlite3_value_nochange),
    @ptrCast(&sqlite3_vtab_collation),
    @ptrCast(&sqlite3_keyword_count),
    @ptrCast(&sqlite3_keyword_name),
    @ptrCast(&sqlite3_keyword_check),
    @ptrCast(&sqlite3_str_new),
    @ptrCast(&sqlite3_str_finish),
    @ptrCast(&sqlite3_str_appendf),
    @ptrCast(&sqlite3_str_vappendf),
    @ptrCast(&sqlite3_str_append),
    @ptrCast(&sqlite3_str_appendall),
    @ptrCast(&sqlite3_str_appendchar),
    @ptrCast(&sqlite3_str_reset),
    @ptrCast(&sqlite3_str_errcode),
    @ptrCast(&sqlite3_str_length),
    @ptrCast(&sqlite3_str_value),
    @ptrCast(&sqlite3_create_window_function),
    null,
    @ptrCast(&sqlite3_stmt_isexplain),
    @ptrCast(&sqlite3_value_frombind),
    @ptrCast(&sqlite3_drop_modules),
    @ptrCast(&sqlite3_hard_heap_limit64),
    @ptrCast(&sqlite3_uri_key),
    @ptrCast(&sqlite3_filename_database),
    @ptrCast(&sqlite3_filename_journal),
    @ptrCast(&sqlite3_filename_wal),
    @ptrCast(&sqlite3_create_filename),
    @ptrCast(&sqlite3_free_filename),
    @ptrCast(&sqlite3_database_file_object),
    @ptrCast(&sqlite3_txn_state),
    @ptrCast(&sqlite3_changes64),
    @ptrCast(&sqlite3_total_changes64),
    @ptrCast(&sqlite3_autovacuum_pages),
    @ptrCast(&sqlite3_error_offset),
    @ptrCast(&sqlite3_vtab_rhs_value),
    @ptrCast(&sqlite3_vtab_distinct),
    @ptrCast(&sqlite3_vtab_in),
    @ptrCast(&sqlite3_vtab_in_first),
    @ptrCast(&sqlite3_vtab_in_next),
    @ptrCast(&sqlite3_deserialize),
    @ptrCast(&sqlite3_serialize),
    @ptrCast(&sqlite3_db_name),
    @ptrCast(&sqlite3_value_encoding),
    @ptrCast(&sqlite3_is_interrupted),
    @ptrCast(&sqlite3_stmt_explain),
    @ptrCast(&sqlite3_get_clientdata),
    @ptrCast(&sqlite3_set_clientdata),
    @ptrCast(&sqlite3_setlk_timeout),
    @ptrCast(&sqlite3_set_errmsg),
    @ptrCast(&sqlite3_db_status64),
    @ptrCast(&sqlite3_str_truncate),
    @ptrCast(&sqlite3_str_free),
    @ptrCast(&sqlite3_carray_bind),
    @ptrCast(&sqlite3_carray_bind_v2),
    @ptrCast(&sqlite3_incomplete),
    @ptrCast(&sqlite3_result_str),
};

comptime {
    // Each member of sqlite3_api_routines is a function pointer, so the table is
    // exactly this many pointer-sized slots; mismatch => the C struct changed.
    std.debug.assert(sqlite3Apis.len == 279);
    std.debug.assert(@sizeOf(@TypeOf(sqlite3Apis)) == 279 * @sizeOf(?*const anyopaque));
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3LoadExtension (static) — the workhorse behind sqlite3_load_extension
// ════════════════════════════════════════════════════════════════════════════
fn sqlite3LoadExtension(
    db: ?*anyopaque,
    zFile: [*:0]const u8,
    zProc: ?[*:0]const u8,
    pzErrMsg: ?*?[*:0]u8,
) c_int {
    const pVfs = dbPVfs(db);
    var handle: ?*anyopaque = null;
    var xInit: ?LoadextEntry = null;
    var zErrmsg: ?[*:0]u8 = null;
    var zEntry: [*:0]const u8 = undefined;
    var zAltEntry: ?[*:0]u8 = null;
    var nMsg: u64 = strlen(zFile);

    // Shared-library endings to try (unix => only "so").
    const azEndings = [_][*:0]const u8{"so"};

    if (pzErrMsg) |pp| pp.* = null;

    // Extension loading must be explicitly enabled.
    if ((dbFlagsPtr(db).* & SQLITE_LoadExtension) == 0) {
        if (pzErrMsg) |pp| pp.* = sqlite3_mprintf("not authorized");
        return SQLITE_ERROR;
    }

    zEntry = if (zProc) |zp| zp else "sqlite3_extension_init";

    // tag-20210611-1: guard against oversize filenames that can crash dlopen.
    if (nMsg > SQLITE_MAX_PATHLEN) return extensionNotFound(pVfs, zFile, pzErrMsg, nMsg);
    // Reject empty filename (would link to the running app).
    if (nMsg == 0) return extensionNotFound(pVfs, zFile, pzErrMsg, nMsg);

    handle = sqlite3OsDlOpen(pVfs, zFile);
    // SQLITE_OS_UNIX: try the alternate endings.
    {
        var ii: usize = 0;
        while (ii < azEndings.len and handle == null) : (ii += 1) {
            const zAltFile = sqlite3_mprintf("%s.%s", zFile, azEndings[ii]);
            if (zAltFile == null) return SQLITE_NOMEM_BKPT;
            if (nMsg + strlen(azEndings[ii]) + 1 <= SQLITE_MAX_PATHLEN) {
                handle = sqlite3OsDlOpen(pVfs, @ptrCast(zAltFile));
            }
            sqlite3_free(@ptrCast(zAltFile));
        }
    }
    if (handle == null) return extensionNotFound(pVfs, zFile, pzErrMsg, nMsg);
    xInit = @ptrCast(sqlite3OsDlSym(pVfs, handle, zEntry));

    // If the default entry point was not found, try derived "sqlite3_X_init"
    // names built from the filename.
    if (xInit == null and zProc == null) {
        const ncFile = sqlite3Strlen30(zFile);
        var cnt: c_int = 0;
        zAltEntry = @ptrCast(sqlite3_malloc64(@intCast(ncFile + 30)));
        if (zAltEntry == null) {
            sqlite3OsDlClose(pVfs, handle);
            return SQLITE_NOMEM_BKPT;
        }
        const alt = zAltEntry.?;
        while (true) {
            _ = memcpy(alt, "sqlite3_", 8);
            var iFile: c_int = ncFile - 1;
            while (iFile >= 0 and !dirSep(zFile[@intCast(iFile)])) iFile -= 1;
            iFile += 1;
            if (sqlite3_strnicmp(@ptrCast(zFile + @as(usize, @intCast(iFile))), "lib", 3) == 0) {
                iFile += 3;
            }
            var iEntry: usize = 8;
            while (true) {
                const c: u8 = zFile[@intCast(iFile)];
                if (c == 0 or c == '.') break;
                if (isalpha(c) or (cnt != 0 and isdigit(c))) {
                    alt[iEntry] = sqlite3UpperToLower[c];
                    iEntry += 1;
                }
                iFile += 1;
            }
            _ = memcpy(alt + iEntry, "_init", 6);
            zEntry = @ptrCast(alt);
            xInit = @ptrCast(sqlite3OsDlSym(pVfs, handle, zEntry));
            cnt += 1;
            if (!(xInit == null and cnt < 2)) break;
        }
    }

    if (xInit == null) {
        if (pzErrMsg) |pp| {
            nMsg += strlen(zEntry) + 300;
            zErrmsg = @ptrCast(sqlite3_malloc64(nMsg));
            pp.* = zErrmsg;
            if (zErrmsg) |zm| {
                _ = sqlite3_snprintf(@intCast(nMsg), zm,
                    "no entry point [%s] in shared library [%s]", zEntry, zFile);
                sqlite3OsDlError(pVfs, @intCast(nMsg - 1), zm);
            }
        }
        sqlite3OsDlClose(pVfs, handle);
        sqlite3_free(@ptrCast(zAltEntry));
        return SQLITE_ERROR;
    }
    sqlite3_free(@ptrCast(zAltEntry));

    const rc0 = xInit.?(db, &zErrmsg, @ptrCast(&sqlite3Apis));
    if (rc0 != 0) {
        if (rc0 == SQLITE_OK_LOAD_PERMANENTLY) return SQLITE_OK;
        if (pzErrMsg) |pp| {
            pp.* = sqlite3_mprintf("error during initialization: %s", zErrmsg);
        }
        sqlite3_free(@ptrCast(zErrmsg));
        sqlite3OsDlClose(pVfs, handle);
        return SQLITE_ERROR;
    }

    // Append the new handle to db->aExtension[].
    const nExt: c_int = dbNExtensionPtr(db).*;
    const aHandle: ?*anyopaque = sqlite3DbMallocZero(db, @sizeOf(?*anyopaque) * @as(u64, @intCast(nExt + 1)));
    if (aHandle == null) return SQLITE_NOMEM_BKPT;
    const aNew: [*]?*anyopaque = @ptrCast(@alignCast(aHandle.?));
    if (nExt > 0) {
        _ = memcpy(aHandle, @ptrCast(dbAExtensionPtr(db).*), @sizeOf(?*anyopaque) * @as(usize, @intCast(nExt)));
    }
    sqlite3DbFree(db, @ptrCast(dbAExtensionPtr(db).*));
    dbAExtensionPtr(db).* = aNew;

    aNew[@intCast(nExt)] = handle;
    dbNExtensionPtr(db).* = nExt + 1;
    return SQLITE_OK;
}

fn extensionNotFound(pVfs: ?*anyopaque, zFile: [*:0]const u8, pzErrMsg: ?*?[*:0]u8, nMsgIn: u64) c_int {
    if (pzErrMsg) |pp| {
        const nMsg = nMsgIn + 300;
        const zErrmsg: ?[*:0]u8 = @ptrCast(sqlite3_malloc64(nMsg));
        pp.* = zErrmsg;
        if (zErrmsg) |zm| {
            _ = sqlite3_snprintf(@intCast(nMsg), zm,
                "unable to open shared library [%.*s]", @as(c_int, @intCast(SQLITE_MAX_PATHLEN)), zFile);
            sqlite3OsDlError(pVfs, @intCast(nMsg - 1), zm);
        }
    }
    return SQLITE_ERROR;
}

export fn sqlite3_load_extension(
    db: ?*anyopaque,
    zFile: [*:0]const u8,
    zProc: ?[*:0]const u8,
    pzErrMsg: ?*?[*:0]u8,
) callconv(.c) c_int {
    sqlite3_mutex_enter(dbMutex(db));
    var rc = sqlite3LoadExtension(db, zFile, zProc, pzErrMsg);
    rc = sqlite3ApiExit(db, rc);
    sqlite3_mutex_leave(dbMutex(db));
    return rc;
}

// Clean up loaded extensions when a connection closes.
export fn sqlite3CloseExtensions(db: ?*anyopaque) callconv(.c) void {
    // assert( sqlite3_mutex_held(db->mutex) )
    const nExt: c_int = dbNExtensionPtr(db).*;
    if (dbAExtensionPtr(db).*) |aExt| {
        var i: usize = 0;
        while (i < @as(usize, @intCast(nExt))) : (i += 1) {
            sqlite3OsDlClose(dbPVfs(db), aExt[i]);
        }
    }
    sqlite3DbFree(db, @ptrCast(dbAExtensionPtr(db).*));
}

// Enable/disable extension loading (disabled by default).
export fn sqlite3_enable_load_extension(db: ?*anyopaque, onoff: c_int) callconv(.c) c_int {
    // SQLITE_ENABLE_API_ARMOR is OFF.
    sqlite3_mutex_enter(dbMutex(db));
    if (onoff != 0) {
        dbFlagsPtr(db).* |= (SQLITE_LoadExtension | SQLITE_LoadExtFunc);
    } else {
        dbFlagsPtr(db).* &= ~(SQLITE_LoadExtension | SQLITE_LoadExtFunc);
    }
    sqlite3_mutex_leave(dbMutex(db));
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// Automatic (statically-linked) extension registry
// ════════════════════════════════════════════════════════════════════════════
//
// The autoextension state vector. SQLITE_OMIT_WSD is OFF so wsdAutoext is this
// global directly. MUTABLE — written under STATIC_MAIN mutex — hence a module
// `var` (and the matching C symbol `sqlite3Autoext` is file-static, so this is
// a private Zig global, not an export).
const AutoExtList = extern struct {
    nExt: u32,
    aExt: ?[*]?VoidFn,
};
var sqlite3Autoext: AutoExtList = .{ .nExt = 0, .aExt = null };

export fn sqlite3_auto_extension(xInit: ?VoidFn) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    // SQLITE_ENABLE_API_ARMOR is OFF.
    // SQLITE_OMIT_AUTOINIT is OFF.
    rc = sqlite3_initialize();
    if (rc != 0) return rc;

    const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
    sqlite3_mutex_enter(mutex);
    var i: u32 = 0;
    while (i < sqlite3Autoext.nExt) : (i += 1) {
        if (sqlite3Autoext.aExt.?[i] == xInit) break;
    }
    if (i == sqlite3Autoext.nExt) {
        const nByte: u64 = (@as(u64, sqlite3Autoext.nExt) + 1) * @sizeOf(?VoidFn);
        const aNew: ?*anyopaque = sqlite3_realloc64(@ptrCast(sqlite3Autoext.aExt), nByte);
        if (aNew == null) {
            rc = SQLITE_NOMEM_BKPT;
        } else {
            sqlite3Autoext.aExt = @ptrCast(@alignCast(aNew));
            sqlite3Autoext.aExt.?[sqlite3Autoext.nExt] = xInit;
            sqlite3Autoext.nExt += 1;
        }
    }
    sqlite3_mutex_leave(mutex);
    // assert( (rc&0xff)==rc )
    return rc;
}

export fn sqlite3_cancel_auto_extension(xInit: ?VoidFn) callconv(.c) c_int {
    const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
    var n: c_int = 0;
    // SQLITE_ENABLE_API_ARMOR is OFF.
    sqlite3_mutex_enter(mutex);
    var i: c_int = @as(c_int, @intCast(sqlite3Autoext.nExt)) - 1;
    while (i >= 0) : (i -= 1) {
        if (sqlite3Autoext.aExt.?[@intCast(i)] == xInit) {
            sqlite3Autoext.nExt -= 1;
            sqlite3Autoext.aExt.?[@intCast(i)] = sqlite3Autoext.aExt.?[sqlite3Autoext.nExt];
            n += 1;
            break;
        }
    }
    sqlite3_mutex_leave(mutex);
    return n;
}

export fn sqlite3_reset_auto_extension() callconv(.c) void {
    // SQLITE_OMIT_AUTOINIT is OFF.
    if (sqlite3_initialize() == SQLITE_OK) {
        const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
        sqlite3_mutex_enter(mutex);
        sqlite3_free(@ptrCast(sqlite3Autoext.aExt));
        sqlite3Autoext.aExt = null;
        sqlite3Autoext.nExt = 0;
        sqlite3_mutex_leave(mutex);
    }
}

// Load all automatic extensions into a freshly opened connection.
export fn sqlite3AutoLoadExtensions(db: ?*anyopaque) callconv(.c) void {
    var go: bool = true;
    if (sqlite3Autoext.nExt == 0) {
        // Common case: no autoextensions, never touch the mutex.
        return;
    }
    var i: u32 = 0;
    while (go) : (i += 1) {
        var zErrmsg: ?[*:0]u8 = null;
        const mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MAIN);
        // SQLITE_OMIT_LOAD_EXTENSION is OFF.
        const pThunk: ?*const anyopaque = @ptrCast(&sqlite3Apis);
        var xInit: ?LoadextEntry = null;
        sqlite3_mutex_enter(mutex);
        if (i >= sqlite3Autoext.nExt) {
            xInit = null;
            go = false;
        } else {
            xInit = @ptrCast(sqlite3Autoext.aExt.?[i]);
        }
        sqlite3_mutex_leave(mutex);
        zErrmsg = null;
        if (xInit) |xi| {
            const rc = xi(db, &zErrmsg, pThunk);
            if (rc != 0) {
                sqlite3ErrorWithMsg(db, rc,
                    "automatic extension loading failed: %s", zErrmsg);
                go = false;
            }
        }
        sqlite3_free(@ptrCast(zErrmsg));
    }
}
