//! Zig port of SQLite's cross-platform thread-helper layer (src/threads.c).
//!
//! Drop-in replacement exporting `sqlite3ThreadCreate` / `sqlite3ThreadJoin`,
//! the tiny interface SQLite uses to (optionally) run work — currently the
//! external merge-sort worker tasks in vdbesort.c — on a background thread.
//!
//! ## Which threading #if-path is active here
//! threads.c selects an implementation at compile time. In BOTH of this
//! project's builds the active path is the **Unix Pthreads** one:
//!
//!   * `SQLITE_MAX_WORKER_THREADS > 0` — defaults to 8 (sqliteInt.h), so the
//!     whole module body is compiled (it is `#if`'d out entirely otherwise).
//!   * `SQLITE_OS_UNIX` (Linux), `SQLITE_THREADSAFE=1` (build.zig), and
//!     `SQLITE_MUTEX_PTHREADS` — the last is auto-`#define`d by mutex.h when
//!     THREADSAFE && !NOOP on unix. => `SQLITE_THREADS_IMPLEMENTED`, the Unix
//!     pthreads branch. The Win32 and single-threaded fallbacks are dead code
//!     and are NOT ported.
//!
//! ## Config invariance / what is gated
//! The SQLiteThread struct is this module's **own** type — callers (vdbesort.c)
//! only ever hold a `SQLiteThread*`, never its sizeof or field offsets — so its
//! layout is internal and needs no c_layout offset. The only struct coupling is
//! to `sqlite3GlobalConfig.bCoreMutex`, read *only* inside a debug `assert` on
//! the create path; `bCoreMutex` sits at the config-invariant offset 4 (right
//! after `int bMemstat`, the first field of Sqlite3Config). That assert, plus
//! the `NEVER(p==0)` abort on join, are live only under SQLITE_DEBUG, so both
//! are gated on `config.sqlite_debug` and compile away in the production build —
//! exactly as the C asserts do (NDEBUG there).
//!
//! `sqlite3FaultSim()` is a *real* extern function in both builds: SQLITE_TEST's
//! TESTCTRL_FAULT_INSTALL path is compiled because SQLITE_UNTESTABLE is off in
//! both configs (under SQLITE_UNTESTABLE it would be `#define ...SQLITE_OK`).
//! Passing 200 lets the test harness force worker threads to run sequentially.
//!
//! ## Testing note
//! A pure-logic Zig unit test is not feasible: the meaningful behavior is real
//! thread creation/join via pthreads plus the malloc/fault-sim plumbing, which
//! needs the live SQLite runtime. Correctness is covered by the TCL suite
//! (sort*.test exercising the multi-threaded external sorter) run through the
//! testfixture, not by an in-file `test {}`.

const std = @import("std");
const config = @import("config");

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
// SQLITE_NOMEM_BKPT: in production this macro folds extra debug bookkeeping, but
// the returned error code is SQLITE_NOMEM (7) in every build.
const SQLITE_NOMEM: c_int = 7;

// --- C / SQLite helpers resolved at link time -----------------------------
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3FaultSim(x: c_int) c_int;

/// `sqlite3Config` global (`struct Sqlite3Config`). We read only `bCoreMutex`,
/// a `u8` at the config-invariant offset 4 (it follows the sole leading
/// `int bMemstat`). Read solely for the debug-only create-path assert.
extern var sqlite3Config: u8;  // mutable global — see pcache.zig note
const Sqlite3Config_bCoreMutex: usize = 4;
inline fn coreMutexEnabled() bool {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    return base[Sqlite3Config_bCoreMutex] != 0;
}

// --- libc pthread bindings (C ABI) ----------------------------------------
// pthread_t is an opaque scalar handle (unsigned long on glibc/Linux). We keep
// it as the platform-sized integer so SQLiteThread's layout matches C exactly.
const pthread_t = c_ulong;

extern fn pthread_create(
    thread: *pthread_t,
    attr: ?*const anyopaque,
    start_routine: *const fn (?*anyopaque) callconv(.c) ?*anyopaque,
    arg: ?*anyopaque,
) c_int;
extern fn pthread_join(thread: pthread_t, retval: ?*?*anyopaque) c_int;

/// The thread routine signature SQLite passes around: `void *(*)(void*)`.
const XTask = *const fn (?*anyopaque) callconv(.c) ?*anyopaque;

/// A running thread. This is threads.c's own `struct SQLiteThread` for the Unix
/// pthreads path — internal layout, owned here. Mirrors the C field order so
/// the in-memory shape is identical (callers treat it as opaque regardless).
const SQLiteThread = extern struct {
    tid: pthread_t, // Thread ID
    done: c_int, // Set to true when thread finishes
    pOut: ?*anyopaque, // Result returned by the thread
    xTask: ?XTask, // The thread routine
    pIn: ?*anyopaque, // Argument to the thread
};

/// Create a new thread.
///
/// Mirrors C: allocate + zero a SQLiteThread, stash the task/arg, then either
/// spin a real pthread or (if FaultSim(200) fires) run the task inline so the
/// "thread" is already done. On pthread_create failure we likewise fall back to
/// running inline. Always returns SQLITE_OK except on OOM.
export fn sqlite3ThreadCreate(
    ppThread: *?*SQLiteThread,
    xTask: XTask,
    pIn: ?*anyopaque,
) callconv(.c) c_int {
    // assert( ppThread!=0 ); assert( xTask!=0 ); — pointer args are non-null by
    // type in Zig. The remaining create-time assert is debug-only:
    if (config.sqlite_debug) {
        // This routine is never used in single-threaded mode.
        std.debug.assert(coreMutexEnabled());
    }

    ppThread.* = null;
    const raw = sqlite3Malloc(@sizeOf(SQLiteThread)) orelse return SQLITE_NOMEM;
    const p: *SQLiteThread = @ptrCast(@alignCast(raw));
    @memset(std.mem.asBytes(p), 0);
    p.xTask = xTask;
    p.pIn = pIn;

    // If the SQLITE_TESTCTRL_FAULT_INSTALL callback returns SQLITE_ERROR when
    // passed 200, force worker threads to run sequentially / deterministically.
    var rc: c_int = undefined;
    if (sqlite3FaultSim(200) != 0) {
        rc = 1;
    } else {
        rc = pthread_create(&p.tid, null, xTask, pIn);
    }
    if (rc != 0) {
        p.done = 1;
        p.pOut = xTask(pIn);
    }
    ppThread.* = p;
    return SQLITE_OK;
}

/// Get the results of the thread (join), freeing the SQLiteThread.
export fn sqlite3ThreadJoin(p_in: ?*SQLiteThread, ppOut: *?*anyopaque) callconv(.c) c_int {
    // assert( ppOut!=0 ) — non-null by type.
    // NEVER(p==0): defensive. Under SQLITE_DEBUG this aborts (assert(0)); in
    // every build the null path returns SQLITE_NOMEM_BKPT.
    const p = p_in orelse {
        if (config.sqlite_debug) unreachable;
        return SQLITE_NOMEM;
    };

    var rc: c_int = undefined;
    if (p.done != 0) {
        ppOut.* = p.pOut;
        rc = SQLITE_OK;
    } else {
        rc = if (pthread_join(p.tid, ppOut) != 0) SQLITE_ERROR else SQLITE_OK;
    }
    sqlite3_free(p);
    return rc;
}
