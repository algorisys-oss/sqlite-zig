//! Zig port of SQLite's mutex DISPATCH layer (src/mutex.c).
//!
//! This is the architecture-independent mutex front end: the public
//! `sqlite3_mutex_alloc/free/enter/try/leave/held/notheld` API plus the
//! internal `sqlite3MutexInit/End/Alloc`. None of these implement a mutex;
//! they dispatch through the method table embedded in `sqlite3GlobalConfig`
//! (field `mutex`, a `sqlite3_mutex_methods` sub-struct) to the active backend.
//! In this project that backend is mutex_unix.c (still C, `sqlite3DefaultMutex`)
//! for core mutexing, or the already-ported `sqlite3NoopMutex` (src/mutex_noop.zig)
//! when core mutexing is disabled at run time.
//!
//! ## Build config assumed (mirrors `sqlite_flags`/build.zig)
//!   * SQLITE_THREADSAFE=1  -> SQLITE_MUTEX_OMIT is NOT defined, so the whole
//!     file is live (the `#ifndef SQLITE_MUTEX_OMIT` body).
//!   * SQLITE_THREAD_MISUSE_WARNINGS is NOT defined in either build, so the
//!     entire CheckMutex / multiThreadedCheckMutex / sqlite3MutexWarnOnContention
//!     block is omitted. (sqlite3MutexInit therefore always installs
//!     `sqlite3DefaultMutex()` for the bCoreMutex path, never the check wrapper.)
//!   * SQLITE_OMIT_AUTOINIT is NOT defined, so `sqlite3_mutex_alloc` auto-inits.
//!   * SQLITE_ENABLE_API_ARMOR is off (no extra bounds/NULL checks here).
//!
//! ## Prod vs debug split (one object, two configs)
//! One Zig object links into BOTH the production `zig build` library (no
//! SQLITE_DEBUG/TEST) and the `configure --dev` testfixture (SQLITE_DEBUG=1,
//! SQLITE_TEST=1). We select divergent behavior at comptime on
//! `@import("config").sqlite_debug`, reproducing the C `#ifdef SQLITE_DEBUG` /
//! `#ifndef NDEBUG` pairs exactly:
//!   * `mutexIsInit`: a file-static int that tracks whether the subsystem is
//!     initialized. Set/cleared and asserted only under SQLITE_DEBUG. SQLITE_WSD
//!     is off (SQLITE_OMIT_WSD not defined), so `GLOBAL(int, mutexIsInit)` is
//!     just the plain static. Compiled away entirely in production.
//!   * `sqlite3_mutex_held` / `sqlite3_mutex_notheld`: guarded by `#ifndef
//!     NDEBUG` in C. The testfixture compiles with -DSQLITE_DEBUG (NDEBUG off),
//!     production with NDEBUG on, so we export these two symbols only when
//!     `config.sqlite_debug` (via comptime `@export`, like src/os.zig). The
//!     `__has_feature(thread_sanitizer)` branch is omitted: TSAN is not used in
//!     either build.
//!
//! ## sqlite3GlobalConfig fields read at GROUND-TRUTH OFFSETS
//! SQLITE_OMIT_WSD is off, so `sqlite3GlobalConfig` is the global `sqlite3Config`.
//! We read two members at their config-invariant offsets from c_layout.zig
//! (rather than mirroring the whole Sqlite3Config struct, whose size diverges
//! between configs):
//!   * `mutex`       (sqlite3_mutex_methods, embedded) -- Sqlite3Config_mutex
//!   * `bCoreMutex`  (u8)                              -- Sqlite3Config_bCoreMutex
//! `sqlite3_mutex_methods` is PUBLIC ABI (sqlite3.h); we mirror it field-for-
//! field as an `extern struct` (modelled on src/mem1.zig's sqlite3_mem_methods).
//! The `mutex` member is read in-place (a sub-struct, not a pointer): we form a
//! pointer to it at the offset and call its function pointers.
//!
//! ## Testing
//! A pure-Zig unit test is not feasible: every entry point dispatches through
//! `sqlite3GlobalConfig.mutex`, which only exists/is populated in a linked
//! SQLite (it lives in the C `sqlite3Config` global and is filled by
//! sqlite3MutexInit at run time). Validation is via the TCL suite (mutex1.test,
//! mutex2.test) under the testfixture build.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_MUTEX_RECURSIVE: c_int = 1;

/// The public sqlite3_mutex_methods vtable layout (from sqlite3.h). Opaque
/// `sqlite3_mutex*` is modelled as `?*anyopaque`. This mirrors the `mutex`
/// sub-struct embedded in Sqlite3Config.
const MutexMethods = extern struct {
    xMutexInit: ?*const fn () callconv(.c) c_int,
    xMutexEnd: ?*const fn () callconv(.c) c_int,
    xMutexAlloc: ?*const fn (c_int) callconv(.c) ?*anyopaque,
    xMutexFree: ?*const fn (?*anyopaque) callconv(.c) void,
    xMutexEnter: ?*const fn (?*anyopaque) callconv(.c) void,
    xMutexTry: ?*const fn (?*anyopaque) callconv(.c) c_int,
    xMutexLeave: ?*const fn (?*anyopaque) callconv(.c) void,
    xMutexHeld: ?*const fn (?*anyopaque) callconv(.c) c_int,
    xMutexNotheld: ?*const fn (?*anyopaque) callconv(.c) c_int,
};

// --- C / SQLite helpers resolved at link time ---
extern fn sqlite3_initialize() c_int;
extern fn sqlite3MemoryBarrier() void;
/// The active no-op (or, under SQLITE_DEBUG, checking) mutex table. Ported in
/// src/mutex_noop.zig.
extern fn sqlite3NoopMutex() *const MutexMethods;
/// The default (real) mutex backend; mutex_unix.c (still C).
extern fn sqlite3DefaultMutex() *const MutexMethods;

// --- Ground-truth reads of sqlite3GlobalConfig fields ---
// SQLITE_OMIT_WSD is off, so sqlite3GlobalConfig is literally the global
// `sqlite3Config`. We read `mutex` (the embedded method table) and `bCoreMutex`
// at their config-invariant offsets.
extern var sqlite3Config: u8;  // mutable global — see pcache.zig note
inline fn cfgBase() [*]u8 {
    const p: [*]const u8 = @ptrCast(&sqlite3Config);
    return @constCast(p);
}
/// Pointer to the embedded `mutex` sub-struct within sqlite3GlobalConfig.
inline fn cfgMutex() *MutexMethods {
    return @ptrCast(@alignCast(cfgBase() + L.Sqlite3Config_mutex));
}
/// The `bCoreMutex` byte (u8) within sqlite3GlobalConfig.
inline fn cfgBCoreMutex() c_int {
    return cfgBase()[L.Sqlite3Config_bCoreMutex];
}

// --- SQLITE_DEBUG-only bookkeeping ---
// C: `static SQLITE_WSD int mutexIsInit = 0;` (SQLITE_WSD is a no-op here, so a
// plain static int). Only used/asserted under SQLITE_DEBUG; in production it is
// not referenced at all. We keep the storage unconditionally (cheap) but only
// read/write/assert it under config.sqlite_debug, matching the C #ifdef exactly.
var mutexIsInit: c_int = 0;

/// Initialize the mutex system.
/// C: sqlite3MutexInit().
export fn sqlite3MutexInit() callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pTo = cfgMutex();
    if (pTo.xMutexAlloc == null) {
        // The xMutexAlloc method has not been set, so the user did not install a
        // mutex implementation via sqlite3_config() before sqlite3_initialize().
        // Copy pointers from the default implementation into sqlite3GlobalConfig.
        // SQLITE_THREAD_MISUSE_WARNINGS is off, so the bCoreMutex path uses
        // sqlite3DefaultMutex() directly (no multiThreadedCheckMutex wrapper).
        const pFrom = if (cfgBCoreMutex() != 0) sqlite3DefaultMutex() else sqlite3NoopMutex();
        pTo.xMutexInit = pFrom.xMutexInit;
        pTo.xMutexEnd = pFrom.xMutexEnd;
        pTo.xMutexFree = pFrom.xMutexFree;
        pTo.xMutexEnter = pFrom.xMutexEnter;
        pTo.xMutexTry = pFrom.xMutexTry;
        pTo.xMutexLeave = pFrom.xMutexLeave;
        pTo.xMutexHeld = pFrom.xMutexHeld;
        pTo.xMutexNotheld = pFrom.xMutexNotheld;
        sqlite3MemoryBarrier();
        pTo.xMutexAlloc = pFrom.xMutexAlloc;
    }
    std.debug.assert(pTo.xMutexInit != null);
    rc = pTo.xMutexInit.?();

    if (config.sqlite_debug) {
        mutexIsInit = 1;
    }

    sqlite3MemoryBarrier();
    return rc;
}

/// Shutdown the mutex system, freeing resources allocated by sqlite3MutexInit().
/// C: sqlite3MutexEnd().
export fn sqlite3MutexEnd() callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const m = cfgMutex();
    if (m.xMutexEnd) |f| {
        rc = f();
    }

    if (config.sqlite_debug) {
        mutexIsInit = 0;
    }

    return rc;
}

/// Retrieve a pointer to a static mutex or allocate a new dynamic one.
/// C: sqlite3_mutex_alloc(). SQLITE_OMIT_AUTOINIT is off, so we auto-init.
export fn sqlite3_mutex_alloc(id: c_int) callconv(.c) ?*anyopaque {
    if (id <= SQLITE_MUTEX_RECURSIVE and sqlite3_initialize() != 0) return null;
    if (id > SQLITE_MUTEX_RECURSIVE and sqlite3MutexInit() != 0) return null;
    const m = cfgMutex();
    std.debug.assert(m.xMutexAlloc != null);
    return m.xMutexAlloc.?(id);
}

/// Internal allocator: returns null (no mutex) when core mutexing is disabled.
/// C: sqlite3MutexAlloc().
export fn sqlite3MutexAlloc(id: c_int) callconv(.c) ?*anyopaque {
    if (cfgBCoreMutex() == 0) {
        return null;
    }
    if (config.sqlite_debug) {
        std.debug.assert(mutexIsInit != 0);
    }
    const m = cfgMutex();
    std.debug.assert(m.xMutexAlloc != null);
    return m.xMutexAlloc.?(id);
}

/// Free a dynamic mutex.
/// C: sqlite3_mutex_free().
export fn sqlite3_mutex_free(p: ?*anyopaque) callconv(.c) void {
    if (p != null) {
        const m = cfgMutex();
        std.debug.assert(m.xMutexFree != null);
        m.xMutexFree.?(p);
    }
}

/// Obtain the mutex p, blocking until available. NULL is a no-op.
/// C: sqlite3_mutex_enter().
export fn sqlite3_mutex_enter(p: ?*anyopaque) callconv(.c) void {
    if (p != null) {
        const m = cfgMutex();
        std.debug.assert(m.xMutexEnter != null);
        m.xMutexEnter.?(p);
    }
}

/// Try to obtain the mutex p without blocking. Returns SQLITE_OK on success,
/// SQLITE_BUSY if held by another thread. NULL returns SQLITE_OK.
/// C: sqlite3_mutex_try().
export fn sqlite3_mutex_try(p: ?*anyopaque) callconv(.c) c_int {
    const rc: c_int = SQLITE_OK;
    if (p != null) {
        const m = cfgMutex();
        std.debug.assert(m.xMutexTry != null);
        return m.xMutexTry.?(p);
    }
    return rc;
}

/// Exit a mutex previously entered by the same thread. NULL is a no-op;
/// behavior is undefined if the mutex is not currently entered.
/// C: sqlite3_mutex_leave().
export fn sqlite3_mutex_leave(p: ?*anyopaque) callconv(.c) void {
    if (p != null) {
        const m = cfgMutex();
        std.debug.assert(m.xMutexLeave != null);
        m.xMutexLeave.?(p);
    }
}

// --- Debug-only assert helpers (C: #ifndef NDEBUG) ---
// Exported only under SQLITE_DEBUG, mirroring the testfixture (NDEBUG off) vs
// production (NDEBUG on) split. The TSAN `__has_feature` branch is omitted (TSAN
// not used in either build). Wired via comptime @export, like src/os.zig.

fn mutexHeld(p: ?*anyopaque) callconv(.c) c_int {
    const m = cfgMutex();
    std.debug.assert(p == null or m.xMutexHeld != null);
    return @intFromBool(p == null or m.xMutexHeld.?(p) != 0);
}
fn mutexNotheld(p: ?*anyopaque) callconv(.c) c_int {
    const m = cfgMutex();
    std.debug.assert(p == null or m.xMutexNotheld != null);
    return @intFromBool(p == null or m.xMutexNotheld.?(p) != 0);
}

comptime {
    if (config.sqlite_debug) {
        @export(&mutexHeld, .{ .name = "sqlite3_mutex_held" });
        @export(&mutexNotheld, .{ .name = "sqlite3_mutex_notheld" });
    }
}

// Pure-Zig unit testing is not feasible here: every routine dispatches through
// sqlite3GlobalConfig.mutex, which is populated only inside a linked, run-time-
// initialized SQLite. Behavior is validated by the TCL suite (mutex1/mutex2).
