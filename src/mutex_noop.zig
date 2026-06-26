//! Zig port of SQLite's no-op / debug mutex implementation (src/mutex_noop.c).
//!
//! This file supplies `sqlite3NoopMutex()`, the `sqlite3_mutex_methods` table
//! installed when mutexing is disabled at run time (e.g.
//! `sqlite3_config(SQLITE_CONFIG_SINGLETHREAD)`, or as the fallback inside
//! `mutex.c`). The mutexes here provide NO mutual exclusion; they are
//! place-holders for single-threaded use.
//!
//! ## Prod vs debug split (config-divergence)
//! Upstream this `.c` has two mutually exclusive bodies selected by
//! `SQLITE_DEBUG`. ONE Zig object is linked into BOTH builds, so we select the
//! body at comptime on `@import("config").sqlite_debug` — true in the
//! `configure --dev` testfixture (`-DSQLITE_DEBUG`), false in the production
//! `zig build` library — exactly reproducing the C `#ifndef/#ifdef SQLITE_DEBUG`
//! pair:
//!   * production (`!sqlite_debug`): the plain stubs. `xMutexAlloc` returns the
//!     constant fake pointer `(sqlite3_mutex*)8`; everything else is a no-op.
//!     The table's `xMutexHeld`/`xMutexNotheld` slots are null (0 in C).
//!   * testfixture (`sqlite_debug`): a *checking* implementation that tracks a
//!     per-mutex held count (`sqlite3_debug_mutex{ id, cnt }`) and `assert()`s
//!     correct enter/leave nesting. Those C asserts become `std.debug.assert`,
//!     which stays live in the testfixture's ReleaseSafe objects — the right
//!     behavior for a checking mutex. The table additionally carries the
//!     `xMutexHeld`/`xMutexNotheld` function pointers.
//!
//! ## Build config assumed
//! `SQLITE_MUTEX_OMIT` is off (THREADSAFE=1) — so the file is non-empty.
//! `SQLITE_MUTEX_NOOP` is NOT defined in either of this project's builds
//! (mutex_unix.c supplies `sqlite3DefaultMutex`), so the `#ifdef SQLITE_MUTEX_NOOP`
//! tail that would also define `sqlite3DefaultMutex` here is omitted — defining
//! it would duplicate the mutex_unix.c symbol. `SQLITE_ENABLE_API_ARMOR` is off,
//! so the armor bounds-check branches in `debugMutexAlloc`/`Free` are omitted,
//! matching the C preprocessor for this configuration.
//!
//! ## Coupling
//! `sqlite3_mutex_methods` is PUBLIC ABI (sqlite3.h) and is mirrored field-for-
//! field as an `extern struct`. `sqlite3_debug_mutex` is internal to this file
//! (others only hold an opaque `sqlite3_mutex*`), so its layout is private.

const std = @import("std");
const config = @import("config");

const SQLITE_OK: c_int = 0;

// Mutex type ids (sqlite3.h). Only these are referenced here.
const SQLITE_MUTEX_FAST: c_int = 0;
const SQLITE_MUTEX_RECURSIVE: c_int = 1;
const SQLITE_MUTEX_STATIC_VFS3: c_int = 13;

/// The public sqlite3_mutex_methods vtable layout (from sqlite3.h). Opaque
/// `sqlite3_mutex*` is modelled as `?*anyopaque`.
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

// =====================================================================
// Production: plain stub mutexes (C: #ifndef SQLITE_DEBUG)
// =====================================================================

fn noopMutexInit() callconv(.c) c_int {
    return SQLITE_OK;
}
fn noopMutexEnd() callconv(.c) c_int {
    return SQLITE_OK;
}
fn noopMutexAlloc(id: c_int) callconv(.c) ?*anyopaque {
    _ = id;
    // C returns the constant fake pointer (sqlite3_mutex*)8.
    return @ptrFromInt(8);
}
fn noopMutexFree(p: ?*anyopaque) callconv(.c) void {
    _ = p;
}
fn noopMutexEnter(p: ?*anyopaque) callconv(.c) void {
    _ = p;
}
fn noopMutexTry(p: ?*anyopaque) callconv(.c) c_int {
    _ = p;
    return SQLITE_OK;
}
fn noopMutexLeave(p: ?*anyopaque) callconv(.c) void {
    _ = p;
}

const noopMutex: MutexMethods = .{
    .xMutexInit = &noopMutexInit,
    .xMutexEnd = &noopMutexEnd,
    .xMutexAlloc = &noopMutexAlloc,
    .xMutexFree = &noopMutexFree,
    .xMutexEnter = &noopMutexEnter,
    .xMutexTry = &noopMutexTry,
    .xMutexLeave = &noopMutexLeave,
    .xMutexHeld = null,
    .xMutexNotheld = null,
};

// =====================================================================
// Testfixture: checking mutexes (C: #ifdef SQLITE_DEBUG)
// =====================================================================

extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;

/// The internal debug mutex object: id (mutex type) + cnt (entries without a
/// matching leave). Layout is private to this file.
const DebugMutex = extern struct {
    id: c_int,
    cnt: c_int,
};

/// Storage for the static mutexes (those whose id is not FAST/RECURSIVE).
/// C: `static sqlite3_debug_mutex aStatic[SQLITE_MUTEX_STATIC_VFS3 - 1];`
var aStatic: [SQLITE_MUTEX_STATIC_VFS3 - 1]DebugMutex = undefined;

/// For use inside asserts: true if held (or NULL). Static in C — no external
/// callers — so kept as a private helper.
fn debugMutexHeld(pX: ?*anyopaque) bool {
    const p: ?*DebugMutex = @ptrCast(@alignCast(pX));
    return p == null or p.?.cnt > 0;
}
fn debugMutexNotheld(pX: ?*anyopaque) bool {
    const p: ?*DebugMutex = @ptrCast(@alignCast(pX));
    return p == null or p.?.cnt == 0;
}

// The vtable slots want c_int-returning functions; wrap the bool helpers.
fn debugMutexHeldCb(pX: ?*anyopaque) callconv(.c) c_int {
    return @intFromBool(debugMutexHeld(pX));
}
fn debugMutexNotheldCb(pX: ?*anyopaque) callconv(.c) c_int {
    return @intFromBool(debugMutexNotheld(pX));
}

fn debugMutexInit() callconv(.c) c_int {
    return SQLITE_OK;
}
fn debugMutexEnd() callconv(.c) c_int {
    return SQLITE_OK;
}

fn debugMutexAlloc(id: c_int) callconv(.c) ?*anyopaque {
    var pNew: ?*DebugMutex = null;
    switch (id) {
        SQLITE_MUTEX_FAST, SQLITE_MUTEX_RECURSIVE => {
            pNew = @ptrCast(@alignCast(sqlite3Malloc(@sizeOf(DebugMutex))));
            if (pNew) |n| {
                n.id = id;
                n.cnt = 0;
            }
        },
        else => {
            // SQLITE_ENABLE_API_ARMOR is off, so the bounds check is omitted.
            pNew = &aStatic[@intCast(id - 2)];
            pNew.?.id = id;
        },
    }
    return @ptrCast(pNew);
}

fn debugMutexFree(pX: ?*anyopaque) callconv(.c) void {
    const p: *DebugMutex = @ptrCast(@alignCast(pX.?));
    std.debug.assert(p.cnt == 0);
    if (p.id == SQLITE_MUTEX_RECURSIVE or p.id == SQLITE_MUTEX_FAST) {
        sqlite3_free(p);
    } else {
        // SQLITE_ENABLE_API_ARMOR is off: nothing to do (a static mutex).
    }
}

fn debugMutexEnter(pX: ?*anyopaque) callconv(.c) void {
    const p: *DebugMutex = @ptrCast(@alignCast(pX.?));
    std.debug.assert(p.id == SQLITE_MUTEX_RECURSIVE or debugMutexNotheld(pX));
    p.cnt += 1;
}
fn debugMutexTry(pX: ?*anyopaque) callconv(.c) c_int {
    const p: *DebugMutex = @ptrCast(@alignCast(pX.?));
    std.debug.assert(p.id == SQLITE_MUTEX_RECURSIVE or debugMutexNotheld(pX));
    p.cnt += 1;
    return SQLITE_OK;
}

fn debugMutexLeave(pX: ?*anyopaque) callconv(.c) void {
    const p: *DebugMutex = @ptrCast(@alignCast(pX.?));
    std.debug.assert(debugMutexHeld(pX));
    p.cnt -= 1;
    std.debug.assert(p.id == SQLITE_MUTEX_RECURSIVE or debugMutexNotheld(pX));
}

const debugMutex: MutexMethods = .{
    .xMutexInit = &debugMutexInit,
    .xMutexEnd = &debugMutexEnd,
    .xMutexAlloc = &debugMutexAlloc,
    .xMutexFree = &debugMutexFree,
    .xMutexEnter = &debugMutexEnter,
    .xMutexTry = &debugMutexTry,
    .xMutexLeave = &debugMutexLeave,
    .xMutexHeld = &debugMutexHeldCb,
    .xMutexNotheld = &debugMutexNotheldCb,
};

// =====================================================================
// The one external symbol, identical name in both configs.
// =====================================================================

/// Return the no-op (or, under SQLITE_DEBUG, checking) mutex method table.
/// Referenced by mutex.c.
export fn sqlite3NoopMutex() callconv(.c) *const MutexMethods {
    return if (config.sqlite_debug) &debugMutex else &noopMutex;
}

// Note: the `#ifdef SQLITE_MUTEX_NOOP` definition of `sqlite3DefaultMutex` is
// intentionally NOT emitted — SQLITE_MUTEX_NOOP is undefined in both this
// project's builds, and mutex_unix.c provides that symbol.

test "noop mutex table is well formed (prod-shaped)" {
    if (config.sqlite_debug) return error.SkipZigTest;
    const m = sqlite3NoopMutex();
    try std.testing.expect(m.xMutexInit.?() == SQLITE_OK);
    try std.testing.expect(m.xMutexAlloc.?(SQLITE_MUTEX_FAST) == @as(?*anyopaque, @ptrFromInt(8)));
    try std.testing.expect(m.xMutexTry.?(null) == SQLITE_OK);
    try std.testing.expect(m.xMutexHeld == null);
}
