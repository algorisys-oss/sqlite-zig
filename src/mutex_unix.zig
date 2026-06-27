//! Zig port of SQLite's pthreads mutex backend (src/mutex_unix.c).
//!
//! This is the real mutual-exclusion backend used when SQLite is built
//! threadsafe on unix with pthreads (`SQLITE_MUTEX_PTHREADS`). It supplies
//! `sqlite3DefaultMutex()`, which returns the `sqlite3_mutex_methods` table
//! whose slots are the file-private `pthreadMutex*` routines, plus the global
//! `sqlite3MemoryBarrier()` (defined in this translation unit upstream).
//!
//! ## Why pthreads is the active backend in this build
//! build.zig compiles with `-DSQLITE_THREADSAFE=1` and defines neither
//! `SQLITE_MUTEX_NOOP` nor `SQLITE_MUTEX_OMIT`. On unix that selects
//! `SQLITE_MUTEX_PTHREADS` (sqliteInt.h's default-mutex logic), so mutex_unix.c
//! is the live backend and this is the correct file to port. (mutex_w32.c is
//! win32-only; mutex_noop.c — already ported — is the NOOP/disabled fallback.)
//!
//! ## Prod vs debug split (one object, two configs)
//! Upstream toggles per-mutex debug fields and the trace/assert bodies on
//! `SQLITE_DEBUG` (via `SQLITE_MUTEX_NREF`, since SQLITE_HOMEGROWN_RECURSIVE_MUTEX
//! is off here). One Zig object links into BOTH the production `zig build`
//! library (NDEBUG, no SQLITE_DEBUG) and the `configure --dev` testfixture
//! (SQLITE_DEBUG=1). We select the divergent behavior at comptime on
//! `@import("config").sqlite_debug`, reproducing the C `#ifdef` pairs exactly:
//!   * `SQLITE_MUTEX_NREF` == `config.sqlite_debug` (HOMEGROWN off).
//!     SQLITE_ENABLE_API_ARMOR is off in both builds, so the `id` field exists
//!     iff NREF, i.e. iff sqlite_debug; the API-armor bounds checks are omitted.
//!   * Under sqlite_debug the `sqlite3_mutex` struct carries `id/nRef/owner/
//!     trace`, the `pthreadMutexHeld/Notheld` checkers are real and installed in
//!     the table, and the enter/try/leave bodies maintain nRef/owner with the
//!     same asserts. In production the struct is just the bare `pthread_mutex_t`,
//!     the table's xMutexHeld/xMutexNotheld slots are null, and enter/try/leave
//!     are plain lock/trylock/unlock. The `printf` trace branches (SQLITE_DEBUG
//!     only) are reproduced via std.debug.print under sqlite_debug.
//!
//! The `sqlite3_mutex` struct is FILE-PRIVATE (every other module holds an
//! opaque `sqlite3_mutex*`), so we own its layout — no c_layout offsets needed.
//! Its leading member is a libc `pthread_mutex_t`, declared here as a correctly
//! sized extern struct (glibc x86-64: 40 bytes, align 8); the optional debug
//! tail follows it.
//!
//! ## SQLITE_HOMEGROWN_RECURSIVE_MUTEX
//! Not defined in this build, so the home-grown recursive-mutex branches are
//! omitted; we always use the platform's recursive mutex via
//! `pthread_mutexattr_settype(PTHREAD_MUTEX_RECURSIVE)`.

const std = @import("std");
const config = @import("config");

const SQLITE_OK: c_int = 0;
const SQLITE_BUSY: c_int = 5;

// Mutex type ids (sqlite3.h). FAST/RECURSIVE create new mutexes; the rest index
// the static array. STATIC ids run 2..13 (STATIC_MAIN..STATIC_VFS3).
const SQLITE_MUTEX_FAST: c_int = 0;
const SQLITE_MUTEX_RECURSIVE: c_int = 1;
const SQLITE_MUTEX_STATIC_VFS3: c_int = 13;
// Number of distinct static-mutex ids: 2..=13 inclusive => 12 entries.
const N_STATIC: usize = SQLITE_MUTEX_STATIC_VFS3 - 1; // 12

// SQLITE_MUTEX_NREF: the debug bookkeeping fields exist exactly under
// SQLITE_DEBUG here (HOMEGROWN off). One Zig object, comptime-selected.
const NREF = config.sqlite_debug;

// =====================================================================
// libc pthread bindings
// =====================================================================
// pthread_mutex_t is libc-defined. On glibc x86-64 it is 40 bytes, align 8,
// and PTHREAD_MUTEX_INITIALIZER is all-zeros — so a zero-initialized extern
// struct of the right size is a correct static initializer.
const pthread_mutex_t = extern struct {
    data: [40]u8 align(8) = @splat(0),
};
// pthread_mutexattr_t is 4 bytes on glibc; we only ever stack-allocate it.
const pthread_mutexattr_t = extern struct {
    data: [4]u8 align(4) = @splat(0),
};
// pthread_t is an opaque pointer-sized handle on glibc/linux.
const pthread_t = ?*anyopaque;

// PTHREAD_MUTEX_RECURSIVE == 1 on glibc/linux.
const PTHREAD_MUTEX_RECURSIVE: c_int = 1;

extern fn pthread_mutex_init(m: *pthread_mutex_t, attr: ?*const pthread_mutexattr_t) c_int;
extern fn pthread_mutex_lock(m: *pthread_mutex_t) c_int;
extern fn pthread_mutex_trylock(m: *pthread_mutex_t) c_int;
extern fn pthread_mutex_unlock(m: *pthread_mutex_t) c_int;
extern fn pthread_mutex_destroy(m: *pthread_mutex_t) c_int;
extern fn pthread_mutexattr_init(a: *pthread_mutexattr_t) c_int;
extern fn pthread_mutexattr_settype(a: *pthread_mutexattr_t, kind: c_int) c_int;
extern fn pthread_mutexattr_destroy(a: *pthread_mutexattr_t) c_int;
extern fn pthread_self() pthread_t;
extern fn pthread_equal(a: pthread_t, b: pthread_t) c_int;

// =====================================================================
// SQLite helpers resolved at link time
// =====================================================================
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;

// =====================================================================
// The public sqlite3_mutex_methods vtable layout (from sqlite3.h).
// =====================================================================
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
// The file-private sqlite3_mutex struct.
// =====================================================================
// Layout is internal to this file (others hold an opaque pointer), so it is
// comptime-conditional on NREF, exactly mirroring the C struct's #if blocks:
//   pthread_mutex_t mutex;
//   #if NREF (or API_ARMOR, off here): int id;
//   #if NREF: volatile int nRef; volatile pthread_t owner; int trace;
const Mutex = if (NREF) extern struct {
    mutex: pthread_mutex_t = .{},
    id: c_int = 0,
    nRef: c_int = 0,
    owner: pthread_t = null,
    trace: c_int = 0,
} else extern struct {
    mutex: pthread_mutex_t = .{},
};

inline fn cast(p: ?*anyopaque) *Mutex {
    return @ptrCast(@alignCast(p.?));
}

// =====================================================================
// Static mutex storage.
// =====================================================================
// C uses `static union staticMutex { sqlite3_mutex m; char aSpacer[128]; }
// aMutex[12]` aligned to 128 bytes so adjacent mutexes sit on distinct cache
// lines. We reproduce the cache-line padding with an over-aligned wrapper of
// 128 bytes per entry; default-init zeroes the pthread_mutex_t
// (== PTHREAD_MUTEX_INITIALIZER) and the debug fields. The `id` for entry i is
// i+2 (set at first use below, matching the C initializer SQLITE3_MUTEX_INIT(i+2)).
const StaticMutex = extern struct {
    m: Mutex = .{},
    _spacer: [128 - @sizeOf(Mutex)]u8 = @splat(0),
};
var aMutex: [N_STATIC]StaticMutex align(128) = @splat(.{});

// =====================================================================
// Memory barrier (defined in mutex_unix.c upstream; non-static — must export).
// =====================================================================
// SQLITE_MEMORY_BARRIER is not defined; upstream falls back to
// __sync_synchronize() on GCC — a full (seq_cst) memory fence. Current Zig has
// no @fence builtin, so we emit an equivalent full barrier via a seq_cst RMW on
// a dummy global (lowers to an `mfence`/`lock`-prefixed op like __sync_synchronize).
var barrier_dummy: usize = 0;
export fn sqlite3MemoryBarrier() callconv(.c) void {
    _ = @atomicRmw(usize, &barrier_dummy, .Xchg, 0, .seq_cst);
}

// =====================================================================
// Debug-only assert helpers (C: #if !defined(NDEBUG) || defined(SQLITE_DEBUG)).
// =====================================================================
fn pthreadMutexHeld(p: *Mutex) bool {
    if (!NREF) return true;
    return p.nRef != 0 and pthread_equal(p.owner, pthread_self()) != 0;
}
fn pthreadMutexNotheld(p: *Mutex) bool {
    if (!NREF) return true;
    return p.nRef == 0 or pthread_equal(p.owner, pthread_self()) == 0;
}

// c_int-returning vtable wrappers (only installed under SQLITE_DEBUG).
fn pthreadMutexHeldCb(pX: ?*anyopaque) callconv(.c) c_int {
    return @intFromBool(pthreadMutexHeld(cast(pX)));
}
fn pthreadMutexNotheldCb(pX: ?*anyopaque) callconv(.c) c_int {
    return @intFromBool(pthreadMutexNotheld(cast(pX)));
}

// =====================================================================
// Init / End.
// =====================================================================
fn pthreadMutexInit() callconv(.c) c_int {
    return SQLITE_OK;
}
fn pthreadMutexEnd() callconv(.c) c_int {
    return SQLITE_OK;
}

// =====================================================================
// Alloc.
// =====================================================================
fn pthreadMutexAlloc(iType: c_int) callconv(.c) ?*anyopaque {
    var p: ?*Mutex = null;
    switch (iType) {
        SQLITE_MUTEX_RECURSIVE => {
            p = @ptrCast(@alignCast(sqlite3MallocZero(@sizeOf(Mutex))));
            if (p) |m| {
                // Use a recursive mutex (HOMEGROWN off).
                var recursiveAttr: pthread_mutexattr_t = .{};
                _ = pthread_mutexattr_init(&recursiveAttr);
                _ = pthread_mutexattr_settype(&recursiveAttr, PTHREAD_MUTEX_RECURSIVE);
                _ = pthread_mutex_init(&m.mutex, &recursiveAttr);
                _ = pthread_mutexattr_destroy(&recursiveAttr);
                if (NREF) m.id = SQLITE_MUTEX_RECURSIVE;
            }
        },
        SQLITE_MUTEX_FAST => {
            p = @ptrCast(@alignCast(sqlite3MallocZero(@sizeOf(Mutex))));
            if (p) |m| {
                _ = pthread_mutex_init(&m.mutex, null);
                if (NREF) m.id = SQLITE_MUTEX_FAST;
            }
        },
        else => {
            // SQLITE_ENABLE_API_ARMOR is off, so no bounds check: a static mutex.
            p = &aMutex[@intCast(iType - 2)].m;
            if (NREF) p.?.id = iType;
        },
    }
    if (NREF) std.debug.assert(p == null or p.?.id == iType);
    return @ptrCast(p);
}

// =====================================================================
// Free.
// =====================================================================
fn pthreadMutexFree(pX: ?*anyopaque) callconv(.c) void {
    const p = cast(pX);
    if (NREF) std.debug.assert(p.nRef == 0);
    // SQLITE_ENABLE_API_ARMOR is off: always treat as a freeable dynamic mutex.
    _ = pthread_mutex_destroy(&p.mutex);
    sqlite3_free(p);
}

// =====================================================================
// Enter / Try / Leave.
// =====================================================================
fn pthreadMutexEnter(pX: ?*anyopaque) callconv(.c) void {
    const p = cast(pX);
    if (NREF) std.debug.assert(p.id == SQLITE_MUTEX_RECURSIVE or pthreadMutexNotheld(p));

    // Built-in recursive mutexes (HOMEGROWN off).
    _ = pthread_mutex_lock(&p.mutex);
    if (NREF) {
        std.debug.assert(p.nRef > 0 or p.owner == null);
        p.owner = pthread_self();
        p.nRef += 1;
    }

    if (config.sqlite_debug) {
        if (p.trace != 0) {
            std.debug.print("enter mutex {*} ({d}) with nRef={d}\n", .{ p, p.trace, p.nRef });
        }
    }
}

fn pthreadMutexTry(pX: ?*anyopaque) callconv(.c) c_int {
    const p = cast(pX);
    var rc: c_int = undefined;
    if (NREF) std.debug.assert(p.id == SQLITE_MUTEX_RECURSIVE or pthreadMutexNotheld(p));

    // Built-in recursive mutexes (HOMEGROWN off).
    if (pthread_mutex_trylock(&p.mutex) == 0) {
        if (NREF) {
            p.owner = pthread_self();
            p.nRef += 1;
        }
        rc = SQLITE_OK;
    } else {
        rc = SQLITE_BUSY;
    }

    if (config.sqlite_debug) {
        if (rc == SQLITE_OK and p.trace != 0) {
            std.debug.print("enter mutex {*} ({d}) with nRef={d}\n", .{ p, p.trace, p.nRef });
        }
    }
    return rc;
}

fn pthreadMutexLeave(pX: ?*anyopaque) callconv(.c) void {
    const p = cast(pX);
    if (NREF) std.debug.assert(pthreadMutexHeld(p));
    if (NREF) {
        p.nRef -= 1;
        if (p.nRef == 0) p.owner = null;
    }
    if (NREF) std.debug.assert(p.nRef == 0 or p.id == SQLITE_MUTEX_RECURSIVE);

    // HOMEGROWN off: always unlock.
    _ = pthread_mutex_unlock(&p.mutex);

    if (config.sqlite_debug) {
        if (p.trace != 0) {
            std.debug.print("leave mutex {*} ({d}) with nRef={d}\n", .{ p, p.trace, p.nRef });
        }
    }
}

// =====================================================================
// The exported backend accessor.
// =====================================================================
// Table is config-invariant in shape; only the Held/Notheld slots differ
// (null in production, real checkers under SQLITE_DEBUG), mirroring the C
// `#ifdef SQLITE_DEBUG` tail of the static initializer.
const sMutex: MutexMethods = .{
    .xMutexInit = &pthreadMutexInit,
    .xMutexEnd = &pthreadMutexEnd,
    .xMutexAlloc = &pthreadMutexAlloc,
    .xMutexFree = &pthreadMutexFree,
    .xMutexEnter = &pthreadMutexEnter,
    .xMutexTry = &pthreadMutexTry,
    .xMutexLeave = &pthreadMutexLeave,
    .xMutexHeld = if (config.sqlite_debug) &pthreadMutexHeldCb else null,
    .xMutexNotheld = if (config.sqlite_debug) &pthreadMutexNotheldCb else null,
};

/// Return the pthreads mutex method table. Referenced by mutex.c.
export fn sqlite3DefaultMutex() callconv(.c) *const MutexMethods {
    return &sMutex;
}

comptime {
    // Layout guards: pthread_mutex_t must be the libc size/align, or adjacent
    // memory (the debug tail / the next static mutex) would be corrupted.
    std.debug.assert(@sizeOf(pthread_mutex_t) == 40);
    std.debug.assert(@alignOf(pthread_mutex_t) == 8);
    // The static array must hold exactly the STATIC_* id range.
    std.debug.assert(N_STATIC == 12);
    // Each static entry occupies a full 128-byte cache-line slot.
    std.debug.assert(@sizeOf(StaticMutex) == 128);
}

test "static mutex count and id range" {
    try std.testing.expectEqual(@as(usize, 12), N_STATIC);
    // Production-shape table exposes null held/notheld; debug exposes checkers.
    const t = sqlite3DefaultMutex();
    if (config.sqlite_debug) {
        try std.testing.expect(t.xMutexHeld != null);
    } else {
        try std.testing.expect(t.xMutexHeld == null);
    }
}
