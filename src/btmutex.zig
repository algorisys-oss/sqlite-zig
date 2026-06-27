//! btmutex.zig — port of SQLite's src/btmutex.c (Btree mutex management).
//!
//! Original blessing (public domain):
//!
//!    May you do good and not evil.
//!    May you find forgiveness for yourself and forgive others.
//!    May you share freely, never taking more than you give.
//!
//! This module manages the BtShared mutexes that serialize access to a
//! shared-cache b-tree. It is compiled in the SQLITE_THREADSAFE>0 +
//! !SQLITE_OMIT_SHARED_CACHE configuration (this build sets
//! `-DSQLITE_THREADSAFE=1` in build.zig). The SQLITE_THREADSAFE==0 variant
//! (a couple of trivial BtShared.db assignments) is NOT ported because this
//! build never uses it.
//!
//! btree.c is still C, so Btree / BtShared / BtCursor are opaque ABI structs
//! reached through ground-truth field offsets (src/c_layout.zig, falling back
//! to probe-verified literals). The four assert-only routines
//! (sqlite3BtreeHoldsMutex, sqlite3BtreeHoldsAllMutexes, sqlite3SchemaMutexHeld)
//! mirror C's `#ifndef NDEBUG` gating: they are `@export`ed only when
//! `config.sqlite_debug` is set (the testfixture config), matching production
//! (NDEBUG => those symbols absent).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── Result codes ───────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;

// ═══ ground-truth offsets ════════════════════════════════════════════════════
// All probe-verified identical between prod (NDEBUG) and tf (SQLITE_DEBUG).

// Btree
const Btree_db_off: usize = if (@hasDecl(L, "Btree_db")) L.Btree_db else 0;
const Btree_pBt_off: usize = if (@hasDecl(L, "Btree_pBt")) L.Btree_pBt else 8;
const Btree_sharable_off: usize = if (@hasDecl(L, "Btree_sharable")) L.Btree_sharable else 17;
const Btree_locked_off: usize = if (@hasDecl(L, "Btree_locked")) L.Btree_locked else 18;
const Btree_wantToLock_off: usize = if (@hasDecl(L, "Btree_wantToLock")) L.Btree_wantToLock else 20;
const Btree_pNext_off: usize = if (@hasDecl(L, "Btree_pNext")) L.Btree_pNext else 32;
const Btree_pPrev_off: usize = if (@hasDecl(L, "Btree_pPrev")) L.Btree_pPrev else 40;

// BtShared
const BtShared_db_off: usize = if (@hasDecl(L, "BtShared_db")) L.BtShared_db else 8;
const BtShared_mutex_off: usize = if (@hasDecl(L, "BtShared_mutex")) L.BtShared_mutex else 88;

// BtCursor
const BtCursor_pBtree_off: usize = if (@hasDecl(L, "BtCursor_pBtree")) L.BtCursor_pBtree else 8;

// sqlite3
const sqlite3_mutex_off: usize = if (@hasDecl(L, "sqlite3_mutex")) L.sqlite3_mutex else 24;
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_noSharedCache_off: usize = if (@hasDecl(L, "sqlite3_noSharedCache")) L.sqlite3_noSharedCache else 111;
const sqlite3_pVfs_off: usize = if (@hasDecl(L, "sqlite3_pVfs")) L.sqlite3_pVfs else 0;

// Db
const Db_pBt_off: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

// ═══ raw memory helpers ══════════════════════════════════════════════════════
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, off: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + off);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, off: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + off);
    q.* = v;
}

// ─── Btree accessors ─────────────────────────────────────────────────────────
inline fn btDb(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Btree_db_off);
}
inline fn btPBt(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Btree_pBt_off);
}
inline fn btSharable(p: ?*anyopaque) u8 {
    return rd(u8, p, Btree_sharable_off);
}
inline fn btLocked(p: ?*anyopaque) u8 {
    return rd(u8, p, Btree_locked_off);
}
inline fn btSetLocked(p: ?*anyopaque, v: u8) void {
    wr(u8, p, Btree_locked_off, v);
}
inline fn btWantToLock(p: ?*anyopaque) c_int {
    return rd(c_int, p, Btree_wantToLock_off);
}
inline fn btSetWantToLock(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Btree_wantToLock_off, v);
}
inline fn btPNext(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Btree_pNext_off);
}
inline fn btPPrev(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Btree_pPrev_off);
}

// ─── BtShared accessors ──────────────────────────────────────────────────────
inline fn bsMutex(pBt: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pBt, BtShared_mutex_off);
}
inline fn bsDb(pBt: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pBt, BtShared_db_off);
}
inline fn bsSetDb(pBt: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, pBt, BtShared_db_off, v);
}

// ─── BtCursor accessors ──────────────────────────────────────────────────────
inline fn curPBtree(pCur: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pCur, BtCursor_pBtree_off);
}

// ─── sqlite3 / Db accessors ──────────────────────────────────────────────────
inline fn dbMutex(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_mutex_off);
}
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rd(c_int, db, sqlite3_nDb_off);
}
inline fn dbADb(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_aDb_off);
}
inline fn dbNoSharedCache(db: ?*anyopaque) u8 {
    return rd(u8, db, sqlite3_noSharedCache_off);
}
inline fn dbSetNoSharedCache(db: ?*anyopaque, v: u8) void {
    wr(u8, db, sqlite3_noSharedCache_off, v);
}
inline fn dbPVfs(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_pVfs_off);
}
/// db->aDb[i].pBt
inline fn dbADbPBt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const aDb = dbADb(db) orelse return null;
    const elem = base(aDb) + @as(usize, @intCast(i)) * sizeof_Db;
    const q: *align(1) const ?*anyopaque = @ptrCast(elem + Db_pBt_off);
    return q.*;
}

// ─── mutex ABI (mutex.c is ported; these are C-ABI entry points) ─────────────
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3_mutex_try(m: ?*anyopaque) c_int;
// Debug-only predicates (exist only in SQLITE_DEBUG builds).
extern fn sqlite3_mutex_held(m: ?*anyopaque) c_int;
extern fn sqlite3_mutex_notheld(m: ?*anyopaque) c_int;
// btree.c (still C) helper.
extern fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) c_int;

inline fn dbg(comptime cond: bool) bool {
    return config.sqlite_debug and cond;
}
inline fn mutexHeld(m: ?*anyopaque) bool {
    return sqlite3_mutex_held(m) != 0;
}
inline fn mutexNotheld(m: ?*anyopaque) bool {
    return sqlite3_mutex_notheld(m) != 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// static helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Obtain the BtShared mutex associated with B-Tree handle p. Also set
/// BtShared.db to the database handle associated with p and the p->locked
/// boolean to true.
fn lockBtreeMutex(p: ?*anyopaque) void {
    const pBt = btPBt(p);
    if (config.sqlite_debug) {
        std.debug.assert(btLocked(p) == 0);
        std.debug.assert(mutexNotheld(bsMutex(pBt)));
        std.debug.assert(mutexHeld(dbMutex(btDb(p))));
    }
    sqlite3_mutex_enter(bsMutex(pBt));
    bsSetDb(pBt, btDb(p));
    btSetLocked(p, 1);
}

/// Release the BtShared mutex associated with B-Tree handle p and clear the
/// p->locked boolean.
fn unlockBtreeMutex(p: ?*anyopaque) void {
    const pBt = btPBt(p);
    if (config.sqlite_debug) {
        std.debug.assert(btLocked(p) == 1);
        std.debug.assert(mutexHeld(bsMutex(pBt)));
        std.debug.assert(mutexHeld(dbMutex(btDb(p))));
        std.debug.assert(btDb(p) == bsDb(pBt));
    }
    sqlite3_mutex_leave(bsMutex(pBt));
    btSetLocked(p, 0);
}

/// Helper for sqlite3BtreeEnter(): the seldom-used careful ascending-order
/// lock procedure, factored out to keep the common path cheap.
fn btreeLockCarefully(p: ?*anyopaque) void {
    // In most cases we can acquire the lock we want without going through
    // the ascending lock procedure below. Just be sure not to block.
    if (sqlite3_mutex_try(bsMutex(btPBt(p))) == SQLITE_OK) {
        bsSetDb(btPBt(p), btDb(p));
        btSetLocked(p, 1);
        return;
    }

    // To avoid deadlock, first release all locks with a larger BtShared
    // address. Then acquire our lock. Then reacquire the other BtShared
    // locks that we used to hold, in ascending order.
    var pLater = btPNext(p);
    while (pLater) |later| : (pLater = btPNext(later)) {
        if (config.sqlite_debug) {
            std.debug.assert(btSharable(later) != 0);
            std.debug.assert(btPNext(later) == null or
                @intFromPtr(btPBt(btPNext(later))) > @intFromPtr(btPBt(later)));
            std.debug.assert(btLocked(later) == 0 or btWantToLock(later) > 0);
        }
        if (btLocked(later) != 0) {
            unlockBtreeMutex(later);
        }
    }
    lockBtreeMutex(p);
    pLater = btPNext(p);
    while (pLater) |later| : (pLater = btPNext(later)) {
        if (btWantToLock(later) != 0) {
            lockBtreeMutex(later);
        }
    }
}

/// Enter the mutex on every Btree associated with a database connection.
/// Mutexes are entered in ascending order by BtShared pointer to avoid
/// deadlock between two threads that share two or more btrees.
fn btreeEnterAll(db: ?*anyopaque) void {
    if (config.sqlite_debug) std.debug.assert(mutexHeld(dbMutex(db)));
    var skipOk: u8 = 1;
    var i: c_int = 0;
    const n = dbNDb(db);
    while (i < n) : (i += 1) {
        const p = dbADbPBt(db, i);
        if (p != null and btSharable(p) != 0) {
            sqlite3BtreeEnter(p);
            skipOk = 0;
        }
    }
    dbSetNoSharedCache(db, skipOk);
}

fn btreeLeaveAll(db: ?*anyopaque) void {
    if (config.sqlite_debug) std.debug.assert(mutexHeld(dbMutex(db)));
    var i: c_int = 0;
    const n = dbNDb(db);
    while (i < n) : (i += 1) {
        const p = dbADbPBt(db, i);
        if (p != null) sqlite3BtreeLeave(p);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// exported C-ABI entry points
// ═══════════════════════════════════════════════════════════════════════════

/// Enter a (recursive) mutex on the given Btree object. A no-op for
/// non-sharable btrees; otherwise reference-counted via Btree.wantToLock.
pub export fn sqlite3BtreeEnter(p: ?*anyopaque) callconv(.c) void {
    if (config.sqlite_debug) {
        // The list connected by pNext/pPrev is sorted ascending by pBt, all
        // elements belong to the same connection, and only shared btrees are
        // on the list.
        std.debug.assert(btPNext(p) == null or
            @intFromPtr(btPBt(btPNext(p))) > @intFromPtr(btPBt(p)));
        std.debug.assert(btPPrev(p) == null or
            @intFromPtr(btPBt(btPPrev(p))) < @intFromPtr(btPBt(p)));
        std.debug.assert(btPNext(p) == null or btDb(btPNext(p)) == btDb(p));
        std.debug.assert(btPPrev(p) == null or btDb(btPPrev(p)) == btDb(p));
        std.debug.assert(btSharable(p) != 0 or (btPNext(p) == null and btPPrev(p) == null));

        // Locking consistency.
        std.debug.assert(btLocked(p) == 0 or btWantToLock(p) > 0);
        std.debug.assert(btSharable(p) != 0 or btWantToLock(p) == 0);

        // We should already hold a lock on the database connection.
        std.debug.assert(mutexHeld(dbMutex(btDb(p))));

        // Unless sharable and unlocked, BtShared.db should already be set.
        std.debug.assert((btLocked(p) == 0 and btSharable(p) != 0) or bsDb(btPBt(p)) == btDb(p));
    }

    if (btSharable(p) == 0) return;
    btSetWantToLock(p, btWantToLock(p) + 1);
    if (btLocked(p) != 0) return;
    btreeLockCarefully(p);
}

/// Exit the recursive mutex on a Btree.
pub export fn sqlite3BtreeLeave(p: ?*anyopaque) callconv(.c) void {
    if (config.sqlite_debug) std.debug.assert(mutexHeld(dbMutex(btDb(p))));
    if (btSharable(p) != 0) {
        if (config.sqlite_debug) std.debug.assert(btWantToLock(p) > 0);
        btSetWantToLock(p, btWantToLock(p) - 1);
        if (btWantToLock(p) == 0) {
            unlockBtreeMutex(p);
        }
    }
}

/// Enter the mutex on every Btree associated with a database connection.
pub export fn sqlite3BtreeEnterAll(db: ?*anyopaque) callconv(.c) void {
    if (dbNoSharedCache(db) == 0) btreeEnterAll(db);
}

/// Leave the mutex on every Btree associated with a database connection.
pub export fn sqlite3BtreeLeaveAll(db: ?*anyopaque) callconv(.c) void {
    if (dbNoSharedCache(db) == 0) btreeLeaveAll(db);
}

// ─── #ifndef SQLITE_OMIT_INCRBLOB ────────────────────────────────────────────

/// Enter a mutex on a Btree given a cursor owned by that Btree. Used by
/// incremental I/O. Enter() is required whenever OMIT_SHARED_CACHE is not
/// defined, regardless of threadsafety.
pub export fn sqlite3BtreeEnterCursor(pCur: ?*anyopaque) callconv(.c) void {
    sqlite3BtreeEnter(curPBtree(pCur));
}

/// Leave the mutex on a Btree given a cursor owned by that Btree. Only
/// required by threadsafe builds (this one is).
pub export fn sqlite3BtreeLeaveCursor(pCur: ?*anyopaque) callconv(.c) void {
    sqlite3BtreeLeave(curPBtree(pCur));
}

// ═══════════════════════════════════════════════════════════════════════════
// assert-only routines (C: `#ifndef NDEBUG`) — exported only under SQLITE_DEBUG
// ═══════════════════════════════════════════════════════════════════════════

/// True if the BtShared mutex is held on the btree, or if the b-tree is not
/// marked sharable. Used only from within assert() statements.
fn btreeHoldsMutex(p: ?*anyopaque) callconv(.c) c_int {
    std.debug.assert(btSharable(p) == 0 or btLocked(p) == 0 or btWantToLock(p) > 0);
    std.debug.assert(btSharable(p) == 0 or btLocked(p) == 0 or btDb(p) == bsDb(btPBt(p)));
    std.debug.assert(btSharable(p) == 0 or btLocked(p) == 0 or mutexHeld(bsMutex(btPBt(p))));
    std.debug.assert(btSharable(p) == 0 or btLocked(p) == 0 or mutexHeld(dbMutex(btDb(p))));
    return @intFromBool(btSharable(p) == 0 or btLocked(p) != 0);
}

/// True if the current thread holds the db connection mutex and all required
/// BtShared mutexes. Used inside assert() statements only.
fn btreeHoldsAllMutexes(db: ?*anyopaque) callconv(.c) c_int {
    if (!mutexHeld(dbMutex(db))) {
        return 0;
    }
    var i: c_int = 0;
    const n = dbNDb(db);
    while (i < n) : (i += 1) {
        const p = dbADbPBt(db, i);
        if (p != null and btSharable(p) != 0 and
            (btWantToLock(p) == 0 or !mutexHeld(bsMutex(btPBt(p)))))
        {
            return 0;
        }
    }
    return 1;
}

/// True if the correct mutexes are held for accessing db->aDb[iDb].pSchema:
///   (1) the mutex on db, and
///   (2) if iDb!=1, the mutex on db->aDb[iDb].pBt.
/// If pSchema is non-null, iDb is computed from it via sqlite3SchemaToIndex().
fn schemaMutexHeld(db: ?*anyopaque, iDb_in: c_int, pSchema: ?*anyopaque) callconv(.c) c_int {
    std.debug.assert(db != null);
    if (dbPVfs(db) == null and dbNDb(db) == 0) return 1;
    var iDb = iDb_in;
    if (pSchema != null) iDb = sqlite3SchemaToIndex(db, pSchema);
    std.debug.assert(iDb >= 0 and iDb < dbNDb(db));
    if (!mutexHeld(dbMutex(db))) return 0;
    if (iDb == 1) return 1;
    const p = dbADbPBt(db, iDb);
    std.debug.assert(p != null);
    return @intFromBool(btSharable(p) == 0 or btLocked(p) == 1);
}

comptime {
    if (config.sqlite_debug) {
        @export(&btreeHoldsMutex, .{ .name = "sqlite3BtreeHoldsMutex" });
        @export(&btreeHoldsAllMutexes, .{ .name = "sqlite3BtreeHoldsAllMutexes" });
        @export(&schemaMutexHeld, .{ .name = "sqlite3SchemaMutexHeld" });
    }
}

// Behavior is validated by the TCL suite (the shared-cache / mutex tests) once
// linked into a running SQLite; pure-Zig unit testing is not feasible because
// every routine dereferences live Btree/BtShared/sqlite3 structures.
