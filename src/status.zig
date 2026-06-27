//! Zig port of SQLite's sqlite3_status() interface (src/status.c).
//!
//! Implements the global status counters (sqlite3Stat) and the per-connection
//! status queries. The exported symbols (the non-static externals of status.c):
//!   - sqlite3StatusValue
//!   - sqlite3StatusUp
//!   - sqlite3StatusDown
//!   - sqlite3StatusHighwater
//!   - sqlite3_status64
//!   - sqlite3_status
//!   - sqlite3LookasideUsed
//!   - sqlite3_db_status64
//!   - sqlite3_db_status
//! The static helper countLookasideSlots() and the module-private status vector
//! (sqlite3Stat / statMutex) are internal — we own those layouts.
//!
//! Build config assumed (true in both this project's prod and --dev builds):
//!   - SQLITE_PTRSIZE>4 (x86-64) => sqlite3StatValueType is sqlite3_int64.
//!   - SQLITE_OMIT_WSD off => the C `wsdStat` macro is just the real global
//!     `sqlite3Stat`; we keep an equivalent module-global vector here.
//!   - SQLITE_OMIT_TWOSIZE_LOOKASIDE off => the pSmallInit/pSmallFree lists exist.
//!   - SQLITE_OMIT_SHARED_CACHE off => sqlite3BtreeEnterAll/LeaveAll/
//!     ConnectionCount are real functions (not macro no-ops).
//!   - SQLITE_ENABLE_API_ARMOR off => the armor null-pointer guards are not
//!     emitted (matches both configs).
//!   - SQLITE_THREADSAFE=1 => the mutex calls are real.
//!
//! Couplings: reads internal sqlite3 / Lookaside / Db / Schema / Hash fields at
//! ground-truth offsets via c_layout. We do not mirror those structs; we poke
//! ints/pointers at offsets. Assertions are elided (NDEBUG in prod; --dev keeps
//! its own C asserts elsewhere — here we just reproduce behavior).

const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_MISUSE: c_int = 21; // SQLITE_MISUSE_BKPT collapses to this in prod

// DBSTATUS verbs (from sqlite3.h).
const SQLITE_DBSTATUS_LOOKASIDE_USED: c_int = 0;
const SQLITE_DBSTATUS_CACHE_USED: c_int = 1;
const SQLITE_DBSTATUS_SCHEMA_USED: c_int = 2;
const SQLITE_DBSTATUS_STMT_USED: c_int = 3;
const SQLITE_DBSTATUS_LOOKASIDE_HIT: c_int = 4;
const SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE: c_int = 5;
const SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL: c_int = 6;
const SQLITE_DBSTATUS_CACHE_HIT: c_int = 7;
const SQLITE_DBSTATUS_CACHE_MISS: c_int = 8;
const SQLITE_DBSTATUS_CACHE_WRITE: c_int = 9;
const SQLITE_DBSTATUS_DEFERRED_FKS: c_int = 10;
const SQLITE_DBSTATUS_CACHE_USED_SHARED: c_int = 11;
const SQLITE_DBSTATUS_CACHE_SPILL: c_int = 12;
const SQLITE_DBSTATUS_TEMPBUF_SPILL: c_int = 13;

// --- External helpers resolved at link time ---
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;
extern fn sqlite3Pcache1Mutex() ?*anyopaque;
extern fn sqlite3MallocMutex() ?*anyopaque;
extern fn sqlite3_msize(p: ?*anyopaque) u64;

extern fn sqlite3BtreeEnterAll(db: ?*anyopaque) void;
extern fn sqlite3BtreeLeaveAll(db: ?*anyopaque) void;
extern fn sqlite3BtreePager(pBt: ?*anyopaque) ?*anyopaque;
extern fn sqlite3BtreeConnectionCount(pBt: ?*anyopaque) c_int;
extern fn sqlite3BtreeGetPageSize(pBt: ?*anyopaque) c_int;
extern fn sqlite3PagerMemUsed(pPager: ?*anyopaque) c_int;
extern fn sqlite3PagerCacheStat(pPager: ?*anyopaque, op: c_int, reset: c_int, pnRet: *u64) void;
extern fn sqlite3DeleteTrigger(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DeleteTable(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3VdbeDelete(p: ?*anyopaque) void;

// SQLITE_OMIT_WSD is off, so the C `sqlite3Config` global is the literal
// sqlite3GlobalConfig. We read its `m.xRoundup` function pointer through a
// ground-truth offset (config-invariant — both `m` and the mem_methods layout
// are public-ABI, but the offset of `m` within Sqlite3Config differs by config).
extern var sqlite3Config: u8;
const XRoundupFn = ?*const fn (c_int) callconv(.c) c_int;
inline fn cfgRoundup(n: c_int) c_int {
    const base: [*]const u8 = @ptrCast(&sqlite3Config);
    const p: *align(1) const XRoundupFn = @ptrCast(base + L.Sqlite3Config_m_xRoundup);
    return p.*.?(n);
}

// ---------------------------------------------------------------------------
// Global status vector. We own this layout (the C struct is module-static).
// SQLITE_PTRSIZE>4 => values are i64.
// ---------------------------------------------------------------------------
const N_STAT = 10;
var nowValue: [N_STAT]i64 = @splat(0);
var mxValue: [N_STAT]i64 = @splat(0);

/// Return the current value of a status parameter. Caller holds the mutex.
export fn sqlite3StatusValue(op: c_int) callconv(.c) i64 {
    return nowValue[@intCast(op)];
}

/// Add N to a status record, adjusting the high-water mark up if needed.
export fn sqlite3StatusUp(op: c_int, N: c_int) callconv(.c) void {
    const i: usize = @intCast(op);
    nowValue[i] += N;
    if (nowValue[i] > mxValue[i]) {
        mxValue[i] = nowValue[i];
    }
}

/// Lower the current value by N (N>=0). High-water mark unchanged.
export fn sqlite3StatusDown(op: c_int, N: c_int) callconv(.c) void {
    nowValue[@intCast(op)] -= N;
}

/// Adjust the high-water mark if X exceeds it. X>=0.
export fn sqlite3StatusHighwater(op: c_int, X: c_int) callconv(.c) void {
    const newValue: i64 = X;
    const i: usize = @intCast(op);
    if (newValue > mxValue[i]) {
        mxValue[i] = newValue;
    }
}

/// statMutex[]: 0 => malloc mutex, 1 => pcache1 mutex.
const statMutex = [N_STAT]u8{ 0, 1, 1, 0, 0, 0, 0, 1, 0, 0 };

/// Query a global status parameter.
export fn sqlite3_status64(
    op: c_int,
    pCurrent: ?*i64,
    pHighwater: ?*i64,
    resetFlag: c_int,
) callconv(.c) c_int {
    if (op < 0 or op >= N_STAT) {
        return SQLITE_MISUSE;
    }
    const i: usize = @intCast(op);
    const pMutex = if (statMutex[i] != 0) sqlite3Pcache1Mutex() else sqlite3MallocMutex();
    sqlite3_mutex_enter(pMutex);
    pCurrent.?.* = nowValue[i];
    pHighwater.?.* = mxValue[i];
    if (resetFlag != 0) {
        mxValue[i] = nowValue[i];
    }
    sqlite3_mutex_leave(pMutex);
    return SQLITE_OK;
}

/// 32-bit variant of sqlite3_status64().
export fn sqlite3_status(
    op: c_int,
    pCurrent: ?*c_int,
    pHighwater: ?*c_int,
    resetFlag: c_int,
) callconv(.c) c_int {
    var iCur: i64 = 0;
    var iHwtr: i64 = 0;
    const rc = sqlite3_status64(op, &iCur, &iHwtr, resetFlag);
    if (rc == 0) {
        pCurrent.?.* = @truncate(iCur);
        pHighwater.?.* = @truncate(iHwtr);
    }
    return rc;
}

// ---------------------------------------------------------------------------
// Per-connection field accessors. We poke fields of the opaque sqlite3 / nested
// Lookaside struct at ground-truth offsets.
// ---------------------------------------------------------------------------
inline fn dbBase(db: ?*anyopaque) [*]u8 {
    return @ptrCast(db.?);
}
inline fn dbPtr(comptime T: type, db: ?*anyopaque, comptime off: usize) *align(1) T {
    return @ptrCast(dbBase(db) + off);
}

/// Walk a LookasideSlot linked list and count its nodes. The list nodes are
/// `struct LookasideSlot { LookasideSlot *pNext; }` — pNext is at offset 0.
fn countLookasideSlots(p_in: ?*anyopaque) u32 {
    var cnt: u32 = 0;
    var p = p_in;
    while (p) |node| {
        const next: *align(1) ?*anyopaque = @ptrCast(@as([*]u8, @ptrCast(node)));
        p = next.*;
        cnt +%= 1;
    }
    return cnt;
}

/// Number of outstanding lookaside slots; *pHighwater (if non-null) gets the
/// peak usage. Reads db->lookaside.{pInit,pFree,pSmallInit,pSmallFree,nSlot}.
export fn sqlite3LookasideUsed(db: ?*anyopaque, pHighwater: ?*c_int) callconv(.c) c_int {
    const pInit = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pInit).*;
    const pFree = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pFree).*;
    var nInit = countLookasideSlots(pInit);
    var nFree = countLookasideSlots(pFree);
    // SQLITE_OMIT_TWOSIZE_LOOKASIDE is off.
    const pSmallInit = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pSmallInit).*;
    const pSmallFree = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pSmallFree).*;
    nInit +%= countLookasideSlots(pSmallInit);
    nFree +%= countLookasideSlots(pSmallFree);

    const nSlot = dbPtr(u32, db, L.sqlite3_lookaside_nSlot).*;
    if (pHighwater) |h| h.* = @bitCast(nSlot -% nInit);
    return @bitCast(nSlot -% (nInit +% nFree));
}

/// Query status information for a single database connection.
export fn sqlite3_db_status64(
    db: ?*anyopaque,
    op_in: c_int,
    pCurrent: ?*i64,
    pHighwtr: ?*i64,
    resetFlag: c_int,
) callconv(.c) c_int {
    var op = op_in;
    var rc: c_int = SQLITE_OK;
    // SQLITE_ENABLE_API_ARMOR is off => no safety-check guard.

    const dbMutex = dbPtr(?*anyopaque, db, L.sqlite3_mutex).*;
    sqlite3_mutex_enter(dbMutex);

    switch (op) {
        SQLITE_DBSTATUS_LOOKASIDE_USED => {
            var H: c_int = 0;
            pCurrent.?.* = sqlite3LookasideUsed(db, &H);
            pHighwtr.?.* = H;
            if (resetFlag != 0) {
                // Move the free list onto the init list (both full- and small-size).
                moveFreeToInit(db, L.sqlite3_lookaside_pFree, L.sqlite3_lookaside_pInit);
                moveFreeToInit(db, L.sqlite3_lookaside_pSmallFree, L.sqlite3_lookaside_pSmallInit);
            }
        },

        SQLITE_DBSTATUS_LOOKASIDE_HIT,
        SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE,
        SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL,
        => {
            const idx: usize = @intCast(op - SQLITE_DBSTATUS_LOOKASIDE_HIT);
            const anStat: *align(1) u32 = @ptrCast(dbBase(db) + L.sqlite3_lookaside_anStat + idx * @sizeOf(u32));
            pCurrent.?.* = 0;
            pHighwtr.?.* = anStat.*;
            if (resetFlag != 0) {
                anStat.* = 0;
            }
        },

        // Approximate memory used by all pagers of this connection.
        SQLITE_DBSTATUS_CACHE_USED_SHARED, SQLITE_DBSTATUS_CACHE_USED => {
            var totalUsed: i64 = 0;
            sqlite3BtreeEnterAll(db);
            const nDb = dbPtr(c_int, db, L.sqlite3_nDb).*;
            const aDb = dbPtr(?*anyopaque, db, L.sqlite3_aDb).*;
            var i: c_int = 0;
            while (i < nDb) : (i += 1) {
                const pBt = aDbPBt(aDb, i);
                if (pBt) |bt| {
                    const pPager = sqlite3BtreePager(bt);
                    var nByte = sqlite3PagerMemUsed(pPager);
                    if (op == SQLITE_DBSTATUS_CACHE_USED_SHARED) {
                        nByte = @divTrunc(nByte, sqlite3BtreeConnectionCount(bt));
                    }
                    totalUsed += nByte;
                }
            }
            sqlite3BtreeLeaveAll(db);
            pCurrent.?.* = totalUsed;
            pHighwtr.?.* = 0;
        },

        // Estimate of memory used to store all schemas.
        SQLITE_DBSTATUS_SCHEMA_USED => {
            var nByte: c_int = 0;
            sqlite3BtreeEnterAll(db);
            dbPtr(?*anyopaque, db, L.sqlite3_pnBytesFreed).* = @ptrCast(&nByte);
            // db->lookaside.pEnd = db->lookaside.pStart;
            const pStart = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pStart).*;
            dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pEnd).* = pStart;

            const nDb = dbPtr(c_int, db, L.sqlite3_nDb).*;
            const aDb = dbPtr(?*anyopaque, db, L.sqlite3_aDb).*;
            var i: c_int = 0;
            while (i < nDb) : (i += 1) {
                const pSchema = aDbPSchema(aDb, i);
                if (pSchema) |schema| { // ALWAYS(pSchema!=0)
                    const sb: [*]u8 = @ptrCast(schema);
                    const hashElemSz = cfgRoundup(@intCast(L.sizeof_HashElem)); // sizeof(HashElem)
                    nByte += hashElemSz *% (hashCount(sb, L.Schema_tblHash) +
                        hashCount(sb, L.Schema_trigHash) +
                        hashCount(sb, L.Schema_idxHash) +
                        hashCount(sb, L.Schema_fkeyHash));
                    nByte += @intCast(sqlite3_msize(hashHt(sb, L.Schema_tblHash)));
                    nByte += @intCast(sqlite3_msize(hashHt(sb, L.Schema_trigHash)));
                    nByte += @intCast(sqlite3_msize(hashHt(sb, L.Schema_idxHash)));
                    nByte += @intCast(sqlite3_msize(hashHt(sb, L.Schema_fkeyHash)));

                    // Delete all triggers, then all tables (frees into pnBytesFreed).
                    var p = hashFirst(sb, L.Schema_trigHash);
                    while (p) |elem| {
                        sqlite3DeleteTrigger(db, hashData(elem));
                        p = hashNext(elem);
                    }
                    p = hashFirst(sb, L.Schema_tblHash);
                    while (p) |elem| {
                        sqlite3DeleteTable(db, hashData(elem));
                        p = hashNext(elem);
                    }
                }
            }
            dbPtr(?*anyopaque, db, L.sqlite3_pnBytesFreed).* = null;
            // db->lookaside.pEnd = db->lookaside.pTrueEnd;
            const pTrueEnd = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pTrueEnd).*;
            dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pEnd).* = pTrueEnd;
            sqlite3BtreeLeaveAll(db);

            pHighwtr.?.* = 0;
            pCurrent.?.* = nByte;
        },

        // Estimate of memory used to store all prepared statements.
        SQLITE_DBSTATUS_STMT_USED => {
            var nByte: c_int = 0;
            dbPtr(?*anyopaque, db, L.sqlite3_pnBytesFreed).* = @ptrCast(&nByte);
            const pStart = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pStart).*;
            dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pEnd).* = pStart;

            var pVdbe = dbPtr(?*anyopaque, db, L.sqlite3_pVdbe).*;
            while (pVdbe) |vm| {
                const vNext = vdbeVNext(vm);
                sqlite3VdbeDelete(vm);
                pVdbe = vNext;
            }

            const pTrueEnd = dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pTrueEnd).*;
            dbPtr(?*anyopaque, db, L.sqlite3_lookaside_pEnd).* = pTrueEnd;
            dbPtr(?*anyopaque, db, L.sqlite3_pnBytesFreed).* = null;

            pHighwtr.?.* = 0;
            pCurrent.?.* = nByte;
        },

        // Cache hits / misses / writes / spill across all pagers.
        SQLITE_DBSTATUS_CACHE_SPILL,
        SQLITE_DBSTATUS_CACHE_HIT,
        SQLITE_DBSTATUS_CACHE_MISS,
        SQLITE_DBSTATUS_CACHE_WRITE,
        => {
            if (op == SQLITE_DBSTATUS_CACHE_SPILL) {
                op = SQLITE_DBSTATUS_CACHE_WRITE + 1;
            }
            var nRet: u64 = 0;
            const nDb = dbPtr(c_int, db, L.sqlite3_nDb).*;
            const aDb = dbPtr(?*anyopaque, db, L.sqlite3_aDb).*;
            var i: c_int = 0;
            while (i < nDb) : (i += 1) {
                const pBt = aDbPBt(aDb, i);
                if (pBt) |bt| {
                    const pPager = sqlite3BtreePager(bt);
                    sqlite3PagerCacheStat(pPager, op, resetFlag, &nRet);
                }
            }
            pHighwtr.?.* = 0;
            pCurrent.?.* = @bitCast(nRet);
        },

        // Bytes spilled to temp files that could have stayed in memory.
        SQLITE_DBSTATUS_TEMPBUF_SPILL => {
            var nRet: u64 = 0;
            const aDb = dbPtr(?*anyopaque, db, L.sqlite3_aDb).*;
            const pBt1 = aDbPBt(aDb, 1);
            if (pBt1) |bt| {
                const pPager = sqlite3BtreePager(bt);
                sqlite3PagerCacheStat(pPager, SQLITE_DBSTATUS_CACHE_WRITE, resetFlag, &nRet);
                nRet *%= @as(u64, @intCast(sqlite3BtreeGetPageSize(bt)));
            }
            const nSpill = dbPtr(u64, db, L.sqlite3_nSpill).*;
            nRet +%= nSpill;
            if (resetFlag != 0) dbPtr(u64, db, L.sqlite3_nSpill).* = 0;
            pHighwtr.?.* = 0;
            pCurrent.?.* = @bitCast(nRet);
        },

        // Non-zero if there are unresolved deferred foreign-key constraints.
        SQLITE_DBSTATUS_DEFERRED_FKS => {
            pHighwtr.?.* = 0;
            const nDefImm = dbPtr(i64, db, L.sqlite3_nDeferredImmCons).*;
            const nDef = dbPtr(i64, db, L.sqlite3_nDeferredCons).*;
            pCurrent.?.* = if (nDefImm > 0 or nDef > 0) 1 else 0;
        },

        else => {
            rc = SQLITE_ERROR;
        },
    }

    sqlite3_mutex_leave(dbMutex);
    return rc;
}

/// 32-bit variant of sqlite3_db_status64().
export fn sqlite3_db_status(
    db: ?*anyopaque,
    op: c_int,
    pCurrent: ?*c_int,
    pHighwtr: ?*c_int,
    resetFlag: c_int,
) callconv(.c) c_int {
    var C: i64 = 0;
    var H: i64 = 0;
    // SQLITE_ENABLE_API_ARMOR is off => no safety-check guard.
    const rc = sqlite3_db_status64(db, op, &C, &H, resetFlag);
    if (rc == 0) {
        pCurrent.?.* = @intCast(C & 0x7fffffff);
        pHighwtr.?.* = @intCast(H & 0x7fffffff);
    }
    return rc;
}

// ---------------------------------------------------------------------------
// Small offset helpers.
// ---------------------------------------------------------------------------

/// `db->aDb[i].pBt` — aDb is an array of Db (sizeof_Db each); pBt at Db_pBt.
inline fn aDbPBt(aDb: ?*anyopaque, i: c_int) ?*anyopaque {
    const base: [*]u8 = @ptrCast(aDb.?);
    const item = base + @as(usize, @intCast(i)) * L.sizeof_Db + L.Db_pBt;
    const p: *align(1) ?*anyopaque = @ptrCast(item);
    return p.*;
}

/// `db->aDb[i].pSchema`.
inline fn aDbPSchema(aDb: ?*anyopaque, i: c_int) ?*anyopaque {
    const base: [*]u8 = @ptrCast(aDb.?);
    const item = base + @as(usize, @intCast(i)) * L.sizeof_Db + L.Db_pSchema;
    const p: *align(1) ?*anyopaque = @ptrCast(item);
    return p.*;
}

/// `pVdbe->pVNext`.
inline fn vdbeVNext(vm: ?*anyopaque) ?*anyopaque {
    const base: [*]u8 = @ptrCast(vm.?);
    const p: *align(1) ?*anyopaque = @ptrCast(base + L.Vdbe_pVNext);
    return p.*;
}

// Hash field access. `hashOff` is the absolute offset of the Hash member within
// the Schema struct; sb is the Schema base. Hash fields: count@4, first@8, ht@16.
inline fn hashCount(sb: [*]u8, comptime hashOff: usize) c_int {
    const p: *align(1) u32 = @ptrCast(sb + hashOff + L.Hash_count);
    return @bitCast(p.*);
}
inline fn hashHt(sb: [*]u8, comptime hashOff: usize) ?*anyopaque {
    const p: *align(1) ?*anyopaque = @ptrCast(sb + hashOff + L.Hash_ht);
    return p.*;
}
inline fn hashFirst(sb: [*]u8, comptime hashOff: usize) ?*anyopaque {
    const p: *align(1) ?*anyopaque = @ptrCast(sb + hashOff + L.Hash_first);
    return p.*;
}
inline fn hashNext(elem: ?*anyopaque) ?*anyopaque {
    const base: [*]u8 = @ptrCast(elem.?);
    const p: *align(1) ?*anyopaque = @ptrCast(base + L.HashElem_next);
    return p.*;
}
inline fn hashData(elem: ?*anyopaque) ?*anyopaque {
    const base: [*]u8 = @ptrCast(elem.?);
    const p: *align(1) ?*anyopaque = @ptrCast(base + L.HashElem_data);
    return p.*;
}

/// Reset-flag helper for LOOKASIDE_USED: splice the free list onto the head of
/// the init list, then clear the free pointer. (Mirrors the C inline block.)
inline fn moveFreeToInit(db: ?*anyopaque, comptime freeOff: usize, comptime initOff: usize) void {
    const pFreePtr = dbPtr(?*anyopaque, db, freeOff);
    var p = pFreePtr.*;
    if (p != null) {
        // Walk to the last node (p->pNext == 0).
        while (true) {
            const nextPtr: *align(1) ?*anyopaque = @ptrCast(@as([*]u8, @ptrCast(p.?)));
            if (nextPtr.* == null) break;
            p = nextPtr.*;
        }
        const lastNext: *align(1) ?*anyopaque = @ptrCast(@as([*]u8, @ptrCast(p.?)));
        const pInitPtr = dbPtr(?*anyopaque, db, initOff);
        lastNext.* = pInitPtr.*; // p->pNext = db->lookaside.pInit
        pInitPtr.* = pFreePtr.*; // db->lookaside.pInit = db->lookaside.pFree
        pFreePtr.* = null; // db->lookaside.pFree = 0
    }
}
