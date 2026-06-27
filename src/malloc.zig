//! Zig port of SQLite's core memory allocator (src/malloc.c).
//!
//! This is the FOUNDATIONAL allocation layer: every allocation in the engine
//! flows through here. malloc.c sits *above* the low-level driver (mem1/mem5,
//! installed into sqlite3GlobalConfig.m by sqlite3MemSetDefault) and adds:
//!   - statistics + soft/hard heap limits (via sqlite3Status*),
//!   - per-connection lookaside fast-path allocation/free,
//!   - OOM bookkeeping on the sqlite3 connection (mallocFailed/lookaside).
//!
//! Exported (the non-static externals of malloc.c):
//!   public API:  sqlite3_release_memory, sqlite3_memory_alarm,
//!                sqlite3_soft_heap_limit64, sqlite3_soft_heap_limit,
//!                sqlite3_hard_heap_limit64, sqlite3_memory_used,
//!                sqlite3_memory_highwater, sqlite3_malloc, sqlite3_malloc64,
//!                sqlite3_msize, sqlite3_free, sqlite3_realloc, sqlite3_realloc64
//!   internal:    sqlite3MallocMutex, sqlite3MallocInit, sqlite3HeapNearlyFull,
//!                sqlite3MallocEnd, sqlite3Malloc, sqlite3MallocSize,
//!                sqlite3DbMallocSize, sqlite3DbFreeNN, sqlite3DbNNFreeNN,
//!                sqlite3DbFree, sqlite3Realloc, sqlite3MallocZero,
//!                sqlite3DbMallocZero, sqlite3DbMallocRaw, sqlite3DbMallocRawNN,
//!                sqlite3DbRealloc, sqlite3DbReallocOrFree, sqlite3DbStrDup,
//!                sqlite3DbStrNDup, sqlite3DbSpanDup, sqlite3SetString,
//!                sqlite3OomFault, sqlite3OomClear, sqlite3ApiExit
//!
//! The module-private struct `mem0` (a static in malloc.c) we OWN — kept as
//! Zig module globals here. `db->lookaside.*` and `sqlite3Config.*` are poked
//! at ground-truth offsets via c_layout, exactly like status.zig/pragma.zig.
//!
//! Build config assumed (true in both this project's prod and --dev builds):
//!   - SQLITE_OMIT_WSD off  => `sqlite3Config` is the literal global; `mem0` is
//!     a plain static (no GLOBAL() indirection).
//!   - SQLITE_OMIT_LOOKASIDE off, SQLITE_OMIT_TWOSIZE_LOOKASIDE off
//!     => LOOKASIDE_SMALL==128, pMiddle/pSmall* lists exist.
//!   - SQLITE_ENABLE_MEMORY_MANAGEMENT off => sqlite3_release_memory is a no-op
//!     returning 0; the extra alarm-retry malloc/realloc blocks are absent.
//!   - SQLITE_OMIT_AUTOINIT off => the public entry points call sqlite3_initialize.
//!   - SQLITE_OMIT_DEPRECATED off => sqlite3_memory_alarm exists (no-op).
//!   - SQLITE_MEMDEBUG off => sqlite3MemdebugHasType/NoType/SetType are no-ops.
//!   - SQLITE_DEBUG: test_oom_breakpoint is a pure no-op (the gated assert is
//!     "never reached in a human lifetime"); the trash-on-free memsets and the
//!     debug asserts have no functional effect, so they are elided in both.
//!   - SQLITE_THREADSAFE=1 => the mutex calls are real; AtomicStore/Load are
//!     __ATOMIC_RELAXED, reproduced with @atomicStore/@atomicLoad(.monotonic).

const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ── error / verb constants ───────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT collapses to this in prod
const SQLITE_IOERR_NOMEM: c_int = 10 | (12 << 8); // 3082

const SQLITE_STATUS_MEMORY_USED: c_int = 0;
const SQLITE_STATUS_MALLOC_SIZE: c_int = 5;
const SQLITE_STATUS_MALLOC_COUNT: c_int = 9;

const SQLITE_MUTEX_STATIC_MEM: c_int = 3;

// SQLITE_MAX_ALLOCATION_SIZE (sqliteLimit.h): 0x7fffff00 - 0xff = 2147483391.
const SQLITE_MAX_ALLOCATION_SIZE: u64 = 2147483391;

// LOOKASIDE_SMALL (SQLITE_OMIT_TWOSIZE_LOOKASIDE off).
const LOOKASIDE_SMALL: u64 = 128;

// ── raw-memory helpers (verbatim idiom from pragma.zig/status.zig) ───────────
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, offs: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + offs);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, offs: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + offs);
    q.* = v;
}
inline fn rdp(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return rd(?*anyopaque, p, offs);
}
inline fn fieldPtr(p: ?*anyopaque, offs: usize) [*]u8 {
    return base(p) + offs;
}

// ── external ABI helpers resolved at link time ───────────────────────────────
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;
extern fn sqlite3MutexAlloc(id: c_int) ?*anyopaque;
extern fn sqlite3_initialize() c_int;
extern fn sqlite3MemSetDefault() void;

extern fn sqlite3StatusValue(op: c_int) i64;
extern fn sqlite3StatusUp(op: c_int, N: c_int) void;
extern fn sqlite3StatusDown(op: c_int, N: c_int) void;
extern fn sqlite3StatusHighwater(op: c_int, X: c_int) void;
extern fn sqlite3_status64(op: c_int, pCur: ?*i64, pHi: ?*i64, reset: c_int) c_int;

extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3Error(db: ?*anyopaque, err: c_int) void;

extern fn strlen(s: [*:0]const u8) usize;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;

// ── sqlite3GlobalConfig access (SQLITE_OMIT_WSD off => literal symbol) ────────
// MUST be `extern var`: a const read can be CSE'd by the optimizer across the
// opaque C calls that mutate it.
extern var sqlite3Config: u8;

const XMallocFn = ?*const fn (c_int) callconv(.c) ?*anyopaque;
const XFreeFn = ?*const fn (?*anyopaque) callconv(.c) void;
const XReallocFn = ?*const fn (?*anyopaque, c_int) callconv(.c) ?*anyopaque;
const XSizeFn = ?*const fn (?*anyopaque) callconv(.c) c_int;
const XRoundupFn = ?*const fn (c_int) callconv(.c) c_int;
const XInitFn = ?*const fn (?*anyopaque) callconv(.c) c_int;
const XShutdownFn = ?*const fn (?*anyopaque) callconv(.c) void;

inline fn cfgRd(comptime T: type, comptime offs: usize) T {
    const q: *align(1) const T = @ptrCast(fieldPtr(&sqlite3Config, offs));
    return q.*;
}
inline fn cfgWr(comptime T: type, comptime offs: usize, v: T) void {
    const q: *align(1) T = @ptrCast(fieldPtr(&sqlite3Config, offs));
    q.* = v;
}

inline fn xMalloc(n: c_int) ?*anyopaque {
    return cfgRd(XMallocFn, off("Sqlite3Config_m_xMalloc", 32)).?(n);
}
inline fn xFree(p: ?*anyopaque) void {
    cfgRd(XFreeFn, off("Sqlite3Config_m_xFree", 40)).?(p);
}
inline fn xRealloc(p: ?*anyopaque, n: c_int) ?*anyopaque {
    return cfgRd(XReallocFn, off("Sqlite3Config_m_xRealloc", 48)).?(p, n);
}
inline fn xSize(p: ?*anyopaque) c_int {
    return cfgRd(XSizeFn, off("Sqlite3Config_m_xSize", 56)).?(p);
}
inline fn xRoundup(n: c_int) c_int {
    return cfgRd(XRoundupFn, off("Sqlite3Config_m_xRoundup", 64)).?(n);
}
inline fn xInit(p: ?*anyopaque) c_int {
    return cfgRd(XInitFn, off("Sqlite3Config_m_xInit", 72)).?(p);
}
inline fn xShutdown(p: ?*anyopaque) void {
    cfgRd(XShutdownFn, off("Sqlite3Config_m_xShutdown", 80)).?(p);
}
inline fn cfgBMemstat() bool {
    return cfgRd(c_int, L.Sqlite3Config_bMemstat) != 0;
}
inline fn cfgAppData() ?*anyopaque {
    return cfgRd(?*anyopaque, off("Sqlite3Config_m_pAppData", 88));
}

fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

// ── config field offsets ─────────────────────────────────────────────────────
const Sqlite3Config_pPage = off("Sqlite3Config_pPage", 312);
const Sqlite3Config_szPage = off("Sqlite3Config_szPage", 320);
const Sqlite3Config_nPage = off("Sqlite3Config_nPage", 324);

// ── sqlite3 connection field offsets ─────────────────────────────────────────
const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103);
const sqlite3_bBenignMalloc = off("sqlite3_bBenignMalloc", 104);
const sqlite3_nVdbeExec = off("sqlite3_nVdbeExec", 220);
const sqlite3_u1 = off("sqlite3_u1", 424); // u1.isInterrupted is first member
const sqlite3_pParse = off("sqlite3_pParse", 344);
const sqlite3_pnBytesFreed = off("sqlite3_pnBytesFreed", 792);

// Lookaside sub-struct fields (absolute offsets within sqlite3).
const la_bDisable = off("sqlite3_lookaside_bDisable", 432);
const la_sz = off("sqlite3_lookaside_sz", 436);
const la_szTrue = off("sqlite3_lookaside_szTrue", 438);
const la_nSlot = off("sqlite3_lookaside_nSlot", 444);
const la_anStat = off("sqlite3_lookaside_anStat", 448);
const la_pInit = off("sqlite3_lookaside_pInit", 464);
const la_pFree = off("sqlite3_lookaside_pFree", 472);
const la_pSmallInit = off("sqlite3_lookaside_pSmallInit", 480);
const la_pSmallFree = off("sqlite3_lookaside_pSmallFree", 488);
const la_pMiddle = off("sqlite3_lookaside_pMiddle", 496);
const la_pStart = off("sqlite3_lookaside_pStart", 504);
const la_pEnd = off("sqlite3_lookaside_pEnd", 512);
const la_pTrueEnd = off("sqlite3_lookaside_pTrueEnd", 520);

// Parse field offsets.
const Parse_rc = off("Parse_rc", 24);
const Parse_nErr = off("Parse_nErr", 52);
const Parse_pOuterParse = off("Parse_pOuterParse", 200);

// LookasideSlot.pNext is at offset 0 (single-pointer struct).
const LS_pNext: usize = 0;

inline fn lsNext(p: ?*anyopaque) ?*anyopaque {
    return rdp(p, LS_pNext);
}
inline fn lsSetNext(p: ?*anyopaque, next: ?*anyopaque) void {
    wr(?*anyopaque, p, LS_pNext, next);
}
inline fn uptr(p: ?*anyopaque) usize {
    return @intFromPtr(p);
}
// Used only for db->u1.isInterrupted (offset 424, naturally 4-aligned in the
// allocated sqlite3 struct); @alignCast is safe and lets @atomicStore/Load use it.
inline fn intPtr(db: ?*anyopaque, offs: usize) *c_int {
    return @alignCast(@ptrCast(fieldPtr(db, offs)));
}

// ─────────────────────────────────────────────────────────────────────────────
// mem0: the module-private allocator state. We own this layout. Initial values
// (SQLITE_MAX_MEMORY == 0): { mutex=0, alarmThreshold=0, hardLimit=0,
// nearlyFull=0 }.
// ─────────────────────────────────────────────────────────────────────────────
const Mem0 = struct {
    mutex: ?*anyopaque = null,
    alarmThreshold: i64 = 0,
    hardLimit: i64 = 0,
    nearlyFull: i32 = 0,
};
var mem0: Mem0 = .{};

inline fn clearMem0() void {
    mem0 = .{};
}

// ─────────────────────────────────────────────────────────────────────────────
// sqlite3_release_memory: SQLITE_ENABLE_MEMORY_MANAGEMENT off => no-op.
// ─────────────────────────────────────────────────────────────────────────────
export fn sqlite3_release_memory(n: c_int) callconv(.c) c_int {
    _ = n;
    return 0;
}

/// Return the memory allocator mutex. sqlite3_status() needs it.
export fn sqlite3MallocMutex() callconv(.c) ?*anyopaque {
    return mem0.mutex;
}

/// Deprecated external interface; now a no-op.
export fn sqlite3_memory_alarm(
    xCallback: ?*anyopaque,
    pArg: ?*anyopaque,
    iThreshold: i64,
) callconv(.c) c_int {
    _ = xCallback;
    _ = pArg;
    _ = iThreshold;
    return SQLITE_OK;
}

/// Set the soft heap-size limit. Returns the prior limit.
export fn sqlite3_soft_heap_limit64(n_in: i64) callconv(.c) i64 {
    var n = n_in;
    if (sqlite3_initialize() != 0) return -1;
    sqlite3_mutex_enter(mem0.mutex);
    const priorLimit = mem0.alarmThreshold;
    if (n < 0) {
        sqlite3_mutex_leave(mem0.mutex);
        return priorLimit;
    }
    if (mem0.hardLimit > 0 and (n > mem0.hardLimit or n == 0)) {
        n = mem0.hardLimit;
    }
    mem0.alarmThreshold = n;
    const nUsed = sqlite3StatusValue(SQLITE_STATUS_MEMORY_USED);
    @atomicStore(i32, &mem0.nearlyFull, @intFromBool(n > 0 and n <= nUsed), .monotonic);
    sqlite3_mutex_leave(mem0.mutex);
    const excess = sqlite3_memory_used() - n;
    if (excess > 0) _ = sqlite3_release_memory(@intCast(excess & 0x7fffffff));
    return priorLimit;
}

export fn sqlite3_soft_heap_limit(n_in: c_int) callconv(.c) void {
    const n: c_int = if (n_in < 0) 0 else n_in;
    _ = sqlite3_soft_heap_limit64(n);
}

/// Set the hard heap-size limit. Returns the prior limit.
export fn sqlite3_hard_heap_limit64(n: i64) callconv(.c) i64 {
    if (sqlite3_initialize() != 0) return -1;
    sqlite3_mutex_enter(mem0.mutex);
    const priorLimit = mem0.hardLimit;
    if (n >= 0) {
        mem0.hardLimit = n;
        if (n < mem0.alarmThreshold or mem0.alarmThreshold == 0) {
            mem0.alarmThreshold = n;
        }
    }
    sqlite3_mutex_leave(mem0.mutex);
    return priorLimit;
}

/// Initialize the memory allocation subsystem.
export fn sqlite3MallocInit() callconv(.c) c_int {
    if (cfgRd(XMallocFn, off("Sqlite3Config_m_xMalloc", 32)) == null) {
        sqlite3MemSetDefault();
    }
    mem0.mutex = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MEM);
    const pPage = cfgRd(?*anyopaque, Sqlite3Config_pPage);
    const szPage = cfgRd(c_int, Sqlite3Config_szPage);
    const nPage = cfgRd(c_int, Sqlite3Config_nPage);
    if (pPage == null or szPage < 512 or nPage <= 0) {
        cfgWr(?*anyopaque, Sqlite3Config_pPage, null);
        cfgWr(c_int, Sqlite3Config_szPage, 0);
    }
    const rc = xInit(cfgAppData());
    if (rc != SQLITE_OK) clearMem0();
    return rc;
}

/// True if the heap is currently under memory pressure.
export fn sqlite3HeapNearlyFull() callconv(.c) c_int {
    return @atomicLoad(i32, &mem0.nearlyFull, .monotonic);
}

/// Deinitialize the memory allocation subsystem.
export fn sqlite3MallocEnd() callconv(.c) void {
    if (cfgRd(XShutdownFn, off("Sqlite3Config_m_xShutdown", 80)) != null) {
        xShutdown(cfgAppData());
    }
    clearMem0();
}

/// Amount of memory currently checked out.
export fn sqlite3_memory_used() callconv(.c) i64 {
    var res: i64 = 0;
    var mx: i64 = 0;
    _ = sqlite3_status64(SQLITE_STATUS_MEMORY_USED, &res, &mx, 0);
    return res;
}

/// Maximum memory ever checked out (since last reset).
export fn sqlite3_memory_highwater(resetFlag: c_int) callconv(.c) i64 {
    var res: i64 = 0;
    var mx: i64 = 0;
    _ = sqlite3_status64(SQLITE_STATUS_MEMORY_USED, &res, &mx, resetFlag);
    return mx;
}

/// Trigger the alarm. Caller holds mem0.mutex.
fn sqlite3MallocAlarm(nByte: c_int) void {
    if (mem0.alarmThreshold <= 0) return;
    sqlite3_mutex_leave(mem0.mutex);
    _ = sqlite3_release_memory(nByte);
    sqlite3_mutex_enter(mem0.mutex);
}

/// No-op in production; under SQLITE_DEBUG it is only a never-reached
/// breakpoint helper with no functional effect.
inline fn test_oom_breakpoint(n: u64) void {
    _ = n;
}

/// Memory allocation with statistics and alarms. Caller holds mem0.mutex, n>0.
fn mallocWithAlarm(n: c_int, pp: *?*anyopaque) void {
    var nFull = xRoundup(n);
    sqlite3StatusHighwater(SQLITE_STATUS_MALLOC_SIZE, n);
    if (mem0.alarmThreshold > 0) {
        const nUsed = sqlite3StatusValue(SQLITE_STATUS_MEMORY_USED);
        if (nUsed >= mem0.alarmThreshold - nFull) {
            @atomicStore(i32, &mem0.nearlyFull, 1, .monotonic);
            sqlite3MallocAlarm(nFull);
            if (mem0.hardLimit != 0) {
                const nUsed2 = sqlite3StatusValue(SQLITE_STATUS_MEMORY_USED);
                if (nUsed2 >= mem0.hardLimit - nFull) {
                    test_oom_breakpoint(1);
                    pp.* = null;
                    return;
                }
            }
        } else {
            @atomicStore(i32, &mem0.nearlyFull, 0, .monotonic);
        }
    }
    const p = xMalloc(nFull);
    // SQLITE_ENABLE_MEMORY_MANAGEMENT off => no alarm-retry block.
    if (p != null) {
        nFull = sqlite3MallocSize(p);
        sqlite3StatusUp(SQLITE_STATUS_MEMORY_USED, nFull);
        sqlite3StatusUp(SQLITE_STATUS_MALLOC_COUNT, 1);
    }
    pp.* = p;
}

/// Allocate memory (subsystem assumed initialized).
export fn sqlite3Malloc(n: u64) callconv(.c) ?*anyopaque {
    var p: ?*anyopaque = null;
    if (n == 0 or n > SQLITE_MAX_ALLOCATION_SIZE) {
        p = null;
    } else if (cfgBMemstat()) {
        sqlite3_mutex_enter(mem0.mutex);
        mallocWithAlarm(@intCast(n), &p);
        sqlite3_mutex_leave(mem0.mutex);
    } else {
        p = xMalloc(@intCast(n));
    }
    return p;
}

/// Public application allocator (autoinit).
export fn sqlite3_malloc(n: c_int) callconv(.c) ?*anyopaque {
    if (sqlite3_initialize() != 0) return null;
    return if (n <= 0) null else sqlite3Malloc(@intCast(n));
}

export fn sqlite3_malloc64(n: u64) callconv(.c) ?*anyopaque {
    if (sqlite3_initialize() != 0) return null;
    return sqlite3Malloc(n);
}

/// TRUE if p is a lookaside allocation from db. (SQLITE_OMIT_LOOKASIDE off.)
inline fn isLookaside(db: ?*anyopaque, p: ?*anyopaque) bool {
    const start = uptr(rdp(db, la_pStart));
    const trueEnd = uptr(rdp(db, la_pTrueEnd));
    const x = uptr(p);
    return x >= start and x < trueEnd;
}

/// Size of an allocation from sqlite3Malloc()/sqlite3_malloc().
export fn sqlite3MallocSize(p: ?*const anyopaque) callconv(.c) c_int {
    return xSize(@constCast(p));
}

/// Size of a lookaside allocation. (SQLITE_OMIT_TWOSIZE_LOOKASIDE off.)
fn lookasideMallocSize(db: ?*anyopaque, p: ?*anyopaque) c_int {
    if (uptr(p) < uptr(rdp(db, la_pMiddle))) {
        return rd(u16, db, la_szTrue);
    } else {
        return @intCast(LOOKASIDE_SMALL);
    }
}

export fn sqlite3DbMallocSize(db: ?*anyopaque, p: ?*const anyopaque) callconv(.c) c_int {
    if (db != null) {
        const x = uptr(@constCast(p));
        if (x < uptr(rdp(db, la_pTrueEnd))) {
            if (x >= uptr(rdp(db, la_pMiddle))) {
                return @intCast(LOOKASIDE_SMALL);
            }
            if (x >= uptr(rdp(db, la_pStart))) {
                return rd(u16, db, la_szTrue);
            }
        }
    }
    return xSize(@constCast(p));
}

export fn sqlite3_msize(p: ?*anyopaque) callconv(.c) u64 {
    return if (p != null) @intCast(xSize(p)) else 0;
}

/// Free memory previously obtained from sqlite3Malloc().
export fn sqlite3_free(p: ?*anyopaque) callconv(.c) void {
    if (p == null) return;
    if (cfgBMemstat()) {
        sqlite3_mutex_enter(mem0.mutex);
        sqlite3StatusDown(SQLITE_STATUS_MEMORY_USED, sqlite3MallocSize(p));
        sqlite3StatusDown(SQLITE_STATUS_MALLOC_COUNT, 1);
        xFree(p);
        sqlite3_mutex_leave(mem0.mutex);
    } else {
        xFree(p);
    }
}

/// Add the size of "p" to *db->pnBytesFreed.
fn measureAllocationSize(db: ?*anyopaque, p: ?*anyopaque) void {
    const pn = rdp(db, sqlite3_pnBytesFreed);
    const cur = rd(i64, pn, 0);
    wr(i64, pn, 0, cur + sqlite3DbMallocSize(db, p));
}

/// Free memory possibly associated with a connection. p!=0 required.
export fn sqlite3DbFreeNN(db: ?*anyopaque, p: ?*anyopaque) callconv(.c) void {
    if (db != null) {
        const x = uptr(p);
        if (x < uptr(rdp(db, la_pEnd))) {
            if (x >= uptr(rdp(db, la_pMiddle))) {
                lsSetNext(p, rdp(db, la_pSmallFree));
                wr(?*anyopaque, db, la_pSmallFree, p);
                return;
            }
            if (x >= uptr(rdp(db, la_pStart))) {
                lsSetNext(p, rdp(db, la_pFree));
                wr(?*anyopaque, db, la_pFree, p);
                return;
            }
        }
        if (rdp(db, sqlite3_pnBytesFreed) != null) {
            measureAllocationSize(db, p);
            return;
        }
    }
    sqlite3_free(p);
}

export fn sqlite3DbNNFreeNN(db: ?*anyopaque, p: ?*anyopaque) callconv(.c) void {
    const x = uptr(p);
    if (x < uptr(rdp(db, la_pEnd))) {
        if (x >= uptr(rdp(db, la_pMiddle))) {
            lsSetNext(p, rdp(db, la_pSmallFree));
            wr(?*anyopaque, db, la_pSmallFree, p);
            return;
        }
        if (x >= uptr(rdp(db, la_pStart))) {
            lsSetNext(p, rdp(db, la_pFree));
            wr(?*anyopaque, db, la_pFree, p);
            return;
        }
    }
    if (rdp(db, sqlite3_pnBytesFreed) != null) {
        measureAllocationSize(db, p);
        return;
    }
    sqlite3_free(p);
}

export fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) callconv(.c) void {
    if (p != null) sqlite3DbFreeNN(db, p);
}

/// Change the size of an existing allocation.
export fn sqlite3Realloc(pOld: ?*anyopaque, nBytes: u64) callconv(.c) ?*anyopaque {
    if (pOld == null) {
        return sqlite3Malloc(nBytes);
    }
    if (nBytes == 0) {
        sqlite3_free(pOld);
        return null;
    }
    if (nBytes > SQLITE_MAX_ALLOCATION_SIZE) {
        return null;
    }
    const nOld = sqlite3MallocSize(pOld);
    const nNew = xRoundup(@intCast(nBytes));
    var pNew: ?*anyopaque = null;
    if (nOld == nNew) {
        pNew = pOld;
    } else if (cfgBMemstat()) {
        sqlite3_mutex_enter(mem0.mutex);
        sqlite3StatusHighwater(SQLITE_STATUS_MALLOC_SIZE, @intCast(nBytes));
        const nDiff = nNew - nOld;
        if (nDiff > 0) {
            const nUsed = sqlite3StatusValue(SQLITE_STATUS_MEMORY_USED);
            if (nUsed >= mem0.alarmThreshold - nDiff) {
                sqlite3MallocAlarm(nDiff);
                if (mem0.hardLimit > 0 and nUsed >= mem0.hardLimit - nDiff) {
                    sqlite3_mutex_leave(mem0.mutex);
                    test_oom_breakpoint(1);
                    return null;
                }
            }
        }
        pNew = xRealloc(pOld, nNew);
        // SQLITE_ENABLE_MEMORY_MANAGEMENT off => no alarm-retry block.
        if (pNew != null) {
            const nNew2 = sqlite3MallocSize(pNew);
            sqlite3StatusUp(SQLITE_STATUS_MEMORY_USED, nNew2 - nOld);
        }
        sqlite3_mutex_leave(mem0.mutex);
    } else {
        pNew = xRealloc(pOld, nNew);
    }
    return pNew;
}

/// Public sqlite3Realloc (autoinit).
export fn sqlite3_realloc(pOld: ?*anyopaque, n_in: c_int) callconv(.c) ?*anyopaque {
    if (sqlite3_initialize() != 0) return null;
    const n: c_int = if (n_in < 0) 0 else n_in;
    return sqlite3Realloc(pOld, @intCast(n));
}

export fn sqlite3_realloc64(pOld: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque {
    if (sqlite3_initialize() != 0) return null;
    return sqlite3Realloc(pOld, n);
}

/// Allocate and zero memory.
export fn sqlite3MallocZero(n: u64) callconv(.c) ?*anyopaque {
    const p = sqlite3Malloc(n);
    if (p != null) {
        _ = memset(p, 0, @intCast(n));
    }
    return p;
}

/// Allocate and zero; set mallocFailed on the connection if it fails.
export fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque {
    const p = sqlite3DbMallocRaw(db, n);
    if (p != null) _ = memset(p, 0, @intCast(n));
    return p;
}

/// Slow path of sqlite3DbMallocRawNN when lookaside cannot serve the request.
fn dbMallocRawFinish(db: ?*anyopaque, n: u64) ?*anyopaque {
    const p = sqlite3Malloc(n);
    if (p == null) _ = sqlite3OomFault(db);
    return p;
}

/// Allocate lookaside-or-heap; set mallocFailed on failure. db may be NULL.
export fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque {
    if (db != null) return sqlite3DbMallocRawNN(db, n);
    return sqlite3Malloc(n);
}

export fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque {
    // SQLITE_OMIT_LOOKASIDE off.
    if (n > rd(u16, db, la_sz)) {
        if (rd(u32, db, la_bDisable) == 0) {
            incStat(db, 1);
        } else if (rd(u8, db, sqlite3_mallocFailed) != 0) {
            return null;
        }
        return dbMallocRawFinish(db, n);
    }
    // SQLITE_OMIT_TWOSIZE_LOOKASIDE off.
    if (n <= LOOKASIDE_SMALL) {
        var pBuf = rdp(db, la_pSmallFree);
        if (pBuf != null) {
            wr(?*anyopaque, db, la_pSmallFree, lsNext(pBuf));
            incStat(db, 0);
            return pBuf;
        }
        pBuf = rdp(db, la_pSmallInit);
        if (pBuf != null) {
            wr(?*anyopaque, db, la_pSmallInit, lsNext(pBuf));
            incStat(db, 0);
            return pBuf;
        }
    }
    var pBuf = rdp(db, la_pFree);
    if (pBuf != null) {
        wr(?*anyopaque, db, la_pFree, lsNext(pBuf));
        incStat(db, 0);
        return pBuf;
    }
    pBuf = rdp(db, la_pInit);
    if (pBuf != null) {
        wr(?*anyopaque, db, la_pInit, lsNext(pBuf));
        incStat(db, 0);
        return pBuf;
    }
    incStat(db, 2);
    return dbMallocRawFinish(db, n);
}

/// db->lookaside.anStat[idx]++
inline fn incStat(db: ?*anyopaque, idx: usize) void {
    const p: *align(1) u32 = @ptrCast(fieldPtr(db, la_anStat + idx * @sizeOf(u32)));
    p.* +%= 1;
}

/// Resize p to n bytes; set mallocFailed on failure.
export fn sqlite3DbRealloc(db: ?*anyopaque, p: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque {
    if (p == null) return sqlite3DbMallocRawNN(db, n);
    if (uptr(p) < uptr(rdp(db, la_pEnd))) {
        // SQLITE_OMIT_TWOSIZE_LOOKASIDE off.
        if (uptr(p) >= uptr(rdp(db, la_pMiddle))) {
            if (n <= LOOKASIDE_SMALL) return p;
        } else if (uptr(p) >= uptr(rdp(db, la_pStart))) {
            if (n <= rd(u16, db, la_szTrue)) return p;
        }
    }
    return dbReallocFinish(db, p, n);
}

fn dbReallocFinish(db: ?*anyopaque, p: ?*anyopaque, n: u64) ?*anyopaque {
    var pNew: ?*anyopaque = null;
    if (rd(u8, db, sqlite3_mallocFailed) == 0) {
        if (isLookaside(db, p)) {
            pNew = sqlite3DbMallocRawNN(db, n);
            if (pNew != null) {
                _ = memcpy(pNew, p, @intCast(lookasideMallocSize(db, p)));
                sqlite3DbFree(db, p);
            }
        } else {
            pNew = sqlite3Realloc(p, n);
            if (pNew == null) {
                _ = sqlite3OomFault(db);
            }
        }
    }
    return pNew;
}

/// Realloc, freeing p and setting mallocFailed if it fails.
export fn sqlite3DbReallocOrFree(db: ?*anyopaque, p: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque {
    const pNew = sqlite3DbRealloc(db, p, n);
    if (pNew == null) {
        sqlite3DbFree(db, p);
    }
    return pNew;
}

/// Copy a NUL-terminated string into db memory.
export fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) callconv(.c) ?[*:0]u8 {
    if (z == null) return null;
    const n = strlen(z.?) + 1;
    const zNew = sqlite3DbMallocRaw(db, n);
    if (zNew != null) {
        _ = memcpy(zNew, z, n);
    }
    return @ptrCast(zNew);
}

export fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*]const u8, n: u64) callconv(.c) ?[*:0]u8 {
    const zNew = if (z != null) sqlite3DbMallocRawNN(db, n + 1) else null;
    if (zNew != null) {
        _ = memcpy(zNew, z, @intCast(n));
        const dst: [*]u8 = @ptrCast(zNew.?);
        dst[@intCast(n)] = 0;
    }
    return @ptrCast(zNew);
}

/// Duplicate the phrase between zStart and zEnd, trimming surrounding spaces.
export fn sqlite3DbSpanDup(db: ?*anyopaque, zStart_in: [*]const u8, zEnd: [*]const u8) callconv(.c) ?[*:0]u8 {
    var zStart = zStart_in;
    while (isSpace(zStart[0])) zStart += 1;
    var n: usize = @intFromPtr(zEnd) - @intFromPtr(zStart);
    while (n > 0 and isSpace(zStart[n - 1])) n -= 1;
    return sqlite3DbStrNDup(db, zStart, n);
}

/// Replace *pz with a copy of zNew, freeing the old content.
export fn sqlite3SetString(pz: *?[*:0]u8, db: ?*anyopaque, zNew: ?[*:0]const u8) callconv(.c) void {
    const z = sqlite3DbStrDup(db, zNew);
    sqlite3DbFree(db, @ptrCast(pz.*));
    pz.* = z;
}

/// sqlite3Isspace(x): sqlite3CtypeMap[x] & 0x01. Use the real C table so this
/// stays correct regardless of locale/table changes.
extern const sqlite3CtypeMap: [256]u8;
inline fn isSpace(c: u8) bool {
    return (sqlite3CtypeMap[c] & 0x01) != 0;
}

/// Record an OOM error: set mallocFailed, disable lookaside, interrupt VDBEs.
export fn sqlite3OomFault(db: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (rd(u8, db, sqlite3_mallocFailed) == 0 and rd(u8, db, sqlite3_bBenignMalloc) == 0) {
        wr(u8, db, sqlite3_mallocFailed, 1);
        if (rd(c_int, db, sqlite3_nVdbeExec) > 0) {
            // u1.isInterrupted is the first member of the u1 union.
            @atomicStore(c_int, intPtr(db, sqlite3_u1), 1, .monotonic);
        }
        // DisableLookaside: db->lookaside.bDisable++; db->lookaside.sz = 0;
        wr(u32, db, la_bDisable, rd(u32, db, la_bDisable) +% 1);
        wr(u16, db, la_sz, 0);

        const pParse = rdp(db, sqlite3_pParse);
        if (pParse != null) {
            sqlite3ErrorMsg(pParse, "out of memory");
            wr(c_int, pParse, Parse_rc, SQLITE_NOMEM);
            var p = rdp(pParse, Parse_pOuterParse);
            while (p != null) {
                wr(c_int, p, Parse_nErr, rd(c_int, p, Parse_nErr) + 1);
                wr(c_int, p, Parse_rc, SQLITE_NOMEM);
                p = rdp(p, Parse_pOuterParse);
            }
        }
    }
    return null;
}

/// Reactivate the allocator and clear mallocFailed when no VDBEs are running.
export fn sqlite3OomClear(db: ?*anyopaque) callconv(.c) void {
    if (rd(u8, db, sqlite3_mallocFailed) != 0 and rd(c_int, db, sqlite3_nVdbeExec) == 0) {
        wr(u8, db, sqlite3_mallocFailed, 0);
        @atomicStore(c_int, intPtr(db, sqlite3_u1), 0, .monotonic);
        // EnableLookaside: bDisable--; sz = bDisable ? 0 : szTrue;
        const nDis = rd(u32, db, la_bDisable) -% 1;
        wr(u32, db, la_bDisable, nDis);
        wr(u16, db, la_sz, if (nDis != 0) 0 else rd(u16, db, la_szTrue));
    }
}

/// Slow path of sqlite3ApiExit: deal with an error/OOM.
fn apiHandleError(db: ?*anyopaque, rc: c_int) c_int {
    if (rd(u8, db, sqlite3_mallocFailed) != 0 or rc == SQLITE_IOERR_NOMEM) {
        sqlite3OomClear(db);
        sqlite3Error(db, SQLITE_NOMEM);
        return SQLITE_NOMEM;
    }
    return rc & rd(c_int, db, off("sqlite3_errMask", 88));
}

/// Called before returning to the user from an API that allocated memory.
export fn sqlite3ApiExit(db: ?*anyopaque, rc: c_int) callconv(.c) c_int {
    if (rd(u8, db, sqlite3_mallocFailed) != 0 or rc != 0) {
        return apiHandleError(db, rc);
    }
    return 0;
}
