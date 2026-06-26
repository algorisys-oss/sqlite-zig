//! Zig port of SQLite's default system-malloc allocator (src/mem1.c).
//!
//! Implements the low-level `sqlite3_mem_methods` drivers backed by the C
//! library malloc/realloc/free. Only `sqlite3MemSetDefault` is external; it
//! installs these drivers into sqlite3GlobalConfig.m via sqlite3_config().
//!
//! Build config assumed (mirrors `sqlite_flags`/sqlite_cfg.h in this project):
//!   SQLITE_SYSTEM_MALLOC active, non-Apple, and crucially **SQLITE_MALLOCSIZE
//!   undefined** (HAVE_MALLOC_USABLE_SIZE is not set in either the `zig build`
//!   or the testfixture configs). So we use the size-prefix strategy: allocate
//!   8 extra bytes, stash the request size in the leading sqlite3_int64, and
//!   hand back the pointer just past it. This keeps xMalloc/xFree/xSize/xRealloc
//!   mutually consistent — which is all that matters, since the whole allocator
//!   is swapped atomically.

const SQLITE_OK: c_int = 0;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CONFIG_MALLOC: c_int = 4;

// --- libc + SQLite helpers resolved at link time ---
extern fn malloc(n: usize) ?*anyopaque;
extern fn realloc(p: ?*anyopaque, n: usize) ?*anyopaque;
extern fn free(p: ?*anyopaque) void;
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_config(op: c_int, ...) c_int;

/// The public sqlite3_mem_methods vtable layout (from sqlite3.h).
const MemMethods = extern struct {
    xMalloc: ?*const fn (c_int) callconv(.c) ?*anyopaque,
    xFree: ?*const fn (?*anyopaque) callconv(.c) void,
    xRealloc: ?*const fn (?*anyopaque, c_int) callconv(.c) ?*anyopaque,
    xSize: ?*const fn (?*anyopaque) callconv(.c) c_int,
    xRoundup: ?*const fn (c_int) callconv(.c) c_int,
    xInit: ?*const fn (?*anyopaque) callconv(.c) c_int,
    xShutdown: ?*const fn (?*anyopaque) callconv(.c) void,
    pAppData: ?*anyopaque,
};

/// malloc(), remembering the request size in an 8-byte prefix. nByte>0 is
/// guaranteed by higher-level callers.
fn sqlite3MemMalloc(nByte: c_int) callconv(.c) ?*anyopaque {
    const p: ?[*]i64 = @ptrCast(@alignCast(malloc(@as(usize, @intCast(nByte)) + 8)));
    if (p) |hdr| {
        hdr[0] = nByte;
        return @ptrCast(hdr + 1);
    }
    sqlite3_log(SQLITE_NOMEM, "failed to allocate %u bytes of memory", @as(c_uint, @bitCast(nByte)));
    return null;
}

/// free() of an allocation from sqlite3MemMalloc/Realloc. pPrior!=0 guaranteed.
fn sqlite3MemFree(pPrior: ?*anyopaque) callconv(.c) void {
    const p: [*]i64 = @ptrCast(@alignCast(pPrior.?));
    free(@ptrCast(p - 1));
}

/// Report the size recorded for a prior allocation.
fn sqlite3MemSize(pPrior: ?*anyopaque) callconv(.c) c_int {
    const p: [*]i64 = @ptrCast(@alignCast(pPrior.?));
    return @intCast((p - 1)[0]);
}

/// realloc(). pPrior!=0 and nByte>0 (and ROUND8) guaranteed by callers.
fn sqlite3MemRealloc(pPrior: ?*anyopaque, nByte: c_int) callconv(.c) ?*anyopaque {
    const old: [*]i64 = @ptrCast(@alignCast(pPrior.?));
    const p: ?[*]i64 = @ptrCast(@alignCast(realloc(@ptrCast(old - 1), @as(usize, @intCast(nByte)) + 8)));
    if (p) |hdr| {
        hdr[0] = nByte;
        return @ptrCast(hdr + 1);
    }
    sqlite3_log(SQLITE_NOMEM, "failed memory resize %u to %u bytes", @as(c_uint, @bitCast(sqlite3MemSize(pPrior))), @as(c_uint, @bitCast(nByte)));
    return null;
}

/// Round a request up to the next valid (8-byte) allocation size.
fn sqlite3MemRoundup(n: c_int) callconv(.c) c_int {
    return (n + 7) & ~@as(c_int, 7);
}

/// Initialize the module (nothing to do on non-Apple system malloc).
fn sqlite3MemInit(NotUsed: ?*anyopaque) callconv(.c) c_int {
    _ = NotUsed;
    return SQLITE_OK;
}

/// Deinitialize the module (no-op).
fn sqlite3MemShutdown(NotUsed: ?*anyopaque) callconv(.c) void {
    _ = NotUsed;
}

const defaultMethods: MemMethods = .{
    .xMalloc = &sqlite3MemMalloc,
    .xFree = &sqlite3MemFree,
    .xRealloc = &sqlite3MemRealloc,
    .xSize = &sqlite3MemSize,
    .xRoundup = &sqlite3MemRoundup,
    .xInit = &sqlite3MemInit,
    .xShutdown = &sqlite3MemShutdown,
    .pAppData = null,
};

/// The only external symbol: install these drivers as the default allocator.
export fn sqlite3MemSetDefault() callconv(.c) void {
    _ = sqlite3_config(SQLITE_CONFIG_MALLOC, &defaultMethods);
}
