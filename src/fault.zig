//! Zig port of SQLite's "benign malloc" fault hooks (src/fault.c).
//!
//! Drop-in replacement exporting the same C-ABI symbols
//! (`sqlite3BenignMallocHooks`, `sqlite3BeginBenignMalloc`,
//! `sqlite3EndBenignMalloc`). A "benign" malloc failure is one the caller can
//! recover from (e.g. skipping a hash-table resize); the test harness registers
//! hooks here to bracket regions where induced OOMs should not be treated as
//! real faults.
//!
//! Build config assumed (mirrors `sqlite_flags` in build.zig):
//!   no SQLITE_UNTESTABLE (this whole module is compiled),
//!   no SQLITE_OMIT_WSD (the hook vector is a plain static, not run-time located).

const Hook = ?*const fn () callconv(.c) void;

const BenignMallocHooks = struct {
    xBenignBegin: Hook,
    xBenignEnd: Hook,
};

var sqlite3Hooks: BenignMallocHooks = .{ .xBenignBegin = null, .xBenignEnd = null };

/// Register the hooks invoked by Begin/EndBenignMalloc.
export fn sqlite3BenignMallocHooks(xBenignBegin: Hook, xBenignEnd: Hook) callconv(.c) void {
    sqlite3Hooks.xBenignBegin = xBenignBegin;
    sqlite3Hooks.xBenignEnd = xBenignEnd;
}

/// Mark the start of a region where subsequent malloc failures are benign.
export fn sqlite3BeginBenignMalloc() callconv(.c) void {
    if (sqlite3Hooks.xBenignBegin) |f| f();
}

/// Mark the end of a benign-malloc region; later failures are non-benign again.
export fn sqlite3EndBenignMalloc() callconv(.c) void {
    if (sqlite3Hooks.xBenignEnd) |f| f();
}
