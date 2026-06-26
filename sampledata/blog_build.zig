//! blog_build.zig — create and verify the sample blog database from Zig.
//!
//! A standalone Zig program that drives the (partly-Zig) SQLite engine through
//! the public C API to build `sampledata/blog.db` (schema + seed embedded from
//! the .sql files next to this one), then runs a couple of verification queries
//! and prints the results. Linked against this project's libsqlite3.a, so it
//! exercises the ported Zig modules end-to-end.
//!
//! Run with:  zig build sample      (writes sampledata/blog.db)

const std = @import("std");
const print = std.debug.print;

const schema_sql = @embedFile("blog_schema.sql");
const seed_sql = @embedFile("blog_seed.sql");

// --- sqlite3 C API ---
const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
extern fn sqlite3_open(filename: [*:0]const u8, ppDb: *?*anyopaque) c_int;
extern fn sqlite3_close(db: ?*anyopaque) c_int;
extern fn sqlite3_exec(db: ?*anyopaque, sql: [*:0]const u8, cb: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_prepare_v2(db: ?*anyopaque, sql: [*:0]const u8, n: c_int, ppStmt: *?*anyopaque, tail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(stmt: ?*anyopaque) c_int;
extern fn sqlite3_finalize(stmt: ?*anyopaque) c_int;
extern fn sqlite3_column_text(stmt: ?*anyopaque, col: c_int) ?[*:0]const u8;
extern fn sqlite3_column_int(stmt: ?*anyopaque, col: c_int) c_int;
extern fn sqlite3_errmsg(db: ?*anyopaque) [*:0]const u8;
extern fn sqlite3_libversion() [*:0]const u8;
extern fn remove(path: [*:0]const u8) c_int;

const DB_PATH = "sampledata/blog.db";

fn exec(db: ?*anyopaque, sql: [*:0]const u8) !void {
    if (sqlite3_exec(db, sql, null, null, null) != SQLITE_OK) {
        print("SQL error: {s}\n", .{sqlite3_errmsg(db)});
        return error.ExecFailed;
    }
}

pub fn main() !void {
    // Start from a clean database file.
    _ = remove(DB_PATH);
    _ = remove(DB_PATH ++ "-wal");
    _ = remove(DB_PATH ++ "-shm");

    var db: ?*anyopaque = null;
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) return error.OpenFailed;
    defer _ = sqlite3_close(db);

    print("SQLite {s} — building {s} from Zig\n", .{ sqlite3_libversion(), DB_PATH });

    // The embedded .sql is made NUL-terminated for the C API with a sentinel.
    try exec(db, schema_sql ++ "\x00");
    try exec(db, seed_sql ++ "\x00");

    // Verify: published posts with author + comment counts (the view).
    print("\nPublished posts (id | title | author | #comments | views):\n", .{});
    var stmt: ?*anyopaque = null;
    if (sqlite3_prepare_v2(db, "SELECT id, title, author, n_comments, views FROM v_post_summary ORDER BY views DESC", -1, &stmt, null) != SQLITE_OK) {
        return error.PrepareFailed;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        print("  {d} | {s} | {s} | {d} comments | {d} views\n", .{
            sqlite3_column_int(stmt, 0),
            sqlite3_column_text(stmt, 1) orelse "",
            sqlite3_column_text(stmt, 2) orelse "",
            sqlite3_column_int(stmt, 3),
            sqlite3_column_int(stmt, 4),
        });
    }
    _ = sqlite3_finalize(stmt);

    // Verify: FTS5 full-text search.
    print("\nFTS5 search for 'sqlite OR cache':\n", .{});
    if (sqlite3_prepare_v2(db, "SELECT p.title FROM post_fts JOIN posts p ON p.id=post_fts.rowid WHERE post_fts MATCH 'sqlite OR cache' ORDER BY rank", -1, &stmt, null) != SQLITE_OK) return error.PrepareFailed;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        print("  - {s}\n", .{sqlite3_column_text(stmt, 0) orelse ""});
    }
    _ = sqlite3_finalize(stmt);

    // Integrity.
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, null) != SQLITE_OK) return error.PrepareFailed;
    const result = if (sqlite3_step(stmt) == SQLITE_ROW) (sqlite3_column_text(stmt, 0) orelse "?") else "?";
    print("\nintegrity_check: {s}\n", .{result});
    _ = sqlite3_finalize(stmt);

    print("Done. Open it with:  zig-out/bin/sqlite3 {s}\n", .{DB_PATH});
}
