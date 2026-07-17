//! sqlite-zturso — interactive REPL for the fork's SQL frontend (branch-only)
//! ==========================================================================
//! A Zig program that drives the zturso frontend: you type SQL in the fork's
//! dialect, it is compiled to VDBE bytecode by `zturso_prepare` (our tokenizer /
//! parser / codegen — NOT SQLite's) and run on the ported Zig engine.
//!
//! This is the Zig-facing example of Turso's "VDBE as a pluggable IR" thesis:
//! the Zig `main` here never touches SQLite's parser; it hands SQL text to the
//! frontend and steps the resulting statement through the public C API.
//!
//! Build/run:  zig build zturso-repl                                  (interactive)
//!             echo "SELECT name FROM emp WHERE salary>=125" | zig build zturso-repl
//!             printf 'SELECT 2+3*4\nSELECT * FROM emp\n'    | zig build zturso-repl
//! (For one-shot from argv, the C demo binary also works: zturso_frontend "SELECT 2+3*4".)
//!
//! The frontend's grammar (see src/zturso/README.md):
//!   SELECT expr[, expr...] [FROM table [WHERE cond [AND cond]...]]
//!   expr: integers, column names, rowid, + - * / %, parentheses, unary minus
//!   cond: expr {= <> != < <= > >=} expr
//!
//! Fork-only (branch `sqlite-zturso`). Links libsqlite3.a and compiles
//! frontend.c with -DZTURSO_NO_MAIN so we reuse zturso_prepare() as a library.

const std = @import("std");
const print = std.debug.print;

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;

// Public C API of the ported engine + the fork's frontend entry point.
const c = struct {
    extern fn sqlite3_open(filename: [*:0]const u8, ppDb: *?*anyopaque) c_int;
    extern fn sqlite3_close(db: ?*anyopaque) c_int;
    extern fn sqlite3_exec(db: ?*anyopaque, sql: [*:0]const u8, cb: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
    extern fn sqlite3_step(stmt: ?*anyopaque) c_int;
    extern fn sqlite3_finalize(stmt: ?*anyopaque) c_int;
    extern fn sqlite3_column_count(stmt: ?*anyopaque) c_int;
    extern fn sqlite3_column_text(stmt: ?*anyopaque, i: c_int) ?[*:0]const u8;
    extern fn sqlite3_column_name(stmt: ?*anyopaque, i: c_int) ?[*:0]const u8;
    // The fork's frontend (src/zturso/frontend.c, compiled with -DZTURSO_NO_MAIN):
    extern fn zturso_prepare(db: ?*anyopaque, sql: [*:0]const u8, ppStmt: *?*anyopaque, pnCol: *c_int, pzErr: *?[*:0]const u8) c_int;
};

fn cstr(z: ?[*:0]const u8) []const u8 {
    return if (z) |p| std.mem.span(p) else "NULL";
}

// Line-based stdin reader (fd 0) — avoids std.Io churn across Zig versions.
var in_buf: [4096]u8 = undefined;
fn readLine() !?[]const u8 {
    var n: usize = 0;
    while (n < in_buf.len) {
        var ch: [1]u8 = undefined;
        const got = try std.posix.read(0, &ch);
        if (got == 0) return if (n == 0) null else in_buf[0..n];
        if (ch[0] == '\n') return in_buf[0..n];
        in_buf[n] = ch[0];
        n += 1;
    }
    return in_buf[0..n];
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n;");
}

/// Compile one line via the frontend and print the result rows.
fn runOne(db: ?*anyopaque, line: []const u8) void {
    const t = trim(line);
    if (t.len == 0) return;

    // zturso_prepare needs a null-terminated string.
    var sqlbuf: [4096]u8 = undefined;
    if (t.len >= sqlbuf.len) {
        print("  (query too long)\n", .{});
        return;
    }
    @memcpy(sqlbuf[0..t.len], t);
    sqlbuf[t.len] = 0;
    const sqlz: [*:0]const u8 = @ptrCast(&sqlbuf);

    var stmt: ?*anyopaque = null;
    var nCol: c_int = 0;
    var errz: ?[*:0]const u8 = null;
    const rc = c.zturso_prepare(db, sqlz, &stmt, &nCol, &errz);
    if (rc != SQLITE_OK) {
        print("  error: {s}\n", .{cstr(errz)});
        return;
    }

    // header
    print("  ", .{});
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        if (i != 0) print(" | ", .{});
        if (c.sqlite3_column_name(stmt, i)) |nm| print("{s}", .{std.mem.span(nm)}) else print("col{d}", .{i});
    }
    print("\n  ", .{});
    i = 0;
    while (i < nCol) : (i += 1) print("{s}", .{if (i == 0) "--" else "-+--"});
    print("\n", .{});

    var rows: usize = 0;
    while (c.sqlite3_step(stmt) == SQLITE_ROW) {
        print("  ", .{});
        i = 0;
        while (i < nCol) : (i += 1) {
            if (i != 0) print(" | ", .{});
            print("{s}", .{cstr(c.sqlite3_column_text(stmt, i))});
        }
        print("\n", .{});
        rows += 1;
    }
    _ = c.sqlite3_finalize(stmt);
    print("  ({d} row{s})\n", .{ rows, if (rows == 1) "" else "s" });
}

pub fn main() !void {
    var db: ?*anyopaque = null;
    if (c.sqlite3_open(":memory:", &db) != SQLITE_OK) {
        print("open failed\n", .{});
        return;
    }
    defer _ = c.sqlite3_close(db);

    // Seed a real table via the normal engine — the frontend only READS it.
    const seed =
        "CREATE TABLE emp(id INTEGER PRIMARY KEY, name TEXT, dept TEXT, salary INTEGER);" ++
        "INSERT INTO emp(name,dept,salary) VALUES" ++
        " ('Ada','eng',120),('Linus','eng',115),('Grace','ops',130)," ++
        " ('Dennis','eng',110),('Margaret','ops',125);";
    _ = c.sqlite3_exec(db, seed, null, null, null);

    print(
        \\sqlite-zturso REPL — SQL is compiled by the fork's frontend (not SQLite's) onto the ported VDBE.
        \\Seeded table: emp(id, name, dept, salary).  Type a query, or Ctrl-D to quit.
        \\Examples:
        \\  SELECT 2+3*4
        \\  SELECT * FROM emp
        \\  SELECT name, salary FROM emp WHERE salary >= 125
        \\  SELECT id, salary+10 FROM emp WHERE dept <> 999 AND salary < 120
        \\
    , .{});
    while (true) {
        print("zturso> ", .{});
        const line = (try readLine()) orelse break;
        runOne(db, line);
    }
    print("\nbye.\n", .{});
}
