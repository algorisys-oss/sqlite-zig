//! blog_crud.zig — an interactive terminal app doing CRUD on the blog database.
//!
//! A small REPL that drives the (mostly-Zig) SQLite engine through the public
//! sqlite3 C API to create / read / update / delete blog posts in
//! `sampledata/blog.db`. It is linked against this project's libsqlite3.a, so
//! every query exercises the ported Zig modules end-to-end — including FTS5
//! full-text search, foreign-key cascades, and the schema's INSERT trigger.
//!
//! Run with:   zig build example                 (opens sampledata/blog.db)
//!             zig build example -- myblog.db     (opens a different file)
//!
//! If the target file has no `posts` table yet, the full blog schema (embedded
//! from sampledata/blog_schema.sql) is applied first, so it works on a fresh DB.
//!
//! Commands (type `help` at the prompt):
//!   list                  list all posts
//!   add                   create a post (prompts title / body / author)
//!   view <id>             show one post with its comments
//!   edit <id>             change a post's title / body (keeps FTS5 in sync)
//!   publish <id>          mark a post published / unpublished (toggles)
//!   delete <id>           delete a post (comments cascade; FTS5 kept in sync)
//!   search <text>         FTS5 MATCH over post titles + bodies
//!   help                  show this help
//!   quit                  exit

const std = @import("std");
const print = std.debug.print;

// Registered in build.zig via addAnonymousImport (it lives in sampledata/,
// outside this file's directory, which @embedFile cannot otherwise reach).
const schema_sql = @embedFile("blog_schema.sql");

// --- sqlite3 C API (only the entry points this demo needs) ---
const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
// SQLITE_TRANSIENT == (void(*)(void*))-1 : tell SQLite to copy the bound bytes.
const SQLITE_TRANSIENT: ?*const anyopaque = @ptrFromInt(std.math.maxInt(usize));

const c = struct {
    extern fn sqlite3_open(filename: [*:0]const u8, ppDb: *?*anyopaque) c_int;
    extern fn sqlite3_close(db: ?*anyopaque) c_int;
    extern fn sqlite3_exec(db: ?*anyopaque, sql: [*:0]const u8, cb: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
    extern fn sqlite3_prepare_v2(db: ?*anyopaque, sql: [*:0]const u8, n: c_int, ppStmt: *?*anyopaque, tail: ?*?[*:0]const u8) c_int;
    extern fn sqlite3_step(stmt: ?*anyopaque) c_int;
    extern fn sqlite3_reset(stmt: ?*anyopaque) c_int;
    extern fn sqlite3_finalize(stmt: ?*anyopaque) c_int;
    extern fn sqlite3_bind_text(stmt: ?*anyopaque, i: c_int, t: [*]const u8, n: c_int, d: ?*const anyopaque) c_int;
    extern fn sqlite3_bind_int(stmt: ?*anyopaque, i: c_int, v: c_int) c_int;
    extern fn sqlite3_bind_int64(stmt: ?*anyopaque, i: c_int, v: i64) c_int;
    extern fn sqlite3_column_text(stmt: ?*anyopaque, col: c_int) ?[*:0]const u8;
    extern fn sqlite3_column_int(stmt: ?*anyopaque, col: c_int) c_int;
    extern fn sqlite3_column_int64(stmt: ?*anyopaque, col: c_int) i64;
    extern fn sqlite3_last_insert_rowid(db: ?*anyopaque) i64;
    extern fn sqlite3_changes(db: ?*anyopaque) c_int;
    extern fn sqlite3_errmsg(db: ?*anyopaque) [*:0]const u8;
    extern fn sqlite3_libversion() [*:0]const u8;
};

// libc — used for env lookup (the std arg/env API churns across Zig versions).
extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;

var gdb: ?*anyopaque = null;

fn fail(comptime ctx: []const u8) error{Sqlite} {
    print("!! {s}: {s}\n", .{ ctx, c.sqlite3_errmsg(gdb) });
    return error.Sqlite;
}

/// Run a statement that returns no rows (DDL / DML). `sql` must be NUL-terminated.
fn exec(sql: [*:0]const u8) !void {
    if (c.sqlite3_exec(gdb, sql, null, null, null) != SQLITE_OK) return fail("exec");
}

/// Prepare a statement from a (non-sentinel) slice.
fn prepare(sql: []const u8) !?*anyopaque {
    var stmt: ?*anyopaque = null;
    if (c.sqlite3_prepare_v2(gdb, @ptrCast(sql.ptr), @intCast(sql.len), &stmt, null) != SQLITE_OK) {
        return fail("prepare");
    }
    return stmt;
}

fn bindText(stmt: ?*anyopaque, i: c_int, s: []const u8) void {
    _ = c.sqlite3_bind_text(stmt, i, s.ptr, @intCast(s.len), SQLITE_TRANSIENT);
}

fn col(stmt: ?*anyopaque, i: c_int) []const u8 {
    const t = c.sqlite3_column_text(stmt, i) orelse return "";
    return std.mem.span(t);
}

// ---------------------------------------------------------------------------
// Line-based stdin reader (fd 0). Avoids std.Io churn across Zig versions and
// works fine for an interactive REPL.
var in_buf: [4096]u8 = undefined;

/// Read one line (without the trailing newline). Returns null at EOF.
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

fn prompt(label: []const u8) !?[]const u8 {
    print("{s}", .{label});
    return readLine();
}

/// Prompt, then COPY the trimmed result into `dst` — readLine reuses one shared
/// buffer, so a result must be copied out before the next prompt overwrites it.
fn promptCopy(label: []const u8, dst: []u8) !?[]const u8 {
    const line = (try prompt(label)) orelse return null;
    const t = trim(line);
    const n = @min(t.len, dst.len);
    @memcpy(dst[0..n], t[0..n]);
    return dst[0..n];
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r");
}

// ---------------------------------------------------------------------------

fn schemaPresent() bool {
    const stmt = prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='posts'") catch return false;
    defer _ = c.sqlite3_finalize(stmt);
    return c.sqlite3_step(stmt) == SQLITE_ROW;
}

fn cmdList() !void {
    const stmt = try prepare(
        \\SELECT p.id, p.title, u.username, p.views, p.published,
        \\       (SELECT count(*) FROM comments cm WHERE cm.post_id=p.id)
        \\FROM posts p JOIN users u ON u.id=p.author_id
        \\ORDER BY p.id
    );
    defer _ = c.sqlite3_finalize(stmt);
    print("\n  id | pub | views | cmts | author        | title\n", .{});
    print("  ---+-----+-------+------+---------------+----------------------------\n", .{});
    var n: usize = 0;
    while (c.sqlite3_step(stmt) == SQLITE_ROW) : (n += 1) {
        print("  {d:>2} |  {s}  | {d:>5} | {d:>4} | {s:<13} | {s}\n", .{
            c.sqlite3_column_int(stmt, 0),
            if (c.sqlite3_column_int(stmt, 4) != 0) "Y" else "-",
            c.sqlite3_column_int(stmt, 3),
            c.sqlite3_column_int(stmt, 5),
            col(stmt, 2),
            col(stmt, 1),
        });
    }
    if (n == 0) print("  (no posts yet — use `add`)\n", .{});
    print("\n", .{});
}

/// Look up a user id by username, creating the user if necessary.
fn ensureUser(username: []const u8) !i64 {
    {
        const q = try prepare("SELECT id FROM users WHERE username=?");
        defer _ = c.sqlite3_finalize(q);
        bindText(q, 1, username);
        if (c.sqlite3_step(q) == SQLITE_ROW) return c.sqlite3_column_int64(q, 0);
    }
    // Create with a derived email (UNIQUE / CHECK length>=3 enforced by schema).
    const ins = try prepare("INSERT INTO users(username, email) VALUES(?, ? || '@example.com')");
    defer _ = c.sqlite3_finalize(ins);
    bindText(ins, 1, username);
    bindText(ins, 2, username);
    if (c.sqlite3_step(ins) != SQLITE_DONE) return fail("create user");
    const id = c.sqlite3_last_insert_rowid(gdb);
    print("  (created user '{s}' #{d})\n", .{ username, id });
    return id;
}

fn cmdAdd() !void {
    var tbuf: [512]u8 = undefined;
    var bbuf: [4096]u8 = undefined;
    var abuf: [128]u8 = undefined;
    const title = (try promptCopy("  title : ", &tbuf)) orelse return;
    const body = (try promptCopy("  body  : ", &bbuf)) orelse return;
    const author = (try promptCopy("  author: ", &abuf)) orelse return;
    if (title.len == 0 or author.len < 3) {
        print("  ! title required and author must be >= 3 chars\n", .{});
        return;
    }
    const author_id = try ensureUser(author);

    // The schema's AFTER INSERT trigger mirrors the row into post_fts (FTS5).
    const ins = try prepare("INSERT INTO posts(author_id, title, body, published) VALUES(?,?,?,0)");
    defer _ = c.sqlite3_finalize(ins);
    _ = c.sqlite3_bind_int64(ins, 1, author_id);
    bindText(ins, 2, title);
    bindText(ins, 3, body);
    if (c.sqlite3_step(ins) != SQLITE_DONE) return fail("insert post");
    print("  + created post #{d}\n", .{c.sqlite3_last_insert_rowid(gdb)});
}

fn cmdView(id: i64) !void {
    const stmt = try prepare(
        \\SELECT p.title, p.body, u.username, p.views, p.published, p.created
        \\FROM posts p JOIN users u ON u.id=p.author_id WHERE p.id=?
    );
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, id);
    if (c.sqlite3_step(stmt) != SQLITE_ROW) {
        print("  ! no post #{d}\n", .{id});
        return;
    }
    print("\n  #{d}  {s}\n", .{ id, col(stmt, 0) });
    print("  by {s} · {d} views · {s} · {s}\n", .{
        col(stmt, 2), c.sqlite3_column_int(stmt, 3),
        if (c.sqlite3_column_int(stmt, 4) != 0) "published" else "draft",
        col(stmt, 5),
    });
    print("  {s}\n", .{col(stmt, 1)});

    const cstmt = try prepare(
        \\SELECT u.username, cm.body FROM comments cm JOIN users u ON u.id=cm.user_id
        \\WHERE cm.post_id=? ORDER BY cm.id
    );
    defer _ = c.sqlite3_finalize(cstmt);
    _ = c.sqlite3_bind_int64(cstmt, 1, id);
    var any = false;
    while (c.sqlite3_step(cstmt) == SQLITE_ROW) {
        if (!any) print("  comments:\n", .{});
        any = true;
        print("    - {s}: {s}\n", .{ col(cstmt, 0), col(cstmt, 1) });
    }
    print("\n", .{});
}

fn cmdEdit(id: i64) !void {
    // Fetch the current title/body — needed to delete the matching FTS5 row
    // (post_fts is an external-content table; deletes need the old values).
    var old_title_buf: [512]u8 = undefined;
    var old_body_buf: [4096]u8 = undefined;
    var old_title: []const u8 = undefined;
    var old_body: []const u8 = undefined;
    {
        const q = try prepare("SELECT title, body FROM posts WHERE id=?");
        defer _ = c.sqlite3_finalize(q);
        _ = c.sqlite3_bind_int64(q, 1, id);
        if (c.sqlite3_step(q) != SQLITE_ROW) {
            print("  ! no post #{d}\n", .{id});
            return;
        }
        const t = col(q, 0);
        const bdy = col(q, 1);
        @memcpy(old_title_buf[0..t.len], t);
        @memcpy(old_body_buf[0..bdy.len], bdy);
        old_title = old_title_buf[0..t.len];
        old_body = old_body_buf[0..bdy.len];
    }

    print("  (enter blank to keep the current value)\n", .{});
    var new_title_buf: [512]u8 = undefined;
    var new_body_buf: [4096]u8 = undefined;
    var title = (try promptCopy("  new title: ", &new_title_buf)) orelse return;
    var body = (try promptCopy("  new body : ", &new_body_buf)) orelse return;
    if (title.len == 0) title = old_title;
    if (body.len == 0) body = old_body;

    try exec("BEGIN");
    errdefer exec("ROLLBACK") catch {};

    // Remove the stale FTS5 entry, then write the new post row + FTS5 entry.
    {
        const del = try prepare("INSERT INTO post_fts(post_fts, rowid, title, body) VALUES('delete', ?, ?, ?)");
        defer _ = c.sqlite3_finalize(del);
        _ = c.sqlite3_bind_int64(del, 1, id);
        bindText(del, 2, old_title);
        bindText(del, 3, old_body);
        if (c.sqlite3_step(del) != SQLITE_DONE) return fail("fts delete");
    }
    {
        const upd = try prepare("UPDATE posts SET title=?, body=? WHERE id=?");
        defer _ = c.sqlite3_finalize(upd);
        bindText(upd, 1, title);
        bindText(upd, 2, body);
        _ = c.sqlite3_bind_int64(upd, 3, id);
        if (c.sqlite3_step(upd) != SQLITE_DONE) return fail("update post");
    }
    {
        const fts = try prepare("INSERT INTO post_fts(rowid, title, body) VALUES(?, ?, ?)");
        defer _ = c.sqlite3_finalize(fts);
        _ = c.sqlite3_bind_int64(fts, 1, id);
        bindText(fts, 2, title);
        bindText(fts, 3, body);
        if (c.sqlite3_step(fts) != SQLITE_DONE) return fail("fts insert");
    }
    try exec("COMMIT");
    print("  ~ updated post #{d}\n", .{id});
}

fn cmdPublish(id: i64) !void {
    const stmt = try prepare("UPDATE posts SET published = 1 - published WHERE id=?");
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, id);
    if (c.sqlite3_step(stmt) != SQLITE_DONE) return fail("publish");
    if (c.sqlite3_changes(gdb) == 0) print("  ! no post #{d}\n", .{id}) else print("  ~ toggled published on #{d}\n", .{id});
}

fn cmdDelete(id: i64) !void {
    // Keep FTS5 in sync: delete its entry (needs old values) before the row.
    const q = try prepare("SELECT title, body FROM posts WHERE id=?");
    _ = c.sqlite3_bind_int64(q, 1, id);
    if (c.sqlite3_step(q) != SQLITE_ROW) {
        _ = c.sqlite3_finalize(q);
        print("  ! no post #{d}\n", .{id});
        return;
    }
    var tb: [512]u8 = undefined;
    var bb: [4096]u8 = undefined;
    const t = col(q, 0);
    const bdy = col(q, 1);
    @memcpy(tb[0..t.len], t);
    @memcpy(bb[0..bdy.len], bdy);
    _ = c.sqlite3_finalize(q);

    try exec("BEGIN");
    errdefer exec("ROLLBACK") catch {};
    {
        const del = try prepare("INSERT INTO post_fts(post_fts, rowid, title, body) VALUES('delete', ?, ?, ?)");
        defer _ = c.sqlite3_finalize(del);
        _ = c.sqlite3_bind_int64(del, 1, id);
        bindText(del, 2, tb[0..t.len]);
        bindText(del, 3, bb[0..bdy.len]);
        if (c.sqlite3_step(del) != SQLITE_DONE) return fail("fts delete");
    }
    {
        // comments cascade via the schema's ON DELETE CASCADE foreign key.
        const dp = try prepare("DELETE FROM posts WHERE id=?");
        defer _ = c.sqlite3_finalize(dp);
        _ = c.sqlite3_bind_int64(dp, 1, id);
        if (c.sqlite3_step(dp) != SQLITE_DONE) return fail("delete post");
    }
    try exec("COMMIT");
    print("  - deleted post #{d}\n", .{id});
}

fn cmdSearch(q: []const u8) !void {
    const stmt = try prepare(
        \\SELECT p.id, p.title, snippet(post_fts, 1, '[', ']', '…', 8)
        \\FROM post_fts JOIN posts p ON p.id = post_fts.rowid
        \\WHERE post_fts MATCH ? ORDER BY rank
    );
    defer _ = c.sqlite3_finalize(stmt);
    bindText(stmt, 1, q);
    print("\n  FTS5 results for '{s}':\n", .{q});
    var n: usize = 0;
    while (c.sqlite3_step(stmt) == SQLITE_ROW) : (n += 1) {
        print("    #{d} {s}\n        {s}\n", .{ c.sqlite3_column_int(stmt, 0), col(stmt, 1), col(stmt, 2) });
    }
    if (n == 0) print("    (no matches)\n", .{});
    print("\n", .{});
}

fn help() void {
    print(
        \\
        \\  Commands:
        \\    list              list all posts
        \\    add               create a post (prompts for title / body / author)
        \\    view <id>         show a post and its comments
        \\    edit <id>         change a post's title / body (FTS5 kept in sync)
        \\    publish <id>      toggle a post between published / draft
        \\    delete <id>       delete a post (comments cascade)
        \\    search <text>     full-text search (FTS5 MATCH syntax: AND / OR / "phrase" / pre*)
        \\    help              this message
        \\    quit              exit
        \\
    , .{});
}

fn parseId(rest: []const u8) ?i64 {
    return std.fmt.parseInt(i64, trim(rest), 10) catch null;
}

pub fn main() !void {
    // Pick the database file from the BLOG_DB env var, defaulting to the sample
    // DB:   BLOG_DB=myblog.db zig-out/bin/blog_crud
    const path_arg: []const u8 = if (getenv("BLOG_DB")) |p| std.mem.span(p) else "sampledata/blog.db";
    var path_buf: [1024]u8 = undefined;
    if (path_arg.len >= path_buf.len) return error.PathTooLong;
    @memcpy(path_buf[0..path_arg.len], path_arg);
    path_buf[path_arg.len] = 0;
    const db_path: [*:0]const u8 = @ptrCast(&path_buf);

    if (c.sqlite3_open(db_path, &gdb) != SQLITE_OK) {
        print("cannot open {s}: {s}\n", .{ path_arg, c.sqlite3_errmsg(gdb) });
        return error.OpenFailed;
    }
    defer _ = c.sqlite3_close(gdb);
    try exec("PRAGMA foreign_keys=ON");

    if (!schemaPresent()) {
        print("(applying blog schema to {s})\n", .{path_arg});
        try exec(schema_sql ++ "\x00");
    }

    print("sqlite-zig blog CRUD — SQLite {s} via the ported Zig engine\n", .{c.sqlite3_libversion()});
    print("database: {s}   (type `help`)\n", .{path_arg});

    while (true) {
        const line_opt = try prompt("\nblog> ");
        const line = trim(line_opt orelse break); // EOF (Ctrl-D) → exit
        if (line.len == 0) continue;

        // Split into the verb and the remainder.
        const sp = std.mem.indexOfScalar(u8, line, ' ');
        const verb = if (sp) |i| line[0..i] else line;
        const rest = if (sp) |i| line[i + 1 ..] else "";

        if (std.mem.eql(u8, verb, "quit") or std.mem.eql(u8, verb, "exit")) break;
        if (std.mem.eql(u8, verb, "help")) {
            help();
        } else if (std.mem.eql(u8, verb, "list")) {
            cmdList() catch {};
        } else if (std.mem.eql(u8, verb, "add")) {
            cmdAdd() catch {};
        } else if (std.mem.eql(u8, verb, "search")) {
            if (trim(rest).len == 0) print("  usage: search <text>\n", .{}) else cmdSearch(trim(rest)) catch {};
        } else if (std.mem.eql(u8, verb, "view") or std.mem.eql(u8, verb, "edit") or
            std.mem.eql(u8, verb, "publish") or std.mem.eql(u8, verb, "delete"))
        {
            const id = parseId(rest) orelse {
                print("  usage: {s} <id>\n", .{verb});
                continue;
            };
            if (std.mem.eql(u8, verb, "view")) cmdView(id) catch {};
            if (std.mem.eql(u8, verb, "edit")) cmdEdit(id) catch {};
            if (std.mem.eql(u8, verb, "publish")) cmdPublish(id) catch {};
            if (std.mem.eql(u8, verb, "delete")) cmdDelete(id) catch {};
        } else {
            print("  ? unknown command '{s}' — type `help`\n", .{verb});
        }
    }
    print("bye.\n", .{});
}
