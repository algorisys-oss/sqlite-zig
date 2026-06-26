//! Zig-native test suite for the (partly-Zig) SQLite engine.
//!
//! These are SQLite test cases ported to Zig: each `test` block drives the
//! engine through the public C API (declared `extern` below) and asserts results
//! with `std.testing`. Linked against this project's `libsqlite3.a`, so it
//! exercises the whole engine — including every ported Zig module (allocator,
//! VFS dispatch, UTF, journal, hashes, …) — from Zig rather than from the TCL
//! `testfixture`. Run with `zig build test-zig`.
//!
//! The assertions mirror representative cases from SQLite's own suite
//! (select1/func/aggregate/join/expr/…), adapted to a compact Zig form.

const std = @import("std");
const testing = std.testing;

// --- Minimal sqlite3 C API surface used by these tests ---
const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;

extern fn sqlite3_open(filename: [*:0]const u8, ppDb: *?*anyopaque) c_int;
extern fn sqlite3_close(db: ?*anyopaque) c_int;
extern fn sqlite3_exec(db: ?*anyopaque, sql: [*:0]const u8, cb: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_prepare_v2(db: ?*anyopaque, sql: [*:0]const u8, nByte: c_int, ppStmt: *?*anyopaque, pzTail: ?*?[*:0]const u8) c_int;
extern fn sqlite3_step(stmt: ?*anyopaque) c_int;
extern fn sqlite3_finalize(stmt: ?*anyopaque) c_int;
extern fn sqlite3_column_count(stmt: ?*anyopaque) c_int;
extern fn sqlite3_column_int64(stmt: ?*anyopaque, col: c_int) i64;
extern fn sqlite3_column_double(stmt: ?*anyopaque, col: c_int) f64;
extern fn sqlite3_column_text(stmt: ?*anyopaque, col: c_int) ?[*:0]const u8;
extern fn sqlite3_errmsg(db: ?*anyopaque) [*:0]const u8;
extern fn sqlite3_libversion() [*:0]const u8;
extern fn sqlite3_get_table(db: ?*anyopaque, sql: [*:0]const u8, pazResult: *?[*]?[*:0]u8, pnRow: *c_int, pnCol: *c_int, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_free_table(result: ?[*]?[*:0]u8) void;

/// Thin Zig wrapper over an in-memory database connection.
const Db = struct {
    h: ?*anyopaque,

    fn open() !Db {
        var h: ?*anyopaque = null;
        if (sqlite3_open(":memory:", &h) != SQLITE_OK) return error.OpenFailed;
        return .{ .h = h };
    }
    fn close(self: *Db) void {
        _ = sqlite3_close(self.h);
        self.h = null;
    }
    /// Run one or more statements with no result rows.
    fn exec(self: *Db, sql: [*:0]const u8) !void {
        if (sqlite3_exec(self.h, sql, null, null, null) != SQLITE_OK) {
            std.debug.print("exec error: {s}\n", .{sqlite3_errmsg(self.h)});
            return error.ExecFailed;
        }
    }
    /// Like `exec`, but the statement is expected to fail (e.g. a constraint
    /// violation). Returns the error silently — no stderr diagnostic — so a
    /// successful test run produces no spurious output. (Writing to stderr
    /// mid-test confuses the `--listen=-` build-runner protocol and was the
    /// cause of rare false "failed command" reports from `zig build test`.)
    fn execExpectFail(self: *Db, sql: [*:0]const u8) !void {
        if (sqlite3_exec(self.h, sql, null, null, null) == SQLITE_OK) return error.UnexpectedOk;
        return error.ExecFailed;
    }
    /// Run a query expected to yield exactly one integer in the first column.
    fn scalarI64(self: *Db, sql: [*:0]const u8) !i64 {
        var stmt: ?*anyopaque = null;
        if (sqlite3_prepare_v2(self.h, sql, -1, &stmt, null) != SQLITE_OK) return error.PrepareFailed;
        defer _ = sqlite3_finalize(stmt);
        if (sqlite3_step(stmt) != SQLITE_ROW) return error.NoRow;
        return sqlite3_column_int64(stmt, 0);
    }
    fn scalarF64(self: *Db, sql: [*:0]const u8) !f64 {
        var stmt: ?*anyopaque = null;
        if (sqlite3_prepare_v2(self.h, sql, -1, &stmt, null) != SQLITE_OK) return error.PrepareFailed;
        defer _ = sqlite3_finalize(stmt);
        if (sqlite3_step(stmt) != SQLITE_ROW) return error.NoRow;
        return sqlite3_column_double(stmt, 0);
    }
    /// Copy the first column's text of the first row into buf; return the slice.
    fn scalarText(self: *Db, sql: [*:0]const u8, buf: []u8) ![]const u8 {
        var stmt: ?*anyopaque = null;
        if (sqlite3_prepare_v2(self.h, sql, -1, &stmt, null) != SQLITE_OK) return error.PrepareFailed;
        defer _ = sqlite3_finalize(stmt);
        if (sqlite3_step(stmt) != SQLITE_ROW) return error.NoRow;
        const t = sqlite3_column_text(stmt, 0) orelse return buf[0..0];
        const s = std.mem.span(t);
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }
    /// Concatenate every result row's first column with '|' separators — a
    /// compact way to assert a whole result set (à la the TCL `execsql` idiom).
    fn rows(self: *Db, sql: [*:0]const u8, buf: []u8) ![]const u8 {
        var stmt: ?*anyopaque = null;
        if (sqlite3_prepare_v2(self.h, sql, -1, &stmt, null) != SQLITE_OK) return error.PrepareFailed;
        defer _ = sqlite3_finalize(stmt);
        var w: usize = 0;
        var first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const ncol = sqlite3_column_count(stmt);
            var c: c_int = 0;
            while (c < ncol) : (c += 1) {
                if (!first) {
                    buf[w] = '|';
                    w += 1;
                }
                first = false;
                const t = sqlite3_column_text(stmt, c);
                const s = if (t) |p| std.mem.span(p) else "";
                @memcpy(buf[w .. w + s.len], s);
                w += s.len;
            }
        }
        return buf[0..w];
    }
};

test "library version is 3.54.0" {
    try testing.expectEqualStrings("3.54.0", std.mem.span(sqlite3_libversion()));
}

test "open and trivial select" {
    var db = try Db.open();
    defer db.close();
    try testing.expectEqual(@as(i64, 2), try db.scalarI64("SELECT 1+1"));
    try testing.expectEqual(@as(i64, 1), try db.scalarI64("SELECT 1 < 2"));
    try testing.expectEqual(@as(i64, 0), try db.scalarI64("SELECT 5 = 6"));
}

test "create / insert / aggregate" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a INTEGER, b TEXT)");
    try db.exec("INSERT INTO t VALUES(1,'x'),(2,'y'),(3,'z'),(10,'w')");
    try testing.expectEqual(@as(i64, 4), try db.scalarI64("SELECT count(*) FROM t"));
    try testing.expectEqual(@as(i64, 16), try db.scalarI64("SELECT sum(a) FROM t"));
    try testing.expectEqual(@as(i64, 1), try db.scalarI64("SELECT min(a) FROM t"));
    try testing.expectEqual(@as(i64, 10), try db.scalarI64("SELECT max(a) FROM t"));
    try testing.expectApproxEqAbs(@as(f64, 4.0), try db.scalarF64("SELECT avg(a) FROM t"), 1e-9);
}

test "order by / group by / distinct as joined rows" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a,b)");
    try db.exec("INSERT INTO t VALUES(3,'c'),(1,'a'),(2,'b'),(1,'a')");
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("1|1|2|3", try db.rows("SELECT a FROM t ORDER BY a", &buf));
    try testing.expectEqualStrings("1|2|3", try db.rows("SELECT DISTINCT a FROM t ORDER BY a", &buf));
    try testing.expectEqualStrings("1|2|2|1|3|1", try db.rows("SELECT a, count(*) FROM t GROUP BY a ORDER BY a", &buf));
}

test "inner join" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE a(id, name); CREATE TABLE b(id, val)");
    try db.exec("INSERT INTO a VALUES(1,'one'),(2,'two'),(3,'three')");
    try db.exec("INSERT INTO b VALUES(1,100),(2,200),(2,250)");
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "one|100|two|200|two|250",
        try db.rows("SELECT a.name, b.val FROM a JOIN b ON a.id=b.id ORDER BY a.id, b.val", &buf),
    );
    try testing.expectEqual(@as(i64, 550), try db.scalarI64("SELECT sum(b.val) FROM a JOIN b ON a.id=b.id"));
}

test "scalar and string functions" {
    var db = try Db.open();
    defer db.close();
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("HELLO", try db.scalarText("SELECT upper('hello')", &buf));
    try testing.expectEqualStrings("abc", try db.scalarText("SELECT lower('ABC')", &buf));
    try testing.expectEqual(@as(i64, 5), try db.scalarI64("SELECT length('world')"));
    try testing.expectEqualStrings("ell", try db.scalarText("SELECT substr('hello',2,3)", &buf));
    try testing.expectEqualStrings("a-b-c", try db.scalarText("SELECT replace('a.b.c','.','-')", &buf));
    try testing.expectEqual(@as(i64, 1), try db.scalarI64("SELECT instr('abcdef','cd')=3"));
}

test "NULL semantics and coalesce" {
    var db = try Db.open();
    defer db.close();
    // NULL comparisons are NULL (not true); count(col) skips NULLs.
    try testing.expectEqual(@as(i64, 1), try db.scalarI64("SELECT (NULL IS NULL)"));
    try testing.expectEqual(@as(i64, 0), try db.scalarI64("SELECT (NULL IS NOT NULL)"));
    try testing.expectEqual(@as(i64, 7), try db.scalarI64("SELECT coalesce(NULL, NULL, 7)"));
    try db.exec("CREATE TABLE t(x)");
    try db.exec("INSERT INTO t VALUES(1),(NULL),(3),(NULL)");
    try testing.expectEqual(@as(i64, 2), try db.scalarI64("SELECT count(x) FROM t"));
    try testing.expectEqual(@as(i64, 4), try db.scalarI64("SELECT count(*) FROM t"));
}

test "integer and real arithmetic" {
    var db = try Db.open();
    defer db.close();
    try testing.expectEqual(@as(i64, 7), try db.scalarI64("SELECT 17 % 10"));
    try testing.expectEqual(@as(i64, 8), try db.scalarI64("SELECT 1 << 3"));
    try testing.expectEqual(@as(i64, 3), try db.scalarI64("SELECT 7 / 2"));
    try testing.expectApproxEqAbs(@as(f64, 3.5), try db.scalarF64("SELECT 7.0 / 2"), 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 2.0), try db.scalarF64("SELECT abs(-2.0)"), 1e-9);
}

test "subquery and IN" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a)");
    try db.exec("INSERT INTO t VALUES(1),(2),(3),(4),(5),(6)");
    try testing.expectEqual(@as(i64, 3), try db.scalarI64("SELECT count(*) FROM t WHERE a IN (2,4,6)"));
    // t = 1..6, avg = 3.5, so a > 3.5 selects 4,5,6 => 15.
    try testing.expectEqual(
        @as(i64, 15),
        try db.scalarI64("SELECT sum(a) FROM t WHERE a > (SELECT avg(a) FROM t)"),
    );
}

test "transaction rollback and commit (in-memory journal)" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a)");
    try db.exec("INSERT INTO t VALUES(1),(2)");
    try db.exec("BEGIN; INSERT INTO t VALUES(3),(4); ROLLBACK");
    try testing.expectEqual(@as(i64, 2), try db.scalarI64("SELECT count(*) FROM t"));
    try db.exec("BEGIN; INSERT INTO t VALUES(5); COMMIT");
    try testing.expectEqual(@as(i64, 3), try db.scalarI64("SELECT count(*) FROM t"));
    // Rows are 1,2,5 (the 3,4 insert was rolled back) => sum 8.
    try testing.expectEqual(@as(i64, 8), try db.scalarI64("SELECT sum(a) FROM t"));
}

test "index is used and correct" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a,b)");
    try db.exec("INSERT INTO t VALUES(1,'a'),(2,'b'),(3,'c'),(4,'d')");
    try db.exec("CREATE INDEX idx ON t(a)");
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("c", try db.scalarText("SELECT b FROM t WHERE a=3", &buf));
    // The index should be visible via the schema and the EXPLAIN QUERY PLAN.
    try testing.expectEqualStrings("idx", try db.scalarText("SELECT name FROM pragma_index_list('t')", &buf));
    const plan = try db.rows("EXPLAIN QUERY PLAN SELECT b FROM t WHERE a=3", &buf);
    try testing.expect(std.mem.indexOf(u8, plan, "idx") != null);
}

test "CTE (WITH) recursive count" {
    var db = try Db.open();
    defer db.close();
    const sum_1_to_10 = try db.scalarI64(
        \\WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<10)
        \\SELECT sum(x) FROM c
    );
    try testing.expectEqual(@as(i64, 55), sum_1_to_10);
}

test "case expression" {
    var db = try Db.open();
    defer db.close();
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "neg|zero|pos",
        try db.rows(
            \\SELECT CASE WHEN v<0 THEN 'neg' WHEN v=0 THEN 'zero' ELSE 'pos' END
            \\FROM (SELECT -1 AS v UNION ALL SELECT 0 UNION ALL SELECT 5) ORDER BY v
        , &buf),
    );
}

test "sqlite3_get_table (the Zig-ported table.c)" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a,b); INSERT INTO t VALUES(1,'x'),(2,'y'),(3,'z')");
    var result: ?[*]?[*:0]u8 = null;
    var nrow: c_int = 0;
    var ncol: c_int = 0;
    try testing.expectEqual(SQLITE_OK, sqlite3_get_table(db.h, "SELECT a,b FROM t ORDER BY a", &result, &nrow, &ncol, null));
    defer sqlite3_free_table(result);
    try testing.expectEqual(@as(c_int, 3), nrow);
    try testing.expectEqual(@as(c_int, 2), ncol);
    // result[0..ncol] are the column headers; then nrow*ncol cells row-major.
    const cells = result.?;
    try testing.expectEqualStrings("a", std.mem.span(cells[0].?));
    try testing.expectEqualStrings("b", std.mem.span(cells[1].?));
    try testing.expectEqualStrings("1", std.mem.span(cells[2].?)); // row0,col0
    try testing.expectEqualStrings("z", std.mem.span(cells[7].?)); // row2,col1
}

test "foreign key enforcement" {
    var db = try Db.open();
    defer db.close();
    try db.exec("PRAGMA foreign_keys=ON");
    try db.exec("CREATE TABLE parent(id INTEGER PRIMARY KEY)");
    try db.exec("CREATE TABLE child(pid INTEGER REFERENCES parent(id))");
    try db.exec("INSERT INTO parent VALUES(1),(2)");
    try db.exec("INSERT INTO child VALUES(1)");
    // Inserting a child with no matching parent must fail.
    try testing.expectError(error.ExecFailed, db.execExpectFail("INSERT INTO child VALUES(99)"));
    try testing.expectEqual(@as(i64, 1), try db.scalarI64("SELECT count(*) FROM child"));
}

// Exercises the ported analyze.zig (module 59): the ANALYZE command writes
// sqlite_stat1 (statInit/statPush/openStatTable), and sqlite3AnalysisLoad reads
// it back on the next prepare so the planner consumes the stats. The functional
// battery never runs ANALYZE, so this is the only gate-level coverage.
test "ANALYZE writes and loads index statistics" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a,b,c)");
    try db.exec("CREATE INDEX i1 ON t(a,b)");
    try db.exec("CREATE INDEX i2 ON t(c)");
    // 1000 rows: a has 10 distinct values, b has 7, c is unique.
    try db.exec(
        \\INSERT INTO t WITH RECURSIVE g(x) AS (
        \\  SELECT 1 UNION ALL SELECT x+1 FROM g WHERE x<1000)
        \\SELECT x%10, x%7, x FROM g
    );
    try db.exec("ANALYZE");
    var buf: [128]u8 = undefined;
    // sqlite_stat1: i1 → 1000 rows, ~100 per a, ~15 per (a,b); i2 → unique.
    try testing.expectEqualStrings(
        "1000 100 15|1000 1",
        try db.rows("SELECT stat FROM sqlite_stat1 ORDER BY idx", &buf),
    );
    // ANALYZE ends by calling sqlite3AnalysisLoad to reload the stats it just
    // wrote; running a planned query afterward must succeed with those stats
    // live (TF_HasStat1) rather than crash on the loaded aiRowLogEst arrays.
    try testing.expectEqual(
        @as(i64, 100),
        try db.scalarI64("SELECT count(*) FROM t WHERE a=5"),
    );
}

test "view and trigger" {
    var db = try Db.open();
    defer db.close();
    try db.exec("CREATE TABLE t(a,b); INSERT INTO t VALUES(1,10),(2,20),(3,30)");
    try db.exec("CREATE VIEW v AS SELECT a, b*2 AS b2 FROM t WHERE a>1");
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("2|40|3|60", try db.rows("SELECT a,b2 FROM v ORDER BY a", &buf));
    // AFTER INSERT trigger accumulates into a log table.
    try db.exec("CREATE TABLE log(n)");
    try db.exec("CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES(new.a); END");
    try db.exec("INSERT INTO t VALUES(4,40),(5,50)");
    try testing.expectEqual(@as(i64, 9), try db.scalarI64("SELECT sum(n) FROM log")); // 4+5
}

test "blob literals and length" {
    var db = try Db.open();
    defer db.close();
    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(i64, 3), try db.scalarI64("SELECT length(x'aabbcc')"));
    try testing.expectEqualStrings("AABBCC", try db.scalarText("SELECT hex(x'aabbcc')", &buf));
    try testing.expectEqual(@as(i64, 5), try db.scalarI64("SELECT length(zeroblob(5))"));
    try testing.expectEqualStrings("blob", try db.scalarText("SELECT typeof(x'00')", &buf));
}

test "hex / typeof / cast" {
    var db = try Db.open();
    defer db.close();
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("integer", try db.scalarText("SELECT typeof(42)", &buf));
    try testing.expectEqualStrings("real", try db.scalarText("SELECT typeof(42.0)", &buf));
    try testing.expectEqualStrings("text", try db.scalarText("SELECT typeof('x')", &buf));
    try testing.expectEqual(@as(i64, 255), try db.scalarI64("SELECT cast('255' AS INTEGER)"));
    try testing.expectEqualStrings("41", try db.scalarText("SELECT hex('A')", &buf));
    try testing.expectEqualStrings("4162", try db.scalarText("SELECT hex('Ab')", &buf));
}
