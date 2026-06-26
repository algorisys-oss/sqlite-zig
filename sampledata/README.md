# sampledata — blog database demo

A worked example proving the (partly-Zig) SQLite build is fully functional.
`blog.db` is a real database (users / posts / comments / tags, with relations,
constraints, an index, a view, triggers, and an FTS5 index).

## Rebuild from scratch
```sh
rm -f sampledata/blog.db sampledata/blog.db-*
zig-out/bin/sqlite3 sampledata/blog.db ".read sampledata/blog_schema.sql"
zig-out/bin/sqlite3 sampledata/blog.db ".read sampledata/blog_seed.sql"
```

## Try it
```sh
zig-out/bin/sqlite3 sampledata/blog.db          # interactive shell
zig-out/bin/sqlite3 sampledata/blog.db "SELECT * FROM v_post_summary;"
zig-out/bin/sqlite3 sampledata/blog.db \
  "SELECT p.title FROM post_fts JOIN posts p ON p.id=post_fts.rowid WHERE post_fts MATCH 'sqlite';"
```

Verified working: relations + JOINs, aggregates, the `v_post_summary` view,
INSERT triggers (denormalized `user_stats` + FTS sync), FOREIGN KEY enforcement
(rejection + ON DELETE CASCADE), UNIQUE/CHECK constraints, indexed query plans,
transactions (BEGIN/ROLLBACK atomicity), FTS5 MATCH + snippet ranking, JSON
functions, window functions, recursive CTEs, math functions, WAL mode, and
`PRAGMA integrity_check` / `foreign_key_check` = ok.

This `sqlite3` is built by `zig build`; 25 modules are ported to Zig (allocator,
mutexes, VFS dispatch, page cache, UTF, journal, sqlite3_exec, ...) and linked
with the still-C remainder. See ../PROGRESS.md.
