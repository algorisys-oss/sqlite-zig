# examples/

Small standalone programs that drive the **ported Zig** SQLite engine through
the public `sqlite3` C API. They link against this project's `libsqlite3.a`, so
running them exercises the Zig modules end-to-end.

## blog_crud.zig — interactive CRUD terminal

A tiny REPL that does **C**reate / **R**ead / **U**pdate / **D**elete on blog
posts in `sampledata/blog.db`, exercising real engine features: FTS5 full-text
search (`MATCH`, `snippet()`, `bm25` ranking via `ORDER BY rank`), foreign-key
cascades, and the schema's `AFTER INSERT` trigger that mirrors posts into the
FTS5 index. If the database has no `posts` table yet, the full blog schema
(`sampledata/blog_schema.sql`) is applied first, so it also works on a fresh DB.

### Run

```bash
zig build example                       # opens sampledata/blog.db
BLOG_DB=myblog.db zig-out/bin/blog_crud # open/create a different database file
```

`zig build example` builds and installs `zig-out/bin/blog_crud`. The database
file is chosen by the `BLOG_DB` environment variable (default
`sampledata/blog.db`).

### Commands

| Command | Action |
|---|---|
| `list` | list all posts (id, published, views, #comments, author, title) |
| `add` | create a post — prompts for title, body, author (creates the user if new) |
| `view <id>` | show one post and its comments |
| `edit <id>` | change a post's title/body (keeps the FTS5 index in sync) |
| `publish <id>` | toggle a post between published and draft |
| `delete <id>` | delete a post (comments cascade; FTS5 kept in sync) |
| `search <text>` | full-text search — FTS5 `MATCH` syntax (`AND` / `OR` / `"phrase"` / `pre*`) |
| `help` | list commands |
| `quit` | exit |

### Example session

```
blog> add
  title : Hello sqlite-zig
  body  : First post about the zig port of sqlite
  author: alice
  (created user 'alice' #1)
  + created post #1
blog> search zig
  FTS5 results for 'zig':
    #1 Hello sqlite-zig
        First post about the [zig] port of sqlite
blog> quit
```

The `edit` and `delete` paths show the standard FTS5 external-content sync
pattern: issue an `INSERT INTO post_fts(post_fts, rowid, title, body)
VALUES('delete', …)` with the *old* values before writing the new ones.
