# token-count.md — migration scope sizing

Size of the upstream SQLite C source we are porting (the "how big is this job"
number). Distinct from [tokens.txt](tokens.txt), which logs per-prompt LLM
token usage for this project.

- Source: SQLite v3.54.0, `/home/rajesh/opensource/sqlite/src` (`*.c` + `*.h`)
- Lines of code: **219,160** across 125 files
- Estimated tokens (~4 chars/token over source bytes): **~1.9M tokens** (order-of-magnitude scope, excludes `ext/`, `test/`, `tool/`)

Largest files (port-effort hotspots):

| Bytes | File |
|---|---|
| 406 KB | src/btree.c |
| 334 KB | src/select.c |
| 322 KB | src/vdbe.c |
| 302 KB | src/pager.c |
| 298 KB | src/where.c |
| 296 KB | src/os_unix.c |
| 269 KB | src/expr.c |
| 196 KB | src/build.c |
| 186 KB | src/vdbeaux.c |
| 178 KB | src/wal.c |

Regenerate counts with:

```bash
find /home/rajesh/opensource/sqlite/src \( -name '*.c' -o -name '*.h' \) | xargs wc -l | tail -1
```
