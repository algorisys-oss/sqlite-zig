/*
** sqlite-zturso — reusable frontend entry point (branch-only)
** ============================================================
** Exposes the fork's SQL frontend (src/zturso/frontend.c) as a C-ABI function so
** other translation units can drive it — e.g. the Zig REPL in
** examples/zturso_repl.zig. Compile frontend.c with -DZTURSO_NO_MAIN to link it
** as a library (without its demo main()).
*/
#ifndef ZTURSO_FRONTEND_H
#define ZTURSO_FRONTEND_H

#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
** Compile `sql` (in the zturso dialect: SELECT expr… [FROM t [WHERE cond…]]) into
** a runnable statement on the ported engine, WITHOUT SQLite's tokenizer/parser.
** On success returns SQLITE_OK, sets *ppStmt (step it like any sqlite3_stmt) and
** *pnCol (result column count). On failure returns an error code and points
** *pzErr at a static message. The caller sqlite3_finalize()s *ppStmt.
*/
int zturso_prepare(sqlite3 *db, const char *sql,
                   sqlite3_stmt **ppStmt, int *pnCol, const char **pzErr);

#ifdef __cplusplus
}
#endif

#endif /* ZTURSO_FRONTEND_H */
