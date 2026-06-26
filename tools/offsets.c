/*
** Ground-truth struct layout extractor for the C->Zig migration.
**
** Compiled (by tools/gen_layout.sh) under both the production library config
** and the --dev testfixture config; its stdout drives src/c_layout.zig, whose
** numbers the Zig struct mirrors assert against at comptime. This guarantees a
** ported module's view of an internal struct matches the C the build links
** against — a wrong mirror fails to compile rather than silently corrupting.
**
** Add a P()/SZ() line here whenever a new port needs another field/struct, then
** re-run tools/gen_layout.sh.
*/
#include "sqliteInt.h"
#include "vdbeInt.h"
#include <stdio.h>
#include <stddef.h>

#define P(STRUCT, FIELD) printf("%s_%s %zu\n", #STRUCT, #FIELD, offsetof(struct STRUCT, FIELD))
#define SZ(TAG, STRUCT)  printf("sizeof_%s %zu\n", #TAG, sizeof(struct STRUCT))

int main(void) {
    /* Mem (== struct sqlite3_value) — needed by utf.c (stack-allocates one). */
    SZ(Mem, sqlite3_value);
    P(sqlite3_value, z);
    P(sqlite3_value, n);
    P(sqlite3_value, flags);
    P(sqlite3_value, enc);
    P(sqlite3_value, eSubtype);
    P(sqlite3_value, db);
    P(sqlite3_value, szMalloc);
    P(sqlite3_value, uTemp);
    P(sqlite3_value, zMalloc);
    P(sqlite3_value, xDel);

    /* sqlite3 connection — utf.c reads db->mallocFailed; table.c writes db->errCode. */
    SZ(sqlite3, sqlite3);
    P(sqlite3, mallocFailed);
    P(sqlite3, errCode);

    /* Sqlite3Config — os.c reads sqlite3Config.iPrngSeed. */
    SZ(Sqlite3Config, Sqlite3Config);
    P(Sqlite3Config, iPrngSeed);
    return 0;
}
