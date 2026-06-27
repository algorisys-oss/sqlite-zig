#include "sqliteInt.h"
#include <stdio.h>
#include <stddef.h>
#include <string.h>

/* Set one named bit, scan the struct bytes after onError to report byte+mask. */
#define PROBE(FIELD) do { \
    Index ix; memset(&ix, 0, sizeof ix); ix.FIELD = 1; \
    size_t base = offsetof(Index, onError); \
    unsigned char *p = (unsigned char*)&ix; \
    int found = 0; \
    for (size_t i = base; i < sizeof ix; i++) { \
        if (p[i]) { printf("%-12s byte=onError+%zu mask=0x%02x\n", #FIELD, i-base, p[i]); found=1; break; } \
    } \
    if (!found) printf("%-12s (no bit set?)\n", #FIELD); \
} while(0)

int main(void){
    printf("onError offset=%zu sizeof(Index)=%zu\n", offsetof(Index,onError), sizeof(Index));
    /* idxType is 2 bits; set to 3 to see its byte/mask */
    { Index ix; memset(&ix,0,sizeof ix); ix.idxType=3; size_t base=offsetof(Index,onError);
      unsigned char *p=(unsigned char*)&ix;
      for(size_t i=base;i<sizeof ix;i++){ if(p[i]){ printf("%-12s byte=onError+%zu mask=0x%02x\n","idxType",i-base,p[i]); break; } } }
    PROBE(bUnordered);
    PROBE(uniqNotNull);
    PROBE(isResized);
    PROBE(isCovering);
    PROBE(noSkipScan);
    PROBE(hasStat1);
    PROBE(bNoQuery);
    PROBE(bAscKeyBug);
    PROBE(bHasVCol);
    PROBE(bHasExpr);
    return 0;
}
