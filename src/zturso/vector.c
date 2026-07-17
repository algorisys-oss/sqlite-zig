/*
** sqlite-zturso — Phase 4: vector search over the ported engine
** =============================================================
** Turso ships a native vector-search extension; upstream SQLite has none. This
** demonstrates the same capability can be added to *our* ported engine purely
** through the public function-registration API — no engine changes. It registers
** scalar functions and runs a real k-nearest-neighbour query:
**
**     vec_dim(v)        -> number of components
**     vec_dot(a,b)      -> dot product
**     vec_l2(a,b)       -> Euclidean distance
**     vec_cosine(a,b)   -> cosine distance (1 - cosθ), in [0,2]
**
** kNN then falls out of plain SQL the ported VDBE already runs:
**     SELECT label, vec_cosine(embedding, :probe) AS d FROM items ORDER BY d LIMIT k;
**
** Vectors are stored as TEXT like "[0.1, 0.9, 0.2]" (or "0.1 0.9 0.2"). A real
** deployment would use a compact blob + an ANN index; the point here is that the
** *extension seam* is fully open on the ported engine. Public API only.
*/
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define VEC_MAX 64

/* Parse a text vector ("[a, b, c]" or "a b c") into out[]; return the count. */
static int parseVec(const unsigned char *z, double *out){
  int n=0;
  if( z==0 ) return 0;
  const char *p=(const char*)z;
  while( *p && n<VEC_MAX ){
    while( *p==' '||*p=='\t'||*p=='['||*p==']'||*p==','||*p=='\n'||*p=='\r' ) p++;
    if( *p==0 ) break;
    char *end=0;
    double d=strtod(p, &end);
    if( end==p ) break;           /* not a number: stop */
    out[n++]=d; p=end;
  }
  return n;
}

/* Load both args as vectors of equal dim; on mismatch flag an error, return 0. */
static int loadPair(sqlite3_context *ctx, sqlite3_value **v, double *a, double *b){
  int na=parseVec(sqlite3_value_text(v[0]), a);
  int nb=parseVec(sqlite3_value_text(v[1]), b);
  if( na==0 || nb==0 || na!=nb ){
    sqlite3_result_error(ctx, "vector dimension mismatch or empty vector", -1);
    return 0;
  }
  return na;
}

static void fnDim(sqlite3_context *ctx, int argc, sqlite3_value **v){
  (void)argc; double a[VEC_MAX];
  sqlite3_result_int(ctx, parseVec(sqlite3_value_text(v[0]), a));
}
static void fnDot(sqlite3_context *ctx, int argc, sqlite3_value **v){
  (void)argc; double a[VEC_MAX], b[VEC_MAX]; int n=loadPair(ctx,v,a,b); if(!n) return;
  double s=0; for(int i=0;i<n;i++) s+=a[i]*b[i];
  sqlite3_result_double(ctx, s);
}
static void fnL2(sqlite3_context *ctx, int argc, sqlite3_value **v){
  (void)argc; double a[VEC_MAX], b[VEC_MAX]; int n=loadPair(ctx,v,a,b); if(!n) return;
  double s=0; for(int i=0;i<n;i++){ double d=a[i]-b[i]; s+=d*d; }
  sqlite3_result_double(ctx, sqrt(s));
}
static void fnCosine(sqlite3_context *ctx, int argc, sqlite3_value **v){
  (void)argc; double a[VEC_MAX], b[VEC_MAX]; int n=loadPair(ctx,v,a,b); if(!n) return;
  double dot=0, na=0, nb=0;
  for(int i=0;i<n;i++){ dot+=a[i]*b[i]; na+=a[i]*a[i]; nb+=b[i]*b[i]; }
  if( na==0 || nb==0 ){ sqlite3_result_error(ctx,"zero-magnitude vector",-1); return; }
  sqlite3_result_double(ctx, 1.0 - dot/(sqrt(na)*sqrt(nb)));
}

static int registerVectorFns(sqlite3 *db){
  static const struct { const char *z; int n; void (*f)(sqlite3_context*,int,sqlite3_value**); } defs[] = {
    { "vec_dim", 1, fnDim }, { "vec_dot", 2, fnDot },
    { "vec_l2", 2, fnL2 },   { "vec_cosine", 2, fnCosine },
  };
  for(unsigned i=0;i<sizeof(defs)/sizeof(defs[0]);i++){
    int rc = sqlite3_create_function(db, defs[i].z, defs[i].n, SQLITE_UTF8|SQLITE_DETERMINISTIC, 0, defs[i].f, 0, 0);
    if( rc!=SQLITE_OK ) return rc;
  }
  return SQLITE_OK;
}

static int run(sqlite3 *db, const char *sql){
  char *e=0; int rc=sqlite3_exec(db, sql, 0,0,&e);
  if( rc!=SQLITE_OK ){ fprintf(stderr,"  SQL error: %s\n", e); sqlite3_free(e); }
  return rc;
}

int main(void){
  sqlite3 *db;
  if( sqlite3_open(":memory:", &db)!=SQLITE_OK ){ fprintf(stderr,"open failed\n"); return 1; }
  if( registerVectorFns(db)!=SQLITE_OK ){ fprintf(stderr,"function register failed\n"); return 1; }

  printf("sqlite-zturso Phase 4 — vector search over the ported engine\n");
  printf("(vec_l2 / vec_cosine / vec_dot registered via sqlite3_create_function; kNN is plain SQL)\n\n");

  run(db, "CREATE TABLE items(id INTEGER PRIMARY KEY, label TEXT, embedding TEXT);");
  run(db, "INSERT INTO items(label,embedding) VALUES"
          " ('cat',   '[0.9, 0.1, 0.0]'),"
          " ('kitten','[0.8, 0.2, 0.0]'),"
          " ('dog',   '[0.1, 0.9, 0.0]'),"
          " ('canoe', '[0.0, 0.1, 0.9]'),"
          " ('puppy', '[0.2, 0.8, 0.05]');");

  const char *probe = "[0.15, 0.85, 0.0]";   /* close to dog/puppy */
  printf("probe = %s   (semantically near 'dog'/'puppy')\n\n", probe);

  /* k-nearest by cosine distance — ordering/LIMIT handled by the ported VDBE. */
  printf("kNN by cosine distance (k=3):\n");
  sqlite3_stmt *st=0;
  sqlite3_prepare_v2(db,
     "SELECT label, round(vec_cosine(embedding, ?1),4) AS d "
     "FROM items ORDER BY d ASC LIMIT 3;", -1, &st, 0);
  sqlite3_bind_text(st, 1, probe, -1, SQLITE_STATIC);
  int rank=0; char top[32]="";
  while( sqlite3_step(st)==SQLITE_ROW ){
    if(rank==0) snprintf(top,sizeof top,"%s",(const char*)sqlite3_column_text(st,0));
    printf("  %d. %-8s  cosdist=%s\n", ++rank, sqlite3_column_text(st,0), sqlite3_column_text(st,1));
  }
  sqlite3_finalize(st);

  printf("\nL2 distance to every row:\n");
  sqlite3_prepare_v2(db,
     "SELECT label, round(vec_l2(embedding, ?1),4) AS d FROM items ORDER BY d ASC;", -1, &st, 0);
  sqlite3_bind_text(st, 1, probe, -1, SQLITE_STATIC);
  while( sqlite3_step(st)==SQLITE_ROW )
    printf("  %-8s  l2=%s\n", sqlite3_column_text(st,0), sqlite3_column_text(st,1));
  sqlite3_finalize(st);

  int ok = (strcmp(top,"dog")==0 || strcmp(top,"puppy")==0);   /* nearest must be a canine */
  printf("\nthesis check: vector search runs on the ported engine, nearest='%s' -> %s\n",
         top, ok ? "CONFIRMED" : "FAILED");
  sqlite3_close(db);
  return ok ? 0 : 2;
}
