/*
** sqlite-zturso — Phase 1b: a real (tiny) SQL frontend over the ported VDBE
** ==========================================================================
** Phase 1a (poc_frontend.c) hand-emitted a fixed opcode sequence. This grows it
** into an actual *input-driven* frontend: text -> tokens -> AST -> VDBE bytecode
** -> run on the ported Zig interpreter. No SQLite tokenizer/parser is involved;
** we build our own, then drive sqlite3GetVdbe + sqlite3VdbeAddOp* +
** sqlite3FinishCoding ourselves — the exact "pluggable IR" model from Turso's
** "LLVM of databases" thesis (see EXPERIMENT.md, docs/turso-comparison.md).
**
** Grammar (a deliberately small integer-expression dialect):
**
**     stmt    := "SELECT" expr ("," expr)* ";"?
**     expr    := term   (("+" | "-") term)*
**     term    := factor (("*" | "/" | "%") factor)*
**     factor  := "-" factor | primary
**     primary := INTEGER | "(" expr ")"
**
** Each comma-separated expr becomes one result column. The code generator does
** real register allocation: result columns live in registers 1..nCol, scratch
** temporaries above them, and it emits the same arithmetic opcodes SQLite would
** (OP_Integer / OP_Add / OP_Subtract / OP_Multiply / OP_Divide / OP_Remainder).
**
** Fork-only file (branch `sqlite-zturso`); reaches into sqliteInt.h on purpose —
** a frontend lives below the public API. Linked against our libsqlite3.a.
*/
#include "sqliteInt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ───────────────────────────── AST ───────────────────────────── */
typedef enum { N_NUM, N_BIN, N_NEG } NodeKind;
typedef struct Node Node;
struct Node {
  NodeKind kind;
  long long ival;   /* N_NUM */
  int op;           /* N_BIN: one of '+','-','*','/','%'  */
  Node *l, *r;      /* children (N_NEG uses l) */
};

/* ─────────────────────── parser + arena state ─────────────────── */
typedef struct {
  const char *p;    /* cursor into the input */
  int tok;          /* current token: an ASCII punct char, 'N' num, 'S' SELECT, 0 EOF, -1 error */
  long long num;    /* value when tok=='N' */
  const char *err;  /* set on failure */
  Node arena[512];  /* bump-allocated AST nodes (no free needed) */
  int nNode;
} P;

static Node *node(P *s){
  if( s->nNode >= (int)(sizeof(s->arena)/sizeof(s->arena[0])) ){ s->err="expression too large"; return 0; }
  Node *n = &s->arena[s->nNode++];
  memset(n, 0, sizeof(*n));
  return n;
}

/* Lexer: advance s->tok to the next token. */
static void next(P *s){
  const char *p = s->p;
  while( *p==' ' || *p=='\t' || *p=='\n' || *p=='\r' ) p++;
  if( *p==0 ){ s->tok=0; s->p=p; return; }
  if( sqlite3Isdigit((unsigned char)*p) ){
    long long v=0;
    while( sqlite3Isdigit((unsigned char)*p) ){ v = v*10 + (*p - '0'); p++; }
    s->num=v; s->tok='N'; s->p=p; return;
  }
  if( sqlite3Isalpha((unsigned char)*p) ){
    const char *b=p;
    while( sqlite3Isalnum((unsigned char)*p) ) p++;
    if( (p-b)==6 && sqlite3StrNICmp(b,"SELECT",6)==0 ){ s->tok='S'; s->p=p; return; }
    s->tok=-1; s->err="only the SELECT keyword is supported"; s->p=p; return;
  }
  switch( *p ){
    case '+': case '-': case '*': case '/': case '%':
    case '(': case ')': case ',': case ';':
      s->tok=*p; s->p=p+1; return;
    default:
      s->tok=-1; s->err="unexpected character"; s->p=p; return;
  }
}

static Node *parseExpr(P *s);

static Node *parsePrimary(P *s){
  if( s->tok=='N' ){
    Node *n=node(s); if(!n) return 0;
    n->kind=N_NUM; n->ival=s->num; next(s); return n;
  }
  if( s->tok=='(' ){
    next(s);
    Node *n=parseExpr(s); if(!n) return 0;
    if( s->tok!=')' ){ s->err="expected ')'"; return 0; }
    next(s); return n;
  }
  s->err = s->err ? s->err : "expected a number or '('";
  return 0;
}

static Node *parseFactor(P *s){
  if( s->tok=='-' ){
    next(s);
    Node *c=parseFactor(s); if(!c) return 0;
    Node *n=node(s); if(!n) return 0;
    n->kind=N_NEG; n->l=c; return n;
  }
  return parsePrimary(s);
}

static Node *parseTerm(P *s){
  Node *l=parseFactor(s); if(!l) return 0;
  while( s->tok=='*' || s->tok=='/' || s->tok=='%' ){
    int op=s->tok; next(s);
    Node *r=parseFactor(s); if(!r) return 0;
    Node *n=node(s); if(!n) return 0;
    n->kind=N_BIN; n->op=op; n->l=l; n->r=r; l=n;
  }
  return l;
}

static Node *parseExpr(P *s){
  Node *l=parseTerm(s); if(!l) return 0;
  while( s->tok=='+' || s->tok=='-' ){
    int op=s->tok; next(s);
    Node *r=parseTerm(s); if(!r) return 0;
    Node *n=node(s); if(!n) return 0;
    n->kind=N_BIN; n->op=op; n->l=l; n->r=r; l=n;
  }
  return l;
}

/* ─────────────────────────── code generator ─────────────────────────── */
/* Emit code that leaves the value of `n` in register `target`. Scratch regs are
** bump-allocated via *pNext (which tracks the highest register used so we can
** set Parse.nMem). Uses the same arithmetic opcodes SQLite emits — note the
** operand order: for the non-commutative ops SQLite computes r[p3]=r[p2] OP r[p1]. */
static void codegen(Vdbe *v, Node *n, int target, int *pNext){
  switch( n->kind ){
    case N_NUM:
      sqlite3VdbeAddOp2(v, OP_Integer, (int)n->ival, target);
      break;
    case N_NEG: {
      int rt = ++(*pNext);
      int r0 = ++(*pNext);
      codegen(v, n->l, rt, pNext);
      sqlite3VdbeAddOp2(v, OP_Integer, 0, r0);
      /* r[target] = r[r0] - r[rt] = 0 - operand */
      sqlite3VdbeAddOp3(v, OP_Subtract, rt, r0, target);
      break;
    }
    case N_BIN: {
      int rL = ++(*pNext);
      int rR = ++(*pNext);
      codegen(v, n->l, rL, pNext);
      codegen(v, n->r, rR, pNext);
      int opc;
      switch( n->op ){
        case '+': opc=OP_Add;       break;
        case '-': opc=OP_Subtract;  break;
        case '*': opc=OP_Multiply;  break;
        case '/': opc=OP_Divide;    break;
        default:  opc=OP_Remainder; break;  /* '%' */
      }
      /* SQLite: OP_Add r[p3]=r[p1]+r[p2]; OP_Subtract r[p3]=r[p2]-r[p1] (etc.).
      ** Passing (p1=rL, p2=rR) yields left+right and right-left — so for the
      ** subtract-family we pass (p1=rR, p2=rL) to get left-right. */
      if( opc==OP_Add || opc==OP_Multiply ){
        sqlite3VdbeAddOp3(v, opc, rL, rR, target);
      }else{
        sqlite3VdbeAddOp3(v, opc, rR, rL, target);
      }
      break;
    }
  }
}

/* Compile `sql` into a runnable Vdbe. On success returns SQLITE_OK, writes the
** statement to *ppStmt and the column count to *pnCol. On parse error returns
** SQLITE_ERROR and points *pzErr at a message. */
static int compileSelect(sqlite3 *db, const char *sql,
                         sqlite3_stmt **ppStmt, int *pnCol, const char **pzErr){
  P s; memset(&s, 0, sizeof(s));
  s.p = sql;
  next(&s);
  if( s.tok!='S' ){ *pzErr="expected SELECT"; return SQLITE_ERROR; }
  next(&s);

  /* Parse the comma-separated column expressions into ASTs first. */
  Node *cols[64];
  int nCol=0;
  for(;;){
    if( nCol>=64 ){ *pzErr="too many columns"; return SQLITE_ERROR; }
    Node *e=parseExpr(&s);
    if( !e ){ *pzErr = s.err ? s.err : "parse error"; return SQLITE_ERROR; }
    cols[nCol++]=e;
    if( s.tok==',' ){ next(&s); continue; }
    break;
  }
  if( s.tok==';' ) next(&s);
  if( s.tok!=0 ){ *pzErr = s.err ? s.err : "trailing input after statement"; return SQLITE_ERROR; }

  /* Now emit VDBE. Result columns occupy registers 1..nCol. */
  Parse sParse; memset(&sParse, 0, sizeof(sParse));
  sParse.db = db;
  sqlite3_mutex_enter(sqlite3_db_mutex(db));
  Vdbe *v = sqlite3GetVdbe(&sParse);        /* auto-emits OP_Init */
  if( v==0 ){ sqlite3_mutex_leave(sqlite3_db_mutex(db)); *pzErr="out of memory"; return SQLITE_NOMEM; }
  sqlite3VdbeSetNumCols(v, nCol);

  int next_reg = nCol;                      /* temporaries start above the columns */
  for(int i=0;i<nCol;i++){
    codegen(v, cols[i], i+1, &next_reg);
  }
  sqlite3VdbeAddOp2(v, OP_ResultRow, 1, nCol);
  sParse.nMem = next_reg;                    /* highest register used */

  sqlite3FinishCoding(&sParse);              /* OP_Halt + MakeReady */
  int rc = sParse.rc;
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  if( rc!=SQLITE_OK && rc!=SQLITE_DONE ){ *pzErr=sqlite3_errmsg(db); return rc; }

  *ppStmt = (sqlite3_stmt*)v;
  *pnCol = nCol;
  return SQLITE_OK;
}

/* Compile, run one row, print "col0 | col1 | ..." and return column values. */
static int runSelect(sqlite3 *db, const char *sql){
  sqlite3_stmt *stmt=0; int nCol=0; const char *zErr=0;
  int rc = compileSelect(db, sql, &stmt, &nCol, &zErr);
  if( rc!=SQLITE_OK ){
    printf("  %-28s -> ERROR: %s\n", sql, zErr?zErr:"?");
    return rc;
  }
  rc = sqlite3_step(stmt);
  printf("  %-28s -> ", sql);
  if( rc==SQLITE_ROW ){
    for(int i=0;i<nCol;i++){
      printf("%s%lld", i?" | ":"", sqlite3_column_int64(stmt, i));
    }
    printf("\n");
    rc=SQLITE_OK;
  }else{
    printf("(no row, rc=%d)\n", rc);
  }
  sqlite3_finalize(stmt);
  return rc;
}

/* A self-check: expected single-column values for a few inputs. */
struct Case { const char *sql; long long want; };

int main(int argc, char **argv){
  sqlite3 *db;
  if( sqlite3_open(":memory:", &db)!=SQLITE_OK ){
    fprintf(stderr, "zturso: open failed\n"); return 1;
  }

  if( argc>1 ){
    /* Ad-hoc: `zig build zturso -- "SELECT 2+3*4;"` (or run the binary directly). */
    int rc = runSelect(db, argv[1]);
    sqlite3_close(db);
    return rc==SQLITE_OK ? 0 : 1;
  }

  printf("sqlite-zturso Phase 1b — an input-driven frontend over the ported VDBE\n");
  printf("(text -> our tokenizer/parser/AST -> VDBE bytecode -> ported Zig interpreter)\n\n");

  struct Case cases[] = {
    { "SELECT 42;",              42 },
    { "SELECT 2+3*4;",           14 },   /* precedence */
    { "SELECT (2+3)*4;",         20 },   /* parentheses */
    { "SELECT 100-10-10;",       80 },   /* left-assoc subtract */
    { "SELECT -5 + 8;",           3 },   /* unary minus */
    { "SELECT 17 % 5;",           2 },   /* remainder */
    { "SELECT 20 / 3;",           6 },   /* integer divide */
    { "SELECT ((1+2)*(3+4))%5;",  1 },   /* nested */
  };
  int nCase = (int)(sizeof(cases)/sizeof(cases[0]));

  /* First show a multi-column result to prove register layout. */
  printf("multi-column: ");
  runSelect(db, "SELECT 1, 2+2, 3*3, 100/4");

  printf("\nsingle-column self-check:\n");
  int fails=0;
  for(int i=0;i<nCase;i++){
    sqlite3_stmt *stmt=0; int nCol=0; const char *zErr=0;
    int rc = compileSelect(db, cases[i].sql, &stmt, &nCol, &zErr);
    long long got = -999999;
    if( rc==SQLITE_OK && sqlite3_step(stmt)==SQLITE_ROW ) got = sqlite3_column_int64(stmt, 0);
    if( stmt ) sqlite3_finalize(stmt);
    int ok = (rc==SQLITE_OK && got==cases[i].want);
    if( !ok ) fails++;
    printf("  %-28s => %-8lld (want %lld) %s\n",
           cases[i].sql, got, cases[i].want, ok?"ok":"FAIL");
  }

  printf("\nthesis check: input-driven frontend on ported Zig VDBE -> %s\n",
         fails==0 ? "CONFIRMED" : "FAILED");
  sqlite3_close(db);
  return fails==0 ? 0 : 2;
}
