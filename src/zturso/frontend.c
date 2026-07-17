/*
** sqlite-zturso — the fork's SQL frontend over the ported VDBE
** ============================================================
** A self-contained frontend: text -> our tokenizer/parser/AST -> VDBE bytecode
** -> run on the ported Zig interpreter. No SQLite tokenizer/parser is used; we
** drive sqlite3GetVdbe + sqlite3VdbeAddOp* + sqlite3FinishCoding ourselves. This
** is Turso's "VDBE as a pluggable IR" thesis, demonstrated in this codebase.
** See EXPERIMENT.md.
**
** Phases grown here:
**   1a  hand-emitted constant program                 (poc_frontend.c)
**   1b  integer-expression dialect (no tables)        SELECT 2+3*4;
**   1c  real table reads via cursor opcodes           SELECT c, a+1 FROM t WHERE a > 2;
**
** Grammar:
**   stmt    := "SELECT" selcols ["FROM" ident ["WHERE" cond ("AND" cond)*]] ";"?
**   selcols := "*" | expr ("," expr)*
**   cond    := expr cmp expr           cmp := "=" | "<>" | "!=" | "<" | "<=" | ">" | ">="
**   expr    := term   (("+" | "-") term)*
**   term    := factor (("*" | "/" | "%") factor)*
**   factor  := "-" factor | primary
**   primary := INTEGER | ident | "(" expr ")"      (ident = column name, or "rowid")
**
** The code generator emits exactly the opcodes SQLite would: OP_Integer,
** OP_Add/Subtract/Multiply/Divide/Remainder, OP_OpenRead, OP_Rewind, OP_Column,
** OP_Rowid, OP_Next, the OP_Eq/Ne/Lt/Le/Gt/Ge comparison-jumps, OP_ResultRow.
** INTEGER PRIMARY KEY columns correctly read via OP_Rowid, not OP_Column.
**
** Fork-only file (branch `sqlite-zturso`); reaches into sqliteInt.h on purpose —
** a frontend lives below the public sqlite3.h. Linked against our libsqlite3.a.
*/
#include "sqliteInt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Two-char comparison tokens (single-char ones are their own ASCII value). */
#define T_LE 301
#define T_GE 302
#define T_NE 303

/* ───────────────────────────── AST ───────────────────────────── */
typedef enum { N_NUM, N_BIN, N_NEG, N_COL } NodeKind;
typedef struct Node Node;
struct Node {
  NodeKind kind;
  long long ival;       /* N_NUM */
  int op;               /* N_BIN: '+','-','*','/','%' */
  const char *name;     /* N_COL: column name (points into input) */
  int namelen;
  Node *l, *r;
};

typedef struct { Node *l; int cmp; Node *r; } Cond;   /* one WHERE conjunct */

/* ─────────────────────── parser + arena state ─────────────────── */
typedef struct {
  const char *p;
  int tok;              /* ASCII char, 'N' num, 'I' ident, 'S/F/W/A' keywords, cmp tokens, 0 EOF, -1 err */
  long long num;
  const char *idz; int idn;   /* identifier text when tok=='I' */
  const char *err;
  Node arena[512]; int nNode;
} P;

static Node *node(P *s){
  if( s->nNode >= (int)(sizeof(s->arena)/sizeof(s->arena[0])) ){ s->err="expression too large"; return 0; }
  Node *n=&s->arena[s->nNode++]; memset(n,0,sizeof(*n)); return n;
}

static int kw(const char *z, int n){
  if( n==6 && sqlite3StrNICmp(z,"SELECT",6)==0 ) return 'S';
  if( n==4 && sqlite3StrNICmp(z,"FROM",4)==0 )   return 'F';
  if( n==5 && sqlite3StrNICmp(z,"WHERE",5)==0 )  return 'W';
  if( n==3 && sqlite3StrNICmp(z,"AND",3)==0 )    return 'A';
  return 'I';
}

static void next(P *s){
  const char *p=s->p;
  while( *p==' '||*p=='\t'||*p=='\n'||*p=='\r' ) p++;
  if( *p==0 ){ s->tok=0; s->p=p; return; }
  if( sqlite3Isdigit((unsigned char)*p) ){
    long long v=0; while( sqlite3Isdigit((unsigned char)*p) ){ v=v*10+(*p-'0'); p++; }
    s->num=v; s->tok='N'; s->p=p; return;
  }
  if( sqlite3Isalpha((unsigned char)*p) || *p=='_' ){
    const char *b=p; while( sqlite3Isalnum((unsigned char)*p) || *p=='_' ) p++;
    s->idz=b; s->idn=(int)(p-b); s->tok=kw(b,s->idn); s->p=p; return;
  }
  switch( *p ){
    case '<': if(p[1]=='='){s->tok=T_LE;s->p=p+2;} else if(p[1]=='>'){s->tok=T_NE;s->p=p+2;} else {s->tok='<';s->p=p+1;} return;
    case '>': if(p[1]=='='){s->tok=T_GE;s->p=p+2;} else {s->tok='>';s->p=p+1;} return;
    case '!': if(p[1]=='='){s->tok=T_NE;s->p=p+2;} else {s->tok=-1;s->err="expected '=' after '!'";s->p=p+1;} return;
    case '=': case '+': case '-': case '*': case '/': case '%':
    case '(': case ')': case ',': case ';':
      s->tok=*p; s->p=p+1; return;
    default: s->tok=-1; s->err="unexpected character"; s->p=p; return;
  }
}

static Node *parseExpr(P *s);

static Node *parsePrimary(P *s){
  if( s->tok=='N' ){ Node *n=node(s); if(!n)return 0; n->kind=N_NUM; n->ival=s->num; next(s); return n; }
  if( s->tok=='I' ){ Node *n=node(s); if(!n)return 0; n->kind=N_COL; n->name=s->idz; n->namelen=s->idn; next(s); return n; }
  if( s->tok=='(' ){ next(s); Node *n=parseExpr(s); if(!n)return 0; if(s->tok!=')'){s->err="expected ')'";return 0;} next(s); return n; }
  s->err = s->err ? s->err : "expected a number, column, or '('";
  return 0;
}
static Node *parseFactor(P *s){
  if( s->tok=='-' ){ next(s); Node *c=parseFactor(s); if(!c)return 0; Node *n=node(s); if(!n)return 0; n->kind=N_NEG; n->l=c; return n; }
  return parsePrimary(s);
}
static Node *parseTerm(P *s){
  Node *l=parseFactor(s); if(!l)return 0;
  while( s->tok=='*'||s->tok=='/'||s->tok=='%' ){ int op=s->tok; next(s); Node *r=parseFactor(s); if(!r)return 0; Node *n=node(s); if(!n)return 0; n->kind=N_BIN; n->op=op; n->l=l; n->r=r; l=n; }
  return l;
}
static Node *parseExpr(P *s){
  Node *l=parseTerm(s); if(!l)return 0;
  while( s->tok=='+'||s->tok=='-' ){ int op=s->tok; next(s); Node *r=parseTerm(s); if(!r)return 0; Node *n=node(s); if(!n)return 0; n->kind=N_BIN; n->op=op; n->l=l; n->r=r; l=n; }
  return l;
}

/* ─────────────────────────── code generator ─────────────────────────── */
typedef struct { Vdbe *v; Table *pTab; int cursor; int next; } Ctx;

/* Resolve a column name to its index; -1 for the rowid (incl. the IPK column). */
static int resolveCol(Table *pTab, const char *z, int n, const char **pzErr){
  if( (n==5 && sqlite3StrNICmp(z,"rowid",5)==0)
   || (n==4 && sqlite3StrNICmp(z,"_oid",4)==0)
   || (n==7 && sqlite3StrNICmp(z,"_rowid_",7)==0) ) return -1;
  for(int i=0;i<pTab->nCol;i++){
    const char *cn = pTab->aCol[i].zCnName;
    /* n->name points mid-input and is NOT null-terminated: match on length. */
    if( (int)strlen(cn)==n && sqlite3StrNICmp(cn, z, n)==0 ){
      /* INTEGER PRIMARY KEY: the value IS the rowid, not stored in the record. */
      return (i==pTab->iPKey) ? -1 : i;
    }
  }
  *pzErr = "no such column";
  return -2;
}

/* Emit code leaving the value of `n` in register `target`. Returns 0, or an
** error string via *pzErr. */
static const char *codegen(Ctx *c, Node *n, int target){
  const char *err=0;
  switch( n->kind ){
    case N_NUM:
      sqlite3VdbeAddOp2(c->v, OP_Integer, (int)n->ival, target);
      break;
    case N_COL: {
      if( c->pTab==0 ){ return "column reference requires a FROM clause"; }
      int ci = resolveCol(c->pTab, n->name, n->namelen, &err);
      if( ci==-2 ) return err;
      if( ci<0 ) sqlite3VdbeAddOp2(c->v, OP_Rowid, c->cursor, target);
      else       sqlite3VdbeAddOp3(c->v, OP_Column, c->cursor, ci, target);
      break;
    }
    case N_NEG: {
      int rt=++c->next, r0=++c->next;
      if( (err=codegen(c, n->l, rt)) ) return err;
      sqlite3VdbeAddOp2(c->v, OP_Integer, 0, r0);
      sqlite3VdbeAddOp3(c->v, OP_Subtract, rt, r0, target);   /* r[target]=r[r0]-r[rt]=0-x */
      break;
    }
    case N_BIN: {
      int rL=++c->next, rR=++c->next;
      if( (err=codegen(c, n->l, rL)) ) return err;
      if( (err=codegen(c, n->r, rR)) ) return err;
      int opc;
      switch( n->op ){
        case '+': opc=OP_Add; break; case '-': opc=OP_Subtract; break;
        case '*': opc=OP_Multiply; break; case '/': opc=OP_Divide; break;
        default:  opc=OP_Remainder; break;
      }
      if( opc==OP_Add || opc==OP_Multiply ) sqlite3VdbeAddOp3(c->v, opc, rL, rR, target);
      else                                  sqlite3VdbeAddOp3(c->v, opc, rR, rL, target);  /* left OP right */
      break;
    }
  }
  return 0;
}

/* Emit a comparison that jumps to `addrFalse` when (L cmp R) is FALSE. */
static const char *codegenCondFalseJump(Ctx *c, Cond *w, int addrFalse){
  int rL=++c->next, rR=++c->next;
  const char *err;
  if( (err=codegen(c, w->l, rL)) ) return err;
  if( (err=codegen(c, w->r, rR)) ) return err;
  int inv;   /* opcode that jumps when the condition is FALSE */
  switch( w->cmp ){
    case '=':  inv=OP_Ne; break;
    case T_NE: inv=OP_Eq; break;
    case '<':  inv=OP_Ge; break;
    case T_LE: inv=OP_Gt; break;
    case '>':  inv=OP_Le; break;
    default:   inv=OP_Lt; break;   /* T_GE */
  }
  /* OP_xx jumps to P2 when reg[P3] xx reg[P1]; with P1=rR,P3=rL that is L xx R. */
  sqlite3VdbeAddOp3(c->v, inv, rR, addrFalse, rL);
  return 0;
}

/* ───────────────────────── compile a full SELECT ───────────────────────── */
static int compileSelect(sqlite3 *db, const char *sql,
                         sqlite3_stmt **ppStmt, int *pnCol, const char **pzErr){
  P s; memset(&s,0,sizeof(s)); s.p=sql; next(&s);
  if( s.tok!='S' ){ *pzErr="expected SELECT"; return SQLITE_ERROR; }
  next(&s);

  /* select list: '*' or a comma-list of expressions */
  Node *cols[64]; int nSel=0, star=0;
  if( s.tok=='*' ){ star=1; next(&s); }
  else {
    for(;;){
      if( nSel>=64 ){ *pzErr="too many columns"; return SQLITE_ERROR; }
      Node *e=parseExpr(&s); if(!e){ *pzErr=s.err?s.err:"parse error"; return SQLITE_ERROR; }
      cols[nSel++]=e;
      if( s.tok==',' ){ next(&s); continue; }
      break;
    }
  }

  /* optional FROM <table> */
  const char *tabName=0; int tabLen=0;
  if( s.tok=='F' ){
    next(&s);
    if( s.tok!='I' ){ *pzErr="expected a table name after FROM"; return SQLITE_ERROR; }
    tabName=s.idz; tabLen=s.idn; next(&s);
  }
  if( star && tabName==0 ){ *pzErr="'*' requires a FROM clause"; return SQLITE_ERROR; }

  /* optional WHERE cond (AND cond)* */
  Cond wh[32]; int nWh=0;
  if( s.tok=='W' ){
    if( tabName==0 ){ *pzErr="WHERE requires a FROM clause"; return SQLITE_ERROR; }
    next(&s);
    for(;;){
      if( nWh>=32 ){ *pzErr="too many WHERE terms"; return SQLITE_ERROR; }
      Node *l=parseExpr(&s); if(!l){ *pzErr=s.err?s.err:"parse error"; return SQLITE_ERROR; }
      int cmp=s.tok;
      if( cmp!='='&&cmp!='<'&&cmp!='>'&&cmp!=T_LE&&cmp!=T_GE&&cmp!=T_NE ){ *pzErr="expected a comparison operator"; return SQLITE_ERROR; }
      next(&s);
      Node *r=parseExpr(&s); if(!r){ *pzErr=s.err?s.err:"parse error"; return SQLITE_ERROR; }
      wh[nWh].l=l; wh[nWh].cmp=cmp; wh[nWh].r=r; nWh++;
      if( s.tok=='A' ){ next(&s); continue; }
      break;
    }
  }
  if( s.tok==';' ) next(&s);
  if( s.tok!=0 ){ *pzErr=s.err?s.err:"trailing input after statement"; return SQLITE_ERROR; }

  /* ---- codegen ---- */
  Parse sParse; memset(&sParse,0,sizeof(sParse)); sParse.db=db;
  Table *pTab=0; int iDb=0;
  if( tabName ){
    char *z=sqlite3_mprintf("%.*s", tabLen, tabName);
    pTab = sqlite3FindTable(db, z, "main");
    sqlite3_free(z);
    if( pTab==0 ){ *pzErr="no such table"; return SQLITE_ERROR; }
    iDb = sqlite3SchemaToIndex(db, ((Table*)pTab)->pSchema);
  }
  int nRes = star ? pTab->nCol : nSel;

  sqlite3_mutex_enter(sqlite3_db_mutex(db));
  Vdbe *v = sqlite3GetVdbe(&sParse);
  if( v==0 ){ sqlite3_mutex_leave(sqlite3_db_mutex(db)); *pzErr="out of memory"; return SQLITE_NOMEM; }
  sqlite3VdbeSetNumCols(v, nRes);

  Ctx c = { v, pTab, 0, nRes };   /* cursor 0; temporaries start above result regs */
  const char *cgErr=0;

  if( tabName==0 ){
    /* constant SELECT (Phase 1b path): emit each expr, one ResultRow. */
    for(int i=0;i<nSel && !cgErr;i++) cgErr=codegen(&c, cols[i], i+1);
    if( !cgErr ) sqlite3VdbeAddOp2(v, OP_ResultRow, 1, nRes);
  }else{
    /* table scan: OpenRead; Rewind; [WHERE]; columns; ResultRow; Next. */
    sqlite3CodeVerifySchema(&sParse, iDb);          /* -> OP_Transaction in prologue */
    sqlite3VdbeAddOp4Int(v, OP_OpenRead, c.cursor, (int)pTab->tnum, iDb, pTab->nCol);
    sParse.nTab = 1;
    int addrRewind = sqlite3VdbeAddOp1(v, OP_Rewind, c.cursor);   /* p2 patched below */
    int addrTop = sqlite3VdbeCurrentAddr(v);
    int lblNext = sqlite3VdbeMakeLabel(&sParse);
    for(int i=0;i<nWh && !cgErr;i++) cgErr=codegenCondFalseJump(&c, &wh[i], lblNext);
    if( !cgErr ){
      if( star ) for(int i=0;i<pTab->nCol && !cgErr;i++){
        if( i==pTab->iPKey ) sqlite3VdbeAddOp2(v, OP_Rowid, c.cursor, i+1);
        else                 sqlite3VdbeAddOp3(v, OP_Column, c.cursor, i, i+1);
      }
      else for(int i=0;i<nSel && !cgErr;i++) cgErr=codegen(&c, cols[i], i+1);
    }
    if( !cgErr ){
      sqlite3VdbeAddOp2(v, OP_ResultRow, 1, nRes);
      sqlite3VdbeResolveLabel(v, lblNext);
      sqlite3VdbeAddOp2(v, OP_Next, c.cursor, addrTop);
      sqlite3VdbeJumpHere(v, addrRewind);            /* Rewind jumps here when table empty */
    }
  }

  sParse.nMem = c.next;
  if( cgErr ){ sqlite3_mutex_leave(sqlite3_db_mutex(db)); *pzErr=cgErr; return SQLITE_ERROR; }

  sqlite3FinishCoding(&sParse);
  int rc = sParse.rc;
  sqlite3_mutex_leave(sqlite3_db_mutex(db));
  if( rc!=SQLITE_OK && rc!=SQLITE_DONE ){ *pzErr=sqlite3_errmsg(db); return rc; }

  *ppStmt=(sqlite3_stmt*)v; *pnCol=nRes;
  return SQLITE_OK;
}

/* Run a statement, print all rows as "v | v | ...", return row count or <0. */
static int runSelect(sqlite3 *db, const char *sql, int show){
  sqlite3_stmt *stmt=0; int nCol=0; const char *zErr=0;
  int rc = compileSelect(db, sql, &stmt, &nCol, &zErr);
  if( rc!=SQLITE_OK ){ if(show) printf("  %-34s -> ERROR: %s\n", sql, zErr?zErr:"?"); return -1; }
  int rows=0;
  if(show) printf("  %-34s ->", sql);
  while( sqlite3_step(stmt)==SQLITE_ROW ){
    if(show){ printf(rows?" ; ":" "); for(int i=0;i<nCol;i++) printf("%s%s", i?" | ":"", sqlite3_column_text(stmt,i)?(const char*)sqlite3_column_text(stmt,i):"NULL"); }
    rows++;
  }
  if(show) printf(rows?"\n":" (no rows)\n");
  sqlite3_finalize(stmt);
  return rows;
}

int main(int argc, char **argv){
  sqlite3 *db;
  if( sqlite3_open(":memory:", &db)!=SQLITE_OK ){ fprintf(stderr,"zturso: open failed\n"); return 1; }

  /* Seed a real table via the normal engine — our frontend only READS it. */
  char *e=0;
  const char *seed =
    "CREATE TABLE emp(id INTEGER PRIMARY KEY, name TEXT, dept TEXT, salary INTEGER);"
    "INSERT INTO emp(name,dept,salary) VALUES"
    " ('Ada','eng',120),('Linus','eng',115),('Grace','ops',130),"
    " ('Dennis','eng',110),('Margaret','ops',125);";
  if( sqlite3_exec(db, seed, 0,0,&e)!=SQLITE_OK ){ fprintf(stderr,"seed failed: %s\n", e); return 1; }

  if( argc>1 ){ int r=runSelect(db, argv[1], 1); sqlite3_close(db); return r>=0?0:1; }

  printf("sqlite-zturso frontend — text -> our parser/AST/codegen -> ported Zig VDBE\n");
  printf("(reads a real table seeded by the normal engine; no SQLite parser in the read path)\n\n");

  printf("Phase 1b — constant expressions (no table):\n");
  runSelect(db, "SELECT 2+3*4, (2+3)*4, -5+8, 17%5, 20/3", 1);

  printf("\nPhase 1c — real table reads (cursor opcodes):\n");
  runSelect(db, "SELECT * FROM emp", 1);
  runSelect(db, "SELECT name, salary FROM emp WHERE dept = 100", 1);   /* type-mismatch demo: no rows */
  runSelect(db, "SELECT id, name FROM emp WHERE salary >= 125", 1);
  runSelect(db, "SELECT name, salary+10 FROM emp WHERE dept <> 999 AND salary < 120", 1);
  runSelect(db, "SELECT rowid, name FROM emp WHERE id = 3", 1);

  /* Differential self-check: our engine vs the fidelity engine, same SQL. */
  printf("\nself-check (our frontend vs fidelity engine, same queries):\n");
  const char *checks[] = {
    "SELECT id, salary FROM emp WHERE salary >= 125",
    "SELECT id FROM emp WHERE salary < 120 AND id <> 1",
    "SELECT id, salary+1 FROM emp WHERE id > 2",
    "SELECT id FROM emp WHERE salary = 130",
  };
  int fails=0;
  for(int i=0;i<(int)(sizeof(checks)/sizeof(checks[0]));i++){
    /* Our frontend result as a string */
    sqlite3_stmt *a=0; int na=0; const char *ea=0;
    char ours[512]=""; char ref[512]="";
    if( compileSelect(db, checks[i], &a, &na, &ea)==SQLITE_OK ){
      while( sqlite3_step(a)==SQLITE_ROW ){ for(int j=0;j<na;j++){ char b[64]; snprintf(b,sizeof b,"%s%s", j?",":"", sqlite3_column_text(a,j)?(const char*)sqlite3_column_text(a,j):"NULL"); strncat(ours,b,sizeof(ours)-strlen(ours)-1);} strncat(ours,";",sizeof(ours)-strlen(ours)-1); }
    }
    if(a) sqlite3_finalize(a);
    /* Fidelity engine result via the normal prepared statement */
    sqlite3_stmt *r=0;
    if( sqlite3_prepare_v2(db, checks[i], -1, &r, 0)==SQLITE_OK ){
      int nc=sqlite3_column_count(r);
      while( sqlite3_step(r)==SQLITE_ROW ){ for(int j=0;j<nc;j++){ char b[64]; snprintf(b,sizeof b,"%s%s", j?",":"", sqlite3_column_text(r,j)?(const char*)sqlite3_column_text(r,j):"NULL"); strncat(ref,b,sizeof(ref)-strlen(ref)-1);} strncat(ref,";",sizeof(ref)-strlen(ref)-1); }
    }
    if(r) sqlite3_finalize(r);
    int ok = strcmp(ours,ref)==0;
    if(!ok) fails++;
    printf("  %-48s %s\n    ours=[%s] ref=[%s]\n", checks[i], ok?"MATCH":"DIFFER", ours, ref);
  }

  printf("\nthesis check: frontend-over-ported-VDBE reads real tables identically to SQLite -> %s\n",
         fails==0 ? "CONFIRMED" : "FAILED");
  sqlite3_close(db);
  return fails==0 ? 0 : 2;
}
