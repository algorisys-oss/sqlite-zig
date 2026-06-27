//! Zig port of SQLite's src/alter.c — the ALTER TABLE command.
//!
//! Covers RENAME TABLE, ADD COLUMN, DROP COLUMN, RENAME COLUMN, DROP/ADD
//! CONSTRAINT, SET/DROP NOT NULL, plus the rename-resolution AST walkers and
//! the internal SQL functions (sqlite_rename_column/table/test, etc.) used by
//! the nested-parse machinery these commands emit.
//!
//! CODEGEN + AST-walker module. The ALTER commands emit VDBE bytecode by
//! issuing nested SQL (sqlite3NestedParse) and a handful of OP_* ops; the
//! internal SQL functions re-parse schema rows and rewrite token spans.
//!
//! Exported (non-static) symbols — the complete external set of alter.c with
//! SQLITE_OMIT_ALTERTABLE OFF (and all other OMITs OFF):
//!   - sqlite3AlterRenameTable
//!   - sqlite3AlterRenameColumn
//!   - sqlite3AlterDropConstraint
//!   - sqlite3AlterAddConstraint
//!   - sqlite3AlterSetNotNull
//!   - sqlite3AlterFinishAddColumn
//!   - sqlite3AlterBeginAddColumn
//!   - sqlite3AlterDropColumn
//!   - sqlite3RenameTokenMap
//!   - sqlite3RenameTokenRemap
//!   - sqlite3RenameExprUnmap
//!   - sqlite3RenameExprlistUnmap
//!   - sqlite3AlterFunctions
//! Everything else (the static helpers and SQL-function implementations) is a
//! private Zig fn.
//!
//! ─── Config assumptions (true in both build configs) ───────────────────────
//!   * SQLITE_OMIT_ALTERTABLE / OMIT_VIEW / OMIT_VIRTUALTABLE / OMIT_TRIGGER /
//!     OMIT_AUTHORIZATION / OMIT_AUTOINCREMENT / OMIT_FOREIGN_KEY /
//!     OMIT_GENERATED_COLUMNS all OFF.
//!   * SQLITE_DEBUG only in the testfixture config — renameTokenCheckAll and the
//!     post-parse mapping assert are gated on config.sqlite_debug.
//!   * Little-endian x86-64.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers ──────────────────────────────────────────────────────
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rd(comptime T: type, p: ?*anyopaque, offs: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + offs);
    return q.*;
}
inline fn wr(comptime T: type, p: ?*anyopaque, offs: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + offs);
    q.* = v;
}
fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}
inline fn fieldPtr(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return @ptrCast(base(p) + offs);
}

// ─── ground-truth offsets ─────────────────────────────────────────────────────
// Parse
const Parse_db_off = off("Parse_db", 0);
const Parse_rc_off = off("Parse_rc", 24);
const Parse_nErr_off = off("Parse_nErr", 52);
const Parse_nTab_off = off("Parse_nTab", 56);
const Parse_nMem_off = off("Parse_nMem", 60);
const Parse_pVdbe_off = off("Parse_pVdbe", 16);
const Parse_zErrMsg_off = off("Parse_zErrMsg", 8);
const Parse_eParseMode_off = off("Parse_eParseMode", 300);
const Parse_eTriggerOp_off = off("Parse_eTriggerOp", 37);
const Parse_pTriggerTab_off = off("Parse_pTriggerTab", 144);
const Parse_pNewTable_off = off("Parse_pNewTable", 344);
const Parse_pNewIndex_off = off("Parse_pNewIndex", 352);
const Parse_pNewTrigger_off = off("Parse_pNewTrigger", 360);
const Parse_pRename_off = off("Parse_pRename", 408);
const Parse_nQueryLoop_off = off("Parse_nQueryLoop", 28);
const Parse_sLastToken_off = off("Parse_sLastToken", 280);
const sizeof_Parse = off("sizeof_Parse", 416);
// Parse.colNamesSet :1 (mask 0x20) lives in the divergent bft1 byte (39 prod / 42 tf).
const Parse_bft1_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_colNamesSet: u8 = 0x20;

// sqlite3
const sqlite3_flags_off = off("sqlite3_flags", 48);
const sqlite3_mallocFailed_off = off("sqlite3_mallocFailed", 103);
const sqlite3_aDb_off = off("sqlite3_aDb", 32);
const sqlite3_xAuth_off = off("sqlite3_xAuth", 528);
const sqlite3_init_iDb_off = off("sqlite3_init_iDb", 196);

// Db
const sizeof_Db = off("sizeof_Db", 32);
const Db_zDbSName_off = off("Db_zDbSName", 0);
const Db_pSchema_off = off("Db_pSchema", 24);

// Table
const Table_zName_off = off("Table_zName", 0);
const Table_aCol_off = off("Table_aCol", 8);
const Table_pIndex_off = off("Table_pIndex", 16);
const Table_pCheck_off = off("Table_pCheck", 32);
const Table_tabFlags_off = off("Table_tabFlags", 48);
const Table_iPKey_off = off("Table_iPKey", 52);
const Table_nCol_off = off("Table_nCol", 54);
const Table_nTabRef_off = off("Table_nTabRef", 44);
const Table_eTabType_off = off("Table_eTabType", 63);
const Table_u_off = off("Table_u", 64);
const Table_pSchema_off = off("Table_pSchema", 96);
const Table_u_tab_addColOffset_off = off("Table_u_tab_addColOffset", 64);
const Table_u_view_pSelect_off = off("Table_u_view_pSelect", 64);
const Table_u_tab_pFKey_off = off("Table_u_tab_pFKey", 72);
const Table_u_tab_pDfltList_off = off("Table_u_tab_pDfltList", 80);
const sizeof_Table = off("sizeof_Table", 120);

// Column
const Column_zCnName_off = off("Column_zCnName", 0);
const Column_affinity_off = off("Column_affinity", 9);
const Column_hName_off = off("Column_hName", 11);
const Column_colFlags_off = off("Column_colFlags", 14);
const sizeof_Column = off("sizeof_Column", 16);
// Column.notNull :4 lives in byte 8 (low nibble).
const Column_notNull_byte: usize = 8;

// Index
const Index_zName_off = off("Index_zName", 0);
const Index_aColExpr_off = off("Index_aColExpr", 80);
const Index_pPartIdxWhere_off = off("Index_pPartIdxWhere", 72);
const Index_pNext_off = off("Index_pNext", 40);
const Index_nKeyCol_off = off("Index_nKeyCol", 94);

// FKey / FKeyCol(sColMap)
const FKey_pNextFrom_off = off("FKey_pNextFrom", 8);
const FKey_zTo_off = off("FKey_zTo", 16);
const FKey_nCol_off = off("FKey_nCol", 40);
const FKey_aCol_off = off("FKey_aCol", 64);
const sColMap_iFrom_off = off("sColMap_iFrom", 0);
const sColMap_zCol_off = off("sColMap_zCol", 8);
const sizeof_FKeyCol = off("sizeof_FKeyCol", 16);

// Expr
const Expr_op_off = off("Expr_op", 0);
const Expr_flags_off = off("Expr_flags", 4);
const Expr_iColumn_off = off("Expr_iColumn", 48);
const Expr_pLeft_off = off("Expr_pLeft", 16);
const Expr_y_pTab_off = off("Expr_y", 64); // y.pTab is the first member of union y

// ExprList
const ExprList_nExpr_off = off("ExprList_nExpr", 0);
const ExprList_a_off = off("ExprList_a", 8);
const ExprList_item_pExpr_off = off("ExprList_item_pExpr", 0);
const ExprList_item_zEName_off = off("ExprList_item_zEName", 8);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);
// ExprList item fg.eEName :2 (mask 0x03) is in byte 16; we read byte 17 per probe.
const ExprList_item_fg_byte: usize = 16;
const ExprList_item_eEName_byte: usize = 17;
const ENAME_mask: u8 = 0x03;

// IdList
const IdList_nId_off = off("IdList_nId", 0);
const IdList_a_off = off("IdList_a", 8);
// IdList.a[].zName is the first member of the entry struct.
const IdList_item_zName_off: usize = 0;
const sizeof_IdList_item: usize = 8; // struct { char *zName; } — single pointer (probed)

// Select
const Select_selFlags_off = off("Select_selFlags", 4);
const Select_pEList_off = off("Select_pEList", 24);
const Select_pSrc_off = off("Select_pSrc", 32);
const Select_pWith_off = off("Select_pWith", 96);

// SrcList / SrcItem
const SrcList_nSrc_off = off("SrcList_nSrc", 0);
const SrcList_a_off = off("SrcList_a", 8);
const SrcItem_zName_off = off("SrcItem_zName", 0);
const SrcItem_pSTab_off = off("SrcItem_pSTab", 16);
const SrcItem_fg_off = off("SrcItem_fg", 24);
const SrcItem_u3_off = off("SrcItem_u3", 56);
const SrcItem_u4_pSubq_off = off("SrcItem_u4_pSubq", 64);
const sizeof_SrcItem = off("sizeof_SrcItem", 72);
// SrcItem.fg.isSubquery (byte 25, mask 0x04) / isUsing (byte 26, mask 0x08).
const SrcItem_isSubquery_byte: usize = 25;
const SrcItem_isSubquery_mask: u8 = 0x04;
const SrcItem_isUsing_byte: usize = 26;
const SrcItem_isUsing_mask: u8 = 0x08;
const Subquery_pSelect_off = off("Subquery_pSelect", 0);

// With
const With_nCte_off = off("With_nCte", 0);
const With_a_off = off("With_a", 16);
const sizeof_Cte = off("sizeof_Cte", 48);
const Cte_pSelect_off = off("Cte_pSelect", 16);
const Cte_pCols_off = off("Cte_pCols", 8);
// With.pOuter is at offset 8 (after nCte:int + pad? Actually With{ int nCte; With*pOuter; ...}).
const With_pOuter_off: usize = 8;

// Trigger
const Trigger_table_off = off("Trigger_table", 8);
const Trigger_op_off = off("Trigger_op", 16);
const Trigger_pWhen_off = off("Trigger_pWhen", 24);
const Trigger_pColumns_off = off("Trigger_pColumns", 32);
const Trigger_pTabSchema_off = off("Trigger_pTabSchema", 48);
const Trigger_step_list_off = off("Trigger_step_list", 56);

// TriggerStep
const TriggerStep_pSelect_off = off("TriggerStep_pSelect", 16);
const TriggerStep_pSrc_off = off("TriggerStep_pSrc", 24);
const TriggerStep_pWhere_off = off("TriggerStep_pWhere", 32);
const TriggerStep_pExprList_off = off("TriggerStep_pExprList", 40);
const TriggerStep_pIdList_off = off("TriggerStep_pIdList", 48);
const TriggerStep_pUpsert_off = off("TriggerStep_pUpsert", 56);
const TriggerStep_pNext_off = off("TriggerStep_pNext", 72);

// Upsert
const Upsert_pUpsertTarget_off = off("Upsert_pUpsertTarget", 0);
const Upsert_pUpsertTargetWhere_off = off("Upsert_pUpsertTargetWhere", 8);
const Upsert_pUpsertSet_off = off("Upsert_pUpsertSet", 16);
const Upsert_pUpsertWhere_off = off("Upsert_pUpsertWhere", 24);
const Upsert_pUpsertSrc_off = off("Upsert_pUpsertSrc", 64);

// NameContext
const NameContext_pParse_off = off("NameContext_pParse", 0);
const NameContext_pSrcList_off = off("NameContext_pSrcList", 8);
const NameContext_uNC_off = off("NameContext_uNC", 16);
const NameContext_ncFlags_off = off("NameContext_ncFlags", 40);
const sizeof_NameContext = off("sizeof_NameContext", 56);

// Walker
const Walker_pParse_off = off("Walker_pParse", 0);
const Walker_xExprCallback_off = off("Walker_xExprCallback", 8);
const Walker_xSelectCallback_off = off("Walker_xSelectCallback", 16);
const Walker_u_off = off("Walker_u", 40);
const sizeof_Walker = off("sizeof_Walker", 48);

// Token
const Token_z_off = off("Token_z", 0);
const Token_n_off = off("Token_n", 8);
const sizeof_Token = off("sizeof_Token", 16);

// ─── constants (probed ground truth, config-invariant) ───────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_CONSTRAINT: c_int = 19;

const SQLITE_ALTER_TABLE: c_int = 26;
const SQLITE_UTF8: c_int = 1;
const SQLITE_AFF_BLOB: c_int = 65;
const SQLITE_AFF_REAL: u8 = 69;
const SQLITE_AFF_NUMERIC: u8 = 67;

const SQLITE_TRANSIENT: ?*const fn (?*anyopaque) callconv(.c) void = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const SQLITE_DYNAMIC: ?*const fn (?*anyopaque) callconv(.c) void = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const SQLITE_FINISH: c_int = 2;

const TABTYP_NORM: u8 = 0;
const TABTYP_VTAB: u8 = 1;
const TABTYP_VIEW: u8 = 2;

const TF_WithoutRowid: u32 = 0x80;
const TF_Eponymous: u32 = 0x8000;
const TF_Shadow: u32 = 0x1000;
const TF_Strict: u32 = 0x10000;

const COLFLAG_PRIMKEY: u16 = 0x1;
const COLFLAG_UNIQUE: u16 = 0x8;
const COLFLAG_VIRTUAL: u16 = 0x20;
const COLFLAG_STORED: u16 = 0x40;
const COLFLAG_GENERATED: u16 = 0x60;

const EP_WinFunc: u32 = 0x1000000;
const EP_Subrtn: u32 = 0x2000000;
const EP_DblQuoted: u32 = 0x80;

const SF_View: u32 = 0x200000;
const SF_CopyCte: u32 = 0x4000000;
const SF_Expanded: u32 = 0x40;
const SF_Resolved: u32 = 0x10; // not directly used but kept for clarity

const NC_UUpsert: c_int = 0x200;
const NC_IsCheck: c_int = 0x4;

const WRC_Continue: c_int = 0;
const WRC_Prune: c_int = 1;
const WRC_Abort: c_int = 2;

const PARSE_MODE_RENAME: u8 = 2;
const PARSE_MODE_UNMAP: u8 = 3;

const ENAME_NAME: c_int = 0;
const ENAME_SPAN: c_int = 1;
const ENAME_TAB: c_int = 2;

const INITFLAG_AlterRename: u16 = 1;
const INITFLAG_AlterDrop: u16 = 2;
const INITFLAG_AlterAdd: u16 = 3;
const INITFLAG_AlterDropCons: u16 = 4;

const SQLITE_ForeignKeys: u64 = 0x4000;
const SQLITE_LegacyAlter: u64 = 0x4000000;
const SQLITE_Comments: u64 = 0x4000000000;
const SQLITE_DqsDML: u64 = 0x40000000;
const SQLITE_DqsDDL: u64 = 0x20000000;

// opcodes
const OP_VRename: c_int = 179;
const OP_ReadCookie: c_int = 101;
const OP_AddImm: c_int = 88;
const OP_IfPos: c_int = 61;
const OP_SetCookie: c_int = 102;
const OP_Rewind: c_int = 36;
const OP_Rowid: c_int = 137;
const OP_Column: c_int = 96;
const OP_Null: c_int = 77;
const OP_MakeRecord: c_int = 99;
const OP_IdxInsert: c_int = 140;
const OP_Insert: c_int = 130;
const OP_Next: c_int = 40;
const OP_OpenWrite: c_int = 116;

const P4_VTAB: c_int = -12;
const BTREE_FILE_FORMAT: c_int = 2;
const OPFLAG_SAVEPOSITION: c_int = 0x2;

// token types
const TK_SPACE: c_int = 184;
const TK_COMMENT: c_int = 185;
const TK_LP: c_int = 22;
const TK_RP: c_int = 23;
const TK_ILLEGAL: c_int = 186;
const TK_COMMA: c_int = 25;
const TK_CONSTRAINT: c_int = 120;
const TK_PRIMARY: c_int = 123;
const TK_NOT: c_int = 19;
const TK_UNIQUE: c_int = 124;
const TK_CHECK: c_int = 125;
const TK_DEFAULT: c_int = 121;
const TK_COLLATE: c_int = 114;
const TK_REFERENCES: c_int = 126;
const TK_FOREIGN: c_int = 133;
const TK_AS: c_int = 24;
const TK_GENERATED: c_int = 96;
const TK_STRING: c_int = 118;
const TK_COLUMN: c_int = 168;
const TK_TRIGGER: c_int = 78;
const TK_NULL: c_int = 122;
const TK_SPAN: c_int = 181;

// FuncDef flags for INTERNAL_FUNCTION: BUILTIN|INTERNAL|UTF8|CONSTANT
const FUNCFLAG_INTERNAL: u32 = 0x840801;

const LEGACY_SCHEMA_TABLE = "sqlite_master";

// ─── opaque pointer aliases ──────────────────────────────────────────────────
const Ptr = ?*anyopaque;

// ─── extern C declarations ───────────────────────────────────────────────────
extern fn sqlite3_strnicmp(zLeft: [*c]const u8, zRight: [*c]const u8, N: c_int) c_int;
extern fn sqlite3_stricmp(zLeft: [*c]const u8, zRight: [*c]const u8) c_int;
extern fn sqlite3ErrorMsg(pParse: Ptr, zFormat: [*c]const u8, ...) void;
extern fn sqlite3NestedParse(pParse: Ptr, zFormat: [*c]const u8, ...) void;
extern fn sqlite3LocateTableItem(pParse: Ptr, flags: c_uint, p: Ptr) Ptr;
extern fn sqlite3SchemaToIndex(db: Ptr, pSchema: Ptr) c_int;
extern fn sqlite3NameFromToken(db: Ptr, pToken: Ptr) [*c]u8;
extern fn sqlite3FindTable(db: Ptr, zName: [*c]const u8, zDb: [*c]const u8) Ptr;
extern fn sqlite3FindIndex(db: Ptr, zName: [*c]const u8, zDb: [*c]const u8) Ptr;
extern fn sqlite3IsShadowTableOf(db: Ptr, pTab: Ptr, zName: [*c]const u8) c_int;
extern fn sqlite3ReadOnlyShadowTables(db: Ptr) c_int;
extern fn sqlite3CheckObjectName(pParse: Ptr, a: [*c]const u8, b: [*c]const u8, c: [*c]const u8) c_int;
extern fn sqlite3AuthCheck(pParse: Ptr, a: c_int, b: [*c]const u8, c: [*c]const u8, d: [*c]const u8) c_int;
extern fn sqlite3ViewGetColumnNames(pParse: Ptr, pTab: Ptr) c_int;
extern fn sqlite3GetVTable(db: Ptr, pTab: Ptr) Ptr;
extern fn sqlite3MayAbort(pParse: Ptr) void;
extern fn sqlite3GetVdbe(pParse: Ptr) Ptr;
extern fn sqlite3Utf8CharLen(pData: [*c]const u8, nByte: c_int) c_int;
extern fn sqlite3ChangeCookie(pParse: Ptr, iDb: c_int) void;
extern fn sqlite3VdbeAddParseSchemaOp(p: Ptr, iDb: c_int, zWhere: Ptr, p5: u16) void;
extern fn sqlite3VdbeLoadString(p: Ptr, iDest: c_int, zStr: [*c]const u8) c_int;
extern fn sqlite3VdbeAddOp4(p: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: [*c]const u8, p4type: c_int) c_int;
extern fn sqlite3SrcListDelete(db: Ptr, pList: Ptr) void;
extern fn sqlite3DbFree(db: Ptr, p: Ptr) void;
extern fn sqlite3ColumnExpr(pTab: Ptr, pCol: Ptr) Ptr;
extern fn sqlite3DbStrNDup(db: Ptr, z: [*c]const u8, n: u64) [*c]u8;
extern fn sqlite3DbStrDup(db: Ptr, z: [*c]const u8) [*c]u8;
extern fn sqlite3MPrintf(db: Ptr, zFormat: [*c]const u8, ...) [*c]u8;
extern fn sqlite3VMPrintf(db: Ptr, zFormat: [*c]const u8, ap: Ptr) [*c]u8;
extern fn sqlite3ValueFromExpr(db: Ptr, pExpr: Ptr, enc: u8, aff: u8, ppVal: *Ptr) c_int;
extern fn sqlite3ValueFree(v: Ptr) void;
extern fn sqlite3GetTempReg(pParse: Ptr) c_int;
extern fn sqlite3ReleaseTempReg(pParse: Ptr, iReg: c_int) void;
extern fn sqlite3VdbeAddOp1(p: Ptr, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(p: Ptr, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(p: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(p: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeUsesBtree(p: Ptr, i: c_int) void;
extern fn sqlite3VdbeCurrentAddr(p: Ptr) c_int;
extern fn sqlite3VdbeChangeP5(p: Ptr, p5: u16) void;
extern fn sqlite3VdbeJumpHere(p: Ptr, addr: c_int) void;
extern fn sqlite3DbMallocZero(db: Ptr, n: u64) Ptr;
extern fn sqlite3StrIHash(z: [*c]const u8) u8;
extern fn sqlite3ExprListDup(db: Ptr, p: Ptr, flags: c_int) Ptr;
extern fn sqlite3WalkExpr(pWalker: Ptr, pExpr: Ptr) c_int;
extern fn sqlite3WalkExprList(pWalker: Ptr, p: Ptr) c_int;
extern fn sqlite3WalkSelect(pWalker: Ptr, p: Ptr) c_int;
extern fn sqlite3SelectPrep(pParse: Ptr, p: Ptr, pNC: Ptr) void;
extern fn sqlite3ResolveExprNames(pNC: Ptr, pExpr: Ptr) c_int;
extern fn sqlite3ResolveExprListNames(pNC: Ptr, pList: Ptr) c_int;
extern fn sqlite3ResolveSelfReference(pParse: Ptr, pTab: Ptr, t: c_int, pExpr: Ptr, pList: Ptr) c_int;
extern fn sqlite3SelectNew(pParse: Ptr, a: Ptr, b: Ptr, c: Ptr, d: Ptr, e: Ptr, f: Ptr, g: u32, h: Ptr) Ptr;
extern fn sqlite3SrcListDup(db: Ptr, p: Ptr, flags: c_int) Ptr;
extern fn sqlite3SelectDelete(db: Ptr, p: Ptr) void;
extern fn sqlite3WithDup(db: Ptr, p: Ptr) Ptr;
extern fn sqlite3WithPush(pParse: Ptr, p: Ptr, b: u8) Ptr;
extern fn sqlite3ColumnIndex(pTab: Ptr, zCol: [*c]const u8) c_int;
extern fn sqlite3ParseObjectInit(p: Ptr, db: Ptr) void;
extern fn sqlite3ParseObjectReset(p: Ptr) void;
extern fn sqlite3RunParser(p: Ptr, zSql: [*c]const u8) c_int;
extern fn sqlite3FindDbName(db: Ptr, zName: [*c]const u8) c_int;
extern fn sqlite3Strlen30(z: [*c]const u8) c_int;
extern fn sqlite3Dequote(z: [*c]u8) void;
extern fn sqlite3IsIdChar(c: u8) c_int;
extern fn sqlite3GetToken(z: [*c]const u8, t: *c_int) i64;
extern fn sqlite3InsertBuiltinFuncs(aFunc: [*]FuncDef, nFunc: c_int) void;
extern fn sqlite3VdbeFinalize(p: Ptr) c_int;
extern fn sqlite3DeleteTable(db: Ptr, p: Ptr) void;
extern fn sqlite3FreeIndex(db: Ptr, p: Ptr) void;
extern fn sqlite3DeleteTrigger(db: Ptr, p: Ptr) void;
extern fn sqlite3PrimaryKeyIndex(pTab: Ptr) Ptr;
extern fn sqlite3TableColumnToIndex(pIdx: Ptr, iCol: c_int) c_int;
extern fn sqlite3ExprCodeGetColumnOfTable(v: Ptr, pTab: Ptr, iTabCur: c_int, iCol: c_int, regOut: c_int) void;
extern fn sqlite3OpenTable(pParse: Ptr, iCur: c_int, iDb: c_int, pTab: Ptr, opcode: c_int) void;
extern fn sqlite3ExprDelete(db: Ptr, p: Ptr) void;
extern fn sqlite3MallocZero(n: u64) Ptr;
extern fn sqlite3WritableSchema(db: Ptr) c_int;
extern fn sqlite3BtreeEnterAll(db: Ptr) void;
extern fn sqlite3BtreeLeaveAll(db: Ptr) void;

// public API
extern fn sqlite3_context_db_handle(ctx: Ptr) Ptr;
extern fn sqlite3_value_text(v: Ptr) [*c]const u8;
extern fn sqlite3_value_int(v: Ptr) c_int;
extern fn sqlite3_value_type(v: Ptr) c_int;
extern fn sqlite3_result_text(ctx: Ptr, z: [*c]const u8, n: c_int, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3_result_error(ctx: Ptr, z: [*c]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(ctx: Ptr, code: c_int) void;
extern fn sqlite3_result_error_nomem(ctx: Ptr) void;
extern fn sqlite3_result_value(ctx: Ptr, v: Ptr) void;
extern fn sqlite3_result_int(ctx: Ptr, v: c_int) void;
extern fn sqlite3_result_str(ctx: Ptr, p: Ptr, e: c_int) void;
extern fn sqlite3_str_new(db: Ptr) Ptr;
extern fn sqlite3_str_append(p: Ptr, z: [*c]const u8, n: c_int) void;
extern fn sqlite3_str_appendf(p: Ptr, zFormat: [*c]const u8, ...) void;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_snprintf(n: c_int, z: [*c]u8, zFormat: [*c]const u8, ...) [*c]u8;

const SQLITE_INTEGER: c_int = 1;

// FuncDef mirror (ABI-shared; INTERNAL_FUNCTION static initializer).
const FuncDef = extern struct {
    nArg: i16,
    funcFlags: u32,
    pUserData: ?*anyopaque,
    pNext: ?*anyopaque,
    xSFunc: ?*const fn (Ptr, c_int, Ptr) callconv(.c) void,
    xFinalize: ?*const fn (Ptr) callconv(.c) void,
    xValue: ?*const fn (Ptr) callconv(.c) void,
    xInverse: ?*const fn (Ptr, c_int, Ptr) callconv(.c) void,
    zName: [*c]const u8,
    u: ?*anyopaque,
};

// ─── helpers for reading typed struct fields ─────────────────────────────────
inline fn dbOf(pParse: Ptr) Ptr {
    return rd(Ptr, pParse, Parse_db_off);
}
inline fn mallocFailed(db: Ptr) bool {
    return rd(u8, db, sqlite3_mallocFailed_off) != 0;
}
inline fn dbFlags(db: Ptr) u64 {
    return rd(u64, db, sqlite3_flags_off);
}
inline fn tabType(pTab: Ptr) u8 {
    return rd(u8, pTab, Table_eTabType_off);
}
inline fn isView(pTab: Ptr) bool {
    return tabType(pTab) == TABTYP_VIEW;
}
inline fn isVirtual(pTab: Ptr) bool {
    return tabType(pTab) == TABTYP_VTAB;
}
inline fn isOrdinaryTable(pTab: Ptr) bool {
    return tabType(pTab) == TABTYP_NORM;
}
inline fn hasRowid(pTab: Ptr) bool {
    return (rd(u32, pTab, Table_tabFlags_off) & TF_WithoutRowid) == 0;
}
inline fn exprUseYTab(pExpr: Ptr) bool {
    return (rd(u32, pExpr, Expr_flags_off) & (EP_WinFunc | EP_Subrtn)) == 0;
}
// Db aDb[i].zDbSName
inline fn dbName(db: Ptr, iDb: c_int) [*c]u8 {
    const aDb = rd(Ptr, db, sqlite3_aDb_off);
    const entry = base(aDb) + @as(usize, @intCast(iDb)) * sizeof_Db;
    const q: *align(1) const [*c]u8 = @ptrCast(entry + Db_zDbSName_off);
    return q.*;
}
inline fn dbSchema(db: Ptr, iDb: c_int) Ptr {
    const aDb = rd(Ptr, db, sqlite3_aDb_off);
    const entry = base(aDb) + @as(usize, @intCast(iDb)) * sizeof_Db;
    const q: *align(1) const Ptr = @ptrCast(entry + Db_pSchema_off);
    return q.*;
}
// Table.aCol[i]
inline fn colPtr(pTab: Ptr, i: c_int) Ptr {
    const aCol = rd(Ptr, pTab, Table_aCol_off);
    return @ptrCast(base(aCol) + @as(usize, @intCast(i)) * sizeof_Column);
}
inline fn srcA(pSrc: Ptr, i: usize) Ptr {
    const a = base(pSrc) + SrcList_a_off;
    return @ptrCast(a + i * sizeof_SrcItem);
}
inline fn elistA(pList: Ptr, i: usize) Ptr {
    const a = rd(Ptr, pList, ExprList_a_off);
    return @ptrCast(base(a) + i * sizeof_ExprList_item);
}
inline fn elistN(pList: Ptr) c_int {
    return rd(c_int, pList, ExprList_nExpr_off);
}

// RenameToken — alter.c-private struct. Layout: { const void *p; Token t; RenameToken *pNext; }
const RenameToken = extern struct {
    p: ?*const anyopaque,
    t_z: [*c]const u8,
    t_n: c_uint,
    _pad: u32 = 0,
    pNext: ?*RenameToken,
};

const RenameCtx = struct {
    pList: ?*RenameToken = null,
    nList: c_int = 0,
    iCol: c_int = 0,
    pTab: Ptr = null,
    zOld: [*c]const u8 = null,
};

// ─── isAlterableTable ────────────────────────────────────────────────────────
fn isAlterableTable(pParse: Ptr, pTab: Ptr) c_int {
    const zName = rd([*c]const u8, pTab, Table_zName_off);
    const tabFlags = rd(u32, pTab, Table_tabFlags_off);
    const db = dbOf(pParse);
    if (sqlite3_strnicmp(zName, "sqlite_", 7) == 0 or
        (tabFlags & TF_Eponymous) != 0 or
        ((tabFlags & TF_Shadow) != 0 and sqlite3ReadOnlyShadowTables(db) != 0))
    {
        sqlite3ErrorMsg(pParse, "table %s may not be altered", zName);
        return 1;
    }
    return 0;
}

// ─── renameTestSchema ────────────────────────────────────────────────────────
fn renameTestSchema(pParse: Ptr, zDb: [*c]const u8, bTemp: c_int, zWhen: [*c]const u8, bNoDQS: c_int) void {
    // pParse->colNamesSet = 1
    const b = base(pParse) + Parse_bft1_byte;
    b[0] |= BFT_colNamesSet;
    sqlite3NestedParse(pParse, "SELECT 1 " ++
        "FROM \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " " ++
        "WHERE name NOT LIKE 'sqliteX_%%' ESCAPE 'X'" ++
        " AND sql NOT LIKE 'create virtual%%'" ++
        " AND sqlite_rename_test(%Q, sql, type, name, %d, %Q, %d)=NULL ", zDb, zDb, bTemp, zWhen, bNoDQS);

    if (bTemp == 0) {
        sqlite3NestedParse(pParse, "SELECT 1 " ++
            "FROM temp." ++ LEGACY_SCHEMA_TABLE ++ " " ++
            "WHERE name NOT LIKE 'sqliteX_%%' ESCAPE 'X'" ++
            " AND sql NOT LIKE 'create virtual%%'" ++
            " AND sqlite_rename_test(%Q, sql, type, name, 1, %Q, %d)=NULL ", zDb, zWhen, bNoDQS);
    }
}

// ─── renameFixQuotes ─────────────────────────────────────────────────────────
fn renameFixQuotes(pParse: Ptr, zDb: [*c]const u8, bTemp: c_int) void {
    sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++
        " SET sql = sqlite_rename_quotefix(%Q, sql)" ++
        "WHERE name NOT LIKE 'sqliteX_%%' ESCAPE 'X'" ++
        " AND sql NOT LIKE 'create virtual%%'", zDb, zDb);
    if (bTemp == 0) {
        sqlite3NestedParse(pParse, "UPDATE temp." ++ LEGACY_SCHEMA_TABLE ++
            " SET sql = sqlite_rename_quotefix('temp', sql)" ++
            "WHERE name NOT LIKE 'sqliteX_%%' ESCAPE 'X'" ++
            " AND sql NOT LIKE 'create virtual%%'");
    }
}

// ─── renameReloadSchema ──────────────────────────────────────────────────────
fn renameReloadSchema(pParse: Ptr, iDb: c_int, p5: u16) void {
    const v = rd(Ptr, pParse, Parse_pVdbe_off);
    if (v != null) {
        sqlite3ChangeCookie(pParse, iDb);
        sqlite3VdbeAddParseSchemaOp(v, iDb, null, p5);
        if (iDb != 1) sqlite3VdbeAddParseSchemaOp(v, 1, null, p5);
    }
}

// ─── sqlite3AlterRenameTable ─────────────────────────────────────────────────
export fn sqlite3AlterRenameTable(pParse: Ptr, pSrc: Ptr, pName: Ptr) void {
    const db = dbOf(pParse);
    var zName: [*c]u8 = null;
    var pVTab: Ptr = null;

    if (mallocFailed(db)) {
        sqlite3SrcListDelete(db, pSrc);
        return;
    }

    const pTab = sqlite3LocateTableItem(pParse, 0, srcA(pSrc, 0));
    if (pTab == null) {
        sqlite3SrcListDelete(db, pSrc);
        return;
    }
    const iDb = sqlite3SchemaToIndex(db, rd(Ptr, pTab, Table_pSchema_off));
    const zDb = dbName(db, iDb);

    zName = sqlite3NameFromToken(db, pName);
    if (zName == null) {
        sqlite3SrcListDelete(db, pSrc);
        return;
    }

    defer {
        sqlite3SrcListDelete(db, pSrc);
        sqlite3DbFree(db, zName);
    }

    if (sqlite3FindTable(db, zName, zDb) != null or
        sqlite3FindIndex(db, zName, zDb) != null or
        sqlite3IsShadowTableOf(db, pTab, zName) != 0)
    {
        sqlite3ErrorMsg(pParse, "there is already another table or index with this name: %s", zName);
        return;
    }

    if (isAlterableTable(pParse, pTab) != SQLITE_OK) return;
    if (sqlite3CheckObjectName(pParse, zName, "table", zName) != SQLITE_OK) return;

    if (isView(pTab)) {
        sqlite3ErrorMsg(pParse, "view %s may not be altered", rd([*c]const u8, pTab, Table_zName_off));
        return;
    }

    if (sqlite3AuthCheck(pParse, SQLITE_ALTER_TABLE, zDb, rd([*c]const u8, pTab, Table_zName_off), null) != 0) {
        return;
    }

    if (sqlite3ViewGetColumnNames(pParse, pTab) != 0) {
        return;
    }
    if (isVirtual(pTab)) {
        pVTab = sqlite3GetVTable(db, pTab);
        // pVTab->pVtab->pModule->xRename == 0 ?  VTable.pVtab @16, sqlite3_vtab.pModule @0, module.xRename
        const pVtab = rd(Ptr, pVTab, 16);
        const pModule = rd(Ptr, pVtab, 0);
        // sqlite3_module.xRename: iVersion(0) xCreate(8)... — compute via probe? xRename is at offset 96.
        const xRename = rd(Ptr, pModule, sqlite3_module_xRename_off);
        if (xRename == null) {
            pVTab = null;
        }
    }

    const v = sqlite3GetVdbe(pParse);
    if (v == null) return;
    sqlite3MayAbort(pParse);

    const zTabName = rd([*c]const u8, pTab, Table_zName_off);
    const nTabName = sqlite3Utf8CharLen(zTabName, -1);

    sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "sql = sqlite_rename_table(%Q, type, name, sql, %Q, %Q, %d) " ++
        "WHERE (type!='index' OR tbl_name=%Q COLLATE nocase)" ++
        "AND   name NOT LIKE 'sqliteX_%%' ESCAPE 'X'", zDb, zDb, zTabName, zName, @as(c_int, @intFromBool(iDb == 1)), zTabName);

    sqlite3NestedParse(pParse, "UPDATE %Q." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "tbl_name = %Q, " ++
        "name = CASE " ++
        "WHEN type='table' THEN %Q " ++
        "WHEN name LIKE 'sqliteX_autoindex%%' ESCAPE 'X' " ++
        "     AND type='index' THEN " ++
        "'sqlite_autoindex_' || %Q || substr(name,%d+18) " ++
        "ELSE name END " ++
        "WHERE tbl_name=%Q COLLATE nocase AND " ++
        "(type='table' OR type='index' OR type='trigger');", zDb, zName, zName, zName, nTabName, zTabName);

    if (sqlite3FindTable(db, "sqlite_sequence", zDb) != null) {
        sqlite3NestedParse(pParse, "UPDATE \"%w\".sqlite_sequence set name = %Q WHERE name = %Q", zDb, zName, zTabName);
    }

    if (iDb != 1) {
        sqlite3NestedParse(pParse, "UPDATE sqlite_temp_schema SET " ++
            "sql = sqlite_rename_table(%Q, type, name, sql, %Q, %Q, 1), " ++
            "tbl_name = " ++
            "CASE WHEN tbl_name=%Q COLLATE nocase AND " ++
            "  sqlite_rename_test(%Q, sql, type, name, 1, 'after rename', 0) " ++
            "THEN %Q ELSE tbl_name END " ++
            "WHERE type IN ('view', 'trigger')", zDb, zTabName, zName, zTabName, zDb, zName);
    }

    if (pVTab != null) {
        // i = ++pParse->nMem
        const nMem = rd(c_int, pParse, Parse_nMem_off) + 1;
        wr(c_int, pParse, Parse_nMem_off, nMem);
        _ = sqlite3VdbeLoadString(v, nMem, zName);
        _ = sqlite3VdbeAddOp4(v, OP_VRename, nMem, 0, 0, @ptrCast(pVTab), P4_VTAB);
    }

    renameReloadSchema(pParse, iDb, INITFLAG_AlterRename);
    renameTestSchema(pParse, zDb, @intFromBool(iDb == 1), "after rename", 0);
}

const sqlite3_module_xRename_off: usize = 152; // probed: sqlite3_module.xRename

// ─── sqlite3ErrorIfNotEmpty ──────────────────────────────────────────────────
fn errorIfNotEmpty(pParse: Ptr, zDb: [*c]const u8, zTab: [*c]const u8, zErr: [*c]const u8) void {
    sqlite3NestedParse(pParse, "SELECT raise(ABORT,%Q) FROM \"%w\".\"%w\"", zErr, zDb, zTab);
}

// ─── sqlite3AlterFinishAddColumn ─────────────────────────────────────────────
export fn sqlite3AlterFinishAddColumn(pParse: Ptr, pColDef: Ptr) void {
    const db = dbOf(pParse);
    if (rd(c_int, pParse, Parse_nErr_off) != 0) return;
    const pNew = rd(Ptr, pParse, Parse_pNewTable_off);

    const iDb = sqlite3SchemaToIndex(db, rd(Ptr, pNew, Table_pSchema_off));
    const zDb = dbName(db, iDb);
    const pNewName = rd([*c]const u8, pNew, Table_zName_off);
    const zTab = pNewName + 16; // skip "sqlite_altertab_"
    const nCol = rd(i16, pNew, Table_nCol_off);
    const pCol = colPtr(pNew, @as(c_int, nCol) - 1);
    var pDflt = sqlite3ColumnExpr(pNew, pCol);
    const pTab = sqlite3FindTable(db, zTab, zDb);

    if (sqlite3AuthCheck(pParse, SQLITE_ALTER_TABLE, zDb, rd([*c]const u8, pTab, Table_zName_off), null) != 0) {
        return;
    }

    const colFlags = rd(u16, pCol, Column_colFlags_off);
    if (colFlags & COLFLAG_PRIMKEY != 0) {
        sqlite3ErrorMsg(pParse, "Cannot add a PRIMARY KEY column");
        return;
    }
    if (rd(Ptr, pNew, Table_pIndex_off) != null) {
        sqlite3ErrorMsg(pParse, "Cannot add a UNIQUE column");
        return;
    }

    if ((colFlags & COLFLAG_GENERATED) == 0) {
        // if pDflt && pDflt->pLeft->op==TK_NULL => pDflt=0
        if (pDflt != null) {
            const pLeft = rd(Ptr, pDflt, Expr_pLeft_off);
            if (rd(u8, pLeft, Expr_op_off) == TK_NULL) {
                pDflt = null;
            }
        }
        const pFKey = rd(Ptr, pNew, Table_u_tab_pFKey_off);
        if ((dbFlags(db) & SQLITE_ForeignKeys) != 0 and pFKey != null and pDflt != null) {
            errorIfNotEmpty(pParse, zDb, zTab, "Cannot add a REFERENCES column with non-NULL default value");
        }
        // pCol->notNull (low nibble of byte 8)
        const notNull = rd(u8, pCol, Column_notNull_byte) & 0x0f;
        if (notNull != 0 and pDflt == null) {
            errorIfNotEmpty(pParse, zDb, zTab, "Cannot add a NOT NULL column with default value NULL");
        }
        if (pDflt != null) {
            var pVal: Ptr = null;
            const rc = sqlite3ValueFromExpr(db, pDflt, SQLITE_UTF8, SQLITE_AFF_BLOB, &pVal);
            if (rc != SQLITE_OK) {
                return;
            }
            if (pVal == null) {
                errorIfNotEmpty(pParse, zDb, zTab, "Cannot add a column with non-constant default");
            }
            sqlite3ValueFree(pVal);
        }
    } else if (colFlags & COLFLAG_STORED != 0) {
        errorIfNotEmpty(pParse, zDb, zTab, "cannot add a STORED column");
    }

    // Modify the CREATE TABLE statement
    const pColDef_z = rd([*c]const u8, pColDef, Token_z_off);
    const pColDef_n = rd(c_uint, pColDef, Token_n_off);
    const zCol = sqlite3DbStrNDup(db, pColDef_z, pColDef_n);
    if (zCol != null) {
        var zEnd = zCol + (pColDef_n - 1);
        while (@intFromPtr(zEnd) > @intFromPtr(zCol) and (zEnd[0] == ';' or isSpace(zEnd[0]))) {
            zEnd[0] = 0;
            zEnd -= 1;
        }
        const addColOffset = rd(c_int, pNew, Table_u_tab_addColOffset_off);
        sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
            "sql = printf('%%.%ds, ',sql) || %Q" ++
            " || substr(sql,1+length(printf('%%.%ds',sql))) " ++
            "WHERE type = 'table' AND name = %Q", zDb, addColOffset, zCol, addColOffset, zTab);
        sqlite3DbFree(db, zCol);
    }

    const v = sqlite3GetVdbe(pParse);
    if (v != null) {
        const r1 = sqlite3GetTempReg(pParse);
        _ = sqlite3VdbeAddOp3(v, OP_ReadCookie, iDb, r1, BTREE_FILE_FORMAT);
        sqlite3VdbeUsesBtree(v, iDb);
        _ = sqlite3VdbeAddOp2(v, OP_AddImm, r1, -2);
        _ = sqlite3VdbeAddOp2(v, OP_IfPos, r1, sqlite3VdbeCurrentAddr(v) + 2);
        _ = sqlite3VdbeAddOp3(v, OP_SetCookie, iDb, BTREE_FILE_FORMAT, 3);
        sqlite3ReleaseTempReg(pParse, r1);

        renameReloadSchema(pParse, iDb, INITFLAG_AlterAdd);

        const notNull = rd(u8, pCol, Column_notNull_byte) & 0x0f;
        const tabFlags = rd(u32, pTab, Table_tabFlags_off);
        if (rd(Ptr, pNew, Table_pCheck_off) != null or
            (notNull != 0 and (colFlags & COLFLAG_GENERATED) != 0) or
            (tabFlags & TF_Strict) != 0)
        {
            sqlite3NestedParse(pParse, "SELECT CASE WHEN quick_check GLOB 'CHECK*'" ++
                " THEN raise(ABORT,'CHECK constraint failed')" ++
                " WHEN quick_check GLOB 'non-* value in*'" ++
                " THEN raise(ABORT,'type mismatch on DEFAULT')" ++
                " ELSE raise(ABORT,'NOT NULL constraint failed')" ++
                " END" ++
                "  FROM pragma_quick_check(%Q,%Q)" ++
                " WHERE quick_check GLOB 'CHECK*'" ++
                " OR quick_check GLOB 'NULL*'" ++
                " OR quick_check GLOB 'non-* value in*'", zTab, zDb);
        }
    }
}

inline fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\x0b' or c == '\x0c' or c == '\r';
}

// ─── sqlite3AlterBeginAddColumn ──────────────────────────────────────────────
export fn sqlite3AlterBeginAddColumn(pParse: Ptr, pSrc: Ptr) void {
    const db = dbOf(pParse);
    if (mallocFailed(db)) {
        sqlite3SrcListDelete(db, pSrc);
        return;
    }
    const pTab = sqlite3LocateTableItem(pParse, 0, srcA(pSrc, 0));
    if (pTab == null) {
        sqlite3SrcListDelete(db, pSrc);
        return;
    }
    defer sqlite3SrcListDelete(db, pSrc);

    if (isVirtual(pTab)) {
        sqlite3ErrorMsg(pParse, "virtual tables may not be altered");
        return;
    }
    if (isView(pTab)) {
        sqlite3ErrorMsg(pParse, "Cannot add a column to a view");
        return;
    }
    if (isAlterableTable(pParse, pTab) != SQLITE_OK) return;

    sqlite3MayAbort(pParse);
    const iDb = sqlite3SchemaToIndex(db, rd(Ptr, pTab, Table_pSchema_off));

    const pNew = sqlite3DbMallocZero(db, sizeof_Table);
    if (pNew == null) return;
    wr(Ptr, pParse, Parse_pNewTable_off, pNew);
    wr(u32, pNew, Table_nTabRef_off, 1);
    const nCol = rd(i16, pTab, Table_nCol_off);
    wr(i16, pNew, Table_nCol_off, nCol);
    const nAlloc: u32 = (((@as(u32, @intCast(nCol)) - 1) / 8) * 8) + 8;
    const aColNew = sqlite3DbMallocZero(db, sizeof_Column * @as(u64, nAlloc));
    wr(Ptr, pNew, Table_aCol_off, aColNew);
    const zNameNew = sqlite3MPrintf(db, "sqlite_altertab_%s", rd([*c]const u8, pTab, Table_zName_off));
    wr([*c]u8, pNew, Table_zName_off, zNameNew);
    if (aColNew == null or zNameNew == null) {
        return;
    }
    // memcpy aCol
    const srcCol = rd(Ptr, pTab, Table_aCol_off);
    const nBytes: usize = sizeof_Column * @as(usize, @intCast(nCol));
    @memcpy(base(aColNew)[0..nBytes], base(srcCol)[0..nBytes]);
    var i: c_int = 0;
    while (i < @as(c_int, nCol)) : (i += 1) {
        const pCol = colPtr(pNew, i);
        const orig = rd([*c]const u8, pCol, Column_zCnName_off);
        const dup = sqlite3DbStrDup(db, orig);
        wr([*c]u8, pCol, Column_zCnName_off, dup);
        wr(u8, pCol, Column_hName_off, sqlite3StrIHash(dup));
    }
    const pDfltSrc = rd(Ptr, pTab, Table_u_tab_pDfltList_off);
    wr(Ptr, pNew, Table_u_tab_pDfltList_off, sqlite3ExprListDup(db, pDfltSrc, 0));
    wr(Ptr, pNew, Table_pSchema_off, dbSchema(db, iDb));
    const addColOffset = rd(c_int, pTab, Table_u_tab_addColOffset_off);
    wr(c_int, pNew, Table_u_tab_addColOffset_off, addColOffset);
}

// ─── isRealTable ─────────────────────────────────────────────────────────────
fn isRealTable(pParse: Ptr, pTab: Ptr, iOp: c_int) c_int {
    var zType: [*c]const u8 = null;
    if (isView(pTab)) {
        zType = "view";
    }
    if (isVirtual(pTab)) {
        zType = "virtual table";
    }
    if (zType != null) {
        const azMsg = [_][*c]const u8{ "rename columns of", "drop column from", "edit constraints of" };
        sqlite3ErrorMsg(pParse, "cannot %s %s \"%s\"", azMsg[@intCast(iOp)], zType, rd([*c]const u8, pTab, Table_zName_off));
        return 1;
    }
    return 0;
}

// ─── sqlite3AlterRenameColumn ────────────────────────────────────────────────
export fn sqlite3AlterRenameColumn(pParse: Ptr, pSrc: Ptr, pOld: Ptr, pNameTok: Ptr) void {
    const db = dbOf(pParse);
    var zOld: [*c]u8 = null;
    var zNew: [*c]u8 = null;

    const pTab = sqlite3LocateTableItem(pParse, 0, srcA(pSrc, 0));
    defer {
        sqlite3SrcListDelete(db, pSrc);
        sqlite3DbFree(db, zOld);
        sqlite3DbFree(db, zNew);
    }
    if (pTab == null) return;

    if (isAlterableTable(pParse, pTab) != SQLITE_OK) return;
    if (isRealTable(pParse, pTab, 0) != SQLITE_OK) return;

    const iSchema = sqlite3SchemaToIndex(db, rd(Ptr, pTab, Table_pSchema_off));
    const zDb = dbName(db, iSchema);

    if (sqlite3AuthCheck(pParse, SQLITE_ALTER_TABLE, zDb, rd([*c]const u8, pTab, Table_zName_off), null) != 0) {
        return;
    }

    zOld = sqlite3NameFromToken(db, pOld);
    if (zOld == null) return;
    const iCol = sqlite3ColumnIndex(pTab, zOld);
    if (iCol < 0) {
        sqlite3ErrorMsg(pParse, "no such column: \"%T\"", pOld);
        return;
    }

    renameTestSchema(pParse, zDb, @intFromBool(iSchema == 1), "", 0);
    renameFixQuotes(pParse, zDb, @intFromBool(iSchema == 1));

    sqlite3MayAbort(pParse);
    zNew = sqlite3NameFromToken(db, pNameTok);
    if (zNew == null) return;
    const pNew_z = rd([*c]const u8, pNameTok, Token_z_off);
    const bQuote: c_int = @intFromBool(isQuote(pNew_z[0]));
    const zTabName = rd([*c]const u8, pTab, Table_zName_off);

    sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, %d) " ++
        "WHERE name NOT LIKE 'sqliteX_%%' ESCAPE 'X' " ++
        " AND (type != 'index' OR tbl_name = %Q)", zDb, zDb, zTabName, iCol, zNew, bQuote, @as(c_int, @intFromBool(iSchema == 1)), zTabName);

    sqlite3NestedParse(pParse, "UPDATE temp." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) " ++
        "WHERE type IN ('trigger', 'view')", zDb, zTabName, iCol, zNew, bQuote);

    renameReloadSchema(pParse, iSchema, INITFLAG_AlterRename);
    renameTestSchema(pParse, zDb, @intFromBool(iSchema == 1), "after rename", 1);
}

inline fn isQuote(c: u8) bool {
    return c == '"' or c == '\'' or c == '[' or c == '`';
}

// ─── RenameToken bookkeeping ─────────────────────────────────────────────────
fn renameTokenCheckAll(pParse: Ptr, pPtr: ?*const anyopaque) void {
    if (!config.sqlite_debug) return;
    if (rd(c_int, pParse, Parse_nErr_off) == 0) {
        var p = rd(?*RenameToken, pParse, Parse_pRename_off);
        var i: u32 = 1;
        while (p) |pp| : (p = pp.pNext) {
            if (pp.p) |elem| {
                std.debug.assert(elem != pPtr.?);
                i +%= (@as(*const u8, @ptrCast(elem)).* | 1);
            }
        }
        std.debug.assert(i > 0);
    }
}

export fn sqlite3RenameTokenMap(pParse: Ptr, pPtr: ?*const anyopaque, pToken: Ptr) ?*const anyopaque {
    renameTokenCheckAll(pParse, pPtr);
    const eParseMode = rd(u8, pParse, Parse_eParseMode_off);
    if (eParseMode != PARSE_MODE_UNMAP) {
        const db = dbOf(pParse);
        const pNew: ?*RenameToken = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @sizeOf(RenameToken))));
        if (pNew) |n| {
            n.p = pPtr;
            n.t_z = rd([*c]const u8, pToken, Token_z_off);
            n.t_n = rd(c_uint, pToken, Token_n_off);
            n.pNext = rd(?*RenameToken, pParse, Parse_pRename_off);
            wr(?*RenameToken, pParse, Parse_pRename_off, n);
        }
    }
    return pPtr;
}

export fn sqlite3RenameTokenRemap(pParse: Ptr, pTo: ?*const anyopaque, pFrom: ?*const anyopaque) void {
    renameTokenCheckAll(pParse, pTo);
    var p = rd(?*RenameToken, pParse, Parse_pRename_off);
    while (p) |pp| : (p = pp.pNext) {
        if (pp.p == pFrom) {
            pp.p = pTo;
            break;
        }
    }
}

// ─── rename unmap walkers ────────────────────────────────────────────────────
fn renameUnmapExprCb(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const pParse = rd(Ptr, pWalker, Walker_pParse_off);
    sqlite3RenameTokenRemap(pParse, null, @ptrCast(pExpr));
    if (exprUseYTab(pExpr)) {
        sqlite3RenameTokenRemap(pParse, null, fieldPtr(pExpr, Expr_y_pTab_off));
    }
    return WRC_Continue;
}

fn renameWalkWith(pWalker: Ptr, pSelect: Ptr) void {
    const pWith = rd(Ptr, pSelect, Select_pWith_off);
    if (pWith == null) return;
    const pParse = rd(Ptr, pWalker, Walker_pParse_off);
    var pCopy: Ptr = null;
    const nCte = rd(c_int, pWith, With_nCte_off);
    // pWith->a[0].pSelect->selFlags & SF_Expanded
    const a0 = base(pWith) + With_a_off;
    const a0Select = rd(Ptr, @as(Ptr, @ptrCast(a0)), Cte_pSelect_off);
    if ((rd(u32, a0Select, Select_selFlags_off) & SF_Expanded) == 0) {
        pCopy = sqlite3WithDup(dbOf(pParse), pWith);
        pCopy = sqlite3WithPush(pParse, pCopy, 1);
    }
    var i: c_int = 0;
    while (i < nCte) : (i += 1) {
        const cte = @as(Ptr, @ptrCast(base(pWith) + With_a_off + @as(usize, @intCast(i)) * sizeof_Cte));
        const p = rd(Ptr, cte, Cte_pSelect_off);
        var sNC: [sizeof_NameContext]u8 = std.mem.zeroes([sizeof_NameContext]u8);
        const pNC: Ptr = @ptrCast(&sNC);
        wr(Ptr, pNC, NameContext_pParse_off, pParse);
        if (pCopy != null) sqlite3SelectPrep(pParse, p, pNC);
        if (mallocFailed(dbOf(pParse))) return;
        _ = sqlite3WalkSelect(pWalker, p);
        sqlite3RenameExprlistUnmap(pParse, rd(Ptr, cte, Cte_pCols_off));
    }
    if (pCopy != null and rd(Ptr, pParse, Parse_pWith_off) == pCopy) {
        wr(Ptr, pParse, Parse_pWith_off, rd(Ptr, pCopy, With_pOuter_off));
    }
}
const Parse_pWith_off = off("Parse_pWith", 400);

fn unmapColumnIdlistNames(pParse: Ptr, pIdList: Ptr) void {
    const nId = rd(c_int, pIdList, IdList_nId_off);
    var ii: c_int = 0;
    while (ii < nId) : (ii += 1) {
        const item = base(pIdList) + IdList_a_off + @as(usize, @intCast(ii)) * sizeof_IdList_item;
        const zName = rd([*c]const u8, @as(Ptr, @ptrCast(item)), IdList_item_zName_off);
        sqlite3RenameTokenRemap(pParse, null, @ptrCast(zName));
    }
}

fn renameUnmapSelectCb(pWalker: Ptr, p: Ptr) callconv(.c) c_int {
    const pParse = rd(Ptr, pWalker, Walker_pParse_off);
    if (rd(c_int, pParse, Parse_nErr_off) != 0) return WRC_Abort;
    const selFlags = rd(u32, p, Select_selFlags_off);
    if (selFlags & (SF_View | SF_CopyCte) != 0) return WRC_Prune;
    const pEList = rd(Ptr, p, Select_pEList_off);
    if (pEList != null) {
        const n = elistN(pEList);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            const item = elistA(pEList, @intCast(i));
            const zEName = rd([*c]const u8, item, ExprList_item_zEName_off);
            const eEName = readEName(item);
            if (zEName != null and eEName == ENAME_NAME) {
                sqlite3RenameTokenRemap(pParse, null, @ptrCast(zEName));
            }
        }
    }
    const pSrc = rd(Ptr, p, Select_pSrc_off);
    if (pSrc != null) {
        const nSrc = rd(c_int, pSrc, SrcList_nSrc_off);
        var i: c_int = 0;
        while (i < nSrc) : (i += 1) {
            const item = srcA(pSrc, @intCast(i));
            sqlite3RenameTokenRemap(pParse, null, @ptrCast(rd([*c]const u8, item, SrcItem_zName_off)));
            if (!srcIsUsing(item)) {
                _ = sqlite3WalkExpr(pWalker, rd(Ptr, item, SrcItem_u3_off));
            } else {
                unmapColumnIdlistNames(pParse, rd(Ptr, item, SrcItem_u3_off));
            }
        }
    }
    renameWalkWith(pWalker, p);
    return WRC_Continue;
}

inline fn readEName(item: Ptr) c_int {
    const b = base(item) + ExprList_item_eEName_byte;
    return @as(c_int, b[0] & ENAME_mask);
}
inline fn srcIsUsing(item: Ptr) bool {
    return (base(item) + SrcItem_isUsing_byte)[0] & SrcItem_isUsing_mask != 0;
}
inline fn srcIsSubquery(item: Ptr) bool {
    return (base(item) + SrcItem_isSubquery_byte)[0] & SrcItem_isSubquery_mask != 0;
}

export fn sqlite3RenameExprUnmap(pParse: Ptr, pExpr: Ptr) void {
    const eMode = rd(u8, pParse, Parse_eParseMode_off);
    var sWalker: [sizeof_Walker]u8 = std.mem.zeroes([sizeof_Walker]u8);
    const w: Ptr = @ptrCast(&sWalker);
    wr(Ptr, w, Walker_pParse_off, pParse);
    wr(Ptr, w, Walker_xExprCallback_off, @constCast(@ptrCast(&renameUnmapExprCb)));
    wr(Ptr, w, Walker_xSelectCallback_off, @constCast(@ptrCast(&renameUnmapSelectCb)));
    wr(u8, pParse, Parse_eParseMode_off, PARSE_MODE_UNMAP);
    _ = sqlite3WalkExpr(w, pExpr);
    wr(u8, pParse, Parse_eParseMode_off, eMode);
}

export fn sqlite3RenameExprlistUnmap(pParse: Ptr, pEList: Ptr) void {
    if (pEList == null) return;
    var sWalker: [sizeof_Walker]u8 = std.mem.zeroes([sizeof_Walker]u8);
    const w: Ptr = @ptrCast(&sWalker);
    wr(Ptr, w, Walker_pParse_off, pParse);
    wr(Ptr, w, Walker_xExprCallback_off, @constCast(@ptrCast(&renameUnmapExprCb)));
    _ = sqlite3WalkExprList(w, pEList);
    const n = elistN(pEList);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const item = elistA(pEList, @intCast(i));
        if (readEName(item) == ENAME_NAME) {
            sqlite3RenameTokenRemap(pParse, null, @ptrCast(rd([*c]const u8, item, ExprList_item_zEName_off)));
        }
    }
}

// ─── renameTokenFree / renameTokenFind ───────────────────────────────────────
fn renameTokenFree(db: Ptr, pToken: ?*RenameToken) void {
    var p = pToken;
    while (p) |pp| {
        const next = pp.pNext;
        sqlite3DbFree(db, @ptrCast(pp));
        p = next;
    }
}

fn renameTokenFind(pParse: Ptr, pCtx: ?*RenameCtx, pPtr: ?*const anyopaque) ?*RenameToken {
    if (pPtr == null) return null;
    var pp: *?*RenameToken = @ptrCast(@alignCast(base(pParse) + Parse_pRename_off));
    while (pp.*) |tok| {
        if (tok.p == pPtr) {
            if (pCtx) |ctx| {
                pp.* = tok.pNext;
                tok.pNext = ctx.pList;
                ctx.pList = tok;
                ctx.nList += 1;
            }
            return tok;
        }
        pp = &tok.pNext;
    }
    return null;
}

// ─── column-rename walkers ───────────────────────────────────────────────────
fn renameColumnSelectCb(pWalker: Ptr, p: Ptr) callconv(.c) c_int {
    const selFlags = rd(u32, p, Select_selFlags_off);
    if (selFlags & (SF_View | SF_CopyCte) != 0) {
        return WRC_Prune;
    }
    renameWalkWith(pWalker, p);
    return WRC_Continue;
}

fn renameColumnExprCb(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const p: *RenameCtx = @ptrCast(@alignCast(rd(Ptr, pWalker, Walker_u_off)));
    const pParse = rd(Ptr, pWalker, Walker_pParse_off);
    const op = rd(u8, pExpr, Expr_op_off);
    const iColumn = rd(i16, pExpr, Expr_iColumn_off);
    if (op == TK_TRIGGER and @as(c_int, iColumn) == p.iCol and
        rd(Ptr, pParse, Parse_pTriggerTab_off) == p.pTab)
    {
        _ = renameTokenFind(pParse, p, @ptrCast(pExpr));
    } else if (op == TK_COLUMN and @as(c_int, iColumn) == p.iCol and
        exprUseYTab(pExpr) and p.pTab == rd(Ptr, pExpr, Expr_y_pTab_off))
    {
        _ = renameTokenFind(pParse, p, @ptrCast(pExpr));
    }
    return WRC_Continue;
}

fn renameColumnTokenNext(pCtx: *RenameCtx) *RenameToken {
    var pBest = pCtx.pList.?;
    var pToken = pBest.pNext;
    while (pToken) |t| : (pToken = t.pNext) {
        if (@intFromPtr(t.t_z) > @intFromPtr(pBest.t_z)) pBest = t;
    }
    var pp: *?*RenameToken = &pCtx.pList;
    while (pp.* != pBest) {
        pp = &pp.*.?.pNext;
    }
    pp.* = pBest.pNext;
    return pBest;
}

fn errorMPrintf(pCtx: Ptr, zFmt: [*c]const u8, arg: [*c]const u8) void {
    const db = sqlite3_context_db_handle(pCtx);
    const zErr = sqlite3MPrintf(db, zFmt, arg);
    if (zErr != null) {
        sqlite3_result_error(pCtx, zErr, -1);
        sqlite3DbFree(db, zErr);
    } else {
        sqlite3_result_error_nomem(pCtx);
    }
}

fn renameColumnParseError(pCtx: Ptr, zWhen: [*c]const u8, pType: Ptr, pObject: Ptr, pParse: Ptr) void {
    const zT = sqlite3_value_text(pType);
    const zN = sqlite3_value_text(pObject);
    const db = dbOf(pParse);
    const zErrMsg = rd([*c]const u8, pParse, Parse_zErrMsg_off);
    const sep: [*c]const u8 = if (zWhen[0] != 0) " " else "";
    const zErr = sqlite3MPrintf(db, "error in %s %s%s%s: %s", zT, zN, sep, zWhen, zErrMsg);
    sqlite3_result_error(pCtx, zErr, -1);
    sqlite3DbFree(db, zErr);
}

fn renameColumnElistNames(pParse: Ptr, pCtx: *RenameCtx, pEList: Ptr, zOld: [*c]const u8) void {
    if (pEList == null) return;
    const n = elistN(pEList);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const item = elistA(pEList, @intCast(i));
        const zName = rd([*c]const u8, item, ExprList_item_zEName_off);
        if (readEName(item) == ENAME_NAME and zName != null and sqlite3_stricmp(zName, zOld) == 0) {
            _ = renameTokenFind(pParse, pCtx, @ptrCast(zName));
        }
    }
}

fn renameColumnIdlistNames(pParse: Ptr, pCtx: *RenameCtx, pIdList: Ptr, zOld: [*c]const u8) void {
    if (pIdList == null) return;
    const nId = rd(c_int, pIdList, IdList_nId_off);
    var i: c_int = 0;
    while (i < nId) : (i += 1) {
        const item = base(pIdList) + IdList_a_off + @as(usize, @intCast(i)) * sizeof_IdList_item;
        const zName = rd([*c]const u8, @as(Ptr, @ptrCast(item)), IdList_item_zName_off);
        if (sqlite3_stricmp(zName, zOld) == 0) {
            _ = renameTokenFind(pParse, pCtx, @ptrCast(zName));
        }
    }
}

// ─── renameParseSql ──────────────────────────────────────────────────────────
fn renameParseSql(p: Ptr, zDb: [*c]const u8, db: Ptr, zSql: [*c]const u8, bTemp: c_int) c_int {
    sqlite3ParseObjectInit(p, db);
    if (zSql == null) return SQLITE_NOMEM;
    if (sqlite3_strnicmp(zSql, "CREATE ", 7) != 0) return SQLITE_CORRUPT;
    if (bTemp != 0) {
        wr(u8, db, sqlite3_init_iDb_off, 1);
    } else {
        const iDb = sqlite3FindDbName(db, zDb);
        wr(u8, db, sqlite3_init_iDb_off, @intCast(iDb));
    }
    wr(u8, p, Parse_eParseMode_off, PARSE_MODE_RENAME);
    wr(Ptr, p, Parse_db_off, db);
    wr(c_int, p, Parse_nQueryLoop_off, 1);
    const flags = dbFlags(db);
    wr(u64, db, sqlite3_flags_off, flags | SQLITE_Comments);
    var rc = sqlite3RunParser(p, zSql);
    wr(u64, db, sqlite3_flags_off, flags);
    if (mallocFailed(db)) rc = SQLITE_NOMEM;
    if (rc == SQLITE_OK and
        rd(Ptr, p, Parse_pNewTable_off) == null and
        rd(Ptr, p, Parse_pNewIndex_off) == null and
        rd(Ptr, p, Parse_pNewTrigger_off) == null)
    {
        rc = SQLITE_CORRUPT;
    }
    wr(u8, db, sqlite3_init_iDb_off, 0);
    return rc;
}

// ─── renameEditSql ───────────────────────────────────────────────────────────
fn renameEditSql(pCtx: Ptr, pRename: *RenameCtx, zSql: [*c]const u8, zNew: [*c]const u8, bQuote: c_int) c_int {
    const nNew: i64 = sqlite3Strlen30(zNew);
    const nSql: i64 = sqlite3Strlen30(zSql);
    const db = sqlite3_context_db_handle(pCtx);
    var rc: c_int = SQLITE_OK;
    var zQuot: [*c]u8 = null;
    var zOut: [*c]u8 = null;
    var nQuot: i64 = 0;
    var zBuf1: [*c]u8 = null;
    var zBuf2: [*c]u8 = null;

    if (zNew != null) {
        zQuot = sqlite3MPrintf(db, "\"%w\" ", zNew);
        if (zQuot == null) {
            return SQLITE_NOMEM;
        } else {
            nQuot = sqlite3Strlen30(zQuot) - 1;
        }
        zOut = @ptrCast(sqlite3DbMallocZero(db, @as(u64, @intCast(nSql)) + @as(u64, @intCast(pRename.nList)) * @as(u64, @intCast(nQuot)) + 1));
    } else {
        zOut = @ptrCast(sqlite3DbMallocZero(db, (2 * @as(u64, @intCast(nSql)) + 1) * 3));
        if (zOut != null) {
            zBuf1 = zOut + @as(usize, @intCast(nSql * 2 + 1));
            zBuf2 = zOut + @as(usize, @intCast(nSql * 4 + 2));
        }
    }

    if (zOut != null) {
        var nOut: i64 = nSql;
        @memcpy(zOut[0..@intCast(nSql)], zSql[0..@intCast(nSql)]);
        while (pRename.pList != null) {
            var nReplace: i64 = 0;
            var zReplace: [*c]const u8 = null;
            const pBest = renameColumnTokenNext(pRename);

            if (zNew != null) {
                if (bQuote == 0 and sqlite3IsIdChar(pBest.t_z[0]) != 0) {
                    nReplace = nNew;
                    zReplace = zNew;
                } else {
                    nReplace = nQuot;
                    zReplace = zQuot;
                    if (pBest.t_z[pBest.t_n] == '"') nReplace += 1;
                }
            } else {
                @memcpy(zBuf1[0..pBest.t_n], pBest.t_z[0..pBest.t_n]);
                zBuf1[pBest.t_n] = 0;
                sqlite3Dequote(zBuf1);
                const tail: [*c]const u8 = if (pBest.t_z[pBest.t_n] == '\'') " " else "";
                _ = sqlite3_snprintf(@intCast(nSql * 2), zBuf2, "%Q%s", zBuf1, tail);
                zReplace = zBuf2;
                nReplace = sqlite3Strlen30(zReplace);
            }

            const iOff: i64 = @intCast(@intFromPtr(pBest.t_z) - @intFromPtr(zSql));
            if (@as(i64, pBest.t_n) != nReplace) {
                const dst = zOut + @as(usize, @intCast(iOff + nReplace));
                const src = zOut + @as(usize, @intCast(iOff + @as(i64, pBest.t_n)));
                const len: usize = @intCast(nOut - (iOff + @as(i64, pBest.t_n)));
                std.mem.copyBackwards(u8, dst[0..len], src[0..len]);
                nOut += nReplace - @as(i64, pBest.t_n);
                zOut[@intCast(nOut)] = 0;
            }
            @memcpy((zOut + @as(usize, @intCast(iOff)))[0..@intCast(nReplace)], zReplace[0..@intCast(nReplace)]);
            sqlite3DbFree(db, @ptrCast(pBest));
        }
        sqlite3_result_text(pCtx, zOut, -1, SQLITE_TRANSIENT);
        sqlite3DbFree(db, zOut);
    } else {
        rc = SQLITE_NOMEM;
    }

    sqlite3_free(zQuot);
    return rc;
}

// ─── renameSetENames ─────────────────────────────────────────────────────────
fn renameSetENames(pEList: Ptr, val: c_int) void {
    if (pEList == null) return;
    const n = elistN(pEList);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const item = elistA(pEList, @intCast(i));
        const b = base(item) + ExprList_item_eEName_byte;
        b[0] = (b[0] & ~ENAME_mask) | (@as(u8, @intCast(val)) & ENAME_mask);
    }
}

// ─── renameResolveTrigger ────────────────────────────────────────────────────
fn renameResolveTrigger(pParse: Ptr) c_int {
    const db = dbOf(pParse);
    const pNew = rd(Ptr, pParse, Parse_pNewTrigger_off);
    var rc: c_int = SQLITE_OK;

    var sNC: [sizeof_NameContext]u8 = std.mem.zeroes([sizeof_NameContext]u8);
    const pNC: Ptr = @ptrCast(&sNC);
    wr(Ptr, pNC, NameContext_pParse_off, pParse);
    const tabName = rd([*c]const u8, pNew, Trigger_table_off);
    const iTabDb = sqlite3SchemaToIndex(db, rd(Ptr, pNew, Trigger_pTabSchema_off));
    const pTriggerTab = sqlite3FindTable(db, tabName, dbName(db, iTabDb));
    wr(Ptr, pParse, Parse_pTriggerTab_off, pTriggerTab);
    wr(u8, pParse, Parse_eTriggerOp_off, rd(u8, pNew, Trigger_op_off));
    if (pTriggerTab != null) {
        rc = @intFromBool(sqlite3ViewGetColumnNames(pParse, pTriggerTab) != 0);
    }

    const pWhen = rd(Ptr, pNew, Trigger_pWhen_off);
    if (rc == SQLITE_OK and pWhen != null) {
        rc = sqlite3ResolveExprNames(pNC, pWhen);
    }

    var pStep = rd(Ptr, pNew, Trigger_step_list_off);
    while (rc == SQLITE_OK and pStep != null) : (pStep = rd(Ptr, pStep, TriggerStep_pNext_off)) {
        const pSelect = rd(Ptr, pStep, TriggerStep_pSelect_off);
        if (pSelect != null) {
            sqlite3SelectPrep(pParse, pSelect, pNC);
            if (rd(c_int, pParse, Parse_nErr_off) != 0) rc = rd(c_int, pParse, Parse_rc_off);
        }
        const pStepSrc = rd(Ptr, pStep, TriggerStep_pSrc_off);
        if (rc == SQLITE_OK and pStepSrc != null) {
            const pSrc = sqlite3SrcListDup(db, pStepSrc, 0);
            if (pSrc != null) {
                const pExprListStep = rd(Ptr, pStep, TriggerStep_pExprList_off);
                const pSel = sqlite3SelectNew(pParse, pExprListStep, pSrc, null, null, null, null, 0, null);
                if (pSel == null) {
                    wr(Ptr, pStep, TriggerStep_pExprList_off, null);
                    rc = SQLITE_NOMEM;
                } else {
                    renameSetENames(rd(Ptr, pStep, TriggerStep_pExprList_off), ENAME_SPAN);
                    sqlite3SelectPrep(pParse, pSel, null);
                    renameSetENames(rd(Ptr, pStep, TriggerStep_pExprList_off), ENAME_NAME);
                    rc = if (rd(c_int, pParse, Parse_nErr_off) != 0) SQLITE_ERROR else SQLITE_OK;
                    if (rd(Ptr, pStep, TriggerStep_pExprList_off) != null) wr(Ptr, pSel, Select_pEList_off, null);
                    wr(Ptr, pSel, Select_pSrc_off, null);
                    sqlite3SelectDelete(db, pSel);
                }
                const pStepSrc2 = rd(Ptr, pStep, TriggerStep_pSrc_off);
                if (pStepSrc2 != null) {
                    const nSrc = rd(c_int, pStepSrc2, SrcList_nSrc_off);
                    var i: c_int = 0;
                    while (i < nSrc and rc == SQLITE_OK) : (i += 1) {
                        const item = srcA(pStepSrc2, @intCast(i));
                        if (srcIsSubquery(item)) {
                            const pSubq = rd(Ptr, item, SrcItem_u4_pSubq_off);
                            sqlite3SelectPrep(pParse, rd(Ptr, pSubq, Subquery_pSelect_off), null);
                        }
                    }
                }

                if (mallocFailed(db)) rc = SQLITE_NOMEM;
                wr(Ptr, pNC, NameContext_pSrcList_off, pSrc);
                const pWhere = rd(Ptr, pStep, TriggerStep_pWhere_off);
                if (rc == SQLITE_OK and pWhere != null) {
                    rc = sqlite3ResolveExprNames(pNC, pWhere);
                }
                if (rc == SQLITE_OK) {
                    rc = sqlite3ResolveExprListNames(pNC, rd(Ptr, pStep, TriggerStep_pExprList_off));
                }
                const pUpsert = rd(Ptr, pStep, TriggerStep_pUpsert_off);
                if (pUpsert != null and rc == SQLITE_OK) {
                    wr(Ptr, pUpsert, Upsert_pUpsertSrc_off, pSrc);
                    wr(Ptr, pNC, NameContext_uNC_off, pUpsert);
                    wr(c_int, pNC, NameContext_ncFlags_off, NC_UUpsert);
                    rc = sqlite3ResolveExprListNames(pNC, rd(Ptr, pUpsert, Upsert_pUpsertTarget_off));
                    if (rc == SQLITE_OK) {
                        rc = sqlite3ResolveExprListNames(pNC, rd(Ptr, pUpsert, Upsert_pUpsertSet_off));
                    }
                    if (rc == SQLITE_OK) {
                        rc = sqlite3ResolveExprNames(pNC, rd(Ptr, pUpsert, Upsert_pUpsertWhere_off));
                    }
                    if (rc == SQLITE_OK) {
                        rc = sqlite3ResolveExprNames(pNC, rd(Ptr, pUpsert, Upsert_pUpsertTargetWhere_off));
                    }
                    wr(c_int, pNC, NameContext_ncFlags_off, 0);
                }
                wr(Ptr, pNC, NameContext_pSrcList_off, null);
                sqlite3SrcListDelete(db, pSrc);
            } else {
                rc = SQLITE_NOMEM;
            }
        }
    }
    return rc;
}

// ─── renameWalkTrigger ───────────────────────────────────────────────────────
fn renameWalkTrigger(pWalker: Ptr, pTrigger: Ptr) void {
    _ = sqlite3WalkExpr(pWalker, rd(Ptr, pTrigger, Trigger_pWhen_off));
    var pStep = rd(Ptr, pTrigger, Trigger_step_list_off);
    while (pStep != null) : (pStep = rd(Ptr, pStep, TriggerStep_pNext_off)) {
        _ = sqlite3WalkSelect(pWalker, rd(Ptr, pStep, TriggerStep_pSelect_off));
        _ = sqlite3WalkExpr(pWalker, rd(Ptr, pStep, TriggerStep_pWhere_off));
        _ = sqlite3WalkExprList(pWalker, rd(Ptr, pStep, TriggerStep_pExprList_off));
        const pUpsert = rd(Ptr, pStep, TriggerStep_pUpsert_off);
        if (pUpsert != null) {
            _ = sqlite3WalkExprList(pWalker, rd(Ptr, pUpsert, Upsert_pUpsertTarget_off));
            _ = sqlite3WalkExprList(pWalker, rd(Ptr, pUpsert, Upsert_pUpsertSet_off));
            _ = sqlite3WalkExpr(pWalker, rd(Ptr, pUpsert, Upsert_pUpsertWhere_off));
            _ = sqlite3WalkExpr(pWalker, rd(Ptr, pUpsert, Upsert_pUpsertTargetWhere_off));
        }
        const pStepSrc = rd(Ptr, pStep, TriggerStep_pSrc_off);
        if (pStepSrc != null) {
            const nSrc = rd(c_int, pStepSrc, SrcList_nSrc_off);
            var i: c_int = 0;
            while (i < nSrc) : (i += 1) {
                const item = srcA(pStepSrc, @intCast(i));
                if (srcIsSubquery(item)) {
                    const pSubq = rd(Ptr, item, SrcItem_u4_pSubq_off);
                    _ = sqlite3WalkSelect(pWalker, rd(Ptr, pSubq, Subquery_pSelect_off));
                }
            }
        }
    }
}

// ─── renameParseCleanup ──────────────────────────────────────────────────────
fn renameParseCleanup(pParse: Ptr) void {
    const db = dbOf(pParse);
    if (rd(Ptr, pParse, Parse_pVdbe_off) != null) {
        _ = sqlite3VdbeFinalize(rd(Ptr, pParse, Parse_pVdbe_off));
    }
    sqlite3DeleteTable(db, rd(Ptr, pParse, Parse_pNewTable_off));
    var pIdx = rd(Ptr, pParse, Parse_pNewIndex_off);
    while (pIdx != null) {
        wr(Ptr, pParse, Parse_pNewIndex_off, rd(Ptr, pIdx, Index_pNext_off));
        sqlite3FreeIndex(db, pIdx);
        pIdx = rd(Ptr, pParse, Parse_pNewIndex_off);
    }
    sqlite3DeleteTrigger(db, rd(Ptr, pParse, Parse_pNewTrigger_off));
    sqlite3DbFree(db, rd(Ptr, pParse, Parse_zErrMsg_off));
    renameTokenFree(db, rd(?*RenameToken, pParse, Parse_pRename_off));
    sqlite3ParseObjectReset(pParse);
}

// ─── renameColumnFunc (SQL function) ─────────────────────────────────────────
fn renameColumnFunc(context: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const db = sqlite3_context_db_handle(context);
    var sCtx: RenameCtx = .{};
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zSql = sqlite3_value_text(av[0]);
    const zDb = sqlite3_value_text(av[3]);
    const zTable = sqlite3_value_text(av[4]);
    const iCol = sqlite3_value_int(av[5]);
    const zNew = sqlite3_value_text(av[6]);
    const bQuote = sqlite3_value_int(av[7]);
    const bTemp = sqlite3_value_int(av[8]);
    var rc: c_int = SQLITE_OK;
    const xAuth = rd(Ptr, db, sqlite3_xAuth_off);

    if (zSql == null) return;
    if (zTable == null) return;
    if (zNew == null) return;
    if (iCol < 0) return;
    sqlite3BtreeEnterAll(db);
    const pTab = sqlite3FindTable(db, zTable, zDb);
    if (pTab == null or iCol >= @as(c_int, rd(i16, pTab, Table_nCol_off))) {
        sqlite3BtreeLeaveAll(db);
        return;
    }
    const zOld = rd([*c]const u8, colPtr(pTab, iCol), Column_zCnName_off);
    sCtx.iCol = if (iCol == @as(c_int, rd(i16, pTab, Table_iPKey_off))) -1 else iCol;

    wr(Ptr, db, sqlite3_xAuth_off, null);

    var sParseBuf: [sizeof_Parse]u8 align(16) = undefined;
    const sParse: Ptr = @ptrCast(&sParseBuf);
    rc = renameParseSql(sParse, zDb, db, zSql, bTemp);

    var sWalker: [sizeof_Walker]u8 = std.mem.zeroes([sizeof_Walker]u8);
    const w: Ptr = @ptrCast(&sWalker);
    wr(Ptr, w, Walker_pParse_off, sParse);
    wr(Ptr, w, Walker_xExprCallback_off, @constCast(@ptrCast(&renameColumnExprCb)));
    wr(Ptr, w, Walker_xSelectCallback_off, @constCast(@ptrCast(&renameColumnSelectCb)));
    wr(Ptr, w, Walker_u_off, &sCtx);

    sCtx.pTab = pTab;
    blk: {
        if (rc != SQLITE_OK) break :blk;
        const pNewTable = rd(Ptr, sParse, Parse_pNewTable_off);
        const pNewIndex = rd(Ptr, sParse, Parse_pNewIndex_off);
        if (pNewTable != null) {
            if (isView(pNewTable)) {
                const pSelect = rd(Ptr, pNewTable, Table_u_view_pSelect_off);
                const sf = rd(u32, pSelect, Select_selFlags_off);
                wr(u32, pSelect, Select_selFlags_off, sf & ~SF_View);
                wr(c_int, sParse, Parse_rc_off, SQLITE_OK);
                sqlite3SelectPrep(sParse, pSelect, null);
                rc = if (mallocFailed(db)) SQLITE_NOMEM else rd(c_int, sParse, Parse_rc_off);
                if (rc == SQLITE_OK) {
                    _ = sqlite3WalkSelect(w, pSelect);
                }
                if (rc != SQLITE_OK) break :blk;
            } else if (isOrdinaryTable(pNewTable)) {
                const bFKOnly = sqlite3_stricmp(zTable, rd([*c]const u8, pNewTable, Table_zName_off));
                sCtx.pTab = pNewTable;
                if (bFKOnly == 0) {
                    if (iCol < @as(c_int, rd(i16, pNewTable, Table_nCol_off))) {
                        _ = renameTokenFind(sParse, &sCtx, @ptrCast(rd([*c]const u8, colPtr(pNewTable, iCol), Column_zCnName_off)));
                    }
                    if (sCtx.iCol < 0) {
                        _ = renameTokenFind(sParse, &sCtx, fieldPtr(pNewTable, Table_iPKey_off));
                    }
                    _ = sqlite3WalkExprList(w, rd(Ptr, pNewTable, Table_pCheck_off));
                    var pIdx = rd(Ptr, pNewTable, Table_pIndex_off);
                    while (pIdx != null) : (pIdx = rd(Ptr, pIdx, Index_pNext_off)) {
                        _ = sqlite3WalkExprList(w, rd(Ptr, pIdx, Index_aColExpr_off));
                    }
                    pIdx = rd(Ptr, sParse, Parse_pNewIndex_off);
                    while (pIdx != null) : (pIdx = rd(Ptr, pIdx, Index_pNext_off)) {
                        _ = sqlite3WalkExprList(w, rd(Ptr, pIdx, Index_aColExpr_off));
                    }
                    const nC = @as(c_int, rd(i16, pNewTable, Table_nCol_off));
                    var i: c_int = 0;
                    while (i < nC) : (i += 1) {
                        const pExpr = sqlite3ColumnExpr(pNewTable, colPtr(pNewTable, i));
                        _ = sqlite3WalkExpr(w, pExpr);
                    }
                }

                var pFKey = rd(Ptr, pNewTable, Table_u_tab_pFKey_off);
                while (pFKey != null) : (pFKey = rd(Ptr, pFKey, FKey_pNextFrom_off)) {
                    const nFCol = rd(c_int, pFKey, FKey_nCol_off);
                    const zTo = rd([*c]const u8, pFKey, FKey_zTo_off);
                    var i: c_int = 0;
                    while (i < nFCol) : (i += 1) {
                        const fcol = base(pFKey) + FKey_aCol_off + @as(usize, @intCast(i)) * sizeof_FKeyCol;
                        const iFrom = rd(c_int, @as(Ptr, @ptrCast(fcol)), sColMap_iFrom_off);
                        if (bFKOnly == 0 and iFrom == iCol) {
                            _ = renameTokenFind(sParse, &sCtx, @ptrCast(fcol));
                        }
                        const zCol = rd([*c]const u8, @as(Ptr, @ptrCast(fcol)), sColMap_zCol_off);
                        if (sqlite3_stricmp(zTo, zTable) == 0 and sqlite3_stricmp(zCol, zOld) == 0) {
                            _ = renameTokenFind(sParse, &sCtx, @ptrCast(zCol));
                        }
                    }
                }
            }
        } else if (pNewIndex != null) {
            _ = sqlite3WalkExprList(w, rd(Ptr, pNewIndex, Index_aColExpr_off));
            _ = sqlite3WalkExpr(w, rd(Ptr, pNewIndex, Index_pPartIdxWhere_off));
        } else {
            rc = renameResolveTrigger(sParse);
            if (rc != SQLITE_OK) break :blk;
            const pNewTrigger = rd(Ptr, sParse, Parse_pNewTrigger_off);
            var pStep = rd(Ptr, pNewTrigger, Trigger_step_list_off);
            while (pStep != null) : (pStep = rd(Ptr, pStep, TriggerStep_pNext_off)) {
                const pStepSrc = rd(Ptr, pStep, TriggerStep_pSrc_off);
                if (pStepSrc != null) {
                    const pTarget = sqlite3LocateTableItem(sParse, 0, srcA(pStepSrc, 0));
                    if (pTarget == pTab) {
                        const pUpsert = rd(Ptr, pStep, TriggerStep_pUpsert_off);
                        if (pUpsert != null) {
                            renameColumnElistNames(sParse, &sCtx, rd(Ptr, pUpsert, Upsert_pUpsertSet_off), zOld);
                        }
                        renameColumnIdlistNames(sParse, &sCtx, rd(Ptr, pStep, TriggerStep_pIdList_off), zOld);
                        renameColumnElistNames(sParse, &sCtx, rd(Ptr, pStep, TriggerStep_pExprList_off), zOld);
                    }
                }
            }
            if (rd(Ptr, sParse, Parse_pTriggerTab_off) == pTab) {
                renameColumnIdlistNames(sParse, &sCtx, rd(Ptr, pNewTrigger, Trigger_pColumns_off), zOld);
            }
            renameWalkTrigger(w, pNewTrigger);
        }

        rc = renameEditSql(context, &sCtx, zSql, zNew, bQuote);
    }

    if (rc != SQLITE_OK) {
        if (rc == SQLITE_ERROR and sqlite3WritableSchema(db) != 0) {
            sqlite3_result_value(context, av[0]);
        } else if (rd([*c]const u8, sParse, Parse_zErrMsg_off) != null) {
            renameColumnParseError(context, "", av[1], av[2], sParse);
        } else {
            sqlite3_result_error_code(context, rc);
        }
    }

    renameParseCleanup(sParse);
    renameTokenFree(db, sCtx.pList);
    wr(Ptr, db, sqlite3_xAuth_off, xAuth);
    sqlite3BtreeLeaveAll(db);
}

// ─── rename-table walkers ────────────────────────────────────────────────────
fn renameTableExprCb(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const p: *RenameCtx = @ptrCast(@alignCast(rd(Ptr, pWalker, Walker_u_off)));
    if (rd(u8, pExpr, Expr_op_off) == TK_COLUMN and exprUseYTab(pExpr) and
        p.pTab == rd(Ptr, pExpr, Expr_y_pTab_off))
    {
        _ = renameTokenFind(rd(Ptr, pWalker, Walker_pParse_off), p, fieldPtr(pExpr, Expr_y_pTab_off));
    }
    return WRC_Continue;
}

fn renameTableSelectCb(pWalker: Ptr, pSelect: Ptr) callconv(.c) c_int {
    const p: *RenameCtx = @ptrCast(@alignCast(rd(Ptr, pWalker, Walker_u_off)));
    const pSrc = rd(Ptr, pSelect, Select_pSrc_off);
    if (rd(u32, pSelect, Select_selFlags_off) & (SF_View | SF_CopyCte) != 0) {
        return WRC_Prune;
    }
    if (pSrc == null) {
        return WRC_Abort;
    }
    const nSrc = rd(c_int, pSrc, SrcList_nSrc_off);
    var i: c_int = 0;
    while (i < nSrc) : (i += 1) {
        const item = srcA(pSrc, @intCast(i));
        if (rd(Ptr, item, SrcItem_pSTab_off) == p.pTab) {
            _ = renameTokenFind(rd(Ptr, pWalker, Walker_pParse_off), p, @ptrCast(rd([*c]const u8, item, SrcItem_zName_off)));
        }
    }
    renameWalkWith(pWalker, pSelect);
    return WRC_Continue;
}

// ─── renameTableFunc ─────────────────────────────────────────────────────────
fn renameTableFunc(context: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const db = sqlite3_context_db_handle(context);
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zDb = sqlite3_value_text(av[0]);
    const zInput = sqlite3_value_text(av[3]);
    const zOld = sqlite3_value_text(av[4]);
    const zNew = sqlite3_value_text(av[5]);
    const bTemp = sqlite3_value_int(av[6]);

    if (!(zInput != null and zOld != null and zNew != null)) return;

    var rc: c_int = SQLITE_OK;
    const bQuote: c_int = 1;
    var sCtx: RenameCtx = .{};
    const xAuth = rd(Ptr, db, sqlite3_xAuth_off);
    wr(Ptr, db, sqlite3_xAuth_off, null);

    sqlite3BtreeEnterAll(db);

    sCtx.pTab = sqlite3FindTable(db, zOld, zDb);
    var sWalker: [sizeof_Walker]u8 = std.mem.zeroes([sizeof_Walker]u8);
    const w: Ptr = @ptrCast(&sWalker);
    var sParseBuf: [sizeof_Parse]u8 align(16) = undefined;
    const sParse: Ptr = @ptrCast(&sParseBuf);
    wr(Ptr, w, Walker_pParse_off, sParse);
    wr(Ptr, w, Walker_xExprCallback_off, @constCast(@ptrCast(&renameTableExprCb)));
    wr(Ptr, w, Walker_xSelectCallback_off, @constCast(@ptrCast(&renameTableSelectCb)));
    wr(Ptr, w, Walker_u_off, &sCtx);

    rc = renameParseSql(sParse, zDb, db, zInput, bTemp);

    if (rc == SQLITE_OK) {
        const isLegacy = (dbFlags(db) & SQLITE_LegacyAlter) != 0;
        const pNewTable = rd(Ptr, sParse, Parse_pNewTable_off);
        const pNewIndex = rd(Ptr, sParse, Parse_pNewIndex_off);
        if (pNewTable != null) {
            if (isView(pNewTable)) {
                if (!isLegacy) {
                    const pSelect = rd(Ptr, pNewTable, Table_u_view_pSelect_off);
                    var sNC: [sizeof_NameContext]u8 = std.mem.zeroes([sizeof_NameContext]u8);
                    const pNC: Ptr = @ptrCast(&sNC);
                    wr(Ptr, pNC, NameContext_pParse_off, sParse);
                    const sf = rd(u32, pSelect, Select_selFlags_off);
                    wr(u32, pSelect, Select_selFlags_off, sf & ~SF_View);
                    sqlite3SelectPrep(sParse, pSelect, pNC);
                    if (rd(c_int, sParse, Parse_nErr_off) != 0) {
                        rc = rd(c_int, sParse, Parse_rc_off);
                    } else {
                        _ = sqlite3WalkSelect(w, pSelect);
                    }
                }
            } else {
                if ((!isLegacy or (dbFlags(db) & SQLITE_ForeignKeys) != 0) and !isVirtual(pNewTable)) {
                    var pFKey = rd(Ptr, pNewTable, Table_u_tab_pFKey_off);
                    while (pFKey != null) : (pFKey = rd(Ptr, pFKey, FKey_pNextFrom_off)) {
                        if (sqlite3_stricmp(rd([*c]const u8, pFKey, FKey_zTo_off), zOld) == 0) {
                            _ = renameTokenFind(sParse, &sCtx, @ptrCast(rd([*c]const u8, pFKey, FKey_zTo_off)));
                        }
                    }
                }
                if (sqlite3_stricmp(zOld, rd([*c]const u8, pNewTable, Table_zName_off)) == 0) {
                    sCtx.pTab = pNewTable;
                    if (!isLegacy) {
                        _ = sqlite3WalkExprList(w, rd(Ptr, pNewTable, Table_pCheck_off));
                    }
                    _ = renameTokenFind(sParse, &sCtx, @ptrCast(rd([*c]const u8, pNewTable, Table_zName_off)));
                }
            }
        } else if (pNewIndex != null) {
            _ = renameTokenFind(sParse, &sCtx, @ptrCast(rd([*c]const u8, pNewIndex, Index_zName_off)));
            if (!isLegacy) {
                _ = sqlite3WalkExpr(w, rd(Ptr, pNewIndex, Index_pPartIdxWhere_off));
            }
        } else {
            const pTrigger = rd(Ptr, sParse, Parse_pNewTrigger_off);
            if (sqlite3_stricmp(rd([*c]const u8, pTrigger, Trigger_table_off), zOld) == 0 and
                rd(Ptr, sCtx.pTab, Table_pSchema_off) == rd(Ptr, pTrigger, Trigger_pTabSchema_off))
            {
                _ = renameTokenFind(sParse, &sCtx, @ptrCast(rd([*c]const u8, pTrigger, Trigger_table_off)));
            }
            if (!isLegacy) {
                rc = renameResolveTrigger(sParse);
                if (rc == SQLITE_OK) {
                    renameWalkTrigger(w, pTrigger);
                    var pStep = rd(Ptr, pTrigger, Trigger_step_list_off);
                    while (pStep != null) : (pStep = rd(Ptr, pStep, TriggerStep_pNext_off)) {
                        const pStepSrc = rd(Ptr, pStep, TriggerStep_pSrc_off);
                        if (pStepSrc != null) {
                            const nSrc = rd(c_int, pStepSrc, SrcList_nSrc_off);
                            var i: c_int = 0;
                            while (i < nSrc) : (i += 1) {
                                const item = srcA(pStepSrc, @intCast(i));
                                if (sqlite3_stricmp(rd([*c]const u8, item, SrcItem_zName_off), zOld) == 0) {
                                    _ = renameTokenFind(sParse, &sCtx, @ptrCast(rd([*c]const u8, item, SrcItem_zName_off)));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (rc == SQLITE_OK) {
        rc = renameEditSql(context, &sCtx, zInput, zNew, bQuote);
    }
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_ERROR and sqlite3WritableSchema(db) != 0) {
            sqlite3_result_value(context, av[3]);
        } else if (rd([*c]const u8, sParse, Parse_zErrMsg_off) != null) {
            renameColumnParseError(context, "", av[1], av[2], sParse);
        } else {
            sqlite3_result_error_code(context, rc);
        }
    }

    renameParseCleanup(sParse);
    renameTokenFree(db, sCtx.pList);
    sqlite3BtreeLeaveAll(db);
    wr(Ptr, db, sqlite3_xAuth_off, xAuth);
}

// ─── renameQuotefix ──────────────────────────────────────────────────────────
fn renameQuotefixExprCb(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (rd(u8, pExpr, Expr_op_off) == TK_STRING and (rd(u32, pExpr, Expr_flags_off) & EP_DblQuoted) != 0) {
        _ = renameTokenFind(rd(Ptr, pWalker, Walker_pParse_off), @ptrCast(@alignCast(rd(Ptr, pWalker, Walker_u_off))), @ptrCast(pExpr));
    }
    return WRC_Continue;
}

fn renameQuotefixFunc(context: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const db = sqlite3_context_db_handle(context);
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zDb = sqlite3_value_text(av[0]);
    const zInput = sqlite3_value_text(av[1]);
    const xAuth = rd(Ptr, db, sqlite3_xAuth_off);
    wr(Ptr, db, sqlite3_xAuth_off, null);

    sqlite3BtreeEnterAll(db);

    if (zDb != null and zInput != null) {
        var sParseBuf: [sizeof_Parse]u8 align(16) = undefined;
        const sParse: Ptr = @ptrCast(&sParseBuf);
        var rc = renameParseSql(sParse, zDb, db, zInput, 0);

        if (rc == SQLITE_OK) {
            var sCtx: RenameCtx = .{};
            var sWalker: [sizeof_Walker]u8 = std.mem.zeroes([sizeof_Walker]u8);
            const w: Ptr = @ptrCast(&sWalker);
            wr(Ptr, w, Walker_pParse_off, sParse);
            wr(Ptr, w, Walker_xExprCallback_off, @constCast(@ptrCast(&renameQuotefixExprCb)));
            wr(Ptr, w, Walker_xSelectCallback_off, @constCast(@ptrCast(&renameColumnSelectCb)));
            wr(Ptr, w, Walker_u_off, &sCtx);

            const pNewTable = rd(Ptr, sParse, Parse_pNewTable_off);
            const pNewIndex = rd(Ptr, sParse, Parse_pNewIndex_off);
            if (pNewTable != null) {
                if (isView(pNewTable)) {
                    const pSelect = rd(Ptr, pNewTable, Table_u_view_pSelect_off);
                    const sf = rd(u32, pSelect, Select_selFlags_off);
                    wr(u32, pSelect, Select_selFlags_off, sf & ~SF_View);
                    wr(c_int, sParse, Parse_rc_off, SQLITE_OK);
                    sqlite3SelectPrep(sParse, pSelect, null);
                    rc = if (mallocFailed(db)) SQLITE_NOMEM else rd(c_int, sParse, Parse_rc_off);
                    if (rc == SQLITE_OK) {
                        _ = sqlite3WalkSelect(w, pSelect);
                    }
                } else {
                    _ = sqlite3WalkExprList(w, rd(Ptr, pNewTable, Table_pCheck_off));
                    const nC = @as(c_int, rd(i16, pNewTable, Table_nCol_off));
                    var i: c_int = 0;
                    while (i < nC) : (i += 1) {
                        _ = sqlite3WalkExpr(w, sqlite3ColumnExpr(pNewTable, colPtr(pNewTable, i)));
                    }
                }
            } else if (pNewIndex != null) {
                _ = sqlite3WalkExprList(w, rd(Ptr, pNewIndex, Index_aColExpr_off));
                _ = sqlite3WalkExpr(w, rd(Ptr, pNewIndex, Index_pPartIdxWhere_off));
            } else {
                rc = renameResolveTrigger(sParse);
                if (rc == SQLITE_OK) {
                    renameWalkTrigger(w, rd(Ptr, sParse, Parse_pNewTrigger_off));
                }
            }

            if (rc == SQLITE_OK) {
                rc = renameEditSql(context, &sCtx, zInput, null, 0);
            }
            renameTokenFree(db, sCtx.pList);
        }
        if (rc != SQLITE_OK) {
            if (sqlite3WritableSchema(db) != 0 and rc == SQLITE_ERROR) {
                sqlite3_result_value(context, av[1]);
            } else {
                sqlite3_result_error_code(context, rc);
            }
        }
        renameParseCleanup(sParse);
    }

    wr(Ptr, db, sqlite3_xAuth_off, xAuth);
    sqlite3BtreeLeaveAll(db);
}

// ─── renameTableTest ─────────────────────────────────────────────────────────
fn renameTableTest(context: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const db = sqlite3_context_db_handle(context);
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zDb = sqlite3_value_text(av[0]);
    const zInput = sqlite3_value_text(av[1]);
    const bTemp = sqlite3_value_int(av[4]);
    const isLegacy = (dbFlags(db) & SQLITE_LegacyAlter) != 0;
    const zWhen = sqlite3_value_text(av[5]);
    const bNoDQS = sqlite3_value_int(av[6]);
    const xAuth = rd(Ptr, db, sqlite3_xAuth_off);
    wr(Ptr, db, sqlite3_xAuth_off, null);

    if (zDb != null and zInput != null) {
        var sParseBuf: [sizeof_Parse]u8 align(16) = undefined;
        const sParse: Ptr = @ptrCast(&sParseBuf);
        const flags = dbFlags(db);
        if (bNoDQS != 0) wr(u64, db, sqlite3_flags_off, flags & ~(SQLITE_DqsDML | SQLITE_DqsDDL));
        var rc = renameParseSql(sParse, zDb, db, zInput, bTemp);
        wr(u64, db, sqlite3_flags_off, flags);
        if (rc == SQLITE_OK) {
            const pNewTable = rd(Ptr, sParse, Parse_pNewTable_off);
            const pNewTrigger = rd(Ptr, sParse, Parse_pNewTrigger_off);
            if (!isLegacy and pNewTable != null and isView(pNewTable)) {
                var sNC: [sizeof_NameContext]u8 = std.mem.zeroes([sizeof_NameContext]u8);
                const pNC: Ptr = @ptrCast(&sNC);
                wr(Ptr, pNC, NameContext_pParse_off, sParse);
                sqlite3SelectPrep(sParse, rd(Ptr, pNewTable, Table_u_view_pSelect_off), pNC);
                if (rd(c_int, sParse, Parse_nErr_off) != 0) rc = rd(c_int, sParse, Parse_rc_off);
            } else if (pNewTrigger != null) {
                if (!isLegacy) {
                    rc = renameResolveTrigger(sParse);
                }
                if (rc == SQLITE_OK) {
                    const iA = sqlite3SchemaToIndex(db, rd(Ptr, pNewTrigger, Trigger_pTabSchema_off));
                    const iB = sqlite3FindDbName(db, zDb);
                    if (iA == iB) {
                        sqlite3_result_int(context, 1);
                    }
                }
            }
        }

        if (rc != SQLITE_OK and zWhen != null and sqlite3WritableSchema(db) == 0) {
            renameColumnParseError(context, zWhen, av[2], av[3], sParse);
        }
        renameParseCleanup(sParse);
    }

    wr(Ptr, db, sqlite3_xAuth_off, xAuth);
}

// ─── getConstraintToken / getWhitespace / getConstraint ──────────────────────
fn getConstraintToken(z: [*c]const u8, piToken: *c_int) c_int {
    var iOff: c_int = 0;
    var t: c_int = 0;
    while (true) {
        iOff += @intCast(sqlite3GetToken(z + @as(usize, @intCast(iOff)), &t));
        if (!(t == TK_SPACE or t == TK_COMMENT)) break;
    }
    piToken.* = t;
    if (t == TK_LP) {
        var nNest: c_int = 1;
        while (nNest > 0) {
            iOff += @intCast(sqlite3GetToken(z + @as(usize, @intCast(iOff)), &t));
            if (t == TK_LP) {
                nNest += 1;
            } else if (t == TK_RP) {
                t = TK_LP;
                nNest -= 1;
            } else if (t == TK_ILLEGAL) {
                break;
            }
        }
    }
    piToken.* = t;
    return iOff;
}

fn getWhitespace(z: [*c]const u8) c_int {
    var nRet: c_int = 0;
    while (true) {
        var t: c_int = 0;
        const n: c_int = @intCast(sqlite3GetToken(z + @as(usize, @intCast(nRet)), &t));
        if (t != TK_SPACE and t != TK_COMMENT) break;
        nRet += n;
    }
    return nRet;
}

fn getConstraint(z: [*c]const u8) c_int {
    var iOff: c_int = 0;
    var t: c_int = 0;
    while (true) {
        const n = getConstraintToken(z + @as(usize, @intCast(iOff)), &t);
        if (t == TK_CONSTRAINT or t == TK_PRIMARY or t == TK_NOT or t == TK_UNIQUE or
            t == TK_CHECK or t == TK_DEFAULT or t == TK_COLLATE or t == TK_REFERENCES or
            t == TK_FOREIGN or t == TK_RP or t == TK_COMMA or t == TK_ILLEGAL or
            t == TK_AS or t == TK_GENERATED)
        {
            break;
        }
        iOff += n;
    }
    return iOff;
}

// ─── dropColumnFunc ──────────────────────────────────────────────────────────
fn dropColumnFunc(context: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const db = sqlite3_context_db_handle(context);
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const iSchema = sqlite3_value_int(av[0]);
    const zSql = sqlite3_value_text(av[1]);
    const iCol = sqlite3_value_int(av[2]);
    const zDb = dbName(db, iSchema);
    var rc: c_int = SQLITE_OK;
    var zNew: [*c]u8 = null;
    const xAuth = rd(Ptr, db, sqlite3_xAuth_off);
    wr(Ptr, db, sqlite3_xAuth_off, null);

    var sParseBuf: [sizeof_Parse]u8 align(16) = undefined;
    const sParse: Ptr = @ptrCast(&sParseBuf);
    rc = renameParseSql(sParse, zDb, db, zSql, @intFromBool(iSchema == 1));
    blk: {
        if (rc != SQLITE_OK) break :blk;
        const pTab = rd(Ptr, sParse, Parse_pNewTable_off);
        if (pTab == null or rd(i16, pTab, Table_nCol_off) == 1 or iCol >= @as(c_int, rd(i16, pTab, Table_nCol_off))) {
            rc = SQLITE_CORRUPT;
            break :blk;
        }

        var pCol: ?*RenameToken = null;
        var zEnd: [*c]const u8 = null;
        const nCol = @as(c_int, rd(i16, pTab, Table_nCol_off));
        if (iCol < nCol - 1) {
            pCol = renameTokenFind(sParse, null, @ptrCast(rd([*c]const u8, colPtr(pTab, iCol), Column_zCnName_off)));
            const pEnd = renameTokenFind(sParse, null, @ptrCast(rd([*c]const u8, colPtr(pTab, iCol + 1), Column_zCnName_off)));
            zEnd = pEnd.?.t_z;
        } else {
            var eTok: c_int = 0;
            pCol = renameTokenFind(sParse, null, @ptrCast(rd([*c]const u8, colPtr(pTab, iCol - 1), Column_zCnName_off)));
            while (true) {
                pCol.?.t_z += @as(usize, @intCast(getConstraintToken(pCol.?.t_z, &eTok)));
                if (eTok == TK_COMMA) break;
            }
            pCol.?.t_z -= 1;
            const addColOffset = rd(c_int, pTab, Table_u_tab_addColOffset_off);
            zEnd = zSql + @as(usize, @intCast(addColOffset));
        }

        const prefixLen: c_int = @intCast(@intFromPtr(pCol.?.t_z) - @intFromPtr(zSql));
        zNew = sqlite3MPrintf(db, "%.*s%s", prefixLen, zSql, zEnd);
        sqlite3_result_text(context, zNew, -1, SQLITE_TRANSIENT);
        sqlite3_free(zNew);
    }

    renameParseCleanup(sParse);
    wr(Ptr, db, sqlite3_xAuth_off, xAuth);
    if (rc != SQLITE_OK) {
        sqlite3_result_error_code(context, rc);
    }
}

// ─── sqlite3AlterDropColumn ──────────────────────────────────────────────────
export fn sqlite3AlterDropColumn(pParse: Ptr, pSrc: Ptr, pName: Ptr) void {
    const db = dbOf(pParse);
    var zCol: [*c]u8 = null;

    if (mallocFailed(db)) {
        sqlite3SrcListDelete(db, pSrc);
        return;
    }
    const pTab = sqlite3LocateTableItem(pParse, 0, srcA(pSrc, 0));
    defer {
        sqlite3DbFree(db, zCol);
        sqlite3SrcListDelete(db, pSrc);
    }
    if (pTab == null) return;

    if (isAlterableTable(pParse, pTab) != SQLITE_OK) return;
    if (isRealTable(pParse, pTab, 1) != SQLITE_OK) return;

    zCol = sqlite3NameFromToken(db, pName);
    if (zCol == null) return;
    const iCol = sqlite3ColumnIndex(pTab, zCol);
    if (iCol < 0) {
        sqlite3ErrorMsg(pParse, "no such column: \"%T\"", pName);
        return;
    }

    const colFlags = rd(u16, colPtr(pTab, iCol), Column_colFlags_off);
    if (colFlags & (COLFLAG_PRIMKEY | COLFLAG_UNIQUE) != 0) {
        const kind: [*c]const u8 = if (colFlags & COLFLAG_PRIMKEY != 0) "PRIMARY KEY" else "UNIQUE";
        sqlite3ErrorMsg(pParse, "cannot drop %s column: \"%s\"", kind, zCol);
        return;
    }
    if (rd(i16, pTab, Table_nCol_off) <= 1) {
        sqlite3ErrorMsg(pParse, "cannot drop column \"%s\": no other columns exist", zCol);
        return;
    }

    const iDb = sqlite3SchemaToIndex(db, rd(Ptr, pTab, Table_pSchema_off));
    const zDb = dbName(db, iDb);
    const zTabName = rd([*c]const u8, pTab, Table_zName_off);
    if (sqlite3AuthCheck(pParse, SQLITE_ALTER_TABLE, zDb, zTabName, zCol) != 0) {
        return;
    }
    renameTestSchema(pParse, zDb, @intFromBool(iDb == 1), "", 0);
    renameFixQuotes(pParse, zDb, @intFromBool(iDb == 1));
    sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "sql = sqlite_drop_column(%d, sql, %d) " ++
        "WHERE (type=='table' AND tbl_name=%Q COLLATE nocase)", zDb, iDb, iCol, zTabName);

    renameReloadSchema(pParse, iDb, INITFLAG_AlterDrop);
    renameTestSchema(pParse, zDb, @intFromBool(iDb == 1), "after drop column", 1);

    if (rd(c_int, pParse, Parse_nErr_off) == 0 and (colFlags & COLFLAG_VIRTUAL) == 0) {
        var pPk: Ptr = null;
        var nField: c_int = 0;
        const v = sqlite3GetVdbe(pParse);
        const iCur = rd(c_int, pParse, Parse_nTab_off);
        wr(c_int, pParse, Parse_nTab_off, iCur + 1);
        sqlite3OpenTable(pParse, iCur, iDb, pTab, OP_OpenWrite);
        const addr = sqlite3VdbeAddOp1(v, OP_Rewind, iCur);
        const reg = rd(c_int, pParse, Parse_nMem_off) + 1;
        wr(c_int, pParse, Parse_nMem_off, reg);
        const nCol = @as(c_int, rd(i16, pTab, Table_nCol_off));
        if (hasRowid(pTab)) {
            _ = sqlite3VdbeAddOp2(v, OP_Rowid, iCur, reg);
            wr(c_int, pParse, Parse_nMem_off, rd(c_int, pParse, Parse_nMem_off) + nCol);
        } else {
            pPk = sqlite3PrimaryKeyIndex(pTab);
            const nColumn = rd(u16, pPk, off("Index_nColumn", 96));
            wr(c_int, pParse, Parse_nMem_off, rd(c_int, pParse, Parse_nMem_off) + @as(c_int, nColumn));
            const nKeyCol = rd(u16, pPk, Index_nKeyCol_off);
            var i: c_int = 0;
            while (i < @as(c_int, nKeyCol)) : (i += 1) {
                _ = sqlite3VdbeAddOp3(v, OP_Column, iCur, i, reg + i + 1);
            }
            nField = @intCast(nKeyCol);
        }
        const regRec = rd(c_int, pParse, Parse_nMem_off) + 1;
        wr(c_int, pParse, Parse_nMem_off, regRec);
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const pColI = colPtr(pTab, i);
            if (i != iCol and (rd(u16, pColI, Column_colFlags_off) & COLFLAG_VIRTUAL) == 0) {
                var regOut: c_int = undefined;
                if (pPk != null) {
                    const iPos = sqlite3TableColumnToIndex(pPk, i);
                    const iColPos = sqlite3TableColumnToIndex(pPk, iCol);
                    const nKeyCol = @as(c_int, rd(u16, pPk, Index_nKeyCol_off));
                    if (iPos < nKeyCol) continue;
                    regOut = reg + 1 + iPos - @intFromBool(iPos > iColPos);
                } else {
                    regOut = reg + 1 + nField;
                }
                if (i == @as(c_int, rd(i16, pTab, Table_iPKey_off))) {
                    _ = sqlite3VdbeAddOp2(v, OP_Null, 0, regOut);
                } else {
                    const aff = rd(u8, pColI, Column_affinity_off);
                    if (aff == SQLITE_AFF_REAL) {
                        wr(u8, pColI, Column_affinity_off, SQLITE_AFF_NUMERIC);
                    }
                    sqlite3ExprCodeGetColumnOfTable(v, pTab, iCur, i, regOut);
                    wr(u8, pColI, Column_affinity_off, aff);
                }
                nField += 1;
            }
        }
        if (nField == 0) {
            wr(c_int, pParse, Parse_nMem_off, rd(c_int, pParse, Parse_nMem_off) + 1);
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, reg + 1);
            nField = 1;
        }
        _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, reg + 1, nField, regRec);
        if (pPk != null) {
            _ = sqlite3VdbeAddOp4Int(v, OP_IdxInsert, iCur, regRec, reg + 1, @as(c_int, rd(u16, pPk, Index_nKeyCol_off)));
        } else {
            _ = sqlite3VdbeAddOp3(v, OP_Insert, iCur, regRec, reg);
        }
        sqlite3VdbeChangeP5(v, OPFLAG_SAVEPOSITION);
        _ = sqlite3VdbeAddOp2(v, OP_Next, iCur, addr + 1);
        sqlite3VdbeJumpHere(v, addr);
    }
}

// ─── constraint-edit SQL functions ───────────────────────────────────────────
fn quotedCompare(ctx: Ptr, t: c_int, zQuote: [*c]const u8, nQuote: c_int, zCmp: [*c]const u8, pRes: *c_int) c_int {
    if (t == TK_ILLEGAL) {
        pRes.* = 1;
        return SQLITE_OK;
    }
    const zCopy: [*c]u8 = @ptrCast(sqlite3MallocZero(@as(u64, @intCast(nQuote + 1))));
    if (zCopy == null) {
        sqlite3_result_error_nomem(ctx);
        return SQLITE_NOMEM;
    }
    @memcpy(zCopy[0..@intCast(nQuote)], zQuote[0..@intCast(nQuote)]);
    sqlite3Dequote(zCopy);
    pRes.* = sqlite3_stricmp(zCopy, zCmp);
    sqlite3_free(zCopy);
    return SQLITE_OK;
}

fn skipCreateTable(ctx: Ptr, zSql: [*c]const u8, piOff: *c_int) c_int {
    var iOff: c_int = 0;
    if (zSql == null) return SQLITE_ERROR;
    while (true) {
        var t: c_int = 0;
        iOff += @intCast(sqlite3GetToken(zSql + @as(usize, @intCast(iOff)), &t));
        if (t == TK_LP) break;
        if (t == TK_ILLEGAL) {
            sqlite3_result_error_code(ctx, SQLITE_CORRUPT);
            return SQLITE_ERROR;
        }
    }
    piOff.* = iOff;
    return SQLITE_OK;
}

fn dropConstraintFunc(ctx: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zSql = sqlite3_value_text(av[0]);
    var zCons: [*c]const u8 = null;
    var iNotNull: c_int = -1;
    var iOff: c_int = 0;
    var iStart: c_int = 0;
    var iEnd: c_int = 0;
    var t: c_int = 0;

    if (zSql == null) return;
    if (skipCreateTable(ctx, zSql, &iOff) != 0) return;

    if (sqlite3_value_type(av[1]) == SQLITE_INTEGER) {
        iNotNull = sqlite3_value_int(av[1]);
    } else {
        zCons = sqlite3_value_text(av[1]);
    }

    var ii: c_int = 0;
    while (iEnd == 0) : (ii += 1) {
        while (true) {
            iStart = iOff;
            iOff += getConstraintToken(zSql + @as(usize, @intCast(iOff)), &t);
            if (t == TK_CONSTRAINT and (zCons != null or iNotNull == ii)) {
                var nTok: c_int = 0;
                var cmp: c_int = 1;
                iOff += getWhitespace(zSql + @as(usize, @intCast(iOff)));
                nTok = getConstraintToken(zSql + @as(usize, @intCast(iOff)), &t);
                if (zCons != null) {
                    if (quotedCompare(ctx, t, zSql + @as(usize, @intCast(iOff)), nTok, zCons, &cmp) != 0) return;
                }
                iOff += nTok;
                nTok = getConstraintToken(zSql + @as(usize, @intCast(iOff)), &t);
                if (t == TK_CONSTRAINT or t == TK_DEFAULT or t == TK_COLLATE or
                    t == TK_COMMA or t == TK_RP or t == TK_GENERATED or t == TK_AS)
                {
                    t = TK_CHECK;
                } else {
                    iOff += nTok;
                    iOff += getConstraint(zSql + @as(usize, @intCast(iOff)));
                }
                if (cmp == 0 or (iNotNull >= 0 and t == TK_NOT)) {
                    if (t != TK_NOT and t != TK_CHECK) {
                        errorMPrintf(ctx, "constraint may not be dropped: %s", zCons);
                        return;
                    }
                    iEnd = iOff;
                    break;
                }
            } else if (t == TK_NOT and iNotNull == ii) {
                iEnd = iOff + getConstraint(zSql + @as(usize, @intCast(iOff)));
                break;
            } else if (t == TK_RP or t == TK_ILLEGAL) {
                iEnd = -1;
                break;
            } else if (t == TK_COMMA) {
                break;
            }
        }
    }

    if (iEnd <= 0) {
        if (zCons != null) {
            errorMPrintf(ctx, "no such constraint: %s", zCons);
        } else {
            sqlite3_result_text(ctx, zSql, -1, SQLITE_TRANSIENT);
        }
    } else {
        var zSpace: [*c]const u8 = " ";
        iEnd += getWhitespace(zSql + @as(usize, @intCast(iEnd)));
        _ = sqlite3GetToken(zSql + @as(usize, @intCast(iEnd)), &t);
        if (t == TK_RP or t == TK_COMMA) {
            zSpace = "";
            if (zSql[@as(usize, @intCast(iStart - 1))] == ',') iStart -= 1;
        }
        const db = sqlite3_context_db_handle(ctx);
        const zNew = sqlite3MPrintf(db, "%.*s%s%s", iStart, zSql, zSpace, zSql + @as(usize, @intCast(iEnd)));
        sqlite3_result_text(ctx, zNew, -1, SQLITE_DYNAMIC);
    }
}

fn addConstraintFunc(ctx: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zSql = sqlite3_value_text(av[0]);
    const zCons = sqlite3_value_text(av[1]);
    const iCol = sqlite3_value_int(av[2]);
    var iOff: c_int = 0;
    var t: c_int = 0;

    if (skipCreateTable(ctx, zSql, &iOff) != 0) return;

    var ii: c_int = 0;
    while (ii <= iCol or (iCol < 0 and t != TK_RP)) : (ii += 1) {
        iOff += getConstraintToken(zSql + @as(usize, @intCast(iOff)), &t);
        while (true) {
            const nTok = getConstraintToken(zSql + @as(usize, @intCast(iOff)), &t);
            if (t == TK_COMMA or t == TK_RP) break;
            if (t == TK_ILLEGAL) {
                sqlite3_result_error_code(ctx, SQLITE_CORRUPT);
                return;
            }
            iOff += nTok;
        }
    }

    iOff += getWhitespace(zSql + @as(usize, @intCast(iOff)));

    const pNew = sqlite3_str_new(sqlite3_context_db_handle(ctx));
    sqlite3_str_append(pNew, zSql, iOff);
    if (iCol < 0) sqlite3_str_append(pNew, ",", 1);
    sqlite3_str_appendf(pNew, " %s%s", zCons, zSql + @as(usize, @intCast(iOff)));
    sqlite3_result_str(ctx, pNew, SQLITE_FINISH);
}

// ─── alterFindCol / alterFindTable ───────────────────────────────────────────
fn alterFindCol(pParse: Ptr, pTab: Ptr, pCol: Ptr, piCol: *c_int) c_int {
    const db = dbOf(pParse);
    const zName = sqlite3NameFromToken(db, pCol);
    var rc: c_int = SQLITE_NOMEM;
    var iCol: c_int = -1;

    if (zName != null) {
        iCol = sqlite3ColumnIndex(pTab, zName);
        if (iCol < 0) {
            sqlite3ErrorMsg(pParse, "no such column: %s", zName);
            rc = SQLITE_ERROR;
        } else {
            rc = SQLITE_OK;
        }
    }

    if (rc == SQLITE_OK) {
        const zDb = dbName(db, sqlite3SchemaToIndex(db, rd(Ptr, pTab, Table_pSchema_off)));
        const zCol = rd([*c]const u8, colPtr(pTab, iCol), Column_zCnName_off);
        _ = sqlite3AuthCheck(pParse, SQLITE_ALTER_TABLE, zDb, rd([*c]const u8, pTab, Table_zName_off), zCol);
    }

    sqlite3DbFree(db, zName);
    piCol.* = iCol;
    return rc;
}

fn alterFindTable(pParse: Ptr, pSrc: Ptr, piDb: *c_int, pzDb: *[*c]const u8, bAuth: c_int) Ptr {
    const db = dbOf(pParse);
    var pTab = sqlite3LocateTableItem(pParse, 0, srcA(pSrc, 0));
    if (pTab != null) {
        const iDb = sqlite3SchemaToIndex(db, rd(Ptr, pTab, Table_pSchema_off));
        pzDb.* = dbName(db, iDb);
        piDb.* = iDb;
        if (isRealTable(pParse, pTab, 2) != SQLITE_OK or isAlterableTable(pParse, pTab) != SQLITE_OK) {
            pTab = null;
        }
    }
    if (pTab != null and bAuth != 0) {
        if (sqlite3AuthCheck(pParse, SQLITE_ALTER_TABLE, pzDb.*, rd([*c]const u8, pTab, Table_zName_off), null) != 0) {
            pTab = null;
        }
    }
    sqlite3SrcListDelete(db, pSrc);
    return pTab;
}

// ─── sqlite3AlterDropConstraint ──────────────────────────────────────────────
export fn sqlite3AlterDropConstraint(pParse: Ptr, pSrc: Ptr, pCons: Ptr, pCol: Ptr) void {
    const db = dbOf(pParse);
    var iDb: c_int = 0;
    var zDb: [*c]const u8 = null;
    var zArg: [*c]u8 = null;

    const pTab = alterFindTable(pParse, pSrc, &iDb, &zDb, @intFromBool(pCons != null));
    if (pTab == null) return;

    if (pCons != null) {
        const z = sqlite3NameFromToken(db, pCons);
        zArg = sqlite3MPrintf(db, "%Q", z);
        sqlite3DbFree(db, z);
    } else {
        var iCol: c_int = 0;
        if (alterFindCol(pParse, pTab, pCol, &iCol) != 0) return;
        zArg = sqlite3MPrintf(db, "%d", iCol);
    }

    sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "sql = sqlite_drop_constraint(sql, %s) " ++
        "WHERE type='table' AND tbl_name=%Q COLLATE nocase", zDb, zArg, rd([*c]const u8, pTab, Table_zName_off));
    sqlite3DbFree(db, zArg);

    renameReloadSchema(pParse, iDb, INITFLAG_AlterDropCons);
}

fn failConstraintFunc(ctx: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zText = sqlite3_value_text(av[0]);
    const err = sqlite3_value_int(av[1]);
    sqlite3_result_error(ctx, zText, -1);
    sqlite3_result_error_code(ctx, err);
}

fn alterRtrimConstraint(db: Ptr, pCons: [*c]const u8, nCons: c_int) c_int {
    const zTmp: [*c]u8 = sqlite3MPrintf(db, "%.*s", nCons, pCons);
    var iOff: c_int = 0;
    var iEnd: c_int = 0;
    if (zTmp == null) return 0;
    while (true) {
        var t: c_int = 0;
        const nToken: c_int = @intCast(sqlite3GetToken(zTmp + @as(usize, @intCast(iOff)), &t));
        if (t == TK_ILLEGAL) break;
        if (t != TK_SPACE and (t != TK_COMMENT or zTmp[@as(usize, @intCast(iOff))] != '-')) {
            iEnd = iOff + nToken;
        }
        iOff += nToken;
    }
    sqlite3DbFree(db, zTmp);
    return iEnd;
}

// ─── sqlite3AlterSetNotNull ──────────────────────────────────────────────────
export fn sqlite3AlterSetNotNull(pParse: Ptr, pSrc: Ptr, pCol: Ptr, pFirst: Ptr) void {
    var iCol: c_int = 0;
    var iDb: c_int = 0;
    var zDb: [*c]const u8 = null;

    const pTab = alterFindTable(pParse, pSrc, &iDb, &zDb, 0);
    if (pTab == null) return;

    if (alterFindCol(pParse, pTab, pCol, &iCol) != 0) return;

    const pCons = rd([*c]const u8, pFirst, Token_z_off);
    const sLastTokenZ = rd([*c]const u8, @as(Ptr, @ptrCast(base(pParse) + Parse_sLastToken_off)), Token_z_off);
    const nCons = alterRtrimConstraint(dbOf(pParse), pCons, @intCast(@intFromPtr(sLastTokenZ) - @intFromPtr(pCons)));

    const pColN = rd(c_uint, pCol, Token_n_off);
    const pColZ = rd([*c]const u8, pCol, Token_z_off);
    sqlite3NestedParse(pParse, "SELECT sqlite_fail('constraint failed', %d) " ++
        "FROM %Q.%Q AS x WHERE x.%.*s IS NULL", SQLITE_CONSTRAINT, zDb, rd([*c]const u8, pTab, Table_zName_off), @as(c_int, @intCast(pColN)), pColZ);

    sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "sql = sqlite_add_constraint(sqlite_drop_constraint(sql, %d), %.*Q, %d) " ++
        "WHERE type='table' AND tbl_name=%Q COLLATE nocase", zDb, iCol, nCons, pCons, iCol, rd([*c]const u8, pTab, Table_zName_off));

    renameReloadSchema(pParse, iDb, INITFLAG_AlterDropCons);
}

fn findConstraintFunc(ctx: Ptr, NotUsed: c_int, argv: Ptr) callconv(.c) void {
    _ = NotUsed;
    const av: [*c]Ptr = @ptrCast(@alignCast(argv));
    const zSql = sqlite3_value_text(av[0]);
    const zCons = sqlite3_value_text(av[1]);
    var iOff: c_int = 0;
    var t: c_int = 0;

    if (zSql == null or zCons == null) return;
    while (t != TK_LP and t != TK_ILLEGAL) {
        iOff += @intCast(sqlite3GetToken(zSql + @as(usize, @intCast(iOff)), &t));
    }

    while (true) {
        iOff += getConstraintToken(zSql + @as(usize, @intCast(iOff)), &t);
        if (t == TK_CONSTRAINT) {
            var cmp: c_int = 0;
            iOff += getWhitespace(zSql + @as(usize, @intCast(iOff)));
            const nTok = getConstraintToken(zSql + @as(usize, @intCast(iOff)), &t);
            if (quotedCompare(ctx, t, zSql + @as(usize, @intCast(iOff)), nTok, zCons, &cmp) != 0) return;
            if (cmp == 0) {
                sqlite3_result_int(ctx, 1);
                return;
            }
        } else if (t == TK_ILLEGAL) {
            break;
        }
    }
    sqlite3_result_int(ctx, 0);
}

// ─── sqlite3AlterAddConstraint ───────────────────────────────────────────────
export fn sqlite3AlterAddConstraint(pParse: Ptr, pSrc: Ptr, pFirst: Ptr, pName: Ptr, zExpr: [*c]const u8, nExpr: c_int, pExpr: Ptr) void {
    var iDb: c_int = 0;
    var zDb: [*c]const u8 = null;

    const pTab = alterFindTable(pParse, pSrc, &iDb, &zDb, 1);
    if (pTab == null) {
        sqlite3ExprDelete(dbOf(pParse), pExpr);
        return;
    }

    const rc = sqlite3ResolveSelfReference(pParse, pTab, NC_IsCheck, pExpr, null);
    sqlite3ExprDelete(dbOf(pParse), pExpr);
    if (rc != 0) return;

    if (pName != null) {
        const zName = sqlite3NameFromToken(dbOf(pParse), pName);
        sqlite3NestedParse(pParse, "SELECT sqlite_fail('constraint %q already exists', %d) " ++
            "FROM \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " " ++
            "WHERE type='table' AND tbl_name=%Q COLLATE nocase " ++
            "AND sqlite_find_constraint(sql, %Q)", zName, SQLITE_ERROR, zDb, rd([*c]const u8, pTab, Table_zName_off), zName);
        sqlite3DbFree(dbOf(pParse), zName);
    }

    sqlite3NestedParse(pParse, "SELECT sqlite_fail('constraint failed', %d) " ++
        "FROM %Q.%Q WHERE (%.*s) IS NOT TRUE", SQLITE_CONSTRAINT, zDb, rd([*c]const u8, pTab, Table_zName_off), nExpr, zExpr);

    const pCons = rd([*c]const u8, pFirst, Token_z_off);
    const sLastTokenZ = rd([*c]const u8, @as(Ptr, @ptrCast(base(pParse) + Parse_sLastToken_off)), Token_z_off);
    const nCons = alterRtrimConstraint(dbOf(pParse), pCons, @intCast(@intFromPtr(sLastTokenZ) - @intFromPtr(pCons)));

    sqlite3NestedParse(pParse, "UPDATE \"%w\"." ++ LEGACY_SCHEMA_TABLE ++ " SET " ++
        "sql = sqlite_add_constraint(sql, %.*Q, -1) " ++
        "WHERE type='table' AND tbl_name=%Q COLLATE nocase", zDb, nCons, pCons, rd([*c]const u8, pTab, Table_zName_off));

    renameReloadSchema(pParse, iDb, INITFLAG_AlterDropCons);
}

// ─── sqlite3AlterFunctions ───────────────────────────────────────────────────
fn mkInternal(comptime zName: [*c]const u8, comptime nArg: i16, comptime xFunc: *const fn (Ptr, c_int, Ptr) callconv(.c) void) FuncDef {
    return .{
        .nArg = nArg,
        .funcFlags = FUNCFLAG_INTERNAL,
        .pUserData = null,
        .pNext = null,
        .xSFunc = xFunc,
        .xFinalize = null,
        .xValue = null,
        .xInverse = null,
        .zName = zName,
        .u = null,
    };
}

var aAlterTableFuncs = [_]FuncDef{
    mkInternal("sqlite_rename_column", 9, &renameColumnFunc),
    mkInternal("sqlite_rename_table", 7, &renameTableFunc),
    mkInternal("sqlite_rename_test", 7, &renameTableTest),
    mkInternal("sqlite_drop_column", 3, &dropColumnFunc),
    mkInternal("sqlite_rename_quotefix", 2, &renameQuotefixFunc),
    mkInternal("sqlite_drop_constraint", 2, &dropConstraintFunc),
    mkInternal("sqlite_fail", 2, &failConstraintFunc),
    mkInternal("sqlite_add_constraint", 3, &addConstraintFunc),
    mkInternal("sqlite_find_constraint", 2, &findConstraintFunc),
};

export fn sqlite3AlterFunctions() void {
    sqlite3InsertBuiltinFuncs(&aAlterTableFuncs, aAlterTableFuncs.len);
}
