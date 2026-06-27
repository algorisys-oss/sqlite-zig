//! Zig port of SQLite's src/build.c — schema/DDL code generator.
//!
//! CREATE/DROP TABLE/INDEX/VIEW, column/constraint construction, the schema
//! cookie + nested-parse machinery, SrcList/IdList/With builders, transaction
//! and savepoint statements, REINDEX, KeyInfo-of-index, and the constraint
//! halt helpers.  This is heavily-coupled codegen: it emits VDBE bytecode by
//! calling helpers that remain C (or are already-ported Zig exporting the C
//! ABI).  It faithfully reproduces build.c's own functions; static helpers
//! become private Zig fns.
//!
//! Config assumptions (true in BOTH the production library and the --dev
//! testfixture): SQLITE_OMIT_* all OFF (SHARED_CACHE, VIRTUALTABLE, VIEW,
//! GENERATED_COLUMNS, AUTHORIZATION, AUTOINCREMENT, CHECK, FOREIGN_KEY,
//! AUTOVACUUM, REINDEX, CTE, ALTERTABLE, TRIGGER all present).
//! SQLITE_MAX_ATTACHED defaults to 10 (yDbMask is a u32, not an array).
//! SQLITE_DEBUG markExprListImmutable is a no-op in production but real in tf;
//! handled via config.sqlite_debug.

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
inline fn fieldPtr(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return @ptrCast(base(p) + offs);
}
inline fn rdp(p: ?*anyopaque, offs: usize) ?*anyopaque {
    return rd(?*anyopaque, p, offs);
}

fn off(comptime name: []const u8, comptime fallback: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else fallback;
}

// ─── offsets ──────────────────────────────────────────────────────────────────
const Parse_db = off("Parse_db", 0);
const Parse_pVdbe = off("Parse_pVdbe", 16);
const Parse_rc = off("Parse_rc", 24);
const Parse_eParseMode = off("Parse_eParseMode", 300);
const Parse_nested = off("Parse_nested", 30);
const Parse_isMultiWrite = off("Parse_isMultiWrite", 28);
const Parse_nErr = off("Parse_nErr", 52);
const Parse_nTab = off("Parse_nTab", 56);
const Parse_nMem = off("Parse_nMem", 60);
const Parse_nVar = off("Parse_nVar", 290);
const Parse_nSelect = off("Parse_nSelect", 72);
const Parse_explain = off("Parse_explain", 36);
const Parse_prepFlags = off("Parse_prepFlags", 34);
const Parse_pToplevel = off("Parse_pToplevel", 136);
const Parse_pNewTable = off("Parse_pNewTable", 152);
const Parse_pNewIndex = off("Parse_pNewIndex", 168);
const Parse_pNewTrigger = off("Parse_pNewTrigger", 360);
const Parse_pConstExpr = off("Parse_pConstExpr", 160);
const Parse_pAinc = off("Parse_pAinc", 264);
const Parse_cookieMask = off("Parse_cookieMask", 116);
const Parse_writeMask = off("Parse_writeMask", 112);
const Parse_nTableLock = off("Parse_nTableLock", 124);
const Parse_aTableLock = off("Parse_aTableLock", 128);
const Parse_nVtabLock = off("Parse_nVtabLock", 132);
const Parse_apVtabLock = off("Parse_apVtabLock", 256);
const Parse_iPkSortOrder = off("Parse_iPkSortOrder", 291);
const Parse_iSelfTab = off("Parse_iSelfTab", 64);
const Parse_sNameToken = off("Parse_sNameToken", 208);
const Parse_sLastToken = off("Parse_sLastToken", 280);
const Parse_u1 = off("Parse_u1", 232);
const Parse_u1_cr_addrCrTab = off("Parse_u1_cr_addrCrTab", 232);
const Parse_u1_cr_regRowid = off("Parse_u1_cr_regRowid", 236);
const Parse_u1_cr_regRoot = off("Parse_u1_cr_regRoot", 240);
const Parse_u1_cr_constraintName = off("Parse_u1_cr_constraintName", 244);
const Parse_u1_d_pReturning = off("Parse_u1_d_pReturning", 232);
const sizeof_Parse = off("sizeof_Parse", 416);
const PARSE_RECURSE_SZ = off("PARSE_RECURSE_SZ", 280);
const PARSE_TAIL_SZ: usize = sizeof_Parse - PARSE_RECURSE_SZ;

// Parse bft bitfield group: byte 39 prod / 42 tf.
const Parse_bft_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_disableTriggers: u8 = 0x01;
const BFT_mayAbort: u8 = 0x02;
const BFT_bReturning: u8 = 0x08;
const BFT_okConstFactor: u8 = 0x80;
// byte+1: checkSchema=0x01, usesAinc=0x02
const BFT_checkSchema: u8 = 0x01;
const BFT_usesAinc: u8 = 0x02;
// u8 (real byte) Parse fields
const Parse_ifNotExists = off("Parse_ifNotExists", 41);
const Parse_isCreate = off("Parse_isCreate", 42);

// sqlite3
const sqlite3_aDb = off("sqlite3_aDb", 32);
const sqlite3_nDb = off("sqlite3_nDb", 40);
const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103);
const sqlite3_flags = off("sqlite3_flags", 48);
const sqlite3_mDbFlags = off("sqlite3_mDbFlags", 44);
const sqlite3_aLimit = off("sqlite3_aLimit", 136);
const sqlite3_init = off("sqlite3_init", 192);
const sqlite3_init_newTnum = off("sqlite3_init_newTnum", 192);
const sqlite3_init_iDb = off("sqlite3_init_iDb", 196);
const sqlite3_initBusy = off("sqlite3_initBusy", 197);
const sqlite3_init_bitbyte = off("sqlite3_init_bitbyte", 198);
const sqlite3_init_azInit = off("sqlite3_init_azInit", 200);
const sqlite3_aModule = off("sqlite3_aModule", 624);
const sqlite3_nextPagesize = off("sqlite3_nextPagesize", 272);
const sqlite3_pVfs = off("sqlite3_pVfs", 8);
const sqlite3_suppressErr = off("sqlite3_suppressErr", 154);
const sqlite3_nSchemaLock = off("sqlite3_nSchemaLock", 158);
const sqlite3_xAuth = off("sqlite3_xAuth", 528);
const sqlite3_aDbStatic = off("sqlite3_aDbStatic", 472);
const sqlite3_pVtabCtx = off("sqlite3_pVtabCtx", 568);
const sqlite3_nVdbeExec = off("sqlite3_nVdbeExec", 220);
const sqlite3_lookaside_bDisable = off("sqlite3_lookaside_bDisable", 432);
const sqlite3_lookaside_sz = off("sqlite3_lookaside_sz", 436);

// Db (sizeof 32)
const sizeof_Db = off("sizeof_Db", 32);
const sizeof_Table = off("sizeof_Table", 104);
const Db_zDbSName = off("Db_zDbSName", 0);
const Db_pBt = off("Db_pBt", 16);
const Db_pSchema = off("Db_pSchema", 24);
const Db_safety_level = off("Db_safety_level", 8);

// Schema
const Schema_schema_cookie = off("Schema_schema_cookie", 96);
const Schema_iGeneration = off("Schema_iGeneration", 100);
const Schema_tblHash = off("Schema_tblHash", 8);
const Schema_idxHash = off("Schema_idxHash", 40);
const Schema_trigHash = off("Schema_trigHash", 72);
const Schema_fkeyHash = off("Schema_fkeyHash", 104);
const Schema_pSeqTab = off("Schema_pSeqTab", 136);
const Schema_file_format = off("Schema_file_format", 112);
const Schema_schemaFlags = off("Schema_schemaFlags", 116);

// Table
const Table_zName = off("Table_zName", 0);
const Table_aCol = off("Table_aCol", 8);
const Table_pIndex = off("Table_pIndex", 16);
const Table_zColAff = off("Table_zColAff", 24);
const Table_pCheck = off("Table_pCheck", 32);
const Table_tnum = off("Table_tnum", 40);
const Table_nTabRef = off("Table_nTabRef", 44);
const Table_tabFlags = off("Table_tabFlags", 48);
const Table_iPKey = off("Table_iPKey", 52);
const Table_nCol = off("Table_nCol", 54);
const Table_nNVCol = off("Table_nNVCol", 56);
const Table_nRowLogEst = off("Table_nRowLogEst", 58);
const Table_szTabRow = off("Table_szTabRow", 60);
const Table_keyConf = off("Table_keyConf", 62);
const Table_eTabType = off("Table_eTabType", 63);
const Table_u = off("Table_u", 64);
const Table_u_tab_pDfltList = off("Table_u_tab_pDfltList", 64);
const Table_u_tab_pFKey = off("Table_u_tab_pFKey", 72);
const Table_u_tab_addColOffset = off("Table_u_tab_addColOffset", 80);
const Table_u_view_pSelect = off("Table_u_view_pSelect", 64);
const Table_u_vtab_azArg = off("Table_u_vtab_azArg", 72);
const Table_pSchema = off("Table_pSchema", 96);
const Table_aHx = off("Table_aHx", 104);

// Column (sizeof 16): zCnName(0), notNull:4|eCType:4 @8, affinity@9, szEst@10, hName@11, iDflt@12, colFlags@14
const Column_zCnName = off("Column_zCnName", 0);
const Column_bft_byte: usize = 8; // notNull(low nibble) | eCType(high nibble)
const Column_affinity = off("Column_affinity", 9);
const Column_szEst = off("Column_szEst", 10);
const Column_hName = off("Column_hName", 11);
const Column_iDflt = off("Column_iDflt", 12);
const Column_colFlags = off("Column_colFlags", 14);
const sizeof_Column = off("sizeof_Column", 16);

// Index
const Index_zName = off("Index_zName", 0);
const Index_aiColumn = off("Index_aiColumn", 8);
const Index_aiRowLogEst = off("Index_aiRowLogEst", 16);
const Index_aSortOrder = off("Index_aSortOrder", 24);
const Index_azColl = off("Index_azColl", 32);
const Index_zColAff = off("Index_zColAff", 40);
const Index_pNext = off("Index_pNext", 48);
const Index_pSchema = off("Index_pSchema", 56);
const Index_pTable = off("Index_pTable", 64);
const Index_pPartIdxWhere = off("Index_pPartIdxWhere", 80);
const Index_aColExpr = off("Index_aColExpr", 88);
const Index_tnum = off("Index_tnum", 96);
const Index_szIdxRow = off("Index_szIdxRow", 100);
const Index_nKeyCol = off("Index_nKeyCol", 102);
const Index_nColumn = off("Index_nColumn", 104);
const Index_onError = off("Index_onError", 106);
const Index_colNotIdxed = off("Index_colNotIdxed", 112);
// Index bitfield bytes (empirically probed, identical prod/testfixture — see
// tools/bitprobe). After onError comes the packed bit group:
//   byte onError+1: idxType:2(0x03), bUnordered:1(0x04), uniqNotNull:1(0x08),
//                   isResized:1(0x10), isCovering:1(0x20), noSkipScan:1(0x40),
//                   hasStat1:1(0x80)
//   byte onError+2: bNoQuery:1(0x01), bAscKeyBug:1(0x02), bHasVCol:1(0x04),
//                   bHasExpr:1(0x08)
const Index_bits_byte: usize = Index_onError + 1;
const IDX_idxType_mask: u8 = 0x03;
const IDX_uniqNotNull: u8 = 0x08;
const IDX_isResized: u8 = 0x10;
const IDX_isCovering: u8 = 0x20;
const IDX_noSkipScan: u8 = 0x40;
const IDX_hasStat1: u8 = 0x80;
const Index_bits2_byte: usize = Index_onError + 2;
const IDX_bNoQuery: u8 = 0x01;
const IDX_bAscKeyBug: u8 = 0x02;
const IDX_bHasVCol: u8 = 0x04;
const IDX_bHasExpr: u8 = 0x08;

// Token (sizeof 16): z(0), n(8 as u32)
const Token_z: usize = 0;
const Token_n: usize = 8;
const sizeof_Token = off("sizeof_Token", 16);

// ExprList / item
const ExprList_nExpr = off("ExprList_nExpr", 0);
const ExprList_a = off("ExprList_a", 8);
const ExprList_item_pExpr = off("ExprList_item_pExpr", 0);
const ExprList_item_zEName = off("ExprList_item_zEName", 8);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);
const ExprList_item_u = off("ExprList_item_u", 20); // u.iConstExprReg / u.x
inline fn elA(p: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(p) + ExprList_a);
} // ExprList.a is an INLINE flex array
const ExprList_item_fg_sortFlags = off("ExprList_item_fg_sortFlags", 22);
// ExprList_item.fg bitfield: sortFlags is a u8 at off above. bNulls is a :1 bit.
// fg layout: u8 sortFlags; unsigned eEName:2; bNulls:1; bUsed:1; bUsingTerm:1; ...
const ExprList_item_fg_byte: usize = ExprList_item_fg_sortFlags + 1;
const ELI_bNulls: u8 = 0x04; // eEName:2 (0x03), then bNulls:1 (0x04)

// Expr
const Expr_op = off("Expr_op", 0);
const Expr_affExpr = off("Expr_affExpr", 2);
const Expr_flags = off("Expr_flags", 4);
const Expr_u = off("Expr_u", 8); // u.zToken/u.iValue
const Expr_pLeft = off("Expr_pLeft", 16);
const Expr_iColumn = off("Expr_iColumn", 48);

// IdList: { int nId; struct{char*zName;}a[]; } — a is INLINE
const IdList_nId: usize = 0;
const IdList_a = off("IdList_a", 8);
const sizeof_IdListItem: usize = 8;

// SrcList: { int nSrc; u32 nAlloc; SrcItem a[]; } — a is INLINE
const SrcList_nSrc = off("SrcList_nSrc", 0);
const SrcList_nAlloc = off("SrcList_nAlloc", 4);
const SrcList_a = off("SrcList_a", 8);
const sizeof_SrcItem = off("sizeof_SrcItem", 104);
// SrcItem
const SrcItem_zName = off("SrcItem_zName", 16);
const SrcItem_zAlias = off("SrcItem_zAlias", 24);
const SrcItem_iCursor = off("SrcItem_iCursor", 36);
const SrcItem_fg = off("SrcItem_fg", 28);
const SrcItem_u1 = off("SrcItem_u1", 48);
const SrcItem_u3 = off("SrcItem_u3", 64);
const SrcItem_u4 = off("SrcItem_u4", 72);
const SrcItem_pSTab = off("SrcItem_pSTab", 8);
const SrcItem_u4_pSubq = off("SrcItem_u4_pSubq", 72);

// Subquery
const Subquery_pSelect = off("Subquery_pSelect", 0);

// FKey
const FKey_pFrom = off("FKey_pFrom", 0);
const FKey_pNextFrom = off("FKey_pNextFrom", 8);
const FKey_zTo = off("FKey_zTo", 16);
const FKey_pNextTo = off("FKey_pNextTo", 24);
const FKey_pPrevTo = off("FKey_pPrevTo", 32);
const FKey_nCol = off("FKey_nCol", 40);
const FKey_isDeferred = off("FKey_isDeferred", 44);
const FKey_aAction = off("FKey_aAction", 45);
const FKey_aCol = off("FKey_aCol", 64);
const sizeof_sColMap = off("sizeof_sColMap", 16);
const sColMap_iFrom = off("sColMap_iFrom", 0);
const sColMap_zCol = off("sColMap_zCol", 8);

// Select
const Select_op = off("Select_op", 0);
const Select_selFlags = off("Select_selFlags", 4);
const Select_pEList = off("Select_pEList", 24);
const Select_pSrc = off("Select_pSrc", 32);

// KeyInfo
const KeyInfo_nKeyField = off("KeyInfo_nKeyField", 6);
const KeyInfo_nAllField = off("KeyInfo_nAllField", 8);
const KeyInfo_aSortFlags = off("KeyInfo_aSortFlags", 24);
const KeyInfo_aColl = off("KeyInfo_aColl", 32); // INLINE array

// AutoincInfo unused here.

// With / Cte
const With_nCte = off("With_nCte", 8);
const With_a = off("With_a", 16);
const sizeof_Cte = off("sizeof_Cte", 48);
const Cte_pSelect = off("Cte_pSelect", 0);
const Cte_pCols = off("Cte_pCols", 8);
const Cte_zName = off("Cte_zName", 16);
const Cte_eM10d = off("Cte_eM10d", 32);

// Returning
const Returning_pParse = off("Returning_pParse", 0);
const Returning_pReturnEL = off("Returning_pReturnEL", 8);
const Returning_retTrig = off("Returning_retTrig", 16);
const Returning_retTStep = off("Returning_retTStep", 88);
const Returning_iRetCur = off("Returning_iRetCur", 152);
const Returning_nRetCol = off("Returning_nRetCol", 156);
const Returning_iRetReg = off("Returning_iRetReg", 160);
const Returning_zName = off("Returning_zName", 188);
const sizeof_Returning = off("sizeof_Returning", 232);

// Trigger (fields written by sqlite3AddReturning into retTrig)
const Trigger_zName = off("Trigger_zName", 0);
const Trigger_op = off("Trigger_op", 16);
const Trigger_tr_tm = off("Trigger_tr_tm", 18);
const Trigger_bReturning = off("Trigger_bReturning", 19);
const Trigger_pSchema = off("Trigger_pSchema", 24);
const Trigger_pTabSchema = off("Trigger_pTabSchema", 32);
const Trigger_step_list = off("Trigger_step_list", 48);
const Trigger_pNext = off("Trigger_pNext", 56);
// TriggerStep
const TriggerStep_op = off("TriggerStep_op", 0);
const TriggerStep_pTrig = off("TriggerStep_pTrig", 16);
const TriggerStep_pExprList = off("TriggerStep_pExprList", 48);

// ─── constants ────────────────────────────────────────────────────────────────
const OP_Savepoint: u8 = 0;
const OP_AutoCommit: u8 = 1;
const OP_Transaction: u8 = 2;
const OP_JournalMode: u8 = 4;
const OP_Init: u8 = 8;
const OP_Goto: u8 = 9;
const OP_InitCoroutine: u8 = 11;
const OP_Yield: u8 = 12;
const OP_If: u8 = 16;
const OP_SorterSort: u8 = 34;
const OP_Rewind: u8 = 36;
const OP_SorterNext: u8 = 38;
const OP_Next: u8 = 40;
const OP_Halt: u8 = 72;
const OP_Integer: u8 = 73;
const OP_Blob: u8 = 79;
const OP_FkCheck: u8 = 85;
const OP_ResultRow: u8 = 86;
const OP_Column: u8 = 96;
const OP_MakeRecord: u8 = 99;
const OP_ReadCookie: u8 = 101;
const OP_SetCookie: u8 = 102;
const OP_OpenRead: u8 = 114;
const OP_OpenWrite: u8 = 116;
const OP_OpenEphemeral: u8 = 120;
const OP_SorterOpen: u8 = 121;
const OP_Close: u8 = 124;
const OP_NewRowid: u8 = 129;
const OP_Insert: u8 = 130;
const OP_SorterCompare: u8 = 134;
const OP_SorterData: u8 = 135;
const OP_SeekEnd: u8 = 139;
const OP_IdxInsert: u8 = 140;
const OP_SorterInsert: u8 = 141;
const OP_Destroy: u8 = 146;
const OP_Clear: u8 = 147;
const OP_CreateBtree: u8 = 149;
const OP_SqlExec: u8 = 150;
const OP_DropTable: u8 = 153;
const OP_DropIndex: u8 = 155;
const OP_Expire: u8 = 168;
const OP_TableLock: u8 = 171;
const OP_VBegin: u8 = 172;
const OP_VDestroy: u8 = 174;
const OP_Noop: u8 = 189;

const OE_None: i32 = 0;
const OE_Abort: i32 = 2;
const OE_Ignore: i32 = 4;
const OE_Replace: i32 = 5;
const OE_Default: i32 = 11;

const OPFLAG_APPEND: u16 = 0x08;
const OPFLAG_USESEEKRESULT: u16 = 0x10;
const OPFLAG_BULKCSR: u16 = 0x01;
const OPFLAG_P2ISREG: u16 = 0x10;

const P4_STATIC: i32 = -1;
const P4_DYNAMIC: i32 = -7;
const P4_KEYINFO: i32 = -9;
const P4_VTAB: i32 = -12;
const P5_ConstraintUnique: u16 = 2;

const SQLITE_AFF_NONE: u8 = 0x40;
const SQLITE_AFF_BLOB: u8 = 0x41;
const SQLITE_AFF_TEXT: u8 = 0x42;
const SQLITE_AFF_NUMERIC: u8 = 0x43;
const SQLITE_AFF_INTEGER: u8 = 0x44;
const SQLITE_AFF_REAL: u8 = 0x45;
const SQLITE_AFF_FLEXNUM: u8 = 0x46;

const COLTYPE_CUSTOM: u8 = 0;
const COLTYPE_ANY: u8 = 1;
const COLTYPE_INTEGER: u8 = 4;
const SQLITE_N_STDTYPE: usize = 6;

const COLFLAG_PRIMKEY: u16 = 0x0001;
const COLFLAG_HIDDEN: u16 = 0x0002;
const COLFLAG_HASTYPE: u16 = 0x0004;
const COLFLAG_UNIQUE: u16 = 0x0008;
const COLFLAG_VIRTUAL: u16 = 0x0020;
const COLFLAG_STORED: u16 = 0x0040;
const COLFLAG_GENERATED: u16 = 0x0060;
const COLFLAG_NOINSERT: u16 = 0x0062;
const COLFLAG_HASCOLL: u16 = 0x0200;

const TF_Readonly: u32 = 0x00000001;
const TF_HasPrimaryKey: u32 = 0x00000004;
const TF_Autoincrement: u32 = 0x00000008;
const TF_HasVirtual: u32 = 0x00000020;
const TF_HasStored: u32 = 0x00000040;
const TF_HasGenerated: u32 = 0x00000060;
const TF_WithoutRowid: u32 = 0x00000080;
const TF_NoVisibleRowid: u32 = 0x00000200;
const TF_OOOHidden: u32 = 0x00000400;
const TF_HasNotNull: u32 = 0x00000800;
const TF_Shadow: u32 = 0x00001000;
const TF_Ephemeral: u32 = 0x00004000;
const TF_Eponymous: u32 = 0x00008000;
const TF_Strict: u32 = 0x00010000;
const TF_Imposter: u32 = 0x00020000;

const TK_DEFERRED: u8 = 7;
const TK_EXCLUSIVE: u8 = 9;
const TK_COMMIT: u8 = 10;
const TK_END: u8 = 11;
const TK_ROLLBACK: u8 = 12;
const TK_ID: u8 = 60;
const TK_RAISE: u8 = 72;
const TK_COLLATE: u8 = 114;
const TK_STRING: u8 = 118;
const TK_NULL: u8 = 122;
const TK_RETURNING: u8 = 151;
const TK_COLUMN: u8 = 168;
const TK_UPLUS: u8 = 173;
const TK_SPAN: u8 = 181;

const SQLITE_SO_ASC: i32 = 0;
const SQLITE_SO_DESC: i32 = 1;
const SQLITE_SO_UNDEFINED: i32 = -1;
const SQLITE_IDXTYPE_APPDEF: u8 = 0;
const SQLITE_IDXTYPE_UNIQUE: u8 = 1;
const SQLITE_IDXTYPE_PRIMARYKEY: u8 = 2;

const BTREE_INTKEY: i32 = 1;
const BTREE_BLOBKEY: i32 = 2;
const BTREE_SCHEMA_VERSION: i32 = 1;
const BTREE_FILE_FORMAT: i32 = 2;
const BTREE_TEXT_ENCODING: i32 = 5;
const SCHEMA_ROOT: i32 = 1;
const XN_ROWID: i16 = -1;
const XN_EXPR: i16 = -2;

const LOCATE_VIEW: u32 = 0x01;
const LOCATE_NOERR: u32 = 0x02;
const NC_PartIdx: i32 = 0x000002;
const NC_IsCheck: i32 = 0x000004;
const NC_GenCol: i32 = 0x000008;
const NC_IdxExpr: i32 = 0x000020;
const EP_IntValue: u32 = 0x000800;
const EP_Skip: u32 = 0x002000;
const EXPRDUP_REDUCE: i32 = 0x0001;
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;
const PARSE_MODE_NORMAL: u8 = 0;
const PARSE_MODE_DECLARE_VTAB: u8 = 1;
const PARSE_MODE_RENAME: u8 = 2;

const SF_NestedFrom: u32 = 0x0000800;
const SF_View: u32 = 0x0200000;
const SRT_Coroutine: u8 = 11;

const SAVEPOINT_BEGIN: i32 = 0;
const SAVEPOINT_RELEASE: i32 = 1;
const SAVEPOINT_ROLLBACK: i32 = 2;
const PAGER_JOURNALMODE_QUERY: i32 = -1;
const SQLITE_MAX_FILE_FORMAT: i32 = 4;
const SQLITE_LIMIT_COLUMN: usize = 2;
const SQLITE_LIMIT_LENGTH: usize = 0;

const DBFLAG_PreferBuiltin: u32 = 0x0002;
const DBFLAG_SchemaChange: u32 = 0x0001;
const DBFLAG_Vacuum: u32 = 0x0004;
const DBFLAG_SchemaKnownOk: u32 = 0x0010;

const DB_ResetWanted: u32 = 0x0008;
const DB_UnresetViews: u32 = 0x0002;

const SQLITE_WriteSchema: u64 = 0x00000001;
const SQLITE_Defensive: u64 = 0x10000000;
const SQLITE_LegacyFileFmt: u64 = 0x00000002;

const TRIGGER_AFTER: u8 = 2;
const WRC_Continue: c_int = 0;

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_DONE: c_int = 101;
const SQLITE_TOOBIG: c_int = 18;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_CONSTRAINT_PRIMARYKEY: c_int = (SQLITE_CONSTRAINT | (6 << 8));
const SQLITE_CONSTRAINT_UNIQUE: c_int = (SQLITE_CONSTRAINT | (8 << 8));
const SQLITE_CONSTRAINT_ROWID: c_int = (SQLITE_CONSTRAINT | (10 << 8));
const SQLITE_ERROR_MISSING_COLLSEQ: c_int = (SQLITE_ERROR | (1 << 8));
const SQLITE_ERROR_RETRY: c_int = (SQLITE_ERROR | (2 << 8));

const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
const SQLITE_OPEN_CREATE: c_int = 0x00000004;
const SQLITE_OPEN_EXCLUSIVE: c_int = 0x00000010;
const SQLITE_OPEN_DELETEONCLOSE: c_int = 0x00000008;
const SQLITE_OPEN_TEMP_DB: c_int = 0x00000200;

const SQLITE_CREATE_INDEX: c_int = 1;
const SQLITE_CREATE_TABLE: c_int = 2;
const SQLITE_CREATE_TEMP_INDEX: c_int = 3;
const SQLITE_CREATE_TEMP_TABLE: c_int = 4;
const SQLITE_CREATE_TEMP_TRIGGER: c_int = 5;
const SQLITE_CREATE_TEMP_VIEW: c_int = 6;
const SQLITE_CREATE_TRIGGER: c_int = 7;
const SQLITE_CREATE_VIEW: c_int = 8;
const SQLITE_DELETE: c_int = 9;
const SQLITE_DROP_INDEX: c_int = 10;
const SQLITE_DROP_TABLE: c_int = 11;
const SQLITE_DROP_TEMP_INDEX: c_int = 12;
const SQLITE_DROP_TEMP_TABLE: c_int = 13;
const SQLITE_DROP_TEMP_TRIGGER: c_int = 14;
const SQLITE_DROP_TEMP_VIEW: c_int = 15;
const SQLITE_DROP_TRIGGER: c_int = 16;
const SQLITE_DROP_VIEW: c_int = 17;
const SQLITE_INSERT: c_int = 18;
const SQLITE_REINDEX: c_int = 27;
const SQLITE_TRANSACTION: c_int = 22;
const SQLITE_SAVEPOINT: c_int = 32;
const SQLITE_DROP_VTABLE: c_int = 30;
const SQLITE_PREPARE_NO_VTAB: c_uint = 0x04;

const OMIT_TEMPDB: c_int = 0;

// ─── string literals (must match C exactly) ──────────────────────────────────
const LEGACY_SCHEMA_TABLE = "sqlite_master";
const LEGACY_TEMP_SCHEMA_TABLE = "sqlite_temp_master";
const PREFERRED_SCHEMA_TABLE = "sqlite_schema";
const PREFERRED_TEMP_SCHEMA_TABLE = "sqlite_temp_schema";

// ─── extern C/Zig helpers (kept C or already-ported, called by ABI) ──────────
const Cptr = ?*anyopaque;
extern var sqlite3Config: u8; // base symbol; read fields by offset
extern const sqlite3StrBINARY: u8; // char[] — its address is the data
extern const sqlite3UpperToLower: [256]u8;
extern const sqlite3StdTypeLen: [SQLITE_N_STDTYPE]u8;
extern const sqlite3StdTypeAffinity: [SQLITE_N_STDTYPE]u8;
extern const sqlite3StdType: [SQLITE_N_STDTYPE][*:0]const u8;

extern fn sqlite3VdbeAddOp0(p: Cptr, op: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp1(p: Cptr, op: c_int, p1: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp2(p: Cptr, op: c_int, p1: c_int, p2: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp3(p: Cptr, op: c_int, p1: c_int, p2: c_int, p3: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp4(p: Cptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: ?[*]const u8, p4type: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeAddOp4Int(p: Cptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeChangeP3(p: Cptr, addr: c_int, p3: c_int) callconv(.c) void;
extern fn sqlite3VdbeChangeP5(p: Cptr, p5: u16) callconv(.c) void;
extern fn sqlite3VdbeChangeOpcode(p: Cptr, addr: c_int, op: u8) callconv(.c) void;
extern fn sqlite3VdbeCurrentAddr(p: Cptr) callconv(.c) c_int;
extern fn sqlite3VdbeJumpHere(p: Cptr, addr: c_int) callconv(.c) void;
extern fn sqlite3VdbeGoto(p: Cptr, addr: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeGetOp(p: Cptr, addr: c_int) callconv(.c) Cptr;
extern fn sqlite3VdbeUsesBtree(p: Cptr, i: c_int) callconv(.c) void;
extern fn sqlite3VdbeMakeReady(p: Cptr, pParse: Cptr) callconv(.c) void;
extern fn sqlite3VdbeEndCoroutine(p: Cptr, reg: c_int) callconv(.c) void;
extern fn sqlite3VdbeAddParseSchemaOp(p: Cptr, iDb: c_int, zWhere: ?[*]u8, p5: u16) callconv(.c) void;
extern fn sqlite3VdbeAssertMayAbort(p: Cptr, mayAbort: c_int) callconv(.c) c_int;
extern fn sqlite3VdbeComment(v: Cptr, fmt: [*:0]const u8, ...) callconv(.c) void;

extern fn sqlite3GetVdbe(pParse: Cptr) callconv(.c) Cptr;
extern fn sqlite3GetTempReg(pParse: Cptr) callconv(.c) c_int;
extern fn sqlite3ReleaseTempReg(pParse: Cptr, r: c_int) callconv(.c) void;
extern fn sqlite3ErrorMsg(pParse: Cptr, fmt: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3OomFault(db: Cptr) callconv(.c) void;
extern fn sqlite3ReadSchema(pParse: Cptr) callconv(.c) c_int;
extern fn sqlite3SchemaToIndex(db: Cptr, p: Cptr) callconv(.c) c_int;
extern fn sqlite3SchemaMutexHeld(db: Cptr, iDb: c_int, p: Cptr) callconv(.c) c_int;
extern fn sqlite3SchemaClear(p: Cptr) callconv(.c) void;
extern fn sqlite3RunParser(pParse: Cptr, zSql: [*:0]const u8) callconv(.c) c_int;
extern fn sqlite3VMPrintf(db: Cptr, fmt: [*:0]const u8, ap: *std.builtin.VaList) callconv(.c) ?[*:0]u8;
extern fn sqlite3MPrintf(db: Cptr, fmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;

extern fn sqlite3DbFree(db: Cptr, p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3DbNNFreeNN(db: Cptr, p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3DbMallocZero(db: Cptr, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbMallocRaw(db: Cptr, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbMallocRawNN(db: Cptr, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbRealloc(db: Cptr, p: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbReallocOrFree(db: Cptr, p: ?*anyopaque, n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3DbStrDup(db: Cptr, z: ?[*:0]const u8) callconv(.c) ?[*:0]u8;
extern fn sqlite3DbStrNDup(db: Cptr, z: ?[*]const u8, n: u64) callconv(.c) ?[*:0]u8;
extern fn sqlite3DbSpanDup(db: Cptr, z1: ?[*]const u8, z2: ?[*]const u8) callconv(.c) ?[*:0]u8;
extern fn sqlite3_free(p: ?*anyopaque) callconv(.c) void;

extern fn sqlite3Dequote(z: ?[*]u8) callconv(.c) void;
extern fn sqlite3DequoteToken(t: Cptr) callconv(.c) void;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) callconv(.c) c_int;
extern fn sqlite3StrIHash(z: ?[*:0]const u8) callconv(.c) u8;
extern fn sqlite3_snprintf(n: c_int, buf: [*]u8, fmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8;
extern fn sqlite3KeywordCode(z: ?[*]const u8, n: c_int) callconv(.c) c_int;
extern fn sqlite3GetInt32(z: ?[*:0]const u8, p: *c_int) callconv(.c) c_int;
extern fn sqlite3LogEst(x: u64) callconv(.c) u16;
extern const sqlite3CtypeMap: [256]u8;
inline fn sqlite3Isalnum(x: u8) c_int { return sqlite3CtypeMap[x] & 0x06; }
inline fn sqlite3Isdigit(x: u8) c_int { return sqlite3CtypeMap[x] & 0x04; }
inline fn sqlite3Isspace(x: u8) c_int { return sqlite3CtypeMap[x] & 0x01; }

extern fn sqlite3HashFind(h: Cptr, key: ?[*:0]const u8) callconv(.c) ?*anyopaque;
extern fn sqlite3HashInsert(h: Cptr, key: ?[*:0]const u8, data: ?*anyopaque) callconv(.c) ?*anyopaque;

extern fn sqlite3ExprDelete(db: Cptr, p: Cptr) callconv(.c) void;
extern fn sqlite3ExprListDelete(db: Cptr, p: Cptr) callconv(.c) void;
extern fn sqlite3ExprListAppend(pParse: Cptr, pList: Cptr, pExpr: Cptr) callconv(.c) Cptr;
extern fn sqlite3ExprListDup(db: Cptr, p: Cptr, flags: c_int) callconv(.c) Cptr;
extern fn sqlite3ExprListSetName(pParse: Cptr, pList: Cptr, pName: Cptr, dequote: c_int) callconv(.c) void;
extern fn sqlite3ExprListSetSortOrder(p: Cptr, sortOrder: c_int, nulls: c_int) callconv(.c) void;
extern fn sqlite3ExprListCheckLength(pParse: Cptr, pList: Cptr, obj: [*:0]const u8) callconv(.c) void;
extern fn sqlite3ExprAlloc(db: Cptr, op: c_int, pToken: Cptr, dq: c_int) callconv(.c) Cptr;
extern fn sqlite3ExprDup(db: Cptr, p: Cptr, flags: c_int) callconv(.c) Cptr;
extern fn sqlite3ExprSkipCollate(p: Cptr) callconv(.c) Cptr;
extern fn sqlite3ExprIsConstantOrFunction(p: Cptr, isInit: u8) callconv(.c) c_int;
extern fn sqlite3PExpr(pParse: Cptr, op: c_int, pLeft: Cptr, pRight: Cptr) callconv(.c) Cptr;
extern fn sqlite3ExprCode(pParse: Cptr, pExpr: Cptr, target: c_int) callconv(.c) c_int;

extern fn sqlite3SelectDelete(db: Cptr, p: Cptr) callconv(.c) void;
extern fn sqlite3SelectDup(db: Cptr, p: Cptr, flags: c_int) callconv(.c) Cptr;
extern fn sqlite3Select(pParse: Cptr, p: Cptr, dest: Cptr) callconv(.c) c_int;
extern fn sqlite3SelectDestInit(dest: Cptr, srt: c_int, reg: c_int) callconv(.c) void;
extern fn sqlite3ResultSetOfSelect(pParse: Cptr, p: Cptr, aff: u8) callconv(.c) Cptr;
extern fn sqlite3SubqueryColumnTypes(pParse: Cptr, pTab: Cptr, pSel: Cptr, aff: u8) callconv(.c) void;
extern fn sqlite3ColumnsFromExprList(pParse: Cptr, pList: Cptr, pnCol: *i16, paCol: *Cptr) callconv(.c) c_int;
extern fn sqlite3ColumnType(pCol: Cptr, def: [*:0]const u8) callconv(.c) ?[*:0]const u8;
extern fn sqlite3ColumnIndex(pTab: Cptr, z: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3TableAffinity(v: Cptr, pTab: Cptr, base_: c_int) callconv(.c) void;

extern fn sqlite3SrcListLookup(pParse: Cptr, pSrc: Cptr) callconv(.c) Cptr;
extern fn sqlite3ClearOnOrUsing(db: Cptr, p: Cptr) callconv(.c) void;

extern fn sqlite3FixInit(pFix: Cptr, pParse: Cptr, iDb: c_int, ztype: [*:0]const u8, pName: Cptr) callconv(.c) void;
extern fn sqlite3FixSelect(pFix: Cptr, p: Cptr) callconv(.c) c_int;
extern fn sqlite3FixSrcList(pFix: Cptr, p: Cptr) callconv(.c) c_int;

extern fn sqlite3FkDelete(db: Cptr, pTab: Cptr) callconv(.c) void;
extern fn sqlite3FkDropTable(pParse: Cptr, pName: Cptr, pTab: Cptr) callconv(.c) void;

extern fn sqlite3VtabClear(db: Cptr, pTab: Cptr) callconv(.c) void;
extern fn sqlite3VtabUnlockList(db: Cptr) callconv(.c) void;
extern fn sqlite3VtabCallConnect(pParse: Cptr, pTab: Cptr) callconv(.c) c_int;
extern fn sqlite3VtabEponymousTableInit(pParse: Cptr, pMod: Cptr) callconv(.c) c_int;
extern fn sqlite3GetVTable(db: Cptr, pTab: Cptr) callconv(.c) Cptr;
extern fn sqlite3PragmaVtabRegister(db: Cptr, z: ?[*:0]const u8) callconv(.c) Cptr;
extern fn sqlite3JsonVtabRegister(db: Cptr, z: ?[*:0]const u8) callconv(.c) Cptr;
extern fn sqlite3CarrayRegister(db: Cptr) callconv(.c) Cptr;

extern fn sqlite3TriggerList(pParse: Cptr, pTab: Cptr) callconv(.c) Cptr;
extern fn sqlite3DropTriggerPtr(pParse: Cptr, pTrigger: Cptr) callconv(.c) void;
extern fn sqlite3ParserAddCleanup(pParse: Cptr, x: *const fn (Cptr, ?*anyopaque) callconv(.c) void, p: ?*anyopaque) callconv(.c) void;

extern fn sqlite3AuthCheck(pParse: Cptr, code: c_int, a: ?[*:0]const u8, b: ?[*:0]const u8, c: ?[*:0]const u8) callconv(.c) c_int;
extern fn sqlite3DeleteIndexSamples(db: Cptr, p: Cptr) callconv(.c) void;
extern fn sqlite3DbIsNamed(db: Cptr, i: c_int, z: ?[*:0]const u8) callconv(.c) c_int;

extern fn sqlite3KeyInfoAlloc(db: Cptr, nKey: c_int, nExtra: c_int) callconv(.c) Cptr;
extern fn sqlite3KeyInfoRef(p: Cptr) callconv(.c) Cptr;
extern fn sqlite3KeyInfoUnref(p: Cptr) callconv(.c) void;
extern fn sqlite3KeyInfoIsWriteable(p: Cptr) callconv(.c) c_int;
extern fn sqlite3LocateCollSeq(pParse: Cptr, z: ?[*:0]const u8) callconv(.c) Cptr;
extern fn sqlite3FindCollSeq(db: Cptr, enc: u8, z: ?[*:0]const u8, create: u8) callconv(.c) Cptr;

extern fn sqlite3GenerateIndexKey(pParse: Cptr, pIdx: Cptr, iCur: c_int, regOut: c_int, prefixOnly: c_int, piPartIdxLabel: *c_int, pPrior: Cptr, regPrior: c_int) callconv(.c) c_int;
extern fn sqlite3ResolvePartIdxLabel(pParse: Cptr, label: c_int) callconv(.c) void;
extern fn sqlite3ResolveSelfReference(pParse: Cptr, pTab: Cptr, typ: c_int, pExpr: Cptr, pList: Cptr) callconv(.c) c_int;
extern fn sqlite3IndexHasDuplicateRootPage(p: Cptr) callconv(.c) c_int;

extern fn sqlite3OpenTable(pParse: Cptr, iCur: c_int, iDb: c_int, pTab: Cptr, op: c_int) callconv(.c) void;

extern fn sqlite3StrAccumInit(p: Cptr, db: Cptr, zBase: ?[*]u8, n: c_int, mx: c_int) callconv(.c) void;
extern fn sqlite3StrAccumFinish(p: Cptr) callconv(.c) ?[*:0]u8;
extern fn sqlite3_str_append(p: Cptr, z: [*]const u8, n: c_int) callconv(.c) void;
extern fn sqlite3_str_appendall(p: Cptr, z: ?[*:0]const u8) callconv(.c) void;
extern fn sqlite3_str_appendf(p: Cptr, fmt: [*:0]const u8, ...) callconv(.c) void;

extern fn sqlite3RenameTokenMap(pParse: Cptr, p: ?*anyopaque, pToken: Cptr) callconv(.c) ?*anyopaque;
extern fn sqlite3RenameTokenRemap(pParse: Cptr, pTo: ?*anyopaque, pFrom: ?*const anyopaque) callconv(.c) void;
extern fn sqlite3RenameExprUnmap(pParse: Cptr, pExpr: Cptr) callconv(.c) void;
extern fn sqlite3RenameExprlistUnmap(pParse: Cptr, pList: Cptr) callconv(.c) void;

extern fn sqlite3WalkExprList(pWalker: Cptr, pList: Cptr) callconv(.c) c_int;
extern fn sqlite3SelectWalkNoop(pWalker: Cptr, p: Cptr) callconv(.c) c_int;

extern fn sqlite3BtreeSharable(p: Cptr) callconv(.c) c_int;
extern fn sqlite3BtreeIsReadonly(p: Cptr) callconv(.c) c_int;
extern fn sqlite3BtreeHoldsAllMutexes(db: Cptr) callconv(.c) c_int;
extern fn sqlite3BtreeEnterAll(db: Cptr) callconv(.c) void;
extern fn sqlite3BtreeLeaveAll(db: Cptr) callconv(.c) void;
extern fn sqlite3BtreeOpen(pVfs: Cptr, zFilename: ?[*:0]const u8, db: Cptr, ppBtree: *Cptr, flags: c_int, vfsFlags: c_int) callconv(.c) c_int;
extern fn sqlite3BtreeSetPageSize(p: Cptr, pageSize: c_int, nReserve: c_int, fix: c_int) callconv(.c) c_int;
extern fn sqlite3TokenInit(p: Cptr, z: ?[*:0]const u8) callconv(.c) void;

// ─── high-level field accessors ──────────────────────────────────────────────
inline fn parseDb(p: Cptr) Cptr {
    return rdp(p, Parse_db);
}
inline fn dbAt(db: Cptr, i: c_int) ?*anyopaque {
    // &db->aDb[i]
    const aDb = rdp(db, sqlite3_aDb);
    return @ptrCast(base(aDb) + @as(usize, @intCast(i)) * sizeof_Db);
}
inline fn dbZName(db: Cptr, i: c_int) ?[*:0]u8 {
    return @ptrCast(rdp(dbAt(db, i), Db_zDbSName));
}
inline fn dbSchema(db: Cptr, i: c_int) Cptr {
    return rdp(dbAt(db, i), Db_pSchema);
}
inline fn dbNDb(db: Cptr) c_int {
    return rd(c_int, db, sqlite3_nDb);
}
inline fn mallocFailed(db: Cptr) bool {
    return rd(u8, db, sqlite3_mallocFailed) != 0;
}
inline fn initBusy(db: Cptr) u8 {
    return rd(u8, db, sqlite3_initBusy);
}
inline fn initIDb(db: Cptr) u8 {
    return rd(u8, db, sqlite3_init_iDb);
}
inline fn initNewTnum(db: Cptr) u32 {
    return rd(u32, db, sqlite3_init_newTnum);
}
inline fn initImposterTable(db: Cptr) u8 {
    // bitbyte: orphanTrigger:1, imposterTable:2, reopenMemdb:1 → bits 1..2
    return (rd(u8, db, sqlite3_init_bitbyte) >> 1) & 0x03;
}
inline fn parseMode(p: Cptr) u8 {
    return rd(u8, p, Parse_eParseMode);
}
inline fn inSpecialParse(p: Cptr) bool {
    return parseMode(p) != PARSE_MODE_NORMAL;
}
inline fn inRenameObject(p: Cptr) bool {
    return parseMode(p) >= PARSE_MODE_RENAME;
}
inline fn inDeclareVtab(p: Cptr) bool {
    return parseMode(p) == PARSE_MODE_DECLARE_VTAB;
}
inline fn bftSet(p: Cptr, byteoff: usize, mask: u8) void {
    base(p)[byteoff] |= mask;
}
inline fn bftClr(p: Cptr, byteoff: usize, mask: u8) void {
    base(p)[byteoff] &= ~mask;
}
inline fn bftGet(p: Cptr, byteoff: usize, mask: u8) bool {
    return (base(p)[byteoff] & mask) != 0;
}
inline fn parseToplevel(p: Cptr) Cptr {
    const pt = rdp(p, Parse_pToplevel);
    return if (pt != null) pt else p;
}
// yDbMask is a u32 (SQLITE_MAX_ATTACHED<=30)
inline fn dbMaskTest(p: Cptr, off_: usize, iDb: c_int) bool {
    const m = rd(u32, p, off_);
    return (m & (@as(u32, 1) << @intCast(iDb))) != 0;
}
inline fn dbMaskSet(p: Cptr, off_: usize, iDb: c_int) void {
    var m = rd(u32, p, off_);
    m |= (@as(u32, 1) << @intCast(iDb));
    wr(u32, p, off_, m);
}

inline fn schemaTable(x: c_int) [*:0]const u8 {
    return if (OMIT_TEMPDB == 0 and x == 1) LEGACY_TEMP_SCHEMA_TABLE else LEGACY_SCHEMA_TABLE;
}

// Table type predicates (eTabType: TABTYP_NORM=0, VTAB=1, VIEW=2)
const TABTYP_NORM: u8 = 0;
const TABTYP_VTAB: u8 = 1;
const TABTYP_VIEW: u8 = 2;
inline fn eTabType(pTab: Cptr) u8 {
    return rd(u8, pTab, Table_eTabType);
}
inline fn isOrdinaryTable(pTab: Cptr) bool {
    return eTabType(pTab) == TABTYP_NORM;
}
inline fn isVirtual(pTab: Cptr) bool {
    return eTabType(pTab) == TABTYP_VTAB;
}
inline fn isViewTab(pTab: Cptr) bool {
    return eTabType(pTab) == TABTYP_VIEW;
}
inline fn tabFlags(pTab: Cptr) u32 {
    return rd(u32, pTab, Table_tabFlags);
}
inline fn hasRowid(pTab: Cptr) bool {
    return (tabFlags(pTab) & TF_WithoutRowid) == 0;
}
inline fn colFlags(pCol: Cptr) u16 {
    return rd(u16, pCol, Column_colFlags);
}
inline fn colAt(pTab: Cptr, i: c_int) ?*anyopaque {
    const aCol = rdp(pTab, Table_aCol);
    return @ptrCast(base(aCol) + @as(usize, @intCast(i)) * sizeof_Column);
}
inline fn idxType(pIdx: Cptr) u8 {
    return base(pIdx)[Index_bits_byte] & IDX_idxType_mask;
}
inline fn isUniqueIndex(pIdx: Cptr) bool {
    return rd(u8, pIdx, Index_onError) != @as(u8, @intCast(OE_None));
}
inline fn isPrimaryKeyIndex(pIdx: Cptr) bool {
    return idxType(pIdx) == SQLITE_IDXTYPE_PRIMARYKEY;
}

// Token helpers
inline fn tokenZ(t: Cptr) ?[*]const u8 {
    return @ptrCast(rdp(t, Token_z));
}
inline fn tokenN(t: Cptr) u32 {
    return rd(u32, t, Token_n);
}

inline fn vdbeOf(pParse: Cptr) Cptr {
    return rdp(pParse, Parse_pVdbe);
}

// ════════════════════════════════════════════════════════════════════════════
//  Table locks (shared-cache).  struct TableLock { int iDb; Pgno iTab;
//  u8 isWriteLock; const char *zLockName; }  — 24 bytes (aligned).
// ════════════════════════════════════════════════════════════════════════════
const sizeof_TableLock: usize = 24;
const TL_iDb: usize = 0;
const TL_iTab: usize = 4;
const TL_isWriteLock: usize = 8;
const TL_zLockName: usize = 16;

fn lockTable(pParse: Cptr, iDb: c_int, iTab: u32, isWriteLock: u8, zName: ?[*:0]const u8) void {
    const pTop = parseToplevel(pParse);
    const n = rd(c_int, pTop, Parse_nTableLock);
    var aLock = rdp(pTop, Parse_aTableLock);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const p = base(aLock) + @as(usize, @intCast(i)) * sizeof_TableLock;
        if (rd(c_int, @ptrCast(p), TL_iDb) == iDb and rd(u32, @ptrCast(p), TL_iTab) == iTab) {
            const cur = rd(u8, @ptrCast(p), TL_isWriteLock);
            wr(u8, @ptrCast(p), TL_isWriteLock, cur | isWriteLock);
            return;
        }
    }
    const nBytes: u64 = sizeof_TableLock * @as(u64, @intCast(n + 1));
    if (n == 0) wr(?*anyopaque, pTop, Parse_aTableLock, null);
    aLock = sqlite3DbReallocOrFree(parseDb(pTop), rdp(pTop, Parse_aTableLock), nBytes);
    wr(?*anyopaque, pTop, Parse_aTableLock, aLock);
    if (aLock != null) {
        const p = base(aLock) + @as(usize, @intCast(n)) * sizeof_TableLock;
        wr(c_int, pTop, Parse_nTableLock, n + 1);
        wr(c_int, @ptrCast(p), TL_iDb, iDb);
        wr(u32, @ptrCast(p), TL_iTab, iTab);
        wr(u8, @ptrCast(p), TL_isWriteLock, isWriteLock);
        wr(?[*:0]const u8, @ptrCast(p), TL_zLockName, zName);
    } else {
        wr(c_int, pTop, Parse_nTableLock, 0);
        sqlite3OomFault(parseDb(pTop));
    }
}

export fn sqlite3TableLock(pParse: Cptr, iDb: c_int, iTab: u32, isWriteLock: u8, zName: ?[*:0]const u8) void {
    if (iDb == 1) return;
    if (sqlite3BtreeSharable(rdp(dbAt(parseDb(pParse), iDb), Db_pBt)) == 0) return;
    lockTable(pParse, iDb, iTab, isWriteLock, zName);
}

fn codeTableLocks(pParse: Cptr) void {
    const pVdbe = vdbeOf(pParse);
    const n = rd(c_int, pParse, Parse_nTableLock);
    const aLock = rdp(pParse, Parse_aTableLock);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const p = base(aLock) + @as(usize, @intCast(i)) * sizeof_TableLock;
        const p1 = rd(c_int, @ptrCast(p), TL_iDb);
        _ = sqlite3VdbeAddOp4(pVdbe, OP_TableLock, p1, @intCast(rd(u32, @ptrCast(p), TL_iTab)), rd(u8, @ptrCast(p), TL_isWriteLock), @ptrCast(rd(?[*:0]const u8, @ptrCast(p), TL_zLockName)), P4_STATIC);
    }
}

export fn sqlite3FinishCoding(pParse: Cptr) void {
    const db = parseDb(pParse);
    if (rd(u8, pParse, Parse_nested) != 0) return;
    if (rd(c_int, pParse, Parse_nErr) != 0) {
        if (mallocFailed(db)) wr(c_int, pParse, Parse_rc, SQLITE_NOMEM);
        return;
    }
    var v = vdbeOf(pParse);
    if (v == null) {
        if (initBusy(db) != 0) {
            wr(c_int, pParse, Parse_rc, SQLITE_DONE);
            return;
        }
        v = sqlite3GetVdbe(pParse);
        if (v == null) wr(c_int, pParse, Parse_rc, SQLITE_ERROR);
    }
    if (v != null) {
        if (bftGet(pParse, Parse_bft_byte, BFT_bReturning)) {
            const pReturning = rdp(pParse, Parse_u1_d_pReturning);
            const nRetCol = rd(c_int, pReturning, Returning_nRetCol);
            if (nRetCol != 0) {
                _ = sqlite3VdbeAddOp0(v, OP_FkCheck);
                const iRetCur = rd(c_int, pReturning, Returning_iRetCur);
                const addrRewind = sqlite3VdbeAddOp1(v, OP_Rewind, iRetCur);
                const reg = rd(c_int, pReturning, Returning_iRetReg);
                var i: c_int = 0;
                while (i < nRetCol) : (i += 1) {
                    _ = sqlite3VdbeAddOp3(v, OP_Column, iRetCur, i, reg + i);
                }
                _ = sqlite3VdbeAddOp2(v, OP_ResultRow, reg, nRetCol);
                _ = sqlite3VdbeAddOp2(v, OP_Next, iRetCur, addrRewind + 1);
                sqlite3VdbeJumpHere(v, addrRewind);
            }
        }
        _ = sqlite3VdbeAddOp0(v, OP_Halt);

        sqlite3VdbeJumpHere(v, 0);
        var iDb: c_int = 0;
        const nDb = dbNDb(db);
        while (true) {
            if (dbMaskTest(pParse, Parse_cookieMask, iDb)) {
                sqlite3VdbeUsesBtree(v, iDb);
                const pSchema = dbSchema(db, iDb);
                _ = sqlite3VdbeAddOp4Int(v, OP_Transaction, iDb, @intFromBool(dbMaskTest(pParse, Parse_writeMask, iDb)), @intCast(rd(u32, pSchema, Schema_schema_cookie)), @intCast(rd(u32, pSchema, Schema_iGeneration)));
                if (initBusy(db) == 0) sqlite3VdbeChangeP5(v, 1);
                const usesStmtJournal: c_int = @intFromBool(bftGet(pParse, Parse_bft_byte, BFT_mayAbort) and rd(u8, pParse, Parse_isMultiWrite) != 0);
                sqlite3VdbeComment(v, "usesStmtJournal=%d", usesStmtJournal);
            }
            iDb += 1;
            if (iDb >= nDb) break;
        }
        // virtual table locks
        const nVtabLock = rd(c_int, pParse, Parse_nVtabLock);
        var i: c_int = 0;
        while (i < nVtabLock) : (i += 1) {
            const apVtabLock = rdp(pParse, Parse_apVtabLock);
            const pTab = rdp(@ptrCast(base(apVtabLock) + @as(usize, @intCast(i)) * 8), 0);
            const vtab = sqlite3GetVTable(db, pTab);
            _ = sqlite3VdbeAddOp4(v, OP_VBegin, 0, 0, 0, @ptrCast(vtab), P4_VTAB);
        }
        wr(c_int, pParse, Parse_nVtabLock, 0);

        if (rd(c_int, pParse, Parse_nTableLock) != 0) codeTableLocks(pParse);

        if (bftGet(pParse, Parse_bft_byte + 1, BFT_usesAinc)) sqlite3AutoincrementBegin(pParse);

        const pConstExpr = rdp(pParse, Parse_pConstExpr);
        if (pConstExpr != null) {
            bftClr(pParse, Parse_bft_byte, BFT_okConstFactor);
            const nExpr = rd(c_int, pConstExpr, ExprList_nExpr);
            const a = elA(pConstExpr);
            i = 0;
            while (i < nExpr) : (i += 1) {
                const item = base(a) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
                const pExpr = rdp(@ptrCast(item), ExprList_item_pExpr);
                // .u.iConstExprReg is in the zEName union slot (off 8) as int
                const iReg = rd(c_int, @ptrCast(item), ExprList_item_u);
                _ = sqlite3ExprCode(pParse, pExpr, iReg);
            }
        }

        if (bftGet(pParse, Parse_bft_byte, BFT_bReturning)) {
            const pRet = rdp(pParse, Parse_u1_d_pReturning);
            const nRetCol = rd(c_int, pRet, Returning_nRetCol);
            if (nRetCol != 0) {
                _ = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, rd(c_int, pRet, Returning_iRetCur), nRetCol);
            }
        }

        _ = sqlite3VdbeGoto(v, 1);
    }

    if (rd(c_int, pParse, Parse_nErr) == 0) {
        sqlite3VdbeMakeReady(v, pParse);
        wr(c_int, pParse, Parse_rc, SQLITE_DONE);
    } else {
        wr(c_int, pParse, Parse_rc, SQLITE_ERROR);
    }
}

export fn sqlite3NestedParse(pParse: Cptr, zFormat: [*:0]const u8, ...) callconv(.c) void {
    const db = parseDb(pParse);
    const savedDbFlags = rd(u32, db, sqlite3_mDbFlags);
    if (rd(c_int, pParse, Parse_nErr) != 0) return;
    if (parseMode(pParse) != 0) return;
    var ap = @cVaStart();
    const zSql = sqlite3VMPrintf(db, zFormat, &ap);
    @cVaEnd(&ap);
    if (zSql == null) {
        if (!mallocFailed(db)) wr(c_int, pParse, Parse_rc, SQLITE_TOOBIG);
        wr(c_int, pParse, Parse_nErr, rd(c_int, pParse, Parse_nErr) + 1);
        return;
    }
    wr(u8, pParse, Parse_nested, rd(u8, pParse, Parse_nested) + 1);
    // save/restore PARSE_TAIL
    var saveBuf: [PARSE_TAIL_SZ]u8 = undefined;
    const tail = base(pParse) + PARSE_RECURSE_SZ;
    @memcpy(saveBuf[0..PARSE_TAIL_SZ], tail[0..PARSE_TAIL_SZ]);
    @memset(tail[0..PARSE_TAIL_SZ], 0);
    wr(u32, db, sqlite3_mDbFlags, savedDbFlags | DBFLAG_PreferBuiltin);
    _ = sqlite3RunParser(pParse, zSql.?);
    wr(u32, db, sqlite3_mDbFlags, savedDbFlags);
    sqlite3DbFree(db, zSql);
    @memcpy(tail[0..PARSE_TAIL_SZ], saveBuf[0..PARSE_TAIL_SZ]);
    wr(u8, pParse, Parse_nested, rd(u8, pParse, Parse_nested) - 1);
}

export fn sqlite3FindTable(db: Cptr, zName: ?[*:0]const u8, zDatabase: ?[*:0]const u8) Cptr {
    var p: Cptr = null;
    var i: c_int = 0;
    const nDb = dbNDb(db);
    if (zDatabase != null) {
        i = 0;
        while (i < nDb) : (i += 1) {
            if (sqlite3StrICmp(zDatabase, dbZName(db, i)) == 0) break;
        }
        if (i >= nDb) {
            if (sqlite3StrICmp(zDatabase, "main") == 0) {
                i = 0;
            } else return null;
        }
        p = sqlite3HashFind(@ptrCast(base(dbSchema(db, i)) + Schema_tblHash), zName);
        if (p == null and sqlite3_strnicmp(zName, "sqlite_", 7) == 0) {
            if (i == 1) {
                if (sqlite3StrICmp(zNamePlus7(zName), tail7(PREFERRED_TEMP_SCHEMA_TABLE)) == 0 or
                    sqlite3StrICmp(zNamePlus7(zName), tail7(PREFERRED_SCHEMA_TABLE)) == 0 or
                    sqlite3StrICmp(zNamePlus7(zName), tail7(LEGACY_SCHEMA_TABLE)) == 0)
                {
                    p = sqlite3HashFind(@ptrCast(base(dbSchema(db, 1)) + Schema_tblHash), LEGACY_TEMP_SCHEMA_TABLE);
                }
            } else {
                if (sqlite3StrICmp(zNamePlus7(zName), tail7(PREFERRED_SCHEMA_TABLE)) == 0) {
                    p = sqlite3HashFind(@ptrCast(base(dbSchema(db, i)) + Schema_tblHash), LEGACY_SCHEMA_TABLE);
                }
            }
        }
    } else {
        p = sqlite3HashFind(@ptrCast(base(dbSchema(db, 1)) + Schema_tblHash), zName);
        if (p != null) return p;
        p = sqlite3HashFind(@ptrCast(base(dbSchema(db, 0)) + Schema_tblHash), zName);
        if (p != null) return p;
        i = 2;
        while (i < nDb) : (i += 1) {
            p = sqlite3HashFind(@ptrCast(base(dbSchema(db, i)) + Schema_tblHash), zName);
            if (p != null) break;
        }
        if (p == null and sqlite3_strnicmp(zName, "sqlite_", 7) == 0) {
            if (sqlite3StrICmp(zNamePlus7(zName), tail7(PREFERRED_SCHEMA_TABLE)) == 0) {
                p = sqlite3HashFind(@ptrCast(base(dbSchema(db, 0)) + Schema_tblHash), LEGACY_SCHEMA_TABLE);
            } else if (sqlite3StrICmp(zNamePlus7(zName), tail7(PREFERRED_TEMP_SCHEMA_TABLE)) == 0) {
                p = sqlite3HashFind(@ptrCast(base(dbSchema(db, 1)) + Schema_tblHash), LEGACY_TEMP_SCHEMA_TABLE);
            }
        }
    }
    return p;
}
inline fn zNamePlus7(z: ?[*:0]const u8) [*:0]const u8 {
    return @ptrCast(@as([*]const u8, @ptrCast(z.?)) + 7);
}
inline fn tail7(comptime lit: [:0]const u8) [*:0]const u8 {
    return lit[7..].ptr;
}

export fn sqlite3LocateTable(pParse: Cptr, flags: u32, zName: ?[*:0]const u8, zDbase: ?[*:0]const u8) Cptr {
    const db = parseDb(pParse);
    if ((rd(u32, db, sqlite3_mDbFlags) & DBFLAG_SchemaKnownOk) == 0 and sqlite3ReadSchema(pParse) != SQLITE_OK) {
        return null;
    }
    var p = sqlite3FindTable(db, zName, zDbase);
    if (p == null) {
        if ((rd(c_uint, pParse, Parse_prepFlags) & SQLITE_PREPARE_NO_VTAB) == 0 and initBusy(db) == 0) {
            var pMod = sqlite3HashFind(@ptrCast(base(db) + sqlite3_aModule), zName);
            if (pMod == null and sqlite3_strnicmp(zName, "pragma_", 7) == 0) {
                pMod = sqlite3PragmaVtabRegister(db, zName);
            }
            if (pMod == null and sqlite3_strnicmp(zName, "json", 4) == 0) {
                pMod = sqlite3JsonVtabRegister(db, zName);
            }
            // SQLITE_ENABLE_CARRAY on in this build
            if (pMod == null and sqlite3_stricmp(zName, "carray") == 0) {
                pMod = sqlite3CarrayRegister(db);
            }
            if (pMod != null and sqlite3VtabEponymousTableInit(pParse, pMod) != 0) {
                return rdp(pMod, Module_pEpoTab);
            }
        }
        if ((flags & LOCATE_NOERR) != 0) return null;
        bftSet(pParse, Parse_bft_byte + 1, BFT_checkSchema);
    } else if (isVirtual(p) and (rd(c_uint, pParse, Parse_prepFlags) & SQLITE_PREPARE_NO_VTAB) != 0) {
        p = null;
    }

    if (p == null) {
        const zMsg: [*:0]const u8 = if ((flags & LOCATE_VIEW) != 0) "no such view" else "no such table";
        if (zDbase != null) {
            sqlite3ErrorMsg(pParse, "%s: %s.%s", zMsg, zDbase, zName);
        } else {
            sqlite3ErrorMsg(pParse, "%s: %s", zMsg, zName);
        }
    }
    return p;
}
// Module.pEpoTab offset — Module struct, last field pEpoTab.
const Module_pEpoTab: usize = 40;

export fn sqlite3LocateTableItem(pParse: Cptr, flags: u32, p: Cptr) Cptr {
    var zDb: ?[*:0]const u8 = undefined;
    const db = parseDb(pParse);
    if (srcItemFgFixedSchema(p)) {
        const iDb = sqlite3SchemaToIndex(db, rdp(p, SrcItem_u4));
        zDb = dbZName(db, iDb);
    } else {
        zDb = @ptrCast(rdp(p, SrcItem_u4)); // u4.zDatabase
    }
    return sqlite3LocateTable(pParse, flags, @ptrCast(rdp(p, SrcItem_zName)), zDb);
}
// SrcItem.fg bitfield: byte 0 of fg holds jointype(u8); subsequent bits in
// following bytes. fixedSchema / isSubquery are :1 flags. Determine via probing.
inline fn srcItemFgByte(p: Cptr, idx: usize) u8 {
    return base(p)[SrcItem_fg + idx];
}
// fg layout (sqliteInt.h): u8 jointype; bft notIndexed:1; isIndexedBy:1;
//   isTabFunc:1; isCorrelated:1; isMaterialized:1; viaCoroutine:1; isRecursive:1;
//   fromDDL:1; (byte 1) isCte:1; notCte:1; isUsing:1; isOn:1; isSynthUsing:1;
//   isNestedFrom:1; rowidUsed:1; fixedSchema:1; (byte 2) isSubquery:1; ...
// fg+1: notIndexed 0x01, isIndexedBy 0x02, isSubquery 0x04, isTabFunc 0x08,
//        isCorrelated 0x10, isMaterialized 0x20, viaCoroutine 0x40, isRecursive 0x80
const FG_b1: usize = 1;
const FG_notIndexed: u8 = 0x01;
const FG_isIndexedBy: u8 = 0x02;
const FG_isSubquery: u8 = 0x04;
const FG_isTabFunc: u8 = 0x08;
const FG_viaCoroutine: u8 = 0x40;
// fg+2: fromDDL 0x01, isCte 0x02, notCte 0x04, isUsing 0x08, isOn 0x10,
//        isSynthUsing 0x20, isNestedFrom 0x40, rowidUsed 0x80
const FG_b2: usize = 2;
const FG_isCte: u8 = 0x02;
const FG_isUsing: u8 = 0x08;
const FG_isNestedFrom: u8 = 0x40;
// fg+3: fixedSchema 0x01, hadSchema 0x02, fromExists 0x04
const FG_b3: usize = 3;
const FG_fixedSchema: u8 = 0x01;
inline fn srcItemFgFixedSchema(p: Cptr) bool {
    return (srcItemFgByte(p, FG_b3) & FG_fixedSchema) != 0;
}
inline fn srcItemFgIsSubquery(p: Cptr) bool {
    return (srcItemFgByte(p, FG_b1) & FG_isSubquery) != 0;
}

export fn sqlite3PreferredTableName(zName: ?[*:0]const u8) ?[*:0]const u8 {
    if (sqlite3_strnicmp(zName, "sqlite_", 7) == 0) {
        if (sqlite3StrICmp(zNamePlus7(zName), tail7(LEGACY_SCHEMA_TABLE)) == 0) {
            return PREFERRED_SCHEMA_TABLE;
        }
        if (sqlite3StrICmp(zNamePlus7(zName), tail7(LEGACY_TEMP_SCHEMA_TABLE)) == 0) {
            return PREFERRED_TEMP_SCHEMA_TABLE;
        }
    }
    return zName;
}

export fn sqlite3FindIndex(db: Cptr, zName: ?[*:0]const u8, zDb: ?[*:0]const u8) Cptr {
    var p: Cptr = null;
    var i: c_int = OMIT_TEMPDB;
    const nDb = dbNDb(db);
    while (i < nDb) : (i += 1) {
        const j: c_int = if (i < 2) i ^ 1 else i;
        const pSchema = dbSchema(db, j);
        if (zDb != null and sqlite3DbIsNamed(db, j, zDb) == 0) continue;
        p = sqlite3HashFind(@ptrCast(base(pSchema) + Schema_idxHash), zName);
        if (p != null) break;
    }
    return p;
}

export fn sqlite3FreeIndex(db: Cptr, p: Cptr) void {
    sqlite3DeleteIndexSamples(db, p);
    sqlite3ExprDelete(db, rdp(p, Index_pPartIdxWhere));
    sqlite3ExprListDelete(db, rdp(p, Index_aColExpr));
    sqlite3DbFree(db, rdp(p, Index_zColAff));
    if ((base(p)[Index_bits_byte] & IDX_isResized) != 0) sqlite3DbFree(db, rdp(p, Index_azColl));
    sqlite3DbFree(db, p);
}

export fn sqlite3UnlinkAndDeleteIndex(db: Cptr, iDb: c_int, zIdxName: ?[*:0]const u8) void {
    const pHash = base(dbSchema(db, iDb)) + Schema_idxHash;
    const pIndex = sqlite3HashInsert(@ptrCast(pHash), zIdxName, null);
    if (pIndex != null) {
        const pTab = rdp(pIndex, Index_pTable);
        if (rdp(pTab, Table_pIndex) == pIndex) {
            wr(?*anyopaque, pTab, Table_pIndex, rdp(pIndex, Index_pNext));
        } else {
            var pp = rdp(pTab, Table_pIndex);
            while (pp != null and rdp(pp, Index_pNext) != pIndex) {
                pp = rdp(pp, Index_pNext);
            }
            if (pp != null and rdp(pp, Index_pNext) == pIndex) {
                wr(?*anyopaque, pp, Index_pNext, rdp(pIndex, Index_pNext));
            }
        }
        sqlite3FreeIndex(db, pIndex);
    }
    wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) | DBFLAG_SchemaChange);
}

export fn sqlite3CollapseDatabaseArray(db: Cptr) void {
    var i: c_int = 2;
    var j: c_int = 2;
    const nDb = dbNDb(db);
    while (i < nDb) : (i += 1) {
        const pDb = dbAt(db, i);
        if (rdp(pDb, Db_pBt) == null) {
            sqlite3DbFree(db, rdp(pDb, Db_zDbSName));
            wr(?*anyopaque, pDb, Db_zDbSName, null);
            continue;
        }
        if (j < i) {
            const dst = base(dbAt(db, j));
            const src = base(dbAt(db, i));
            @memmove(dst[0..sizeof_Db], src[0..sizeof_Db]);
        }
        j += 1;
    }
    wr(c_int, db, sqlite3_nDb, j);
    if (j <= 2 and rdp(db, sqlite3_aDb) != @as(?*anyopaque, @ptrCast(base(db) + sqlite3_aDbStatic))) {
        const aDbStatic = base(db) + sqlite3_aDbStatic;
        const aDb = base(rdp(db, sqlite3_aDb));
        @memmove(aDbStatic[0 .. 2 * sizeof_Db], aDb[0 .. 2 * sizeof_Db]);
        sqlite3DbFree(db, rdp(db, sqlite3_aDb));
        wr(?*anyopaque, db, sqlite3_aDb, @ptrCast(aDbStatic));
    }
}

// DbHasProperty/DbSetProperty operate on Db.pSchema->schemaFlags.
inline fn dbSetProperty(db: Cptr, i: c_int, p: u32) void {
    const ps = dbSchema(db, i);
    wr(u32, ps, Schema_schemaFlags, rd(u32, ps, Schema_schemaFlags) | p);
}
inline fn dbClearProperty(db: Cptr, i: c_int, p: u32) void {
    const ps = dbSchema(db, i);
    wr(u32, ps, Schema_schemaFlags, rd(u32, ps, Schema_schemaFlags) & ~p);
}
inline fn dbHasProperty(db: Cptr, i: c_int, p: u32) bool {
    return (rd(u32, dbSchema(db, i), Schema_schemaFlags) & p) == p;
}

export fn sqlite3ResetOneSchema(db: Cptr, iDb: c_int) void {
    if (iDb >= 0) {
        dbSetProperty(db, iDb, DB_ResetWanted);
        dbSetProperty(db, 1, DB_ResetWanted);
        wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) & ~DBFLAG_SchemaKnownOk);
    }
    if (rd(c_int, db, sqlite3_nSchemaLock) == 0) {
        var i: c_int = 0;
        const nDb = dbNDb(db);
        while (i < nDb) : (i += 1) {
            if (dbHasProperty(db, i, DB_ResetWanted)) {
                sqlite3SchemaClear(dbSchema(db, i));
            }
        }
    }
}

export fn sqlite3ResetAllSchemasOfConnection(db: Cptr) void {
    sqlite3BtreeEnterAll(db);
    var i: c_int = 0;
    const nDb = dbNDb(db);
    while (i < nDb) : (i += 1) {
        const pDb = dbAt(db, i);
        if (rdp(pDb, Db_pSchema) != null) {
            if (rd(c_int, db, sqlite3_nSchemaLock) == 0) {
                sqlite3SchemaClear(rdp(pDb, Db_pSchema));
            } else {
                dbSetProperty(db, i, DB_ResetWanted);
            }
        }
    }
    wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) & ~(DBFLAG_SchemaChange | DBFLAG_SchemaKnownOk));
    // sqlite3VtabUnlockList(db) — with virtual tables, real call:
    sqlite3VtabUnlockList(db);
    sqlite3BtreeLeaveAll(db);
    if (rd(c_int, db, sqlite3_nSchemaLock) == 0) {
        sqlite3CollapseDatabaseArray(db);
    }
}

export fn sqlite3CommitInternalChanges(db: Cptr) void {
    wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) & ~DBFLAG_SchemaChange);
}

export fn sqlite3ColumnSetExpr(pParse: Cptr, pTab: Cptr, pCol: Cptr, pExpr: Cptr) void {
    const pList = rdp(pTab, Table_u_tab_pDfltList);
    const iDflt = rd(u16, pCol, Column_iDflt);
    if (iDflt == 0 or pList == null or rd(c_int, pList, ExprList_nExpr) < iDflt) {
        wr(u16, pCol, Column_iDflt, if (pList == null) 1 else @intCast(rd(c_int, pList, ExprList_nExpr) + 1));
        wr(?*anyopaque, pTab, Table_u_tab_pDfltList, sqlite3ExprListAppend(pParse, pList, pExpr));
    } else {
        const a = elA(pList);
        const item = base(a) + @as(usize, @intCast(iDflt - 1)) * sizeof_ExprList_item;
        sqlite3ExprDelete(parseDb(pParse), rdp(@ptrCast(item), ExprList_item_pExpr));
        wr(?*anyopaque, @ptrCast(item), ExprList_item_pExpr, pExpr);
    }
}

export fn sqlite3ColumnExpr(pTab: Cptr, pCol: Cptr) Cptr {
    const iDflt = rd(u16, pCol, Column_iDflt);
    if (iDflt == 0) return null;
    if (!isOrdinaryTable(pTab)) return null;
    const pList = rdp(pTab, Table_u_tab_pDfltList);
    if (pList == null) return null;
    if (rd(c_int, pList, ExprList_nExpr) < iDflt) return null;
    const a = elA(pList);
    const item = base(a) + @as(usize, @intCast(iDflt - 1)) * sizeof_ExprList_item;
    return rdp(@ptrCast(item), ExprList_item_pExpr);
}

export fn sqlite3ColumnSetColl(db: Cptr, pCol: Cptr, zColl: [*:0]const u8) void {
    const zCnName: ?[*:0]const u8 = @ptrCast(rdp(pCol, Column_zCnName));
    var n: i64 = sqlite3Strlen30(zCnName) + 1;
    if ((colFlags(pCol) & COLFLAG_HASTYPE) != 0) {
        const after: [*:0]const u8 = @ptrCast(@as([*]const u8, @ptrCast(zCnName.?)) + @as(usize, @intCast(n)));
        n += sqlite3Strlen30(after) + 1;
    }
    const nColl: i64 = sqlite3Strlen30(zColl) + 1;
    const zNew = sqlite3DbRealloc(db, rdp(pCol, Column_zCnName), @intCast(nColl + n));
    if (zNew != null) {
        wr(?*anyopaque, pCol, Column_zCnName, zNew);
        const dst = base(zNew) + @as(usize, @intCast(n));
        @memcpy(dst[0..@intCast(nColl)], @as([*]const u8, @ptrCast(zColl))[0..@intCast(nColl)]);
        wr(u16, pCol, Column_colFlags, colFlags(pCol) | COLFLAG_HASCOLL);
    }
}

export fn sqlite3ColumnColl(pCol: Cptr) ?[*:0]const u8 {
    if ((colFlags(pCol) & COLFLAG_HASCOLL) == 0) return null;
    var z: [*]const u8 = @ptrCast(rdp(pCol, Column_zCnName).?);
    while (z[0] != 0) z += 1;
    if ((colFlags(pCol) & COLFLAG_HASTYPE) != 0) {
        z += 1;
        while (z[0] != 0) z += 1;
    }
    return @ptrCast(z + 1);
}

export fn sqlite3DeleteColumnNames(db: Cptr, pTable: Cptr) void {
    const aCol = rdp(pTable, Table_aCol);
    if (aCol != null) {
        const nCol = rd(i16, pTable, Table_nCol);
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const pCol = base(aCol) + @as(usize, @intCast(i)) * sizeof_Column;
            sqlite3DbFree(db, rdp(@ptrCast(pCol), Column_zCnName));
        }
        sqlite3DbNNFreeNN(db, aCol);
        if (isOrdinaryTable(pTable)) {
            sqlite3ExprListDelete(db, rdp(pTable, Table_u_tab_pDfltList));
        }
        if (rdp(db, sqlite3_pnBytesFreed) == null) {
            wr(?*anyopaque, pTable, Table_aCol, null);
            wr(i16, pTable, Table_nCol, 0);
            if (isOrdinaryTable(pTable)) {
                wr(?*anyopaque, pTable, Table_u_tab_pDfltList, null);
            }
        }
    }
}
const sqlite3_pnBytesFreed = off("sqlite3_pnBytesFreed", 168);

fn deleteTable(db: Cptr, pTable: Cptr) void {
    var pIndex = rdp(pTable, Table_pIndex);
    while (pIndex != null) {
        const pNext = rdp(pIndex, Index_pNext);
        if (rdp(db, sqlite3_pnBytesFreed) == null and !isVirtual(pTable)) {
            const zName: ?[*:0]const u8 = @ptrCast(rdp(pIndex, Index_zName));
            _ = sqlite3HashInsert(@ptrCast(base(rdp(pIndex, Index_pSchema)) + Schema_idxHash), zName, null);
        }
        sqlite3FreeIndex(db, pIndex);
        pIndex = pNext;
    }
    if (isOrdinaryTable(pTable)) {
        sqlite3FkDelete(db, pTable);
    } else if (isVirtual(pTable)) {
        sqlite3VtabClear(db, pTable);
    } else {
        sqlite3SelectDelete(db, rdp(pTable, Table_u_view_pSelect));
    }
    sqlite3DeleteColumnNames(db, pTable);
    sqlite3DbFree(db, rdp(pTable, Table_zName));
    sqlite3DbFree(db, rdp(pTable, Table_zColAff));
    sqlite3ExprListDelete(db, rdp(pTable, Table_pCheck));
    sqlite3DbFree(db, pTable);
}

export fn sqlite3DeleteTable(db: Cptr, pTable: Cptr) void {
    if (pTable == null) return;
    if (rdp(db, sqlite3_pnBytesFreed) == null) {
        const nref = rd(u32, pTable, Table_nTabRef) - 1;
        wr(u32, pTable, Table_nTabRef, nref);
        if (nref > 0) return;
    }
    deleteTable(db, pTable);
}

export fn sqlite3DeleteTableGeneric(db: Cptr, pTable: ?*anyopaque) void {
    sqlite3DeleteTable(db, pTable);
}

export fn sqlite3UnlinkAndDeleteTable(db: Cptr, iDb: c_int, zTabName: ?[*:0]const u8) void {
    const pDb = dbAt(db, iDb);
    const p = sqlite3HashInsert(@ptrCast(base(rdp(pDb, Db_pSchema)) + Schema_tblHash), zTabName, null);
    sqlite3DeleteTable(db, p);
    wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) | DBFLAG_SchemaChange);
}

export fn sqlite3NameFromToken(db: Cptr, pName: Cptr) ?[*:0]u8 {
    if (pName != null) {
        const zName = sqlite3DbStrNDup(db, tokenZ(pName), tokenN(pName));
        sqlite3Dequote(@ptrCast(zName));
        return zName;
    }
    return null;
}

export fn sqlite3OpenSchemaTable(p: Cptr, iDb: c_int) void {
    const v = sqlite3GetVdbe(p);
    sqlite3TableLock(p, iDb, @intCast(SCHEMA_ROOT), 1, LEGACY_SCHEMA_TABLE);
    _ = sqlite3VdbeAddOp4Int(v, OP_OpenWrite, 0, SCHEMA_ROOT, iDb, 5);
    if (rd(c_int, p, Parse_nTab) == 0) {
        wr(c_int, p, Parse_nTab, 1);
    }
}

export fn sqlite3FindDbName(db: Cptr, zName: ?[*:0]const u8) c_int {
    var i: c_int = -1;
    if (zName != null) {
        i = dbNDb(db) - 1;
        while (i >= 0) : (i -= 1) {
            if (sqlite3_stricmp(dbZName(db, i), zName) == 0) break;
            if (i == 0 and sqlite3_stricmp("main", zName) == 0) break;
        }
    }
    return i;
}

export fn sqlite3FindDb(db: Cptr, pName: Cptr) c_int {
    const zName = sqlite3NameFromToken(db, pName);
    const i = sqlite3FindDbName(db, @ptrCast(zName));
    sqlite3DbFree(db, zName);
    return i;
}

export fn sqlite3TwoPartName(pParse: Cptr, pName1: Cptr, pName2: Cptr, pUnqual: *Cptr) c_int {
    var iDb: c_int = undefined;
    const db = parseDb(pParse);
    if (tokenN(pName2) > 0) {
        if (initBusy(db) != 0) {
            sqlite3ErrorMsg(pParse, "corrupt database");
            return -1;
        }
        pUnqual.* = pName2;
        iDb = sqlite3FindDb(db, pName1);
        if (iDb < 0) {
            sqlite3ErrorMsg(pParse, "unknown database %T", pName1);
            return -1;
        }
    } else {
        iDb = initIDb(db);
        pUnqual.* = pName1;
    }
    return iDb;
}

export fn sqlite3WritableSchema(db: Cptr) c_int {
    const f = rd(u64, db, sqlite3_flags);
    return @intFromBool((f & (SQLITE_WriteSchema | SQLITE_Defensive)) == SQLITE_WriteSchema);
}

export fn sqlite3CheckObjectName(pParse: Cptr, zName: ?[*:0]const u8, zType: ?[*:0]const u8, zTblName: ?[*:0]const u8) c_int {
    const db = parseDb(pParse);
    const bExtra = base(&sqlite3Config)[Sqlite3Config_bExtraSchemaChecks];
    if (sqlite3WritableSchema(db) != 0 or initImposterTable(db) != 0 or bExtra == 0) {
        return SQLITE_OK;
    }
    if (initBusy(db) != 0) {
        const azInit: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(db, sqlite3_init_azInit).?));
        if (sqlite3_stricmp(zType, azInit[0]) != 0 or
            sqlite3_stricmp(zName, azInit[1]) != 0 or
            sqlite3_stricmp(zTblName, azInit[2]) != 0)
        {
            sqlite3ErrorMsg(pParse, "");
            return SQLITE_ERROR;
        }
    } else {
        if ((rd(u8, pParse, Parse_nested) == 0 and sqlite3_strnicmp(zName, "sqlite_", 7) == 0) or
            (sqlite3ReadOnlyShadowTables(db) != 0 and sqlite3ShadowTableName(db, zName.?) != 0))
        {
            sqlite3ErrorMsg(pParse, "object name reserved for internal use: %s", zName);
            return SQLITE_ERROR;
        }
    }
    return SQLITE_OK;
}
const Sqlite3Config_bExtraSchemaChecks = off("Sqlite3Config_bExtraSchemaChecks", 9);

export fn sqlite3PrimaryKeyIndex(pTab: Cptr) Cptr {
    var p = rdp(pTab, Table_pIndex);
    while (p != null and !isPrimaryKeyIndex(p)) p = rdp(p, Index_pNext);
    return p;
}

export fn sqlite3TableColumnToIndex(pIdx: Cptr, iCol: c_int) c_int {
    const iCol16: i16 = @truncate(iCol);
    const nColumn = rd(u16, pIdx, Index_nColumn);
    const aiColumn: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
    var i: c_int = 0;
    while (i < nColumn) : (i += 1) {
        if (iCol16 == aiColumn[@intCast(i)]) return i;
    }
    return -1;
}

export fn sqlite3StorageColumnToTable(pTab: Cptr, iColIn: i16) i16 {
    var iCol = iColIn;
    if ((tabFlags(pTab) & TF_HasVirtual) != 0) {
        var i: i16 = 0;
        while (i <= iCol) : (i += 1) {
            if ((colFlags(colAt(pTab, i)) & COLFLAG_VIRTUAL) != 0) iCol += 1;
        }
    }
    return iCol;
}

export fn sqlite3TableColumnToStorage(pTab: Cptr, iCol: i16) i16 {
    if ((tabFlags(pTab) & TF_HasVirtual) == 0 or iCol < 0) return iCol;
    var n: i16 = 0;
    var i: c_int = 0;
    while (i < iCol) : (i += 1) {
        if ((colFlags(colAt(pTab, i)) & COLFLAG_VIRTUAL) == 0) n += 1;
    }
    if ((colFlags(colAt(pTab, i)) & COLFLAG_VIRTUAL) != 0) {
        return @intCast(rd(i16, pTab, Table_nNVCol) + @as(i16, @intCast(i)) - n);
    } else {
        return n;
    }
}

fn sqlite3ForceNotReadOnly(pParse: Cptr) void {
    const iReg = rd(c_int, pParse, Parse_nMem) + 1;
    wr(c_int, pParse, Parse_nMem, iReg);
    const v = sqlite3GetVdbe(pParse);
    if (v != null) {
        _ = sqlite3VdbeAddOp3(v, OP_JournalMode, 0, iReg, PAGER_JOURNALMODE_QUERY);
        sqlite3VdbeUsesBtree(v, 0);
    }
}

export fn sqlite3StartTable(pParse: Cptr, pName1: Cptr, pName2: Cptr, isTempIn: c_int, isView: c_int, isVirtualF: c_int, noErr: c_int) void {
    var isTemp = isTempIn;
    var zName: ?[*:0]u8 = null;
    const db = parseDb(pParse);
    var iDb: c_int = undefined;
    var pName: Cptr = undefined;

    if (initBusy(db) != 0 and initNewTnum(db) == 1) {
        iDb = initIDb(db);
        zName = sqlite3DbStrDup(db, schemaTable(iDb));
        pName = pName1;
    } else {
        iDb = sqlite3TwoPartName(pParse, pName1, pName2, &pName);
        if (iDb < 0) return;
        if (OMIT_TEMPDB == 0 and isTemp != 0 and tokenN(pName2) > 0 and iDb != 1) {
            sqlite3ErrorMsg(pParse, "temporary table name must be unqualified");
            return;
        }
        if (OMIT_TEMPDB == 0 and isTemp != 0) iDb = 1;
        zName = sqlite3NameFromToken(db, pName);
        if (inRenameObject(pParse)) {
            _ = sqlite3RenameTokenMap(pParse, @ptrCast(zName), pName);
        }
    }
    // pParse->sNameToken = *pName
    @memcpy((base(pParse) + Parse_sNameToken)[0..sizeof_Token], base(pName)[0..sizeof_Token]);
    if (zName == null) return;
    if (sqlite3CheckObjectName(pParse, @ptrCast(zName), if (isView != 0) "view" else "table", @ptrCast(zName)) != 0) {
        return beginTableError(pParse, db, zName);
    }
    if (initIDb(db) == 1) isTemp = 1;
    {
        const aCode = [_]c_int{ SQLITE_CREATE_TABLE, SQLITE_CREATE_TEMP_TABLE, SQLITE_CREATE_VIEW, SQLITE_CREATE_TEMP_VIEW };
        const zDb = dbZName(db, iDb);
        if (sqlite3AuthCheck(pParse, SQLITE_INSERT, schemaTable(isTemp), null, zDb) != 0) {
            return beginTableError(pParse, db, zName);
        }
        if (isVirtualF == 0 and sqlite3AuthCheck(pParse, aCode[@intCast(isTemp + 2 * isView)], @ptrCast(zName), null, zDb) != 0) {
            return beginTableError(pParse, db, zName);
        }
    }

    if (!inSpecialParse(pParse)) {
        const zDb = dbZName(db, iDb);
        if (sqlite3ReadSchema(pParse) != SQLITE_OK) {
            return beginTableError(pParse, db, zName);
        }
        const pTabExisting = sqlite3FindTable(db, @ptrCast(zName), zDb);
        if (pTabExisting != null) {
            if (noErr == 0) {
                sqlite3ErrorMsg(pParse, "%s %T already exists", @as([*:0]const u8, if (isView0(pTabExisting)) "view" else "table"), pName);
            } else {
                sqlite3CodeVerifySchema(pParse, iDb);
                sqlite3ForceNotReadOnly(pParse);
            }
            return beginTableError(pParse, db, zName);
        }
        if (sqlite3FindIndex(db, @ptrCast(zName), zDb) != null) {
            sqlite3ErrorMsg(pParse, "there is already an index named %s", zName);
            return beginTableError(pParse, db, zName);
        }
    }

    const pTable = sqlite3DbMallocZero(db, sizeof_Table);
    if (pTable == null) {
        wr(c_int, pParse, Parse_rc, SQLITE_NOMEM);
        wr(c_int, pParse, Parse_nErr, rd(c_int, pParse, Parse_nErr) + 1);
        return beginTableError(pParse, db, zName);
    }
    wr(?*anyopaque, pTable, Table_zName, zName);
    wr(i16, pTable, Table_iPKey, -1);
    wr(?*anyopaque, pTable, Table_pSchema, dbSchema(db, iDb));
    wr(u32, pTable, Table_nTabRef, 1);
    wr(u16, pTable, Table_nRowLogEst, 200);
    wr(?*anyopaque, pParse, Parse_pNewTable, pTable);

    var v: Cptr = null;
    if (initBusy(db) == 0) {
        v = sqlite3GetVdbe(pParse);
        if (v != null) {
            const nullRow = [_]u8{ 6, 0, 0, 0, 0, 0 };
            sqlite3BeginWriteOperation(pParse, 1, iDb);
            if (isVirtualF != 0) {
                _ = sqlite3VdbeAddOp0(v, OP_VBegin);
            }
            const reg1 = rd(c_int, pParse, Parse_nMem) + 1;
            wr(c_int, pParse, Parse_u1_cr_regRowid, reg1);
            const reg2 = reg1 + 1;
            wr(c_int, pParse, Parse_u1_cr_regRoot, reg2);
            const reg3 = reg2 + 1;
            wr(c_int, pParse, Parse_nMem, reg3);
            _ = sqlite3VdbeAddOp3(v, OP_ReadCookie, iDb, reg3, BTREE_FILE_FORMAT);
            sqlite3VdbeUsesBtree(v, iDb);
            const addr1 = sqlite3VdbeAddOp1(v, OP_If, reg3);
            const fileFormat: c_int = if ((rd(u64, db, sqlite3_flags) & SQLITE_LegacyFileFmt) != 0) 1 else SQLITE_MAX_FILE_FORMAT;
            _ = sqlite3VdbeAddOp3(v, OP_SetCookie, iDb, BTREE_FILE_FORMAT, fileFormat);
            _ = sqlite3VdbeAddOp3(v, OP_SetCookie, iDb, BTREE_TEXT_ENCODING, rd(u8, db, sqlite3_enc));
            sqlite3VdbeJumpHere(v, addr1);

            if (isView != 0 or isVirtualF != 0) {
                _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, reg2);
            } else {
                wr(c_int, pParse, Parse_u1_cr_addrCrTab, sqlite3VdbeAddOp3(v, OP_CreateBtree, iDb, reg2, BTREE_INTKEY));
            }
            sqlite3OpenSchemaTable(pParse, iDb);
            _ = sqlite3VdbeAddOp2(v, OP_NewRowid, 0, reg1);
            _ = sqlite3VdbeAddOp4(v, OP_Blob, 6, reg3, 0, &nullRow, P4_STATIC);
            _ = sqlite3VdbeAddOp3(v, OP_Insert, 0, reg3, reg1);
            sqlite3VdbeChangeP5(v, OPFLAG_APPEND);
            _ = sqlite3VdbeAddOp0(v, OP_Close);
        }
    } else if (initImposterTable(db) != 0) {
        wr(u32, pTable, Table_tabFlags, tabFlags(pTable) | TF_Imposter);
        if (initImposterTable(db) >= 2) wr(u32, pTable, Table_tabFlags, tabFlags(pTable) | TF_Readonly);
    }
    return;
}
const sqlite3_enc = off("sqlite3_enc", 100);
inline fn isView0(pTab: Cptr) bool {
    return isViewTab(pTab);
}
fn beginTableError(pParse: Cptr, db: Cptr, zName: ?[*:0]u8) void {
    bftSet(pParse, Parse_bft_byte + 1, BFT_checkSchema);
    sqlite3DbFree(db, zName);
}

// SQLITE_ENABLE_HIDDEN_COLUMNS is OFF in both configs → this is a no-op fn that
// is NOT defined (the prototype is gated). So we do NOT export it. But callers
// (sqlite3AddColumn) call sqlite3ColumnPropertiesFromName only under the ifdef,
// so the call is omitted too. Provide a private no-op used nowhere.

fn deleteReturning(db: Cptr, pArg: ?*anyopaque) callconv(.c) void {
    const pRet = pArg;
    const pHash = base(dbSchema(db, 1)) + Schema_trigHash;
    // zName is an inline char[40]; pass its address (like the matching insert at
    // sqlite3AddReturning), not the bytes read from it.
    _ = sqlite3HashInsert(@ptrCast(pHash), @ptrCast(base(pRet) + Returning_zName), null);
    sqlite3ExprListDelete(db, rdp(pRet, Returning_pReturnEL));
    sqlite3DbFree(db, pRet);
}

export fn sqlite3AddReturning(pParse: Cptr, pList: Cptr) void {
    const db = parseDb(pParse);
    if (rdp(pParse, Parse_pNewTrigger) != null) {
        sqlite3ErrorMsg(pParse, "cannot use RETURNING in a trigger");
    }
    bftSet(pParse, Parse_bft_byte, BFT_bReturning);
    const pRet = sqlite3DbMallocZero(db, sizeof_Returning);
    if (pRet == null) {
        sqlite3ExprListDelete(db, pList);
        return;
    }
    wr(?*anyopaque, pParse, Parse_u1_d_pReturning, pRet);
    wr(?*anyopaque, pRet, Returning_pParse, pParse);
    wr(?*anyopaque, pRet, Returning_pReturnEL, pList);
    sqlite3ParserAddCleanup(pParse, &deleteReturning, pRet);
    if (mallocFailed(db)) return;
    _ = sqlite3_snprintf(40, @ptrCast(base(pRet) + Returning_zName), "sqlite_returning_%p", pParse);
    // retTrig fields
    const retTrig = base(pRet) + Returning_retTrig;
    wr(?*anyopaque, @ptrCast(retTrig), Trigger_zName, @ptrCast(base(pRet) + Returning_zName));
    wr(u8, @ptrCast(retTrig), Trigger_op, TK_RETURNING);
    wr(u8, @ptrCast(retTrig), Trigger_tr_tm, TRIGGER_AFTER);
    wr(u8, @ptrCast(retTrig), Trigger_bReturning, 1);
    wr(?*anyopaque, @ptrCast(retTrig), Trigger_pSchema, dbSchema(db, 1));
    wr(?*anyopaque, @ptrCast(retTrig), Trigger_pTabSchema, dbSchema(db, 1));
    wr(?*anyopaque, @ptrCast(retTrig), Trigger_step_list, @ptrCast(base(pRet) + Returning_retTStep));
    const retTStep = base(pRet) + Returning_retTStep;
    wr(u8, @ptrCast(retTStep), TriggerStep_op, TK_RETURNING);
    wr(?*anyopaque, @ptrCast(retTStep), TriggerStep_pTrig, @ptrCast(retTrig));
    wr(?*anyopaque, @ptrCast(retTStep), TriggerStep_pExprList, pList);
    const pHash = base(dbSchema(db, 1)) + Schema_trigHash;
    if (sqlite3HashInsert(@ptrCast(pHash), @ptrCast(base(pRet) + Returning_zName), @ptrCast(retTrig)) == @as(?*anyopaque, @ptrCast(retTrig))) {
        sqlite3OomFault(db);
    }
}

export fn sqlite3AddColumn(pParse: Cptr, sNameIn: Token16, sTypeIn: Token16) void {
    var sName = sNameIn;
    var sType = sTypeIn;
    const db = parseDb(pParse);
    var eType: u8 = COLTYPE_CUSTOM;
    var szEst: u8 = 1;
    var affinity: u8 = SQLITE_AFF_BLOB;

    const p = rdp(pParse, Parse_pNewTable);
    if (p == null) return;
    const nCol = rd(i16, p, Table_nCol);
    if (nCol + 1 > limitCol(db)) {
        sqlite3ErrorMsg(pParse, "too many columns on %s", rdp(p, Table_zName));
        return;
    }
    if (!inRenameObject(pParse)) sqlite3DequoteToken(@ptrCast(&sName));

    if (sType.n >= 16 and sqlite3_strnicmp(@ptrCast(sType.z + (sType.n - 6)), "always", 6) == 0) {
        sType.n -= 6;
        while (sType.n > 0 and sqlite3Isspace(sType.z[sType.n - 1]) != 0) sType.n -= 1;
        if (sType.n >= 9 and sqlite3_strnicmp(@ptrCast(sType.z + (sType.n - 9)), "generated", 9) == 0) {
            sType.n -= 9;
            while (sType.n > 0 and sqlite3Isspace(sType.z[sType.n - 1]) != 0) sType.n -= 1;
        }
    }

    if (sType.n >= 3) {
        sqlite3DequoteToken(@ptrCast(&sType));
        var i: usize = 0;
        while (i < SQLITE_N_STDTYPE) : (i += 1) {
            if (sType.n == sqlite3StdTypeLen[i] and sqlite3_strnicmp(@ptrCast(sType.z), sqlite3StdType[i], @intCast(sType.n)) == 0) {
                sType.n = 0;
                eType = @intCast(i + 1);
                affinity = @bitCast(sqlite3StdTypeAffinity[i]);
                if (affinity <= SQLITE_AFF_TEXT) szEst = 5;
                break;
            }
        }
    }

    const z: ?[*]u8 = @ptrCast(sqlite3DbMallocRaw(db, @as(u64, sName.n) + 1 + @as(u64, sType.n) + @intFromBool(sType.n > 0)));
    if (z == null) return;
    if (inRenameObject(pParse)) _ = sqlite3RenameTokenMap(pParse, @ptrCast(z), @ptrCast(&sName));
    @memcpy(z.?[0..sName.n], sName.z[0..sName.n]);
    z.?[sName.n] = 0;
    sqlite3Dequote(z);
    if (nCol != 0 and sqlite3ColumnIndex(p, @ptrCast(z)) >= 0) {
        sqlite3ErrorMsg(pParse, "duplicate column name: %s", z);
        sqlite3DbFree(db, z);
        return;
    }
    const aNew = sqlite3DbRealloc(db, rdp(p, Table_aCol), (@as(u64, @intCast(nCol)) + 1) * sizeof_Column);
    if (aNew == null) {
        sqlite3DbFree(db, z);
        return;
    }
    wr(?*anyopaque, p, Table_aCol, aNew);
    const pCol = base(aNew) + @as(usize, @intCast(nCol)) * sizeof_Column;
    @memset(pCol[0..sizeof_Column], 0);
    wr(?*anyopaque, @ptrCast(pCol), Column_zCnName, z);
    wr(u8, @ptrCast(pCol), Column_hName, sqlite3StrIHash(@ptrCast(z)));

    if (sType.n == 0) {
        wr(u8, @ptrCast(pCol), Column_affinity, affinity);
        // eCType = high nibble of bft byte; notNull = low nibble (currently 0)
        pCol[Column_bft_byte] = (pCol[Column_bft_byte] & 0x0f) | @as(u8, @intCast(eType << 4));
        wr(u8, @ptrCast(pCol), Column_szEst, szEst);
    } else {
        const zType: [*:0]u8 = @ptrCast(z.? + @as(usize, @intCast(sqlite3Strlen30(@ptrCast(z)) + 1)));
        @memcpy(@as([*]u8, @ptrCast(zType))[0..sType.n], sType.z[0..sType.n]);
        zType[sType.n] = 0;
        sqlite3Dequote(@ptrCast(zType));
        wr(u8, @ptrCast(pCol), Column_affinity, @bitCast(sqlite3AffinityType(zType, @ptrCast(pCol))));
        wr(u16, @ptrCast(pCol), Column_colFlags, colFlags(@ptrCast(pCol)) | COLFLAG_HASTYPE);
    }
    if (nCol <= 0xff) {
        const h = rd(u8, @ptrCast(pCol), Column_hName) % 16;
        base(p)[Table_aHx + h] = @intCast(nCol);
    }
    wr(i16, p, Table_nCol, nCol + 1);
    wr(i16, p, Table_nNVCol, rd(i16, p, Table_nNVCol) + 1);
    // pParse->u1.cr.constraintName.n = 0
    wr(u32, pParse, Parse_u1_cr_constraintName + Token_n, 0);
}
const Token16 = extern struct { z: [*]const u8, n: u32 };
inline fn limitCol(db: Cptr) c_int {
    const aLimit: [*]const c_int = @ptrCast(@alignCast(fieldPtr(db, sqlite3_aLimit)));
    return aLimit[SQLITE_LIMIT_COLUMN];
}
inline fn limitLen(db: Cptr) c_int {
    const aLimit: [*]const c_int = @ptrCast(@alignCast(fieldPtr(db, sqlite3_aLimit)));
    return aLimit[SQLITE_LIMIT_LENGTH];
}

export fn sqlite3AddNotNull(pParse: Cptr, onError: c_int) void {
    const p = rdp(pParse, Parse_pNewTable);
    if (p == null) return;
    const nCol = rd(i16, p, Table_nCol);
    if (nCol < 1) return;
    const pCol = colAt(p, nCol - 1);
    // notNull = low nibble of bft byte
    base(pCol)[Column_bft_byte] = (base(pCol)[Column_bft_byte] & 0xf0) | (@as(u8, @intCast(onError)) & 0x0f);
    wr(u32, p, Table_tabFlags, tabFlags(p) | TF_HasNotNull);
    if ((colFlags(pCol) & COLFLAG_UNIQUE) != 0) {
        var pIdx = rdp(p, Table_pIndex);
        while (pIdx != null) {
            const aiColumn: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
            if (aiColumn[0] == nCol - 1) {
                base(pIdx)[Index_bits_byte] |= IDX_uniqNotNull;
            }
            pIdx = rdp(pIdx, Index_pNext);
        }
    }
}

export fn sqlite3AffinityType(zIn: [*:0]const u8, pCol: Cptr) u8 {
    var h: u32 = 0;
    var aff: u8 = SQLITE_AFF_NUMERIC;
    var zChar: ?[*:0]const u8 = null;
    var z: [*:0]const u8 = zIn;
    while (z[0] != 0) {
        const x = z[0];
        h = (h << 8) +% sqlite3UpperToLower[x];
        z += 1;
        if (h == (('c' << 24) + ('h' << 16) + ('a' << 8) + 'r')) {
            aff = SQLITE_AFF_TEXT;
            zChar = z;
        } else if (h == (('c' << 24) + ('l' << 16) + ('o' << 8) + 'b')) {
            aff = SQLITE_AFF_TEXT;
        } else if (h == (('t' << 24) + ('e' << 16) + ('x' << 8) + 't')) {
            aff = SQLITE_AFF_TEXT;
        } else if (h == (('b' << 24) + ('l' << 16) + ('o' << 8) + 'b') and (aff == SQLITE_AFF_NUMERIC or aff == SQLITE_AFF_REAL)) {
            aff = SQLITE_AFF_BLOB;
            if (z[0] == '(') zChar = z;
        } else if (h == (('r' << 24) + ('e' << 16) + ('a' << 8) + 'l') and aff == SQLITE_AFF_NUMERIC) {
            aff = SQLITE_AFF_REAL;
        } else if (h == (('f' << 24) + ('l' << 16) + ('o' << 8) + 'a') and aff == SQLITE_AFF_NUMERIC) {
            aff = SQLITE_AFF_REAL;
        } else if (h == (('d' << 24) + ('o' << 16) + ('u' << 8) + 'b') and aff == SQLITE_AFF_NUMERIC) {
            aff = SQLITE_AFF_REAL;
        } else if ((h & 0x00FFFFFF) == (('i' << 16) + ('n' << 8) + 't')) {
            aff = SQLITE_AFF_INTEGER;
            break;
        }
    }
    if (pCol != null) {
        var v: c_int = 0;
        if (aff < SQLITE_AFF_NUMERIC) {
            if (zChar != null) {
                var zc = zChar.?;
                while (zc[0] != 0) {
                    if (sqlite3Isdigit(zc[0]) != 0) {
                        _ = sqlite3GetInt32(zc, &v);
                        break;
                    }
                    zc += 1;
                }
            } else {
                v = 16;
            }
        }
        v = @divTrunc(v, 4) + 1;
        if (v > 255) v = 255;
        wr(u8, pCol, Column_szEst, @intCast(v));
    }
    return aff;
}

export fn sqlite3AddDefaultValue(pParse: Cptr, pExpr: Cptr, zStart: [*]const u8, zEnd: [*]const u8) void {
    const db = parseDb(pParse);
    const p = rdp(pParse, Parse_pNewTable);
    if (p != null) {
        const isInit: u8 = @intFromBool(initBusy(db) != 0 and initIDb(db) != 1);
        const pCol = colAt(p, rd(i16, p, Table_nCol) - 1);
        if (sqlite3ExprIsConstantOrFunction(pExpr, isInit) == 0) {
            sqlite3ErrorMsg(pParse, "default value of column [%s] is not constant", rdp(pCol, Column_zCnName));
        } else if ((colFlags(pCol) & COLFLAG_GENERATED) != 0) {
            sqlite3ErrorMsg(pParse, "cannot use DEFAULT on a generated column");
        } else {
            // Expr x; memset; x.op=TK_SPAN; x.u.zToken=DbSpanDup; x.pLeft=pExpr; x.flags=EP_Skip;
            var x: [sizeof_Expr]u8 align(8) = std.mem.zeroes([sizeof_Expr]u8);
            const xp: ?*anyopaque = @ptrCast(&x);
            wr(u8, xp, Expr_op, TK_SPAN);
            const zTok = sqlite3DbSpanDup(db, zStart, zEnd);
            wr(?*anyopaque, xp, Expr_u, @ptrCast(zTok));
            wr(?*anyopaque, xp, Expr_pLeft, pExpr);
            wr(u32, xp, Expr_flags, EP_Skip);
            const pDfltExpr = sqlite3ExprDup(db, xp, EXPRDUP_REDUCE);
            sqlite3DbFree(db, zTok);
            sqlite3ColumnSetExpr(pParse, p, pCol, pDfltExpr);
        }
    }
    if (inRenameObject(pParse)) {
        sqlite3RenameExprUnmap(pParse, pExpr);
    }
    sqlite3ExprDelete(db, pExpr);
}
const sizeof_Expr = off("sizeof_Expr", 72);

fn sqlite3StringToIdLocal(p: Cptr) void {
    if (rd(u8, p, Expr_op) == TK_STRING) {
        wr(u8, p, Expr_op, TK_ID);
    } else if (rd(u8, p, Expr_op) == TK_COLLATE) {
        const pLeft = rdp(p, Expr_pLeft);
        if (rd(u8, pLeft, Expr_op) == TK_STRING) {
            wr(u8, pLeft, Expr_op, TK_ID);
        }
    }
}

fn makeColumnPartOfPrimaryKey(pParse: Cptr, pCol: Cptr) void {
    wr(u16, pCol, Column_colFlags, colFlags(pCol) | COLFLAG_PRIMKEY);
    if ((colFlags(pCol) & COLFLAG_GENERATED) != 0) {
        sqlite3ErrorMsg(pParse, "generated columns cannot be part of the PRIMARY KEY");
    }
}

export fn sqlite3AddPrimaryKey(pParse: Cptr, pListIn: Cptr, onError: c_int, autoInc: c_int, sortOrder: c_int) void {
    var pList = pListIn;
    const pTab = rdp(pParse, Parse_pNewTable);
    var pCol: Cptr = null;
    var iCol: c_int = -1;
    var nTerm: c_int = undefined;
    if (pTab == null) return primaryKeyExit(pParse, pList);
    if ((tabFlags(pTab) & TF_HasPrimaryKey) != 0) {
        sqlite3ErrorMsg(pParse, "table \"%s\" has more than one primary key", rdp(pTab, Table_zName));
        return primaryKeyExit(pParse, pList);
    }
    wr(u32, pTab, Table_tabFlags, tabFlags(pTab) | TF_HasPrimaryKey);
    if (pList == null) {
        iCol = rd(i16, pTab, Table_nCol) - 1;
        pCol = colAt(pTab, iCol);
        makeColumnPartOfPrimaryKey(pParse, pCol);
        nTerm = 1;
    } else {
        nTerm = rd(c_int, pList, ExprList_nExpr);
        const a = elA(pList);
        var i: c_int = 0;
        while (i < nTerm) : (i += 1) {
            const item = base(a) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
            const pCExpr = sqlite3ExprSkipCollate(rdp(@ptrCast(item), ExprList_item_pExpr));
            sqlite3StringToIdLocal(pCExpr);
            if (rd(u8, pCExpr, Expr_op) == TK_ID) {
                iCol = sqlite3ColumnIndex(pTab, @ptrCast(rdp(pCExpr, Expr_u)));
                if (iCol >= 0) {
                    pCol = colAt(pTab, iCol);
                    makeColumnPartOfPrimaryKey(pParse, pCol);
                }
            }
        }
    }
    if (nTerm == 1 and pCol != null and rdColECType(pCol) == COLTYPE_INTEGER and sortOrder != SQLITE_SO_DESC) {
        if (inRenameObject(pParse) and pList != null) {
            const a = elA(pList);
            const pCExpr = sqlite3ExprSkipCollate(rdp(@ptrCast(a), ExprList_item_pExpr));
            sqlite3RenameTokenRemap(pParse, @ptrCast(base(pTab) + Table_iPKey), pCExpr);
        }
        wr(i16, pTab, Table_iPKey, @intCast(iCol));
        wr(u8, pTab, Table_keyConf, @intCast(onError));
        wr(u32, pTab, Table_tabFlags, tabFlags(pTab) | (@as(u32, @intCast(autoInc)) * TF_Autoincrement));
        if (pList != null) {
            const a = elA(pList);
            wr(u8, pParse, Parse_iPkSortOrder, base(a)[ExprList_item_fg_sortFlags]);
        }
        _ = sqlite3HasExplicitNulls(pParse, pList);
    } else if (autoInc != 0) {
        sqlite3ErrorMsg(pParse, "AUTOINCREMENT is only allowed on an INTEGER PRIMARY KEY");
    } else {
        sqlite3CreateIndex(pParse, null, null, null, pList, onError, null, null, sortOrder, 0, SQLITE_IDXTYPE_PRIMARYKEY);
        pList = null;
    }
    return primaryKeyExit(pParse, pList);
}
inline fn rdColECType(pCol: Cptr) u8 {
    return (base(pCol)[Column_bft_byte] >> 4) & 0x0f;
}
fn primaryKeyExit(pParse: Cptr, pList: Cptr) void {
    sqlite3ExprListDelete(parseDb(pParse), pList);
}

export fn sqlite3AddCheckConstraint(pParse: Cptr, pCheckExpr: Cptr, zStart: [*]const u8, zEnd: [*]const u8) void {
    const pTab = rdp(pParse, Parse_pNewTable);
    const db = parseDb(pParse);
    if (pTab != null and !inDeclareVtab(pParse) and sqlite3BtreeIsReadonly(rdp(dbAt(db, initIDb(db)), Db_pBt)) == 0) {
        wr(?*anyopaque, pTab, Table_pCheck, sqlite3ExprListAppend(pParse, rdp(pTab, Table_pCheck), pCheckExpr));
        const cnameN = rd(u32, pParse, Parse_u1_cr_constraintName + Token_n);
        if (cnameN != 0) {
            sqlite3ExprListSetName(pParse, rdp(pTab, Table_pCheck), @ptrCast(base(pParse) + Parse_u1_cr_constraintName), 1);
        } else {
            var t: [sizeof_Token]u8 align(8) = undefined;
            var zs = zStart + 1;
            while (sqlite3Isspace(zs[0]) != 0) zs += 1;
            var ze = zEnd;
            while (sqlite3Isspace((ze - 1)[0]) != 0) ze -= 1;
            const tp: ?*anyopaque = @ptrCast(&t);
            wr([*]const u8, tp, Token_z, zs);
            wr(u32, tp, Token_n, @intCast(@intFromPtr(ze) - @intFromPtr(zs)));
            sqlite3ExprListSetName(pParse, rdp(pTab, Table_pCheck), tp, 1);
        }
    } else {
        sqlite3ExprDelete(db, pCheckExpr);
    }
}

export fn sqlite3AddCollateType(pParse: Cptr, pToken: Cptr) void {
    const p = rdp(pParse, Parse_pNewTable);
    if (p == null or inRenameObject(pParse)) return;
    const i = rd(i16, p, Table_nCol) - 1;
    const db = parseDb(pParse);
    const zColl = sqlite3NameFromToken(db, pToken);
    if (zColl == null) return;
    if (sqlite3LocateCollSeq(pParse, @ptrCast(zColl)) != null) {
        sqlite3ColumnSetColl(db, colAt(p, i), @ptrCast(zColl.?));
        var pIdx = rdp(p, Table_pIndex);
        while (pIdx != null) {
            const aiColumn: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
            if (aiColumn[0] == i) {
                const azColl: [*]?*anyopaque = @ptrCast(@alignCast(rdp(pIdx, Index_azColl).?));
                azColl[0] = @constCast(@ptrCast(sqlite3ColumnColl(colAt(p, i))));
            }
            pIdx = rdp(pIdx, Index_pNext);
        }
    }
    sqlite3DbFree(db, zColl);
}

export fn sqlite3AddGenerated(pParse: Cptr, pExprIn: Cptr, pType: Cptr) void {
    var pExpr = pExprIn;
    var eType: u8 = @intCast(COLFLAG_VIRTUAL);
    const pTab = rdp(pParse, Parse_pNewTable);
    if (pTab == null) return generatedDone(pParse, pExpr);
    const pCol = colAt(pTab, rd(i16, pTab, Table_nCol) - 1);
    if (inDeclareVtab(pParse)) {
        sqlite3ErrorMsg(pParse, "virtual tables cannot use computed columns");
        return generatedDone(pParse, pExpr);
    }
    if (rd(u16, pCol, Column_iDflt) > 0) return generatedError(pParse, pCol, pExpr);
    if (pType != null) {
        const tn = tokenN(pType);
        if (tn == 7 and sqlite3_strnicmp(@ptrCast(tokenZ(pType)), "virtual", 7) == 0) {
            // no-op
        } else if (tn == 6 and sqlite3_strnicmp(@ptrCast(tokenZ(pType)), "stored", 6) == 0) {
            eType = @intCast(COLFLAG_STORED);
        } else {
            return generatedError(pParse, pCol, pExpr);
        }
    }
    if (eType == @as(u8, @intCast(COLFLAG_VIRTUAL))) wr(i16, pTab, Table_nNVCol, rd(i16, pTab, Table_nNVCol) - 1);
    wr(u16, pCol, Column_colFlags, colFlags(pCol) | eType);
    wr(u32, pTab, Table_tabFlags, tabFlags(pTab) | eType);
    if ((colFlags(pCol) & COLFLAG_PRIMKEY) != 0) {
        makeColumnPartOfPrimaryKey(pParse, pCol);
    }
    if (pExpr != null and rd(u8, pExpr, Expr_op) == TK_ID) {
        pExpr = sqlite3PExpr(pParse, TK_UPLUS, pExpr, null);
    }
    if (pExpr != null and rd(u8, pExpr, Expr_op) != TK_RAISE) {
        wr(u8, pExpr, Expr_affExpr, rd(u8, pCol, Column_affinity));
    }
    sqlite3ColumnSetExpr(pParse, pTab, pCol, pExpr);
    pExpr = null;
    return generatedDone(pParse, pExpr);
}
fn generatedError(pParse: Cptr, pCol: Cptr, pExpr: Cptr) void {
    sqlite3ErrorMsg(pParse, "error in generated column \"%s\"", rdp(pCol, Column_zCnName));
    return generatedDone(pParse, pExpr);
}
fn generatedDone(pParse: Cptr, pExpr: Cptr) void {
    sqlite3ExprDelete(parseDb(pParse), pExpr);
}

export fn sqlite3ChangeCookie(pParse: Cptr, iDb: c_int) void {
    const db = parseDb(pParse);
    const v = vdbeOf(pParse);
    const pSchema = dbSchema(db, iDb);
    const cookie = rd(u32, pSchema, Schema_schema_cookie);
    _ = sqlite3VdbeAddOp3(v, OP_SetCookie, iDb, BTREE_SCHEMA_VERSION, @bitCast(1 +% cookie));
}

// ─── Hash iteration helpers ──────────────────────────────────────────────────
inline fn hashFirst(h: ?*anyopaque) ?*anyopaque {
    return rdp(h, 8);
}
inline fn hashNext(e: ?*anyopaque) ?*anyopaque {
    return rdp(e, 0);
}
inline fn hashData(e: ?*anyopaque) ?*anyopaque {
    return rdp(e, 16);
}
const Module_pModule = off("Module_pModule", 0);
const Module_pEpoTabF = off("Module_pEpoTab", 40);
const sqlite3_module_iVersion = off("sqlite3_module_iVersion", 0);
const sqlite3_module_xShadowName = off("sqlite3_module_xShadowName", 184);
const ShadowNameFn = *const fn (?[*:0]const u8) callconv(.c) c_int;

export fn sqlite3IsShadowTableOf(db: Cptr, pTab: Cptr, zName: [*:0]const u8) c_int {
    if (!isVirtual(pTab)) return 0;
    const zTabName: ?[*:0]const u8 = @ptrCast(rdp(pTab, Table_zName));
    const nName = sqlite3Strlen30(zTabName);
    if (sqlite3_strnicmp(zName, zTabName, nName) != 0) return 0;
    if (zName[@intCast(nName)] != '_') return 0;
    const azArg: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pTab, Table_u_vtab_azArg).?));
    const pMod = sqlite3HashFind(@ptrCast(base(db) + sqlite3_aModule), azArg[0]);
    if (pMod == null) return 0;
    const pModule = rdp(pMod, Module_pModule);
    if (rd(c_int, pModule, sqlite3_module_iVersion) < 3) return 0;
    const xShadow = rdp(pModule, sqlite3_module_xShadowName);
    if (xShadow == null) return 0;
    const f: ShadowNameFn = @ptrCast(xShadow);
    return f(@ptrCast(@as([*]const u8, @ptrCast(zName)) + @as(usize, @intCast(nName)) + 1));
}

export fn sqlite3MarkAllShadowTablesOf(db: Cptr, pTab: Cptr) void {
    const azArg: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pTab, Table_u_vtab_azArg).?));
    const pMod = sqlite3HashFind(@ptrCast(base(db) + sqlite3_aModule), azArg[0]);
    if (pMod == null) return;
    const pModule = rdp(pMod, Module_pModule);
    if (pModule == null) return;
    if (rd(c_int, pModule, sqlite3_module_iVersion) < 3) return;
    const xShadow = rdp(pModule, sqlite3_module_xShadowName);
    if (xShadow == null) return;
    const f: ShadowNameFn = @ptrCast(xShadow);
    const zTabName: [*:0]const u8 = @ptrCast(rdp(pTab, Table_zName).?);
    const nName = sqlite3Strlen30(zTabName);
    var k = hashFirst(@ptrCast(base(rdp(pTab, Table_pSchema)) + Schema_tblHash));
    while (k != null) : (k = hashNext(k)) {
        const pOther = hashData(k);
        if (!isOrdinaryTable(pOther)) continue;
        if ((tabFlags(pOther) & TF_Shadow) != 0) continue;
        const zOther: [*:0]const u8 = @ptrCast(rdp(pOther, Table_zName).?);
        if (sqlite3_strnicmp(zOther, zTabName, nName) == 0 and zOther[@intCast(nName)] == '_' and f(@ptrCast(@as([*]const u8, @ptrCast(zOther)) + @as(usize, @intCast(nName)) + 1)) != 0) {
            wr(u32, pOther, Table_tabFlags, tabFlags(pOther) | TF_Shadow);
        }
    }
}

export fn sqlite3ShadowTableName(db: Cptr, zName: [*:0]const u8) c_int {
    const zTail = strrchr(zName, '_');
    if (zTail == null) return 0;
    const zCopy = sqlite3DbStrNDup(db, @ptrCast(zName), @intCast(@intFromPtr(zTail.?) - @intFromPtr(zName)));
    const pTab = if (zCopy != null) sqlite3FindTable(db, @ptrCast(zCopy), null) else null;
    sqlite3DbFree(db, zCopy);
    if (pTab == null) return 0;
    if (!isVirtual(pTab)) return 0;
    return sqlite3IsShadowTableOf(db, pTab, zName);
}
fn strrchr(s: [*:0]const u8, ch: u8) ?[*:0]const u8 {
    var last: ?[*:0]const u8 = null;
    var p: [*:0]const u8 = s;
    while (p[0] != 0) : (p += 1) {
        if (p[0] == ch) last = p;
    }
    return last;
}

// markExprListImmutable — SQLITE_DEBUG only (real in testfixture, no-op in prod)
fn markImmutableExprStep(pWalker: Cptr, pExpr: Cptr) callconv(.c) c_int {
    _ = pWalker;
    _ = pExpr;
    return WRC_Continue;
}
fn markExprListImmutable(pList: Cptr) void {
    if (!config.sqlite_debug) return;
    if (pList != null) {
        var w: [sizeof_Walker]u8 align(8) = std.mem.zeroes([sizeof_Walker]u8);
        const wp: ?*anyopaque = @ptrCast(&w);
        wr(?*anyopaque, wp, Walker_xExprCallback, @constCast(@ptrCast(&markImmutableExprStep)));
        wr(?*anyopaque, wp, Walker_xSelectCallback, @constCast(@ptrCast(&sqlite3SelectWalkNoop)));
        wr(?*anyopaque, wp, Walker_xSelectCallback2, null);
        _ = sqlite3WalkExprList(wp, pList);
    }
}
const sizeof_Walker = off("sizeof_Walker", 48);
const Walker_xExprCallback = off("Walker_xExprCallback", 8);
const Walker_xSelectCallback = off("Walker_xSelectCallback", 16);
const Walker_xSelectCallback2 = off("Walker_xSelectCallback2", 24);

export fn sqlite3EndTable(pParse: Cptr, pCons: Cptr, pEnd: Cptr, tabOpts: u32, pSelect: Cptr) void {
    const db = parseDb(pParse);
    if (pEnd == null and pSelect == null) return;
    const p = rdp(pParse, Parse_pNewTable);
    if (p == null) return;

    if (pSelect == null and sqlite3ShadowTableName(db, @ptrCast(rdp(p, Table_zName).?)) != 0) {
        wr(u32, p, Table_tabFlags, tabFlags(p) | TF_Shadow);
    }

    if (initBusy(db) != 0) {
        if (pSelect != null or (!isOrdinaryTable(p) and initNewTnum(db) != 0)) {
            sqlite3ErrorMsg(pParse, "");
            return;
        }
        wr(u32, p, Table_tnum, initNewTnum(db));
        if (rd(u32, p, Table_tnum) == 1) wr(u32, p, Table_tabFlags, tabFlags(p) | TF_Readonly);
    }

    if ((tabOpts & TF_Strict) != 0) {
        wr(u32, p, Table_tabFlags, tabFlags(p) | TF_Strict);
        var ii: c_int = 0;
        const nCol = rd(i16, p, Table_nCol);
        while (ii < nCol) : (ii += 1) {
            const pCol = colAt(p, ii);
            const ect = rdColECType(pCol);
            if (ect == COLTYPE_CUSTOM) {
                if ((colFlags(pCol) & COLFLAG_HASTYPE) != 0) {
                    sqlite3ErrorMsg(pParse, "unknown datatype for %s.%s: \"%s\"", rdp(p, Table_zName), rdp(pCol, Column_zCnName), sqlite3ColumnType(pCol, ""));
                } else {
                    sqlite3ErrorMsg(pParse, "missing datatype for %s.%s", rdp(p, Table_zName), rdp(pCol, Column_zCnName));
                }
                return;
            } else if (ect == COLTYPE_ANY) {
                wr(u8, pCol, Column_affinity, SQLITE_AFF_BLOB);
            }
            if ((colFlags(pCol) & COLFLAG_PRIMKEY) != 0 and rd(i16, p, Table_iPKey) != ii and (base(pCol)[Column_bft_byte] & 0x0f) == @as(u8, @intCast(OE_None))) {
                base(pCol)[Column_bft_byte] = (base(pCol)[Column_bft_byte] & 0xf0) | (@as(u8, @intCast(OE_Abort)) & 0x0f);
                wr(u32, p, Table_tabFlags, tabFlags(p) | TF_HasNotNull);
            }
        }
    }

    if ((tabOpts & TF_WithoutRowid) != 0) {
        if ((tabFlags(p) & TF_Autoincrement) != 0) {
            sqlite3ErrorMsg(pParse, "AUTOINCREMENT not allowed on WITHOUT ROWID tables");
            return;
        }
        if ((tabFlags(p) & TF_HasPrimaryKey) == 0) {
            sqlite3ErrorMsg(pParse, "PRIMARY KEY missing on table %s", rdp(p, Table_zName));
            return;
        }
        wr(u32, p, Table_tabFlags, tabFlags(p) | TF_WithoutRowid | TF_NoVisibleRowid);
        convertToWithoutRowidTable(pParse, p);
    }
    const iDb = sqlite3SchemaToIndex(db, rdp(p, Table_pSchema));

    if (rdp(p, Table_pCheck) != null) {
        _ = sqlite3ResolveSelfReference(pParse, p, NC_IsCheck, null, rdp(p, Table_pCheck));
        if (rd(c_int, pParse, Parse_nErr) != 0) {
            sqlite3ExprListDelete(db, rdp(p, Table_pCheck));
            wr(?*anyopaque, p, Table_pCheck, null);
        } else {
            markExprListImmutable(rdp(p, Table_pCheck));
        }
    }

    if ((tabFlags(p) & TF_HasGenerated) != 0) {
        var ii: c_int = 0;
        var nNG: c_int = 0;
        const nCol = rd(i16, p, Table_nCol);
        while (ii < nCol) : (ii += 1) {
            const cf = colFlags(colAt(p, ii));
            if ((cf & COLFLAG_GENERATED) != 0) {
                const pX = sqlite3ColumnExpr(p, colAt(p, ii));
                if (sqlite3ResolveSelfReference(pParse, p, NC_GenCol, pX, null) != 0) {
                    sqlite3ColumnSetExpr(pParse, p, colAt(p, ii), sqlite3ExprAlloc(db, TK_NULL, null, 0));
                }
            } else {
                nNG += 1;
            }
        }
        if (nNG == 0) {
            sqlite3ErrorMsg(pParse, "must have at least one non-generated column");
            return;
        }
    }

    estimateTableWidth(p);
    var pIdx = rdp(p, Table_pIndex);
    while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
        estimateIndexWidth(pIdx);
    }

    if (initBusy(db) == 0) {
        const v = sqlite3GetVdbe(pParse);
        if (v == null) return;
        _ = sqlite3VdbeAddOp1(v, OP_Close, 0);

        var zType: [*:0]const u8 = undefined;
        var zType2: [*:0]const u8 = undefined;
        if (isOrdinaryTable(p)) {
            zType = "table";
            zType2 = "TABLE";
        } else {
            zType = "view";
            zType2 = "VIEW";
        }

        if (pSelect != null) {
            if (inSpecialParse(pParse)) {
                wr(c_int, pParse, Parse_rc, SQLITE_ERROR);
                wr(c_int, pParse, Parse_nErr, rd(c_int, pParse, Parse_nErr) + 1);
                return;
            }
            const iCsr = rd(c_int, pParse, Parse_nTab);
            wr(c_int, pParse, Parse_nTab, iCsr + 1);
            const regYield = rd(c_int, pParse, Parse_nMem) + 1;
            const regRec = regYield + 1;
            const regRowid = regRec + 1;
            wr(c_int, pParse, Parse_nMem, regRowid);
            sqlite3MayAbort(pParse);
            _ = sqlite3VdbeAddOp3(v, OP_OpenWrite, iCsr, rd(c_int, pParse, Parse_u1_cr_regRoot), iDb);
            sqlite3VdbeChangeP5(v, OPFLAG_P2ISREG);
            const addrTop = sqlite3VdbeCurrentAddr(v) + 1;
            _ = sqlite3VdbeAddOp3(v, OP_InitCoroutine, regYield, 0, addrTop);
            if (rd(c_int, pParse, Parse_nErr) != 0) return;
            const pSelTab = sqlite3ResultSetOfSelect(pParse, pSelect, SQLITE_AFF_BLOB);
            if (pSelTab == null) return;
            wr(i16, p, Table_nCol, rd(i16, pSelTab, Table_nCol));
            wr(i16, p, Table_nNVCol, rd(i16, pSelTab, Table_nCol));
            wr(?*anyopaque, p, Table_aCol, rdp(pSelTab, Table_aCol));
            wr(i16, pSelTab, Table_nCol, 0);
            wr(?*anyopaque, pSelTab, Table_aCol, null);
            sqlite3DeleteTable(db, pSelTab);
            var dest: [sizeof_SelectDest]u8 align(8) = undefined;
            sqlite3SelectDestInit(@ptrCast(&dest), SRT_Coroutine, regYield);
            _ = sqlite3Select(pParse, pSelect, @ptrCast(&dest));
            if (rd(c_int, pParse, Parse_nErr) != 0) return;
            sqlite3VdbeEndCoroutine(v, regYield);
            sqlite3VdbeJumpHere(v, addrTop - 1);
            const iSDParm = rd(c_int, @ptrCast(&dest), SelectDest_iSDParm);
            const addrInsLoop = sqlite3VdbeAddOp1(v, OP_Yield, iSDParm);
            const iSdst = rd(c_int, @ptrCast(&dest), SelectDest_iSdst);
            const nSdst = rd(c_int, @ptrCast(&dest), SelectDest_nSdst);
            _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, iSdst, nSdst, regRec);
            sqlite3TableAffinity(v, p, 0);
            _ = sqlite3VdbeAddOp2(v, OP_NewRowid, iCsr, regRowid);
            _ = sqlite3VdbeAddOp3(v, OP_Insert, iCsr, regRec, regRowid);
            _ = sqlite3VdbeGoto(v, addrInsLoop);
            sqlite3VdbeJumpHere(v, addrInsLoop);
            _ = sqlite3VdbeAddOp1(v, OP_Close, iCsr);
        }

        var zStmt: ?[*:0]u8 = undefined;
        if (pSelect != null) {
            zStmt = createTableStmt(db, p);
        } else {
            const pEnd2 = if (tabOpts != 0) @as(Cptr, @ptrCast(base(pParse) + Parse_sLastToken)) else pEnd;
            const nameTokZ = rdp(pParse, Parse_sNameToken + Token_z);
            var n: c_int = @intCast(@intFromPtr(tokenZ(pEnd2).?) - @intFromPtr(nameTokZ.?));
            if (tokenZ(pEnd2).?[0] != ';') n += @intCast(tokenN(pEnd2));
            zStmt = sqlite3MPrintf(db, "CREATE %s %.*s", zType2, n, nameTokZ);
        }

        sqlite3NestedParse(pParse, "UPDATE %Q." ++ LEGACY_SCHEMA_TABLE ++ " SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d", dbZName(db, iDb), zType, rdp(p, Table_zName), rdp(p, Table_zName), rd(c_int, pParse, Parse_u1_cr_regRoot), zStmt, rd(c_int, pParse, Parse_u1_cr_regRowid));
        sqlite3DbFree(db, zStmt);
        sqlite3ChangeCookie(pParse, iDb);

        if ((tabFlags(p) & TF_Autoincrement) != 0 and !inSpecialParse(pParse)) {
            const pDb = dbAt(db, iDb);
            if (rdp(rdp(pDb, Db_pSchema), Schema_pSeqTab) == null) {
                sqlite3NestedParse(pParse, "CREATE TABLE %Q.sqlite_sequence(name,seq)", dbZName(db, iDb));
            }
        }

        sqlite3VdbeAddParseSchemaOp(v, iDb, sqlite3MPrintf(db, "tbl_name='%q' AND type!='trigger'", rdp(p, Table_zName)), 0);

        if ((tabFlags(p) & TF_HasGenerated) != 0) {
            _ = sqlite3VdbeAddOp4(v, OP_SqlExec, 0x0001, 0, 0, @ptrCast(sqlite3MPrintf(db, "SELECT*FROM\"%w\".\"%w\"", dbZName(db, iDb), rdp(p, Table_zName))), P4_DYNAMIC);
        }
    }

    if (initBusy(db) != 0) {
        const pSchema = rdp(p, Table_pSchema);
        const pOld = sqlite3HashInsert(@ptrCast(base(pSchema) + Schema_tblHash), @ptrCast(rdp(p, Table_zName)), p);
        if (pOld != null) {
            sqlite3OomFault(db);
            return;
        }
        wr(?*anyopaque, pParse, Parse_pNewTable, null);
        wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) | DBFLAG_SchemaChange);
        if (strcmp0(@ptrCast(rdp(p, Table_zName)), "sqlite_sequence") == 0) {
            wr(?*anyopaque, rdp(p, Table_pSchema), Schema_pSeqTab, p);
        }
    }

    if (pSelect == null and isOrdinaryTable(p)) {
        var pc = pCons;
        if (tokenZ(pc) == null) {
            pc = pEnd;
        }
        const nameTokZ = rdp(pParse, Parse_sNameToken + Token_z);
        const diff: isize = @as(isize, @bitCast(@intFromPtr(tokenZ(pc).?))) - @as(isize, @bitCast(@intFromPtr(nameTokZ.?)));
        wr(c_int, p, Table_u_tab_addColOffset, @truncate(13 + diff));
    }
}
const sizeof_SelectDest = off("sizeof_SelectDest", 40);
const SelectDest_iSDParm = off("SelectDest_iSDParm", 4);
const SelectDest_iSdst = off("SelectDest_iSdst", 12);
const SelectDest_nSdst = off("SelectDest_nSdst", 16);
fn strcmp0(a: [*:0]const u8, b: [*:0]const u8) c_int {
    var i: usize = 0;
    while (a[i] == b[i] and a[i] != 0) i += 1;
    return @as(c_int, a[i]) - @as(c_int, b[i]);
}

export fn sqlite3CreateView(pParse: Cptr, pBegin: Cptr, pName1: Cptr, pName2: Cptr, pCNames: Cptr, pSelectIn: Cptr, isTemp: c_int, noErr: c_int) void {
    var pSelect = pSelectIn;
    const db = parseDb(pParse);
    if (rd(i16, pParse, Parse_nVar) > 0) {
        sqlite3ErrorMsg(pParse, "parameters are not allowed in views");
        return createViewFail(pParse, db, pSelect, pCNames);
    }
    sqlite3StartTable(pParse, pName1, pName2, isTemp, 1, 0, noErr);
    const p = rdp(pParse, Parse_pNewTable);
    if (p == null or rd(c_int, pParse, Parse_nErr) != 0) return createViewFail(pParse, db, pSelect, pCNames);

    wr(u32, p, Table_tabFlags, tabFlags(p) | TF_NoVisibleRowid);

    var pName: Cptr = null;
    _ = sqlite3TwoPartName(pParse, pName1, pName2, &pName);
    const iDb = sqlite3SchemaToIndex(db, rdp(p, Table_pSchema));
    var sFix: [sizeof_DbFixer]u8 align(8) = undefined;
    sqlite3FixInit(@ptrCast(&sFix), pParse, iDb, "view", pName);
    if (sqlite3FixSelect(@ptrCast(&sFix), pSelect) != 0) return createViewFail(pParse, db, pSelect, pCNames);

    wr(u32, pSelect, Select_selFlags, rd(u32, pSelect, Select_selFlags) | SF_View);
    if (inRenameObject(pParse)) {
        wr(?*anyopaque, p, Table_u_view_pSelect, pSelect);
        pSelect = null;
    } else {
        wr(?*anyopaque, p, Table_u_view_pSelect, sqlite3SelectDup(db, pSelect, EXPRDUP_REDUCE));
    }
    wr(?*anyopaque, p, Table_pCheck, sqlite3ExprListDup(db, pCNames, EXPRDUP_REDUCE));
    wr(u8, p, Table_eTabType, TABTYP_VIEW);
    if (mallocFailed(db)) return createViewFail(pParse, db, pSelect, pCNames);

    // Locate end of CREATE VIEW
    var sEnd: [sizeof_Token]u8 align(8) = undefined;
    @memcpy(sEnd[0..sizeof_Token], (base(pParse) + Parse_sLastToken)[0..sizeof_Token]);
    const sp: ?*anyopaque = @ptrCast(&sEnd);
    var sEndZ = tokenZ(sp).?;
    if (sEndZ[0] != ';') {
        sEndZ += tokenN(sp);
        wr([*]const u8, sp, Token_z, sEndZ);
    }
    wr(u32, sp, Token_n, 0);
    const beginZ = tokenZ(pBegin).?;
    var n: c_int = @intCast(@intFromPtr(tokenZ(sp).?) - @intFromPtr(beginZ));
    const z = beginZ;
    while (sqlite3Isspace(z[@intCast(n - 1)]) != 0) n -= 1;
    wr([*]const u8, sp, Token_z, z + @as(usize, @intCast(n - 1)));
    wr(u32, sp, Token_n, 1);

    sqlite3EndTable(pParse, null, sp, 0, null);

    return createViewFail(pParse, db, pSelect, pCNames);
}
const sizeof_DbFixer = off("sizeof_DbFixer", 56);
fn createViewFail(pParse: Cptr, db: Cptr, pSelect: Cptr, pCNames: Cptr) void {
    sqlite3SelectDelete(db, pSelect);
    if (inRenameObject(pParse)) {
        sqlite3RenameExprlistUnmap(pParse, pCNames);
    }
    sqlite3ExprListDelete(db, pCNames);
}

fn viewGetColumnNames(pParse: Cptr, pTable: Cptr) c_int {
    var nErr: c_int = 0;
    const db = parseDb(pParse);

    if (isVirtual(pTable)) {
        wr(c_int, db, sqlite3_nSchemaLock, rd(c_int, db, sqlite3_nSchemaLock) + 1);
        const rc = sqlite3VtabCallConnect(pParse, pTable);
        wr(c_int, db, sqlite3_nSchemaLock, rd(c_int, db, sqlite3_nSchemaLock) - 1);
        return rc;
    }

    if (rd(i16, pTable, Table_nCol) < 0) {
        sqlite3ErrorMsg(pParse, "view %s is circularly defined", rdp(pTable, Table_zName));
        return 1;
    }

    const pSel = sqlite3SelectDup(db, rdp(pTable, Table_u_view_pSelect), 0);
    if (pSel != null) {
        const eParseMode = parseMode(pParse);
        const nTab = rd(c_int, pParse, Parse_nTab);
        const nSelect = rd(c_int, pParse, Parse_nSelect);
        wr(u8, pParse, Parse_eParseMode, PARSE_MODE_NORMAL);
        sqlite3SrcListAssignCursors(pParse, rdp(pSel, Select_pSrc));
        wr(i16, pTable, Table_nCol, -1);
        // DisableLookaside
        wr(u32, db, sqlite3_lookaside_bDisable, rd(u32, db, sqlite3_lookaside_bDisable) + 1);
        wr(u16, db, sqlite3_lookaside_sz, 0); // sz is u16 — a u32 write spills into szTrue@438
        // Save xAuth, set 0
        const xAuth = rdp(db, sqlite3_xAuth);
        wr(?*anyopaque, db, sqlite3_xAuth, null);
        const pSelTab = sqlite3ResultSetOfSelect(pParse, pSel, SQLITE_AFF_NONE);
        wr(?*anyopaque, db, sqlite3_xAuth, xAuth);
        wr(c_int, pParse, Parse_nTab, nTab);
        wr(c_int, pParse, Parse_nSelect, nSelect);
        if (pSelTab == null) {
            wr(i16, pTable, Table_nCol, 0);
            nErr += 1;
        } else if (rdp(pTable, Table_pCheck) != null) {
            _ = sqlite3ColumnsFromExprList(pParse, rdp(pTable, Table_pCheck), @ptrCast(@alignCast(base(pTable) + Table_nCol)), @ptrCast(@alignCast(base(pTable) + Table_aCol)));
            if (rd(c_int, pParse, Parse_nErr) == 0 and rd(i16, pTable, Table_nCol) == rd(c_int, rdp(pSel, Select_pEList), ExprList_nExpr)) {
                sqlite3SubqueryColumnTypes(pParse, pTable, pSel, SQLITE_AFF_NONE);
            }
        } else {
            wr(i16, pTable, Table_nCol, rd(i16, pSelTab, Table_nCol));
            wr(?*anyopaque, pTable, Table_aCol, rdp(pSelTab, Table_aCol));
            wr(u32, pTable, Table_tabFlags, tabFlags(pTable) | (tabFlags(pSelTab) & COLFLAG_NOINSERT));
            wr(i16, pSelTab, Table_nCol, 0);
            wr(?*anyopaque, pSelTab, Table_aCol, null);
        }
        wr(i16, pTable, Table_nNVCol, rd(i16, pTable, Table_nCol));
        sqlite3DeleteTable(db, pSelTab);
        sqlite3SelectDelete(db, pSel);
        // EnableLookaside
        wr(u32, db, sqlite3_lookaside_bDisable, rd(u32, db, sqlite3_lookaside_bDisable) - 1);
        wr(u16, db, sqlite3_lookaside_sz, lookasideSzRestore(db));
        wr(u8, pParse, Parse_eParseMode, eParseMode);
    } else {
        nErr += 1;
    }
    wr(u32, rdp(pTable, Table_pSchema), Schema_schemaFlags, rd(u32, rdp(pTable, Table_pSchema), Schema_schemaFlags) | DB_UnresetViews);
    if (mallocFailed(db)) {
        sqlite3DeleteColumnNames(db, pTable);
    }
    return nErr + rd(c_int, pParse, Parse_nErr);
}
const COLFLAG_NOINSERT_u32: u32 = 0x0062;
const sqlite3_lookaside_szTrue = off("sqlite3_lookaside_szTrue", 438);
inline fn lookasideSzRestore(db: Cptr) u16 {
    // EnableLookaside sets sz = bDisable ? 0 : szTrue. sz/szTrue are u16; using
    // u32 here clobbered szTrue (→0), so sqlite3DbMallocSize returned garbage
    // and growOpArray's realloc dropped emitted opcodes — corrupting any view query.
    return if (rd(u32, db, sqlite3_lookaside_bDisable) != 0) 0 else rd(u16, db, sqlite3_lookaside_szTrue);
}

export fn sqlite3ViewGetColumnNames(pParse: Cptr, pTable: Cptr) c_int {
    if (!isVirtual(pTable) and rd(i16, pTable, Table_nCol) > 0) return 0;
    return viewGetColumnNames(pParse, pTable);
}

fn sqliteViewResetAll(db: Cptr, idx: c_int) void {
    if (!dbHasProperty(db, idx, DB_UnresetViews)) return;
    var i = hashFirst(@ptrCast(base(dbSchema(db, idx)) + Schema_tblHash));
    while (i != null) : (i = hashNext(i)) {
        const pTab = hashData(i);
        if (isViewTab(pTab)) {
            sqlite3DeleteColumnNames(db, pTab);
        }
    }
    dbClearProperty(db, idx, DB_UnresetViews);
}

export fn sqlite3RootPageMoved(db: Cptr, iDb: c_int, iFrom: u32, iTo: u32) void {
    const pDb = dbAt(db, iDb);
    var pHash = base(rdp(pDb, Db_pSchema)) + Schema_tblHash;
    var pElem = hashFirst(@ptrCast(pHash));
    while (pElem != null) : (pElem = hashNext(pElem)) {
        const pTab = hashData(pElem);
        if (rd(u32, pTab, Table_tnum) == iFrom) wr(u32, pTab, Table_tnum, iTo);
    }
    pHash = base(rdp(pDb, Db_pSchema)) + Schema_idxHash;
    pElem = hashFirst(@ptrCast(pHash));
    while (pElem != null) : (pElem = hashNext(pElem)) {
        const pIdx = hashData(pElem);
        if (rd(u32, pIdx, Index_tnum) == iFrom) wr(u32, pIdx, Index_tnum, iTo);
    }
}

fn destroyRootPage(pParse: Cptr, iTable: c_int, iDb: c_int) void {
    const v = sqlite3GetVdbe(pParse);
    const r1 = sqlite3GetTempReg(pParse);
    if (iTable < 2) sqlite3ErrorMsg(pParse, "corrupt schema");
    _ = sqlite3VdbeAddOp3(v, OP_Destroy, iTable, r1, iDb);
    sqlite3MayAbort(pParse);
    sqlite3NestedParse(pParse, "UPDATE %Q." ++ LEGACY_SCHEMA_TABLE ++ " SET rootpage=%d WHERE #%d AND rootpage=#%d", dbZName(parseDb(pParse), iDb), iTable, r1, r1);
    sqlite3ReleaseTempReg(pParse, r1);
}

fn destroyTable(pParse: Cptr, pTab: Cptr) void {
    const iTab = rd(u32, pTab, Table_tnum);
    var iDestroyed: u32 = 0;
    while (true) {
        var iLargest: u32 = 0;
        if (iDestroyed == 0 or iTab < iDestroyed) {
            iLargest = iTab;
        }
        var pIdx = rdp(pTab, Table_pIndex);
        while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
            const iIdx = rd(u32, pIdx, Index_tnum);
            if ((iDestroyed == 0 or iIdx < iDestroyed) and iIdx > iLargest) {
                iLargest = iIdx;
            }
        }
        if (iLargest == 0) {
            return;
        } else {
            const iDb = sqlite3SchemaToIndex(parseDb(pParse), rdp(pTab, Table_pSchema));
            destroyRootPage(pParse, @intCast(iLargest), iDb);
            iDestroyed = iLargest;
        }
    }
}

export fn sqlite3ClearStatTables(pParse: Cptr, iDb: c_int, zType: [*:0]const u8, zName: [*:0]const u8) void {
    const zDbName = dbZName(parseDb(pParse), iDb);
    var i: c_int = 1;
    while (i <= 4) : (i += 1) {
        var zTab: [24]u8 = undefined;
        _ = sqlite3_snprintf(24, &zTab, "sqlite_stat%d", i);
        if (sqlite3FindTable(parseDb(pParse), @ptrCast(&zTab), zDbName) != null) {
            sqlite3NestedParse(pParse, "DELETE FROM %Q.%s WHERE %s=%Q", zDbName, @as([*:0]const u8, @ptrCast(&zTab)), zType, zName);
        }
    }
}

export fn sqlite3CodeDropTable(pParse: Cptr, pTab: Cptr, iDb: c_int, isView: c_int) void {
    const db = parseDb(pParse);
    const pDb = dbAt(db, iDb);
    const v = sqlite3GetVdbe(pParse);
    sqlite3BeginWriteOperation(pParse, 1, iDb);

    if (isVirtual(pTab)) {
        _ = sqlite3VdbeAddOp0(v, OP_VBegin);
    }

    var pTrigger = sqlite3TriggerList(pParse, pTab);
    while (pTrigger != null) {
        sqlite3DropTriggerPtr(pParse, pTrigger);
        pTrigger = rdp(pTrigger, Trigger_pNext);
    }

    if ((tabFlags(pTab) & TF_Autoincrement) != 0) {
        sqlite3NestedParse(pParse, "DELETE FROM %Q.sqlite_sequence WHERE name=%Q", rdp(pDb, Db_zDbSName), rdp(pTab, Table_zName));
    }

    sqlite3NestedParse(pParse, "DELETE FROM %Q." ++ LEGACY_SCHEMA_TABLE ++ " WHERE tbl_name=%Q and type!='trigger'", rdp(pDb, Db_zDbSName), rdp(pTab, Table_zName));
    if (isView == 0 and !isVirtual(pTab)) {
        destroyTable(pParse, pTab);
    }

    if (isVirtual(pTab)) {
        _ = sqlite3VdbeAddOp4(v, OP_VDestroy, iDb, 0, 0, @ptrCast(rdp(pTab, Table_zName)), 0);
        sqlite3MayAbort(pParse);
    }
    _ = sqlite3VdbeAddOp4(v, OP_DropTable, iDb, 0, 0, @ptrCast(rdp(pTab, Table_zName)), 0);
    sqlite3ChangeCookie(pParse, iDb);
    sqliteViewResetAll(db, iDb);
}

export fn sqlite3ReadOnlyShadowTables(db: Cptr) c_int {
    if ((rd(u64, db, sqlite3_flags) & SQLITE_Defensive) != 0 and rdp(db, sqlite3_pVtabCtx) == null and rd(c_int, db, sqlite3_nVdbeExec) == 0 and !vtabInSync(db)) {
        return 1;
    }
    return 0;
}
const sqlite3_nVTrans = off("sqlite3_nVTrans", 600);
const sqlite3_aVTrans = off("sqlite3_aVTrans", 592);
inline fn vtabInSync(db: Cptr) bool {
    return rd(c_int, db, sqlite3_nVTrans) > 0 and rdp(db, sqlite3_aVTrans) == null;
}

fn tableMayNotBeDropped(db: Cptr, pTab: Cptr) bool {
    const zName: [*:0]const u8 = @ptrCast(rdp(pTab, Table_zName).?);
    if (sqlite3_strnicmp(zName, "sqlite_", 7) == 0) {
        if (sqlite3_strnicmp(@ptrCast(zNamePlus7(zName)), "stat", 4) == 0) return false;
        if (sqlite3_strnicmp(@ptrCast(zNamePlus7(zName)), "parameters", 10) == 0) return false;
        return true;
    }
    if ((tabFlags(pTab) & TF_Shadow) != 0 and sqlite3ReadOnlyShadowTables(db) != 0) {
        return true;
    }
    if ((tabFlags(pTab) & TF_Eponymous) != 0) {
        return true;
    }
    return false;
}

export fn sqlite3DropTable(pParse: Cptr, pName: Cptr, isView: c_int, noErr: c_int) void {
    const db = parseDb(pParse);
    if (mallocFailed(db)) return dropTableExit(db, pName);
    if (sqlite3ReadSchema(pParse) != 0) return dropTableExit(db, pName);
    if (noErr != 0) wr(c_int, db, sqlite3_suppressErr, rd(c_int, db, sqlite3_suppressErr) + 1);
    const aItem: Cptr = @ptrCast(base(pName) + SrcList_a);
    const pTab = sqlite3LocateTableItem(pParse, @intCast(isView), aItem);
    if (noErr != 0) wr(c_int, db, sqlite3_suppressErr, rd(c_int, db, sqlite3_suppressErr) - 1);

    if (pTab == null) {
        if (noErr != 0) {
            sqlite3CodeVerifyNamedSchema(pParse, @ptrCast(rdp(aItem, SrcItem_u4)));
            sqlite3ForceNotReadOnly(pParse);
        }
        return dropTableExit(db, pName);
    }
    const iDb = sqlite3SchemaToIndex(db, rdp(pTab, Table_pSchema));

    if (isVirtual(pTab) and sqlite3ViewGetColumnNames(pParse, pTab) != 0) {
        return dropTableExit(db, pName);
    }
    {
        var code: c_int = undefined;
        const zTab = schemaTable(iDb);
        const zDb = dbZName(db, iDb);
        var zArg2: ?[*:0]const u8 = null;
        if (sqlite3AuthCheck(pParse, SQLITE_DELETE, zTab, null, zDb) != 0) {
            return dropTableExit(db, pName);
        }
        if (isView != 0) {
            code = if (OMIT_TEMPDB == 0 and iDb == 1) SQLITE_DROP_TEMP_VIEW else SQLITE_DROP_VIEW;
        } else if (isVirtual(pTab)) {
            code = SQLITE_DROP_VTABLE;
            zArg2 = vtableModZName(sqlite3GetVTable(db, pTab));
        } else {
            code = if (OMIT_TEMPDB == 0 and iDb == 1) SQLITE_DROP_TEMP_TABLE else SQLITE_DROP_TABLE;
        }
        if (sqlite3AuthCheck(pParse, code, @ptrCast(rdp(pTab, Table_zName)), zArg2, zDb) != 0) {
            return dropTableExit(db, pName);
        }
        if (sqlite3AuthCheck(pParse, SQLITE_DELETE, @ptrCast(rdp(pTab, Table_zName)), null, zDb) != 0) {
            return dropTableExit(db, pName);
        }
    }
    if (tableMayNotBeDropped(db, pTab)) {
        sqlite3ErrorMsg(pParse, "table %s may not be dropped", rdp(pTab, Table_zName));
        return dropTableExit(db, pName);
    }

    if (isView != 0 and !isViewTab(pTab)) {
        sqlite3ErrorMsg(pParse, "use DROP TABLE to delete table %s", rdp(pTab, Table_zName));
        return dropTableExit(db, pName);
    }
    if (isView == 0 and isViewTab(pTab)) {
        sqlite3ErrorMsg(pParse, "use DROP VIEW to delete view %s", rdp(pTab, Table_zName));
        return dropTableExit(db, pName);
    }

    const v = sqlite3GetVdbe(pParse);
    if (v != null) {
        sqlite3BeginWriteOperation(pParse, 1, iDb);
        if (isView == 0) {
            sqlite3ClearStatTables(pParse, iDb, "tbl", @ptrCast(rdp(pTab, Table_zName).?));
            sqlite3FkDropTable(pParse, pName, pTab);
        }
        sqlite3CodeDropTable(pParse, pTab, iDb, isView);
    }
    return dropTableExit(db, pName);
}
fn dropTableExit(db: Cptr, pName: Cptr) void {
    sqlite3SrcListDelete(db, pName);
}
// VTable->pMod->zName : VTable.pMod (offset), Module.zName (offset 8)
const VTable_pMod = off("VTable_pMod", 8);
// We need pMod->zName; compute via two derefs — but extern fn returns VTable*.
// Provide a helper offset chain by reading pMod (VTable.pMod) then Module.zName.
const Module_zName: usize = 8;
inline fn vtableModZName(vt: Cptr) ?[*:0]const u8 {
    const pMod = rdp(vt, VTable_pMod);
    return @ptrCast(rdp(pMod, Module_zName));
}

export fn sqlite3CreateForeignKey(pParse: Cptr, pFromCol: Cptr, pTo: Cptr, pToCol: Cptr, flags: c_int) void {
    const db = parseDb(pParse);
    var pFKey: Cptr = null;
    const p = rdp(pParse, Parse_pNewTable);
    var nCol: c_int = undefined;

    if (p == null or inDeclareVtab(pParse)) return fkEnd(db, pFKey, pFromCol, pToCol);
    if (pFromCol == null) {
        const iCol = rd(i16, p, Table_nCol) - 1;
        if (iCol < 0) return fkEnd(db, pFKey, pFromCol, pToCol);
        if (pToCol != null and rd(c_int, pToCol, ExprList_nExpr) != 1) {
            sqlite3ErrorMsg(pParse, "foreign key on %s should reference only one column of table %T", rdp(colAt(p, iCol), Column_zCnName), pTo);
            return fkEnd(db, pFKey, pFromCol, pToCol);
        }
        nCol = 1;
    } else if (pToCol != null and rd(c_int, pToCol, ExprList_nExpr) != rd(c_int, pFromCol, ExprList_nExpr)) {
        sqlite3ErrorMsg(pParse, "number of columns in foreign key does not match the number of columns in the referenced table");
        return fkEnd(db, pFKey, pFromCol, pToCol);
    } else {
        nCol = rd(c_int, pFromCol, ExprList_nExpr);
    }
    var nByte: i64 = @as(i64, @intCast(FKey_aCol + @as(usize, @intCast(nCol)) * sizeof_sColMap)) + @as(i64, tokenN(pTo)) + 1;
    if (pToCol != null) {
        const a = elA(pToCol);
        var i: c_int = 0;
        const ntc = rd(c_int, pToCol, ExprList_nExpr);
        while (i < ntc) : (i += 1) {
            const item = base(a) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
            nByte += sqlite3Strlen30(@ptrCast(rdp(@ptrCast(item), ExprList_item_zEName))) + 1;
        }
    }
    pFKey = sqlite3DbMallocZero(db, @intCast(nByte));
    if (pFKey == null) return fkEnd(db, pFKey, pFromCol, pToCol);
    wr(?*anyopaque, pFKey, FKey_pFrom, p);
    wr(?*anyopaque, pFKey, FKey_pNextFrom, rdp(p, Table_u_tab_pFKey));
    var z: [*]u8 = @ptrCast(base(pFKey) + FKey_aCol + @as(usize, @intCast(nCol)) * sizeof_sColMap);
    wr([*]u8, pFKey, FKey_zTo, z);
    if (inRenameObject(pParse)) {
        _ = sqlite3RenameTokenMap(pParse, @ptrCast(z), pTo);
    }
    @memcpy(z[0..tokenN(pTo)], tokenZ(pTo).?[0..tokenN(pTo)]);
    z[tokenN(pTo)] = 0;
    sqlite3Dequote(z);
    z += tokenN(pTo) + 1;
    wr(c_int, pFKey, FKey_nCol, nCol);
    if (pFromCol == null) {
        wr(c_int, @ptrCast(base(pFKey) + FKey_aCol), sColMap_iFrom, rd(i16, p, Table_nCol) - 1);
    } else {
        const a = elA(pFromCol);
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const item = base(a) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
            const zEName: [*:0]const u8 = @ptrCast(rdp(@ptrCast(item), ExprList_item_zEName).?);
            var j: c_int = 0;
            const pnCol = rd(i16, p, Table_nCol);
            while (j < pnCol) : (j += 1) {
                if (sqlite3StrICmp(@ptrCast(rdp(colAt(p, j), Column_zCnName)), zEName) == 0) {
                    wr(c_int, @ptrCast(base(pFKey) + FKey_aCol + @as(usize, @intCast(i)) * sizeof_sColMap), sColMap_iFrom, j);
                    break;
                }
            }
            if (j >= pnCol) {
                sqlite3ErrorMsg(pParse, "unknown column \"%s\" in foreign key definition", zEName);
                return fkEnd(db, pFKey, pFromCol, pToCol);
            }
            if (inRenameObject(pParse)) {
                sqlite3RenameTokenRemap(pParse, @ptrCast(base(pFKey) + FKey_aCol + @as(usize, @intCast(i)) * sizeof_sColMap), @ptrCast(zEName));
            }
        }
    }
    if (pToCol != null) {
        const a = elA(pToCol);
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const item = base(a) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
            const zEName: [*:0]const u8 = @ptrCast(rdp(@ptrCast(item), ExprList_item_zEName).?);
            const n: usize = @intCast(sqlite3Strlen30(zEName));
            wr([*]u8, @ptrCast(base(pFKey) + FKey_aCol + @as(usize, @intCast(i)) * sizeof_sColMap), sColMap_zCol, z);
            if (inRenameObject(pParse)) {
                sqlite3RenameTokenRemap(pParse, @ptrCast(z), @ptrCast(zEName));
            }
            @memcpy(z[0..n], @as([*]const u8, @ptrCast(zEName))[0..n]);
            z[n] = 0;
            z += n + 1;
        }
    }
    wr(u8, pFKey, FKey_isDeferred, 0);
    base(pFKey)[FKey_aAction + 0] = @intCast(flags & 0xff);
    base(pFKey)[FKey_aAction + 1] = @intCast((flags >> 8) & 0xff);

    const pNextTo = sqlite3HashInsert(@ptrCast(base(rdp(p, Table_pSchema)) + Schema_fkeyHash), @ptrCast(rdp(pFKey, FKey_zTo)), pFKey);
    if (pNextTo == pFKey) {
        sqlite3OomFault(db);
        return fkEnd(db, pFKey, pFromCol, pToCol);
    }
    if (pNextTo != null) {
        wr(?*anyopaque, pFKey, FKey_pNextTo, pNextTo);
        wr(?*anyopaque, pNextTo, FKey_pPrevTo, pFKey);
    }

    wr(?*anyopaque, p, Table_u_tab_pFKey, pFKey);
    pFKey = null;
    return fkEnd(db, pFKey, pFromCol, pToCol);
}
fn fkEnd(db: Cptr, pFKey: Cptr, pFromCol: Cptr, pToCol: Cptr) void {
    sqlite3DbFree(db, pFKey);
    sqlite3ExprListDelete(db, pFromCol);
    sqlite3ExprListDelete(db, pToCol);
}

export fn sqlite3DeferForeignKey(pParse: Cptr, isDeferred: c_int) void {
    const pTab = rdp(pParse, Parse_pNewTable);
    if (pTab == null) return;
    if (!isOrdinaryTable(pTab)) return;
    const pFKey = rdp(pTab, Table_u_tab_pFKey);
    if (pFKey == null) return;
    wr(u8, pFKey, FKey_isDeferred, @intCast(isDeferred));
}

fn sqlite3RefillIndex(pParse: Cptr, pIndex: Cptr, memRootPage: c_int) void {
    const pTab = rdp(pIndex, Index_pTable);
    const iTab = rd(c_int, pParse, Parse_nTab);
    wr(c_int, pParse, Parse_nTab, iTab + 1);
    const iIdx = iTab + 1;
    wr(c_int, pParse, Parse_nTab, iIdx + 1);
    const db = parseDb(pParse);
    const iDb = sqlite3SchemaToIndex(db, rdp(pIndex, Index_pSchema));

    if (sqlite3AuthCheck(pParse, SQLITE_REINDEX, @ptrCast(rdp(pIndex, Index_zName)), null, dbZName(db, iDb)) != 0) {
        return;
    }
    sqlite3TableLock(pParse, iDb, rd(u32, pTab, Table_tnum), 1, @ptrCast(rdp(pTab, Table_zName)));

    const v = sqlite3GetVdbe(pParse);
    if (v == null) return;
    const tnum: u32 = if (memRootPage >= 0) @intCast(memRootPage) else rd(u32, pIndex, Index_tnum);
    const pKey = sqlite3KeyInfoOfIndex(pParse, pIndex);

    const iSorter = rd(c_int, pParse, Parse_nTab);
    wr(c_int, pParse, Parse_nTab, iSorter + 1);
    _ = sqlite3VdbeAddOp4(v, OP_SorterOpen, iSorter, 0, rd(u16, pIndex, Index_nKeyCol), @ptrCast(sqlite3KeyInfoRef(pKey)), P4_KEYINFO);

    sqlite3OpenTable(pParse, iTab, iDb, pTab, OP_OpenRead);
    var addr1 = sqlite3VdbeAddOp2(v, OP_Rewind, iTab, 0);
    const regRecord = sqlite3GetTempReg(pParse);
    sqlite3MultiWrite(pParse);

    var iPartIdxLabel: c_int = undefined;
    _ = sqlite3GenerateIndexKey(pParse, pIndex, iTab, regRecord, 0, &iPartIdxLabel, null, 0);
    _ = sqlite3VdbeAddOp2(v, OP_SorterInsert, iSorter, regRecord);
    sqlite3ResolvePartIdxLabel(pParse, iPartIdxLabel);
    _ = sqlite3VdbeAddOp2(v, OP_Next, iTab, addr1 + 1);
    sqlite3VdbeJumpHere(v, addr1);
    if (memRootPage < 0) _ = sqlite3VdbeAddOp2(v, OP_Clear, @intCast(tnum), iDb);
    _ = sqlite3VdbeAddOp4(v, OP_OpenWrite, iIdx, @intCast(tnum), iDb, @ptrCast(pKey), P4_KEYINFO);
    sqlite3VdbeChangeP5(v, OPFLAG_BULKCSR | (if (memRootPage >= 0) OPFLAG_P2ISREG else 0));

    addr1 = sqlite3VdbeAddOp2(v, OP_SorterSort, iSorter, 0);
    var addr2: c_int = undefined;
    if (isUniqueIndex(pIndex)) {
        const j2 = sqlite3VdbeGoto(v, 1);
        addr2 = sqlite3VdbeCurrentAddr(v);
        if (config.sqlite_debug) sqlite3VdbeVerifyAbortable(v, OE_Abort);
        _ = sqlite3VdbeAddOp4Int(v, OP_SorterCompare, iSorter, j2, regRecord, rd(u16, pIndex, Index_nKeyCol));
        sqlite3UniqueConstraint(pParse, OE_Abort, pIndex);
        sqlite3VdbeJumpHere(v, j2);
    } else {
        sqlite3MayAbort(pParse);
        addr2 = sqlite3VdbeCurrentAddr(v);
    }
    _ = sqlite3VdbeAddOp3(v, OP_SorterData, iSorter, regRecord, iIdx);
    if ((base(pIndex)[Index_bits2_byte] & IDX_bAscKeyBug) == 0) {
        _ = sqlite3VdbeAddOp1(v, OP_SeekEnd, iIdx);
    }
    _ = sqlite3VdbeAddOp2(v, OP_IdxInsert, iIdx, regRecord);
    sqlite3VdbeChangeP5(v, OPFLAG_USESEEKRESULT);
    sqlite3ReleaseTempReg(pParse, regRecord);
    _ = sqlite3VdbeAddOp2(v, OP_SorterNext, iSorter, addr2);
    sqlite3VdbeJumpHere(v, addr1);

    _ = sqlite3VdbeAddOp1(v, OP_Close, iTab);
    _ = sqlite3VdbeAddOp1(v, OP_Close, iIdx);
    _ = sqlite3VdbeAddOp1(v, OP_Close, iSorter);
}
extern fn sqlite3AutoincrementBegin(pParse: Cptr) callconv(.c) void;
extern fn sqlite3VdbeVerifyAbortable(v: Cptr, onError: c_int) callconv(.c) void;

// ─── static helpers for CREATE TABLE / INDEX ─────────────────────────────────
fn identLength(z: [*:0]const u8) i64 {
    var n: i64 = 0;
    var p: [*:0]const u8 = z;
    while (p[0] != 0) : (p += 1) {
        n += 1;
        if (p[0] == '"') n += 1;
    }
    return n + 2;
}

fn identPut(z: [*]u8, pIdx: *c_int, zSignedIdent: [*:0]const u8) void {
    const zIdent = zSignedIdent;
    var i: c_int = pIdx.*;
    var j: c_int = 0;
    while (zIdent[@intCast(j)] != 0) : (j += 1) {
        if (sqlite3Isalnum(zIdent[@intCast(j)]) == 0 and zIdent[@intCast(j)] != '_') break;
    }
    const needQuote = sqlite3Isdigit(zIdent[0]) != 0 or sqlite3KeywordCode(@ptrCast(zIdent), j) != TK_ID or zIdent[@intCast(j)] != 0 or j == 0;
    if (needQuote) {
        z[@intCast(i)] = '"';
        i += 1;
    }
    j = 0;
    while (zIdent[@intCast(j)] != 0) : (j += 1) {
        z[@intCast(i)] = zIdent[@intCast(j)];
        i += 1;
        if (zIdent[@intCast(j)] == '"') {
            z[@intCast(i)] = '"';
            i += 1;
        }
    }
    if (needQuote) {
        z[@intCast(i)] = '"';
        i += 1;
    }
    z[@intCast(i)] = 0;
    pIdx.* = i;
}

fn createTableStmt(db: Cptr, p: Cptr) ?[*:0]u8 {
    var n: i64 = 0;
    const nCol = rd(i16, p, Table_nCol);
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        n += identLength(@ptrCast(rdp(colAt(p, i), Column_zCnName).?)) + 5;
    }
    n += identLength(@ptrCast(rdp(p, Table_zName).?));
    var zSep: [*:0]const u8 = undefined;
    var zSep2: [*:0]const u8 = undefined;
    var zEnd: [*:0]const u8 = undefined;
    if (n < 50) {
        zSep = "";
        zSep2 = ",";
        zEnd = ")";
    } else {
        zSep = "\n  ";
        zSep2 = ",\n  ";
        zEnd = "\n)";
    }
    n += 35 + 6 * @as(i64, nCol);
    const zStmt: ?[*]u8 = @ptrCast(sqlite3DbMallocRaw(null, @intCast(n)));
    if (zStmt == null) {
        sqlite3OomFault(db);
        return null;
    }
    const azType = [_][*:0]const u8{ "", " TEXT", " NUM", " INT", " REAL", " NUM" };
    @memcpy(zStmt.?[0..13], "CREATE TABLE ");
    var k: c_int = 13;
    identPut(zStmt.?, &k, @ptrCast(rdp(p, Table_zName).?));
    zStmt.?[@intCast(k)] = '(';
    k += 1;
    i = 0;
    while (i < nCol) : (i += 1) {
        const pCol = colAt(p, i);
        var len: c_int = sqlite3Strlen30(zSep);
        @memcpy((zStmt.? + @as(usize, @intCast(k)))[0..@intCast(len)], zSep[0..@intCast(len)]);
        k += len;
        zSep = zSep2;
        identPut(zStmt.?, &k, @ptrCast(rdp(pCol, Column_zCnName).?));
        const aff = rd(u8, pCol, Column_affinity);
        const zType = azType[@intCast(aff - SQLITE_AFF_BLOB)];
        len = sqlite3Strlen30(zType);
        @memcpy((zStmt.? + @as(usize, @intCast(k)))[0..@intCast(len)], zType[0..@intCast(len)]);
        k += len;
    }
    const len: c_int = sqlite3Strlen30(zEnd);
    @memcpy((zStmt.? + @as(usize, @intCast(k)))[0..@intCast(len + 1)], zEnd[0..@intCast(len + 1)]);
    return @ptrCast(zStmt);
}

fn resizeIndexObject(pParse: Cptr, pIdx: Cptr, N: c_int) c_int {
    if (rd(u16, pIdx, Index_nColumn) >= N) return SQLITE_OK;
    const db = parseDb(pParse);
    const nByte: u64 = (@sizeOf(usize) + @sizeOf(u16) + @sizeOf(i16) + 1) * @as(u64, @intCast(N));
    const zExtraRaw = sqlite3DbMallocZero(db, nByte);
    if (zExtraRaw == null) return SQLITE_NOMEM;
    var zExtra: [*]u8 = @ptrCast(zExtraRaw.?);
    const nColumn = rd(u16, pIdx, Index_nColumn);
    const nKeyCol = rd(u16, pIdx, Index_nKeyCol);
    @memmove(zExtra[0 .. @sizeOf(usize) * nColumn], @as([*]const u8, @ptrCast(rdp(pIdx, Index_azColl).?))[0 .. @sizeOf(usize) * nColumn]);
    wr(?*anyopaque, pIdx, Index_azColl, @ptrCast(zExtra));
    zExtra += @sizeOf(usize) * @as(usize, @intCast(N));
    @memmove(zExtra[0 .. @sizeOf(u16) * (nKeyCol + 1)], @as([*]const u8, @ptrCast(rdp(pIdx, Index_aiRowLogEst).?))[0 .. @sizeOf(u16) * (nKeyCol + 1)]);
    wr(?*anyopaque, pIdx, Index_aiRowLogEst, @ptrCast(zExtra));
    zExtra += @sizeOf(u16) * @as(usize, @intCast(N));
    @memmove(zExtra[0 .. @sizeOf(i16) * nColumn], @as([*]const u8, @ptrCast(rdp(pIdx, Index_aiColumn).?))[0 .. @sizeOf(i16) * nColumn]);
    wr(?*anyopaque, pIdx, Index_aiColumn, @ptrCast(zExtra));
    zExtra += @sizeOf(i16) * @as(usize, @intCast(N));
    @memmove(zExtra[0..nColumn], @as([*]const u8, @ptrCast(rdp(pIdx, Index_aSortOrder).?))[0..nColumn]);
    wr(?*anyopaque, pIdx, Index_aSortOrder, @ptrCast(zExtra));
    wr(u16, pIdx, Index_nColumn, @intCast(N));
    base(pIdx)[Index_bits_byte] |= IDX_isResized;
    return SQLITE_OK;
}

fn estimateTableWidth(pTab: Cptr) void {
    var wTable: u32 = 0;
    const nCol = rd(i16, pTab, Table_nCol);
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        wTable += rd(u8, colAt(pTab, i), Column_szEst);
    }
    if (rd(i16, pTab, Table_iPKey) < 0) wTable += 1;
    wr(u16, pTab, Table_szTabRow, sqlite3LogEst(wTable * 4));
}

fn estimateIndexWidth(pIdx: Cptr) void {
    var wIndex: u32 = 0;
    const pTab = rdp(pIdx, Index_pTable);
    const aiColumn: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
    const nColumn = rd(u16, pIdx, Index_nColumn);
    var i: c_int = 0;
    while (i < nColumn) : (i += 1) {
        const x = aiColumn[@intCast(i)];
        wIndex += if (x < 0) 1 else rd(u8, colAt(pTab, x), Column_szEst);
    }
    wr(u16, pIdx, Index_szIdxRow, sqlite3LogEst(wIndex * 4));
}

fn hasColumn(aiCol: [*]const i16, nColIn: c_int, x: i16) bool {
    var nCol = nColIn;
    var p = aiCol;
    while (nCol > 0) : (nCol -= 1) {
        if (x == p[0]) return true;
        p += 1;
    }
    return false;
}

fn isDupColumn(pIdx: Cptr, nKey: c_int, pPk: Cptr, iCol: c_int) bool {
    const aiColPk: [*]const i16 = @ptrCast(@alignCast(rdp(pPk, Index_aiColumn).?));
    const j = aiColPk[@intCast(iCol)];
    const aiColIdx: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
    const azCollIdx: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pIdx, Index_azColl).?));
    const azCollPk: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pPk, Index_azColl).?));
    var i: c_int = 0;
    while (i < nKey) : (i += 1) {
        if (aiColIdx[@intCast(i)] == j and sqlite3StrICmp(azCollIdx[@intCast(i)], azCollPk[@intCast(iCol)]) == 0) {
            return true;
        }
    }
    return false;
}

fn recomputeColumnsNotIndexed(pIdx: Cptr) void {
    var m: u64 = 0;
    const pTab = rdp(pIdx, Index_pTable);
    const aiColumn: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
    const nColumn = rd(u16, pIdx, Index_nColumn);
    var j: c_int = @as(c_int, nColumn) - 1;
    const BMS: c_int = 64;
    while (j >= 0) : (j -= 1) {
        const x = aiColumn[@intCast(j)];
        if (x >= 0 and (colFlags(colAt(pTab, x)) & COLFLAG_VIRTUAL) == 0) {
            if (x < BMS - 1) m |= (@as(u64, 1) << @intCast(x));
        }
    }
    wr(u64, pIdx, Index_colNotIdxed, ~m);
}

fn convertToWithoutRowidTable(pParse: Cptr, pTab: Cptr) void {
    const db = parseDb(pParse);
    const v = vdbeOf(pParse);

    if (initImposterTable(db) == 0) {
        var i: c_int = 0;
        const nCol = rd(i16, pTab, Table_nCol);
        while (i < nCol) : (i += 1) {
            const pCol = colAt(pTab, i);
            if ((colFlags(pCol) & COLFLAG_PRIMKEY) != 0 and (base(pCol)[Column_bft_byte] & 0x0f) == @as(u8, @intCast(OE_None))) {
                base(pCol)[Column_bft_byte] = (base(pCol)[Column_bft_byte] & 0xf0) | (@as(u8, @intCast(OE_Abort)) & 0x0f);
            }
        }
        wr(u32, pTab, Table_tabFlags, tabFlags(pTab) | TF_HasNotNull);
    }

    if (rd(c_int, pParse, Parse_u1_cr_addrCrTab) != 0) {
        sqlite3VdbeChangeP3(v, rd(c_int, pParse, Parse_u1_cr_addrCrTab), BTREE_BLOBKEY);
    }

    var pPk: Cptr = undefined;
    if (rd(i16, pTab, Table_iPKey) >= 0) {
        var ipkToken: [sizeof_Token]u8 align(8) = undefined;
        sqlite3TokenInit(@ptrCast(&ipkToken), @ptrCast(rdp(colAt(pTab, rd(i16, pTab, Table_iPKey)), Column_zCnName)));
        const pList = sqlite3ExprListAppend(pParse, null, sqlite3ExprAlloc(db, TK_ID, @ptrCast(&ipkToken), 0));
        if (pList == null) {
            wr(u32, pTab, Table_tabFlags, tabFlags(pTab) & ~TF_WithoutRowid);
            return;
        }
        if (inRenameObject(pParse)) {
            sqlite3RenameTokenRemap(pParse, rdp(elA(pList), ExprList_item_pExpr), @ptrCast(base(pTab) + Table_iPKey));
        }
        base(elA(pList))[ExprList_item_fg_sortFlags] = rd(u8, pParse, Parse_iPkSortOrder);
        wr(i16, pTab, Table_iPKey, -1);
        sqlite3CreateIndex(pParse, null, null, null, pList, rd(u8, pTab, Table_keyConf), null, null, 0, 0, SQLITE_IDXTYPE_PRIMARYKEY);
        if (rd(c_int, pParse, Parse_nErr) != 0) {
            wr(u32, pTab, Table_tabFlags, tabFlags(pTab) & ~TF_WithoutRowid);
            return;
        }
        pPk = sqlite3PrimaryKeyIndex(pTab);
    } else {
        pPk = sqlite3PrimaryKeyIndex(pTab);

        var i: c_int = 1;
        var j: c_int = 1;
        const nKeyCol = rd(u16, pPk, Index_nKeyCol);
        const azColl: [*]?*anyopaque = @ptrCast(@alignCast(rdp(pPk, Index_azColl).?));
        const aSortOrder: [*]u8 = @ptrCast(rdp(pPk, Index_aSortOrder).?);
        const aiColumn: [*]i16 = @ptrCast(@alignCast(rdp(pPk, Index_aiColumn).?));
        while (i < nKeyCol) : (i += 1) {
            if (isDupColumn(pPk, j, pPk, i)) {
                wr(u16, pPk, Index_nColumn, rd(u16, pPk, Index_nColumn) - 1);
            } else {
                azColl[@intCast(j)] = azColl[@intCast(i)];
                aSortOrder[@intCast(j)] = aSortOrder[@intCast(i)];
                aiColumn[@intCast(j)] = aiColumn[@intCast(i)];
                j += 1;
            }
        }
        wr(u16, pPk, Index_nKeyCol, @intCast(j));
    }
    base(pPk)[Index_bits_byte] |= IDX_isCovering;
    if (initImposterTable(db) == 0) base(pPk)[Index_bits_byte] |= IDX_uniqNotNull;
    const nPk: c_int = @intCast(rd(u16, pPk, Index_nKeyCol));
    wr(u16, pPk, Index_nColumn, @intCast(nPk));

    if (v != null and rd(u32, pPk, Index_tnum) > 0) {
        sqlite3VdbeChangeOpcode(v, @intCast(rd(u32, pPk, Index_tnum)), OP_Goto);
    }

    wr(u32, pPk, Index_tnum, rd(u32, pTab, Table_tnum));

    var pIdx = rdp(pTab, Table_pIndex);
    while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
        if (isPrimaryKeyIndex(pIdx)) continue;
        var n: c_int = 0;
        var i: c_int = 0;
        const pkColPk: [*]const i16 = @ptrCast(@alignCast(rdp(pPk, Index_aiColumn).?));
        const pkColl: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pPk, Index_azColl).?));
        const pkSort: [*]const u8 = @ptrCast(rdp(pPk, Index_aSortOrder).?);
        const nKeyColIdx = rd(u16, pIdx, Index_nKeyCol);
        while (i < nPk) : (i += 1) {
            if (!isDupColumn(pIdx, nKeyColIdx, pPk, i)) n += 1;
        }
        if (n == 0) {
            wr(u16, pIdx, Index_nColumn, nKeyColIdx);
            continue;
        }
        if (resizeIndexObject(pParse, pIdx, @as(c_int, nKeyColIdx) + n) != 0) return;
        i = 0;
        var j: c_int = @intCast(nKeyColIdx);
        const idxCol: [*]i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
        const idxColl: [*]?*anyopaque = @ptrCast(@alignCast(rdp(pIdx, Index_azColl).?));
        while (i < nPk) : (i += 1) {
            if (!isDupColumn(pIdx, nKeyColIdx, pPk, i)) {
                idxCol[@intCast(j)] = pkColPk[@intCast(i)];
                idxColl[@intCast(j)] = @constCast(@ptrCast(pkColl[@intCast(i)]));
                if (pkSort[@intCast(i)] != 0) {
                    base(pIdx)[Index_bits2_byte] |= IDX_bAscKeyBug;
                }
                j += 1;
            }
        }
    }

    var nExtra: c_int = 0;
    var i: c_int = 0;
    const nCol = rd(i16, pTab, Table_nCol);
    const pkColPk2: [*]const i16 = @ptrCast(@alignCast(rdp(pPk, Index_aiColumn).?));
    while (i < nCol) : (i += 1) {
        if (!hasColumn(pkColPk2, nPk, @intCast(i)) and (colFlags(colAt(pTab, i)) & COLFLAG_VIRTUAL) == 0) nExtra += 1;
    }
    if (resizeIndexObject(pParse, pPk, nPk + nExtra) != 0) return;
    i = 0;
    var j: c_int = nPk;
    const pkCol3: [*]i16 = @ptrCast(@alignCast(rdp(pPk, Index_aiColumn).?));
    const pkColl3: [*]?*anyopaque = @ptrCast(@alignCast(rdp(pPk, Index_azColl).?));
    while (i < nCol) : (i += 1) {
        if (!hasColumn(pkCol3, j, @intCast(i)) and (colFlags(colAt(pTab, i)) & COLFLAG_VIRTUAL) == 0) {
            const zColl = sqlite3ColumnColl(colAt(pTab, i));
            pkCol3[@intCast(j)] = @intCast(i);
            pkColl3[@intCast(j)] = if (zColl != null) @constCast(@ptrCast(zColl)) else @constCast(@ptrCast(&sqlite3StrBINARY));
            j += 1;
        }
    }
    recomputeColumnsNotIndexed(pPk);
}

export fn sqlite3AllocateIndexObject(db: Cptr, nCol: c_int, nExtra: c_int, ppExtra: *?[*]u8) Cptr {
    const round8 = struct {
        inline fn r(x: u64) u64 {
            return (x + 7) & ~@as(u64, 7);
        }
    }.r;
    const nByte: u64 = round8(sizeof_Index) +
        round8(@sizeOf(usize) * @as(u64, @intCast(nCol))) +
        round8(@sizeOf(u16) * @as(u64, @intCast(nCol + 1)) +
            @sizeOf(i16) * @as(u64, @intCast(nCol)) +
            @sizeOf(u8) * @as(u64, @intCast(nCol)));
    const p = sqlite3DbMallocZero(db, nByte + @as(u64, @intCast(nExtra)));
    if (p != null) {
        var pExtra: [*]u8 = base(p) + round8(sizeof_Index);
        wr(?*anyopaque, p, Index_azColl, @ptrCast(pExtra));
        pExtra += round8(@sizeOf(usize) * @as(u64, @intCast(nCol)));
        wr(?*anyopaque, p, Index_aiRowLogEst, @ptrCast(pExtra));
        pExtra += @sizeOf(u16) * @as(usize, @intCast(nCol + 1));
        wr(?*anyopaque, p, Index_aiColumn, @ptrCast(pExtra));
        pExtra += @sizeOf(i16) * @as(usize, @intCast(nCol));
        wr(?*anyopaque, p, Index_aSortOrder, @ptrCast(pExtra));
        wr(u16, p, Index_nColumn, @intCast(nCol));
        wr(u16, p, Index_nKeyCol, @intCast(nCol - 1));
        ppExtra.* = base(p) + nByte;
    }
    return p;
}
const sizeof_Index = off("sizeof_Index", 120);

export fn sqlite3HasExplicitNulls(pParse: Cptr, pList: Cptr) c_int {
    if (pList != null) {
        const nExpr = rd(c_int, pList, ExprList_nExpr);
        const a = elA(pList);
        var i: c_int = 0;
        while (i < nExpr) : (i += 1) {
            const item = base(a) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
            // fg.bNulls bit
            if ((base(@ptrCast(item))[ExprList_item_fg_byte] & ELI_bNulls) != 0) {
                const sf = base(@ptrCast(item))[ExprList_item_fg_sortFlags];
                sqlite3ErrorMsg(pParse, "unsupported use of NULLS %s", @as([*:0]const u8, if (sf == 0 or sf == 3) "FIRST" else "LAST"));
                return 1;
            }
        }
    }
    return 0;
}

export fn sqlite3DefaultRowEst(pIdx: Cptr) void {
    const aVal = [_]i16{ 33, 32, 30, 28, 26 };
    const a: [*]i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiRowLogEst).?));
    const nKeyCol = rd(u16, pIdx, Index_nKeyCol);
    const nCopy: usize = @min(aVal.len, nKeyCol);
    const pTab = rdp(pIdx, Index_pTable);
    var x = rd(i16, pTab, Table_nRowLogEst);
    if (x < 99) {
        wr(i16, pTab, Table_nRowLogEst, 99);
        x = 99;
    }
    if (rdp(pIdx, Index_pPartIdxWhere) != null) {
        x -= 10;
    }
    a[0] = x;
    @memcpy(@as([*]u8, @ptrCast(a + 1))[0 .. nCopy * 2], @as([*]const u8, @ptrCast(&aVal))[0 .. nCopy * 2]);
    var i: usize = nCopy + 1;
    while (i <= nKeyCol) : (i += 1) {
        a[i] = 23;
    }
    if (isUniqueIndex(pIdx)) a[nKeyCol] = 0;
}

export fn sqlite3DropIndex(pParse: Cptr, pName: Cptr, ifExists: c_int) void {
    const db = parseDb(pParse);
    if (mallocFailed(db)) return dropIndexExit(db, pName);
    if (sqlite3ReadSchema(pParse) != SQLITE_OK) return dropIndexExit(db, pName);
    const aItem: Cptr = @ptrCast(base(pName) + SrcList_a);
    const pIndex = sqlite3FindIndex(db, @ptrCast(rdp(aItem, SrcItem_zName)), @ptrCast(rdp(aItem, SrcItem_u4)));
    if (pIndex == null) {
        if (ifExists == 0) {
            sqlite3ErrorMsg(pParse, "no such index: %S", aItem);
        } else {
            sqlite3CodeVerifyNamedSchema(pParse, @ptrCast(rdp(aItem, SrcItem_u4)));
            sqlite3ForceNotReadOnly(pParse);
        }
        bftSet(pParse, Parse_bft_byte + 1, BFT_checkSchema);
        return dropIndexExit(db, pName);
    }
    if (idxType(pIndex) != SQLITE_IDXTYPE_APPDEF) {
        sqlite3ErrorMsg(pParse, "index associated with UNIQUE or PRIMARY KEY constraint cannot be dropped");
        return dropIndexExit(db, pName);
    }
    const iDb = sqlite3SchemaToIndex(db, rdp(pIndex, Index_pSchema));
    {
        var code: c_int = SQLITE_DROP_INDEX;
        const pTab = rdp(pIndex, Index_pTable);
        const zDb = dbZName(db, iDb);
        const zTab = schemaTable(iDb);
        if (sqlite3AuthCheck(pParse, SQLITE_DELETE, zTab, null, zDb) != 0) {
            return dropIndexExit(db, pName);
        }
        if (OMIT_TEMPDB == 0 and iDb == 1) code = SQLITE_DROP_TEMP_INDEX;
        if (sqlite3AuthCheck(pParse, code, @ptrCast(rdp(pIndex, Index_zName)), @ptrCast(rdp(pTab, Table_zName)), zDb) != 0) {
            return dropIndexExit(db, pName);
        }
    }
    const v = sqlite3GetVdbe(pParse);
    if (v != null) {
        sqlite3BeginWriteOperation(pParse, 1, iDb);
        sqlite3NestedParse(pParse, "DELETE FROM %Q." ++ LEGACY_SCHEMA_TABLE ++ " WHERE name=%Q AND type='index'", dbZName(db, iDb), rdp(pIndex, Index_zName));
        sqlite3ClearStatTables(pParse, iDb, "idx", @ptrCast(rdp(pIndex, Index_zName).?));
        sqlite3ChangeCookie(pParse, iDb);
        destroyRootPage(pParse, @intCast(rd(u32, pIndex, Index_tnum)), iDb);
        _ = sqlite3VdbeAddOp4(v, OP_DropIndex, iDb, 0, 0, @ptrCast(rdp(pIndex, Index_zName)), 0);
    }
    return dropIndexExit(db, pName);
}
fn dropIndexExit(db: Cptr, pName: Cptr) void {
    sqlite3SrcListDelete(db, pName);
}

export fn sqlite3CreateIndex(pParse: Cptr, pName1: Cptr, pName2: Cptr, pTblName: Cptr, pListIn: Cptr, onError: c_int, pStart: Cptr, pPIWhereIn: Cptr, sortOrder: c_int, ifNotExist: c_int, idxTypeArg: u8) void {
    var pList = pListIn;
    var pPIWhere = pPIWhereIn;
    var pTab: Cptr = null;
    var pIndex: Cptr = null;
    var zName: ?[*:0]u8 = null;
    const db = parseDb(pParse);
    var iDb: c_int = undefined;
    var pName: Cptr = null;
    var nExtra: c_int = 0;
    var zExtra: ?[*]u8 = null;
    var pPk: Cptr = null;
    var i: c_int = undefined;
    var j: c_int = undefined;

    if (rd(c_int, pParse, Parse_nErr) != 0) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    if (inDeclareVtab(pParse) and idxTypeArg != SQLITE_IDXTYPE_PRIMARYKEY) {
        return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    }
    if (sqlite3ReadSchema(pParse) != SQLITE_OK) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    if (sqlite3HasExplicitNulls(pParse, pList) != 0) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);

    if (pTblName != null) {
        iDb = sqlite3TwoPartName(pParse, pName1, pName2, &pName);
        if (iDb < 0) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);

        if (initBusy(db) == 0) {
            pTab = sqlite3SrcListLookup(pParse, pTblName);
            if (tokenN(pName2) == 0 and pTab != null and rdp(pTab, Table_pSchema) == dbSchema(db, 1)) {
                iDb = 1;
            }
        }

        var sFix: [sizeof_DbFixer]u8 align(8) = undefined;
        sqlite3FixInit(@ptrCast(&sFix), pParse, iDb, "index", pName);
        _ = sqlite3FixSrcList(@ptrCast(&sFix), pTblName);
        const aItem: Cptr = @ptrCast(base(pTblName) + SrcList_a);
        pTab = sqlite3LocateTableItem(pParse, 0, aItem);
        if (pTab == null) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        if (iDb == 1 and dbSchema(db, iDb) != rdp(pTab, Table_pSchema)) {
            sqlite3ErrorMsg(pParse, "cannot create a TEMP index on non-TEMP table \"%s\"", rdp(pTab, Table_zName));
            return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        }
        if (!hasRowid(pTab)) pPk = sqlite3PrimaryKeyIndex(pTab);
    } else {
        pTab = rdp(pParse, Parse_pNewTable);
        if (pTab == null) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        iDb = sqlite3SchemaToIndex(db, rdp(pTab, Table_pSchema));
    }
    const pDb = dbAt(db, iDb);

    if (sqlite3_strnicmp(@ptrCast(rdp(pTab, Table_zName)), "sqlite_", 7) == 0 and initBusy(db) == 0 and pTblName != null) {
        sqlite3ErrorMsg(pParse, "table %s may not be indexed", rdp(pTab, Table_zName));
        return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    }
    if (isViewTab(pTab)) {
        sqlite3ErrorMsg(pParse, "views may not be indexed");
        return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    }
    if (isVirtual(pTab)) {
        sqlite3ErrorMsg(pParse, "virtual tables may not be indexed");
        return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    }

    if (pName != null) {
        zName = sqlite3NameFromToken(db, pName);
        if (zName == null) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        if (sqlite3CheckObjectName(pParse, @ptrCast(zName), "index", @ptrCast(rdp(pTab, Table_zName))) != SQLITE_OK) {
            return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        }
        if (!inRenameObject(pParse)) {
            if (initBusy(db) == 0) {
                if (sqlite3FindTable(db, @ptrCast(zName), @ptrCast(rdp(pDb, Db_zDbSName))) != null) {
                    sqlite3ErrorMsg(pParse, "there is already a table named %s", zName);
                    return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
                }
            }
            if (sqlite3FindIndex(db, @ptrCast(zName), @ptrCast(rdp(pDb, Db_zDbSName))) != null) {
                if (ifNotExist == 0) {
                    sqlite3ErrorMsg(pParse, "index %s already exists", zName);
                } else {
                    sqlite3CodeVerifySchema(pParse, iDb);
                    sqlite3ForceNotReadOnly(pParse);
                }
                return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
            }
        }
    } else {
        var pLoop = rdp(pTab, Table_pIndex);
        var n: c_int = 1;
        while (pLoop != null) : (pLoop = rdp(pLoop, Index_pNext)) {
            n += 1;
        }
        zName = sqlite3MPrintf(db, "sqlite_autoindex_%s_%d", rdp(pTab, Table_zName), n);
        if (zName == null) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        if (inSpecialParse(pParse)) zName.?[7] += 1;
    }

    if (!inRenameObject(pParse)) {
        const zDb = dbZName(db, iDb);
        if (sqlite3AuthCheck(pParse, SQLITE_INSERT, schemaTable(iDb), null, zDb) != 0) {
            return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        }
        var ic: c_int = SQLITE_CREATE_INDEX;
        if (OMIT_TEMPDB == 0 and iDb == 1) ic = SQLITE_CREATE_TEMP_INDEX;
        if (sqlite3AuthCheck(pParse, ic, @ptrCast(zName), @ptrCast(rdp(pTab, Table_zName)), zDb) != 0) {
            return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        }
    }

    if (pList == null) {
        var prevCol: [sizeof_Token]u8 align(8) = undefined;
        const pCol = colAt(pTab, rd(i16, pTab, Table_nCol) - 1);
        wr(u16, pCol, Column_colFlags, colFlags(pCol) | COLFLAG_UNIQUE);
        sqlite3TokenInit(@ptrCast(&prevCol), @ptrCast(rdp(pCol, Column_zCnName)));
        pList = sqlite3ExprListAppend(pParse, null, sqlite3ExprAlloc(db, TK_ID, @ptrCast(&prevCol), 0));
        if (pList == null) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
        sqlite3ExprListSetSortOrder(pList, sortOrder, SQLITE_SO_UNDEFINED);
    } else {
        sqlite3ExprListCheckLength(pParse, pList, "index");
        if (rd(c_int, pParse, Parse_nErr) != 0) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    }

    {
        const nExpr = rd(c_int, pList, ExprList_nExpr);
        const a = elA(pList);
        i = 0;
        while (i < nExpr) : (i += 1) {
            const item = base(a) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
            const pExpr = rdp(@ptrCast(item), ExprList_item_pExpr);
            if (rd(u8, pExpr, Expr_op) == TK_COLLATE) {
                nExtra += 1 + sqlite3Strlen30(@ptrCast(rdp(pExpr, Expr_u)));
            }
        }
    }

    const nName = sqlite3Strlen30(@ptrCast(zName));
    const nExtraCol: c_int = if (pPk != null) @intCast(rd(u16, pPk, Index_nKeyCol)) else 1;
    pIndex = sqlite3AllocateIndexObject(db, rd(c_int, pList, ExprList_nExpr) + nExtraCol, nName + nExtra + 1, &zExtra);
    if (mallocFailed(db)) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
    wr(?*anyopaque, pIndex, Index_zName, @ptrCast(zExtra));
    @memcpy(zExtra.?[0..@intCast(nName + 1)], @as([*]const u8, @ptrCast(zName.?))[0..@intCast(nName + 1)]);
    zExtra.? += @intCast(nName + 1);
    wr(?*anyopaque, pIndex, Index_pTable, pTab);
    wr(u8, pIndex, Index_onError, @intCast(onError));
    // uniqNotNull = onError!=OE_None
    if (onError != OE_None) base(pIndex)[Index_bits_byte] |= IDX_uniqNotNull else base(pIndex)[Index_bits_byte] &= ~IDX_uniqNotNull;
    base(pIndex)[Index_bits_byte] = (base(pIndex)[Index_bits_byte] & ~IDX_idxType_mask) | (idxTypeArg & IDX_idxType_mask);
    wr(?*anyopaque, pIndex, Index_pSchema, dbSchema(db, iDb));
    wr(u16, pIndex, Index_nKeyCol, @intCast(rd(c_int, pList, ExprList_nExpr)));
    if (pPIWhere != null) {
        _ = sqlite3ResolveSelfReference(pParse, pTab, NC_PartIdx, pPIWhere, null);
        wr(?*anyopaque, pIndex, Index_pPartIdxWhere, pPIWhere);
        pPIWhere = null;
    }

    var sortOrderMask: c_int = undefined;
    if (rd(u16, rdp(pDb, Db_pSchema), Schema_file_format) >= 4) {
        sortOrderMask = -1;
    } else {
        sortOrderMask = 0;
    }

    {
        const aList = elA(pList);
        const nKeyCol = rd(u16, pIndex, Index_nKeyCol);
        const aiColumn: [*]i16 = @ptrCast(@alignCast(rdp(pIndex, Index_aiColumn).?));
        const azColl: [*]?*anyopaque = @ptrCast(@alignCast(rdp(pIndex, Index_azColl).?));
        const aSortOrder: [*]u8 = @ptrCast(rdp(pIndex, Index_aSortOrder).?);
        if (inRenameObject(pParse)) {
            wr(?*anyopaque, pIndex, Index_aColExpr, pList);
            pList = null;
        }
        i = 0;
        while (i < nKeyCol) : (i += 1) {
            const pListItem = base(aList) + @as(usize, @intCast(i)) * sizeof_ExprList_item;
            const pItemExpr = rdp(@ptrCast(pListItem), ExprList_item_pExpr);
            sqlite3StringToIdLocal(pItemExpr);
            _ = sqlite3ResolveSelfReference(pParse, pTab, NC_IdxExpr, pItemExpr, null);
            if (rd(c_int, pParse, Parse_nErr) != 0) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
            const pCExpr = sqlite3ExprSkipCollate(pItemExpr);
            if (rd(u8, pCExpr, Expr_op) != TK_COLUMN) {
                if (pTab == rdp(pParse, Parse_pNewTable)) {
                    sqlite3ErrorMsg(pParse, "expressions prohibited in PRIMARY KEY and UNIQUE constraints");
                    return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
                }
                if (rdp(pIndex, Index_aColExpr) == null) {
                    wr(?*anyopaque, pIndex, Index_aColExpr, pList);
                    pList = null;
                }
                j = XN_EXPR;
                aiColumn[@intCast(i)] = XN_EXPR;
                base(pIndex)[Index_bits_byte] &= ~IDX_uniqNotNull;
                base(pIndex)[Index_bits2_byte] |= IDX_bHasExpr;
            } else {
                j = rd(i16, pCExpr, Expr_iColumn);
                if (j < 0) {
                    j = rd(i16, pTab, Table_iPKey);
                } else {
                    if ((base(colAt(pTab, j))[Column_bft_byte] & 0x0f) == 0) {
                        base(pIndex)[Index_bits_byte] &= ~IDX_uniqNotNull;
                    }
                    if ((colFlags(colAt(pTab, j)) & COLFLAG_VIRTUAL) != 0) {
                        base(pIndex)[Index_bits2_byte] |= IDX_bHasVCol;
                        base(pIndex)[Index_bits2_byte] |= IDX_bHasExpr;
                    }
                }
                aiColumn[@intCast(i)] = @intCast(j);
            }
            var zColl: ?[*:0]const u8 = null;
            if (rd(u8, pItemExpr, Expr_op) == TK_COLLATE) {
                const ztok: [*:0]const u8 = @ptrCast(rdp(pItemExpr, Expr_u).?);
                const nColl = sqlite3Strlen30(ztok) + 1;
                @memcpy(zExtra.?[0..@intCast(nColl)], @as([*]const u8, @ptrCast(ztok))[0..@intCast(nColl)]);
                zColl = @ptrCast(zExtra);
                zExtra.? += @intCast(nColl);
                nExtra -= nColl;
            } else if (j >= 0) {
                zColl = sqlite3ColumnColl(colAt(pTab, j));
            }
            if (zColl == null) zColl = @ptrCast(&sqlite3StrBINARY);
            if (initBusy(db) == 0 and sqlite3LocateCollSeq(pParse, zColl) == null) {
                return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
            }
            azColl[@intCast(i)] = @constCast(@ptrCast(zColl));
            const requestedSortOrder = base(@ptrCast(pListItem))[ExprList_item_fg_sortFlags] & @as(u8, @intCast(sortOrderMask & 0xff));
            aSortOrder[@intCast(i)] = requestedSortOrder;
        }
    }

    if (pPk != null) {
        const pkCol: [*]const i16 = @ptrCast(@alignCast(rdp(pPk, Index_aiColumn).?));
        const pkColl: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pPk, Index_azColl).?));
        const pkSort: [*]const u8 = @ptrCast(rdp(pPk, Index_aSortOrder).?);
        const idxCol: [*]i16 = @ptrCast(@alignCast(rdp(pIndex, Index_aiColumn).?));
        const idxColl: [*]?*anyopaque = @ptrCast(@alignCast(rdp(pIndex, Index_azColl).?));
        const idxSort: [*]u8 = @ptrCast(rdp(pIndex, Index_aSortOrder).?);
        const nKeyColIdx = rd(u16, pIndex, Index_nKeyCol);
        const nKeyColPk = rd(u16, pPk, Index_nKeyCol);
        j = 0;
        while (j < nKeyColPk) : (j += 1) {
            const x = pkCol[@intCast(j)];
            if (isDupColumn(pIndex, @intCast(nKeyColIdx), pPk, j)) {
                wr(u16, pIndex, Index_nColumn, rd(u16, pIndex, Index_nColumn) - 1);
            } else {
                idxCol[@intCast(i)] = x;
                idxColl[@intCast(i)] = @constCast(@ptrCast(pkColl[@intCast(j)]));
                idxSort[@intCast(i)] = pkSort[@intCast(j)];
                i += 1;
            }
        }
    } else {
        const idxCol: [*]i16 = @ptrCast(@alignCast(rdp(pIndex, Index_aiColumn).?));
        const idxColl: [*]?*anyopaque = @ptrCast(@alignCast(rdp(pIndex, Index_azColl).?));
        idxCol[@intCast(i)] = XN_ROWID;
        idxColl[@intCast(i)] = @constCast(@ptrCast(&sqlite3StrBINARY));
    }
    sqlite3DefaultRowEst(pIndex);
    if (rdp(pParse, Parse_pNewTable) == null) estimateIndexWidth(pIndex);

    recomputeColumnsNotIndexed(pIndex);
    if (pTblName != null and rd(u16, pIndex, Index_nColumn) >= rd(i16, pTab, Table_nCol)) {
        base(pIndex)[Index_bits_byte] |= IDX_isCovering;
        j = 0;
        const nCol = rd(i16, pTab, Table_nCol);
        while (j < nCol) : (j += 1) {
            if (j == rd(i16, pTab, Table_iPKey)) continue;
            if (sqlite3TableColumnToIndex(pIndex, j) >= 0) continue;
            base(pIndex)[Index_bits_byte] &= ~IDX_isCovering;
            break;
        }
    }

    if (pTab == rdp(pParse, Parse_pNewTable)) {
        var pIdx = rdp(pTab, Table_pIndex);
        outer: while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
            const nKeyColIdx = rd(u16, pIdx, Index_nKeyCol);
            if (nKeyColIdx != rd(u16, pIndex, Index_nKeyCol)) continue;
            const colA: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
            const colB: [*]const i16 = @ptrCast(@alignCast(rdp(pIndex, Index_aiColumn).?));
            const collA: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pIdx, Index_azColl).?));
            const collB: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pIndex, Index_azColl).?));
            var k: c_int = 0;
            while (k < nKeyColIdx) : (k += 1) {
                if (colA[@intCast(k)] != colB[@intCast(k)]) break;
                if (sqlite3StrICmp(collA[@intCast(k)], collB[@intCast(k)]) != 0) break;
            }
            if (k == nKeyColIdx) {
                if (rd(u8, pIdx, Index_onError) != rd(u8, pIndex, Index_onError)) {
                    if (!(rd(u8, pIdx, Index_onError) == @as(u8, @intCast(OE_Default)) or rd(u8, pIndex, Index_onError) == @as(u8, @intCast(OE_Default)))) {
                        sqlite3ErrorMsg(pParse, "conflicting ON CONFLICT clauses specified");
                    }
                    if (rd(u8, pIdx, Index_onError) == @as(u8, @intCast(OE_Default))) {
                        wr(u8, pIdx, Index_onError, rd(u8, pIndex, Index_onError));
                    }
                }
                if (idxTypeArg == SQLITE_IDXTYPE_PRIMARYKEY) {
                    base(pIdx)[Index_bits_byte] = (base(pIdx)[Index_bits_byte] & ~IDX_idxType_mask) | idxTypeArg;
                }
                if (inRenameObject(pParse)) {
                    wr(?*anyopaque, pIndex, Index_pNext, rdp(pParse, Parse_pNewIndex));
                    wr(?*anyopaque, pParse, Parse_pNewIndex, pIndex);
                    pIndex = null;
                }
                return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
            }
            _ = &k;
            break :outer;
        }
    }

    if (!inRenameObject(pParse)) {
        if (initBusy(db) != 0) {
            if (pTblName != null) {
                wr(u32, pIndex, Index_tnum, initNewTnum(db));
                if (sqlite3IndexHasDuplicateRootPage(pIndex) != 0) {
                    sqlite3ErrorMsg(pParse, "invalid rootpage");
                    wr(c_int, pParse, Parse_rc, SQLITE_CORRUPT);
                    return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
                }
            }
            const pdup = sqlite3HashInsert(@ptrCast(base(rdp(pIndex, Index_pSchema)) + Schema_idxHash), @ptrCast(rdp(pIndex, Index_zName)), pIndex);
            if (pdup != null) {
                sqlite3OomFault(db);
                return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
            }
            wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) | DBFLAG_SchemaChange);
        } else if (hasRowid(pTab) or pTblName != null) {
            const v = sqlite3GetVdbe(pParse);
            if (v == null) return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
            const iMem = rd(c_int, pParse, Parse_nMem) + 1;
            wr(c_int, pParse, Parse_nMem, iMem);
            sqlite3BeginWriteOperation(pParse, 1, iDb);
            wr(u32, pIndex, Index_tnum, @intCast(sqlite3VdbeAddOp0(v, OP_Noop)));
            _ = sqlite3VdbeAddOp3(v, OP_CreateBtree, iDb, iMem, BTREE_BLOBKEY);
            var zStmt: ?[*:0]u8 = undefined;
            if (pStart != null) {
                const sLastZ = rdp(pParse, Parse_sLastToken + Token_z);
                var n: c_int = @intCast(@as(isize, @intCast(@intFromPtr(sLastZ.?))) - @as(isize, @intCast(@intFromPtr(tokenZ(pName).?))));
                n += @intCast(rd(u32, pParse, Parse_sLastToken + Token_n));
                if (tokenZ(pName).?[@intCast(n - 1)] == ';') n -= 1;
                zStmt = sqlite3MPrintf(db, "CREATE%s INDEX %.*s", @as([*:0]const u8, if (onError == OE_None) "" else " UNIQUE"), n, tokenZ(pName));
            } else {
                zStmt = null;
            }
            sqlite3NestedParse(pParse, "INSERT INTO %Q." ++ LEGACY_SCHEMA_TABLE ++ " VALUES('index',%Q,%Q,#%d,%Q);", dbZName(db, iDb), rdp(pIndex, Index_zName), rdp(pTab, Table_zName), iMem, zStmt);
            sqlite3DbFree(db, zStmt);
            if (pTblName != null) {
                sqlite3RefillIndex(pParse, pIndex, iMem);
                sqlite3ChangeCookie(pParse, iDb);
                sqlite3VdbeAddParseSchemaOp(v, iDb, sqlite3MPrintf(db, "name='%q' AND type='index'", rdp(pIndex, Index_zName)), 0);
                _ = sqlite3VdbeAddOp2(v, OP_Expire, 0, 1);
            }
            sqlite3VdbeJumpHere(v, @intCast(rd(u32, pIndex, Index_tnum)));
        }
    }
    if (initBusy(db) != 0 or pTblName == null) {
        wr(?*anyopaque, pIndex, Index_pNext, rdp(pTab, Table_pIndex));
        wr(?*anyopaque, pTab, Table_pIndex, pIndex);
        pIndex = null;
    } else if (inRenameObject(pParse)) {
        wr(?*anyopaque, pParse, Parse_pNewIndex, pIndex);
        pIndex = null;
    }

    return createIndexExit(pParse, db, pIndex, pTab, pPIWhere, pList, pTblName, zName);
}

fn createIndexExit(pParse: Cptr, db: Cptr, pIndex: Cptr, pTab: Cptr, pPIWhere: Cptr, pList: Cptr, pTblName: Cptr, zName: ?[*:0]u8) void {
    _ = pParse;
    if (pIndex != null) sqlite3FreeIndex(db, pIndex);
    if (pTab != null) {
        var ppFrom: *?*anyopaque = @ptrCast(@alignCast(base(pTab) + Table_pIndex));
        while (ppFrom.* != null) {
            const pThis = ppFrom.*;
            if (rd(u8, pThis, Index_onError) != @as(u8, @intCast(OE_Replace))) {
                ppFrom = @ptrCast(@alignCast(base(pThis) + Index_pNext));
                continue;
            }
            var pNext = rdp(pThis, Index_pNext);
            while (pNext != null and rd(u8, pNext, Index_onError) != @as(u8, @intCast(OE_Replace))) {
                ppFrom.* = pNext;
                wr(?*anyopaque, pThis, Index_pNext, rdp(pNext, Index_pNext));
                wr(?*anyopaque, pNext, Index_pNext, pThis);
                ppFrom = @ptrCast(@alignCast(base(pNext) + Index_pNext));
                pNext = rdp(pThis, Index_pNext);
            }
            break;
        }
    }
    sqlite3ExprDelete(db, pPIWhere);
    sqlite3ExprListDelete(db, pList);
    sqlite3SrcListDelete(db, pTblName);
    sqlite3DbFree(db, zName);
}

const sizeof_IdListItem_real = off("sizeof_IdList", 16); // SZ_IDLIST base = IdList_a; item is 8 bytes
inline fn idListN(n: c_int) usize {
    return IdList_a + @as(usize, @intCast(n)) * sizeof_IdListItem;
}

export fn sqlite3ArrayAllocate(db: Cptr, pArrayIn: ?*anyopaque, szEntry: c_int, pnEntry: *c_int, pIdx: *c_int) ?*anyopaque {
    var pArray = pArrayIn;
    const n: i64 = pnEntry.*;
    pIdx.* = @intCast(n);
    if ((n & (n - 1)) == 0) {
        const sz: i64 = if (n == 0) 1 else 2 * n;
        const pNew = sqlite3DbRealloc(db, pArray, @intCast(sz * szEntry));
        if (pNew == null) {
            pIdx.* = -1;
            return pArray;
        }
        pArray = pNew;
    }
    const z: [*]u8 = @ptrCast(pArray.?);
    @memset((z + @as(usize, @intCast(n * szEntry)))[0..@intCast(szEntry)], 0);
    pnEntry.* += 1;
    return pArray;
}

export fn sqlite3IdListAppend(pParse: Cptr, pListIn: Cptr, pToken: Cptr) Cptr {
    const db = parseDb(pParse);
    var pList = pListIn;
    if (pList == null) {
        pList = sqlite3DbMallocZero(db, IdList_a + sizeof_IdListItem);
        if (pList == null) return null;
    } else {
        const nId = rd(c_int, pList, IdList_nId);
        const pNew = sqlite3DbRealloc(db, pList, IdList_a + @as(u64, @intCast(nId + 1)) * sizeof_IdListItem);
        if (pNew == null) {
            sqlite3IdListDelete(db, pList);
            return null;
        }
        pList = pNew;
    }
    const i = rd(c_int, pList, IdList_nId);
    wr(c_int, pList, IdList_nId, i + 1);
    const item = base(pList) + idListN(i);
    wr(?*anyopaque, @ptrCast(item), 0, sqlite3NameFromToken(db, pToken));
    if (inRenameObject(pParse) and rdp(@ptrCast(item), 0) != null) {
        _ = sqlite3RenameTokenMap(pParse, rdp(@ptrCast(item), 0), pToken);
    }
    return pList;
}

export fn sqlite3IdListDelete(db: Cptr, pList: Cptr) void {
    if (pList == null) return;
    const nId = rd(c_int, pList, IdList_nId);
    var i: c_int = 0;
    while (i < nId) : (i += 1) {
        const item = base(pList) + idListN(i);
        sqlite3DbFree(db, rdp(@ptrCast(item), 0));
    }
    sqlite3DbNNFreeNN(db, pList);
}

export fn sqlite3IdListIndex(pList: Cptr, zName: [*:0]const u8) c_int {
    const nId = rd(c_int, pList, IdList_nId);
    var i: c_int = 0;
    while (i < nId) : (i += 1) {
        const item = base(pList) + idListN(i);
        if (sqlite3StrICmp(@ptrCast(rdp(@ptrCast(item), 0)), zName) == 0) return i;
    }
    return -1;
}

const SQLITE_MAX_SRCLIST: c_int = 200;

export fn sqlite3SrcListEnlarge(pParse: Cptr, pSrcIn: Cptr, nExtra: c_int, iStart: c_int) Cptr {
    var pSrc = pSrcIn;
    const nSrc = rd(c_int, pSrc, SrcList_nSrc);
    if (@as(u32, @intCast(nSrc)) + @as(u32, @intCast(nExtra)) > rd(u32, pSrc, SrcList_nAlloc)) {
        var nAlloc: i64 = 2 * @as(i64, nSrc) + nExtra;
        const db = parseDb(pParse);
        if (nSrc + nExtra >= SQLITE_MAX_SRCLIST) {
            sqlite3ErrorMsg(pParse, "too many FROM clause terms, max: %d", SQLITE_MAX_SRCLIST);
            return null;
        }
        if (nAlloc > SQLITE_MAX_SRCLIST) nAlloc = SQLITE_MAX_SRCLIST;
        const pNew = sqlite3DbRealloc(db, pSrc, SrcList_a + @as(u64, @intCast(nAlloc)) * sizeof_SrcItem);
        if (pNew == null) return null;
        pSrc = pNew;
        wr(u32, pSrc, SrcList_nAlloc, @intCast(nAlloc));
    }
    var i: c_int = rd(c_int, pSrc, SrcList_nSrc) - 1;
    while (i >= iStart) : (i -= 1) {
        const dst = base(pSrc) + SrcList_a + @as(usize, @intCast(i + nExtra)) * sizeof_SrcItem;
        const srcp = base(pSrc) + SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem;
        @memmove(dst[0..sizeof_SrcItem], srcp[0..sizeof_SrcItem]);
    }
    wr(c_int, pSrc, SrcList_nSrc, rd(c_int, pSrc, SrcList_nSrc) + nExtra);
    const zeroStart = base(pSrc) + SrcList_a + @as(usize, @intCast(iStart)) * sizeof_SrcItem;
    @memset(zeroStart[0 .. sizeof_SrcItem * @as(usize, @intCast(nExtra))], 0);
    i = iStart;
    while (i < iStart + nExtra) : (i += 1) {
        wr(c_int, @ptrCast(base(pSrc) + SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem), SrcItem_iCursor, -1);
    }
    return pSrc;
}

export fn sqlite3SrcListAppend(pParse: Cptr, pListIn: Cptr, pTable: Cptr, pDatabaseIn: Cptr) Cptr {
    var pList = pListIn;
    var pDatabase = pDatabaseIn;
    const db = parseDb(pParse);
    if (pList == null) {
        pList = sqlite3DbMallocRawNN(db, SrcList_a + sizeof_SrcItem);
        if (pList == null) return null;
        wr(u32, pList, SrcList_nAlloc, 1);
        wr(c_int, pList, SrcList_nSrc, 1);
        const item0 = base(pList) + SrcList_a;
        @memset(item0[0..sizeof_SrcItem], 0);
        wr(c_int, @ptrCast(item0), SrcItem_iCursor, -1);
    } else {
        const pNew = sqlite3SrcListEnlarge(pParse, pList, 1, rd(c_int, pList, SrcList_nSrc));
        if (pNew == null) {
            sqlite3SrcListDelete(db, pList);
            return null;
        } else {
            pList = pNew;
        }
    }
    const pItem = base(pList) + SrcList_a + @as(usize, @intCast(rd(c_int, pList, SrcList_nSrc) - 1)) * sizeof_SrcItem;
    if (pDatabase != null and tokenZ(pDatabase) == null) {
        pDatabase = null;
    }
    if (pDatabase != null) {
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_zName, sqlite3NameFromToken(db, pDatabase));
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_u4, sqlite3NameFromToken(db, pTable));
    } else {
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_zName, sqlite3NameFromToken(db, pTable));
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_u4, null);
    }
    return pList;
}

export fn sqlite3SrcListAssignCursors(pParse: Cptr, pList: Cptr) void {
    if (pList == null) return;
    const nSrc = rd(c_int, pList, SrcList_nSrc);
    var i: c_int = 0;
    while (i < nSrc) : (i += 1) {
        const pItem = base(pList) + SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem;
        if (rd(c_int, @ptrCast(pItem), SrcItem_iCursor) >= 0) continue;
        wr(c_int, @ptrCast(pItem), SrcItem_iCursor, rd(c_int, pParse, Parse_nTab));
        wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
        if (srcItemFgIsSubquery(@ptrCast(pItem))) {
            const pSubq = rdp(@ptrCast(pItem), SrcItem_u4);
            sqlite3SrcListAssignCursors(pParse, rdp(rdp(pSubq, Subquery_pSelect), Select_pSrc));
        }
    }
}

export fn sqlite3SubqueryDelete(db: Cptr, pSubq: Cptr) void {
    sqlite3SelectDelete(db, rdp(pSubq, Subquery_pSelect));
    sqlite3DbFree(db, pSubq);
}

export fn sqlite3SubqueryDetach(db: Cptr, pItem: Cptr) Cptr {
    const pSubq = rdp(pItem, SrcItem_u4);
    const pSel = rdp(pSubq, Subquery_pSelect);
    sqlite3DbFree(db, pSubq);
    wr(?*anyopaque, pItem, SrcItem_u4, null);
    base(pItem)[SrcItem_fg + FG_b1] &= ~FG_isSubquery;
    return pSel;
}

export fn sqlite3SrcListDelete(db: Cptr, pList: Cptr) void {
    if (pList == null) return;
    const nSrc = rd(c_int, pList, SrcList_nSrc);
    var i: c_int = 0;
    while (i < nSrc) : (i += 1) {
        const pItem = base(pList) + SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem;
        if (rdp(@ptrCast(pItem), SrcItem_zName) != null) sqlite3DbNNFreeNN(db, rdp(@ptrCast(pItem), SrcItem_zName));
        if (rdp(@ptrCast(pItem), SrcItem_zAlias) != null) sqlite3DbNNFreeNN(db, rdp(@ptrCast(pItem), SrcItem_zAlias));
        if (srcItemFgIsSubquery(@ptrCast(pItem))) {
            sqlite3SubqueryDelete(db, rdp(@ptrCast(pItem), SrcItem_u4));
        } else if (!srcItemFgFixedSchema(@ptrCast(pItem)) and rdp(@ptrCast(pItem), SrcItem_u4) != null) {
            sqlite3DbNNFreeNN(db, rdp(@ptrCast(pItem), SrcItem_u4));
        }
        if ((base(pItem)[SrcItem_fg + FG_b1] & FG_isIndexedBy) != 0) sqlite3DbFree(db, rdp(@ptrCast(pItem), SrcItem_u1));
        if ((base(pItem)[SrcItem_fg + FG_b1] & FG_isTabFunc) != 0) sqlite3ExprListDelete(db, rdp(@ptrCast(pItem), SrcItem_u1));
        sqlite3DeleteTable(db, rdp(@ptrCast(pItem), SrcItem_pSTab));
        if ((base(pItem)[SrcItem_fg + FG_b2] & FG_isUsing) != 0) {
            sqlite3IdListDelete(db, rdp(@ptrCast(pItem), SrcItem_u3));
        } else if (rdp(@ptrCast(pItem), SrcItem_u3) != null) {
            sqlite3ExprDelete(db, rdp(@ptrCast(pItem), SrcItem_u3));
        }
    }
    sqlite3DbNNFreeNN(db, pList);
}

export fn sqlite3SrcItemAttachSubquery(pParse: Cptr, pItem: Cptr, pSelectIn: Cptr, dupSelect: c_int) c_int {
    var pSelect = pSelectIn;
    if (srcItemFgFixedSchema(pItem)) {
        wr(?*anyopaque, pItem, SrcItem_u4, null);
        base(pItem)[SrcItem_fg + FG_b3] &= ~FG_fixedSchema;
    } else if (rdp(pItem, SrcItem_u4) != null) {
        sqlite3DbFree(parseDb(pParse), rdp(pItem, SrcItem_u4));
        wr(?*anyopaque, pItem, SrcItem_u4, null);
    }
    if (dupSelect != 0) {
        pSelect = sqlite3SelectDup(parseDb(pParse), pSelect, 0);
        if (pSelect == null) return 0;
    }
    const p = sqlite3DbMallocRawNN(parseDb(pParse), sizeof_Subquery);
    wr(?*anyopaque, pItem, SrcItem_u4, p);
    if (p == null) {
        sqlite3SelectDelete(parseDb(pParse), pSelect);
        return 0;
    }
    base(pItem)[SrcItem_fg + FG_b1] |= FG_isSubquery;
    wr(?*anyopaque, p, Subquery_pSelect, pSelect);
    @memset((base(p) + @sizeOf(usize))[0 .. sizeof_Subquery - @sizeOf(usize)], 0);
    return 1;
}
const sizeof_Subquery = off("sizeof_Subquery", 24);

export fn sqlite3SrcListAppendFromTerm(pParse: Cptr, pIn: Cptr, pTable: Cptr, pDatabase: Cptr, pAlias: Cptr, pSubquery: Cptr, pOnUsing: Cptr) Cptr {
    var p = pIn;
    const db = parseDb(pParse);
    if (p == null and pOnUsing != null and (rdp(pOnUsing, OnOrUsing_pOn) != null or rdp(pOnUsing, OnOrUsing_pUsing) != null)) {
        sqlite3ErrorMsg(pParse, "a JOIN clause is required before %s", @as([*:0]const u8, if (rdp(pOnUsing, OnOrUsing_pOn) != null) "ON" else "USING"));
        sqlite3ClearOnOrUsing(db, pOnUsing);
        sqlite3SelectDelete(db, pSubquery);
        return null;
    }
    p = sqlite3SrcListAppend(pParse, p, pTable, pDatabase);
    if (p == null) {
        sqlite3ClearOnOrUsing(db, pOnUsing);
        sqlite3SelectDelete(db, pSubquery);
        return null;
    }
    const pItem = base(p) + SrcList_a + @as(usize, @intCast(rd(c_int, p, SrcList_nSrc) - 1)) * sizeof_SrcItem;
    if (inRenameObject(pParse) and rdp(@ptrCast(pItem), SrcItem_zName) != null) {
        const pToken = if (pDatabase != null and tokenZ(pDatabase) != null) pDatabase else pTable;
        _ = sqlite3RenameTokenMap(pParse, rdp(@ptrCast(pItem), SrcItem_zName), pToken);
    }
    if (pAlias != null and tokenN(pAlias) != 0) {
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_zAlias, sqlite3NameFromToken(db, pAlias));
    }
    if (pSubquery != null) {
        if (sqlite3SrcItemAttachSubquery(pParse, @ptrCast(pItem), pSubquery, 0) != 0) {
            if ((rd(u32, pSubquery, Select_selFlags) & SF_NestedFrom) != 0) {
                base(pItem)[SrcItem_fg + FG_b2] |= FG_isNestedFrom;
            }
        }
    }
    if (pOnUsing == null) {
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_u3, null);
    } else if (rdp(pOnUsing, OnOrUsing_pUsing) != null) {
        base(pItem)[SrcItem_fg + FG_b2] |= FG_isUsing;
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_u3, rdp(pOnUsing, OnOrUsing_pUsing));
    } else {
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_u3, rdp(pOnUsing, OnOrUsing_pOn));
    }
    return p;
}
const OnOrUsing_pOn: usize = 0;
const OnOrUsing_pUsing: usize = 8;

export fn sqlite3SrcListIndexedBy(pParse: Cptr, p: Cptr, pIndexedBy: Cptr) void {
    if (p != null and tokenN(pIndexedBy) > 0) {
        const pItem = base(p) + SrcList_a + @as(usize, @intCast(rd(c_int, p, SrcList_nSrc) - 1)) * sizeof_SrcItem;
        if (tokenN(pIndexedBy) == 1 and tokenZ(pIndexedBy) == null) {
            base(pItem)[SrcItem_fg + FG_b1] |= FG_notIndexed;
        } else {
            wr(?*anyopaque, @ptrCast(pItem), SrcItem_u1, sqlite3NameFromToken(parseDb(pParse), pIndexedBy));
            base(pItem)[SrcItem_fg + FG_b1] |= FG_isIndexedBy;
        }
    }
}

export fn sqlite3SrcListAppendList(pParse: Cptr, p1: Cptr, p2: Cptr) Cptr {
    var r = p1;
    if (p2 != null) {
        const nOld = rd(c_int, p1, SrcList_nSrc);
        const pNew = sqlite3SrcListEnlarge(pParse, p1, rd(c_int, p2, SrcList_nSrc), nOld);
        if (pNew == null) {
            sqlite3SrcListDelete(parseDb(pParse), p2);
        } else {
            r = pNew;
            const dst = base(r) + SrcList_a + @as(usize, @intCast(nOld)) * sizeof_SrcItem;
            const src = base(p2) + SrcList_a;
            const cnt = @as(usize, @intCast(rd(c_int, p2, SrcList_nSrc))) * sizeof_SrcItem;
            @memmove(dst[0..cnt], src[0..cnt]);
            // p1->a[0].fg.jointype |= JT_LTORJ & p2->a[0].fg.jointype
            const jt0 = base(r)[SrcList_a + SrcItem_fg];
            const jt2 = base(p2)[SrcList_a + SrcItem_fg];
            base(r)[SrcList_a + SrcItem_fg] = jt0 | (JT_LTORJ & jt2);
            sqlite3DbFree(parseDb(pParse), p2);
        }
    }
    return r;
}
const JT_LTORJ: u8 = 0x40;
const JT_RIGHT: u8 = 0x20;

export fn sqlite3SrcListFuncArgs(pParse: Cptr, p: Cptr, pList: Cptr) void {
    if (p != null) {
        const pItem = base(p) + SrcList_a + @as(usize, @intCast(rd(c_int, p, SrcList_nSrc) - 1)) * sizeof_SrcItem;
        wr(?*anyopaque, @ptrCast(pItem), SrcItem_u1, pList);
        base(pItem)[SrcItem_fg + FG_b1] |= FG_isTabFunc;
    } else {
        sqlite3ExprListDelete(parseDb(pParse), pList);
    }
}

export fn sqlite3SrcListShiftJoinType(pParse: Cptr, p: Cptr) void {
    _ = pParse;
    if (p != null and rd(c_int, p, SrcList_nSrc) > 1) {
        var i: c_int = rd(c_int, p, SrcList_nSrc) - 1;
        var allFlags: u8 = 0;
        while (true) {
            const cur = base(p) + SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem;
            const prev = base(p) + SrcList_a + @as(usize, @intCast(i - 1)) * sizeof_SrcItem;
            const jt = prev[SrcItem_fg];
            cur[SrcItem_fg] = jt;
            allFlags |= jt;
            i -= 1;
            if (i <= 0) break;
        }
        base(p)[SrcList_a + SrcItem_fg] = 0;
        if ((allFlags & JT_RIGHT) != 0) {
            i = rd(c_int, p, SrcList_nSrc) - 1;
            while (i > 0 and (base(p)[SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem + SrcItem_fg] & JT_RIGHT) == 0) i -= 1;
            i -= 1;
            while (i >= 0) : (i -= 1) {
                base(p)[SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem + SrcItem_fg] |= JT_LTORJ;
            }
        }
    }
}

export fn sqlite3BeginTransaction(pParse: Cptr, typ: c_int) void {
    const db = parseDb(pParse);
    if (sqlite3AuthCheck(pParse, SQLITE_TRANSACTION, "BEGIN", null, null) != 0) return;
    const v = sqlite3GetVdbe(pParse);
    if (v == null) return;
    if (typ != TK_DEFERRED) {
        var i: c_int = 0;
        const nDb = dbNDb(db);
        while (i < nDb) : (i += 1) {
            var eTxnType: c_int = undefined;
            const pBt = rdp(dbAt(db, i), Db_pBt);
            if (pBt != null and sqlite3BtreeIsReadonly(pBt) != 0) {
                eTxnType = 0;
            } else if (typ == TK_EXCLUSIVE) {
                eTxnType = 2;
            } else {
                eTxnType = 1;
            }
            _ = sqlite3VdbeAddOp2(v, OP_Transaction, i, eTxnType);
            sqlite3VdbeUsesBtree(v, i);
        }
    }
    _ = sqlite3VdbeAddOp0(v, OP_AutoCommit);
}

export fn sqlite3EndTransaction(pParse: Cptr, eType: c_int) void {
    const isRollback: c_int = @intFromBool(eType == TK_ROLLBACK);
    if (sqlite3AuthCheck(pParse, SQLITE_TRANSACTION, if (isRollback != 0) "ROLLBACK" else "COMMIT", null, null) != 0) return;
    const v = sqlite3GetVdbe(pParse);
    if (v != null) {
        _ = sqlite3VdbeAddOp2(v, OP_AutoCommit, 1, isRollback);
    }
}

export fn sqlite3Savepoint(pParse: Cptr, op: c_int, pName: Cptr) void {
    const zName = sqlite3NameFromToken(parseDb(pParse), pName);
    if (zName != null) {
        const v = sqlite3GetVdbe(pParse);
        const az = [_][*:0]const u8{ "BEGIN", "RELEASE", "ROLLBACK" };
        if (v == null or sqlite3AuthCheck(pParse, SQLITE_SAVEPOINT, az[@intCast(op)], @ptrCast(zName), null) != 0) {
            sqlite3DbFree(parseDb(pParse), zName);
            return;
        }
        _ = sqlite3VdbeAddOp4(v, OP_Savepoint, op, 0, 0, @ptrCast(zName), P4_DYNAMIC);
    }
}

export fn sqlite3OpenTempDatabase(pParse: Cptr) c_int {
    const db = parseDb(pParse);
    if (rdp(dbAt(db, 1), Db_pBt) == null and rd(c_int, pParse, Parse_explain) == 0) {
        const flags: c_int = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_TEMP_DB;
        var pBt: Cptr = null;
        const rc = sqlite3BtreeOpen(rdp(db, sqlite3_pVfs), null, db, &pBt, 0, flags);
        if (rc != SQLITE_OK) {
            sqlite3ErrorMsg(pParse, "unable to open a temporary database file for storing temporary tables");
            wr(c_int, pParse, Parse_rc, rc);
            return 1;
        }
        wr(?*anyopaque, dbAt(db, 1), Db_pBt, pBt);
        if (sqlite3BtreeSetPageSize(pBt, rd(c_int, db, sqlite3_nextPagesize), 0, 0) == SQLITE_NOMEM) {
            sqlite3OomFault(db);
            return 1;
        }
    }
    return 0;
}

fn sqlite3CodeVerifySchemaAtToplevel(pToplevel: Cptr, iDb: c_int) void {
    if (!dbMaskTest(pToplevel, Parse_cookieMask, iDb)) {
        dbMaskSet(pToplevel, Parse_cookieMask, iDb);
        if (OMIT_TEMPDB == 0 and iDb == 1) {
            _ = sqlite3OpenTempDatabase(pToplevel);
        }
    }
}

export fn sqlite3CodeVerifySchema(pParse: Cptr, iDb: c_int) void {
    sqlite3CodeVerifySchemaAtToplevel(parseToplevel(pParse), iDb);
}

export fn sqlite3CodeVerifyNamedSchema(pParse: Cptr, zDb: ?[*:0]const u8) void {
    const db = parseDb(pParse);
    var i: c_int = 0;
    const nDb = dbNDb(db);
    while (i < nDb) : (i += 1) {
        const pDb = dbAt(db, i);
        if (rdp(pDb, Db_pBt) != null and (zDb == null or sqlite3StrICmp(zDb, @ptrCast(rdp(pDb, Db_zDbSName))) == 0)) {
            sqlite3CodeVerifySchema(pParse, i);
        }
    }
}

export fn sqlite3BeginWriteOperation(pParse: Cptr, setStatement: c_int, iDb: c_int) void {
    const pToplevel = parseToplevel(pParse);
    sqlite3CodeVerifySchemaAtToplevel(pToplevel, iDb);
    dbMaskSet(pToplevel, Parse_writeMask, iDb);
    if (setStatement != 0) wr(u8, pToplevel, Parse_isMultiWrite, 1);
}

export fn sqlite3MultiWrite(pParse: Cptr) void {
    const pToplevel = parseToplevel(pParse);
    wr(u8, pToplevel, Parse_isMultiWrite, 1);
}

export fn sqlite3MayAbort(pParse: Cptr) void {
    const pToplevel = parseToplevel(pParse);
    bftSet(pToplevel, Parse_bft_byte, BFT_mayAbort);
}

export fn sqlite3HaltConstraint(pParse: Cptr, errCode: c_int, onError: c_int, p4: ?[*:0]u8, p4type: i8, p5Errmsg: u8) void {
    const v = sqlite3GetVdbe(pParse);
    if (onError == OE_Abort) {
        sqlite3MayAbort(pParse);
    }
    _ = sqlite3VdbeAddOp4(v, OP_Halt, errCode, onError, 0, @ptrCast(p4), p4type);
    sqlite3VdbeChangeP5(v, p5Errmsg);
}

export fn sqlite3UniqueConstraint(pParse: Cptr, onError: c_int, pIdx: Cptr) void {
    const pTab = rdp(pIdx, Index_pTable);
    var errMsg: [sizeof_StrAccum]u8 align(8) = undefined;
    sqlite3StrAccumInit(@ptrCast(&errMsg), parseDb(pParse), null, 0, limitLen(parseDb(pParse)));
    if (rdp(pIdx, Index_aColExpr) != null) {
        sqlite3_str_appendf(@ptrCast(&errMsg), "index '%q'", rdp(pIdx, Index_zName));
    } else {
        const nKeyCol = rd(u16, pIdx, Index_nKeyCol);
        const aiColumn: [*]const i16 = @ptrCast(@alignCast(rdp(pIdx, Index_aiColumn).?));
        var j: c_int = 0;
        while (j < nKeyCol) : (j += 1) {
            const zCol: [*:0]const u8 = @ptrCast(rdp(colAt(pTab, aiColumn[@intCast(j)]), Column_zCnName).?);
            if (j != 0) sqlite3_str_append(@ptrCast(&errMsg), ", ", 2);
            sqlite3_str_appendall(@ptrCast(&errMsg), @ptrCast(rdp(pTab, Table_zName)));
            sqlite3_str_append(@ptrCast(&errMsg), ".", 1);
            sqlite3_str_appendall(@ptrCast(&errMsg), zCol);
        }
    }
    const zErr = sqlite3StrAccumFinish(@ptrCast(&errMsg));
    sqlite3HaltConstraint(pParse, if (isPrimaryKeyIndex(pIdx)) SQLITE_CONSTRAINT_PRIMARYKEY else SQLITE_CONSTRAINT_UNIQUE, onError, zErr, P4_DYNAMIC, P5_ConstraintUnique);
}
const sizeof_StrAccum = off("sizeof_sqlite3_str", 48);

export fn sqlite3RowidConstraint(pParse: Cptr, onError: c_int, pTab: Cptr) void {
    var zMsg: ?[*:0]u8 = undefined;
    var rc: c_int = undefined;
    if (rd(i16, pTab, Table_iPKey) >= 0) {
        zMsg = sqlite3MPrintf(parseDb(pParse), "%s.%s", rdp(pTab, Table_zName), rdp(colAt(pTab, rd(i16, pTab, Table_iPKey)), Column_zCnName));
        rc = SQLITE_CONSTRAINT_PRIMARYKEY;
    } else {
        zMsg = sqlite3MPrintf(parseDb(pParse), "%s.rowid", rdp(pTab, Table_zName));
        rc = SQLITE_CONSTRAINT_ROWID;
    }
    sqlite3HaltConstraint(pParse, rc, onError, zMsg, P4_DYNAMIC, P5_ConstraintUnique);
}

fn collationMatch(zColl: [*:0]const u8, pIndex: Cptr) bool {
    const nColumn = rd(u16, pIndex, Index_nColumn);
    const azColl: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pIndex, Index_azColl).?));
    var i: c_int = 0;
    while (i < nColumn) : (i += 1) {
        if (sqlite3StrICmp(azColl[@intCast(i)], zColl) == 0) return true;
    }
    return false;
}

export fn sqlite3Reindex(pParse: Cptr, pName1: Cptr, pName2: Cptr) void {
    var z: ?[*:0]u8 = null;
    var zDb: ?[*:0]const u8 = null;
    var iReDb: c_int = -1;
    const db = parseDb(pParse);
    var zColl: ?[*:0]const u8 = null;
    var pReTab: Cptr = null;
    var pReIndex: Cptr = null;
    var isExprIdx: bool = false;
    var bAll: bool = false;
    var bMatch: bool = false;

    if (sqlite3ReadSchema(pParse) != SQLITE_OK) return;

    if (pName1 == null) {
        bMatch = true;
        bAll = true;
    } else if (pName2 == null or tokenZ(pName2) == null) {
        z = sqlite3NameFromToken(db, pName1);
        if (z == null) return;
    } else {
        var pObjName: Cptr = null;
        iReDb = sqlite3TwoPartName(pParse, pName1, pName2, &pObjName);
        if (iReDb < 0) return;
        z = sqlite3NameFromToken(db, pObjName);
        if (z == null) return;
        zDb = dbZName(db, iReDb);
    }
    if (!bAll) {
        if (zDb == null and sqlite3StrICmp(@ptrCast(z), "expressions") == 0) {
            isExprIdx = true;
            bMatch = true;
        }
        if (zDb == null and sqlite3FindCollSeq(db, rd(u8, db, sqlite3_enc), @ptrCast(z), 0) != null) {
            zColl = @ptrCast(z);
            bMatch = true;
        }
        if (zColl == null) {
            pReTab = sqlite3FindTable(db, @ptrCast(z), zDb);
            if (pReTab != null) bMatch = true;
        }
        if (zColl == null) {
            pReIndex = sqlite3FindIndex(db, @ptrCast(z), zDb);
            if (pReIndex != null) bMatch = true;
        }
    }
    if (bMatch) {
        var iDb: c_int = 0;
        const nDb = dbNDb(db);
        while (iDb < nDb) : (iDb += 1) {
            if (iReDb >= 0 and iReDb != iDb) continue;
            var k = hashFirst(@ptrCast(base(dbSchema(db, iDb)) + Schema_tblHash));
            while (k != null) : (k = hashNext(k)) {
                const pTab = hashData(k);
                if (isVirtual(pTab)) continue;
                var pIdx = rdp(pTab, Table_pIndex);
                while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
                    if (bAll or pTab == pReTab or pIdx == pReIndex or (isExprIdx and (base(pIdx)[Index_bits2_byte] & IDX_bHasExpr) != 0) or (zColl != null and collationMatch(zColl.?, pIdx))) {
                        sqlite3BeginWriteOperation(pParse, 0, iDb);
                        sqlite3RefillIndex(pParse, pIdx, -1);
                    }
                }
            }
        }
    } else {
        sqlite3ErrorMsg(pParse, "unable to identify the object to be reindexed");
    }
    sqlite3DbFree(db, z);
}

export fn sqlite3KeyInfoOfIndex(pParse: Cptr, pIdx: Cptr) Cptr {
    const nCol = rd(u16, pIdx, Index_nColumn);
    const nKey = rd(u16, pIdx, Index_nKeyCol);
    if (rd(c_int, pParse, Parse_nErr) != 0) return null;
    var pKey: Cptr = undefined;
    if ((base(pIdx)[Index_bits_byte] & IDX_uniqNotNull) != 0) {
        pKey = sqlite3KeyInfoAlloc(parseDb(pParse), nKey, nCol - nKey);
    } else {
        pKey = sqlite3KeyInfoAlloc(parseDb(pParse), nCol, 0);
    }
    if (pKey != null) {
        const azColl: [*]const ?[*:0]const u8 = @ptrCast(@alignCast(rdp(pIdx, Index_azColl).?));
        const aSortOrder: [*]const u8 = @ptrCast(rdp(pIdx, Index_aSortOrder).?);
        // KeyInfo.aColl is INLINE array
        const aColl: [*]?*anyopaque = @ptrCast(@alignCast(base(pKey) + KeyInfo_aColl));
        const aSortFlags: [*]u8 = @ptrCast(rdp(pKey, KeyInfo_aSortFlags).?);
        var i: c_int = 0;
        while (i < nCol) : (i += 1) {
            const zColl = azColl[@intCast(i)];
            aColl[@intCast(i)] = if (zColl == @as(?[*:0]const u8, @ptrCast(&sqlite3StrBINARY))) null else sqlite3LocateCollSeq(pParse, zColl);
            aSortFlags[@intCast(i)] = aSortOrder[@intCast(i)];
        }
        if (rd(c_int, pParse, Parse_nErr) != 0) {
            if ((base(pIdx)[Index_bits_byte] & IDX_bNoQuery) == 0 and sqlite3HashFind(@ptrCast(base(rdp(pIdx, Index_pSchema)) + Schema_idxHash), @ptrCast(rdp(pIdx, Index_zName))) != null) {
                base(pIdx)[Index_bits_byte] |= IDX_bNoQuery;
                wr(c_int, pParse, Parse_rc, SQLITE_ERROR_RETRY);
            }
            sqlite3KeyInfoUnref(pKey);
            pKey = null;
        }
    }
    return pKey;
}

export fn sqlite3CteNew(pParse: Cptr, pName: Cptr, pArglist: Cptr, pQuery: Cptr, eM10d: u8) Cptr {
    const db = parseDb(pParse);
    const pNew = sqlite3DbMallocZero(db, sizeof_Cte);
    if (mallocFailed(db)) {
        sqlite3ExprListDelete(db, pArglist);
        sqlite3SelectDelete(db, pQuery);
    } else {
        wr(?*anyopaque, pNew, Cte_pSelect, pQuery);
        wr(?*anyopaque, pNew, Cte_pCols, pArglist);
        wr(?*anyopaque, pNew, Cte_zName, sqlite3NameFromToken(db, pName));
        wr(u8, pNew, Cte_eM10d, eM10d);
    }
    return pNew;
}

fn cteClear(db: Cptr, pCte: Cptr) void {
    sqlite3ExprListDelete(db, rdp(pCte, Cte_pCols));
    sqlite3SelectDelete(db, rdp(pCte, Cte_pSelect));
    sqlite3DbFree(db, rdp(pCte, Cte_zName));
}

export fn sqlite3CteDelete(db: Cptr, pCte: Cptr) void {
    cteClear(db, pCte);
    sqlite3DbFree(db, pCte);
}

export fn sqlite3WithAdd(pParse: Cptr, pWith: Cptr, pCte: Cptr) Cptr {
    const db = parseDb(pParse);
    var pNew: Cptr = undefined;
    if (pCte == null) {
        return pWith;
    }
    const zName: ?[*:0]const u8 = @ptrCast(rdp(pCte, Cte_zName));
    if (zName != null and pWith != null) {
        const nCte = rd(c_int, pWith, With_nCte);
        var i: c_int = 0;
        while (i < nCte) : (i += 1) {
            const item = base(pWith) + With_a + @as(usize, @intCast(i)) * sizeof_Cte;
            if (sqlite3StrICmp(zName, @ptrCast(rdp(@ptrCast(item), Cte_zName))) == 0) {
                sqlite3ErrorMsg(pParse, "duplicate WITH table name: %s", zName);
            }
        }
    }
    if (pWith != null) {
        pNew = sqlite3DbRealloc(db, pWith, With_a + @as(u64, @intCast(rd(c_int, pWith, With_nCte) + 1)) * sizeof_Cte);
    } else {
        pNew = sqlite3DbMallocZero(db, With_a + sizeof_Cte);
    }
    if (mallocFailed(db)) {
        sqlite3CteDelete(db, pCte);
        pNew = pWith;
    } else {
        const n = rd(c_int, pNew, With_nCte);
        const dst = base(pNew) + With_a + @as(usize, @intCast(n)) * sizeof_Cte;
        @memmove(dst[0..sizeof_Cte], base(pCte)[0..sizeof_Cte]);
        wr(c_int, pNew, With_nCte, n + 1);
        sqlite3DbFree(db, pCte);
    }
    return pNew;
}

export fn sqlite3WithDelete(db: Cptr, pWith: Cptr) void {
    if (pWith != null) {
        const nCte = rd(c_int, pWith, With_nCte);
        var i: c_int = 0;
        while (i < nCte) : (i += 1) {
            cteClear(db, @ptrCast(base(pWith) + With_a + @as(usize, @intCast(i)) * sizeof_Cte));
        }
        sqlite3DbFree(db, pWith);
    }
}

export fn sqlite3WithDeleteGeneric(db: Cptr, pWith: ?*anyopaque) void {
    sqlite3WithDelete(db, pWith);
}
