//! Zig port of SQLite's src/select.c — the SELECT statement code generator.
//! Every non-static function of select.c is exported here with the same C ABI;
//! static helpers become private Zig fns.  Struct fields are accessed via
//! ground-truth offsets (src/c_layout.zig) using the raw-memory helper idiom
//! shared with build.zig / resolve.zig / expr.zig.
//!
//! Config assumptions (true in BOTH production and the --dev testfixture):
//! SQLITE_OMIT_* all OFF (SUBQUERY, VIEW, TRIGGER, CTE, WINDOWFUNC, COMPOUND_
//! SELECT, EXPLAIN, DECLTYPE all present).  SQLITE_ENABLE_SORTER_REFERENCES,
//! _COLUMN_METADATA, _STMT_SCANSTATUS OFF.  SQLITE_ALLOW_ROWID_IN_VIEW OFF.
//! SQLITE_DEBUG / TREETRACE handled via config.sqlite_debug (treeview/asserts
//! gated; SF_WhereBegin debug bit unused at runtime here).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers (shared idiom with expr.zig/build.zig) ───────────────
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

const Ptr = ?*anyopaque;

// ════════════════════════════════════════════════════════════════════════════
// Struct field offsets (from c_layout, with probe-verified fallbacks for the
// handful of fields not yet present there — see final report).
// ════════════════════════════════════════════════════════════════════════════
const Select_op = off("Select_op", 0);
const Select_selFlags = off("Select_selFlags", 4);
const Select_nSelectRow = off("Select_nSelectRow", 2);
const Select_iLimit = off("Select_iLimit", 8);
const Select_iOffset = off("Select_iOffset", 12);
const Select_selId = off("Select_selId", 16);
const Select_pEList = off("Select_pEList", 24);
const Select_pSrc = off("Select_pSrc", 32);
const Select_pWhere = off("Select_pWhere", 40);
const Select_pGroupBy = off("Select_pGroupBy", 48);
const Select_pHaving = off("Select_pHaving", 56);
const Select_pOrderBy = off("Select_pOrderBy", 64);
const Select_pPrior = off("Select_pPrior", 72);
const Select_pNext = off("Select_pNext", 80);
const Select_pLimit = off("Select_pLimit", 88);
const Select_pWith = off("Select_pWith", 96);
const Select_pWin = off("Select_pWin", 104);
const Select_pWinDefn = off("Select_pWinDefn", 112);
const sizeof_Select = off("sizeof_Select", 120);

const SelectDest_eDest = off("SelectDest_eDest", 0);
const SelectDest_iSDParm = off("SelectDest_iSDParm", 4);
const SelectDest_iSDParm2 = off("SelectDest_iSDParm2", 8);
const SelectDest_iSdst = off("SelectDest_iSdst", 12);
const SelectDest_nSdst = off("SelectDest_nSdst", 16);
const SelectDest_zAffSdst = off("SelectDest_zAffSdst", 24);
// pOrderBy follows the 24-byte head + nSdst/iSdst; not in layout. probe: 32.
const SelectDest_pOrderBy = off("SelectDest_pOrderBy", 32);
const sizeof_SelectDest = off("sizeof_SelectDest", 40);

const SrcList_nSrc = off("SrcList_nSrc", 0);
const SrcList_a = off("SrcList_a", 8);
const sizeof_SrcList = off("sizeof_SrcList", 8);
const SZ_SRCLIST_1 = off("SZ_SRCLIST_1", 80);

const SrcItem_zName = off("SrcItem_zName", 0);
const SrcItem_zAlias = off("SrcItem_zAlias", 8);
const SrcItem_pSTab = off("SrcItem_pSTab", 16);
const SrcItem_fg = off("SrcItem_fg", 24);
const SrcItem_iCursor = off("SrcItem_iCursor", 28);
const SrcItem_colUsed = off("SrcItem_colUsed", 32);
const SrcItem_u1 = off("SrcItem_u1", 40);
const SrcItem_u2 = off("SrcItem_u2", 48);
const SrcItem_u3 = off("SrcItem_u3", 56);
const SrcItem_u4 = off("SrcItem_u4", 64);
const SrcItem_u4_pSubq = off("SrcItem_u4_pSubq", 64);
const SrcItem_u4_zDatabase = off("SrcItem_u4_zDatabase", 64);
const sizeof_SrcItem = off("sizeof_SrcItem", 72);

const Subquery_pSelect = off("Subquery_pSelect", 0);
const Subquery_addrFillSub = off("Subquery_addrFillSub", 8);
const Subquery_regReturn = off("Subquery_regReturn", 12);
const Subquery_regResult = off("Subquery_regResult", 16);
const sizeof_Subquery = off("sizeof_Subquery", 24);

const ExprList_nExpr = off("ExprList_nExpr", 0);
const ExprList_a = off("ExprList_a", 8);
const ExprList_item_pExpr = off("ExprList_item_pExpr", 0);
const ExprList_item_zEName = off("ExprList_item_zEName", 8);
const ExprList_item_fg = off("ExprList_item_fg", 16);
const ExprList_item_fg_sortFlags = off("ExprList_item_fg_sortFlags", 16);
const ExprList_item_u = off("ExprList_item_u", 20);
const ExprList_item_u_x_iOrderByCol = off("ExprList_item_u_x_iOrderByCol", 20);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);

const Expr_op = off("Expr_op", 0);
const Expr_op2 = off("Expr_op2", 2);
const Expr_affExpr = off("Expr_affExpr", 1);
const Expr_flags = off("Expr_flags", 4);
const Expr_u = off("Expr_u", 8);
const Expr_pLeft = off("Expr_pLeft", 16);
const Expr_pRight = off("Expr_pRight", 24);
const Expr_x = off("Expr_x", 32);
const Expr_iTable = off("Expr_iTable", 44);
const Expr_iColumn = off("Expr_iColumn", 48);
const Expr_iAgg = off("Expr_iAgg", 50);
const Expr_w = off("Expr_w", 52); // w.iJoin / w.iOfst (int)
const Expr_y = off("Expr_y", 64); // y.pTab / y.pWin / y.pSelect
const Expr_pAggInfo = off("Expr_pAggInfo", 56);
const sizeof_Expr = off("sizeof_Expr", 72);

const Table_zName = off("Table_zName", 0);
const Table_aCol = off("Table_aCol", 8);
const Table_pIndex = off("Table_pIndex", 16);
const Table_zColAff = off("Table_zColAff", 24);
const Table_tnum = off("Table_tnum", 40);
const Table_tabFlags = off("Table_tabFlags", 48);
const Table_iPKey = off("Table_iPKey", 52);
const Table_nCol = off("Table_nCol", 54);
const Table_nNVCol = off("Table_nNVCol", 56);
const Table_nRowLogEst = off("Table_nRowLogEst", 58);
const Table_szTabRow = off("Table_szTabRow", 60);
const Table_eTabType = off("Table_eTabType", 63);
const Table_u = off("Table_u", 64);
const Table_nTabRef = off("Table_nTabRef", 44);
const Table_pSchema = off("Table_pSchema", 96);
const Table_u_view_pSelect = off("Table_u_view_pSelect", 64);
const Table_u_vtab_p = off("Table_u_vtab_p", 80);
const Table_aHx = off("Table_aHx", 104);
const sizeof_Table = off("sizeof_Table", 120);

const Column_zCnName = off("Column_zCnName", 0);
const Column_affinity = off("Column_affinity", 9);
const Column_hName = off("Column_hName", 11);
const Column_colFlags = off("Column_colFlags", 14);
const sizeof_Column = off("sizeof_Column", 16);

const Index_zName = off("Index_zName", 0);
const Index_pNext = off("Index_pNext", 40);
const Index_pPartIdxWhere = off("Index_pPartIdxWhere", 72);
const Index_tnum = off("Index_tnum", 88);
const Index_szIdxRow = off("Index_szIdxRow", 92);
const Index_nKeyCol = off("Index_nKeyCol", 94);
const Index_onError = off("Index_onError", 98);
const Index_aiColumn = off("Index_aiColumn", 8);
// Index.bUnordered bitfield: probe byte 99, mask 0x04
const Index_bUnordered_byte = off("Index_bUnordered_byte", 99);
const Index_bUnordered_mask: u8 = 0x04;

const KeyInfo_nRef = off("KeyInfo_nRef", 0);
const KeyInfo_enc = off("KeyInfo_enc", 4);
const KeyInfo_nKeyField = off("KeyInfo_nKeyField", 6);
const KeyInfo_nAllField = off("KeyInfo_nAllField", 8);
const KeyInfo_db = off("KeyInfo_db", 16);
const KeyInfo_aSortFlags = off("KeyInfo_aSortFlags", 24);
const KeyInfo_aColl = off("KeyInfo_aColl", 32);
const sizeof_KeyInfo = off("sizeof_KeyInfo", 32);

const Token_z = off("Token_z", 0);
const Token_n = off("Token_n", 8);
const sizeof_Token = off("sizeof_Token", 16);

const IdList_nId = off("IdList_nId", 0);
const IdList_a = off("IdList_a", 8);
const IdList_item_zName = off("IdList_item_zName", 0);
const sizeof_IdList_item = off("sizeof_IdList_item", 8);

const With_nCte = off("With_nCte", 0);
const With_pOuter = off("With_pOuter", 8);
const With_a = off("With_a", 16);
const sizeof_With = off("sizeof_With", 16);
// With.bView is a u8 flag; probe not done — value not needed at runtime here
// (set via field write).  We treat its byte position as part of the head.

const Cte_zName = off("Cte_zName", 0);
const Cte_pCols = off("Cte_pCols", 8);
const Cte_pSelect = off("Cte_pSelect", 16);
const Cte_eM10d = off("Cte_eM10d", 40);
const sizeof_Cte = off("sizeof_Cte", 48);

const CteUse_nUse = off("CteUse_nUse", 0);
const CteUse_addrM9e = off("CteUse_addrM9e", 4);
const CteUse_regRtn = off("CteUse_regRtn", 8);
const CteUse_iCur = off("CteUse_iCur", 12);
const CteUse_nRowEst = off("CteUse_nRowEst", 16);
const CteUse_eM10d = off("CteUse_eM10d", 18);
const sizeof_CteUse = off("sizeof_CteUse", 20);

const NameContext_pParse = off("NameContext_pParse", 0);
const NameContext_pSrcList = off("NameContext_pSrcList", 8);
const NameContext_uNC = off("NameContext_uNC", 16);
const NameContext_pNext = off("NameContext_pNext", 24);
const NameContext_ncFlags = off("NameContext_ncFlags", 40);
const sizeof_NameContext = off("sizeof_NameContext", 56);

const AggInfo_directMode = off("AggInfo_directMode", 0);
const AggInfo_useSortingIdx = off("AggInfo_useSortingIdx", 1);
const AggInfo_nSortingColumn = off("AggInfo_nSortingColumn", 4);
const AggInfo_sortingIdx = off("AggInfo_sortingIdx", 8);
const AggInfo_sortingIdxPTab = off("AggInfo_sortingIdxPTab", 12);
const AggInfo_iFirstReg = off("AggInfo_iFirstReg", 16);
const AggInfo_pGroupBy = off("AggInfo_pGroupBy", 24);
const AggInfo_aCol = off("AggInfo_aCol", 32);
const AggInfo_nColumn = off("AggInfo_nColumn", 40);
const AggInfo_nAccumulator = off("AggInfo_nAccumulator", 44);
const AggInfo_aFunc = off("AggInfo_aFunc", 48);
const AggInfo_nFunc = off("AggInfo_nFunc", 56);
const AggInfo_selId = off("AggInfo_selId", 60);
const sizeof_AggInfo = off("sizeof_AggInfo", 64);

const sizeof_AggInfo_col = off("sizeof_AggInfo_col", 32);
const AggInfo_col_pTab = off("AggInfo_col_pTab", 0);
const AggInfo_col_pCExpr = off("AggInfo_col_pCExpr", 8);
const AggInfo_col_iTable = off("AggInfo_col_iTable", 16);
const AggInfo_col_iColumn = off("AggInfo_col_iColumn", 20);
const AggInfo_col_iSorterColumn = off("AggInfo_col_iSorterColumn", 24);

const sizeof_AggInfo_func = off("sizeof_AggInfo_func", 32);
const AggInfo_func_pFExpr = off("AggInfo_func_pFExpr", 0);
const AggInfo_func_pFunc = off("AggInfo_func_pFunc", 8);
const AggInfo_func_iDistinct = off("AggInfo_func_iDistinct", 16);
const AggInfo_func_iDistAddr = off("AggInfo_func_iDistAddr", 20);
const AggInfo_func_iOBTab = off("AggInfo_func_iOBTab", 24);
const AggInfo_func_bOBPayload = off("AggInfo_func_bOBPayload", 28);
const AggInfo_func_bOBUnique = off("AggInfo_func_bOBUnique", 29);
const AggInfo_func_bUseSubtype = off("AggInfo_func_bUseSubtype", 30);

const Walker_pParse = off("Walker_pParse", 0);
const Walker_xExprCallback = off("Walker_xExprCallback", 8);
const Walker_xSelectCallback = off("Walker_xSelectCallback", 16);
const Walker_xSelectCallback2 = off("Walker_xSelectCallback2", 24);
const Walker_walkerDepth = off("Walker_walkerDepth", 32);
const Walker_eCode = off("Walker_eCode", 36);
const Walker_u = off("Walker_u", 40);
const sizeof_Walker = off("sizeof_Walker", 48);

const Window_pPartition = off("Window_pPartition", 16);
const Window_ppThis = off("Window_ppThis", 56);
const Window_pFilter = off("Window_pFilter", 72);
const FuncDef_funcFlags = off("FuncDef_funcFlags", 4);
const FuncDef_zName = off("FuncDef_zName", 56);

// sqlite3 / Parse / Db / Schema
const sqlite3_pDfltColl = off("sqlite3_pDfltColl", 16);
const sqlite3_flags = off("sqlite3_flags", 48);
const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103);
const sqlite3_dbOptFlags = off("sqlite3_dbOptFlags", 96);
const sqlite3_aDb = off("sqlite3_aDb", 32);
const sqlite3_aLimit = off("sqlite3_aLimit", 136);
const sqlite3_pParse = off("sqlite3_pParse", 344);
const sqlite3_enc = off("sqlite3_enc", 100);
const Db_zDbSName = off("Db_zDbSName", 0);
const Db_pSchema = off("Db_pSchema", 24);
const sizeof_Db = off("sizeof_Db", 32);
const Schema_pSeqTab = off("Schema_pSeqTab", 104);

const Parse_db = off("Parse_db", 0);
const Parse_zErrMsg = off("Parse_zErrMsg", 8);
const Parse_pVdbe = off("Parse_pVdbe", 16);
const Parse_rc = off("Parse_rc", 24);
const Parse_nTab = off("Parse_nTab", 56);
const Parse_nMem = off("Parse_nMem", 60);
const Parse_nNestSel = off("Parse_nNestSel", 68);
const Parse_nErr = off("Parse_nErr", 52);
const Parse_nSelect = off("Parse_nSelect", 124);
const Parse_nHeight = off("Parse_nHeight", 308);
const Parse_pToplevel = off("Parse_pToplevel", 136);
const Parse_pWith = off("Parse_pWith", 400);
const Parse_pIdxEpr = off("Parse_pIdxEpr", 96);
const Parse_zAuthContext = off("Parse_zAuthContext", 368);
const Parse_explain = off("Parse_explain", 299);
const Parse_prepFlags = off("Parse_prepFlags", 34);
const Parse_addrExplain = off("Parse_addrExplain", 312);
// Parse bft cluster: byte 39 (okConstFactor 0x80, colNamesSet 0x20,
// bHasExists 0x10, hasCompound 0x04); checkSchema byte 40 bit 0x01.
// Parse bft bitfield bytes are config-divergent (SQLITE_DEBUG shifts them);
// hardcode per config like expr.zig (can't offsetof a bitfield).
const Parse_bft_byte: usize = if (config.sqlite_debug) 42 else 39;
const Parse_okConstFactor_mask: u8 = 0x80;
const Parse_colNamesSet_mask: u8 = 0x20;
const Parse_bHasExists_mask: u8 = 0x10;
const Parse_hasCompound_mask: u8 = 0x04;
const Parse_checkSchema_byte: usize = if (config.sqlite_debug) 43 else 40;
const Parse_checkSchema_mask: u8 = 0x01;

// ════════════════════════════════════════════════════════════════════════════
// Magic constants (must equal the C headers exactly).
// ════════════════════════════════════════════════════════════════════════════
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_UTF8: u8 = 1;

// SRT_* (sqliteInt.h) — destination types.
const SRT_Exists: c_int = 1;
const SRT_Discard: c_int = 2;
const SRT_DistFifo: c_int = 3;
const SRT_DistQueue: c_int = 4;
const SRT_Queue: c_int = 5;
const SRT_Fifo: c_int = 6;
const SRT_Output: c_int = 7;
const SRT_Mem: c_int = 8;
const SRT_Set: c_int = 9;
const SRT_EphemTab: c_int = 10;
const SRT_Coroutine: c_int = 11;
const SRT_Table: c_int = 12;
const SRT_Upfrom: c_int = 13;

// SF_* (Select.selFlags bits)
const SF_Distinct: u32 = 0x0000001;
const SF_All: u32 = 0x0000002;
const SF_Resolved: u32 = 0x0000004;
const SF_Aggregate: u32 = 0x0000008;
const SF_HasAgg: u32 = 0x0000010;
const SF_ClonedRhsIn: u32 = 0x0000020;
const SF_Expanded: u32 = 0x0000040;
const SF_HasTypeInfo: u32 = 0x0000080;
const SF_Compound: u32 = 0x0000100;
const SF_Values: u32 = 0x0000200;
const SF_MultiValue: u32 = 0x0000400;
const SF_NestedFrom: u32 = 0x0000800;
const SF_MinMaxAgg: u32 = 0x0001000;
const SF_Recursive: u32 = 0x0002000;
const SF_FixedLimit: u32 = 0x0004000;
const SF_Converted: u32 = 0x0010000;
const SF_IncludeHidden: u32 = 0x0020000;
const SF_ComplexResult: u32 = 0x0040000;
const SF_WhereBegin: u32 = 0x0080000;
const SF_WinRewrite: u32 = 0x0100000;
const SF_View: u32 = 0x0200000;
const SF_UFSrcCheck: u32 = 0x0800000;
const SF_PushDown: u32 = 0x1000000;
const SF_MultiPart: u32 = 0x2000000;
const SF_CopyCte: u32 = 0x4000000;
const SF_OrderByReqd: u32 = 0x8000000;
const SF_UpdateFrom: u32 = 0x10000000;
const SF_Correlated: u32 = 0x20000000;
const SF_OnToWhere: u32 = 0x40000000;

// TK_* (token / opcode-aligned operator codes)
const TK_ASTERISK: c_int = 180;
const TK_NOT: c_int = 19;
const TK_EXISTS: c_int = 20;
const TK_CAST: c_int = 36;
const TK_OR: c_int = 43;
const TK_AND: c_int = 44;
const TK_IS: c_int = 45;
const TK_BETWEEN: c_int = 49;
const TK_IN: c_int = 50;
const TK_ISNULL: c_int = 51;
const TK_NOTNULL: c_int = 52;
const TK_NE: c_int = 53;
const TK_EQ: c_int = 54;
const TK_GT: c_int = 55;
const TK_LE: c_int = 56;
const TK_LT: c_int = 57;
const TK_GE: c_int = 58;
const TK_ID: c_int = 60;
const TK_DOT: c_int = 142;
const TK_PLUS: c_int = 107;
const TK_NULL: c_int = 122;
const TK_INTEGER: c_int = 156;
const TK_COLLATE: c_int = 114;
const TK_ALL: c_int = 136;
const TK_EXCEPT: c_int = 137;
const TK_INTERSECT: c_int = 138;
const TK_SELECT: c_int = 139;
const TK_UNION: c_int = 135;
const TK_ORDER: c_int = 146;
const TK_LIMIT: c_int = 149;
const TK_TRUEFALSE: c_int = 171;
const TK_COLUMN: c_int = 168;
const TK_AGG_FUNCTION: c_int = 169;
const TK_AGG_COLUMN: c_int = 170;
const TK_FUNCTION: c_int = 172;
const TK_IF_NULL_ROW: c_int = 179;
const TK_REGISTER: c_int = 176;
const TK_TRIGGER: c_int = 78;

// EP_* (Expr.flags, u32)
const EP_OuterON: u32 = 0x000001;
const EP_InnerON: u32 = 0x000002;
const EP_Distinct: u32 = 0x000004;
const EP_HasFunc: u32 = 0x000008;
const EP_FixedCol: u32 = 0x000020;
const EP_Collate: u32 = 0x000200;
const EP_IntValue: u32 = 0x000800;
const EP_xIsSelect: u32 = 0x001000;
const EP_Skip: u32 = 0x002000;
const EP_Reduced: u32 = 0x004000;
const EP_Win: u32 = 0x008000;
const EP_TokenOnly: u32 = 0x010000;
const EP_IfNullRow: u32 = 0x040000;
const EP_Unlikely: u32 = 0x080000;
const EP_CanBeNull: u32 = 0x200000;
const EP_Subquery: u32 = 0x400000;
const EP_Leaf: u32 = 0x800000;
const EP_WinFunc: u32 = 0x1000000;

// P4_* operand types (vdbe.h)
const P4_KEYINFO: c_int = -9;
const P4_COLLSEQ: c_int = -2;
const P4_FUNCDEF: c_int = -8;
const P4_INTARRAY: c_int = -15;
const P4_TRANSIENT: c_int = 0;
const P4_DYNAMIC: c_int = -7;
const P4_STATIC: c_int = -1;

// ECEL flags for sqlite3ExprCodeExprList
const SQLITE_ECEL_DUP: u8 = 0x01;
const SQLITE_ECEL_FACTOR: u8 = 0x02;
const SQLITE_ECEL_REF: u8 = 0x04;
const SQLITE_ECEL_OMITREF: u8 = 0x08;

// OPFLAG_*
const OPFLAG_APPEND: u16 = 0x08;
const OPFLAG_USESEEKRESULT: u16 = 0x10;
const OPFLAG_PERMUTE: u16 = 0x01;
const OPFLAG_NOCHNG_MAGIC: u16 = 0x6d;

// affinity
const SQLITE_AFF_NONE: u8 = 0x40;
const SQLITE_AFF_BLOB: u8 = 0x41;
const SQLITE_AFF_TEXT: u8 = 0x42;
const SQLITE_AFF_NUMERIC: u8 = 0x43;
const SQLITE_AFF_INTEGER: u8 = 0x44;
const SQLITE_AFF_REAL: u8 = 0x45;
const SQLITE_AFF_FLEXNUM: u8 = 0x46;
const SQLITE_AFF_DEFER: u8 = 0x58;

// COLNAME_*
const COLNAME_NAME: c_int = 0;
const COLNAME_DECLTYPE: c_int = 1;

// COLFLAG_*
const COLFLAG_HIDDEN: u16 = 0x0002;
const COLFLAG_HASTYPE: u16 = 0x0004;
const COLFLAG_SORTERREF: u16 = 0x0010;
const COLFLAG_HASCOLL: u16 = 0x0200;
const COLFLAG_NOEXPAND: u16 = 0x0400;
const COLFLAG_NOINSERT: u16 = 0x0062;

// ENAME_*
const ENAME_NAME: u32 = 0;
const ENAME_SPAN: u32 = 1;
const ENAME_TAB: u32 = 2;
const ENAME_ROWID: u32 = 3;

// JT_* join types
const JT_INNER: u8 = 0x01;
const JT_CROSS: u8 = 0x02;
const JT_NATURAL: u8 = 0x04;
const JT_LEFT: u8 = 0x08;
const JT_RIGHT: u8 = 0x10;
const JT_OUTER: u8 = 0x20;
const JT_LTORJ: u8 = 0x40;
const JT_ERROR: u8 = 0x80;

// WHERE_DISTINCT_*
const WHERE_DISTINCT_NOOP: c_int = 0;
const WHERE_DISTINCT_UNIQUE: c_int = 1;
const WHERE_DISTINCT_ORDERED: c_int = 2;
const WHERE_DISTINCT_UNORDERED: c_int = 3;

// WHERE control flags
const WHERE_ORDERBY_NORMAL: c_int = 0;
const WHERE_ORDERBY_MIN: c_int = 1;
const WHERE_ORDERBY_MAX: c_int = 2;
const WHERE_GROUPBY: u16 = 0x0040;
const WHERE_DISTINCTBY: u16 = 0x0080;
const WHERE_SORTBYGROUP: u16 = 0x0200;
const WHERE_WANT_DISTINCT: u16 = 0x0100;
const WHERE_AGG_DISTINCT: u16 = 0x0400;
const WHERE_USE_LIMIT: u16 = 0x4000;

// KEYINFO_ORDER_*
const KEYINFO_ORDER_DESC: u8 = 0x01;
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

// WRC_*
const WRC_Continue: c_int = 0;
const WRC_Prune: c_int = 1;
const WRC_Abort: c_int = 2;

// M10d_*
const M10d_Yes: u8 = 0;
const M10d_Any: u8 = 1;
const M10d_No: u8 = 2;

// NC flags
const NC_InAggFunc: c_int = 0x020000;
const NC_UAggInfo: c_int = 0x000100;

// limits
const SQLITE_LIMIT_EXPR_DEPTH: c_int = 3;
const SQLITE_LIMIT_COLUMN: c_int = 2;

// Table flags
const TF_Ephemeral: u32 = 0x00004000;
const TF_NoVisibleRowid: u32 = 0x00000200;

// TABTYP_*
const TABTYP_VIEW: u8 = 2;

// db->flags optimization bits & misc db->flags
const SQLITE_FullColNames: u64 = 0x00000004;
const SQLITE_ShortColNames: u64 = 0x00000040;
const SQLITE_EnableView: u64 = 0x80000000;
const SQLITE_TrustedSchema: u64 = 0x00000080 << 32; // see header; only used by view risk
const SQLITE_PREPARE_FROM_DDL: u32 = 0x40;

// Optimization disable bits (db->dbOptFlags)
const OPT_QueryFlattener: u32 = 0x00000001;
const OPT_GroupByOrder: u32 = 0x00000004;
const OPT_FactorOutConst: u32 = 0x00000008;
const OPT_Transitive: u32 = 0x00000080;
const OPT_OmitNoopJoin: u32 = 0x00000100;
const OPT_CountOfView: u32 = 0x00000200;
const OPT_PushDown: u32 = 0x00001000;
const OPT_SimplifyJoin: u32 = 0x00002000;
const OPT_PropagateConst: u32 = 0x00008000;
const OPT_MinMaxOpt: u32 = 0x00010000;
const OPT_BalancedMerge: u32 = 0x00200000;
const OPT_OmitOrderBy: u32 = 0x00400000;
const OPT_FlttnUnionAll: u32 = 0x00800000;
const OPT_ExistsToJoin: u32 = 0x01000000;
const OPT_Coroutines: u32 = 0x02000000;
const OPT_NullUnusedCols: u32 = 0x04000000;

// auth action codes
const SQLITE_SELECT: c_int = 21;
const SQLITE_READ: c_int = 20;
const SQLITE_RECURSIVE: c_int = 33;

// VTABRISK
const SQLITE_VTABRISK_Normal: c_int = 1;

// SORTFLAG
const SORTFLAG_UseSorter: u8 = 0x01;

const SQLITE_JUMPIFNULL: c_int = 0x10;
const SQLITE_NULLEQ: c_int = 0x80;

const BTREE_UNORDERED: c_int = 8;

// SQLITE_FUNC_*
const SQLITE_FUNC_COUNT: u32 = 0x0100;
const SQLITE_FUNC_NEEDCOLL: u32 = 0x0020;

// VdbeOp field offsets / sizeof (already in layout)
const VdbeOp_opcode = off("VdbeOp_opcode", 0);
const VdbeOp_p1 = off("VdbeOp_p1", 4);
const VdbeOp_p2 = off("VdbeOp_p2", 8);
const VdbeOp_p4 = off("VdbeOp_p4", 16);

// BMS = number of bits in a Bitmask (u64) => 64
const BMS: c_int = 64;

// ── Shared local consts used across the ported clusters ──────────────────────
const EP_IsFalse: u32 = 0x20000000; // Expr is the constant FALSE
const TF_WithoutRowid: u32 = 0x00000080;
const TABTYP_NORMAL: u8 = 0; // IsOrdinaryTable
const TABTYP_VTAB: u8 = 1; // IsVirtual
// (TABTYP_VIEW=2 already as TABTYP_VIEW above)
const PARSE_MODE_RENAME: u8 = 2; // IN_RENAME_OBJECT = eParseMode>=2
const SQLITE_IDXTYPE_PRIMARYKEY: u8 = 2;
const SQLITE_N_STDTYPE: c_int = 6;
const CollSeq_zName = off("CollSeq_zName", 0);
const Window_pOrderBy = off("Window_pOrderBy", 24);
const Cte_zCteErr = off("Cte_zCteErr", 24);
const Cte_pUse = off("Cte_pUse", 32);
const With_bView_byte = off("With_bView_byte", 4);
const Parse_eParseMode = off("Parse_eParseMode", 300);
const VTable_eVtabRisk = off("VTable_eVtabRisk", 30);
const Index_idxType_byte = off("Index_idxType_byte", 99);
const Index_idxType_mask: u8 = 0x03;
const sizeof_Hash = off("sizeof_Hash", 24);
// SQLITE_TRANSIENT / SQLITE_DYNAMIC destructor sentinels for VdbeSetColName.
const SQLITE_TRANSIENT: ?*const anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
// SQLITE_DYNAMIC is the ADDRESS of sqlite3RowSetClear (a sentinel), NOT 1.
extern fn sqlite3RowSetClear(?*anyopaque) callconv(.c) void;
const SQLITE_DYNAMIC: ?*const anyopaque = @ptrCast(&sqlite3RowSetClear);

inline fn exprUseXList(p: Ptr) bool {
    return !hasProp(p, EP_xIsSelect);
}
inline fn inRenameObject(pParse: Ptr) bool {
    return rd(u8, pParse, Parse_eParseMode) >= PARSE_MODE_RENAME;
}

// ── Opcodes (numeric, from vendor/tsrc/opcodes.h; probe-extracted) ───────────
const OP = struct {
    const Integer: c_int = 73;
    const Null: c_int = 77;
    const SCopy: c_int = 83;
    const Copy: c_int = 82;
    const Move: c_int = 81;
    const Sequence: c_int = 128;
    const SequenceTest: c_int = 122;
    const Column: c_int = 96;
    const MakeRecord: c_int = 99;
    const Affinity: c_int = 98;
    const Compare: c_int = 92;
    const Jump: c_int = 14;
    const Permutation: c_int = 91;
    const Goto: c_int = 9;
    const Gosub: c_int = 10;
    const Return: c_int = 69;
    const InitCoroutine: c_int = 11;
    const EndCoroutine: c_int = 70;
    const Yield: c_int = 12;
    const If: c_int = 16;
    const IfNot: c_int = 17;
    const IfPos: c_int = 61;
    const IfNotZero: c_int = 62;
    const DecrJumpZero: c_int = 63;
    const IsNull: c_int = 51;
    const Ne: c_int = 53;
    const Eq: c_int = 54;
    const Found: c_int = 29;
    const NotFound: c_int = 28;
    const NewRowid: c_int = 129;
    const Insert: c_int = 130;
    const Delete: c_int = 132;
    const IdxInsert: c_int = 140;
    const SorterInsert: c_int = 141;
    const OpenEphemeral: c_int = 120;
    const SorterOpen: c_int = 121;
    const OpenPseudo: c_int = 123;
    const OpenRead: c_int = 114;
    const OpenDup: c_int = 117;
    const ResetSorter: c_int = 148;
    const Last: c_int = 32;
    const IdxLE: c_int = 41;
    const Sort: c_int = 35;
    const SorterSort: c_int = 34;
    const SorterData: c_int = 135;
    const Rewind: c_int = 36;
    const Next: c_int = 40;
    const SorterNext: c_int = 38;
    const RowData: c_int = 136;
    const NullRow: c_int = 138;
    const Once: c_int = 15;
    const ResultRow: c_int = 86;
    const Explain: c_int = 190;
    const Noop: c_int = 189;
    const FilterAdd: c_int = 185;
    const AddImm: c_int = 88;
    const MustBeInt: c_int = 13;
    const OffsetLimit: c_int = 162;
    const AggStep: c_int = 164;
    const AggFinal: c_int = 167;
    const SetSubtype: c_int = 184;
    const GetSubtype: c_int = 183;
    const Count: c_int = 100;
    const Close: c_int = 124;
    const CollSeq: c_int = 87;
    const SeekGE: c_int = 23;
    const SeekRowid: c_int = 30;
};

// ════════════════════════════════════════════════════════════════════════════
// Inline accessors (typed reads/writes of struct fields)
// ════════════════════════════════════════════════════════════════════════════
inline fn parseDb(p: Ptr) Ptr {
    return rdp(p, Parse_db);
}
inline fn parseVdbe(p: Ptr) Ptr {
    return rdp(p, Parse_pVdbe);
}
inline fn parseNErr(p: Ptr) c_int {
    return rd(c_int, p, Parse_nErr);
}
inline fn dbMallocFailed(db: Ptr) bool {
    return rd(u8, db, sqlite3_mallocFailed) != 0;
}

inline fn exprOp(p: Ptr) c_int {
    return rd(u8, p, Expr_op);
}
inline fn setExprOp(p: Ptr, v: u8) void {
    wr(u8, p, Expr_op, v);
}
inline fn exprOp2(p: Ptr) c_int {
    return rd(u8, p, Expr_op2);
}
inline fn exprFlags(p: Ptr) u32 {
    return rd(u32, p, Expr_flags);
}
inline fn setExprFlags(p: Ptr, v: u32) void {
    wr(u32, p, Expr_flags, v);
}
inline fn exprPLeft(p: Ptr) Ptr {
    return rdp(p, Expr_pLeft);
}
inline fn exprPRight(p: Ptr) Ptr {
    return rdp(p, Expr_pRight);
}
inline fn exprPList(p: Ptr) Ptr {
    return rdp(p, Expr_x); // x.pList overlaps x.pSelect
}
inline fn exprPSelect(p: Ptr) Ptr {
    return rdp(p, Expr_x);
}
inline fn exprITable(p: Ptr) c_int {
    return rd(c_int, p, Expr_iTable);
}
inline fn setExprITable(p: Ptr, v: c_int) void {
    wr(c_int, p, Expr_iTable, v);
}
inline fn exprIColumn(p: Ptr) c_int {
    return rd(i16, p, Expr_iColumn);
}
inline fn exprIAgg(p: Ptr) c_int {
    return rd(i16, p, Expr_iAgg);
}
inline fn exprPAggInfo(p: Ptr) Ptr {
    return rdp(p, Expr_pAggInfo);
}
inline fn exprWJoin(p: Ptr) c_int {
    return rd(c_int, p, Expr_w);
}
inline fn setExprWJoin(p: Ptr, v: c_int) void {
    wr(c_int, p, Expr_w, v);
}
inline fn exprYTab(p: Ptr) Ptr {
    return rdp(p, Expr_y);
}
inline fn exprYWin(p: Ptr) Ptr {
    return rdp(p, Expr_y);
}
inline fn exprUToken(p: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(p, Expr_u));
}
inline fn exprUValue(p: Ptr) c_int {
    return rd(c_int, p, Expr_u);
}
inline fn exprAffExpr(p: Ptr) u8 {
    return rd(u8, p, Expr_affExpr);
}

inline fn hasProp(p: Ptr, m: u32) bool {
    return (exprFlags(p) & m) != 0;
}
inline fn setProp(p: Ptr, m: u32) void {
    setExprFlags(p, exprFlags(p) | m);
}
inline fn clearProp(p: Ptr, m: u32) void {
    setExprFlags(p, exprFlags(p) & ~m);
}
inline fn exprUseXSelect(p: Ptr) bool {
    return hasProp(p, EP_xIsSelect);
}

// Select accessors
inline fn selOp(p: Ptr) c_int {
    return rd(u8, p, Select_op);
}
inline fn setSelOp(p: Ptr, v: u8) void {
    wr(u8, p, Select_op, v);
}
inline fn selFlags(p: Ptr) u32 {
    return rd(u32, p, Select_selFlags);
}
inline fn setSelFlags(p: Ptr, v: u32) void {
    wr(u32, p, Select_selFlags, v);
}
inline fn selHas(p: Ptr, m: u32) bool {
    return (selFlags(p) & m) != 0;
}
inline fn selSet(p: Ptr, m: u32) void {
    setSelFlags(p, selFlags(p) | m);
}
inline fn selClear(p: Ptr, m: u32) void {
    setSelFlags(p, selFlags(p) & ~m);
}
inline fn selPEList(p: Ptr) Ptr {
    return rdp(p, Select_pEList);
}
inline fn setSelPEList(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pEList, v);
}
inline fn selPSrc(p: Ptr) Ptr {
    return rdp(p, Select_pSrc);
}
inline fn setSelPSrc(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pSrc, v);
}
inline fn selPWhere(p: Ptr) Ptr {
    return rdp(p, Select_pWhere);
}
inline fn setSelPWhere(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pWhere, v);
}
inline fn selPGroupBy(p: Ptr) Ptr {
    return rdp(p, Select_pGroupBy);
}
inline fn setSelPGroupBy(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pGroupBy, v);
}
inline fn selPHaving(p: Ptr) Ptr {
    return rdp(p, Select_pHaving);
}
inline fn setSelPHaving(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pHaving, v);
}
inline fn selPOrderBy(p: Ptr) Ptr {
    return rdp(p, Select_pOrderBy);
}
inline fn setSelPOrderBy(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pOrderBy, v);
}
inline fn selPPrior(p: Ptr) Ptr {
    return rdp(p, Select_pPrior);
}
inline fn setSelPPrior(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pPrior, v);
}
inline fn selPNext(p: Ptr) Ptr {
    return rdp(p, Select_pNext);
}
inline fn setSelPNext(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pNext, v);
}
inline fn selPLimit(p: Ptr) Ptr {
    return rdp(p, Select_pLimit);
}
inline fn setSelPLimit(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pLimit, v);
}
inline fn selPWith(p: Ptr) Ptr {
    return rdp(p, Select_pWith);
}
inline fn setSelPWith(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, Select_pWith, v);
}
inline fn selPWin(p: Ptr) Ptr {
    return rdp(p, Select_pWin);
}
inline fn selPWinDefn(p: Ptr) Ptr {
    return rdp(p, Select_pWinDefn);
}
inline fn selId(p: Ptr) c_int {
    return rd(c_int, p, Select_selId);
}
inline fn setSelId(p: Ptr, v: c_int) void {
    wr(c_int, p, Select_selId, v);
}
inline fn selNSelectRow(p: Ptr) i16 {
    return rd(i16, p, Select_nSelectRow);
}
inline fn setSelNSelectRow(p: Ptr, v: i16) void {
    wr(i16, p, Select_nSelectRow, v);
}
inline fn selILimit(p: Ptr) c_int {
    return rd(c_int, p, Select_iLimit);
}
inline fn setSelILimit(p: Ptr, v: c_int) void {
    wr(c_int, p, Select_iLimit, v);
}
inline fn selIOffset(p: Ptr) c_int {
    return rd(c_int, p, Select_iOffset);
}
inline fn setSelIOffset(p: Ptr, v: c_int) void {
    wr(c_int, p, Select_iOffset, v);
}

// ExprList accessors
inline fn listNExpr(p: Ptr) c_int {
    return rd(c_int, p, ExprList_nExpr);
}
inline fn setListNExpr(p: Ptr, v: c_int) void {
    wr(c_int, p, ExprList_nExpr, v);
}
inline fn listA(p: Ptr) Ptr {
    return fieldPtr(p, ExprList_a); // INLINE array — address is data
}
inline fn itemAt(a0: Ptr, i: c_int) Ptr {
    return @ptrCast(base(a0) + @as(usize, @intCast(i)) * sizeof_ExprList_item);
}
inline fn elItem(pList: Ptr, i: c_int) Ptr {
    return itemAt(listA(pList), i);
}
inline fn itemExpr(item: Ptr) Ptr {
    return rdp(item, ExprList_item_pExpr);
}
inline fn setItemExpr(item: Ptr, v: Ptr) void {
    wr(?*anyopaque, item, ExprList_item_pExpr, v);
}
inline fn itemZEName(item: Ptr) ?[*:0]u8 {
    return @ptrCast(rdp(item, ExprList_item_zEName));
}
inline fn setItemZEName(item: Ptr, v: ?[*:0]const u8) void {
    wr(?*const anyopaque, item, ExprList_item_zEName, @ptrCast(v));
}
inline fn itemSortFlags(item: Ptr) u8 {
    return rd(u8, item, ExprList_item_fg_sortFlags);
}
inline fn setItemSortFlags(item: Ptr, v: u8) void {
    wr(u8, item, ExprList_item_fg_sortFlags, v);
}
inline fn itemFgWord(item: Ptr) u32 {
    return rd(u32, item, ExprList_item_fg);
}
inline fn setItemFgWord(item: Ptr, v: u32) void {
    wr(u32, item, ExprList_item_fg, v);
}
// ExprList_item.fg bits (word at offset 16): sortFlags=byte0; eEName:2 @8;
// done@10; reusable@11; bSorterRef@12; bNulls@13; bUsed@14; bUsingTerm@15;
// bNoExpand@16.
const EFG_eEName_shift: u5 = 8;
const EFG_eEName_mask: u32 = 0x3 << 8;
const EFG_bUsed: u32 = 1 << 14;
const EFG_bUsingTerm: u32 = 1 << 15;
const EFG_bNoExpand: u32 = 1 << 16;
inline fn itemEEName(item: Ptr) u32 {
    return (itemFgWord(item) & EFG_eEName_mask) >> EFG_eEName_shift;
}
inline fn setItemEEName(item: Ptr, v: u32) void {
    setItemFgWord(item, (itemFgWord(item) & ~EFG_eEName_mask) | ((v & 0x3) << EFG_eEName_shift));
}
inline fn itemBUsed(item: Ptr) bool {
    return (itemFgWord(item) & EFG_bUsed) != 0;
}
inline fn setItemBUsed(item: Ptr) void {
    setItemFgWord(item, itemFgWord(item) | EFG_bUsed);
}
inline fn itemBUsingTerm(item: Ptr) bool {
    return (itemFgWord(item) & EFG_bUsingTerm) != 0;
}
inline fn itemBNoExpand(item: Ptr) bool {
    return (itemFgWord(item) & EFG_bNoExpand) != 0;
}
inline fn setItemBNoExpand(item: Ptr) void {
    setItemFgWord(item, itemFgWord(item) | EFG_bNoExpand);
}
inline fn itemIOrderByCol(item: Ptr) u16 {
    return rd(u16, item, ExprList_item_u_x_iOrderByCol);
}
inline fn setItemIOrderByCol(item: Ptr, v: u16) void {
    wr(u16, item, ExprList_item_u_x_iOrderByCol, v);
}
inline fn setItemIAlias(item: Ptr, v: u16) void {
    wr(u16, item, ExprList_item_u_x_iOrderByCol + 2, v);
}

// SrcList / SrcItem accessors
inline fn srcNSrc(p: Ptr) c_int {
    return rd(c_int, p, SrcList_nSrc);
}
inline fn srcA(p: Ptr) Ptr {
    return fieldPtr(p, SrcList_a); // INLINE array
}
inline fn srcItemAt(pList: Ptr, i: c_int) Ptr {
    return @ptrCast(base(srcA(pList)) + @as(usize, @intCast(i)) * sizeof_SrcItem);
}
inline fn itemPTab(item: Ptr) Ptr {
    return rdp(item, SrcItem_pSTab);
}
inline fn setItemPTab(item: Ptr, v: Ptr) void {
    wr(?*anyopaque, item, SrcItem_pSTab, v);
}
inline fn itemICursor(item: Ptr) c_int {
    return rd(c_int, item, SrcItem_iCursor);
}
inline fn setItemICursor(item: Ptr, v: c_int) void {
    wr(c_int, item, SrcItem_iCursor, v);
}
inline fn itemColUsed(item: Ptr) u64 {
    return rd(u64, item, SrcItem_colUsed);
}
inline fn setItemColUsed(item: Ptr, v: u64) void {
    wr(u64, item, SrcItem_colUsed, v);
}
inline fn itemZName(item: Ptr) ?[*:0]u8 {
    return @ptrCast(rdp(item, SrcItem_zName));
}
inline fn itemZAlias(item: Ptr) ?[*:0]u8 {
    return @ptrCast(rdp(item, SrcItem_zAlias));
}
inline fn itemFg(item: Ptr) u32 {
    return rd(u32, item, SrcItem_fg);
}
inline fn setItemFg(item: Ptr, v: u32) void {
    wr(u32, item, SrcItem_fg, v);
}
inline fn srcFgJoinType(item: Ptr) u8 {
    return rd(u8, item, SrcItem_fg); // jointype is the low byte
}
inline fn setSrcFgJoinType(item: Ptr, v: u8) void {
    wr(u8, item, SrcItem_fg, v);
}
inline fn srcHas(item: Ptr, m: u32) bool {
    return (itemFg(item) & m) != 0;
}
inline fn srcSet(item: Ptr, m: u32) void {
    setItemFg(item, itemFg(item) | m);
}
inline fn srcClear(item: Ptr, m: u32) void {
    setItemFg(item, itemFg(item) & ~m);
}
// SrcItem.fg bit positions (after the 8-bit jointype low byte):
const FG_notIndexed: u32 = 1 << 8;
const FG_isIndexedBy: u32 = 1 << 9;
const FG_isSubquery: u32 = 1 << 10;
const FG_isTabFunc: u32 = 1 << 11;
const FG_isCorrelated: u32 = 1 << 12;
const FG_isMaterialized: u32 = 1 << 13;
const FG_viaCoroutine: u32 = 1 << 14;
const FG_isRecursive: u32 = 1 << 15;
const FG_fromDDL: u32 = 1 << 16;
const FG_isCte: u32 = 1 << 17;
const FG_notCte: u32 = 1 << 18;
const FG_isUsing: u32 = 1 << 19;
const FG_isOn: u32 = 1 << 20;
const FG_isSynthUsing: u32 = 1 << 21;
const FG_isNestedFrom: u32 = 1 << 22;
const FG_rowidUsed: u32 = 1 << 23;
const FG_fixedSchema: u32 = 1 << 24;
const FG_hadSchema: u32 = 1 << 25;
const FG_fromExists: u32 = 1 << 26;

// u4.pSubq / u4.zDatabase / u4.pSchema all overlap at SrcItem_u4
inline fn itemPSubq(item: Ptr) Ptr {
    return rdp(item, SrcItem_u4);
}
inline fn itemU4Ptr(item: Ptr) Ptr {
    return rdp(item, SrcItem_u4);
}
inline fn itemU1(item: Ptr) Ptr {
    return rdp(item, SrcItem_u1); // pFuncArg / zIndexedBy overlap
}
inline fn itemU2(item: Ptr) Ptr {
    return rdp(item, SrcItem_u2); // pCteUse / pIBIndex overlap
}
inline fn itemU3(item: Ptr) Ptr {
    return rdp(item, SrcItem_u3); // pOn / pUsing overlap
}
inline fn setItemU3(item: Ptr, v: Ptr) void {
    wr(?*anyopaque, item, SrcItem_u3, v);
}
// Subquery accessors
inline fn subqPSelect(pSubq: Ptr) Ptr {
    return rdp(pSubq, Subquery_pSelect);
}
inline fn subqAddrFillSub(pSubq: Ptr) c_int {
    return rd(c_int, pSubq, Subquery_addrFillSub);
}
inline fn setSubqAddrFillSub(pSubq: Ptr, v: c_int) void {
    wr(c_int, pSubq, Subquery_addrFillSub, v);
}
inline fn subqRegReturn(pSubq: Ptr) c_int {
    return rd(c_int, pSubq, Subquery_regReturn);
}
inline fn setSubqRegReturn(pSubq: Ptr, v: c_int) void {
    wr(c_int, pSubq, Subquery_regReturn, v);
}
inline fn subqRegResult(pSubq: Ptr) c_int {
    return rd(c_int, pSubq, Subquery_regResult);
}
inline fn setSubqRegResult(pSubq: Ptr, v: c_int) void {
    wr(c_int, pSubq, Subquery_regResult, v);
}
// item subquery select (only valid if fg.isSubquery)
inline fn itemSelect(item: Ptr) Ptr {
    return subqPSelect(itemPSubq(item));
}

// SelectDest accessors
inline fn destEDest(p: Ptr) c_int {
    return rd(u8, p, SelectDest_eDest);
}
inline fn setDestEDest(p: Ptr, v: u8) void {
    wr(u8, p, SelectDest_eDest, v);
}
inline fn destISDParm(p: Ptr) c_int {
    return rd(c_int, p, SelectDest_iSDParm);
}
inline fn setDestISDParm(p: Ptr, v: c_int) void {
    wr(c_int, p, SelectDest_iSDParm, v);
}
inline fn destISDParm2(p: Ptr) c_int {
    return rd(c_int, p, SelectDest_iSDParm2);
}
inline fn setDestISDParm2(p: Ptr, v: c_int) void {
    wr(c_int, p, SelectDest_iSDParm2, v);
}
inline fn destISdst(p: Ptr) c_int {
    return rd(c_int, p, SelectDest_iSdst);
}
inline fn setDestISdst(p: Ptr, v: c_int) void {
    wr(c_int, p, SelectDest_iSdst, v);
}
inline fn destNSdst(p: Ptr) c_int {
    return rd(c_int, p, SelectDest_nSdst);
}
inline fn setDestNSdst(p: Ptr, v: c_int) void {
    wr(c_int, p, SelectDest_nSdst, v);
}
inline fn destZAffSdst(p: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(p, SelectDest_zAffSdst));
}
inline fn destPOrderBy(p: Ptr) Ptr {
    return rdp(p, SelectDest_pOrderBy);
}
inline fn setDestPOrderBy(p: Ptr, v: Ptr) void {
    wr(?*anyopaque, p, SelectDest_pOrderBy, v);
}

// Table accessors
inline fn tabNCol(p: Ptr) i16 {
    return rd(i16, p, Table_nCol);
}
inline fn setTabNCol(p: Ptr, v: i16) void {
    wr(i16, p, Table_nCol, v);
}
inline fn tabACol(p: Ptr) Ptr {
    return rdp(p, Table_aCol);
}
inline fn tabColAt(p: Ptr, i: c_int) Ptr {
    return @ptrCast(base(tabACol(p)) + @as(usize, @intCast(i)) * sizeof_Column);
}
inline fn tabZName(p: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(p, Table_zName));
}
inline fn tabTabFlags(p: Ptr) u32 {
    return rd(u32, p, Table_tabFlags);
}
inline fn setTabTabFlags(p: Ptr, v: u32) void {
    wr(u32, p, Table_tabFlags, v);
}
inline fn tabIPKey(p: Ptr) c_int {
    return rd(i16, p, Table_iPKey);
}
inline fn tabPSchema(p: Ptr) Ptr {
    return rdp(p, Table_pSchema);
}
inline fn tabPIndex(p: Ptr) Ptr {
    return rdp(p, Table_pIndex);
}
inline fn tabETabType(p: Ptr) u8 {
    return rd(u8, p, Table_eTabType);
}
inline fn colCnName(pCol: Ptr) ?[*:0]u8 {
    return @ptrCast(rdp(pCol, Column_zCnName));
}
inline fn colFlags(pCol: Ptr) u16 {
    return rd(u16, pCol, Column_colFlags);
}
inline fn setColFlags(pCol: Ptr, v: u16) void {
    wr(u16, pCol, Column_colFlags, v);
}
inline fn colAffinity(pCol: Ptr) u8 {
    return rd(u8, pCol, Column_affinity);
}
inline fn setColAffinity(pCol: Ptr, v: u8) void {
    wr(u8, pCol, Column_affinity, v);
}

// KeyInfo accessors
inline fn kiNKeyField(p: Ptr) u16 {
    return rd(u16, p, KeyInfo_nKeyField);
}
inline fn setKiNKeyField(p: Ptr, v: u16) void {
    wr(u16, p, KeyInfo_nKeyField, v);
}
inline fn kiNAllField(p: Ptr) u16 {
    return rd(u16, p, KeyInfo_nAllField);
}
inline fn setKiNAllField(p: Ptr, v: u16) void {
    wr(u16, p, KeyInfo_nAllField, v);
}
inline fn kiAColl(p: Ptr) [*]?*anyopaque {
    return @ptrCast(@alignCast(fieldPtr(p, KeyInfo_aColl)));
}
inline fn kiASortFlags(p: Ptr) [*]u8 {
    return @ptrCast(rdp(p, KeyInfo_aSortFlags));
}

// AggInfo accessors
inline fn aiNFunc(p: Ptr) c_int {
    return rd(c_int, p, AggInfo_nFunc);
}
inline fn aiNColumn(p: Ptr) c_int {
    return rd(c_int, p, AggInfo_nColumn);
}
inline fn setAiNColumn(p: Ptr, v: c_int) void {
    wr(c_int, p, AggInfo_nColumn, v);
}
inline fn aiNAccumulator(p: Ptr) c_int {
    return rd(c_int, p, AggInfo_nAccumulator);
}
inline fn aiNSortingColumn(p: Ptr) c_int {
    return rd(c_int, p, AggInfo_nSortingColumn);
}
inline fn setAiNSortingColumn(p: Ptr, v: c_int) void {
    wr(c_int, p, AggInfo_nSortingColumn, v);
}
inline fn aiIFirstReg(p: Ptr) c_int {
    return rd(c_int, p, AggInfo_iFirstReg);
}
inline fn aiACol(p: Ptr) Ptr {
    return rdp(p, AggInfo_aCol);
}
inline fn aiColAt(p: Ptr, i: c_int) Ptr {
    return @ptrCast(base(aiACol(p)) + @as(usize, @intCast(i)) * sizeof_AggInfo_col);
}
inline fn aiAFunc(p: Ptr) Ptr {
    return rdp(p, AggInfo_aFunc);
}
inline fn aiFuncAt(p: Ptr, i: c_int) Ptr {
    return @ptrCast(base(aiAFunc(p)) + @as(usize, @intCast(i)) * sizeof_AggInfo_func);
}
inline fn aiSortingIdx(p: Ptr) c_int {
    return rd(c_int, p, AggInfo_sortingIdx);
}
inline fn setAiSortingIdx(p: Ptr, v: c_int) void {
    wr(c_int, p, AggInfo_sortingIdx, v);
}
inline fn setAiSortingIdxPTab(p: Ptr, v: c_int) void {
    wr(c_int, p, AggInfo_sortingIdxPTab, v);
}
inline fn setAiDirectMode(p: Ptr, v: u8) void {
    wr(u8, p, AggInfo_directMode, v);
}
inline fn setAiUseSortingIdx(p: Ptr, v: u8) void {
    wr(u8, p, AggInfo_useSortingIdx, v);
}
// AggInfoColumnReg(A,i) = A->iFirstReg+i ; AggInfoFuncReg(A,i)=iFirstReg+nColumn+i
inline fn aggColReg(p: Ptr, i: c_int) c_int {
    return aiIFirstReg(p) + i;
}
inline fn aggFuncReg(p: Ptr, i: c_int) c_int {
    return aiIFirstReg(p) + aiNColumn(p) + i;
}

// Walker accessors
inline fn setWalkerExprCb(w: Ptr, f: Ptr) void {
    wr(?*anyopaque, w, Walker_xExprCallback, f);
}

// ════════════════════════════════════════════════════════════════════════════
// ExprSetProperty/ClearProperty/HasProperty are bit-ops (not extern symbols).
// ExprSetVVAProperty is a no-op unless SQLITE_DEBUG.  OptimizationEnabled/
// Disabled test db->dbOptFlags.  These are implemented inline.
// ════════════════════════════════════════════════════════════════════════════
inline fn optDisabled(db: Ptr, mask: u32) bool {
    return (rd(u32, db, sqlite3_dbOptFlags) & mask) != 0;
}
inline fn optEnabled(db: Ptr, mask: u32) bool {
    return (rd(u32, db, sqlite3_dbOptFlags) & mask) == 0;
}
inline fn dbFlags(db: Ptr) u64 {
    return rd(u64, db, sqlite3_flags);
}
inline fn dbAt(db: Ptr, iDb: c_int) Ptr {
    const aDb = rdp(db, sqlite3_aDb);
    return @ptrCast(base(aDb) + @as(usize, @intCast(iDb)) * sizeof_Db);
}
inline fn dbZDbSName(pDb: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(pDb, Db_zDbSName));
}
inline fn dbLimit(db: Ptr, which: c_int) c_int {
    const a: [*]align(1) const c_int = @ptrCast(base(db) + sqlite3_aLimit);
    return a[@intCast(which)];
}

// Parse single-bit bft accessors
inline fn parseSetBit(p: Ptr, byteOff: usize, mask: u8) void {
    wr(u8, p, byteOff, rd(u8, p, byteOff) | mask);
}
inline fn parseClearBit(p: Ptr, byteOff: usize, mask: u8) void {
    wr(u8, p, byteOff, rd(u8, p, byteOff) & ~mask);
}
inline fn parseGetBit(p: Ptr, byteOff: usize, mask: u8) bool {
    return (rd(u8, p, byteOff) & mask) != 0;
}

inline fn round8c(x: c_int) c_int {
    return (x + 7) & ~@as(c_int, 7);
}

// ════════════════════════════════════════════════════════════════════════════
// Extern functions.  Most still C (build.c, where.c, resolve.c, vdbeaux.c,
// util.c, etc.); the expr coders are ported-Zig but keep the same C ABI so they
// are referenced identically.  All resolved at link time.
// ════════════════════════════════════════════════════════════════════════════
const c = struct {
    // memory
    extern fn sqlite3DbMallocRawNN(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbMallocZero(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbReallocOrFree(db: Ptr, p: Ptr, n: u64) Ptr;
    extern fn sqlite3DbFree(db: Ptr, p: Ptr) void;
    extern fn sqlite3DbFreeNN(db: Ptr, p: Ptr) void;
    extern fn sqlite3DbNNFreeNN(db: Ptr, p: Ptr) void;
    extern fn sqlite3DbStrDup(db: Ptr, z: ?[*:0]const u8) ?[*:0]u8;
    extern fn sqlite3OomFault(db: Ptr) Ptr;
    extern fn sqlite3MPrintf(db: Ptr, fmt: ?[*:0]const u8, ...) ?[*:0]u8;
    extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
    extern fn memset(dst: ?*anyopaque, v: c_int, n: usize) ?*anyopaque;
    extern fn strlen(s: ?[*:0]const u8) usize;
    // string
    extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
    extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;
    // sqlite3StrNICmp is a #define alias for sqlite3_strnicmp.
    fn sqlite3StrNICmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int {
        return sqlite3_strnicmp(a, b, n);
    }
    extern const sqlite3CtypeMap: [256]u8;
    extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
    extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
    extern fn sqlite3StrIHash(z: ?[*:0]const u8) u8;
    // sqlite3Isdigit(x) = sqlite3CtypeMap[x] & 0x04 (SQLITE_ASCII macro).
    fn sqlite3Isdigit(c_: u8) c_int {
        return sqlite3CtypeMap[c_] & 0x04;
    }
    extern fn sqlite3IsTrueOrFalse(z: ?[*:0]const u8) c_int;
    extern fn sqlite3_randomness(n: c_int, p: ?*anyopaque) void;
    // error / auth / progress
    extern fn sqlite3ErrorMsg(pParse: Ptr, fmt: ?[*:0]const u8, ...) void;
    extern fn sqlite3AuthCheck(pParse: Ptr, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;
    extern fn sqlite3ProgressCheck(pParse: Ptr) void;
    // logest
    extern fn sqlite3LogEst(x: u64) i16;
    extern fn sqlite3LogEstAdd(a: i16, b: i16) i16;
    // hash
    extern fn sqlite3HashInit(p: Ptr) void;
    extern fn sqlite3HashClear(p: Ptr) void;
    extern fn sqlite3HashFind(p: Ptr, z: ?[*:0]const u8) Ptr;
    extern fn sqlite3HashInsert(p: Ptr, z: ?[*:0]const u8, data: Ptr) Ptr;
    // collation / affinity / column types
    extern fn sqlite3AffinityType(z: ?[*:0]const u8, p: Ptr) u8;
    extern fn sqlite3IsBinary(p: Ptr) c_int;
    extern fn sqlite3ColumnType(pCol: Ptr, zDflt: ?[*:0]const u8) ?[*:0]const u8;
    extern fn sqlite3ColumnSetColl(db: Ptr, pCol: Ptr, zColl: ?[*:0]const u8) void;
    // no-op macro unless SQLITE_ENABLE_HIDDEN_COLUMNS (OFF in this build).
    fn sqlite3ColumnPropertiesFromName(_: Ptr, _: Ptr) void {}
    extern fn sqlite3ColumnIndex(pTab: Ptr, z: ?[*:0]const u8) c_int;
    extern fn sqlite3RowidAlias(pTab: Ptr) ?[*:0]const u8;
    extern fn sqlite3MatchEName(item: Ptr, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8, p: Ptr) c_int;
    // expr
    extern fn sqlite3Expr(db: Ptr, op: c_int, z: ?[*:0]const u8) Ptr;
    extern fn sqlite3PExpr(pParse: Ptr, op: c_int, pLeft: Ptr, pRight: Ptr) Ptr;
    extern fn sqlite3PExprAddSelect(pParse: Ptr, pExpr: Ptr, pSelect: Ptr) void;
    extern fn sqlite3ExprAnd(pParse: Ptr, pLeft: Ptr, pRight: Ptr) Ptr;
    extern fn sqlite3ExprFunction(pParse: Ptr, pList: Ptr, pToken: Ptr, eDistinct: c_int) Ptr;
    extern fn sqlite3ExprInt32(db: Ptr, v: c_int) Ptr;
    extern fn sqlite3ExprDup(db: Ptr, p: Ptr, flags: c_int) Ptr;
    extern fn sqlite3ExprDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3ExprAffinity(p: Ptr) u8;
    extern fn sqlite3ExprDataType(p: Ptr) c_int;
    extern fn sqlite3ExprCollSeq(pParse: Ptr, p: Ptr) Ptr;
    extern fn sqlite3ExprNNCollSeq(pParse: Ptr, p: Ptr) Ptr;
    extern fn sqlite3ExprCompareCollSeq(pParse: Ptr, p: Ptr) Ptr;
    extern fn sqlite3ExprAddCollateString(pParse: Ptr, p: Ptr, z: ?[*:0]const u8) Ptr;
    extern fn sqlite3ExprSkipCollateAndLikely(p: Ptr) Ptr;
    extern fn sqlite3ExprCanBeNull(p: Ptr) c_int;
    extern fn sqlite3ExprIsVector(p: Ptr) c_int;
    extern fn sqlite3ExprIsInteger(p: Ptr, pV: *c_int, pParse: Ptr) c_int;
    extern fn sqlite3ExprIsConstant(pParse: Ptr, p: Ptr) c_int;
    extern fn sqlite3ExprIsConstantOrGroupBy(pParse: Ptr, p: Ptr, pGroupBy: Ptr) c_int;
    extern fn sqlite3ExprIsSingleTableConstraint(p: Ptr, pSrc: Ptr, iSrc: c_int, b: c_int) c_int;
    extern fn sqlite3ExprImpliesNonNullRow(p: Ptr, iTab: c_int, b: c_int) c_int;
    extern fn sqlite3ExprTruthValue(p: Ptr) c_int;
    extern fn sqlite3ExprColUsed(p: Ptr) u64;
    extern fn sqlite3ExprToRegister(p: Ptr, iReg: c_int) void;
    extern fn sqlite3ExprSetErrorOffset(p: Ptr, iOfst: c_int) void;
    extern fn sqlite3VectorErrorMsg(pParse: Ptr, p: Ptr) void;
    extern fn sqlite3CreateColumnExpr(db: Ptr, pSrc: Ptr, iSrc: c_int, iCol: c_int) Ptr;
    // expr code generation (ported-Zig, same ABI)
    extern fn sqlite3ExprCode(pParse: Ptr, p: Ptr, target: c_int) void;
    extern fn sqlite3ExprCodeMove(pParse: Ptr, iFrom: c_int, iTo: c_int, n: c_int) void;
    extern fn sqlite3ExprCodeExprList(pParse: Ptr, pList: Ptr, target: c_int, srcReg: c_int, flags: u8) c_int;
    extern fn sqlite3ExprIfFalse(pParse: Ptr, p: Ptr, dest: c_int, jumpIfNull: c_int) void;
    extern fn sqlite3ExprNullRegisterRange(pParse: Ptr, iReg: c_int, n: c_int) void;
    // expr lists
    extern fn sqlite3ExprListAppend(pParse: Ptr, pList: Ptr, pExpr: Ptr) Ptr;
    extern fn sqlite3ExprListDup(db: Ptr, p: Ptr, flags: c_int) Ptr;
    extern fn sqlite3ExprListDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3ExprListCompare(p1: Ptr, p2: Ptr, iTab: c_int) c_int;
    extern fn sqlite3ExprListDeleteGeneric(db: Ptr, p: ?*anyopaque) void;
    // aggregate analysis
    extern fn sqlite3ExprAnalyzeAggList(pNC: Ptr, pList: Ptr) void;
    extern fn sqlite3ExprAnalyzeAggregates(pNC: Ptr, pExpr: Ptr) void;
    extern fn sqlite3AggInfoPersistWalkerInit(pWalker: Ptr, pParse: Ptr) void;
    // src list / id list
    extern fn sqlite3SrcListDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3SrcListEnlarge(pParse: Ptr, p: Ptr, nExtra: c_int, iStart: c_int) Ptr;
    extern fn sqlite3SrcListAssignCursors(pParse: Ptr, p: Ptr) void;
    extern fn sqlite3SrcListAppendFromTerm(pParse: Ptr, p: Ptr, pTable: Ptr, pDatabase: Ptr, pAlias: Ptr, pSubquery: Ptr, pOn: Ptr) Ptr;
    extern fn sqlite3SrcListAppendList(pParse: Ptr, p1: Ptr, p2: Ptr) Ptr;
    extern fn sqlite3SrcItemAttachSubquery(pParse: Ptr, pItem: Ptr, pSelect: Ptr, b: c_int) c_int;
    extern fn sqlite3SubqueryDetach(db: Ptr, pItem: Ptr) Ptr;
    extern fn sqlite3IdListAppend(pParse: Ptr, p: Ptr, pToken: Ptr) Ptr;
    extern fn sqlite3IdListDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3IdListIndex(p: Ptr, z: ?[*:0]const u8) c_int;
    // table / schema / index
    extern fn sqlite3LocateTableItem(pParse: Ptr, flags: u32, pItem: Ptr) Ptr;
    extern fn sqlite3DeleteTable(db: Ptr, p: Ptr) void;
    extern fn sqlite3DeleteTableGeneric(db: Ptr, p: ?*anyopaque) void;
    extern fn sqlite3SchemaToIndex(db: Ptr, pSchema: Ptr) c_int;
    extern fn sqlite3CodeVerifySchema(pParse: Ptr, iDb: c_int) void;
    extern fn sqlite3TableLock(pParse: Ptr, iDb: c_int, tnum: c_int, isWrite: u8, zName: ?[*:0]const u8) void;
    extern fn sqlite3OpenTable(pParse: Ptr, iCur: c_int, iDb: c_int, pTab: Ptr, op: c_int) void;
    extern fn sqlite3PrimaryKeyIndex(pTab: Ptr) Ptr;
    extern fn sqlite3ViewGetColumnNames(pParse: Ptr, pTab: Ptr) c_int;
    extern fn sqlite3KeyInfoOfIndex(pParse: Ptr, pIdx: Ptr) Ptr;
    // resolve / prep
    extern fn sqlite3ResolveSelectNames(pParse: Ptr, p: Ptr, pOuterNC: Ptr) void;
    extern fn sqlite3ResolveOrderGroupBy(pParse: Ptr, pSelect: Ptr, pOrderBy: Ptr, zType: ?[*:0]const u8) c_int;
    // sqlite3ParseToplevel(p) = p->pToplevel ? p->pToplevel : p  (macro).
    fn sqlite3ParseToplevel(pParse: Ptr) Ptr {
        const top = rd(?*anyopaque, pParse, Parse_pToplevel);
        return if (top != null) top else pParse;
    }
    extern fn sqlite3ParserAddCleanup(pParse: Ptr, x: ?*anyopaque, p: ?*anyopaque) Ptr;
    extern fn sqlite3SelectExprHeight(p: Ptr) c_int;
    extern fn sqlite3SelectDup(db: Ptr, p: Ptr, flags: c_int) Ptr;
    extern fn sqlite3RenameTokenRemap(pParse: Ptr, pNew: Ptr, pOld: Ptr) void;
    // temp regs
    extern fn sqlite3GetTempReg(pParse: Ptr) c_int;
    extern fn sqlite3GetTempRange(pParse: Ptr, n: c_int) c_int;
    extern fn sqlite3ReleaseTempReg(pParse: Ptr, r: c_int) void;
    extern fn sqlite3ReleaseTempRange(pParse: Ptr, r: c_int, n: c_int) void;
    extern fn sqlite3ClearTempRegCache(pParse: Ptr) void;
    // vdbe
    extern fn sqlite3GetVdbe(pParse: Ptr) Ptr;
    extern fn sqlite3VdbeCreate(pParse: Ptr) Ptr;
    extern fn sqlite3VdbeAddOp0(v: Ptr, op: c_int) c_int;
    extern fn sqlite3VdbeAddOp1(v: Ptr, op: c_int, p1: c_int) c_int;
    extern fn sqlite3VdbeAddOp2(v: Ptr, op: c_int, p1: c_int, p2: c_int) c_int;
    extern fn sqlite3VdbeAddOp3(v: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
    extern fn sqlite3VdbeAddOp4(v: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: ?[*]const u8, p4type: c_int) c_int;
    extern fn sqlite3VdbeAddOp4Int(v: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
    extern fn sqlite3VdbeAppendP4(v: Ptr, p4: ?*anyopaque, p4type: c_int) void;
    extern fn sqlite3VdbeChangeOpcode(v: Ptr, addr: c_int, op: u8) void;
    extern fn sqlite3VdbeChangeP2(v: Ptr, addr: c_int, p2: c_int) void;
    extern fn sqlite3VdbeChangeP4(v: Ptr, addr: c_int, p4: ?[*]const u8, n: c_int) void;
    extern fn sqlite3VdbeChangeP5(v: Ptr, p5: u16) void;
    extern fn sqlite3VdbeChangeToNoop(v: Ptr, addr: c_int) c_int;
    extern fn sqlite3VdbeJumpHere(v: Ptr, addr: c_int) void;
    extern fn sqlite3VdbeJumpHereOrPopInst(v: Ptr, addr: c_int) void;
    extern fn sqlite3VdbeResolveLabel(v: Ptr, x: c_int) void;
    extern fn sqlite3VdbeMakeLabel(pParse: Ptr) c_int;
    extern fn sqlite3VdbeGoto(v: Ptr, addr: c_int) void;
    extern fn sqlite3VdbeCurrentAddr(v: Ptr) c_int;
    extern fn sqlite3VdbeGetOp(v: Ptr, addr: c_int) Ptr;
    extern fn sqlite3VdbeEndCoroutine(v: Ptr, regYield: c_int) void;
    extern fn sqlite3VdbeExplain(pParse: Ptr, bPush: u8, fmt: ?[*:0]const u8, ...) void;
    extern fn sqlite3VdbeSetColName(v: Ptr, idx: c_int, var_: c_int, name: ?[*:0]const u8, x: ?*const anyopaque) c_int;
    extern fn sqlite3VdbeSetNumCols(v: Ptr, n: c_int) void;
    extern fn sqlite3VdbeScanStatusCounters(v: Ptr, a: c_int, b: c_int, cc: c_int) void;
    extern fn sqlite3VdbeScanStatusRange(v: Ptr, a: c_int, b: c_int, cc: c_int) void;
    // keyinfo: sqlite3KeyInfoUnref / sqlite3KeyInfoRef are DEFINED in this
    // module (ported from select.c) — callers use the bare in-module names.
    // walker
    extern fn sqlite3WalkExpr(pWalker: Ptr, pExpr: Ptr) c_int;
    extern fn sqlite3WalkExprNN(pWalker: Ptr, pExpr: Ptr) c_int;
    extern fn sqlite3WalkExprList(pWalker: Ptr, pList: Ptr) c_int;
    extern fn sqlite3WalkSelect(pWalker: Ptr, p: Ptr) c_int;
    extern fn sqlite3SelectWalkNoop(pWalker: Ptr, p: Ptr) c_int;
    extern fn sqlite3ExprWalkNoop(pWalker: Ptr, p: Ptr) c_int;
    // with
    extern fn sqlite3WithDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3WithDeleteGeneric(db: Ptr, p: ?*anyopaque) void;
    // window (ported-Zig, same ABI; only present when WINDOWFUNC enabled)
    extern fn sqlite3WindowListDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3WindowUnlinkFromSelect(p: Ptr) void;
    extern fn sqlite3WindowRewrite(pParse: Ptr, p: Ptr) c_int;
    extern fn sqlite3WindowCodeInit(pParse: Ptr, p: Ptr) void;
    extern fn sqlite3WindowCodeStep(pParse: Ptr, p: Ptr, pWInfo: Ptr, regGosub: c_int, addrGosub: c_int) void;
    // where (still C)
    extern fn sqlite3WhereBegin(pParse: Ptr, pTabList: Ptr, pWhere: Ptr, pOrderBy: Ptr, pResultSet: Ptr, pSelect: Ptr, wctrlFlags: u16, iAuxArg: c_int) Ptr;
    extern fn sqlite3WhereEnd(pWInfo: Ptr) void;
    extern fn sqlite3WhereOutputRowCount(pWInfo: Ptr) i16;
    extern fn sqlite3WhereIsDistinct(pWInfo: Ptr) c_int;
    extern fn sqlite3WhereIsOrdered(pWInfo: Ptr) c_int;
    extern fn sqlite3WhereIsSorted(pWInfo: Ptr) c_int;
    extern fn sqlite3WhereOrderByLimitOptLabel(pWInfo: Ptr) c_int;
    extern fn sqlite3WhereContinueLabel(pWInfo: Ptr) c_int;
    extern fn sqlite3WhereBreakLabel(pWInfo: Ptr) c_int;
    extern fn sqlite3WhereMinMaxOptEarlyOut(v: Ptr, pWInfo: Ptr) void;
    // sqlite3IndexedByLookup is DEFINED in this module (ported from select.c).
    // EQP pop (ExplainQueryPlanPop) — real fn in vdbeaux.c.
    extern fn sqlite3VdbeExplainPop(pParse: Ptr) void;
};

// ════════════ CLUSTER A ════════════
// ════════════════════════════════════════════════════════════════════════════
// CLUSTER A — clearSelect .. sqlite3ProcessJoin  (src/select.c lines 82..668)
// ════════════════════════════════════════════════════════════════════════════

// clearSelect (static) — line 82
fn clearSelect(db: Ptr, p0: Ptr, bFree0: c_int) void {
    var p = p0;
    var bFree = bFree0;
    while (p != null) {
        const pPrior = selPPrior(p);
        c.sqlite3ExprListDelete(db, selPEList(p));
        c.sqlite3SrcListDelete(db, selPSrc(p));
        c.sqlite3ExprDelete(db, selPWhere(p));
        c.sqlite3ExprListDelete(db, selPGroupBy(p));
        c.sqlite3ExprDelete(db, selPHaving(p));
        c.sqlite3ExprListDelete(db, selPOrderBy(p));
        c.sqlite3ExprDelete(db, selPLimit(p));
        if (selPWith(p) != null) c.sqlite3WithDelete(db, selPWith(p));
        // SQLITE_OMIT_WINDOWFUNC is OFF
        if (selPWinDefn(p) != null) {
            c.sqlite3WindowListDelete(db, selPWinDefn(p));
        }
        while (selPWin(p) != null) {
            c.sqlite3WindowUnlinkFromSelect(selPWin(p));
        }
        if (bFree != 0) c.sqlite3DbNNFreeNN(db, p);
        p = pPrior;
        bFree = 1;
    }
}

// sqlite3SelectDestInit (EXPORT) — line 112
export fn sqlite3SelectDestInit(pDest: Ptr, eDest: c_int, iParm: c_int) void {
    setDestEDest(pDest, @truncate(@as(u32, @bitCast(eDest))));
    setDestISDParm(pDest, iParm);
    setDestISDParm2(pDest, 0);
    wr(?*anyopaque, pDest, SelectDest_zAffSdst, null);
    setDestISdst(pDest, 0);
    setDestNSdst(pDest, 0);
}

// sqlite3SelectNew (EXPORT) — line 126
export fn sqlite3SelectNew(
    pParse: Ptr,
    pEList0: Ptr,
    pSrc0: Ptr,
    pWhere: Ptr,
    pGroupBy: Ptr,
    pHaving: Ptr,
    pOrderBy: Ptr,
    selFlagsArg: u32,
    pLimit: Ptr,
) Ptr {
    const db = parseDb(pParse);
    var pEList = pEList0;
    var pSrc = pSrc0;
    var standin: [sizeof_Select]u8 align(8) = undefined;
    var pAllocated = c.sqlite3DbMallocRawNN(db, sizeof_Select);
    var pNew = pAllocated;
    if (pNew == null) {
        // assert mallocFailed
        pNew = @ptrCast(&standin);
    }
    if (pEList == null) {
        pEList = c.sqlite3ExprListAppend(pParse, null, c.sqlite3Expr(db, TK_ASTERISK, null));
    }
    setSelPEList(pNew, pEList);
    setSelOp(pNew, TK_SELECT);
    setSelFlags(pNew, selFlagsArg);
    setSelILimit(pNew, 0);
    setSelIOffset(pNew, 0);
    wr(c_int, pParse, Parse_nSelect, rd(c_int, pParse, Parse_nSelect) + 1);
    setSelId(pNew, rd(c_int, pParse, Parse_nSelect));
    setSelNSelectRow(pNew, 0);
    if (pSrc == null) pSrc = c.sqlite3DbMallocZero(db, SZ_SRCLIST_1);
    setSelPSrc(pNew, pSrc);
    setSelPWhere(pNew, pWhere);
    setSelPGroupBy(pNew, pGroupBy);
    setSelPHaving(pNew, pHaving);
    setSelPOrderBy(pNew, pOrderBy);
    setSelPPrior(pNew, null);
    setSelPNext(pNew, null);
    setSelPLimit(pNew, pLimit);
    setSelPWith(pNew, null);
    // SQLITE_OMIT_WINDOWFUNC OFF
    wr(?*anyopaque, pNew, Select_pWin, null);
    wr(?*anyopaque, pNew, Select_pWinDefn, null);
    if (dbMallocFailed(db)) {
        clearSelect(db, pNew, @intFromBool(pNew != @as(Ptr, @ptrCast(&standin))));
        pAllocated = null;
    } else {
        // assert pNew->pSrc!=0 || pParse->nErr>0
    }
    return pAllocated;
}

// sqlite3SelectDelete (EXPORT) — line 182
export fn sqlite3SelectDelete(db: Ptr, p: Ptr) void {
    if (p != null) clearSelect(db, p, 1);
}

// sqlite3SelectDeleteGeneric (EXPORT) — line 185
export fn sqlite3SelectDeleteGeneric(db: Ptr, p: ?*anyopaque) void {
    if (p != null) clearSelect(db, p, 1);
}

// findRightmost (static) — line 192
fn findRightmost(p0: Ptr) Ptr {
    var p = p0;
    while (selPNext(p) != null) p = selPNext(p);
    return p;
}

// sqlite3JoinType (EXPORT) — line 260
export fn sqlite3JoinType(pParse: Ptr, pA: Ptr, pB: Ptr, pC: Ptr) c_int {
    var jointype: c_int = 0;
    var apAll: [3]Ptr = undefined;
    //                              0123456789 123456789 123456789 123
    const zKeyText = "naturaleftouterightfullinnercross";
    const Kw = struct {
        i: u8,
        nChar: u8,
        code: u8,
    };
    const aKeyword = [_]Kw{
        .{ .i = 0, .nChar = 7, .code = JT_NATURAL },
        .{ .i = 6, .nChar = 4, .code = JT_LEFT | JT_OUTER },
        .{ .i = 10, .nChar = 5, .code = JT_OUTER },
        .{ .i = 14, .nChar = 5, .code = JT_RIGHT | JT_OUTER },
        .{ .i = 19, .nChar = 4, .code = JT_LEFT | JT_RIGHT | JT_OUTER },
        .{ .i = 23, .nChar = 5, .code = JT_INNER },
        .{ .i = 28, .nChar = 5, .code = JT_INNER | JT_CROSS },
    };
    apAll[0] = pA;
    apAll[1] = pB;
    apAll[2] = pC;
    var i: c_int = 0;
    var j: usize = 0;
    while (i < 3 and apAll[@intCast(i)] != null) : (i += 1) {
        const p = apAll[@intCast(i)];
        const pn: c_int = rd(c_int, p, Token_n);
        const pz: ?[*:0]const u8 = @ptrCast(rdp(p, Token_z));
        j = 0;
        while (j < aKeyword.len) : (j += 1) {
            if (pn == @as(c_int, aKeyword[j].nChar) and
                c.sqlite3StrNICmp(pz, @ptrCast(&zKeyText[aKeyword[j].i]), pn) == 0)
            {
                jointype |= @as(c_int, aKeyword[j].code);
                break;
            }
        }
        if (j >= aKeyword.len) {
            jointype |= @as(c_int, JT_ERROR);
            break;
        }
    }
    if ((jointype & (@as(c_int, JT_INNER) | JT_OUTER)) == (@as(c_int, JT_INNER) | JT_OUTER) or
        (jointype & @as(c_int, JT_ERROR)) != 0 or
        (jointype & (@as(c_int, JT_OUTER) | JT_LEFT | JT_RIGHT)) == @as(c_int, JT_OUTER))
    {
        var zSp1: [*:0]const u8 = " ";
        var zSp2: [*:0]const u8 = " ";
        if (pB == null) zSp1 += 1;
        if (pC == null) zSp2 += 1;
        c.sqlite3ErrorMsg(pParse, "unknown join type: %T%s%T%s%T", pA, zSp1, pB, zSp2, pC);
        jointype = JT_INNER;
    }
    return jointype;
}

// sqlite3ColumnIndex (EXPORT) — line 318
export fn sqlite3ColumnIndex(pTab: Ptr, zCol: ?[*:0]const u8) c_int {
    const h: u8 = c.sqlite3StrIHash(zCol);
    const nCol: c_int = tabNCol(pTab);

    // See if the aHx gives us a lucky match.  aHx is u8[16]; index = h % 16.
    const aHx: [*]const u8 = @ptrCast(fieldPtr(pTab, Table_aHx));
    var i: c_int = aHx[h % 16];
    {
        const col = tabColAt(pTab, i);
        if (rd(u8, col, Column_hName) == h and
            c.sqlite3StrICmp(@ptrCast(rdp(col, Column_zCnName)), zCol) == 0)
        {
            return i;
        }
    }

    // Full search.
    i = 0;
    while (true) {
        const col = tabColAt(pTab, i);
        if (rd(u8, col, Column_hName) == h and
            c.sqlite3StrICmp(@ptrCast(rdp(col, Column_zCnName)), zCol) == 0)
        {
            return i;
        }
        i += 1;
        if (i >= nCol) break;
    }
    return -1;
}

// sqlite3SrcItemColumnUsed (EXPORT) — line 354
export fn sqlite3SrcItemColumnUsed(pItem: Ptr, iCol: c_int) void {
    if (srcHas(pItem, FG_isNestedFrom)) {
        const pResults = selPEList(itemSelect(pItem));
        const item = elItem(pResults, iCol);
        // pResults->a[iCol].fg.bUsed = 1
        setItemBUsed(item);
    }
}

// tableAndColumnIndex (static) — line 379
fn tableAndColumnIndex(
    pSrc: Ptr,
    iStart: c_int,
    iEnd: c_int,
    zCol: ?[*:0]const u8,
    piTab: ?*c_int,
    piCol: ?*c_int,
    bIgnoreHidden: c_int,
) c_int {
    var i: c_int = iStart;
    while (i <= iEnd) : (i += 1) {
        const srcItem = srcItemAt(pSrc, i);
        const pTab = itemPTab(srcItem);
        const iCol = sqlite3ColumnIndex(pTab, zCol);
        if (iCol >= 0 and
            (bIgnoreHidden == 0 or
                (colFlags(tabColAt(pTab, iCol)) & COLFLAG_HIDDEN) == 0))
        {
            if (piTab != null) {
                sqlite3SrcItemColumnUsed(srcItem, iCol);
                piTab.?.* = i;
                piCol.?.* = iCol;
            }
            return 1;
        }
    }
    return 0;
}

// sqlite3SetJoinExpr (EXPORT) — line 437
export fn sqlite3SetJoinExpr(p0: Ptr, iTable: c_int, joinFlag: u32) void {
    var p = p0;
    while (p != null) {
        setProp(p, joinFlag);
        // ExprSetVVAProperty omitted (debug-only)
        setExprWJoin(p, iTable);
        if (exprUseXList(p)) {
            const pList = exprPList(p);
            if (pList != null) {
                var i: c_int = 0;
                const n = listNExpr(pList);
                while (i < n) : (i += 1) {
                    sqlite3SetJoinExpr(itemExpr(elItem(pList, i)), iTable, joinFlag);
                }
            }
        }
        sqlite3SetJoinExpr(exprPLeft(p), iTable, joinFlag);
        p = exprPRight(p);
    }
}

// unsetJoinExpr (static) — line 471
fn unsetJoinExpr(p0: Ptr, iTable: c_int, nullable: c_int) void {
    var p = p0;
    while (p != null) {
        if (iTable < 0 or (hasProp(p, EP_OuterON) and exprWJoin(p) == iTable)) {
            clearProp(p, EP_OuterON | EP_InnerON);
            if (iTable >= 0) setProp(p, EP_InnerON);
        }
        if (exprOp(p) == TK_COLUMN and exprITable(p) == iTable and nullable == 0) {
            clearProp(p, EP_CanBeNull);
        }
        if (exprOp(p) == TK_FUNCTION) {
            const pList = exprPList(p);
            if (pList != null) {
                var i: c_int = 0;
                const n = listNExpr(pList);
                while (i < n) : (i += 1) {
                    unsetJoinExpr(itemExpr(elItem(pList, i)), iTable, nullable);
                }
            }
        }
        unsetJoinExpr(exprPLeft(p), iTable, nullable);
        p = exprPRight(p);
    }
}

// exprUseXList(p) inline helper: matches scaffold pattern — x.pList valid when
// !EP_xIsSelect. (EP_TokenOnly path treated as has-list-only-if-not-token; but
// per the convention here we mirror C's ExprUseXList == !ExprHasProperty(EP_xIsSelect).)

// sqlite3ProcessJoin (static) — line 516. Returns # errors (0 = success).
fn sqlite3ProcessJoin(pParse: Ptr, p: Ptr) c_int {
    const pSrc = selPSrc(p);
    var i: c_int = 0;
    var j: c_int = 0;
    const nSrc = srcNSrc(pSrc);
    while (i < nSrc - 1) : (i += 1) {
        const pLeft = srcItemAt(pSrc, i);
        const pRight = srcItemAt(pSrc, i + 1);
        const pRightTab = itemPTab(pRight);
        const jtype = srcFgJoinType(pRight);

        if (itemPTab(pLeft) == null or pRightTab == null) continue;
        const joinType: u32 = if ((jtype & JT_OUTER) != 0) EP_OuterON else EP_InnerON;

        // NATURAL join -> synthesize a USING clause.
        if ((jtype & JT_NATURAL) != 0) {
            var pUsing: Ptr = null;
            if (srcHas(pRight, FG_isUsing) or itemU3(pRight) != null) {
                c.sqlite3ErrorMsg(pParse, "a NATURAL join may not have an ON or USING clause", @as(c_int, 0));
                return 1;
            }
            j = 0;
            const nCol: c_int = tabNCol(pRightTab);
            while (j < nCol) : (j += 1) {
                const pCol = tabColAt(pRightTab, j);
                if ((colFlags(pCol) & COLFLAG_HIDDEN) != 0) continue;
                const zName: ?[*:0]const u8 = @ptrCast(rdp(pCol, Column_zCnName));
                if (tableAndColumnIndex(pSrc, 0, i, zName, null, null, 1) != 0) {
                    pUsing = c.sqlite3IdListAppend(pParse, pUsing, null);
                    if (pUsing != null) {
                        const nId = rd(c_int, pUsing, IdList_nId);
                        const idItem = @as(Ptr, @ptrCast(base(fieldPtr(pUsing, IdList_a)) +
                            @as(usize, @intCast(nId - 1)) * sizeof_IdList_item));
                        wr(?*anyopaque, idItem, IdList_item_zName, @ptrCast(c.sqlite3DbStrDup(parseDb(pParse), zName)));
                    }
                }
            }
            if (pUsing != null) {
                srcSet(pRight, FG_isUsing);
                srcSet(pRight, FG_isSynthUsing);
                setItemU3(pRight, pUsing);
            }
            if (parseNErr(pParse) != 0) return 1;
        }

        // Create extra WHERE terms for each USING column.
        if (srcHas(pRight, FG_isUsing)) {
            const pList = itemU3(pRight);
            const db = parseDb(pParse);
            const nId = rd(c_int, pList, IdList_nId);
            j = 0;
            while (j < nId) : (j += 1) {
                const idItem = @as(Ptr, @ptrCast(base(fieldPtr(pList, IdList_a)) +
                    @as(usize, @intCast(j)) * sizeof_IdList_item));
                const zName: ?[*:0]const u8 = @ptrCast(rdp(idItem, IdList_item_zName));
                var iLeft: c_int = 0;
                var iLeftCol: c_int = 0;
                const iRightCol = sqlite3ColumnIndex(pRightTab, zName);
                if (iRightCol < 0 or
                    tableAndColumnIndex(pSrc, 0, i, zName, &iLeft, &iLeftCol, @intFromBool(srcHas(pRight, FG_isSynthUsing))) == 0)
                {
                    c.sqlite3ErrorMsg(pParse, "cannot join using column %s - column not present in both tables", zName);
                    return 1;
                }
                var pE1 = c.sqlite3CreateColumnExpr(db, pSrc, iLeft, iLeftCol);
                sqlite3SrcItemColumnUsed(srcItemAt(pSrc, iLeft), iLeftCol);
                if ((srcFgJoinType(srcItemAt(pSrc, 0)) & JT_LTORJ) != 0 and parseNErr(pParse) == 0) {
                    var pFuncArgs: Ptr = null;
                    // static const Token tkCoalesce = { "coalesce", 8 };
                    var tkCoalesce: [sizeof_Token]u8 align(8) = undefined;
                    wr(?*const anyopaque, &tkCoalesce, Token_z, @ptrCast(@as([*:0]const u8, "coalesce")));
                    wr(c_int, &tkCoalesce, Token_n, 8);
                    setProp(pE1, EP_CanBeNull);
                    while (tableAndColumnIndex(pSrc, iLeft + 1, i, zName, &iLeft, &iLeftCol, @intFromBool(srcHas(pRight, FG_isSynthUsing))) != 0) {
                        const lItem = srcItemAt(pSrc, iLeft);
                        if (!srcHas(lItem, FG_isUsing) or
                            c.sqlite3IdListIndex(itemU3(lItem), zName) < 0)
                        {
                            c.sqlite3ErrorMsg(pParse, "ambiguous reference to %s in USING()", zName);
                            break;
                        }
                        pFuncArgs = c.sqlite3ExprListAppend(pParse, pFuncArgs, pE1);
                        pE1 = c.sqlite3CreateColumnExpr(db, pSrc, iLeft, iLeftCol);
                        sqlite3SrcItemColumnUsed(srcItemAt(pSrc, iLeft), iLeftCol);
                    }
                    if (pFuncArgs != null) {
                        pFuncArgs = c.sqlite3ExprListAppend(pParse, pFuncArgs, pE1);
                        pE1 = c.sqlite3ExprFunction(pParse, pFuncArgs, @ptrCast(&tkCoalesce), 0);
                        if (pE1 != null) {
                            wr(u8, pE1, Expr_affExpr, SQLITE_AFF_DEFER);
                        }
                    }
                } else if ((srcFgJoinType(srcItemAt(pSrc, i + 1)) & JT_LEFT) != 0 and parseNErr(pParse) == 0) {
                    setProp(pE1, EP_CanBeNull);
                }
                const pE2 = c.sqlite3CreateColumnExpr(db, pSrc, i + 1, iRightCol);
                sqlite3SrcItemColumnUsed(pRight, iRightCol);
                const pEq = c.sqlite3PExpr(pParse, TK_EQ, pE1, pE2);
                if (pEq != null) {
                    setProp(pEq, joinType);
                    // ExprSetVVAProperty omitted
                    setExprWJoin(pEq, exprITable(pE2));
                }
                setSelPWhere(p, c.sqlite3ExprAnd(pParse, selPWhere(p), pEq));
            }
        }

        // Add the ON clause to the WHERE clause.
        else if (itemU3(pRight) != null) {
            sqlite3SetJoinExpr(itemU3(pRight), itemICursor(pRight), joinType);
            setSelPWhere(p, c.sqlite3ExprAnd(pParse, selPWhere(p), itemU3(pRight)));
            setItemU3(pRight, null);
            srcSet(pRight, FG_isOn);
            selSet(p, SF_OnToWhere);
        }

        // IsVirtual(pRightTab): eTabType==TABTYP_VTAB (==1).
        if (tabETabType(pRightTab) == 1 and joinType == EP_OuterON and itemU1(pRight) != null) {
            selSet(p, SF_OnToWhere);
        }
    }
    return 0;
}

// ════════════ CLUSTER B ════════════
// ════════════════════════════════════════════════════════════════════════════
// CLUSTER B — inner-loop + sorter machinery from src/select.c
//
// Functions ported (in C order):
//   RowLoadInfo / SortCtx / DistinctCtx   (local stack structs; SortCtx is
//       shared with cluster F sqlite3Select → defined pub as extern structs)
//   innerLoopLoadRow   (static)
//   makeSorterRecord   (static)
//   pushOntoSorter     (static)
//   codeOffset         (static)
//   codeDistinct       (static)
//   fixDistinctOpenEph (static)
//   selectInnerLoop    (static; needed by cluster F too)
//
// SQLITE_ENABLE_SORTER_REFERENCES and SQLITE_ENABLE_STMT_SCANSTATUS are OFF, so
// those #ifdef fields and blocks are OMITTED (struct layout matches the C build
// with those features disabled).
// ════════════════════════════════════════════════════════════════════════════

// ─── Local stack structs (shared layout) ─────────────────────────────────────
// Field order MUST match select.c exactly (with SORTER_REFERENCES/SCANSTATUS
// fields omitted, matching this build's configuration).

pub const DistinctCtx = extern struct {
    isTnct: u8, // True if the DISTINCT keyword is present
    eTnctType: u8, // One of the WHERE_DISTINCT_* operators
    tabTnct: c_int, // Ephemeral table used for DISTINCT processing
    addrTnct: c_int, // Address of OP_OpenEphemeral opcode for tabTnct
};

pub const SortCtx = extern struct {
    pOrderBy: ?*anyopaque, // The ORDER BY (or GROUP BY) clause, or NULL
    nOBSat: c_int, // Number of ORDER BY terms satisfied by indices
    iECursor: c_int, // Cursor number for the sorter
    regReturn: c_int, // Register holding block-output return address
    labelBkOut: c_int, // Start label for the block-output subroutine
    addrSortIndex: c_int, // Address of the OP_SorterOpen or OP_OpenEphemeral
    labelDone: c_int, // Jump here when done, ex: LIMIT reached
    labelOBLopt: c_int, // Jump here when sorter is full
    sortFlags: u8, // Zero or more SORTFLAG_* bits
    pDeferredRowLoad: ?*anyopaque, // Deferred row loading info or NULL
};

pub const RowLoadInfo = extern struct {
    regResult: c_int, // Store results in array of registers here
    ecelFlags: u8, // Flag argument to ExprCodeExprList()
};

// ─── innerLoopLoadRow (select.c:688) ─────────────────────────────────────────
fn innerLoopLoadRow(
    pParse: Ptr,
    pSelect: Ptr,
    pInfo: *RowLoadInfo,
) void {
    _ = c.sqlite3ExprCodeExprList(pParse, selPEList(pSelect), pInfo.regResult, 0, pInfo.ecelFlags);
}

// ─── makeSorterRecord (select.c:709) ─────────────────────────────────────────
fn makeSorterRecord(
    pParse: Ptr,
    pSort: *SortCtx,
    pSelect: Ptr,
    regBase: c_int,
    nBase: c_int,
) c_int {
    const nOBSat = pSort.nOBSat;
    const v = parseVdbe(pParse);
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
    const regOut = rd(c_int, pParse, Parse_nMem);
    if (pSort.pDeferredRowLoad) |pDRL| {
        innerLoopLoadRow(pParse, pSelect, @ptrCast(@alignCast(pDRL)));
    }
    _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regBase + nOBSat, nBase - nOBSat, regOut);
    return regOut;
}

// ─── pushOntoSorter (select.c:730) ───────────────────────────────────────────
fn pushOntoSorter(
    pParse: Ptr,
    pSort: *SortCtx,
    pSelect: Ptr,
    regData: c_int,
    regOrigData: c_int,
    nData: c_int,
    nPrefixReg: c_int,
) void {
    const v = parseVdbe(pParse);
    const bSeq: c_int = if ((pSort.sortFlags & SORTFLAG_UseSorter) == 0) 1 else 0;
    const nExpr = listNExpr(pSort.pOrderBy); // No. of ORDER BY terms
    const nBase = nExpr + bSeq + nData; // Fields in sorter record
    var regBase: c_int = undefined; // Regs for sorter record
    var regRecord: c_int = 0; // Assembled sorter record
    const nOBSat = pSort.nOBSat; // ORDER BY terms to skip
    var op: c_int = undefined; // Opcode to add sorter record to sorter
    var iLimit: c_int = undefined; // LIMIT counter
    var iSkip: c_int = 0; // End of the sorter insert loop

    if (nPrefixReg != 0) {
        regBase = regData - nPrefixReg;
    } else {
        regBase = rd(c_int, pParse, Parse_nMem) + 1;
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + nBase);
    }
    iLimit = if (selIOffset(pSelect) != 0) selIOffset(pSelect) + 1 else selILimit(pSelect);
    pSort.labelDone = c.sqlite3VdbeMakeLabel(pParse);
    _ = c.sqlite3ExprCodeExprList(pParse, pSort.pOrderBy, regBase, regOrigData, SQLITE_ECEL_DUP | (if (regOrigData != 0) SQLITE_ECEL_REF else 0));
    if (bSeq != 0) {
        _ = c.sqlite3VdbeAddOp2(v, OP.Sequence, pSort.iECursor, regBase + nExpr);
    }
    if (nPrefixReg == 0 and nData > 0) {
        c.sqlite3ExprCodeMove(pParse, regData, regBase + nExpr + bSeq, nData);
    }
    if (nOBSat > 0) {
        var regPrevKey: c_int = undefined;
        var addrFirst: c_int = undefined;
        var addrJmp: c_int = undefined;
        var pOp: Ptr = undefined;
        var nKey: c_int = undefined;
        var pKI: Ptr = undefined;

        regRecord = makeSorterRecord(pParse, pSort, pSelect, regBase, nBase);
        regPrevKey = rd(c_int, pParse, Parse_nMem) + 1;
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + pSort.nOBSat);
        nKey = nExpr - pSort.nOBSat + bSeq;
        if (bSeq != 0) {
            addrFirst = c.sqlite3VdbeAddOp1(v, OP.IfNot, regBase + nExpr);
        } else {
            addrFirst = c.sqlite3VdbeAddOp1(v, OP.SequenceTest, pSort.iECursor);
        }
        _ = c.sqlite3VdbeAddOp3(v, OP.Compare, regPrevKey, regBase, pSort.nOBSat);
        pOp = c.sqlite3VdbeGetOp(v, pSort.addrSortIndex);
        if (dbMallocFailed(parseDb(pParse))) return;
        wr(c_int, pOp, VdbeOp_p2, nKey + nData);
        pKI = rdp(pOp, VdbeOp_p4);
        _ = c.memset(@ptrCast(kiASortFlags(pKI)), 0, kiNKeyField(pKI)); // Makes OP_Jump testable
        c.sqlite3VdbeChangeP4(v, -1, @ptrCast(pKI), P4_KEYINFO);
        wr(?*anyopaque, pOp, VdbeOp_p4, sqlite3KeyInfoFromExprList(pParse, pSort.pOrderBy, nOBSat, @as(c_int, @intCast(kiNAllField(pKI))) - @as(c_int, @intCast(kiNKeyField(pKI))) - 1));
        pOp = null; // Ensure pOp not used after sqlite3VdbeAddOp3()
        addrJmp = c.sqlite3VdbeCurrentAddr(v);
        _ = c.sqlite3VdbeAddOp3(v, OP.Jump, addrJmp + 1, 0, addrJmp + 1);
        pSort.labelBkOut = c.sqlite3VdbeMakeLabel(pParse);
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
        pSort.regReturn = rd(c_int, pParse, Parse_nMem);
        _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, pSort.regReturn, pSort.labelBkOut);
        _ = c.sqlite3VdbeAddOp1(v, OP.ResetSorter, pSort.iECursor);
        if (iLimit != 0) {
            _ = c.sqlite3VdbeAddOp2(v, OP.IfNot, iLimit, pSort.labelDone);
        }
        c.sqlite3VdbeJumpHere(v, addrFirst);
        c.sqlite3ExprCodeMove(pParse, regBase, regPrevKey, pSort.nOBSat);
        c.sqlite3VdbeJumpHere(v, addrJmp);
    }
    if (iLimit != 0) {
        const iCsr = pSort.iECursor;
        _ = c.sqlite3VdbeAddOp2(v, OP.IfNotZero, iLimit, c.sqlite3VdbeCurrentAddr(v) + 4);
        _ = c.sqlite3VdbeAddOp2(v, OP.Last, iCsr, 0);
        iSkip = c.sqlite3VdbeAddOp4Int(v, OP.IdxLE, iCsr, 0, regBase + nOBSat, nExpr - nOBSat);
        _ = c.sqlite3VdbeAddOp1(v, OP.Delete, iCsr);
    }
    if (regRecord == 0) {
        regRecord = makeSorterRecord(pParse, pSort, pSelect, regBase, nBase);
    }
    if ((pSort.sortFlags & SORTFLAG_UseSorter) != 0) {
        op = OP.SorterInsert;
    } else {
        op = OP.IdxInsert;
    }
    _ = c.sqlite3VdbeAddOp4Int(v, op, pSort.iECursor, regRecord, regBase + nOBSat, nBase - nOBSat);
    if (iSkip != 0) {
        c.sqlite3VdbeChangeP2(v, iSkip, if (pSort.labelOBLopt != 0) pSort.labelOBLopt else c.sqlite3VdbeCurrentAddr(v));
    }
}

// ─── codeOffset (select.c:879) ───────────────────────────────────────────────
fn codeOffset(
    v: Ptr,
    iOffset: c_int,
    iContinue: c_int,
) void {
    if (iOffset > 0) {
        _ = c.sqlite3VdbeAddOp3(v, OP.IfPos, iOffset, iContinue, 1);
    }
}

// ─── codeDistinct (select.c:933) ─────────────────────────────────────────────
fn codeDistinct(
    pParse: Ptr,
    eTnctType: c_int,
    iTab: c_int,
    addrRepeat: c_int,
    pEList: Ptr,
    regElem: c_int,
) c_int {
    var iRet: c_int = 0;
    const nResultCol = listNExpr(pEList);
    const v = parseVdbe(pParse);

    switch (eTnctType) {
        WHERE_DISTINCT_ORDERED => {
            var i: c_int = 0;
            var iJump: c_int = undefined;
            var regPrev: c_int = undefined;

            // Allocate space for the previous row
            regPrev = rd(c_int, pParse, Parse_nMem) + 1;
            iRet = regPrev;
            wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + nResultCol);

            iJump = c.sqlite3VdbeCurrentAddr(v) + nResultCol;
            i = 0;
            while (i < nResultCol) : (i += 1) {
                const pColl = c.sqlite3ExprCollSeq(pParse, itemExpr(elItem(pEList, i)));
                if (i < nResultCol - 1) {
                    _ = c.sqlite3VdbeAddOp3(v, OP.Ne, regElem + i, iJump, regPrev + i);
                } else {
                    _ = c.sqlite3VdbeAddOp3(v, OP.Eq, regElem + i, addrRepeat, regPrev + i);
                }
                c.sqlite3VdbeChangeP4(v, -1, @ptrCast(pColl), P4_COLLSEQ);
                c.sqlite3VdbeChangeP5(v, @intCast(SQLITE_NULLEQ));
            }
            _ = c.sqlite3VdbeAddOp3(v, OP.Copy, regElem, regPrev, nResultCol - 1);
        },

        WHERE_DISTINCT_UNIQUE => {
            // nothing to do
        },

        else => {
            const r1 = c.sqlite3GetTempReg(pParse);
            _ = c.sqlite3VdbeAddOp4Int(v, OP.Found, iTab, addrRepeat, regElem, nResultCol);
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regElem, nResultCol, r1);
            _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iTab, r1, regElem, nResultCol);
            c.sqlite3VdbeChangeP5(v, OPFLAG_USESEEKRESULT);
            c.sqlite3ReleaseTempReg(pParse, r1);
            iRet = iTab;
        },
    }

    return iRet;
}

// ─── fixDistinctOpenEph (select.c:1017) ──────────────────────────────────────
fn fixDistinctOpenEph(
    pParse: Ptr,
    eTnctType: c_int,
    iVal: c_int,
    iOpenEphAddr: c_int,
) void {
    if (parseNErr(pParse) == 0 and
        (eTnctType == WHERE_DISTINCT_UNIQUE or eTnctType == WHERE_DISTINCT_ORDERED))
    {
        const v = parseVdbe(pParse);
        _ = c.sqlite3VdbeChangeToNoop(v, iOpenEphAddr);
        if (rd(u8, c.sqlite3VdbeGetOp(v, iOpenEphAddr + 1), VdbeOp_opcode) == OP.Explain) {
            _ = c.sqlite3VdbeChangeToNoop(v, iOpenEphAddr + 1);
        }
        if (eTnctType == WHERE_DISTINCT_ORDERED) {
            // Change the OP_OpenEphemeral to an OP_Null that sets the MEM_Cleared
            // bit on the first register of the previous value.
            const pOp = c.sqlite3VdbeGetOp(v, iOpenEphAddr);
            wr(u8, pOp, VdbeOp_opcode, @intCast(OP.Null));
            wr(c_int, pOp, VdbeOp_p1, 1);
            wr(c_int, pOp, VdbeOp_p2, iVal);
        }
    }
}

// ─── selectInnerLoop (select.c:1139) ─────────────────────────────────────────
// SQLITE_ENABLE_SORTER_REFERENCES blocks are omitted (feature OFF).
fn selectInnerLoop(
    pParse: Ptr,
    p: Ptr,
    srcTab: c_int,
    pSortArg: ?*SortCtx,
    pDistinct: ?*DistinctCtx,
    pDest: Ptr,
    iContinue: c_int,
    iBreak: c_int,
) void {
    const v = parseVdbe(pParse);
    var i: c_int = undefined;
    var hasDistinct: c_int = undefined; // True if the DISTINCT keyword is present
    const eDest = destEDest(pDest); // How to dispose of results
    const iParm = destISDParm(pDest); // First argument to disposal method
    var nResultCol: c_int = undefined; // Number of result columns
    var nPrefixReg: c_int = 0; // Number of extra registers before regResult
    var sRowLoadInfo: RowLoadInfo = undefined; // Info for deferred row loading

    var regResult: c_int = undefined; // Start of memory holding current results
    var regOrig: c_int = undefined; // Start of memory holding full result (or 0)

    var pSort = pSortArg;

    hasDistinct = if (pDistinct) |pd| pd.eTnctType else WHERE_DISTINCT_NOOP;
    if (pSort) |ps| {
        if (ps.pOrderBy == null) pSort = null;
    }
    if (pSort == null and hasDistinct == 0) {
        codeOffset(v, selIOffset(p), iContinue);
    }

    // Pull the requested columns.
    nResultCol = listNExpr(selPEList(p));

    if (destISdst(pDest) == 0) {
        if (pSort) |ps| {
            nPrefixReg = listNExpr(ps.pOrderBy);
            if ((ps.sortFlags & SORTFLAG_UseSorter) == 0) nPrefixReg += 1;
            wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + nPrefixReg);
        }
        setDestISdst(pDest, rd(c_int, pParse, Parse_nMem) + 1);
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + nResultCol);
    } else if (destISdst(pDest) + nResultCol > rd(c_int, pParse, Parse_nMem)) {
        // Error condition (e.g. SELECT in INSERT with too many columns).
        // Make sure enough memory is allocated to avoid spurious errors.
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + nResultCol);
    }
    setDestNSdst(pDest, nResultCol);
    regResult = destISdst(pDest);
    regOrig = regResult;
    if (srcTab >= 0) {
        i = 0;
        while (i < nResultCol) : (i += 1) {
            _ = c.sqlite3VdbeAddOp3(v, OP.Column, srcTab, i, regResult + i);
        }
    } else if (eDest != SRT_Exists) {
        // If the destination is an EXISTS(...) expression, the actual
        // values returned by the SELECT are not required.
        var ecelFlags: u8 = undefined; // "ecel" abbreviates "ExprCodeExprList"
        var pEList: Ptr = undefined;
        if (eDest == SRT_Mem or eDest == SRT_Output or eDest == SRT_Coroutine) {
            ecelFlags = SQLITE_ECEL_DUP;
        } else {
            ecelFlags = 0;
        }
        if (pSort != null and hasDistinct == 0 and eDest != SRT_EphemTab and eDest != SRT_Table) {
            const ps = pSort.?;
            // For each expression in p->pEList that is a copy of an expression in
            // the ORDER BY clause, set the associated iOrderByCol value so the
            // p->pEList field can be omitted from the sorted record.
            ecelFlags |= (SQLITE_ECEL_OMITREF | SQLITE_ECEL_REF);

            i = ps.nOBSat;
            while (i < listNExpr(ps.pOrderBy)) : (i += 1) {
                const j: c_int = @intCast(itemIOrderByCol(elItem(ps.pOrderBy, i)));
                if (j > 0) {
                    setItemIOrderByCol(elItem(selPEList(p), j - 1), @intCast(i + 1 - ps.nOBSat));
                }
            }

            // Adjust nResultCol to account for columns omitted from the sorter.
            pEList = selPEList(p);
            i = 0;
            while (i < listNExpr(pEList)) : (i += 1) {
                if (itemIOrderByCol(elItem(pEList, i)) > 0) {
                    nResultCol -= 1;
                    regOrig = 0;
                }
            }
        }
        sRowLoadInfo.regResult = regResult;
        sRowLoadInfo.ecelFlags = ecelFlags;
        if (selILimit(p) != 0 and (ecelFlags & SQLITE_ECEL_OMITREF) != 0 and nPrefixReg > 0) {
            pSort.?.pDeferredRowLoad = @ptrCast(&sRowLoadInfo);
            regOrig = 0;
        } else {
            innerLoopLoadRow(pParse, p, &sRowLoadInfo);
        }
    }

    // If the DISTINCT keyword was present and this row has been seen before,
    // then do not make this row part of the result.
    if (hasDistinct != 0) {
        const pd = pDistinct.?;
        const eType = pd.eTnctType;
        var iTab = pd.tabTnct;
        iTab = codeDistinct(pParse, eType, iTab, iContinue, selPEList(p), regResult);
        fixDistinctOpenEph(pParse, eType, iTab, pd.addrTnct);
        if (pSort == null) {
            codeOffset(v, selIOffset(p), iContinue);
        }
    }

    switch (eDest) {
        // Store the result as data using a unique key.
        SRT_Fifo, SRT_DistFifo, SRT_Table, SRT_EphemTab => {
            const r1 = c.sqlite3GetTempRange(pParse, nPrefixReg + 1);
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regResult, nResultCol, r1 + nPrefixReg);
            // SRT_DistFifo: cursor (iParm+1) holds an ephemeral index. If the
            // current row is already present, do not write it to the output.
            if (eDest == SRT_DistFifo) {
                const addr = c.sqlite3VdbeCurrentAddr(v) + 4;
                _ = c.sqlite3VdbeAddOp4Int(v, OP.Found, iParm + 1, addr, r1, 0);
                _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm + 1, r1, regResult, nResultCol);
            }
            if (pSort) |ps| {
                pushOntoSorter(pParse, ps, p, r1 + nPrefixReg, regOrig, 1, nPrefixReg);
            } else {
                const r2 = c.sqlite3GetTempReg(pParse);
                _ = c.sqlite3VdbeAddOp2(v, OP.NewRowid, iParm, r2);
                _ = c.sqlite3VdbeAddOp3(v, OP.Insert, iParm, r1, r2);
                c.sqlite3VdbeChangeP5(v, OPFLAG_APPEND);
                c.sqlite3ReleaseTempReg(pParse, r2);
            }
            c.sqlite3ReleaseTempRange(pParse, r1, nPrefixReg + 1);
        },

        SRT_Upfrom => {
            if (pSort) |ps| {
                pushOntoSorter(pParse, ps, p, regResult, regOrig, nResultCol, nPrefixReg);
            } else {
                const iSDP2 = destISDParm2(pDest);
                const r1 = c.sqlite3GetTempReg(pParse);

                // If the UPDATE FROM join is an aggregate that matches no rows,
                // it might still return one row.  Don't record that empty row.
                _ = c.sqlite3VdbeAddOp2(v, OP.IsNull, regResult, iBreak);

                const b: c_int = if (iSDP2 < 0) 1 else 0;
                _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regResult + b, nResultCol - b, r1);
                if (iSDP2 < 0) {
                    _ = c.sqlite3VdbeAddOp3(v, OP.Insert, iParm, r1, regResult);
                } else {
                    _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm, r1, regResult, iSDP2);
                }
            }
        },

        // If we are creating a set for an "expr IN (SELECT ...)" construct,
        // then there should be a single item on the stack.
        SRT_Set => {
            if (pSort) |ps| {
                // There might be a LIMIT clause, in which case order matters.
                pushOntoSorter(pParse, ps, p, regResult, regOrig, nResultCol, nPrefixReg);
                setDestISDParm2(pDest, 0); // Signal: Bloom filter unpopulated
            } else {
                const r1 = c.sqlite3GetTempReg(pParse);
                _ = c.sqlite3VdbeAddOp4(v, OP.MakeRecord, regResult, nResultCol, r1, @ptrCast(destZAffSdst(pDest)), nResultCol);
                _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm, r1, regResult, nResultCol);
                if (destISDParm2(pDest) != 0) {
                    _ = c.sqlite3VdbeAddOp4Int(v, OP.FilterAdd, destISDParm2(pDest), 0, regResult, nResultCol);
                    c.sqlite3VdbeExplain(pParse, 0, "CREATE BLOOM FILTER");
                }
                c.sqlite3ReleaseTempReg(pParse, r1);
            }
        },

        // If any row exist in the result set, record that fact and abort.
        SRT_Exists => {
            _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 1, iParm);
            // The LIMIT clause will terminate the loop for us
        },

        // Scalar select that is part of an expression: store the results in
        // the appropriate memory cell(s) and break out of the scan loop.
        SRT_Mem => {
            if (pSort) |ps| {
                pushOntoSorter(pParse, ps, p, regResult, regOrig, nResultCol, nPrefixReg);
                setDestISDParm(pDest, regResult);
            } else {
                if (regResult != iParm) {
                    // Occurs when the SELECT had both DISTINCT and OFFSET.
                    _ = c.sqlite3VdbeAddOp3(v, OP.Copy, regResult, iParm, nResultCol - 1);
                }
                // The LIMIT clause will jump out of the loop for us
            }
        },

        SRT_Coroutine, SRT_Output => {
            if (pSort) |ps| {
                pushOntoSorter(pParse, ps, p, regResult, regOrig, nResultCol, nPrefixReg);
            } else if (eDest == SRT_Coroutine) {
                _ = c.sqlite3VdbeAddOp1(v, OP.Yield, destISDParm(pDest));
            } else {
                _ = c.sqlite3VdbeAddOp2(v, OP.ResultRow, regResult, nResultCol);
            }
        },

        // Write the results into a priority queue ordered by pDest->pOrderBy.
        SRT_DistQueue, SRT_Queue => {
            var nKey: c_int = undefined;
            var addrTest: c_int = 0;
            const pSO = destPOrderBy(pDest);
            nKey = listNExpr(pSO);
            const r1 = c.sqlite3GetTempReg(pParse);
            const r2 = c.sqlite3GetTempRange(pParse, nKey + 2);
            const r3 = r2 + nKey + 1;
            if (eDest == SRT_DistQueue) {
                // Cursor (iParm+1) holds all values every previously added.
                addrTest = c.sqlite3VdbeAddOp4Int(v, OP.Found, iParm + 1, 0, regResult, nResultCol);
            }
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regResult, nResultCol, r3);
            if (eDest == SRT_DistQueue) {
                _ = c.sqlite3VdbeAddOp2(v, OP.IdxInsert, iParm + 1, r3);
                c.sqlite3VdbeChangeP5(v, OPFLAG_USESEEKRESULT);
            }
            i = 0;
            while (i < nKey) : (i += 1) {
                _ = c.sqlite3VdbeAddOp2(v, OP.SCopy, regResult + @as(c_int, @intCast(itemIOrderByCol(elItem(pSO, i)))) - 1, r2 + i);
            }
            _ = c.sqlite3VdbeAddOp2(v, OP.Sequence, iParm, r2 + nKey);
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, r2, nKey + 2, r1);
            _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm, r1, r2, nKey + 2);
            if (addrTest != 0) c.sqlite3VdbeJumpHere(v, addrTest);
            c.sqlite3ReleaseTempReg(pParse, r1);
            c.sqlite3ReleaseTempRange(pParse, r2, nKey + 2);
        },

        // Discard the results (SELECT statements inside a TRIGGER body).
        else => {
            // assert( eDest==SRT_Discard );
        },
    }

    // Jump to the end of the loop if the LIMIT is reached.  Except, if there
    // is a sorter, in which case the sorter has already limited the output.
    if (pSort == null and selILimit(p) != 0) {
        _ = c.sqlite3VdbeAddOp2(v, OP.DecrJumpZero, selILimit(p), iBreak);
    }
}

// ════════════ CLUSTER C ════════════
// ════════════════════════════════════════════════════════════════════════════
// CLUSTER C — KeyInfo + column names/types + compound helpers.
// (Function definitions only; all consts/accessors/externs come from select.zig.)
// ════════════════════════════════════════════════════════════════════════════

// Local consts needed by this cluster (sentinels + struct sizes not in scaffold).

// SortCtx field offsets (SORTER_REFERENCES + STMT_SCANSTATUS both OFF).
//   pOrderBy@0  nOBSat@8  iECursor@12  regReturn@16  labelBkOut@20
//   addrSortIndex@24  labelDone@28  labelOBLopt@32  sortFlags@36(u8)
//   pDeferredRowLoad@40
const SortCtx_pOrderBy: usize = 0;
const SortCtx_nOBSat: usize = 8;
const SortCtx_iECursor: usize = 12;
const SortCtx_regReturn: usize = 16;
const SortCtx_labelBkOut: usize = 20;
const SortCtx_labelDone: usize = 28;
const SortCtx_sortFlags: usize = 36;

inline fn sortPOrderBy(p: Ptr) Ptr {
    return rdp(p, SortCtx_pOrderBy);
}
inline fn sortNOBSat(p: Ptr) c_int {
    return rd(c_int, p, SortCtx_nOBSat);
}
inline fn sortIECursor(p: Ptr) c_int {
    return rd(c_int, p, SortCtx_iECursor);
}
inline fn sortRegReturn(p: Ptr) c_int {
    return rd(c_int, p, SortCtx_regReturn);
}
inline fn sortLabelBkOut(p: Ptr) c_int {
    return rd(c_int, p, SortCtx_labelBkOut);
}
inline fn sortLabelDone(p: Ptr) c_int {
    return rd(c_int, p, SortCtx_labelDone);
}
inline fn sortSortFlags(p: Ptr) u8 {
    return rd(u8, p, SortCtx_sortFlags);
}

// ── KeyInfo allocation / refcounting ─────────────────────────────────────────

/// Allocate a KeyInfo object sufficient for an index of N key columns and X
/// extra columns.
pub export fn sqlite3KeyInfoAlloc(db: Ptr, N: c_int, X: c_int) Ptr {
    // nExtra = (N+X)*(sizeof(CollSeq*)+1) = (N+X)*9
    const nExtra: usize = @as(usize, @intCast(N + X)) * (@sizeOf(?*anyopaque) + 1);
    if (N + X > 0xffff) return c.sqlite3OomFault(db);
    // SZ_KEYINFO(0) == offsetof(KeyInfo, aColl) == KeyInfo_aColl
    const p = c.sqlite3DbMallocRawNN(db, @as(u64, KeyInfo_aColl) + @as(u64, nExtra));
    if (p == null) return c.sqlite3OomFault(db);
    // p->aSortFlags = (u8*)&p->aColl[N+X];
    const aColl = kiAColl(p);
    const pSortFlags: ?*anyopaque = @ptrCast(aColl + @as(usize, @intCast(N + X)));
    wr(?*anyopaque, p, KeyInfo_aSortFlags, pSortFlags);
    setKiNKeyField(p, @intCast(N));
    setKiNAllField(p, @intCast(N + X));
    wr(u8, p, KeyInfo_enc, rd(u8, db, sqlite3_enc));
    wr(?*anyopaque, p, KeyInfo_db, db);
    wr(u32, p, KeyInfo_nRef, 1);
    _ = c.memset(@ptrCast(aColl), 0, nExtra);
    return p;
}

/// Deallocate a KeyInfo object.
pub export fn sqlite3KeyInfoUnref(p: Ptr) void {
    if (p != null) {
        const n = rd(u32, p, KeyInfo_nRef) - 1;
        wr(u32, p, KeyInfo_nRef, n);
        if (n == 0) {
            const db = rdp(p, KeyInfo_db);
            c.sqlite3DbNNFreeNN(db, p);
        }
    }
}

/// Make a new pointer to a KeyInfo object.
pub export fn sqlite3KeyInfoRef(p: Ptr) Ptr {
    if (p != null) {
        wr(u32, p, KeyInfo_nRef, rd(u32, p, KeyInfo_nRef) + 1);
    }
    return p;
}

// sqlite3KeyInfoIsWriteable: in C this is compiled only under SQLITE_DEBUG and
// used solely inside assert().  We gate its export on config.sqlite_debug so the
// symbol exists exactly when the C build would have provided it.
comptime {
    if (config.sqlite_debug) {
        @export(&keyInfoIsWriteable, .{ .name = "sqlite3KeyInfoIsWriteable", .linkage = .strong });
    }
}
fn keyInfoIsWriteable(p: Ptr) callconv(.c) c_int {
    return @intFromBool(rd(u32, p, KeyInfo_nRef) == 1);
}

/// Given an expression list, generate a KeyInfo recording the collating
/// sequence for each expression.
pub export fn sqlite3KeyInfoFromExprList(pParse: Ptr, pList: Ptr, iStart: c_int, nExtra: c_int) Ptr {
    const db = parseDb(pParse);
    const nExpr = listNExpr(pList);
    const pInfo = sqlite3KeyInfoAlloc(db, nExpr - iStart, nExtra + 1);
    if (pInfo != null) {
        const aColl = kiAColl(pInfo);
        const aSortFlags = kiASortFlags(pInfo);
        var i: c_int = iStart;
        while (i < nExpr) : (i += 1) {
            const pItem = elItem(pList, i);
            const idx: usize = @intCast(i - iStart);
            aColl[idx] = c.sqlite3ExprNNCollSeq(pParse, itemExpr(pItem));
            aSortFlags[idx] = itemSortFlags(pItem);
        }
    }
    return pInfo;
}

/// Name of the connection operator, used for error messages.
pub export fn sqlite3SelectOpName(id: c_int) ?[*:0]const u8 {
    return switch (id) {
        TK_ALL => "UNION ALL",
        TK_INTERSECT => "INTERSECT",
        TK_EXCEPT => "EXCEPT",
        else => "UNION",
    };
}

// ── EXPLAIN QUERY PLAN helpers ───────────────────────────────────────────────

/// Unless an "EXPLAIN QUERY PLAN" command is being processed, a no-op.
/// Otherwise adds "USE TEMP B-TREE FOR xxx" to the EQP output.
fn explainTempTable(pParse: Ptr, zUsage: ?[*:0]const u8) void {
    c.sqlite3VdbeExplain(pParse, 0, "USE TEMP B-TREE FOR %s", zUsage);
}

// ── Sort tail ────────────────────────────────────────────────────────────────

/// If the inner loop placed results in a sorter, run the sorter and output the
/// results.  (SORTER_REFERENCES and STMT_SCANSTATUS are OFF, so the deferred-
/// row-load and scanstatus paths are omitted.)
fn generateSortTail(pParse: Ptr, p: Ptr, pSort: Ptr, nColumnIn: c_int, pDest: Ptr) void {
    var nColumn = nColumnIn;
    const v = parseVdbe(pParse);
    const addrBreak = sortLabelDone(pSort);
    const addrContinue = c.sqlite3VdbeMakeLabel(pParse);
    var addr: c_int = undefined;
    var addrOnce: c_int = 0;
    const pOrderBy = sortPOrderBy(pSort);
    const eDest = destEDest(pDest);
    const iParm = destISDParm(pDest);
    var regRow: c_int = undefined;
    var regRowid: c_int = undefined;
    var iCol: c_int = undefined;
    var iSortTab: c_int = undefined;
    var i: c_int = undefined;
    var bSeq: c_int = undefined;
    const nRefKey: c_int = 0;
    const aOutEx = listA(selPEList(p)); // p->pEList->a

    const nKey = listNExpr(pOrderBy) - sortNOBSat(pSort);
    // EQP output (ScanStatus* calls omitted — STMT_SCANSTATUS OFF).
    if (sortNOBSat(pSort) == 0 or nKey == 1) {
        c.sqlite3VdbeExplain(pParse, 0, "USE TEMP B-TREE FOR %sORDER BY", @as(
            ?[*:0]const u8,
            if (sortNOBSat(pSort) != 0) "LAST TERM OF " else "",
        ));
    } else {
        c.sqlite3VdbeExplain(pParse, 0, "USE TEMP B-TREE FOR LAST %d TERMS OF ORDER BY", nKey);
    }

    if (sortLabelBkOut(pSort) != 0) {
        _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, sortRegReturn(pSort), sortLabelBkOut(pSort));
        c.sqlite3VdbeGoto(v, addrBreak);
        c.sqlite3VdbeResolveLabel(v, sortLabelBkOut(pSort));
    }

    const iTab = sortIECursor(pSort);
    if (eDest == SRT_Output or eDest == SRT_Coroutine or eDest == SRT_Mem) {
        if (eDest == SRT_Mem and selIOffset(p) != 0) {
            _ = c.sqlite3VdbeAddOp2(v, OP.Null, 0, destISdst(pDest));
        }
        regRowid = 0;
        regRow = destISdst(pDest);
    } else {
        regRowid = c.sqlite3GetTempReg(pParse);
        if (eDest == SRT_EphemTab or eDest == SRT_Table) {
            regRow = c.sqlite3GetTempReg(pParse);
            nColumn = 0;
        } else {
            regRow = c.sqlite3GetTempRange(pParse, nColumn);
        }
    }
    if ((sortSortFlags(pSort) & SORTFLAG_UseSorter) != 0) {
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
        const regSortOut = rd(c_int, pParse, Parse_nMem);
        iSortTab = rd(c_int, pParse, Parse_nTab);
        wr(c_int, pParse, Parse_nTab, iSortTab + 1);
        if (sortLabelBkOut(pSort) != 0) {
            addrOnce = c.sqlite3VdbeAddOp0(v, OP.Once);
        }
        _ = c.sqlite3VdbeAddOp3(v, OP.OpenPseudo, iSortTab, regSortOut, nKey + 1 + nColumn + nRefKey);
        if (addrOnce != 0) c.sqlite3VdbeJumpHere(v, addrOnce);
        addr = 1 + c.sqlite3VdbeAddOp2(v, OP.SorterSort, iTab, addrBreak);
        _ = c.sqlite3VdbeAddOp3(v, OP.SorterData, iTab, regSortOut, iSortTab);
        bSeq = 0;
    } else {
        addr = 1 + c.sqlite3VdbeAddOp2(v, OP.Sort, iTab, addrBreak);
        // codeOffset(v, p->iOffset, addrContinue)
        if (selIOffset(p) > 0) {
            _ = c.sqlite3VdbeAddOp3(v, OP.IfPos, selIOffset(p), addrContinue, 1);
        }
        iSortTab = iTab;
        bSeq = 1;
        if (selIOffset(p) > 0) {
            _ = c.sqlite3VdbeAddOp2(v, OP.AddImm, selILimit(p), -1);
        }
    }
    i = 0;
    iCol = nKey + bSeq - 1;
    while (i < nColumn) : (i += 1) {
        if (itemIOrderByCol(itemAt(aOutEx, i)) == 0) iCol += 1;
    }
    i = nColumn - 1;
    while (i >= 0) : (i -= 1) {
        const ex = itemAt(aOutEx, i);
        var iRead: c_int = undefined;
        if (itemIOrderByCol(ex) != 0) {
            iRead = @as(c_int, itemIOrderByCol(ex)) - 1;
        } else {
            iRead = iCol;
            iCol -= 1;
        }
        _ = c.sqlite3VdbeAddOp3(v, OP.Column, iSortTab, iRead, regRow + i);
    }
    switch (eDest) {
        SRT_Table, SRT_EphemTab => {
            _ = c.sqlite3VdbeAddOp3(v, OP.Column, iSortTab, nKey + bSeq, regRow);
            _ = c.sqlite3VdbeAddOp2(v, OP.NewRowid, iParm, regRowid);
            _ = c.sqlite3VdbeAddOp3(v, OP.Insert, iParm, regRow, regRowid);
            c.sqlite3VdbeChangeP5(v, OPFLAG_APPEND);
        },
        SRT_Set => {
            _ = c.sqlite3VdbeAddOp4(v, OP.MakeRecord, regRow, nColumn, regRowid, @ptrCast(destZAffSdst(pDest)), nColumn);
            _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm, regRowid, regRow, nColumn);
        },
        SRT_Mem => {
            // The LIMIT clause will terminate the loop for us
        },
        SRT_Upfrom => {
            const iUp2 = destISDParm2(pDest);
            const r1 = c.sqlite3GetTempReg(pParse);
            const adj: c_int = @intFromBool(iUp2 < 0);
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regRow + adj, nColumn - adj, r1);
            if (iUp2 < 0) {
                _ = c.sqlite3VdbeAddOp3(v, OP.Insert, iParm, r1, regRow);
            } else {
                _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm, r1, regRow, iUp2);
            }
        },
        else => {
            // eDest==SRT_Output || eDest==SRT_Coroutine
            if (eDest == SRT_Output) {
                _ = c.sqlite3VdbeAddOp2(v, OP.ResultRow, destISdst(pDest), nColumn);
            } else {
                _ = c.sqlite3VdbeAddOp1(v, OP.Yield, destISDParm(pDest));
            }
        },
    }
    if (regRowid != 0) {
        if (eDest == SRT_Set) {
            c.sqlite3ReleaseTempRange(pParse, regRow, nColumn);
        } else {
            c.sqlite3ReleaseTempReg(pParse, regRow);
        }
        c.sqlite3ReleaseTempReg(pParse, regRowid);
    }
    // The bottom of the loop
    c.sqlite3VdbeResolveLabel(v, addrContinue);
    if ((sortSortFlags(pSort) & SORTFLAG_UseSorter) != 0) {
        _ = c.sqlite3VdbeAddOp2(v, OP.SorterNext, iTab, addr);
    } else {
        _ = c.sqlite3VdbeAddOp2(v, OP.Next, iTab, addr);
    }
    if (sortRegReturn(pSort) != 0) _ = c.sqlite3VdbeAddOp1(v, OP.Return, sortRegReturn(pSort));
    c.sqlite3VdbeResolveLabel(v, addrBreak);
}

// ── Column declaration types ─────────────────────────────────────────────────

/// Return the 'declaration type' of expression pExpr (NULL for non-columns).
/// (SQLITE_ENABLE_COLUMN_METADATA OFF → 2-parameter signature.)
fn columnType(pNCin: Ptr, pExpr: Ptr) ?[*:0]const u8 {
    var pNC = pNCin;
    var zType: ?[*:0]const u8 = null;
    switch (exprOp(pExpr)) {
        TK_COLUMN => {
            var pTab: Ptr = null;
            var pS: Ptr = null;
            const iCol: c_int = exprIColumn(pExpr);
            while (pNC != null and pTab == null) {
                const pTabList = rdp(pNC, NameContext_pSrcList);
                const nSrc = srcNSrc(pTabList);
                var j: c_int = 0;
                while (j < nSrc and itemICursor(srcItemAt(pTabList, j)) != exprITable(pExpr)) : (j += 1) {}
                if (j < nSrc) {
                    const it = srcItemAt(pTabList, j);
                    pTab = itemPTab(it);
                    if (srcHas(it, FG_isSubquery)) {
                        pS = subqPSelect(itemPSubq(it));
                    } else {
                        pS = null;
                    }
                } else {
                    pNC = rdp(pNC, NameContext_pNext);
                }
            }

            // If pTab==0 the column type is left NULL (see C comment).
            if (pTab != null) {
                if (pS != null) {
                    // The "table" is a sub-select or view: return the
                    // declaration type for the relevant result-set column of the
                    // sub-select.  ViewCanHaveRowid is OFF, so the rowid
                    // sub-condition is always true.
                    if (iCol < listNExpr(selPEList(pS))) {
                        var sNC: [sizeof_NameContext]u8 align(8) = undefined;
                        const pSNC: Ptr = @ptrCast(&sNC);
                        const pp = itemExpr(elItem(selPEList(pS), iCol));
                        wr(?*anyopaque, pSNC, NameContext_pSrcList, selPSrc(pS));
                        wr(?*anyopaque, pSNC, NameContext_pNext, pNC);
                        wr(?*anyopaque, pSNC, NameContext_pParse, rdp(pNC, NameContext_pParse));
                        zType = columnType(pSNC, pp);
                    }
                } else {
                    // A real table or a CTE table
                    if (iCol < 0) {
                        zType = "INTEGER";
                    } else {
                        zType = c.sqlite3ColumnType(tabColAt(pTab, iCol), null);
                    }
                }
            }
        },
        TK_SELECT => {
            // The expression is a sub-select: return the declaration type for
            // the single column in its result set.
            const pS = exprPSelect(pExpr);
            const pp = itemExpr(elItem(selPEList(pS), 0));
            var sNC: [sizeof_NameContext]u8 align(8) = undefined;
            const pSNC: Ptr = @ptrCast(&sNC);
            wr(?*anyopaque, pSNC, NameContext_pSrcList, selPSrc(pS));
            wr(?*anyopaque, pSNC, NameContext_pNext, pNC);
            wr(?*anyopaque, pSNC, NameContext_pParse, rdp(pNC, NameContext_pParse));
            zType = columnType(pSNC, pp);
        },
        else => {},
    }
    return zType;
}

/// Generate code telling the VDBE the declaration types of result columns.
/// (SQLITE_OMIT_DECLTYPE / COLUMN_METADATA OFF → only the DECLTYPE branch.)
fn generateColumnTypes(pParse: Ptr, pTabList: Ptr, pEList: Ptr) void {
    const v = parseVdbe(pParse);
    var sNC: [sizeof_NameContext]u8 align(8) = undefined;
    const pNC: Ptr = @ptrCast(&sNC);
    wr(?*anyopaque, pNC, NameContext_pSrcList, pTabList);
    wr(?*anyopaque, pNC, NameContext_pParse, pParse);
    wr(?*anyopaque, pNC, NameContext_pNext, null);
    var i: c_int = 0;
    const n = listNExpr(pEList);
    while (i < n) : (i += 1) {
        const pExpr = itemExpr(elItem(pEList, i));
        const zType = columnType(pNC, pExpr);
        _ = c.sqlite3VdbeSetColName(v, i, COLNAME_DECLTYPE, zType, SQLITE_TRANSIENT);
    }
}

// ── Column names ─────────────────────────────────────────────────────────────

/// Compute the column names for a SELECT statement.
pub export fn sqlite3GenerateColumnNames(pParse: Ptr, pSelectIn: Ptr) void {
    var pSelect = pSelectIn;
    const v = parseVdbe(pParse);
    const db = parseDb(pParse);

    if (parseGetBit(pParse, Parse_bft_byte, Parse_colNamesSet_mask)) return;
    // Column names are determined by the left-most term of a compound select.
    while (selPPrior(pSelect) != null) pSelect = selPPrior(pSelect);
    const pTabList = selPSrc(pSelect);
    const pEList = selPEList(pSelect);
    parseSetBit(pParse, Parse_bft_byte, Parse_colNamesSet_mask);
    const fullName = (dbFlags(db) & SQLITE_FullColNames) != 0;
    const srcName = (dbFlags(db) & SQLITE_ShortColNames) != 0 or fullName;
    const nExpr = listNExpr(pEList);
    c.sqlite3VdbeSetNumCols(v, nExpr);
    var i: c_int = 0;
    while (i < nExpr) : (i += 1) {
        const item = elItem(pEList, i);
        const pExpr = itemExpr(item);
        if (itemZEName(item) != null and itemEEName(item) == ENAME_NAME) {
            // An AS clause always takes first priority.
            _ = c.sqlite3VdbeSetColName(v, i, COLNAME_NAME, @ptrCast(itemZEName(item)), SQLITE_TRANSIENT);
        } else if (srcName and exprOp(pExpr) == TK_COLUMN) {
            var zCol: ?[*:0]const u8 = undefined;
            var iCol: c_int = exprIColumn(pExpr);
            const pTab = exprYTab(pExpr);
            if (iCol < 0) iCol = tabIPKey(pTab);
            if (iCol < 0) {
                zCol = "rowid";
            } else {
                zCol = @ptrCast(colCnName(tabColAt(pTab, iCol)));
            }
            if (fullName) {
                const zName = c.sqlite3MPrintf(db, "%s.%s", tabZName(pTab), zCol);
                _ = c.sqlite3VdbeSetColName(v, i, COLNAME_NAME, @ptrCast(zName), SQLITE_DYNAMIC);
            } else {
                _ = c.sqlite3VdbeSetColName(v, i, COLNAME_NAME, zCol, SQLITE_TRANSIENT);
            }
        } else {
            const zE = itemZEName(item);
            const z: ?[*:0]const u8 = if (zE == null)
                @ptrCast(c.sqlite3MPrintf(db, "column%d", i + 1))
            else
                @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(zE)));
            _ = c.sqlite3VdbeSetColName(v, i, COLNAME_NAME, z, SQLITE_DYNAMIC);
        }
    }
    generateColumnTypes(pParse, pTabList, pEList);
}

/// Given an expression list (the result set of a SELECT), compute appropriate
/// unique column names for a table that would hold the expression list.
pub export fn sqlite3ColumnsFromExprList(pParse: Ptr, pEList: Ptr, pnCol: *i16, paCol: *Ptr) c_int {
    const db = parseDb(pParse);
    var i: c_int = 0;
    var j: c_int = undefined;
    var cnt: u32 = undefined;
    var aCol: Ptr = undefined;
    var pCol: Ptr = undefined;
    var nCol: c_int = undefined;
    var zName: ?[*:0]u8 = undefined;
    var nName: c_int = undefined;
    var ht: [sizeof_Hash]u8 align(8) = undefined;
    const pHt: Ptr = @ptrCast(&ht);
    var pTab: Ptr = undefined;

    c.sqlite3HashInit(pHt);
    if (pEList != null) {
        nCol = listNExpr(pEList);
        aCol = c.sqlite3DbMallocZero(db, @as(u64, sizeof_Column) * @as(u64, @intCast(nCol)));
        if (nCol > 32767) nCol = 32767;
    } else {
        nCol = 0;
        aCol = null;
    }
    pnCol.* = @intCast(nCol);
    paCol.* = aCol;

    pCol = aCol;
    while (i < nCol and parseNErr(pParse) == 0) : (i += 1) {
        const pX = elItem(pEList, i);
        // Get an appropriate name for the column.
        zName = itemZEName(pX);
        if (zName != null and itemEEName(pX) == ENAME_NAME) {
            // "AS <name>" — use <name> as the name.
        } else {
            var pColExpr = c.sqlite3ExprSkipCollateAndLikely(itemExpr(pX));
            while (pColExpr != null and exprOp(pColExpr) == TK_DOT) {
                pColExpr = exprPRight(pColExpr);
            }
            if (exprOp(pColExpr) == TK_COLUMN and exprYTab(pColExpr) != null) {
                // For columns use the column name.
                var iCol: c_int = exprIColumn(pColExpr);
                pTab = exprYTab(pColExpr);
                if (iCol < 0) iCol = tabIPKey(pTab);
                zName = if (iCol >= 0) @ptrCast(colCnName(tabColAt(pTab, iCol))) else @constCast("rowid");
            } else if (exprOp(pColExpr) == TK_ID) {
                zName = @constCast(exprUToken(pColExpr));
            } else {
                // Use the original text of the column expression as its name
                // (zName already == pX->zEName).
            }
        }
        if (zName != null and c.sqlite3IsTrueOrFalse(@ptrCast(zName)) == 0) {
            zName = c.sqlite3DbStrDup(db, @ptrCast(zName));
        } else {
            zName = c.sqlite3MPrintf(db, "column%d", i + 1);
        }

        // Make sure the column name is unique; append an integer if not.
        cnt = 0;
        while (zName != null) {
            const pCollide = c.sqlite3HashFind(pHt, @ptrCast(zName));
            if (pCollide == null) break;
            if (itemBUsingTerm(pCollide)) {
                setColFlags(pCol, colFlags(pCol) | COLFLAG_NOEXPAND);
            }
            nName = c.sqlite3Strlen30(@ptrCast(zName));
            if (nName > 0) {
                const zBytes: [*]u8 = @ptrCast(zName.?);
                j = nName - 1;
                while (j > 0 and c.sqlite3Isdigit(zBytes[@intCast(j)]) != 0) : (j -= 1) {}
                if (zBytes[@intCast(j)] == ':') nName = j;
            }
            cnt += 1;
            zName = c.sqlite3MPrintf(db, "%.*z:%u", nName, zName, cnt);
            c.sqlite3ProgressCheck(pParse);
            if (cnt > 3) {
                c.sqlite3_randomness(@sizeOf(u32), &cnt);
            }
        }
        wr(?*anyopaque, pCol, Column_zCnName, @ptrCast(zName));
        wr(u8, pCol, Column_hName, c.sqlite3StrIHash(@ptrCast(zName)));
        if (itemBNoExpand(pX)) {
            setColFlags(pCol, colFlags(pCol) | COLFLAG_NOEXPAND);
        }
        c.sqlite3ColumnPropertiesFromName(null, pCol);
        if (zName != null and c.sqlite3HashInsert(pHt, @ptrCast(zName), pX) == pX) {
            _ = c.sqlite3OomFault(db);
        }
        pCol = @ptrCast(base(pCol) + sizeof_Column);
    }
    c.sqlite3HashClear(pHt);
    if (parseNErr(pParse) != 0) {
        j = 0;
        while (j < i) : (j += 1) {
            const cj: Ptr = @ptrCast(base(aCol) + @as(usize, @intCast(j)) * sizeof_Column);
            c.sqlite3DbFree(db, colCnName(cj));
        }
        c.sqlite3DbFree(db, aCol);
        paCol.* = null;
        pnCol.* = 0;
        return rd(c_int, pParse, Parse_rc);
    }
    return SQLITE_OK;
}

// ════════════ CLUSTER D ════════════
// ════════════════════════════════════════════════════════════════════════════
// CLUSTER D — subquery column types, result-set table, limits, compound engine.
//
// These function bodies are concatenated into src/select.zig after integration;
// they rely on the scaffold (raw mem helpers, offset consts, inline accessors,
// `c` extern struct, magic constants).  Only items NOT in the scaffold are
// declared locally below.
// ════════════════════════════════════════════════════════════════════════════

// ── Local offset consts not present in the scaffold ──────────────────────────
// (Table_szTabRow already exists in the scaffold; reuse it.)

// PARSE_MODE_RENAME: IN_RENAME_OBJECT == (eParseMode >= PARSE_MODE_RENAME)

// Standard-type tables (util.c / global.c): sqlite3StdType[] & affinity[].
// SQLITE_N_STDTYPE == 6.  Looked up bare via extern arrays.

// ── Externs for symbols defined in OTHER clusters of this module (link-time
// resolved) and a couple of plain C helpers not in the scaffold `c` struct. ──

// Functions defined in sibling clusters (same final module, C ABI).  After
// integration these become ordinary in-module symbols; declared extern here so
// the standalone D.zig type-checks and links.

// The two standard-type lookup arrays (global.c).
extern const sqlite3StdTypeAffinity: [SQLITE_N_STDTYPE]u8;
extern const sqlite3StdType: [SQLITE_N_STDTYPE]?[*:0]const u8;

inline fn collZName(pColl: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(pColl, CollSeq_zName));
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3SubqueryColumnTypes — fill in column type/affinity/collation info for a
// Table that describes the result set of `pSelect`.
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3SubqueryColumnTypes(
    pParse: Ptr,
    pTab: Ptr,
    pSelectIn: Ptr,
    aff: u8,
) void {
    const db = parseDb(pParse);
    if (dbMallocFailed(db) or inRenameObject(pParse)) return;

    var pSelect = pSelectIn;
    while (selPPrior(pSelect)) |prior| pSelect = prior;

    const a = listA(selPEList(pSelect)); // &pSelect->pEList->a[0]

    // NameContext sNC, zeroed; only pSrcList is set.
    var sNC: [sizeof_NameContext]u8 align(8) = undefined;
    const pNC: Ptr = @ptrCast(&sNC);
    _ = c.memset(pNC, 0, sizeof_NameContext);
    wr(?*anyopaque, pNC, NameContext_pSrcList, selPSrc(pSelect));

    const nCol = tabNCol(pTab);
    var i: c_int = 0;
    while (i < nCol) : (i += 1) {
        const pCol = tabColAt(pTab, i);
        var m: c_int = 0;
        var pS2 = pSelect;
        // pTab->tabFlags |= (pCol->colFlags & COLFLAG_NOINSERT);
        setTabTabFlags(pTab, tabTabFlags(pTab) | (colFlags(pCol) & COLFLAG_NOINSERT));
        const p = itemExpr(itemAt(a, i));

        setColAffinity(pCol, c.sqlite3ExprAffinity(p));
        while (colAffinity(pCol) <= SQLITE_AFF_NONE and selPNext(pS2) != null) {
            m |= c.sqlite3ExprDataType(itemExpr(itemAt(listA(selPEList(pS2)), i)));
            pS2 = selPNext(pS2);
            setColAffinity(pCol, c.sqlite3ExprAffinity(itemExpr(itemAt(listA(selPEList(pS2)), i))));
        }
        if (colAffinity(pCol) <= SQLITE_AFF_NONE) {
            setColAffinity(pCol, aff);
        }
        if (colAffinity(pCol) >= SQLITE_AFF_TEXT and (selPNext(pS2) != null or pS2 != pSelect)) {
            pS2 = selPNext(pS2);
            while (pS2 != null) : (pS2 = selPNext(pS2)) {
                m |= c.sqlite3ExprDataType(itemExpr(itemAt(listA(selPEList(pS2)), i)));
            }
            if (colAffinity(pCol) == SQLITE_AFF_TEXT and (m & 0x01) != 0) {
                setColAffinity(pCol, SQLITE_AFF_BLOB);
            } else if (colAffinity(pCol) >= SQLITE_AFF_NUMERIC and (m & 0x02) != 0) {
                setColAffinity(pCol, SQLITE_AFF_BLOB);
            }
            if (colAffinity(pCol) >= SQLITE_AFF_NUMERIC and exprOp(p) == TK_CAST) {
                setColAffinity(pCol, SQLITE_AFF_FLEXNUM);
            }
        }

        var zType: ?[*:0]const u8 = columnType(pNC, p);
        if (zType == null or colAffinity(pCol) != c.sqlite3AffinityType(zType, null)) {
            if (colAffinity(pCol) == SQLITE_AFF_NUMERIC or colAffinity(pCol) == SQLITE_AFF_FLEXNUM) {
                zType = "NUM";
            } else {
                zType = null;
                var j: c_int = 1;
                while (j < SQLITE_N_STDTYPE) : (j += 1) {
                    if (sqlite3StdTypeAffinity[@intCast(j)] == colAffinity(pCol)) {
                        zType = sqlite3StdType[@intCast(j)];
                        break;
                    }
                }
            }
        }
        if (zType) |zt| {
            const k: u64 = c.strlen(zt);
            const zCn = colCnName(pCol);
            const n: u64 = c.strlen(@ptrCast(zCn));
            const pNew = c.sqlite3DbReallocOrFree(db, @ptrCast(zCn), n + k + 2);
            wr(?*anyopaque, pCol, Column_zCnName, pNew);
            setColFlags(pCol, colFlags(pCol) & ~(COLFLAG_HASTYPE | COLFLAG_HASCOLL));
            if (pNew != null) {
                const dst: [*]u8 = @ptrCast(pNew.?);
                _ = c.memcpy(dst + n + 1, @ptrCast(zt), k + 1);
                setColFlags(pCol, colFlags(pCol) | COLFLAG_HASTYPE);
            }
        }
        const pColl = c.sqlite3ExprCollSeq(pParse, p);
        if (pColl != null) {
            c.sqlite3ColumnSetColl(db, pCol, collZName(pColl));
        }
    }
    wr(u8, pTab, Table_szTabRow, 1); // any non-zero value works
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3ResultSetOfSelect — synthesize a Table describing a SELECT's result.
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3ResultSetOfSelect(pParse: Ptr, pSelectIn: Ptr, aff: u8) Ptr {
    const db = parseDb(pParse);

    // pParse->nNestSel++
    wr(c_int, pParse, Parse_nNestSel, rd(c_int, pParse, Parse_nNestSel) + 1);
    if (rd(c_int, pParse, Parse_nNestSel) >= dbLimit(db, SQLITE_LIMIT_EXPR_DEPTH)) {
        c.sqlite3ErrorMsg(pParse, "VIEWs and/or subqueries nested too deep");
        return null;
    }

    const savedFlags = dbFlags(db);
    wr(u64, db, sqlite3_flags, (savedFlags & ~SF_FullColNamesU64()) | SQLITE_ShortColNames);
    sqlite3SelectPrep(pParse, pSelectIn, null);
    wr(u64, db, sqlite3_flags, savedFlags);
    if (parseNErr(pParse) != 0) return null;

    var pSelect = pSelectIn;
    while (selPPrior(pSelect)) |prior| pSelect = prior;

    const pTab = c.sqlite3DbMallocZero(db, @intCast(sizeof_Table));
    if (pTab == null) return null;

    wr(c_int, pTab, Table_nTabRef, 1);
    wr(?*anyopaque, pTab, Table_zName, null);
    wr(i16, pTab, Table_nRowLogEst, 200); // == sqlite3LogEst(1048576)

    const pnCol: *i16 = @ptrCast(@alignCast(fieldPtr(pTab, Table_nCol)));
    const paCol: *Ptr = @ptrCast(@alignCast(fieldPtr(pTab, Table_aCol)));
    _ = sqlite3ColumnsFromExprList(pParse, selPEList(pSelect), pnCol, paCol);
    sqlite3SubqueryColumnTypes(pParse, pTab, pSelect, aff);
    wr(i16, pTab, Table_iPKey, -1);
    if (dbMallocFailed(db)) {
        c.sqlite3DeleteTable(db, pTab);
        return null;
    }
    // pParse->nNestSel--
    wr(c_int, pParse, Parse_nNestSel, rd(c_int, pParse, Parse_nNestSel) - 1);
    return pTab;
}

// SQLITE_FullColNames as a u64 mask (scaffold defines it as u64 already).
inline fn SF_FullColNamesU64() u64 {
    return SQLITE_FullColNames;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3GetVdbe — fetch (or create) the VDBE for the parser context.
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3GetVdbe(pParse: Ptr) Ptr {
    if (parseVdbe(pParse)) |v| return v;
    if (rdp(pParse, Parse_pToplevel) == null and optEnabled(parseDb(pParse), OPT_FactorOutConst)) {
        parseSetBit(pParse, Parse_bft_byte, Parse_okConstFactor_mask);
    }
    return c.sqlite3VdbeCreate(pParse);
}

// ════════════════════════════════════════════════════════════════════════════
// computeLimitRegisters — set up Select.iLimit / iOffset from the LIMIT clause.
// ════════════════════════════════════════════════════════════════════════════
fn computeLimitRegisters(pParse: Ptr, p: Ptr, iBreak: c_int) void {
    var v: Ptr = null;
    var iLimit: c_int = 0;
    var n: c_int = undefined;
    const pLimit = selPLimit(p);

    if (selILimit(p) != 0) return;

    if (pLimit) |pLim| {
        // assert pLimit->op==TK_LIMIT (dropped); pLimit->pLeft!=0
        // pParse->nMem++; iLimit = pParse->nMem
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
        iLimit = rd(c_int, pParse, Parse_nMem);
        setSelILimit(p, iLimit);
        v = sqlite3GetVdbe(pParse);
        if (c.sqlite3ExprIsInteger(exprPLeft(pLim), &n, pParse) != 0) {
            _ = c.sqlite3VdbeAddOp2(v, OP.Integer, n, iLimit);
            if (n == 0) {
                c.sqlite3VdbeGoto(v, iBreak);
            } else if (n >= 0 and selNSelectRow(p) > c.sqlite3LogEst(@intCast(n))) {
                setSelNSelectRow(p, c.sqlite3LogEst(@intCast(n)));
                selSet(p, SF_FixedLimit);
            }
        } else {
            c.sqlite3ExprCode(pParse, exprPLeft(pLim), iLimit);
            _ = c.sqlite3VdbeAddOp1(v, OP.MustBeInt, iLimit);
            _ = c.sqlite3VdbeAddOp2(v, OP.IfNot, iLimit, iBreak);
        }
        if (exprPRight(pLim)) |pRight| {
            // pParse->nMem++; iOffset = pParse->nMem; then nMem++ again.
            wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
            const iOffset = rd(c_int, pParse, Parse_nMem);
            setSelIOffset(p, iOffset);
            wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
            c.sqlite3ExprCode(pParse, pRight, iOffset);
            _ = c.sqlite3VdbeAddOp1(v, OP.MustBeInt, iOffset);
            _ = c.sqlite3VdbeAddOp3(v, OP.OffsetLimit, iLimit, iOffset + 1, iOffset);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// multiSelectCollSeq — collating sequence for column iCol of a compound select.
// ════════════════════════════════════════════════════════════════════════════
fn multiSelectCollSeq(pParse: Ptr, p: Ptr, iCol: c_int) Ptr {
    var pRet: Ptr = null;
    if (selPPrior(p)) |prior| {
        pRet = multiSelectCollSeq(pParse, prior, iCol);
    }
    if (pRet == null and iCol < listNExpr(selPEList(p))) {
        pRet = c.sqlite3ExprCollSeq(pParse, itemExpr(elItem(selPEList(p), iCol)));
    }
    return pRet;
}

// ════════════════════════════════════════════════════════════════════════════
// multiSelectByMergeKeyInfo — KeyInfo for a compound SELECT's ORDER BY.
// ════════════════════════════════════════════════════════════════════════════
fn multiSelectByMergeKeyInfo(pParse: Ptr, p: Ptr, nExtra: c_int) Ptr {
    const pOrderBy = selPOrderBy(p);
    const nOrderBy: c_int = if (pOrderBy != null) listNExpr(pOrderBy) else 0;
    const db = parseDb(pParse);
    const pRet = sqlite3KeyInfoAlloc(db, nOrderBy + nExtra, 1);
    if (pRet) |pKI| {
        var i: c_int = 0;
        while (i < nOrderBy) : (i += 1) {
            const pItem = elItem(pOrderBy, i);
            const pTerm = itemExpr(pItem);
            var pColl: Ptr = undefined;
            if ((exprFlags(pTerm) & EP_Collate) != 0) {
                pColl = c.sqlite3ExprCollSeq(pParse, pTerm);
            } else {
                pColl = multiSelectCollSeq(pParse, p, @as(c_int, itemIOrderByCol(pItem)) - 1);
                if (pColl == null) pColl = rdp(db, sqlite3_pDfltColl);
                setItemExpr(pItem, c.sqlite3ExprAddCollateString(pParse, pTerm, collZName(pColl)));
            }
            kiAColl(pKI)[@intCast(i)] = pColl;
            kiASortFlags(pKI)[@intCast(i)] = itemSortFlags(pItem);
        }
    }
    return pRet;
}

// ════════════════════════════════════════════════════════════════════════════
// generateWithRecursiveQuery — code a WITH RECURSIVE compound SELECT.
// ════════════════════════════════════════════════════════════════════════════
fn generateWithRecursiveQuery(pParse: Ptr, p: Ptr, pDest: Ptr) void {
    const pSrc = selPSrc(p);
    var nCol = listNExpr(selPEList(p));
    const v = parseVdbe(pParse);
    var iCurrent: c_int = 0;
    var iDistinct: c_int = 0;
    var eDest: c_int = SRT_Fifo;
    var destQueueBuf: [sizeof_SelectDest]u8 align(8) = undefined;
    const destQueue: Ptr = @ptrCast(&destQueueBuf);

    // Window functions not allowed in recursive queries.
    if (selPWin(p) != null) {
        c.sqlite3ErrorMsg(pParse, "cannot use window functions in recursive queries");
        return;
    }

    if (c.sqlite3AuthCheck(pParse, SQLITE_RECURSIVE, null, null, null) != 0) return;

    const addrBreak = c.sqlite3VdbeMakeLabel(pParse);
    setSelNSelectRow(p, 320); // 4 billion rows
    computeLimitRegisters(pParse, p, addrBreak);
    const pLimit = selPLimit(p);
    const regLimit = selILimit(p);
    const regOffset = selIOffset(p);
    setSelPLimit(p, null);
    setSelILimit(p, 0);
    setSelIOffset(p, 0);
    var pOrderBy = selPOrderBy(p);

    // Find the cursor number of the Current (recursive) table.
    {
        var i: c_int = 0;
        while (i < srcNSrc(pSrc)) : (i += 1) {
            const it = srcItemAt(pSrc, i);
            if (srcHas(it, FG_isRecursive)) {
                iCurrent = itemICursor(it);
                break;
            }
        }
    }

    // Allocate cursors for Queue and Distinct.
    const iQueue = rd(c_int, pParse, Parse_nTab);
    wr(c_int, pParse, Parse_nTab, iQueue + 1);
    if (selOp(p) == TK_UNION) {
        eDest = if (pOrderBy != null) SRT_DistQueue else SRT_DistFifo;
        iDistinct = rd(c_int, pParse, Parse_nTab);
        wr(c_int, pParse, Parse_nTab, iDistinct + 1);
    } else {
        eDest = if (pOrderBy != null) SRT_Queue else SRT_Fifo;
    }
    sqlite3SelectDestInit(destQueue, eDest, iQueue);

    // regCurrent = ++pParse->nMem
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
    const regCurrent = rd(c_int, pParse, Parse_nMem);
    _ = c.sqlite3VdbeAddOp3(v, OP.OpenPseudo, iCurrent, regCurrent, nCol);
    if (pOrderBy != null) {
        const pKeyInfo = multiSelectByMergeKeyInfo(pParse, p, 1);
        _ = c.sqlite3VdbeAddOp4(v, OP.OpenEphemeral, iQueue, listNExpr(pOrderBy) + 2, 0, @ptrCast(pKeyInfo), P4_KEYINFO);
        setDestPOrderBy(destQueue, pOrderBy);
    } else {
        _ = c.sqlite3VdbeAddOp2(v, OP.OpenEphemeral, iQueue, nCol);
    }
    if (iDistinct != 0) {
        // assert p->pNext==0 && p->pEList!=0 (dropped)
        nCol = listNExpr(selPEList(p));
        const pKeyInfo = sqlite3KeyInfoAlloc(parseDb(pParse), nCol, 1);
        if (pKeyInfo) |pKI| {
            const apColl = kiAColl(pKI);
            var i: c_int = 0;
            while (i < nCol) : (i += 1) {
                var pc = multiSelectCollSeq(pParse, p, i);
                if (pc == null) pc = rdp(parseDb(pParse), sqlite3_pDfltColl);
                apColl[@intCast(i)] = pc;
            }
            _ = c.sqlite3VdbeAddOp4(v, OP.OpenEphemeral, iDistinct, nCol, 0, @ptrCast(pKI), P4_KEYINFO);
        }
        // else: assert pParse->nErr>0 (dropped)
    }

    // Detach the ORDER BY clause from the compound SELECT.
    setSelPOrderBy(p, null);

    // Figure out which elements are part of the recursive query.
    var pFirstRec = p;
    while (true) {
        if (selHas(pFirstRec, SF_Aggregate)) {
            c.sqlite3ErrorMsg(pParse, "recursive aggregate queries not supported");
            // goto end_of_recursive_query
            c.sqlite3ExprListDelete(parseDb(pParse), selPOrderBy(p));
            setSelPOrderBy(p, pOrderBy);
            setSelPLimit(p, pLimit);
            return;
        }
        setSelOp(pFirstRec, TK_ALL);
        const prior = selPPrior(pFirstRec);
        if ((selFlags(prior) & SF_Recursive) == 0) break;
        pFirstRec = prior;
    }

    // Store the results of the setup-query in Queue.
    const pSetup = selPPrior(pFirstRec);
    setSelPNext(pSetup, null);
    c.sqlite3VdbeExplain(pParse, 1, "SETUP");
    const rc = sqlite3Select(pParse, pSetup, destQueue);
    setSelPNext(pSetup, p);
    if (rc != 0) {
        c.sqlite3ExprListDelete(parseDb(pParse), selPOrderBy(p));
        setSelPOrderBy(p, pOrderBy);
        setSelPLimit(p, pLimit);
        return;
    }

    // Find the next row in the Queue and output it.
    const addrTop = c.sqlite3VdbeAddOp2(v, OP.Rewind, iQueue, addrBreak);

    // Transfer the next row in Queue over to Current.
    _ = c.sqlite3VdbeAddOp1(v, OP.NullRow, iCurrent);
    if (pOrderBy != null) {
        _ = c.sqlite3VdbeAddOp3(v, OP.Column, iQueue, listNExpr(pOrderBy) + 1, regCurrent);
    } else {
        _ = c.sqlite3VdbeAddOp2(v, OP.RowData, iQueue, regCurrent);
    }
    _ = c.sqlite3VdbeAddOp1(v, OP.Delete, iQueue);

    // Output the single row in Current.
    const addrCont = c.sqlite3VdbeMakeLabel(pParse);
    codeOffset(v, regOffset, addrCont);
    selectInnerLoop(pParse, p, iCurrent, @as(?*SortCtx, null), @as(?*DistinctCtx, null), pDest, addrCont, addrBreak);
    if (regLimit != 0) {
        _ = c.sqlite3VdbeAddOp2(v, OP.DecrJumpZero, regLimit, addrBreak);
    }
    c.sqlite3VdbeResolveLabel(v, addrCont);

    // Execute the recursive SELECT.
    setSelPPrior(pFirstRec, null);
    c.sqlite3VdbeExplain(pParse, 1, "RECURSIVE STEP");
    _ = sqlite3Select(pParse, p, destQueue);
    setSelPPrior(pFirstRec, pSetup);

    // Keep running until the Queue is empty.
    c.sqlite3VdbeGoto(v, addrTop);
    c.sqlite3VdbeResolveLabel(v, addrBreak);

    // end_of_recursive_query:
    c.sqlite3ExprListDelete(parseDb(pParse), selPOrderBy(p));
    setSelPOrderBy(p, pOrderBy);
    setSelPLimit(p, pLimit);
    _ = &pOrderBy;
}

// ════════════════════════════════════════════════════════════════════════════
// multiSelectValues — compound select originating from a VALUES clause.
// ════════════════════════════════════════════════════════════════════════════
fn multiSelectValues(pParse: Ptr, pIn: Ptr, pDest: Ptr) c_int {
    var nRow: c_int = 1;
    const rc: c_int = 0;
    const bShowAll: c_int = if (selPLimit(pIn) == null) 1 else 0;
    var p = pIn;
    // assert SF_MultiValue / SF_Values (dropped)
    while (true) {
        if (selPWin(p) != null) return -1;
        if (selPPrior(p) == null) break;
        p = selPPrior(p);
        nRow += bShowAll;
    }
    c.sqlite3VdbeExplain(pParse, 0, "SCAN %d CONSTANT ROW%s", nRow, if (nRow == 1) @as([*:0]const u8, "") else @as([*:0]const u8, "S"));
    while (p != null) {
        selectInnerLoop(pParse, p, -1, @as(?*SortCtx, null), @as(?*DistinctCtx, null), pDest, 1, 1);
        if (bShowAll == 0) break;
        setSelNSelectRow(p, @intCast(nRow));
        p = selPNext(p);
    }
    return rc;
}

// ════════════════════════════════════════════════════════════════════════════
// hasAnchor — does the recursive part of a CTE still have its anchor terms?
// ════════════════════════════════════════════════════════════════════════════
fn hasAnchor(pIn: Ptr) c_int {
    var p = pIn;
    while (p != null and (selFlags(p) & SF_Recursive) != 0) {
        p = selPPrior(p);
    }
    return if (p != null) 1 else 0;
}

// ════════════════════════════════════════════════════════════════════════════
// multiSelect — code a compound SELECT (UNION / UNION ALL / EXCEPT / INTERSECT).
// ════════════════════════════════════════════════════════════════════════════
fn multiSelect(pParse: Ptr, p: Ptr, pDest: Ptr) c_int {
    var rc: c_int = SQLITE_OK;
    var pDelete: Ptr = null;
    const db = parseDb(pParse);
    const pPrior = selPPrior(p);

    // dest = *pDest  (copy 40 bytes onto the stack)
    var destBuf: [sizeof_SelectDest]u8 align(8) = undefined;
    const dest: Ptr = @ptrCast(&destBuf);
    _ = c.memcpy(dest, pDest, sizeof_SelectDest);

    const v = sqlite3GetVdbe(pParse);

    // Create the destination temporary table if necessary.
    if (destEDest(dest) == SRT_EphemTab) {
        _ = c.sqlite3VdbeAddOp2(v, OP.OpenEphemeral, destISDParm(dest), listNExpr(selPEList(p)));
        setDestEDest(dest, SRT_Table);
    }

    // VALUES-originated compound select.
    if (selHas(p, SF_MultiValue)) {
        rc = multiSelectValues(pParse, p, dest);
        if (rc >= 0) {
            // goto multi_select_end
            return multiSelectEnd(pParse, p, pDest, dest, pDelete, rc);
        }
        rc = SQLITE_OK;
    }

    if ((selFlags(p) & SF_Recursive) != 0 and hasAnchor(p) != 0) {
        generateWithRecursiveQuery(pParse, p, dest);
    } else if (selPOrderBy(p) != null) {
        // Compound with ORDER BY: always merge.
        return multiSelectByMerge(pParse, p, pDest);
    } else if (selOp(p) != TK_ALL) {
        // EXCEPT / INTERSECT / UNION: invent an ORDER BY, then merge.
        const pOne = c.sqlite3ExprInt32(db, 1);
        setSelPOrderBy(p, c.sqlite3ExprListAppend(pParse, null, pOne));
        if (parseNErr(pParse) != 0) {
            return multiSelectEnd(pParse, p, pDest, dest, pDelete, rc);
        }
        setItemIOrderByCol(elItem(selPOrderBy(p), 0), 1);
        return multiSelectByMerge(pParse, p, pDest);
    } else {
        // UNION ALL without ORDER BY: run left query, then right query.
        var addr: c_int = 0;
        var nLimit: c_int = 0;

        if (selPPrior(pPrior) == null) {
            c.sqlite3VdbeExplain(pParse, 1, "COMPOUND QUERY");
            c.sqlite3VdbeExplain(pParse, 1, "LEFT-MOST SUBQUERY");
        }
        setSelILimit(pPrior, selILimit(p));
        setSelIOffset(pPrior, selIOffset(p));
        setSelPLimit(pPrior, c.sqlite3ExprDup(db, selPLimit(p), 0));
        rc = sqlite3Select(pParse, pPrior, dest);
        c.sqlite3ExprDelete(db, selPLimit(pPrior));
        setSelPLimit(pPrior, null);
        if (rc != 0) {
            return multiSelectEnd(pParse, p, pDest, dest, pDelete, rc);
        }
        setSelPPrior(p, null);
        setSelILimit(p, selILimit(pPrior));
        setSelIOffset(p, selIOffset(pPrior));
        if (selILimit(p) != 0) {
            addr = c.sqlite3VdbeAddOp1(v, OP.IfNot, selILimit(p));
            if (selIOffset(p) != 0) {
                _ = c.sqlite3VdbeAddOp3(v, OP.OffsetLimit, selILimit(p), selIOffset(p) + 1, selIOffset(p));
            }
        }
        c.sqlite3VdbeExplain(pParse, 1, "UNION ALL");
        rc = sqlite3Select(pParse, p, dest);
        pDelete = selPPrior(p);
        setSelPPrior(p, pPrior);
        setSelNSelectRow(p, c.sqlite3LogEstAdd(selNSelectRow(p), selNSelectRow(pPrior)));
        if (selPLimit(p) != null and
            c.sqlite3ExprIsInteger(exprPLeft(selPLimit(p)), &nLimit, pParse) != 0 and
            nLimit > 0 and selNSelectRow(p) > c.sqlite3LogEst(@intCast(nLimit)))
        {
            setSelNSelectRow(p, c.sqlite3LogEst(@intCast(nLimit)));
        }
        if (addr != 0) {
            c.sqlite3VdbeJumpHere(v, addr);
        }
        if (selPNext(p) == null) {
            c.sqlite3VdbeExplainPop(pParse);
        }
    }

    return multiSelectEnd(pParse, p, pDest, dest, pDelete, rc);
}

// Shared `multi_select_end:` tail of multiSelect.
inline fn multiSelectEnd(pParse: Ptr, p: Ptr, pDest: Ptr, dest: Ptr, pDelete: Ptr, rc: c_int) c_int {
    _ = p;
    setDestISdst(pDest, destISdst(dest));
    setDestNSdst(pDest, destNSdst(dest));
    setDestISDParm2(pDest, destISDParm2(dest));
    if (pDelete != null) {
        _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&sqlite3SelectDeleteGeneric)), pDelete);
    }
    return rc;
}

// ════════════ CLUSTER E ════════════
// ════════════════════════════════════════════════════════════════════════════
// CLUSTER E — merge engine, query flattener, optimizers, CTE resolver, expander.
// These definitions are concatenated into src/select.zig and therefore reuse all
// of the scaffold's constants, offset consts, inline accessors and the `c`
// extern struct.  Only declarations that the scaffold does NOT already provide
// appear below (extra extern fns, two local structs, a handful of offsets, and
// one cleanup wrapper).
// ════════════════════════════════════════════════════════════════════════════

// ── Extra extern fns referenced by this cluster but not in the `c` struct ────
// (sqlite3SelectDup, sqlite3VdbeExplainPop; plus the bare-named functions that
//  live in sibling part files — all have C ABI so an extern decl resolves them
//  whether linked or concatenated.)
// cluster A statics/exports (bare names)
// cluster C export, cluster D statics, cluster F export (bare names)

// ── Offsets not present in the scaffold (probe-verified against sqliteInt.h) ──

// ── Local stack structs (LOCAL to select.c; mirror C layout exactly) ─────────
pub const SubstContext = extern struct {
    pParse: Ptr,
    iTable: c_int,
    iNewTable: c_int,
    isOuterJoin: c_int,
    nSelDepth: c_int,
    pEList: Ptr,
    pCList: Ptr,
};

pub const WhereConst = extern struct {
    pParse: Ptr,
    pOomFault: ?*u8,
    nConst: c_int,
    nChng: c_int,
    bHasAffBlob: c_int,
    mExcludeOn: u32,
    apExpr: ?*?*anyopaque,
};

// ── tiny helpers local to this cluster ───────────────────────────────────────
// Cleanup wrapper so we can pass sqlite3DbFree's address to AddCleanup.
fn cleanupDbFree(db: Ptr, p: Ptr) callconv(.c) void {
    c.sqlite3DbFree(db, p);
}

// codeOffset() lives in cluster D; replicate it locally (it is a trivial static
// helper and several cluster-E functions need it).

// ════════════════════════════════════════════════════════════════════════════
// sqlite3SelectWrongNumTermsError (export)
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3SelectWrongNumTermsError(pParse: Ptr, p: Ptr) void {
    if ((selFlags(p) & SF_Values) != 0) {
        c.sqlite3ErrorMsg(pParse, "all VALUES must have the same number of terms");
    } else {
        c.sqlite3ErrorMsg(pParse, "SELECTs to the left and right of %s do not have the same number of result columns", sqlite3SelectOpName(selOp(p)));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// generateOutputSubroutine (static)
// ════════════════════════════════════════════════════════════════════════════
fn generateOutputSubroutine(
    pParse: Ptr,
    p: Ptr,
    pIn: Ptr,
    pDest: Ptr,
    regReturn: c_int,
    regPrev: c_int,
    pKeyInfo: Ptr,
    iBreak: c_int,
) c_int {
    const v = parseVdbe(pParse);
    var iContinue: c_int = undefined;
    var addr: c_int = undefined;

    addr = c.sqlite3VdbeCurrentAddr(v);
    iContinue = c.sqlite3VdbeMakeLabel(pParse);

    // Suppress duplicates for UNION, EXCEPT, and INTERSECT
    if (regPrev != 0) {
        const addr1 = c.sqlite3VdbeAddOp1(v, OP.IfNot, regPrev);
        const addr2 = c.sqlite3VdbeAddOp4(v, OP.Compare, destISdst(pIn), regPrev + 1, destNSdst(pIn), @ptrCast(sqlite3KeyInfoRef(pKeyInfo)), P4_KEYINFO);
        _ = c.sqlite3VdbeAddOp3(v, OP.Jump, addr2 + 2, iContinue, addr2 + 2);
        c.sqlite3VdbeJumpHere(v, addr1);
        _ = c.sqlite3VdbeAddOp3(v, OP.Copy, destISdst(pIn), regPrev + 1, destNSdst(pIn) - 1);
        _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 1, regPrev);
    }
    if (dbMallocFailed(parseDb(pParse))) return 0;

    // Suppress the first OFFSET entries if there is an OFFSET clause
    codeOffset(v, selIOffset(p), iContinue);

    switch (destEDest(pDest)) {
        SRT_Fifo, SRT_DistFifo, SRT_Table, SRT_EphemTab => {
            const r1 = c.sqlite3GetTempReg(pParse);
            const r2 = c.sqlite3GetTempReg(pParse);
            const iParm = destISDParm(pDest);
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, destISdst(pIn), destNSdst(pIn), r1);
            if (destEDest(pDest) == SRT_DistFifo) {
                _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm + 1, r1, destISdst(pIn), destNSdst(pIn));
            }
            _ = c.sqlite3VdbeAddOp2(v, OP.NewRowid, iParm, r2);
            _ = c.sqlite3VdbeAddOp3(v, OP.Insert, iParm, r1, r2);
            c.sqlite3VdbeChangeP5(v, OPFLAG_APPEND);
            c.sqlite3ReleaseTempReg(pParse, r2);
            c.sqlite3ReleaseTempReg(pParse, r1);
        },

        SRT_Exists => {
            _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 1, destISDParm(pDest));
        },

        SRT_Set => {
            const r1 = c.sqlite3GetTempReg(pParse);
            _ = c.sqlite3VdbeAddOp4(v, OP.MakeRecord, destISdst(pIn), destNSdst(pIn), r1, @ptrCast(destZAffSdst(pDest)), destNSdst(pIn));
            _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, destISDParm(pDest), r1, destISdst(pIn), destNSdst(pIn));
            if (destISDParm2(pDest) > 0) {
                _ = c.sqlite3VdbeAddOp4Int(v, OP.FilterAdd, destISDParm2(pDest), 0, destISdst(pIn), destNSdst(pIn));
                c.sqlite3VdbeExplain(pParse, 0, "CREATE BLOOM FILTER");
            }
            c.sqlite3ReleaseTempReg(pParse, r1);
        },

        SRT_Mem => {
            c.sqlite3ExprCodeMove(pParse, destISdst(pIn), destISDParm(pDest), destNSdst(pIn));
        },

        SRT_Coroutine => {
            if (destISdst(pDest) == 0) {
                setDestISdst(pDest, c.sqlite3GetTempRange(pParse, destNSdst(pIn)));
                setDestNSdst(pDest, destNSdst(pIn));
            }
            c.sqlite3ExprCodeMove(pParse, destISdst(pIn), destISdst(pDest), destNSdst(pIn));
            _ = c.sqlite3VdbeAddOp1(v, OP.Yield, destISDParm(pDest));
        },

        SRT_DistQueue, SRT_Queue => {
            const iParm = destISDParm(pDest);
            const pSO = destPOrderBy(pDest);
            const nKey = listNExpr(pSO);
            const r1 = c.sqlite3GetTempReg(pParse);
            const r2 = c.sqlite3GetTempRange(pParse, nKey + 2);
            const r3 = r2 + nKey + 1;

            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, destISdst(pIn), destNSdst(pIn), r3);
            if (destEDest(pDest) == SRT_DistQueue) {
                _ = c.sqlite3VdbeAddOp2(v, OP.IdxInsert, iParm + 1, r3);
            }
            var ii: c_int = 0;
            while (ii < nKey) : (ii += 1) {
                _ = c.sqlite3VdbeAddOp2(v, OP.SCopy, destISdst(pIn) + @as(c_int, @intCast(itemIOrderByCol(elItem(pSO, ii)))) - 1, r2 + ii);
            }
            _ = c.sqlite3VdbeAddOp2(v, OP.Sequence, iParm, r2 + nKey);
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, r2, nKey + 2, r1);
            _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iParm, r1, r2, nKey + 2);
            c.sqlite3ReleaseTempReg(pParse, r1);
            c.sqlite3ReleaseTempRange(pParse, r2, nKey + 2);
        },

        SRT_Discard => {},

        else => {
            _ = c.sqlite3VdbeAddOp2(v, OP.ResultRow, destISdst(pIn), destNSdst(pIn));
        },
    }

    // Jump to the end of the loop if the LIMIT is reached.
    if (selILimit(p) != 0) {
        _ = c.sqlite3VdbeAddOp2(v, OP.DecrJumpZero, selILimit(p), iBreak);
    }

    // Generate the subroutine return
    c.sqlite3VdbeResolveLabel(v, iContinue);
    _ = c.sqlite3VdbeAddOp1(v, OP.Return, regReturn);

    return addr;
}

// ════════════════════════════════════════════════════════════════════════════
// multiSelectByMerge (static)
// ════════════════════════════════════════════════════════════════════════════
fn multiSelectByMerge(pParse: Ptr, p: Ptr, pDest: Ptr) c_int {
    var i: c_int = undefined;
    var j: c_int = undefined;
    var pPrior: Ptr = undefined;
    var pSplit: Ptr = undefined;
    var nSelect: c_int = undefined;
    const v = parseVdbe(pParse);
    var destA_buf: [sizeof_SelectDest]u8 align(8) = undefined;
    var destB_buf: [sizeof_SelectDest]u8 align(8) = undefined;
    const destA: Ptr = @ptrCast(&destA_buf);
    const destB: Ptr = @ptrCast(&destB_buf);
    var regAddrA: c_int = undefined;
    var regAddrB: c_int = undefined;
    var addrSelectA: c_int = undefined;
    var addrSelectB: c_int = undefined;
    var regOutA: c_int = undefined;
    var regOutB: c_int = undefined;
    var addrOutA: c_int = undefined;
    var addrOutB: c_int = 0;
    var addrEofA: c_int = undefined;
    var addrEofA_noB: c_int = undefined;
    var addrEofB: c_int = undefined;
    var addrAltB: c_int = undefined;
    var addrAeqB: c_int = undefined;
    var addrAgtB: c_int = undefined;
    var regLimitA: c_int = undefined;
    var regLimitB: c_int = undefined;
    var regPrev: c_int = undefined;
    var savedLimit: c_int = undefined;
    var savedOffset: c_int = undefined;
    var labelCmpr: c_int = undefined;
    var labelEnd: c_int = undefined;
    var addr1: c_int = undefined;
    var op: c_int = undefined;
    var pKeyDup: Ptr = null;
    var pKeyMerge: Ptr = undefined;
    const db = parseDb(pParse);
    var pOrderBy: Ptr = undefined;
    var nOrderBy: c_int = undefined;
    var aPermute: ?[*]u32 = null;

    labelEnd = c.sqlite3VdbeMakeLabel(pParse);
    labelCmpr = c.sqlite3VdbeMakeLabel(pParse);

    // Patch up the ORDER BY clause
    op = selOp(p);
    pOrderBy = selPOrderBy(p);
    nOrderBy = listNExpr(pOrderBy);

    // For operators other than UNION ALL we have to make sure that the ORDER BY
    // clause covers every term of the result set.
    if (op != TK_ALL) {
        i = 1;
        while (!dbMallocFailed(db) and i <= listNExpr(selPEList(p))) : (i += 1) {
            j = 0;
            var pItem = listA(pOrderBy);
            while (j < nOrderBy) : (j += 1) {
                if (@as(c_int, @intCast(itemIOrderByCol(pItem))) == i) break;
                pItem = @ptrCast(base(pItem) + sizeof_ExprList_item);
            }
            if (j == nOrderBy) {
                const pNew = c.sqlite3ExprInt32(db, i);
                if (pNew == null) return SQLITE_NOMEM;
                pOrderBy = c.sqlite3ExprListAppend(pParse, pOrderBy, pNew);
                setSelPOrderBy(p, pOrderBy);
                if (pOrderBy != null) {
                    setItemIOrderByCol(elItem(pOrderBy, nOrderBy), @intCast(i));
                    nOrderBy += 1;
                }
            }
        }
    }

    // Compute the comparison permutation and keyinfo.
    aPermute = @ptrCast(@alignCast(c.sqlite3DbMallocRawNN(db, @sizeOf(u32) * @as(u64, @intCast(nOrderBy + 1)))));
    if (aPermute) |ap| {
        var bKeep: c_int = 0;
        ap[0] = @intCast(nOrderBy);
        i = 1;
        var pItem = listA(pOrderBy);
        while (i <= nOrderBy) : (i += 1) {
            ap[@intCast(i)] = @intCast(@as(c_int, @intCast(itemIOrderByCol(pItem))) - 1);
            if (ap[@intCast(i)] != @as(u32, @intCast(i - 1))) bKeep = 1;
            pItem = @ptrCast(base(pItem) + sizeof_ExprList_item);
        }
        if (bKeep == 0) {
            c.sqlite3DbFreeNN(db, @ptrCast(ap));
            aPermute = null;
        }
    }
    pKeyMerge = multiSelectByMergeKeyInfo(pParse, p, 1);

    // Allocate temp registers + KeyInfo for duplicate removal (UNION/EXCEPT/
    // INTERSECT, but not UNION ALL).
    if (op == TK_ALL) {
        regPrev = 0;
    } else {
        const nExpr = listNExpr(selPEList(p));
        regPrev = rd(c_int, pParse, Parse_nMem) + 1;
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + nExpr + 1);
        _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 0, regPrev);
        pKeyDup = sqlite3KeyInfoAlloc(db, nExpr, 1);
        if (pKeyDup != null) {
            const aColl = kiAColl(pKeyDup);
            const aSortFlags = kiASortFlags(pKeyDup);
            i = 0;
            while (i < nExpr) : (i += 1) {
                aColl[@intCast(i)] = multiSelectCollSeq(pParse, p, i);
                aSortFlags[@intCast(i)] = 0;
            }
        }
    }

    // Separate the left and the right query from one another
    nSelect = 1;
    if ((op == TK_ALL or op == TK_UNION) and optEnabled(db, OPT_BalancedMerge)) {
        pSplit = p;
        while (selPPrior(pSplit) != null and selOp(pSplit) == op) {
            nSelect += 1;
            pSplit = selPPrior(pSplit);
        }
    }
    if (nSelect <= 3) {
        pSplit = p;
    } else {
        pSplit = p;
        i = 2;
        while (i < nSelect) : (i += 2) {
            pSplit = selPPrior(pSplit);
        }
    }
    pPrior = selPPrior(pSplit);
    setSelPPrior(pSplit, null);
    setSelPNext(pPrior, null);
    setSelPOrderBy(pPrior, c.sqlite3ExprListDup(parseDb(pParse), pOrderBy, 0));
    _ = c.sqlite3ResolveOrderGroupBy(pParse, p, selPOrderBy(p), "ORDER");
    _ = c.sqlite3ResolveOrderGroupBy(pParse, pPrior, selPOrderBy(pPrior), "ORDER");

    // Compute the limit registers
    computeLimitRegisters(pParse, p, labelEnd);
    if (selILimit(p) != 0 and op == TK_ALL) {
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
        regLimitA = rd(c_int, pParse, Parse_nMem);
        wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
        regLimitB = rd(c_int, pParse, Parse_nMem);
        _ = c.sqlite3VdbeAddOp2(v, OP.Copy, if (selIOffset(p) != 0) selIOffset(p) + 1 else selILimit(p), regLimitA);
        _ = c.sqlite3VdbeAddOp2(v, OP.Copy, regLimitA, regLimitB);
    } else {
        regLimitA = 0;
        regLimitB = 0;
    }
    c.sqlite3ExprDelete(db, selPLimit(p));
    setSelPLimit(p, null);

    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
    regAddrA = rd(c_int, pParse, Parse_nMem);
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
    regAddrB = rd(c_int, pParse, Parse_nMem);
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
    regOutA = rd(c_int, pParse, Parse_nMem);
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
    regOutB = rd(c_int, pParse, Parse_nMem);
    sqlite3SelectDestInit(destA, SRT_Coroutine, regAddrA);
    sqlite3SelectDestInit(destB, SRT_Coroutine, regAddrB);

    c.sqlite3VdbeExplain(pParse, 1, "MERGE (%s)", sqlite3SelectOpName(selOp(p)));

    // Coroutine for the "A" select (left of the compound operator).
    addrSelectA = c.sqlite3VdbeCurrentAddr(v) + 1;
    addr1 = c.sqlite3VdbeAddOp3(v, OP.InitCoroutine, regAddrA, 0, addrSelectA);
    setSelILimit(pPrior, regLimitA);
    c.sqlite3VdbeExplain(pParse, 1, "LEFT");
    _ = sqlite3Select(pParse, pPrior, destA);
    c.sqlite3VdbeEndCoroutine(v, regAddrA);
    c.sqlite3VdbeJumpHere(v, addr1);

    // Coroutine for the "B" select (right of the compound operator).
    addrSelectB = c.sqlite3VdbeCurrentAddr(v) + 1;
    addr1 = c.sqlite3VdbeAddOp3(v, OP.InitCoroutine, regAddrB, 0, addrSelectB);
    savedLimit = selILimit(p);
    savedOffset = selIOffset(p);
    setSelILimit(p, regLimitB);
    setSelIOffset(p, 0);
    c.sqlite3VdbeExplain(pParse, 1, "RIGHT");
    _ = sqlite3Select(pParse, p, destB);
    setSelILimit(p, savedLimit);
    setSelIOffset(p, savedOffset);
    c.sqlite3VdbeEndCoroutine(v, regAddrB);

    // Output-A subroutine.
    addrOutA = generateOutputSubroutine(pParse, p, destA, pDest, regOutA, regPrev, pKeyDup, labelEnd);

    // Output-B subroutine (UNION and UNION ALL only).
    if (op == TK_ALL or op == TK_UNION) {
        addrOutB = generateOutputSubroutine(pParse, p, destB, pDest, regOutB, regPrev, pKeyDup, labelEnd);
    }
    sqlite3KeyInfoUnref(pKeyDup);

    // Subroutine for when select A is exhausted.
    if (op == TK_EXCEPT or op == TK_INTERSECT) {
        addrEofA = labelEnd;
        addrEofA_noB = labelEnd;
    } else {
        addrEofA = c.sqlite3VdbeAddOp2(v, OP.Gosub, regOutB, addrOutB);
        addrEofA_noB = c.sqlite3VdbeAddOp2(v, OP.Yield, regAddrB, labelEnd);
        c.sqlite3VdbeGoto(v, addrEofA);
        setSelNSelectRow(p, c.sqlite3LogEstAdd(selNSelectRow(p), selNSelectRow(pPrior)));
    }

    // Subroutine for when select B is exhausted.
    if (op == TK_INTERSECT) {
        addrEofB = addrEofA;
        if (selNSelectRow(p) > selNSelectRow(pPrior)) setSelNSelectRow(p, selNSelectRow(pPrior));
    } else {
        addrEofB = c.sqlite3VdbeAddOp2(v, OP.Gosub, regOutA, addrOutA);
        _ = c.sqlite3VdbeAddOp2(v, OP.Yield, regAddrA, labelEnd);
        c.sqlite3VdbeGoto(v, addrEofB);
    }

    // Handle the case of A<B
    addrAltB = c.sqlite3VdbeAddOp2(v, OP.Gosub, regOutA, addrOutA);
    _ = c.sqlite3VdbeAddOp2(v, OP.Yield, regAddrA, addrEofA);
    c.sqlite3VdbeGoto(v, labelCmpr);

    // Handle the case of A==B
    if (op == TK_ALL) {
        addrAeqB = addrAltB;
    } else if (op == TK_INTERSECT) {
        addrAeqB = addrAltB;
        addrAltB += 1;
    } else {
        addrAeqB = addrAltB + 1;
    }

    // Handle the case of A>B
    addrAgtB = c.sqlite3VdbeCurrentAddr(v);
    if (op == TK_ALL or op == TK_UNION) {
        _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, regOutB, addrOutB);
        _ = c.sqlite3VdbeAddOp2(v, OP.Yield, regAddrB, addrEofB);
        c.sqlite3VdbeGoto(v, labelCmpr);
    } else {
        addrAgtB += 1;
    }

    // This code runs once to initialize everything.
    c.sqlite3VdbeJumpHere(v, addr1);
    _ = c.sqlite3VdbeAddOp2(v, OP.Yield, regAddrA, addrEofA_noB);
    _ = c.sqlite3VdbeAddOp2(v, OP.Yield, regAddrB, addrEofB);

    // Implement the main merge loop
    if (aPermute) |ap| {
        _ = c.sqlite3VdbeAddOp4(v, OP.Permutation, 0, 0, 0, @ptrCast(ap), P4_INTARRAY);
    }
    c.sqlite3VdbeResolveLabel(v, labelCmpr);
    _ = c.sqlite3VdbeAddOp4(v, OP.Compare, destISdst(destA), destISdst(destB), nOrderBy, @ptrCast(pKeyMerge), P4_KEYINFO);
    if (aPermute != null) {
        c.sqlite3VdbeChangeP5(v, OPFLAG_PERMUTE);
    }
    _ = c.sqlite3VdbeAddOp3(v, OP.Jump, addrAltB, addrAeqB, addrAgtB);

    // Jump to the this point in order to terminate the query.
    c.sqlite3VdbeResolveLabel(v, labelEnd);

    // Free the 2nd and subsequent arms after the parse has finished.
    if (selPPrior(pSplit) != null) {
        _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&sqlite3SelectDeleteGeneric)), selPPrior(pSplit));
    }
    setSelPPrior(pSplit, pPrior);
    setSelPNext(pPrior, pSplit);
    c.sqlite3ExprListDelete(db, selPOrderBy(pPrior));
    setSelPOrderBy(pPrior, null);

    c.sqlite3VdbeExplainPop(pParse);
    return @intFromBool(parseNErr(pParse) != 0);
}

// ════════════════════════════════════════════════════════════════════════════
// substExpr / substExprList / substSelect (static)
// ════════════════════════════════════════════════════════════════════════════
fn substExpr(pSubst: *SubstContext, pExprIn: Ptr) Ptr {
    var pExpr = pExprIn;
    if (pExpr == null) return null;
    if (hasProp(pExpr, EP_OuterON | EP_InnerON) and exprWJoin(pExpr) == pSubst.iTable) {
        setExprWJoin(pExpr, pSubst.iNewTable);
    }
    if (exprOp(pExpr) == TK_COLUMN and exprITable(pExpr) == pSubst.iTable and !hasProp(pExpr, EP_FixedCol)) {
        const iColumn = exprIColumn(pExpr);
        var pCopy = itemExpr(elItem(pSubst.pEList, iColumn));
        if (c.sqlite3ExprIsVector(pCopy) != 0) {
            c.sqlite3VectorErrorMsg(pSubst.pParse, pCopy);
        } else {
            const db = parseDb(pSubst.pParse);
            var ifNullRow: [sizeof_Expr]u8 align(8) = undefined;
            const pIfNullRow: Ptr = @ptrCast(&ifNullRow);
            if (pSubst.isOuterJoin != 0 and (exprOp(pCopy) != TK_COLUMN or exprITable(pCopy) != pSubst.iNewTable)) {
                _ = c.memset(pIfNullRow, 0, sizeof_Expr);
                setExprOp(pIfNullRow, @intCast(TK_IF_NULL_ROW));
                wr(?*anyopaque, pIfNullRow, Expr_pLeft, pCopy);
                setExprITable(pIfNullRow, pSubst.iNewTable);
                wr(i16, pIfNullRow, Expr_iColumn, -99);
                setExprFlags(pIfNullRow, EP_IfNullRow);
                pCopy = pIfNullRow;
            }
            var pNew = c.sqlite3ExprDup(db, pCopy, 0);
            if (dbMallocFailed(db)) {
                c.sqlite3ExprDelete(db, pNew);
                return pExpr;
            }
            if (pSubst.isOuterJoin != 0) {
                setProp(pNew, EP_CanBeNull);
            }
            if (exprOp(pNew) == TK_TRUEFALSE) {
                wr(c_int, pNew, Expr_u, c.sqlite3ExprTruthValue(pNew));
                setExprOp(pNew, @intCast(TK_INTEGER));
                setProp(pNew, EP_IntValue);
            }

            // Ensure that the expression now has an implicit collation sequence.
            {
                const pNat = c.sqlite3ExprCollSeq(pSubst.pParse, pNew);
                const pColl = c.sqlite3ExprCollSeq(pSubst.pParse, itemExpr(elItem(pSubst.pCList, iColumn)));
                if (pNat != pColl or (exprOp(pNew) != TK_COLUMN and exprOp(pNew) != TK_COLLATE)) {
                    const zColl: ?[*:0]const u8 = if (pColl != null) @ptrCast(rdp(pColl, CollSeq_zName)) else "BINARY";
                    pNew = c.sqlite3ExprAddCollateString(pSubst.pParse, pNew, zColl);
                }
            }
            clearProp(pNew, EP_Collate);
            if (hasProp(pExpr, EP_OuterON | EP_InnerON)) {
                sqlite3SetJoinExpr(pNew, exprWJoin(pExpr), exprFlags(pExpr) & (EP_OuterON | EP_InnerON));
            }
            c.sqlite3ExprDelete(db, pExpr);
            pExpr = pNew;
        }
    } else {
        if (exprOp(pExpr) == TK_IF_NULL_ROW and exprITable(pExpr) == pSubst.iTable) {
            setExprITable(pExpr, pSubst.iNewTable);
        }
        if (exprOp(pExpr) == TK_AGG_FUNCTION and exprOp2(pExpr) >= pSubst.nSelDepth) {
            wr(u8, pExpr, Expr_op2, @intCast(exprOp2(pExpr) - 1));
        }
        wr(?*anyopaque, pExpr, Expr_pLeft, substExpr(pSubst, exprPLeft(pExpr)));
        wr(?*anyopaque, pExpr, Expr_pRight, substExpr(pSubst, exprPRight(pExpr)));
        if (exprUseXSelect(pExpr)) {
            substSelect(pSubst, exprPSelect(pExpr), 1);
        } else {
            substExprList(pSubst, exprPList(pExpr));
        }
        if (hasProp(pExpr, EP_WinFunc)) {
            const pWin = exprYWin(pExpr);
            wr(?*anyopaque, pWin, Window_pFilter, substExpr(pSubst, rdp(pWin, Window_pFilter)));
            substExprList(pSubst, rdp(pWin, Window_pPartition));
            substExprList(pSubst, rdp(pWin, Window_pOrderBy));
        }
    }
    return pExpr;
}

fn substExprList(pSubst: *SubstContext, pList: Ptr) void {
    if (pList == null) return;
    var i: c_int = 0;
    const n = listNExpr(pList);
    while (i < n) : (i += 1) {
        const item = elItem(pList, i);
        setItemExpr(item, substExpr(pSubst, itemExpr(item)));
    }
}

fn substSelect(pSubst: *SubstContext, pIn: Ptr, doPrior: c_int) void {
    var p = pIn;
    if (p == null) return;
    pSubst.nSelDepth += 1;
    while (true) {
        substExprList(pSubst, selPEList(p));
        substExprList(pSubst, selPGroupBy(p));
        substExprList(pSubst, selPOrderBy(p));
        setSelPHaving(p, substExpr(pSubst, selPHaving(p)));
        setSelPWhere(p, substExpr(pSubst, selPWhere(p)));
        const pSrc = selPSrc(p);
        var i = srcNSrc(pSrc);
        var idx: c_int = 0;
        while (i > 0) : (i -= 1) {
            const pItem = srcItemAt(pSrc, idx);
            if (srcHas(pItem, FG_isSubquery)) {
                substSelect(pSubst, itemSelect(pItem), 1);
            }
            if (srcHas(pItem, FG_isTabFunc)) {
                substExprList(pSubst, itemU1(pItem));
            }
            idx += 1;
        }
        if (doPrior == 0) break;
        p = selPPrior(p);
        if (p == null) break;
    }
    pSubst.nSelDepth -= 1;
}

// ════════════════════════════════════════════════════════════════════════════
// recomputeColumnsUsedExpr / recomputeColumnsUsed (static)
// ════════════════════════════════════════════════════════════════════════════
fn recomputeColumnsUsedExpr(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (exprOp(pExpr) != TK_COLUMN) return WRC_Continue;
    const pItem = rdp(pWalker, Walker_u); // u.pSrcItem
    if (itemICursor(pItem) != exprITable(pExpr)) return WRC_Continue;
    if (exprIColumn(pExpr) < 0) return WRC_Continue;
    setItemColUsed(pItem, itemColUsed(pItem) | c.sqlite3ExprColUsed(pExpr));
    return WRC_Continue;
}

fn recomputeColumnsUsed(pSelect: Ptr, pSrcItem: Ptr) void {
    if (itemPTab(pSrcItem) == null) return;
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    _ = c.memset(pw, 0, sizeof_Walker);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&recomputeColumnsUsedExpr)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&c.sqlite3SelectWalkNoop)));
    wr(?*anyopaque, pw, Walker_u, pSrcItem);
    setItemColUsed(pSrcItem, 0);
    _ = c.sqlite3WalkSelect(pw, pSelect);
}

// ════════════════════════════════════════════════════════════════════════════
// srclistRenumberCursors / renumberCursorDoMapping / renumberCursorsCb /
// renumberCursors (static)
// ════════════════════════════════════════════════════════════════════════════
fn srclistRenumberCursors(pParse: Ptr, aCsrMap: [*]c_int, pSrc: Ptr, iExcept: c_int) void {
    var i: c_int = 0;
    const n = srcNSrc(pSrc);
    while (i < n) : (i += 1) {
        if (i != iExcept) {
            const pItem = srcItemAt(pSrc, i);
            if (!srcHas(pItem, FG_isRecursive) or aCsrMap[@intCast(itemICursor(pItem) + 1)] == 0) {
                aCsrMap[@intCast(itemICursor(pItem) + 1)] = rd(c_int, pParse, Parse_nTab);
                wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
            }
            setItemICursor(pItem, aCsrMap[@intCast(itemICursor(pItem) + 1)]);
            if (srcHas(pItem, FG_isSubquery)) {
                var p = itemSelect(pItem);
                while (p != null) : (p = selPPrior(p)) {
                    srclistRenumberCursors(pParse, aCsrMap, selPSrc(p), -1);
                }
            }
        }
    }
}

fn renumberCursorDoMapping(pWalker: Ptr, piCursor: *c_int) void {
    const aCsrMap: [*]c_int = @ptrCast(@alignCast(rdp(pWalker, Walker_u))); // u.aiCol
    const iCsr = piCursor.*;
    if (iCsr < aCsrMap[0] and aCsrMap[@intCast(iCsr + 1)] > 0) {
        piCursor.* = aCsrMap[@intCast(iCsr + 1)];
    }
}

fn renumberCursorsCb(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const op = exprOp(pExpr);
    if (op == TK_COLUMN or op == TK_IF_NULL_ROW) {
        var v = exprITable(pExpr);
        renumberCursorDoMapping(pWalker, &v);
        setExprITable(pExpr, v);
    }
    if (hasProp(pExpr, EP_OuterON)) {
        var v = exprWJoin(pExpr);
        renumberCursorDoMapping(pWalker, &v);
        setExprWJoin(pExpr, v);
    }
    return WRC_Continue;
}

fn renumberCursors(pParse: Ptr, p: Ptr, iExcept: c_int, aCsrMap: [*]c_int) void {
    srclistRenumberCursors(pParse, aCsrMap, selPSrc(p), iExcept);
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    _ = c.memset(pw, 0, sizeof_Walker);
    wr(?*anyopaque, pw, Walker_u, @ptrCast(aCsrMap));
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&renumberCursorsCb)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&c.sqlite3SelectWalkNoop)));
    _ = c.sqlite3WalkSelect(pw, p);
}

// ════════════════════════════════════════════════════════════════════════════
// findLeftmostExprlist / compoundHasDifferentAffinities (static)
// ════════════════════════════════════════════════════════════════════════════
fn findLeftmostExprlist(pSelIn: Ptr) Ptr {
    var pSel = pSelIn;
    while (selPPrior(pSel) != null) {
        pSel = selPPrior(pSel);
    }
    return selPEList(pSel);
}

fn compoundHasDifferentAffinities(p: Ptr) c_int {
    const pList = selPEList(p);
    var ii: c_int = 0;
    const n = listNExpr(pList);
    while (ii < n) : (ii += 1) {
        const aff = c.sqlite3ExprAffinity(itemExpr(elItem(pList, ii)));
        var pSub1 = selPPrior(p);
        while (pSub1 != null) : (pSub1 = selPPrior(pSub1)) {
            if (c.sqlite3ExprAffinity(itemExpr(elItem(selPEList(pSub1), ii))) != aff) {
                return 1;
            }
        }
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// flattenSubquery (static) — very large
// ════════════════════════════════════════════════════════════════════════════
fn flattenSubquery(pParse: Ptr, p: Ptr, iFrom: c_int, isAgg: c_int) c_int {
    const zSavedAuthContext = rdp(pParse, Parse_zAuthContext);
    var pParent: Ptr = undefined;
    var pSub: Ptr = undefined;
    var pSub1: Ptr = undefined;
    var pSrc: Ptr = undefined;
    var pSubSrc: Ptr = undefined;
    const iParent: c_int = undefined;
    var iNewParent: c_int = -1;
    _ = &iNewParent;
    var isOuterJoin: c_int = 0;
    var i: c_int = undefined;
    var pWhere: Ptr = undefined;
    var pSubitem: Ptr = undefined;
    const db = parseDb(pParse);
    var w: [sizeof_Walker]u8 align(8) = undefined;
    var aCsrMap: ?[*]c_int = null;

    // Check to see if flattening is permitted.  Return 0 if not.
    if (optDisabled(db, OPT_QueryFlattener)) return 0;
    pSrc = selPSrc(p);
    pSubitem = srcItemAt(pSrc, iFrom);
    const iParentVal = itemICursor(pSubitem);
    pSub = itemSelect(pSubitem);

    if (selPWin(p) != null or selPWin(pSub) != null) return 0; // Restriction (25)

    pSubSrc = selPSrc(pSub);
    if (selPLimit(pSub) != null and selPLimit(p) != null) return 0; // (13)
    if (selPLimit(pSub) != null and exprPRight(selPLimit(pSub)) != null) return 0; // (14)
    if ((selFlags(p) & SF_Compound) != 0 and selPLimit(pSub) != null) return 0; // (15)
    if (srcNSrc(pSubSrc) == 0) return 0; // (7)
    if ((selFlags(pSub) & SF_Distinct) != 0) return 0; // (4)
    if (selPLimit(pSub) != null and (srcNSrc(pSrc) > 1 or isAgg != 0)) return 0; // (8)(9)
    if (selPOrderBy(p) != null and selPOrderBy(pSub) != null) return 0; // (11)
    if (isAgg != 0 and selPOrderBy(pSub) != null) return 0; // (16)
    if (selPLimit(pSub) != null and selPWhere(p) != null) return 0; // (19)
    if (selPLimit(pSub) != null and (selFlags(p) & SF_Distinct) != 0) return 0; // (21)
    if ((selFlags(pSub) & SF_Recursive) != 0) return 0; // (22)

    // If the subquery is the right operand of a LEFT JOIN, restriction (3).
    if ((srcFgJoinType(pSubitem) & (JT_OUTER | JT_LTORJ)) != 0) {
        if (srcNSrc(pSubSrc) > 1 // (3a)
        or (selFlags(p) & SF_Distinct) != 0 // (3d)
        or (srcFgJoinType(pSubitem) & JT_RIGHT) != 0 // (26)
        ) {
            return 0;
        }
        isOuterJoin = 1;
    }

    if (iFrom > 0 and (srcFgJoinType(srcItemAt(pSubSrc, 0)) & JT_LTORJ) != 0) {
        return 0; // (27a)
    }

    // Restriction (17): compound sub-query must be UNION ALL only, etc.
    if (selPPrior(pSub) != null) {
        var ii: c_int = undefined;
        if (selPOrderBy(pSub) != null) return 0; // (20)
        if (isAgg != 0 or (selFlags(p) & SF_Distinct) != 0 or isOuterJoin > 0) return 0; // (17d1/d2/f)
        pSub1 = pSub;
        while (pSub1 != null) : (pSub1 = selPPrior(pSub1)) {
            if ((selFlags(pSub1) & (SF_Distinct | SF_Aggregate)) != 0 // (17b)
            or (selPPrior(pSub1) != null and selOp(pSub1) != TK_ALL) // (17a)
            or srcNSrc(selPSrc(pSub1)) < 1 // (17c)
            or selPWin(pSub1) != null // (17e)
            ) {
                return 0;
            }
            if (iFrom > 0 and (srcFgJoinType(srcItemAt(selPSrc(pSub1), 0)) & JT_LTORJ) != 0) {
                return 0; // (17g)(27b)
            }
        }

        // Restriction (18)
        if (selPOrderBy(p) != null) {
            const pOB = selPOrderBy(p);
            ii = 0;
            const nOB = listNExpr(pOB);
            while (ii < nOB) : (ii += 1) {
                if (itemIOrderByCol(elItem(pOB, ii)) == 0) return 0;
            }
        }

        if ((selFlags(p) & SF_Recursive) != 0) return 0; // (23)
        if (compoundHasDifferentAffinities(pSub) != 0) return 0; // (17h)

        if (srcNSrc(pSrc) > 1) {
            if (rd(c_int, pParse, Parse_nSelect) > 500) return 0;
            if (optDisabled(db, OPT_FlttnUnionAll)) return 0;
            aCsrMap = @ptrCast(@alignCast(c.sqlite3DbMallocZero(db, @as(u64, @intCast(rd(c_int, pParse, Parse_nTab) + 1)) * @sizeOf(c_int))));
            if (aCsrMap) |a| a[0] = rd(c_int, pParse, Parse_nTab);
        }
    }

    // ***** Flattening is permitted. *****
    _ = iParent;

    // Authorize the subquery
    wr(?*anyopaque, pParse, Parse_zAuthContext, itemZName(pSubitem));
    _ = c.sqlite3AuthCheck(pParse, SQLITE_SELECT, null, null, null);
    wr(?*anyopaque, pParse, Parse_zAuthContext, zSavedAuthContext);

    // Delete the transient structures associated with the subquery
    if (srcHas(pSubitem, FG_isSubquery)) {
        pSub1 = c.sqlite3SubqueryDetach(db, pSubitem);
    } else {
        pSub1 = null;
    }
    c.sqlite3DbFree(db, @ptrCast(itemZName(pSubitem)));
    c.sqlite3DbFree(db, @ptrCast(itemZAlias(pSubitem)));
    wr(?*anyopaque, pSubitem, SrcItem_zName, null);
    wr(?*anyopaque, pSubitem, SrcItem_zAlias, null);

    // Compound-subquery flattening: create N-1 copies of the parent query.
    pSub = selPPrior(pSub);
    while (pSub != null) : (pSub = selPPrior(pSub)) {
        const pOrderBy = selPOrderBy(p);
        const pLimit = selPLimit(p);
        const pPrior = selPPrior(p);
        const pItemTab = itemPTab(pSubitem);
        setItemPTab(pSubitem, null);
        setSelPOrderBy(p, null);
        setSelPPrior(p, null);
        setSelPLimit(p, null);
        const pNew = c.sqlite3SelectDup(db, p, 0);
        setSelPLimit(p, pLimit);
        setSelPOrderBy(p, pOrderBy);
        setSelOp(p, @intCast(TK_ALL));
        setItemPTab(pSubitem, pItemTab);
        if (pNew == null) {
            setSelPPrior(p, pPrior);
        } else {
            wr(c_int, pParse, Parse_nSelect, rd(c_int, pParse, Parse_nSelect) + 1);
            setSelId(pNew, rd(c_int, pParse, Parse_nSelect));
            if (aCsrMap != null and !dbMallocFailed(db)) {
                renumberCursors(pParse, pNew, iFrom, aCsrMap.?);
            }
            setSelPPrior(pNew, pPrior);
            if (pPrior != null) setSelPNext(pPrior, pNew);
            setSelPNext(pNew, p);
            setSelPPrior(p, pNew);
        }
    }
    c.sqlite3DbFree(db, @ptrCast(aCsrMap));
    if (dbMallocFailed(db)) {
        _ = c.sqlite3SrcItemAttachSubquery(pParse, pSubitem, pSub1, 0);
        return 1;
    }

    // Defer deleting the Table object associated with the subquery.
    if (itemPTab(pSubitem) != null) {
        const pTabToDel = itemPTab(pSubitem);
        if (rd(u32, pTabToDel, Table_nTabRef) == 1) {
            const pToplevel = c.sqlite3ParseToplevel(pParse);
            _ = c.sqlite3ParserAddCleanup(pToplevel, @ptrCast(@constCast(&c.sqlite3DeleteTableGeneric)), pTabToDel);
        } else {
            wr(u32, pTabToDel, Table_nTabRef, rd(u32, pTabToDel, Table_nTabRef) - 1);
        }
        setItemPTab(pSubitem, null);
    }

    // The following loop runs once for each term in a compound-subquery
    // flattening.  It moves all of the FROM elements of the subquery into the
    // FROM clause of the outer query.
    pSub = pSub1;
    pParent = p;
    while (pParent != null) : ({
        pParent = selPPrior(pParent);
        pSub = selPPrior(pSub);
    }) {
        const jointype = srcFgJoinType(pSubitem);
        pSubSrc = selPSrc(pSub);
        const nSubSrc = srcNSrc(pSubSrc);
        pSrc = selPSrc(pParent);

        if (nSubSrc > 1) {
            pSrc = c.sqlite3SrcListEnlarge(pParse, pSrc, nSubSrc - 1, iFrom + 1);
            if (pSrc == null) break;
            setSelPSrc(pParent, pSrc);
            pSubitem = srcItemAt(pSrc, iFrom);
        }

        // Transfer the FROM clause terms from the subquery into the outer query.
        iNewParent = itemICursor(srcItemAt(pSubSrc, 0));
        i = 0;
        while (i < nSubSrc) : (i += 1) {
            const pItem = srcItemAt(pSrc, i + iFrom);
            if (srcHas(pItem, FG_isUsing)) c.sqlite3IdListDelete(db, itemU3(pItem));
            const pSubItemSrc = srcItemAt(pSubSrc, i);
            _ = c.memcpy(pItem, pSubItemSrc, sizeof_SrcItem);
            setSrcFgJoinType(pItem, srcFgJoinType(pItem) | (jointype & JT_LTORJ));
            _ = c.memset(pSubItemSrc, 0, sizeof_SrcItem);
        }
        setSrcFgJoinType(pSubitem, srcFgJoinType(pSubitem) | jointype);

        // Begin substituting subquery result set expressions for references to
        // iParent in the outer query.
        if (selPOrderBy(pSub) != null) {
            const pOrderBy = selPOrderBy(pSub);
            i = 0;
            const nOB = listNExpr(pOrderBy);
            while (i < nOB) : (i += 1) {
                setItemIOrderByCol(elItem(pOrderBy, i), 0);
            }
            setSelPOrderBy(pParent, pOrderBy);
            setSelPOrderBy(pSub, null);
        }
        pWhere = selPWhere(pSub);
        setSelPWhere(pSub, null);
        if (isOuterJoin > 0) {
            sqlite3SetJoinExpr(pWhere, iNewParent, EP_OuterON);
        }
        if (pWhere != null) {
            if (selPWhere(pParent) != null) {
                setSelPWhere(pParent, c.sqlite3PExpr(pParse, TK_AND, pWhere, selPWhere(pParent)));
            } else {
                setSelPWhere(pParent, pWhere);
            }
        }
        if (!dbMallocFailed(db)) {
            var x: SubstContext = undefined;
            x.pParse = pParse;
            x.iTable = iParentVal;
            x.iNewTable = iNewParent;
            x.isOuterJoin = isOuterJoin;
            x.nSelDepth = 0;
            x.pEList = selPEList(pSub);
            x.pCList = findLeftmostExprlist(pSub);
            substSelect(&x, pParent, 0);
        }

        // The flattened query is a compound if inner or outer query is.
        setSelFlags(pParent, selFlags(pParent) | (selFlags(pSub) & SF_Compound));

        if (selPLimit(pSub) != null) {
            setSelPLimit(pParent, selPLimit(pSub));
            setSelPLimit(pSub, null);
        }

        // Recompute the SrcItem.colUsed masks.
        i = 0;
        while (i < nSubSrc) : (i += 1) {
            recomputeColumnsUsed(pParent, srcItemAt(pSrc, i + iFrom));
        }
    }

    // Finally, delete what is left of the subquery and return success.
    c.sqlite3AggInfoPersistWalkerInit(@ptrCast(&w), pParse);
    _ = c.sqlite3WalkSelect(@ptrCast(&w), pSub1);
    sqlite3SelectDelete(db, pSub1);

    return 1;
}

// ════════════════════════════════════════════════════════════════════════════
// constInsert / findConstInWhere / propagateConstantExprRewriteOne /
// propagateConstantExprRewrite / propagateConstants (static)
// ════════════════════════════════════════════════════════════════════════════
fn constInsert(pConst: *WhereConst, pColumn: Ptr, pValue: Ptr, pExpr: Ptr) void {
    if (hasProp(pColumn, EP_FixedCol)) return;
    if (c.sqlite3ExprAffinity(pValue) != 0) return;
    if (c.sqlite3IsBinary(c.sqlite3ExprCompareCollSeq(pConst.pParse, pExpr)) == 0) {
        return;
    }

    // apExpr is null until the first insert; the loop is empty then. Casting a
    // null to a non-optional [*] panics, so only walk when it's set.
    if (pConst.apExpr != null) {
        const apExpr: [*]?*anyopaque = @ptrCast(@alignCast(pConst.apExpr));
        var i: c_int = 0;
        while (i < pConst.nConst) : (i += 1) {
            const pE2 = apExpr[@intCast(i * 2)];
            if (exprITable(pE2) == exprITable(pColumn) and exprIColumn(pE2) == exprIColumn(pColumn)) {
                return; // Already present
            }
        }
    }
    if (c.sqlite3ExprAffinity(pColumn) <= SQLITE_AFF_BLOB) {
        pConst.bHasAffBlob = 1;
    }

    pConst.nConst += 1;
    pConst.apExpr = @ptrCast(@alignCast(c.sqlite3DbReallocOrFree(parseDb(pConst.pParse), @ptrCast(pConst.apExpr), @as(u64, @intCast(pConst.nConst)) * 2 * @sizeOf(?*anyopaque))));
    if (pConst.apExpr == null) {
        pConst.nConst = 0;
    } else {
        const ap: [*]?*anyopaque = @ptrCast(@alignCast(pConst.apExpr));
        ap[@intCast(pConst.nConst * 2 - 2)] = pColumn;
        ap[@intCast(pConst.nConst * 2 - 1)] = pValue;
    }
}

fn findConstInWhere(pConst: *WhereConst, pExpr: Ptr) void {
    if (pExpr == null) return;
    if (hasProp(pExpr, pConst.mExcludeOn)) {
        return;
    }
    if (exprOp(pExpr) == TK_AND) {
        findConstInWhere(pConst, exprPRight(pExpr));
        findConstInWhere(pConst, exprPLeft(pExpr));
        return;
    }
    if (exprOp(pExpr) != TK_EQ) return;
    const pRight = exprPRight(pExpr);
    const pLeft = exprPLeft(pExpr);
    if (exprOp(pRight) == TK_COLUMN and c.sqlite3ExprIsConstant(pConst.pParse, pLeft) != 0) {
        constInsert(pConst, pRight, pLeft, pExpr);
    }
    if (exprOp(pLeft) == TK_COLUMN and c.sqlite3ExprIsConstant(pConst.pParse, pRight) != 0) {
        constInsert(pConst, pLeft, pRight, pExpr);
    }
}

fn propagateConstantExprRewriteOne(pConst: *WhereConst, pExpr: Ptr, bIgnoreAffBlob: c_int) c_int {
    if (pConst.pOomFault.?.* != 0) return WRC_Prune;
    if (exprOp(pExpr) != TK_COLUMN) return WRC_Continue;
    if (hasProp(pExpr, EP_FixedCol | pConst.mExcludeOn)) {
        return WRC_Continue;
    }
    var i: c_int = 0;
    const apExpr: [*]?*anyopaque = @ptrCast(@alignCast(pConst.apExpr));
    while (i < pConst.nConst) : (i += 1) {
        const pColumn = apExpr[@intCast(i * 2)];
        if (pColumn == pExpr) continue;
        if (exprITable(pColumn) != exprITable(pExpr)) continue;
        if (exprIColumn(pColumn) != exprIColumn(pExpr)) continue;
        if (bIgnoreAffBlob != 0 and c.sqlite3ExprAffinity(pColumn) <= SQLITE_AFF_BLOB) {
            break;
        }
        // A match is found.  Add the EP_FixedCol property.
        pConst.nChng += 1;
        clearProp(pExpr, EP_Leaf);
        setProp(pExpr, EP_FixedCol);
        wr(?*anyopaque, pExpr, Expr_pLeft, c.sqlite3ExprDup(parseDb(pConst.pParse), apExpr[@intCast(i * 2 + 1)], 0));
        if (dbMallocFailed(parseDb(pConst.pParse))) return WRC_Prune;
        break;
    }
    return WRC_Prune;
}

fn propagateConstantExprRewrite(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const pConst: *WhereConst = @ptrCast(@alignCast(rdp(pWalker, Walker_u)));
    if (pConst.bHasAffBlob != 0) {
        if ((exprOp(pExpr) >= TK_EQ and exprOp(pExpr) <= TK_GE) or exprOp(pExpr) == TK_IS) {
            _ = propagateConstantExprRewriteOne(pConst, exprPLeft(pExpr), 0);
            if (pConst.pOomFault.?.* != 0) return WRC_Prune;
            if (c.sqlite3ExprAffinity(exprPLeft(pExpr)) != SQLITE_AFF_TEXT) {
                _ = propagateConstantExprRewriteOne(pConst, exprPRight(pExpr), 0);
            }
        }
    }
    return propagateConstantExprRewriteOne(pConst, pExpr, pConst.bHasAffBlob);
}

fn propagateConstants(pParse: Ptr, p: Ptr) c_int {
    var x: WhereConst = undefined;
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    var nChng: c_int = 0;
    x.pParse = pParse;
    x.pOomFault = @ptrCast(base(parseDb(pParse)) + sqlite3_mallocFailed);
    while (true) {
        x.nConst = 0;
        x.nChng = 0;
        x.apExpr = null;
        x.bHasAffBlob = 0;
        if (selPSrc(p) != null and srcNSrc(selPSrc(p)) > 0 and (srcFgJoinType(srcItemAt(selPSrc(p), 0)) & JT_LTORJ) != 0) {
            x.mExcludeOn = EP_InnerON | EP_OuterON;
        } else {
            x.mExcludeOn = EP_OuterON;
        }
        findConstInWhere(&x, selPWhere(p));
        if (x.nConst != 0) {
            _ = c.memset(pw, 0, sizeof_Walker);
            wr(?*anyopaque, pw, Walker_pParse, pParse);
            wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&propagateConstantExprRewrite)));
            wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&c.sqlite3SelectWalkNoop)));
            wr(?*anyopaque, pw, Walker_u, @ptrCast(&x));
            _ = c.sqlite3WalkExpr(pw, selPWhere(p));
            c.sqlite3DbFree(parseDb(x.pParse), @ptrCast(x.apExpr));
            nChng += x.nChng;
        }
        if (x.nChng == 0) break;
    }
    return nChng;
}

// ════════════════════════════════════════════════════════════════════════════
// pushDownWindowCheck (static)
// ════════════════════════════════════════════════════════════════════════════
fn pushDownWindowCheck(pParse: Ptr, pSubq: Ptr, pExpr: Ptr) c_int {
    return c.sqlite3ExprIsConstantOrGroupBy(pParse, pExpr, rdp(selPWin(pSubq), Window_pPartition));
}

// ════════════════════════════════════════════════════════════════════════════
// pushDownWhereTerms (static)
// ════════════════════════════════════════════════════════════════════════════
fn pushDownWhereTerms(pParse: Ptr, pSubqIn: Ptr, pWhereIn: Ptr, pSrcList: Ptr, iSrc: c_int) c_int {
    var pSubq = pSubqIn;
    var pWhere = pWhereIn;
    var nChng: c_int = 0;
    const pSrc = srcItemAt(pSrcList, iSrc);
    if (pWhere == null) return 0;
    if ((selFlags(pSubq) & (SF_Recursive | SF_MultiPart)) != 0) {
        return 0; // (2) and (11)
    }
    if ((srcFgJoinType(pSrc) & (JT_LTORJ | JT_RIGHT)) != 0) {
        return 0; // (10)
    }

    if (selPPrior(pSubq) != null) {
        var pSel = pSubq;
        var notUnionAll: c_int = 0;
        while (pSel != null) : (pSel = selPPrior(pSel)) {
            const op = selOp(pSel);
            if (op != TK_ALL and op != TK_SELECT) {
                notUnionAll = 1;
            }
            if (selPWin(pSel) != null) return 0; // (6b)
        }
        if (notUnionAll != 0) {
            pSel = pSubq;
            while (pSel != null) : (pSel = selPPrior(pSel)) {
                var ii: c_int = 0;
                const pList = selPEList(pSel);
                const nE = listNExpr(pList);
                while (ii < nE) : (ii += 1) {
                    const pColl = c.sqlite3ExprCollSeq(pParse, itemExpr(elItem(pList, ii)));
                    if (c.sqlite3IsBinary(pColl) == 0) {
                        return 0; // (8)
                    }
                }
            }
        }
    } else {
        if (selPWin(pSubq) != null and rdp(selPWin(pSubq), Window_pPartition) == null) return 0;
    }

    if (selPLimit(pSubq) != null) {
        return 0; // (3)
    }
    while (exprOp(pWhere) == TK_AND) {
        nChng += pushDownWhereTerms(pParse, pSubq, exprPRight(pWhere), pSrcList, iSrc);
        pWhere = exprPLeft(pWhere);
    }

    if (c.sqlite3ExprIsSingleTableConstraint(pWhere, pSrcList, iSrc, 1) != 0) {
        nChng += 1;
        setSelFlags(pSubq, selFlags(pSubq) | SF_PushDown);
        while (pSubq != null) {
            var x: SubstContext = undefined;
            var pNew = c.sqlite3ExprDup(parseDb(pParse), pWhere, 0);
            unsetJoinExpr(pNew, -1, 1);
            x.pParse = pParse;
            x.iTable = itemICursor(pSrc);
            x.iNewTable = itemICursor(pSrc);
            x.isOuterJoin = 0;
            x.nSelDepth = 0;
            x.pEList = selPEList(pSubq);
            x.pCList = findLeftmostExprlist(pSubq);
            pNew = substExpr(&x, pNew);
            if (parseNErr(pParse) == 0 and exprOp(pNew) == TK_IN and exprUseXSelect(pNew)) {
                const pSel = exprPSelect(pNew);
                setSelFlags(pSel, selFlags(pSel) | SF_ClonedRhsIn);
                const pWSel = exprPSelect(pWhere);
                setSelFlags(pWSel, selFlags(pWSel) | SF_ClonedRhsIn);
            }
            if (selPWin(pSubq) != null and pushDownWindowCheck(pParse, pSubq, pNew) == 0) {
                // Restriction 6c has prevented push-down in this case.
                c.sqlite3ExprDelete(parseDb(pParse), pNew);
                nChng -= 1;
                break;
            }
            if ((selFlags(pSubq) & SF_Aggregate) != 0) {
                setSelPHaving(pSubq, c.sqlite3ExprAnd(pParse, selPHaving(pSubq), pNew));
            } else {
                setSelPWhere(pSubq, c.sqlite3ExprAnd(pParse, selPWhere(pSubq), pNew));
            }
            pSubq = selPPrior(pSubq);
        }
    }
    return nChng;
}

// ════════════════════════════════════════════════════════════════════════════
// disableUnusedSubqueryResultColumns (static)
// ════════════════════════════════════════════════════════════════════════════
fn disableUnusedSubqueryResultColumns(pItem: Ptr) c_int {
    var nChng: c_int = 0;
    if (srcHas(pItem, FG_isCorrelated) or srcHas(pItem, FG_isCte)) {
        return 0;
    }
    const pTab = itemPTab(pItem);
    const pSub = itemSelect(pItem);
    var pX = pSub;
    while (pX != null) : (pX = selPPrior(pX)) {
        if ((selFlags(pX) & (SF_Distinct | SF_Aggregate)) != 0) {
            return 0;
        }
        if (selPPrior(pX) != null and selOp(pX) != TK_ALL) {
            return 0;
        }
        if (selPWin(pX) != null) {
            return 0;
        }
    }
    var colUsed = itemColUsed(pItem);
    if (selPOrderBy(pSub) != null) {
        const pList = selPOrderBy(pSub);
        var j: c_int = 0;
        const nE = listNExpr(pList);
        while (j < nE) : (j += 1) {
            var iCol: c_int = itemIOrderByCol(elItem(pList, j));
            if (iCol > 0) {
                iCol -= 1;
                const shift: u6 = @intCast(if (iCol >= BMS) BMS - 1 else iCol);
                colUsed |= @as(u64, 1) << shift;
            }
        }
    }
    const nCol: c_int = tabNCol(pTab);
    var j: c_int = 0;
    while (j < nCol) : (j += 1) {
        const m: u64 = if (j < BMS - 1) (@as(u64, 1) << @intCast(j)) else (@as(u64, 1) << 63);
        if ((m & colUsed) != 0) continue;
        pX = pSub;
        while (pX != null) : (pX = selPPrior(pX)) {
            const pY = itemExpr(elItem(selPEList(pX), j));
            if (exprOp(pY) == TK_NULL) continue;
            setExprOp(pY, @intCast(TK_NULL));
            clearProp(pY, EP_Skip | EP_Unlikely);
            setSelFlags(pX, selFlags(pX) | SF_PushDown);
            nChng += 1;
        }
    }
    return nChng;
}

// ════════════════════════════════════════════════════════════════════════════
// minMaxQuery (static) — returns u8
// ════════════════════════════════════════════════════════════════════════════
fn minMaxQuery(db: Ptr, pFunc: Ptr, ppMinMax: *Ptr) u8 {
    var eRet: c_int = WHERE_ORDERBY_NORMAL;
    var sortFlags: u8 = 0;

    const pEList = exprPList(pFunc);
    if (pEList == null or listNExpr(pEList) != 1 or hasProp(pFunc, EP_WinFunc) or optDisabled(db, OPT_MinMaxOpt)) {
        return @intCast(eRet);
    }
    const zFunc = exprUToken(pFunc);
    if (c.sqlite3StrICmp(zFunc, "min") == 0) {
        eRet = WHERE_ORDERBY_MIN;
        if (c.sqlite3ExprCanBeNull(itemExpr(elItem(pEList, 0))) != 0) {
            sortFlags = KEYINFO_ORDER_BIGNULL;
        }
    } else if (c.sqlite3StrICmp(zFunc, "max") == 0) {
        eRet = WHERE_ORDERBY_MAX;
        sortFlags = KEYINFO_ORDER_DESC;
    } else {
        return @intCast(eRet);
    }
    const pOrderBy = c.sqlite3ExprListDup(db, pEList, 0);
    ppMinMax.* = pOrderBy;
    if (pOrderBy != null) setItemSortFlags(elItem(pOrderBy, 0), sortFlags);
    return @intCast(eRet);
}

// ════════════════════════════════════════════════════════════════════════════
// isSimpleCount (static) — returns Table*
// ════════════════════════════════════════════════════════════════════════════
fn isSimpleCount(p: Ptr, pAggInfo: Ptr) Ptr {
    if (selPWhere(p) != null or listNExpr(selPEList(p)) != 1 or srcNSrc(selPSrc(p)) != 1 or srcHas(srcItemAt(selPSrc(p), 0), FG_isSubquery) or aiNFunc(pAggInfo) != 1 or selPHaving(p) != null) {
        return null;
    }
    const pTab = itemPTab(srcItemAt(selPSrc(p), 0));
    if (tabETabType(pTab) != 0) return null; // !IsOrdinaryTable
    const pExpr = itemExpr(elItem(selPEList(p), 0));
    if (exprOp(pExpr) != TK_AGG_FUNCTION) return null;
    if (exprPAggInfo(pExpr) != pAggInfo) return null;
    const pFunc0 = aiFuncAt(pAggInfo, 0);
    const pFunc = rdp(pFunc0, AggInfo_func_pFunc);
    if ((rd(u32, pFunc, FuncDef_funcFlags) & SQLITE_FUNC_COUNT) == 0) return null;
    if (hasProp(pExpr, EP_Distinct | EP_WinFunc)) return null;

    return pTab;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3IndexedByLookup (export)
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3IndexedByLookup(pParse: Ptr, pFrom: Ptr) c_int {
    const pTab = itemPTab(pFrom);
    const zIndexedBy: ?[*:0]const u8 = @ptrCast(itemU1(pFrom));
    var pIdx = tabPIndex(pTab);
    while (pIdx != null and c.sqlite3StrICmp(@ptrCast(rdp(pIdx, Index_zName)), zIndexedBy) != 0) {
        pIdx = rdp(pIdx, Index_pNext);
    }
    if (pIdx == null) {
        c.sqlite3ErrorMsg(pParse, "no such index: %s", zIndexedBy, @as(?*anyopaque, null));
        parseSetBit(pParse, Parse_checkSchema_byte, Parse_checkSchema_mask);
        return SQLITE_ERROR;
    }
    wr(?*anyopaque, pFrom, SrcItem_u2, pIdx); // u2.pIBIndex
    return SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// convertCompoundSelectToSubquery (static, Walker cb)
// ════════════════════════════════════════════════════════════════════════════
fn convertCompoundSelectToSubquery(pWalker: Ptr, p: Ptr) callconv(.c) c_int {
    var i: c_int = undefined;

    if (selPPrior(p) == null) return WRC_Continue;
    if (selPOrderBy(p) == null) return WRC_Continue;
    var pX = p;
    while (pX != null and (selOp(pX) == TK_ALL or selOp(pX) == TK_SELECT)) {
        pX = selPPrior(pX);
    }
    if (pX == null) return WRC_Continue;
    const pOB = selPOrderBy(p);
    if (itemIOrderByCol(elItem(pOB, 0)) != 0) return WRC_Continue;
    i = listNExpr(pOB) - 1;
    while (i >= 0) : (i -= 1) {
        if ((exprFlags(itemExpr(elItem(pOB, i))) & EP_Collate) != 0) break;
    }
    if (i < 0) return WRC_Continue;

    // If we reach this point, the transformation is required.
    const pParse = rdp(pWalker, Walker_pParse);
    const db = parseDb(pParse);
    const pNew = c.sqlite3DbMallocZero(db, sizeof_Select);
    if (pNew == null) return WRC_Abort;
    var dummy: [sizeof_Token]u8 align(8) = undefined;
    _ = c.memset(@ptrCast(&dummy), 0, sizeof_Token);
    const pNewSrc = c.sqlite3SrcListAppendFromTerm(pParse, null, null, null, @ptrCast(&dummy), pNew, null);
    if (parseNErr(pParse) != 0) {
        c.sqlite3SrcListDelete(db, pNewSrc);
        return WRC_Abort;
    }
    _ = c.memcpy(pNew, p, sizeof_Select); // *pNew = *p
    setSelPSrc(p, pNewSrc);
    setSelPEList(p, c.sqlite3ExprListAppend(pParse, null, c.sqlite3Expr(db, TK_ASTERISK, null)));
    setSelOp(p, @intCast(TK_SELECT));
    setSelPWhere(p, null);
    setSelPGroupBy(pNew, null);
    setSelPHaving(pNew, null);
    setSelPOrderBy(pNew, null);
    setSelPPrior(p, null);
    setSelPNext(p, null);
    setSelPWith(p, null);
    wr(?*anyopaque, p, Select_pWinDefn, null);
    setSelFlags(p, selFlags(p) & ~SF_Compound);
    setSelFlags(p, selFlags(p) | SF_Converted);
    setSelPNext(selPPrior(pNew), pNew);
    setSelPLimit(pNew, null);
    return WRC_Continue;
}

// ════════════════════════════════════════════════════════════════════════════
// cannotBeFunction (static)
// ════════════════════════════════════════════════════════════════════════════
fn cannotBeFunction(pParse: Ptr, pFrom: Ptr) c_int {
    if (srcHas(pFrom, FG_isTabFunc)) {
        c.sqlite3ErrorMsg(pParse, "'%s' is not a function", itemZName(pFrom));
        return 1;
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// searchWith (static) — returns Cte*
// ════════════════════════════════════════════════════════════════════════════
fn searchWith(pWith: Ptr, pItem: Ptr, ppContext: *Ptr) Ptr {
    const zName = itemZName(pItem);
    var p = pWith;
    while (p != null) : (p = rdp(p, With_pOuter)) {
        var i: c_int = 0;
        const nCte = rd(c_int, p, With_nCte);
        const a0 = fieldPtr(p, With_a);
        while (i < nCte) : (i += 1) {
            const pCte: Ptr = @ptrCast(base(a0) + @as(usize, @intCast(i)) * sizeof_Cte);
            if (c.sqlite3StrICmp(zName, @ptrCast(rdp(pCte, Cte_zName))) == 0) {
                ppContext.* = p;
                return pCte;
            }
        }
        if (rd(u8, p, With_bView_byte) != 0) break;
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3WithPush (export)
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3WithPush(pParse: Ptr, pWithIn: Ptr, bFree: u8) Ptr {
    var pWith = pWithIn;
    if (pWith != null) {
        if (bFree != 0) {
            pWith = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&c.sqlite3WithDeleteGeneric)), pWith);
            if (pWith == null) return null;
        }
        if (parseNErr(pParse) == 0) {
            wr(?*anyopaque, pWith, With_pOuter, rdp(pParse, Parse_pWith));
            wr(?*anyopaque, pParse, Parse_pWith, pWith);
        }
    }
    return pWith;
}

// ════════════════════════════════════════════════════════════════════════════
// resolveFromTermToCte (static)
// ════════════════════════════════════════════════════════════════════════════
fn resolveFromTermToCte(pParse: Ptr, pWalker: Ptr, pFrom: Ptr) c_int {
    var pWith: Ptr = undefined;

    if (rdp(pParse, Parse_pWith) == null) {
        return 0;
    }
    if (parseNErr(pParse) != 0) {
        return 0;
    }
    if (!srcHas(pFrom, FG_fixedSchema) and rdp(pFrom, SrcItem_u4_zDatabase) != null) {
        return 0;
    }
    if (srcHas(pFrom, FG_notCte)) {
        return 0;
    }
    const pCte = searchWith(rdp(pParse, Parse_pWith), pFrom, &pWith);
    if (pCte != null) {
        const db = parseDb(pParse);
        var pRecTerm: Ptr = undefined;
        var iRecTab: c_int = -1;
        var pCteUse: Ptr = undefined;

        if (rdp(pCte, Cte_zCteErr) != null) {
            c.sqlite3ErrorMsg(pParse, @ptrCast(rdp(pCte, Cte_zCteErr)), @as(?*anyopaque, @ptrCast(rdp(pCte, Cte_zName))));
            return 2;
        }
        if (cannotBeFunction(pParse, pFrom) != 0) return 2;

        const pTab = c.sqlite3DbMallocZero(db, sizeof_Table);
        if (pTab == null) return 2;
        pCteUse = rdp(pCte, Cte_pUse);
        if (pCteUse == null) {
            pCteUse = c.sqlite3DbMallocZero(db, sizeof_CteUse);
            wr(?*anyopaque, pCte, Cte_pUse, pCteUse);
            if (pCteUse == null or c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&cleanupDbFree)), pCteUse) == null) {
                c.sqlite3DbFree(db, pTab);
                return 2;
            }
            wr(u8, pCteUse, CteUse_eM10d, rd(u8, pCte, Cte_eM10d));
        }
        setItemPTab(pFrom, pTab);
        wr(u32, pTab, Table_nTabRef, 1);
        wr(?*anyopaque, pTab, Table_zName, c.sqlite3DbStrDup(db, @ptrCast(rdp(pCte, Cte_zName))));
        wr(i16, pTab, Table_iPKey, -1);
        wr(i16, pTab, Table_nRowLogEst, 200);
        setTabTabFlags(pTab, tabTabFlags(pTab) | TF_Ephemeral | TF_NoVisibleRowid);
        _ = c.sqlite3SrcItemAttachSubquery(pParse, pFrom, rdp(pCte, Cte_pSelect), 1);
        if (dbMallocFailed(db)) return 2;
        const pSel = itemSelect(pFrom);
        setSelFlags(pSel, selFlags(pSel) | SF_CopyCte);
        if (srcHas(pFrom, FG_isIndexedBy)) {
            c.sqlite3ErrorMsg(pParse, "no such index: \"%s\"", itemU1(pFrom));
            return 2;
        }
        srcSet(pFrom, FG_isCte);
        wr(?*anyopaque, pFrom, SrcItem_u2, pCteUse); // u2.pCteUse
        wr(c_int, pCteUse, CteUse_nUse, rd(c_int, pCteUse, CteUse_nUse) + 1);

        // Check if this is a recursive CTE.
        pRecTerm = pSel;
        const bMayRecursive = (selOp(pSel) == TK_ALL or selOp(pSel) == TK_UNION);
        while (bMayRecursive and selOp(pRecTerm) == selOp(pSel)) {
            const pSrc = selPSrc(pRecTerm);
            var i: c_int = 0;
            const nSrc = srcNSrc(pSrc);
            while (i < nSrc) : (i += 1) {
                const pItem = srcItemAt(pSrc, i);
                if (itemZName(pItem) != null and !srcHas(pItem, FG_hadSchema) and !srcHas(pItem, FG_isSubquery) and (srcHas(pItem, FG_fixedSchema) or rdp(pItem, SrcItem_u4_zDatabase) == null) and c.sqlite3StrICmp(itemZName(pItem), @ptrCast(rdp(pCte, Cte_zName))) == 0) {
                    setItemPTab(pItem, pTab);
                    wr(u32, pTab, Table_nTabRef, rd(u32, pTab, Table_nTabRef) + 1);
                    srcSet(pItem, FG_isRecursive);
                    if ((selFlags(pRecTerm) & SF_Recursive) != 0) {
                        c.sqlite3ErrorMsg(pParse, "multiple references to recursive table: %s", @as(?*anyopaque, @ptrCast(rdp(pCte, Cte_zName))));
                        return 2;
                    }
                    setSelFlags(pRecTerm, selFlags(pRecTerm) | SF_Recursive);
                    if (iRecTab < 0) {
                        iRecTab = rd(c_int, pParse, Parse_nTab);
                        wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
                    }
                    setItemICursor(pItem, iRecTab);
                }
            }
            if ((selFlags(pRecTerm) & SF_Recursive) == 0) break;
            pRecTerm = selPPrior(pRecTerm);
        }

        wr(?*anyopaque, pCte, Cte_zCteErr, @constCast(@ptrCast(@as(?[*:0]const u8, "circular reference: %s"))));
        const pSavedWith = rdp(pParse, Parse_pWith);
        wr(?*anyopaque, pParse, Parse_pWith, pWith);
        if ((selFlags(pSel) & SF_Recursive) != 0) {
            setSelPWith(pRecTerm, selPWith(pSel));
            const rc = c.sqlite3WalkSelect(pWalker, pRecTerm);
            setSelPWith(pRecTerm, null);
            if (rc != 0) {
                wr(?*anyopaque, pParse, Parse_pWith, pSavedWith);
                return 2;
            }
        } else {
            if (c.sqlite3WalkSelect(pWalker, pSel) != 0) {
                wr(?*anyopaque, pParse, Parse_pWith, pSavedWith);
                return 2;
            }
        }
        wr(?*anyopaque, pParse, Parse_pWith, pWith);

        var pLeft = pSel;
        while (selPPrior(pLeft) != null) : (pLeft = selPPrior(pLeft)) {}
        var pEList = selPEList(pLeft);
        if (rdp(pCte, Cte_pCols) != null) {
            if (pEList != null and listNExpr(pEList) != listNExpr(rdp(pCte, Cte_pCols))) {
                c.sqlite3ErrorMsg(pParse, "table %s has %d values for %d columns", @as(?*anyopaque, @ptrCast(rdp(pCte, Cte_zName))), listNExpr(pEList), listNExpr(rdp(pCte, Cte_pCols)));
                wr(?*anyopaque, pParse, Parse_pWith, pSavedWith);
                return 2;
            }
            pEList = rdp(pCte, Cte_pCols);
        }

        _ = sqlite3ColumnsFromExprList(pParse, pEList, @ptrCast(@alignCast(base(pTab) + Table_nCol)), @ptrCast(@alignCast(base(pTab) + Table_aCol)));
        if (bMayRecursive) {
            if ((selFlags(pSel) & SF_Recursive) != 0) {
                wr(?*anyopaque, pCte, Cte_zCteErr, @constCast(@ptrCast(@as(?[*:0]const u8, "multiple recursive references: %s"))));
            } else {
                wr(?*anyopaque, pCte, Cte_zCteErr, @constCast(@ptrCast(@as(?[*:0]const u8, "recursive reference in a subquery: %s"))));
            }
            _ = c.sqlite3WalkSelect(pWalker, pSel);
        }
        wr(?*anyopaque, pCte, Cte_zCteErr, null);
        wr(?*anyopaque, pParse, Parse_pWith, pSavedWith);
        return 1; // Success
    }
    return 0; // No match
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3SelectPopWith (export)
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3SelectPopWith(pWalker: Ptr, p: Ptr) void {
    const pParse = rdp(pWalker, Walker_pParse);
    if (rdp(pParse, Parse_pWith) != null and selPPrior(p) == null) {
        const pWith = selPWith(findRightmost(p));
        if (pWith != null) {
            wr(?*anyopaque, pParse, Parse_pWith, rdp(pWith, With_pOuter));
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3ExpandSubquery (export)
// ════════════════════════════════════════════════════════════════════════════
export fn sqlite3ExpandSubquery(pParse: Ptr, pFrom: Ptr) c_int {
    var pSel = itemSelect(pFrom);
    const pTab = c.sqlite3DbMallocZero(parseDb(pParse), sizeof_Table);
    setItemPTab(pFrom, pTab);
    if (pTab == null) return SQLITE_NOMEM;
    wr(u32, pTab, Table_nTabRef, 1);
    if (itemZAlias(pFrom) != null) {
        wr(?*anyopaque, pTab, Table_zName, c.sqlite3DbStrDup(parseDb(pParse), @ptrCast(itemZAlias(pFrom))));
    } else {
        wr(?*anyopaque, pTab, Table_zName, c.sqlite3MPrintf(parseDb(pParse), "%!S", pFrom));
    }
    while (selPPrior(pSel) != null) {
        pSel = selPPrior(pSel);
    }
    _ = sqlite3ColumnsFromExprList(pParse, selPEList(pSel), @ptrCast(@alignCast(base(pTab) + Table_nCol)), @ptrCast(@alignCast(base(pTab) + Table_aCol)));
    wr(i16, pTab, Table_iPKey, -1);
    wr(u8, pTab, Table_eTabType, TABTYP_VIEW);
    wr(i16, pTab, Table_nRowLogEst, 200);
    setTabTabFlags(pTab, tabTabFlags(pTab) | TF_Ephemeral | TF_NoVisibleRowid);
    return if (parseNErr(pParse) != 0) SQLITE_ERROR else SQLITE_OK;
}

// ════════════════════════════════════════════════════════════════════════════
// inAnyUsingClause (static)
// ════════════════════════════════════════════════════════════════════════════
fn inAnyUsingClause(zName: ?[*:0]const u8, pBaseIn: Ptr, NIn: c_int) c_int {
    var N = NIn;
    var pBase = pBaseIn;
    while (N > 0) {
        N -= 1;
        pBase = @ptrCast(base(pBase) + sizeof_SrcItem);
        if (!srcHas(pBase, FG_isUsing)) continue;
        if (itemU3(pBase) == null) continue;
        if (c.sqlite3IdListIndex(itemU3(pBase), zName) >= 0) return 1;
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// selectExpander (static, Walker cb) — VERY large
// ════════════════════════════════════════════════════════════════════════════
fn selectExpander(pWalker: Ptr, p: Ptr) callconv(.c) c_int {
    const pParse = rdp(pWalker, Walker_pParse);
    var i: c_int = undefined;
    var j: c_int = undefined;
    var k: c_int = undefined;
    var rc: c_int = undefined;
    const db = parseDb(pParse);
    var pE: Ptr = undefined;
    var pRight: Ptr = undefined;
    var pExpr: Ptr = undefined;
    const selFlagsSaved: u32 = selFlags(p);
    var elistFlags: u32 = 0;

    setSelFlags(p, selFlags(p) | SF_Expanded);
    if (dbMallocFailed(db)) {
        return WRC_Abort;
    }
    if ((selFlagsSaved & SF_Expanded) != 0) {
        return WRC_Prune;
    }
    if (rd(c_int, pWalker, Walker_eCode) != 0) {
        // Renumber selId because it has been copied from a view
        wr(c_int, pParse, Parse_nSelect, rd(c_int, pParse, Parse_nSelect) + 1);
        setSelId(p, rd(c_int, pParse, Parse_nSelect));
    }
    const pTabList = selPSrc(p);
    var pEList = selPEList(p);
    if (rdp(pParse, Parse_pWith) != null and (selFlags(p) & SF_View) != 0) {
        if (selPWith(p) == null) {
            const pW = c.sqlite3DbMallocZero(db, off("With_a", 16) + 1 * sizeof_Cte);
            setSelPWith(p, pW);
            if (pW == null) {
                return WRC_Abort;
            }
        }
        wr(u8, selPWith(p), With_bView_byte, 1);
    }
    _ = sqlite3WithPush(pParse, selPWith(p), 0);

    // Make sure cursor numbers have been assigned.
    c.sqlite3SrcListAssignCursors(pParse, pTabList);

    // Look up every table named in the FROM clause.
    i = 0;
    while (i < srcNSrc(pTabList)) : (i += 1) {
        const pFrom = srcItemAt(pTabList, i);
        var pTab: Ptr = undefined;
        if (itemPTab(pFrom) != null) continue;
        if (itemZName(pFrom) == null) {
            // A sub-query in the FROM clause of a SELECT
            const pSel = itemSelect(pFrom);
            if (c.sqlite3WalkSelect(pWalker, pSel) != 0) return WRC_Abort;
            if (sqlite3ExpandSubquery(pParse, pFrom) != 0) return WRC_Abort;
        } else if (blk: {
            rc = resolveFromTermToCte(pParse, pWalker, pFrom);
            break :blk rc != 0;
        }) {
            if (rc > 1) return WRC_Abort;
            pTab = itemPTab(pFrom);
        } else {
            // An ordinary table or view name in the FROM clause
            pTab = c.sqlite3LocateTableItem(pParse, 0, pFrom);
            setItemPTab(pFrom, pTab);
            if (pTab == null) return WRC_Abort;
            if (rd(u32, pTab, Table_nTabRef) >= 0xffff) {
                c.sqlite3ErrorMsg(pParse, "too many references to \"%s\": max 65535", tabZName(pTab));
                setItemPTab(pFrom, null);
                return WRC_Abort;
            }
            wr(u32, pTab, Table_nTabRef, rd(u32, pTab, Table_nTabRef) + 1);
            if (tabETabType(pTab) != 1 and cannotBeFunction(pParse, pFrom) != 0) { // !IsVirtual
                return WRC_Abort;
            }
            if (tabETabType(pTab) != 0) { // !IsOrdinaryTable
                const eCodeOrig = rd(u8, pWalker, Walker_eCode);
                if (c.sqlite3ViewGetColumnNames(pParse, pTab) != 0) return WRC_Abort;
                if (tabETabType(pTab) == TABTYP_VIEW) { // IsView
                    if ((dbFlags(db) & SQLITE_EnableView) == 0 and tabPSchema(pTab) != rdp(dbAt(db, 1), Db_pSchema)) {
                        c.sqlite3ErrorMsg(pParse, "access to view \"%s\" prohibited", tabZName(pTab));
                    }
                    _ = c.sqlite3SrcItemAttachSubquery(pParse, pFrom, rdp(pTab, Table_u_view_pSelect), 1);
                } else if (tabETabType(pTab) == 1) { // IsVirtual
                    const fromDDL = srcHas(pFrom, FG_fromDDL) or (rd(u32, pParse, Parse_prepFlags) & SQLITE_PREPARE_FROM_DDL) != 0;
                    if (fromDDL) {
                        const pVtab = rdp(pTab, Table_u_vtab_p);
                        if (pVtab != null) {
                            const eVtabRisk = rd(c_int, pVtab, off("VTable_eVtabRisk", 56));
                            const trusted: c_int = @intFromBool((dbFlags(db) & SQLITE_TrustedSchema) != 0);
                            if (eVtabRisk > trusted) {
                                c.sqlite3ErrorMsg(pParse, "unsafe use of virtual table \"%s\"", tabZName(pTab));
                            }
                        }
                    }
                }
                const nCol = tabNCol(pTab);
                setTabNCol(pTab, -1);
                wr(u8, pWalker, Walker_eCode, 1);
                if (srcHas(pFrom, FG_isSubquery)) {
                    _ = c.sqlite3WalkSelect(pWalker, itemSelect(pFrom));
                }
                wr(u8, pWalker, Walker_eCode, eCodeOrig);
                setTabNCol(pTab, nCol);
            }
        }

        // Locate the index named by the INDEXED BY clause, if any.
        if (srcHas(pFrom, FG_isIndexedBy) and sqlite3IndexedByLookup(pParse, pFrom) != 0) {
            return WRC_Abort;
        }
    }

    // Process NATURAL keywords, and ON and USING clauses of joins.
    if (parseNErr(pParse) != 0 or sqlite3ProcessJoin(pParse, p) != 0) {
        return WRC_Abort;
    }

    // For every "*" that occurs in the column list, insert the names of all
    // columns in all tables.  First loop: check if there are any "*" operators.
    k = 0;
    while (k < listNExpr(pEList)) : (k += 1) {
        pE = itemExpr(elItem(pEList, k));
        if (exprOp(pE) == TK_ASTERISK) break;
        if (exprOp(pE) == TK_DOT and exprOp(exprPRight(pE)) == TK_ASTERISK) break;
        elistFlags |= exprFlags(pE);
    }
    if (k < listNExpr(pEList)) {
        // Result set contains one or more "*" operators that need expanding.
        var pNew: Ptr = null;
        const flags = dbFlags(db);
        const longNames = (flags & SQLITE_FullColNames) != 0 and (flags & SQLITE_ShortColNames) == 0;

        k = 0;
        while (k < listNExpr(pEList)) : (k += 1) {
            const aK = elItem(pEList, k);
            pE = itemExpr(aK);
            elistFlags |= exprFlags(pE);
            pRight = exprPRight(pE);
            if (exprOp(pE) != TK_ASTERISK and (exprOp(pE) != TK_DOT or exprOp(pRight) != TK_ASTERISK)) {
                // This particular expression does not need to be expanded.
                pNew = c.sqlite3ExprListAppend(pParse, pNew, itemExpr(aK));
                if (pNew != null) {
                    const last = elItem(pNew, listNExpr(pNew) - 1);
                    setItemZEName(last, itemZEName(aK));
                    setItemEEName(last, itemEEName(aK));
                    setItemZEName(aK, null);
                }
                setItemExpr(aK, null);
            } else {
                // This expression is a "*" or "TABLE.*" and needs to be expanded.
                var tableSeen: c_int = 0;
                var zTName: ?[*:0]const u8 = null;
                var iErrOfst: c_int = undefined;
                if (exprOp(pE) == TK_DOT) {
                    zTName = exprUToken(exprPLeft(pE));
                    iErrOfst = rd(c_int, exprPRight(pE), Expr_w);
                } else {
                    iErrOfst = rd(c_int, pE, Expr_w);
                }
                i = 0;
                while (i < srcNSrc(pTabList)) : (i += 1) {
                    const pFrom = srcItemAt(pTabList, i);
                    const pTab = itemPTab(pFrom);
                    var pNestedFrom: Ptr = null;
                    var zSchemaName: ?[*:0]const u8 = null;
                    var iDb: c_int = undefined;
                    var pUsing: Ptr = null;

                    var zTabName = itemZAlias(pFrom);
                    if (zTabName == null) {
                        zTabName = @ptrCast(@constCast(tabZName(pTab)));
                    }
                    if (dbMallocFailed(db)) break;
                    if (srcHas(pFrom, FG_isNestedFrom)) {
                        pNestedFrom = selPEList(itemSelect(pFrom));
                    } else {
                        if (zTName != null and c.sqlite3StrICmp(zTName, @ptrCast(zTabName)) != 0) {
                            continue;
                        }
                        pNestedFrom = null;
                        iDb = c.sqlite3SchemaToIndex(db, tabPSchema(pTab));
                        zSchemaName = if (iDb >= 0) dbZDbSName(dbAt(db, iDb)) else "*";
                    }
                    if (i + 1 < srcNSrc(pTabList) and srcHas(srcItemAt(pTabList, i + 1), FG_isUsing) and (selFlagsSaved & SF_NestedFrom) != 0) {
                        pUsing = itemU3(srcItemAt(pTabList, i + 1));
                        var ii: c_int = 0;
                        const nId = rd(c_int, pUsing, IdList_nId);
                        while (ii < nId) : (ii += 1) {
                            const pIdItem: Ptr = @ptrCast(base(fieldPtr(pUsing, IdList_a)) + @as(usize, @intCast(ii)) * sizeof_IdList_item);
                            const zUName: ?[*:0]const u8 = @ptrCast(rdp(pIdItem, IdList_item_zName));
                            pRight = c.sqlite3Expr(db, TK_ID, zUName);
                            c.sqlite3ExprSetErrorOffset(pRight, iErrOfst);
                            pNew = c.sqlite3ExprListAppend(pParse, pNew, pRight);
                            if (pNew != null) {
                                const pX = elItem(pNew, listNExpr(pNew) - 1);
                                setItemZEName(pX, c.sqlite3MPrintf(db, "..%s", zUName));
                                setItemEEName(pX, ENAME_TAB);
                                setItemFgWord(pX, itemFgWord(pX) | EFG_bUsingTerm);
                            }
                        }
                    } else {
                        pUsing = null;
                    }

                    var nAdd = @as(c_int, tabNCol(pTab));
                    const visibleRowid = (tabTabFlags(pTab) & TF_NoVisibleRowid) == 0;
                    if (visibleRowid and (selFlagsSaved & SF_NestedFrom) != 0) nAdd += 1;
                    j = 0;
                    while (j < nAdd) : (j += 1) {
                        var zName: ?[*:0]const u8 = undefined;
                        var pX: Ptr = undefined;

                        if (j == tabNCol(pTab)) {
                            zName = c.sqlite3RowidAlias(pTab);
                            if (zName == null) continue;
                        } else {
                            const pCol = tabColAt(pTab, j);
                            zName = @ptrCast(colCnName(pCol));

                            if (pNestedFrom != null and itemEEName(elItem(pNestedFrom, j)) == ENAME_ROWID) {
                                continue;
                            }
                            if (zTName != null and pNestedFrom != null and c.sqlite3MatchEName(elItem(pNestedFrom, j), null, zTName, null, null) == 0) {
                                continue;
                            }
                            if ((selFlags(p) & SF_IncludeHidden) == 0 and (colFlags(pCol) & COLFLAG_HIDDEN) != 0) {
                                continue;
                            }
                            if ((colFlags(pCol) & COLFLAG_NOEXPAND) != 0 and zTName == null and (selFlagsSaved & SF_NestedFrom) == 0) {
                                continue;
                            }
                        }
                        tableSeen = 1;

                        if (i > 0 and zTName == null and (selFlagsSaved & SF_NestedFrom) == 0) {
                            if (srcHas(pFrom, FG_isUsing) and c.sqlite3IdListIndex(itemU3(pFrom), zName) >= 0) {
                                continue;
                            }
                        }
                        pRight = c.sqlite3Expr(db, TK_ID, zName);
                        if ((srcNSrc(pTabList) > 1 and ((srcFgJoinType(pFrom) & JT_LTORJ) == 0 or (selFlagsSaved & SF_NestedFrom) != 0 or inAnyUsingClause(zName, pFrom, srcNSrc(pTabList) - i - 1) == 0)) or inRenameObject(pParse)) {
                            var pLeft = c.sqlite3Expr(db, TK_ID, @ptrCast(zTabName));
                            pExpr = c.sqlite3PExpr(pParse, TK_DOT, pLeft, pRight);
                            if (inRenameObject(pParse) and exprPLeft(pE) != null) {
                                c.sqlite3RenameTokenRemap(pParse, pLeft, exprPLeft(pE));
                            }
                            if (zSchemaName != null) {
                                pLeft = c.sqlite3Expr(db, TK_ID, zSchemaName);
                                pExpr = c.sqlite3PExpr(pParse, TK_DOT, pLeft, pExpr);
                            }
                        } else {
                            pExpr = pRight;
                        }
                        c.sqlite3ExprSetErrorOffset(pExpr, iErrOfst);
                        pNew = c.sqlite3ExprListAppend(pParse, pNew, pExpr);
                        if (pNew == null) {
                            break; // OOM
                        }
                        pX = elItem(pNew, listNExpr(pNew) - 1);
                        if ((selFlagsSaved & SF_NestedFrom) != 0 and !inRenameObject(pParse)) {
                            if (pNestedFrom != null) {
                                setItemZEName(pX, c.sqlite3DbStrDup(db, itemZEName(elItem(pNestedFrom, j))));
                            } else {
                                setItemZEName(pX, c.sqlite3MPrintf(db, "%s.%s.%s", zSchemaName, zTabName, zName));
                            }
                            setItemEEName(pX, if (j == tabNCol(pTab)) ENAME_ROWID else ENAME_TAB);
                            if ((srcHas(pFrom, FG_isUsing) and c.sqlite3IdListIndex(itemU3(pFrom), zName) >= 0) or (pUsing != null and c.sqlite3IdListIndex(pUsing, zName) >= 0) or (j < tabNCol(pTab) and (colFlags(tabColAt(pTab, j)) & COLFLAG_NOEXPAND) != 0)) {
                                setItemBNoExpand(pX);
                            }
                        } else if (longNames) {
                            setItemZEName(pX, c.sqlite3MPrintf(db, "%s.%s", zTabName, zName));
                            setItemEEName(pX, ENAME_NAME);
                        } else {
                            setItemZEName(pX, c.sqlite3DbStrDup(db, zName));
                            setItemEEName(pX, ENAME_NAME);
                        }
                    }
                }
                if (tableSeen == 0) {
                    if (zTName != null) {
                        c.sqlite3ErrorMsg(pParse, "no such table: %s", zTName);
                    } else {
                        c.sqlite3ErrorMsg(pParse, "no tables specified");
                    }
                }
            }
        }
        c.sqlite3ExprListDelete(db, pEList);
        setSelPEList(p, pNew);
    }
    pEList = selPEList(p);
    if (pEList != null) {
        if (listNExpr(pEList) > dbLimit(db, SQLITE_LIMIT_COLUMN)) {
            c.sqlite3ErrorMsg(pParse, "too many columns in result set");
            return WRC_Abort;
        }
        if ((elistFlags & (EP_HasFunc | EP_Subquery)) != 0) {
            setSelFlags(p, selFlags(p) | SF_ComplexResult);
        }
    }
    return WRC_Continue;
}

// ════════════ CLUSTER F ════════════
// ════════════════════════════════════════════════════════════════════════════
// CLUSTER F — type-info / prep / aggregate machinery / optimizers / sqlite3Select
//
// All of these are the SELECT statement code generator's "back half".  They
// reuse the scaffold (constants, offsets, inline accessors, the `c` extern
// struct) defined at the top of select.zig (lines 1..1453) and call cluster
// B/C/D/E functions by bare name (selectInnerLoop, generateSortTail,
// codeDistinct, fixDistinctOpenEph, sqlite3SubqueryColumnTypes,
// sqlite3KeyInfoFromExprList, sqlite3GenerateColumnNames, computeLimitRegisters,
// multiSelect, flattenSubquery, propagateConstants, pushDownWhereTerms,
// disableUnusedSubqueryResultColumns, convertCompoundSelectToSubquery,
// selectExpander, sqlite3SelectPopWith, renumberCursors, minMaxQuery,
// isSimpleCount).
// ════════════════════════════════════════════════════════════════════════════

// ─── extra externs not present in the scaffold `c` struct ────────────────────
// NOTE: the scaffold's `c` struct already declares `sqlite3VdbeExplainPop`
// (vdbeaux.c) and the sqlite3Where* / sqlite3Window* externs, so we call those
// via `c.`.  The three below are NOT in the scaffold and are declared here.

// ─── local constants not in scaffold ─────────────────────────────────────────
// Index.idxType is the 2-bit field at the start of the bitfield word that
// also holds bUnordered (the scaffold gives Index_bUnordered_byte=99,
// mask 0x04 => bit 2; idxType occupies bits 0-1 of that same byte 99).

// Parse.bHasExists lives in the bft cluster at byte 39, mask 0x10 (scaffold:
// Parse_bHasExists_mask).  Index_pNext / Index_zName / Index_tnum /
// Index_szIdxRow / Index_pPartIdxWhere / Index_bUnordered_byte are scaffold.

// ════════════════════════════════════════════════════════════════════════════
// selectAddSubqueryTypeInfo (select.c:6408) — Walker xSelectCallback2.
// xSelectCallback2 returns void.
// ════════════════════════════════════════════════════════════════════════════
fn selectAddSubqueryTypeInfo(pWalker: Ptr, p: Ptr) callconv(.c) void {
    if (selHas(p, SF_HasTypeInfo)) return;
    selSet(p, SF_HasTypeInfo);
    const pParse = rdp(pWalker, Walker_pParse);
    const pTabList = selPSrc(p);
    const n = srcNSrc(pTabList);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const pFrom = srcItemAt(pTabList, i);
        const pTab = itemPTab(pFrom);
        if ((tabTabFlags(pTab) & TF_Ephemeral) != 0 and srcHas(pFrom, FG_isSubquery)) {
            const pSel = itemSelect(pFrom);
            sqlite3SubqueryColumnTypes(pParse, pTab, pSel, SQLITE_AFF_NONE);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3SelectAddTypeInfo (select.c:6439) static.
// ════════════════════════════════════════════════════════════════════════════
fn sqlite3SelectAddTypeInfo(pParse: Ptr, pSelect: Ptr) void {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    _ = c.memset(&w, 0, sizeof_Walker);
    const pw: Ptr = @ptrCast(&w);
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&c.sqlite3SelectWalkNoop)));
    wr(?*anyopaque, pw, Walker_xSelectCallback2, @ptrCast(@constCast(&selectAddSubqueryTypeInfo)));
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&c.sqlite3ExprWalkNoop)));
    wr(?*anyopaque, pw, Walker_pParse, pParse);
    _ = c.sqlite3WalkSelect(pw, pSelect);
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3SelectExpand (select.c:6378) static.
// (Defined in select.c just above selectAddSubqueryTypeInfo; uses cluster-E
// statics convertCompoundSelectToSubquery / selectExpander and cluster-E
// export sqlite3SelectPopWith.)
// ════════════════════════════════════════════════════════════════════════════
fn sqlite3SelectExpand(pParse: Ptr, pSelect: Ptr) void {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    _ = c.memset(&w, 0, sizeof_Walker);
    const pw: Ptr = @ptrCast(&w);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&c.sqlite3ExprWalkNoop)));
    wr(?*anyopaque, pw, Walker_pParse, pParse);
    wr(c_int, pw, Walker_eCode, 0);
    if (parseGetBit(pParse, Parse_bft_byte, Parse_hasCompound_mask)) {
        wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&convertCompoundSelectToSubquery)));
        _ = c.sqlite3WalkSelect(pw, pSelect);
    }
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&selectExpander)));
    wr(?*anyopaque, pw, Walker_xSelectCallback2, @ptrCast(@constCast(&sqlite3SelectPopWith)));
    _ = c.sqlite3WalkSelect(pw, pSelect);
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3SelectPrep (select.c:6463) EXPORT.
// ════════════════════════════════════════════════════════════════════════════
pub export fn sqlite3SelectPrep(pParse: Ptr, p: Ptr, pOuterNC: Ptr) void {
    const db = parseDb(pParse);
    if (dbMallocFailed(db)) return;
    if (selHas(p, SF_HasTypeInfo)) return;
    sqlite3SelectExpand(pParse, p);
    if (parseNErr(pParse) != 0) return;
    c.sqlite3ResolveSelectNames(pParse, p, pOuterNC);
    if (parseNErr(pParse) != 0) return;
    sqlite3SelectAddTypeInfo(pParse, p);
}

// ════════════════════════════════════════════════════════════════════════════
// analyzeAggFuncArgs (select.c:6523) static.
// ════════════════════════════════════════════════════════════════════════════
fn analyzeAggFuncArgs(pAggInfo: Ptr, pNC: Ptr) void {
    wr(c_int, pNC, NameContext_ncFlags, rd(c_int, pNC, NameContext_ncFlags) | NC_InAggFunc);
    const nFunc = aiNFunc(pAggInfo);
    var i: c_int = 0;
    while (i < nFunc) : (i += 1) {
        const pFunc = aiFuncAt(pAggInfo, i);
        const pExpr = rdp(pFunc, AggInfo_func_pFExpr);
        c.sqlite3ExprAnalyzeAggList(pNC, exprPList(pExpr));
        const pLeft = exprPLeft(pExpr);
        if (pLeft != null) {
            c.sqlite3ExprAnalyzeAggList(pNC, exprPList(pLeft));
        }
        if (hasProp(pExpr, EP_WinFunc)) {
            const pWin = exprYWin(pExpr);
            c.sqlite3ExprAnalyzeAggregates(pNC, rdp(pWin, Window_pFilter));
        }
    }
    wr(c_int, pNC, NameContext_ncFlags, rd(c_int, pNC, NameContext_ncFlags) & ~NC_InAggFunc);
}

// ════════════════════════════════════════════════════════════════════════════
// optimizeAggregateUseOfIndexedExpr (select.c:6558) static.
// ════════════════════════════════════════════════════════════════════════════
fn optimizeAggregateUseOfIndexedExpr(pParse: Ptr, pSelect: Ptr, pAggInfo: Ptr, pNC: Ptr) void {
    _ = pParse;
    setAiNColumn(pAggInfo, aiNAccumulator(pAggInfo));
    if (aiNSortingColumn(pAggInfo) > 0) {
        var mx: c_int = listNExpr(selPGroupBy(pSelect)) - 1;
        const nCol = aiNColumn(pAggInfo);
        var j: c_int = 0;
        while (j < nCol) : (j += 1) {
            const k = rd(c_int, aiColAt(pAggInfo, j), AggInfo_col_iSorterColumn);
            if (k > mx) mx = k;
        }
        setAiNSortingColumn(pAggInfo, mx + 1);
    }
    analyzeAggFuncArgs(pAggInfo, pNC);
}

// ════════════════════════════════════════════════════════════════════════════
// aggregateIdxEprRefToColCallback (select.c:6600) static — Walker xExpr cb.
// ════════════════════════════════════════════════════════════════════════════
fn aggregateIdxEprRefToColCallback(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    _ = pWalker;
    const pAggInfo = exprPAggInfo(pExpr);
    if (pAggInfo == null) return WRC_Continue;
    const opc = exprOp(pExpr);
    if (opc == TK_AGG_COLUMN) return WRC_Continue;
    if (opc == TK_AGG_FUNCTION) return WRC_Continue;
    if (opc == TK_IF_NULL_ROW) return WRC_Continue;
    const iAgg = exprIAgg(pExpr);
    if (iAgg >= aiNColumn(pAggInfo)) return WRC_Continue;
    const pCol = aiColAt(pAggInfo, iAgg);
    setExprOp(pExpr, @intCast(TK_AGG_COLUMN));
    setExprITable(pExpr, rd(c_int, pCol, AggInfo_col_iTable));
    wr(i16, pExpr, Expr_iColumn, @intCast(rd(c_int, pCol, AggInfo_col_iColumn)));
    clearProp(pExpr, EP_Skip | EP_Collate | EP_Unlikely);
    return WRC_Prune;
}

// ════════════════════════════════════════════════════════════════════════════
// aggregateConvertIndexedExprRefToColumn (select.c:6624) static.
// ════════════════════════════════════════════════════════════════════════════
fn aggregateConvertIndexedExprRefToColumn(pAggInfo: Ptr) void {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    _ = c.memset(&w, 0, sizeof_Walker);
    const pw: Ptr = @ptrCast(&w);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&aggregateIdxEprRefToColCallback)));
    const nFunc = aiNFunc(pAggInfo);
    var i: c_int = 0;
    while (i < nFunc) : (i += 1) {
        _ = c.sqlite3WalkExpr(pw, rdp(aiFuncAt(pAggInfo, i), AggInfo_func_pFExpr));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// assignAggregateRegisters (select.c:6652) static.
// ════════════════════════════════════════════════════════════════════════════
fn assignAggregateRegisters(pParse: Ptr, pAggInfo: Ptr) void {
    wr(c_int, pAggInfo, AggInfo_iFirstReg, rd(c_int, pParse, Parse_nMem) + 1);
    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + aiNColumn(pAggInfo) + aiNFunc(pAggInfo));
}

// ════════════════════════════════════════════════════════════════════════════
// resetAccumulator (select.c:6667) static.
// ════════════════════════════════════════════════════════════════════════════
fn resetAccumulator(pParse: Ptr, pAggInfo: Ptr) void {
    const v = parseVdbe(pParse);
    const nReg = aiNFunc(pAggInfo) + aiNColumn(pAggInfo);
    if (nReg == 0) return;
    if (parseNErr(pParse) != 0) return;
    const iFirst = aiIFirstReg(pAggInfo);
    _ = c.sqlite3VdbeAddOp3(v, OP.Null, 0, iFirst, iFirst + nReg - 1);
    const nFunc = aiNFunc(pAggInfo);
    var i: c_int = 0;
    while (i < nFunc) : (i += 1) {
        const pFunc = aiFuncAt(pAggInfo, i);
        const pFExpr = rdp(pFunc, AggInfo_func_pFExpr);
        const pFFunc = rdp(pFunc, AggInfo_func_pFunc);
        if (rd(c_int, pFunc, AggInfo_func_iDistinct) >= 0) {
            const pList = exprPList(pFExpr);
            if (pList == null or listNExpr(pList) != 1) {
                c.sqlite3ErrorMsg(pParse, "DISTINCT aggregates must have exactly one argument");
                wr(c_int, pFunc, AggInfo_func_iDistinct, -1);
            } else {
                const pKeyInfo = sqlite3KeyInfoFromExprList(pParse, pList, 0, 0);
                const addr = c.sqlite3VdbeAddOp4(v, OP.OpenEphemeral, rd(c_int, pFunc, AggInfo_func_iDistinct), 0, 0, @ptrCast(pKeyInfo), P4_KEYINFO);
                wr(c_int, pFunc, AggInfo_func_iDistAddr, addr);
                c.sqlite3VdbeExplain(pParse, 0, "USE TEMP B-TREE FOR %s(DISTINCT)", @as(?[*:0]const u8, @ptrCast(rdp(pFFunc, FuncDef_zName))));
            }
        }
        if (rd(c_int, pFunc, AggInfo_func_iOBTab) >= 0) {
            var nExtra: c_int = 0;
            const pLeft = exprPLeft(pFExpr);
            const pOBList = exprPList(pLeft);
            if (rd(u8, pFunc, AggInfo_func_bOBUnique) == 0) {
                nExtra += 1;
            }
            if (rd(u8, pFunc, AggInfo_func_bOBPayload) != 0) {
                nExtra += listNExpr(exprPList(pFExpr));
            }
            if (rd(u8, pFunc, AggInfo_func_bUseSubtype) != 0) {
                nExtra += listNExpr(exprPList(pFExpr));
            }
            const pKeyInfo = sqlite3KeyInfoFromExprList(pParse, pOBList, 0, nExtra);
            if (rd(u8, pFunc, AggInfo_func_bOBUnique) == 0 and parseNErr(pParse) == 0) {
                setKiNKeyField(pKeyInfo, kiNKeyField(pKeyInfo) + 1);
            }
            _ = c.sqlite3VdbeAddOp4(v, OP.OpenEphemeral, rd(c_int, pFunc, AggInfo_func_iOBTab), listNExpr(pOBList) + nExtra, 0, @ptrCast(pKeyInfo), P4_KEYINFO);
            c.sqlite3VdbeExplain(pParse, 0, "USE TEMP B-TREE FOR %s(ORDER BY)", @as(?[*:0]const u8, @ptrCast(rdp(pFFunc, FuncDef_zName))));
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// finalizeAggFunctions (select.c:6733) static.
// ════════════════════════════════════════════════════════════════════════════
fn finalizeAggFunctions(pParse: Ptr, pAggInfo: Ptr) void {
    const v = parseVdbe(pParse);
    const nFunc = aiNFunc(pAggInfo);
    var i: c_int = 0;
    while (i < nFunc) : (i += 1) {
        const pF = aiFuncAt(pAggInfo, i);
        const pFExpr = rdp(pF, AggInfo_func_pFExpr);
        const pFFunc = rdp(pF, AggInfo_func_pFunc);
        if (parseNErr(pParse) != 0) return;
        const pList = exprPList(pFExpr);
        if (rd(c_int, pF, AggInfo_func_iOBTab) >= 0) {
            const iOBTab = rd(c_int, pF, AggInfo_func_iOBTab);
            const nArg = listNExpr(pList);
            const regAgg = c.sqlite3GetTempRange(pParse, nArg);
            var nKey: c_int = undefined;
            if (rd(u8, pF, AggInfo_func_bOBPayload) == 0) {
                nKey = 0;
            } else {
                const pLeft = exprPLeft(pFExpr);
                nKey = listNExpr(exprPList(pLeft));
                if (rd(u8, pF, AggInfo_func_bOBUnique) == 0) nKey += 1;
            }
            const iTop = c.sqlite3VdbeAddOp1(v, OP.Rewind, iOBTab);
            var j: c_int = nArg - 1;
            while (j >= 0) : (j -= 1) {
                _ = c.sqlite3VdbeAddOp3(v, OP.Column, iOBTab, nKey + j, regAgg + j);
            }
            if (rd(u8, pF, AggInfo_func_bUseSubtype) != 0) {
                const regSubtype = c.sqlite3GetTempReg(pParse);
                const bExtra: c_int = if (rd(u8, pF, AggInfo_func_bOBPayload) == 0 and rd(u8, pF, AggInfo_func_bOBUnique) == 0) 1 else 0;
                const iBaseCol = nKey + nArg + bExtra;
                var jj: c_int = nArg - 1;
                while (jj >= 0) : (jj -= 1) {
                    _ = c.sqlite3VdbeAddOp3(v, OP.Column, iOBTab, iBaseCol + jj, regSubtype);
                    _ = c.sqlite3VdbeAddOp2(v, OP.SetSubtype, regSubtype, regAgg + jj);
                }
                c.sqlite3ReleaseTempReg(pParse, regSubtype);
            }
            _ = c.sqlite3VdbeAddOp3(v, OP.AggStep, 0, regAgg, aggFuncReg(pAggInfo, i));
            c.sqlite3VdbeAppendP4(v, pFFunc, P4_FUNCDEF);
            c.sqlite3VdbeChangeP5(v, @intCast(@as(u32, @bitCast(nArg)) & 0xffff));
            _ = c.sqlite3VdbeAddOp2(v, OP.Next, iOBTab, iTop + 1);
            c.sqlite3VdbeJumpHere(v, iTop);
            c.sqlite3ReleaseTempRange(pParse, regAgg, nArg);
        }
        _ = c.sqlite3VdbeAddOp2(v, OP.AggFinal, aggFuncReg(pAggInfo, i), if (pList != null) listNExpr(pList) else 0);
        c.sqlite3VdbeAppendP4(v, pFFunc, P4_FUNCDEF);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// updateAccumulator (select.c:6808) static.
// ════════════════════════════════════════════════════════════════════════════
fn updateAccumulator(pParse: Ptr, regAcc: c_int, pAggInfo: Ptr, eDistinctType: c_int) void {
    const v = parseVdbe(pParse);
    var regHit: c_int = 0;
    var addrHitTest: c_int = 0;
    if (parseNErr(pParse) != 0) return;
    setAiDirectMode(pAggInfo, 1);
    const db = parseDb(pParse);
    const nFunc = aiNFunc(pAggInfo);
    var i: c_int = 0;
    while (i < nFunc) : (i += 1) {
        const pF = aiFuncAt(pAggInfo, i);
        const pFExpr = rdp(pF, AggInfo_func_pFExpr);
        const pFFunc = rdp(pF, AggInfo_func_pFunc);
        var nArg: c_int = undefined;
        var addrNext: c_int = 0;
        var regAgg: c_int = undefined;
        var regAggSz: c_int = 0;
        var regDistinct: c_int = 0;
        const pList = exprPList(pFExpr);
        if (hasProp(pFExpr, EP_WinFunc)) {
            const pWin = exprYWin(pFExpr);
            const pFilter = rdp(pWin, Window_pFilter);
            if (aiNAccumulator(pAggInfo) != 0 and (rd(u32, pFFunc, FuncDef_funcFlags) & SQLITE_FUNC_NEEDCOLL) != 0 and regAcc != 0) {
                if (regHit == 0) {
                    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                    regHit = rd(c_int, pParse, Parse_nMem);
                }
                _ = c.sqlite3VdbeAddOp2(v, OP.Copy, regAcc, regHit);
            }
            addrNext = c.sqlite3VdbeMakeLabel(pParse);
            c.sqlite3ExprIfFalse(pParse, pFilter, addrNext, SQLITE_JUMPIFNULL);
        }
        if (rd(c_int, pF, AggInfo_func_iOBTab) >= 0) {
            const iOBTab = rd(c_int, pF, AggInfo_func_iOBTab);
            nArg = listNExpr(pList);
            const pLeft = exprPLeft(pFExpr);
            const pOBList = exprPList(pLeft);
            regAggSz = listNExpr(pOBList);
            if (rd(u8, pF, AggInfo_func_bOBUnique) == 0) {
                regAggSz += 1;
            }
            if (rd(u8, pF, AggInfo_func_bOBPayload) != 0) {
                regAggSz += nArg;
            }
            if (rd(u8, pF, AggInfo_func_bUseSubtype) != 0) {
                regAggSz += nArg;
            }
            regAggSz += 1; // one extra register for result of MakeRecord
            regAgg = c.sqlite3GetTempRange(pParse, regAggSz);
            regDistinct = regAgg;
            _ = c.sqlite3ExprCodeExprList(pParse, pOBList, regAgg, 0, SQLITE_ECEL_DUP);
            var jj: c_int = listNExpr(pOBList);
            if (rd(u8, pF, AggInfo_func_bOBUnique) == 0) {
                _ = c.sqlite3VdbeAddOp2(v, OP.Sequence, iOBTab, regAgg + jj);
                jj += 1;
            }
            if (rd(u8, pF, AggInfo_func_bOBPayload) != 0) {
                regDistinct = regAgg + jj;
                _ = c.sqlite3ExprCodeExprList(pParse, pList, regDistinct, 0, SQLITE_ECEL_DUP);
                jj += nArg;
            }
            if (rd(u8, pF, AggInfo_func_bUseSubtype) != 0) {
                const regBase = if (rd(u8, pF, AggInfo_func_bOBPayload) != 0) regDistinct else regAgg;
                var kk: c_int = 0;
                while (kk < nArg) : (kk += 1) {
                    _ = c.sqlite3VdbeAddOp2(v, OP.GetSubtype, regBase + kk, regAgg + jj);
                    jj += 1;
                }
            }
        } else if (pList != null) {
            nArg = listNExpr(pList);
            regAgg = c.sqlite3GetTempRange(pParse, nArg);
            regDistinct = regAgg;
            _ = c.sqlite3ExprCodeExprList(pParse, pList, regAgg, 0, SQLITE_ECEL_DUP);
        } else {
            nArg = 0;
            regAgg = 0;
        }
        if (rd(c_int, pF, AggInfo_func_iDistinct) >= 0 and pList != null) {
            if (addrNext == 0) {
                addrNext = c.sqlite3VdbeMakeLabel(pParse);
            }
            const newDist = codeDistinct(pParse, eDistinctType, rd(c_int, pF, AggInfo_func_iDistinct), addrNext, pList, regDistinct);
            wr(c_int, pF, AggInfo_func_iDistinct, newDist);
        }
        if (rd(c_int, pF, AggInfo_func_iOBTab) >= 0) {
            const iOBTab = rd(c_int, pF, AggInfo_func_iOBTab);
            _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regAgg, regAggSz - 1, regAgg + regAggSz - 1);
            _ = c.sqlite3VdbeAddOp4Int(v, OP.IdxInsert, iOBTab, regAgg + regAggSz - 1, regAgg, regAggSz - 1);
            c.sqlite3ReleaseTempRange(pParse, regAgg, regAggSz);
        } else {
            if ((rd(u32, pFFunc, FuncDef_funcFlags) & SQLITE_FUNC_NEEDCOLL) != 0) {
                var pColl: Ptr = null;
                var jc: c_int = 0;
                while (pColl == null and jc < nArg) : (jc += 1) {
                    const pItem = elItem(pList, jc);
                    pColl = c.sqlite3ExprCollSeq(pParse, itemExpr(pItem));
                }
                if (pColl == null) {
                    pColl = rdp(db, sqlite3_pDfltColl);
                }
                if (regHit == 0 and aiNAccumulator(pAggInfo) != 0) {
                    wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                    regHit = rd(c_int, pParse, Parse_nMem);
                }
                _ = c.sqlite3VdbeAddOp4(v, OP.CollSeq, regHit, 0, 0, @ptrCast(pColl), P4_COLLSEQ);
            }
            _ = c.sqlite3VdbeAddOp3(v, OP.AggStep, 0, regAgg, aggFuncReg(pAggInfo, i));
            c.sqlite3VdbeAppendP4(v, pFFunc, P4_FUNCDEF);
            c.sqlite3VdbeChangeP5(v, @intCast(@as(u32, @bitCast(nArg)) & 0xffff));
            c.sqlite3ReleaseTempRange(pParse, regAgg, nArg);
        }
        if (addrNext != 0) {
            c.sqlite3VdbeResolveLabel(v, addrNext);
        }
        if (parseNErr(pParse) != 0) return;
    }
    if (regHit == 0 and aiNAccumulator(pAggInfo) != 0) {
        regHit = regAcc;
    }
    if (regHit != 0) {
        addrHitTest = c.sqlite3VdbeAddOp1(v, OP.If, regHit);
    }
    const nAcc = aiNAccumulator(pAggInfo);
    var k: c_int = 0;
    while (k < nAcc) : (k += 1) {
        const pC = aiColAt(pAggInfo, k);
        c.sqlite3ExprCode(pParse, rdp(pC, AggInfo_col_pCExpr), aggColReg(pAggInfo, k));
        if (parseNErr(pParse) != 0) return;
    }
    setAiDirectMode(pAggInfo, 0);
    if (addrHitTest != 0) {
        c.sqlite3VdbeJumpHereOrPopInst(v, addrHitTest);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// explainSimpleCount (select.c:6974) static. SQLITE_OMIT_EXPLAIN OFF.
// ════════════════════════════════════════════════════════════════════════════
inline fn hasRowid(pTab: Ptr) bool {
    return (tabTabFlags(pTab) & TF_WithoutRowid) == 0;
}
fn explainSimpleCount(pParse: Ptr, pTab: Ptr, pIdx: Ptr) void {
    if (rd(u8, pParse, Parse_explain) == 2) {
        const idxType: u8 = if (pIdx != null) (rd(u8, pIdx, Index_idxType_byte) & Index_idxType_mask) else 0;
        const isPk = pIdx != null and idxType == SQLITE_IDXTYPE_PRIMARYKEY;
        const bCover = pIdx != null and (hasRowid(pTab) or !isPk);
        c.sqlite3VdbeExplain(pParse, 0, "SCAN %s%s%s", tabZName(pTab), if (bCover) @as(?[*:0]const u8, " USING COVERING INDEX ") else @as(?[*:0]const u8, ""), if (bCover) @as(?[*:0]const u8, @ptrCast(rdp(pIdx, Index_zName))) else @as(?[*:0]const u8, ""));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// havingToWhereExprCb (select.c:7003) static — Walker xExpr cb.
// ════════════════════════════════════════════════════════════════════════════
inline fn exprAlwaysFalse(p: Ptr) bool {
    return hasProp(p, EP_IsFalse);
}
fn havingToWhereExprCb(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (exprOp(pExpr) != TK_AND) {
        const pS = rdp(pWalker, Walker_u); // u.pSelect
        const pParse = rdp(pWalker, Walker_pParse);
        if (c.sqlite3ExprIsConstantOrGroupBy(pParse, pExpr, selPGroupBy(pS)) != 0 and
            !exprAlwaysFalse(pExpr) and
            exprPAggInfo(pExpr) == null)
        {
            const db = parseDb(pParse);
            var pNew = c.sqlite3ExprInt32(db, 1);
            if (pNew != null) {
                const pWhere = selPWhere(pS);
                // SWAP(Expr, *pNew, *pExpr): exchange sizeof_Expr bytes.
                var tmp: [sizeof_Expr]u8 align(8) = undefined;
                _ = c.memcpy(&tmp, pNew, sizeof_Expr);
                _ = c.memcpy(pNew, pExpr, sizeof_Expr);
                _ = c.memcpy(pExpr, &tmp, sizeof_Expr);
                pNew = c.sqlite3ExprAnd(pParse, pWhere, pNew);
                setSelPWhere(pS, pNew);
                wr(c_int, pWalker, Walker_eCode, 1);
            }
        }
        return WRC_Prune;
    }
    return WRC_Continue;
}

// ════════════════════════════════════════════════════════════════════════════
// havingToWhere (select.c:7047) static.
// ════════════════════════════════════════════════════════════════════════════
fn havingToWhere(pParse: Ptr, p: Ptr) void {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    _ = c.memset(&w, 0, sizeof_Walker);
    const pw: Ptr = @ptrCast(&w);
    wr(?*anyopaque, pw, Walker_pParse, pParse);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&havingToWhereExprCb)));
    wr(?*anyopaque, pw, Walker_u, p); // u.pSelect
    _ = c.sqlite3WalkExpr(pw, selPHaving(p));
}

// ════════════════════════════════════════════════════════════════════════════
// isSelfJoinView (select.c:7070) static — returns SrcItem*.
// ════════════════════════════════════════════════════════════════════════════
fn isSelfJoinView(pTabList: Ptr, pThis: Ptr, iFirstIn: c_int, iEnd: c_int) Ptr {
    const pSel = itemSelect(pThis);
    if (selHas(pSel, SF_PushDown)) return null;
    var iFirst = iFirstIn;
    while (iFirst < iEnd) {
        const pItem = srcItemAt(pTabList, iFirst);
        iFirst += 1;
        if (!srcHas(pItem, FG_isSubquery)) continue;
        if (srcHas(pItem, FG_viaCoroutine)) continue;
        if (itemZName(pItem) == null) continue;
        const pItemTab = itemPTab(pItem);
        const pThisTab = itemPTab(pThis);
        if (tabPSchema(pItemTab) != tabPSchema(pThisTab)) continue;
        if (c.sqlite3_stricmp(@ptrCast(itemZName(pItem)), @ptrCast(itemZName(pThis))) != 0) continue;
        const pS1 = itemSelect(pItem);
        if (tabPSchema(pItemTab) == null and selId(pSel) != selId(pS1)) {
            continue;
        }
        if (selHas(pS1, SF_PushDown)) {
            continue;
        }
        return pItem;
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// agginfoFree (select.c:7110) static — ParserAddCleanup callback.
// ════════════════════════════════════════════════════════════════════════════
fn agginfoFree(db: Ptr, pArg: ?*anyopaque) callconv(.c) void {
    const p: Ptr = pArg;
    c.sqlite3DbFree(db, aiACol(p));
    c.sqlite3DbFree(db, aiAFunc(p));
    c.sqlite3DbFreeNN(db, p);
}

// ════════════════════════════════════════════════════════════════════════════
// countOfViewOptimization (select.c:7137) static.
// ════════════════════════════════════════════════════════════════════════════
fn countOfViewOptimization(pParse: Ptr, p: Ptr) c_int {
    if ((selFlags(p) & SF_Aggregate) == 0) return 0;
    if (listNExpr(selPEList(p)) != 1) return 0;
    if (selPWhere(p) != null) return 0;
    if (selPHaving(p) != null) return 0;
    if (selPGroupBy(p) != null) return 0;
    if (selPOrderBy(p) != null) return 0;
    var pExpr = itemExpr(elItem(selPEList(p), 0));
    if (exprOp(pExpr) != TK_AGG_FUNCTION) return 0;
    if (c.sqlite3_stricmp(exprUToken(pExpr), "count") != 0) return 0;
    if (exprPList(pExpr) != null) return 0;
    if (srcNSrc(selPSrc(p)) != 1) return 0;
    if (hasProp(pExpr, EP_WinFunc)) return 0;
    const pFrom = srcItemAt(selPSrc(p), 0);
    if (!srcHas(pFrom, FG_isSubquery)) return 0;
    var pSub = itemSelect(pFrom);
    if (selPPrior(pSub) == null) return 0;
    if (selHas(pSub, SF_CopyCte)) return 0;
    while (true) {
        if (selOp(pSub) != TK_ALL and selPPrior(pSub) != null) return 0;
        if (selPWhere(pSub) != null) return 0;
        if (selPLimit(pSub) != null) return 0;
        if ((selFlags(pSub) & (SF_Aggregate | SF_Distinct)) != 0) {
            return 0;
        }
        pSub = selPPrior(pSub);
        if (pSub == null) break;
    }

    // Perform the transformation.
    const db = parseDb(pParse);
    const pCount = pExpr;
    pExpr = null;
    pSub = c.sqlite3SubqueryDetach(db, pFrom);
    c.sqlite3SrcListDelete(db, selPSrc(p));
    setSelPSrc(p, c.sqlite3DbMallocZero(db, SZ_SRCLIST_1));
    while (pSub != null) {
        const pPrior = selPPrior(pSub);
        setSelPPrior(pSub, null);
        setSelPNext(pSub, null);
        selSet(pSub, SF_Aggregate);
        selClear(pSub, SF_Compound);
        setSelNSelectRow(pSub, 0);
        _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&c.sqlite3ExprListDeleteGeneric)), selPEList(pSub));
        const pTermArg = if (pPrior != null) c.sqlite3ExprDup(db, pCount, 0) else pCount;
        setSelPEList(pSub, c.sqlite3ExprListAppend(pParse, null, pTermArg));
        const pTerm = c.sqlite3PExpr(pParse, TK_SELECT, null, null);
        c.sqlite3PExprAddSelect(pParse, pTerm, pSub);
        if (pExpr == null) {
            pExpr = pTerm;
        } else {
            pExpr = c.sqlite3PExpr(pParse, TK_PLUS, pTerm, pExpr);
        }
        pSub = pPrior;
    }
    setItemExpr(elItem(selPEList(p), 0), pExpr);
    selClear(p, SF_Aggregate);
    return 1;
}

// ════════════════════════════════════════════════════════════════════════════
// sameSrcAlias (select.c:7220) static — recursive.
// ════════════════════════════════════════════════════════════════════════════
fn sameSrcAlias(p0: Ptr, pSrc: Ptr) c_int {
    const n = srcNSrc(pSrc);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const p1 = srcItemAt(pSrc, i);
        if (p1 == p0) continue;
        if (itemPTab(p0) == itemPTab(p1) and c.sqlite3_stricmp(@ptrCast(itemZAlias(p0)), @ptrCast(itemZAlias(p1))) == 0) {
            return 1;
        }
        if (srcHas(p1, FG_isSubquery)) {
            const pSel = itemSelect(p1);
            if ((selFlags(pSel) & SF_NestedFrom) != 0 and sameSrcAlias(p0, selPSrc(pSel)) != 0) {
                return 1;
            }
        }
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// fromClauseTermCanBeCoroutine (select.c:7266) static.
// ════════════════════════════════════════════════════════════════════════════
fn fromClauseTermCanBeCoroutine(pParse: Ptr, pTabList: Ptr, iIn: c_int, selFlagsIn: c_int) c_int {
    var i = iIn;
    var pItem = srcItemAt(pTabList, i);
    if (srcHas(pItem, FG_isCte)) {
        const pCteUse = itemU2(pItem);
        if (rd(u8, pCteUse, CteUse_eM10d) == M10d_Yes) return 0; // (2a)
        if (rd(c_int, pCteUse, CteUse_nUse) >= 2 and rd(u8, pCteUse, CteUse_eM10d) != M10d_No) return 0; // (2b)
    }
    if ((srcFgJoinType(srcItemAt(pTabList, 0)) & JT_LTORJ) != 0) return 0; // (3)
    if (optDisabled(parseDb(pParse), OPT_Coroutines)) return 0; // (4)
    if (isSelfJoinView(pTabList, pItem, i + 1, srcNSrc(pTabList)) != null) {
        return 0; // (5)
    }
    if (i == 0) {
        if (srcNSrc(pTabList) == 1) return 1; // (1a)
        if ((srcFgJoinType(srcItemAt(pTabList, 1)) & JT_CROSS) != 0) return 1; // (1b)
        if ((selFlagsIn & @as(c_int, @bitCast(@as(u32, @truncate(SF_UpdateFrom))))) != 0) return 0; // (1c-iii)
        return 1;
    }
    if ((selFlagsIn & @as(c_int, @bitCast(@as(u32, @truncate(SF_UpdateFrom))))) != 0) return 0; // (1c-iii)
    while (true) {
        if ((srcFgJoinType(pItem) & (JT_OUTER | JT_CROSS)) != 0) return 0; // (1c-ii)
        if (i == 0) break;
        i -= 1;
        pItem = srcItemAt(pTabList, i);
        if (srcHas(pItem, FG_isSubquery)) return 0; // (1c-i)
    }
    return 1;
}

// ════════════════════════════════════════════════════════════════════════════
// existsToJoin (select.c:7326) static (SQLITE_NOINLINE) — recursive.
// ════════════════════════════════════════════════════════════════════════════
fn existsToJoin(pParse: Ptr, p: Ptr, pWhere: Ptr) void {
    if (parseNErr(pParse) != 0) return;
    if (pWhere == null) return;
    if (hasProp(pWhere, EP_OuterON | EP_InnerON)) return;
    if (selPSrc(p) == null) return;
    if (srcNSrc(selPSrc(p)) >= BMS) return;
    const pLimit = selPLimit(p);
    if (!(pLimit == null or exprPRight(pLimit) == null)) return;

    if (exprOp(pWhere) == TK_AND) {
        const pRight = exprPRight(pWhere);
        existsToJoin(pParse, p, exprPLeft(pWhere));
        existsToJoin(pParse, p, pRight);
    } else if (exprOp(pWhere) == TK_EXISTS) {
        const pSub = exprPSelect(pWhere);
        const pSubWhere = selPWhere(pSub);
        if (srcNSrc(selPSrc(pSub)) == 1 and
            (selFlags(pSub) & SF_Aggregate) == 0 and
            !srcHas(srcItemAt(selPSrc(pSub), 0), FG_isSubquery) and
            selPLimit(pSub) == null and
            selPPrior(pSub) == null)
        {
            const db = parseDb(pParse);
            const nTab = rd(c_int, pParse, Parse_nTab);
            const aCsrMap: ?[*]c_int = @ptrCast(@alignCast(c.sqlite3DbMallocZero(db, @as(u64, @intCast(nTab + 2)) * @sizeOf(c_int))));
            if (aCsrMap == null) return;
            aCsrMap.?[0] = nTab + 1;
            renumberCursors(pParse, pSub, -1, @ptrCast(aCsrMap));
            c.sqlite3DbFree(db, @ptrCast(aCsrMap));

            _ = c.memset(pWhere, 0, sizeof_Expr);
            setExprOp(pWhere, @intCast(TK_INTEGER));
            wr(c_int, pWhere, Expr_u, 1); // u.iValue
            setProp(pWhere, EP_IntValue);
            srcSet(srcItemAt(selPSrc(pSub), 0), FG_fromExists);
            setSelPSrc(p, c.sqlite3SrcListAppendList(pParse, selPSrc(p), selPSrc(pSub)));
            if (pSubWhere != null) {
                setSelPWhere(p, c.sqlite3PExpr(pParse, TK_AND, selPWhere(p), pSubWhere));
                setSelPWhere(pSub, null);
            }
            setSelPSrc(pSub, null);
            _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&sqlite3SelectDeleteGeneric)), pSub);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CheckOnCtx (select.c:7392) — Walker callback context type.
// ════════════════════════════════════════════════════════════════════════════
pub const CheckOnCtx = extern struct {
    pSrc: Ptr,
    iJoin: c_int,
    bFuncArg: c_int,
    pParent: ?*CheckOnCtx,
};

inline fn hasRightJoin(pSrc: Ptr) bool {
    return (srcFgJoinType(srcItemAt(pSrc, 0)) & JT_LTORJ) != 0;
}

// ════════════════════════════════════════════════════════════════════════════
// selectCheckOnClausesExpr (select.c:7409) static — Walker xExpr cb.
// ════════════════════════════════════════════════════════════════════════════
fn selectCheckOnClausesExpr(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    var pCtx: ?*CheckOnCtx = @ptrCast(@alignCast(rdp(pWalker, Walker_u)));
    if (hasProp(pExpr, EP_OuterON) or
        (hasProp(pExpr, EP_InnerON) and hasRightJoin(pCtx.?.pSrc)))
    {
        if (pCtx.?.iJoin == 0) {
            pCtx.?.iJoin = exprWJoin(pExpr);
            _ = c.sqlite3WalkExprNN(pWalker, pExpr);
            pCtx.?.iJoin = 0;
            return WRC_Prune;
        }
    }

    if (exprOp(pExpr) == TK_COLUMN) {
        while (true) {
            const pSrc = pCtx.?.pSrc;
            const nSrc = srcNSrc(pSrc);
            const iTab = exprITable(pExpr);
            var ii: c_int = 0;
            while (ii < nSrc and itemICursor(srcItemAt(pSrc, ii)) != iTab) : (ii += 1) {}
            if (ii < nSrc) {
                if (pCtx.?.iJoin != 0 and iTab > pCtx.?.iJoin) {
                    c.sqlite3ErrorMsg(rdp(pWalker, Walker_pParse), "%s references tables to its right", if (pCtx.?.bFuncArg != 0) @as(?[*:0]const u8, "table-function argument") else @as(?[*:0]const u8, "ON clause"));
                    return WRC_Abort;
                }
                break;
            }
            pCtx = pCtx.?.pParent;
            if (pCtx == null) break;
        }
    }
    return WRC_Continue;
}

// ════════════════════════════════════════════════════════════════════════════
// selectCheckOnClausesSelect (select.c:7467) static — Walker xSelect cb.
// ════════════════════════════════════════════════════════════════════════════
fn selectCheckOnClausesSelect(pWalker: Ptr, pSelect: Ptr) callconv(.c) c_int {
    const pCtx: ?*CheckOnCtx = @ptrCast(@alignCast(rdp(pWalker, Walker_u)));
    if (selPSrc(pSelect) == pCtx.?.pSrc or srcNSrc(selPSrc(pSelect)) == 0) {
        return WRC_Continue;
    } else {
        var sCtx: CheckOnCtx = std.mem.zeroes(CheckOnCtx);
        sCtx.pSrc = selPSrc(pSelect);
        sCtx.pParent = pCtx;
        wr(?*anyopaque, pWalker, Walker_u, &sCtx);
        _ = c.sqlite3WalkSelect(pWalker, pSelect);
        wr(?*anyopaque, pWalker, Walker_u, pCtx);
        selClear(pSelect, SF_OnToWhere);
        return WRC_Prune;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3SelectCheckOnClauses (select.c:7488) EXPORT.
// ════════════════════════════════════════════════════════════════════════════
pub export fn sqlite3SelectCheckOnClauses(pParse: Ptr, pSelect: Ptr) void {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    _ = c.memset(&w, 0, sizeof_Walker);
    const pw: Ptr = @ptrCast(&w);
    var sCtx: CheckOnCtx = std.mem.zeroes(CheckOnCtx);
    wr(?*anyopaque, pw, Walker_pParse, pParse);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&selectCheckOnClausesExpr)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&selectCheckOnClausesSelect)));
    wr(?*anyopaque, pw, Walker_u, &sCtx);
    sCtx.pSrc = selPSrc(pSelect);
    _ = c.sqlite3WalkExpr(pw, selPWhere(pSelect));
    selClear(pSelect, SF_OnToWhere);

    sCtx.bFuncArg = 1;
    const n = srcNSrc(selPSrc(pSelect));
    var ii: c_int = 0;
    while (ii < n) : (ii += 1) {
        const pItem = srcItemAt(selPSrc(pSelect), ii);
        if (srcHas(pItem, FG_isTabFunc) and (srcFgJoinType(pItem) & JT_OUTER) != 0) {
            sCtx.iJoin = itemICursor(pItem);
            _ = c.sqlite3WalkExprList(pw, itemU1(pItem)); // u1.pFuncArg
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3CopySortOrder (select.c:7528) static.
// ════════════════════════════════════════════════════════════════════════════
fn sqlite3CopySortOrder(p1: Ptr, p2: Ptr) c_int {
    if (p2 != null and listNExpr(p1) == listNExpr(p2)) {
        const n = listNExpr(p1);
        var ii: c_int = 0;
        while (ii < n) : (ii += 1) {
            const sf = itemSortFlags(elItem(p2, ii)) & KEYINFO_ORDER_DESC;
            setItemSortFlags(elItem(p1, ii), sf);
        }
        return 1;
    } else {
        return 0;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// sqlite3Select (select.c:7590) EXPORT — the core.
//
// The C original uses `goto select_end`.  Zig has no goto, so the whole body
// (up to the `select_end:` label) is wrapped in a labeled block `blk`.  Every
// `goto select_end` becomes `break :blk`.  The cleanup code that followed the
// label (delete pMinMaxOrderBy, ExplainQueryPlanPop, return rc) runs after the
// block.  `rc` is initialised to 1 (matching C) and updated to (nErr>0) on the
// normal completion path just before the implicit fall-through to the label.
// ════════════════════════════════════════════════════════════════════════════
pub export fn sqlite3Select(pParse: Ptr, p: Ptr, pDest: Ptr) c_int {
    @setEvalBranchQuota(1000000);
    var i: c_int = 0;
    var j: c_int = 0;
    var pWInfo: Ptr = undefined;
    var isAgg: c_int = undefined;
    var pEList: Ptr = null;
    var pTabList: Ptr = undefined;
    var pWhere: Ptr = undefined;
    var pGroupBy: Ptr = undefined;
    var pHaving: Ptr = undefined;
    var pAggInfo: Ptr = null;
    var rc: c_int = 1;
    var sDistinct: DistinctCtx = std.mem.zeroes(DistinctCtx);
    var sSort: SortCtx = std.mem.zeroes(SortCtx);
    var iEnd: c_int = undefined;
    var pMinMaxOrderBy: Ptr = null;
    var minMaxFlag: u8 = WHERE_ORDERBY_NORMAL;

    const db = parseDb(pParse);
    const v = c.sqlite3GetVdbe(pParse);
    if (p == null or parseNErr(pParse) != 0) {
        return 1;
    }
    if (c.sqlite3AuthCheck(pParse, SQLITE_SELECT, null, null, null) != 0) return 1;

    blk: {
        // tag-select-0100
        if (destEDest(pDest) <= SRT_DistQueue) { // IgnorableDistinct
            if (selPOrderBy(p) != null) {
                _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&c.sqlite3ExprListDeleteGeneric)), selPOrderBy(p));
                setSelPOrderBy(p, null);
            }
            selClear(p, SF_Distinct);
        }
        sqlite3SelectPrep(pParse, p, null);
        if (parseNErr(pParse) != 0) {
            break :blk;
        }

        // SF_UFSrcCheck — UPDATE...FROM duplicate target check.
        if (selHas(p, SF_UFSrcCheck)) {
            const p0 = srcItemAt(selPSrc(p), 0);
            if (sameSrcAlias(p0, selPSrc(p)) != 0) {
                const zNm: ?[*:0]const u8 = if (itemZAlias(p0) != null) @ptrCast(itemZAlias(p0)) else tabZName(itemPTab(p0));
                c.sqlite3ErrorMsg(pParse, "target object/alias may not appear in FROM clause: %s", zNm);
                break :blk;
            }
            selClear(p, SF_UFSrcCheck);
        }

        if (destEDest(pDest) == SRT_Output) {
            sqlite3GenerateColumnNames(pParse, p);
        }

        // WINDOWFUNC
        if (c.sqlite3WindowRewrite(pParse, p) != 0) {
            break :blk;
        }

        pTabList = selPSrc(p);
        isAgg = if ((selFlags(p) & SF_Aggregate) != 0) 1 else 0;
        sSort = std.mem.zeroes(SortCtx);
        sSort.pOrderBy = selPOrderBy(p);

        // tag-select-0200: FROM-clause flattening / join strength reduction.
        i = 0;
        while (selPPrior(p) == null and i < srcNSrc(pTabList)) : (i += 1) {
            const pItem = srcItemAt(pTabList, i);
            const pSub: Ptr = if (srcHas(pItem, FG_isSubquery)) itemSelect(pItem) else null;
            const pTab = itemPTab(pItem);

            // OUTER JOIN strength reduction. tag-select-0220
            if ((srcFgJoinType(pItem) & (JT_LEFT | JT_LTORJ)) != 0 and
                c.sqlite3ExprImpliesNonNullRow(selPWhere(p), itemICursor(pItem), @intCast(srcFgJoinType(pItem) & JT_LTORJ)) != 0 and
                optEnabled(db, OPT_SimplifyJoin))
            {
                if ((srcFgJoinType(pItem) & JT_LEFT) != 0) {
                    if ((srcFgJoinType(pItem) & JT_RIGHT) != 0) {
                        setSrcFgJoinType(pItem, srcFgJoinType(pItem) & ~JT_LEFT);
                    } else {
                        setSrcFgJoinType(pItem, srcFgJoinType(pItem) & ~(JT_LEFT | JT_OUTER));
                        unsetJoinExpr(selPWhere(p), itemICursor(pItem), 0);
                    }
                }
                if ((srcFgJoinType(pItem) & JT_LTORJ) != 0) {
                    j = i + 1;
                    while (j < srcNSrc(pTabList)) : (j += 1) {
                        const pI2 = srcItemAt(pTabList, j);
                        if ((srcFgJoinType(pI2) & JT_RIGHT) != 0) {
                            if ((srcFgJoinType(pI2) & JT_LEFT) != 0) {
                                setSrcFgJoinType(pI2, srcFgJoinType(pI2) & ~JT_RIGHT);
                            } else {
                                setSrcFgJoinType(pI2, srcFgJoinType(pI2) & ~(JT_RIGHT | JT_OUTER));
                                unsetJoinExpr(selPWhere(p), itemICursor(pI2), 1);
                            }
                        }
                    }
                    j = srcNSrc(pTabList) - 1;
                    while (j >= 0) : (j -= 1) {
                        const pIj = srcItemAt(pTabList, j);
                        setSrcFgJoinType(pIj, srcFgJoinType(pIj) & ~JT_LTORJ);
                        if ((srcFgJoinType(pIj) & JT_RIGHT) != 0) break;
                    }
                }
            }

            if (pSub == null) continue;

            // View column count mismatch.
            if (tabNCol(pTab) != listNExpr(selPEList(pSub))) {
                c.sqlite3ErrorMsg(pParse, "expected %d columns for '%s' but got %d", @as(c_int, tabNCol(pTab)), tabZName(pTab), listNExpr(selPEList(pSub)));
                break :blk;
            }

            // MATERIALIZED CTE is an optimization fence.
            if (srcHas(pItem, FG_isCte) and rd(u8, itemU2(pItem), CteUse_eM10d) == M10d_Yes) {
                continue;
            }

            // Do not flatten an aggregate subquery.
            if ((selFlags(pSub) & SF_Aggregate) != 0) continue;

            // tag-select-0230: superfluous ORDER BY removal.
            if (selPOrderBy(pSub) != null and
                (selPOrderBy(p) != null or srcNSrc(pTabList) > 1) and
                selPLimit(pSub) == null and
                (selFlags(pSub) & (SF_OrderByReqd | SF_Recursive)) == 0 and
                (selFlags(p) & SF_OrderByReqd) == 0 and
                optEnabled(db, OPT_OmitOrderBy))
            {
                _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&c.sqlite3ExprListDeleteGeneric)), selPOrderBy(pSub));
                setSelPOrderBy(pSub, null);
            }

            // Complex-result-set co-routine ORDER BY retention.
            if (selPOrderBy(pSub) != null and
                i == 0 and
                (selFlags(p) & SF_ComplexResult) != 0 and
                (srcNSrc(pTabList) == 1 or (srcFgJoinType(srcItemAt(pTabList, 1)) & (JT_OUTER | JT_CROSS)) != 0))
            {
                continue;
            }

            // tag-select-0240
            if (flattenSubquery(pParse, p, i, isAgg) != 0) {
                if (parseNErr(pParse) != 0) break :blk;
                i = -1;
            }
            pTabList = selPSrc(p);
            if (dbMallocFailed(db)) break :blk;
            if (!(destEDest(pDest) <= SRT_Fifo)) { // !IgnorableOrderby
                sSort.pOrderBy = selPOrderBy(p);
            }
        }

        // tag-select-0300: compound SELECT.
        if (selPPrior(p) != null) {
            rc = multiSelect(pParse, p, pDest);
            if (selPNext(p) == null) c.sqlite3VdbeExplainPop(pParse);
            return rc;
        }

        // EXISTS-to-JOIN.
        if (parseGetBit(pParse, Parse_bft_byte, Parse_bHasExists_mask) and optEnabled(db, OPT_ExistsToJoin)) {
            existsToJoin(pParse, p, selPWhere(p));
            pTabList = selPSrc(p);
        }

        // tag-select-0330: WHERE-clause constant propagation.
        if (selPWhere(p) != null and
            exprOp(selPWhere(p)) == TK_AND and
            optEnabled(db, OPT_PropagateConst) and
            propagateConstants(pParse, p) != 0)
        {
            // (treeview only)
        }

        // tag-select-0350: count()-of-VIEW optimization.
        if (optEnabled(db, OPT_QueryFlattener | OPT_CountOfView) and
            countOfViewOptimization(pParse, p) != 0)
        {
            if (dbMallocFailed(db)) break :blk;
            pTabList = selPSrc(p);
        }

        // tag-select-0400: authorize + generate code for FROM-clause subqueries.
        i = 0;
        while (i < srcNSrc(pTabList)) : (i += 1) {
            const pItem = srcItemAt(pTabList, i);

            // tag-select-0410: authorize unreferenced tables.
            if (itemColUsed(pItem) == 0 and itemZName(pItem) != null) {
                var zDb: ?[*:0]const u8 = undefined;
                if (srcHas(pItem, FG_fixedSchema)) {
                    const iDb = c.sqlite3SchemaToIndex(parseDb(pParse), itemU4Ptr(pItem));
                    zDb = dbZDbSName(dbAt(db, iDb));
                } else if (srcHas(pItem, FG_isSubquery)) {
                    zDb = null;
                } else {
                    zDb = @ptrCast(itemU4Ptr(pItem)); // u4.zDatabase
                }
                _ = c.sqlite3AuthCheck(pParse, SQLITE_READ, @ptrCast(itemZName(pItem)), "", zDb);
            }

            if (!srcHas(pItem, FG_isSubquery)) continue;
            const pSubq = itemPSubq(pItem);
            const pSub = subqPSelect(pSubq);

            if (subqAddrFillSub(pSubq) != 0) continue;

            wr(c_int, pParse, Parse_nHeight, rd(c_int, pParse, Parse_nHeight) + c.sqlite3SelectExprHeight(p));

            // tag-select-0420: predicate push-down.
            if (optEnabled(db, OPT_PushDown) and
                (!srcHas(pItem, FG_isCte) or
                    (rd(u8, itemU2(pItem), CteUse_eM10d) != M10d_Yes and rd(c_int, itemU2(pItem), CteUse_nUse) < 2)) and
                pushDownWhereTerms(pParse, pSub, selPWhere(p), pTabList, i) != 0)
            {
                // (treeview only)
            }

            // tag-select-0440: NULL out unused subquery result columns.
            if (optEnabled(db, OPT_NullUnusedCols) and
                disableUnusedSubqueryResultColumns(pItem) != 0)
            {
                // (treeview only)
            }

            const zSavedAuthContext = rdp(pParse, Parse_zAuthContext);
            wr(?*anyopaque, pParse, Parse_zAuthContext, itemZName(pItem));

            // tag-select-0480: generate byte-code for the subquery.
            var dest: [sizeof_SelectDest]u8 align(8) = undefined;
            const pdest: Ptr = @ptrCast(&dest);
            if (fromClauseTermCanBeCoroutine(pParse, pTabList, i, @bitCast(@as(u32, @truncate(selFlags(p))))) != 0) {
                // tag-select-0482: co-routine.
                const addrTop = c.sqlite3VdbeCurrentAddr(v) + 1;
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                setSubqRegReturn(pSubq, rd(c_int, pParse, Parse_nMem));
                _ = c.sqlite3VdbeAddOp3(v, OP.InitCoroutine, subqRegReturn(pSubq), 0, addrTop);
                setSubqAddrFillSub(pSubq, addrTop);
                sqlite3SelectDestInit(pdest, SRT_Coroutine, subqRegReturn(pSubq));
                c.sqlite3VdbeExplain(pParse, 1, "CO-ROUTINE %!S", pItem);
                _ = sqlite3Select(pParse, pSub, pdest);
                wr(i16, itemPTab(pItem), Table_nRowLogEst, selNSelectRow(pSub));
                srcSet(pItem, FG_viaCoroutine);
                setSubqRegResult(pSubq, destISdst(pdest));
                c.sqlite3VdbeEndCoroutine(v, subqRegReturn(pSubq));
                c.sqlite3VdbeJumpHere(v, addrTop - 1);
                c.sqlite3ClearTempRegCache(pParse);
            } else if (srcHas(pItem, FG_isCte) and rd(c_int, itemU2(pItem), CteUse_addrM9e) > 0) {
                // tag-select-0484: reuse previously materialized CTE.
                const pCteUse = itemU2(pItem);
                _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, rd(c_int, pCteUse, CteUse_regRtn), rd(c_int, pCteUse, CteUse_addrM9e));
                if (itemICursor(pItem) != rd(c_int, pCteUse, CteUse_iCur)) {
                    _ = c.sqlite3VdbeAddOp2(v, OP.OpenDup, itemICursor(pItem), rd(c_int, pCteUse, CteUse_iCur));
                }
                setSelNSelectRow(pSub, @intCast(rd(i16, pCteUse, CteUse_nRowEst)));
            } else blk2: {
                const pPrior = isSelfJoinView(pTabList, pItem, 0, i);
                if (pPrior != null) {
                    // tag-select-0486: reuse previously materialized view.
                    const pPriorSubq = itemPSubq(pPrior);
                    if (subqAddrFillSub(pPriorSubq) != 0) {
                        _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, subqRegReturn(pPriorSubq), subqAddrFillSub(pPriorSubq));
                    }
                    _ = c.sqlite3VdbeAddOp2(v, OP.OpenDup, itemICursor(pItem), itemICursor(pPrior));
                    setSelNSelectRow(pSub, selNSelectRow(subqPSelect(pPriorSubq)));
                    break :blk2;
                }
                // tag-select-0488: materialize the view.
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                setSubqRegReturn(pSubq, rd(c_int, pParse, Parse_nMem));
                const topAddr = c.sqlite3VdbeAddOp0(v, OP.Goto);
                setSubqAddrFillSub(pSubq, topAddr + 1);
                srcSet(pItem, FG_isMaterialized);
                var onceAddr: c_int = 0;
                if (!srcHas(pItem, FG_isCorrelated)) {
                    onceAddr = c.sqlite3VdbeAddOp0(v, OP.Once);
                }
                sqlite3SelectDestInit(pdest, SRT_EphemTab, itemICursor(pItem));
                c.sqlite3VdbeExplain(pParse, 1, "MATERIALIZE %!S", pItem);
                _ = sqlite3Select(pParse, pSub, pdest);
                wr(i16, itemPTab(pItem), Table_nRowLogEst, selNSelectRow(pSub));
                if (onceAddr != 0) c.sqlite3VdbeJumpHere(v, onceAddr);
                _ = c.sqlite3VdbeAddOp2(v, OP.Return, subqRegReturn(pSubq), topAddr + 1);
                c.sqlite3VdbeJumpHere(v, topAddr);
                c.sqlite3ClearTempRegCache(pParse);
                if (srcHas(pItem, FG_isCte) and !srcHas(pItem, FG_isCorrelated)) {
                    const pCteUse = itemU2(pItem);
                    wr(c_int, pCteUse, CteUse_addrM9e, subqAddrFillSub(pSubq));
                    wr(c_int, pCteUse, CteUse_regRtn, subqRegReturn(pSubq));
                    wr(c_int, pCteUse, CteUse_iCur, itemICursor(pItem));
                    wr(i16, pCteUse, CteUse_nRowEst, selNSelectRow(pSub));
                }
            }
            if (dbMallocFailed(db)) break :blk;
            wr(c_int, pParse, Parse_nHeight, rd(c_int, pParse, Parse_nHeight) - c.sqlite3SelectExprHeight(p));
            wr(?*anyopaque, pParse, Parse_zAuthContext, zSavedAuthContext);
        }

        // Local copies of SELECT clauses.
        pEList = selPEList(p);
        pWhere = selPWhere(p);
        pGroupBy = selPGroupBy(p);
        pHaving = selPHaving(p);
        sDistinct.isTnct = if ((selFlags(p) & SF_Distinct) != 0) 1 else 0;

        // tag-select-0500: DISTINCT ORDER BY -> GROUP BY.
        if ((selFlags(p) & (SF_Distinct | SF_Aggregate)) == SF_Distinct and
            sqlite3CopySortOrder(pEList, sSort.pOrderBy) != 0 and
            c.sqlite3ExprListCompare(pEList, sSort.pOrderBy, -1) == 0 and
            optEnabled(db, OPT_GroupByOrder) and
            selPWin(p) == null)
        {
            selClear(p, SF_Distinct);
            pGroupBy = c.sqlite3ExprListDup(db, pEList, 0);
            setSelPGroupBy(p, pGroupBy);
            if (pGroupBy != null) {
                const n = listNExpr(pGroupBy);
                i = 0;
                while (i < n) : (i += 1) {
                    setItemIOrderByCol(elItem(pGroupBy, i), @intCast(i + 1));
                }
            }
            selSet(p, SF_Aggregate);
            sDistinct.isTnct = 2;
        }

        // tag-select-0600: set up ORDER BY ephemeral index.
        if (sSort.pOrderBy != null) {
            const pKeyInfo = sqlite3KeyInfoFromExprList(pParse, sSort.pOrderBy, 0, listNExpr(pEList));
            sSort.iECursor = rd(c_int, pParse, Parse_nTab);
            wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
            sSort.addrSortIndex = c.sqlite3VdbeAddOp4(v, OP.OpenEphemeral, sSort.iECursor, listNExpr(sSort.pOrderBy) + 1 + listNExpr(pEList), 0, @ptrCast(pKeyInfo), P4_KEYINFO);
        } else {
            sSort.addrSortIndex = -1;
        }

        // tag-select-0630: open output ephemeral table.
        if (destEDest(pDest) == SRT_EphemTab) {
            _ = c.sqlite3VdbeAddOp2(v, OP.OpenEphemeral, destISDParm(pDest), listNExpr(pEList));
            if (selHas(p, SF_NestedFrom)) {
                var ii: c_int = listNExpr(pEList) - 1;
                while (ii > 0 and !itemBUsed(elItem(pEList, ii))) : (ii -= 1) {
                    c.sqlite3ExprDelete(db, itemExpr(elItem(pEList, ii)));
                    c.sqlite3DbFree(db, @ptrCast(itemZEName(elItem(pEList, ii))));
                    setListNExpr(pEList, listNExpr(pEList) - 1);
                }
                ii = 0;
                while (ii < listNExpr(pEList)) : (ii += 1) {
                    if (!itemBUsed(elItem(pEList, ii))) setExprOp(itemExpr(elItem(pEList, ii)), @intCast(TK_NULL));
                }
            }
        }

        // tag-select-0650: set the limiter.
        iEnd = c.sqlite3VdbeMakeLabel(pParse);
        if ((selFlags(p) & SF_FixedLimit) == 0) {
            setSelNSelectRow(p, 320);
        }
        if (selPLimit(p) != null) computeLimitRegisters(pParse, p, iEnd);
        if (selILimit(p) == 0 and sSort.addrSortIndex >= 0) {
            c.sqlite3VdbeChangeOpcode(v, sSort.addrSortIndex, OP.SorterOpen);
            sSort.sortFlags |= SORTFLAG_UseSorter;
        }

        // tag-select-0680: open DISTINCT ephemeral index.
        if (selHas(p, SF_Distinct)) {
            sDistinct.tabTnct = rd(c_int, pParse, Parse_nTab);
            wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
            sDistinct.addrTnct = c.sqlite3VdbeAddOp4(v, OP.OpenEphemeral, sDistinct.tabTnct, 0, 0, @ptrCast(sqlite3KeyInfoFromExprList(pParse, selPEList(p), 0, 0)), P4_KEYINFO);
            c.sqlite3VdbeChangeP5(v, @intCast(BTREE_UNORDERED));
            sDistinct.eTnctType = @intCast(WHERE_DISTINCT_UNORDERED);
        } else {
            sDistinct.eTnctType = @intCast(WHERE_DISTINCT_NOOP);
        }

        if (isAgg == 0 and pGroupBy == null) {
            // tag-select-0700: no aggregate, no GROUP BY.
            const wctrlFlags: u16 = (if (sDistinct.isTnct != 0) WHERE_WANT_DISTINCT else @as(u16, 0)) | @as(u16, @intCast(selFlags(p) & SF_FixedLimit));
            const pWin = selPWin(p);
            if (pWin != null) {
                c.sqlite3WindowCodeInit(pParse, p);
            }

            pWInfo = c.sqlite3WhereBegin(pParse, pTabList, pWhere, sSort.pOrderBy, selPEList(p), p, wctrlFlags, @intCast(selNSelectRow(p)));
            if (pWInfo == null) break :blk;
            if (c.sqlite3WhereOutputRowCount(pWInfo) < selNSelectRow(p)) {
                setSelNSelectRow(p, c.sqlite3WhereOutputRowCount(pWInfo));
                if (destEDest(pDest) <= SRT_DistQueue and destEDest(pDest) >= SRT_DistFifo) {
                    setSelNSelectRow(p, selNSelectRow(p) - 30);
                }
            }
            if (sDistinct.isTnct != 0 and c.sqlite3WhereIsDistinct(pWInfo) != 0) {
                sDistinct.eTnctType = @intCast(c.sqlite3WhereIsDistinct(pWInfo));
            }
            if (sSort.pOrderBy != null) {
                sSort.nOBSat = c.sqlite3WhereIsOrdered(pWInfo);
                sSort.labelOBLopt = c.sqlite3WhereOrderByLimitOptLabel(pWInfo);
                if (sSort.nOBSat == listNExpr(sSort.pOrderBy)) {
                    sSort.pOrderBy = null;
                }
            }

            if (sSort.addrSortIndex >= 0 and sSort.pOrderBy == null) {
                _ = c.sqlite3VdbeChangeToNoop(v, sSort.addrSortIndex);
            }

            if (pWin != null) {
                const addrGosub = c.sqlite3VdbeMakeLabel(pParse);
                const iCont = c.sqlite3VdbeMakeLabel(pParse);
                const iBreak = c.sqlite3VdbeMakeLabel(pParse);
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                const regGosub = rd(c_int, pParse, Parse_nMem);

                c.sqlite3WindowCodeStep(pParse, p, pWInfo, regGosub, addrGosub);

                _ = c.sqlite3VdbeAddOp2(v, OP.Goto, 0, iBreak);
                c.sqlite3VdbeResolveLabel(v, addrGosub);
                sSort.labelOBLopt = 0;
                selectInnerLoop(pParse, p, -1, &sSort, &sDistinct, pDest, iCont, iBreak);
                c.sqlite3VdbeResolveLabel(v, iCont);
                _ = c.sqlite3VdbeAddOp1(v, OP.Return, regGosub);
                c.sqlite3VdbeResolveLabel(v, iBreak);
            } else {
                selectInnerLoop(pParse, p, -1, &sSort, &sDistinct, pDest, c.sqlite3WhereContinueLabel(pWInfo), c.sqlite3WhereBreakLabel(pWInfo));
                c.sqlite3WhereEnd(pWInfo);
            }
        } else {
            // tag-select-0800: aggregate and/or GROUP BY.
            var sNC: [sizeof_NameContext]u8 align(8) = undefined;
            const pNC: Ptr = @ptrCast(&sNC);
            var iAMem: c_int = undefined;
            var iBMem: c_int = undefined;
            var iUseFlag: c_int = undefined;
            var iAbortFlag: c_int = undefined;
            var groupBySort: c_int = undefined;
            var addrEnd: c_int = undefined;
            var sortPTab: c_int = 0;
            var sortOut: c_int = 0;
            var orderByGrp: c_int = 0;

            if (pGroupBy != null) {
                var k: c_int = listNExpr(selPEList(p));
                var idx: c_int = 0;
                while (k > 0) : (k -= 1) {
                    setItemIAlias(elItem(selPEList(p), idx), 0);
                    idx += 1;
                }
                k = listNExpr(pGroupBy);
                idx = 0;
                while (k > 0) : (k -= 1) {
                    setItemIAlias(elItem(pGroupBy, idx), 0);
                    idx += 1;
                }
                if (selNSelectRow(p) > 66) setSelNSelectRow(p, 66);
                if (sqlite3CopySortOrder(pGroupBy, sSort.pOrderBy) != 0 and
                    c.sqlite3ExprListCompare(pGroupBy, sSort.pOrderBy, -1) == 0)
                {
                    orderByGrp = 1;
                }
            } else {
                setSelNSelectRow(p, 0);
            }

            addrEnd = c.sqlite3VdbeMakeLabel(pParse);

            pAggInfo = c.sqlite3DbMallocZero(db, sizeof_AggInfo);
            if (pAggInfo != null) {
                _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&agginfoFree)), pAggInfo);
            }
            if (dbMallocFailed(db)) {
                break :blk;
            }
            wr(c_int, pAggInfo, AggInfo_selId, selId(p));
            _ = c.memset(pNC, 0, sizeof_NameContext);
            wr(?*anyopaque, pNC, NameContext_pParse, pParse);
            wr(?*anyopaque, pNC, NameContext_pSrcList, pTabList);
            wr(?*anyopaque, pNC, NameContext_uNC, pAggInfo); // uNC.pAggInfo
            if (config.sqlite_debug) {
                wr(c_int, pNC, NameContext_ncFlags, NC_UAggInfo);
            }
            wr(c_int, pAggInfo, AggInfo_nSortingColumn, if (pGroupBy != null) listNExpr(pGroupBy) else 0);
            wr(?*anyopaque, pAggInfo, AggInfo_pGroupBy, pGroupBy);
            c.sqlite3ExprAnalyzeAggList(pNC, pEList);
            c.sqlite3ExprAnalyzeAggList(pNC, sSort.pOrderBy);
            if (pHaving != null) {
                if (pGroupBy != null) {
                    havingToWhere(pParse, p);
                    pWhere = selPWhere(p);
                }
                c.sqlite3ExprAnalyzeAggregates(pNC, pHaving);
            }
            wr(c_int, pAggInfo, AggInfo_nAccumulator, aiNColumn(pAggInfo));
            if (selPGroupBy(p) == null and selPHaving(p) == null and aiNFunc(pAggInfo) == 1) {
                minMaxFlag = minMaxQuery(db, rdp(aiFuncAt(pAggInfo, 0), AggInfo_func_pFExpr), &pMinMaxOrderBy);
            } else {
                minMaxFlag = WHERE_ORDERBY_NORMAL;
            }
            analyzeAggFuncArgs(pAggInfo, pNC);
            if (dbMallocFailed(db)) break :blk;

            // tag-select-0810: GROUP BY aggregates.
            if (pGroupBy != null) {
                var addrSortingIdx: c_int = undefined;
                var pDistinct: Ptr = null;
                var distFlag: u16 = 0;
                var eDist: c_int = WHERE_DISTINCT_NOOP;

                if (aiNFunc(pAggInfo) == 1 and
                    rd(c_int, aiFuncAt(pAggInfo, 0), AggInfo_func_iDistinct) >= 0 and
                    rdp(aiFuncAt(pAggInfo, 0), AggInfo_func_pFExpr) != null and
                    exprPList(rdp(aiFuncAt(pAggInfo, 0), AggInfo_func_pFExpr)) != null)
                {
                    const pF0Expr = rdp(aiFuncAt(pAggInfo, 0), AggInfo_func_pFExpr);
                    var pExpr = itemExpr(elItem(exprPList(pF0Expr), 0));
                    pExpr = c.sqlite3ExprDup(db, pExpr, 0);
                    pDistinct = c.sqlite3ExprListDup(db, pGroupBy, 0);
                    pDistinct = c.sqlite3ExprListAppend(pParse, pDistinct, pExpr);
                    distFlag = if (pDistinct != null) (WHERE_WANT_DISTINCT | WHERE_AGG_DISTINCT) else 0;
                }

                setAiSortingIdx(pAggInfo, rd(c_int, pParse, Parse_nTab));
                wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
                const pKeyInfo = sqlite3KeyInfoFromExprList(pParse, pGroupBy, 0, aiNColumn(pAggInfo));
                addrSortingIdx = c.sqlite3VdbeAddOp4(v, OP.SorterOpen, aiSortingIdx(pAggInfo), aiNSortingColumn(pAggInfo), 0, @ptrCast(pKeyInfo), P4_KEYINFO);

                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                iUseFlag = rd(c_int, pParse, Parse_nMem);
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                iAbortFlag = rd(c_int, pParse, Parse_nMem);
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                const regOutputRow = rd(c_int, pParse, Parse_nMem);
                var addrOutputRow = c.sqlite3VdbeMakeLabel(pParse);
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                const regReset = rd(c_int, pParse, Parse_nMem);
                const addrReset = c.sqlite3VdbeMakeLabel(pParse);
                iAMem = rd(c_int, pParse, Parse_nMem) + 1;
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + listNExpr(pGroupBy));
                iBMem = rd(c_int, pParse, Parse_nMem) + 1;
                wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + listNExpr(pGroupBy));
                _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 0, iAbortFlag);
                _ = c.sqlite3VdbeAddOp3(v, OP.Null, 0, iAMem, iAMem + listNExpr(pGroupBy) - 1);
                c.sqlite3ExprNullRegisterRange(pParse, iAMem, listNExpr(pGroupBy));

                _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, regReset, addrReset);
                pWInfo = c.sqlite3WhereBegin(pParse, pTabList, pWhere, pGroupBy, pDistinct, p, (if (sDistinct.isTnct == 2) WHERE_DISTINCTBY else WHERE_GROUPBY) | (if (orderByGrp != 0) WHERE_SORTBYGROUP else @as(u16, 0)) | distFlag, 0);
                if (pWInfo == null) {
                    c.sqlite3ExprListDelete(db, pDistinct);
                    break :blk;
                }
                if (rdp(pParse, Parse_pIdxEpr) != null) {
                    optimizeAggregateUseOfIndexedExpr(pParse, p, pAggInfo, pNC);
                }
                assignAggregateRegisters(pParse, pAggInfo);
                eDist = c.sqlite3WhereIsDistinct(pWInfo);
                if (c.sqlite3WhereIsOrdered(pWInfo) == listNExpr(pGroupBy)) {
                    groupBySort = 0;
                } else {
                    groupBySort = 1;
                    const nGroupBy = listNExpr(pGroupBy);
                    var nCol = nGroupBy;
                    j = nGroupBy;
                    i = 0;
                    while (i < aiNColumn(pAggInfo)) : (i += 1) {
                        if (rd(c_int, aiColAt(pAggInfo, i), AggInfo_col_iSorterColumn) >= j) {
                            nCol += 1;
                            j += 1;
                        }
                    }
                    const regBase = c.sqlite3GetTempRange(pParse, nCol);
                    _ = c.sqlite3ExprCodeExprList(pParse, pGroupBy, regBase, 0, 0);
                    j = nGroupBy;
                    setAiDirectMode(pAggInfo, 1);
                    i = 0;
                    while (i < aiNColumn(pAggInfo)) : (i += 1) {
                        const pCol = aiColAt(pAggInfo, i);
                        if (rd(c_int, pCol, AggInfo_col_iSorterColumn) >= j) {
                            c.sqlite3ExprCode(pParse, rdp(pCol, AggInfo_col_pCExpr), j + regBase);
                            j += 1;
                        }
                    }
                    setAiDirectMode(pAggInfo, 0);
                    const regRecord = c.sqlite3GetTempReg(pParse);
                    _ = c.sqlite3VdbeAddOp3(v, OP.MakeRecord, regBase, nCol, regRecord);
                    _ = c.sqlite3VdbeAddOp2(v, OP.SorterInsert, aiSortingIdx(pAggInfo), regRecord);
                    c.sqlite3ReleaseTempReg(pParse, regRecord);
                    c.sqlite3ReleaseTempRange(pParse, regBase, nCol);
                    c.sqlite3WhereEnd(pWInfo);
                    sortPTab = rd(c_int, pParse, Parse_nTab);
                    setAiSortingIdxPTab(pAggInfo, sortPTab);
                    wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
                    sortOut = c.sqlite3GetTempReg(pParse);
                    _ = c.sqlite3VdbeAddOp3(v, OP.OpenPseudo, sortPTab, sortOut, nCol);
                    _ = c.sqlite3VdbeAddOp2(v, OP.SorterSort, aiSortingIdx(pAggInfo), addrEnd);
                    setAiUseSortingIdx(pAggInfo, 1);
                }

                if (rdp(pParse, Parse_pIdxEpr) != null) {
                    aggregateConvertIndexedExprRefToColumn(pAggInfo);
                }

                if (orderByGrp != 0 and optEnabled(db, OPT_GroupByOrder) and
                    (groupBySort != 0 or c.sqlite3WhereIsSorted(pWInfo) != 0))
                {
                    sSort.pOrderBy = null;
                    _ = c.sqlite3VdbeChangeToNoop(v, sSort.addrSortIndex);
                }

                const addrTopOfLoop = c.sqlite3VdbeCurrentAddr(v);
                if (groupBySort != 0) {
                    _ = c.sqlite3VdbeAddOp3(v, OP.SorterData, aiSortingIdx(pAggInfo), sortOut, sortPTab);
                }
                j = 0;
                while (j < listNExpr(pGroupBy)) : (j += 1) {
                    const iOrderByCol = itemIOrderByCol(elItem(pGroupBy, j));
                    if (groupBySort != 0) {
                        _ = c.sqlite3VdbeAddOp3(v, OP.Column, sortPTab, j, iBMem + j);
                    } else {
                        setAiDirectMode(pAggInfo, 1);
                        c.sqlite3ExprCode(pParse, itemExpr(elItem(pGroupBy, j)), iBMem + j);
                    }
                    if (iOrderByCol != 0) {
                        var pX = itemExpr(elItem(selPEList(p), @as(c_int, @intCast(iOrderByCol)) - 1));
                        var pBase = c.sqlite3ExprSkipCollateAndLikely(pX);
                        while (pBase != null and exprOp(pBase) == TK_IF_NULL_ROW) {
                            pX = exprPLeft(pBase);
                            pBase = c.sqlite3ExprSkipCollateAndLikely(pX);
                        }
                        if (pBase != null and exprOp(pBase) != TK_AGG_COLUMN and exprOp(pBase) != TK_REGISTER) {
                            c.sqlite3ExprToRegister(pX, iAMem + j);
                        }
                    }
                }
                _ = c.sqlite3VdbeAddOp4(v, OP.Compare, iAMem, iBMem, listNExpr(pGroupBy), @ptrCast(sqlite3KeyInfoRef(pKeyInfo)), P4_KEYINFO);
                const addr1 = c.sqlite3VdbeCurrentAddr(v);
                _ = c.sqlite3VdbeAddOp3(v, OP.Jump, addr1 + 1, 0, addr1 + 1);

                _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, regOutputRow, addrOutputRow);
                c.sqlite3ExprCodeMove(pParse, iBMem, iAMem, listNExpr(pGroupBy));
                _ = c.sqlite3VdbeAddOp2(v, OP.IfPos, iAbortFlag, addrEnd);
                _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, regReset, addrReset);

                c.sqlite3VdbeJumpHere(v, addr1);
                updateAccumulator(pParse, iUseFlag, pAggInfo, eDist);
                _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 1, iUseFlag);

                if (groupBySort != 0) {
                    _ = c.sqlite3VdbeAddOp2(v, OP.SorterNext, aiSortingIdx(pAggInfo), addrTopOfLoop);
                } else {
                    c.sqlite3WhereEnd(pWInfo);
                    _ = c.sqlite3VdbeChangeToNoop(v, addrSortingIdx);
                }
                c.sqlite3ExprListDelete(db, pDistinct);

                _ = c.sqlite3VdbeAddOp2(v, OP.Gosub, regOutputRow, addrOutputRow);

                c.sqlite3VdbeGoto(v, addrEnd);

                const addrSetAbort = c.sqlite3VdbeCurrentAddr(v);
                _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 1, iAbortFlag);
                _ = c.sqlite3VdbeAddOp1(v, OP.Return, regOutputRow);
                c.sqlite3VdbeResolveLabel(v, addrOutputRow);
                addrOutputRow = c.sqlite3VdbeCurrentAddr(v);
                _ = c.sqlite3VdbeAddOp2(v, OP.IfPos, iUseFlag, addrOutputRow + 2);
                _ = c.sqlite3VdbeAddOp1(v, OP.Return, regOutputRow);
                finalizeAggFunctions(pParse, pAggInfo);
                c.sqlite3ExprIfFalse(pParse, pHaving, addrOutputRow + 1, SQLITE_JUMPIFNULL);
                selectInnerLoop(pParse, p, -1, &sSort, &sDistinct, pDest, addrOutputRow + 1, addrSetAbort);
                _ = c.sqlite3VdbeAddOp1(v, OP.Return, regOutputRow);

                c.sqlite3VdbeResolveLabel(v, addrReset);
                resetAccumulator(pParse, pAggInfo);
                _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 0, iUseFlag);
                _ = c.sqlite3VdbeAddOp1(v, OP.Return, regReset);

                if (distFlag != 0 and eDist != WHERE_DISTINCT_NOOP) {
                    const pF = aiFuncAt(pAggInfo, 0);
                    fixDistinctOpenEph(pParse, eDist, rd(c_int, pF, AggInfo_func_iDistinct), rd(c_int, pF, AggInfo_func_iDistAddr));
                }
            } else {
                // tag-select-0820: aggregate without GROUP BY.
                const pTab = isSimpleCount(p, pAggInfo);
                if (pTab != null) {
                    // tag-select-0821: SELECT count(*) FROM <tbl>.
                    const iDb = c.sqlite3SchemaToIndex(parseDb(pParse), tabPSchema(pTab));
                    const iCsr = rd(c_int, pParse, Parse_nTab);
                    wr(c_int, pParse, Parse_nTab, rd(c_int, pParse, Parse_nTab) + 1);
                    var pKeyInfo: Ptr = null;
                    var pBest: Ptr = null;
                    var iRoot: c_int = rd(c_int, pTab, Table_tnum);

                    c.sqlite3CodeVerifySchema(pParse, iDb);
                    c.sqlite3TableLock(pParse, iDb, rd(c_int, pTab, Table_tnum), 0, tabZName(pTab));

                    if (!hasRowid(pTab)) pBest = c.sqlite3PrimaryKeyIndex(pTab);
                    if (!srcHas(srcItemAt(selPSrc(p), 0), FG_notIndexed)) {
                        var pIdx = tabPIndex(pTab);
                        while (pIdx != null) : (pIdx = rdp(pIdx, Index_pNext)) {
                            if ((rd(u8, pIdx, Index_bUnordered_byte) & Index_bUnordered_mask) == 0 and
                                rd(i16, pIdx, Index_szIdxRow) < rd(i16, pTab, Table_szTabRow) and
                                rdp(pIdx, Index_pPartIdxWhere) == null and
                                (pBest == null or rd(i16, pIdx, Index_szIdxRow) < rd(i16, pBest, Index_szIdxRow)))
                            {
                                pBest = pIdx;
                            }
                        }
                    }
                    if (pBest != null) {
                        iRoot = rd(c_int, pBest, Index_tnum);
                        pKeyInfo = c.sqlite3KeyInfoOfIndex(pParse, pBest);
                    }

                    _ = c.sqlite3VdbeAddOp4Int(v, OP.OpenRead, iCsr, iRoot, iDb, 1);
                    if (pKeyInfo != null) {
                        c.sqlite3VdbeChangeP4(v, -1, @ptrCast(pKeyInfo), P4_KEYINFO);
                    }
                    assignAggregateRegisters(pParse, pAggInfo);
                    _ = c.sqlite3VdbeAddOp2(v, OP.Count, iCsr, aggFuncReg(pAggInfo, 0));
                    _ = c.sqlite3VdbeAddOp1(v, OP.Close, iCsr);
                    explainSimpleCount(pParse, pTab, pBest);
                } else {
                    // tag-select-0822: general non-GROUP BY aggregate.
                    var regAcc: c_int = 0;
                    var pDistinct: Ptr = null;
                    var distFlag: u16 = 0;

                    if (aiNAccumulator(pAggInfo) != 0) {
                        i = 0;
                        while (i < aiNFunc(pAggInfo)) : (i += 1) {
                            const pFx = aiFuncAt(pAggInfo, i);
                            if (hasProp(rdp(pFx, AggInfo_func_pFExpr), EP_WinFunc)) {
                                continue;
                            }
                            if ((rd(u32, rdp(pFx, AggInfo_func_pFunc), FuncDef_funcFlags) & SQLITE_FUNC_NEEDCOLL) != 0) {
                                break;
                            }
                        }
                        if (i == aiNFunc(pAggInfo)) {
                            wr(c_int, pParse, Parse_nMem, rd(c_int, pParse, Parse_nMem) + 1);
                            regAcc = rd(c_int, pParse, Parse_nMem);
                            _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 0, regAcc);
                        }
                    } else if (aiNFunc(pAggInfo) == 1 and rd(c_int, aiFuncAt(pAggInfo, 0), AggInfo_func_iDistinct) >= 0) {
                        pDistinct = exprPList(rdp(aiFuncAt(pAggInfo, 0), AggInfo_func_pFExpr));
                        distFlag = if (pDistinct != null) (WHERE_WANT_DISTINCT | WHERE_AGG_DISTINCT) else 0;
                    }
                    assignAggregateRegisters(pParse, pAggInfo);
                    resetAccumulator(pParse, pAggInfo);

                    pWInfo = c.sqlite3WhereBegin(pParse, pTabList, pWhere, pMinMaxOrderBy, pDistinct, p, @as(u16, minMaxFlag) | distFlag, 0);
                    if (pWInfo == null) {
                        break :blk;
                    }
                    const eDist = c.sqlite3WhereIsDistinct(pWInfo);
                    updateAccumulator(pParse, regAcc, pAggInfo, eDist);
                    if (eDist != WHERE_DISTINCT_NOOP) {
                        const pF = aiAFunc(pAggInfo);
                        if (pF != null) {
                            fixDistinctOpenEph(pParse, eDist, rd(c_int, pF, AggInfo_func_iDistinct), rd(c_int, pF, AggInfo_func_iDistAddr));
                        }
                    }

                    if (regAcc != 0) _ = c.sqlite3VdbeAddOp2(v, OP.Integer, 1, regAcc);
                    if (minMaxFlag != 0) {
                        c.sqlite3WhereMinMaxOptEarlyOut(v, pWInfo);
                    }
                    c.sqlite3WhereEnd(pWInfo);
                    finalizeAggFunctions(pParse, pAggInfo);
                }

                sSort.pOrderBy = null;
                c.sqlite3ExprIfFalse(pParse, pHaving, addrEnd, SQLITE_JUMPIFNULL);
                selectInnerLoop(pParse, p, -1, null, null, pDest, addrEnd, addrEnd);
            }
            c.sqlite3VdbeResolveLabel(v, addrEnd);
        } // endif aggregate query

        if (sDistinct.eTnctType == WHERE_DISTINCT_UNORDERED) {
            explainTempTable(pParse, "DISTINCT");
        }

        // tag-select-0900: sort results.
        if (sSort.pOrderBy != null) {
            generateSortTail(pParse, p, &sSort, listNExpr(pEList), pDest);
        }

        c.sqlite3VdbeResolveLabel(v, iEnd);

        rc = if (parseNErr(pParse) > 0) 1 else 0;
    } // :blk  (== select_end)

    // select_end cleanup.
    c.sqlite3ExprListDelete(db, pMinMaxOrderBy);
    c.sqlite3VdbeExplainPop(pParse);
    return rc;
}

// ════════════ sqlite3SelectWalkAssert2 (SQLITE_DEBUG-only export) ════════════
// select.c:6360 — proves xSelectCallback2 is never invoked for this walker.
// In C it is `void sqlite3SelectWalkAssert2(Walker*, Select*){ assert(0); }`,
// compiled only under SQLITE_DEBUG.  Gate the export on config.sqlite_debug.
fn selectWalkAssert2(pWalker: Ptr, p: Ptr) callconv(.c) void {
    _ = pWalker;
    _ = p;
    unreachable; // assert(0)
}
comptime {
    if (config.sqlite_debug) {
        @export(&selectWalkAssert2, .{ .name = "sqlite3SelectWalkAssert2", .linkage = .strong });
    }
}
