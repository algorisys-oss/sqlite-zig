//! Zig port of SQLite's src/expr.c — expression analysis and VDBE code
//! generation.  This is the largest and most foundational codegen module:
//! it underpins SELECT/WHERE/INSERT/UPDATE/triggers.  Every non-static
//! function of expr.c is exported here with the same C ABI; static helpers
//! become private Zig fns.  Struct fields are accessed via ground-truth
//! offsets (src/c_layout.zig) using the raw-memory helper idiom shared with
//! build.zig / resolve.zig / window.zig.
//!
//! Config assumptions (true in BOTH production and the --dev testfixture):
//! SQLITE_OMIT_* all OFF (SUBQUERY, VIEW, TRIGGER, CTE, WINDOWFUNC, CAST,
//! GENERATED_COLUMNS, FLOATING_POINT, BLOB_LITERAL, HEX_INTEGER,
//! VIRTUALTABLE all present).  SQLITE_MAX_EXPR_DEPTH>0 (height enforcement).
//! SQLITE_ENABLE_CURSOR_HINTS, _OFFSET_SQL_FUNC, _STAT4, _SORTER_REFERENCES,
//! _COLUMN_USED_MASK, _STMT_SCANSTATUS, _UNKNOWN_SQL_FUNCTION,
//! _ALLOW_ROWID_IN_VIEW all OFF.  SQLITE_UNTESTABLE OFF (test-only inline
//! funcs present).  SQLITE_DEBUG / vvaFlags handled via config.sqlite_debug.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── raw memory helpers (copied from build.zig) ─────────────────────────────
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

// ─── EP_* flags (Expr.flags, u32) ───────────────────────────────────────────
const EP_OuterON: u32 = 0x000001;
const EP_InnerON: u32 = 0x000002;
const EP_Distinct: u32 = 0x000004;
const EP_HasFunc: u32 = 0x000008;
const EP_Agg: u32 = 0x000010;
const EP_FixedCol: u32 = 0x000020;
const EP_VarSelect: u32 = 0x000040;
const EP_DblQuoted: u32 = 0x000080;
const EP_InfixFunc: u32 = 0x000100;
const EP_Collate: u32 = 0x000200;
const EP_Commuted: u32 = 0x000400;
const EP_IntValue: u32 = 0x000800;
const EP_xIsSelect: u32 = 0x001000;
const EP_Skip: u32 = 0x002000;
const EP_Reduced: u32 = 0x004000;
const EP_Win: u32 = 0x008000;
const EP_TokenOnly: u32 = 0x010000;
const EP_FullSize: u32 = 0x020000;
const EP_IfNullRow: u32 = 0x040000;
const EP_Unlikely: u32 = 0x080000;
const EP_ConstFunc: u32 = 0x100000;
const EP_CanBeNull: u32 = 0x200000;
const EP_Subquery: u32 = 0x400000;
const EP_Leaf: u32 = 0x800000;
const EP_WinFunc: u32 = 0x1000000;
const EP_Subrtn: u32 = 0x2000000;
const EP_Quoted: u32 = 0x4000000;
const EP_Static: u32 = 0x8000000;
const EP_IsTrue: u32 = 0x10000000;
const EP_IsFalse: u32 = 0x20000000;
const EP_FromDDL: u32 = 0x40000000;
const EP_SubtArg: u32 = 0x80000000;
const EP_Propagate: u32 = EP_Collate | EP_Subquery | EP_HasFunc;

// vvaFlags (SQLITE_DEBUG only)
const EP_NoReduce: u8 = 0x01;
const EP_Immutable: u8 = 0x02;

// ─── TK_* token / opcode-aligned operator codes ─────────────────────────────
const TK_NOT: c_int = 19;
const TK_EXISTS: c_int = 20;
const TK_CAST: c_int = 36;
const TK_OR: c_int = 43;
const TK_AND: c_int = 44;
const TK_IS: c_int = 45;
const TK_ISNOT: c_int = 46;
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
const TK_RAISE: c_int = 72;
const TK_TRIGGER: c_int = 78;
const TK_NULLS: c_int = 83;
const TK_LSHIFT: c_int = 105;
const TK_RSHIFT: c_int = 106;
const TK_PLUS: c_int = 107;
const TK_MINUS: c_int = 108;
const TK_STAR: c_int = 109;
const TK_SLASH: c_int = 110;
const TK_REM: c_int = 111;
const TK_CONCAT: c_int = 112;
const TK_COLLATE: c_int = 114;
const TK_BITNOT: c_int = 115;
const TK_BITAND: c_int = 103;
const TK_BITOR: c_int = 104;
const TK_STRING: c_int = 118;
const TK_NULL: c_int = 122;
const TK_ALL: c_int = 136;
const TK_SELECT: c_int = 139;
const TK_DOT: c_int = 142;
const TK_ORDER: c_int = 146;
const TK_LIMIT: c_int = 149;
const TK_FLOAT: c_int = 154;
const TK_BLOB: c_int = 155;
const TK_INTEGER: c_int = 156;
const TK_VARIABLE: c_int = 157;
const TK_CASE: c_int = 158;
const TK_COLUMN: c_int = 168;
const TK_FILTER: c_int = 167;
const TK_AGG_FUNCTION: c_int = 169;
const TK_AGG_COLUMN: c_int = 170;
const TK_TRUEFALSE: c_int = 171;
const TK_FUNCTION: c_int = 172;
const TK_UPLUS: c_int = 173;
const TK_UMINUS: c_int = 174;
const TK_TRUTH: c_int = 175;
const TK_REGISTER: c_int = 176;
const TK_VECTOR: c_int = 177;
const TK_SELECT_COLUMN: c_int = 178;
const TK_IF_NULL_ROW: c_int = 179;
const TK_SPAN: c_int = 181;
const TK_ERROR: c_int = 182;

// ─── OP_* opcodes (resolved at link time from C; we reference them as the
// numeric token equivalents that vdbe.c aligns, or via extern consts where the
// value is not token-aligned).  For codegen we use sqlite3VdbeAddOp* which take
// the opcode as an int; pull the needed opcode constants from opcodes.h.
// To stay config-robust we declare them extern (they are #defines in C, so
// instead we hardcode from opcodes.h — these are stable within a vendored
// build).  Values fetched from vendor/tsrc/opcodes.h. ───────────────────────
const OP = struct {
    // token-aligned (asserted in C): equal to TK_*
    const Add = TK_PLUS;
    const Subtract = TK_MINUS;
    const Multiply = TK_STAR;
    const Divide = TK_SLASH;
    const Remainder = TK_REM;
    const Concat = TK_CONCAT;
    const BitAnd = TK_BITAND;
    const BitOr = TK_BITOR;
    const ShiftLeft = TK_LSHIFT;
    const ShiftRight = TK_RSHIFT;
    const And = TK_AND;
    const Or = TK_OR;
    const Not = TK_NOT;
    const BitNot = TK_BITNOT;
    const IsNull = TK_ISNULL;
    const NotNull = TK_NOTNULL;
    const Ne = TK_NE;
    const Eq = TK_EQ;
    const Gt = TK_GT;
    const Le = TK_LE;
    const Lt = TK_LT;
    const Ge = TK_GE;
};

// Non-token-aligned opcodes (numeric values from vendor opcodes.h, like
// window.zig hardcodes them).  Stable within the vendored build.
const op = struct {
    const Integer: c_int = 73;
    const Int64: c_int = 74;
    const Real: c_int = 154;
    const IsNull: c_int = 51;
    const NotNull: c_int = 52;
    const Offset: c_int = 95;
    const Null: c_int = 77;
    const Variable: c_int = 80;
    const Move: c_int = 81;
    const Copy: c_int = 82;
    const SCopy: c_int = 83;
    const Cast: c_int = 90;
    const Column: c_int = 96;
    const Rowid: c_int = 137;
    const Affinity: c_int = 98;
    const MakeRecord: c_int = 99;
    const IdxInsert: c_int = 140;
    const OpenEphemeral: c_int = 120;
    const OpenRead: c_int = 114;
    const OpenDup: c_int = 117;
    const NullRow: c_int = 138;
    const Once: c_int = 15;
    const Gosub: c_int = 10;
    const Return: c_int = 69;
    const BeginSubrtn: c_int = 76;
    const Blob: c_int = 79;
    const Goto: c_int = 9;
    const If: c_int = 16;
    const IfNot: c_int = 17;
    const IfNullRow: c_int = 20;
    const IsTrue: c_int = 93;
    const ZeroOrNull: c_int = 94;
    const AddImm: c_int = 88;
    const Param: c_int = 159;
    const CollSeq: c_int = 87;
    const Halt: c_int = 72;
    const Filter: c_int = 66;
    const Found: c_int = 29;
    const NotFound: c_int = 28;
    const SeekRowid: c_int = 30;
    const Rewind: c_int = 36;
    const Next: c_int = 40;
    const ElseEq: c_int = 59;
    const RealAffinity: c_int = 89;
    const ClrSubtype: c_int = 182;
    const TypeCheck: c_int = 97;
    const VColumn: c_int = 178;
    const Subtract: c_int = 108;
    const BitAnd: c_int = 103;
    const Ne: c_int = 53;
    const And: c_int = 44;
    const Or: c_int = 43;
};

// ─── affinity ───────────────────────────────────────────────────────────────
const SQLITE_AFF_NONE: u8 = 0x40;
const SQLITE_AFF_BLOB: u8 = 0x41;
const SQLITE_AFF_TEXT: u8 = 0x42;
const SQLITE_AFF_NUMERIC: u8 = 0x43;
const SQLITE_AFF_INTEGER: u8 = 0x44;
const SQLITE_AFF_REAL: u8 = 0x45;
const SQLITE_AFF_FLEXNUM: u8 = 0x46;
const SQLITE_AFF_DEFER: u8 = 0x58;

inline fn isNumericAffinity(aff: u8) bool {
    return aff >= SQLITE_AFF_NUMERIC;
}

// ─── misc constants ─────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_UTF8: c_int = 1;

const SQLITE_JUMPIFNULL: c_int = 0x10;
const SQLITE_NULLEQ: c_int = 0x80;

const SQLITE_LIMIT_EXPR_DEPTH: c_int = 3;
const SQLITE_LIMIT_VARIABLE_NUMBER: c_int = 9;
const SQLITE_LIMIT_COLUMN: c_int = 2;
const SQLITE_LIMIT_FUNCTION_ARG: c_int = 6;

const SQLITE_SO_ASC: c_int = 0;
const SQLITE_SO_DESC: c_int = 1;
const SQLITE_SO_UNDEFINED: c_int = -1;
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

const ENAME_NAME: c_uint = 0;
const ENAME_SPAN: c_uint = 1;

const IN_INDEX_ROWID: c_int = 1;
const IN_INDEX_EPH: c_int = 2;
const IN_INDEX_INDEX_ASC: c_int = 3;
const IN_INDEX_INDEX_DESC: c_int = 4;
const IN_INDEX_NOOP: c_int = 5;
const IN_INDEX_NOOP_OK: u32 = 0x0001;
const IN_INDEX_MEMBERSHIP: u32 = 0x0002;
const IN_INDEX_LOOP: u32 = 0x0004;

const XN_ROWID: c_int = -1;
const XN_EXPR: c_int = -2;

const OE_Rollback: c_int = 1;
const OE_Abort: c_int = 2;
const OE_Fail: c_int = 3;
const OE_Ignore: c_int = 4;

const SF_Distinct: u32 = 0x0000001;
const SF_All: u32 = 0x0000002;
const SF_Aggregate: u32 = 0x0000008;
const SF_ClonedRhsIn: u32 = 0x0000020;
const SF_Values: u32 = 0x0000200;
const SF_MultiValue: u32 = 0x0000400;
const SF_Correlated: u32 = 0x20000000;

const NC_UAggInfo: c_int = 0x000100;
const NC_InAggFunc: c_int = 0x020000;

const COLFLAG_VIRTUAL: u16 = 0x0020;
const COLFLAG_NOTAVAIL: u16 = 0x0080;
const COLFLAG_BUSY: u16 = 0x0100;
const COLFLAG_GENERATED: u16 = 0x0060;

const TF_Strict: u32 = 0x00010000;

const JT_LEFT: u8 = 0x08;
const JT_LTORJ: u8 = 0x40;

const OPFLAG_NOCHNG: u8 = 0x01;
const OPFLAG_TYPEOFARG: u8 = 0x80;
const OPFLAG_LENGTHARG: u8 = 0x40;
const OPFLAG_BYTELENARG: u8 = 0xc0;

const SQLITE_ECEL_DUP: u8 = 0x01;
const SQLITE_ECEL_FACTOR: u8 = 0x02;
const SQLITE_ECEL_REF: u8 = 0x04;
const SQLITE_ECEL_OMITREF: u8 = 0x08;

const INLINEFUNC_coalesce: c_int = 0;
const INLINEFUNC_iif: c_int = 5;
const INLINEFUNC_sqlite_offset: c_int = 6;
const INLINEFUNC_expr_compare: c_int = 3;
const INLINEFUNC_expr_implies_expr: c_int = 2;
const INLINEFUNC_implies_nonnull_row: c_int = 1;
const INLINEFUNC_affinity: c_int = 4;

const SQLITE_FUNC_NEEDCOLL: u32 = 0x0020;
const SQLITE_FUNC_LENGTH: u32 = 0x0040;
const SQLITE_FUNC_TYPEOF: u32 = 0x0080;
const SQLITE_FUNC_CONSTANT: u32 = 0x0800;
const SQLITE_FUNC_SLOCHNG: u32 = 0x2000;
const SQLITE_FUNC_INTERNAL: u32 = 0x00040000;
const SQLITE_FUNC_DIRECT: u32 = 0x00080000;
const SQLITE_FUNC_UNSAFE: u32 = 0x00200000;
const SQLITE_FUNC_INLINE: u32 = 0x00400000;
const SQLITE_RESULT_SUBTYPE: u32 = 0x01000000;
const SQLITE_SUBTYPE: u32 = 0x00100000;

const SQLITE_PREPARE_FROM_DDL: u32 = 0x40;
const SQLITE_TrustedSchema: u64 = 0x0000080000000000;
const SQLITE_EnableQPSG: u64 = 0x0000800000000000;
const DBFLAG_InternalFunc: u32 = 0x0040;
const SQLITE_BloomFilter: u32 = 0x00080000;

const SQLITE_INTEGER: c_int = 1;
const SQLITE_TEXT: c_int = 3;

// Must match vdbe.h exactly — a wrong value makes vdbeaux freeP4 misroute the
// P4 pointer (e.g. -12 is P4_VTAB: a mislabeled P4_REAL crashes VtabUnlock).
const P4_COLLSEQ: c_int = -2;
const P4_KEYINFO: c_int = -9;
const P4_STATIC: c_int = -1;
const P4_DYNAMIC: c_int = -7;
const P4_INT64: c_int = -14;
const P4_REAL: c_int = -13;
const P4_SUBRTNSIG: c_int = -18;
const P4_TABLE: c_int = -5;

const PARSE_MODE_RENAME: c_int = 1;
const PARSE_MODE_UNMAP: c_int = 3;
const WRC_Continue: c_int = 0;
const WRC_Prune: c_int = 1;
const WRC_Abort: c_int = 2;

const SMALLEST_INT64: i64 = @bitCast(@as(u64, 0x8000000000000000));
const BMS: c_int = @bitCast(@as(c_uint, @sizeOf(u64) * 8));

// ─── struct offsets (report missing ones to tools/offsets.c) ────────────────
const Expr_op = off("Expr_op", 0);
const Expr_affExpr = off("Expr_affExpr", 1);
const Expr_op2 = off("Expr_op2", 2);
const Expr_flags = off("Expr_flags", 4);
const Expr_u = off("Expr_u", 8);
const Expr_pLeft = off("Expr_pLeft", 16);
const Expr_pRight = off("Expr_pRight", 24);
const Expr_x = off("Expr_x", 32);
const Expr_nHeight = off("Expr_nHeight", 40);
const Expr_iTable = off("Expr_iTable", 44);
const Expr_iColumn = off("Expr_iColumn", 48);
const Expr_iAgg = off("Expr_iAgg", 50);
const Expr_w = off("Expr_w", 52);
const Expr_pAggInfo = off("Expr_pAggInfo", 56);
const Expr_y = off("Expr_y", 64);
const Expr_y_sub_regReturn = off("Expr_y_sub_regReturn", 68);
const sizeof_Expr = off("sizeof_Expr", 72);
const EXPR_FULLSIZE = sizeof_Expr;
const EXPR_REDUCEDSIZE = off("EXPR_REDUCEDSIZE", 44);
const EXPR_TOKENONLYSIZE = off("EXPR_TOKENONLYSIZE", 16);
const Expr_vvaFlags = off("Expr_vvaFlags", 3); // SQLITE_DEBUG only

const ExprList_nExpr = off("ExprList_nExpr", 0);
const ExprList_nAlloc = off("ExprList_nAlloc", 4);
const ExprList_a = off("ExprList_a", 8);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);
const ExprList_item_pExpr = off("ExprList_item_pExpr", 0);
const ExprList_item_zEName = off("ExprList_item_zEName", 8);
const ExprList_item_fg = off("ExprList_item_fg", 16);
const ExprList_item_u = off("ExprList_item_u", 20);
const ExprList_item_u_iConstExprReg = off("ExprList_item_u_iConstExprReg", 20);
const ExprList_item_u_x_iOrderByCol = off("ExprList_item_u_x_iOrderByCol", 20);

const Parse_db = off("Parse_db", 0);
const Parse_pVdbe = off("Parse_pVdbe", 16);
const Parse_nQueryLoop = off("Parse_nQueryLoop", 28);
const Parse_nTempReg = off("Parse_nTempReg", 31);
const Parse_prepFlags = off("Parse_prepFlags", 34);
const Parse_withinRJSubrtn = off("Parse_withinRJSubrtn", 35);
const Parse_mSubrtnSig = off("Parse_mSubrtnSig", 36);
const Parse_bft_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_okConstFactor: u8 = 0x80;
const Parse_nRangeReg = off("Parse_nRangeReg", 44);
const Parse_iRangeReg = off("Parse_iRangeReg", 48);
const Parse_nErr = off("Parse_nErr", 52);
const Parse_nTab = off("Parse_nTab", 56);
const Parse_nMem = off("Parse_nMem", 60);
const Parse_nLabel = off("Parse_nLabel", 72);
const Parse_pIdxEpr = off("Parse_pIdxEpr", 96);
const Parse_pIdxPartExpr = off("Parse_pIdxPartExpr", 104);
const Parse_pConstExpr = off("Parse_pConstExpr", 160);
const Parse_aTempReg = off("Parse_aTempReg", 168);
const Parse_iSelfTab = off("Parse_iSelfTab", 64);
const Parse_eParseMode = off("Parse_eParseMode", 300);
const Parse_pVList = off("Parse_pVList", 320);
const Parse_pReprepare = off("Parse_pReprepare", 328);
const Parse_zTail = off("Parse_zTail", 336);
const Parse_nested = off("Parse_nested", 30);
const Parse_explain = off("Parse_explain", 36); // not used; placeholder
const Parse_pTriggerTab = off("Parse_pTriggerTab", 344);
const ArraySize_aTempReg: usize = 8;

const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103);
const sqlite3_flags = off("sqlite3_flags", 48);
const sqlite3_mDbFlags = off("sqlite3_mDbFlags", 44);
const sqlite3_aLimit = off("sqlite3_aLimit", 136);
const sqlite3_enc = off("sqlite3_enc", 100);
const sqlite3_pDfltColl = off("sqlite3_pDfltColl", 16);
const sqlite3_errByteOffset = off("sqlite3_errByteOffset", 84);

const CollSeq_zName = off("CollSeq_zName", 0);

const Token_z = off("Token_z", 0);
const Token_n = off("Token_n", 8);
const sizeof_Token = off("sizeof_Token", 16);

const Table_zName = off("Table_zName", 0);
const Table_aCol = off("Table_aCol", 8);
const Table_pIndex = off("Table_pIndex", 16);
const Table_tnum = off("Table_tnum", 40);
const Table_tabFlags = off("Table_tabFlags", 48);
const Table_iPKey = off("Table_iPKey", 52);
const Table_nCol = off("Table_nCol", 54);
const Table_pSchema = off("Table_pSchema", 96);
const sizeof_Column = off("sizeof_Column", 24);
const Column_zCnName = off("Column_zCnName", 0);
const Column_notNull = off("Column_zCnName", 0); // notNull is low nibble of byte at zCnName+8
const Column_affinity = off("Column_affinity", 12);
const Column_colFlags = off("Column_colFlags", 16);
const Column_zCnName_strptr = off("Column_zCnName", 0);

const Index_pNext = off("Index_pNext", 40);
const Index_aiColumn = off("Index_aiColumn", 8);
const Index_aSortOrder = off("Index_aSortOrder", 56);
const Index_azColl = off("Index_azColl", 64);
const Index_pPartIdxWhere = off("Index_pPartIdxWhere", 72);
const Index_aColExpr = off("Index_aColExpr", 80);
const Index_zName = off("Index_zName", 0);
const Index_pTable = off("Index_pTable", 24);
const Index_tnum = off("Index_tnum", 88);
const Index_nColumn = off("Index_nColumn", 96);
const Index_nKeyCol = off("Index_nKeyCol", 94);

const Select_op = off("Select_op", 0);
const Select_selFlags = off("Select_selFlags", 4);
const Select_iLimit = off("Select_iLimit", 8);
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
const Select_nSelectRow = off("Select_nSelectRow", 2);
const Select_iOffset = off("Select_iOffset", 12);
const sizeof_Select = off("sizeof_Select", 120);

const SrcList_nSrc = off("SrcList_nSrc", 0);
const SrcList_nAlloc = off("SrcList_nAlloc", 4);
const SrcList_a = off("SrcList_a", 8);
const sizeof_SrcItem = off("sizeof_SrcItem", 72);
const SrcItem_pSTab = off("SrcItem_pSTab", 16);
const SrcItem_fg = off("SrcItem_fg", 24);
const SrcItem_iCursor = off("SrcItem_iCursor", 28);
const SrcItem_colUsed = off("SrcItem_colUsed", 32);
const SrcItem_u1 = off("SrcItem_u1", 40);
const SrcItem_u2 = off("SrcItem_u2", 48);
const SrcItem_u3 = off("SrcItem_u3", 56);
const SrcItem_u4 = off("SrcItem_u4", 64);

const IdList_nId = off("IdList_nId", 0);
const IdList_a = off("IdList_a", 8);
const IdList_item_zName = off("IdList_item_zName", 0);
const sizeof_IdList_item = off("sizeof_IdList_item", 16);

const FuncDef_funcFlags = off("FuncDef_funcFlags", 4);
const FuncDef_xFinalize = off("FuncDef_xFinalize", 32);
const FuncDef_pUserData = off("FuncDef_pUserData", 8);

const Walker_pParse = off("Walker_pParse", 0);
const Walker_xExprCallback = off("Walker_xExprCallback", 8);
const Walker_xSelectCallback = off("Walker_xSelectCallback", 16);
const Walker_xSelectCallback2 = off("Walker_xSelectCallback2", 24);
const Walker_walkerDepth = off("Walker_walkerDepth", 32);
const Walker_eCode = off("Walker_eCode", 36);
const Walker_mWFlags = off("Walker_mWFlags", 38);
const Walker_u = off("Walker_u", 40);
const sizeof_Walker = off("sizeof_Walker", 48);

const NameContext_pParse = off("NameContext_pParse", 0);
const NameContext_pSrcList = off("NameContext_pSrcList", 8);
const NameContext_uNC = off("NameContext_uNC", 16);
const NameContext_ncFlags = off("NameContext_ncFlags", 40);

const AggInfo_directMode = off("AggInfo_directMode", 0);
const AggInfo_useSortingIdx = off("AggInfo_useSortingIdx", 1);
const AggInfo_nSortingColumn = off("AggInfo_nSortingColumn", 4);
const AggInfo_sortingIdxPTab = off("AggInfo_sortingIdxPTab", 12);
const AggInfo_iFirstReg = off("AggInfo_iFirstReg", 16);
const AggInfo_pGroupBy = off("AggInfo_pGroupBy", 24);
const AggInfo_aCol = off("AggInfo_aCol", 32);
const AggInfo_nColumn = off("AggInfo_nColumn", 40);
const AggInfo_aFunc = off("AggInfo_aFunc", 48);
const AggInfo_nFunc = off("AggInfo_nFunc", 56);
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
const AggInfo_func_iOBTab = off("AggInfo_func_iOBTab", 24);
const AggInfo_func_bOBPayload = off("AggInfo_func_bOBPayload", 28);
const AggInfo_func_bOBUnique = off("AggInfo_func_bOBUnique", 29);
const AggInfo_func_bUseSubtype = off("AggInfo_func_bUseSubtype", 30);

const IndexedExpr_pExpr = off("IndexedExpr_pExpr", 0);
const IndexedExpr_iDataCur = off("IndexedExpr_iDataCur", 8);
const IndexedExpr_iIdxCur = off("IndexedExpr_iIdxCur", 12);
const IndexedExpr_iIdxCol = off("IndexedExpr_iIdxCol", 16);
const IndexedExpr_bMaybeNullRow = off("IndexedExpr_bMaybeNullRow", 20);
const IndexedExpr_aff = off("IndexedExpr_aff", 21);
const IndexedExpr_pIENext = off("IndexedExpr_pIENext", 24);

const SubrtnSig_selId = off("SubrtnSig_selId", 0);
const SubrtnSig_bComplete = off("SubrtnSig_bComplete", 4);
const SubrtnSig_zAff = off("SubrtnSig_zAff", 8);
const SubrtnSig_iTable = off("SubrtnSig_iTable", 16);
const SubrtnSig_iAddr = off("SubrtnSig_iAddr", 20);
const SubrtnSig_regReturn = off("SubrtnSig_regReturn", 24);
const sizeof_SubrtnSig = off("sizeof_SubrtnSig", 32);

const SelectDest_eDest = off("SelectDest_eDest", 0);
const SelectDest_iSDParm = off("SelectDest_iSDParm", 4);
const SelectDest_iSDParm2 = off("SelectDest_iSDParm2", 8);
const SelectDest_iSdst = off("SelectDest_iSdst", 12);
const SelectDest_nSdst = off("SelectDest_nSdst", 16);
const SelectDest_zAffSdst = off("SelectDest_zAffSdst", 24);
const sizeof_SelectDest = off("sizeof_SelectDest", 32);

const VdbeOp_opcode = off("VdbeOp_opcode", 0);
const VdbeOp_p1 = off("VdbeOp_p1", 4);
const VdbeOp_p2 = off("VdbeOp_p2", 8);
const VdbeOp_p3 = off("VdbeOp_p3", 12);
const VdbeOp_p4 = off("VdbeOp_p4", 16);
const VdbeOp_p4type = off("VdbeOp_p4type", 24);
const VdbeOp_p5 = off("VdbeOp_p5", 25);
const sizeof_VdbeOp = off("sizeof_VdbeOp", 32);

const With_a = off("With_a", 16);
const With_nCte = off("With_nCte", 0);
const Cte_pSelect = off("Cte_pSelect", 16);
const Cte_pCols = off("Cte_pCols", 8);
const Cte_zName = off("Cte_zName", 0);
const Cte_eM10d = off("Cte_eM10d", 40);
const sizeof_Cte = off("sizeof_Cte", 48);

// SRT_* selectdest codes
const SRT_Set: u8 = 9;
const SRT_Mem: u8 = 8;
const SRT_Exists: u8 = 1;

// ─── field accessor inlines for Expr (the hot struct) ───────────────────────
inline fn exprOp(p: Ptr) c_int {
    return rd(u8, p, Expr_op);
}
inline fn setExprOp(p: Ptr, v: c_int) void {
    wr(u8, p, Expr_op, @truncate(@as(c_uint, @bitCast(v))));
}
inline fn exprOp2(p: Ptr) c_int {
    return rd(u8, p, Expr_op2);
}
inline fn setExprOp2(p: Ptr, v: c_int) void {
    wr(u8, p, Expr_op2, @truncate(@as(c_uint, @bitCast(v))));
}
inline fn exprAffExpr(p: Ptr) u8 {
    return rd(u8, p, Expr_affExpr);
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
    return rdp(p, Expr_x);
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
    return rd(i16, p, Expr_iColumn); // ynVar is i16
}
inline fn exprIAgg(p: Ptr) c_int {
    return rd(i16, p, Expr_iAgg);
}
inline fn setExprIAgg(p: Ptr, v: i16) void {
    wr(i16, p, Expr_iAgg, v);
}
inline fn exprPAggInfo(p: Ptr) Ptr {
    return rdp(p, Expr_pAggInfo);
}
inline fn exprUToken(p: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(p, Expr_u));
}
inline fn exprUValue(p: Ptr) c_int {
    return rd(c_int, p, Expr_u);
}
inline fn exprYTab(p: Ptr) Ptr {
    return rdp(p, Expr_y);
}
inline fn exprYWin(p: Ptr) Ptr {
    return rdp(p, Expr_y);
}

inline fn hasProp(p: Ptr, m: u32) bool {
    return (exprFlags(p) & m) != 0;
}
inline fn hasAllProp(p: Ptr, m: u32) bool {
    return (exprFlags(p) & m) == m;
}
inline fn setProp(p: Ptr, m: u32) void {
    setExprFlags(p, exprFlags(p) | m);
}
inline fn clearProp(p: Ptr, m: u32) void {
    setExprFlags(p, exprFlags(p) & ~m);
}
inline fn useUToken(p: Ptr) bool {
    return (exprFlags(p) & EP_IntValue) == 0;
}
inline fn useUValue(p: Ptr) bool {
    return (exprFlags(p) & EP_IntValue) != 0;
}
inline fn useXList(p: Ptr) bool {
    return (exprFlags(p) & EP_xIsSelect) == 0;
}
inline fn useXSelect(p: Ptr) bool {
    return (exprFlags(p) & EP_xIsSelect) != 0;
}
inline fn useYTab(p: Ptr) bool {
    return (exprFlags(p) & (EP_WinFunc | EP_Subrtn)) == 0;
}
inline fn useYWin(p: Ptr) bool {
    return (exprFlags(p) & EP_WinFunc) != 0;
}
inline fn useYSub(p: Ptr) bool {
    return (exprFlags(p) & EP_Subrtn) != 0;
}
inline fn alwaysTrue(p: Ptr) bool {
    return (exprFlags(p) & (EP_OuterON | EP_IsTrue)) == EP_IsTrue;
}
inline fn alwaysFalse(p: Ptr) bool {
    return (exprFlags(p) & (EP_OuterON | EP_IsFalse)) == EP_IsFalse;
}

// VVA (vvaFlags) — only meaningful under SQLITE_DEBUG
inline fn setVVA(p: Ptr, m: u8) void {
    if (config.sqlite_debug) {
        wr(u8, p, Expr_vvaFlags, rd(u8, p, Expr_vvaFlags) | m);
    }
}
inline fn clearVVA(p: Ptr) void {
    if (config.sqlite_debug) {
        wr(u8, p, Expr_vvaFlags, 0);
    }
}

// Parse helpers
inline fn parseDb(pParse: Ptr) Ptr {
    return rdp(pParse, Parse_db);
}
inline fn parseVdbe(pParse: Ptr) Ptr {
    return rdp(pParse, Parse_pVdbe);
}
inline fn parseNErr(pParse: Ptr) c_int {
    return rd(c_int, pParse, Parse_nErr);
}
inline fn parseNMem(pParse: Ptr) c_int {
    return rd(c_int, pParse, Parse_nMem);
}
inline fn setParseNMem(pParse: Ptr, v: c_int) void {
    wr(c_int, pParse, Parse_nMem, v);
}
inline fn incParseNMem(pParse: Ptr) c_int {
    const v = parseNMem(pParse) + 1;
    setParseNMem(pParse, v);
    return v;
}
inline fn parseNTab(pParse: Ptr) c_int {
    return rd(c_int, pParse, Parse_nTab);
}
inline fn setParseNTab(pParse: Ptr, v: c_int) void {
    wr(c_int, pParse, Parse_nTab, v);
}
inline fn parseISelfTab(pParse: Ptr) c_int {
    return rd(c_int, pParse, Parse_iSelfTab);
}
inline fn setParseISelfTab(pParse: Ptr, v: c_int) void {
    wr(c_int, pParse, Parse_iSelfTab, v);
}
inline fn okConstFactor(pParse: Ptr) bool {
    return (rd(u8, pParse, Parse_bft_byte) & BFT_okConstFactor) != 0;
}
inline fn setOkConstFactor(pParse: Ptr, on: bool) void {
    const b = rd(u8, pParse, Parse_bft_byte);
    wr(u8, pParse, Parse_bft_byte, if (on) b | BFT_okConstFactor else b & ~BFT_okConstFactor);
}
inline fn dbMallocFailed(db: Ptr) bool {
    return rd(u8, db, sqlite3_mallocFailed) != 0;
}
inline fn dbEnc(db: Ptr) u8 {
    return rd(u8, db, sqlite3_enc);
}
inline fn dbLimit(db: Ptr, i: c_int) c_int {
    return rd(c_int, db, sqlite3_aLimit + @as(usize, @intCast(i)) * 4);
}
inline fn inRenameObject(pParse: Ptr) bool {
    return rd(c_int, pParse, Parse_eParseMode) >= PARSE_MODE_RENAME;
}

// ─── extern ABI fns (already ported or still C) ─────────────────────────────
const c = struct {
    // memory
    extern fn sqlite3DbMallocRawNN(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbMallocRaw(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbMallocZero(db: Ptr, n: u64) Ptr;
    extern fn sqlite3DbRealloc(db: Ptr, p: Ptr, n: u64) Ptr;
    extern fn sqlite3DbMallocSize(db: Ptr, p: Ptr) u64;
    extern fn sqlite3DbFree(db: Ptr, p: Ptr) void;
    extern fn sqlite3DbNNFreeNN(db: Ptr, p: Ptr) void;
    extern fn sqlite3DbStrDup(db: Ptr, z: ?[*:0]const u8) ?[*:0]u8;
    extern fn sqlite3DbStrNDup(db: Ptr, z: ?[*:0]const u8, n: u64) ?[*:0]u8;
    extern fn sqlite3DbSpanDup(db: Ptr, a: ?[*]const u8, b: ?[*]const u8) ?[*:0]u8;
    // strings / util
    extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
    // sqlite3Strlen30NN(C) is a C macro: strlen(C)&0x3fffffff; for non-null input
    // sqlite3Strlen30 yields the identical value.
    fn sqlite3Strlen30NN(z: ?[*:0]const u8) c_int {
        return sqlite3Strlen30(z);
    }
    extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
    extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
    extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;
    extern fn strcmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
    extern fn sqlite3Dequote(z: ?[*:0]u8) void;
    extern fn sqlite3DequoteExpr(p: Ptr) void;
    extern fn sqlite3TokenInit(p: Ptr, z: ?[*:0]u8) void;
    // sqlite3Isquote(x) is a C macro (SQLITE_ASCII: ctypeMap[x]&0x80); the set bit
    // marks exactly the four quote chars.
    fn sqlite3Isquote(c_: c_int) c_int {
        return @intFromBool(c_ == '"' or c_ == '\'' or c_ == '[' or c_ == '`');
    }
    extern fn sqlite3GetInt32(z: ?[*:0]const u8, p: *c_int) c_int;
    extern fn sqlite3Atoi64(z: ?[*:0]const u8, p: *i64, n: c_int, enc: u8) c_int;
    extern fn sqlite3DecOrHexToI64(z: ?[*:0]const u8, p: *i64) c_int;
    extern fn sqlite3AtoF(z: ?[*:0]const u8, p: *f64) c_int;
    extern fn sqlite3IsNaN(v: f64) c_int;
    extern fn sqlite3HexToBlob(db: Ptr, z: ?[*:0]const u8, n: c_int) Ptr;
    extern fn sqlite3AffinityType(z: ?[*:0]const u8, p: Ptr) u8;
    extern fn sqlite3IsBinary(p: Ptr) c_int;
    extern fn sqlite3MemCompare(a: Ptr, b: Ptr, p: Ptr) c_int;
    // error
    extern fn sqlite3ErrorMsg(pParse: Ptr, fmt: ?[*:0]const u8, ...) void;
    extern fn sqlite3RecordErrorOffsetOfExpr(db: Ptr, p: Ptr) void;
    // collations
    extern fn sqlite3FindCollSeq(db: Ptr, enc: u8, z: ?[*:0]const u8, create: c_int) Ptr;
    extern fn sqlite3GetCollSeq(pParse: Ptr, enc: u8, p: Ptr, z: ?[*:0]const u8) Ptr;
    extern fn sqlite3CheckCollSeq(pParse: Ptr, p: Ptr) c_int;
    extern fn sqlite3ColumnColl(pCol: Ptr) ?[*:0]const u8;
    extern fn sqlite3ColumnExpr(pTab: Ptr, pCol: Ptr) Ptr;
    extern fn sqlite3ColumnDefault(v: Ptr, pTab: Ptr, i: c_int, reg: c_int) void;
    extern fn sqlite3ColumnIndex(pTab: Ptr, z: ?[*:0]const u8) c_int;
    // VDBE
    extern fn sqlite3GetVdbe(pParse: Ptr) Ptr;
    extern fn sqlite3VdbeDb(v: Ptr) Ptr;
    extern fn sqlite3VdbeParser(v: Ptr) Ptr;
    extern fn sqlite3VdbeAddOp0(v: Ptr, op: c_int) c_int;
    extern fn sqlite3VdbeAddOp1(v: Ptr, op: c_int, p1: c_int) c_int;
    extern fn sqlite3VdbeAddOp2(v: Ptr, op: c_int, p1: c_int, p2: c_int) c_int;
    extern fn sqlite3VdbeAddOp3(v: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
    extern fn sqlite3VdbeAddOp4(v: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: ?[*]const u8, p4type: c_int) c_int;
    extern fn sqlite3VdbeAddOp4Int(v: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
    extern fn sqlite3VdbeAddOp4Dup8(v: Ptr, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: ?[*]const u8, p4type: c_int) c_int;
    extern fn sqlite3VdbeChangeP2(v: Ptr, addr: c_int, p2: c_int) void;
    extern fn sqlite3VdbeChangeP3(v: Ptr, addr: c_int, p3: c_int) void;
    extern fn sqlite3VdbeChangeP4(v: Ptr, addr: c_int, p4: ?[*]const u8, n: c_int) void;
    extern fn sqlite3VdbeChangeP5(v: Ptr, p5: u16) void;
    extern fn sqlite3VdbeJumpHere(v: Ptr, addr: c_int) void;
    extern fn sqlite3VdbeResolveLabel(v: Ptr, x: c_int) void;
    extern fn sqlite3VdbeMakeLabel(pParse: Ptr) c_int;
    extern fn sqlite3VdbeGoto(v: Ptr, addr: c_int) void;
    extern fn sqlite3VdbeCurrentAddr(v: Ptr) c_int;
    extern fn sqlite3VdbeGetOp(v: Ptr, addr: c_int) Ptr;
    extern fn sqlite3VdbeGetLastOp(v: Ptr) Ptr;
    extern fn sqlite3VdbeChangeToNoop(v: Ptr, addr: c_int) c_int;
    extern fn sqlite3VdbeSetP4KeyInfo(pParse: Ptr, pIdx: Ptr) void;
    extern fn sqlite3VdbeLoadString(v: Ptr, iReg: c_int, z: ?[*:0]const u8) void;
    extern fn sqlite3VdbeAddFunctionCall(pParse: Ptr, p1: c_int, p2: c_int, p3: c_int, nArg: c_int, pDef: Ptr, eCallCtx: c_int) c_int;
    // sqlite3VdbeReleaseRegisters is a real function only under SQLITE_DEBUG;
    // elsewhere it is a no-op macro. Gate the extern reference on config so the
    // production link doesn't pull an undefined symbol.
    fn sqlite3VdbeReleaseRegisters(pParse: Ptr, iReg: c_int, n: c_int, mask: u32, b: c_int) void {
        if (comptime config.sqlite_debug) {
            const f = @extern(*const fn (Ptr, c_int, c_int, u32, c_int) callconv(.c) void, .{ .name = "sqlite3VdbeReleaseRegisters" });
            f(pParse, iReg, n, mask, b);
        }
    }
    extern fn sqlite3VdbeSetVarmask(v: Ptr, i: c_int) void;
    extern fn sqlite3VdbeGetBoundValue(p: Ptr, i: c_int, aff: u8) Ptr;
    extern fn sqlite3VdbeTypeofColumn(v: Ptr, i: c_int) void;
    extern fn sqlite3VdbeScanStatusCounters(v: Ptr, a: c_int, b: c_int, c_: c_int) void;
    extern fn sqlite3VdbeScanStatusRange(v: Ptr, a: c_int, b: c_int, c_: c_int) void;
    // functions / vtab
    extern fn sqlite3FindFunction(db: Ptr, z: ?[*:0]const u8, nArg: c_int, enc: u8, create: u8) Ptr;
    extern fn sqlite3VtabOverloadFunction(db: Ptr, pDef: Ptr, nArg: c_int, pExpr: Ptr) Ptr;
    // schema / table
    extern fn sqlite3SchemaToIndex(db: Ptr, pSchema: Ptr) c_int;
    extern fn sqlite3CodeVerifySchema(pParse: Ptr, iDb: c_int) void;
    extern fn sqlite3TableLock(pParse: Ptr, iDb: c_int, tnum: c_int, isWriteLock: u8, zName: ?[*:0]const u8) void;
    extern fn sqlite3OpenTable(pParse: Ptr, iCur: c_int, iDb: c_int, pTab: Ptr, opcode: c_int) void;
    extern fn sqlite3PrimaryKeyIndex(pTab: Ptr) Ptr;
    // Returns i16 in C — declaring c_int here would read undefined upper bits of
    // the return register (x86-64 leaves them unspecified for a 16-bit return),
    // turning a -1 rowid result into 65535 and corrupting trigger OP_Param p1.
    extern fn sqlite3TableColumnToStorage(pTab: Ptr, iCol: i16) i16;
    extern fn sqlite3TableColumnToIndex(pIdx: Ptr, iCol: i16) c_int;
    // keyinfo
    extern fn sqlite3KeyInfoAlloc(db: Ptr, n1: c_int, n2: c_int) Ptr;
    extern fn sqlite3KeyInfoUnref(p: Ptr) void;
    // select / vlist
    extern fn sqlite3SelectNew(pParse: Ptr, pEList: Ptr, pSrc: Ptr, pWhere: Ptr, pGroupBy: Ptr, pHaving: Ptr, pOrderBy: Ptr, selFlags: u32, pLimit: Ptr) Ptr;
    extern fn sqlite3SelectDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3SelectDup(db: Ptr, p: Ptr, flags: c_int) Ptr;
    extern fn sqlite3IdListDup(db: Ptr, p: Ptr) Ptr;
    extern fn sqlite3Select(pParse: Ptr, p: Ptr, pDest: Ptr) c_int;
    extern fn sqlite3SelectDestInit(pDest: Ptr, eDest: c_int, iParm: c_int) void;
    extern fn sqlite3WindowListDup(db: Ptr, p: Ptr) Ptr;
    extern fn sqlite3WindowDup(db: Ptr, pOwner: Ptr, p: Ptr) Ptr;
    extern fn sqlite3WindowDelete(db: Ptr, p: Ptr) void;
    extern fn sqlite3WindowLink(pSelect: Ptr, pWin: Ptr) void;
    extern fn sqlite3WindowCompare(pParse: Ptr, p1: Ptr, p2: Ptr, b: c_int) c_int;
    extern fn sqlite3VListAdd(db: Ptr, pVList: Ptr, z: ?[*:0]const u8, n: c_int, x: c_int) Ptr;
    extern fn sqlite3VListNumToName(pVList: Ptr, n: c_int) ?[*:0]const u8;
    extern fn sqlite3VListNameToNum(pVList: Ptr, z: ?[*:0]const u8, n: c_int) c_int;
    // ID/Src lists
    extern fn sqlite3IdListDelete(db: Ptr, p: Ptr) void;
    // walker
    extern fn sqlite3WalkExpr(pWalker: Ptr, pExpr: Ptr) c_int;
    extern fn sqlite3WalkExprList(pWalker: Ptr, pList: Ptr) c_int;
    extern fn sqlite3WalkSelect(pWalker: Ptr, p: Ptr) c_int;
    extern fn sqlite3WalkerDepthIncrease(pWalker: Ptr, p: Ptr) c_int;
    extern fn sqlite3WalkerDepthDecrease(pWalker: Ptr, p: Ptr) void;
    extern fn sqlite3SelectWalkNoop(pWalker: Ptr, p: Ptr) c_int;
    extern fn sqlite3ExprWalkNoop(pWalker: Ptr, p: Ptr) c_int;
    extern fn sqlite3SelectWalkAssert2(pWalker: Ptr, p: Ptr) void;
    // misc codegen
    extern fn sqlite3RenameExprUnmap(pParse: Ptr, p: Ptr) void;
    extern fn sqlite3RenameTokenMap(pParse: Ptr, p: Ptr, pToken: Ptr) Ptr;
    extern fn sqlite3ParserAddCleanup(pParse: Ptr, x: Ptr, p: Ptr) Ptr;
    extern fn sqlite3MayAbort(pParse: Ptr) void;
    extern fn sqlite3ValueFromExpr(db: Ptr, pExpr: Ptr, enc: u8, aff: u8, pp: *Ptr) c_int;
    extern fn sqlite3ValueFree(p: Ptr) void;
    extern fn sqlite3_value_type(p: Ptr) c_int;
    extern fn sqlite3_value_int64(p: Ptr) i64;
    extern fn sqlite3_value_text(p: Ptr) ?[*:0]const u8;
    extern fn sqlite3ArrayAllocate(db: Ptr, pArray: Ptr, szEntry: c_int, pnEntry: Ptr, pIdx: *c_int) Ptr;
    extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
    extern fn memset(dst: ?*anyopaque, v: c_int, n: usize) ?*anyopaque;
};

// Helpers built on extern primitives
inline fn errMsg0(pParse: Ptr, msg: [*:0]const u8) void {
    c.sqlite3ErrorMsg(pParse, msg);
}

// ROUND8
inline fn round8(x: c_int) c_int {
    return (x + 7) & ~@as(c_int, 7);
}
inline fn round8u(x: u64) u64 {
    return (x + 7) & ~@as(u64, 7);
}

// ════════════════════════════════════════════════════════════════════════════
// Section 1: affinity, collation, vectors
// ════════════════════════════════════════════════════════════════════════════

inline fn rdpCol(pTab: Ptr, iCol: c_int) Ptr {
    const aCol = rdp(pTab, Table_aCol);
    return @ptrCast(base(aCol) + @as(usize, @intCast(iCol)) * sizeof_Column);
}
inline fn colAffinity(pCol: Ptr) u8 {
    return rd(u8, pCol, Column_affinity);
}
inline fn colFlags(pCol: Ptr) u16 {
    return rd(u16, pCol, Column_colFlags);
}
inline fn setColFlags(pCol: Ptr, v: u16) void {
    wr(u16, pCol, Column_colFlags, v);
}
inline fn colNotNull(pCol: Ptr) u8 {
    return rd(u8, pCol, Column_zCnName_strptr + 8) & 0x0f;
}
inline fn colCnName(pCol: Ptr) ?[*:0]const u8 {
    return @ptrCast(rdp(pCol, Column_zCnName));
}

export fn sqlite3TableColumnAffinity(pTab: Ptr, iCol: c_int) u8 {
    if (iCol < 0 or iCol >= rd(i16, pTab, Table_nCol)) return SQLITE_AFF_INTEGER;
    return colAffinity(rdpCol(pTab, iCol));
}

export fn sqlite3ExprAffinity(pExpr0: Ptr) u8 {
    var pExpr = pExpr0;
    var o = exprOp(pExpr);
    while (true) {
        if (o == TK_COLUMN or (o == TK_AGG_COLUMN and exprYTab(pExpr) != null)) {
            return sqlite3TableColumnAffinity(exprYTab(pExpr), exprIColumn(pExpr));
        }
        if (o == TK_SELECT) {
            const pSel = exprPSelect(pExpr);
            const pEList = rdp(pSel, Select_pEList);
            return sqlite3ExprAffinity(itemExpr(listA(pEList), 0));
        }
        if (o == TK_CAST) {
            return c.sqlite3AffinityType(exprUToken(pExpr), null);
        }
        if (o == TK_SELECT_COLUMN) {
            const pLeft = exprPLeft(pExpr);
            const pSel = exprPSelect(pLeft);
            const pEList = rdp(pSel, Select_pEList);
            return sqlite3ExprAffinity(itemExpr(listA(pEList), exprIColumn(pExpr)));
        }
        if (o == TK_VECTOR or (o == TK_FUNCTION and exprAffExpr(pExpr) == SQLITE_AFF_DEFER)) {
            const pList = exprPList(pExpr);
            return sqlite3ExprAffinity(itemExpr(listA(pList), 0));
        }
        if (hasProp(pExpr, EP_Skip | EP_IfNullRow)) {
            pExpr = exprPLeft(pExpr);
            o = exprOp(pExpr);
            continue;
        }
        if (o != TK_REGISTER) break;
        o = exprOp2(pExpr);
        if (o == TK_REGISTER) break;
    }
    return exprAffExpr(pExpr);
}

// Read the i-th ExprList_item's pExpr, given a pointer to a[0].
inline fn itemAt(a0: Ptr, i: c_int) Ptr {
    return @ptrCast(base(a0) + @as(usize, @intCast(i)) * sizeof_ExprList_item);
}
inline fn itemExpr(a0: Ptr, i: c_int) Ptr {
    return rdp(itemAt(a0, i), ExprList_item_pExpr);
}
inline fn listNExpr(pList: Ptr) c_int {
    return rd(c_int, pList, ExprList_nExpr);
}
inline fn listA(pList: Ptr) Ptr {
    // ExprList.a is an INLINE array (struct ExprList_item a[1]) at the tail of
    // ExprList — its address is the data, not a pointer to dereference.
    return fieldPtr(pList, ExprList_a);
}

export fn sqlite3ExprDataType(pExpr0: Ptr) c_int {
    var pExpr = pExpr0;
    while (pExpr != null) {
        switch (exprOp(pExpr)) {
            TK_COLLATE, TK_IF_NULL_ROW, TK_UPLUS => {
                pExpr = exprPLeft(pExpr);
            },
            TK_NULL => {
                pExpr = null;
            },
            TK_STRING => return 0x02,
            TK_BLOB => return 0x04,
            TK_CONCAT => return 0x06,
            TK_VARIABLE, TK_AGG_FUNCTION, TK_FUNCTION => return 0x07,
            TK_COLUMN, TK_AGG_COLUMN, TK_SELECT, TK_CAST, TK_SELECT_COLUMN, TK_VECTOR => {
                const aff = sqlite3ExprAffinity(pExpr);
                if (aff >= SQLITE_AFF_NUMERIC) return 0x05;
                if (aff == SQLITE_AFF_TEXT) return 0x06;
                return 0x07;
            },
            TK_CASE => {
                var res: c_int = 0;
                const pList = exprPList(pExpr);
                const a0 = listA(pList);
                const n = listNExpr(pList);
                var ii: c_int = 1;
                while (ii < n) : (ii += 2) {
                    res |= sqlite3ExprDataType(itemExpr(a0, ii));
                }
                if (@rem(n, 2) != 0) {
                    res |= sqlite3ExprDataType(itemExpr(a0, n - 1));
                }
                return res;
            },
            else => return 0x01,
        }
    }
    return 0x00;
}

export fn sqlite3ExprAddCollateToken(pParse: Ptr, pExpr: Ptr, pCollName: Ptr, dequote: c_int) Ptr {
    if (rd(c_int, pCollName, Token_n) > 0) {
        const pNew = sqlite3ExprAlloc(parseDb(pParse), TK_COLLATE, pCollName, dequote);
        if (pNew != null) {
            wr(?*anyopaque, pNew, Expr_pLeft, pExpr);
            setProp(pNew, EP_Collate | EP_Skip);
            return pNew;
        }
    }
    return pExpr;
}

export fn sqlite3ExprAddCollateString(pParse: Ptr, pExpr: Ptr, zC: [*:0]const u8) Ptr {
    var s: [sizeof_Token]u8 align(8) = undefined;
    c.sqlite3TokenInit(@ptrCast(&s), @constCast(zC));
    return sqlite3ExprAddCollateToken(pParse, pExpr, @ptrCast(&s), 0);
}

export fn sqlite3ExprSkipCollate(pExpr0: Ptr) Ptr {
    var pExpr = pExpr0;
    while (pExpr != null and hasProp(pExpr, EP_Skip)) {
        pExpr = exprPLeft(pExpr);
    }
    return pExpr;
}

export fn sqlite3ExprSkipCollateAndLikely(pExpr0: Ptr) Ptr {
    var pExpr = pExpr0;
    while (pExpr != null and hasProp(pExpr, EP_Skip | EP_Unlikely)) {
        if (hasProp(pExpr, EP_Unlikely)) {
            pExpr = itemExpr(listA(exprPList(pExpr)), 0);
        } else if (exprOp(pExpr) == TK_COLLATE) {
            pExpr = exprPLeft(pExpr);
        } else break;
    }
    return pExpr;
}

export fn sqlite3ExprCollSeq(pParse: Ptr, pExpr: Ptr) Ptr {
    const db = parseDb(pParse);
    var pColl: Ptr = null;
    var p = pExpr;
    while (p != null) {
        var o = exprOp(p);
        if (o == TK_REGISTER) o = exprOp2(p);
        if ((o == TK_AGG_COLUMN and exprYTab(p) != null) or o == TK_COLUMN or o == TK_TRIGGER) {
            const j = exprIColumn(p);
            if (j >= 0) {
                const pCol = rdpCol(exprYTab(p), j);
                const zColl = c.sqlite3ColumnColl(pCol);
                pColl = c.sqlite3FindCollSeq(db, dbEnc(db), zColl, 0);
            }
            break;
        }
        if (o == TK_CAST or o == TK_UPLUS) {
            p = exprPLeft(p);
            continue;
        }
        if (o == TK_VECTOR or (o == TK_FUNCTION and exprAffExpr(p) == SQLITE_AFF_DEFER)) {
            p = itemExpr(listA(exprPList(p)), 0);
            continue;
        }
        if (o == TK_COLLATE) {
            pColl = c.sqlite3GetCollSeq(pParse, dbEnc(db), null, exprUToken(p));
            break;
        }
        if ((exprFlags(p) & EP_Collate) != 0) {
            const pl = exprPLeft(p);
            if (pl != null and (exprFlags(pl) & EP_Collate) != 0) {
                p = pl;
            } else {
                var pNext = exprPRight(p);
                if (useXList(p) and exprPList(p) != null and !dbMallocFailed(db)) {
                    const pList = exprPList(p);
                    const a0 = listA(pList);
                    const n = listNExpr(pList);
                    var i: c_int = 0;
                    while (i < n) : (i += 1) {
                        if (hasProp(itemExpr(a0, i), EP_Collate)) {
                            pNext = itemExpr(a0, i);
                            break;
                        }
                    }
                }
                p = pNext;
            }
        } else break;
    }
    if (c.sqlite3CheckCollSeq(pParse, pColl) != 0) {
        pColl = null;
    }
    return pColl;
}

export fn sqlite3ExprNNCollSeq(pParse: Ptr, pExpr: Ptr) Ptr {
    var p = sqlite3ExprCollSeq(pParse, pExpr);
    if (p == null) p = rdp(parseDb(pParse), sqlite3_pDfltColl);
    return p;
}

export fn sqlite3ExprCollSeqMatch(pParse: Ptr, pE1: Ptr, pE2: Ptr) c_int {
    const pColl1 = sqlite3ExprNNCollSeq(pParse, pE1);
    const pColl2 = sqlite3ExprNNCollSeq(pParse, pE2);
    return @intFromBool(pColl1 == pColl2);
}

export fn sqlite3CompareAffinity(pExpr: Ptr, aff2: u8) u8 {
    const aff1 = sqlite3ExprAffinity(pExpr);
    if (aff1 > SQLITE_AFF_NONE and aff2 > SQLITE_AFF_NONE) {
        if (isNumericAffinity(aff1) or isNumericAffinity(aff2)) {
            return SQLITE_AFF_NUMERIC;
        } else {
            return SQLITE_AFF_BLOB;
        }
    } else {
        return (if (aff1 <= SQLITE_AFF_NONE) aff2 else aff1) | SQLITE_AFF_NONE;
    }
}

fn comparisonAffinity(pExpr: Ptr) u8 {
    var aff = sqlite3ExprAffinity(exprPLeft(pExpr));
    if (exprPRight(pExpr) != null) {
        aff = sqlite3CompareAffinity(exprPRight(pExpr), aff);
    } else if (useXSelect(pExpr)) {
        const pEList = rdp(exprPSelect(pExpr), Select_pEList);
        aff = sqlite3CompareAffinity(itemExpr(listA(pEList), 0), aff);
    } else if (aff == 0) {
        aff = SQLITE_AFF_BLOB;
    }
    return aff;
}

export fn sqlite3IndexAffinityOk(pExpr: Ptr, idx_affinity: u8) c_int {
    const aff = comparisonAffinity(pExpr);
    if (aff < SQLITE_AFF_TEXT) return 1;
    if (aff == SQLITE_AFF_TEXT) return @intFromBool(idx_affinity == SQLITE_AFF_TEXT);
    return @intFromBool(isNumericAffinity(idx_affinity));
}

fn binaryCompareP5(pExpr1: Ptr, pExpr2: Ptr, jumpIfNull: c_int) u8 {
    var aff: u8 = sqlite3ExprAffinity(pExpr2);
    aff = sqlite3CompareAffinity(pExpr1, aff) | @as(u8, @truncate(@as(c_uint, @bitCast(jumpIfNull))));
    return aff;
}

export fn sqlite3BinaryCompareCollSeq(pParse: Ptr, pLeft: Ptr, pRight: Ptr) Ptr {
    var pColl: Ptr = undefined;
    if ((exprFlags(pLeft) & EP_Collate) != 0) {
        pColl = sqlite3ExprCollSeq(pParse, pLeft);
    } else if (pRight != null and (exprFlags(pRight) & EP_Collate) != 0) {
        pColl = sqlite3ExprCollSeq(pParse, pRight);
    } else {
        pColl = sqlite3ExprCollSeq(pParse, pLeft);
        if (pColl == null) {
            pColl = sqlite3ExprCollSeq(pParse, pRight);
        }
    }
    return pColl;
}

export fn sqlite3ExprCompareCollSeq(pParse: Ptr, p: Ptr) Ptr {
    if (hasProp(p, EP_Commuted)) {
        return sqlite3BinaryCompareCollSeq(pParse, exprPRight(p), exprPLeft(p));
    } else {
        return sqlite3BinaryCompareCollSeq(pParse, exprPLeft(p), exprPRight(p));
    }
}

fn codeCompare(pParse: Ptr, pLeft: Ptr, pRight: Ptr, opcode: c_int, in1: c_int, in2: c_int, dest: c_int, jumpIfNull: c_int, isCommuted: c_int) c_int {
    if (parseNErr(pParse) != 0) return 0;
    var p4: Ptr = undefined;
    if (isCommuted != 0) {
        p4 = sqlite3BinaryCompareCollSeq(pParse, pRight, pLeft);
    } else {
        p4 = sqlite3BinaryCompareCollSeq(pParse, pLeft, pRight);
    }
    const p5 = binaryCompareP5(pLeft, pRight, jumpIfNull);
    const v = parseVdbe(pParse);
    const addr = c.sqlite3VdbeAddOp4(v, opcode, in2, dest, in1, @ptrCast(p4), P4_COLLSEQ);
    c.sqlite3VdbeChangeP5(v, p5);
    return addr;
}

export fn sqlite3ExprIsVector(pExpr: Ptr) c_int {
    return @intFromBool(sqlite3ExprVectorSize(pExpr) > 1);
}

export fn sqlite3ExprVectorSize(pExpr: Ptr) c_int {
    var o = exprOp(pExpr);
    if (o == TK_REGISTER) o = exprOp2(pExpr);
    if (o == TK_VECTOR) {
        return listNExpr(exprPList(pExpr));
    } else if (o == TK_SELECT) {
        return listNExpr(rdp(exprPSelect(pExpr), Select_pEList));
    } else {
        return 1;
    }
}

export fn sqlite3VectorFieldSubexpr(pVector: Ptr, i: c_int) Ptr {
    if (sqlite3ExprIsVector(pVector) != 0) {
        if (exprOp(pVector) == TK_SELECT or exprOp2(pVector) == TK_SELECT) {
            return itemExpr(listA(rdp(exprPSelect(pVector), Select_pEList)), i);
        } else {
            return itemExpr(listA(exprPList(pVector)), i);
        }
    }
    return pVector;
}

export fn sqlite3ExprForVectorField(pParse: Ptr, pVector0: Ptr, iField: c_int, nField: c_int) Ptr {
    var pVector = pVector0;
    var pRet: Ptr = undefined;
    if (exprOp(pVector) == TK_SELECT) {
        pRet = sqlite3PExpr(pParse, TK_SELECT_COLUMN, null, null);
        if (pRet != null) {
            setProp(pRet, EP_FullSize);
            setExprITable(pRet, nField);
            wr(i16, pRet, Expr_iColumn, @intCast(iField));
            wr(?*anyopaque, pRet, Expr_pLeft, pVector);
        }
    } else {
        if (exprOp(pVector) == TK_VECTOR) {
            const ppVector = itemAt(listA(exprPList(pVector)), iField);
            pVector = rdp(ppVector, ExprList_item_pExpr);
            if (inRenameObject(pParse)) {
                wr(?*anyopaque, ppVector, ExprList_item_pExpr, null);
                return pVector;
            }
        }
        pRet = sqlite3ExprDup(parseDb(pParse), pVector, 0);
    }
    return pRet;
}

fn exprCodeSubselect(pParse: Ptr, pExpr: Ptr) c_int {
    var reg: c_int = 0;
    if (exprOp(pExpr) == TK_SELECT) {
        reg = sqlite3CodeSubselect(pParse, pExpr);
    }
    return reg;
}

fn exprVectorRegister(pParse: Ptr, pVector: Ptr, iField: c_int, regSelect: c_int, ppExpr: *Ptr, pRegFree: *c_int) c_int {
    const o = exprOp(pVector);
    if (o == TK_REGISTER) {
        ppExpr.* = sqlite3VectorFieldSubexpr(pVector, iField);
        return exprITable(pVector) + iField;
    }
    if (o == TK_SELECT) {
        ppExpr.* = itemExpr(listA(rdp(exprPSelect(pVector), Select_pEList)), iField);
        return regSelect + iField;
    }
    if (o == TK_VECTOR) {
        ppExpr.* = itemExpr(listA(exprPList(pVector)), iField);
        return sqlite3ExprCodeTemp(pParse, ppExpr.*, pRegFree);
    }
    return 0;
}

fn codeVectorCompare(pParse: Ptr, pExpr: Ptr, dest: c_int, opIn: u8, p5: u8) void {
    const v = parseVdbe(pParse);
    const pLeft = exprPLeft(pExpr);
    const pRight = exprPRight(pExpr);
    const nLeft = sqlite3ExprVectorSize(pLeft);
    var opx: c_int = opIn;
    var addrCmp: c_int = 0;
    const addrDone = c.sqlite3VdbeMakeLabel(pParse);
    const isCommuted: c_int = @intFromBool(hasProp(pExpr, EP_Commuted));

    if (parseNErr(pParse) != 0) return;
    if (nLeft != sqlite3ExprVectorSize(pRight)) {
        errMsg0(pParse, "row value misused");
        return;
    }

    if (opIn == TK_LE) opx = TK_LT;
    if (opIn == TK_GE) opx = TK_GT;
    if (opIn == TK_NE) opx = TK_EQ;

    const regLeft = exprCodeSubselect(pParse, pLeft);
    const regRight = exprCodeSubselect(pParse, pRight);

    _ = c.sqlite3VdbeAddOp2(v, op.Integer, 1, dest);
    var i: c_int = 0;
    while (true) : (i += 1) {
        var regFree1: c_int = 0;
        var regFree2: c_int = 0;
        var pL: Ptr = null;
        var pR: Ptr = null;
        if (addrCmp != 0) c.sqlite3VdbeJumpHere(v, addrCmp);
        const r1 = exprVectorRegister(pParse, pLeft, i, regLeft, &pL, &regFree1);
        const r2 = exprVectorRegister(pParse, pRight, i, regRight, &pR, &regFree2);
        addrCmp = c.sqlite3VdbeCurrentAddr(v);
        _ = codeCompare(pParse, pL, pR, opx, r1, r2, addrDone, p5, isCommuted);
        sqlite3ReleaseTempReg(pParse, regFree1);
        sqlite3ReleaseTempReg(pParse, regFree2);
        if ((opx == TK_LT or opx == TK_GT) and i < nLeft - 1) {
            addrCmp = c.sqlite3VdbeAddOp0(v, op.ElseEq);
        }
        if (p5 == SQLITE_NULLEQ) {
            _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, dest);
        } else {
            _ = c.sqlite3VdbeAddOp3(v, op.ZeroOrNull, r1, dest, r2);
        }
        if (i == nLeft - 1) break;
        if (opx == TK_EQ) {
            _ = c.sqlite3VdbeAddOp2(v, op.NotNull, dest, addrDone);
        } else {
            _ = c.sqlite3VdbeAddOp2(v, op.Goto, 0, addrDone);
            if (i == nLeft - 2) opx = opIn;
        }
    }
    c.sqlite3VdbeJumpHere(v, addrCmp);
    c.sqlite3VdbeResolveLabel(v, addrDone);
    if (opIn == TK_NE) {
        _ = c.sqlite3VdbeAddOp2(v, OP.Not, dest, dest);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 2: height, allocation, construction, deletion, duplication
// ════════════════════════════════════════════════════════════════════════════

inline fn exprNHeight(p: Ptr) c_int {
    return rd(c_int, p, Expr_nHeight);
}
inline fn setExprNHeight(p: Ptr, v: c_int) void {
    wr(c_int, p, Expr_nHeight, v);
}

export fn sqlite3ExprCheckHeight(pParse: Ptr, nHeight: c_int) c_int {
    var rc: c_int = SQLITE_OK;
    const mxHeight = dbLimit(parseDb(pParse), SQLITE_LIMIT_EXPR_DEPTH);
    if (nHeight > mxHeight) {
        c.sqlite3ErrorMsg(pParse, "Expression tree is too large (maximum depth %d)", mxHeight);
        rc = SQLITE_ERROR;
    }
    return rc;
}

fn heightOfExpr(p: Ptr, pnHeight: *c_int) void {
    if (p != null) {
        if (exprNHeight(p) > pnHeight.*) pnHeight.* = exprNHeight(p);
    }
}
fn heightOfExprList(p: Ptr, pnHeight: *c_int) void {
    if (p != null) {
        const a0 = listA(p);
        const n = listNExpr(p);
        var i: c_int = 0;
        while (i < n) : (i += 1) heightOfExpr(itemExpr(a0, i), pnHeight);
    }
}
fn heightOfSelect(pSelect: Ptr, pnHeight: *c_int) void {
    var p = pSelect;
    while (p != null) : (p = rdp(p, Select_pPrior)) {
        heightOfExpr(rdp(p, Select_pWhere), pnHeight);
        heightOfExpr(rdp(p, Select_pHaving), pnHeight);
        heightOfExpr(rdp(p, Select_pLimit), pnHeight);
        heightOfExprList(rdp(p, Select_pEList), pnHeight);
        heightOfExprList(rdp(p, Select_pGroupBy), pnHeight);
        heightOfExprList(rdp(p, Select_pOrderBy), pnHeight);
    }
}

fn exprSetHeight(p: Ptr) void {
    var nHeight: c_int = if (exprPLeft(p) != null) exprNHeight(exprPLeft(p)) else 0;
    if (useXSelect(p)) {
        heightOfSelect(exprPSelect(p), &nHeight);
    } else if (exprPList(p) != null) {
        heightOfExprList(exprPList(p), &nHeight);
        setExprFlags(p, exprFlags(p) | (EP_Propagate & sqlite3ExprListFlags(exprPList(p))));
    }
    setExprNHeight(p, nHeight + 1);
}

export fn sqlite3ExprSetHeightAndFlags(pParse: Ptr, p: Ptr) void {
    if (parseNErr(pParse) != 0) return;
    exprSetHeight(p);
    _ = sqlite3ExprCheckHeight(pParse, exprNHeight(p));
}

export fn sqlite3SelectExprHeight(p: Ptr) c_int {
    var nHeight: c_int = 0;
    heightOfSelect(p, &nHeight);
    return nHeight;
}

inline fn exprUseWJoin(p: Ptr) bool {
    return (exprFlags(p) & (EP_InnerON | EP_OuterON)) != 0;
}

export fn sqlite3ExprSetErrorOffset(pExpr: Ptr, iOfst: c_int) void {
    if (pExpr == null) return;
    if (exprUseWJoin(pExpr)) return;
    wr(c_int, pExpr, Expr_w, iOfst); // w.iOfst
}

export fn sqlite3ExprAlloc(db: Ptr, opcode: c_int, pToken: Ptr, dequote: c_int) Ptr {
    var nExtra: c_int = 0;
    if (pToken != null) nExtra = rd(c_int, pToken, Token_n) + 1;
    const pNew = c.sqlite3DbMallocRawNN(db, sizeof_Expr + @as(u64, @intCast(nExtra)));
    if (pNew != null) {
        _ = c.memset(pNew, 0, sizeof_Expr);
        setExprOp(pNew, opcode);
        wr(i16, pNew, Expr_iAgg, -1);
        if (nExtra != 0) {
            const zTok: [*]u8 = @ptrCast(base(pNew) + sizeof_Expr);
            wr(?*anyopaque, pNew, Expr_u, @ptrCast(zTok));
            const tn = rd(c_int, pToken, Token_n);
            const tz = rdp(pToken, Token_z);
            if (tn != 0) _ = c.memcpy(zTok, tz, @intCast(tn));
            zTok[@intCast(tn)] = 0;
            if (dequote != 0 and c.sqlite3Isquote(zTok[0]) != 0) {
                c.sqlite3DequoteExpr(pNew);
            }
        }
        setExprNHeight(pNew, 1);
    }
    return pNew;
}

export fn sqlite3Expr(db: Ptr, opcode: c_int, zToken: ?[*:0]const u8) Ptr {
    var x: [sizeof_Token]u8 align(8) = undefined;
    wr(?*anyopaque, @ptrCast(&x), Token_z, @ptrCast(@constCast(zToken)));
    wr(c_int, @ptrCast(&x), Token_n, c.sqlite3Strlen30(zToken));
    return sqlite3ExprAlloc(db, opcode, @ptrCast(&x), 0);
}

export fn sqlite3ExprInt32(db: Ptr, iVal: c_int) Ptr {
    const pNew = c.sqlite3DbMallocRawNN(db, sizeof_Expr);
    if (pNew != null) {
        _ = c.memset(pNew, 0, sizeof_Expr);
        setExprOp(pNew, TK_INTEGER);
        wr(i16, pNew, Expr_iAgg, -1);
        setExprFlags(pNew, EP_IntValue | EP_Leaf | (if (iVal != 0) EP_IsTrue else EP_IsFalse));
        wr(c_int, pNew, Expr_u, iVal);
        setExprNHeight(pNew, 1);
    }
    return pNew;
}

export fn sqlite3ExprAttachSubtrees(db: Ptr, pRoot: Ptr, pLeft: Ptr, pRight: Ptr) void {
    if (pRoot == null) {
        sqlite3ExprDelete(db, pLeft);
        sqlite3ExprDelete(db, pRight);
    } else {
        if (pRight != null) {
            wr(?*anyopaque, pRoot, Expr_pRight, pRight);
            setExprFlags(pRoot, exprFlags(pRoot) | (EP_Propagate & exprFlags(pRight)));
            setExprNHeight(pRoot, exprNHeight(pRight) + 1);
        } else {
            setExprNHeight(pRoot, 1);
        }
        if (pLeft != null) {
            wr(?*anyopaque, pRoot, Expr_pLeft, pLeft);
            setExprFlags(pRoot, exprFlags(pRoot) | (EP_Propagate & exprFlags(pLeft)));
            if (exprNHeight(pLeft) >= exprNHeight(pRoot)) {
                setExprNHeight(pRoot, exprNHeight(pLeft) + 1);
            }
        }
    }
}

export fn sqlite3PExpr(pParse: Ptr, opcode: c_int, pLeft: Ptr, pRight: Ptr) Ptr {
    const p = c.sqlite3DbMallocRawNN(parseDb(pParse), sizeof_Expr);
    if (p != null) {
        _ = c.memset(p, 0, sizeof_Expr);
        setExprOp(p, opcode & 0xff);
        wr(i16, p, Expr_iAgg, -1);
        sqlite3ExprAttachSubtrees(parseDb(pParse), p, pLeft, pRight);
        _ = sqlite3ExprCheckHeight(pParse, exprNHeight(p));
    } else {
        sqlite3ExprDelete(parseDb(pParse), pLeft);
        sqlite3ExprDelete(parseDb(pParse), pRight);
    }
    return p;
}

export fn sqlite3PExprAddSelect(pParse: Ptr, pExpr: Ptr, pSelect: Ptr) void {
    if (pExpr != null) {
        wr(?*anyopaque, pExpr, Expr_x, pSelect);
        setProp(pExpr, EP_xIsSelect | EP_Subquery);
        sqlite3ExprSetHeightAndFlags(pParse, pExpr);
    } else {
        c.sqlite3SelectDelete(parseDb(pParse), pSelect);
    }
}

export fn sqlite3ExprListToValues(pParse: Ptr, nElem: c_int, pEList: Ptr) Ptr {
    var pRet: Ptr = null;
    const a0 = listA(pEList);
    const n = listNExpr(pEList);
    var ii: c_int = 0;
    while (ii < n) : (ii += 1) {
        const pExpr = itemExpr(a0, ii);
        var nExprElem: c_int = undefined;
        if (exprOp(pExpr) == TK_VECTOR) {
            nExprElem = listNExpr(exprPList(pExpr));
        } else {
            nExprElem = 1;
        }
        if (nExprElem != nElem) {
            c.sqlite3ErrorMsg(pParse, "IN(...) element has %d term%s - expected %d", nExprElem, @as([*:0]const u8, if (nExprElem > 1) "s" else ""), nElem);
            break;
        }
        const pSel = c.sqlite3SelectNew(pParse, exprPList(pExpr), null, null, null, null, null, SF_Values, null);
        wr(?*anyopaque, pExpr, Expr_x, null);
        if (pSel != null) {
            if (pRet != null) {
                wr(u8, pSel, Select_op, TK_ALL);
                wr(?*anyopaque, pSel, Select_pPrior, pRet);
            }
            pRet = pSel;
        }
    }
    if (pRet != null and rdp(pRet, Select_pPrior) != null) {
        wr(u32, pRet, Select_selFlags, rd(u32, pRet, Select_selFlags) | SF_MultiValue);
    }
    sqlite3ExprListDelete(parseDb(pParse), pEList);
    return pRet;
}

export fn sqlite3ExprAnd(pParse: Ptr, pLeft: Ptr, pRight: Ptr) Ptr {
    const db = parseDb(pParse);
    if (pLeft == null) {
        return pRight;
    } else if (pRight == null) {
        return pLeft;
    } else {
        const f = exprFlags(pLeft) | exprFlags(pRight);
        if ((f & (EP_OuterON | EP_InnerON | EP_IsFalse | EP_HasFunc)) == EP_IsFalse and !inRenameObject(pParse)) {
            _ = sqlite3ExprDeferredDelete(pParse, pLeft);
            _ = sqlite3ExprDeferredDelete(pParse, pRight);
            return sqlite3ExprInt32(db, 0);
        } else {
            return sqlite3PExpr(pParse, TK_AND, pLeft, pRight);
        }
    }
}

export fn sqlite3ExprFunction(pParse: Ptr, pList: Ptr, pToken: Ptr, eDistinct: c_int) Ptr {
    const db = parseDb(pParse);
    const pNew = sqlite3ExprAlloc(db, TK_FUNCTION, pToken, 1);
    if (pNew == null) {
        sqlite3ExprListDelete(db, pList);
        return null;
    }
    const tz = rdp(pToken, Token_z);
    const zTail = rdp(pParse, Parse_zTail);
    wr(c_int, pNew, Expr_w, @intCast(@intFromPtr(tz.?) - @intFromPtr(zTail.?)));
    if (pList != null and listNExpr(pList) > dbLimit(db, SQLITE_LIMIT_FUNCTION_ARG) and rd(c_int, pParse, Parse_nested) == 0) {
        c.sqlite3ErrorMsg(pParse, "too many arguments on function %T", pToken);
    }
    wr(?*anyopaque, pNew, Expr_x, pList);
    setProp(pNew, EP_HasFunc);
    sqlite3ExprSetHeightAndFlags(pParse, pNew);
    if (eDistinct == @as(c_int, @bitCast(SF_Distinct))) setProp(pNew, EP_Distinct);
    return pNew;
}

export fn sqlite3ExprOrderByAggregateError(pParse: Ptr, p: Ptr) void {
    c.sqlite3ErrorMsg(pParse, "ORDER BY may not be used with non-aggregate %#T()", p);
}

inline fn isWindowFunc(p: Ptr) bool {
    return exprOp(p) == TK_FUNCTION and hasProp(p, EP_WinFunc) and
        false; // eFrmType!=TK_FILTER check omitted: handled by caller path
}

export fn sqlite3ExprAddFunctionOrderBy(pParse: Ptr, pExpr: Ptr, pOrderBy: Ptr) void {
    const db = parseDb(pParse);
    if (pOrderBy == null) {
        return;
    }
    if (pExpr == null) {
        sqlite3ExprListDelete(db, pOrderBy);
        return;
    }
    if (exprPList(pExpr) == null or listNExpr(exprPList(pExpr)) == 0) {
        _ = c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&sqlite3ExprListDeleteGeneric)), pOrderBy);
        return;
    }
    if (isWindowFuncReal(pExpr)) {
        sqlite3ExprOrderByAggregateError(pParse, pExpr);
        sqlite3ExprListDelete(db, pOrderBy);
        return;
    }
    if (listNExpr(pOrderBy) > dbLimit(db, SQLITE_LIMIT_COLUMN)) {
        errMsg0(pParse, "too many terms in ORDER BY clause");
        sqlite3ExprListDelete(db, pOrderBy);
        return;
    }
    const pOB = sqlite3ExprAlloc(db, TK_ORDER, null, 0);
    if (pOB == null) {
        sqlite3ExprListDelete(db, pOrderBy);
        return;
    }
    wr(?*anyopaque, pOB, Expr_x, pOrderBy);
    wr(?*anyopaque, pExpr, Expr_pLeft, pOB);
    setProp(pOB, EP_FullSize);
}

// IsWindowFunc(p): EP_WinFunc set and the window's eFrmType != TK_FILTER.
inline fn isWindowFuncReal(p: Ptr) bool {
    if (exprOp(p) != TK_FUNCTION) return false;
    if (!hasProp(p, EP_WinFunc)) return false;
    const pWin = exprYWin(p);
    if (pWin == null) return false;
    const eFrmType = rd(u8, pWin, off("Window_eFrmType", 32));
    return eFrmType != TK_FILTER;
}

export fn sqlite3ExprFunctionUsable(pParse: Ptr, pExpr: Ptr, pDef: Ptr) void {
    const ff = rd(u32, pDef, FuncDef_funcFlags);
    if (hasProp(pExpr, EP_FromDDL) or (rd(u32, pParse, Parse_prepFlags) & SQLITE_PREPARE_FROM_DDL) != 0) {
        if ((ff & SQLITE_FUNC_DIRECT) != 0 or (rd(u64, parseDb(pParse), sqlite3_flags) & SQLITE_TrustedSchema) == 0) {
            c.sqlite3ErrorMsg(pParse, "unsafe use of %#T()", pExpr);
        }
    }
}

export fn sqlite3ExprAssignVarNumber(pParse: Ptr, pExpr: Ptr, n: u32) void {
    const db = parseDb(pParse);
    var x: c_int = undefined;
    if (pExpr == null) return;
    const z = exprUToken(pExpr).?;
    if (z[1] == 0) {
        // "?"
        x = incParseNVar(pParse);
    } else {
        var doAdd: c_int = 0;
        if (z[0] == '?') {
            var i: i64 = undefined;
            var bOk: c_int = undefined;
            if (n == 2) {
                i = z[1] - '0';
                bOk = 1;
            } else {
                bOk = @intFromBool(0 == c.sqlite3Atoi64(@ptrCast(z + 1), &i, @intCast(n - 1), SQLITE_UTF8));
            }
            if (bOk == 0 or i < 1 or i > dbLimit(db, SQLITE_LIMIT_VARIABLE_NUMBER)) {
                c.sqlite3ErrorMsg(pParse, "variable number must be between ?1 and ?%d", dbLimit(db, SQLITE_LIMIT_VARIABLE_NUMBER));
                c.sqlite3RecordErrorOffsetOfExpr(db, pExpr);
                return;
            }
            x = @intCast(i);
            if (x > parseNVar(pParse)) {
                setParseNVar(pParse, x);
                doAdd = 1;
            } else if (c.sqlite3VListNumToName(rdp(pParse, Parse_pVList), x) == null) {
                doAdd = 1;
            }
        } else {
            x = c.sqlite3VListNameToNum(rdp(pParse, Parse_pVList), z, @intCast(n));
            if (x == 0) {
                x = incParseNVar(pParse);
                doAdd = 1;
            }
        }
        if (doAdd != 0) {
            wr(?*anyopaque, pParse, Parse_pVList, c.sqlite3VListAdd(db, rdp(pParse, Parse_pVList), z, @intCast(n), x));
        }
    }
    wr(i16, pExpr, Expr_iColumn, @intCast(x));
    if (x > dbLimit(db, SQLITE_LIMIT_VARIABLE_NUMBER)) {
        errMsg0(pParse, "too many SQL variables");
        c.sqlite3RecordErrorOffsetOfExpr(db, pExpr);
    }
}

const Parse_nVar = off("Parse_nVar", 290);
inline fn parseNVar(pParse: Ptr) c_int {
    return rd(i16, pParse, Parse_nVar);
}
inline fn setParseNVar(pParse: Ptr, v: c_int) void {
    wr(i16, pParse, Parse_nVar, @intCast(v));
}
inline fn incParseNVar(pParse: Ptr) c_int {
    const v = parseNVar(pParse) + 1;
    setParseNVar(pParse, v);
    return v;
}

// ─── deletion ───────────────────────────────────────────────────────────────
fn exprDeleteNN(db: Ptr, p0: Ptr) void {
    var p = p0;
    while (true) {
        if (!hasProp(p, EP_TokenOnly | EP_Leaf)) {
            if (exprPRight(p) != null) {
                exprDeleteNN(db, exprPRight(p));
            } else if (useXSelect(p)) {
                c.sqlite3SelectDelete(db, exprPSelect(p));
            } else {
                sqlite3ExprListDelete(db, exprPList(p));
                if (hasProp(p, EP_WinFunc)) {
                    c.sqlite3WindowDelete(db, exprYWin(p));
                }
            }
            if (exprPLeft(p) != null and exprOp(p) != TK_SELECT_COLUMN) {
                const pLeft = exprPLeft(p);
                if (!hasProp(p, EP_Static) and !hasProp(pLeft, EP_Static)) {
                    c.sqlite3DbNNFreeNN(db, p);
                    p = pLeft;
                    continue;
                } else {
                    exprDeleteNN(db, pLeft);
                }
            }
        }
        if (!hasProp(p, EP_Static)) {
            c.sqlite3DbNNFreeNN(db, p);
        }
        break;
    }
}

export fn sqlite3ExprDelete(db: Ptr, p: Ptr) void {
    if (p != null) exprDeleteNN(db, p);
}

export fn sqlite3ExprDeleteGeneric(db: Ptr, p: Ptr) void {
    if (p != null) exprDeleteNN(db, p);
}

const OnOrUsing_pOn = off("OnOrUsing_pOn", 0);
const OnOrUsing_pUsing = off("OnOrUsing_pUsing", 8);
export fn sqlite3ClearOnOrUsing(db: Ptr, p: Ptr) void {
    if (p == null) {} else if (rdp(p, OnOrUsing_pOn) != null) {
        exprDeleteNN(db, rdp(p, OnOrUsing_pOn));
    } else if (rdp(p, OnOrUsing_pUsing) != null) {
        c.sqlite3IdListDelete(db, rdp(p, OnOrUsing_pUsing));
    }
}

export fn sqlite3ExprDeferredDelete(pParse: Ptr, pExpr: Ptr) c_int {
    return @intFromBool(null == c.sqlite3ParserAddCleanup(pParse, @ptrCast(@constCast(&sqlite3ExprDeleteGeneric)), pExpr));
}

export fn sqlite3ExprUnmapAndDelete(pParse: Ptr, p: Ptr) void {
    if (p != null) {
        if (inRenameObject(pParse)) {
            c.sqlite3RenameExprUnmap(pParse, p);
        }
        exprDeleteNN(parseDb(pParse), p);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 3: Expr/list duplication and append
// ════════════════════════════════════════════════════════════════════════════

fn exprStructSize(p: Ptr) c_int {
    if (hasProp(p, EP_TokenOnly)) return @intCast(EXPR_TOKENONLYSIZE);
    if (hasProp(p, EP_Reduced)) return @intCast(EXPR_REDUCEDSIZE);
    return @intCast(EXPR_FULLSIZE);
}

const EXPRDUP_REDUCE: c_int = 0x0001;

fn dupedExprStructSize(p: Ptr, flags: c_int) c_int {
    var nSize: c_int = undefined;
    if (0 == flags or hasProp(p, EP_FullSize)) {
        nSize = @intCast(EXPR_FULLSIZE);
    } else {
        if (exprPLeft(p) != null or exprPList(p) != null) {
            nSize = @as(c_int, @intCast(EXPR_REDUCEDSIZE)) | @as(c_int, @bitCast(EP_Reduced));
        } else {
            nSize = @as(c_int, @intCast(EXPR_TOKENONLYSIZE)) | @as(c_int, @bitCast(EP_TokenOnly));
        }
    }
    return nSize;
}

fn dupedExprNodeSize(p: Ptr, flags: c_int) c_int {
    var nByte = dupedExprStructSize(p, flags) & 0xfff;
    if (!hasProp(p, EP_IntValue) and exprUToken(p) != null) {
        nByte += c.sqlite3Strlen30NN(exprUToken(p)) + 1;
    }
    return round8(nByte);
}

fn dupedExprSize(p: Ptr) c_int {
    var nByte = dupedExprNodeSize(p, EXPRDUP_REDUCE);
    if (exprPLeft(p) != null) nByte += dupedExprSize(exprPLeft(p));
    if (exprPRight(p) != null) nByte += dupedExprSize(exprPRight(p));
    return nByte;
}

const EdupBuf = struct {
    zAlloc: ?[*]u8,
};

fn exprDup(db: Ptr, p: Ptr, dupFlags: c_int, pEdupBuf: ?*EdupBuf) Ptr {
    var pNew: Ptr = undefined;
    var sEdupBuf: EdupBuf = undefined;
    var staticFlag: u32 = undefined;
    var nToken: c_int = -1;

    if (pEdupBuf) |peb| {
        sEdupBuf.zAlloc = peb.zAlloc;
        staticFlag = EP_Static;
    } else {
        var nAlloc: c_int = undefined;
        if (dupFlags != 0) {
            nAlloc = dupedExprSize(p);
        } else if (!hasProp(p, EP_IntValue) and exprUToken(p) != null) {
            nToken = c.sqlite3Strlen30NN(exprUToken(p)) + 1;
            nAlloc = round8(@as(c_int, @intCast(EXPR_FULLSIZE)) + nToken);
        } else {
            nToken = 0;
            nAlloc = round8(@intCast(EXPR_FULLSIZE));
        }
        sEdupBuf.zAlloc = @ptrCast(c.sqlite3DbMallocRawNN(db, @intCast(nAlloc)));
        staticFlag = 0;
    }
    pNew = @ptrCast(sEdupBuf.zAlloc);

    if (pNew != null) {
        const nStructSize: u32 = @bitCast(dupedExprStructSize(p, dupFlags));
        var nNewSize: c_int = @bitCast(nStructSize & 0xfff);
        if (nToken < 0) {
            if (!hasProp(p, EP_IntValue) and exprUToken(p) != null) {
                nToken = c.sqlite3Strlen30(exprUToken(p)) + 1;
            } else {
                nToken = 0;
            }
        }
        if (dupFlags != 0) {
            _ = c.memcpy(sEdupBuf.zAlloc, p, @intCast(nNewSize));
        } else {
            const nSize: u32 = @bitCast(exprStructSize(p));
            _ = c.memcpy(sEdupBuf.zAlloc, p, nSize);
            if (nSize < EXPR_FULLSIZE) {
                _ = c.memset(sEdupBuf.zAlloc.? + nSize, 0, @as(usize, @intCast(EXPR_FULLSIZE)) - nSize);
            }
            nNewSize = @intCast(EXPR_FULLSIZE);
        }

        setExprFlags(pNew, exprFlags(pNew) & ~(EP_Reduced | EP_TokenOnly | EP_Static));
        setExprFlags(pNew, exprFlags(pNew) | (nStructSize & (EP_Reduced | EP_TokenOnly)));
        setExprFlags(pNew, exprFlags(pNew) | staticFlag);
        clearVVA(pNew);
        if (dupFlags != 0) {
            setVVA(pNew, EP_Immutable);
        }

        if (nToken > 0) {
            const zToken: [*]u8 = sEdupBuf.zAlloc.? + @as(usize, @intCast(nNewSize));
            wr(?*anyopaque, pNew, Expr_u, @ptrCast(zToken));
            _ = c.memcpy(zToken, exprUToken(p), @intCast(nToken));
            nNewSize += nToken;
        }
        sEdupBuf.zAlloc = sEdupBuf.zAlloc.? + @as(usize, @intCast(round8(nNewSize)));

        if (((exprFlags(p) | exprFlags(pNew)) & (EP_TokenOnly | EP_Leaf)) == 0) {
            if (useXSelect(p)) {
                wr(?*anyopaque, pNew, Expr_x, c.sqlite3SelectDup(db, exprPSelect(p), dupFlags));
            } else {
                wr(?*anyopaque, pNew, Expr_x, sqlite3ExprListDup(db, exprPList(p), if (exprOp(p) != TK_ORDER) dupFlags else 0));
            }

            if (hasProp(p, EP_WinFunc)) {
                wr(?*anyopaque, pNew, Expr_y, c.sqlite3WindowDup(db, pNew, exprYWin(p)));
            }

            if (dupFlags != 0) {
                if (exprOp(p) == TK_SELECT_COLUMN) {
                    wr(?*anyopaque, pNew, Expr_pLeft, exprPLeft(p));
                } else {
                    wr(?*anyopaque, pNew, Expr_pLeft, if (exprPLeft(p) != null) exprDup(db, exprPLeft(p), EXPRDUP_REDUCE, &sEdupBuf) else null);
                }
                wr(?*anyopaque, pNew, Expr_pRight, if (exprPRight(p) != null) exprDup(db, exprPRight(p), EXPRDUP_REDUCE, &sEdupBuf) else null);
            } else {
                if (exprOp(p) == TK_SELECT_COLUMN) {
                    wr(?*anyopaque, pNew, Expr_pLeft, exprPLeft(p));
                } else {
                    wr(?*anyopaque, pNew, Expr_pLeft, sqlite3ExprDup(db, exprPLeft(p), 0));
                }
                wr(?*anyopaque, pNew, Expr_pRight, sqlite3ExprDup(db, exprPRight(p), 0));
            }
        }
    }
    if (pEdupBuf) |peb| peb.* = sEdupBuf;
    return pNew;
}

export fn sqlite3WithDup(db: Ptr, p: Ptr) Ptr {
    var pRet: Ptr = null;
    if (p != null) {
        const nCte = rd(c_int, p, With_nCte);
        const nByte: u64 = @intCast(sizeof_Cte * @as(usize, @intCast(nCte)) + (With_a));
        pRet = c.sqlite3DbMallocZero(db, nByte);
        if (pRet != null) {
            wr(c_int, pRet, With_nCte, nCte);
            var i: c_int = 0;
            while (i < nCte) : (i += 1) {
                const srcCte = cteAt(p, i);
                const dstCte = cteAt(pRet, i);
                wr(?*anyopaque, dstCte, Cte_pSelect, c.sqlite3SelectDup(db, rdp(srcCte, Cte_pSelect), 0));
                wr(?*anyopaque, dstCte, Cte_pCols, sqlite3ExprListDup(db, rdp(srcCte, Cte_pCols), 0));
                wr(?*anyopaque, dstCte, Cte_zName, @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(rdp(srcCte, Cte_zName)))));
                wr(u8, dstCte, Cte_eM10d, rd(u8, srcCte, Cte_eM10d));
            }
        }
    }
    return pRet;
}
inline fn cteAt(pWith: Ptr, i: c_int) Ptr {
    return @ptrCast(base(pWith) + With_a + @as(usize, @intCast(i)) * sizeof_Cte);
}

fn gatherSelectWindowsCallback(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_FUNCTION and hasProp(pExpr, EP_WinFunc)) {
        const pSelect = rdp(pWalker, Walker_u);
        const pWin = exprYWin(pExpr);
        c.sqlite3WindowLink(pSelect, pWin);
    }
    return WRC_Continue;
}
fn gatherSelectWindowsSelectCallback(pWalker: Ptr, p: Ptr) callconv(.c) c_int {
    return if (p == rdp(pWalker, Walker_u)) WRC_Continue else WRC_Prune;
}
fn gatherSelectWindows(p: Ptr) void {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&gatherSelectWindowsCallback)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&gatherSelectWindowsSelectCallback)));
    wr(?*anyopaque, pw, Walker_xSelectCallback2, null);
    wr(?*anyopaque, pw, Walker_pParse, null);
    wr(?*anyopaque, pw, Walker_u, p);
    _ = c.sqlite3WalkSelect(pw, p);
}

export fn sqlite3ExprDup(db: Ptr, p: Ptr, flags: c_int) Ptr {
    return if (p != null) exprDup(db, p, flags, null) else null;
}

export fn sqlite3ExprListDup(db: Ptr, p: Ptr, flags: c_int) Ptr {
    if (p == null) return null;
    const pNew = c.sqlite3DbMallocRawNN(db, c.sqlite3DbMallocSize(db, p));
    if (pNew == null) return null;
    const nExpr = listNExpr(p);
    wr(c_int, pNew, ExprList_nExpr, nExpr);
    wr(c_int, pNew, ExprList_nAlloc, rd(c_int, p, ExprList_nAlloc));
    const aNew = listA(pNew);
    const aOld = listA(p);
    var pPriorSelectColOld: Ptr = null;
    var pPriorSelectColNew: Ptr = null;
    var i: c_int = 0;
    while (i < nExpr) : (i += 1) {
        const pItem = itemAt(aNew, i);
        const pOldItem = itemAt(aOld, i);
        const pOldExpr = rdp(pOldItem, ExprList_item_pExpr);
        wr(?*anyopaque, pItem, ExprList_item_pExpr, sqlite3ExprDup(db, pOldExpr, flags));
        const pNewExpr = rdp(pItem, ExprList_item_pExpr);
        if (pOldExpr != null and exprOp(pOldExpr) == TK_SELECT_COLUMN and pNewExpr != null) {
            if (exprPRight(pNewExpr) != null) {
                pPriorSelectColOld = exprPRight(pOldExpr);
                pPriorSelectColNew = exprPRight(pNewExpr);
                wr(?*anyopaque, pNewExpr, Expr_pLeft, exprPRight(pNewExpr));
            } else {
                if (exprPLeft(pOldExpr) != pPriorSelectColOld) {
                    pPriorSelectColOld = exprPLeft(pOldExpr);
                    pPriorSelectColNew = sqlite3ExprDup(db, pPriorSelectColOld, flags);
                    wr(?*anyopaque, pNewExpr, Expr_pRight, pPriorSelectColNew);
                }
                wr(?*anyopaque, pNewExpr, Expr_pLeft, pPriorSelectColNew);
            }
        }
        wr(?*anyopaque, pItem, ExprList_item_zEName, @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(rdp(pOldItem, ExprList_item_zEName)))));
        // copy fg (4 bytes) and u (4 bytes)
        wr(u32, pItem, ExprList_item_fg, rd(u32, pOldItem, ExprList_item_fg));
        wr(u32, pItem, ExprList_item_u, rd(u32, pOldItem, ExprList_item_u));
    }
    return pNew;
}

// SrcList dup
const SrcItem_zName = off("SrcItem_zName", 0);
const SrcItem_zAlias = off("SrcItem_zAlias", 8);
const SrcItem_u4_pSubq = off("SrcItem_u4_pSubq", 64);
const SrcItem_u4_zDatabase = off("SrcItem_u4_zDatabase", 64);
const sizeof_Subquery = off("sizeof_Subquery", 24);
const Subquery_pSelect = off("Subquery_pSelect", 0);
const Table_nTabRef = off("Table_nTabRef", 44);

// SrcItem.fg bitfield byte layout: byte 0 = jointype(u8); flags start at byte 1.
inline fn srcFgJoinType(pItem: Ptr) u8 {
    return rd(u8, pItem, SrcItem_fg);
}
// the unsigned :1 bitfields after jointype: bit indices within the 4-byte word
// starting at SrcItem_fg+? — we read the dword at fg and test bit positions.
inline fn srcFgWord(pItem: Ptr) u32 {
    return rd(u32, pItem, SrcItem_fg);
}
// bit positions (after the 8-bit jointype): notIndexed=8,isIndexedBy=9,
// isSubquery=10,isTabFunc=11,isCorrelated=12,...,isCte=17,notCte=18,isUsing=19,
// isOn=20,...,fixedSchema=25
const FG_isIndexedBy: u32 = 1 << 9;
const FG_isSubquery: u32 = 1 << 10;
const FG_isTabFunc: u32 = 1 << 11;
const FG_isCte: u32 = 1 << 17;
const FG_isUsing: u32 = 1 << 19;
const FG_fixedSchema: u32 = 1 << 24;
inline fn srcHas(pItem: Ptr, m: u32) bool {
    return (srcFgWord(pItem) & m) != 0;
}
inline fn srcClear(pItem: Ptr, m: u32) void {
    wr(u32, pItem, SrcItem_fg, srcFgWord(pItem) & ~m);
}

export fn sqlite3SrcListDup(db: Ptr, p: Ptr, flags: c_int) Ptr {
    if (p == null) return null;
    const nSrc = rd(c_int, p, SrcList_nSrc);
    // SZ_SRCLIST(n) = offsetof(SrcList,a) + n*sizeof(SrcItem)
    const nByte: u64 = @intCast(SrcList_a + @as(usize, @intCast(nSrc)) * sizeof_SrcItem);
    const pNew = c.sqlite3DbMallocRawNN(db, nByte);
    if (pNew == null) return null;
    wr(c_int, pNew, SrcList_nSrc, nSrc);
    wr(c_int, pNew, SrcList_nAlloc, nSrc);
    var i: c_int = 0;
    while (i < nSrc) : (i += 1) {
        const pNewItem = srcItemAt(pNew, i);
        const pOldItem = srcItemAt(p, i);
        // copy fg fully (4 bytes word at fg)
        wr(u32, pNewItem, SrcItem_fg, srcFgWord(pOldItem));
        if (srcHas(pOldItem, FG_isSubquery)) {
            var pNewSubq = c.sqlite3DbMallocRaw(db, sizeof_Subquery);
            if (pNewSubq == null) {
                srcClear(pNewItem, FG_isSubquery);
            } else {
                _ = c.memcpy(pNewSubq, rdp(pOldItem, SrcItem_u4_pSubq), sizeof_Subquery);
                wr(?*anyopaque, pNewSubq, Subquery_pSelect, c.sqlite3SelectDup(db, rdp(pNewSubq, Subquery_pSelect), flags));
                if (rdp(pNewSubq, Subquery_pSelect) == null) {
                    c.sqlite3DbFree(db, pNewSubq);
                    pNewSubq = null;
                    srcClear(pNewItem, FG_isSubquery);
                }
            }
            wr(?*anyopaque, pNewItem, SrcItem_u4_pSubq, pNewSubq);
        } else if (srcHas(pOldItem, FG_fixedSchema)) {
            wr(?*anyopaque, pNewItem, SrcItem_u4, rdp(pOldItem, SrcItem_u4));
        } else {
            wr(?*anyopaque, pNewItem, SrcItem_u4_zDatabase, @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(rdp(pOldItem, SrcItem_u4_zDatabase)))));
        }
        wr(?*anyopaque, pNewItem, SrcItem_zName, @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(rdp(pOldItem, SrcItem_zName)))));
        wr(?*anyopaque, pNewItem, SrcItem_zAlias, @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(rdp(pOldItem, SrcItem_zAlias)))));
        wr(c_int, pNewItem, SrcItem_iCursor, rd(c_int, pOldItem, SrcItem_iCursor));
        if (srcHas(pNewItem, FG_isIndexedBy)) {
            wr(?*anyopaque, pNewItem, SrcItem_u1, @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(rdp(pOldItem, SrcItem_u1)))));
        } else if (srcHas(pNewItem, FG_isTabFunc)) {
            wr(?*anyopaque, pNewItem, SrcItem_u1, sqlite3ExprListDup(db, rdp(pOldItem, SrcItem_u1), flags));
        } else {
            wr(?*anyopaque, pNewItem, SrcItem_u1, rdp(pOldItem, SrcItem_u1));
        }
        wr(?*anyopaque, pNewItem, SrcItem_u2, rdp(pOldItem, SrcItem_u2));
        if (srcHas(pNewItem, FG_isCte)) {
            const pCteUse = rdp(pNewItem, SrcItem_u2);
            wr(c_int, pCteUse, 0, rd(c_int, pCteUse, 0) + 1); // nUse++
        }
        const pTab = rdp(pOldItem, SrcItem_pSTab);
        wr(?*anyopaque, pNewItem, SrcItem_pSTab, pTab);
        if (pTab != null) {
            wr(u32, pTab, Table_nTabRef, rd(u32, pTab, Table_nTabRef) +% 1);
        }
        if (srcHas(pOldItem, FG_isUsing)) {
            wr(?*anyopaque, pNewItem, SrcItem_u3, c.sqlite3IdListDup(db, rdp(pOldItem, SrcItem_u3)));
        } else {
            wr(?*anyopaque, pNewItem, SrcItem_u3, sqlite3ExprDup(db, rdp(pOldItem, SrcItem_u3), flags));
        }
        wr(u64, pNewItem, SrcItem_colUsed, rd(u64, pOldItem, SrcItem_colUsed));
    }
    return pNew;
}
inline fn srcItemAt(pList: Ptr, i: c_int) Ptr {
    return @ptrCast(base(pList) + SrcList_a + @as(usize, @intCast(i)) * sizeof_SrcItem);
}

export fn sqlite3IdListDup(db: Ptr, p: Ptr) Ptr {
    if (p == null) return null;
    const nId = rd(c_int, p, IdList_nId);
    const nByte: u64 = @intCast(IdList_a + @as(usize, @intCast(nId)) * sizeof_IdList_item);
    const pNew = c.sqlite3DbMallocRawNN(db, nByte);
    if (pNew == null) return null;
    wr(c_int, pNew, IdList_nId, nId);
    var i: c_int = 0;
    while (i < nId) : (i += 1) {
        const pNewItem = idItemAt(pNew, i);
        const pOldItem = idItemAt(p, i);
        wr(?*anyopaque, pNewItem, IdList_item_zName, @ptrCast(c.sqlite3DbStrDup(db, @ptrCast(rdp(pOldItem, IdList_item_zName)))));
    }
    return pNew;
}
inline fn idItemAt(pList: Ptr, i: c_int) Ptr {
    return @ptrCast(base(pList) + IdList_a + @as(usize, @intCast(i)) * sizeof_IdList_item);
}

export fn sqlite3SelectDup(db: Ptr, pDup: Ptr, flags: c_int) Ptr {
    var pRet: Ptr = null;
    var pNext: Ptr = null;
    var pp: *Ptr = &pRet;
    var p = pDup;
    while (p != null) : (p = rdp(p, Select_pPrior)) {
        const pNew = c.sqlite3DbMallocRawNN(db, sizeof_Select);
        if (pNew == null) break;
        wr(?*anyopaque, pNew, Select_pEList, sqlite3ExprListDup(db, rdp(p, Select_pEList), flags));
        wr(?*anyopaque, pNew, Select_pSrc, sqlite3SrcListDup(db, rdp(p, Select_pSrc), flags));
        wr(?*anyopaque, pNew, Select_pWhere, sqlite3ExprDup(db, rdp(p, Select_pWhere), flags));
        wr(?*anyopaque, pNew, Select_pGroupBy, sqlite3ExprListDup(db, rdp(p, Select_pGroupBy), flags));
        wr(?*anyopaque, pNew, Select_pHaving, sqlite3ExprDup(db, rdp(p, Select_pHaving), flags));
        wr(?*anyopaque, pNew, Select_pOrderBy, sqlite3ExprListDup(db, rdp(p, Select_pOrderBy), flags));
        wr(u8, pNew, Select_op, rd(u8, p, Select_op));
        wr(?*anyopaque, pNew, Select_pNext, pNext);
        wr(?*anyopaque, pNew, Select_pPrior, null);
        wr(?*anyopaque, pNew, Select_pLimit, sqlite3ExprDup(db, rdp(p, Select_pLimit), flags));
        wr(c_int, pNew, Select_iLimit, 0);
        wr(c_int, pNew, Select_iOffset, 0);
        wr(u32, pNew, Select_selFlags, rd(u32, p, Select_selFlags));
        wr(i16, pNew, Select_nSelectRow, rd(i16, p, Select_nSelectRow));
        wr(?*anyopaque, pNew, Select_pWith, sqlite3WithDup(db, rdp(p, Select_pWith)));
        wr(?*anyopaque, pNew, Select_pWin, null);
        wr(?*anyopaque, pNew, Select_pWinDefn, c.sqlite3WindowListDup(db, rdp(p, Select_pWinDefn)));
        if (rdp(p, Select_pWin) != null and !dbMallocFailed(db)) gatherSelectWindows(pNew);
        wr(u32, pNew, Select_selId, rd(u32, p, Select_selId));
        if (dbMallocFailed(db)) {
            wr(?*anyopaque, pNew, Select_pNext, null);
            c.sqlite3SelectDelete(db, pNew);
            break;
        }
        pp.* = pNew;
        pp = @ptrCast(@alignCast(base(pNew) + Select_pPrior));
        pNext = pNew;
    }
    return pRet;
}

const zeroItemBuf: [sizeof_ExprList_item]u8 = @splat(0);

const SZ_EXPRLIST_4: u64 = @intCast(ExprList_a + 4 * sizeof_ExprList_item);
export fn sqlite3ExprListAppendNew(db: Ptr, pExpr: Ptr) Ptr {
    const pList = c.sqlite3DbMallocRawNN(db, SZ_EXPRLIST_4);
    if (pList == null) {
        sqlite3ExprDelete(db, pExpr);
        return null;
    }
    wr(c_int, pList, ExprList_nAlloc, 4);
    wr(c_int, pList, ExprList_nExpr, 1);
    const pItem = itemAt(listA(pList), 0);
    _ = c.memcpy(pItem, @constCast(@ptrCast(&zeroItemBuf)), sizeof_ExprList_item);
    wr(?*anyopaque, pItem, ExprList_item_pExpr, pExpr);
    return pList;
}

export fn sqlite3ExprListAppendGrow(db: Ptr, pList0: Ptr, pExpr: Ptr) Ptr {
    var pList = pList0;
    const nAlloc = rd(c_int, pList, ExprList_nAlloc) * 2;
    wr(c_int, pList, ExprList_nAlloc, nAlloc);
    const pNew = c.sqlite3DbRealloc(db, pList, @intCast(ExprList_a + @as(usize, @intCast(nAlloc)) * sizeof_ExprList_item));
    if (pNew == null) {
        sqlite3ExprListDelete(db, pList);
        sqlite3ExprDelete(db, pExpr);
        return null;
    } else {
        pList = pNew;
    }
    const idx = rd(c_int, pList, ExprList_nExpr);
    wr(c_int, pList, ExprList_nExpr, idx + 1);
    const pItem = itemAt(listA(pList), idx);
    _ = c.memcpy(pItem, @constCast(@ptrCast(&zeroItemBuf)), sizeof_ExprList_item);
    wr(?*anyopaque, pItem, ExprList_item_pExpr, pExpr);
    return pList;
}

export fn sqlite3ExprListAppend(pParse: Ptr, pList: Ptr, pExpr: Ptr) Ptr {
    if (pList == null) {
        return sqlite3ExprListAppendNew(parseDb(pParse), pExpr);
    }
    if (rd(c_int, pList, ExprList_nAlloc) < listNExpr(pList) + 1) {
        return sqlite3ExprListAppendGrow(parseDb(pParse), pList, pExpr);
    }
    const idx = listNExpr(pList);
    wr(c_int, pList, ExprList_nExpr, idx + 1);
    const pItem = itemAt(listA(pList), idx);
    _ = c.memcpy(pItem, @constCast(@ptrCast(&zeroItemBuf)), sizeof_ExprList_item);
    wr(?*anyopaque, pItem, ExprList_item_pExpr, pExpr);
    return pList;
}

export fn sqlite3ExprListAppendVector(pParse: Ptr, pList0: Ptr, pColumns: Ptr, pExpr0: Ptr) Ptr {
    var pList = pList0;
    var pExpr = pExpr0;
    const db = parseDb(pParse);
    const iFirst: c_int = if (pList != null) listNExpr(pList) else 0;
    if (pColumns == null) {
        sqlite3ExprUnmapAndDelete(pParse, pExpr);
        c.sqlite3IdListDelete(db, pColumns);
        return pList;
    }
    if (pExpr == null) {
        sqlite3ExprUnmapAndDelete(pParse, pExpr);
        c.sqlite3IdListDelete(db, pColumns);
        return pList;
    }
    const nId = rd(c_int, pColumns, IdList_nId);
    if (exprOp(pExpr) != TK_SELECT) {
        const n = sqlite3ExprVectorSize(pExpr);
        if (nId != n) {
            c.sqlite3ErrorMsg(pParse, "%d columns assigned %d values", nId, n);
            sqlite3ExprUnmapAndDelete(pParse, pExpr);
            c.sqlite3IdListDelete(db, pColumns);
            return pList;
        }
    }
    var i: c_int = 0;
    while (i < nId) : (i += 1) {
        const pSubExpr = sqlite3ExprForVectorField(pParse, pExpr, i, nId);
        if (pSubExpr == null) continue;
        pList = sqlite3ExprListAppend(pParse, pList, pSubExpr);
        if (pList != null) {
            const pItem = itemAt(listA(pList), listNExpr(pList) - 1);
            const pIdItem = idItemAt(pColumns, i);
            wr(?*anyopaque, pItem, ExprList_item_zEName, rdp(pIdItem, IdList_item_zName));
            wr(?*anyopaque, pIdItem, IdList_item_zName, null);
        }
    }
    if (!dbMallocFailed(db) and exprOp(pExpr) == TK_SELECT and pList != null) {
        const pFirst = itemExpr(listA(pList), iFirst);
        wr(?*anyopaque, pFirst, Expr_pRight, pExpr);
        pExpr = null;
        setExprITable(pFirst, nId);
    }
    sqlite3ExprUnmapAndDelete(pParse, pExpr);
    c.sqlite3IdListDelete(db, pColumns);
    return pList;
}

// ════════════════════════════════════════════════════════════════════════════
// Section 4: ExprList setters/delete/flags, constant analysis, integer/null
// ════════════════════════════════════════════════════════════════════════════

// ExprList_item.fg is a struct: byte0 = sortFlags(u8); then bitfields
// eEName:2, done:1, reusable:1, bSorterRef:1, bNulls:1, bUsed:1, bUsingTerm:1,
// bNoExpand:1.  We read/write the 4-byte word at fg.
const FGI_eEName_shift: u5 = 8;
const FGI_eEName_mask: u32 = 0x3 << 8;
const FGI_done: u32 = 1 << 10;
const FGI_reusable: u32 = 1 << 11;
const FGI_bSorterRef: u32 = 1 << 12;
const FGI_bNulls: u32 = 1 << 13;
inline fn itemFg(pItem: Ptr) u32 {
    return rd(u32, pItem, ExprList_item_fg);
}
inline fn setItemFg(pItem: Ptr, v: u32) void {
    wr(u32, pItem, ExprList_item_fg, v);
}
inline fn itemSortFlags(pItem: Ptr) u8 {
    return rd(u8, pItem, ExprList_item_fg);
}
inline fn setItemSortFlags(pItem: Ptr, v: u8) void {
    wr(u8, pItem, ExprList_item_fg, v);
}

export fn sqlite3ExprListSetSortOrder(p: Ptr, iSortOrder0: c_int, eNulls: c_int) void {
    var iSortOrder = iSortOrder0;
    if (p == null) return;
    const pItem = itemAt(listA(p), listNExpr(p) - 1);
    if (iSortOrder == SQLITE_SO_UNDEFINED) {
        iSortOrder = SQLITE_SO_ASC;
    }
    setItemSortFlags(pItem, @truncate(@as(c_uint, @bitCast(iSortOrder))));
    if (eNulls != SQLITE_SO_UNDEFINED) {
        setItemFg(pItem, itemFg(pItem) | FGI_bNulls);
        if (iSortOrder != eNulls) {
            setItemSortFlags(pItem, itemSortFlags(pItem) | KEYINFO_ORDER_BIGNULL);
        }
    }
}

export fn sqlite3ExprListSetName(pParse: Ptr, pList: Ptr, pName: Ptr, dequote: c_int) void {
    if (pList != null) {
        const pItem = itemAt(listA(pList), listNExpr(pList) - 1);
        wr(?*anyopaque, pItem, ExprList_item_zEName, @ptrCast(c.sqlite3DbStrNDup(parseDb(pParse), @ptrCast(rdp(pName, Token_z)), @intCast(rd(c_int, pName, Token_n)))));
        if (dequote != 0) {
            c.sqlite3Dequote(@ptrCast(rdp(pItem, ExprList_item_zEName)));
            if (inRenameObject(pParse)) {
                _ = c.sqlite3RenameTokenMap(pParse, rdp(pItem, ExprList_item_zEName), pName);
            }
        }
    }
}

export fn sqlite3ExprListSetSpan(pParse: Ptr, pList: Ptr, zStart: ?[*]const u8, zEnd: ?[*]const u8) void {
    const db = parseDb(pParse);
    if (pList != null) {
        const pItem = itemAt(listA(pList), listNExpr(pList) - 1);
        if (rdp(pItem, ExprList_item_zEName) == null) {
            wr(?*anyopaque, pItem, ExprList_item_zEName, @ptrCast(c.sqlite3DbSpanDup(db, zStart, zEnd)));
            // set eEName = ENAME_SPAN
            setItemFg(pItem, (itemFg(pItem) & ~FGI_eEName_mask) | (ENAME_SPAN << FGI_eEName_shift));
        }
    }
}

export fn sqlite3ExprListCheckLength(pParse: Ptr, pEList: Ptr, zObject: ?[*:0]const u8) void {
    const mx = dbLimit(parseDb(pParse), SQLITE_LIMIT_COLUMN);
    if (pEList != null and listNExpr(pEList) > mx) {
        c.sqlite3ErrorMsg(pParse, "too many columns in %s", zObject);
    }
}

fn exprListDeleteNN(db: Ptr, pList: Ptr) void {
    var i = listNExpr(pList);
    const a0 = listA(pList);
    var idx: c_int = 0;
    while (true) {
        const pItem = itemAt(a0, idx);
        sqlite3ExprDelete(db, rdp(pItem, ExprList_item_pExpr));
        if (rdp(pItem, ExprList_item_zEName) != null) c.sqlite3DbNNFreeNN(db, rdp(pItem, ExprList_item_zEName));
        idx += 1;
        i -= 1;
        if (i <= 0) break;
    }
    c.sqlite3DbNNFreeNN(db, pList);
}

export fn sqlite3ExprListDelete(db: Ptr, pList: Ptr) void {
    if (pList != null) exprListDeleteNN(db, pList);
}
export fn sqlite3ExprListDeleteGeneric(db: Ptr, pList: Ptr) void {
    if (pList != null) exprListDeleteNN(db, pList);
}

export fn sqlite3ExprListFlags(pList: Ptr) u32 {
    var m: u32 = 0;
    const a0 = listA(pList);
    const n = listNExpr(pList);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        m |= exprFlags(itemExpr(a0, i));
    }
    return m;
}

inline fn walkerSetCode(pWalker: Ptr, v: u16) void {
    wr(u16, pWalker, Walker_eCode, v);
}
inline fn walkerCode(pWalker: Ptr) u16 {
    return rd(u16, pWalker, Walker_eCode);
}
inline fn walkerParse(pWalker: Ptr) Ptr {
    return rdp(pWalker, Walker_pParse);
}
inline fn walkerUInt(pWalker: Ptr) c_int {
    return rd(c_int, pWalker, Walker_u);
}

export fn sqlite3SelectWalkFail(pWalker: Ptr, NotUsed: Ptr) c_int {
    _ = NotUsed;
    walkerSetCode(pWalker, 0);
    return WRC_Abort;
}

export fn sqlite3IsTrueOrFalse(zIn: ?[*:0]const u8) u32 {
    if (c.sqlite3StrICmp(zIn, "true") == 0) return EP_IsTrue;
    if (c.sqlite3StrICmp(zIn, "false") == 0) return EP_IsFalse;
    return 0;
}

export fn sqlite3ExprIdToTrueFalse(pExpr: Ptr) c_int {
    if (!hasProp(pExpr, EP_Quoted | EP_IntValue)) {
        const v = sqlite3IsTrueOrFalse(exprUToken(pExpr));
        if (v != 0) {
            setExprOp(pExpr, TK_TRUEFALSE);
            setProp(pExpr, v);
            return 1;
        }
    }
    return 0;
}

export fn sqlite3ExprTruthValue(pExpr0: Ptr) c_int {
    const pExpr = sqlite3ExprSkipCollateAndLikely(@constCast(pExpr0));
    return @intFromBool(exprUToken(pExpr).?[4] == 0);
}

export fn sqlite3ExprSimplifiedAndOr(pExpr0: Ptr) Ptr {
    var pExpr = pExpr0;
    if (exprOp(pExpr) == TK_AND or exprOp(pExpr) == TK_OR) {
        const pRight = sqlite3ExprSimplifiedAndOr(exprPRight(pExpr));
        const pLeft = sqlite3ExprSimplifiedAndOr(exprPLeft(pExpr));
        if (alwaysTrue(pLeft) or alwaysFalse(pRight)) {
            pExpr = if (exprOp(pExpr) == TK_AND) pRight else pLeft;
        } else if (alwaysTrue(pRight) or alwaysFalse(pLeft)) {
            pExpr = if (exprOp(pExpr) == TK_AND) pLeft else pRight;
        }
    }
    return pExpr;
}

fn exprEvalRhsFirst(pExpr: Ptr) bool {
    return hasProp(exprPLeft(pExpr), EP_Subquery) and !hasProp(exprPRight(pExpr), EP_Subquery);
}

fn exprComputeOperands(pParse: Ptr, pExpr: Ptr, pR1: *c_int, pR2: *c_int, pFree1: *c_int, pFree2: *c_int) c_int {
    var addrIsNull: c_int = undefined;
    var r2: c_int = 0;
    const v = parseVdbe(pParse);
    if (exprEvalRhsFirst(pExpr) and sqlite3ExprCanBeNull(exprPRight(pExpr)) != 0) {
        r2 = sqlite3ExprCodeTemp(pParse, exprPRight(pExpr), pFree2);
        addrIsNull = c.sqlite3VdbeAddOp1(v, OP.IsNull, r2);
    } else {
        r2 = 0;
        addrIsNull = 0;
    }
    const r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), pFree1);
    if (addrIsNull == 0) {
        if (hasProp(exprPRight(pExpr), EP_Subquery) and sqlite3ExprCanBeNull(exprPLeft(pExpr)) != 0) {
            addrIsNull = c.sqlite3VdbeAddOp1(v, OP.IsNull, r1);
        }
        r2 = sqlite3ExprCodeTemp(pParse, exprPRight(pExpr), pFree2);
    }
    pR1.* = r1;
    pR2.* = r2;
    return addrIsNull;
}

fn exprNodeIsConstantFunction(pWalker: Ptr, pExpr: Ptr) c_int {
    var n: c_int = undefined;
    if (hasProp(pExpr, EP_TokenOnly) or exprPList(pExpr) == null) {
        n = 0;
    } else {
        const pList = exprPList(pExpr);
        n = listNExpr(pList);
        _ = c.sqlite3WalkExprList(pWalker, pList);
        if (walkerCode(pWalker) == 0) return WRC_Abort;
    }
    const db = parseDb(walkerParse(pWalker));
    const pDef = c.sqlite3FindFunction(db, exprUToken(pExpr), n, dbEnc(db), 0);
    if (pDef == null or rdp(pDef, FuncDef_xFinalize) != null or (rd(u32, pDef, FuncDef_funcFlags) & (SQLITE_FUNC_CONSTANT | SQLITE_FUNC_SLOCHNG)) == 0 or hasProp(pExpr, EP_WinFunc)) {
        walkerSetCode(pWalker, 0);
        return WRC_Abort;
    }
    return WRC_Prune;
}

fn exprNodeIsConstant(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const ec = walkerCode(pWalker);
    if (ec == 2 and hasProp(pExpr, EP_OuterON)) {
        walkerSetCode(pWalker, 0);
        return WRC_Abort;
    }
    switch (exprOp(pExpr)) {
        TK_FUNCTION => {
            if ((ec >= 4 or hasProp(pExpr, EP_ConstFunc)) and !hasProp(pExpr, EP_WinFunc)) {
                if (ec == 5) setProp(pExpr, EP_FromDDL);
                return WRC_Continue;
            } else if (walkerParse(pWalker) != null) {
                return exprNodeIsConstantFunction(pWalker, pExpr);
            } else {
                walkerSetCode(pWalker, 0);
                return WRC_Abort;
            }
        },
        TK_ID => {
            if (sqlite3ExprIdToTrueFalse(pExpr) != 0) {
                return WRC_Prune;
            }
            return constColumnCase(pWalker, pExpr, ec);
        },
        TK_COLUMN, TK_AGG_FUNCTION, TK_AGG_COLUMN => {
            return constColumnCase(pWalker, pExpr, ec);
        },
        TK_IF_NULL_ROW, TK_REGISTER, TK_DOT, TK_RAISE => {
            walkerSetCode(pWalker, 0);
            return WRC_Abort;
        },
        TK_VARIABLE => {
            if (ec == 5) {
                setExprOp(pExpr, TK_NULL);
            } else if (ec == 4) {
                walkerSetCode(pWalker, 0);
                return WRC_Abort;
            }
            return WRC_Continue;
        },
        else => return WRC_Continue,
    }
}
// shared fall-through from TK_ID/TK_COLUMN/TK_AGG_* into TK_IF_NULL_ROW/etc.
fn constColumnCase(pWalker: Ptr, pExpr: Ptr, ec: u16) c_int {
    if (hasProp(pExpr, EP_FixedCol) and ec != 2) {
        return WRC_Continue;
    }
    if (ec == 3 and exprITable(pExpr) == walkerUInt(pWalker)) {
        return WRC_Continue;
    }
    walkerSetCode(pWalker, 0);
    return WRC_Abort;
}

fn initWalkerConst(pw: Ptr, pParse: Ptr, initFlag: c_int) void {
    walkerSetCode(pw, @intCast(initFlag));
    wr(?*anyopaque, pw, Walker_pParse, pParse);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&exprNodeIsConstant)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&sqlite3SelectWalkFail)));
    if (config.sqlite_debug) {
        wr(?*anyopaque, pw, Walker_xSelectCallback2, @ptrCast(@constCast(&c.sqlite3SelectWalkAssert2)));
    }
}

fn exprIsConst(pParse: Ptr, p: Ptr, initFlag: c_int) c_int {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    initWalkerConst(pw, pParse, initFlag);
    _ = c.sqlite3WalkExpr(pw, p);
    return walkerCode(pw);
}

export fn sqlite3ExprIsConstant(pParse: Ptr, p: Ptr) c_int {
    return exprIsConst(pParse, p, 1);
}

fn sqlite3ExprIsConstantNotJoin(pParse: Ptr, p: Ptr) c_int {
    return exprIsConst(pParse, p, 2);
}

fn exprSelectWalkTableConstant(pWalker: Ptr, pSelect: Ptr) callconv(.c) c_int {
    if ((rd(u32, pSelect, Select_selFlags) & SF_Correlated) != 0) {
        walkerSetCode(pWalker, 0);
        return WRC_Abort;
    }
    return WRC_Prune;
}

fn sqlite3ExprIsTableConstant(p: Ptr, iCur: c_int, bAllowSubq: c_int) c_int {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    walkerSetCode(pw, 3);
    wr(?*anyopaque, pw, Walker_pParse, null);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&exprNodeIsConstant)));
    if (bAllowSubq != 0) {
        wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&exprSelectWalkTableConstant)));
    } else {
        wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&sqlite3SelectWalkFail)));
        if (config.sqlite_debug) {
            wr(?*anyopaque, pw, Walker_xSelectCallback2, @ptrCast(@constCast(&c.sqlite3SelectWalkAssert2)));
        }
    }
    wr(c_int, pw, Walker_u, iCur);
    _ = c.sqlite3WalkExpr(pw, p);
    return walkerCode(pw);
}

inline fn exprWJoin(p: Ptr) c_int {
    return rd(c_int, p, Expr_w);
}

export fn sqlite3ExprIsSingleTableConstraint(pExpr: Ptr, pSrcList: Ptr, iSrc: c_int, bAllowSubq: c_int) c_int {
    const pSrc = srcItemAt(pSrcList, iSrc);
    const jt = srcFgJoinType(pSrc);
    if ((jt & JT_LTORJ) != 0) return 0;
    if ((jt & JT_LEFT) != 0) {
        if (!hasProp(pExpr, EP_OuterON)) return 0;
        if (exprWJoin(pExpr) != rd(c_int, pSrc, SrcItem_iCursor)) return 0;
    } else {
        if (hasProp(pExpr, EP_OuterON)) return 0;
    }
    if (hasProp(pExpr, EP_OuterON | EP_InnerON) and (srcFgJoinType(srcItemAt(pSrcList, 0)) & JT_LTORJ) != 0) {
        var jj: c_int = 0;
        while (jj < iSrc) : (jj += 1) {
            if (exprWJoin(pExpr) == rd(c_int, srcItemAt(pSrcList, jj), SrcItem_iCursor)) {
                if ((srcFgJoinType(srcItemAt(pSrcList, jj)) & JT_LTORJ) != 0) {
                    return 0;
                }
                break;
            }
        }
    }
    return sqlite3ExprIsTableConstant(pExpr, rd(c_int, pSrc, SrcItem_iCursor), bAllowSubq);
}

fn exprNodeIsConstantOrGroupBy(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const pGroupBy = rdp(pWalker, Walker_u);
    const a0 = listA(pGroupBy);
    const n = listNExpr(pGroupBy);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const p = itemExpr(a0, i);
        if (sqlite3ExprCompare(null, pExpr, p, -1) < 2) {
            const pColl = sqlite3ExprNNCollSeq(walkerParse(pWalker), p);
            if (c.sqlite3IsBinary(pColl) != 0) {
                return WRC_Prune;
            }
        }
    }
    if (useXSelect(pExpr)) {
        walkerSetCode(pWalker, 0);
        return WRC_Abort;
    }
    return exprNodeIsConstant(pWalker, pExpr);
}

export fn sqlite3ExprIsConstantOrGroupBy(pParse: Ptr, p: Ptr, pGroupBy: Ptr) c_int {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    walkerSetCode(pw, 1);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&exprNodeIsConstantOrGroupBy)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, null);
    wr(?*anyopaque, pw, Walker_u, pGroupBy);
    wr(?*anyopaque, pw, Walker_pParse, pParse);
    _ = c.sqlite3WalkExpr(pw, p);
    return walkerCode(pw);
}

export fn sqlite3ExprIsConstantOrFunction(p: Ptr, isInit: u8) c_int {
    return exprIsConst(null, p, 4 + @as(c_int, isInit));
}

export fn sqlite3ExprIsInteger(p: Ptr, pValue: *c_int, pParse: Ptr) c_int {
    var rc: c_int = 0;
    if (p == null) return 0;
    if ((exprFlags(p) & EP_IntValue) != 0) {
        pValue.* = exprUValue(p);
        return 1;
    }
    switch (exprOp(p)) {
        TK_UPLUS => {
            rc = sqlite3ExprIsInteger(exprPLeft(p), pValue, null);
        },
        TK_UMINUS => {
            var vv: c_int = 0;
            if (sqlite3ExprIsInteger(exprPLeft(p), &vv, null) != 0) {
                pValue.* = -vv;
                rc = 1;
            }
        },
        TK_VARIABLE => {
            if (pParse == null) return rc;
            if (parseVdbe(pParse) == null) return rc;
            if ((rd(u64, parseDb(pParse), sqlite3_flags) & SQLITE_EnableQPSG) != 0) return rc;
            c.sqlite3VdbeSetVarmask(parseVdbe(pParse), exprIColumn(p));
            const pVal = c.sqlite3VdbeGetBoundValue(rdp(pParse, Parse_pReprepare), exprIColumn(p), SQLITE_AFF_BLOB);
            if (pVal != null) {
                if (c.sqlite3_value_type(pVal) == SQLITE_INTEGER) {
                    const vv = c.sqlite3_value_int64(pVal);
                    if (vv == (vv & 0x7fffffff)) {
                        pValue.* = @intCast(vv);
                        rc = 1;
                    }
                }
                c.sqlite3ValueFree(pVal);
            }
        },
        else => {},
    }
    return rc;
}

export fn sqlite3ExprCanBeNull(p0: Ptr) c_int {
    var p = p0;
    while (exprOp(p) == TK_UPLUS or exprOp(p) == TK_UMINUS) {
        p = exprPLeft(p);
    }
    var o = exprOp(p);
    if (o == TK_REGISTER) o = exprOp2(p);
    switch (o) {
        TK_INTEGER, TK_STRING, TK_FLOAT, TK_BLOB => return 0,
        TK_COLUMN => {
            const pTab = exprYTab(p);
            if (hasProp(p, EP_CanBeNull)) return 1;
            if (pTab == null) return 1;
            const iCol = exprIColumn(p);
            if (iCol >= 0 and rdp(pTab, Table_aCol) != null and iCol < rd(i16, pTab, Table_nCol) and colNotNull(rdpCol(pTab, iCol)) == 0) {
                return 1;
            }
            return 0;
        },
        else => return 1,
    }
}

export fn sqlite3ExprNeedsNoAffinityChange(p0: Ptr, aff: u8) c_int {
    var p = p0;
    var unaryMinus: c_int = 0;
    if (aff == SQLITE_AFF_BLOB) return 1;
    while (exprOp(p) == TK_UPLUS or exprOp(p) == TK_UMINUS) {
        if (exprOp(p) == TK_UMINUS) unaryMinus = 1;
        p = exprPLeft(p);
    }
    var o = exprOp(p);
    if (o == TK_REGISTER) o = exprOp2(p);
    switch (o) {
        TK_INTEGER => return @intFromBool(aff >= SQLITE_AFF_NUMERIC),
        TK_FLOAT => return @intFromBool(aff >= SQLITE_AFF_NUMERIC),
        TK_STRING => return @intFromBool(unaryMinus == 0 and aff == SQLITE_AFF_TEXT),
        TK_BLOB => return @intFromBool(unaryMinus == 0),
        TK_COLUMN => return @intFromBool(aff >= SQLITE_AFF_NUMERIC and exprIColumn(p) < 0),
        else => return 0,
    }
}

export fn sqlite3IsRowid(z: ?[*:0]const u8) c_int {
    if (c.sqlite3StrICmp(z, "_ROWID_") == 0) return 1;
    if (c.sqlite3StrICmp(z, "ROWID") == 0) return 1;
    if (c.sqlite3StrICmp(z, "OID") == 0) return 1;
    return 0;
}

const azRowidOpt = [_][*:0]const u8{ "_ROWID_", "ROWID", "OID" };
export fn sqlite3RowidAlias(pTab: Ptr) ?[*:0]const u8 {
    var ii: usize = 0;
    while (ii < azRowidOpt.len) : (ii += 1) {
        if (c.sqlite3ColumnIndex(pTab, azRowidOpt[ii]) < 0) return azRowidOpt[ii];
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Section 5: IN-operator index selection, RHS materialization, subselect
// ════════════════════════════════════════════════════════════════════════════

const SrcItem_pSchema = 0; // unused
fn isCandidateForInOpt(pX: Ptr) Ptr {
    if (!useXSelect(pX)) return null;
    if (hasProp(pX, EP_VarSelect)) return null;
    const p = exprPSelect(pX);
    if (rdp(p, Select_pPrior) != null) return null;
    if ((rd(u32, p, Select_selFlags) & (SF_Distinct | SF_Aggregate)) != 0) return null;
    if (rdp(p, Select_pLimit) != null) return null;
    if (rdp(p, Select_pWhere) != null) return null;
    const pSrc = rdp(p, Select_pSrc);
    if (rd(c_int, pSrc, SrcList_nSrc) != 1) return null;
    const item0 = srcItemAt(pSrc, 0);
    if (srcHas(item0, FG_isSubquery)) return null;
    const pTab = rdp(item0, SrcItem_pSTab);
    if (isVirtual(pTab)) return null;
    const pEList = rdp(p, Select_pEList);
    const a0 = listA(pEList);
    const n = listNExpr(pEList);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        if (exprOp(itemExpr(a0, i)) != TK_COLUMN) return null;
    }
    return p;
}

inline fn isVirtual(pTab: Ptr) bool {
    // Table.eTabType==TABTYP_VTAB (==1)
    const eTabType = rd(u8, pTab, off("Table_eTabType", 51));
    return eTabType == 1;
}
inline fn hasRowid(pTab: Ptr) bool {
    return (rd(u32, pTab, Table_tabFlags) & 0x0080) == 0; // TF_WithoutRowid==0x80
}

fn setHasNullFlag(v: Ptr, iCur: c_int, regHasNull: c_int) void {
    _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, regHasNull);
    const addr1 = c.sqlite3VdbeAddOp1(v, op.Rewind, iCur);
    _ = c.sqlite3VdbeAddOp3(v, op.Column, iCur, 0, regHasNull);
    c.sqlite3VdbeChangeP5(v, OPFLAG_TYPEOFARG);
    c.sqlite3VdbeJumpHere(v, addr1);
}

fn inRhsIsConstant(pParse: Ptr, pIn: Ptr) c_int {
    const pLHS = exprPLeft(pIn);
    wr(?*anyopaque, pIn, Expr_pLeft, null);
    const res = sqlite3ExprIsConstant(pParse, pIn);
    wr(?*anyopaque, pIn, Expr_pLeft, pLHS);
    return res;
}

inline fn isUniqueIndex(pIdx: Ptr) bool {
    return rd(u8, pIdx, off("Index_onError", 93)) != 0; // OE_None==0
}
inline fn idxAiColumn(pIdx: Ptr, j: c_int) i16 {
    const a = rdp(pIdx, Index_aiColumn);
    return rd(i16, a, @as(usize, @intCast(j)) * 2);
}
inline fn idxAzColl(pIdx: Ptr, j: c_int) ?[*:0]const u8 {
    const a = rdp(pIdx, Index_azColl);
    return @ptrCast(rd(?*anyopaque, a, @as(usize, @intCast(j)) * 8));
}
inline fn idxASortOrder(pIdx: Ptr, j: c_int) u8 {
    const a = rdp(pIdx, Index_aSortOrder);
    return rd(u8, a, @as(usize, @intCast(j)));
}

export fn sqlite3FindInIndex(pParse: Ptr, pX: Ptr, inFlags: u32, prRhsHasNull0: ?*c_int, aiMap: ?[*]c_int, piTab: *c_int) c_int {
    var prRhsHasNull = prRhsHasNull0;
    var eType: c_int = 0;
    const mustBeUnique = (inFlags & IN_INDEX_LOOP) != 0;
    var iTab = parseNTab(pParse);
    setParseNTab(pParse, iTab + 1);
    const v = c.sqlite3GetVdbe(pParse);

    if (prRhsHasNull != null and useXSelect(pX)) {
        const pEList = rdp(exprPSelect(pX), Select_pEList);
        const a0 = listA(pEList);
        const ne = listNExpr(pEList);
        var i: c_int = 0;
        while (i < ne) : (i += 1) {
            if (sqlite3ExprCanBeNull(itemExpr(a0, i)) != 0) break;
        }
        if (i == ne) prRhsHasNull = null;
    }

    if (parseNErr(pParse) == 0) {
        const p = isCandidateForInOpt(pX);
        if (p != null) {
            const db = parseDb(pParse);
            const pEList = rdp(p, Select_pEList);
            const nExpr = listNExpr(pEList);
            const pTab = rdp(srcItemAt(rdp(p, Select_pSrc), 0), SrcItem_pSTab);
            const iDb = c.sqlite3SchemaToIndex(db, rdp(pTab, Table_pSchema));
            c.sqlite3CodeVerifySchema(pParse, iDb);
            c.sqlite3TableLock(pParse, iDb, rd(c_int, pTab, Table_tnum), 0, @ptrCast(rdp(pTab, Table_zName)));
            if (nExpr == 1 and exprIColumn(itemExpr(listA(pEList), 0)) < 0) {
                const iAddr = c.sqlite3VdbeAddOp0(v, op.Once);
                c.sqlite3OpenTable(pParse, iTab, iDb, pTab, op.OpenRead);
                eType = IN_INDEX_ROWID;
                c.sqlite3VdbeJumpHere(v, iAddr);
            } else {
                var affinity_ok: c_int = 1;
                var i: c_int = 0;
                while (i < nExpr and affinity_ok != 0) : (i += 1) {
                    const pLhs = sqlite3VectorFieldSubexpr(exprPLeft(pX), i);
                    const iCol = exprIColumn(itemExpr(listA(pEList), i));
                    const idxaff = sqlite3TableColumnAffinity(pTab, iCol);
                    const cmpaff = sqlite3CompareAffinity(pLhs, idxaff);
                    switch (cmpaff) {
                        SQLITE_AFF_BLOB => {},
                        SQLITE_AFF_TEXT => {},
                        else => affinity_ok = @intFromBool(isNumericAffinity(idxaff)),
                    }
                }
                if (affinity_ok != 0) {
                    var pIdx = rdp(pTab, Table_pIndex);
                    while (pIdx != null and eType == 0) : (pIdx = rdp(pIdx, Index_pNext)) {
                        if (rd(i16, pIdx, Index_nColumn) < nExpr) continue;
                        if (rdp(pIdx, Index_pPartIdxWhere) != null) continue;
                        if (rd(i16, pIdx, Index_nColumn) >= BMS - 1) continue;
                        if (mustBeUnique) {
                            if (rd(i16, pIdx, Index_nKeyCol) > nExpr or (rd(i16, pIdx, Index_nColumn) > nExpr and !isUniqueIndex(pIdx))) {
                                continue;
                            }
                        }
                        var colUsed: u64 = 0;
                        i = 0;
                        while (i < nExpr) : (i += 1) {
                            const pLhs = sqlite3VectorFieldSubexpr(exprPLeft(pX), i);
                            const pRhs = itemExpr(listA(pEList), i);
                            const pReq = sqlite3BinaryCompareCollSeq(pParse, pLhs, pRhs);
                            var j: c_int = 0;
                            while (j < nExpr) : (j += 1) {
                                if (idxAiColumn(pIdx, j) != exprIColumn(pRhs)) continue;
                                if (pReq != null and c.sqlite3StrICmp(@ptrCast(rdp(pReq, CollSeq_zName)), idxAzColl(pIdx, j)) != 0) {
                                    continue;
                                }
                                break;
                            }
                            if (j == nExpr) break;
                            const mCol = @as(u64, 1) << @intCast(j);
                            if ((mCol & colUsed) != 0) break;
                            colUsed |= mCol;
                            if (aiMap) |am| am[@intCast(i)] = j;
                        }
                        if (colUsed == (@as(u64, 1) << @intCast(nExpr)) - 1) {
                            const iAddr = c.sqlite3VdbeAddOp0(v, op.Once);
                            _ = c.sqlite3VdbeAddOp3(v, op.OpenRead, iTab, rd(c_int, pIdx, Index_tnum), iDb);
                            c.sqlite3VdbeSetP4KeyInfo(pParse, pIdx);
                            eType = IN_INDEX_INDEX_ASC + idxASortOrder(pIdx, 0);
                            if (prRhsHasNull != null) {
                                prRhsHasNull.?.* = incParseNMem(pParse);
                                if (nExpr == 1) {
                                    setHasNullFlag(v, iTab, prRhsHasNull.?.*);
                                }
                            }
                            c.sqlite3VdbeJumpHere(v, iAddr);
                        }
                    }
                }
            }
        }
    }

    if (eType == 0 and (inFlags & IN_INDEX_NOOP_OK) != 0 and useXList(pX) and (inRhsIsConstant(pParse, pX) == 0 or listNExpr(exprPList(pX)) <= 2)) {
        setParseNTab(pParse, parseNTab(pParse) - 1);
        iTab = -1;
        eType = IN_INDEX_NOOP;
    }

    if (eType == 0) {
        const savedNQueryLoop = rd(u32, pParse, Parse_nQueryLoop);
        var rMayHaveNull: c_int = 0;
        var bloomOk: c_int = @intFromBool((inFlags & IN_INDEX_MEMBERSHIP) != 0);
        eType = IN_INDEX_EPH;
        if ((inFlags & IN_INDEX_LOOP) != 0) {
            wr(u32, pParse, Parse_nQueryLoop, 0);
        } else if (prRhsHasNull != null) {
            rMayHaveNull = incParseNMem(pParse);
            prRhsHasNull.?.* = rMayHaveNull;
        }
        if (bloomOk == 0 and useXSelect(pX) and (rd(u32, exprPSelect(pX), Select_selFlags) & SF_ClonedRhsIn) != 0) {
            bloomOk = 1;
        }
        sqlite3CodeRhsOfIN(pParse, pX, iTab, bloomOk);
        if (rMayHaveNull != 0) {
            setHasNullFlag(v, iTab, rMayHaveNull);
        }
        wr(u32, pParse, Parse_nQueryLoop, savedNQueryLoop);
    }

    if (aiMap != null and eType != IN_INDEX_INDEX_ASC and eType != IN_INDEX_INDEX_DESC) {
        const n = sqlite3ExprVectorSize(exprPLeft(pX));
        var i: c_int = 0;
        while (i < n) : (i += 1) aiMap.?[@intCast(i)] = i;
    }
    piTab.* = iTab;
    return eType;
}

fn exprINAffinity(pParse: Ptr, pExpr: Ptr) ?[*]u8 {
    const pLeft = exprPLeft(pExpr);
    const nVal = sqlite3ExprVectorSize(pLeft);
    const pSelect: Ptr = if (useXSelect(pExpr)) exprPSelect(pExpr) else null;
    const zRet: ?[*]u8 = @ptrCast(c.sqlite3DbMallocRaw(pParse.?, @intCast(1 + nVal)));
    if (zRet) |z| {
        var i: c_int = 0;
        while (i < nVal) : (i += 1) {
            const pA = sqlite3VectorFieldSubexpr(pLeft, i);
            const a = sqlite3ExprAffinity(pA);
            if (pSelect != null) {
                z[@intCast(i)] = sqlite3CompareAffinity(itemExpr(listA(rdp(pSelect, Select_pEList)), i), a);
            } else {
                z[@intCast(i)] = a;
            }
        }
        z[@intCast(nVal)] = 0;
    }
    return zRet;
}

export fn sqlite3SubselectError(pParse: Ptr, nActual: c_int, nExpect: c_int) void {
    if (parseNErr(pParse) == 0) {
        c.sqlite3ErrorMsg(pParse, "sub-select returns %d columns - expected %d", nActual, nExpect);
    }
}

export fn sqlite3VectorErrorMsg(pParse: Ptr, pExpr: Ptr) void {
    if (useXSelect(pExpr)) {
        sqlite3SubselectError(pParse, listNExpr(rdp(exprPSelect(pExpr), Select_pEList)), 1);
    } else {
        errMsg0(pParse, "row value misused");
    }
}

fn findCompatibleInRhsSubrtn(pParse: Ptr, pExpr: Ptr, pNewSig: Ptr) c_int {
    if (pNewSig == null) return 0;
    const selId = rd(c_int, pNewSig, SubrtnSig_selId);
    const sh: u3 = @intCast(@as(u32, @bitCast(selId)) & 7);
    if ((rd(u8, pParse, Parse_mSubrtnSig) & (@as(u8, 1) << sh)) == 0) return 0;
    const v = parseVdbe(pParse);
    var pOp = c.sqlite3VdbeGetOp(v, 1);
    const pEnd = c.sqlite3VdbeGetLastOp(v);
    while (@intFromPtr(pOp.?) < @intFromPtr(pEnd.?)) : (pOp = @ptrFromInt(@intFromPtr(pOp.?) + sizeof_VdbeOp)) {
        if (rd(i8, pOp, VdbeOp_p4type) != P4_SUBRTNSIG) continue;
        const pSig = rdp(pOp, VdbeOp_p4);
        if (rd(u8, pSig, SubrtnSig_bComplete) == 0) continue;
        if (rd(c_int, pNewSig, SubrtnSig_selId) != rd(c_int, pSig, SubrtnSig_selId)) continue;
        if (c.strcmp(@ptrCast(rdp(pNewSig, SubrtnSig_zAff)), @ptrCast(rdp(pSig, SubrtnSig_zAff))) != 0) continue;
        wr(c_int, pExpr, Expr_y, rd(c_int, pSig, SubrtnSig_iAddr)); // y.sub.iAddr
        wr(c_int, pExpr, Expr_y_sub_regReturn, rd(c_int, pSig, SubrtnSig_regReturn));
        setExprITable(pExpr, rd(c_int, pSig, SubrtnSig_iTable));
        setProp(pExpr, EP_Subrtn);
        return 1;
    }
    return 0;
}

inline fn exprYSubIAddr(p: Ptr) c_int {
    return rd(c_int, p, Expr_y);
}
inline fn setExprYSubIAddr(p: Ptr, v: c_int) void {
    wr(c_int, p, Expr_y, v);
}
inline fn exprYSubRegReturn(p: Ptr) c_int {
    return rd(c_int, p, Expr_y_sub_regReturn);
}
inline fn setExprYSubRegReturn(p: Ptr, v: c_int) void {
    wr(c_int, p, Expr_y_sub_regReturn, v);
}

export fn sqlite3CodeRhsOfIN(pParse: Ptr, pExpr: Ptr, iTab: c_int, allowBloom: c_int) void {
    var addrOnce: c_int = 0;
    var pKeyInfo: Ptr = null;
    var pSig: Ptr = null;
    const v = parseVdbe(pParse);

    if (!hasProp(pExpr, EP_VarSelect) and parseISelfTab(pParse) == 0) {
        if (useXSelect(pExpr) and (rd(u32, exprPSelect(pExpr), Select_selFlags) & SF_All) == 0) {
            pSig = c.sqlite3DbMallocRawNN(parseDb(pParse), sizeof_SubrtnSig);
            if (pSig != null) {
                wr(c_int, pSig, SubrtnSig_selId, @bitCast(rd(u32, exprPSelect(pExpr), Select_selId)));
                wr(?*anyopaque, pSig, SubrtnSig_zAff, @ptrCast(exprINAffinity(pParse, pExpr)));
            }
        }

        if (hasProp(pExpr, EP_Subrtn) or findCompatibleInRhsSubrtn(pParse, pExpr, pSig) != 0) {
            addrOnce = c.sqlite3VdbeAddOp0(v, op.Once);
            _ = c.sqlite3VdbeAddOp2(v, op.Gosub, exprYSubRegReturn(pExpr), exprYSubIAddr(pExpr));
            _ = c.sqlite3VdbeAddOp2(v, op.OpenDup, iTab, exprITable(pExpr));
            c.sqlite3VdbeJumpHere(v, addrOnce);
            if (pSig != null) {
                c.sqlite3DbFree(parseDb(pParse), rdp(pSig, SubrtnSig_zAff));
                c.sqlite3DbFree(parseDb(pParse), pSig);
            }
            return;
        }

        setProp(pExpr, EP_Subrtn);
        setExprYSubRegReturn(pExpr, incParseNMem(pParse));
        setExprYSubIAddr(pExpr, c.sqlite3VdbeAddOp2(v, op.BeginSubrtn, 0, exprYSubRegReturn(pExpr)) + 1);
        if (pSig != null) {
            wr(u8, pSig, SubrtnSig_bComplete, 0);
            wr(c_int, pSig, SubrtnSig_iAddr, exprYSubIAddr(pExpr));
            wr(c_int, pSig, SubrtnSig_regReturn, exprYSubRegReturn(pExpr));
            wr(c_int, pSig, SubrtnSig_iTable, iTab);
            const sh: u3 = @intCast(@as(u32, @bitCast(rd(c_int, pSig, SubrtnSig_selId))) & 7);
            wr(u8, pParse, Parse_mSubrtnSig, @as(u8, 1) << sh);
            c.sqlite3VdbeChangeP4(v, -1, @ptrCast(pSig), P4_SUBRTNSIG);
        }
        addrOnce = c.sqlite3VdbeAddOp0(v, op.Once);
    }

    const pLeft = exprPLeft(pExpr);
    const nVal = sqlite3ExprVectorSize(pLeft);

    setExprITable(pExpr, iTab);
    const addr = c.sqlite3VdbeAddOp2(v, op.OpenEphemeral, exprITable(pExpr), nVal);
    pKeyInfo = c.sqlite3KeyInfoAlloc(parseDb(pParse), nVal, 1);

    if (useXSelect(pExpr)) {
        const pSelect = exprPSelect(pExpr);
        const pEList = rdp(pSelect, Select_pEList);
        if (listNExpr(pEList) == nVal) {
            var dest: [sizeof_SelectDest]u8 align(8) = undefined;
            const pdest: Ptr = @ptrCast(&dest);
            var addrBloom: c_int = 0;
            c.sqlite3SelectDestInit(pdest, SRT_Set, iTab);
            wr(?*anyopaque, pdest, SelectDest_zAffSdst, @ptrCast(exprINAffinity(pParse, pExpr)));
            wr(c_int, pSelect, Select_iLimit, 0);
            if (addrOnce != 0 and allowBloom != 0 and optimizationEnabled(parseDb(pParse), SQLITE_BloomFilter)) {
                const regBloom = incParseNMem(pParse);
                addrBloom = c.sqlite3VdbeAddOp2(v, op.Blob, 10000, regBloom);
                wr(c_int, pdest, SelectDest_iSDParm2, regBloom);
            }
            const pCopy = sqlite3SelectDup(parseDb(pParse), pSelect, 0);
            const rc: c_int = if (dbMallocFailed(parseDb(pParse))) 1 else c.sqlite3Select(pParse, pCopy, pdest);
            c.sqlite3SelectDelete(parseDb(pParse), pCopy);
            c.sqlite3DbFree(parseDb(pParse), rdp(pdest, SelectDest_zAffSdst));
            if (addrBloom != 0) {
                wr(c_int, c.sqlite3VdbeGetOp(v, addrOnce), VdbeOp_p3, rd(c_int, pdest, SelectDest_iSDParm2));
                if (rd(c_int, pdest, SelectDest_iSDParm2) == 0) {
                    wr(c_int, c.sqlite3VdbeGetOp(v, addrBloom), VdbeOp_p1, 10);
                }
            }
            if (rc != 0) {
                c.sqlite3KeyInfoUnref(pKeyInfo);
                return;
            }
            var i: c_int = 0;
            while (i < nVal) : (i += 1) {
                const p = sqlite3VectorFieldSubexpr(pLeft, i);
                keyInfoSetColl(pKeyInfo, i, sqlite3BinaryCompareCollSeq(pParse, p, itemExpr(listA(pEList), i)));
            }
        }
    } else if (exprPList(pExpr) != null) {
        var affinity = sqlite3ExprAffinity(pLeft);
        const pList = exprPList(pExpr);
        if (affinity <= SQLITE_AFF_NONE) {
            affinity = SQLITE_AFF_BLOB;
        } else if (affinity == SQLITE_AFF_REAL) {
            affinity = SQLITE_AFF_NUMERIC;
        }
        if (pKeyInfo != null) {
            keyInfoSetColl(pKeyInfo, 0, sqlite3ExprCollSeq(pParse, exprPLeft(pExpr)));
        }
        const r1 = sqlite3GetTempReg(pParse);
        const r2 = sqlite3GetTempReg(pParse);
        const a0 = listA(pList);
        var i = listNExpr(pList);
        var k: c_int = 0;
        while (i > 0) : (i -= 1) {
            const pE2 = itemExpr(a0, k);
            k += 1;
            if (addrOnce != 0 and sqlite3ExprIsConstant(pParse, pE2) == 0) {
                _ = c.sqlite3VdbeChangeToNoop(v, addrOnce - 1);
                _ = c.sqlite3VdbeChangeToNoop(v, addrOnce);
                clearProp(pExpr, EP_Subrtn);
                addrOnce = 0;
            }
            sqlite3ExprCode(pParse, pE2, r1);
            var affByte: [1]u8 = .{affinity};
            _ = c.sqlite3VdbeAddOp4(v, op.MakeRecord, r1, 1, r2, &affByte, 1);
            _ = c.sqlite3VdbeAddOp4Int(v, op.IdxInsert, iTab, r2, r1, 1);
        }
        sqlite3ReleaseTempReg(pParse, r1);
        sqlite3ReleaseTempReg(pParse, r2);
    }
    if (pSig != null) wr(u8, pSig, SubrtnSig_bComplete, 1);
    if (pKeyInfo != null) {
        c.sqlite3VdbeChangeP4(v, addr, @ptrCast(pKeyInfo), P4_KEYINFO);
    }
    if (addrOnce != 0) {
        _ = c.sqlite3VdbeAddOp1(v, op.NullRow, iTab);
        c.sqlite3VdbeJumpHere(v, addrOnce);
        _ = c.sqlite3VdbeAddOp3(v, op.Return, exprYSubRegReturn(pExpr), exprYSubIAddr(pExpr), 1);
        sqlite3ClearTempRegCache(pParse);
    }
}

inline fn optimizationEnabled(db: Ptr, mask: u32) bool {
    // (db->dbOptFlags & mask)==0
    const dbOptFlags = rd(u32, db, off("sqlite3_dbOptFlags", 220));
    return (dbOptFlags & mask) == 0;
}
const KeyInfo_aColl = off("KeyInfo_aColl", 32);
inline fn keyInfoSetColl(pKeyInfo: Ptr, i: c_int, pColl: Ptr) void {
    const a = base(pKeyInfo) + KeyInfo_aColl;
    const slot: *align(1) ?*anyopaque = @ptrCast(a + @as(usize, @intCast(i)) * 8);
    slot.* = pColl;
}

export fn sqlite3CodeSubselect(pParse: Ptr, pExpr: Ptr) c_int {
    var addrOnce: c_int = 0;
    var rReg: c_int = 0;
    const v = parseVdbe(pParse);
    if (parseNErr(pParse) != 0) return 0;
    const pSel = exprPSelect(pExpr);

    if (hasProp(pExpr, EP_Subrtn)) {
        _ = c.sqlite3VdbeAddOp2(v, op.Gosub, exprYSubRegReturn(pExpr), exprYSubIAddr(pExpr));
        return exprITable(pExpr);
    }

    setProp(pExpr, EP_Subrtn);
    setExprYSubRegReturn(pExpr, incParseNMem(pParse));
    setExprYSubIAddr(pExpr, c.sqlite3VdbeAddOp2(v, op.BeginSubrtn, 0, exprYSubRegReturn(pExpr)) + 1);

    if (!hasProp(pExpr, EP_VarSelect)) {
        addrOnce = c.sqlite3VdbeAddOp0(v, op.Once);
    }

    const nReg: c_int = if (exprOp(pExpr) == TK_SELECT) listNExpr(rdp(pSel, Select_pEList)) else 1;
    var dest: [sizeof_SelectDest]u8 align(8) = undefined;
    const pdest: Ptr = @ptrCast(&dest);
    c.sqlite3SelectDestInit(pdest, 0, parseNMem(pParse) + 1);
    setParseNMem(pParse, parseNMem(pParse) + nReg);
    if (exprOp(pExpr) == TK_SELECT) {
        wr(u8, pdest, SelectDest_eDest, SRT_Mem);
        const lim = rdp(pSel, Select_pLimit);
        if ((rd(u32, pSel, Select_selFlags) & SF_Distinct) != 0 and lim != null and exprPRight(lim) != null) {
            wr(c_int, pdest, SelectDest_iSdst, parseNMem(pParse) + 1);
            setParseNMem(pParse, parseNMem(pParse) + nReg);
        } else {
            wr(c_int, pdest, SelectDest_iSdst, rd(c_int, pdest, SelectDest_iSDParm));
        }
        wr(c_int, pdest, SelectDest_nSdst, nReg);
        _ = c.sqlite3VdbeAddOp3(v, op.Null, 0, rd(c_int, pdest, SelectDest_iSDParm), parseNMem(pParse));
    } else {
        wr(u8, pdest, SelectDest_eDest, SRT_Exists);
        _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, rd(c_int, pdest, SelectDest_iSDParm));
    }
    if (rdp(pSel, Select_pLimit) != null) {
        const pLeft = exprPLeft(rdp(pSel, Select_pLimit));
        if (!hasProp(pLeft, EP_IntValue) or (exprUValue(pLeft) != 1 and exprUValue(pLeft) != 0)) {
            const db = parseDb(pParse);
            var pLimit = sqlite3ExprInt32(db, 0);
            if (pLimit != null) {
                wr(u8, pLimit, Expr_affExpr, SQLITE_AFF_NUMERIC);
                pLimit = sqlite3PExpr(pParse, TK_NE, sqlite3ExprDup(db, pLeft, 0), pLimit);
            }
            _ = sqlite3ExprDeferredDelete(pParse, pLeft);
            wr(?*anyopaque, rdp(pSel, Select_pLimit), Expr_pLeft, pLimit);
        }
    } else {
        const pLimit = sqlite3ExprInt32(parseDb(pParse), 1);
        wr(?*anyopaque, pSel, Select_pLimit, sqlite3PExpr(pParse, TK_LIMIT, pLimit, null));
    }
    wr(c_int, pSel, Select_iLimit, 0);
    if (c.sqlite3Select(pParse, pSel, pdest) != 0) {
        setExprOp2(pExpr, exprOp(pExpr));
        setExprOp(pExpr, TK_ERROR);
        return 0;
    }
    rReg = rd(c_int, pdest, SelectDest_iSDParm);
    setExprITable(pExpr, rReg);
    setVVA(pExpr, EP_NoReduce);
    if (addrOnce != 0) {
        c.sqlite3VdbeJumpHere(v, addrOnce);
    }
    _ = c.sqlite3VdbeAddOp3(v, op.Return, exprYSubRegReturn(pExpr), exprYSubIAddr(pExpr), 1);
    sqlite3ClearTempRegCache(pParse);
    return rReg;
}

export fn sqlite3ExprCheckIN(pParse: Ptr, pIn: Ptr) c_int {
    const nVector = sqlite3ExprVectorSize(exprPLeft(pIn));
    if (useXSelect(pIn) and !dbMallocFailed(parseDb(pParse))) {
        if (nVector != listNExpr(rdp(exprPSelect(pIn), Select_pEList))) {
            sqlite3SubselectError(pParse, listNExpr(rdp(exprPSelect(pIn), Select_pEList)), nVector);
            return 1;
        }
    } else if (nVector != 1) {
        sqlite3VectorErrorMsg(pParse, exprPLeft(pIn));
        return 1;
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// Section 6: IN codegen, literals, column extraction, ExprCodeTarget
// ════════════════════════════════════════════════════════════════════════════

fn sqlite3ExprCodeIN(pParse: Ptr, pExpr: Ptr, destIfFalse: c_int, destIfNull: c_int) void {
    var rRhsHasNull: c_int = 0;
    var iTab: c_int = 0;
    const savedOkConstFactor = okConstFactor(pParse);
    const pLeft = exprPLeft(pExpr);
    if (sqlite3ExprCheckIN(pParse, pExpr) != 0) return;
    const zAff = exprINAffinity(pParse, pExpr);
    const nVector = sqlite3ExprVectorSize(exprPLeft(pExpr));
    const aiMapRaw = c.sqlite3DbMallocZero(parseDb(pParse), @intCast(nVector * 4));
    const aiMap: ?[*]c_int = @ptrCast(@alignCast(aiMapRaw));
    if (dbMallocFailed(parseDb(pParse))) {
        c.sqlite3DbFree(parseDb(pParse), aiMapRaw);
        c.sqlite3DbFree(parseDb(pParse), @ptrCast(zAff));
        return;
    }
    const v = parseVdbe(pParse);
    const eType = sqlite3FindInIndex(pParse, pExpr, IN_INDEX_MEMBERSHIP | IN_INDEX_NOOP_OK, if (destIfFalse == destIfNull) null else &rRhsHasNull, aiMap, &iTab);

    setOkConstFactor(pParse, false);
    var iDummy: c_int = 0;
    var rLhs = exprCodeVector(pParse, pLeft, &iDummy);
    setOkConstFactor(pParse, savedOkConstFactor);

    if (eType == IN_INDEX_NOOP) {
        const pList = exprPList(pExpr);
        const pColl = sqlite3ExprCollSeq(pParse, exprPLeft(pExpr));
        const labelOk = c.sqlite3VdbeMakeLabel(pParse);
        var regCkNull: c_int = 0;
        if (destIfNull != destIfFalse) {
            regCkNull = sqlite3GetTempReg(pParse);
            _ = c.sqlite3VdbeAddOp3(v, op.BitAnd, rLhs, rLhs, regCkNull);
        }
        const a0 = listA(pList);
        const ne = listNExpr(pList);
        var ii: c_int = 0;
        while (ii < ne) : (ii += 1) {
            var regToFree: c_int = 0;
            const r2 = sqlite3ExprCodeTemp(pParse, itemExpr(a0, ii), &regToFree);
            if (regCkNull != 0 and sqlite3ExprCanBeNull(itemExpr(a0, ii)) != 0) {
                _ = c.sqlite3VdbeAddOp3(v, op.BitAnd, regCkNull, r2, regCkNull);
            }
            sqlite3ReleaseTempReg(pParse, regToFree);
            if (ii < ne - 1 or destIfNull != destIfFalse) {
                const o: c_int = if (rLhs != r2) OP.Eq else OP.NotNull;
                _ = c.sqlite3VdbeAddOp4(v, o, rLhs, labelOk, r2, @ptrCast(pColl), P4_COLLSEQ);
                c.sqlite3VdbeChangeP5(v, zAff.?[0]);
            } else {
                const o: c_int = if (rLhs != r2) OP.Ne else OP.IsNull;
                _ = c.sqlite3VdbeAddOp4(v, o, rLhs, destIfFalse, r2, @ptrCast(pColl), P4_COLLSEQ);
                c.sqlite3VdbeChangeP5(v, zAff.?[0] | @as(u8, @intCast(SQLITE_JUMPIFNULL)));
            }
        }
        if (regCkNull != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.IsNull, regCkNull, destIfNull);
            c.sqlite3VdbeGoto(v, destIfFalse);
        }
        c.sqlite3VdbeResolveLabel(v, labelOk);
        sqlite3ReleaseTempReg(pParse, regCkNull);
        c.sqlite3DbFree(parseDb(pParse), aiMapRaw);
        c.sqlite3DbFree(parseDb(pParse), @ptrCast(zAff));
        return;
    }

    if (eType != IN_INDEX_ROWID) {
        _ = c.sqlite3VdbeAddOp4(v, op.Affinity, rLhs, nVector, 0, @ptrCast(zAff), nVector);
        var i: c_int = 0;
        while (i < nVector and aiMap.?[@intCast(i)] == i) : (i += 1) {}
        if (i != nVector) {
            const rLhsOrig = rLhs;
            rLhs = sqlite3GetTempRange(pParse, nVector);
            i = 0;
            while (i < nVector) : (i += 1) {
                _ = c.sqlite3VdbeAddOp3(v, op.Copy, rLhsOrig + i, rLhs + aiMap.?[@intCast(i)], 0);
            }
            sqlite3ReleaseTempReg(pParse, rLhsOrig);
        }
    }

    var destStep2: c_int = undefined;
    var destStep6: c_int = 0;
    if (destIfNull == destIfFalse) {
        destStep2 = destIfFalse;
    } else {
        destStep6 = c.sqlite3VdbeMakeLabel(pParse);
        destStep2 = destStep6;
    }
    var i: c_int = 0;
    while (i < nVector) : (i += 1) {
        const p = sqlite3VectorFieldSubexpr(exprPLeft(pExpr), i);
        if (parseNErr(pParse) != 0) {
            c.sqlite3DbFree(parseDb(pParse), aiMapRaw);
            c.sqlite3DbFree(parseDb(pParse), @ptrCast(zAff));
            return;
        }
        if (sqlite3ExprCanBeNull(p) != 0) {
            _ = c.sqlite3VdbeAddOp2(v, op.IsNull, rLhs + aiMap.?[@intCast(i)], destStep2);
        }
    }

    var addrTruthOp: c_int = 0;
    if (eType == IN_INDEX_ROWID) {
        _ = c.sqlite3VdbeAddOp3(v, op.SeekRowid, iTab, destIfFalse, rLhs);
        addrTruthOp = c.sqlite3VdbeAddOp0(v, op.Goto);
    } else {
        if (destIfFalse == destIfNull) {
            if (hasProp(pExpr, EP_Subrtn)) {
                const pOp = c.sqlite3VdbeGetOp(v, exprYSubIAddr(pExpr));
                if (rd(c_int, pOp, VdbeOp_p3) > 0) {
                    _ = c.sqlite3VdbeAddOp4Int(v, op.Filter, rd(c_int, pOp, VdbeOp_p3), destIfFalse, rLhs, nVector);
                }
            }
            _ = c.sqlite3VdbeAddOp4Int(v, op.NotFound, iTab, destIfFalse, rLhs, nVector);
            c.sqlite3DbFree(parseDb(pParse), aiMapRaw);
            c.sqlite3DbFree(parseDb(pParse), @ptrCast(zAff));
            return;
        }
        addrTruthOp = c.sqlite3VdbeAddOp4Int(v, op.Found, iTab, 0, rLhs, nVector);
    }

    if (rRhsHasNull != 0 and nVector == 1) {
        _ = c.sqlite3VdbeAddOp2(v, op.NotNull, rRhsHasNull, destIfFalse);
    }

    if (destIfFalse == destIfNull) c.sqlite3VdbeGoto(v, destIfFalse);

    if (destStep6 != 0) c.sqlite3VdbeResolveLabel(v, destStep6);
    const addrTop = c.sqlite3VdbeAddOp2(v, op.Rewind, iTab, destIfFalse);
    var destNotNull: c_int = undefined;
    if (nVector > 1) {
        destNotNull = c.sqlite3VdbeMakeLabel(pParse);
    } else {
        destNotNull = destIfFalse;
    }
    i = 0;
    while (i < nVector) : (i += 1) {
        const r3 = sqlite3GetTempReg(pParse);
        const p = sqlite3VectorFieldSubexpr(pLeft, i);
        var pColl: Ptr = undefined;
        if (useXSelect(pExpr)) {
            const pRhs = itemExpr(listA(rdp(exprPSelect(pExpr), Select_pEList)), i);
            pColl = sqlite3BinaryCompareCollSeq(pParse, p, pRhs);
        } else {
            pColl = sqlite3ExprCollSeq(pParse, p);
        }
        _ = c.sqlite3VdbeAddOp3(v, op.Column, iTab, aiMap.?[@intCast(i)], r3);
        _ = c.sqlite3VdbeAddOp4(v, OP.Ne, rLhs + aiMap.?[@intCast(i)], destNotNull, r3, @ptrCast(pColl), P4_COLLSEQ);
        sqlite3ReleaseTempReg(pParse, r3);
    }
    _ = c.sqlite3VdbeAddOp2(v, op.Goto, 0, destIfNull);
    if (nVector > 1) {
        c.sqlite3VdbeResolveLabel(v, destNotNull);
        _ = c.sqlite3VdbeAddOp2(v, op.Next, iTab, addrTop + 1);
        _ = c.sqlite3VdbeAddOp2(v, op.Goto, 0, destIfFalse);
    }

    c.sqlite3VdbeJumpHere(v, addrTruthOp);

    c.sqlite3DbFree(parseDb(pParse), aiMapRaw);
    c.sqlite3DbFree(parseDb(pParse), @ptrCast(zAff));
}

fn codeReal(v: Ptr, z: ?[*:0]const u8, negateFlag: c_int, iMem: c_int) void {
    var value: f64 = undefined;
    _ = c.sqlite3AtoF(z, &value);
    if (negateFlag != 0) value = -value;
    const vp: [*]const u8 = @ptrCast(&value);
    _ = c.sqlite3VdbeAddOp4Dup8(v, op.Real, 0, iMem, 0, vp, P4_REAL);
}

fn codeInteger(pParse: Ptr, pExpr: Ptr, negFlag: c_int, iMem: c_int) void {
    const v = parseVdbe(pParse);
    if ((exprFlags(pExpr) & EP_IntValue) != 0) {
        var i = exprUValue(pExpr);
        if (negFlag != 0) i = -i;
        _ = c.sqlite3VdbeAddOp2(v, op.Integer, i, iMem);
    } else {
        var value: i64 = undefined;
        const z = exprUToken(pExpr);
        const cc = c.sqlite3DecOrHexToI64(z, &value);
        if ((cc == 3 and negFlag == 0) or cc == 2 or (negFlag != 0 and value == SMALLEST_INT64)) {
            if (c.sqlite3_strnicmp(z, "0x", 2) == 0) {
                c.sqlite3ErrorMsg(pParse, "hex literal too big: %s%#T", @as([*:0]const u8, if (negFlag != 0) "-" else ""), pExpr);
            } else {
                codeReal(v, z, negFlag, iMem);
            }
        } else {
            if (negFlag != 0) {
                value = if (cc == 3) SMALLEST_INT64 else -value;
            }
            const vp: [*]const u8 = @ptrCast(&value);
            _ = c.sqlite3VdbeAddOp4Dup8(v, op.Int64, 0, iMem, 0, vp, P4_INT64);
        }
    }
}

export fn sqlite3ExprCodeLoadIndexColumn(pParse: Ptr, pIdx: Ptr, iTabCur: c_int, iIdxCol: c_int, regOut: c_int) void {
    const iTabCol = idxAiColumn(pIdx, iIdxCol);
    if (iTabCol == XN_EXPR) {
        setParseISelfTab(pParse, iTabCur + 1);
        sqlite3ExprCodeCopy(pParse, itemExpr(listA(rdp(pIdx, Index_aColExpr)), iIdxCol), regOut);
        setParseISelfTab(pParse, 0);
    } else {
        sqlite3ExprCodeGetColumnOfTable(parseVdbe(pParse), rdp(pIdx, Index_pTable), iTabCur, iTabCol, regOut);
    }
}

export fn sqlite3ExprCodeGeneratedColumn(pParse: Ptr, pTab: Ptr, pCol: Ptr, regOut: c_int) void {
    var iAddr: c_int = 0;
    const v = parseVdbe(pParse);
    const nErr = parseNErr(pParse);
    if (parseISelfTab(pParse) > 0) {
        iAddr = c.sqlite3VdbeAddOp3(v, op.IfNullRow, parseISelfTab(pParse) - 1, 0, regOut);
    } else {
        iAddr = 0;
    }
    sqlite3ExprCodeCopy(pParse, c.sqlite3ColumnExpr(pTab, pCol), regOut);
    if ((colFlags(pCol) & COLFLAG_VIRTUAL) != 0 and (rd(u32, pTab, Table_tabFlags) & TF_Strict) != 0) {
        const p3 = 2 + @as(c_int, @intCast((@intFromPtr(pCol.?) - @intFromPtr(rdp(pTab, Table_aCol).?)) / sizeof_Column));
        _ = c.sqlite3VdbeAddOp4(v, op.TypeCheck, regOut, 1, p3, @ptrCast(pTab), P4_TABLE);
    } else if (colAffinity(pCol) >= SQLITE_AFF_TEXT) {
        _ = c.sqlite3VdbeAddOp4(v, op.Affinity, regOut, 1, 0, @ptrCast(base(pCol) + Column_affinity), 1);
    }
    if (iAddr != 0) c.sqlite3VdbeJumpHere(v, iAddr);
    if (parseNErr(pParse) > nErr) wr(c_int, parseDb(pParse), sqlite3_errByteOffset, -1);
}

export fn sqlite3ExprCodeGetColumnOfTable(v: Ptr, pTab: Ptr, iTabCur: c_int, iCol: c_int, regOut: c_int) void {
    if (iCol < 0 or iCol == rd(i16, pTab, Table_iPKey)) {
        _ = c.sqlite3VdbeAddOp2(v, op.Rowid, iTabCur, regOut);
    } else {
        var opcode: c_int = undefined;
        var x: c_int = undefined;
        if (isVirtual(pTab)) {
            opcode = op.VColumn;
            x = iCol;
        } else if ((colFlags(rdpCol(pTab, iCol)) & COLFLAG_VIRTUAL) != 0) {
            const pCol = rdpCol(pTab, iCol);
            const pParse = c.sqlite3VdbeParser(v);
            if ((colFlags(pCol) & COLFLAG_BUSY) != 0) {
                c.sqlite3ErrorMsg(pParse, "generated column loop on \"%s\"", colCnName(pCol));
            } else {
                const savedSelfTab = parseISelfTab(pParse);
                setColFlags(pCol, colFlags(pCol) | COLFLAG_BUSY);
                setParseISelfTab(pParse, iTabCur + 1);
                sqlite3ExprCodeGeneratedColumn(pParse, pTab, pCol, regOut);
                setParseISelfTab(pParse, savedSelfTab);
                setColFlags(pCol, colFlags(pCol) & ~COLFLAG_BUSY);
            }
            return;
        } else if (!hasRowid(pTab)) {
            x = c.sqlite3TableColumnToIndex(c.sqlite3PrimaryKeyIndex(pTab), @intCast(iCol));
            opcode = op.Column;
        } else {
            x = c.sqlite3TableColumnToStorage(pTab, @intCast(iCol));
            opcode = op.Column;
        }
        _ = c.sqlite3VdbeAddOp3(v, opcode, iTabCur, x, regOut);
        c.sqlite3ColumnDefault(v, pTab, iCol, regOut);
    }
}

export fn sqlite3ExprCodeGetColumn(pParse: Ptr, pTab: Ptr, iColumn: c_int, iTable: c_int, iReg: c_int, p5: u8) c_int {
    sqlite3ExprCodeGetColumnOfTable(parseVdbe(pParse), pTab, iTable, iColumn, iReg);
    if (p5 != 0) {
        const pOp = c.sqlite3VdbeGetLastOp(parseVdbe(pParse));
        if (rd(u8, pOp, VdbeOp_opcode) == op.Column) wr(u8, pOp, VdbeOp_p5, p5);
        if (rd(u8, pOp, VdbeOp_opcode) == op.VColumn) wr(u8, pOp, VdbeOp_p5, p5 & OPFLAG_NOCHNG);
    }
    return iReg;
}

export fn sqlite3ExprCodeMove(pParse: Ptr, iFrom: c_int, iTo: c_int, nReg: c_int) void {
    _ = c.sqlite3VdbeAddOp3(parseVdbe(pParse), op.Move, iFrom, iTo, nReg);
}

export fn sqlite3ExprToRegister(pExpr: Ptr, iReg: c_int) void {
    const p = sqlite3ExprSkipCollateAndLikely(pExpr);
    if (p == null) return;
    if (exprOp(p) == TK_REGISTER) {
        // assert
    } else {
        setExprOp2(p, exprOp(p));
        setExprOp(p, TK_REGISTER);
        setExprITable(p, iReg);
        clearProp(p, EP_Skip);
    }
}

fn exprCodeVector(pParse: Ptr, p: Ptr, piFreeable: *c_int) c_int {
    var iResult: c_int = undefined;
    const nResult = sqlite3ExprVectorSize(p);
    if (nResult == 1) {
        iResult = sqlite3ExprCodeTemp(pParse, p, piFreeable);
    } else {
        piFreeable.* = 0;
        if (exprOp(p) == TK_SELECT) {
            iResult = sqlite3CodeSubselect(pParse, p);
        } else {
            iResult = parseNMem(pParse) + 1;
            setParseNMem(pParse, parseNMem(pParse) + nResult);
            var i: c_int = 0;
            while (i < nResult) : (i += 1) {
                sqlite3ExprCodeFactorable(pParse, itemExpr(listA(exprPList(p)), i), i + iResult);
            }
        }
    }
    return iResult;
}

fn setDoNotMergeFlagOnCopy(v: Ptr) void {
    if (rd(u8, c.sqlite3VdbeGetLastOp(v), VdbeOp_opcode) == op.Copy) {
        c.sqlite3VdbeChangeP5(v, 1);
    }
}

fn exprCodeInlineFunction(pParse: Ptr, pFarg: Ptr, iFuncId: c_int, target0: c_int) c_int {
    var target = target0;
    const v = parseVdbe(pParse);
    const nFarg = listNExpr(pFarg);
    const a0 = listA(pFarg);
    switch (iFuncId) {
        INLINEFUNC_coalesce => {
            const endCoalesce = c.sqlite3VdbeMakeLabel(pParse);
            sqlite3ExprCode(pParse, itemExpr(a0, 0), target);
            var i: c_int = 1;
            while (i < nFarg) : (i += 1) {
                _ = c.sqlite3VdbeAddOp2(v, op.NotNull, target, endCoalesce);
                sqlite3ExprCode(pParse, itemExpr(a0, i), target);
            }
            setDoNotMergeFlagOnCopy(v);
            c.sqlite3VdbeResolveLabel(v, endCoalesce);
        },
        INLINEFUNC_iif => {
            var caseExpr: [sizeof_Expr]u8 align(8) = undefined;
            const pce: Ptr = @ptrCast(&caseExpr);
            _ = c.memset(pce, 0, sizeof_Expr);
            setExprOp(pce, TK_CASE);
            wr(?*anyopaque, pce, Expr_x, pFarg);
            return sqlite3ExprCodeTarget(pParse, pce, target);
        },
        INLINEFUNC_sqlite_offset => {
            const pArg = itemExpr(a0, 0);
            if (exprOp(pArg) == TK_COLUMN and exprITable(pArg) >= 0) {
                _ = c.sqlite3VdbeAddOp3(v, op.Offset, exprITable(pArg), exprIColumn(pArg), target);
            } else {
                _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, target);
            }
        },
        INLINEFUNC_expr_compare => {
            _ = c.sqlite3VdbeAddOp2(v, op.Integer, sqlite3ExprCompare(null, itemExpr(a0, 0), itemExpr(a0, 1), -1), target);
        },
        INLINEFUNC_expr_implies_expr => {
            _ = c.sqlite3VdbeAddOp2(v, op.Integer, sqlite3ExprImpliesExpr(pParse, itemExpr(a0, 0), itemExpr(a0, 1), -1), target);
        },
        INLINEFUNC_implies_nonnull_row => {
            const pA1 = itemExpr(a0, 1);
            if (exprOp(pA1) == TK_COLUMN) {
                _ = c.sqlite3VdbeAddOp2(v, op.Integer, sqlite3ExprImpliesNonNullRow(itemExpr(a0, 0), exprITable(pA1), 1), target);
            } else {
                _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, target);
            }
        },
        INLINEFUNC_affinity => {
            const azAff = [_][*:0]const u8{ "blob", "text", "numeric", "integer", "real", "flexnum" };
            const aff = sqlite3ExprAffinity(itemExpr(a0, 0));
            c.sqlite3VdbeLoadString(v, target, if (aff <= SQLITE_AFF_NONE) "none" else azAff[aff - SQLITE_AFF_BLOB]);
        },
        else => {
            target = sqlite3ExprCodeTarget(pParse, itemExpr(a0, 0), target);
        },
    }
    return target;
}

fn exprNodeCanReturnSubtype(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_CASE or exprOp(pExpr) == TK_UPLUS or exprOp(pExpr) == TK_COLLATE or exprOp(pExpr) == TK_CAST) {
        return WRC_Continue;
    }
    if (exprOp(pExpr) != TK_FUNCTION) {
        return WRC_Prune;
    }
    const db = parseDb(walkerParse(pWalker));
    const n: c_int = if (exprPList(pExpr) != null) listNExpr(exprPList(pExpr)) else 0;
    const pDef = c.sqlite3FindFunction(db, exprUToken(pExpr), n, dbEnc(db), 0);
    if (pDef == null or (rd(u32, pDef, FuncDef_funcFlags) & SQLITE_RESULT_SUBTYPE) != 0) {
        walkerSetCode(pWalker, 1);
        return WRC_Abort;
    }
    return WRC_Continue;
}

fn sqlite3ExprCanReturnSubtype(pParse: Ptr, pExpr: Ptr) c_int {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    _ = c.memset(pw, 0, sizeof_Walker);
    wr(?*anyopaque, pw, Walker_pParse, pParse);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&exprNodeCanReturnSubtype)));
    _ = c.sqlite3WalkExpr(pw, pExpr);
    return walkerCode(pw);
}

fn sqlite3IndexedExprLookup(pParse: Ptr, pExpr: Ptr, target: c_int) c_int {
    var p = rdp(pParse, Parse_pIdxEpr);
    while (p != null) : (p = rdp(p, IndexedExpr_pIENext)) {
        var iDataCur = rd(c_int, p, IndexedExpr_iDataCur);
        if (iDataCur < 0) continue;
        if (parseISelfTab(pParse) != 0) {
            if (rd(c_int, p, IndexedExpr_iDataCur) != parseISelfTab(pParse) - 1) continue;
            iDataCur = -1;
        }
        if (sqlite3ExprCompare(null, pExpr, rdp(p, IndexedExpr_pExpr), iDataCur) != 0) continue;
        const exprAff = sqlite3ExprAffinity(pExpr);
        const paff = rd(u8, p, IndexedExpr_aff);
        if ((exprAff <= SQLITE_AFF_BLOB and paff != SQLITE_AFF_BLOB) or (exprAff == SQLITE_AFF_TEXT and paff != SQLITE_AFF_TEXT) or (exprAff >= SQLITE_AFF_NUMERIC and paff != SQLITE_AFF_NUMERIC)) {
            continue;
        }
        if (hasProp(pExpr, EP_SubtArg) and sqlite3ExprCanReturnSubtype(pParse, pExpr) != 0) {
            continue;
        }
        const v = parseVdbe(pParse);
        if (rd(u8, p, IndexedExpr_bMaybeNullRow) != 0) {
            const addr = c.sqlite3VdbeCurrentAddr(v);
            _ = c.sqlite3VdbeAddOp3(v, op.IfNullRow, rd(c_int, p, IndexedExpr_iIdxCur), addr + 3, target);
            _ = c.sqlite3VdbeAddOp3(v, op.Column, rd(c_int, p, IndexedExpr_iIdxCur), rd(c_int, p, IndexedExpr_iIdxCol), target);
            c.sqlite3VdbeGoto(v, 0);
            const psave = rdp(pParse, Parse_pIdxEpr);
            wr(?*anyopaque, pParse, Parse_pIdxEpr, null);
            sqlite3ExprCode(pParse, pExpr, target);
            wr(?*anyopaque, pParse, Parse_pIdxEpr, psave);
            c.sqlite3VdbeJumpHere(v, addr + 2);
        } else {
            _ = c.sqlite3VdbeAddOp3(v, op.Column, rd(c_int, p, IndexedExpr_iIdxCur), rd(c_int, p, IndexedExpr_iIdxCol), target);
        }
        return target;
    }
    return -1;
}

fn exprPartidxExprLookup(pParse: Ptr, pExpr: Ptr, iTarget: c_int) c_int {
    var p = rdp(pParse, Parse_pIdxPartExpr);
    while (p != null) : (p = rdp(p, IndexedExpr_pIENext)) {
        if (exprIColumn(pExpr) == rd(c_int, p, IndexedExpr_iIdxCol) and exprITable(pExpr) == rd(c_int, p, IndexedExpr_iDataCur)) {
            const v = parseVdbe(pParse);
            var addr: c_int = 0;
            if (rd(u8, p, IndexedExpr_bMaybeNullRow) != 0) {
                addr = c.sqlite3VdbeAddOp1(v, op.IfNullRow, rd(c_int, p, IndexedExpr_iIdxCur));
            }
            const ret = sqlite3ExprCodeTarget(pParse, rdp(p, IndexedExpr_pExpr), iTarget);
            _ = c.sqlite3VdbeAddOp4(parseVdbe(pParse), op.Affinity, ret, 1, 0, @ptrCast(base(p) + IndexedExpr_aff), 1);
            if (addr != 0) {
                c.sqlite3VdbeJumpHere(v, addr);
                c.sqlite3VdbeChangeP3(v, addr, ret);
            }
            return ret;
        }
    }
    return 0;
}

fn exprCodeTargetAndOr(pParse: Ptr, pExpr: Ptr, target: c_int, pTmpReg: *c_int) c_int {
    const o = exprOp(pExpr);
    const v = parseVdbe(pParse);
    const pAlt = sqlite3ExprSimplifiedAndOr(pExpr);
    if (pAlt != pExpr) {
        const r1 = sqlite3ExprCodeTarget(pParse, pAlt, target);
        _ = c.sqlite3VdbeAddOp3(v, op.And, r1, r1, target);
        return target;
    }
    const skipOp: c_int = if (o == TK_AND) op.IfNot else op.If;
    var r1: c_int = undefined;
    var r2: c_int = undefined;
    var regSS: c_int = 0;
    var addrSkip: c_int = undefined;
    if (exprEvalRhsFirst(pExpr)) {
        r2 = sqlite3ExprCodeTarget(pParse, exprPRight(pExpr), target);
        regSS = r2;
        addrSkip = c.sqlite3VdbeAddOp1(v, skipOp, r2);
        r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), pTmpReg);
    } else {
        r1 = sqlite3ExprCodeTarget(pParse, exprPLeft(pExpr), target);
        if (hasProp(exprPRight(pExpr), EP_Subquery)) {
            regSS = r1;
            addrSkip = c.sqlite3VdbeAddOp1(v, skipOp, r1);
        } else {
            addrSkip = 0;
            regSS = 0;
        }
        r2 = sqlite3ExprCodeTemp(pParse, exprPRight(pExpr), pTmpReg);
    }
    _ = c.sqlite3VdbeAddOp3(v, o, r2, r1, target);
    if (addrSkip != 0) {
        _ = c.sqlite3VdbeAddOp2(v, op.Goto, 0, c.sqlite3VdbeCurrentAddr(v) + 2);
        c.sqlite3VdbeJumpHere(v, addrSkip);
        _ = c.sqlite3VdbeAddOp3(v, op.Or, regSS, regSS, target);
    }
    return target;
}

inline fn aggColAt(pAggInfo: Ptr, i: c_int) Ptr {
    const a = rdp(pAggInfo, AggInfo_aCol);
    return @ptrCast(base(a) + @as(usize, @intCast(i)) * sizeof_AggInfo_col);
}
inline fn aggInfoColumnReg(pAggInfo: Ptr, i: c_int) c_int {
    return rd(c_int, pAggInfo, AggInfo_iFirstReg) + i;
}
inline fn aggInfoFuncReg(pAggInfo: Ptr, i: c_int) c_int {
    return rd(c_int, pAggInfo, AggInfo_iFirstReg) + rd(c_int, pAggInfo, AggInfo_nColumn) + i;
}

export fn sqlite3ExprCodeTarget(pParse: Ptr, pExpr0: Ptr, target: c_int) c_int {
    var pExpr = pExpr0;
    const v = parseVdbe(pParse);
    var o: c_int = undefined;
    var inReg = target;
    var regFree1: c_int = 0;
    var regFree2: c_int = 0;
    var r1: c_int = undefined;
    var r2: c_int = undefined;
    var p5: c_int = 0;

    expr_code_doover: while (true) {
        if (pExpr == null) {
            o = TK_NULL;
        } else if (rdp(pParse, Parse_pIdxEpr) != null and !hasProp(pExpr, EP_Leaf)) {
            r1 = sqlite3IndexedExprLookup(pParse, pExpr, target);
            if (r1 >= 0) return r1;
            o = exprOp(pExpr);
        } else {
            o = exprOp(pExpr);
        }
        switch (o) {
            TK_AGG_COLUMN => {
                const pAggInfo = exprPAggInfo(pExpr);
                if (exprIAgg(pExpr) >= rd(c_int, pAggInfo, AggInfo_nColumn)) {
                    _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, target);
                    break;
                }
                const pCol = aggColAt(pAggInfo, exprIAgg(pExpr));
                if (rd(u8, pAggInfo, AggInfo_directMode) == 0) {
                    return aggInfoColumnReg(pAggInfo, exprIAgg(pExpr));
                } else if (rd(u8, pAggInfo, AggInfo_useSortingIdx) != 0) {
                    const pTab = rdp(pCol, AggInfo_col_pTab);
                    _ = c.sqlite3VdbeAddOp3(v, op.Column, rd(c_int, pAggInfo, AggInfo_sortingIdxPTab), rd(c_int, pCol, AggInfo_col_iSorterColumn), target);
                    if (pTab != null and rd(c_int, pCol, AggInfo_col_iColumn) >= 0) {
                        if (colAffinity(rdpCol(pTab, rd(c_int, pCol, AggInfo_col_iColumn))) == SQLITE_AFF_REAL) {
                            _ = c.sqlite3VdbeAddOp1(v, op.RealAffinity, target);
                        }
                    }
                    return target;
                } else if (exprYTab(pExpr) == null) {
                    _ = c.sqlite3VdbeAddOp3(v, op.Column, exprITable(pExpr), exprIColumn(pExpr), target);
                    return target;
                }
                // fall through to TK_COLUMN
                inReg = codeColumn(pParse, pExpr, target, v, &r1);
                return inReg;
            },
            TK_COLUMN => {
                inReg = codeColumn(pParse, pExpr, target, v, &r1);
                return inReg;
            },
            TK_INTEGER => {
                codeInteger(pParse, pExpr, 0, target);
                return target;
            },
            TK_TRUEFALSE => {
                _ = c.sqlite3VdbeAddOp2(v, op.Integer, sqlite3ExprTruthValue(pExpr), target);
                return target;
            },
            TK_FLOAT => {
                codeReal(v, exprUToken(pExpr), 0, target);
                return target;
            },
            TK_STRING => {
                c.sqlite3VdbeLoadString(v, target, exprUToken(pExpr));
                return target;
            },
            TK_NULLS => {
                _ = c.sqlite3VdbeAddOp3(v, op.Null, 0, target, target + exprYNReg(pExpr) - 1);
                return target;
            },
            TK_BLOB => {
                const z = exprUToken(pExpr).? + 2;
                const n = c.sqlite3Strlen30(z) - 1;
                const zBlob = c.sqlite3HexToBlob(c.sqlite3VdbeDb(v), z, n);
                _ = c.sqlite3VdbeAddOp4(v, op.Blob, @divTrunc(n, 2), target, 0, @ptrCast(zBlob), P4_DYNAMIC);
                return target;
            },
            TK_VARIABLE => {
                _ = c.sqlite3VdbeAddOp2(v, op.Variable, exprIColumn(pExpr), target);
                return target;
            },
            TK_REGISTER => {
                return exprITable(pExpr);
            },
            TK_CAST => {
                sqlite3ExprCode(pParse, exprPLeft(pExpr), target);
                _ = c.sqlite3VdbeAddOp2(v, op.Cast, target, c.sqlite3AffinityType(exprUToken(pExpr), null));
                return inReg;
            },
            TK_IS, TK_ISNOT, TK_LT, TK_LE, TK_GT, TK_GE, TK_NE, TK_EQ => {
                if (o == TK_IS) {
                    o = TK_EQ;
                    p5 = SQLITE_NULLEQ;
                } else if (o == TK_ISNOT) {
                    o = TK_NE;
                    p5 = SQLITE_NULLEQ;
                }
                const pLeft = exprPLeft(pExpr);
                var addrIsNull: c_int = 0;
                if (sqlite3ExprIsVector(pLeft) != 0) {
                    codeVectorCompare(pParse, pExpr, target, @intCast(o), @intCast(p5));
                } else {
                    if (hasProp(pExpr, EP_Subquery) and p5 != SQLITE_NULLEQ) {
                        addrIsNull = exprComputeOperands(pParse, pExpr, &r1, &r2, &regFree1, &regFree2);
                    } else {
                        r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                        r2 = sqlite3ExprCodeTemp(pParse, exprPRight(pExpr), &regFree2);
                    }
                    _ = c.sqlite3VdbeAddOp2(v, op.Integer, 1, inReg);
                    _ = codeCompare(pParse, pLeft, exprPRight(pExpr), o, r1, r2, c.sqlite3VdbeCurrentAddr(v) + 2, p5, @intFromBool(hasProp(pExpr, EP_Commuted)));
                    if (p5 == SQLITE_NULLEQ) {
                        _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, inReg);
                    } else {
                        _ = c.sqlite3VdbeAddOp3(v, op.ZeroOrNull, r1, inReg, r2);
                        if (addrIsNull != 0) {
                            _ = c.sqlite3VdbeAddOp2(v, op.Goto, 0, c.sqlite3VdbeCurrentAddr(v) + 2);
                            c.sqlite3VdbeJumpHere(v, addrIsNull);
                            _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, inReg);
                        }
                    }
                }
                break;
            },
            TK_AND, TK_OR => {
                inReg = exprCodeTargetAndOr(pParse, pExpr, target, &regFree1);
                break;
            },
            TK_PLUS, TK_STAR, TK_MINUS, TK_REM, TK_BITAND, TK_BITOR, TK_SLASH, TK_LSHIFT, TK_RSHIFT, TK_CONCAT => {
                var addrIsNull: c_int = undefined;
                if (hasProp(pExpr, EP_Subquery)) {
                    addrIsNull = exprComputeOperands(pParse, pExpr, &r1, &r2, &regFree1, &regFree2);
                } else {
                    r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                    r2 = sqlite3ExprCodeTemp(pParse, exprPRight(pExpr), &regFree2);
                    addrIsNull = 0;
                }
                _ = c.sqlite3VdbeAddOp3(v, o, r2, r1, target);
                if (addrIsNull != 0) {
                    _ = c.sqlite3VdbeAddOp2(v, op.Goto, 0, c.sqlite3VdbeCurrentAddr(v) + 2);
                    c.sqlite3VdbeJumpHere(v, addrIsNull);
                    _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, target);
                }
                break;
            },
            TK_UMINUS => {
                const pLeft = exprPLeft(pExpr);
                if (exprOp(pLeft) == TK_INTEGER) {
                    codeInteger(pParse, pLeft, 1, target);
                    return target;
                } else if (exprOp(pLeft) == TK_FLOAT) {
                    codeReal(v, exprUToken(pLeft), 1, target);
                    return target;
                } else {
                    var tempX: [sizeof_Expr]u8 align(8) = undefined;
                    const ptx: Ptr = @ptrCast(&tempX);
                    setExprOp(ptx, TK_INTEGER);
                    setExprFlags(ptx, EP_IntValue | EP_TokenOnly);
                    wr(c_int, ptx, Expr_u, 0);
                    clearVVA(ptx);
                    r1 = sqlite3ExprCodeTemp(pParse, ptx, &regFree1);
                    r2 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree2);
                    _ = c.sqlite3VdbeAddOp3(v, op.Subtract, r2, r1, target);
                }
                break;
            },
            TK_BITNOT, TK_NOT => {
                r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                _ = c.sqlite3VdbeAddOp2(v, o, r1, inReg);
                break;
            },
            TK_TRUTH => {
                r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                const isTrue = sqlite3ExprTruthValue(exprPRight(pExpr));
                const bNormal: c_int = @intFromBool(exprOp2(pExpr) == TK_IS);
                _ = c.sqlite3VdbeAddOp4Int(v, op.IsTrue, r1, inReg, @intFromBool(isTrue == 0), isTrue ^ bNormal);
                break;
            },
            TK_ISNULL, TK_NOTNULL => {
                _ = c.sqlite3VdbeAddOp2(v, op.Integer, 1, target);
                r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                const addr = c.sqlite3VdbeAddOp1(v, o, r1);
                _ = c.sqlite3VdbeAddOp2(v, op.Integer, 0, target);
                c.sqlite3VdbeJumpHere(v, addr);
                break;
            },
            TK_AGG_FUNCTION => {
                const pInfo = exprPAggInfo(pExpr);
                if (pInfo == null or exprIAgg(pExpr) < 0 or exprIAgg(pExpr) >= rd(c_int, pInfo, AggInfo_nFunc)) {
                    c.sqlite3ErrorMsg(pParse, "misuse of aggregate: %#T()", pExpr);
                } else {
                    return aggInfoFuncReg(pInfo, exprIAgg(pExpr));
                }
                break;
            },
            TK_FUNCTION => {
                inReg = codeFunction(pParse, pExpr, target, v);
                if (inReg == FUNC_RETURNED) return target;
                if (inReg == FUNC_BROKE) break;
                return inReg;
            },
            TK_EXISTS, TK_SELECT => {
                if (dbMallocFailed(parseDb(pParse))) {
                    return 0;
                } else if (o == TK_SELECT and listNExpr(rdp(exprPSelect(pExpr), Select_pEList)) != 1) {
                    sqlite3SubselectError(pParse, listNExpr(rdp(exprPSelect(pExpr), Select_pEList)), 1);
                } else {
                    return sqlite3CodeSubselect(pParse, pExpr);
                }
                break;
            },
            TK_SELECT_COLUMN => {
                const pLeft = exprPLeft(pExpr);
                if (exprITable(pLeft) == 0 or rd(u8, pParse, Parse_withinRJSubrtn) > exprOp2(pLeft)) {
                    setExprITable(pLeft, sqlite3CodeSubselect(pParse, pLeft));
                    setExprOp2(pLeft, rd(u8, pParse, Parse_withinRJSubrtn));
                }
                const n = sqlite3ExprVectorSize(pLeft);
                if (exprITable(pExpr) != n) {
                    c.sqlite3ErrorMsg(pParse, "%d columns assigned %d values", exprITable(pExpr), n);
                }
                return exprITable(pLeft) + exprIColumn(pExpr);
            },
            TK_IN => {
                const destIfFalse = c.sqlite3VdbeMakeLabel(pParse);
                const destIfNull = c.sqlite3VdbeMakeLabel(pParse);
                _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, target);
                sqlite3ExprCodeIN(pParse, pExpr, destIfFalse, destIfNull);
                _ = c.sqlite3VdbeAddOp2(v, op.Integer, 1, target);
                c.sqlite3VdbeResolveLabel(v, destIfFalse);
                _ = c.sqlite3VdbeAddOp2(v, op.AddImm, target, 0);
                c.sqlite3VdbeResolveLabel(v, destIfNull);
                return target;
            },
            TK_BETWEEN => {
                exprCodeBetween(pParse, pExpr, target, null, 0);
                return target;
            },
            TK_COLLATE => {
                if (!hasProp(pExpr, EP_Collate)) {
                    sqlite3ExprCode(pParse, exprPLeft(pExpr), target);
                    _ = c.sqlite3VdbeAddOp1(v, op.ClrSubtype, target);
                    return target;
                } else {
                    pExpr = exprPLeft(pExpr);
                    continue :expr_code_doover;
                }
            },
            TK_SPAN, TK_UPLUS => {
                pExpr = exprPLeft(pExpr);
                continue :expr_code_doover;
            },
            TK_TRIGGER => {
                const pTab = exprYTab(pExpr);
                const iCol = exprIColumn(pExpr);
                const p1 = exprITable(pExpr) * (rd(i16, pTab, Table_nCol) + 1) + 1 + @as(c_int, c.sqlite3TableColumnToStorage(pTab, @intCast(iCol)));
                _ = c.sqlite3VdbeAddOp2(v, op.Param, p1, target);
                if (iCol >= 0 and colAffinity(rdpCol(pTab, iCol)) == SQLITE_AFF_REAL) {
                    _ = c.sqlite3VdbeAddOp1(v, op.RealAffinity, target);
                }
                break;
            },
            TK_VECTOR => {
                errMsg0(pParse, "row value misused");
                break;
            },
            TK_IF_NULL_ROW => {
                const savedOk = okConstFactor(pParse);
                const pAggInfo = exprPAggInfo(pExpr);
                if (pAggInfo != null) {
                    if (rd(u8, pAggInfo, AggInfo_directMode) == 0) {
                        inReg = aggInfoColumnReg(pAggInfo, exprIAgg(pExpr));
                        break;
                    }
                    if (rd(u8, pAggInfo, AggInfo_useSortingIdx) != 0) {
                        _ = c.sqlite3VdbeAddOp3(v, op.Column, rd(c_int, pAggInfo, AggInfo_sortingIdxPTab), rd(c_int, aggColAt(pAggInfo, exprIAgg(pExpr)), AggInfo_col_iSorterColumn), target);
                        inReg = target;
                        break;
                    }
                }
                const addrINR = c.sqlite3VdbeAddOp3(v, op.IfNullRow, exprITable(pExpr), 0, target);
                setOkConstFactor(pParse, false);
                sqlite3ExprCode(pParse, exprPLeft(pExpr), target);
                setOkConstFactor(pParse, savedOk);
                c.sqlite3VdbeJumpHere(v, addrINR);
                break;
            },
            TK_CASE => {
                codeCase(pParse, pExpr, target, v, &regFree1);
                break;
            },
            TK_RAISE => {
                if (rdp(pParse, Parse_pTriggerTab) == null and rd(c_int, pParse, Parse_nested) == 0) {
                    errMsg0(pParse, "RAISE() may only be used within a trigger-program");
                    return 0;
                }
                if (exprAffExpr(pExpr) == OE_Abort) {
                    c.sqlite3MayAbort(pParse);
                }
                if (exprAffExpr(pExpr) == OE_Ignore) {
                    _ = c.sqlite3VdbeAddOp2(v, op.Halt, SQLITE_OK, OE_Ignore);
                } else {
                    r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                    _ = c.sqlite3VdbeAddOp3(v, op.Halt, if (rdp(pParse, Parse_pTriggerTab) != null) @as(c_int, 0x113) else SQLITE_ERROR, exprAffExpr(pExpr), r1);
                }
                break;
            },
            else => {
                _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, target);
                return target;
            },
        }
        break;
    }
    sqlite3ReleaseTempReg(pParse, regFree1);
    sqlite3ReleaseTempReg(pParse, regFree2);
    return inReg;
}

inline fn exprYNReg(p: Ptr) c_int {
    return rd(c_int, p, Expr_y);
}

// the TK_COLUMN body (shared by TK_AGG_COLUMN fall-through)
fn codeColumn(pParse: Ptr, pExpr: Ptr, target: c_int, v: Ptr, pr1: *c_int) c_int {
    var iTab = exprITable(pExpr);
    if (hasProp(pExpr, EP_FixedCol)) {
        const iReg = sqlite3ExprCodeTarget(pParse, exprPLeft(pExpr), target);
        const aff = sqlite3TableColumnAffinity(exprYTab(pExpr), exprIColumn(pExpr));
        if (aff > SQLITE_AFF_BLOB) {
            const zAff = "B\x00C\x00D\x00E\x00F";
            _ = c.sqlite3VdbeAddOp4(v, op.Affinity, iReg, 1, 0, @ptrCast(@as([*]const u8, zAff) + @as(usize, @intCast(aff - 'B')) * 2), P4_STATIC);
        }
        return iReg;
    }
    if (iTab < 0) {
        if (parseISelfTab(pParse) < 0) {
            const iCol = exprIColumn(pExpr);
            const pTab = exprYTab(pExpr);
            if (iCol < 0) {
                return -1 - parseISelfTab(pParse);
            }
            const pCol = rdpCol(pTab, iCol);
            const iSrc = @as(c_int, c.sqlite3TableColumnToStorage(pTab, @intCast(iCol))) - parseISelfTab(pParse);
            if ((colFlags(pCol) & COLFLAG_GENERATED) != 0) {
                if ((colFlags(pCol) & COLFLAG_BUSY) != 0) {
                    c.sqlite3ErrorMsg(pParse, "generated column loop on \"%s\"", colCnName(pCol));
                    return 0;
                }
                setColFlags(pCol, colFlags(pCol) | COLFLAG_BUSY);
                if ((colFlags(pCol) & COLFLAG_NOTAVAIL) != 0) {
                    sqlite3ExprCodeGeneratedColumn(pParse, pTab, pCol, iSrc);
                }
                setColFlags(pCol, colFlags(pCol) & ~(COLFLAG_BUSY | COLFLAG_NOTAVAIL));
                return iSrc;
            } else if (colAffinity(pCol) == SQLITE_AFF_REAL) {
                _ = c.sqlite3VdbeAddOp2(v, op.SCopy, iSrc, target);
                _ = c.sqlite3VdbeAddOp1(v, op.RealAffinity, target);
                return target;
            } else {
                return iSrc;
            }
        } else {
            iTab = parseISelfTab(pParse) - 1;
        }
    } else if (rdp(pParse, Parse_pIdxPartExpr) != null) {
        pr1.* = exprPartidxExprLookup(pParse, pExpr, target);
        if (pr1.* != 0) return pr1.*;
    }
    return sqlite3ExprCodeGetColumn(pParse, exprYTab(pExpr), exprIColumn(pExpr), iTab, target, @intCast(exprOp2(pExpr)));
}

const FUNC_RETURNED: c_int = -2147483647;
const FUNC_BROKE: c_int = -2147483646;
fn codeFunction(pParse: Ptr, pExpr: Ptr, target: c_int, v: Ptr) c_int {
    var constMask: u32 = 0;
    const db = parseDb(pParse);
    const enc = dbEnc(db);
    var pColl: Ptr = null;

    if (hasProp(pExpr, EP_WinFunc)) {
        return rd(c_int, exprYWin(pExpr), off("Window_regResult", 0));
    }

    if (okConstFactor(pParse) and sqlite3ExprIsConstantNotJoin(pParse, pExpr) != 0) {
        // Constant function: cache the value once in a fresh register and return
        // THAT register (matches C). Returning `target` would leave it unwritten.
        return sqlite3ExprCodeRunJustOnce(pParse, pExpr, -1);
    }
    const pFarg = exprPList(pExpr);
    const nFarg: c_int = if (pFarg != null) listNExpr(pFarg) else 0;
    const zId = exprUToken(pExpr);
    var pDef = c.sqlite3FindFunction(db, zId, nFarg, enc, 0);
    if (pDef == null or rdp(pDef, FuncDef_xFinalize) != null or ((rd(u32, pDef, FuncDef_funcFlags) & SQLITE_FUNC_INTERNAL) != 0 and rd(c_int, pParse, Parse_nested) == 0 and (rd(u32, db, sqlite3_mDbFlags) & DBFLAG_InternalFunc) == 0)) {
        c.sqlite3ErrorMsg(pParse, "unknown function: %#T()", pExpr);
        return FUNC_BROKE;
    }
    if ((rd(u32, pDef, FuncDef_funcFlags) & SQLITE_FUNC_INLINE) != 0 and pFarg != null) {
        return exprCodeInlineFunction(pParse, pFarg, @intCast(@intFromPtr(rdp(pDef, FuncDef_pUserData))), target);
    } else if ((rd(u32, pDef, FuncDef_funcFlags) & (SQLITE_FUNC_DIRECT | SQLITE_FUNC_UNSAFE)) != 0) {
        sqlite3ExprFunctionUsable(pParse, pExpr, pDef);
    }

    var r1: c_int = 0;
    var i: c_int = 0;
    while (i < nFarg) : (i += 1) {
        if (i < 32 and sqlite3ExprIsConstant(pParse, itemExpr(listA(pFarg), i)) != 0) {
            constMask |= (@as(u32, 1) << @intCast(i));
        }
        if ((rd(u32, pDef, FuncDef_funcFlags) & SQLITE_FUNC_NEEDCOLL) != 0 and pColl == null) {
            pColl = sqlite3ExprCollSeq(pParse, itemExpr(listA(pFarg), i));
        }
    }
    if (pFarg != null) {
        if (constMask != 0) {
            r1 = parseNMem(pParse) + 1;
            setParseNMem(pParse, parseNMem(pParse) + nFarg);
        } else {
            r1 = sqlite3GetTempRange(pParse, nFarg);
        }
        if ((rd(u32, pDef, FuncDef_funcFlags) & (SQLITE_FUNC_LENGTH | SQLITE_FUNC_TYPEOF)) != 0) {
            const a0 = listA(pFarg);
            const exprOpc = exprOp(itemExpr(a0, 0));
            if (exprOpc == TK_COLUMN or exprOpc == TK_AGG_COLUMN) {
                setExprOp2(itemExpr(a0, 0), @intCast(rd(u32, pDef, FuncDef_funcFlags) & OPFLAG_BYTELENARG));
            }
        }
        _ = sqlite3ExprCodeExprList(pParse, pFarg, r1, 0, SQLITE_ECEL_FACTOR);
    } else {
        r1 = 0;
    }
    if (nFarg >= 2 and hasProp(pExpr, EP_InfixFunc)) {
        pDef = c.sqlite3VtabOverloadFunction(db, pDef, nFarg, itemExpr(listA(pFarg), 1));
    } else if (nFarg > 0) {
        pDef = c.sqlite3VtabOverloadFunction(db, pDef, nFarg, itemExpr(listA(pFarg), 0));
    }
    if ((rd(u32, pDef, FuncDef_funcFlags) & SQLITE_FUNC_NEEDCOLL) != 0) {
        if (pColl == null) pColl = rdp(db, sqlite3_pDfltColl);
        _ = c.sqlite3VdbeAddOp4(v, op.CollSeq, 0, 0, 0, @ptrCast(pColl), P4_COLLSEQ);
    }
    _ = c.sqlite3VdbeAddFunctionCall(pParse, @bitCast(constMask), r1, target, nFarg, pDef, exprOp2(pExpr));
    if (nFarg != 0) {
        if (constMask == 0) {
            sqlite3ReleaseTempRange(pParse, r1, nFarg);
        } else {
            c.sqlite3VdbeReleaseRegisters(pParse, r1, nFarg, constMask, 1);
        }
    }
    return target;
}

fn codeCase(pParse: Ptr, pExpr: Ptr, target: c_int, v: Ptr, pRegFree1: *c_int) void {
    const db = parseDb(pParse);
    const pEList = exprPList(pExpr);
    const aListelem = listA(pEList);
    const nExpr = listNExpr(pEList);
    const endLabel = c.sqlite3VdbeMakeLabel(pParse);
    const pX = exprPLeft(pExpr);
    var pDel: Ptr = null;
    var opCompare: [sizeof_Expr]u8 align(8) = undefined;
    const pCmp: Ptr = @ptrCast(&opCompare);
    var pTest: Ptr = null;
    if (pX != null) {
        pDel = sqlite3ExprDup(db, pX, 0);
        if (dbMallocFailed(db)) {
            sqlite3ExprDelete(db, pDel);
            return;
        }
        sqlite3ExprToRegister(pDel, exprCodeVector(pParse, pDel, pRegFree1));
        _ = c.memset(pCmp, 0, sizeof_Expr);
        setExprOp(pCmp, TK_EQ);
        wr(?*anyopaque, pCmp, Expr_pLeft, pDel);
        pTest = pCmp;
        pRegFree1.* = 0;
    }
    var i: c_int = 0;
    while (i < nExpr - 1) : (i += 2) {
        if (pX != null) {
            wr(?*anyopaque, pCmp, Expr_pRight, itemExpr(aListelem, i));
        } else {
            pTest = itemExpr(aListelem, i);
        }
        const nextCase = c.sqlite3VdbeMakeLabel(pParse);
        sqlite3ExprIfFalse(pParse, pTest, nextCase, SQLITE_JUMPIFNULL);
        sqlite3ExprCode(pParse, itemExpr(aListelem, i + 1), target);
        c.sqlite3VdbeGoto(v, endLabel);
        c.sqlite3VdbeResolveLabel(v, nextCase);
    }
    if ((nExpr & 1) != 0) {
        sqlite3ExprCode(pParse, itemExpr(aListelem, nExpr - 1), target);
    } else {
        _ = c.sqlite3VdbeAddOp2(v, op.Null, 0, target);
    }
    sqlite3ExprDelete(db, pDel);
    setDoNotMergeFlagOnCopy(v);
    c.sqlite3VdbeResolveLabel(v, endLabel);
}

// ════════════════════════════════════════════════════════════════════════════
// Section 7: factoring, ExprCode*, IfTrue/IfFalse, Compare, Implies, AggInfo
// ════════════════════════════════════════════════════════════════════════════

export fn sqlite3ExprCodeRunJustOnce(pParse: Ptr, pExpr0: Ptr, regDest0: c_int) c_int {
    var regDest = regDest0;
    var pExpr = pExpr0;
    var p = rdp(pParse, Parse_pConstExpr);
    if (regDest < 0 and p != null) {
        const a0 = listA(p);
        var i = listNExpr(p);
        var k: c_int = 0;
        while (i > 0) : (i -= 1) {
            const pItem = itemAt(a0, k);
            k += 1;
            if ((itemFg(pItem) & FGI_reusable) != 0 and sqlite3ExprCompare(null, rdp(pItem, ExprList_item_pExpr), pExpr, -1) == 0) {
                return rd(c_int, pItem, ExprList_item_u_iConstExprReg);
            }
        }
    }
    pExpr = sqlite3ExprDup(parseDb(pParse), pExpr, 0);
    if (pExpr != null and hasProp(pExpr, EP_HasFunc)) {
        const v = parseVdbe(pParse);
        const addr = c.sqlite3VdbeAddOp0(v, op.Once);
        setOkConstFactor(pParse, false);
        if (!dbMallocFailed(parseDb(pParse))) {
            if (regDest < 0) regDest = incParseNMem(pParse);
            sqlite3ExprCode(pParse, pExpr, regDest);
        }
        setOkConstFactor(pParse, true);
        sqlite3ExprDelete(parseDb(pParse), pExpr);
        c.sqlite3VdbeJumpHere(v, addr);
    } else {
        p = sqlite3ExprListAppend(pParse, p, pExpr);
        if (p != null) {
            const pItem = itemAt(listA(p), listNExpr(p) - 1);
            // fg.reusable = regDest<0
            if (regDest < 0) {
                setItemFg(pItem, itemFg(pItem) | FGI_reusable);
            } else {
                setItemFg(pItem, itemFg(pItem) & ~FGI_reusable);
            }
            if (regDest < 0) regDest = incParseNMem(pParse);
            wr(c_int, pItem, ExprList_item_u_iConstExprReg, regDest);
        }
        wr(?*anyopaque, pParse, Parse_pConstExpr, p);
    }
    return regDest;
}

export fn sqlite3ExprNullRegisterRange(pParse: Ptr, iReg: c_int, nReg: c_int) void {
    const savedOk = okConstFactor(pParse);
    var t: [sizeof_Expr]u8 align(8) = undefined;
    const pt: Ptr = @ptrCast(&t);
    _ = c.memset(pt, 0, sizeof_Expr);
    setExprOp(pt, TK_NULLS);
    wr(c_int, pt, Expr_y, nReg); // y.nReg
    setOkConstFactor(pParse, true);
    _ = sqlite3ExprCodeRunJustOnce(pParse, pt, iReg);
    setOkConstFactor(pParse, savedOk);
}

export fn sqlite3ExprCodeTemp(pParse: Ptr, pExpr0: Ptr, pReg: *c_int) c_int {
    var r2: c_int = undefined;
    const pExpr = sqlite3ExprSkipCollateAndLikely(pExpr0);
    if (okConstFactor(pParse) and pExpr != null and exprOp(pExpr) != TK_REGISTER and sqlite3ExprIsConstantNotJoin(pParse, pExpr) != 0) {
        pReg.* = 0;
        r2 = sqlite3ExprCodeRunJustOnce(pParse, pExpr, -1);
    } else {
        const r1 = sqlite3GetTempReg(pParse);
        r2 = sqlite3ExprCodeTarget(pParse, pExpr, r1);
        if (r2 == r1) {
            pReg.* = r1;
        } else {
            sqlite3ReleaseTempReg(pParse, r1);
            pReg.* = 0;
        }
    }
    return r2;
}

export fn sqlite3ExprCode(pParse: Ptr, pExpr: Ptr, target: c_int) void {
    if (parseVdbe(pParse) == null) return;
    const inReg = sqlite3ExprCodeTarget(pParse, pExpr, target);
    if (inReg != target) {
        var o: c_int = undefined;
        const pX = sqlite3ExprSkipCollateAndLikely(pExpr);
        if (pX != null and (hasProp(pX, EP_Subquery) or exprOp(pX) == TK_REGISTER)) {
            o = op.Copy;
        } else {
            o = op.SCopy;
        }
        _ = c.sqlite3VdbeAddOp2(parseVdbe(pParse), o, inReg, target);
    }
}

export fn sqlite3ExprCodeCopy(pParse: Ptr, pExpr0: Ptr, target: c_int) void {
    const db = parseDb(pParse);
    const pExpr = sqlite3ExprDup(db, pExpr0, 0);
    if (!dbMallocFailed(db)) sqlite3ExprCode(pParse, pExpr, target);
    sqlite3ExprDelete(db, pExpr);
}

export fn sqlite3ExprCodeFactorable(pParse: Ptr, pExpr: Ptr, target: c_int) void {
    if (okConstFactor(pParse) and sqlite3ExprIsConstantNotJoin(pParse, pExpr) != 0) {
        _ = sqlite3ExprCodeRunJustOnce(pParse, pExpr, target);
    } else {
        sqlite3ExprCodeCopy(pParse, pExpr, target);
    }
}

export fn sqlite3ExprCodeExprList(pParse: Ptr, pList: Ptr, target: c_int, srcReg: c_int, flags0: u8) c_int {
    var flags = flags0;
    const copyOp: c_int = if ((flags & SQLITE_ECEL_DUP) != 0) op.Copy else op.SCopy;
    const v = parseVdbe(pParse);
    var n = listNExpr(pList);
    const a0 = listA(pList);
    if (!okConstFactor(pParse)) flags &= ~SQLITE_ECEL_FACTOR;
    // C iterates `pItem` over the list while `i` (the target register slot) can
    // be held back by the OMITREF path to reuse a slot — they are NOT the same
    // counter. `m` is the item index (always advances); `i` is the slot.
    var i: c_int = 0;
    var m: c_int = 0;
    while (i < n) : ({
        i += 1;
        m += 1;
    }) {
        const pItem = itemAt(a0, m);
        const pExpr = rdp(pItem, ExprList_item_pExpr);
        const j = rd(u16, pItem, ExprList_item_u_x_iOrderByCol);
        if ((flags & SQLITE_ECEL_REF) != 0 and j > 0) {
            if ((flags & SQLITE_ECEL_OMITREF) != 0) {
                i -= 1;
                n -= 1;
            } else {
                _ = c.sqlite3VdbeAddOp2(v, copyOp, @as(c_int, j) + srcReg - 1, target + i);
            }
        } else if ((flags & SQLITE_ECEL_FACTOR) != 0 and sqlite3ExprIsConstantNotJoin(pParse, pExpr) != 0) {
            _ = sqlite3ExprCodeRunJustOnce(pParse, pExpr, target + i);
        } else {
            const inReg = sqlite3ExprCodeTarget(pParse, pExpr, target + i);
            if (inReg != target + i) {
                const pOp = c.sqlite3VdbeGetLastOp(v);
                if (copyOp == op.Copy and rd(u8, pOp, VdbeOp_opcode) == op.Copy and rd(c_int, pOp, VdbeOp_p1) + rd(c_int, pOp, VdbeOp_p3) + 1 == inReg and rd(c_int, pOp, VdbeOp_p2) + rd(c_int, pOp, VdbeOp_p3) + 1 == target + i and rd(u8, pOp, VdbeOp_p5) == 0) {
                    wr(c_int, pOp, VdbeOp_p3, rd(c_int, pOp, VdbeOp_p3) + 1);
                } else {
                    _ = c.sqlite3VdbeAddOp2(v, copyOp, inReg, target + i);
                }
            }
        }
    }
    return n;
}

fn exprCodeBetween(pParse: Ptr, pExpr: Ptr, dest: c_int, xJump: ?*const fn (Ptr, Ptr, c_int, c_int) callconv(.c) void, jumpIfNull: c_int) void {
    var exprAnd: [sizeof_Expr]u8 align(8) = undefined;
    var compLeft: [sizeof_Expr]u8 align(8) = undefined;
    var compRight: [sizeof_Expr]u8 align(8) = undefined;
    var regFree1: c_int = 0;
    const db = parseDb(pParse);
    const pAnd: Ptr = @ptrCast(&exprAnd);
    const pcL: Ptr = @ptrCast(&compLeft);
    const pcR: Ptr = @ptrCast(&compRight);
    _ = c.memset(pcL, 0, sizeof_Expr);
    _ = c.memset(pcR, 0, sizeof_Expr);
    _ = c.memset(pAnd, 0, sizeof_Expr);
    const pDel = sqlite3ExprDup(db, exprPLeft(pExpr), 0);
    if (!dbMallocFailed(db)) {
        setExprOp(pAnd, TK_AND);
        wr(?*anyopaque, pAnd, Expr_pLeft, pcL);
        wr(?*anyopaque, pAnd, Expr_pRight, pcR);
        setExprOp(pcL, TK_GE);
        wr(?*anyopaque, pcL, Expr_pLeft, pDel);
        wr(?*anyopaque, pcL, Expr_pRight, itemExpr(listA(exprPList(pExpr)), 0));
        setExprOp(pcR, TK_LE);
        wr(?*anyopaque, pcR, Expr_pLeft, pDel);
        wr(?*anyopaque, pcR, Expr_pRight, itemExpr(listA(exprPList(pExpr)), 1));
        sqlite3ExprToRegister(pDel, exprCodeVector(pParse, pDel, &regFree1));
        if (xJump) |xj| {
            xj(pParse, pAnd, dest, jumpIfNull);
        } else {
            setExprFlags(pDel, exprFlags(pDel) | EP_OuterON);
            _ = sqlite3ExprCodeTarget(pParse, pAnd, dest);
        }
        sqlite3ReleaseTempReg(pParse, regFree1);
    }
    sqlite3ExprDelete(db, pDel);
}

export fn sqlite3ExprIfTrue(pParse: Ptr, pExpr: Ptr, dest: c_int, jumpIfNull0: c_int) callconv(.c) void {
    var jumpIfNull = jumpIfNull0;
    const v = parseVdbe(pParse);
    var o: c_int = 0;
    var regFree1: c_int = 0;
    var regFree2: c_int = 0;
    var r1: c_int = undefined;
    var r2: c_int = undefined;
    if (v == null) return;
    if (pExpr == null) return;
    o = exprOp(pExpr);
    blk: {
        switch (o) {
            TK_AND, TK_OR => {
                const pAlt = sqlite3ExprSimplifiedAndOr(pExpr);
                if (pAlt != pExpr) {
                    sqlite3ExprIfTrue(pParse, pAlt, dest, jumpIfNull);
                } else {
                    var pFirst: Ptr = undefined;
                    var pSecond: Ptr = undefined;
                    if (exprEvalRhsFirst(pExpr)) {
                        pFirst = exprPRight(pExpr);
                        pSecond = exprPLeft(pExpr);
                    } else {
                        pFirst = exprPLeft(pExpr);
                        pSecond = exprPRight(pExpr);
                    }
                    if (o == TK_AND) {
                        const d2 = c.sqlite3VdbeMakeLabel(pParse);
                        sqlite3ExprIfFalse(pParse, pFirst, d2, jumpIfNull ^ SQLITE_JUMPIFNULL);
                        sqlite3ExprIfTrue(pParse, pSecond, dest, jumpIfNull);
                        c.sqlite3VdbeResolveLabel(v, d2);
                    } else {
                        sqlite3ExprIfTrue(pParse, pFirst, dest, jumpIfNull);
                        sqlite3ExprIfTrue(pParse, pSecond, dest, jumpIfNull);
                    }
                }
            },
            TK_NOT => {
                sqlite3ExprIfFalse(pParse, exprPLeft(pExpr), dest, jumpIfNull);
            },
            TK_TRUTH => {
                const isNot: c_int = @intFromBool(exprOp2(pExpr) == TK_ISNOT);
                const isTrue = sqlite3ExprTruthValue(exprPRight(pExpr));
                if ((isTrue ^ isNot) != 0) {
                    sqlite3ExprIfTrue(pParse, exprPLeft(pExpr), dest, if (isNot != 0) SQLITE_JUMPIFNULL else 0);
                } else {
                    sqlite3ExprIfFalse(pParse, exprPLeft(pExpr), dest, if (isNot != 0) SQLITE_JUMPIFNULL else 0);
                }
            },
            TK_IS, TK_ISNOT, TK_LT, TK_LE, TK_GT, TK_GE, TK_NE, TK_EQ => {
                if (o == TK_IS) {
                    o = TK_EQ;
                    jumpIfNull = SQLITE_NULLEQ;
                } else if (o == TK_ISNOT) {
                    o = TK_NE;
                    jumpIfNull = SQLITE_NULLEQ;
                }
                var addrIsNull: c_int = 0;
                if (sqlite3ExprIsVector(exprPLeft(pExpr)) != 0) {
                    ifTrueDefault(pParse, pExpr, dest, jumpIfNull, v, &regFree1);
                    break :blk;
                }
                if (hasProp(pExpr, EP_Subquery) and jumpIfNull != SQLITE_NULLEQ) {
                    addrIsNull = exprComputeOperands(pParse, pExpr, &r1, &r2, &regFree1, &regFree2);
                } else {
                    r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                    r2 = sqlite3ExprCodeTemp(pParse, exprPRight(pExpr), &regFree2);
                    addrIsNull = 0;
                }
                _ = codeCompare(pParse, exprPLeft(pExpr), exprPRight(pExpr), o, r1, r2, dest, jumpIfNull, @intFromBool(hasProp(pExpr, EP_Commuted)));
                if (addrIsNull != 0) {
                    if (jumpIfNull != 0) {
                        c.sqlite3VdbeChangeP2(v, addrIsNull, dest);
                    } else {
                        c.sqlite3VdbeJumpHere(v, addrIsNull);
                    }
                }
            },
            TK_ISNULL, TK_NOTNULL => {
                r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                if (regFree1 != 0) c.sqlite3VdbeTypeofColumn(v, r1);
                _ = c.sqlite3VdbeAddOp2(v, o, r1, dest);
            },
            TK_BETWEEN => {
                exprCodeBetween(pParse, pExpr, dest, sqlite3ExprIfTrue, jumpIfNull);
            },
            TK_IN => {
                const destIfFalse = c.sqlite3VdbeMakeLabel(pParse);
                const destIfNull: c_int = if (jumpIfNull != 0) dest else destIfFalse;
                sqlite3ExprCodeIN(pParse, pExpr, destIfFalse, destIfNull);
                c.sqlite3VdbeGoto(v, dest);
                c.sqlite3VdbeResolveLabel(v, destIfFalse);
            },
            else => {
                ifTrueDefault(pParse, pExpr, dest, jumpIfNull, v, &regFree1);
            },
        }
    }
    sqlite3ReleaseTempReg(pParse, regFree1);
    sqlite3ReleaseTempReg(pParse, regFree2);
}
fn ifTrueDefault(pParse: Ptr, pExpr: Ptr, dest: c_int, jumpIfNull: c_int, v: Ptr, pRegFree1: *c_int) void {
    if (alwaysTrue(pExpr)) {
        c.sqlite3VdbeGoto(v, dest);
    } else if (alwaysFalse(pExpr)) {
        // no-op
    } else {
        const r1 = sqlite3ExprCodeTemp(pParse, pExpr, pRegFree1);
        _ = c.sqlite3VdbeAddOp3(v, op.If, r1, dest, @intFromBool(jumpIfNull != 0));
    }
}

export fn sqlite3ExprIfFalse(pParse: Ptr, pExpr: Ptr, dest: c_int, jumpIfNull0: c_int) callconv(.c) void {
    var jumpIfNull = jumpIfNull0;
    const v = parseVdbe(pParse);
    var regFree1: c_int = 0;
    var regFree2: c_int = 0;
    var r1: c_int = undefined;
    var r2: c_int = undefined;
    if (v == null) return;
    if (pExpr == null) return;
    var o: c_int = ((exprOp(pExpr) + (TK_ISNULL & 1)) ^ 1) - (TK_ISNULL & 1);
    blk: {
        switch (exprOp(pExpr)) {
            TK_AND, TK_OR => {
                const pAlt = sqlite3ExprSimplifiedAndOr(pExpr);
                if (pAlt != pExpr) {
                    sqlite3ExprIfFalse(pParse, pAlt, dest, jumpIfNull);
                } else {
                    var pFirst: Ptr = undefined;
                    var pSecond: Ptr = undefined;
                    if (exprEvalRhsFirst(pExpr)) {
                        pFirst = exprPRight(pExpr);
                        pSecond = exprPLeft(pExpr);
                    } else {
                        pFirst = exprPLeft(pExpr);
                        pSecond = exprPRight(pExpr);
                    }
                    if (exprOp(pExpr) == TK_AND) {
                        sqlite3ExprIfFalse(pParse, pFirst, dest, jumpIfNull);
                        sqlite3ExprIfFalse(pParse, pSecond, dest, jumpIfNull);
                    } else {
                        const d2 = c.sqlite3VdbeMakeLabel(pParse);
                        sqlite3ExprIfTrue(pParse, pFirst, d2, jumpIfNull ^ SQLITE_JUMPIFNULL);
                        sqlite3ExprIfFalse(pParse, pSecond, dest, jumpIfNull);
                        c.sqlite3VdbeResolveLabel(v, d2);
                    }
                }
            },
            TK_NOT => {
                sqlite3ExprIfTrue(pParse, exprPLeft(pExpr), dest, jumpIfNull);
            },
            TK_TRUTH => {
                const isNot: c_int = @intFromBool(exprOp2(pExpr) == TK_ISNOT);
                const isTrue = sqlite3ExprTruthValue(exprPRight(pExpr));
                if ((isTrue ^ isNot) != 0) {
                    sqlite3ExprIfFalse(pParse, exprPLeft(pExpr), dest, if (isNot != 0) 0 else SQLITE_JUMPIFNULL);
                } else {
                    sqlite3ExprIfTrue(pParse, exprPLeft(pExpr), dest, if (isNot != 0) 0 else SQLITE_JUMPIFNULL);
                }
            },
            TK_IS, TK_ISNOT, TK_LT, TK_LE, TK_GT, TK_GE, TK_NE, TK_EQ => {
                if (exprOp(pExpr) == TK_IS) {
                    o = TK_NE;
                    jumpIfNull = SQLITE_NULLEQ;
                } else if (exprOp(pExpr) == TK_ISNOT) {
                    o = TK_EQ;
                    jumpIfNull = SQLITE_NULLEQ;
                }
                var addrIsNull: c_int = 0;
                if (sqlite3ExprIsVector(exprPLeft(pExpr)) != 0) {
                    ifFalseDefault(pParse, pExpr, dest, jumpIfNull, v, &regFree1);
                    break :blk;
                }
                if (hasProp(pExpr, EP_Subquery) and jumpIfNull != SQLITE_NULLEQ) {
                    addrIsNull = exprComputeOperands(pParse, pExpr, &r1, &r2, &regFree1, &regFree2);
                } else {
                    r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                    r2 = sqlite3ExprCodeTemp(pParse, exprPRight(pExpr), &regFree2);
                    addrIsNull = 0;
                }
                _ = codeCompare(pParse, exprPLeft(pExpr), exprPRight(pExpr), o, r1, r2, dest, jumpIfNull, @intFromBool(hasProp(pExpr, EP_Commuted)));
                if (addrIsNull != 0) {
                    if (jumpIfNull != 0) {
                        c.sqlite3VdbeChangeP2(v, addrIsNull, dest);
                    } else {
                        c.sqlite3VdbeJumpHere(v, addrIsNull);
                    }
                }
            },
            TK_ISNULL, TK_NOTNULL => {
                r1 = sqlite3ExprCodeTemp(pParse, exprPLeft(pExpr), &regFree1);
                if (regFree1 != 0) c.sqlite3VdbeTypeofColumn(v, r1);
                _ = c.sqlite3VdbeAddOp2(v, o, r1, dest);
            },
            TK_BETWEEN => {
                exprCodeBetween(pParse, pExpr, dest, sqlite3ExprIfFalse, jumpIfNull);
            },
            TK_IN => {
                if (jumpIfNull != 0) {
                    sqlite3ExprCodeIN(pParse, pExpr, dest, dest);
                } else {
                    const destIfNull = c.sqlite3VdbeMakeLabel(pParse);
                    sqlite3ExprCodeIN(pParse, pExpr, dest, destIfNull);
                    c.sqlite3VdbeResolveLabel(v, destIfNull);
                }
            },
            else => {
                ifFalseDefault(pParse, pExpr, dest, jumpIfNull, v, &regFree1);
            },
        }
    }
    sqlite3ReleaseTempReg(pParse, regFree1);
    sqlite3ReleaseTempReg(pParse, regFree2);
}
fn ifFalseDefault(pParse: Ptr, pExpr: Ptr, dest: c_int, jumpIfNull: c_int, v: Ptr, pRegFree1: *c_int) void {
    if (alwaysFalse(pExpr)) {
        c.sqlite3VdbeGoto(v, dest);
    } else if (alwaysTrue(pExpr)) {
        // no-op
    } else {
        const r1 = sqlite3ExprCodeTemp(pParse, pExpr, pRegFree1);
        _ = c.sqlite3VdbeAddOp3(v, op.IfNot, r1, dest, @intFromBool(jumpIfNull != 0));
    }
}

export fn sqlite3ExprIfFalseDup(pParse: Ptr, pExpr: Ptr, dest: c_int, jumpIfNull: c_int) void {
    const db = parseDb(pParse);
    const pCopy = sqlite3ExprDup(db, pExpr, 0);
    if (!dbMallocFailed(db)) {
        sqlite3ExprIfFalse(pParse, pCopy, dest, jumpIfNull);
    }
    sqlite3ExprDelete(db, pCopy);
}

fn exprCompareVariable(pParse: Ptr, pVar: Ptr, pExpr: Ptr) c_int {
    var res: c_int = 2;
    var pR: Ptr = null;
    if (exprOp(pExpr) == TK_VARIABLE and exprIColumn(pVar) == exprIColumn(pExpr)) {
        return 0;
    }
    if ((rd(u64, parseDb(pParse), sqlite3_flags) & SQLITE_EnableQPSG) != 0) return 2;
    _ = c.sqlite3ValueFromExpr(parseDb(pParse), pExpr, SQLITE_UTF8, SQLITE_AFF_BLOB, &pR);
    if (pR != null) {
        const iVar = exprIColumn(pVar);
        c.sqlite3VdbeSetVarmask(parseVdbe(pParse), iVar);
        const pL = c.sqlite3VdbeGetBoundValue(rdp(pParse, Parse_pReprepare), iVar, SQLITE_AFF_BLOB);
        if (pL != null) {
            if (c.sqlite3_value_type(pL) == SQLITE_TEXT) {
                _ = c.sqlite3_value_text(pL);
            }
            res = if (c.sqlite3MemCompare(pL, pR, null) != 0) 2 else 0;
        }
        c.sqlite3ValueFree(pR);
        c.sqlite3ValueFree(pL);
    }
    return res;
}

export fn sqlite3ExprCompare(pParse: Ptr, pA: Ptr, pB: Ptr, iTab: c_int) c_int {
    if (pA == null or pB == null) {
        return if (pB == pA) 0 else 2;
    }
    if (pParse != null and exprOp(pA) == TK_VARIABLE) {
        return exprCompareVariable(pParse, pA, pB);
    }
    const combinedFlags = exprFlags(pA) | exprFlags(pB);
    if ((combinedFlags & EP_IntValue) != 0) {
        if ((exprFlags(pA) & exprFlags(pB) & EP_IntValue) != 0 and exprUValue(pA) == exprUValue(pB)) {
            return 0;
        }
        return 2;
    }
    if (exprOp(pA) != exprOp(pB) or exprOp(pA) == TK_RAISE) {
        if (exprOp(pA) == TK_COLLATE and sqlite3ExprCompare(pParse, exprPLeft(pA), pB, iTab) < 2) {
            return 1;
        }
        if (exprOp(pB) == TK_COLLATE and sqlite3ExprCompare(pParse, pA, exprPLeft(pB), iTab) < 2) {
            return 1;
        }
        if (exprOp(pA) == TK_AGG_COLUMN and exprOp(pB) == TK_COLUMN and exprITable(pB) < 0 and exprITable(pA) == iTab) {
            // fall through
        } else {
            return 2;
        }
    }
    if (exprUToken(pA) != null) {
        if (exprOp(pA) == TK_FUNCTION or exprOp(pA) == TK_AGG_FUNCTION) {
            if (c.sqlite3StrICmp(exprUToken(pA), exprUToken(pB)) != 0) return 2;
            if (hasProp(pA, EP_WinFunc) != hasProp(pB, EP_WinFunc)) {
                return 2;
            }
            if (hasProp(pA, EP_WinFunc)) {
                if (c.sqlite3WindowCompare(pParse, exprYWin(pA), exprYWin(pB), 1) != 0) {
                    return 2;
                }
            }
        } else if (exprOp(pA) == TK_NULL) {
            return 0;
        } else if (exprOp(pA) == TK_COLLATE) {
            if (c.sqlite3_stricmp(exprUToken(pA), exprUToken(pB)) != 0) return 2;
        } else if (exprUToken(pB) != null and exprOp(pA) != TK_COLUMN and exprOp(pA) != TK_AGG_COLUMN and c.strcmp(exprUToken(pA), exprUToken(pB)) != 0) {
            return 2;
        }
    }
    if ((exprFlags(pA) & (EP_Distinct | EP_Commuted)) != (exprFlags(pB) & (EP_Distinct | EP_Commuted))) return 2;
    if ((combinedFlags & EP_TokenOnly) == 0) {
        if ((combinedFlags & EP_xIsSelect) != 0) return 2;
        if ((combinedFlags & EP_FixedCol) == 0 and sqlite3ExprCompare(pParse, exprPLeft(pA), exprPLeft(pB), iTab) != 0) return 2;
        if (sqlite3ExprCompare(pParse, exprPRight(pA), exprPRight(pB), iTab) != 0) return 2;
        if (sqlite3ExprListCompare(exprPList(pA), exprPList(pB), iTab) != 0) return 2;
        if (exprOp(pA) != TK_STRING and exprOp(pA) != TK_TRUEFALSE and (combinedFlags & EP_Reduced) == 0) {
            if (exprIColumn(pA) != exprIColumn(pB)) return 2;
            if (exprOp2(pA) != exprOp2(pB) and exprOp(pA) == TK_TRUTH) return 2;
            if (exprOp(pA) != TK_IN and exprITable(pA) != exprITable(pB) and exprITable(pA) != iTab) {
                return 2;
            }
        }
    }
    return 0;
}

export fn sqlite3ExprListCompare(pA: Ptr, pB: Ptr, iTab: c_int) c_int {
    if (pA == null and pB == null) return 0;
    if (pA == null or pB == null) return 1;
    if (listNExpr(pA) != listNExpr(pB)) return 1;
    const n = listNExpr(pA);
    const aA = listA(pA);
    const aB = listA(pB);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const itA = itemAt(aA, i);
        const itB = itemAt(aB, i);
        if (itemSortFlags(itA) != itemSortFlags(itB)) return 1;
        const res = sqlite3ExprCompare(null, rdp(itA, ExprList_item_pExpr), rdp(itB, ExprList_item_pExpr), iTab);
        if (res != 0) return res;
    }
    return 0;
}

export fn sqlite3ExprCompareSkip(pA: Ptr, pB: Ptr, iTab: c_int) c_int {
    return sqlite3ExprCompare(null, sqlite3ExprSkipCollate(pA), sqlite3ExprSkipCollate(pB), iTab);
}

fn exprImpliesNotNull(pParse: Ptr, p: Ptr, pNN: Ptr, iTab: c_int, seenNot0: c_int) c_int {
    var seenNot = seenNot0;
    if (sqlite3ExprCompare(pParse, p, pNN, iTab) == 0) {
        return @intFromBool(exprOp(pNN) != TK_NULL);
    }
    switch (exprOp(p)) {
        TK_IN => {
            if (seenNot != 0 and hasProp(p, EP_xIsSelect)) return 0;
            return exprImpliesNotNull(pParse, exprPLeft(p), pNN, iTab, 1);
        },
        TK_BETWEEN => {
            const pList = exprPList(p);
            if (seenNot != 0) return 0;
            if (exprImpliesNotNull(pParse, itemExpr(listA(pList), 0), pNN, iTab, 1) != 0 or exprImpliesNotNull(pParse, itemExpr(listA(pList), 1), pNN, iTab, 1) != 0) {
                return 1;
            }
            return exprImpliesNotNull(pParse, exprPLeft(p), pNN, iTab, 1);
        },
        TK_EQ, TK_NE, TK_LT, TK_LE, TK_GT, TK_GE, TK_PLUS, TK_MINUS, TK_BITOR, TK_LSHIFT, TK_RSHIFT, TK_CONCAT => {
            seenNot = 1;
            if (exprImpliesNotNull(pParse, exprPRight(p), pNN, iTab, seenNot) != 0) return 1;
            return exprImpliesNotNull(pParse, exprPLeft(p), pNN, iTab, seenNot);
        },
        TK_STAR, TK_REM, TK_BITAND, TK_SLASH => {
            if (exprImpliesNotNull(pParse, exprPRight(p), pNN, iTab, seenNot) != 0) return 1;
            return exprImpliesNotNull(pParse, exprPLeft(p), pNN, iTab, seenNot);
        },
        TK_SPAN, TK_COLLATE, TK_UPLUS, TK_UMINUS => {
            return exprImpliesNotNull(pParse, exprPLeft(p), pNN, iTab, seenNot);
        },
        TK_TRUTH => {
            if (seenNot != 0) return 0;
            if (exprOp2(p) != TK_IS) return 0;
            return exprImpliesNotNull(pParse, exprPLeft(p), pNN, iTab, 1);
        },
        TK_BITNOT, TK_NOT => {
            return exprImpliesNotNull(pParse, exprPLeft(p), pNN, iTab, 1);
        },
        else => return 0,
    }
}

fn sqlite3ExprIsNotTrue(pExpr: Ptr) c_int {
    var vv: c_int = 1;
    if (exprOp(pExpr) == TK_NULL) return 1;
    if (exprOp(pExpr) == TK_TRUEFALSE and sqlite3ExprTruthValue(pExpr) == 0) return 1;
    if (sqlite3ExprIsInteger(pExpr, &vv, null) != 0 and vv == 0) return 1;
    return 0;
}

fn sqlite3ExprIsIIF(db: Ptr, pExpr: Ptr) c_int {
    if (exprOp(pExpr) == TK_FUNCTION) {
        const z = exprUToken(pExpr).?;
        if (z[0] != 'i' and z[0] != 'I') return 0;
        if (exprPList(pExpr) == null) return 0;
        const pDef = c.sqlite3FindFunction(db, z, listNExpr(exprPList(pExpr)), dbEnc(db), 0);
        if (pDef == null) return 0;
        if ((rd(u32, pDef, FuncDef_funcFlags) & SQLITE_FUNC_INLINE) == 0) return 0;
        if (@as(c_int, @intCast(@intFromPtr(rdp(pDef, FuncDef_pUserData)))) != INLINEFUNC_iif) return 0;
    } else if (exprOp(pExpr) == TK_CASE) {
        if (exprPLeft(pExpr) != null) return 0;
    } else {
        return 0;
    }
    const pList = exprPList(pExpr);
    if (listNExpr(pList) == 2) return 1;
    if (listNExpr(pList) == 3 and sqlite3ExprIsNotTrue(itemExpr(listA(pList), 2)) != 0) return 1;
    return 0;
}

export fn sqlite3ExprImpliesExpr(pParse: Ptr, pE1: Ptr, pE2: Ptr, iTab: c_int) c_int {
    if (sqlite3ExprCompare(pParse, pE1, pE2, iTab) == 0) {
        return 1;
    }
    if (exprOp(pE2) == TK_OR and (sqlite3ExprImpliesExpr(pParse, pE1, exprPLeft(pE2), iTab) != 0 or sqlite3ExprImpliesExpr(pParse, pE1, exprPRight(pE2), iTab) != 0)) {
        return 1;
    }
    if (exprOp(pE2) == TK_NOTNULL and exprImpliesNotNull(pParse, pE1, exprPLeft(pE2), iTab, 0) != 0) {
        return 1;
    }
    if (sqlite3ExprIsIIF(parseDb(pParse), pE1) != 0) {
        return sqlite3ExprImpliesExpr(pParse, itemExpr(listA(exprPList(pE1)), 0), pE2, iTab);
    }
    return 0;
}

fn bothImplyNotNullRow(pWalker: Ptr, pE1: Ptr, pE2: Ptr) void {
    if (walkerCode(pWalker) == 0) {
        _ = c.sqlite3WalkExpr(pWalker, pE1);
        if (walkerCode(pWalker) != 0) {
            walkerSetCode(pWalker, 0);
            _ = c.sqlite3WalkExpr(pWalker, pE2);
        }
    }
}

inline fn walkerMWFlags(pWalker: Ptr) u16 {
    return rd(u16, pWalker, Walker_mWFlags);
}

fn impliesNotNullRow(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (hasProp(pExpr, EP_OuterON)) return WRC_Prune;
    if (hasProp(pExpr, EP_InnerON) and walkerMWFlags(pWalker) != 0) {
        return WRC_Prune;
    }
    switch (exprOp(pExpr)) {
        TK_ISNOT, TK_ISNULL, TK_NOTNULL, TK_IS, TK_VECTOR, TK_FUNCTION, TK_TRUTH, TK_CASE => {
            return WRC_Prune;
        },
        TK_COLUMN => {
            if (walkerUInt(pWalker) == exprITable(pExpr)) {
                walkerSetCode(pWalker, 1);
                return WRC_Abort;
            }
            return WRC_Prune;
        },
        TK_OR, TK_AND => {
            bothImplyNotNullRow(pWalker, exprPLeft(pExpr), exprPRight(pExpr));
            return WRC_Prune;
        },
        TK_IN => {
            if (useXList(pExpr) and listNExpr(exprPList(pExpr)) > 0) {
                _ = c.sqlite3WalkExpr(pWalker, exprPLeft(pExpr));
            }
            return WRC_Prune;
        },
        TK_BETWEEN => {
            _ = c.sqlite3WalkExpr(pWalker, exprPLeft(pExpr));
            bothImplyNotNullRow(pWalker, itemExpr(listA(exprPList(pExpr)), 0), itemExpr(listA(exprPList(pExpr)), 1));
            return WRC_Prune;
        },
        TK_EQ, TK_NE, TK_LT, TK_LE, TK_GT, TK_GE => {
            const pLeft = exprPLeft(pExpr);
            const pRight = exprPRight(pExpr);
            if ((exprOp(pLeft) == TK_COLUMN and exprYTab(pLeft) != null and isVirtual(exprYTab(pLeft))) or (exprOp(pRight) == TK_COLUMN and exprYTab(pRight) != null and isVirtual(exprYTab(pRight)))) {
                return WRC_Prune;
            }
            return WRC_Continue;
        },
        else => return WRC_Continue,
    }
}

export fn sqlite3ExprImpliesNonNullRow(p0: Ptr, iTab: c_int, isRJ: c_int) c_int {
    var p = sqlite3ExprSkipCollateAndLikely(p0);
    if (p == null) return 0;
    if (exprOp(p) == TK_NOTNULL) {
        p = exprPLeft(p);
    } else {
        while (exprOp(p) == TK_AND) {
            if (sqlite3ExprImpliesNonNullRow(exprPLeft(p), iTab, isRJ) != 0) return 1;
            p = exprPRight(p);
        }
    }
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&impliesNotNullRow)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, null);
    wr(?*anyopaque, pw, Walker_xSelectCallback2, null);
    walkerSetCode(pw, 0);
    wr(u16, pw, Walker_mWFlags, @intFromBool(isRJ != 0));
    wr(c_int, pw, Walker_u, iTab);
    _ = c.sqlite3WalkExpr(pw, p);
    return walkerCode(pw);
}

const IdxCover_pIdx = off("IdxCover_pIdx", 0);
const IdxCover_iCur = off("IdxCover_iCur", 8);

fn exprIdxCover(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const pCov = rdp(pWalker, Walker_u);
    if (exprOp(pExpr) == TK_COLUMN and exprITable(pExpr) == rd(c_int, pCov, IdxCover_iCur) and c.sqlite3TableColumnToIndex(rdp(pCov, IdxCover_pIdx), @intCast(exprIColumn(pExpr))) < 0) {
        walkerSetCode(pWalker, 1);
        return WRC_Abort;
    }
    return WRC_Continue;
}

export fn sqlite3ExprCoveredByIndex(pExpr: Ptr, iCur: c_int, pIdx: Ptr) c_int {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    var xcov: [16]u8 align(8) = undefined;
    const pcov: Ptr = @ptrCast(&xcov);
    _ = c.memset(pw, 0, sizeof_Walker);
    wr(c_int, pcov, IdxCover_iCur, iCur);
    wr(?*anyopaque, pcov, IdxCover_pIdx, pIdx);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&exprIdxCover)));
    wr(?*anyopaque, pw, Walker_u, pcov);
    _ = c.sqlite3WalkExpr(pw, pExpr);
    return @intFromBool(walkerCode(pw) == 0);
}

// RefSrcList struct (local to expr.c): db, pRef, nExclude(i64), aiExclude(*int)
const RefSrcList = extern struct {
    db: ?*anyopaque,
    pRef: ?*anyopaque,
    nExclude: i64,
    aiExclude: ?[*]c_int,
};

fn selectRefEnter(pWalker: Ptr, pSelect: Ptr) callconv(.c) c_int {
    const p: *RefSrcList = @ptrCast(@alignCast(rdp(pWalker, Walker_u)));
    const pSrc = rdp(pSelect, Select_pSrc);
    const nSrc = rd(c_int, pSrc, SrcList_nSrc);
    if (nSrc == 0) return WRC_Continue;
    var j = p.nExclude;
    p.nExclude += nSrc;
    const piNew: ?[*]c_int = @ptrCast(@alignCast(c.sqlite3DbRealloc(p.db, @ptrCast(p.aiExclude), @intCast(p.nExclude * 4))));
    if (piNew == null) {
        p.nExclude = 0;
        return WRC_Abort;
    } else {
        p.aiExclude = piNew;
    }
    var i: c_int = 0;
    while (i < nSrc) : (i += 1) {
        p.aiExclude.?[@intCast(j)] = rd(c_int, srcItemAt(pSrc, i), SrcItem_iCursor);
        j += 1;
    }
    return WRC_Continue;
}
fn selectRefLeave(pWalker: Ptr, pSelect: Ptr) callconv(.c) void {
    const p: *RefSrcList = @ptrCast(@alignCast(rdp(pWalker, Walker_u)));
    const pSrc = rdp(pSelect, Select_pSrc);
    if (p.nExclude != 0) {
        p.nExclude -= rd(c_int, pSrc, SrcList_nSrc);
    }
}
fn exprRefToSrcList(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_COLUMN or exprOp(pExpr) == TK_AGG_COLUMN) {
        const p: *RefSrcList = @ptrCast(@alignCast(rdp(pWalker, Walker_u)));
        const pSrc = p.pRef;
        const nSrc: c_int = if (pSrc != null) rd(c_int, pSrc, SrcList_nSrc) else 0;
        var i: c_int = 0;
        while (i < nSrc) : (i += 1) {
            if (exprITable(pExpr) == rd(c_int, srcItemAt(pSrc, i), SrcItem_iCursor)) {
                walkerSetCode(pWalker, walkerCode(pWalker) | 1);
                return WRC_Continue;
            }
        }
        i = 0;
        while (i < p.nExclude and p.aiExclude.?[@intCast(i)] != exprITable(pExpr)) : (i += 1) {}
        if (i >= p.nExclude) {
            walkerSetCode(pWalker, walkerCode(pWalker) | 2);
        }
    }
    return WRC_Continue;
}

export fn sqlite3ReferencesSrcList(pParse: Ptr, pExpr: Ptr, pSrcList: Ptr) c_int {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    var x: RefSrcList = std.mem.zeroes(RefSrcList);
    _ = c.memset(pw, 0, sizeof_Walker);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&exprRefToSrcList)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&selectRefEnter)));
    wr(?*anyopaque, pw, Walker_xSelectCallback2, @ptrCast(@constCast(&selectRefLeave)));
    wr(?*anyopaque, pw, Walker_u, @ptrCast(&x));
    x.db = parseDb(pParse);
    x.pRef = pSrcList;
    _ = c.sqlite3WalkExprList(pw, exprPList(pExpr));
    if (exprPLeft(pExpr) != null) {
        _ = c.sqlite3WalkExprList(pw, exprPList(exprPLeft(pExpr)));
    }
    if (hasProp(pExpr, EP_WinFunc)) {
        _ = c.sqlite3WalkExpr(pw, rdp(exprYWin(pExpr), off("Window_pFilter", 0)));
    }
    if (x.aiExclude != null) c.sqlite3DbNNFreeNN(parseDb(pParse), @ptrCast(x.aiExclude));
    if ((walkerCode(pw) & 0x01) != 0) {
        return 1;
    } else if (walkerCode(pw) != 0) {
        return 0;
    } else {
        return -1;
    }
}

fn agginfoPersistExprCb(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    if (!hasProp(pExpr, EP_TokenOnly | EP_Reduced) and exprPAggInfo(pExpr) != null) {
        const pAggInfo = exprPAggInfo(pExpr);
        const iAgg = exprIAgg(pExpr);
        const pParse = walkerParse(pWalker);
        const db = parseDb(pParse);
        if (exprOp(pExpr) != TK_AGG_FUNCTION) {
            if (iAgg < rd(c_int, pAggInfo, AggInfo_nColumn) and rdp(aggColAt(pAggInfo, iAgg), AggInfo_col_pCExpr) == pExpr) {
                const pNew = sqlite3ExprDup(db, pExpr, 0);
                if (pNew != null and sqlite3ExprDeferredDelete(pParse, pNew) == 0) {
                    wr(?*anyopaque, aggColAt(pAggInfo, iAgg), AggInfo_col_pCExpr, pNew);
                }
            }
        } else {
            if (iAgg < rd(c_int, pAggInfo, AggInfo_nFunc) and rdp(aggFuncAt(pAggInfo, iAgg), AggInfo_func_pFExpr) == pExpr) {
                const pNew = sqlite3ExprDup(db, pExpr, 0);
                if (pNew != null and sqlite3ExprDeferredDelete(pParse, pNew) == 0) {
                    wr(?*anyopaque, aggFuncAt(pAggInfo, iAgg), AggInfo_func_pFExpr, pNew);
                }
            }
        }
    }
    return WRC_Continue;
}
inline fn aggFuncAt(pAggInfo: Ptr, i: c_int) Ptr {
    const a = rdp(pAggInfo, AggInfo_aFunc);
    return @ptrCast(base(a) + @as(usize, @intCast(i)) * sizeof_AggInfo_func);
}

export fn sqlite3AggInfoPersistWalkerInit(pWalker: Ptr, pParse: Ptr) void {
    _ = c.memset(pWalker, 0, sizeof_Walker);
    wr(?*anyopaque, pWalker, Walker_pParse, pParse);
    wr(?*anyopaque, pWalker, Walker_xExprCallback, @ptrCast(@constCast(&agginfoPersistExprCb)));
    wr(?*anyopaque, pWalker, Walker_xSelectCallback, @ptrCast(@constCast(&c.sqlite3SelectWalkNoop)));
}

fn addAggInfoColumn(db: Ptr, pInfo: Ptr) c_int {
    var i: c_int = undefined;
    const pNew = c.sqlite3ArrayAllocate(db, rdp(pInfo, AggInfo_aCol), sizeof_AggInfo_col, fieldPtr(pInfo, AggInfo_nColumn), &i);
    wr(?*anyopaque, pInfo, AggInfo_aCol, pNew);
    return i;
}
fn addAggInfoFunc(db: Ptr, pInfo: Ptr) c_int {
    var i: c_int = undefined;
    const pNew = c.sqlite3ArrayAllocate(db, rdp(pInfo, AggInfo_aFunc), sizeof_AggInfo_func, fieldPtr(pInfo, AggInfo_nFunc), &i);
    wr(?*anyopaque, pInfo, AggInfo_aFunc, pNew);
    return i;
}

fn findOrCreateAggInfoColumn(pParse: Ptr, pAggInfo: Ptr, pExpr: Ptr) void {
    var k: c_int = 0;
    const mxTerm = dbLimit(parseDb(pParse), SQLITE_LIMIT_COLUMN);
    const n0 = rd(c_int, pAggInfo, AggInfo_nColumn);
    while (k < n0) : (k += 1) {
        const pCol = aggColAt(pAggInfo, k);
        if (rdp(pCol, AggInfo_col_pCExpr) == pExpr) return;
        if (rd(c_int, pCol, AggInfo_col_iTable) == exprITable(pExpr) and rd(c_int, pCol, AggInfo_col_iColumn) == exprIColumn(pExpr) and exprOp(pExpr) != TK_IF_NULL_ROW) {
            goto_fixup(pParse, pAggInfo, pExpr, k);
            return;
        }
    }
    k = addAggInfoColumn(parseDb(pParse), pAggInfo);
    if (k < 0) {
        return;
    }
    if (k > mxTerm) {
        c.sqlite3ErrorMsg(pParse, "more than %d aggregate terms", mxTerm);
        k = mxTerm;
    }
    const pCol = aggColAt(pAggInfo, k);
    wr(?*anyopaque, pCol, AggInfo_col_pTab, exprYTab(pExpr));
    wr(c_int, pCol, AggInfo_col_iTable, exprITable(pExpr));
    wr(c_int, pCol, AggInfo_col_iColumn, exprIColumn(pExpr));
    wr(c_int, pCol, AggInfo_col_iSorterColumn, -1);
    wr(?*anyopaque, pCol, AggInfo_col_pCExpr, pExpr);
    if (rdp(pAggInfo, AggInfo_pGroupBy) != null and exprOp(pExpr) != TK_IF_NULL_ROW) {
        const pGB = rdp(pAggInfo, AggInfo_pGroupBy);
        const aGB = listA(pGB);
        const nGB = listNExpr(pGB);
        var j: c_int = 0;
        while (j < nGB) : (j += 1) {
            const pE = itemExpr(aGB, j);
            if (exprOp(pE) == TK_COLUMN and exprITable(pE) == exprITable(pExpr) and exprIColumn(pE) == exprIColumn(pExpr)) {
                wr(c_int, pCol, AggInfo_col_iSorterColumn, j);
                break;
            }
        }
    }
    if (rd(c_int, pCol, AggInfo_col_iSorterColumn) < 0) {
        wr(c_int, pCol, AggInfo_col_iSorterColumn, @bitCast(rd(u32, pAggInfo, AggInfo_nSortingColumn)));
        wr(u32, pAggInfo, AggInfo_nSortingColumn, rd(u32, pAggInfo, AggInfo_nSortingColumn) +% 1);
    }
    goto_fixup(pParse, pAggInfo, pExpr, k);
}
fn goto_fixup(pParse: Ptr, pAggInfo: Ptr, pExpr: Ptr, k: c_int) void {
    _ = pParse;
    setVVA(pExpr, EP_NoReduce);
    wr(?*anyopaque, pExpr, Expr_pAggInfo, pAggInfo);
    if (exprOp(pExpr) == TK_COLUMN) {
        setExprOp(pExpr, TK_AGG_COLUMN);
    }
    setExprIAgg(pExpr, @intCast(k));
}

fn analyzeAggregate(pWalker: Ptr, pExpr: Ptr) callconv(.c) c_int {
    const pNC = rdp(pWalker, Walker_u);
    const pParse = rdp(pNC, NameContext_pParse);
    const pSrcList = rdp(pNC, NameContext_pSrcList);
    const pAggInfo = rdp(pNC, NameContext_uNC);
    switch (exprOp(pExpr)) {
        TK_IF_NULL_ROW, TK_AGG_COLUMN, TK_COLUMN => {
            if (pSrcList != null) {
                const nSrc = rd(c_int, pSrcList, SrcList_nSrc);
                var i: c_int = 0;
                while (i < nSrc) : (i += 1) {
                    if (exprITable(pExpr) == rd(c_int, srcItemAt(pSrcList, i), SrcItem_iCursor)) {
                        findOrCreateAggInfoColumn(pParse, pAggInfo, pExpr);
                        break;
                    }
                }
            }
            return WRC_Continue;
        },
        TK_AGG_FUNCTION => {
            if ((rd(c_int, pNC, NameContext_ncFlags) & NC_InAggFunc) == 0 and rd(c_int, pWalker, Walker_walkerDepth) == exprOp2(pExpr) and exprPAggInfo(pExpr) == null) {
                const mxTerm = dbLimit(parseDb(pParse), SQLITE_LIMIT_COLUMN);
                var i: c_int = 0;
                const nF = rd(c_int, pAggInfo, AggInfo_nFunc);
                while (i < nF) : (i += 1) {
                    const pItem = aggFuncAt(pAggInfo, i);
                    if (rdp(pItem, AggInfo_func_pFExpr) == pExpr) break;
                    if (sqlite3ExprCompare(null, rdp(pItem, AggInfo_func_pFExpr), pExpr, -1) == 0) {
                        break;
                    }
                }
                if (i > mxTerm) {
                    c.sqlite3ErrorMsg(pParse, "more than %d aggregate terms", mxTerm);
                    i = mxTerm;
                } else if (i >= rd(c_int, pAggInfo, AggInfo_nFunc)) {
                    const enc = dbEnc(parseDb(pParse));
                    i = addAggInfoFunc(parseDb(pParse), pAggInfo);
                    if (i >= 0) {
                        const pItem = aggFuncAt(pAggInfo, i);
                        wr(?*anyopaque, pItem, AggInfo_func_pFExpr, pExpr);
                        const nArg: c_int = if (exprPList(pExpr) != null) listNExpr(exprPList(pExpr)) else 0;
                        const pFunc = c.sqlite3FindFunction(parseDb(pParse), exprUToken(pExpr), nArg, enc, 0);
                        wr(?*anyopaque, pItem, AggInfo_func_pFunc, pFunc);
                        if (exprPLeft(pExpr) != null and (rd(u32, pFunc, FuncDef_funcFlags) & SQLITE_FUNC_NEEDCOLL) == 0) {
                            wr(c_int, pItem, AggInfo_func_iOBTab, parseNTab(pParse));
                            setParseNTab(pParse, parseNTab(pParse) + 1);
                            const pOBList = exprPList(exprPLeft(pExpr));
                            if (listNExpr(pOBList) == 1 and nArg == 1 and sqlite3ExprCompare(null, itemExpr(listA(pOBList), 0), itemExpr(listA(exprPList(pExpr)), 0), 0) == 0) {
                                wr(u8, pItem, AggInfo_func_bOBPayload, 0);
                                wr(u8, pItem, AggInfo_func_bOBUnique, @intFromBool(hasProp(pExpr, EP_Distinct)));
                            } else {
                                wr(u8, pItem, AggInfo_func_bOBPayload, 1);
                            }
                            wr(u8, pItem, AggInfo_func_bUseSubtype, @intFromBool((rd(u32, pFunc, FuncDef_funcFlags) & SQLITE_SUBTYPE) != 0));
                        } else {
                            wr(c_int, pItem, AggInfo_func_iOBTab, -1);
                        }
                        if (hasProp(pExpr, EP_Distinct) and rd(u8, pItem, AggInfo_func_bOBUnique) == 0) {
                            wr(c_int, pItem, AggInfo_func_iDistinct, parseNTab(pParse));
                            setParseNTab(pParse, parseNTab(pParse) + 1);
                        } else {
                            wr(c_int, pItem, AggInfo_func_iDistinct, -1);
                        }
                    }
                }
                setVVA(pExpr, EP_NoReduce);
                setExprIAgg(pExpr, @intCast(i));
                wr(?*anyopaque, pExpr, Expr_pAggInfo, pAggInfo);
                return WRC_Prune;
            } else {
                return WRC_Continue;
            }
        },
        else => {
            const pIdxEpr0 = rdp(pParse, Parse_pIdxEpr);
            if ((rd(c_int, pNC, NameContext_ncFlags) & NC_InAggFunc) == 0) return WRC_Continue;
            if (pIdxEpr0 == null) return WRC_Continue;
            var pIEpr = pIdxEpr0;
            while (pIEpr != null) : (pIEpr = rdp(pIEpr, IndexedExpr_pIENext)) {
                const iDataCur = rd(c_int, pIEpr, IndexedExpr_iDataCur);
                if (iDataCur < 0) continue;
                if (sqlite3ExprCompare(null, pExpr, rdp(pIEpr, IndexedExpr_pExpr), iDataCur) == 0) break;
            }
            if (pIEpr == null) return WRC_Continue;
            if (!useYTab(pExpr)) return WRC_Continue;
            var i: c_int = 0;
            const nSrc = rd(c_int, pSrcList, SrcList_nSrc);
            while (i < nSrc) : (i += 1) {
                if (rd(c_int, srcItemAt(pSrcList, i), SrcItem_iCursor) == rd(c_int, pIEpr, IndexedExpr_iDataCur)) break;
            }
            if (i >= nSrc) return WRC_Continue;
            if (exprPAggInfo(pExpr) != null) return WRC_Continue;
            if (parseNErr(pParse) != 0) return WRC_Abort;
            var tmp: [sizeof_Expr]u8 align(8) = undefined;
            const pt: Ptr = @ptrCast(&tmp);
            _ = c.memset(pt, 0, sizeof_Expr);
            setExprOp(pt, TK_AGG_COLUMN);
            setExprITable(pt, rd(c_int, pIEpr, IndexedExpr_iIdxCur));
            wr(i16, pt, Expr_iColumn, @intCast(rd(c_int, pIEpr, IndexedExpr_iIdxCol)));
            findOrCreateAggInfoColumn(pParse, pAggInfo, pt);
            if (parseNErr(pParse) != 0) return WRC_Abort;
            wr(?*anyopaque, aggColAt(pAggInfo, exprIAgg(pt)), AggInfo_col_pCExpr, pExpr);
            wr(?*anyopaque, pExpr, Expr_pAggInfo, pAggInfo);
            setExprIAgg(pExpr, @intCast(exprIAgg(pt)));
            return WRC_Prune;
        },
    }
}

export fn sqlite3ExprAnalyzeAggregates(pNC: Ptr, pExpr: Ptr) void {
    var w: [sizeof_Walker]u8 align(8) = undefined;
    const pw: Ptr = @ptrCast(&w);
    wr(?*anyopaque, pw, Walker_xExprCallback, @ptrCast(@constCast(&analyzeAggregate)));
    wr(?*anyopaque, pw, Walker_xSelectCallback, @ptrCast(@constCast(&c.sqlite3WalkerDepthIncrease)));
    wr(?*anyopaque, pw, Walker_xSelectCallback2, @ptrCast(@constCast(&c.sqlite3WalkerDepthDecrease)));
    wr(c_int, pw, Walker_walkerDepth, 0);
    wr(?*anyopaque, pw, Walker_u, pNC);
    wr(?*anyopaque, pw, Walker_pParse, null);
    _ = c.sqlite3WalkExpr(pw, pExpr);
}

export fn sqlite3ExprAnalyzeAggList(pNC: Ptr, pList: Ptr) void {
    if (pList != null) {
        const a0 = listA(pList);
        const n = listNExpr(pList);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            sqlite3ExprAnalyzeAggregates(pNC, itemExpr(a0, i));
        }
    }
}

// ─── temp register management ───────────────────────────────────────────────
inline fn parseNTempReg(pParse: Ptr) c_int {
    return rd(u8, pParse, Parse_nTempReg);
}
inline fn setParseNTempReg(pParse: Ptr, v: c_int) void {
    wr(u8, pParse, Parse_nTempReg, @truncate(@as(c_uint, @bitCast(v))));
}
inline fn aTempRegAt(pParse: Ptr, i: c_int) c_int {
    return rd(c_int, pParse, Parse_aTempReg + @as(usize, @intCast(i)) * 4);
}
inline fn setATempRegAt(pParse: Ptr, i: c_int, v: c_int) void {
    wr(c_int, pParse, Parse_aTempReg + @as(usize, @intCast(i)) * 4, v);
}
inline fn parseNRangeReg(pParse: Ptr) c_int {
    return rd(c_int, pParse, Parse_nRangeReg);
}
inline fn setParseNRangeReg(pParse: Ptr, v: c_int) void {
    wr(c_int, pParse, Parse_nRangeReg, v);
}
inline fn parseIRangeReg(pParse: Ptr) c_int {
    return rd(c_int, pParse, Parse_iRangeReg);
}
inline fn setParseIRangeReg(pParse: Ptr, v: c_int) void {
    wr(c_int, pParse, Parse_iRangeReg, v);
}

export fn sqlite3GetTempReg(pParse: Ptr) c_int {
    if (parseNTempReg(pParse) == 0) {
        return incParseNMem(pParse);
    }
    setParseNTempReg(pParse, parseNTempReg(pParse) - 1);
    return aTempRegAt(pParse, parseNTempReg(pParse));
}

export fn sqlite3ReleaseTempReg(pParse: Ptr, iReg: c_int) void {
    if (iReg != 0) {
        c.sqlite3VdbeReleaseRegisters(pParse, iReg, 1, 0, 0);
        if (parseNTempReg(pParse) < ArraySize_aTempReg) {
            setATempRegAt(pParse, parseNTempReg(pParse), iReg);
            setParseNTempReg(pParse, parseNTempReg(pParse) + 1);
        }
    }
}

export fn sqlite3GetTempRange(pParse: Ptr, nReg: c_int) c_int {
    if (nReg == 1) return sqlite3GetTempReg(pParse);
    var i = parseIRangeReg(pParse);
    const n = parseNRangeReg(pParse);
    if (nReg <= n) {
        setParseIRangeReg(pParse, parseIRangeReg(pParse) + nReg);
        setParseNRangeReg(pParse, parseNRangeReg(pParse) - nReg);
    } else {
        i = parseNMem(pParse) + 1;
        setParseNMem(pParse, parseNMem(pParse) + nReg);
    }
    return i;
}

export fn sqlite3ReleaseTempRange(pParse: Ptr, iReg: c_int, nReg: c_int) void {
    if (nReg == 1) {
        sqlite3ReleaseTempReg(pParse, iReg);
        return;
    }
    c.sqlite3VdbeReleaseRegisters(pParse, iReg, nReg, 0, 0);
    if (nReg > parseNRangeReg(pParse)) {
        setParseNRangeReg(pParse, nReg);
        setParseIRangeReg(pParse, iReg);
    }
}

export fn sqlite3ClearTempRegCache(pParse: Ptr) void {
    setParseNTempReg(pParse, 0);
    setParseNRangeReg(pParse, 0);
}

export fn sqlite3TouchRegister(pParse: Ptr, iReg: c_int) void {
    if (parseNMem(pParse) < iReg) setParseNMem(pParse, iReg);
}

export fn sqlite3FirstAvailableRegister(pParse: Ptr, iMin0: c_int) c_int {
    var iMin = iMin0;
    const pList = rdp(pParse, Parse_pConstExpr);
    if (pList != null) {
        const a0 = listA(pList);
        const n = listNExpr(pList);
        var i: c_int = 0;
        while (i < n) : (i += 1) {
            const reg = rd(c_int, itemAt(a0, i), ExprList_item_u_iConstExprReg);
            if (reg >= iMin) iMin = reg + 1;
        }
    }
    setParseNTempReg(pParse, 0);
    setParseNRangeReg(pParse, 0);
    return iMin;
}

export fn sqlite3NoTempsInRange(pParse: Ptr, iFirst: c_int, iLast: c_int) c_int {
    if (parseNRangeReg(pParse) > 0 and parseIRangeReg(pParse) + parseNRangeReg(pParse) > iFirst and parseIRangeReg(pParse) <= iLast) {
        return 0;
    }
    var i: c_int = 0;
    while (i < parseNTempReg(pParse)) : (i += 1) {
        if (aTempRegAt(pParse, i) >= iFirst and aTempRegAt(pParse, i) <= iLast) {
            return 0;
        }
    }
    const pList = rdp(pParse, Parse_pConstExpr);
    if (pList != null) {
        const a0 = listA(pList);
        const n = listNExpr(pList);
        i = 0;
        while (i < n) : (i += 1) {
            const reg = rd(c_int, itemAt(a0, i), ExprList_item_u_iConstExprReg);
            if (reg == 0) continue;
            if (reg >= iFirst and reg <= iLast) return 0;
        }
    }
    return 1;
}
