//! Zig port of SQLite's src/insert.c — INSERT-statement code generation.
//!
//! This is a CODEGEN module: it emits VDBE bytecode by calling helpers that
//! remain C (or are already-ported Zig exporting the C ABI). It faithfully
//! reproduces sqlite3Insert's control flow and the helpers defined IN insert.c.
//!
//! Exported (non-static) symbols — the complete external set of insert.c
//! (matching prototypes in sqliteInt.h, with this project's config: SQLITE_OMIT_*
//! all OFF, SQLITE_ENABLE_PREUPDATE_HOOK ON, SQLITE_ENABLE_NULL_TRIM OFF,
//! SQLITE_ALLOW_ROWID_IN_VIEW OFF, SQLITE_OMIT_XFER_OPT OFF):
//!   - sqlite3OpenTable
//!   - sqlite3IndexAffinityStr
//!   - sqlite3TableAffinityStr
//!   - sqlite3TableAffinity
//!   - sqlite3ComputeGeneratedColumns
//!   - sqlite3AutoincrementBegin
//!   - sqlite3AutoincrementEnd
//!   - sqlite3MultiValuesEnd
//!   - sqlite3MultiValues
//!   - sqlite3Insert
//!   - sqlite3ExprReferencesUpdatedColumn
//!   - sqlite3GenerateConstraintChecks
//!   - sqlite3CompleteInsertion
//!   - sqlite3OpenTableAndIndices
//!   - sqlite3_xferopt_count (SQLITE_TEST only; comptime @export)
//! Static helpers become private Zig fns.
//!
//! ─── Config assumptions (true in both build configs) ───────────────────────
//!   * SQLITE_OMIT_VIRTUALTABLE / OMIT_TRIGGER / OMIT_VIEW / OMIT_GENERATED_COLUMNS
//!     / OMIT_AUTHORIZATION / OMIT_AUTOINCREMENT / OMIT_UPSERT / OMIT_CHECK /
//!     OMIT_FOREIGN_KEY / OMIT_XFER_OPT  all OFF.
//!   * SQLITE_ENABLE_PREUPDATE_HOOK ON (codeWithoutRowidPreupdate / OP_Delete
//!     pre-update path compiled; the ifndef-PREUPDATE collision shortcut omitted).
//!   * SQLITE_ENABLE_NULL_TRIM OFF → sqlite3SetMakeRecordP5 is a no-op macro.
//!   * SQLITE_ENABLE_HIDDEN_COLUMNS OFF; SQLITE_ENABLE_STAT4 layout already in
//!     c_layout's Index trailing fields (offsets we use are all before it).
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

// ─── ground-truth offsets ─────────────────────────────────────────────────────
// Parse
const Parse_db_off = off("Parse_db", 0);
const Parse_rc_off = off("Parse_rc", 24);
const Parse_nErr_off = off("Parse_nErr", 52);
const Parse_nTab_off = off("Parse_nTab", 56);
const Parse_nMem_off = off("Parse_nMem", 60);
const Parse_nested_off = off("Parse_nested", 30);
const Parse_pVdbe_off = off("Parse_pVdbe", 16);
const Parse_pToplevel_off = off("Parse_pToplevel", 136);
const Parse_pTriggerTab_off = off("Parse_pTriggerTab", 144);
const Parse_iSelfTab_off = off("Parse_iSelfTab", 64);
const Parse_pAinc_off = off("Parse_pAinc", 264);
// bft bitfield group-1 byte: disableTriggers(0x01)..okConstFactor(0x80). Divergent.
const Parse_bft1_byte: usize = if (config.sqlite_debug) 42 else 39;
const BFT_bReturning: u8 = 0x08;
const BFT_bHasWith: u8 = 0x40;
// bft group-2 byte: checkSchema(0x01), usesAinc(0x02). Divergent.
const Parse_bft2_byte: usize = if (config.sqlite_debug) 43 else 40;
const BFT_checkSchema: u8 = 0x01;
const BFT_usesAinc: u8 = 0x02;

// sqlite3
const sqlite3_flags_off = off("sqlite3_flags", 48);
const sqlite3_mDbFlags_off = off("sqlite3_mDbFlags", 44);
const sqlite3_mallocFailed_off = off("sqlite3_mallocFailed", 103);
const sqlite3_aDb_off = off("sqlite3_aDb", 32);
const sqlite3_nDb_off = off("sqlite3_nDb", 40);
const sqlite3_noSharedCache_off = off("sqlite3_noSharedCache", 111);
const sqlite3_xAuth_off = off("sqlite3_xAuth", 528);
const sqlite3_init_busy_off = off("sqlite3_initBusy", 197);

// Db
const sizeof_Db = off("sizeof_Db", 32);
const Db_zDbSName_off = off("Db_zDbSName", 0);
const Db_pSchema_off = off("Db_pSchema", 24);

// Schema
const Schema_pSeqTab_off = off("Schema_pSeqTab", 104);
const Schema_file_format_off = off("Schema_file_format", 112);

// Table
const Table_zName_off = off("Table_zName", 0);
const Table_aCol_off = off("Table_aCol", 8);
const Table_pIndex_off = off("Table_pIndex", 16);
const Table_zColAff_off = off("Table_zColAff", 24);
const Table_pCheck_off = off("Table_pCheck", 32);
const Table_tnum_off = off("Table_tnum", 40);
const Table_tabFlags_off = off("Table_tabFlags", 48);
const Table_iPKey_off = off("Table_iPKey", 52);
const Table_nCol_off = off("Table_nCol", 54);
const Table_nNVCol_off = off("Table_nNVCol", 56);
const Table_keyConf_off = off("Table_keyConf", 62);
const Table_eTabType_off = off("Table_eTabType", 63);
const Table_u_tab_pFKey_off = off("Table_u_tab_pFKey", 72);
const Table_pSchema_off = off("Table_pSchema", 96);

// Column
const Column_zCnName_off = off("Column_zCnName", 0);
const Column_notNull_byte: usize = 8; // notNull:4 | eCType:4 in this byte (mask 0x0f)
const Column_affinity_off = off("Column_affinity", 9);
const Column_iDflt_off = off("Column_iDflt", 12);
const Column_colFlags_off = off("Column_colFlags", 14);
const sizeof_Column = off("sizeof_Column", 16);

// Index
const Index_zColAff_off = off("Index_zColAff", 32);
const Index_aiColumn_off = off("Index_aiColumn", 8);
const Index_aSortOrder_off = off("Index_aSortOrder", 56);
const Index_azColl_off = off("Index_azColl", 64);
const Index_pNext_off = off("Index_pNext", 40);
const Index_pPartIdxWhere_off = off("Index_pPartIdxWhere", 72);
const Index_aColExpr_off = off("Index_aColExpr", 80);
const Index_tnum_off = off("Index_tnum", 88);
const Index_nKeyCol_off = off("Index_nKeyCol", 94);
const Index_nColumn_off = off("Index_nColumn", 96);
const Index_onError_off = off("Index_onError", 98);
// bitfield byte (onError+1 = 99): idxType:2 (mask 0x03), bUnordered:1, uniqNotNull:1 (mask 0x08)
const Index_idxType_byte: usize = if (@hasDecl(L, "Index_idxType_byte")) L.Index_idxType_byte else 99;
// bHasExpr is the 12th bit-flag → byte onError+3 = 101, bit 3 → mask 0x08
const Index_bHasExpr_byte: usize = 101;

// ExprList / item
const ExprList_nExpr_off = off("ExprList_nExpr", 0);
const ExprList_a_off = off("ExprList_a", 8);
const ExprList_item_pExpr_off = off("ExprList_item_pExpr", 0);
const ExprList_item_zEName_off = off("ExprList_item_zEName", 8);
const sizeof_ExprList_item = off("sizeof_ExprList_item", 24);

// IdList (pColumn): struct IdList { int nId; struct {char *zName;} a[FLEXARRAY]; }
const IdList_nId_off: usize = 0;
const IdList_a_off: usize = 8;
const sizeof_IdListItem: usize = 8;
const IdListItem_zName_off: usize = 0;

// SrcList / SrcItem
const SrcList_nSrc_off = off("SrcList_nSrc", 0);
const SrcList_a_off = off("SrcList_a", 8);
const SrcItem_iCursor_off = off("SrcItem_iCursor", 28);
const SrcItem_u1_off = off("SrcItem_u1", 40);
const SrcItem_u4_off = off("SrcItem_u4", 64);
// SrcItem.fg bitfield struct at off 24, 2nd byte (25) holds the flags we read.
const SrcItem_fg_off = off("SrcItem_fg", 24);
const SrcItem_fg_byte1: usize = SrcItem_fg_off + 1;
const FG_isIndexedBy: u8 = 0x02;
const FG_isSubquery: u8 = 0x04;
const FG_isTabFunc: u8 = 0x08;
const FG_viaCoroutine: u8 = 0x40;

// Subquery (reached via SrcItem.u4.pSubq)
const Subquery_pSelect_off = off("Subquery_pSelect", 0);
const Subquery_addrFillSub_off = off("Subquery_addrFillSub", 8);
const Subquery_regReturn_off = off("Subquery_regReturn", 12);
const Subquery_regResult_off = off("Subquery_regResult", 16);

// AutoincInfo
const AutoincInfo_pNext_off = off("AutoincInfo_pNext", 0);
const AutoincInfo_pTab_off = off("AutoincInfo_pTab", 8);
const AutoincInfo_iDb_off = off("AutoincInfo_iDb", 16);
const AutoincInfo_regCtr_off = off("AutoincInfo_regCtr", 20);
const sizeof_AutoincInfo = off("sizeof_AutoincInfo", 24);

// Select
const Select_op_off = off("Select_op", 0);
const Select_selFlags_off = off("Select_selFlags", 4);
const Select_pEList_off = off("Select_pEList", 24);
const Select_pSrc_off = off("Select_pSrc", 32);
const Select_pWhere_off = off("Select_pWhere", 40);
const Select_pGroupBy_off = off("Select_pGroupBy", 48);
const Select_pOrderBy_off = off("Select_pOrderBy", 64);
const Select_pPrior_off = off("Select_pPrior", 72);
const Select_pNext_off: usize = 80; // Select *pNext (after pPrior)
const Select_pLimit_off = off("Select_pLimit", 88);
const Select_pWith_off = off("Select_pWith", 96);

// Expr
const Expr_op_off = off("Expr_op", 0);
const Expr_iColumn_off = off("Expr_iColumn", 48);
const Expr_flags_off = off("Expr_flags", 4); // u32 flags (offsetof Expr.flags)
const Expr_u_zToken_off: usize = 8; // Expr.u.zToken (union first member)

// VdbeOp (for autoinc aOp[] field-setting)
const sizeof_VdbeOp = off("sizeof_VdbeOp", 32);
const VdbeOp_opcode_off = off("VdbeOp_opcode", 0);
const VdbeOp_p5_off = off("VdbeOp_p5", 2);
const VdbeOp_p1_off = off("VdbeOp_p1", 4);
const VdbeOp_p2_off = off("VdbeOp_p2", 8);
const VdbeOp_p3_off = off("VdbeOp_p3", 12);
const VdbeOp_p4type_off = off("VdbeOp_p4type", 1);
const VdbeOp_p4_off = off("VdbeOp_p4", 16);

// SelectDest layout (config-invariant)
const SelectDest_eDest_off: usize = 0;
const SelectDest_iSDParm_off: usize = 4;
const SelectDest_iSDParm2_off: usize = 8;
const SelectDest_iSdst_off: usize = 12;
const SelectDest_nSdst_off: usize = 16;
const SelectDest_sz: usize = off("sizeof_SelectDest", 40);

// NameContext
const sizeof_NameContext = off("sizeof_NameContext", 56);
const NameContext_pParse_off = off("NameContext_pParse", 0);

// ─── constants ───────────────────────────────────────────────────────────────
const TF_WithoutRowid: u32 = 0x00000080;
const TF_Autoincrement: u32 = 0x00000008;
const TF_HasNotNull: u32 = 0x00000800;
const TF_OOOHidden: u32 = 0x00000400;
const TF_HasStored: u32 = 0x00000040;
const TF_HasVirtual: u32 = 0x00000020;
const TF_HasGenerated: u32 = 0x60;
const TF_HasHidden: u32 = 0x0002;
const TF_Strict: u32 = 0x00010000;

const COLFLAG_PRIMKEY: u16 = 0x0001;
const COLFLAG_HIDDEN: u16 = 0x0002;
const COLFLAG_STORED: u16 = 0x0040;
const COLFLAG_VIRTUAL: u16 = 0x0020;
const COLFLAG_GENERATED: u16 = 0x0060;
const COLFLAG_NOINSERT: u16 = 0x0062;
const COLFLAG_NOTAVAIL: u16 = 0x0080;
const COLFLAG_BUSY: u16 = 0x0100;

const COLTYPE_ANY: u32 = 1;
const COLTYPE_INT: u32 = 3;
const COLTYPE_INTEGER: u32 = 4;
const Column_eCType_shift: u3 = 4;

const SQLITE_AFF_NONE: u8 = 0x40; // '@'
const SQLITE_AFF_BLOB: u8 = 0x41; // 'A'
const SQLITE_AFF_TEXT: u8 = 0x42;
const SQLITE_AFF_NUMERIC: u8 = 0x43;
const SQLITE_AFF_INTEGER: u8 = 0x44;
const SQLITE_AFF_REAL: u8 = 0x45;

const XN_ROWID: i16 = -1;
const XN_EXPR: i16 = -2;

const OE_None: c_int = 0;
const OE_Rollback: c_int = 1;
const OE_Abort: c_int = 2;
const OE_Fail: c_int = 3;
const OE_Ignore: c_int = 4;
const OE_Replace: c_int = 5;
const OE_Update: c_int = 6;
const OE_Default: c_int = 11;

const SQLITE_IDXTYPE_PRIMARYKEY: u8 = 2;

const ONEPASS_OFF: c_int = 0;
const ONEPASS_SINGLE: c_int = 1;

const SF_Values: u32 = 0x0000200;
const SF_MultiValue: u32 = 0x0000400;
const SF_Distinct: u32 = 0x0000001;

const TK_SELECT: c_int = 139;
const TK_ALL: c_int = 136;
const TK_INSERT: c_int = 128;
const TK_DELETE: c_int = 129;
const TK_NULL: c_int = 122;
const TK_ASTERISK: c_int = 180;
const TK_COLUMN: c_int = 168;
const TK_SPAN: c_int = 181;
const TK_RAISE: c_int = 72;
const TK_ROW: c_int = 76;

const EP_IntValue: u32 = 0x000800;
const EP_Subquery: u32 = 0x400000;

const SRT_Coroutine: c_int = 11;

const SQLITE_CountRows: u64 = 0x100000000;
const SQLITE_ForeignKeys: u64 = 0x00004000;
const SQLITE_RecTriggers: u64 = 0x00002000;
const SQLITE_IgnoreChecks: u64 = 0x00000200;

const DBFLAG_Vacuum: u32 = 0x0004;
const DBFLAG_VacuumInto: u32 = 0x0008;
const DBFLAG_SchemaKnownOk: u32 = 0x0010;

const SQLITE_JUMPIFNULL: c_int = 0x10;
const SQLITE_NOTNULL: u16 = 0x90;

const TRIGGER_BEFORE: c_int = 1;
const TRIGGER_AFTER: c_int = 2;

const P4_TABLE: c_int = -5;
const P4_VTAB: c_int = -12;
const P4_DYNAMIC: c_int = -7;
const P4_COLLSEQ: c_int = -2;
const P4_TRANSIENT: c_int = 0;
const P4_INT32: i8 = -3;

const SQLITE_INSERT: c_int = 18;
const SQLITE_SELECT: c_int = 21;
const SQLITE_DENY: c_int = 1;
const SQLITE_OK: c_int = 0;
const SQLITE_CORRUPT_SEQUENCE: c_int = 523;

const P5_ConstraintNotNull: u16 = 1;
const P5_ConstraintCheck: u16 = 3;
const SQLITE_CONSTRAINT_NOTNULL: c_int = 1299;
const SQLITE_CONSTRAINT_CHECK: c_int = 275;

const OPFLAG_NCHANGE: u16 = 0x01;
const OPFLAG_LASTROWID: u16 = 0x20;
const OPFLAG_APPEND: u16 = 0x08;
const OPFLAG_USESEEKRESULT: u16 = 0x10;
const OPFLAG_SAVEPOSITION: u16 = 0x02;
const OPFLAG_ISUPDATE: u16 = 0x04;
const OPFLAG_ISNOOP: u16 = 0x40;
const OPFLAG_PREFORMAT: u16 = 0x80;
const OPFLAG_BULKCSR: u16 = 0x01;

const OPFLG_JUMP: u8 = 0x01;

const WRC_Continue: c_int = 0;
const WRC_Abort: c_int = 2;

// VDBE opcodes (exact values from generated opcodes.h)
const OP_Goto: c_int = 9;
const OP_InitCoroutine: c_int = 11;
const OP_Yield: c_int = 12;
const OP_MustBeInt: c_int = 13;
const OP_IfNot: c_int = 17;
const OP_NoConflict: c_int = 27;
const OP_NotExists: c_int = 31;
const OP_Rewind: c_int = 36;
const OP_Next: c_int = 40;
const OP_IsNull: c_int = 51;
const OP_NotNull: c_int = 52;
const OP_Ne: c_int = 53;
const OP_Eq: c_int = 54;
const OP_Le: c_int = 56;
const OP_HaltIfNull: c_int = 71;
const OP_Halt: c_int = 72;
const OP_Integer: c_int = 73;
const OP_Null: c_int = 77;
const OP_SoftNull: c_int = 78;
const OP_Copy: c_int = 82;
const OP_SCopy: c_int = 83;
const OP_IntCopy: c_int = 84;
const OP_AddImm: c_int = 88;
const OP_Column: c_int = 96;
const OP_TypeCheck: c_int = 97;
const OP_Affinity: c_int = 98;
const OP_MakeRecord: c_int = 99;
const OP_Count: c_int = 100;
const OP_OpenRead: c_int = 114;
const OP_OpenWrite: c_int = 116;
const OP_OpenEphemeral: c_int = 120;
const OP_Close: c_int = 124;
const OP_NewRowid: c_int = 129;
const OP_Insert: c_int = 130;
const OP_RowCell: c_int = 131;
const OP_Delete: c_int = 132;
const OP_RowData: c_int = 136;
const OP_Rowid: c_int = 137;
const OP_SeekEnd: c_int = 139;
const OP_IdxInsert: c_int = 140;
const OP_IdxRowid: c_int = 144;
const OP_MemMax: c_int = 161;
const OP_CursorLock: c_int = 169;
const OP_CursorUnlock: c_int = 170;
const OP_VOpen: c_int = 175;
const OP_ReleaseReg: c_int = 188;
const OP_VUpdate: c_int = 7;

// ═══ extern C / internal-ABI helpers ═════════════════════════════════════════
extern fn sqlite3VdbeDb(v: ?*anyopaque) ?*anyopaque;
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeMakeLabel(pParse: ?*anyopaque) c_int;
extern fn sqlite3VdbeCurrentAddr(p: ?*anyopaque) c_int;
extern fn sqlite3VdbeAddOp0(p: ?*anyopaque, op: c_int) c_int;
extern fn sqlite3VdbeAddOp1(p: ?*anyopaque, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp4Int(p: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, p4: c_int) c_int;
extern fn sqlite3VdbeChangeP4(p: ?*anyopaque, addr: c_int, zP4: ?[*]const u8, n: c_int) void;
extern fn sqlite3VdbeChangeP5(p: ?*anyopaque, p5: u16) void;
extern fn sqlite3VdbeJumpHere(p: ?*anyopaque, addr: c_int) void;
extern fn sqlite3VdbeResolveLabel(p: ?*anyopaque, x: c_int) void;
extern fn sqlite3VdbeGoto(p: ?*anyopaque, addr: c_int) c_int;
extern fn sqlite3VdbeAppendP4(p: ?*anyopaque, pP4: ?*anyopaque, p4type: c_int) void;
extern fn sqlite3VdbeCountChanges(v: ?*anyopaque) void;
extern fn sqlite3VdbeGetOp(p: ?*anyopaque, addr: c_int) ?*anyopaque;
extern fn sqlite3VdbeGetLastOp(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeAddOpList(p: ?*anyopaque, nOp: c_int, aOp: ?*const anyopaque, iLineno: c_int) ?*anyopaque;
extern fn sqlite3VdbeLoadString(p: ?*anyopaque, iDest: c_int, zStr: ?[*:0]const u8) c_int;
extern fn sqlite3VdbeEndCoroutine(v: ?*anyopaque, regYield: c_int) void;
extern fn sqlite3VdbeSetP4KeyInfo(pParse: ?*anyopaque, pIdx: ?*anyopaque) void;
// VdbeVerifyAbortable / VdbeReleaseRegisters are SQLITE_DEBUG-only (no-op macros
// in production); @extern only inside the debug branch so production never
// references the symbol.
inline fn sqlite3VdbeVerifyAbortable(p: ?*anyopaque, onError: c_int) void {
    if (config.sqlite_debug) {
        const f = @extern(*const fn (?*anyopaque, c_int) callconv(.c) void, .{ .name = "sqlite3VdbeVerifyAbortable" });
        f(p, onError);
    }
}
inline fn sqlite3VdbeReleaseRegisters(pParse: ?*anyopaque, iFirst: c_int, N: c_int, mask: u32, bUndefine: c_int) void {
    if (config.sqlite_debug) {
        const f = @extern(*const fn (?*anyopaque, c_int, c_int, u32, c_int) callconv(.c) void, .{ .name = "sqlite3VdbeReleaseRegisters" });
        f(pParse, iFirst, N, mask, bUndefine);
    }
}
extern fn sqlite3VdbeHasSubProgram(p: ?*anyopaque) c_int;
// EXPLAIN_COMMENTS is ON in both build configs → these are real symbols.
// VdbeComment attaches a comment (no opcode); VdbeNoopComment / VdbeModuleComment
// emit a real OP_Noop, so they must be reproduced for address-identical codegen.
extern fn sqlite3VdbeComment(v: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3VdbeNoopComment(v: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3VdbeExplain(pParse: ?*anyopaque, bPush: u8, fmt: [*:0]const u8, ...) c_int;

extern fn sqlite3DbMallocRaw(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbNNFreeNN(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3MPrintf(db: ?*anyopaque, fmt: [*:0]const u8, ...) ?[*]u8;

extern fn sqlite3ColumnExpr(pTab: ?*anyopaque, pCol: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ColumnColl(pCol: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3ExprAffinity(pExpr: ?*anyopaque) u8;
extern fn sqlite3ExprIsConstant(pParse: ?*anyopaque, p: ?*anyopaque) c_int;
extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprCode(pParse: ?*anyopaque, pExpr: ?*anyopaque, target: c_int) void;
extern fn sqlite3ExprCodeCopy(pParse: ?*anyopaque, pExpr: ?*anyopaque, target: c_int) void;
extern fn sqlite3ExprCodeFactorable(pParse: ?*anyopaque, pExpr: ?*anyopaque, target: c_int) void;
extern fn sqlite3ExprCodeTarget(pParse: ?*anyopaque, pExpr: ?*anyopaque, target: c_int) c_int;
extern fn sqlite3ExprCodeExprList(pParse: ?*anyopaque, pList: ?*anyopaque, target: c_int, srcReg: c_int, flags: u8) c_int;
extern fn sqlite3ExprCodeGeneratedColumn(pParse: ?*anyopaque, pTab: ?*anyopaque, pCol: ?*anyopaque, regOut: c_int) void;
extern fn sqlite3ExprIfTrue(pParse: ?*anyopaque, pExpr: ?*anyopaque, dest: c_int, jumpIfNull: c_int) void;
extern fn sqlite3ExprIfFalseDup(pParse: ?*anyopaque, pExpr: ?*anyopaque, dest: c_int, jumpIfNull: c_int) void;
extern fn sqlite3ExprCompare(pParse: ?*anyopaque, pA: ?*anyopaque, pB: ?*anyopaque, iTab: c_int) c_int;
extern fn sqlite3ExprListCompare(pA: ?*anyopaque, pB: ?*anyopaque, iTab: c_int) c_int;

extern fn sqlite3WalkExpr(pWalker: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3WalkExprList(pWalker: ?*anyopaque, pList: ?*anyopaque) c_int;

extern fn sqlite3SrcListLookup(pParse: ?*anyopaque, pSrc: ?*anyopaque) ?*anyopaque;
extern fn sqlite3SrcListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3IdListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SrcItemAttachSubquery(pParse: ?*anyopaque, pItem: ?*anyopaque, pSubq: ?*anyopaque, addToSrc: c_int) c_int;

extern fn sqlite3SelectNew(pParse: ?*anyopaque, pEList: ?*anyopaque, pSrc: ?*anyopaque, pWhere: ?*anyopaque, pGroupBy: ?*anyopaque, pHaving: ?*anyopaque, pOrderBy: ?*anyopaque, selFlags: u32, pLimit: ?*anyopaque) ?*anyopaque;
extern fn sqlite3Select(pParse: ?*anyopaque, p: ?*anyopaque, pDest: ?*anyopaque) c_int;
extern fn sqlite3SelectDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SelectDestInit(pDest: ?*anyopaque, eDest: c_int, iParm: c_int) void;
extern fn sqlite3SelectWrongNumTermsError(pParse: ?*anyopaque, p: ?*anyopaque) void;

extern fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) c_int;
extern fn sqlite3PrimaryKeyIndex(pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3TableLock(pParse: ?*anyopaque, iDb: c_int, tnum: u32, isWriteLock: u8, zName: ?[*:0]const u8) void;
extern fn sqlite3LocateCollSeq(pParse: ?*anyopaque, zName: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3LocateTableItem(pParse: ?*anyopaque, flags: u32, pItem: ?*anyopaque) ?*anyopaque;
extern fn sqlite3CodeVerifySchema(pParse: ?*anyopaque, iDb: c_int) void;
extern fn sqlite3ColumnIndex(pTab: ?*anyopaque, zCol: ?[*:0]const u8) c_int;
extern fn sqlite3IsRowid(z: ?[*:0]const u8) c_int;
extern fn sqlite3TableColumnToStorage(pTab: ?*anyopaque, iCol: i16) i16;
extern fn sqlite3TableColumnToIndex(pIdx: ?*anyopaque, iCol: i16) i16;

extern fn sqlite3TriggersExist(pParse: ?*anyopaque, pTab: ?*anyopaque, op: c_int, pChanges: ?*anyopaque, pMask: ?*c_int) ?*anyopaque;
extern fn sqlite3CodeRowTrigger(pParse: ?*anyopaque, pTrigger: ?*anyopaque, op: c_int, pChanges: ?*anyopaque, tr_tm: c_int, pTab: ?*anyopaque, reg: c_int, orconf: c_int, ignoreJump: c_int) void;

extern fn sqlite3ViewGetColumnNames(pParse: ?*anyopaque, pTab: ?*anyopaque) c_int;
extern fn sqlite3IsReadOnly(pParse: ?*anyopaque, pTab: ?*anyopaque, pTrigger: ?*anyopaque) c_int;

extern fn sqlite3ResolveExprListNames(pNC: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3ReadSchema(pParse: ?*anyopaque) c_int;

extern fn sqlite3FkCheck(pParse: ?*anyopaque, pTab: ?*anyopaque, regOld: c_int, regNew: c_int, aChange: ?*c_int, chngRowid: c_int) void;
extern fn sqlite3FkRequired(pParse: ?*anyopaque, pTab: ?*anyopaque, aChange: ?*c_int, chngRowid: c_int) c_int;
extern fn sqlite3FkReferences(pTab: ?*anyopaque) ?*anyopaque;

extern fn sqlite3MultiWrite(pParse: ?*anyopaque) void;
extern fn sqlite3MayAbort(pParse: ?*anyopaque) void;
extern fn sqlite3BeginWriteOperation(pParse: ?*anyopaque, setStatement: c_int, iDb: c_int) void;
extern fn sqlite3CodeChangeCount(v: ?*anyopaque, regCounter: c_int, zColName: [*:0]const u8) void;

extern fn sqlite3GetTempReg(pParse: ?*anyopaque) c_int;
extern fn sqlite3ReleaseTempReg(pParse: ?*anyopaque, iReg: c_int) void;
extern fn sqlite3GetTempRange(pParse: ?*anyopaque, nReg: c_int) c_int;
extern fn sqlite3ReleaseTempRange(pParse: ?*anyopaque, iReg: c_int, nReg: c_int) void;

extern fn sqlite3GenerateRowDelete(pParse: ?*anyopaque, pTab: ?*anyopaque, pTrigger: ?*anyopaque, iDataCur: c_int, iIdxCur: c_int, iPk: c_int, nPk: i16, count: u8, onconf: u8, eMode: u8, iIdxNoSeek: c_int) void;
extern fn sqlite3GenerateRowIndexDelete(pParse: ?*anyopaque, pTab: ?*anyopaque, iDataCur: c_int, iIdxCur: c_int, aRegIdx: ?*c_int, iIdxNoSeek: c_int) void;

extern fn sqlite3HaltConstraint(pParse: ?*anyopaque, errCode: c_int, onError: c_int, p4: ?[*]const u8, p4type: i8, p5: u8) void;
extern fn sqlite3UniqueConstraint(pParse: ?*anyopaque, onError: c_int, pIdx: ?*anyopaque) void;
extern fn sqlite3RowidConstraint(pParse: ?*anyopaque, onError: c_int, pTab: ?*anyopaque) void;

extern fn sqlite3GetVTable(db: ?*anyopaque, pTab: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VtabMakeWritable(pParse: ?*anyopaque, pTab: ?*anyopaque) void;

extern fn sqlite3HasExplicitNulls(pParse: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3UpsertDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3UpsertAnalyzeTarget(pParse: ?*anyopaque, pTabList: ?*anyopaque, pUpsert: ?*anyopaque, pAll: ?*anyopaque) c_int;
extern fn sqlite3UpsertDoUpdate(pParse: ?*anyopaque, pUpsert: ?*anyopaque, pTab: ?*anyopaque, pIdx: ?*anyopaque, iCur: c_int) void;
extern fn sqlite3UpsertOfIndex(pUpsert: ?*anyopaque, pIdx: ?*anyopaque) ?*anyopaque;
extern fn sqlite3UpsertNextIsIPK(pUpsert: ?*anyopaque) c_int;

extern fn sqlite3AuthCheck(pParse: ?*anyopaque, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;
extern fn sqlite3AuthReadCol(pParse: ?*anyopaque, zTab: ?[*:0]const u8, zCol: ?[*:0]const u8, iDb: c_int) c_int;

extern fn sqlite3ParserAddCleanup(pParse: ?*anyopaque, xCleanup: *const fn (?*anyopaque, ?*anyopaque) callconv(.c) void, p: ?*anyopaque) ?*anyopaque;

extern fn sqlite3FaultSim(iTest: c_int) c_int;
extern fn sqlite3_stricmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;

// Upsert field accessors (offsets from c_layout / update.zig)
const Upsert_pUpsertTarget_off = off("Upsert_pUpsertTarget", 0);
const Upsert_pNextUpsert_off = off("Upsert_pNextUpsert", 32);
const Upsert_isDoUpdate_off: usize = 40; // probe-verified
const Upsert_pToFree_off: usize = 48; // probe-verified
const Upsert_pUpsertIdx_off: usize = 56; // probe-verified
const Upsert_pUpsertSrc_off: usize = 64; // probe-verified
const Upsert_regData_off: usize = 72; // probe-verified
const Upsert_iDataCur_off = off("Upsert_iDataCur", 76);
const Upsert_iIdxCur_off = off("Upsert_iIdxCur", 80);

// sqlite3StrBINARY / sqlite3OpcodeProperty are C arrays: the symbol address IS
// the data — bind as a byte and take &.
extern const sqlite3StrBINARY: u8;
extern const sqlite3OpcodeProperty: u8;
inline fn strBINARY() [*:0]const u8 {
    return @ptrCast(&sqlite3StrBINARY);
}
inline fn opcodeProp(opcode: u8) u8 {
    const arr: [*]const u8 = @ptrCast(&sqlite3OpcodeProperty);
    return arr[opcode];
}

// ─── accessors ───────────────────────────────────────────────────────────────
inline fn pDb(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_db_off);
}
inline fn pNErr(pParse: ?*anyopaque) c_int {
    return rd(c_int, pParse, Parse_nErr_off);
}
inline fn pIncNErr(pParse: ?*anyopaque) void {
    wr(c_int, pParse, Parse_nErr_off, pNErr(pParse) + 1);
}
inline fn pSetRc(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_rc_off, v);
}
inline fn pNTab(pParse: ?*anyopaque) c_int {
    return rd(c_int, pParse, Parse_nTab_off);
}
inline fn pSetNTab(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_nTab_off, v);
}
inline fn pIncNTab(pParse: ?*anyopaque) c_int {
    const v = pNTab(pParse);
    pSetNTab(pParse, v + 1);
    return v;
}
inline fn pNMem(pParse: ?*anyopaque) c_int {
    return rd(c_int, pParse, Parse_nMem_off);
}
inline fn pSetNMem(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_nMem_off, v);
}
inline fn pIncNMem(pParse: ?*anyopaque) c_int {
    const v = pNMem(pParse) + 1;
    pSetNMem(pParse, v);
    return v;
}
inline fn pNested(pParse: ?*anyopaque) u8 {
    return base(pParse)[Parse_nested_off];
}
inline fn pVdbe(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pVdbe_off);
}
inline fn pPTriggerTab(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pTriggerTab_off);
}
inline fn pSetISelfTab(pParse: ?*anyopaque, v: c_int) void {
    wr(c_int, pParse, Parse_iSelfTab_off, v);
}
inline fn pPAinc(pParse: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pParse, Parse_pAinc_off);
}
inline fn pSetPAinc(pParse: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, pParse, Parse_pAinc_off, v);
}
inline fn pBReturning(pParse: ?*anyopaque) bool {
    return (base(pParse)[Parse_bft1_byte] & BFT_bReturning) != 0;
}
inline fn pBHasWith(pParse: ?*anyopaque) bool {
    return (base(pParse)[Parse_bft1_byte] & BFT_bHasWith) != 0;
}
inline fn pSetCheckSchema(pParse: ?*anyopaque) void {
    base(pParse)[Parse_bft2_byte] |= BFT_checkSchema;
}
inline fn pUsesAinc(pParse: ?*anyopaque) bool {
    return (base(pParse)[Parse_bft2_byte] & BFT_usesAinc) != 0;
}
inline fn pSetUsesAinc(pParse: ?*anyopaque) void {
    base(pParse)[Parse_bft2_byte] |= BFT_usesAinc;
}
// pToplevel ? pToplevel : p
inline fn pToplevel(pParse: ?*anyopaque) ?*anyopaque {
    const t = rd(?*anyopaque, pParse, Parse_pToplevel_off);
    return if (t != null) t else pParse;
}

inline fn dbFlags(db: ?*anyopaque) u64 {
    return rd(u64, db, sqlite3_flags_off);
}
inline fn dbMDbFlags(db: ?*anyopaque) u32 {
    return rd(u32, db, sqlite3_mDbFlags_off);
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}
inline fn dbInitBusy(db: ?*anyopaque) bool {
    return base(db)[sqlite3_init_busy_off] != 0;
}
inline fn dbXAuth(db: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, db, sqlite3_xAuth_off);
}
inline fn dbNoSharedCache(db: ?*anyopaque) bool {
    return base(db)[sqlite3_noSharedCache_off] != 0;
}
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rd(c_int, db, sqlite3_nDb_off);
}
inline fn dbAt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, db, sqlite3_aDb_off).?);
    return @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Db);
}
inline fn dbZDbSName(db: ?*anyopaque, i: c_int) ?[*:0]const u8 {
    return rd(?[*:0]const u8, dbAt(db, i), Db_zDbSName_off);
}
inline fn dbPSchema(db: ?*anyopaque, i: c_int) ?*anyopaque {
    return rd(?*anyopaque, dbAt(db, i), Db_pSchema_off);
}

inline fn tabZName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Table_zName_off);
}
inline fn tabPSchema(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pSchema_off);
}
inline fn tabPIndex(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pIndex_off);
}
inline fn tabPCheck(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_pCheck_off);
}
inline fn tabTnum(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tnum_off);
}
inline fn tabIPKey(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_iPKey_off);
}
inline fn tabNCol(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_nCol_off);
}
inline fn tabNNVCol(p: ?*anyopaque) i16 {
    return rd(i16, p, Table_nNVCol_off);
}
inline fn tabKeyConf(p: ?*anyopaque) u8 {
    return base(p)[Table_keyConf_off];
}
inline fn tabTabFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Table_tabFlags_off);
}
inline fn tabETabType(p: ?*anyopaque) u8 {
    return base(p)[Table_eTabType_off];
}
inline fn tabIsVirtual(p: ?*anyopaque) bool {
    return tabETabType(p) == 1;
}
inline fn tabIsView(p: ?*anyopaque) bool {
    return tabETabType(p) == 2;
}
inline fn tabIsOrdinary(p: ?*anyopaque) bool {
    return tabETabType(p) == 0;
}
inline fn tabHasRowid(p: ?*anyopaque) bool {
    return (tabTabFlags(p) & TF_WithoutRowid) == 0;
}
inline fn tabZColAff(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_zColAff_off);
}
inline fn tabSetZColAff(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Table_zColAff_off, v);
}
inline fn tabPFKey(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Table_u_tab_pFKey_off);
}
inline fn tabColAt(p: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Table_aCol_off).?);
    return @ptrCast(a + @as(usize, @intCast(i)) * sizeof_Column);
}

inline fn colZCnName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Column_zCnName_off);
}
inline fn colNotNull(p: ?*anyopaque) u8 {
    return base(p)[Column_notNull_byte] & 0x0f;
}
inline fn colECType(p: ?*anyopaque) u32 {
    return @as(u32, base(p)[Column_notNull_byte] >> Column_eCType_shift);
}
inline fn colAffinity(p: ?*anyopaque) u8 {
    return base(p)[Column_affinity_off];
}
inline fn colIDflt(p: ?*anyopaque) u16 {
    return rd(u16, p, Column_iDflt_off);
}
inline fn colColFlags(p: ?*anyopaque) u16 {
    return rd(u16, p, Column_colFlags_off);
}
inline fn colSetColFlags(p: ?*anyopaque, v: u16) void {
    wr(u16, p, Column_colFlags_off, v);
}

inline fn idxPNext(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pNext_off);
}
inline fn idxTnum(p: ?*anyopaque) u32 {
    return rd(u32, p, Index_tnum_off);
}
inline fn idxPSchema(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pSchema_off);
}
const Index_pSchema_off = off("Index_pSchema", 48);
const Index_zName_off = off("Index_zName", 0);
inline fn idxZName(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Index_zName_off);
}
inline fn idxNKeyCol(p: ?*anyopaque) u16 {
    return rd(u16, p, Index_nKeyCol_off);
}
inline fn idxNColumn(p: ?*anyopaque) u16 {
    return rd(u16, p, Index_nColumn_off);
}
inline fn idxOnError(p: ?*anyopaque) u8 {
    return base(p)[Index_onError_off];
}
inline fn idxType(p: ?*anyopaque) u8 {
    return base(p)[Index_idxType_byte] & 0x03;
}
inline fn idxUniqNotNull(p: ?*anyopaque) bool {
    return (base(p)[Index_idxType_byte] & 0x08) != 0;
}
inline fn idxBHasExpr(p: ?*anyopaque) bool {
    return (base(p)[Index_bHasExpr_byte] & 0x08) != 0;
}
inline fn idxIsPrimaryKey(p: ?*anyopaque) bool {
    return idxType(p) == SQLITE_IDXTYPE_PRIMARYKEY;
}
inline fn idxIsUnique(p: ?*anyopaque) bool {
    return idxType(p) != 0; // UNIQUE/PK/IPK
}
inline fn idxPPartIdxWhere(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_pPartIdxWhere_off);
}
inline fn idxZColAff(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_zColAff_off);
}
inline fn idxSetZColAff(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Index_zColAff_off, v);
}
inline fn idxAiColumn(p: ?*anyopaque, i: usize) i16 {
    const a: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_aiColumn_off).?);
    const q: *align(1) const i16 = @ptrCast(a + i * @sizeOf(i16));
    return q.*;
}
inline fn idxAColExpr(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Index_aColExpr_off);
}
// Index.aColExpr->a[i].pExpr  (ExprList.a is INLINE)
inline fn idxColExprAt(p: ?*anyopaque, i: usize) ?*anyopaque {
    const pList = idxAColExpr(p);
    const a: [*]u8 = @as([*]u8, @ptrCast(pList.?)) + ExprList_a_off;
    return rd(?*anyopaque, @as(?*anyopaque, @ptrCast(a + i * sizeof_ExprList_item)), ExprList_item_pExpr_off);
}
inline fn idxAColl(p: ?*anyopaque, i: usize) ?[*:0]const u8 {
    const arr: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_azColl_off).?);
    const q: *align(1) const ?[*:0]const u8 = @ptrCast(arr + i * @sizeOf(usize));
    return q.*;
}
inline fn idxASortOrder(p: ?*anyopaque, i: usize) u8 {
    const arr: [*]u8 = @ptrCast(rd(?*anyopaque, p, Index_aSortOrder_off).?);
    return arr[i];
}

inline fn elNExpr(p: ?*anyopaque) c_int {
    return rd(c_int, p, ExprList_nExpr_off);
}
inline fn elItem(p: ?*anyopaque, i: usize) ?*anyopaque {
    const a: [*]u8 = @as([*]u8, @ptrCast(p.?)) + ExprList_a_off;
    return @ptrCast(a + i * sizeof_ExprList_item);
}
inline fn elPExpr(p: ?*anyopaque, i: usize) ?*anyopaque {
    return rd(?*anyopaque, elItem(p, i), ExprList_item_pExpr_off);
}
inline fn elZEName(p: ?*anyopaque, i: usize) ?[*:0]const u8 {
    return rd(?[*:0]const u8, elItem(p, i), ExprList_item_zEName_off);
}

inline fn srcNSrc(p: ?*anyopaque) c_int {
    return rd(c_int, p, SrcList_nSrc_off);
}
inline fn srcItem0(p: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(p) + SrcList_a_off);
}
inline fn itemSetICursor(pItem: ?*anyopaque, v: c_int) void {
    wr(c_int, pItem, SrcItem_iCursor_off, v);
}
inline fn itemFgByte1(pItem: ?*anyopaque) u8 {
    return base(pItem)[SrcItem_fg_byte1];
}
inline fn itemSetFgBit(pItem: ?*anyopaque, mask: u8) void {
    base(pItem)[SrcItem_fg_byte1] |= mask;
}
inline fn itemIsSubquery(pItem: ?*anyopaque) bool {
    return (itemFgByte1(pItem) & FG_isSubquery) != 0;
}
inline fn itemViaCoroutine(pItem: ?*anyopaque) bool {
    return (itemFgByte1(pItem) & FG_viaCoroutine) != 0;
}
inline fn itemPSubq(pItem: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pItem, SrcItem_u4_off);
}
inline fn itemSetU1NRow(pItem: ?*anyopaque, v: c_int) void {
    wr(c_int, pItem, SrcItem_u1_off, v);
}
inline fn itemU1NRow(pItem: ?*anyopaque) c_int {
    return rd(c_int, pItem, SrcItem_u1_off);
}

inline fn subqPSelect(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Subquery_pSelect_off);
}
inline fn subqRegReturn(p: ?*anyopaque) c_int {
    return rd(c_int, p, Subquery_regReturn_off);
}
inline fn subqRegResult(p: ?*anyopaque) c_int {
    return rd(c_int, p, Subquery_regResult_off);
}
inline fn subqAddrFillSub(p: ?*anyopaque) c_int {
    return rd(c_int, p, Subquery_addrFillSub_off);
}

inline fn selOp(p: ?*anyopaque) u8 {
    return base(p)[Select_op_off];
}
inline fn selSetOp(p: ?*anyopaque, v: u8) void {
    base(p)[Select_op_off] = v;
}
inline fn selSelFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Select_selFlags_off);
}
inline fn selSetSelFlags(p: ?*anyopaque, v: u32) void {
    wr(u32, p, Select_selFlags_off, v);
}
inline fn selPEList(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pEList_off);
}
inline fn selSetPEList(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Select_pEList_off, v);
}
inline fn selPSrc(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pSrc_off);
}
inline fn selPWhere(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pWhere_off);
}
inline fn selPGroupBy(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pGroupBy_off);
}
inline fn selPOrderBy(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pOrderBy_off);
}
inline fn selPPrior(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pPrior_off);
}
inline fn selSetPPrior(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Select_pPrior_off, v);
}
inline fn selPNext(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pNext_off);
}
inline fn selPLimit(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pLimit_off);
}
inline fn selPWith(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Select_pWith_off);
}

inline fn exprOp(p: ?*anyopaque) u8 {
    return base(p)[Expr_op_off];
}
inline fn exprFlags(p: ?*anyopaque) u32 {
    return rd(u32, p, Expr_flags_off);
}
inline fn exprHasProperty(p: ?*anyopaque, prop: u32) bool {
    return (exprFlags(p) & prop) != 0;
}
inline fn exprIColumn(p: ?*anyopaque) i16 {
    return rd(i16, p, Expr_iColumn_off);
}
inline fn exprZToken(p: ?*anyopaque) ?[*:0]const u8 {
    return rd(?[*:0]const u8, p, Expr_u_zToken_off);
}

inline fn schemaPSeqTab(pSchema: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, pSchema, Schema_pSeqTab_off);
}
inline fn schemaFileFormat(pSchema: ?*anyopaque) u8 {
    return base(pSchema)[Schema_file_format_off];
}

// IdList
inline fn idlNId(p: ?*anyopaque) c_int {
    return rd(c_int, p, IdList_nId_off);
}
inline fn idlItem(p: ?*anyopaque, i: usize) ?*anyopaque {
    // IdList.a is an INLINE flex array at IdList_a_off — take its address.
    const a: [*]u8 = @as([*]u8, @ptrCast(p.?)) + IdList_a_off;
    return @ptrCast(a + i * sizeof_IdListItem);
}
inline fn idlZName(p: ?*anyopaque, i: usize) ?[*:0]const u8 {
    return rd(?[*:0]const u8, idlItem(p, i), IdListItem_zName_off);
}

// Upsert
inline fn upPUpsertTarget(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertTarget_off);
}
inline fn upPNextUpsert(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pNextUpsert_off);
}
inline fn upIsDoUpdate(p: ?*anyopaque) u8 {
    return base(p)[Upsert_isDoUpdate_off];
}
inline fn upPUpsertIdx(p: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, p, Upsert_pUpsertIdx_off);
}
inline fn upSetPToFree(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Upsert_pToFree_off, v);
}
inline fn upSetPUpsertSrc(p: ?*anyopaque, v: ?*anyopaque) void {
    wr(?*anyopaque, p, Upsert_pUpsertSrc_off, v);
}
inline fn upSetRegData(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Upsert_regData_off, v);
}
inline fn upSetIDataCur(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Upsert_iDataCur_off, v);
}
inline fn upSetIIdxCur(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, Upsert_iIdxCur_off, v);
}

// VdbeOp array accessors (for autoinc; aOp returned by AddOpList)
inline fn opAt(aOp: ?*anyopaque, i: usize) ?*anyopaque {
    return @ptrCast(base(aOp) + i * sizeof_VdbeOp);
}
inline fn opSetP1(op: ?*anyopaque, v: c_int) void {
    wr(c_int, op, VdbeOp_p1_off, v);
}
inline fn opSetP2(op: ?*anyopaque, v: c_int) void {
    wr(c_int, op, VdbeOp_p2_off, v);
}
inline fn opSetP3(op: ?*anyopaque, v: c_int) void {
    wr(c_int, op, VdbeOp_p3_off, v);
}
inline fn opSetP5(op: ?*anyopaque, v: u16) void {
    wr(u16, op, VdbeOp_p5_off, v);
}
inline fn opOpcode(op: ?*anyopaque) u8 {
    return base(op)[VdbeOp_opcode_off];
}
inline fn opSetOpcode(op: ?*anyopaque, v: u8) void {
    base(op)[VdbeOp_opcode_off] = v;
}
inline fn opP1(op: ?*anyopaque) c_int {
    return rd(c_int, op, VdbeOp_p1_off);
}
inline fn opP2(op: ?*anyopaque) c_int {
    return rd(c_int, op, VdbeOp_p2_off);
}
inline fn opP3(op: ?*anyopaque) c_int {
    return rd(c_int, op, VdbeOp_p3_off);
}
inline fn opP5(op: ?*anyopaque) u16 {
    return rd(u16, op, VdbeOp_p5_off);
}
inline fn opSetP3z(op: ?*anyopaque, v: c_int) void {
    wr(c_int, op, VdbeOp_p3_off, v);
}
inline fn opP4type(op: ?*anyopaque) i8 {
    return rd(i8, op, VdbeOp_p4type_off);
}
inline fn opP4z(op: ?*anyopaque) ?[*]const u8 {
    return rd(?[*]const u8, op, VdbeOp_p4_off);
}
inline fn opP4i(op: ?*anyopaque) c_int {
    return rd(c_int, op, VdbeOp_p4_off);
}

// SelectDest writers
inline fn destSetISDParm(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, SelectDest_iSDParm_off, v);
}
inline fn destISDParm(p: ?*anyopaque) c_int {
    return rd(c_int, p, SelectDest_iSDParm_off);
}
inline fn destSetISdst(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, SelectDest_iSdst_off, v);
}
inline fn destISdst(p: ?*anyopaque) c_int {
    return rd(c_int, p, SelectDest_iSdst_off);
}
inline fn destSetNSdst(p: ?*anyopaque, v: c_int) void {
    wr(c_int, p, SelectDest_nSdst_off, v);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3OpenTable
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3OpenTable(pParse: ?*anyopaque, iCur: c_int, iDb: c_int, pTab: ?*anyopaque, opcode: c_int) callconv(.c) void {
    // assert !IsVirtual(pTab); assert pParse->pVdbe!=0
    const v = pVdbe(pParse);
    const db = pDb(pParse);
    if (!dbNoSharedCache(db)) {
        sqlite3TableLock(pParse, iDb, tabTnum(pTab), if (opcode == OP_OpenWrite) @as(u8, 1) else 0, tabZName(pTab));
    }
    if (tabHasRowid(pTab)) {
        _ = sqlite3VdbeAddOp4Int(v, opcode, iCur, @intCast(tabTnum(pTab)), iDb, tabNNVCol(pTab));
        sqlite3VdbeComment(v, "%s", tabZName(pTab));
    } else {
        const pPk = sqlite3PrimaryKeyIndex(pTab);
        _ = sqlite3VdbeAddOp3(v, opcode, iCur, @intCast(idxTnum(pPk)), iDb);
        sqlite3VdbeSetP4KeyInfo(pParse, pPk);
        sqlite3VdbeComment(v, "%s", tabZName(pTab));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// computeIndexAffStr (static) + sqlite3IndexAffinityStr
// ═══════════════════════════════════════════════════════════════════════════
fn computeIndexAffStr(db: ?*anyopaque, pIdx: ?*anyopaque) ?[*]const u8 {
    const pTab = rd(?*anyopaque, pIdx, off("Index_pTable", 24));
    const nColumn: usize = @intCast(idxNColumn(pIdx));
    const buf = sqlite3DbMallocRaw(null, @as(u64, @intCast(nColumn + 1)));
    if (buf == null) {
        _ = sqlite3OomFault(db);
        idxSetZColAff(pIdx, null);
        return null;
    }
    idxSetZColAff(pIdx, buf);
    const z: [*]u8 = @ptrCast(buf.?);
    var n: usize = 0;
    while (n < nColumn) : (n += 1) {
        const x = idxAiColumn(pIdx, n);
        var aff: u8 = undefined;
        if (x >= 0) {
            aff = colAffinity(tabColAt(pTab, x));
        } else if (x == XN_ROWID) {
            aff = SQLITE_AFF_INTEGER;
        } else {
            // assert x==XN_EXPR
            aff = sqlite3ExprAffinity(idxColExprAt(pIdx, n));
        }
        if (aff < SQLITE_AFF_BLOB) aff = SQLITE_AFF_BLOB;
        if (aff > SQLITE_AFF_NUMERIC) aff = SQLITE_AFF_NUMERIC;
        z[n] = aff;
    }
    z[n] = 0;
    return z;
}

export fn sqlite3IndexAffinityStr(db: ?*anyopaque, pIdx: ?*anyopaque) callconv(.c) ?[*]const u8 {
    if (idxZColAff(pIdx) == null) return computeIndexAffStr(db, pIdx);
    return @ptrCast(idxZColAff(pIdx).?);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3TableAffinityStr
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3TableAffinityStr(db: ?*anyopaque, pTab: ?*anyopaque) callconv(.c) ?[*]u8 {
    const nCol: c_int = tabNCol(pTab);
    const buf = sqlite3DbMallocRaw(db, @as(u64, @intCast(nCol + 1)));
    if (buf != null) {
        const z: [*]u8 = @ptrCast(buf.?);
        var i: c_int = 0;
        var j: usize = 0;
        while (i < nCol) : (i += 1) {
            if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_VIRTUAL) == 0) {
                z[j] = colAffinity(tabColAt(pTab, i));
                j += 1;
            }
        }
        // do { z[j--]=0 } while( j>=0 && z[j]<=SQLITE_AFF_BLOB )
        // (j is usize; emulate the signed loop carefully)
        var jj: i64 = @intCast(j);
        while (true) {
            z[@intCast(jj)] = 0;
            jj -= 1;
            if (!(jj >= 0 and z[@intCast(jj)] <= SQLITE_AFF_BLOB)) break;
        }
    }
    return if (buf) |b| @ptrCast(b) else null;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3TableAffinity
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3TableAffinity(v: ?*anyopaque, pTab: ?*anyopaque, iReg: c_int) callconv(.c) void {
    if ((tabTabFlags(pTab) & TF_Strict) != 0) {
        if (iReg == 0) {
            sqlite3VdbeAppendP4(v, pTab, P4_TABLE);
            const pPrev = sqlite3VdbeGetLastOp(v);
            // assert pPrev!=0 && (opcode==MakeRecord || mallocFailed)
            opSetOpcode(pPrev, @intCast(OP_TypeCheck));
            const p3 = opP3(pPrev);
            opSetP3(pPrev, 0);
            _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, opP1(pPrev), opP2(pPrev), p3);
        } else {
            _ = sqlite3VdbeAddOp2(v, OP_TypeCheck, iReg, tabNNVCol(pTab));
            sqlite3VdbeAppendP4(v, pTab, P4_TABLE);
        }
        return;
    }
    var zColAff = tabZColAff(pTab);
    if (zColAff == null) {
        zColAff = @ptrCast(@constCast(sqlite3TableAffinityStr(null, pTab)));
        if (zColAff == null) {
            _ = sqlite3OomFault(sqlite3VdbeDb(v));
            return;
        }
        tabSetZColAff(pTab, zColAff);
    }
    const z: [*:0]const u8 = @ptrCast(zColAff.?);
    const i: c_int = @intCast(std.mem.len(z) & 0x3fffffff);
    if (i != 0) {
        if (iReg != 0) {
            _ = sqlite3VdbeAddOp4(v, OP_Affinity, iReg, i, 0, z, i);
        } else {
            sqlite3VdbeChangeP4(v, -1, z, i);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// readsTable (static)
// ═══════════════════════════════════════════════════════════════════════════
fn readsTable(p: ?*anyopaque, iDb: c_int, pTab: ?*anyopaque) bool {
    const v = sqlite3GetVdbe(p);
    const iEnd = sqlite3VdbeCurrentAddr(v);
    const pVTab: ?*anyopaque = if (tabIsVirtual(pTab)) sqlite3GetVTable(pDb(p), pTab) else null;

    var i: c_int = 1;
    while (i < iEnd) : (i += 1) {
        const pOp = sqlite3VdbeGetOp(v, i);
        if (opOpcode(pOp) == OP_OpenRead and opP3(pOp) == iDb) {
            const tnum: u32 = @bitCast(opP2(pOp));
            if (tnum == tabTnum(pTab)) return true;
            var pIndex = tabPIndex(pTab);
            while (pIndex != null) : (pIndex = idxPNext(pIndex)) {
                if (tnum == idxTnum(pIndex)) return true;
            }
        }
        if (opOpcode(pOp) == OP_VOpen and opP4type(pOp) == P4_VTAB and opP4z(pOp) == @as(?[*]const u8, @ptrCast(pVTab))) {
            return true;
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// exprColumnFlagUnion (static Walker callback) + sqlite3ComputeGeneratedColumns
// ═══════════════════════════════════════════════════════════════════════════
const Walker_eCode_off = off("Walker_eCode", 36);
const Walker_u_off = off("Walker_u", 40);
const Walker_pParse_off = off("Walker_pParse", 0);
const Walker_xExprCallback_off = off("Walker_xExprCallback", 8);
const Walker_xSelectCallback_off = off("Walker_xSelectCallback", 16);
const Walker_xSelectCallback2_off = off("Walker_xSelectCallback2", 24);
const sizeof_Walker = off("sizeof_Walker", 48);

inline fn wkECode(w: ?*anyopaque) u32 {
    return rd(u32, w, Walker_eCode_off);
}
inline fn wkSetECode(w: ?*anyopaque, v: u32) void {
    wr(u32, w, Walker_eCode_off, v);
}
inline fn wkUPTab(w: ?*anyopaque) ?*anyopaque {
    return rd(?*anyopaque, w, Walker_u_off);
}
inline fn wkUAiCol(w: ?*anyopaque) [*c]c_int {
    return @ptrCast(@alignCast(rd(?*anyopaque, w, Walker_u_off)));
}

fn exprColumnFlagUnion(pWalker: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_COLUMN and exprIColumn(pExpr) >= 0) {
        const pTab = wkUPTab(pWalker);
        const col = tabColAt(pTab, exprIColumn(pExpr));
        wkSetECode(pWalker, wkECode(pWalker) | colColFlags(col));
    }
    return WRC_Continue;
}

export fn sqlite3ComputeGeneratedColumns(pParse: ?*anyopaque, iRegStore: c_int, pTab: ?*anyopaque) callconv(.c) void {
    var w: [sizeof_Walker]u8 align(8) = @splat(0);
    const pW: ?*anyopaque = @ptrCast(&w);

    // affinity on the regular columns first
    sqlite3TableAffinity(pVdbe(pParse), pTab, iRegStore);
    if ((tabTabFlags(pTab) & TF_HasStored) != 0) {
        const pOp = sqlite3VdbeGetLastOp(pVdbe(pParse));
        if (opOpcode(pOp) == OP_Affinity) {
            const zP4: [*]u8 = @ptrCast(@constCast(opP4z(pOp).?));
            // assert p4type==P4_DYNAMIC
            var ii: c_int = 0;
            var jj: usize = 0;
            while (zP4[jj] != 0) : (ii += 1) {
                if ((colColFlags(tabColAt(pTab, ii)) & COLFLAG_VIRTUAL) != 0) {
                    continue;
                }
                if ((colColFlags(tabColAt(pTab, ii)) & COLFLAG_STORED) != 0) {
                    zP4[jj] = SQLITE_AFF_NONE;
                }
                jj += 1;
            }
        } else if (opOpcode(pOp) == OP_TypeCheck) {
            opSetP3(pOp, 1);
        }
    }

    // Pass 1: mark generated columns NOT-AVAILABLE.
    var i: c_int = 0;
    const nCol: c_int = tabNCol(pTab);
    while (i < nCol) : (i += 1) {
        const col = tabColAt(pTab, i);
        if ((colColFlags(col) & COLFLAG_GENERATED) != 0) {
            colSetColFlags(col, colColFlags(col) | COLFLAG_NOTAVAIL);
        }
    }

    wr(?*anyopaque, pW, Walker_u_off, pTab);
    wr(?*anyopaque, pW, Walker_xExprCallback_off, @ptrCast(@constCast(&exprColumnFlagUnion)));
    wr(?*anyopaque, pW, Walker_xSelectCallback_off, null);
    wr(?*anyopaque, pW, Walker_xSelectCallback2_off, null);

    // Pass 2: compute NOT-AVAILABLE columns.
    pSetISelfTab(pParse, -iRegStore);
    var pRedo: ?*anyopaque = null;
    var eProgress: bool = undefined;
    while (true) {
        eProgress = false;
        pRedo = null;
        i = 0;
        while (i < nCol) : (i += 1) {
            const pCol = tabColAt(pTab, i);
            if ((colColFlags(pCol) & COLFLAG_NOTAVAIL) != 0) {
                colSetColFlags(pCol, colColFlags(pCol) | COLFLAG_BUSY);
                wkSetECode(pW, 0);
                _ = sqlite3WalkExpr(pW, sqlite3ColumnExpr(pTab, pCol));
                colSetColFlags(pCol, colColFlags(pCol) & ~COLFLAG_BUSY);
                if ((wkECode(pW) & COLFLAG_NOTAVAIL) != 0) {
                    pRedo = pCol;
                    continue;
                }
                eProgress = true;
                const x = sqlite3TableColumnToStorage(pTab, @intCast(i)) + @as(i16, @intCast(iRegStore));
                sqlite3ExprCodeGeneratedColumn(pParse, pTab, pCol, x);
                colSetColFlags(pCol, colColFlags(pCol) & ~COLFLAG_NOTAVAIL);
            }
        }
        if (!(pRedo != null and eProgress)) break;
    }
    if (pRedo != null) {
        sqlite3ErrorMsg(pParse, "generated column loop on \"%s\"", colZCnName(pRedo));
    }
    pSetISelfTab(pParse, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// autoIncBegin (static)
// ═══════════════════════════════════════════════════════════════════════════
fn autoIncBegin(pParse: ?*anyopaque, iDb: c_int, pTab: ?*anyopaque) c_int {
    var memId: c_int = 0;
    const db = pDb(pParse);
    if ((tabTabFlags(pTab) & TF_Autoincrement) != 0 and (dbMDbFlags(db) & DBFLAG_Vacuum) == 0) {
        const pTop = pToplevel(pParse);
        const pSchema = dbPSchema(db, iDb);
        const pSeqTab = schemaPSeqTab(pSchema);

        if (pSeqTab == null or !tabHasRowid(pSeqTab) or tabIsVirtual(pSeqTab) or tabNCol(pSeqTab) != 2) {
            pIncNErr(pParse);
            pSetRc(pParse, SQLITE_CORRUPT_SEQUENCE);
            return 0;
        }

        if (!pUsesAinc(pTop)) {
            pSetPAinc(pTop, null);
        }
        var pInfo = pPAinc(pTop);
        while (pInfo != null and rd(?*anyopaque, pInfo, AutoincInfo_pTab_off) != pTab) {
            pInfo = rd(?*anyopaque, pInfo, AutoincInfo_pNext_off);
        }
        if (pInfo == null) {
            pInfo = sqlite3DbMallocRawNN(db, sizeof_AutoincInfo);
            _ = sqlite3ParserAddCleanup(pTop, sqlite3DbFreeCleanup, pInfo);
            if (dbMallocFailed(db)) return 0;
            wr(?*anyopaque, pInfo, AutoincInfo_pNext_off, pPAinc(pTop));
            pSetPAinc(pTop, pInfo);
            pSetUsesAinc(pTop);
            wr(?*anyopaque, pInfo, AutoincInfo_pTab_off, pTab);
            wr(c_int, pInfo, AutoincInfo_iDb_off, iDb);
            pSetNMem(pTop, pNMem(pTop) + 1); // register to hold name of table
            wr(c_int, pInfo, AutoincInfo_regCtr_off, pIncNMem(pTop));
            pSetNMem(pTop, pNMem(pTop) + 2); // rowid in sqlite_sequence + orig max
        }
        memId = rd(c_int, pInfo, AutoincInfo_regCtr_off);
    }
    return memId;
}

// sqlite3DbFree has signature (sqlite3*, void*); ParserAddCleanup wants the
// same — wrap so the cast is explicit.
fn sqlite3DbFreeCleanup(db: ?*anyopaque, p: ?*anyopaque) callconv(.c) void {
    sqlite3DbFree(db, p);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3AutoincrementBegin
// ═══════════════════════════════════════════════════════════════════════════
const autoInc = [_]u8{
    // {opcode, p1, p2, p3} — VdbeOpList (4 bytes each)
    OP_Null,    0, 0, 0,
    OP_Rewind,  0, 10, 0,
    OP_Column,  0, 0, 0,
    OP_Ne,      0, 9, 0,
    OP_Rowid,   0, 0, 0,
    OP_Column,  0, 1, 0,
    OP_AddImm,  0, 0, 0,
    OP_Copy,    0, 0, 0,
    OP_Goto,    0, 11, 0,
    OP_Next,    0, 2, 0,
    OP_Integer, 0, 0, 0,
    OP_Close,   0, 0, 0,
};
const autoInc_nOp: c_int = 12;
const SQLITE_JUMPIFNULL_u16: u16 = 0x10;

export fn sqlite3AutoincrementBegin(pParse: ?*anyopaque) callconv(.c) void {
    const db = pDb(pParse);
    const v = pVdbe(pParse);
    // assert pTriggerTab==0 && toplevel && v && usesAinc
    var p = pPAinc(pParse);
    while (p != null) : (p = rd(?*anyopaque, p, AutoincInfo_pNext_off)) {
        const iDb = rd(c_int, p, AutoincInfo_iDb_off);
        const memId = rd(c_int, p, AutoincInfo_regCtr_off);
        const pSchema = dbPSchema(db, iDb);
        sqlite3OpenTable(pParse, 0, iDb, schemaPSeqTab(pSchema), OP_OpenRead);
        const pTab = rd(?*anyopaque, p, AutoincInfo_pTab_off);
        _ = sqlite3VdbeLoadString(v, memId - 1, tabZName(pTab));
        const aOp = sqlite3VdbeAddOpList(v, autoInc_nOp, @ptrCast(&autoInc), 0);
        if (aOp == null) break;
        opSetP2(opAt(aOp, 0), memId);
        opSetP3(opAt(aOp, 0), memId + 2);
        opSetP3(opAt(aOp, 2), memId);
        opSetP1(opAt(aOp, 3), memId - 1);
        opSetP3(opAt(aOp, 3), memId);
        opSetP5(opAt(aOp, 3), SQLITE_JUMPIFNULL_u16);
        opSetP2(opAt(aOp, 4), memId + 1);
        opSetP3(opAt(aOp, 5), memId);
        opSetP1(opAt(aOp, 6), memId);
        opSetP2(opAt(aOp, 7), memId + 2);
        opSetP1(opAt(aOp, 7), memId);
        opSetP2(opAt(aOp, 10), memId);
        if (pNTab(pParse) == 0) pSetNTab(pParse, 1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// autoIncStep (static) + autoIncrementEnd (static) + sqlite3AutoincrementEnd
// ═══════════════════════════════════════════════════════════════════════════
fn autoIncStep(pParse: ?*anyopaque, memId: c_int, regRowid: c_int) void {
    if (memId > 0) {
        _ = sqlite3VdbeAddOp2(pVdbe(pParse), OP_MemMax, memId, regRowid);
    }
}

const autoIncEnd = [_]u8{
    OP_NotNull,    0, 2, 0,
    OP_NewRowid,   0, 0, 0,
    OP_MakeRecord, 0, 2, 0,
    OP_Insert,     0, 0, 0,
    OP_Close,      0, 0, 0,
};
const autoIncEnd_nOp: c_int = 5;

fn autoIncrementEnd(pParse: ?*anyopaque) void {
    const v = pVdbe(pParse);
    const db = pDb(pParse);
    var p = pPAinc(pParse);
    while (p != null) : (p = rd(?*anyopaque, p, AutoincInfo_pNext_off)) {
        const iDb = rd(c_int, p, AutoincInfo_iDb_off);
        const pSchema = dbPSchema(db, iDb);
        const memId = rd(c_int, p, AutoincInfo_regCtr_off);
        const iRec = sqlite3GetTempReg(pParse);
        _ = sqlite3VdbeAddOp3(v, OP_Le, memId + 2, sqlite3VdbeCurrentAddr(v) + 7, memId);
        sqlite3OpenTable(pParse, 0, iDb, schemaPSeqTab(pSchema), OP_OpenWrite);
        const aOp = sqlite3VdbeAddOpList(v, autoIncEnd_nOp, @ptrCast(&autoIncEnd), 0);
        if (aOp == null) break;
        opSetP1(opAt(aOp, 0), memId + 1);
        opSetP2(opAt(aOp, 1), memId + 1);
        opSetP1(opAt(aOp, 2), memId - 1);
        opSetP3(opAt(aOp, 2), iRec);
        opSetP2(opAt(aOp, 3), iRec);
        opSetP3(opAt(aOp, 3), memId + 1);
        opSetP5(opAt(aOp, 3), OPFLAG_APPEND);
        sqlite3ReleaseTempReg(pParse, iRec);
    }
}

export fn sqlite3AutoincrementEnd(pParse: ?*anyopaque) callconv(.c) void {
    if (pUsesAinc(pParse)) autoIncrementEnd(pParse);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3MultiValuesEnd
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3MultiValuesEnd(pParse: ?*anyopaque, pVal: ?*anyopaque) callconv(.c) void {
    if (pVal != null and srcNSrc(selPSrc(pVal)) > 0) {
        const pItem = srcItem0(selPSrc(pVal));
        if (itemIsSubquery(pItem)) {
            const pSubq = itemPSubq(pItem);
            sqlite3VdbeEndCoroutine(pVdbe(pParse), subqRegReturn(pSubq));
            sqlite3VdbeJumpHere(pVdbe(pParse), subqAddrFillSub(pSubq) - 1);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// exprListIsConstant / exprListIsNoAffinity (static)
// ═══════════════════════════════════════════════════════════════════════════
fn exprListIsConstant(pParse: ?*anyopaque, pRow: ?*anyopaque) bool {
    var ii: usize = 0;
    const n: usize = @intCast(elNExpr(pRow));
    while (ii < n) : (ii += 1) {
        if (sqlite3ExprIsConstant(pParse, elPExpr(pRow, ii)) == 0) return false;
    }
    return true;
}

fn exprListIsNoAffinity(pParse: ?*anyopaque, pRow: ?*anyopaque) bool {
    if (!exprListIsConstant(pParse, pRow)) return false;
    var ii: usize = 0;
    const n: usize = @intCast(elNExpr(pRow));
    while (ii < n) : (ii += 1) {
        const pExpr = elPExpr(pRow, ii);
        if (sqlite3ExprAffinity(pExpr) != 0) return false;
    }
    return true;
}

// IN_SPECIAL_PARSE: pParse->eParseMode != PARSE_MODE_NORMAL
const Parse_eParseMode_off = off("Parse_eParseMode", 300);
inline fn inSpecialParse(pParse: ?*anyopaque) bool {
    return base(pParse)[Parse_eParseMode_off] != 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3MultiValues
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3MultiValues(pParse: ?*anyopaque, pLeft_in: ?*anyopaque, pRow: ?*anyopaque) callconv(.c) ?*anyopaque {
    var pLeft = pLeft_in;
    const db = pDb(pParse);

    if (pBHasWith(pParse) or
        dbInitBusy(db) or
        !exprListIsConstant(pParse, pRow) or
        (srcNSrc(selPSrc(pLeft)) == 0 and !exprListIsNoAffinity(pParse, selPEList(pLeft))) or
        inSpecialParse(pParse))
    {
        // UNION ALL method.
        var pSelect: ?*anyopaque = null;
        var f: u32 = SF_Values | SF_MultiValue;
        if (srcNSrc(selPSrc(pLeft)) != 0) {
            sqlite3MultiValuesEnd(pParse, pLeft);
            f = SF_Values;
        } else if (selPPrior(pLeft) != null) {
            f = f & selSelFlags(pLeft);
        }
        pSelect = sqlite3SelectNew(pParse, pRow, null, null, null, null, null, f, null);
        selSetSelFlags(pLeft, selSelFlags(pLeft) & ~@as(u32, SF_MultiValue));
        if (pSelect != null) {
            selSetOp(pSelect, @intCast(TK_ALL));
            selSetPPrior(pSelect, pLeft);
            pLeft = pSelect;
        }
    } else {
        var p: ?*anyopaque = null;

        if (srcNSrc(selPSrc(pLeft)) == 0) {
            const v = sqlite3GetVdbe(pParse);
            const pRet = sqlite3SelectNew(pParse, null, null, null, null, null, null, 0, null);

            if ((dbMDbFlags(db) & DBFLAG_SchemaKnownOk) == 0) {
                _ = sqlite3ReadSchema(pParse);
            }

            if (pRet != null) {
                var dest: [SelectDest_sz]u8 align(8) = undefined;
                const pDest: ?*anyopaque = @ptrCast(&dest);
                wr(c_int, selPSrc(pRet), SrcList_nSrc_off, 1);
                selSetPPrior(pRet, selPPrior(pLeft));
                selSetOp(pRet, selOp(pLeft));
                if (selPPrior(pRet) != null) selSetSelFlags(pRet, selSelFlags(pRet) | SF_Values);
                selSetPPrior(pLeft, null);
                selSetOp(pLeft, @intCast(TK_SELECT));
                p = srcItem0(selPSrc(pRet));
                itemSetFgBit(p, FG_viaCoroutine);
                itemSetICursor(p, -1);
                itemSetU1NRow(p, 2);
                if (sqlite3SrcItemAttachSubquery(pParse, p, pLeft, 0) != 0) {
                    const pSubq = itemPSubq(p);
                    wr(c_int, pSubq, Subquery_addrFillSub_off, sqlite3VdbeCurrentAddr(v) + 1);
                    wr(c_int, pSubq, Subquery_regReturn_off, pIncNMem(pParse));
                    _ = sqlite3VdbeAddOp3(v, OP_InitCoroutine, subqRegReturn(pSubq), 0, subqAddrFillSub(pSubq));
                    sqlite3SelectDestInit(pDest, SRT_Coroutine, subqRegReturn(pSubq));

                    // Two unused registers immediately before the co-routine's.
                    destSetISdst(pDest, pNMem(pParse) + 3);
                    const nSdst = elNExpr(selPEList(pLeft));
                    destSetNSdst(pDest, nSdst);
                    pSetNMem(pParse, pNMem(pParse) + 2 + nSdst);

                    selSetSelFlags(pLeft, selSelFlags(pLeft) | SF_MultiValue);
                    _ = sqlite3Select(pParse, pLeft, pDest);
                    wr(c_int, pSubq, Subquery_regResult_off, destISdst(pDest));
                }
                pLeft = pRet;
            }
        } else {
            p = srcItem0(selPSrc(pLeft));
            itemSetU1NRow(p, itemU1NRow(p) + 1);
        }

        if (pNErr(pParse) == 0) {
            const pSubq = itemPSubq(p);
            const psel = subqPSelect(pSubq);
            if (elNExpr(selPEList(psel)) != elNExpr(pRow)) {
                sqlite3SelectWrongNumTermsError(pParse, psel);
            } else {
                _ = sqlite3ExprCodeExprList(pParse, pRow, subqRegResult(pSubq), 0, 0);
                _ = sqlite3VdbeAddOp1(pVdbe(pParse), OP_Yield, subqRegReturn(pSubq));
            }
        }
        sqlite3ExprListDelete(db, pRow);
    }

    return pLeft;
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3Insert
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3Insert(
    pParse: ?*anyopaque,
    pTabList: ?*anyopaque,
    pSelect_in: ?*anyopaque,
    pColumn: ?*anyopaque,
    onError: c_int,
    pUpsert: ?*anyopaque,
) callconv(.c) void {
    var pSelect = pSelect_in;
    const db = pDb(pParse);
    var pTab: ?*anyopaque = undefined;
    var i: c_int = undefined;
    var j: c_int = undefined;
    var v: ?*anyopaque = undefined;
    var pIdx: ?*anyopaque = undefined;
    var nColumn: c_int = undefined;
    var nHidden: c_int = 0;
    var iDataCur: c_int = 0;
    var iIdxCur: c_int = 0;
    var ipkColumn: c_int = -1;
    var endOfLoop: c_int = undefined;
    var srcTab: c_int = 0;
    var addrInsTop: c_int = 0;
    var addrCont: c_int = 0;
    var dest: [SelectDest_sz]u8 align(8) = undefined;
    const pDest: ?*anyopaque = @ptrCast(&dest);
    var iDb: c_int = undefined;
    var useTempTable: bool = false;
    var appendFlag: bool = false;
    var withoutRowid: bool = undefined;
    var bIdListInOrder: bool = undefined;
    var pList: ?*anyopaque = null;
    var iRegStore: c_int = undefined;

    var regFromSelect: c_int = 0;
    var regAutoinc: c_int = 0;
    var regRowCount: c_int = 0;
    var regIns: c_int = undefined;
    var regRowid: c_int = undefined;
    var regData: c_int = undefined;
    var aRegIdx: [*c]c_int = null;
    var aTabColMap: [*c]c_int = null;

    var isView: bool = undefined;
    var pTrigger: ?*anyopaque = undefined;
    var tmask: c_int = undefined;

    // assert db->pParse==pParse
    if (pNErr(pParse) != 0) {
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }
    // dest.iSDParm = 0
    destSetISDParm(pDest, 0);

    // Collapse single-row VALUES.
    if (pSelect != null and (selSelFlags(pSelect) & SF_Values) != 0 and selPPrior(pSelect) == null) {
        pList = selPEList(pSelect);
        selSetPEList(pSelect, null);
        sqlite3SelectDelete(db, pSelect);
        pSelect = null;
    }

    // Locate table.
    pTab = sqlite3SrcListLookup(pParse, pTabList);
    if (pTab == null) {
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }
    iDb = sqlite3SchemaToIndex(db, tabPSchema(pTab));
    // assert iDb<db->nDb
    if (sqlite3AuthCheck(pParse, SQLITE_INSERT, tabZName(pTab), null, dbZDbSName(db, iDb)) != 0) {
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }
    withoutRowid = !tabHasRowid(pTab);

    // Triggers + view detection.
    tmask = 0;
    pTrigger = sqlite3TriggersExist(pParse, pTab, TK_INSERT, null, &tmask);
    isView = tabIsView(pTab);

    // Ensure view column names initialized.
    if (sqlite3ViewGetColumnNames(pParse, pTab) != 0) {
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }

    // Cannot insert into read-only table.
    if (sqlite3IsReadOnly(pParse, pTab, pTrigger) != 0) {
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }

    // Allocate VDBE.
    v = sqlite3GetVdbe(pParse);
    if (v == null) {
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }
    if (pNested(pParse) == 0) sqlite3VdbeCountChanges(v);
    sqlite3BeginWriteOperation(pParse, if (pSelect != null or pTrigger != null) 1 else 0, iDb);

    // Xfer optimization (2nd template).
    if (pColumn == null and pSelect != null and pTrigger == null and
        xferOptimization(pParse, pTab, pSelect, onError, iDb) != 0)
    {
        // goto insert_end
        if (pNested(pParse) == 0 and pPTriggerTab(pParse) == null) {
            sqlite3AutoincrementEnd(pParse);
        }
        if (regRowCount != 0) {
            sqlite3CodeChangeCount(v, regRowCount, "rows inserted");
        }
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }

    regAutoinc = autoIncBegin(pParse, iDb, pTab);

    // Allocate register block for rowid+columns.
    regRowid = pNMem(pParse) + 1;
    regIns = regRowid;
    pSetNMem(pParse, pNMem(pParse) + @as(c_int, tabNCol(pTab)) + 1);
    if (tabIsVirtual(pTab)) {
        regRowid += 1;
        pSetNMem(pParse, pNMem(pParse) + 1);
    }
    regData = regRowid + 1;

    // IDLIST processing.
    bIdListInOrder = (tabTabFlags(pTab) & (TF_OOOHidden | TF_HasStored)) == 0;
    if (pColumn != null) {
        aTabColMap = @ptrCast(@alignCast(sqlite3DbMallocZero(db, @as(u64, @intCast(tabNCol(pTab))) * @sizeOf(c_int))));
        if (aTabColMap == null) {
            insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
            return;
        }
        i = 0;
        while (i < idlNId(pColumn)) : (i += 1) {
            j = sqlite3ColumnIndex(pTab, idlZName(pColumn, @intCast(i)));
            if (j >= 0) {
                if (aTabColMap[@intCast(j)] == 0) aTabColMap[@intCast(j)] = i + 1;
                if (i != j) bIdListInOrder = false;
                if (j == tabIPKey(pTab)) {
                    ipkColumn = i;
                }
                if ((colColFlags(tabColAt(pTab, j)) & (COLFLAG_STORED | COLFLAG_VIRTUAL)) != 0) {
                    sqlite3ErrorMsg(pParse, "cannot INSERT into generated column \"%s\"", colZCnName(tabColAt(pTab, j)));
                    insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
                    return;
                }
            } else {
                if (sqlite3IsRowid(idlZName(pColumn, @intCast(i))) != 0 and !withoutRowid) {
                    ipkColumn = i;
                    bIdListInOrder = false;
                } else {
                    sqlite3ErrorMsg(pParse, "table %S has no column named %s", srcItem0(pTabList), idlZName(pColumn, @intCast(i)));
                    pSetCheckSchema(pParse);
                    insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
                    return;
                }
            }
        }
    }

    // Figure out number of data columns; build co-routine for SELECT.
    if (pSelect != null) {
        if (srcNSrc(selPSrc(pSelect)) == 1 and itemViaCoroutine(srcItem0(selPSrc(pSelect))) and selPPrior(pSelect) == null) {
            const pItem = srcItem0(selPSrc(pSelect));
            const pSubq = itemPSubq(pItem);
            destSetISDParm(pDest, subqRegReturn(pSubq));
            regFromSelect = subqRegResult(pSubq);
            nColumn = elNExpr(selPEList(subqPSelect(pSubq)));
            _ = sqlite3VdbeExplain(pParse, 0, "SCAN %S", pItem);
            if (bIdListInOrder and nColumn == tabNCol(pTab)) {
                regData = regFromSelect;
                regRowid = regData - 1;
                regIns = regRowid - (if (tabIsVirtual(pTab)) @as(c_int, 1) else 0);
            }
        } else {
            const regYield = pIncNMem(pParse);
            const addrTop = sqlite3VdbeCurrentAddr(v) + 1;
            _ = sqlite3VdbeAddOp3(v, OP_InitCoroutine, regYield, 0, addrTop);
            sqlite3SelectDestInit(pDest, SRT_Coroutine, regYield);
            destSetISdst(pDest, if (bIdListInOrder) regData else 0);
            destSetNSdst(pDest, tabNCol(pTab));
            const rc = sqlite3Select(pParse, pSelect, pDest);
            regFromSelect = destISdst(pDest);
            if (rc != 0 or pNErr(pParse) != 0) {
                insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
                return;
            }
            sqlite3VdbeEndCoroutine(v, regYield);
            sqlite3VdbeJumpHere(v, addrTop - 1); // label B
            nColumn = elNExpr(selPEList(pSelect));
        }

        if (pTrigger != null or readsTable(pParse, iDb, pTab)) {
            useTempTable = true;
        }

        if (useTempTable) {
            const regRec = sqlite3GetTempReg(pParse);
            const regTempRowid = sqlite3GetTempReg(pParse);
            srcTab = pIncNTab(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, srcTab, nColumn);
            const addrL = sqlite3VdbeAddOp1(v, OP_Yield, destISDParm(pDest));
            _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, regFromSelect, nColumn, regRec);
            _ = sqlite3VdbeAddOp2(v, OP_NewRowid, srcTab, regTempRowid);
            _ = sqlite3VdbeAddOp3(v, OP_Insert, srcTab, regRec, regTempRowid);
            _ = sqlite3VdbeGoto(v, addrL);
            sqlite3VdbeJumpHere(v, addrL);
            sqlite3ReleaseTempReg(pParse, regRec);
            sqlite3ReleaseTempReg(pParse, regTempRowid);
        }
    } else {
        // Single-row VALUES.
        var sNC: [sizeof_NameContext]u8 align(8) = @splat(0);
        wr(?*anyopaque, @ptrCast(&sNC), NameContext_pParse_off, pParse);
        srcTab = -1;
        if (pList != null) {
            nColumn = elNExpr(pList);
            if (sqlite3ResolveExprListNames(@ptrCast(&sNC), pList) != 0) {
                insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
                return;
            }
        } else {
            nColumn = 0;
        }
    }

    // ipkColumn from IPK table.
    if (pColumn == null and nColumn > 0) {
        ipkColumn = tabIPKey(pTab);
        if (ipkColumn >= 0 and (tabTabFlags(pTab) & TF_HasGenerated) != 0) {
            i = ipkColumn - 1;
            while (i >= 0) : (i -= 1) {
                if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_GENERATED) != 0) {
                    ipkColumn -= 1;
                }
            }
        }

        if ((tabTabFlags(pTab) & (TF_HasGenerated | TF_HasHidden)) != 0) {
            i = 0;
            while (i < tabNCol(pTab)) : (i += 1) {
                if ((colColFlags(tabColAt(pTab, i)) & COLFLAG_NOINSERT) != 0) nHidden += 1;
            }
        }
        if (nColumn != (@as(c_int, tabNCol(pTab)) - nHidden)) {
            sqlite3ErrorMsg(pParse, "table %S has %d columns but %d values were supplied", srcItem0(pTabList), @as(c_int, tabNCol(pTab)) - nHidden, nColumn);
            insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
            return;
        }
    }
    if (pColumn != null and nColumn != idlNId(pColumn)) {
        sqlite3ErrorMsg(pParse, "%d values for %d columns", nColumn, idlNId(pColumn));
        insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
        return;
    }

    // Row counter.
    if ((dbFlags(db) & SQLITE_CountRows) != 0 and pNested(pParse) == 0 and pPTriggerTab(pParse) == null and !pBReturning(pParse)) {
        regRowCount = pIncNMem(pParse);
        _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, regRowCount);
    }

    // Open table + indices.
    if (!isView) {
        var d: c_int = 0;
        var x: c_int = 0;
        const nIdx = sqlite3OpenTableAndIndices(pParse, pTab, OP_OpenWrite, 0, -1, null, &d, &x);
        iDataCur = d;
        iIdxCur = x;
        aRegIdx = @ptrCast(@alignCast(sqlite3DbMallocRawNN(db, @sizeOf(c_int) * @as(u64, @intCast(nIdx + 2)))));
        if (aRegIdx == null) {
            insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
            return;
        }
        i = 0;
        pIdx = tabPIndex(pTab);
        while (i < nIdx) : ({
            pIdx = idxPNext(pIdx);
            i += 1;
        }) {
            aRegIdx[@intCast(i)] = pIncNMem(pParse);
            pSetNMem(pParse, pNMem(pParse) + @as(c_int, @intCast(idxNColumn(pIdx))));
        }
        aRegIdx[@intCast(i)] = pIncNMem(pParse); // register for table record
    }

    // UPSERT prep.
    if (pUpsert != null) {
        if (tabIsVirtual(pTab)) {
            sqlite3ErrorMsg(pParse, "UPSERT not implemented for virtual table \"%s\"", tabZName(pTab));
            insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
            return;
        }
        if (tabIsView(pTab)) {
            sqlite3ErrorMsg(pParse, "cannot UPSERT a view");
            insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
            return;
        }
        if (sqlite3HasExplicitNulls(pParse, upPUpsertTarget(pUpsert)) != 0) {
            insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
            return;
        }
        itemSetICursor(srcItem0(pTabList), iDataCur);
        var pNx = pUpsert;
        while (true) {
            upSetPUpsertSrc(pNx, pTabList);
            upSetRegData(pNx, regData);
            upSetIDataCur(pNx, iDataCur);
            upSetIIdxCur(pNx, iIdxCur);
            if (upPUpsertTarget(pNx) != null) {
                if (sqlite3UpsertAnalyzeTarget(pParse, pTabList, pNx, pUpsert) != 0) {
                    insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
                    return;
                }
            }
            pNx = upPNextUpsert(pNx);
            if (pNx == null) break;
        }
    }

    // Top of the main insertion loop.
    if (useTempTable) {
        addrInsTop = sqlite3VdbeAddOp1(v, OP_Rewind, srcTab);
        addrCont = sqlite3VdbeCurrentAddr(v);
    } else if (pSelect != null) {
        sqlite3VdbeReleaseRegisters(pParse, regData, tabNCol(pTab), 0, 0);
        addrInsTop = sqlite3VdbeAddOp1(v, OP_Yield, destISDParm(pDest));
        addrCont = addrInsTop;
        if (ipkColumn >= 0) {
            _ = sqlite3VdbeAddOp2(v, OP_Copy, regFromSelect + ipkColumn, regRowid);
        }
    }

    // Compute ordinary columns into registers (storage order).
    nHidden = 0;
    iRegStore = regData; // assert regData==regRowid+1
    i = 0;
    while (i < tabNCol(pTab)) : ({
        i += 1;
        iRegStore += 1;
    }) {
        var k: c_int = undefined;
        if (i == tabIPKey(pTab)) {
            _ = sqlite3VdbeAddOp1(v, OP_SoftNull, iRegStore);
            continue;
        }
        const colFlags = colColFlags(tabColAt(pTab, i));
        if ((colFlags & COLFLAG_NOINSERT) != 0) {
            nHidden += 1;
            if ((colFlags & COLFLAG_VIRTUAL) != 0) {
                iRegStore -= 1;
                continue;
            } else if ((colFlags & COLFLAG_STORED) != 0) {
                if ((tmask & TRIGGER_BEFORE) != 0) {
                    _ = sqlite3VdbeAddOp1(v, OP_SoftNull, iRegStore);
                }
                continue;
            } else if (pColumn == null) {
                sqlite3ExprCodeFactorable(pParse, sqlite3ColumnExpr(pTab, tabColAt(pTab, i)), iRegStore);
                continue;
            }
        }
        if (pColumn != null) {
            j = aTabColMap[@intCast(i)];
            if (j == 0) {
                sqlite3ExprCodeFactorable(pParse, sqlite3ColumnExpr(pTab, tabColAt(pTab, i)), iRegStore);
                continue;
            }
            k = j - 1;
        } else if (nColumn == 0) {
            sqlite3ExprCodeFactorable(pParse, sqlite3ColumnExpr(pTab, tabColAt(pTab, i)), iRegStore);
            continue;
        } else {
            k = i - nHidden;
        }

        if (useTempTable) {
            _ = sqlite3VdbeAddOp3(v, OP_Column, srcTab, k, iRegStore);
        } else if (pSelect != null) {
            if (regFromSelect != regData) {
                _ = sqlite3VdbeAddOp2(v, OP_SCopy, regFromSelect + k, iRegStore);
            }
        } else {
            const pX = elPExpr(pList, @intCast(k));
            const y = sqlite3ExprCodeTarget(pParse, pX, iRegStore);
            if (y != iRegStore) {
                _ = sqlite3VdbeAddOp2(v, if (exprHasProperty(pX, EP_Subquery)) OP_Copy else OP_SCopy, y, iRegStore);
            }
        }
    }

    // BEFORE / INSTEAD OF triggers.
    endOfLoop = sqlite3VdbeMakeLabel(pParse);
    if ((tmask & TRIGGER_BEFORE) != 0) {
        const regCols = sqlite3GetTempRange(pParse, @as(c_int, tabNCol(pTab)) + 1);

        if (ipkColumn < 0) {
            _ = sqlite3VdbeAddOp2(v, OP_Integer, -1, regCols);
        } else {
            if (useTempTable) {
                _ = sqlite3VdbeAddOp3(v, OP_Column, srcTab, ipkColumn, regCols);
            } else {
                sqlite3ExprCode(pParse, elPExpr(pList, @intCast(ipkColumn)), regCols);
            }
            const addr1 = sqlite3VdbeAddOp1(v, OP_NotNull, regCols);
            _ = sqlite3VdbeAddOp2(v, OP_Integer, -1, regCols);
            sqlite3VdbeJumpHere(v, addr1);
            _ = sqlite3VdbeAddOp1(v, OP_MustBeInt, regCols);
        }

        _ = sqlite3VdbeAddOp3(v, OP_Copy, regRowid + 1, regCols + 1, @as(c_int, tabNNVCol(pTab)) - 1);

        if ((tabTabFlags(pTab) & TF_HasGenerated) != 0) {
            sqlite3ComputeGeneratedColumns(pParse, regCols + 1, pTab);
        }

        if (!isView) {
            sqlite3TableAffinity(v, pTab, regCols + 1);
        }

        sqlite3CodeRowTrigger(pParse, pTrigger, TK_INSERT, null, TRIGGER_BEFORE, pTab, regCols - @as(c_int, tabNCol(pTab)) - 1, onError, endOfLoop);

        sqlite3ReleaseTempRange(pParse, regCols, @as(c_int, tabNCol(pTab)) + 1);
    }

    if (!isView) {
        if (tabIsVirtual(pTab)) {
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, regIns);
        }
        if (ipkColumn >= 0) {
            if (useTempTable) {
                _ = sqlite3VdbeAddOp3(v, OP_Column, srcTab, ipkColumn, regRowid);
            } else if (pSelect != null) {
                // rowid already initialized at tag-20191021-001
            } else {
                const pIpk = elPExpr(pList, @intCast(ipkColumn));
                if (exprOp(pIpk) == TK_NULL and !tabIsVirtual(pTab)) {
                    _ = sqlite3VdbeAddOp3(v, OP_NewRowid, iDataCur, regRowid, regAutoinc);
                    appendFlag = true;
                } else {
                    sqlite3ExprCode(pParse, elPExpr(pList, @intCast(ipkColumn)), regRowid);
                }
            }
            if (!appendFlag) {
                if (!tabIsVirtual(pTab)) {
                    const addr1 = sqlite3VdbeAddOp1(v, OP_NotNull, regRowid);
                    _ = sqlite3VdbeAddOp3(v, OP_NewRowid, iDataCur, regRowid, regAutoinc);
                    sqlite3VdbeJumpHere(v, addr1);
                } else {
                    const addr1 = sqlite3VdbeCurrentAddr(v);
                    _ = sqlite3VdbeAddOp2(v, OP_IsNull, regRowid, addr1 + 2);
                }
                _ = sqlite3VdbeAddOp1(v, OP_MustBeInt, regRowid);
            }
        } else if (tabIsVirtual(pTab) or withoutRowid) {
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, regRowid);
        } else {
            _ = sqlite3VdbeAddOp3(v, OP_NewRowid, iDataCur, regRowid, regAutoinc);
            appendFlag = true;
        }
        autoIncStep(pParse, regAutoinc, regRowid);

        if ((tabTabFlags(pTab) & TF_HasGenerated) != 0) {
            sqlite3ComputeGeneratedColumns(pParse, regRowid + 1, pTab);
        }

        // Constraint checks + insertion.
        if (tabIsVirtual(pTab)) {
            const pVTab = sqlite3GetVTable(db, pTab);
            sqlite3VtabMakeWritable(pParse, pTab);
            _ = sqlite3VdbeAddOp4(v, OP_VUpdate, 1, @as(c_int, tabNCol(pTab)) + 2, regIns, @ptrCast(pVTab), P4_VTAB);
            sqlite3VdbeChangeP5(v, @intCast(if (onError == OE_Default) OE_Abort else onError));
            sqlite3MayAbort(pParse);
        } else {
            var isReplace: c_int = 0;
            sqlite3GenerateConstraintChecks(pParse, pTab, aRegIdx, iDataCur, iIdxCur, regIns, 0, if (ipkColumn >= 0) @as(u8, 1) else 0, @intCast(onError), endOfLoop, &isReplace, null, pUpsert);
            if ((dbFlags(db) & SQLITE_ForeignKeys) != 0) {
                sqlite3FkCheck(pParse, pTab, 0, regIns, null, 0);
            }
            const bUseSeek: c_int = if (isReplace == 0 or sqlite3VdbeHasSubProgram(v) == 0) 1 else 0;
            sqlite3CompleteInsertion(pParse, pTab, iDataCur, iIdxCur, regIns, aRegIdx, 0, if (appendFlag) @as(c_int, 1) else 0, bUseSeek);
        }
    }

    // Row count update.
    if (regRowCount != 0) {
        _ = sqlite3VdbeAddOp2(v, OP_AddImm, regRowCount, 1);
    }

    if (pTrigger != null) {
        sqlite3CodeRowTrigger(pParse, pTrigger, TK_INSERT, null, TRIGGER_AFTER, pTab, regData - 2 - @as(c_int, tabNCol(pTab)), onError, endOfLoop);
    }

    // Bottom of loop.
    sqlite3VdbeResolveLabel(v, endOfLoop);
    if (useTempTable) {
        _ = sqlite3VdbeAddOp2(v, OP_Next, srcTab, addrCont);
        sqlite3VdbeJumpHere(v, addrInsTop);
        _ = sqlite3VdbeAddOp1(v, OP_Close, srcTab);
    } else if (pSelect != null) {
        _ = sqlite3VdbeGoto(v, addrCont);
        if (config.sqlite_debug) {
            if (opOpcode(sqlite3VdbeGetOp(v, addrCont - 1)) == OP_ReleaseReg) {
                sqlite3VdbeChangeP5(v, 1);
            }
        }
        sqlite3VdbeJumpHere(v, addrInsTop);
    }

    // insert_end:
    if (pNested(pParse) == 0 and pPTriggerTab(pParse) == null) {
        sqlite3AutoincrementEnd(pParse);
    }
    if (regRowCount != 0) {
        sqlite3CodeChangeCount(v, regRowCount, "rows inserted");
    }

    insertCleanup(db, pTabList, pList, pUpsert, pSelect, pColumn, aTabColMap, aRegIdx);
}

fn insertCleanup(
    db: ?*anyopaque,
    pTabList: ?*anyopaque,
    pList: ?*anyopaque,
    pUpsert: ?*anyopaque,
    pSelect: ?*anyopaque,
    pColumn: ?*anyopaque,
    aTabColMap: [*c]c_int,
    aRegIdx: [*c]c_int,
) void {
    sqlite3SrcListDelete(db, pTabList);
    sqlite3ExprListDelete(db, pList);
    sqlite3UpsertDelete(db, pUpsert);
    sqlite3SelectDelete(db, pSelect);
    if (pColumn != null) {
        sqlite3IdListDelete(db, pColumn);
        sqlite3DbFree(db, @ptrCast(aTabColMap));
    }
    if (aRegIdx != null) sqlite3DbNNFreeNN(db, @ptrCast(aRegIdx));
}

// ═══════════════════════════════════════════════════════════════════════════
// checkConstraintExprNode (static) + sqlite3ExprReferencesUpdatedColumn
// ═══════════════════════════════════════════════════════════════════════════
const CKCNSTRNT_COLUMN: u32 = 0x01;
const CKCNSTRNT_ROWID: u32 = 0x02;

fn checkConstraintExprNode(pWalker: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_COLUMN) {
        if (exprIColumn(pExpr) >= 0) {
            const aiCol = wkUAiCol(pWalker);
            if (aiCol[@intCast(exprIColumn(pExpr))] >= 0) {
                wkSetECode(pWalker, wkECode(pWalker) | CKCNSTRNT_COLUMN);
            }
        } else {
            wkSetECode(pWalker, wkECode(pWalker) | CKCNSTRNT_ROWID);
        }
    }
    return WRC_Continue;
}

export fn sqlite3ExprReferencesUpdatedColumn(pExpr: ?*anyopaque, aiChng: [*c]c_int, chngRowid: c_int) callconv(.c) c_int {
    var w: [sizeof_Walker]u8 align(8) = @splat(0);
    const pW: ?*anyopaque = @ptrCast(&w);
    wkSetECode(pW, 0);
    wr(?*anyopaque, pW, Walker_xExprCallback_off, @ptrCast(@constCast(&checkConstraintExprNode)));
    wr(?*anyopaque, pW, Walker_u_off, @ptrCast(aiChng));
    _ = sqlite3WalkExpr(pW, pExpr);
    if (chngRowid == 0) {
        wkSetECode(pW, wkECode(pW) & ~CKCNSTRNT_ROWID);
    }
    return if (wkECode(pW) != 0) 1 else 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// IndexIterator (static helpers for GenerateConstraintChecks)
// ═══════════════════════════════════════════════════════════════════════════
// struct IndexIterator { int eType; int i; union { struct{Index *pIdx;} lx;
//   struct{int nIdx; IndexListTerm *aIdx;} ax; } u; }
// struct IndexListTerm { Index *p; int ix; }  (8+4 -> 16 padded)
const sizeof_IndexListTerm: usize = 16;
const IndexIterator = struct {
    eType: c_int,
    i: c_int,
    // union: when eType==0 -> pIdx; when eType==1 -> {nIdx, aIdx}
    pIdx: ?*anyopaque, // lx
    nIdx: c_int, // ax.nIdx
    aIdx: [*c]u8, // ax.aIdx (array of IndexListTerm)
};
inline fn iltAt(aIdx: [*c]u8, i: usize) [*c]u8 {
    return aIdx + i * sizeof_IndexListTerm;
}
inline fn iltP(aIdx: [*c]u8, i: usize) ?*anyopaque {
    return rd(?*anyopaque, @ptrCast(iltAt(aIdx, i)), 0);
}
inline fn iltSetP(aIdx: [*c]u8, i: usize, v: ?*anyopaque) void {
    wr(?*anyopaque, @ptrCast(iltAt(aIdx, i)), 0, v);
}
inline fn iltIx(aIdx: [*c]u8, i: usize) c_int {
    return rd(c_int, @ptrCast(iltAt(aIdx, i)), 8);
}
inline fn iltSetIx(aIdx: [*c]u8, i: usize, v: c_int) void {
    wr(c_int, @ptrCast(iltAt(aIdx, i)), 8, v);
}

fn indexIteratorFirst(pIter: *IndexIterator, pIx: *c_int) ?*anyopaque {
    if (pIter.eType != 0) {
        pIx.* = iltIx(pIter.aIdx, 0);
        return iltP(pIter.aIdx, 0);
    } else {
        pIx.* = 0;
        return pIter.pIdx;
    }
}
fn indexIteratorNext(pIter: *IndexIterator, pIx: *c_int) ?*anyopaque {
    if (pIter.eType != 0) {
        pIter.i += 1;
        const i = pIter.i;
        if (i >= pIter.nIdx) {
            pIx.* = i;
            return null;
        }
        pIx.* = iltIx(pIter.aIdx, @intCast(i));
        return iltP(pIter.aIdx, @intCast(i));
    } else {
        pIx.* += 1;
        pIter.pIdx = idxPNext(pIter.pIdx);
        return pIter.pIdx;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3GenerateConstraintChecks
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3GenerateConstraintChecks(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    aRegIdx: [*c]c_int,
    iDataCur: c_int,
    iIdxCur: c_int,
    regNewData: c_int,
    regOldData: c_int,
    pkChng: u8,
    overrideError_in: u8,
    ignoreDest: c_int,
    pbMayReplace: *c_int,
    aiChng: [*c]c_int,
    pUpsert_in: ?*anyopaque,
) callconv(.c) void {
    var overrideError: c_int = overrideError_in;
    var pUpsert = pUpsert_in;
    var pIdx: ?*anyopaque = undefined;
    var pPk: ?*anyopaque = null;
    var i: c_int = undefined;
    var ix: c_int = undefined;
    const nCol: c_int = tabNCol(pTab);
    var onError: c_int = undefined;
    var seenReplace: c_int = 0;
    var nPkField: c_int = undefined;
    var pUpsertClause: ?*anyopaque = null;
    const isUpdate: bool = regOldData != 0;
    var bAffinityDone: bool = false;
    var upsertIpkReturn: c_int = 0;
    var upsertIpkDelay: c_int = 0;
    var ipkTop: c_int = 0;
    var ipkBottom: c_int = 0;
    var regTrigCnt: c_int = undefined;
    var addrRecheck: c_int = 0;
    var lblRecheckOk: c_int = 0;
    var pTrigger: ?*anyopaque = undefined;
    var nReplaceTrig: c_int = 0;
    var sIdxIter: IndexIterator = undefined;

    const db = pDb(pParse);
    const v = pVdbe(pParse);

    if (tabHasRowid(pTab)) {
        pPk = null;
        nPkField = 1;
    } else {
        pPk = sqlite3PrimaryKeyIndex(pTab);
        nPkField = @intCast(idxNKeyCol(pPk));
    }

    // VdbeModuleComment is a no-op unless SQLITE_ENABLE_MODULE_COMMENTS (off in
    // both configs) — so "BEGIN/END: GenCnstCks" emit nothing.

    // NOT NULL constraints.
    if ((tabTabFlags(pTab) & TF_HasNotNull) != 0) {
        var b2ndPass: bool = false;
        var nSeenReplace: c_int = 0;
        var nGenerated: c_int = 0;
        while (true) {
            i = 0;
            while (i < nCol) : (i += 1) {
                const pCol = tabColAt(pTab, i);
                onError = colNotNull(pCol);
                if (onError == OE_None) continue;
                if (i == tabIPKey(pTab)) continue;
                const isGenerated: bool = (colColFlags(pCol) & COLFLAG_GENERATED) != 0;
                if (isGenerated and !b2ndPass) {
                    nGenerated += 1;
                    continue;
                }
                if (aiChng != null and aiChng[@intCast(i)] < 0 and !isGenerated) {
                    continue;
                }
                if (overrideError != OE_Default) {
                    onError = overrideError;
                } else if (onError == OE_Default) {
                    onError = OE_Abort;
                }
                if (onError == OE_Replace) {
                    if (b2ndPass or colIDflt(pCol) == 0) {
                        onError = OE_Abort;
                    }
                } else if (b2ndPass and !isGenerated) {
                    continue;
                }
                const iReg = sqlite3TableColumnToStorage(pTab, @intCast(i)) + @as(i16, @intCast(regNewData)) + 1;
                switch (onError) {
                    OE_Replace => {
                        const addr1 = sqlite3VdbeAddOp1(v, OP_NotNull, iReg);
                        nSeenReplace += 1;
                        sqlite3ExprCodeCopy(pParse, sqlite3ColumnExpr(pTab, pCol), iReg);
                        sqlite3VdbeJumpHere(v, addr1);
                    },
                    OE_Abort, OE_Rollback, OE_Fail => {
                        if (onError == OE_Abort) sqlite3MayAbort(pParse);
                        const zMsg = sqlite3MPrintf(db, "%s.%s", tabZName(pTab), colZCnName(pCol));
                        _ = sqlite3VdbeAddOp3(v, OP_HaltIfNull, SQLITE_CONSTRAINT_NOTNULL, onError, iReg);
                        sqlite3VdbeAppendP4(v, @ptrCast(zMsg), P4_DYNAMIC);
                        sqlite3VdbeChangeP5(v, P5_ConstraintNotNull);
                    },
                    else => {
                        // OE_Ignore
                        _ = sqlite3VdbeAddOp2(v, OP_IsNull, iReg, ignoreDest);
                    },
                }
            }
            if (nGenerated == 0 and nSeenReplace == 0) break;
            if (b2ndPass) break;
            b2ndPass = true;
            if (nSeenReplace > 0 and (tabTabFlags(pTab) & TF_HasGenerated) != 0) {
                sqlite3ComputeGeneratedColumns(pParse, regNewData + 1, pTab);
            }
        }
    }

    // CHECK constraints.
    if (tabPCheck(pTab) != null and (dbFlags(db) & SQLITE_IgnoreChecks) == 0) {
        const pCheck = tabPCheck(pTab);
        pSetISelfTab(pParse, -(regNewData + 1));
        onError = if (overrideError != OE_Default) overrideError else OE_Abort;
        i = 0;
        while (i < elNExpr(pCheck)) : (i += 1) {
            const pExpr = elPExpr(pCheck, @intCast(i));
            if (aiChng != null and sqlite3ExprReferencesUpdatedColumn(pExpr, aiChng, pkChng) == 0) {
                continue;
            }
            if (!bAffinityDone) {
                sqlite3TableAffinity(v, pTab, regNewData + 1);
                bAffinityDone = true;
            }
            const allOk = sqlite3VdbeMakeLabel(pParse);
            sqlite3VdbeVerifyAbortable(v, onError);
            const pCopy = sqlite3ExprDup(db, pExpr, 0);
            if (!dbMallocFailed(db)) {
                sqlite3ExprIfTrue(pParse, pCopy, allOk, SQLITE_JUMPIFNULL);
            }
            sqlite3ExprDelete(db, pCopy);
            if (onError == OE_Ignore) {
                _ = sqlite3VdbeGoto(v, ignoreDest);
            } else {
                const zName = elZEName(pCheck, @intCast(i));
                if (onError == OE_Replace) onError = OE_Abort;
                sqlite3HaltConstraint(pParse, SQLITE_CONSTRAINT_CHECK, onError, @ptrCast(zName), P4_TRANSIENT, P5_ConstraintCheck);
            }
            sqlite3VdbeResolveLabel(v, allOk);
        }
        pSetISelfTab(pParse, 0);
    }

    // Index iterator setup.
    sIdxIter.eType = 0;
    sIdxIter.i = 0;
    sIdxIter.aIdx = null;
    sIdxIter.nIdx = 0;
    sIdxIter.pIdx = tabPIndex(pTab);
    if (pUpsert != null) {
        if (upPUpsertTarget(pUpsert) == null) {
            if (upIsDoUpdate(pUpsert) == 0) {
                overrideError = OE_Ignore;
                pUpsert = null;
            } else {
                overrideError = OE_Update;
            }
        } else if (tabPIndex(pTab) != null) {
            var nIdx: c_int = 0;
            var jj: c_int = undefined;
            pIdx = tabPIndex(pTab);
            while (pIdx != null) : ({
                pIdx = idxPNext(pIdx);
                nIdx += 1;
            }) {}
            sIdxIter.eType = 1;
            sIdxIter.nIdx = nIdx;
            const nByte: u64 = (sizeof_IndexListTerm + 1) * @as(u64, @intCast(nIdx)) + @as(u64, @intCast(nIdx));
            sIdxIter.aIdx = @ptrCast(@alignCast(sqlite3DbMallocZero(db, nByte)));
            if (sIdxIter.aIdx == null) return;
            const bUsed: [*]u8 = @ptrCast(iltAt(sIdxIter.aIdx, @intCast(nIdx)));
            upSetPToFree(pUpsert, @ptrCast(sIdxIter.aIdx));
            i = 0;
            var pTerm = pUpsert;
            while (pTerm != null) : (pTerm = upPNextUpsert(pTerm)) {
                if (upPUpsertTarget(pTerm) == null) break;
                if (upPUpsertIdx(pTerm) == null) continue;
                jj = 0;
                pIdx = tabPIndex(pTab);
                while (pIdx != null and pIdx != upPUpsertIdx(pTerm)) {
                    pIdx = idxPNext(pIdx);
                    jj += 1;
                }
                if (bUsed[@intCast(jj)] != 0) continue;
                bUsed[@intCast(jj)] = 1;
                iltSetP(sIdxIter.aIdx, @intCast(i), pIdx);
                iltSetIx(sIdxIter.aIdx, @intCast(i), jj);
                i += 1;
            }
            jj = 0;
            pIdx = tabPIndex(pTab);
            while (pIdx != null) : ({
                pIdx = idxPNext(pIdx);
                jj += 1;
            }) {
                if (bUsed[@intCast(jj)] != 0) continue;
                iltSetP(sIdxIter.aIdx, @intCast(i), pIdx);
                iltSetIx(sIdxIter.aIdx, @intCast(i), jj);
                i += 1;
            }
        }
    }

    // Replace-trigger detection.
    if ((dbFlags(db) & (SQLITE_RecTriggers | SQLITE_ForeignKeys)) == 0) {
        pTrigger = null;
        regTrigCnt = 0;
    } else {
        if ((dbFlags(db) & SQLITE_RecTriggers) != 0) {
            pTrigger = sqlite3TriggersExist(pParse, pTab, TK_DELETE, null, null);
            regTrigCnt = if (pTrigger != null or sqlite3FkRequired(pParse, pTab, null, 0) != 0) 1 else 0;
        } else {
            pTrigger = null;
            regTrigCnt = sqlite3FkRequired(pParse, pTab, null, 0);
        }
        if (regTrigCnt != 0) {
            regTrigCnt = pIncNMem(pParse);
            _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, regTrigCnt);
            sqlite3VdbeComment(v, "trigger count");
            lblRecheckOk = sqlite3VdbeMakeLabel(pParse);
            addrRecheck = lblRecheckOk;
        }
    }

    // Rowid uniqueness (rowid changing).
    if (pkChng != 0 and pPk == null) {
        const addrRowidOk = sqlite3VdbeMakeLabel(pParse);

        onError = tabKeyConf(pTab);
        if (overrideError != OE_Default) {
            onError = overrideError;
        } else if (onError == OE_Default) {
            onError = OE_Abort;
        }

        if (pUpsert != null) {
            pUpsertClause = sqlite3UpsertOfIndex(pUpsert, null);
            if (pUpsertClause != null) {
                if (upIsDoUpdate(pUpsertClause) == 0) {
                    onError = OE_Ignore;
                } else {
                    onError = OE_Update;
                }
            }
            if (pUpsertClause != pUpsert) {
                upsertIpkDelay = sqlite3VdbeAddOp0(v, OP_Goto);
            }
        }

        if (onError == OE_Replace and onError != overrideError and tabPIndex(pTab) != null and upsertIpkDelay == 0) {
            ipkTop = sqlite3VdbeAddOp0(v, OP_Goto) + 1;
            sqlite3VdbeComment(v, "defer IPK REPLACE until last");
        }

        if (isUpdate) {
            _ = sqlite3VdbeAddOp3(v, OP_Eq, regNewData, addrRowidOk, regOldData);
            sqlite3VdbeChangeP5(v, SQLITE_NOTNULL);
        }

        sqlite3VdbeNoopComment(v, "uniqueness check for ROWID");
        sqlite3VdbeVerifyAbortable(v, onError);
        _ = sqlite3VdbeAddOp3(v, OP_NotExists, iDataCur, addrRowidOk, regNewData);

        switch (onError) {
            OE_Rollback, OE_Abort, OE_Fail => {
                sqlite3RowidConstraint(pParse, onError, pTab);
            },
            OE_Replace => {
                if (regTrigCnt != 0) {
                    sqlite3MultiWrite(pParse);
                    sqlite3GenerateRowDelete(pParse, pTab, pTrigger, iDataCur, iIdxCur, regNewData, 1, 0, OE_Replace, 1, -1);
                    _ = sqlite3VdbeAddOp2(v, OP_AddImm, regTrigCnt, 1);
                    nReplaceTrig += 1;
                } else {
                    // SQLITE_ENABLE_PREUPDATE_HOOK ON
                    // assert HasRowid(pTab)
                    _ = sqlite3VdbeAddOp2(v, OP_Delete, iDataCur, OPFLAG_ISNOOP);
                    sqlite3VdbeAppendP4(v, pTab, P4_TABLE);
                    if (tabPIndex(pTab) != null) {
                        sqlite3MultiWrite(pParse);
                        sqlite3GenerateRowIndexDelete(pParse, pTab, iDataCur, iIdxCur, null, -1);
                    }
                }
                seenReplace = 1;
            },
            OE_Update => {
                sqlite3UpsertDoUpdate(pParse, pUpsert, pTab, null, iDataCur);
                _ = sqlite3VdbeGoto(v, ignoreDest);
            },
            OE_Ignore => {
                _ = sqlite3VdbeGoto(v, ignoreDest);
            },
            else => {
                onError = OE_Abort;
                sqlite3RowidConstraint(pParse, onError, pTab);
            },
        }
        sqlite3VdbeResolveLabel(v, addrRowidOk);
        if (pUpsert != null and pUpsertClause != pUpsert) {
            upsertIpkReturn = sqlite3VdbeAddOp0(v, OP_Goto);
        } else if (ipkTop != 0) {
            ipkBottom = sqlite3VdbeAddOp0(v, OP_Goto);
            sqlite3VdbeJumpHere(v, ipkTop - 1);
        }
    }

    // UNIQUE / PRIMARY KEY constraints.
    pIdx = indexIteratorFirst(&sIdxIter, &ix);
    while (pIdx != null) : (pIdx = indexIteratorNext(&sIdxIter, &ix)) {
        var regIdx: c_int = undefined;
        var regR: c_int = undefined;
        var iThisCur: c_int = undefined;
        var addrUniqueOk: c_int = undefined;
        var addrConflictCk: c_int = undefined;

        if (aRegIdx[@intCast(ix)] == 0) continue;
        if (pUpsert != null) {
            pUpsertClause = sqlite3UpsertOfIndex(pUpsert, pIdx);
            if (upsertIpkDelay != 0 and pUpsertClause == pUpsert) {
                sqlite3VdbeJumpHere(v, upsertIpkDelay);
            }
        }
        addrUniqueOk = sqlite3VdbeMakeLabel(pParse);
        if (!bAffinityDone) {
            sqlite3TableAffinity(v, pTab, regNewData + 1);
            bAffinityDone = true;
        }
        sqlite3VdbeNoopComment(v, "prep index %s", idxZName(pIdx));
        iThisCur = iIdxCur + ix;

        // Partial indices.
        if (idxPPartIdxWhere(pIdx) != null) {
            _ = sqlite3VdbeAddOp2(v, OP_Null, 0, aRegIdx[@intCast(ix)]);
            pSetISelfTab(pParse, -(regNewData + 1));
            sqlite3ExprIfFalseDup(pParse, idxPPartIdxWhere(pIdx), addrUniqueOk, SQLITE_JUMPIFNULL);
            pSetISelfTab(pParse, 0);
        }

        // Build index record.
        regIdx = aRegIdx[@intCast(ix)] + 1;
        i = 0;
        while (i < @as(c_int, @intCast(idxNColumn(pIdx)))) : (i += 1) {
            const iField = idxAiColumn(pIdx, @intCast(i));
            if (iField == XN_EXPR) {
                pSetISelfTab(pParse, -(regNewData + 1));
                sqlite3ExprCodeCopy(pParse, idxColExprAt(pIdx, @intCast(i)), regIdx + i);
                pSetISelfTab(pParse, 0);
                sqlite3VdbeComment(v, "%s column %d", idxZName(pIdx), i);
            } else if (iField == XN_ROWID or iField == tabIPKey(pTab)) {
                _ = sqlite3VdbeAddOp2(v, OP_IntCopy, regNewData, regIdx + i);
                sqlite3VdbeComment(v, "rowid");
            } else {
                const x = sqlite3TableColumnToStorage(pTab, iField) + @as(i16, @intCast(regNewData)) + 1;
                _ = sqlite3VdbeAddOp2(v, OP_SCopy, x, regIdx + i);
                sqlite3VdbeComment(v, "%s", colZCnName(tabColAt(pTab, iField)));
            }
        }
        _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, regIdx, @intCast(idxNColumn(pIdx)), aRegIdx[@intCast(ix)]);
        sqlite3VdbeComment(v, "for %s", idxZName(pIdx));
        sqlite3VdbeReleaseRegisters(pParse, regIdx, @intCast(idxNColumn(pIdx)), 0, 0);

        // WITHOUT ROWID PK with no PK change → skip.
        if (isUpdate and pPk == pIdx and pkChng == 0) {
            sqlite3VdbeResolveLabel(v, addrUniqueOk);
            continue;
        }

        onError = idxOnError(pIdx);
        if (onError == OE_None) {
            sqlite3VdbeResolveLabel(v, addrUniqueOk);
            continue;
        }
        if (overrideError != OE_Default) {
            onError = overrideError;
        } else if (onError == OE_Default) {
            onError = OE_Abort;
        }

        if (pUpsertClause != null) {
            if (upIsDoUpdate(pUpsertClause) == 0) {
                onError = OE_Ignore;
            } else {
                onError = OE_Update;
            }
        }

        // (PREUPDATE_HOOK ON → the collision-omission shortcut is compiled out.)

        sqlite3VdbeVerifyAbortable(v, onError);
        addrConflictCk = sqlite3VdbeAddOp4Int(v, OP_NoConflict, iThisCur, addrUniqueOk, regIdx, @intCast(idxNKeyCol(pIdx)));

        regR = if (pIdx == pPk) regIdx else sqlite3GetTempRange(pParse, nPkField);
        if (isUpdate or onError == OE_Replace) {
            if (tabHasRowid(pTab)) {
                _ = sqlite3VdbeAddOp2(v, OP_IdxRowid, iThisCur, regR);
                if (isUpdate) {
                    _ = sqlite3VdbeAddOp3(v, OP_Eq, regR, addrUniqueOk, regOldData);
                    sqlite3VdbeChangeP5(v, SQLITE_NOTNULL);
                }
            } else {
                if (pIdx != pPk) {
                    var ii: c_int = 0;
                    while (ii < @as(c_int, @intCast(idxNKeyCol(pPk)))) : (ii += 1) {
                        const xCol = sqlite3TableColumnToIndex(pIdx, idxAiColumn(pPk, @intCast(ii)));
                        _ = sqlite3VdbeAddOp3(v, OP_Column, iThisCur, xCol, regR + ii);
                        sqlite3VdbeComment(v, "%s.%s", tabZName(pTab), colZCnName(tabColAt(pTab, idxAiColumn(pPk, @intCast(ii)))));
                    }
                }
                if (isUpdate) {
                    var addrJump = sqlite3VdbeCurrentAddr(v) + @as(c_int, @intCast(idxNKeyCol(pPk)));
                    var op: c_int = OP_Ne;
                    const regCmp = if (idxIsPrimaryKey(pIdx)) regIdx else regR;
                    var ii: c_int = 0;
                    while (ii < @as(c_int, @intCast(idxNKeyCol(pPk)))) : (ii += 1) {
                        const p4 = sqlite3LocateCollSeq(pParse, idxAColl(pPk, @intCast(ii)));
                        var xCol = idxAiColumn(pPk, @intCast(ii));
                        if (ii == @as(c_int, @intCast(idxNKeyCol(pPk))) - 1) {
                            addrJump = addrUniqueOk;
                            op = OP_Eq;
                        }
                        xCol = sqlite3TableColumnToStorage(pTab, xCol);
                        _ = sqlite3VdbeAddOp4(v, op, regOldData + 1 + xCol, addrJump, regCmp + ii, @ptrCast(p4), P4_COLLSEQ);
                        sqlite3VdbeChangeP5(v, SQLITE_NOTNULL);
                    }
                }
            }
        }

        switch (onError) {
            OE_Rollback, OE_Abort, OE_Fail => {
                sqlite3UniqueConstraint(pParse, onError, pIdx);
            },
            OE_Update => {
                sqlite3UpsertDoUpdate(pParse, pUpsert, pTab, pIdx, iIdxCur + ix);
                _ = sqlite3VdbeGoto(v, ignoreDest);
            },
            OE_Ignore => {
                _ = sqlite3VdbeGoto(v, ignoreDest);
            },
            else => {
                // OE_Replace
                var nConflictCk = sqlite3VdbeCurrentAddr(v) - addrConflictCk;
                if (regTrigCnt != 0) {
                    sqlite3MultiWrite(pParse);
                    nReplaceTrig += 1;
                }
                if (pTrigger != null and isUpdate) {
                    _ = sqlite3VdbeAddOp1(v, OP_CursorLock, iDataCur);
                }
                sqlite3GenerateRowDelete(pParse, pTab, pTrigger, iDataCur, iIdxCur, regR, @intCast(nPkField), 0, OE_Replace, if (pIdx == pPk) @as(u8, ONEPASS_SINGLE) else @as(u8, ONEPASS_OFF), iThisCur);
                if (pTrigger != null and isUpdate) {
                    _ = sqlite3VdbeAddOp1(v, OP_CursorUnlock, iDataCur);
                }
                if (regTrigCnt != 0) {
                    _ = sqlite3VdbeAddOp2(v, OP_AddImm, regTrigCnt, 1);
                    const addrBypass = sqlite3VdbeAddOp0(v, OP_Goto);
                    sqlite3VdbeComment(v, "bypass recheck");

                    sqlite3VdbeResolveLabel(v, lblRecheckOk);
                    lblRecheckOk = sqlite3VdbeMakeLabel(pParse);
                    if (idxPPartIdxWhere(pIdx) != null) {
                        _ = sqlite3VdbeAddOp2(v, OP_IsNull, regIdx - 1, lblRecheckOk);
                    }
                    while (nConflictCk > 0) {
                        // make a complete copy of the opcode (array may realloc)
                        const srcOp = sqlite3VdbeGetOp(v, addrConflictCk);
                        const xop = opOpcode(srcOp);
                        if (xop != OP_IdxRowid) {
                            const xp1 = opP1(srcOp);
                            const xp2 = opP2(srcOp);
                            const xp3 = opP3(srcOp);
                            const xp4type = opP4type(srcOp);
                            const xp5 = opP5(srcOp);
                            var p2: c_int = undefined;
                            if ((opcodeProp(xop) & OPFLG_JUMP) != 0) {
                                p2 = lblRecheckOk;
                            } else {
                                p2 = xp2;
                            }
                            const zP4: ?[*]const u8 = if (xp4type == P4_INT32) @ptrFromInt(@as(usize, @bitCast(@as(isize, opP4i(srcOp))))) else opP4z(srcOp);
                            _ = sqlite3VdbeAddOp4(v, xop, xp1, p2, xp3, zP4, xp4type);
                            sqlite3VdbeChangeP5(v, xp5);
                        }
                        nConflictCk -= 1;
                        addrConflictCk += 1;
                    }
                    sqlite3UniqueConstraint(pParse, OE_Abort, pIdx);
                    sqlite3VdbeJumpHere(v, addrBypass);
                }
                seenReplace = 1;
            },
        }
        sqlite3VdbeResolveLabel(v, addrUniqueOk);
        if (regR != regIdx) sqlite3ReleaseTempRange(pParse, regR, nPkField);
        if (pUpsertClause != null and upsertIpkReturn != 0 and sqlite3UpsertNextIsIPK(pUpsertClause) != 0) {
            _ = sqlite3VdbeGoto(v, upsertIpkDelay + 1);
            sqlite3VdbeJumpHere(v, upsertIpkReturn);
            upsertIpkReturn = 0;
        }
    }

    if (ipkTop != 0) {
        _ = sqlite3VdbeGoto(v, ipkTop);
        sqlite3VdbeComment(v, "Do IPK REPLACE");
        sqlite3VdbeJumpHere(v, ipkBottom);
    }

    // Recheck after replace triggers.
    if (nReplaceTrig != 0) {
        _ = sqlite3VdbeAddOp2(v, OP_IfNot, regTrigCnt, lblRecheckOk);
        if (pPk == null) {
            if (isUpdate) {
                _ = sqlite3VdbeAddOp3(v, OP_Eq, regNewData, addrRecheck, regOldData);
                sqlite3VdbeChangeP5(v, SQLITE_NOTNULL);
            }
            _ = sqlite3VdbeAddOp3(v, OP_NotExists, iDataCur, addrRecheck, regNewData);
            sqlite3RowidConstraint(pParse, OE_Abort, pTab);
        } else {
            _ = sqlite3VdbeGoto(v, addrRecheck);
        }
        sqlite3VdbeResolveLabel(v, lblRecheckOk);
    }

    // Generate the table record.
    if (tabHasRowid(pTab)) {
        const regRec = aRegIdx[@intCast(ix)];
        _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, regNewData + 1, tabNNVCol(pTab), regRec);
        if (!bAffinityDone) {
            sqlite3TableAffinity(v, pTab, 0);
        }
    }

    pbMayReplace.* = seenReplace;
    // VdbeModuleComment "END: GenCnstCks" → no-op (SQLITE_ENABLE_MODULE_COMMENTS off).
}

// ═══════════════════════════════════════════════════════════════════════════
// codeWithoutRowidPreupdate (static) — SQLITE_ENABLE_PREUPDATE_HOOK ON
// ═══════════════════════════════════════════════════════════════════════════
fn codeWithoutRowidPreupdate(pParse: ?*anyopaque, pTab: ?*anyopaque, iCur: c_int, regData: c_int) void {
    const v = pVdbe(pParse);
    const r = sqlite3GetTempReg(pParse);
    _ = sqlite3VdbeAddOp2(v, OP_Integer, 0, r);
    _ = sqlite3VdbeAddOp4(v, OP_Insert, iCur, regData, r, @ptrCast(pTab), P4_TABLE);
    sqlite3VdbeChangeP5(v, OPFLAG_ISNOOP);
    sqlite3ReleaseTempReg(pParse, r);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3CompleteInsertion
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3CompleteInsertion(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    iDataCur: c_int,
    iIdxCur: c_int,
    regNewData: c_int,
    aRegIdx: [*c]c_int,
    update_flags: c_int,
    appendBias: c_int,
    useSeekResult: c_int,
) callconv(.c) void {
    const v = pVdbe(pParse);
    var pIdx: ?*anyopaque = undefined;
    var pik_flags: u16 = undefined;
    var i: c_int = 0;

    pIdx = tabPIndex(pTab);
    while (pIdx != null) : ({
        pIdx = idxPNext(pIdx);
        i += 1;
    }) {
        if (aRegIdx[@intCast(i)] == 0) continue;
        if (idxPPartIdxWhere(pIdx) != null or (update_flags != 0 and idxBHasExpr(pIdx))) {
            _ = sqlite3VdbeAddOp2(v, OP_IsNull, aRegIdx[@intCast(i)], sqlite3VdbeCurrentAddr(v) + 2);
        }
        pik_flags = if (useSeekResult != 0) OPFLAG_USESEEKRESULT else 0;
        if (idxIsPrimaryKey(pIdx) and !tabHasRowid(pTab)) {
            pik_flags |= OPFLAG_NCHANGE;
            pik_flags |= (@as(u16, @intCast(update_flags)) & OPFLAG_SAVEPOSITION);
            if (update_flags == 0) {
                codeWithoutRowidPreupdate(pParse, pTab, iIdxCur + i, aRegIdx[@intCast(i)]);
            }
        }
        _ = sqlite3VdbeAddOp4Int(v, OP_IdxInsert, iIdxCur + i, aRegIdx[@intCast(i)], aRegIdx[@intCast(i)] + 1, if (idxUniqNotNull(pIdx)) @as(c_int, @intCast(idxNKeyCol(pIdx))) else @as(c_int, @intCast(idxNColumn(pIdx))));
        sqlite3VdbeChangeP5(v, pik_flags);
    }
    if (!tabHasRowid(pTab)) return;
    if (pNested(pParse) != 0) {
        pik_flags = 0;
    } else {
        pik_flags = OPFLAG_NCHANGE;
        pik_flags |= if (update_flags != 0) @as(u16, @intCast(update_flags)) else OPFLAG_LASTROWID;
    }
    if (appendBias != 0) pik_flags |= OPFLAG_APPEND;
    if (useSeekResult != 0) pik_flags |= OPFLAG_USESEEKRESULT;
    _ = sqlite3VdbeAddOp3(v, OP_Insert, iDataCur, aRegIdx[@intCast(i)], regNewData);
    if (pNested(pParse) == 0) {
        sqlite3VdbeAppendP4(v, pTab, P4_TABLE);
    }
    sqlite3VdbeChangeP5(v, pik_flags);
}

// ═══════════════════════════════════════════════════════════════════════════
// sqlite3OpenTableAndIndices
// ═══════════════════════════════════════════════════════════════════════════
export fn sqlite3OpenTableAndIndices(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    op: c_int,
    p5_in: u8,
    iBase_in: c_int,
    aToOpen: [*c]u8,
    piDataCur: *c_int,
    piIdxCur: *c_int,
) callconv(.c) c_int {
    var p5 = p5_in;
    var iBase = iBase_in;
    var i: c_int = undefined;
    var iDb: c_int = undefined;
    var iDataCur: c_int = undefined;
    var pIdx: ?*anyopaque = undefined;
    var v: ?*anyopaque = undefined;

    if (tabIsVirtual(pTab)) {
        piDataCur.* = -999;
        piIdxCur.* = -999;
        return 0;
    }
    iDb = sqlite3SchemaToIndex(pDb(pParse), tabPSchema(pTab));
    v = pVdbe(pParse);
    if (iBase < 0) iBase = pNTab(pParse);
    iDataCur = iBase;
    iBase += 1;
    piDataCur.* = iDataCur;
    if (tabHasRowid(pTab) and (aToOpen == null or aToOpen[0] != 0)) {
        sqlite3OpenTable(pParse, iDataCur, iDb, pTab, op);
    } else if (!dbNoSharedCache(pDb(pParse))) {
        sqlite3TableLock(pParse, iDb, tabTnum(pTab), if (op == OP_OpenWrite) @as(u8, 1) else 0, tabZName(pTab));
    }
    piIdxCur.* = iBase;
    i = 0;
    pIdx = tabPIndex(pTab);
    while (pIdx != null) : ({
        pIdx = idxPNext(pIdx);
        i += 1;
    }) {
        const iIdxCur = iBase;
        iBase += 1;
        if (idxIsPrimaryKey(pIdx) and !tabHasRowid(pTab)) {
            piDataCur.* = iIdxCur;
            p5 = 0;
        }
        if (aToOpen == null or aToOpen[@intCast(i + 1)] != 0) {
            _ = sqlite3VdbeAddOp3(v, op, iIdxCur, @intCast(idxTnum(pIdx)), iDb);
            sqlite3VdbeSetP4KeyInfo(pParse, pIdx);
            sqlite3VdbeChangeP5(v, p5);
            sqlite3VdbeComment(v, "%s", idxZName(pIdx));
        }
    }
    if (iBase > pNTab(pParse)) pSetNTab(pParse, iBase);
    return i;
}

// ═══════════════════════════════════════════════════════════════════════════
// SQLITE_TEST: sqlite3_xferopt_count
// ═══════════════════════════════════════════════════════════════════════════
var xferopt_count: c_int = 0;
comptime {
    if (config.sqlite_test) {
        @export(&xferopt_count, .{ .name = "sqlite3_xferopt_count", .linkage = .strong });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// xferCompatibleIndex / xferCheckRowid / xferCompatibleCheck (static)
// ═══════════════════════════════════════════════════════════════════════════
fn xferCompatibleIndex(pDest: ?*anyopaque, pSrc: ?*anyopaque) bool {
    if (idxNKeyCol(pDest) != idxNKeyCol(pSrc) or idxNColumn(pDest) != idxNColumn(pSrc)) return false;
    if (idxOnError(pDest) != idxOnError(pSrc)) return false;
    var i: usize = 0;
    const nk: usize = @intCast(idxNKeyCol(pSrc));
    while (i < nk) : (i += 1) {
        if (idxAiColumn(pSrc, i) != idxAiColumn(pDest, i)) return false;
        if (idxAiColumn(pSrc, i) == XN_EXPR) {
            if (sqlite3ExprCompare(null, idxColExprAt(pSrc, i), idxColExprAt(pDest, i), -1) != 0) return false;
        }
        if (idxASortOrder(pSrc, i) != idxASortOrder(pDest, i)) return false;
        if (sqlite3_stricmp(idxAColl(pSrc, i), idxAColl(pDest, i)) != 0) return false;
    }
    if (sqlite3ExprCompare(null, idxPPartIdxWhere(pSrc), idxPPartIdxWhere(pDest), -1) != 0) return false;
    return true;
}

fn xferCheckRowid(pWalk: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    if (exprOp(pExpr) == TK_COLUMN and exprIColumn(pExpr) < 0) {
        wkSetECode(pWalk, 1);
        return WRC_Abort;
    }
    return WRC_Continue;
}

fn xferCompatibleCheck(pDest: ?*anyopaque, pSrc: ?*anyopaque) bool {
    if (sqlite3ExprListCompare(tabPCheck(pSrc), tabPCheck(pDest), -1) != 0) return false;
    if (tabIPKey(pDest) < 0) {
        var w: [sizeof_Walker]u8 align(8) = @splat(0);
        const pW: ?*anyopaque = @ptrCast(&w);
        wr(?*anyopaque, pW, Walker_xExprCallback_off, @ptrCast(@constCast(&xferCheckRowid)));
        _ = sqlite3WalkExprList(pW, tabPCheck(pDest));
        if (wkECode(pW) != 0) return false;
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// xferOptimization (static)
// ═══════════════════════════════════════════════════════════════════════════
fn xferOptimization(pParse: ?*anyopaque, pDest: ?*anyopaque, pSelect: ?*anyopaque, onError_in: c_int, iDbDest: c_int) c_int {
    var onError = onError_in;
    const db = pDb(pParse);
    var pSrcIdx: ?*anyopaque = undefined;
    var pDestIdx: ?*anyopaque = undefined;
    var i: c_int = undefined;
    var iDbSrc: c_int = undefined;
    var iSrc: c_int = undefined;
    var iDest: c_int = undefined;
    var addr1: c_int = undefined;
    var addr2: c_int = undefined;
    var emptyDestTest: c_int = 0;
    var emptySrcTest: c_int = 0;
    var v: ?*anyopaque = undefined;
    var regAutoinc: c_int = undefined;
    var destHasUniqueIdx: bool = false;
    var regData: c_int = undefined;
    var regRowid: c_int = undefined;

    if (selPWith(pSelect) != null or rd(?*anyopaque, pParse, off("Parse_pWith", 400)) != null) {
        return 0;
    }
    if (tabIsVirtual(pDest)) return 0;
    if (onError == OE_Default) {
        if (tabIPKey(pDest) >= 0) onError = tabKeyConf(pDest);
        if (onError == OE_Default) onError = OE_Abort;
    }
    if (srcNSrc(selPSrc(pSelect)) != 1) return 0;
    if (itemIsSubquery(srcItem0(selPSrc(pSelect)))) return 0;
    if (selPWhere(pSelect) != null) return 0;
    if (selPOrderBy(pSelect) != null) return 0;
    if (selPGroupBy(pSelect) != null) return 0;
    if (selPLimit(pSelect) != null) return 0;
    if (selPPrior(pSelect) != null) return 0;
    if ((selSelFlags(pSelect) & SF_Distinct) != 0) return 0;
    const pEList = selPEList(pSelect);
    if (elNExpr(pEList) != 1) return 0;
    if (exprOp(elPExpr(pEList, 0)) != TK_ASTERISK) return 0;

    const pItem = srcItem0(selPSrc(pSelect));
    const pSrc = sqlite3LocateTableItem(pParse, 0, pItem);
    if (pSrc == null) return 0;
    if (tabTnum(pSrc) == tabTnum(pDest) and tabPSchema(pSrc) == tabPSchema(pDest)) return 0;
    if (tabHasRowid(pDest) != tabHasRowid(pSrc)) return 0;
    if (!tabIsOrdinary(pSrc)) return 0;
    if (tabNCol(pDest) != tabNCol(pSrc)) return 0;
    if (tabIPKey(pDest) != tabIPKey(pSrc)) return 0;
    if ((tabTabFlags(pDest) & TF_Strict) != 0) {
        if ((tabTabFlags(pSrc) & TF_Strict) == 0) return 0;
        i = 0;
        while (i < tabNCol(pDest)) : (i += 1) {
            const eDestType = colECType(tabColAt(pDest, i));
            const eSrcType = colECType(tabColAt(pSrc, i));
            if (eDestType == COLTYPE_ANY) continue;
            if (eDestType == eSrcType) continue;
            if (eDestType == COLTYPE_INT and eSrcType == COLTYPE_INTEGER) continue;
            if (eDestType == COLTYPE_INTEGER and eSrcType == COLTYPE_INT) continue;
            return 0;
        }
    }
    i = 0;
    while (i < tabNCol(pDest)) : (i += 1) {
        const pDestCol = tabColAt(pDest, i);
        const pSrcCol = tabColAt(pSrc, i);
        if ((colColFlags(pDestCol) & COLFLAG_GENERATED) != (colColFlags(pSrcCol) & COLFLAG_GENERATED)) return 0;
        if ((colColFlags(pDestCol) & COLFLAG_GENERATED) != 0) {
            if (sqlite3ExprCompare(null, sqlite3ColumnExpr(pSrc, pSrcCol), sqlite3ColumnExpr(pDest, pDestCol), -1) != 0) {
                return 0;
            }
        }
        if (colAffinity(pDestCol) != colAffinity(pSrcCol)) return 0;
        if (sqlite3_stricmp(sqlite3ColumnColl(pDestCol), sqlite3ColumnColl(pSrcCol)) != 0) return 0;
        if (colNotNull(pDestCol) != 0 and colNotNull(pSrcCol) == 0) return 0;
        if ((colColFlags(pDestCol) & COLFLAG_GENERATED) == 0 and i > 0) {
            const pDestExpr = sqlite3ColumnExpr(pDest, pDestCol);
            const pSrcExpr = sqlite3ColumnExpr(pSrc, pSrcCol);
            const destNull = pDestExpr == null;
            const srcNull = pSrcExpr == null;
            if (destNull != srcNull or
                (pDestExpr != null and cstrcmp(exprZToken(pDestExpr), exprZToken(pSrcExpr)) != 0))
            {
                return 0;
            }
        }
    }
    pDestIdx = tabPIndex(pDest);
    while (pDestIdx != null) : (pDestIdx = idxPNext(pDestIdx)) {
        if (idxIsUnique(pDestIdx)) destHasUniqueIdx = true;
        pSrcIdx = tabPIndex(pSrc);
        while (pSrcIdx != null) : (pSrcIdx = idxPNext(pSrcIdx)) {
            if (xferCompatibleIndex(pDestIdx, pSrcIdx)) break;
        }
        if (pSrcIdx == null) return 0;
        if (idxTnum(pSrcIdx) == idxTnum(pDestIdx) and tabPSchema(pSrc) == tabPSchema(pDest) and sqlite3FaultSim(411) == SQLITE_OK) {
            return 0;
        }
    }
    if (tabPCheck(pDest) != null and (dbMDbFlags(db) & DBFLAG_Vacuum) == 0 and !xferCompatibleCheck(pDest, pSrc)) {
        return 0;
    }
    if ((dbFlags(db) & SQLITE_ForeignKeys) != 0 and tabPFKey(pDest) != null) return 0;
    if ((dbFlags(db) & SQLITE_CountRows) != 0) return 0;
    if (dbXAuth(db) != null) {
        const iDb = sqlite3SchemaToIndex(db, tabPSchema(pSrc));
        if (sqlite3AuthCheck(pParse, SQLITE_SELECT, null, null, null) != 0) return 0;
        i = 0;
        while (i < tabNCol(pSrc)) : (i += 1) {
            const pSrcCol = tabColAt(pSrc, i);
            if (sqlite3AuthReadCol(pParse, tabZName(pSrc), colZCnName(pSrcCol), iDb) != 0) return 0;
        }
    }

    // Optimization is at least possible.
    if (config.sqlite_test) {
        xferopt_count += 1;
    }
    iDbSrc = sqlite3SchemaToIndex(db, tabPSchema(pSrc));
    v = sqlite3GetVdbe(pParse);
    sqlite3CodeVerifySchema(pParse, iDbSrc);
    iSrc = pIncNTab(pParse);
    iDest = pIncNTab(pParse);
    regAutoinc = autoIncBegin(pParse, iDbDest, pDest);
    regData = sqlite3GetTempReg(pParse);
    _ = sqlite3VdbeAddOp2(v, OP_Null, 0, regData);
    regRowid = sqlite3GetTempReg(pParse);
    sqlite3OpenTable(pParse, iDest, iDbDest, pDest, OP_OpenWrite);
    if ((dbMDbFlags(db) & DBFLAG_Vacuum) == 0 and
        ((tabIPKey(pDest) < 0 and tabPIndex(pDest) != null) or destHasUniqueIdx or (onError != OE_Abort and onError != OE_Rollback)))
    {
        addr1 = sqlite3VdbeAddOp2(v, OP_Rewind, iDest, 0);
        emptyDestTest = sqlite3VdbeAddOp0(v, OP_Goto);
        sqlite3VdbeJumpHere(v, addr1);
    }
    if (tabHasRowid(pSrc)) {
        var insFlags: u16 = undefined;
        sqlite3OpenTable(pParse, iSrc, iDbSrc, pSrc, OP_OpenRead);
        emptySrcTest = sqlite3VdbeAddOp2(v, OP_Rewind, iSrc, 0);
        if (tabIPKey(pDest) >= 0) {
            addr1 = sqlite3VdbeAddOp2(v, OP_Rowid, iSrc, regRowid);
            if ((dbMDbFlags(db) & DBFLAG_Vacuum) == 0) {
                sqlite3VdbeVerifyAbortable(v, onError);
                addr2 = sqlite3VdbeAddOp3(v, OP_NotExists, iDest, 0, regRowid);
                sqlite3RowidConstraint(pParse, onError, pDest);
                sqlite3VdbeJumpHere(v, addr2);
            }
            autoIncStep(pParse, regAutoinc, regRowid);
        } else if (tabPIndex(pDest) == null and (dbMDbFlags(db) & DBFLAG_VacuumInto) == 0) {
            addr1 = sqlite3VdbeAddOp2(v, OP_NewRowid, iDest, regRowid);
        } else {
            addr1 = sqlite3VdbeAddOp2(v, OP_Rowid, iSrc, regRowid);
        }

        if ((dbMDbFlags(db) & DBFLAG_Vacuum) != 0) {
            _ = sqlite3VdbeAddOp1(v, OP_SeekEnd, iDest);
            insFlags = OPFLAG_APPEND | OPFLAG_USESEEKRESULT | OPFLAG_PREFORMAT;
        } else {
            insFlags = OPFLAG_NCHANGE | OPFLAG_LASTROWID | OPFLAG_APPEND | OPFLAG_PREFORMAT;
        }
        // SQLITE_ENABLE_PREUPDATE_HOOK ON
        if ((dbMDbFlags(db) & DBFLAG_Vacuum) == 0) {
            _ = sqlite3VdbeAddOp3(v, OP_RowData, iSrc, regData, 1);
            insFlags &= ~OPFLAG_PREFORMAT;
        } else {
            _ = sqlite3VdbeAddOp3(v, OP_RowCell, iDest, iSrc, regRowid);
        }
        _ = sqlite3VdbeAddOp3(v, OP_Insert, iDest, regData, regRowid);
        if ((dbMDbFlags(db) & DBFLAG_Vacuum) == 0) {
            sqlite3VdbeChangeP4(v, -1, @ptrCast(pDest), P4_TABLE);
        }
        sqlite3VdbeChangeP5(v, insFlags);

        _ = sqlite3VdbeAddOp2(v, OP_Next, iSrc, addr1);
        _ = sqlite3VdbeAddOp2(v, OP_Close, iSrc, 0);
        _ = sqlite3VdbeAddOp2(v, OP_Close, iDest, 0);
    } else {
        sqlite3TableLock(pParse, iDbDest, tabTnum(pDest), 1, tabZName(pDest));
        sqlite3TableLock(pParse, iDbSrc, tabTnum(pSrc), 0, tabZName(pSrc));
    }
    pDestIdx = tabPIndex(pDest);
    while (pDestIdx != null) : (pDestIdx = idxPNext(pDestIdx)) {
        var idxInsFlags: u16 = 0;
        pSrcIdx = tabPIndex(pSrc);
        while (pSrcIdx != null) : (pSrcIdx = idxPNext(pSrcIdx)) {
            if (xferCompatibleIndex(pDestIdx, pSrcIdx)) break;
        }
        _ = sqlite3VdbeAddOp3(v, OP_OpenRead, iSrc, @intCast(idxTnum(pSrcIdx)), iDbSrc);
        sqlite3VdbeSetP4KeyInfo(pParse, pSrcIdx);
        sqlite3VdbeComment(v, "%s", idxZName(pSrcIdx));
        _ = sqlite3VdbeAddOp3(v, OP_OpenWrite, iDest, @intCast(idxTnum(pDestIdx)), iDbDest);
        sqlite3VdbeSetP4KeyInfo(pParse, pDestIdx);
        sqlite3VdbeChangeP5(v, OPFLAG_BULKCSR);
        sqlite3VdbeComment(v, "%s", idxZName(pDestIdx));
        addr1 = sqlite3VdbeAddOp2(v, OP_Rewind, iSrc, 0);
        if ((dbMDbFlags(db) & DBFLAG_Vacuum) != 0) {
            i = 0;
            while (i < @as(c_int, @intCast(idxNColumn(pSrcIdx)))) : (i += 1) {
                const zColl = idxAColl(pSrcIdx, @intCast(i));
                if (sqlite3_stricmp(strBINARY(), zColl) != 0) break;
            }
            if (i == @as(c_int, @intCast(idxNColumn(pSrcIdx)))) {
                idxInsFlags = OPFLAG_USESEEKRESULT | OPFLAG_PREFORMAT;
                _ = sqlite3VdbeAddOp1(v, OP_SeekEnd, iDest);
                _ = sqlite3VdbeAddOp2(v, OP_RowCell, iDest, iSrc);
            }
        } else if (!tabHasRowid(pSrc) and idxIsPrimaryKey(pDestIdx)) {
            idxInsFlags |= OPFLAG_NCHANGE;
        }
        if (idxInsFlags != (OPFLAG_USESEEKRESULT | OPFLAG_PREFORMAT)) {
            _ = sqlite3VdbeAddOp3(v, OP_RowData, iSrc, regData, 1);
            if ((dbMDbFlags(db) & DBFLAG_Vacuum) == 0 and !tabHasRowid(pDest) and idxIsPrimaryKey(pDestIdx)) {
                codeWithoutRowidPreupdate(pParse, pDest, iDest, regData);
            }
        }
        _ = sqlite3VdbeAddOp2(v, OP_IdxInsert, iDest, regData);
        sqlite3VdbeChangeP5(v, idxInsFlags | OPFLAG_APPEND);
        _ = sqlite3VdbeAddOp2(v, OP_Next, iSrc, addr1 + 1);
        sqlite3VdbeJumpHere(v, addr1);
        _ = sqlite3VdbeAddOp2(v, OP_Close, iSrc, 0);
        _ = sqlite3VdbeAddOp2(v, OP_Close, iDest, 0);
    }
    if (emptySrcTest != 0) sqlite3VdbeJumpHere(v, emptySrcTest);
    sqlite3ReleaseTempReg(pParse, regRowid);
    sqlite3ReleaseTempReg(pParse, regData);
    if (emptyDestTest != 0) {
        sqlite3AutoincrementEnd(pParse);
        _ = sqlite3VdbeAddOp2(v, OP_Halt, SQLITE_OK, 0);
        sqlite3VdbeJumpHere(v, emptyDestTest);
        _ = sqlite3VdbeAddOp2(v, OP_Close, iDest, 0);
        return 0;
    } else {
        return 1;
    }
}

extern fn strcmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
inline fn cstrcmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int {
    return strcmp(a, b);
}
