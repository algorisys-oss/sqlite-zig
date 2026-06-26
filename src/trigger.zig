//! Zig port of SQLite's src/trigger.c — the TRIGGER machinery: CREATE/DROP
//! TRIGGER parse glue, the TriggerStep builders, trigger-existence/colmask
//! queries, and the FOR EACH ROW sub-program code generator (OP_Program), plus
//! the in-line RETURNING-trigger codegen.
//!
//! Exported (non-static) symbols — the complete external set of trigger.c,
//! matching the prototypes in sqliteInt.h (SQLITE_OMIT_TRIGGER is OFF):
//!   - sqlite3DeleteTriggerStep
//!   - sqlite3TriggerList
//!   - sqlite3BeginTrigger        sqlite3FinishTrigger
//!   - sqlite3TriggerSelectStep   sqlite3TriggerInsertStep
//!   - sqlite3TriggerUpdateStep   sqlite3TriggerDeleteStep
//!   - sqlite3DeleteTrigger       (defined HERE; callback.zig declares it extern)
//!   - sqlite3DropTrigger         sqlite3DropTriggerPtr
//!   - sqlite3UnlinkAndDeleteTrigger
//!   - sqlite3TriggersExist
//!   - sqlite3CodeRowTrigger      sqlite3CodeRowTriggerDirect
//!   - sqlite3TriggerColmask
//! Static helpers (triggerSpanDup, triggerStepAllocate, tableOfTrigger,
//! checkColumnOverlap, tempTriggersExist, triggersReallyExist, isAsteriskTerm,
//! sqlite3ExpandReturning, the two Returning-subquery walker callbacks,
//! sqlite3ProcessReturningSubqueries, codeReturningTrigger, codeTriggerProgram,
//! onErrorText, transferParseError, codeRowTrigger, getRowTrigger) are private.
//! The two walker callbacks keep callconv(.c) so the AST walker can dispatch
//! them.
//!
//! ─── Struct coupling / ground-truth offsets ────────────────────────────────
//! Every offset used here was probe-verified with offsetof in BOTH the
//! production library config and the `--dev` testfixture (SQLITE_DEBUG +
//! SQLITE_TEST) config. All probed offsets are IDENTICAL across configs EXCEPT
//! the Parse bitfield region (SQLITE_DEBUG inserts ifNotExists/isCreate/
//! earlyCleanup u8 fields, shifting disableTriggers/bReturning/okConstFactor/
//! checkSchema by 3 bytes). Those four bitfields are config-gated below.
//!
//! NOTE the gotcha that bit this exact struct before: TriggerPrg.pNext is at
//! offset 8 (pTrigger is the first field), NOT 0.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ═══ result codes / constants ════════════════════════════════════════════════
const SQLITE_OK: c_int = 0;

// Tokens (parse.h)
const TK_BEFORE: c_int = 33;
const TK_AFTER: c_int = 29;
const TK_INSTEAD: c_int = 66;
const TK_INSERT: c_int = 128;
const TK_DELETE: c_int = 129;
const TK_UPDATE: c_int = 130;
const TK_SELECT: c_int = 139;
const TK_RETURNING: c_int = 151;
const TK_DOT: c_int = 142;
const TK_ASTERISK: c_int = 180;
const TK_ID: c_int = 60;

// TRIGGER_BEFORE / TRIGGER_AFTER
const TRIGGER_BEFORE: u8 = 1;
const TRIGGER_AFTER: u8 = 2;

// ON CONFLICT
const OE_Default: u8 = 11;

// Table types
const TABTYP_VIEW: u8 = 2;
const TABTYP_VTAB: u8 = 1;

// Table flags / column flags
const TF_Shadow: u32 = 0x00001000;
const COLFLAG_HIDDEN: u16 = 0x0002;

// sqlite3.flags / mDbFlags
const SQLITE_RecTriggers: u64 = 0x00002000;
const SQLITE_EnableTrigger: u64 = 0x00040000;
const DBFLAG_SchemaChange: u32 = 0x0001;

// Select / NameContext / Expr flags
const SF_NestedFrom: u32 = 0x0000800;
const SF_Correlated: u32 = 0x20000000;
const NC_UBaseReg: c_int = 0x000400;
const EP_VarSelect: u32 = 0x000040;
const EP_xIsSelect: u32 = 0x001000;
const ENAME_NAME: u8 = 0;
const SQLITE_AFF_REAL: u8 = 0x45;
const EXPRDUP_REDUCE: c_int = 0x0001;
const SRT_Discard: c_int = 2;
const SQLITE_JUMPIFNULL: c_int = 0x10;
const WRC_Continue: c_int = 0;

// limits / authorizer codes
const SQLITE_LIMIT_TRIGGER_DEPTH: usize = 10;
const SQLITE_CREATE_TRIGGER: c_int = 7;
const SQLITE_CREATE_TEMP_TRIGGER: c_int = 8;
const SQLITE_DROP_TRIGGER: c_int = 16;
const SQLITE_DROP_TEMP_TRIGGER: c_int = 17;
const SQLITE_INSERT: c_int = 18;
const SQLITE_DELETE: c_int = 9;

// P4 / parse-mode
const P4_DYNAMIC: c_int = -7;
const P4_SUBPROGRAM: c_int = -4;
const PARSE_MODE_RENAME: u8 = 2;
const OMIT_TEMPDB: c_int = 0;
const LEGACY_SCHEMA_TABLE: [*:0]const u8 = "sqlite_master";

// opcodes
const OP_Trace: c_int = 186;
const OP_ResetCount: c_int = 133;
const OP_Halt: c_int = 72;
const OP_Program: c_int = 50;
const OP_DropTrigger: c_int = 156;
const OP_MakeRecord: c_int = 99;
const OP_NewRowid: c_int = 129;
const OP_Insert: c_int = 130;
const OP_RealAffinity: c_int = 89;

// ═══ ground-truth offsets ════════════════════════════════════════════════════
// Reuse c_layout entries where present, else the probe-verified fallback.

// Trigger
const Trigger_zName_off: usize = if (@hasDecl(L, "Trigger_zName")) L.Trigger_zName else 0;
const Trigger_table_off: usize = if (@hasDecl(L, "Trigger_table")) L.Trigger_table else 8;
const Trigger_op_off: usize = if (@hasDecl(L, "Trigger_op")) L.Trigger_op else 16;
const Trigger_tr_tm_off: usize = if (@hasDecl(L, "Trigger_tr_tm")) L.Trigger_tr_tm else 17;
const Trigger_bReturning_off: usize = if (@hasDecl(L, "Trigger_bReturning")) L.Trigger_bReturning else 18;
const Trigger_pWhen_off: usize = if (@hasDecl(L, "Trigger_pWhen")) L.Trigger_pWhen else 24;
const Trigger_pColumns_off: usize = if (@hasDecl(L, "Trigger_pColumns")) L.Trigger_pColumns else 32;
const Trigger_pSchema_off: usize = if (@hasDecl(L, "Trigger_pSchema")) L.Trigger_pSchema else 40;
const Trigger_pTabSchema_off: usize = if (@hasDecl(L, "Trigger_pTabSchema")) L.Trigger_pTabSchema else 48;
const Trigger_step_list_off: usize = if (@hasDecl(L, "Trigger_step_list")) L.Trigger_step_list else 56;
const Trigger_pNext_off: usize = if (@hasDecl(L, "Trigger_pNext")) L.Trigger_pNext else 64;
const sizeof_Trigger: usize = if (@hasDecl(L, "sizeof_Trigger")) L.sizeof_Trigger else 72;

// TriggerStep
const TriggerStep_op_off: usize = if (@hasDecl(L, "TriggerStep_op")) L.TriggerStep_op else 0;
const TriggerStep_orconf_off: usize = if (@hasDecl(L, "TriggerStep_orconf")) L.TriggerStep_orconf else 1;
const TriggerStep_pTrig_off: usize = if (@hasDecl(L, "TriggerStep_pTrig")) L.TriggerStep_pTrig else 8;
const TriggerStep_pSelect_off: usize = if (@hasDecl(L, "TriggerStep_pSelect")) L.TriggerStep_pSelect else 16;
const TriggerStep_pSrc_off: usize = if (@hasDecl(L, "TriggerStep_pSrc")) L.TriggerStep_pSrc else 24;
const TriggerStep_pWhere_off: usize = if (@hasDecl(L, "TriggerStep_pWhere")) L.TriggerStep_pWhere else 32;
const TriggerStep_pExprList_off: usize = if (@hasDecl(L, "TriggerStep_pExprList")) L.TriggerStep_pExprList else 40;
const TriggerStep_pIdList_off: usize = if (@hasDecl(L, "TriggerStep_pIdList")) L.TriggerStep_pIdList else 48;
const TriggerStep_pUpsert_off: usize = if (@hasDecl(L, "TriggerStep_pUpsert")) L.TriggerStep_pUpsert else 56;
const TriggerStep_zSpan_off: usize = if (@hasDecl(L, "TriggerStep_zSpan")) L.TriggerStep_zSpan else 64;
const TriggerStep_pNext_off: usize = if (@hasDecl(L, "TriggerStep_pNext")) L.TriggerStep_pNext else 72;
const sizeof_TriggerStep: usize = if (@hasDecl(L, "sizeof_TriggerStep")) L.sizeof_TriggerStep else 88;

// TriggerPrg  (NOTE: pNext is at 8, not 0)
const TriggerPrg_pTrigger_off: usize = if (@hasDecl(L, "TriggerPrg_pTrigger")) L.TriggerPrg_pTrigger else 0;
const TriggerPrg_pNext_off: usize = if (@hasDecl(L, "TriggerPrg_pNext")) L.TriggerPrg_pNext else 8;
const TriggerPrg_pProgram_off: usize = if (@hasDecl(L, "TriggerPrg_pProgram")) L.TriggerPrg_pProgram else 16;
const TriggerPrg_orconf_off: usize = if (@hasDecl(L, "TriggerPrg_orconf")) L.TriggerPrg_orconf else 24;
const TriggerPrg_aColmask_off: usize = if (@hasDecl(L, "TriggerPrg_aColmask")) L.TriggerPrg_aColmask else 28;
const sizeof_TriggerPrg: usize = if (@hasDecl(L, "sizeof_TriggerPrg")) L.sizeof_TriggerPrg else 40;

// SubProgram
const SubProgram_aOp_off: usize = if (@hasDecl(L, "SubProgram_aOp")) L.SubProgram_aOp else 0;
const SubProgram_nOp_off: usize = if (@hasDecl(L, "SubProgram_nOp")) L.SubProgram_nOp else 8;
const SubProgram_nMem_off: usize = if (@hasDecl(L, "SubProgram_nMem")) L.SubProgram_nMem else 12;
const SubProgram_nCsr_off: usize = if (@hasDecl(L, "SubProgram_nCsr")) L.SubProgram_nCsr else 16;
const SubProgram_token_off: usize = if (@hasDecl(L, "SubProgram_token")) L.SubProgram_token else 32;
const sizeof_SubProgram: usize = if (@hasDecl(L, "sizeof_SubProgram")) L.sizeof_SubProgram else 48;

// Parse — regular fields
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_zErrMsg_off: usize = if (@hasDecl(L, "Parse_zErrMsg")) L.Parse_zErrMsg else 8;
const Parse_pVdbe_off: usize = if (@hasDecl(L, "Parse_pVdbe")) L.Parse_pVdbe else 16;
const Parse_rc_off: usize = if (@hasDecl(L, "Parse_rc")) L.Parse_rc else 24;
const Parse_nQueryLoop_off: usize = if (@hasDecl(L, "Parse_nQueryLoop")) L.Parse_nQueryLoop else 28;
const Parse_eTriggerOp_off: usize = if (@hasDecl(L, "Parse_eTriggerOp")) L.Parse_eTriggerOp else 37;
const Parse_eOrconf_off: usize = if (@hasDecl(L, "Parse_eOrconf")) L.Parse_eOrconf else 38;
const Parse_prepFlags_off: usize = if (@hasDecl(L, "Parse_prepFlags")) L.Parse_prepFlags else 34;
const Parse_nErr_off: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;
const Parse_nTab_off: usize = if (@hasDecl(L, "Parse_nTab")) L.Parse_nTab else 56;
const Parse_nMem_off: usize = if (@hasDecl(L, "Parse_nMem")) L.Parse_nMem else 60;
const Parse_nMaxArg_off: usize = if (@hasDecl(L, "Parse_nMaxArg")) L.Parse_nMaxArg else 120;
const Parse_pToplevel_off: usize = if (@hasDecl(L, "Parse_pToplevel")) L.Parse_pToplevel else 136;
const Parse_pTriggerTab_off: usize = if (@hasDecl(L, "Parse_pTriggerTab")) L.Parse_pTriggerTab else 144;
const Parse_pTriggerPrg_off: usize = if (@hasDecl(L, "Parse_pTriggerPrg")) L.Parse_pTriggerPrg else 152;
const Parse_pOuterParse_off: usize = if (@hasDecl(L, "Parse_pOuterParse")) L.Parse_pOuterParse else 200;
const Parse_oldmask_off: usize = if (@hasDecl(L, "Parse_oldmask")) L.Parse_oldmask else 224;
const Parse_newmask_off: usize = if (@hasDecl(L, "Parse_newmask")) L.Parse_newmask else 228;
const Parse_u1_off: usize = if (@hasDecl(L, "Parse_u1")) L.Parse_u1 else 232;
const Parse_eParseMode_off: usize = if (@hasDecl(L, "Parse_eParseMode")) L.Parse_eParseMode else 300;
const Parse_zAuthContext_off: usize = if (@hasDecl(L, "Parse_zAuthContext")) L.Parse_zAuthContext else 368;
const Parse_pNewTrigger_off: usize = if (@hasDecl(L, "Parse_pNewTrigger")) L.Parse_pNewTrigger else 360;

// Parse bitfields — these diverge between prod (39/40) and tf (42/43) configs.
const Parse_disableTriggers_byte: usize = if (config.sqlite_debug) 42 else 39;
const Parse_disableTriggers_bit: u8 = 0x01;
const Parse_checkSchema_byte: usize = if (config.sqlite_debug) 43 else 40;
const Parse_checkSchema_bit: u8 = 0x01;
const Parse_okConstFactor_byte: usize = if (config.sqlite_debug) 42 else 39;
const Parse_okConstFactor_bit: u8 = 0x80;
const Parse_bReturning_byte: usize = if (config.sqlite_debug) 42 else 39;
const Parse_bReturning_bit: u8 = 0x08;
// ifNotExists is a u8 field present only under SQLITE_DEBUG (byte 40).
const Parse_ifNotExists_off: usize = 40;

// Returning
const Returning_pReturnEL_off: usize = if (@hasDecl(L, "Returning_pReturnEL")) L.Returning_pReturnEL else 8;
const Returning_retTrig_off: usize = if (@hasDecl(L, "Returning_retTrig")) L.Returning_retTrig else 16;
const Returning_nRetCol_off: usize = if (@hasDecl(L, "Returning_nRetCol")) L.Returning_nRetCol else 180;
const Returning_iRetCur_off: usize = if (@hasDecl(L, "Returning_iRetCur")) L.Returning_iRetCur else 176;
const Returning_iRetReg_off: usize = if (@hasDecl(L, "Returning_iRetReg")) L.Returning_iRetReg else 184;

// sqlite3
const sqlite3_aLimit_off: usize = if (@hasDecl(L, "sqlite3_aLimit")) L.sqlite3_aLimit else 136;
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_mDbFlags_off: usize = if (@hasDecl(L, "sqlite3_mDbFlags")) L.sqlite3_mDbFlags else 44;
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_errByteOffset_off: usize = if (@hasDecl(L, "sqlite3_errByteOffset")) L.sqlite3_errByteOffset else 84;
const sqlite3_pParse_off: usize = if (@hasDecl(L, "sqlite3_pParse")) L.sqlite3_pParse else 344;
const sqlite3_init_busy_off: usize = if (@hasDecl(L, "sqlite3_initBusy")) L.sqlite3_initBusy else 197;
const sqlite3_init_iDb_off: usize = if (@hasDecl(L, "sqlite3_init_iDb")) L.sqlite3_init_iDb else 196;
// init.orphanTrigger is a 1-bit field at byte 198 (shares the byte with reopenMemdb=0x08).
const sqlite3_init_orphanTrigger_byte: usize = 198;
const sqlite3_init_orphanTrigger_bit: u8 = 0x01;

// Db / Schema / Hash
const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pSchema_off: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;
const Schema_trigHash_off: usize = if (@hasDecl(L, "Schema_trigHash")) L.Schema_trigHash else 56;
const Schema_tblHash_off: usize = if (@hasDecl(L, "Schema_tblHash")) L.Schema_tblHash else 8;
const Hash_first_off: usize = if (@hasDecl(L, "Hash_first")) L.Hash_first else 8;
const HashElem_next_off: usize = if (@hasDecl(L, "HashElem_next")) L.HashElem_next else 0;
const HashElem_data_off: usize = if (@hasDecl(L, "HashElem_data")) L.HashElem_data else 16;

// Table
const Table_zName_off: usize = if (@hasDecl(L, "Table_zName")) L.Table_zName else 0;
const Table_aCol_off: usize = if (@hasDecl(L, "Table_aCol")) L.Table_aCol else 8;
const Table_tabFlags_off: usize = if (@hasDecl(L, "Table_tabFlags")) L.Table_tabFlags else 48;
const Table_nCol_off: usize = if (@hasDecl(L, "Table_nCol")) L.Table_nCol else 54;
const Table_eTabType_off: usize = if (@hasDecl(L, "Table_eTabType")) L.Table_eTabType else 63;
const Table_u_off: usize = if (@hasDecl(L, "Table_u")) L.Table_u else 64;
const Table_pTrigger_off: usize = if (@hasDecl(L, "Table_pTrigger")) L.Table_pTrigger else 88;
const Table_pSchema_off: usize = if (@hasDecl(L, "Table_pSchema")) L.Table_pSchema else 96;

// Column
const sizeof_Column: usize = if (@hasDecl(L, "sizeof_Column")) L.sizeof_Column else 16;
const Column_zCnName_off: usize = if (@hasDecl(L, "Column_zCnName")) L.Column_zCnName else 0;
const Column_colFlags_off: usize = if (@hasDecl(L, "Column_colFlags")) L.Column_colFlags else 14;

// Walker
const Walker_xExprCallback_off: usize = if (@hasDecl(L, "Walker_xExprCallback")) L.Walker_xExprCallback else 8;
const Walker_xSelectCallback_off: usize = if (@hasDecl(L, "Walker_xSelectCallback")) L.Walker_xSelectCallback else 16;
const Walker_eCode_off: usize = if (@hasDecl(L, "Walker_eCode")) L.Walker_eCode else 36;
const Walker_u_off: usize = if (@hasDecl(L, "Walker_u")) L.Walker_u else 40;
const sizeof_Walker: usize = if (@hasDecl(L, "sizeof_Walker")) L.sizeof_Walker else 48;

// NameContext
const sizeof_NameContext: usize = if (@hasDecl(L, "sizeof_NameContext")) L.sizeof_NameContext else 56;
const NameContext_pParse_off: usize = if (@hasDecl(L, "NameContext_pParse")) L.NameContext_pParse else 0;
const NameContext_uNC_off: usize = if (@hasDecl(L, "NameContext_uNC")) L.NameContext_uNC else 16;
const NameContext_ncFlags_off: usize = if (@hasDecl(L, "NameContext_ncFlags")) L.NameContext_ncFlags else 40;

// ExprList / Expr
const ExprList_nExpr_off: usize = if (@hasDecl(L, "ExprList_nExpr")) L.ExprList_nExpr else 0;
const ExprList_a_off: usize = if (@hasDecl(L, "ExprList_a")) L.ExprList_a else 8;
const ExprList_item_pExpr_off: usize = if (@hasDecl(L, "ExprList_item_pExpr")) L.ExprList_item_pExpr else 0;
const ExprList_item_zEName_off: usize = if (@hasDecl(L, "ExprList_item_zEName")) L.ExprList_item_zEName else 8;
const sizeof_ExprList_item: usize = if (@hasDecl(L, "sizeof_ExprList_item")) L.sizeof_ExprList_item else 24;
const Expr_op_off: usize = if (@hasDecl(L, "Expr_op")) L.Expr_op else 0;
const Expr_flags_off: usize = if (@hasDecl(L, "Expr_flags")) L.Expr_flags else 4;
const Expr_u_off: usize = if (@hasDecl(L, "Expr_u")) L.Expr_u else 8;
const Expr_pLeft_off: usize = if (@hasDecl(L, "Expr_pLeft")) L.Expr_pLeft else 16;
const Expr_pRight_off: usize = if (@hasDecl(L, "Expr_pRight")) L.Expr_pRight else 24;
const Expr_x_off: usize = if (@hasDecl(L, "Expr_x")) L.Expr_x else 32;

// Select
const sizeof_Select: usize = if (@hasDecl(L, "sizeof_Select")) L.sizeof_Select else 120;
const Select_selFlags_off: usize = if (@hasDecl(L, "Select_selFlags")) L.Select_selFlags else 4;
const Select_pEList_off: usize = if (@hasDecl(L, "Select_pEList")) L.Select_pEList else 24;
const Select_pSrc_off: usize = if (@hasDecl(L, "Select_pSrc")) L.Select_pSrc else 32;

// SrcList / SrcItem
const SrcList_nSrc_off: usize = if (@hasDecl(L, "SrcList_nSrc")) L.SrcList_nSrc else 0;
const SrcList_a_off: usize = if (@hasDecl(L, "SrcList_a")) L.SrcList_a else 8;
const sizeof_SrcItem: usize = if (@hasDecl(L, "sizeof_SrcItem")) L.sizeof_SrcItem else 72;
const SrcItem_zName_off: usize = if (@hasDecl(L, "SrcItem_zName")) L.SrcItem_zName else 0;
const SrcItem_pSTab_off: usize = if (@hasDecl(L, "SrcItem_pSTab")) L.SrcItem_pSTab else 16;
const SrcItem_iCursor_off: usize = if (@hasDecl(L, "SrcItem_iCursor")) L.SrcItem_iCursor else 28;
const SrcItem_u4_off: usize = if (@hasDecl(L, "SrcItem_u4")) L.SrcItem_u4 else 64;
const SZ_SRCLIST_1: usize = if (@hasDecl(L, "SZ_SRCLIST_1")) L.SZ_SRCLIST_1 else 80;

// DbFixer — only its on-stack size is needed (its fields are touched by the
// ported attach.zig sqlite3Fix* functions). sizeof DbFixer == 96.
const sizeof_DbFixer: usize = 96;
// Full struct Parse size (config-invariant 416) — for the sub-vdbe Parse on stack.
const sizeof_Parse: usize = if (@hasDecl(L, "sizeof_Parse")) L.sizeof_Parse else 416;
// SelectDest size (40, config-invariant).
const sizeof_SelectDest: usize = 40;

// Token — {z: ?[*]const u8, n: c_uint}. 16 bytes on x86-64.
const Token = extern struct { z: ?[*]const u8, n: c_uint };

// ═══ raw-memory helpers ══════════════════════════════════════════════════════
inline fn base(p: ?*anyopaque) [*]u8 {
    return @ptrCast(p.?);
}
inline fn rdPtr(comptime T: type, p: ?*anyopaque, off: usize) T {
    const q: *align(1) const T = @ptrCast(base(p) + off);
    return q.*;
}
inline fn wrPtr(comptime T: type, p: ?*anyopaque, off: usize, v: T) void {
    const q: *align(1) T = @ptrCast(base(p) + off);
    q.* = v;
}
inline fn fieldPtr(p: ?*anyopaque, off: usize) ?*anyopaque {
    return @ptrCast(base(p) + off);
}
inline fn getBit(p: ?*anyopaque, byte: usize, bit: u8) bool {
    return (base(p)[byte] & bit) != 0;
}
inline fn setBit(p: ?*anyopaque, byte: usize, bit: u8) void {
    base(p)[byte] |= bit;
}

// ─── Trigger ──────────────────────────────────────────────────────────────
inline fn trigZName(p: ?*anyopaque) ?[*:0]u8 {
    return rdPtr(?[*:0]u8, p, Trigger_zName_off);
}
inline fn trigSetZName(p: ?*anyopaque, v: ?[*:0]u8) void {
    wrPtr(?[*:0]u8, p, Trigger_zName_off, v);
}
inline fn trigTable(p: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, p, Trigger_table_off);
}
inline fn trigSetTable(p: ?*anyopaque, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, p, Trigger_table_off, v);
}
inline fn trigOp(p: ?*anyopaque) u8 {
    return base(p)[Trigger_op_off];
}
inline fn trigSetOp(p: ?*anyopaque, v: u8) void {
    base(p)[Trigger_op_off] = v;
}
inline fn trigTrTm(p: ?*anyopaque) u8 {
    return base(p)[Trigger_tr_tm_off];
}
inline fn trigSetTrTm(p: ?*anyopaque, v: u8) void {
    base(p)[Trigger_tr_tm_off] = v;
}
inline fn trigBReturning(p: ?*anyopaque) u8 {
    return base(p)[Trigger_bReturning_off];
}
inline fn trigPWhen(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_pWhen_off);
}
inline fn trigSetPWhen(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Trigger_pWhen_off, v);
}
inline fn trigPColumns(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_pColumns_off);
}
inline fn trigSetPColumns(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Trigger_pColumns_off, v);
}
inline fn trigPSchema(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_pSchema_off);
}
inline fn trigSetPSchema(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Trigger_pSchema_off, v);
}
inline fn trigPTabSchema(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_pTabSchema_off);
}
inline fn trigSetPTabSchema(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Trigger_pTabSchema_off, v);
}
inline fn trigStepList(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_step_list_off);
}
inline fn trigSetStepList(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Trigger_step_list_off, v);
}
inline fn trigPNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_pNext_off);
}
inline fn trigSetPNext(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Trigger_pNext_off, v);
}

// ─── TriggerStep ──────────────────────────────────────────────────────────
inline fn stepOp(p: ?*anyopaque) u8 {
    return base(p)[TriggerStep_op_off];
}
inline fn stepSetOp(p: ?*anyopaque, v: u8) void {
    base(p)[TriggerStep_op_off] = v;
}
inline fn stepOrconf(p: ?*anyopaque) u8 {
    return base(p)[TriggerStep_orconf_off];
}
inline fn stepSetOrconf(p: ?*anyopaque, v: u8) void {
    base(p)[TriggerStep_orconf_off] = v;
}
inline fn stepSetPTrig(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerStep_pTrig_off, v);
}
inline fn stepPSelect(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pSelect_off);
}
inline fn stepSetPSelect(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerStep_pSelect_off, v);
}
inline fn stepPSrc(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pSrc_off);
}
inline fn stepSetPSrc(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerStep_pSrc_off, v);
}
inline fn stepPWhere(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pWhere_off);
}
inline fn stepSetPWhere(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerStep_pWhere_off, v);
}
inline fn stepPExprList(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pExprList_off);
}
inline fn stepSetPExprList(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerStep_pExprList_off, v);
}
inline fn stepPIdList(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pIdList_off);
}
inline fn stepSetPIdList(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerStep_pIdList_off, v);
}
inline fn stepPUpsert(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pUpsert_off);
}
inline fn stepSetPUpsert(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerStep_pUpsert_off, v);
}
inline fn stepZSpan(p: ?*anyopaque) ?[*:0]u8 {
    return rdPtr(?[*:0]u8, p, TriggerStep_zSpan_off);
}
inline fn stepSetZSpan(p: ?*anyopaque, v: ?[*:0]u8) void {
    wrPtr(?[*:0]u8, p, TriggerStep_zSpan_off, v);
}
inline fn stepPNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pNext_off);
}

// ─── TriggerPrg ─────────────────────────────────────────────────────────────
inline fn prgPTrigger(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerPrg_pTrigger_off);
}
inline fn prgSetPTrigger(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerPrg_pTrigger_off, v);
}
inline fn prgPNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerPrg_pNext_off);
}
inline fn prgSetPNext(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerPrg_pNext_off, v);
}
inline fn prgPProgram(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerPrg_pProgram_off);
}
inline fn prgSetPProgram(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, TriggerPrg_pProgram_off, v);
}
inline fn prgOrconf(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, TriggerPrg_orconf_off);
}
inline fn prgSetOrconf(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, TriggerPrg_orconf_off, v);
}
inline fn prgColmask(p: ?*anyopaque, i: usize) u32 {
    return rdPtr(u32, p, TriggerPrg_aColmask_off + i * @sizeOf(u32));
}
inline fn prgSetColmask(p: ?*anyopaque, i: usize, v: u32) void {
    wrPtr(u32, p, TriggerPrg_aColmask_off + i * @sizeOf(u32), v);
}

// ─── SubProgram ─────────────────────────────────────────────────────────────
inline fn subSetAOp(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, SubProgram_aOp_off, v);
}
inline fn subNOpPtr(p: ?*anyopaque) *align(1) c_int {
    return @ptrCast(base(p) + SubProgram_nOp_off);
}
inline fn subSetNMem(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, SubProgram_nMem_off, v);
}
inline fn subSetNCsr(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, SubProgram_nCsr_off, v);
}
inline fn subSetToken(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, SubProgram_token_off, v);
}

// ─── Parse ──────────────────────────────────────────────────────────────────
inline fn pDb(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Parse_db_off);
}
inline fn pNErr(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, Parse_nErr_off);
}
inline fn pVdbe(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Parse_pVdbe_off);
}
inline fn pZErrMsg(p: ?*anyopaque) ?[*:0]u8 {
    return rdPtr(?[*:0]u8, p, Parse_zErrMsg_off);
}
inline fn pSetZErrMsg(p: ?*anyopaque, v: ?[*:0]u8) void {
    wrPtr(?[*:0]u8, p, Parse_zErrMsg_off, v);
}
inline fn pRc(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, Parse_rc_off);
}
inline fn pSetRc(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, Parse_rc_off, v);
}
inline fn pSetNErr(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, Parse_nErr_off, v);
}
inline fn pNQueryLoop(p: ?*anyopaque) c_short {
    return rdPtr(c_short, p, Parse_nQueryLoop_off);
}
inline fn pSetNQueryLoop(p: ?*anyopaque, v: c_short) void {
    wrPtr(c_short, p, Parse_nQueryLoop_off, v);
}
inline fn pPrepFlags(p: ?*anyopaque) u8 {
    return base(p)[Parse_prepFlags_off];
}
inline fn pSetPrepFlags(p: ?*anyopaque, v: u8) void {
    base(p)[Parse_prepFlags_off] = v;
}
inline fn pSetETriggerOp(p: ?*anyopaque, v: u8) void {
    base(p)[Parse_eTriggerOp_off] = v;
}
inline fn pEOrconf(p: ?*anyopaque) u8 {
    return base(p)[Parse_eOrconf_off];
}
inline fn pSetEOrconf(p: ?*anyopaque, v: u8) void {
    base(p)[Parse_eOrconf_off] = v;
}
inline fn pNTab(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, Parse_nTab_off);
}
inline fn pSetNTab(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, Parse_nTab_off, v);
}
inline fn pNMem(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, Parse_nMem_off);
}
inline fn pSetNMem(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, Parse_nMem_off, v);
}
inline fn pPToplevel(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Parse_pToplevel_off);
}
inline fn pSetPToplevel(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Parse_pToplevel_off, v);
}
inline fn pSetPTriggerTab(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Parse_pTriggerTab_off, v);
}
inline fn pPTriggerPrg(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Parse_pTriggerPrg_off);
}
inline fn pSetPTriggerPrg(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Parse_pTriggerPrg_off, v);
}
inline fn pPOuterParse(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Parse_pOuterParse_off);
}
inline fn pSetOldmask(p: ?*anyopaque, v: u32) void {
    wrPtr(u32, p, Parse_oldmask_off, v);
}
inline fn pOldmask(p: ?*anyopaque) u32 {
    return rdPtr(u32, p, Parse_oldmask_off);
}
inline fn pSetNewmask(p: ?*anyopaque, v: u32) void {
    wrPtr(u32, p, Parse_newmask_off, v);
}
inline fn pNewmask(p: ?*anyopaque) u32 {
    return rdPtr(u32, p, Parse_newmask_off);
}
inline fn pSetZAuthContext(p: ?*anyopaque, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, p, Parse_zAuthContext_off, v);
}
inline fn pPNewTrigger(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Parse_pNewTrigger_off);
}
inline fn pSetPNewTrigger(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Parse_pNewTrigger_off, v);
}
inline fn pU1(p: ?*anyopaque) ?*anyopaque {
    // u1.d.pReturning == first member of the union arm == *(void**)(p+u1)
    return rdPtr(?*anyopaque, p, Parse_u1_off);
}
inline fn pEParseMode(p: ?*anyopaque) u8 {
    return base(p)[Parse_eParseMode_off];
}
inline fn pDisableTriggers(p: ?*anyopaque) bool {
    return getBit(p, Parse_disableTriggers_byte, Parse_disableTriggers_bit);
}
inline fn pBReturning(p: ?*anyopaque) bool {
    return getBit(p, Parse_bReturning_byte, Parse_bReturning_bit);
}
inline fn pOkConstFactor(p: ?*anyopaque) bool {
    return getBit(p, Parse_okConstFactor_byte, Parse_okConstFactor_bit);
}
inline fn pSetCheckSchema(p: ?*anyopaque) void {
    setBit(p, Parse_checkSchema_byte, Parse_checkSchema_bit);
}
// IN_RENAME_OBJECT
inline fn inRenameObject(p: ?*anyopaque) bool {
    return pEParseMode(p) >= PARSE_MODE_RENAME;
}
// sqlite3IsToplevel(p)  == (p->pToplevel==0)
inline fn isToplevel(p: ?*anyopaque) bool {
    return pPToplevel(p) == null;
}
// sqlite3ParseToplevel(p) == p->pToplevel ? p->pToplevel : p
inline fn parseToplevel(p: ?*anyopaque) ?*anyopaque {
    return if (pPToplevel(p)) |t| t else p;
}

// ─── sqlite3 ──────────────────────────────────────────────────────────────
inline fn dbALimit(db: ?*anyopaque, lim: usize) c_int {
    return rdPtr(c_int, db, sqlite3_aLimit_off + lim * @sizeOf(c_int));
}
inline fn dbFlags(db: ?*anyopaque) u64 {
    return rdPtr(u64, db, sqlite3_flags_off);
}
inline fn dbMDbFlags(db: ?*anyopaque) u32 {
    return rdPtr(u32, db, sqlite3_mDbFlags_off);
}
inline fn dbSetMDbFlags(db: ?*anyopaque, v: u32) void {
    wrPtr(u32, db, sqlite3_mDbFlags_off, v);
}
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rdPtr(c_int, db, sqlite3_nDb_off);
}
inline fn dbADb(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_aDb_off);
}
inline fn dbAt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(dbADb(db).?);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_Db));
}
inline fn dbAtPSchema(db: ?*anyopaque, i: c_int) ?*anyopaque {
    return rdPtr(?*anyopaque, dbAt(db, i), Db_pSchema_off);
}
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}
inline fn dbSetErrByteOffset(db: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, db, sqlite3_errByteOffset_off, v);
}
inline fn dbPParse(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_pParse_off);
}
inline fn dbInitBusy(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_init_busy_off];
}
inline fn dbInitIDb(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_init_iDb_off];
}
inline fn dbSetOrphanTrigger(db: ?*anyopaque) void {
    setBit(db, sqlite3_init_orphanTrigger_byte, sqlite3_init_orphanTrigger_bit);
}

// ─── Schema / Table ─────────────────────────────────────────────────────────
inline fn schemaTrigHash(s: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(s) + Schema_trigHash_off);
}
inline fn schemaTblHash(s: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(s) + Schema_tblHash_off);
}
inline fn tabZName(t: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, t, Table_zName_off);
}
inline fn tabPSchema(t: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, t, Table_pSchema_off);
}
inline fn tabPTrigger(t: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, t, Table_pTrigger_off);
}
inline fn tabSetPTrigger(t: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, t, Table_pTrigger_off, v);
}
inline fn tabTabFlags(t: ?*anyopaque) u32 {
    return rdPtr(u32, t, Table_tabFlags_off);
}
inline fn tabNCol(t: ?*anyopaque) i16 {
    return rdPtr(i16, t, Table_nCol_off);
}
inline fn tabETabType(t: ?*anyopaque) u8 {
    return base(t)[Table_eTabType_off];
}
inline fn tabAColAt(t: ?*anyopaque, i: c_int) ?*anyopaque {
    const a = rdPtr(?*anyopaque, t, Table_aCol_off);
    const ap: [*]u8 = @ptrCast(a.?);
    return @ptrCast(ap + (@as(usize, @intCast(i)) * sizeof_Column));
}
inline fn isView(t: ?*anyopaque) bool {
    return tabETabType(t) == TABTYP_VIEW;
}
inline fn isVirtual(t: ?*anyopaque) bool {
    return tabETabType(t) == TABTYP_VTAB;
}
inline fn colZCnName(col: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, col, Column_zCnName_off);
}
inline fn colIsHidden(col: ?*anyopaque) bool {
    return (rdPtr(u16, col, Column_colFlags_off) & COLFLAG_HIDDEN) != 0;
}

// ─── Hash iteration (sqliteHashFirst/Next/Data are C macros) ────────────────
inline fn hashFirst(h: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, h, Hash_first_off);
}
inline fn hashElemNext(e: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, e, HashElem_next_off);
}
inline fn hashElemData(e: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, e, HashElem_data_off);
}

// ─── ExprList / Expr ────────────────────────────────────────────────────────
inline fn elNExpr(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, ExprList_nExpr_off);
}
inline fn elItemAt(p: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(base(p) + ExprList_a_off);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_ExprList_item));
}
inline fn itemPExpr(it: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, it, ExprList_item_pExpr_off);
}
inline fn itemZEName(it: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, it, ExprList_item_zEName_off);
}
inline fn itemSetZEName(it: ?*anyopaque, v: ?[*:0]u8) void {
    wrPtr(?[*:0]u8, it, ExprList_item_zEName_off, v);
}
// ExprList_item.fg is the anon struct at zEName+8: byte 0 = sortFlags (u8),
// byte 1 = the bitfield word whose LOW 2 bits are fg.eEName. Probe-verified in
// both configs: fg @ zEName+8, eEName lives in fg+1 (byte 17). Read-modify-write
// only the low 2 bits so neighbouring bits are preserved.
const ExprList_item_fg_off: usize = ExprList_item_zEName_off + 8;
const ExprList_item_eEName_byte: usize = ExprList_item_fg_off + 1;
inline fn itemSetENameKind(it: ?*anyopaque, v: u8) void {
    const b = &base(it)[ExprList_item_eEName_byte];
    b.* = (b.* & ~@as(u8, 0x03)) | (v & 0x03);
}
inline fn itemENameKind(it: ?*anyopaque) u8 {
    return base(it)[ExprList_item_eEName_byte] & 0x03;
}
inline fn exprOp(e: ?*anyopaque) u8 {
    return base(e)[Expr_op_off];
}
inline fn exprFlags(e: ?*anyopaque) u32 {
    return rdPtr(u32, e, Expr_flags_off);
}
inline fn exprSetFlags(e: ?*anyopaque, v: u32) void {
    wrPtr(u32, e, Expr_flags_off, v);
}
inline fn exprPLeft(e: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, e, Expr_pLeft_off);
}
inline fn exprPRight(e: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, e, Expr_pRight_off);
}
inline fn exprXSelect(e: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, e, Expr_x_off);
}
inline fn exprUseXSelect(e: ?*anyopaque) bool {
    return (exprFlags(e) & EP_xIsSelect) != 0;
}

// ─── Select ─────────────────────────────────────────────────────────────────
inline fn selSetPEList(s: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, s, Select_pEList_off, v);
}
inline fn selPEList(s: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, s, Select_pEList_off);
}
inline fn selSetPSrc(s: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, s, Select_pSrc_off, v);
}
inline fn selPSrc(s: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, s, Select_pSrc_off);
}
inline fn selSelFlags(s: ?*anyopaque) u32 {
    return rdPtr(u32, s, Select_selFlags_off);
}
inline fn selSetSelFlags(s: ?*anyopaque, v: u32) void {
    wrPtr(u32, s, Select_selFlags_off, v);
}

// ─── SrcList / SrcItem ──────────────────────────────────────────────────────
inline fn srcNSrc(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, SrcList_nSrc_off);
}
inline fn srcSetNSrc(p: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, p, SrcList_nSrc_off, v);
}
inline fn srcItemAt(p: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(base(p) + SrcList_a_off);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_SrcItem));
}
inline fn itemZName(it: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, it, SrcItem_zName_off);
}
inline fn itemSetZName(it: ?*anyopaque, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, it, SrcItem_zName_off, v);
}
inline fn itemPSTab(it: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, it, SrcItem_pSTab_off);
}
inline fn itemSetPSTab(it: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, it, SrcItem_pSTab_off, v);
}
inline fn itemSetICursor(it: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, it, SrcItem_iCursor_off, v);
}
inline fn itemU4ZDatabase(it: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, it, SrcItem_u4_off);
}
inline fn itemSetU4ZDatabase(it: ?*anyopaque, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, it, SrcItem_u4_off, v);
}

// ─── NameContext / Walker ───────────────────────────────────────────────────
inline fn ncSetPParse(nc: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, nc, NameContext_pParse_off, v);
}
inline fn ncSetUNCIBaseReg(nc: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, nc, NameContext_uNC_off, v);
}
inline fn ncSetNCFlags(nc: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, nc, NameContext_ncFlags_off, v);
}
inline fn wSetXExpr(w: ?*anyopaque, v: ?*const anyopaque) void {
    wrPtr(?*const anyopaque, w, Walker_xExprCallback_off, v);
}
inline fn wSetXSelect(w: ?*anyopaque, v: ?*const anyopaque) void {
    wrPtr(?*const anyopaque, w, Walker_xSelectCallback_off, v);
}
inline fn wECode(w: ?*anyopaque) u16 {
    return rdPtr(u16, w, Walker_eCode_off);
}
inline fn wSetECode(w: ?*anyopaque, v: u16) void {
    wrPtr(u16, w, Walker_eCode_off, v);
}
inline fn wSetUPTab(w: ?*anyopaque, v: ?*anyopaque) void {
    // Walker.u is a union; .pTab is the first member at the same offset.
    wrPtr(?*anyopaque, w, Walker_u_off, v);
}
inline fn wUPTab(w: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, w, Walker_u_off);
}

// ═══ extern C / internal-ABI helpers ════════════════════════════════════════
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbStrNDup(db: ?*anyopaque, z: ?[*:0]const u8, n: u64) ?[*:0]u8;
extern fn sqlite3DbSpanDup(db: ?*anyopaque, zStart: ?[*]const u8, zEnd: ?[*]const u8) ?[*:0]u8;
extern fn sqlite3MPrintf(db: ?*anyopaque, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
// sqlite3Isspace(x) is a macro: sqlite3CtypeMap[x] & 0x01 (SQLITE_ASCII is ON).
extern const sqlite3CtypeMap: [256]u8;
inline fn sqlite3Isspace(c: u8) c_int {
    return @intFromBool((sqlite3CtypeMap[c] & 0x01) != 0);
}

// AST dup / delete
extern fn sqlite3ExprDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3ExprListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3SelectDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3SrcListDup(db: ?*anyopaque, p: ?*anyopaque, flags: c_int) ?*anyopaque;
extern fn sqlite3IdListDup(db: ?*anyopaque, p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3UpsertDup(db: ?*anyopaque, p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ExprDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3ExprListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SelectDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SrcListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3IdListDelete(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3UpsertDelete(db: ?*anyopaque, p: ?*anyopaque) void;

// expr / list builders
extern fn sqlite3Expr(db: ?*anyopaque, op: c_int, z: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3ExprListAppend(pParse: ?*anyopaque, pList: ?*anyopaque, pExpr: ?*anyopaque) ?*anyopaque;
extern fn sqlite3SelectNew(pParse: ?*anyopaque, pEList: ?*anyopaque, pSrc: ?*anyopaque, pWhere: ?*anyopaque, pGroupBy: ?*anyopaque, pHaving: ?*anyopaque, pOrderBy: ?*anyopaque, selFlags: u32, pLimit: ?*anyopaque) ?*anyopaque;
extern fn sqlite3SrcListAppendFromTerm(pParse: ?*anyopaque, p: ?*anyopaque, pTable: ?*const Token, pDatabase: ?*const Token, pAlias: ?*const Token, pSubquery: ?*anyopaque, pOn: ?*anyopaque) ?*anyopaque;
extern fn sqlite3SrcListAppendList(pParse: ?*anyopaque, p1: ?*anyopaque, p2: ?*anyopaque) ?*anyopaque;

// name resolution / walk / codegen
extern fn sqlite3ResolveExprNames(nc: ?*anyopaque, e: ?*anyopaque) c_int;
extern fn sqlite3ResolveExprListNames(nc: ?*anyopaque, l: ?*anyopaque) c_int;
extern fn sqlite3WalkExprList(w: ?*anyopaque, l: ?*anyopaque) c_int;
extern fn sqlite3ExprWalkNoop(w: ?*anyopaque, e: ?*anyopaque) callconv(.c) c_int;
extern fn sqlite3SelectWalkNoop(w: ?*anyopaque, s: ?*anyopaque) callconv(.c) c_int;
extern fn sqlite3SelectPrep(pParse: ?*anyopaque, p: ?*anyopaque, nc: ?*anyopaque) void;
extern fn sqlite3GenerateColumnNames(pParse: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3SelectDestInit(dest: ?*anyopaque, eDest: c_int, iParm: c_int) void;
extern fn sqlite3ExprIfFalse(pParse: ?*anyopaque, e: ?*anyopaque, dest: c_int, jumpIfNull: c_int) void;
extern fn sqlite3ExprCodeFactorable(pParse: ?*anyopaque, e: ?*anyopaque, target: c_int) void;
extern fn sqlite3ExprAffinity(e: ?*anyopaque) u8;

// DML codegen (the heavy hitters dispatched by codeTriggerProgram)
extern fn sqlite3Insert(pParse: ?*anyopaque, pTabList: ?*anyopaque, pSelect: ?*anyopaque, pColumn: ?*anyopaque, onError: c_int, pUpsert: ?*anyopaque) void;
extern fn sqlite3Update(pParse: ?*anyopaque, pTabList: ?*anyopaque, pChanges: ?*anyopaque, pWhere: ?*anyopaque, onError: c_int, pOrderBy: ?*anyopaque, pLimit: ?*anyopaque, pUpsert: ?*anyopaque) void;
extern fn sqlite3DeleteFrom(pParse: ?*anyopaque, pTabList: ?*anyopaque, pWhere: ?*anyopaque, pOrderBy: ?*anyopaque, pLimit: ?*anyopaque) void;
extern fn sqlite3Select(pParse: ?*anyopaque, p: ?*anyopaque, dest: ?*anyopaque) c_int;

// schema / fixer / catalog
extern fn sqlite3SchemaToIndex(db: ?*anyopaque, pSchema: ?*anyopaque) c_int;
extern fn sqlite3FixInit(pFix: ?*anyopaque, pParse: ?*anyopaque, iDb: c_int, zType: ?[*:0]const u8, pName: ?*const Token) void;
extern fn sqlite3FixSrcList(pFix: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3FixTriggerStep(pFix: ?*anyopaque, pStep: ?*anyopaque) c_int;
extern fn sqlite3FixExpr(pFix: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3SrcListLookup(pParse: ?*anyopaque, pSrc: ?*anyopaque) ?*anyopaque;
extern fn sqlite3TwoPartName(pParse: ?*anyopaque, pName1: ?*const Token, pName2: ?*const Token, pUnqual: *?*const Token) c_int;
extern fn sqlite3NameFromToken(db: ?*anyopaque, pName: ?*const Token) ?[*:0]u8;
extern fn sqlite3CheckObjectName(pParse: ?*anyopaque, zName: ?[*:0]const u8, zType: ?[*:0]const u8, zTblName: ?[*:0]const u8) c_int;
extern fn sqlite3CodeVerifySchema(pParse: ?*anyopaque, iDb: c_int) void;
extern fn sqlite3CodeVerifyNamedSchema(pParse: ?*anyopaque, zDb: ?[*:0]const u8) void;
extern fn sqlite3ReadOnlyShadowTables(db: ?*anyopaque) c_int;
extern fn sqlite3ShadowTableName(db: ?*anyopaque, zName: ?[*:0]const u8) c_int;
extern fn sqlite3HasExplicitNulls(pParse: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3ReadSchema(pParse: ?*anyopaque) c_int;
extern fn sqlite3DbIsNamed(db: ?*anyopaque, iDb: c_int, zName: ?[*:0]const u8) c_int;
extern fn sqlite3RenameTokenRemap(pParse: ?*anyopaque, pTo: ?*const anyopaque, pFrom: ?*const anyopaque) void;

// hashes / tokens
extern fn sqlite3HashInsert(pHash: ?*anyopaque, pKey: ?[*:0]const u8, pData: ?*anyopaque) ?*anyopaque;
extern fn sqlite3HashFind(pHash: ?*anyopaque, pKey: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3IdListIndex(pList: ?*anyopaque, zName: ?[*:0]const u8) c_int;
extern fn sqlite3TokenInit(p: ?*Token, z: ?[*]const u8) void;

// authorization (SQLITE_OMIT_AUTHORIZATION is OFF)
extern fn sqlite3AuthCheck(pParse: ?*anyopaque, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;

// write / cookie / nested parse
extern fn sqlite3BeginWriteOperation(pParse: ?*anyopaque, setStatement: c_int, iDb: c_int) void;
extern fn sqlite3ChangeCookie(pParse: ?*anyopaque, iDb: c_int) void;
extern fn sqlite3NestedParse(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;

// Parse object lifecycle for the sub-vdbe
extern fn sqlite3ParseObjectInit(pParse: ?*anyopaque, db: ?*anyopaque) void;
extern fn sqlite3ParseObjectReset(pParse: ?*anyopaque) void;

// VDBE
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*anyopaque;
extern fn sqlite3VdbeAddOp0(v: ?*anyopaque, op: c_int) c_int;
extern fn sqlite3VdbeAddOp1(v: ?*anyopaque, op: c_int, p1: c_int) c_int;
extern fn sqlite3VdbeAddOp2(v: ?*anyopaque, op: c_int, p1: c_int, p2: c_int) c_int;
extern fn sqlite3VdbeAddOp3(v: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int) c_int;
extern fn sqlite3VdbeAddOp4(v: ?*anyopaque, op: c_int, p1: c_int, p2: c_int, p3: c_int, zP4: ?[*:0]const u8, p4type: c_int) c_int;
extern fn sqlite3VdbeChangeP4(v: ?*anyopaque, addr: c_int, zP4: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3VdbeChangeP5(v: ?*anyopaque, p5: u16) void;
extern fn sqlite3VdbeMakeLabel(pParse: ?*anyopaque) c_int;
extern fn sqlite3VdbeResolveLabel(v: ?*anyopaque, x: c_int) void;
extern fn sqlite3VdbeDelete(v: ?*anyopaque) void;
extern fn sqlite3VdbeLinkSubProgram(v: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3VdbeTakeOpArray(v: ?*anyopaque, pnOp: *align(1) c_int, pnMaxArg: *align(1) c_int) ?*anyopaque;
extern fn sqlite3VdbeAddParseSchemaOp(v: ?*anyopaque, iDb: c_int, zWhere: ?[*:0]u8, p5: u16) void;

// ═══ sqlite3DeleteTriggerStep ════════════════════════════════════════════════
export fn sqlite3DeleteTriggerStep(db: ?*anyopaque, pTriggerStep: ?*anyopaque) callconv(.c) void {
    var p = pTriggerStep;
    while (p) |pStep| {
        const pNext = stepPNext(pStep);
        sqlite3ExprDelete(db, stepPWhere(pStep));
        sqlite3ExprListDelete(db, stepPExprList(pStep));
        sqlite3SelectDelete(db, stepPSelect(pStep));
        sqlite3IdListDelete(db, stepPIdList(pStep));
        sqlite3UpsertDelete(db, stepPUpsert(pStep));
        sqlite3SrcListDelete(db, stepPSrc(pStep));
        sqlite3DbFree(db, @ptrCast(stepZSpan(pStep)));
        sqlite3DbFree(db, pStep);
        p = pNext;
    }
}

// ═══ sqlite3TriggerList ══════════════════════════════════════════════════════
export fn sqlite3TriggerList(pParse: ?*anyopaque, pTab: ?*anyopaque) callconv(.c) ?*anyopaque {
    const db = pDb(pParse);
    // pParse->db->aDb[1].pSchema
    const pTmpSchema = dbAtPSchema(db, 1);
    var p = hashFirst(schemaTrigHash(pTmpSchema));
    var pList = tabPTrigger(pTab);
    while (p) |entry| {
        const pTrig = hashElemData(entry);
        if (trigPTabSchema(pTrig) == tabPSchema(pTab) and
            trigTable(pTrig) != null and
            sqlite3StrICmp(trigTable(pTrig), tabZName(pTab)) == 0 and
            (trigPTabSchema(pTrig) != pTmpSchema or trigBReturning(pTrig) != 0))
        {
            trigSetPNext(pTrig, pList);
            pList = pTrig;
        } else if (trigOp(pTrig) == @as(u8, @intCast(TK_RETURNING & 0xff))) {
            // RETURNING pseudo-trigger: bind to this table.
            trigSetTable(pTrig, tabZName(pTab));
            trigSetPTabSchema(pTrig, tabPSchema(pTab));
            trigSetPNext(pTrig, pList);
            pList = pTrig;
        }
        p = hashElemNext(entry);
    }
    return pList;
}

// ═══ sqlite3BeginTrigger ═════════════════════════════════════════════════════
export fn sqlite3BeginTrigger(
    pParse: ?*anyopaque,
    pName1: ?*const Token,
    pName2: ?*const Token,
    tr_tm_in: c_int,
    op: c_int,
    pColumns_in: ?*anyopaque,
    pTableName_in: ?*anyopaque,
    pWhen_in: ?*anyopaque,
    isTemp: c_int,
    noErr: c_int,
) callconv(.c) void {
    var tr_tm = tr_tm_in;
    var pColumns = pColumns_in;
    const pTableName = pTableName_in;
    var pWhen = pWhen_in;
    var pTrigger: ?*anyopaque = null;
    var zName: ?[*:0]u8 = null;
    const db = pDb(pParse);
    var iDb: c_int = undefined;
    var pName: ?*const Token = undefined;
    var sFix: [sizeof_DbFixer]u8 align(8) = undefined;

    // local cleanup helper inlined via labeled blocks
    const Cleanup = struct {
        fn run(db_: ?*anyopaque, pParse_: ?*anyopaque, zName_: ?[*:0]u8, pTableName_: ?*anyopaque, pColumns_: ?*anyopaque, pWhen_: ?*anyopaque, pTrigger_: ?*anyopaque) void {
            sqlite3DbFree(db_, @ptrCast(zName_));
            sqlite3SrcListDelete(db_, pTableName_);
            sqlite3IdListDelete(db_, pColumns_);
            sqlite3ExprDelete(db_, pWhen_);
            if (pPNewTrigger(pParse_) == null) {
                sqlite3DeleteTrigger(db_, pTrigger_);
            }
        }
    };

    if (isTemp != 0) {
        if (pName2.?.n > 0) {
            sqlite3ErrorMsg(pParse, "temporary trigger may not have qualified name");
            Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
            return;
        }
        iDb = 1;
        pName = pName1;
    } else {
        iDb = sqlite3TwoPartName(pParse, pName1, pName2, &pName);
        if (iDb < 0) {
            Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
            return;
        }
    }
    if (pTableName == null or dbMallocFailed(db)) {
        Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
        return;
    }

    // Long-standing parser-bug compat: strip schema name when reparsing.
    if (dbInitBusy(db) != 0 and iDb != 1) {
        const it0 = srcItemAt(pTableName, 0);
        sqlite3DbFree(db, @ptrCast(@constCast(itemU4ZDatabase(it0))));
        itemSetU4ZDatabase(it0, null);
    }

    var pTab = sqlite3SrcListLookup(pParse, pTableName);
    if (dbInitBusy(db) == 0 and pName2.?.n == 0 and pTab != null and
        tabPSchema(pTab) == dbAtPSchema(db, 1))
    {
        iDb = 1;
    }

    if (dbMallocFailed(db)) {
        Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
        return;
    }
    sqlite3FixInit(&sFix, pParse, iDb, "trigger", pName);
    if (sqlite3FixSrcList(&sFix, pTableName) != 0) {
        Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
        return;
    }
    pTab = sqlite3SrcListLookup(pParse, pTableName);

    // orphan-error path is shared via a flag; emulate the C goto labels.
    var orphan = false;
    blk: {
        if (pTab == null) {
            orphan = true;
            break :blk;
        }
        if (isVirtual(pTab)) {
            sqlite3ErrorMsg(pParse, "cannot create triggers on virtual tables");
            orphan = true;
            break :blk;
        }
        if ((tabTabFlags(pTab) & TF_Shadow) != 0 and sqlite3ReadOnlyShadowTables(db) != 0) {
            sqlite3ErrorMsg(pParse, "cannot create triggers on shadow tables");
            orphan = true;
            break :blk;
        }

        zName = sqlite3NameFromToken(db, pName);
        if (zName == null) {
            Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
            return;
        }
        if (sqlite3CheckObjectName(pParse, zName, "trigger", tabZName(pTab)) != 0) {
            Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
            return;
        }
        if (!inRenameObject(pParse)) {
            const pSchema = dbAtPSchema(db, iDb);
            if (sqlite3HashFind(schemaTrigHash(pSchema), zName) != null) {
                if (noErr == 0) {
                    sqlite3ErrorMsg(pParse, "trigger %T already exists", pName);
                } else {
                    sqlite3CodeVerifySchema(pParse, iDb);
                    if (config.sqlite_debug) {
                        base(pParse)[Parse_ifNotExists_off] = 1;
                    }
                }
                Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
                return;
            }
        }

        // Do not create a trigger on a system table (sqlite_*).
        if (strniCmp7(tabZName(pTab), "sqlite_")) {
            sqlite3ErrorMsg(pParse, "cannot create trigger on system table");
            Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
            return;
        }

        // INSTEAD OF only on views; views only support INSTEAD OF.
        if (isView(pTab) and tr_tm != TK_INSTEAD) {
            sqlite3ErrorMsg(pParse, "cannot create %s trigger on view: %S", if (tr_tm == TK_BEFORE) @as([*:0]const u8, "BEFORE") else @as([*:0]const u8, "AFTER"), srcItemAt(pTableName, 0));
            orphan = true;
            break :blk;
        }
        if (!isView(pTab) and tr_tm == TK_INSTEAD) {
            sqlite3ErrorMsg(pParse, "cannot create INSTEAD OF trigger on table: %S", srcItemAt(pTableName, 0));
            orphan = true;
            break :blk;
        }

        if (!inRenameObject(pParse)) {
            const iTabDb = sqlite3SchemaToIndex(db, tabPSchema(pTab));
            var code: c_int = SQLITE_CREATE_TRIGGER;
            const zDb = dbAtZDbSName(db, iTabDb);
            const zDbTrig = if (isTemp != 0) dbAtZDbSName(db, 1) else zDb;
            if (iTabDb == 1 or isTemp != 0) code = SQLITE_CREATE_TEMP_TRIGGER;
            if (sqlite3AuthCheck(pParse, code, zName, tabZName(pTab), zDbTrig) != 0) {
                Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
                return;
            }
            if (sqlite3AuthCheck(pParse, SQLITE_INSERT, schemaTableName(iTabDb), null, zDb) != 0) {
                Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
                return;
            }
        }

        // Translate INSTEAD OF -> BEFORE.
        if (tr_tm == TK_INSTEAD) tr_tm = TK_BEFORE;

        // Build the Trigger object.
        pTrigger = sqlite3DbMallocZero(db, sizeof_Trigger);
        if (pTrigger == null) {
            Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
            return;
        }
        trigSetZName(pTrigger, zName);
        zName = null;
        trigSetTable(pTrigger, sqlite3DbStrDup(db, itemZName(srcItemAt(pTableName, 0))));
        trigSetPSchema(pTrigger, dbAtPSchema(db, iDb));
        trigSetPTabSchema(pTrigger, tabPSchema(pTab));
        trigSetOp(pTrigger, @truncate(@as(c_uint, @bitCast(op))));
        trigSetTrTm(pTrigger, if (tr_tm == TK_BEFORE) TRIGGER_BEFORE else TRIGGER_AFTER);
        if (inRenameObject(pParse)) {
            sqlite3RenameTokenRemap(pParse, trigTable(pTrigger), itemZName(srcItemAt(pTableName, 0)));
            trigSetPWhen(pTrigger, pWhen);
            pWhen = null;
        } else {
            trigSetPWhen(pTrigger, sqlite3ExprDup(db, pWhen, EXPRDUP_REDUCE));
        }
        trigSetPColumns(pTrigger, pColumns);
        pColumns = null;
        pSetPNewTrigger(pParse, pTrigger);
    }

    if (orphan) {
        // trigger_orphan_error
        if (dbInitIDb(db) == 1) {
            dbSetOrphanTrigger(db);
        }
    }
    Cleanup.run(db, pParse, zName, pTableName, pColumns, pWhen, pTrigger);
}

// helper: db->aDb[i].zDbSName
inline fn dbAtZDbSName(db: ?*anyopaque, i: c_int) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, dbAt(db, i), Db_zDbSName_off);
}
// helper: SCHEMA_TABLE(x) (OMIT_TEMPDB=0): x==1 ? temp-schema : legacy-schema.
inline fn schemaTableName(x: c_int) ?[*:0]const u8 {
    return if (x == 1) @as([*:0]const u8, "sqlite_temp_master") else LEGACY_SCHEMA_TABLE;
}
// helper: 0==sqlite3StrNICmp(z, "sqlite_", 7)  (sqlite3StrNICmp is a macro for
// sqlite3_strnicmp).
extern fn sqlite3_strnicmp(a: ?[*:0]const u8, b: ?[*:0]const u8, n: c_int) c_int;
inline fn strniCmp7(z: ?[*:0]const u8, lit: [*:0]const u8) bool {
    return sqlite3_strnicmp(z, lit, 7) == 0;
}

// ═══ sqlite3FinishTrigger ════════════════════════════════════════════════════
export fn sqlite3FinishTrigger(
    pParse: ?*anyopaque,
    pStepList_in: ?*anyopaque,
    pAll: ?*const Token,
) callconv(.c) void {
    var pStepList = pStepList_in;
    var pTrig = pPNewTrigger(pParse);
    const db = pDb(pParse);
    var sFix: [sizeof_DbFixer]u8 align(8) = undefined;
    var nameToken: Token = undefined;

    pSetPNewTrigger(pParse, null);

    finish: {
        if (pNErr(pParse) != 0 or pTrig == null) break :finish;
        const zName = trigZName(pTrig);
        const iDb = sqlite3SchemaToIndex(db, trigPSchema(pTrig));
        trigSetStepList(pTrig, pStepList);
        // The steps now belong to pTrig; consume the local pStepList to NULL so
        // the triggerfinish_cleanup below does not double-free the chain (C does
        // this by advancing the `pStepList` local in this same loop).
        while (pStepList) |pStep| {
            stepSetPTrig(pStep, pTrig);
            pStepList = stepPNext(pStep);
        }
        sqlite3TokenInit(&nameToken, @ptrCast(trigZName(pTrig)));
        sqlite3FixInit(&sFix, pParse, iDb, "trigger", &nameToken);
        if (sqlite3FixTriggerStep(&sFix, trigStepList(pTrig)) != 0 or
            sqlite3FixExpr(&sFix, trigPWhen(pTrig)) != 0)
        {
            break :finish;
        }

        // SQLITE_OMIT_ALTERTABLE is OFF.
        if (inRenameObject(pParse)) {
            pSetPNewTrigger(pParse, pTrig);
            pTrig = null;
        } else if (dbInitBusy(db) == 0) {
            // Build the sqlite_schema entry.
            if (sqlite3ReadOnlyShadowTables(db) != 0) {
                var pStep = trigStepList(pTrig);
                while (pStep) |st| {
                    const pSrc = stepPSrc(st);
                    if (pSrc != null and
                        sqlite3ShadowTableName(db, itemZName(srcItemAt(pSrc, 0))) != 0)
                    {
                        sqlite3ErrorMsg(pParse, "trigger \"%s\" may not write to shadow table \"%s\"", trigZName(pTrig), itemZName(srcItemAt(pSrc, 0)));
                        break :finish;
                    }
                    pStep = stepPNext(st);
                }
            }

            const v = sqlite3GetVdbe(pParse);
            if (v == null) break :finish;
            sqlite3BeginWriteOperation(pParse, 0, iDb);
            const z = sqlite3DbStrNDup(db, @ptrCast(pAll.?.z), pAll.?.n);
            sqlite3NestedParse(pParse, "INSERT INTO %Q.\"sqlite_master\" VALUES('trigger',%Q,%Q,0,'CREATE TRIGGER %q')", dbAtZDbSName(db, iDb), zName, trigTable(pTrig), z);
            sqlite3DbFree(db, @ptrCast(z));
            sqlite3ChangeCookie(pParse, iDb);
            sqlite3VdbeAddParseSchemaOp(v, iDb, sqlite3MPrintf(db, "type='trigger' AND name='%q'", zName), 0);
        }

        if (dbInitBusy(db) != 0) {
            const pLink = pTrig;
            const pHash = schemaTrigHash(dbAtPSchema(db, iDb));
            const prev = sqlite3HashInsert(pHash, zName, pTrig);
            pTrig = prev;
            if (pTrig != null) {
                _ = sqlite3OomFault(db);
            } else if (trigPSchema(pLink) == trigPTabSchema(pLink)) {
                const pTab = sqlite3HashFind(schemaTblHash(trigPTabSchema(pLink)), trigTable(pLink));
                trigSetPNext(pLink, tabPTrigger(pTab));
                tabSetPTrigger(pTab, pLink);
            }
        }
    }

    // triggerfinish_cleanup
    sqlite3DeleteTrigger(db, pTrig);
    sqlite3DeleteTriggerStep(db, pStepList);
    pStepList = null;
}

// ═══ triggerSpanDup (static) ═════════════════════════════════════════════════
fn triggerSpanDup(db: ?*anyopaque, zStart: ?[*]const u8, zEnd: ?[*]const u8) ?[*:0]u8 {
    const z = sqlite3DbSpanDup(db, zStart, zEnd);
    if (z) |zz| {
        var i: usize = 0;
        while (zz[i] != 0) : (i += 1) {
            if (sqlite3Isspace(zz[i]) != 0) zz[i] = ' ';
        }
    }
    return z;
}

// ═══ sqlite3TriggerSelectStep ════════════════════════════════════════════════
export fn sqlite3TriggerSelectStep(
    db: ?*anyopaque,
    pSelect: ?*anyopaque,
    zStart: ?[*]const u8,
    zEnd: ?[*]const u8,
) callconv(.c) ?*anyopaque {
    const pTriggerStep = sqlite3DbMallocZero(db, sizeof_TriggerStep);
    if (pTriggerStep == null) {
        sqlite3SelectDelete(db, pSelect);
        return null;
    }
    stepSetOp(pTriggerStep, @intCast(TK_SELECT));
    stepSetPSelect(pTriggerStep, pSelect);
    stepSetOrconf(pTriggerStep, OE_Default);
    stepSetZSpan(pTriggerStep, triggerSpanDup(db, zStart, zEnd));
    return pTriggerStep;
}

// ═══ triggerStepAllocate (static) ════════════════════════════════════════════
fn triggerStepAllocate(
    pParse: ?*anyopaque,
    op: u8,
    pTabList: ?*anyopaque,
    zStart: ?[*]const u8,
    zEnd: ?[*]const u8,
) ?*anyopaque {
    const pNew = pPNewTrigger(pParse);
    const db = pDb(pParse);
    var pTriggerStep: ?*anyopaque = null;

    if (pNErr(pParse) == 0) {
        if (pNew != null and
            trigPSchema(pNew) != dbAtPSchema(db, 1) and
            itemU4ZDatabase(srcItemAt(pTabList, 0)) != null)
        {
            sqlite3ErrorMsg(pParse, "qualified table names are not allowed on INSERT, UPDATE, and DELETE statements within triggers");
        } else {
            pTriggerStep = sqlite3DbMallocZero(db, sizeof_TriggerStep);
            if (pTriggerStep) |st| {
                stepSetPSrc(st, sqlite3SrcListDup(db, pTabList, EXPRDUP_REDUCE));
                stepSetOp(st, op);
                stepSetZSpan(st, triggerSpanDup(db, zStart, zEnd));
                if (stepPSrc(st) != null and inRenameObject(pParse)) {
                    sqlite3RenameTokenRemap(pParse, itemZName(srcItemAt(stepPSrc(st), 0)), itemZName(srcItemAt(pTabList, 0)));
                }
            }
        }
    }

    sqlite3SrcListDelete(db, pTabList);
    return pTriggerStep;
}

// ═══ sqlite3TriggerInsertStep ════════════════════════════════════════════════
export fn sqlite3TriggerInsertStep(
    pParse: ?*anyopaque,
    pTabList: ?*anyopaque,
    pColumn: ?*anyopaque,
    pSelect_in: ?*anyopaque,
    orconf: u8,
    pUpsert: ?*anyopaque,
    zStart: ?[*]const u8,
    zEnd: ?[*]const u8,
) callconv(.c) ?*anyopaque {
    var pSelect = pSelect_in;
    const db = pDb(pParse);

    const pTriggerStep = triggerStepAllocate(pParse, @intCast(TK_INSERT), pTabList, zStart, zEnd);
    if (pTriggerStep) |st| {
        if (inRenameObject(pParse)) {
            stepSetPSelect(st, pSelect);
            pSelect = null;
        } else {
            stepSetPSelect(st, sqlite3SelectDup(db, pSelect, EXPRDUP_REDUCE));
        }
        stepSetPIdList(st, pColumn);
        stepSetPUpsert(st, pUpsert);
        stepSetOrconf(st, orconf);
        if (pUpsert) |up| {
            // pUpsert->pUpsertTarget is the first field of Upsert (offset 0).
            _ = sqlite3HasExplicitNulls(pParse, rdPtr(?*anyopaque, up, 0));
        }
    } else {
        sqlite3IdListDelete(db, pColumn);
        sqlite3UpsertDelete(db, pUpsert);
    }
    sqlite3SelectDelete(db, pSelect);

    return pTriggerStep;
}

// ═══ sqlite3TriggerUpdateStep ════════════════════════════════════════════════
export fn sqlite3TriggerUpdateStep(
    pParse: ?*anyopaque,
    pTabList: ?*anyopaque,
    pFrom_in: ?*anyopaque,
    pEList_in: ?*anyopaque,
    pWhere_in: ?*anyopaque,
    orconf: u8,
    zStart: ?[*]const u8,
    zEnd: ?[*]const u8,
) callconv(.c) ?*anyopaque {
    var pFrom = pFrom_in;
    var pEList = pEList_in;
    var pWhere = pWhere_in;
    const db = pDb(pParse);

    const pTriggerStep = triggerStepAllocate(pParse, @intCast(TK_UPDATE), pTabList, zStart, zEnd);
    if (pTriggerStep) |st| {
        var pFromDup: ?*anyopaque = null;
        if (inRenameObject(pParse)) {
            stepSetPExprList(st, pEList);
            stepSetPWhere(st, pWhere);
            pFromDup = pFrom;
            pEList = null;
            pWhere = null;
            pFrom = null;
        } else {
            stepSetPExprList(st, sqlite3ExprListDup(db, pEList, EXPRDUP_REDUCE));
            stepSetPWhere(st, sqlite3ExprDup(db, pWhere, EXPRDUP_REDUCE));
            pFromDup = sqlite3SrcListDup(db, pFrom, EXPRDUP_REDUCE);
        }
        stepSetOrconf(st, orconf);

        if (pFromDup != null and !inRenameObject(pParse)) {
            var as_tok: Token = .{ .z = null, .n = 0 };
            const pSub = sqlite3SelectNew(pParse, null, pFromDup, null, null, null, null, SF_NestedFrom, null);
            pFromDup = sqlite3SrcListAppendFromTerm(pParse, null, null, null, &as_tok, pSub, null);
        }
        if (pFromDup != null and stepPSrc(st) != null) {
            stepSetPSrc(st, sqlite3SrcListAppendList(pParse, stepPSrc(st), pFromDup));
        } else {
            sqlite3SrcListDelete(db, pFromDup);
        }
    }
    sqlite3ExprListDelete(db, pEList);
    sqlite3ExprDelete(db, pWhere);
    sqlite3SrcListDelete(db, pFrom);
    return pTriggerStep;
}

// ═══ sqlite3TriggerDeleteStep ════════════════════════════════════════════════
export fn sqlite3TriggerDeleteStep(
    pParse: ?*anyopaque,
    pTabList: ?*anyopaque,
    pWhere_in: ?*anyopaque,
    zStart: ?[*]const u8,
    zEnd: ?[*]const u8,
) callconv(.c) ?*anyopaque {
    var pWhere = pWhere_in;
    const db = pDb(pParse);

    const pTriggerStep = triggerStepAllocate(pParse, @intCast(TK_DELETE), pTabList, zStart, zEnd);
    if (pTriggerStep) |st| {
        if (inRenameObject(pParse)) {
            stepSetPWhere(st, pWhere);
            pWhere = null;
        } else {
            stepSetPWhere(st, sqlite3ExprDup(db, pWhere, EXPRDUP_REDUCE));
        }
        stepSetOrconf(st, OE_Default);
    }
    sqlite3ExprDelete(db, pWhere);
    return pTriggerStep;
}

// ═══ sqlite3DeleteTrigger (DEFINED here) ═════════════════════════════════════
export fn sqlite3DeleteTrigger(db: ?*anyopaque, pTrigger: ?*anyopaque) callconv(.c) void {
    if (pTrigger == null or trigBReturning(pTrigger) != 0) return;
    sqlite3DeleteTriggerStep(db, trigStepList(pTrigger));
    sqlite3DbFree(db, @ptrCast(trigZName(pTrigger)));
    sqlite3DbFree(db, @ptrCast(@constCast(trigTable(pTrigger))));
    sqlite3ExprDelete(db, trigPWhen(pTrigger));
    sqlite3IdListDelete(db, trigPColumns(pTrigger));
    sqlite3DbFree(db, pTrigger);
}

// ═══ sqlite3DropTrigger ══════════════════════════════════════════════════════
export fn sqlite3DropTrigger(pParse: ?*anyopaque, pName: ?*anyopaque, noErr: c_int) callconv(.c) void {
    const db = pDb(pParse);
    var pTrigger: ?*anyopaque = null;

    cleanup: {
        if (dbMallocFailed(db)) break :cleanup;
        if (sqlite3ReadSchema(pParse) != SQLITE_OK) break :cleanup;

        const it0 = srcItemAt(pName, 0);
        const zDb = itemU4ZDatabase(it0);
        const zName = itemZName(it0);
        var i: c_int = OMIT_TEMPDB;
        while (i < dbNDb(db)) : (i += 1) {
            const j = if (i < 2) (i ^ 1) else i; // search TEMP before MAIN
            if (zDb != null and sqlite3DbIsNamed(db, j, zDb) == 0) continue;
            pTrigger = sqlite3HashFind(schemaTrigHash(dbAtPSchema(db, j)), zName);
            if (pTrigger != null) break;
        }
        if (pTrigger == null) {
            if (noErr == 0) {
                sqlite3ErrorMsg(pParse, "no such trigger: %S", it0);
            } else {
                sqlite3CodeVerifyNamedSchema(pParse, zDb);
            }
            pSetCheckSchema(pParse);
            break :cleanup;
        }
        sqlite3DropTriggerPtr(pParse, pTrigger);
    }
    sqlite3SrcListDelete(db, pName);
}

// ═══ tableOfTrigger (static) ═════════════════════════════════════════════════
fn tableOfTrigger(pTrigger: ?*anyopaque) ?*anyopaque {
    return sqlite3HashFind(schemaTblHash(trigPTabSchema(pTrigger)), trigTable(pTrigger));
}

// ═══ sqlite3DropTriggerPtr ═══════════════════════════════════════════════════
export fn sqlite3DropTriggerPtr(pParse: ?*anyopaque, pTrigger: ?*anyopaque) callconv(.c) void {
    const db = pDb(pParse);
    const iDb = sqlite3SchemaToIndex(db, trigPSchema(pTrigger));
    const pTable = tableOfTrigger(pTrigger);

    // SQLITE_OMIT_AUTHORIZATION is OFF.
    if (pTable != null) {
        var code: c_int = SQLITE_DROP_TRIGGER;
        const zDb = dbAtZDbSName(db, iDb);
        const zTab = schemaTableName(iDb);
        if (iDb == 1) code = SQLITE_DROP_TEMP_TRIGGER;
        if (sqlite3AuthCheck(pParse, code, trigZName(pTrigger), tabZName(pTable), zDb) != 0 or
            sqlite3AuthCheck(pParse, SQLITE_DELETE, zTab, null, zDb) != 0)
        {
            return;
        }
    }

    const v = sqlite3GetVdbe(pParse);
    if (v != null) {
        sqlite3NestedParse(pParse, "DELETE FROM %Q.\"sqlite_master\" WHERE name=%Q AND type='trigger'", dbAtZDbSName(db, iDb), trigZName(pTrigger));
        sqlite3ChangeCookie(pParse, iDb);
        _ = sqlite3VdbeAddOp4(v, OP_DropTrigger, iDb, 0, 0, @ptrCast(trigZName(pTrigger)), 0);
    }
}

// ═══ sqlite3UnlinkAndDeleteTrigger ═══════════════════════════════════════════
export fn sqlite3UnlinkAndDeleteTrigger(db: ?*anyopaque, iDb: c_int, zName: ?[*:0]const u8) callconv(.c) void {
    const pHash = schemaTrigHash(dbAtPSchema(db, iDb));
    const pTrigger = sqlite3HashInsert(pHash, zName, null);
    if (pTrigger != null) {
        if (trigPSchema(pTrigger) == trigPTabSchema(pTrigger)) {
            const pTab = tableOfTrigger(pTrigger);
            if (pTab != null) {
                // pp = &pTab->pTrigger; walk the singly-linked list.
                var ppHolder = pTab; // base for the first link
                var ppOff = Table_pTrigger_off;
                while (true) {
                    const cur = rdPtr(?*anyopaque, ppHolder, ppOff);
                    if (cur == null) break;
                    if (cur == pTrigger) {
                        wrPtr(?*anyopaque, ppHolder, ppOff, trigPNext(cur));
                        break;
                    }
                    ppHolder = cur;
                    ppOff = Trigger_pNext_off;
                }
            }
        }
        sqlite3DeleteTrigger(db, pTrigger);
        dbSetMDbFlags(db, dbMDbFlags(db) | DBFLAG_SchemaChange);
    }
}

// ═══ checkColumnOverlap (static) ═════════════════════════════════════════════
fn checkColumnOverlap(pIdList: ?*anyopaque, pEList: ?*anyopaque) c_int {
    if (pIdList == null or pEList == null) return 1;
    var e: c_int = 0;
    const n = elNExpr(pEList);
    while (e < n) : (e += 1) {
        if (sqlite3IdListIndex(pIdList, itemZEName(elItemAt(pEList, e))) >= 0) return 1;
    }
    return 0;
}

// ═══ tempTriggersExist (static) ══════════════════════════════════════════════
fn tempTriggersExist(db: ?*anyopaque) bool {
    const pSchema = dbAtPSchema(db, 1);
    if (pSchema == null) return false;
    if (hashFirst(schemaTrigHash(pSchema)) == null) return false;
    return true;
}

// ═══ triggersReallyExist (static) ════════════════════════════════════════════
fn triggersReallyExist(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    op: c_int,
    pChanges: ?*anyopaque,
    pMask: ?*c_int,
) ?*anyopaque {
    var mask: c_int = 0;
    var pList = sqlite3TriggerList(pParse, pTab);
    const db = pDb(pParse);

    if (pList != null) {
        var p = pList;
        if ((dbFlags(db) & SQLITE_EnableTrigger) == 0 and
            tabPTrigger(pTab) != null and
            sqlite3SchemaToIndex(db, trigPSchema(tabPTrigger(pTab))) != 1)
        {
            // Only TEMP triggers allowed; truncate pList to the TEMP triggers.
            if (pList == tabPTrigger(pTab)) {
                pList = null;
                if (pMask) |m| m.* = mask;
                return null;
            }
            while (trigPNext(p) != null and trigPNext(p) != tabPTrigger(pTab)) {
                p = trigPNext(p);
            }
            trigSetPNext(p, null);
            p = pList;
        }
        while (true) {
            if (trigOp(p) == @as(u8, @intCast(op & 0xff)) and checkColumnOverlap(trigPColumns(p), pChanges) != 0) {
                mask |= trigTrTm(p);
            } else if (trigOp(p) == @as(u8, @intCast(TK_RETURNING & 0xff))) {
                trigSetOp(p, @intCast(op & 0xff));
                if (isVirtual(pTab)) {
                    if (op != TK_INSERT) {
                        sqlite3ErrorMsg(pParse, "%s RETURNING is not available on virtual tables", if (op == TK_DELETE) @as([*:0]const u8, "DELETE") else @as([*:0]const u8, "UPDATE"));
                    }
                    trigSetTrTm(p, TRIGGER_BEFORE);
                } else {
                    trigSetTrTm(p, TRIGGER_AFTER);
                }
                mask |= trigTrTm(p);
            } else if (trigBReturning(p) != 0 and trigOp(p) == @as(u8, @intCast(TK_INSERT & 0xff)) and op == TK_UPDATE and isToplevel(pParse)) {
                mask |= trigTrTm(p);
            }
            p = trigPNext(p);
            if (p == null) break;
        }
    }
    if (pMask) |m| m.* = mask;
    return if (mask != 0) pList else null;
}

// ═══ sqlite3TriggersExist ════════════════════════════════════════════════════
export fn sqlite3TriggersExist(
    pParse: ?*anyopaque,
    pTab: ?*anyopaque,
    op: c_int,
    pChanges: ?*anyopaque,
    pMask: ?*c_int,
) callconv(.c) ?*anyopaque {
    const db = pDb(pParse);
    if ((tabPTrigger(pTab) == null and !tempTriggersExist(db)) or
        pDisableTriggers(pParse))
    {
        if (pMask) |m| m.* = 0;
        return null;
    }
    return triggersReallyExist(pParse, pTab, op, pChanges, pMask);
}

// ═══ isAsteriskTerm (static) ═════════════════════════════════════════════════
fn isAsteriskTerm(pParse: ?*anyopaque, pTerm: ?*anyopaque) c_int {
    if (exprOp(pTerm) == @as(u8, @intCast(TK_ASTERISK & 0xff))) return 1;
    if (exprOp(pTerm) != @as(u8, @intCast(TK_DOT & 0xff))) return 0;
    if (exprOp(exprPRight(pTerm)) != @as(u8, @intCast(TK_ASTERISK & 0xff))) return 0;
    sqlite3ErrorMsg(pParse, "RETURNING may not use \"TABLE.*\" wildcards");
    return 1;
}

// ═══ sqlite3ExpandReturning (static) ═════════════════════════════════════════
fn sqlite3ExpandReturning(pParse: ?*anyopaque, pList: ?*anyopaque, pTab: ?*anyopaque) ?*anyopaque {
    var pNew: ?*anyopaque = null;
    const db = pDb(pParse);
    var i: c_int = 0;
    const n = elNExpr(pList);
    while (i < n) : (i += 1) {
        const pOldExpr = itemPExpr(elItemAt(pList, i));
        if (pOldExpr == null) continue;
        if (isAsteriskTerm(pParse, pOldExpr) != 0) {
            var jj: c_int = 0;
            const nc = tabNCol(pTab);
            while (jj < nc) : (jj += 1) {
                const col = tabAColAt(pTab, jj);
                if (colIsHidden(col)) continue;
                const pNewExpr = sqlite3Expr(db, TK_ID, colZCnName(col));
                pNew = sqlite3ExprListAppend(pParse, pNew, pNewExpr);
                if (!dbMallocFailed(db)) {
                    const pItem = elItemAt(pNew, elNExpr(pNew) - 1);
                    itemSetZEName(pItem, sqlite3DbStrDup(db, colZCnName(col)));
                    itemSetENameKind(pItem, ENAME_NAME);
                }
            }
        } else {
            const pNewExpr = sqlite3ExprDup(db, pOldExpr, 0);
            pNew = sqlite3ExprListAppend(pParse, pNew, pNewExpr);
            const srcItem = elItemAt(pList, i);
            if (!dbMallocFailed(db) and itemZEName(srcItem) != null) {
                const pItem = elItemAt(pNew, elNExpr(pNew) - 1);
                itemSetZEName(pItem, sqlite3DbStrDup(db, itemZEName(srcItem)));
                itemSetENameKind(pItem, itemENameKind(srcItem));
            }
        }
    }
    return pNew;
}

// ═══ Returning-subquery walker callbacks (static, callconv .c) ═══════════════
fn sqlite3ReturningSubqueryVarSelect(notUsed: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    _ = notUsed;
    if (exprUseXSelect(pExpr) and
        (selSelFlags(exprXSelect(pExpr)) & SF_Correlated) != 0)
    {
        exprSetFlags(pExpr, exprFlags(pExpr) | EP_VarSelect);
    }
    return WRC_Continue;
}

fn sqlite3ReturningSubqueryCorrelated(pWalker: ?*anyopaque, pSelect: ?*anyopaque) callconv(.c) c_int {
    const pSrc = selPSrc(pSelect);
    var i: c_int = 0;
    const n = srcNSrc(pSrc);
    while (i < n) : (i += 1) {
        if (itemPSTab(srcItemAt(pSrc, i)) == wUPTab(pWalker)) {
            selSetSelFlags(pSelect, selSelFlags(pSelect) | SF_Correlated);
            wSetECode(pWalker, 1);
            break;
        }
    }
    return WRC_Continue;
}

// ═══ sqlite3ProcessReturningSubqueries (static) ══════════════════════════════
fn sqlite3ProcessReturningSubqueries(pEList: ?*anyopaque, pTab: ?*anyopaque) void {
    var w: [sizeof_Walker]u8 align(8) = std.mem.zeroes([sizeof_Walker]u8);
    const wp: ?*anyopaque = @ptrCast(&w);
    wSetXExpr(wp, @ptrCast(&sqlite3ExprWalkNoop));
    wSetXSelect(wp, @ptrCast(&sqlite3ReturningSubqueryCorrelated));
    wSetUPTab(wp, pTab);
    _ = sqlite3WalkExprList(wp, pEList);
    if (wECode(wp) != 0) {
        wSetXExpr(wp, @ptrCast(&sqlite3ReturningSubqueryVarSelect));
        wSetXSelect(wp, @ptrCast(&sqlite3SelectWalkNoop));
        _ = sqlite3WalkExprList(wp, pEList);
    }
}

// ═══ codeReturningTrigger (static) ═══════════════════════════════════════════
fn codeReturningTrigger(pParse: ?*anyopaque, pTrigger: ?*anyopaque, pTab: ?*anyopaque, regIn: c_int) void {
    const v = pVdbe(pParse);
    const db = pDb(pParse);

    if (!pBReturning(pParse)) return;
    const pReturning = pU1(pParse); // u1.d.pReturning
    // pTrigger != &pReturning->retTrig ?
    const retTrigAddr: ?*anyopaque = fieldPtr(pReturning, Returning_retTrig_off);
    if (pTrigger != retTrigAddr) return;

    var sSelect: [sizeof_Select]u8 align(8) = std.mem.zeroes([sizeof_Select]u8);
    // uSrc: a SrcList header sized SZ_SRCLIST_1 (one a[] slot), zero-initialized.
    var uSrc: [SZ_SRCLIST_1]u8 align(8) = std.mem.zeroes([SZ_SRCLIST_1]u8);
    const ssel: ?*anyopaque = @ptrCast(&sSelect);
    const pFrom: ?*anyopaque = @ptrCast(&uSrc);

    selSetPEList(ssel, sqlite3ExprListDup(db, rdPtr(?*anyopaque, pReturning, Returning_pReturnEL_off), 0));
    selSetPSrc(ssel, pFrom);
    srcSetNSrc(pFrom, 1);
    const fi0 = srcItemAt(pFrom, 0);
    itemSetPSTab(fi0, pTab);
    itemSetZName(fi0, tabZName(pTab));
    itemSetICursor(fi0, -1);
    sqlite3SelectPrep(pParse, ssel, null);
    if (pNErr(pParse) == 0) {
        sqlite3GenerateColumnNames(pParse, ssel);
    }
    sqlite3ExprListDelete(db, selPEList(ssel));
    const pNew = sqlite3ExpandReturning(pParse, rdPtr(?*anyopaque, pReturning, Returning_pReturnEL_off), pTab);
    if (pNErr(pParse) == 0) {
        var sNC: [sizeof_NameContext]u8 align(8) = std.mem.zeroes([sizeof_NameContext]u8);
        const nc: ?*anyopaque = @ptrCast(&sNC);
        if (rdPtr(c_int, pReturning, Returning_nRetCol_off) == 0) {
            wrPtr(c_int, pReturning, Returning_nRetCol_off, elNExpr(pNew));
            wrPtr(c_int, pReturning, Returning_iRetCur_off, pNTab(pParse));
            pSetNTab(pParse, pNTab(pParse) + 1);
        }
        ncSetPParse(nc, pParse);
        ncSetUNCIBaseReg(nc, regIn);
        ncSetNCFlags(nc, NC_UBaseReg);
        pSetETriggerOp(pParse, trigOp(pTrigger));
        pSetPTriggerTab(pParse, pTab);
        if (sqlite3ResolveExprListNames(nc, pNew) == SQLITE_OK and !dbMallocFailed(db)) {
            var i: c_int = 0;
            const nCol = elNExpr(pNew);
            const reg = pNMem(pParse) + 1;
            sqlite3ProcessReturningSubqueries(pNew, pTab);
            pSetNMem(pParse, pNMem(pParse) + nCol + 2);
            wrPtr(c_int, pReturning, Returning_iRetReg_off, reg);
            while (i < nCol) : (i += 1) {
                const pCol = itemPExpr(elItemAt(pNew, i));
                sqlite3ExprCodeFactorable(pParse, pCol, reg + i);
                if (sqlite3ExprAffinity(pCol) == SQLITE_AFF_REAL) {
                    _ = sqlite3VdbeAddOp1(v, OP_RealAffinity, reg + i);
                }
            }
            _ = sqlite3VdbeAddOp3(v, OP_MakeRecord, reg, i, reg + i);
            _ = sqlite3VdbeAddOp2(v, OP_NewRowid, rdPtr(c_int, pReturning, Returning_iRetCur_off), reg + i + 1);
            _ = sqlite3VdbeAddOp3(v, OP_Insert, rdPtr(c_int, pReturning, Returning_iRetCur_off), reg + i, reg + i + 1);
        }
    }
    sqlite3ExprListDelete(db, pNew);
    pSetETriggerOp(pParse, 0);
    pSetPTriggerTab(pParse, null);
}

// ═══ codeTriggerProgram (static) ═════════════════════════════════════════════
fn codeTriggerProgram(pParse: ?*anyopaque, pStepList: ?*anyopaque, orconf: c_int) c_int {
    const v = pVdbe(pParse);
    const db = pDb(pParse);

    var pStep = pStepList;
    while (pStep) |st| {
        pSetEOrconf(pParse, if (orconf == OE_Default) stepOrconf(st) else @as(u8, @intCast(orconf & 0xff)));

        // SQLITE_OMIT_TRACE is OFF.
        if (stepZSpan(st) != null) {
            _ = sqlite3VdbeAddOp4(v, OP_Trace, 0x7fffffff, 1, 0, sqlite3MPrintf(db, "-- %s", stepZSpan(st)), P4_DYNAMIC);
        }

        switch (stepOp(st)) {
            @as(u8, @intCast(TK_UPDATE & 0xff)) => {
                sqlite3Update(pParse, sqlite3SrcListDup(db, stepPSrc(st), 0), sqlite3ExprListDup(db, stepPExprList(st), 0), sqlite3ExprDup(db, stepPWhere(st), 0), pEOrconf(pParse), null, null, null);
                _ = sqlite3VdbeAddOp0(v, OP_ResetCount);
            },
            @as(u8, @intCast(TK_INSERT & 0xff)) => {
                sqlite3Insert(pParse, sqlite3SrcListDup(db, stepPSrc(st), 0), sqlite3SelectDup(db, stepPSelect(st), 0), sqlite3IdListDup(db, stepPIdList(st)), pEOrconf(pParse), sqlite3UpsertDup(db, stepPUpsert(st)));
                _ = sqlite3VdbeAddOp0(v, OP_ResetCount);
            },
            @as(u8, @intCast(TK_DELETE & 0xff)) => {
                sqlite3DeleteFrom(pParse, sqlite3SrcListDup(db, stepPSrc(st), 0), sqlite3ExprDup(db, stepPWhere(st), 0), null, null);
                _ = sqlite3VdbeAddOp0(v, OP_ResetCount);
            },
            else => {
                // TK_SELECT
                var sDest: [sizeof_SelectDest]u8 align(8) = undefined;
                const pSelect = sqlite3SelectDup(db, stepPSelect(st), 0);
                sqlite3SelectDestInit(@ptrCast(&sDest), SRT_Discard, 0);
                _ = sqlite3Select(pParse, pSelect, @ptrCast(&sDest));
                sqlite3SelectDelete(db, pSelect);
            },
        }
        pStep = stepPNext(st);
    }
    return 0;
}

// ═══ transferParseError (static) ═════════════════════════════════════════════
fn transferParseError(pTo: ?*anyopaque, pFrom: ?*anyopaque) void {
    if (pNErr(pTo) == 0) {
        pSetZErrMsg(pTo, pZErrMsg(pFrom));
        pSetNErr(pTo, pNErr(pFrom));
        pSetRc(pTo, pRc(pFrom));
    } else {
        sqlite3DbFree(pDb(pFrom), @ptrCast(pZErrMsg(pFrom)));
    }
}

// ═══ codeRowTrigger (static) ═════════════════════════════════════════════════
fn codeRowTrigger(pParse: ?*anyopaque, pTrigger: ?*anyopaque, pTab: ?*anyopaque, orconf: c_int) ?*anyopaque {
    const db = pDb(pParse);
    var pWhen: ?*anyopaque = null;
    var iEndTrigger: c_int = 0;

    // Ensure triggers are not chained too deep.
    var pTop = pParse;
    var nDepth: c_int = 0;
    while (pPOuterParse(pTop)) |outer| {
        pTop = outer;
        nDepth += 1;
    }
    if (nDepth >= dbALimit(db, SQLITE_LIMIT_TRIGGER_DEPTH)) {
        sqlite3ErrorMsg(pParse, "triggers nested too deep");
        return null;
    }

    pTop = parseToplevel(pParse);

    // Allocate the TriggerPrg + SubProgram, linking into pTop->pTriggerPrg early.
    const pPrg = sqlite3DbMallocZero(db, sizeof_TriggerPrg);
    if (pPrg == null) return null;
    prgSetPNext(pPrg, pPTriggerPrg(pTop));
    pSetPTriggerPrg(pTop, pPrg);
    const pProgram = sqlite3DbMallocZero(db, sizeof_SubProgram);
    prgSetPProgram(pPrg, pProgram);
    if (pProgram == null) return null;
    sqlite3VdbeLinkSubProgram(pVdbe(pTop), pProgram);
    prgSetPTrigger(pPrg, pTrigger);
    prgSetOrconf(pPrg, orconf);
    prgSetColmask(pPrg, 0, 0xffffffff);
    prgSetColmask(pPrg, 1, 0xffffffff);

    // Allocate and populate a new Parse context for the sub-program. The full
    // struct Parse (416 bytes, config-invariant) is stack-allocated; ParseObjectInit
    // zeroes the relevant regions.
    var sSubParse: [sizeof_Parse]u8 align(16) = undefined;
    const sp: ?*anyopaque = @ptrCast(&sSubParse);
    sqlite3ParseObjectInit(sp, db);
    var sNC: [sizeof_NameContext]u8 align(8) = std.mem.zeroes([sizeof_NameContext]u8);
    const nc: ?*anyopaque = @ptrCast(&sNC);
    ncSetPParse(nc, sp);
    pSetPTriggerTab(sp, pTab);
    pSetPToplevel(sp, pTop);
    pSetZAuthContext(sp, @ptrCast(trigZName(pTrigger)));
    pSetETriggerOp(sp, trigOp(pTrigger));
    pSetNQueryLoop(sp, pNQueryLoop(pParse));
    pSetPrepFlags(sp, pPrepFlags(pParse));
    pSetOldmask(sp, 0);
    pSetNewmask(sp, 0);

    const v = sqlite3GetVdbe(sp);
    if (v != null) {
        // VdbeComment is debug-only; skipped (no behavioral effect).
        // SQLITE_OMIT_TRACE is OFF.
        if (trigZName(pTrigger) != null) {
            sqlite3VdbeChangeP4(v, -1, sqlite3MPrintf(db, "-- TRIGGER %s", trigZName(pTrigger)), P4_DYNAMIC);
        }

        if (trigPWhen(pTrigger) != null) {
            pWhen = sqlite3ExprDup(db, trigPWhen(pTrigger), 0);
            if (!dbMallocFailed(db) and sqlite3ResolveExprNames(nc, pWhen) == SQLITE_OK) {
                iEndTrigger = sqlite3VdbeMakeLabel(sp);
                sqlite3ExprIfFalse(sp, pWhen, iEndTrigger, SQLITE_JUMPIFNULL);
            }
            sqlite3ExprDelete(db, pWhen);
        }

        _ = codeTriggerProgram(sp, trigStepList(pTrigger), orconf);

        if (iEndTrigger != 0) {
            sqlite3VdbeResolveLabel(v, iEndTrigger);
        }
        _ = sqlite3VdbeAddOp0(v, OP_Halt);
        transferParseError(pParse, sp);

        if (pNErr(pParse) == 0) {
            const aOp = sqlite3VdbeTakeOpArray(v, subNOpPtr(pProgram), @ptrCast(base(pTop) + Parse_nMaxArg_off));
            subSetAOp(pProgram, aOp);
        }
        subSetNMem(pProgram, pNMem(sp));
        subSetNCsr(pProgram, pNTab(sp));
        subSetToken(pProgram, pTrigger);
        prgSetColmask(pPrg, 0, pOldmask(sp));
        prgSetColmask(pPrg, 1, pNewmask(sp));
        sqlite3VdbeDelete(v);
    } else {
        transferParseError(pParse, sp);
    }

    sqlite3ParseObjectReset(sp);
    return pPrg;
}

// ═══ getRowTrigger (static) ══════════════════════════════════════════════════
fn getRowTrigger(pParse: ?*anyopaque, pTrigger: ?*anyopaque, pTab: ?*anyopaque, orconf: c_int) ?*anyopaque {
    const pRoot = parseToplevel(pParse);
    var pPrg = pPTriggerPrg(pRoot);
    while (pPrg != null and (prgPTrigger(pPrg) != pTrigger or prgOrconf(pPrg) != orconf)) {
        pPrg = prgPNext(pPrg);
    }
    if (pPrg == null) {
        pPrg = codeRowTrigger(pParse, pTrigger, pTab, orconf);
        dbSetErrByteOffset(pDb(pParse), -1);
    }
    return pPrg;
}

// ═══ sqlite3CodeRowTriggerDirect ═════════════════════════════════════════════
export fn sqlite3CodeRowTriggerDirect(
    pParse: ?*anyopaque,
    p: ?*anyopaque,
    pTab: ?*anyopaque,
    reg: c_int,
    orconf: c_int,
    ignoreJump: c_int,
) callconv(.c) void {
    const v = sqlite3GetVdbe(pParse);
    const pPrg = getRowTrigger(pParse, p, pTab, orconf);

    if (pPrg != null) {
        const bRecursive: c_int = @intFromBool(trigZName(p) != null and (dbFlags(pDb(pParse)) & SQLITE_RecTriggers) == 0);
        pSetNMem(pParse, pNMem(pParse) + 1);
        _ = sqlite3VdbeAddOp4(v, OP_Program, reg, ignoreJump, pNMem(pParse), @ptrCast(prgPProgram(pPrg)), P4_SUBPROGRAM);
        sqlite3VdbeChangeP5(v, @truncate(@as(c_uint, @bitCast(bRecursive))));
    }
}

// ═══ sqlite3CodeRowTrigger ═══════════════════════════════════════════════════
export fn sqlite3CodeRowTrigger(
    pParse: ?*anyopaque,
    pTrigger: ?*anyopaque,
    op: c_int,
    pChanges: ?*anyopaque,
    tr_tm: c_int,
    pTab: ?*anyopaque,
    reg: c_int,
    orconf: c_int,
    ignoreJump: c_int,
) callconv(.c) void {
    var p = pTrigger;
    while (p) |pt| {
        if ((trigOp(pt) == @as(u8, @intCast(op & 0xff)) or (trigBReturning(pt) != 0 and trigOp(pt) == @as(u8, @intCast(TK_INSERT & 0xff)) and op == TK_UPDATE)) and
            trigTrTm(pt) == @as(u8, @intCast(tr_tm & 0xff)) and
            checkColumnOverlap(trigPColumns(pt), pChanges) != 0)
        {
            if (trigBReturning(pt) == 0) {
                sqlite3CodeRowTriggerDirect(pParse, pt, pTab, reg, orconf, ignoreJump);
            } else if (isToplevel(pParse)) {
                codeReturningTrigger(pParse, pt, pTab, reg);
            }
        }
        p = trigPNext(pt);
    }
}

// ═══ sqlite3TriggerColmask ═══════════════════════════════════════════════════
export fn sqlite3TriggerColmask(
    pParse: ?*anyopaque,
    pTrigger: ?*anyopaque,
    pChanges: ?*anyopaque,
    isNew: c_int,
    tr_tm: c_int,
    pTab: ?*anyopaque,
    orconf: c_int,
) callconv(.c) u32 {
    const op: c_int = if (pChanges != null) TK_UPDATE else TK_DELETE;
    var mask: u32 = 0;

    if (isView(pTab)) {
        return 0xffffffff;
    }
    var p = pTrigger;
    while (p) |pt| {
        if (trigOp(pt) == @as(u8, @intCast(op & 0xff)) and
            (tr_tm & trigTrTm(pt)) != 0 and
            checkColumnOverlap(trigPColumns(pt), pChanges) != 0)
        {
            if (trigBReturning(pt) != 0) {
                mask = 0xffffffff;
            } else {
                const pPrg = getRowTrigger(pParse, pt, pTab, orconf);
                if (pPrg != null) {
                    mask |= prgColmask(pPrg, @intCast(isNew));
                }
            }
        }
        p = trigPNext(pt);
    }
    return mask;
}

// ═══ comptime layout sanity ══════════════════════════════════════════════════
comptime {
    std.debug.assert(@sizeOf(Token) == 16);
}
