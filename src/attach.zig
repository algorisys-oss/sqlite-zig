//! Zig port of SQLite's src/attach.c — the ATTACH / DETACH DATABASE commands
//! and the DbFixer family of AST-walkers (sqlite3Fix*) that pin schema objects
//! to a single database.
//!
//! Exported (non-static) symbols — the complete external set of attach.c,
//! matching the prototypes in sqliteInt.h:
//!   - sqlite3DbIsNamed
//!   - sqlite3Attach          sqlite3Detach
//!   - sqlite3FixInit
//!   - sqlite3FixSrcList      sqlite3FixSelect     sqlite3FixExpr
//!   - sqlite3FixTriggerStep
//! The static helpers (resolveAttachExpr, attachFunc, detachFunc, codeAttach,
//! fixExprCb, fixSelectCb) are private to this module. The two SQL user
//! functions (attachFunc/detachFunc) are referenced by the FuncDef literals
//! built in sqlite3Attach/sqlite3Detach and dispatched by the VDBE; they keep
//! the C ABI (callconv(.c)) so the function-call opcode can invoke them.
//!
//! ─── Struct coupling / ground-truth offsets ────────────────────────────────
//! Every field offset used here was probe-verified with offsetof in BOTH the
//! production library config and the `--dev` testfixture (SQLITE_DEBUG +
//! SQLITE_TEST) config. ALL probed offsets are IDENTICAL across the two configs
//! (no divergence), including the SrcItem.fg bitfield byte/bit positions and
//! sqlite3.init.reopenMemdb.
//!
//!   sqlite3 : nDb@40 aDb@32 aDbStatic@688 aLimit@136 openFlags@76 pVfs@0
//!             flags@48 mDbFlags@44 mallocFailed@103 noSharedCache@111
//!             dfltLockMode@105 init@192 (init.iDb@196 init.busy@197
//!             init.reopenMemdb = byte 198 bit 0x08)
//!   Db      : zDbSName@0 pBt@8 safety_level@16 pSchema@24  (sizeof 32)
//!   DbFixer : pParse@0 w@8 pSchema@56 bTemp@64 zDb@72 zType@80 pName@88 (sz 96)
//!   Walker  : pParse@0 xExprCallback@8 xSelectCallback@16 xSelectCallback2@24
//!             walkerDepth@32 eCode@36 mWFlags@38 u@40  (sizeof 48)
//!   SrcList : nSrc@0 nAlloc@4 a@8
//!   SrcItem : zName@0 fg@24 u3@56 u4@64  (sizeof 72)
//!             fg bits: fromDDL=byte26/0x01 notCte=byte26/0x04 isUsing=byte26/0x08
//!                      isSubquery=byte25/0x04 fixedSchema=byte27/0x01
//!                      hadSchema=byte27/0x02
//!   Select  : pSrc@32 pWith@96  (sizeof 120)
//!   With    : nCte@0 a@16        Cte: pSelect@16 (sizeof 48)
//!   TriggerStep: pSelect@16 pSrc@24 pWhere@32 pExprList@40 pUpsert@56 pNext@72
//!   Trigger : pSchema@40 pTabSchema@48
//!   Upsert  : pUpsertTarget@0 pUpsertTargetWhere@8 pUpsertSet@16
//!             pUpsertWhere@24 pNextUpsert@32
//!   Expr    : op@0 flags@4 u@8     Schema: file_format@112 enc@113
//!   NameContext: pParse@0 (sizeof 56)   FuncDef: nArg@0 (sizeof 72)
//!
//! ─── Config assumptions (true in both this project's builds) ────────────────
//!   * SQLITE_OMIT_ATTACH       OFF → attach/detach codegen compiled.
//!   * SQLITE_OMIT_DESERIALIZE  OFF → REOPEN_AS_MEMDB reads init.reopenMemdb.
//!   * SQLITE_OMIT_AUTHORIZATION OFF → sqlite3AuthCheck in codeAttach.
//!   * SQLITE_OMIT_PAGER_PRAGMAS OFF → sqlite3BtreeSetPagerFlags in attachFunc.
//!   * SQLITE_OMIT_VIEW / SQLITE_OMIT_TRIGGER OFF → FixSelect/FixExpr/the ON
//!     clause walk and FixTriggerStep are compiled.
//!   * SQLITE_OMIT_UPSERT       OFF → upsert walk in FixTriggerStep.
//!   * SQLITE_ENABLE_SETLK_TIMEOUT OFF → the block-on-connect hint is omitted.
//!   * SQLITE_DEFAULT_SYNCHRONOUS == 2 → safety_level = 3.
//!   * Little-endian x86-64.
//!
//! Validated through the engine by the TCL suite (attach/attach2/attach3/attach4,
//! the view/trigger/alter fixers); no standalone Zig unit test is feasible —
//! every path couples to the live connection, parser, btree and VDBE.

const std = @import("std");
const c_layout = @import("c_layout.zig");
const config = @import("config");
const L = c_layout.c;

// ─── Result codes ───────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_BUSY: c_int = 5;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_IOERR_NOMEM: c_int = 10 | (12 << 8);

// ─── Text encodings ─────────────────────────────────────────────────────────
const SQLITE_UTF8: u8 = 1;

// ─── Open flags ─────────────────────────────────────────────────────────────
const SQLITE_OPEN_READONLY: u32 = 0x00000001;
const SQLITE_OPEN_READWRITE: u32 = 0x00000002;
const SQLITE_OPEN_CREATE: u32 = 0x00000004;
const SQLITE_OPEN_MAIN_DB: u32 = 0x00000100;

// ─── sqlite3.flags bits (HI(x) == (u64)x << 32) ─────────────────────────────
const SQLITE_AttachCreate: u64 = 0x00010 << 32;
const SQLITE_AttachWrite: u64 = 0x00020 << 32;

// ─── sqlite3.mDbFlags bits ──────────────────────────────────────────────────
const DBFLAG_SchemaKnownOk: u32 = 0x0010;

// ─── Pager flag masks ───────────────────────────────────────────────────────
const PAGER_SYNCHRONOUS_FULL: u8 = 0x03;
const PAGER_FLAGS_MASK: u64 = 0x38;

// ─── safety level / txn / authorizer / tokens / opcodes ─────────────────────
const SQLITE_DEFAULT_SYNCHRONOUS: c_int = 2;
const SQLITE_TXN_NONE: c_int = 0;
const SQLITE_ATTACH: c_int = 24;
const SQLITE_DETACH: c_int = 25;
const SQLITE_LIMIT_ATTACHED: usize = 7;

const TK_ID: u8 = 60;
const TK_STRING: u8 = 118;
const TK_NULL: u8 = 122;
const TK_VARIABLE: u8 = 157;

const EP_IntValue: u32 = 0x000800;
const EP_FromDDL: u32 = 0x40000000;

const WRC_Continue: c_int = 0;
const WRC_Abort: c_int = 2;

const OP_Expire: c_int = 168;

// ═══ ground-truth offsets ════════════════════════════════════════════════════
// Reuse c_layout entries where present, else the probe-verified fallback. All
// of these are identical in prod and tf.

// sqlite3
const sqlite3_nDb_off: usize = if (@hasDecl(L, "sqlite3_nDb")) L.sqlite3_nDb else 40;
const sqlite3_aDb_off: usize = if (@hasDecl(L, "sqlite3_aDb")) L.sqlite3_aDb else 32;
const sqlite3_aDbStatic_off: usize = if (@hasDecl(L, "sqlite3_aDbStatic")) L.sqlite3_aDbStatic else 688;
const sqlite3_aLimit_off: usize = if (@hasDecl(L, "sqlite3_aLimit")) L.sqlite3_aLimit else 136;
const sqlite3_openFlags_off: usize = if (@hasDecl(L, "sqlite3_openFlags")) L.sqlite3_openFlags else 76;
const sqlite3_pVfs_off: usize = if (@hasDecl(L, "sqlite3_pVfs")) L.sqlite3_pVfs else 0;
// sqlite3_vfs.zName (public ABI struct) — offset 24, config-invariant.
const sqlite3_vfs_zName_off: usize = if (@hasDecl(L, "sqlite3_vfs_zName")) L.sqlite3_vfs_zName else 24;
const sqlite3_flags_off: usize = if (@hasDecl(L, "sqlite3_flags")) L.sqlite3_flags else 48;
const sqlite3_mDbFlags_off: usize = if (@hasDecl(L, "sqlite3_mDbFlags")) L.sqlite3_mDbFlags else 44;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_noSharedCache_off: usize = if (@hasDecl(L, "sqlite3_noSharedCache")) L.sqlite3_noSharedCache else 111;
const sqlite3_dfltLockMode_off: usize = if (@hasDecl(L, "sqlite3_dfltLockMode")) L.sqlite3_dfltLockMode else 105;
const sqlite3_enc_off: usize = if (@hasDecl(L, "sqlite3_enc")) L.sqlite3_enc else 100;
const sqlite3_init_iDb_off: usize = if (@hasDecl(L, "sqlite3_init_iDb")) L.sqlite3_init_iDb else 196;
const sqlite3_initBusy_off: usize = if (@hasDecl(L, "sqlite3_initBusy")) L.sqlite3_initBusy else 197;
// init.reopenMemdb: byte 198, bit 0x08.
const sqlite3_init_bitbyte_off: usize = if (@hasDecl(L, "sqlite3_init_bitbyte")) L.sqlite3_init_bitbyte else 198;
const INIT_REOPEN_MEMDB_BIT: u8 = 0x08;

// Db
const Db_zDbSName_off: usize = if (@hasDecl(L, "Db_zDbSName")) L.Db_zDbSName else 0;
const Db_pBt_off: usize = if (@hasDecl(L, "Db_pBt")) L.Db_pBt else 8;
const Db_safety_level_off: usize = if (@hasDecl(L, "Db_safety_level")) L.Db_safety_level else 16;
const Db_pSchema_off: usize = if (@hasDecl(L, "Db_pSchema")) L.Db_pSchema else 24;
const sizeof_Db: usize = if (@hasDecl(L, "sizeof_Db")) L.sizeof_Db else 32;

// Parse — only db (offset 0) and nErr are read here.
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_nErr_off: usize = if (@hasDecl(L, "Parse_nErr")) L.Parse_nErr else 52;

// Schema
const Schema_file_format_off: usize = if (@hasDecl(L, "Schema_file_format")) L.Schema_file_format else 112;
const Schema_enc_off: usize = if (@hasDecl(L, "Schema_enc")) L.Schema_enc else 113;

// DbFixer (attach/auth-internal struct, mirrored field-for-field)
const DbFixer_w_off: usize = if (@hasDecl(L, "DbFixer_w")) L.DbFixer_w else 8;
const DbFixer_pSchema_off: usize = if (@hasDecl(L, "DbFixer_pSchema")) L.DbFixer_pSchema else 56;
const DbFixer_bTemp_off: usize = if (@hasDecl(L, "DbFixer_bTemp")) L.DbFixer_bTemp else 64;
const DbFixer_zDb_off: usize = if (@hasDecl(L, "DbFixer_zDb")) L.DbFixer_zDb else 72;
const DbFixer_zType_off: usize = if (@hasDecl(L, "DbFixer_zType")) L.DbFixer_zType else 80;
const DbFixer_pName_off: usize = if (@hasDecl(L, "DbFixer_pName")) L.DbFixer_pName else 88;

// Walker (ABI-shared AST walker)
const Walker_pParse_off: usize = if (@hasDecl(L, "Walker_pParse")) L.Walker_pParse else 0;
const Walker_xExprCallback_off: usize = if (@hasDecl(L, "Walker_xExprCallback")) L.Walker_xExprCallback else 8;
const Walker_xSelectCallback_off: usize = if (@hasDecl(L, "Walker_xSelectCallback")) L.Walker_xSelectCallback else 16;
const Walker_xSelectCallback2_off: usize = if (@hasDecl(L, "Walker_xSelectCallback2")) L.Walker_xSelectCallback2 else 24;
const Walker_walkerDepth_off: usize = if (@hasDecl(L, "Walker_walkerDepth")) L.Walker_walkerDepth else 32;
const Walker_eCode_off: usize = if (@hasDecl(L, "Walker_eCode")) L.Walker_eCode else 36;
const Walker_u_off: usize = if (@hasDecl(L, "Walker_u")) L.Walker_u else 40;

// SrcList / SrcItem (ABI-shared)
const SrcList_nSrc_off: usize = if (@hasDecl(L, "SrcList_nSrc")) L.SrcList_nSrc else 0;
const SrcList_a_off: usize = if (@hasDecl(L, "SrcList_a")) L.SrcList_a else 8;
const SrcItem_u3_off: usize = if (@hasDecl(L, "SrcItem_u3")) L.SrcItem_u3 else 56;
const SrcItem_u4_off: usize = if (@hasDecl(L, "SrcItem_u4")) L.SrcItem_u4 else 64;
const sizeof_SrcItem: usize = if (@hasDecl(L, "sizeof_SrcItem")) L.sizeof_SrcItem else 72;
// fg bitfield byte+bit positions (relative to the SrcItem base).
const SrcItem_fg_off: usize = if (@hasDecl(L, "SrcItem_fg")) L.SrcItem_fg else 24;
const FG_isSubquery_byte: usize = 25;
const FG_isSubquery_bit: u8 = 0x04;
const FG_fromDDL_byte: usize = 26;
const FG_fromDDL_bit: u8 = 0x01;
const FG_notCte_byte: usize = 26;
const FG_notCte_bit: u8 = 0x04;
const FG_isUsing_byte: usize = 26;
const FG_isUsing_bit: u8 = 0x08;
const FG_fixedSchema_byte: usize = 27;
const FG_fixedSchema_bit: u8 = 0x01;
const FG_hadSchema_byte: usize = 27;
const FG_hadSchema_bit: u8 = 0x02;

// Select / With / Cte
const Select_pSrc_off: usize = if (@hasDecl(L, "Select_pSrc")) L.Select_pSrc else 32;
const Select_pWith_off: usize = if (@hasDecl(L, "Select_pWith")) L.Select_pWith else 96;
const sizeof_Select: usize = if (@hasDecl(L, "sizeof_Select")) L.sizeof_Select else 120;
const With_nCte_off: usize = if (@hasDecl(L, "With_nCte")) L.With_nCte else 0;
const With_a_off: usize = if (@hasDecl(L, "With_a")) L.With_a else 16;
const sizeof_Cte: usize = if (@hasDecl(L, "sizeof_Cte")) L.sizeof_Cte else 48;
const Cte_pSelect_off: usize = if (@hasDecl(L, "Cte_pSelect")) L.Cte_pSelect else 16;

// TriggerStep / Trigger / Upsert
const TriggerStep_pSelect_off: usize = if (@hasDecl(L, "TriggerStep_pSelect")) L.TriggerStep_pSelect else 16;
const TriggerStep_pSrc_off: usize = if (@hasDecl(L, "TriggerStep_pSrc")) L.TriggerStep_pSrc else 24;
const TriggerStep_pWhere_off: usize = if (@hasDecl(L, "TriggerStep_pWhere")) L.TriggerStep_pWhere else 32;
const TriggerStep_pExprList_off: usize = if (@hasDecl(L, "TriggerStep_pExprList")) L.TriggerStep_pExprList else 40;
const TriggerStep_pUpsert_off: usize = if (@hasDecl(L, "TriggerStep_pUpsert")) L.TriggerStep_pUpsert else 56;
const TriggerStep_pNext_off: usize = if (@hasDecl(L, "TriggerStep_pNext")) L.TriggerStep_pNext else 72;
const Upsert_pUpsertTarget_off: usize = if (@hasDecl(L, "Upsert_pUpsertTarget")) L.Upsert_pUpsertTarget else 0;
const Upsert_pUpsertTargetWhere_off: usize = if (@hasDecl(L, "Upsert_pUpsertTargetWhere")) L.Upsert_pUpsertTargetWhere else 8;
const Upsert_pUpsertSet_off: usize = if (@hasDecl(L, "Upsert_pUpsertSet")) L.Upsert_pUpsertSet else 16;
const Upsert_pUpsertWhere_off: usize = if (@hasDecl(L, "Upsert_pUpsertWhere")) L.Upsert_pUpsertWhere else 24;
const Upsert_pNextUpsert_off: usize = if (@hasDecl(L, "Upsert_pNextUpsert")) L.Upsert_pNextUpsert else 32;

// Expr / NameContext / FuncDef
const Expr_op_off: usize = 0;
const Expr_flags_off: usize = 4;
const Expr_u_off: usize = 8; // u.zToken == first member of the union
const sizeof_NameContext: usize = if (@hasDecl(L, "sizeof_NameContext")) L.sizeof_NameContext else 56;
const NameContext_pParse_off: usize = 0;
const FuncDef_nArg_off: usize = 0;

// ═══ raw memory helpers ══════════════════════════════════════════════════════
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

// ─── sqlite3 accessors ───────────────────────────────────────────────────────
inline fn dbNDb(db: ?*anyopaque) c_int {
    return rdPtr(c_int, db, sqlite3_nDb_off);
}
inline fn dbSetNDb(db: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, db, sqlite3_nDb_off, v);
}
inline fn dbADb(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_aDb_off);
}
inline fn dbSetADb(db: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, db, sqlite3_aDb_off, v);
}
inline fn dbADbStatic(db: ?*anyopaque) ?*anyopaque {
    // address of the embedded array db->aDbStatic[]
    return @ptrCast(base(db) + sqlite3_aDbStatic_off);
}
inline fn dbAt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(dbADb(db).?);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_Db));
}
inline fn dbAtZName(db: ?*anyopaque, i: c_int) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, dbAt(db, i), Db_zDbSName_off);
}
inline fn dbAtPBt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    return rdPtr(?*anyopaque, dbAt(db, i), Db_pBt_off);
}
inline fn dbAtPSchema(db: ?*anyopaque, i: c_int) ?*anyopaque {
    return rdPtr(?*anyopaque, dbAt(db, i), Db_pSchema_off);
}
inline fn dbALimit(db: ?*anyopaque, lim: usize) c_int {
    const q: *align(1) const c_int = @ptrCast(base(db) + sqlite3_aLimit_off + lim * @sizeOf(c_int));
    return q.*;
}
inline fn dbOpenFlags(db: ?*anyopaque) u32 {
    return rdPtr(u32, db, sqlite3_openFlags_off);
}
inline fn dbPVfs(db: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, db, sqlite3_pVfs_off);
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
inline fn dbMallocFailed(db: ?*anyopaque) bool {
    return base(db)[sqlite3_mallocFailed_off] != 0;
}
inline fn dbSetNoSharedCache(db: ?*anyopaque, v: u8) void {
    base(db)[sqlite3_noSharedCache_off] = v;
}
inline fn dbDfltLockMode(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_dfltLockMode_off];
}
inline fn dbEnc(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_enc_off];
}
inline fn dbSetInitIDb(db: ?*anyopaque, v: u8) void {
    base(db)[sqlite3_init_iDb_off] = v;
}
inline fn dbInitIDb(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_init_iDb_off];
}
inline fn dbInitBusy(db: ?*anyopaque) u8 {
    return base(db)[sqlite3_initBusy_off];
}
inline fn dbReopenMemdb(db: ?*anyopaque) bool {
    return (base(db)[sqlite3_init_bitbyte_off] & INIT_REOPEN_MEMDB_BIT) != 0;
}

// ─── Db slot field writers ───────────────────────────────────────────────────
inline fn dbSetAtPBt(db: ?*anyopaque, i: c_int, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, dbAt(db, i), Db_pBt_off, v);
}
inline fn dbSetAtPSchema(db: ?*anyopaque, i: c_int, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, dbAt(db, i), Db_pSchema_off, v);
}
inline fn dbSetAtZName(db: ?*anyopaque, i: c_int, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, dbAt(db, i), Db_zDbSName_off, v);
}
inline fn dbSetAtSafety(db: ?*anyopaque, i: c_int, v: u8) void {
    base(dbAt(db, i).?)[Db_safety_level_off] = v;
}

// ─── Schema ──────────────────────────────────────────────────────────────────
inline fn schemaFileFormat(p: ?*anyopaque) u8 {
    return base(p)[Schema_file_format_off];
}
inline fn schemaEnc(p: ?*anyopaque) u8 {
    return base(p)[Schema_enc_off];
}

// ─── Parse ─────────────────────────────────────────────────────────────────
inline fn pDb(pParse: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pParse, Parse_db_off);
}
inline fn pNErr(pParse: ?*anyopaque) c_int {
    return rdPtr(c_int, pParse, Parse_nErr_off);
}

// ─── DbFixer accessors ───────────────────────────────────────────────────────
inline fn fixWalker(pFix: ?*anyopaque) ?*anyopaque {
    return @ptrCast(base(pFix) + DbFixer_w_off);
}
inline fn fixPParse(pFix: ?*anyopaque) ?*anyopaque {
    // DbFixer.pParse is at offset 0.
    return rdPtr(?*anyopaque, pFix, 0);
}
inline fn fixSetPParse(pFix: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pFix, 0, v);
}
inline fn fixPSchema(pFix: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pFix, DbFixer_pSchema_off);
}
inline fn fixSetPSchema(pFix: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pFix, DbFixer_pSchema_off, v);
}
inline fn fixBTemp(pFix: ?*anyopaque) u8 {
    return base(pFix)[DbFixer_bTemp_off];
}
inline fn fixSetBTemp(pFix: ?*anyopaque, v: u8) void {
    base(pFix)[DbFixer_bTemp_off] = v;
}
inline fn fixZDb(pFix: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, pFix, DbFixer_zDb_off);
}
inline fn fixSetZDb(pFix: ?*anyopaque, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, pFix, DbFixer_zDb_off, v);
}
inline fn fixZType(pFix: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, pFix, DbFixer_zType_off);
}
inline fn fixSetZType(pFix: ?*anyopaque, v: ?[*:0]const u8) void {
    wrPtr(?[*:0]const u8, pFix, DbFixer_zType_off, v);
}
inline fn fixPName(pFix: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pFix, DbFixer_pName_off);
}
inline fn fixSetPName(pFix: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pFix, DbFixer_pName_off, v);
}

// ─── Walker writers (used by sqlite3FixInit) ─────────────────────────────────
inline fn wSetPParse(w: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, w, Walker_pParse_off, v);
}
inline fn wSetXExpr(w: ?*anyopaque, v: ?*const anyopaque) void {
    wrPtr(?*const anyopaque, w, Walker_xExprCallback_off, v);
}
inline fn wSetXSelect(w: ?*anyopaque, v: ?*const anyopaque) void {
    wrPtr(?*const anyopaque, w, Walker_xSelectCallback_off, v);
}
inline fn wSetXSelect2(w: ?*anyopaque, v: ?*const anyopaque) void {
    wrPtr(?*const anyopaque, w, Walker_xSelectCallback2_off, v);
}
inline fn wSetWalkerDepth(w: ?*anyopaque, v: c_int) void {
    wrPtr(c_int, w, Walker_walkerDepth_off, v);
}
inline fn wSetECode(w: ?*anyopaque, v: u16) void {
    wrPtr(u16, w, Walker_eCode_off, v);
}
inline fn wSetU(w: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, w, Walker_u_off, v);
}
// Walker.u.pFix — the DbFixer pointer stored in the callback union.
inline fn wUFix(w: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, w, Walker_u_off);
}

// ─── Expr accessors ──────────────────────────────────────────────────────────
inline fn exprOp(p: ?*anyopaque) u8 {
    return base(p)[Expr_op_off];
}
inline fn exprSetOp(p: ?*anyopaque, v: u8) void {
    base(p)[Expr_op_off] = v;
}
inline fn exprFlags(p: ?*anyopaque) u32 {
    return rdPtr(u32, p, Expr_flags_off);
}
inline fn exprSetFlags(p: ?*anyopaque, v: u32) void {
    wrPtr(u32, p, Expr_flags_off, v);
}
inline fn exprHasProperty(p: ?*anyopaque, prop: u32) bool {
    return (exprFlags(p) & prop) != 0;
}
inline fn exprSetProperty(p: ?*anyopaque, prop: u32) void {
    exprSetFlags(p, exprFlags(p) | prop);
}
// Expr.u.zToken — first member of the u union (char*).
inline fn exprZToken(p: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, p, Expr_u_off);
}

// ─── SrcList / SrcItem accessors ─────────────────────────────────────────────
inline fn srcNSrc(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, SrcList_nSrc_off);
}
// Pointer to SrcItem i of the SrcList's a[] array.
inline fn srcItemAt(pList: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(base(pList) + SrcList_a_off);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_SrcItem));
}
inline fn fgBit(pItem: ?*anyopaque, byte: usize, bit: u8) bool {
    return (base(pItem)[byte] & bit) != 0;
}
inline fn fgSet(pItem: ?*anyopaque, byte: usize, bit: u8) void {
    base(pItem)[byte] |= bit;
}
// u4.zDatabase / u4.pSchema share offset; u3.pOn shares u3 offset.
inline fn itemU4ZDatabase(pItem: ?*anyopaque) ?[*:0]const u8 {
    return rdPtr(?[*:0]const u8, pItem, SrcItem_u4_off);
}
inline fn itemSetU4PSchema(pItem: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, pItem, SrcItem_u4_off, v);
}
inline fn itemU3POn(pItem: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, pItem, SrcItem_u3_off);
}

// ─── Select / With / Cte accessors ───────────────────────────────────────────
inline fn selPSrc(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Select_pSrc_off);
}
inline fn selPWith(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Select_pWith_off);
}
inline fn withNCte(p: ?*anyopaque) c_int {
    return rdPtr(c_int, p, With_nCte_off);
}
// Pointer to Cte i of the With's a[] array.
inline fn withCteAt(pWith: ?*anyopaque, i: c_int) ?*anyopaque {
    const a: [*]u8 = @ptrCast(base(pWith) + With_a_off);
    return @ptrCast(a + (@as(usize, @intCast(i)) * sizeof_Cte));
}
inline fn ctePSelect(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Cte_pSelect_off);
}

// ─── TriggerStep / Trigger / Upsert accessors ────────────────────────────────
inline fn stepPSelect(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pSelect_off);
}
inline fn stepPSrc(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pSrc_off);
}
inline fn stepPWhere(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pWhere_off);
}
inline fn stepPExprList(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pExprList_off);
}
inline fn stepPUpsert(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pUpsert_off);
}
inline fn stepPNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, TriggerStep_pNext_off);
}
inline fn upTarget(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Upsert_pUpsertTarget_off);
}
inline fn upTargetWhere(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Upsert_pUpsertTargetWhere_off);
}
inline fn upSet(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Upsert_pUpsertSet_off);
}
inline fn upWhere(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Upsert_pUpsertWhere_off);
}
inline fn upNext(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Upsert_pNextUpsert_off);
}

// ═══ extern C / internal-ABI helpers (resolved at link time) ═════════════════
// Memory / string
extern fn sqlite3MPrintf(db: ?*anyopaque, fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbRealloc(db: ?*anyopaque, p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_snprintf(n: c_int, z: [*]u8, fmt: [*:0]const u8, ...) ?[*:0]u8;

// resolve / walk / schema lookup
extern fn sqlite3ResolveExprNames(pName: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3WalkExpr(w: ?*anyopaque, pExpr: ?*anyopaque) c_int;
extern fn sqlite3WalkExprList(w: ?*anyopaque, pList: ?*anyopaque) c_int;
extern fn sqlite3WalkSelect(w: ?*anyopaque, pSelect: ?*anyopaque) c_int;
extern fn sqlite3WalkWinDefnDummyCallback(w: ?*anyopaque, pSelect: ?*anyopaque) callconv(.c) void;
extern fn sqlite3FindDbName(db: ?*anyopaque, zName: ?[*:0]const u8) c_int;

// schema / catalog (sqlite3ReadSchema is provided by the ported prepare.zig)
extern fn sqlite3ReadSchema(pParse: ?*anyopaque) c_int;
extern fn sqlite3SchemaGet(db: ?*anyopaque, pBt: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ResetAllSchemasOfConnection(db: ?*anyopaque) void;
extern fn sqlite3CollapseDatabaseArray(db: ?*anyopaque) void;
extern fn sqlite3ParseUri(zDefaultVfs: ?[*:0]const u8, zUri: ?[*:0]const u8, pFlags: *u32, ppVfs: *?*anyopaque, pzFile: *?[*:0]u8, pzErr: *?[*:0]u8) c_int;

// codegen / vdbe
extern fn sqlite3GetVdbe(pParse: ?*anyopaque) ?*anyopaque;
extern fn sqlite3GetTempRange(pParse: ?*anyopaque, n: c_int) c_int;
extern fn sqlite3ExprCode(pParse: ?*anyopaque, pExpr: ?*anyopaque, target: c_int) void;
extern fn sqlite3ExprDelete(db: ?*anyopaque, pExpr: ?*anyopaque) void;
extern fn sqlite3VdbeAddFunctionCall(pParse: ?*anyopaque, p1: c_int, p2: c_int, p3: c_int, nArg: c_int, pFunc: ?*const anyopaque, p4type: c_int) c_int;
extern fn sqlite3VdbeAddOp1(p: ?*anyopaque, op: c_int, p1: c_int) c_int;
extern fn sqlite3AuthCheck(pParse: ?*anyopaque, code: c_int, z1: ?[*:0]const u8, z2: ?[*:0]const u8, z3: ?[*:0]const u8) c_int;

// btree / pager
extern fn sqlite3BtreeTxnState(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeIsInBackup(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeOpen(pVfs: ?*anyopaque, zFilename: ?[*:0]const u8, db: ?*anyopaque, ppBtree: *align(1) ?*anyopaque, flags: c_int, vfsFlags: c_int) c_int;
extern fn sqlite3BtreeClose(p: ?*anyopaque) c_int;
extern fn sqlite3BtreePager(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3BtreeEnter(p: ?*anyopaque) void;
extern fn sqlite3BtreeLeave(p: ?*anyopaque) void;
extern fn sqlite3BtreeEnterAll(db: ?*anyopaque) void;
extern fn sqlite3BtreeLeaveAll(db: ?*anyopaque) void;
extern fn sqlite3BtreeSecureDelete(p: ?*anyopaque, newFlag: c_int) c_int;
extern fn sqlite3BtreeSetPagerFlags(p: ?*anyopaque, pgFlags: c_uint) void;
extern fn sqlite3PagerLockingMode(p: ?*anyopaque, mode: c_int) c_int;

// schema init (driven by prepare.zig)
extern fn sqlite3Init(db: ?*anyopaque, pzErrMsg: ?*align(1) ?[*:0]u8) c_int;

// public C-API used by the SQL user-functions
extern fn sqlite3_context_db_handle(context: ?*anyopaque) ?*anyopaque;
extern fn sqlite3_value_text(v: ?*anyopaque) ?[*:0]const u8;
extern fn sqlite3_result_error(context: ?*anyopaque, z: ?[*:0]const u8, n: c_int) void;
extern fn sqlite3_result_error_code(context: ?*anyopaque, code: c_int) void;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_free_filename(p: ?[*:0]u8) void;
extern fn sqlite3_vfs_find(zName: ?[*:0]const u8) ?*anyopaque;

// ═══ resolveAttachExpr (static) ══════════════════════════════════════════════
fn resolveAttachExpr(pName: ?*anyopaque, pExpr: ?*anyopaque) c_int {
    var rc: c_int = SQLITE_OK;
    if (pExpr) |e| {
        if (exprOp(e) != TK_ID) {
            rc = sqlite3ResolveExprNames(pName, e);
        } else {
            exprSetOp(e, TK_STRING);
        }
    }
    return rc;
}

// ═══ sqlite3DbIsNamed ════════════════════════════════════════════════════════
export fn sqlite3DbIsNamed(db: ?*anyopaque, iDb: c_int, zName: ?[*:0]const u8) callconv(.c) c_int {
    const named = sqlite3StrICmp(dbAtZName(db, iDb), zName) == 0 or
        (iDb == 0 and sqlite3StrICmp("main", zName) == 0);
    return @intFromBool(named);
}

// ═══ attachFunc (static SQL user-function) ═══════════════════════════════════
fn attachFunc(context: ?*anyopaque, notUsed: c_int, argv: [*]?*anyopaque) callconv(.c) void {
    _ = notUsed;
    var rc: c_int = 0;
    const db = sqlite3_context_db_handle(context);
    var zPath: ?[*:0]u8 = null;
    var zErr: ?[*:0]u8 = null;
    var flags: u32 = undefined;
    var zErrDyn: ?[*:0]u8 = null;
    var pVfs: ?*anyopaque = undefined;
    // Index of the Db slot being (re)opened. In the memdb path it is
    // db->init.iDb (nDb unchanged); in the real-ATTACH path it is the freshly
    // appended slot. The C code carries this as the pointer `pNew`; we carry the
    // index so it survives the aDb[] realloc.
    var iNew: c_int = undefined;

    var zFile = sqlite3_value_text(argv[0]);
    var zName = sqlite3_value_text(argv[1]);
    if (zFile == null) zFile = "";
    if (zName == null) zName = "";

    if (dbReopenMemdb(db)) {
        // Not a real ATTACH: sqlite3_deserialize() closing db->init.iDb and
        // reopening it as a MemDB.
        var pNewBt: ?*anyopaque = null;
        const iDb: c_int = @intCast(dbInitIDb(db));
        iNew = iDb;
        // assert pNew->pBt != 0
        if (sqlite3BtreeTxnState(dbAtPBt(db, iDb)) != SQLITE_TXN_NONE or
            sqlite3BtreeIsInBackup(dbAtPBt(db, iDb)) != 0)
        {
            rc = SQLITE_BUSY;
            return attachError(context, db, rc, zErrDyn);
        }

        pVfs = sqlite3_vfs_find("memdb");
        if (pVfs == null) return;
        rc = sqlite3BtreeOpen(pVfs, "x\x00", db, &pNewBt, 0, @intCast(SQLITE_OPEN_MAIN_DB));
        if (rc == SQLITE_OK) {
            const pNewSchema = sqlite3SchemaGet(db, pNewBt);
            if (pNewSchema != null) {
                _ = sqlite3BtreeClose(dbAtPBt(db, iDb));
                dbSetAtPBt(db, iDb, pNewBt);
                dbSetAtPSchema(db, iDb, pNewSchema);
            } else {
                _ = sqlite3BtreeClose(pNewBt);
                rc = SQLITE_NOMEM;
            }
        }
        if (rc != 0) return attachError(context, db, rc, zErrDyn);
    } else {
        // A real ATTACH. Error checks: too many DBs / name already in use.
        if (dbNDb(db) >= dbALimit(db, SQLITE_LIMIT_ATTACHED) + 2) {
            zErrDyn = sqlite3MPrintf(db, "too many attached databases - max %d", dbALimit(db, SQLITE_LIMIT_ATTACHED));
            return attachError(context, db, rc, zErrDyn);
        }
        var i: c_int = 0;
        while (i < dbNDb(db)) : (i += 1) {
            if (sqlite3DbIsNamed(db, i, zName) != 0) {
                zErrDyn = sqlite3MPrintf(db, "database %s is already in use", zName);
                return attachError(context, db, rc, zErrDyn);
            }
        }

        // Allocate the new entry in db->aDb[] (which holds Db, not Db*).
        var aNew: ?*anyopaque = undefined;
        if (@intFromPtr(dbADb(db).?) == @intFromPtr(dbADbStatic(db).?)) {
            aNew = sqlite3DbMallocRawNN(db, @as(u64, sizeof_Db) * 3);
            if (aNew == null) return;
            const dst: [*]u8 = @ptrCast(aNew.?);
            const src: [*]u8 = @ptrCast(dbADb(db).?);
            @memcpy(dst[0 .. sizeof_Db * 2], src[0 .. sizeof_Db * 2]);
        } else {
            aNew = sqlite3DbRealloc(db, dbADb(db), @as(u64, sizeof_Db) * (1 + @as(u64, @intCast(dbNDb(db)))));
            if (aNew == null) return;
        }
        dbSetADb(db, aNew);
        const newIdx = dbNDb(db);
        iNew = newIdx;
        const pNew = dbAt(db, newIdx);
        @memset(@as([*]u8, @ptrCast(pNew.?))[0..sizeof_Db], 0);

        // Open the database file, then use it to obtain the schema.
        flags = dbOpenFlags(db);
        {
            // sqlite3_vfs.zName is at offset 24.
            const vfsName = rdPtr(?[*:0]const u8, dbPVfs(db), sqlite3_vfs_zName_off);
            rc = sqlite3ParseUri(vfsName, zFile, &flags, &pVfs, &zPath, &zErr);
        }
        if (rc != SQLITE_OK) {
            if (rc == SQLITE_NOMEM) _ = sqlite3OomFault(db);
            sqlite3_result_error(context, zErr, -1);
            sqlite3_free(@ptrCast(zErr));
            return;
        }
        if ((dbFlags(db) & SQLITE_AttachWrite) == 0) {
            flags &= ~(SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE);
            flags |= SQLITE_OPEN_READONLY;
        } else if ((dbFlags(db) & SQLITE_AttachCreate) == 0) {
            flags &= ~SQLITE_OPEN_CREATE;
        }
        // assert pVfs
        flags |= SQLITE_OPEN_MAIN_DB;
        const pNewBtPtr: *align(1) ?*anyopaque = @ptrCast(base(pNew) + Db_pBt_off);
        rc = sqlite3BtreeOpen(pVfs, zPath, db, pNewBtPtr, 0, @bitCast(flags));
        dbSetNDb(db, dbNDb(db) + 1);
        dbSetAtZName(db, newIdx, sqlite3DbStrDup(db, zName));
    }
    dbSetNoSharedCache(db, 0);

    if (rc == SQLITE_CONSTRAINT) {
        rc = SQLITE_ERROR;
        zErrDyn = sqlite3MPrintf(db, "database is already attached");
    } else if (rc == SQLITE_OK) {
        const pSchema = sqlite3SchemaGet(db, dbAtPBt(db, iNew));
        dbSetAtPSchema(db, iNew, pSchema);
        if (pSchema == null) {
            rc = SQLITE_NOMEM_BKPT();
        } else if (schemaFileFormat(pSchema) != 0 and schemaEnc(pSchema) != dbEnc(db)) {
            zErrDyn = sqlite3MPrintf(db, "attached databases must use the same text encoding as main database");
            rc = SQLITE_ERROR;
        }
        const pBt = dbAtPBt(db, iNew);
        sqlite3BtreeEnter(pBt);
        const pPager = sqlite3BtreePager(pBt);
        _ = sqlite3PagerLockingMode(pPager, dbDfltLockMode(db));
        _ = sqlite3BtreeSecureDelete(pBt, sqlite3BtreeSecureDelete(dbAtPBt(db, 0), -1));
        sqlite3BtreeSetPagerFlags(pBt, @intCast(PAGER_SYNCHRONOUS_FULL | (dbFlags(db) & PAGER_FLAGS_MASK)));
        sqlite3BtreeLeave(pBt);
    }
    dbSetAtSafety(db, iNew, @intCast(SQLITE_DEFAULT_SYNCHRONOUS + 1));
    if (rc == SQLITE_OK and dbAtZName(db, iNew) == null) {
        rc = SQLITE_NOMEM_BKPT();
    }
    sqlite3_free_filename(zPath);

    // If the file opened, read the new schema. On failure, close the file and
    // remove the entry from db->aDb[], restoring the prior state.
    if (rc == SQLITE_OK) {
        sqlite3BtreeEnterAll(db);
        dbSetInitIDb(db, 0);
        dbSetMDbFlags(db, dbMDbFlags(db) & ~DBFLAG_SchemaKnownOk);
        if (!dbReopenMemdb(db)) {
            rc = sqlite3Init(db, @ptrCast(&zErrDyn));
        }
        sqlite3BtreeLeaveAll(db);
        // assert zErrDyn==0 || rc!=SQLITE_OK
    }
    if (rc != 0) {
        // ALWAYS(!REOPEN_AS_MEMDB(db)) — in the error path this is always true.
        if (!dbReopenMemdb(db)) {
            const iDb: c_int = dbNDb(db) - 1;
            // assert iDb>=2
            if (dbAtPBt(db, iDb) != null) {
                _ = sqlite3BtreeClose(dbAtPBt(db, iDb));
                dbSetAtPBt(db, iDb, null);
                dbSetAtPSchema(db, iDb, null);
            }
            sqlite3ResetAllSchemasOfConnection(db);
            dbSetNDb(db, iDb);
            if (rc == SQLITE_NOMEM or rc == SQLITE_IOERR_NOMEM) {
                _ = sqlite3OomFault(db);
                sqlite3DbFree(db, @ptrCast(zErrDyn));
                zErrDyn = sqlite3MPrintf(db, "out of memory");
            } else if (zErrDyn == null) {
                zErrDyn = sqlite3MPrintf(db, "unable to open database: %s", zFile);
            }
        }
        return attachError(context, db, rc, zErrDyn);
    }
    return;
}

// attach_error: label.
fn attachError(context: ?*anyopaque, db: ?*anyopaque, rc: c_int, zErrDyn: ?[*:0]u8) void {
    if (zErrDyn) |z| {
        sqlite3_result_error(context, z, -1);
        sqlite3DbFree(db, @ptrCast(z));
    }
    if (rc != 0) sqlite3_result_error_code(context, rc);
}

// SQLITE_NOMEM_BKPT — under SQLITE_DEBUG it maps to sqlite3NomemError(__LINE__)
// (defined only in those configs); otherwise the bare result code.
inline fn SQLITE_NOMEM_BKPT() c_int {
    return if (config.sqlite_debug) sqlite3NomemError(0) else SQLITE_NOMEM;
}
extern fn sqlite3NomemError(line: c_int) c_int;

// ═══ detachFunc (static SQL user-function) ═══════════════════════════════════
fn detachFunc(context: ?*anyopaque, notUsed: c_int, argv: [*]?*anyopaque) callconv(.c) void {
    _ = notUsed;
    var zName = sqlite3_value_text(argv[0]);
    const db = sqlite3_context_db_handle(context);
    var zErr: [128]u8 = undefined;

    if (zName == null) zName = "";
    var i: c_int = 0;
    var found = false;
    while (i < dbNDb(db)) : (i += 1) {
        if (dbAtPBt(db, i) == null) continue;
        if (sqlite3DbIsNamed(db, i, zName) != 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        _ = sqlite3_snprintf(@intCast(zErr.len), &zErr, "no such database: %s", zName);
        sqlite3_result_error(context, @ptrCast(&zErr), -1);
        return;
    }
    if (i < 2) {
        _ = sqlite3_snprintf(@intCast(zErr.len), &zErr, "cannot detach database %s", zName);
        sqlite3_result_error(context, @ptrCast(&zErr), -1);
        return;
    }
    const pBt = dbAtPBt(db, i);
    if (sqlite3BtreeTxnState(pBt) != SQLITE_TXN_NONE or sqlite3BtreeIsInBackup(pBt) != 0) {
        _ = sqlite3_snprintf(@intCast(zErr.len), &zErr, "database %s is locked", zName);
        sqlite3_result_error(context, @ptrCast(&zErr), -1);
        return;
    }

    // If any TEMP triggers reference the schema being detached, move those
    // triggers to reference the TEMP schema itself. sqliteHash{First,Next,Data}
    // are C macros — inline them via the Hash/HashElem field offsets.
    const tempSchema = dbAtPSchema(db, 1); // assert db->aDb[1].pSchema
    const detachedSchema = dbAtPSchema(db, i);
    // pEntry = sqliteHashFirst(&schema->trigHash) == trigHash.first
    var pEntry = rdPtr(?*anyopaque, tempSchema, Schema_trigHash_off + Hash_first_off);
    while (pEntry) |entry| {
        const pTrig = rdPtr(?*anyopaque, entry, HashElem_data_off); // sqliteHashData(E)
        if (trigPTabSchema(pTrig) == detachedSchema) {
            trigSetPTabSchema(pTrig, trigPSchema(pTrig));
        }
        pEntry = rdPtr(?*anyopaque, entry, HashElem_next_off); // sqliteHashNext(E)
    }

    _ = sqlite3BtreeClose(pBt);
    dbSetAtPBt(db, i, null);
    dbSetAtPSchema(db, i, null);
    sqlite3CollapseDatabaseArray(db);
    return;
}

// Schema.trigHash + Trigger.pSchema/pTabSchema + Hash iteration glue.
const Schema_trigHash_off: usize = if (@hasDecl(L, "Schema_trigHash")) L.Schema_trigHash else 56;
const Trigger_pSchema_off: usize = if (@hasDecl(L, "Trigger_pSchema")) L.Trigger_pSchema else 40;
const Trigger_pTabSchema_off: usize = if (@hasDecl(L, "Trigger_pTabSchema")) L.Trigger_pTabSchema else 48;
inline fn trigPSchema(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_pSchema_off);
}
inline fn trigPTabSchema(p: ?*anyopaque) ?*anyopaque {
    return rdPtr(?*anyopaque, p, Trigger_pTabSchema_off);
}
inline fn trigSetPTabSchema(p: ?*anyopaque, v: ?*anyopaque) void {
    wrPtr(?*anyopaque, p, Trigger_pTabSchema_off, v);
}
// Hash / HashElem field offsets — sqliteHashFirst/Next/Data are C macros.
const Hash_first_off: usize = if (@hasDecl(L, "Hash_first")) L.Hash_first else 8;
const HashElem_next_off: usize = if (@hasDecl(L, "HashElem_next")) L.HashElem_next else 0;
const HashElem_data_off: usize = if (@hasDecl(L, "HashElem_data")) L.HashElem_data else 16;

// ═══ FuncDef literals (static const, like the C `static const FuncDef`) ══════
// Layout mirrors callback.zig's FuncDef. We build a properly-typed struct so the
// VDBE's function-call opcode sees the same bytes.
const XSFunc = ?*const fn (?*anyopaque, c_int, [*]?*anyopaque) callconv(.c) void;
const XFinalize = ?*const fn (?*anyopaque) callconv(.c) void;
const FuncDef = extern struct {
    nArg: i16, // 0
    funcFlags: u32, // 4
    pUserData: ?*anyopaque, // 8
    pNext: ?*FuncDef, // 16
    xSFunc: XSFunc, // 24
    xFinalize: XFinalize, // 32
    xValue: XFinalize, // 40
    xInverse: XSFunc, // 48
    zName: ?[*:0]const u8, // 56
    u: extern union { pHash: ?*FuncDef, pDestructor: ?*anyopaque }, // 64
};
comptime {
    std.debug.assert(@sizeOf(FuncDef) == 72);
    std.debug.assert(@offsetOf(FuncDef, "nArg") == 0);
    std.debug.assert(@offsetOf(FuncDef, "funcFlags") == 4);
    std.debug.assert(@offsetOf(FuncDef, "xSFunc") == 24);
    std.debug.assert(@offsetOf(FuncDef, "zName") == 56);
    std.debug.assert(@offsetOf(FuncDef, "u") == 64);
}
const SQLITE_UTF8_FLAG: u32 = 1; // SQLITE_UTF8 funcFlags

const detach_func: FuncDef = .{
    .nArg = 1,
    .funcFlags = SQLITE_UTF8_FLAG,
    .pUserData = null,
    .pNext = null,
    .xSFunc = detachFunc,
    .xFinalize = null,
    .xValue = null,
    .xInverse = null,
    .zName = "sqlite_detach",
    .u = .{ .pHash = null },
};
const attach_func: FuncDef = .{
    .nArg = 3,
    .funcFlags = SQLITE_UTF8_FLAG,
    .pUserData = null,
    .pNext = null,
    .xSFunc = attachFunc,
    .xFinalize = null,
    .xValue = null,
    .xInverse = null,
    .zName = "sqlite_attach",
    .u = .{ .pHash = null },
};

// ═══ codeAttach (static) ═════════════════════════════════════════════════════
fn codeAttach(
    pParse: ?*anyopaque,
    typ: c_int,
    pFunc: *const FuncDef,
    pAuthArg: ?*anyopaque,
    pFilename: ?*anyopaque,
    pDbname: ?*anyopaque,
    pKey: ?*anyopaque,
) void {
    const db = pDb(pParse);
    // NameContext sName; memset to 0; sName.pParse = pParse.
    var sName: [sizeof_NameContext]u8 align(8) = undefined;
    @memset(&sName, 0);
    const pName: ?*anyopaque = @ptrCast(&sName);

    if (SQLITE_OK != sqlite3ReadSchema(pParse)) return codeAttachEnd(db, pFilename, pDbname, pKey);
    if (pNErr(pParse) != 0) return codeAttachEnd(db, pFilename, pDbname, pKey);
    wrPtr(?*anyopaque, pName, NameContext_pParse_off, pParse);

    if (SQLITE_OK != resolveAttachExpr(pName, pFilename) or
        SQLITE_OK != resolveAttachExpr(pName, pDbname) or
        SQLITE_OK != resolveAttachExpr(pName, pKey))
    {
        return codeAttachEnd(db, pFilename, pDbname, pKey);
    }

    // SQLITE_OMIT_AUTHORIZATION is OFF.
    // ALWAYS(pAuthArg) holds.
    if (pAuthArg) |aexpr| {
        var zAuthArg: ?[*:0]const u8 = null;
        if (exprOp(aexpr) == TK_STRING) {
            // assert !ExprHasProperty(pAuthArg, EP_IntValue)
            std.debug.assert(!exprHasProperty(aexpr, EP_IntValue));
            zAuthArg = exprZToken(aexpr);
        }
        const rc = sqlite3AuthCheck(pParse, typ, zAuthArg, null, null);
        if (rc != SQLITE_OK) {
            return codeAttachEnd(db, pFilename, pDbname, pKey);
        }
    }

    const v = sqlite3GetVdbe(pParse);
    const regArgs = sqlite3GetTempRange(pParse, 4);
    sqlite3ExprCode(pParse, pFilename, regArgs);
    sqlite3ExprCode(pParse, pDbname, regArgs + 1);
    sqlite3ExprCode(pParse, pKey, regArgs + 2);

    // assert v || db->mallocFailed
    if (v != null) {
        const nArg: c_int = pFunc.nArg;
        _ = sqlite3VdbeAddFunctionCall(pParse, 0, regArgs + 3 - nArg, regArgs + 3, nArg, @ptrCast(pFunc), 0);
        // OP_Expire: P1=true for ATTACH (expire this stmt only), false for DETACH.
        _ = sqlite3VdbeAddOp1(v, OP_Expire, @intFromBool(typ == SQLITE_ATTACH));
    }
    return codeAttachEnd(db, pFilename, pDbname, pKey);
}

// attach_end: label.
fn codeAttachEnd(db: ?*anyopaque, pFilename: ?*anyopaque, pDbname: ?*anyopaque, pKey: ?*anyopaque) void {
    sqlite3ExprDelete(db, pFilename);
    sqlite3ExprDelete(db, pDbname);
    sqlite3ExprDelete(db, pKey);
}

// ═══ sqlite3Detach ═══════════════════════════════════════════════════════════
export fn sqlite3Detach(pParse: ?*anyopaque, pDbname: ?*anyopaque) callconv(.c) void {
    codeAttach(pParse, SQLITE_DETACH, &detach_func, pDbname, null, null, pDbname);
}

// ═══ sqlite3Attach ═══════════════════════════════════════════════════════════
export fn sqlite3Attach(pParse: ?*anyopaque, p: ?*anyopaque, pDbname: ?*anyopaque, pKey: ?*anyopaque) callconv(.c) void {
    codeAttach(pParse, SQLITE_ATTACH, &attach_func, p, p, pDbname, pKey);
}

// ═══ fixExprCb (static walker callback) ══════════════════════════════════════
fn fixExprCb(p: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    const pFix = wUFix(p);
    if (fixBTemp(pFix) == 0) exprSetProperty(pExpr, EP_FromDDL);
    if (exprOp(pExpr) == TK_VARIABLE) {
        const db = pDb(fixPParse(pFix));
        if (dbInitBusy(db) != 0) {
            exprSetOp(pExpr, TK_NULL);
        } else {
            sqlite3ErrorMsg(fixPParse(pFix), "%s cannot use variables", fixZType(pFix));
            return WRC_Abort;
        }
    }
    return WRC_Continue;
}

// ═══ fixSelectCb (static walker callback) ════════════════════════════════════
fn fixSelectCb(p: ?*anyopaque, pSelect: ?*anyopaque) callconv(.c) c_int {
    const pFix = wUFix(p);
    const db = pDb(fixPParse(pFix));
    const iDb = sqlite3FindDbName(db, fixZDb(pFix));
    const pList = selPSrc(pSelect);

    if (pList == null) return WRC_Continue; // NEVER(pList==0)
    const nSrc = srcNSrc(pList);
    var i: c_int = 0;
    while (i < nSrc) : (i += 1) {
        const pItem = srcItemAt(pList, i);
        if (fixBTemp(pFix) == 0 and !fgBit(pItem, FG_isSubquery_byte, FG_isSubquery_bit)) {
            if (!fgBit(pItem, FG_fixedSchema_byte, FG_fixedSchema_bit) and itemU4ZDatabase(pItem) != null) {
                if (iDb != sqlite3FindDbName(db, itemU4ZDatabase(pItem))) {
                    sqlite3ErrorMsg(fixPParse(pFix), "%s %T cannot reference objects in database %s", fixZType(pFix), fixPName(pFix), itemU4ZDatabase(pItem));
                    return WRC_Abort;
                }
                sqlite3DbFree(db, @ptrCast(@constCast(itemU4ZDatabase(pItem))));
                fgSet(pItem, FG_notCte_byte, FG_notCte_bit);
                fgSet(pItem, FG_hadSchema_byte, FG_hadSchema_bit);
            }
            itemSetU4PSchema(pItem, fixPSchema(pFix));
            fgSet(pItem, FG_fromDDL_byte, FG_fromDDL_bit);
            fgSet(pItem, FG_fixedSchema_byte, FG_fixedSchema_bit);
        }
        // (!OMIT_VIEW || !OMIT_TRIGGER): walk the ON clause when not USING.
        if (!fgBit(pItem, FG_isUsing_byte, FG_isUsing_bit) and
            sqlite3WalkExpr(fixWalker(pFix), itemU3POn(pItem)) != 0)
        {
            return WRC_Abort;
        }
    }
    const pWith = selPWith(pSelect);
    if (pWith != null) {
        const nCte = withNCte(pWith);
        var j: c_int = 0;
        while (j < nCte) : (j += 1) {
            if (sqlite3WalkSelect(p, ctePSelect(withCteAt(pWith, j))) != 0) {
                return WRC_Abort;
            }
        }
    }
    return WRC_Continue;
}

// ═══ sqlite3FixInit ══════════════════════════════════════════════════════════
export fn sqlite3FixInit(
    pFix: ?*anyopaque,
    pParse: ?*anyopaque,
    iDb: c_int,
    zType: ?[*:0]const u8,
    pName: ?*anyopaque, // const Token*
) callconv(.c) void {
    const db = pDb(pParse);
    // assert db->nDb > iDb
    fixSetPParse(pFix, pParse);
    fixSetZDb(pFix, dbAtZName(db, iDb));
    fixSetPSchema(pFix, dbAtPSchema(db, iDb));
    fixSetZType(pFix, zType);
    fixSetPName(pFix, pName);
    fixSetBTemp(pFix, @intFromBool(iDb == 1));

    const w = fixWalker(pFix);
    wSetPParse(w, pParse);
    wSetXExpr(w, @ptrCast(&fixExprCb));
    wSetXSelect(w, @ptrCast(&fixSelectCb));
    wSetXSelect2(w, @ptrCast(&sqlite3WalkWinDefnDummyCallback));
    wSetWalkerDepth(w, 0);
    wSetECode(w, 0);
    wSetU(w, pFix); // w.u.pFix = pFix
}

// ═══ sqlite3FixSrcList ═══════════════════════════════════════════════════════
export fn sqlite3FixSrcList(pFix: ?*anyopaque, pList: ?*anyopaque) callconv(.c) c_int {
    var res: c_int = 0;
    if (pList != null) {
        // Select s; memset(&s,0,sizeof(s)); s.pSrc = pList.
        var s: [sizeof_Select]u8 align(8) = undefined;
        @memset(&s, 0);
        const ps: ?*anyopaque = @ptrCast(&s);
        wrPtr(?*anyopaque, ps, Select_pSrc_off, pList);
        res = sqlite3WalkSelect(fixWalker(pFix), ps);
    }
    return res;
}

// ═══ sqlite3FixSelect / sqlite3FixExpr (OMIT_VIEW || OMIT_TRIGGER off) ═══════
export fn sqlite3FixSelect(pFix: ?*anyopaque, pSelect: ?*anyopaque) callconv(.c) c_int {
    return sqlite3WalkSelect(fixWalker(pFix), pSelect);
}
export fn sqlite3FixExpr(pFix: ?*anyopaque, pExpr: ?*anyopaque) callconv(.c) c_int {
    return sqlite3WalkExpr(fixWalker(pFix), pExpr);
}

// ═══ sqlite3FixTriggerStep (OMIT_TRIGGER off) ════════════════════════════════
export fn sqlite3FixTriggerStep(pFix: ?*anyopaque, pStepIn: ?*anyopaque) callconv(.c) c_int {
    var pStep = pStepIn;
    const w = fixWalker(pFix);
    while (pStep) |step| {
        if (sqlite3WalkSelect(w, stepPSelect(step)) != 0 or
            sqlite3WalkExpr(w, stepPWhere(step)) != 0 or
            sqlite3WalkExprList(w, stepPExprList(step)) != 0 or
            sqlite3FixSrcList(pFix, stepPSrc(step)) != 0)
        {
            return 1;
        }
        // SQLITE_OMIT_UPSERT is OFF.
        var pUp = stepPUpsert(step);
        while (pUp) |up| {
            if (sqlite3WalkExprList(w, upTarget(up)) != 0 or
                sqlite3WalkExpr(w, upTargetWhere(up)) != 0 or
                sqlite3WalkExprList(w, upSet(up)) != 0 or
                sqlite3WalkExpr(w, upWhere(up)) != 0)
            {
                return 1;
            }
            pUp = upNext(up);
        }
        pStep = stepPNext(step);
    }
    return 0;
}
