//! Zig port of SQLite's bytecode interpreter (src/vdbe.c).
//!
//! This is THE virtual machine: sqlite3VdbeExec — the giant opcode-dispatch
//! loop that runs a prepared statement's VDBE program — plus the OP_ handlers
//! for every opcode, the register machine, and the helpers allocateCursor /
//! applyAffinity / out2Prerelease / the OP_Column record decoder.
//!
//! Strategy (identical to vdbeaux.zig / vdbeblob.zig):
//!  * The big structs (Vdbe, sqlite3, VdbeFrame, Savepoint, Db, Schema, Table,
//!    Column, KeyInfo, UnpackedRecord, SubProgram, sqlite3_module, …) are
//!    reached field-by-field at ground-truth offsets, config-selected against
//!    c_layout where present, else probed values (verified prod + --dev).
//!  * The HOT register-machine structs (Mem and VdbeOp) are modelled as Zig
//!    `extern struct` overlays. VdbeOp is config-invariant (sizeof 32). Mem's
//!    field offsets are invariant but its sizeof moves 56→72 under SQLITE_DEBUG;
//!    we pad the tail config-gated and stride aMem[] by the real sizeof. The
//!    DEBUG-only Mem fields (pScopyFrom/bScopy/…) are not modelled (we never
//!    touch them — their bookkeeping lives in vdbemem.zig's memAboutToChange).
//!  * VdbeCursor DIVERGES heavily prod/debug; modelled via offset accessors.
//!  * Everything heavy is delegated to already-ported Zig (btree/pager/vdbeaux/
//!    vdbemem/util/printf) or remaining C, called via extern.
//!
//! The dispatch is a plain `switch (opcode)`. SQLite's computed-goto is a perf
//! optimization only; the switch is behaviorally identical. The unstructured
//! gotos (jump_to_p2, abort_due_to_error, no_mem, …) are modelled with a small
//! state machine around the loop, since Zig has no cross-block goto.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

const DEBUG = config.sqlite_debug;

// ===========================================================================
// Result codes / states / constants
// ===========================================================================
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_BUSY: c_int = 5;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_READONLY: c_int = 8;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_IOERR: c_int = 10;
const SQLITE_CORRUPT: c_int = 11;
const SQLITE_FULL: c_int = 13;
const SQLITE_SCHEMA: c_int = 17;
const SQLITE_TOOBIG: c_int = 18;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_MISMATCH: c_int = 20;
const SQLITE_INTERNAL: c_int = 2;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_ABORT: c_int = 4;
const SQLITE_ABORT_ROLLBACK: c_int = SQLITE_ABORT | (2 << 8);
const SQLITE_BUSY_SNAPSHOT: c_int = SQLITE_BUSY | (2 << 8);
const SQLITE_BUSY_RECOVERY: c_int = SQLITE_BUSY | (1 << 8);
const SQLITE_CORRUPT_INDEX: c_int = SQLITE_CORRUPT | (3 << 8);
const SQLITE_CONSTRAINT_DATATYPE: c_int = SQLITE_CONSTRAINT | (12 << 8);
const SQLITE_IOERR_CORRUPTFS: c_int = SQLITE_IOERR | (33 << 8);
const SQLITE_IOERR_NOMEM: c_int = SQLITE_IOERR | (12 << 8);

const LARGEST_UINT64: u64 = 0xffffffff_ffffffff;
const SMALLEST_INT64: i64 = @bitCast(@as(u64, 0x8000000000000000));
const MAX_ROWID: i64 = 0x7fffffff_ffffffff;

// VDBE states
const VDBE_RUN_STATE: u8 = 2;
const VDBE_HALT_STATE: u8 = 3;

// CURTYPE_*
const CURTYPE_BTREE: u8 = 0;
const CURTYPE_SORTER: u8 = 1;
const CURTYPE_VTAB: u8 = 2;
const CURTYPE_PSEUDO: u8 = 3;
const CACHE_STALE: u32 = 0;
const SQLITE_FRAME_MAGIC: u32 = 0x879fb71e;

// SAVEPOINT_*
const SAVEPOINT_BEGIN: c_int = 0;
const SAVEPOINT_RELEASE: c_int = 1;
const SAVEPOINT_ROLLBACK: c_int = 2;

// ON-conflict actions (OE_*)
const OE_Rollback: u8 = 1;
const OE_Abort: u8 = 2;
const OE_Fail: u8 = 3;
const OE_Ignore: u8 = 4;
const OE_Replace: u8 = 5;

// MEM_* flags
const MEM_Undefined: u16 = 0x0000;
const MEM_Null: u16 = 0x0001;
const MEM_Str: u16 = 0x0002;
const MEM_Int: u16 = 0x0004;
const MEM_Real: u16 = 0x0008;
const MEM_Blob: u16 = 0x0010;
const MEM_IntReal: u16 = 0x0020;
const MEM_AffMask: u16 = 0x003f;
const MEM_FromBind: u16 = 0x0040;
const MEM_Cleared: u16 = 0x0100;
const MEM_Term: u16 = 0x0200;
const MEM_Zero: u16 = 0x0400;
const MEM_Subtype: u16 = 0x0800;
const MEM_TypeMask: u16 = 0x0dbf;
const MEM_Dyn: u16 = 0x1000;
const MEM_Static: u16 = 0x2000;
const MEM_Ephem: u16 = 0x4000;
const MEM_Agg: u16 = 0x8000;

// SQLITE_AFF_*
const SQLITE_AFF_NONE: u8 = 0x40;
const SQLITE_AFF_BLOB: u8 = 0x41;
const SQLITE_AFF_TEXT: u8 = 0x42;
const SQLITE_AFF_NUMERIC: u8 = 0x43;
const SQLITE_AFF_INTEGER: u8 = 0x44;
const SQLITE_AFF_REAL: u8 = 0x45;
const SQLITE_AFF_FLEXNUM: u8 = 0x46;
const SQLITE_AFF_MASK: u8 = 0x47;

// P5 flags for comparison opcodes
const SQLITE_JUMPIFNULL: u8 = 0x10;
const SQLITE_NULLEQ: u8 = 0x80;
const OPFLAG_PERMUTE: u8 = 0x01;

// OPFLAG_*
const OPFLAG_NCHANGE: u8 = 0x01;
const OPFLAG_LASTROWID: u8 = 0x20;
const OPFLAG_ISUPDATE: u8 = 0x04;
const OPFLAG_APPEND: u8 = 0x08;
const OPFLAG_USESEEKRESULT: u8 = 0x10;
const OPFLAG_ISNOOP: u8 = 0x40;
const OPFLAG_LENGTHARG: u8 = 0x40;
const OPFLAG_TYPEOFARG: u8 = 0x80;
const OPFLAG_BYTELENARG: u8 = 0xc0;
const OPFLAG_NOCHNG: u8 = 0x01;
const OPFLAG_NOCHNG_MAGIC: u8 = 0x6d;
const OPFLAG_PREFORMAT: u8 = 0x80;
const OPFLAG_SAVEPOSITION: u8 = 0x02;
const OPFLAG_AUXDELETE: u8 = 0x04;
const OPFLAG_SEEKEQ: u8 = 0x02;
const OPFLAG_P2ISREG: u8 = 0x10;
const OPFLAG_FORDELETE: u8 = 0x08;
const OPFLAG_BULKCSR: u8 = 0x01;
const OPFLAG_NULLROW: u8 = 0x40;

// BTREE_*
const BTREE_INTKEY: c_int = 1;
const BTREE_BLOBKEY: c_int = 2;
const BTREE_WRCSR: c_int = 0x00000004;
const BTREE_FORDELETE: c_int = 0x00000008;
const BTREE_SEEK_EQ: c_int = 0x00000002;
const BTREE_BULKLOAD: c_int = 0x00000001;
const BTREE_AUXDELETE: u8 = 0x04;
const BTREE_SAVEPOSITION: u8 = 0x02;
const BTREE_OMIT_JOURNAL: c_int = 1;
const BTREE_SINGLE: c_int = 4;
const BTREE_UNORDERED: c_int = 8;
const BTREE_SCHEMA_VERSION: c_int = 1;
const BTREE_FILE_FORMAT: c_int = 2;
const SCHEMA_ROOT: u32 = 1;

// KeyInfo sort flags
const KEYINFO_ORDER_DESC: u8 = 0x01;
const KEYINFO_ORDER_BIGNULL: u8 = 0x02;

// P4 types
const P4_NOTUSED: i8 = 0;
const P4_STATIC: i8 = -1;
const P4_COLLSEQ: i8 = -2;
const P4_INT32: i8 = -3;
const P4_SUBPROGRAM: i8 = -4;
const P4_TABLE: i8 = -5;
const P4_FUNCDEF: i8 = -8;
const P4_KEYINFO: i8 = -9;
const P4_MEM: i8 = -11;
const P4_VTAB: i8 = -12;
const P4_FUNCCTX: i8 = -16;
const P4_DYNAMIC: i8 = -7;
const P4_INTARRAY: i8 = -15;
const P4_TABLEREF: i8 = -17;
const P4_INDEX: i8 = -6;
const P4_EXPR: i8 = -10;

// SQLITE_LIMIT_* indices into db->aLimit[]
const SQLITE_LIMIT_LENGTH: usize = 0;
const SQLITE_LIMIT_VDBE_OP: usize = 5;
const SQLITE_LIMIT_TRIGGER_DEPTH: usize = 10;

// db->flags bits
const SQLITE_QueryOnly: u64 = 0x00100000;
const SQLITE_CorruptRdOnly: u64 = 0x40000000_00000000;
const SQLITE_DeferFKs: u64 = 0x00080000;
const SQLITE_VdbeTrace: u64 = 0x00000100; // (debug only; we never set)
const SQLITE_NoSchemaError: u64 = 0x08000000;
const SQLITE_LegacyAlter: u64 = 0x04000000;
const SQLITE_ReadUncommit: u64 = 0x00000400;
// db->mDbFlags
const DBFLAG_SchemaChange: u32 = 0x0001;
const DBFLAG_SchemaKnownOk: u32 = 0x0010;

// Trace masks
const SQLITE_TRACE_STMT: u8 = 0x01;
const SQLITE_TRACE_ROW: u8 = 0x04;
const SQLITE_TRACE_LEGACY: u8 = 0x40;

// Stmt status counters
const SQLITE_STMTSTATUS_FULLSCAN_STEP: u8 = 1;
const SQLITE_STMTSTATUS_SORT: usize = 2;
const SQLITE_STMTSTATUS_AUTOINDEX: u8 = 3;
const SQLITE_STMTSTATUS_VM_STEP: usize = 4;
const SQLITE_STMTSTATUS_RUN: usize = 6;
const SQLITE_STMTSTATUS_FILTER_MISS: usize = 7;
const SQLITE_STMTSTATUS_FILTER_HIT: usize = 8;

// txn states / checkpoint / pager journal modes
const SQLITE_TXN_WRITE: c_int = 2;
const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16BE: u8 = 3;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_CHECKPOINT_PASSIVE: c_int = 0;
const SQLITE_CHECKPOINT_FULL: c_int = 1;
const SQLITE_CHECKPOINT_RESTART: c_int = 2;
const SQLITE_CHECKPOINT_TRUNCATE: c_int = 3;
const SQLITE_CHECKPOINT_NOOP: c_int = 4;
const PAGER_JOURNALMODE_QUERY: c_int = -1;
const PAGER_JOURNALMODE_WAL: c_int = 5;
const PAGER_JOURNALMODE_MEMORY: c_int = 4;
const PAGER_JOURNALMODE_OFF: c_int = 2;

// Column types / flags
const TF_Strict: u32 = 0x00010000;
const COLFLAG_VIRTUAL: u16 = 0x0020;
const COLFLAG_GENERATED: u16 = 0x0060;
// Column.eCType values (vendored sqliteInt.h): CUSTOM=0, ANY=1, BLOB=2, INT=3,
// INTEGER=4, REAL=5, TEXT=6. These were off-by-one (missing CUSTOM), so STRICT
// type checks matched the wrong type or (for TEXT) fell through with no check.
const COLTYPE_ANY: u8 = 1;
const COLTYPE_BLOB: u8 = 2;
const COLTYPE_INT: u8 = 3;
const COLTYPE_INTEGER: u8 = 4;
const COLTYPE_REAL: u8 = 5;
const COLTYPE_TEXT: u8 = 6;

const NC_SelfRef: c_int = 0x00002e;

const SQLITE_RESULT_SUBTYPE: u32 = 0x001000000;
const SQLITE_N_BTREE_META: c_int = 16;

// LEGACY_SCHEMA_TABLE
const LEGACY_SCHEMA_TABLE: [*:0]const u8 = "sqlite_master";

// ===========================================================================
// Opcodes (vendored opcodes.h). Loaded as comptime from the vendored header
// would be ideal, but we list the ones we dispatch on. To stay robust against
// renumbering, we read them out of the vendored opcodes.h via @cImport-free
// constants generated here. (These match v3.54.0 opcodes.h exactly.)
// ===========================================================================
const OP_Savepoint       : u8 = 0;
const OP_AutoCommit      : u8 = 1;
const OP_Transaction     : u8 = 2;
const OP_Checkpoint      : u8 = 3;
const OP_JournalMode     : u8 = 4;
const OP_Vacuum          : u8 = 5;
const OP_VFilter         : u8 = 6;
const OP_VUpdate         : u8 = 7;
const OP_Init            : u8 = 8;
const OP_Goto            : u8 = 9;
const OP_Gosub           : u8 = 10;
const OP_InitCoroutine   : u8 = 11;
const OP_Yield           : u8 = 12;
const OP_MustBeInt       : u8 = 13;
const OP_Jump            : u8 = 14;
const OP_Once            : u8 = 15;
const OP_If              : u8 = 16;
const OP_IfNot           : u8 = 17;
const OP_IsType          : u8 = 18;
const OP_Not             : u8 = 19;
const OP_IfNullRow       : u8 = 20;
const OP_SeekLT          : u8 = 21;
const OP_SeekLE          : u8 = 22;
const OP_SeekGE          : u8 = 23;
const OP_SeekGT          : u8 = 24;
const OP_IfNotOpen       : u8 = 25;
const OP_IfNoHope        : u8 = 26;
const OP_NoConflict      : u8 = 27;
const OP_NotFound        : u8 = 28;
const OP_Found           : u8 = 29;
const OP_SeekRowid       : u8 = 30;
const OP_NotExists       : u8 = 31;
const OP_Last            : u8 = 32;
const OP_IfSizeBetween   : u8 = 33;
const OP_SorterSort      : u8 = 34;
const OP_Sort            : u8 = 35;
const OP_Rewind          : u8 = 36;
const OP_IfEmpty         : u8 = 37;
const OP_SorterNext      : u8 = 38;
const OP_Prev            : u8 = 39;
const OP_Next            : u8 = 40;
const OP_IdxLE           : u8 = 41;
const OP_IdxGT           : u8 = 42;
const OP_Or              : u8 = 43;
const OP_And             : u8 = 44;
const OP_IdxLT           : u8 = 45;
const OP_IdxGE           : u8 = 46;
const OP_IFindKey        : u8 = 47;
const OP_RowSetRead      : u8 = 48;
const OP_RowSetTest      : u8 = 49;
const OP_Program         : u8 = 50;
const OP_IsNull          : u8 = 51;
const OP_NotNull         : u8 = 52;
const OP_Ne              : u8 = 53;
const OP_Eq              : u8 = 54;
const OP_Gt              : u8 = 55;
const OP_Le              : u8 = 56;
const OP_Lt              : u8 = 57;
const OP_Ge              : u8 = 58;
const OP_ElseEq          : u8 = 59;
const OP_FkIfZero        : u8 = 60;
const OP_IfPos           : u8 = 61;
const OP_IfNotZero       : u8 = 62;
const OP_DecrJumpZero    : u8 = 63;
const OP_IncrVacuum      : u8 = 64;
const OP_VNext           : u8 = 65;
const OP_Filter          : u8 = 66;
const OP_PureFunc        : u8 = 67;
const OP_Function        : u8 = 68;
const OP_Return          : u8 = 69;
const OP_EndCoroutine    : u8 = 70;
const OP_HaltIfNull      : u8 = 71;
const OP_Halt            : u8 = 72;
const OP_Integer         : u8 = 73;
const OP_Int64           : u8 = 74;
const OP_String          : u8 = 75;
const OP_BeginSubrtn     : u8 = 76;
const OP_Null            : u8 = 77;
const OP_SoftNull        : u8 = 78;
const OP_Blob            : u8 = 79;
const OP_Variable        : u8 = 80;
const OP_Move            : u8 = 81;
const OP_Copy            : u8 = 82;
const OP_SCopy           : u8 = 83;
const OP_IntCopy         : u8 = 84;
const OP_FkCheck         : u8 = 85;
const OP_ResultRow       : u8 = 86;
const OP_CollSeq         : u8 = 87;
const OP_AddImm          : u8 = 88;
const OP_RealAffinity    : u8 = 89;
const OP_Cast            : u8 = 90;
const OP_Permutation     : u8 = 91;
const OP_Compare         : u8 = 92;
const OP_IsTrue          : u8 = 93;
const OP_ZeroOrNull      : u8 = 94;
const OP_Offset          : u8 = 95;
const OP_Column          : u8 = 96;
const OP_TypeCheck       : u8 = 97;
const OP_Affinity        : u8 = 98;
const OP_MakeRecord      : u8 = 99;
const OP_Count           : u8 = 100;
const OP_ReadCookie      : u8 = 101;
const OP_SetCookie       : u8 = 102;
const OP_BitAnd          : u8 = 103;
const OP_BitOr           : u8 = 104;
const OP_ShiftLeft       : u8 = 105;
const OP_ShiftRight      : u8 = 106;
const OP_Add             : u8 = 107;
const OP_Subtract        : u8 = 108;
const OP_Multiply        : u8 = 109;
const OP_Divide          : u8 = 110;
const OP_Remainder       : u8 = 111;
const OP_Concat          : u8 = 112;
const OP_ReopenIdx       : u8 = 113;
const OP_OpenRead        : u8 = 114;
const OP_BitNot          : u8 = 115;
const OP_OpenWrite       : u8 = 116;
const OP_OpenDup         : u8 = 117;
const OP_String8         : u8 = 118;
const OP_OpenAutoindex   : u8 = 119;
const OP_OpenEphemeral   : u8 = 120;
const OP_SorterOpen      : u8 = 121;
const OP_SequenceTest    : u8 = 122;
const OP_OpenPseudo      : u8 = 123;
const OP_Close           : u8 = 124;
const OP_ColumnsUsed     : u8 = 125;
const OP_SeekScan        : u8 = 126;
const OP_SeekHit         : u8 = 127;
const OP_Sequence        : u8 = 128;
const OP_NewRowid        : u8 = 129;
const OP_Insert          : u8 = 130;
const OP_RowCell         : u8 = 131;
const OP_Delete          : u8 = 132;
const OP_ResetCount      : u8 = 133;
const OP_SorterCompare   : u8 = 134;
const OP_SorterData      : u8 = 135;
const OP_RowData         : u8 = 136;
const OP_Rowid           : u8 = 137;
const OP_NullRow         : u8 = 138;
const OP_SeekEnd         : u8 = 139;
const OP_IdxInsert       : u8 = 140;
const OP_SorterInsert    : u8 = 141;
const OP_IdxDelete       : u8 = 142;
const OP_DeferredSeek    : u8 = 143;
const OP_IdxRowid        : u8 = 144;
const OP_FinishSeek      : u8 = 145;
const OP_Destroy         : u8 = 146;
const OP_Clear           : u8 = 147;
const OP_ResetSorter     : u8 = 148;
const OP_CreateBtree     : u8 = 149;
const OP_SqlExec         : u8 = 150;
const OP_ParseSchema     : u8 = 151;
const OP_LoadAnalysis    : u8 = 152;
const OP_DropTable       : u8 = 153;
const OP_Real            : u8 = 154;
const OP_DropIndex       : u8 = 155;
const OP_DropTrigger     : u8 = 156;
const OP_IntegrityCk     : u8 = 157;
const OP_RowSetAdd       : u8 = 158;
const OP_Param           : u8 = 159;
const OP_FkCounter       : u8 = 160;
const OP_MemMax          : u8 = 161;
const OP_OffsetLimit     : u8 = 162;
const OP_AggInverse      : u8 = 163;
const OP_AggStep         : u8 = 164;
const OP_AggStep1        : u8 = 165;
const OP_AggValue        : u8 = 166;
const OP_AggFinal        : u8 = 167;
const OP_Expire          : u8 = 168;
const OP_CursorLock      : u8 = 169;
const OP_CursorUnlock    : u8 = 170;
const OP_TableLock       : u8 = 171;
const OP_VBegin          : u8 = 172;
const OP_VCreate         : u8 = 173;
const OP_VDestroy        : u8 = 174;
const OP_VOpen           : u8 = 175;
const OP_VCheck          : u8 = 176;
const OP_VInitIn         : u8 = 177;
const OP_VColumn         : u8 = 178;
const OP_VRename         : u8 = 179;
const OP_Pagecount       : u8 = 180;
const OP_MaxPgcnt        : u8 = 181;
const OP_ClrSubtype      : u8 = 182;
const OP_GetSubtype      : u8 = 183;
const OP_SetSubtype      : u8 = 184;
const OP_FilterAdd       : u8 = 185;
const OP_Trace           : u8 = 186;
const OP_CursorHint      : u8 = 187;
const OP_ReleaseReg      : u8 = 188;
const OP_Noop            : u8 = 189;
const OP_Explain         : u8 = 190;
const OP_Abortable       : u8 = 191;

// ===========================================================================
// Opaque handle aliases
// ===========================================================================
const sqlite3 = anyopaque;
const Vdbe = anyopaque;
const Btree = anyopaque;
const BtCursor = anyopaque;
const Pager = anyopaque;
const KeyInfo = anyopaque;
const FuncDef = anyopaque;
const Table = anyopaque;
const Index = anyopaque;
const CollSeq = anyopaque;
const VTable = anyopaque;
const RowSet = anyopaque;
const sqlite3_vtab = anyopaque;
const sqlite3_vtab_cursor = anyopaque;
const sqlite3_module = anyopaque;
const sqlite3_context = anyopaque;

// ===========================================================================
// Hot-path struct overlays (config-invariant field offsets).
// ===========================================================================

// VdbeOp / VdbeOp — sizeof 32 in both configs. p4 is a union; we treat it as
// raw bytes and read it typed as needed.
const Op = extern struct {
    opcode: u8,
    p4type: i8,
    p5: u16,
    p1: c_int,
    p2: c_int,
    p3: c_int,
    p4: extern union {
        i: c_int,
        p: ?*anyopaque,
        z: ?[*:0]u8,
        pI64: ?*i64,
        pReal: ?*f64,
        pFunc: ?*FuncDef,
        pColl: ?*CollSeq,
        pVtab: ?*VTable,
        pKeyInfo: ?*KeyInfo,
        ai: ?[*]u32,
        pProgram: ?*anyopaque,
        pTab: ?*Table,
        pCtx: ?*sqlite3_context,
        pIdx: ?*Index,
        pMem: ?*Mem,
        pExpr: ?*anyopaque,
    },
    // zComment present (EXPLAIN_COMMENTS on in both) — 8 bytes, ignored
    zComment: ?[*:0]u8,
};
comptime {
    std.debug.assert(@sizeOf(Op) == 32);
    std.debug.assert(@offsetOf(Op, "p1") == 4);
    std.debug.assert(@offsetOf(Op, "p4") == 16);
}

// Mem (sqlite3_value). Field offsets invariant; sizeof 56 prod / 72 debug.
const sizeof_Mem: usize = if (@hasDecl(L, "sizeof_Mem")) L.sizeof_Mem else if (DEBUG) 72 else 56;
// MEMCELLSIZE == offsetof(Mem,db): the "shallow copy" prefix (u,z,n,flags,
// enc,eSubtype). OP_Variable memcpy's exactly this prefix — copying more would
// clobber pOut's szMalloc/zMalloc with pVar's, aliasing the bound-parameter
// buffer and double-freeing it (corrupts the lookaside free-list).
const MEMCELLSIZE: usize = if (@hasDecl(L, "sqlite3_value_db")) L.sqlite3_value_db else 24;

const Mem = extern struct {
    u: extern union { r: f64, i: i64, nZero: c_int, pPtr: ?*anyopaque },
    z: ?[*]u8,
    n: c_int,
    flags: u16,
    enc: u8,
    eSubtype: u8,
    db: ?*sqlite3,
    szMalloc: c_int,
    uTemp: u32,
    zMalloc: ?[*]u8,
    xDel: ?*const fn (?*anyopaque) callconv(.c) void,
    // DEBUG tail (pScopyFrom, mScopyFlags, bScopy, …) not modelled.
};
comptime {
    std.debug.assert(@offsetOf(Mem, "flags") == 20);
    std.debug.assert(@offsetOf(Mem, "z") == 8);
    std.debug.assert(@offsetOf(Mem, "db") == 24);
    std.debug.assert(@offsetOf(Mem, "xDel") == 48);
}

inline fn memAt(aMem: [*]u8, i: anytype) *Mem {
    const idx: usize = @intCast(i);
    return @ptrCast(@alignCast(aMem + idx * sizeof_Mem));
}

// ===========================================================================
// Offset helpers for the big (divergent) structs.
// ===========================================================================
fn off(comptime name: []const u8, prod: usize, dbg: usize) usize {
    return if (@hasDecl(L, name)) @field(L, name) else if (DEBUG) dbg else prod;
}

inline fn fp(comptime T: type, base: ?*anyopaque, o: usize) *T {
    const p: [*]u8 = @ptrCast(base.?);
    return @ptrCast(@alignCast(p + o));
}
inline fn rd(comptime T: type, base: ?*anyopaque, o: usize) T {
    return fp(T, base, o).*;
}
inline fn wr(comptime T: type, base: ?*anyopaque, o: usize, v: T) void {
    fp(T, base, o).* = v;
}
inline fn rdU8(base: ?*anyopaque, o: usize) u8 {
    const p: [*]const u8 = @ptrCast(base.?);
    return p[o];
}
inline fn wrU8(base: ?*anyopaque, o: usize, v: u8) void {
    const p: [*]u8 = @ptrCast(base.?);
    p[o] = v;
}
inline fn rdPtr(base: ?*anyopaque, o: usize) ?*anyopaque {
    return fp(?*anyopaque, base, o).*;
}
inline fn wrPtr(base: ?*anyopaque, o: usize, v: ?*anyopaque) void {
    fp(?*anyopaque, base, o).* = v;
}

// --- struct Vdbe ---
const Vdbe_db = off("Vdbe_db", 0, 0);
const Vdbe_nVar = off("Vdbe_nVar", 32, 32);
const Vdbe_nMem = off("Vdbe_nMem", 36, 36);
const Vdbe_nCursor = off("Vdbe_nCursor", 40, 40);
const Vdbe_cacheCtr = off("Vdbe_cacheCtr", 44, 44);
const Vdbe_pc = off("Vdbe_pc", 48, 48);
const Vdbe_rc = off("Vdbe_rc", 52, 52);
const Vdbe_nChange = off("Vdbe_nChange", 56, 56);
const Vdbe_iStatement = off("Vdbe_iStatement", 64, 64);
const Vdbe_iCurrentTime = off("Vdbe_iCurrentTime", 72, 72);
const Vdbe_nFkConstraint = off("Vdbe_nFkConstraint", 80, 80);
const Vdbe_nStmtDefCons = off("Vdbe_nStmtDefCons", 88, 88);
const Vdbe_nStmtDefImmCons = off("Vdbe_nStmtDefImmCons", 96, 96);
const Vdbe_aMem = off("Vdbe_aMem", 104, 104);
const Vdbe_apArg = off("Vdbe_apArg", 112, 112);
const Vdbe_apCsr = off("Vdbe_apCsr", 120, 120);
const Vdbe_aVar = off("Vdbe_aVar", 128, 128);
const Vdbe_aOp = off("Vdbe_aOp", 136, 136);
const Vdbe_nOp = off("Vdbe_nOp", 144, 144);
const Vdbe_aColName = off("Vdbe_aColName", 152, 152);
const Vdbe_pResultRow = off("Vdbe_pResultRow", 160, 160);
const Vdbe_zErrMsg = off("Vdbe_zErrMsg", 168, 168);
const Vdbe_nResColumn = off("Vdbe_nResColumn", 192, 204);
const Vdbe_errorAction = off("Vdbe_errorAction", 196, 208);
const Vdbe_minWriteFileFormat = off("Vdbe_minWriteFileFormat", 197, 209);
const Vdbe_prepFlags = off("Vdbe_prepFlags", 198, 210);
const Vdbe_eVdbeState = off("Vdbe_eVdbeState", 199, 211);
const Vdbe_bitfields = Vdbe_eVdbeState + 1;
const Vdbe_lockMask = off("Vdbe_lockMask", 208, 220);
const Vdbe_aCounter = off("Vdbe_aCounter", 212, 224);
const Vdbe_zSql = off("Vdbe_zSql", 248, 264);
const Vdbe_pFrame = off("Vdbe_pFrame", 264, 280);
const Vdbe_nFrame = off("Vdbe_nFrame", 280, 296);
const Vdbe_pProgram = off("Vdbe_pProgram", 288, 304);
const Vdbe_pAuxData = off("Vdbe_pAuxData", 296, 312);
// (Vdbe.napArg is SQLITE_DEBUG-only, used only in asserts; not modelled.)

// Vdbe bitfield byte (expired:2, explain:2, changeCntOn:1, usesStmtJournal:1,
// readOnly:1, bIsReader:1) sharing one byte at eVdbeState+1.
inline fn vbits(v: ?*anyopaque) *u8 {
    return fp(u8, v, Vdbe_bitfields);
}
inline fn getExpired(v: ?*anyopaque) u8 {
    return vbits(v).* & 0x03;
}
inline fn setExpired(v: ?*anyopaque, val: u8) void {
    const p = vbits(v);
    p.* = (p.* & ~@as(u8, 0x03)) | (val & 0x03);
}
inline fn setExplain(v: ?*anyopaque, val: u8) void {
    const p = vbits(v);
    p.* = (p.* & ~@as(u8, 0x0c)) | ((val & 0x03) << 2);
}
inline fn getExplain(v: ?*anyopaque) u8 {
    return (vbits(v).* >> 2) & 0x03;
}
inline fn getChangeCntOn(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x10) != 0;
}
inline fn setChangeCntOn(v: ?*anyopaque, b: bool) void {
    const p = vbits(v);
    if (b) p.* |= 0x10 else p.* &= ~@as(u8, 0x10);
}
inline fn getUsesStmtJournal(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x20) != 0;
}
inline fn getReadOnly(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x40) != 0;
}
inline fn getBIsReader(v: ?*anyopaque) bool {
    return (vbits(v).* & 0x80) != 0;
}

// --- struct sqlite3 ---
const sqlite3_pVfs = off("sqlite3_pVfs", 0, 0);
const sqlite3_aDb = off("sqlite3_aDb", 32, 32);
const sqlite3_nDb = off("sqlite3_nDb", 40, 40);
const sqlite3_mDbFlags = off("sqlite3_mDbFlags", 44, 44);
const sqlite3_flags = off("sqlite3_flags", 48, 48);
const sqlite3_lastRowid = off("sqlite3_lastRowid", 56, 56);
const sqlite3_enc = off("sqlite3_enc", 100, 100);
const sqlite3_autoCommit = off("sqlite3_autoCommit", 101, 101);
const sqlite3_mallocFailed = off("sqlite3_mallocFailed", 103, 103);
const sqlite3_vtabOnConflict = off("sqlite3_vtabOnConflict", 108, 108);
const sqlite3_isTransactionSavepoint = off("sqlite3_isTransactionSavepoint", 109, 109);
const sqlite3_mTrace = off("sqlite3_mTrace", 110, 110);
const sqlite3_nSqlExec = off("sqlite3_nSqlExec", 112, 112);
const sqlite3_nChange = off("sqlite3_nChange", 120, 120);
const sqlite3_nVdbeActive = off("sqlite3_nVdbeActive", 208, 208);
const sqlite3_nVdbeRead = off("sqlite3_nVdbeRead", 212, 212);
const sqlite3_nVdbeWrite = off("sqlite3_nVdbeWrite", 216, 216);
const sqlite3_nVdbeExec = off("sqlite3_nVdbeExec", 220, 220);
const sqlite3_nVDestroy = off("sqlite3_nVDestroy", 224, 224);
const sqlite3_pUpdateArg = off("sqlite3_pUpdateArg", 304, 304);
const sqlite3_xUpdateCallback = off("sqlite3_xUpdateCallback", 312, 312);
const sqlite3_xPreUpdateCallback = off("sqlite3_xPreUpdateCallback", 360, 360);
const sqlite3_u1_isInterrupted = off("sqlite3_u1_isInterrupted", 424, 424);
const sqlite3_busyHandler_nBusy = off("sqlite3_busyHandler_nBusy", 680, 680);
const sqlite3_init_busy = off("sqlite3_init_busy", 197, 197);
const sqlite3_trace = off("sqlite3_trace", 240, 240);
const sqlite3_pTraceArg = off("sqlite3_pTraceArg", 248, 248);
const sqlite3_nProgressOps = off("sqlite3_nProgressOps", 560, 560);
const sqlite3_xProgress = off("sqlite3_xProgress", 544, 544);
const sqlite3_pProgressArg = off("sqlite3_pProgressArg", 552, 552);
const sqlite3_aLimit = off("sqlite3_aLimit", 136, 136);
const sqlite3_nStatement = off("sqlite3_nStatement", 772, 772);
const sqlite3_nSavepoint = off("sqlite3_nSavepoint", 768, 768);
const sqlite3_pSavepoint = off("sqlite3_pSavepoint", 752, 752);
const sqlite3_nDeferredCons = off("sqlite3_nDeferredCons", 776, 776);
const sqlite3_nDeferredImmCons = off("sqlite3_nDeferredImmCons", 784, 784);
const sqlite3_nVTrans = off("sqlite3_nVTrans", 564, 564);
const sqlite3_nAnalysisLimit = off("sqlite3_nAnalysisLimit", 760, 760);
const sqlite3_xAuth = off("sqlite3_xAuth", 528, 528);

inline fn dbLimit(db: ?*anyopaque, idx: usize) c_int {
    return fp(c_int, db, sqlite3_aLimit + idx * @sizeOf(c_int)).*;
}
inline fn ENC(db: ?*anyopaque) u8 {
    return rdU8(db, sqlite3_enc);
}
inline fn mallocFailed(db: ?*anyopaque) bool {
    return rdU8(db, sqlite3_mallocFailed) != 0;
}
inline fn isInterrupted(db: ?*anyopaque) bool {
    // u1.isInterrupted is an AtomicInt (int). Plain read suffices here.
    return rd(c_int, db, sqlite3_u1_isInterrupted) != 0;
}

// --- struct Db (sizeof 32) ---
const Db_zDbSName = off("Db_zDbSName", 0, 0);
const Db_pBt = off("Db_pBt", 8, 8);
const Db_pSchema = off("Db_pSchema", 24, 24);
const sizeof_Db = off("sizeof_Db", 32, 32);
inline fn dbEnt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const aDb = rdPtr(db, sqlite3_aDb).?;
    return @as([*]u8, @ptrCast(aDb)) + @as(usize, @intCast(i)) * sizeof_Db;
}

// --- struct Schema ---
const Schema_schema_cookie = off("Schema_schema_cookie", 0, 0);
const Schema_iGeneration = off("Schema_iGeneration", 4, 4);
const Schema_file_format = off("Schema_file_format", 112, 112);

// --- struct Savepoint (sizeof 32) ---
const Savepoint_zName = off("Savepoint_zName", 0, 0);
const Savepoint_nDeferredCons = off("Savepoint_nDeferredCons", 8, 8);
const Savepoint_nDeferredImmCons = off("Savepoint_nDeferredImmCons", 16, 16);
const Savepoint_pNext = off("Savepoint_pNext", 24, 24);
const sizeof_Savepoint = off("sizeof_Savepoint", 32, 32);

// --- struct VdbeFrame (DIVERGES under DEBUG: iFrameMagic) ---
const VdbeFrame_v = off("VdbeFrame_v", 0, 0);
const VdbeFrame_pParent = off("VdbeFrame_pParent", 8, 8);
const VdbeFrame_aOp = off("VdbeFrame_aOp", 16, 16);
const VdbeFrame_aMem = off("VdbeFrame_aMem", 24, 24);
const VdbeFrame_apCsr = off("VdbeFrame_apCsr", 32, 32);
const VdbeFrame_aOnce = off("VdbeFrame_aOnce", 40, 40);
const VdbeFrame_token = off("VdbeFrame_token", 48, 48);
const VdbeFrame_lastRowid = off("VdbeFrame_lastRowid", 56, 56);
const VdbeFrame_pAuxData = off("VdbeFrame_pAuxData", 64, 64);
const VdbeFrame_iFrameMagic = 72; // DEBUG only
const VdbeFrame_nCursor = off("VdbeFrame_nCursor", 72, 76);
const VdbeFrame_pc = off("VdbeFrame_pc", 76, 80);
const VdbeFrame_nOp = off("VdbeFrame_nOp", 80, 84);
const VdbeFrame_nMem = off("VdbeFrame_nMem", 84, 88);
const VdbeFrame_nChildMem = off("VdbeFrame_nChildMem", 88, 92);
const VdbeFrame_nChildCsr = off("VdbeFrame_nChildCsr", 92, 96);
const VdbeFrame_nChange = off("VdbeFrame_nChange", 96, 104);
const VdbeFrame_nDbChange = off("VdbeFrame_nDbChange", 104, 112);
const sizeof_VdbeFrame = off("sizeof_VdbeFrame", 112, 120);
inline fn VdbeFrameMem(pFrame: ?*anyopaque) [*]u8 {
    // (Mem*)((u8*)pFrame + ROUND8(sizeof(VdbeFrame)))
    const r8 = (sizeof_VdbeFrame + 7) & ~@as(usize, 7);
    return @as([*]u8, @ptrCast(pFrame.?)) + r8;
}

// --- struct VdbeCursor (DIVERGES) ---
const VC_eCurType = off("VdbeCursor_eCurType", 0, 0);
const VC_iDb = off("VdbeCursor_iDb", 1, 1);
const VC_nullRow = off("VdbeCursor_nullRow", 2, 2);
const VC_deferredMoveto = off("VdbeCursor_deferredMoveto", 3, 3);
const VC_isTable = off("VdbeCursor_isTable", 4, 4);
const VC_bits = off("VdbeCursor_bits", 5, 7);
const VC_seekHit = off("VdbeCursor_seekHit", 6, 8);
const VC_ub = off("VdbeCursor_ub", 8, 16);
const VC_seqCount = off("VdbeCursor_seqCount", 16, 24);
const VC_cacheStatus = off("VdbeCursor_cacheStatus", 24, 32);
const VC_seekResult = off("VdbeCursor_seekResult", 28, 36);
const VC_pAltCursor = off("VdbeCursor_pAltCursor", 32, 40);
const VC_uc = off("VdbeCursor_uc", 40, 48);
const VC_pKeyInfo = off("VdbeCursor_pKeyInfo", 48, 56);
const VC_iHdrOffset = off("VdbeCursor_iHdrOffset", 56, 64);
const VC_pgnoRoot = off("VdbeCursor_pgnoRoot", 60, 68);
const VC_nField = off("VdbeCursor_nField", 64, 72);
const VC_nHdrParsed = off("VdbeCursor_nHdrParsed", 66, 74);
const VC_movetoTarget = off("VdbeCursor_movetoTarget", 72, 80);
const VC_aOffset = off("VdbeCursor_aOffset", 80, 88);
const VC_aRow = off("VdbeCursor_aRow", 88, 96);
const VC_payloadSize = off("VdbeCursor_payloadSize", 96, 104);
const VC_szRow = off("VdbeCursor_szRow", 100, 108);
const VC_pCache = off("VdbeCursor_pCache", 104, 112);
const VC_aType = off("VdbeCursor_aType", 112, 120);
const VC_seekOp = off("VdbeCursor_seekOp", 5, 5); // DEBUG only

// VdbeCursor :1 bitfield bits at VC_bits
const BIT_isEphemeral: u8 = 0x01;
const BIT_useRandomRowid: u8 = 0x02;
const BIT_isOrdered: u8 = 0x04;
const BIT_noReuse: u8 = 0x08;
const BIT_colCache: u8 = 0x10;
inline fn vcBit(pC: ?*anyopaque, m: u8) bool {
    return (rdU8(pC, VC_bits) & m) != 0;
}
inline fn vcSetBit(pC: ?*anyopaque, m: u8, b: bool) void {
    const p = fp(u8, pC, VC_bits);
    if (b) p.* |= m else p.* &= ~m;
}
inline fn isSorter(pC: ?*anyopaque) bool {
    return rdU8(pC, VC_eCurType) == CURTYPE_SORTER;
}

// --- struct KeyInfo ---
const KeyInfo_enc = off("KeyInfo_enc", 4, 4);
const KeyInfo_nKeyField = off("KeyInfo_nKeyField", 6, 6);
const KeyInfo_nAllField = off("KeyInfo_nAllField", 8, 8);
const KeyInfo_db = off("KeyInfo_db", 16, 16);
const KeyInfo_aSortFlags = off("KeyInfo_aSortFlags", 24, 24);
const KeyInfo_aColl = off("KeyInfo_aColl", 32, 32);

// --- struct UnpackedRecord (sizeof 40) ---
const UR_pKeyInfo = off("UnpackedRecord_pKeyInfo", 0, 0);
const UR_aMem = off("UnpackedRecord_aMem", 8, 8);
const UR_nField = off("UnpackedRecord_nField", 28, 28);
const UR_default_rc = off("UnpackedRecord_default_rc", 30, 30);
const UR_eqSeen = off("UnpackedRecord_eqSeen", 34, 34);
const sizeof_UnpackedRecord = off("sizeof_UnpackedRecord", 40, 40);

// A small on-stack UnpackedRecord. We allocate the C-layout-sized bytes and
// access via offsets, so it is ABI-compatible with the b-tree consumers.
const URBuf = struct {
    bytes: [64]u8 align(8) = std.mem.zeroes([64]u8),
    inline fn ptr(self: *URBuf) ?*anyopaque {
        return @ptrCast(&self.bytes);
    }
};

// --- struct SubProgram ---
const SubProgram_aOp = off("SubProgram_aOp", 0, 0);
const SubProgram_nOp = off("SubProgram_nOp", 8, 8);
const SubProgram_nMem = off("SubProgram_nMem", 12, 12);
const SubProgram_nCsr = off("SubProgram_nCsr", 16, 16);
const SubProgram_token = off("SubProgram_token", 32, 32);

// --- struct sqlite3_context ---
const Ctx_pOut = off("sqlite3_context_pOut", 0, 0);
const Ctx_pFunc = off("sqlite3_context_pFunc", 8, 8);
const Ctx_pMem = off("sqlite3_context_pMem", 16, 16);
const Ctx_pVdbe = off("sqlite3_context_pVdbe", 24, 24);
const Ctx_iOp = off("sqlite3_context_iOp", 32, 32);
const Ctx_isError = off("sqlite3_context_isError", 36, 36);
const Ctx_enc = off("sqlite3_context_enc", 40, 40);
const Ctx_skipFlag = off("sqlite3_context_skipFlag", 41, 41);
const Ctx_argc = off("sqlite3_context_argc", 42, 42);
const Ctx_argv = 48;
const sizeof_sqlite3_context = 48;

// --- struct Table ---
const Table_zName = off("Table_zName", 0, 0);
const Table_aCol = off("Table_aCol", 8, 8);
const Table_tabFlags = off("Table_tabFlags", 48, 48);
const Table_nCol = off("Table_nCol", 54, 54);
const Table_uvtab = off("Table_uvtab_p", 80, 80); // u.vtab.p (union@64 + vtab.p@16)
// Column
const Column_zCnName = off("Column_zCnName", 0, 0);
const Column_eCTypeByte = off("Column_eCTypeByte", 8, 8); // byte holding notNull:4,eCType:4
const Column_affinity = off("Column_affinity", 9, 9);
const Column_colFlags = off("Column_colFlags", 14, 14);
const sizeof_Column = off("sizeof_Column", 16, 16);

// --- struct FuncDef ---
const FuncDef_funcFlags = off("FuncDef_funcFlags", 4, 4);
const FuncDef_pUserData = off("FuncDef_pUserData", 8, 8);
const FuncDef_xSFunc = off("FuncDef_xSFunc", 24, 24);
const FuncDef_xValue = off("FuncDef_xValue", 40, 40);
const FuncDef_xInverse = off("FuncDef_xInverse", 48, 48);
const sizeof_FuncDef = off("sizeof_FuncDef", 72, 72);

// --- struct sqlite3_module method offsets ---
const mod_xOpen = off("sqlite3_module_xOpen", 48, 48);
const mod_xClose = off("sqlite3_module_xClose", 56, 56);
const mod_xFilter = off("sqlite3_module_xFilter", 64, 64);
const mod_xNext = off("sqlite3_module_xNext", 72, 72);
const mod_xEof = off("sqlite3_module_xEof", 80, 80);
const mod_xColumn = off("sqlite3_module_xColumn", 88, 88);
const mod_xRowid = off("sqlite3_module_xRowid", 96, 96);
const mod_xUpdate = off("sqlite3_module_xUpdate", 104, 104);
const mod_xRename = off("sqlite3_module_xRename", 152, 152);
const mod_xIntegrity = off("sqlite3_module_xIntegrity", 192, 192);

// --- sqlite3_vtab / vtab_cursor ---
const vtab_pModule = off("sqlite3_vtab_pModule", 0, 0);
const vtab_nRef = off("sqlite3_vtab_nRef", 8, 8);
const vcur_pVtab = off("sqlite3_vtab_cursor_pVtab", 0, 0);
// VTable
const VTable_pVtab = off("VTable_pVtab", 16, 16);
const VTable_bConstraint = off("VTable_bConstraint", 28, 28);

// --- struct BtreePayload (sizeof 48) ---
const BP_pKey = off("BtreePayload_pKey", 0, 0);
const BP_nKey = off("BtreePayload_nKey", 8, 8);
const BP_pData = off("BtreePayload_pData", 16, 16);
const BP_aMem = off("BtreePayload_aMem", 24, 24);
const BP_nMem = off("BtreePayload_nMem", 32, 32);
const BP_nData = off("BtreePayload_nData", 36, 36);
const BP_nZero = off("BtreePayload_nZero", 40, 40);
const sizeof_BtreePayload = off("sizeof_BtreePayload", 48, 48);

// --- struct InitData (sizeof 40) ---
const ID_db = 0;
const ID_pzErrMsg = 8;
const ID_iDb = 16;
const ID_rc = 20;
const ID_mInitFlags = 24;
const ID_nInitRow = 28;
const ID_mxPage = 32;
const sizeof_InitData = 40;

// --- struct ValueList (sizeof 16) ---
const VL_pCsr = 0;
const VL_pOut = 8;
const sizeof_ValueList = 16;

// ===========================================================================
// Test-only globals — DEFINED here (C: `int sqlite3_search_count=0;` etc.).
// vdbeaux.zig externs sqlite3_search_count; we are its definition. Gated on
// SQLITE_TEST like upstream.
// ===========================================================================
var g_search_count: c_int = 0;
var g_interrupt_count: c_int = 0;
var g_sort_count: c_int = 0;
var g_max_blobsize: c_int = 0;
var g_found_count: c_int = 0;
comptime {
    if (config.sqlite_test) {
        @export(&g_search_count, .{ .name = "sqlite3_search_count" });
        @export(&g_interrupt_count, .{ .name = "sqlite3_interrupt_count" });
        @export(&g_sort_count, .{ .name = "sqlite3_sort_count" });
        @export(&g_max_blobsize, .{ .name = "sqlite3_max_blobsize" });
        @export(&g_found_count, .{ .name = "sqlite3_found_count" });
    }
}
inline fn updateMaxBlobsize(p: *Mem) void {
    if (config.sqlite_test) {
        if ((p.flags & (MEM_Str | MEM_Blob)) != 0 and p.n > g_max_blobsize) {
            g_max_blobsize = p.n;
        }
    }
}

// ===========================================================================
// External C / ported-Zig symbols.
// ===========================================================================
extern fn sqlite3DbMallocRaw(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocRawNN(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocZero(db: ?*sqlite3, n: u64) ?*anyopaque;
extern fn sqlite3DbFree(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3DbFreeNN(db: ?*sqlite3, p: ?*anyopaque) void;
extern fn sqlite3DbStrDup(db: ?*sqlite3, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3OomFault(db: ?*sqlite3) void;
extern fn sqlite3_snprintf(n: c_int, zBuf: [*]u8, zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3MPrintf(db: ?*sqlite3, zFormat: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_log(iErrCode: c_int, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3_randomness(N: c_int, pBuf: ?*anyopaque) void;
extern fn sqlite3_interrupt(db: ?*sqlite3) void;
extern fn sqlite3_strlike(zPattern: [*:0]const u8, zStr: ?[*:0]const u8, esc: c_uint) c_int;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3SystemError(db: ?*sqlite3, rc: c_int) void;
extern fn sqlite3ErrStr(rc: c_int) [*:0]const u8;
extern fn sqlite3IsNaN(x: f64) c_int;
extern fn sqlite3GetVarint32(p: [*]const u8, v: *u32) u8;
extern fn sqlite3PutVarint(p: [*]u8, v: u64) c_int;
extern fn sqlite3VarintLen(v: u64) c_int;
extern fn sqlite3LogEst(v: u64) u16;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn sqlite3_exec(db: ?*sqlite3, sql: ?[*:0]const u8, cb: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn strncmp(a: [*:0]const u8, b: [*:0]const u8, n: usize) c_int;

// arithmetic helpers (util.zig)
extern fn sqlite3AddInt64(pA: *i64, b: i64) c_int;
extern fn sqlite3SubInt64(pA: *i64, b: i64) c_int;
extern fn sqlite3MulInt64(pA: *i64, b: i64) c_int;
extern fn sqlite3Atoi64(z: ?[*]const u8, p: *i64, n: c_int, enc: u8) c_int;
extern fn sqlite3RealToI64(r: f64) i64;
extern fn sqlite3RealSameAsInt(r: f64, i: i64) c_int;
extern fn sqlite3IntFloatCompare(i: i64, r: f64) c_int;

// Vdbe helpers (vdbeaux.zig)
extern fn sqlite3VdbeError(p: ?*Vdbe, zFormat: [*:0]const u8, ...) void;
extern fn sqlite3VdbeHalt(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeSetChanges(db: ?*sqlite3, n: i64) void;
extern fn sqlite3VdbeFrameRestore(pFrame: ?*anyopaque) c_int;
extern fn sqlite3VdbeCheckFkImmediate(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeCheckFkDeferred(p: ?*Vdbe) c_int;
extern fn sqlite3VdbeEnter(p: ?*Vdbe) void;
extern fn sqlite3VdbeLeave(p: ?*Vdbe) void;
// sqlite3VdbeIOTraceSql is defined only under SQLITE_ENABLE_IOTRACE, which is
// enabled in neither the production nor the --dev testfixture config — so the
// upstream call site is a no-op macro. Mirror that with a no-op wrapper.
inline fn sqlite3VdbeIOTraceSql(p: ?*Vdbe) void {
    _ = p;
}
extern fn sqlite3VdbeFreeCursor(p: ?*Vdbe, pC: ?*anyopaque) void;
extern fn sqlite3VdbeFreeCursorNN(p: ?*Vdbe, pC: ?*anyopaque) void;
extern fn sqlite3VdbeSorterClose(db: ?*sqlite3, pC: ?*anyopaque) void;
extern fn sqlite3VdbeFinishMoveto(pC: ?*anyopaque) c_int;
extern fn sqlite3VdbeHandleMovedCursor(pC: ?*anyopaque) c_int;
extern fn sqlite3VdbeCursorRestore(pC: ?*anyopaque) c_int;
extern fn sqlite3VdbeIdxRowid(db: ?*sqlite3, pCur: ?*BtCursor, p: *i64) c_int;
extern fn sqlite3VdbeFindIndexKey(pCur: ?*BtCursor, pIdx: ?*Index, r: ?*anyopaque, pRes: *c_int, b: c_int) c_int;
extern fn sqlite3VdbeIdxKeyCompare(db: ?*sqlite3, pC: ?*anyopaque, r: ?*anyopaque, pRes: *c_int) c_int;
extern fn sqlite3VdbeRecordCompareWithSkip(nKey: c_int, pKey: ?*const anyopaque, r: ?*anyopaque, bSkip: c_int) c_int;
extern fn sqlite3VdbeAllocUnpackedRecord(pKeyInfo: ?*KeyInfo) ?*anyopaque;
extern fn sqlite3VdbeRecordUnpack(nKey: c_int, pKey: ?*const anyopaque, p: ?*anyopaque) void;
extern fn sqlite3VdbeSerialGet(buf: [*]const u8, t: u32, pMem: ?*Mem) void;
extern fn sqlite3VdbeSerialTypeLen(t: u32) u32;
extern fn sqlite3VdbeOneByteSerialTypeLen(t: u8) u8;
extern fn sqlite3VdbeMemFromBtree(pCur: ?*BtCursor, offset: u32, amt: u32, pMem: ?*Mem) c_int;
extern fn sqlite3VdbeMemFromBtreeZeroOffset(pCur: ?*BtCursor, amt: u32, pMem: ?*Mem) c_int;
extern fn sqlite3MemCompare(a: ?*const Mem, b: ?*const Mem, pColl: ?*CollSeq) c_int;
// sqlite3VdbeIncrWriteCounter exists only under SQLITE_DEBUG (vdbeaux exports it
// gated on config.sqlite_debug); in the production build the upstream call site
// is a no-op macro. Gate on config.sqlite_debug so the extern symbol is only
// referenced when it is actually defined.
inline fn sqlite3VdbeIncrWriteCounter(p: ?*Vdbe, pC: ?*anyopaque) void {
    if (config.sqlite_debug) {
        const f = @extern(*const fn (?*Vdbe, ?*anyopaque) callconv(.c) void, .{ .name = "sqlite3VdbeIncrWriteCounter" });
        f(p, pC);
    }
}
extern fn sqlite3VdbePreUpdateHook(p: ?*Vdbe, pC: ?*anyopaque, op: c_int, zDb: ?[*:0]const u8, pTab: ?*Table, iKey: i64, iReg: c_int, iBlobWrite: c_int) void;
extern fn sqlite3VdbeDeleteAuxData(db: ?*sqlite3, pp: *?*anyopaque, iOp: c_int, mask: c_int) void;
extern fn sqlite3VdbeFrameMemDel(p: ?*anyopaque) void;
extern fn sqlite3VdbeValueListFree(p: ?*anyopaque) void;
extern fn sqlite3VdbeExpandSql(p: ?*Vdbe, zSql: [*:0]const u8) ?[*:0]u8;

// Mem helpers (vdbemem.zig)
extern fn sqlite3VdbeMemSetNull(p: ?*Mem) void;
extern fn sqlite3VdbeMemSetInt64(p: ?*Mem, v: i64) void;
extern fn sqlite3VdbeMemSetStr(p: ?*Mem, z: ?[*]const u8, n: i64, enc: u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) c_int;
extern fn sqlite3VdbeMemSetZeroBlob(p: ?*Mem, n: c_int) c_int;
extern fn sqlite3VdbeMemSetPointer(p: ?*Mem, ptr: ?*anyopaque, zType: [*:0]const u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3VdbeMemSetRowSet(p: ?*Mem) c_int;
extern fn sqlite3VdbeMemIsRowSet(p: ?*const Mem) c_int;
extern fn sqlite3VdbeMemInit(p: ?*Mem, db: ?*sqlite3, flags: u16) void;
extern fn sqlite3VdbeMemRelease(p: ?*Mem) void;
extern fn sqlite3VdbeMemReleaseMalloc(p: ?*Mem) void;
extern fn sqlite3VdbeMemShallowCopy(to: ?*Mem, from: ?*const Mem, srcType: c_int) void;
extern fn sqlite3VdbeMemCopy(to: ?*Mem, from: ?*const Mem) c_int;
extern fn sqlite3VdbeMemMove(to: ?*Mem, from: ?*Mem) void;
extern fn sqlite3VdbeMemGrow(p: ?*Mem, n: c_int, preserve: c_int) c_int;
extern fn sqlite3VdbeMemClearAndResize(p: ?*Mem, n: c_int) c_int;
extern fn sqlite3VdbeMemMakeWriteable(p: ?*Mem) c_int;
extern fn sqlite3VdbeMemExpandBlob(p: ?*Mem) c_int;
extern fn sqlite3VdbeMemStringify(p: ?*Mem, enc: u8, bForce: u8) c_int;
extern fn sqlite3VdbeMemCast(p: ?*Mem, aff: u8, enc: u8) c_int;
extern fn sqlite3VdbeMemRealify(p: ?*Mem) c_int;
extern fn sqlite3VdbeMemIntegerify(p: ?*Mem) c_int;
extern fn sqlite3VdbeIntegerAffinity(p: ?*Mem) void;
extern fn sqlite3VdbeMemTooBig(p: ?*Mem) c_int;
extern fn sqlite3VdbeMemFinalize(p: ?*Mem, pFunc: ?*FuncDef) c_int;
extern fn sqlite3VdbeMemAggValue(pAcc: ?*Mem, pOut: ?*Mem, pFunc: ?*FuncDef) c_int;
extern fn sqlite3VdbeBooleanValue(p: ?*Mem, ifNull: c_int) c_int;
extern fn sqlite3VdbeIntValue(p: ?*const Mem) i64;
extern fn sqlite3VdbeRealValue(p: ?*Mem) f64;
extern fn sqlite3MemRealValueRC(p: ?*Mem, pr: *f64) c_int;
extern fn sqlite3VdbeChangeEncoding(p: ?*Mem, enc: c_int) c_int;
extern fn sqlite3_value_type(p: ?*Mem) c_int;
extern fn sqlite3_value_text(p: ?*Mem) ?[*:0]const u8;
extern fn sqlite3ValueText(p: ?*Mem, enc: u8) ?[*:0]const u8;

// b-tree / pager (btree.zig / pager.zig)
extern fn sqlite3BtreeCursorZero(p: ?*BtCursor) void;
extern fn sqlite3BtreeCursorSize() c_int;
extern fn sqlite3BtreeFakeValidCursor() ?*BtCursor;
extern fn sqlite3BtreeCursor(p: ?*Btree, iTable: u32, wrFlag: c_int, pKeyInfo: ?*KeyInfo, pCur: ?*BtCursor) c_int;
extern fn sqlite3BtreeCursorHintFlags(p: ?*BtCursor, mask: c_uint) void;
extern fn sqlite3BtreeCursorHasHint(p: ?*BtCursor, mask: c_uint) c_int;
extern fn sqlite3BtreeClearCursor(p: ?*BtCursor) void;
extern fn sqlite3BtreeClearTable(p: ?*Btree, iTable: c_int, pnChange: ?*i64) c_int;
extern fn sqlite3BtreeClearTableOfCursor(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeOpen(pVfs: ?*anyopaque, zFile: ?[*:0]const u8, db: ?*sqlite3, pp: *?*Btree, flags: c_int, vfsFlags: c_int) c_int;
extern fn sqlite3BtreeClose(p: ?*Btree) c_int;
extern fn sqlite3BtreeClosesWithCursor(p: ?*Btree, pCur: ?*BtCursor) c_int;
extern fn sqlite3BtreeBeginTrans(p: ?*Btree, wrFlag: c_int, pSchemaVersion: ?*c_int) c_int;
extern fn sqlite3BtreeBeginStmt(p: ?*Btree, iStatement: c_int) c_int;
extern fn sqlite3BtreeCreateTable(p: ?*Btree, pgno: *u32, flags: c_int) c_int;
extern fn sqlite3BtreeTableMoveto(p: ?*BtCursor, key: i64, bias: c_int, pRes: *c_int) c_int;
extern fn sqlite3BtreeIndexMoveto(p: ?*BtCursor, r: ?*anyopaque, pRes: *c_int) c_int;
extern fn sqlite3BtreeInsert(p: ?*BtCursor, payload: ?*const anyopaque, flags: c_int, seekResult: c_int) c_int;
extern fn sqlite3BtreeDelete(p: ?*BtCursor, flags: u8) c_int;
extern fn sqlite3BtreeFirst(p: ?*BtCursor, pRes: *c_int) c_int;
extern fn sqlite3BtreeLast(p: ?*BtCursor, pRes: *c_int) c_int;
extern fn sqlite3BtreeNext(p: ?*BtCursor, flags: c_int) c_int;
extern fn sqlite3BtreePrevious(p: ?*BtCursor, flags: c_int) c_int;
extern fn sqlite3BtreeEof(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeIsEmpty(p: ?*BtCursor, pRes: *c_int) c_int;
extern fn sqlite3BtreeIntegerKey(p: ?*BtCursor) i64;
extern fn sqlite3BtreeOffset(p: ?*BtCursor) i64;
extern fn sqlite3BtreePayload(p: ?*BtCursor, offset: u32, amt: u32, pBuf: ?*anyopaque) c_int;
extern fn sqlite3BtreePayloadSize(p: ?*BtCursor) u32;
extern fn sqlite3BtreePayloadFetch(p: ?*BtCursor, pAmt: *u32) ?[*]const u8;
extern fn sqlite3BtreeCursorIsValid(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeCursorIsValidNN(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeCursorHasMoved(p: ?*BtCursor) c_int;
extern fn sqlite3BtreeRowCountEst(p: ?*BtCursor) i64;
extern fn sqlite3BtreeCount(db: ?*sqlite3, p: ?*BtCursor, pn: *i64) c_int;
extern fn sqlite3BtreeTransferRow(pDest: ?*BtCursor, pSrc: ?*BtCursor, iKey: i64) c_int;
extern fn sqlite3BtreeCursorPin(p: ?*BtCursor) void;
extern fn sqlite3BtreeCursorUnpin(p: ?*BtCursor) void;
extern fn sqlite3BtreeGetMeta(p: ?*Btree, idx: c_int, pValue: *u32) void;
extern fn sqlite3BtreeUpdateMeta(p: ?*Btree, idx: c_int, value: u32) c_int;
extern fn sqlite3BtreeDropTable(p: ?*Btree, iTable: c_int, piMoved: *c_int) c_int;
extern fn sqlite3BtreeTripAllCursors(p: ?*Btree, code: c_int, force: c_int) c_int;
extern fn sqlite3BtreeSavepoint(p: ?*Btree, op: c_int, iSavepoint: c_int) c_int;
extern fn sqlite3BtreeLastPage(p: ?*Btree) u32;
extern fn sqlite3BtreeMaxPageCount(p: ?*Btree, mx: u32) u32;
extern fn sqlite3BtreeIncrVacuum(p: ?*Btree) c_int;
extern fn sqlite3BtreeLockTable(p: ?*Btree, iTab: c_int, isWriteLock: u8) c_int;
extern fn sqlite3BtreeTxnState(p: ?*Btree) c_int;
extern fn sqlite3BtreePager(p: ?*Btree) ?*Pager;
extern fn sqlite3BtreeSetVersion(p: ?*Btree, iVersion: c_int) c_int;
extern fn sqlite3BtreeIntegrityCheck(db: ?*sqlite3, p: ?*Btree, aRoot: [*]u32, aCnt: ?*Mem, nRoot: c_int, mxErr: c_int, pnErr: *c_int, pzOut: *?[*:0]u8) c_int;
extern fn sqlite3PagerGetJournalMode(p: ?*Pager) c_int;
extern fn sqlite3PagerSetJournalMode(p: ?*Pager, mode: c_int) c_int;
extern fn sqlite3PagerOkToChangeJournalMode(p: ?*Pager) c_int;
extern fn sqlite3PagerFilename(p: ?*Pager, b: c_int) [*:0]const u8;
extern fn sqlite3PagerWalSupported(p: ?*Pager) c_int;
extern fn sqlite3PagerCloseWal(p: ?*Pager, db: ?*sqlite3) c_int;

// RCStr
extern fn sqlite3RCStrNew(n: u64) ?[*]u8;
extern fn sqlite3RCStrRef(z: ?*anyopaque) void;
extern fn sqlite3RCStrUnref(z: ?*anyopaque) void;

// RowSet (rowset.zig)
extern fn sqlite3RowSetInsert(p: ?*RowSet, rowid: i64) void;
extern fn sqlite3RowSetNext(p: ?*RowSet, pRowid: *i64) c_int;
extern fn sqlite3RowSetTest(p: ?*RowSet, iBatch: c_int, rowid: i64) c_int;

// Sorter (vdbesort.c — still C)
extern fn sqlite3VdbeSorterInit(db: ?*sqlite3, nField: c_int, pC: ?*anyopaque) c_int;
extern fn sqlite3VdbeSorterRewind(pC: ?*anyopaque, pRes: *c_int) c_int;
extern fn sqlite3VdbeSorterNext(db: ?*sqlite3, pC: ?*anyopaque) c_int;
extern fn sqlite3VdbeSorterWrite(pC: ?*anyopaque, pMem: ?*Mem) c_int;
extern fn sqlite3VdbeSorterRowkey(pC: ?*anyopaque, pOut: ?*Mem) c_int;
extern fn sqlite3VdbeSorterCompare(pC: ?*anyopaque, pVal: ?*Mem, nKeyCol: c_int, pRes: *c_int) c_int;
extern fn sqlite3VdbeSorterReset(db: ?*sqlite3, pSorter: ?*anyopaque) void;

// vtab (vtab.zig)
extern fn sqlite3VtabImportErrmsg(p: ?*Vdbe, pVtab: ?*sqlite3_vtab) void;
extern fn sqlite3VtabBegin(db: ?*sqlite3, pVTab: ?*VTable) c_int;
extern fn sqlite3VtabSavepoint(db: ?*sqlite3, op: c_int, iSavepoint: c_int) c_int;
extern fn sqlite3VtabCallCreate(db: ?*sqlite3, iDb: c_int, zTab: [*:0]const u8, pzErr: *?[*:0]u8) c_int;
extern fn sqlite3VtabCallDestroy(db: ?*sqlite3, iDb: c_int, zTab: [*:0]const u8) c_int;
extern fn sqlite3VtabLock(p: ?*anyopaque) void;
extern fn sqlite3VtabUnlock(p: ?*anyopaque) void;

// schema / build / analyze (still C)
extern fn sqlite3ExpirePreparedStatements(db: ?*sqlite3, iCode: c_int) void;
extern fn sqlite3ResetAllSchemasOfConnection(db: ?*sqlite3) void;
extern fn sqlite3ResetOneSchema(db: ?*sqlite3, iDb: c_int) void;
extern fn sqlite3FkClearTriggerCache(db: ?*sqlite3, iDb: c_int) void;
extern fn sqlite3RootPageMoved(db: ?*sqlite3, iDb: c_int, iFrom: c_int, iTo: c_int) void;
extern fn sqlite3RollbackAll(db: ?*sqlite3, tripCode: c_int) void;
extern fn sqlite3CloseSavepoints(db: ?*sqlite3) void;
extern fn sqlite3SchemaClear(p: ?*anyopaque) void;
extern fn sqlite3InitOne(db: ?*sqlite3, iDb: c_int, pzErr: ?*?[*:0]u8, mFlags: u32) c_int;
extern fn sqlite3InitCallback(pInit: ?*anyopaque, argc: c_int, argv: ?*?[*:0]u8, azCol: ?*?[*:0]u8) c_int;
extern fn sqlite3AnalysisLoad(db: ?*sqlite3, iDb: c_int) c_int;
extern fn sqlite3UnlinkAndDeleteTable(db: ?*sqlite3, iDb: c_int, zName: [*:0]const u8) void;
extern fn sqlite3UnlinkAndDeleteIndex(db: ?*sqlite3, iDb: c_int, zName: [*:0]const u8) void;
extern fn sqlite3UnlinkAndDeleteTrigger(db: ?*sqlite3, iDb: c_int, zName: [*:0]const u8) void;
extern fn sqlite3WritableSchema(db: ?*sqlite3) c_int;
extern fn sqlite3ReportError(iErr: c_int, lineno: c_int, zType: [*:0]const u8) c_int;
extern fn sqlite3RunVacuum(pzErr: *?[*:0]u8, db: ?*sqlite3, iDb: c_int, pOut: ?*Mem) c_int;
extern fn sqlite3Checkpoint(db: ?*sqlite3, iDb: c_int, eMode: c_int, pnLog: *c_int, pnCkpt: *c_int) c_int;
extern fn sqlite3JournalModename(eMode: c_int) [*:0]const u8;

// SQLITE_DEBUG-only assert helpers (gated)
extern fn sqlite3FaultSim(iTest: c_int) c_int;

// char[] data tables — bind a byte, take its address (the char[]-as-pointer
// gotcha: declaring [*]const u8 reads the array bytes AS a pointer).
extern const sqlite3SmallTypeSizes: u8;
extern const sqlite3CtypeMap: u8;
// These three are `const unsigned char *` POINTER variables (see global.c),
// not arrays: they point into sqlite3UpperToLower at computed offsets. So the
// extern symbol holds a pointer that must be dereferenced — unlike the array
// symbols above whose address IS the data.
extern const sqlite3aGTb: [*c]const u8;
extern const sqlite3aLTb: [*c]const u8;
extern const sqlite3aEQb: [*c]const u8;
extern const sqlite3StdType: [*:0]const u8; // const char* const aStdType[] — symbol address IS the array
inline fn aGTb(op: u8) bool {
    return sqlite3aGTb[op] != 0;
}
inline fn aLTb(op: u8) bool {
    return sqlite3aLTb[op] != 0;
}
inline fn aEQb(op: u8) bool {
    return sqlite3aEQb[op] != 0;
}
inline fn smallTypeSize(t: u32) u8 {
    const base: [*]const u8 = @ptrCast(&sqlite3SmallTypeSizes);
    return base[t];
}

// sqlite3GlobalConfig.iOnceResetThreshold — read the field at its offset out of
// the global config struct. We extern the global and offset into it.
extern var sqlite3Config: u8;
const Config_iOnceResetThreshold = off("Sqlite3Config_iOnceResetThreshold", 424, 424);
inline fn iOnceResetThreshold() c_int {
    return rd(c_int, @ptrCast(&sqlite3Config), Config_iOnceResetThreshold);
}

// db->trace union: { xLegacy; xV2 } — both are fn pointers at sqlite3_trace.
const TraceV2Fn = ?*const fn (mask: c_uint, ctx: ?*anyopaque, p: ?*anyopaque, x: ?*anyopaque) callconv(.c) c_uint;
const TraceLegacyFn = ?*const fn (ctx: ?*anyopaque, z: ?[*:0]const u8) callconv(.c) void;
const UpdateCb = ?*const fn (arg: ?*anyopaque, op: c_int, zDb: ?[*:0]const u8, zTab: ?[*:0]const u8, rowid: i64) callconv(.c) void;
const PreUpdateCb = ?*anyopaque;
const ProgressCb = ?*const fn (arg: ?*anyopaque) callconv(.c) c_int;

// sqlite3_module method fn types
const xOpenFn = *const fn (pVtab: ?*sqlite3_vtab, ppCur: *?*sqlite3_vtab_cursor) callconv(.c) c_int;
const xCloseFn = *const fn (pCur: ?*sqlite3_vtab_cursor) callconv(.c) c_int;
const xFilterFn = *const fn (pCur: ?*sqlite3_vtab_cursor, idxNum: c_int, idxStr: ?[*:0]const u8, argc: c_int, argv: [*]?*Mem) callconv(.c) c_int;
const xNextFn = *const fn (pCur: ?*sqlite3_vtab_cursor) callconv(.c) c_int;
const xEofFn = *const fn (pCur: ?*sqlite3_vtab_cursor) callconv(.c) c_int;
const xColumnFn = *const fn (pCur: ?*sqlite3_vtab_cursor, ctx: ?*sqlite3_context, n: c_int) callconv(.c) c_int;
const xRowidFn = *const fn (pCur: ?*sqlite3_vtab_cursor, pRowid: *i64) callconv(.c) c_int;
const xUpdateFn = *const fn (pVtab: ?*sqlite3_vtab, argc: c_int, argv: [*]?*Mem, pRowid: *i64) callconv(.c) c_int;
const xRenameFn = *const fn (pVtab: ?*sqlite3_vtab, zNew: ?[*:0]const u8) callconv(.c) c_int;
const xIntegrityFn = *const fn (pVtab: ?*sqlite3_vtab, zSchema: ?[*:0]const u8, zTabName: ?[*:0]const u8, mFlags: c_int, pzErr: *?[*:0]u8) callconv(.c) c_int;

inline fn modFn(comptime T: type, pModule: ?*anyopaque, mo: usize) T {
    return @ptrCast(@alignCast(rdPtr(pModule, mo).?));
}

// xSFunc / xInverse signatures
const SFunc = *const fn (ctx: ?*sqlite3_context, argc: c_int, argv: [*]?*Mem) callconv(.c) void;

// ===========================================================================
// Helper routines (mirroring the static fns in vdbe.c)
// ===========================================================================

// allocateCursor — VdbeCursor number iCur.
fn allocateCursor(p: ?*Vdbe, iCur: c_int, nField: c_int, eCurType: u8) ?*anyopaque {
    // pMem = iCur>0 ? &aMem[nMem-iCur] : aMem[0]
    const aMem: [*]u8 = @ptrCast(rdPtr(p, Vdbe_aMem).?);
    const nMem = rd(c_int, p, Vdbe_nMem);
    const pMem: *Mem = if (iCur > 0) memAt(aMem, nMem - iCur) else memAt(aMem, 0);

    // SZ_VDBECURSOR(nField) = ROUND8(offsetof(VdbeCursor,aType) + 2*nField*sizeof(u32)+... )
    // C: SZ_VDBECURSOR(nField) = ROUND8( offsetof(VdbeCursor,aType)
    //                                    + (2*(i64)(nField)+1)*sizeof(u32) )
    var nByte: i64 = @as(i64, @intCast(VC_aType)) +
        (2 * @as(i64, nField) + 1) * @sizeOf(u32);
    nByte = (nByte + 7) & ~@as(i64, 7);
    if (eCurType == CURTYPE_BTREE) nByte += sqlite3BtreeCursorSize();

    const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
    const ci: usize = @intCast(iCur);
    if (apCsr[ci] != null) {
        sqlite3VdbeFreeCursorNN(p, apCsr[ci]);
        apCsr[ci] = null;
    }

    if (pMem.szMalloc < nByte) {
        if (pMem.szMalloc > 0) {
            sqlite3DbFreeNN(pMem.db, pMem.zMalloc);
        }
        pMem.z = @ptrCast(sqlite3DbMallocRaw(pMem.db, @intCast(nByte)));
        pMem.zMalloc = pMem.z;
        if (pMem.zMalloc == null) {
            pMem.szMalloc = 0;
            return null;
        }
        pMem.szMalloc = @intCast(nByte);
    }

    const pCx: ?*anyopaque = @ptrCast(pMem.zMalloc.?);
    apCsr[ci] = pCx;
    // memset(pCx, 0, offsetof(VdbeCursor,pAltCursor))
    @memset(@as([*]u8, @ptrCast(pCx.?))[0..VC_pAltCursor], 0);
    wrU8(pCx, VC_eCurType, eCurType);
    wr(i16, pCx, VC_nField, @truncate(nField));
    // pCx->aOffset = &pCx->aType[nField]
    const aTypeBase: [*]u32 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pCx.?)) + VC_aType));
    wrPtr(pCx, VC_aOffset, @ptrCast(aTypeBase + @as(usize, @intCast(nField))));
    if (eCurType == CURTYPE_BTREE) {
        // pCx->uc.pCursor = (BtCursor*)&pMem->z[SZ_VDBECURSOR(nField)]
        var szCur: i64 = @as(i64, @intCast(VC_aType)) + (2 * @as(i64, nField) + 1) * @sizeOf(u32);
        szCur = (szCur + 7) & ~@as(i64, 7);
        const pCur: ?*BtCursor = @ptrCast(pMem.z.? + @as(usize, @intCast(szCur)));
        wrPtr(pCx, VC_uc, @ptrCast(pCur));
        sqlite3BtreeCursorZero(pCur);
    }
    return pCx;
}

fn alsoAnInt(pRec: *Mem, rValue: f64, piValue: *i64) bool {
    const iValue = sqlite3RealToI64(rValue);
    if (sqlite3RealSameAsInt(rValue, iValue) != 0) {
        piValue.* = iValue;
        return true;
    }
    return sqlite3Atoi64(@ptrCast(pRec.z), piValue, pRec.n, pRec.enc) == 0;
}

fn applyNumericAffinity(pRec: *Mem, bTryForInt: bool) void {
    var rValue: f64 = undefined;
    const rc = sqlite3MemRealValueRC(pRec, &rValue);
    if (rc <= 0) return;
    if ((rc & 2) == 0 and alsoAnInt(pRec, rValue, &pRec.u.i)) {
        pRec.flags |= MEM_Int;
    } else {
        pRec.u.r = rValue;
        pRec.flags |= MEM_Real;
        if (bTryForInt) sqlite3VdbeIntegerAffinity(pRec);
    }
    pRec.flags &= ~MEM_Str;
}

fn applyAffinity(pRec: *Mem, affinity: u8, enc: u8) void {
    if (affinity >= SQLITE_AFF_NUMERIC) {
        if ((pRec.flags & MEM_Int) == 0) {
            if ((pRec.flags & (MEM_Real | MEM_IntReal)) == 0) {
                if ((pRec.flags & MEM_Str) != 0) applyNumericAffinity(pRec, true);
            } else if (affinity <= SQLITE_AFF_REAL) {
                sqlite3VdbeIntegerAffinity(pRec);
            }
        }
    } else if (affinity == SQLITE_AFF_TEXT) {
        if ((pRec.flags & MEM_Str) == 0) {
            if ((pRec.flags & (MEM_Real | MEM_Int | MEM_IntReal)) != 0) {
                _ = sqlite3VdbeMemStringify(pRec, enc, 1);
            }
        }
        pRec.flags &= ~(MEM_Real | MEM_Int | MEM_IntReal);
    }
}

fn computeNumericType(pMem: *Mem) u16 {
    if (ExpandBlob(pMem) != 0) {
        pMem.u.i = 0;
        return MEM_Int;
    }
    var ix: i64 = undefined;
    const rc = sqlite3MemRealValueRC(pMem, &pMem.u.r);
    if (rc <= 0) {
        if ((rc & 2) == 0 and sqlite3Atoi64(@ptrCast(pMem.z), &ix, pMem.n, pMem.enc) <= 1) {
            pMem.u.i = ix;
            return MEM_Int;
        } else {
            return MEM_Real;
        }
    } else if ((rc & 2) == 0 and sqlite3Atoi64(@ptrCast(pMem.z), &ix, pMem.n, pMem.enc) == 0) {
        pMem.u.i = ix;
        return MEM_Int;
    }
    return MEM_Real;
}

fn numericType(pMem: *Mem) u16 {
    if ((pMem.flags & (MEM_Int | MEM_Real | MEM_IntReal | MEM_Null)) != 0) {
        return pMem.flags & (MEM_Int | MEM_Real | MEM_IntReal | MEM_Null);
    }
    return computeNumericType(pMem);
}

// ExpandBlob(P) macro: ((P)->flags&MEM_Zero)?sqlite3VdbeMemExpandBlob(P):0
inline fn ExpandBlob(p: *Mem) c_int {
    return if ((p.flags & MEM_Zero) != 0) sqlite3VdbeMemExpandBlob(p) else 0;
}
// VdbeMemDynamic(X): (((X)->flags&(MEM_Agg|MEM_Dyn))!=0)
inline fn VdbeMemDynamic(p: *Mem) bool {
    return (p.flags & (MEM_Agg | MEM_Dyn)) != 0;
}
inline fn MemSetTypeFlag(p: *Mem, f: u16) void {
    p.flags = (p.flags & ~(MEM_TypeMask | MEM_Zero)) | f;
}

fn out2PrereleaseWithClear(pOut: *Mem) *Mem {
    sqlite3VdbeMemSetNull(pOut);
    pOut.flags = MEM_Int;
    return pOut;
}
fn out2Prerelease(p: ?*Vdbe, pOp: *Op) *Mem {
    const aMem: [*]u8 = @ptrCast(rdPtr(p, Vdbe_aMem).?);
    const pOut = memAt(aMem, pOp.p2);
    if (VdbeMemDynamic(pOut)) {
        return out2PrereleaseWithClear(pOut);
    } else {
        pOut.flags = MEM_Int;
        return pOut;
    }
}

fn filterHash(aMem: [*]u8, pOp: *Op) u64 {
    var h: u64 = 0;
    var i: c_int = pOp.p3;
    const mx: c_int = i + pOp.p4.i;
    while (i < mx) : (i += 1) {
        const pm = memAt(aMem, i);
        if ((pm.flags & (MEM_Int | MEM_IntReal)) != 0) {
            h +%= @bitCast(pm.u.i);
        } else if ((pm.flags & MEM_Real) != 0) {
            h +%= @bitCast(sqlite3VdbeIntValue(pm));
        } else if ((pm.flags & (MEM_Str | MEM_Blob)) != 0) {
            h +%= 4093 + (pm.flags & (MEM_Str | MEM_Blob));
        }
    }
    return h;
}

fn swapMixedEndianFloat(v: u64) u64 {
    return v; // MIXED_ENDIAN_64BIT_FLOAT off
}

// vdbeColumnFromOverflow — OP_Column overflow-page path.
fn vdbeColumnFromOverflow(pC: ?*anyopaque, iCol: c_int, t: u32, iOffset: i64, cacheStatus: u32, colCacheCtr: u32, pDest: *Mem) c_int {
    const db = pDest.db;
    const encoding = pDest.enc;
    const len: c_int = @intCast(sqlite3VdbeSerialTypeLen(t));
    if (len > dbLimit(db, SQLITE_LIMIT_LENGTH)) return SQLITE_TOOBIG;
    const pCur: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    if (len > 4000 and rdPtr(pC, VC_pKeyInfo) == null) {
        // VdbeTxtBlbCache path: pCache fields { pCValue@0, iOffset@8, iCol@16,
        // cacheStatus@20, colCacheCtr@24 } — sizeof 32 (ptr+i64+int+u32+u32).
        if (!vcBit(pC, BIT_colCache)) {
            wrPtr(pC, VC_pCache, sqlite3DbMallocZero(db, 32));
            if (rdPtr(pC, VC_pCache) == null) return SQLITE_NOMEM;
            vcSetBit(pC, BIT_colCache, true);
        }
        const pCache = rdPtr(pC, VC_pCache);
        const c_pCValue: usize = 0;
        const c_iOffset: usize = 8;
        const c_iCol: usize = 16;
        const c_cacheStatus: usize = 20;
        const c_colCacheCtr: usize = 24;
        var pBuf: ?[*]u8 = undefined;
        if (rdPtr(pCache, c_pCValue) == null or
            rd(c_int, pCache, c_iCol) != iCol or
            rd(u32, pCache, c_cacheStatus) != cacheStatus or
            rd(u32, pCache, c_colCacheCtr) != colCacheCtr or
            rd(i64, pCache, c_iOffset) != sqlite3BtreeOffset(pCur))
        {
            if (rdPtr(pCache, c_pCValue) != null) sqlite3RCStrUnref(rdPtr(pCache, c_pCValue));
            pBuf = sqlite3RCStrNew(@intCast(len + 3));
            wrPtr(pCache, c_pCValue, @ptrCast(pBuf));
            if (pBuf == null) return SQLITE_NOMEM;
            const rc = sqlite3BtreePayload(pCur, @intCast(iOffset), @intCast(len), pBuf);
            if (rc != 0) return rc;
            pBuf.?[@intCast(len)] = 0;
            pBuf.?[@intCast(len + 1)] = 0;
            pBuf.?[@intCast(len + 2)] = 0;
            wr(c_int, pCache, c_iCol, iCol);
            wr(u32, pCache, c_cacheStatus, cacheStatus);
            wr(u32, pCache, c_colCacheCtr, colCacheCtr);
            wr(i64, pCache, c_iOffset, sqlite3BtreeOffset(pCur));
        } else {
            pBuf = @ptrCast(rdPtr(pCache, c_pCValue));
        }
        sqlite3RCStrRef(@ptrCast(pBuf));
        var rc: c_int = undefined;
        if (t & 1 != 0) {
            rc = sqlite3VdbeMemSetStr(pDest, pBuf, len, encoding, sqlite3RCStrUnref);
            pDest.flags |= MEM_Term;
        } else {
            rc = sqlite3VdbeMemSetStr(pDest, pBuf, len, 0, sqlite3RCStrUnref);
        }
        pDest.flags &= ~MEM_Ephem;
        return rc;
    } else {
        var rc = sqlite3VdbeMemFromBtree(pCur, @intCast(iOffset), @intCast(len), pDest);
        if (rc != 0) return rc;
        sqlite3VdbeSerialGet(@ptrCast(pDest.z.?), t, pDest);
        if ((t & 1) != 0 and encoding == SQLITE_UTF8) {
            pDest.z.?[@intCast(len)] = 0;
            pDest.flags |= MEM_Term;
        }
        pDest.flags &= ~MEM_Ephem;
        rc = 0;
        return rc;
    }
}

fn vdbeIndexKeyCompare(pCsr: ?*BtCursor, pMem: *Mem, pRc: *c_int) bool {
    var ret = false;
    const nKey = sqlite3BtreePayloadSize(pCsr);
    if (nKey == @as(u32, @bitCast(pMem.n)) and (pMem.flags & MEM_Blob) != 0) {
        var m: Mem = std.mem.zeroes(Mem);
        pRc.* = sqlite3VdbeMemFromBtreeZeroOffset(pCsr, nKey, &m);
        ret = (pRc.* != SQLITE_OK or 0 == memcmp(pMem.z, m.z, nKey));
        sqlite3VdbeMemReleaseMalloc(&m);
    }
    return ret;
}

fn vdbeLogAbort(p: ?*Vdbe, rc: c_int, pOp: *Op, aOp: [*]Op) void {
    const zSql = rd(?[*:0]const u8, p, Vdbe_zSql);
    var zPrefix: [*:0]const u8 = "";
    var zXtra: [100]u8 = undefined;
    if (rdPtr(p, Vdbe_pFrame) != null) {
        if (aOp[0].p4.z != null) {
            _ = sqlite3_snprintf(@intCast(zXtra.len), &zXtra, "/* %s */ ", aOp[0].p4.z.? + 3);
            zPrefix = @ptrCast(&zXtra);
        } else {
            zPrefix = "/* unknown trigger */ ";
        }
    }
    const pc = (@intFromPtr(pOp) - @intFromPtr(aOp)) / @sizeOf(Op);
    sqlite3_log(rc, "statement aborts at %d: %s; [%s%s]", @as(c_int, @intCast(pc)), rd(?[*:0]const u8, p, Vdbe_zErrMsg), zPrefix, zSql orelse @as([*:0]const u8, ""));
}

const StdTypeNames = [_][*:0]const u8{ "INT", "REAL", "TEXT", "BLOB", "NULL" };
fn vdbeMemTypeName(pMem: *Mem) [*:0]const u8 {
    return StdTypeNames[@intCast(sqlite3_value_type(pMem) - 1)];
}

const SQLITE_TEXT: c_int = 3;
const sqlite3_mutex_off = off("sqlite3_mutex", 24, 24);
extern fn sqlite3_mutex_enter(p: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(p: ?*anyopaque) void;

// Public API: convert a function argument / result column to a numeric type
// without loss, returning the revised type.
export fn sqlite3_value_numeric_type(pVal: ?*Mem) callconv(.c) c_int {
    var eType = sqlite3_value_type(pVal);
    if (eType == SQLITE_TEXT) {
        const pMem = pVal.?;
        const pMutex: ?*anyopaque = if (pMem.db != null) rdPtr(pMem.db, sqlite3_mutex_off) else null;
        sqlite3_mutex_enter(pMutex);
        applyNumericAffinity(pMem, false);
        sqlite3_mutex_leave(pMutex);
        eType = sqlite3_value_type(pVal);
    }
    return eType;
}

// Exported version of applyAffinity() working on sqlite3_value*.
export fn sqlite3ValueApplyAffinity(pVal: ?*Mem, affinity: u8, enc: u8) callconv(.c) void {
    applyAffinity(pVal.?, affinity, enc);
}

// SQLITE_DEBUG-only: pretty-print and register dump. Exported only under
// SQLITE_DEBUG, mirroring the C #ifdef. These are no-op stubs sufficient to
// satisfy the link (real tracing output is not reproduced bit-for-bit; they
// are only reached via PRAGMA vdbe_trace and interactive debugging).
fn sqlite3VdbeMemPrettyPrint(pMem: ?*Mem, pStr: ?*anyopaque) callconv(.c) void {
    _ = pMem;
    _ = pStr;
}
fn sqlite3VdbeRegisterDump(v: ?*Vdbe) callconv(.c) void {
    _ = v;
}
comptime {
    if (DEBUG) {
        @export(&sqlite3VdbeMemPrettyPrint, .{ .name = "sqlite3VdbeMemPrettyPrint" });
        @export(&sqlite3VdbeRegisterDump, .{ .name = "sqlite3VdbeRegisterDump" });
    }
}

// ===========================================================================
// ===========================================================================
// Opcode handler helpers (the bodies of the more involved OP_ cases).
// Each returns enough information for the driver loop to set pc / exit.
// ===========================================================================

inline fn apCsrOf(p: ?*Vdbe) [*]?*anyopaque {
    return @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
}

// ---- OP_Halt --------------------------------------------------------------
// Returns true if caller should `continue :main` (sub-frame restart). Sets pc.
fn opHalt(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOpRef: *[*]Op, aMemRef: *[*]u8, pc: *usize, rc: *c_int, exitKind: *ExitKind, done: *bool) bool {
    if (rdPtr(p, Vdbe_pFrame) != null and pOp.p1 == SQLITE_OK) {
        const pFrame = rdPtr(p, Vdbe_pFrame);
        wrPtr(p, Vdbe_pFrame, rdPtr(pFrame, VdbeFrame_pParent));
        wr(c_int, p, Vdbe_nFrame, rd(c_int, p, Vdbe_nFrame) - 1);
        sqlite3VdbeSetChanges(db, rd(c_int, p, Vdbe_nChange));
        var pcx: c_int = sqlite3VdbeFrameRestore(pFrame);
        // refresh aOp / aMem after frame restore
        aOpRef.* = @ptrCast(@alignCast(rdPtr(p, Vdbe_aOp).?));
        aMemRef.* = @ptrCast(rdPtr(p, Vdbe_aMem).?);
        if (pOp.p2 == OE_Ignore) {
            pcx = aOpRef.*[@intCast(pcx)].p2 - 1;
        }
        pc.* = @intCast(pcx);
        pc.* += 1;
        return true;
    }
    wr(c_int, p, Vdbe_rc, pOp.p1);
    wrU8(p, Vdbe_errorAction, @intCast(pOp.p2 & 0xff));
    if (pOp.p1 != 0) {
        if (pOp.p3 > 0 and pOp.p4type == P4_NOTUSED) {
            const zErr = sqlite3ValueText(memAt(aMemRef.*, pOp.p3), SQLITE_UTF8);
            sqlite3VdbeError(p, "%s", zErr orelse @as([*:0]const u8, ""));
        } else if (pOp.p5 != 0) {
            const azType = [_][*:0]const u8{ "NOT NULL", "UNIQUE", "CHECK", "FOREIGN KEY" };
            sqlite3VdbeError(p, "%s constraint failed", azType[@intCast(pOp.p5 - 1)]);
            if (pOp.p4.z != null) {
                wrPtr(p, Vdbe_zErrMsg, @ptrCast(sqlite3MPrintf(db, "%z: %s", rd(?[*:0]u8, p, Vdbe_zErrMsg), pOp.p4.z)));
            }
        } else {
            sqlite3VdbeError(p, "%s", pOp.p4.z orelse @as([*:0]const u8, ""));
        }
        vdbeLogAbort(p, pOp.p1, pOp, aOpRef.*);
    }
    rc.* = sqlite3VdbeHalt(p);
    if (rc.* == SQLITE_BUSY) {
        wr(c_int, p, Vdbe_rc, SQLITE_BUSY);
    } else {
        rc.* = if (rd(c_int, p, Vdbe_rc) != 0) SQLITE_ERROR else SQLITE_DONE;
    }
    exitKind.* = .ret;
    done.* = true;
    return true; // continue :main (loop ends)
}

// ---- OP_Concat ------------------------------------------------------------
// Returns true on error (rc set: NOMEM or TOOBIG).
fn opConcat(db: ?*anyopaque, pOp: *Op, aMem: [*]u8, encoding: u8, rc: *c_int) bool {
    const pIn1 = memAt(aMem, pOp.p1);
    const pIn2 = memAt(aMem, pOp.p2);
    const pOut = memAt(aMem, pOp.p3);
    var flags1 = pIn1.flags;
    if (((flags1 | pIn2.flags) & MEM_Null) != 0) {
        sqlite3VdbeMemSetNull(pOut);
        return false;
    }
    if ((flags1 & (MEM_Str | MEM_Blob)) == 0) {
        if (sqlite3VdbeMemStringify(pIn1, encoding, 0) != 0) {
            rc.* = SQLITE_NOMEM;
            return true;
        }
        flags1 = pIn1.flags & ~MEM_Str;
    } else if ((flags1 & MEM_Zero) != 0) {
        if (sqlite3VdbeMemExpandBlob(pIn1) != 0) {
            rc.* = SQLITE_NOMEM;
            return true;
        }
        flags1 = pIn1.flags & ~MEM_Str;
    }
    var flags2 = pIn2.flags;
    if ((flags2 & (MEM_Str | MEM_Blob)) == 0) {
        if (sqlite3VdbeMemStringify(pIn2, encoding, 0) != 0) {
            rc.* = SQLITE_NOMEM;
            return true;
        }
        flags2 = pIn2.flags & ~MEM_Str;
    } else if ((flags2 & MEM_Zero) != 0) {
        if (sqlite3VdbeMemExpandBlob(pIn2) != 0) {
            rc.* = SQLITE_NOMEM;
            return true;
        }
        flags2 = pIn2.flags & ~MEM_Str;
    }
    var nByte: i64 = pIn1.n;
    nByte += pIn2.n;
    if (nByte > dbLimit(db, SQLITE_LIMIT_LENGTH)) {
        rc.* = SQLITE_TOOBIG;
        return true;
    }
    if (sqlite3VdbeMemGrow(pOut, @intCast(nByte + 2), @intFromBool(pOut == pIn2)) != 0) {
        rc.* = SQLITE_NOMEM;
        return true;
    }
    MemSetTypeFlag(pOut, MEM_Str);
    if (pOut != pIn2) {
        @memcpy(pOut.z.?[0..@intCast(pIn2.n)], pIn2.z.?[0..@intCast(pIn2.n)]);
        pIn2.flags = flags2;
    }
    @memcpy(pOut.z.?[@intCast(pIn2.n)..@intCast(pIn2.n + pIn1.n)], pIn1.z.?[0..@intCast(pIn1.n)]);
    pIn1.flags = flags1;
    if (encoding > SQLITE_UTF8) nByte &= ~@as(i64, 1);
    pOut.z.?[@intCast(nByte)] = 0;
    pOut.z.?[@intCast(nByte + 1)] = 0;
    pOut.flags |= MEM_Term;
    pOut.n = @intCast(nByte);
    pOut.enc = encoding;
    updateMaxBlobsize(pOut);
    return false;
}

// ---- OP_Add/Subtract/Multiply/Divide/Remainder ---------------------------
fn opArith(pOp: *Op, aMem: [*]u8) void {
    const op = pOp.opcode;
    const pIn1 = memAt(aMem, pOp.p1);
    const pIn2 = memAt(aMem, pOp.p2);
    const pOut = memAt(aMem, pOp.p3);
    var type1 = pIn1.flags;
    var type2 = pIn2.flags;

    if ((type1 & type2 & MEM_Int) != 0) {
        if (intMath(op, pIn1, pIn2, pOut)) return; // done (int or null)
        // overflow -> fp_math
        fpMath(op, pIn1, pIn2, pOut);
        return;
    } else if (((type1 | type2) & MEM_Null) != 0) {
        sqlite3VdbeMemSetNull(pOut);
        return;
    } else {
        type1 = numericType(pIn1);
        type2 = numericType(pIn2);
        if ((type1 & type2 & MEM_Int) != 0) {
            if (intMath(op, pIn1, pIn2, pOut)) return;
        }
        fpMath(op, pIn1, pIn2, pOut);
        return;
    }
}

// returns true if handled fully (result stored or null); false if must fall to
// fp_math (integer overflow).
fn intMath(op: u8, pIn1: *Mem, pIn2: *Mem, pOut: *Mem) bool {
    var iA = pIn1.u.i;
    var iB = pIn2.u.i;
    switch (op) {
        OP_Add => {
            if (sqlite3AddInt64(&iB, iA) != 0) return false;
        },
        OP_Subtract => {
            if (sqlite3SubInt64(&iB, iA) != 0) return false;
        },
        OP_Multiply => {
            if (sqlite3MulInt64(&iB, iA) != 0) return false;
        },
        OP_Divide => {
            if (iA == 0) {
                sqlite3VdbeMemSetNull(pOut);
                return true;
            }
            if (iA == -1 and iB == SMALLEST_INT64) return false;
            iB = @divTrunc(iB, iA);
        },
        else => { // OP_Remainder
            if (iA == 0) {
                sqlite3VdbeMemSetNull(pOut);
                return true;
            }
            if (iA == -1) iA = 1;
            iB = @rem(iB, iA);
        },
    }
    pOut.u.i = iB;
    MemSetTypeFlag(pOut, MEM_Int);
    return true;
}

fn fpMath(op: u8, pIn1: *Mem, pIn2: *Mem, pOut: *Mem) void {
    const rA = sqlite3VdbeRealValue(pIn1);
    var rB = sqlite3VdbeRealValue(pIn2);
    switch (op) {
        OP_Add => rB += rA,
        OP_Subtract => rB -= rA,
        OP_Multiply => rB *= rA,
        OP_Divide => {
            if (rA == 0) {
                sqlite3VdbeMemSetNull(pOut);
                return;
            }
            rB /= rA;
        },
        else => {
            const iA = sqlite3VdbeIntValue(pIn1);
            const iB = sqlite3VdbeIntValue(pIn2);
            if (iA == 0) {
                sqlite3VdbeMemSetNull(pOut);
                return;
            }
            const iAd: i64 = if (iA == -1) 1 else iA;
            rB = @floatFromInt(@rem(iB, iAd));
        },
    }
    if (sqlite3IsNaN(rB) != 0) {
        sqlite3VdbeMemSetNull(pOut);
        return;
    }
    pOut.u.r = rB;
    MemSetTypeFlag(pOut, MEM_Real);
}

// ---- OP_BitAnd/BitOr/ShiftLeft/ShiftRight --------------------------------
fn opBitwise(pOp: *Op, aMem: [*]u8) void {
    const pIn1 = memAt(aMem, pOp.p1);
    const pIn2 = memAt(aMem, pOp.p2);
    const pOut = memAt(aMem, pOp.p3);
    if (((pIn1.flags | pIn2.flags) & MEM_Null) != 0) {
        sqlite3VdbeMemSetNull(pOut);
        return;
    }
    var iA = sqlite3VdbeIntValue(pIn2);
    const iB = sqlite3VdbeIntValue(pIn1);
    var op = pOp.opcode;
    if (op == OP_BitAnd) {
        iA &= iB;
    } else if (op == OP_BitOr) {
        iA |= iB;
    } else if (iB != 0) {
        var shift = iB;
        if (shift < 0) {
            op = 2 * OP_ShiftLeft + 1 - op;
            shift = if (shift > -64) -shift else 64;
        }
        if (shift >= 64) {
            iA = if (iA >= 0 or op == OP_ShiftLeft) 0 else -1;
        } else {
            var uA: u64 = @bitCast(iA);
            const sh: u6 = @intCast(shift);
            if (op == OP_ShiftLeft) {
                uA <<= sh;
            } else {
                uA >>= sh;
                if (iA < 0) {
                    const fill: u64 = 0xffffffff_ffffffff;
                    uA |= fill << @intCast(64 - shift);
                }
            }
            iA = @bitCast(uA);
        }
    }
    pOut.u.i = iA;
    MemSetTypeFlag(pOut, MEM_Int);
}

// ---- OP_Eq/Ne/Lt/Le/Gt/Ge ------------------------------------------------
// Returns true if the jump to p2 should be taken.
fn opCompare(pOp: *Op, aMem: [*]u8, encoding: u8, iCompare: *c_int) bool {
    const op = pOp.opcode;
    const pIn1 = memAt(aMem, pOp.p1);
    const pIn3 = memAt(aMem, pOp.p3);
    var flags1 = pIn1.flags;
    var flags3 = pIn3.flags;

    if ((flags1 & flags3 & MEM_Int) != 0) {
        if (pIn3.u.i > pIn1.u.i) {
            if (aGTb(op)) return true;
            iCompare.* = 1;
        } else if (pIn3.u.i < pIn1.u.i) {
            if (aLTb(op)) return true;
            iCompare.* = -1;
        } else {
            if (aEQb(op)) return true;
            iCompare.* = 0;
        }
        return false;
    }
    var res: c_int = undefined;
    if (((flags1 | flags3) & MEM_Null) != 0) {
        if ((pOp.p5 & SQLITE_NULLEQ) != 0) {
            if ((flags1 & flags3 & MEM_Null) != 0 and (flags3 & MEM_Cleared) == 0) {
                res = 0;
            } else {
                res = if ((flags3 & MEM_Null) != 0) -1 else 1;
            }
        } else {
            if ((pOp.p5 & SQLITE_JUMPIFNULL) != 0) {
                return true;
            }
            iCompare.* = 1;
            return false;
        }
    } else {
        const affinity = pOp.p5 & SQLITE_AFF_MASK;
        if (affinity >= SQLITE_AFF_NUMERIC) {
            if (((flags1 | flags3) & MEM_Str) != 0) {
                if ((flags1 & (MEM_Int | MEM_IntReal | MEM_Real | MEM_Str)) == MEM_Str) {
                    applyNumericAffinity(pIn1, false);
                    flags3 = pIn3.flags;
                }
                if ((flags3 & (MEM_Int | MEM_IntReal | MEM_Real | MEM_Str)) == MEM_Str) {
                    applyNumericAffinity(pIn3, false);
                }
            }
        } else if (affinity == SQLITE_AFF_TEXT and ((flags1 | flags3) & MEM_Str) != 0) {
            if ((flags1 & MEM_Str) != 0) {
                pIn1.flags &= ~(MEM_Int | MEM_Real | MEM_IntReal);
            } else if ((flags1 & (MEM_Int | MEM_Real | MEM_IntReal)) != 0) {
                _ = sqlite3VdbeMemStringify(pIn1, encoding, 1);
                flags1 = (pIn1.flags & ~MEM_TypeMask) | (flags1 & MEM_TypeMask);
                if (pIn1 == pIn3) flags3 = flags1 | MEM_Str;
            }
            if ((flags3 & MEM_Str) != 0) {
                pIn3.flags &= ~(MEM_Int | MEM_Real | MEM_IntReal);
            } else if ((flags3 & (MEM_Int | MEM_Real | MEM_IntReal)) != 0) {
                _ = sqlite3VdbeMemStringify(pIn3, encoding, 1);
                flags3 = (pIn3.flags & ~MEM_TypeMask) | (flags3 & MEM_TypeMask);
            }
        }
        res = sqlite3MemCompare(pIn3, pIn1, pOp.p4.pColl);
    }

    var res2: bool = undefined;
    if (res < 0) {
        res2 = aLTb(op);
    } else if (res == 0) {
        res2 = aEQb(op);
    } else {
        res2 = aGTb(op);
    }
    iCompare.* = res;
    pIn3.flags = flags3;
    pIn1.flags = flags1;
    return res2;
}

// ---- OP_Compare (vector) --------------------------------------------------
fn opCompareVec(pOp: *Op, aOp: [*]Op, aMem: [*]u8, pc: usize, iCompare: *c_int) void {
    var aPermute: ?[*]u32 = null;
    if ((pOp.p5 & OPFLAG_PERMUTE) != 0) {
        aPermute = aOp[pc - 1].p4.ai.? + 1;
    }
    const n = pOp.p3;
    const pKeyInfo = pOp.p4.pKeyInfo;
    const p1 = pOp.p1;
    const p2 = pOp.p2;
    const aColl: [*]?*CollSeq = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pKeyInfo.?)) + KeyInfo_aColl));
    const aSortFlags: [*]const u8 = @ptrCast(rdPtr(pKeyInfo, KeyInfo_aSortFlags).?);
    var i: c_int = 0;
    while (i < n) : (i += 1) {
        const idx: c_int = if (aPermute) |ap| @intCast(ap[@intCast(i)]) else i;
        const pColl = aColl[@intCast(i)];
        const bRev = (aSortFlags[@intCast(i)] & KEYINFO_ORDER_DESC) != 0;
        iCompare.* = sqlite3MemCompare(memAt(aMem, p1 + idx), memAt(aMem, p2 + idx), pColl);
        if (iCompare.* != 0) {
            if ((aSortFlags[@intCast(i)] & KEYINFO_ORDER_BIGNULL) != 0 and
                ((memAt(aMem, p1 + idx).flags & MEM_Null) != 0 or (memAt(aMem, p2 + idx).flags & MEM_Null) != 0))
            {
                iCompare.* = -iCompare.*;
            }
            if (bRev) iCompare.* = -iCompare.*;
            break;
        }
    }
}

// ---- OP_IsType ------------------------------------------------------------
fn opIsType(p: ?*Vdbe, pOp: *Op, aMem: [*]u8) bool {
    var typeMask: u16 = undefined;
    if (pOp.p1 >= 0) {
        const apCsr = apCsrOf(p);
        const pC = apCsr[@intCast(pOp.p1)];
        if (pOp.p3 < rd(u16, pC, VC_nHdrParsed)) {
            const aType: [*]u32 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pC.?)) + VC_aType));
            const serialType = aType[@intCast(pOp.p3)];
            if (serialType >= 12) {
                typeMask = if (serialType & 1 != 0) 0x04 else 0x08;
            } else {
                const aMask = [_]u8{ 0x10, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x2, 0x01, 0x01, 0x10, 0x10 };
                typeMask = aMask[@intCast(serialType)];
            }
        } else {
            typeMask = @as(u16, 1) << @intCast(pOp.p4.i - 1);
        }
    } else {
        typeMask = @as(u16, 1) << @intCast(sqlite3_value_type(memAt(aMem, pOp.p3)) - 1);
    }
    return (typeMask & pOp.p5) != 0;
}

// ---- OP_Column ------------------------------------------------------------
const ColumnResult = union(enum) { ok, corrupt_jump: usize, no_mem, too_big, err };

fn opColumn(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOp: [*]Op, aMem: [*]u8, encoding: u8, colCacheCtr: u32, rc: *c_int) ColumnResult {
    const apCsr = apCsrOf(p);
    var pC = apCsr[@intCast(pOp.p1)];
    var p2: u32 = @intCast(pOp.p2);
    var sMem: Mem = undefined;
    var len: c_int = undefined;
    var i: c_int = undefined;
    var pDest: *Mem = undefined;
    var t: u32 = undefined;
    var zData: [*]const u8 = undefined;

    op_column_restart: while (true) {
        const aOffset: [*]u32 = @ptrCast(@alignCast(rdPtr(pC, VC_aOffset).?));
        const cacheCtr = rd(c_int, p, Vdbe_cacheCtr);
        var goto_read_header = false;

        if (rd(u32, pC, VC_cacheStatus) != @as(u32, @bitCast(cacheCtr))) {
            if (rdU8(pC, VC_nullRow) != 0) {
                if (rdU8(pC, VC_eCurType) == CURTYPE_PSEUDO and rd(c_int, pC, VC_seekResult) > 0) {
                    const pReg = memAt(aMem, rd(c_int, pC, VC_seekResult));
                    wr(u32, pC, VC_payloadSize, @intCast(pReg.n));
                    wr(u32, pC, VC_szRow, @intCast(pReg.n));
                    wrPtr(pC, VC_aRow, @ptrCast(pReg.z));
                } else {
                    pDest = memAt(aMem, pOp.p3);
                    sqlite3VdbeMemSetNull(pDest);
                    updateMaxBlobsize(pDest);
                    return .ok;
                }
            } else {
                const pCrsr: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
                if (rdU8(pC, VC_deferredMoveto) != 0) {
                    const aAltMap = rdPtr(pC, VC_ub);
                    if (aAltMap != null) {
                        const am: [*]u32 = @ptrCast(@alignCast(aAltMap.?));
                        const iMap = am[1 + p2];
                        if (iMap > 0) {
                            pC = rdPtr(pC, VC_pAltCursor);
                            p2 = iMap - 1;
                            continue :op_column_restart;
                        }
                    }
                    rc.* = sqlite3VdbeFinishMoveto(pC);
                    if (rc.* != 0) return .err;
                } else if (sqlite3BtreeCursorHasMoved(pCrsr) != 0) {
                    rc.* = sqlite3VdbeHandleMovedCursor(pC);
                    if (rc.* != 0) return .err;
                    continue :op_column_restart;
                }
                wr(u32, pC, VC_payloadSize, sqlite3BtreePayloadSize(pCrsr));
                var szRow: u32 = 0;
                wrPtr(pC, VC_aRow, @ptrCast(@constCast(sqlite3BtreePayloadFetch(pCrsr, &szRow))));
                wr(u32, pC, VC_szRow, szRow);
            }
            wr(u32, pC, VC_cacheStatus, @bitCast(cacheCtr));
            const aRow: [*]const u8 = @ptrCast(rdPtr(pC, VC_aRow).?);
            aOffset[0] = aRow[0];
            if (aOffset[0] < 0x80) {
                wr(u32, pC, VC_iHdrOffset, 1);
            } else {
                wr(u32, pC, VC_iHdrOffset, sqlite3GetVarint32(aRow, &aOffset[0]));
            }
            wr(u16, pC, VC_nHdrParsed, 0);

            if (rd(u32, pC, VC_szRow) < aOffset[0]) {
                wrPtr(pC, VC_aRow, null);
                wr(u32, pC, VC_szRow, 0);
                if (aOffset[0] > 98307 or aOffset[0] > rd(u32, pC, VC_payloadSize)) {
                    return opColumnCorrupt(pOp, aOp, rc);
                }
            } else {
                zData = aRow;
                goto_read_header = true;
            }
        } else if (sqlite3BtreeCursorHasMoved(@ptrCast(rdPtr(pC, VC_uc))) != 0) {
            rc.* = sqlite3VdbeHandleMovedCursor(pC);
            if (rc.* != 0) return .err;
            continue :op_column_restart;
        }

        // header-parse section
        if (rd(u16, pC, VC_nHdrParsed) <= p2 or goto_read_header) {
            if (goto_read_header or rd(u32, pC, VC_iHdrOffset) < aOffset[0]) {
                if (!goto_read_header) {
                    if (rdPtr(pC, VC_aRow) == null) {
                        sMem = std.mem.zeroes(Mem);
                        rc.* = sqlite3VdbeMemFromBtreeZeroOffset(@ptrCast(rdPtr(pC, VC_uc)), aOffset[0], &sMem);
                        if (rc.* != SQLITE_OK) return .err;
                        zData = @ptrCast(sMem.z.?);
                    } else {
                        zData = @ptrCast(rdPtr(pC, VC_aRow).?);
                    }
                }
                // op_column_read_header:
                const aType: [*]u32 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pC.?)) + VC_aType));
                i = rd(u16, pC, VC_nHdrParsed);
                var offset64: u64 = aOffset[@intCast(i)];
                var zHdr = zData + rd(u32, pC, VC_iHdrOffset);
                const zEndHdr = zData + aOffset[0];
                while (true) {
                    t = zHdr[0];
                    if (t < 0x80) {
                        aType[@intCast(i)] = t;
                        zHdr += 1;
                        offset64 += sqlite3VdbeOneByteSerialTypeLen(@intCast(t));
                    } else {
                        zHdr += sqlite3GetVarint32(zHdr, &t);
                        aType[@intCast(i)] = t;
                        offset64 += sqlite3VdbeSerialTypeLen(t);
                    }
                    i += 1;
                    aOffset[@intCast(i)] = @truncate(offset64);
                    if (!(@as(u32, @intCast(i)) <= p2 and @intFromPtr(zHdr) < @intFromPtr(zEndHdr))) break;
                }

                if ((@intFromPtr(zHdr) >= @intFromPtr(zEndHdr) and (@intFromPtr(zHdr) > @intFromPtr(zEndHdr) or offset64 != rd(u32, pC, VC_payloadSize))) or
                    (offset64 > rd(u32, pC, VC_payloadSize)))
                {
                    if (aOffset[0] == 0) {
                        i = 0;
                        zHdr = zEndHdr;
                    } else {
                        if (rdPtr(pC, VC_aRow) == null) sqlite3VdbeMemRelease(&sMem);
                        return opColumnCorrupt(pOp, aOp, rc);
                    }
                }
                wr(u16, pC, VC_nHdrParsed, @intCast(i));
                wr(u32, pC, VC_iHdrOffset, @intCast((@intFromPtr(zHdr) - @intFromPtr(zData))));
                if (rdPtr(pC, VC_aRow) == null) sqlite3VdbeMemRelease(&sMem);
            } else {
                t = 0;
            }

            if (rd(u16, pC, VC_nHdrParsed) <= p2) {
                pDest = memAt(aMem, pOp.p3);
                if (pOp.p4type == P4_MEM) {
                    sqlite3VdbeMemShallowCopy(pDest, pOp.p4.pMem, MEM_Static);
                } else {
                    sqlite3VdbeMemSetNull(pDest);
                }
                updateMaxBlobsize(pDest);
                return .ok;
            }
        } else {
            const aType: [*]u32 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pC.?)) + VC_aType));
            t = aType[@intCast(p2)];
        }

        // Extract content.
        pDest = memAt(aMem, pOp.p3);
        if (VdbeMemDynamic(pDest)) sqlite3VdbeMemSetNull(pDest);
        const aRowP = rdPtr(pC, VC_aRow);
        if (rd(u32, pC, VC_szRow) >= aOffset[p2 + 1]) {
            const zd = @as([*]const u8, @ptrCast(aRowP.?)) + aOffset[p2];
            if (t < 12) {
                sqlite3VdbeSerialGet(zd, t, pDest);
            } else {
                const aFlag = [_]u16{ MEM_Blob, MEM_Str | MEM_Term };
                len = @intCast((t - 12) / 2);
                pDest.n = len;
                pDest.enc = encoding;
                if (pDest.szMalloc < len + 2) {
                    if (len > dbLimit(db, SQLITE_LIMIT_LENGTH)) return .too_big;
                    pDest.flags = MEM_Null;
                    if (sqlite3VdbeMemGrow(pDest, len + 2, 0) != 0) return .no_mem;
                } else {
                    pDest.z = pDest.zMalloc;
                }
                @memcpy(pDest.z.?[0..@intCast(len)], zd[0..@intCast(len)]);
                pDest.z.?[@intCast(len)] = 0;
                pDest.z.?[@intCast(len + 1)] = 0;
                pDest.flags = aFlag[t & 1];
            }
        } else {
            pDest.enc = encoding;
            const p5 = pOp.p5 & OPFLAG_BYTELENARG;
            if ((p5 != 0 and (p5 == OPFLAG_TYPEOFARG or (t >= 12 and ((t & 1) == 0 or p5 == OPFLAG_BYTELENARG)))) or
                sqlite3VdbeSerialTypeLen(t) == 0)
            {
                sqlite3VdbeSerialGet(@ptrCast(&sqlite3CtypeMap), t, pDest);
            } else {
                rc.* = vdbeColumnFromOverflow(pC, @intCast(p2), t, @intCast(aOffset[p2]), @bitCast(rd(c_int, p, Vdbe_cacheCtr)), colCacheCtr, pDest);
                if (rc.* != 0) {
                    if (rc.* == SQLITE_NOMEM) return .no_mem;
                    if (rc.* == SQLITE_TOOBIG) return .too_big;
                    return .err;
                }
            }
        }
        updateMaxBlobsize(pDest);
        return .ok;
    }
}

fn opColumnCorrupt(pOp: *Op, aOp: [*]Op, rc: *c_int) ColumnResult {
    if (aOp[0].p3 > 0) {
        return .{ .corrupt_jump = @intCast(aOp[0].p3) }; // C: pOp=&aOp[p3-1]; loop top lands on p3
    } else {
        rc.* = SQLITE_CORRUPT;
        return .err;
    }
    _ = pOp;
}

// ---- OP_TypeCheck ---------------------------------------------------------
fn opTypeCheck(p: ?*Vdbe, pOp: *Op, aMem: [*]u8, encoding: u8, rc: *c_int) bool {
    const pTab = pOp.p4.pTab;
    const aCol: [*]u8 = @ptrCast(rdPtr(pTab, Table_aCol).?);
    var pIn1 = memAt(aMem, pOp.p1);
    var i: c_int = undefined;
    var nCol: c_int = undefined;
    const nColTab: c_int = rd(i16, pTab, Table_nCol);
    if (pOp.p3 < 2) {
        i = 0;
        nCol = nColTab;
    } else {
        i = pOp.p3 - 2;
        nCol = i + 1;
    }
    while (i < nCol) : (i += 1) {
        const pCol = aCol + @as(usize, @intCast(i)) * sizeof_Column;
        const colFlags = rd(u16, pCol, Column_colFlags);
        const eCType: u8 = (rdU8(pCol, Column_eCTypeByte) >> 4) & 0x0f;
        if ((colFlags & COLFLAG_GENERATED) != 0 and pOp.p3 < 2) {
            if ((colFlags & COLFLAG_VIRTUAL) != 0) continue;
            if (pOp.p3 != 0) {
                pIn1 = @ptrFromInt(@intFromPtr(pIn1) + sizeof_Mem);
                continue;
            }
        }
        applyAffinity(pIn1, rdU8(pCol, Column_affinity), encoding);
        if ((pIn1.flags & MEM_Null) == 0) {
            switch (eCType) {
                COLTYPE_BLOB => {
                    if ((pIn1.flags & MEM_Blob) == 0) return typeError(p, pIn1, pTab, pCol, eCType, rc);
                },
                COLTYPE_INTEGER, COLTYPE_INT => {
                    if ((pIn1.flags & MEM_Int) == 0) return typeError(p, pIn1, pTab, pCol, eCType, rc);
                },
                COLTYPE_TEXT => {
                    if ((pIn1.flags & MEM_Str) == 0) return typeError(p, pIn1, pTab, pCol, eCType, rc);
                },
                COLTYPE_REAL => {
                    if ((pIn1.flags & MEM_Int) != 0) {
                        if (pIn1.u.i <= 140737488355327 and pIn1.u.i >= -140737488355328) {
                            pIn1.flags |= MEM_IntReal;
                            pIn1.flags &= ~MEM_Int;
                        } else {
                            pIn1.u.r = @floatFromInt(pIn1.u.i);
                            pIn1.flags |= MEM_Real;
                            pIn1.flags &= ~MEM_Int;
                        }
                    } else if ((pIn1.flags & (MEM_Real | MEM_IntReal)) == 0) {
                        return typeError(p, pIn1, pTab, pCol, eCType, rc);
                    }
                },
                else => {},
            }
        }
        pIn1 = @ptrFromInt(@intFromPtr(pIn1) + sizeof_Mem);
    }
    return false;
}

fn typeError(p: ?*Vdbe, pIn1: *Mem, pTab: ?*Table, pCol: ?*anyopaque, eCType: u8, rc: *c_int) bool {
    const stdTypeArr: [*]const [*:0]const u8 = @ptrCast(&sqlite3StdType);
    const zTab: [*:0]const u8 = @ptrCast(rdPtr(pTab, Table_zName) orelse @as(?*anyopaque, @constCast(@ptrCast(@as([*:0]const u8, "")))));
    const zCol: [*:0]const u8 = @ptrCast(rdPtr(pCol, Column_zCnName) orelse @as(?*anyopaque, @constCast(@ptrCast(@as([*:0]const u8, "")))));
    sqlite3VdbeError(p, "cannot store %s value in %s column %s.%s", vdbeMemTypeName(pIn1), stdTypeArr[eCType - 1], zTab, zCol);
    rc.* = SQLITE_CONSTRAINT_DATATYPE;
    return true;
}

// ---- OP_Affinity ----------------------------------------------------------
fn opAffinity(pOp: *Op, aMem: [*]u8, encoding: u8) void {
    var zAff: [*:0]const u8 = pOp.p4.z.?;
    var pIn1 = memAt(aMem, pOp.p1);
    while (true) {
        applyAffinity(pIn1, zAff[0], encoding);
        if (zAff[0] == SQLITE_AFF_REAL and (pIn1.flags & MEM_Int) != 0) {
            if (pIn1.u.i <= 140737488355327 and pIn1.u.i >= -140737488355328) {
                pIn1.flags |= MEM_IntReal;
                pIn1.flags &= ~MEM_Int;
            } else {
                pIn1.u.r = @floatFromInt(pIn1.u.i);
                pIn1.flags |= MEM_Real;
                pIn1.flags &= ~(MEM_Int | MEM_Str);
            }
        }
        zAff += 1;
        if (zAff[0] == 0) break;
        pIn1 = @ptrFromInt(@intFromPtr(pIn1) + sizeof_Mem);
    }
}

// ---- OP_MakeRecord --------------------------------------------------------
const MakeRecordResult = enum { ok, no_mem, too_big };

fn opMakeRecord(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, encoding: u8, rc: *c_int) MakeRecordResult {
    _ = rc;
    var nData: u64 = 0;
    var nHdr: c_int = 0;
    var nZero: i64 = 0;
    var nFieldIn = pOp.p1;
    const zAffinity = pOp.p4.z;
    const pData0 = memAt(aMem, nFieldIn);
    nFieldIn = pOp.p2;
    const pLast = memAt(@as([*]u8, @ptrCast(pData0)), nFieldIn - 1);
    const pOut = memAt(aMem, pOp.p3);

    // apply affinity
    if (zAffinity) |za0| {
        var za = za0;
        var pRec = pData0;
        while (true) {
            applyAffinity(pRec, za[0], encoding);
            if (za[0] == SQLITE_AFF_REAL and (pRec.flags & MEM_Int) != 0) {
                pRec.flags |= MEM_IntReal;
                pRec.flags &= ~MEM_Int;
            }
            za += 1;
            pRec = @ptrFromInt(@intFromPtr(pRec) + sizeof_Mem);
            if (za[0] == 0) break;
        }
    }

    // size the record
    var pRec = pLast;
    var serial_type: u32 = undefined;
    while (true) {
        if ((pRec.flags & MEM_Null) != 0) {
            if ((pRec.flags & MEM_Zero) != 0) {
                pRec.uTemp = 10;
            } else {
                pRec.uTemp = 0;
            }
            nHdr += 1;
        } else if ((pRec.flags & (MEM_Int | MEM_IntReal)) != 0) {
            const iv = pRec.u.i;
            const uu: u64 = if (iv < 0) ~@as(u64, @bitCast(iv)) else @bitCast(iv);
            nHdr += 1;
            if (uu <= 127) {
                if ((iv & 1) == iv and rdU8(p, Vdbe_minWriteFileFormat) >= 4) {
                    pRec.uTemp = 8 + @as(u32, @intCast(uu));
                } else {
                    nData += 1;
                    pRec.uTemp = 1;
                }
            } else if (uu <= 32767) {
                nData += 2;
                pRec.uTemp = 2;
            } else if (uu <= 8388607) {
                nData += 3;
                pRec.uTemp = 3;
            } else if (uu <= 2147483647) {
                nData += 4;
                pRec.uTemp = 4;
            } else if (uu <= 140737488355327) {
                nData += 6;
                pRec.uTemp = 5;
            } else {
                nData += 8;
                if ((pRec.flags & MEM_IntReal) != 0) {
                    pRec.u.r = @floatFromInt(pRec.u.i);
                    pRec.flags &= ~MEM_IntReal;
                    pRec.flags |= MEM_Real;
                    pRec.uTemp = 7;
                } else {
                    pRec.uTemp = 6;
                }
            }
        } else if ((pRec.flags & MEM_Real) != 0) {
            nHdr += 1;
            nData += 8;
            pRec.uTemp = 7;
        } else {
            var len: u32 = @intCast(pRec.n);
            serial_type = (len * 2) + 12 + @intFromBool((pRec.flags & MEM_Str) != 0);
            if ((pRec.flags & MEM_Zero) != 0) {
                serial_type += @as(u32, @intCast(pRec.u.nZero)) * 2;
                if (nData != 0) {
                    if (sqlite3VdbeMemExpandBlob(pRec) != 0) return .no_mem;
                    len += @intCast(pRec.u.nZero);
                } else {
                    nZero += pRec.u.nZero;
                }
            }
            nData += len;
            nHdr += sqlite3VarintLen(serial_type);
            pRec.uTemp = serial_type;
        }
        if (pRec == pData0) break;
        pRec = @ptrFromInt(@intFromPtr(pRec) - sizeof_Mem);
    }

    if (nHdr <= 126) {
        nHdr += 1;
    } else {
        const nVarint = sqlite3VarintLen(@intCast(nHdr));
        nHdr += nVarint;
        if (nVarint < sqlite3VarintLen(@intCast(nHdr))) nHdr += 1;
    }
    const nByte: i64 = @as(i64, nHdr) + @as(i64, @intCast(nData));

    if (nByte + nZero <= pOut.szMalloc) {
        pOut.z = pOut.zMalloc;
    } else {
        if (nByte + nZero > dbLimit(db, SQLITE_LIMIT_LENGTH)) return .too_big;
        if (sqlite3VdbeMemClearAndResize(pOut, @intCast(nByte)) != 0) return .no_mem;
    }
    pOut.n = @intCast(nByte);
    pOut.flags = MEM_Blob;
    if (nZero != 0) {
        pOut.u.nZero = @intCast(nZero);
        pOut.flags |= MEM_Zero;
    }
    updateMaxBlobsize(pOut);
    var zHdr: [*]u8 = @ptrCast(pOut.z.?);
    var zPayload: [*]u8 = zHdr + @as(usize, @intCast(nHdr));

    if (nHdr < 0x80) {
        zHdr[0] = @intCast(nHdr);
        zHdr += 1;
    } else {
        zHdr += @intCast(sqlite3PutVarint(zHdr, @intCast(nHdr)));
    }
    pRec = pData0;
    while (true) {
        serial_type = pRec.uTemp;
        if (serial_type <= 7) {
            zHdr[0] = @intCast(serial_type);
            zHdr += 1;
            if (serial_type != 0) {
                var v: u64 = undefined;
                if (serial_type == 7) {
                    v = @bitCast(pRec.u.r);
                    v = swapMixedEndianFloat(v);
                } else {
                    v = @bitCast(pRec.u.i);
                }
                const slen = smallTypeSize(serial_type);
                var k: usize = slen;
                while (k > 0) {
                    k -= 1;
                    zPayload[k] = @truncate(v & 0xff);
                    v >>= 8;
                }
                zPayload += slen;
            }
        } else if (serial_type < 0x80) {
            zHdr[0] = @intCast(serial_type);
            zHdr += 1;
            if (serial_type >= 14 and pRec.n > 0) {
                // memmove semantics: upstream uses memcpy but the src/dst can
                // alias (e.g. FTS5 content rows), which Zig's @memcpy forbids.
                @memmove(zPayload[0..@intCast(pRec.n)], pRec.z.?[0..@intCast(pRec.n)]);
                zPayload += @intCast(pRec.n);
            }
        } else {
            zHdr += @intCast(sqlite3PutVarint(zHdr, serial_type));
            if (pRec.n != 0) {
                @memmove(zPayload[0..@intCast(pRec.n)], pRec.z.?[0..@intCast(pRec.n)]);
                zPayload += @intCast(pRec.n);
            }
        }
        if (pRec == pLast) break;
        pRec = @ptrFromInt(@intFromPtr(pRec) + sizeof_Mem);
    }
    return .ok;
}
// ===========================================================================
// Opcode handlers, batch 2: savepoint / transaction / cursor open / seek /
// insert / delete / index / vtab / function / aggregate / misc.
// ===========================================================================

// ---- OP_Savepoint ---------------------------------------------------------
// Returns true if the driver must `continue :main` (exit machinery set), false
// to fall through (pc+=1). On the vdbe_return / abort paths sets exitKind+done.
fn opSavepoint(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, rc: *c_int, exitKind: *ExitKind, done: *bool) bool {
    const p1 = pOp.p1;
    const zName: ?[*:0]const u8 = @ptrCast(pOp.p4.z);

    if (p1 == SAVEPOINT_BEGIN) {
        if (rd(c_int, db, sqlite3_nVdbeWrite) > 0) {
            sqlite3VdbeError(p, "cannot open savepoint - SQL statements in progress");
            rc.* = SQLITE_BUSY;
        } else {
            const nName = sqlite3Strlen30(zName);
            rc.* = sqlite3VtabSavepoint(db, SAVEPOINT_BEGIN, rd(c_int, db, sqlite3_nStatement) + rd(c_int, db, sqlite3_nSavepoint));
            if (rc.* != SQLITE_OK) {
                exitKind.* = .abort_error;
                done.* = true;
                return true;
            }
            const pNew = sqlite3DbMallocRawNN(db, @intCast(sizeof_Savepoint + @as(usize, @intCast(nName)) + 1));
            if (pNew != null) {
                const zDst: [*]u8 = @as([*]u8, @ptrCast(pNew.?)) + sizeof_Savepoint;
                wrPtr(pNew, Savepoint_zName, @ptrCast(zDst));
                @memcpy(zDst[0..@intCast(nName + 1)], zName.?[0..@intCast(nName + 1)]);
                if (rdU8(db, sqlite3_autoCommit) != 0) {
                    wrU8(db, sqlite3_autoCommit, 0);
                    wrU8(db, sqlite3_isTransactionSavepoint, 1);
                } else {
                    wr(c_int, db, sqlite3_nSavepoint, rd(c_int, db, sqlite3_nSavepoint) + 1);
                }
                wrPtr(pNew, Savepoint_pNext, rdPtr(db, sqlite3_pSavepoint));
                wrPtr(db, sqlite3_pSavepoint, pNew);
                wr(i64, pNew, Savepoint_nDeferredCons, rd(i64, db, sqlite3_nDeferredCons));
                wr(i64, pNew, Savepoint_nDeferredImmCons, rd(i64, db, sqlite3_nDeferredImmCons));
            }
        }
    } else {
        var iSavepoint: c_int = 0;
        var pSavepoint = rdPtr(db, sqlite3_pSavepoint);
        while (pSavepoint != null and sqlite3StrICmp(@ptrCast(rdPtr(pSavepoint, Savepoint_zName)), zName) != 0) {
            iSavepoint += 1;
            pSavepoint = rdPtr(pSavepoint, Savepoint_pNext);
        }
        if (pSavepoint == null) {
            sqlite3VdbeError(p, "no such savepoint: %s", zName orelse @as([*:0]const u8, ""));
            rc.* = SQLITE_ERROR;
        } else if (rd(c_int, db, sqlite3_nVdbeWrite) > 0 and p1 == SAVEPOINT_RELEASE) {
            sqlite3VdbeError(p, "cannot release savepoint - SQL statements in progress");
            rc.* = SQLITE_BUSY;
        } else {
            const isTransaction = rdPtr(pSavepoint, Savepoint_pNext) == null and rdU8(db, sqlite3_isTransactionSavepoint) != 0;
            if (isTransaction and p1 == SAVEPOINT_RELEASE) {
                rc.* = sqlite3VdbeCheckFkDeferred(p);
                if (rc.* != SQLITE_OK) {
                    exitKind.* = .ret;
                    done.* = true;
                    return true;
                }
                wrU8(db, sqlite3_autoCommit, 1);
                if (sqlite3VdbeHalt(p) == SQLITE_BUSY) {
                    wrU8(db, sqlite3_autoCommit, 0);
                    wr(c_int, p, Vdbe_rc, SQLITE_BUSY);
                    rc.* = SQLITE_BUSY;
                    exitKind.* = .ret;
                    done.* = true;
                    return true;
                }
                rc.* = rd(c_int, p, Vdbe_rc);
                if (rc.* != 0) {
                    wrU8(db, sqlite3_autoCommit, 0);
                } else {
                    wrU8(db, sqlite3_isTransactionSavepoint, 0);
                }
            } else {
                iSavepoint = rd(c_int, db, sqlite3_nSavepoint) - iSavepoint - 1;
                var isSchemaChange: bool = false;
                const nDb = rd(c_int, db, sqlite3_nDb);
                if (p1 == SAVEPOINT_ROLLBACK) {
                    isSchemaChange = (rd(u32, db, sqlite3_mDbFlags) & DBFLAG_SchemaChange) != 0;
                    var ii: c_int = 0;
                    while (ii < nDb) : (ii += 1) {
                        rc.* = sqlite3BtreeTripAllCursors(rdPtr(dbEnt(db, ii), Db_pBt), SQLITE_ABORT_ROLLBACK, @intFromBool(!isSchemaChange));
                        if (rc.* != SQLITE_OK) {
                            exitKind.* = .abort_error;
                            done.* = true;
                            return true;
                        }
                    }
                }
                var ii: c_int = 0;
                while (ii < nDb) : (ii += 1) {
                    rc.* = sqlite3BtreeSavepoint(rdPtr(dbEnt(db, ii), Db_pBt), p1, iSavepoint);
                    if (rc.* != SQLITE_OK) {
                        exitKind.* = .abort_error;
                        done.* = true;
                        return true;
                    }
                }
                if (isSchemaChange) {
                    sqlite3ExpirePreparedStatements(db, 0);
                    sqlite3ResetAllSchemasOfConnection(db);
                    wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) | DBFLAG_SchemaChange);
                }
            }
            if (rc.* != 0) {
                exitKind.* = .abort_error;
                done.* = true;
                return true;
            }
            // destroy nested savepoints
            while (rdPtr(db, sqlite3_pSavepoint) != pSavepoint) {
                const pTmp = rdPtr(db, sqlite3_pSavepoint);
                wrPtr(db, sqlite3_pSavepoint, rdPtr(pTmp, Savepoint_pNext));
                sqlite3DbFree(db, pTmp);
                wr(c_int, db, sqlite3_nSavepoint, rd(c_int, db, sqlite3_nSavepoint) - 1);
            }
            // Use the `isTransaction` computed at the top (before the RELEASE
            // commit path may clear db->isTransactionSavepoint). Recomputing it
            // here read the already-cleared flag and wrongly decremented
            // nSavepoint for a transaction savepoint (→ nSavepoint went negative,
            // crashing a later ROLLBACK in the pager). Matches upstream, which
            // reuses the single `isTransaction` local.
            if (p1 == SAVEPOINT_RELEASE) {
                wrPtr(db, sqlite3_pSavepoint, rdPtr(pSavepoint, Savepoint_pNext));
                sqlite3DbFree(db, pSavepoint);
                if (!isTransaction) {
                    wr(c_int, db, sqlite3_nSavepoint, rd(c_int, db, sqlite3_nSavepoint) - 1);
                }
            } else {
                wr(i64, db, sqlite3_nDeferredCons, rd(i64, pSavepoint, Savepoint_nDeferredCons));
                wr(i64, db, sqlite3_nDeferredImmCons, rd(i64, pSavepoint, Savepoint_nDeferredImmCons));
            }
            if (!isTransaction or p1 == SAVEPOINT_ROLLBACK) {
                rc.* = sqlite3VtabSavepoint(db, p1, iSavepoint);
                if (rc.* != SQLITE_OK) {
                    exitKind.* = .abort_error;
                    done.* = true;
                    return true;
                }
            }
        }
    }
    if (rc.* != 0) {
        exitKind.* = .abort_error;
        done.* = true;
        return true;
    }
    if (rdU8(p, Vdbe_eVdbeState) == VDBE_HALT_STATE) {
        rc.* = SQLITE_DONE;
        exitKind.* = .ret;
        done.* = true;
        return true;
    }
    return false;
}

// ---- OP_AutoCommit (always halts) ----------------------------------------
fn opAutoCommit(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOpRef: *[*]Op, pc: usize, rc: *c_int, exitKind: *ExitKind, done: *bool) void {
    const desiredAutoCommit = pOp.p1;
    const iRollback = pOp.p2;
    const aOp = aOpRef.*;

    if (desiredAutoCommit != rdU8(db, sqlite3_autoCommit)) {
        if (iRollback != 0) {
            sqlite3RollbackAll(db, SQLITE_ABORT_ROLLBACK);
            wrU8(db, sqlite3_autoCommit, 1);
        } else if (desiredAutoCommit != 0 and rd(c_int, db, sqlite3_nVdbeWrite) > 0) {
            sqlite3VdbeError(p, "cannot commit transaction - SQL statements in progress");
            rc.* = SQLITE_BUSY;
            exitKind.* = .abort_error;
            done.* = true;
            return;
        } else {
            rc.* = sqlite3VdbeCheckFkDeferred(p);
            if (rc.* != SQLITE_OK) {
                exitKind.* = .ret;
                done.* = true;
                return;
            }
            wrU8(db, sqlite3_autoCommit, @intCast(desiredAutoCommit & 0xff));
        }
        if (sqlite3VdbeHalt(p) == SQLITE_BUSY) {
            wr(c_int, p, Vdbe_pc, @intCast(pc));
            wrU8(db, sqlite3_autoCommit, @intCast((1 - desiredAutoCommit) & 0xff));
            wr(c_int, p, Vdbe_rc, SQLITE_BUSY);
            rc.* = SQLITE_BUSY;
            exitKind.* = .ret;
            done.* = true;
            return;
        }
        sqlite3CloseSavepoints(db);
        if (rd(c_int, p, Vdbe_rc) == SQLITE_OK) {
            rc.* = SQLITE_DONE;
        } else {
            rc.* = SQLITE_ERROR;
        }
        exitKind.* = .ret;
        done.* = true;
        return;
    } else {
        const msg: [*:0]const u8 = if (desiredAutoCommit == 0)
            "cannot start a transaction within a transaction"
        else if (iRollback != 0)
            "cannot rollback - no transaction is active"
        else
            "cannot commit - no transaction is active";
        sqlite3VdbeError(p, "%s", msg);
        rc.* = SQLITE_ERROR;
        exitKind.* = .abort_error;
        done.* = true;
    }
    _ = aOp;
}

// ---- OP_Transaction -------------------------------------------------------
// Returns true if driver must `continue :main` (exit set, or BUSY return).
fn opTransaction(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOpRef: *[*]Op, pc: usize, rc: *c_int, exitKind: *ExitKind, done: *bool) bool {
    _ = aOpRef;
    const pDb = dbEnt(db, pOp.p1);
    var iMeta: c_int = 0;

    if (pOp.p2 != 0 and (rd(u64, db, sqlite3_flags) & (SQLITE_QueryOnly | SQLITE_CorruptRdOnly)) != 0) {
        if ((rd(u64, db, sqlite3_flags) & SQLITE_QueryOnly) != 0) {
            rc.* = SQLITE_READONLY;
        } else {
            rc.* = SQLITE_CORRUPT;
        }
        exitKind.* = .abort_error;
        done.* = true;
        return true;
    }
    const pBt = rdPtr(pDb, Db_pBt);

    if (pBt != null) {
        rc.* = sqlite3BtreeBeginTrans(pBt, pOp.p2, &iMeta);
        if (rc.* != SQLITE_OK) {
            if ((rc.* & 0xff) == SQLITE_BUSY) {
                wr(c_int, p, Vdbe_pc, @intCast(pc));
                wr(c_int, p, Vdbe_rc, rc.*);
                exitKind.* = .ret;
                done.* = true;
                return true;
            }
            exitKind.* = .abort_error;
            done.* = true;
            return true;
        }
        if (getUsesStmtJournal(p) and pOp.p2 != 0 and (rdU8(db, sqlite3_autoCommit) == 0 or rd(c_int, db, sqlite3_nVdbeRead) > 1)) {
            if (rd(c_int, p, Vdbe_iStatement) == 0) {
                wr(c_int, db, sqlite3_nStatement, rd(c_int, db, sqlite3_nStatement) + 1);
                wr(c_int, p, Vdbe_iStatement, rd(c_int, db, sqlite3_nSavepoint) + rd(c_int, db, sqlite3_nStatement));
            }
            rc.* = sqlite3VtabSavepoint(db, SAVEPOINT_BEGIN, rd(c_int, p, Vdbe_iStatement) - 1);
            if (rc.* == SQLITE_OK) {
                rc.* = sqlite3BtreeBeginStmt(pBt, rd(c_int, p, Vdbe_iStatement));
            }
            wr(i64, p, Vdbe_nStmtDefCons, rd(i64, db, sqlite3_nDeferredCons));
            wr(i64, p, Vdbe_nStmtDefImmCons, rd(i64, db, sqlite3_nDeferredImmCons));
        }
    }
    if (rc.* == SQLITE_OK and pOp.p5 != 0) {
        const pSchema = rdPtr(pDb, Db_pSchema);
        if (iMeta != pOp.p3 or rd(c_int, pSchema, Schema_iGeneration) != pOp.p4.i) {
            sqlite3DbFree(db, rd(?[*:0]u8, p, Vdbe_zErrMsg));
            wrPtr(p, Vdbe_zErrMsg, @ptrCast(sqlite3DbStrDup(db, "database schema has changed")));
            if (rd(c_int, pSchema, Schema_schema_cookie) != iMeta) {
                sqlite3ResetOneSchema(db, pOp.p1);
            }
            setExpired(p, 1);
            rc.* = SQLITE_SCHEMA;
            setChangeCntOn(p, false);
        }
    }
    if (rc.* != 0) {
        exitKind.* = .abort_error;
        done.* = true;
        return true;
    }
    return false;
}

// ---- OP_SetCookie ---------------------------------------------------------
fn opSetCookie(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, rc: *c_int) bool {
    sqlite3VdbeIncrWriteCounter(p, null);
    const pDb = dbEnt(db, pOp.p1);
    rc.* = sqlite3BtreeUpdateMeta(rdPtr(pDb, Db_pBt), pOp.p2, @bitCast(pOp.p3));
    const pSchema = rdPtr(pDb, Db_pSchema);
    if (pOp.p2 == BTREE_SCHEMA_VERSION) {
        wr(u32, pSchema, Schema_schema_cookie, @bitCast(pOp.p3 - pOp.p5));
        wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) | DBFLAG_SchemaChange);
        sqlite3FkClearTriggerCache(db, pOp.p1);
    } else if (pOp.p2 == BTREE_FILE_FORMAT) {
        wr(u8, pSchema, Schema_file_format, @intCast(pOp.p3 & 0xff));
    }
    if (pOp.p1 == 1) {
        sqlite3ExpirePreparedStatements(db, 0);
        setExpired(p, 0);
    }
    return rc.* != 0;
}

// ---- OP_OpenRead/OpenWrite/ReopenIdx -------------------------------------
const OpenResult = enum { ok, no_mem, err };

fn opOpen(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, op: u8, aMem: [*]u8, rc: *c_int) OpenResult {
    const apCsr = apCsrOf(p);
    if (op == OP_ReopenIdx) {
        const pCur = apCsr[@intCast(pOp.p1)];
        if (pCur != null and rd(u32, pCur, VC_pgnoRoot) == @as(u32, @intCast(pOp.p2))) {
            sqlite3BtreeClearCursor(@ptrCast(rdPtr(pCur, VC_uc)));
            return openSetHints(pCur, pOp, rc);
        }
        // fall through to OpenRead logic
    }

    if (getExpired(p) == 1) {
        rc.* = SQLITE_ABORT_ROLLBACK;
        return .err;
    }

    var nField: c_int = 0;
    var pKeyInfo: ?*KeyInfo = null;
    var p2: u32 = @intCast(pOp.p2);
    const iDb = pOp.p3;
    const pDb = dbEnt(db, iDb);
    const pX = rdPtr(pDb, Db_pBt);
    var wrFlag: c_int = 0;
    if (op == OP_OpenWrite) {
        wrFlag = BTREE_WRCSR | (@as(c_int, pOp.p5) & BTREE_FORDELETE);
        const pSchema = rdPtr(pDb, Db_pSchema);
        if (rd(c_int, pSchema, Schema_file_format) < rdU8(p, Vdbe_minWriteFileFormat)) {
            wrU8(p, Vdbe_minWriteFileFormat, @intCast(rd(c_int, pSchema, Schema_file_format) & 0xff));
        }
        if ((pOp.p5 & OPFLAG_P2ISREG) != 0) {
            const pIn2 = memAt(aMem, @as(c_int, @intCast(p2)));
            _ = sqlite3VdbeMemIntegerify(pIn2);
            p2 = @intCast(pIn2.u.i);
        }
    }
    if (pOp.p4type == P4_KEYINFO) {
        pKeyInfo = pOp.p4.pKeyInfo;
        nField = rd(u16, pKeyInfo, KeyInfo_nAllField);
    } else if (pOp.p4type == P4_INT32) {
        nField = pOp.p4.i;
    }
    const pCur = allocateCursor(p, pOp.p1, nField, CURTYPE_BTREE);
    if (pCur == null) return .no_mem;
    wrU8(pCur, VC_iDb, @intCast(iDb & 0xff));
    wrU8(pCur, VC_nullRow, 1);
    vcSetBit(pCur, BIT_isOrdered, true);
    wr(u32, pCur, VC_pgnoRoot, p2);
    rc.* = sqlite3BtreeCursor(pX, p2, wrFlag, pKeyInfo, @ptrCast(rdPtr(pCur, VC_uc)));
    wrPtr(pCur, VC_pKeyInfo, pKeyInfo);
    wrU8(pCur, VC_isTable, @intFromBool(pOp.p4type != P4_KEYINFO));
    return openSetHints(pCur, pOp, rc);
}

fn openSetHints(pCur: ?*anyopaque, pOp: *Op, rc: *c_int) OpenResult {
    sqlite3BtreeCursorHintFlags(@ptrCast(rdPtr(pCur, VC_uc)), pOp.p5 & (OPFLAG_BULKCSR | OPFLAG_SEEKEQ));
    if (rc.* != 0) return .err;
    return .ok;
}

// ---- OP_OpenDup -----------------------------------------------------------
fn opOpenDup(p: ?*Vdbe, pOp: *Op, rc: *c_int) bool {
    const apCsr = apCsrOf(p);
    const pOrig = apCsr[@intCast(pOp.p2)];
    const pCx = allocateCursor(p, pOp.p1, rd(i16, pOrig, VC_nField), CURTYPE_BTREE);
    if (pCx == null) return true;
    wrU8(pCx, VC_nullRow, 1);
    vcSetBit(pCx, BIT_isEphemeral, true);
    wrPtr(pCx, VC_pKeyInfo, rdPtr(pOrig, VC_pKeyInfo));
    wrU8(pCx, VC_isTable, rdU8(pOrig, VC_isTable));
    wr(u32, pCx, VC_pgnoRoot, rd(u32, pOrig, VC_pgnoRoot));
    vcSetBit(pCx, BIT_isOrdered, vcBit(pOrig, BIT_isOrdered));
    wrPtr(pCx, VC_ub, rdPtr(pOrig, VC_ub)); // pBtx
    vcSetBit(pCx, BIT_noReuse, true);
    vcSetBit(pOrig, BIT_noReuse, true);
    rc.* = sqlite3BtreeCursor(@ptrCast(rdPtr(pCx, VC_ub)), rd(u32, pCx, VC_pgnoRoot), BTREE_WRCSR, @ptrCast(rdPtr(pCx, VC_pKeyInfo)), @ptrCast(rdPtr(pCx, VC_uc)));
    return false;
}

// ---- OP_OpenEphemeral / OpenAutoindex ------------------------------------
fn opOpenEphemeral(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, op: u8, aMem: [*]u8, rc: *c_int) OpenResult {
    _ = op;
    const vfsFlags: c_int = 0x00000002 | 0x00000004 | 0x00000010 | 0x00000008 | 0x00001000; // RW|CREATE|EXCL|DELETEONCLOSE|TRANSIENT_DB
    const apCsr = apCsrOf(p);
    if (pOp.p3 > 0) {
        const m = memAt(aMem, pOp.p3);
        m.n = 0;
        m.z = @ptrCast(@constCast(@as([*:0]const u8, "")));
    }
    var pCx = apCsr[@intCast(pOp.p1)];
    if (pCx != null and !vcBit(pCx, BIT_noReuse) and pOp.p2 <= rd(i16, pCx, VC_nField)) {
        wr(i64, pCx, VC_seqCount, 0);
        wr(u32, pCx, VC_cacheStatus, CACHE_STALE);
        rc.* = sqlite3BtreeClearTable(@ptrCast(rdPtr(pCx, VC_ub)), @intCast(rd(u32, pCx, VC_pgnoRoot)), null);
    } else {
        pCx = allocateCursor(p, pOp.p1, pOp.p2, CURTYPE_BTREE);
        if (pCx == null) return .no_mem;
        vcSetBit(pCx, BIT_isEphemeral, true);
        var pBtx: ?*Btree = null;
        rc.* = sqlite3BtreeOpen(rdPtr(db, sqlite3_pVfs), null, db, &pBtx, BTREE_OMIT_JOURNAL | BTREE_SINGLE | pOp.p5, vfsFlags);
        wrPtr(pCx, VC_ub, @ptrCast(pBtx));
        if (rc.* == SQLITE_OK) {
            rc.* = sqlite3BtreeBeginTrans(pBtx, 1, null);
            if (rc.* == SQLITE_OK) {
                const pKeyInfo = pOp.p4.pKeyInfo;
                wrPtr(pCx, VC_pKeyInfo, pKeyInfo);
                if (pKeyInfo != null) {
                    var pgno: u32 = 0;
                    rc.* = sqlite3BtreeCreateTable(pBtx, &pgno, BTREE_BLOBKEY | pOp.p5);
                    wr(u32, pCx, VC_pgnoRoot, pgno);
                    if (rc.* == SQLITE_OK) {
                        rc.* = sqlite3BtreeCursor(pBtx, pgno, BTREE_WRCSR, pKeyInfo, @ptrCast(rdPtr(pCx, VC_uc)));
                    }
                    wrU8(pCx, VC_isTable, 0);
                } else {
                    wr(u32, pCx, VC_pgnoRoot, SCHEMA_ROOT);
                    rc.* = sqlite3BtreeCursor(pBtx, SCHEMA_ROOT, BTREE_WRCSR, null, @ptrCast(rdPtr(pCx, VC_uc)));
                    wrU8(pCx, VC_isTable, 1);
                }
            }
            vcSetBit(pCx, BIT_isOrdered, pOp.p5 != BTREE_UNORDERED);
            if (rc.* != 0) {
                _ = sqlite3BtreeClose(pBtx);
                apCsr[@intCast(pOp.p1)] = null;
            }
        }
    }
    if (rc.* != 0) return .err;
    wrU8(pCx, VC_nullRow, 1);
    return .ok;
}

// ---- OP_SeekLT/LE/GE/GT ---------------------------------------------------
const SeekResult = enum { fall, jumped, err };

fn opSeek(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, op: u8, aMem: [*]u8, encoding: u8, pc: *usize, rc: *c_int) SeekResult {
    _ = db;
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    var oc: c_int = op;
    var eqOnly = false;
    var res: c_int = 0;
    wrU8(pC, VC_nullRow, 0);
    if (DEBUG) wrU8(pC, VC_seekOp, op);
    wrU8(pC, VC_deferredMoveto, 0);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    const pCur: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));

    if (rdU8(pC, VC_isTable) != 0) {
        const pIn3 = memAt(aMem, pOp.p3);
        const flags3 = pIn3.flags;
        if ((flags3 & (MEM_Int | MEM_Real | MEM_IntReal | MEM_Str)) == MEM_Str) {
            applyNumericAffinity(pIn3, false);
        }
        const iKey = sqlite3VdbeIntValue(pIn3);
        const newType = pIn3.flags;
        pIn3.flags = flags3;

        if ((newType & (MEM_Int | MEM_IntReal)) == 0) {
            if ((newType & MEM_Real) == 0) {
                if ((newType & MEM_Null) != 0 or oc >= OP_SeekGE) {
                    pc.* = @intCast(pOp.p2);
                    return .jumped;
                } else {
                    rc.* = sqlite3BtreeLast(pCur, &res);
                    if (rc.* != SQLITE_OK) return .err;
                    return seekNotFound(pOp, pc, res, eqOnly);
                }
            }
            const c = sqlite3IntFloatCompare(iKey, pIn3.u.r);
            if (c > 0) {
                if ((oc & 0x0001) == (OP_SeekGT & 0x0001)) oc -= 1;
            } else if (c < 0) {
                if ((oc & 0x0001) == (OP_SeekLT & 0x0001)) oc += 1;
            }
        }
        rc.* = sqlite3BtreeTableMoveto(pCur, iKey, 0, &res);
        wr(i64, pC, VC_movetoTarget, iKey);
        if (rc.* != SQLITE_OK) return .err;
    } else {
        var r: URBuf = .{};
        if (sqlite3BtreeCursorHasHint(pCur, BTREE_SEEK_EQ) != 0) {
            eqOnly = true;
        }
        const nField = pOp.p4.i;
        wrPtr(r.ptr(), UR_pKeyInfo, rdPtr(pC, VC_pKeyInfo));
        wr(u16, r.ptr(), UR_nField, @intCast(nField));
        const default_rc: i8 = if ((1 & (oc - OP_SeekLT)) != 0) -1 else 1;
        wr(i8, r.ptr(), UR_default_rc, default_rc);
        wrPtr(r.ptr(), UR_aMem, @ptrCast(memAt(aMem, pOp.p3)));
        wrU8(r.ptr(), UR_eqSeen, 0);
        rc.* = sqlite3BtreeIndexMoveto(pCur, r.ptr(), &res);
        if (rc.* != SQLITE_OK) return .err;
        if (eqOnly and rdU8(r.ptr(), UR_eqSeen) == 0) {
            return seekNotFound(pOp, pc, res, eqOnly);
        }
    }
    if (config.sqlite_test) g_search_count += 1;
    if (oc >= OP_SeekGE) {
        if (res < 0 or (res == 0 and oc == OP_SeekGT)) {
            res = 0;
            rc.* = sqlite3BtreeNext(pCur, 0);
            if (rc.* != SQLITE_OK) {
                if (rc.* == SQLITE_DONE) {
                    rc.* = SQLITE_OK;
                    res = 1;
                } else {
                    return .err;
                }
            }
        } else {
            res = 0;
        }
    } else {
        if (res > 0 or (res == 0 and oc == OP_SeekLT)) {
            res = 0;
            rc.* = sqlite3BtreePrevious(pCur, 0);
            if (rc.* != SQLITE_OK) {
                if (rc.* == SQLITE_DONE) {
                    rc.* = SQLITE_OK;
                    res = 1;
                } else {
                    return .err;
                }
            }
        } else {
            res = sqlite3BtreeEof(pCur);
        }
    }
    _ = encoding;
    return seekNotFound(pOp, pc, res, eqOnly);
}

fn seekNotFound(pOp: *Op, pc: *usize, res: c_int, eqOnly: bool) SeekResult {
    if (res != 0) {
        pc.* = @intCast(pOp.p2);
        return .jumped;
    } else if (eqOnly) {
        // skip the following OP_IdxLt/IdxGT: pc points at this op; advance 2
        pc.* += 2;
        return .jumped;
    }
    return .fall;
}

// ---- OP_SeekScan ----------------------------------------------------------
fn opSeekScan(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOp: [*]Op, aMem: [*]u8, pc: *usize, rc: *c_int) SeekResult {
    _ = db;
    const apCsr = apCsrOf(p);
    const here = pc.*;
    const seekOp = &aOp[here + 1];
    const pC = apCsr[@intCast(seekOp.p1)];
    const pCur: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    if (sqlite3BtreeCursorIsValidNN(pCur) == 0) return .fall;
    var nStep = pOp.p1;
    var r: URBuf = .{};
    wrPtr(r.ptr(), UR_pKeyInfo, rdPtr(pC, VC_pKeyInfo));
    wr(u16, r.ptr(), UR_nField, @intCast(seekOp.p4.i));
    wr(i8, r.ptr(), UR_default_rc, 0);
    wrPtr(r.ptr(), UR_aMem, @ptrCast(memAt(aMem, seekOp.p3)));
    var res: c_int = 0;
    while (true) {
        rc.* = sqlite3VdbeIdxKeyCompare(rdPtr(p, Vdbe_db), pC, r.ptr(), &res);
        if (rc.* != 0) return .err;
        if (res > 0 and pOp.p5 == 0) {
            // seekscan_search_fail: pOp++; goto jump_to_p2 -> SeekGE.p2
            pc.* = @intCast(seekOp.p2);
            return .jumped;
        }
        if (res >= 0) {
            // jump to This.P2
            pc.* = @intCast(pOp.p2);
            return .jumped;
        }
        if (nStep <= 0) {
            return .fall;
        }
        nStep -= 1;
        wr(u32, pC, VC_cacheStatus, CACHE_STALE);
        rc.* = sqlite3BtreeNext(pCur, 0);
        if (rc.* != 0) {
            if (rc.* == SQLITE_DONE) {
                rc.* = SQLITE_OK;
                pc.* = @intCast(seekOp.p2);
                return .jumped;
            } else {
                return .err;
            }
        }
    }
}
// ===========================================================================
// Opcode handlers, batch 3.
// ===========================================================================

const FoundResult = enum { fall, jump, no_mem, err };

// ---- OP_Found / NotFound / NoConflict / IfNoHope -------------------------
fn opFound(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, op: u8, aMem: [*]u8, rc: *c_int) FoundResult {
    if (config.sqlite_test) {
        if (op != OP_NoConflict) g_found_count += 1;
    }
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    if (DEBUG) wrU8(pC, VC_seekOp, op);
    const pCur: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    var r: URBuf = .{};
    wrPtr(r.ptr(), UR_aMem, @ptrCast(memAt(aMem, pOp.p3)));
    const nField: c_int = pOp.p4.i;
    wr(u16, r.ptr(), UR_nField, @intCast(nField));
    var seekRes: c_int = 0;
    if (nField > 0) {
        wrPtr(r.ptr(), UR_pKeyInfo, rdPtr(pC, VC_pKeyInfo));
        wr(i8, r.ptr(), UR_default_rc, 0);
        rc.* = sqlite3BtreeIndexMoveto(pCur, r.ptr(), &seekRes);
        wr(c_int, pC, VC_seekResult, seekRes);
    } else {
        const pRec = memAt(aMem, pOp.p3);
        rc.* = ExpandBlob(pRec);
        if (rc.* != 0) return .no_mem;
        const pIdxKey = sqlite3VdbeAllocUnpackedRecord(@ptrCast(rdPtr(pC, VC_pKeyInfo)));
        if (pIdxKey == null) return .no_mem;
        sqlite3VdbeRecordUnpack(pRec.n, pRec.z, pIdxKey);
        wr(i8, pIdxKey, UR_default_rc, 0);
        rc.* = sqlite3BtreeIndexMoveto(pCur, pIdxKey, &seekRes);
        wr(c_int, pC, VC_seekResult, seekRes);
        sqlite3DbFreeNN(db, pIdxKey);
    }
    if (rc.* != SQLITE_OK) return .err;
    const alreadyExists = (rd(c_int, pC, VC_seekResult) == 0);
    wrU8(pC, VC_nullRow, @intFromBool(!alreadyExists));
    wrU8(pC, VC_deferredMoveto, 0);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    if (op == OP_Found) {
        if (alreadyExists) return .jump;
    } else {
        if (!alreadyExists) return .jump;
        if (op == OP_NoConflict) {
            var ii: c_int = 0;
            while (ii < nField) : (ii += 1) {
                if ((memAt(aMem, pOp.p3 + ii).flags & MEM_Null) != 0) {
                    return .jump;
                }
            }
        }
        if (op == OP_IfNoHope) {
            wr(u16, pC, VC_seekHit, @intCast(pOp.p4.i));
        }
    }
    return .fall;
}

// ---- OP_SeekRowid / NotExists --------------------------------------------
const SeekRowidResult = enum { fall, jump, err };

fn opSeekRowid(p: ?*Vdbe, pOp: *Op, op: u8, aMem: [*]u8, encoding: u8, rc: *c_int) SeekRowidResult {
    const apCsr = apCsrOf(p);
    var iKey: u64 = undefined;
    var pIn3 = memAt(aMem, pOp.p3);
    if (op == OP_SeekRowid and (pIn3.flags & (MEM_Int | MEM_IntReal)) == 0) {
        var x = pIn3.*;
        applyAffinity(&x, SQLITE_AFF_NUMERIC, encoding);
        if ((x.flags & MEM_Int) == 0) return .jump;
        iKey = @bitCast(x.u.i);
    } else {
        pIn3 = memAt(aMem, pOp.p3);
        iKey = @bitCast(pIn3.u.i);
    }
    const pC = apCsr[@intCast(pOp.p1)];
    if (DEBUG and op == OP_SeekRowid) wrU8(pC, VC_seekOp, OP_SeekRowid);
    const pCrsr: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    var res: c_int = 0;
    rc.* = sqlite3BtreeTableMoveto(pCrsr, @bitCast(iKey), 0, &res);
    wr(i64, pC, VC_movetoTarget, @bitCast(iKey));
    wrU8(pC, VC_nullRow, 0);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    wrU8(pC, VC_deferredMoveto, 0);
    wr(c_int, pC, VC_seekResult, res);
    if (res != 0) {
        if (pOp.p2 == 0) {
            rc.* = SQLITE_CORRUPT;
        } else {
            if (rc.* != 0) return .err;
            return .jump;
        }
    }
    if (rc.* != 0) return .err;
    return .fall;
}

// ---- OP_NewRowid ----------------------------------------------------------
fn opNewRowid(p: ?*Vdbe, pOp: *Op, rc: *c_int) bool {
    var v: i64 = 0;
    var res: c_int = 0;
    const pOut = out2Prerelease(p, pOp);
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    const pCur: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));

    if (!vcBit(pC, BIT_useRandomRowid)) {
        rc.* = sqlite3BtreeLast(pCur, &res);
        if (rc.* != SQLITE_OK) return true;
        if (res != 0) {
            v = 1;
        } else {
            v = sqlite3BtreeIntegerKey(pCur);
            if (v >= MAX_ROWID) {
                vcSetBit(pC, BIT_useRandomRowid, true);
            } else {
                v += 1;
            }
        }
    }

    if (pOp.p3 != 0) {
        var pMem: *Mem = undefined;
        const pFrame0 = rdPtr(p, Vdbe_pFrame);
        if (pFrame0 != null) {
            var pFrame = pFrame0;
            while (rdPtr(pFrame, VdbeFrame_pParent) != null) pFrame = rdPtr(pFrame, VdbeFrame_pParent);
            const fAMem: [*]u8 = @ptrCast(rdPtr(pFrame, VdbeFrame_aMem).?);
            pMem = memAt(fAMem, pOp.p3);
        } else {
            const aMem: [*]u8 = @ptrCast(rdPtr(p, Vdbe_aMem).?);
            pMem = memAt(aMem, pOp.p3);
        }
        _ = sqlite3VdbeMemIntegerify(pMem);
        if (pMem.u.i == MAX_ROWID or vcBit(pC, BIT_useRandomRowid)) {
            rc.* = SQLITE_FULL;
            return true;
        }
        if (v < pMem.u.i + 1) v = pMem.u.i + 1;
        pMem.u.i = v;
    }
    if (vcBit(pC, BIT_useRandomRowid)) {
        var cnt: c_int = 0;
        while (true) {
            sqlite3_randomness(@sizeOf(i64), &v);
            v &= (MAX_ROWID >> 1);
            v += 1;
            rc.* = sqlite3BtreeTableMoveto(pCur, v, 0, &res);
            cnt += 1;
            if (!(rc.* == SQLITE_OK and res == 0 and cnt < 100)) break;
        }
        if (rc.* != 0) return true;
        if (res == 0) {
            rc.* = SQLITE_FULL;
            return true;
        }
    }
    wrU8(pC, VC_deferredMoveto, 0);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    pOut.u.i = v;
    return false;
}

// HAS_UPDATE_HOOK(DB): xPreUpdateCallback || xUpdateCallback
inline fn hasUpdateHook(db: ?*anyopaque) bool {
    return rdPtr(db, sqlite3_xPreUpdateCallback) != null or rdPtr(db, sqlite3_xUpdateCallback) != null;
}

// ---- OP_Insert ------------------------------------------------------------
fn opInsert(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, colCacheCtr: *u32, rc: *c_int) bool {
    const apCsr = apCsrOf(p);
    const pData = memAt(aMem, pOp.p2);
    const pC = apCsr[@intCast(pOp.p1)];
    sqlite3VdbeIncrWriteCounter(p, pC);
    const pKey = memAt(aMem, pOp.p3);
    var x: [sizeof_BtreePayload]u8 align(8) = std.mem.zeroes([sizeof_BtreePayload]u8);
    const xp: *anyopaque = @ptrCast(&x);
    wr(i64, xp, BP_nKey, pKey.u.i);

    var zDb: ?[*:0]const u8 = null;
    var pTab: ?*Table = null;
    if (pOp.p4type == P4_TABLE and hasUpdateHook(db)) {
        zDb = @ptrCast(rdPtr(dbEnt(db, rdU8(pC, VC_iDb)), Db_zDbSName));
        pTab = pOp.p4.pTab;
    }

    if (PREUPDATE_HOOK) {
        if (pTab != null) {
            if (rdPtr(db, sqlite3_xPreUpdateCallback) != null and (pOp.p5 & OPFLAG_ISUPDATE) == 0) {
                sqlite3VdbePreUpdateHook(p, pC, SQLITE_INSERT, zDb, pTab, pKey.u.i, pOp.p2, -1);
            }
            if (rdPtr(db, sqlite3_xUpdateCallback) == null or rdPtr(pTab, Table_aCol) == null) {
                pTab = null;
            }
        }
        if ((pOp.p5 & OPFLAG_ISNOOP) != 0) return false;
    }

    if ((pOp.p5 & OPFLAG_NCHANGE) != 0) {
        wr(c_int, p, Vdbe_nChange, rd(c_int, p, Vdbe_nChange) + 1);
        if ((pOp.p5 & OPFLAG_LASTROWID) != 0) wr(i64, db, sqlite3_lastRowid, pKey.u.i);
    }
    wrPtr(xp, BP_pData, @ptrCast(pData.z));
    wr(c_int, xp, BP_nData, pData.n);
    const seekResult: c_int = if ((pOp.p5 & OPFLAG_USESEEKRESULT) != 0) rd(c_int, pC, VC_seekResult) else 0;
    if ((pData.flags & MEM_Zero) != 0) {
        wr(c_int, xp, BP_nZero, pData.u.nZero);
    } else {
        wr(c_int, xp, BP_nZero, 0);
    }
    wrPtr(xp, BP_pKey, null);
    rc.* = sqlite3BtreeInsert(@ptrCast(rdPtr(pC, VC_uc)), xp, pOp.p5 & (OPFLAG_APPEND | OPFLAG_SAVEPOSITION | OPFLAG_PREFORMAT), seekResult);
    wrU8(pC, VC_deferredMoveto, 0);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    colCacheCtr.* +%= 1;

    if (rc.* != 0) return true;
    if (pTab != null) {
        const xUpd: UpdateCb = @ptrCast(rdPtr(db, sqlite3_xUpdateCallback));
        xUpd.?(rdPtr(db, sqlite3_pUpdateArg), if ((pOp.p5 & OPFLAG_ISUPDATE) != 0) SQLITE_UPDATE else SQLITE_INSERT, zDb, @ptrCast(rdPtr(pTab, Table_zName)), pKey.u.i);
    }
    return false;
}
const SQLITE_INSERT: c_int = 18;
const SQLITE_UPDATE: c_int = 23;
const SQLITE_DELETE: c_int = 9;

// ---- OP_Delete ------------------------------------------------------------
fn opDelete(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, colCacheCtr: *u32, rc: *c_int) bool {
    const apCsr = apCsrOf(p);
    const opflags = pOp.p2;
    const pC = apCsr[@intCast(pOp.p1)];
    sqlite3VdbeIncrWriteCounter(p, pC);

    var zDb: ?[*:0]const u8 = null;
    var pTab: ?*Table = null;
    if (pOp.p4type == P4_TABLE and hasUpdateHook(db)) {
        zDb = @ptrCast(rdPtr(dbEnt(db, rdU8(pC, VC_iDb)), Db_zDbSName));
        pTab = pOp.p4.pTab;
        if ((pOp.p5 & OPFLAG_SAVEPOSITION) != 0 and rdU8(pC, VC_isTable) != 0) {
            wr(i64, pC, VC_movetoTarget, sqlite3BtreeIntegerKey(@ptrCast(rdPtr(pC, VC_uc))));
        }
    }

    if (PREUPDATE_HOOK) {
        if (rdPtr(db, sqlite3_xPreUpdateCallback) != null and pTab != null) {
            sqlite3VdbePreUpdateHook(p, pC, if ((opflags & OPFLAG_ISUPDATE) != 0) SQLITE_UPDATE else SQLITE_DELETE, zDb, pTab, rd(i64, pC, VC_movetoTarget), pOp.p3, -1);
        }
        if ((opflags & OPFLAG_ISNOOP) != 0) return false;
    }

    rc.* = sqlite3BtreeDelete(@ptrCast(rdPtr(pC, VC_uc)), @intCast(pOp.p5 & 0xff));
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    colCacheCtr.* +%= 1;
    wr(c_int, pC, VC_seekResult, 0);
    if (rc.* != 0) return true;

    if ((opflags & OPFLAG_NCHANGE) != 0) {
        wr(c_int, p, Vdbe_nChange, rd(c_int, p, Vdbe_nChange) + 1);
        if (rdPtr(db, sqlite3_xUpdateCallback) != null and pTab != null) {
            const xUpd: UpdateCb = @ptrCast(rdPtr(db, sqlite3_xUpdateCallback));
            xUpd.?(rdPtr(db, sqlite3_pUpdateArg), SQLITE_DELETE, zDb, @ptrCast(rdPtr(pTab, Table_zName)), rd(i64, pC, VC_movetoTarget));
        }
    }
    _ = aMem;
    return false;
}

// ---- OP_RowData -----------------------------------------------------------
fn opRowData(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) ?ExitKind {
    _ = aMem;
    const pOut = out2Prerelease(p, pOp);
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    const pCrsr: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    const n = sqlite3BtreePayloadSize(pCrsr);
    if (n > @as(u32, @intCast(dbLimit(db, SQLITE_LIMIT_LENGTH)))) {
        return .too_big;
    }
    rc.* = sqlite3VdbeMemFromBtreeZeroOffset(pCrsr, n, pOut);
    if (rc.* != 0) return .abort_error;
    if (pOp.p3 == 0) {
        if (deephemeralize(pOut)) return .no_mem;
    }
    updateMaxBlobsize(pOut);
    return null;
}

// ---- OP_Rowid -------------------------------------------------------------
fn opRowid(p: ?*Vdbe, pOp: *Op, aMem: [*]u8, rc: *c_int) bool {
    _ = aMem;
    const pOut = out2Prerelease(p, pOp);
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    var v: i64 = undefined;
    if (rdU8(pC, VC_nullRow) != 0) {
        pOut.flags = MEM_Null;
        return false;
    } else if (rdU8(pC, VC_deferredMoveto) != 0) {
        v = rd(i64, pC, VC_movetoTarget);
    } else if (rdU8(pC, VC_eCurType) == CURTYPE_VTAB) {
        const pVCur = rdPtr(pC, VC_uc);
        const pVtab = rdPtr(pVCur, vcur_pVtab);
        const pModule = rdPtr(pVtab, vtab_pModule);
        const xRowid = modFn(xRowidFn, pModule, mod_xRowid);
        rc.* = xRowid(pVCur, &v);
        sqlite3VtabImportErrmsg(p, pVtab);
        if (rc.* != 0) return true;
    } else {
        rc.* = sqlite3VdbeCursorRestore(pC);
        if (rc.* != 0) return true;
        if (rdU8(pC, VC_nullRow) != 0) {
            pOut.flags = MEM_Null;
            return false;
        }
        v = sqlite3BtreeIntegerKey(@ptrCast(rdPtr(pC, VC_uc)));
    }
    pOut.u.i = v;
    return false;
}

// ---- OP_NullRow -----------------------------------------------------------
fn opNullRow(p: ?*Vdbe, pOp: *Op) bool {
    const apCsr = apCsrOf(p);
    var pC = apCsr[@intCast(pOp.p1)];
    if (pC == null) {
        pC = allocateCursor(p, pOp.p1, 1, CURTYPE_PSEUDO);
        if (pC == null) return true;
        wr(c_int, pC, VC_seekResult, 0);
        wrU8(pC, VC_isTable, 1);
        vcSetBit(pC, BIT_noReuse, true);
        wrPtr(pC, VC_uc, @ptrCast(sqlite3BtreeFakeValidCursor()));
    }
    wrU8(pC, VC_nullRow, 1);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    if (rdU8(pC, VC_eCurType) == CURTYPE_BTREE) {
        sqlite3BtreeClearCursor(@ptrCast(rdPtr(pC, VC_uc)));
    }
    if (DEBUG and rdU8(pC, VC_seekOp) == 0) wrU8(pC, VC_seekOp, OP_NullRow);
    return false;
}

const JumpFallErr = enum { fall, jump, err };

// ---- OP_SeekEnd / Last ----------------------------------------------------
fn opLast(p: ?*Vdbe, pOp: *Op, op: u8, rc: *c_int) JumpFallErr {
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    const pCrsr: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    var res: c_int = 0;
    if (DEBUG) wrU8(pC, VC_seekOp, op);
    if (op == OP_SeekEnd) {
        wr(c_int, pC, VC_seekResult, -1);
        if (sqlite3BtreeCursorIsValidNN(pCrsr) != 0) {
            return .fall;
        }
    }
    rc.* = sqlite3BtreeLast(pCrsr, &res);
    wrU8(pC, VC_nullRow, @intCast(res & 0xff));
    wrU8(pC, VC_deferredMoveto, 0);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    if (rc.* != 0) return .err;
    if (pOp.p2 > 0 and res != 0) return .jump;
    return .fall;
}

// ---- OP_IfSizeBetween -----------------------------------------------------
fn opIfSizeBetween(p: ?*Vdbe, pOp: *Op, rc: *c_int) JumpFallErr {
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    const pCrsr: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    var res: c_int = 0;
    var sz: i64 = undefined;
    rc.* = sqlite3BtreeFirst(pCrsr, &res);
    if (rc.* != 0) return .err;
    if (res != 0) {
        sz = -1;
    } else {
        sz = sqlite3BtreeRowCountEst(pCrsr);
        sz = sqlite3LogEst(@intCast(sz));
    }
    const hit = sz >= pOp.p3 and sz <= pOp.p4.i;
    if (hit) return .jump;
    return .fall;
}

// ---- OP_Rewind ------------------------------------------------------------
fn opRewind(p: ?*Vdbe, pOp: *Op, op: u8, rc: *c_int) JumpFallErr {
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    var res: c_int = 1;
    if (DEBUG) wrU8(pC, VC_seekOp, OP_Rewind);
    if (isSorter(pC)) {
        rc.* = sqlite3VdbeSorterRewind(pC, &res);
    } else {
        const pCrsr: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
        rc.* = sqlite3BtreeFirst(pCrsr, &res);
        wrU8(pC, VC_deferredMoveto, 0);
        wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    }
    _ = op;
    if (rc.* != 0) return .err;
    wrU8(pC, VC_nullRow, @intCast(res & 0xff));
    if (pOp.p2 > 0 and res != 0) return .jump;
    return .fall;
}

// ---- OP_IdxInsert ---------------------------------------------------------
fn opIdxInsert(p: ?*Vdbe, pOp: *Op, aMem: [*]u8, rc: *c_int) bool {
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    sqlite3VdbeIncrWriteCounter(p, pC);
    const pIn2 = memAt(aMem, pOp.p2);
    if ((pOp.p5 & OPFLAG_NCHANGE) != 0) wr(c_int, p, Vdbe_nChange, rd(c_int, p, Vdbe_nChange) + 1);
    rc.* = ExpandBlob(pIn2);
    if (rc.* != 0) return true;
    var x: [sizeof_BtreePayload]u8 align(8) = std.mem.zeroes([sizeof_BtreePayload]u8);
    const xp: *anyopaque = @ptrCast(&x);
    wr(i64, xp, BP_nKey, pIn2.n);
    wrPtr(xp, BP_pKey, @ptrCast(pIn2.z));
    wrPtr(xp, BP_aMem, @ptrCast(memAt(aMem, pOp.p3)));
    wr(u16, xp, BP_nMem, @intCast(pOp.p4.i));
    rc.* = sqlite3BtreeInsert(@ptrCast(rdPtr(pC, VC_uc)), xp, pOp.p5 & (OPFLAG_APPEND | OPFLAG_SAVEPOSITION | OPFLAG_PREFORMAT), if ((pOp.p5 & OPFLAG_USESEEKRESULT) != 0) rd(c_int, pC, VC_seekResult) else 0);
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    return rc.* != 0;
}

// ---- OP_IdxDelete ---------------------------------------------------------
const OkErr = enum { ok, err };
fn opIdxDelete(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) OkErr {
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    sqlite3VdbeIncrWriteCounter(p, pC);
    const pCrsr: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    var r: URBuf = .{};
    wrPtr(r.ptr(), UR_pKeyInfo, rdPtr(pC, VC_pKeyInfo));
    wr(u16, r.ptr(), UR_nField, @intCast(pOp.p5));
    wr(i8, r.ptr(), UR_default_rc, 0);
    wrPtr(r.ptr(), UR_aMem, @ptrCast(memAt(aMem, pOp.p2)));
    var res: c_int = 0;
    rc.* = sqlite3BtreeIndexMoveto(pCrsr, r.ptr(), &res);
    if (rc.* != 0) return .err;
    if (res != 0) {
        rc.* = sqlite3VdbeFindIndexKey(pCrsr, pOp.p4.pIdx, r.ptr(), &res, 0);
        if (rc.* != SQLITE_OK) return .err;
        if (res != 0) {
            if (sqlite3WritableSchema(db) == 0) {
                rc.* = sqlite3ReportError(SQLITE_CORRUPT_INDEX, 0, "index corruption");
                return .err;
            }
            wr(u32, pC, VC_cacheStatus, CACHE_STALE);
            wr(c_int, pC, VC_seekResult, 0);
            return .ok;
        }
    }
    if (pOp.p3 != 0 and vdbeIndexKeyCompare(pCrsr, memAt(aMem, pOp.p3), rc)) {
        if (rc.* != 0) return .err;
        sqlite3VdbeMemSetNull(memAt(aMem, pOp.p3));
        return .ok;
    }
    rc.* = sqlite3BtreeDelete(pCrsr, BTREE_AUXDELETE);
    if (rc.* != 0) return .err;
    wr(u32, pC, VC_cacheStatus, CACHE_STALE);
    wr(c_int, pC, VC_seekResult, 0);
    return .ok;
}

// ---- OP_DeferredSeek / IdxRowid ------------------------------------------
fn opIdxRowid(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) bool {
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    rc.* = sqlite3VdbeCursorRestore(pC);
    if (rc.* != SQLITE_OK) return true;
    if (rdU8(pC, VC_nullRow) == 0) {
        var rowid: i64 = 0;
        rc.* = sqlite3VdbeIdxRowid(db, @ptrCast(rdPtr(pC, VC_uc)), &rowid);
        if (rc.* != SQLITE_OK) return true;
        if (pOp.opcode == OP_DeferredSeek) {
            const pTabCur = apCsr[@intCast(pOp.p3)];
            wrU8(pTabCur, VC_nullRow, 0);
            wr(i64, pTabCur, VC_movetoTarget, rowid);
            wrU8(pTabCur, VC_deferredMoveto, 1);
            wr(u32, pTabCur, VC_cacheStatus, CACHE_STALE);
            wrPtr(pTabCur, VC_ub, @ptrCast(pOp.p4.ai));
            wrPtr(pTabCur, VC_pAltCursor, pC);
        } else {
            const pOut = out2Prerelease(p, pOp);
            pOut.u.i = rowid;
        }
    } else {
        sqlite3VdbeMemSetNull(memAt(aMem, pOp.p2));
    }
    return false;
}

// ---- OP_IdxLE/IdxGT/IdxLT/IdxGE ------------------------------------------
fn opIdxCompare(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, op: u8, aMem: [*]u8, rc: *c_int) JumpFallErr {
    const apCsr = apCsrOf(p);
    const pC = apCsr[@intCast(pOp.p1)];
    var r: URBuf = .{};
    wrPtr(r.ptr(), UR_pKeyInfo, rdPtr(pC, VC_pKeyInfo));
    wr(u16, r.ptr(), UR_nField, @intCast(pOp.p4.i));
    if (op < OP_IdxLT) {
        wr(i8, r.ptr(), UR_default_rc, -1);
    } else {
        wr(i8, r.ptr(), UR_default_rc, 0);
    }
    wrPtr(r.ptr(), UR_aMem, @ptrCast(memAt(aMem, pOp.p3)));

    const pCur: ?*BtCursor = @ptrCast(rdPtr(pC, VC_uc));
    const nCellKey = sqlite3BtreePayloadSize(pCur);
    if (nCellKey == 0 or nCellKey > 0x7fffffff) {
        rc.* = SQLITE_CORRUPT;
        return .err;
    }
    var m: Mem = undefined;
    sqlite3VdbeMemInit(&m, db, 0);
    rc.* = sqlite3VdbeMemFromBtreeZeroOffset(pCur, nCellKey, &m);
    if (rc.* != 0) return .err;
    var res = sqlite3VdbeRecordCompareWithSkip(m.n, m.z, r.ptr(), 0);
    sqlite3VdbeMemReleaseMalloc(&m);

    if ((op & 1) == (OP_IdxLT & 1)) {
        res = -res;
    } else {
        res += 1;
    }
    if (res > 0) return .jump;
    return .fall;
}

// ---- OP_Destroy -----------------------------------------------------------
fn opDestroy(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, resetSchemaOnFault: *u8, rc: *c_int) bool {
    sqlite3VdbeIncrWriteCounter(p, null);
    const pOut = out2Prerelease(p, pOp);
    pOut.flags = MEM_Null;
    if (rd(c_int, db, sqlite3_nVdbeRead) > rd(c_int, db, sqlite3_nVDestroy) + 1) {
        rc.* = SQLITE_LOCKED;
        wrU8(p, Vdbe_errorAction, OE_Abort);
        return true;
    } else {
        const iDb = pOp.p3;
        var iMoved: c_int = 0;
        rc.* = sqlite3BtreeDropTable(rdPtr(dbEnt(db, iDb), Db_pBt), pOp.p1, &iMoved);
        pOut.flags = MEM_Int;
        pOut.u.i = iMoved;
        if (rc.* != 0) return true;
        if (iMoved != 0) {
            sqlite3RootPageMoved(db, iDb, iMoved, pOp.p1);
            resetSchemaOnFault.* = @intCast(iDb + 1);
        }
    }
    return false;
}

// ---- OP_SqlExec -----------------------------------------------------------
fn opSqlExec(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, rc: *c_int) ?ExitKind {
    sqlite3VdbeIncrWriteCounter(p, null);
    wr(c_int, db, sqlite3_nSqlExec, rd(c_int, db, sqlite3_nSqlExec) + 1);
    var zErr: ?[*:0]u8 = null;
    const xAuthSaved = rdPtr(db, sqlite3_xAuth);
    const mTrace = rdU8(db, sqlite3_mTrace);
    const savedAnalysisLimit = rd(c_int, db, sqlite3_nAnalysisLimit);
    if ((pOp.p1 & 0x0001) != 0) {
        wrPtr(db, sqlite3_xAuth, null);
        wrU8(db, sqlite3_mTrace, 0);
    }
    if ((pOp.p1 & 0x0002) != 0) {
        wr(c_int, db, sqlite3_nAnalysisLimit, pOp.p2);
    }
    rc.* = sqlite3_exec(db, pOp.p4.z, null, null, &zErr);
    wr(c_int, db, sqlite3_nSqlExec, rd(c_int, db, sqlite3_nSqlExec) - 1);
    wrPtr(db, sqlite3_xAuth, xAuthSaved);
    wrU8(db, sqlite3_mTrace, mTrace);
    wr(c_int, db, sqlite3_nAnalysisLimit, savedAnalysisLimit);
    if (zErr != null or rc.* != 0) {
        sqlite3VdbeError(p, "%s", zErr orelse @as([*:0]const u8, ""));
        sqlite3_free(zErr);
        if (rc.* == SQLITE_NOMEM) return .no_mem;
        return .abort_error;
    }
    return null;
}

// ---- OP_ParseSchema -------------------------------------------------------
fn opParseSchema(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, rc: *c_int) ?ExitKind {
    const iDb = pOp.p1;
    if (pOp.p4.z == null) {
        sqlite3SchemaClear(rdPtr(dbEnt(db, iDb), Db_pSchema));
        wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) & ~DBFLAG_SchemaKnownOk);
        rc.* = sqlite3InitOne(db, iDb, @ptrCast(fp(?[*:0]u8, p, Vdbe_zErrMsg)), @intCast(pOp.p5));
        wr(u32, db, sqlite3_mDbFlags, rd(u32, db, sqlite3_mDbFlags) | DBFLAG_SchemaChange);
        setExpired(p, 0);
    } else {
        var initData: [sizeof_InitData]u8 align(8) = std.mem.zeroes([sizeof_InitData]u8);
        const idp: *anyopaque = @ptrCast(&initData);
        wrPtr(idp, ID_db, db);
        wr(c_int, idp, ID_iDb, iDb);
        wrPtr(idp, ID_pzErrMsg, @ptrCast(fp(?[*:0]u8, p, Vdbe_zErrMsg)));
        wr(u32, idp, ID_mInitFlags, 0);
        wr(u32, idp, ID_mxPage, sqlite3BtreeLastPage(rdPtr(dbEnt(db, iDb), Db_pBt)));
        const zSql = sqlite3MPrintf(db, "SELECT*FROM\"%w\".%s WHERE %s ORDER BY rowid", rdPtr(dbEnt(db, iDb), Db_zDbSName), LEGACY_SCHEMA_TABLE, pOp.p4.z);
        if (zSql == null) {
            rc.* = SQLITE_NOMEM;
        } else {
            wrU8(db, sqlite3_init_busy, 1);
            wr(c_int, idp, ID_rc, SQLITE_OK);
            wr(u32, idp, ID_nInitRow, 0);
            rc.* = sqlite3_exec(db, zSql, @ptrCast(&sqlite3InitCallback), idp, null);
            if (rc.* == SQLITE_OK) rc.* = rd(c_int, idp, ID_rc);
            if (rc.* == SQLITE_OK and rd(u32, idp, ID_nInitRow) == 0) {
                rc.* = SQLITE_CORRUPT;
            }
            sqlite3DbFreeNN(db, zSql);
            wrU8(db, sqlite3_init_busy, 0);
        }
    }
    if (rc.* != 0) {
        sqlite3ResetAllSchemasOfConnection(db);
        if (rc.* == SQLITE_NOMEM) return .no_mem;
        return .abort_error;
    }
    return null;
}

// ---- OP_IntegrityCk -------------------------------------------------------
fn opIntegrityCk(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, encoding: u8, rc: *c_int) bool {
    _ = p;
    const nRoot = pOp.p2;
    const aRoot: [*]u32 = pOp.p4.ai.?;
    const pnErr = memAt(aMem, pOp.p1);
    const pIn1 = memAt(aMem, pOp.p1 + 1);
    var nErr: c_int = 0;
    var z: ?[*:0]u8 = null;
    rc.* = sqlite3BtreeIntegrityCheck(db, rdPtr(dbEnt(db, pOp.p5), Db_pBt), aRoot + 1, memAt(aMem, pOp.p3), nRoot, @as(c_int, @intCast(pnErr.u.i)) + 1, &nErr, &z);
    sqlite3VdbeMemSetNull(pIn1);
    if (nErr == 0) {
        // z==0
    } else if (rc.* != 0) {
        sqlite3_free(z);
        return true;
    } else {
        pnErr.u.i -= nErr - 1;
        _ = sqlite3VdbeMemSetStr(pIn1, @ptrCast(z), -1, SQLITE_UTF8, @ptrCast(&sqlite3_free));
    }
    updateMaxBlobsize(pIn1);
    _ = sqlite3VdbeChangeEncoding(pIn1, encoding);
    return false;
}
// ===========================================================================
// Opcode handlers, batch 4: Program / aggregates / vtab / function / init.
// ===========================================================================

// SQLITE_ENABLE_PREUPDATE_HOOK is ON in both this project's builds.
const PREUPDATE_HOOK = true;

// ---- OP_Program -----------------------------------------------------------
// Returns the new pc (usize) to land the loop on, or null when an exit was set.
fn opProgram(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOpRef: *[*]Op, aMemRef: *[*]u8, pc: usize, rc: *c_int, exitKind: *ExitKind, done: *bool) ?usize {
    _ = rc;
    const pProgram = pOp.p4.pProgram;
    const pRt = memAt(aMemRef.*, pOp.p3);

    if (pOp.p5 != 0) {
        const t = rdPtr(pProgram, SubProgram_token);
        var pFrame = rdPtr(p, Vdbe_pFrame);
        while (pFrame != null and rdPtr(pFrame, VdbeFrame_token) != t) pFrame = rdPtr(pFrame, VdbeFrame_pParent);
        if (pFrame != null) return pc + 1; // break (no-op recursion guard)
    }

    if (rd(c_int, p, Vdbe_nFrame) >= dbLimit(db, SQLITE_LIMIT_TRIGGER_DEPTH)) {
        sqlite3VdbeError(p, "triggers nested too deep");
        exitKind.* = .abort_error;
        done.* = true;
        return null;
    }

    var pFrame: ?*anyopaque = undefined;
    const pgmNMem = rd(c_int, pProgram, SubProgram_nMem);
    const pgmNCsr = rd(c_int, pProgram, SubProgram_nCsr);
    const pgmNOp = rd(c_int, pProgram, SubProgram_nOp);
    if ((pRt.flags & MEM_Blob) == 0) {
        var nMem = pgmNMem + pgmNCsr;
        if (pgmNCsr == 0) nMem += 1;
        const r8frame = (sizeof_VdbeFrame + 7) & ~@as(usize, 7);
        const nByte: i64 = @as(i64, @intCast(r8frame)) + @as(i64, nMem) * @as(i64, @intCast(sizeof_Mem)) + @as(i64, pgmNCsr) * @sizeOf(usize) + @divTrunc(7 + @as(i64, pgmNOp), 8);
        pFrame = sqlite3DbMallocZero(db, @intCast(nByte));
        if (pFrame == null) {
            exitKind.* = .no_mem;
            done.* = true;
            return null;
        }
        sqlite3VdbeMemRelease(pRt);
        pRt.flags = MEM_Blob | MEM_Dyn;
        pRt.z = @ptrCast(pFrame);
        pRt.n = @intCast(nByte);
        pRt.xDel = sqlite3VdbeFrameMemDel;

        wrPtr(pFrame, VdbeFrame_v, p);
        wr(c_int, pFrame, VdbeFrame_nChildMem, nMem);
        wr(c_int, pFrame, VdbeFrame_nChildCsr, pgmNCsr);
        wr(c_int, pFrame, VdbeFrame_pc, @intCast(pc));
        wrPtr(pFrame, VdbeFrame_aMem, @ptrCast(rdPtr(p, Vdbe_aMem)));
        wr(c_int, pFrame, VdbeFrame_nMem, rd(c_int, p, Vdbe_nMem));
        wrPtr(pFrame, VdbeFrame_apCsr, rdPtr(p, Vdbe_apCsr));
        wr(c_int, pFrame, VdbeFrame_nCursor, rd(c_int, p, Vdbe_nCursor));
        wrPtr(pFrame, VdbeFrame_aOp, rdPtr(p, Vdbe_aOp));
        wr(c_int, pFrame, VdbeFrame_nOp, rd(c_int, p, Vdbe_nOp));
        wrPtr(pFrame, VdbeFrame_token, rdPtr(pProgram, SubProgram_token));
        if (DEBUG) wr(u32, pFrame, VdbeFrame_iFrameMagic, SQLITE_FRAME_MAGIC);

        const fm = VdbeFrameMem(pFrame);
        var im: c_int = 0;
        while (im < nMem) : (im += 1) {
            const m = memAt(fm, im);
            m.flags = MEM_Undefined;
            m.db = db;
        }
    } else {
        pFrame = @ptrCast(pRt.z);
    }

    wr(c_int, p, Vdbe_nFrame, rd(c_int, p, Vdbe_nFrame) + 1);
    wrPtr(pFrame, VdbeFrame_pParent, rdPtr(p, Vdbe_pFrame));
    wr(i64, pFrame, VdbeFrame_lastRowid, rd(i64, db, sqlite3_lastRowid));
    wr(i64, pFrame, VdbeFrame_nChange, rd(c_int, p, Vdbe_nChange));
    wr(i64, pFrame, VdbeFrame_nDbChange, rd(c_int, db, sqlite3_nChange));
    wrPtr(pFrame, VdbeFrame_pAuxData, rdPtr(p, Vdbe_pAuxData));
    wrPtr(p, Vdbe_pAuxData, null);
    wr(c_int, p, Vdbe_nChange, 0);
    wrPtr(p, Vdbe_pFrame, pFrame);

    const newAMem = VdbeFrameMem(pFrame);
    aMemRef.* = newAMem;
    wrPtr(p, Vdbe_aMem, @ptrCast(newAMem));
    wr(c_int, p, Vdbe_nMem, rd(c_int, pFrame, VdbeFrame_nChildMem));
    const nCsr = rd(c_int, pFrame, VdbeFrame_nChildCsr);
    wr(c_int, p, Vdbe_nCursor, @intCast(@as(u16, @intCast(nCsr))));
    // p->apCsr = (VdbeCursor**)&aMem[p->nMem]
    const apCsrNew: [*]u8 = newAMem + @as(usize, @intCast(rd(c_int, p, Vdbe_nMem))) * sizeof_Mem;
    wrPtr(p, Vdbe_apCsr, @ptrCast(apCsrNew));
    // pFrame->aOnce = (u8*)&apCsr[nCsr]
    const aOnce: [*]u8 = apCsrNew + @as(usize, @intCast(pgmNCsr)) * @sizeOf(usize);
    wrPtr(pFrame, VdbeFrame_aOnce, @ptrCast(aOnce));
    @memset(aOnce[0..@intCast(@divTrunc(pgmNOp + 7, 8))], 0);
    wrPtr(p, Vdbe_aOp, rdPtr(pProgram, SubProgram_aOp));
    aOpRef.* = @ptrCast(@alignCast(rdPtr(p, Vdbe_aOp).?));
    wr(c_int, p, Vdbe_nOp, pgmNOp);

    // pOp = &aOp[-1]; goto check_for_interrupt -> pc = 0 with interrupt check.
    // We return pc=0; the driver's OP_Program path treats null/value: here
    // we cannot do the interrupt check inline, but upstream's check happens
    // before the next opcode; returning 0 lands on the first sub-op.
    return 0;
}

// ---- OP_AggInverse / AggStep (init) --------------------------------------
fn opAggStep0(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOp: [*]Op, pc: usize, encoding: u8, rc: *c_int) bool {
    _ = rc;
    const n = pOp.p5;
    // SZ_CONTEXT(n) = offsetof(argv) + n*sizeof(ptr); ROUND8P keeps it 8-aligned
    const szCtx: u64 = @intCast(Ctx_argv + @as(usize, n) * @sizeOf(usize));
    const nAlloc = (szCtx + 7) & ~@as(u64, 7);
    const pCtx = sqlite3DbMallocRawNN(db, nAlloc + sizeof_Mem);
    if (pCtx == null) return true;
    const pOut: *Mem = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pCtx.?)) + nAlloc));
    wrPtr(pCtx, Ctx_pOut, @ptrCast(pOut));
    sqlite3VdbeMemInit(pOut, db, MEM_Null);
    wrPtr(pCtx, Ctx_pMem, null);
    wrPtr(pCtx, Ctx_pFunc, pOp.p4.pFunc);
    wr(c_int, pCtx, Ctx_iOp, @intCast(pc));
    wrPtr(pCtx, Ctx_pVdbe, p);
    wrU8(pCtx, Ctx_skipFlag, 0);
    wr(c_int, pCtx, Ctx_isError, 0);
    wrU8(pCtx, Ctx_enc, encoding);
    wr(u16, pCtx, Ctx_argc, @intCast(n));
    pOp.p4type = P4_FUNCCTX;
    pOp.p4.pCtx = pCtx;
    _ = aOp;
    return false;
}

// ---- OP_AggStep1 ----------------------------------------------------------
fn opAggStep1(p: ?*Vdbe, pOp: *Op, aOp: [*]Op, aMem: [*]u8, pc: usize, rc: *c_int) bool {
    const pCtx = pOp.p4.pCtx;
    const pMem = memAt(aMem, pOp.p3);
    if (rdPtr(pCtx, Ctx_pMem) != @as(?*anyopaque, @ptrCast(pMem))) {
        wrPtr(pCtx, Ctx_pMem, @ptrCast(pMem));
        const argc = rd(u16, pCtx, Ctx_argc);
        var i: c_int = @as(c_int, argc) - 1;
        const argvBase: [*]?*Mem = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pCtx.?)) + Ctx_argv));
        while (i >= 0) : (i -= 1) {
            argvBase[@intCast(i)] = memAt(aMem, pOp.p2 + i);
        }
    }
    pMem.n += 1;
    const pFunc = rdPtr(pCtx, Ctx_pFunc);
    const argc = rd(u16, pCtx, Ctx_argc);
    const argvBase: [*]?*Mem = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pCtx.?)) + Ctx_argv));
    if (pOp.p1 != 0) {
        const xInv: SFunc = @ptrCast(rdPtr(pFunc, FuncDef_xInverse).?);
        xInv(@ptrCast(pCtx), argc, argvBase);
    } else {
        const xStep: SFunc = @ptrCast(rdPtr(pFunc, FuncDef_xSFunc).?);
        xStep(@ptrCast(pCtx), argc, argvBase);
    }
    if (rd(c_int, pCtx, Ctx_isError) != 0) {
        if (rd(c_int, pCtx, Ctx_isError) > 0) {
            const pOut = rdPtr(pCtx, Ctx_pOut);
            sqlite3VdbeError(p, "%s", sqlite3_value_text(@ptrCast(@alignCast(pOut))) orelse @as([*:0]const u8, ""));
            rc.* = rd(c_int, pCtx, Ctx_isError);
        }
        if (rdU8(pCtx, Ctx_skipFlag) != 0) {
            const ii = aOp[pc - 1].p1;
            if (ii != 0) sqlite3VdbeMemSetInt64(memAt(aMem, ii), 1);
            wrU8(pCtx, Ctx_skipFlag, 0);
        }
        const pOut: *Mem = @ptrCast(@alignCast(rdPtr(pCtx, Ctx_pOut).?));
        sqlite3VdbeMemRelease(pOut);
        pOut.flags = MEM_Null;
        wr(c_int, pCtx, Ctx_isError, 0);
        if (rc.* != 0) return true;
    }
    return false;
}

// ---- OP_AggFinal / AggValue ----------------------------------------------
fn opAggFinal(p: ?*Vdbe, pOp: *Op, op: u8, aMem: [*]u8, encoding: u8, rc: *c_int) bool {
    var pMem = memAt(aMem, pOp.p1);
    if (op == OP_AggValue and pOp.p3 != 0) {
        rc.* = sqlite3VdbeMemAggValue(pMem, memAt(aMem, pOp.p3), pOp.p4.pFunc);
        pMem = memAt(aMem, pOp.p3);
    } else {
        rc.* = sqlite3VdbeMemFinalize(pMem, pOp.p4.pFunc);
    }
    if (rc.* != 0) {
        sqlite3VdbeError(p, "%s", sqlite3_value_text(pMem) orelse @as([*:0]const u8, ""));
        return true;
    }
    _ = sqlite3VdbeChangeEncoding(pMem, encoding);
    updateMaxBlobsize(pMem);
    return false;
}

// ---- OP_Checkpoint --------------------------------------------------------
fn opCheckpoint(db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) bool {
    var aRes = [_]c_int{ 0, -1, -1 };
    rc.* = sqlite3Checkpoint(db, pOp.p1, pOp.p2, &aRes[1], &aRes[2]);
    if (rc.* != 0) {
        if (rc.* != SQLITE_BUSY) return true;
        rc.* = SQLITE_OK;
        aRes[0] = 1;
    }
    var i: c_int = 0;
    while (i < 3) : (i += 1) {
        sqlite3VdbeMemSetInt64(memAt(aMem, pOp.p3 + i), aRes[@intCast(i)]);
    }
    return false;
}

// ---- OP_JournalMode -------------------------------------------------------
fn opJournalMode(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, encoding: u8, rc: *c_int) bool {
    const pBt = rdPtr(dbEnt(db, pOp.p1), Db_pBt);
    const pPager = sqlite3BtreePager(pBt);
    var eNew = pOp.p3;
    const eOld = sqlite3PagerGetJournalMode(pPager);
    const pOut = out2Prerelease(p, pOp);
    if (eNew == PAGER_JOURNALMODE_QUERY) eNew = eOld;
    if (sqlite3PagerOkToChangeJournalMode(pPager) == 0) eNew = eOld;

    const zFilename = sqlite3PagerFilename(pPager, 1);
    if (eNew == PAGER_JOURNALMODE_WAL and (sqlite3Strlen30(zFilename) == 0 or sqlite3PagerWalSupported(pPager) == 0)) {
        eNew = eOld;
    }
    if (eNew != eOld and (eOld == PAGER_JOURNALMODE_WAL or eNew == PAGER_JOURNALMODE_WAL)) {
        if (rdU8(db, sqlite3_autoCommit) == 0 or rd(c_int, db, sqlite3_nVdbeRead) > 1) {
            rc.* = SQLITE_ERROR;
            sqlite3VdbeError(p, "cannot change %s wal mode from within a transaction", if (eNew == PAGER_JOURNALMODE_WAL) @as([*:0]const u8, "into") else @as([*:0]const u8, "out of"));
            return true;
        } else {
            if (eOld == PAGER_JOURNALMODE_WAL) {
                rc.* = sqlite3PagerCloseWal(pPager, db);
                if (rc.* == SQLITE_OK) {
                    _ = sqlite3PagerSetJournalMode(pPager, eNew);
                }
            } else if (eOld == PAGER_JOURNALMODE_MEMORY) {
                _ = sqlite3PagerSetJournalMode(pPager, PAGER_JOURNALMODE_OFF);
            }
            if (rc.* == SQLITE_OK) {
                rc.* = sqlite3BtreeSetVersion(pBt, if (eNew == PAGER_JOURNALMODE_WAL) 2 else 1);
            }
        }
    }
    if (rc.* != 0) eNew = eOld;
    eNew = sqlite3PagerSetJournalMode(pPager, eNew);
    pOut.flags = MEM_Str | MEM_Static | MEM_Term;
    pOut.z = @ptrCast(@constCast(sqlite3JournalModename(eNew)));
    pOut.n = sqlite3Strlen30(@ptrCast(pOut.z));
    pOut.enc = SQLITE_UTF8;
    _ = sqlite3VdbeChangeEncoding(pOut, encoding);
    return rc.* != 0;
}

// ---- OP_VCreate -----------------------------------------------------------
fn opVCreate(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) bool {
    var sMem: Mem = std.mem.zeroes(Mem);
    sMem.db = db;
    rc.* = sqlite3VdbeMemCopy(&sMem, memAt(aMem, pOp.p2));
    const zTab = sqlite3_value_text(&sMem);
    if (zTab != null) {
        rc.* = sqlite3VtabCallCreate(db, pOp.p1, zTab.?, @ptrCast(fp(?[*:0]u8, p, Vdbe_zErrMsg)));
    }
    sqlite3VdbeMemRelease(&sMem);
    return rc.* != 0;
}

// ---- OP_VOpen -------------------------------------------------------------
const VOpenResult = enum { ok, no_mem, err };
fn opVOpen(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, rc: *c_int) VOpenResult {
    _ = db;
    const apCsr = apCsrOf(p);
    var pCur = apCsr[@intCast(pOp.p1)];
    const pVTab = pOp.p4.pVtab;
    if (pCur != null and rdU8(pCur, VC_eCurType) == CURTYPE_VTAB) {
        // already open if same vtab
        const existing = rdPtr(rdPtr(pCur, VC_uc), vcur_pVtab);
        if (existing == rdPtr(pVTab, VTable_pVtab)) {
            return .ok;
        }
    }
    const pVtab = rdPtr(pVTab, VTable_pVtab);
    if (pVtab == null) {
        rc.* = SQLITE_LOCKED;
        return .err;
    }
    const pModule = rdPtr(pVtab, vtab_pModule);
    var pVCur: ?*sqlite3_vtab_cursor = null;
    const xOpen = modFn(xOpenFn, pModule, mod_xOpen);
    rc.* = xOpen(@ptrCast(pVtab), &pVCur);
    sqlite3VtabImportErrmsg(p, @ptrCast(pVtab));
    if (rc.* != 0) return .err;
    wrPtr(pVCur, vcur_pVtab, pVtab);
    pCur = allocateCursor(p, pOp.p1, 0, CURTYPE_VTAB);
    if (pCur != null) {
        wrPtr(pCur, VC_uc, @ptrCast(pVCur));
        wr(c_int, pVtab, vtab_nRef, rd(c_int, pVtab, vtab_nRef) + 1);
    } else {
        const xClose = modFn(xCloseFn, pModule, mod_xClose);
        _ = xClose(pVCur);
        return .no_mem;
    }
    return .ok;
}

// ---- OP_VCheck ------------------------------------------------------------
fn opVCheck(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) bool {
    _ = p;
    const pOut = memAt(aMem, pOp.p2);
    sqlite3VdbeMemSetNull(pOut);
    const pTab = pOp.p4.pTab;
    const pVtabObj = rdPtr(pTab, Table_uvtab); // Table.u.vtab.p
    if (pVtabObj == null) return false;
    const pVtab = rdPtr(pVtabObj, VTable_pVtab);
    const pModule = rdPtr(pVtab, vtab_pModule);
    var zErr: ?[*:0]u8 = null;
    sqlite3VtabLock(pVtabObj);
    const xInteg = modFn(xIntegrityFn, pModule, mod_xIntegrity);
    rc.* = xInteg(@ptrCast(pVtab), @ptrCast(rdPtr(dbEnt(db, pOp.p1), Db_zDbSName)), @ptrCast(rdPtr(pTab, Table_zName)), pOp.p3, &zErr);
    sqlite3VtabUnlock(pVtabObj);
    if (rc.* != 0) {
        sqlite3_free(zErr);
        return true;
    }
    if (zErr != null) {
        _ = sqlite3VdbeMemSetStr(pOut, @ptrCast(zErr), -1, SQLITE_UTF8, @ptrCast(&sqlite3_free));
    }
    return false;
}

// ---- OP_VFilter -----------------------------------------------------------
fn opVFilter(p: ?*Vdbe, pOp: *Op, aMem: [*]u8, rc: *c_int) JumpFallErr {
    const apCsr = apCsrOf(p);
    const pQuery = memAt(aMem, pOp.p3);
    const pArgc = memAt(aMem, pOp.p3 + 1);
    const pCur = apCsr[@intCast(pOp.p1)];
    const pVCur = rdPtr(pCur, VC_uc);
    const pVtab = rdPtr(pVCur, vcur_pVtab);
    const pModule = rdPtr(pVtab, vtab_pModule);
    const nArg: c_int = @intCast(pArgc.u.i);
    const iQuery: c_int = @intCast(pQuery.u.i);
    const apArg: [*]?*Mem = @ptrCast(@alignCast(rdPtr(p, Vdbe_apArg).?));
    var i: c_int = 0;
    while (i < nArg) : (i += 1) {
        apArg[@intCast(i)] = memAt(aMem, pOp.p3 + 1 + i + 1);
    }
    const xFilter = modFn(xFilterFn, pModule, mod_xFilter);
    rc.* = xFilter(pVCur, iQuery, pOp.p4.z, nArg, apArg);
    sqlite3VtabImportErrmsg(p, @ptrCast(pVtab));
    if (rc.* != 0) return .err;
    const xEof = modFn(xEofFn, pModule, mod_xEof);
    const res = xEof(pVCur);
    wrU8(pCur, VC_nullRow, 0);
    if (res != 0) return .jump;
    return .fall;
}

// ---- OP_VColumn -----------------------------------------------------------
fn opVColumn(p: ?*Vdbe, pOp: *Op, aMem: [*]u8, encoding: u8, rc: *c_int) bool {
    const apCsr = apCsrOf(p);
    const pCur = apCsr[@intCast(pOp.p1)];
    const pDest = memAt(aMem, pOp.p3);
    if (rdU8(pCur, VC_nullRow) != 0) {
        sqlite3VdbeMemSetNull(pDest);
        return false;
    }
    const pVtab = rdPtr(rdPtr(pCur, VC_uc), vcur_pVtab);
    const pModule = rdPtr(pVtab, vtab_pModule);
    var sContext: [sizeof_sqlite3_context]u8 align(8) = std.mem.zeroes([sizeof_sqlite3_context]u8);
    var nullFunc: [sizeof_FuncDef]u8 align(8) = std.mem.zeroes([sizeof_FuncDef]u8);
    const scp: *anyopaque = @ptrCast(&sContext);
    const nfp: *anyopaque = @ptrCast(&nullFunc);
    wrPtr(scp, Ctx_pOut, @ptrCast(pDest));
    wrU8(scp, Ctx_enc, encoding);
    wrPtr(nfp, FuncDef_pUserData, null);
    wr(u32, nfp, FuncDef_funcFlags, SQLITE_RESULT_SUBTYPE);
    wrPtr(scp, Ctx_pFunc, nfp);
    if ((pOp.p5 & OPFLAG_NOCHNG) != 0) {
        sqlite3VdbeMemSetNull(pDest);
        pDest.flags = MEM_Null | MEM_Zero;
        pDest.u.nZero = 0;
    } else {
        MemSetTypeFlag(pDest, MEM_Null);
    }
    const xColumn = modFn(xColumnFn, pModule, mod_xColumn);
    rc.* = xColumn(rdPtr(pCur, VC_uc), @ptrCast(scp), pOp.p2);
    sqlite3VtabImportErrmsg(p, @ptrCast(pVtab));
    if (rd(c_int, scp, Ctx_isError) > 0) {
        sqlite3VdbeError(p, "%s", sqlite3_value_text(pDest) orelse @as([*:0]const u8, ""));
        rc.* = rd(c_int, scp, Ctx_isError);
    }
    _ = sqlite3VdbeChangeEncoding(pDest, encoding);
    updateMaxBlobsize(pDest);
    return rc.* != 0;
}

// ---- OP_VNext -------------------------------------------------------------
fn opVNext(p: ?*Vdbe, pOp: *Op, rc: *c_int) JumpFallErr {
    const apCsr = apCsrOf(p);
    const pCur = apCsr[@intCast(pOp.p1)];
    if (rdU8(pCur, VC_nullRow) != 0) {
        return .fall;
    }
    const pVtab = rdPtr(rdPtr(pCur, VC_uc), vcur_pVtab);
    const pModule = rdPtr(pVtab, vtab_pModule);
    const xNext = modFn(xNextFn, pModule, mod_xNext);
    rc.* = xNext(rdPtr(pCur, VC_uc));
    sqlite3VtabImportErrmsg(p, @ptrCast(pVtab));
    if (rc.* != 0) return .err;
    const xEof = modFn(xEofFn, pModule, mod_xEof);
    const res = xEof(rdPtr(pCur, VC_uc));
    if (res == 0) return .jump;
    return .fall;
}

// ---- OP_VRename -----------------------------------------------------------
fn opVRename(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) bool {
    const isLegacy = (rd(u64, db, sqlite3_flags) & SQLITE_LegacyAlter);
    wr(u64, db, sqlite3_flags, rd(u64, db, sqlite3_flags) | SQLITE_LegacyAlter);
    const pVtab = rdPtr(pOp.p4.pVtab, VTable_pVtab);
    const pModule = rdPtr(pVtab, vtab_pModule);
    const pName = memAt(aMem, pOp.p1);
    rc.* = sqlite3VdbeChangeEncoding(pName, SQLITE_UTF8);
    if (rc.* != 0) return true;
    const xRename = modFn(xRenameFn, pModule, mod_xRename);
    rc.* = xRename(@ptrCast(pVtab), @ptrCast(pName.z));
    if (isLegacy == 0) wr(u64, db, sqlite3_flags, rd(u64, db, sqlite3_flags) & ~SQLITE_LegacyAlter);
    sqlite3VtabImportErrmsg(p, @ptrCast(pVtab));
    setExpired(p, 0);
    return rc.* != 0;
}

// ---- OP_VUpdate -----------------------------------------------------------
fn opVUpdate(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, rc: *c_int) ?ExitKind {
    if (mallocFailed(db)) return .no_mem;
    sqlite3VdbeIncrWriteCounter(p, null);
    const pVtab = rdPtr(pOp.p4.pVtab, VTable_pVtab);
    if (pVtab == null) {
        rc.* = SQLITE_LOCKED;
        return .abort_error;
    }
    const pModule = rdPtr(pVtab, vtab_pModule);
    const nArg = pOp.p2;
    var rowid: i64 = 0;
    const apArg: [*]?*Mem = @ptrCast(@alignCast(rdPtr(p, Vdbe_apArg).?));
    var i: c_int = 0;
    while (i < nArg) : (i += 1) {
        apArg[@intCast(i)] = memAt(aMem, pOp.p3 + i);
    }
    const vtabOnConflict = rdU8(db, sqlite3_vtabOnConflict);
    wrU8(db, sqlite3_vtabOnConflict, @intCast(pOp.p5 & 0xff));
    const xUpdate = modFn(xUpdateFn, pModule, mod_xUpdate);
    rc.* = xUpdate(@ptrCast(pVtab), nArg, apArg, &rowid);
    wrU8(db, sqlite3_vtabOnConflict, vtabOnConflict);
    sqlite3VtabImportErrmsg(p, @ptrCast(pVtab));
    if (rc.* == SQLITE_OK and pOp.p1 != 0) {
        wr(i64, db, sqlite3_lastRowid, rowid);
    }
    if ((rc.* & 0xff) == SQLITE_CONSTRAINT and rd(c_int, pOp.p4.pVtab, VTable_bConstraint) != 0) {
        if (pOp.p5 == OE_Ignore) {
            rc.* = SQLITE_OK;
        } else {
            wrU8(p, Vdbe_errorAction, if (pOp.p5 == OE_Replace) OE_Abort else @as(u8, @intCast(pOp.p5)));
        }
    } else {
        wr(c_int, p, Vdbe_nChange, rd(c_int, p, Vdbe_nChange) + 1);
    }
    if (rc.* != 0) return .abort_error;
    return null;
}

// ---- OP_Function / PureFunc ----------------------------------------------
fn opFunction(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aMem: [*]u8, encoding: u8, rc: *c_int) bool {
    const pCtx = pOp.p4.pCtx;
    const pOut = memAt(aMem, pOp.p3);
    if (rdPtr(pCtx, Ctx_pOut) != @as(?*anyopaque, @ptrCast(pOut))) {
        wrPtr(pCtx, Ctx_pVdbe, p);
        wrPtr(pCtx, Ctx_pOut, @ptrCast(pOut));
        wrU8(pCtx, Ctx_enc, encoding);
        const argc = rd(u16, pCtx, Ctx_argc);
        const argvBase: [*]?*Mem = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pCtx.?)) + Ctx_argv));
        var i: c_int = @as(c_int, argc) - 1;
        while (i >= 0) : (i -= 1) {
            argvBase[@intCast(i)] = memAt(aMem, pOp.p2 + i);
        }
    }
    MemSetTypeFlag(pOut, MEM_Null);
    const pFunc = rdPtr(pCtx, Ctx_pFunc);
    const argc = rd(u16, pCtx, Ctx_argc);
    const argvBase: [*]?*Mem = @ptrCast(@alignCast(@as([*]u8, @ptrCast(pCtx.?)) + Ctx_argv));
    const xFunc: SFunc = @ptrCast(rdPtr(pFunc, FuncDef_xSFunc).?);
    xFunc(@ptrCast(pCtx), argc, argvBase);

    if (rd(c_int, pCtx, Ctx_isError) != 0) {
        if (rd(c_int, pCtx, Ctx_isError) > 0) {
            sqlite3VdbeError(p, "%s", sqlite3_value_text(pOut) orelse @as([*:0]const u8, ""));
            rc.* = rd(c_int, pCtx, Ctx_isError);
        }
        sqlite3VdbeDeleteAuxData(db, @ptrCast(fp(?*anyopaque, p, Vdbe_pAuxData)), rd(c_int, pCtx, Ctx_iOp), pOp.p1);
        wr(c_int, pCtx, Ctx_isError, 0);
        if (rc.* != 0) return true;
    }
    updateMaxBlobsize(pOut);
    return false;
}

// ---- OP_Init / Trace ------------------------------------------------------
fn opInit(p: ?*Vdbe, db: ?*anyopaque, pOp: *Op, aOp: [*]Op, op: u8, pc: *usize) void {
    const mTrace = rdU8(db, sqlite3_mTrace);
    if ((mTrace & (SQLITE_TRACE_STMT | SQLITE_TRACE_LEGACY)) != 0 and rdU8(p, Vdbe_minWriteFileFormat) != 254) {
        const zTrace: ?[*:0]const u8 = if (pOp.p4.z != null) @ptrCast(pOp.p4.z) else rd(?[*:0]const u8, p, Vdbe_zSql);
        if (zTrace != null) {
            if ((mTrace & SQLITE_TRACE_LEGACY) != 0) {
                const z = sqlite3VdbeExpandSql(p, zTrace.?);
                const xLeg: TraceLegacyFn = @ptrCast(rdPtr(db, sqlite3_trace));
                xLeg.?(rdPtr(db, sqlite3_pTraceArg), @ptrCast(z));
                sqlite3_free(z);
            } else if (rd(c_int, db, sqlite3_nVdbeExec) > 1) {
                const z = sqlite3MPrintf(db, "-- %s", zTrace);
                const xv2: TraceV2Fn = @ptrCast(rdPtr(db, sqlite3_trace));
                _ = xv2.?(SQLITE_TRACE_STMT, rdPtr(db, sqlite3_pTraceArg), p, @ptrCast(z));
                sqlite3DbFree(db, z);
            } else {
                const xv2: TraceV2Fn = @ptrCast(rdPtr(db, sqlite3_trace));
                _ = xv2.?(SQLITE_TRACE_STMT, rdPtr(db, sqlite3_pTraceArg), p, @ptrCast(@constCast(zTrace.?)));
            }
        }
    }
    if (pOp.p1 >= iOnceResetThreshold()) {
        if (op == OP_Trace) {
            pc.* += 1;
            return;
        }
        var i: c_int = 1;
        const nOp = rd(c_int, p, Vdbe_nOp);
        while (i < nOp) : (i += 1) {
            if (aOp[@intCast(i)].opcode == OP_Once) aOp[@intCast(i)].p1 = 0;
        }
        pOp.p1 = 0;
    }
    pOp.p1 += 1;
    const idx = Vdbe_aCounter + SQLITE_STMTSTATUS_RUN * 4;
    wr(u32, p, idx, rd(u32, p, idx) +% 1);
    pc.* = @intCast(pOp.p2);
}
// ===========================================================================
// The interpreter.
// ===========================================================================
//
// vdbe.c uses unstructured gotos heavily. We model them with a single big
// switch inside a while(true) loop. Jumps inside an opcode set `pc` (or the
// shared jump target) and `continue :main`. The shared cleanup labels
// (abort_due_to_error / too_big / no_mem / abort_due_to_interrupt /
// vdbe_return) are reached by setting `rc` and breaking out to the tail code
// after the loop, driven by the `done` flag.
//
// Each opcode handler ends by selecting one of:
//   - fall through to `pc += 1` (the C `break;`)
//   - jump_to_p2  : pc = pOp.p2  (lands on aOp[p2])
//   - jump_to_p2 + check_for_interrupt
//   - check_for_interrupt (no jump)
//   - one of the error exits
// We encode this with the `Act` enum returned where ambiguous; most handlers
// just set `pc` and `continue`.

const ExitKind = enum { ret, abort_error, too_big, no_mem, abort_interrupt };

pub export fn sqlite3VdbeExec(p: ?*Vdbe) callconv(.c) c_int {
    var aOp: [*]Op = @ptrCast(@alignCast(rdPtr(p, Vdbe_aOp).?));
    var rc: c_int = SQLITE_OK;
    const db = rdPtr(p, Vdbe_db);
    var resetSchemaOnFault: u8 = 0;
    const encoding: u8 = ENC(db);
    var iCompare: c_int = 0;
    var nVmStep: u64 = 0;
    var nProgressLimit: u64 = LARGEST_UINT64;
    var aMem: [*]u8 = @ptrCast(rdPtr(p, Vdbe_aMem).?);
    var colCacheCtr: u32 = 0;

    if (rd(c_int, p, Vdbe_lockMask) != 0) {
        sqlite3VdbeEnter(p);
    }
    if (rdPtr(db, sqlite3_xProgress) != null) {
        const iPrior = rd(u32, p, Vdbe_aCounter + SQLITE_STMTSTATUS_VM_STEP * 4);
        const nOps = rd(c_int, db, sqlite3_nProgressOps);
        nProgressLimit = @as(u64, @intCast(nOps)) - (@as(u64, iPrior) % @as(u64, @intCast(nOps)));
    }

    // The exit machinery. We jump here by setting `exitKind` and `done=true`.
    var exitKind: ExitKind = .ret;
    var done = false;

    var pc: usize = @intCast(rd(c_int, p, Vdbe_pc));

    if (rd(c_int, p, Vdbe_rc) == SQLITE_NOMEM) {
        exitKind = .no_mem;
        done = true;
    } else {
        wr(c_int, p, Vdbe_rc, SQLITE_OK);
        wr(c_int, p, Vdbe_iCurrentTime, 0);
        wr(c_int, db, sqlite3_busyHandler_nBusy, 0);
        if (isInterrupted(db)) {
            exitKind = .abort_interrupt;
            done = true;
        } else {
            sqlite3VdbeIOTraceSql(p);
        }
    }

    // pOp pointer (current op).
    var pOp: *Op = &aOp[pc];

    main: while (!done) {
        pOp = &aOp[pc];
        nVmStep += 1;
        const op = pOp.opcode;

        if (config.sqlite_test) {
            if (g_interrupt_count > 0) {
                g_interrupt_count -= 1;
                if (g_interrupt_count == 0) sqlite3_interrupt(db);
            }
        }

        // ---- opcode dispatch -------------------------------------------------
        // Convention inside each block:
        //   to fall through (C `break;`): `pc += 1; continue :main;`
        //   to jump to p2:               `pc = @intCast(pOp.p2); continue :main;`
        // The error exits set exitKind + done and `continue :main` (loop ends).
        sw: switch (op) {
            OP_Goto => {
                // jump_to_p2_and_check_for_interrupt
                pc = @intCast(pOp.p2);
                if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                continue :main;
            },
            OP_Gosub => {
                const pIn1 = memAt(aMem, pOp.p1);
                pIn1.flags = MEM_Int;
                pIn1.u.i = @intCast(pc);
                pc = @intCast(pOp.p2);
                if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                continue :main;
            },
            OP_Return => {
                const pIn1 = memAt(aMem, pOp.p1);
                if ((pIn1.flags & MEM_Int) != 0) {
                    pc = @intCast(pIn1.u.i);
                    pc += 1;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_InitCoroutine => {
                const pOut = memAt(aMem, pOp.p1);
                pOut.u.i = pOp.p3 - 1;
                pOut.flags = MEM_Int;
                if (pOp.p2 == 0) {
                    pc += 1;
                    continue :main;
                }
                pc = @intCast(pOp.p2);
                continue :main;
            },
            OP_EndCoroutine => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pCaller = &aOp[@intCast(pIn1.u.i)];
                pIn1.u.i = @as(i64, @intCast(pc)) - 1;
                pc = @intCast(pCaller.p2);
                continue :main;
            },
            OP_Yield => {
                const pIn1 = memAt(aMem, pOp.p1);
                pIn1.flags = MEM_Int;
                const pcDest: c_int = @intCast(pIn1.u.i);
                pIn1.u.i = @intCast(pc);
                pc = @intCast(pcDest);
                pc += 1;
                continue :main;
            },
            OP_HaltIfNull => {
                const pIn3 = memAt(aMem, pOp.p3);
                if ((pIn3.flags & MEM_Null) == 0) {
                    pc += 1;
                    continue :main;
                }
                continue :sw OP_Halt;
            },
            OP_Halt => {
                if (opHalt(p, db, pOp, &aOp, &aMem, &pc, &rc, &exitKind, &done)) continue :main;
                continue :main;
            },
            OP_Integer => {
                const pOut = out2Prerelease(p, pOp);
                pOut.u.i = pOp.p1;
                pc += 1;
                continue :main;
            },
            OP_Int64 => {
                const pOut = out2Prerelease(p, pOp);
                pOut.u.i = pOp.p4.pI64.?.*;
                pc += 1;
                continue :main;
            },
            OP_Real => {
                const pOut = out2Prerelease(p, pOp);
                pOut.flags = MEM_Real;
                pOut.u.r = pOp.p4.pReal.?.*;
                pc += 1;
                continue :main;
            },
            OP_String8 => {
                const pOut = out2Prerelease(p, pOp);
                pOp.p1 = sqlite3Strlen30(pOp.p4.z);
                if (encoding != SQLITE_UTF8) {
                    rc = sqlite3VdbeMemSetStr(pOut, @ptrCast(pOp.p4.z), -1, SQLITE_UTF8, sqliteStatic());
                    if (rc != 0) {
                        exitKind = .too_big;
                        done = true;
                        continue :main;
                    }
                    if (sqlite3VdbeChangeEncoding(pOut, encoding) != SQLITE_OK) {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    }
                    pOut.szMalloc = 0;
                    pOut.flags |= MEM_Static;
                    if (pOp.p4type == P4_DYNAMIC) sqlite3DbFree(db, pOp.p4.z);
                    pOp.p4type = P4_DYNAMIC;
                    pOp.p4.z = @ptrCast(pOut.z);
                    pOp.p1 = pOut.n;
                }
                if (pOp.p1 > dbLimit(db, SQLITE_LIMIT_LENGTH)) {
                    exitKind = .too_big;
                    done = true;
                    continue :main;
                }
                pOp.opcode = OP_String;
                continue :sw OP_String;
            },
            OP_String => {
                const pOut = out2Prerelease(p, pOp);
                pOut.flags = MEM_Str | MEM_Static | MEM_Term;
                pOut.z = @ptrCast(pOp.p4.z);
                pOut.n = pOp.p1;
                pOut.enc = encoding;
                updateMaxBlobsize(pOut);
                if (pOp.p3 > 0) {
                    const pIn3 = memAt(aMem, pOp.p3);
                    if (pIn3.u.i == pOp.p5) pOut.flags = MEM_Blob | MEM_Static | MEM_Term;
                }
                pc += 1;
                continue :main;
            },
            OP_BeginSubrtn, OP_Null => {
                var pOut = out2Prerelease(p, pOp);
                var cnt = pOp.p3 - pOp.p2;
                const nullFlag: u16 = if (pOp.p1 != 0) (MEM_Null | MEM_Cleared) else MEM_Null;
                pOut.flags = nullFlag;
                pOut.n = 0;
                while (cnt > 0) : (cnt -= 1) {
                    pOut = @ptrFromInt(@intFromPtr(pOut) + sizeof_Mem);
                    sqlite3VdbeMemSetNull(pOut);
                    pOut.flags = nullFlag;
                    pOut.n = 0;
                }
                pc += 1;
                continue :main;
            },
            OP_SoftNull => {
                const pOut = memAt(aMem, pOp.p1);
                pOut.flags = (pOut.flags & ~(MEM_Undefined | MEM_AffMask)) | MEM_Null;
                pc += 1;
                continue :main;
            },
            OP_Blob => {
                const pOut = out2Prerelease(p, pOp);
                if (pOp.p4.z == null) {
                    _ = sqlite3VdbeMemSetZeroBlob(pOut, pOp.p1);
                    if (sqlite3VdbeMemExpandBlob(pOut) != 0) {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    }
                } else {
                    _ = sqlite3VdbeMemSetStr(pOut, @ptrCast(pOp.p4.z), pOp.p1, 0, null);
                }
                pOut.enc = encoding;
                updateMaxBlobsize(pOut);
                pc += 1;
                continue :main;
            },
            OP_Variable => {
                const aVar: [*]u8 = @ptrCast(rdPtr(p, Vdbe_aVar).?);
                const pVar = memAt(aVar, pOp.p1 - 1);
                if (sqlite3VdbeMemTooBig(pVar) != 0) {
                    exitKind = .too_big;
                    done = true;
                    continue :main;
                }
                const pOut = memAt(aMem, pOp.p2);
                if (VdbeMemDynamic(pOut)) sqlite3VdbeMemSetNull(pOut);
                @memcpy(@as([*]u8, @ptrCast(pOut))[0..MEMCELLSIZE], @as([*]u8, @ptrCast(pVar))[0..MEMCELLSIZE]);
                pOut.flags &= ~(MEM_Dyn | MEM_Ephem);
                pOut.flags |= MEM_Static | MEM_FromBind;
                updateMaxBlobsize(pOut);
                pc += 1;
                continue :main;
            },
            OP_Move => {
                var n = pOp.p3;
                var p1 = pOp.p1;
                var p2 = pOp.p2;
                var pIn1 = memAt(aMem, p1);
                var pOut = memAt(aMem, p2);
                while (true) {
                    sqlite3VdbeMemMove(pOut, pIn1);
                    if (deephemeralize(pOut)) {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    }
                    p2 += 1;
                    p1 += 1;
                    pIn1 = @ptrFromInt(@intFromPtr(pIn1) + sizeof_Mem);
                    pOut = @ptrFromInt(@intFromPtr(pOut) + sizeof_Mem);
                    n -= 1;
                    if (n == 0) break;
                }
                pc += 1;
                continue :main;
            },
            OP_Copy => {
                var n = pOp.p3;
                var pIn1 = memAt(aMem, pOp.p1);
                var pOut = memAt(aMem, pOp.p2);
                while (true) {
                    sqlite3VdbeMemShallowCopy(pOut, pIn1, MEM_Ephem);
                    if (deephemeralize(pOut)) {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    }
                    if ((pOut.flags & MEM_Subtype) != 0 and (pOp.p5 & 0x0002) != 0) {
                        pOut.flags &= ~MEM_Subtype;
                    }
                    n -= 1;
                    if (n < 0) break;
                    pOut = @ptrFromInt(@intFromPtr(pOut) + sizeof_Mem);
                    pIn1 = @ptrFromInt(@intFromPtr(pIn1) + sizeof_Mem);
                }
                pc += 1;
                continue :main;
            },
            OP_SCopy => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pOut = memAt(aMem, pOp.p2);
                sqlite3VdbeMemShallowCopy(pOut, pIn1, MEM_Ephem);
                pc += 1;
                continue :main;
            },
            OP_IntCopy => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pOut = memAt(aMem, pOp.p2);
                sqlite3VdbeMemSetInt64(pOut, pIn1.u.i);
                pc += 1;
                continue :main;
            },
            OP_FkCheck => {
                rc = sqlite3VdbeCheckFkImmediate(p);
                if (rc != SQLITE_OK) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ResultRow => {
                wr(c_int, p, Vdbe_cacheCtr, (rd(c_int, p, Vdbe_cacheCtr) + 2) | 1);
                wrPtr(p, Vdbe_pResultRow, @ptrCast(memAt(aMem, pOp.p1)));
                if (mallocFailed(db)) {
                    exitKind = .no_mem;
                    done = true;
                    continue :main;
                }
                if ((rdU8(db, sqlite3_mTrace) & SQLITE_TRACE_ROW) != 0) {
                    const xv2: TraceV2Fn = @ptrCast(rdPtr(db, sqlite3_trace));
                    _ = xv2.?(SQLITE_TRACE_ROW, rdPtr(db, sqlite3_pTraceArg), p, null);
                }
                wr(c_int, p, Vdbe_pc, @as(c_int, @intCast(pc)) + 1);
                rc = SQLITE_ROW;
                exitKind = .ret;
                done = true;
                continue :main;
            },
            OP_Concat => {
                if (opConcat(db, pOp, aMem, encoding, &rc)) {
                    exitKind = if (rc == SQLITE_TOOBIG) .too_big else .no_mem;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Add, OP_Subtract, OP_Multiply, OP_Divide, OP_Remainder => {
                opArith(pOp, aMem);
                pc += 1;
                continue :main;
            },
            OP_CollSeq => {
                if (pOp.p1 != 0) sqlite3VdbeMemSetInt64(memAt(aMem, pOp.p1), 0);
                pc += 1;
                continue :main;
            },
            OP_BitAnd, OP_BitOr, OP_ShiftLeft, OP_ShiftRight => {
                opBitwise(pOp, aMem);
                pc += 1;
                continue :main;
            },
            OP_AddImm => {
                const pIn1 = memAt(aMem, pOp.p1);
                _ = sqlite3VdbeMemIntegerify(pIn1);
                pIn1.u.i = @bitCast(@as(u64, @bitCast(pIn1.u.i)) +% @as(u64, @bitCast(@as(i64, pOp.p2))));
                pc += 1;
                continue :main;
            },
            OP_MustBeInt => {
                const pIn1 = memAt(aMem, pOp.p1);
                if ((pIn1.flags & MEM_Int) == 0) {
                    applyAffinity(pIn1, SQLITE_AFF_NUMERIC, encoding);
                    if ((pIn1.flags & MEM_Int) == 0) {
                        if (pOp.p2 == 0) {
                            rc = SQLITE_MISMATCH;
                            exitKind = .abort_error;
                            done = true;
                            continue :main;
                        } else {
                            pc = @intCast(pOp.p2);
                            continue :main;
                        }
                    }
                }
                MemSetTypeFlag(pIn1, MEM_Int);
                pc += 1;
                continue :main;
            },
            OP_RealAffinity => {
                const pIn1 = memAt(aMem, pOp.p1);
                if ((pIn1.flags & (MEM_Int | MEM_IntReal)) != 0) {
                    _ = sqlite3VdbeMemRealify(pIn1);
                }
                pc += 1;
                continue :main;
            },
            OP_Cast => {
                const pIn1 = memAt(aMem, pOp.p1);
                rc = ExpandBlob(pIn1);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                rc = sqlite3VdbeMemCast(pIn1, @intCast(pOp.p2), encoding);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                updateMaxBlobsize(pIn1);
                pc += 1;
                continue :main;
            },
            OP_Eq, OP_Ne, OP_Lt, OP_Le, OP_Gt, OP_Ge => {
                if (opCompare(pOp, aMem, encoding, &iCompare)) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ElseEq => {
                if (iCompare == 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Permutation => {
                pc += 1;
                continue :main;
            },
            OP_Compare => {
                opCompareVec(pOp, aOp, aMem, pc, &iCompare);
                pc += 1;
                continue :main;
            },
            OP_Jump => {
                if (iCompare < 0) {
                    pc = @intCast(pOp.p1);
                } else if (iCompare == 0) {
                    pc = @intCast(pOp.p2);
                } else {
                    pc = @intCast(pOp.p3);
                }
                continue :main;
            },
            OP_And, OP_Or => {
                var v1 = sqlite3VdbeBooleanValue(memAt(aMem, pOp.p1), 2);
                const v2 = sqlite3VdbeBooleanValue(memAt(aMem, pOp.p2), 2);
                const and_logic = [_]u8{ 0, 0, 0, 0, 1, 2, 0, 2, 2 };
                const or_logic = [_]u8{ 0, 1, 2, 1, 1, 1, 2, 1, 2 };
                if (op == OP_And) {
                    v1 = and_logic[@intCast(v1 * 3 + v2)];
                } else {
                    v1 = or_logic[@intCast(v1 * 3 + v2)];
                }
                const pOut = memAt(aMem, pOp.p3);
                if (v1 == 2) {
                    MemSetTypeFlag(pOut, MEM_Null);
                } else {
                    pOut.u.i = v1;
                    MemSetTypeFlag(pOut, MEM_Int);
                }
                pc += 1;
                continue :main;
            },
            OP_IsTrue => {
                sqlite3VdbeMemSetInt64(memAt(aMem, pOp.p2), sqlite3VdbeBooleanValue(memAt(aMem, pOp.p1), pOp.p3) ^ pOp.p4.i);
                pc += 1;
                continue :main;
            },
            OP_Not => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pOut = memAt(aMem, pOp.p2);
                if ((pIn1.flags & MEM_Null) == 0) {
                    sqlite3VdbeMemSetInt64(pOut, @intFromBool(sqlite3VdbeBooleanValue(pIn1, 0) == 0));
                } else {
                    sqlite3VdbeMemSetNull(pOut);
                }
                pc += 1;
                continue :main;
            },
            OP_BitNot => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pOut = memAt(aMem, pOp.p2);
                sqlite3VdbeMemSetNull(pOut);
                if ((pIn1.flags & MEM_Null) == 0) {
                    pOut.flags = MEM_Int;
                    pOut.u.i = ~sqlite3VdbeIntValue(pIn1);
                }
                pc += 1;
                continue :main;
            },
            OP_Once => {
                const pFrame = rdPtr(p, Vdbe_pFrame);
                if (pFrame != null) {
                    const iAddr: usize = pc;
                    const aOnce: [*]u8 = @ptrCast(rdPtr(pFrame, VdbeFrame_aOnce).?);
                    const mask = @as(u8, 1) << @intCast(iAddr & 7);
                    if ((aOnce[iAddr / 8] & mask) != 0) {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    }
                    aOnce[iAddr / 8] |= mask;
                } else {
                    if (aOp[0].p1 == pOp.p1) {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    }
                }
                pOp.p1 = aOp[0].p1;
                pc += 1;
                continue :main;
            },
            OP_If => {
                const c = sqlite3VdbeBooleanValue(memAt(aMem, pOp.p1), pOp.p3);
                if (c != 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_IfNot => {
                const c = sqlite3VdbeBooleanValue(memAt(aMem, pOp.p1), @intFromBool(pOp.p3 == 0)) == 0;
                if (c) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_IsNull => {
                const pIn1 = memAt(aMem, pOp.p1);
                if ((pIn1.flags & MEM_Null) != 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_IsType => {
                if (opIsType(p, pOp, aMem)) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ZeroOrNull => {
                if ((memAt(aMem, pOp.p1).flags & MEM_Null) != 0 or (memAt(aMem, pOp.p3).flags & MEM_Null) != 0) {
                    sqlite3VdbeMemSetNull(memAt(aMem, pOp.p2));
                } else {
                    sqlite3VdbeMemSetInt64(memAt(aMem, pOp.p2), 0);
                }
                pc += 1;
                continue :main;
            },
            OP_NotNull => {
                const pIn1 = memAt(aMem, pOp.p1);
                if ((pIn1.flags & MEM_Null) == 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_IfNullRow => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                if (pC != null and rdU8(pC, VC_nullRow) != 0) {
                    sqlite3VdbeMemSetNull(memAt(aMem, pOp.p3));
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Column => {
                const r = opColumn(p, db, pOp, aOp, aMem, encoding, colCacheCtr, &rc);
                switch (r) {
                    .ok => {
                        pc += 1;
                        continue :main;
                    },
                    .corrupt_jump => |target| {
                        pc = target;
                        continue :main;
                    },
                    .no_mem => {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    },
                    .too_big => {
                        exitKind = .too_big;
                        done = true;
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_TypeCheck => {
                const r = opTypeCheck(p, pOp, aMem, encoding, &rc);
                if (r) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Affinity => {
                opAffinity(pOp, aMem, encoding);
                pc += 1;
                continue :main;
            },
            OP_MakeRecord => {
                const r = opMakeRecord(p, db, pOp, aMem, encoding, &rc);
                switch (r) {
                    .ok => {
                        pc += 1;
                        continue :main;
                    },
                    .no_mem => {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    },
                    .too_big => {
                        exitKind = .too_big;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_Count => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pCrsr: ?*BtCursor = @ptrCast(rdPtr(apCsr[@intCast(pOp.p1)], VC_uc));
                var nEntry: i64 = 0;
                if (pOp.p3 != 0) {
                    nEntry = sqlite3BtreeRowCountEst(pCrsr);
                } else {
                    rc = sqlite3BtreeCount(db, pCrsr, &nEntry);
                    if (rc != 0) {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    }
                }
                const pOut = out2Prerelease(p, pOp);
                pOut.u.i = nEntry;
                pc += 1;
                if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                continue :main;
            },
            OP_Savepoint => {
                const cont = opSavepoint(p, db, pOp, &rc, &exitKind, &done);
                if (cont) continue :main; // vdbe_return / abort already set
                pc += 1;
                continue :main;
            },
            OP_AutoCommit => {
                opAutoCommit(p, db, pOp, &aOp, pc, &rc, &exitKind, &done);
                continue :main;
            },
            OP_Transaction => {
                if (opTransaction(p, db, pOp, &aOp, pc, &rc, &exitKind, &done)) continue :main;
                pc += 1;
                continue :main;
            },
            OP_ReadCookie => {
                const iDb = pOp.p1;
                var iMeta: u32 = 0;
                sqlite3BtreeGetMeta(rdPtr(dbEnt(db, iDb), Db_pBt), pOp.p3, &iMeta);
                const pOut = out2Prerelease(p, pOp);
                pOut.u.i = @intCast(@as(i32, @bitCast(iMeta)));
                pc += 1;
                continue :main;
            },
            OP_SetCookie => {
                if (opSetCookie(p, db, pOp, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ReopenIdx, OP_OpenRead, OP_OpenWrite => {
                const r = opOpen(p, db, pOp, op, aMem, &rc);
                switch (r) {
                    .ok => {
                        pc += 1;
                        continue :main;
                    },
                    .no_mem => {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_OpenDup => {
                if (opOpenDup(p, pOp, &rc)) {
                    exitKind = .no_mem;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_OpenAutoindex, OP_OpenEphemeral => {
                const r = opOpenEphemeral(p, db, pOp, op, aMem, &rc);
                switch (r) {
                    .ok => {
                        pc += 1;
                        continue :main;
                    },
                    .no_mem => {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_SorterOpen => {
                const pCx = allocateCursor(p, pOp.p1, pOp.p2, CURTYPE_SORTER);
                if (pCx == null) {
                    exitKind = .no_mem;
                    done = true;
                    continue :main;
                }
                wrPtr(pCx, VC_pKeyInfo, pOp.p4.pKeyInfo);
                rc = sqlite3VdbeSorterInit(db, pOp.p3, pCx);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_SequenceTest => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                const sc = rd(i64, pC, VC_seqCount);
                wr(i64, pC, VC_seqCount, sc + 1);
                if (sc == 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_OpenPseudo => {
                const pCx = allocateCursor(p, pOp.p1, pOp.p3, CURTYPE_PSEUDO);
                if (pCx == null) {
                    exitKind = .no_mem;
                    done = true;
                    continue :main;
                }
                wrU8(pCx, VC_nullRow, 1);
                wr(c_int, pCx, VC_seekResult, pOp.p2);
                wrU8(pCx, VC_isTable, 1);
                wrPtr(pCx, VC_uc, @ptrCast(sqlite3BtreeFakeValidCursor()));
                pc += 1;
                continue :main;
            },
            OP_Close => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                sqlite3VdbeFreeCursor(p, apCsr[@intCast(pOp.p1)]);
                apCsr[@intCast(pOp.p1)] = null;
                pc += 1;
                continue :main;
            },
            OP_SeekLT, OP_SeekLE, OP_SeekGE, OP_SeekGT => {
                const r = opSeek(p, db, pOp, op, aMem, encoding, &pc, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jumped => continue :main, // pc set by opSeek (p2 or pc++ for skip)
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_SeekScan => {
                const r = opSeekScan(p, db, pOp, aOp, aMem, &pc, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jumped => continue :main,
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_SeekHit => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                const sh = rd(c_int, pC, VC_seekHit) & 0xffff;
                if (sh < pOp.p2) {
                    wr(u16, pC, VC_seekHit, @intCast(pOp.p2));
                } else if (sh > pOp.p3) {
                    wr(u16, pC, VC_seekHit, @intCast(pOp.p3));
                }
                pc += 1;
                continue :main;
            },
            OP_IfNotOpen => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pCur = apCsr[@intCast(pOp.p1)];
                if (pCur == null or rdU8(pCur, VC_nullRow) != 0) {
                    pc = @intCast(pOp.p2);
                    if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_IfNoHope => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                if ((rd(c_int, pC, VC_seekHit) & 0xffff) >= pOp.p4.i) {
                    pc += 1;
                    continue :main;
                }
                continue :sw OP_NotFound;
            },
            OP_NoConflict, OP_NotFound, OP_Found => {
                const r = opFound(p, db, pOp, op, aMem, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    },
                    .no_mem => {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_SeekRowid, OP_NotExists => {
                const r = opSeekRowid(p, pOp, op, aMem, encoding, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_Sequence => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                const pOut = out2Prerelease(p, pOp);
                const sc = rd(i64, pC, VC_seqCount);
                pOut.u.i = sc;
                wr(i64, pC, VC_seqCount, sc + 1);
                pc += 1;
                continue :main;
            },
            OP_NewRowid => {
                if (opNewRowid(p, pOp, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Insert => {
                if (opInsert(p, db, pOp, aMem, &colCacheCtr, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_RowCell => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pDest = apCsr[@intCast(pOp.p1)];
                const pSrc = apCsr[@intCast(pOp.p2)];
                const iKey: i64 = if (pOp.p3 != 0) memAt(aMem, pOp.p3).u.i else 0;
                rc = sqlite3BtreeTransferRow(@ptrCast(rdPtr(pDest, VC_uc)), @ptrCast(rdPtr(pSrc, VC_uc)), iKey);
                if (rc != SQLITE_OK) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Delete => {
                if (opDelete(p, db, pOp, aMem, &colCacheCtr, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ResetCount => {
                sqlite3VdbeSetChanges(db, rd(c_int, p, Vdbe_nChange));
                wr(c_int, p, Vdbe_nChange, 0);
                pc += 1;
                continue :main;
            },
            OP_SorterCompare => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                var res: c_int = 0;
                rc = sqlite3VdbeSorterCompare(pC, memAt(aMem, pOp.p3), pOp.p4.i, &res);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                if (res != 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_SorterData => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pOut = memAt(aMem, pOp.p2);
                const pC = apCsr[@intCast(pOp.p1)];
                rc = sqlite3VdbeSorterRowkey(pC, pOut);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                wr(u32, apCsr[@intCast(pOp.p3)], VC_cacheStatus, CACHE_STALE);
                pc += 1;
                continue :main;
            },
            OP_RowData => {
                if (opRowData(p, db, pOp, aMem, &rc)) |ek| {
                    exitKind = ek;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Rowid => {
                if (opRowid(p, pOp, aMem, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_NullRow => {
                if (opNullRow(p, pOp)) {
                    exitKind = .no_mem;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_SeekEnd, OP_Last => {
                const r = opLast(p, pOp, op, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_IfSizeBetween => {
                const r = opIfSizeBetween(p, pOp, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_SorterSort, OP_Sort => {
                if (config.sqlite_test) {
                    g_sort_count += 1;
                    g_search_count -= 1;
                }
                const idx = Vdbe_aCounter + SQLITE_STMTSTATUS_SORT * 4;
                wr(u32, p, idx, rd(u32, p, idx) +% 1);
                continue :sw OP_Rewind;
            },
            OP_Rewind => {
                const r = opRewind(p, pOp, op, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_IfEmpty => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pCrsr: ?*BtCursor = @ptrCast(rdPtr(apCsr[@intCast(pOp.p1)], VC_uc));
                var res: c_int = 0;
                rc = sqlite3BtreeIsEmpty(pCrsr, &res);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                if (res != 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_SorterNext, OP_Prev, OP_Next => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                if (op == OP_SorterNext) {
                    rc = sqlite3VdbeSorterNext(db, pC);
                } else if (op == OP_Prev) {
                    rc = sqlite3BtreePrevious(@ptrCast(rdPtr(pC, VC_uc)), pOp.p3);
                } else {
                    rc = sqlite3BtreeNext(@ptrCast(rdPtr(pC, VC_uc)), pOp.p3);
                }
                // next_tail:
                wr(u32, pC, VC_cacheStatus, CACHE_STALE);
                if (rc == SQLITE_OK) {
                    wrU8(pC, VC_nullRow, 0);
                    const idx = Vdbe_aCounter + @as(usize, pOp.p5) * 4;
                    wr(u32, p, idx, rd(u32, p, idx) +% 1);
                    if (config.sqlite_test) g_search_count += 1;
                    pc = @intCast(pOp.p2);
                    if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                    continue :main;
                }
                if (rc != SQLITE_DONE) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                rc = SQLITE_OK;
                wrU8(pC, VC_nullRow, 1);
                // End of scan: fall through to the next instruction. The OK
                // branch above jumps to p2; this branch must advance pc by one
                // (mirrors C's check_for_interrupt → loop pOp++).
                pc += 1;
                if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                continue :main;
            },
            OP_IdxInsert => {
                if (opIdxInsert(p, pOp, aMem, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_SorterInsert => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                sqlite3VdbeIncrWriteCounter(p, pC);
                const pIn2 = memAt(aMem, pOp.p2);
                rc = ExpandBlob(pIn2);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                rc = sqlite3VdbeSorterWrite(pC, pIn2);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_IdxDelete => {
                const r = opIdxDelete(p, db, pOp, aMem, &rc);
                switch (r) {
                    .ok => {
                        pc += 1;
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_DeferredSeek, OP_IdxRowid => {
                if (opIdxRowid(p, db, pOp, aMem, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_FinishSeek => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                if (rdU8(pC, VC_deferredMoveto) != 0) {
                    rc = sqlite3VdbeFinishMoveto(pC);
                    if (rc != 0) {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    }
                }
                pc += 1;
                continue :main;
            },
            OP_IdxLE, OP_IdxGT, OP_IdxLT, OP_IdxGE => {
                const r = opIdxCompare(p, db, pOp, op, aMem, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_Destroy => {
                if (opDestroy(p, db, pOp, &resetSchemaOnFault, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Clear => {
                var nChange: i64 = 0;
                sqlite3VdbeIncrWriteCounter(p, null);
                rc = sqlite3BtreeClearTable(rdPtr(dbEnt(db, pOp.p2), Db_pBt), pOp.p1, &nChange);
                if (pOp.p3 != 0) {
                    wr(c_int, p, Vdbe_nChange, rd(c_int, p, Vdbe_nChange) + @as(c_int, @intCast(nChange)));
                    if (pOp.p3 > 0) {
                        memAt(aMem, pOp.p3).u.i += nChange;
                    }
                }
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ResetSorter => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                if (isSorter(pC)) {
                    sqlite3VdbeSorterReset(db, rdPtr(pC, VC_uc));
                } else {
                    rc = sqlite3BtreeClearTableOfCursor(@ptrCast(rdPtr(pC, VC_uc)));
                    if (rc != 0) {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    }
                }
                pc += 1;
                continue :main;
            },
            OP_CreateBtree => {
                sqlite3VdbeIncrWriteCounter(p, null);
                const pOut = out2Prerelease(p, pOp);
                var pgno: u32 = 0;
                rc = sqlite3BtreeCreateTable(rdPtr(dbEnt(db, pOp.p1), Db_pBt), &pgno, pOp.p3);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pOut.u.i = pgno;
                pc += 1;
                continue :main;
            },
            OP_SqlExec => {
                if (opSqlExec(p, db, pOp, &rc)) |ek| {
                    exitKind = ek;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ParseSchema => {
                if (opParseSchema(p, db, pOp, &rc)) |ek| {
                    exitKind = ek;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_LoadAnalysis => {
                rc = sqlite3AnalysisLoad(db, pOp.p1);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_DropTable => {
                sqlite3VdbeIncrWriteCounter(p, null);
                sqlite3UnlinkAndDeleteTable(db, pOp.p1, pOp.p4.z.?);
                pc += 1;
                continue :main;
            },
            OP_DropIndex => {
                sqlite3VdbeIncrWriteCounter(p, null);
                sqlite3UnlinkAndDeleteIndex(db, pOp.p1, pOp.p4.z.?);
                pc += 1;
                continue :main;
            },
            OP_DropTrigger => {
                sqlite3VdbeIncrWriteCounter(p, null);
                sqlite3UnlinkAndDeleteTrigger(db, pOp.p1, pOp.p4.z.?);
                pc += 1;
                continue :main;
            },
            OP_IntegrityCk => {
                if (opIntegrityCk(p, db, pOp, aMem, encoding, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                continue :main;
            },
            OP_IFindKey => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                var r: URBuf = .{};
                wrPtr(r.ptr(), UR_aMem, @ptrCast(memAt(aMem, pOp.p3)));
                wr(u16, r.ptr(), UR_nField, indexNColumn(pOp.p4.pIdx));
                wrPtr(r.ptr(), UR_pKeyInfo, rdPtr(pC, VC_pKeyInfo));
                var res: c_int = 0;
                rc = sqlite3VdbeFindIndexKey(@ptrCast(rdPtr(pC, VC_uc)), pOp.p4.pIdx, r.ptr(), &res, 1);
                if (rc != 0 or res != 0) {
                    rc = SQLITE_OK;
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                wrU8(pC, VC_nullRow, 0);
                pc += 1;
                continue :main;
            },
            OP_RowSetAdd => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pIn2 = memAt(aMem, pOp.p2);
                if ((pIn1.flags & MEM_Blob) == 0) {
                    if (sqlite3VdbeMemSetRowSet(pIn1) != 0) {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    }
                }
                sqlite3RowSetInsert(@ptrCast(pIn1.z), pIn2.u.i);
                pc += 1;
                continue :main;
            },
            OP_RowSetRead => {
                const pIn1 = memAt(aMem, pOp.p1);
                var val: i64 = undefined;
                if ((pIn1.flags & MEM_Blob) == 0 or sqlite3RowSetNext(@ptrCast(pIn1.z), &val) == 0) {
                    sqlite3VdbeMemSetNull(pIn1);
                    pc = @intCast(pOp.p2);
                    if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                    continue :main;
                } else {
                    sqlite3VdbeMemSetInt64(memAt(aMem, pOp.p3), val);
                }
                pc += 1;
                if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                continue :main;
            },
            OP_RowSetTest => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pIn3 = memAt(aMem, pOp.p3);
                const iSet = pOp.p4.i;
                if ((pIn1.flags & MEM_Blob) == 0) {
                    if (sqlite3VdbeMemSetRowSet(pIn1) != 0) {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    }
                }
                if (iSet != 0) {
                    const exists = sqlite3RowSetTest(@ptrCast(pIn1.z), iSet, pIn3.u.i);
                    if (exists != 0) {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    }
                }
                if (iSet >= 0) {
                    sqlite3RowSetInsert(@ptrCast(pIn1.z), pIn3.u.i);
                }
                pc += 1;
                continue :main;
            },
            OP_Program => {
                if (opProgram(p, db, pOp, &aOp, &aMem, pc, &rc, &exitKind, &done)) |newpc| {
                    pc = newpc;
                    continue :main;
                }
                // done flag possibly set by no_mem/error
                continue :main;
            },
            OP_Param => {
                const pOut = out2Prerelease(p, pOp);
                const pFrame = rdPtr(p, Vdbe_pFrame);
                const fAOp: [*]Op = @ptrCast(@alignCast(rdPtr(pFrame, VdbeFrame_aOp).?));
                const fpc: usize = @intCast(rd(c_int, pFrame, VdbeFrame_pc));
                const fAMem: [*]u8 = @ptrCast(rdPtr(pFrame, VdbeFrame_aMem).?);
                const pIn = memAt(fAMem, pOp.p1 + fAOp[fpc].p1);
                sqlite3VdbeMemShallowCopy(pOut, pIn, MEM_Ephem);
                pc += 1;
                continue :main;
            },
            OP_FkCounter => {
                if (pOp.p1 != 0) {
                    wr(i64, db, sqlite3_nDeferredCons, rd(i64, db, sqlite3_nDeferredCons) + pOp.p2);
                } else {
                    if ((rd(u64, db, sqlite3_flags) & SQLITE_DeferFKs) != 0) {
                        wr(i64, db, sqlite3_nDeferredImmCons, rd(i64, db, sqlite3_nDeferredImmCons) + pOp.p2);
                    } else {
                        wr(c_int, p, Vdbe_nFkConstraint, rd(c_int, p, Vdbe_nFkConstraint) + pOp.p2);
                    }
                }
                pc += 1;
                continue :main;
            },
            OP_FkIfZero => {
                const nDefImm = rd(i64, db, sqlite3_nDeferredImmCons);
                if (pOp.p1 != 0) {
                    if (rd(i64, db, sqlite3_nDeferredCons) == 0 and nDefImm == 0) {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    }
                } else {
                    if (rd(c_int, p, Vdbe_nFkConstraint) == 0 and nDefImm == 0) {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    }
                }
                pc += 1;
                continue :main;
            },
            OP_MemMax => {
                var pIn1: *Mem = undefined;
                const pFrame0 = rdPtr(p, Vdbe_pFrame);
                if (pFrame0 != null) {
                    var pFrame = pFrame0;
                    while (rdPtr(pFrame, VdbeFrame_pParent) != null) pFrame = rdPtr(pFrame, VdbeFrame_pParent);
                    const fAMem: [*]u8 = @ptrCast(rdPtr(pFrame, VdbeFrame_aMem).?);
                    pIn1 = memAt(fAMem, pOp.p1);
                } else {
                    pIn1 = memAt(aMem, pOp.p1);
                }
                _ = sqlite3VdbeMemIntegerify(pIn1);
                const pIn2 = memAt(aMem, pOp.p2);
                _ = sqlite3VdbeMemIntegerify(pIn2);
                if (pIn1.u.i < pIn2.u.i) pIn1.u.i = pIn2.u.i;
                pc += 1;
                continue :main;
            },
            OP_IfPos => {
                const pIn1 = memAt(aMem, pOp.p1);
                if (pIn1.u.i > 0) {
                    pIn1.u.i -= pOp.p3;
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_OffsetLimit => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pIn3 = memAt(aMem, pOp.p3);
                const pOut = out2Prerelease(p, pOp);
                var x = pIn1.u.i;
                const off3: i64 = if (pIn3.u.i > 0) pIn3.u.i else 0;
                if (x <= 0 or sqlite3AddInt64(&x, off3) != 0) {
                    pOut.u.i = -1;
                } else {
                    pOut.u.i = x;
                }
                pc += 1;
                continue :main;
            },
            OP_IfNotZero => {
                const pIn1 = memAt(aMem, pOp.p1);
                if (pIn1.u.i != 0) {
                    if (pIn1.u.i > 0) pIn1.u.i -= 1;
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_DecrJumpZero => {
                const pIn1 = memAt(aMem, pOp.p1);
                if (pIn1.u.i > SMALLEST_INT64) pIn1.u.i -= 1;
                if (pIn1.u.i == 0) {
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_AggInverse, OP_AggStep => {
                if (opAggStep0(p, db, pOp, aOp, pc, encoding, &rc)) {
                    exitKind = .no_mem;
                    done = true;
                    continue :main;
                }
                pOp.opcode = OP_AggStep1;
                continue :sw OP_AggStep1;
            },
            OP_AggStep1 => {
                if (opAggStep1(p, pOp, aOp, aMem, pc, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_AggValue, OP_AggFinal => {
                if (opAggFinal(p, pOp, op, aMem, encoding, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Checkpoint => {
                if (opCheckpoint(db, pOp, aMem, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_JournalMode => {
                if (opJournalMode(p, db, pOp, encoding, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Vacuum => {
                rc = sqlite3RunVacuum(@ptrCast(fp(?[*:0]u8, p, Vdbe_zErrMsg)), db, pOp.p1, if (pOp.p2 != 0) memAt(aMem, pOp.p2) else null);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_IncrVacuum => {
                const pBt = rdPtr(dbEnt(db, pOp.p1), Db_pBt);
                rc = sqlite3BtreeIncrVacuum(pBt);
                if (rc != 0) {
                    if (rc != SQLITE_DONE) {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    }
                    rc = SQLITE_OK;
                    pc = @intCast(pOp.p2);
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Expire => {
                if (pOp.p1 == 0) {
                    sqlite3ExpirePreparedStatements(db, pOp.p2);
                } else {
                    setExpired(p, @intCast(pOp.p2 + 1));
                }
                pc += 1;
                continue :main;
            },
            OP_CursorLock => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                sqlite3BtreeCursorPin(@ptrCast(rdPtr(apCsr[@intCast(pOp.p1)], VC_uc)));
                pc += 1;
                continue :main;
            },
            OP_CursorUnlock => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                sqlite3BtreeCursorUnpin(@ptrCast(rdPtr(apCsr[@intCast(pOp.p1)], VC_uc)));
                pc += 1;
                continue :main;
            },
            OP_TableLock => {
                const isWriteLock: u8 = @intCast(pOp.p3 & 0xff);
                if (isWriteLock != 0 or 0 == (rd(u64, db, sqlite3_flags) & SQLITE_ReadUncommit)) {
                    rc = sqlite3BtreeLockTable(rdPtr(dbEnt(db, pOp.p1), Db_pBt), pOp.p2, isWriteLock);
                    if (rc != 0) {
                        if ((rc & 0xff) == SQLITE_LOCKED) {
                            sqlite3VdbeError(p, "database table is locked: %s", pOp.p4.z orelse @as([*:0]const u8, ""));
                        }
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    }
                }
                pc += 1;
                continue :main;
            },
            OP_VBegin => {
                const pVTab = pOp.p4.pVtab;
                rc = sqlite3VtabBegin(db, pVTab);
                if (pVTab != null) sqlite3VtabImportErrmsg(p, @ptrCast(rdPtr(pVTab, VTable_pVtab)));
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_VCreate => {
                if (opVCreate(p, db, pOp, aMem, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_VDestroy => {
                wr(c_int, db, sqlite3_nVDestroy, rd(c_int, db, sqlite3_nVDestroy) + 1);
                rc = sqlite3VtabCallDestroy(db, pOp.p1, pOp.p4.z.?);
                wr(c_int, db, sqlite3_nVDestroy, rd(c_int, db, sqlite3_nVDestroy) - 1);
                if (rc != 0) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_VOpen => {
                const r = opVOpen(p, db, pOp, &rc);
                switch (r) {
                    .ok => {
                        pc += 1;
                        continue :main;
                    },
                    .no_mem => {
                        exitKind = .no_mem;
                        done = true;
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_VCheck => {
                if (opVCheck(p, db, pOp, aMem, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_VInitIn => {
                const apCsr: [*]?*anyopaque = @ptrCast(@alignCast(rdPtr(p, Vdbe_apCsr).?));
                const pC = apCsr[@intCast(pOp.p1)];
                const pRhs = sqlite3_malloc64(sizeof_ValueList);
                if (pRhs == null) {
                    exitKind = .no_mem;
                    done = true;
                    continue :main;
                }
                wrPtr(pRhs, VL_pCsr, rdPtr(pC, VC_uc));
                wrPtr(pRhs, VL_pOut, @ptrCast(memAt(aMem, pOp.p3)));
                const pOut = out2Prerelease(p, pOp);
                pOut.flags = MEM_Null;
                sqlite3VdbeMemSetPointer(pOut, pRhs, "ValueList", sqlite3VdbeValueListFree);
                pc += 1;
                continue :main;
            },
            OP_VFilter => {
                const r = opVFilter(p, pOp, aMem, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_VColumn => {
                if (opVColumn(p, pOp, aMem, encoding, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_VNext => {
                const r = opVNext(p, pOp, &rc);
                switch (r) {
                    .fall => {
                        pc += 1;
                        if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                        continue :main;
                    },
                    .jump => {
                        pc = @intCast(pOp.p2);
                        if (checkInterrupt(p, db, &rc, &nVmStep, &nProgressLimit, &exitKind, &done)) continue :main;
                        continue :main;
                    },
                    .err => {
                        exitKind = .abort_error;
                        done = true;
                        continue :main;
                    },
                }
            },
            OP_VRename => {
                if (opVRename(p, db, pOp, aMem, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_VUpdate => {
                if (opVUpdate(p, db, pOp, aMem, &rc)) |ek| {
                    exitKind = ek;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_Pagecount => {
                const pOut = out2Prerelease(p, pOp);
                pOut.u.i = sqlite3BtreeLastPage(rdPtr(dbEnt(db, pOp.p1), Db_pBt));
                pc += 1;
                continue :main;
            },
            OP_MaxPgcnt => {
                const pOut = out2Prerelease(p, pOp);
                const pBt = rdPtr(dbEnt(db, pOp.p1), Db_pBt);
                var newMax: u32 = 0;
                if (pOp.p3 != 0) {
                    newMax = sqlite3BtreeLastPage(pBt);
                    if (newMax < @as(u32, @intCast(pOp.p3))) newMax = @intCast(pOp.p3);
                }
                pOut.u.i = sqlite3BtreeMaxPageCount(pBt, newMax);
                pc += 1;
                continue :main;
            },
            OP_Function, OP_PureFunc => {
                if (opFunction(p, db, pOp, aMem, encoding, &rc)) {
                    exitKind = .abort_error;
                    done = true;
                    continue :main;
                }
                pc += 1;
                continue :main;
            },
            OP_ClrSubtype => {
                memAt(aMem, pOp.p1).flags &= ~MEM_Subtype;
                pc += 1;
                continue :main;
            },
            OP_GetSubtype => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pOut = memAt(aMem, pOp.p2);
                if ((pIn1.flags & MEM_Subtype) != 0) {
                    sqlite3VdbeMemSetInt64(pOut, pIn1.eSubtype);
                } else {
                    sqlite3VdbeMemSetNull(pOut);
                }
                pc += 1;
                continue :main;
            },
            OP_SetSubtype => {
                const pIn1 = memAt(aMem, pOp.p1);
                const pOut = memAt(aMem, pOp.p2);
                if ((pIn1.flags & MEM_Null) != 0) {
                    pOut.flags &= ~MEM_Subtype;
                } else {
                    pOut.flags |= MEM_Subtype;
                    pOut.eSubtype = @intCast(pIn1.u.i & 0xff);
                }
                pc += 1;
                continue :main;
            },
            OP_FilterAdd => {
                const pIn1 = memAt(aMem, pOp.p1);
                var h = filterHash(aMem, pOp);
                h %= (@as(u64, @intCast(pIn1.n)) * 8);
                pIn1.z.?[@intCast(h / 8)] |= @as(u8, 1) << @intCast(h & 7);
                pc += 1;
                continue :main;
            },
            OP_Filter => {
                const pIn1 = memAt(aMem, pOp.p1);
                var h = filterHash(aMem, pOp);
                h %= (@as(u64, @intCast(pIn1.n)) * 8);
                if ((pIn1.z.?[@intCast(h / 8)] & (@as(u8, 1) << @intCast(h & 7))) == 0) {
                    const idx = Vdbe_aCounter + SQLITE_STMTSTATUS_FILTER_HIT * 4;
                    wr(u32, p, idx, rd(u32, p, idx) +% 1);
                    pc = @intCast(pOp.p2);
                    continue :main;
                } else {
                    const idx = Vdbe_aCounter + SQLITE_STMTSTATUS_FILTER_MISS * 4;
                    wr(u32, p, idx, rd(u32, p, idx) +% 1);
                }
                pc += 1;
                continue :main;
            },
            OP_Trace, OP_Init => {
                opInit(p, db, pOp, aOp, op, &pc);
                continue :main;
            },
            OP_Abortable => {
                pc += 1;
                continue :main;
            },
            OP_ReleaseReg => {
                // DEBUG-only opcode; in production it should not appear, but
                // be defensive and treat as no-op.
                pc += 1;
                continue :main;
            },
            else => {
                // OP_Noop, OP_Explain, OP_CursorHint, OP_ColumnsUsed (omitted),
                // OP_Offset (omitted) — all no-ops in this build.
                pc += 1;
                continue :main;
            },
        }
    }

    // ---- shared cleanup tail (abort_due_to_error / vdbe_return / …) ----------
    return finishExec(p, db, exitKind, rc, &nVmStep, nProgressLimit, resetSchemaOnFault, &aOp, pOp);
}

// ===========================================================================
// Shared exit / interrupt helpers.
// ===========================================================================

// check_for_interrupt: returns true if the caller must `continue :main` because
// the exit machinery was triggered (interrupt or progress abort).
inline fn checkInterrupt(p: ?*Vdbe, db: ?*anyopaque, rc: *c_int, nVmStep: *u64, nProgressLimit: *u64, exitKind: *ExitKind, done: *bool) bool {
    _ = p;
    if (isInterrupted(db)) {
        rc.* = SQLITE_INTERRUPT;
        exitKind.* = .abort_error;
        done.* = true;
        return true;
    }
    while (nVmStep.* >= nProgressLimit.* and rdPtr(db, sqlite3_xProgress) != null) {
        const nOps = rd(c_int, db, sqlite3_nProgressOps);
        nProgressLimit.* += @intCast(nOps);
        const xProg: ProgressCb = @ptrCast(rdPtr(db, sqlite3_xProgress));
        if (xProg.?(rdPtr(db, sqlite3_pProgressArg)) != 0) {
            nProgressLimit.* = LARGEST_UINT64;
            rc.* = SQLITE_INTERRUPT;
            exitKind.* = .abort_error;
            done.* = true;
            return true;
        }
    }
    return false;
}

fn finishExec(p: ?*Vdbe, db: ?*anyopaque, kind0: ExitKind, rc0: c_int, nVmStep: *u64, nProgressLimit0: u64, resetSchemaOnFault: u8, aOpRef: *[*]Op, pOp: *Op) c_int {
    var rc = rc0;
    var kind = kind0;
    var nProgressLimit = nProgressLimit0;
    const aOp = aOpRef.*;

    if (kind == .too_big) {
        sqlite3VdbeError(p, "string or blob too big");
        rc = SQLITE_TOOBIG;
        kind = .abort_error;
    } else if (kind == .no_mem) {
        sqlite3OomFault(db);
        sqlite3VdbeError(p, "out of memory");
        rc = SQLITE_NOMEM;
        kind = .abort_error;
    } else if (kind == .abort_interrupt) {
        rc = SQLITE_INTERRUPT;
        kind = .abort_error;
    }

    if (kind == .abort_error) {
        // abort_due_to_error:
        if (mallocFailed(db)) {
            rc = SQLITE_NOMEM;
        } else if (rc == SQLITE_IOERR_CORRUPTFS) {
            rc = SQLITE_CORRUPT;
        }
        if (rd(?[*:0]const u8, p, Vdbe_zErrMsg) == null and rc != SQLITE_IOERR_NOMEM) {
            sqlite3VdbeError(p, "%s", sqlite3ErrStr(rc));
        }
        wr(c_int, p, Vdbe_rc, rc);
        sqlite3SystemError(db, rc);
        vdbeLogAbort(p, rc, pOp, aOp);
        if (rdU8(p, Vdbe_eVdbeState) == VDBE_RUN_STATE) _ = sqlite3VdbeHalt(p);
        if (rc == SQLITE_IOERR_NOMEM) sqlite3OomFault(db);
        if (rc == SQLITE_CORRUPT and rdU8(db, sqlite3_autoCommit) == 0) {
            wr(u64, db, sqlite3_flags, rd(u64, db, sqlite3_flags) | SQLITE_CorruptRdOnly);
        }
        rc = SQLITE_ERROR;
        if (resetSchemaOnFault > 0) {
            sqlite3ResetOneSchema(db, resetSchemaOnFault - 1);
        }
    }

    // vdbe_return:
    while (nVmStep.* >= nProgressLimit and rdPtr(db, sqlite3_xProgress) != null) {
        const nOps = rd(c_int, db, sqlite3_nProgressOps);
        nProgressLimit += @intCast(nOps);
        const xProg: ProgressCb = @ptrCast(rdPtr(db, sqlite3_xProgress));
        if (xProg.?(rdPtr(db, sqlite3_pProgressArg)) != 0) {
            nProgressLimit = LARGEST_UINT64;
            rc = SQLITE_INTERRUPT;
            // upstream goes back to abort_due_to_error; emulate minimal path
            wr(c_int, p, Vdbe_rc, rc);
            rc = SQLITE_ERROR;
            break;
        }
    }
    const idx = Vdbe_aCounter + SQLITE_STMTSTATUS_VM_STEP * 4;
    wr(u32, p, idx, rd(u32, p, idx) +% @as(u32, @truncate(nVmStep.*)));
    if (rd(c_int, p, Vdbe_lockMask) != 0) {
        sqlite3VdbeLeave(p);
    }
    return rc;
}

// out2Prerelease / memAt-using small inline helpers are defined above.

inline fn deephemeralize(p: *Mem) bool {
    // Deephemeralize(P): if MEM_Ephem && MakeWriteable -> goto no_mem
    if ((p.flags & MEM_Ephem) != 0 and sqlite3VdbeMemMakeWriteable(p) != 0) return true;
    return false;
}

// SQLITE_STATIC destructor sentinel = (void(*)(void*))0
inline fn sqliteStatic() ?*const fn (?*anyopaque) callconv(.c) void {
    return null;
}

fn indexNColumn(pIdx: ?*Index) u16 {
    // Index.nColumn is an i16 at a known offset; probe says off 78 prod. We
    // read it as i16 to avoid width bugs. (Used only by OP_IFindKey.)
    return @bitCast(rd(i16, pIdx, off("Index_nColumn", 96, 96)));
}
