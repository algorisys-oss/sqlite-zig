//! Zig port of SQLite's global data definitions (src/global.c).
//!
//! This module DEFINES the global variables and constant tables that every
//! other subsystem binds to by symbol (and, for `sqlite3Config`, reads by
//! ground-truth byte offset). It is the keystone of the migration: getting any
//! byte wrong here silently corrupts the whole engine.
//!
//! Symbols defined (all with C ABI):
//!   * `sqlite3Config`        — writable global config singleton (export var).
//!                              Modeled as a raw `[N]u8` byte array so ONE Zig
//!                              object serves both the production build and the
//!                              `--dev` testfixture build (which adds
//!                              `bJsonSelfcheck` and a trailing `aTune[6]`),
//!                              with the default fields written at their exact
//!                              C offsets. Size: 440 (prod) / 488 (SQLITE_DEBUG).
//!   * `sqlite3UpperToLower`  — 256-byte upper→lower map + 18 trailing
//!                              comparison-result flag bytes (aLTb/aEQb/aGTb).
//!   * `sqlite3aLTb/aEQb/aGTb`— pointers into sqlite3UpperToLower[256-OP_Ne...].
//!   * `sqlite3CtypeMap`      — 256-byte ctype classification table.
//!   * `sqlite3OpcodeProperty`— OPFLG_INITIALIZER opcode-property table.
//!   * `sqlite3StrBINARY`     — "BINARY" (default collation name).
//!   * `sqlite3StdTypeLen/Affinity/StdType` — standard typename tables.
//!   * `sqlite3OomStr`        — singleton sqlite3_str returned on OOM.
//!   * `sqlite3BuiltinFunctions` — global builtin function hash (export var,
//!                              zero-initialized; populated by sqlite3_initialize).
//!   * `sqlite3PendingByte`   — the WSD pending-byte position (export var).
//!   * `sqlite3TreeTrace`/`sqlite3WhereTrace` — tracing flags (export var).
//!   * `sqlite3CoverageCounter` — coverage counter (SQLITE_DEBUG / COVERAGE only).
//!
//! SQLITE_OMIT_WSD is OFF in this build, so these are plain globals (no GLOBAL()
//! indirection). The const tables are `export const`; the mutable globals are
//! `export var`.

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ---------------------------------------------------------------------------
// Compile-time constants mirroring the C -D flags / sqliteInt.h defaults that
// determine sqlite3Config's default field values. Verified against build.zig
// `sqlite_flags` and vendor/tsrc/sqliteInt.h.
// ---------------------------------------------------------------------------
const OP_Ne: usize = 53; // opcodes.h: #define OP_Ne 53

const SQLITE_DEFAULT_MEMSTATUS: i32 = 1; // bMemstat
// SQLITE_THREADSAFE==1 in this build -> bCoreMutex=1, bFullMutex=1.
const SQLITE_USE_URI: i32 = 0; // bOpenUri (default 0)
const SQLITE_ALLOW_COVERING_INDEX_SCAN: i32 = 1; // bUseCis
const MX_STRLEN: i32 = 0x7ffffffe; // mxStrlen
const SZLOOKASIDE: i32 = 1200; // SQLITE_DEFAULT_LOOKASIDE size
const NLOOKASIDE: i32 = 40; // SQLITE_DEFAULT_LOOKASIDE count (two-size build)
const STMTJRNL_SPILL: i32 = 64 * 1024; // nStmtSpill (SQLITE_STMTJRNL_SPILL)
const SZMMAP: i64 = 0; // SQLITE_DEFAULT_MMAP_SIZE (0 == off)
const MXMMAP: i64 = 0x7fff0000; // SQLITE_MAX_MMAP_SIZE (2147418112)
const PCACHE_INITSZ: i32 = 20; // SQLITE_DEFAULT_PCACHE_INITSZ -> nPage
const SORTER_PMASZ: i32 = 250; // SQLITE_SORTER_PMASZ -> szPma
const MEMDB_MAXSIZE: i64 = 1073741824; // SQLITE_MEMDB_DEFAULT_MAXSIZE -> mxMemdbSize
const ONCE_RESET_THRESHOLD: i32 = 0x7ffffffe; // iOnceResetThreshold
const SORTERREF_SIZE: i32 = 0x7fffffff; // SQLITE_DEFAULT_SORTERREF_SIZE -> szSorterRef

// ---------------------------------------------------------------------------
// sqlite3Config — the writable global configuration singleton.
//
// Modeled as a byte array of the exact C sizeof so the layout matches BOTH
// configs. The size and every initialized offset are cross-checked against
// src/c_layout.zig (Sqlite3Config_* / sizeof_Sqlite3Config) below. Default
// non-zero fields are written at their ground-truth offsets in a comptime
// initializer; all other bytes are zero (as in the C initializer).
// ---------------------------------------------------------------------------
const config_size = L.sizeof_Sqlite3Config; // 440 prod / 488 tf

fn buildConfig() [config_size]u8 {
    var b = std.mem.zeroes([config_size]u8);
    const w32 = struct {
        fn put(buf: []u8, off: usize, v: i32) void {
            std.mem.writeInt(i32, buf[off..][0..4], v, .little);
        }
    }.put;
    const w64 = struct {
        fn put(buf: []u8, off: usize, v: i64) void {
            std.mem.writeInt(i64, buf[off..][0..8], v, .little);
        }
    }.put;

    w32(&b, L.Sqlite3Config_bMemstat, SQLITE_DEFAULT_MEMSTATUS); // off 0
    b[L.Sqlite3Config_bCoreMutex] = 1; // off 4
    b[L.Sqlite3Config_bFullMutex] = 1; // off 5 (SQLITE_THREADSAFE==1)
    b[L.Sqlite3Config_bOpenUri] = @intCast(SQLITE_USE_URI); // off 6 (=0)
    b[L.Sqlite3Config_bUseCis] = @intCast(SQLITE_ALLOW_COVERING_INDEX_SCAN); // off 7
    // bSmallMalloc (off 8) = 0
    b[L.Sqlite3Config_bExtraSchemaChecks] = 1; // off 9
    // bJsonSelfcheck (off 10, SQLITE_DEBUG only) = 0
    w32(&b, L.Sqlite3Config_mxStrlen, MX_STRLEN); // off 12
    // neverCorrupt (off 16) = 0
    w32(&b, L.Sqlite3Config_szLookaside, SZLOOKASIDE); // off 20
    w32(&b, L.Sqlite3Config_nLookaside, NLOOKASIDE); // off 24
    w32(&b, L.Sqlite3Config_nStmtSpill, STMTJRNL_SPILL); // off 28
    // m (off 32), mutex (96), pcache2 (168), pHeap (272), nHeap/mn/mx = 0
    w64(&b, L.Sqlite3Config_szMmap, SZMMAP); // off 296 (=0)
    w64(&b, L.Sqlite3Config_mxMmap, MXMMAP); // off 304
    // pPage (312), szPage (320) = 0
    w32(&b, L.Sqlite3Config_nPage, PCACHE_INITSZ); // off 324
    // mxParserStack (328), sharedCacheEnabled (332) = 0
    w32(&b, L.Sqlite3Config_szPma, SORTER_PMASZ); // off 336
    // isInit..pInitMutex, xLog/pLogArg = 0
    w64(&b, L.Sqlite3Config_mxMemdbSize, MEMDB_MAXSIZE); // off 392
    // xTestCallback (400) = 0; bLocaltimeFault (408) = 0; xAltLocaltime (416) = 0
    w32(&b, L.Sqlite3Config_iOnceResetThreshold, ONCE_RESET_THRESHOLD); // off 424
    // szSorterRef is at iOnceResetThreshold + 4 (off 428). c_layout has no
    // dedicated symbol for it; derive from the adjacent ground-truth offset.
    w32(&b, L.Sqlite3Config_iOnceResetThreshold + 4, SORTERREF_SIZE); // off 428
    // iPrngSeed (432) = 0; aTune[] (440, SQLITE_DEBUG only) = 0
    return b;
}

pub export var sqlite3Config: [config_size]u8 = buildConfig();

comptime {
    // Ground-truth cross-checks against the C struct (src/c_layout.zig).
    std.debug.assert(config_size == L.sizeof_Sqlite3Config);
    std.debug.assert(L.Sqlite3Config_iPrngSeed == 432);
    std.debug.assert(L.Sqlite3Config_szPma == 336);
    std.debug.assert(L.Sqlite3Config_mxMemdbSize == 392);
    std.debug.assert(L.Sqlite3Config_nPage == 324);
    std.debug.assert(L.Sqlite3Config_mxMmap == 304);
    std.debug.assert(L.Sqlite3Config_iOnceResetThreshold == 424);
    // bJsonSelfcheck (off 10) only exists in the SQLITE_DEBUG/testfixture build,
    // which is exactly when config_size==488.
    if (config.sqlite_debug) {
        std.debug.assert(config_size == 488);
    } else {
        std.debug.assert(config_size == 440);
    }
}

// ---------------------------------------------------------------------------
// sqlite3UpperToLower[] — upper→lower case map (256 bytes) followed by the 18
// comparison-result flag bytes (aLTb / aEQb / aGTb), exactly as in global.c.
// ---------------------------------------------------------------------------
pub export const sqlite3UpperToLower: [256 + 18]u8 = .{
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,
    18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,
    36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53,
    54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  97,  98,  99,  100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122, 91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107,
    108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
    126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161,
    162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
    198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
    216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
    234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
    252, 253, 254, 255,
    // The following 18 integers are unrelated to case conversion; they are the
    // aLTb[]/aEQb[]/aGTb[] comparison-result tables appended here to keep the
    // negative-offset pointer arithmetic below in-bounds (matches global.c).
    // NE EQ GT LE LT GE
    1, 0, 0, 1, 1, 0, // aLTb[]: compare(A,B) < 0
    0, 1, 0, 1, 0, 1, // aEQb[]: compare(A,B) == 0
    1, 0, 1, 0, 0, 1, // aGTb[]: compare(A,B) > 0
};

pub export const sqlite3aLTb: *const u8 = &sqlite3UpperToLower[256 - OP_Ne];
pub export const sqlite3aEQb: *const u8 = &sqlite3UpperToLower[256 + 6 - OP_Ne];
pub export const sqlite3aGTb: *const u8 = &sqlite3UpperToLower[256 + 12 - OP_Ne];

// ---------------------------------------------------------------------------
// sqlite3CtypeMap[256] — character classification table.
// ---------------------------------------------------------------------------
pub export const sqlite3CtypeMap: [256]u8 = .{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00..07
    0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, // 08..0f
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 10..17
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 18..1f
    0x01, 0x00, 0x80, 0x00, 0x40, 0x00, 0x00, 0x80, // 20..27
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 28..2f
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, // 30..37
    0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 38..3f
    0x00, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x02, // 40..47
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // 48..4f
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // 50..57
    0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x00, 0x40, // 58..5f
    0x80, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x22, // 60..67
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // 68..6f
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // 70..77
    0x22, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, // 78..7f
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // 80..87
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // 88..8f
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // 90..97
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // 98..9f
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // a0..a7
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // a8..af
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // b0..b7
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // b8..bf
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // c0..c7
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // c8..cf
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // d0..d7
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // d8..df
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // e0..e7
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // e8..ef
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // f0..f7
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // f8..ff
};

// ---------------------------------------------------------------------------
// sqlite3BuiltinFunctions — global builtin-function hash (FuncDefHash).
// Zero-initialized here; populated by sqlite3_initialize / registerBuiltinFunctions.
// FuncDefHash is { FuncDef *a[SQLITE_FUNC_HASH_SZ]; } (23 pointers => 184 bytes).
// ---------------------------------------------------------------------------
const FUNC_HASH_SZ = 23; // SQLITE_FUNC_HASH_SZ
pub export var sqlite3BuiltinFunctions: [FUNC_HASH_SZ]?*anyopaque = std.mem.zeroes([FUNC_HASH_SZ]?*anyopaque);

comptime {
    // FuncDefHash is { FuncDef *a[23]; } => 23 * 8 = 184 bytes.
    std.debug.assert(@sizeOf(@TypeOf(sqlite3BuiltinFunctions)) == FUNC_HASH_SZ * @sizeOf(usize));
}

// ---------------------------------------------------------------------------
// sqlite3OomStr — singleton sqlite3_str returned when malloc can't make a real
// one. Layout: { db, zText, nAlloc, mxAlloc, nChar, accError, printfFlags }.
// Initialized as {0,0,0,0,0,SQLITE_NOMEM,0}. Modeled as the exact-size byte
// array (sizeof StrAccum) with accError set at its ground-truth offset.
// ---------------------------------------------------------------------------
const SQLITE_NOMEM: u8 = 7;

fn buildOomStr() [L.sizeof_StrAccum]u8 {
    var b = std.mem.zeroes([L.sizeof_StrAccum]u8);
    // accError is the byte just before printfFlags (off 29) => off 28.
    b[L.StrAccum_printfFlags - 1] = SQLITE_NOMEM;
    return b;
}
pub export const sqlite3OomStr: [L.sizeof_StrAccum]u8 = buildOomStr();

// ---------------------------------------------------------------------------
// Coverage / profile counters (only in SQLITE_DEBUG or coverage builds).
// ---------------------------------------------------------------------------
var coverage_counter: c_uint = 0;
comptime {
    // SQLITE_COVERAGE_TEST || SQLITE_DEBUG. We only know SQLITE_DEBUG here.
    if (config.sqlite_debug) {
        @export(&coverage_counter, .{ .name = "sqlite3CoverageCounter" });
    }
}

// ---------------------------------------------------------------------------
// sqlite3PendingByte — WSD pending-byte position (mutable; main.c can move it
// via sqlite3_test_control). SQLITE_OMIT_WSD is OFF, so it's a plain global.
// ---------------------------------------------------------------------------
pub export var sqlite3PendingByte: c_int = 0x40000000;

// ---------------------------------------------------------------------------
// Tracing flags set by SQLITE_TESTCTRL_TRACEFLAGS.
// ---------------------------------------------------------------------------
pub export var sqlite3TreeTrace: u32 = 0;
pub export var sqlite3WhereTrace: u32 = 0;

// ---------------------------------------------------------------------------
// sqlite3OpcodeProperty[] — OPFLG_INITIALIZER (from mkopcodeh, via opcodes.h).
// ---------------------------------------------------------------------------
pub export const sqlite3OpcodeProperty = [_]u8{
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x41, 0x00, //   0
    0x81, 0x01, 0x01, 0x81, 0x83, 0x83, 0x01, 0x01, //   8
    0x03, 0x03, 0x01, 0x12, 0x01, 0xc9, 0xc9, 0xc9, //  16
    0xc9, 0x01, 0x49, 0x49, 0x49, 0x49, 0xc9, 0x49, //  24
    0xc1, 0x01, 0x41, 0x41, 0xc1, 0x01, 0x01, 0x41, //  32
    0x41, 0x41, 0x41, 0x26, 0x26, 0x41, 0x41, 0x09, //  40
    0x23, 0x0b, 0x81, 0x03, 0x03, 0x0b, 0x0b, 0x0b, //  48
    0x0b, 0x0b, 0x0b, 0x01, 0x01, 0x03, 0x03, 0x03, //  56
    0x01, 0x41, 0x01, 0x00, 0x00, 0x02, 0x02, 0x08, //  64
    0x00, 0x10, 0x10, 0x10, 0x00, 0x10, 0x00, 0x10, //  72
    0x10, 0x00, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00, //  80
    0x02, 0x02, 0x02, 0x00, 0x00, 0x12, 0x1e, 0x20, //  88
    0x40, 0x00, 0x00, 0x00, 0x10, 0x10, 0x00, 0x26, //  96
    0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, // 104
    0x26, 0x40, 0x40, 0x12, 0x00, 0x40, 0x10, 0x40, // 112
    0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x40, // 120
    0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, // 128
    0x00, 0x50, 0x00, 0x40, 0x04, 0x04, 0x00, 0x40, // 136
    0x50, 0x40, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, // 144
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x10, // 152
    0x00, 0x04, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, // 160
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, // 168
    0x10, 0x50, 0x40, 0x00, 0x10, 0x10, 0x02, 0x12, // 176
    0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 184
};

// ---------------------------------------------------------------------------
// sqlite3StrBINARY[] — name of the default collating sequence. A char[]; its
// ADDRESS is the data (consumers take &sqlite3StrBINARY). NUL-terminated.
// ---------------------------------------------------------------------------
pub export const sqlite3StrBINARY: [7]u8 = "BINARY\x00".*;

// ---------------------------------------------------------------------------
// Standard typename tables. These must match the COLTYPE_* definitions.
//   sqlite3StdType[]         the datatype names
//   sqlite3StdTypeLen[]      length (bytes) of each name
//   sqlite3StdTypeAffinity[] affinity of each name
// ---------------------------------------------------------------------------
const SQLITE_AFF_BLOB: u8 = 0x41;
const SQLITE_AFF_TEXT: u8 = 0x42;
const SQLITE_AFF_NUMERIC: u8 = 0x43;
const SQLITE_AFF_INTEGER: u8 = 0x44;
const SQLITE_AFF_REAL: u8 = 0x45;

pub export const sqlite3StdTypeLen: [6]u8 = .{ 3, 4, 3, 7, 4, 4 };

pub export const sqlite3StdTypeAffinity: [6]u8 = .{
    SQLITE_AFF_NUMERIC,
    SQLITE_AFF_BLOB,
    SQLITE_AFF_INTEGER,
    SQLITE_AFF_INTEGER,
    SQLITE_AFF_REAL,
    SQLITE_AFF_TEXT,
};

pub export const sqlite3StdType: [6][*:0]const u8 = .{
    "ANY",
    "BLOB",
    "INT",
    "INTEGER",
    "REAL",
    "TEXT",
};
