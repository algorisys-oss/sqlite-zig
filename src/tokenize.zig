//! Zig port of SQLite's src/tokenize.c — the SQL tokenizer.
//!
//! Splits SQL text into tokens (sqlite3GetToken), recognizes keywords via the
//! generated hash table (keywordhash.h reproduced here), and drives the
//! Lemon-generated parser (sqlite3RunParser). sqlite3_complete lives in its own
//! module (complete.c -> complete.zig) and is not our concern.
//!
//! Exported (non-static) symbols — the complete external set of tokenize.c
//! (with this project's config: SQLITE_ASCII, SQLITE_OMIT_* all OFF,
//! SQLITE_ENABLE_NORMALIZE OFF, SQLITE_OMIT_WINDOWFUNC OFF). keywordhash.h is
//! #included into tokenize.c, so the symbols it defines are OWNED here:
//!   - sqlite3GetToken
//!   - sqlite3RunParser
//!   - sqlite3IsIdChar
//!   - sqlite3KeywordCode       (from keywordhash.h)
//!   - sqlite3_keyword_name     (from keywordhash.h)
//!   - sqlite3_keyword_count    (from keywordhash.h)
//!   - sqlite3_keyword_check    (from keywordhash.h)
//! Static helpers (keywordCode, getToken, analyzeWindowKeyword,
//! analyzeOverKeyword, analyzeFilterKeyword) become private Zig fns.
//!
//! sqlite3Normalize is excluded — SQLITE_ENABLE_NORMALIZE is OFF in both build
//! configs (production and --dev testfixture).
//!
//! ─── Config assumptions (true in both build configs) ───────────────────────
//!   * SQLITE_ASCII (not EBCDIC) → aiClass/charMap/IdChar use the ASCII tables.
//!   * SQLITE_OMIT_WINDOWFUNC / OMIT_FLOATING_POINT / OMIT_HEX_INTEGER /
//!     OMIT_BLOB_LITERAL / OMIT_TCL_VARIABLE / OMIT_VIRTUALTABLE all OFF.
//!   * sqlite3Parser_ENGINEALWAYSONSTACK / YYTRACKMAXSTACKDEPTH OFF → the
//!     parser engine is heap-allocated (sqlite3ParserAlloc/Free).
//!   * IN_SPECIAL_PARSE / IN_RENAME_OBJECT are the runtime forms keyed on
//!     pParse->eParseMode (OMIT_VIRTUALTABLE / rename support compiled in).
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

// ─── ground-truth offsets (config-invariant — verified equal under PROD & TF) ─
// Parse
const Parse_db_off = off("Parse_db", 0);
const Parse_rc_off = off("Parse_rc", 24);
const Parse_zErrMsg_off = off("Parse_zErrMsg", 8);
const Parse_nErr_off = off("Parse_nErr", 52);
const Parse_sLastToken_off = off("Parse_sLastToken", 280);
const Parse_nVar_off = off("Parse_nVar", 296);
const Parse_eParseMode_off = off("Parse_eParseMode", 300);
const Parse_pVList_off = off("Parse_pVList", 320); // probed: PROD==TF==320
const Parse_zTail_off = off("Parse_zTail", 336);
const Parse_pNewTable_off = off("Parse_pNewTable", 344);
const Parse_pNewTrigger_off = off("Parse_pNewTrigger", 360);
const Parse_apVtabLock_off = off("Parse_apVtabLock", 392);
const Parse_prepFlags_off = off("Parse_prepFlags", 34);
// sqlite3
const sqlite3_aLimit_off = off("sqlite3_aLimit", 136);
const sqlite3_nVdbeActive_off = off("sqlite3_nVdbeActive", 208);
const sqlite3_u1_isInterrupted_off = off("sqlite3_u1", 424); // u1.isInterrupted == start of u1
const sqlite3_initBusy_off = off("sqlite3_initBusy", 197);
const sqlite3_flags_off = off("sqlite3_flags", 48);
const sqlite3_mallocFailed_off = off("sqlite3_mallocFailed", 103);
const sqlite3_pParse_off = off("sqlite3_pParse", 344);
// Token { const char *z; u32 n; }
const Token_z_off = off("Token_z", 0);
const Token_n_off = off("Token_n", 8);

// ─── constants ──────────────────────────────────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_INTERRUPT: c_int = 9;
const SQLITE_TOOBIG: c_int = 18;
const SQLITE_NOMEM: c_int = 7;
const SQLITE_DONE: c_int = 101;

const SQLITE_LIMIT_SQL_LENGTH: usize = 1;
const SQLITE_DIGIT_SEPARATOR: u8 = '_';
const SQLITE_Comments: u64 = 0x00040 << 32; // HI(0x00040)
const SQLITE_PREPARE_DONT_LOG: u32 = 0x10;
const PARSE_MODE_NORMAL: u8 = 0;
const PARSE_MODE_RENAME: u8 = 2;

// Token type codes (parse.h — identical in both configs).
const TK_SEMI: c_int = 1;
const TK_AS: c_int = 24;
const TK_LP: c_int = 22;
const TK_RP: c_int = 23;
const TK_ID: c_int = 60;
const TK_BITAND: c_int = 103;
const TK_BITOR: c_int = 104;
const TK_LSHIFT: c_int = 105;
const TK_RSHIFT: c_int = 106;
const TK_PLUS: c_int = 107;
const TK_MINUS: c_int = 108;
const TK_STAR: c_int = 109;
const TK_SLASH: c_int = 110;
const TK_REM: c_int = 111;
const TK_CONCAT: c_int = 112;
const TK_PTR: c_int = 113;
const TK_BITNOT: c_int = 115;
const TK_STRING: c_int = 118;
const TK_JOIN_KW: c_int = 119;
const TK_DOT: c_int = 142;
const TK_NE: c_int = 53;
const TK_EQ: c_int = 54;
const TK_GT: c_int = 55;
const TK_LE: c_int = 56;
const TK_LT: c_int = 57;
const TK_GE: c_int = 58;
const TK_COMMA: c_int = 25;
const TK_FLOAT: c_int = 154;
const TK_BLOB: c_int = 155;
const TK_INTEGER: c_int = 156;
const TK_VARIABLE: c_int = 157;
const TK_WINDOW: c_int = 165;
const TK_OVER: c_int = 166;
const TK_FILTER: c_int = 167;
const TK_QNUMBER: c_int = 183;
const TK_SPACE: c_int = 184;
const TK_COMMENT: c_int = 185;
const TK_ILLEGAL: c_int = 186;

// Character classes (CC_*) for the first byte of a token.
const CC_X: u8 = 0;
const CC_KYWD0: u8 = 1;
const CC_KYWD: u8 = 2;
const CC_DIGIT: u8 = 3;
const CC_DOLLAR: u8 = 4;
const CC_VARALPHA: u8 = 5;
const CC_VARNUM: u8 = 6;
const CC_SPACE: u8 = 7;
const CC_QUOTE: u8 = 8;
const CC_QUOTE2: u8 = 9;
const CC_PIPE: u8 = 10;
const CC_MINUS: u8 = 11;
const CC_LT: u8 = 12;
const CC_GT: u8 = 13;
const CC_EQ: u8 = 14;
const CC_BANG: u8 = 15;
const CC_SLASH: u8 = 16;
const CC_LP: u8 = 17;
const CC_RP: u8 = 18;
const CC_SEMI: u8 = 19;
const CC_PLUS: u8 = 20;
const CC_STAR: u8 = 21;
const CC_PERCENT: u8 = 22;
const CC_COMMA: u8 = 23;
const CC_AND: u8 = 24;
const CC_TILDA: u8 = 25;
const CC_DOT: u8 = 26;
const CC_ID: u8 = 27;
const CC_ILLEGAL: u8 = 28;
const CC_NUL: u8 = 29;
const CC_BOM: u8 = 30;

// SQLITE_ASCII character-class table (identical to aiClass[] in tokenize.c).
const aiClass = [256]u8{
    29, 28, 28, 28, 28, 28, 28, 28, 28, 7,  7,  28, 7,  7,  28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    7,  15, 8,  5,  4,  22, 24, 8,  17, 18, 21, 20, 23, 11, 26, 16,
    3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  5,  19, 12, 14, 13, 6,
    5,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  0,  2,  2,  9,  28, 28, 28, 2,
    8,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  0,  2,  2,  28, 10, 28, 25, 28,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 30,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
};

// ─── extern C-ABI types & helpers ────────────────────────────────────────────
const Parse = anyopaque;
const Sqlite3 = anyopaque;
const Table = anyopaque;
const Trigger = anyopaque;

// Token is passed BY VALUE to sqlite3Parser; mirror its C layout exactly.
const Token = extern struct {
    z: ?[*]const u8,
    n: u32,
};

// Global ctype tables (defined in global.c, stay C).
extern const sqlite3CtypeMap: [256]u8;
extern const sqlite3UpperToLower: [256]u8;

// Lemon parser interface (parse.c stays C).
extern fn sqlite3ParserAlloc(xMalloc: ?*const fn (u64) callconv(.c) ?*anyopaque, pParse: ?*Parse) ?*anyopaque;
extern fn sqlite3ParserFree(p: ?*anyopaque, xFree: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3Parser(yyp: ?*anyopaque, yymajor: c_int, yyminor: Token) void;
extern fn sqlite3ParserFallback(iToken: c_int) c_int;

// Memory + error helpers.
extern fn sqlite3Malloc(n: u64) callconv(.c) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) callconv(.c) void;
extern fn sqlite3OomFault(db: ?*Sqlite3) ?*anyopaque;
extern fn sqlite3DbStrDup(db: ?*Sqlite3, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbNNFreeNN(db: ?*Sqlite3, p: ?*anyopaque) void;
extern fn sqlite3ErrStr(rc: c_int) ?[*:0]const u8;
extern fn sqlite3ErrorMsg(pParse: ?*Parse, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_log(iErrCode: c_int, fmt: [*:0]const u8, ...) void;
extern fn sqlite3DeleteTable(db: ?*Sqlite3, pTab: ?*Table) void;
extern fn sqlite3DeleteTrigger(db: ?*Sqlite3, pTrig: ?*Trigger) void;

// ─── keyword hash table (reproduced from keywordhash.h) ──────────────────────
const zKWText = [666]u8{
    'R', 'E', 'I', 'N', 'D', 'E', 'X', 'E', 'D', 'E', 'S', 'C', 'A', 'P', 'E', 'A', 'C', 'H',
    'E', 'C', 'K', 'E', 'Y', 'B', 'E', 'F', 'O', 'R', 'E', 'I', 'G', 'N', 'O', 'R', 'E', 'G',
    'E', 'X', 'P', 'L', 'A', 'I', 'N', 'S', 'T', 'E', 'A', 'D', 'D', 'A', 'T', 'A', 'B', 'A',
    'S', 'E', 'L', 'E', 'C', 'T', 'A', 'B', 'L', 'E', 'F', 'T', 'H', 'E', 'N', 'D', 'E', 'F',
    'E', 'R', 'R', 'A', 'B', 'L', 'E', 'L', 'S', 'E', 'X', 'C', 'L', 'U', 'D', 'E', 'L', 'E',
    'T', 'E', 'M', 'P', 'O', 'R', 'A', 'R', 'Y', 'I', 'S', 'N', 'U', 'L', 'L', 'S', 'A', 'V',
    'E', 'P', 'O', 'I', 'N', 'T', 'E', 'R', 'S', 'E', 'C', 'T', 'I', 'E', 'S', 'N', 'O', 'T',
    'N', 'U', 'L', 'L', 'I', 'K', 'E', 'X', 'C', 'E', 'P', 'T', 'R', 'A', 'N', 'S', 'A', 'C',
    'T', 'I', 'O', 'N', 'A', 'T', 'U', 'R', 'A', 'L', 'T', 'E', 'R', 'A', 'I', 'S', 'E', 'X',
    'C', 'L', 'U', 'S', 'I', 'V', 'E', 'X', 'I', 'S', 'T', 'S', 'C', 'O', 'N', 'S', 'T', 'R',
    'A', 'I', 'N', 'T', 'O', 'F', 'F', 'S', 'E', 'T', 'R', 'I', 'G', 'G', 'E', 'R', 'A', 'N',
    'G', 'E', 'N', 'E', 'R', 'A', 'T', 'E', 'D', 'E', 'T', 'A', 'C', 'H', 'A', 'V', 'I', 'N',
    'G', 'L', 'O', 'B', 'E', 'G', 'I', 'N', 'N', 'E', 'R', 'E', 'F', 'E', 'R', 'E', 'N', 'C',
    'E', 'S', 'U', 'N', 'I', 'Q', 'U', 'E', 'R', 'Y', 'W', 'I', 'T', 'H', 'O', 'U', 'T', 'E',
    'R', 'E', 'L', 'E', 'A', 'S', 'E', 'A', 'T', 'T', 'A', 'C', 'H', 'B', 'E', 'T', 'W', 'E',
    'E', 'N', 'O', 'T', 'H', 'I', 'N', 'G', 'R', 'O', 'U', 'P', 'S', 'C', 'A', 'S', 'C', 'A',
    'D', 'E', 'F', 'A', 'U', 'L', 'T', 'C', 'A', 'S', 'E', 'C', 'O', 'L', 'L', 'A', 'T', 'E',
    'C', 'R', 'E', 'A', 'T', 'E', 'C', 'U', 'R', 'R', 'E', 'N', 'T', '_', 'D', 'A', 'T', 'E',
    'I', 'M', 'M', 'E', 'D', 'I', 'A', 'T', 'E', 'J', 'O', 'I', 'N', 'S', 'E', 'R', 'T', 'M',
    'A', 'T', 'C', 'H', 'P', 'L', 'A', 'N', 'A', 'L', 'Y', 'Z', 'E', 'P', 'R', 'A', 'G', 'M',
    'A', 'T', 'E', 'R', 'I', 'A', 'L', 'I', 'Z', 'E', 'D', 'E', 'F', 'E', 'R', 'R', 'E', 'D',
    'I', 'S', 'T', 'I', 'N', 'C', 'T', 'U', 'P', 'D', 'A', 'T', 'E', 'V', 'A', 'L', 'U', 'E',
    'S', 'V', 'I', 'R', 'T', 'U', 'A', 'L', 'W', 'A', 'Y', 'S', 'W', 'H', 'E', 'N', 'W', 'H',
    'E', 'R', 'E', 'C', 'U', 'R', 'S', 'I', 'V', 'E', 'A', 'B', 'O', 'R', 'T', 'A', 'F', 'T',
    'E', 'R', 'E', 'N', 'A', 'M', 'E', 'A', 'N', 'D', 'R', 'O', 'P', 'A', 'R', 'T', 'I', 'T',
    'I', 'O', 'N', 'A', 'U', 'T', 'O', 'I', 'N', 'C', 'R', 'E', 'M', 'E', 'N', 'T', 'C', 'A',
    'S', 'T', 'C', 'O', 'L', 'U', 'M', 'N', 'C', 'O', 'M', 'M', 'I', 'T', 'C', 'O', 'N', 'F',
    'L', 'I', 'C', 'T', 'C', 'R', 'O', 'S', 'S', 'C', 'U', 'R', 'R', 'E', 'N', 'T', '_', 'T',
    'I', 'M', 'E', 'S', 'T', 'A', 'M', 'P', 'R', 'E', 'C', 'E', 'D', 'I', 'N', 'G', 'F', 'A',
    'I', 'L', 'A', 'S', 'T', 'F', 'I', 'L', 'T', 'E', 'R', 'E', 'P', 'L', 'A', 'C', 'E', 'F',
    'I', 'R', 'S', 'T', 'F', 'O', 'L', 'L', 'O', 'W', 'I', 'N', 'G', 'F', 'R', 'O', 'M', 'F',
    'U', 'L', 'L', 'I', 'M', 'I', 'T', 'I', 'F', 'O', 'R', 'D', 'E', 'R', 'E', 'S', 'T', 'R',
    'I', 'C', 'T', 'O', 'T', 'H', 'E', 'R', 'S', 'O', 'V', 'E', 'R', 'E', 'T', 'U', 'R', 'N',
    'I', 'N', 'G', 'R', 'I', 'G', 'H', 'T', 'R', 'O', 'L', 'L', 'B', 'A', 'C', 'K', 'R', 'O',
    'W', 'S', 'U', 'N', 'B', 'O', 'U', 'N', 'D', 'E', 'D', 'U', 'N', 'I', 'O', 'N', 'U', 'S',
    'I', 'N', 'G', 'V', 'A', 'C', 'U', 'U', 'M', 'V', 'I', 'E', 'W', 'I', 'N', 'D', 'O', 'W',
    'B', 'Y', 'I', 'N', 'I', 'T', 'I', 'A', 'L', 'L', 'Y', 'P', 'R', 'I', 'M', 'A', 'R', 'Y',
};
const aKWHash = [127]u8{
    84,  92,  134, 82,  105, 29,  0,   0,   94,  0,   85,  72,  0,
    53,  35,  86,  15,  0,   42,  97,  54,  89,  135, 19,  0,   0,
    140, 0,   40,  129, 0,   22,  107, 0,   9,   0,   0,   123, 80,
    0,   78,  6,   0,   65,  103, 147, 0,   136, 115, 0,   0,   48,
    0,   90,  24,  0,   17,  0,   27,  70,  23,  26,  5,   60,  142,
    110, 122, 0,   73,  91,  71,  145, 61,  120, 74,  0,   49,  0,
    11,  41,  0,   113, 0,   0,   0,   109, 10,  111, 116, 125, 14,
    50,  124, 0,   100, 0,   18,  121, 144, 56,  130, 139, 88,  83,
    37,  30,  126, 0,   0,   108, 51,  131, 128, 0,   34,  0,   0,
    132, 0,   98,  38,  39,  0,   20,  45,  117, 93,
};
const aKWNext = [148]u8{
    0,   0,   0,   0,   0,   4,   0,   43,  0,   0,   106, 114, 0,   0,
    0,   2,   0,   0,   143, 0,   0,   0,   13,  0,   0,   0,   0,
    141, 0,   0,   119, 52,  0,   0,   137, 12,  0,   0,   62,  0,
    138, 0,   133, 0,   0,   36,  0,   0,   28,  77,  0,   0,   0,
    0,   59,  0,   47,  0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   69,  0,   0,   0,   0,   0,   146, 3,   0,   58,  0,   1,
    75,  0,   0,   0,   31,  0,   0,   0,   0,   0,   127, 0,   104,
    0,   64,  66,  63,  0,   0,   0,   0,   0,   46,  0,   16,  8,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   81,  101, 0,
    112, 21,  7,   67,  0,   79,  96,  118, 0,   0,   68,  0,   0,
    99,  44,  0,   55,  0,   76,  0,   95,  32,  33,  57,  25,  0,
    102, 0,   0,   87,
};
const aKWLen = [148]u8{
    0,   7,   7,   5,   4,   6,   4,   5,   3,   6,   7,   3,   6,   6,
    7,   7,   3,   8,   2,   6,   5,   4,   4,   3,   10,  4,   7,
    6,   9,   4,   2,   6,   5,   9,   9,   4,   7,   3,   2,   4,
    4,   6,   11,  6,   2,   7,   5,   5,   9,   6,   10,  4,   6,
    2,   3,   7,   5,   9,   6,   6,   4,   5,   5,   10,  6,   5,
    7,   4,   5,   7,   6,   7,   7,   6,   5,   7,   3,   7,   4,
    7,   6,   12,  9,   4,   6,   5,   4,   7,   6,   12,  8,   8,
    2,   6,   6,   7,   6,   4,   5,   9,   5,   5,   6,   3,   4,
    9,   13,  2,   2,   4,   6,   6,   8,   5,   17,  12,  7,   9,
    4,   4,   6,   7,   5,   9,   4,   4,   5,   2,   5,   8,   6,
    4,   9,   5,   8,   4,   3,   9,   5,   5,   6,   4,   6,   2,
    2,   9,   3,   7,
};
const aKWOffset = [148]u16{
    0,   0,   2,   2,   8,   9,   14,  16,  20,  23,  25,  25,  29,  33,
    36,  41,  46,  48,  53,  54,  59,  62,  65,  67,  69,  78,  81,
    86,  90,  90,  94,  99,  101, 105, 111, 119, 123, 123, 123, 126,
    129, 132, 137, 142, 146, 147, 152, 156, 160, 168, 174, 181, 184,
    184, 187, 189, 195, 198, 206, 211, 216, 219, 222, 226, 236, 239,
    244, 244, 248, 252, 259, 265, 271, 277, 277, 283, 284, 288, 295,
    299, 306, 312, 324, 333, 335, 341, 346, 348, 355, 359, 370, 377,
    378, 385, 391, 397, 402, 408, 412, 415, 424, 429, 433, 439, 441,
    444, 453, 455, 457, 466, 470, 476, 482, 490, 495, 495, 495, 511,
    520, 523, 527, 532, 539, 544, 553, 557, 560, 565, 567, 571, 579,
    585, 588, 597, 602, 610, 610, 614, 623, 628, 633, 639, 642, 645,
    648, 650, 655, 659,
};
// aKWCode[i] — parser symbol code for the i-th keyword (TK_* values), copied
// 1:1 from keywordhash.h's aKWCode[] (148 entries, [0]=0 placeholder).
const aKWCode = [148]c_int{
    0, // 0 (unused)
    99,  117, 162, 39,  59,  // REINDEX INDEXED INDEX DESC ESCAPE
    41,  125, 68,  33,  133, // EACH CHECK KEY BEFORE FOREIGN
    63,  64,  48,  2,   66,  // FOR IGNORE LIKE_KW EXPLAIN INSTEAD
    164, 38,  24,  139, 16,  // ADD DATABASE AS SELECT TABLE
    119, 160, 11,  132, 161, // JOIN_KW THEN END DEFERRABLE ELSE
    92,  129, 21,  21,  43,  // EXCLUDE DELETE TEMP TEMP OR
    51,  83,  13,  138, 95,  // ISNULL NULLS SAVEPOINT INTERSECT TIES
    52,  19,  67,  122, 48,  // NOTNULL NOT NO NULL LIKE_KW
    137, 6,   28,  116, 119, // EXCEPT TRANSACTION ACTION ON JOIN_KW
    163, 72,  9,   20,  120, // ALTER RAISE EXCLUSIVE EXISTS CONSTRAINT
    152, 70,  69,  131, 78,  // INTO OFFSET OF SET TRIGGER
    90,  96,  40,  148, 48,  // RANGE GENERATED DETACH HAVING LIKE_KW
    5,   119, 126, 124, 3,   // BEGIN JOIN_KW REFERENCES UNIQUE QUERY
    26,  82,  119, 14,  32,  // WITHOUT WITH JOIN_KW RELEASE ATTACH
    49,  153, 93,  147, 35,  // BETWEEN NOTHING GROUPS GROUP CASCADE
    31,  121, 158, 114, 17,  // ASC DEFAULT CASE COLLATE CREATE
    101, 8,   144, 128, 47,  // CTIME_KW IMMEDIATE JOIN INSERT MATCH
    4,   30,  71,  98,  7,   // PLAN ANALYZE PRAGMA MATERIALIZED DEFERRED
    141, 45,  130, 140, 81,  // DISTINCT IS UPDATE VALUES VIRTUAL
    97,  159, 150, 73,  27,  // ALWAYS WHEN WHERE RECURSIVE ABORT
    29,  100, 44,  134, 88,  // AFTER RENAME AND DROP PARTITION
    127, 15,  50,  36,  61,  // AUTOINCR TO IN CAST COLUMNKW
    10,  37,  119, 101, 101, // COMMIT CONFLICT JOIN_KW CTIME_KW CTIME_KW
    86,  89,  42,  85,  167, // CURRENT PRECEDING FAIL LAST FILTER
    74,  84,  87,  143, 119, // REPLACE FIRST FOLLOWING FROM JOIN_KW
    149, 18,  146, 75,  94,  // LIMIT IF ORDER RESTRICT OTHERS
    166, 151, 119, 12,  77,  // OVER RETURNING JOIN_KW ROLLBACK ROWS
    76,  91,  135, 145, 79,  // ROW UNBOUNDED UNION USING VACUUM
    80,  165, 62,  34,  65,  // VIEW WINDOW DO BY INITIALLY
    136, 123, // ALL PRIMARY
};
const SQLITE_N_KEYWORD: c_int = 147;

inline fn charMap(x: u8) u8 {
    return sqlite3UpperToLower[x];
}

// IdChar(C): true if C is usable inside an identifier. SQLITE_ASCII form.
inline fn idChar(c: u8) bool {
    return (sqlite3CtypeMap[c] & 0x46) != 0;
}
inline fn isSpace(c: u8) bool {
    return (sqlite3CtypeMap[c] & 0x01) != 0;
}
inline fn isDigit(c: u8) bool {
    return (sqlite3CtypeMap[c] & 0x04) != 0;
}
inline fn isXdigit(c: u8) bool {
    return (sqlite3CtypeMap[c] & 0x08) != 0;
}

// keywordCode: if z[0..n-1] is a keyword, write its token code into *pType.
// Always returns n. Mirrors the static keywordCode() in keywordhash.h.
fn keywordCode(z: [*]const u8, n: i64, pType: *c_int) i64 {
    std.debug.assert(n >= 2);
    const un: u64 = @intCast(n);
    var i: i64 = @intCast(((@as(u64, charMap(z[0])) * 4) ^
        (@as(u64, charMap(z[@intCast(n - 1)])) * 3) ^ un) % 127);
    i = aKWHash[@intCast(i)];
    while (i > 0) : (i = aKWNext[@intCast(i)]) {
        const idx: usize = @intCast(i);
        if (aKWLen[idx] != un) continue;
        const zKW = zKWText[aKWOffset[idx]..];
        if ((z[0] & ~@as(u8, 0x20)) != zKW[0]) continue;
        if ((z[1] & ~@as(u8, 0x20)) != zKW[1]) continue;
        var j: usize = 2;
        while (j < un and (z[j] & ~@as(u8, 0x20)) == zKW[j]) j += 1;
        if (j < un) continue;
        pType.* = aKWCode[idx];
        break;
    }
    return n;
}

// ─── exported: sqlite3IsIdChar ───────────────────────────────────────────────
export fn sqlite3IsIdChar(c: u8) callconv(.c) c_int {
    return @intFromBool(idChar(c));
}

// ─── exported keyword API (from keywordhash.h) ───────────────────────────────
export fn sqlite3KeywordCode(z: [*]const u8, n: c_int) callconv(.c) c_int {
    var id: c_int = TK_ID;
    if (n >= 2) _ = keywordCode(z, n, &id);
    return id;
}
export fn sqlite3_keyword_name(i: c_int, pzName: *?[*]const u8, pnName: *c_int) callconv(.c) c_int {
    if (i < 0 or i >= SQLITE_N_KEYWORD) return SQLITE_ERROR;
    const idx: usize = @intCast(i + 1);
    pzName.* = zKWText[aKWOffset[idx]..].ptr;
    pnName.* = aKWLen[idx];
    return SQLITE_OK;
}
export fn sqlite3_keyword_count() callconv(.c) c_int {
    return SQLITE_N_KEYWORD;
}
export fn sqlite3_keyword_check(zName: [*]const u8, nName: c_int) callconv(.c) c_int {
    return @intFromBool(TK_ID != sqlite3KeywordCode(zName, nName));
}

// ─── window-keyword disambiguation (static helpers) ──────────────────────────
fn getTok(pz: *[*]const u8) c_int {
    var z = pz.*;
    var t: c_int = 0;
    while (true) {
        z += @intCast(sqlite3GetToken(z, &t));
        if (t != TK_SPACE and t != TK_COMMENT) break;
    }
    if (t == TK_ID or t == TK_STRING or t == TK_JOIN_KW or
        t == TK_WINDOW or t == TK_OVER or sqlite3ParserFallback(t) == TK_ID)
    {
        t = TK_ID;
    }
    pz.* = z;
    return t;
}
fn analyzeWindowKeyword(z0: [*]const u8) c_int {
    var z = z0;
    var t = getTok(&z);
    if (t != TK_ID) return TK_ID;
    t = getTok(&z);
    if (t != TK_AS) return TK_ID;
    return TK_WINDOW;
}
fn analyzeOverKeyword(z0: [*]const u8, lastToken: c_int) c_int {
    if (lastToken == TK_RP) {
        var z = z0;
        const t = getTok(&z);
        if (t == TK_LP or t == TK_ID) return TK_OVER;
    }
    return TK_ID;
}
fn analyzeFilterKeyword(z0: [*]const u8, lastToken: c_int) c_int {
    if (lastToken == TK_RP) {
        var z = z0;
        if (getTok(&z) == TK_LP) return TK_FILTER;
    }
    return TK_ID;
}

// ─── exported: sqlite3GetToken ───────────────────────────────────────────────
export fn sqlite3GetToken(z: [*]const u8, tokenType: *c_int) callconv(.c) i64 {
    var i: i64 = undefined;
    var c: u8 = undefined;
    switch (aiClass[z[0]]) {
        CC_SPACE => {
            i = 1;
            while (isSpace(z[@intCast(i)])) i += 1;
            tokenType.* = TK_SPACE;
            return i;
        },
        CC_MINUS => {
            if (z[1] == '-') {
                i = 2;
                while (z[@intCast(i)] != 0 and z[@intCast(i)] != '\n') i += 1;
                tokenType.* = TK_COMMENT;
                return i;
            } else if (z[1] == '>') {
                tokenType.* = TK_PTR;
                return 2 + @as(i64, @intFromBool(z[2] == '>'));
            }
            tokenType.* = TK_MINUS;
            return 1;
        },
        CC_LP => {
            tokenType.* = TK_LP;
            return 1;
        },
        CC_RP => {
            tokenType.* = TK_RP;
            return 1;
        },
        CC_SEMI => {
            tokenType.* = TK_SEMI;
            return 1;
        },
        CC_PLUS => {
            tokenType.* = TK_PLUS;
            return 1;
        },
        CC_STAR => {
            tokenType.* = TK_STAR;
            return 1;
        },
        CC_SLASH => {
            if (z[1] != '*' or z[2] == 0) {
                tokenType.* = TK_SLASH;
                return 1;
            }
            i = 3;
            c = z[2];
            while ((c != '*' or z[@intCast(i)] != '/') and (blk: {
                c = z[@intCast(i)];
                break :blk c != 0;
            })) i += 1;
            if (c != 0) i += 1;
            tokenType.* = TK_COMMENT;
            return i;
        },
        CC_PERCENT => {
            tokenType.* = TK_REM;
            return 1;
        },
        CC_EQ => {
            tokenType.* = TK_EQ;
            return 1 + @as(i64, @intFromBool(z[1] == '='));
        },
        CC_LT => {
            c = z[1];
            if (c == '=') {
                tokenType.* = TK_LE;
                return 2;
            } else if (c == '>') {
                tokenType.* = TK_NE;
                return 2;
            } else if (c == '<') {
                tokenType.* = TK_LSHIFT;
                return 2;
            } else {
                tokenType.* = TK_LT;
                return 1;
            }
        },
        CC_GT => {
            c = z[1];
            if (c == '=') {
                tokenType.* = TK_GE;
                return 2;
            } else if (c == '>') {
                tokenType.* = TK_RSHIFT;
                return 2;
            } else {
                tokenType.* = TK_GT;
                return 1;
            }
        },
        CC_BANG => {
            if (z[1] != '=') {
                tokenType.* = TK_ILLEGAL;
                return 1;
            } else {
                tokenType.* = TK_NE;
                return 2;
            }
        },
        CC_PIPE => {
            if (z[1] != '|') {
                tokenType.* = TK_BITOR;
                return 1;
            } else {
                tokenType.* = TK_CONCAT;
                return 2;
            }
        },
        CC_COMMA => {
            tokenType.* = TK_COMMA;
            return 1;
        },
        CC_AND => {
            tokenType.* = TK_BITAND;
            return 1;
        },
        CC_TILDA => {
            tokenType.* = TK_BITNOT;
            return 1;
        },
        CC_QUOTE => {
            const delim = z[0];
            i = 1;
            c = 0;
            while (true) {
                c = z[@intCast(i)];
                if (c == 0) break;
                if (c == delim) {
                    if (z[@intCast(i + 1)] == delim) {
                        i += 1;
                    } else {
                        break;
                    }
                }
                i += 1;
            }
            if (c == '\'') {
                tokenType.* = TK_STRING;
                return i + 1;
            } else if (c != 0) {
                tokenType.* = TK_ID;
                return i + 1;
            } else {
                tokenType.* = TK_ILLEGAL;
                return i;
            }
        },
        CC_DOT => {
            if (!isDigit(z[1])) {
                tokenType.* = TK_DOT;
                return 1;
            }
            // Fall through into CC_DIGIT (floating point starting with '.').
            return scanNumber(z, tokenType);
        },
        CC_DIGIT => {
            return scanNumber(z, tokenType);
        },
        CC_QUOTE2 => {
            i = 1;
            c = z[0];
            while (c != ']' and (blk: {
                c = z[@intCast(i)];
                break :blk c != 0;
            })) i += 1;
            tokenType.* = if (c == ']') TK_ID else TK_ILLEGAL;
            return i;
        },
        CC_VARNUM => {
            tokenType.* = TK_VARIABLE;
            i = 1;
            while (isDigit(z[@intCast(i)])) i += 1;
            return i;
        },
        CC_DOLLAR, CC_VARALPHA => {
            var n: i64 = 0;
            tokenType.* = TK_VARIABLE;
            i = 1;
            while (true) {
                c = z[@intCast(i)];
                if (c == 0) break;
                if (idChar(c)) {
                    n += 1;
                } else if (c == '(' and n > 0) {
                    while (true) {
                        i += 1;
                        c = z[@intCast(i)];
                        if (c == 0 or isSpace(c) or c == ')') break;
                    }
                    if (c == ')') {
                        i += 1;
                    } else {
                        tokenType.* = TK_ILLEGAL;
                    }
                    break;
                } else if (c == ':' and z[@intCast(i + 1)] == ':') {
                    i += 1;
                } else {
                    break;
                }
                i += 1;
            }
            if (n == 0) tokenType.* = TK_ILLEGAL;
            return i;
        },
        CC_KYWD0 => {
            if (aiClass[z[1]] > CC_KYWD) {
                i = 1;
                return finishId(z, i, tokenType);
            }
            i = 2;
            while (aiClass[z[@intCast(i)]] <= CC_KYWD) i += 1;
            if (idChar(z[@intCast(i)])) {
                // Not a keyword after all — an identifier.
                i += 1;
                return finishId(z, i, tokenType);
            }
            tokenType.* = TK_ID;
            return keywordCode(z, i, tokenType);
        },
        CC_X => {
            if (z[1] == '\'') {
                tokenType.* = TK_BLOB;
                i = 2;
                while (isXdigit(z[@intCast(i)])) i += 1;
                if (z[@intCast(i)] != '\'' or @mod(i, 2) != 0) {
                    tokenType.* = TK_ILLEGAL;
                    while (z[@intCast(i)] != 0 and z[@intCast(i)] != '\'') i += 1;
                }
                if (z[@intCast(i)] != 0) i += 1;
                return i;
            }
            // Not a BLOB literal → an ID (no keyword starts with 'x').
            i = 1;
            return finishId(z, i, tokenType);
        },
        CC_KYWD, CC_ID => {
            i = 1;
            return finishId(z, i, tokenType);
        },
        CC_BOM => {
            if (z[1] == 0xbb and z[2] == 0xbf) {
                tokenType.* = TK_SPACE;
                return 3;
            }
            i = 1;
            return finishId(z, i, tokenType);
        },
        CC_NUL => {
            tokenType.* = TK_ILLEGAL;
            return 0;
        },
        else => {
            tokenType.* = TK_ILLEGAL;
            return 1;
        },
    }
}

// Tail shared by the CC_KYWD0/CC_X/CC_KYWD/CC_ID/CC_BOM "break" paths in C:
//   while( IdChar(z[i]) ){ i++; }  *tokenType = TK_ID;  return i;
fn finishId(z: [*]const u8, iStart: i64, tokenType: *c_int) i64 {
    var i = iStart;
    while (idChar(z[@intCast(i)])) i += 1;
    tokenType.* = TK_ID;
    return i;
}

// The CC_DIGIT case (also entered by CC_DOT fall-through for ".<digit>").
fn scanNumber(z: [*]const u8, tokenType: *c_int) i64 {
    var i: i64 = undefined;
    tokenType.* = TK_INTEGER;
    if (z[0] == '0' and (z[1] == 'x' or z[1] == 'X') and isXdigit(z[2])) {
        i = 3;
        while (true) : (i += 1) {
            if (!isXdigit(z[@intCast(i)])) {
                if (z[@intCast(i)] == SQLITE_DIGIT_SEPARATOR) {
                    tokenType.* = TK_QNUMBER;
                } else {
                    break;
                }
            }
        }
    } else {
        i = 0;
        while (true) : (i += 1) {
            if (!isDigit(z[@intCast(i)])) {
                if (z[@intCast(i)] == SQLITE_DIGIT_SEPARATOR) {
                    tokenType.* = TK_QNUMBER;
                } else {
                    break;
                }
            }
        }
        if (z[@intCast(i)] == '.') {
            if (tokenType.* == TK_INTEGER) tokenType.* = TK_FLOAT;
            i += 1;
            while (true) : (i += 1) {
                if (!isDigit(z[@intCast(i)])) {
                    if (z[@intCast(i)] == SQLITE_DIGIT_SEPARATOR) {
                        tokenType.* = TK_QNUMBER;
                    } else {
                        break;
                    }
                }
            }
        }
        if ((z[@intCast(i)] == 'e' or z[@intCast(i)] == 'E') and
            (isDigit(z[@intCast(i + 1)]) or
                ((z[@intCast(i + 1)] == '+' or z[@intCast(i + 1)] == '-') and isDigit(z[@intCast(i + 2)]))))
        {
            if (tokenType.* == TK_INTEGER) tokenType.* = TK_FLOAT;
            i += 2;
            while (true) : (i += 1) {
                if (!isDigit(z[@intCast(i)])) {
                    if (z[@intCast(i)] == SQLITE_DIGIT_SEPARATOR) {
                        tokenType.* = TK_QNUMBER;
                    } else {
                        break;
                    }
                }
            }
        }
    }
    while (idChar(z[@intCast(i)])) {
        tokenType.* = TK_ILLEGAL;
        i += 1;
    }
    return i;
}

// ─── relaxed atomic helpers for db->u1.isInterrupted (volatile int) ──────────
inline fn atomicLoadInterrupted(db: ?*Sqlite3) c_int {
    const p: *volatile c_int = @ptrCast(@alignCast(base(db) + sqlite3_u1_isInterrupted_off));
    return p.*;
}
inline fn atomicStoreInterrupted(db: ?*Sqlite3, v: c_int) void {
    const p: *volatile c_int = @ptrCast(@alignCast(base(db) + sqlite3_u1_isInterrupted_off));
    p.* = v;
}

// ─── exported: sqlite3RunParser ──────────────────────────────────────────────
export fn sqlite3RunParser(pParse: ?*Parse, zSql0: ?[*:0]const u8) callconv(.c) c_int {
    var nErr: c_int = 0;
    var n: i64 = 0;
    var tokenType: c_int = 0;
    var lastTokenParsed: c_int = -1;
    const db = rd(?*Sqlite3, pParse, Parse_db_off);
    var zSql: [*]const u8 = @ptrCast(zSql0.?);

    std.debug.assert(zSql0 != null);
    // mxSqlLen = db->aLimit[SQLITE_LIMIT_SQL_LENGTH];
    var mxSqlLen: i64 = rd(c_int, db, sqlite3_aLimit_off + SQLITE_LIMIT_SQL_LENGTH * @sizeOf(c_int));

    if (rd(c_int, db, sqlite3_nVdbeActive_off) == 0) {
        atomicStoreInterrupted(db, 0);
    }
    wr(c_int, pParse, Parse_rc_off, SQLITE_OK);
    wr([*]const u8, pParse, Parse_zTail_off, zSql);

    const pEngine = sqlite3ParserAlloc(sqlite3MallocWrap, pParse);
    if (pEngine == null) {
        _ = sqlite3OomFault(db);
        return SQLITE_NOMEM;
    }
    std.debug.assert(rd(?*anyopaque, pParse, Parse_pNewTable_off) == null);
    std.debug.assert(rd(?*anyopaque, pParse, Parse_pNewTrigger_off) == null);
    // nVar is ynVar (i16); a c_int read here spans into Parse.explain@299, so an
    // EXPLAIN reprepare (explain=2) made this assert spuriously fail.
    std.debug.assert(rd(i16, pParse, Parse_nVar_off) == 0);
    std.debug.assert(rd(?*anyopaque, pParse, Parse_pVList_off) == null);

    const pParentParse = rd(?*Parse, db, sqlite3_pParse_off);
    wr(?*Parse, db, sqlite3_pParse_off, pParse);

    while (true) {
        n = sqlite3GetToken(zSql, &tokenType);
        mxSqlLen -= n;
        if (mxSqlLen < 0) {
            wr(c_int, pParse, Parse_rc_off, SQLITE_TOOBIG);
            wr(c_int, pParse, Parse_nErr_off, rd(c_int, pParse, Parse_nErr_off) + 1);
            break;
        }
        if (tokenType >= TK_WINDOW) {
            if (atomicLoadInterrupted(db) != 0) {
                wr(c_int, pParse, Parse_rc_off, SQLITE_INTERRUPT);
                wr(c_int, pParse, Parse_nErr_off, rd(c_int, pParse, Parse_nErr_off) + 1);
                break;
            }
            if (tokenType == TK_SPACE) {
                zSql += @intCast(n);
                continue;
            }
            if (zSql[0] == 0) {
                // End of input: call the parser with TK_SEMI then 0.
                if (lastTokenParsed == TK_SEMI) {
                    tokenType = 0;
                } else if (lastTokenParsed == 0) {
                    break;
                } else {
                    tokenType = TK_SEMI;
                }
                n = 0;
            } else if (tokenType == TK_WINDOW) {
                std.debug.assert(n == 6);
                tokenType = analyzeWindowKeyword(zSql + 6);
            } else if (tokenType == TK_OVER) {
                std.debug.assert(n == 4);
                tokenType = analyzeOverKeyword(zSql + 4, lastTokenParsed);
            } else if (tokenType == TK_FILTER) {
                std.debug.assert(n == 6);
                tokenType = analyzeFilterKeyword(zSql + 6, lastTokenParsed);
            } else if (tokenType == TK_COMMENT and
                (rd(u8, db, sqlite3_initBusy_off) != 0 or
                    (rd(u64, db, sqlite3_flags_off) & SQLITE_Comments) != 0))
            {
                // Ignore comments while reparsing schema or when comments enabled.
                zSql += @intCast(n);
                continue;
            } else if (tokenType != TK_QNUMBER) {
                var x: Token = undefined;
                x.z = zSql;
                x.n = @intCast(n);
                sqlite3ErrorMsg(pParse, "unrecognized token: \"%T\"", &x);
                break;
            }
        }
        // pParse->sLastToken.z = zSql; .n = n;
        wr([*]const u8, pParse, Parse_sLastToken_off + Token_z_off, zSql);
        wr(u32, pParse, Parse_sLastToken_off + Token_n_off, @intCast(n));
        var lastTok: Token = undefined;
        lastTok.z = zSql;
        lastTok.n = @intCast(n);
        sqlite3Parser(pEngine, tokenType, lastTok);
        lastTokenParsed = tokenType;
        zSql += @intCast(n);
        if (rd(c_int, pParse, Parse_rc_off) != SQLITE_OK) break;
    }

    sqlite3ParserFree(pEngine, sqlite3FreeWrap);

    if (rd(u8, db, sqlite3_mallocFailed_off) != 0) {
        wr(c_int, pParse, Parse_rc_off, SQLITE_NOMEM);
    }
    const zErrMsg = rd(?[*:0]u8, pParse, Parse_zErrMsg_off);
    const rc = rd(c_int, pParse, Parse_rc_off);
    if (zErrMsg != null or (rc != SQLITE_OK and rc != SQLITE_DONE)) {
        if (rd(?*anyopaque, pParse, Parse_zErrMsg_off) == null) {
            wr(?[*:0]u8, pParse, Parse_zErrMsg_off, sqlite3DbStrDup(db, sqlite3ErrStr(rc)));
        }
        if ((rd(u32, pParse, Parse_prepFlags_off) & SQLITE_PREPARE_DONT_LOG) == 0) {
            sqlite3_log(rc, "%s in \"%s\"", rd(?[*:0]u8, pParse, Parse_zErrMsg_off), rd(?[*:0]const u8, pParse, Parse_zTail_off));
        }
        nErr += 1;
    }
    wr([*]const u8, pParse, Parse_zTail_off, zSql);

    sqlite3_free(rd(?*anyopaque, pParse, Parse_apVtabLock_off));

    const eParseMode = rd(u8, pParse, Parse_eParseMode_off);
    const inSpecialParse = eParseMode != PARSE_MODE_NORMAL;
    const inRenameObject = eParseMode >= PARSE_MODE_RENAME;
    const pNewTable = rd(?*Table, pParse, Parse_pNewTable_off);
    if (pNewTable != null and !inSpecialParse) {
        sqlite3DeleteTable(db, pNewTable);
    }
    const pNewTrigger = rd(?*Trigger, pParse, Parse_pNewTrigger_off);
    if (pNewTrigger != null and !inRenameObject) {
        sqlite3DeleteTrigger(db, pNewTrigger);
    }
    const pVList = rd(?*anyopaque, pParse, Parse_pVList_off);
    if (pVList != null) sqlite3DbNNFreeNN(db, pVList);
    wr(?*Parse, db, sqlite3_pParse_off, pParentParse);
    return nErr;
}

// Wrappers matching the Lemon-allocator function-pointer signatures.
fn sqlite3MallocWrap(n: u64) callconv(.c) ?*anyopaque {
    return sqlite3Malloc(n);
}
fn sqlite3FreeWrap(p: ?*anyopaque) callconv(.c) void {
    sqlite3_free(p);
}
