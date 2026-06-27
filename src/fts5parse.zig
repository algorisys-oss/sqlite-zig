//! Zig port of the fts5parse.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 1772-3364).
//!
//! This is the Lemon-GENERATED, table-driven push-down automaton that parses
//! FTS5 MATCH queries. It is a faithful transliteration of the generated C: the
//! big static action/lookahead/offset tables are reproduced byte-for-byte, and
//! the fts5yy_reduce() switch carries the grammar's reduce actions (which call
//! the sqlite3Fts5Parse* builder callbacks that live in fts5_expr.c).
//!
//! Control parameters from the generated `#define` block (amalgamation
//! 1912-1962), matched EXACTLY:
//!   fts5YYCODETYPE   = unsigned char  -> u8
//!   fts5YYACTIONTYPE = unsigned char  -> u8
//!   fts5YYNOCODE        = 27
//!   fts5YYNSTATE        = 35
//!   fts5YYNRULE         = 28
//!   fts5YYNFTS5TOKEN    = 16
//!   fts5YY_MAX_SHIFT       = 34
//!   fts5YY_MIN_SHIFTREDUCE = 52
//!   fts5YY_MAX_SHIFTREDUCE = 79
//!   fts5YY_ERROR_ACTION    = 80
//!   fts5YY_ACCEPT_ACTION   = 81
//!   fts5YY_NO_ACTION       = 82
//!   fts5YY_MIN_REDUCE      = 83
//!   fts5YY_MAX_REDUCE      = 110
//!   fts5YY_MIN_DSTRCTR     = 16
//!   fts5YY_MAX_DSTRCTR     = 24
//!   fts5YYSTACKDEPTH       = 100
//!   fts5YYNOERRORRECOVERY  defined ; fts5YYERRORSYMBOL / fts5YYFALLBACK / NDEBUG
//!                                     tracing all OFF in production.
//!   fts5YYMALLOCARGTYPE = u64 ; realloc==realloc, free==free, DYNSTACK==0,
//!                               GROWABLESTACK==0 (so fts5yyGrowStack always
//!                               returns 1 -> stack overflow on growth).
//!
//! The %extra_argument is `Fts5Parse *pParse`. The minor token type is
//! `Fts5Token` (passed BY VALUE). Both layouts come from fts5_int.zig.
//!
//! Cross-object: this file `export`s the parser entry points the (Zig) fts5_expr
//! section calls (sqlite3Fts5Parser/Alloc/Free/Fallback) and `extern`s the
//! sqlite3Fts5Parse* builder callbacks fts5_expr defines.

const int = @import("fts5_int.zig");

const Fts5Token = int.Fts5Token;
const Fts5Parse = int.Fts5Parse;
const Fts5Colset = int.Fts5Colset;
const Fts5ExprNode = int.Fts5ExprNode;
const Fts5ExprNearset = int.Fts5ExprNearset;
const Fts5ExprPhrase = int.Fts5ExprPhrase;

// --- token codes (fts5parse.h / fts5_int.zig) -------------------------------
const FTS5_AND = int.FTS5_AND;
const FTS5_OR = int.FTS5_OR;
const FTS5_NOT = int.FTS5_NOT;
const FTS5_STRING = int.FTS5_STRING;

// --- libc (resolved at link time) -------------------------------------------
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;

// --- sibling section: fts5_expr.c parser-callback builders ------------------
// (These are the %destructor / reduce-action callbacks. All take Fts5Parse*.)
extern fn sqlite3Fts5ParseError(pParse: ?*Fts5Parse, zFmt: [*:0]const u8, ...) callconv(.c) void;
extern fn sqlite3Fts5ParseFinished(pParse: ?*Fts5Parse, p: ?*Fts5ExprNode) callconv(.c) void;
extern fn sqlite3Fts5ParseNode(pParse: ?*Fts5Parse, eType: c_int, pLeft: ?*Fts5ExprNode, pRight: ?*Fts5ExprNode, pNear: ?*Fts5ExprNearset) callconv(.c) ?*Fts5ExprNode;
extern fn sqlite3Fts5ParseImplicitAnd(pParse: ?*Fts5Parse, pLeft: ?*Fts5ExprNode, pRight: ?*Fts5ExprNode) callconv(.c) ?*Fts5ExprNode;
extern fn sqlite3Fts5ParseColset(pParse: ?*Fts5Parse, pColset: ?*Fts5Colset, p: ?*Fts5Token) callconv(.c) ?*Fts5Colset;
extern fn sqlite3Fts5ParseColsetInvert(pParse: ?*Fts5Parse, p: ?*Fts5Colset) callconv(.c) ?*Fts5Colset;
extern fn sqlite3Fts5ParseSetColset(pParse: ?*Fts5Parse, pExpr: ?*Fts5ExprNode, pColset: ?*Fts5Colset) callconv(.c) void;
extern fn sqlite3Fts5ParseNearset(pParse: ?*Fts5Parse, pNear: ?*Fts5ExprNearset, pPhrase: ?*Fts5ExprPhrase) callconv(.c) ?*Fts5ExprNearset;
extern fn sqlite3Fts5ParseSetCaret(pPhrase: ?*Fts5ExprPhrase) callconv(.c) void;
extern fn sqlite3Fts5ParseNear(pParse: ?*Fts5Parse, pTok: ?*Fts5Token) callconv(.c) void;
extern fn sqlite3Fts5ParseSetDistance(pParse: ?*Fts5Parse, pNear: ?*Fts5ExprNearset, p: ?*Fts5Token) callconv(.c) void;
extern fn sqlite3Fts5ParseTerm(pParse: ?*Fts5Parse, pAppend: ?*Fts5ExprPhrase, pToken: ?*Fts5Token, bPrefix: c_int) callconv(.c) ?*Fts5ExprPhrase;
extern fn sqlite3Fts5ParseNodeFree(p: ?*Fts5ExprNode) callconv(.c) void;
extern fn sqlite3Fts5ParseNearsetFree(p: ?*Fts5ExprNearset) callconv(.c) void;
extern fn sqlite3Fts5ParsePhraseFree(p: ?*Fts5ExprPhrase) callconv(.c) void;

// ===========================================================================
// Control #defines (amalgamation 1912-1964). Names kept ~identical for fidelity.
// ===========================================================================
const fts5YYNOCODE: c_int = 27;
const fts5YYNSTATE: c_int = 35;
const fts5YYNRULE: c_int = 28;
const fts5YYNRULE_WITH_ACTION: c_int = 28;
const fts5YYNFTS5TOKEN: c_int = 16;
const fts5YY_MAX_SHIFT: c_int = 34;
const fts5YY_MIN_SHIFTREDUCE: c_int = 52;
const fts5YY_MAX_SHIFTREDUCE: c_int = 79;
const fts5YY_ERROR_ACTION: c_int = 80;
const fts5YY_ACCEPT_ACTION: c_int = 81;
const fts5YY_NO_ACTION: c_int = 82;
const fts5YY_MIN_REDUCE: c_int = 83;
const fts5YY_MAX_REDUCE: c_int = 110;
const fts5YY_MIN_DSTRCTR: c_int = 16;
const fts5YY_MAX_DSTRCTR: c_int = 24;
const fts5YYSTACKDEPTH: usize = 100;

const fts5YY_ACTTAB_COUNT: c_int = 105;
const fts5YY_SHIFT_COUNT: c_int = 34;
const fts5YY_REDUCE_COUNT: c_int = 17;

// fts5YYCODETYPE -> u8 ; fts5YYACTIONTYPE -> u8.
const fts5YYCODETYPE = u8;
const fts5YYACTIONTYPE = u8;

// ===========================================================================
// fts5YYMINORTYPE union (amalgamation 1916-1924). The largest member is
// Fts5Token (the terminal minor `fts5yy0`); the rest are int / pointers.
// Byte-exact via an extern union so by-value passing matches the C ABI.
// ===========================================================================
const fts5YYMINORTYPE = extern union {
    fts5yyinit: c_int,
    fts5yy0: Fts5Token,
    fts5yy4: c_int,
    fts5yy11: ?*Fts5Colset,
    fts5yy24: ?*Fts5ExprNode,
    fts5yy46: ?*Fts5ExprNearset,
    fts5yy53: ?*Fts5ExprPhrase,
};

// ===========================================================================
// Parsing tables (amalgamation 2046-2095). Reproduced byte-for-byte. Element
// widths match the C declarations exactly:
//   fts5yy_action[]      : fts5YYACTIONTYPE (u8)
//   fts5yy_lookahead[]   : fts5YYCODETYPE   (u8)
//   fts5yy_shift_ofst[]  : unsigned char    (u8)
//   fts5yy_reduce_ofst[] : signed char      (i8)
//   fts5yy_default[]     : fts5YYACTIONTYPE (u8)
// ===========================================================================
const fts5yy_action = [_]fts5YYACTIONTYPE{
    81, 20, 96, 6,  28,  99, 98, 26, 26, 18,
    96, 6,  28, 17, 98,  56, 26, 19, 96, 6,
    28, 14, 98, 14, 26,  31, 92, 96, 6,  28,
    108, 98, 25, 26, 21, 96, 6,  28, 78, 98,
    58, 26, 29, 96, 6,  28, 107, 98, 22, 26,
    24, 16, 12, 11, 1,  13, 13, 24, 16, 23,
    11, 33, 34, 13, 97, 8,  27, 32, 98, 7,
    26, 3,  4,  5,  3,  4,  5,  3,  83, 4,
    5,  3,  63, 5,  3,  62, 12, 2,  86, 13,
    9,  30, 10, 10, 54, 57, 75, 78, 78, 53,
    57, 15, 82, 82, 71,
};
const fts5yy_lookahead = [_]fts5YYCODETYPE{
    16, 17, 18, 19, 20, 22, 22, 24, 24, 17,
    18, 19, 20, 7,  22, 9,  24, 17, 18, 19,
    20, 9,  22, 9,  24, 13, 17, 18, 19, 20,
    26, 22, 24, 24, 17, 18, 19, 20, 15, 22,
    9,  24, 17, 18, 19, 20, 26, 22, 21, 24,
    6,  7,  9,  9,  10, 12, 12, 6,  7,  21,
    9,  24, 25, 12, 18, 5,  20, 14, 22, 5,
    24, 3,  1,  2,  3,  1,  2,  3,  0,  1,
    2,  3,  11, 2,  3,  11, 9,  10, 5,  12,
    23, 24, 10, 10, 8,  9,  9,  15, 15, 8,
    9,  9,  27, 27, 11, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27,
};
// fts5YY_NLOOKAHEAD == sizeof(fts5yy_lookahead)/sizeof(...) == 121.
const fts5YY_NLOOKAHEAD: c_int = @intCast(fts5yy_lookahead.len);

const fts5yy_shift_ofst = [_]u8{
    44, 44, 44, 44, 44, 44, 51, 77, 43, 12,
    14, 83, 82, 14, 23, 23, 31, 31, 71, 74,
    78, 81, 86, 91, 6,  53, 53, 60, 64, 68,
    53, 87, 92, 53, 93,
};
const fts5yy_reduce_ofst = [_]i8{
    -16, -8, 0,  9,  17, 25, 46, -17, -17, 37,
    67,  4,  4,  8,  4,  20, 27, 38,
};
const fts5yy_default = [_]fts5YYACTIONTYPE{
    80, 80, 80, 80, 80, 80, 95, 80, 80,  105,
    80, 110, 110, 80, 110, 110, 80, 80, 80, 80,
    80, 91, 80, 80, 80, 101, 100, 80, 80, 90,
    103, 80, 80, 104, 80,
};

// fts5yyRuleInfoLhs[] : fts5YYCODETYPE (u8) (amalgamation 2732-2761).
const fts5yyRuleInfoLhs = [_]fts5YYCODETYPE{
    16, // (0) input ::= expr
    20, // (1) colset ::= MINUS LCP colsetlist RCP
    20, // (2) colset ::= LCP colsetlist RCP
    20, // (3) colset ::= STRING
    20, // (4) colset ::= MINUS STRING
    21, // (5) colsetlist ::= colsetlist STRING
    21, // (6) colsetlist ::= STRING
    17, // (7) expr ::= expr AND expr
    17, // (8) expr ::= expr OR expr
    17, // (9) expr ::= expr NOT expr
    17, // (10) expr ::= colset COLON LP expr RP
    17, // (11) expr ::= LP expr RP
    17, // (12) expr ::= exprlist
    19, // (13) exprlist ::= cnearset
    19, // (14) exprlist ::= exprlist cnearset
    18, // (15) cnearset ::= nearset
    18, // (16) cnearset ::= colset COLON nearset
    22, // (17) nearset ::= phrase
    22, // (18) nearset ::= CARET phrase
    22, // (19) nearset ::= STRING LP nearphrases neardist_opt RP
    23, // (20) nearphrases ::= phrase
    23, // (21) nearphrases ::= nearphrases phrase
    25, // (22) neardist_opt ::=
    25, // (23) neardist_opt ::= COMMA STRING
    24, // (24) phrase ::= phrase PLUS STRING star_opt
    24, // (25) phrase ::= STRING star_opt
    26, // (26) star_opt ::= STAR
    26, // (27) star_opt ::=
};

// fts5yyRuleInfoNRhs[] : signed char (i8) (amalgamation 2765-2794).
const fts5yyRuleInfoNRhs = [_]i8{
    -1, // (0) input ::= expr
    -4, // (1) colset ::= MINUS LCP colsetlist RCP
    -3, // (2) colset ::= LCP colsetlist RCP
    -1, // (3) colset ::= STRING
    -2, // (4) colset ::= MINUS STRING
    -2, // (5) colsetlist ::= colsetlist STRING
    -1, // (6) colsetlist ::= STRING
    -3, // (7) expr ::= expr AND expr
    -3, // (8) expr ::= expr OR expr
    -3, // (9) expr ::= expr NOT expr
    -5, // (10) expr ::= colset COLON LP expr RP
    -3, // (11) expr ::= LP expr RP
    -1, // (12) expr ::= exprlist
    -1, // (13) exprlist ::= cnearset
    -2, // (14) exprlist ::= exprlist cnearset
    -1, // (15) cnearset ::= nearset
    -3, // (16) cnearset ::= colset COLON nearset
    -1, // (17) nearset ::= phrase
    -2, // (18) nearset ::= CARET phrase
    -5, // (19) nearset ::= STRING LP nearphrases neardist_opt RP
    -1, // (20) nearphrases ::= phrase
    -2, // (21) nearphrases ::= nearphrases phrase
    0, // (22) neardist_opt ::=
    -2, // (23) neardist_opt ::= COMMA STRING
    -4, // (24) phrase ::= phrase PLUS STRING star_opt
    -2, // (25) phrase ::= STRING star_opt
    -1, // (26) star_opt ::= STAR
    0, // (27) star_opt ::=
};

// ===========================================================================
// Stack entry + parser object (amalgamation 2133-2158).
// ===========================================================================
const fts5yyStackEntry = extern struct {
    stateno: fts5YYACTIONTYPE, // state-number, or reduce action in SHIFTREDUCE
    major: fts5YYCODETYPE, // major token value
    minor: fts5YYMINORTYPE, // user-supplied minor token value
};

const fts5yyParser = extern struct {
    fts5yytos: [*]fts5yyStackEntry, // top of the stack
    pParse: ?*Fts5Parse, // %extra_argument (ARG_SDECL)
    fts5yystackEnd: [*]fts5yyStackEntry, // last entry in the stack
    fts5yystack: [*]fts5yyStackEntry, // the parser stack
    fts5yystk0: [fts5YYSTACKDEPTH]fts5yyStackEntry, // initial stack space
};

// ===========================================================================
// fts5yy_destructor (amalgamation 2372-2433): release a symbol's minor value.
// ===========================================================================
fn fts5yy_destructor(
    fts5yypParser: *fts5yyParser,
    fts5yymajor: fts5YYCODETYPE,
    fts5yypminor: *fts5YYMINORTYPE,
) void {
    _ = fts5yypParser;
    switch (fts5yymajor) {
        16 => { // input : (void)pParse;
        },
        17, 18, 19 => { // expr / cnearset / exprlist
            sqlite3Fts5ParseNodeFree(fts5yypminor.fts5yy24);
        },
        20, 21 => { // colset / colsetlist
            sqlite3_free(fts5yypminor.fts5yy11);
        },
        22, 23 => { // nearset / nearphrases
            sqlite3Fts5ParseNearsetFree(fts5yypminor.fts5yy46);
        },
        24 => { // phrase
            sqlite3Fts5ParsePhraseFree(fts5yypminor.fts5yy53);
        },
        else => {},
    }
}

// ===========================================================================
// fts5yy_pop_parser_stack (amalgamation 2441-2454).
// ===========================================================================
fn fts5yy_pop_parser_stack(pParser: *fts5yyParser) void {
    const fts5yytos = pParser.fts5yytos;
    pParser.fts5yytos -= 1;
    fts5yy_destructor(pParser, fts5yytos[0].major, &fts5yytos[0].minor);
}

// ===========================================================================
// sqlite3Fts5ParserInit (amalgamation 2324-2338).
// ===========================================================================
fn sqlite3Fts5ParserInit(fts5yypRawParser: *anyopaque) void {
    const fts5yypParser: *fts5yyParser = @ptrCast(@alignCast(fts5yypRawParser));
    fts5yypParser.fts5yystack = &fts5yypParser.fts5yystk0;
    fts5yypParser.fts5yystackEnd = @ptrCast(&fts5yypParser.fts5yystk0[fts5YYSTACKDEPTH - 1]);
    fts5yypParser.fts5yytos = fts5yypParser.fts5yystack;
    fts5yypParser.fts5yystack[0].stateno = 0;
    fts5yypParser.fts5yystack[0].major = 0;
}

// ===========================================================================
// sqlite3Fts5ParserAlloc (amalgamation 2353-2361). Exported: called by
// fts5_expr.c (fts5ParseAlloc -> sqlite3_malloc64).
// ===========================================================================
const MallocProc = ?*const fn (u64) callconv(.c) ?*anyopaque;
export fn sqlite3Fts5ParserAlloc(mallocProc: MallocProc) callconv(.c) ?*anyopaque {
    const fts5yypParser: ?*fts5yyParser = @ptrCast(@alignCast(mallocProc.?(@sizeOf(fts5yyParser))));
    if (fts5yypParser) |p| {
        sqlite3Fts5ParserInit(p);
    }
    return fts5yypParser;
}

// ===========================================================================
// sqlite3Fts5ParserFinalize (amalgamation 2459-2484). GROWABLESTACK==0, so the
// trailing free of a heap stack is compiled out (stack never grows).
// ===========================================================================
fn sqlite3Fts5ParserFinalize(p: *anyopaque) void {
    const pParser: *fts5yyParser = @ptrCast(@alignCast(p));
    var fts5yytos = pParser.fts5yytos;
    while (@intFromPtr(fts5yytos) > @intFromPtr(pParser.fts5yystack)) {
        if (fts5yytos[0].major >= fts5YY_MIN_DSTRCTR) {
            fts5yy_destructor(pParser, fts5yytos[0].major, &fts5yytos[0].minor);
        }
        fts5yytos -= 1;
    }
}

// ===========================================================================
// sqlite3Fts5ParserFree (amalgamation 2495-2504). fts5YYPARSEFREENOTNULL is set
// but fts5YYPARSEFREENEVERNULL is NOT, so the p==0 guard stays.
// ===========================================================================
const FreeProc = ?*const fn (?*anyopaque) callconv(.c) void;
export fn sqlite3Fts5ParserFree(p: ?*anyopaque, freeProc: FreeProc) callconv(.c) void {
    if (p == null) return;
    sqlite3Fts5ParserFinalize(p.?);
    freeProc.?(p);
}

// ===========================================================================
// fts5yy_find_shift_action (amalgamation 2558-2617). fts5YYFALLBACK / WILDCARD /
// COVERAGE all undefined -> simplified body.
// ===========================================================================
fn fts5yy_find_shift_action(
    iLookAhead0: fts5YYCODETYPE,
    stateno: fts5YYACTIONTYPE,
) fts5YYACTIONTYPE {
    const iLookAhead = iLookAhead0;
    if (@as(c_int, stateno) > fts5YY_MAX_SHIFT) return stateno;
    var i: c_int = undefined;
    while (true) {
        i = fts5yy_shift_ofst[stateno];
        i += iLookAhead;
        if (fts5yy_lookahead[@intCast(i)] != iLookAhead) {
            return fts5yy_default[stateno];
        } else {
            return fts5yy_action[@intCast(i)];
        }
    }
}

// ===========================================================================
// fts5yy_find_reduce_action (amalgamation 2623-2647). fts5YYERRORSYMBOL
// undefined -> the assert-only branch.
// ===========================================================================
fn fts5yy_find_reduce_action(
    stateno: fts5YYACTIONTYPE,
    iLookAhead: fts5YYCODETYPE,
) fts5YYACTIONTYPE {
    var i: c_int = fts5yy_reduce_ofst[stateno];
    i += iLookAhead;
    return fts5yy_action[@intCast(i)];
}

// ===========================================================================
// fts5yyStackOverflow (amalgamation 2652-2671).
// ===========================================================================
fn fts5yyStackOverflow(fts5yypParser: *fts5yyParser) void {
    const pParse = fts5yypParser.pParse;
    while (@intFromPtr(fts5yypParser.fts5yytos) > @intFromPtr(fts5yypParser.fts5yystack)) {
        fts5yy_pop_parser_stack(fts5yypParser);
    }
    // %stack_overflow code (fts5parse.y 36):
    sqlite3Fts5ParseError(pParse, "fts5: parser stack overflow");
}

// ===========================================================================
// fts5yy_shift (amalgamation 2697-2728). fts5yyGrowStack()==1 always (no
// growable stack), so a push past the end triggers overflow.
// ===========================================================================
fn fts5yy_shift(
    fts5yypParser: *fts5yyParser,
    fts5yyNewState0: fts5YYACTIONTYPE,
    fts5yyMajor: fts5YYCODETYPE,
    fts5yyMinor: Fts5Token,
) void {
    var fts5yyNewState = fts5yyNewState0;
    fts5yypParser.fts5yytos += 1;
    var fts5yytos = fts5yypParser.fts5yytos;
    if (@intFromPtr(fts5yytos) > @intFromPtr(fts5yypParser.fts5yystackEnd)) {
        // fts5yyGrowStack() returns 1 (non-growable): stack overflow.
        fts5yypParser.fts5yytos -= 1;
        fts5yyStackOverflow(fts5yypParser);
        return;
    }
    fts5yytos = fts5yypParser.fts5yytos;
    if (@as(c_int, fts5yyNewState) > fts5YY_MAX_SHIFT) {
        fts5yyNewState += @intCast(fts5YY_MIN_REDUCE - fts5YY_MIN_SHIFTREDUCE);
    }
    fts5yytos[0].stateno = fts5yyNewState;
    fts5yytos[0].major = fts5yyMajor;
    fts5yytos[0].minor.fts5yy0 = fts5yyMinor;
}

// ===========================================================================
// fts5yy_reduce (amalgamation 2808-3051): the grammar reduce actions.
// Returns the next action.
// ===========================================================================
fn fts5yy_reduce(
    fts5yypParser: *fts5yyParser,
    fts5yyruleno: c_uint,
    fts5yyLookahead: c_int,
    fts5yyLookaheadToken: Fts5Token,
) fts5YYACTIONTYPE {
    _ = fts5yyLookahead;
    _ = fts5yyLookaheadToken;
    const pParse = fts5yypParser.pParse;
    var fts5yymsp: [*]fts5yyStackEntry = fts5yypParser.fts5yytos;

    // Reused storage for "lhsminor" rules (declared once at switch scope in C).
    var fts5yylhsminor: fts5YYMINORTYPE = undefined;

    switch (fts5yyruleno) {
        0 => { // input ::= expr
            sqlite3Fts5ParseFinished(pParse, fts5yymsp[0].minor.fts5yy24);
        },
        1 => { // colset ::= MINUS LCP colsetlist RCP
            fts5yymsp[neg(3)].minor.fts5yy11 = sqlite3Fts5ParseColsetInvert(pParse, fts5yymsp[neg(1)].minor.fts5yy11);
        },
        2 => { // colset ::= LCP colsetlist RCP
            fts5yymsp[neg(2)].minor.fts5yy11 = fts5yymsp[neg(1)].minor.fts5yy11;
        },
        3 => { // colset ::= STRING
            fts5yylhsminor.fts5yy11 = sqlite3Fts5ParseColset(pParse, null, &fts5yymsp[0].minor.fts5yy0);
            fts5yymsp[0].minor.fts5yy11 = fts5yylhsminor.fts5yy11;
        },
        4 => { // colset ::= MINUS STRING
            fts5yymsp[neg(1)].minor.fts5yy11 = sqlite3Fts5ParseColset(pParse, null, &fts5yymsp[0].minor.fts5yy0);
            fts5yymsp[neg(1)].minor.fts5yy11 = sqlite3Fts5ParseColsetInvert(pParse, fts5yymsp[neg(1)].minor.fts5yy11);
        },
        5 => { // colsetlist ::= colsetlist STRING
            fts5yylhsminor.fts5yy11 = sqlite3Fts5ParseColset(pParse, fts5yymsp[neg(1)].minor.fts5yy11, &fts5yymsp[0].minor.fts5yy0);
            fts5yymsp[neg(1)].minor.fts5yy11 = fts5yylhsminor.fts5yy11;
        },
        6 => { // colsetlist ::= STRING
            fts5yylhsminor.fts5yy11 = sqlite3Fts5ParseColset(pParse, null, &fts5yymsp[0].minor.fts5yy0);
            fts5yymsp[0].minor.fts5yy11 = fts5yylhsminor.fts5yy11;
        },
        7 => { // expr ::= expr AND expr
            fts5yylhsminor.fts5yy24 = sqlite3Fts5ParseNode(pParse, FTS5_AND, fts5yymsp[neg(2)].minor.fts5yy24, fts5yymsp[0].minor.fts5yy24, null);
            fts5yymsp[neg(2)].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        8 => { // expr ::= expr OR expr
            fts5yylhsminor.fts5yy24 = sqlite3Fts5ParseNode(pParse, FTS5_OR, fts5yymsp[neg(2)].minor.fts5yy24, fts5yymsp[0].minor.fts5yy24, null);
            fts5yymsp[neg(2)].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        9 => { // expr ::= expr NOT expr
            fts5yylhsminor.fts5yy24 = sqlite3Fts5ParseNode(pParse, FTS5_NOT, fts5yymsp[neg(2)].minor.fts5yy24, fts5yymsp[0].minor.fts5yy24, null);
            fts5yymsp[neg(2)].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        10 => { // expr ::= colset COLON LP expr RP
            sqlite3Fts5ParseSetColset(pParse, fts5yymsp[neg(1)].minor.fts5yy24, fts5yymsp[neg(4)].minor.fts5yy11);
            fts5yylhsminor.fts5yy24 = fts5yymsp[neg(1)].minor.fts5yy24;
            fts5yymsp[neg(4)].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        11 => { // expr ::= LP expr RP
            fts5yymsp[neg(2)].minor.fts5yy24 = fts5yymsp[neg(1)].minor.fts5yy24;
        },
        12, 13 => { // expr ::= exprlist ; exprlist ::= cnearset
            fts5yylhsminor.fts5yy24 = fts5yymsp[0].minor.fts5yy24;
            fts5yymsp[0].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        14 => { // exprlist ::= exprlist cnearset
            fts5yylhsminor.fts5yy24 = sqlite3Fts5ParseImplicitAnd(pParse, fts5yymsp[neg(1)].minor.fts5yy24, fts5yymsp[0].minor.fts5yy24);
            fts5yymsp[neg(1)].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        15 => { // cnearset ::= nearset
            fts5yylhsminor.fts5yy24 = sqlite3Fts5ParseNode(pParse, FTS5_STRING, null, null, fts5yymsp[0].minor.fts5yy46);
            fts5yymsp[0].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        16 => { // cnearset ::= colset COLON nearset
            fts5yylhsminor.fts5yy24 = sqlite3Fts5ParseNode(pParse, FTS5_STRING, null, null, fts5yymsp[0].minor.fts5yy46);
            sqlite3Fts5ParseSetColset(pParse, fts5yylhsminor.fts5yy24, fts5yymsp[neg(2)].minor.fts5yy11);
            fts5yymsp[neg(2)].minor.fts5yy24 = fts5yylhsminor.fts5yy24;
        },
        17 => { // nearset ::= phrase
            fts5yylhsminor.fts5yy46 = sqlite3Fts5ParseNearset(pParse, null, fts5yymsp[0].minor.fts5yy53);
            fts5yymsp[0].minor.fts5yy46 = fts5yylhsminor.fts5yy46;
        },
        18 => { // nearset ::= CARET phrase
            sqlite3Fts5ParseSetCaret(fts5yymsp[0].minor.fts5yy53);
            fts5yymsp[neg(1)].minor.fts5yy46 = sqlite3Fts5ParseNearset(pParse, null, fts5yymsp[0].minor.fts5yy53);
        },
        19 => { // nearset ::= STRING LP nearphrases neardist_opt RP
            sqlite3Fts5ParseNear(pParse, &fts5yymsp[neg(4)].minor.fts5yy0);
            sqlite3Fts5ParseSetDistance(pParse, fts5yymsp[neg(2)].minor.fts5yy46, &fts5yymsp[neg(1)].minor.fts5yy0);
            fts5yylhsminor.fts5yy46 = fts5yymsp[neg(2)].minor.fts5yy46;
            fts5yymsp[neg(4)].minor.fts5yy46 = fts5yylhsminor.fts5yy46;
        },
        20 => { // nearphrases ::= phrase
            fts5yylhsminor.fts5yy46 = sqlite3Fts5ParseNearset(pParse, null, fts5yymsp[0].minor.fts5yy53);
            fts5yymsp[0].minor.fts5yy46 = fts5yylhsminor.fts5yy46;
        },
        21 => { // nearphrases ::= nearphrases phrase
            fts5yylhsminor.fts5yy46 = sqlite3Fts5ParseNearset(pParse, fts5yymsp[neg(1)].minor.fts5yy46, fts5yymsp[0].minor.fts5yy53);
            fts5yymsp[neg(1)].minor.fts5yy46 = fts5yylhsminor.fts5yy46;
        },
        22 => { // neardist_opt ::=
            fts5yymsp[1].minor.fts5yy0.p = null;
            fts5yymsp[1].minor.fts5yy0.n = 0;
        },
        23 => { // neardist_opt ::= COMMA STRING
            fts5yymsp[neg(1)].minor.fts5yy0 = fts5yymsp[0].minor.fts5yy0;
        },
        24 => { // phrase ::= phrase PLUS STRING star_opt
            fts5yylhsminor.fts5yy53 = sqlite3Fts5ParseTerm(pParse, fts5yymsp[neg(3)].minor.fts5yy53, &fts5yymsp[neg(1)].minor.fts5yy0, fts5yymsp[0].minor.fts5yy4);
            fts5yymsp[neg(3)].minor.fts5yy53 = fts5yylhsminor.fts5yy53;
        },
        25 => { // phrase ::= STRING star_opt
            fts5yylhsminor.fts5yy53 = sqlite3Fts5ParseTerm(pParse, null, &fts5yymsp[neg(1)].minor.fts5yy0, fts5yymsp[0].minor.fts5yy4);
            fts5yymsp[neg(1)].minor.fts5yy53 = fts5yylhsminor.fts5yy53;
        },
        26 => { // star_opt ::= STAR
            fts5yymsp[0].minor.fts5yy4 = 1;
        },
        27 => { // star_opt ::=
            fts5yymsp[1].minor.fts5yy4 = 0;
        },
        else => {},
    }

    const fts5yygoto: c_int = fts5yyRuleInfoLhs[fts5yyruleno];
    const fts5yysize: c_int = fts5yyRuleInfoNRhs[fts5yyruleno];
    // fts5yymsp[fts5yysize] (fts5yysize is <= 0): index at a signed offset.
    const fts5yyact = fts5yy_find_reduce_action(
        fts5yymsp[off2idx(fts5yysize)].stateno,
        @intCast(fts5yygoto),
    );

    // No SHIFTREDUCE on nonterminals; a REDUCE cannot be followed by an error.
    // fts5yymsp += fts5yysize+1 (net advance, fts5yysize+1 <= 1).
    fts5yymsp += off2idx(fts5yysize + 1);
    fts5yypParser.fts5yytos = fts5yymsp;
    fts5yymsp[0].stateno = @intCast(fts5yyact);
    fts5yymsp[0].major = @intCast(fts5yygoto);
    return fts5yyact;
}

// fts5yymsp[-N] in C: index/advance a [*] pointer by a signed element offset.
// (Bit-casting the signed value to usize makes [*]T indexing / += wrap to the
//  correct negative byte offset.)
inline fn neg(comptime n: comptime_int) usize {
    return @bitCast(@as(isize, -n));
}
inline fn off2idx(o: c_int) usize {
    return @bitCast(@as(isize, o));
}

// ===========================================================================
// fts5yy_syntax_error (amalgamation 3080-3099).
// ===========================================================================
fn fts5yy_syntax_error(
    fts5yypParser: *fts5yyParser,
    fts5yymajor: c_int,
    fts5yyminor: Fts5Token,
) void {
    _ = fts5yymajor;
    const pParse = fts5yypParser.pParse;
    sqlite3Fts5ParseError(pParse, "fts5: syntax error near \"%.*s\"", fts5yyminor.n, fts5yyminor.p);
}

// ===========================================================================
// fts5yy_accept (amalgamation 3104-3124).
// ===========================================================================
fn fts5yy_accept(fts5yypParser: *fts5yyParser) void {
    _ = fts5yypParser;
    // %parse_accept code is empty.
}

// ===========================================================================
// sqlite3Fts5Parser (amalgamation 3145-3349): the main push-down automaton.
// fts5YYNOERRORRECOVERY is defined and fts5YYERRORSYMBOL is not, so the error
// path is the simple "report + discard, fail on $" branch.
// Exported: the only entry point fts5_expr.c drives.
// ===========================================================================
export fn sqlite3Fts5Parser(
    fts5yyp: ?*anyopaque,
    fts5yymajor0: c_int,
    fts5yyminor: Fts5Token,
    pParse: ?*Fts5Parse,
) callconv(.c) void {
    const fts5yymajor = fts5yymajor0;
    var fts5yyminorunion: fts5YYMINORTYPE = undefined;
    var fts5yyact: fts5YYACTIONTYPE = undefined;
    const fts5yyendofinput: c_int = @intFromBool(fts5yymajor == 0);
    const fts5yypParser: *fts5yyParser = @ptrCast(@alignCast(fts5yyp.?));
    fts5yypParser.pParse = pParse; // ARG_STORE

    fts5yyact = fts5yypParser.fts5yytos[0].stateno;

    while (true) { // Exit by "break"/"return"
        fts5yyact = fts5yy_find_shift_action(@intCast(fts5yymajor), fts5yyact);
        if (@as(c_int, fts5yyact) >= fts5YY_MIN_REDUCE) {
            const fts5yyruleno: c_uint = @intCast(@as(c_int, fts5yyact) - fts5YY_MIN_REDUCE);
            // Ensure room to push the LHS of an empty-RHS rule.
            if (fts5yyRuleInfoNRhs[fts5yyruleno] == 0) {
                if (@intFromPtr(fts5yypParser.fts5yytos) >= @intFromPtr(fts5yypParser.fts5yystackEnd)) {
                    // fts5yyGrowStack()==1 (non-growable): overflow.
                    fts5yyStackOverflow(fts5yypParser);
                    break;
                }
            }
            fts5yyact = fts5yy_reduce(fts5yypParser, fts5yyruleno, fts5yymajor, fts5yyminor);
        } else if (@as(c_int, fts5yyact) <= fts5YY_MAX_SHIFTREDUCE) {
            fts5yy_shift(fts5yypParser, fts5yyact, @intCast(fts5yymajor), fts5yyminor);
            break;
        } else if (@as(c_int, fts5yyact) == fts5YY_ACCEPT_ACTION) {
            fts5yypParser.fts5yytos -= 1;
            fts5yy_accept(fts5yypParser);
            return;
        } else {
            // fts5yyact == fts5YY_ERROR_ACTION
            fts5yyminorunion.fts5yy0 = fts5yyminor;
            // fts5YYNOERRORRECOVERY: report once per 3-token window, discard token,
            // fail the parse at end-of-input.
            if (fts5yyerrcntLE0(fts5yypParser)) {
                fts5yy_syntax_error(fts5yypParser, fts5yymajor, fts5yyminor);
            }
            fts5yy_destructor(fts5yypParser, @intCast(fts5yymajor), &fts5yyminorunion);
            if (fts5yyendofinput != 0) {
                // fts5yy_parse_failed inlined: pop the whole stack.
                // (fts5YYNOERRORRECOVERY -> no fts5yyerrcnt to reset.)
                fts5yyParseFailed(fts5yypParser);
            }
            break;
        }
    }
    return;
}

// In the production config (fts5YYNOERRORRECOVERY defined) fts5yyParser has no
// fts5yyerrcnt member; the C "if(errcnt<=0)" reduces to "always report" because
// the field is compiled out and only the fts5YYERRORSYMBOL-undefined branch is
// taken. Reproduce that: always report.
inline fn fts5yyerrcntLE0(_: *fts5yyParser) bool {
    return true;
}

// fts5yy_parse_failed (amalgamation 3057-3074), reachable here because the
// generic (non-ERRORSYMBOL) error branch calls it at end of input.
fn fts5yyParseFailed(fts5yypParser: *fts5yyParser) void {
    while (@intFromPtr(fts5yypParser.fts5yytos) > @intFromPtr(fts5yypParser.fts5yystack)) {
        fts5yy_pop_parser_stack(fts5yypParser);
    }
    // %parse_failure code is empty.
}

// ===========================================================================
// sqlite3Fts5ParserFallback (amalgamation 3355-3363). fts5YYFALLBACK undefined,
// so this is always the no-op form. Exported: referenced by fts5_expr.c (to
// silence an unused-symbol warning) and must exist at link time.
// ===========================================================================
export fn sqlite3Fts5ParserFallback(iToken: c_int) callconv(.c) c_int {
    _ = iToken;
    return 0;
}

// ===========================================================================
// sqlite3Fts5ParserTrace (amalgamation 2185-2190). NDEBUG-only no-op shim: the
// production build #defines NDEBUG so the body is empty, but fts5_expr.c takes
// its address under `#ifndef NDEBUG`. Exported as a harmless stub so the symbol
// resolves regardless of NDEBUG.
// ===========================================================================
export fn sqlite3Fts5ParserTrace(TraceFILE: ?*anyopaque, zTracePrompt: ?[*:0]u8) callconv(.c) void {
    _ = TraceFILE;
    _ = zTracePrompt;
}

comptime {
    _ = int;
}
