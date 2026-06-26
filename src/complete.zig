//! Zig port of SQLite's sqlite3_complete() SQL tokenizer (src/complete.c).
//!
//! Drop-in replacement exporting `sqlite3_incomplete`, `sqlite3_complete`,
//! `sqlite3_complete16`. A self-contained state machine that decides whether a
//! SQL string forms one or more complete statements (all literals/comments
//! closed, ends in ";", or ";END;" for CREATE TRIGGER). The only couplings are
//! function calls and the config-invariant `sqlite3CtypeMap[]` lookup table —
//! no internal struct layouts are touched (`sqlite3_complete16` passes the
//! `sqlite3_value*` around opaquely), so this one Zig object is correct in both
//! the production `zig build` and the `--dev` testfixture configs.
//!
//! Build config assumed (true in both this project's builds): SQLITE_ASCII (not
//! EBCDIC), triggers/explain/utf16/complete not omitted, autoinit on, no
//! SQLITE_ENABLE_API_ARMOR.

const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT collapses to this
const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16NATIVE: u8 = 2; // little-endian target -> SQLITE_UTF16LE

// Token types for the state machine.
const tkSEMI: u8 = 0;
const tkWS: u8 = 1;
const tkOTHER: u8 = 2;
const tkEXPLAIN: u8 = 3;
const tkCREATE: u8 = 4;
const tkTEMP: u8 = 5;
const tkTRIGGER: u8 = 6;
const tkEND: u8 = 7;

// --- C helpers / data resolved at link time ---
extern const sqlite3CtypeMap: [256]u8;
extern fn sqlite3_strnicmp(a: [*:0]const u8, b: [*:0]const u8, n: c_int) c_int;
extern fn sqlite3_initialize() c_int;
extern fn sqlite3ValueNew(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ValueSetStr(v: ?*anyopaque, n: c_int, z: ?*const anyopaque, enc: u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3ValueText(v: ?*anyopaque, enc: u8) ?[*:0]const u8;
extern fn sqlite3ValueFree(v: ?*anyopaque) void;

/// Keyword/identifier character test (SQLITE_ASCII: mask 0x46).
inline fn idChar(c: u8) bool {
    return (sqlite3CtypeMap[c] & 0x46) != 0;
}

// State transition table (with trigger support): trans[state][token].
const trans = [8][8]u8{
    //  SEMI WS OTHER EXPLAIN CREATE TEMP TRIGGER END
    .{ 1, 0, 2, 3, 4, 2, 2, 2 }, // 0 INVALID
    .{ 1, 1, 2, 3, 4, 2, 2, 2 }, // 1 START
    .{ 1, 2, 2, 2, 2, 2, 2, 2 }, // 2 NORMAL
    .{ 1, 3, 3, 2, 4, 2, 2, 2 }, // 3 EXPLAIN
    .{ 1, 4, 2, 2, 2, 4, 5, 2 }, // 4 CREATE
    .{ 6, 5, 5, 5, 5, 5, 5, 5 }, // 5 TRIGGER
    .{ 6, 6, 5, 5, 5, 5, 5, 7 }, // 6 SEMI
    .{ 1, 7, 5, 5, 5, 5, 5, 5 }, // 7 END
};

// Map state number to the yy byte of the return value.
const statemap = [8]u8{ 1, 0, 1, 1, 1, 3, 2, 1 };

/// Return 0 if zSql is a complete SQL input, else a non-zero code whose
/// subfields describe what is missing (see complete.c header for the encoding).
export fn sqlite3_incomplete(zSql_in: [*:0]const u8) callconv(.c) i64 {
    var state: u8 = 0; // current state
    var token: u8 = undefined; // next token
    var pending: u8 = 0; // unmatched structure character
    var nParen: c_int = 0; // nested parentheses
    var zSql = zSql_in;

    sm: {
        while (zSql[0] != 0) {
            switch (zSql[0]) {
                ';' => token = tkSEMI,
                ' ', '\r', '\t', '\n', '\x0c' => token = tkWS,
                '/' => { // C-style comments
                    if (zSql[1] != '*') {
                        token = tkOTHER;
                    } else {
                        zSql += 2;
                        while (zSql[0] != 0 and (zSql[0] != '*' or zSql[1] != '/')) zSql += 1;
                        if (zSql[0] == 0) {
                            pending = '/';
                            break :sm;
                        }
                        zSql += 1;
                        token = tkWS;
                    }
                },
                '-' => { // SQL-style "--" comments to end of line
                    if (zSql[1] != '-') {
                        token = tkOTHER;
                    } else {
                        while (zSql[0] != 0 and zSql[0] != '\n') zSql += 1;
                        if (zSql[0] == 0) {
                            if (state != 1) pending = '-';
                            break :sm;
                        }
                        token = tkWS;
                    }
                },
                '[' => { // Microsoft-style [...] identifiers
                    zSql += 1;
                    while (zSql[0] != 0 and zSql[0] != ']') zSql += 1;
                    if (zSql[0] == 0) {
                        pending = ']';
                        break :sm;
                    }
                    token = tkOTHER;
                },
                '`', '"', '\'' => { // quoted strings / identifiers
                    const c = zSql[0];
                    zSql += 1;
                    while (zSql[0] != 0 and zSql[0] != c) zSql += 1;
                    if (zSql[0] == 0) {
                        pending = c;
                        break :sm;
                    }
                    token = tkOTHER;
                },
                '(' => {
                    nParen += 1;
                    token = tkOTHER;
                },
                ')' => {
                    nParen -= 1;
                    token = tkOTHER;
                },
                else => {
                    if (idChar(zSql[0])) {
                        // Keywords and unquoted identifiers
                        var nId: usize = 1;
                        while (idChar(zSql[nId])) : (nId += 1) {}
                        switch (zSql[0]) {
                            'c', 'C' => token = if (nId == 6 and sqlite3_strnicmp(zSql, "create", 6) == 0) tkCREATE else tkOTHER,
                            't', 'T' => {
                                if (nId == 7 and sqlite3_strnicmp(zSql, "trigger", 7) == 0) {
                                    token = tkTRIGGER;
                                } else if (nId == 4 and sqlite3_strnicmp(zSql, "temp", 4) == 0) {
                                    token = tkTEMP;
                                } else if (nId == 9 and sqlite3_strnicmp(zSql, "temporary", 9) == 0) {
                                    token = tkTEMP;
                                } else {
                                    token = tkOTHER;
                                }
                            },
                            'e', 'E' => {
                                if (nId == 3 and sqlite3_strnicmp(zSql, "end", 3) == 0) {
                                    token = tkEND;
                                } else if (nId == 7 and sqlite3_strnicmp(zSql, "explain", 7) == 0) {
                                    token = tkEXPLAIN;
                                } else {
                                    token = tkOTHER;
                                }
                            },
                            else => token = tkOTHER,
                        }
                        zSql += nId - 1;
                    } else {
                        // Operators and special symbols
                        token = tkOTHER;
                    }
                },
            }
            state = trans[state][token];
            zSql += 1;
        }
    }

    // incomplete_finish:
    if (state == 1) nParen = 0;
    const r = (@as(u64, @as(u32, @bitCast(nParen))) << 32) |
        (@as(u64, pending) << 16) |
        (@as(u64, statemap[state]) << 8) |
        @as(u64, @intFromBool(state != 1));
    return @bitCast(r);
}

/// Return true (1) if zSql forms one or more complete SQL statements.
export fn sqlite3_complete(zSql: [*:0]const u8) callconv(.c) c_int {
    return @intFromBool(sqlite3_incomplete(zSql) == 0);
}

/// UTF-16 variant: transcode to UTF-8, then reuse sqlite3_incomplete.
export fn sqlite3_complete16(zSql: ?*const anyopaque) callconv(.c) c_int {
    const rc0 = sqlite3_initialize();
    if (rc0 != 0) return rc0;
    const pVal = sqlite3ValueNew(null);
    sqlite3ValueSetStr(pVal, -1, zSql, SQLITE_UTF16NATIVE, null);
    var rc: c_int = undefined;
    if (sqlite3ValueText(pVal, SQLITE_UTF8)) |zSql8| {
        rc = @intFromBool(sqlite3_incomplete(zSql8) == 0);
    } else {
        rc = SQLITE_NOMEM;
    }
    sqlite3ValueFree(pVal);
    return rc & 0xff;
}
