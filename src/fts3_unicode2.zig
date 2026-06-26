//! Zig port of SQLite's FTS3 Unicode case-fold / category DATA module
//! (ext/fts3/fts3_unicode2.c — itself a machine-generated file from the Unicode
//! Character Database).
//!
//! Drop-in replacement exporting the three external symbols read across the C
//! ABI by the already-ported fts3_unicode.zig (and by fts5):
//!
//!   - `sqlite3FtsUnicodeIsalnum(int c)`        -> 1 if letter/number, else 0
//!   - `sqlite3FtsUnicodeIsdiacritic(int c)`    -> 1 if combining diacritic mark
//!   - `sqlite3FtsUnicodeFold(int c, int e)`    -> lower-case fold of `c`,
//!                                                 optionally diacritic-stripped
//!
//! These are pure functions over large `static const` tables. Each table encodes
//! Unicode codepoint ranges with packed bit fields; the lookups are binary
//! searches plus bit twiddling. Every value below is copied byte-for-byte from
//! the C source — the tables ARE the spec, so they must match exactly.
//!
//! Coupling taxonomy: NONE. No structs cross the ABI; the signatures are just
//! `int -> int`. The `static remove_diacritic()` helper stays a private Zig
//! function. No `sqlite3` calls, no allocators.
//!
//! Config-invariant: no `@import("config")`. The C file is gated only by
//! `!SQLITE_DISABLE_FTS3_UNICODE && (SQLITE_ENABLE_FTS3 || SQLITE_ENABLE_FTS4)`,
//! constant across both this project's builds. The C `assert()`s have no
//! externally visible effect (they compile away in production and merely abort
//! on impossible inputs under `--dev`); the Zig `std.debug.assert`s mirror that —
//! active in Debug/ReleaseSafe, elided in ReleaseFast. So the same object is
//! correct in production `zig build` and in the `--dev` testfixture build. No
//! c_layout offsets are needed.
//!
//! Bit-math notes (C `unsigned int` wraps; Zig must be explicit):
//!   - C `<<` on u32 that may overflow -> Zig `*%` with a power-of-two literal,
//!     or `<<` on a value proven in range. Here the shift amounts (0..31) keep
//!     `1u << k` in range, so plain `<<` on u32 is exact.
//!   - C `(unsigned char)`/`(u8)` casts -> `@truncate`.
//!   - The range decode `(C<<22)+N` / `(C<<10)|0x3FF` / `(C<<3)|7` is done on u32.

const std = @import("std");

// ---------------------------------------------------------------------------
// sqlite3FtsUnicodeIsalnum
// ---------------------------------------------------------------------------

/// Each u32 encodes a contiguous range of codepoints that are NOT letters or
/// numbers. The top 22 bits hold the first codepoint C; the low 10 bits hold
/// the range size N (>=1). Value == (C<<22)+N. Sorted ascending.
const isalnum_aEntry = [_]u32{
    0x00000030, 0x0000E807, 0x00016C06, 0x0001EC2F, 0x0002AC07,
    0x0002D001, 0x0002D803, 0x0002EC01, 0x0002FC01, 0x00035C01,
    0x0003DC01, 0x000B0804, 0x000B480E, 0x000B9407, 0x000BB401,
    0x000BBC81, 0x000DD401, 0x000DF801, 0x000E1002, 0x000E1C01,
    0x000FD801, 0x00120808, 0x00156806, 0x00162402, 0x00163C01,
    0x00164437, 0x0017CC02, 0x00180005, 0x00181816, 0x00187802,
    0x00192C15, 0x0019A804, 0x0019C001, 0x001B5001, 0x001B580F,
    0x001B9C07, 0x001BF402, 0x001C000E, 0x001C3C01, 0x001C4401,
    0x001CC01B, 0x001E980B, 0x001FAC09, 0x001FD804, 0x00205804,
    0x00206C09, 0x00209403, 0x0020A405, 0x0020C00F, 0x00216403,
    0x00217801, 0x0023901B, 0x00240004, 0x0024E803, 0x0024F812,
    0x00254407, 0x00258804, 0x0025C001, 0x00260403, 0x0026F001,
    0x0026F807, 0x00271C02, 0x00272C03, 0x00275C01, 0x00278802,
    0x0027C802, 0x0027E802, 0x00280403, 0x0028F001, 0x0028F805,
    0x00291C02, 0x00292C03, 0x00294401, 0x0029C002, 0x0029D401,
    0x002A0403, 0x002AF001, 0x002AF808, 0x002B1C03, 0x002B2C03,
    0x002B8802, 0x002BC002, 0x002C0403, 0x002CF001, 0x002CF807,
    0x002D1C02, 0x002D2C03, 0x002D5802, 0x002D8802, 0x002DC001,
    0x002E0801, 0x002EF805, 0x002F1803, 0x002F2804, 0x002F5C01,
    0x002FCC08, 0x00300403, 0x0030F807, 0x00311803, 0x00312804,
    0x00315402, 0x00318802, 0x0031FC01, 0x00320802, 0x0032F001,
    0x0032F807, 0x00331803, 0x00332804, 0x00335402, 0x00338802,
    0x00340802, 0x0034F807, 0x00351803, 0x00352804, 0x00355C01,
    0x00358802, 0x0035E401, 0x00360802, 0x00372801, 0x00373C06,
    0x00375801, 0x00376008, 0x0037C803, 0x0038C401, 0x0038D007,
    0x0038FC01, 0x00391C09, 0x00396802, 0x003AC401, 0x003AD006,
    0x003AEC02, 0x003B2006, 0x003C041F, 0x003CD00C, 0x003DC417,
    0x003E340B, 0x003E6424, 0x003EF80F, 0x003F380D, 0x0040AC14,
    0x00412806, 0x00415804, 0x00417803, 0x00418803, 0x00419C07,
    0x0041C404, 0x0042080C, 0x00423C01, 0x00426806, 0x0043EC01,
    0x004D740C, 0x004E400A, 0x00500001, 0x0059B402, 0x005A0001,
    0x005A6C02, 0x005BAC03, 0x005C4803, 0x005CC805, 0x005D4802,
    0x005DC802, 0x005ED023, 0x005F6004, 0x005F7401, 0x0060000F,
    0x0062A401, 0x0064800C, 0x0064C00C, 0x00650001, 0x00651002,
    0x0066C011, 0x00672002, 0x00677822, 0x00685C05, 0x00687802,
    0x0069540A, 0x0069801D, 0x0069FC01, 0x006A8007, 0x006AA006,
    0x006C0005, 0x006CD011, 0x006D6823, 0x006E0003, 0x006E840D,
    0x006F980E, 0x006FF004, 0x00709014, 0x0070EC05, 0x0071F802,
    0x00730008, 0x00734019, 0x0073B401, 0x0073C803, 0x00770027,
    0x0077F004, 0x007EF401, 0x007EFC03, 0x007F3403, 0x007F7403,
    0x007FB403, 0x007FF402, 0x00800065, 0x0081A806, 0x0081E805,
    0x00822805, 0x0082801A, 0x00834021, 0x00840002, 0x00840C04,
    0x00842002, 0x00845001, 0x00845803, 0x00847806, 0x00849401,
    0x00849C01, 0x0084A401, 0x0084B801, 0x0084E802, 0x00850005,
    0x00852804, 0x00853C01, 0x00864264, 0x00900027, 0x0091000B,
    0x0092704E, 0x00940200, 0x009C0475, 0x009E53B9, 0x00AD400A,
    0x00B39406, 0x00B3BC03, 0x00B3E404, 0x00B3F802, 0x00B5C001,
    0x00B5FC01, 0x00B7804F, 0x00B8C00C, 0x00BA001A, 0x00BA6C59,
    0x00BC00D6, 0x00BFC00C, 0x00C00005, 0x00C02019, 0x00C0A807,
    0x00C0D802, 0x00C0F403, 0x00C26404, 0x00C28001, 0x00C3EC01,
    0x00C64002, 0x00C6580A, 0x00C70024, 0x00C8001F, 0x00C8A81E,
    0x00C94001, 0x00C98020, 0x00CA2827, 0x00CB003F, 0x00CC0100,
    0x01370040, 0x02924037, 0x0293F802, 0x02983403, 0x0299BC10,
    0x029A7C01, 0x029BC008, 0x029C0017, 0x029C8002, 0x029E2402,
    0x02A00801, 0x02A01801, 0x02A02C01, 0x02A08C09, 0x02A0D804,
    0x02A1D004, 0x02A20002, 0x02A2D011, 0x02A33802, 0x02A38012,
    0x02A3E003, 0x02A4980A, 0x02A51C0D, 0x02A57C01, 0x02A60004,
    0x02A6CC1B, 0x02A77802, 0x02A8A40E, 0x02A90C01, 0x02A93002,
    0x02A97004, 0x02A9DC03, 0x02A9EC01, 0x02AAC001, 0x02AAC803,
    0x02AADC02, 0x02AAF802, 0x02AB0401, 0x02AB7802, 0x02ABAC07,
    0x02ABD402, 0x02AF8C0B, 0x03600001, 0x036DFC02, 0x036FFC02,
    0x037FFC01, 0x03EC7801, 0x03ECA401, 0x03EEC810, 0x03F4F802,
    0x03F7F002, 0x03F8001A, 0x03F88007, 0x03F8C023, 0x03F95013,
    0x03F9A004, 0x03FBFC01, 0x03FC040F, 0x03FC6807, 0x03FCEC06,
    0x03FD6C0B, 0x03FF8007, 0x03FFA007, 0x03FFE405, 0x04040003,
    0x0404DC09, 0x0405E411, 0x0406400C, 0x0407402E, 0x040E7C01,
    0x040F4001, 0x04215C01, 0x04247C01, 0x0424FC01, 0x04280403,
    0x04281402, 0x04283004, 0x0428E003, 0x0428FC01, 0x04294009,
    0x0429FC01, 0x042CE407, 0x04400003, 0x0440E016, 0x04420003,
    0x0442C012, 0x04440003, 0x04449C0E, 0x04450004, 0x04460003,
    0x0446CC0E, 0x04471404, 0x045AAC0D, 0x0491C004, 0x05BD442E,
    0x05BE3C04, 0x074000F6, 0x07440027, 0x0744A4B5, 0x07480046,
    0x074C0057, 0x075B0401, 0x075B6C01, 0x075BEC01, 0x075C5401,
    0x075CD401, 0x075D3C01, 0x075DBC01, 0x075E2401, 0x075EA401,
    0x075F0C01, 0x07BBC002, 0x07C0002C, 0x07C0C064, 0x07C2800F,
    0x07C2C40E, 0x07C3040F, 0x07C3440F, 0x07C4401F, 0x07C4C03C,
    0x07C5C02B, 0x07C7981D, 0x07C8402B, 0x07C90009, 0x07C94002,
    0x07CC0021, 0x07CCC006, 0x07CCDC46, 0x07CE0014, 0x07CE8025,
    0x07CF1805, 0x07CF8011, 0x07D0003F, 0x07D10001, 0x07D108B6,
    0x07D3E404, 0x07D4003E, 0x07D50004, 0x07D54018, 0x07D7EC46,
    0x07D9140B, 0x07DA0046, 0x07DC0074, 0x38000401, 0x38008060,
    0x380400F0,
};

/// Bit-set of the ASCII (0..127) codepoints that are NOT alnum.
const isalnum_aAscii = [4]u32{
    0xFFFFFFFF, 0xFC00FFFF, 0xF8000001, 0xF8000001,
};

/// Return true (1) if the argument is a Unicode letter or number. Results are
/// undefined if `c` < 0 (C contract). Mirrors C exactly.
export fn sqlite3FtsUnicodeIsalnum(c: c_int) callconv(.c) c_int {
    const uc: u32 = @bitCast(c);
    if (uc < 128) {
        // (aAscii[c>>5] & (1u << (c & 0x1F))) == 0
        const bit: u32 = @as(u32, 1) << @truncate(uc & 0x1F);
        return @intFromBool((isalnum_aAscii[uc >> 5] & bit) == 0);
    } else if (uc < (1 << 22)) {
        const key: u32 = (uc << 10) | 0x000003FF;
        var iRes: usize = 0;
        var iHi: isize = @as(isize, @intCast(isalnum_aEntry.len)) - 1;
        var iLo: isize = 0;
        while (iHi >= iLo) {
            const iTest: isize = @divTrunc(iHi + iLo, 2);
            if (key >= isalnum_aEntry[@intCast(iTest)]) {
                iRes = @intCast(iTest);
                iLo = iTest + 1;
            } else {
                iHi = iTest - 1;
            }
        }
        std.debug.assert(isalnum_aEntry[0] < key);
        std.debug.assert(key >= isalnum_aEntry[iRes]);
        const e = isalnum_aEntry[iRes];
        return @intFromBool(uc >= ((e >> 10) + (e & 0x3FF)));
    }
    return 1;
}

// ---------------------------------------------------------------------------
// remove_diacritic (static helper)
// ---------------------------------------------------------------------------

/// Sorted table of packed (codepoint<<3 | rangeSize) for accented letters.
const dia_aDia = [_]u16{
    0,     1797,  1848,  1859,  1891,  1928,  1940,  1995,
    2024,  2040,  2060,  2110,  2168,  2206,  2264,  2286,
    2344,  2383,  2472,  2488,  2516,  2596,  2668,  2732,
    2782,  2842,  2894,  2954,  2984,  3000,  3028,  3336,
    3456,  3696,  3712,  3728,  3744,  3766,  3832,  3896,
    3912,  3928,  3944,  3968,  4008,  4040,  4056,  4106,
    4138,  4170,  4202,  4234,  4266,  4296,  4312,  4344,
    4408,  4424,  4442,  4472,  4488,  4504,  6148,  6198,
    6264,  6280,  6360,  6429,  6505,  6529,  61448, 61468,
    61512, 61534, 61592, 61610, 61642, 61672, 61688, 61704,
    61726, 61784, 61800, 61816, 61836, 61880, 61896, 61914,
    61948, 61998, 62062, 62122, 62154, 62184, 62200, 62218,
    62252, 62302, 62364, 62410, 62442, 62478, 62536, 62554,
    62584, 62604, 62640, 62648, 62656, 62664, 62730, 62766,
    62830, 62890, 62924, 62974, 63032, 63050, 63082, 63118,
    63182, 63242, 63274, 63310, 63368, 63390,
};

const HIBIT: u8 = 0x80;

/// Parallel to dia_aDia: the ASCII base letter for each accented entry. The
/// high bit (0x80) marks "complex" mappings only applied when bComplex!=0.
const dia_aChar = [_]u8{
    0,           'a',         'c',         'e',          'i',          'n',
    'o',         'u',         'y',         'y',          'a',          'c',
    'd',         'e',         'e',         'g',          'h',          'i',
    'j',         'k',         'l',         'n',          'o',          'r',
    's',         't',         'u',         'u',          'w',          'y',
    'z',         'o',         'u',         'a',          'i',          'o',
    'u',         'u' | HIBIT, 'a' | HIBIT, 'g',          'k',          'o',
    'o' | HIBIT, 'j',         'g',         'n',          'a' | HIBIT,  'a',
    'e',         'i',         'o',         'r',          'u',          's',
    't',         'h',         'a',         'e',          'o' | HIBIT,  'o',
    'o' | HIBIT, 'y',         0,           0,            0,            0,
    0,           0,           0,           0,            'a',          'b',
    'c' | HIBIT, 'd',         'd',         'e' | HIBIT,  'e',          'e' | HIBIT,
    'f',         'g',         'h',         'h',          'i',          'i' | HIBIT,
    'k',         'l',         'l' | HIBIT, 'l',          'm',          'n',
    'o' | HIBIT, 'p',         'r',         'r' | HIBIT,  'r',          's',
    's' | HIBIT, 't',         'u',         'u' | HIBIT,  'v',          'w',
    'w',         'x',         'y',         'z',          'h',          't',
    'w',         'y',         'a',         'a' | HIBIT,  'a' | HIBIT,  'a' | HIBIT,
    'e',         'e' | HIBIT, 'e' | HIBIT, 'i',          'o',          'o' | HIBIT,
    'o' | HIBIT, 'o' | HIBIT, 'u',         'u' | HIBIT,  'u' | HIBIT,  'y',
};

/// If `c` is a lowercase ASCII letter with a diacritic, return the bare ASCII
/// letter; otherwise return `c`. Results undefined for uppercase input.
/// `bComplex` enables the high-bit ("complex") mappings.
fn remove_diacritic(c: c_int, bComplex: bool) c_int {
    const key: u32 = (@as(u32, @bitCast(c)) << 3) | 0x00000007;
    var iRes: usize = 0;
    var iHi: isize = @as(isize, @intCast(dia_aDia.len)) - 1;
    var iLo: isize = 0;
    while (iHi >= iLo) {
        const iTest: isize = @divTrunc(iHi + iLo, 2);
        if (key >= dia_aDia[@intCast(iTest)]) {
            iRes = @intCast(iTest);
            iLo = iTest + 1;
        } else {
            iHi = iTest - 1;
        }
    }
    std.debug.assert(key >= dia_aDia[iRes]);
    if (!bComplex and (dia_aChar[iRes] & 0x80) != 0) return c;
    const d = dia_aDia[iRes];
    const limit: c_int = @intCast((d >> 3) + (d & 0x07));
    return if (c > limit) c else (@as(c_int, dia_aChar[iRes]) & 0x7F);
}

// ---------------------------------------------------------------------------
// sqlite3FtsUnicodeIsdiacritic
// ---------------------------------------------------------------------------

/// Return true (1) if `c` is a combining diacritical mark (U+0300..U+0331 subset).
export fn sqlite3FtsUnicodeIsdiacritic(c: c_int) callconv(.c) c_int {
    const mask0: u32 = 0x08029FDF;
    const mask1: u32 = 0x000361F8;
    if (c < 768 or c > 817) return 0;
    if (c < 768 + 32) {
        const shift: u5 = @truncate(@as(u32, @bitCast(c - 768)));
        return @intFromBool((mask0 & (@as(u32, 1) << shift)) != 0);
    } else {
        const shift: u5 = @truncate(@as(u32, @bitCast(c - 768 - 32)));
        return @intFromBool((mask1 & (@as(u32, 1) << shift)) != 0);
    }
}

// ---------------------------------------------------------------------------
// sqlite3FtsUnicodeFold
// ---------------------------------------------------------------------------

/// Case-folding rule. Applies to `nRange` codepoints starting at `iCode`.
/// If (flags & 1)==0 the rule covers every codepoint in the range; if set, only
/// every second one (starting at iCode). `flags>>1` indexes fold_aiOff[]; the
/// fold of C is ((C + aiOff[flags>>1]) & 0xFFFF).
const TableEntry = struct { iCode: u16, flags: u8, nRange: u8 };

fn te(iCode: u16, flags: u8, nRange: u8) TableEntry {
    return .{ .iCode = iCode, .flags = flags, .nRange = nRange };
}

const fold_aEntry = [_]TableEntry{
    te(65, 14, 26),     te(181, 64, 1),    te(192, 14, 23),
    te(216, 14, 7),     te(256, 1, 48),    te(306, 1, 6),
    te(313, 1, 16),     te(330, 1, 46),    te(376, 116, 1),
    te(377, 1, 6),      te(383, 104, 1),   te(385, 50, 1),
    te(386, 1, 4),      te(390, 44, 1),    te(391, 0, 1),
    te(393, 42, 2),     te(395, 0, 1),     te(398, 32, 1),
    te(399, 38, 1),     te(400, 40, 1),    te(401, 0, 1),
    te(403, 42, 1),     te(404, 46, 1),    te(406, 52, 1),
    te(407, 48, 1),     te(408, 0, 1),     te(412, 52, 1),
    te(413, 54, 1),     te(415, 56, 1),    te(416, 1, 6),
    te(422, 60, 1),     te(423, 0, 1),     te(425, 60, 1),
    te(428, 0, 1),      te(430, 60, 1),    te(431, 0, 1),
    te(433, 58, 2),     te(435, 1, 4),     te(439, 62, 1),
    te(440, 0, 1),      te(444, 0, 1),     te(452, 2, 1),
    te(453, 0, 1),      te(455, 2, 1),     te(456, 0, 1),
    te(458, 2, 1),      te(459, 1, 18),    te(478, 1, 18),
    te(497, 2, 1),      te(498, 1, 4),     te(502, 122, 1),
    te(503, 134, 1),    te(504, 1, 40),    te(544, 110, 1),
    te(546, 1, 18),     te(570, 70, 1),    te(571, 0, 1),
    te(573, 108, 1),    te(574, 68, 1),    te(577, 0, 1),
    te(579, 106, 1),    te(580, 28, 1),    te(581, 30, 1),
    te(582, 1, 10),     te(837, 36, 1),    te(880, 1, 4),
    te(886, 0, 1),      te(902, 18, 1),    te(904, 16, 3),
    te(908, 26, 1),     te(910, 24, 2),    te(913, 14, 17),
    te(931, 14, 9),     te(962, 0, 1),     te(975, 4, 1),
    te(976, 140, 1),    te(977, 142, 1),   te(981, 146, 1),
    te(982, 144, 1),    te(984, 1, 24),    te(1008, 136, 1),
    te(1009, 138, 1),   te(1012, 130, 1),  te(1013, 128, 1),
    te(1015, 0, 1),     te(1017, 152, 1),  te(1018, 0, 1),
    te(1021, 110, 3),   te(1024, 34, 16),  te(1040, 14, 32),
    te(1120, 1, 34),    te(1162, 1, 54),   te(1216, 6, 1),
    te(1217, 1, 14),    te(1232, 1, 88),   te(1329, 22, 38),
    te(4256, 66, 38),   te(4295, 66, 1),   te(4301, 66, 1),
    te(7680, 1, 150),   te(7835, 132, 1),  te(7838, 96, 1),
    te(7840, 1, 96),    te(7944, 150, 8),  te(7960, 150, 6),
    te(7976, 150, 8),   te(7992, 150, 8),  te(8008, 150, 6),
    te(8025, 151, 8),   te(8040, 150, 8),  te(8072, 150, 8),
    te(8088, 150, 8),   te(8104, 150, 8),  te(8120, 150, 2),
    te(8122, 126, 2),   te(8124, 148, 1),  te(8126, 100, 1),
    te(8136, 124, 4),   te(8140, 148, 1),  te(8152, 150, 2),
    te(8154, 120, 2),   te(8168, 150, 2),  te(8170, 118, 2),
    te(8172, 152, 1),   te(8184, 112, 2),  te(8186, 114, 2),
    te(8188, 148, 1),   te(8486, 98, 1),   te(8490, 92, 1),
    te(8491, 94, 1),    te(8498, 12, 1),   te(8544, 8, 16),
    te(8579, 0, 1),     te(9398, 10, 26),  te(11264, 22, 47),
    te(11360, 0, 1),    te(11362, 88, 1),  te(11363, 102, 1),
    te(11364, 90, 1),   te(11367, 1, 6),   te(11373, 84, 1),
    te(11374, 86, 1),   te(11375, 80, 1),  te(11376, 82, 1),
    te(11378, 0, 1),    te(11381, 0, 1),   te(11390, 78, 2),
    te(11392, 1, 100),  te(11499, 1, 4),   te(11506, 0, 1),
    te(42560, 1, 46),   te(42624, 1, 24),  te(42786, 1, 14),
    te(42802, 1, 62),   te(42873, 1, 4),   te(42877, 76, 1),
    te(42878, 1, 10),   te(42891, 0, 1),   te(42893, 74, 1),
    te(42896, 1, 4),    te(42912, 1, 10),  te(42922, 72, 1),
    te(65313, 14, 26),
};

const fold_aiOff = [_]u16{
    1,     2,     8,     15,    16,    26,    28,    32,
    37,    38,    40,    48,    63,    64,    69,    71,
    79,    80,    116,   202,   203,   205,   206,   207,
    209,   210,   211,   213,   214,   217,   218,   219,
    775,   7264,  10792, 10795, 23228, 23256, 30204, 54721,
    54753, 54754, 54756, 54787, 54793, 54809, 57153, 57274,
    57921, 58019, 58363, 61722, 65268, 65341, 65373, 65406,
    65408, 65410, 65415, 65424, 65436, 65439, 65450, 65462,
    65472, 65476, 65478, 65480, 65482, 65488, 65506, 65511,
    65514, 65521, 65527, 65528, 65529,
};

/// If `c` is an uppercase codepoint with a lowercase equivalent, return that
/// lowercase codepoint; otherwise return `c`. When `eRemoveDiacritic` is 1 or 2,
/// also strip diacritics (2 = include complex mappings). Undefined for `c` < 0.
export fn sqlite3FtsUnicodeFold(c: c_int, eRemoveDiacritic: c_int) callconv(.c) c_int {
    var ret: c_int = c;

    if (c < 128) {
        if (c >= 'A' and c <= 'Z') ret = c + ('a' - 'A');
    } else if (c < 65536) {
        var iHi: isize = @as(isize, @intCast(fold_aEntry.len)) - 1;
        var iLo: isize = 0;
        var iRes: isize = -1;

        std.debug.assert(c > fold_aEntry[0].iCode);
        while (iHi >= iLo) {
            const iTest: isize = @divTrunc(iHi + iLo, 2);
            const cmp: c_int = c - @as(c_int, fold_aEntry[@intCast(iTest)].iCode);
            if (cmp >= 0) {
                iRes = iTest;
                iLo = iTest + 1;
            } else {
                iHi = iTest - 1;
            }
        }

        std.debug.assert(iRes >= 0 and c >= fold_aEntry[@intCast(iRes)].iCode);
        const p = fold_aEntry[@intCast(iRes)];
        // c < (iCode + nRange) && 0 == (1 & flags & (iCode ^ c))
        if (c < (@as(c_int, p.iCode) + @as(c_int, p.nRange)) and
            (0x01 & @as(c_int, p.flags) & (@as(c_int, p.iCode) ^ c)) == 0)
        {
            const off: c_int = @intCast(fold_aiOff[p.flags >> 1]);
            ret = (c + off) & 0x0000FFFF;
            std.debug.assert(ret > 0);
        }

        if (eRemoveDiacritic != 0) {
            ret = remove_diacritic(ret, eRemoveDiacritic == 2);
        }
    } else if (c >= 66560 and c < 66600) {
        ret = c + 40;
    }

    return ret;
}

// ---------------------------------------------------------------------------
// Self-contained tests (no C externs required)
// ---------------------------------------------------------------------------

test "fold basic ASCII" {
    try std.testing.expectEqual(@as(c_int, 'a'), sqlite3FtsUnicodeFold('A', 0));
    try std.testing.expectEqual(@as(c_int, 'z'), sqlite3FtsUnicodeFold('Z', 0));
    try std.testing.expectEqual(@as(c_int, 'a'), sqlite3FtsUnicodeFold('a', 0));
    try std.testing.expectEqual(@as(c_int, '5'), sqlite3FtsUnicodeFold('5', 0));
}

test "fold accented uppercase to lowercase" {
    // U+00C0 'À' (LATIN CAPITAL A WITH GRAVE) -> U+00E0 'à'
    try std.testing.expectEqual(@as(c_int, 0xE0), sqlite3FtsUnicodeFold(0xC0, 0));
    // U+00C9 'É' -> U+00E9 'é'
    try std.testing.expectEqual(@as(c_int, 0xE9), sqlite3FtsUnicodeFold(0xC9, 0));
    // U+0100 'Ā' -> U+0101 'ā'
    try std.testing.expectEqual(@as(c_int, 0x101), sqlite3FtsUnicodeFold(0x100, 0));
    // Greek U+0391 'Α' -> U+03B1 'α'
    try std.testing.expectEqual(@as(c_int, 0x3B1), sqlite3FtsUnicodeFold(0x391, 0));
}

test "fold with remove_diacritic" {
    // U+00C9 'É' folds to 'é' (0xE9) then diacritic-strips to 'e'.
    try std.testing.expectEqual(@as(c_int, 'e'), sqlite3FtsUnicodeFold(0xC9, 1));
    // 'é' (already lowercase) with diacritic removal -> 'e'.
    try std.testing.expectEqual(@as(c_int, 'e'), sqlite3FtsUnicodeFold(0xE9, 1));
    // Without diacritic removal stays 'é'.
    try std.testing.expectEqual(@as(c_int, 0xE9), sqlite3FtsUnicodeFold(0xE9, 0));
}

test "fold supplementary plane (Deseret)" {
    // U+10400 (66560) DESERET CAPITAL LONG I -> +40 = U+10428.
    try std.testing.expectEqual(@as(c_int, 66600), sqlite3FtsUnicodeFold(66560, 0));
    try std.testing.expectEqual(@as(c_int, 66639), sqlite3FtsUnicodeFold(66599, 0));
    // Out of range stays put.
    try std.testing.expectEqual(@as(c_int, 66600), sqlite3FtsUnicodeFold(66600, 0));
}

test "isalnum ASCII" {
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsalnum('A'));
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsalnum('z'));
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsalnum('0'));
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsalnum('9'));
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsalnum(' '));
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsalnum('.'));
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsalnum('!'));
}

test "isalnum non-ASCII" {
    // U+00E9 'é' is a letter.
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsalnum(0xE9));
    // U+00C0 'À' is a letter.
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsalnum(0xC0));
    // U+0020 already covered; U+00A0 NBSP is not alnum.
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsalnum(0xA0));
    // U+0300 combining grave accent is not alnum.
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsalnum(0x300));
    // Way above plane 0 -> default 1.
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsalnum(0x400000));
}

test "isdiacritic" {
    // U+0300 COMBINING GRAVE ACCENT is a diacritic (bit 0 of mask0 set).
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsdiacritic(0x300));
    // U+0301 COMBINING ACUTE ACCENT.
    try std.testing.expectEqual(@as(c_int, 1), sqlite3FtsUnicodeIsdiacritic(0x301));
    // Below the window.
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsdiacritic(767));
    // Above the window.
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsdiacritic(818));
    // 'A' clearly not a diacritic.
    try std.testing.expectEqual(@as(c_int, 0), sqlite3FtsUnicodeIsdiacritic('A'));
}

test "remove_diacritic complex flag" {
    // Find a codepoint whose aChar entry has HIBIT set so bComplex matters.
    // U+01FA 'Ǻ' folds to U+01FB 'ǻ'; its base 'a' with HIBIT (complex).
    // remove_diacritics=1 (simple) leaves it; =2 (complex) strips to 'a'.
    const simple = sqlite3FtsUnicodeFold(0x1FB, 1);
    const complex = sqlite3FtsUnicodeFold(0x1FB, 2);
    try std.testing.expectEqual(@as(c_int, 0x1FB), simple);
    try std.testing.expectEqual(@as(c_int, 'a'), complex);
}
