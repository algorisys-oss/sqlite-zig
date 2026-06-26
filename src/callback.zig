//! Zig port of SQLite's src/callback.c — access to the internal hash tables of
//! user-defined functions and collation sequences.
//!
//! Exported (non-static) symbols — the full external set of callback.c, matching
//! the prototypes in sqliteInt.h:
//!   - sqlite3CheckCollSeq
//!   - sqlite3FindCollSeq
//!   - sqlite3SetTextEncoding
//!   - sqlite3GetCollSeq
//!   - sqlite3LocateCollSeq
//!   - sqlite3FunctionSearch
//!   - sqlite3InsertBuiltinFuncs
//!   - sqlite3FindFunction
//!   - sqlite3SchemaClear
//!   - sqlite3SchemaGet
//! The static helpers (callCollNeeded, synthCollSeq, findCollSeqEntry,
//! matchQuality) are private to this module and stay non-exported. callback.c
//! defines no file-scope globals (the only `static` data is a function-local
//! `aEnc[]`), so there is nothing else to export.
//!
//! ─── Struct coupling ──────────────────────────────────────────────────────
//! All the layout-bearing structs this module touches were probe-verified
//! (tools/offsets.c style probe, BOTH build configs) to have IDENTICAL offsets
//! and sizeof in the production and the `--dev` testfixture builds — none of
//! them gain a field under SQLITE_DEBUG:
//!   * CollSeq, FuncDef, Schema, Hash, HashElem  — config-INVARIANT pure-layout
//!     structs; mirrored directly as extern structs with comptime sizeof/offset
//!     asserts. NO c_layout entry strictly needed (they are invariant), but the
//!     orchestrator may add them for the assert harness.
//!   * The `sqlite3` connection struct DOES depend on build `-D` flags in
//!     general, but every field this module reads
//!     (pDfltColl, mDbFlags, enc, mallocFailed, init.busy, xCollNeeded,
//!     xCollNeeded16, pCollNeededArg, aFunc, aCollSeq) sits at a config-invariant
//!     offset (verified). They are read at GROUND-TRUTH offsets via c_layout
//!     where available, else a probe-verified fallback constant (printf.zig
//!     idiom). The base `&db->aCollSeq` / `&db->aFunc` are passed as `*Hash`.
//!
//! ─── Globals ──────────────────────────────────────────────────────────────
//!   * sqlite3BuiltinFunctions (FuncDefHash == FuncDef*[23]) is MUTABLE —
//!     sqlite3InsertBuiltinFuncs writes its buckets — so it is `extern var`,
//!     never `extern const` (avoids the optimizer CSE-ing a stale read, per the
//!     PROGRESS gotcha).
//!   * sqlite3UpperToLower[256], sqlite3StrBINARY[] are `extern const`.
//!
//! ─── Config assumptions (true in both this project's builds) ───────────────
//!   * SQLITE_OMIT_UTF16 is OFF  → the xCollNeeded16 path in callCollNeeded and
//!     the synthCollSeq UTF16 entries are compiled.
//!   * SQLITE_OMIT_TRIGGER is OFF → sqlite3DeleteTrigger is a real function
//!     (not the empty macro); sqlite3SchemaClear calls it.
//!   * SQLITE_OMIT_GET_TABLE / API_ARMOR irrelevant here.
//!   * Little-endian x86-64 → SQLITE_UTF16NATIVE == SQLITE_UTF16LE (2).
//!
//! No standalone Zig unit test is feasible — every path couples to the live
//! connection, hash tables, and the sqlite3_value_* / btree APIs. Validated
//! through the engine via the TCL suite (collate*, func*, and every test that
//! registers a collation or function or loads a schema).

const std = @import("std");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ─── Result codes / text-encoding constants ────────────────────────────────
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_ERROR_MISSING_COLLSEQ: c_int = SQLITE_ERROR | (1 << 8); // 257

const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const SQLITE_UTF16BE: u8 = 3;
// x86-64 is little-endian.
const SQLITE_UTF16NATIVE: u8 = SQLITE_UTF16LE;
// SQLITE_STATIC == (sqlite3_destructor_type)0
const SQLITE_STATIC: ?*const fn (?*anyopaque) callconv(.c) void = null;

// FuncDef.funcFlags bits
const SQLITE_FUNC_ENCMASK: u32 = 0x0003;
const SQLITE_FUNC_BUILTIN: u32 = 0x00800000;

// sqlite3.mDbFlags
const DBFLAG_PreferBuiltin: u32 = 0x0002;

// Schema.schemaFlags
const DB_SchemaLoaded: u16 = 0x0001;
const DB_ResetWanted: u16 = 0x0008;

const FUNC_PERFECT_MATCH: c_int = 6;

// SQLITE_FUNC_HASH(C,L) = ((C)+(L)) % 23
const SQLITE_FUNC_HASH_SZ: usize = 23;

// ─── Config-invariant pure-layout struct mirrors ────────────────────────────
// Verified identical in PROD and TF configs (no SQLITE_DEBUG fields).

const Hash = extern struct {
    htsize: c_uint, // 0
    count: c_uint, // 4
    first: ?*HashElem, // 8
    ht: ?*anyopaque, // 16  (struct _ht *)
};
comptime {
    std.debug.assert(@sizeOf(Hash) == 24);
    std.debug.assert(@offsetOf(Hash, "first") == 8);
    std.debug.assert(@offsetOf(Hash, "ht") == 16);
}

const HashElem = extern struct {
    next: ?*HashElem, // 0
    prev: ?*HashElem, // 8
    data: ?*anyopaque, // 16
    pKey: ?[*:0]const u8, // 24
    h: c_uint, // 32
};
comptime {
    std.debug.assert(@sizeOf(HashElem) == 40);
    std.debug.assert(@offsetOf(HashElem, "data") == 16);
    std.debug.assert(@offsetOf(HashElem, "pKey") == 24);
}

const CollSeq = extern struct {
    zName: ?[*:0]u8, // 0
    enc: u8, // 8
    pUser: ?*anyopaque, // 16
    xCmp: ?*const fn (?*anyopaque, c_int, ?*const anyopaque, c_int, ?*const anyopaque) callconv(.c) c_int, // 24
    xDel: ?*const fn (?*anyopaque) callconv(.c) void, // 32
};
comptime {
    std.debug.assert(@sizeOf(CollSeq) == 40);
    std.debug.assert(@offsetOf(CollSeq, "enc") == 8);
    std.debug.assert(@offsetOf(CollSeq, "pUser") == 16);
    std.debug.assert(@offsetOf(CollSeq, "xCmp") == 24);
    std.debug.assert(@offsetOf(CollSeq, "xDel") == 32);
}

const FuncDef = extern struct {
    nArg: i16, // 0
    funcFlags: u32, // 4
    pUserData: ?*anyopaque, // 8
    pNext: ?*FuncDef, // 16
    xSFunc: ?*anyopaque, // 24
    xFinalize: ?*anyopaque, // 32
    xValue: ?*anyopaque, // 40
    xInverse: ?*anyopaque, // 48
    zName: ?[*:0]const u8, // 56
    u: extern union { pHash: ?*FuncDef, pDestructor: ?*anyopaque }, // 64
};
comptime {
    std.debug.assert(@sizeOf(FuncDef) == 72);
    std.debug.assert(@offsetOf(FuncDef, "funcFlags") == 4);
    std.debug.assert(@offsetOf(FuncDef, "pNext") == 16);
    std.debug.assert(@offsetOf(FuncDef, "xSFunc") == 24);
    std.debug.assert(@offsetOf(FuncDef, "zName") == 56);
    std.debug.assert(@offsetOf(FuncDef, "u") == 64);
}

const Schema = extern struct {
    schema_cookie: c_int, // 0
    iGeneration: c_int, // 4
    tblHash: Hash, // 8
    idxHash: Hash, // 32
    trigHash: Hash, // 56
    fkeyHash: Hash, // 80
    pSeqTab: ?*anyopaque, // 104
    file_format: u8, // 112
    enc: u8, // 113
    schemaFlags: u16, // 114
    cache_size: c_int, // 116
};
comptime {
    std.debug.assert(@sizeOf(Schema) == 120);
    std.debug.assert(@offsetOf(Schema, "tblHash") == 8);
    std.debug.assert(@offsetOf(Schema, "idxHash") == 32);
    std.debug.assert(@offsetOf(Schema, "trigHash") == 56);
    std.debug.assert(@offsetOf(Schema, "fkeyHash") == 80);
    std.debug.assert(@offsetOf(Schema, "pSeqTab") == 104);
    std.debug.assert(@offsetOf(Schema, "file_format") == 112);
    std.debug.assert(@offsetOf(Schema, "enc") == 113);
    std.debug.assert(@offsetOf(Schema, "schemaFlags") == 114);
}

// FuncDefHash == struct { FuncDef *a[23]; }
const FuncDefHash = extern struct {
    a: [SQLITE_FUNC_HASH_SZ]?*FuncDef,
};

// ─── sqlite3 connection field offsets (ground truth, config-invariant) ───────
// Prefer the c_layout entry once the orchestrator adds it; else the
// probe-verified fallback (printf.zig idiom).
const sqlite3_pDfltColl_off: usize = if (@hasDecl(L, "sqlite3_pDfltColl")) L.sqlite3_pDfltColl else 16;
const sqlite3_mDbFlags_off: usize = if (@hasDecl(L, "sqlite3_mDbFlags")) L.sqlite3_mDbFlags else 44;
const sqlite3_enc_off: usize = if (@hasDecl(L, "sqlite3_enc")) L.sqlite3_enc else 100;
const sqlite3_mallocFailed_off: usize = if (@hasDecl(L, "sqlite3_mallocFailed")) L.sqlite3_mallocFailed else 103;
const sqlite3_initBusy_off: usize = if (@hasDecl(L, "sqlite3_initBusy")) L.sqlite3_initBusy else 197; // init(192)+busy(5)
const sqlite3_xCollNeeded_off: usize = if (@hasDecl(L, "sqlite3_xCollNeeded")) L.sqlite3_xCollNeeded else 392;
const sqlite3_xCollNeeded16_off: usize = if (@hasDecl(L, "sqlite3_xCollNeeded16")) L.sqlite3_xCollNeeded16 else 400;
const sqlite3_pCollNeededArg_off: usize = if (@hasDecl(L, "sqlite3_pCollNeededArg")) L.sqlite3_pCollNeededArg else 408;
const sqlite3_aFunc_off: usize = if (@hasDecl(L, "sqlite3_aFunc")) L.sqlite3_aFunc else 616;
const sqlite3_aCollSeq_off: usize = if (@hasDecl(L, "sqlite3_aCollSeq")) L.sqlite3_aCollSeq else 640;

// callback signatures for the collation-needed hooks.
const XCollNeeded = ?*const fn (?*anyopaque, ?*anyopaque, c_int, ?[*:0]const u8) callconv(.c) void;
const XCollNeeded16 = ?*const fn (?*anyopaque, ?*anyopaque, c_int, ?*const anyopaque) callconv(.c) void;

inline fn dbBase(db: ?*anyopaque) [*]u8 {
    return @ptrCast(db.?);
}
inline fn dbPDfltCollPtr(db: ?*anyopaque) *align(1) ?*CollSeq {
    return @ptrCast(dbBase(db) + sqlite3_pDfltColl_off);
}
inline fn dbMDbFlags(db: ?*anyopaque) u32 {
    const p: *align(1) const u32 = @ptrCast(dbBase(db) + sqlite3_mDbFlags_off);
    return p.*;
}
inline fn dbEnc(db: ?*anyopaque) u8 {
    return dbBase(db)[sqlite3_enc_off];
}
inline fn dbEncPtr(db: ?*anyopaque) *u8 {
    return &dbBase(db)[sqlite3_enc_off];
}
inline fn dbInitBusy(db: ?*anyopaque) u8 {
    return dbBase(db)[sqlite3_initBusy_off];
}
inline fn dbXCollNeeded(db: ?*anyopaque) XCollNeeded {
    const p: *align(1) const XCollNeeded = @ptrCast(dbBase(db) + sqlite3_xCollNeeded_off);
    return p.*;
}
inline fn dbXCollNeeded16(db: ?*anyopaque) XCollNeeded16 {
    const p: *align(1) const XCollNeeded16 = @ptrCast(dbBase(db) + sqlite3_xCollNeeded16_off);
    return p.*;
}
inline fn dbPCollNeededArg(db: ?*anyopaque) ?*anyopaque {
    const p: *align(1) const ?*anyopaque = @ptrCast(dbBase(db) + sqlite3_pCollNeededArg_off);
    return p.*;
}
inline fn dbAFunc(db: ?*anyopaque) *Hash {
    return @ptrCast(@alignCast(dbBase(db) + sqlite3_aFunc_off));
}
inline fn dbACollSeq(db: ?*anyopaque) *Hash {
    return @ptrCast(@alignCast(dbBase(db) + sqlite3_aCollSeq_off));
}

// ─── extern globals ─────────────────────────────────────────────────────────
// MUTABLE — written by sqlite3InsertBuiltinFuncs. Must be `extern var`.
extern var sqlite3BuiltinFunctions: FuncDefHash;
extern const sqlite3UpperToLower: [256]u8;
// C: `const char sqlite3StrBINARY[] = "BINARY";` — an ARRAY, so the symbol's
// address IS the string data. Declaring it as a pointer would make Zig read the
// bytes "BINARY\0" AS a pointer value. Bind the symbol as a byte and take its
// address to get a `[*:0]const u8`, size-independent.
extern const sqlite3StrBINARY: u8;
inline fn strBINARY() [*:0]const u8 {
    return @ptrCast(&sqlite3StrBINARY);
}

// ─── extern C / internal-ABI helpers (resolved at link time) ────────────────
extern fn sqlite3DbStrDup(db: ?*anyopaque, z: ?[*:0]const u8) ?[*:0]u8;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DbMallocZero(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3OomFault(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;
extern fn sqlite3ExpirePreparedStatements(db: ?*anyopaque, i: c_int) void;
extern fn sqlite3ErrorMsg(pParse: ?*anyopaque, fmt: [*:0]const u8, ...) void;

extern fn sqlite3HashInit(h: *Hash) void;
extern fn sqlite3HashInsert(h: *Hash, pKey: ?[*:0]const u8, pData: ?*anyopaque) ?*anyopaque;
extern fn sqlite3HashFind(h: *const Hash, pKey: ?[*:0]const u8) ?*anyopaque;
extern fn sqlite3HashClear(h: *Hash) void;

// UTF16-path value helpers (SQLITE_OMIT_UTF16 is OFF).
extern fn sqlite3ValueNew(db: ?*anyopaque) ?*anyopaque;
extern fn sqlite3ValueSetStr(v: ?*anyopaque, n: c_int, z: ?*const anyopaque, enc: u8, xDel: ?*const fn (?*anyopaque) callconv(.c) void) void;
extern fn sqlite3ValueText(v: ?*anyopaque, enc: u8) ?*const anyopaque;
extern fn sqlite3ValueFree(v: ?*anyopaque) void;

// trigger / table / btree helpers used by the schema routines.
extern fn sqlite3DeleteTrigger(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3DeleteTable(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3BtreeSchema(p: ?*anyopaque, nBytes: c_int, xFree: ?*const fn (?*anyopaque) callconv(.c) void) ?*anyopaque;

extern fn memcpy(noalias d: ?*anyopaque, noalias s: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(d: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;

// ─── ENC(db) ────────────────────────────────────────────────────────────────
inline fn ENC(db: ?*anyopaque) u8 {
    return dbEnc(db);
}

// ─── callCollNeeded (static) ────────────────────────────────────────────────
fn callCollNeeded(db: ?*anyopaque, enc: c_int, zName: [*:0]const u8) void {
    std.debug.assert(dbXCollNeeded(db) == null or dbXCollNeeded16(db) == null);
    if (dbXCollNeeded(db)) |xc| {
        const zExternal = sqlite3DbStrDup(db, zName);
        if (zExternal == null) return;
        xc(dbPCollNeededArg(db), db, enc, zExternal);
        sqlite3DbFree(db, @ptrCast(zExternal));
    }
    // SQLITE_OMIT_UTF16 is OFF.
    if (dbXCollNeeded16(db)) |xc16| {
        const pTmp = sqlite3ValueNew(db);
        sqlite3ValueSetStr(pTmp, -1, zName, SQLITE_UTF8, SQLITE_STATIC);
        const zExternal = sqlite3ValueText(pTmp, SQLITE_UTF16NATIVE);
        if (zExternal) |z| {
            xc16(dbPCollNeededArg(db), db, @intCast(ENC(db)), z);
        }
        sqlite3ValueFree(pTmp);
    }
}

// ─── synthCollSeq (static) ──────────────────────────────────────────────────
fn synthCollSeq(db: ?*anyopaque, pColl: *CollSeq) c_int {
    const aEnc = [3]u8{ SQLITE_UTF16BE, SQLITE_UTF16LE, SQLITE_UTF8 };
    const z = pColl.zName;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const pColl2 = sqlite3FindCollSeq(db, aEnc[i], z, 0);
        if (pColl2) |p2| {
            if (p2.xCmp != null) {
                _ = memcpy(pColl, p2, @sizeOf(CollSeq));
                pColl.xDel = null; // Do not copy the destructor
                return SQLITE_OK;
            }
        }
    }
    return SQLITE_ERROR;
}

// ─── sqlite3CheckCollSeq ────────────────────────────────────────────────────
export fn sqlite3CheckCollSeq(pParse: ?*anyopaque, pColl: ?*CollSeq) callconv(.c) c_int {
    if (pColl) |pc| {
        if (pc.xCmp == null) {
            const zName = pc.zName;
            const db = parseDb(pParse);
            const p = sqlite3GetCollSeq(pParse, ENC(db), pColl, @ptrCast(zName));
            if (p == null) {
                return SQLITE_ERROR;
            }
            std.debug.assert(p == pColl);
        }
    }
    return SQLITE_OK;
}

// ─── findCollSeqEntry (static) ──────────────────────────────────────────────
fn findCollSeqEntry(db: ?*anyopaque, zName: [*:0]const u8, create: c_int) ?*CollSeq {
    var pColl: ?*CollSeq = @ptrCast(@alignCast(sqlite3HashFind(dbACollSeq(db), zName)));

    if (pColl == null and create != 0) {
        const nName: usize = @intCast(sqlite3Strlen30(zName) + 1);
        const raw = sqlite3DbMallocZero(db, 3 * @sizeOf(CollSeq) + nName);
        if (raw != null) {
            const arr: [*]CollSeq = @ptrCast(@alignCast(raw.?));
            // The name copy lives immediately after the 3 CollSeq structs.
            const zNamePtr: [*]u8 = @ptrCast(&arr[3]);
            arr[0].zName = @ptrCast(zNamePtr);
            arr[0].enc = SQLITE_UTF8;
            arr[1].zName = @ptrCast(zNamePtr);
            arr[1].enc = SQLITE_UTF16LE;
            arr[2].zName = @ptrCast(zNamePtr);
            arr[2].enc = SQLITE_UTF16BE;
            _ = memcpy(zNamePtr, zName, nName);
            const pDel = sqlite3HashInsert(dbACollSeq(db), @ptrCast(arr[0].zName), raw);
            // assert( pDel==0 || pDel==pColl )
            std.debug.assert(pDel == null or pDel == raw);
            if (pDel != null) {
                _ = sqlite3OomFault(db);
                sqlite3DbFree(db, pDel);
                pColl = null;
            } else {
                pColl = &arr[0];
            }
        }
    }
    return pColl;
}

// ─── sqlite3FindCollSeq ─────────────────────────────────────────────────────
export fn sqlite3FindCollSeq(
    db: ?*anyopaque,
    enc: u8,
    zName: ?[*:0]const u8,
    create: c_int,
) callconv(.c) ?*CollSeq {
    std.debug.assert(SQLITE_UTF8 == 1 and SQLITE_UTF16LE == 2 and SQLITE_UTF16BE == 3);
    std.debug.assert(enc >= SQLITE_UTF8 and enc <= SQLITE_UTF16BE);
    var pColl: ?*CollSeq = undefined;
    if (zName) |zn| {
        pColl = findCollSeqEntry(db, zn, create);
        if (pColl) |p| {
            const base: [*]CollSeq = @ptrCast(p);
            pColl = &base[enc - 1];
        }
    } else {
        pColl = dbPDfltCollPtr(db).*;
    }
    return pColl;
}

// ─── sqlite3SetTextEncoding ─────────────────────────────────────────────────
export fn sqlite3SetTextEncoding(db: ?*anyopaque, enc: u8) callconv(.c) void {
    std.debug.assert(enc == SQLITE_UTF8 or enc == SQLITE_UTF16LE or enc == SQLITE_UTF16BE);
    dbEncPtr(db).* = enc;
    // EVIDENCE-OF: R-08308-17224 The default collating function for all
    // strings is BINARY.
    dbPDfltCollPtr(db).* = sqlite3FindCollSeq(db, enc, strBINARY(), 0);
    sqlite3ExpirePreparedStatements(db, 1);
}

// ─── sqlite3GetCollSeq ──────────────────────────────────────────────────────
export fn sqlite3GetCollSeq(
    pParse: ?*anyopaque,
    enc: u8,
    pColl: ?*CollSeq,
    zName: ?[*:0]const u8,
) callconv(.c) ?*CollSeq {
    const db = parseDb(pParse);
    var p: ?*CollSeq = pColl;
    if (p == null) {
        p = sqlite3FindCollSeq(db, enc, zName, 0);
    }
    if (p == null or p.?.xCmp == null) {
        // No collation sequence of this type for this encoding is registered.
        // Call the collation factory to see if it can supply us with one.
        callCollNeeded(db, @intCast(enc), zName.?);
        p = sqlite3FindCollSeq(db, enc, zName, 0);
    }
    if (p != null and p.?.xCmp == null and synthCollSeq(db, p.?) != 0) {
        p = null;
    }
    std.debug.assert(p == null or p.?.xCmp != null);
    if (p == null) {
        sqlite3ErrorMsg(pParse, "no such collation sequence: %s", zName);
        parseSetRc(pParse, SQLITE_ERROR_MISSING_COLLSEQ);
    }
    return p;
}

// ─── sqlite3LocateCollSeq ───────────────────────────────────────────────────
export fn sqlite3LocateCollSeq(pParse: ?*anyopaque, zName: ?[*:0]const u8) callconv(.c) ?*CollSeq {
    const db = parseDb(pParse);
    const enc = ENC(db);
    const initbusy = dbInitBusy(db);

    var pColl = sqlite3FindCollSeq(db, enc, zName, @intCast(initbusy));
    if (initbusy == 0 and (pColl == null or pColl.?.xCmp == null)) {
        pColl = sqlite3GetCollSeq(pParse, enc, pColl, zName);
    }
    return pColl;
}

// ─── matchQuality (static) ──────────────────────────────────────────────────
fn matchQuality(p: *FuncDef, nArg: c_int, enc: u8) c_int {
    std.debug.assert(p.nArg >= -4 and p.nArg != -2);
    std.debug.assert(nArg >= -2);

    var match: c_int = undefined;

    // Wrong number of arguments means "no match"
    if (p.nArg != nArg) {
        if (nArg == -2) return if (p.xSFunc == null) 0 else FUNC_PERFECT_MATCH;
        if (p.nArg >= 0) return 0;
        // Special p->nArg values available to built-in functions only:
        //    -3     1 or more arguments required
        //    -4     2 or more arguments required
        if (p.nArg < -2 and nArg < (-2 - @as(c_int, p.nArg))) return 0;
    }

    // Give a better score to a function with a specific number of arguments
    // than to function that accepts any number of arguments.
    if (p.nArg == nArg) {
        match = 4;
    } else {
        match = 1;
    }

    // Bonus points if the text encoding matches
    if (@as(u32, enc) == (p.funcFlags & SQLITE_FUNC_ENCMASK)) {
        match += 2; // Exact encoding match
    } else if ((@as(u32, enc) & p.funcFlags & 2) != 0) {
        match += 1; // Both are UTF16, but with different byte orders
    }

    return match;
}

// ─── sqlite3FunctionSearch ──────────────────────────────────────────────────
export fn sqlite3FunctionSearch(h: c_int, zFunc: ?[*:0]const u8) callconv(.c) ?*FuncDef {
    var p: ?*FuncDef = sqlite3BuiltinFunctions.a[@intCast(h)];
    while (p) |pp| {
        std.debug.assert((pp.funcFlags & SQLITE_FUNC_BUILTIN) != 0);
        if (sqlite3StrICmp(pp.zName, zFunc) == 0) {
            return pp;
        }
        p = pp.u.pHash;
    }
    return null;
}

// ─── sqlite3InsertBuiltinFuncs ──────────────────────────────────────────────
export fn sqlite3InsertBuiltinFuncs(aDef: [*]FuncDef, nDef: c_int) callconv(.c) void {
    var i: usize = 0;
    while (i < @as(usize, @intCast(nDef))) : (i += 1) {
        const zName = aDef[i].zName;
        const nName = sqlite3Strlen30(zName);
        const c0: u8 = zName.?[0];
        const h: usize = (@as(usize, c0) + @as(usize, @intCast(nName))) % SQLITE_FUNC_HASH_SZ;
        std.debug.assert((aDef[i].funcFlags & SQLITE_FUNC_BUILTIN) != 0);
        const pOther = sqlite3FunctionSearch(@intCast(h), zName);
        if (pOther) |po| {
            std.debug.assert(po != &aDef[i] and po.pNext != &aDef[i]);
            aDef[i].pNext = po.pNext;
            po.pNext = &aDef[i];
        } else {
            aDef[i].pNext = null;
            aDef[i].u.pHash = sqlite3BuiltinFunctions.a[h];
            sqlite3BuiltinFunctions.a[h] = &aDef[i];
        }
    }
}

// ─── sqlite3FindFunction ────────────────────────────────────────────────────
export fn sqlite3FindFunction(
    db: ?*anyopaque,
    zName: [*:0]const u8,
    nArg: c_int,
    enc: u8,
    createFlag: u8,
) callconv(.c) ?*FuncDef {
    var pBest: ?*FuncDef = null; // Best match found so far
    var bestScore: c_int = 0; // Score of best match
    var h: c_int = undefined; // Hash value
    var nName: c_int = undefined; // Length of the name

    std.debug.assert(nArg >= -2);
    std.debug.assert(nArg >= -1 or createFlag == 0);
    nName = sqlite3Strlen30(zName);

    // First search amongst the application-defined functions.
    var p: ?*FuncDef = @ptrCast(@alignCast(sqlite3HashFind(dbAFunc(db), zName)));
    while (p) |pp| {
        const score = matchQuality(pp, nArg, enc);
        if (score > bestScore) {
            pBest = pp;
            bestScore = score;
        }
        p = pp.pNext;
    }

    // If no match is found, search the built-in functions.
    if (createFlag == 0 and (pBest == null or (dbMDbFlags(db) & DBFLAG_PreferBuiltin) != 0)) {
        bestScore = 0;
        h = @intCast((@as(usize, sqlite3UpperToLower[zName[0]]) + @as(usize, @intCast(nName))) % SQLITE_FUNC_HASH_SZ);
        p = sqlite3FunctionSearch(h, zName);
        while (p) |pp| {
            const score = matchQuality(pp, nArg, enc);
            if (score > bestScore) {
                pBest = pp;
                bestScore = score;
            }
            p = pp.pNext;
        }
    }

    // If the createFlag is true and the search did not reveal an exact match,
    // add a new entry to the hash table and return it.
    if (createFlag != 0 and bestScore < FUNC_PERFECT_MATCH) {
        const raw = sqlite3DbMallocZero(db, @sizeOf(FuncDef) + @as(u64, @intCast(nName + 1)));
        if (raw != null) {
            const pb: *FuncDef = @ptrCast(@alignCast(raw.?));
            pBest = pb;
            const after: [*]u8 = @ptrCast(@as([*]FuncDef, @ptrCast(pb)) + 1);
            pb.zName = @ptrCast(after);
            // C: `pBest->nArg = (u16)nArg;` — truncate to 16 bits with sign
            // reinterpret (nArg may be -1 for variadic), NOT a range-checked cast.
            pb.nArg = @truncate(nArg);
            pb.funcFlags = enc;
            _ = memcpy(after, zName, @intCast(nName + 1));
            var z: [*]u8 = after;
            while (z[0] != 0) : (z += 1) z[0] = sqlite3UpperToLower[z[0]];
            const pOther = sqlite3HashInsert(dbAFunc(db), pb.zName, raw);
            if (pOther == raw) {
                sqlite3DbFree(db, raw);
                _ = sqlite3OomFault(db);
                return null;
            } else {
                pb.pNext = @ptrCast(@alignCast(pOther));
            }
        }
    }

    if (pBest) |pb| {
        if (pb.xSFunc != null or createFlag != 0) {
            return pb;
        }
    }
    return null;
}

// ─── sqlite3SchemaClear ─────────────────────────────────────────────────────
export fn sqlite3SchemaClear(p: ?*anyopaque) callconv(.c) void {
    const pSchema: *Schema = @ptrCast(@alignCast(p.?));

    // C stack-allocates a zeroed `sqlite3 xdb` and passes &xdb to the delete
    // helpers (which only need a connection handle to free with). A zeroed
    // buffer of sizeof(sqlite3) replicates that exactly.
    var xdb: [sizeOfSqlite3]u8 align(16) = undefined;
    @memset(&xdb, 0);
    const xdbp: ?*anyopaque = @ptrCast(&xdb);

    var temp1: Hash = pSchema.tblHash;
    var temp2: Hash = pSchema.trigHash;
    sqlite3HashInit(&pSchema.trigHash);
    sqlite3HashClear(&pSchema.idxHash);

    var pElem: ?*HashElem = temp2.first;
    while (pElem) |e| {
        sqlite3DeleteTrigger(xdbp, e.data);
        pElem = e.next;
    }
    sqlite3HashClear(&temp2);

    sqlite3HashInit(&pSchema.tblHash);
    pElem = temp1.first;
    while (pElem) |e| {
        sqlite3DeleteTable(xdbp, e.data);
        pElem = e.next;
    }
    sqlite3HashClear(&temp1);
    sqlite3HashClear(&pSchema.fkeyHash);
    pSchema.pSeqTab = null;
    if ((pSchema.schemaFlags & DB_SchemaLoaded) != 0) {
        pSchema.iGeneration += 1;
    }
    pSchema.schemaFlags &= ~(DB_SchemaLoaded | DB_ResetWanted);
}

// ─── sqlite3SchemaGet ───────────────────────────────────────────────────────
export fn sqlite3SchemaGet(db: ?*anyopaque, pBt: ?*anyopaque) callconv(.c) ?*Schema {
    var p: ?*Schema = undefined;
    if (pBt != null) {
        p = @ptrCast(@alignCast(sqlite3BtreeSchema(pBt, @sizeOf(Schema), sqlite3SchemaClear)));
    } else {
        p = @ptrCast(@alignCast(sqlite3DbMallocZero(null, @sizeOf(Schema))));
    }
    if (p == null) {
        _ = sqlite3OomFault(db);
    } else if (p.?.file_format == 0) {
        sqlite3HashInit(&p.?.tblHash);
        sqlite3HashInit(&p.?.idxHash);
        sqlite3HashInit(&p.?.trigHash);
        sqlite3HashInit(&p.?.fkeyHash);
        p.?.enc = SQLITE_UTF8;
    }
    return p;
}

// ─── Parse field access ─────────────────────────────────────────────────────
// Parse->db is at offset 0 (the very first field of struct Parse). Parse->rc is
// read at its ground-truth offset.
const Parse_db_off: usize = if (@hasDecl(L, "Parse_db")) L.Parse_db else 0;
const Parse_rc_off: usize = if (@hasDecl(L, "Parse_rc")) L.Parse_rc else 24;
// Parse.rc is at offset 24 in both configs (probe-verified; requested as a
// c_layout entry).

inline fn parseDb(pParse: ?*anyopaque) ?*anyopaque {
    const base: [*]const u8 = @ptrCast(pParse.?);
    const pp: *align(1) const ?*anyopaque = @ptrCast(base + Parse_db_off);
    return pp.*;
}
inline fn parseSetRc(pParse: ?*anyopaque, rc: c_int) void {
    const base: [*]u8 = @ptrCast(pParse.?);
    const pp: *align(1) c_int = @ptrCast(base + Parse_rc_off);
    pp.* = rc;
}

// sizeof(struct sqlite3) — config-invariant (816 in both builds).
const sizeOfSqlite3: usize = if (@hasDecl(L, "sizeof_sqlite3")) L.sizeof_sqlite3 else 816;
