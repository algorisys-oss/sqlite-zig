//! Zig port of the fts5_buffer.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 4188-4600).
//!
//! Growable byte-buffer primitives plus the small grab-bag of utilities that
//! live in this TU: the 32-bit big-endian codec, the position-list reader/
//! writer/append helpers, malloc/strndup wrappers, the bareword char test, and
//! the Fts5Termset hash bucket used by the offsets=0 integrity check.
//!
//! Imports the shared foundation (Fts5Buffer / Fts5PoslistReader / … layouts).
//! The varint codec lives in the fts5_varint.c section; this file calls it via
//! `extern fn` (resolved at link time within the single FTS5 object).

const int = @import("fts5_int.zig");

const Fts5Buffer = int.Fts5Buffer;
const Fts5PoslistReader = int.Fts5PoslistReader;
const Fts5PoslistWriter = int.Fts5PoslistWriter;
const SQLITE_OK = int.SQLITE_OK;
const SQLITE_NOMEM = int.SQLITE_NOMEM;

// --- sibling section: fts5_varint.c -----------------------------------------
extern fn sqlite3Fts5PutVarint(p: [*]u8, v: u64) callconv(.c) c_int;
extern fn sqlite3Fts5GetVarint32(p: [*]const u8, v: *u32) callconv(.c) c_int;

// --- libc + public sqlite3 API (resolved at link time) ----------------------
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn strlen(s: [*:0]const u8) usize;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_vmprintf(fmt: [*:0]const u8, ap: *anyopaque) ?[*:0]u8;

// ===========================================================================
// fts5BufferGrow (fts5Int.h 1149-1152): ensure space for nn more bytes.
// Returns true (non-zero) on OOM. Inlined from the C macro.
// ===========================================================================
inline fn fts5BufferGrow(pRc: *c_int, pBuf: *Fts5Buffer, nn: u32) bool {
    if (@as(u32, @bitCast(pBuf.n)) + nn <= @as(u32, @bitCast(pBuf.nSpace))) {
        return false;
    }
    return sqlite3Fts5BufferSize(pRc, pBuf, nn + @as(u32, @bitCast(pBuf.n))) != 0;
}

/// fts5.c 4206-4223: grow pBuf so nSpace >= nByte. Returns 1 on OOM.
export fn sqlite3Fts5BufferSize(pRc: *c_int, pBuf: *Fts5Buffer, nByte: u32) callconv(.c) c_int {
    if (@as(u32, @bitCast(pBuf.nSpace)) < nByte) {
        var nNew: u64 = if (pBuf.nSpace != 0) @intCast(pBuf.nSpace) else 64;
        while (nNew < nByte) {
            nNew = nNew * 2;
        }
        const pNew = sqlite3_realloc64(pBuf.p, nNew);
        if (pNew == null) {
            pRc.* = SQLITE_NOMEM;
            return 1;
        } else {
            pBuf.nSpace = @intCast(nNew);
            pBuf.p = @ptrCast(pNew);
        }
    }
    return 0;
}

/// fts5.c 4230-4233: append iVal as a varint.
export fn sqlite3Fts5BufferAppendVarint(pRc: *c_int, pBuf: *Fts5Buffer, iVal: i64) callconv(.c) void {
    if (fts5BufferGrow(pRc, pBuf, 9)) return;
    pBuf.n += sqlite3Fts5PutVarint(pBuf.p.? + @as(usize, @intCast(pBuf.n)), @bitCast(iVal));
}

/// fts5.c 4235-4240: write a 32-bit big-endian value.
export fn sqlite3Fts5Put32(aBuf: [*]u8, iVal: c_int) callconv(.c) void {
    const u: u32 = @bitCast(iVal);
    aBuf[0] = @truncate((u >> 24) & 0x00FF);
    aBuf[1] = @truncate((u >> 16) & 0x00FF);
    aBuf[2] = @truncate((u >> 8) & 0x00FF);
    aBuf[3] = @truncate((u >> 0) & 0x00FF);
}

/// fts5.c 4242-4244: read a 32-bit big-endian value.
export fn sqlite3Fts5Get32(aBuf: [*]const u8) callconv(.c) c_int {
    const v: u32 = (@as(u32, aBuf[0]) << 24) +%
        (@as(u32, aBuf[1]) << 16) +%
        (@as(u32, aBuf[2]) << 8) +%
        @as(u32, aBuf[3]);
    return @bitCast(v);
}

/// fts5.c 4251-4263: append nData bytes from pData.
export fn sqlite3Fts5BufferAppendBlob(pRc: *c_int, pBuf: *Fts5Buffer, nData: u32, pData: [*]const u8) callconv(.c) void {
    if (nData != 0) {
        if (fts5BufferGrow(pRc, pBuf, nData)) return;
        _ = memcpy(pBuf.p.? + @as(usize, @intCast(pBuf.n)), pData, nData);
        pBuf.n += @bitCast(nData);
    }
}

/// fts5.c 4270-4278: append the nul-terminated string zStr (nul written but
/// not counted in pBuf->n).
export fn sqlite3Fts5BufferAppendString(pRc: *c_int, pBuf: *Fts5Buffer, zStr: [*:0]const u8) callconv(.c) void {
    const nStr: c_int = @intCast(strlen(zStr));
    sqlite3Fts5BufferAppendBlob(pRc, pBuf, @intCast(nStr + 1), zStr);
    pBuf.n -= 1;
}

/// fts5.c 4288-4307: printf into the buffer (nul written but not counted).
export fn sqlite3Fts5BufferAppendPrintf(pRc: *c_int, pBuf: *Fts5Buffer, zFmt: [*:0]const u8, ...) callconv(.c) void {
    if (pRc.* == SQLITE_OK) {
        var ap = @cVaStart();
        const zTmp = sqlite3_vmprintf(zFmt, @ptrCast(&ap));
        @cVaEnd(&ap);
        if (zTmp == null) {
            pRc.* = SQLITE_NOMEM;
        } else {
            sqlite3Fts5BufferAppendString(pRc, pBuf, zTmp.?);
            sqlite3_free(zTmp);
        }
    }
}

/// fts5.c 4309-4321: sqlite3_vmprintf wrapper that latches OOM into *pRc.
export fn sqlite3Fts5Mprintf(pRc: *c_int, zFmt: [*:0]const u8, ...) callconv(.c) ?[*:0]u8 {
    var zRet: ?[*:0]u8 = null;
    if (pRc.* == SQLITE_OK) {
        var ap = @cVaStart();
        zRet = sqlite3_vmprintf(zFmt, @ptrCast(&ap));
        @cVaEnd(&ap);
        if (zRet == null) {
            pRc.* = SQLITE_NOMEM;
        }
    }
    return zRet;
}

/// fts5.c 4327-4330: free the buffer and zero the struct.
export fn sqlite3Fts5BufferFree(pBuf: *Fts5Buffer) callconv(.c) void {
    sqlite3_free(pBuf.p);
    _ = memset(pBuf, 0, @sizeOf(Fts5Buffer));
}

/// fts5.c 4336-4338: reset length to 0 (keep the allocation).
export fn sqlite3Fts5BufferZero(pBuf: *Fts5Buffer) callconv(.c) void {
    pBuf.n = 0;
}

/// fts5.c 4345-4353: replace the buffer contents with nData/pData.
export fn sqlite3Fts5BufferSet(pRc: *c_int, pBuf: *Fts5Buffer, nData: c_int, pData: [*]const u8) callconv(.c) void {
    pBuf.n = 0;
    sqlite3Fts5BufferAppendBlob(pRc, pBuf, @bitCast(nData), pData);
}

// fts5FastGetVarint32 (fts5Int.h 1422-1428): read a 32-bit varint at a[*iOff],
// advancing *iOff. Inlined from the C macro.
inline fn fts5FastGetVarint32(a: [*]const u8, iOff: *c_int, nVal: *u32) void {
    nVal.* = a[@intCast(iOff.*)];
    iOff.* += 1;
    if (nVal.* & 0x80 != 0) {
        iOff.* -= 1;
        iOff.* += sqlite3Fts5GetVarint32(a + @as(usize, @intCast(iOff.*)), nVal);
    }
}

/// fts5.c 4355-4393: advance a poslist iterator. Returns 1 at EOF.
export fn sqlite3Fts5PoslistNext64(a: ?[*]const u8, n: c_int, pi: *c_int, piOff: *i64) callconv(.c) c_int {
    var i = pi.*;
    if (i >= n) {
        piOff.* = -1;
        return 1;
    } else {
        const ap = a.?;
        var iOff = piOff.*;
        var iVal: u32 = undefined;
        fts5FastGetVarint32(ap, &i, &iVal);
        if (iVal <= 1) {
            if (iVal == 0) {
                pi.* = i;
                return 0;
            }
            fts5FastGetVarint32(ap, &i, &iVal);
            iOff = @as(i64, iVal) << 32;
            fts5FastGetVarint32(ap, &i, &iVal);
            if (iVal < 2) {
                // Corrupt record: stop parsing here.
                piOff.* = -1;
                return 1;
            }
            piOff.* = iOff + @as(i64, (iVal -% 2) & 0x7FFFFFFF);
        } else {
            piOff.* = (iOff & (@as(i64, 0x7FFFFFFF) << 32)) +
                ((iOff + (@as(i64, iVal) - 2)) & 0x7FFFFFFF);
        }
        pi.* = i;
        return 0;
    }
}

/// fts5.c 4400-4405: advance the poslist reader. Returns bEof.
export fn sqlite3Fts5PoslistReaderNext(pIter: *Fts5PoslistReader) callconv(.c) c_int {
    if (sqlite3Fts5PoslistNext64(pIter.a, pIter.n, &pIter.i, &pIter.iPos) != 0) {
        pIter.bEof = 1;
    }
    return pIter.bEof;
}

/// fts5.c 4407-4416: initialise a poslist reader over a[0..n].
export fn sqlite3Fts5PoslistReaderInit(a: ?[*]const u8, n: c_int, pIter: *Fts5PoslistReader) callconv(.c) c_int {
    _ = memset(pIter, 0, @sizeOf(Fts5PoslistReader));
    pIter.a = a;
    pIter.n = n;
    _ = sqlite3Fts5PoslistReaderNext(pIter);
    return pIter.bEof;
}

/// fts5.c 4424-4439: append position iPos to a poslist (space pre-reserved).
export fn sqlite3Fts5PoslistSafeAppend(pBuf: *Fts5Buffer, piPrev: *i64, iPos: i64) callconv(.c) void {
    if (iPos >= piPrev.*) {
        const colmask: i64 = @as(i64, 0x7FFFFFFF) << 32;
        if ((iPos & colmask) != (piPrev.* & colmask)) {
            pBuf.p.?[@intCast(pBuf.n)] = 1;
            pBuf.n += 1;
            pBuf.n += sqlite3Fts5PutVarint(pBuf.p.? + @as(usize, @intCast(pBuf.n)), @bitCast(iPos >> 32));
            piPrev.* = (iPos & colmask);
        }
        pBuf.n += sqlite3Fts5PutVarint(pBuf.p.? + @as(usize, @intCast(pBuf.n)), @bitCast((iPos - piPrev.*) + 2));
        piPrev.* = iPos;
    }
}

/// fts5.c 4441-4450: grow the buffer then safe-append iPos.
export fn sqlite3Fts5PoslistWriterAppend(pBuf: *Fts5Buffer, pWriter: *Fts5PoslistWriter, iPos: i64) callconv(.c) c_int {
    var rc: c_int = 0;
    if (fts5BufferGrow(&rc, pBuf, 5 + 5 + 5)) return rc;
    sqlite3Fts5PoslistSafeAppend(pBuf, &pWriter.iPrev, iPos);
    return SQLITE_OK;
}

/// fts5.c 4452-4463: malloc nByte zeroed bytes, latching OOM into *pRc.
export fn sqlite3Fts5MallocZero(pRc: *c_int, nByte: i64) callconv(.c) ?*anyopaque {
    var pRet: ?*anyopaque = null;
    if (pRc.* == SQLITE_OK) {
        pRet = sqlite3_malloc64(@bitCast(nByte));
        if (pRet == null) {
            if (nByte > 0) pRc.* = SQLITE_NOMEM;
        } else {
            _ = memset(pRet, 0, @intCast(nByte));
        }
    }
    return pRet;
}

/// fts5.c 4473-4488: nul-terminated copy of pIn (nIn<0 => strlen).
export fn sqlite3Fts5Strndup(pRc: *c_int, pIn: [*]const u8, nIn0: c_int) callconv(.c) ?[*:0]u8 {
    var nIn = nIn0;
    var zRet: ?[*]u8 = null;
    if (pRc.* == SQLITE_OK) {
        if (nIn < 0) {
            nIn = @intCast(strlen(@ptrCast(pIn)));
        }
        zRet = @ptrCast(sqlite3_malloc64(@as(u64, @intCast(nIn)) + 1));
        if (zRet) |z| {
            _ = memcpy(z, pIn, @intCast(nIn));
            z[@intCast(nIn)] = 0;
        } else {
            pRc.* = SQLITE_NOMEM;
        }
    }
    return @ptrCast(zRet);
}

/// fts5.c 4501-4514: true if t may be part of an FTS5 bareword.
const aBareword = [128]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x00..0x0F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, // 0x10..0x1F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x20..0x2F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 0x30..0x3F
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x40..0x4F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // 0x50..0x5F
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x60..0x6F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // 0x70..0x7F
};
export fn sqlite3Fts5IsBareword(t: u8) callconv(.c) c_int {
    if (t & 0x80 != 0) return 1;
    return aBareword[t];
}

// ===========================================================================
// Fts5Termset (fts5.c 4519-4599): a small open-chained hash bucket of terms,
// used by the offsets=0 integrity check. Fts5TermsetEntry/Fts5Termset are
// private to this section, so they are defined here rather than in fts5_int.zig
// (Fts5Termset is `opaque` there).
// ===========================================================================
const Fts5TermsetEntry = extern struct {
    pTerm: ?[*]u8,
    nTerm: c_int,
    iIdx: c_int, // index (main or aPrefix[] entry)
    pNext: ?*Fts5TermsetEntry,
};
const Fts5Termset = extern struct {
    apHash: [512]?*Fts5TermsetEntry,
};

/// fts5.c 4531-4535: allocate a new (zeroed) Fts5Termset.
export fn sqlite3Fts5TermsetNew(pp: *?*Fts5Termset) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    pp.* = @ptrCast(@alignCast(sqlite3Fts5MallocZero(&rc, @sizeOf(Fts5Termset))));
    return rc;
}

/// fts5.c 4537-4584: add a (iIdx, term) pair; set *pbPresent if already there.
export fn sqlite3Fts5TermsetAdd(
    p: ?*Fts5Termset,
    iIdx: c_int,
    pTerm: [*]const u8,
    nTerm: c_int,
    pbPresent: *c_int,
) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    pbPresent.* = 0;
    if (p) |ts| {
        var hash: u32 = 13;
        // Same hash checksum as fts5_hash.c (needed for collision tests).
        var i: c_int = nTerm - 1;
        while (i >= 0) : (i -= 1) {
            hash = (hash << 3) ^ hash ^ pTerm[@intCast(i)];
        }
        hash = (hash << 3) ^ hash ^ @as(u32, @bitCast(iIdx));
        hash = hash % @as(u32, @intCast(ts.apHash.len));

        var pEntry = ts.apHash[hash];
        while (pEntry) |e| : (pEntry = e.pNext) {
            if (e.iIdx == iIdx and e.nTerm == nTerm and
                memcmp(e.pTerm, pTerm, @intCast(nTerm)) == 0)
            {
                pbPresent.* = 1;
                break;
            }
        }

        if (pEntry == null) {
            const pNew: ?*Fts5TermsetEntry = @ptrCast(@alignCast(sqlite3Fts5MallocZero(
                &rc,
                @as(i64, @sizeOf(Fts5TermsetEntry)) + nTerm,
            )));
            if (pNew) |e| {
                // pTerm points to the bytes immediately after the entry.
                const after: [*]u8 = @ptrCast(@as([*]Fts5TermsetEntry, @ptrCast(e)) + 1);
                e.pTerm = after;
                e.nTerm = nTerm;
                e.iIdx = iIdx;
                _ = memcpy(after, pTerm, @intCast(nTerm));
                e.pNext = ts.apHash[hash];
                ts.apHash[hash] = e;
            }
        }
    }
    return rc;
}

/// fts5.c 4586-4599: free an Fts5Termset and all its entries.
export fn sqlite3Fts5TermsetFree(p: ?*Fts5Termset) callconv(.c) void {
    if (p) |ts| {
        var i: usize = 0;
        while (i < ts.apHash.len) : (i += 1) {
            var pEntry = ts.apHash[i];
            while (pEntry) |e| {
                const pDel = e;
                pEntry = e.pNext;
                sqlite3_free(pDel);
            }
        }
        sqlite3_free(ts);
    }
}

comptime {
    _ = int;
}
