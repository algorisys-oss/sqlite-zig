//! Zig port of the fts5_hash.c section of the FTS5 amalgamation
//! (vendor/tsrc/fts5.c lines 9016-9607).
//!
//! The in-memory "term -> doclist" hash table that accumulates index content
//! before it is flushed to a level-0 segment. Each entry, its key and its
//! position-list data live in a single allocation: the Fts5HashEntry struct,
//! immediately followed by the nKey-byte key ("0token"), immediately followed
//! by the doclist bytes.
//!
//! Fts5Hash / Fts5HashEntry are private to this section (the foundation exposes
//! Fts5Hash as `opaque`), so they are defined locally as `extern struct`s with
//! the exact C layout. The varint codec lives in fts5_varint.c; this file calls
//! it via `extern fn` (resolved at link time within the single FTS5 object).

const int = @import("fts5_int.zig");
const config = @import("config");

const Fts5Config = int.Fts5Config;
const SQLITE_OK = int.SQLITE_OK;
const SQLITE_NOMEM = int.SQLITE_NOMEM;
const FTS5_DETAIL_NONE = int.FTS5_DETAIL_NONE;
const FTS5_DETAIL_FULL = int.FTS5_DETAIL_FULL;

// --- sibling section: fts5_varint.c -----------------------------------------
extern fn sqlite3Fts5PutVarint(p: [*]u8, v: u64) callconv(.c) c_int;
extern fn sqlite3Fts5GetVarintLen(iVal: u32) callconv(.c) c_int;

// --- libc + public sqlite3 API (resolved at link time) ----------------------
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: usize) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: usize) c_int;
extern fn memmove(dst: ?*anyopaque, src: ?*const anyopaque, n: usize) ?*anyopaque;
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;

// ===========================================================================
// Section-private structs (fts5.c 9044-9093). Defined here because the
// foundation only exposes Fts5Hash as `opaque`.
// ===========================================================================

/// fts5.c 9080-9093: one entry in the hash table. The key follows the struct
/// in memory, the doclist follows the key.
const Fts5HashEntry = extern struct {
    pHashNext: ?*Fts5HashEntry, // next entry with same hash key
    pScanNext: ?*Fts5HashEntry, // next entry in sorted order

    nAlloc: c_int, // total size of allocation
    iSzPoslist: c_int, // offset of space for 4-byte poslist size
    nData: c_int, // total bytes of data (incl. structure)
    nKey: c_int, // length of key in bytes
    bDel: u8, // set delete-flag @ iSzPoslist
    bContent: u8, // set content-flag (detail=none mode)
    iCol: i16, // column of last value written
    iPos: c_int, // position of last value written
    iRowid: i64, // rowid of last value written
};

/// fts5.c 9044-9051: the hash table header.
const Fts5Hash = extern struct {
    eDetail: c_int, // copy of Fts5Config.eDetail
    pnByte: ?*c_int, // pointer to bytes counter
    nEntry: c_int, // number of entries currently in hash
    nSlot: c_int, // size of aSlot[] array
    pScan: ?*Fts5HashEntry, // current ordered scan item
    aSlot: ?[*]?*Fts5HashEntry, // array of hash slots
};

/// fts5.c 9100: `#define fts5EntryKey(p) ((char*)(&(p)[1]))`.
/// Returns a pointer to the key bytes immediately after the entry struct.
inline fn fts5EntryKey(p: *Fts5HashEntry) [*]u8 {
    return @ptrCast(@as([*]Fts5HashEntry, @ptrCast(p)) + 1);
}

/// Raw byte pointer to the start of the entry allocation (the `(u8*)p` cast).
inline fn entryBytes(p: *Fts5HashEntry) [*]u8 {
    return @ptrCast(p);
}

// ===========================================================================
// fts5.c 9106-9131: allocate a new hash table.
// ===========================================================================
export fn sqlite3Fts5HashNew(pConfig: *Fts5Config, ppNew: *?*Fts5Hash, pnByte: *c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pNew: ?*Fts5Hash = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(Fts5Hash))));
    ppNew.* = pNew;
    if (pNew == null) {
        rc = SQLITE_NOMEM;
    } else {
        const h = pNew.?;
        _ = memset(h, 0, @sizeOf(Fts5Hash));
        h.pnByte = pnByte;
        h.eDetail = pConfig.eDetail;

        h.nSlot = 1024;
        const nByte: i64 = @as(i64, @sizeOf(?*Fts5HashEntry)) * h.nSlot;
        h.aSlot = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
        if (h.aSlot == null) {
            sqlite3_free(h);
            ppNew.* = null;
            rc = SQLITE_NOMEM;
        } else {
            _ = memset(@ptrCast(h.aSlot), 0, @intCast(nByte));
        }
    }
    return rc;
}

// ===========================================================================
// fts5.c 9136-9142: free a hash table object.
// ===========================================================================
export fn sqlite3Fts5HashFree(pHash: ?*Fts5Hash) callconv(.c) void {
    if (pHash) |h| {
        sqlite3Fts5HashClear(h);
        sqlite3_free(@ptrCast(h.aSlot));
        sqlite3_free(h);
    }
}

// ===========================================================================
// fts5.c 9147-9159: empty (but do not delete) a hash table.
// ===========================================================================
export fn sqlite3Fts5HashClear(pHash: *Fts5Hash) callconv(.c) void {
    const aSlot = pHash.aSlot.?;
    var i: c_int = 0;
    while (i < pHash.nSlot) : (i += 1) {
        var pSlot = aSlot[@intCast(i)];
        while (pSlot) |s| {
            const pNext = s.pHashNext;
            sqlite3_free(s);
            pSlot = pNext;
        }
    }
    _ = memset(@ptrCast(pHash.aSlot), 0, @as(usize, @intCast(pHash.nSlot)) * @sizeOf(?*Fts5HashEntry));
    pHash.nEntry = 0;
}

// fts5.c 9161-9168
fn fts5HashKey(nSlot: c_int, p: [*]const u8, n: c_int) c_uint {
    var h: c_uint = 13;
    var i: c_int = n - 1;
    while (i >= 0) : (i -= 1) {
        h = (h << 3) ^ h ^ p[@intCast(i)];
    }
    return h % @as(c_uint, @bitCast(nSlot));
}

// fts5.c 9170-9178
fn fts5HashKey2(nSlot: c_int, b: u8, p: [*]const u8, n: c_int) c_uint {
    var h: c_uint = 13;
    var i: c_int = n - 1;
    while (i >= 0) : (i -= 1) {
        h = (h << 3) ^ h ^ p[@intCast(i)];
    }
    h = (h << 3) ^ h ^ b;
    return h % @as(c_uint, @bitCast(nSlot));
}

// ===========================================================================
// fts5.c 9183-9208: resize the hash table by doubling the number of slots.
// ===========================================================================
fn fts5HashResize(pHash: *Fts5Hash) c_int {
    const nNew: c_int = pHash.nSlot * 2;
    const apOld = pHash.aSlot.?;

    const apNew: ?[*]?*Fts5HashEntry = @ptrCast(@alignCast(sqlite3_malloc64(
        @as(u64, @intCast(nNew)) * @sizeOf(?*Fts5HashEntry),
    )));
    if (apNew == null) return SQLITE_NOMEM;
    const an = apNew.?;
    _ = memset(@ptrCast(an), 0, @as(usize, @intCast(nNew)) * @sizeOf(?*Fts5HashEntry));

    var i: c_int = 0;
    while (i < pHash.nSlot) : (i += 1) {
        while (apOld[@intCast(i)]) |p| {
            apOld[@intCast(i)] = p.pHashNext;
            const iHash = fts5HashKey(nNew, fts5EntryKey(p), p.nKey);
            p.pHashNext = an[iHash];
            an[iHash] = p;
        }
    }

    sqlite3_free(@ptrCast(apOld));
    pHash.nSlot = nNew;
    pHash.aSlot = apNew;
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 9210-9251: add the 4-byte poslist size field to entry p (or to a
// faux copy p2). Returns the change in nData.
// ===========================================================================
fn fts5HashAddPoslistSize(pHash: *Fts5Hash, p: *Fts5HashEntry, p2: ?*Fts5HashEntry) c_int {
    var nRet: c_int = 0;
    if (p.iSzPoslist != 0) {
        const pPtr: [*]u8 = if (p2) |x| entryBytes(x) else entryBytes(p);
        var nData = p.nData;
        if (pHash.eDetail == FTS5_DETAIL_NONE) {
            // assert( nData==p.iSzPoslist );
            if (p.bDel != 0) {
                pPtr[@intCast(nData)] = 0x00;
                nData += 1;
                if (p.bContent != 0) {
                    pPtr[@intCast(nData)] = 0x00;
                    nData += 1;
                }
            }
        } else {
            const nSz: c_int = nData - p.iSzPoslist - 1; // size in bytes
            const nPos: c_int = nSz * 2 + p.bDel; // value of nPos field

            // assert( p.bDel==0 || p.bDel==1 );
            if (nPos <= 127) {
                pPtr[@intCast(p.iSzPoslist)] = @intCast(nPos);
            } else {
                const nByte = sqlite3Fts5GetVarintLen(@bitCast(nPos));
                _ = memmove(
                    pPtr + @as(usize, @intCast(p.iSzPoslist + nByte)),
                    pPtr + @as(usize, @intCast(p.iSzPoslist + 1)),
                    @intCast(nSz),
                );
                _ = sqlite3Fts5PutVarint(pPtr + @as(usize, @intCast(p.iSzPoslist)), @intCast(nPos));
                nData += (nByte - 1);
            }
        }

        nRet = nData - p.nData;
        if (p2 == null) {
            p.iSzPoslist = 0;
            p.bDel = 0;
            p.bContent = 0;
            p.nData = nData;
        }
    }
    return nRet;
}

// ===========================================================================
// fts5.c 9261-9406: add an entry to the in-memory hash table.
//   (bByte || pToken) -> (iRowid,iCol,iPos). iCol<0 => delete marker.
// ===========================================================================
export fn sqlite3Fts5HashWrite(
    pHash: *Fts5Hash,
    iRowid: i64,
    iCol: c_int,
    iPos0: c_int,
    bByte: u8,
    pToken: [*]const u8,
    nToken: c_int,
) callconv(.c) c_int {
    var iPos = iPos0;
    var iHash: c_uint = undefined;
    var p: ?*Fts5HashEntry = null;
    var nIncr: c_int = 0; // amount to increment (*pHash->pnByte) by
    var bNew: c_int = @intFromBool(pHash.eDetail == FTS5_DETAIL_FULL);

    const aSlot = pHash.aSlot.?;

    // Attempt to locate an existing hash entry.
    iHash = fts5HashKey2(pHash.nSlot, bByte, pToken, nToken);
    {
        var it = aSlot[iHash];
        while (it) |e| : (it = e.pHashNext) {
            const zKey = fts5EntryKey(e);
            if (zKey[0] == bByte and e.nKey == nToken + 1 and
                memcmp(zKey + 1, pToken, @intCast(nToken)) == 0)
            {
                p = e;
                break;
            }
        }
    }

    // If an existing hash entry cannot be found, create a new one.
    if (p == null) {
        var nByte: i64 = @as(i64, @sizeOf(Fts5HashEntry)) + (nToken + 1) + 1 + 64;
        if (nByte < 128) nByte = 128;

        // Grow the aSlot[] array if necessary.
        if ((pHash.nEntry * 2) >= pHash.nSlot) {
            const rc = fts5HashResize(pHash);
            if (rc != SQLITE_OK) return rc;
            iHash = fts5HashKey2(pHash.nSlot, bByte, pToken, nToken);
        }

        const pNew: ?*Fts5HashEntry = @ptrCast(@alignCast(sqlite3_malloc64(@bitCast(nByte))));
        if (pNew == null) return SQLITE_NOMEM;
        p = pNew;
        const e = pNew.?;
        _ = memset(e, 0, @sizeOf(Fts5HashEntry));
        e.nAlloc = @intCast(nByte);
        const zKey = fts5EntryKey(e);
        zKey[0] = bByte;
        _ = memcpy(zKey + 1, pToken, @intCast(nToken));
        e.nKey = nToken + 1;
        zKey[@intCast(nToken + 1)] = 0;
        e.nData = nToken + 1 + @sizeOf(Fts5HashEntry);
        e.pHashNext = pHash.aSlot.?[iHash];
        pHash.aSlot.?[iHash] = e;
        pHash.nEntry += 1;

        // Add the first rowid field to the hash entry.
        e.nData += sqlite3Fts5PutVarint(entryBytes(e) + @as(usize, @intCast(e.nData)), @bitCast(iRowid));
        e.iRowid = iRowid;

        e.iSzPoslist = e.nData;
        if (pHash.eDetail != FTS5_DETAIL_NONE) {
            e.nData += 1;
            e.iCol = if (pHash.eDetail == FTS5_DETAIL_FULL) 0 else -1;
        }
    } else {
        const e = p.?;
        // Appending to an existing hash entry. Ensure space for the largest
        // possible new entry (9 + 4 + 1 + 3 + 5).
        if ((e.nAlloc - e.nData) < (9 + 4 + 1 + 3 + 5)) {
            const nNew: i64 = @as(i64, e.nAlloc) * 2;
            const pNew: ?*Fts5HashEntry = @ptrCast(@alignCast(sqlite3_realloc64(e, @bitCast(nNew))));
            if (pNew == null) return SQLITE_NOMEM;
            const ne = pNew.?;
            ne.nAlloc = @intCast(nNew);
            var pp: *?*Fts5HashEntry = &pHash.aSlot.?[iHash];
            while (pp.* != p) : (pp = &pp.*.?.pHashNext) {}
            pp.* = ne;
            p = ne;
        }
        nIncr -= p.?.nData;
    }

    const pe = p.?;
    const pPtr: [*]u8 = entryBytes(pe);

    // If this is a new rowid, append the 4-byte size field for the previous
    // entry, and the new rowid for this entry.
    if (iRowid != pe.iRowid) {
        const iDiff: u64 = @as(u64, @bitCast(iRowid)) -% @as(u64, @bitCast(pe.iRowid));
        _ = fts5HashAddPoslistSize(pHash, pe, null);
        pe.nData += sqlite3Fts5PutVarint(pPtr + @as(usize, @intCast(pe.nData)), iDiff);
        pe.iRowid = iRowid;
        bNew = 1;
        pe.iSzPoslist = pe.nData;
        if (pHash.eDetail != FTS5_DETAIL_NONE) {
            pe.nData += 1;
            pe.iCol = if (pHash.eDetail == FTS5_DETAIL_FULL) 0 else -1;
            pe.iPos = 0;
        }
    }

    if (iCol >= 0) {
        if (pHash.eDetail == FTS5_DETAIL_NONE) {
            pe.bContent = 1;
        } else {
            // Append a new column value, if necessary.
            if (iCol != pe.iCol) {
                if (pHash.eDetail == FTS5_DETAIL_FULL) {
                    pPtr[@intCast(pe.nData)] = 0x01;
                    pe.nData += 1;
                    pe.nData += sqlite3Fts5PutVarint(pPtr + @as(usize, @intCast(pe.nData)), @intCast(iCol));
                    pe.iCol = @intCast(iCol);
                    pe.iPos = 0;
                } else {
                    bNew = 1;
                    iPos = iCol;
                    pe.iCol = @intCast(iCol);
                }
            }

            // Append the new position offset, if necessary.
            if (bNew != 0) {
                pe.nData += sqlite3Fts5PutVarint(pPtr + @as(usize, @intCast(pe.nData)), @intCast(iPos - pe.iPos + 2));
                pe.iPos = iPos;
            }
        }
    } else {
        // This is a delete. Set the delete flag.
        pe.bDel = 1;
    }

    nIncr += pe.nData;
    pHash.pnByte.?.* += nIncr;
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 9414-9457: merge two key-sorted linked lists into one.
// ===========================================================================
fn fts5HashEntryMerge(pLeft: ?*Fts5HashEntry, pRight: ?*Fts5HashEntry) ?*Fts5HashEntry {
    var p1 = pLeft;
    var p2 = pRight;
    var pRet: ?*Fts5HashEntry = null;
    var ppOut: *?*Fts5HashEntry = &pRet;

    while (p1 != null or p2 != null) {
        if (p1 == null) {
            ppOut.* = p2;
            p2 = null;
        } else if (p2 == null) {
            ppOut.* = p1;
            p1 = null;
        } else {
            const e1 = p1.?;
            const e2 = p2.?;
            const zKey1 = fts5EntryKey(e1);
            const zKey2 = fts5EntryKey(e2);
            const nMin: c_int = if (e1.nKey < e2.nKey) e1.nKey else e2.nKey;

            var cmp: c_int = memcmp(zKey1, zKey2, @intCast(nMin));
            if (cmp == 0) {
                cmp = e1.nKey - e2.nKey;
            }
            // assert( cmp!=0 );

            if (cmp > 0) {
                // p2 is smaller
                ppOut.* = p2;
                ppOut = &e2.pScanNext;
                p2 = e2.pScanNext;
            } else {
                // p1 is smaller
                ppOut.* = p1;
                ppOut = &e1.pScanNext;
                p1 = e1.pScanNext;
            }
            ppOut.* = null;
        }
    }

    return pRet;
}

// ===========================================================================
// fts5.c 9463-9504: link all matching tokens into a sorted list.
// ===========================================================================
fn fts5HashEntrySort(
    pHash: *Fts5Hash,
    pTerm: ?[*]const u8,
    nTerm: c_int,
    ppSorted: *?*Fts5HashEntry,
) c_int {
    const nMergeSlot: usize = 32;

    ppSorted.* = null;
    const ap: ?[*]?*Fts5HashEntry = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(?*Fts5HashEntry) * nMergeSlot)));
    if (ap == null) return SQLITE_NOMEM;
    const a = ap.?;
    _ = memset(@ptrCast(a), 0, @sizeOf(?*Fts5HashEntry) * nMergeSlot);

    const aSlot = pHash.aSlot.?;
    var iSlot: c_int = 0;
    while (iSlot < pHash.nSlot) : (iSlot += 1) {
        var pIter = aSlot[@intCast(iSlot)];
        while (pIter) |it| : (pIter = it.pHashNext) {
            if (pTerm == null or
                (it.nKey >= nTerm and 0 == memcmp(fts5EntryKey(it), pTerm.?, @intCast(nTerm))))
            {
                var pEntry: ?*Fts5HashEntry = it;
                it.pScanNext = null;
                var i: usize = 0;
                while (a[i] != null) : (i += 1) {
                    pEntry = fts5HashEntryMerge(pEntry, a[i]);
                    a[i] = null;
                }
                a[i] = pEntry;
            }
        }
    }

    var pList: ?*Fts5HashEntry = null;
    var i: usize = 0;
    while (i < nMergeSlot) : (i += 1) {
        pList = fts5HashEntryMerge(pList, a[i]);
    }

    sqlite3_free(@ptrCast(ap));
    ppSorted.* = pList;
    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 9509-9544: query the hash table for a doclist.
// ===========================================================================
export fn sqlite3Fts5HashQuery(
    pHash: *Fts5Hash,
    nPre: c_int,
    pTerm: [*]const u8,
    nTerm: c_int,
    ppOut: *?*anyopaque,
    pnDoclist: *c_int,
) callconv(.c) c_int {
    const iHash = fts5HashKey(pHash.nSlot, pTerm, nTerm);
    const aSlot = pHash.aSlot.?;

    var p: ?*Fts5HashEntry = aSlot[iHash];
    while (p) |e| : (p = e.pHashNext) {
        const zKey = fts5EntryKey(e);
        if (nTerm == e.nKey and memcmp(zKey, pTerm, @intCast(nTerm)) == 0) break;
    }

    if (p) |e| {
        const nHashPre: c_int = @as(c_int, @sizeOf(Fts5HashEntry)) + nTerm;
        var nList: c_int = e.nData - nHashPre;
        const pRet: ?[*]u8 = @ptrCast(@alignCast(sqlite3_malloc64(@intCast(nPre + nList + 10))));
        ppOut.* = pRet;
        if (pRet) |ret| {
            const pFaux: *Fts5HashEntry = @ptrCast(@alignCast(ret + @as(usize, @intCast(nPre - nHashPre))));
            _ = memcpy(ret + @as(usize, @intCast(nPre)), entryBytes(e) + @as(usize, @intCast(nHashPre)), @intCast(nList));
            nList += fts5HashAddPoslistSize(pHash, e, pFaux);
            pnDoclist.* = nList;
        } else {
            pnDoclist.* = 0;
            return SQLITE_NOMEM;
        }
    } else {
        ppOut.* = null;
        pnDoclist.* = 0;
    }

    return SQLITE_OK;
}

// ===========================================================================
// fts5.c 9546-9551
// ===========================================================================
export fn sqlite3Fts5HashScanInit(p: *Fts5Hash, pTerm: ?[*]const u8, nTerm: c_int) callconv(.c) c_int {
    return fts5HashEntrySort(p, pTerm, nTerm, &p.pScan);
}

// fts5.c 9554-9564 (SQLITE_DEBUG only): count entries.
fn fts5HashCount(pHash: *Fts5Hash) c_int {
    var nEntry: c_int = 0;
    const aSlot = pHash.aSlot.?;
    var ii: c_int = 0;
    while (ii < pHash.nSlot) : (ii += 1) {
        var p = aSlot[@intCast(ii)];
        while (p) |e| : (p = e.pHashNext) {
            nEntry += 1;
        }
    }
    return nEntry;
}

// ===========================================================================
// fts5.c 9570-9573: return true if the hash table is empty.
// ===========================================================================
export fn sqlite3Fts5HashIsEmpty(pHash: *Fts5Hash) callconv(.c) c_int {
    if (config.sqlite_debug) {
        // assert( pHash->nEntry==fts5HashCount(pHash) );
        if (pHash.nEntry != fts5HashCount(pHash)) unreachable;
    }
    return @intFromBool(pHash.nEntry == 0);
}

// ===========================================================================
// fts5.c 9575-9578
// ===========================================================================
export fn sqlite3Fts5HashScanNext(p: *Fts5Hash) callconv(.c) void {
    // assert( !sqlite3Fts5HashScanEof(p) );
    p.pScan = p.pScan.?.pScanNext;
}

// ===========================================================================
// fts5.c 9580-9582
// ===========================================================================
export fn sqlite3Fts5HashScanEof(p: *Fts5Hash) callconv(.c) c_int {
    return @intFromBool(p.pScan == null);
}

// ===========================================================================
// fts5.c 9584-9606: read the current scan entry's term and doclist.
// ===========================================================================
export fn sqlite3Fts5HashScanEntry(
    pHash: *Fts5Hash,
    pzTerm: *?[*]const u8,
    pnTerm: *c_int,
    ppDoclist: *?[*]const u8,
    pnDoclist: *c_int,
) callconv(.c) void {
    if (pHash.pScan) |p| {
        const zKey = fts5EntryKey(p);
        const nTerm = p.nKey;
        _ = fts5HashAddPoslistSize(pHash, p, null);
        pzTerm.* = zKey;
        pnTerm.* = nTerm;
        ppDoclist.* = zKey + @as(usize, @intCast(nTerm));
        pnDoclist.* = p.nData - (@as(c_int, @sizeOf(Fts5HashEntry)) + nTerm);
    } else {
        pzTerm.* = null;
        pnTerm.* = 0;
        ppDoclist.* = null;
        pnDoclist.* = 0;
    }
}

comptime {
    _ = int;
}
