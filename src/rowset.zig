//! Zig port of SQLite's RowSet — a collection of rowids supporting batched
//! insert/test and sorted extraction (src/rowset.c).
//!
//! Drop-in replacement exporting the same C-ABI symbols. `RowSet` is opaque
//! (only forward-declared in sqliteInt.h); callers in vdbe.c/vdbemem.c hold it
//! as `RowSet*` stored in a Mem's `z` blob and free it via `xDel ==
//! sqlite3RowSetDelete` (an address comparison — hence we export that symbol).
//! `sqlite3RowSetInit` packs its first batch of entries into the tail of its own
//! allocation, so the struct/entry sizes and ROUND8 padding are kept faithful.
//!
//! Build config assumed (mirrors `sqlite_flags` in build.zig): a 64-bit target
//! (8-byte pointers), so the BITVEC-style geometry below matches the C macros.

const std = @import("std");

const ROWSET_ALLOCATION_SIZE = 1024;
const ROWSET_SORTED: u16 = 0x01; // RowSet.pEntry is sorted
const ROWSET_NEXT: u16 = 0x02; // sqlite3RowSetNext() has been called

const RowSetEntry = extern struct {
    v: i64, // ROWID value (unused when this node heads a forest list)
    pRight: ?*RowSetEntry, // right subtree (larger) or next list element
    pLeft: ?*RowSetEntry, // left subtree (smaller)
};

/// Entries per chunk: (alloc size - one next-pointer) / entry size.
const ROWSET_ENTRY_PER_CHUNK = (ROWSET_ALLOCATION_SIZE - 8) / @sizeOf(RowSetEntry);

const RowSetChunk = extern struct {
    pNextChunk: ?*RowSetChunk,
    aEntry: [ROWSET_ENTRY_PER_CHUNK]RowSetEntry,
};

const RowSet = extern struct {
    pChunk: ?*RowSetChunk, // all chunk allocations
    db: ?*anyopaque, // the database connection (sqlite3*)
    pEntry: ?*RowSetEntry, // list of entries via pRight
    pLast: ?*RowSetEntry, // last entry on pEntry
    pFresh: ?*RowSetEntry, // source of new entry objects
    pForest: ?*RowSetEntry, // list of binary trees of entries
    nFresh: u16, // objects remaining on pFresh
    rsFlags: u16, // ROWSET_* flags
    iBatch: c_int, // current insert batch
};

comptime {
    std.debug.assert(@sizeOf(RowSetEntry) == 24);
    std.debug.assert(@sizeOf(RowSet) == 56);
    std.debug.assert(ROWSET_ENTRY_PER_CHUNK == 42);
}

inline fn round8(x: usize) usize {
    return (x + 7) & ~@as(usize, 7);
}

// --- C helpers we call back into (resolved at link time from the C objects) ---
extern fn sqlite3DbMallocRawNN(db: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3DbMallocSize(db: ?*anyopaque, p: ?*const anyopaque) c_int;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;

/// Advance a RowSetEntry pointer by one element (mirrors C `pFresh++`).
inline fn nextEntry(p: *RowSetEntry) *RowSetEntry {
    return @ptrFromInt(@intFromPtr(p) + @sizeOf(RowSetEntry));
}

/// Allocate a RowSet object. Returns null on OOM.
export fn sqlite3RowSetInit(db: ?*anyopaque) callconv(.c) ?*RowSet {
    const p: ?*RowSet = @ptrCast(@alignCast(sqlite3DbMallocRawNN(db, @sizeOf(RowSet))));
    if (p) |pp| {
        const N = sqlite3DbMallocSize(db, pp);
        pp.pChunk = null;
        pp.db = db;
        pp.pEntry = null;
        pp.pLast = null;
        pp.pForest = null;
        const base: [*]u8 = @ptrCast(pp);
        pp.pFresh = @ptrCast(@alignCast(base + round8(@sizeOf(RowSet))));
        pp.nFresh = @intCast(@divTrunc(N - @as(c_int, @intCast(round8(@sizeOf(RowSet)))), @sizeOf(RowSetEntry)));
        pp.rsFlags = ROWSET_SORTED;
        pp.iBatch = 0;
    }
    return p;
}

/// Deallocate every chunk, resetting the RowSet to empty. This is the RowSet's
/// destructor body; also reused after extraction to free memory eagerly.
export fn sqlite3RowSetClear(pArg: ?*anyopaque) callconv(.c) void {
    const p: *RowSet = @ptrCast(@alignCast(pArg.?));
    var pChunk = p.pChunk;
    while (pChunk) |chunk| {
        const pNextChunk = chunk.pNextChunk;
        sqlite3DbFree(p.db, chunk);
        pChunk = pNextChunk;
    }
    p.pChunk = null;
    p.nFresh = 0;
    p.pEntry = null;
    p.pLast = null;
    p.pForest = null;
    p.rsFlags = ROWSET_SORTED;
}

/// Destroy the RowSet: free chunks, then the RowSet allocation itself.
export fn sqlite3RowSetDelete(pArg: ?*anyopaque) callconv(.c) void {
    sqlite3RowSetClear(pArg);
    const p: *RowSet = @ptrCast(@alignCast(pArg.?));
    sqlite3DbFree(p.db, pArg);
}

/// Pull a fresh (uninitialized) RowSetEntry from the pool, allocating a chunk if
/// needed. Returns null on OOM (db.mallocFailed is set by the allocator).
fn rowSetEntryAlloc(p: *RowSet) ?*RowSetEntry {
    if (p.nFresh == 0) {
        const pNew: ?*RowSetChunk = @ptrCast(@alignCast(sqlite3DbMallocRawNN(p.db, @sizeOf(RowSetChunk))));
        const chunk = pNew orelse return null;
        chunk.pNextChunk = p.pChunk;
        p.pChunk = chunk;
        p.pFresh = &chunk.aEntry[0];
        p.nFresh = ROWSET_ENTRY_PER_CHUNK;
    }
    p.nFresh -= 1;
    const result = p.pFresh.?;
    p.pFresh = nextEntry(result);
    return result;
}

/// Insert a rowid. Sets db.mallocFailed (and silently returns) on OOM.
export fn sqlite3RowSetInsert(p: *RowSet, rowid: i64) callconv(.c) void {
    const pEntry = rowSetEntryAlloc(p) orelse return;
    pEntry.v = rowid;
    pEntry.pRight = null;
    if (p.pLast) |pLast| {
        if (rowid <= pLast.v) {
            // Preserve ROWSET_SORTED only while inserts stay in order.
            p.rsFlags &= ~ROWSET_SORTED;
        }
        pLast.pRight = pEntry;
    } else {
        p.pEntry = pEntry;
    }
    p.pLast = pEntry;
}

/// Merge two pRight-linked sorted lists, dropping duplicates.
fn rowSetEntryMerge(pA_in: *RowSetEntry, pB_in: *RowSetEntry) *RowSetEntry {
    var head: RowSetEntry = undefined;
    var pTail: *RowSetEntry = &head;
    var pA: *RowSetEntry = pA_in;
    var pB: *RowSetEntry = pB_in;
    while (true) {
        if (pA.v <= pB.v) {
            if (pA.v < pB.v) {
                pTail.pRight = pA;
                pTail = pA;
            }
            pA = pA.pRight orelse {
                pTail.pRight = pB;
                break;
            };
        } else {
            pTail.pRight = pB;
            pTail = pB;
            pB = pB.pRight orelse {
                pTail.pRight = pA;
                break;
            };
        }
    }
    return head.pRight.?;
}

/// Sort a pRight-linked list into increasing v using a 40-bucket merge.
fn rowSetEntrySort(pIn_in: *RowSetEntry) *RowSetEntry {
    var aBucket: [40]?*RowSetEntry = @splat(null);
    var pIn: ?*RowSetEntry = pIn_in;
    while (pIn) |cur| {
        const pNext = cur.pRight;
        cur.pRight = null;
        var i: usize = 0;
        var acc: *RowSetEntry = cur;
        while (aBucket[i]) |bkt| {
            acc = rowSetEntryMerge(bkt, acc);
            aBucket[i] = null;
            i += 1;
        }
        aBucket[i] = acc;
        pIn = pNext;
    }
    var result: ?*RowSetEntry = aBucket[0];
    var i: usize = 1;
    while (i < aBucket.len) : (i += 1) {
        const bkt = aBucket[i] orelse continue;
        result = if (result) |r| rowSetEntryMerge(r, bkt) else bkt;
    }
    return result.?;
}

/// In-order flatten a tree into a pRight-linked list; report head and tail.
fn rowSetTreeToList(pIn: *RowSetEntry, ppFirst: *?*RowSetEntry, ppLast: *?*RowSetEntry) void {
    if (pIn.pLeft) |left| {
        var p: ?*RowSetEntry = undefined;
        rowSetTreeToList(left, ppFirst, &p);
        p.?.pRight = pIn;
    } else {
        ppFirst.* = pIn;
    }
    if (pIn.pRight) |right| {
        rowSetTreeToList(right, &pIn.pRight, ppLast);
    } else {
        ppLast.* = pIn;
    }
}

/// Build a balanced tree of the given depth from the head of *ppList, advancing
/// *ppList past the consumed entries.
fn rowSetNDeepTree(ppList: *?*RowSetEntry, iDepth: c_int) ?*RowSetEntry {
    if (ppList.* == null) return null; // prevent needless deep recursion
    if (iDepth > 1) {
        const pLeft = rowSetNDeepTree(ppList, iDepth - 1);
        const p = ppList.* orelse return pLeft; // safe, though tree is unbalanced
        p.pLeft = pLeft;
        ppList.* = p.pRight;
        p.pRight = rowSetNDeepTree(ppList, iDepth - 1);
        return p;
    } else {
        const p = ppList.*.?;
        ppList.* = p.pRight;
        p.pLeft = null;
        p.pRight = null;
        return p;
    }
}

/// Convert a sorted pRight-linked list into a tree deep enough to hold it all.
fn rowSetListToTree(pList_in: *RowSetEntry) *RowSetEntry {
    var p: *RowSetEntry = pList_in;
    var pList: ?*RowSetEntry = p.pRight;
    p.pLeft = null;
    p.pRight = null;
    var iDepth: c_int = 1;
    while (pList) |next| {
        const pLeft = p;
        p = next;
        pList = p.pRight;
        p.pLeft = pLeft;
        p.pRight = rowSetNDeepTree(&pList, iDepth);
        iDepth += 1;
    }
    return p;
}

/// Extract the smallest element into *pRowid. Returns 1 on success, 0 if empty.
/// After the first call no more inserts may occur; must not mix with Test().
export fn sqlite3RowSetNext(p: *RowSet, pRowid: *i64) callconv(.c) c_int {
    // On first call, merge the entry list into sorted order.
    if ((p.rsFlags & ROWSET_NEXT) == 0) {
        if ((p.rsFlags & ROWSET_SORTED) == 0) {
            if (p.pEntry) |e| p.pEntry = rowSetEntrySort(e);
        }
        p.rsFlags |= ROWSET_SORTED | ROWSET_NEXT;
    }
    if (p.pEntry) |e| {
        pRowid.* = e.v;
        p.pEntry = e.pRight;
        if (p.pEntry == null) {
            // Free memory now rather than waiting on finalize.
            sqlite3RowSetClear(p);
        }
        return 1;
    }
    return 0;
}

/// Return 1 if iRowid was inserted in any batch before iBatch, else 0. On a new
/// batch, sorts pending entries into the forest of balanced trees.
export fn sqlite3RowSetTest(pRowSet: *RowSet, iBatch: c_int, iRowid: i64) callconv(.c) c_int {
    if (iBatch != pRowSet.iBatch) {
        if (pRowSet.pEntry) |entry0| {
            var p: *RowSetEntry = entry0;
            var ppPrevTree: *?*RowSetEntry = &pRowSet.pForest;
            if ((pRowSet.rsFlags & ROWSET_SORTED) == 0) {
                p = rowSetEntrySort(entry0);
            }
            var pTree = pRowSet.pForest;
            while (pTree) |tree| {
                ppPrevTree = &tree.pRight;
                if (tree.pLeft == null) {
                    tree.pLeft = rowSetListToTree(p);
                    break;
                } else {
                    var pAux: ?*RowSetEntry = undefined;
                    var pTail: ?*RowSetEntry = undefined;
                    rowSetTreeToList(tree.pLeft.?, &pAux, &pTail);
                    tree.pLeft = null;
                    p = rowSetEntryMerge(pAux.?, p);
                }
                pTree = tree.pRight;
            }
            if (pTree == null) {
                pTree = rowSetEntryAlloc(pRowSet);
                ppPrevTree.* = pTree;
                if (pTree) |tree| {
                    tree.v = 0;
                    tree.pRight = null;
                    tree.pLeft = rowSetListToTree(p);
                }
            }
            pRowSet.pEntry = null;
            pRowSet.pLast = null;
            pRowSet.rsFlags |= ROWSET_SORTED;
        }
        pRowSet.iBatch = iBatch;
    }

    // Search the forest for iRowid.
    var pTree = pRowSet.pForest;
    while (pTree) |tree| {
        var p = tree.pLeft;
        while (p) |node| {
            if (node.v < iRowid) {
                p = node.pRight;
            } else if (node.v > iRowid) {
                p = node.pLeft;
            } else {
                return 1;
            }
        }
        pTree = tree.pRight;
    }
    return 0;
}
