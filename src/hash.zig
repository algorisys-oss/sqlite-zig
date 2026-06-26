//! Zig port of SQLite's generic hash table (src/hash.c).
//!
//! Drop-in replacement: exports the same C-ABI symbols
//! (`sqlite3HashInit`, `sqlite3HashInsert`, `sqlite3HashFind`,
//! `sqlite3HashClear`) over the exact `Hash`/`HashElem`/`struct _ht` layout
//! from hash.h, so C callers that reach into the structs via the
//! `sqliteHashFirst`/`Next`/`Data`/`Count` macros keep working unchanged.
//!
//! Behaviorally identical to the C original: same Knuth multiplicative hash,
//! same linear-search-below-threshold strategy, same rehash growth.
//!
//! Build config assumed (mirrors `sqlite_flags` in build.zig):
//!   no SQLITE_EBCDIC, no SQLITE_UNTESTABLE (benign-malloc hooks exist),
//!   SQLITE_MALLOC_SOFT_LIMIT defaults to 1024.

const std = @import("std");

const SQLITE_MALLOC_SOFT_LIMIT = 1024;

// --- ABI-shared layouts (must match hash.h byte-for-byte) ---

const HashElem = extern struct {
    next: ?*HashElem,
    prev: ?*HashElem,
    data: ?*anyopaque,
    pKey: ?[*:0]const u8,
    h: c_uint,
};

/// `struct _ht` — one hash bucket.
const Ht = extern struct {
    count: c_uint,
    chain: ?*HashElem,
};

const Hash = extern struct {
    htsize: c_uint,
    count: c_uint,
    first: ?*HashElem,
    ht: ?[*]Ht,
};

// --- C helpers we call back into (resolved at link time from the C objects) ---
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3Malloc(n: u64) ?*anyopaque;
extern fn sqlite3MallocSize(p: ?*const anyopaque) c_int;
extern fn sqlite3BeginBenignMalloc() void;
extern fn sqlite3EndBenignMalloc() void;
extern fn sqlite3StrICmp(a: ?[*:0]const u8, b: ?[*:0]const u8) c_int;

/// The hashing function: Knuth multiplicative hashing. Only bits 0xdf of each
/// octet are hashed (the omitted bit carries ASCII upper/lower case), so the
/// hash is case-insensitive — consistent with the sqlite3StrICmp comparison.
fn strHash(z_in: [*:0]const u8) c_uint {
    var h: c_uint = 0;
    var z = z_in;
    while (z[0] != 0) {
        h +%= 0xdf & @as(c_uint, z[0]);
        z += 1;
        h *%= 0x9e3779b1;
    }
    return h;
}

/// Link pNew into the hash table pH. If pEntry!=null then also insert pNew into
/// that bucket.
fn insertElement(pH: *Hash, pEntry: ?*Ht, pNew: *HashElem) void {
    var pHead: ?*HashElem = null;
    if (pEntry) |pe| {
        pHead = if (pe.count != 0) pe.chain else null;
        pe.count += 1;
        pe.chain = pNew;
    }
    if (pHead) |ph| {
        pNew.next = ph;
        pNew.prev = ph.prev;
        if (ph.prev) |pp| {
            pp.next = pNew;
        } else {
            pH.first = pNew;
        }
        ph.prev = pNew;
    } else {
        pNew.next = pH.first;
        if (pH.first) |f| {
            f.prev = pNew;
        }
        pNew.prev = null;
        pH.first = pNew;
    }
}

/// Resize the hash table to contain `new_size` buckets. Returns 1 if the resize
/// occurred, 0 if not (allocation failed or size unchanged).
fn rehash(pH: *Hash, new_size_in: c_uint) c_int {
    var new_size = new_size_in;

    // SQLITE_MALLOC_SOFT_LIMIT > 0
    if (@as(usize, new_size) * @sizeOf(Ht) > SQLITE_MALLOC_SOFT_LIMIT) {
        new_size = SQLITE_MALLOC_SOFT_LIMIT / @sizeOf(Ht);
    }
    if (new_size == pH.htsize) return 0;

    // Mark the allocation benign: a failure to grow is a perf hit, not fatal.
    sqlite3BeginBenignMalloc();
    const new_ht_raw = sqlite3Malloc(@as(u64, new_size) * @sizeOf(Ht));
    sqlite3EndBenignMalloc();

    if (new_ht_raw == null) return 0;
    const new_ht: [*]Ht = @ptrCast(@alignCast(new_ht_raw.?));
    sqlite3_free(@ptrCast(pH.ht));
    pH.ht = new_ht;
    // Use the actual allocated size (may exceed the request), and zero all of it.
    new_size = @intCast(@divTrunc(@as(usize, @intCast(sqlite3MallocSize(new_ht_raw))), @sizeOf(Ht)));
    pH.htsize = new_size;
    @memset(std.mem.sliceAsBytes(new_ht[0..new_size]), 0);

    var elem = pH.first;
    pH.first = null;
    while (elem) |e| {
        const next_elem = e.next;
        insertElement(pH, &new_ht[e.h % new_size], e);
        elem = next_elem;
    }
    return 1;
}

/// Static null element returned when a key is not found; only its `data` field
/// (always null) is read by callers, matching the C `static HashElem`.
var nullElement: HashElem = .{ .next = null, .prev = null, .data = null, .pKey = null, .h = 0 };

/// Locate the element matching pKey, or return &nullElement. If pHash!=null the
/// computed hash is written there.
fn findElementWithHash(pH: *const Hash, pKey: [*:0]const u8, pHash: ?*c_uint) *HashElem {
    var elem: ?*HashElem = undefined;
    var count: c_uint = undefined;
    const h = strHash(pKey);
    if (pH.ht) |ht| {
        const pEntry = &ht[h % pH.htsize];
        elem = pEntry.chain;
        count = pEntry.count;
    } else {
        elem = pH.first;
        count = pH.count;
    }
    if (pHash) |ph| ph.* = h;
    while (count != 0) {
        const e = elem.?;
        if (h == e.h and sqlite3StrICmp(e.pKey, pKey) == 0) {
            return e;
        }
        elem = e.next;
        count -= 1;
    }
    return &nullElement;
}

/// Remove a single element from the hash table and free it.
fn removeElement(pH: *Hash, elem: *HashElem) void {
    if (elem.prev) |p| {
        p.next = elem.next;
    } else {
        pH.first = elem.next;
    }
    if (elem.next) |n| {
        n.prev = elem.prev;
    }
    if (pH.ht) |ht| {
        const pEntry = &ht[elem.h % pH.htsize];
        if (pEntry.chain == elem) {
            pEntry.chain = elem.next;
        }
        pEntry.count -= 1;
    }
    sqlite3_free(elem);
    pH.count -= 1;
    if (pH.count == 0) {
        sqlite3HashClear(pH);
    }
}

// --- Public C-ABI surface ---

/// Initialize a Hash structure (turn bulk memory into an empty hash table).
export fn sqlite3HashInit(pNew: *Hash) callconv(.c) void {
    pNew.first = null;
    pNew.count = 0;
    pNew.htsize = 0;
    pNew.ht = null;
}

/// Remove all entries and reclaim all memory, resetting to the empty state.
export fn sqlite3HashClear(pH: *Hash) callconv(.c) void {
    var elem = pH.first;
    pH.first = null;
    sqlite3_free(@ptrCast(pH.ht));
    pH.ht = null;
    pH.htsize = 0;
    while (elem) |e| {
        const next_elem = e.next;
        sqlite3_free(e);
        elem = next_elem;
    }
    pH.count = 0;
}

/// Return the data for the element matching pKey, or null if no match.
export fn sqlite3HashFind(pH: *const Hash, pKey: [*:0]const u8) callconv(.c) ?*anyopaque {
    return findElementWithHash(pH, pKey, null).data;
}

/// Insert an element. With a fresh key, creates an entry and returns null. With
/// an existing key, replaces the data and returns the old data. With data==null,
/// removes the element (returning the old data). On malloc failure the table is
/// left unchanged and `data` is returned.
export fn sqlite3HashInsert(pH: *Hash, pKey: [*:0]const u8, data: ?*anyopaque) callconv(.c) ?*anyopaque {
    var h: c_uint = undefined;
    const elem = findElementWithHash(pH, pKey, &h);
    if (elem.data != null) {
        const old_data = elem.data;
        if (data == null) {
            removeElement(pH, elem);
        } else {
            elem.data = data;
            elem.pKey = pKey;
        }
        return old_data;
    }
    if (data == null) return null;
    const new_raw = sqlite3Malloc(@sizeOf(HashElem));
    if (new_raw == null) return data;
    const new_elem: *HashElem = @ptrCast(@alignCast(new_raw.?));
    new_elem.pKey = pKey;
    new_elem.h = h;
    new_elem.data = data;
    pH.count += 1;
    if (pH.count >= 5 and pH.count > 2 * pH.htsize) {
        _ = rehash(pH, pH.count * 3);
    }
    insertElement(pH, if (pH.ht) |ht| &ht[new_elem.h % pH.htsize] else null, new_elem);
    return null;
}
