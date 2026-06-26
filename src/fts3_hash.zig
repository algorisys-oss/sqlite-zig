//! Zig port of FTS3's standalone hash table (src/fts3_hash.c).
//!
//! Drop-in replacement exporting `sqlite3Fts3HashInit`, `sqlite3Fts3HashInsert`,
//! `sqlite3Fts3HashFind`, `sqlite3Fts3HashClear`, `sqlite3Fts3HashFindElem`.
//! Like the core `hash.c`, the `Fts3Hash`/`Fts3HashElem`/`_fts3ht` structs are
//! ABI-shared (defined in fts3_hash.h, reached by callers via the
//! `fts3HashFirst/Next/Data/Key/Keysize/Count` macros), so they are mirrored as
//! `extern struct`. Supports STRING and BINARY key classes and an optional
//! private copy of each key. Config-invariant: only sqlite3_malloc64/free and
//! libc str/mem compare are used. Power-of-two bucket sizing.

const std = @import("std");

const FTS3_HASH_STRING: i8 = 1;
const FTS3_HASH_BINARY: i8 = 2;

// --- ABI-shared layouts (must match fts3_hash.h) ---

const Fts3HashElem = extern struct {
    next: ?*Fts3HashElem,
    prev: ?*Fts3HashElem,
    data: ?*anyopaque,
    pKey: ?*anyopaque,
    nKey: c_int,
};

/// `struct _fts3ht` — one hash bucket.
const Fts3ht = extern struct {
    count: c_int,
    chain: ?*Fts3HashElem,
};

const Fts3Hash = extern struct {
    keyClass: i8, // HASH_STRING or HASH_BINARY
    copyKey: i8, // true if a copy of the key is made on insert
    count: c_int,
    first: ?*Fts3HashElem,
    htsize: c_int,
    ht: ?[*]Fts3ht,
};

// --- C helpers resolved at link time ---
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn strlen(s: [*:0]const u8) usize;
extern fn strncmp(a: [*]const u8, b: [*]const u8, n: usize) c_int;
extern fn memcmp(a: [*]const u8, b: [*]const u8, n: usize) c_int;

/// Allocate n zeroed bytes (fts3HashMalloc).
fn fts3HashMalloc(n: u64) ?*anyopaque {
    const p = sqlite3_malloc64(n);
    if (p) |pp| {
        @memset(@as([*]u8, @ptrCast(pp))[0..@intCast(n)], 0);
    }
    return p;
}

inline fn fts3HashFree(p: ?*anyopaque) void {
    sqlite3_free(p);
}

/// A key byte's contribution to the hash, matching C's `char`->`int`->unsigned
/// promotion (sign-extended) so the hash sequence is byte-identical to the C.
inline fn signedByte(b: u8) c_uint {
    return @bitCast(@as(i32, @as(i8, @bitCast(b))));
}

fn fts3StrHash(pKey: ?*const anyopaque, nKey_in: c_int) c_int {
    const z: [*]const u8 = @ptrCast(pKey.?);
    var h: c_uint = 0;
    var nKey = nKey_in;
    if (nKey <= 0) nKey = @intCast(strlen(@ptrCast(z)));
    var i: usize = 0;
    while (nKey > 0) : (nKey -= 1) {
        h = (h *% 8) ^ h ^ signedByte(z[i]); // (h<<3) with wraparound
        i += 1;
    }
    return @intCast(h & 0x7fffffff);
}

fn fts3BinHash(pKey: ?*const anyopaque, nKey: c_int) c_int {
    const z: [*]const u8 = @ptrCast(pKey.?);
    var h: c_uint = 0;
    var n = nKey;
    var i: usize = 0;
    while (n > 0) : (n -= 1) {
        h = (h *% 8) ^ h ^ signedByte(z[i]); // (h<<3) with wraparound
        i += 1;
    }
    return @intCast(h & 0x7fffffff);
}

inline fn hashKey(keyClass: i8, pKey: ?*const anyopaque, nKey: c_int) c_int {
    return if (keyClass == FTS3_HASH_STRING) fts3StrHash(pKey, nKey) else fts3BinHash(pKey, nKey);
}

inline fn compareKey(keyClass: i8, k1: ?*const anyopaque, n1: c_int, k2: ?*const anyopaque, n2: c_int) c_int {
    if (n1 != n2) return 1;
    const a: [*]const u8 = @ptrCast(k1.?);
    const b: [*]const u8 = @ptrCast(k2.?);
    const n: usize = @intCast(n1);
    return if (keyClass == FTS3_HASH_STRING) strncmp(a, b, n) else memcmp(a, b, n);
}

/// Turn bulk memory into an empty hash table.
export fn sqlite3Fts3HashInit(pNew: *Fts3Hash, keyClass: i8, copyKey: i8) callconv(.c) void {
    pNew.keyClass = keyClass;
    pNew.copyKey = copyKey;
    pNew.first = null;
    pNew.count = 0;
    pNew.htsize = 0;
    pNew.ht = null;
}

/// Remove all entries and reclaim all memory.
export fn sqlite3Fts3HashClear(pH: *Fts3Hash) callconv(.c) void {
    var elem = pH.first;
    pH.first = null;
    fts3HashFree(@ptrCast(pH.ht));
    pH.ht = null;
    pH.htsize = 0;
    while (elem) |e| {
        const next_elem = e.next;
        if (pH.copyKey != 0 and e.pKey != null) {
            fts3HashFree(e.pKey);
        }
        fts3HashFree(e);
        elem = next_elem;
    }
    pH.count = 0;
}

/// Link pNew into bucket pEntry.
fn fts3HashInsertElement(pH: *Fts3Hash, pEntry: *Fts3ht, pNew: *Fts3HashElem) void {
    const pHead = pEntry.chain;
    if (pHead) |head| {
        pNew.next = head;
        pNew.prev = head.prev;
        if (head.prev) |pp| {
            pp.next = pNew;
        } else {
            pH.first = pNew;
        }
        head.prev = pNew;
    } else {
        pNew.next = pH.first;
        if (pH.first) |f| {
            f.prev = pNew;
        }
        pNew.prev = null;
        pH.first = pNew;
    }
    pEntry.count += 1;
    pEntry.chain = pNew;
}

/// Resize to new_size (a power of 2) buckets. Returns non-zero on OOM.
fn fts3Rehash(pH: *Fts3Hash, new_size: c_int) c_int {
    const new_ht_raw = fts3HashMalloc(@as(u64, @intCast(new_size)) * @sizeOf(Fts3ht));
    const new_ht: [*]Fts3ht = @ptrCast(@alignCast(new_ht_raw orelse return 1));
    fts3HashFree(@ptrCast(pH.ht));
    pH.ht = new_ht;
    pH.htsize = new_size;
    var elem = pH.first;
    pH.first = null;
    while (elem) |e| {
        const h: usize = @intCast(hashKey(pH.keyClass, e.pKey, e.nKey) & (new_size - 1));
        const next_elem = e.next;
        fts3HashInsertElement(pH, &new_ht[h], e);
        elem = next_elem;
    }
    return 0;
}

/// Locate the element matching pKey,nKey whose bucket index is h, or null.
fn fts3FindElementByHash(pH: *const Fts3Hash, pKey: ?*const anyopaque, nKey: c_int, h: c_int) ?*Fts3HashElem {
    if (pH.ht) |ht| {
        const pEntry = &ht[@intCast(h)];
        var elem = pEntry.chain;
        var count = pEntry.count;
        while (count > 0 and elem != null) {
            count -= 1;
            const e = elem.?;
            if (compareKey(pH.keyClass, e.pKey, e.nKey, pKey, nKey) == 0) {
                return e;
            }
            elem = e.next;
        }
    }
    return null;
}

/// Remove and free an element given its bucket index h.
fn fts3RemoveElementByHash(pH: *Fts3Hash, elem: *Fts3HashElem, h: c_int) void {
    if (elem.prev) |p| {
        p.next = elem.next;
    } else {
        pH.first = elem.next;
    }
    if (elem.next) |n| {
        n.prev = elem.prev;
    }
    const pEntry = &pH.ht.?[@intCast(h)];
    if (pEntry.chain == elem) {
        pEntry.chain = elem.next;
    }
    pEntry.count -= 1;
    if (pEntry.count <= 0) {
        pEntry.chain = null;
    }
    if (pH.copyKey != 0 and elem.pKey != null) {
        fts3HashFree(elem.pKey);
    }
    fts3HashFree(elem);
    pH.count -= 1;
    if (pH.count <= 0) {
        sqlite3Fts3HashClear(pH);
    }
}

/// Locate the element matching pKey,nKey, or null.
export fn sqlite3Fts3HashFindElem(pH: ?*const Fts3Hash, pKey: ?*const anyopaque, nKey: c_int) callconv(.c) ?*Fts3HashElem {
    const h = pH orelse return null;
    if (h.ht == null) return null;
    const hraw = hashKey(h.keyClass, pKey, nKey);
    return fts3FindElementByHash(h, pKey, nKey, hraw & (h.htsize - 1));
}

/// Return the data for the element matching pKey,nKey, or null.
export fn sqlite3Fts3HashFind(pH: *const Fts3Hash, pKey: ?*const anyopaque, nKey: c_int) callconv(.c) ?*anyopaque {
    const pElem = sqlite3Fts3HashFindElem(pH, pKey, nKey);
    return if (pElem) |e| e.data else null;
}

/// Insert (data==null removes; existing key replaces and returns old data; new
/// key returns null; OOM leaves the table unchanged and returns `data`).
export fn sqlite3Fts3HashInsert(pH: *Fts3Hash, pKey: ?*const anyopaque, nKey: c_int, data: ?*anyopaque) callconv(.c) ?*anyopaque {
    const hraw = hashKey(pH.keyClass, pKey, nKey);
    var h = hraw & (pH.htsize - 1);
    if (fts3FindElementByHash(pH, pKey, nKey, h)) |elem| {
        const old_data = elem.data;
        if (data == null) {
            fts3RemoveElementByHash(pH, elem, h);
        } else {
            elem.data = data;
        }
        return old_data;
    }
    if (data == null) return null;
    if ((pH.htsize == 0 and fts3Rehash(pH, 8) != 0) or
        (pH.count >= pH.htsize and fts3Rehash(pH, pH.htsize * 2) != 0))
    {
        pH.count = 0;
        return data;
    }
    const new_elem: *Fts3HashElem = @ptrCast(@alignCast(fts3HashMalloc(@sizeOf(Fts3HashElem)) orelse return data));
    if (pH.copyKey != 0 and pKey != null) {
        const keyCopy = fts3HashMalloc(@intCast(nKey)) orelse {
            fts3HashFree(new_elem);
            return data;
        };
        @memcpy(@as([*]u8, @ptrCast(keyCopy))[0..@intCast(nKey)], @as([*]const u8, @ptrCast(pKey.?))[0..@intCast(nKey)]);
        new_elem.pKey = keyCopy;
    } else {
        new_elem.pKey = @constCast(pKey);
    }
    new_elem.nKey = nKey;
    pH.count += 1;
    h = hraw & (pH.htsize - 1);
    fts3HashInsertElement(pH, &pH.ht.?[@intCast(h)], new_elem);
    new_elem.data = data;
    return null;
}
