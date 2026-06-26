//! Zig port of SQLite's online backup API (src/backup.c).
//!
//! Drop-in replacement exporting every external-linkage symbol backup.c defines:
//!   Public API:
//!     - sqlite3_backup_init
//!     - sqlite3_backup_step
//!     - sqlite3_backup_finish
//!     - sqlite3_backup_remaining
//!     - sqlite3_backup_pagecount
//!   Internal-ABI hooks called from the still-C pager (pager.c) on the source
//!   page cache (mutex held by the caller):
//!     - sqlite3BackupUpdate   (page-modified callback)
//!     - sqlite3BackupRestart  (cache-invalidated callback)
//!   Internal-ABI vacuum helper (SQLITE_OMIT_VACUUM is OFF in both configs):
//!     - sqlite3BtreeCopyFile
//!
//! The `sqlite3_backup` struct is PRIVATE to this module (callers hold an opaque
//! pointer / use it only via the entry points above), so we own its layout. We
//! mirror upstream's field order exactly because sqlite3BtreeCopyFile builds one
//! on the stack and zeroes it with memset, and because the allocation in
//! sqlite3_backup_init() stashes the destination db name in the trailing bytes
//! (`p->zDestDb = (char*)&p[1]`).
//!
//! Internal struct fields read at ground-truth offsets (NOT mirrored as structs):
//!   - sqlite3.mutex                 -> L.sqlite3_mutex
//!   - sqlite3.mallocFailed          -> (via sqlite3MallocZero/Error returning 0)
//!   - Parse.rc / Parse.zErrMsg      -> L.Parse_rc / L.Parse_zErrMsg (in findBtree)
//!   - Db.pBt (aDb[i].pBt)           -> L.Db_pBt, stride L.sizeof_Db
//!   - sqlite3.aDb                   -> L.sqlite3_aDb
//!   - Btree.pBt / Btree.nBackup / Btree.db  -> probe fallbacks (config-invariant)
//!   - BtShared.inTransaction / btsFlags / pageSize / mutex -> probe fallbacks
//!   - sqlite3_file.pMethods         -> offset 0
//! Everything else goes through C-ABI helpers resolved at link time (btree/pager/
//! os wrappers, mutex, malloc, error helpers).
//!
//! Config divergence: every field offset used here is identical in the production
//! and --dev (SQLITE_DEBUG/TEST) builds. `sizeof(Btree)` and `sizeof(BtShared)`
//! diverge (trailing debug fields), but we never allocate or stride over them; we
//! only chase pointers and read leading fields. SQLITE_ENABLE_API_ARMOR is OFF in
//! both configs, so the p==0 / safety guards in init/step/remaining/pagecount are
//! absent (matching the active C path).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// --- SQLite result codes (sqlite.h.in) ---
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_BUSY: c_int = 5;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT collapses to this in production
const SQLITE_READONLY: c_int = 8;
const SQLITE_NOTFOUND: c_int = 12;
const SQLITE_DONE: c_int = 101;
const SQLITE_IOERR_NOMEM: c_int = 10 | (12 << 8); // 3082

// Transaction states (sqlite.h.in / btreeInt.h: TRANS_* match SQLITE_TXN_*).
const SQLITE_TXN_NONE: c_int = 0;
const TRANS_WRITE: u8 = 2;

// Journal modes (pager.h).
const PAGER_JOURNALMODE_WAL: c_int = 5;

// sqlite3PagerGet() flags (pager.h).
const PAGER_GET_READONLY: c_int = 0x02;

// File control opcode (sqlite.h.in).
const SQLITE_FCNTL_OVERWRITE: c_int = 11;

// btreeInt.h: BTS_PAGESIZE_FIXED.
const BTS_PAGESIZE_FIXED: u16 = 0x0002;

// --- Btree / BtShared field offsets (config-invariant; not in c_layout) ---
// Probed in both prod and --dev configs: identical. Only sizeof(Btree)/sizeof
// (BtShared) diverge (trailing SQLITE_DEBUG fields), which we never stride over.
const Btree_db: usize = if (@hasDecl(L, "Btree_db")) L.Btree_db else 0;
const Btree_pBt: usize = if (@hasDecl(L, "Btree_pBt")) L.Btree_pBt else 8;
const Btree_nBackup: usize = if (@hasDecl(L, "Btree_nBackup")) L.Btree_nBackup else 24;
const BtShared_inTransaction: usize = if (@hasDecl(L, "BtShared_inTransaction")) L.BtShared_inTransaction else 36;
const BtShared_btsFlags: usize = if (@hasDecl(L, "BtShared_btsFlags")) L.BtShared_btsFlags else 40;
const BtShared_pageSize: usize = if (@hasDecl(L, "BtShared_pageSize")) L.BtShared_pageSize else 52;

// PENDING_BYTE: SQLITE_OMIT_WSD is OFF in both configs, so it is the mutable
// global `sqlite3PendingByte`. extern var (mutable) — main.c can change it.
extern var sqlite3PendingByte: c_int;
inline fn pendingByte() i64 {
    return @as(i64, sqlite3PendingByte);
}
/// PENDING_BYTE_PAGE(pBt) = (Pgno)((PENDING_BYTE/pBt->pageSize)+1)
inline fn pendingBytePage(pBt: ?*anyopaque) u32 {
    const ps = btSharedPageSize(pBt);
    return @as(u32, @intCast(@divTrunc(pendingByte(), @as(i64, ps)))) +% 1;
}

// --- The private sqlite3_backup object. We own this layout. ---
const Backup = extern struct {
    pDestDb: ?*anyopaque, // Destination database handle (sqlite3*)
    zDestDb: ?[*:0]u8, // Name of database within pDestDb (points into tail)
    pDest: ?*anyopaque, // Destination b-tree file (Btree*)
    iDestSchema: u32, // Original schema cookie in destination
    bDestLocked: c_int, // True once a write-transaction is open on pDest

    iNext: u32, // Page number (Pgno) of the next source page to copy
    pSrcDb: ?*anyopaque, // Source database handle (sqlite3*)
    pSrc: ?*anyopaque, // Source b-tree file (Btree*)

    rc: c_int, // Backup process error code

    // Set by every backup_step(); read by backup_remaining()/pagecount().
    nRemaining: u32, // Number of pages left to copy (Pgno)
    nPagecount: u32, // Total number of pages to copy (Pgno)

    isAttached: c_int, // True once backup has been registered with pager
    pNext: ?*Backup, // Next backup associated with source pager
};

// --- C-ABI helpers resolved at link time ---
// btree.h
extern fn sqlite3BtreeSetPageSize(p: ?*anyopaque, nPagesize: c_int, nReserve: c_int, eFix: c_int) c_int;
extern fn sqlite3BtreeGetPageSize(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeLastPage(p: ?*anyopaque) u32;
extern fn sqlite3BtreeGetReserveNoMutex(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeBeginTrans(p: ?*anyopaque, n: c_int, pSchemaVersion: ?*c_int) c_int;
extern fn sqlite3BtreeCommitPhaseOne(p: ?*anyopaque, zSuper: ?[*:0]const u8) c_int;
extern fn sqlite3BtreeCommitPhaseTwo(p: ?*anyopaque, bCleanup: c_int) c_int;
extern fn sqlite3BtreeRollback(p: ?*anyopaque, tripCode: c_int, writeOnly: c_int) c_int;
extern fn sqlite3BtreeTxnState(p: ?*anyopaque) c_int;
extern fn sqlite3BtreeUpdateMeta(p: ?*anyopaque, idx: c_int, value: u32) c_int;
extern fn sqlite3BtreeNewDb(p: ?*anyopaque) c_int;
extern fn sqlite3BtreePager(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3BtreeSetVersion(pBt: ?*anyopaque, iVersion: c_int) c_int;
extern fn sqlite3BtreeEnter(p: ?*anyopaque) void;
extern fn sqlite3BtreeLeave(p: ?*anyopaque) void;
// pager.h
extern fn sqlite3PagerGetJournalMode(p: ?*anyopaque) c_int;
extern fn sqlite3PagerBackupPtr(p: ?*anyopaque) *?*Backup;
extern fn sqlite3PagerGet(pPager: ?*anyopaque, pgno: u32, ppPage: *?*anyopaque, clrFlag: c_int) c_int;
extern fn sqlite3PagerUnref(p: ?*anyopaque) void;
extern fn sqlite3PagerWrite(p: ?*anyopaque) c_int;
extern fn sqlite3PagerGetData(p: ?*anyopaque) ?[*]u8;
extern fn sqlite3PagerGetExtra(p: ?*anyopaque) ?[*]u8;
extern fn sqlite3PagerPagecount(p: ?*anyopaque, pn: *c_int) void;
extern fn sqlite3PagerCommitPhaseOne(p: ?*anyopaque, zSuper: ?[*:0]const u8, noSync: c_int) c_int;
extern fn sqlite3PagerSync(pPager: ?*anyopaque, zSuper: ?[*:0]const u8) c_int;
extern fn sqlite3PagerFile(p: ?*anyopaque) ?*anyopaque;
extern fn sqlite3PagerIsMemdb(p: ?*anyopaque) c_int;
extern fn sqlite3PagerClearCache(p: ?*anyopaque) void;
extern fn sqlite3PagerTruncateImage(p: ?*anyopaque, nPage: u32) void;
// os.h
extern fn sqlite3OsFileSize(p: ?*anyopaque, pSize: *i64) c_int;
extern fn sqlite3OsTruncate(p: ?*anyopaque, size: i64) c_int;
extern fn sqlite3OsWrite(p: ?*anyopaque, z: ?*const anyopaque, amt: c_int, offset: i64) c_int;
extern fn sqlite3OsFileControl(p: ?*anyopaque, op: c_int, pArg: ?*anyopaque) c_int;
// sqliteInt.h (misc helpers)
extern fn sqlite3FindDbName(db: ?*anyopaque, zDb: ?[*:0]const u8) c_int;
extern fn sqlite3ParseObjectInit(p: ?*anyopaque, db: ?*anyopaque) void;
extern fn sqlite3ParseObjectReset(p: ?*anyopaque) void;
extern fn sqlite3OpenTempDatabase(p: ?*anyopaque) c_int;
extern fn sqlite3ErrorWithMsg(db: ?*anyopaque, err: c_int, zFormat: ?[*:0]const u8, ...) void;
extern fn sqlite3Error(db: ?*anyopaque, err: c_int) void;
extern fn sqlite3DbFree(db: ?*anyopaque, p: ?*anyopaque) void;
extern fn sqlite3Strlen30(z: ?[*:0]const u8) c_int;
extern fn sqlite3MallocZero(n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3ResetAllSchemasOfConnection(db: ?*anyopaque) void;
extern fn sqlite3LeaveMutexAndCloseZombie(db: ?*anyopaque) void;
extern fn sqlite3Put4byte(p: ?[*]u8, v: u32) void;
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;

// --- field-offset readers (chase pointers, read leading fields) ---
inline fn fieldPtr(comptime T: type, base: ?*anyopaque, off: usize) *align(1) T {
    const b: [*]u8 = @ptrCast(base.?);
    return @ptrCast(b + off);
}
inline fn dbMutex(db: ?*anyopaque) ?*anyopaque {
    return fieldPtr(?*anyopaque, db, L.sqlite3_mutex).*;
}
/// db->aDb[i].pBt  (aDb is a Db* array; Db.pBt at L.Db_pBt, stride L.sizeof_Db).
inline fn dbADbPBt(db: ?*anyopaque, i: c_int) ?*anyopaque {
    const aDb = fieldPtr(?*anyopaque, db, L.sqlite3_aDb).*;
    const base: [*]u8 = @ptrCast(aDb.?);
    const slot = base + @as(usize, @intCast(i)) * L.sizeof_Db + L.Db_pBt;
    const p: *align(1) ?*anyopaque = @ptrCast(slot);
    return p.*;
}
/// Btree->pBt
inline fn btPBt(pBtree: ?*anyopaque) ?*anyopaque {
    return fieldPtr(?*anyopaque, pBtree, Btree_pBt).*;
}
/// Btree->db
inline fn btDb(pBtree: ?*anyopaque) ?*anyopaque {
    return fieldPtr(?*anyopaque, pBtree, Btree_db).*;
}
/// &Btree->nBackup
inline fn btNBackupPtr(pBtree: ?*anyopaque) *align(1) c_int {
    return fieldPtr(c_int, pBtree, Btree_nBackup);
}
/// BtShared->inTransaction (u8)
inline fn btSharedInTransaction(pBt: ?*anyopaque) u8 {
    return fieldPtr(u8, pBt, BtShared_inTransaction).*;
}
/// &BtShared->btsFlags (u16)
inline fn btSharedBtsFlagsPtr(pBt: ?*anyopaque) *align(1) u16 {
    return fieldPtr(u16, pBt, BtShared_btsFlags);
}
/// BtShared->pageSize (u32)
inline fn btSharedPageSize(pBt: ?*anyopaque) u32 {
    return fieldPtr(u32, pBt, BtShared_pageSize).*;
}
/// sqlite3_file->pMethods (offset 0)
inline fn fileMethods(pFile: ?*anyopaque) ?*anyopaque {
    return fieldPtr(?*anyopaque, pFile, 0).*;
}
// Parse.rc / Parse.zErrMsg
inline fn parseRc(p: [*]u8) c_int {
    const q: *align(1) c_int = @ptrCast(p + L.Parse_rc);
    return q.*;
}
inline fn parseZErrMsg(p: [*]u8) ?[*:0]const u8 {
    const q: *align(1) ?[*:0]const u8 = @ptrCast(p + L.Parse_zErrMsg);
    return q.*;
}

inline fn min_int(a: c_int, b: c_int) c_int {
    return if (a < b) a else b;
}

// ============================================================================

/// Return a pointer corresponding to database zDb (i.e. "main", "temp") in
/// connection handle pDb. If such a database cannot be found, return NULL and
/// write an error message to pErrorDb.
fn findBtree(pErrorDb: ?*anyopaque, pDb: ?*anyopaque, zDb: ?[*:0]const u8) ?*anyopaque {
    const i = sqlite3FindDbName(pDb, zDb);

    if (i == 1) {
        // Parse sParse on the stack: allocate a buffer of sizeof(Parse) bytes,
        // aligned for any field, and use it via the C parse helpers.
        var sParse: [L.sizeof_Parse]u8 align(16) = undefined;
        const pParse: *anyopaque = @ptrCast(&sParse);
        var rc: c_int = 0;
        sqlite3ParseObjectInit(pParse, pDb);
        if (sqlite3OpenTempDatabase(pParse) != 0) {
            sqlite3ErrorWithMsg(pErrorDb, parseRc(&sParse), "%s", parseZErrMsg(&sParse));
            rc = SQLITE_ERROR;
        }
        sqlite3DbFree(pErrorDb, @ptrCast(@constCast(parseZErrMsg(&sParse))));
        sqlite3ParseObjectReset(pParse);
        if (rc != 0) {
            return null;
        }
    }

    if (i < 0) {
        sqlite3ErrorWithMsg(pErrorDb, SQLITE_ERROR, "unknown database %s", zDb);
        return null;
    }

    return dbADbPBt(pDb, i);
}

/// Attempt to set the page size of the destination to match that of the source.
fn setDestPgsz(pDest: ?*anyopaque, pSrc: ?*anyopaque) c_int {
    return sqlite3BtreeSetPageSize(pDest, sqlite3BtreeGetPageSize(pSrc), 0, 0);
}

/// Check that there is no open read-transaction on b-tree p. SQLITE_OK if none,
/// else SQLITE_ERROR with an error message in db.
fn checkReadTransaction(db: ?*anyopaque, p: ?*anyopaque) c_int {
    if (sqlite3BtreeTxnState(p) != SQLITE_TXN_NONE) {
        sqlite3ErrorWithMsg(db, SQLITE_ERROR, "destination database is in use");
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

/// Create an sqlite3_backup process copying zSrcDb from pSrcDb to zDestDb in
/// pDestDb. Returns a pointer to the new object, or NULL on error (with code +
/// message stored in pDestDb).
export fn sqlite3_backup_init(
    pDestDb: ?*anyopaque, // Database to write to
    zDestDb: ?[*:0]const u8, // Name of database within pDestDb
    pSrcDb: ?*anyopaque, // Database connection to read from
    zSrcDb: ?[*:0]const u8, // Name of database within pSrcDb
) callconv(.c) ?*Backup {
    var p: ?*Backup = null;

    // (SQLITE_ENABLE_API_ARMOR off: no safety check here.)

    // Lock the source database handle; then the destination. The destination is
    // not held for the whole backup — the user must keep other threads off it.
    sqlite3_mutex_enter(dbMutex(pSrcDb));
    sqlite3_mutex_enter(dbMutex(pDestDb));

    if (pSrcDb == pDestDb) {
        sqlite3ErrorWithMsg(pDestDb, SQLITE_ERROR, "source and destination must be distinct");
        p = null;
    } else {
        const nDest = sqlite3Strlen30(zDestDb);
        // Allocate the object plus nDest+1 trailing bytes for the db name.
        const raw = sqlite3MallocZero(@sizeOf(Backup) + @as(u64, @intCast(nDest)) + 1);
        if (raw == null) {
            sqlite3Error(pDestDb, SQLITE_NOMEM); // SQLITE_NOMEM_BKPT
            p = null;
        } else {
            p = @ptrCast(@alignCast(raw));
            const tail: [*]u8 = @as([*]u8, @ptrCast(p.?)) + @sizeOf(Backup);
            p.?.zDestDb = @ptrCast(tail);
            if (nDest > 0) {
                const src: [*]const u8 = @ptrCast(zDestDb.?);
                @memcpy(tail[0..@intCast(nDest)], src[0..@intCast(nDest)]);
            }
        }
    }

    if (p) |pp| {
        // Do not store pDest yet — nothing prevents it being detached/freed
        // before the first backup_step(). The source is pinned via nBackup++.
        const pDest = findBtree(pDestDb, pDestDb, zDestDb);
        pp.pSrc = findBtree(pDestDb, pSrcDb, zSrcDb);
        pp.pDestDb = pDestDb;
        pp.pSrcDb = pSrcDb;
        pp.iNext = 1;
        pp.isAttached = 0;

        if (pp.pSrc == null or pDest == null or
            checkReadTransaction(pDestDb, pDest) != SQLITE_OK)
        {
            sqlite3_free(@ptrCast(pp));
            p = null;
        }
    }
    if (p) |pp| {
        btNBackupPtr(pp.pSrc).* +%= 1;
    }

    sqlite3_mutex_leave(dbMutex(pDestDb));
    sqlite3_mutex_leave(dbMutex(pSrcDb));
    return p;
}

/// Return true if rc is fatal during a backup. All errors are fatal except
/// SQLITE_BUSY and SQLITE_LOCKED.
fn isFatalError(rc: c_int) bool {
    return rc != SQLITE_OK and rc != SQLITE_BUSY and rc != SQLITE_LOCKED;
}

/// Copy page iSrcPg's data (zSrcData) from the source DB into the destination.
fn backupOnePage(p: *Backup, iSrcPg: u32, zSrcData: [*]const u8, bUpdate: c_int) c_int {
    const pDestPager = sqlite3BtreePager(p.pDest);
    const nSrcPgsz: i64 = sqlite3BtreeGetPageSize(p.pSrc);
    const nDestPgsz: i64 = sqlite3BtreeGetPageSize(p.pDest);
    const nCopy: usize = @intCast(min_int(@intCast(nSrcPgsz), @intCast(nDestPgsz)));
    const iEnd: i64 = @as(i64, iSrcPg) * nSrcPgsz;
    var rc: c_int = SQLITE_OK;

    // assert( bDestLocked && !isFatalError(rc) && zSrcData )

    // One iteration per destination page spanned by the source page. iOff is the
    // byte offset of the destination page.
    var iOff: i64 = iEnd - nSrcPgsz;
    while (rc == SQLITE_OK and iOff < iEnd) : (iOff += nDestPgsz) {
        var pDestPg: ?*anyopaque = null;
        const iDest: u32 = @as(u32, @intCast(@divTrunc(iOff, nDestPgsz))) +% 1;
        if (iDest == pendingBytePage(btPBt(p.pDest))) continue;
        rc = sqlite3PagerGet(pDestPager, iDest, &pDestPg, 0);
        if (rc == SQLITE_OK) {
            rc = sqlite3PagerWrite(pDestPg);
            if (rc == SQLITE_OK) {
                const zIn: [*]const u8 = zSrcData + @as(usize, @intCast(@mod(iOff, nSrcPgsz)));
                const zDestData = sqlite3PagerGetData(pDestPg).?;
                const zOut: [*]u8 = zDestData + @as(usize, @intCast(@mod(iOff, nDestPgsz)));

                // Copy source -> dest, then clear the first byte of the dest
                // page 'extra' space to invalidate the Btree layer's cached
                // parse (MemPage.isInit, "MUST BE FIRST").
                @memcpy(zOut[0..nCopy], zIn[0..nCopy]);
                sqlite3PagerGetExtra(pDestPg).?[0] = 0;
                if (iOff == 0 and bUpdate == 0) {
                    sqlite3Put4byte(zOut + 28, sqlite3BtreeLastPage(p.pSrc));
                }
            }
        }
        sqlite3PagerUnref(pDestPg);
    }

    return rc;
}

/// If pFile is larger than iSize bytes, truncate it to exactly iSize. No-op
/// otherwise.
fn backupTruncateFile(pFile: ?*anyopaque, iSize: i64) c_int {
    var iCurrent: i64 = undefined;
    var rc = sqlite3OsFileSize(pFile, &iCurrent);
    if (rc == SQLITE_OK and iCurrent > iSize) {
        rc = sqlite3OsTruncate(pFile, iSize);
    }
    return rc;
}

/// Register this backup with the source pager for change/invalidate callbacks.
fn attachBackupObject(p: *Backup) void {
    const pp = sqlite3PagerBackupPtr(sqlite3BtreePager(p.pSrc));
    p.pNext = pp.*;
    pp.* = p;
    p.isAttached = 1;
}

/// Copy nPage pages from the source b-tree to the destination.
export fn sqlite3_backup_step(p: *Backup, nPage: c_int) callconv(.c) c_int {
    var rc: c_int = undefined;
    var destMode: c_int = 0; // Destination journal mode
    var pgszSrc: c_int = 0; // Source page size
    var pgszDest: c_int = 0; // Destination page size

    // (SQLITE_ENABLE_API_ARMOR off: no p==0 check.)
    sqlite3_mutex_enter(dbMutex(p.pSrcDb));
    sqlite3BtreeEnter(p.pSrc);
    if (p.pDestDb != null) {
        sqlite3_mutex_enter(dbMutex(p.pDestDb));
    }

    rc = p.rc;
    if (!isFatalError(rc)) {
        const pSrcPager = sqlite3BtreePager(p.pSrc); // Source pager
        var pDest: ?*anyopaque = null; // Dest btree
        var pDestPager: ?*anyopaque = null; // Dest pager
        var nSrcPage: c_int = -1; // Size of source db in pages
        var bCloseTrans: c_int = 0; // True if src db requires unlocking

        // If the source pager is in a write-transaction, SQLITE_BUSY at once.
        if (p.pDestDb != null and btSharedInTransaction(btPBt(p.pSrc)) == TRANS_WRITE) {
            rc = SQLITE_BUSY;
        } else {
            rc = SQLITE_OK;
        }

        // Open a read-transaction on the source if none is open; close it before
        // returning if we opened it here.
        if (rc == SQLITE_OK and SQLITE_TXN_NONE == sqlite3BtreeTxnState(p.pSrc)) {
            rc = sqlite3BtreeBeginTrans(p.pSrc, 0, null);
            bCloseTrans = 1;
        }

        // Locate the destination btree and pager.
        pDest = p.pDest;
        if (pDest == null) {
            pDest = findBtree(p.pDestDb, p.pDestDb, p.zDestDb);
        }
        if (pDest == null) {
            rc = SQLITE_ERROR;
        } else {
            pDestPager = sqlite3BtreePager(pDest);
        }

        // First call: try to set the destination page size to match the source.
        if (p.bDestLocked == 0 and rc == SQLITE_OK and
            setDestPgsz(pDest, p.pSrc) == SQLITE_NOMEM)
        {
            rc = SQLITE_NOMEM;
        }

        // Lock the destination database if not already locked.
        if (SQLITE_OK == rc and p.bDestLocked == 0) {
            rc = sqlite3BtreeBeginTrans(pDest, 2, @ptrCast(&p.iDestSchema));
            if (rc == SQLITE_OK) {
                p.bDestLocked = 1;
                p.pDest = pDest;
            }
        }

        // Disallow backup if dest is in WAL mode and page sizes differ.
        if (rc == SQLITE_OK) {
            pgszSrc = sqlite3BtreeGetPageSize(p.pSrc);
            pgszDest = sqlite3BtreeGetPageSize(p.pDest);
            destMode = sqlite3PagerGetJournalMode(sqlite3BtreePager(p.pDest));
            if ((destMode == PAGER_JOURNALMODE_WAL or sqlite3PagerIsMemdb(pDestPager) != 0) and
                pgszSrc != pgszDest)
            {
                rc = SQLITE_READONLY;
            }
        }

        // Now we hold a read-lock on the source: query its page count.
        nSrcPage = @intCast(sqlite3BtreeLastPage(p.pSrc));
        // assert( nSrcPage>=0 )
        var ii: c_int = 0;
        while ((nPage < 0 or ii < nPage) and p.iNext <= @as(u32, @intCast(nSrcPage)) and rc == 0) : (ii += 1) {
            const iSrcPg = p.iNext; // Source page number
            if (iSrcPg != pendingBytePage(btPBt(p.pSrc))) {
                var pSrcPg: ?*anyopaque = null; // Source page object
                rc = sqlite3PagerGet(pSrcPager, iSrcPg, &pSrcPg, PAGER_GET_READONLY);
                if (rc == SQLITE_OK) {
                    rc = backupOnePage(p, iSrcPg, sqlite3PagerGetData(pSrcPg).?, 0);
                    sqlite3PagerUnref(pSrcPg);
                }
            }
            p.iNext +%= 1;
        }
        if (rc == SQLITE_OK) {
            p.nPagecount = @intCast(nSrcPage);
            p.nRemaining = @as(u32, @intCast(nSrcPage)) +% 1 -% p.iNext;
            if (p.iNext > @as(u32, @intCast(nSrcPage))) {
                rc = SQLITE_DONE;
            } else if (p.isAttached == 0) {
                attachBackupObject(p);
            }
        }

        // Update the schema version in the destination so it really changes even
        // when source and destination share the same schema version.
        if (rc == SQLITE_DONE) {
            if (nSrcPage == 0) {
                rc = sqlite3BtreeNewDb(p.pDest);
                nSrcPage = 1;
            }
            if (rc == SQLITE_OK or rc == SQLITE_DONE) {
                rc = sqlite3BtreeUpdateMeta(p.pDest, 1, p.iDestSchema +% 1);
            }
            if (rc == SQLITE_OK) {
                if (p.pDestDb != null) {
                    sqlite3ResetAllSchemasOfConnection(p.pDestDb);
                }
                if (destMode == PAGER_JOURNALMODE_WAL) {
                    rc = sqlite3BtreeSetVersion(p.pDest, 2);
                }
            }
            if (rc == SQLITE_OK) {
                var nDestTruncate: c_int = undefined;
                // Final number of pages in the destination. Page sizes may differ.
                // assert pgszSrc/pgszDest unchanged.
                if (pgszSrc < pgszDest) {
                    const ratio = @divTrunc(pgszDest, pgszSrc);
                    nDestTruncate = @divTrunc(nSrcPage + ratio - 1, ratio);
                    if (nDestTruncate == @as(c_int, @intCast(pendingBytePage(btPBt(p.pDest))))) {
                        nDestTruncate -= 1;
                    }
                } else {
                    nDestTruncate = nSrcPage * @divTrunc(pgszSrc, pgszDest);
                }
                // assert( nDestTruncate>0 )

                if (pgszSrc < pgszDest) {
                    // Source page-size smaller than destination: the destination
                    // may need truncating, and data on pages right after the
                    // pending-byte page in the source may need copying.
                    const iSize: i64 = @as(i64, pgszSrc) * @as(i64, nSrcPage);
                    const pFile = sqlite3PagerFile(pDestPager);
                    var nDstPage: c_int = undefined;

                    // Ensure all data needed to recreate the original db is in the
                    // dest journal and synced, so the db file may be modified safely.
                    sqlite3PagerPagecount(pDestPager, &nDstPage);
                    var iPg: u32 = @intCast(nDestTruncate);
                    while (rc == SQLITE_OK and iPg <= @as(u32, @intCast(nDstPage))) : (iPg += 1) {
                        if (iPg != pendingBytePage(btPBt(p.pDest))) {
                            var pPg: ?*anyopaque = null;
                            rc = sqlite3PagerGet(pDestPager, iPg, &pPg, 0);
                            if (rc == SQLITE_OK) {
                                rc = sqlite3PagerWrite(pPg);
                                sqlite3PagerUnref(pPg);
                            }
                        }
                    }
                    if (rc == SQLITE_OK) {
                        rc = sqlite3PagerCommitPhaseOne(pDestPager, null, 1);
                    }

                    // Write the extra pages and truncate the db file as required.
                    const iEnd: i64 = @min(pendingByte() + @as(i64, pgszDest), iSize);
                    var iOff: i64 = pendingByte() + @as(i64, pgszSrc);
                    while (rc == SQLITE_OK and iOff < iEnd) : (iOff += @as(i64, pgszSrc)) {
                        var pSrcPg: ?*anyopaque = null;
                        const iSrcPg: u32 = @as(u32, @intCast(@divTrunc(iOff, @as(i64, pgszSrc)))) +% 1;
                        rc = sqlite3PagerGet(pSrcPager, iSrcPg, &pSrcPg, 0);
                        if (rc == SQLITE_OK) {
                            const zData = sqlite3PagerGetData(pSrcPg).?;
                            rc = sqlite3OsWrite(pFile, zData, pgszSrc, iOff);
                        }
                        sqlite3PagerUnref(pSrcPg);
                    }
                    if (rc == SQLITE_OK) {
                        rc = backupTruncateFile(pFile, iSize);
                    }

                    // Sync the database file to disk.
                    if (rc == SQLITE_OK) {
                        rc = sqlite3PagerSync(pDestPager, null);
                    }
                } else {
                    sqlite3PagerTruncateImage(pDestPager, @intCast(nDestTruncate));
                    rc = sqlite3PagerCommitPhaseOne(pDestPager, null, 0);
                }

                // Finish committing the transaction to the destination database.
                if (SQLITE_OK == rc) {
                    rc = sqlite3BtreeCommitPhaseTwo(p.pDest, 0);
                    if (rc == SQLITE_OK) {
                        rc = SQLITE_DONE;
                    }
                }
            }
        }

        // If we opened the source read-transaction, close it now. Committing a
        // read-only transaction cannot fail.
        if (bCloseTrans != 0) {
            _ = sqlite3BtreeCommitPhaseOne(p.pSrc, null);
            _ = sqlite3BtreeCommitPhaseTwo(p.pSrc, 0);
        }

        if (rc == SQLITE_IOERR_NOMEM) {
            rc = SQLITE_NOMEM; // SQLITE_NOMEM_BKPT
        }
        p.rc = rc;
    }
    if (p.pDestDb != null) {
        sqlite3_mutex_leave(dbMutex(p.pDestDb));
    }
    sqlite3BtreeLeave(p.pSrc);
    sqlite3_mutex_leave(dbMutex(p.pSrcDb));
    return rc;
}

/// Release all resources associated with an sqlite3_backup* handle.
export fn sqlite3_backup_finish(p: ?*Backup) callconv(.c) c_int {
    if (p == null) return SQLITE_OK;
    const pp_b = p.?;
    const pSrcDb = pp_b.pSrcDb; // Source database connection

    // Enter the mutexes.
    sqlite3_mutex_enter(dbMutex(pSrcDb));
    sqlite3BtreeEnter(pp_b.pSrc);
    if (pp_b.pDestDb != null) {
        sqlite3_mutex_enter(dbMutex(pp_b.pDestDb));
    }

    // Detach this backup from the source pager.
    if (pp_b.pDestDb != null) {
        btNBackupPtr(pp_b.pSrc).* -%= 1;
    }
    if (pp_b.isAttached != 0) {
        var pp = sqlite3PagerBackupPtr(sqlite3BtreePager(pp_b.pSrc));
        while (pp.* != p) {
            pp = &(pp.*.?.pNext);
        }
        pp.* = pp_b.pNext;
    }

    // If a transaction is still open on the Btree, roll it back.
    if (pp_b.pDest != null) {
        _ = sqlite3BtreeRollback(pp_b.pDest, SQLITE_OK, 0);
    }

    // Set the error code of the destination database handle.
    const rc: c_int = if (pp_b.rc == SQLITE_DONE) SQLITE_OK else pp_b.rc;
    if (pp_b.pDestDb != null) {
        sqlite3Error(pp_b.pDestDb, rc);
        // Exit the mutexes and free the backup context.
        sqlite3LeaveMutexAndCloseZombie(pp_b.pDestDb);
    }
    sqlite3BtreeLeave(pp_b.pSrc);
    if (pp_b.pDestDb != null) {
        sqlite3_free(@ptrCast(pp_b));
    }
    sqlite3LeaveMutexAndCloseZombie(pSrcDb);
    return rc;
}

/// Number of pages still to be backed up as of the most recent backup_step().
export fn sqlite3_backup_remaining(p: *Backup) callconv(.c) c_int {
    // (SQLITE_ENABLE_API_ARMOR off: no p==0 guard.)
    return @bitCast(p.nRemaining);
}

/// Total number of pages in the source database as of the most recent
/// backup_step().
export fn sqlite3_backup_pagecount(p: *Backup) callconv(.c) c_int {
    // (SQLITE_ENABLE_API_ARMOR off: no p==0 guard.)
    return @bitCast(p.nPagecount);
}

/// Called after page iPage of the source database has been modified. If iPage
/// has already been copied into the destination, that copy is now stale and must
/// be re-copied before the backup completes. The source BtShared mutex is held.
fn backupUpdate(pBackup: *Backup, iPage: u32, aData: [*]const u8) void {
    var p: ?*Backup = pBackup;
    while (p) |pp| {
        // assert( sqlite3_mutex_held(pp->pSrc->pBt->mutex) )
        if (!isFatalError(pp.rc) and iPage < pp.iNext) {
            // Backup pp already copied iPage but the source transaction just
            // modified it. Copy the new data into the backup.
            // assert( pp->pDestDb )
            sqlite3_mutex_enter(dbMutex(pp.pDestDb));
            const rc = backupOnePage(pp, iPage, aData, 1);
            sqlite3_mutex_leave(dbMutex(pp.pDestDb));
            // assert( rc!=SQLITE_BUSY && rc!=SQLITE_LOCKED )
            if (rc != SQLITE_OK) {
                pp.rc = rc;
            }
        }
        p = pp.pNext;
    }
}

export fn sqlite3BackupUpdate(pBackup: ?*Backup, iPage: u32, aData: ?[*]const u8) callconv(.c) void {
    if (pBackup) |b| backupUpdate(b, iPage, aData.?);
}

/// Restart the backup process. Called when the pager detects the database was
/// modified by an external connection: there is no way to know which copied
/// pages remain valid, so the whole process must restart. Source BtShared mutex
/// held.
export fn sqlite3BackupRestart(pBackup: ?*Backup) callconv(.c) void {
    var p: ?*Backup = pBackup;
    while (p) |pp| {
        // assert( sqlite3_mutex_held(pp->pSrc->pBt->mutex) )
        pp.iNext = 1;
        p = pp.pNext;
    }
}

/// Copy the complete content of pBtFrom into pBtTo. A transaction must be active
/// on both. (SQLITE_OMIT_VACUUM is OFF in both configs.)
export fn sqlite3BtreeCopyFile(pTo: ?*anyopaque, pFrom: ?*anyopaque) callconv(.c) c_int {
    var rc: c_int = undefined;
    var b: Backup = undefined; // The on-stack backup object
    sqlite3BtreeEnter(pTo);
    sqlite3BtreeEnter(pFrom);

    // assert( sqlite3BtreeTxnState(pTo)==SQLITE_TXN_WRITE )
    const pFd = sqlite3PagerFile(sqlite3BtreePager(pTo)); // File descriptor for pTo
    if (fileMethods(pFd) != null) {
        var nByte: i64 = @as(i64, sqlite3BtreeGetPageSize(pFrom)) * @as(i64, sqlite3BtreeLastPage(pFrom));
        rc = sqlite3OsFileControl(pFd, SQLITE_FCNTL_OVERWRITE, &nByte);
        if (rc == SQLITE_NOTFOUND) rc = SQLITE_OK;
        if (rc != 0) {
            sqlite3BtreeLeave(pFrom);
            sqlite3BtreeLeave(pTo);
            return rc;
        }
    }

    // Set up the backup object. b.pDestDb must be 0; backup_step()/finish() use
    // that to detect they were called from here, not by the user directly.
    @memset(std.mem.asBytes(&b), 0);
    b.pSrcDb = btDb(pFrom);
    b.pSrc = pFrom;
    b.pDest = pTo;
    b.iNext = 1;

    // 0x7FFFFFFF is the hard page-count limit, so the copy finishes in one call
    // (barring errors). After it, b.rc must be SQLITE_DONE or an error code.
    _ = sqlite3_backup_step(&b, 0x7FFFFFFF);
    // assert( b.rc!=SQLITE_OK )

    rc = sqlite3_backup_finish(&b);
    if (rc == SQLITE_OK) {
        btSharedBtsFlagsPtr(btPBt(pTo)).* &= ~BTS_PAGESIZE_FIXED;
    } else {
        sqlite3PagerClearCache(sqlite3BtreePager(b.pDest));
    }

    // assert( sqlite3BtreeTxnState(pTo)!=SQLITE_TXN_WRITE )
    sqlite3BtreeLeave(pFrom);
    sqlite3BtreeLeave(pTo);
    return rc;
}
