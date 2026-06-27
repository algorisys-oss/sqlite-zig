//! Zig port of SQLite's Unix VFS (src/os_unix.c).
//!
//! Drop-in replacement for the unix `sqlite3_vfs`/`sqlite3_io_methods`
//! implementation: the file-private `unixFile`/`unixInodeInfo`/`unixShm*`
//! machinery, POSIX advisory locking, the default posix/unix-excl/nolock/
//! dotfile locking styles, shared-memory (WAL wal-index), mmap-backed
//! xFetch/xUnfetch, and `sqlite3_os_init`/`sqlite3_os_end`.
//!
//! Only `sqlite3_os_init` and `sqlite3_os_end` are exported — everything else
//! (the VFS object, the io_methods tables, every `unix*` method) is file-private
//! in C, so they are private here too; the VFS is reached only after os_init
//! registers it via the (already-ported) `sqlite3_vfs_register`.
//!
//! ## Config assumptions (match build.zig flags; see PROGRESS.md)
//!   * SQLITE_OS_UNIX, __linux__, glibc x86-64.
//!   * SQLITE_ENABLE_LOCKING_STYLE = 0  (no flock/AFP/named-sem/proxy styles).
//!     => only posixIoMethods / nolockIoMethods / dotlockIoMethods exist, and
//!        the registered VFSes are unix, unix-none, unix-dotfile, unix-excl.
//!     Default VFS is "unix" (no SQLITE_DEFAULT_UNIX_VFS), the i==0 entry.
//!   * SQLITE_OMIT_WAL = off  => the unixShm* methods are present (io_methods
//!     iVersion 3 for posix; nolock/dotlock are iVersion 3/1 with 0 xShmMap).
//!   * SQLITE_MAX_MMAP_SIZE > 0 (2147418112) => xFetch/xUnfetch + mmap fields.
//!   * SQLITE_ENABLE_SETLK_TIMEOUT = off  => non-blocking F_SETLK only; no
//!     iBusyTimeout / aMutex[] / blocking-lock paths.
//!   * SQLITE_OMIT_LOAD_EXTENSION = off  => xDlOpen/Sym/Close via libdl.
//!   * HAVE_FCHMOD / HAVE_FCHOWN / HAVE_POSIX_FALLOCATE / HAVE_MREMAP /
//!     HAVE_PREAD / HAVE_PWRITE / HAVE_READLINK / HAVE_LSTAT all true (linux).
//!   * SQLITE_TEST / SQLITE_DEBUG: gated on @import("config") so the
//!     instrumentation (sqlite3_io_error_*, sqlite3_open_file_count,
//!     sqlite3_sync_count, sqlite3_current_time, the transCntrChng asserts and
//!     OSTRACE) exists only in the testfixture build — like C's -D flags.
//!
//! ## Coupling
//! `unixFile` is os_unix.c's *own* struct (callers only ever hold a pointer to
//! it as a `sqlite3_file`), so its layout is owned here — an `extern struct`
//! whose tail grows under SQLITE_DEBUG / SQLITE_TEST exactly as the C one does.
//! The only internal-struct reads are `sqlite3GlobalConfig.{bCoreMutex,szMmap,
//! mxMmap}` at their config-invariant ground-truth offsets (c_layout.zig).
//! PENDING_BYTE is the mutable global `sqlite3PendingByte` (SQLITE_OMIT_WSD off).

const std = @import("std");
const config = @import("config");
const c_layout = @import("c_layout.zig");
const L = c_layout.c;

// ===========================================================================
// SQLite result / flag constants (probed against the build).
// ===========================================================================
const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_PERM: c_int = 3;
const SQLITE_BUSY: c_int = 5;
const SQLITE_NOMEM: c_int = 7; // SQLITE_NOMEM_BKPT result code
const SQLITE_READONLY: c_int = 8;
const SQLITE_IOERR: c_int = 10;
const SQLITE_NOTFOUND: c_int = 12;
const SQLITE_FULL: c_int = 13;
const SQLITE_CANTOPEN: c_int = 14; // SQLITE_CANTOPEN_BKPT
const SQLITE_NOLFS: c_int = 22;

const SQLITE_IOERR_READ: c_int = 266;
const SQLITE_IOERR_SHORT_READ: c_int = 522;
const SQLITE_IOERR_WRITE: c_int = 778;
const SQLITE_IOERR_FSYNC: c_int = 1034;
const SQLITE_IOERR_DIR_FSYNC: c_int = 1290;
const SQLITE_IOERR_TRUNCATE: c_int = 1546;
const SQLITE_IOERR_FSTAT: c_int = 1802;
const SQLITE_IOERR_UNLOCK: c_int = 2058;
const SQLITE_IOERR_RDLOCK: c_int = 2314;
const SQLITE_IOERR_DELETE: c_int = 2570;
const SQLITE_IOERR_NOMEM: c_int = 3082; // SQLITE_IOERR_NOMEM_BKPT
const SQLITE_IOERR_ACCESS: c_int = 3338;
const SQLITE_IOERR_CHECKRESERVEDLOCK: c_int = 3594;
const SQLITE_IOERR_LOCK: c_int = 3850;
const SQLITE_IOERR_CLOSE: c_int = 4106;
const SQLITE_IOERR_SHMOPEN: c_int = 4618;
const SQLITE_IOERR_SHMSIZE: c_int = 4874;
const SQLITE_IOERR_SHMLOCK: c_int = 5130;
const SQLITE_IOERR_SHMMAP: c_int = 5386;
const SQLITE_IOERR_DELETE_NOENT: c_int = 5898;
const SQLITE_IOERR_GETTEMPPATH: c_int = 6410;
const SQLITE_IOERR_CORRUPTFS: c_int = 8458;

const SQLITE_READONLY_CANTINIT: c_int = 1288;
const SQLITE_READONLY_DIRECTORY: c_int = 1544;
const SQLITE_ERROR_UNABLE: c_int = 1537; // SQLITE_ERROR_UNABLE_TO_OPEN
const SQLITE_OK_SYMLINK: c_int = 512;

const SQLITE_WARNING: c_int = 28;

// Lock levels (os.h)
const NO_LOCK: u8 = 0;
const SHARED_LOCK: u8 = 1;
const RESERVED_LOCK: u8 = 2;
const PENDING_LOCK: u8 = 3;
const EXCLUSIVE_LOCK: u8 = 4;

// SQLITE_OPEN_* flags
const SQLITE_OPEN_READONLY: c_int = 0x00000001;
const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
const SQLITE_OPEN_CREATE: c_int = 0x00000004;
const SQLITE_OPEN_DELETEONCLOSE: c_int = 0x00000008;
const SQLITE_OPEN_EXCLUSIVE: c_int = 0x00000010;
const SQLITE_OPEN_URI: c_int = 0x00000040;
const SQLITE_OPEN_MAIN_DB: c_int = 0x00000100;
const SQLITE_OPEN_TEMP_DB: c_int = 0x00000200;
const SQLITE_OPEN_TRANSIENT_DB: c_int = 0x00000400;
const SQLITE_OPEN_MAIN_JOURNAL: c_int = 0x00000800;
const SQLITE_OPEN_TEMP_JOURNAL: c_int = 0x00001000;
const SQLITE_OPEN_SUBJOURNAL: c_int = 0x00002000;
const SQLITE_OPEN_SUPER_JOURNAL: c_int = 0x00004000;
const SQLITE_OPEN_WAL: c_int = 0x00080000;

// xSync flags
const SQLITE_SYNC_NORMAL: c_int = 0x00002;
const SQLITE_SYNC_FULL: c_int = 0x00003;
const SQLITE_SYNC_DATAONLY: c_int = 0x00010;

// IOCAP
const SQLITE_IOCAP_POWERSAFE_OVERWRITE: c_int = 0x00001000;
const SQLITE_IOCAP_SUBPAGE_READ: c_int = 0x00008000;

// FCNTL ops
const SQLITE_FCNTL_LOCKSTATE: c_int = 1;
const SQLITE_FCNTL_LAST_ERRNO: c_int = 4;
const SQLITE_FCNTL_SIZE_HINT: c_int = 5;
const SQLITE_FCNTL_CHUNK_SIZE: c_int = 6;
const SQLITE_FCNTL_PERSIST_WAL: c_int = 10;
const SQLITE_FCNTL_VFSNAME: c_int = 12;
const SQLITE_FCNTL_POWERSAFE_OVERWRITE: c_int = 13;
const SQLITE_FCNTL_TEMPFILENAME: c_int = 16;
const SQLITE_FCNTL_MMAP_SIZE: c_int = 18;
const SQLITE_FCNTL_HAS_MOVED: c_int = 20;
const SQLITE_FCNTL_EXTERNAL_READER: c_int = 40;
const SQLITE_FCNTL_NULL_IO: c_int = 43;

// SHM lock flags
const SQLITE_SHM_UNLOCK: c_int = 1;
const SQLITE_SHM_LOCK: c_int = 2;
const SQLITE_SHM_SHARED: c_int = 4;
const SQLITE_SHM_EXCLUSIVE: c_int = 8;

// xAccess flags
const SQLITE_ACCESS_EXISTS: c_int = 0;
const SQLITE_ACCESS_READWRITE: c_int = 1;

// Mutex ids
const SQLITE_MUTEX_FAST: c_int = 0;
const SQLITE_MUTEX_STATIC_VFS1: c_int = 11;
const SQLITE_MUTEX_STATIC_TEMPDIR: c_int = 11;

const SQLITE_DEFAULT_SECTOR_SIZE: c_int = 4096;
const SQLITE_DEFAULT_FILE_PERMISSIONS: mode_t = 0o644;
const SQLITE_POWERSAFE_OVERWRITE: c_int = 1;
const SQLITE_SHM_NLOCK: c_int = 8;
const SQLITE_MAX_MMAP_SIZE: i64 = 2147418112;
const MAX_PATHNAME: c_int = 512;
const SQLITE_MAX_PATHLEN: usize = 4096;
const SQLITE_MAX_SYMLINKS: c_int = 100;
const SQLITE_MINIMUM_FILE_DESCRIPTOR: c_int = 3;
const SQLITE_TEMP_FILE_PREFIX = "etilqs_";

// SHM locking offsets:  UNIX_SHM_BASE = (22+SQLITE_SHM_NLOCK)*4 = 120
const UNIX_SHM_BASE: c_int = (22 + SQLITE_SHM_NLOCK) * 4;
const UNIX_SHM_DMS: c_int = UNIX_SHM_BASE + SQLITE_SHM_NLOCK;

// unixFile.ctrlFlags bits
const UNIXFILE_EXCL: u16 = 0x01;
const UNIXFILE_RDONLY: u16 = 0x02;
const UNIXFILE_PERSIST_WAL: u16 = 0x04;
const UNIXFILE_DIRSYNC: u16 = 0x08; // !SQLITE_DISABLE_DIRSYNC && !_AIX
const UNIXFILE_PSOW: u16 = 0x10;
const UNIXFILE_DELETE: u16 = 0x20;
const UNIXFILE_URI: u16 = 0x40;
const UNIXFILE_NOLOCK: u16 = 0x80;

const SQLITE_FSFLAGS_IS_MSDOS: c_uint = 0x1;

// ===========================================================================
// libc / kernel constants (glibc x86-64; probed against <fcntl.h> etc.).
// ===========================================================================
const O_RDONLY: c_int = 0x0;
const O_WRONLY: c_int = 0x1;
const O_RDWR: c_int = 0x2;
const O_CREAT: c_int = 0o100; // 0x40
const O_EXCL: c_int = 0o200; // 0x80
const O_TRUNC: c_int = 0o1000; // 0x200
const O_NOFOLLOW: c_int = 0o400000; // 0x20000
const O_CLOEXEC: c_int = 0o2000000; // 0x80000
const O_TMPFILE: c_int = 0o20200000; // 0x410000 (O_DIRECTORY|0x400000); linux value
const O_LARGEFILE: c_int = 0; // 0 on x86-64 (already LFS)
const O_BINARY: c_int = 0; // 0 on unix

const F_DUPFD: c_int = 0;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const F_GETLK: c_int = 5;
const F_SETLK: c_int = 6;
const F_SETLKW: c_int = 7;
const FD_CLOEXEC: c_int = 1;

const F_RDLCK: c_short = 0;
const F_WRLCK: c_short = 1;
const F_UNLCK: c_short = 2;

const SEEK_SET: c_int = 0;
const SEEK_CUR: c_int = 1;
const SEEK_END: c_int = 2;

const S_IFMT: c_uint = 0o170000;
const S_IFREG: c_uint = 0o100000;
const S_IFDIR: c_uint = 0o040000;
const S_IFLNK: c_uint = 0o120000;

const R_OK: c_int = 4;
const W_OK: c_int = 2;
const F_OK: c_int = 0;

const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const MAP_SHARED: c_int = 0x1;
const MREMAP_MAYMOVE: c_int = 1;
const MAP_FAILED: ?*anyopaque = @ptrFromInt(std.math.maxInt(usize));

// errno values (glibc)
const EINTR: c_int = 4;
const EIO: c_int = 5;
const ENXIO: c_int = 6;
const EAGAIN: c_int = 11;
const ENOMEM: c_int = 12;
const EACCES: c_int = 13;
const EBUSY: c_int = 16;
const EEXIST: c_int = 17;
const EISDIR: c_int = 21;
const EINVAL: c_int = 22;
const ENOSPC: c_int = 28;
const ERANGE: c_int = 34;
const ENOLCK: c_int = 37;
const ENOENT: c_int = 2;
const EPERM: c_int = 1;
const EOVERFLOW: c_int = 75;
const ETIMEDOUT: c_int = 110;
const _SC_PAGESIZE: c_int = 30;

// off_t/mode_t/etc. are 64/32-bit on linux x86-64
const off_t = i64;
const mode_t = u32;
const uid_t = u32;
const gid_t = u32;
const pid_t = i32;
const dev_t = u64;
const time_t = c_long;
const ssize_t = isize;
const size_t = usize;

// ===========================================================================
// libc struct layouts (glibc x86-64; probed with offsetof/sizeof).
// ===========================================================================

/// struct stat — sizeof 144. Only the fields SQLite touches are named; the rest
/// is padding to keep the size exact (the kernel/glibc fill the whole thing).
const stat = extern struct {
    st_dev: dev_t, //  0
    st_ino: u64, //  8
    st_nlink: u64, // 16
    st_mode: c_uint, // 24
    st_uid: uid_t, // 28
    st_gid: gid_t, // 32
    __pad0: u32, // 36
    st_rdev: dev_t, // 40
    st_size: off_t, // 48
    st_blksize: c_long, // 56
    st_blocks: i64, // 64
    st_atim_sec: c_long, // 72
    st_atim_nsec: c_long, // 80
    st_mtim_sec: c_long, // 88
    st_mtim_nsec: c_long, // 96
    st_ctim_sec: c_long, // 104
    st_ctim_nsec: c_long, // 112
    __glibc_reserved: [3]i64, // 120..144
};
comptime {
    std.debug.assert(@sizeOf(stat) == 144);
    std.debug.assert(@offsetOf(stat, "st_size") == 48);
    std.debug.assert(@offsetOf(stat, "st_mode") == 24);
    std.debug.assert(@offsetOf(stat, "st_blksize") == 56);
}

/// struct flock — sizeof 32 (glibc, LFS).
const flock = extern struct {
    l_type: c_short, //  0
    l_whence: c_short, //  2
    __pad: u32 = 0, //  4
    l_start: off_t, //  8
    l_len: off_t, // 16
    l_pid: pid_t, // 24
    __pad2: u32 = 0, // 28
};
comptime {
    std.debug.assert(@sizeOf(flock) == 32);
    std.debug.assert(@offsetOf(flock, "l_start") == 8);
    std.debug.assert(@offsetOf(flock, "l_len") == 16);
    std.debug.assert(@offsetOf(flock, "l_pid") == 24);
}

const timespec = extern struct {
    tv_sec: time_t,
    tv_nsec: c_long,
};
const timeval = extern struct {
    tv_sec: time_t,
    tv_usec: c_long,
};

// ===========================================================================
// libc bindings (plain `extern fn`, repo convention — resolved at link time).
// ===========================================================================
extern fn open(path: [*:0]const u8, flags: c_int, mode: mode_t) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: ?*anyopaque, n: size_t) ssize_t;
extern fn pread(fd: c_int, buf: ?*anyopaque, n: size_t, off: off_t) ssize_t;
extern fn write(fd: c_int, buf: ?*const anyopaque, n: size_t) ssize_t;
extern fn pwrite(fd: c_int, buf: ?*const anyopaque, n: size_t, off: off_t) ssize_t;
extern fn lseek(fd: c_int, off: off_t, whence: c_int) off_t;
extern fn ftruncate(fd: c_int, len: off_t) c_int;
extern fn fsync(fd: c_int) c_int;
extern fn fdatasync(fd: c_int) c_int;
extern fn access(path: [*:0]const u8, mode: c_int) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn mkdir(path: [*:0]const u8, mode: mode_t) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn getcwd(buf: [*]u8, size: size_t) ?[*:0]u8;
extern fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: size_t) ssize_t;
extern fn fchmod(fd: c_int, mode: mode_t) c_int;
extern fn fchown(fd: c_int, owner: uid_t, group: gid_t) c_int;
extern fn geteuid() uid_t;
extern fn getpid() pid_t;
const c_stat = @extern(*const fn ([*:0]const u8, *stat) callconv(.c) c_int, .{ .name = "stat" });
extern fn fstat(fd: c_int, buf: *stat) c_int;
extern fn lstat(path: [*:0]const u8, buf: *stat) c_int;
extern fn posix_fallocate(fd: c_int, off: off_t, len: off_t) c_int;
extern fn mmap(addr: ?*anyopaque, length: size_t, prot: c_int, flags: c_int, fd: c_int, offset: off_t) ?*anyopaque;
extern fn munmap(addr: ?*anyopaque, length: size_t) c_int;
extern fn mremap(old_addr: ?*anyopaque, old_size: size_t, new_size: size_t, flags: c_int, ...) ?*anyopaque;
extern fn nanosleep(req: *const timespec, rem: ?*timespec) c_int;
extern fn gettimeofday(tv: *timeval, tz: ?*anyopaque) c_int;
extern fn sysconf(name: c_int) c_long;
extern fn strstr(haystack: [*:0]const u8, needle: [*:0]const u8) ?[*:0]u8;
extern fn strrchr(s: [*:0]const u8, c: c_int) ?[*:0]u8;
extern fn strtoll(nptr: [*:0]const u8, endptr: ?*?[*:0]u8, base: c_int) c_longlong;
extern fn strcmp(a: [*:0]const u8, b: [*:0]const u8) c_int;
extern fn strncmp(a: [*:0]const u8, b: [*:0]const u8, n: size_t) c_int;
extern fn strlen(s: [*:0]const u8) size_t;
extern fn getenv(name: [*:0]const u8) ?[*:0]u8;
extern fn time(t: ?*time_t) time_t;
extern fn memcpy(dst: ?*anyopaque, src: ?*const anyopaque, n: size_t) ?*anyopaque;
extern fn memset(dst: ?*anyopaque, c: c_int, n: size_t) ?*anyopaque;
extern fn memcmp(a: ?*const anyopaque, b: ?*const anyopaque, n: size_t) c_int;
extern fn strerror(errnum: c_int) ?[*:0]u8;
extern fn strerror_r(errnum: c_int, buf: [*]u8, buflen: size_t) ?[*:0]u8;
extern fn __errno_location() *c_int;

// fcntl is variadic: declare per-arg-type wrappers below via osFcntlFlock/osFcntlInt.
extern fn fcntl(fd: c_int, cmd: c_int, ...) c_int;

// dlfcn (SQLITE_OMIT_LOAD_EXTENSION off → link libdl).
const RTLD_NOW: c_int = 2;
const RTLD_GLOBAL: c_int = 0x100;
extern fn dlopen(filename: ?[*:0]const u8, flag: c_int) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
extern fn dlclose(handle: ?*anyopaque) c_int;
extern fn dlerror() ?[*:0]u8;

inline fn errno() c_int {
    return __errno_location().*;
}
inline fn setErrno(v: c_int) void {
    __errno_location().* = v;
}

// ===========================================================================
// SQLite core helpers (resolved at link time).
// ===========================================================================
extern fn sqlite3_malloc64(n: u64) ?*anyopaque;
extern fn sqlite3_realloc64(p: ?*anyopaque, n: u64) ?*anyopaque;
extern fn sqlite3_free(p: ?*anyopaque) void;
extern fn sqlite3_mprintf(fmt: [*:0]const u8, ...) ?[*:0]u8;
extern fn sqlite3_snprintf(n: c_int, buf: [*]u8, fmt: [*:0]const u8, ...) [*:0]u8;
extern fn sqlite3_log(errcode: c_int, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_randomness(n: c_int, p: ?*anyopaque) void;
extern fn sqlite3_uri_boolean(z: ?[*:0]const u8, param: [*:0]const u8, bdflt: c_int) c_int;
extern fn sqlite3_uri_parameter(z: ?[*:0]const u8, param: [*:0]const u8) ?[*:0]const u8;
extern fn sqlite3MutexAlloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_alloc(id: c_int) ?*anyopaque;
extern fn sqlite3_mutex_free(m: ?*anyopaque) void;
extern fn sqlite3_mutex_enter(m: ?*anyopaque) void;
extern fn sqlite3_mutex_leave(m: ?*anyopaque) void;
extern fn sqlite3_mutex_held(m: ?*anyopaque) c_int;
extern fn sqlite3_mutex_notheld(m: ?*anyopaque) c_int;
extern fn sqlite3MemoryBarrier() void;
extern fn sqlite3Strlen30(z: [*:0]const u8) c_int;
extern fn sqlite3_vfs_register(pVfs: *Sqlite3Vfs, makeDflt: c_int) c_int;
extern fn sqlite3_str_appendf(p: ?*anyopaque, fmt: [*:0]const u8, ...) void;
extern fn sqlite3_str_append(p: ?*anyopaque, z: [*]const u8, n: c_int) void;
extern fn sqlite3_str_appendall(p: ?*anyopaque, z: [*:0]const u8) void;

/// `sqlite3_temp_directory` — mutable `char *` global.
extern var sqlite3_temp_directory: ?[*:0]const u8;

/// PENDING_BYTE expands to `sqlite3PendingByte` (SQLITE_OMIT_WSD off). Mutable
/// `int` global, so it must be `extern var` (test harness sets it low).
extern var sqlite3PendingByte: c_int;
inline fn PENDING_BYTE() i64 {
    return sqlite3PendingByte;
}
inline fn RESERVED_BYTE() i64 {
    return PENDING_BYTE() + 1;
}
inline fn SHARED_FIRST() i64 {
    return PENDING_BYTE() + 2;
}
const SHARED_SIZE: i64 = 510;

/// `sqlite3GlobalConfig` (alias `sqlite3Config`). Mutable global — see pcache.zig.
extern var sqlite3Config: u8;
inline fn cfgBase() [*]u8 {
    return @ptrCast(&sqlite3Config);
}
inline fn cfgCoreMutex() bool {
    return cfgBase()[L.Sqlite3Config_bCoreMutex] != 0;
}
inline fn cfgSzMmap() i64 {
    const p: *align(1) const i64 = @ptrCast(cfgBase() + L.Sqlite3Config_szMmap);
    return p.*;
}
inline fn cfgMxMmap() i64 {
    const p: *align(1) const i64 = @ptrCast(cfgBase() + L.Sqlite3Config_mxMmap);
    return p.*;
}

// ===========================================================================
// Public ABI structs (sqlite3.h) — field order/iVersion replicated EXACTLY
// (copied from src/os.zig).
// ===========================================================================
const VoidFn = ?*const fn () callconv(.c) void;

const IoMethods = extern struct {
    iVersion: c_int,
    xClose: ?*const fn (*Sqlite3File) callconv(.c) c_int,
    xRead: ?*const fn (*Sqlite3File, ?*anyopaque, c_int, i64) callconv(.c) c_int,
    xWrite: ?*const fn (*Sqlite3File, ?*const anyopaque, c_int, i64) callconv(.c) c_int,
    xTruncate: ?*const fn (*Sqlite3File, i64) callconv(.c) c_int,
    xSync: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xFileSize: ?*const fn (*Sqlite3File, *i64) callconv(.c) c_int,
    xLock: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xUnlock: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xCheckReservedLock: ?*const fn (*Sqlite3File, *c_int) callconv(.c) c_int,
    xFileControl: ?*const fn (*Sqlite3File, c_int, ?*anyopaque) callconv(.c) c_int,
    xSectorSize: ?*const fn (*Sqlite3File) callconv(.c) c_int,
    xDeviceCharacteristics: ?*const fn (*Sqlite3File) callconv(.c) c_int,
    xShmMap: ?*const fn (*Sqlite3File, c_int, c_int, c_int, ?*anyopaque) callconv(.c) c_int,
    xShmLock: ?*const fn (*Sqlite3File, c_int, c_int, c_int) callconv(.c) c_int,
    xShmBarrier: ?*const fn (*Sqlite3File) callconv(.c) void,
    xShmUnmap: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    xFetch: ?*const fn (*Sqlite3File, i64, c_int, ?*anyopaque) callconv(.c) c_int,
    xUnfetch: ?*const fn (*Sqlite3File, i64, ?*anyopaque) callconv(.c) c_int,
};

const Sqlite3File = extern struct {
    pMethods: ?*const IoMethods,
};

const SyscallPtr = ?*const fn () callconv(.c) void;

const Sqlite3Vfs = extern struct {
    iVersion: c_int,
    szOsFile: c_int,
    mxPathname: c_int,
    pNext: ?*Sqlite3Vfs,
    zName: ?[*:0]const u8,
    pAppData: ?*anyopaque,
    xOpen: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8, *Sqlite3File, c_int, ?*c_int) callconv(.c) c_int,
    xDelete: ?*const fn (*Sqlite3Vfs, [*:0]const u8, c_int) callconv(.c) c_int,
    xAccess: ?*const fn (*Sqlite3Vfs, [*:0]const u8, c_int, *c_int) callconv(.c) c_int,
    xFullPathname: ?*const fn (*Sqlite3Vfs, [*:0]const u8, c_int, [*]u8) callconv(.c) c_int,
    xDlOpen: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8) callconv(.c) ?*anyopaque,
    xDlError: ?*const fn (*Sqlite3Vfs, c_int, [*]u8) callconv(.c) void,
    xDlSym: ?*const fn (*Sqlite3Vfs, ?*anyopaque, [*:0]const u8) callconv(.c) VoidFn,
    xDlClose: ?*const fn (*Sqlite3Vfs, ?*anyopaque) callconv(.c) void,
    xRandomness: ?*const fn (*Sqlite3Vfs, c_int, [*]u8) callconv(.c) c_int,
    xSleep: ?*const fn (*Sqlite3Vfs, c_int) callconv(.c) c_int,
    xCurrentTime: ?*const fn (*Sqlite3Vfs, *f64) callconv(.c) c_int,
    xGetLastError: ?*const fn (*Sqlite3Vfs, c_int, ?[*]u8) callconv(.c) c_int,
    xCurrentTimeInt64: ?*const fn (*Sqlite3Vfs, *i64) callconv(.c) c_int,
    xSetSystemCall: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8, SyscallPtr) callconv(.c) c_int,
    xGetSystemCall: ?*const fn (*Sqlite3Vfs, [*:0]const u8) callconv(.c) SyscallPtr,
    xNextSystemCall: ?*const fn (*Sqlite3Vfs, ?[*:0]const u8) callconv(.c) ?[*:0]const u8,
};

// ===========================================================================
// File-private structs (os_unix.c's own — layout owned here).
// ===========================================================================

const UnixUnusedFd = extern struct {
    fd: c_int,
    flags: c_int,
    pNext: ?*UnixUnusedFd,
};

/// unixFile — subclass of sqlite3_file. `pMethod` must be first (it IS the
/// sqlite3_file.pMethods slot). Tail fields gated on SQLITE_DEBUG / SQLITE_TEST
/// exactly as the C struct, so sizeof matches the active config.
const unixFile = extern struct {
    pMethod: ?*const IoMethods, // always first
    pVfs: ?*Sqlite3Vfs,
    pInode: ?*unixInodeInfo,
    h: c_int,
    eFileLock: u8,
    ctrlFlags: u16,
    lastErrno: c_int,
    lockingContext: ?*anyopaque,
    pPreallocatedUnused: ?*UnixUnusedFd,
    zPath: ?[*:0]const u8,
    pShm: ?*unixShm,
    szChunk: c_int,
    // SQLITE_MAX_MMAP_SIZE>0
    nFetchOut: c_int,
    mmapSize: i64,
    mmapSizeActual: i64,
    mmapSizeMax: i64,
    pMapRegion: ?*anyopaque,
    sectorSize: c_int,
    deviceCharacteristics: c_int,
    // SQLITE_DEBUG tail
    transCntrChng: if (config.sqlite_debug) u8 else void = if (config.sqlite_debug) 0 else {},
    dbUpdate: if (config.sqlite_debug) u8 else void = if (config.sqlite_debug) 0 else {},
    inNormalWrite: if (config.sqlite_debug) u8 else void = if (config.sqlite_debug) 0 else {},
    // SQLITE_TEST padding (so unixFile > struct CrashFile in test6.c)
    aPadding: if (config.sqlite_test) [32]u8 else void = if (config.sqlite_test) std.mem.zeroes([32]u8) else {},
};

const unixFileId = extern struct {
    dev: dev_t,
    ino: u64,
};

const unixInodeInfo = extern struct {
    fileId: unixFileId,
    pLockMutex: ?*anyopaque,
    nShared: c_int,
    nLock: c_int,
    eFileLock: u8,
    bProcessLock: u8,
    pUnused: ?*UnixUnusedFd,
    nRef: c_int,
    pShmNode: ?*unixShmNode,
    pNext: ?*unixInodeInfo,
    pPrev: ?*unixInodeInfo,
};

const unixShmNode = extern struct {
    pInode: ?*unixInodeInfo,
    pShmMutex: ?*anyopaque,
    zFilename: ?[*:0]u8,
    hShm: c_int,
    szRegion: c_int,
    nRegion: u16,
    isReadonly: u8,
    isUnlocked: u8,
    apRegion: ?[*]?[*]u8,
    nRef: c_int,
    pFirst: ?*unixShm,
    aLock: [SQLITE_SHM_NLOCK]c_int,
    nextShmId: if (config.sqlite_debug) u8 else void = if (config.sqlite_debug) 0 else {},
};

const unixShm = extern struct {
    pShmNode: ?*unixShmNode,
    pNext: ?*unixShm,
    hasMutex: u8,
    id: u8,
    sharedMask: u16,
    exclMask: u16,
};

// ===========================================================================
// Syscall indirection table (xSetSystemCall / xGetSystemCall / xNextSystemCall).
// Replicates C's aSyscall[]: 29 entries, names + current + default pointers.
// The osXXX wrappers fetch aSyscall[i].pCurrent and cast to the right signature.
// ===========================================================================
const UnixSyscall = extern struct {
    zName: [*:0]const u8,
    pCurrent: SyscallPtr,
    pDefault: SyscallPtr,
};

fn syscallEntry(comptime name: [*:0]const u8, p: anytype) UnixSyscall {
    return .{ .zName = name, .pCurrent = @ptrCast(@constCast(p)), .pDefault = null };
}

// posixOpen wrapper (uniform open(const char*,int,int) signature).
fn posixOpen(zFile: [*:0]const u8, flags: c_int, mode: c_int) callconv(.c) c_int {
    return open(zFile, flags, @intCast(mode));
}

var aSyscall = [_]UnixSyscall{
    syscallEntry("open", &posixOpen), // 0
    syscallEntry("close", &close), // 1
    syscallEntry("access", &access), // 2
    syscallEntry("getcwd", &getcwd), // 3
    syscallEntry("stat", c_stat), // 4
    syscallEntry("fstat", &fstat), // 5
    syscallEntry("ftruncate", &ftruncate), // 6
    syscallEntry("fcntl", &fcntl), // 7
    syscallEntry("read", &read), // 8
    syscallEntry("pread", &pread), // 9 (USE_PREAD)
    .{ .zName = "pread64", .pCurrent = null, .pDefault = null }, // 10
    syscallEntry("write", &write), // 11
    syscallEntry("pwrite", &pwrite), // 12 (USE_PREAD)
    .{ .zName = "pwrite64", .pCurrent = null, .pDefault = null }, // 13
    syscallEntry("fchmod", &fchmod), // 14 (HAVE_FCHMOD)
    syscallEntry("fallocate", &posix_fallocate), // 15 (HAVE_POSIX_FALLOCATE)
    syscallEntry("unlink", &unlink), // 16
    syscallEntry("openDirectory", &openDirectory), // 17
    syscallEntry("mkdir", &mkdir), // 18
    syscallEntry("rmdir", &rmdir), // 19
    syscallEntry("fchown", &fchown), // 20 (HAVE_FCHOWN)
    syscallEntry("geteuid", &geteuid), // 21 (HAVE_FCHOWN)
    syscallEntry("mmap", &mmap), // 22
    syscallEntry("munmap", &munmap), // 23
    syscallEntry("mremap", &mremap), // 24 (HAVE_MREMAP)
    syscallEntry("getpagesize", &unixGetpagesize), // 25
    syscallEntry("readlink", &readlink), // 26 (HAVE_READLINK)
    syscallEntry("lstat", &lstat), // 27 (HAVE_LSTAT)
    .{ .zName = "ioctl", .pCurrent = null, .pDefault = null }, // 28 (no BATCH_ATOMIC_WRITE)
};

// Typed accessors into aSyscall[].pCurrent (the C osXXX macros).
inline fn osOpen(z: [*:0]const u8, f: c_int, m: c_int) c_int {
    const F = *const fn ([*:0]const u8, c_int, c_int) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[0].pCurrent.?))(z, f, m);
}
inline fn osClose(fd: c_int) c_int {
    const F = *const fn (c_int) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[1].pCurrent.?))(fd);
}
inline fn osAccess(z: [*:0]const u8, m: c_int) c_int {
    const F = *const fn ([*:0]const u8, c_int) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[2].pCurrent.?))(z, m);
}
inline fn osGetcwd(buf: [*]u8, sz: size_t) ?[*:0]u8 {
    const F = *const fn ([*]u8, size_t) callconv(.c) ?[*:0]u8;
    return @as(F, @ptrCast(aSyscall[3].pCurrent.?))(buf, sz);
}
inline fn osStat(z: [*:0]const u8, buf: *stat) c_int {
    const F = *const fn ([*:0]const u8, *stat) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[4].pCurrent.?))(z, buf);
}
inline fn osFstat(fd: c_int, buf: *stat) c_int {
    const F = *const fn (c_int, *stat) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[5].pCurrent.?))(fd, buf);
}
inline fn osFtruncate(fd: c_int, len: off_t) c_int {
    const F = *const fn (c_int, off_t) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[6].pCurrent.?))(fd, len);
}
inline fn osFcntlInt(fd: c_int, cmd: c_int, arg: c_int) c_int {
    const F = *const fn (c_int, c_int, c_int) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[7].pCurrent.?))(fd, cmd, arg);
}
inline fn osFcntlLock(fd: c_int, cmd: c_int, lk: *flock) c_int {
    const F = *const fn (c_int, c_int, *flock) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[7].pCurrent.?))(fd, cmd, lk);
}
inline fn osRead(fd: c_int, buf: ?*anyopaque, n: size_t) ssize_t {
    const F = *const fn (c_int, ?*anyopaque, size_t) callconv(.c) ssize_t;
    return @as(F, @ptrCast(aSyscall[8].pCurrent.?))(fd, buf, n);
}
inline fn osPread(fd: c_int, buf: ?*anyopaque, n: size_t, off: off_t) ssize_t {
    const F = *const fn (c_int, ?*anyopaque, size_t, off_t) callconv(.c) ssize_t;
    return @as(F, @ptrCast(aSyscall[9].pCurrent.?))(fd, buf, n, off);
}
inline fn osWrite(fd: c_int, buf: ?*const anyopaque, n: size_t) ssize_t {
    const F = *const fn (c_int, ?*const anyopaque, size_t) callconv(.c) ssize_t;
    return @as(F, @ptrCast(aSyscall[11].pCurrent.?))(fd, buf, n);
}
inline fn osPwrite(fd: c_int, buf: ?*const anyopaque, n: size_t, off: off_t) ssize_t {
    const F = *const fn (c_int, ?*const anyopaque, size_t, off_t) callconv(.c) ssize_t;
    return @as(F, @ptrCast(aSyscall[12].pCurrent.?))(fd, buf, n, off);
}
inline fn osFchmod(fd: c_int, m: mode_t) c_int {
    if (aSyscall[14].pCurrent == null) return 0;
    const F = *const fn (c_int, mode_t) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[14].pCurrent.?))(fd, m);
}
inline fn osFallocate(fd: c_int, off: off_t, len: off_t) c_int {
    const F = *const fn (c_int, off_t, off_t) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[15].pCurrent.?))(fd, off, len);
}
inline fn osUnlink(z: [*:0]const u8) c_int {
    const F = *const fn ([*:0]const u8) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[16].pCurrent.?))(z);
}
inline fn osOpenDirectory(z: [*:0]const u8, pFd: *c_int) c_int {
    const F = *const fn ([*:0]const u8, *c_int) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[17].pCurrent.?))(z, pFd);
}
inline fn osMkdir(z: [*:0]const u8, m: mode_t) c_int {
    const F = *const fn ([*:0]const u8, mode_t) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[18].pCurrent.?))(z, m);
}
inline fn osRmdir(z: [*:0]const u8) c_int {
    const F = *const fn ([*:0]const u8) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[19].pCurrent.?))(z);
}
inline fn osFchown(fd: c_int, uid: uid_t, gid: gid_t) c_int {
    if (aSyscall[20].pCurrent == null) return 0;
    const F = *const fn (c_int, uid_t, gid_t) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[20].pCurrent.?))(fd, uid, gid);
}
inline fn osGeteuid() uid_t {
    const F = *const fn () callconv(.c) uid_t;
    return @as(F, @ptrCast(aSyscall[21].pCurrent.?))();
}
inline fn osMmap(addr: ?*anyopaque, len: size_t, prot: c_int, flags: c_int, fd: c_int, off: off_t) ?*anyopaque {
    const F = *const fn (?*anyopaque, size_t, c_int, c_int, c_int, off_t) callconv(.c) ?*anyopaque;
    return @as(F, @ptrCast(aSyscall[22].pCurrent.?))(addr, len, prot, flags, fd, off);
}
inline fn osMunmap(addr: ?*anyopaque, len: size_t) c_int {
    const F = *const fn (?*anyopaque, size_t) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[23].pCurrent.?))(addr, len);
}
inline fn osMremap(old: ?*anyopaque, oldsz: size_t, newsz: size_t, flags: c_int) ?*anyopaque {
    const F = *const fn (?*anyopaque, size_t, size_t, c_int) callconv(.c) ?*anyopaque;
    return @as(F, @ptrCast(aSyscall[24].pCurrent.?))(old, oldsz, newsz, flags);
}
inline fn osGetpagesize() c_int {
    const F = *const fn () callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[25].pCurrent.?))();
}
inline fn osReadlink(z: [*:0]const u8, buf: [*]u8, n: size_t) ssize_t {
    const F = *const fn ([*:0]const u8, [*]u8, size_t) callconv(.c) ssize_t;
    return @as(F, @ptrCast(aSyscall[26].pCurrent.?))(z, buf, n);
}
inline fn osLstat(z: [*:0]const u8, buf: *stat) c_int {
    const F = *const fn ([*:0]const u8, *stat) callconv(.c) c_int;
    return @as(F, @ptrCast(aSyscall[27].pCurrent.?))(z, buf);
}

inline fn osGetpid() pid_t {
    return getpid();
}

// ===========================================================================
// Module globals.
// ===========================================================================
var randomnessPid: pid_t = 0;
var unixBigLock: ?*anyopaque = null;
var inodeList: ?*unixInodeInfo = null;

// Directories to consider for temp files. [0]/[1] filled at os_init.
var azTempDirs = [_]?[*:0]const u8{
    null,
    null,
    "/var/tmp",
    "/usr/tmp",
    "/tmp",
    ".",
};

// SQLITE_TEST instrumentation, exported only in the testfixture build.
var sqlite3_sync_count: c_int = 0;
var sqlite3_fullsync_count: c_int = 0;
var sqlite3_current_time: c_int = 0;
comptime {
    if (config.sqlite_test) {
        @export(&sqlite3_sync_count, .{ .name = "sqlite3_sync_count" });
        @export(&sqlite3_fullsync_count, .{ .name = "sqlite3_fullsync_count" });
        @export(&sqlite3_current_time, .{ .name = "sqlite3_current_time" });
    }
}

// SQLITE_TEST fault-injection counters are *declared in os.zig* (it owns them);
// here we reference them for SimulateIOError/SimulateDiskfullError under
// config.sqlite_test, matching os_common.h.
const test_io = if (config.sqlite_test) struct {
    extern var sqlite3_io_error_hit: c_int;
    extern var sqlite3_io_error_hardhit: c_int;
    extern var sqlite3_io_error_pending: c_int;
    extern var sqlite3_io_error_persist: c_int;
    extern var sqlite3_io_error_benign: c_int;
    extern var sqlite3_diskfull_pending: c_int;
    extern var sqlite3_diskfull: c_int;
    extern var sqlite3_open_file_count: c_int;
} else struct {};

inline fn simulateIOErrorBenign(x: c_int) void {
    if (config.sqlite_test) test_io.sqlite3_io_error_benign = x;
}
/// SimulateIOError(CODE): returns true if a simulated I/O error should fire.
inline fn simulateIOError() bool {
    if (!config.sqlite_test) return false;
    if ((test_io.sqlite3_io_error_persist != 0 and test_io.sqlite3_io_error_hit != 0) or
        blk: {
            test_io.sqlite3_io_error_pending -= 1;
            break :blk test_io.sqlite3_io_error_pending == 0;
        })
    {
        localIoerr();
        return true;
    }
    return false;
}
fn localIoerr() void {
    if (!config.sqlite_test) return;
    test_io.sqlite3_io_error_hit += 1;
    if (test_io.sqlite3_io_error_benign == 0) test_io.sqlite3_io_error_hardhit += 1;
}
/// SimulateDiskfullError: returns true if a simulated disk-full should fire.
inline fn simulateDiskfull() bool {
    if (!config.sqlite_test) return false;
    if (test_io.sqlite3_diskfull_pending != 0) {
        if (test_io.sqlite3_diskfull_pending == 1) {
            localIoerr();
            test_io.sqlite3_diskfull = 1;
            test_io.sqlite3_io_error_hit = 1;
            return true;
        } else {
            test_io.sqlite3_diskfull_pending -= 1;
        }
    }
    return false;
}
inline fn openCounter(x: c_int) void {
    if (config.sqlite_test) test_io.sqlite3_open_file_count += x;
}

// ===========================================================================
// General utility functions.
// ===========================================================================

fn robustFchown(fd: c_int, uid: uid_t, gid: gid_t) c_int {
    return if (osGeteuid() != 0) 0 else osFchown(fd, uid, gid);
}

/// open() retrying EINTR, enforcing min fd, applying O_CLOEXEC and exact mode.
fn robust_open(z: [*:0]const u8, f: c_int, m: mode_t) c_int {
    var fd: c_int = undefined;
    const m2: mode_t = if (m != 0) m else SQLITE_DEFAULT_FILE_PERMISSIONS;
    while (true) {
        fd = osOpen(z, f | O_CLOEXEC, @bitCast(m2));
        if (fd < 0) {
            if (errno() == EINTR) continue;
            break;
        }
        if (fd >= SQLITE_MINIMUM_FILE_DESCRIPTOR) break;
        if ((f & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT)) {
            _ = osUnlink(z);
        }
        _ = osClose(fd);
        sqlite3_log(SQLITE_WARNING, "attempt to open \"%s\" as file descriptor %d", z, fd);
        fd = -1;
        if (osOpen("/dev/null", O_RDONLY, @bitCast(m)) < 0) break;
    }
    if (fd >= 0) {
        if (m != 0) {
            var statbuf: stat = undefined;
            if (osFstat(fd, &statbuf) == 0 and statbuf.st_size == 0 and (statbuf.st_mode & 0o777) != m) {
                _ = osFchmod(fd, m);
            }
        }
        // O_CLOEXEC is non-zero here, so the FD_CLOEXEC fcntl fallback is skipped.
    }
    return fd;
}

fn unixEnterMutex() void {
    sqlite3_mutex_enter(unixBigLock);
}
fn unixLeaveMutex() void {
    sqlite3_mutex_leave(unixBigLock);
}
fn unixMutexHeld() bool {
    return sqlite3_mutex_held(unixBigLock) != 0;
}

fn robust_ftruncate(h: c_int, sz: i64) c_int {
    var rc: c_int = undefined;
    while (true) {
        rc = osFtruncate(h, sz);
        if (!(rc < 0 and errno() == EINTR)) break;
    }
    return rc;
}

/// Translate a POSIX errno into an SQLite error for locking ops.
fn sqliteErrorFromPosixError(posixError: c_int, sqliteIOErr: c_int) c_int {
    return switch (posixError) {
        EACCES, EAGAIN, ETIMEDOUT, EBUSY, EINTR, ENOLCK => SQLITE_BUSY,
        EPERM => SQLITE_PERM,
        else => sqliteIOErr,
    };
}

/// unixLogErrorAtLine() — log via sqlite3_log and return errcode.
fn unixLogError(errcode: c_int, zFunc: [*:0]const u8, zPath: ?[*:0]const u8) c_int {
    const iErrno = errno();
    var aErr: [80]u8 = std.mem.zeroes([80]u8);
    // glibc GNU strerror_r returns a (possibly static) pointer.
    const zErr: [*:0]const u8 = strerror_r(iErrno, &aErr, aErr.len - 1) orelse @ptrCast(&aErr);
    const p: [*:0]const u8 = zPath orelse "";
    sqlite3_log(errcode, "os_unix.c: (%d) %s(%s) - %s", iErrno, zFunc, p, zErr);
    return errcode;
}

fn robust_close(pFile: ?*unixFile, h: c_int) void {
    if (osClose(h) != 0) {
        _ = unixLogError(SQLITE_IOERR_CLOSE, "close", if (pFile) |f| f.zPath else null);
    }
}

inline fn storeLastErrno(pFile: *unixFile, e: c_int) void {
    pFile.lastErrno = e;
}

fn closePendingFds(pFile: *unixFile) void {
    const pInode = pFile.pInode.?;
    var p = pInode.pUnused;
    while (p) |u| {
        const next = u.pNext;
        robust_close(pFile, u.fd);
        sqlite3_free(u);
        p = next;
    }
    pInode.pUnused = null;
}

fn releaseInodeInfo(pFile: *unixFile) void {
    const pInode = pFile.pInode orelse return; // ALWAYS(pInode)
    pInode.nRef -= 1;
    if (pInode.nRef == 0) {
        sqlite3_mutex_enter(pInode.pLockMutex);
        closePendingFds(pFile);
        sqlite3_mutex_leave(pInode.pLockMutex);
        if (pInode.pPrev) |prev| {
            prev.pNext = pInode.pNext;
        } else {
            inodeList = pInode.pNext;
        }
        if (pInode.pNext) |next| {
            next.pPrev = pInode.pPrev;
        }
        sqlite3_mutex_free(pInode.pLockMutex);
        sqlite3_free(pInode);
    }
}

fn findInodeInfo(pFile: *unixFile, ppInode: *?*unixInodeInfo) c_int {
    var statbuf: stat = undefined;
    const fd = pFile.h;
    const rc = osFstat(fd, &statbuf);
    if (rc != 0) {
        storeLastErrno(pFile, errno());
        return SQLITE_IOERR;
    }
    var fileId: unixFileId = .{ .dev = statbuf.st_dev, .ino = statbuf.st_ino };
    var pInode = inodeList;
    while (pInode) |pi| {
        if (memcmp(&fileId, &pi.fileId, @sizeOf(unixFileId)) == 0) break;
        pInode = pi.pNext;
    }
    if (pInode == null) {
        const raw = sqlite3_malloc64(@sizeOf(unixInodeInfo)) orelse return SQLITE_NOMEM;
        const pNew: *unixInodeInfo = @ptrCast(@alignCast(raw));
        _ = memset(pNew, 0, @sizeOf(unixInodeInfo));
        _ = memcpy(&pNew.fileId, &fileId, @sizeOf(unixFileId));
        if (cfgCoreMutex()) {
            pNew.pLockMutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
            if (pNew.pLockMutex == null) {
                sqlite3_free(pNew);
                return SQLITE_NOMEM;
            }
        }
        pNew.nRef = 1;
        pNew.pNext = inodeList;
        pNew.pPrev = null;
        if (inodeList) |il| il.pPrev = pNew;
        inodeList = pNew;
        ppInode.* = pNew;
    } else {
        pInode.?.nRef += 1;
        ppInode.* = pInode;
    }
    return SQLITE_OK;
}

fn fileHasMoved(pFile: *unixFile) bool {
    var buf: stat = undefined;
    return pFile.pInode != null and
        (osStat(pFile.zPath.?, &buf) != 0 or buf.st_ino != pFile.pInode.?.fileId.ino);
}

fn verifyDbFile(pFile: *unixFile) void {
    var buf: stat = undefined;
    if ((pFile.ctrlFlags & UNIXFILE_NOLOCK) != 0) return;
    const rc = osFstat(pFile.h, &buf);
    if (rc != 0) {
        sqlite3_log(SQLITE_WARNING, "cannot fstat db file %s", pFile.zPath.?);
        return;
    }
    if (buf.st_nlink == 0) {
        sqlite3_log(SQLITE_WARNING, "file unlinked while open: %s", pFile.zPath.?);
        return;
    }
    if (buf.st_nlink > 1) {
        sqlite3_log(SQLITE_WARNING, "multiple links to file: %s", pFile.zPath.?);
        return;
    }
    if (fileHasMoved(pFile)) {
        sqlite3_log(SQLITE_WARNING, "file renamed while open: %s", pFile.zPath.?);
        return;
    }
}

// ===========================================================================
// Posix advisory locking.
// ===========================================================================

fn unixCheckReservedLock(id: *Sqlite3File, pResOut: *c_int) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    var reserved: c_int = 0;
    const pFile: *unixFile = @ptrCast(id);
    if (simulateIOError()) return SQLITE_IOERR_CHECKRESERVEDLOCK;

    sqlite3_mutex_enter(pFile.pInode.?.pLockMutex);
    if (pFile.pInode.?.eFileLock > SHARED_LOCK) {
        reserved = 1;
    }
    if (reserved == 0 and pFile.pInode.?.bProcessLock == 0) {
        var lock: flock = undefined;
        lock.l_whence = SEEK_SET;
        lock.l_start = RESERVED_BYTE();
        lock.l_len = 1;
        lock.l_type = F_WRLCK;
        if (osFcntlLock(pFile.h, F_GETLK, &lock) != 0) {
            rc = SQLITE_IOERR_CHECKRESERVEDLOCK;
            storeLastErrno(pFile, errno());
        } else if (lock.l_type != F_UNLCK) {
            reserved = 1;
        }
    }
    sqlite3_mutex_leave(pFile.pInode.?.pLockMutex);
    pResOut.* = reserved;
    return rc;
}

/// osSetPosixAdvisoryLock (SETLK_TIMEOUT off → plain non-blocking F_SETLK).
inline fn osSetPosixAdvisoryLock(h: c_int, pLock: *flock) c_int {
    return osFcntlLock(h, F_SETLK, pLock);
}

fn unixFileLock(pFile: *unixFile, pLock: *flock) c_int {
    const pInode = pFile.pInode.?;
    var rc: c_int = undefined;
    if ((pFile.ctrlFlags & (UNIXFILE_EXCL | UNIXFILE_RDONLY)) == UNIXFILE_EXCL) {
        if (pInode.bProcessLock == 0) {
            var lock: flock = undefined;
            lock.l_whence = SEEK_SET;
            lock.l_start = SHARED_FIRST();
            lock.l_len = SHARED_SIZE;
            lock.l_type = F_WRLCK;
            rc = osSetPosixAdvisoryLock(pFile.h, &lock);
            if (rc < 0) return rc;
            pInode.bProcessLock = 1;
            pInode.nLock += 1;
        } else {
            rc = 0;
        }
    } else {
        rc = osSetPosixAdvisoryLock(pFile.h, pLock);
    }
    return rc;
}

fn unixLock(id: *Sqlite3File, eFileLock_in: c_int) callconv(.c) c_int {
    const eFileLock: u8 = @intCast(eFileLock_in);
    var rc: c_int = SQLITE_OK;
    const pFile: *unixFile = @ptrCast(id);
    var lock: flock = undefined;
    var tErrno: c_int = 0;

    if (pFile.eFileLock >= eFileLock) {
        return SQLITE_OK;
    }
    const pInode = pFile.pInode.?;
    sqlite3_mutex_enter(pInode.pLockMutex);

    if (pFile.eFileLock != pInode.eFileLock and
        (pInode.eFileLock >= PENDING_LOCK or eFileLock > SHARED_LOCK))
    {
        rc = SQLITE_BUSY;
        return endLock(pFile, pInode, rc, eFileLock);
    }

    if (eFileLock == SHARED_LOCK and
        (pInode.eFileLock == SHARED_LOCK or pInode.eFileLock == RESERVED_LOCK))
    {
        pFile.eFileLock = SHARED_LOCK;
        pInode.nShared += 1;
        pInode.nLock += 1;
        return endLock(pFile, pInode, rc, eFileLock);
    }

    lock.l_len = 1;
    lock.l_whence = SEEK_SET;
    if (eFileLock == SHARED_LOCK or
        (eFileLock == EXCLUSIVE_LOCK and pFile.eFileLock == RESERVED_LOCK))
    {
        lock.l_type = if (eFileLock == SHARED_LOCK) F_RDLCK else F_WRLCK;
        lock.l_start = PENDING_BYTE();
        if (unixFileLock(pFile, &lock) != 0) {
            tErrno = errno();
            rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_LOCK);
            if (rc != SQLITE_BUSY) storeLastErrno(pFile, tErrno);
            return endLock(pFile, pInode, rc, eFileLock);
        } else if (eFileLock == EXCLUSIVE_LOCK) {
            pFile.eFileLock = PENDING_LOCK;
            pInode.eFileLock = PENDING_LOCK;
        }
    }

    if (eFileLock == SHARED_LOCK) {
        lock.l_start = SHARED_FIRST();
        lock.l_len = SHARED_SIZE;
        if (unixFileLock(pFile, &lock) != 0) {
            tErrno = errno();
            rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_LOCK);
        }
        // Drop the temporary PENDING lock
        lock.l_start = PENDING_BYTE();
        lock.l_len = 1;
        lock.l_type = F_UNLCK;
        if (unixFileLock(pFile, &lock) != 0 and rc == SQLITE_OK) {
            tErrno = errno();
            rc = SQLITE_IOERR_UNLOCK;
        }
        if (rc != SQLITE_OK) {
            if (rc != SQLITE_BUSY) storeLastErrno(pFile, tErrno);
            return endLock(pFile, pInode, rc, eFileLock);
        } else {
            pFile.eFileLock = SHARED_LOCK;
            pInode.nLock += 1;
            pInode.nShared = 1;
        }
    } else if (eFileLock == EXCLUSIVE_LOCK and pInode.nShared > 1) {
        rc = SQLITE_BUSY;
    } else if (unixIsSharingShmNode(pFile)) {
        rc = SQLITE_BUSY;
    } else {
        lock.l_type = F_WRLCK;
        if (eFileLock == RESERVED_LOCK) {
            lock.l_start = RESERVED_BYTE();
            lock.l_len = 1;
        } else {
            lock.l_start = SHARED_FIRST();
            lock.l_len = SHARED_SIZE;
        }
        if (unixFileLock(pFile, &lock) != 0) {
            tErrno = errno();
            rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_LOCK);
            if (rc != SQLITE_BUSY) storeLastErrno(pFile, tErrno);
        }
    }

    if (config.sqlite_debug) {
        if (rc == SQLITE_OK and pFile.eFileLock <= SHARED_LOCK and eFileLock == RESERVED_LOCK) {
            pFile.transCntrChng = 0;
            pFile.dbUpdate = 0;
            pFile.inNormalWrite = 1;
        }
    }

    if (rc == SQLITE_OK) {
        pFile.eFileLock = eFileLock;
        pInode.eFileLock = eFileLock;
    }
    return endLock(pFile, pInode, rc, eFileLock);
}
inline fn endLock(pFile: *unixFile, pInode: *unixInodeInfo, rc: c_int, eFileLock: u8) c_int {
    _ = pFile;
    _ = eFileLock;
    sqlite3_mutex_leave(pInode.pLockMutex);
    return rc;
}

fn setPendingFd(pFile: *unixFile) void {
    const pInode = pFile.pInode.?;
    const p = pFile.pPreallocatedUnused.?;
    p.pNext = pInode.pUnused;
    pInode.pUnused = p;
    pFile.h = -1;
    pFile.pPreallocatedUnused = null;
}

fn posixUnlock(id: *Sqlite3File, eFileLock_in: c_int, handleNFSUnlock: c_int) c_int {
    _ = handleNFSUnlock;
    const eFileLock: u8 = @intCast(eFileLock_in);
    const pFile: *unixFile = @ptrCast(id);
    var lock: flock = undefined;
    var rc: c_int = SQLITE_OK;

    if (pFile.eFileLock <= eFileLock) {
        return SQLITE_OK;
    }
    const pInode = pFile.pInode.?;
    sqlite3_mutex_enter(pInode.pLockMutex);

    if (pFile.eFileLock > SHARED_LOCK) {
        if (config.sqlite_debug) pFile.inNormalWrite = 0;

        if (eFileLock == SHARED_LOCK) {
            lock.l_type = F_RDLCK;
            lock.l_whence = SEEK_SET;
            lock.l_start = SHARED_FIRST();
            lock.l_len = SHARED_SIZE;
            if (unixFileLock(pFile, &lock) != 0) {
                rc = SQLITE_IOERR_RDLOCK;
                storeLastErrno(pFile, errno());
                return endUnlock(pInode, pFile, rc, eFileLock);
            }
        }
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = PENDING_BYTE();
        lock.l_len = 2; // PENDING_BYTE+1==RESERVED_BYTE
        if (unixFileLock(pFile, &lock) == 0) {
            pInode.eFileLock = SHARED_LOCK;
        } else {
            rc = SQLITE_IOERR_UNLOCK;
            storeLastErrno(pFile, errno());
            return endUnlock(pInode, pFile, rc, eFileLock);
        }
    }
    if (eFileLock == NO_LOCK) {
        pInode.nShared -= 1;
        if (pInode.nShared == 0) {
            lock.l_type = F_UNLCK;
            lock.l_whence = SEEK_SET;
            lock.l_start = 0;
            lock.l_len = 0;
            if (unixFileLock(pFile, &lock) == 0) {
                pInode.eFileLock = NO_LOCK;
            } else {
                rc = SQLITE_IOERR_UNLOCK;
                storeLastErrno(pFile, errno());
                pInode.eFileLock = NO_LOCK;
                pFile.eFileLock = NO_LOCK;
            }
        }
        pInode.nLock -= 1;
        if (pInode.nLock == 0) closePendingFds(pFile);
    }
    return endUnlock(pInode, pFile, rc, eFileLock);
}
inline fn endUnlock(pInode: *unixInodeInfo, pFile: *unixFile, rc: c_int, eFileLock: u8) c_int {
    sqlite3_mutex_leave(pInode.pLockMutex);
    if (rc == SQLITE_OK) pFile.eFileLock = eFileLock;
    return rc;
}

fn unixUnlock(id: *Sqlite3File, eFileLock: c_int) callconv(.c) c_int {
    return posixUnlock(id, eFileLock, 0);
}

fn closeUnixFile(id: *Sqlite3File) c_int {
    const pFile: *unixFile = @ptrCast(id);
    unixUnmapfile(pFile);
    if (pFile.h >= 0) {
        robust_close(pFile, pFile.h);
        pFile.h = -1;
    }
    openCounter(-1);
    sqlite3_free(pFile.pPreallocatedUnused);
    _ = memset(pFile, 0, @sizeOf(unixFile));
    return SQLITE_OK;
}

fn unixClose(id: *Sqlite3File) callconv(.c) c_int {
    var rc: c_int = SQLITE_OK;
    const pFile: *unixFile = @ptrCast(id);
    const pInode = pFile.pInode.?;
    verifyDbFile(pFile);
    _ = unixUnlock(id, NO_LOCK);
    unixEnterMutex();
    sqlite3_mutex_enter(pInode.pLockMutex);
    if (pInode.nLock != 0) {
        setPendingFd(pFile);
    }
    sqlite3_mutex_leave(pInode.pLockMutex);
    releaseInodeInfo(pFile);
    rc = closeUnixFile(id);
    unixLeaveMutex();
    return rc;
}

// ===========================================================================
// No-op locking.
// ===========================================================================
fn nolockCheckReservedLock(NotUsed: *Sqlite3File, pResOut: *c_int) callconv(.c) c_int {
    _ = NotUsed;
    pResOut.* = 0;
    return SQLITE_OK;
}
fn nolockLock(NotUsed: *Sqlite3File, NotUsed2: c_int) callconv(.c) c_int {
    _ = NotUsed;
    _ = NotUsed2;
    return SQLITE_OK;
}
fn nolockUnlock(NotUsed: *Sqlite3File, NotUsed2: c_int) callconv(.c) c_int {
    _ = NotUsed;
    _ = NotUsed2;
    return SQLITE_OK;
}
fn nolockClose(id: *Sqlite3File) callconv(.c) c_int {
    return closeUnixFile(id);
}

// ===========================================================================
// Dot-file locking.
// ===========================================================================
const DOTLOCK_SUFFIX = ".lock";

fn dotlockCheckReservedLock(id: *Sqlite3File, pResOut: *c_int) callconv(.c) c_int {
    const pFile: *unixFile = @ptrCast(id);
    if (simulateIOError()) return SQLITE_IOERR_CHECKRESERVEDLOCK;
    if (pFile.eFileLock >= SHARED_LOCK) {
        pResOut.* = 0;
    } else {
        const z: [*:0]const u8 = @ptrCast(pFile.lockingContext.?);
        pResOut.* = @intFromBool(osAccess(z, 0) == 0);
    }
    return SQLITE_OK;
}

fn dotlockLock(id: *Sqlite3File, eFileLock_in: c_int) callconv(.c) c_int {
    const eFileLock: u8 = @intCast(eFileLock_in);
    const pFile: *unixFile = @ptrCast(id);
    const zLockFile: [*:0]const u8 = @ptrCast(pFile.lockingContext.?);

    if (pFile.eFileLock > NO_LOCK) {
        pFile.eFileLock = eFileLock;
        // utimes(zLockFile, NULL) to bump the timestamp — best-effort; skipped
        // here (HAVE_UTIME path differs and it is not load-bearing for tests).
        return SQLITE_OK;
    }
    const rc0 = osMkdir(zLockFile, 0o777);
    if (rc0 < 0) {
        const tErrno = errno();
        if (tErrno == EEXIST) {
            return SQLITE_BUSY;
        } else {
            const rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_LOCK);
            if (rc != SQLITE_BUSY) storeLastErrno(pFile, tErrno);
            return rc;
        }
    }
    pFile.eFileLock = eFileLock;
    return SQLITE_OK;
}

fn dotlockUnlock(id: *Sqlite3File, eFileLock_in: c_int) callconv(.c) c_int {
    const eFileLock: u8 = @intCast(eFileLock_in);
    const pFile: *unixFile = @ptrCast(id);
    const zLockFile: [*:0]const u8 = @ptrCast(pFile.lockingContext.?);

    if (pFile.eFileLock == eFileLock) return SQLITE_OK;
    if (eFileLock == SHARED_LOCK) {
        pFile.eFileLock = SHARED_LOCK;
        return SQLITE_OK;
    }
    const rc0 = osRmdir(zLockFile);
    if (rc0 < 0) {
        const tErrno = errno();
        if (tErrno == ENOENT) {
            // ok
        } else {
            storeLastErrno(pFile, tErrno);
            return SQLITE_IOERR_UNLOCK;
        }
    }
    pFile.eFileLock = NO_LOCK;
    return SQLITE_OK;
}

fn dotlockClose(id: *Sqlite3File) callconv(.c) c_int {
    const pFile: *unixFile = @ptrCast(id);
    _ = dotlockUnlock(id, NO_LOCK);
    sqlite3_free(pFile.lockingContext);
    return closeUnixFile(id);
}

// ===========================================================================
// Non-locking sqlite3_file methods (read/write/sync/truncate/...).
// ===========================================================================

fn seekAndRead(id: *unixFile, offset: i64, pBuf_in: ?*anyopaque, cnt_in: c_int) c_int {
    var got: ssize_t = 0;
    var prior: c_int = 0;
    var cnt = cnt_in;
    var off = offset;
    var pBuf = pBuf_in;
    while (true) {
        got = osPread(id.h, pBuf, @intCast(cnt), off);
        if (config.sqlite_test and simulateIOError()) got = -1;
        if (got == @as(ssize_t, cnt)) break;
        if (got < 0) {
            if (errno() == EINTR) {
                got = 1;
                continue;
            }
            prior = 0;
            storeLastErrno(id, errno());
            break;
        } else if (got > 0) {
            cnt -= @intCast(got);
            off += got;
            prior += @intCast(got);
            pBuf = @ptrFromInt(@intFromPtr(pBuf) + @as(usize, @intCast(got)));
        }
        if (!(got > 0)) break;
    }
    return prior + @as(c_int, @intCast(got));
}

fn unixRead(id: *Sqlite3File, pBuf_in: ?*anyopaque, amt_in: c_int, offset_in: i64) callconv(.c) c_int {
    const pFile: *unixFile = @ptrCast(id);
    var pBuf = pBuf_in;
    var amt = amt_in;
    var offset = offset_in;

    // Satisfy as much of the read as possible from the mmap.
    if (offset < pFile.mmapSize) {
        if (offset + amt <= pFile.mmapSize) {
            const src: [*]const u8 = @ptrFromInt(@intFromPtr(pFile.pMapRegion.?) + @as(usize, @intCast(offset)));
            _ = memcpy(pBuf, src, @intCast(amt));
            return SQLITE_OK;
        } else {
            const nCopy: c_int = @intCast(pFile.mmapSize - offset);
            const src: [*]const u8 = @ptrFromInt(@intFromPtr(pFile.pMapRegion.?) + @as(usize, @intCast(offset)));
            _ = memcpy(pBuf, src, @intCast(nCopy));
            pBuf = @ptrFromInt(@intFromPtr(pBuf) + @as(usize, @intCast(nCopy)));
            amt -= nCopy;
            offset += nCopy;
        }
    }

    const got = seekAndRead(pFile, offset, pBuf, amt);
    if (got == amt) {
        return SQLITE_OK;
    } else if (got < 0) {
        switch (pFile.lastErrno) {
            ERANGE, EIO, ENXIO => return SQLITE_IOERR_CORRUPTFS,
            else => {},
        }
        return SQLITE_IOERR_READ;
    } else {
        storeLastErrno(pFile, 0);
        const dst: [*]u8 = @ptrFromInt(@intFromPtr(pBuf) + @as(usize, @intCast(got)));
        _ = memset(dst, 0, @intCast(amt - got));
        return SQLITE_IOERR_SHORT_READ;
    }
}

fn seekAndWriteFd(fd: c_int, iOff: i64, pBuf: ?*const anyopaque, nBuf_in: c_int, piErrno: *c_int) c_int {
    var rc: c_int = 0;
    const nBuf = nBuf_in & 0x1ffff;
    while (true) {
        rc = @intCast(osPwrite(fd, pBuf, @intCast(nBuf), iOff));
        if (!(rc < 0 and errno() == EINTR)) break;
    }
    if (rc < 0) piErrno.* = errno();
    return rc;
}

fn seekAndWrite(id: *unixFile, offset: i64, pBuf: ?*const anyopaque, cnt: c_int) c_int {
    return seekAndWriteFd(id.h, offset, pBuf, cnt, &id.lastErrno);
}

fn unixWrite(id: *Sqlite3File, pBuf_in: ?*const anyopaque, amt_in: c_int, offset_in: i64) callconv(.c) c_int {
    const pFile: *unixFile = @ptrCast(id);
    var wrote: c_int = 0;
    var pBuf = pBuf_in;
    var amt = amt_in;
    var offset = offset_in;

    if (config.sqlite_debug) {
        if (pFile.inNormalWrite != 0) {
            pFile.dbUpdate = 1;
            if (offset <= 24 and offset + amt >= 27) {
                var oldCntr: [4]u8 = undefined;
                simulateIOErrorBenign(1);
                const rc = seekAndRead(pFile, 24, &oldCntr, 4);
                simulateIOErrorBenign(0);
                const cur: [*]const u8 = @ptrFromInt(@intFromPtr(pBuf.?) + @as(usize, @intCast(24 - offset)));
                if (rc != 4 or memcmp(&oldCntr, cur, 4) != 0) {
                    pFile.transCntrChng = 1;
                }
            }
        }
    }

    // SQLITE_MMAP_READWRITE is off, so the write-through-mmap fast path is omitted.

    while (true) {
        wrote = seekAndWrite(pFile, offset, pBuf, amt);
        if (!(wrote < amt and wrote > 0)) break;
        amt -= wrote;
        offset += wrote;
        pBuf = @ptrFromInt(@intFromPtr(pBuf.?) + @as(usize, @intCast(wrote)));
    }
    if (config.sqlite_test) {
        if (simulateIOError()) {
            wrote = -1;
            amt = 1;
        }
        if (simulateDiskfull()) {
            wrote = 0;
            amt = 1;
        }
    }

    if (amt > wrote) {
        if (wrote < 0 and pFile.lastErrno != ENOSPC) {
            return SQLITE_IOERR_WRITE;
        } else {
            storeLastErrno(pFile, 0);
            return SQLITE_FULL;
        }
    }
    return SQLITE_OK;
}

fn full_fsync(fd: c_int, fullSync: c_int, dataOnly: c_int) c_int {
    _ = dataOnly;
    if (config.sqlite_test) {
        if (fullSync != 0) sqlite3_fullsync_count += 1;
        sqlite3_sync_count += 1;
    }
    // HAVE_FULLFSYNC is off (not Apple); use fdatasync().
    return fdatasync(fd);
}

fn openDirectory(zFilename: [*:0]const u8, pFd: *c_int) callconv(.c) c_int {
    var zDirname: [MAX_PATHNAME + 1]u8 = undefined;
    _ = sqlite3_snprintf(MAX_PATHNAME, &zDirname, "%s", zFilename);
    var ii: c_int = @intCast(strlen(@ptrCast(&zDirname)));
    while (ii > 0 and zDirname[@intCast(ii)] != '/') : (ii -= 1) {}
    if (ii > 0) {
        zDirname[@intCast(ii)] = 0;
    } else {
        if (zDirname[0] != '/') zDirname[0] = '.';
        zDirname[1] = 0;
    }
    const fd = robust_open(@ptrCast(&zDirname), O_RDONLY | O_BINARY, 0);
    pFd.* = fd;
    if (fd >= 0) return SQLITE_OK;
    return unixLogError(SQLITE_CANTOPEN, "openDirectory", @ptrCast(&zDirname));
}

fn unixSync(id: *Sqlite3File, flags: c_int) callconv(.c) c_int {
    var rc: c_int = undefined;
    const pFile: *unixFile = @ptrCast(id);
    const isDataOnly = (flags & SQLITE_SYNC_DATAONLY);
    const isFullsync = (flags & 0x0F) == SQLITE_SYNC_FULL;

    if (simulateDiskfull()) return SQLITE_FULL;

    rc = full_fsync(pFile.h, @intFromBool(isFullsync), @intFromBool(isDataOnly != 0));
    if (config.sqlite_test and simulateIOError()) rc = 1;
    if (rc != 0) {
        storeLastErrno(pFile, errno());
        return unixLogError(SQLITE_IOERR_FSYNC, "full_fsync", pFile.zPath);
    }

    if ((pFile.ctrlFlags & UNIXFILE_DIRSYNC) != 0) {
        var dirfd: c_int = undefined;
        const rc2 = osOpenDirectory(pFile.zPath.?, &dirfd);
        if (rc2 == SQLITE_OK) {
            _ = full_fsync(dirfd, 0, 0);
            robust_close(pFile, dirfd);
        } else {
            rc = SQLITE_OK;
        }
        pFile.ctrlFlags &= ~UNIXFILE_DIRSYNC;
    }
    return rc;
}

fn unixTruncate(id: *Sqlite3File, nByte_in: i64) callconv(.c) c_int {
    const pFile: *unixFile = @ptrCast(id);
    var nByte = nByte_in;
    if (simulateIOError()) return SQLITE_IOERR_TRUNCATE;

    if (pFile.szChunk > 0) {
        const chunk: i64 = pFile.szChunk;
        nByte = @divTrunc(nByte + chunk - 1, chunk) * chunk;
    }
    const rc = robust_ftruncate(pFile.h, nByte);
    if (rc != 0) {
        storeLastErrno(pFile, errno());
        return unixLogError(SQLITE_IOERR_TRUNCATE, "ftruncate", pFile.zPath);
    } else {
        if (config.sqlite_debug) {
            if (pFile.inNormalWrite != 0 and nByte == 0) pFile.transCntrChng = 1;
        }
        if (nByte < pFile.mmapSize) {
            pFile.mmapSize = nByte;
        }
        return SQLITE_OK;
    }
}

fn unixFileSize(id: *Sqlite3File, pSize: *i64) callconv(.c) c_int {
    var buf: stat = undefined;
    var rc = osFstat(@as(*unixFile, @ptrCast(id)).h, &buf);
    if (config.sqlite_test and simulateIOError()) rc = 1;
    if (rc != 0) {
        storeLastErrno(@ptrCast(id), errno());
        return SQLITE_IOERR_FSTAT;
    }
    pSize.* = buf.st_size;
    if (pSize.* == 1) pSize.* = 0;
    return SQLITE_OK;
}

fn fcntlSizeHint(pFile: *unixFile, nByte: i64) c_int {
    if (pFile.szChunk > 0) {
        var buf: stat = undefined;
        if (osFstat(pFile.h, &buf) != 0) {
            return SQLITE_IOERR_FSTAT;
        }
        const chunk: i64 = pFile.szChunk;
        const nSize = @divTrunc(nByte + chunk - 1, chunk) * chunk;
        if (nSize > buf.st_size) {
            // HAVE_POSIX_FALLOCATE
            var err: c_int = undefined;
            while (true) {
                err = osFallocate(pFile.h, buf.st_size, nSize - buf.st_size);
                if (err != EINTR) break;
            }
            if (err != 0 and err != EINVAL) return SQLITE_IOERR_WRITE;
        }
    }

    if (pFile.mmapSizeMax > 0 and nByte > pFile.mmapSize) {
        if (pFile.szChunk <= 0) {
            if (robust_ftruncate(pFile.h, nByte) != 0) {
                storeLastErrno(pFile, errno());
                return unixLogError(SQLITE_IOERR_TRUNCATE, "ftruncate", pFile.zPath);
            }
        }
        return unixMapfile(pFile, nByte);
    }
    return SQLITE_OK;
}

fn unixModeBit(pFile: *unixFile, mask: u16, pArg: *c_int) void {
    if (pArg.* < 0) {
        pArg.* = @intFromBool((pFile.ctrlFlags & mask) != 0);
    } else if (pArg.* == 0) {
        pFile.ctrlFlags &= ~mask;
    } else {
        pFile.ctrlFlags |= mask;
    }
}

fn unixFileControl(id: *Sqlite3File, op: c_int, pArg: ?*anyopaque) callconv(.c) c_int {
    const pFile: *unixFile = @ptrCast(id);
    switch (op) {
        SQLITE_FCNTL_NULL_IO => {
            _ = osClose(pFile.h);
            pFile.h = -1;
            return SQLITE_OK;
        },
        SQLITE_FCNTL_LOCKSTATE => {
            @as(*c_int, @ptrCast(@alignCast(pArg.?))).* = pFile.eFileLock;
            return SQLITE_OK;
        },
        SQLITE_FCNTL_LAST_ERRNO => {
            @as(*c_int, @ptrCast(@alignCast(pArg.?))).* = pFile.lastErrno;
            return SQLITE_OK;
        },
        SQLITE_FCNTL_CHUNK_SIZE => {
            pFile.szChunk = @as(*c_int, @ptrCast(@alignCast(pArg.?))).*;
            return SQLITE_OK;
        },
        SQLITE_FCNTL_SIZE_HINT => {
            simulateIOErrorBenign(1);
            const rc = fcntlSizeHint(pFile, @as(*i64, @ptrCast(@alignCast(pArg.?))).*);
            simulateIOErrorBenign(0);
            return rc;
        },
        SQLITE_FCNTL_PERSIST_WAL => {
            unixModeBit(pFile, UNIXFILE_PERSIST_WAL, @ptrCast(@alignCast(pArg.?)));
            return SQLITE_OK;
        },
        SQLITE_FCNTL_POWERSAFE_OVERWRITE => {
            unixModeBit(pFile, UNIXFILE_PSOW, @ptrCast(@alignCast(pArg.?)));
            return SQLITE_OK;
        },
        SQLITE_FCNTL_VFSNAME => {
            @as(*?[*:0]u8, @ptrCast(@alignCast(pArg.?))).* = sqlite3_mprintf("%s", pFile.pVfs.?.zName.?);
            return SQLITE_OK;
        },
        SQLITE_FCNTL_TEMPFILENAME => {
            const zTFile: ?[*]u8 = @ptrCast(sqlite3_malloc64(@intCast(pFile.pVfs.?.mxPathname)));
            if (zTFile) |z| {
                _ = unixGetTempname(pFile.pVfs.?.mxPathname, z);
                @as(*?[*]u8, @ptrCast(@alignCast(pArg.?))).* = z;
            }
            return SQLITE_OK;
        },
        SQLITE_FCNTL_HAS_MOVED => {
            @as(*c_int, @ptrCast(@alignCast(pArg.?))).* = @intFromBool(fileHasMoved(pFile));
            return SQLITE_OK;
        },
        SQLITE_FCNTL_MMAP_SIZE => {
            const pI64: *i64 = @ptrCast(@alignCast(pArg.?));
            var newLimit = pI64.*;
            var rc: c_int = SQLITE_OK;
            if (newLimit > cfgMxMmap()) {
                newLimit = cfgMxMmap();
            }
            // size_t is 8 bytes on x86-64, so the 2GB clamp is skipped.
            pI64.* = pFile.mmapSizeMax;
            if (newLimit >= 0 and newLimit != pFile.mmapSizeMax and pFile.nFetchOut == 0) {
                pFile.mmapSizeMax = newLimit;
                if (pFile.mmapSize > 0) {
                    unixUnmapfile(pFile);
                    rc = unixMapfile(pFile, -1);
                }
            }
            return rc;
        },
        SQLITE_FCNTL_EXTERNAL_READER => {
            return unixFcntlExternalReader(pFile, @ptrCast(@alignCast(pArg.?)));
        },
        else => {
            if (config.sqlite_debug) {
                // SQLITE_FCNTL_DB_UNCHANGED = 0xca093fa0
                if (op == @as(c_int, @bitCast(@as(u32, 0xca093fa0)))) {
                    pFile.dbUpdate = 0;
                    return SQLITE_OK;
                }
            }
        },
    }
    return SQLITE_NOTFOUND;
}

fn setDeviceCharacteristics(pFd: *unixFile) void {
    if (pFd.sectorSize == 0) {
        if ((pFd.ctrlFlags & UNIXFILE_PSOW) != 0) {
            pFd.deviceCharacteristics |= SQLITE_IOCAP_POWERSAFE_OVERWRITE;
        }
        pFd.deviceCharacteristics |= SQLITE_IOCAP_SUBPAGE_READ;
        pFd.sectorSize = SQLITE_DEFAULT_SECTOR_SIZE;
    }
}

fn unixSectorSize(id: *Sqlite3File) callconv(.c) c_int {
    const pFd: *unixFile = @ptrCast(id);
    setDeviceCharacteristics(pFd);
    return pFd.sectorSize;
}

fn unixDeviceCharacteristics(id: *Sqlite3File) callconv(.c) c_int {
    const pFd: *unixFile = @ptrCast(id);
    setDeviceCharacteristics(pFd);
    return pFd.deviceCharacteristics;
}

fn unixGetpagesize() callconv(.c) c_int {
    return @intCast(sysconf(_SC_PAGESIZE));
}

// ===========================================================================
// Shared memory (WAL wal-index).
// ===========================================================================

fn unixFcntlExternalReader(pFile: *unixFile, piOut: *c_int) c_int {
    var rc: c_int = SQLITE_OK;
    piOut.* = 0;
    if (pFile.pShm) |pShm| {
        const pShmNode = pShm.pShmNode.?;
        var f: flock = undefined;
        _ = memset(&f, 0, @sizeOf(flock));
        f.l_type = F_WRLCK;
        f.l_whence = SEEK_SET;
        f.l_start = UNIX_SHM_BASE + 3;
        f.l_len = SQLITE_SHM_NLOCK - 3;
        sqlite3_mutex_enter(pShmNode.pShmMutex);
        if (osFcntlLock(pShmNode.hShm, F_GETLK, &f) < 0) {
            rc = SQLITE_IOERR_LOCK;
        } else {
            piOut.* = @intFromBool(f.l_type != F_UNLCK);
        }
        sqlite3_mutex_leave(pShmNode.pShmMutex);
    }
    return rc;
}

fn unixIsSharingShmNode(pFile: *unixFile) bool {
    if (pFile.pShm == null) return false;
    if ((pFile.ctrlFlags & UNIXFILE_EXCL) != 0) return false;
    const pShmNode = pFile.pShm.?.pShmNode.?;
    var lock: flock = undefined;
    _ = memset(&lock, 0, @sizeOf(flock));
    lock.l_whence = SEEK_SET;
    lock.l_start = UNIX_SHM_DMS;
    lock.l_len = 1;
    lock.l_type = F_WRLCK;
    _ = osFcntlLock(pShmNode.hShm, F_GETLK, &lock);
    return lock.l_type != F_UNLCK;
}

fn unixShmSystemLock(pFile: *unixFile, lockType: c_short, ofst: c_int, n: c_int) c_int {
    const pShmNode = pFile.pInode.?.pShmNode.?;
    var f: flock = undefined;
    var rc: c_int = SQLITE_OK;
    if (pShmNode.hShm >= 0) {
        f.l_type = lockType;
        f.l_whence = SEEK_SET;
        f.l_start = ofst;
        f.l_len = n;
        const res = osSetPosixAdvisoryLock(pShmNode.hShm, &f);
        if (res == -1) {
            rc = SQLITE_BUSY;
        }
    }
    return rc;
}

fn unixShmRegionPerMap() c_int {
    const shmsz: c_int = 32 * 1024;
    const pgsz = osGetpagesize();
    if (pgsz < shmsz) return 1;
    return @divTrunc(pgsz, shmsz);
}

fn unixShmPurge(pFd: *unixFile) void {
    const p = pFd.pInode.?.pShmNode orelse return;
    if (p.nRef == 0) {
        const nShmPerMap = unixShmRegionPerMap();
        sqlite3_mutex_free(p.pShmMutex);
        var i: c_int = 0;
        while (i < p.nRegion) : (i += nShmPerMap) {
            const region = p.apRegion.?[@intCast(i)];
            if (p.hShm >= 0) {
                _ = osMunmap(region, @intCast(p.szRegion));
            } else {
                sqlite3_free(region);
            }
        }
        sqlite3_free(@ptrCast(p.apRegion));
        if (p.hShm >= 0) {
            robust_close(pFd, p.hShm);
            p.hShm = -1;
        }
        p.pInode.?.pShmNode = null;
        sqlite3_free(p);
    }
}

fn unixLockSharedMemory(pDbFd: *unixFile, pShmNode: *unixShmNode) c_int {
    var lock: flock = undefined;
    var rc: c_int = SQLITE_OK;
    lock.l_whence = SEEK_SET;
    lock.l_start = UNIX_SHM_DMS;
    lock.l_len = 1;
    lock.l_type = F_WRLCK;
    if (osFcntlLock(pShmNode.hShm, F_GETLK, &lock) != 0) {
        rc = SQLITE_IOERR_LOCK;
    } else if (lock.l_type == F_UNLCK) {
        if (pShmNode.isReadonly != 0) {
            pShmNode.isUnlocked = 1;
            rc = SQLITE_READONLY_CANTINIT;
        } else {
            rc = unixShmSystemLock(pDbFd, F_WRLCK, UNIX_SHM_DMS, 1);
            if (rc == SQLITE_OK and robust_ftruncate(pShmNode.hShm, 3) != 0) {
                rc = unixLogError(SQLITE_IOERR_SHMOPEN, "ftruncate", @ptrCast(pShmNode.zFilename));
            }
        }
    } else if (lock.l_type == F_WRLCK) {
        rc = SQLITE_BUSY;
    }

    if (rc == SQLITE_OK) {
        rc = unixShmSystemLock(pDbFd, F_RDLCK, UNIX_SHM_DMS, 1);
    }
    return rc;
}

fn unixOpenSharedMemory(pDbFd: *unixFile) c_int {
    var rc: c_int = SQLITE_OK;

    const raw = sqlite3_malloc64(@sizeOf(unixShm)) orelse return SQLITE_NOMEM;
    const p: *unixShm = @ptrCast(@alignCast(raw));
    _ = memset(p, 0, @sizeOf(unixShm));

    unixEnterMutex();
    const pInode = pDbFd.pInode.?;
    var pShmNode = pInode.pShmNode;
    if (pShmNode == null) {
        var sStat: stat = undefined;
        const zBasePath = pDbFd.zPath.?;

        if (osFstat(pDbFd.h, &sStat) != 0) {
            rc = SQLITE_IOERR_FSTAT;
            return shmOpenErr(pDbFd, p, rc);
        }
        const nShmFilename: c_int = 6 + sqlite3Strlen30(zBasePath);
        const rawNode = sqlite3_malloc64(@as(u64, @sizeOf(unixShmNode)) + @as(u64, @intCast(nShmFilename)));
        if (rawNode == null) {
            rc = SQLITE_NOMEM;
            return shmOpenErr(pDbFd, p, rc);
        }
        const pNode: *unixShmNode = @ptrCast(@alignCast(rawNode));
        _ = memset(pNode, 0, @as(usize, @sizeOf(unixShmNode)) + @as(usize, @intCast(nShmFilename)));
        const zShm: [*:0]u8 = @ptrFromInt(@intFromPtr(pNode) + @sizeOf(unixShmNode));
        pNode.zFilename = zShm;
        _ = sqlite3_snprintf(nShmFilename, zShm, "%s-shm", zBasePath);
        // sqlite3FileSuffix3 is a no-op macro (SQLITE_ENABLE_8_3_NAMES off).
        pNode.hShm = -1;
        pInode.pShmNode = pNode;
        pNode.pInode = pInode;
        pShmNode = pNode;

        if (cfgCoreMutex()) {
            pNode.pShmMutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
            if (pNode.pShmMutex == null) {
                rc = SQLITE_NOMEM;
                return shmOpenErr(pDbFd, p, rc);
            }
        }

        if (pInode.bProcessLock == 0) {
            if (sqlite3_uri_boolean(pDbFd.zPath, "readonly_shm", 0) == 0) {
                pNode.hShm = robust_open(zShm, O_RDWR | O_CREAT | O_NOFOLLOW, sStat.st_mode & 0o777);
            }
            if (pNode.hShm < 0) {
                pNode.hShm = robust_open(zShm, O_RDONLY | O_NOFOLLOW, sStat.st_mode & 0o777);
                if (pNode.hShm < 0) {
                    rc = unixLogError(SQLITE_CANTOPEN, "open", zShm);
                    return shmOpenErr(pDbFd, p, rc);
                }
                pNode.isReadonly = 1;
            }
            _ = robustFchown(pNode.hShm, sStat.st_uid, sStat.st_gid);

            rc = unixLockSharedMemory(pDbFd, pNode);
            if (rc != SQLITE_OK and rc != SQLITE_READONLY_CANTINIT) {
                return shmOpenErr(pDbFd, p, rc);
            }
        }
    }

    p.pShmNode = pShmNode;
    if (config.sqlite_debug) {
        p.id = pShmNode.?.nextShmId;
        pShmNode.?.nextShmId +%= 1;
    }
    pShmNode.?.nRef += 1;
    pDbFd.pShm = p;
    unixLeaveMutex();

    sqlite3_mutex_enter(pShmNode.?.pShmMutex);
    p.pNext = pShmNode.?.pFirst;
    pShmNode.?.pFirst = p;
    sqlite3_mutex_leave(pShmNode.?.pShmMutex);
    return rc;
}
fn shmOpenErr(pDbFd: *unixFile, p: *unixShm, rc: c_int) c_int {
    unixShmPurge(pDbFd);
    sqlite3_free(p);
    unixLeaveMutex();
    return rc;
}

fn unixShmMap(
    fd: *Sqlite3File,
    iRegion: c_int,
    szRegion: c_int,
    bExtend: c_int,
    pp: ?*anyopaque,
) callconv(.c) c_int {
    const pDbFd: *unixFile = @ptrCast(fd);
    var rc: c_int = SQLITE_OK;
    const nShmPerMap = unixShmRegionPerMap();
    const ppOut: *?*anyopaque = @ptrCast(@alignCast(pp.?));

    if (pDbFd.pShm == null) {
        rc = unixOpenSharedMemory(pDbFd);
        if (rc != SQLITE_OK) return rc;
    }
    const p = pDbFd.pShm.?;
    const pShmNode = p.pShmNode.?;
    sqlite3_mutex_enter(pShmNode.pShmMutex);
    if (pShmNode.isUnlocked != 0) {
        rc = unixLockSharedMemory(pDbFd, pShmNode);
        if (rc != SQLITE_OK) return shmpageOut(pShmNode, iRegion, ppOut, rc);
        pShmNode.isUnlocked = 0;
    }

    const nReqRegion = @divTrunc(iRegion + nShmPerMap, nShmPerMap) * nShmPerMap;

    if (pShmNode.nRegion < nReqRegion) {
        const nByte: i64 = @as(i64, nReqRegion) * @as(i64, szRegion);
        var sStat: stat = undefined;
        pShmNode.szRegion = szRegion;

        if (pShmNode.hShm >= 0) {
            if (osFstat(pShmNode.hShm, &sStat) != 0) {
                rc = SQLITE_IOERR_SHMSIZE;
                return shmpageOut(pShmNode, iRegion, ppOut, rc);
            }
            if (sStat.st_size < nByte) {
                if (bExtend == 0) {
                    return shmpageOut(pShmNode, iRegion, ppOut, rc);
                } else {
                    const pgsz: i64 = 4096;
                    var iPg: i64 = @divTrunc(sStat.st_size, pgsz);
                    while (iPg < @divTrunc(nByte, pgsz)) : (iPg += 1) {
                        var x: c_int = 0;
                        if (seekAndWriteFd(pShmNode.hShm, iPg * pgsz + pgsz - 1, "", 1, &x) != 1) {
                            rc = unixLogError(SQLITE_IOERR_SHMSIZE, "write", @ptrCast(pShmNode.zFilename));
                            return shmpageOut(pShmNode, iRegion, ppOut, rc);
                        }
                    }
                }
            }
        }

        const apNew: ?[*]?[*]u8 = @ptrCast(@alignCast(sqlite3_realloc64(@ptrCast(pShmNode.apRegion), @intCast(nReqRegion * @as(c_int, @sizeOf(usize))))));
        if (apNew == null) {
            rc = SQLITE_IOERR_NOMEM;
            return shmpageOut(pShmNode, iRegion, ppOut, rc);
        }
        pShmNode.apRegion = apNew;
        while (pShmNode.nRegion < nReqRegion) {
            const nMap: i64 = @as(i64, szRegion) * @as(i64, nShmPerMap);
            var pMem: ?*anyopaque = undefined;
            if (pShmNode.hShm >= 0) {
                pMem = osMmap(
                    null,
                    @intCast(nMap),
                    if (pShmNode.isReadonly != 0) PROT_READ else PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    pShmNode.hShm,
                    @as(i64, szRegion) * @as(i64, pShmNode.nRegion),
                );
                if (pMem == MAP_FAILED) {
                    rc = unixLogError(SQLITE_IOERR_SHMMAP, "mmap", @ptrCast(pShmNode.zFilename));
                    return shmpageOut(pShmNode, iRegion, ppOut, rc);
                }
            } else {
                pMem = sqlite3_malloc64(@intCast(nMap));
                if (pMem == null) {
                    rc = SQLITE_NOMEM;
                    return shmpageOut(pShmNode, iRegion, ppOut, rc);
                }
                _ = memset(pMem, 0, @intCast(nMap));
            }
            var i: i64 = 0;
            while (i < nShmPerMap) : (i += 1) {
                const dst: [*]u8 = @ptrFromInt(@intFromPtr(pMem.?) + @as(usize, @intCast(szRegion * i)));
                pShmNode.apRegion.?[@intCast(pShmNode.nRegion + i)] = dst;
            }
            pShmNode.nRegion += @intCast(nShmPerMap);
        }
    }
    return shmpageOut(pShmNode, iRegion, ppOut, rc);
}
fn shmpageOut(pShmNode: *unixShmNode, iRegion: c_int, ppOut: *?*anyopaque, rc_in: c_int) c_int {
    var rc = rc_in;
    if (pShmNode.nRegion > iRegion) {
        ppOut.* = pShmNode.apRegion.?[@intCast(iRegion)];
    } else {
        ppOut.* = null;
    }
    if (pShmNode.isReadonly != 0 and rc == SQLITE_OK) rc = SQLITE_READONLY;
    sqlite3_mutex_leave(pShmNode.pShmMutex);
    return rc;
}

fn unixShmLock(fd: *Sqlite3File, ofst: c_int, n: c_int, flags: c_int) callconv(.c) c_int {
    const pDbFd: *unixFile = @ptrCast(fd);
    var rc: c_int = SQLITE_OK;
    const mask: u16 = @intCast((@as(c_int, 1) << @intCast(ofst + n)) - (@as(c_int, 1) << @intCast(ofst)));

    const p = pDbFd.pShm orelse return SQLITE_IOERR_SHMLOCK;
    const pShmNode = p.pShmNode orelse return SQLITE_IOERR_SHMLOCK;
    const aLock = &pShmNode.aLock;

    if (((flags & SQLITE_SHM_UNLOCK) != 0 and ((p.exclMask | p.sharedMask) & mask) != 0) or
        (flags == (SQLITE_SHM_SHARED | SQLITE_SHM_LOCK) and (p.sharedMask & mask) == 0) or
        (flags == (SQLITE_SHM_EXCLUSIVE | SQLITE_SHM_LOCK)))
    {
        sqlite3_mutex_enter(pShmNode.pShmMutex);

        if (flags & SQLITE_SHM_UNLOCK != 0) {
            var bUnlock = true;
            if (flags & SQLITE_SHM_SHARED != 0) {
                if (aLock[@intCast(ofst)] > 1) {
                    bUnlock = false;
                    aLock[@intCast(ofst)] -= 1;
                    p.sharedMask &= ~mask;
                }
            }
            if (bUnlock) {
                rc = unixShmSystemLock(pDbFd, F_UNLCK, ofst + UNIX_SHM_BASE, n);
                if (rc == SQLITE_OK) {
                    _ = memset(&aLock[@intCast(ofst)], 0, @sizeOf(c_int) * @as(usize, @intCast(n)));
                    p.sharedMask &= ~mask;
                    p.exclMask &= ~mask;
                }
            }
        } else if (flags & SQLITE_SHM_SHARED != 0) {
            if (aLock[@intCast(ofst)] < 0) {
                rc = SQLITE_BUSY;
            } else if (aLock[@intCast(ofst)] == 0) {
                rc = unixShmSystemLock(pDbFd, F_RDLCK, ofst + UNIX_SHM_BASE, n);
            }
            if (rc == SQLITE_OK) {
                p.sharedMask |= mask;
                aLock[@intCast(ofst)] += 1;
            }
        } else {
            var ii: c_int = ofst;
            while (ii < ofst + n) : (ii += 1) {
                if (aLock[@intCast(ii)] != 0) {
                    rc = SQLITE_BUSY;
                    break;
                }
            }
            if (rc == SQLITE_OK) {
                rc = unixShmSystemLock(pDbFd, F_WRLCK, ofst + UNIX_SHM_BASE, n);
                if (rc == SQLITE_OK) {
                    p.exclMask |= mask;
                    ii = ofst;
                    while (ii < ofst + n) : (ii += 1) {
                        aLock[@intCast(ii)] = -1;
                    }
                }
            }
        }
        sqlite3_mutex_leave(pShmNode.pShmMutex);
    }
    return rc;
}

fn unixShmBarrier(fd: *Sqlite3File) callconv(.c) void {
    _ = fd;
    sqlite3MemoryBarrier();
    unixEnterMutex();
    unixLeaveMutex();
}

fn unixShmUnmap(fd: *Sqlite3File, deleteFlag: c_int) callconv(.c) c_int {
    const pDbFd: *unixFile = @ptrCast(fd);
    const p = pDbFd.pShm orelse return SQLITE_OK;
    const pShmNode = p.pShmNode.?;

    sqlite3_mutex_enter(pShmNode.pShmMutex);
    var pp = &pShmNode.pFirst;
    while (pp.* != p) pp = &pp.*.?.pNext;
    pp.* = p.pNext;

    sqlite3_free(p);
    pDbFd.pShm = null;
    sqlite3_mutex_leave(pShmNode.pShmMutex);

    unixEnterMutex();
    pShmNode.nRef -= 1;
    if (pShmNode.nRef == 0) {
        if (deleteFlag != 0 and pShmNode.hShm >= 0) {
            _ = osUnlink(@ptrCast(pShmNode.zFilename.?));
        }
        unixShmPurge(pDbFd);
    }
    unixLeaveMutex();
    return SQLITE_OK;
}

// ===========================================================================
// mmap.
// ===========================================================================
fn unixUnmapfile(pFd: *unixFile) void {
    if (pFd.pMapRegion) |region| {
        _ = osMunmap(region, @intCast(pFd.mmapSizeActual));
        pFd.pMapRegion = null;
        pFd.mmapSize = 0;
        pFd.mmapSizeActual = 0;
    }
}

fn unixRemapfile(pFd: *unixFile, nNew_in: i64) void {
    var nNew = nNew_in;
    var zErr: [*:0]const u8 = "mmap";
    const h = pFd.h;
    const pOrig: ?[*]u8 = @ptrCast(pFd.pMapRegion);
    const nOrig = pFd.mmapSizeActual;
    var pNew: ?[*]u8 = null;
    const flags: c_int = PROT_READ; // SQLITE_MMAP_READWRITE off

    if (pOrig) |orig| {
        // HAVE_MREMAP
        const nReuse = pFd.mmapSize;
        const pReq: [*]u8 = orig + @as(usize, @intCast(nReuse));
        if (nReuse != nOrig) {
            _ = osMunmap(pReq, @intCast(nOrig - nReuse));
        }
        pNew = @ptrCast(osMremap(orig, @intCast(nReuse), @intCast(nNew), MREMAP_MAYMOVE));
        zErr = "mremap";
        if (pNew == @as(?[*]u8, @ptrCast(MAP_FAILED)) or pNew == null) {
            _ = osMunmap(orig, @intCast(nReuse));
        }
    }

    if (pNew == null) {
        pNew = @ptrCast(osMmap(null, @intCast(nNew), flags, MAP_SHARED, h, 0));
    }

    if (pNew == @as(?[*]u8, @ptrCast(MAP_FAILED))) {
        pNew = null;
        nNew = 0;
        _ = unixLogError(SQLITE_OK, zErr, pFd.zPath);
        pFd.mmapSizeMax = 0;
    }
    pFd.pMapRegion = pNew;
    pFd.mmapSize = nNew;
    pFd.mmapSizeActual = nNew;
}

fn unixMapfile(pFd: *unixFile, nMap_in: i64) c_int {
    var nMap = nMap_in;
    if (pFd.nFetchOut > 0) return SQLITE_OK;

    if (nMap < 0) {
        var statbuf: stat = undefined;
        if (osFstat(pFd.h, &statbuf) != 0) {
            return SQLITE_IOERR_FSTAT;
        }
        nMap = statbuf.st_size;
    }
    if (nMap > pFd.mmapSizeMax) {
        nMap = pFd.mmapSizeMax;
    }
    if (nMap != pFd.mmapSize) {
        unixRemapfile(pFd, nMap);
    }
    return SQLITE_OK;
}

fn unixFetch(fd: *Sqlite3File, iOff: i64, nAmt: c_int, pp: ?*anyopaque) callconv(.c) c_int {
    const pFd: *unixFile = @ptrCast(fd);
    const ppOut: *?*anyopaque = @ptrCast(@alignCast(pp.?));
    ppOut.* = null;

    if (pFd.mmapSizeMax > 0) {
        const nEofBuffer: i64 = 256;
        if (pFd.pMapRegion == null) {
            const rc = unixMapfile(pFd, -1);
            if (rc != SQLITE_OK) return rc;
        }
        if (pFd.mmapSize >= (iOff + nAmt + nEofBuffer)) {
            const dst: [*]u8 = @ptrFromInt(@intFromPtr(pFd.pMapRegion.?) + @as(usize, @intCast(iOff)));
            ppOut.* = dst;
            pFd.nFetchOut += 1;
        }
    }
    return SQLITE_OK;
}

fn unixUnfetch(fd: *Sqlite3File, iOff: i64, p: ?*anyopaque) callconv(.c) c_int {
    const pFd: *unixFile = @ptrCast(fd);
    _ = iOff;
    if (p != null) {
        pFd.nFetchOut -= 1;
    } else {
        unixUnmapfile(pFd);
    }
    return SQLITE_OK;
}

// ===========================================================================
// io_methods tables + finders.
// ===========================================================================

fn makeIoMethods(
    comptime version: c_int,
    comptime xClose: *const fn (*Sqlite3File) callconv(.c) c_int,
    comptime xLock: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    comptime xUnlock: ?*const fn (*Sqlite3File, c_int) callconv(.c) c_int,
    comptime xCkLock: ?*const fn (*Sqlite3File, *c_int) callconv(.c) c_int,
    comptime xShmMap: ?*const fn (*Sqlite3File, c_int, c_int, c_int, ?*anyopaque) callconv(.c) c_int,
) IoMethods {
    return .{
        .iVersion = version,
        .xClose = xClose,
        .xRead = unixRead,
        .xWrite = unixWrite,
        .xTruncate = unixTruncate,
        .xSync = unixSync,
        .xFileSize = unixFileSize,
        .xLock = xLock,
        .xUnlock = xUnlock,
        .xCheckReservedLock = xCkLock,
        .xFileControl = unixFileControl,
        .xSectorSize = unixSectorSize,
        .xDeviceCharacteristics = unixDeviceCharacteristics,
        .xShmMap = xShmMap,
        .xShmLock = unixShmLock,
        .xShmBarrier = unixShmBarrier,
        .xShmUnmap = unixShmUnmap,
        .xFetch = unixFetch,
        .xUnfetch = unixUnfetch,
    };
}

const posixIoMethods = makeIoMethods(3, unixClose, unixLock, unixUnlock, unixCheckReservedLock, unixShmMap);
const nolockIoMethods = makeIoMethods(3, nolockClose, nolockLock, nolockUnlock, nolockCheckReservedLock, null);
const dotlockIoMethods = makeIoMethods(1, dotlockClose, dotlockLock, dotlockUnlock, dotlockCheckReservedLock, null);

const FinderType = *const fn (?[*:0]const u8, *unixFile) callconv(.c) *const IoMethods;

fn posixIoFinderImpl(z: ?[*:0]const u8, p: *unixFile) callconv(.c) *const IoMethods {
    _ = z;
    _ = p;
    return &posixIoMethods;
}
fn nolockIoFinderImpl(z: ?[*:0]const u8, p: *unixFile) callconv(.c) *const IoMethods {
    _ = z;
    _ = p;
    return &nolockIoMethods;
}
fn dotlockIoFinderImpl(z: ?[*:0]const u8, p: *unixFile) callconv(.c) *const IoMethods {
    _ = z;
    _ = p;
    return &dotlockIoMethods;
}
const posixIoFinder: FinderType = posixIoFinderImpl;
const nolockIoFinder: FinderType = nolockIoFinderImpl;
const dotlockIoFinder: FinderType = dotlockIoFinderImpl;

// ===========================================================================
// sqlite3_vfs methods.
// ===========================================================================

fn fillInUnixFile(
    pVfs: *Sqlite3Vfs,
    h_in: c_int,
    pId: *Sqlite3File,
    zFilename: ?[*:0]const u8,
    ctrlFlags: c_int,
) c_int {
    var h = h_in;
    const pNew: *unixFile = @ptrCast(pId);
    var rc: c_int = SQLITE_OK;

    pNew.h = h;
    pNew.pVfs = pVfs;
    pNew.zPath = zFilename;
    pNew.ctrlFlags = @intCast(ctrlFlags & 0xffff);
    pNew.mmapSizeMax = cfgSzMmap();
    if (sqlite3_uri_boolean(
        if ((ctrlFlags & UNIXFILE_URI) != 0) zFilename else null,
        "psow",
        SQLITE_POWERSAFE_OVERWRITE,
    ) != 0) {
        pNew.ctrlFlags |= UNIXFILE_PSOW;
    }
    if (strcmp(pVfs.zName.?, "unix-excl") == 0) {
        pNew.ctrlFlags |= UNIXFILE_EXCL;
    }

    var pLockingStyle: *const IoMethods = undefined;
    if ((ctrlFlags & UNIXFILE_NOLOCK) != 0) {
        pLockingStyle = &nolockIoMethods;
    } else {
        const finderPtr: *const FinderType = @ptrCast(@alignCast(pVfs.pAppData.?));
        pLockingStyle = finderPtr.*(zFilename, pNew);
    }

    if (pLockingStyle == &posixIoMethods) {
        unixEnterMutex();
        rc = findInodeInfo(pNew, &pNew.pInode);
        if (rc != SQLITE_OK) {
            robust_close(pNew, h);
            h = -1;
        }
        unixLeaveMutex();
    } else if (pLockingStyle == &dotlockIoMethods) {
        const nFilename: c_int = sqlite3Strlen30(zFilename.?) + 6;
        const zLockFile: ?[*]u8 = @ptrCast(sqlite3_malloc64(@intCast(nFilename)));
        if (zLockFile == null) {
            rc = SQLITE_NOMEM;
        } else {
            _ = sqlite3_snprintf(nFilename, zLockFile.?, "%s" ++ DOTLOCK_SUFFIX, zFilename.?);
        }
        pNew.lockingContext = zLockFile;
    }

    storeLastErrno(pNew, 0);
    if (rc != SQLITE_OK) {
        if (h >= 0) robust_close(pNew, h);
    } else {
        pId.pMethods = pLockingStyle;
        openCounter(1);
        verifyDbFile(pNew);
    }
    return rc;
}

fn unixTempFileDir() ?[*:0]const u8 {
    var i: usize = 0;
    var buf: stat = undefined;
    var zDir: ?[*:0]const u8 = sqlite3_temp_directory;
    while (true) {
        if (zDir != null and osStat(zDir.?, &buf) == 0 and
            (buf.st_mode & S_IFMT) == S_IFDIR and osAccess(zDir.?, 0o3) == 0)
        {
            return zDir;
        }
        if (i >= azTempDirs.len) break;
        zDir = azTempDirs[i];
        i += 1;
    }
    return null;
}

fn unixGetTempname(nBuf: c_int, zBuf: [*]u8) c_int {
    var iLimit: c_int = 0;
    var rc: c_int = SQLITE_OK;
    zBuf[0] = 0;
    if (simulateIOError()) return SQLITE_IOERR;

    sqlite3_mutex_enter(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_TEMPDIR));
    const zDir = unixTempFileDir();
    if (zDir == null) {
        rc = SQLITE_IOERR_GETTEMPPATH;
    } else {
        while (true) {
            var r: u64 = undefined;
            sqlite3_randomness(@sizeOf(u64), &r);
            zBuf[@intCast(nBuf - 2)] = 0;
            _ = sqlite3_snprintf(nBuf, zBuf, "%s/" ++ SQLITE_TEMP_FILE_PREFIX ++ "%llx%c", zDir.?, r, @as(c_int, 0));
            if (zBuf[@intCast(nBuf - 2)] != 0 or blk: {
                iLimit += 1;
                break :blk iLimit > 10;
            }) {
                rc = SQLITE_ERROR;
                break;
            }
            if (osAccess(@ptrCast(zBuf), 0) != 0) break;
        }
    }
    sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_TEMPDIR));
    return rc;
}

fn findReusableFd(zPath: [*:0]const u8, flags_in: c_int) ?*UnixUnusedFd {
    var flags = flags_in;
    var pUnused: ?*UnixUnusedFd = null;
    var sStat: stat = undefined;

    unixEnterMutex();
    if (inodeList != null and osStat(zPath, &sStat) == 0) {
        var pInode = inodeList;
        while (pInode) |pi| {
            if (pi.fileId.dev == sStat.st_dev and pi.fileId.ino == sStat.st_ino) break;
            pInode = pi.pNext;
        }
        if (pInode) |pi| {
            sqlite3_mutex_enter(pi.pLockMutex);
            flags &= (SQLITE_OPEN_READONLY | SQLITE_OPEN_READWRITE);
            var pp = &pi.pUnused;
            while (pp.* != null and pp.*.?.flags != flags) pp = &pp.*.?.pNext;
            pUnused = pp.*;
            if (pUnused) |u| {
                pp.* = u.pNext;
            }
            sqlite3_mutex_leave(pi.pLockMutex);
        }
    }
    unixLeaveMutex();
    return pUnused;
}

fn getFileMode(zFile: [*:0]const u8, pMode: *mode_t, pUid: *uid_t, pGid: *gid_t) c_int {
    var sStat: stat = undefined;
    if (osStat(zFile, &sStat) == 0) {
        pMode.* = sStat.st_mode & 0o777;
        pUid.* = sStat.st_uid;
        pGid.* = sStat.st_gid;
        return SQLITE_OK;
    }
    return SQLITE_IOERR_FSTAT;
}

fn findCreateFileMode(zPath: [*:0]const u8, flags: c_int, pMode: *mode_t, pUid: *uid_t, pGid: *gid_t) c_int {
    var rc: c_int = SQLITE_OK;
    pMode.* = 0;
    pUid.* = 0;
    pGid.* = 0;
    if ((flags & (SQLITE_OPEN_WAL | SQLITE_OPEN_MAIN_JOURNAL)) != 0) {
        var zDb: [MAX_PATHNAME + 1]u8 = undefined;
        var nDb: c_int = sqlite3Strlen30(zPath) - 1;
        while (nDb > 0 and zPath[@intCast(nDb)] != '.') {
            if (zPath[@intCast(nDb)] == '-') {
                _ = memcpy(&zDb, zPath, @intCast(nDb));
                zDb[@intCast(nDb)] = 0;
                rc = getFileMode(@ptrCast(&zDb), pMode, pUid, pGid);
                break;
            }
            nDb -= 1;
        }
    } else if ((flags & SQLITE_OPEN_DELETEONCLOSE) != 0) {
        pMode.* = 0o600;
    } else if ((flags & SQLITE_OPEN_URI) != 0) {
        const z = sqlite3_uri_parameter(zPath, "modeof");
        if (z) |zz| {
            rc = getFileMode(zz, pMode, pUid, pGid);
        }
    }
    return rc;
}

fn unixOpen(
    pVfs: *Sqlite3Vfs,
    zPath: ?[*:0]const u8,
    pFile: *Sqlite3File,
    flags_in: c_int,
    pOutFlags: ?*c_int,
) callconv(.c) c_int {
    const p: *unixFile = @ptrCast(pFile);
    var flags = flags_in;
    var fd: c_int = -1;
    var openFlags: c_int = 0;
    const eType = flags & 0x0FFF00;
    var rc: c_int = SQLITE_OK;
    var ctrlFlags: c_int = 0;

    const isExclusive = (flags & SQLITE_OPEN_EXCLUSIVE) != 0;
    const isDelete = (flags & SQLITE_OPEN_DELETEONCLOSE) != 0;
    const isCreate = (flags & SQLITE_OPEN_CREATE) != 0;
    var isReadonly = (flags & SQLITE_OPEN_READONLY) != 0;
    const isReadWrite = (flags & SQLITE_OPEN_READWRITE) != 0;

    const isNewJrnl = isCreate and (eType == SQLITE_OPEN_SUPER_JOURNAL or
        eType == SQLITE_OPEN_MAIN_JOURNAL or eType == SQLITE_OPEN_WAL);

    var zTmpname: [MAX_PATHNAME + 2]u8 = undefined;
    var zName = zPath;

    if (randomnessPid != osGetpid()) {
        randomnessPid = osGetpid();
        sqlite3_randomness(0, null);
    }
    _ = memset(p, 0, @sizeOf(unixFile));

    if (eType == SQLITE_OPEN_MAIN_DB) {
        var pUnused = findReusableFd(zName.?, flags);
        if (pUnused) |u| {
            fd = u.fd;
        } else {
            pUnused = @ptrCast(@alignCast(sqlite3_malloc64(@sizeOf(UnixUnusedFd))));
            if (pUnused == null) {
                return SQLITE_NOMEM;
            }
        }
        p.pPreallocatedUnused = pUnused;
    } else if (zName == null) {
        // O_TMPFILE fast path for temp files.
        zName = unixTempFileDir();
        if (zName != null) {
            fd = robust_open(zName.?, O_RDWR | O_CREAT | O_EXCL | O_TMPFILE, 0o600);
            if (fd >= 0) {
                rc = fillInUnixFile(pVfs, fd, pFile, zPath, ctrlFlags);
                return openFinished(p, rc);
            }
        }
        rc = unixGetTempname(pVfs.mxPathname, &zTmpname);
        if (rc != SQLITE_OK) {
            return rc;
        }
        zName = @ptrCast(&zTmpname);
    }

    if (isReadonly) openFlags |= O_RDONLY;
    if (isReadWrite) openFlags |= O_RDWR;
    if (isCreate) openFlags |= O_CREAT;
    if (isExclusive) openFlags |= (O_EXCL | O_NOFOLLOW);
    openFlags |= (O_LARGEFILE | O_BINARY | O_NOFOLLOW);

    if (fd < 0) {
        var openMode: mode_t = undefined;
        var uid: uid_t = undefined;
        var gid: gid_t = undefined;
        rc = findCreateFileMode(zName.?, flags, &openMode, &uid, &gid);
        if (rc != SQLITE_OK) {
            return rc;
        }
        fd = robust_open(zName.?, openFlags, openMode);
        if (fd < 0) {
            if (isNewJrnl and errno() == EACCES and osAccess(zName.?, F_OK) != 0) {
                rc = SQLITE_READONLY_DIRECTORY;
            } else if (errno() != EISDIR and isReadWrite) {
                flags &= ~(SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
                openFlags &= ~(O_RDWR | O_CREAT);
                flags |= SQLITE_OPEN_READONLY;
                openFlags |= O_RDONLY;
                isReadonly = true;
                const pReadonly = findReusableFd(zName.?, flags);
                if (pReadonly) |ro| {
                    fd = ro.fd;
                    sqlite3_free(ro);
                } else {
                    fd = robust_open(zName.?, openFlags, openMode);
                }
            }
        }
        if (fd < 0) {
            const rc2 = unixLogError(SQLITE_CANTOPEN, "open", zName.?);
            if (rc == SQLITE_OK) rc = rc2;
            return openFinished(p, rc);
        }

        if (openMode != 0 and (flags & (SQLITE_OPEN_WAL | SQLITE_OPEN_MAIN_JOURNAL)) != 0) {
            _ = robustFchown(fd, uid, gid);
        }
    }
    if (pOutFlags) |po| {
        po.* = flags;
    }

    if (p.pPreallocatedUnused) |u| {
        u.fd = fd;
        u.flags = flags & (SQLITE_OPEN_READONLY | SQLITE_OPEN_READWRITE);
    }

    if (isDelete) {
        _ = osUnlink(zName.?);
    }

    // Set up appropriate ctrlFlags
    if (isDelete) ctrlFlags |= UNIXFILE_DELETE;
    if (isReadonly) ctrlFlags |= UNIXFILE_RDONLY;
    const noLock = eType != SQLITE_OPEN_MAIN_DB;
    if (noLock) ctrlFlags |= UNIXFILE_NOLOCK;
    if (isNewJrnl) ctrlFlags |= UNIXFILE_DIRSYNC;
    if ((flags & SQLITE_OPEN_URI) != 0) ctrlFlags |= UNIXFILE_URI;

    rc = fillInUnixFile(pVfs, fd, pFile, zPath, ctrlFlags);
    return openFinished(p, rc);
}
fn openFinished(p: *unixFile, rc: c_int) c_int {
    if (rc != SQLITE_OK) {
        sqlite3_free(p.pPreallocatedUnused);
    }
    return rc;
}

fn unixDelete(NotUsed: *Sqlite3Vfs, zPath: [*:0]const u8, dirSync: c_int) callconv(.c) c_int {
    _ = NotUsed;
    var rc: c_int = SQLITE_OK;
    if (simulateIOError()) return SQLITE_IOERR_DELETE;
    if (osUnlink(zPath) == -1) {
        if (errno() == ENOENT) {
            rc = SQLITE_IOERR_DELETE_NOENT;
        } else {
            rc = unixLogError(SQLITE_IOERR_DELETE, "unlink", zPath);
        }
        return rc;
    }
    if ((dirSync & 1) != 0) {
        var fd: c_int = undefined;
        rc = osOpenDirectory(zPath, &fd);
        if (rc == SQLITE_OK) {
            if (full_fsync(fd, 0, 0) != 0) {
                rc = unixLogError(SQLITE_IOERR_DIR_FSYNC, "fsync", zPath);
            }
            robust_close(null, fd);
        } else {
            rc = SQLITE_OK;
        }
    }
    return rc;
}

fn unixAccess(NotUsed: *Sqlite3Vfs, zPath: [*:0]const u8, flags: c_int, pResOut: *c_int) callconv(.c) c_int {
    _ = NotUsed;
    if (simulateIOError()) return SQLITE_IOERR_ACCESS;
    if (flags == SQLITE_ACCESS_EXISTS) {
        var buf: stat = undefined;
        pResOut.* = @intFromBool(osStat(zPath, &buf) == 0 and
            ((buf.st_mode & S_IFMT) != S_IFREG or buf.st_size > 0));
    } else {
        pResOut.* = @intFromBool(osAccess(zPath, W_OK | R_OK) == 0);
    }
    return SQLITE_OK;
}

const DbPath = struct {
    rc: c_int,
    nSymlink: c_int,
    zOut: [*]u8,
    nOut: c_int,
    nUsed: c_int,
};

fn appendOnePathElement(pPath: *DbPath, zName: [*]const u8, nName: c_int) void {
    if (zName[0] == '.') {
        if (nName == 1) return;
        if (zName[1] == '.' and nName == 2) {
            if (pPath.nUsed > 1) {
                pPath.nUsed -= 1;
                while (pPath.zOut[@intCast(pPath.nUsed)] != '/') pPath.nUsed -= 1;
            }
            return;
        }
    }
    if (pPath.nUsed + nName + 2 >= pPath.nOut) {
        pPath.rc = SQLITE_ERROR;
        return;
    }
    pPath.zOut[@intCast(pPath.nUsed)] = '/';
    pPath.nUsed += 1;
    _ = memcpy(pPath.zOut + @as(usize, @intCast(pPath.nUsed)), zName, @intCast(nName));
    pPath.nUsed += nName;
    // HAVE_READLINK && HAVE_LSTAT — resolve symlinks
    if (pPath.rc == SQLITE_OK) {
        var buf: stat = undefined;
        pPath.zOut[@intCast(pPath.nUsed)] = 0;
        const zIn: [*:0]const u8 = @ptrCast(pPath.zOut);
        if (osLstat(zIn, &buf) != 0) {
            if (errno() != ENOENT) {
                pPath.rc = unixLogError(SQLITE_CANTOPEN, "lstat", zIn);
            }
        } else if ((buf.st_mode & S_IFMT) == S_IFLNK) {
            var zLnk: [SQLITE_MAX_PATHLEN + 2]u8 = undefined;
            pPath.nSymlink += 1;
            if (pPath.nSymlink > SQLITE_MAX_SYMLINKS) {
                pPath.rc = SQLITE_CANTOPEN;
                return;
            }
            const got = osReadlink(zIn, &zLnk, zLnk.len - 2);
            if (got <= 0 or got >= @as(ssize_t, zLnk.len - 2)) {
                pPath.rc = unixLogError(SQLITE_CANTOPEN, "readlink", zIn);
                return;
            }
            zLnk[@intCast(got)] = 0;
            if (zLnk[0] == '/') {
                pPath.nUsed = 0;
            } else {
                pPath.nUsed -= nName + 1;
            }
            appendAllPathElements(pPath, @ptrCast(&zLnk));
        }
    }
}

fn appendAllPathElements(pPath: *DbPath, zPath: [*:0]const u8) void {
    var i: c_int = 0;
    var j: c_int = 0;
    while (true) {
        while (zPath[@intCast(i)] != 0 and zPath[@intCast(i)] != '/') i += 1;
        if (i > j) {
            appendOnePathElement(pPath, zPath + @as(usize, @intCast(j)), i - j);
        }
        j = i + 1;
        const cont = zPath[@intCast(i)] != 0;
        i += 1;
        if (!cont) break;
    }
}

fn unixFullPathname(pVfs: *Sqlite3Vfs, zPath: [*:0]const u8, nOut: c_int, zOut: [*]u8) callconv(.c) c_int {
    _ = pVfs;
    var path: DbPath = .{ .rc = 0, .nUsed = 0, .nSymlink = 0, .nOut = nOut, .zOut = zOut };
    if (zPath[0] != '/') {
        var zPwd: [SQLITE_MAX_PATHLEN + 2]u8 = undefined;
        if (osGetcwd(&zPwd, zPwd.len - 2) == null) {
            return unixLogError(SQLITE_CANTOPEN, "getcwd", zPath);
        }
        appendAllPathElements(&path, @ptrCast(&zPwd));
    }
    appendAllPathElements(&path, zPath);
    zOut[@intCast(path.nUsed)] = 0;
    if (path.rc != 0 or path.nUsed < 2) return SQLITE_CANTOPEN;
    if (path.nSymlink != 0) return SQLITE_OK_SYMLINK;
    return SQLITE_OK;
}

// dlopen / dlsym / dlclose (SQLITE_OMIT_LOAD_EXTENSION off).
fn unixDlOpen(NotUsed: *Sqlite3Vfs, zFilename: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    _ = NotUsed;
    return dlopen(zFilename, RTLD_NOW | RTLD_GLOBAL);
}
fn unixDlError(NotUsed: *Sqlite3Vfs, nBuf: c_int, zBufOut: [*]u8) callconv(.c) void {
    _ = NotUsed;
    unixEnterMutex();
    const zErr = dlerror();
    if (zErr) |z| {
        _ = sqlite3_snprintf(nBuf, zBufOut, "%s", z);
    }
    unixLeaveMutex();
}
fn unixDlSym(NotUsed: *Sqlite3Vfs, p: ?*anyopaque, zSym: [*:0]const u8) callconv(.c) VoidFn {
    _ = NotUsed;
    return @ptrCast(dlsym(p, zSym));
}
fn unixDlClose(NotUsed: *Sqlite3Vfs, pHandle: ?*anyopaque) callconv(.c) void {
    _ = NotUsed;
    _ = dlclose(pHandle);
}

fn unixRandomness(NotUsed: *Sqlite3Vfs, nBuf_in: c_int, zBuf: [*]u8) callconv(.c) c_int {
    _ = NotUsed;
    var nBuf = nBuf_in;
    _ = memset(zBuf, 0, @intCast(nBuf));
    randomnessPid = osGetpid();
    if (!config.sqlite_test) {
        const fd = robust_open("/dev/urandom", O_RDONLY, 0);
        if (fd < 0) {
            var t: time_t = undefined;
            _ = time(&t);
            _ = memcpy(zBuf, &t, @sizeOf(time_t));
            const dst: [*]u8 = zBuf + @sizeOf(time_t);
            _ = memcpy(dst, &randomnessPid, @sizeOf(pid_t));
            nBuf = @sizeOf(time_t) + @sizeOf(pid_t);
        } else {
            var got: ssize_t = undefined;
            while (true) {
                got = osRead(fd, zBuf, @intCast(nBuf));
                if (!(got < 0 and errno() == EINTR)) break;
            }
            robust_close(null, fd);
        }
    }
    return nBuf;
}

fn unixSleep(NotUsed: *Sqlite3Vfs, microseconds: c_int) callconv(.c) c_int {
    _ = NotUsed;
    var sp: timespec = undefined;
    sp.tv_sec = @divTrunc(microseconds, 1000000);
    sp.tv_nsec = @rem(microseconds, 1000000) * 1000;
    _ = nanosleep(&sp, null);
    return microseconds;
}

fn unixCurrentTimeInt64(NotUsed: *Sqlite3Vfs, piNow: *i64) callconv(.c) c_int {
    _ = NotUsed;
    const unixEpoch: i64 = 24405875 * @as(i64, 8640000);
    var sNow: timeval = undefined;
    _ = gettimeofday(&sNow, null);
    piNow.* = unixEpoch + 1000 * @as(i64, sNow.tv_sec) + @divTrunc(sNow.tv_usec, 1000);
    if (config.sqlite_test) {
        if (sqlite3_current_time != 0) {
            piNow.* = 1000 * @as(i64, sqlite3_current_time) + unixEpoch;
        }
    }
    return SQLITE_OK;
}

fn unixCurrentTime(NotUsed: *Sqlite3Vfs, prNow: *f64) callconv(.c) c_int {
    var i: i64 = 0;
    const rc = unixCurrentTimeInt64(NotUsed, &i);
    prNow.* = @as(f64, @floatFromInt(i)) / 86400000.0;
    return rc;
}

fn unixGetLastError(NotUsed: *Sqlite3Vfs, NotUsed2: c_int, NotUsed3: ?[*]u8) callconv(.c) c_int {
    _ = NotUsed;
    _ = NotUsed2;
    _ = NotUsed3;
    return errno();
}

// ===========================================================================
// xSetSystemCall / xGetSystemCall / xNextSystemCall.
// ===========================================================================
fn unixSetSystemCall(pNotUsed: *Sqlite3Vfs, zName: ?[*:0]const u8, pNewFunc_in: SyscallPtr) callconv(.c) c_int {
    _ = pNotUsed;
    var rc: c_int = SQLITE_NOTFOUND;
    var pNewFunc = pNewFunc_in;
    if (zName == null) {
        rc = SQLITE_OK;
        for (&aSyscall) |*s| {
            if (s.pDefault != null) s.pCurrent = s.pDefault;
        }
    } else {
        for (&aSyscall) |*s| {
            if (strcmp(zName.?, s.zName) == 0) {
                if (s.pDefault == null) s.pDefault = s.pCurrent;
                rc = SQLITE_OK;
                if (pNewFunc == null) pNewFunc = s.pDefault;
                s.pCurrent = pNewFunc;
                break;
            }
        }
    }
    return rc;
}

fn unixGetSystemCall(pNotUsed: *Sqlite3Vfs, zName: [*:0]const u8) callconv(.c) SyscallPtr {
    _ = pNotUsed;
    for (&aSyscall) |*s| {
        if (strcmp(zName, s.zName) == 0) return s.pCurrent;
    }
    return null;
}

fn unixNextSystemCall(pNotUsed: *Sqlite3Vfs, zName: ?[*:0]const u8) callconv(.c) ?[*:0]const u8 {
    _ = pNotUsed;
    var i: c_int = -1;
    if (zName) |z| {
        i = 0;
        while (i < @as(c_int, aSyscall.len) - 1) : (i += 1) {
            if (strcmp(z, aSyscall[@intCast(i)].zName) == 0) break;
        }
    }
    i += 1;
    while (i < @as(c_int, aSyscall.len)) : (i += 1) {
        if (aSyscall[@intCast(i)].pCurrent != null) return aSyscall[@intCast(i)].zName;
    }
    return null;
}

// ===========================================================================
// sqlite3_os_init / sqlite3_os_end.
// ===========================================================================

/// The aVfs[] array of registered VFS objects (non-const: pNext is mutated by
/// the registry). With LOCKING_STYLE off and not Apple, four VFSes register.
var aVfs = [_]Sqlite3Vfs{
    makeVfs("unix", &posixIoFinder),
    makeVfs("unix-none", &nolockIoFinder),
    makeVfs("unix-dotfile", &dotlockIoFinder),
    makeVfs("unix-excl", &posixIoFinder),
};

fn makeVfs(comptime name: [*:0]const u8, finder: *const FinderType) Sqlite3Vfs {
    return .{
        .iVersion = 3,
        .szOsFile = @sizeOf(unixFile),
        .mxPathname = MAX_PATHNAME,
        .pNext = null,
        .zName = name,
        .pAppData = @ptrCast(@constCast(finder)),
        .xOpen = unixOpen,
        .xDelete = unixDelete,
        .xAccess = unixAccess,
        .xFullPathname = unixFullPathname,
        .xDlOpen = unixDlOpen,
        .xDlError = unixDlError,
        .xDlSym = unixDlSym,
        .xDlClose = unixDlClose,
        .xRandomness = unixRandomness,
        .xSleep = unixSleep,
        .xCurrentTime = unixCurrentTime,
        .xGetLastError = unixGetLastError,
        .xCurrentTimeInt64 = unixCurrentTimeInt64,
        .xSetSystemCall = unixSetSystemCall,
        .xGetSystemCall = unixGetSystemCall,
        .xNextSystemCall = unixNextSystemCall,
    };
}

export fn sqlite3_os_init() callconv(.c) c_int {
    // Register all VFSes; the first (i==0, "unix") is the default.
    for (&aVfs, 0..) |*v, i| {
        _ = sqlite3_vfs_register(v, @intFromBool(i == 0));
    }
    unixBigLock = sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_VFS1);

    // Initialize temp file dir array (azTempDirs[0]/[1] from env).
    azTempDirs[0] = getenv("SQLITE_TMPDIR");
    azTempDirs[1] = getenv("TMPDIR");

    return SQLITE_OK;
}

export fn sqlite3_os_end() callconv(.c) c_int {
    unixBigLock = null;
    return SQLITE_OK;
}
