//! sqlite-zig build — Phase 0 foundation.
//!
//! Two build modes:
//!   * split (default): compile each SQLite C translation unit from vendor/tsrc
//!     separately, then link.  This is the mode that enables the incremental
//!     C -> Zig migration: as each module is ported, its .c file is dropped
//!     from the list (see `ported_modules`) and the Zig replacement in src/ is
//!     compiled in its place, keeping the same C-ABI symbols.
//!   * amalgamation (-Damalgamation=true): build the single-file sqlite3.c.
//!     A fast sanity check; cannot be swapped file-by-file.
//!
//! Both produce a static libsqlite3 and the `sqlite3` CLI shell.

const std = @import("std");

/// SQLite compile-time configuration. Mirrors the upstream `--dev` configure
/// (OPT_FEATURE_FLAGS + shell options). SQLITE_CORE makes the bundled
/// extensions (fts5, rtree, ...) link into the core instead of each declaring
/// its own loadable-extension `sqlite3_api` pointer.
const sqlite_flags = [_][]const u8{
    "-DSQLITE_CORE=1",
    "-DSQLITE_THREADSAFE=1",
    "-DSQLITE_ENABLE_MATH_FUNCTIONS",
    "-DSQLITE_ENABLE_FTS4",
    "-DSQLITE_ENABLE_FTS5",
    "-DSQLITE_ENABLE_RTREE",
    "-DSQLITE_ENABLE_GEOPOLY",
    "-DSQLITE_ENABLE_SESSION",
    "-DSQLITE_ENABLE_PREUPDATE_HOOK",
    "-DSQLITE_ENABLE_CARRAY",
    "-DSQLITE_ENABLE_MEMSYS5",
    "-DSQLITE_ENABLE_PERCENTILE",
    "-DSQLITE_ENABLE_DBPAGE_VTAB",
    "-DSQLITE_ENABLE_DBSTAT_VTAB",
    "-DSQLITE_ENABLE_STMTVTAB",
    "-DSQLITE_ENABLE_BYTECODE_VTAB",
    "-DSQLITE_ENABLE_OFFSET_SQL_FUNC",
    "-DSQLITE_ENABLE_UNKNOWN_SQL_FUNCTION",
    "-DSQLITE_ENABLE_EXPLAIN_COMMENTS",
    "-DSQLITE_DQS=0",
    "-DSQLITE_HAVE_ZLIB=1",
};

/// tsrc files that are NOT standalone translation units and must be skipped
/// when compiling the library:
///   geopoly.c     -> #include'd into rtree.c
///   shell.c       -> the CLI's main(); linked only into the executable
///   tclsqlite-ex.c-> TCL test harness, needs tcl.h; not part of the library
const non_tu = [_][]const u8{ "geopoly.c", "shell.c", "tclsqlite-ex.c" };

/// Modules that have been ported to Zig. As each lands, add its C basename
/// (e.g. "random.c") here AND add the corresponding src/<name>.zig below.
/// The C file is then excluded and the Zig object linked in its place.
const ported_modules = [_][]const u8{
    "random.c", // -> src/random.zig (first port; PRNG)
    "hash.c", // -> src/hash.zig (generic hash table)
    "bitvec.c", // -> src/bitvec.zig (fixed-length bitmap)
    "rowset.c", // -> src/rowset.zig (rowid set / forest of trees)
    "fault.c", // -> src/fault.zig (benign-malloc fault hooks)
    "mem1.c", // -> src/mem1.zig (default system-malloc allocator)
    "complete.c", // -> src/complete.zig (sqlite3_complete SQL tokenizer)
    "memjournal.c", // -> src/memjournal.zig (in-memory rollback journal)
    "fts3_hash.c", // -> src/fts3_hash.zig (FTS3 standalone hash table)
    "utf.c", // -> src/utf.zig (UTF-8/16 translation; first Mem-coupled port)
    "os.c", // -> src/os.zig (VFS/file dispatch + VFS registry)
    "fts3_porter.c", // -> src/fts3_porter.zig (FTS3 Porter stemmer tokenizer)
    "fts3_tokenizer1.c", // -> src/fts3_tokenizer1.zig (FTS3 "simple" tokenizer)
    "fts3_unicode.c", // -> src/fts3_unicode.zig (FTS3 unicode61 tokenizer)
    "carray.c", // -> src/carray.zig (carray table-valued function / vtab)
    "table.c", // -> src/table.zig (sqlite3_get_table / sqlite3_free_table)
    "fts3_unicode2.c", // -> src/fts3_unicode2.zig (Unicode fold/category data)
    "threads.c", // -> src/threads.zig (pthreads worker-thread helper)
    "mutex_noop.c", // -> src/mutex_noop.zig (no-op / debug-checking mutex)
    "mem5.c", // -> src/mem5.zig (MEMSYS5 buddy allocator)
    "stmt.c", // -> src/stmt.zig (sqlite_stmt eponymous virtual table)
    "mutex.c", // -> src/mutex.zig (mutex dispatch layer)
    "vdbetrace.c", // -> src/vdbetrace.zig (sqlite3VdbeExpandSql for tracing)
    "legacy.c", // -> src/legacy.zig (sqlite3_exec)
    "pcache.c", // -> src/pcache.zig (page-cache dispatch + dirty-list mgmt)
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const use_amalgamation = b.option(bool, "amalgamation", "Build the single-file amalgamation instead of the per-file split build") orelse false;
    // When true, ported Zig objects are compiled with the upstream `--dev`
    // testfixture configuration (SQLITE_DEBUG, SQLITE_TEST) instead of the
    // production library config. tools/tcltest.sh uses this so the Zig objects'
    // struct layouts / test instrumentation match the testfixture C they link
    // against. See docs/architecture.md. The flags live in the build-generated
    // `config` options module below, imported by each ported object as
    // `@import("config")`.
    const testfixture = b.option(bool, "testfixture", "Compile ported Zig objects with the --dev testfixture config (for tcltest.sh)") orelse false;

    const include_dir: []const u8 = if (use_amalgamation) "vendor/amalg" else "vendor/tsrc";

    // Comptime config mirroring the C `-D` flags that affect ported modules'
    // struct layouts and behavior. Each ported object imports this as
    // `@import("config")`; the values differ between the production library and
    // the testfixture build, exactly as C's -D flags do.
    const cfg = b.addOptions();
    cfg.addOption(bool, "sqlite_debug", testfixture);
    cfg.addOption(bool, "sqlite_test", testfixture);
    const cfg_mod = cfg.createModule();

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_mod.addIncludePath(b.path(include_dir));

    if (use_amalgamation) {
        lib_mod.addCSourceFile(.{ .file = b.path("vendor/amalg/sqlite3.c"), .flags = &sqlite_flags });
    } else {
        const tu = collectTranslationUnits(b) catch |e| std.debug.panic("failed to scan vendor/tsrc: {s}", .{@errorName(e)});
        lib_mod.addCSourceFiles(.{ .files = tu, .flags = &sqlite_flags });

        // Compile any ported Zig modules into the same library.
        for (ported_modules) |m| {
            const stem = m[0 .. m.len - 2];
            const zig_name = b.fmt("src/{s}.zig", .{stem});
            const obj_mod = b.createModule(.{
                .root_source_file = b.path(zig_name),
                .target = target,
                .optimize = optimize,
            });
            obj_mod.addImport("config", cfg_mod);
            const obj = b.addObject(.{ .name = stem, .root_module = obj_mod });
            lib_mod.addObject(obj);
        }
    }

    // `zig build test-objs [-Dtestfixture=true]` — emit each ported Zig module
    // as a standalone object into zig-out/test-objs/<name>.o, compiled
    // ReleaseSafe + PIC + no-stack-probe so tools/tcltest.sh can link them into
    // the upstream testfixture in place of the matching C file.
    {
        const test_objs_step = b.step("test-objs", "Emit ported Zig objects for tcltest.sh (use -Dtestfixture=true)");
        for (ported_modules) |m| {
            const stem = m[0 .. m.len - 2];
            const zig_name = b.fmt("src/{s}.zig", .{stem});
            const tobj_mod = b.createModule(.{
                .root_source_file = b.path(zig_name),
                .target = target,
                .optimize = .ReleaseSafe,
                .pic = true,
                .stack_check = false,
            });
            tobj_mod.addImport("config", cfg_mod);
            const tobj = b.addObject(.{ .name = stem, .root_module = tobj_mod });
            const inst = b.addInstallFileWithDir(tobj.getEmittedBin(), .prefix, b.fmt("test-objs/{s}.o", .{stem}));
            test_objs_step.dependOn(&inst.step);
        }
    }

    const lib = b.addLibrary(.{ .name = "sqlite3", .linkage = .static, .root_module = lib_mod });
    b.installArtifact(lib);

    // CLI shell: shell.c + the library.
    const shell_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    shell_mod.linkLibrary(lib);
    shell_mod.linkSystemLibrary("z", .{});
    shell_mod.linkSystemLibrary("m", .{});
    shell_mod.addIncludePath(b.path(include_dir));
    shell_mod.addCSourceFile(.{
        .file = b.path(b.fmt("{s}/shell.c", .{include_dir})),
        .flags = &sqlite_flags,
    });
    const shell = b.addExecutable(.{ .name = "sqlite3", .root_module = shell_mod });
    b.installArtifact(shell);

    // `zig build run` launches the shell (interactive). For ad-hoc queries,
    // run the installed binary directly: zig-out/bin/sqlite3 :memory: "select 1"
    const run = b.addRunArtifact(shell);
    b.step("run", "Run the sqlite3 shell").dependOn(&run.step);

    // `zig build smoke` — minimal end-to-end check.
    const smoke = b.addRunArtifact(shell);
    smoke.addArgs(&.{ ":memory:", "create table t(a,b); insert into t values(1,'x'),(2,'y'); select count(*)||'|'||group_concat(b) from t;" });
    smoke.expectStdOutEqual("2|x,y\n");
    b.step("smoke", "Build and run a smoke-test query").dependOn(&smoke.step);

    // `zig build test` — functional regression battery (core SQL + extensions).
    // Until the full upstream TCL `testfixture` suite is wired in, this is the
    // gate every ported module must keep green. See PROGRESS.md.
    const func = b.addRunArtifact(shell);
    func.setCwd(b.path("."));
    func.addArgs(&.{ ":memory:", ".read test/functional.sql" });
    func.expectStdOutEqual(@embedFile("test/functional.expected"));
    const test_step = b.step("test", "Run the functional regression battery");
    test_step.dependOn(&func.step);

    // `zig build test-unit` — Zig unit tests for ported modules (algorithm-level
    // checks, e.g. ChaCha20 against the RFC test vector). Also folded into `test`.
    const unit_step = b.step("test-unit", "Run Zig unit tests for ported modules");
    for ([_][]const u8{"src/chacha.zig"}) |t| {
        const ut = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path(t),
            .target = target,
            .optimize = optimize,
        }) });
        unit_step.dependOn(&b.addRunArtifact(ut).step);
    }
    test_step.dependOn(unit_step);

    // `zig build test-zig` — Zig-native engine test suite: SQLite test cases
    // ported to Zig `test` blocks that drive the public C API and assert results,
    // linked against this libsqlite3.a (so they exercise the ported Zig modules
    // end-to-end). Also folded into `test`.
    const zig_test_mod = b.createModule(.{
        .root_source_file = b.path("test/engine_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    zig_test_mod.linkLibrary(lib);
    zig_test_mod.linkSystemLibrary("z", .{});
    zig_test_mod.linkSystemLibrary("m", .{});
    const zig_test = b.addTest(.{ .root_module = zig_test_mod });
    const zig_test_step = b.step("test-zig", "Run the Zig-native engine test suite (links libsqlite3.a)");
    zig_test_step.dependOn(&b.addRunArtifact(zig_test).step);
    test_step.dependOn(zig_test_step);

    // `zig build sample` — a Zig program that builds + verifies the sample blog
    // database (sampledata/blog.db) through the public C API, linked against this
    // libsqlite3.a (so it drives the ported Zig modules end-to-end).
    const sample_mod = b.createModule(.{
        .root_source_file = b.path("sampledata/blog_build.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sample_mod.linkLibrary(lib);
    sample_mod.linkSystemLibrary("z", .{});
    sample_mod.linkSystemLibrary("m", .{});
    const sample_exe = b.addExecutable(.{ .name = "blog_build", .root_module = sample_mod });
    const sample_run = b.addRunArtifact(sample_exe);
    sample_run.setCwd(b.path(".")); // write sampledata/blog.db at the project root
    b.step("sample", "Build + verify the sample blog DB via a Zig program").dependOn(&sample_run.step);
}

/// The library translation-unit list. Sourced from vendor/tu.txt (one C
/// basename per line), which was generated from vendor/tsrc excluding the
/// non-standalone files in `non_tu`. Regenerate tu.txt if the vendored sources
/// change. Modules in `ported_modules` are dropped here and replaced by their
/// Zig object.
const tu_manifest = @embedFile("vendor/tu.txt");

fn collectTranslationUnits(b: *std.Build) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, tu_manifest, '\n');
    outer: while (it.next()) |name| {
        const trimmed = std.mem.trim(u8, name, " \r\t");
        if (trimmed.len == 0) continue;
        for (ported_modules) |skip| if (std.mem.eql(u8, trimmed, skip)) continue :outer;
        try list.append(b.allocator, b.fmt("vendor/tsrc/{s}", .{trimmed}));
    }
    return list.toOwnedSlice(b.allocator);
}
