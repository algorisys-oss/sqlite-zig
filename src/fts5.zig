//! ROOT of the Zig port of SQLite's FTS5 extension.
//!
//! The vendored `vendor/tsrc/fts5.c` is a ~28k-line amalgamation of the whole
//! FTS5 extension (ext/fts5/*). Mirroring the FTS3 family's idiom, we port it
//! as ONE Zig object: a shared foundation (`fts5_int.zig`) `@import`ed by one
//! Zig sub-file per amalgamation section. Each section file `export`s the same
//! C-ABI symbols its C counterpart defined, and calls its siblings via
//! `extern fn` — so within this single object the sections link together
//! exactly as the C TU did. The Lemon parser table (fts5parse.c) stays C.
//!
//! This file is the aggregation point: the `comptime` block below pulls every
//! section file into the compilation so their `export fn`s are emitted into the
//! one object that `build.zig` substitutes for `fts5.c`.
//!
//! ───────────────────────────────────────────────────────────────────────────
//! Section port status (amalgamation line ranges in vendor/tsrc/fts5.c):
//!
//!   [done]  fts5_int.zig      foundation: fts5.h + fts5Int.h structs/consts
//!   [done]  fts5_varint.zig   26881-27226  varint codec (leaf)
//!   [done]  fts5_buffer.zig    4188-4600   Fts5Buffer + poslist + termset utils
//!
//!   [TODO]  fts5_hash.zig      9016-9607   in-memory term hash (Fts5Hash)
//!   [TODO]  fts5_unicode2.zig 26099-26880  unicode fold/category tables (leaf)
//!   [TODO]  fts5_tokenize.zig 24601-26098  built-in tokenizers
//!   [TODO]  fts5_config.zig    4601-5727   CREATE-VTAB / %_config parsing
//!   [TODO]  fts5_aux.zig       3365-4187   built-in auxiliary funcs (bm25 etc.)
//!   [TODO]  fts5_vocab.zig    27227-28050  fts5vocab virtual table
//!   [TODO]  fts5_expr.zig      5728-9015   MATCH expression evaluator (+ parser
//!                                          glue; fts5parse.c stays C)
//!   [TODO]  fts5_index.zig     9608-19169  %_data segment b-tree (the big one)
//!   [TODO]  fts5_storage.zig  23072-24600  %_content / %_docsize access
//!   [TODO]  fts5_main.zig     19170-23071  the fts5 vtab module + registration
//!
//! Section-agent pattern (every TODO file follows this):
//!   1. `const int = @import("fts5_int.zig");` for ALL shared types/constants.
//!   2. `export fn <CName>(...) callconv(.c) ...` for each non-static C symbol
//!      the section defines (the names sibling sections / the core expect).
//!   3. `extern fn <CName>(...) callconv(.c) ...` for each sibling-section
//!      symbol it calls (resolved at link time within this object).
//!   4. Define section-PRIVATE structs locally; the foundation exposes them as
//!      `opaque{}` so other sections can hold pointers. Promote a concrete
//!      `extern struct` into fts5_int.zig only if a field must be read across
//!      a section boundary.
//!   5. Add `_ = @import("fts5_<name>.zig");` to the comptime block below.
//!   6. `zig ast-check` it, then drop "fts5.c" from build and link this object.
//! ───────────────────────────────────────────────────────────────────────────

comptime {
    _ = @import("fts5_varint.zig");
    _ = @import("fts5_buffer.zig");
    _ = @import("fts5_hash.zig");
    _ = @import("fts5_unicode2.zig");
    _ = @import("fts5_tokenize.zig");
    _ = @import("fts5_config.zig");
    _ = @import("fts5_aux.zig");
    _ = @import("fts5_vocab.zig");
    _ = @import("fts5parse.zig");
    _ = @import("fts5_expr.zig");
    _ = @import("fts5_index.zig");
    _ = @import("fts5_storage.zig");
    _ = @import("fts5_main.zig");
}
