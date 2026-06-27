#!/bin/bash
# tcltest.sh — build SQLite's TCL `testfixture` and run upstream .test files
# against our build, using the vendored TCL headers (vendor/tcl) and the
# system libtcl8.6 (no tcl-dev package required).
#
# Two variants:
#   (default)   testfixture      — upstream C library (baseline)
#   --zig       testfixture_zig  — same, but our ported Zig modules linked in
#                                  place of their C counterparts (proves ports
#                                  pass SQLite's own suite)
#
# Usage:
#   tools/tcltest.sh [--zig] [test1 test2 ...]      # default tests if none given
#
# Requires: the upstream SQLite tree and a C compiler + tclsh (for codegen).
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM="${SQLITE_SRC:-/home/rajesh/opensource/sqlite}"
GEN="$PROJ/build/gen"
TCLDIR="$PROJ/vendor/tcl"

ZIG=0
TESTS=()
for a in "$@"; do
  case "$a" in
    --zig) ZIG=1 ;;
    *) TESTS+=("$a") ;;
  esac
done
[ ${#TESTS[@]} -eq 0 ] && TESTS=(select1 func randexpr1 where2)

# 1. Configure out-of-tree with the vendored TCL (keeps upstream tree clean).
mkdir -p "$GEN"
cd "$GEN"
[ -f Makefile ] || "$UPSTREAM/configure" --dev --with-tcl="$TCLDIR" >configure.log 2>&1

# 2. Build the baseline testfixture. Remove it first so the link command is
# always logged (make is otherwise silent when the binary is up to date), which
# step 3 reconstructs to swap in the Zig objects.
rm -f testfixture
make testfixture >make_tf.log 2>&1
FIXTURE=./testfixture

# 3. Optionally relink with our Zig object(s) swapping the matching C file(s).
# MODULES lists every ported module stem; keep in sync with `ported_modules`
# in build.zig. The Zig objects are emitted by `zig build test-objs
# -Dtestfixture=true`, which compiles each src/<stem>.zig with the testfixture
# config (SQLITE_DEBUG/SQLITE_TEST) so struct layouts / test instrumentation
# match the testfixture C. Each is swapped in for upstream src/<stem>.c in the
# testfixture link command.
MODULES=(global random hash bitvec rowset fault mem1 complete ctime memjournal fts3_hash utf os fts3_porter fts3_tokenizer1 fts3_unicode carray table fts3_unicode2 threads mutex_noop mutex_unix mem5 stmt mutex vdbetrace legacy main pcache pcache1 printf fts3_aux callback vdbevtab util loadext vtab prepare auth vacuum attach backup date vdbeblob fkey trigger pager wal btree vdbemem vdbeapi vdbeaux walker update delete insert resolve vdbe func json window build analyze upsert tokenize alter vdbesort treeview pragma status btmutex dbpage dbstat memdb malloc expr whereexpr wherecode where select)
if [ "$ZIG" = 1 ]; then
  ( cd "$PROJ" && zig build test-objs -Dtestfixture=true ) >zigobjs.log 2>&1 \
    || { echo "FATAL: zig build test-objs failed"; cat zigobjs.log; exit 1; }
  OBJDIR="$PROJ/zig-out/test-objs"
  # reconstruct the testfixture link command, swapping each src/<m>.c -> <m>.o
  python3 - "$UPSTREAM" "$OBJDIR" "${MODULES[@]}" <<'PY'
import re, sys
up = sys.argv[1]
objdir = sys.argv[2]
mods = sys.argv[3:]
lines = open('make_tf.log').read().split('\n')
cmds, cur = [], []
for ln in lines:
    if ln.endswith('\\'): cur.append(ln[:-1])
    else: cur.append(ln); cmds.append(' '.join(cur)); cur=[]
if cur: cmds.append(' '.join(cur))
cmd = [c for c in cmds if '-o testfixture ' in c and 'cc ' in c][-1]
cmd = re.sub(r'^.*?exit \$\?;\s*', '', cmd)
for m in mods:
    cmd = cmd.replace(up + '/src/%s.c' % m, '%s/%s.o' % (objdir, m))
cmd = cmd.replace('-o testfixture ', '-o testfixture_zig ')
open('relink_zig.sh','w').write('#!/bin/bash\nset -e\nset -a; . ./.tclenv.sh; set +a\n'+cmd+'\n')
PY
  bash relink_zig.sh
  FIXTURE=./testfixture_zig
fi

# 4. Run the requested tests; report the per-file error summary.
echo "fixture: $FIXTURE"
fail=0
for t in "${TESTS[@]}"; do
  tf="$UPSTREAM/test/$t.test"
  [ -f "$tf" ] || { echo "$t: (no such test)"; continue; }
  out="$($FIXTURE "$tf" 2>&1 || true)"
  line="$(echo "$out" | grep -iE 'errors out of' | tail -1)"
  echo "$t: ${line:-<no summary — see output>}"
  echo "$line" | grep -qE '^0 errors|: 0 errors' || fail=1
done
exit $fail
