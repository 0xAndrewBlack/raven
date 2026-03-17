#!/usr/bin/env bash
#
# regression.sh - runtime regression harness.
#
# Check the Go runtime and NT/win32k syscall boundary. Each case runs
# headless (-wayland=false) with a timeout and asserts a deterministic golden
# signal plus "the emulator did not panic".
#
# Usage:
#   scripts/regression.sh            # builds raven (both guest tags) and runs
#   RAVEN=/path/to/raven scripts/regression.sh   # use a prebuilt binary
#
# Exit code 0 = all pass, 1 = at least one regression.

set -u
cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"

RAVEN="${RAVEN:-}"
if [[ -z "$RAVEN" ]]; then
  RAVEN="$ROOT/.regression-raven"
  echo "==> building raven (guest_windows guest_linux)"
  if ! go build -tags "guest_windows guest_linux" -o "$RAVEN" ./cmd/govm; then
    echo "BUILD FAILED"; exit 2
  fi
fi

PASS=0; FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# run_case <name> <timeout> <golden-grep-ere> <stdin-or-/dev/null> <args...>
#
# Guest stdout and emulator stderr are captured to SEPARATE files: merging them
# into one stream lets the emulator's verbose logging interleave with and
# corrupt guest output (e.g. sqlite). The golden signal may land on either
# stream, so it is matched against both files.
run_case() {
  local name="$1" tmo="$2" golden="$3" stdin="$4"; shift 4
  local out="$TMP/$name.out" err="$TMP/$name.err"
  timeout "$tmo" "$RAVEN" -wayland=false "$@" <"$stdin" >"$out" 2>"$err"
  local rc=$?
  local why=""
  # A Go panic / runtime error is always a regression, regardless of golden.
  if grep -qE "panic:|runtime error:|fatal error:" "$out" "$err"; then
    why="emulator panicked"
  elif ! grep -qhE "$golden" "$out" "$err"; then
    why="golden not found: /$golden/ (rc=$rc)"
  fi
  if [[ -z "$why" ]]; then
    printf "  PASS  %-22s\n" "$name"; PASS=$((PASS+1))
  else
    printf "  FAIL  %-22s %s\n" "$name" "$why"; FAIL=$((FAIL+1))
    { cat "$out"; cat "$err"; } | sed 's/^/        | /' | tail -4
  fi
}

echo "==> running regression cases"

# 1. RISC-V ELF: prints a known string.
run_case hello_rv64    20 "Hello, Tech VM!"        /dev/null testdata/hello.rv64

# 2. RISC-V ELF: loads and runs to completion without crashing.
run_case exit42_rv64   20 "\[loader\] ELF Type"   /dev/null testdata/exit42.rv64

# 3. Windows PE CLI: SQLite evaluates a query correctly (SELECT 2+2 -> 4).
printf 'SELECT 2+2;\n.quit\n' > "$TMP/sql.in"
run_case sqlite_select 30 "sqlite> *4"            "$TMP/sql.in" testdata/sqlite3.exe

# 4. Windows PE GUI: Notepad runs the message loop and exits cleanly.
run_case notepad_run   25 "\[win32\] exit\(0\)"   /dev/null testdata/notepad.exe

# 5-7. DLL export check: load a real (non-synthetic) PE DLL, run DllMain, call an
#      export end-to-end, recover the correct return value.
FIX=testdata/dll_fixture/raven_min.dll
run_case dll_add       20 "raven_add => 42"       /dev/null -call-export raven_add:20,22  "$FIX"
run_case dll_magic     20 "raven_magic => 10794"  /dev/null -call-export raven_magic       "$FIX"
run_case dll_sum3      20 "raven_sum3 => 6"        /dev/null -call-export raven_sum3:1,2,3  "$FIX"
run_case dll_inc       20 "raven_inc => 101"       /dev/null -call-export raven_inc          "$FIX"  # .data + reloc
run_case dll_double    20 "raven_double => 42"     /dev/null -call-export raven_double:21    "$FIX"  # intra-module call

echo "==> $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
