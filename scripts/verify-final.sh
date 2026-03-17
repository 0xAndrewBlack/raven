#!/usr/bin/env bash
#
# verify-final.sh - end-to-end verification of the Go runtime, with explicit fixture, control and application checks gate reporting.
#
# Usage:
#   RAVEN_SYSROOT=/path/to/reactos-sysroot scripts/verify-final.sh
#   (optional) WAYLAND=1 to also open a live Wayland window for the render case.
#
# It runs, in order:
#   1. build (4 tag configs)            - must compile
#   2. go test ./...                    - unit tests
#   3. scripts/regression.sh            - 10/10 end-to-end
#   4. REAL gdi32 (ReactOS) exec proof  - -call-export on a real gdi32 export
#   5. render-png                        - produces /tmp/raven-final.png
#   6. fixture, control and application check summary
#
# Exit 0 only if build+tests+regression pass. Gate PASS/FAIL is reported
# truthfully regardless.

set -u
cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
SYSROOT="${RAVEN_SYSROOT:-/home/user/reactos-sysroot}"
PNG=/tmp/raven-final.png
PASS_ALL=0

say(){ printf '\n=== %s ===\n' "$*"; }

# --- 1. build (4 tag configs) ---
say "1. build (4 configs)"
build_ok=1
for tags in "" "guest_windows" "guest_linux" "guest_windows guest_linux"; do
  if go build -tags "$tags" -o /tmp/raven-vf-build ./cmd/govm 2>/tmp/vf-build.err; then
    echo "  OK   tags=[$tags]"
  else
    echo "  FAIL tags=[$tags]"; tail -3 /tmp/vf-build.err; build_ok=0
  fi
done
# the binary used for the run cases (needs both guest tags)
go build -tags "guest_windows guest_linux" -o /tmp/raven-vf ./cmd/govm 2>/dev/null
[ "$build_ok" = 1 ] || PASS_ALL=1

# --- 2. unit tests ---
say "2. go test ./..."
if go test -tags "guest_windows guest_linux" ./... >/tmp/vf-test.out 2>&1; then
  echo "  OK"
else
  echo "  FAIL"; grep -E "FAIL|panic" /tmp/vf-test.out | head; PASS_ALL=1
fi

# --- 3. regression ---
say "3. scripts/regression.sh"
if RAVEN=/tmp/raven-vf bash scripts/regression.sh >/tmp/vf-reg.out 2>&1; then
  tail -1 /tmp/vf-reg.out
else
  echo "  FAIL"; tail -4 /tmp/vf-reg.out; PASS_ALL=1
fi

# --- 4. REAL ReactOS gdi32 execution proof ---
say "4. REAL gdi32 (ReactOS) - -call-export CreateCompatibleDC"
GDI32="$SYSROOT/Windows/System32/gdi32.dll"
gdi32_real="n/a"
if [ -f "$GDI32" ]; then
  out=$(timeout 25 /tmp/raven-vf -wayland=false -sysroot "$SYSROOT" \
          -call-export CreateCompatibleDC "$GDI32" </dev/null 2>/dev/null \
          | grep "CreateCompatibleDC =>")
  echo "  $out"
  # a valid HDC is non-zero
  if echo "$out" | grep -qE "=> [1-9]"; then gdi32_real="PASS"; else gdi32_real="FAIL"; fi
else
  echo "  sysroot gdi32 not found at $GDI32 (set RAVEN_SYSROOT)"
fi

# --- 5. render-png (win32k → gfx → PNG) ---
say "5. render-png → $PNG"
rm -f "$PNG"
render_real="n/a"
# Highest case that produces a PNG today is the win32k syscall fixture
# (guest issues real numbered win32k syscalls → pkg/gfx → PNG). NOTE: this
# exercises the win32k engine + display path, NOT the real ReactOS gdi32.
timeout 25 /tmp/raven-vf -wayland=false -call-export demo -render-png "$PNG" \
  testdata/dll_fixture/raven_win32k.dll </dev/null >/tmp/vf-png.out 2>&1
if [ -f "$PNG" ]; then
  echo "  wrote $PNG ($(file -b "$PNG" 2>/dev/null | cut -c1-40))"
  render_real="engine-only"
else
  echo "  no PNG produced"; tail -3 /tmp/vf-png.out
fi
if [ "${WAYLAND:-0}" = 1 ]; then
  echo "  (opening live Wayland window - close it to continue)"
  timeout 20 /tmp/raven-vf -wayland=true -call-export demo \
    testdata/dll_fixture/raven_win32k.dll </dev/null >/dev/null 2>&1 || true
fi

# --- 6. verification summary ---
say "GATE SUMMARY "
echo "  Build/tests/regression : $([ "$PASS_ALL" = 0 ] && echo PASS || echo FAIL)"
echo "  Real gdi32 executes    : $gdi32_real   (real ReactOS gdi32 runs a GDI export end-to-end, returns a valid HDC)"
echo "  Render engine → PNG    : $render_real (win32k syscall fixture renders to PNG via pkg/gfx)"
echo
echo "  GUI_FIXTURE (real user32+gdi32 app paints, headless PNG + live Wayland): NOT MET"
echo "     Why: the render PNG above is the SYNTHETIC win32k fixture, not real"
echo "     gdi32/user32. Real gdi32 executes individual exports (proof above),"
echo "     but a full real GUI app (notepad) does not yet reach its message loop:"
echo "     it now runs past CRT memcpy corruption (fixed) into real msvcrt/COM"
echo "     init, where it hits a chain of NULL function-pointer calls (CRT/COM"
echo "     bring-up)."
echo "  CONTROL_CHECK (comctl32 real control, zero per-control code): NOT MET (blocked on GUI_FIXTURE)"
echo "  APPLICATION_CHECK (shipped app like notepad++):                   NOT MET (blocked on GUI_FIXTURE)"
echo
echo "  Highest gate reached: real gdi32 executes GDI exports end-to-end through"
echo "  the pinned win32k syscall seam. Full application compatibility is incomplete."

exit $PASS_ALL
