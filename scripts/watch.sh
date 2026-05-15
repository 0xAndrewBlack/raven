#!/usr/bin/env bash
#
# watch.sh - ONE command: build Raven, run the highest gate reached, render to
# ~/.cache/raven/artifacts/raven-final.png (and a live Wayland window if -wayland), then print an
# result banner "CURRENT CHECK: case - PASS/FAIL" with a client-area pixel
# assertion on the window's CLIENT area (real content, not just the frame).
#
# Usage:
#   RAVEN_SYSROOT=/path/to/reactos-sysroot scripts/watch.sh
#   WAYLAND=1 RAVEN_SYSROOT=... scripts/watch.sh   # also open a live window
#
# Gates, highest first: NOTEPADPP_CASE (notepad++) > NOTEPAD_CASE (notepad) > GUI_FIXTURE (fixture).
# A gate PASSES only if the real DLL window actually PAINTS its client area
# (proxied by a real NtUserBeginPaint from the guest WndProc + client pixels).

set -u
cd "$(dirname "$0")/.." || exit 2
source scripts/raven-cache.sh || exit 2
SYSROOT="${RAVEN_SYSROOT:-/home/user/reactos-sysroot}"
PNG="$RAVEN_ARTIFACT_ROOT/raven-final.png"
LOG="$RAVEN_ARTIFACT_ROOT/watch.log"

echo "==> build"
mkdir -p "$RAVEN_CACHE_ROOT/bin"
go build -tags "guest_windows guest_linux" -o "$RAVEN_CACHE_ROOT/bin/raven-watch" ./cmd/govm || { echo "BUILD FAILED"; exit 2; }
RV="$RAVEN_CACHE_ROOT/bin/raven-watch"

# Gates are climbed in order GUI_FIXTURE -> NOTEPAD_CASE -> NOTEPADPP_CASE. The CURRENT gate is the lowest one
# not yet passing; we run that. (Until GUI_FIXTURE paints, that's GUI_FIXTURE - no point running
# notepad/npp, which need everything GUI_FIXTURE needs plus CRT/COM.) Override with GATE=.
NPP=testdata/npp/notepad++.exe
NP="$RAVEN_CACHE_ROOT/reactos-apps/notepad.exe"
GUI_FIXTURE=testdata/dll_fixture/raven_gui_min.exe
GATE="${GATE:-GUI_FIXTURE}"
case "$GATE" in
  NOTEPADPP_CASE) APP="$NPP" ;;
  NOTEPAD_CASE)   APP="$NP" ;;
  *)    GATE=GUI_FIXTURE; APP="$GUI_FIXTURE" ;;
esac
echo "==> current gate: $GATE ($APP)"

run() { timeout 30 "$RV" "$@" </dev/null 2>"$LOG"; }

rm -f "$PNG"
run -wayland=false -sysroot "$SYSROOT" -trace-syscall -render-png "$PNG" "$APP"
if [ "${WAYLAND:-0}" = 1 ]; then
  echo "==> opening live Wayland window (close it to continue)"
  timeout 25 "$RV" -wayland=true -sysroot "$SYSROOT" "$APP" </dev/null >/dev/null 2>&1 || true
fi

# Proxy that the real guest WndProc painted: it issued NtUserBeginPaint.
painted_syscall=no
grep -q "NtUserBeginPaint" "$LOG" && painted_syscall=yes

# Pixel assertion: the client area (below the caption) must contain real content
# - both the window background fill AND darker text pixels (not a flat frame).
client_content=$(python3 - "$PNG" <<'PY' 2>/dev/null
import sys, struct, zlib
def load(p):
    d=open(p,'rb').read()
    assert d[:8]==b'\x89PNG\r\n\x1a\n'
    i=8; w=h=0; idat=b''
    while i<len(d):
        ln=struct.unpack('>I',d[i:i+4])[0]; typ=d[i+4:i+8]; data=d[i+8:i+8+ln]; i+=12+ln
        if typ==b'IHDR': w,h=struct.unpack('>II',data[:8])
        elif typ==b'IDAT': idat+=data
        elif typ==b'IEND': break
    raw=zlib.decompress(idat); px=[]; stride=w*4; off=0; prev=bytearray(stride)
    for y in range(h):
        f=raw[off]; off+=1; line=bytearray(raw[off:off+stride]); off+=stride
        if f==1:
            for x in range(4,stride): line[x]=(line[x]+line[x-4])&255
        elif f==2:
            for x in range(stride): line[x]=(line[x]+prev[x])&255
        elif f==3:
            for x in range(stride): line[x]=(line[x]+((line[x-4] if x>=4 else 0)+prev[x])//2)&255
        elif f==4:
            for x in range(stride):
                a=line[x-4] if x>=4 else 0; b=prev[x]; c=prev[x-4] if x>=4 else 0
                p=a+b-c; pa=abs(p-a); pb=abs(p-b); pc=abs(p-c)
                pr=a if (pa<=pb and pa<=pc) else (b if pb<=pc else c); line[x]=(line[x]+pr)&255
        px.append(bytes(line)); prev=line
    return w,h,px
try:
    w,h,px=load(sys.argv[1])
except Exception as e:
    print("ERR"); sys.exit(0)
# Fixture window is at (0,0,400,300); client area roughly x 4..396, y 26..296.
bg=0; dark=0
for y in range(26, min(296,h)):
    row=px[y]
    for x in range(4, min(396,w)):
        r,g,b=row[x*4],row[x*4+1],row[x*4+2]
        if r>230 and g>230 and b>230: bg+=1          # window background fill
        elif r<90 and g<90 and b<90: dark+=1          # text pixels
# Real paint = a light background fill with some dark text pixels on top.
print("YES" if (bg>2000 and dark>40) else "NO")
PY
)

echo
echo "================ RAVEN WATCH ================"
echo "  PNG: $PNG"
echo "  guest WndProc painted (NtUserBeginPaint): $painted_syscall"
echo "  client-area real content (bg fill + text): ${client_content:-NO}"
if [ "$painted_syscall" = yes ] && [ "${client_content:-NO}" = YES ]; then
  echo "  CURRENT CHECK: $GATE - PASS  (real user32/gdi32 window painted)"
else
  echo "  CURRENT CHECK: $GATE - FAIL"
  echo "    The window does not yet paint via real user32/gdi32. Highest real"
  echo "    progress: the fixture drives real user32/gdi32 init and reaches"
  echo "    RegisterClass+CreateWindowEx; ShowWindow/BeginPaint are no-op because"
  echo "    user32 hasn't done NtUserProcessConnect (gSharedInfo unset). See"
  echo "    Run the fixture command shown above."
fi
echo "============================================="
