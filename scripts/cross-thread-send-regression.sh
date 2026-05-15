#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/raven-cache.sh || exit 2

TMP="$(mktemp -d "$RAVEN_TMPDIR/cross-thread-send.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

RAVEN="${RAVEN:-$TMP/raven}"
if [[ ! -x "$RAVEN" ]]; then
  go build -tags guest_windows -o "$RAVEN" ./cmd/govm
fi

SOURCE="testdata/dll_fixture/cross_thread_send_fixture.c"
RESOURCE="testdata/dll_fixture/cross_thread_send_fixture.rc"
i686-w64-mingw32-windres "$RESOURCE" "$TMP/send32-resource.o"
x86_64-w64-mingw32-windres "$RESOURCE" "$TMP/send64-resource.o"
i686-w64-mingw32-gcc \
  -O2 -std=c99 -Wall -Wextra -Werror -nostdlib \
  -e _raven_entry -Wl,--subsystem,console \
  -o "$TMP/send32.exe" "$SOURCE" "$TMP/send32-resource.o" \
  -lcomctl32 -luser32 -lkernel32
zig cc \
  -target x86_64-windows-gnu \
  -O2 -std=c99 -Wall -Wextra -Werror -nostdlib \
  -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console \
  -o "$TMP/send64.exe" "$SOURCE" "$TMP/send64-resource.o" \
  -lcomctl32 -luser32 -lkernel32

for arch in 32 64; do
  log="$TMP/send-$arch.log"
  timeout --foreground --kill-after=3s 30s \
    "$RAVEN" -wayland=false "$TMP/send$arch.exe" >"$log" 2>&1
  grep -q '\[resolve\] send.* 0 unresolved' "$log"
  grep -q '\[win32\] ExitProcess(0)' "$log"
  if grep -q '\[cpu-fault\]' "$log"; then
    cat "$log"
    exit 1
  fi
done

echo "cross-thread and modal SendMessageA/W regression: PASS"
