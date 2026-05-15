#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/raven-cache.sh || exit 2

TMP="$(mktemp -d "$RAVEN_TMPDIR/binary-type.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

RAVEN="${RAVEN:-$TMP/raven}"
if [[ ! -x "$RAVEN" ]]; then
  go build -tags guest_windows -o "$RAVEN" ./cmd/govm
fi

SOURCE="testdata/dll_fixture/binary_type_fixture.c"
PROBE_SOURCE="testdata/dll_fixture/binary_type_probe.c"
i686-w64-mingw32-gcc \
  -O2 -std=c99 -Wall -Wextra -Werror -nostdlib \
  -e _raven_entry -Wl,--subsystem,console \
  -o "$TMP/binary-type-32.exe" "$SOURCE" -lkernel32
zig cc \
  -target x86_64-windows-gnu \
  -O2 -std=c99 -Wall -Wextra -Werror -nostdlib \
  -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console \
  -o "$TMP/binary-type-64.exe" "$SOURCE" -lkernel32
i686-w64-mingw32-gcc \
  -O2 -std=c99 -Wall -Wextra -Werror -shared \
  -o "$TMP/binary-type-32.dll" "$PROBE_SOURCE"
zig cc \
  -target x86_64-windows-gnu \
  -O2 -std=c99 -Wall -Wextra -Werror -shared \
  -fno-sanitize=undefined -fno-stack-protector \
  -o "$TMP/binary-type-64.dll" "$PROBE_SOURCE"

for arch in 32 64; do
  log="$TMP/binary-type-$arch.log"
  timeout --foreground --kill-after=3s 30s \
    "$RAVEN" -wayland=false "$TMP/binary-type-$arch.exe" >"$log" 2>&1
  grep -q '\[resolve\] binary-type-.* 0 unresolved' "$log"
  grep -q '\[win32\] ExitProcess(0)' "$log"
  if grep -q '\[cpu-fault\]' "$log"; then
    cat "$log"
    exit 1
  fi
done

echo "GetBinaryTypeW PE32/PE64 EXE and DLL regression: PASS"
