#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE_WIDE="$ROOT/testdata/dll_fixture/end_dialog_fixture.c"
SOURCE_ANSI="$ROOT/testdata/dll_fixture/end_dialog_ansi_fixture.c"
CC32=${CC32:-i686-w64-mingw32-gcc}
CC64=${CC64:-x86_64-w64-mingw32-gcc}
RAVEN=${RAVEN:-}
TIMEOUT_SECONDS=${END_DIALOG_TIMEOUT:-15}
TMP=$(mktemp -d /tmp/raven-end-dialog.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

for command in "$CC32" "$CC64" timeout; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "required command not found: $command" >&2
		exit 2
	fi
done

if [[ -z "$RAVEN" ]]; then
	RAVEN="$TMP/raven"
	(
		cd "$ROOT"
		go build -tags guest_windows -o "$RAVEN" ./cmd/govm
	)
fi
if [[ ! -x "$RAVEN" ]]; then
	echo "Raven executable not found: $RAVEN" >&2
	exit 2
fi

for api in wide ansi; do
	source_var="SOURCE_${api^^}"
	source=${!source_var}
	"$CC32" -nostdlib -fno-stack-protector -e _raven_entry \
		-Wl,--subsystem,console -o "$TMP/end-dialog-$api-32.exe" "$source" \
		-luser32 -lkernel32
	"$CC64" -nostdlib -fno-stack-protector -e raven_entry \
		-Wl,--subsystem,console -o "$TMP/end-dialog-$api-64.exe" "$source" \
		-luser32 -lkernel32
done

for api in wide ansi; do
	for arch in 32 64; do
		fixture="$TMP/end-dialog-$api-$arch.exe"
		log="$TMP/end-dialog-$api-$arch.log"

		set +e
		env -u DISPLAY -u WAYLAND_DISPLAY -u WAYLAND_SOCKET -u XDG_RUNTIME_DIR \
			timeout --foreground --signal=TERM --kill-after=3s \
			"${TIMEOUT_SECONDS}s" "$RAVEN" -wayland=false "$fixture" \
			>"$log" 2>&1
		status=$?
		set -e

		if [[ $status -eq 124 || $status -eq 137 ]]; then
			echo "PE$arch $api EndDialog fixture timed out" >&2
			tail -80 "$log" >&2
			exit 1
		fi
		if [[ $status -ne 0 ]]; then
			echo "PE$arch $api EndDialog fixture failed with status $status" >&2
			tail -80 "$log" >&2
			exit 1
		fi
		if ! grep -Eq "\\[resolve\\] end-dialog-$api-$arch\\.exe: .* 0 unresolved" "$log"; then
			echo "PE$arch $api EndDialog fixture has unresolved imports" >&2
			tail -80 "$log" >&2
			exit 1
		fi
		if ! grep -q '\[win32\] ExitProcess(0)' "$log"; then
			echo "PE$arch $api EndDialog contract failed" >&2
			tail -80 "$log" >&2
			exit 1
		fi
		if grep -Eq 'panic:|fatal error:|runtime error:|PE runtime error|\[cpu-fault\]|cpu-recover|RIP=.*fault' "$log"; then
			echo "PE$arch $api EndDialog fixture produced a runtime fault" >&2
			tail -80 "$log" >&2
			exit 1
		fi
		printf 'PE%s %s EndDialog contract passed\n' "$arch" "$api"
	done
done
