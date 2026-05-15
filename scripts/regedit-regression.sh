#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/scripts/raven-cache.sh" || exit 2
TARGET=${REGEDIT_EXE:-"$HOME/Downloads/regedit.exe"}
RUNTIME_FILE="$RAVEN_LABWC_RUNTIME_FILE"
RAVEN=${RAVEN:-}
TIMEOUT_SECONDS=${REGEDIT_TIMEOUT:-18}

if [[ ! -f "$TARGET" ]]; then
	echo "regedit executable not found: $TARGET" >&2
	exit 1
fi
if [[ ! -f "$RUNTIME_FILE" ]]; then
	echo "isolated labwc runtime file not found: $RUNTIME_FILE" >&2
	exit 1
fi

runtime_raw=$(<"$RUNTIME_FILE")
runtime=$(realpath -m -- "$runtime_raw")
if [[ -z "$runtime_raw" || "$runtime" != "$RAVEN_RUNTIME_ROOT"/labwc-* || ! -S "$runtime/wayland-0" ]]; then
	echo "isolated labwc socket is unavailable" >&2
	exit 1
fi
user_runtime="/run/user/$(id -u)"
if [[ -S "$user_runtime/wayland-0" &&
	"$runtime/wayland-0" -ef "$user_runtime/wayland-0" ]]; then
	echo "isolated socket resolves to the user compositor" >&2
	exit 1
fi
labwc_pid=""
for proc in /proc/[0-9]*; do
	[[ "$(cat "$proc/comm" 2>/dev/null)" == "labwc" ]] || continue
	if (tr '\0' '\n' <"$proc/environ") 2>/dev/null | grep -Fqx "XDG_RUNTIME_DIR=$runtime"; then
		labwc_pid="${proc##*/}"
		break
	fi
done
if [[ -z "$labwc_pid" ]]; then
	echo "isolated labwc process is unavailable" >&2
	exit 1
fi
if [[ -z "$RAVEN" ]]; then
	RAVEN=$(mktemp "$RAVEN_TMPDIR/regedit.XXXXXX")
	(
		cd "$ROOT"
		go build -tags guest_windows -o "$RAVEN" ./cmd/govm
	)
	trap 'rm -f "$RAVEN"' EXIT
fi

if [[ -z "${REGEDIT_ARTIFACTS:-}" ]]; then
	out=$(mktemp -d "$RAVEN_ARTIFACT_ROOT/regedit.XXXXXX") || exit 2
	printf 'raven-regedit-regression\n' >"$out/.raven-regedit-owned"
	raven_prune_owned_runs "$RAVEN_ARTIFACT_ROOT" ".raven-regedit-owned" 5 || exit 2
else
	out=$(realpath -m -- "$REGEDIT_ARTIFACTS")
	case "$out/" in
	"$RAVEN_HOME"/*) ;;
	*)
		echo "REGEDIT_ARTIFACTS must stay under HOME" >&2
		exit 2
		;;
	esac
fi
mkdir -p "$out"
log="$out/regedit.log"
screen="$out/regedit.png"
selected="$out/regedit-selected.png"

set +e
env -u DISPLAY -u WAYLAND_SOCKET \
	XDG_RUNTIME_DIR="$runtime" \
	WAYLAND_DISPLAY=wayland-0 \
	RAVEN_TRACE_CLICK=1 \
	timeout --foreground --kill-after=2s "${TIMEOUT_SECONDS}s" \
	"$RAVEN" \
	-auto "5:screenshot:$screen;7:click:80,46;10:screenshot:$selected" \
	"$TARGET" >"$log" 2>&1
status=$?
set -e

if [[ $status -ne 124 ]]; then
	echo "regedit exited before the regression window elapsed (status $status)" >&2
	tail -80 "$log" >&2
	exit 1
fi
if ! grep -q 'CreateWindowExW class="RegEdit_RegEdit"' "$log"; then
	echo "regedit did not create its main window" >&2
	tail -80 "$log" >&2
	exit 1
fi
for control in SysTreeView32 SysListView32; do
	if ! grep -q "CreateWindowExW class=\"$control\"" "$log"; then
		echo "regedit did not create $control" >&2
		tail -80 "$log" >&2
		exit 1
	fi
done
if ! grep -q '\[comctl32\] CreateStatusWindowW' "$log"; then
	echo "regedit did not create its status bar" >&2
	tail -80 "$log" >&2
	exit 1
fi
if grep -Eq 'cpu-recover|PE runtime error|fatal error|RIP=.*fault' "$log"; then
	echo "regedit hit a runtime fault" >&2
	tail -80 "$log" >&2
	exit 1
fi
if grep -q 'FlatSB_GetScrollInfo' "$log"; then
	echo "COMCTL32 ordinal 4 still resolves to FlatSB_GetScrollInfo" >&2
	exit 1
fi
if grep -Eq 'UNRESOLVED: ntdll\.dll!Rtl(Cm|Io)DecodeMemIoResource' "$log"; then
	echo "ntdll resource decoder imports are unresolved" >&2
	exit 1
fi
if grep -q 'UNIMPLEMENTED: shell32.dll!SHGetStockIconInfo' "$log"; then
	echo "SHGetStockIconInfo is still unimplemented" >&2
	exit 1
fi
if [[ ! -s "$screen" ]] || [[ $(stat -c %s "$screen") -lt 2000 ]]; then
	echo "regedit screenshot is missing or empty" >&2
	exit 1
fi
if [[ ! -s "$selected" ]] || [[ $(stat -c %s "$selected") -lt 2000 ]]; then
	echo "regedit selection screenshot is missing or empty" >&2
	exit 1
fi
for resource in 17 18 19 31; do
	if ! grep -q "fallback string $resource " "$log"; then
		echo "regedit did not load fallback string resource $resource" >&2
		exit 1
	fi
done
if grep -q 'Error 0x0' "$log"; then
	echo "regedit rendered an unresolved FormatMessage template" >&2
	exit 1
fi
tree_ink=$(convert "$screen" -crop 190x112+5+0 -colorspace Gray -threshold 50% -format '%[fx:(1-mean)*w*h]' info:)
header_ink=$(convert "$screen" -crop 90x14+225+3 -colorspace Gray -threshold 50% -format '%[fx:(1-mean)*w*h]' info:)
if ! awk -v pixels="$tree_ink" 'BEGIN { exit !(pixels > 500) }'; then
	echo "regedit tree contents were not rendered" >&2
	exit 1
fi
if ! awk -v pixels="$header_ink" 'BEGIN { exit !(pixels > 50) }'; then
	echo "regedit list header text was not rendered" >&2
	exit 1
fi
if ! grep -q 'hitChild=0x[0-9a-f]* class="systreeview32"' "$log"; then
	echo "regedit tree did not receive the selection click" >&2
	exit 1
fi
selection_color=$(convert "$selected" -format '%[pixel:p{200,46}]' info:)
value_ink=$(convert "$selected" -crop 100x18+225+23 -colorspace Gray -threshold 50% -format '%[fx:(1-mean)*w*h]' info:)
if [[ "$selection_color" != "srgb(0,120,215)" ]]; then
	echo "regedit tree selection was not rendered" >&2
	exit 1
fi
if ! awk -v pixels="$value_ink" 'BEGIN { exit !(pixels > 80) }'; then
	echo "regedit selected hive did not populate the value list" >&2
	exit 1
fi

printf 'regedit regression passed: %s\n' "$out"
