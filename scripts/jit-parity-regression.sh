#!/usr/bin/env bash

set -uo pipefail

TOTAL_TIMEOUT_SEC="${JIT_PARITY_TOTAL_TIMEOUT_SEC:-720}"
if [[ ! "$TOTAL_TIMEOUT_SEC" =~ ^[1-9][0-9]*$ ]]; then
	echo "FAIL: JIT_PARITY_TOTAL_TIMEOUT_SEC must be a positive integer" >&2
	exit 2
fi
if [[ "${JIT_PARITY_TIMEOUT_INNER:-}" != 1 ]]; then
	exec timeout --signal=TERM --kill-after=5s \
		"${TOTAL_TIMEOUT_SEC}s" env JIT_PARITY_TIMEOUT_INNER=1 "$0" "$@"
fi

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
source scripts/raven-cache.sh || exit 2

ARTIFACTS="${JIT_PARITY_ARTIFACTS:-}"
RUN_NPP=1
RUN_DXBALL=1
MODE_FILTER=""

usage() {
	cat <<'EOF'
Usage: scripts/jit-parity-regression.sh [options]

Options:
  --artifacts DIR   create and retain a unique owned run under DIR
  --fixtures-only   run only PE32 and PE64 fixture parity
  --skip-npp        skip the Notepad++ workflow
  --skip-dxball     skip the DX-Ball progress sample
  --mode MODE       run only interpreter, closure, or native
  -h, --help        show this help

Environment:
  JIT_PARITY_TOTAL_TIMEOUT_SEC    whole-script hard timeout, default 720
  FIXTURE_TIMEOUT_SEC             fixture timeout, default 30
  NPP_TIMEOUT_SEC                 Notepad++ timeout, default 150
  DXBALL_SAMPLE_SEC               DX-Ball screenshot delay, default 30
  DXBALL_TIMEOUT_SEC              DX-Ball timeout, default sample + 45
  NPP_PIXEL_FUZZ                  ImageMagick color fuzz, default 2%
  NPP_EDITOR_PIXEL_TOLERANCE      cross-mode editor AE limit, default 3000
  NPP_DIALOG_PIXEL_TOLERANCE      cross-mode dialog AE limit, default 2500
  DXBALL_OUTSIDE_PIXEL_TOLERANCE  cross-mode non-progress AE limit, default 500
  DXBALL_MIN_PROGRESS_PIXELS      changed progress pixels required, default 28
  DXBALL_NATIVE_MIN_RATIO         native/closure progress floor, default 0.50
  RAVEN_DXBALL_EXE                override the DX-Ball payload path
  RAVEN_LABWC_RUNTIME             isolated runtime, must match the trusted path
EOF
}

while (($#)); do
	case "$1" in
	--artifacts)
		[[ $# -ge 2 ]] || {
			echo "FAIL: --artifacts requires a directory" >&2
			exit 2
		}
		ARTIFACTS="$2"
		shift 2
		;;
	--fixtures-only)
		RUN_NPP=0
		RUN_DXBALL=0
		shift
		;;
	--skip-npp)
		RUN_NPP=0
		shift
		;;
	--skip-dxball)
		RUN_DXBALL=0
		shift
		;;
	--mode)
		[[ $# -ge 2 ]] || {
			echo "FAIL: --mode requires a value" >&2
			exit 2
		}
		MODE_FILTER="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "FAIL: unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

case "$MODE_FILTER" in
"") MODES=(interpreter closure native) ;;
interpreter | closure | native) MODES=("$MODE_FILTER") ;;
*)
	echo "FAIL: --mode must be interpreter, closure, or native" >&2
	exit 2
	;;
esac

if [[ -z "$ARTIFACTS" ]]; then
	ARTIFACTS="$RAVEN_ARTIFACT_ROOT/jit-parity"
fi
if [[ "$ARTIFACTS" != /* ]]; then
	ARTIFACTS="$ROOT/${ARTIFACTS#./}"
fi
ARTIFACTS="$(readlink -m "$ARTIFACTS")"
case "$ARTIFACTS" in
"$ROOT" | "$ROOT"/*)
	echo "FAIL: artifacts must be outside the repository" >&2
	exit 2
	;;
esac
mkdir -p "$ARTIFACTS" || {
	echo "FAIL: could not create artifact root: $ARTIFACTS" >&2
	exit 2
}
ARTIFACT_ROOT="$(cd "$ARTIFACTS" && pwd)" || exit 2
ARTIFACTS="$ARTIFACT_ROOT/run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir "$ARTIFACTS" || {
	echo "FAIL: could not create owned artifact run: $ARTIFACTS" >&2
	exit 2
}
printf 'raven-jit-parity\n' >"$ARTIFACTS/.raven-jit-parity-owned"
raven_prune_owned_runs "$ARTIFACT_ROOT" ".raven-jit-parity-owned" 5 || {
	echo "FAIL: could not prune owned JIT parity runs" >&2
	exit 2
}
echo "JIT parity artifacts: $ARTIFACTS"

FIXTURE_TIMEOUT_SEC="${FIXTURE_TIMEOUT_SEC:-30}"
NPP_TIMEOUT_SEC="${NPP_TIMEOUT_SEC:-150}"
DXBALL_SAMPLE_SEC="${DXBALL_SAMPLE_SEC:-30}"
DXBALL_TIMEOUT_SEC="${DXBALL_TIMEOUT_SEC:-$((DXBALL_SAMPLE_SEC + 45))}"
NPP_PIXEL_FUZZ="${NPP_PIXEL_FUZZ:-2%}"
NPP_EDITOR_PIXEL_TOLERANCE="${NPP_EDITOR_PIXEL_TOLERANCE:-3000}"
NPP_DIALOG_PIXEL_TOLERANCE="${NPP_DIALOG_PIXEL_TOLERANCE:-2500}"
DXBALL_OUTSIDE_PIXEL_TOLERANCE="${DXBALL_OUTSIDE_PIXEL_TOLERANCE:-500}"
DXBALL_MIN_PROGRESS_PIXELS="${DXBALL_MIN_PROGRESS_PIXELS:-28}"
DXBALL_NATIVE_MIN_RATIO="${DXBALL_NATIVE_MIN_RATIO:-0.50}"

declare -a ACTIVE_TIMERS=()
declare -a KNOWN_GROUPS=()
declare -a FAILURES=()
declare -a MODE_ENV=()
declare -A TIMER_GROUP=()
declare -A NPP_OK=()
declare -A DXBALL_OK=()
GUI_PROCESS_GROUP=""
GUI_RAVEN_PID=""
CLEANUP_DONE=0
LAST_METRIC=""

raven_processes() {
	local proc
	local executable

	[[ -n "${RAVEN:-}" ]] || return
	for proc in /proc/[0-9]*; do
		executable="$(readlink "$proc/exe" 2>/dev/null || true)"
		[[ "$executable" == "$RAVEN" ]] || continue
		printf '%s\n' "${proc##*/}"
	done
}

find_timer_raven() {
	local timer_pid="$1"
	local deadline=$((SECONDS + 10))
	local pid
	local parent

	while ((SECONDS < deadline)); do
		while read -r pid; do
			[[ -n "$pid" ]] || continue
			parent="$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/$pid/status" \
				2>/dev/null)"
			if [[ "$parent" == "$timer_pid" ]]; then
				printf '%s\n' "$pid"
				return 0
			fi
		done < <(raven_processes)
		sleep 0.05
	done
	return 1
}

group_processes() {
	local process_group="$1"

	ps -eo pid=,pgid= |
		awk -v process_group="$process_group" '$2 == process_group { print $1 }'
}

assert_group_environment() {
	local mode="$1"
	local scenario="$2"
	local process_group="$3"
	local stage="$4"
	local evidence="$ARTIFACTS/$mode/${scenario}.environment"
	local pid
	local child_env
	local jit_value
	local native_value
	local members=0
	local hash

	printf 'stage=%s process_group=%s\n' "$stage" "$process_group" >>"$evidence"
	while read -r pid; do
		[[ -n "$pid" && -r "/proc/$pid/environ" ]] || continue
		child_env="$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null)" || continue
		members=$((members + 1))
		if grep -Eq '^(DISPLAY|WAYLAND_SOCKET)=' <<<"$child_env"; then
			fatal "$mode/$scenario process $pid inherited DISPLAY or WAYLAND_SOCKET"
		fi
		grep -Fqx "XDG_RUNTIME_DIR=$RUNTIME" <<<"$child_env" ||
			fatal "$mode/$scenario process $pid has the wrong XDG_RUNTIME_DIR"
		grep -Fqx 'WAYLAND_DISPLAY=wayland-0' <<<"$child_env" ||
			fatal "$mode/$scenario process $pid has the wrong WAYLAND_DISPLAY"
		jit_value="$(sed -n 's/^RAVEN_JIT=//p' <<<"$child_env")"
		native_value="$(sed -n 's/^RAVEN_JIT_NATIVE=//p' <<<"$child_env")"
		[[ -n "$jit_value" ]] || jit_value="unset"
		[[ -n "$native_value" ]] || native_value="unset"
		case "$mode" in
		interpreter)
			[[ "$jit_value" == unset && "$native_value" == unset ]] ||
				fatal "$mode/$scenario process $pid has JIT variables enabled"
			;;
		closure)
			[[ "$jit_value" == 1 && "$native_value" == unset ]] ||
				fatal "$mode/$scenario process $pid does not have closure-only JIT"
			;;
		native)
			[[ "$jit_value" == 1 && "$native_value" == 1 ]] ||
				fatal "$mode/$scenario process $pid does not have native JIT"
			;;
		esac
		hash="$(sha256sum "/proc/$pid/environ" 2>/dev/null | awk '{ print $1 }')"
		printf 'pid=%s environ_sha256=%s display_entries=0\n' "$pid" "$hash" \
			>>"$evidence"
		grep -E '^(XDG_RUNTIME_DIR|WAYLAND_DISPLAY|RAVEN_JIT|RAVEN_JIT_NATIVE)=' \
			<<<"$child_env" >>"$evidence"
	done < <(group_processes "$process_group")
	printf 'members=%s\n' "$members" >>"$evidence"
	[[ "$stage" != initial || "$members" -gt 0 ]] ||
		fatal "$mode/$scenario process group $process_group had no observable members"
}

assert_gui_environment() {
	local mode="$1"
	local scenario="$2"
	local timer_pid="$3"
	local pid
	local evidence="$ARTIFACTS/$mode/${scenario}.environment"

	pid="$(find_timer_raven "$timer_pid")" ||
		fatal "$mode/$scenario Raven GUI child was not observable under timer $timer_pid"
	GUI_RAVEN_PID="$pid"
	GUI_PROCESS_GROUP="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')"
	[[ -n "$GUI_PROCESS_GROUP" && "$GUI_PROCESS_GROUP" == "$pid" ]] ||
		fatal "$mode/$scenario Raven GUI child did not lead an isolated process group"
	: >"$evidence"
	TIMER_GROUP["$timer_pid"]="$GUI_PROCESS_GROUP"
	KNOWN_GROUPS+=("$GUI_PROCESS_GROUP")
	assert_group_environment "$mode" "$scenario" "$GUI_PROCESS_GROUP" initial
}

stop_raven_processes() {
	local pid

	while read -r pid; do
		[[ -n "$pid" ]] || continue
		kill -TERM "$pid" 2>/dev/null || true
	done < <(raven_processes)
	sleep 0.2
	while read -r pid; do
		[[ -n "$pid" ]] || continue
		kill -KILL "$pid" 2>/dev/null || true
	done < <(raven_processes)
}

cleanup_group() {
	local process_group="$1"
	local deadline

	[[ -n "$process_group" ]] || return
	kill -TERM -- "-$process_group" 2>/dev/null || true
	deadline=$((SECONDS + 1))
	while [[ -n "$(group_processes "$process_group")" ]] &&
		((SECONDS < deadline)); do
		sleep 0.05
	done
	kill -KILL -- "-$process_group" 2>/dev/null || true
}

terminate_timer() {
	local timer_pid="$1"
	local deadline

	kill -TERM "$timer_pid" 2>/dev/null || true
	deadline=$((SECONDS + 1))
	while kill -0 "$timer_pid" 2>/dev/null && ((SECONDS < deadline)); do
		sleep 0.05
	done
	kill -KILL "$timer_pid" 2>/dev/null || true
}

cleanup_all() {
	local timer_pid
	local process_group

	((CLEANUP_DONE == 0)) || return
	CLEANUP_DONE=1
	for timer_pid in "${ACTIVE_TIMERS[@]}"; do
		process_group="${TIMER_GROUP[$timer_pid]:-}"
		cleanup_group "$process_group"
		terminate_timer "$timer_pid"
	done
	stop_raven_processes
}
trap cleanup_all EXIT
trap 'cleanup_all; exit 130' INT
trap 'cleanup_all; exit 143' TERM

fatal() {
	echo "FAIL: $1" >&2
	echo "$1" >>"$ARTIFACTS/failures.txt"
	exit 2
}

record_failure() {
	FAILURES+=("$1")
	echo "FAIL: $1" >&2
	echo "$1" >>"$ARTIFACTS/failures.txt"
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fatal "required command is missing: $1"
}

for command_name in go git tar find sort sha256sum timeout /usr/bin/time setsid ps \
	i686-w64-mingw32-gcc zig cc identify magick compare awk grep sed \
	readlink wc date cp tee cat tr id; do
	require_command "$command_name"
done

TRUSTED_RUNTIME_RAW="$(cat "$RAVEN_LABWC_RUNTIME_FILE" 2>/dev/null || true)"
TRUSTED_RUNTIME=""
if [[ -n "$TRUSTED_RUNTIME_RAW" ]]; then
	TRUSTED_RUNTIME="$(realpath -m -- "$TRUSTED_RUNTIME_RAW")"
fi
RUNTIME_RAW="${RAVEN_LABWC_RUNTIME:-$TRUSTED_RUNTIME}"
RUNTIME=""
if [[ -n "$RUNTIME_RAW" ]]; then
	RUNTIME="$(realpath -m -- "$RUNTIME_RAW")"
fi
case "$RUNTIME" in
"$RAVEN_RUNTIME_ROOT"/labwc-*) ;;
*) fatal "isolated labwc runtime path is not trusted: ${RUNTIME:-empty}" ;;
esac
[[ -n "$TRUSTED_RUNTIME" && "$RUNTIME" == "$TRUSTED_RUNTIME" ]] ||
	fatal "isolated labwc runtime does not match $RAVEN_LABWC_RUNTIME_FILE"
[[ -S "$RUNTIME/wayland-0" ]] || fatal "isolated labwc socket is unavailable"
USER_SESSION_RUNTIME="/run/user/$(id -u)"
if [[ -S "$USER_SESSION_RUNTIME/wayland-0" &&
	"$RUNTIME/wayland-0" -ef "$USER_SESSION_RUNTIME/wayland-0" ]]; then
	fatal "isolated socket resolves to the user compositor"
fi

LABWC_PID=""
for proc in /proc/[0-9]*; do
	[[ "$(cat "$proc/comm" 2>/dev/null || true)" == "labwc" ]] || continue
	if (tr '\0' '\n' <"$proc/environ") 2>/dev/null |
		grep -Fqx "XDG_RUNTIME_DIR=$RUNTIME"; then
		LABWC_PID="${proc##*/}"
		break
	fi
done
[[ -n "$LABWC_PID" ]] || fatal "isolated labwc process is unavailable"
printf 'runtime=%s\nlabwc_pid=%s\n' "$RUNTIME" "$LABWC_PID" \
	>"$ARTIFACTS/compositor.txt"

SOURCE_SNAPSHOT="$ARTIFACTS/source"
mkdir -p "$SOURCE_SNAPSHOT"
find . -type f \
	\( -name '*.go' -o -name '*.s' -o -name go.mod -o -name go.sum \) \
	-not -path './.git/*' -print0 |
	sort -z |
	tar --null -T - -cf "$ARTIFACTS/source.tar"
tar -xf "$ARTIFACTS/source.tar" -C "$SOURCE_SNAPSHOT" ||
	fatal "source snapshot extraction failed"
(
	cd "$SOURCE_SNAPSHOT" || exit 1
	find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$ARTIFACTS/source.sha256" || fatal "source snapshot manifest failed"
git rev-parse HEAD >"$ARTIFACTS/source-revision.txt" 2>/dev/null || true
git status --porcelain=v1 >"$ARTIFACTS/source-status.txt" 2>/dev/null || true

mkdir -p "$ARTIFACTS/bin"
(
	cd "$SOURCE_SNAPSHOT" || exit 1
	go build -buildvcs=false -trimpath -tags guest_windows \
		-o "$ARTIFACTS/bin/raven" ./cmd/govm
) >"$ARTIFACTS/build.log" 2>&1 || fatal "guest_windows Raven build failed"
RAVEN="$ARTIFACTS/bin/raven"
sha256sum "$RAVEN" >"$ARTIFACTS/raven.sha256"

FIXTURE_SOURCE="$ROOT/testdata/fixtures/jit_parity_arithmetic.c"
[[ -f "$FIXTURE_SOURCE" ]] || fatal "JIT parity fixture source is missing"
mkdir -p "$ARTIFACTS/fixtures"
cc -O2 -std=c99 -Wall -Wextra -Werror \
	-o "$ARTIFACTS/fixtures/jit_parity_reference" "$FIXTURE_SOURCE" \
	>"$ARTIFACTS/fixtures/build-reference.log" 2>&1 ||
	fatal "host fixture reference did not build"
HOST_RESULT="$("$ARTIFACTS/fixtures/jit_parity_reference")"
[[ "$HOST_RESULT" =~ ^[0-9]+$ ]] ||
	fatal "host fixture reference returned a non-numeric result"
EXPECTED_RESULT=76592578
[[ "$HOST_RESULT" == "$EXPECTED_RESULT" ]] ||
	fatal "host fixture result changed: $HOST_RESULT, expected $EXPECTED_RESULT"
printf '%s\n' "$EXPECTED_RESULT" >"$ARTIFACTS/fixtures/expected-result.txt"

i686-w64-mingw32-gcc -O2 -std=c99 -Wall -Wextra -Werror -nostdlib \
	-fno-stack-protector -e _raven_entry -Wl,--subsystem,console \
	-o "$ARTIFACTS/fixtures/jit_parity_32.exe" "$FIXTURE_SOURCE" -lkernel32 \
	>"$ARTIFACTS/fixtures/build-32.log" 2>&1 ||
	fatal "PE32 JIT parity fixture did not build"
zig cc -target x86_64-windows-gnu -O2 -std=c99 -Wall -Wextra -Werror \
	-nostdlib -fno-sanitize=undefined -fno-stack-protector \
	-Wl,-e,raven_entry -Wl,--subsystem,console \
	-o "$ARTIFACTS/fixtures/jit_parity_64.exe" "$FIXTURE_SOURCE" -lkernel32 \
	>"$ARTIFACTS/fixtures/build-64.log" 2>&1 ||
	fatal "PE64 JIT parity fixture did not build"

set_mode_env() {
	local mode="$1"

	case "$mode" in
	interpreter)
		MODE_ENV=(-u RAVEN_JIT -u RAVEN_JIT_NATIVE \
			-u RAVEN_JIT_PE32_EXPERIMENTAL)
		;;
	closure)
		MODE_ENV=(-u RAVEN_JIT_NATIVE RAVEN_JIT=1 \
			RAVEN_JIT_PE32_EXPERIMENTAL=1)
		;;
	native)
		MODE_ENV=(RAVEN_JIT=1 RAVEN_JIT_NATIVE=1 \
			RAVEN_JIT_PE32_EXPERIMENTAL=1)
		;;
	*) fatal "unknown execution mode: $mode" ;;
	esac
}

mode_selected() {
	local wanted="$1"
	local mode

	for mode in "${MODES[@]}"; do
		[[ "$mode" == "$wanted" ]] && return 0
	done
	return 1
}

check_log_health() {
	local mode="$1"
	local scenario="$2"
	local log="$3"

	if grep -Eqi '\[cpu-fault\]|PE runtime error|panic:|fatal error:|segmentation fault|UNIMPLEMENTED-OPCODE' "$log"; then
		record_failure "$mode/$scenario reported a CPU or runtime failure"
	fi
	if grep -Eq '(^|[^0-9])[1-9][0-9]* unresolved([^0-9]|$)' "$log"; then
		record_failure "$mode/$scenario reported unresolved imports"
	fi
	case "$mode" in
	interpreter)
		if grep -q '\[jit\] enabled' "$log"; then
			record_failure "$mode/$scenario unexpectedly enabled JIT"
		fi
		;;
	closure)
		grep -q '\[jit\] enabled mode32=' "$log" ||
			record_failure "$mode/$scenario did not enable closure JIT"
		if grep -q '\[jit\] native x86-64 codegen enabled' "$log"; then
			record_failure "$mode/$scenario unexpectedly enabled native codegen"
		fi
		;;
	native)
		grep -q '\[jit\] enabled mode32=' "$log" ||
			record_failure "$mode/$scenario did not enable JIT"
		grep -q '\[jit\] native x86-64 codegen enabled' "$log" ||
			record_failure "$mode/$scenario lacks native-enabled evidence"
		;;
	esac
}

read_timing() {
	local path="$1"
	local key="$2"

	sed -n "s/^${key}=//p" "$path" 2>/dev/null | tail -1
}

run_fixture() {
	local mode="$1"
	local arch="$2"
	local mode_dir="$ARTIFACTS/$mode"
	local fixture="$ARTIFACTS/fixtures/jit_parity_${arch}.exe"
	local log="$mode_dir/fixture-${arch}.log"
	local timing="$mode_dir/fixture-${arch}.time"
	local status
	local observed

	mkdir -p "$mode_dir"
	set_mode_env "$mode"
	/usr/bin/time -f 'elapsed_sec=%e\nmaxrss_kb=%M' -o "$timing" \
		timeout --foreground --kill-after=3s "${FIXTURE_TIMEOUT_SEC}s" \
		env -u DISPLAY -u WAYLAND_SOCKET \
		"${MODE_ENV[@]}" XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
		"$RAVEN" -wayland=false "$fixture" \
		>"$log" 2>&1
	status=$?
	if ((status != (EXPECTED_RESULT & 255))); then
		record_failure "$mode/fixture-$arch host status $status, expected $((EXPECTED_RESULT & 255))"
	fi
	check_log_health "$mode" "fixture-$arch" "$log"
	observed="$(sed -n 's/.*\[win32\] ExitProcess(\([0-9][0-9]*\)).*/\1/p' \
		"$log" | tail -1)"
	if [[ "$observed" != "$EXPECTED_RESULT" ]]; then
		record_failure "$mode/fixture-$arch result ${observed:-missing}, expected $EXPECTED_RESULT"
	fi
	printf '%s\tfixture-%s\t%s\t%s\t%s\t%s\n' \
		"$mode" "$arch" "${observed:-missing}" \
		"$(read_timing "$timing" elapsed_sec)" \
		"$(read_timing "$timing" maxrss_kb)" "-" \
		>>"$ARTIFACTS/summary.tsv"
}

run_gui() {
	local mode="$1"
	local scenario="$2"
	local timeout_sec="$3"
	local log="$4"
	local timing="$5"
	shift 5
	local start_ns
	local now_ns
	local deadline
	local timer_pid
	local complete=0
	local startup_written=0
	local status=0
	local remaining
	local timer_index
	local clean_deadline
	local process_group
	local wait_deadline

	[[ -S "$RUNTIME/wayland-0" ]] ||
		fatal "isolated labwc socket disappeared before $mode/$scenario"
	kill -0 "$LABWC_PID" 2>/dev/null ||
		fatal "isolated labwc process disappeared before $mode/$scenario"
	set_mode_env "$mode"
	start_ns="$(date +%s%N)"
	deadline=$((SECONDS + timeout_sec))
	env -u DISPLAY -u WAYLAND_SOCKET \
		XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
		/usr/bin/time -f 'elapsed_sec=%e\nmaxrss_kb=%M' -o "$timing" \
		setsid env "${MODE_ENV[@]}" "$RAVEN" "$@" >"$log" 2>&1 &
	timer_pid=$!
	timer_index=${#ACTIVE_TIMERS[@]}
	ACTIVE_TIMERS+=("$timer_pid")
	assert_gui_environment "$mode" "$scenario" "$timer_pid"
	process_group="$GUI_PROCESS_GROUP"

	while kill -0 "$timer_pid" 2>/dev/null; do
		if ((startup_written == 0)) &&
			grep -q '\[auto\] first window ready' "$log" 2>/dev/null; then
			now_ns="$(date +%s%N)"
			printf '%s\n' "$(((now_ns - start_ns) / 1000000))" \
				>"${timing%.time}.startup-ms"
			startup_written=1
		fi
		if grep -q '\[auto\] script complete' "$log" 2>/dev/null; then
			complete=1
			break
		fi
		if ((SECONDS >= deadline)); then
			break
		fi
		sleep 0.1
	done

	if ((complete == 0)); then
		record_failure "$mode/$scenario did not complete automation before timeout"
		cleanup_group "$process_group"
	else
		assert_group_environment "$mode" "$scenario" "$process_group" post-automation
		clean_deadline=$((SECONDS + 10))
		if ((clean_deadline > deadline)); then
			clean_deadline="$deadline"
		fi
		while kill -0 "$timer_pid" 2>/dev/null && ((SECONDS < clean_deadline)); do
			sleep 0.1
		done
		if kill -0 "$timer_pid" 2>/dev/null; then
			record_failure "$mode/$scenario did not exit cleanly after automation"
			cleanup_group "$process_group"
		fi
	fi
	wait_deadline=$((SECONDS + 2))
	while kill -0 "$timer_pid" 2>/dev/null && ((SECONDS < wait_deadline)); do
		sleep 0.05
	done
	if kill -0 "$timer_pid" 2>/dev/null; then
		record_failure "$mode/$scenario timing wrapper did not exit after group cleanup"
		terminate_timer "$timer_pid"
	fi
	wait "$timer_pid" 2>/dev/null || status=$?
	unset 'ACTIVE_TIMERS[timer_index]'
	unset 'TIMER_GROUP[$timer_pid]'
	printf '%s\n' "$status" >"${timing%.time}.status"
	if ((status != 0)); then
		record_failure "$mode/$scenario exited with nonzero host status $status"
	fi
	if [[ -z "$(read_timing "$timing" elapsed_sec)" ||
		-z "$(read_timing "$timing" maxrss_kb)" ]]; then
		record_failure "$mode/$scenario did not capture elapsed time and max RSS"
	fi
	check_log_health "$mode" "$scenario" "$log"
	remaining="$(group_processes "$process_group")"
	if [[ -n "$remaining" ]]; then
		record_failure "$mode/$scenario left process-group members: ${remaining//$'\n'/,}"
		cleanup_group "$process_group"
	fi
	remaining="$(raven_processes)"
	if [[ -n "$remaining" ]]; then
		record_failure "$mode/$scenario left Raven processes: ${remaining//$'\n'/,}"
		stop_raven_processes
	fi
}

check_png() {
	local label="$1"
	local path="$2"
	local metrics

	if [[ ! -s "$path" ]]; then
		record_failure "$label screenshot is missing: $path"
		return 1
	fi
	metrics="$(identify -format '%w %h %[fx:standard_deviation]' "$path" \
		2>/dev/null || true)"
	if ! awk -v metrics="$metrics" \
		'BEGIN { split(metrics, v); exit !(v[1] >= 300 && v[2] >= 150 && v[3] >= 0.01) }'; then
		record_failure "$label screenshot is blank, undersized, or invalid"
		return 1
	fi
	return 0
}

image_ae() {
	local first="$1"
	local second="$2"
	local geometry="$3"
	local fuzz="$4"
	local metric

	metric="$(compare -metric AE -fuzz "$fuzz" -extract "$geometry" \
		"$first" -extract "$geometry" "$second" null: 2>&1 || true)"
	metric="${metric%% *}"
	[[ "$metric" =~ ^[0-9]+$ ]] || metric="invalid"
	printf '%s\n' "$metric"
}

assert_ae_limit() {
	local label="$1"
	local first="$2"
	local second="$3"
	local geometry="$4"
	local limit="$5"
	local metric

	if [[ ! -s "$first" || ! -s "$second" ]]; then
		LAST_METRIC="missing"
		record_failure "$label comparison image is missing"
		return 1
	fi
	metric="$(image_ae "$first" "$second" "$geometry" "$NPP_PIXEL_FUZZ")"
	if [[ "$metric" == "invalid" ]] || ((metric > limit)); then
		LAST_METRIC="$metric"
		record_failure "$label pixel mismatch ${metric}, limit $limit"
		return 1
	fi
	LAST_METRIC="$metric"
	return 0
}

select_window_png() {
	local width="$1"
	local height="$2"
	shift 2
	local path

	for path in "$@"; do
		[[ -e "$path" ]] || continue
		if [[ "$(identify -format '%w %h' "$path" 2>/dev/null || true)" == "$width $height" ]]; then
			printf '%s\n' "$path"
			return 0
		fi
	done
	return 1
}

printf 'mode\tscenario\tresult\telapsed_sec\tmaxrss_kb\tmetric\n' \
	>"$ARTIFACTS/summary.tsv"

for mode in "${MODES[@]}"; do
	run_fixture "$mode" 32
	run_fixture "$mode" 64
done

run_npp_mode() {
	local mode="$1"
	local mode_dir="$ARTIFACTS/$mode"
	local npp_dir="$mode_dir/npp-app"
	local first="$mode_dir/npp-first.txt"
	local second="$mode_dir/npp-second.txt"
	local log="$mode_dir/npp.log"
	local timing="$mode_dir/npp.time"
	local auto
	local find_main=""
	local find_dialog=""
	local closed_main=""
	local startup_ms
	local failure_count=${#FAILURES[@]}
	local workflow_result="workflow-ok"

	cp -a "$ARTIFACTS/apps/npp" "$npp_dir" ||
		fatal "could not copy Notepad++ test application"
	printf 'Raven first tab document.\n' >"$first"
	printf 'Raven second tab document.\n' >"$second"
	auto="35:screenshot:$mode_dir/npp-startup.png"
	auto+=";40:chord:29,24"
	auto+=";50:screenshot:$mode_dir/npp-open-second.png"
	auto+=";54:click:30,55"
	auto+=";60:screenshot:$mode_dir/npp-open-first.png"
	auto+=";64:click:110,55"
	auto+=";70:screenshot:$mode_dir/npp-open-second-again.png"
	auto+=";74:chord:29,33"
	auto+=";79:click-title:Find,220,52"
	auto+=";80:type-title:Find,Raven"
	auto+=";83:key-title:Find,28"
	auto+=";84:click-title:Find,647,53"
	auto+=";87:screenshot-all:$mode_dir/npp-find-open"
	auto+=";90:key-title:Find,1"
	auto+=";91:click-title:Find,647,226"
	auto+=";92:close-title:Find"
	auto+=";97:screenshot-all:$mode_dir/npp-find-closed"
	auto+=";101:screenshot:$mode_dir/npp-final.png"
	auto+=";105:chord:56,62"
	auto+=";105:close-title:Notepad++"

	RAVEN_FILE_DIALOG_PATH="$second" run_gui "$mode" npp "$NPP_TIMEOUT_SEC" \
		"$log" "$timing" -auto "$auto" "$npp_dir/notepad++.exe" "$first"

	grep -Fq 'IFileOpenDialog::Show selected' "$log" ||
		record_failure "$mode/npp did not complete the Open picker"
	grep -Fq 'text="Raven second tab document."' "$log" ||
		record_failure "$mode/npp did not paint the opened document"
	awk '/\[auto\] click at \(30,55\)/ { clicked=1 } clicked &&
		/text="Raven first tab document\."/ { found=1; exit }
		END { exit !found }' "$log" ||
		record_failure "$mode/npp did not activate the first tab"
	awk '/\[auto\] click at \(110,55\)/ { clicked=1 } clicked &&
		/text="Raven second tab document\."/ { found=1; exit }
		END { exit !found }' "$log" ||
		record_failure "$mode/npp did not reactivate the second tab"
	grep -q 'click-title "Find"' "$log" ||
		record_failure "$mode/npp did not open Find as a separate window"
	grep -Eq '\[button\] BN_CLICKED.* id=1|\[dialog\] key command id=1' "$log" ||
		record_failure "$mode/npp did not dispatch Find Next"
	grep -Eq '\[button\] BN_CLICKED.* id=2|\[wl\] dialog close .*WM_COMMAND id=2|\[dialog\] key command id=2' "$log" ||
		record_failure "$mode/npp did not dispatch Find Close"
	grep -q '\[dialog-window\] destroyed hwnd=' "$log" ||
		record_failure "$mode/npp did not destroy the Find window"

	for path in "$mode_dir"/npp-startup.png "$mode_dir"/npp-open-second.png \
		"$mode_dir"/npp-open-first.png "$mode_dir"/npp-open-second-again.png \
		"$mode_dir"/npp-final.png; do
		check_png "$mode/npp" "$path" || true
	done
	find_main="$(select_window_png 1100 700 "$mode_dir"/npp-find-open-*.png || true)"
	find_dialog="$(select_window_png 782 394 "$mode_dir"/npp-find-open-*.png || true)"
	closed_main="$(select_window_png 1100 700 "$mode_dir"/npp-find-closed-*.png || true)"
	[[ -n "$find_main" ]] ||
		record_failure "$mode/npp Find main-window screenshot is missing"
	[[ -n "$find_dialog" ]] ||
		record_failure "$mode/npp Find dialog screenshot is missing"
	[[ -n "$closed_main" ]] ||
		record_failure "$mode/npp post-close screenshot is missing"
	if [[ "$(compgen -G "$mode_dir/npp-find-closed-*.png" | wc -l)" -ne 1 ]]; then
		record_failure "$mode/npp left a secondary window after Find Close"
	fi
	[[ -z "$find_main" ]] || check_png "$mode/npp-find-main" "$find_main" || true
	[[ -z "$find_dialog" ]] || check_png "$mode/npp-find-dialog" "$find_dialog" || true
	[[ -z "$closed_main" ]] || check_png "$mode/npp-find-closed" "$closed_main" || true

	assert_ae_limit "$mode/npp second-tab restore" \
		"$mode_dir/npp-open-second.png" "$mode_dir/npp-open-second-again.png" \
		'1000x500+50+70' 100 || true
	if [[ -s "$mode_dir/npp-open-second.png" && -s "$mode_dir/npp-open-first.png" ]]; then
		local tab_change
		tab_change="$(image_ae "$mode_dir/npp-open-second.png" \
			"$mode_dir/npp-open-first.png" '1000x300+50+70' "$NPP_PIXEL_FUZZ")"
		if [[ "$tab_change" == "invalid" ]] || ((tab_change < 10)); then
			record_failure "$mode/npp tab switch lacked a visual state change"
		fi
	fi

	startup_ms="$(cat "${timing%.time}.startup-ms" 2>/dev/null || true)"
	if ((${#FAILURES[@]} > failure_count || ${#FAILURES[@]} > 0)); then
		workflow_result="workflow-failed"
		NPP_OK["$mode"]=0
	else
		NPP_OK["$mode"]=1
	fi
	printf '%s\tnpp\t%s\t%s\t%s\tstartup_ms=%s\n' \
		"$mode" "$workflow_result" "$(read_timing "$timing" elapsed_sec)" \
		"$(read_timing "$timing" maxrss_kb)" "${startup_ms:-missing}" \
		>>"$ARTIFACTS/summary.tsv"
}

if ((RUN_NPP)); then
	mkdir -p "$ARTIFACTS/apps"
	cp -a "$ROOT/testdata/npp" "$ARTIFACTS/apps/npp" ||
		fatal "could not snapshot the Notepad++ test application"
	for mode in "${MODES[@]}"; do
		run_npp_mode "$mode"
	done

	for mode in closure native; do
		mode_selected interpreter && mode_selected "$mode" || continue
		parity_result="visual-match"
		if ((${#FAILURES[@]})) ||
			[[ "${NPP_OK[interpreter]:-0}" != 1 || "${NPP_OK[$mode]:-0}" != 1 ]]; then
			parity_result="parity-failed"
		fi
		if ! assert_ae_limit "$mode/npp editor vs interpreter" \
			"$ARTIFACTS/interpreter/npp-open-second-again.png" \
			"$ARTIFACTS/$mode/npp-open-second-again.png" \
			'1000x500+50+70' "$NPP_EDITOR_PIXEL_TOLERANCE"; then
			parity_result="visual-failed"
		fi
		metric="$LAST_METRIC"
		find_reference="$(select_window_png 782 394 \
			"$ARTIFACTS/interpreter"/npp-find-open-*.png || true)"
		find_candidate="$(select_window_png 782 394 \
			"$ARTIFACTS/$mode"/npp-find-open-*.png || true)"
		dialog_metric="missing"
		if [[ -n "$find_reference" && -n "$find_candidate" ]]; then
			if ! assert_ae_limit "$mode/npp Find vs interpreter" \
				"$find_reference" "$find_candidate" '740x330+20+40' \
				"$NPP_DIALOG_PIXEL_TOLERANCE"; then
				parity_result="visual-failed"
			fi
			dialog_metric="$LAST_METRIC"
		else
			record_failure "$mode/npp Find parity image is missing"
			parity_result="visual-failed"
		fi
		printf '%s\tnpp-parity\t%s\t-\t-\teditor_ae=%s,dialog_ae=%s\n' \
			"$mode" "$parity_result" "$metric" "$dialog_metric" \
			>>"$ARTIFACTS/summary.tsv"
	done
fi

DXBALL="${RAVEN_DXBALL_EXE:-}"
if [[ -z "$DXBALL" ]]; then
	if [[ -f "$ROOT/testdata/games/pno0001.exe" ]]; then
		DXBALL="$ROOT/testdata/games/pno0001.exe"
	elif [[ -f "$ROOT/testdata/games/DXBall.EXE" ]]; then
		DXBALL="$ROOT/testdata/games/DXBall.EXE"
	fi
fi
if [[ -n "$DXBALL" && -f "$DXBALL" ]]; then
	mkdir -p "$ARTIFACTS/apps"
	cp -a "$DXBALL" "$ARTIFACTS/apps/dxball.exe" ||
		fatal "could not snapshot the DX-Ball payload"
	DXBALL="$ARTIFACTS/apps/dxball.exe"
fi

dxball_progress_pixels() {
	local path="$1"
	local value

	value="$(magick "$path" -crop '970x28+28+370' +repage \
		-threshold 90% -format '%[fx:round(mean*w*h)]' info: 2>/dev/null || true)"
	[[ "$value" =~ ^[0-9]+$ ]] || value="invalid"
	printf '%s\n' "$value"
}

run_dxball_mode() {
	local mode="$1"
	local mode_dir="$ARTIFACTS/$mode"
	local log="$mode_dir/dxball.log"
	local timing="$mode_dir/dxball.time"
	local baseline_png="$mode_dir/dxball-baseline.png"
	local png="$mode_dir/dxball-${DXBALL_SAMPLE_SEC}s.png"
	local auto="5:screenshot:$baseline_png"
	auto+=";${DXBALL_SAMPLE_SEC}:screenshot:$png"
	auto+=";$((DXBALL_SAMPLE_SEC + 1)):key:1"
	auto+=";$((DXBALL_SAMPLE_SEC + 2)):chord:56,62"
	auto+=";$((DXBALL_SAMPLE_SEC + 3)):close-title:kk"
	local baseline_pixels
	local pixels
	local progress_pixels
	local width
	local failure_count=${#FAILURES[@]}
	local progress_result="progress-ok"

	run_gui "$mode" dxball "$DXBALL_TIMEOUT_SEC" "$log" "$timing" \
		-auto "$auto" "$DXBALL"
	check_png "$mode/dxball-baseline" "$baseline_png" || true
	check_png "$mode/dxball" "$png" || true
	if [[ -s "$baseline_png" ]]; then
		baseline_pixels="$(dxball_progress_pixels "$baseline_png")"
	else
		baseline_pixels="invalid"
	fi
	if [[ -s "$png" ]]; then
		pixels="$(dxball_progress_pixels "$png")"
	else
		pixels="invalid"
	fi
	progress_pixels="invalid"
	if [[ "$baseline_pixels" =~ ^[0-9]+$ && "$pixels" =~ ^[0-9]+$ ]] &&
		((pixels >= baseline_pixels)); then
		progress_pixels="$((pixels - baseline_pixels))"
	fi
	if [[ "$progress_pixels" == "invalid" ]] ||
		((progress_pixels < DXBALL_MIN_PROGRESS_PIXELS)); then
		record_failure "$mode/dxball progress delta ${progress_pixels}, expected at least $DXBALL_MIN_PROGRESS_PIXELS pixels"
		width="missing"
	else
		width="$(awk -v pixels="$progress_pixels" 'BEGIN { printf "%.2f", pixels / 28 }')"
	fi
	if ((${#FAILURES[@]} > failure_count || ${#FAILURES[@]} > 0)); then
		progress_result="progress-failed"
		DXBALL_OK["$mode"]=0
	else
		DXBALL_OK["$mode"]=1
	fi
	printf '%s\tdxball\t%s\t%s\t%s\tbaseline=%s,sample=%s,progress=%s,width_px=%s\n' \
		"$mode" "$progress_result" "$(read_timing "$timing" elapsed_sec)" \
		"$(read_timing "$timing" maxrss_kb)" "$baseline_pixels" "$pixels" \
		"$progress_pixels" "$width" \
		>>"$ARTIFACTS/summary.tsv"
}

if ((RUN_DXBALL)); then
	if [[ -z "$DXBALL" || ! -f "$DXBALL" ]]; then
		echo "SKIP: DX-Ball executable is not present" |
			tee "$ARTIFACTS/dxball-skip.txt"
	else
		printf '%s\n' "$DXBALL" >"$ARTIFACTS/dxball-executable.txt"
		for mode in "${MODES[@]}"; do
			run_dxball_mode "$mode"
		done

		for mode in closure native; do
			mode_selected interpreter && mode_selected "$mode" || continue
			parity_result="visual-match"
			if ((${#FAILURES[@]})) ||
				[[ "${DXBALL_OK[interpreter]:-0}" != 1 ||
					"${DXBALL_OK[$mode]:-0}" != 1 ]]; then
				parity_result="parity-failed"
			fi
			upper_ae="$(image_ae \
				"$ARTIFACTS/interpreter/dxball-${DXBALL_SAMPLE_SEC}s.png" \
				"$ARTIFACTS/$mode/dxball-${DXBALL_SAMPLE_SEC}s.png" \
				'1024x360+0+0' "$NPP_PIXEL_FUZZ")"
			lower_ae="$(image_ae \
				"$ARTIFACTS/interpreter/dxball-${DXBALL_SAMPLE_SEC}s.png" \
				"$ARTIFACTS/$mode/dxball-${DXBALL_SAMPLE_SEC}s.png" \
				'1024x282+0+410' "$NPP_PIXEL_FUZZ")"
			outside_ae="invalid"
			if [[ "$upper_ae" =~ ^[0-9]+$ && "$lower_ae" =~ ^[0-9]+$ ]]; then
				outside_ae="$((upper_ae + lower_ae))"
			fi
			if [[ "$outside_ae" == "invalid" ]] ||
				((outside_ae > DXBALL_OUTSIDE_PIXEL_TOLERANCE)); then
				record_failure "$mode/dxball non-progress regions mismatch interpreter"
				parity_result="visual-failed"
			fi
			printf '%s\tdxball-parity\t%s\t-\t-\toutside_ae=%s\n' \
				"$mode" "$parity_result" "$outside_ae" \
				>>"$ARTIFACTS/summary.tsv"
		done

		if mode_selected closure && mode_selected native; then
			closure_baseline="$(dxball_progress_pixels \
				"$ARTIFACTS/closure/dxball-baseline.png")"
			closure_pixels="$(dxball_progress_pixels \
				"$ARTIFACTS/closure/dxball-${DXBALL_SAMPLE_SEC}s.png")"
			native_baseline="$(dxball_progress_pixels \
				"$ARTIFACTS/native/dxball-baseline.png")"
			native_pixels="$(dxball_progress_pixels \
				"$ARTIFACTS/native/dxball-${DXBALL_SAMPLE_SEC}s.png")"
			if [[ "$closure_baseline" =~ ^[0-9]+$ &&
				"$closure_pixels" =~ ^[0-9]+$ &&
				"$native_baseline" =~ ^[0-9]+$ &&
				"$native_pixels" =~ ^[0-9]+$ &&
				"$closure_pixels" -ge "$closure_baseline" &&
				"$native_pixels" -ge "$native_baseline" ]]; then
				closure_progress="$((closure_pixels - closure_baseline))"
				native_progress="$((native_pixels - native_baseline))"
				if ! awk -v native="$native_progress" -v closure="$closure_progress" \
					-v ratio="$DXBALL_NATIVE_MIN_RATIO" \
					'BEGIN { exit !(native >= closure * ratio) }'; then
					record_failure "native/DX-Ball progress regressed below closure ratio $DXBALL_NATIVE_MIN_RATIO"
				fi
			fi
		fi
	fi
fi

declare -A CLEANUP_GROUP_SEEN=()
: >"$ARTIFACTS/process-cleanup.txt"
for process_group in "${KNOWN_GROUPS[@]}"; do
	[[ -z "${CLEANUP_GROUP_SEEN[$process_group]:-}" ]] || continue
	CLEANUP_GROUP_SEEN["$process_group"]=1
	FINAL_GROUP_PROCESSES="$(group_processes "$process_group")"
	if [[ -n "$FINAL_GROUP_PROCESSES" ]]; then
		record_failure "final cleanup found process-group $process_group members: ${FINAL_GROUP_PROCESSES//$'\n'/,}"
		cleanup_group "$process_group"
	fi
	FINAL_GROUP_PROCESSES="$(group_processes "$process_group")"
	if [[ -n "$FINAL_GROUP_PROCESSES" ]]; then
		record_failure "final cleanup could not empty process-group $process_group"
		printf 'process_group_%s=%s\n' "$process_group" \
			"${FINAL_GROUP_PROCESSES//$'\n'/,}" >>"$ARTIFACTS/process-cleanup.txt"
	else
		printf 'process_group_%s=0\n' "$process_group" \
			>>"$ARTIFACTS/process-cleanup.txt"
	fi
done

FINAL_RAVEN_PROCESSES="$(raven_processes)"
if [[ -n "$FINAL_RAVEN_PROCESSES" ]]; then
	record_failure "final cleanup found Raven processes: ${FINAL_RAVEN_PROCESSES//$'\n'/,}"
	stop_raven_processes
fi
FINAL_RAVEN_PROCESSES="$(raven_processes)"
if [[ -n "$FINAL_RAVEN_PROCESSES" ]]; then
	record_failure "final cleanup could not stop Raven processes: ${FINAL_RAVEN_PROCESSES//$'\n'/,}"
	printf 'raven_processes=%s\n' "${FINAL_RAVEN_PROCESSES//$'\n'/,}" \
		>>"$ARTIFACTS/process-cleanup.txt"
else
	printf 'raven_processes=0\n' >>"$ARTIFACTS/process-cleanup.txt"
fi

{
	printf 'MODE         SCENARIO        RESULT       ELAPSED  MAXRSS  METRIC\n'
	awk -F '\t' 'NR > 1 {
		printf "%-12s %-15s %-12s %-8s %-7s %s\n", $1, $2, $3, $4, $5, $6
	}' "$ARTIFACTS/summary.tsv"
} | tee "$ARTIFACTS/summary.txt"

if ((${#FAILURES[@]})); then
	printf '\nFailures (%d):\n' "${#FAILURES[@]}" |
		tee -a "$ARTIFACTS/summary.txt"
	printf ' - %s\n' "${FAILURES[@]}" |
		tee -a "$ARTIFACTS/summary.txt"
	exit 1
fi

echo "PASS: interpreter, closure JIT, and native JIT parity gate"
