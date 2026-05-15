#!/usr/bin/env bash

set -u
cd "$(dirname "$0")/.." || exit 2
source scripts/raven-cache.sh || exit 2

RAVEN="${RAVEN:-}"
if [[ -z "$RAVEN" ]]; then
  mkdir -p "$RAVEN_CACHE_ROOT/bin"
  RAVEN="$RAVEN_CACHE_ROOT/bin/raven-npp-regression"
  go build -tags guest_windows -o "$RAVEN" ./cmd/govm || exit 2
fi

TRUSTED_RUNTIME_RAW="$(cat "$RAVEN_LABWC_RUNTIME_FILE" 2>/dev/null)"
TRUSTED_RUNTIME=""
if [[ -n "$TRUSTED_RUNTIME_RAW" ]]; then
  TRUSTED_RUNTIME="$(realpath -m -- "$TRUSTED_RUNTIME_RAW")"
fi
RUNTIME_RAW="${RAVEN_LABWC_RUNTIME:-$TRUSTED_RUNTIME}"
RUNTIME=""
if [[ -n "$RUNTIME_RAW" ]]; then
  RUNTIME="$(realpath -m -- "$RUNTIME_RAW")"
fi
USER_SESSION_RUNTIME="/run/user/$(id -u)"
if [[ -z "$RUNTIME" || "$RUNTIME" != "$TRUSTED_RUNTIME" ||
   "$RUNTIME" != "$RAVEN_RUNTIME_ROOT"/labwc-* ||
   "$RUNTIME" == "$USER_SESSION_RUNTIME" ||
   ! -S "$RUNTIME/wayland-0" ]]; then
  echo "FAIL: isolated labwc socket is unavailable"
  exit 2
fi
if [[ -S "$USER_SESSION_RUNTIME/wayland-0" &&
   "$RUNTIME/wayland-0" -ef "$USER_SESSION_RUNTIME/wayland-0" ]]; then
  echo "FAIL: isolated socket resolves to the user compositor"
  exit 2
fi

LABWC_PID=""
for proc in /proc/[0-9]*; do
  [[ "$(cat "$proc/comm" 2>/dev/null)" == "labwc" ]] || continue
  if (tr '\0' '\n' <"$proc/environ") 2>/dev/null | grep -Fqx "XDG_RUNTIME_DIR=$RUNTIME"; then
    LABWC_PID="${proc##*/}"
    break
  fi
done
if [[ -z "$LABWC_PID" ]]; then
  echo "FAIL: isolated labwc process is unavailable"
  exit 2
fi
echo "NPP isolated runtime: $RUNTIME"
echo "NPP GUI env: DISPLAY=<unset> WAYLAND_SOCKET=<unset> WAYLAND_DISPLAY=wayland-0"

if [[ -z "${RAVEN_NPP_KEEP_TMP:-}" ]]; then
  TMP="$(mktemp -d "$RAVEN_TMPDIR/npp.XXXXXX")" || exit 2
  trap 'rm -rf "$TMP"' EXIT
else
  TMP="$(mktemp -d "$RAVEN_ARTIFACT_ROOT/npp.XXXXXX")" || exit 2
  printf 'raven-npp-regression\n' >"$TMP/.raven-npp-owned"
  raven_prune_owned_runs "$RAVEN_ARTIFACT_ROOT" ".raven-npp-owned" 5 || exit 2
  echo "NPP regression artifacts: $TMP"
fi
NPP="$(pwd)/testdata/npp/notepad++.exe"
FIXTURE="$TMP/raven-open-fixture.txt"
printf 'Raven open flow works.\n' >"$FIXTURE"

validate_raven_gui_env() {
  local pid="$1"
  local child_env attempt
  for attempt in $(seq 1 100); do
    child_env="$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null)" || return 1
    if ! grep -q '^DISPLAY=' <<<"$child_env" &&
      ! grep -q '^WAYLAND_SOCKET=' <<<"$child_env" &&
      grep -Fqx "XDG_RUNTIME_DIR=$RUNTIME" <<<"$child_env" &&
      grep -Fqx 'WAYLAND_DISPLAY=wayland-0' <<<"$child_env"; then
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.01
  done
  return 1
}

stop_raven_pid() {
  local pid="$1"
  local attempt
  kill -INT "$pid" 2>/dev/null || true
  for attempt in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || {
      wait "$pid" 2>/dev/null || true
      return
    }
    sleep 0.02
  done
  kill -TERM "$pid" 2>/dev/null || true
  for attempt in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || {
      wait "$pid" 2>/dev/null || true
      return
    }
    sleep 0.02
  done
  kill -KILL "$pid" 2>/dev/null || true
  for attempt in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || {
      wait "$pid" 2>/dev/null || true
      return
    }
    sleep 0.02
  done
}

run_npp() {
  local log="$1"; shift
  env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
    RAVEN_FILE_DIALOG_PATH="${DIALOG_PATH:-}" \
    RAVEN_COLOR_DIALOG_VALUE="${RAVEN_COLOR_DIALOG_VALUE:-}" \
    RAVEN_PRINT_DIALOG_RESULT="${RAVEN_PRINT_DIALOG_RESULT:-}" \
    RAVEN_PRINT_OUTPUT="${RAVEN_PRINT_OUTPUT:-}" \
    RAVEN_TRACE_CLICK="${RAVEN_TRACE_CLICK:-}" \
    RAVEN_TRACE_FIND="${RAVEN_TRACE_FIND:-}" \
    "$RAVEN" "$@" >"$log" 2>&1 &
  local pid=$!
  if ! validate_raven_gui_env "$pid"; then
    stop_raven_pid "$pid"
    echo "FAIL: Raven GUI child environment is not isolated" >>"$log"
    return 1
  fi
  local deadline=$((SECONDS + ${RUN_TIMEOUT:-110}))
  while kill -0 "$pid" 2>/dev/null; do
    if grep -q '\[auto\] script failed:' "$log" 2>/dev/null; then
      stop_raven_pid "$pid"
      return 1
    fi
    if grep -q '\[auto\] script complete' "$log" 2>/dev/null; then
      stop_raven_pid "$pid"
      grep -q '\[auto\] script complete' "$log" &&
        ! grep -Eq '\[cpu-fault\]|PE runtime error' "$log"
      return
    fi
    if (( SECONDS >= deadline )); then
      stop_raven_pid "$pid"
      return 1
    fi
    sleep 0.2
  done
  wait "$pid" 2>/dev/null || true
  grep -q '\[auto\] script complete' "$log" &&
    ! grep -Eq '\[cpu-fault\]|PE runtime error' "$log"
}

fail() {
  echo "FAIL: $1"
  exit 1
}

REPLACE_FIXTURE="$TMP/replace_file_fixture.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$REPLACE_FIXTURE" testdata/dll_fixture/replace_file_fixture.c -lkernel32 || fail "ReplaceFile fixture did not build"
env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
  timeout --foreground --kill-after=3s 30s "$RAVEN" "$REPLACE_FIXTURE" >"$TMP/replace-file.log" 2>&1 || \
  fail "ReplaceFile fixture failed"
grep -q '\[resolve\] replace_file_fixture.exe: 7 imports, 7 resolved, 0 unresolved' "$TMP/replace-file.log" || \
  fail "ReplaceFile fixture imports were not resolved"
grep -q '\[win32\] ExitProcess(0)' "$TMP/replace-file.log" || fail "ReplaceFile fixture did not verify target and backup"

PRINT_FIXTURE="$TMP/print_dialog_fixture.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$PRINT_FIXTURE" testdata/dll_fixture/print_dialog_fixture.c -lcomdlg32 -lgdi32 -lkernel32 || \
  fail "PrintDlg fixture did not build"
env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
  timeout --foreground --kill-after=3s 30s "$RAVEN" "$PRINT_FIXTURE" >"$TMP/print-dialog.log" 2>&1 || \
  fail "PrintDlg fixture failed"
grep -q '\[resolve\] print_dialog_fixture.exe: .* 0 unresolved' "$TMP/print-dialog.log" || \
  fail "PrintDlg fixture imports were not resolved"
grep -q '\[comdlg32\] PrintDlg accepted flags=0x500' "$TMP/print-dialog.log" || \
  fail "PrintDlg did not return the default virtual printer"
grep -q '\[win32\] ExitProcess(0)' "$TMP/print-dialog.log" || fail "PrintDlg fixture did not validate returned resources"

WINDOW_POINT_FIXTURE="$TMP/window_point_fixture.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$WINDOW_POINT_FIXTURE" testdata/dll_fixture/window_point_fixture.c -luser32 -lkernel32 || \
  fail "WindowFromPoint fixture did not build"
env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
  timeout --foreground --kill-after=3s 30s "$RAVEN" "$WINDOW_POINT_FIXTURE" >"$TMP/window-point.log" 2>&1 || \
  fail "WindowFromPoint fixture failed"
grep -q '\[resolve\] window_point_fixture.exe: .* 0 unresolved' "$TMP/window-point.log" || \
  fail "WindowFromPoint fixture imports were not resolved"
grep -q '\[win32\] ExitProcess(0)' "$TMP/window-point.log" || \
  fail "WindowFromPoint fixture did not verify hit testing"

TAB_CONTROL_FIXTURE="$TMP/tab_control_fixture.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$TAB_CONTROL_FIXTURE" testdata/dll_fixture/tab_control_fixture.c -lcomctl32 -luser32 -lkernel32 || \
  fail "tab control fixture did not build"
env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
  timeout --foreground --kill-after=3s 30s "$RAVEN" "$TAB_CONTROL_FIXTURE" >"$TMP/tab-control.log" 2>&1 || \
  fail "tab control fixture failed"
grep -q '\[resolve\] tab_control_fixture.exe: .* 0 unresolved' "$TMP/tab-control.log" || \
  fail "tab control fixture imports were not resolved"
grep -q '\[win32\] ExitProcess(0)' "$TMP/tab-control.log" || \
  fail "tab control fixture did not verify PE32 tab notifications"

TEXT_METRICS_FIXTURE="$TMP/text_metrics_fixture.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$TEXT_METRICS_FIXTURE" testdata/dll_fixture/text_metrics_fixture.c -lgdi32 -lkernel32 || \
  fail "Text metrics fixture did not build"
env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
  timeout --foreground --kill-after=3s 30s "$RAVEN" "$TEXT_METRICS_FIXTURE" >"$TMP/text-metrics.log" 2>&1 || \
  fail "Text metrics fixture failed"
grep -q '\[resolve\] text_metrics_fixture.exe: 10 imports, 10 resolved, 0 unresolved' "$TMP/text-metrics.log" || \
  fail "Text metrics fixture imports were not resolved"
grep -q '\[win32\] ExitProcess(0)' "$TMP/text-metrics.log" || \
  fail "Text metrics fixture did not validate GDI pitch and ABI layouts"

NT_VERSION_FIXTURE="$TMP/nt_version_fixture.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$NT_VERSION_FIXTURE" testdata/dll_fixture/nt_version_fixture.c -lkernel32 || \
  fail "NT version fixture did not build"
env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
  timeout --foreground --kill-after=3s 30s "$RAVEN" "$NT_VERSION_FIXTURE" >"$TMP/nt-version.log" 2>&1 || \
  fail "NT version fixture failed"
grep -q '\[resolve\] nt_version_fixture.exe: .* 0 unresolved' "$TMP/nt-version.log" || \
  fail "NT version fixture imports were not resolved"
grep -q '\[win32\] ExitProcess(0)' "$TMP/nt-version.log" || \
  fail "NT version fixture did not validate dynamic ntdll exports"

DPI_DYNAMIC_FIXTURE32="$TMP/dpi_dynamic_fixture32.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$DPI_DYNAMIC_FIXTURE32" testdata/dll_fixture/dpi_dynamic_fixture.c -luser32 -lkernel32 || \
  fail "PE32 dynamic DPI fixture did not build"
DPI_DYNAMIC_FIXTURE64="$TMP/dpi_dynamic_fixture64.exe"
zig cc -target x86_64-windows-gnu -nostdlib -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console -o "$DPI_DYNAMIC_FIXTURE64" \
  testdata/dll_fixture/dpi_dynamic_fixture.c -luser32 -lkernel32 || \
  fail "PE64 dynamic DPI fixture did not build"
for arch in 32 64; do
  fixture_var="DPI_DYNAMIC_FIXTURE${arch}"
  fixture="${!fixture_var}"
  env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
    timeout --foreground --kill-after=3s 15s "$RAVEN" "$fixture" >"$TMP/dpi-dynamic-$arch.log" 2>&1 || \
    fail "PE$arch dynamic DPI fixture failed"
  grep -q '\[win32\] ExitProcess(0)' "$TMP/dpi-dynamic-$arch.log" || \
    fail "PE$arch dynamic DPI fixture did not validate user32 exports"
done

WAIT_MULTIPLE_FIXTURE32="$TMP/wait_multiple_fixture32.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$WAIT_MULTIPLE_FIXTURE32" testdata/dll_fixture/wait_multiple_fixture.c -lkernel32 || \
  fail "PE32 wait multiple fixture did not build"
WAIT_MULTIPLE_FIXTURE64="$TMP/wait_multiple_fixture64.exe"
zig cc -target x86_64-windows-gnu -nostdlib -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console -o "$WAIT_MULTIPLE_FIXTURE64" \
  testdata/dll_fixture/wait_multiple_fixture.c -lkernel32 || \
  fail "PE64 wait multiple fixture did not build"
for arch in 32 64; do
  fixture_var="WAIT_MULTIPLE_FIXTURE${arch}"
  fixture="${!fixture_var}"
  timeout --foreground --kill-after=3s 30s "$RAVEN" -wayland=false "$fixture" \
    >"$TMP/wait-multiple-$arch.log" 2>&1 || \
    fail "PE$arch wait multiple fixture failed"
  grep -q '\[resolve\] wait_multiple_fixture.* 0 unresolved' "$TMP/wait-multiple-$arch.log" || \
    fail "PE$arch wait multiple fixture imports were not resolved"
  grep -q '\[win32\] ExitProcess(0)' "$TMP/wait-multiple-$arch.log" || \
    fail "PE$arch wait multiple fixture did not validate wait semantics"
  ! grep -q '\[cpu-fault\]' "$TMP/wait-multiple-$arch.log" || \
    fail "PE$arch wait multiple fixture produced a CPU fault"
done

OVERLAPPED_DIRECTORY_FIXTURE32="$TMP/overlapped_directory_fixture32.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$OVERLAPPED_DIRECTORY_FIXTURE32" \
  testdata/dll_fixture/overlapped_directory_fixture.c -lkernel32 || \
  fail "PE32 overlapped directory fixture did not build"
OVERLAPPED_DIRECTORY_FIXTURE64="$TMP/overlapped_directory_fixture64.exe"
zig cc -target x86_64-windows-gnu -nostdlib -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console \
  -o "$OVERLAPPED_DIRECTORY_FIXTURE64" \
  testdata/dll_fixture/overlapped_directory_fixture.c -lkernel32 || \
  fail "PE64 overlapped directory fixture did not build"
for arch in 32 64; do
  fixture_var="OVERLAPPED_DIRECTORY_FIXTURE${arch}"
  fixture="${!fixture_var}"
  fixture_dir="$TMP/overlapped-directory-$arch"
  mkdir "$fixture_dir" || fail "PE$arch overlapped directory fixture setup failed"
  timeout --foreground --kill-after=3s 12s "$RAVEN" -wayland=false \
    "$fixture" "$fixture_dir" >"$TMP/overlapped-directory-$arch.log" 2>&1 || \
    fail "PE$arch overlapped directory fixture failed"
  grep -q '\[resolve\] overlapped_directory_fixture.* 0 unresolved' \
    "$TMP/overlapped-directory-$arch.log" || \
    fail "PE$arch overlapped directory fixture imports were not resolved"
  grep -q '\[win32\] ExitProcess(0)' "$TMP/overlapped-directory-$arch.log" || \
    fail "PE$arch overlapped directory fixture did not validate rearm, IOCP, timeout, APC, and cancellation semantics"
  ! grep -q '\[cpu-fault\]' "$TMP/overlapped-directory-$arch.log" || \
    fail "PE$arch overlapped directory fixture produced a CPU fault"
done

THREAD_MESSAGE_FIXTURE32="$TMP/thread_message_fixture32.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$THREAD_MESSAGE_FIXTURE32" testdata/dll_fixture/thread_message_fixture.c -luser32 -lkernel32 || \
  fail "PE32 thread message fixture did not build"
THREAD_MESSAGE_FIXTURE64="$TMP/thread_message_fixture64.exe"
zig cc -target x86_64-windows-gnu -nostdlib -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console -o "$THREAD_MESSAGE_FIXTURE64" \
  testdata/dll_fixture/thread_message_fixture.c -luser32 -lkernel32 || \
  fail "PE64 thread message fixture did not build"
for arch in 32 64; do
  fixture_var="THREAD_MESSAGE_FIXTURE${arch}"
  fixture="${!fixture_var}"
  timeout --foreground --kill-after=3s 30s "$RAVEN" -wayland=false "$fixture" \
    >"$TMP/thread-message-$arch.log" 2>&1 || \
    fail "PE$arch thread message fixture failed"
  grep -q '\[resolve\] thread_message_fixture.* 0 unresolved' "$TMP/thread-message-$arch.log" || \
    fail "PE$arch thread message fixture imports were not resolved"
  grep -q '\[win32\] ExitProcess(0)' "$TMP/thread-message-$arch.log" || \
    fail "PE$arch thread message fixture did not validate queue and timer ownership"
  ! grep -q '\[cpu-fault\]' "$TMP/thread-message-$arch.log" || \
    fail "PE$arch thread message fixture produced a CPU fault"
done

FIND_FILE_MARKER="$TMP/find_file_fixture_marker.txt"
printf 'marker\n' >"$FIND_FILE_MARKER"
FIND_FILE_FIXTURE32="$TMP/find_file_fixture32.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$FIND_FILE_FIXTURE32" testdata/dll_fixture/find_file_fixture.c -lkernel32 || \
  fail "PE32 find file fixture did not build"
FIND_FILE_FIXTURE64="$TMP/find_file_fixture64.exe"
zig cc -target x86_64-windows-gnu -nostdlib -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console -o "$FIND_FILE_FIXTURE64" \
  testdata/dll_fixture/find_file_fixture.c -lkernel32 || \
  fail "PE64 find file fixture did not build"
for arch in 32 64; do
  fixture_var="FIND_FILE_FIXTURE${arch}"
  fixture="${!fixture_var}"
  timeout --foreground --kill-after=3s 30s "$RAVEN" -wayland=false "$fixture" "$FIND_FILE_MARKER" \
    >"$TMP/find-file-$arch.log" 2>&1 || \
    fail "PE$arch find file fixture failed"
  grep -q '\[resolve\] find_file_fixture.* 0 unresolved' "$TMP/find-file-$arch.log" || \
    fail "PE$arch find file fixture imports were not resolved"
  grep -q '\[win32\] ExitProcess(0)' "$TMP/find-file-$arch.log" || \
    fail "PE$arch find file fixture did not validate enumeration and thread-local errors"
  ! grep -q '\[cpu-fault\]' "$TMP/find-file-$arch.log" || \
    fail "PE$arch find file fixture produced a CPU fault"
done

UNICODE_ARG="$TMP/"$'unicode-\U0001f600-\u65e5\u672c\u8a9e.md'
printf 'unicode\n' >"$UNICODE_ARG"
UNICODE_CMD_FIXTURE32="$TMP/unicode_command_line_fixture32.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$UNICODE_CMD_FIXTURE32" testdata/dll_fixture/unicode_command_line_fixture.c \
  -lkernel32 || \
  fail "PE32 Unicode command line fixture did not build"
UNICODE_CMD_FIXTURE64="$TMP/unicode_command_line_fixture64.exe"
zig cc -target x86_64-windows-gnu -nostdlib -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console -o "$UNICODE_CMD_FIXTURE64" \
  testdata/dll_fixture/unicode_command_line_fixture.c -lkernel32 || \
  fail "PE64 Unicode command line fixture did not build"
for arch in 32 64; do
  fixture_var="UNICODE_CMD_FIXTURE${arch}"
  fixture="${!fixture_var}"
  timeout --foreground --kill-after=3s 30s "$RAVEN" -wayland=false "$fixture" "$UNICODE_ARG" \
    >"$TMP/unicode-command-line-$arch.log" 2>&1 || \
    fail "PE$arch Unicode command line fixture failed"
  grep -q '\[resolve\] unicode_command_line_fixture.* 0 unresolved' \
    "$TMP/unicode-command-line-$arch.log" || \
    fail "PE$arch Unicode command line fixture imports were not resolved"
  grep -q '\[win32\] ExitProcess(0)' "$TMP/unicode-command-line-$arch.log" || \
    fail "PE$arch Unicode command line was corrupted"
done

check_png() {
  local path="$1"
  [[ -s "$path" ]] || fail "screenshot was not produced: $path"
  local metrics
  metrics="$(identify -format '%w %h %[fx:standard_deviation]' "$path" 2>/dev/null)" || fail "invalid PNG: $path"
  awk -v metrics="$metrics" 'BEGIN { split(metrics, v); exit !(v[1] >= 300 && v[2] >= 150 && v[3] >= 0.01) }' || \
    fail "screenshot is blank or undersized: $path"
}

check_png_region() {
  local path="$1"
  local geometry="$2"
  local deviation
  deviation="$(convert "$path" -crop "$geometry" +repage -format '%[fx:standard_deviation]' info: 2>/dev/null)" || \
    fail "invalid PNG region: $path $geometry"
  awk -v deviation="$deviation" 'BEGIN { exit !(deviation >= 0.02) }' || \
    fail "expected painted content is missing: $path $geometry"
}

check_png_region_colors() {
  local path="$1"
  local geometry="$2"
  local minimum="$3"
  local colors
  colors="$(convert "$path" -crop "$geometry" +repage -format '%k' info: 2>/dev/null)" || \
    fail "invalid PNG region: $path $geometry"
  awk -v colors="$colors" -v minimum="$minimum" 'BEGIN { exit !(colors >= minimum) }' || \
    fail "expected color detail is missing: $path $geometry"
}

check_png_region_luminance() {
  local path="$1"
  local geometry="$2"
  local minimum="$3"
  local maximum="$4"
  local label="$5"
  local mean
  mean="$(convert "$path" -crop "$geometry" +repage -colorspace Gray -format '%[fx:mean]' info: 2>/dev/null)" || \
    fail "invalid PNG luminance region: $path $geometry"
  awk -v mean="$mean" -v minimum="$minimum" -v maximum="$maximum" \
    'BEGIN { exit !(mean >= minimum && mean <= maximum) }' || \
    fail "$label luminance $mean is outside [$minimum, $maximum]"
}

check_png_region_changed() {
  local before="$1"
  local after="$2"
  local geometry="$3"
  local changed
  changed="$(compare -metric AE -extract "$geometry" "$before" -extract "$geometry" "$after" null: 2>&1)"
  changed="${changed%% *}"
  awk -v changed="$changed" 'BEGIN { exit !(changed >= 10) }' || \
    fail "expected visual state change is missing: $geometry"
}

check_png_region_same() {
  local first="$1"
  local second="$2"
  local geometry="$3"
  local changed
  changed="$(compare -metric AE -extract "$geometry" "$first" -extract "$geometry" "$second" null: 2>&1)"
  changed="${changed%% *}"
  awk -v changed="$changed" 'BEGIN { exit !(changed == 0) }' || \
    fail "expected identical visual state is missing: $geometry"
}

MESSAGE_BOX_FIXTURE32="$TMP/message_box_fixture32.exe"
i686-w64-mingw32-gcc -nostdlib -e _raven_entry -Wl,--subsystem,console \
  -o "$MESSAGE_BOX_FIXTURE32" testdata/dll_fixture/message_box_fixture.c -luser32 -lkernel32 || \
  fail "PE32 MessageBox fixture did not build"
MESSAGE_BOX_FIXTURE64="$TMP/message_box_fixture64.exe"
zig cc -target x86_64-windows-gnu -nostdlib -fno-sanitize=undefined -fno-stack-protector \
  -Wl,-e,raven_entry -Wl,--subsystem,console -o "$MESSAGE_BOX_FIXTURE64" \
  testdata/dll_fixture/message_box_fixture.c -luser32 -lkernel32 || \
  fail "PE64 MessageBox fixture did not build"
for arch in 32 64; do
  fixture_var="MESSAGE_BOX_FIXTURE${arch}"
  fixture="${!fixture_var}"
  auto="1:screenshot-all:$TMP/message-box-$arch;2:key-title:Raven MessageBox,28;3:screenshot-all:$TMP/message-box-close-$arch;4:close-title:Raven MessageBox Close;5:screenshot-all:$TMP/message-box-ansi-$arch;6:click-title:Raven MessageBox ANSI,230,116"
  env -u DISPLAY -u WAYLAND_SOCKET XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-0 \
    timeout --foreground --kill-after=3s 15s "$RAVEN" -auto "$auto" "$fixture" >"$TMP/message-box-$arch.log" 2>&1 || \
    fail "PE$arch MessageBox fixture failed"
  grep -q '\[messagebox\] selected .* result=7' "$TMP/message-box-$arch.log" || \
    fail "PE$arch MessageBox did not return the default IDNO button"
  grep -q '\[messagebox\] closed .* result=7' "$TMP/message-box-$arch.log" || \
    fail "PE$arch MessageBox window did not close"
  [[ "$(grep -c '\[messagebox\] selected .* result=2' "$TMP/message-box-$arch.log")" -ge 2 ]] || \
    fail "PE$arch MessageBox close and ANSI click did not return IDCANCEL"
  [[ "$(grep -c '\[messagebox\] closed .* result=2' "$TMP/message-box-$arch.log")" -ge 2 ]] || \
    fail "PE$arch MessageBox close and ANSI click did not destroy their windows"
  grep -q '\[win32\] ExitProcess(0)' "$TMP/message-box-$arch.log" || \
    fail "PE$arch MessageBox did not return through the guest call site"
  message_box_png=""
  for png in "$TMP"/message-box-"$arch"-*.png; do
    if [[ "$(identify -format '%w %h' "$png" 2>/dev/null)" == "360 150" ]]; then
      message_box_png="$png"
      break
    fi
  done
  [[ -n "$message_box_png" ]] || fail "PE$arch MessageBox screenshot is missing"
  check_png "$message_box_png"
  check_png_region "$message_box_png" '320x110+20+20'
done

OPEN_FIRST="$TMP/first.txt"
printf 'Raven first tab document.\n' >"$OPEN_FIRST"
OPEN_AUTO='35:chord:29,24;50:screenshot:'"$TMP/open-second.png"';54:click:30,55;60:screenshot:'"$TMP/open-first.png"';64:click:110,55;70:screenshot:'"$TMP/open-second-again.png"
DIALOG_PATH="$FIXTURE" RAVEN_TRACE_CLICK=1 run_npp "$TMP/open.log" -auto "$OPEN_AUTO" "$NPP" "$OPEN_FIRST" || \
  fail "Open dialog and tab switching run terminated unexpectedly"
grep -Fq "IFileOpenDialog::Show selected" "$TMP/open.log" || fail "IFileOpenDialog did not return the selected host file"
grep -q 'text="Raven open flow works."' "$TMP/open.log" || fail "Open dialog selection did not reach Scintilla"
awk '/\[auto\] click at \(30,55\)/ { clicked=1 } clicked && /text="Raven first tab document\."/ { found=1; exit } END { exit !found }' "$TMP/open.log" || \
  fail "Selecting the first tab after Open did not activate its Scintilla document"
awk '/\[auto\] click at \(110,55\)/ { clicked=1 } clicked && /text="Raven open flow works\."/ { found=1; exit } END { exit !found }' "$TMP/open.log" || \
  fail "Selecting the Opened tab did not reactivate its Scintilla document"
grep -Eq '\[gpa\] GetProcAddress\(.*"RtlGetNtVersionNumbers"\)' "$TMP/open.log" || \
  fail "RtlGetNtVersionNumbers was not resolved from ntdll"
grep -Fq '"wine_get_version") -> not found' "$TMP/open.log" || \
  fail "Wine detection export was exposed to the application"
[[ "$(grep -c '\[commit\] Commit' "$TMP/open.log")" -le 120 ]] || fail "Idle editor produced excessive frame commits"
check_png "$TMP/open-second.png"
check_png "$TMP/open-first.png"
check_png "$TMP/open-second-again.png"
check_png_region_changed "$TMP/open-second.png" "$TMP/open-first.png" '1000x200+50+70'
check_png_region_same "$TMP/open-second.png" "$TMP/open-second-again.png" '1000x200+50+70'

MARKDOWN_FIXTURE="$TMP/raven-markdown-fixture.md"
printf '# Raven Markdown fixture\n\n## Stable Scintilla marker\n\n- **Bold marker**\n- `inline code marker`\n- [Raven link](https://example.invalid/raven)\n\n> Markdown rendering stays independent from README edits.\n' >"$MARKDOWN_FIXTURE"
MARKDOWN_AUTO='35:screenshot:'"$TMP/markdown.png"
RAVEN_TRACE_FIND=1 run_npp "$TMP/markdown.log" -auto "$MARKDOWN_AUTO" "$NPP" "$MARKDOWN_FIXTURE" || \
  fail "Markdown UDL run terminated unexpectedly"
grep -F 'FindFirstFileW pattern="C:\\npp\\userDefineLangs\\*.xml"' "$TMP/markdown.log" |
  grep -Fq 'entries=2 err=<nil>' || fail "Markdown UDL files were not enumerated from the VFS"
grep -F 'CreateFileW: "C:\\npp\\userDefineLangs\\markdown._preinstalled.udl.xml"' "$TMP/markdown.log" |
  grep -Fq 'handle=' || fail "Markdown UDL file was not opened"
grep -Fq 'text="## Stable Scintilla marker"' "$TMP/markdown.log" || fail "Markdown text was not painted by Scintilla"
check_png "$TMP/markdown.png"
check_png_region_colors "$TMP/markdown.png" '1000x540+70+72' 800

FOLD_FIXTURE="$TMP/fold-margin.cpp"
cat >"$FOLD_FIXTURE" <<'EOF'
int main() {
    if (true) {
        for (int i = 0; i < 4; ++i) {
            if (i > 1) {
                return i;
            }
        }
    }
    return 0;
}
EOF
FOLD_AUTO='35:screenshot:'"$TMP/fold-margin.png"
run_npp "$TMP/fold-margin.log" -auto "$FOLD_AUTO" "$NPP" "$FOLD_FIXTURE" || \
  fail "fold-margin rendering run terminated unexpectedly"
check_png "$TMP/fold-margin.png"
check_png_region_colors "$TMP/fold-margin.png" '58x360+0+72' 12
check_png_region_luminance "$TMP/fold-margin.png" '58x360+0+72' 0.08 0.94 \
  "Scintilla fold margin"
check_png_region_luminance "$TMP/fold-margin.png" '1050x15+20+637' 0.60 0.98 \
  "Scintilla horizontal scrollbar"
check_png_region_luminance "$TMP/fold-margin.png" '1080x20+10+656' 0.60 0.98 \
  "light bottom rebar"

UNICODE_NPP_FILE="$TMP/"$'unicode-\U0001f600-\u65e5\u672c\u8a9e.md'
printf '# Unicode path\n\nCaf\303\251, \316\225\316\273\316\273\316\267\316\275\316\271\316\272\316\254, \346\227\245\346\234\254\350\252\236, emoji: \360\237\230\200\n' >"$UNICODE_NPP_FILE"
UNICODE_AUTO='35:screenshot:'"$TMP/unicode.png"
run_npp "$TMP/unicode.log" -auto "$UNICODE_AUTO" "$NPP" "$UNICODE_NPP_FILE" || \
  fail "Unicode path run terminated unexpectedly"
! grep -Fq "doesn't exist. Create it?" "$TMP/unicode.log" || \
  fail "Unicode path was corrupted before Notepad++ opened it"
grep -Fq 'text="# Unicode path"' "$TMP/unicode.log" || \
  fail "Unicode path content did not reach Scintilla"
grep -Fq 'text="Caf' "$TMP/unicode.log" || \
  fail "Unicode text was not painted by Scintilla"
check_png "$TMP/unicode.png"

FIND_AUTO='35:chord:29,33;40:click-title:Find,220,52;41:key-title:Find,14;41.2:key-title:Find,14;41.4:key-title:Find,14;41.6:key-title:Find,14;41.8:key-title:Find,14;43:key-title:Find,17;43.2:key-title:Find,24;43.4:key-title:Find,19;43.6:key-title:Find,37;43.8:key-title:Find,31;47:click-title:Find,647,53;52:screenshot-all:'"$TMP/find"';55:key-title:Find,15;58:click-title:Find,100,296;61:screenshot-all:'"$TMP/find-group-before"';64:key-title:Find,106;68:screenshot-all:'"$TMP/find-group-after"';72:click-title:Find,647,226;78:screenshot-all:'"$TMP/find-closed"
run_npp "$TMP/find.log" -auto "$FIND_AUTO" "$NPP" "$FIXTURE" || fail "Find run terminated unexpectedly"
FIND_HWND="$(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\) size=782x394 .*/\1/p' "$TMP/find.log" | tail -1)"
[[ -n "$FIND_HWND" ]] || fail "Find did not create a separate window"
grep -q 'text="Raven open flow works."' "$TMP/find.log" || fail "Scintilla did not paint the opened file"
grep -q 'click-title "Find"' "$TMP/find.log" || fail "Find did not open as a separate window"
grep -q '\[button\] BN_CLICKED.* id=1' "$TMP/find.log" || fail "Find Next did not dispatch BN_CLICKED"
grep -q '\[dialog\] tab focus hwnd=' "$TMP/find.log" || fail "Find did not move focus on Tab"
grep -q '\[dialog\] group focus hwnd=' "$TMP/find.log" || fail "Find did not move within the radio group"
grep -q "\[button\] BN_CLICKED.* parent=$FIND_HWND id=2" "$TMP/find.log" || fail "Find Close did not dispatch IDCANCEL"
grep -q "\[dialog-window\] destroyed hwnd=$FIND_HWND" "$TMP/find.log" || fail "Find Close did not destroy the same window"
check_png "$TMP/find-0.png"
check_png "$TMP/find-1.png"
FIND_GROUP_BEFORE=""
FIND_GROUP_AFTER=""
for png in "$TMP"/find-group-before-*.png; do
  [[ "$(identify -format '%w %h' "$png")" == "782 394" ]] && FIND_GROUP_BEFORE="$png"
done
for png in "$TMP"/find-group-after-*.png; do
  [[ "$(identify -format '%w %h' "$png")" == "782 394" ]] && FIND_GROUP_AFTER="$png"
done
[[ -n "$FIND_GROUP_BEFORE" && -n "$FIND_GROUP_AFTER" ]] || fail "Find radio group screenshots are missing"
check_png_region_changed "$FIND_GROUP_BEFORE" "$FIND_GROUP_AFTER" '16x16+20+286'
check_png_region_changed "$FIND_GROUP_BEFORE" "$FIND_GROUP_AFTER" '16x16+20+310'
mapfile -t FIND_CLOSED_PNGS < <(compgen -G "$TMP/find-closed-[0-9]*.png")
[[ ${#FIND_CLOSED_PNGS[@]} -eq 1 ]] || fail "Find remained open after Escape"
check_png "${FIND_CLOSED_PNGS[0]}"

TITLEBAR_AUTO='35:chord:29,33;43:screenshot-all:'"$TMP/find-titlebar-open"';48:close-title:Find;54:screenshot-all:'"$TMP/find-titlebar-closed"';56:click:18,10;59:screenshot:'"$TMP/find-titlebar-responsive.png"
run_npp "$TMP/find-titlebar.log" -auto "$TITLEBAR_AUTO" "$NPP" "$FIXTURE" || \
  fail "Find titlebar close run terminated unexpectedly"
TITLEBAR_FIND_HWND="$(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\) size=782x394 .*/\1/p' "$TMP/find-titlebar.log" | tail -1)"
[[ -n "$TITLEBAR_FIND_HWND" ]] || fail "Find titlebar close did not create a separate window"
grep -q "\[wl\] EventClose target=$TITLEBAR_FIND_HWND" "$TMP/find-titlebar.log" || fail "close did not target Find"
grep -q "\[wl\] dialog close target=$TITLEBAR_FIND_HWND -> WM_COMMAND id=2 " "$TMP/find-titlebar.log" || fail "Find titlebar close did not dispatch IDCANCEL"
grep -q "\[dialog-window\] destroyed hwnd=$TITLEBAR_FIND_HWND" "$TMP/find-titlebar.log" || fail "Find titlebar close did not destroy the window"
awk '/\[dialog-window\] destroyed hwnd=/ { closed=1 } closed && /\[click\] menu bar hit/ { responsive=1; exit } END { exit !responsive }' "$TMP/find-titlebar.log" || fail "NPP did not process input after closing Find"
mapfile -t TITLEBAR_CLOSED_PNGS < <(compgen -G "$TMP/find-titlebar-closed-[0-9]*.png")
[[ ${#TITLEBAR_CLOSED_PNGS[@]} -eq 1 ]] || fail "Find titlebar close left a secondary window open"
check_png "$TMP/find-titlebar-responsive.png"

FIND_FILES_HOST_DIR="$TMP/find-files-target"
mkdir -p "$FIND_FILES_HOST_DIR"
printf 'Raven open flow works.\n' >"$FIND_FILES_HOST_DIR/raven-open-fixture.txt"
FIND_FILES_DIR="Z:${FIND_FILES_HOST_DIR//\//\\}"
FIND_FILES_AUTO='35:click:95,10;39:click:120,52;44:click-title:Find in Files,250,52;45:type-title:Find in Files,Raven open flow works.;48:click-title:Find in Files,250,124;49:type-title:Find in Files,*.txt;52:click-title:Find in Files,250,160;53:type-title:Find in Files,'"$FIND_FILES_DIR"';57:screenshot-all:'"$TMP/find-files-filled"';61:click-title:Find in Files,650,52;72:screenshot-all:'"$TMP/find-files-results"';80:double-click:180,520;85:screenshot:'"$TMP/find-files-opened.png"
RAVEN_TRACE_CLICK=1 run_npp "$TMP/find-files.log" -auto "$FIND_FILES_AUTO" "$NPP" || fail "Find in Files run terminated unexpectedly"
grep -q '\[combobox\] dropdown .* id=1601 ' "$TMP/find-files.log" || fail "Find in Files did not focus the search field"
grep -q '\[combobox\] dropdown .* id=1652 ' "$TMP/find-files.log" || fail "Find in Files did not focus the filters field"
grep -q '\[combobox\] dropdown .* id=1653 ' "$TMP/find-files.log" || fail "Find in Files did not focus the directory field"
grep -q '\[button\] BN_CLICKED.* id=1656 ' "$TMP/find-files.log" || fail "Find in Files did not dispatch Find All"
grep -Fq 'raven-open-fixture.txt (1 hit)' "$TMP/find-files.log" || fail "Find in Files did not find the fixture file"
awk 'index($0, "raven-open-fixture.txt (1 hit)") { result=1 } result && index($0, "text=\"Raven open flow works.\"") { matched=1; exit } END { exit !matched }' "$TMP/find-files.log" || \
  fail "Find in Files did not emit the matching line"
awk '/\[auto\] double-click at \(180,520\)/ { clicked=1 } clicked && /\[click\].*hitChild=.*class="scintilla"/ { targeted=1 } clicked && index($0, "text=\"Raven open flow works.\"") { opened=1 } END { exit !(targeted && opened) }' "$TMP/find-files.log" || \
  fail "Find in Files result did not open the matching file"
FIND_FILES_FILLED_MAIN=""
FIND_FILES_FILLED_DIALOG=""
FIND_FILES_RESULTS_MAIN=""
for png in "$TMP"/find-files-filled-*.png; do
  check_png "$png"
  dimensions="$(identify -format '%w %h' "$png")"
  [[ "$dimensions" == "1100 700" ]] && FIND_FILES_FILLED_MAIN="$png"
  [[ "$dimensions" == "782 394" ]] && FIND_FILES_FILLED_DIALOG="$png"
done
for png in "$TMP"/find-files-results-*.png; do
  check_png "$png"
  dimensions="$(identify -format '%w %h' "$png")"
  [[ "$dimensions" == "1100 700" ]] && FIND_FILES_RESULTS_MAIN="$png"
done
[[ -n "$FIND_FILES_FILLED_MAIN" && -n "$FIND_FILES_FILLED_DIALOG" ]] || fail "Find in Files opening screenshots are incomplete"
[[ -n "$FIND_FILES_RESULTS_MAIN" ]] || fail "Find in Files result screenshot is missing"
check_png_region_changed "$FIND_FILES_FILLED_MAIN" "$FIND_FILES_RESULTS_MAIN" '1080x205+0+475'
check_png_region "$FIND_FILES_RESULTS_MAIN" '800x72+10+475'
check_png "$TMP/find-files-opened.png"
check_png_region_changed "$FIND_FILES_RESULTS_MAIN" "$TMP/find-files-opened.png" '1080x400+0+70'

REPLACE_FIXTURE="$TMP/raven-replace-fixture.txt"
printf 'alpha beta alpha\n' >"$REPLACE_FIXTURE"
REPLACE_AUTO='35:chord:29,35;40:click-title:Replace,220,88;41:key-title:Replace,24;41.2:key-title:Replace,50;41.4:key-title:Replace,18;41.6:key-title:Replace,34;41.8:key-title:Replace,30;45:click-title:Replace,647,126;49:screenshot-all:'"$TMP/replace"';52:click-title:Replace,647,212;55:chord:29,31;70:screenshot:'"$TMP/replace-main.png"
run_npp "$TMP/replace.log" -auto "$REPLACE_AUTO" "$NPP" "$REPLACE_FIXTURE" || fail "Replace run terminated unexpectedly"
grep -q 'click-title "Replace"' "$TMP/replace.log" || fail "Replace did not open as a separate window"
grep -q '\[button\] BN_CLICKED.* id=1609' "$TMP/replace.log" || fail "Replace All did not dispatch BN_CLICKED"
grep -q 'text="omega beta omega"' "$TMP/replace.log" || fail "Replace All did not update the Scintilla document"
[[ "$(cat "$REPLACE_FIXTURE")" == "omega beta omega" ]] || fail "Ctrl+S did not flush the replaced text to the host"
check_png "$TMP/replace-0.png"
check_png "$TMP/replace-1.png"
check_png "$TMP/replace-main.png"

ABOUT_AUTO='35:click:607,10;39:click:700,272;47:screenshot-all:'"$TMP/about"';50:close-title:;56:screenshot-all:'"$TMP/about-closed"';58:click:18,10;61:screenshot:'"$TMP/about-responsive.png"
run_npp "$TMP/about.log" -auto "$ABOUT_AUTO" "$NPP" || fail "About run terminated unexpectedly"
ABOUT_HWND="$(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\) size=540x480.*/\1/p' "$TMP/about.log" | tail -1)"
[[ -n "$ABOUT_HWND" ]] || fail "About did not open as a separate window"
grep -q '\[callwndproc\] CallWindowProcW .* msg=0xf' "$TMP/about.log" || fail "About subclassed controls did not receive WM_PAINT"
grep -q "\[wl\] dialog close target=$ABOUT_HWND -> WM_COMMAND id=1 " "$TMP/about.log" || fail "About titlebar close did not dispatch IDOK"
grep -q "\[dialog-window\] destroyed hwnd=$ABOUT_HWND" "$TMP/about.log" || fail "About OK did not close the same separate window"
awk '/\[dialog-window\] destroyed hwnd=/ { closed=1 } closed && /\[click\] menu bar hit/ { responsive=1; exit } END { exit !responsive }' "$TMP/about.log" || fail "NPP did not process input after closing About"
mapfile -t ABOUT_PNGS < <(compgen -G "$TMP/about-[0-9]*.png")
mapfile -t ABOUT_CLOSED_PNGS < <(compgen -G "$TMP/about-closed-*.png")
[[ ${#ABOUT_PNGS[@]} -eq 2 ]] || fail "About opening did not produce two window screenshots"
[[ ${#ABOUT_CLOSED_PNGS[@]} -eq 1 ]] || fail "About window remained open after OK"
for png in "${ABOUT_PNGS[@]}" "${ABOUT_CLOSED_PNGS[@]}"; do
  check_png "$png"
done
ABOUT_DIALOG_PNG=""
for png in "${ABOUT_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "540 480" ]] && ABOUT_DIALOG_PNG="$png"
done
[[ -n "$ABOUT_DIALOG_PNG" ]] || fail "About screenshot dimensions do not match the separate dialog"
check_png_region "$ABOUT_DIALOG_PNG" '280x24+165+48'
check_png_region "$ABOUT_DIALOG_PNG" '260x24+95+108'
check_png_region "$ABOUT_DIALOG_PNG" '110x32+215+436'
check_png "$TMP/about-responsive.png"

PREFERENCES_AUTO='35:click:337,10;39:click:365,31;47:click-title:Preferences,100,67;52:click-title:Preferences,270,62;54:click-title:Preferences,270,62;57:screenshot-all:'"$TMP/preferences"';60:click-title:Preferences,48,83;64:click-title:Preferences,257,62;140:screenshot-all:'"$TMP/preferences-dark"';145:click-title:Preferences,257,32;190:close-title:Preferences;205:screenshot-all:'"$TMP/preferences-closed"';208:click:18,10;214:screenshot:'"$TMP/preferences-responsive.png"
RUN_TIMEOUT=250 run_npp "$TMP/preferences.log" -auto "$PREFERENCES_AUTO" "$NPP" || fail "Preferences run terminated unexpectedly"
PREFERENCES_HWND="$(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\) size=1160x470 title="Preferences".*/\1/p' "$TMP/preferences.log" | tail -1)"
[[ -n "$PREFERENCES_HWND" ]] || fail "Preferences did not open as a separate window"
grep -q '\[auto\] click-title "Preferences" at (100,67)' "$TMP/preferences.log" || fail "Preferences did not select the Editing 2 page"
awk '/\[auto\] click-title "Preferences" at \(270,62\)/ { clicks++; next } clicks == 1 && /\[button\] BN_CLICKED.* id=6522 checked=0/ { unchecked=1 } clicks == 2 && /\[button\] BN_CLICKED.* id=6522 checked=1/ { checked=1; exit } END { exit !(unchecked && checked) }' "$TMP/preferences.log" || fail "Preferences checkbox did not toggle off and on"
grep -q '\[button\] BN_CLICKED.* id=7132 checked=1' "$TMP/preferences.log" || fail "Preferences did not enable dark mode"
grep -q '\[button\] BN_CLICKED.* id=7131 checked=1' "$TMP/preferences.log" || fail "Preferences did not restore light mode"
grep -q "\[wl\] dialog close target=$PREFERENCES_HWND -> WM_COMMAND id=6001 " "$TMP/preferences.log" || fail "Preferences titlebar close did not dispatch the Close command"
grep -q "\[dialog-window\] destroyed hwnd=$PREFERENCES_HWND" "$TMP/preferences.log" || fail "Preferences Close did not destroy the same window"
awk '/\[dialog-window\] destroyed hwnd=/ { closed=1 } closed && /\[click\] menu bar hit/ { responsive=1; exit } END { exit !responsive }' "$TMP/preferences.log" || fail "NPP did not process input after closing Preferences"
! grep -q '\[subclass\].*failed' "$TMP/preferences.log" || fail "Preferences custom control painting failed"
awk '/\[dialog-window\] created .* title="Preferences"/ { opened=1; next } opened && /\[cpu-fault\]/ { exit 1 }' "$TMP/preferences.log" || fail "Preferences triggered a CPU fault"
mapfile -t PREFERENCES_PNGS < <(compgen -G "$TMP/preferences-[0-9]*.png")
mapfile -t PREFERENCES_DARK_PNGS < <(compgen -G "$TMP/preferences-dark-*.png")
mapfile -t PREFERENCES_CLOSED_PNGS < <(compgen -G "$TMP/preferences-closed-*.png")
[[ ${#PREFERENCES_PNGS[@]} -eq 2 ]] || fail "Preferences opening did not produce two window screenshots"
[[ ${#PREFERENCES_DARK_PNGS[@]} -eq 2 ]] || fail "Preferences dark mode did not produce two window screenshots"
[[ ${#PREFERENCES_CLOSED_PNGS[@]} -eq 1 ]] || fail "Preferences window remained open after Close"
PREFERENCES_DIALOG_PNG=""
PREFERENCES_MAIN_PNG=""
PREFERENCES_DARK_MAIN_PNG=""
PREFERENCES_DARK_DIALOG_PNG=""
for png in "${PREFERENCES_PNGS[@]}"; do
  check_png "$png"
  [[ "$(identify -format '%w %h' "$png")" == "1100 700" ]] && PREFERENCES_MAIN_PNG="$png"
  [[ "$(identify -format '%w %h' "$png")" == "1160 470" ]] && PREFERENCES_DIALOG_PNG="$png"
done
for png in "${PREFERENCES_DARK_PNGS[@]}"; do
  check_png "$png"
  [[ "$(identify -format '%w %h' "$png")" == "1100 700" ]] && PREFERENCES_DARK_MAIN_PNG="$png"
  [[ "$(identify -format '%w %h' "$png")" == "1160 470" ]] && PREFERENCES_DARK_DIALOG_PNG="$png"
done
[[ -n "$PREFERENCES_MAIN_PNG" && -n "$PREFERENCES_DIALOG_PNG" &&
   -n "$PREFERENCES_DARK_MAIN_PNG" && -n "$PREFERENCES_DARK_DIALOG_PNG" ]] || \
  fail "Preferences screenshots do not match the expected windows"
check_png "$TMP/preferences-responsive.png"
check_png_region_colors "$TMP/preferences-responsive.png" '800x25+0+20' 50
check_png_region_changed "$PREFERENCES_MAIN_PNG" "$PREFERENCES_DARK_MAIN_PNG" '1080x620+10+50'
check_png_region_colors "$PREFERENCES_DARK_MAIN_PNG" '800x25+0+20' 50
check_png_region_luminance "$PREFERENCES_DARK_MAIN_PNG" '900x20+0+0' 0.05 0.62 \
  "dark menu"
check_png_region_luminance "$PREFERENCES_DARK_MAIN_PNG" '1000x24+0+22' 0.05 0.68 \
  "dark toolbar"
check_png_region_luminance "$PREFERENCES_DARK_MAIN_PNG" '1000x18+0+681' 0.05 0.62 \
  "dark status bar"
check_png_region_luminance "$PREFERENCES_DARK_DIALOG_PNG" '1120x430+20+20' 0.05 0.62 \
  "dark Preferences"
check_png_region_luminance "$PREFERENCES_DARK_DIALOG_PNG" '190x400+20+20' 0.05 0.62 \
  "dark Preferences navigation"
check_png_region "$PREFERENCES_DIALOG_PNG" '190x400+20+20'
check_png_region "$PREFERENCES_DIALOG_PNG" '580x118+252+26'
check_png_region "$PREFERENCES_DIALOG_PNG" '620x242+252+156'

COLOR_AUTO='35:click:337,10;39:click:365,54;44:screenshot-all:'"$TMP/color-before"';47:click-title:Style Configurator,541,152;53:screenshot-all:'"$TMP/color-palette"';56:click-title:,115,25;62:screenshot-all:'"$TMP/color-after"';66:click-title:Style Configurator,541,152;75:click-title:,133,200;140:screenshot-all:'"$TMP/color-more"';145:click-title:Style Configurator,724,458;150:screenshot-all:'"$TMP/color-closed"
RUN_TIMEOUT=220 RAVEN_COLOR_DIALOG_VALUE='#ff00ff' run_npp "$TMP/color.log" -auto "$COLOR_AUTO" "$NPP" || fail "Style color picker run terminated unexpectedly"
mapfile -t COLOR_BEFORE_PNGS < <(compgen -G "$TMP/color-before-[0-9]*.png")
mapfile -t COLOR_PALETTE_PNGS < <(compgen -G "$TMP/color-palette-[0-9]*.png")
mapfile -t COLOR_AFTER_PNGS < <(compgen -G "$TMP/color-after-[0-9]*.png")
mapfile -t COLOR_MORE_PNGS < <(compgen -G "$TMP/color-more-[0-9]*.png")
mapfile -t COLOR_CLOSED_PNGS < <(compgen -G "$TMP/color-closed-[0-9]*.png")
[[ ${#COLOR_BEFORE_PNGS[@]} -eq 2 && ${#COLOR_PALETTE_PNGS[@]} -eq 3 && ${#COLOR_AFTER_PNGS[@]} -eq 2 && ${#COLOR_MORE_PNGS[@]} -eq 2 ]] || fail "Style color picker screenshots are incomplete"
[[ ${#COLOR_CLOSED_PNGS[@]} -eq 1 ]] || fail "Style Configurator remained open after color picker test"
COLOR_BEFORE_DIALOG=""
COLOR_PALETTE_DIALOG=""
COLOR_AFTER_DIALOG=""
COLOR_MORE_DIALOG=""
for png in "${COLOR_BEFORE_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "1000 492" ]] && COLOR_BEFORE_DIALOG="$png"
done
for png in "${COLOR_PALETTE_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "264 226" ]] && COLOR_PALETTE_DIALOG="$png"
done
for png in "${COLOR_AFTER_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "1000 492" ]] && COLOR_AFTER_DIALOG="$png"
done
for png in "${COLOR_MORE_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "1000 492" ]] && COLOR_MORE_DIALOG="$png"
done
[[ -n "$COLOR_BEFORE_DIALOG" && -n "$COLOR_PALETTE_DIALOG" && -n "$COLOR_AFTER_DIALOG" && -n "$COLOR_MORE_DIALOG" ]] || fail "Style color picker windows are missing"
check_png_region "$COLOR_PALETTE_DIALOG" '234x158+14+14'
COLOR_BEFORE_PIXEL="$(convert "$COLOR_BEFORE_DIALOG" -format '%[pixel:p{540,151}]' info:)"
COLOR_AFTER_PIXEL="$(convert "$COLOR_AFTER_DIALOG" -format '%[pixel:p{540,151}]' info:)"
COLOR_MORE_PIXEL="$(convert "$COLOR_MORE_DIALOG" -format '%[pixel:p{540,151}]' info:)"
[[ "$COLOR_BEFORE_PIXEL" == "srgb(0,0,0)" ]] || fail "Style foreground swatch did not start black"
[[ "$COLOR_AFTER_PIXEL" == "srgb(0,255,0)" ]] || fail "Style foreground swatch did not change to green"
[[ "$COLOR_MORE_PIXEL" == "srgb(255,0,255)" ]] || fail "Style More Colours did not apply the selected color"
grep -q '\[dialog-window\] created .* size=264x226 title=""' "$TMP/color.log" || fail "Style color palette did not open as a separate window"
grep -q '\[dialog-window\] destroyed .*' "$TMP/color.log" || fail "Style color palette did not close after selection"
grep -q '\[comdlg32\] ChooseColorW default=' "$TMP/color.log" || fail "Style More Colours did not invoke ChooseColorW"

STYLE_AUTO='35:click:337,10;39:click:365,54;43:click-title:Style Configurator,75,335;46:click-title:Style Configurator,840,147;48:screenshot-all:'"$TMP/style-open"';50:click-title:Style Configurator,840,188;52:click-title:Style Configurator,660,185;55:click-title:Style Configurator,596,458;65:click:337,10;69:click:365,54;76:screenshot-all:'"$TMP/style-reopened"';82:click-title:Style Configurator,724,458;87:screenshot-all:'"$TMP/style-closed"
run_npp "$TMP/style.log" -auto "$STYLE_AUTO" "$NPP" || fail "Style Configurator run terminated unexpectedly"
mapfile -t STYLE_HWNDS < <(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\) size=1000x492 title="Style Configurator".*/\1/p' "$TMP/style.log")
[[ ${#STYLE_HWNDS[@]} -eq 2 ]] || fail "Style Configurator did not open twice as a separate window"
STYLE_SAVE_HWND="${STYLE_HWNDS[0]}"
STYLE_REOPEN_HWND="${STYLE_HWNDS[1]}"
grep -q '\[combobox\] dropdown.* id=2202 open=true items=' "$TMP/style.log" || fail "Style Configurator font dropdown did not open"
grep -q '\[combobox\] select.* id=2202 index=1 text="Inter"' "$TMP/style.log" || fail "Style Configurator font selection did not change"
grep -q '\[button\] BN_CLICKED.* id=2204 checked=1' "$TMP/style.log" || fail "Style Configurator Bold did not enter the checked state"
grep -q "\[button\] BN_CLICKED.* parent=$STYLE_SAVE_HWND id=2301" "$TMP/style.log" || fail "Style Configurator Save & Close did not dispatch BN_CLICKED"
grep -q "\[dialog-window\] destroyed hwnd=$STYLE_SAVE_HWND" "$TMP/style.log" || fail "Saved Style Configurator window did not close"
grep -q "\[dialog-window\] destroyed hwnd=$STYLE_REOPEN_HWND" "$TMP/style.log" || fail "Reopened Style Configurator window did not close"
[[ "$(grep -c '\[dialog-window\] destroyed hwnd=' "$TMP/style.log")" -ge 2 ]] || fail "Style Configurator windows did not close cleanly"
awk '/\[dialog-window\] created .* title="Style Configurator"/ { opened=1; next } opened && /\[cpu-fault\]/ { exit 1 }' "$TMP/style.log" || fail "Style Configurator triggered a CPU fault"
mapfile -t STYLE_OPEN_PNGS < <(compgen -G "$TMP/style-open-[0-9]*.png")
mapfile -t STYLE_REOPENED_PNGS < <(compgen -G "$TMP/style-reopened-[0-9]*.png")
mapfile -t STYLE_CLOSED_PNGS < <(compgen -G "$TMP/style-closed-[0-9]*.png")
[[ ${#STYLE_OPEN_PNGS[@]} -eq 2 && ${#STYLE_REOPENED_PNGS[@]} -eq 2 ]] || fail "Style Configurator screenshots are incomplete"
[[ ${#STYLE_CLOSED_PNGS[@]} -eq 1 ]] || fail "Style Configurator remained open after Cancel"
STYLE_OPEN_DIALOG=""
STYLE_REOPENED_DIALOG=""
for png in "${STYLE_OPEN_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "1000 492" ]] && STYLE_OPEN_DIALOG="$png"
done
for png in "${STYLE_REOPENED_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "1000 492" ]] && STYLE_REOPENED_DIALOG="$png"
done
[[ -n "$STYLE_OPEN_DIALOG" && -n "$STYLE_REOPENED_DIALOG" ]] || fail "Style Configurator dialog screenshots are missing"
check_png_region "$STYLE_OPEN_DIALOG" '208x44+742+136'
check_png_region "$STYLE_REOPENED_DIALOG" '208x24+742+136'
check_png_region "$STYLE_REOPENED_DIALOG" '90x24+650+174'
check_png_region_changed "$STYLE_OPEN_DIALOG" "$STYLE_REOPENED_DIALOG" '208x24+742+136'
check_png_region_changed "$STYLE_OPEN_DIALOG" "$STYLE_REOPENED_DIALOG" '90x24+650+174'

SAVE_AUTO='35:click:200,81;38:chord:29,30;40:key:17;43:chord:29,31;48:screenshot:'"$TMP/save.png"
run_npp "$TMP/save.log" -auto "$SAVE_AUTO" "$NPP" "$FIXTURE" || fail "Save run terminated unexpectedly"
[[ "$(cat "$FIXTURE")" == "w" ]] || fail "Ctrl+S did not flush the edited file to the host"
check_png "$TMP/save.png"

SAVE_ALL_FIRST="$TMP/raven-save-all-first.txt"
SAVE_ALL_SECOND="$TMP/raven-save-all-second.txt"
printf 'first original\n' >"$SAVE_ALL_FIRST"
printf 'second original\n' >"$SAVE_ALL_SECOND"
SAVE_ALL_AUTO='35:click:200,81;40:chord:29,30;45:key:45;60:click:30,55;65:click:200,81;70:chord:29,30;75:key:44;90:click:18,10;95:click:70,229;105:click-title:Save,144,164;115:screenshot:'"$TMP/save-all.png"
RUN_TIMEOUT=140 RAVEN_TRACE_CLICK=1 run_npp "$TMP/save-all.log" -auto "$SAVE_ALL_AUTO" "$NPP" "$SAVE_ALL_FIRST" "$SAVE_ALL_SECOND" || \
  fail "Save All run terminated unexpectedly"
awk '/\[auto\] key 45/ { keyed=1; next } keyed && /path="\/npp\/backup\/raven-save-all-second\.txt@.* hex=78$/ { flushed=1 } /\[auto\] click at \(30,55\)/ { exit !flushed } END { exit !flushed }' "$TMP/save-all.log" || \
  fail "Save All switched tabs before the second document edit was flushed"
awk '/\[auto\] key 44/ { keyed=1; next } keyed && /path="\/npp\/backup\/raven-save-all-first\.txt@.* hex=7a$/ { flushed=1 } /\[auto\] click at \(18,10\)/ { exit !flushed } END { exit !flushed }' "$TMP/save-all.log" || \
  fail "Save All opened the menu before the first document edit was flushed"
grep -q '\[dialog\] DialogBoxParamW template=#1765' "$TMP/save-all.log" || fail "Save All confirmation did not open"
grep -q '\[button\] BN_CLICKED .* id=6 ' "$TMP/save-all.log" || fail "Save All confirmation did not receive Yes"
SAVE_ALL_HWND="$(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\).* title="Save".*/\1/p' "$TMP/save-all.log" | tail -1)"
[[ -n "$SAVE_ALL_HWND" ]] || fail "Save All confirmation window handle is missing"
grep -q "\[dialog-window\] destroyed hwnd=$SAVE_ALL_HWND" "$TMP/save-all.log" || fail "Save All confirmation did not close"
[[ "$(cat "$SAVE_ALL_FIRST")" == "z" ]] || fail "Save All did not persist the first document"
[[ "$(cat "$SAVE_ALL_SECOND")" == "x" ]] || fail "Save All did not persist the second document"
check_png "$TMP/save-all.png"

RELOAD_SOURCE="$TMP/raven-reload-source.txt"
RELOAD_CONTENT="Reload source remains."
printf '%s\n' "$RELOAD_CONTENT" >"$RELOAD_SOURCE"
RELOAD_AUTO='35:click:200,81;38:chord:29,30;40:key:45;43:click:18,10;46:click:70,141;53:click-title:Reload,218,116;60:chord:29,31;64:screenshot:'"$TMP/reload.png"
RAVEN_TRACE_CLICK=1 run_npp "$TMP/reload.log" -auto "$RELOAD_AUTO" "$NPP" "$RELOAD_SOURCE" || \
  fail "Reload run terminated unexpectedly"
grep -Fq '[click] popup item index=5 id=41014 text="Reload from Disk' "$TMP/reload.log" || \
  fail "File menu did not dispatch Reload from Disk"
grep -q '\[messagebox\] selected .* result=6' "$TMP/reload.log" || fail "Reload confirmation did not return Yes"
grep -q '\[dialog-window\] destroyed .*' "$TMP/reload.log" || fail "Reload confirmation window did not close"
[[ "$(cat "$RELOAD_SOURCE")" == "$RELOAD_CONTENT" ]] || fail "Reload did not restore the host file content"
check_png "$TMP/reload.png"

SAVE_AS_TARGET="$TMP/raven-save-as-output.txt"
SAVE_AS_AUTO='35:click:200,81;38:chord:29,30;40:key:45;44:click:18,10;47:click:70,185;53:click:200,81;55:chord:29,30;57:key:44;59:chord:29,31;63:screenshot:'"$TMP/save-as.png"
DIALOG_PATH="$SAVE_AS_TARGET" run_npp "$TMP/save-as.log" -auto "$SAVE_AS_AUTO" "$NPP" "$FIXTURE" || fail "Save As run terminated unexpectedly"
grep -Fq "IFileSaveDialog::Show selected" "$TMP/save-as.log" || fail "IFileSaveDialog did not return the selected host path"
[[ "$(cat "$FIXTURE")" == "w" ]] || fail "Save As modified the original host file"
[[ -f "$SAVE_AS_TARGET" && "$(cat "$SAVE_AS_TARGET")" == "z" ]] || fail "Save As did not bind subsequent saves to the selected host file"
check_png "$TMP/save-as.png"

SAVE_COPY_SOURCE="$TMP/raven-save-copy-source.txt"
SAVE_COPY_TARGET="$TMP/raven-save-copy-target.txt"
printf 'w\n' >"$SAVE_COPY_SOURCE"
SAVE_COPY_AUTO='35:click:200,81;38:chord:29,30;40:key:45;44:click:18,10;47:click:70,207;55:click:200,81;58:chord:29,30;60:key:44;63:chord:29,31;68:screenshot:'"$TMP/save-copy.png"
DIALOG_PATH="$SAVE_COPY_TARGET" RAVEN_TRACE_CLICK=1 run_npp "$TMP/save-copy.log" -auto "$SAVE_COPY_AUTO" "$NPP" "$SAVE_COPY_SOURCE" || \
  fail "Save a Copy As run terminated unexpectedly"
grep -Fq '[click] popup item index=8 id=41015 text="Save a Copy As..."' "$TMP/save-copy.log" || \
  fail "File menu did not dispatch Save a Copy As"
grep -Fq "IFileSaveDialog::Show selected" "$TMP/save-copy.log" || fail "Save a Copy As did not open IFileSaveDialog"
[[ "$(cat "$SAVE_COPY_SOURCE")" == "z" ]] || fail "Save a Copy As changed the current host binding"
[[ -f "$SAVE_COPY_TARGET" && "$(cat "$SAVE_COPY_TARGET")" == "x" ]] || fail "Save a Copy As did not persist the copied content"
check_png "$TMP/save-copy.png"

RENAME_SOURCE="$TMP/raven-rename-source.txt"
RENAME_TARGET="$TMP/raven-renamed-target.txt"
RENAME_CONTENT="Raven rename flow works."
printf '%s\n' "$RENAME_CONTENT" >"$RENAME_SOURCE"
RENAME_AUTO='35:click:18,10;39:click:70,251;48:click:200,81;50:chord:29,30;52:key:45;54:chord:29,31;60:screenshot:'"$TMP/rename.png"
DIALOG_PATH="$RENAME_TARGET" RAVEN_TRACE_CLICK=1 run_npp "$TMP/rename.log" -auto "$RENAME_AUTO" "$NPP" "$RENAME_SOURCE" || \
  fail "Rename run terminated unexpectedly"
grep -Fq '[click] popup item index=10 id=41017 text="Rename..."' "$TMP/rename.log" || \
  fail "File menu did not dispatch Rename"
grep -Fq "IFileSaveDialog::Show selected" "$TMP/rename.log" || fail "Rename did not open IFileSaveDialog"
[[ ! -e "$RENAME_SOURCE" ]] || fail "Rename left the original host file in place"
[[ -f "$RENAME_TARGET" && "$(cat "$RENAME_TARGET")" == "x" ]] || \
  fail "Rename did not preserve the selected host binding for subsequent saves"
check_png "$TMP/rename.png"

DELETE_SOURCE="$TMP/raven-delete-source.txt"
DELETE_DATA_HOME="$TMP/delete-xdg-data"
DELETE_CONTENT="Deleted content must not reopen."
printf '%s\n' "$DELETE_CONTENT" >"$DELETE_SOURCE"
DELETE_AUTO='35:click:18,10;39:click:70,339;44:screenshot-all:'"$TMP/delete-confirm"';48:click-title:Delete file,260,142;58:click:18,10;61:click:70,53;72:screenshot:'"$TMP/delete.png"
XDG_DATA_HOME="$DELETE_DATA_HOME" DIALOG_PATH="$DELETE_SOURCE" RAVEN_TRACE_CLICK=1 \
  run_npp "$TMP/delete.log" -auto "$DELETE_AUTO" "$NPP" "$DELETE_SOURCE" || \
  fail "Move to Recycle Bin run terminated unexpectedly"
grep -Fq '[click] popup item index=14 id=41016 text="Move to Recycle Bin"' "$TMP/delete.log" || \
  fail "File menu did not dispatch Move to Recycle Bin"
grep -q '\[messagebox\] selected .* result=1' "$TMP/delete.log" || fail "Delete confirmation did not return OK"
grep -Fq '[click] popup item index=1 id=41002 text="Open...' "$TMP/delete.log" || fail "Deleted file reopen was not attempted"
grep -Fq "[com] IFileOpenDialog::Show failed path=\"$DELETE_SOURCE\"" "$TMP/delete.log" || \
  fail "Deleted file reopen did not complete with a missing-file result"
[[ ! -e "$DELETE_SOURCE" ]] || fail "Move to Recycle Bin left the original host file in place"
DELETE_TRASH_FILE="$DELETE_DATA_HOME/Trash/files/$(basename "$DELETE_SOURCE")"
DELETE_TRASH_INFO="$DELETE_DATA_HOME/Trash/info/$(basename "$DELETE_SOURCE").trashinfo"
[[ -f "$DELETE_TRASH_FILE" && "$(cat "$DELETE_TRASH_FILE")" == "$DELETE_CONTENT" ]] || \
  fail "Move to Recycle Bin did not preserve the deleted content"
grep -Fq "Path=$DELETE_SOURCE" "$DELETE_TRASH_INFO" || fail "Move to Recycle Bin did not write trash metadata"
awk -v content="$DELETE_CONTENT" '/popup item index=1 id=41002/ { afterOpen=1; next } afterOpen && index($0, "text=\"" content "\"") { exit 1 }' "$TMP/delete.log" || \
  fail "Deleted file reopened from stale VFS content"
mapfile -t DELETE_CONFIRM_PNGS < <(compgen -G "$TMP/delete-confirm-[0-9]*.png")
[[ ${#DELETE_CONFIRM_PNGS[@]} -eq 2 ]] || fail "Delete confirmation did not render as a separate window"
for png in "${DELETE_CONFIRM_PNGS[@]}"; do
  check_png "$png"
done
check_png "$TMP/delete.png"

NEW_SAVE_TARGET="$TMP/raven-new-document.txt"
NEW_SAVE_AUTO='35:chord:29,49;40:click:200,81;43:key:19;46:chord:29,31;55:screenshot:'"$TMP/new-save.png"
DIALOG_PATH="$NEW_SAVE_TARGET" run_npp "$TMP/new-save.log" -auto "$NEW_SAVE_AUTO" "$NPP" || fail "New document save run terminated unexpectedly"
grep -Fq "IFileSaveDialog::Show selected" "$TMP/new-save.log" || fail "New document did not open IFileSaveDialog"
! grep -q 'Save failed' "$TMP/new-save.log" || fail "New document save reported a write failure"
[[ -f "$NEW_SAVE_TARGET" && "$(cat "$NEW_SAVE_TARGET")" == "r" ]] || fail "New document did not persist its text to the selected host file"
check_png "$TMP/new-save.png"

EDIT_FIXTURE="$TMP/raven-edit-fixture.txt"
EDIT_TOKEN="raven-copy-${TMP##*/}"
printf '%s' "$EDIT_TOKEN" >"$EDIT_FIXTURE"
EDIT_AUTO='35:click:200,81;38:chord:29,30;40:chord:29,46;42:key:106;44:key:28;46:chord:29,47;49:screenshot:'"$TMP/edit-copy-paste.png"';51:chord:29,44;53:screenshot:'"$TMP/edit-undo.png"';55:chord:29,21;57:screenshot:'"$TMP/edit-redo.png"';59:chord:29,30;61:chord:29,45;63:screenshot:'"$TMP/edit-cut.png"';65:chord:29,47;67:chord:29,31;70:screenshot:'"$TMP/edit-final.png"
run_npp "$TMP/edit.log" -auto "$EDIT_AUTO" "$NPP" "$EDIT_FIXTURE" || fail "Edit command run terminated unexpectedly"
grep -q '\[auto\] chord 29,46' "$TMP/edit.log" || fail "Copy shortcut was not delivered"
grep -q '\[auto\] chord 29,45' "$TMP/edit.log" || fail "Cut shortcut was not delivered"
grep -q '\[auto\] chord 29,47' "$TMP/edit.log" || fail "Paste shortcut was not delivered"
grep -q '\[auto\] chord 29,44' "$TMP/edit.log" || fail "Undo shortcut was not delivered"
grep -q '\[auto\] chord 29,21' "$TMP/edit.log" || fail "Redo shortcut was not delivered"
EDIT_TEXT="$(cat "$EDIT_FIXTURE")"
EXPECTED_EDIT_LF="${EDIT_TOKEN}"$'\n'"${EDIT_TOKEN}"
EXPECTED_EDIT_CRLF="${EDIT_TOKEN}"$'\r\n'"${EDIT_TOKEN}"
[[ "$EDIT_TEXT" == "$EXPECTED_EDIT_LF" || "$EDIT_TEXT" == "$EXPECTED_EDIT_CRLF" ]] || fail "Copy, Cut, Paste, Undo, Redo, and Save did not persist the expected document"
check_png "$TMP/edit-copy-paste.png"
check_png "$TMP/edit-cut.png"
check_png "$TMP/edit-undo.png"
check_png "$TMP/edit-redo.png"
check_png "$TMP/edit-final.png"
check_png_region_changed "$TMP/edit-undo.png" "$TMP/edit-redo.png" '400x60+50+95'
check_png_region_same "$TMP/edit-copy-paste.png" "$TMP/edit-redo.png" '400x60+50+95'
check_png_region_changed "$TMP/edit-cut.png" "$TMP/edit-final.png" '400x60+50+95'

GOTO_RUN_AUTO='34:screenshot:'"$TMP/goto-before.png"';35:chord:29,34;40:click-title:Go To...,280,88;42:key-title:Go To...,3;45:screenshot-all:'"$TMP/goto-open"';48:click-title:Go To...,430,88;53:screenshot-all:'"$TMP/goto-closed"';55:key:63;60:screenshot-all:'"$TMP/run-open"';63:type-title:Run...,notepad++.exe;66:click-title:Run...,82,134;82:screenshot-all:'"$TMP/run-closed"
run_npp "$TMP/goto-run.log" -auto "$GOTO_RUN_AUTO" "$NPP" "$EDIT_FIXTURE" || fail "Go To and Run dialog test terminated unexpectedly"
grep -q '\[dialog-window\] created .* size=516x150 title="Go To\.\.\."' "$TMP/goto-run.log" || fail "Go To did not open as a separate window"
grep -q '\[dialog-window\] created .* size=372x160 title="Run\.\.\."' "$TMP/goto-run.log" || fail "Run did not open as a separate window"
GOTO_HWND="$(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\) size=516x150 title="Go To\.\.\.".*/\1/p' "$TMP/goto-run.log" | tail -1)"
RUN_HWND="$(sed -n 's/.*\[dialog-window\] created hwnd=\(0x[0-9a-f]*\) size=372x160 title="Run\.\.\.".*/\1/p' "$TMP/goto-run.log" | tail -1)"
[[ -n "$GOTO_HWND" && -n "$RUN_HWND" ]] || fail "Go To or Run window handle is missing"
grep -q "\[button\] BN_CLICKED.* parent=$GOTO_HWND id=1" "$TMP/goto-run.log" || fail "Go To did not dispatch BN_CLICKED"
grep -q "\[dialog-window\] destroyed hwnd=$GOTO_HWND" "$TMP/goto-run.log" || fail "Go To did not destroy the same window"
grep -q "\[dialog-window\] destroyed hwnd=$RUN_HWND" "$TMP/goto-run.log" || fail "Run did not destroy the same window"
grep -q '\[process\] started target=.*testdata/npp/notepad++\.exe' "$TMP/goto-run.log" || fail "Run did not start the requested PE"
[[ "$(grep -c '\[resolve\] notepad++\.exe: 587 imports, 587 resolved, 0 unresolved' "$TMP/goto-run.log")" -ge 2 ]] || fail "Run did not load the child PE"
mapfile -t GOTO_OPEN_PNGS < <(compgen -G "$TMP/goto-open-[0-9]*.png")
mapfile -t GOTO_CLOSED_PNGS < <(compgen -G "$TMP/goto-closed-[0-9]*.png")
mapfile -t RUN_OPEN_PNGS < <(compgen -G "$TMP/run-open-[0-9]*.png")
mapfile -t RUN_CLOSED_PNGS < <(compgen -G "$TMP/run-closed-[0-9]*.png")
[[ ${#GOTO_OPEN_PNGS[@]} -eq 2 && ${#GOTO_CLOSED_PNGS[@]} -eq 1 ]] || fail "Go To window lifecycle is incorrect"
[[ ${#RUN_OPEN_PNGS[@]} -eq 2 && ${#RUN_CLOSED_PNGS[@]} -eq 1 ]] || fail "Run window lifecycle is incorrect"
check_png_region_changed "$TMP/goto-before.png" "${GOTO_CLOSED_PNGS[0]}" '1100x620+0+65'
GOTO_DIALOG_PNG=""
RUN_DIALOG_PNG=""
for png in "${GOTO_OPEN_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "516 150" ]] && GOTO_DIALOG_PNG="$png"
done
for png in "${RUN_OPEN_PNGS[@]}"; do
  [[ "$(identify -format '%w %h' "$png")" == "372 160" ]] && RUN_DIALOG_PNG="$png"
done
[[ -n "$GOTO_DIALOG_PNG" && -n "$RUN_DIALOG_PNG" ]] || fail "Go To or Run dialog screenshot is missing"
check_png_region "$GOTO_DIALOG_PNG" '480x120+16+10'
check_png_region "$RUN_DIALOG_PNG" '344x136+14+12'

PRINT_AUTO='35:chord:29,25;43:screenshot-all:'"$TMP/print-dialog-open"';46:click-title:Print,200,290;49:click-title:Print,50,205;52:screenshot-all:'"$TMP/print-dialog-changed"';55:click-title:Print,350,330;68:screenshot:'"$TMP/print.png"
PRINT_OUTPUT="$TMP/printed-document.png"
PRINT_COPY_OUTPUT="$TMP/printed-document-copy-2.png"
PRINT_DOCUMENT="$TMP/raven-print-fixture.txt"
printf 'Raven virtual printer output.\nScintilla text is rasterized to a dedicated page.\nLine three verifies page content.\n' >"$PRINT_DOCUMENT"
RAVEN_PRINT_DIALOG_RESULT= RAVEN_PRINT_OUTPUT="$PRINT_OUTPUT" run_npp "$TMP/print.log" -auto "$PRINT_AUTO" "$NPP" "$PRINT_DOCUMENT" || fail "Print run terminated unexpectedly"
grep -q '\[dialog-window\] created .* size=520x360 title="Print"' "$TMP/print.log" || fail "Print did not open as a separate window"
grep -q '\[dialog-window\] destroyed .*' "$TMP/print.log" || fail "Print did not close after confirmation"
grep -q '\[comdlg32\] PrintDlg accepted flags=0x40106 copies=2 nCopies=1' "$TMP/print.log" || fail "Print dialog did not apply the DEVMODE copies contract"
grep -q '\[comdlg32\] PrintDlg accepted flags=' "$TMP/print.log" || fail "Ctrl+P did not invoke PrintDlgW"
grep -q '\[gdi32\] StartDocW' "$TMP/print.log" || fail "Notepad++ did not start the print document"
grep -q '\[gdi32\] StartPage' "$TMP/print.log" || fail "Notepad++ did not start a print page"
grep -q '\[gdi32\] EndPage' "$TMP/print.log" || fail "Notepad++ did not finish the print page"
grep -q '\[gdi32\] EndDoc' "$TMP/print.log" || fail "Notepad++ did not finish the print document"
PRINT_HDC="$(sed -n 's/.*\[gdi32\] StartPage(\(0x[0-9a-f]*\)).*/\1/p' "$TMP/print.log" | tail -1)"
[[ -n "$PRINT_HDC" ]] || fail "Print HDC was not recorded"
grep -F "ExtTextOut dc=$PRINT_HDC" "$TMP/print.log" | grep -Fq 'text="Raven virtual printer output."' || fail "Print did not rasterize the first expected line"
grep -F "ExtTextOut dc=$PRINT_HDC" "$TMP/print.log" | grep -Fq 'text="Scintilla text is rasterized to a dedicated page."' || fail "Print did not rasterize the second expected line"
grep -F "ExtTextOut dc=$PRINT_HDC" "$TMP/print.log" | grep -Fq 'text="Line three verifies page content."' || fail "Print did not rasterize the third expected line"
check_png "$TMP/print.png"
check_png "$PRINT_OUTPUT"
check_png "$PRINT_COPY_OUTPUT"
check_png_region "$PRINT_OUTPUT" '700x80+40+15'
check_png_region_same "$PRINT_OUTPUT" "$PRINT_COPY_OUTPUT" '1240x1754+0+0'
PRINT_DIALOG_OPEN=""
PRINT_DIALOG_CHANGED=""
for png in "$TMP"/print-dialog-open-*.png; do
  [[ "$(identify -format '%w %h' "$png")" == "520 360" ]] && PRINT_DIALOG_OPEN="$png"
done
for png in "$TMP"/print-dialog-changed-*.png; do
  [[ "$(identify -format '%w %h' "$png")" == "520 360" ]] && PRINT_DIALOG_CHANGED="$png"
done
[[ -n "$PRINT_DIALOG_OPEN" && -n "$PRINT_DIALOG_CHANGED" ]] || fail "Print dialog screenshots are missing"
check_png "$PRINT_DIALOG_OPEN"
check_png "$PRINT_DIALOG_CHANGED"
check_png_region_changed "$PRINT_DIALOG_OPEN" "$PRINT_DIALOG_CHANGED" '210x54+34+170'
check_png_region_changed "$PRINT_DIALOG_OPEN" "$PRINT_DIALOG_CHANGED" '120x30+100+276'

PRINT_CANCEL_AUTO='35:chord:29,25;43:screenshot-all:'"$TMP/print-cancel-open"';46:click-title:Print,450,330;55:screenshot-all:'"$TMP/print-cancel-closed"
RAVEN_PRINT_DIALOG_RESULT= run_npp "$TMP/print-cancel.log" -auto "$PRINT_CANCEL_AUTO" "$NPP" "$PRINT_DOCUMENT" || fail "Print cancellation run terminated unexpectedly"
grep -q '\[comdlg32\] PrintDlg dialog cancelled' "$TMP/print-cancel.log" || fail "Print Cancel did not cancel PrintDlg"
! grep -q '\[gdi32\] StartDoc' "$TMP/print-cancel.log" || fail "Cancelled Print started a document"
mapfile -t PRINT_CANCEL_OPEN_PNGS < <(compgen -G "$TMP/print-cancel-open-[0-9]*.png")
mapfile -t PRINT_CANCEL_CLOSED_PNGS < <(compgen -G "$TMP/print-cancel-closed-[0-9]*.png")
[[ ${#PRINT_CANCEL_OPEN_PNGS[@]} -eq 2 && ${#PRINT_CANCEL_CLOSED_PNGS[@]} -eq 1 ]] || fail "Print Cancel window lifecycle is incorrect"

if grep -qE 'panic:|fatal error:|PE runtime error:|\[cpu-fault\]|\[cpu-recover\]|\[govm\] thread .* crashed:' "$TMP"/*.log; then
  fail "runtime failure detected"
fi

echo "PASS: ReplaceFile, PrintDlg, tab controls, PE32/PE64 dynamic DPI and MessageBox, NPP dialog open, Scintilla paint, multi-document tabs, Find, Find in Files, Replace, Go To, Run, Print, About, Preferences, Style colors, Style Configurator, Save, Reload, Save As, Save a Copy As, Rename, Move to Recycle Bin, new document save, clipboard, Undo, and Redo"
