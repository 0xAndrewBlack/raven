#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/raven-cache.sh || exit 2

go test -race -tags 'guest_windows guest_linux' ./pkg/ntapi \
	-run 'Test(FH4|VirtualUnwind|UnwindStack)' -count=1
go test -race -tags 'guest_windows guest_linux' ./cmd/govm \
	-run 'Test(Cxx|TerminateRtlUnwind)' -count=1
go test -race ./pkg/x64 \
	-run 'TestWindowsContextRoundTripPreservesNonvolatileXMM' -count=1
go test -race -tags 'guest_windows guest_linux' ./pkg/ntapi \
	-run '^TestFH4TypedReferenceCatchUsesCatchableTypes$' -count=20

TMP="$(mktemp -d "$RAVEN_TMPDIR/fh4.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
FH4_FIXTURE_EXE="$TMP/fh4_exception_fixture.exe"
CE_RESPONSE="$TMP/compiler-explorer-response.json"
go run scripts/ce-fh4-fixture.go \
	testdata/dll_fixture/fh4_exception_fixture.cpp \
	"$FH4_FIXTURE_EXE" \
	"$CE_RESPONSE"

LLVM_READOBJ="${LLVM_READOBJ:-/usr/lib/llvm-21/bin/llvm-readobj}"
if [[ ! -x "$LLVM_READOBJ" ]]; then
	echo "required LLVM PE inspector is unavailable: $LLVM_READOBJ" >&2
	exit 2
fi
"$LLVM_READOBJ" --file-headers "$FH4_FIXTURE_EXE" |
	grep -q 'Format: COFF-x86-64'
IMPORTS="$("$LLVM_READOBJ" --coff-imports "$FH4_FIXTURE_EXE")"
grep -q 'Symbol: __CxxFrameHandler4' <<<"$IMPORTS"
UNWIND="$("$LLVM_READOBJ" --unwind "$FH4_FIXTURE_EXE")"
grep -q 'ExceptionHandler' <<<"$UNWIND"

RAVEN="${RAVEN:-$TMP/raven}"
if [[ ! -x "$RAVEN" ]]; then
	go build -tags guest_windows -o "$RAVEN" ./cmd/govm
fi
LOG="$TMP/fh4-fixture.log"
timeout --foreground --kill-after=3s 30s \
	"$RAVEN" -wayland=false "$FH4_FIXTURE_EXE" >"$LOG" 2>&1
grep -q '\[win32\] ExitProcess(0)' "$LOG"
if grep -Eq '\[cpu-fault\]|PE runtime error|terminated with unwind failed' "$LOG"; then
	cat "$LOG"
	exit 1
fi

echo "MSVC FH4 executable and table regressions: PASS"
