#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$root_dir/scripts/raven-cache.sh" || exit 2
format=json
baseline=
hotness=
out_path=
max_regression=
max_starts=${RAVEN_NATIVE_JIT_MAX_STARTS:-20000}

fail_arg() { printf 'error: %s\n' "$1" >&2; exit 2; }
is_positive_int() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
is_nonnegative_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

while (($#)); do
	case "$1" in
		--json) format=json ;;
		--text) format=text ;;
		--baseline) (($# >= 2)) || fail_arg '--baseline requires a path'; baseline=$2; shift; [[ -f "$baseline" ]] || fail_arg "baseline file not found: $baseline" ;;
		--hotness) (($# >= 2)) || fail_arg '--hotness requires a path'; hotness=$2; shift; [[ -f "$hotness" ]] || fail_arg "hotness file not found: $hotness" ;;
		--out) (($# >= 2)) || fail_arg '--out requires a path'; out_path=$2; shift ;;
		--max-regression-pp) (($# >= 2)) || fail_arg '--max-regression-pp requires a value'; max_regression=$2; shift; is_nonnegative_int "$max_regression" || fail_arg "max regression pp must be a nonnegative integer: $max_regression" ;;
		--max-starts) (($# >= 2)) || fail_arg '--max-starts requires a value'; max_starts=$2; shift; is_positive_int "$max_starts" || fail_arg "max starts must be a positive integer: $max_starts" ;;
		-h|--help)
			printf '%s\n' 'usage: scripts/native-jit-coverage.sh [--json|--text] [--out PATH] [--baseline FILE] [--hotness FILE] [--max-regression-pp N] [--max-starts N]'
			printf '%s\n' 'hotness format: FIXTURE ADDRESS COUNT'
			exit 0
			;;
		*) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
	esac
	shift
done

is_positive_int "$max_starts" || fail_arg "max starts must be a positive integer: $max_starts"
if [[ -n "$max_regression" ]]; then
	is_nonnegative_int "$max_regression" || fail_arg "max regression pp must be a nonnegative integer: $max_regression"
	[[ -n "$baseline" ]] || fail_arg '--max-regression-pp requires --baseline'
fi

if [[ -n "$out_path" ]]; then
	out=$out_path
	cleanup_out=
else
	out=$(mktemp "$RAVEN_TMPDIR/native-jit-coverage.XXXXXX")
	cleanup_out=$out
fi
log=$(mktemp "$RAVEN_TMPDIR/native-jit-coverage-log.XXXXXX")
trap 'rm -f "$cleanup_out" "$log"' EXIT
if [[ -n "$baseline" ]]; then
	baseline=$(cd "$(dirname "$baseline")" && pwd)/$(basename "$baseline")
fi
env_args=(
	RAVEN_NATIVE_JIT_COVERAGE=1
	RAVEN_NATIVE_JIT_OUT="$out"
	RAVEN_NATIVE_JIT_FORMAT="$format"
	RAVEN_NATIVE_JIT_MAX_STARTS="$max_starts"
	RAVEN_NATIVE_JIT_HOTNESS="$hotness"
)
if [[ -n "$baseline" ]]; then env_args+=(RAVEN_NATIVE_JIT_BASELINE="$baseline"); fi
if [[ -n "$max_regression" ]]; then env_args+=(RAVEN_NATIVE_JIT_MAX_REGRESSION_PP="$max_regression"); fi

(
	cd "$root_dir"
	if ! env "${env_args[@]}" go test ./pkg/jit -run '^TestNativeJITCoverageReport$' -count=1 -timeout=10m >"$log" 2>&1; then
		cat "$log" >&2
		exit 1
	fi
)
cat "$out"
