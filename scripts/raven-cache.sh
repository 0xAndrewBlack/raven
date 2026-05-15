#!/usr/bin/env bash

raven_cache_error() {
	echo "$1" >&2
	return 2
}

if [[ -z "${HOME:-}" ]]; then
	raven_cache_error "HOME is required for Raven cache isolation" || return 2 2>/dev/null || exit 2
fi
RAVEN_HOME="$(realpath -m -- "$HOME")" ||
	{ raven_cache_error "could not resolve HOME" || return 2 2>/dev/null || exit 2; }
cache_home="${XDG_CACHE_HOME:-$RAVEN_HOME/.cache}"
RAVEN_CACHE_ROOT="$(realpath -m -- "${RAVEN_CACHE_ROOT:-$cache_home/raven}")" ||
	{ raven_cache_error "could not resolve RAVEN_CACHE_ROOT" || return 2 2>/dev/null || exit 2; }
case "$RAVEN_CACHE_ROOT/" in
"$RAVEN_HOME"/*) ;;
*)
	raven_cache_error "RAVEN_CACHE_ROOT must stay under HOME" ||
		return 2 2>/dev/null || exit 2
	;;
esac

RAVEN_TMPDIR="${RAVEN_TMPDIR:-$RAVEN_CACHE_ROOT/tmp}"
RAVEN_GOTMPDIR="${RAVEN_GOTMPDIR:-$RAVEN_CACHE_ROOT/go-tmp}"
RAVEN_RUNTIME_ROOT="${RAVEN_RUNTIME_ROOT:-$RAVEN_CACHE_ROOT/runtime}"
RAVEN_ARTIFACT_ROOT="${RAVEN_ARTIFACT_ROOT:-$RAVEN_CACHE_ROOT/artifacts}"
for variable in RAVEN_TMPDIR RAVEN_GOTMPDIR RAVEN_RUNTIME_ROOT RAVEN_ARTIFACT_ROOT; do
	value="$(realpath -m -- "${!variable}")" ||
		{ raven_cache_error "could not resolve $variable" || return 2 2>/dev/null || exit 2; }
	case "$value/" in
	"$RAVEN_CACHE_ROOT"/*) printf -v "$variable" '%s' "$value" ;;
	*)
		raven_cache_error "$variable must stay under RAVEN_CACHE_ROOT" ||
			return 2 2>/dev/null || exit 2
		;;
	esac
done
RAVEN_LABWC_RUNTIME_FILE="$RAVEN_RUNTIME_ROOT/labwc.path"

if ! mkdir -p "$RAVEN_TMPDIR" "$RAVEN_GOTMPDIR" "$RAVEN_RUNTIME_ROOT" "$RAVEN_ARTIFACT_ROOT"; then
	raven_cache_error "could not create Raven cache directories" ||
		return 2 2>/dev/null || exit 2
fi
if ! chmod 700 "$RAVEN_RUNTIME_ROOT"; then
	raven_cache_error "could not secure Raven runtime directory" ||
		return 2 2>/dev/null || exit 2
fi

export TMPDIR="$RAVEN_TMPDIR"
export GOTMPDIR="$RAVEN_GOTMPDIR"
export RAVEN_CACHE_ROOT RAVEN_TMPDIR RAVEN_GOTMPDIR
export RAVEN_RUNTIME_ROOT RAVEN_ARTIFACT_ROOT RAVEN_LABWC_RUNTIME_FILE

raven_prune_owned_runs() {
	local root="$1"
	local marker="$2"
	local keep="${3:-5}"
	local count=0
	local resolved run timestamp

	resolved="$(realpath -m -- "$root")" || return 2
	case "$resolved/" in
	"$RAVEN_ARTIFACT_ROOT"/*) ;;
	*) return 2 ;;
	esac
	[[ "$marker" != */* && "$keep" =~ ^[1-9][0-9]*$ ]] || return 2
	while read -r timestamp run; do
		[[ -n "$timestamp" && -n "$run" && -f "$run/$marker" ]] || continue
		count=$((count + 1))
		((count <= keep)) && continue
		[[ "$(realpath -m -- "$run")/" == "$resolved"/* ]] || return 2
		rm -rf -- "$run"
	done < <(find "$resolved" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr)
}
