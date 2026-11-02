#!/usr/bin/env bash
# HTTP plumbing for the lab bootstrap and the check/solve scripts. Source it; it sets no shell options.
# Bash 3.2 compatible (the dev machine) as well as 5.x (the VM). Needs curl and jq.
#
# Environment: KIBANA_URL, ELASTICSEARCH_URL, ELASTICSEARCH_AUTH_BASE64 (see load_env).
# The Authorization header is fed to curl on stdin (-K -), never on its command line, so it cannot
# show up in `ps`, error echoes or logs.

# Header Kibana requires on internal APIs. Spike item 8 confirms the value.
KBN_ORIGIN_HEADER="x-elastic-internal-origin: Kibana"

LAST_STATUS=""
LAST_BODY=""

log() {
  printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2
}

die() {
  printf 'ERROR: %s: %s\n' "$1" "${2-}" >&2
  if [ "${LIB_NO_EXIT:-0}" = "1" ]; then return 1; fi
  exit 1
}

require_tools() {
  local tool
  for tool in curl jq python3 git; do
    command -v "$tool" >/dev/null 2>&1 || die tools "$tool is required but not installed"
  done
}

load_env() {
  local file="${1:-/home/kubernetes-vm/env}" var
  if [ -f "$file" ]; then
    # shellcheck disable=SC1090
    . "$file"
  fi
  for var in KIBANA_URL ELASTICSEARCH_URL ELASTICSEARCH_AUTH_BASE64; do
    eval "[ -n \"\${$var:-}\" ]" || { die env "$var is not set (looked in $file)"; return 1; }
  done
  export KIBANA_URL ELASTICSEARCH_URL ELASTICSEARCH_AUTH_BASE64
}

_auth_config() {
  printf 'header = "Authorization: Basic %s"\n' "$ELASTICSEARCH_AUTH_BASE64"
}

# _http <base-url> <method> <path> <body|@file|""> <content-type> <kibana:0|1>
# Sets LAST_STATUS and LAST_BODY. Returns 22 on HTTP >= 400 or a transport failure.
_http() {
  local base="$1" method="$2" path="$3" body="${4-}" ctype="$5" kibana="$6"
  local out code
  out="$(mktemp)"
  local args=(-sS -m "${CURL_MAX_TIME:-120}" --connect-timeout 10 -o "$out" -w '%{http_code}' -X "$method" -K - -H "Content-Type: $ctype")
  if [ "$kibana" = "1" ]; then
    args=("${args[@]}" -H "kbn-xsrf: true" -H "$KBN_ORIGIN_HEADER")
  fi
  if [ -n "$body" ]; then
    args=("${args[@]}" --data-binary "$body")
  fi
  code="$(_auth_config | curl "${args[@]}" "${base}${path}")" || code="000"
  LAST_STATUS="$code"
  LAST_BODY="$(cat "$out")"
  rm -f "$out"
  case "$code" in
    [23]??) return 0 ;;
  esac
  case ",${QUIET_STATUS:-}," in *",$code,"*) return 22 ;; esac # a status the caller expects (e.g. 409)
  printf 'ERROR: HTTP %s %s %s: %s\n' "$code" "$method" "$path" "$(printf '%s' "$LAST_BODY" | head -c 300)" >&2
  return 22
}

kbn_api() {
  _http "$KIBANA_URL" "$1" "$2" "${3-}" "application/json" 1 || return $?
  printf '%s\n' "$LAST_BODY"
}

es_api() {
  _http "$ELASTICSEARCH_URL" "$1" "$2" "${3-}" "application/json" 0 || return $?
  printf '%s\n' "$LAST_BODY"
}

wait_for_kibana() {
  local timeout="${1:-${WAIT_KIBANA_TIMEOUT:-300}}" start="$SECONDS" level
  while :; do
    level="$(_auth_config | curl -s -m 5 -K - "$KIBANA_URL/api/status" 2>/dev/null |
      jq -r '.status.overall.level // empty' 2>/dev/null)" || level=""
    [ "$level" = "available" ] && return 0
    if [ $((SECONDS - start)) -ge "$timeout" ]; then
      die kibana "not available after ${timeout}s (last level: ${level:-no answer})"
      return 1
    fi
    sleep "${WAIT_INTERVAL:-2}"
  done
}

# es_bulk <data-stream-or-index> <ndjson-file>; BULK_QUERY (e.g. pipeline=_none) is appended when set.
es_bulk() {
  local target="$1" file="$2" reason count
  CURL_MAX_TIME="${CURL_MAX_TIME:-300}" _http "$ELASTICSEARCH_URL" POST "/${target}/_bulk${BULK_QUERY:+?$BULK_QUERY}" "@${file}" \
    "application/x-ndjson" 0 || die bulk "$target: request failed"
  if [ "$(printf '%s' "$LAST_BODY" | jq -r '.errors')" = "true" ]; then
    reason="$(printf '%s' "$LAST_BODY" |
      jq -r '[.items[] | to_entries[0].value.error.reason // empty][0] // "unknown error"')"
    die bulk "$target: $reason"
    return 1
  fi
  count="$(printf '%s' "$LAST_BODY" | jq -r '.items | length')"
  printf 'loaded %s docs into %s\n' "$count" "$target"
}
