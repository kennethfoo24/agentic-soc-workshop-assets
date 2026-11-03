#!/usr/bin/env bash
# Diagnostics for the lab VM, written to the bootstrap log, so the first live run records the real API shapes (the
# spike). Source it; it sets no shell options. Read-only except probe_mail, which sends one message to the lab's own
# inbox. Never prints credentials or environment values (only variable names).

_PRB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/apply.sh
. "$_PRB_DIR/apply.sh"
MAILPIT_URL="${MAILPIT_URL:-http://127.0.0.1:8025}"

# probe_get <kibana|es> <path> [<max-body-chars>]: one line, "<who> <path> -> <status> <start of the body>".
probe_get() {
  local who="$1" path="$2" chars="${3:-${PROBE_BODY_CHARS:-500}}" fn=kbn_api
  [ "$who" = "es" ] && fn=es_api
  QUIET_STATUS="400,401,403,404,405,409,500,501,502,503" "$fn" GET "$path" >/dev/null 2>&1 || true
  printf '%s %s -> %s %s\n' "$who" "$path" "${LAST_STATUS:-none}" "$(printf '%s' "$LAST_BODY" | tr '\n' ' ' | cut -c1-"$chars")"
}

probe_environment() {
  local LIB_NO_EXIT=1 file="${PROBE_ENV_FILE:-/home/kubernetes-vm/env}" tool tools=""
  for tool in jq git curl unzip python3; do command -v "$tool" >/dev/null 2>&1 && tools="$tools $tool"; done
  log "probe: host $(hostname); $(python3 --version 2>&1); tools:$tools"
  log "probe: /opt/workshops: $(ls /opt/workshops 2>/dev/null | tr '\n' ' ')"
  if [ -f "$file" ]; then
    log "probe: env file variable names: $(sed -nE 's/^(export )?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p' "$file" | tr '\n' ' ')"
  else
    log "probe: no env file at $file"
  fi
  load_env "$file" >/dev/null 2>&1 || { log "probe: could not load the environment, stopping the probe"; return 0; }
  # Where is Kibana reachable from outside? (credentials in a URL are redacted)
  local name value
  for name in KIBANA_URL KIBANA_URL_UI KIBANA_URL_LOCAL KIBANA_URL_ELASTIC_LAB ELASTICSEARCH_URL; do
    eval "value=\"\${$name:-}\""
    log "probe: $name=$(printf '%s' "$value" | sed -E 's#(://)[^/@]*@#\1***@#')"
  done
  log "probe: kibana login (training) -> HTTP $(curl -sk -m 8 -o /dev/null -w '%{http_code}' -u training:nonprodpwd "${KIBANA_URL:-http://127.0.0.1}/api/status" 2>/dev/null || echo none)"
  log "probe: kibana on local 443 -> HTTP $(curl -sk -m 8 -o /dev/null -w '%{http_code}' https://127.0.0.1:443/ 2>/dev/null || echo none)"
  log "probe: listening ports: $( (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | awk 'NR>1 {n=split($4,a,":"); print a[n]}' | sort -un | tr '\n' ' ')"
  if command -v kubectl >/dev/null 2>&1; then
    log "probe: kubernetes service ports: $(kubectl get svc -A --no-headers 2>&1 | awk '{print $1"/"$2" "$3" "$6}' | tr '\n' ';' | cut -c1-1800)"
    log "probe: kubernetes ingress: $(kubectl get ingress -A --no-headers 2>&1 | tr -s ' ' | tr '\n' ';' | cut -c1-800)"
  else
    log "probe: kubernetes services: kubectl not available"
  fi
  local line
  while IFS= read -r line; do
    log "probe: $line"
  done <<EOF2
$(probe_get es /_license 400)
$(probe_get es /_cluster/health 300)
$(probe_get kibana /api/status 200)
$(probe_get kibana /internal/kibana/settings 700)
$(probe_get kibana /api/actions/connectors 700)
$(probe_get kibana /api/agent_builder/tools 1400)
$(probe_get kibana /api/agent_builder/agents 1400)
$(probe_get kibana /api/agent_builder/skills 500)
$(probe_get kibana /api/agent_builder/conversations 400)
$(probe_get kibana /api/workflows 500)
$(probe_get kibana /api/workflows/workflow 300)
$(probe_get kibana "/api/cases/_find?perPage=1" 400)
$(probe_get kibana "/api/detection_engine/rules/_find?per_page=1" 200)
$(probe_get kibana /api/fleet/epm/packages/system 200)
$(probe_get kibana /api/attack_discovery/_find 400)
EOF2
  return 0
}

# probe_mail: runs the lab's email connector once and counts what reached the inbox (is Mailpit reachable from Kibana?).
probe_mail() {
  local LIB_NO_EXIT=1 id total
  kbn_api GET "$CONNECTORS_LIST_PATH" >/dev/null 2>&1 || true
  id="$(printf '%s' "$LAST_BODY" | jq -r '[.[]? | select(.name == "Elastibank Mailpit") | .id][0] // empty' 2>/dev/null)"
  if [ -z "$id" ]; then
    log "probe: no Elastibank Mailpit connector to execute"
    return 0
  fi
  QUIET_STATUS="400,404,500,502,503" kbn_api POST "$CONNECTORS_PATH/$id/_execute" \
    '{"params":{"to":["probe@elastibank.example"],"subject":"probe","message":"probe"}}' >/dev/null 2>&1 || true
  log "probe: email execute -> $LAST_STATUS $(printf '%s' "$LAST_BODY" | tr '\n' ' ' | cut -c1-300)"
  sleep "${PROBE_MAIL_WAIT:-2}"
  total="$(curl -sS -m 5 "$MAILPIT_URL/api/v1/messages" 2>/dev/null | jq -r '.total // "unknown"' 2>/dev/null)" || total="unreachable"
  log "probe: inbox total=${total:-unreachable}"
  return 0
}
