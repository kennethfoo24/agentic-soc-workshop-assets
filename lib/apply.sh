#!/usr/bin/env bash
# One apply_* function per kind of lab content. Source it; it sets no shell options.
# Every function is idempotent: "already exists" (409) is success, anything else is a failure.
# Endpoint paths below are the spike's open questions (items 6, 7, 8, 10, 11); the values are the best-known
# ones and this block is the one place to change them.

RULES_PATH=/api/detection_engine/rules
TOOLS_PATH=/api/agent_builder/tools
AGENTS_PATH=/api/agent_builder/agents
SKILLS_PATH=/api/agent_builder/skills
WORKFLOWS_PATH=/api/workflows/workflow      # create (POST) and update (PUT <path>/<id>)
WORKFLOWS_LIST_PATH=/api/workflows          # GET -> {"results":[{"id","name"},...]}
CONNECTORS_PATH=/api/actions/connector
CONNECTORS_LIST_PATH=/api/actions/connectors
SETTINGS_PATH=/internal/kibana/settings
EPM_PATH=/api/fleet/epm/packages
SIGNALS_SEARCH_PATH=/api/detection_engine/signals/search

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "$_LIB_DIR/.." && pwd)}"
# shellcheck source=lib/kibana.sh
. "$_LIB_DIR/kibana.sh"

# substitute <file>: print the file with __LLM_CONNECTOR_ID__, __EMAIL_CONNECTOR_ID__ and
# __ESCALATION_WORKFLOW_ID__ replaced from the environment. A placeholder with no value, or one this
# function does not know, is an error. Python does the replacing so ids containing / or & are safe.
substitute() {
  python3 - "$1" <<'PY'
import os, re, sys

text = open(sys.argv[1]).read()
known = {
    "__LLM_CONNECTOR_ID__": "LLM_CONNECTOR_ID",
    "__EMAIL_CONNECTOR_ID__": "EMAIL_CONNECTOR_ID",
    "__ESCALATION_WORKFLOW_ID__": "ESCALATION_WORKFLOW_ID",
}
for placeholder, var in known.items():
    if placeholder in text:
        value = os.environ.get(var, "")
        if not value:
            sys.exit(f"ERROR: substitute: {placeholder} in {sys.argv[1]} needs ${var}, which is not set")
        text = text.replace(placeholder, value)
left = re.findall(r"__[A-Z][A-Z_]*__", text)
if left:
    sys.exit(f"ERROR: substitute: unknown placeholder {left[0]} in {sys.argv[1]}")
sys.stdout.write(text)
PY
}

# _valid_id <id>: a create response that lacked an id yields "" or the string "null".
_valid_id() { [ -n "$1" ] && [ "$1" != "null" ]; }

# _last <chars>: the start of the last response, for timeout messages.
_last() { printf 'last answer: HTTP %s %s' "${LAST_STATUS:-none}" "$(printf '%s' "$LAST_BODY" | head -c "$1")"; }

# _upsert <collection-path> <id> <json-body>: POST, and on 409 PUT <collection-path>/<id> without the id.
_upsert() {
  local path="$1" id="$2" body="$3"
  QUIET_STATUS=409 kbn_api POST "$path" "$body" >/dev/null && return 0
  [ "$LAST_STATUS" = "409" ] || return 1
  kbn_api PUT "$path/$id" "$(printf '%s' "$body" | jq -c 'del(.id)')" >/dev/null
}

apply_index_templates() {
  local file name
  for file in "$REPO_DIR"/kibana/index-templates/*.json; do
    name="$(basename "$file" .json)"
    es_api PUT "/_index_template/$name" "@$file" >/dev/null || die templates "$name"
    log "index template $name"
  done
}

install_packages() {
  local pkg
  for pkg in system endpoint network_traffic; do
    CURL_MAX_TIME="${CURL_MAX_TIME:-300}" QUIET_STATUS=409 kbn_api POST "$EPM_PATH/$pkg" '{"force":true}' >/dev/null ||
      [ "$LAST_STATUS" = "409" ] || die packages "installing $pkg failed"
    log "package $pkg installed"
  done
}

# load_dataset <dir>: bulk each <dir>/*.ndjson into the data stream named after the file. A stream that already
# holds exactly the file's documents is skipped, so a re-run does not double the data; one holding a different
# number (an interrupted load) is deleted and loaded again.
load_dataset() {
  local dir="$1" file stream expected current
  for file in "$dir"/*.ndjson; do
    stream="$(basename "$file" .ndjson)"
    expected=$(($(wc -l <"$file") / 2))
    current=0
    if QUIET_STATUS=404 es_api GET "/$stream/_count" >/dev/null; then
      current="$(printf '%s' "$LAST_BODY" | jq '.count // 0')"
    fi
    if [ "$current" -eq "$expected" ]; then
      log "$stream already holds $current docs, skipping"
      continue
    fi
    if [ "$current" -gt 0 ]; then
      log "$stream holds $current of $expected docs, reloading"
      QUIET_STATUS=404 es_api DELETE "/_data_stream/$stream" >/dev/null || [ "$LAST_STATUS" = "404" ] ||
        die dataset "could not delete $stream"
    fi
    if [ "${BULK_PIPELINE_NONE:-0}" = "1" ]; then
      BULK_QUERY="pipeline=_none" es_bulk "$stream" "$file" || return 1
    else
      BULK_QUERY="" es_bulk "$stream" "$file" || return 1
    fi
  done
}

apply_lookups() {
  local dir="$1" file index
  apply_index_templates || return 1
  for file in "$dir"/lookup/*.ndjson; do
    index="$(basename "$file" .ndjson)"
    BULK_QUERY="" es_bulk "$index" "$file" || return 1
  done
}

apply_rules() {
  local file expected timeout start enabled=0
  expected="$(ls "$REPO_DIR"/kibana/rules/*.json | wc -l | tr -d ' ')"
  for file in "$REPO_DIR"/kibana/rules/*.json; do
    if ! QUIET_STATUS=409 kbn_api POST "$RULES_PATH" "@$file" >/dev/null; then
      [ "$LAST_STATUS" = "409" ] || die rules "creating $(basename "$file") failed"
      kbn_api PUT "$RULES_PATH" "@$file" >/dev/null || die rules "updating $(basename "$file") failed"
    fi
  done
  timeout="${RULES_ENABLED_TIMEOUT:-60}"
  start="$SECONDS"
  while :; do
    if kbn_api GET "$RULES_PATH/_find?per_page=100&filter=alert.attributes.tags:%22Elastibank%20Lab%22" >/dev/null 2>&1; then
      enabled="$(printf '%s' "$LAST_BODY" | jq '[.data[]? | select(.enabled)] | length' 2>/dev/null)" || enabled=0
    fi
    [ "$enabled" -ge "$expected" ] && { log "$enabled rules enabled"; return 0; }
    if [ $((SECONDS - start)) -ge "$timeout" ]; then
      die rules "$enabled of $expected rules enabled after ${timeout}s ($(_last 100))"
      return 1
    fi
    sleep "${WAIT_INTERVAL:-2}"
  done
}

find_llm_connector() {
  local id
  kbn_api GET "$CONNECTORS_LIST_PATH" >/dev/null || die "llm connector" "could not list connectors"
  id="$(printf '%s' "$LAST_BODY" | jq -r '[.[]? | select(.connector_type_id == ".gen-ai") | .id][0] // empty')"
  [ -n "$id" ] || die "llm connector" "no .gen-ai connector found; did elastic-llm.sh run?" || return 1
  LLM_CONNECTOR_ID="$id"
  export LLM_CONNECTOR_ID
  log "llm connector $LLM_CONNECTOR_ID"
}

# create_email_connector <smtp-host> <smtp-port>
create_email_connector() {
  local host="$1" port="$2" id body
  kbn_api GET "$CONNECTORS_LIST_PATH" >/dev/null || die connectors "could not list connectors"
  id="$(printf '%s' "$LAST_BODY" | jq -r '[.[]? | select(.name == "Elastibank Mailpit") | .id][0] // empty')"
  if [ -z "$id" ]; then
    body="$(jq -nc --arg h "$host" --argjson p "$port" '{
      name: "Elastibank Mailpit", connector_type_id: ".email",
      config: {from: "soc@elastibank.example", host: $h, port: $p, secure: false, hasAuth: false, service: "other"},
      secrets: {}}')"
    kbn_api POST "$CONNECTORS_PATH" "$body" >/dev/null || die connectors "creating the email connector failed"
    id="$(printf '%s' "$LAST_BODY" | jq -r '.id')"
    _valid_id "$id" || { die connectors "the create response had no id: $(printf '%s' "$LAST_BODY" | head -c 100)"; return 1; }
  fi
  EMAIL_CONNECTOR_ID="$id"
  export EMAIL_CONNECTOR_ID
  log "email connector $EMAIL_CONNECTOR_ID"
}

apply_settings() {
  local body
  body="$(substitute "$REPO_DIR/kibana/settings.json" | jq -c '{changes: .}')" || return 1
  kbn_api POST "$SETTINGS_PATH" "$body" >/dev/null || die settings "applying advanced settings failed"
  log "advanced settings applied"
}

# Only the ES|QL tools; the workflow tool needs the workflow id, so apply_workflows posts it.
apply_tools() {
  local file id
  for file in "$REPO_DIR"/kibana/tools/*.json; do
    jq -e '.type == "esql"' "$file" >/dev/null || continue
    id="$(jq -r .id "$file")"
    _upsert "$TOOLS_PATH" "$id" "$(jq -c . "$file")" || { die tools "$id failed"; return 1; }
    log "tool $id"
  done
}

apply_skill() {
  local md="$REPO_DIR/kibana/skills/elastibank-org-context.md" meta="$REPO_DIR/kibana/skills/elastibank-org-context.meta.json" body
  body="$(jq -nc --rawfile content "$md" --slurpfile meta "$meta" '$meta[0] + {content: $content}')"
  _upsert "$SKILLS_PATH" "$(jq -r .id "$meta")" "$body" || { die skill "elastibank-org-context failed"; return 1; }
  log "skill elastibank-org-context"
}

apply_workflows() {
  local list name yaml id body tool
  kbn_api GET "$WORKFLOWS_LIST_PATH" >/dev/null || die workflows "could not list workflows"
  list="$LAST_BODY"
  for name in escalation-email soc-autopilot; do
    yaml="$(substitute "$REPO_DIR/kibana/workflows/$name.yaml")" || return 1
    body="$(jq -nc --arg y "$yaml" '{yaml: $y}')"
    id="$(printf '%s' "$list" | jq -r --arg n "$name" '[.results[]? | select(.name == $n) | .id][0] // empty')"
    if [ -n "$id" ]; then
      kbn_api PUT "$WORKFLOWS_PATH/$id" "$body" >/dev/null || die workflows "updating $name failed"
    else
      kbn_api POST "$WORKFLOWS_PATH" "$body" >/dev/null || die workflows "creating $name failed"
      id="$(printf '%s' "$LAST_BODY" | jq -r '.id')"
      _valid_id "$id" || { die workflows "creating $name returned no id: $(printf '%s' "$LAST_BODY" | head -c 100)"; return 1; }
    fi
    [ "$name" = "escalation-email" ] && { ESCALATION_WORKFLOW_ID="$id"; export ESCALATION_WORKFLOW_ID; }
    log "workflow $name ($id)"
  done
  tool="$(substitute "$REPO_DIR/kibana/tools/elastibank-escalation-email.json" | jq -c .)" || return 1
  _upsert "$TOOLS_PATH" elastibank-escalation-email "$tool" || die tools "elastibank-escalation-email failed"
}

apply_agent() {
  _upsert "$AGENTS_PATH" elastibank-soc-analyst "$(jq -c . "$REPO_DIR/kibana/agents/elastibank-soc-analyst.json")" ||
    { die agent "elastibank-soc-analyst failed"; return 1; }
  log "agent elastibank-soc-analyst"
}

# wait_for_alerts <min> [timeout_s=180]
wait_for_alerts() {
  local min="$1" timeout="${2:-180}" start="$SECONDS" count=0
  while :; do
    if kbn_api POST "$SIGNALS_SEARCH_PATH" '{"size":0,"track_total_hits":true,"query":{"match_all":{}}}' >/dev/null 2>&1; then
      count="$(printf '%s' "$LAST_BODY" | jq '(.hits.total.value // .hits.total // 0)' 2>/dev/null)" || count=0
    fi
    [ "$count" -ge "$min" ] && { log "$count alerts"; return 0; }
    if [ $((SECONDS - start)) -ge "$timeout" ]; then
      die alerts "$count of $min alerts after ${timeout}s ($(_last 100))"
      return 1
    fi
    sleep "${WAIT_INTERVAL:-2}"
  done
}
