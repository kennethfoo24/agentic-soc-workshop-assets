#!/usr/bin/env bash
# Creates, through the API, the objects the challenge steps have the student create. Source it; it sets no shell
# options. solve_open_case and solve_create_rule are idempotent on their own. solve_run_workflow, solve_ask_agent
# and solve_run_attack_discovery each make something new on every call, so a challenge's solve script guards them
# with the matching check (the check is the definition of "already done").
# Endpoint paths below are spike item 11; this block is the one place to change them.

CASES_PATH=/api/cases
WORKFLOW_RUN_PATH_FMT=/api/workflows/workflow/%s/run
WORKFLOW_EXEC_PATH_FMT=/api/workflows/executions/%s
CONVERSE_PATH=/api/agent_builder/converse
AD_GENERATE_PATH=/api/attack_discovery/_generate

_SLV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/checks.sh
. "$_SLV_DIR/checks.sh"

solve_init() {
  LIB_NO_EXIT=1
  load_env || return 1
}

# solve_run_workflow <name> [<json-inputs>]: runs the workflow and waits for it to finish.
solve_run_workflow() {
  local name="$1" inputs="${2:-}" id exec_id body status start timeout path
  [ -n "$inputs" ] || inputs='{}'
  kbn_api GET "$WORKFLOWS_LIST_PATH" >/dev/null || { die solve "could not list workflows"; return 1; }
  id="$(printf '%s' "$LAST_BODY" | jq -r --arg n "$name" '[.results[]? | select(.name == $n) | .id][0] // empty')"
  [ -n "$id" ] || { die solve "no workflow named $name"; return 1; }
  body="$(jq -nc --argjson i "$inputs" '{inputs: $i}')" || { die solve "inputs for $name are not valid JSON"; return 1; }
  # shellcheck disable=SC2059
  path="$(printf "$WORKFLOW_RUN_PATH_FMT" "$id")"
  kbn_api POST "$path" "$body" >/dev/null || { die solve "running $name failed"; return 1; }
  exec_id="$(printf '%s' "$LAST_BODY" | jq -r '.workflowExecutionId // .workflow_execution_id // .id // empty')"
  _valid_id "$exec_id" || { die solve "running $name returned no execution id ($(_last 100))"; return 1; }
  timeout="${WORKFLOW_WAIT_TIMEOUT:-420}"
  start="$SECONDS"
  while :; do
    # shellcheck disable=SC2059
    path="$(printf "$WORKFLOW_EXEC_PATH_FMT" "$exec_id")"
    if kbn_api GET "$path" >/dev/null 2>&1; then
      status="$(printf '%s' "$LAST_BODY" | jq -r '.status // empty')"
      case "$status" in
        completed) return 0 ;;
        failed | cancelled | timed_out) die solve "workflow $name ended as $status ($(_last 200))"; return 1 ;;
      esac
    fi
    if [ $((SECONDS - start)) -ge "$timeout" ]; then
      die solve "workflow $name did not finish within ${timeout}s ($(_last 100))"
      return 1
    fi
    sleep "${WAIT_INTERVAL:-2}"
  done
}

solve_run_attack_discovery() {
  local body timeout start fields
  find_llm_connector || return 1
  # The generate call requires anonymizationFields; the docs fetch them from the AI Assistant API first.
  fields='[]'
  if kbn_api GET "/api/security_ai_assistant/anonymization_fields/_find?per_page=1000" >/dev/null 2>&1; then
    fields="$(printf '%s' "$LAST_BODY" | jq -c '.data // []' 2>/dev/null)" || fields='[]'
  fi
  body="$(jq -nc --arg c "$LLM_CONNECTOR_ID" --argjson f "$fields" '{
    alertsIndexPattern: ".alerts-security.alerts-default", anonymizationFields: $f,
    apiConfig: {connectorId: $c, actionTypeId: ".gen-ai"}, subAction: "invokeAI", size: 100, start: "now-72h", end: "now"}')"
  if ! CURL_MAX_TIME=120 kbn_api POST "$AD_GENERATE_PATH" "$body" >/dev/null; then
    # The generate call's body is not in the public docs. The autopilot workflow's first step runs Attack Discovery too.
    log "generate call rejected (HTTP ${LAST_STATUS:-none}: $(printf '%s' "$LAST_BODY" | head -c 700)); running soc-autopilot instead"
    solve_run_workflow soc-autopilot || return 1
  fi
  timeout="${AD_WAIT_TIMEOUT:-240}"
  start="$SECONDS"
  while [ "$(_ad_count)" -lt 1 ]; do
    if [ $((SECONDS - start)) -ge "$timeout" ]; then
      die solve "no attack discovery appeared within ${timeout}s"
      return 1
    fi
    sleep "${WAIT_INTERVAL:-2}"
  done
}

# solve_ask_agent <agent-id> <prompt>
solve_ask_agent() {
  local body
  body="$(jq -nc --arg a "$1" --arg p "$2" '{agent_id: $a, input: $p}')"
  CURL_MAX_TIME="${CONVERSE_MAX_TIME:-240}" kbn_api POST "$CONVERSE_PATH" "$body" >/dev/null ||
    { die solve "asking agent $1 failed"; return 1; }
}

# solve_open_case <title> <severity> <description> [<tag>...]
solve_open_case() {
  local title="$1" severity="$2" description="$3" tags body n
  shift 3
  if [ $# -eq 0 ]; then tags='[]'; else tags="$(printf '%s\n' "$@" | jq -R . | jq -sc .)"; fi
  kbn_api GET "$CASES_FIND_PATH?perPage=100" >/dev/null || { die solve "could not list cases"; return 1; }
  n="$(printf '%s' "$LAST_BODY" | jq --arg t "$title" '[.cases[]? | select(.title == $t)] | length')"
  [ "$n" -ge 1 ] && return 0
  body="$(jq -nc --arg t "$title" --arg d "$description" --arg s "$severity" --argjson tags "$tags" '{
    title: $t, description: $d, severity: $s, tags: $tags, owner: "securitySolution",
    connector: {id: "none", name: "none", type: ".none", fields: null}, settings: {syncAlerts: false}}')"
  kbn_api POST "$CASES_PATH" "$body" >/dev/null || { die solve "creating case '$title' failed"; return 1; }
}

# solve_create_rule <json-file>: POST, and PUT when the rule id already exists.
solve_create_rule() {
  local file="$1"
  if ! QUIET_STATUS=409 kbn_api POST "$RULES_PATH" "@$file" >/dev/null; then
    [ "$LAST_STATUS" = "409" ] || { die solve "creating the rule from $(basename "$file") failed"; return 1; }
    kbn_api PUT "$RULES_PATH" "@$file" >/dev/null || { die solve "updating the rule from $(basename "$file") failed"; return 1; }
  fi
}

# solve_assert_esql <label> <min-rows> <max-rows> <query> [<needle>]: runs a query printed in a lesson against the live data
# and fails unless it returns min..max rows (and, when given, a value containing <needle>). A lesson query that returns
# nothing is a bug in the lesson or the data, so `instruqt track test` must catch it.
solve_assert_esql() {
  local label="$1" min="$2" max="$3" query="$4" needle="${5:-}" body n
  body="$(jq -nc --arg q "$query" '{query: $q}')"
  if ! es_api POST "/_query" "$body" >/dev/null; then
    die solve "lesson query '$label' failed: $(_last 300)"
    return 1
  fi
  n="$(printf '%s' "$LAST_BODY" | jq '.values | length')"
  if [ "$n" -lt "$min" ] || [ "$n" -gt "$max" ]; then
    die solve "lesson query '$label' returned $n rows, expected $min..$max"
    return 1
  fi
  if [ -n "$needle" ] && ! printf '%s' "$LAST_BODY" | jq -e --arg n "$needle" '[.values[][] | strings | select(contains($n))] | length > 0' >/dev/null; then
    die solve "lesson query '$label' did not return a value containing '$needle'"
    return 1
  fi
}
