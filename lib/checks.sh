#!/usr/bin/env bash
# Read-only assertions for the challenge check scripts. Source it; it sets no shell options.
# Each check_* returns 0, or calls check_fail (an actionable message for the student) and returns 1.
# A check never looks at what an agent said, only at whether the object the student made exists.
# Endpoint paths below are spike item 11 (and 7 for Mailpit); this block is the one place to change them.

CASES_FIND_PATH=/api/cases/_find
CONVERSATIONS_PATH=/api/agent_builder/conversations
RULES_FIND_PATH=/api/detection_engine/rules/_find
ATTACK_DISCOVERY_FIND_PATH=/api/attack_discovery/_find   # live-confirmed: {data, total, page, per_page, ...}
MAILPIT_URL="${MAILPIT_URL:-http://127.0.0.1:8025}"

_CHK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/apply.sh
. "$_CHK_DIR/apply.sh"

# check_fail <message>: shows the message to the student (fail-message exists on the lab VM), returns 1.
# With CHECK_QUIET=1 it only returns 1, so a solve script can ask "is this already done?" silently.
check_fail() {
  [ "${CHECK_QUIET:-0}" = "1" ] && return 1
  if command -v fail-message >/dev/null 2>&1; then
    fail-message "$1"
  else
    printf 'FAIL: %s\n' "$1" >&2
  fi
  return 1
}

# check_init: soft errors (no exit), a 4 s HTTP budget, and the lab environment loaded.
check_init() {
  LIB_NO_EXIT=1
  CURL_MAX_TIME=4
  export CURL_MAX_TIME
  load_env >/dev/null 2>&1 || check_fail "The lab environment is not ready yet. Wait a minute and press Check again."
}

_urlenc() { jq -rn --arg v "$1" '$v | @uri'; }

# _chk_fetch <path> <what>: GET quietly. Returns 0 on success, 2 on 404, 1 (after check_fail) on anything else.
_chk_fetch() {
  QUIET_STATUS=404 kbn_api GET "$1" >/dev/null 2>&1 && return 0
  [ "$LAST_STATUS" = "404" ] && return 2
  check_fail "Could not read $2 from Kibana (HTTP ${LAST_STATUS:-none}). Wait a moment and press Check again."
  return 1
}

check_case_tagged() {
  local tag="$1" n
  _chk_fetch "$CASES_FIND_PATH?tags=$(_urlenc "$tag")&perPage=100" "the cases" || return 1
  n="$(printf '%s' "$LAST_BODY" | jq '.total // 0')"
  [ "$n" -ge 1 ] && return 0
  check_fail "No case tagged '$tag' yet. Open Workflows, run soc-autopilot, wait until all four steps have finished, then press Check again."
}

# check_case_matching <high|critical> <needle> <excluded-tag>
check_case_matching() {
  local min="$1" needle="$2" excluded="$3" sevs label n
  case "$min" in
    critical) sevs='["critical"]'; label="Critical" ;;
    *) sevs='["high","critical"]'; label="High" ;;
  esac
  _chk_fetch "$CASES_FIND_PATH?perPage=100" "the cases" || return 1
  n="$(printf '%s' "$LAST_BODY" | jq --argjson s "$sevs" --arg n "$needle" --arg x "$excluded" '
    [.cases[]?
      | select(.severity as $v | $s | index($v) != null)
      | select(((.tags // []) | index($x)) == null)
      | select(((.title // "") + " " + (.description // "")) | contains($n))] | length')"
  [ "$n" -ge 1 ] && return 0
  check_fail "No case rated $label or higher that mentions '$needle' was found (the case made by the $excluded workflow does not count). Create one from the Attack discovery page with severity $label and put '$needle' in the description."
}

# check_skill_contains <id> <needle>...
check_skill_contains() {
  local id="$1" needle content rc missing=""
  shift
  _chk_fetch "$SKILLS_PATH/$id" "the skill"
  rc=$?
  [ "$rc" -eq 2 ] && { check_fail "Skill '$id' was not found. In Agent Builder open Skills and create a skill whose ID is exactly '$id'."; return 1; }
  [ "$rc" -ne 0 ] && return 1
  content="$(printf '%s' "$LAST_BODY" | jq -r '.content // ""')"
  for needle in "$@"; do
    case "$content" in *"$needle"*) ;; *) missing="$missing '$needle'" ;; esac
  done
  [ -z "$missing" ] && return 0
  check_fail "Skill '$id' exists but its content is missing$missing. Paste the whole Markdown from the challenge into the skill and save."
}

# check_agent_wired <agent-id> <skill-id> <tool-id>...
check_agent_wired() {
  local agent="$1" skill="$2" tool rc problems="" missing=""
  shift 2
  _chk_fetch "$AGENTS_PATH/$agent" "the agent"
  rc=$?
  [ "$rc" -eq 2 ] && { check_fail "Agent '$agent' was not found. In Agent Builder create an agent whose ID is exactly '$agent' (check the spelling of the ID)."; return 1; }
  [ "$rc" -ne 0 ] && return 1
  if [ -z "$(printf '%s' "$LAST_BODY" | jq -r '(.configuration.instructions // "") | gsub("\\s"; "")')" ]; then
    problems="$problems it has no instructions;"
  fi
  if [ "$(printf '%s' "$LAST_BODY" | jq --arg s "$skill" '[.configuration.skill_ids[]?] | index($s) != null')" != "true" ]; then
    problems="$problems the skill '$skill' is not attached;"
  fi
  for tool in "$@"; do
    if [ "$(printf '%s' "$LAST_BODY" | jq --arg t "$tool" '[.configuration.tools[]?.tool_ids[]?] | index($t) != null')" != "true" ]; then
      missing="$missing $tool"
    fi
  done
  [ -n "$missing" ] && problems="$problems these tools are not attached:$missing;"
  [ -z "$problems" ] && return 0
  check_fail "Agent '$agent' is not finished:${problems%;}. Open the agent, fix this and save."
}

# _ad_count: how many Attack Discoveries exist, scheduled or ad hoc (0 when the call fails).
_ad_count() {
  if kbn_api GET "$ATTACK_DISCOVERY_FIND_PATH?per_page=1" >/dev/null 2>&1; then
    printf '%s' "$LAST_BODY" | jq '.total // 0' 2>/dev/null || echo 0
  else
    echo 0
  fi
}

check_attack_discovery_exists() {
  [ "$(_ad_count)" -ge 1 ] && return 0
  check_fail "No Attack discovery found yet. Open Security > Attack discovery, choose the lab's AI connector, press Generate and wait for the results."
}

check_conversation_with() {
  local agent="$1" n
  _chk_fetch "$CONVERSATIONS_PATH" "your conversations" || return 1
  n="$(printf '%s' "$LAST_BODY" | jq --arg a "$agent" '[.results[]? | select(.agent_id == $a)] | length')"
  [ "$n" -ge 1 ] && return 0
  check_fail "No conversation with the agent '$agent' found. Open the agent chat, choose '$agent' (not the default agent) and send the prompt from the challenge."
}

check_mail_to() {
  local address="$1" out n
  if ! out="$(curl -sS -m "${CURL_MAX_TIME:-4}" -G --data-urlencode "query=to:$address" "$MAILPIT_URL/api/v1/search" 2>/dev/null)"; then
    check_fail "Could not open the mail inbox. Wait a moment and press Check again."
    return 1
  fi
  n="$(printf '%s' "$out" | jq '(.messages_count // (.messages | length) // 0)' 2>/dev/null)" || n=0
  [ "$n" -ge 1 ] && return 0
  check_fail "No email to $address in the inbox yet. Ask the agent to escalate, wait a few seconds, open the Mailpit tab to look, then press Check again."
}

# check_rule_enabled_matching <regex> <shipped-rules-dir>: an enabled rule the student made (not one shipped in the
# directory) whose query matches the regex.
check_rule_enabled_matching() {
  local regex="$1" dir="$2" shipped matching enabled
  shipped="$(jq -sc '[.[].name]' "$dir"/*.json)"
  _chk_fetch "$RULES_FIND_PATH?per_page=200" "the detection rules" || return 1
  matching="$(printf '%s' "$LAST_BODY" | jq --argjson sh "$shipped" --arg re "$regex" '
    [.data[]? | select(.name as $n | $sh | index($n) == null) | select((.query // "") | test($re))] | length')"
  enabled="$(printf '%s' "$LAST_BODY" | jq --argjson sh "$shipped" --arg re "$regex" '
    [.data[]? | select(.enabled == true) | select(.name as $n | $sh | index($n) == null) | select((.query // "") | test($re))] | length')"
  [ "$enabled" -ge 1 ] && return 0
  if [ "$matching" -ge 1 ]; then
    check_fail "Your rule exists but is not enabled. Open Security > Rules, switch it on and press Check again."
  else
    check_fail "No rule of yours that looks for the beacon was found. Use the AI rule creation in Security > Rules, press Apply, then save and enable the rule."
  fi
}
