#!/usr/bin/env bash
# Diagnostics for the live spike: runs each lab step's solve and check in turn WITHOUT stopping at the first failure,
# and prints one "SPIKE <step> rc=<n> <start of the output>" line per step. Not part of the student path. Source it
# after load_env; it sets no shell options. The real fail-message is never called (a local function stands in).

_SPK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/solves.sh
. "$_SPK_DIR/solves.sh"

_spike_step() {
  local name="$1" out rc
  shift
  out="$( ("$@") 2>&1)"
  rc=$?
  printf 'SPIKE %-26s rc=%s %s\n' "$name" "$rc" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-"${SPIKE_CHARS:-700}")"
}

spike_run_all() {
  local LIB_NO_EXIT=1 tools="elastibank-asset-lookup elastibank-user-lookup elastibank-host-timeline elastibank-escalation-email"
  fail-message() { printf 'FAIL: %s\n' "$1"; }
  # shellcheck disable=SC2086
  _spike_step "05 apply_skill" apply_skill
  _spike_step "05 check" check_skill_contains elastibank-org-context FIN-DB01 svc_findb APT29
  _spike_step "06 apply_agent" apply_agent
  # shellcheck disable=SC2086
  _spike_step "06 check" check_agent_wired elastibank-soc-analyst elastibank-org-context $tools
  _spike_step "03 run soc-autopilot" solve_run_workflow soc-autopilot
  _spike_step "03 check" check_case_tagged autopilot
  _spike_step "07 attack discovery" solve_run_attack_discovery
  _spike_step "07 check" check_attack_discovery_exists
  _spike_step "08 ask the agent" solve_ask_agent elastibank-soc-analyst \
    "Using the latest Attack Discovery, give me a risk score, the MITRE ATT&CK techniques and the blast radius. Which alerts look like false positives?"
  _spike_step "08 check" check_conversation_with elastibank-soc-analyst
  _spike_step "09 open case" solve_open_case "Intrusion on WS-FIN-042" high \
    "Spearphish foothold on WS-FIN-042 (j.martin), credential theft, then WMI lateral movement to FIN-DB01 (Tier 1) with svc_findb." elastibank
  _spike_step "09 check" check_case_matching high WS-FIN-042 autopilot
  _spike_step "12 escalate" solve_run_workflow escalation-email \
    '{"host":"FIN-DB01","tier":"1","summary":"Credential theft on WS-FIN-042 and lateral movement to FIN-DB01."}'
  _spike_step "12 check" check_mail_to ciso@elastibank.example
  _spike_step "15 create rule" solve_create_rule "$REPO_DIR/kibana/solutions/beacon-rule.json"
  _spike_step "15 check" check_rule_enabled_matching 'telemetry\.azure-cdnedge\.net|203\.0\.113\.47' "$REPO_DIR/kibana/rules"
  unset -f fail-message
  return 0
}
