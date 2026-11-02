#!/usr/bin/env bash
# Builds a ready Elastibank lab on a bare managed sandbox. Source it, then call bootstrap_all.
# The Instruqt setup script (track/track_scripts/setup-kubernetes-vm) fetches this repo first.
# Sets no shell options; the caller decides (the setup script uses set -euo pipefail).

_BOOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/apply.sh
. "$_BOOT_DIR/apply.sh"

ELASTIC_VIEW_SH="${ELASTIC_VIEW_SH:-/opt/workshops/elastic-view.sh}"
ELASTIC_LLM_SH="${ELASTIC_LLM_SH:-/opt/workshops/elastic-llm.sh}"
LLM_MODEL="${LLM_MODEL:-claude-sonnet-4.6}"
BOOTSTRAP_MARKER="${BOOTSTRAP_MARKER:-/var/lib/elastibank/bootstrap.ok}"
MIN_ALERTS=40
EXPECTED_DOCS=33048

# Mailpit: pinned release (spike item 7 confirms the version and where Kibana can reach SMTP).
MAILPIT_VERSION="${MAILPIT_VERSION:-v1.21.8}"
MAILPIT_URL="${MAILPIT_URL:-http://127.0.0.1:8025}"
MAILPIT_SMTP_PORT="${MAILPIT_SMTP_PORT:-1025}"

_vm_ip() {
  ip route get 1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

# start_mailpit: no-op when Mailpit already answers.
start_mailpit() {
  local arch tmp
  if curl -fs -m 3 "$MAILPIT_URL/api/v1/info" >/dev/null 2>&1; then
    log "mailpit already running"
    return 0
  fi
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die mailpit "unsupported architecture $(uname -m)" ;;
  esac
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/mailpit.tgz" \
    "https://github.com/axllent/mailpit/releases/download/${MAILPIT_VERSION}/mailpit-linux-${arch}.tar.gz" ||
    die mailpit "download failed"
  tar -xzf "$tmp/mailpit.tgz" -C "$tmp" mailpit && install -m 0755 "$tmp/mailpit" /usr/local/bin/mailpit ||
    die mailpit "install failed"
  rm -rf "$tmp"
  # A systemd unit survives a VM stop/start (hot-start pool, then student claim); nohup is the fallback.
  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run --quiet --unit=mailpit --property=Restart=always \
      /usr/local/bin/mailpit --smtp "0.0.0.0:${MAILPIT_SMTP_PORT}" --listen "0.0.0.0:8025" ||
      die mailpit "systemd-run failed"
  else
    nohup /usr/local/bin/mailpit --smtp "0.0.0.0:${MAILPIT_SMTP_PORT}" --listen "0.0.0.0:8025" \
      >/var/log/mailpit.log 2>&1 &
  fi
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    curl -fs -m 3 "$MAILPIT_URL/api/v1/info" >/dev/null 2>&1 && return 0
    sleep 1
  done
  die mailpit "did not start (see /var/log/mailpit.log)"
}

_STEP_START=0
_step_done() {
  log "step $1/9 $2 done in $((SECONDS - _STEP_START))s"
  _STEP_START="$SECONDS"
}

bootstrap_all() {
  local total_start="$SECONDS" data_dir smtp_host
  _STEP_START="$SECONDS"

  require_tools
  load_env
  wait_for_kibana
  _step_done 1 "kibana ready"

  "$ELASTIC_VIEW_SH" -v security || die view "elastic-view.sh failed"
  _step_done 2 "security view"

  "$ELASTIC_LLM_SH" -m "$LLM_MODEL" -k false || die llm "elastic-llm.sh failed; the lab's AI cannot work, stopping"
  find_llm_connector || return 1
  apply_settings || return 1
  _step_done 3 "llm connector and settings"

  install_packages || return 1
  apply_index_templates || return 1
  _step_done 4 "integrations and templates"

  data_dir="$(mktemp -d)"
  # GENERATOR_ANCHOR (ISO-8601 with offset) pins "now" for the dataset; unset means the current time. The beacon
  # streams grow by a document every few minutes, so a re-run with the default reloads them rather than skipping.
  (cd "$REPO_DIR" && python3 -m scenario.generator --out "$data_dir" ${GENERATOR_ANCHOR:+--anchor "$GENERATOR_ANCHOR"} >&2) ||
    die dataset "generator failed"
  load_dataset "$data_dir" || return 1
  apply_lookups "$data_dir" || return 1
  rm -rf "$data_dir"
  _step_done 5 "dataset loaded"

  apply_rules || return 1
  wait_for_alerts "$MIN_ALERTS" || return 1
  _step_done 6 "rules and alerts"

  start_mailpit || return 1
  smtp_host="${MAILPIT_SMTP_HOST:-$(_vm_ip)}"
  [ -n "$smtp_host" ] || { die mailpit "cannot determine this VM's address for the SMTP connector; set MAILPIT_SMTP_HOST"; return 1; }
  create_email_connector "$smtp_host" "$MAILPIT_SMTP_PORT" || return 1
  _step_done 7 "mail inbox"

  # The skill and agent are built by the students (challenges 05 and 06); their solve scripts apply them.
  apply_tools || return 1
  apply_workflows || return 1
  _step_done 8 "tools and workflows"

  mkdir -p "$(dirname "$BOOTSTRAP_MARKER")"
  printf '%s\n' "$((SECONDS - total_start))" >"$BOOTSTRAP_MARKER"
  _step_done 9 "marker written"
  log "bootstrap finished in $((SECONDS - total_start))s"
  if [ $((SECONDS - total_start)) -gt 300 ]; then
    log "WARNING: bootstrap took longer than 300s"
  fi
}

# verify_ready: used by challenge 01's check. Fast (< 5 s) and read-only.
verify_ready() {
  local count low high
  [ -f "$BOOTSTRAP_MARKER" ] || die ready "bootstrap has not finished (no $BOOTSTRAP_MARKER)" || return 1
  wait_for_alerts "$MIN_ALERTS" 3 || return 1
  es_api GET "/logs-*/_count" >/dev/null || die ready "could not count documents" || return 1
  count="$(printf '%s' "$LAST_BODY" | jq '.count // 0')"
  low=$((EXPECTED_DOCS * 90 / 100))
  high=$((EXPECTED_DOCS * 110 / 100))
  if [ "$count" -lt "$low" ] || [ "$count" -gt "$high" ]; then
    die ready "$count documents loaded, expected about $EXPECTED_DOCS" || return 1
  fi
}
