#!/usr/bin/env bash
#
# ralph-shield.sh — Autonomous Shield Security Assessment Loop
#
# Runs Claude Code in a loop, one task per iteration, until all 66 tasks
# in RALPH_TASKS.md are DONE or max-iterations is reached.
#
# Usage:
#   ./ralph-shield.sh                        # Run until COMPLETE (no limit)
#   ./ralph-shield.sh --max-iterations 10    # Run at most 10 successful iterations
#   ./ralph-shield.sh --dry-run              # Show what would run, don't execute
#   ./ralph-shield.sh --model opus           # Override model (default: opus)
#
# Requires: claude CLI v2.1+ (Claude Code)
#
# State files (updated by each Claude session):
#   RALPH_STATE.md     — loop metadata, current phase, resume point
#   RALPH_TASKS.md     — 66-task state machine with statuses
#   findings/          — security assessment output
#
# Log: ralph-loop.log (appended, timestamped)
#
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROMPT_FILE=".GM/Ralph-Exec-Prompt.md"
STATE_FILE="RALPH_STATE.md"
TASKS_FILE="RALPH_TASKS.md"
REPORT_FILE="findings/SECURITY_REPORT.md"
LOG_FILE="ralph-loop.log"
ITERATION_LOG_DIR=".GM/iterations"

# Defaults
MAX_ITERATIONS=0          # 0 = no limit
MODEL="opus"
DRY_RUN=false
COOLDOWN_INTERVAL=300     # 5 minutes between limit-hit retries
MAX_CRASH_RETRIES=3       # retries per iteration before moving on
CRASH_BACKOFF_BASE=30     # seconds, doubled each retry
MAPS_DIGEST=".GM/agent-skills-maps.txt"   # small — read every task
REPO_DIGEST=".GM/Digest.txt"              # large — referenced, not piped

# ──────────────────────────────────────────────────────────────────────
# PARSE CLI ARGS
# ──────────────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-iterations)
      MAX_ITERATIONS="$2"
      shift 2
      ;;
    --model)
      MODEL="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --cooldown)
      COOLDOWN_INTERVAL="$2"
      shift 2
      ;;
    -h|--help)
      head -20 "$0" | tail -18
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# ──────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────

timestamp() {
  TZ="Asia/Jerusalem" date '+%Y-%m-%d %H:%M:%S %Z'
}

log() {
  local msg="[$(timestamp)] $*"
  echo "$msg" | tee -a "$LOG_FILE"
}

log_section() {
  echo "" >> "$LOG_FILE"
  log "════════════════════════════════════════════════════════════════"
  log "$*"
  log "════════════════════════════════════════════════════════════════"
}

# ──────────────────────────────────────────────────────────────────────
# GRACEFUL SHUTDOWN
# ──────────────────────────────────────────────────────────────────────

SHUTDOWN_REQUESTED=false

shutdown_handler() {
  SHUTDOWN_REQUESTED=true
  log ""
  log "SIGNAL RECEIVED — graceful shutdown initiated"
  log "State files are safe (written by Claude, not by this script)"
  log "Resume with: ./ralph-shield.sh"
  # Don't exit here — let the main loop detect SHUTDOWN_REQUESTED
  # and exit at a clean boundary
}

trap shutdown_handler SIGINT SIGTERM

# ──────────────────────────────────────────────────────────────────────
# STATE PARSING
# ──────────────────────────────────────────────────────────────────────

# macOS grep has no -P flag. Use sed to extract values from markdown.
extract_state() {
  local key="$1"
  sed -n "s/.*\*\*${key}\*\*: *//p" "$STATE_FILE" 2>/dev/null | head -1
}

get_current_phase() {
  extract_state "Current Phase" || echo "UNKNOWN"
}

get_current_task() {
  extract_state "Current Task" || echo "NONE"
}

get_total_iterations() {
  extract_state "Total Iterations" || echo "0"
}

get_findings_total() {
  extract_state "Findings Total" || echo "0"
}

get_resume_point() {
  extract_state "Resume Point" || echo "UNKNOWN"
}

count_tasks_done() {
  # Only count in the TASK sections, not the coverage checklist at the bottom
  sed -n '/^## PHASE/,/^## COVERAGE/p' "$TASKS_FILE" 2>/dev/null | grep -c '\[x\] DONE' || echo "0"
}

count_tasks_total() {
  sed -n '/^## PHASE/,/^## COVERAGE/p' "$TASKS_FILE" 2>/dev/null | grep -c '^\- \*\*Status\*\*:' || echo "66"
}

is_assessment_complete() {
  local phase
  phase=$(get_current_phase)
  [[ "$phase" == *"COMPLETE"* ]] && return 0

  local done total
  done=$(count_tasks_done)
  total=$(count_tasks_total)
  [[ "$done" -ge "$total" ]] && return 0

  return 1
}

# ──────────────────────────────────────────────────────────────────────
# LIMIT / CRASH DETECTION
# ──────────────────────────────────────────────────────────────────────

is_limit_hit() {
  local output="$1"
  local exit_code="$2"

  # Check exit code patterns for rate limiting
  [[ "$exit_code" -eq 429 ]] && return 0

  # Check output for limit-related patterns (case-insensitive)
  local patterns=(
    "rate limit"
    "rate_limit"
    "token limit"
    "usage limit"
    "credit limit"
    "exceeded"
    "quota"
    "capacity"
    "too many requests"
    "overloaded"
    "billing"
    "insufficient credits"
    "ResourceExhausted"
    "503"
    "529"
  )

  local lower_output
  lower_output=$(echo "$output" | tr '[:upper:]' '[:lower:]')

  for pattern in "${patterns[@]}"; do
    local lower_pattern
    lower_pattern=$(echo "$pattern" | tr '[:upper:]' '[:lower:]')
    if echo "$lower_output" | grep -qi "$lower_pattern"; then
      return 0
    fi
  done

  return 1
}

# ──────────────────────────────────────────────────────────────────────
# COOLDOWN (wait for credits to free up)
# ──────────────────────────────────────────────────────────────────────

parse_wait_seconds() {
  # Parse wait/retry duration from Claude's error output.
  # Looks for patterns like "retry after 3600 seconds", "wait 4 hours",
  # "retry in 30 minutes", "Retry-After: 1800", etc.
  local output="$1"
  local seconds=0

  # "retry after N seconds" / "wait N seconds" / "N seconds"
  seconds=$(echo "$output" | sed -n 's/.*[Rr]etry.*[Aa]fter[: ]*\([0-9]*\) *[Ss]ec.*/\1/p' | head -1)
  [[ -n "$seconds" && "$seconds" -gt 0 ]] 2>/dev/null && echo "$seconds" && return

  # "N minutes"
  local minutes
  minutes=$(echo "$output" | sed -n 's/.*[Rr]etry.*[Aa]fter[: ]*\([0-9]*\) *[Mm]in.*/\1/p' | head -1)
  [[ -n "$minutes" && "$minutes" -gt 0 ]] 2>/dev/null && echo "$((minutes * 60))" && return

  # "N hours"
  local hours
  hours=$(echo "$output" | sed -n 's/.*[Ww]ait[: ]*\([0-9]*\) *[Hh]our.*/\1/p' | head -1)
  [[ -n "$hours" && "$hours" -gt 0 ]] 2>/dev/null && echo "$((hours * 3600))" && return

  # "Retry-After: N" header (raw seconds)
  seconds=$(echo "$output" | sed -n 's/.*[Rr]etry-[Aa]fter[: ]*\([0-9]*\).*/\1/p' | head -1)
  [[ -n "$seconds" && "$seconds" -gt 0 ]] 2>/dev/null && echo "$seconds" && return

  # Fallback: no parseable duration found
  echo "0"
}

wait_for_credits() {
  local last_output="$1"
  local attempt=0

  # Try to parse how long to wait from the error output
  local parsed_wait
  parsed_wait=$(parse_wait_seconds "$last_output")

  local wait_time="$COOLDOWN_INTERVAL"
  if [[ "$parsed_wait" -gt 0 ]] 2>/dev/null; then
    wait_time="$parsed_wait"
    log "COOLDOWN: API says wait ${wait_time}s ($(( wait_time / 60 ))m). Honoring it."
  else
    log "COOLDOWN: No wait duration in response. Using default ${wait_time}s."
  fi

  log "COOLDOWN: Credit/rate limit hit. Will retry after ${wait_time}s..."

  while true; do
    if [[ "$SHUTDOWN_REQUESTED" == true ]]; then
      log "COOLDOWN: Shutdown requested during cooldown. Exiting."
      exit 0
    fi

    attempt=$((attempt + 1))
    log "COOLDOWN: Attempt $attempt — sleeping ${wait_time}s ($(( wait_time / 60 ))m)..."
    sleep "$wait_time"

    # Probe with a minimal request
    local probe_output probe_exit
    probe_exit=0
    probe_output=$(claude -p --model "$MODEL" --dangerously-skip-permissions \
      --output-format text \
      "Reply with exactly: READY" 2>&1) || probe_exit=$?

    if [[ "$probe_exit" -eq 0 ]] && echo "$probe_output" | grep -qi "READY"; then
      log "COOLDOWN: Credits available. Resuming assessment."
      return 0
    fi

    if ! is_limit_hit "$probe_output" "$probe_exit"; then
      log "COOLDOWN: Non-limit response (exit=$probe_exit). Attempting resume."
      return 0
    fi

    # Re-parse wait time from new response (might have changed)
    parsed_wait=$(parse_wait_seconds "$probe_output")
    if [[ "$parsed_wait" -gt 0 ]] 2>/dev/null; then
      wait_time="$parsed_wait"
      log "COOLDOWN: Updated wait to ${wait_time}s ($(( wait_time / 60 ))m) from response."
    else
      # Exponential backoff: double each attempt, cap at 1 hour
      wait_time=$(( wait_time * 2 ))
      [[ "$wait_time" -gt 3600 ]] && wait_time=3600
      log "COOLDOWN: Still limited. Backing off to ${wait_time}s ($(( wait_time / 60 ))m)."
    fi
  done
}

# ──────────────────────────────────────────────────────────────────────
# BUILD PROMPT
# ──────────────────────────────────────────────────────────────────────

generate_digests() {
  # Run once at startup. Two digest files:
  # 1. Maps digest (small) — agent/team/skill maps, read every task
  # 2. Repo digest (large) — full codebase, referenced but not piped

  log "Generating maps digest: $MAPS_DIGEST"
  gitingest .GM/ \
    --output "$MAPS_DIGEST" \
    --include-pattern "*.md" \
    --exclude-pattern "iterations/*" \
    --exclude-pattern "Digest.txt" \
    --exclude-pattern "agent-skills-maps.txt" \
    2>/dev/null || {
      log "WARNING: gitingest failed for maps — falling back to cat"
      cat .GM/agent-map.md .GM/agent-teams-map.md .GM/skills-map.md \
        .GM/SHIELD_SECURITY_CONTEXT.md > "$MAPS_DIGEST"
    }
  log "Maps digest: $(wc -c < "$MAPS_DIGEST" | tr -d ' ') bytes"

  log "Generating full repo digest: $REPO_DIGEST"
  gitingest . \
    --output "$REPO_DIGEST" \
    --exclude-pattern "branding/*" \
    --exclude-pattern ".GM/iterations/*" \
    --exclude-pattern ".GM/Digest.txt" \
    --exclude-pattern ".GM/agent-skills-maps.txt" \
    --exclude-pattern "node_modules/*" \
    --exclude-pattern "target/*" \
    --exclude-pattern ".git/*" \
    2>/dev/null || {
      log "WARNING: gitingest failed for repo digest — Claude can still read files directly"
    }
  if [[ -f "$REPO_DIGEST" ]]; then
    log "Repo digest: $(wc -c < "$REPO_DIGEST" | tr -d ' ') bytes"
  fi
}

build_prompt() {
  # Pipe to Claude each iteration:
  #   1. Iteration prompt (Ralph-Exec-Prompt.md)
  #   2. State files (small, change every iteration)
  #   3. Maps digest (small, agent/team/skill context)
  #   4. Reference to repo digest (NOT the content — just the path)

  cat <<'PROMPT_HEADER'
You are executing one iteration of the Ralph Wiggum autonomous security assessment loop.

CONTEXT PROVIDED BELOW (do NOT re-read these files):
- Iteration instructions
- RALPH_STATE.md, RALPH_TASKS.md, SECURITY_REPORT.md (current state)
- Agent/team/skill maps digest

FULL REPO DIGEST available at .GM/Digest.txt — read it when you need broad codebase context.
Do NOT read it every time. Only when your task requires exploring unfamiliar source code.

TOKEN-SAVING: Use `gitingest` via Bash to digest specific directories instead of reading files one-by-one:
  gitingest shield-core/src/ --output .GM/task-digest.txt --exclude-pattern "branding/*"
  gitingest python/shield/ --output .GM/task-digest.txt --exclude-pattern "branding/*"
  gitingest c/src/ --output .GM/task-digest.txt --exclude-pattern "branding/*"
Then read .GM/task-digest.txt for compact context. ALWAYS exclude branding/*.

PROMPT_HEADER

  echo "=== ITERATION PROMPT ==="
  cat "$PROMPT_FILE"

  echo ""
  echo "=== RALPH_STATE.md ==="
  cat "$STATE_FILE"

  echo ""
  echo "=== RALPH_TASKS.md ==="
  cat "$TASKS_FILE"

  echo ""
  echo "=== findings/SECURITY_REPORT.md ==="
  cat "$REPORT_FILE"

  echo ""
  echo "=== AGENT / TEAM / SKILL MAPS (digest) ==="
  cat "$MAPS_DIGEST"
}

# ──────────────────────────────────────────────────────────────────────
# SAVE ITERATION SUMMARY
# ──────────────────────────────────────────────────────────────────────

save_iteration_summary() {
  local iteration="$1"
  local start_time="$2"
  local end_time="$3"
  local task="$4"
  local findings="$5"
  local status="$6"

  mkdir -p "$ITERATION_LOG_DIR"

  local summary_file="$ITERATION_LOG_DIR/iteration-$(printf '%03d' "$iteration").md"

  cat > "$summary_file" <<SUMMARY
# Ralph Iteration $iteration Summary

- **Start**: $start_time
- **End**: $end_time
- **Task**: $task
- **Findings This Iteration**: $findings
- **Status**: $status
- **Phase**: $(get_current_phase)
- **Tasks Done**: $(count_tasks_done)/$(count_tasks_total)
- **Total Findings**: $(get_findings_total)
- **Resume Point**: $(get_resume_point)
SUMMARY

  log "Iteration summary saved: $summary_file"
}

# ──────────────────────────────────────────────────────────────────────
# PRE-FLIGHT CHECKS
# ──────────────────────────────────────────────────────────────────────

preflight() {
  local errors=0

  if ! command -v claude &>/dev/null; then
    log "ERROR: 'claude' CLI not found in PATH"
    errors=$((errors + 1))
  fi

  for f in "$PROMPT_FILE" "$STATE_FILE" "$TASKS_FILE" "$REPORT_FILE"; do
    if [[ ! -f "$f" ]]; then
      log "ERROR: Required file missing: $f"
      errors=$((errors + 1))
    fi
  done

  if [[ ! -d "findings/agents" ]] || [[ ! -d "findings/teams" ]]; then
    log "ERROR: findings/agents/ or findings/teams/ directory missing"
    errors=$((errors + 1))
  fi

  if [[ "$errors" -gt 0 ]]; then
    log "PREFLIGHT FAILED: $errors errors. Fix before running."
    exit 1
  fi

  log "Preflight OK: all required files and directories present"
}

# ──────────────────────────────────────────────────────────────────────
# MAIN LOOP
# ──────────────────────────────────────────────────────────────────────

main() {
  log_section "RALPH SHIELD SECURITY ASSESSMENT — STARTING"
  log "Claude Code version: $(claude --version 2>&1 || echo 'unknown')"
  log "Model: $MODEL"
  log "Max iterations: $([ "$MAX_ITERATIONS" -eq 0 ] && echo 'unlimited' || echo "$MAX_ITERATIONS")"
  log "Prompt file: $PROMPT_FILE"
  log "Cooldown interval: ${COOLDOWN_INTERVAL}s"
  log "Working directory: $SCRIPT_DIR"

  preflight
  generate_digests

  if is_assessment_complete; then
    log "Assessment already COMPLETE. Nothing to do."
    exit 0
  fi

  if [[ "$DRY_RUN" == true ]]; then
    log "DRY RUN — would execute loop with above config. Exiting."
    exit 0
  fi

  local successful_iterations=0
  local total_attempts=0
  local limit_hits=0

  while true; do
    # ── Check shutdown ──
    if [[ "$SHUTDOWN_REQUESTED" == true ]]; then
      log_section "SHUTDOWN: Graceful exit after $successful_iterations iterations"
      log "Tasks done: $(count_tasks_done)/$(count_tasks_total)"
      log "Findings: $(get_findings_total)"
      log "Resume with: ./ralph-shield.sh"
      exit 0
    fi

    # ── Check max iterations ──
    if [[ "$MAX_ITERATIONS" -gt 0 ]] && [[ "$successful_iterations" -ge "$MAX_ITERATIONS" ]]; then
      log_section "MAX ITERATIONS ($MAX_ITERATIONS) REACHED"
      log "Tasks done: $(count_tasks_done)/$(count_tasks_total)"
      log "Findings: $(get_findings_total)"
      log "Tasks remaining: $(($(count_tasks_total) - $(count_tasks_done)))"
      log ""
      log "TO CONTINUE: ./ralph-shield.sh --max-iterations N"
      exit 0
    fi

    # ── Check completion ──
    if is_assessment_complete; then
      log_section "ASSESSMENT COMPLETE"
      log "All tasks DONE after $successful_iterations iterations"
      log "Total findings: $(get_findings_total)"
      log "Final report: $REPORT_FILE"
      exit 0
    fi

    # ── Prepare iteration ──
    total_attempts=$((total_attempts + 1))
    local iter_num=$((successful_iterations + 1))
    local current_task
    current_task=$(get_resume_point)
    local iter_start
    iter_start=$(timestamp)

    log ""
    log "── Iteration $iter_num (attempt $total_attempts) ──"
    log "Phase: $(get_current_phase)"
    log "Next task: $current_task"
    log "Tasks done: $(count_tasks_done)/$(count_tasks_total)"

    # ── Heartbeat: write timestamp so you can check if stuck ──
    echo "$(timestamp) | iter=$iter_num | task=$current_task | pid=$$" > .GM/ralph-heartbeat

    # ── Build and execute ──
    local prompt
    prompt=$(build_prompt)

    local output=""
    local exit_code=0
    local crash_retries=0

    while true; do
      # Run Claude in print mode with the iteration prompt
      output=$(echo "$prompt" | claude \
        -p \
        --model "$MODEL" \
        --dangerously-skip-permissions \
        --output-format text \
        2>&1) || exit_code=$?
      exit_code=${exit_code:-0}

      # ── Handle limit hit ──
      if is_limit_hit "$output" "$exit_code"; then
        limit_hits=$((limit_hits + 1))
        log "LIMIT HIT #$limit_hits (exit=$exit_code). NOT counting toward iterations."

        # Save partial output for debugging
        echo "$output" >> "$LOG_FILE"

        wait_for_credits "$output"

        if [[ "$SHUTDOWN_REQUESTED" == true ]]; then
          break
        fi

        log "Resuming after cooldown — retrying same task: $current_task"
        exit_code=0
        continue
      fi

      # ── Handle crash / non-zero exit ──
      if [[ "$exit_code" -ne 0 ]]; then
        crash_retries=$((crash_retries + 1))

        if [[ "$crash_retries" -ge "$MAX_CRASH_RETRIES" ]]; then
          log "CRASH: $MAX_CRASH_RETRIES retries exhausted for task $current_task (exit=$exit_code)"
          log "Last output (tail):"
          echo "$output" | tail -20 >> "$LOG_FILE"
          log "Skipping to next iteration — state files may need manual review"
          break
        fi

        local backoff=$((CRASH_BACKOFF_BASE * (2 ** (crash_retries - 1))))
        log "CRASH: exit=$exit_code, retry $crash_retries/$MAX_CRASH_RETRIES in ${backoff}s"
        echo "$output" | tail -10 >> "$LOG_FILE"
        sleep "$backoff"

        if [[ "$SHUTDOWN_REQUESTED" == true ]]; then
          break
        fi

        exit_code=0
        continue
      fi

      # ── Success ──
      break
    done

    if [[ "$SHUTDOWN_REQUESTED" == true ]]; then
      continue  # will catch at top of outer loop
    fi

    # ── Post-iteration ──
    local iter_end
    iter_end=$(timestamp)
    local findings_before findings_after new_findings
    findings_before=$(get_findings_total)

    # Re-read state after Claude updated it
    local post_task
    post_task=$(get_current_task)
    findings_after=$(get_findings_total)
    new_findings=$((findings_after - findings_before))
    if [[ "$new_findings" -lt 0 ]]; then
      new_findings=0
    fi

    successful_iterations=$((successful_iterations + 1))

    log "Iteration $successful_iterations complete: task=$post_task, new_findings=$new_findings"

    # Save iteration summary file (Protocol 13: COMMUNICATION)
    save_iteration_summary \
      "$successful_iterations" \
      "$iter_start" \
      "$iter_end" \
      "$post_task" \
      "$new_findings" \
      "$(get_current_phase)"

    # Brief pause between iterations to avoid hammering
    sleep 2
  done
}

# ──────────────────────────────────────────────────────────────────────
# RUN
# ──────────────────────────────────────────────────────────────────────

main "$@"
