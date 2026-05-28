#!/usr/bin/env bash
# Granular capstone tasks under UC1–UC8 epics.
# Run AFTER bootstrap-github-project.sh (epics must exist).
#
# Usage:
#   ./scripts/bootstrap-github-project-tasks.sh [--dry-run]
set -euo pipefail

REPO="${ARGUSS_GITHUB_REPO:-ajrosales-max/arguss}"
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI not found" >&2
  exit 1
fi
gh auth status >/dev/null 2>&1 || {
  echo "error: run 'gh auth login' first" >&2
  exit 1
}

create_label() {
  local name="$1" color="$2" description="$3"
  if $DRY_RUN; then return 0; fi
  gh label create "$name" --repo "$REPO" --color "$color" --description "$description" 2>/dev/null || true
}

issue_exists() {
  local title="$1"
  gh issue list --repo "$REPO" --search "in:title \"${title}\"" --state all --json title \
    --jq ".[] | select(.title == \"${title}\") | .title" | grep -q .
}

epic_ref() {
  local epic_title="$1"
  if $DRY_RUN; then
    echo "EPIC"
    return 0
  fi
  local num
  num="$(gh issue list --repo "$REPO" --search "in:title \"${epic_title}\"" --state all \
    --json number,title --jq ".[] | select(.title == \"${epic_title}\") | .number" | head -1)"
  if [[ -n "$num" ]]; then
    echo "#${num}"
  else
    echo "(epic not found — create [UC*] epics first)"
  fi
}

create_task() {
  local uc="$1"
  local sprint="$2"
  local priority="$3"
  local title="$4"
  local body_extra="$5"
  local epic_title=""

  case "$uc" in
    1) epic_title="[UC1] Read-only dependency audit" ;;
    2) epic_title="[UC2] Auto-remediate low-impact upgrades" ;;
    3) epic_title="[UC3] SBOM for compliance audit" ;;
    4) epic_title="[UC4] Evaluate before granting GitHub PAT" ;;
    5) epic_title="[UC5] Fix-confidence on contested fix" ;;
    6) epic_title="[UC6] AI-generated explanations" ;;
    7) epic_title="[UC7] Incident triage" ;;
    8) epic_title="[UC8] Org-wide rollout" ;;
  esac

  local full_title="[UC${uc}][task] ${title}"
  local labels="capstone-plan,UC${uc},type:task,priority:${priority}"
  [[ -n "$sprint" ]] && labels="${labels},sprint:${sprint}"

  local parent
  parent="$(epic_ref "$epic_title")"

  local body
  body="## Parent epic
Tracks under ${parent} — \`${epic_title}\`

${body_extra}

---
Doc: \`docs/planning/use-cases-and-delivery-plan.md\`"

  if issue_exists "$full_title"; then
    echo "skip (exists): $full_title"
    return 0
  fi
  if $DRY_RUN; then
    echo "[dry-run] $full_title"
    return 0
  fi
  gh issue create --repo "$REPO" --title "$full_title" --label "$labels" --body "$body"
  echo "created: $full_title"
}

echo "==> label type:task"
create_label "type:task" "EDEDED" "Subtask under a UC epic"

echo "==> UC1 tasks"
create_task 1 w1 must "Add docs/demo-scenarios.md with Express fork URL, ref, expected counts" \
  "Create docs/demo-scenarios.md. Pin fork commit; record expected finding/candidate/tier counts."
create_task 1 w1 must "Point dashboard demo button at Express fork (not only axios)" \
  "Update index.html demo target to frozen Express fork ref."
create_task 1 w1 must "Verify Fly URL + demo auth for class reviewers" \
  "Confirm production deploy and ARGUSS_DEMO_* credentials for team."
create_task 1 w2 must "Pre-warm OSV + trust cache for demo ref on Fly" \
  "Run full scan once; document cold-start time for demo script."
create_task 1 w2 should "Polish Mode A/B error messages (404 lockfile, rate limit, invalid zip)" \
  "User-visible errors in dashboard + API."
create_task 1 w3 must "Document OSV vs Snyk finding overlap on Express fork" \
  "Week 11 eval subset: same lockfile, comparison table."

echo "==> UC2 tasks"
create_task 2 w1 must "Create owned GitHub repo for Mode C dry-runs" \
  "Minimal npm repo you control; PAT scoped to repo only."
create_task 2 w2 must "Dry-run Mode C: open AUTO_MERGE PRs on test repo" \
  "Verify arguss/fix-* branches and idempotent re-run."
create_task 2 w2 must "Finalize Mode C consent copy in index.html" \
  "Open PRs only; no merge; session PAT."
create_task 2 w2 must "Polish results_with_actions.html (PR links, skipped, failures)" \
  "Clear UX when actions fail or skip."
create_task 2 w2 must "Document v1: AUTO_MERGE opens PR, does not merge after CI" \
  "Align README and use-cases doc with shipped behavior."
create_task 2 w3 could "Stretch: poll GitHub CI status after PR open (display only)" \
  "Optional; show check status in action results."
create_task 2 w3 could "Stretch: feature-flag merge when CI green" \
  "Post-v1 only."

echo "==> UC3 tasks"
create_task 3 w2 must "Add web SBOM download after scan" \
  "Button or endpoint on results using analyzed lockfile."
create_task 3 w3 must "Add sample CycloneDX JSON under docs/samples/" \
  "For compliance narrative on project site."
create_task 3 w3 should "Add SBOM section to GitHub Pages project site" \
  "Link sample and document arguss sbom CLI."

echo "==> UC4 tasks"
create_task 4 w2 must "Write docs/demo-script.md (Mode A → review → optional C)" \
  "Live demo and PoC video steps."
create_task 4 w1 must "Threat model: team review checklist + sign-off" \
  "Review docs/threat-model.md for all three modes."
create_task 4 w3 should "Add per-IP rate limiting on public scan endpoints" \
  "Mitigate abuse on Fly."

echo "==> UC5 tasks"
create_task 5 w2 must "Script demo scenario B (major bump → REVIEW_REQUIRED)" \
  "Expected fix_kind.major in demo-scenarios.md."
create_task 5 w2 must "Script demo scenario C (trust veto → REVIEW_REQUIRED)" \
  "Expected trust.* veto_signals documented."
create_task 5 w2 must "Rehearse scenario B on frozen fork" \
  "Screenshot for final webpage."
create_task 5 w2 must "Rehearse scenario C (fixture or fork)" \
  "Trust-save demo moment."
create_task 5 w3 should "Add collapsible Why this tier on finding card" \
  "partials/_finding_card.html expansion."
create_task 5 w3 could "Add per-entry Explain button (REVIEW_REQUIRED only)" \
  "HTMX + Claude; must not change tier."
create_task 5 w3 could "Document blast-radius gap or add path-depth veto" \
  "Engine has no blast-radius gate today."

echo "==> UC6 tasks"
create_task 6 w2 must "Pre-cache AI explanations for demo ref" \
  "Populate SQLite cache before live demo."
create_task 6 w2 must "Verify template fallback when ANTHROPIC_API_KEY unset" \
  "Offline-safe escalation copy."
create_task 6 w2 should "Document Anthropic spending cap in docs/ops.md" \
  "Console cap and degradation behavior."
create_task 6 w3 should "Week 11: rate 15–20 sample explanations" \
  "Two reviewers; document failure cases."

echo "==> UC7 tasks"
create_task 7 w3 could "Add EPSS score to findings (display-only)" \
  "No AUTO_MERGE path change."
create_task 7 w3 could "Add CISA KEV flag on findings (display-only)" \
  "Catalog fetch + cache."
create_task 7 w3 could "Add results sort/filter by severity and tier" \
  "Beyond current tier filter buttons."
create_task 7 w3 could "Document minimal incident triage via UC1 tier sort" \
  "Short ops/demo note."

echo "==> UC8 tasks"
create_task 8 w3 wont "Add UC8 future-work blurb to project webpage" \
  "Multi-tenant, webhooks, GitHub App out of scope."

create_shared() {
  local title="$1" labels="$2" body="$3"
  local full_title="[shared][task] ${title}"
  if issue_exists "$full_title"; then echo "skip (exists): $full_title"; return 0; fi
  if $DRY_RUN; then echo "[dry-run] $full_title"; return 0; fi
  gh issue create --repo "$REPO" --title "$full_title" --label "$labels" --body "$body"
  echo "created: $full_title"
}

echo "==> Shared tasks"
create_shared "UI design pass: resolve template TODOs + Tailwind layout" \
  "capstone-plan,UC1,UC5,priority:should,sprint:w3,type:task" \
  "base.html, results.html, finding card."
create_shared "Decide Scorecard/deps.dev: Won't v1 vs Week 10 — update docs" \
  "capstone-plan,priority:should,sprint:w1,type:task" \
  "Close open gaps row in use-cases-and-delivery-plan.md."

echo ""
echo "Done (~35 tasks). Filter issues: label:type:task"
