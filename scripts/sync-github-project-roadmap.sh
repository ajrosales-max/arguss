#!/usr/bin/env bash
# Set GitHub Project Roadmap dates (Start date + Target date) on project items.
#
# Roadmap view uses PROJECT fields "Start date" and "Target date" (YYYY-MM-DD).
# Issue milestones alone do NOT populate the timeline — this script does.
#
# Usage:
#   gh auth refresh -s project,read:project
#   ./scripts/sync-github-project-roadmap.sh [--dry-run]
#
# Env (optional):
#   PROJECT_OWNER=ajrosales-max
#   PROJECT_NUMBER=1
set -euo pipefail

REPO="${ARGUSS_GITHUB_REPO:-ajrosales-max/arguss}"
OWNER="${PROJECT_OWNER:-ajrosales-max}"
PROJ_NUM="${PROJECT_NUMBER:-1}"
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

DATE_SPRINT_W1_START="2026-05-27"
DATE_SPRINT_W1_END="2026-06-02"
DATE_SPRINT_W2_START="2026-06-03"
DATE_SPRINT_W2_END="2026-06-09"
DATE_SPRINT_W3_START="2026-06-10"
DATE_SPRINT_W3_END="2026-06-16"
DATE_W8_START="2026-06-17"
DATE_W8_END="2026-06-24"
DATE_W9_START="2026-06-24"
DATE_W9_END="2026-07-01"
DATE_W10_START="2026-07-01"
DATE_W10_END="2026-07-08"
DATE_W11_START="2026-07-08"
DATE_W11_END="2026-07-15"
DATE_W12_START="2026-07-15"
DATE_W12_END="2026-07-22"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI required" >&2
  exit 1
fi
gh auth status >/dev/null 2>&1 || {
  echo "error: gh auth login + gh auth refresh -s project,read:project" >&2
  exit 1
}

PROJECT_ID="$(gh project view "$PROJ_NUM" --owner "$OWNER" --format json --jq .id)"
FIELD_START="$(gh project field-list "$PROJ_NUM" --owner "$OWNER" --format json \
  --jq '.fields[] | select(.name=="Start date") | .id')"
FIELD_TARGET="$(gh project field-list "$PROJ_NUM" --owner "$OWNER" --format json \
  --jq '.fields[] | select(.name=="Target date") | .id')"

if [[ -z "$FIELD_START" || -z "$FIELD_TARGET" ]]; then
  echo "error: add 'Start date' and 'Target date' fields to the project." >&2
  exit 1
fi

echo "Project: $OWNER #$PROJ_NUM"

resolve_dates_from_issue() {
  local issue_num="$1"
  local labels milestone title
  labels="$(gh issue view "$issue_num" --repo "$REPO" --json labels --jq '.labels[].name' 2>/dev/null || true)"
  milestone="$(gh issue view "$issue_num" --repo "$REPO" --json milestone --jq '.milestone.title // empty' 2>/dev/null || true)"
  title="$(gh issue view "$issue_num" --repo "$REPO" --json title --jq .title 2>/dev/null || true)"

  # Title overrides (syllabus weeks beat sprint labels)
  case "$title" in
    *"OSV vs Snyk"*|*"Snyk vs Dependabot"*) echo "$DATE_W11_START $DATE_W11_END"; return 0 ;;
    *"rate 15"*) echo "$DATE_W11_START $DATE_W11_END"; return 0 ;;
    *"GitHub Pages"*) echo "$DATE_W12_START $DATE_W12_END"; return 0 ;;
    *"collapsible Why this tier"*) echo "$DATE_W9_START $DATE_W9_END"; return 0 ;;
    *"EPSS"*|*"KEV"*|*"rate limiting"*) echo "$DATE_W10_START $DATE_W10_END"; return 0 ;;
    *"backup demo video"*) echo "$DATE_SPRINT_W2_START $DATE_W8_END"; return 0 ;;
    *"Pin frozen Express"*) echo "$DATE_SPRINT_W1_START $DATE_SPRINT_W1_END"; return 0 ;;
  esac

  if echo "$labels" | grep -qx 'sprint:w1'; then echo "$DATE_SPRINT_W1_START $DATE_SPRINT_W1_END"; return 0; fi
  if echo "$labels" | grep -qx 'sprint:w2'; then echo "$DATE_SPRINT_W2_START $DATE_SPRINT_W2_END"; return 0; fi
  if echo "$labels" | grep -qx 'sprint:w3'; then echo "$DATE_SPRINT_W3_START $DATE_SPRINT_W3_END"; return 0; fi

  case "$milestone" in
    "Sprint W1 — Truth & demo target") echo "$DATE_SPRINT_W1_START $DATE_SPRINT_W1_END" ; return 0 ;;
    "Sprint W2 — PoC")                 echo "$DATE_SPRINT_W2_START $DATE_SPRINT_W2_END" ; return 0 ;;
    "Sprint W3 — Eval & ship")         echo "$DATE_SPRINT_W3_START $DATE_SPRINT_W3_END" ; return 0 ;;
    "Syllabus W8 — Demo / PoC")        echo "$DATE_W8_START $DATE_W8_END" ; return 0 ;;
    "Syllabus W10 — v2 enrichments")   echo "$DATE_W10_START $DATE_W10_END" ; return 0 ;;
    "Syllabus W11 — Evaluation")       echo "$DATE_W11_START $DATE_W11_END" ; return 0 ;;
    "Syllabus W12 — Final webpage")    echo "$DATE_W12_START $DATE_W12_END" ; return 0 ;;
  esac

  case "$title" in
    "[UC1]"*) echo "$DATE_SPRINT_W1_START $DATE_W9_END" ;;
    "[UC2]"*) echo "$DATE_SPRINT_W2_START $DATE_W9_END" ;;
    "[UC3]"*) echo "$DATE_SPRINT_W2_START $DATE_W12_END" ;;
    "[UC4]"*) echo "$DATE_SPRINT_W1_START $DATE_W8_END" ;;
    "[UC5]"*) echo "$DATE_SPRINT_W2_START $DATE_W11_END" ;;
    "[UC6]"*) echo "$DATE_SPRINT_W2_START $DATE_W11_END" ;;
    "[UC7]"*) echo "$DATE_W10_START $DATE_W11_END" ;;
    "[UC8]"*) echo "$DATE_W12_START $DATE_W12_END" ;;
    *) echo "" ;;
  esac
}

set_item_dates() {
  local item_id="$1" start="$2" end="$3" label="$4"
  [[ -z "$start" || -z "$end" ]] && { echo "skip (no dates): $label"; return 0; }
  if $DRY_RUN; then echo "[dry-run] $label → $start .. $end"; return 0; fi
  gh project item-edit --id "$item_id" --project-id "$PROJECT_ID" --field-id "$FIELD_START" --date "$start" >/dev/null
  gh project item-edit --id "$item_id" --project-id "$PROJECT_ID" --field-id "$FIELD_TARGET" --date "$end" >/dev/null
  echo "roadmap: $label → $start → $end"
}

echo "==> Capstone items"
UPDATED=0
gh project item-list "$PROJ_NUM" --owner "$OWNER" --limit 200 --format json --jq '.items[]' | while read -r row; do
  item_id="$(echo "$row" | jq -r .id)"
  title="$(echo "$row" | jq -r .title)"
  issue_num="$(echo "$row" | jq -r '.content.number // empty')"
  content_type="$(echo "$row" | jq -r '.content.type // empty')"
  [[ "$content_type" != "Issue" || -z "$issue_num" ]] && continue

  is_capstone=false
  gh issue view "$issue_num" --repo "$REPO" --json labels --jq '.labels[].name' 2>/dev/null \
    | grep -qx 'capstone-plan' && is_capstone=true
  [[ "$title" == \[UC* ]] || [[ "$title" == *\[task\]* ]] && is_capstone=true
  [[ "$is_capstone" != true ]] && continue

  dates="$(resolve_dates_from_issue "$issue_num")"
  start="${dates%% *}"
  end="${dates##* }"
  set_item_dates "$item_id" "$start" "$end" "#$issue_num $title"
done

echo ""
echo "Configure Roadmap: Start date + Target date fields. Zoom: Month/Quarter."
