#!/usr/bin/env bash
# Create or UPDATE all capstone task issues with details, dates, and milestones.
# Safe to re-run: matches by exact title, then gh issue edit.
#
# Usage:
#   ./scripts/sync-github-project-tasks.sh [--dry-run]
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

MS_SPRINT_W1="2026-06-02T23:59:59Z"
MS_SPRINT_W2="2026-06-09T23:59:59Z"
MS_SPRINT_W3="2026-06-16T23:59:59Z"
MS_W8_POC="2026-06-24T23:59:59Z"
MS_W10_V2="2026-07-08T23:59:59Z"
MS_W11_EVAL="2026-07-15T23:59:59Z"
MS_W12_SITE="2026-07-22T23:59:59Z"

declare -A MILESTONE_NUM=()

ensure_milestone() {
  local title="$1"
  local due_on="$2"
  if $DRY_RUN; then
    MILESTONE_NUM[$title]=0
    return 0
  fi
  local num
  num="$(gh api "repos/${REPO}/milestones" --jq ".[] | select(.title==\"${title}\") | .number" | head -1)"
  if [[ -z "$num" ]]; then
    num="$(gh api "repos/${REPO}/milestones" -f title="$title" -f due_on="$due_on" --jq .number)"
    echo "milestone created: $title (#$num)"
  else
    gh api -X PATCH "repos/${REPO}/milestones/${num}" -f due_on="$due_on" >/dev/null
    echo "milestone exists: $title (#$num)"
  fi
  MILESTONE_NUM[$title]=$num
}

epic_ref() {
  local epic_title="$1"
  if $DRY_RUN; then echo "#EPIC"; return 0; fi
  local num
  num="$(gh issue list --repo "$REPO" --search "in:title \"${epic_title}\"" --state all \
    --json number,title --jq ".[] | select(.title == \"${epic_title}\") | .number" | head -1)"
  [[ -n "$num" ]] && echo "#${num}" || echo "(epic missing)"
}

issue_number_by_title() {
  local title="$1"
  gh issue list --repo "$REPO" --search "in:title \"${title}\"" --state all \
    --json number,title --jq ".[] | select(.title == \"${title}\") | .number" | head -1
}

upsert_task() {
  local uc="$1" sprint="$2" priority="$3" ms_title="$4" target_date="$5" syllabus="$6" short="$7"
  local body="$8"

  local epic_title
  case "$uc" in
    1) epic_title="[UC1] Read-only dependency audit" ;;
    2) epic_title="[UC2] Auto-remediate low-impact upgrades" ;;
    3) epic_title="[UC3] SBOM for compliance audit" ;;
    4) epic_title="[UC4] Evaluate before granting GitHub PAT" ;;
    5) epic_title="[UC5] Fix-confidence on contested fix" ;;
    6) epic_title="[UC6] AI-generated explanations" ;;
    7) epic_title="[UC7] Incident triage" ;;
    8) epic_title="[UC8] Org-wide rollout" ;;
    *) epic_title="[shared]" ;;
  esac

  local prefix="[UC${uc}][task]"
  [[ "$uc" == "shared" ]] && prefix="[shared][task]"
  local full_title="${prefix} ${short}"
  local parent
  parent="$(epic_ref "$epic_title")"

  local labels="capstone-plan,type:task,priority:${priority}"
  [[ "$uc" != "shared" ]] && labels="${labels},UC${uc}"
  [[ -n "$sprint" && "$sprint" != "-" ]] && labels="${labels},sprint:${sprint}"

  local full_body
  full_body="$(cat <<EOF
## Schedule
| Field | Value |
|-------|--------|
| **Target date** | ${target_date} |
| **Sprint** | ${sprint} (go-live overlay May 27 – Jun 16, 2026) |
| **Syllabus** | ${syllabus} |
| **Milestone** | ${ms_title} |

## Parent epic
${parent} — \`${epic_title}\`

${body}

---
Plan: \`docs/planning/use-cases-and-delivery-plan.md\`
EOF
)"

  if $DRY_RUN; then
    echo "[dry-run] $full_title → $ms_title ($target_date)"
    return 0
  fi

  local num
  num="$(issue_number_by_title "$full_title")"
  if [[ -n "$num" ]]; then
    gh issue edit "$num" --repo "$REPO" --body "$full_body" >/dev/null
    gh issue edit "$num" --repo "$REPO" --add-label "$labels" 2>/dev/null || true
    gh issue edit "$num" --repo "$REPO" --milestone "$ms_title" 2>/dev/null || true
    echo "updated #$num: $short"
  else
    num="$(gh issue create --repo "$REPO" --title "$full_title" --label "$labels" --body "$full_body" \
      --milestone "$ms_title" --json number --jq .number)"
    echo "created #$num: $short"
  fi
}

echo "==> Milestones"
ensure_milestone "Sprint W1 — Truth & demo target" "$MS_SPRINT_W1"
ensure_milestone "Sprint W2 — PoC" "$MS_SPRINT_W2"
ensure_milestone "Sprint W3 — Eval & ship" "$MS_SPRINT_W3"
ensure_milestone "Syllabus W8 — Demo / PoC" "$MS_W8_POC"
ensure_milestone "Syllabus W10 — v2 enrichments" "$MS_W10_V2"
ensure_milestone "Syllabus W11 — Evaluation" "$MS_W11_EVAL"
ensure_milestone "Syllabus W12 — Final webpage" "$MS_W12_SITE"

gh label create "type:task" --repo "$REPO" --color "EDEDED" --description "Subtask" 2>/dev/null || true

echo "==> UC1"
upsert_task 1 w1 must "Sprint W1 — Truth & demo target" "2026-06-02" "Week 8 prep" \
  "Add docs/demo-scenarios.md with Express fork URL, ref, expected counts" \
  "## Description
Frozen demo/eval target: fork \`expressjs/express\` at a pinned commit with real CVEs.

## Acceptance criteria
- [ ] Fork URL + ref in doc
- [ ] Record \`total_findings\`, \`auto_merge_count\`, \`review_required_count\` from one scan
- [ ] Scenarios A/B/C outlined

## Files
- \`docs/demo-scenarios.md\`"

upsert_task 1 w1 must "Sprint W1 — Truth & demo target" "2026-06-02" "Week 8 prep" \
  "Point dashboard demo button at Express fork (not only axios)" \
  "## Acceptance criteria
- [ ] Demo button uses ref from demo-scenarios.md
- [ ] HTMX scan smoke test passes

## Files
- \`arguss/web/templates/index.html\`"

upsert_task 1 w1 must "Sprint W1 — Truth & demo target" "2026-06-02" "Week 8 prep" \
  "Verify Fly URL + demo auth for class reviewers" \
  "## Acceptance criteria
- [ ] \`/health\` ok on Fly
- [ ] Demo credentials documented for team (not in git)
- [ ] Mode A works in production"

upsert_task 1 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8 — Demo / PoC" \
  "Pre-warm OSV + trust cache for demo ref on Fly" \
  "## Acceptance criteria
- [ ] Full scan on Fly before live demo
- [ ] Duration noted in demo-script.md"

upsert_task 1 w2 should "Sprint W2 — PoC" "2026-06-09" "Week 8–9" \
  "Polish Mode A/B error messages (404 lockfile, rate limit, invalid zip)" \
  "## Files
- \`arguss/web/routes.py\`, \`dashboard.py\`, \`templates/error.html\`"

upsert_task 1 w11 must "Syllabus W11 — Evaluation" "2026-07-15" "Week 11" \
  "Document OSV vs Snyk finding overlap on Express fork" \
  "## Deliverable
Comparison table for Week 11 eval."

echo "==> UC2"
upsert_task 2 w1 must "Sprint W1 — Truth & demo target" "2026-06-02" "Week 8 prep" \
  "Create owned GitHub repo for Mode C dry-runs" \
  "## Acceptance criteria
- [ ] Test repo with lockfile + CI
- [ ] PAT tested; URL in demo-scenarios.md"

upsert_task 2 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Dry-run Mode C: open AUTO_MERGE PRs on test repo" \
  "## Acceptance criteria
- [ ] PRs opened; re-run idempotent
- [ ] PR body: agent did not merge"

upsert_task 2 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Finalize Mode C consent copy in index.html" \
  "## Files
- \`index.html\` — session PAT, open PRs only, no CI merge"

upsert_task 2 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 9" \
  "Polish results_with_actions.html (PR links, skipped, failures)" \
  "## Files
- \`results_with_actions.html\`"

upsert_task 2 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Document v1: AUTO_MERGE opens PR, does not merge after CI" \
  "## Files
- README, use-cases doc, 5W1H if applicable"

upsert_task 2 w3 could "Sprint W3 — Eval & ship" "2026-06-16" "Stretch" \
  "Stretch: poll GitHub CI status after PR open (display only)" "Optional."

upsert_task 2 w3 could "Sprint W3 — Eval & ship" "2026-06-16" "Post-v1" \
  "Stretch: feature-flag merge when CI green" "Optional / post-capstone."

echo "==> UC3"
upsert_task 3 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 10" \
  "Add web SBOM download after scan" \
  "## Files
- \`arguss/core/sbom.py\`, new dashboard/route endpoint"

upsert_task 3 w3 must "Sprint W3 — Eval & ship" "2026-06-16" "Week 12" \
  "Add sample CycloneDX JSON under docs/samples/" "Committed sample from Express fork scan."

upsert_task 3 w12 should "Syllabus W12 — Final webpage" "2026-07-22" "Week 12" \
  "Add SBOM section to GitHub Pages project site" "EO 14028 blurb + CLI + sample link."

echo "==> UC4"
upsert_task 4 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Write docs/demo-script.md (Mode A → review → optional C)" \
  "## Deliverable
\`docs/demo-script.md\` (~5 min flow)."

upsert_task 4 w1 must "Sprint W1 — Truth & demo target" "2026-06-02" "Week 6–8" \
  "Threat model: team review checklist + sign-off" \
  "## File
\`docs/threat-model.md\` — all team sign off in issue/PR."

upsert_task 4 w10 should "Syllabus W10 — v2 enrichments" "2026-07-08" "Week 10" \
  "Add per-IP rate limiting on public scan endpoints" "Document in threat model."

echo "==> UC5"
upsert_task 5 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8–11" \
  "Script demo scenario B (major bump → REVIEW_REQUIRED)" \
  "Expected veto: \`fix_kind.major\` in demo-scenarios.md."

upsert_task 5 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8–11" \
  "Script demo scenario C (trust veto → REVIEW_REQUIRED)" \
  "Expected trust.* veto in demo-scenarios.md."

upsert_task 5 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Rehearse scenario B on frozen fork" "Screenshot for webpage."

upsert_task 5 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Rehearse scenario C (fixture or fork)" "Trust-save demo moment."

upsert_task 5 w9 should "Syllabus W8 — Demo / PoC" "2026-06-24" "Week 9" \
  "Add collapsible Why this tier on finding card" \
  "## Files
- \`partials/_finding_card.html\`"

upsert_task 5 w10 could "Syllabus W10 — v2 enrichments" "2026-07-08" "Optional" \
  "Add per-entry Explain button (REVIEW_REQUIRED only)" "HTMX + Claude; no tier change."

upsert_task 5 w3 could "Sprint W3 — Eval & ship" "2026-06-16" "Week 11" \
  "Document blast-radius gap or add path-depth veto" "Engine gap vs 5W1H envelope."

echo "==> UC6"
upsert_task 6 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Pre-cache AI explanations for demo ref" "Populate SQLite on Fly."

upsert_task 6 w2 must "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Verify template fallback when ANTHROPIC_API_KEY unset" \
  "## Files
- \`arguss/engine/explanation.py\`"

upsert_task 6 w2 should "Sprint W2 — PoC" "2026-06-09" "Week 8" \
  "Document Anthropic spending cap in docs/ops.md" "Cap + degradation."

upsert_task 6 w11 should "Syllabus W11 — Evaluation" "2026-07-15" "Week 11" \
  "Week 11: rate 15–20 sample explanations" "Two reviewers; failure cases."

echo "==> UC7"
upsert_task 7 w10 could "Syllabus W10 — v2 enrichments" "2026-07-08" "Week 10" \
  "Add EPSS score to findings (display-only)" "No tier change."

upsert_task 7 w10 could "Syllabus W10 — v2 enrichments" "2026-07-08" "Week 10" \
  "Add CISA KEV flag on findings (display-only)" "Cached catalog."

upsert_task 7 w10 could "Syllabus W10 — v2 enrichments" "2026-07-08" "Week 10" \
  "Add results sort/filter by severity and tier" "Optional UI."

upsert_task 7 w3 could "Sprint W3 — Eval & ship" "2026-06-16" "Could" \
  "Document minimal incident triage via UC1 tier sort" "Short ops note."

echo "==> UC8"
upsert_task 8 w12 wont "Syllabus W12 — Final webpage" "2026-07-22" "Week 12" \
  "Add UC8 future-work blurb to project webpage" "Future work only."

echo "==> Shared"
upsert_task shared w3 should "Sprint W3 — Eval & ship" "2026-06-16" "Week 9" \
  "UI design pass: resolve template TODOs + Tailwind layout" \
  "Templates: index, results, finding card."

upsert_task shared w1 should "Sprint W1 — Truth & demo target" "2026-06-02" "Week 10 decision" \
  "Decide Scorecard/deps.dev: Won't v1 vs Week 10 — update docs" \
  "Update open gaps in use-cases doc."

update_epic() {
  local title="$1" body="$2" ms="$3"
  local num
  num="$(issue_number_by_title "$title")"
  [[ -z "$num" ]] && return 0
  if $DRY_RUN; then echo "[dry-run] epic: $title"; return 0; fi
  gh issue edit "$num" --repo "$REPO" --body "$body" >/dev/null
  gh issue edit "$num" --repo "$REPO" --milestone "$ms" 2>/dev/null || true
  echo "updated epic #$num"
}

echo "==> Cross-cutting epics"
update_epic "Pin frozen Express fork for demo + evaluation" \
  "**Target:** 2026-06-02 | **Syllabus:** Week 8 prep — see UC1 demo-scenarios task." \
  "Sprint W1 — Truth & demo target"
update_epic "Record backup demo video" \
  "**Target:** 2026-06-09 | **Syllabus:** Week 8 PoC — 3–5 min Fly walkthrough." \
  "Sprint W2 — PoC"
update_epic "Snyk vs Dependabot comparison (Express fork)" \
  "**Target:** 2026-07-15 | **Syllabus:** Week 11 eval." \
  "Syllabus W11 — Evaluation"
update_epic "GitHub Pages project site" \
  "**Target:** 2026-07-22 | **Syllabus:** Week 12 final webpage." \
  "Syllabus W12 — Final webpage"

echo ""
echo "Done. Project Roadmap: group by Milestone for dates."
