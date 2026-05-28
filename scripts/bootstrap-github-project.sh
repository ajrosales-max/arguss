#!/usr/bin/env bash
# Create Arguss capstone planning issues from use-cases-and-delivery-plan.md
# Usage: ./scripts/bootstrap-github-project.sh [--dry-run]
set -euo pipefail

REPO="${ARGUSS_GITHUB_REPO:-ajrosales-max/arguss}"
DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI not found. Install: https://cli.github.com/" >&2
  exit 1
fi

gh auth status >/dev/null 2>&1 || {
  echo "error: run 'gh auth login' first" >&2
  exit 1
}

create_label() {
  local name="$1" color="$2" description="$3"
  if $DRY_RUN; then
    echo "[dry-run] label: $name"
    return 0
  fi
  gh label create "$name" --repo "$REPO" --color "$color" --description "$description" 2>/dev/null || true
}

issue_exists() {
  local title="$1"
  gh issue list --repo "$REPO" --search "in:title \"${title}\"" --json title --jq ".[] | select(.title == \"${title}\") | .title" | grep -q .
}

create_issue() {
  local title="$1"
  local labels="$2"
  local body="$3"
  if issue_exists "$title"; then
    echo "skip (exists): $title"
    return 0
  fi
  if $DRY_RUN; then
    echo "[dry-run] issue: $title  labels=$labels"
    return 0
  fi
  gh issue create --repo "$REPO" --title "$title" --label "$labels" --body "$body"
  echo "created: $title"
}

echo "==> Labels"
create_label "capstone-plan" "0E8A16" "Capstone delivery plan item"
for i in 1 2 3 4 5 6 7 8; do
  create_label "UC${i}" "1D76DB" "Use case UC${i}"
done
create_label "priority:must" "B60205" "MoSCoW Must"
create_label "priority:should" "D93F0B" "MoSCoW Should"
create_label "priority:could" "FBCA04" "MoSCoW Could"
create_label "priority:wont" "CCCCCC" "MoSCoW Won't"
for w in w1 w2 w3; do
  create_label "sprint:${w}" "5319E7" "Three-week sprint ${w}"
done

echo "==> Epic issues (UC1–UC8)"

create_issue "[UC1] Read-only dependency audit" "capstone-plan,UC1,priority:must,sprint:w1" "$(cat <<'EOF'
**MoSCoW:** Must | **Modes:** A, B

## Acceptance criteria
- [x] Mode A + B shipped
- [ ] Frozen Express fork documented
- [ ] Fly demo URL verified for reviewers

Doc: `docs/planning/use-cases-and-delivery-plan.md`
EOF
)"

create_issue "[UC2] Auto-remediate low-impact upgrades" "capstone-plan,UC2,priority:must,sprint:w2" "$(cat <<'EOF'
**MoSCoW:** Must | **Mode:** C | **v1:** open PRs only (no CI merge)

## Acceptance criteria
- [x] Fix-confidence + Mode C PR open
- [ ] Dry-run on owned test repo
- [ ] Optional: CI poll + merge (stretch)
EOF
)"

create_issue "[UC3] SBOM for compliance audit" "capstone-plan,UC3,priority:must,sprint:w3" "$(cat <<'EOF'
**MoSCoW:** Must

## Acceptance criteria
- [x] CLI `arguss sbom`
- [ ] Web SBOM export
- [ ] Sample artifact for project webpage
EOF
)"

create_issue "[UC4] Evaluate before granting GitHub PAT" "capstone-plan,UC4,priority:must,sprint:w1" "$(cat <<'EOF'
**MoSCoW:** Must

## Acceptance criteria
- [x] A/B without PAT; Mode C consent
- [ ] Demo script A → optional C
- [ ] Threat model team sign-off
EOF
)"

create_issue "[UC5] Fix-confidence on contested fix" "capstone-plan,UC5,priority:should,sprint:w2" "$(cat <<'EOF'
**MoSCoW:** Should

## Acceptance criteria
- [x] Verdict + finding card UI
- [ ] Scenarios B & C scripted
- [ ] "Why this tier" UI polish
EOF
)"

create_issue "[UC6] AI-generated explanations" "capstone-plan,UC6,priority:should,sprint:w2" "$(cat <<'EOF'
**MoSCoW:** Should

## Acceptance criteria
- [x] Executive summary + fallback
- [ ] Pre-cache demo explanations
- [ ] Document Anthropic spending cap
EOF
)"

create_issue "[UC7] Incident triage" "capstone-plan,UC7,priority:could" "$(cat <<'EOF'
**MoSCoW:** Could | Week 10+

- [ ] EPSS/KEV display
- [ ] Sort/filter UI
EOF
)"

create_issue "[UC8] Org-wide rollout" "capstone-plan,UC8,priority:wont" "$(cat <<'EOF'
**MoSCoW:** Won't — document as future work only.
EOF
)"

echo "==> Task issues"

create_issue "Pin frozen Express fork for demo + evaluation" "capstone-plan,UC1,UC5,priority:must,sprint:w1" "Fork express at pinned commit; add docs/demo-scenarios.md."
create_issue "Record backup demo video" "capstone-plan,UC1,UC6,priority:must,sprint:w2" "Week 8 PoC: Fly walkthrough with pre-cached scan."
create_issue "Snyk vs Dependabot comparison (Express fork)" "capstone-plan,UC1,UC2,priority:must,sprint:w3" "Week 11 evaluation table."
create_issue "GitHub Pages project site" "capstone-plan,priority:must,sprint:w3" "Week 12 final deliverable webpage."

echo ""
echo "Done. See docs/planning/github-project-setup.md"
