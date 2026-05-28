# GitHub Project setup — Arguss use cases

Easiest path: **script creates labeled issues** → **one Project board** with custom fields → drag cards by week/status.

Repo: `ajrosales-max/arguss`

---

## Prerequisites (one time)

```bash
# Project + issue scopes for gh CLI
gh auth refresh -s project,read:project

# From repo root
cd /path/to/arguss
```

---

## Option A — Fastest (recommended, ~10 minutes)

### 1. Create epic issues

```bash
./scripts/bootstrap-github-project.sh
```

This creates labels, **8 UC epics**, and a few cross-cutting epics (Express fork, demo video, etc.).

### 2. Create granular tasks (under each UC)

```bash
./scripts/bootstrap-github-project-tasks.sh --dry-run   # preview ~35 tasks
./scripts/bootstrap-github-project-tasks.sh
```

Task titles look like **`[UC1][task] Verify Fly URL + demo auth`**. Each body links to the parent epic (`#N`). Labels: `type:task`, `UC*`, `sprint:w*`, `priority:*`.

Skip duplicates: re-running is safe (same title = skip).

### 2b. Add details, target dates, and milestones (after tasks exist)

```bash
./scripts/sync-github-project-tasks.sh --dry-run
./scripts/sync-github-project-tasks.sh
```

This **updates** every `[UC*][task]` issue (and cross-cutting epics) with:

- Schedule table: target date, sprint, syllabus week, milestone name
- Description, acceptance criteria, file paths
- GitHub **Milestone** due dates (Sprint W1–W3 + Syllabus W8/W10/W11/W12)

| Milestone | Due date |
|-----------|----------|
| Sprint W1 — Truth & demo target | 2026-06-02 |
| Sprint W2 — PoC | 2026-06-09 |
| Sprint W3 — Eval & ship | 2026-06-16 |
| Syllabus W8 — Demo / PoC | 2026-06-24 |
| Syllabus W10 — v2 enrichments | 2026-07-08 |
| Syllabus W11 — Evaluation | 2026-07-15 |
| Syllabus W12 — Final webpage | 2026-07-22 |

### 2c. Roadmap timeline dates (Project fields)

GitHub **Roadmap** uses **Project** fields `Start date` and `Target date` (`YYYY-MM-DD`). Issue milestones do **not** automatically appear on the timeline.

```bash
gh auth refresh -s project,read:project
./scripts/sync-github-project-roadmap.sh --dry-run
./scripts/sync-github-project-roadmap.sh
```

Then in the Project UI: switch to **Roadmap** → **Configure** (gear) → set **Start date field** = `Start date`, **Target date field** = `Target date`.

| Date source | Start | Target (due) |
|-------------|-------|----------------|
| Sprint W1 | 2026-05-27 | 2026-06-02 |
| Sprint W2 | 2026-06-03 | 2026-06-09 |
| Sprint W3 | 2026-06-10 | 2026-06-16 |
| Syllabus W8 (PoC) | 2026-06-17 | 2026-06-24 |
| Syllabus W10 | 2026-07-01 | 2026-07-08 |
| Syllabus W11 (Eval) | 2026-07-08 | 2026-07-15 |
| Syllabus W12 (Site) | 2026-07-15 | 2026-07-22 |

**Minimum for Roadmap:** `Target date` alone works (item shows as a point on that day). **Start + Target** draws a bar across the sprint/week.

### 3. Create the Project in the UI

1. GitHub → **Projects** → **New project** → **Board** (or **Roadmap** for a timeline).
2. Name: **Arguss Capstone — Summer 2026**.
3. **Link repository:** `ajrosales-max/arguss`.
4. **Add all open issues** (filter label `capstone-plan`).

### 4. Add custom fields

Project → **⋯** → **Settings** → **Fields**:

| Field | Type | Options |
|-------|------|---------|
| **Status** | Status | Backlog, This week, In progress, In review, Done |
| **UC** | Single select | UC1 … UC8 |
| **Priority** | Single select | Must, Should, Could, Won't |
| **Week** | Single select | Week 8–14, Sprint W1–W3 |
| **Owner** | Single select | Team names |

### 5. Views

- **Board** — group by Status
- **Roadmap** — group by Week (milestone screenshots)
- **Table** — filter `priority:must`

---

## Option B — UI only (~8 issues)

Create one issue per UC; paste acceptance criteria from [`use-cases-and-delivery-plan.md`](use-cases-and-delivery-plan.md).

---

## Option C — Full CLI

```bash
gh project create --owner ajrosales-max --title "Arguss Capstone — Summer 2026"
gh project link PROJECT_NUMBER --owner ajrosales-max --repo ajrosales-max/arguss
```

Field setup is faster in the UI than `gh project field-create`.

---

## Sync with docs

| Narrative | Execution |
|-----------|-----------|
| `use-cases-and-delivery-plan.md` | GitHub issues + Project |

Check off acceptance criteria in issues as you ship; update the markdown at milestones if instructors need a static export.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `missing required scopes [read:project]` | `gh auth refresh -s project,read:project` |
| Duplicate issues on re-run | Script skips existing titles |
