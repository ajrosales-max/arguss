# Lockfile test fixtures

npm `package-lock.json` inputs for the Week 3 parser. Fixtures use **`lockfileVersion: 2`** or **`3`** (parser supports both).

| File | Source | Direct deps | Total deps | Notes |
|------|--------|-------------|------------|--------|
| `minimal.json` | Hand-crafted (Week 3 plan Step 1) | 1 | **1** | `left-pad@1.3.0` only; no transitive deps. |
| `minimal-v2.json` | Hand-crafted (v2 chalk tree) | 1 | **6** | Same `packages` tree as `with-transitive.json` plus v1-style top-level `dependencies` for backward-compat testing. |
| `with-transitive.json` | Real output of `npm install chalk@4.1.2` in a fresh project | 1 | **6** | Do not edit by hand. |
| `real-world.json` | Real output of `npm install express@4.17.0` in a fresh project | 1 | **50** | Do not edit by hand. |

Total deps counts `packages` keys whose path starts with `node_modules/` (same as `docs/planning/cursor-prompts/arguss-week-3-step-1-cursor-prompt.md`). After regenerating a fixture, re-run that count and update this table if the tree changed.

## Regenerating `with-transitive.json`

Requires **npm 7+** (lockfile v3). From a temporary directory:

```bash
mkdir -p /tmp/arguss-fixture-2 && cd /tmp/arguss-fixture-2
npm init -y
npm install chalk@4.1.2 --no-audit --no-fund
# copy package-lock.json to tests/fixtures/lockfiles/with-transitive.json
```

## Regenerating `real-world.json`

```bash
mkdir -p /tmp/arguss-fixture-3 && cd /tmp/arguss-fixture-3
npm init -y
npm install express@4.17.0 --no-audit --no-fund
# copy package-lock.json to tests/fixtures/lockfiles/real-world.json
```

## Regenerating `minimal.json`

Only if the Week 3 plan’s Step 1 spec changes. Copy the JSON from `docs/planning/arguss-week-3-plan.md` (Step 1 — `minimal.json`); do not “improve” the structure by hand.

## Verification

```bash
ls tests/fixtures/lockfiles/
# Expect: README.md, minimal.json, minimal-v2.json, with-transitive.json, real-world.json

for f in tests/fixtures/lockfiles/*.json; do
  python3 -c "import json; d=json.load(open('$f')); v=d.get('lockfileVersion'); assert v in (2,3), v; print(f\"$f: lockfileVersion={v}\")"
done
```

`with-transitive.json` and `real-world.json` must always come from real `npm install` output (synthetic lockfiles would not exercise npm’s `packages` path encoding correctly).
