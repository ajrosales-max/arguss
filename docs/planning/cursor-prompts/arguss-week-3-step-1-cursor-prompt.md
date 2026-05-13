# Cursor prompt — Week 3, Step 1: test fixtures

This is the first branch of Week 3 work. Goal: get three real `package-lock.json` files into `tests/fixtures/lockfiles/` to serve as parser test inputs.

**Branch name:** `feature/lockfile-fixtures`

**Estimated time:** 30 minutes to 1 hour. This is the easiest step of the week — pure data, no logic.

---

## Before pasting into Cursor

Get on the new branch from clean main:

```bash
git checkout main
git pull
git checkout -b feature/lockfile-fixtures
```

You should also have `npm` installed locally — required for fixtures 2 and 3. Verify:

```bash
npm --version       # should be 7+ for lockfile v3 generation
node --version
```

If npm is older than 7, the lockfiles it generates will be v2 and the parser will reject them. Upgrade with `brew install node` (macOS) or `nvm install node`.

---

## The prompt to paste into Cursor

I'm starting Week 3 of the Arguss capstone project. The first task is creating test fixtures for the package-lock.json parser. I have a detailed plan in `arguss-week-3-plan.md` — please refer to Step 1 in that file for the full spec.

**The task: create three test fixtures in `tests/fixtures/lockfiles/`.**

1. **`minimal.json`** — a tiny hand-crafted lockfile with one direct dep (`left-pad@1.3.0`) and no transitive deps. Use the exact JSON contents specified in Step 1 of the plan.

2. **`with-transitive.json`** — a real lockfile from `npm install chalk@4.1.2` in a fresh project. I'll run the npm commands myself; you don't need to. After I generate it, I'll copy it into the fixtures folder.

3. **`real-world.json`** — a real lockfile from `npm install express@4.17.0`. Same approach as #2.

4. **`tests/fixtures/lockfiles/README.md`** — a short README documenting where each fixture came from, approximately how many deps each contains, and instructions for regenerating them.

**Critical rules:**

1. **Don't generate fixtures 2 and 3 with random data.** They MUST be real lockfiles produced by real `npm install` commands. Synthetic data would not exercise the parser correctly because npm's path-encoding for transitive deps is non-obvious and easy to get wrong.

2. **The minimal fixture is the only one to create directly.** Use the exact JSON contents from Step 1 of the Week 3 plan. Don't paraphrase or "improve" it.

3. **Don't touch any other code or files.** This branch is fixtures only. The parser comes next branch.

4. **Don't run npm yourself.** I'll handle the npm commands and copy the resulting files into the fixtures folder. You're responsible for the directory structure, the minimal fixture, and the README.

**Verification at the end:** `ls tests/fixtures/lockfiles/` should show exactly 4 files: `README.md`, `minimal.json`, `with-transitive.json`, `real-world.json`. Each lockfile file should validate as JSON and have `lockfileVersion: 3`.

**Start by:** Confirming you've read the rules above and that you have access to `arguss-week-3-plan.md`. Then create:

1. The directory `tests/fixtures/lockfiles/` if it doesn't exist
2. The `minimal.json` file with the exact contents from Step 1
3. The `README.md` template (I'll fill in the exact dep counts after generating the other fixtures)

After you've done those three things, wait for me — I'll generate `with-transitive.json` and `real-world.json` via npm and place them in the folder, then I'll come back to update the README counts.

---

## After Cursor finishes the directory + minimal fixture + README

Cursor will have created the structure and the minimal fixture. Now you generate the two real fixtures yourself:

### Generate `with-transitive.json`

```bash
mkdir -p /tmp/arguss-fixture-2
cd /tmp/arguss-fixture-2
npm init -y > /dev/null
npm install chalk@4.1.2 --no-audit --no-fund

# Verify it's v3
python3 -c "import json; print('lockfileVersion:', json.load(open('package-lock.json'))['lockfileVersion'])"

# Should print "lockfileVersion: 3"

# Copy it over
cp package-lock.json /Users/arosales_restore/Documents/MICS/C295/arguss/tests/fixtures/lockfiles/with-transitive.json
cd -
```

### Generate `real-world.json`

```bash
mkdir -p /tmp/arguss-fixture-3
cd /tmp/arguss-fixture-3
npm init -y > /dev/null
npm install express@4.17.0 --no-audit --no-fund

# Verify it's v3
python3 -c "import json; print('lockfileVersion:', json.load(open('package-lock.json'))['lockfileVersion'])"

# Copy it over
cp package-lock.json /Users/arosales_restore/Documents/MICS/C295/arguss/tests/fixtures/lockfiles/real-world.json
cd -
```

### Count the deps in each fixture

This tells you what numbers to put in the README:

```bash
cd /Users/arosales_restore/Documents/MICS/C295/arguss

for f in tests/fixtures/lockfiles/*.json; do
  count=$(python3 -c "
import json
data = json.load(open('$f'))
pkgs = data.get('packages', {})
deps = [k for k in pkgs if k.startswith('node_modules/')]
print(len(deps))
")
  echo "$f: $count deps"
done
```

You should see output like:

```
tests/fixtures/lockfiles/minimal.json: 1 deps
tests/fixtures/lockfiles/real-world.json: 50 deps
tests/fixtures/lockfiles/with-transitive.json: 7 deps
```

Numbers will vary slightly depending on chalk and express's exact dep trees at the version pinned.

### Then ask Cursor to update the README

> Update `tests/fixtures/lockfiles/README.md` with these actual dep counts:
> - minimal.json: 1 dep
> - with-transitive.json: 7 deps (or whatever you got)
> - real-world.json: 50 deps (or whatever you got)
>
> Keep the table format from before.

---

## Verification before committing

```bash
# All four files exist
ls tests/fixtures/lockfiles/

# All three lockfiles are valid JSON v3
for f in tests/fixtures/lockfiles/*.json; do
  python3 -c "import json; d=json.load(open('$f')); print('$f:', 'v' + str(d['lockfileVersion']))"
done

# Should print:
# tests/fixtures/lockfiles/minimal.json: v3
# tests/fixtures/lockfiles/real-world.json: v3
# tests/fixtures/lockfiles/with-transitive.json: v3
```

If any file shows v1 or v2, the `npm install` ran with an older npm. Upgrade and regenerate.

---

## Commit and push

```bash
git add tests/fixtures/lockfiles/
git commit -m "week3: add three lockfile test fixtures (minimal, transitive, real-world)"
git push -u origin feature/lockfile-fixtures
```

Then open a PR on GitHub:

```bash
gh pr create --base main --head feature/lockfile-fixtures \
  --title "Week 3 Step 1: lockfile test fixtures" \
  --body "Adds three real package-lock.json files for parser testing: a hand-crafted minimal fixture, a small real npm tree from chalk@4.1.2, and a larger tree from express@4.17.0. See tests/fixtures/lockfiles/README.md for details."
```

Wait for CI to pass, then merge. After merge:

```bash
git checkout main
git pull
git checkout -b feature/parser
```

That's the next branch — implementing the actual parser using these fixtures.

---

## Troubleshooting

**npm install warning about funding/audit messages:** ignore them. The `--no-audit --no-fund` flags suppress these but some still leak through. The lockfile is what matters.

**Lockfile is v2 instead of v3:** your npm is older than version 7. `node --version` should be 16+. Run `brew upgrade node` or use nvm to get a newer version. Delete the temp directory and start over.

**Lockfile has tons of extraneous fields like `engines`, `funding`, `deprecated`:** that's normal for real lockfiles. The parser ignores them.

**`express@4.17.0` gives a deprecation warning during install:** that's fine — older packages are exactly what we want here for testing known CVEs.

**Want a fixture with more aggressively old CVEs:** swap `express@4.17.0` for `npm install lodash@4.17.20 marked@0.3.6` in the fixture-3 step. Both have multiple known historical vulnerabilities, which makes the OSV integration tests in later steps more interesting. Save this for later if you want.

---

## What success looks like

End of this step, you have:

- A `feature/lockfile-fixtures` branch merged to main via PR
- Four files committed in `tests/fixtures/lockfiles/`
- A README documenting the source and contents of each fixture
- All three lockfiles validated as v3
- The CI workflow green on the PR

Then you're ready for the parser branch (`feature/parser`), which is the bulk of Week 3's work.
