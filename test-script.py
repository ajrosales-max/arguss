# One-shot cache inspection: pass the scan hash as argv or SCAN_HASH env var.
import json
import os
import sqlite3
import sys

scan_hash = os.environ.get("SCAN_HASH") or (sys.argv[1] if len(sys.argv) > 1 else None)
if not scan_hash:
    sys.exit("Usage: python test-script.py <scan_hash>  (or set SCAN_HASH)")

conn = sqlite3.connect("./arguss.db")
row = conn.execute(
    "SELECT response_json FROM api_cache WHERE source='scan_response' AND key=?",
    (scan_hash,),
).fetchone()
if row is None:
    sys.exit(f"No cached scan_response for key {scan_hash!r}")

data = json.loads(row[0])

deps_set = {(d["package"], d["version"]) for d in data.get("deps", [])}
findings_set = {
    (e["finding"]["dependency"]["name"], e["finding"]["dependency"]["version"])
    for e in data.get("entries", [])
}
no_fix_set = {
    (s["package"], s["current_version"])
    for s in data.get("skipped_findings", [])
    if s.get("kind") == "no_fix"
}
vulnerable = findings_set | no_fix_set

print(f"deps:        {len(deps_set)}")
print(f"vulnerable:  {len(vulnerable)}")
print(f"in vulnerable, NOT in deps: {len(vulnerable - deps_set)}")
print(f"in deps, in vulnerable:     {len(deps_set & vulnerable)}")
print(f"clean (deps - vulnerable):  {len(deps_set - vulnerable)}")
print()
print("First 15 (package, version) in vulnerable but NOT in deps:")
for pv in list(vulnerable - deps_set)[:15]:
    print(f"  {pv}")
