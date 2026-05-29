# `arguss.engine` — remediation decisions

Maps findings to upgrade proposals and fix-confidence verdicts.

## Files

| File | Purpose |
|------|---------|
| [`propose.py`](propose.py) | Orchestrator → `ProposalReport` |
| [`fix_discovery.py`](fix_discovery.py) | OSV fixed version → `FixCandidate` |
| [`fix_kind.py`](fix_kind.py) | patch / minor / major classification |
| [`fix_confidence.py`](fix_confidence.py) | Tier, score, reasons, veto signals |
| [`kill_switch.py`](kill_switch.py) | Halt all auto-merges |
| [`project_scores.py`](project_scores.py) | Lens subscores for results UI |
| [`explanation.py`](explanation.py) | Deterministic text when AI is off |
| [`__init__.py`](__init__.py) | Package marker |
