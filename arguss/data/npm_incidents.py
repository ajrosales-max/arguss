"""Load and match curated npm malware incidents for Top Packages."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

_DEFAULT_PATH = Path(__file__).resolve().with_name("npm_incidents.json")


@dataclass(frozen=True)
class NpmIncident:
    incident_id: str
    name: str
    date_range: tuple[date, date]
    packages: frozenset[str]
    description: str
    link: str | None = None


@dataclass(frozen=True)
class IncidentMatch:
    """A package matched to a curated incident via malware advisory date."""

    incident: NpmIncident
    advisory_id: str
    published: str


def load_npm_incidents(path: Path | None = None) -> list[NpmIncident]:
    """Load curated incidents from JSON. Missing/invalid file → empty list."""
    source = path if path is not None else _DEFAULT_PATH
    if not source.is_file():
        return []
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, list):
        return []

    incidents: list[NpmIncident] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        parsed = _parse_incident(item)
        if parsed is not None:
            incidents.append(parsed)
    return incidents


def _parse_incident(item: dict[str, Any]) -> NpmIncident | None:
    incident_id = item.get("incident_id")
    name = item.get("name")
    date_range = item.get("date_range")
    packages = item.get("packages")
    description = item.get("description")
    if not isinstance(incident_id, str) or not incident_id.strip():
        return None
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(description, str):
        return None
    if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
        return None
    if (
        not isinstance(date_range, list)
        or len(date_range) != 2
        or not all(isinstance(d, str) for d in date_range)
    ):
        return None
    try:
        start = date.fromisoformat(date_range[0])
        end = date.fromisoformat(date_range[1])
    except ValueError:
        return None
    if end < start:
        return None
    link_raw = item.get("link")
    link = link_raw if isinstance(link_raw, str) and link_raw.strip() else None
    return NpmIncident(
        incident_id=incident_id.strip(),
        name=name.strip(),
        date_range=(start, end),
        packages=frozenset(p for p in packages if p.strip()),
        description=description,
        link=link,
    )


def _advisory_date(published: object) -> date | None:
    if not isinstance(published, str) or not published.strip():
        return None
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        # Accept bare YYYY-MM-DD
        try:
            return date.fromisoformat(published[:10])
        except ValueError:
            return None
    return dt.date()


def match_package_to_incidents(
    package_name: str,
    malware_advisories: list[dict[str, Any]],
    incidents: list[NpmIncident],
) -> list[IncidentMatch]:
    """Match when package is listed AND a malware advisory falls in date_range.

    Both conditions required. Returns one match per (incident, advisory) pair;
    callers typically take the first incident for display.
    """
    matches: list[IncidentMatch] = []
    for incident in incidents:
        if package_name not in incident.packages:
            continue
        start, end = incident.date_range
        for adv in malware_advisories:
            if not adv.get("is_malware"):
                continue
            pub_day = _advisory_date(adv.get("published"))
            if pub_day is None or pub_day < start or pub_day > end:
                continue
            adv_id = adv.get("id")
            pub_raw = adv.get("published")
            matches.append(
                IncidentMatch(
                    incident=incident,
                    advisory_id=str(adv_id) if adv_id is not None else "—",
                    published=str(pub_raw) if isinstance(pub_raw, str) else "",
                )
            )
    return matches


def build_incident_match_report(
    packages: list[tuple[str, list[dict[str, Any]]]],
    incidents: list[NpmIncident] | None = None,
) -> dict[str, list[dict[str, str]]]:
    """incident_id → [{package, advisory_id, published}, ...] for verification."""
    catalog = incidents if incidents is not None else load_npm_incidents()
    report: dict[str, list[dict[str, str]]] = {i.incident_id: [] for i in catalog}
    for name, malware_advisories in packages:
        for match in match_package_to_incidents(name, malware_advisories, catalog):
            report[match.incident.incident_id].append(
                {
                    "package": name,
                    "advisory_id": match.advisory_id,
                    "published": match.published,
                }
            )
    return report
