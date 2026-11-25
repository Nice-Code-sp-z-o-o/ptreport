"""CWE weaknesses.

The full MITRE catalogue (names, descriptions, potential mitigations) ships with ptreport in
``data/cwe.json.gz``. Any ``CWE-<number>`` is accepted by validation.
"""

from __future__ import annotations

import gzip
import json
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "cwe.json.gz"


@lru_cache(maxsize=1)
def _catalogue() -> dict:
    """MITRE's CWE catalogue bundled with ptreport (see scripts/update_cwe.py)."""
    with gzip.open(_DATA_FILE, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def catalogue_version() -> str:
    return _catalogue()["version"]


def _entry(number: int) -> dict | None:
    return _catalogue()["entries"].get(str(number))


def _names() -> dict[int, str]:
    return {int(k): v["n"] for k, v in _catalogue()["entries"].items()}


def cwe_number(cwe: str) -> int | None:
    if cwe and cwe.upper().startswith("CWE-") and cwe[4:].isdigit():
        return int(cwe[4:])
    return None


def cwe_name(cwe: str) -> str:
    number = cwe_number(cwe)
    entry = _entry(number) if number is not None else None
    return entry["n"] if entry else ""


def cwe_reference(cwe: str) -> dict:
    """MITRE's text for a CWE: {name, description, mitigation} ('' when unknown)."""
    number = cwe_number(cwe)
    entry = _entry(number) if number is not None else None
    if not entry:
        return {"name": "", "description": "", "mitigation": ""}
    return {"name": entry["n"], "description": entry["d"], "mitigation": entry["m"]}


def cwe_url(cwe: str) -> str:
    number = cwe_number(cwe)
    return f"https://cwe.mitre.org/data/definitions/{number}.html" if number is not None else ""


def cwe_choices() -> list[tuple[str, str]]:
    """(CWE-n, name) for the autocomplete; the first common alias (e.g. "SQL Injection") is appended."""
    out = []
    for key, entry in sorted(_catalogue()["entries"].items(), key=lambda kv: int(kv[0])):
        alias = entry.get("a") or []
        out.append((f"CWE-{key}", entry["n"] + (f" ({alias[0]})" if alias else "")))
    return out


def search(query: str, limit: int = 80) -> list[tuple[str, str]]:
    """CWEs by number, name or description; exact number first, then name matches, then description matches."""
    q = query.strip().lower()
    if not q:
        return []
    number = q.upper().removeprefix("CWE-").strip()
    exact, by_name, by_text = [], [], []
    for key, entry in _catalogue()["entries"].items():
        aliases = entry.get("a", [])
        label = entry["n"] + (f" ({', '.join(aliases)})" if aliases else "")
        row = (f"CWE-{key}", label)
        if number.isdigit() and key == str(int(number)):
            exact.append(row)
        elif q in label.lower():
            by_name.append(row)
        elif len(q) >= 3 and q in entry["d"].lower():
            by_text.append(row)
    return (exact + by_name + by_text)[:limit]
