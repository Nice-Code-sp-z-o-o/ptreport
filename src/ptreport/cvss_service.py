"""CVSS scoring (2.0, 3.0, 3.1, 4.0) and metric definitions for the UI calculator.

Scoring is delegated to the ``cvss`` library (Red Hat Product Security), which
implements the official FIRST algorithms including the CVSS 4.0 macro-vector
lookup tables. The server is the single source of truth for scores: the browser
only builds vectors and asks this module for the result.
"""

from __future__ import annotations

from dataclasses import dataclass

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

VERSIONS = ("4.0", "3.1", "3.0", "2.0")
_V3_TEMPORAL = {"E", "RL", "RC"}
_V3_ENVIRONMENTAL = {"CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
MAX_VECTOR_LEN = 512


@dataclass(frozen=True)
class CvssResult:
    version: str
    vector: str
    base_score: float
    score: float
    severity: str  # one of SEVERITIES in validation (lower-case)

    def as_dict(self) -> dict:
        return {
            "valid": True,
            "version": self.version,
            "vector": self.vector,
            "base_score": self.base_score,
            "score": self.score,
            "severity": self.severity,
            "rating": rating_for_score(self.score, self.version),
        }


class CvssInvalid(ValueError):
    pass


def _severity_from_label(label: str | None) -> str:
    label = (label or "none").lower()
    return "info" if label == "none" else label


def _v2_severity(score: float) -> str:
    # NVD qualitative ranges for CVSS v2 (the spec itself defines none).
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def rating_for_score(score: float | None, version: str) -> str:
    """Qualitative CVSS rating of a score (none, low, medium, high, critical); '' when there is no score."""
    if score is None:
        return ""
    if version == "2.0":
        sev = _v2_severity(score)
        return "none" if sev == "info" else sev
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def detect_version(vector: str) -> str:
    v = vector.strip()
    if v.startswith("CVSS:4.0/"):
        return "4.0"
    if v.startswith("CVSS:3.1/"):
        return "3.1"
    if v.startswith("CVSS:3.0/"):
        return "3.0"
    return "2.0"


def _normalize_v2(vector: str) -> str:
    v = vector.strip()
    if v.startswith("CVSS2#"):
        v = v[len("CVSS2#"):]
    if v.startswith("(") and v.endswith(")"):
        v = v[1:-1]
    return v


def score_vector(vector: str, expected_version: str | None = None) -> CvssResult:
    """Validate a vector and compute its score. Raises CvssInvalid on any problem."""
    if not isinstance(vector, str) or not vector.strip():
        raise CvssInvalid("CVSS vector is required.")
    if len(vector) > MAX_VECTOR_LEN:
        raise CvssInvalid("CVSS vector is too long.")

    version = detect_version(vector)
    if expected_version and expected_version != version:
        raise CvssInvalid(
            f"Vector does not match the selected CVSS version {expected_version}."
        )

    try:
        if version == "4.0":
            c4 = CVSS4(vector.strip())
            score = float(c4.base_score)
            return CvssResult(version, c4.clean_vector(), score, score,
                              _severity_from_label(c4.severity))
        if version in ("3.0", "3.1"):
            c3 = CVSS3(vector.strip())
            # The environmental equation differs from the base one even with no environmental metrics
            # (Scope:Changed uses 0.9731 and power 13 in 3.1), so pick the score of the most specific
            # metric group actually present in the vector.
            keys = {part.split(":", 1)[0] for part in c3.clean_vector().split("/")[1:]}
            idx = 2 if keys & _V3_ENVIRONMENTAL else (1 if keys & _V3_TEMPORAL else 0)
            scores = c3.scores()
            return CvssResult(version, c3.clean_vector(), float(scores[0]), float(scores[idx]),
                              _severity_from_label(c3.severities()[idx]))
        c2 = CVSS2(_normalize_v2(vector))
        scores = [s for s in c2.scores() if s is not None]
        effective = float(scores[-1])
        return CvssResult(version, c2.clean_vector(), float(scores[0]), effective,
                          _v2_severity(effective))
    except CVSSError as exc:
        raise CvssInvalid(f"Invalid CVSS {version} vector: {exc}") from None


# --------------------------------------------------------------------------- #
# Metric definitions consumed by static/cvss.js. Order matters: vectors are
# built in this order, which matches the order mandated by each specification.
# --------------------------------------------------------------------------- #

def _m(key: str, name: str, values: list[tuple[str, str]]) -> dict:
    return {"key": key, "name": name, "values": [{"key": k, "name": n} for k, n in values]}


_CIA3 = [("H", "High"), ("L", "Low"), ("N", "None")]

_V3_GROUPS = [
    {
        "name": "Base",
        "required": True,
        "metrics": [
            _m("AV", "Attack Vector", [("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")]),
            _m("AC", "Attack Complexity", [("L", "Low"), ("H", "High")]),
            _m("PR", "Privileges Required", [("N", "None"), ("L", "Low"), ("H", "High")]),
            _m("UI", "User Interaction", [("N", "None"), ("R", "Required")]),
            _m("S", "Scope", [("U", "Unchanged"), ("C", "Changed")]),
            _m("C", "Confidentiality", _CIA3),
            _m("I", "Integrity", _CIA3),
            _m("A", "Availability", _CIA3),
        ],
    },
    {
        "name": "Temporal",
        "required": False,
        "not_defined": "X",
        "metrics": [
            _m("E", "Exploit Code Maturity", [("X", "Not Defined"), ("U", "Unproven"), ("P", "Proof-of-Concept"), ("F", "Functional"), ("H", "High")]),
            _m("RL", "Remediation Level", [("X", "Not Defined"), ("O", "Official Fix"), ("T", "Temporary Fix"), ("W", "Workaround"), ("U", "Unavailable")]),
            _m("RC", "Report Confidence", [("X", "Not Defined"), ("U", "Unknown"), ("R", "Reasonable"), ("C", "Confirmed")]),
        ],
    },
]

_CIA2 = [("N", "None"), ("P", "Partial"), ("C", "Complete")]
_CIA4 = [("H", "High"), ("L", "Low"), ("N", "None")]

METRIC_DEFINITIONS: dict[str, dict] = {
    "4.0": {
        "prefix": "CVSS:4.0",
        "groups": [
            {
                "name": "Base: Exploitability",
                "required": True,
                "metrics": [
                    _m("AV", "Attack Vector", [("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")]),
                    _m("AC", "Attack Complexity", [("L", "Low"), ("H", "High")]),
                    _m("AT", "Attack Requirements", [("N", "None"), ("P", "Present")]),
                    _m("PR", "Privileges Required", [("N", "None"), ("L", "Low"), ("H", "High")]),
                    _m("UI", "User Interaction", [("N", "None"), ("P", "Passive"), ("A", "Active")]),
                ],
            },
            {
                "name": "Base: Vulnerable System Impact",
                "required": True,
                "metrics": [
                    _m("VC", "Confidentiality", _CIA4),
                    _m("VI", "Integrity", _CIA4),
                    _m("VA", "Availability", _CIA4),
                ],
            },
            {
                "name": "Base: Subsequent System Impact",
                "required": True,
                "metrics": [
                    _m("SC", "Confidentiality", _CIA4),
                    _m("SI", "Integrity", _CIA4),
                    _m("SA", "Availability", _CIA4),
                ],
            },
            {
                "name": "Threat",
                "required": False,
                "not_defined": "X",
                "metrics": [
                    _m("E", "Exploit Maturity", [("X", "Not Defined"), ("A", "Attacked"), ("P", "POC"), ("U", "Unreported")]),
                ],
            },
        ],
    },
    "3.1": {"prefix": "CVSS:3.1", "groups": _V3_GROUPS},
    "3.0": {"prefix": "CVSS:3.0", "groups": _V3_GROUPS},
    "2.0": {
        "prefix": "",
        "groups": [
            {
                "name": "Base",
                "required": True,
                "metrics": [
                    _m("AV", "Access Vector", [("L", "Local"), ("A", "Adjacent Network"), ("N", "Network")]),
                    _m("AC", "Access Complexity", [("H", "High"), ("M", "Medium"), ("L", "Low")]),
                    _m("Au", "Authentication", [("M", "Multiple"), ("S", "Single"), ("N", "None")]),
                    _m("C", "Confidentiality Impact", _CIA2),
                    _m("I", "Integrity Impact", _CIA2),
                    _m("A", "Availability Impact", _CIA2),
                ],
            },
            {
                "name": "Temporal",
                "required": False,
                "not_defined": "ND",
                "metrics": [
                    _m("E", "Exploitability", [("ND", "Not Defined"), ("U", "Unproven"), ("POC", "Proof-of-Concept"), ("F", "Functional"), ("H", "High")]),
                    _m("RL", "Remediation Level", [("ND", "Not Defined"), ("OF", "Official Fix"), ("TF", "Temporary Fix"), ("W", "Workaround"), ("U", "Unavailable")]),
                    _m("RC", "Report Confidence", [("ND", "Not Defined"), ("UC", "Unconfirmed"), ("UR", "Uncorroborated"), ("C", "Confirmed")]),
                ],
            },
        ],
    },
}


# --------------------------------------------------------------------------- #
# Vector strip: tone (0..3 = how much a value raises the score within its
# metric) and display group per metric. One mapping shared by the server-side
# strip (templates) and the browser (via the cvss-defs JSON, key "tone").
# [TO CONFIRM with the score logic owner: final level mapping.]
# --------------------------------------------------------------------------- #

_TONES_V4 = {
    "AV": {"N": 3, "A": 2, "L": 1, "P": 0}, "AC": {"L": 3, "H": 1},
    "AT": {"N": 3, "P": 1}, "PR": {"N": 3, "L": 2, "H": 1},
    "UI": {"N": 3, "P": 2, "A": 1},
    **{k: {"H": 3, "L": 1, "N": 0} for k in ("VC", "VI", "VA", "SC", "SI", "SA")},
    "E": {"A": 3, "P": 2, "U": 1},
}
_TONES_V3 = {
    "AV": {"N": 3, "A": 2, "L": 1, "P": 0}, "AC": {"L": 3, "H": 1},
    "PR": {"N": 3, "L": 2, "H": 1}, "UI": {"N": 3, "R": 1}, "S": {"U": 0, "C": 2},
    **{k: {"H": 3, "L": 1, "N": 0} for k in ("C", "I", "A")},
    "E": {"H": 3, "F": 2, "P": 1, "U": 0}, "RL": {"U": 3, "W": 2, "T": 1, "O": 0},
    "RC": {"C": 3, "R": 2, "U": 1},
}
_TONES_V2 = {
    "AV": {"N": 3, "A": 2, "L": 1}, "AC": {"L": 3, "M": 2, "H": 1}, "Au": {"N": 3, "S": 2, "M": 1},
    **{k: {"C": 3, "P": 1, "N": 0} for k in ("C", "I", "A")},
    "E": {"H": 3, "F": 2, "POC": 1, "U": 0}, "RL": {"U": 3, "W": 2, "TF": 1, "OF": 0},
    "RC": {"C": 3, "UR": 2, "UC": 1},
}
_TONES = {"4.0": _TONES_V4, "3.1": _TONES_V3, "3.0": _TONES_V3, "2.0": _TONES_V2}

_STRIP_GROUPS = {
    "4.0": [("Exploitability", ("AV", "AC", "AT", "PR", "UI")), ("Vulnerable system", ("VC", "VI", "VA")),
            ("Subsequent system", ("SC", "SI", "SA")), ("Threat", ("E",))],
    "3.1": [("Exploitability", ("AV", "AC", "PR", "UI")), ("Scope", ("S",)), ("Impact", ("C", "I", "A")),
            ("Temporal", ("E", "RL", "RC"))],
    "2.0": [("Exploitability", ("AV", "AC", "Au")), ("Impact", ("C", "I", "A")),
            ("Temporal", ("E", "RL", "RC"))],
}
_STRIP_GROUPS["3.0"] = _STRIP_GROUPS["3.1"]


def _decorate_definitions() -> None:
    """Add ``tone`` to every value and ``strip_group`` to every metric (in place)."""
    for version, definition in METRIC_DEFINITIONS.items():
        group_of = {key: name for name, keys in _STRIP_GROUPS[version] for key in keys}
        for group in definition["groups"]:
            for metric in group["metrics"]:
                tones = _TONES[version].get(metric["key"], {})
                metric["strip_group"] = group_of.get(metric["key"], group["name"])
                for value in metric["values"]:
                    value["tone"] = tones.get(value["key"], 0)


_decorate_definitions()


def vector_strip(vector: str | None) -> list[dict]:
    """Parse a stored vector into display groups for the strip.

    Returns ``[{"name": str, "cells": [{"key", "value", "name", "value_name",
    "tone", "group"}]}]``. Unknown metrics and not-defined values are skipped;
    an unparsable vector yields an empty list.
    """
    if not isinstance(vector, str) or not vector.strip():
        return []
    version = detect_version(vector)
    definition = METRIC_DEFINITIONS[version]
    text = vector.strip()
    if version == "2.0":
        text = _normalize_v2(text)
    selected: dict[str, str] = {}
    for part in text.split("/"):
        key, sep, value = part.partition(":")
        if sep and key != "CVSS":
            selected[key] = value
    groups: dict[str, list[dict]] = {}
    for group in definition["groups"]:
        for metric in group["metrics"]:
            value = selected.get(metric["key"])
            if value is None or value == group.get("not_defined"):
                continue
            match = next((v for v in metric["values"] if v["key"] == value), None)
            if match is None:
                continue
            groups.setdefault(metric["strip_group"], []).append({
                "key": metric["key"], "value": value, "name": metric["name"],
                "value_name": match["name"], "tone": match["tone"],
                "group": metric["strip_group"],
            })
    order = [name for name, _ in _STRIP_GROUPS[version]]
    return [{"name": n, "cells": groups[n]} for n in order if n in groups]
