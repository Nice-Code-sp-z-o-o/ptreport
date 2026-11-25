"""Rebuild src/ptreport/data/cwe.json.gz from MITRE's CWE catalogue (cwec_vX.Y.xml).

    curl -fsSLO https://cwe.mitre.org/data/xml/cwec_latest.xml.zip && unzip cwec_latest.xml.zip
    python scripts/update_cwe.py cwec_v5.0.xml

Keeps, per weakness and category: name, description, extended description and potential mitigations
(formatted as "Phase: ... - text" paragraphs, as pentest reports quote them). Deprecated entries are dropped.
CWE is (c) The MITRE Corporation, see src/ptreport/data/CWE-LICENSE.txt.
"""

from __future__ import annotations

import gzip
import json
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - build-time tool on MITRE's own file
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src" / "ptreport" / "data" / "cwe.json.gz"


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child(el, name):
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def paragraphs(el) -> str:
    """Text of an element that may hold xhtml paragraphs/lists; paragraphs separated by blank lines."""
    if el is None:
        return ""
    blocks = []
    if el.text and el.text.strip():
        blocks.append(el.text)
    for c in el:
        name = local(c.tag)
        if name in ("ul", "ol"):
            blocks.append("\n".join("- " + " ".join("".join(li.itertext()).split()) for li in c))
        else:
            blocks.append("".join(c.itertext()))
        if c.tail and c.tail.strip():
            blocks.append(c.tail)
    out = []
    for b in blocks:
        if b.startswith("- "):
            out.append(b.strip())
        else:
            text = " ".join(b.split())
            if text:
                out.append(text)
    return "\n\n".join(out)


def mitigations(el) -> str:
    pm = child(el, "Potential_Mitigations")
    if pm is None:
        return ""
    items = []
    for m in pm:
        phases = [" ".join(p.text.split()) for p in m if local(p.tag) == "Phase" and p.text]
        desc = paragraphs(child(m, "Description"))
        if not desc:
            continue
        prefix = f"Phase: {', '.join(phases)} - " if phases else ""
        items.append(prefix + desc)
    return "\n\n".join(items)


def main(path: str) -> None:
    root = ET.parse(path).getroot()  # noqa: S314 - MITRE's catalogue, build time only
    version = root.get("Version", "")
    entries = {}
    for el in root.iter():
        kind = local(el.tag)
        if kind not in ("Weakness", "Category") or el.get("Status") == "Deprecated":
            continue
        cwe_id = int(el.get("ID"))
        name = " ".join((el.get("Name") or "").split())
        if kind == "Weakness":
            description = paragraphs(child(el, "Description"))
            extended = paragraphs(child(el, "Extended_Description"))
            text = "\n\n".join(x for x in (description, extended) if x)
        else:
            text = paragraphs(child(el, "Summary"))
        alternate = []
        terms = child(el, "Alternate_Terms")
        for term in terms if terms is not None else []:
            t = child(term, "Term")
            if t is not None and t.text:
                alternate.append(" ".join(t.text.split()))
        entries[cwe_id] = {
            "a": alternate,
            "n": name,
            "k": "w" if kind == "Weakness" else "c",
            "d": re.sub(r"\n{3,}", "\n\n", text),
            "m": mitigations(el) if kind == "Weakness" else "",
        }
    data = {"version": version, "entries": {str(k): entries[k] for k in sorted(entries)}}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8", compresslevel=9) as fh:
        json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
    weaknesses = sum(1 for e in entries.values() if e["k"] == "w")
    print(f"CWE {version}: {weaknesses} weaknesses, {len(entries) - weaknesses} categories -> {OUT} "
          f"({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main(sys.argv[1])
