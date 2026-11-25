"""Capture demo data from the ptreport DB into data/*.json for the mockup generators. Prints counts only."""
import json
import sys
from pathlib import Path

from ptreport import export
from ptreport.cvss_service import METRIC_DEFINITIONS
from ptreport.cwe import cwe_name
from ptreport.db import connect

db_path, out_dir = sys.argv[1], Path(sys.argv[2])
conn = connect(db_path)
reports = [dict(r) for r in conn.execute("SELECT id FROM reports")]
ctxs = []
for r in reports:
    ctx = export.build_context(conn, r["id"])
    for f in ctx["findings"]:
        f["cwe_name"] = cwe_name(f["cwe"])
    ctxs.append({k: ctx[k] for k in ("report", "targets", "findings", "counts", "lang")})
(out_dir / "reports.json").write_text(json.dumps(ctxs, ensure_ascii=False, indent=1))
(out_dir / "cvss-metrics.json").write_text(json.dumps(METRIC_DEFINITIONS, indent=1))
print("reports", len(ctxs), "| findings", sum(len(c["findings"]) for c in ctxs),
      "| targets", sum(len(c["targets"]) for c in ctxs))
print("finding fields:", sorted(ctxs[0]["findings"][0].keys()) if ctxs and ctxs[0]["findings"] else [])
