"""Output formats: text, JSON, SARIF 2.1.0."""
from __future__ import annotations

import json
import textwrap
from collections import Counter
from pathlib import Path

from . import __version__
from .model import RANK, SEVERITIES, ScanResult
from .rules import RULES

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
NOTE = ("Static analysis of configuration only: mcpaudit does not connect to servers, read tool "
        "descriptions at runtime or prove exploitability. Findings are heuristics.")


def summary_counts(result: ScanResult) -> Counter:
    return Counter(f.severity for f in result.findings)


def render_text(result: ScanResult, color: bool = False) -> str:
    def paint(sev, text):
        return f"{_COLORS[sev]}{text}{_RESET}" if color else text

    out = [f"mcpaudit {__version__} - static audit of MCP / agent configuration", ""]
    explained: set[str] = set()
    by_file: dict[str, list] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)
    for sf in result.files:
        n = len(sf.servers)
        out.append(f"{sf.path}  ({n} server{'s' if n != 1 else ''})")
        if sf.error:
            out.append(f"  ! not scanned: {sf.error}")
        for f in by_file.get(sf.path, []):
            where = f"{f.server} / {f.location}" if f.server != "*" else f.location
            out.append(f"  [{paint(f.severity, f.severity.upper())}] {f.rule_id} {f.title}")
            out.append(f"      at {where}, line {f.line}")
            rows = [("What", f.detail)]
            if f.rule_id not in explained:
                rows += [("Why", f.why), ("Fix", f.fix)]
                explained.add(f.rule_id)
            else:
                rows.append(("Why/Fix", f"same as the first {f.rule_id} finding above."))
            for label, text in rows:
                out.append(textwrap.fill(text, width=92, initial_indent=f"      {label}: ",
                                         subsequent_indent=" " * (8 + len(label))))
            out.append(f"      Ref: {'; '.join(f.owasp)}; {', '.join(f.cwe)}")
            out.append("")
        if not by_file.get(sf.path) and not sf.error:
            out.append("  no findings")
            out.append("")
    counts = summary_counts(result)
    total = len(result.findings)
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]]
    out.append("Summary: " + (f"{total} finding(s): " + ", ".join(parts) if total else "no findings"))
    scanned = [f for f in result.files if not f.error]
    out.append(f"Coverage: {len(scanned)} file(s) scanned, {sum(len(f.servers) for f in scanned)} server(s).")
    errors = [f for f in result.files if f.error]
    if errors:
        out.append(f"          {len(errors)} file(s) could not be scanned (see above).")
    if result.checked:
        out.append(f"          Auto-discovery checked {len(result.checked)} default location(s).")
    out.append(NOTE)
    return "\n".join(out) + "\n"


def render_json(result: ScanResult) -> str:
    counts = summary_counts(result)
    doc = {
        "tool": "mcpaudit",
        "version": __version__,
        "summary": {"total": len(result.findings), **{s: counts[s] for s in SEVERITIES}},
        "coverage": {
            "files": [{"path": f.path, "servers": len(f.servers), "error": f.error} for f in result.files],
            "default_locations_checked": result.checked,
            "note": NOTE,
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for rid in sorted(RULES):
        meta = RULES[rid]
        rules.append({
            "id": rid,
            "name": meta["title"],
            "shortDescription": {"text": meta["title"]},
            "fullDescription": {"text": meta["why"]},
            "help": {"text": meta["fix"]},
            "properties": {
                "tags": ["security", "mcp"] + [f"external/cwe/{c.lower()}" for c in meta["cwe"]] + meta["owasp"],
            },
        })
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.detail} Fix: {f.fix}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": Path(f.file).as_posix()},
                "region": {"startLine": f.line},
            }}],
            "properties": {"security-severity": _SECURITY_SEVERITY[f.severity], "server": f.server,
                           "severity": f.severity, "owasp": f.owasp, "cwe": f.cwe},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcpaudit", "version": __version__, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
