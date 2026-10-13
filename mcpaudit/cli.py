from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .loader import default_locations, expand_targets, load_file
from .model import RANK, SEVERITIES, ScanResult
from .report import render_json, render_sarif, render_text
from .rules import RULES, audit_file

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcpaudit",
        description="Static security audit of MCP / AI-agent configuration files.",
        epilog="Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage error or unscannable input.",
    )
    p.add_argument("--version", action="version", version=f"mcpaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan config files (auto-discovers common locations if no path is given)")
    s.add_argument("paths", nargs="*", help="config files or directories")
    s.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    s.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    s.add_argument("--no-color", action="store_true")
    sub.add_parser("rules", help="list all rules")
    return p


def _scan(args) -> int:
    result = ScanResult()
    if args.paths:
        files, problems = expand_targets(args.paths)
        for msg in problems:
            print(f"mcpaudit: {msg}", file=sys.stderr)
        if not files:
            return EXIT_ERROR
    else:
        locs = default_locations()
        result.checked = [str(p) for p in locs]
        files = [p for p in locs if p.is_file()]
        problems = []
        if not files:
            print("mcpaudit: no MCP config files found in default locations:", file=sys.stderr)
            for p in locs:
                print(f"  {p}", file=sys.stderr)
            print("Pass a path explicitly: mcpaudit scan <file>", file=sys.stderr)
            return EXIT_OK
    for path in files:
        sf = load_file(path)
        result.files.append(sf)
        if not sf.error:
            result.findings.extend(audit_file(sf))
    floor = RANK[args.min_severity]
    result.findings = [f for f in result.findings if RANK[f.severity] >= floor]

    if args.format == "json":
        text = render_json(result)
    elif args.format == "sarif":
        text = render_sarif(result)
    else:
        color = (not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
        text = render_text(result, color)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"mcpaudit: report written to {args.output} ({len(result.findings)} finding(s))", file=sys.stderr)
    else:
        sys.stdout.write(text)

    if args.fail_on != "none" and any(RANK[f.severity] >= RANK[args.fail_on] for f in result.findings):
        return EXIT_FINDINGS
    if any(sf.error for sf in result.files):
        return EXIT_ERROR
    return EXIT_OK


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["scan"]
    elif argv[0] not in ("scan", "rules", "-h", "--help", "--version"):
        argv = ["scan"] + argv
    args = build_parser().parse_args(argv)
    if args.cmd == "rules":
        for rid in sorted(RULES):
            print(f"{rid}  {RULES[rid]['title']}")
        return EXIT_OK
    return _scan(args)


if __name__ == "__main__":
    sys.exit(main())
