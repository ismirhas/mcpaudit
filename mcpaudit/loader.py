"""Discover and parse MCP configuration files (JSON or JSONC)."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from .model import ScannedFile, Server

SERVER_KEYS = ("mcpServers", "servers", "mcp_servers", "context_servers")
SERVER_HINTS = ("command", "url", "args", "serverUrl", "httpUrl", "type")
KNOWN_RELATIVE = (
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "claude_desktop_config.json",
    "mcp_config.json",
)


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments (outside strings) and trailing commas."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and text[i + 1 : i + 2] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
        elif c == "/" and text[i + 1 : i + 2] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def find_line(text: str, name: str, hint: str | None = None) -> int:
    """Best-effort 1-based line number of a server (or a key/value inside it)."""
    lines = text.splitlines()
    key = json.dumps(name, ensure_ascii=False)
    start = None
    for i, line in enumerate(lines):
        if re.search(re.escape(key) + r"\s*:", line):
            start = i
            break
    if start is None:
        return 1
    if hint:
        for j in range(start, min(start + 80, len(lines))):
            if hint in lines[j]:
                return j + 1
    return start + 1


def _looks_like_server(cfg) -> bool:
    return isinstance(cfg, dict) and any(k in cfg for k in SERVER_HINTS)


def find_servers(obj, found=None):
    found = [] if found is None else found
    if isinstance(obj, dict):
        for key, val in obj.items():
            if (
                key in SERVER_KEYS
                and isinstance(val, dict)
                and val
                and all(isinstance(v, dict) for v in val.values())
                and any(_looks_like_server(v) for v in val.values())
            ):
                for name, cfg in val.items():
                    found.append((str(name), cfg))
            else:
                find_servers(val, found)
    elif isinstance(obj, list):
        for item in obj:
            find_servers(item, found)
    return found


def default_locations(cwd=None, home=None, env=None, system=None) -> list[Path]:
    cwd = Path(cwd) if cwd else Path.cwd()
    home = Path(home) if home else Path.home()
    env = os.environ if env is None else env
    system = system or sys.platform
    locs = [
        cwd / ".mcp.json",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
        home / ".cursor" / "mcp.json",
        home / ".claude.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
    ]
    if system == "darwin":
        support = home / "Library/Application Support"
        locs += [support / "Claude/claude_desktop_config.json", support / "Code/User/mcp.json"]
    elif system.startswith("win"):
        appdata, local = env.get("APPDATA"), env.get("LOCALAPPDATA")
        if appdata:
            locs += [Path(appdata) / "Claude" / "claude_desktop_config.json",
                     Path(appdata) / "Code" / "User" / "mcp.json"]
        if local:
            # Microsoft Store (MSIX) installs keep per-app data under Packages.
            try:
                for pkg in sorted((Path(local) / "Packages").glob("Claude_*")):
                    locs.append(pkg / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json")
            except OSError:
                pass
    else:
        locs += [home / ".config/Claude/claude_desktop_config.json", home / ".config/Code/User/mcp.json"]
    return list(dict.fromkeys(locs))


def expand_targets(paths: list[str]) -> tuple[list[Path], list[str]]:
    """Resolve CLI paths to config files. Returns (files, problems)."""
    files, problems = [], []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            hits = [p / rel for rel in KNOWN_RELATIVE if (p / rel).is_file()]
            if hits:
                files.extend(hits)
            else:
                problems.append(f"{raw}: directory contains no known MCP config file")
        else:
            problems.append(f"{raw}: no such file or directory")
    return list(dict.fromkeys(files)), problems


def load_file(path) -> ScannedFile:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        return ScannedFile(str(p), "", [], f"cannot read file: {exc}")
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = json.loads(strip_jsonc(text))
        except ValueError as exc:
            return ScannedFile(str(p), text, [], f"invalid JSON/JSONC: {exc}")
    if not isinstance(data, dict):
        return ScannedFile(str(p), text, [], "top-level JSON value is not an object")
    servers = [Server(n, c, str(p), find_line(text, n)) for n, c in find_servers(data)]
    return ScannedFile(str(p), text, servers)
