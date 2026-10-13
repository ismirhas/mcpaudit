from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Server:
    name: str
    config: dict
    file: str
    line: int


@dataclass
class ScannedFile:
    path: str
    text: str
    servers: list = field(default_factory=list)
    error: str | None = None


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    server: str
    file: str
    line: int
    location: str
    detail: str
    why: str
    fix: str
    owasp: list
    cwe: list

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    files: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    checked: list = field(default_factory=list)  # default locations looked at
