"""Rule engine: static checks over parsed MCP server entries.

Everything here is heuristic string/structure analysis. It never connects to a
server and never prints secret values (findings only carry location + length).
"""
from __future__ import annotations

import os
import re
from urllib.parse import parse_qsl, urlparse

from .loader import find_line
from .model import RANK, Finding

LLM01 = "LLM01:2025 Prompt Injection"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM03 = "LLM03:2025 Supply Chain"
LLM06 = "LLM06:2025 Excessive Agency"

RULES = {
    "MCP001": dict(
        title="Hardcoded secret in MCP configuration",
        why="Config files are plaintext, get synced, backed up or committed, and are readable by every process the agent runs. A leaked token gives an attacker whatever the token allows.",
        fix="Keep the secret in an OS keychain or secret manager and pass it by reference (e.g. ${env:NAME} or an input prompt). Rotate the exposed value.",
        owasp=[LLM02], cwe=["CWE-798"],
    ),
    "MCP002": dict(
        title="Unpinned server package or image",
        why="Runners such as npx and uvx resolve the version at every start. If the package or a maintainer account is compromised, the new code runs with your privileges the next time the agent launches.",
        fix="Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...) and update it deliberately after review.",
        owasp=[LLM03], cwe=["CWE-494", "CWE-829"],
    ),
    "MCP003": dict(
        title="Overly broad filesystem or sensitive path access",
        why="A prompt-injected or misbehaving agent can read or overwrite everything the path exposes, including SSH keys, cloud credentials and browser data.",
        fix="Restrict access to the specific project directory, keep credential directories out of scope and prefer read-only access.",
        owasp=[LLM06, LLM02], cwe=["CWE-732", "CWE-250"],
    ),
    "MCP004": dict(
        title="Remote server over cleartext HTTP",
        why="Tool calls, results and any credentials travel unencrypted and can be read or altered by anyone on the network path.",
        fix="Use https:// or a local stdio server.",
        owasp=[LLM02], cwe=["CWE-319"],
    ),
    "MCP005": dict(
        title="Third-party remote server (review trust)",
        why="The remote operator controls tool descriptions and behaviour and can change them without notice. Tool descriptions are read by the model, so they are a prompt-injection channel.",
        fix="Confirm you trust the operator, prefer self-hosted or pinned alternatives for sensitive work and re-review tool descriptions after updates.",
        owasp=[LLM01, LLM03], cwe=["CWE-829"],
    ),
    "MCP006": dict(
        title="Shell wrapper or inline code as server command",
        why="Launching a server through a shell string or inline code makes the effective command opaque, and a one-liner that downloads and executes content bypasses any review.",
        fix="Run a pinned, reviewed executable directly with explicit arguments.",
        owasp=[LLM03, LLM06], cwe=["CWE-78", "CWE-494"],
    ),
    "MCP007": dict(
        title="Security control disabled",
        why="Flags that skip sandboxing, permission prompts or TLS verification remove the safeguards that limit the damage of a compromised or manipulated agent.",
        fix="Remove the setting. If an exception is genuinely needed, scope it narrowly and document why.",
        owasp=[LLM06], cwe=["CWE-693", "CWE-295"],
    ),
    "MCP008": dict(
        title="Container run with excessive host privileges",
        why="A privileged container, or one that mounts the Docker socket or host root, is effectively root on the host, so a compromised server escapes its isolation.",
        fix="Drop --privileged, never mount docker.sock, mount only specific directories read-only and add only the capabilities needed.",
        owasp=[LLM06], cwe=["CWE-250", "CWE-269"],
    ),
    "MCP009": dict(
        title="Command-execution capability",
        why="A server that can run commands turns any successful prompt injection into code execution on the host.",
        fix="Use it only inside a sandbox, VM or dev container, require confirmation per call and keep it out of clients that read untrusted content.",
        owasp=[LLM01, LLM06], cwe=["CWE-78"],
    ),
    "MCP010": dict(
        title="Untrusted input + private data + outbound channel in one agent",
        why="When one agent can read untrusted content, reach private data and communicate externally, an attacker who plants instructions in the content can make it exfiltrate the data (the 'lethal trifecta').",
        fix="Break the combination: split into separate profiles, remove or restrict the outbound channel, make private-data access read-only and narrow, or require human approval for outbound actions.",
        owasp=[LLM01, LLM02, LLM06], cwe=["CWE-1427"],
    ),
    "MCP011": dict(
        title="Tool calls auto-approved",
        why="Auto-approval removes the human check, so manipulated tool output can trigger writes, sends or deletes without anyone noticing.",
        fix="Auto-approve only read-only tools. Require confirmation for anything that writes, sends, executes or deletes.",
        owasp=[LLM06], cwe=["CWE-862"],
    ),
    "MCP012": dict(
        title="Config file with secrets readable by other users",
        why="Other local accounts and processes running as other users can read the credentials stored in the file.",
        fix="Restrict permissions (chmod 600) and move the secrets out of the file.",
        owasp=[LLM02], cwe=["CWE-732"],
    ),
    "MCP013": dict(
        title="Server launched from a temporary or download location",
        why="Temp and download folders are writable by other software and not reviewed. Replacing a file there gives code execution the next time the agent starts.",
        fix="Install the server in an owner-only directory and pin its version.",
        owasp=[LLM03], cwe=["CWE-829"],
    ),
}

# ----------------------------------------------------------------- helpers

SECRET_PATTERNS = [
    ("Private key", "critical", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key ID", "critical", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("API key (sk- prefix)", "high", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("Slack token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("Stripe key", "high", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("JSON Web Token", "high", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Bearer token", "high", re.compile(r"(?i)\bbearer\s+(?!\$|\{|<)[A-Za-z0-9._\-]{16,}")),
]
NAME_RE = re.compile(
    r"(token|secret|passw|api[_\-]?key|apikey|private[_\-]?key|credential|authorization|access[_\-]?key|bearer)",
    re.I,
)
_PLACEHOLDER = re.compile(
    r"^(<.*>|\[.*\]|your[_\- ].*|x{3,}|\*+|\.{3}|change-?me|todo.*|example.*|placeholder.*|null|none|true|false|\d+)$",
    re.I,
)
_ENVNAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _is_ref(value: str) -> bool:
    v = value.strip()
    return v.startswith("$") or "${" in v or bool(re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", v))


def _secret_hit(key, value):
    for kind, sev, rx in SECRET_PATTERNS:
        if rx.search(value):
            return kind, sev
    if key and NAME_RE.search(key) and len(value) >= 6:
        v = value.strip()
        if not (_is_ref(v) or _PLACEHOLDER.match(v) or _ENVNAME.match(v)):
            return f"Credential-like value for '{key.lstrip('-')}'", "high"
    return None


def _basename(cmd: str) -> str:
    b = cmd.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return re.sub(r"\.(exe|cmd|bat|ps1)$", "", b)


def _norm(p: str) -> str:
    return p.strip().strip("\"'").replace("\\", "/")


_SENSITIVE = re.compile(
    r"(^|/)\.(ssh|aws|gnupg|kube|azure|docker)(/|$)|(^|/)\.config/gcloud"
    r"|(^|/)\.(npmrc|netrc|git-credentials|pypirc)$|(^|/)id_(rsa|ed25519|ecdsa)",
    re.I,
)


def _is_broad(p: str) -> bool:
    n = _norm(p)
    if not n:
        return False
    if set(n) <= {"/"}:
        return True
    n2 = n.rstrip("/").lower()
    if n2 in {"~", "$home", "${home}", "%userprofile%", "${env:home}", "${userprofile}",
              "/users", "/home", "/root", "/etc", "/var", "/usr"}:
        return True
    if re.fullmatch(r"[a-z]:", n2) or re.fullmatch(r"/(users|home)/[^/]+", n2) or re.fullmatch(r"[a-z]:/users/[^/]+", n2):
        return True
    home = os.path.expanduser("~").replace("\\", "/").rstrip("/").lower()
    return bool(home) and n2 == home


class _Ctx:
    def __init__(self, sf, server):
        cfg = server.config
        self.sf, self.name, self.cfg = sf, server.name, cfg
        self.command = str(cfg.get("command") or "")
        raw = cfg.get("args") or []
        self.args = [str(a) for a in raw] if isinstance(raw, list) else [str(raw)]
        env = cfg.get("env") or {}
        self.env = {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}
        hdr = cfg.get("headers") or {}
        self.headers = {str(k): str(v) for k, v in hdr.items()} if isinstance(hdr, dict) else {}
        self.url = str(cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or "")
        self.base = _basename(self.command)
        self.findings: list[Finding] = []

    def add(self, rule_id, severity, location, detail, hint=None, fix=None):
        meta = RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id, severity=severity, title=meta["title"], server=self.name,
            file=self.sf.path, line=find_line(self.sf.text, self.name, hint),
            location=location, detail=detail, why=meta["why"], fix=fix or meta["fix"],
            owasp=list(meta["owasp"]), cwe=list(meta["cwe"]),
        ))

    def has(self, rule_id):
        return any(f.rule_id == rule_id for f in self.findings)


# ----------------------------------------------------------------- rules


def rule_secrets(c: _Ctx):
    seen = set()

    def check(location, key, value, hint):
        if location in seen:
            return
        hit = _secret_hit(key, value)
        if hit:
            seen.add(location)
            kind, sev = hit
            c.add("MCP001", sev, location,
                  f"{kind} found in {location} (value redacted, {len(value)} chars).", hint)

    for k, v in c.env.items():
        check(f"env.{k}", k, v, k)
    for k, v in c.headers.items():
        check(f"headers.{k}", k, v, k)
    for i, a in enumerate(c.args):
        check(f"args[{i}]", None, a, a)
        if "=" in a:
            key, _, val = a.lstrip("-").partition("=")
            check(f"args[{i}]", key, val, a)
        elif a.startswith("-") and NAME_RE.search(a) and i + 1 < len(c.args) and not c.args[i + 1].startswith("-"):
            check(f"args[{i + 1}]", a.lstrip("-"), c.args[i + 1], c.args[i + 1])
    if c.url:
        u = urlparse(c.url)
        if u.password and not _is_ref(u.password):
            c.add("MCP001", "high", "url", f"Credentials embedded in URL (redacted, {len(u.password)} chars).", u.netloc.split("@")[0])
        for k, v in parse_qsl(u.query):
            check(f"url?{k}", k, v, k)
        check("url", None, c.url, "url")


_RUNNER_VALUE_FLAGS = {"-p", "--package", "--from", "--with"}


def _runner_package(c: _Ctx):
    """Return (ecosystem, spec) when the command is a package runner."""
    base, rest = c.base, list(c.args)
    if base in ("npx", "bunx", "pnpx"):
        eco = "npm"
    elif base == "npm" and rest[:1] in (["exec"], ["x"]):
        eco, rest = "npm", rest[1:]
    elif base in ("pnpm", "yarn") and rest[:1] == ["dlx"]:
        eco, rest = "npm", rest[1:]
    elif base == "bun" and rest[:1] == ["x"]:
        eco, rest = "npm", rest[1:]
    elif base == "uvx":
        eco = "py"
    elif base == "uv" and rest[:2] == ["tool", "run"]:
        eco, rest = "py", rest[2:]
    elif base == "pipx" and rest[:1] == ["run"]:
        eco, rest = "py", rest[1:]
    else:
        return None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in _RUNNER_VALUE_FLAGS and i + 1 < len(rest):
            return eco, rest[i + 1]
        if a.startswith("--") and "=" in a and a.split("=", 1)[0] in _RUNNER_VALUE_FLAGS:
            return eco, a.split("=", 1)[1]
        if not a.startswith("-"):
            return eco, a
        i += 1
    return None


def _pin_status(eco: str, spec: str) -> str:
    if spec.startswith((".", "/", "file:", "~")):
        return "local"
    if spec.startswith(("git+", "github:", "http:", "https:", "git:")):
        return "pinned" if re.search(r"[#@][0-9a-f]{40}$", spec) else "unpinned"
    if eco == "npm":
        at = spec.find("@", 1)
        if at == -1:
            return "unpinned"
        ver = spec[at + 1:]
        if ver in ("", "latest", "next", "*", "beta", "canary", "nightly"):
            return "latest"
        return "pinned" if re.fullmatch(r"v?\d+\.\d+\.\d+([\-+][\w.\-+]+)?", ver) else "range"
    if "==" in spec and "*" not in spec:
        return "pinned"
    m = re.fullmatch(r"[^@=<>~!]+@([\w.\-+]+)", spec)
    if m:
        return "latest" if m.group(1) == "latest" else "pinned"
    if re.search(r"[<>~!]=?|=", spec):
        return "range"
    return "unpinned"


def rule_unpinned(c: _Ctx):
    pkg = _runner_package(c)
    if pkg:
        eco, spec = pkg
        status = _pin_status(eco, spec)
        if status in ("unpinned", "latest"):
            c.add("MCP002", "medium", "command/args",
                  f"'{spec}' is not pinned to an exact version" + (" ('latest')." if status == "latest" else "."), spec)
        elif status == "range":
            c.add("MCP002", "low", "command/args", f"'{spec}' uses a version range, not an exact version.", spec)


_PATH_FLAG_SKIP = ("docker", "podman", "nerdctl")


def rule_paths(c: _Ctx):
    if c.base in _PATH_FLAG_SKIP:
        return
    for i, a in enumerate(c.args):
        cands = [a]
        if a.startswith("-") and "=" in a:
            cands.append(a.split("=", 1)[1])
        for cand in cands:
            n = _norm(cand)
            if _is_broad(cand):
                c.add("MCP003", "high", f"args[{i}]", f"args[{i}] exposes a very broad location ('{n}').", a)
                break
            if _SENSITIVE.search(n):
                c.add("MCP003", "high", f"args[{i}]", f"args[{i}] points at a credentials location ('{n}').", a)
                break


def rule_remote(c: _Ctx):
    if not c.url:
        return
    u = urlparse(c.url)
    host = (u.hostname or "").lower()
    local = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".localhost")
    if local:
        return
    if u.scheme == "http":
        c.add("MCP004", "high", "url", f"Remote server '{host}' is reached over plain http.", "url")
    else:
        c.add("MCP005", "info", "url", f"Remote server '{host}' is operated by a third party.", "url")


_SHELLS = {"sh", "bash", "zsh", "dash", "fish", "ksh", "cmd", "powershell", "pwsh"}
_SHELL_C = {"-c", "/c", "/k", "-command", "-encodedcommand", "-enc", "-ec"}
_INLINE = {"node": {"-e", "--eval", "-p"}, "python": {"-c"}, "python3": {"-c"}, "deno": {"eval"}}
_DANGEROUS_PIPE = re.compile(
    r"(curl|wget|iwr|invoke-webrequest)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b|base64\s+(-d|--decode)|-encodedcommand|\beval\b",
    re.I,
)


def rule_shell(c: _Ctx):
    lowered = {a.lower() for a in c.args}
    if c.base in _SHELLS and lowered & _SHELL_C:
        script = " ".join(c.args)
        if _DANGEROUS_PIPE.search(script):
            c.add("MCP006", "critical", "command/args",
                  f"'{c.base}' runs a script that downloads, decodes or evals content before executing it.", "command")
        else:
            c.add("MCP006", "medium", "command/args", f"Server is launched through a '{c.base}' command string.", "command")
    elif c.base in _INLINE and lowered & _INLINE[c.base]:
        c.add("MCP006", "medium", "command/args", f"Server is launched with inline code ('{c.base}').", "command")


_DANGEROUS_FLAG = re.compile(
    r"^--(dangerously-[a-z\-]+|no-sandbox|disable-sandbox|disable-web-security|allow-all|yolo|insecure|"
    r"unsafe[a-z\-]*|ignore-certificate-errors)$",
    re.I,
)


def rule_disabled_controls(c: _Ctx):
    for i, a in enumerate(c.args):
        flag = a.split("=", 1)[0]
        if _DANGEROUS_FLAG.match(flag) or (c.base == "deno" and a in ("-A", "--allow-all")):
            c.add("MCP007", "high", f"args[{i}]", f"Flag '{flag}' disables a safety control.", a)
    for k in ("NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY"):
        if c.env.get(k, "").strip().lower() in ("0", "false"):
            c.add("MCP007", "high", f"env.{k}", f"{k} disables TLS certificate verification.", k)


_DOCKER_VALUE_FLAGS = {
    "-v", "--volume", "-e", "--env", "-p", "--publish", "--name", "--network", "--net", "-w", "--workdir",
    "-u", "--user", "--mount", "--entrypoint", "--env-file", "-l", "--label", "--platform", "--cap-add",
    "--cap-drop", "-m", "--memory", "--cpus", "--pid", "--ipc", "--add-host", "--restart", "--security-opt",
    "--device", "--tmpfs", "--hostname", "-h",
}


def rule_docker(c: _Ctx):
    if c.base not in _PATH_FLAG_SKIP or "run" not in c.args:
        return
    args, i, image, flags = c.args, c.args.index("run") + 1, None, []
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if "=" in a:
                flags.append(tuple(a.split("=", 1)))
            elif a in _DOCKER_VALUE_FLAGS and i + 1 < len(args):
                flags.append((a, args[i + 1]))
                i += 1
            else:
                flags.append((a, None))
        else:
            image = a
            break
        i += 1
    for flag, val in flags:
        v = (val or "").strip()
        if flag == "--privileged":
            c.add("MCP008", "high", "args", "Container runs with --privileged.", flag)
        elif flag in ("--cap-add",) and v.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"):
            c.add("MCP008", "high", "args", f"Container adds capability {v.upper()}.", flag)
        elif flag in ("--network", "--net") and v == "host":
            c.add("MCP008", "medium", "args", "Container shares the host network namespace.", flag)
        elif flag == "--pid" and v == "host":
            c.add("MCP008", "high", "args", "Container shares the host PID namespace.", flag)
        elif flag == "--security-opt" and "unconfined" in v:
            c.add("MCP008", "high", "args", f"Container disables a security profile ({v}).", flag)
        elif flag in ("-v", "--volume", "--mount"):
            sources = []
            if flag == "--mount":
                for part in v.split(","):
                    k, _, pv = part.partition("=")
                    if k in ("source", "src"):
                        sources.append(pv)
            else:
                sources.append(v.split(":")[0])
            for s in sources:
                if "docker.sock" in s:
                    c.add("MCP008", "critical", "args", "Container mounts the Docker socket (host root equivalent).", s)
                elif _is_broad(s) or _SENSITIVE.search(_norm(s)):
                    c.add("MCP008", "high", "args", f"Container mounts a broad or sensitive host path ('{_norm(s)}').", s)
    if image and "@sha256:" not in image:
        last = image.rsplit("/", 1)[-1]
        tag = last.split(":", 1)[1] if ":" in last else None
        if tag in (None, "latest"):
            c.add("MCP002", "medium", "args", f"Image '{image}' has no version tag (resolves to latest).", image)
        else:
            c.add("MCP002", "low", "args", f"Image '{image}' is tagged but not pinned by digest.", image)


_WRITE_LIKE = re.compile(r"(write|delete|remove|exec|run|shell|push|send|create|update|drop|commit|merge)", re.I)


def rule_auto_approve(c: _Ctx):
    for key in ("autoApprove", "alwaysAllow", "auto_approve", "autoapprove"):
        v = c.cfg.get(key)
        if v is None:
            continue
        names = [str(x) for x in v] if isinstance(v, list) else []
        if v is True or v == "*" or "*" in names or "all" in [n.lower() for n in names]:
            c.add("MCP011", "high", key, f"'{key}' approves every tool call without confirmation.", key)
        elif names:
            risky = [n for n in names if _WRITE_LIKE.search(n)]
            if risky:
                c.add("MCP011", "medium", key, f"'{key}' auto-approves state-changing tools: {', '.join(risky[:5])}.", key)
            else:
                c.add("MCP011", "low", key, f"'{key}' auto-approves {len(names)} tool(s); confirm they are read-only.", key)
    if c.cfg.get("trust") is True:
        c.add("MCP011", "high", "trust", "'trust: true' skips tool-call confirmation for this server.", "trust")


_TEMP = re.compile(r"^(/tmp/|/var/tmp/|/private/tmp/|/dev/shm/|%temp%|\$tmpdir|~/downloads/)|/downloads/|/temp/|/appdata/local/temp/", re.I)


def rule_temp_location(c: _Ctx):
    for cand in [c.command] + c.args[:3]:
        if _TEMP.search(_norm(cand)):
            c.add("MCP013", "medium", "command/args", f"Server is launched from '{_norm(cand)}'.", cand)
            return


CAPS = {
    "untrusted": ["fetch", "browser", "puppeteer", "playwright", "brave", "tavily", "firecrawl", "scrape", "crawl",
                  "web-search", "websearch", "web_search", "gmail", "imap", "slack", "discord", "telegram", "github",
                  "gitlab", "jira", "confluence", "notion", "zendesk", "intercom", "reddit", "twitter"],
    "private": ["filesystem", "postgres", "mysql", "sqlite", "mongo", "redis", "supabase", "snowflake", "bigquery",
                "gdrive", "google-drive", "googledrive", "gmail", "slack", "github", "gitlab", "notion", "1password",
                "vault", "secrets", "aws", "kubectl", "kubernetes", "ssh", "obsidian", "jira", "confluence",
                "salesforce", "hubspot"],
    "egress": ["fetch", "browser", "puppeteer", "playwright", "gmail", "smtp", "email", "slack", "discord",
               "telegram", "twilio", "webhook", "zapier", "n8n", "github", "gitlab", "curl", "shell",
               "desktop-commander"],
    "exec": ["shell", "terminal", "desktop-commander", "command-runner", "run-command", "ssh", "kubectl",
             "code-runner", "e2b", "python-repl", "jupyter"],
}
_PATHISH = re.compile(r"^(/|~|\./|\.\./|[A-Za-z]:[\\/])")


def _capabilities(c: _Ctx) -> set:
    host = (urlparse(c.url).hostname or "") if c.url else ""
    parts = [c.name, c.base, host] + [a for a in c.args if not _PATHISH.match(a)]
    hay = " ".join(parts).lower()
    return {cap for cap, words in CAPS.items() if any(w in hay for w in words)}


def rule_exec_capability(c: _Ctx, caps: set):
    if "exec" in caps and c.base not in _SHELLS:
        c.add("MCP009", "medium", "server", f"Server '{c.name}' appears to provide command execution.", c.name)


SERVER_RULES = [rule_secrets, rule_unpinned, rule_paths, rule_remote, rule_shell,
                rule_disabled_controls, rule_docker, rule_auto_approve, rule_temp_location]


def _trifecta(sf, per_server):
    union = {cap: [n for n, caps in per_server if cap in caps] for cap in ("untrusted", "private", "egress")}
    if not all(union.values()):
        return []
    single = any({"untrusted", "private", "egress"} <= caps for _, caps in per_server)
    meta = RULES["MCP010"]
    detail = ("Agent can read untrusted content [{u}], reach private data [{p}] and communicate outward [{e}]."
              .format(u=", ".join(dict.fromkeys(union["untrusted"])), p=", ".join(dict.fromkeys(union["private"])),
                      e=", ".join(dict.fromkeys(union["egress"]))))
    return [Finding(
        rule_id="MCP010", severity="high" if single else "medium", title=meta["title"], server="*",
        file=sf.path, line=1, location="file", detail=detail, why=meta["why"], fix=meta["fix"],
        owasp=list(meta["owasp"]), cwe=list(meta["cwe"]),
    )]


def _file_permissions(sf, findings):
    if os.name != "posix" or not any(f.rule_id == "MCP001" for f in findings):
        return []
    try:
        mode = os.stat(sf.path).st_mode & 0o777
    except OSError:
        return []
    if not mode & 0o044:
        return []
    meta = RULES["MCP012"]
    return [Finding(
        rule_id="MCP012", severity="medium", title=meta["title"], server="*", file=sf.path, line=1,
        location="file", detail=f"File mode is {oct(mode)[2:]} and the file contains secrets.",
        why=meta["why"], fix=meta["fix"], owasp=list(meta["owasp"]), cwe=list(meta["cwe"]),
    )]


def audit_file(sf) -> list[Finding]:
    findings, per_server = [], []
    for server in sf.servers:
        c = _Ctx(sf, server)
        for rule in SERVER_RULES:
            rule(c)
        caps = _capabilities(c)
        rule_exec_capability(c, caps)
        per_server.append((server.name, caps))
        findings.extend(c.findings)
    findings.extend(_trifecta(sf, per_server))
    findings.extend(_file_permissions(sf, findings))
    findings.sort(key=lambda f: (-RANK[f.severity], f.line, f.rule_id))
    return findings
