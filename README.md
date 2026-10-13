# mcpaudit

Static security audit for **MCP and AI-agent configuration files**.

AI agents are only as safe as the tools wired into them. `mcpaudit` reads the config files for Claude Desktop, Claude Code, Cursor, VS Code and Windsurf, and reports what an attacker (or a prompt-injected agent) could do with the access you have granted: leaked secrets, unpinned packages, whole-disk access, privileged containers, auto-approved tool calls and risky capability combinations.

- Python standard library only. No dependencies, no network access, no telemetry.
- Every finding says **what** is wrong, **why it matters** and **how to fix it**, with an OWASP LLM Top 10 (2025) and CWE reference.
- Secret values are **never printed**. Findings carry only the location and the length.
- Output as text, JSON or SARIF 2.1.0 (GitHub code scanning).
- Honest about its limits: results are heuristics, and the report states what was and was not scanned.

## Quick start

```bash
git clone https://github.com/ismirhas/mcpaudit.git && cd mcpaudit
python -m mcpaudit scan demo/vulnerable-mcp.json      # see it find things
python -m mcpaudit scan                               # auto-discover your real configs
python -m mcpaudit scan .mcp.json --fail-on medium    # use in CI
python -m mcpaudit scan . -f sarif -o mcpaudit.sarif  # for GitHub code scanning
python -m mcpaudit rules                              # list all rules
```

Or install it: `pip install .` gives you the `mcpaudit` command.

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` usage error or a file that could not be parsed.

## What it checks

| Rule | Checks for | Severity |
|------|-----------|----------|
| MCP001 | Hardcoded secrets in `env`, `headers`, args and URLs (vendor key formats and credential-like names) | high / critical |
| MCP002 | Unpinned packages and images (`npx`, `uvx`, `pipx`, `docker run`) | medium / low |
| MCP003 | Whole-disk, home-directory or credential-directory access (`/`, `~`, `.ssh`, `.aws`) | high |
| MCP004 | Remote servers over cleartext HTTP | high |
| MCP005 | Third-party remote servers (trust review) | info |
| MCP006 | Shell wrappers, inline code, `curl ... \| sh` as the server command | medium / critical |
| MCP007 | Disabled safety controls (`--no-sandbox`, `--dangerously-*`, TLS verification off) | high |
| MCP008 | Containers that are privileged, mount `docker.sock`, host root or host namespaces | medium to critical |
| MCP009 | Servers that provide command execution | medium |
| MCP010 | Untrusted input + private data + outbound channel in one agent | medium / high |
| MCP011 | Auto-approved tool calls (`autoApprove`, `alwaysAllow`, `trust: true`) | low to high |
| MCP012 | Config file with secrets readable by other users | medium |
| MCP013 | Servers launched from temp or download folders | medium |

MCP010 applies the "lethal trifecta" framing by Simon Willison: if one agent can read content an attacker may control, reach private data, and communicate externally, a single planted instruction can exfiltrate data. The rule looks at the whole file, because the agent has access to all the servers in it.

## Example

```
demo/vulnerable-mcp.json  (7 servers)
  [CRITICAL] MCP008 Container run with excessive host privileges
      at db / args, line 28
      What: Container mounts the Docker socket (host root equivalent).
      Why: A privileged container, or one that mounts the Docker socket or host root, is
           effectively root on the host, so a compromised server escapes its isolation.
      Fix: Drop --privileged, never mount docker.sock, mount only specific directories
           read-only and add only the capabilities needed.
      Ref: LLM06:2025 Excessive Agency; CWE-250, CWE-269
...
Summary: 17 finding(s): 3 critical, 9 high, 5 medium
```

`demo/clean-mcp.json` is a control config that must produce **no** findings, so false alarms show up as test failures. All credentials in the demo files are fake examples.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- run: python -m mcpaudit scan . -f sarif -o mcpaudit.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: mcpaudit.sarif }
```

## Limitations

- **Static only.** It does not start servers, so it cannot see malicious or changing tool descriptions (tool poisoning) at runtime.
- **Heuristics, not proof.** Capability detection (MCP009/MCP010) matches server names, packages and hostnames. A custom server with an unusual name will be missed, and a harmless one may be flagged. Treat findings as review prompts.
- **Secret detection** covers common vendor formats and credential-like key names. It is not a replacement for a dedicated secret scanner.
- It scans configuration the client reads, not the code of the servers themselves.

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT
