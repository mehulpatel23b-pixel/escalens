"""End-to-end CLI tests: real files, real exit codes, real stdout."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SRC = HERE / "src"
EXAMPLES = HERE / "examples" / "policies"


def run(*args):
    return subprocess.run(
        [sys.executable, "-m", "escalens", *args],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )


class CliTests(unittest.TestCase):
    def test_dangerous_policy_exits_clean_without_gate(self):
        proc = run(str(EXAMPLES / "dangerous-team-role.json"), "--no-color")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ESCALENS", proc.stdout)
        self.assertIn("privilege-escalation", proc.stdout.lower())

    def test_hardened_policy_reports_no_findings(self):
        proc = run(str(EXAMPLES / "hardened-role.json"), "--no-color")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("No active privilege-escalation paths detected", proc.stdout)

    def test_fail_on_high_gates_ci(self):
        proc = run(str(EXAMPLES / "dangerous-team-role.json"), "--fail-on", "high", "--quiet")
        self.assertEqual(proc.returncode, 1)

    def test_fail_on_critical_untouched_by_clean_policy(self):
        proc = run(str(EXAMPLES / "hardened-role.json"), "--fail-on", "critical", "--quiet")
        self.assertEqual(proc.returncode, 0)

    def test_min_score_gate(self):
        proc = run(str(EXAMPLES / "account-details.json"), "--min-score", "50", "--quiet")
        self.assertEqual(proc.returncode, 1)

    def test_json_output_is_valid_and_complete(self):
        proc = run(str(EXAMPLES / "account-details.json"), "--json")
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["tool"], "escalens")
        self.assertEqual(payload["summary"]["principals"], 5)
        self.assertGreater(payload["summary"]["findings_active"], 0)
        for finding in payload["findings"]:
            for key in ("id", "severity", "principal", "impact", "remediation", "evidence"):
                self.assertIn(key, finding)

    def test_bad_path_exits_2(self):
        proc = run("/nonexistent/nope.json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("escalens:", proc.stderr)

    def test_list_rules(self):
        proc = run("x", "--list-rules")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ESC-001", proc.stdout)
        self.assertIn("ADM-001", proc.stdout)

    def test_verbose_shows_all_evidence(self):
        proc = run(str(EXAMPLES / "dangerous-team-role.json"), "--no-color", "-v")
        self.assertIn("evidence", proc.stdout)

    def test_no_secrets_or_arns_leak_from_examples(self):
        proc = run(str(EXAMPLES / "account-details.json"), "--json")
        self.assertNotIn("AKIA", proc.stdout)


if __name__ == "__main__":
    unittest.main()
