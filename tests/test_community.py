from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from codeaudit_community import scanner  # noqa: E402


class CommunityScannerTests(unittest.TestCase):
    def test_vulnerable_sample_finds_expected_rules(self) -> None:
        findings = scanner.scan_file(FIXTURES / "vulnerable_sample.py")
        patterns = {finding["pattern"] for finding in findings}
        self.assertEqual(
            patterns,
            {"sql-concat", "pickle-loads", "eval-exec-subprocess", "raw-html-reflect"},
        )

    def test_parameterized_sql_is_not_flagged(self) -> None:
        findings = scanner.scan_file(FIXTURES / "clean_sample.py")
        patterns = {finding["pattern"] for finding in findings}
        self.assertNotIn("sql-concat", patterns)

    def test_javascript_exec_is_flagged(self) -> None:
        findings = scanner.scan_file(FIXTURES / "dangerous_web.js")
        self.assertIn("js-command-exec", {finding["pattern"] for finding in findings})

    def test_cli_writes_json_report(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "codeaudit_community.cli",
                    str(FIXTURES / "vulnerable_sample.py"),
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--fail-on",
                    "none",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                cwd=str(PROJECT_ROOT),
                check=True,
            )
            self.assertIn("summary=", result.stdout)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload)

    def test_cli_returns_one_on_high(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "codeaudit_community.cli",
                str(FIXTURES / "vulnerable_sample.py"),
                "--fail-on",
                "high",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=str(PROJECT_ROOT),
        )
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
