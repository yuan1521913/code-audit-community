from __future__ import annotations

import ast
import fnmatch
import json
import os
import re
from pathlib import Path
from typing import Any

RULES: list[dict[str, str]] = [
    {
        "name": "sql-concat",
        "pattern": r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\{|\\+|f[\"'])",
        "severity": "high",
        "reason": "SQL built by string concatenation may allow injection",
    },
    {
        "name": "pickle-loads",
        "pattern": r"pickle\.loads",
        "severity": "high",
        "reason": "unsafe deserialization may allow remote code execution",
    },
    {
        "name": "eval-exec-subprocess",
        "pattern": (
            r"\beval\(|\bexec\(|os\.system\(|os\.popen\(|"
            r"subprocess\.(?:run|Popen|call|check_output|check_call|getoutput|getstatusoutput)"
        ),
        "severity": "high",
        "reason": "dynamic code or command execution sink",
    },
    {
        "name": "js-command-exec",
        "pattern": (
            r"(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(|"
            r"eval\s*\(|new\s+Function\s*\("
        ),
        "severity": "high",
        "reason": "JavaScript dynamic code or command execution sink",
    },
    {
        "name": "raw-html-reflect",
        "pattern": r"f[\"'][^\"']*(?:<[^\"']*\{|\{[^\"']*<)[^\"']*[\"']",
        "severity": "medium",
        "reason": "HTML f-string may reflect user data without encoding",
    },
]

SKIP_DIRS = {
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "site-packages",
    "reports",
    "state",
    "dist",
    "build",
}

SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
PYTHON_RULE_NAMES = {
    "sql-concat",
    "pickle-loads",
    "eval-exec-subprocess",
    "raw-html-reflect",
}
JS_RULE_NAMES = {"js-command-exec"}


def rules_for_path(path: Path) -> list[dict[str, str]]:
    names = PYTHON_RULE_NAMES if path.suffix.lower() == ".py" else JS_RULE_NAMES
    return [rule for rule in RULES if rule["name"] in names]


def scan_file(path: Path, skip_rules: set[str] | None = None) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
    except OSError:
        return []

    findings = (
        scan_python_ast(path, text, lines)
        if path.suffix.lower() == ".py"
        else scan_regex_lines(path, lines)
    )
    findings = _dedupe(findings)
    if skip_rules:
        findings = [finding for finding in findings if finding["pattern"] not in skip_rules]
    return findings


def scan_regex_lines(path: Path, lines: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, line in enumerate(lines, 1):
        for rule in rules_for_path(path):
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append(
                    {
                        "file": str(path),
                        "line": index,
                        "pattern": rule["name"],
                        "severity": rule["severity"],
                        "reason": rule["reason"],
                        "snippet": line.strip()[:180],
                    }
                )
    return findings


def scan_python_ast(path: Path, text: str, lines: list[str]) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return scan_regex_lines(path, lines)

    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func).strip()
            if name == "pickle.loads":
                findings.append(finding_from_node(path, lines, node, "pickle-loads"))
            elif name in {
                "eval",
                "exec",
                "os.system",
                "os.popen",
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_output",
                "subprocess.check_call",
                "subprocess.getoutput",
                "subprocess.getstatusoutput",
            }:
                findings.append(finding_from_node(path, lines, node, "eval-exec-subprocess"))
        elif isinstance(node, ast.JoinedStr):
            constants = [
                value.value
                for value in node.values
                if isinstance(value, ast.Constant) and isinstance(value.value, str)
            ]
            has_value = any(isinstance(value, ast.FormattedValue) for value in node.values)
            if has_value and any(
                re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", value, re.IGNORECASE)
                for value in constants
            ):
                findings.append(finding_from_node(path, lines, node, "sql-concat"))
            if has_value and any("<" in value for value in constants):
                findings.append(finding_from_node(path, lines, node, "raw-html-reflect"))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            for operand in (node.left, node.right):
                if (
                    isinstance(operand, ast.Constant)
                    and isinstance(operand.value, str)
                    and re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", operand.value, re.IGNORECASE)
                ):
                    findings.append(finding_from_node(path, lines, node, "sql-concat"))
                    break
    return findings


def finding_from_node(path: Path, lines: list[str], node: ast.AST, pattern: str) -> dict[str, Any]:
    rule = next(rule for rule in RULES if rule["name"] == pattern)
    line = getattr(node, "lineno", 1)
    return {
        "file": str(path),
        "line": line,
        "pattern": pattern,
        "severity": rule["severity"],
        "reason": rule["reason"],
        "snippet": lines[line - 1].strip()[:180] if 0 < line <= len(lines) else "",
    }


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int, str]] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        key = (str(finding["file"]), int(finding["line"]), str(finding["pattern"]))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def scan_path(
    path: Path,
    ignore_patterns: list[str] | None = None,
    skip_rules: set[str] | None = None,
) -> list[dict[str, Any]]:
    ignore_patterns = list(ignore_patterns or [])
    skip_rules = set(skip_rules or [])
    path = path.resolve()
    if path.is_file():
        return scan_file(path, skip_rules=skip_rules)

    findings: list[dict[str, Any]] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(directory for directory in dirs if directory not in SKIP_DIRS)
        root_path = Path(root)
        for name in sorted(files):
            item = root_path / name
            relative = item.relative_to(path).as_posix()
            if any(
                fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(item.name, pattern)
                for pattern in ignore_patterns
            ):
                continue
            if item.suffix.lower() in SUPPORTED_SUFFIXES:
                findings.extend(scan_file(item, skip_rules=skip_rules))
    return findings


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for finding in findings:
        severity = finding.get("severity", "low")
        if severity in summary:
            summary[severity] += 1
    return summary


def render_json(findings: list[dict[str, Any]]) -> str:
    return json.dumps(findings, ensure_ascii=False, indent=2)


def md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(findings: list[dict[str, Any]]) -> str:
    summary = summarize(findings)
    lines = [
        "# Code Audit Community Report",
        "",
        "> Automated heuristic scan. Results require human confirmation.",
        "",
        f"- High: {summary['high']}",
        f"- Medium: {summary['medium']}",
        f"- Low: {summary['low']}",
        f"- Total: {summary['total']}",
        "",
        "| File | Line | Severity | Rule | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(
            f"| {md_cell(finding['file'])} | {finding['line']} | "
            f"{finding['severity']} | {md_cell(finding['pattern'])} | "
            f"{md_cell(finding['reason'])} |"
        )
    return "\n".join(lines)


def render(findings: list[dict[str, Any]], fmt: str) -> str:
    if fmt == "json":
        return render_json(findings)
    return render_markdown(findings)


def has_high(findings: list[dict[str, Any]]) -> bool:
    return any(finding["severity"] == "high" for finding in findings)
