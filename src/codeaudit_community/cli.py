from __future__ import annotations

import argparse
import sys
from pathlib import Path

from codeaudit_community import __version__, scanner


def main() -> None:
    parser = argparse.ArgumentParser(description="Code Audit Community CLI")
    parser.add_argument("path", nargs="?", default=".", help="file or directory to scan")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--output", default="", help="write the report to a file")
    parser.add_argument("--ignore", action="append", default=[], help="skip files matching fnmatch pattern")
    parser.add_argument("--skip-rule", action="append", default=[], help="skip a rule by name")
    parser.add_argument("--fail-on", choices=["high", "none"], default="high")
    parser.add_argument("--version", action="version", version=f"code-audit-community {__version__}")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"error=path not found: {args.path}", file=sys.stderr)
        sys.exit(2)

    findings = scanner.scan_path(
        target,
        ignore_patterns=args.ignore,
        skip_rules=set(args.skip_rule),
    )
    report = scanner.render(findings, args.format)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"report={args.output}")
    else:
        print(report)

    summary = scanner.summarize(findings)
    print(f"summary={summary}")
    if args.fail_on == "high" and scanner.has_high(findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
