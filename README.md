# Code Audit Community

A small, local-first scanner for a few dangerous patterns that are easy to
miss before code ships.

This repository is the free community edition of `code-audit-cli`.

Product page:

https://yuan1521913.github.io/code-audit-community/

## What it checks

| Rule | Severity | Typical signal |
| --- | --- | --- |
| `sql-concat` | high | SQL assembled with an f-string or string addition |
| `pickle-loads` | high | `pickle.loads()` on data that may be untrusted |
| `eval-exec-subprocess` | high | `eval`, `exec`, `os.system`, or `subprocess` sinks |
| `js-command-exec` | high | JavaScript `child_process`, `eval`, or `new Function` |
| `raw-html-reflect` | medium | HTML f-string that may reflect user data |

Supported source suffixes: `.py`, `.js`, `.jsx`, `.ts`, `.tsx`.

## Install

```bash
python -m pip install .
```

## Use

```bash
code-audit-community path/to/project
code-audit-community path/to/project --format json --output report.json
code-audit-community path/to/project --fail-on high
code-audit-community path/to/project --ignore "tests/**"
code-audit-community path/to/project --skip-rule raw-html-reflect
```

The command returns exit code `1` when a high-risk finding is present. Use
`--fail-on none` when the command should only produce a report.

## Boundary

This is a heuristic first pass, not a formal security audit. A finding is a
location for human review, not proof that an exploit exists. A clean scan does
not prove that code is safe.

The community edition intentionally does not include:

- HTML and SARIF report generation
- baseline review for CI
- the complete multilingual rule set
- private or organization-level rule packs
- priority support and commercial rule updates

The commercial edition is available from the product links on the
[public product repository](https://github.com/yuan1521913/code-audit-cli).

## GitHub Action

Use the free GitHub Action for pull-request scans and SARIF output:

```text
https://github.com/yuan1521913/code-audit-action
```

## Development

```bash
python -m pip install .
python -m unittest discover -s tests -v
```

## License

MIT. See `LICENSE`.
