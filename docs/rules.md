# Community rules

These rules are heuristic signals for human review.

| Rule | Severity | Language | Signal |
| --- | --- | --- | --- |
| `sql-concat` | high | Python | SQL assembled with an f-string or string addition |
| `pickle-loads` | high | Python | `pickle.loads()` on data that may be untrusted |
| `eval-exec-subprocess` | high | Python | Dynamic execution or command execution sink |
| `js-command-exec` | high | JavaScript / TypeScript | `child_process`, `eval`, or `new Function` |
| `raw-html-reflect` | medium | Python | HTML f-string that may reflect user data |

A parameterized SQL query should not be flagged by the Python AST scanner.
A finding still needs confirmation of input source, reachable execution path,
and missing protection before it becomes a security conclusion.
