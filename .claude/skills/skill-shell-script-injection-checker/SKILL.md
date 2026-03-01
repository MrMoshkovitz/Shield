---
name: skill-shell-script-injection-checker
description: Audit shell scripts, Makefiles, and CI configs for command injection, unquoted variables, eval usage, and unsafe subprocess calls. Use for infrastructure security auditing.
---

# Shell Script Injection Checker

Audit shell scripts and build files for injection vulnerabilities.

## When to Use
- Auditing Makefiles, shell scripts, CI/CD configs
- Checking for command injection in build tooling
- Reviewing subprocess calls in application code

## Inputs
- Target files or directories
- Scope: shell scripts, Makefiles, CI configs, application code

## Procedure
1. Identify shell-related files:
   - `*.sh`, `*.bash`, `*.zsh`
   - `Makefile`, `*.mk`
   - `.github/workflows/*.yml`
   - `Dockerfile`, `docker-compose.yml`
   - `*.py` (subprocess), `*.js` (child_process), `*.go` (exec.Command)

2. Check for dangerous patterns:
   | Pattern | Risk | CWE |
   |---------|------|-----|
   | Unquoted `$VAR` | Variable injection | CWE-78 |
   | `eval "$user_input"` | Code injection | CWE-94 |
   | `$(...)` with user input | Command substitution injection | CWE-78 |
   | Backticks with user input | Command injection | CWE-78 |
   | `curl \| sh` | Remote code execution | CWE-94 |
   | `xargs` without `-0` | Argument injection | CWE-88 |
   | Missing `set -euo pipefail` | Error handling | CWE-252 |
   | `chmod 777` | Excessive permissions | CWE-732 |
   | Hardcoded secrets/tokens | Credential exposure | CWE-798 |

3. In application code, check subprocess calls:
   - Python: `os.system()`, `subprocess.call(shell=True)`, `os.popen()`
   - JavaScript: `child_process.exec()` with string arg
   - Go: `exec.Command` with unsanitized input
   - Rust: `std::process::Command` with user input

4. Rate each finding by exploitability

## Output Format
```
### Shell Injection Audit
| # | File:Line | Pattern | Risk | CWE | Exploitable? |
|---|-----------|---------|------|-----|-------------|
| 1 | build.sh:12 | Unquoted $VAR | High | CWE-78 | If VAR controlled |
...
```

## Used By
- A5 (Docker), A10 (CI/CD Supply Chain), A16 (Fingerprint)
