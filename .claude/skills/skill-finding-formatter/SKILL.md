---
name: skill-finding-formatter
description: Format security findings into standardized output with severity, CWE mapping, file location, evidence, and remediation. Use whenever producing audit output.
---

# Finding Formatter

Standardize all security findings into a consistent, machine-parseable format.

## When to Use
- After discovering any security issue during audit
- When consolidating findings from multiple scans
- Before adding findings to any report

## Inputs
- Finding title (brief description)
- Severity level (Critical/High/Medium/Low/Info)
- Affected file(s) and line number(s)
- Code evidence (snippet)
- CWE ID if applicable

## Procedure
1. Assign finding ID using skill-finding-id-generator
2. Classify severity using CVSS-like criteria:
   - **Critical**: Remote code execution, key exposure, auth bypass
   - **High**: Crypto weakness, memory corruption, injection
   - **Medium**: Info disclosure, missing validation, weak config
   - **Low**: Best practice violation, minor hardening gap
   - **Info**: Observation, no direct security impact
3. Map to CWE ID (use closest match):
   - Crypto: CWE-327 (broken crypto), CWE-330 (weak random), CWE-326 (weak key)
   - Memory: CWE-120 (buffer overflow), CWE-416 (use-after-free), CWE-401 (memory leak)
   - Injection: CWE-78 (OS cmd), CWE-79 (XSS), CWE-89 (SQL)
   - Auth: CWE-287 (improper auth), CWE-306 (missing auth), CWE-798 (hardcoded creds)
   - Info: CWE-209 (error info leak), CWE-532 (log info leak)
4. Extract code evidence (3-5 lines around the issue)
5. Write concise remediation guidance

## Output Format
```
### [FINDING-ID] Title
- **Severity**: Critical|High|Medium|Low|Info
- **CWE**: CWE-XXX (Name)
- **Location**: `file/path.ext:line`
- **Evidence**:
  ```lang
  // code snippet showing the issue
  ```
- **Impact**: What an attacker could achieve
- **Remediation**: Specific fix guidance
```

## Used By
- All 16 agents (A1-A16)
- All 7 teams (T6-T12)
