---
name: skill-route-exclusion-bypass-checker
description: Check path-based route exclusion mechanisms for traversal, encoding, and case bypass vulnerabilities. Use when auditing middleware route filtering.
---

# Route Exclusion Bypass Checker

Check if route exclusion rules can be bypassed via path manipulation.

## When to Use
- Auditing middleware route filtering
- Testing path-based security controls
- Checking for authentication bypass via path manipulation

## Inputs
- Middleware/framework target
- Route exclusion patterns

## Procedure
1. Find route exclusion configuration:
   - `python/shield/integrations/middleware.py`: `exclude_paths` parameter
   - `python/shield/integrations/flask_shield.py`: route decorators

2. Identify exclusion mechanism:
   - String prefix match (`/public/`)
   - Regex pattern (`^/api/v[0-9]+/public`)
   - Exact match (`/health`)
   - Decorator-based (`@shield_required`)

3. Test bypass techniques:
   | Technique | Example | Bypasses |
   |-----------|---------|----------|
   | Path traversal | `/public/../admin/secret` | Prefix match |
   | Double encoding | `%252fadmin` | Single decode |
   | Case variation | `/Public/` vs `/public/` | Case-sensitive |
   | Trailing slash | `/admin` vs `/admin/` | Exact match |
   | Dot segments | `/admin/./config` | Normalize |
   | Null byte | `/admin%00.html` | Extension check |
   | Unicode normalization | `/adm\u0131n` | String compare |
   | URL parameter | `/public?redirect=/admin` | Prefix only |
   | Fragment | `/public#/admin` | Prefix only |

4. Check if path normalization happens BEFORE exclusion check
5. Verify framework's URL routing vs middleware's path matching

## Output Format
```
### Route Exclusion Bypass Analysis
**Mechanism**: {type of exclusion}
**Normalization**: Before/After check

| Technique | Payload | Bypasses? | Risk |
|-----------|---------|-----------|------|
| Path traversal | `/public/../admin` | Yes | High |
| Case variation | `/Public/` | No | — |
...
```

## Used By
- A6 (Web Integration)
