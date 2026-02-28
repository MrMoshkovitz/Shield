# Cross-Domain Team 11: Configuration & Deployment Drift Chain

**Priority**: HIGH
**Phase**: 4 (after Phase 2 — needs Agents 5, 6, 10, 11 findings)
**Type**: Cross-Domain Attack Chain
**Question**: Can development/test configuration differences from production create exploitable security gaps?

## Team Composition

| Role | Agent # | Agent File | Contribution |
|------|---------|-----------|-------------|
| Lead | 5 | `security-docker-container.md` | Catalog Docker dev vs prod configuration differences |
| Support | 10 | `security-cicd-supply-chain.md` | Check if CI/CD enforces production configuration |
| Support | 6 | `security-web-integration.md` | Check middleware configuration drift |
| Support | 11 | `security-error-disclosure.md` | Check if debug/verbose errors reach production |

## Coordination Flow

```
Agent 5: Docker configuration audit
    → docker-compose.yml: uvicorn --reload flag (dev only!)
    → Running as root in container
    → Dev deps included in production image
Agent 10: CI/CD enforcement gaps
    → No validation that release builds use prod config
    → No constants integrity check before release
    → max_age_ms can be set to None → replay protection disabled
Agent 6: Middleware config drift
    → FastAPI/Flask debug mode detection
    → CORS configuration differences dev vs prod
    → Route exclusion patterns (startswith() bypass)
Agent 11: Error verbosity in production
    → FastAPI returns f"Decryption failed: {e}" → leaks exception type
    → Express returns err.message → leaks crypto internals
    → Is there a "production mode" that strips error details? (NO)
Joint verdict: Dev→prod drift exploitation chain + remediation priorities
```

## Known Evidence

- `uvicorn --reload` in docker-compose.yml:71
- No production configuration validation in any middleware
- `max_age_ms` can be `None` to disable replay protection
- Hardcoded demo credentials in examples/browser-integration/server.py:40-43

## Expected Output

1. Dev→prod drift exploitation chain
2. Configuration hardening checklist
3. CI/CD enforcement recommendations
4. Cross-references to Agents 5, 6, 10, 11 domain findings by ID

## Dedup Rule

Cross-domain finding REFERENCES domain finding by ID, never duplicates. If this chain escalates a MEDIUM domain finding to CRITICAL, the consolidated severity is CRITICAL.
