---
name: skill-rate-limiter-bypass-analyzer
description: Analyze rate limiting implementation for bypass techniques including counter reset, IP spoofing, race conditions, and distributed attacks. Use when auditing API protection.
---

# Rate Limiter Bypass Analyzer

Analyze rate limiting for bypass vulnerabilities.

## When to Use
- Auditing API rate limiting implementation
- Checking for brute force protection
- Assessing DoS protection mechanisms

## Inputs
- Rate limiter implementation file
- Configuration parameters

## Procedure
1. Locate rate limiter code:
   - `python/shield/integrations/rate_limiter.py`
   - `python/shield/integrations/api_protector.py`

2. Analyze rate limiting mechanism:
   - Algorithm: Token bucket, sliding window, fixed window, leaky bucket
   - Storage: In-memory, Redis, database
   - Granularity: Per-IP, per-user, per-endpoint, global

3. Test bypass techniques:
   | Technique | Description | Check |
   |-----------|------------|-------|
   | IP spoofing | X-Forwarded-For header manipulation | Does it trust proxy headers? |
   | Distributed | Multiple source IPs | Per-IP only? |
   | Counter reset | Window boundary race | Fixed window reset? |
   | Race condition | Concurrent requests | Thread-safe counter? |
   | Key manipulation | Change API key mid-limit | Per-key tracking? |
   | Endpoint variation | `/api/v1/` vs `/api/v1` | Path normalization? |
   | HTTP method | GET vs POST same endpoint | Method-aware? |
   | Case sensitivity | `/API/` vs `/api/` | Case-insensitive? |
   | Encrypted state | Tamper with rate limit state | Is state encrypted? |

4. Check Shield-specific concerns:
   - Rate limit state encrypted with Shield?
   - Brute force on Shield passwords rate-limited?
   - PBKDF2 iteration timing vs rate limit window

## Output Format
```
### Rate Limiter Bypass Analysis
**Algorithm**: {type}
**Storage**: {backend}
**Granularity**: {level}

| Bypass Technique | Vulnerable? | Risk | Details |
|-----------------|------------|------|---------|
| IP spoofing via XFF | Yes | High | Trusts X-Forwarded-For |
| Race condition | No | — | Uses atomic counter |
...
```

## Used By
- A7 (Auth & Session), T6 (Crypto Oracle)
