---
name: skill-crypto-oracle-feasibility-assessor
description: Assess whether distinguishable error responses enable adaptive chosen-ciphertext (oracle) attacks against Shield encryption. Use when evaluating combined crypto + error handling risks.
---

# Crypto Oracle Feasibility Assessor

Assess if error behavior enables oracle attacks against Shield.

## When to Use
- Combining findings from error disclosure and crypto audits
- Assessing chosen-ciphertext attack feasibility
- Evaluating padding/MAC oracle risks

## Inputs
- Error catalog (from skill-error-message-cataloger)
- Error propagation trace (from skill-middleware-error-propagation-tracer)
- Timing data (from skill-constant-time-verifier)

## Procedure
1. Classify error distinguishability:
   | Error Pair | Distinguishable? | Via |
   |-----------|-----------------|-----|
   | MAC fail vs format fail | ? | Status code, message, timing |
   | MAC fail vs wrong key | ? | Status code, message, timing |
   | Format fail vs wrong key | ? | Status code, message, timing |
   | Decrypt success vs any fail | ? | Status code, timing |

2. Assess oracle attack types:
   | Oracle Type | Requires | Impact |
   |------------|---------|--------|
   | MAC oracle | MAC pass/fail distinguishable | Forgery |
   | Padding oracle | Pad valid/invalid distinguishable | Decrypt without key |
   | Timing oracle | Processing time differs | Byte-by-byte MAC recovery |
   | Error oracle | Different errors for different failures | Information leak |

3. Shield-specific analysis:
   - Shield uses Encrypt-then-MAC -> no padding oracle (CTR mode, no padding)
   - BUT: if MAC is checked AFTER partial decrypt -> timing oracle
   - If MAC check timing varies -> MAC oracle
   - If error messages differ -> error oracle

4. Assess practical exploitability:
   | Factor | Assessment |
   |--------|-----------|
   | Network reachable? | Can attacker send ciphertexts? |
   | Queries needed | How many for full key/plaintext recovery? |
   | Rate limiting | Does rate limiter block oracle queries? |
   | Noise | Network jitter masks timing? |
   | Adaptive | Can attacker modify ciphertext between queries? |

5. Produce go/no-go assessment

## Output Format
```
### Crypto Oracle Feasibility Assessment
**Architecture**: Encrypt-then-MAC (CTR + HMAC-SHA256)

| Oracle Type | Feasible? | Evidence | Queries Needed | Practical? |
|------------|-----------|----------|---------------|-----------|
| Padding | No | CTR mode, no padding | N/A | N/A |
| MAC | Maybe | Timing diff: 2ms | ~2^17 | If no rate limit |
| Error | No | Generic error response | N/A | N/A |

**Overall Risk**: Low/Medium/High
**Recommendation**: [action items]
```

## Used By
- T6 (Crypto Oracle)
