---
name: skill-middleware-error-propagation-tracer
description: Trace error propagation from Shield decrypt failures through middleware to HTTP responses. Classify information leakage at each stage. Use when auditing web integration error handling.
---

# Middleware Error Propagation Tracer

Trace how Shield errors propagate through web middleware to HTTP responses.

## When to Use
- Auditing error handling in FastAPI/Flask integrations
- Checking if decryption errors leak information
- Assessing crypto oracle attack feasibility

## Inputs
- Target framework (FastAPI, Flask, or both)
- Error path focus (decrypt, auth, rate-limit)

## Procedure
1. Locate error origin points in Shield core:
   - `python/shield/core.py`: decrypt failures (MAC mismatch, invalid format)
   - `python/shield/integrations/middleware.py`: middleware error handling
   - `python/shield/integrations/flask_shield.py`: Flask extension errors

2. Trace each error type through the stack:
   ```
   Shield.decrypt() raises Exception
     → Middleware catches (or not?)
       → Error handler formats response
         → HTTP response to client
   ```

3. For each error path, classify:
   | Error Type | Internal Message | HTTP Response | Info Leaked? |
   |-----------|-----------------|---------------|-------------|
   | MAC mismatch | "MAC verification failed" | ? | Distinguishable? |
   | Invalid format | "Invalid ciphertext format" | ? | Distinguishable? |
   | Key derivation fail | "PBKDF2 failed" | ? | Distinguishable? |
   | Wrong key | Decrypt produces garbage | ? | Distinguishable? |

4. Check for oracle attack indicators:
   - Different HTTP status codes for different crypto errors
   - Different error messages for MAC vs format vs key errors
   - Different response timing for different error types
   - Error details in response body or headers

5. Check middleware error handling:
   - Are Shield exceptions caught?
   - Is there a generic error response?
   - Are error details logged (and is log accessible)?
   - Do debug modes expose more information?

## Output Format
```
### Error Propagation Analysis
| Error Source | Exception | Middleware Action | HTTP Status | Response Body | Oracle Risk |
|-------------|-----------|------------------|-------------|---------------|-------------|
| MAC fail | ValueError | Caught, generic 400 | 400 | "Bad request" | Low |
| Format fail | ValueError | Caught, generic 400 | 400 | "Bad request" | Low |
| Wrong key | Succeeds (garbage) | No error | 200 | Garbage data | N/A |

**Oracle Assessment**: Low/Medium/High risk
**Distinguishable Errors**: X types produce different responses
```

## Used By
- A6 (Web Integration), A11 (Error Disclosure), T6 (Crypto Oracle)
