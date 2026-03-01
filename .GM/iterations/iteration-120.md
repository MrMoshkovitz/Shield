# Iteration 36 — TASK-2-024: A11 Middleware Error Propagation & Crypto Leakage

**Start**: 2026-03-03T03:00:00+03:00 (Jerusalem time)
**End**: 2026-03-03T04:00:00+03:00 (Jerusalem time)
**Task**: TASK-2-024 — A11 Middleware Error Propagation & Crypto Leakage
**Agent**: Agent 11 — Error Disclosure (task 2 of 3)

## What Was Done

Traced the complete error propagation chain from Shield `decrypt()` failures through all 4 web framework middlewares (FastAPI, Flask, Express, Django) to HTTP responses. Assessed crypto oracle feasibility at each stage. Also audited confidential computing middleware error paths and AttestationRouter endpoints.

**Files Audited**: `fastapi.py`, `flask.py`, `express.js`, `django/__init__.py`, `confidential/middleware.py`, `browser.py`, `protection.py`, `fido2_api.py`, `core.py` (Python decrypt), `shield.js` (JS decrypt), `error.rs` (Rust errors)

## Key Findings (10 new)

| ID | Title | Severity | Key Insight |
|----|-------|----------|-------------|
| A11-016 | FastAPI shield_protected unhandled TypeError → 500/400 oracle | **HIGH** | Python `Shield.decrypt()` returns `None`. `json.loads(None)` → `TypeError` NOT in the except clause → **500 Internal Server Error** vs other errors → **400**. Binary crypto oracle. |
| A11-025 | Systemic fail-open on encryption across Flask/Express/Django | **HIGH** | All 3 frameworks catch encrypt errors and return **plaintext**. Fundamental security model violation. |
| A11-017 | Express shieldRequired leaks decrypt-vs-parse error | MEDIUM | `null.toString()` → TypeError reveals decrypt returned null (MAC failure) vs JSON parse error (decrypt succeeded) |
| A11-018 | Flask _before_request silently swallows ALL decrypt errors | MEDIUM | `except Exception: pass` — fail-open, request continues without decrypted data |
| A11-019 | Flask _after_request silently swallows encrypt errors | MEDIUM | Encrypt failure → plaintext response |
| A11-020 | Express shieldMiddleware sends plaintext on encrypt failure | MEDIUM | Same as Flask but in Express |
| A11-021 | Django middleware encrypt fails open to plaintext | MEDIUM | Same pattern in Django |
| A11-022 | requires_attestation leaks AttestationError + TEE type | MEDIUM | TEE type, measurement names leaked in error responses |
| A11-023 | AttestationRouter verify returns full measurements/claims | MEDIUM | Unauthenticated endpoint returns all PCR values and claims |
| A11-024 | Health endpoint exposes TEE measurements | LOW | `/attestation/health` reveals TEE type and measurements |

## Error Propagation Matrix

| Scenario | FastAPI | Flask | Express | Django |
|----------|---------|-------|---------|--------|
| MAC failure | **500** (TypeError) | Silent pass | 400 + "null" error | 400 "Decryption failed" |
| Bad base64 | 400 + detail | Silent pass | 400 + error msg | 400 "Decryption failed" |
| **Oracle?** | **YES (500 vs 400)** | No (fail-open) | **YES (error msg)** | **No (safe)** |

## What Was Found

- **FastAPI** has the MOST DANGEROUS error handling: unhandled TypeError creates a binary crypto oracle via HTTP status codes (500 vs 400)
- **Express** is second worst: error messages distinguish decrypt failure from JSON parse failure
- **Flask** has no oracle but FAILS OPEN on all decrypt errors — worse than an oracle in some ways
- **Django** `shield_required` is the ONLY safe pattern — generic "Decryption failed" for all errors
- **ALL 3 Python frameworks + Express** fail-open on ENCRYPT errors — returning plaintext when encryption was mandated
- Confidential middleware has 3 separate information leak paths through error responses

## Cumulative Status

- **A11 Total**: 25 findings (5 HIGH, 14 MEDIUM, 4 LOW, 1 INFO) — 2/3 tasks done
- **Overall**: 302 findings across 40/66 tasks
- **Phase 2**: 23/26 tasks done, 3 remaining (A11 stack traces, checkpoint, dedup)

## Next Steps

- TASK-2-025: A11 Stack Trace & Debug Info Exposure (MEDIUM priority, last A11 task)
- Then TASK-2-026: Phase 2 Checkpoint
- Then TASK-2-027: Phase 2 Dedup → Phase 2 COMPLETE
