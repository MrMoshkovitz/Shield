# Security Agent: Browser & WASM

**Priority**: HIGH (Phase 2)
**Team**: Application
**Domain**: WASM memory isolation, fetch interceptor, TypeScript bindings, CSP, browser SDK integrity

## Purpose

Audit the browser SDK and WASM module for browser-specific security issues including memory isolation, fetch hook safety, CSP compatibility, and client-side key management.

## Files to Audit

### Primary Ownership
- `shield-core/src/wasm.rs` — WASM Rust bindings
- `browser/js/fetch-hook.ts` — Fetch interceptor
- `browser/js/index.ts` — Browser SDK entry point
- `wasm/` — WASM module build

### Secondary
- `python/shield/integrations/browser.py` — Server-side browser bridge
- `browser/` — All browser SDK files

## Known Findings to Verify

1. **WASM linear memory inspectable by JS** — Any JS on the page can read WASM memory containing keys. CWE-316.
2. **Fetch hook inconsistent error handling** — Some fetch errors return encrypted data, others plaintext. CWE-636.
3. **No WASM binary integrity check** — WASM module loaded without Subresource Integrity (SRI). CWE-494.
4. **CSP compatibility** — SDK may require `unsafe-eval` or `unsafe-inline` to function. CWE-1021.
5. **Key stored in JS variable** — Decryption key kept in accessible JS scope after init.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-316 | Cleartext in memory | WASM linear memory |
| CWE-636 | Not failing securely | Fetch hook error paths |
| CWE-494 | Download without integrity | WASM loading |
| CWE-1021 | CSP bypass | SDK initialization |
| CWE-200 | Information exposure | Key in JS scope |
| CWE-79 | XSS | Decrypted content rendering |

## Audit Checklist

1. [ ] WASM memory: Document that linear memory is accessible to page JS
2. [ ] Fetch hook: Verify all error paths return error, never plaintext fallback
3. [ ] Fetch hook: Verify interceptor doesn't break non-encrypted responses
4. [ ] SRI: Verify WASM binary can use Subresource Integrity hash
5. [ ] CSP: Document minimum CSP policy needed for SDK
6. [ ] Key lifecycle: Verify key is not stored in global/window scope
7. [ ] TypeScript bindings: Verify no type confusion between JS and WASM types
8. [ ] XSS: Verify decrypted content is not directly injected into DOM
9. [ ] CORS: Verify fetch hook respects CORS policies

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Key theft, XSS, or bypass
- **Remediation**: Browser-specific fix
```

## Cross-References
- Agent 3 (memory-safety) — WASM .unwrap() panics
- Agent 6 (web-integration) — Browser bridge server side
- Agent 11 (error-disclosure) — Error messages in browser context
