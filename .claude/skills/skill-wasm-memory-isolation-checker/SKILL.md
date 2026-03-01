---
name: skill-wasm-memory-isolation-checker
description: Assess WASM memory isolation, key exposure through linear memory, and JS interop security boundaries. Use when auditing browser/WASM security.
---

# WASM Memory Isolation Checker

Assess WebAssembly memory isolation and JS interop for key material exposure.

## When to Use
- Auditing WASM module for key leakage through linear memory
- Checking JS-WASM boundary for security issues
- Reviewing memory management in browser context

## Inputs
- WASM source: `wasm/`, `shield-core/` (with wasm feature)
- Browser SDK: `browser/shield-browser.js`

## Procedure
1. Locate WASM-related files:
   - `wasm/src/lib.rs` (WASM bindings)
   - `shield-core/src/lib.rs` (core with `wasm` feature)
   - `browser/shield-browser.js` (JS consumer)

2. Audit memory isolation:

### Linear Memory Exposure
| Check | Pattern | Risk | CWE |
|-------|---------|------|-----|
| Key in linear memory | Key bytes in WASM memory buffer | High | CWE-316 |
| Memory not cleared | Key remains after use | High | CWE-244 |
| Memory growth | `memory.grow` exposes old pages | Medium | CWE-226 |
| Buffer views | `Uint8Array` views into WASM memory | High | CWE-200 |

### JS Interop Checks
| Check | Pattern | Risk |
|-------|---------|------|
| Key returned to JS | Key bytes cross WASM-JS boundary | Critical |
| Plaintext in JS | Decrypted data held in JS heap | Medium |
| GC timing | Key in JS objects subject to GC | Medium |
| console.log exposure | Logging key-related WASM exports | High |
| Prototype pollution | WASM exports on pollutable object | Medium |

### wasm-bindgen/wasm-pack Checks
| Check | What to Verify |
|-------|---------------|
| #[wasm_bindgen] exports | Only necessary functions exported |
| Return types | Keys not returned as Vec<u8>/Box<[u8]> |
| Error messages | No key material in error strings |
| Memory management | Proper free/dealloc of sensitive buffers |

### Browser Context
| Check | Risk |
|-------|------|
| Key in localStorage/sessionStorage | Critical |
| Key in IndexedDB without encryption | High |
| Key visible in DevTools Memory tab | Medium |
| Key in Service Worker cache | High |

## Output Format
```
### WASM Memory Isolation Audit
| # | File:Line | Check | Status | Risk |
|---|-----------|-------|--------|------|
| 1 | wasm/src/lib.rs:28 | Key export to JS | FAIL | Critical |
...

**Isolation Score**: X/Y checks passed
```

## Used By
- A09 (Browser & WASM)
- A03 (Memory Safety)
- T09 (Key Lifecycle)
