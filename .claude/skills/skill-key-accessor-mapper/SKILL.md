---
name: skill-key-accessor-mapper
description: Find all public methods, properties, and APIs that expose raw key material in Shield implementations. Map the complete key exposure surface. Use for key lifecycle auditing.
---

# Key Accessor Mapper

Map all public entry points that expose raw cryptographic key material.

## When to Use
- Auditing key material exposure surface
- Checking if keys are accessible after use
- Mapping key lifecycle from creation to destruction

## Inputs
- Target language(s) or "all"
- Key types to check (master key, derived key, HMAC key, session key)

## Procedure
1. Search for key-related symbols in each implementation:
   - Fields/properties: `key`, `_key`, `master_key`, `derived_key`, `hmac_key`, `session_key`
   - Methods returning keys: `get_key`, `export_key`, `derive_key`, `getKey`
   - Key as return value from public methods
   - Key passed to callbacks or events

2. For each accessor found, classify:
   | Access Type | Risk |
   |------------|------|
   | Public getter returning raw bytes | Critical |
   | Public field with raw key | Critical |
   | Protected/private but accessible via reflection | High |
   | Key in toString/debug output | High |
   | Key logged to console/file | Critical |
   | Key in error message | Critical |
   | Key returned from public API | High |
   | Key stored in non-secure memory | Medium |

3. Check language-specific exposure:
   - Python: `__dict__`, `vars()`, pickle serialization
   - JavaScript: `JSON.stringify`, prototype chain, `console.log`
   - Java: reflection, serialization, `toString()`
   - Rust: `Debug` trait impl, `Clone` on key types
   - Go: `fmt.Stringer`, exported fields
   - C: pointer access to key buffers

4. Map key flow: creation -> storage -> usage -> destruction

## Output Format
```
### Key Exposure Surface: {language}
| # | File:Line | Symbol | Access | Key Type | Risk |
|---|-----------|--------|--------|----------|------|
| 1 | core.py:23 | `self.key` | Public attr | Master | Critical |
| 2 | shield.js:45 | `getKey()` | Public method | Derived | High |
...

**Exposure Summary**:
- Public key accessors: 4
- Debug/log exposure: 2
- Serialization risk: 1
```

## Used By
- A3 (Memory Safety), A9 (Browser & WASM), T9 (Key Lifecycle)
