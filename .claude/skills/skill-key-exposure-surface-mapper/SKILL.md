---
name: skill-key-exposure-surface-mapper
description: Map the complete key exposure surface across all platforms and lifecycle stages, from generation through storage to destruction. Use when assessing overall key security posture.
---

# Key Exposure Surface Mapper

Map complete key exposure surface across all platforms.

## When to Use
- Building comprehensive key lifecycle security map
- Identifying all points where key material could leak
- Cross-platform key security comparison

## Inputs
- Results from skill-key-accessor-mapper
- Results from skill-zeroization-verifier
- Platform audit results (Android/iOS/WASM)

## Procedure
1. Map key lifecycle stages per platform:
   ```
   Generation -> Derivation -> Storage -> Usage -> Rotation -> Destruction
   ```

2. For each stage, identify exposure points:

### Generation
| Platform | Source | Exposure Risk |
|----------|--------|--------------|
| All | CSPRNG | Low (if correct) |
| All | Password input | High (user-provided) |
| Android | Keystore keygen | Low (hardware) |
| iOS | Secure Enclave keygen | Low (hardware) |
| WASM | JS crypto.getRandomValues | Medium (JS accessible) |

### Storage
| Platform | Location | Protection | Risk |
|----------|----------|-----------|------|
| Desktop | Memory only | Process isolation | Medium |
| Android | Keystore | Hardware-backed | Low |
| iOS | Keychain | Secure Enclave | Low |
| Browser | JS heap | None | High |
| WASM | Linear memory | JS accessible | High |
| Server | Process memory | OS protection | Medium |

### Usage (Active in memory)
| Platform | Duration | Exposure |
|----------|----------|---------|
| All | During encrypt/decrypt | In process memory |
| WASM | During WASM execution | Linear memory |
| Browser | JS function scope | JS heap + closures |

### Destruction
| Platform | Method | Effective? |
|----------|--------|-----------|
| Rust | Zeroize crate | Yes |
| Python | del + gc | Partial (copies) |
| JS/Browser | fill(0) | Partial (GC) |
| C | explicit_bzero | Yes |
| Android | Keystore handles | Yes |
| iOS | Keychain handles | Yes |

3. Produce aggregate exposure map with risk scores

## Output Format
```
### Key Exposure Surface Map
| Stage | Desktop | Mobile | Browser | Server |
|-------|---------|--------|---------|--------|
| Generate | CSPRNG | Hardware | JS | CSPRNG |
| Store | Memory | Keystore/Keychain | JS heap | Memory |
| Use | Process | TEE | Linear mem | Process |
| Destroy | Zeroize | Hardware | GC | Partial |

**Highest Risk**: Browser/WASM key storage and destruction
**Recommendation**: [prioritized actions]
```

## Used By
- T9 (Key Lifecycle), A3 (Memory Safety)
