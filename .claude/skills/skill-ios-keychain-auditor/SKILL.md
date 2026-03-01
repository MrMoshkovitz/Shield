---
name: skill-ios-keychain-auditor
description: Audit iOS Keychain usage for access control, Secure Enclave, data protection class, and biometric integration. Use when auditing iOS key management.
---

# iOS Keychain Auditor

Audit iOS Keychain integration for secure key storage and biometric protection.

## When to Use
- Auditing iOS SDK key storage security
- Checking Secure Enclave usage
- Reviewing Face ID / Touch ID integration

## Inputs
- iOS source directory (default: `ios/`)
- Scope: "keychain" | "biometric" | "storage" | "all"

## Procedure
1. Locate iOS security files:
   - `SecureKeychain` class
   - `Shield` iOS implementation
   - Biometric authentication code
   - `Info.plist` for privacy keys

2. Audit Keychain configuration:

### Keychain Access Checks
| Check | Good | Bad | Risk |
|-------|------|-----|------|
| Access control | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | `kSecAttrAccessibleAlways` | Critical |
| Secure Enclave | `kSecAttrTokenIDSecureEnclave` | Software-only keys | Medium |
| Biometric binding | `.biometryCurrentSet` | No biometric | Medium |
| Device-only | `ThisDeviceOnly` suffix | Migratable | High |
| Synchronizable | `kSecAttrSynchronizable: false` | true (iCloud sync) | High |

### Data Protection Classes (Best to Worst)
| Class | When Available | Use For |
|-------|---------------|---------|
| `CompleteProtection` | Only when unlocked | Keys, secrets |
| `CompleteUnlessOpen` | Until first lock | Active sessions |
| `AfterFirstUnlock` | After first unlock | Background access |
| `Always` | Always | NEVER for keys |

### Biometric Checks
| Check | Pattern | Risk |
|-------|---------|------|
| LAContext used | `LAContext()` | Check policy |
| Policy type | `.deviceOwnerAuthenticationWithBiometrics` | Safe |
| Fallback to passcode | `.deviceOwnerAuthentication` | Medium |
| Error handling | `LAError` cases handled | Required |
| Reuse duration | `touchIDAuthenticationAllowableReuseDuration` | Check value |

### Storage Checks
| Check | Pattern | Risk |
|-------|---------|------|
| UserDefaults for keys | `UserDefaults.*key` | Critical |
| File system storage | Writing keys to Documents/ | Critical |
| NSLog with keys | `NSLog.*key\|print.*key` | Critical |
| Backup exclusion | `isExcludedFromBackup` | Required |

3. Check `Info.plist` for:
   - `NSFaceIDUsageDescription` (required for Face ID)
   - App Transport Security settings

## Output Format
```
### iOS Keychain Audit
| # | File:Line | Check | Status | Risk |
|---|-----------|-------|--------|------|
| 1 | SecureKeychain.swift:28 | Access control level | PASS | - |
...

**Summary**: X/Y checks passed, Secure Enclave: Yes/No
```

## Used By
- A12 (Mobile Platform)
- T09 (Key Lifecycle)
