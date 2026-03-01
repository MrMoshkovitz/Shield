---
name: skill-android-keystore-auditor
description: Audit Android Keystore usage for hardware backing, biometric protection, key purposes, and secure storage patterns. Use when auditing mobile key management.
---

# Android Keystore Auditor

Audit Android Keystore integration for secure key storage and biometric protection.

## When to Use
- Auditing Android SDK key storage security
- Checking hardware-backed key protection
- Reviewing biometric authentication integration

## Inputs
- Android source directory (default: `android/`)
- Scope: "keystore" | "biometric" | "storage" | "all"

## Procedure
1. Locate Android security files:
   - `SecureKeyStore` class
   - `Shield` Android implementation
   - Biometric authentication code
   - `AndroidManifest.xml` for permissions

2. Audit Keystore configuration:

### Key Storage Checks
| Check | Good | Bad | Risk |
|-------|------|-----|------|
| KeyGenParameterSpec | `.setIsStrongBoxBacked(true)` | No StrongBox | Medium |
| Hardware backing | `isInsideSecureHardware()` check | No verification | High |
| Key purposes | Minimal (ENCRYPT_DECRYPT only) | All purposes | Medium |
| User auth required | `.setUserAuthenticationRequired(true)` | No auth | High |
| Invalidate by enrollment | `.setInvalidatedByBiometricEnrollment(true)` | false | Medium |

### Biometric Checks
| Check | Pattern | Risk |
|-------|---------|------|
| BiometricPrompt used | `BiometricPrompt` class | Safe |
| Deprecated API | `FingerprintManager` | Medium |
| Auth timeout | `setUserAuthenticationValidityDurationSeconds` | Check value |
| Crypto object binding | `CryptoObject` with BiometricPrompt | Required |

### Storage Checks
| Check | Pattern | Risk |
|-------|---------|------|
| EncryptedSharedPrefs | `EncryptedSharedPreferences` | Safe |
| Plain SharedPrefs | `SharedPreferences` for keys | Critical |
| File storage | Keys written to file system | Critical |
| Logging keys | `Log.d/i/e` with key data | Critical |
| Backup inclusion | `android:allowBackup="true"` | High |

3. Check for fallback behavior when hardware unavailable

## Output Format
```
### Android Keystore Audit
| # | File:Line | Check | Status | Risk |
|---|-----------|-------|--------|------|
| 1 | SecureKeyStore.java:42 | StrongBox backing | PASS | - |
...

**Summary**: X/Y checks passed, hardware backing: Yes/No
```

## Used By
- A12 (Mobile Platform)
- T09 (Key Lifecycle)
