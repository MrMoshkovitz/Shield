# Security Agent: Mobile Platform

**Priority**: MEDIUM (Phase 3)
**Team**: Platform & HW
**Domain**: Android Keystore/TEE/StrongBox, iOS Keychain/Secure Enclave, biometric auth

## Purpose

Audit Android and iOS SDK implementations for platform-specific security issues including hardware-backed key storage, biometric authentication bypass, and secure enclave usage.

## Files to Audit

### Primary Ownership — Android
- `android/shield/src/` — All Kotlin/Java source files
- `android/shield/src/main/java/ai/guard8/shield/Shield.kt` — Core Shield
- `android/shield/src/main/java/ai/guard8/shield/SecureKeyStore.kt` — Keystore integration
- `android/build.gradle` — Dependencies and min SDK

### Primary Ownership — iOS
- `ios/Sources/Shield/` — All Swift source files
- `ios/Sources/Shield/Shield.swift` — Core Shield
- `ios/Sources/Shield/SecureKeychain.swift` — Keychain integration
- `ios/Shield.podspec` or `ios/Package.swift` — Dependencies

## Known Findings to Verify

1. **Keystore key not hardware-backed** — Android KeyStore may use software-only keys if TEE/StrongBox not requested. CWE-320.
2. **Keychain access too permissive** — iOS Keychain items may use `kSecAttrAccessibleAlways` instead of `WhenUnlockedThisDeviceOnly`. CWE-311.
3. **Biometric fallback to password** — Biometric auth falls back to device PIN, weakening security. CWE-287.
4. **No ProGuard/R8 config** — Android release builds may not obfuscate Shield code. CWE-200.
5. **No certificate pinning** — Mobile SDKs may not pin TLS certificates for key exchange. CWE-295.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-320 | Key management errors | Keystore/Keychain config |
| CWE-311 | Missing encryption of sensitive data | Keychain accessibility |
| CWE-287 | Improper authentication | Biometric fallback |
| CWE-200 | Information exposure | Missing obfuscation |
| CWE-295 | Improper certificate validation | TLS/network calls |

## Audit Checklist

### Android
1. [ ] KeyStore: Verify `setIsStrongBoxBacked(true)` or TEE requirement
2. [ ] KeyStore: Verify key purposes limited to encrypt/decrypt only
3. [ ] Biometric: Verify `setUserAuthenticationRequired(true)` with no device credential fallback
4. [ ] ProGuard: Verify R8/ProGuard rules for release builds
5. [ ] Min SDK: Verify minSdkVersion is reasonable (API 23+ for fingerprint)
6. [ ] Backup: Verify `android:allowBackup="false"` or encrypted backup

### iOS
1. [ ] Keychain: Verify `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
2. [ ] Keychain: Verify access control requires biometric, not device passcode
3. [ ] Secure Enclave: Verify usage where available
4. [ ] App Transport Security: Verify ATS not disabled
5. [ ] Data Protection: Verify `NSFileProtectionComplete`

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **Platform**: Android | iOS | Both
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Key extraction, auth bypass, or data exposure
- **Remediation**: Platform-specific fix
```

## Cross-References
- Agent 1 (crypto-primitives) — Core encryption correctness on mobile
- Agent 3 (memory-safety) — Key lifecycle on mobile
