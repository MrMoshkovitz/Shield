# Agent 14: Streaming & Group Encryption — Security Findings

**Agent**: A14 — Streaming & Group
**Phase**: 3 (Platform & HW)
**Priority**: MEDIUM
**Files Audited**: `shield-core/src/stream.rs`, `shield-core/src/group.rs`
**Date**: 2026-03-03
**Status**: COMPLETE

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 6 |
| LOW | 4 |
| INFO | 2 |
| **Total** | **14** |

---

## StreamCipher Findings

### SHIELD-A14-001: Silent Stream Truncation — Missing End-of-Stream Verification
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-354 (Improper Validation of Integrity Check Value)
- **Location**: `shield-core/src/stream.rs:73-109`
- **Evidence**:
```rust
// decrypt_stream() — line 73-109
while pos < encrypted.len() {
    // ...
    let chunk_len = u32::from_le_bytes([...]) as usize;
    // End marker
    if chunk_len == 0 {
        break;
    }
    // ... decrypt chunk ...
    chunk_num += 1;
}
Ok(output)  // Returns partial data without verifying end marker was seen
```
The `while pos < encrypted.len()` loop exits cleanly when all bytes are consumed. There is NO check that the end marker (4 zero bytes) was actually encountered. An attacker can truncate the stream after any complete chunk by removing trailing chunks AND the end marker.
- **Impact**: An attacker performing a truncation attack can cause the receiver to accept a prefix of the original plaintext as the complete message. For example, a 4-chunk stream can be silently truncated to 1-2 chunks. The receiver sees valid data with no error, but it's incomplete. This is particularly dangerous for structured data where truncation changes semantics (e.g., truncating a JSON array, removing trailing authentication fields, cutting a contract short).
- **Reproduction**:
  1. Encrypt data large enough for multiple chunks (e.g., 200KB with 64KB chunks = 4 chunks)
  2. Capture the wire format
  3. Remove the last N chunk entries and the end marker (4 zero bytes)
  4. Decrypt the truncated stream — succeeds with partial plaintext, no error
- **Fix Complexity**: LOW
- **Remediation**: Add a `seen_end_marker` flag in `decrypt_stream()`. After the while loop, verify `seen_end_marker == true`. If not, return `Err(ShieldError::StreamError("stream truncated: missing end marker"))`. Alternatively, include total chunk count in the header (authenticated).
- **Verification Notes**: Confirmed by reading decrypt_stream logic. The end marker check at line 88 only breaks the loop when present — its absence causes silent exit via the while condition. No test exists for this case.

### SHIELD-A14-002: Unauthenticated Stream Header
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-354 (Improper Validation of Integrity Check Value)
- **Location**: `shield-core/src/stream.rs:64-67`, `shield-core/src/stream.rs:168-173`
- **Evidence**:
```rust
// Encrypt header (line 168-173)
let mut header = Vec::with_capacity(20);
header.extend_from_slice(&(self.chunk_size as u32).to_le_bytes());
header.extend_from_slice(&self.stream_salt);
return Some(Ok(header));

// Decrypt header (line 64-67)
let _chunk_size = u32::from_le_bytes([...]) as usize;  // UNUSED
let stream_salt = &encrypted[4..20];
```
The header (chunk_size + stream_salt) is not authenticated. While modifying stream_salt would cause all chunk MAC verifications to fail (detected), the chunk_size field in the header is completely unused during decryption (stored in `_chunk_size`). It serves no purpose and could be any value.
- **Impact**: The chunk_size field in the stream header is dead data — it's never used for decryption. This is a protocol design flaw that could mislead implementers in other languages who might rely on it for buffer allocation, potentially causing DoS via a crafted header with chunk_size = `u32::MAX`. The stream_salt modification is detected indirectly.
- **Reproduction**: Modify bytes 0-3 of the encrypted stream to any value. Decryption still succeeds.
- **Fix Complexity**: LOW
- **Remediation**: Either (a) add an HMAC over the entire header using the master key, or (b) remove the chunk_size from the header since it's unused. If kept, it should be authenticated and validated against chunk lengths.
- **Verification Notes**: Confirmed: `_chunk_size` on line 65 is prefixed with underscore (unused variable). Decryption reads each chunk's length from inline chunk_len fields.

### SHIELD-A14-003: No Minimum Chunk Size Validation
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `shield-core/src/stream.rs:40-42`
- **Evidence**:
```rust
pub fn with_chunk_size(key: [u8; 32], chunk_size: usize) -> Self {
    Self { key, chunk_size }
}
```
No validation on `chunk_size`. Values of 0 cause division by zero in `div_ceil(32)` during keystream generation. Value of 1 creates one encrypted chunk per plaintext byte, adding 32 bytes overhead per byte (nonce + MAC) — a ~33x size amplification.
- **Impact**: chunk_size=0 causes panic (DoS). Very small chunk sizes cause extreme ciphertext expansion and performance degradation. Malicious input to chunk_size in deserialized configs could be exploited.
- **Reproduction**: `StreamCipher::with_chunk_size(key, 0).encrypt(b"test")` — panics.
- **Fix Complexity**: LOW
- **Remediation**: Add validation: `assert!(chunk_size >= 32, "chunk_size must be at least 32 bytes")` or return Result with error. Set reasonable minimum (e.g., 1024) and maximum (e.g., 16MB).
- **Verification Notes**: Confirmed via code inspection. No bounds check exists on the parameter.

### SHIELD-A14-004: Same Key for Chunk Encryption and HMAC
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Location**: `shield-core/src/stream.rs:219-253`
- **Evidence**:
```rust
fn encrypt_chunk(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    // Keystream uses key directly (line 228)
    hash_input.extend_from_slice(key);
    hash_input.extend_from_slice(&nonce);
    hash_input.extend_from_slice(&counter);

    // HMAC also uses key directly (line 243)
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
```
The same 32-byte chunk key is used for both XOR keystream generation AND HMAC authentication within each chunk. Best practice requires separate encryption and MAC keys (Encrypt-then-MAC with key separation).
- **Impact**: Reusing the same key for encryption and authentication violates the principle of key separation. While no practical attack is known for this specific construction (SHA256-CTR + HMAC-SHA256 with same key), it's a deviation from best practice that could become exploitable if the construction changes.
- **Reproduction**: Read encrypt_chunk() — same `key` parameter flows into both keystream generation and HMAC.
- **Fix Complexity**: MEDIUM
- **Remediation**: Derive separate keys: `enc_key = SHA256(chunk_key || "enc")`, `mac_key = SHA256(chunk_key || "mac")`. This is the same recommendation as SHIELD-A01-001 for the core cipher.
- **Verification Notes**: Same pattern as core Shield cipher. Cross-references SHIELD-A01-001.

### SHIELD-A14-005: Chunk Key Derivation Uses Simple SHA256 Hash
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-328 (Use of Weak Hash)
- **Location**: `shield-core/src/stream.rs:206-216`
- **Evidence**:
```rust
fn derive_chunk_key(key: &[u8], stream_salt: &[u8], chunk_num: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(key.len() + stream_salt.len() + 8);
    data.extend_from_slice(key);
    data.extend_from_slice(stream_salt);
    data.extend_from_slice(&chunk_num.to_le_bytes());
    let hash = digest::digest(&digest::SHA256, &data);
    // ...
}
```
Chunk key is derived via simple `SHA256(master_key || stream_salt || chunk_num)`. While SHA256 is a secure hash, this is not a proper KDF (like HKDF). The concatenation approach is vulnerable to length-extension attacks on SHA256, though in this specific case the fixed-size inputs make exploitation unlikely.
- **Impact**: Theoretical weakness. The simple concatenation KDF is less robust than HKDF-SHA256 but the fixed-size inputs (32 + 16 + 8 = 56 bytes) mitigate practical risks.
- **Reproduction**: Code inspection only — no practical exploit.
- **Fix Complexity**: LOW
- **Remediation**: Consider using HKDF-Expand (RFC 5869) for chunk key derivation: `chunk_key = HKDF-Expand(master_key, stream_salt || chunk_num, 32)`.
- **Verification Notes**: Known theoretical concern. No practical attack path for fixed-size inputs.

### SHIELD-A14-006: No Zeroization of StreamCipher Key Material
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
- **Location**: `shield-core/src/stream.rs:23-26`
- **Evidence**:
```rust
pub struct StreamCipher {
    key: [u8; 32],
    chunk_size: usize,
}
// No #[derive(Zeroize, ZeroizeOnDrop)]
```
StreamCipher holds a 32-byte key but has no Zeroize implementation. Key material persists in memory after the struct is dropped.
- **Impact**: Key material remains in process memory after StreamCipher is dropped. If memory is later dumped (core dump, swap, cold boot), the key could be recovered.
- **Reproduction**: Create and drop StreamCipher, inspect heap memory.
- **Fix Complexity**: LOW
- **Remediation**: Add `#[derive(Zeroize, ZeroizeOnDrop)]` or manual `impl Drop for StreamCipher` that zeros the key field.
- **Verification Notes**: Same pattern found in other components. Cross-references SHIELD-A03-xxx (memory safety agent findings).

---

## GroupEncryption Findings

### SHIELD-A14-007: Member Identity Leakage in Encrypted Group Messages
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**: `shield-core/src/group.rs:96-100`, `shield-core/src/group.rs:142-145`
- **Evidence**:
```rust
#[derive(Serialize, Deserialize)]
pub struct EncryptedGroupMessage {
    pub version: u8,
    pub ciphertext: String,
    pub keys: HashMap<String, String>,  // member_id → encrypted_group_key
}

// Encryption fills the HashMap with plaintext member IDs:
for (member_id, member_key) in &self.members {
    let encrypted_key = encrypt_block(member_key, &self.group_key)?;
    keys.insert(member_id.clone(), ...);  // member_id is PLAINTEXT
}
```
The `EncryptedGroupMessage` serializes member IDs in the clear as HashMap keys. Anyone who intercepts the encrypted message can enumerate all group members by inspecting the `keys` field.
- **Impact**: Full group membership is exposed to any observer who can see the encrypted message. In applications where group membership is sensitive (e.g., whistleblower groups, medical consultations, legal proceedings), this is a privacy breach. The same issue exists in `EncryptedBroadcast` (line 197-202) which additionally leaks subgroup assignment structure.
- **Reproduction**: Encrypt a group message, serialize to JSON, observe that member IDs are plaintext keys in the JSON object.
- **Fix Complexity**: MEDIUM
- **Remediation**: Replace plaintext member_ids with opaque identifiers (e.g., `SHA256(member_id || group_nonce)`). Members can identify their own entry by computing their own hash. Alternatively, encrypt the member_id alongside the key.
- **Verification Notes**: Confirmed by reading EncryptedGroupMessage struct and encrypt() method. Same issue in EncryptedBroadcast.

### SHIELD-A14-008: No Automatic Rekey on Member Removal
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-324 (Use of a Key Past its Expiration Date)
- **Location**: `shield-core/src/group.rs:129-131`
- **Evidence**:
```rust
pub fn remove_member(&mut self, member_id: &str) -> bool {
    self.members.remove(member_id).is_some()
}
```
`remove_member()` only removes the member from the HashMap. It does NOT rotate the group key. A removed member who previously received and decrypted a group message possesses the `group_key`. They can use it to decrypt any future messages encrypted with the same group key.
- **Impact**: Removed members retain the ability to decrypt future group messages until `rotate_key()` is explicitly called. This violates forward secrecy expectations for group membership changes. An expelled member or compromised member key continues to have access.
- **Reproduction**:
  1. Create group with Alice, Bob, Carol
  2. Encrypt message M1 — Bob decrypts, obtains group_key
  3. Remove Bob from group
  4. Encrypt message M2 (no rekey happened)
  5. Bob can still decrypt M2 using the group_key from step 2
- **Fix Complexity**: MEDIUM
- **Remediation**: Auto-call `rotate_key()` inside `remove_member()` and re-encrypt the group key for remaining members. Add documentation warning that key rotation is required after member removal.
- **Verification Notes**: Confirmed: `rotate_key()` exists (line 182) but is not called from `remove_member()`. No documentation warns about this.

### SHIELD-A14-009: Group Key Accessor Exposes Raw Key Material
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**: `shield-core/src/group.rs:189-192`
- **Evidence**:
```rust
pub fn group_key(&self) -> &[u8; 32] {
    &self.group_key
}
```
The `group_key()` method returns a direct reference to the raw 32-byte group encryption key. Any code with access to a `GroupEncryption` instance can extract the key.
- **Impact**: Key material is freely accessible, defeating key encapsulation. Combined with SHIELD-A14-008, this means any member who ever held a GroupEncryption instance has permanent access to the group key.
- **Reproduction**: `let key = group.group_key().clone();` — now have raw key outside the group context.
- **Fix Complexity**: LOW
- **Remediation**: Remove or restrict to `pub(crate)`. If needed for testing, gate behind `#[cfg(test)]`.
- **Verification Notes**: Same pattern as SHIELD-A01-004 (core key accessor). Cross-references that finding.

### SHIELD-A14-010: rotate_key() Returns Old Key Material
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**: `shield-core/src/group.rs:182-186`
- **Evidence**:
```rust
pub fn rotate_key(&mut self) -> Result<[u8; 32]> {
    let old_key = self.group_key;
    self.group_key = crate::random::random_bytes()?;
    Ok(old_key)
}
```
`rotate_key()` returns the OLD key after rotation. While this could be useful for re-encrypting existing messages with the new key, it also means old key material flows to the caller without zeroization.
- **Impact**: Old key material is returned and persists in the caller's scope. If not explicitly zeroized by the caller, it remains in memory indefinitely.
- **Reproduction**: `let old = group.rotate_key().unwrap();` — old key now in scope.
- **Fix Complexity**: LOW
- **Remediation**: Consider whether returning old key is necessary. If so, document that caller must zeroize it. If not, return `Result<()>` and zeroize internally.
- **Verification Notes**: Design decision may be intentional for re-encryption workflows, but creates a key leak surface.

### SHIELD-A14-011: Empty Group Encryption Succeeds Silently
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Location**: `shield-core/src/group.rs:139-153`
- **Evidence**:
```rust
pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedGroupMessage> {
    let ciphertext = encrypt_block(&self.group_key, plaintext)?;
    let mut keys = HashMap::new();
    for (member_id, member_key) in &self.members {  // Empty iterator — no entries
        // ...
    }
    Ok(EncryptedGroupMessage {
        version: 1,
        ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        keys,  // Empty HashMap — nobody can decrypt
    })
}
```
If `encrypt()` is called with zero members, it succeeds and produces a valid `EncryptedGroupMessage` with an empty `keys` HashMap. The data is encrypted but nobody can decrypt it.
- **Impact**: Data loss scenario — developer encrypts for a group before adding members, gets no error, but the message is irrecoverable (nobody has the wrapped group key).
- **Reproduction**: `GroupEncryption::new(None).unwrap().encrypt(b"secret")` — succeeds with empty keys.
- **Fix Complexity**: LOW
- **Remediation**: Add check at start of `encrypt()`: `if self.members.is_empty() { return Err(ShieldError::EmptyGroup) }`.
- **Verification Notes**: Confirmed by code inspection. No guard against empty membership.

### SHIELD-A14-012: Broadcast master_key Stored but Never Used (Dead Key Material)
- **Tag**: VERIFIED
- **Severity**: INFO
- **CWE**: CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
- **Location**: `shield-core/src/group.rs:212-213`
- **Evidence**:
```rust
pub struct BroadcastEncryption {
    #[allow(dead_code)]
    master_key: [u8; 32],
    // ...
}
```
The `master_key` field is stored but never used (annotated with `#[allow(dead_code)]`). Key material occupies memory without serving any purpose.
- **Impact**: Unnecessary key material in memory increases the attack surface for memory extraction. If this key is the same as the encryption key passed by the caller, its presence creates a redundant copy.
- **Reproduction**: Code inspection — field has `#[allow(dead_code)]`.
- **Fix Complexity**: LOW
- **Remediation**: Remove the field if unused, or implement its intended purpose. Do not store key material that serves no function.
- **Verification Notes**: The `allow(dead_code)` annotation confirms the author was aware this field is unused.

### SHIELD-A14-013: No Zeroization of GroupEncryption or BroadcastEncryption Key Material
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
- **Location**: `shield-core/src/group.rs:103-106`, `shield-core/src/group.rs:211-218`
- **Evidence**:
```rust
pub struct GroupEncryption {
    group_key: [u8; 32],
    members: HashMap<String, [u8; 32]>,  // ALL member keys stored
}

pub struct BroadcastEncryption {
    master_key: [u8; 32],
    // ...
    members: HashMap<String, (u32, [u8; 32])>,  // ALL member keys
    subgroup_keys: HashMap<u32, [u8; 32]>,       // ALL subgroup keys
}
// Neither has Zeroize derive
```
Both `GroupEncryption` and `BroadcastEncryption` hold multiple key materials (group key, all member keys, subgroup keys) but have no Zeroize implementation. On drop, all keys persist in memory.
- **Impact**: GroupEncryption holds N+1 keys (1 group + N members), BroadcastEncryption holds N+M+1 keys (1 master + N members + M subgroups). All persist after drop. Memory dump reveals all group key material.
- **Reproduction**: Create and drop a GroupEncryption with members, inspect heap.
- **Fix Complexity**: MEDIUM
- **Remediation**: Implement `ZeroizeOnDrop` for both structs. For HashMap-based storage, iterate and zeroize all values in a custom Drop impl since HashMap doesn't support Zeroize directly.
- **Verification Notes**: HashMap<String, [u8; 32]> requires custom zeroization logic — standard derive won't cover it.

### SHIELD-A14-014: Broadcast Subgroup Panic on Missing Subgroup Key
- **Tag**: VERIFIED
- **Severity**: INFO
- **CWE**: CWE-248 (Uncaught Exception)
- **Location**: `shield-core/src/group.rs:289`
- **Evidence**:
```rust
// Inside BroadcastEncryption::encrypt()
let sg_key = self.subgroup_keys.get(sg_id).unwrap();
```
If `subgroup_keys` doesn't contain the expected `sg_id` (data corruption, race condition in concurrent access), this `.unwrap()` panics. All other error paths in this file use `Result` / `?`.
- **Impact**: Potential panic in production if data structures become inconsistent. Unlikely under normal single-threaded use, but possible in concurrent scenarios or after deserialization from corrupted state.
- **Reproduction**: Would require corrupting internal state (removing subgroup key entry while member still references it).
- **Fix Complexity**: LOW
- **Remediation**: Replace with `.ok_or(ShieldError::InvalidFormat)?`.
- **Verification Notes**: This is an internal consistency check — under normal use, subgroup_keys always has all referenced entries. But defensive coding should handle it.

---

## Checklist Completion

### StreamCipher
1. [x] Chunk auth: Chunk index IS included in key derivation via `chunk_num` → reordering detected
2. [x] Chunk order: Reordering causes MAC failure (different chunk keys) — PROTECTED
3. [x] Truncation: End marker exists BUT absence is NOT verified → **SHIELD-A14-001**
4. [x] Empty chunks: Empty data produces header + end marker (safe)
5. [x] Large files: u32 counter in keystream ok for 64KB chunks; chunk_size=0 panics → **SHIELD-A14-003**

### GroupEncryption
6. [x] Key distribution: Per-recipient key wrapping uses encrypt_block — authenticated
7. [x] Member privacy: Member IDs in plaintext in ciphertext → **SHIELD-A14-007**
8. [x] Member removal: No rekey → **SHIELD-A14-008**
9. [x] Self-inclusion: Sender can decrypt if they're in members list (no auto-include for sender)
10. [x] Empty group: Succeeds silently → **SHIELD-A14-011**
