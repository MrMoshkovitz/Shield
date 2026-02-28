# Cross-Domain Team 7: Supply Chain to Runtime Chain

**Priority**: HIGH
**Phase**: 4 (after Phase 2 — needs Agents 5, 9, 10 findings)
**Type**: Cross-Domain Attack Chain
**Question**: Can a supply chain compromise propagate through CI/CD and deployment to silently corrupt runtime crypto?

## Team Composition

| Role | Agent # | Agent File | Contribution |
|------|---------|-----------|-------------|
| Lead | 10 | `security-cicd-supply-chain.md` | Identify supply chain entry points + CI/CD gaps |
| Support | 5 | `security-docker-container.md` | Check deployment integrity + container hardening |
| Support | 9 | `security-browser-wasm.md` | Check WASM binary verification + SRI |

## Coordination Flow

```
Agent 10: Map all build → publish → deploy paths
    → npm publish, cargo publish, pip publish, GitHub Release
    → Which steps lack signing? Which secrets could be stolen?
Agent 5: Check if deployed containers verify artifact integrity
    → Docker images: are checksums verified on pull?
    → Opaque containers: build-opaque.sh uses SHIELD_PASSWORD in env
Agent 9: Check WASM binary integrity in browser SDK
    → No SRI hash, no signature, no checksum verification
    → npm provenance covers JS wrapper but NOT WASM binary
Joint verdict: Full supply chain attack tree with exploitation path
```

## Known Evidence

- Release binaries have SHA256 checksums but no cryptographic signatures
- WASM binary not included in npm provenance signing
- `SHIELD_PASSWORD` visible in process listing via env vars
- No SBOM, no SLSA, no Sigstore integration

## Expected Output

1. Full supply chain attack tree (build → publish → deploy → runtime)
2. Exploitation path for each entry point
3. Remediation priorities: signing, SBOM, SLSA, SRI
4. Cross-references to Agents 5, 9, 10 domain findings by ID

## Dedup Rule

Cross-domain finding REFERENCES domain finding by ID, never duplicates. If this chain escalates a MEDIUM domain finding to CRITICAL, the consolidated severity is CRITICAL.
