---
name: skill-config-drift-detector
description: Compare development, test, and production configurations to identify security-relevant drift such as debug modes, weak settings, or missing hardening. Use when auditing deployment security.
---

# Config Drift Detector

Detect security-relevant configuration drift across environments.

## When to Use
- Comparing dev vs prod security settings
- Checking for debug modes left enabled
- Auditing environment-specific configurations

## Inputs
- Configuration files (Dockerfile, docker-compose, env files, app configs)
- Environment scope (dev, test, staging, prod)

## Procedure
1. Identify configuration sources:
   - `Dockerfile` (build-time config)
   - `docker-compose.yml` (runtime config)
   - Environment variables
   - Application config files
   - CI/CD workflow configs

2. Check for security-relevant drift:
   | Setting | Dev (typical) | Prod (required) | Risk if Dev in Prod |
   |---------|--------------|-----------------|-------------------|
   | DEBUG mode | Enabled | Disabled | Info disclosure |
   | Verbose errors | Enabled | Disabled | Info disclosure |
   | PBKDF2 iterations | Low (1000) | High (100000) | Weak key derivation |
   | TLS/HTTPS | Optional | Required | MITM |
   | CORS origin | `*` | Specific origins | CSRF |
   | Rate limiting | Disabled | Enabled | Brute force |
   | Log level | DEBUG | WARN/ERROR | Info disclosure |
   | Secret values | Hardcoded | Env/vault | Credential exposure |
   | Container user | root | non-root | Privilege escalation |

3. Check for missing environment separation:
   - Same Docker image for dev and prod?
   - Same environment variables?
   - Same database credentials?
   - Same API keys?

4. Check for configuration injection:
   - Can environment variables override security settings?
   - Are config files writable in production?

## Output Format
```
### Configuration Drift Analysis
| Setting | Dev | Prod | Drift? | Risk |
|---------|-----|------|--------|------|
| DEBUG | true | true | SAME | High -- debug in prod |
| ITERATIONS | 1000 | 100000 | Different | -- |
| CORS | * | * | SAME | Medium -- open CORS in prod |
...

**Security Drift Issues**: X found
```

## Used By
- T11 (Config Drift)
