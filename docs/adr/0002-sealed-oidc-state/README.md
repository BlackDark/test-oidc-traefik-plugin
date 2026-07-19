# 0002. Seal entire OIDC `state` parameter

**Status:** Accepted  
**Date:** 2026-07-19  
**Related:** [ADR 0001](../0001-pkce-verifier-in-oidc-state/), `docs/tasks.md` Task 1

## Context

OIDC `state` currently is JSON → RawURL base64. Field `cve` (PKCE verifier) is AES-GCM encrypted, but `action` and `redirect_url` are plaintext inside that JSON. Anyone who can craft or modify `state` can change the post-login redirect (open redirect) or action.

The plugin already uses a 32-byte `Secret` with `utils.Encrypt` / `Decrypt` for session tickets and PKCE.

## Decision

Encrypt and MAC the **entire** `OidcState` JSON with `Secret` before putting it in the authorize/callback `state` query parameter.

Wire format:

1. `json.Marshal(OidcState)`
2. `utils.Encrypt(json, Secret)` → StdEncoding ciphertext
3. `base64.RawURLEncoding.EncodeToString([]byte(ciphertext))` for the query value

Unseal reverses the steps and fails closed on any error.

Keep struct fields (`action`, `redirect_url`, `cve`, later `csrf` / `nonce`) as internal cleartext only after successful unseal.

## Consequences

- Tampering without `Secret` fails decrypt.
- Mid-upgrade in-flight logins with old unsealed state break once (acceptable).
- `state` size grows (~same order as encrypting session tickets).
- Does not alone stop login CSRF (see ADR 0003).
