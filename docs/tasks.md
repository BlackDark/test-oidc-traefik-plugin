# OIDC security hardening task list

**Branch:** `feat/oidc-security-hardening` (from `fix/gh-170-pkce-state-verifier`)  
**Goals:** KISS, security first, configurable with safe defaults, scales without shared server state (yaegi / multi-replica Traefik).  
**Cluster for smoke tests:** kubectl context `informaten` (Pocket ID + Traefik + whoami available).

Living checklist. Each task: ADR (if design choice) → implement → tests → subagent review loop → conventional commit → mark done here with ADR/doc links.

## Principles

- No Redis / shared pending-login store (replicas must stay independent).
- Prefer encrypt+MAC with existing 32-byte `Secret` over new crypto stacks.
- Breaking defaults only when security payoff is clear; document migration.
- Do not reintroduce PKCE cookies (see ADR 0001).

## Upstream survey (cherry-pick / skip)

| Item | Action |
|------|--------|
| [#170](https://github.com/sevensolutions/traefik-oidc-auth/issues/170) / [PR #283](https://github.com/sevensolutions/traefik-oidc-auth/pull/283) | Done on base branch (PKCE in state). Keep. |
| [#259](https://github.com/sevensolutions/traefik-oidc-auth/issues/259) VerifierCookie domain | Mostly obsolete after ADR 0001; legacy clear remains. |
| [PR #282](https://github.com/sevensolutions/traefik-oidc-auth/pull/282) Unauth behavior split | Valuable UX/authz; **defer** (large, orthogonal). Track as follow-up. |
| [PR #216](https://github.com/sevensolutions/traefik-oidc-auth/pull/216) Front-channel logout (draft) | **Defer** (draft, scope). |
| [#236](https://github.com/sevensolutions/traefik-oidc-auth/issues/236) `nbf` / clock skew | **Do** small JWT leeway (Task 6). |
| [#195](https://github.com/sevensolutions/traefik-oidc-auth/issues/195) `expires_in` validation mode | Useful scale/perf; **defer** unless time left. |
| [#275](https://github.com/sevensolutions/traefik-oidc-auth/issues/275) camelCase keys | Traefik plugin catalog constraint; **skip** (not a real bug). |
| [#87](https://github.com/sevensolutions/traefik-oidc-auth/issues/87) / [#262](https://github.com/sevensolutions/traefik-oidc-auth/issues/262) Redis / in-memory sessions | **Out of scope** for this branch (stateful). |

## Tasks

### Task 0 — Plan + branch

- [x] Create branch `feat/oidc-security-hardening`
- [x] This document (`docs/tasks.md`)
- Commit: `docs: add OIDC security hardening task list`

### Task 1 — Seal entire OIDC `state` (P0)

**Why:** Only `cve` is encrypted today; `redirect_url` / `action` are forgeable base64 JSON → open redirect / flow tampering after callback.

**Design:** ADR 0002 — encrypt+MAC whole state payload with `Secret` (reuse `utils.Encrypt` / `Decrypt`). Outer wire format stays opaque base64url string for the `state` query param.

- [ ] ADR: `docs/adr/0002-sealed-oidc-state/README.md`
- [ ] Impl: `SealState` / `UnsealState` (or evolve Encode/Decode)
- [ ] Wire all Encode/Decode call sites through seal with `Config.Secret`
- [ ] Tests: tampered ciphertext fails; round-trip; redirect_url cannot be forged without Secret
- [ ] Review loop → commit: `feat(oidc): seal OIDC state with plugin secret`
- **Done →** link ADR here: _(pending)_

### Task 2 — Login CSRF cookie binding (P0)

**Why:** Encrypted state alone does not stop classic login CSRF (attacker starts flow, victim completes callback).

**Design:** ADR 0003 — short-lived HttpOnly cookie (`CookieNamePrefix.LoginCsrf`) holding random value; same value inside sealed state; callback must match; clear cookie after use.

- [ ] ADR: `docs/adr/0003-login-csrf-binding/README.md`
- [ ] Impl + clear on success/failure paths as appropriate
- [ ] Config: always on (no disable) unless strong reason; optional `LoginCsrfCookieMaxAge` default 600s
- [ ] Tests: mismatch rejects; missing cookie rejects; happy path OK; parallel flows OK (unique csrf per flow)
- [ ] Review loop → commit: `feat(oidc): bind login flow with CSRF cookie`
- **Done →** link ADR here: _(pending)_

### Task 3 — OIDC `nonce` for ID tokens (P1)

**Why:** OIDC Core expects `nonce` to bind ID token to this authentication. Plugin validates IdToken by default but never sends/checks nonce.

**Design:** ADR 0004 — generate nonce, put in authorize request + sealed state; when `TokenValidation=IdToken` (or always when id_token present), require claim match. Configurable: `Provider.ValidateNonce` default `true`.

- [ ] ADR: `docs/adr/0004-oidc-nonce/README.md`
- [ ] Impl + reserve `nonce` in `reservedAuthorizationParams`
- [ ] Tests: missing/mismatch fail; match passes; AccessToken-only path does not require nonce claim when ValidateNonce off or no id_token validation
- [ ] Review loop → commit: `feat(oidc): send and validate OIDC nonce`
- **Done →** link ADR here: _(pending)_

### Task 4 — Hard fail default Secret + safer defaults (P0/P1)

**Why:** Default Secret decrypts sessions and sealed state. PKCE off by default fights RFC 9700. SessionCookie SameSite `default` is vague.

- [ ] Refuse `Secret == DefaultSecret` in `New()` (keep `.traefik.yml` catalog hack if needed via provider URL sentinel)
- [ ] Default `UsePkceBool: true` (document: set `false` only for broken IdPs)
- [ ] Default `SessionCookie.SameSite: lax`
- [ ] Short note in `website/docs/getting-started/middleware-configuration.md` (migration)
- [ ] Tests for refuse-default-secret
- [ ] Review loop → commit: `fix(security): refuse default secret and tighten defaults`
- **Done →** note in this file when complete

### Task 5 — Re-validate post-login redirect on callback (P1)

**Why:** Login query path uses `ValidateRedirectUri`; callback trusts `state.RedirectUrl` after unseal. Defense in depth if allowlist configured (and safe default when empty).

- [ ] Call `ValidateRedirectUri` on callback redirect before final redirect
- [ ] Tests: allowlist reject still works post-callback
- [ ] Review loop → commit: `fix(oidc): validate redirect URL on callback`
- **Done →** note when complete

### Task 6 — JWT clock skew leeway (P1, issue #236)

**Why:** `token is not valid yet` / clock drift between Traefik and IdP.

- [ ] Add `Provider.TokenClockSkew` (duration string or seconds); default **60s**
- [ ] Pass `jwt.WithLeeway` into local validation
- [ ] Tests for near-future `nbf` within leeway
- [ ] Review loop → commit: `fix(oidc): add JWT clock skew leeway`
- **Done →** refs #236

### Task 7 — Docs index + tasks closeout

- [ ] Update `docs/adr/README.md` index for 0002–0004
- [ ] Mark all tasks done in this file with links
- [ ] Optional: smoke login on `informaten` (whoami + pocket-id) if local plugin mount feasible
- [ ] Final review → commit: `docs: close OIDC hardening task list`

## Explicitly out of scope (this branch)

- UnauthorizedBehavior split (PR #282)
- Front-channel logout (PR #216)
- Redis / in-memory session backends
- PAR, DPoP, JAR
- camelCase Traefik CRD keys (#275)

## Progress log

| Date | Commit | Notes |
|------|--------|-------|
| 2026-07-19 | _(pending)_ | Plan created |
