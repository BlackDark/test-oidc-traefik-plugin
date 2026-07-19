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
| [PR #282](https://github.com/sevensolutions/traefik-oidc-auth/pull/282) Unauth behavior split | Valuable UX/authz; **deferred** (large, orthogonal). |
| [PR #216](https://github.com/sevensolutions/traefik-oidc-auth/pull/216) Front-channel logout (draft) | **Deferred** (draft, scope). |
| [#236](https://github.com/sevensolutions/traefik-oidc-auth/issues/236) `nbf` / clock skew | **Done** (Task 6, `TokenClockSkewSeconds` default 60). |
| [#195](https://github.com/sevensolutions/traefik-oidc-auth/issues/195) `expires_in` validation mode | Deferred. |
| [#275](https://github.com/sevensolutions/traefik-oidc-auth/issues/275) camelCase keys | Skipped (Traefik catalog constraint). |
| [#87](https://github.com/sevensolutions/traefik-oidc-auth/issues/87) / [#262](https://github.com/sevensolutions/traefik-oidc-auth/issues/262) Redis / in-memory sessions | Out of scope. |

## Tasks

### Task 0 — Plan + branch

- [x] Create branch `feat/oidc-security-hardening`
- [x] This document (`docs/tasks.md`)
- Commit: `docs: add OIDC security hardening task list`

### Task 1 — Seal entire OIDC `state` (P0)

- [x] ADR: [`docs/adr/0002-sealed-oidc-state/README.md`](adr/0002-sealed-oidc-state/)
- [x] Impl + tests + review approve
- Commit: `feat(oidc): seal OIDC state with plugin secret`

### Task 2 — Login CSRF cookie binding (P0)

- [x] ADR: [`docs/adr/0003-login-csrf-binding/README.md`](adr/0003-login-csrf-binding/)
- [x] Per-flow `LoginCsrf.<csrf>` cookie + sealed `state.Csrf`
- Commit: `feat(oidc): bind login flow with CSRF cookie`

### Task 3 — OIDC `nonce` for ID tokens (P1)

- [x] ADR: [`docs/adr/0004-oidc-nonce/README.md`](adr/0004-oidc-nonce/)
- [x] Send `nonce`, store in sealed state, validate on IdToken when `ValidateNonce` (default true)

### Task 4 — Hard fail default Secret + safer defaults (P0/P1)

- [x] Refuse `Secret == DefaultSecret`
- [x] Default `UsePkceBool: true`, `SessionCookie.SameSite: lax`, `ValidateNonceBool: true`

### Task 5 — Re-validate post-login redirect on callback (P1)

- [x] When `ValidPostLoginRedirectUris` configured, validate `state.RedirectUrl` on callback

### Task 6 — JWT clock skew leeway (P1, issue #236)

- [x] `Provider.TokenClockSkewSeconds` default 60 + `jwt.WithLeeway`

### Task 7 — Docs index + tasks closeout

- [x] Update `docs/adr/README.md` for 0002–0004
- [x] Mark tasks done in this file

## Explicitly out of scope (this branch)

- UnauthorizedBehavior split (PR #282)
- Front-channel logout (PR #216)
- Redis / in-memory session backends
- PAR, DPoP, JAR
- camelCase Traefik CRD keys (#275)

## Migration notes

1. **Secret:** plugin refuses to start with the built-in default Secret. Set a random 32-char `Secret`.
2. **PKCE:** defaults to on. Set `Provider.UsePkce: false` only if the IdP rejects PKCE.
3. **SameSite:** session cookie default is `lax` (was `default`).
4. **State format:** sealed (encrypted). In-flight logins during upgrade fail once; users re-login.
5. **Nonce:** IdP must return `nonce` in ID token when `TokenValidation=IdToken` (disable with `ValidateNonce: false` if needed).

## Progress log

| Date | Commit | Notes |
|------|--------|-------|
| 2026-07-19 | `c419300` | Plan created |
| 2026-07-19 | `4068baa` | ADR 0002 sealed state |
| 2026-07-19 | `43ae810` | ADR 0003 login CSRF |
| 2026-07-19 | _(pending)_ | Tasks 3–7 |
