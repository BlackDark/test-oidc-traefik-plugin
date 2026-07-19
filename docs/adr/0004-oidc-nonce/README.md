# 0004. OIDC `nonce` for ID tokens

**Status:** Accepted  
**Date:** 2026-07-19  
**Related:** `docs/tasks.md` Task 3

## Context

Default `TokenValidation` is `IdToken`. OIDC Core uses `nonce` to bind the ID token to the authentication request and mitigate replay/mix-up. This plugin never sent or checked `nonce`.

## Decision

1. On IdP redirect, generate random `nonce`, store in sealed `OidcState.Nonce`, add `nonce` query param to authorize URL.
2. When validating an ID token locally (`TokenValidation=IdToken`), require `claims["nonce"]` to equal `state.Nonce` (constant-time compare).
3. Config: `Provider.ValidateNonce` (bool), default **true**. When false, skip claim check (escape hatch). Still send nonce in authorize request when using IdToken validation so IdPs that echo it keep working.
4. Reserve `nonce` in `reservedAuthorizationParams`.

Introspection / AccessToken-only validation: no nonce claim check (token type has no standard nonce). If both access + id token present and validating IdToken, check applies.

Callback must pass expected nonce from state into `validateTokenLocally`.

## Consequences

- Breaking for IdPs that strip/ignore nonce and clients that somehow got tokens without it when ValidateNonce true — rare; disable flag available.
- Nonce lives only in sealed state + authorize URL (IdP may log it); not a secret like code_verifier.
