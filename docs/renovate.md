# Renovate

Dependency updates are handled by Renovate, not Dependabot. Config lives in
`.github/renovate.json5`; that file is the reference for what is updated and how.

## Automerge is gated on branch protection

`:automergeMinor` and `:automergeDigest` let Renovate merge every patch, minor, pin
and digest bump without review. Major bumps always get a PR.

That is only safe because a Renovate merge is held until `main` reports green. If
`go test -count=1 -race ./...` stops being a required status check, Renovate starts
merging on CI state alone and green-but-wrong lands silently.

Keep these as required status checks on `main`:

- `Go tests / Go tests` (`.github/workflows/testing.yaml`)
- `Go (golangci-lint)` and `Go (golangci-lint (extauth-server))` (`.github/workflows/lint.yml`)

Verify after changing branch protection:
`https://github.com/BlackDark/test-oidc-traefik-plugin/settings/branches`

## Why vendor/ is ignored

The repo commits a vendor/ tree, and Renovate cannot run `task vendor`. A merged
`go.mod` bump without a regenerated tree fails CI anyway: `go build` with a vendor
directory verifies `vendor/modules.txt` against `go.mod` and errors with
*inconsistent vendoring*. So stale-vendor bumps are blocked by the gate rather than
by a config exception - but they arrive as red PRs until someone runs `task vendor`
and pushes. Expect automerge to no-op on Go bumps until that loop closes.

## Dependabot

Disabled via repository settings: `Security > Dependabot alerts` and
`Security updates` are both off, which stops PRs regardless of
`.github/dependabot.yml`. Removing that file is still worth doing so the tree
matches the intent, and so re-enabling settings later does not silently revive it.