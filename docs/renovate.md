# Renovate

Dependency updates are handled by Renovate, not Dependabot.

## Where the config lives

Shared settings live in `https://github.com/BlackDark/renovate-base` (`default.json5`)
and are pulled in with `github>blackdark/renovate-base//default.json5`. That base carries
`config:best-practices`, action/docker digest pinning, automerge below major, the monthly
schedule and dependency grouping.

`.github/renovate.json5` holds only what is specific to this repo: Go grouping, the
`vendor/` and `node_modules/` ignores, and the regex manager that picks up `image:` pins
in the IdP playground compose files.

Validate changes with the same tool CI uses:
`renovate-config-validator --strict --no-global .github/renovate.json5`
(`renovate-base` runs this on every `.json5` change in that repo; this repo has no
equivalent workflow yet).

## Automerge is gated on branch protection

Automerge below major (`:automergeMinor`, `:automergeDigest`) comes from the base preset,
so it is governed from `renovate-base`, not from this file.

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

Replaced by Renovate; `.github/dependabot.yml` is removed. `Security > Dependabot
alerts` and `Security updates` are also off in repository settings, so re-enabling
those later will not silently revive Dependabot PRs.