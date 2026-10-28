# Security policy

## Support and reporting

This is an experimental private-SPI extension, currently `0.1.0-rc.1`.
Only Keycloak versions listed in [compatibility.json](compatibility.json) are
qualified. There is no stable release or long-term support branch.

Report vulnerabilities through the [private reporting form](https://github.com/Alien6-Studio/keycloak-bounded-delegation/security/advisories/new).
If unavailable, contact [contact@alien6.com](mailto:contact@alien6.com) to request
a secure channel before sharing details. Include the affected revision, exact
Keycloak version, cache topology, impact and a synthetic reproducer. Exclude
credentials, raw tokens, private keys and customer data.

## Runtime boundaries

The software-only profile requires explicit realm activation and administrator
configuration. It does not qualify human consent or impersonation. Offline JWTs
remain valid until their bounded expiry; instant resource-side revocation is not
claimed. Shared-cache failover, release qualification and operational gaps are tracked in
the [project roadmap](docs/roadmap.md). Consumer deployment tests remain with consumers.
See [README.md](README.md) for deployment and withdrawal requirements.

## Administration

Console-managed grants use native component Admin API permissions: `view-realm`
for reads and `manage-realm` for writes, scoped to the target realm. Enable native
administrative events to audit changes. The authenticated diagnostics endpoint
exposes structural state, never tokens or credentials; the public discovery
endpoint retains its limited seven-field contract. External-writer documents are
not overwritten or silently merged. Actor protection remains after withdrawal.
See [administration](docs/administration.md) for writer ownership, same-entry
concurrency and the administrator's expiry confirmation before disabling enforcement.

## Repository protections

[Default-branch](.github/rulesets/default-branch.json) and
[tag](.github/rulesets/release-tags.json) rulesets require signed commits, linear
history, squash PRs, resolved review threads and the up-to-date `Extension checks`
aggregate bound to GitHub Actions. CodeQL blocks errors and high-or-higher
security findings. Force pushes and deletion are blocked, with no bypass actors.
No independent approving reviewer is currently
required; [CODEOWNERS](.github/CODEOWNERS) identifies the maintainer.

`make policy-check` checks the reviewed exports. `python3 scripts/check-rulesets.py
--live` compares the actual GitHub configuration using read-only requests.
The weekly CI audit checks all visible policy and explicitly warns when GitHub
hides bypass lists from its read-only token. A full administrator audit must
confirm those lists; an omitted list is never treated as empty.

Actions receive read-only repository permissions and cannot approve PRs.
Dependencies and Actions have weekly Dependabot updates; secret scanning, push
protection, dependency alerts and private vulnerability reporting are enabled.
The release workflow can create a draft prerelease only after verified-tag and
complete SDK qualification gates. Stable publication is blocked while the project
is experimental. It never creates tags or deploys to Maven Central; see
[the release policy](docs/releases.md).

The draft release publisher uses the [reviewed `release` environment](.github/release-environment.json), restricted to workflow
runs from main. It rechecks GitHub-Verified source/tag identity and artifact hashes
before attestation and draft creation. Build jobs remain read-only; first-release
OIDC/publication validation is not established by local rehearsal. Downloaded
artifact integrity and SDK/version matching are required before installation.
