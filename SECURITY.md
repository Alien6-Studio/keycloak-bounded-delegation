# Security policy

## Support and reporting

This is an experimental private-SPI extension, currently `0.1.0-SNAPSHOT`.
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
claimed. Shared-cache failover and installed Kubernetes qualification remain
tracked by [Hanko #71](https://github.com/Alien6-Studio/hankoshell-operator/issues/71).
See [README.md](README.md) for deployment and withdrawal requirements.

## Repository protections

[Default-branch](.github/rulesets/default-branch.json) and
[tag](.github/rulesets/release-tags.json) rulesets require signed commits, linear
history, squash PRs, resolved review threads and the up-to-date `Extension checks`
aggregate bound to GitHub Actions. CodeQL blocks errors and high-or-higher
security findings. Force pushes and deletion are blocked, with no bypass actors.
As in the operator repository, no independent approving reviewer is currently
required; [CODEOWNERS](.github/CODEOWNERS) identifies the maintainer.

`make policy-check` checks the reviewed exports. `python3 scripts/check-rulesets.py
--live` compares the actual GitHub configuration using read-only requests.
The weekly CI audit checks all visible policy and explicitly warns when GitHub
hides bypass lists from its read-only token. A full administrator audit must
confirm those lists; an omitted list is never treated as empty.

Actions receive read-only repository permissions and cannot approve PRs.
Dependencies and Actions have weekly Dependabot updates; secret scanning, push
protection, dependency alerts and private vulnerability reporting are enabled.
No workflow publishes Maven artifacts, tags or releases.
