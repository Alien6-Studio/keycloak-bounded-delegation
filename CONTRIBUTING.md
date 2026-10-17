# Contributing

Changes must explain their effect on authority, expiry, inherited limits and
alternative token-exchange routes, with regression tests and documentation.
Run Java tests and real HTTPS interoperability against every SDK listed in
compatibility.json. Use DCO sign-off (`git commit -s`) and signed commits.

The provider uses Keycloak's private SPI. Adding a supported version requires
actual compilation and native qualification; changing a filename or advertised
version is insufficient. Keep the generic policy kernel independent of Hanko and
Kubernetes. Hanko's controller adapter and installed workload qualification stay
in its own repository.

Contributions intended for Keycloak follow its current contribution guide:
https://github.com/keycloak/keycloak/blob/main/CONTRIBUTING.md
Discuss a substantial enhancement before preparing a focused patch on Keycloak
main, with its native tests and documentation. Disclose AI agent assistance and
retain human responsibility for review and licensing. This prototype is not an
upstream patch and does not claim upstream endorsement.

## Contributor checks

Install Python dependencies with `python3 -m pip install -r scripts/requirements.txt`.
Run `make hook-tools` then `make hooks-check policy-check` before committing.
Install the commit hook with `python3 .tools/hook-tools/pre-commit.pyz install`.
CI runs the same hooks and policy regression tests. The pull-request DCO check
examines every commit in the exact base/head range. GitHub Verified Dependabot
commits and GitHub Verified web-flow commits are explicit automation exceptions;
other contributions require an author-matching `Signed-off-by` trailer.
Before squash merge, retain contributor sign-offs and include one matching the
resulting author; verify GitHub's signature on the merged commit.
Implementation tickets close when their completed implementation is pushed, with
its exact commit and available qualification evidence. Qualification tickets stay
open until their full runtime criteria pass.
