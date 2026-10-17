# Contributing

This project maintains a Keycloak extension and prepares a focused contribution
to native Keycloak. Start with the [proposal](docs/upstream-proposal.md),
[architecture](docs/architecture.md) and [roadmap](docs/roadmap.md). Raise design
questions in Discussions and use issue templates for reproducible bugs/proposals.
Security and conduct reports use [SECURITY.md](SECURITY.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Local development

Use JDK 21, Chrome for console tests, and the pinned Maven wrapper. Run SDK variants sequentially locally:

```sh
./mvnw spotless:apply
./mvnw verify
make integration-test KEYCLOAK_VERSION=26.7.5
make integration-test KEYCLOAK_VERSION=26.8.0
make integration-test KEYCLOAK_VERSION=26.8.1
make release-dry-run KEYCLOAK_VERSION=26.8.1
```

The Java import-order, unused-import and wildcard checks follow the reviewed
Keycloak Spotless rules.
Native tests use Keycloak's own framework with real distributions and native
Admin/OAuth APIs. Keep the kernel small and independent; add functional regression
cases for changed issuance, policy, expiry, depth, replay and alternate routes.
Do not add mocking frameworks. Consumer tests are optional and separate.
See [testing](docs/testing.md) for ports, evidence and qualification limits.

Install Python policy dependencies with `python3 -m pip install -r scripts/requirements.txt`.
Run `make hook-tools hooks-check policy-check`. Install the commit hook using
`python3 .tools/hook-tools/pre-commit.pyz install`. CI also checks the complete
SDK inventory, Maven/wrapper metadata, repository policy and release validation.

## Pull requests and certification

Explain the concrete behavior, compatibility and migration effect. Link the issue
or design decision, include qualification evidence and disclose AI-agent
assistance when applicable. Preserve the software-v1 wire contract unless a new
version and migration plan are reviewed. Adding an SDK requires real native tests;
changing a version string alone is insufficient.

Use signed commits with an author-matching DCO trailer (`git commit -s`). The PR
check examines every commit in the exact base/head range. GitHub Verified
Dependabot and GitHub Verified web-flow commits are the documented automation
exceptions. Squash merges retain contributor sign-offs and one matching the
resulting author. Verify GitHub's signature after integration.

Completed implementation tickets close at the implementation push with exact
commit/evidence references. Qualification tickets close only after all runtime
criteria pass. Do not describe the upstream proposal as accepted or the
experimental extension as stable. Releases follow [docs/releases.md](docs/releases.md).

## Contributing to official Keycloak

Follow [Keycloak's current guide](https://github.com/keycloak/keycloak/blob/main/CONTRIBUTING.md)
and refresh the [reviewed baseline](upstream.json). Discuss substantial changes
first; port an agreed small scope to current upstream main using its native test
helpers and documentation. The prototype's administrative writer protocol is not
an upstream API proposal. All contributions remain Apache-2.0; the submitting
maintainer is responsible for understanding the code and responding to review.
