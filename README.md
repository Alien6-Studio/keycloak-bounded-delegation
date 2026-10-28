# Keycloak Bounded Delegation

[![CI](https://github.com/Alien6-Studio/keycloak-bounded-delegation/actions/workflows/ci.yml/badge.svg)](https://github.com/Alien6-Studio/keycloak-bounded-delegation/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Java 21](https://img.shields.io/badge/Java-21-007396)](CONTRIBUTING.md)
[![Keycloak compatibility](https://img.shields.io/badge/Keycloak-26.7.5%20%7C%2026.8.0%20%7C%2026.8.1-4d4d4d)](compatibility.json)
[![Experimental](https://img.shields.io/badge/status-experimental-orange)](docs/roadmap.md)
[![Release candidate](https://img.shields.io/badge/release-0.1.0--rc.1-orange)](https://github.com/Alien6-Studio/keycloak-bounded-delegation/releases/tag/v0.1.0-rc.2)

Give a service limited permission to act on behalf of another service, with
**bounded permissions, audience, lifetime and delegation depth**.

For example, a billing service can let a worker read one invoice for 30 seconds,
with at most two delegation hops. Every exchange keeps those limits, even when
the original clients or tokens have broader permissions.

This is an independent Apache-2.0 extension maintained by Alien6 Studio. We are
preparing a focused contribution to native Keycloak; no upstream proposal has
been submitted or accepted. [Read the integration plan](docs/upstream-proposal.md).

## Build and install

Use **JDK 21** and the Maven wrapper. The default SDK is Keycloak **26.8.1**.

```sh
./mvnw verify
```

Set `KEYCLOAK_HOME` to a matching Keycloak installation, then install the provider:

```sh
cp target/26.8.1/bounded-delegation-keycloak-26.8.1.jar "$KEYCLOAK_HOME/providers/"
"$KEYCLOAK_HOME/bin/kc.sh" build --features=declarative-ui
```

Restart the server with the same feature enabled. In a dedicated software realm:

1. Configure the service-account clients and native Authorization Services policies.
2. Activate **Realm settings → Bounded delegation**.
3. Open **Bounded delegations**, select actor, subject and audience, enter the
   resource and scopes, and set lifetime and depth limits.

Follow the [installation guide](docs/installation.md) for prerequisites and
[administration guide](docs/administration.md) for the screens and equivalent API.
The console uses Keycloak's opt-in `declarative-ui` extension mechanism. Automated
configuration remains available through the Admin API.

## What it enforces

- Resource/scope permissions shared by both input tokens, the grant and current native policies.
- One declared audience, at most **600 seconds** and **four inherited hops**.
- Actor replay protection and refusal of stale identity bindings or changed ancestor grants.
- Console/API administration with native permissions, validation and administrative audit events.
- Optional [task authorization](docs/rfcs/RFC-0002-task-authorization.md), with issuer-controlled single-use approval, cancellation and mandatory online recipient checks.

The current profile supports **software service accounts and UMA permissions**.
Human delegation and production readiness remain unqualified. A disposable
[two-node suite](docs/testing.md#two-node-failure-qualification) covers the explicit
database-backed single-use topology; this does not certify other cache topologies.
Withdrawing a grant stops future issuance; existing offline JWTs remain valid
until expiry. See [security boundaries](SECURITY.md) and the [roadmap](docs/roadmap.md).

## Develop and contribute

Run the functional and console tests against a real Keycloak distribution:

```sh
make integration-test KEYCLOAK_VERSION=26.8.1
```

Use JDK 21 and Chrome; no Docker, Go or consumer repository is needed. Run SDK
variants sequentially locally. See [testing](docs/testing.md) and
[CONTRIBUTING.md](CONTRIBUTING.md) for the full matrix and checks.

The first distributed experimental candidate is **0.1.0-rc.2**. The
[release workflow](docs/releases.md) qualifies every SDK and prepares versioned
JARs, sources, Javadoc, SBOM, checksums and attestations in a GitHub draft.
After publication, download the JAR matching your exact Keycloak version from the
[candidate assets](https://github.com/Alien6-Studio/keycloak-bounded-delegation/releases/tag/v0.1.0-rc.2).
Verify its checksums and provenance before installation; Maven Central publication
is not configured.

[Architecture](docs/architecture.md) · [Roadmap](docs/roadmap.md)
