# Keycloak Bounded Delegation

[![CI](https://github.com/Alien6-Studio/keycloak-bounded-delegation/actions/workflows/ci.yml/badge.svg)](https://github.com/Alien6-Studio/keycloak-bounded-delegation/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An experimental Keycloak extension for **bounded delegated token exchange**, and
a reference implementation for proposing these controls to the Keycloak project.
It limits what a software actor can do on behalf of a subject: permissions,
audience, token lifetime and inherited delegation depth.

The project targets integration with Keycloak's native exchange and client-policy
mechanisms. It is independently maintained by Alien6 Studio; an upstream proposal
is being prepared and has not been submitted or accepted. See the
[proposal and integration plan](docs/upstream-proposal.md).

## Why bounded delegation?

A billing service may delegate permission to read one invoice to a worker, for
30 seconds and at most two hops. An exchange must preserve those limits even
when an input token or the requesting client's defaults contain more authority.
This extension's software profile enforces:

```text
output permissions ⊆ actor input ∩ subject input ∩ declared grant ∩ current native policies
output audience    = one declared resource server
output expiration  ≤ min(actor expiry, subject expiry, native expiry, policy TTL)
output depth       ≤ every inherited chain limit
```

Keycloak already provides standard token exchange, delegation work and a
[client policy for downscoping](https://www.keycloak.org/securing-apps/token-exchange).
Our [upstream comparison](docs/upstream-proposal.md#relationship-to-native-keycloak)
explains the proposed additional policy controls and the integration questions.
The prototype's administrative journal and replay policy are separate design
choices, not requirements of RFC 8693.

## Try the extension

Use **JDK 21**. The Maven wrapper downloads its pinned Maven distribution.

```sh
./mvnw verify
./mvnw -Pnative-tests verify
```

The first command runs isolated Java tests and builds the provider, sources and
Javadoc JARs. The second runs functional tests on a real Keycloak distribution
managed by the **official Keycloak test framework**. It needs no Docker, Go,
Kubernetes or consumer repository. The framework uses local ports 8080, 8443
and 9001; keep those ports free. Run SDK variants sequentially on a developer
machine; CI isolates each matrix cell.

```sh
make integration-test KEYCLOAK_VERSION=26.7.5
make integration-test KEYCLOAK_VERSION=26.8.0
```

The exact qualification window is recorded in [compatibility.json](compatibility.json).
The current profile is `bounded-delegation/software-v1`, version
`0.1.0-SNAPSHOT`. There is no published release yet. A failed, missing or skipped
required test fails qualification; results record source identity and JAR hashes.

Follow [installation and configuration](docs/installation.md) to build a server
image, explicitly activate the realm profile and install administrative grants.
The provider JAR is `target/VERSION/bounded-delegation-keycloak-VERSION.jar`.
Match its SDK to the running Keycloak version.

## What is implemented?

| Area | Current software profile |
| --- | --- |
| Identities | Distinct, enabled confidential service-account clients |
| Authority | UMA resource/scope permissions intersected with both inputs and live native policy |
| Other claims | Ambient OAuth scopes, realm/client roles and arbitrary mapper claims are removed from delegated output |
| Audience | One explicitly declared Authorization Services resource server |
| Lifetime and depth | Minimum input/native/policy expiry; inherited limits; ceilings of 600 seconds and four hops |
| Replay | Atomic actor JTI consumption through Keycloak's single-use-object provider |
| Administrative state | Only committed, identity-bound grants execute; stale bindings and changed ancestor grants are refused |
| Ordinary exchange | Unselected realms retain native exchange; selected realms prevent alternative-route bypasses |

The independent [policy kernel](src/main/java/io/alien6/keycloak/delegation/Bounds.java)
can represent additional authority dimensions. The current server bridge emits
only bounded UMA permissions; kernel tests do not establish server support for
additional role or scope grant modes. See [architecture and protocol](docs/architecture.md).

Multi-node failover, human delegation, sender-constrained delegated tokens and
production readiness remain outside the current qualification. Previously issued
offline JWTs remain valid until their bounded expiry. See
[security boundaries](SECURITY.md) and the [release readiness roadmap](docs/roadmap.md).

## Releases and contribution

The [release process](docs/releases.md) prepares one versioned binary, sources,
Javadoc and SBOM per qualified SDK, SHA256 checksums and build attestations.
Publication starts with a verified annotated tag on protected `main`, reruns
qualification, and creates a **draft prerelease**. The current experimental
policy blocks stable releases. No release has been created by this refactoring.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [support](SUPPORT.md) and
[governance](GOVERNANCE.md). For the intended official contribution, follow the
[upstream path](docs/upstream-proposal.md#contribution-sequence): focused scope,
maintainer discussion, native tests and documentation. The original consumer's
[optional interoperability suite](docs/integrations/hanko.md) stays separate
from the extension's own qualification. Historical provenance is in [SOURCE.md](SOURCE.md).
