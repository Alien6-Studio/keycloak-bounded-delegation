# Roadmap and release readiness

The project develops an extension and an upstream proposal in parallel. Completing
repository scaffolding does not mark the security/runtime gates below complete.

| Milestone | Evidence required | Status |
| --- | --- | --- |
| Independent extension | Native functional tests, version-specific builds, public protocol and contribution documentation | Qualified by the required native SDK matrix |
| Console and API administration | Native forms, shared server validation, RBAC/audit, withdrawal and Chrome/OAuth end-to-end tests | Implemented; complete SDK qualification required |
| First experimental prerelease | Protected-main source, verified signed tag, complete SDK matrix, versioned assets/SBOM/checksums/attestations, reviewed scope and known limitations | Workflow prepared; no release issued |
| Cluster qualification | Two real Keycloak nodes with shared PostgreSQL and native database-backed single-use state; replay, chain, partition and restart evidence | Suite implemented; all three SDKs passed local dirty-source runs; clean CI evidence required; cache-only recovery unsupported |
| Operational qualification | SDK upgrade/removal, alternate exchange routes, provider failures, leak checks and performance budgets | Partially covered; complete matrix open |
| Upstream design agreement | Maintainer discussion, overlap review with native policies, agreed first scope and configuration | Not submitted |
| Upstream implementation | Focused patch on current Keycloak main, native functional tests, documentation, DCO and AI disclosure | Not started |
| Stable extension release | Runtime gaps above closed with linked evidence, stable configuration/support policy and maintainer sign-off | Blocked by open qualification work |

The first upstream candidate should be small: optional lifetime/depth bounds
integrated with native exchange. Full authority intersection, cluster evidence and
actor single-use semantics require explicit design discussion and may be separate
changes. Reuse the existing downscoping executor where it supplies the requested
semantics. No accepted upstream issue or maintenance commitment is implied.

Consumer-specific installed tests, Kubernetes identity federation and external
configuration-journal recovery remain in consumer repositories. They are useful
interop evidence, not the extension's identity or its upstream contribution scope.

Hanko 1.1.0 includes optional issuer-controlled task authorization, with native
database state, one-use approvals, cancellation and online resource enforcement.
Default software-v1 remains compatible. Native/consumer clean CI and release
qualification are still required; the feature name is independent of product
versioning. See the [selected contract](rfcs/RFC-0002-task-authorization.md).
