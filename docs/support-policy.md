# 0.1.0 support and qualification policy

Version 0.1.0 is a qualified release of the independently maintained extension
for software service accounts. Each JAR supports only its exact Keycloak SDK:
26.7.5, 26.8.0 or 26.8.1, with Java 21. The complete release matrix must pass on
the exact signed release source before publication. No LTS branch or response
time SLA is declared; report vulnerabilities through [SECURITY.md](../SECURITY.md).

## Qualified scope

- Explicit realm activation, distinct confidential service-account clients and
  native Authorization Services permission intersection, bounded audience,
  lifetime and depth, replay refusal, native console/Admin API administration.
- Optional issuer-controlled single-use task approval, cancellation and mandatory
  authenticated online recipient decisions. Default software-v1 remains unchanged.
- Single-node native functional/console tests and the recorded two-node topology
  using shared PostgreSQL and the native `stateless` database-backed state store.
- Coordinated rc.2-to-0.1.0 replacement and rollback, guarded removal/reinstall,
  preservation of native identities, grant journals, spent actors and credentials.

Every SDK release requires 30 native/console cases, six two-node cases and the
20 lifecycle invariants listed in [compatibility.json](../compatibility.json),
plus its unit tests, class-byte/JAR/SDK checks, SBOM, checksums and provenance.
Skipped, incomplete, foreign-source or substituted-binary evidence is refused.
The lifecycle baseline is the actual public rc.2 JAR pinned by SHA-256.

## Contract and operational limits

The version is stable in the release channel; the 0.x administrative contract
is still in initial development. Its existing `experimental: true` discovery
marker remains part of the wire contract. A stable artifact version does not
silently change that marker, enable a realm or alter a consumer's version checks.
Breaking contract changes need explicit migration and a separately reviewed
version. Future stable versions are not automatically admitted by the publisher.

Human delegation/consent, cache-only recovery, mixed-version rolling upgrades,
arbitrary database/CNI topologies, sustained production load and a throughput SLA
are outside this qualification. Bounded concurrent measurements are reported for
the tested lab only. Already issued offline JWTs remain usable until expiry;
task cancellation requires the documented online recipient check.

Build and start every node with the documented database-state feature. Use a
coordinated maintenance window, preserve native database state, and withdraw
grants/wait their bounded lifetime before removing enforcement. See
[installation](installation.md) and [testing](testing.md) for the exact procedure.

Operator 1.1.0 requires extension rc.2. Its published binary is unchanged; use a
consumer build explicitly supporting 0.1.0 before replacing that provider.
Keycloak's community extension listing is independent of core Keycloak inclusion.
