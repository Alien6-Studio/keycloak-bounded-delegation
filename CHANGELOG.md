# Changelog

## Unreleased — 0.1.0-SNAPSHOT

- Harden selected-profile routing and reject unsupported bounded-exchange form fields without standard-exchange fallback; preserve unselected native realms.
- Add HTTPS native regressions for separate protected audiences, mapper/duplicate-field refusal, fresh fan-out, replay and disabled inputs.
- Add digest-pinned two-node PostgreSQL/native database-state replay, chain, partition and recovery qualification for every supported SDK, with mandatory release evidence and measured limits.
- Add optional issuer-controlled task authorization for Hanko 1.1.0: one-use approvals bound to exact native inputs, signed context, cancellation and authenticated online recipient decisions. Preserve default software-v1 discovery and wire bytes; use an explicit legacy-refusal journal discriminator for task-required audiences.
- Refuse previously issued subject inputs after their client becomes public.
- Add native console forms and component Admin API for bounded software delegations, shared server validation, realm-scoped diagnostics, withdrawal safeguards and browser tests.
- Qualify Keycloak 26.8.1 alongside 26.7.5 and 26.8.0; update Maven test/build tools, JUnit, PyYAML hashes and Node 24 Actions.
- Simplify the README around installation and administration, with CI/license/Java/SDK/status badges.

- Reframe the project around Keycloak-native integration and a focused upstream proposal.
- Add standalone real-server tests using the official Keycloak framework; separate consumer interoperability.
- Add a pinned Maven wrapper, native formatting rules, packaged version metadata, sources/Javadoc and release SBOMs.
- Prepare signed-tag eligibility, asset/checksum verification, provenance attestations and draft-prerelease publication.
- Document installation, architecture, support, governance, roadmap and the current native downscoping overlap.

- Extract the experimental software-only bounded delegation extension from Hanko
  while preserving component history and source provenance.
- Qualify Java and real HTTPS interoperability on Keycloak 26.7.5 and 26.8.0.
- Add independent CI, DCO, repository protection auditing and dependency updates.

No stable release or Maven publication exists.
