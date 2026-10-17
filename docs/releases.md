# Releases

## Version and scope

The project is currently `0.1.0-SNAPSHOT`. The intended first public candidate is
**0.1.0-rc.1**, after native qualification and maintainer review. No release or tag
has been issued as part of repository preparation. The current release validator
accepts experimental prereleases only; stable publication requires a separately
reviewed readiness/support-policy change and closing the runtime gaps in the
[roadmap](roadmap.md).

One project version covers the extension contract. Every qualified Keycloak SDK
gets its own binary; private-SPI compatibility is never inferred from a shared
project version. Breaking grant-schema changes require a new contract/profile and
migration notes. Update the Maven version in a reviewed commit; packaged discovery
metadata is generated from that version.

## Distribution

Each SDK cell supplies:

- `bounded-delegation-VERSION-keycloak-SDK.jar`: thin provider, license and NOTICE.
- `...-sources.jar` and `...-javadoc.jar`.
- `...-sbom.json`: CycloneDX inventory including provided Keycloak dependencies,
  excluding test dependencies. These provided libraries are not shaded into the JAR.
- `...-qualification.json`: clean source/SDK identity, exact native outcomes and JAR SHA256.
- `release-SDK.json`: asset hashes and matrix-cell identity.

The complete bundle adds LICENSE, NOTICE, the exact committed source archive,
release notes and SHA256SUMS. GitHub provenance attestations cover every final
file, including the checksum list. An SBOM is an inventory, and an attestation
binds build identity/content; neither establishes absence of vulnerabilities.
This workflow publishes GitHub draft assets only. Maven Central namespace,
signing and publication are not configured or claimed; identical Maven
coordinates must never be overwritten with different SDK builds.

## Rehearse without publication

```sh
make release-dry-run KEYCLOAK_VERSION=26.7.5
make release-dry-run KEYCLOAK_VERSION=26.8.0
```

Each command runs native qualification, generates all SDK assets and checks the
provider's Java 21 bytecode, packaged version/licenses, SDK inventory and hashes.
CI also downloads both immutable SDK candidates and exercises the full bundle
assembly. Candidate manifests are explicitly non-releasable. Local/CI rehearsal
does not exercise production GitHub OIDC signing or remote publication.

## Cut an experimental candidate

1. Review the roadmap, compatibility window, dependency/security findings and
   release notes. Close only qualification work supported by actual evidence.
2. Prepare a PR changing the POM to `0.1.0-rc.1`, reviewing CHANGELOG.md and updating
   README release status/badges and the supported-version security policy. Keep
   the complete SDK matrix and required `Extension checks` / CodeQL gates green.
3. Merge through protected main. Create a **signed annotated** tag such as
   `v0.1.0-rc.1` for that exact GitHub-Verified source commit and push the tag.
   Both source and tag must be GitHub Verified; lightweight, foreign and moved
   tag identities are rejected. The workflow never creates or rewrites tags.
   Start the workflow while main still identifies that exact tagged commit.
   Eligibility runs its checker from the immutable workflow commit, never from
   unverified tag code, and requires the tag to match it. This also keeps the
   attested workflow/source identity equal to the actual artifact source.
4. Run the `Draft prerelease` workflow **from main**, supplying that existing tag:

   ```sh
   gh workflow run release.yml --ref main -f tag=v0.1.0-rc.1
   ```

5. Eligibility verifies tag/source signatures, protected-main ancestry and POM
   version. Source policy and every native SDK cell rerun on the exact revision.
   The publisher downloads only this run's SDK artifacts, verifies the complete
   inventory/hashes and rechecks the tag before attesting and creating a draft.
6. Review the draft's evidence, assets, notes and known limitations; publish it
   manually when ready. The workflow never publishes a stable or public release
   automatically. If a draft/tag already exists, creation fails rather than
   overwriting existing release assets; inspect the earlier run before retrying.
   A retry of the original workflow run retains its source identity. Starting a
   new run after main advances requires a new reviewed candidate; do not move tags.

Only the final draft job has content/attestation write permissions. It uses the
`release` environment restricted to workflows running from main. Build/test jobs
are read-only. These environment settings complement the versioned main/tag
rulesets; administration changes require review.

## Verify a download

```sh
sha256sum -c SHA256SUMS
gh attestation verify bounded-delegation-VERSION-keycloak-SDK.jar \
  --repo Alien6-Studio/keycloak-bounded-delegation
```

Match the attested source and exact SDK to the intended release. Copy only its
provider JAR to Keycloak's providers directory and rebuild the server. Review
[activation and safe withdrawal](installation.md) before installing or removing it.
