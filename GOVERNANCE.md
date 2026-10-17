# Governance and maintenance

Alien6 Studio maintains this independent Apache-2.0 project. The current repository
maintainer is [@Coopyrightdmin](https://github.com/Coopyrightdmin), also listed in
[CODEOWNERS](.github/CODEOWNERS). Additional maintainers can be proposed through a
reviewed pull request documenting responsibilities and access changes.

Changes use public issues/discussions and reviewed pull requests. Security reports
use the private process in [SECURITY.md](SECURITY.md). Maintainers decide scope,
compatibility and release eligibility from the documented contract and available
evidence; disagreements can be raised in a discussion with a concrete alternative.

Protected main requires verified signatures, linear history, the complete CI
aggregate, CodeQL and resolved review threads. Squash merges retain contributor
sign-offs. No independent approving reviewer is mandatory while there is a single
maintainer; that limitation is explicit, not a claim of independent security review.

A maintainer reviews release notes, compatibility and evidence before manually
publishing the draft created by the release workflow. Open runtime qualification
work must be disclosed. Upstream Keycloak maintainers alone decide whether a
proposal is accepted and how it is integrated. A prototype release here does not
imply official Keycloak support or a commitment from that project.
