# Testing and evidence

## Extension qualification

`make integration-test KEYCLOAK_VERSION=VERSION` builds the provider and runs
isolated kernel/parser tests plus functional tests using the official
[Keycloak test framework](https://github.com/keycloak/keycloak/tree/2827b3fa10f96c6795d641636397252a8186115a/test-framework/docs).
The framework owns a real local Keycloak distribution and its disposable database.
Tests provision native clients, Authorization Services policies and administrative
grants, obtain actual OAuth tokens and verify signatures, issuer and expiry.
There are no mocking frameworks and no consumer/operator in this suite.
Chrome and a compatible ChromeDriver are required for the console case; Selenium
Manager can resolve the driver if it is not installed. The test opens an isolated
browser profile, creates a synthetic administrator and never uses a personal
browser session. Set `SE_AVOID_STATS=true` to disable Selenium Manager statistics.

The native cases cover activation/discovery, unchanged unselected-realm exchange,
permission intersection, audience/expiry/claim attenuation, noncommitted grants,
concurrent replay, inherited depth, live policy withdrawal, stale identity
bindings, invalid requests and actor-removal bypasses. Administration cases add
CRUD/withdrawal with actual token issuance, immutable client/resource identities,
external-writer isolation, realm-scoped view/manage rights, safe activation and
concurrent independent writes. A Chrome case creates, edits and disables a grant
in the real console, verifies the OAuth effect, and captures `qualification/console.png`. This is single-node
functional evidence, not cluster failover or production qualification.

The runner rejects absent, failed, duplicate or skipped required tests. Reports
under `target/VERSION/qualification/` bind results to source revision, worktree
state, SDK, packaged JAR and its SHA256. CI requires clean committed source.
Maven's Surefire and Failsafe reports remain available as build diagnostics.
The framework loads the compiled provider. Release validation checks that the
packaged JAR contains exactly those class bytes and resources, including SPI
descriptors, rather than assuming that packaging preserved the tested inputs.

## Consumer interoperability

Hanko's controller/transaction tests remain in its own repository. The optional
[consumer workflow](../.github/workflows/consumer-interop.yml) uses a fixed
harness commit and exercises this extension's actual JAR. It does not replace
native extension tests and is not a prerequisite for developing the extension.
Its pinned fixture window is separate from the extension SDK matrix; an extension
SDK upgrade never silently expands consumer qualification. See [consumer integration](integrations/hanko.md).

## Upstream evidence

The current-main source review is pinned in [upstream.json](../upstream.json).
Compilation and runtime tests against release SDKs are not qualification of
Keycloak main. An official change must be ported to the native test classes and
configuration hooks agreed with maintainers. The [proposal](upstream-proposal.md)
records target locations and remaining work.

## Before the first release

The [roadmap](roadmap.md) tracks clean CI evidence, alternate routes and version
upgrade/removal qualification. Performance under sustained
load, human/native consent, production incidents and all downstream topologies
are not established by the current CI. Keep release claims tied to actual tests.

## Two-node failure qualification

Build the exact SDK JAR, then run `make cluster-test KEYCLOAK_VERSION=VERSION`
with JDK 21 and Docker. `scripts/cluster.py` creates two isolated Keycloak JVMs
and PostgreSQL from [digest-pinned images](../cluster-images.json). HTTPS validates
the lab CA. The nodes share the database; a separate JGroups network allows a
cache partition while HTTPS and database access remain available. Cleanup targets
only randomly named, labelled lab resources. No existing deployment is used.

The lab generates temporary credentials inside a mode-0700 parent. Private Java
and Docker inputs are created exclusively with mode 0600, before their contents
are written. Only a separate TLS directory is mounted into the owned Keycloak
containers; credentials are excluded from the image build context and public
evidence. These plaintext inputs serve the disposable test processes and are
removed with the lab. Docker administrators remain a superior authority.

The required topology enables Keycloak's native `stateless` build feature so
single-use actor and chain state use the database. The suite checks competing
replay across nodes, independent fresh fan-out at 1/10/100 requests, inherited
depth/rights, acknowledged policy withdrawal, process kill/restart/rejoin and a
cache-only partition. It records accepted counts, p50/p95, withdrawal and recovery
timings. Requests use up to 100 worker threads, matching each selected concurrent sample count. These bounded synthetic samples
are not sustained overload or a throughput SLA. Per-node limits are two CPUs and
1 GiB. Reports record the Docker CPU/architecture allocation and a bounded
point-in-time CPU/memory sample after tests; this is not peak-memory profiling
or a physical-hardware benchmark.

`qualification/cluster.json` binds outcomes, measurements, image digests and JAR
hash to the exact SDK and source. `cluster-failsafe-reports/` retains raw JUnit
outcomes. Dirty local runs require `--allow-dirty` and remain nonpublishable.
Release packaging requires this evidence as well as the primary native suite;
CI must regenerate it from clean committed source for all supported SDKs.

During a cache partition, policy writes may fail or have an uncertain outcome.
The suite distinguishes an acknowledged withdrawal from such a failure and does
not infer global revocation from an unacknowledged write. Already issued offline
JWTs remain valid until expiry. The optional diagnostic `--state-store cache`
uses synchronous two-owner action-token storage and denies partition reads/writes;
it failed node-rejoin recovery in local testing and is **not a qualified topology**.
Neither the extension nor Hanko silently changes an existing deployment to the
database-backed feature. Select and qualify the topology explicitly before use.

Hanko 1.1.0 retains default software-v1 and adds explicit task authorization.
Native cases exercise issuer authentication, exact input-JTI approval binding,
single use, signed context, authenticated resource checks, cancellation, expiry,
policy withdrawal and refusal of task-claim stripping. The cluster suite adds
competing approval consumption and cancellation across a cache partition/rejoin.
See the [task authorization contract](rfcs/RFC-0002-task-authorization.md).

## Provider replacement and removal

`make lifecycle-test KEYCLOAK_VERSION=VERSION` downloads and verifies the actual published rc.2
provider JAR in [lifecycle-baseline.json](../lifecycle-baseline.json) for the
same exact SDK. It replaces both lab JVMs while retaining their PostgreSQL
database, native client/service-account identities and grant journal. Signed
software exchanges and unexpired spent-actor refusal are checked before and
after upgrade and rollback. Task authorization is enabled explicitly, exercised,
cancelled and withdrawn; its remaining lifetime elapses before rollback.

Removal first withdraws the grant and disables native token exchange for its
actor. The suite then runs the actual server without any provider JAR, proves
delegation is refused while native client credentials still work, and reinstalls
the candidate. Reinstallation does not re-enable exchange; a fresh explicit
configuration is required. Existing actor replay evidence must survive all phases.
The 20 required checks and restart timings are bound to source, exact SDK,
published baseline/candidate JAR hashes and pinned server/database images in
`qualification/lifecycle.json`. Release packaging rejects missing, foreign or
incomplete proof. CI runs it for every SDK. This covers coordinated restarts;
mixed-version rolling upgrades and arbitrary provider versions remain unqualified.
