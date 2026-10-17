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
See [consumer integration](integrations/hanko.md).

## Upstream evidence

The current-main source review is pinned in [upstream.json](../upstream.json).
Compilation and runtime tests against release SDKs are not qualification of
Keycloak main. An official change must be ported to the native test classes and
configuration hooks agreed with maintainers. The [proposal](upstream-proposal.md)
records target locations and remaining work.

## Before the first release

The [roadmap](roadmap.md) tracks multi-node cache/replay/chain failover, alternate
routes and version upgrade/removal qualification. Performance under sustained
load, human/native consent, production incidents and all downstream topologies
are not established by the current CI. Keep release claims tied to actual tests.
