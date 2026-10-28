# Architecture and software-v1 protocol

## Components

| Component | Responsibility | Candidate upstream scope |
| --- | --- | --- |
| `Authority`, `Bounds` | Immutable authority intersection, minimum expiry and depth decision | Generic optional policy semantics |
| `BoundedTokenExchangeProvider` | Verify native inputs, evaluate current native policies, constrain output before signing | Integrate with the native exchange pipeline after design agreement |
| `GrantDocument`, `SoftwareProfile` | Strict experimental administrative schema and deployment limits | Prototype configuration, not an agreed Keycloak API |
| `ChainState` | Expiring inherited policy evidence and atomic actor consumption | Cluster state and optional replay policy need separate review |
| `AdministrativeGrants`, `DelegationPage`, `DelegationSettings` | Native component storage, server validation and optional console forms | Prototype administration; reuse agreed native screens upstream |
| `AdministrationResource` | Realm-authorized structural diagnostics; writes stay in the native audited Admin API | Prototype diagnostics |
| `CapabilityResource` | Public version/profile/activation metadata | Extension discovery, not a proposed mandatory native endpoint |

The Java kernel does not depend on Kubernetes, an operator, a token broker or
application frameworks. The bridge uses private Keycloak APIs and must be
compiled and qualified for every supported SDK.

## Issuance

1. The realm administrator explicitly selects `software-v1`.
2. The requester authenticates to Keycloak using a supported native confidential
   client authentication method and sends both actor and subject access tokens.
3. Keycloak verifies both tokens. The provider resolves one committed grant for
   the requester, subject and audience and rechecks the bound client identities.
4. Current native service-account memberships and Authorization Services
   policies must allow the requested resource/scope permissions for both parties.
5. The provider intersects input authority, the grant and live policy; inherited
   chain evidence constrains depth and TTL. It rejects an empty intersection,
   alternate-route bypasses, unsupported token types and sender constraints.
6. The actor JTI is consumed atomically. Keycloak creates and signs an access
   token with one audience, bounded expiry, attenuated permissions and `act`.
   Private expiring evidence records inherited limits, without raw tokens.

A failure after actor consumption can consume the input without returning an
output token. Callers must obtain a new actor token; issuance is not an
exactly-once delivery protocol. The [cluster suite](testing.md#two-node-failure-qualification)
tests native database-backed single-use state (`stateless`) with a shared
PostgreSQL database. It does not establish correctness of arbitrary embedded
cache topologies or immediate policy revocation during a partition.

Unknown or blank selected profile values refuse bounded requests rather than
falling through to standard exchange. Only removing the realm selector restores
the unselected native path. Bounded actor requests use a strict form allowlist;
software-v1 rejects task-context fields and unsupported exchange options.

## Administrative wire contract

The realm attribute is `oauth.bounded-delegation.profile=software-v1`.
The audience client attribute `oauth.bounded-delegation.v1` holds a version-1
`GrantDocument`. Only `Committed` executes. `Prepared`, `Applied` and `Verified`
are non-executable states available to external configuration writers.

Each binding contains a native client UUID and an administrator-selected
attribute/value. Those values must still match at issuance. `ownerUID` is an
opaque administrative owner key retained for wire compatibility; it is not
interpreted as a Kubernetes UID by this extension. `revision` is a non-secret
configuration revision, not an approval supplied in an OAuth request.

A grant identifies distinct actor and subject clients, authority, native client,
role or group conditions, maximum depth and TTL. Software-v1 requires nonempty
UMA permissions and imposes four-hop / 600-second ceilings. Unknown fields,
duplicate JSON keys, malformed values and oversized documents are rejected.
The complete parser is [GrantDocument.java](../src/main/java/io/alien6/keycloak/delegation/GrantDocument.java).

Task-required audiences explicitly use `version: 2` and
`profile: task-bound-software` in that same attribute. This journal discriminator
refuses legacy parsers; it does not rename the product or the default software
profile. The separate [task contract](rfcs/RFC-0002-task-authorization.md) defines
issuer registration, exact-input one-use approval, signed context, cancellation
and authenticated online recipient checks. It requires native database-backed
single-use state and one hop. Existing version-1 audiences keep their wire bytes
and behavior even when the task option is enabled elsewhere in the realm.

`oauth.bounded-delegation.actor.v1` on an actor blocks omission of `actor_token`
from falling through to ordinary native exchange. Configuration writers own its
lifecycle and must preserve other writers' bindings. The provider does not
implement an external writer's ownership/reconciliation protocol.

## Console-managed configuration

The optional [console and component API](administration.md) stores one grant per
native Keycloak component. No aggregate journal is rewritten on each save. The
server binds native client/resource UUIDs at creation, validates scope membership
and limits, and rejects audiences owned by an external document writer. The
reserved binding `@keycloak.client.uuid` compares the exact native client UUID,
not a client attribute or reusable name; external attribute/value bindings remain
unchanged. The private generated grant snapshot is deterministic across JVMs,
including scope ordering, so ancestor hashes do not depend on map iteration.

Native component transactions, realm permissions and administrative audit events
apply to both forms and direct API calls. Ordinary same-entry updates use native
last-committed-write semantics; independent grant rows avoid aggregate lost updates.
Changing/removing a component invalidates the audience snapshot for future chaining.
Deleting a grant retains its actor guard; restoring ordinary exchange is a separate
administrative trust-boundary change. The realm settings form checks withdrawal
and requires explicit expiry confirmation before disabling enforcement.

## Revocation and removal

Withdrawal or modification of a grant prevents future affected issuance and
invalidates further exchange of recorded descendant chains. Already issued,
offline-validated access tokens are bounded by expiry, not instant revocation.
Withdraw grants and wait their maximum remaining lifetime before disabling the
realm profile or removing the provider. Removing enforcement prematurely changes
the deployment's trust boundary.
