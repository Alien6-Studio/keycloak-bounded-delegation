# Architecture and software-v1 protocol

## Components

| Component | Responsibility | Candidate upstream scope |
| --- | --- | --- |
| `Authority`, `Bounds` | Immutable authority intersection, minimum expiry and depth decision | Generic optional policy semantics |
| `BoundedTokenExchangeProvider` | Verify native inputs, evaluate current native policies, constrain output before signing | Integrate with the native exchange pipeline after design agreement |
| `GrantDocument`, `SoftwareProfile` | Strict experimental administrative schema and deployment limits | Prototype configuration, not an agreed Keycloak API |
| `ChainState` | Expiring inherited policy evidence and atomic actor consumption | Cluster state and optional replay policy need separate review |
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
exactly-once delivery protocol. Multi-node atomicity/failover remains a release
readiness gap until tested with a shared database/cache.

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

`oauth.bounded-delegation.actor.v1` on an actor blocks omission of `actor_token`
from falling through to ordinary native exchange. Configuration writers own its
lifecycle and must preserve other writers' bindings. The provider does not
implement an external writer's ownership/reconciliation protocol.

## Revocation and removal

Withdrawal or modification of a grant prevents future affected issuance and
invalidates further exchange of recorded descendant chains. Already issued,
offline-validated access tokens are bounded by expiry, not instant revocation.
Withdraw grants and wait their maximum remaining lifetime before disabling the
realm profile or removing the provider. Removing enforcement prematurely changes
the deployment's trust boundary.
