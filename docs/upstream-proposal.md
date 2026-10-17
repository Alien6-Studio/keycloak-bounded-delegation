# Proposal: optional bounds for delegated token exchange

Status: local proposal, not submitted or accepted. Source review targets
Keycloak [`2827b3fa10f96c6795d641636397252a8186115a`](https://github.com/keycloak/keycloak/tree/2827b3fa10f96c6795d641636397252a8186115a),
reviewed on 2026-10-17. Release-SDK functional tests do not qualify this main revision.
Machine-readable tracking is in [upstream.json](../upstream.json).

## Problem and desired behavior

A software actor needs a deliberately limited part of a subject's authority for
one downstream API. Administrators need optional limits that remain effective
across a chain: authority, audience, expiry and hop count. These are application
policy requirements; RFC 8693 does not automatically provide them or mandate
one-use actor inputs.

```text
output authority ⊆ actor input ∩ subject input ∩ current grants ∩ configured policy
output audience ⊆ policy audience
output expiry ≤ min(actor expiry, subject expiry, native expiry, now + policy TTL)
output depth ≤ configured and inherited limits
```

An `act` history provides identity/audit context. It does not itself prove an
ancestor's permission to create another hop. Neither scopes, realm/client roles
nor UMA permissions may be treated as interchangeable authority dimensions.

## Relationship to native Keycloak

| Native mechanism at the reviewed revision | Relationship to the proposal |
| --- | --- |
| Standard token exchange V2 | Preserve its endpoint, client authentication, token validation and native issuance pipeline |
| Delegation implementation in `TokenExchangeDelegationTest` | Integrate with native actor binding and consent; the software-only prototype does not qualify human delegation |
| `downscope-assertion-grant-enforcer` | Reuse its restrictions on client scopes; do not introduce a competing downscoping system |
| `RejectMayActClaimExecutor` | Preserve its claim-issuance/consent policy; it does not constitute evidence of all proposed bounds |
| Authorization Services policy evaluation | Candidate basis for live resource/scope intersection; effective memberships and composites need explicit tests |

The [native downscoping executor](https://github.com/keycloak/keycloak/blob/2827b3fa10f96c6795d641636397252a8186115a/services/src/main/java/org/keycloak/services/clientpolicy/executor/DownscopeAssertionGrantEnforcerExecutor.java)
restricts effective scopes in token-exchange and JWT assertion-grant contexts.
The [exchange guide](https://www.keycloak.org/securing-apps/token-exchange)
documents that policy. This source review identifies overlap, not a complete
runtime comparison with the bounded software profile. A first upstream patch
should extend the existing native mechanism where possible.

## Proposed first scope

Discuss optional **lifetime and inherited depth bounds** on native delegated
exchange as a focused first contribution. Agree whether those belong in client
policies, the native delegation provider or a small shared issuance hook before
choosing a public configuration model. Add no external service or token format.

Treat authority intersection as a related but separately reviewable scope, with
explicit dimensions and live native authorization. The prototype's UMA-only
bridge should not be presented as complete role/scope intersection support.

Atomic actor replay protection and cluster-side chain evidence need their own
design agreement. Input reuse is permitted by RFC 8693; single-use semantics are
an optional deployment policy. Human consent stays native. The following are
prototype integration details rather than proposed core APIs: administrative
`ownerUID`/journal fields, consumer reconciliation, the capability endpoint,
Kubernetes references, and deployment-specific actor ownership markers.

## Candidate implementation locations

| Concern | Existing target to review with maintainers |
| --- | --- |
| Policy configuration and invocation | `services/.../clientpolicy/executor/DownscopeAssertionGrantEnforcerExecutor.java` and native token-exchange contexts |
| Actor/subject validation and output bounds | `services/.../protocol/oidc/tokenexchange/StandardTokenExchangeProvider.java` and the delegation implementation |
| Functional regression tests | `tests/base/.../oauth/tokenexchange/TokenExchangeDelegationTest.java` and `StandardBaseTokenExchangeClientPoliciesV2Test.java` |
| Test conventions | `test-framework/docs/` and adjacent native tests |
| User documentation | Native token-exchange and client-policy guide chapters |

The standalone [official-framework tests](../src/it/java/io/alien6/keycloak/delegation/BoundedDelegationIT.java)
are portable functional evidence. They exercise a private-SPI provider on release
SDKs. The actual upstream patch must use the accepted main-branch extension points,
package/layout and existing test helpers; this repository is not that patch.

## Questions to resolve

- Which lifetime/depth configuration and inherited-state representation fit the
  existing native delegation feature?
- Can the downscoping executor supply part of the required authority intersection,
  and which dimensions need additional evaluation?
- How should ancestor policy changes and cache loss affect further exchange?
- Is one-use actor input desirable as a separate optional policy?
- Which clustering, consent and alternative-route regressions should be required
  for each focused change?

## Contribution sequence

Follow the current [Keycloak contribution guide](https://github.com/keycloak/keycloak/blob/2827b3fa10f96c6795d641636397252a8186115a/CONTRIBUTING.md):

1. Refresh the baseline and inspect related delegation work before opening duplicates.
2. Open an Ideas discussion with the focused problem, existing native overlap,
   desired invariants and prototype evidence. No message has been posted yet.
3. Agree scope with maintainers; create an associated upstream issue using its
   templates. Record links in `upstream.json`.
4. Implement one focused change on current upstream main, with native functional
   tests, documentation and the project's formatting checks.
5. Submit a single signed-off commit, disclose AI-agent assistance and respond
   directly to review. The submitting maintainer must understand and maintain it.

Repository packaging, private-SPI compatibility and a prototype prerelease are
maintained here independently of acceptance upstream. Genuine vulnerabilities
follow private disclosure; stronger optional policy requirements are not presented
as defects in standards-compliant native exchange.
