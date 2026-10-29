# Install and configure the extension

## Requirements

Use an isolated server first and review the [0.1.0 support policy](support-policy.md).
Select a JAR matching exactly the running SDK in
[compatibility.json](../compatibility.json), with Java 21. A realm administrator
installs and activates the provider; an OAuth client cannot grant itself authority.

## Release downloads

Download **0.1.0** and verify the binary matching your server. For Keycloak 26.8.1:

```sh
gh release download v0.1.0 --repo Alien6-Studio/keycloak-bounded-delegation \
  --pattern bounded-delegation-0.1.0-keycloak-26.8.1.jar --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify bounded-delegation-0.1.0-keycloak-26.8.1.jar \
  --repo Alien6-Studio/keycloak-bounded-delegation
cp bounded-delegation-0.1.0-keycloak-26.8.1.jar "$KEYCLOAK_HOME/providers/"
"$KEYCLOAK_HOME/bin/kc.sh" build --features=stateless,declarative-ui
```

Set `KEYCLOAK_HOME` to the matching server first. Restart every node with the
same features enabled. The qualified two-node topology uses shared PostgreSQL
and native database-backed state. `declarative-ui` enables the native console;
API-only installations can omit that feature. Never install sources/Javadoc JARs
in `providers/`. See Keycloak's
[provider deployment guide](https://www.keycloak.org/docs/latest/server_development/index.html).

The release also supplies sources, Javadoc, SBOM and native/two-node/lifecycle
reports. Verify the attested source matches the signed release and exact SDK.
The 0.x wire contract retains `experimental: true`; it is independent of the
stable artifact version. **Operator 1.1.0 accepts rc.2 only**. Keep rc.2 for that
operator, or upgrade to a consumer explicitly supporting 0.1.0 before replacing
the provider; see [consumer compatibility](integrations/hanko.md).

## Build from source

Use JDK 21 and the wrapper:

```sh
./mvnw -Dkeycloak.version=26.8.1 verify
```

The provider is `target/26.8.1/bounded-delegation-keycloak-26.8.1.jar`.
Use the same installation and feature configuration as for a verified download.

## Native prerequisites

- Keep standard token exchange V2 enabled.
- Select a realm dedicated to the software profile with the realm attribute
  `oauth.bounded-delegation.profile=software-v1`.
- Use distinct confidential OIDC clients with enabled service accounts and
  enable standard exchange on requesters.
- Configure the audience as an enabled Authorization Services resource server in
  enforcing mode. Declare native resources, scopes and policies for both actors
  and subjects before installing a delegation grant.
- Bind each client to a current, administrator-controlled attribute/value. Install
  a committed version-1 grant document and the actor marker described in the
  [protocol](architecture.md#administrative-wire-contract).

[examples/grant.json](../examples/grant.json) illustrates the complete grant schema.
Replace its placeholder IDs and install matching administrator-controlled client
attributes and native resource policies; the example alone grants no access.

For interactive administration, enable `declarative-ui` when building and starting
the server, then follow the [console and component API guide](administration.md).
Use either console-managed components or an external document writer per audience.
These administrative attributes remain an experimental external-writer protocol. The [functional fixture](../src/it/java/io/alien6/keycloak/delegation/BoundedDelegationIT.java)
provides a complete executable configuration using only native Admin/OAuth APIs
and arbitrary deployment bindings. It never needs an operator or Kubernetes.
Existing consumers can retain their own configuration writers.

`GET /realms/REALM/bounded-delegation` exposes the non-secret contract, extension
and Keycloak versions, limits and activation state. It does not expose grants,
identities or tokens. An unselected realm keeps ordinary native exchange.

## Exchange

The requester authenticates normally and posts to its realm's standard token
endpoint with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
`subject_token`, `actor_token`, both token types set to
`urn:ietf:params:oauth:token-type:access_token`, and the declared `audience`.
Inputs must carry overlapping authorized UMA permissions. Refresh output,
undeclared resource indicators and excess scopes are refused.

Do not put tokens or client credentials in shell history, logs or example files.
The test fixture uses ephemeral in-memory values and excludes OAuth response
bodies from assertion diagnostics.

## Upgrade and rollback

Build and rerun qualification for the destination SDK before changing the server
image. Keep protocol compatibility separate from private-SPI binary compatibility.
The server loads one provider build matching its own version.

For removal, first withdraw grants, wait the maximum remaining delegated token
lifetime, then disable the realm profile and remove the JAR in a rebuilt image.
Existing ordinary clients, unrelated native policies and sessions remain owned
by their administrators. Never uninstall the enforcing provider as an immediate
revocation mechanism. See [security boundaries](../SECURITY.md).
