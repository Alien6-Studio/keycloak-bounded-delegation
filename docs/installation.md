# Install and configure the experimental extension

## Requirements

Use an isolated development server first. The qualified versions are listed in
[compatibility.json](../compatibility.json). Build with JDK 21 and select exactly
the running Keycloak SDK. A realm administrator installs and activates the
provider; an OAuth client cannot opt itself into an administrative grant.

```sh
./mvnw -Dkeycloak.version=26.8.1 verify
```

Copy `target/26.8.1/bounded-delegation-keycloak-26.8.1.jar` into the server's
`providers/` directory, then run `bin/kc.sh build` as part of image construction.
Follow Keycloak's [provider deployment guide](https://www.keycloak.org/docs/latest/server_development/index.html).
Do not copy the sources or Javadoc JAR into `providers/`.

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
