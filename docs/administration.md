# Administer bounded delegation

The extension adds native console forms and uses the same Keycloak component
Admin API for automation. Enable `declarative-ui` when building and starting the
server. The enforcement provider remains usable with an external configuration
writer without enabling the UI. Both paths retain the software-v1 limits.

## Prepare the realm

Use a realm dedicated to the software profile. Create distinct confidential OIDC
actor and subject clients with enabled service accounts. Enable standard token
exchange on the actor. The audience must be an enabled confidential Authorization
Services resource server in enforcing mode. Create its resources, scopes and
native policies authorizing both clients. Creating a bounded grant does not add
native resource permissions or bypass those policies.

Enable administrative events under **Realm settings → Events → Admin events**
to record component creation, update and deletion. Event representations are
optional; no OAuth token or client secret belongs in a delegation form.

## Activate and manage

1. In **Realm settings → Bounded delegation**, enable the software profile and save.
2. Open **Bounded delegations** in the navigation menu and choose **Create item**.
3. Give the delegation a name. Use the native client selectors for actor, subject
   and audience. Enter the exact resource name from the audience's **Authorization
   → Resources** screen and add existing resource scope names.
4. Set maximum lifetime (1–600 seconds) and inherited depth (1–4), enable and save.
5. Edit the entry to change scopes or limits. Disable or delete it to withdraw
   future issuance. The native deletion dialog asks for confirmation.

The first console profile supports one resource per actor/subject/audience pair.
Client and resource UUIDs are bound by the server; changing identities requires a
new entry. Renaming an existing client does not transfer its grant to another
UUID. Re-select its current name when editing after a rename. Replacement clients
and resources never inherit grants merely by reusing a display name.

The native console supplies labels, keyboard navigation, field help, list/detail
views and client selection. Server validation also applies to direct API calls.
The browser does not make authorization decisions. The prototype UI is an optional
Keycloak extension; a future upstream change should use the agreed native
client-policy screens rather than make this prototype's component schema a core API.

## API and permissions

Reading configuration and diagnostics requires `realm-management/view-realm`.
Creating, changing or deleting components requires `realm-management/manage-realm`.
The console's client selectors additionally need client-query/view permissions.
Keep those administrative roles separate from the software clients' OAuth rights.
A token for another realm does not authorize access here.

The standard endpoints are:

| Operation | Endpoint |
| --- | --- |
| List | `GET /admin/realms/REALM/components?type=org.keycloak.services.ui.extend.UiPageProvider&providerId=Bounded%20delegations` |
| Create | `POST /admin/realms/REALM/components` |
| Read/update/delete | `GET`, `PUT`, `DELETE /admin/realms/REALM/components/COMPONENT_ID` |
| Diagnostics | `GET /admin/realms/REALM/bounded-delegation` |

[examples/administrative-grant.json](../examples/administrative-grant.json) is a
complete create payload. Supply an administrative bearer token, JSON content type
and your own native client/resource/scope names. A successful create returns 201
and the component location; update/delete return 204. Keycloak's ordinary component
API handles authentication, authorization, transaction persistence and audit events.

Read the full component before updating it and retain its server-generated
identity fields. Existing identities are immutable. Independent entries are
separate rows; updates to the same entry use Keycloak's normal last-committed-write
semantics. Coordinate multiple administrators rather than treating this API as
an ETag/compare-and-swap protocol. Simultaneous conflicting grants fail closed at
issuance if they make actor/subject selection ambiguous.

Diagnostics are authenticated and non-cacheable. `configured` means the structural
configuration exists; native authorization is evaluated again during issuance with
both actual input tokens. Diagnostics neither expose credentials/tokens nor claim
a runtime permission evaluation without those inputs. Native token-exchange error
codes and administrative events provide additional troubleshooting evidence.

## External writers and safe withdrawal

An audience with an external `oauth.bounded-delegation.v1` document remains owned
by that writer. Console/API creation for it is refused; existing documents are
never overwritten or silently merged. Remove or migrate the external configuration
through its owner before using the console. If an external writer later installs
its document, diagnostics identify the conflict and external configuration takes
precedence; coordinate writers explicitly.

Withdrawal removes permission to issue new delegated tokens and invalidates
further chaining when ancestor configuration changes. Already issued offline JWTs
remain valid until expiry. The actor's namespaced protection marker remains after
withdrawal, preventing omission of `actor_token` from bypassing the withdrawn grant.
Other writers' marker values are preserved.

Before disabling the realm profile, remove all grants through their respective
owners and wait their maximum remaining token lifetime. The settings form checks
that no grants remain and requires the administrator to confirm expiry; the
confirmation is an administrative assertion, not automatic tracking of every JWT.
Deleting the settings component alone never disables enforcement. Restore ordinary
actor exchange or remove the provider only as a deliberate, separately reviewed
trust-boundary change. See [installation](installation.md) and [SECURITY.md](../SECURITY.md).
