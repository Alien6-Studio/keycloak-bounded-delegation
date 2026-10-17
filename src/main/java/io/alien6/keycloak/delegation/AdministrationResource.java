/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.Config;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/** Authenticated structural diagnostics; mutations use Keycloak's audited component Admin API. */
public final class AdministrationResource implements AdminRealmResourceProvider, AdminRealmResourceProviderFactory {
    @Override public String getId() { return "bounded-delegation"; }
    @Override public AdminRealmResourceProvider create(KeycloakSession session) { return this; }
    @Override public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder events) {
        return new State(session, realm, auth);
    }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}

    public static final class State {
        private final KeycloakSession session;
        private final RealmModel realm;
        private final AdminPermissionEvaluator auth;
        State(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) { this.session = session; this.realm = realm; this.auth = auth; }

        @GET @Produces(MediaType.APPLICATION_JSON)
        public Response status() {
            auth.realm().requireViewRealm();
            List<Map<String, Object>> grants = new ArrayList<>();
            for (var model : AdministrativeGrants.components(realm)) {
                String state = "disabled";
                if ("true".equals(model.get("enabled"))) {
                    try {
                        var audience = session.clients().getClientById(realm, model.get("audienceId"));
                        if (audience != null && audience.getAttribute(GrantDocument.ATTRIBUTE) == null) {
                            AdministrativeGrants.prepare(session, realm, new org.keycloak.component.ComponentModel(model));
                        }
                        String value = AdministrativeGrants.configuration(session, realm, audience);
                        var document = GrantDocument.parse(value);
                        document.audience().resolve(session, realm);
                        document.grants().forEach(g -> { g.actor().resolve(session, realm); g.subject().resolve(session, realm); });
                        state = audience.getAttribute(GrantDocument.ATTRIBUTE) == null ? "configured" : "external_writer_conflict";
                    } catch (Bounds.Rejected | ComponentValidationException ex) { state = "invalid_configuration"; }
                }
                grants.add(Map.of("id", model.getId(), "name", model.get("name", ""), "state", state,
                        "actor", model.get("actor", ""), "subject", model.get("subject", ""), "audience", model.get("audience", "")));
            }
            return Response.ok(Map.of("contract", SoftwareProfile.CONTRACT, "extensionVersion", SoftwareProfile.VERSION,
                    "enabled", SoftwareProfile.ID.equals(realm.getAttribute(GrantDocument.REALM_ATTRIBUTE))
                            && org.keycloak.common.Profile.isFeatureEnabled(org.keycloak.common.Profile.Feature.TOKEN_EXCHANGE_STANDARD_V2),
                    "grants", grants, "authorizationEvaluatedAtIssuance", true,
                    "offlineTokensRemainValidUntilExpiry", true, "actorGuardRetainedAfterWithdrawal", true))
                    .header("Cache-Control", "no-store").build();
        }
    }
}
