/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.List;
import java.util.Map;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.ui.extend.UiPageProvider;
import org.keycloak.services.ui.extend.UiPageProviderFactory;

/** Native, accessible master/detail forms; the component Admin API invokes these same validators. */
public final class DelegationPage implements UiPageProvider, UiPageProviderFactory<ComponentModel> {
    @Override public String getId() { return AdministrativeGrants.PROVIDER; }
    @Override public String getHelpText() {
        return "Grant limited access between software clients. Enable the software profile in Realm settings first. "
                + "Deleting or disabling a grant stops future issuance; existing JWTs remain valid until expiry. "
                + "Actor protection remains installed after withdrawal. Native authorization policies still apply.";
    }
    @Override public Map<String, Object> getTypeMetadata() { return Map.of("displayFields", List.of("name", "audience", "enabled")); }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("name").label("Delegation name").helpText("A short label for administrators.").type(ProviderConfigProperty.STRING_TYPE).required(true).add()
                .property().name("actor").label("Actor client").helpText("Confidential service-account client requesting the exchange. Enable standard token exchange on it first.").type(ProviderConfigProperty.CLIENT_LIST_TYPE).required(true).add()
                .property().name("subject").label("Subject client").helpText("Confidential service-account client whose authority is delegated.").type(ProviderConfigProperty.CLIENT_LIST_TYPE).required(true).add()
                .property().name("audience").label("Audience client").helpText("The Authorization Services resource server receiving the bounded token.").type(ProviderConfigProperty.CLIENT_LIST_TYPE).required(true).add()
                .property().name("resource").label("Resource name").helpText("Exact resource name from the audience client's Authorization / Resources screen. One resource per delegation.").type(ProviderConfigProperty.STRING_TYPE).required(true).add()
                .property().name("scopes").label("Resource scopes").helpText("Existing scope names on that resource, for example read. Native policies must authorize both clients.").type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE).required(true).add()
                .property().name("maxDepth").label("Maximum delegation depth").helpText("Total inherited hop limit, from 1 to 4.").type(ProviderConfigProperty.INTEGER_TYPE).defaultValue("2").required(true).add()
                .property().name("maxTTLSeconds").label("Maximum lifetime in seconds").helpText("From 1 to 600 seconds. Input and inherited lifetimes can shorten it further.").type(ProviderConfigProperty.INTEGER_TYPE).defaultValue("30").required(true).add()
                .property().name("enabled").label("Enabled").helpText("Disable to withdraw future issuance. Existing offline JWTs remain valid until their bounded expiry.").type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("false").add()
                .build();
    }
    @Override public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) { AdministrativeGrants.prepare(session, realm, model); }
    @Override public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) { AdministrativeGrants.protectActor(session, realm, model); }
    @Override public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel model) { AdministrativeGrants.protectActor(session, realm, model); }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
