/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.ui.extend.UiTabProvider;
import org.keycloak.services.ui.extend.UiTabProviderFactory;

/** Explicit realm activation, using the console's existing component API and admin audit trail. */
public final class DelegationSettings implements UiTabProvider, UiTabProviderFactory<ComponentModel> {
    @Override public String getId() { return "Bounded delegation"; }
    @Override public String getPath() { return "/:realm/realm-settings/:tab"; }
    @Override public Map<String, String> getParams() { return Map.of("tab", "bounded-delegation"); }
    @Override public String getHelpText() { return "Activate the experimental software-only profile. Withdraw all grants and wait for issued tokens to expire before disabling it."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("enabled").label("Enable bounded software delegation").helpText("Use a realm dedicated to this software profile. Human delegation is outside its qualification.").type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("false").add()
                .property().name("confirmExpiry").label("Issued delegated tokens have expired").helpText("Required before disabling: withdraw grants and wait their maximum remaining lifetime (up to 600 seconds).").type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("false").add()
                .build();
    }
    @Override public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) {
        String selected = realm.getAttribute(GrantDocument.REALM_ATTRIBUTE);
        if ("true".equals(model.get("enabled")) && !org.keycloak.common.Profile.isFeatureEnabled(org.keycloak.common.Profile.Feature.TOKEN_EXCHANGE_STANDARD_V2)) {
            throw new ComponentValidationException("Enable standard token exchange V2 on the server before activating this profile.");
        }
        if (selected != null && !SoftwareProfile.ID.equals(selected)) {
            throw new ComponentValidationException("Another realm profile is selected. Migrate it explicitly before changing bounded delegation.");
        }
        if (!realm.getId().equals(model.getParentId()) || !Set.of("true", "false").contains(model.get("enabled"))
                || realm.getComponentsStream(realm.getId(), UiTabProvider.class.getName()).anyMatch(c -> getId().equals(c.getProviderId()) && !c.getId().equals(model.getId()))) {
            throw new ComponentValidationException("Use one bounded-delegation settings entry in this realm.");
        }
        if (!"true".equals(model.get("enabled")) && SoftwareProfile.ID.equals(realm.getAttribute(GrantDocument.REALM_ATTRIBUTE))) {
            if (AdministrativeGrants.hasGrants(session, realm) || !"true".equals(model.get("confirmExpiry"))) {
                throw new ComponentValidationException("Remove all delegation grants and confirm that issued tokens have expired before disabling enforcement.");
            }
        }
    }
    private void apply(RealmModel realm, ComponentModel model) {
        if ("true".equals(model.get("enabled"))) realm.setAttribute(GrantDocument.REALM_ATTRIBUTE, SoftwareProfile.ID);
        else if (SoftwareProfile.ID.equals(realm.getAttribute(GrantDocument.REALM_ATTRIBUTE))) realm.removeAttribute(GrantDocument.REALM_ATTRIBUTE);
    }
    @Override public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) { apply(realm, model); }
    @Override public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel model) { apply(realm, model); }
    // Deleting the display settings must never silently disable enforcement.
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
