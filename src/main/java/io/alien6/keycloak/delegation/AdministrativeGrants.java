/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.services.ui.extend.UiPageProvider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/** Native components are the source of truth for console-managed grants, never a second writer's journal. */
final class AdministrativeGrants {
    static final String PROVIDER = "Bounded delegations";
    static final String NATIVE_ID = "@keycloak.client.uuid";
    static final String TYPE = UiPageProvider.class.getName();
    private static final String OWNER = "keycloak-admin-console";
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private static final Set<String> FIELDS = Set.of("name", "actor", "subject", "audience", "resource", "scopes", "enabled",
            "maxDepth", "maxTTLSeconds", "actorId", "subjectId", "audienceId", "resourceId", "realm", "providerId", "id");

    private AdministrativeGrants() {}

    static List<ComponentModel> components(RealmModel realm) {
        var result = realm.getComponentsStream(realm.getId(), TYPE).filter(c -> PROVIDER.equals(c.getProviderId()))
                .sorted(Comparator.comparing(ComponentModel::getId)).limit(1025).toList();
        require(result.size() <= 1024, "The realm supports at most 1024 console-managed delegations.");
        return result;
    }

    static void prepare(KeycloakSession session, RealmModel realm, ComponentModel model) {
        require(realm.getId().equals(model.getParentId()), "A delegation must belong to its own realm.");
        require(model.getConfig().keySet().stream().allMatch(FIELDS::contains), "Unknown delegation field.");
        for (var field : model.getConfig().entrySet()) {
            require(field.getValue() != null && field.getValue().size() <= (field.getKey().equals("scopes") ? 128 : 1), "Invalid field cardinality.");
            field.getValue().forEach(AdministrativeGrants::text);
        }
        text(model.get("name"));
        model.setName(model.get("name"));
        require(Set.of("true", "false").contains(model.get("enabled")), "Choose whether the delegation is enabled.");
        number(model, "maxDepth", SoftwareProfile.MAX_DEPTH);
        number(model, "maxTTLSeconds", SoftwareProfile.MAX_TTL_SECONDS);
        var actor = client(session, realm, model.get("actor"));
        var subject = client(session, realm, model.get("subject"));
        var audience = client(session, realm, model.get("audience"));
        require(!actor.equals(subject), "Actor and subject must be different clients.");
        require(actor.isServiceAccountsEnabled() && subject.isServiceAccountsEnabled(), "Actor and subject need enabled service accounts.");
        require(OIDCAdvancedConfigWrapper.fromClientModel(actor).isStandardTokenExchangeEnabled(), "Enable standard token exchange on the actor first.");
        require(audience.getAttribute(GrantDocument.ATTRIBUTE) == null, "This audience is managed by another configuration writer. Use that writer to change it.");
        var authorization = session.getProvider(AuthorizationProvider.class);
        var server = authorization.getStoreFactory().getResourceServerStore().findByClient(audience);
        require(server != null && server.getPolicyEnforcementMode() == PolicyEnforcementMode.ENFORCING,
                "The audience needs Authorization Services in enforcing mode.");
        var resource = authorization.getStoreFactory().getResourceStore().findByName(server, model.get("resource"));
        require(resource != null && !resource.isOwnerManagedAccess(), "Choose an existing administrator-managed resource name on the audience.");
        var scopes = scopes(model);
        require(resource.getScopes().stream().map(s -> s.getName()).collect(Collectors.toSet()).containsAll(scopes),
                "Every scope must already belong to the selected resource.");
        ComponentModel previous = model.getId() == null ? null : realm.getComponent(model.getId());
        for (var binding : Map.of("actorId", actor.getId(), "subjectId", subject.getId(), "audienceId", audience.getId(), "resourceId", resource.getId()).entrySet()) {
            require(previous == null ? model.get(binding.getKey()) == null : binding.getValue().equals(previous.get(binding.getKey())),
                    "Client and resource identities are immutable. Create a new delegation when replacing them.");
            model.put(binding.getKey(), binding.getValue());
        }
        var others = components(realm).stream().filter(c -> !c.getId().equals(model.getId())).toList();
        require(others.size() < 1024, "The realm delegation limit has been reached.");
        require(others.stream().filter(c -> audience.getId().equals(c.get("audienceId"))).count() < 128, "The audience delegation limit has been reached.");
        require(others.stream().noneMatch(c -> actor.getId().equals(c.get("actorId")) && subject.getId().equals(c.get("subjectId"))
                && audience.getId().equals(c.get("audienceId"))), "This actor, subject and audience already have a delegation.");
    }

    static void protectActor(KeycloakSession session, RealmModel realm, ComponentModel model) {
        var actor = session.clients().getClientById(realm, model.get("actorId"));
        if (actor != null && actor.getAttribute(GrantDocument.ACTOR_ATTRIBUTE) == null) {
            // Retain this guard after withdrawal: omitting actor_token must not turn revocation into ordinary exchange.
            actor.setAttribute(GrantDocument.ACTOR_ATTRIBUTE, OWNER);
        }
    }

    static String configuration(KeycloakSession session, RealmModel realm, ClientModel audience) {
        try { return snapshot(session, realm, audience); }
        catch (ComponentValidationException ex) { throw new Bounds.Rejected("grant_invalid"); }
    }

    private static String snapshot(KeycloakSession session, RealmModel realm, ClientModel audience) {
        if (audience == null || !audience.isEnabled()) throw new Bounds.Rejected("grant_unavailable");
        String external = audience.getAttribute(GrantDocument.ATTRIBUTE);
        if (external != null) return external;
        List<Map<String, Object>> grants = new ArrayList<>();
        for (var model : components(realm)) {
            if (!audience.getId().equals(model.get("audienceId")) || !"true".equals(model.get("enabled"))) continue;
            var actor = identity(session, realm, model.get("actorId"));
            var subject = identity(session, realm, model.get("subjectId"));
            Map<String, Object> grant = new TreeMap<>();
            grant.put("name", model.getId());
            grant.put("actor", binding(actor));
            grant.put("subject", binding(subject));
            grant.put("authority", Map.of("scopes", List.of(), "realmRoles", List.of(), "clientRoles", Map.of(),
                    "permissions", new TreeMap<>(Map.of(model.get("resourceId"), new TreeSet<>(scopes(model))))));
            grant.put("conditions", List.of(condition(actor), condition(subject)));
            grant.put("maxDepth", number(model, "maxDepth", SoftwareProfile.MAX_DEPTH));
            grant.put("maxTTLSeconds", number(model, "maxTTLSeconds", SoftwareProfile.MAX_TTL_SECONDS));
            grants.add(grant);
        }
        if (grants.isEmpty()) throw new Bounds.Rejected("grant_unavailable");
        require(grants.size() <= 128, "The audience delegation limit has been reached.");
        var document = new TreeMap<String, Object>();
        document.put("version", 1); document.put("phase", "Committed"); document.put("ownerUID", OWNER);
        document.put("revision", ChainState.hash(json(grants))); document.put("realmID", realm.getId());
        document.put("audience", binding(audience)); document.put("grants", grants); document.put("retiredActors", List.of());
        return json(document);
    }

    static boolean hasGrants(KeycloakSession session, RealmModel realm) {
        return !components(realm).isEmpty() || session.clients().getClientsStream(realm)
                .anyMatch(c -> c.getAttribute(GrantDocument.ATTRIBUTE) != null);
    }

    private static Map<String, String> binding(ClientModel client) {
        return Map.of("id", client.getId(), "attribute", NATIVE_ID, "value", client.getId());
    }
    private static Map<String, String> condition(ClientModel client) {
        return Map.of("kind", "client", "id", client.getId(), "attribute", NATIVE_ID, "value", client.getId());
    }
    private static ClientModel client(KeycloakSession session, RealmModel realm, String name) {
        text(name);
        var client = session.clients().getClientByClientId(realm, name);
        require(client != null && client.isEnabled() && !client.isPublicClient() && "openid-connect".equals(client.getProtocol()),
                "Choose an enabled confidential OIDC client in this realm.");
        return client;
    }
    private static ClientModel identity(KeycloakSession session, RealmModel realm, String id) {
        var client = id == null ? null : session.clients().getClientById(realm, id);
        if (client == null || !client.isEnabled() || client.isPublicClient() || !"openid-connect".equals(client.getProtocol())) {
            throw new Bounds.Rejected("stale_identity");
        }
        return client;
    }
    private static Set<String> scopes(ComponentModel model) {
        List<String> values = model.getConfig().get("scopes");
        require(values != null && !values.isEmpty() && values.size() <= 128, "Choose at least one resource scope.");
        values.forEach(AdministrativeGrants::text);
        require(Set.copyOf(values).size() == values.size(), "Resource scopes must be unique.");
        return Set.copyOf(values);
    }
    private static int number(ComponentModel model, String key, int ceiling) {
        String value = model.get(key);
        require(value != null && value.matches("[1-9][0-9]{0,2}"), "Use a positive whole number for " + key + ".");
        int result = Integer.parseInt(value);
        require(result <= ceiling, key + " exceeds the software profile limit of " + ceiling + ".");
        return result;
    }
    private static String json(Object value) {
        try { return JSON.writeValueAsString(value); }
        catch (JsonProcessingException ex) { throw new IllegalStateException("Cannot encode administrative policy", ex); }
    }
    private static void text(String value) {
        require(value != null && !value.isBlank() && value.length() <= 512 && value.chars().noneMatch(Character::isISOControl), "Invalid or missing delegation field.");
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new ComponentValidationException(message);
    }
}
