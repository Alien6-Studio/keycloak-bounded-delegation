/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.common.Profile;
import org.keycloak.common.Version;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

/** Issuer-created, expiring native state. References never replace authenticated token inputs. */
final class TaskContext {
    static final String PROFILE = "task-bound-software";
    static final String CONTRACT = "bounded-delegation/task-reference-v1";
    static final String PROFILE_ATTRIBUTE = "oauth.bounded-delegation.task.profile";
    static final String ISSUER_ATTRIBUTE = "oauth.bounded-delegation.task.issuer";
    static final String ENDPOINT_AUDIENCE = "bounded-delegation-task-context";
    static final String CLAIM = "urn:alien6:bounded-delegation:task";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = JsonMapper.builder(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16).maxStringLength(8192).maxNumberLength(12).build()).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                    DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT).disable(MapperFeature.ALLOW_COERCION_OF_SCALARS).build();

    record Registration(String audience, String grant, String actorJti, String subjectJti, String actorSubject,
                        String subjectSubject, Map<String, Set<String>> permissions, String parametersHash, int ttlSeconds) {
        Registration {
            for (String value : List.of(audience, grant, actorJti, subjectJti, actorSubject, subjectSubject)) name(value);
            if (ttlSeconds < 1 || ttlSeconds > 600 || parametersHash == null || !parametersHash.matches("[0-9a-f]{64}")) {
                throw new Bounds.Rejected("task_input_invalid");
            }
            permissions = new Authority(Set.of(), Set.of(), Map.of(), permissions).permissions();
            if (permissions.isEmpty() || permissions.size() > 16) throw new Bounds.Rejected("task_input_invalid");
        }
    }
    record Stored(String reference, GrantDocument.Binding issuer, Registration request, GrantDocument.Binding actor,
                  GrantDocument.Binding subject, GrantDocument.Binding audience, String policy, long expiresAt) {}
    record Created(String reference, String approval, long expiresAt) {}
    record Check(String reference, String tokenId, String parametersHash, String resource, String scope) {}
    record Issued(String context, Authority authority, long expiresAt) {}

    private TaskContext() {}

    static <T> T parse(String body, Class<T> type) {
        if (body == null || body.length() > 32768) throw new Bounds.Rejected("task_input_invalid");
        try { return JSON.readValue(body, type); }
        catch (IOException | IllegalArgumentException ex) { throw new Bounds.Rejected("task_input_invalid"); }
    }
    static <T> T read(InputStream input, Class<T> type) {
        try {
            byte[] body = input.readNBytes(16385);
            if (body.length > 16384) throw new Bounds.Rejected("task_input_invalid");
            return JSON.readValue(body, type);
        } catch (IOException | IllegalArgumentException ex) { throw new Bounds.Rejected("task_input_invalid"); }
    }
    private static String json(Object value) {
        try { return JSON.writeValueAsString(value); }
        catch (IOException ex) { throw new Bounds.Rejected("task_state_unavailable"); }
    }
    static boolean enabled(KeycloakSession session, RealmModel realm) {
        return session != null && realm != null && SoftwareProfile.ID.equals(realm.getAttribute(GrantDocument.REALM_ATTRIBUTE))
                && Set.of("26.7.5", "26.8.0", "26.8.1").contains(Version.VERSION) && SoftwareProfile.SDK.equals(Version.VERSION)
                && PROFILE.equals(realm.getAttribute(PROFILE_ATTRIBUTE)) && Profile.isFeatureEnabled(Profile.Feature.STATELESS)
                && Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE_STANDARD_V2) && realm.getAttribute(ISSUER_ATTRIBUTE) != null;
    }
    static GrantDocument.Binding issuer(KeycloakSession session, RealmModel realm) {
        if (!enabled(session, realm)) throw new Bounds.Rejected("task_capability_unavailable");
        GrantDocument.Binding binding = parse(realm.getAttribute(ISSUER_ATTRIBUTE), GrantDocument.Binding.class);
        software(session, realm, binding);
        return binding;
    }
    private static ClientModel software(KeycloakSession session, RealmModel realm, GrantDocument.Binding binding) {
        ClientModel client = binding.resolve(session, realm);
        if (client.isPublicClient() || !client.isServiceAccountsEnabled()) throw new Bounds.Rejected("task_identity_unavailable");
        var user = session.users().getServiceAccount(client);
        if (user == null || !user.isEnabled()) {
            throw new Bounds.Rejected("task_identity_unavailable");
        }
        return client;
    }
    static Created create(KeycloakSession session, RealmModel realm, String issuerId, Registration request, long now) {
        if (!issuer(session, realm).id().equals(issuerId)) throw new Bounds.Rejected("task_issuer_required");
        ClientModel audience = session.clients().getClientById(realm, request.audience());
        if (audience == null || !audience.isEnabled()) throw new Bounds.Rejected("task_grant_unavailable");
        String configuration = AdministrativeGrants.configuration(session, realm, audience);
        GrantDocument document = GrantDocument.parse(configuration);
        if (document.version() != 2 || !"Committed".equals(document.phase()) || !realm.getId().equals(document.realmID())
                || !document.audience().resolve(session, realm).equals(audience)) throw new Bounds.Rejected("task_grant_unavailable");
        var grants = document.grants().stream().filter(grant -> grant.name().equals(request.grant())).toList();
        if (grants.size() != 1) throw new Bounds.Rejected("task_grant_unavailable");
        GrantDocument.Grant grant = grants.getFirst();
        ClientModel actor = software(session, realm, grant.actor()), subject = software(session, realm, grant.subject());
        if (issuerId.equals(actor.getId()) || issuerId.equals(subject.getId()) || issuerId.equals(audience.getId())
                || !session.users().getServiceAccount(actor).getId().equals(request.actorSubject())
                || !session.users().getServiceAccount(subject).getId().equals(request.subjectSubject())
                || !grant.authority().contains(new Authority(Set.of(), Set.of(), Map.of(), request.permissions()))) {
            throw new Bounds.Rejected("task_binding_invalid");
        }
        long expires = now + Math.min(request.ttlSeconds(), grant.maxTTLSeconds());
        String reference = reference(), approval = reference();
        Stored context = new Stored(reference, issuer(session, realm), request, grant.actor(), grant.subject(), document.audience(), ChainState.hash(configuration), expires);
        put(session, realm, "context", reference, expires - now, Map.of("value", json(context)));
        put(session, realm, "approval", approval, Math.min(30, expires - now), Map.of("context", reference));
        return new Created(reference, approval, expires);
    }
    static Stored current(KeycloakSession session, RealmModel realm, String reference, long now) {
        issuer(session, realm);
        Map<String, String> record = session.singleUseObjects().get(key(realm, "context", reference));
        if (record == null || record.get("value") == null) throw new Bounds.Rejected("task_unavailable");
        Stored stored = parse(record.get("value"), Stored.class);
        if (stored.expiresAt() <= now || !stored.issuer().equals(issuer(session, realm))
                || session.singleUseObjects().contains(key(realm, "cancelled", reference))) throw new Bounds.Rejected("task_inactive");
        ClientModel audience = stored.audience().resolve(session, realm);
        software(session, realm, stored.actor()); software(session, realm, stored.subject());
        String configuration = AdministrativeGrants.configuration(session, realm, audience);
        if (configuration == null || !stored.policy().equals(ChainState.hash(configuration))
                || !"Committed".equals(GrantDocument.parse(configuration).phase())) throw new Bounds.Rejected("task_policy_stale");
        return stored;
    }
    static Stored admit(KeycloakSession session, RealmModel realm, GrantDocument document, String configuration,
                        GrantDocument.Grant grant, AccessToken actor, AccessToken subject, Authority requested, String approval, long now) {
        if (document.version() == 1) {
            if (approval != null) throw new Bounds.Rejected("task_profile_required");
            return null;
        }
        Map<String, String> approved = session.singleUseObjects().get(key(realm, "approval", approval));
        if (approved == null) throw new Bounds.Rejected("task_approval_required");
        Stored stored = current(session, realm, approved.get("context"), now);
        Registration request = stored.request();
        if (!stored.policy().equals(ChainState.hash(configuration)) || !request.grant().equals(grant.name())
                || !stored.actor().equals(grant.actor()) || !stored.subject().equals(grant.subject())
                || !stored.audience().equals(document.audience()) || !request.actorJti().equals(actor.getId())
                || !request.subjectJti().equals(subject.getId()) || !request.actorSubject().equals(actor.getSubject())
                || !request.subjectSubject().equals(subject.getSubject())
                || !new Authority(Set.of(), Set.of(), Map.of(), request.permissions()).contains(requested)) {
            throw new Bounds.Rejected("task_binding_invalid");
        }
        if (!NativeState.claim(session, key(realm, "approval-used", approval), stored.expiresAt() - now)) {
            throw new Bounds.Rejected("task_approval_replayed");
        }
        current(session, realm, stored.reference(), now);
        return stored;
    }
    static void bindOutput(KeycloakSession session, RealmModel realm, Stored stored, AccessToken output, long now) {
        current(session, realm, stored.reference(), now);
        output.setOtherClaims(CLAIM, Map.of("version", 1, "reference", stored.reference(), "parametersHash", stored.request().parametersHash(), "policyRevision", stored.policy()));
        put(session, realm, "issued", output.getId(), output.getExp() - now,
                Map.of("value", json(new Issued(stored.reference(), NativeAuthority.fromToken(output), output.getExp()))));
    }
    static void cancel(KeycloakSession session, RealmModel realm, String requester, String reference, long now) {
        Stored stored = current(session, realm, reference, now);
        if (!stored.issuer().id().equals(requester)) throw new Bounds.Rejected("task_issuer_required");
        NativeState.claim(session, key(realm, "cancelled", reference), stored.expiresAt() - now);
    }
    static boolean check(KeycloakSession session, RealmModel realm, String requester, Check request, long now) {
        Stored stored = current(session, realm, request.reference(), now);
        // The exact protected resource authenticates independently of the actor.
        if (!stored.audience().id().equals(requester)
                || !stored.request().parametersHash().equals(request.parametersHash())
                || !stored.request().permissions().getOrDefault(request.resource(), Set.of()).contains(request.scope())) {
            throw new Bounds.Rejected("task_recipient_invalid");
        }
        Map<String, String> issued = session.singleUseObjects().get(key(realm, "issued", request.tokenId()));
        if (issued == null || issued.get("value") == null) throw new Bounds.Rejected("task_token_invalid");
        Issued output = parse(issued.get("value"), Issued.class);
        if (!stored.reference().equals(output.context()) || output.expiresAt() <= now) throw new Bounds.Rejected("task_token_invalid");
        ClientModel target = stored.audience().resolve(session, realm);
        GrantDocument document = GrantDocument.parse(AdministrativeGrants.configuration(session, realm, target));
        GrantDocument.Grant grant = document.grants().stream().filter(value -> value.name().equals(stored.request().grant())).findFirst()
                .orElseThrow(() -> new Bounds.Rejected("task_grant_unavailable"));
        Authority operation = new Authority(Set.of(), Set.of(), Map.of(), Map.of(request.resource(), Set.of(request.scope())));
        if (!output.authority().contains(operation)) throw new Bounds.Rejected("task_operation_denied");
        AccessToken claims = new AccessToken();
        NativeAuthority.apply(claims, operation);
        for (GrantDocument.Binding binding : List.of(stored.actor(), stored.subject())) {
            ClientModel client = software(session, realm, binding);
            var user = session.users().getServiceAccount(client);
            grant.authorize(session, realm, client, user);
            if (!NativeAuthority.current(session, realm, target, client, user, claims, operation).contains(operation)) {
                throw new Bounds.Rejected("task_policy_denied");
            }
        }
        // An online allow precedes application execution; it is not an atomic business transaction.
        current(session, realm, request.reference(), now);
        return true;
    }
    private static void put(KeycloakSession session, RealmModel realm, String purpose, String id, long ttl, Map<String, String> values) {
        String key = key(realm, purpose, id);
        if (ttl <= 0 || !NativeState.claim(session, key, ttl) || !session.singleUseObjects().replace(key, values)) {
            throw new Bounds.Rejected("task_state_unavailable");
        }
    }
    private static String key(RealmModel realm, String purpose, String id) {
        name(id);
        // A backend diagnostic must not expose the actual approval/context reference.
        return "bounded-task/" + purpose + "/" + ChainState.hash(realm.getId() + "/" + id);
    }
    private static void name(String value) {
        if (value == null || value.isBlank() || value.length() > 512 || value.chars().anyMatch(Character::isISOControl)) throw new Bounds.Rejected("task_input_invalid");
    }
    private static String reference() { byte[] bytes = new byte[32]; RANDOM.nextBytes(bytes); return HexFormat.of().formatHex(bytes); }
}
