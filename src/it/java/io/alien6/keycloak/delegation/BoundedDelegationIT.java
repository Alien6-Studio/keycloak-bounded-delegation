/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testframework.annotations.InjectAdminClient;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakUrls;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Functional tests using Keycloak's own extension test framework and native Admin/OAuth APIs. */
@KeycloakIntegrationTest(config = BoundedDelegationIT.Server.class)
public class BoundedDelegationIT {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ACCESS = "urn:ietf:params:oauth:token-type:access_token";
    private static final String OWNER_ATTRIBUTE = "bounded.test.deployment";
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    @InjectAdminClient Keycloak admin;
    @InjectKeycloakUrls KeycloakUrls urls;

    private String realm;
    private String issuer;
    private String api;
    private String base;
    private String resource;
    private String policy;
    private String secret;
    private final Map<String, String> clients = new HashMap<>();
    private GrantDocument document;

    public static class Server implements KeycloakServerConfig {
        @Override public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.dependencyCurrentProject();
        }
    }

    @BeforeEach void configureNativeRealm() throws Exception {
        realm = "bounded-" + UUID.randomUUID();
        issuer = urls.getBase() + "/realms/" + realm;
        secret = UUID.randomUUID().toString();
        RealmRepresentation representation = new RealmRepresentation();
        representation.setRealm(realm);
        representation.setEnabled(true);
        representation.setAccessTokenLifespan(120);
        representation.setAttributes(Map.of(GrantDocument.REALM_ATTRIBUTE, SoftwareProfile.ID));
        admin.realms().create(representation);
        for (String name : List.of("actor", "subject", "next", "invoice-api")) {
            ClientRepresentation client = new ClientRepresentation();
            client.setClientId(name);
            client.setEnabled(true);
            client.setProtocol("openid-connect");
            client.setPublicClient(false);
            client.setFullScopeAllowed(false);
            client.setServiceAccountsEnabled(true);
            client.setSecret(secret);
            client.setAuthorizationServicesEnabled(name.equals("invoice-api"));
            client.setAttributes(Map.of(OWNER_ATTRIBUTE, name, "standard.token.exchange.enabled", "true"));
            try (var response = admin.realm(realm).clients().create(client)) {
                assertEquals(201, response.getStatus(), "Native client creation failed");
            }
            clients.put(name, admin.realm(realm).clients().findByClientId(name).getFirst().getId());
        }
        api = clients.get("invoice-api");
        base = "/admin/realms/" + realm + "/clients/" + api + "/authz/resource-server";
        // Remove the server's permissive example policy before declaring the fixture's own graph.
        for (JsonNode permission : admin("GET", base + "/permission", null).body()) {
            admin("DELETE", base + "/permission/" + permission.path("id").asText(), null);
        }
        for (JsonNode nativeResource : admin("GET", base + "/resource", null).body()) {
            admin("DELETE", base + "/resource/" + nativeResource.path("_id").asText(), null);
        }
        for (JsonNode nativePolicy : admin("GET", base + "/policy", null).body()) {
            admin("DELETE", base + "/policy/" + nativePolicy.path("id").asText(), null);
        }
        List<Map<String, String>> scopes = new ArrayList<>();
        for (String scope : List.of("read", "write")) {
            String id = created(admin("POST", base + "/scope", Map.of("name", scope)));
            scopes.add(Map.of("id", id, "name", scope));
        }
        resource = created(admin("POST", base + "/resource", Map.of("name", "invoice", "type", "invoice",
                "uris", List.of("https://api.example.test/invoice"), "ownerManagedAccess", false, "scopes", scopes)));
        policy = created(admin("POST", base + "/policy/client", Map.of("name", "software-identities", "type", "client",
                "logic", "POSITIVE", "decisionStrategy", "AFFIRMATIVE", "clients", identityIDs())));
        admin("POST", base + "/permission/scope", Map.of("name", "invoice-access", "type", "scope", "logic", "POSITIVE",
                "decisionStrategy", "AFFIRMATIVE", "resources", List.of(resource), "scopes", scopes.stream().map(s -> s.get("id")).toList(), "policies", List.of(policy)));
        List<GrantDocument.Grant> grants = new ArrayList<>();
        for (String[] pair : List.of(new String[]{"actor", "subject"}, new String[]{"subject", "next"}, new String[]{"next", "actor"})) {
            grants.add(new GrantDocument.Grant(pair[0] + "-" + pair[1], binding(pair[0]), binding(pair[1]),
                    new Authority(Set.of(), Set.of(), Map.of(), Map.of(resource, Set.of("read"))),
                    List.of(condition(pair[0]), condition(pair[1])), 2, 30));
        }
        document = new GrantDocument(1, "Committed", "deployment-test", "revision-1",
                admin.realm(realm).toRepresentation().getId(), binding("invoice-api"), grants, List.of());
        save(document);
        for (String name : List.of("actor", "subject", "next")) attributes(name, Map.of(GrantDocument.ACTOR_ATTRIBUTE, "administratively-bound"));
    }

    @AfterEach void deleteOnlyFixtureRealm() {
        if (realm != null && admin != null) admin.realm(realm).remove();
        clients.clear();
    }

    @Test void discoveryReportsOnlyVersionedPublicCapabilities() throws Exception {
        Result result = request("GET", issuer + "/bounded-delegation", null, null, null);
        assertEquals(200, result.status());
        assertEquals(7, result.body().size());
        assertEquals(SoftwareProfile.CONTRACT, result.body().path("contract").asText());
        assertEquals(SoftwareProfile.VERSION, result.body().path("extensionVersion").asText());
        assertEquals(System.getProperty("bounded.keycloak.version"), result.body().path("keycloakVersion").asText());
        assertTrue(result.body().path("enabled").asBoolean());
    }

    @Test void intersectsBothInputsAndGrantAndBoundsAudienceExpiryAndClaims() throws Exception {
        String subject = rpt("subject", "read", "write"), actor = rpt("actor", "read", "write");
        Result result = exchange("actor", subject, actor, Map.of());
        AccessToken token = issued(result);
        assertTrue(token.getExp() <= Math.min(verified(subject).getExp(), verified(actor).getExp()));
        assertTrue(token.getExp() <= org.keycloak.common.util.Time.currentTime() + 30);
        assertEquals(Set.of("invoice-api"), Set.of(token.getAudience()));
        assertEquals(Map.of(resource, Set.of("read")), NativeAuthority.fromToken(token).permissions());
        assertTrue(NativeAuthority.fromToken(token).realmRoles().isEmpty());
        assertTrue(NativeAuthority.fromToken(token).clientRoles().isEmpty());
        assertTrue(NativeAuthority.fromToken(token).scopes().isEmpty());
        assertEquals(Set.of("act"), token.getOtherClaims().keySet());
        assertEquals("actor", ((Map<?, ?>) token.getOtherClaims().get("act")).get("client_id"));
        assertFalse(result.body().hasNonNull("refresh_token"));
    }

    @Test void disjointInputPermissionsIssueNoToken() throws Exception {
        denied(exchange("actor", rpt("subject", "write"), rpt("actor", "read"), Map.of()));
    }

    @Test void nonCommittedAdministrativeGrantsIssueNoToken() throws Exception {
        for (String phase : List.of("Prepared", "Applied", "Verified")) {
            save(new GrantDocument(1, phase, document.ownerUID(), document.revision(), document.realmID(), document.audience(), document.grants(), List.of()));
            denied(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        }
    }

    @Test void concurrentActorReplayHasExactlyOneSuccessfulIssuance() throws Exception {
        String actor = rpt("actor", "read"), subject = rpt("subject", "read");
        try (var executor = Executors.newFixedThreadPool(8)) {
            List<Callable<Result>> attempts = new ArrayList<>();
            for (int i = 0; i < 8; i++) attempts.add(() -> exchange("actor", subject, actor, Map.of()));
            int successes = 0;
            for (var future : executor.invokeAll(attempts)) {
                Result result = future.get();
                if (result.status() == 200) { issued(result); successes++; } else denied(result);
            }
            assertEquals(1, successes);
        }
    }

    @Test void inheritedDepthRefusesTheThirdHop() throws Exception {
        String first = rawIssued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        String second = rawIssued(exchange("subject", rpt("next", "read"), first, Map.of()));
        assertEquals(2, ChainState.actorDepth(verified(second).getOtherClaims().get("act")));
        assertTrue(verified(second).getExp() <= verified(first).getExp());
        denied(exchange("next", rpt("actor", "read"), second, Map.of()));
    }

    @Test void shortInputBoundsOutputAndUnusedExpiredInputCannotIssue() throws Exception {
        attributes("actor", Map.of("access.token.lifespan", "5"));
        String actor = rpt("actor", "read"), unused = rpt("actor", "read"), subject = rpt("subject", "read");
        long expiry = Math.max(verified(actor).getExp(), verified(unused).getExp());
        AccessToken output = issued(exchange("actor", subject, actor, Map.of()));
        assertTrue(output.getExp() <= verified(actor).getExp());
        while (org.keycloak.common.util.Time.currentTime() <= expiry) Thread.sleep(200);
        Result result = exchange("actor", subject, unused, Map.of());
        denied(result);
        assertEquals("token_invalid", result.body().path("error_description").asText());
    }

    @Test void ancestorGrantChangeStopsChainingWithoutClaimingOfflineRevocation() throws Exception {
        String first = rawIssued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        long expiry = verified(first).getExp();
        save(new GrantDocument(1, "Committed", document.ownerUID(), "revision-2", document.realmID(),
                document.audience(), document.grants(), List.of()));
        denied(exchange("subject", rpt("next", "read"), first, Map.of()));
        assertEquals(expiry, verified(first).getExp());
    }

    @Test void liveNativePolicyWithdrawalRefusesAlreadyIssuedInputs() throws Exception {
        String actor = rpt("actor", "read"), subject = rpt("subject", "read");
        admin("PUT", base + "/policy/client/" + policy, Map.of("id", policy, "name", "software-identities", "type", "client",
                "logic", "POSITIVE", "decisionStrategy", "AFFIRMATIVE", "clients", List.of(clients.get("actor"))));
        denied(exchange("actor", subject, actor, Map.of()));
    }

    @Test void replacedAdministrativeIdentityBindingRefusesIssuance() throws Exception {
        String actor = rpt("actor", "read"), subject = rpt("subject", "read");
        attributes("subject", Map.of(OWNER_ATTRIBUTE, "replacement"));
        denied(exchange("actor", subject, actor, Map.of()));
    }

    @Test void invalidTokensAudienceScopesAndRefreshRequestsAreRefused() throws Exception {
        String subject = rpt("subject", "read");
        denied(exchange("actor", subject, "invalid-synthetic-token", Map.of()));
        denied(exchange("actor", "invalid-synthetic-token", rpt("actor", "read"), Map.of()));
        for (Map<String, String> extra : List.of(Map.of("audience", "actor"), Map.of("scope", "admin"),
                Map.of("resource", "https://foreign.example.test"), Map.of("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"))) {
            denied(exchange("actor", subject, rpt("actor", "read"), extra));
        }
    }

    @Test void actorRemovalCannotFallThroughToOrdinaryExchange() throws Exception {
        denied(token("actor", Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token", rpt("subject", "read"), "subject_token_type", ACCESS, "audience", "invoice-api")));
    }

    @Test void unselectedRealmPreservesOrdinaryNativeExchange() throws Exception {
        RealmRepresentation current = admin.realm(realm).toRepresentation();
        current.setAttributes(Map.of());
        admin.realm(realm).update(current);
        // Native audience permission: make actor an explicit audience on subject's input token.
        String path = "/admin/realms/" + realm + "/clients/" + clients.get("subject") + "/protocol-mappers/models";
        admin("POST", path, Map.of("name", "actor-audience", "protocol", "openid-connect", "protocolMapper", "oidc-audience-mapper",
                "config", Map.of("included.client.audience", "actor", "access.token.claim", "true")));
        Result result = token("actor", Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token", rawIssued(token("subject", Map.of("grant_type", "client_credentials"))), "subject_token_type", ACCESS));
        AccessToken nativeToken = issued(result);
        assertFalse(nativeToken.getOtherClaims().containsKey("act"));
        assertFalse(request("GET", issuer + "/bounded-delegation", null, null, null).body().path("enabled").asBoolean());
    }

    private List<String> identityIDs() { return List.of(clients.get("actor"), clients.get("subject"), clients.get("next")); }
    private GrantDocument.Binding binding(String name) { return new GrantDocument.Binding(clients.get(name), OWNER_ATTRIBUTE, name); }
    private GrantDocument.Condition condition(String name) { return new GrantDocument.Condition("client", clients.get(name), OWNER_ATTRIBUTE, name); }
    private void save(GrantDocument value) throws Exception { attributes("invoice-api", Map.of(GrantDocument.ATTRIBUTE, JSON.writeValueAsString(value))); }
    private void attributes(String name, Map<String, String> changes) {
        var resource = admin.realm(realm).clients().get(clients.get(name));
        var current = resource.toRepresentation();
        Map<String, String> attrs = new HashMap<>(current.getAttributes());
        attrs.putAll(changes);
        current.setAttributes(attrs);
        resource.update(current);
    }

    private Result token(String client, Map<String, String> values) throws Exception {
        Map<String, List<String>> form = new HashMap<>();
        values.forEach((key, value) -> form.put(key, List.of(value)));
        form.put("client_id", List.of(client));
        form.put("client_secret", List.of(secret));
        return request("POST", issuer + "/protocol/openid-connect/token", form, null, null);
    }
    private String rpt(String client, String... scopes) throws Exception {
        String access = rawIssued(token(client, Map.of("grant_type", "client_credentials")));
        return rawIssued(request("POST", issuer + "/protocol/openid-connect/token", Map.of(
                "grant_type", List.of("urn:ietf:params:oauth:grant-type:uma-ticket"), "audience", List.of("invoice-api"),
                "permission", Arrays.stream(scopes).map(scope -> "invoice#" + scope).toList()), access, null));
    }
    private Result exchange(String client, String subject, String actor, Map<String, String> extra) throws Exception {
        Map<String, String> form = new HashMap<>(Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token", subject, "subject_token_type", ACCESS, "actor_token", actor, "actor_token_type", ACCESS, "audience", "invoice-api"));
        form.putAll(extra);
        return token(client, form);
    }
    private AccessToken issued(Result result) throws Exception { return verified(rawIssued(result)); }
    private String rawIssued(Result result) {
        assertEquals(200, result.status(), "OAuth issuance failed (response bodies are deliberately excluded)");
        assertTrue(result.body().hasNonNull("access_token"));
        return result.body().path("access_token").asText();
    }
    private void denied(Result result) {
        assertTrue(result.status() >= 400 && result.status() < 500, "Expected an OAuth denial");
        assertFalse(result.body().hasNonNull("access_token"));
    }
    private AccessToken verified(String raw) throws Exception {
        var jws = new JWSInput(raw);
        assertEquals("RS256", jws.getHeader().getAlgorithm().name());
        JSONWebKeySet jwks = JSON.treeToValue(request("GET", issuer + "/protocol/openid-connect/certs", null, null, null).body(), JSONWebKeySet.class);
        var key = Arrays.stream(jwks.getKeys()).filter(k -> k.getKeyId().equals(jws.getHeader().getKeyId())).findFirst().orElseThrow();
        return TokenVerifier.create(raw, AccessToken.class).withDefaultChecks().realmUrl(issuer)
                .publicKey(JWKParser.create(key).toPublicKey()).verify().getToken();
    }
    private Result admin(String method, String path, Object body) throws Exception {
        Result result = request(method, urls.getBase() + path, null, admin.tokenManager().getAccessTokenString(), body);
        assertTrue(result.status() >= 200 && result.status() < 300, "Native fixture administration failed: HTTP " + result.status());
        return result;
    }
    private String created(Result result) {
        String id = result.body().path("id").asText(result.body().path("_id").asText());
        assertFalse(id.isBlank(), "Native object identity missing");
        return id;
    }
    private Result request(String method, String url, Map<String, List<String>> form, String bearer, Object json) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30));
        if (bearer != null) request.header("Authorization", "Bearer " + bearer);
        String body = "";
        if (form != null) {
            List<String> encoded = new ArrayList<>();
            form.forEach((key, values) -> values.forEach(value -> encoded.add(URLEncoder.encode(key, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8))));
            body = String.join("&", encoded);
            request.header("Content-Type", "application/x-www-form-urlencoded");
        } else if (json != null) {
            body = JSON.writeValueAsString(json);
            request.header("Content-Type", "application/json");
        }
        var result = HTTP.send(request.method(method, HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(result.body().length() <= 1024 * 1024, "Response budget exceeded");
        return new Result(result.statusCode(), result.body().isBlank() ? JSON.createObjectNode() : JSON.readTree(result.body()));
    }
    private record Result(int status, JsonNode body) { }
}
