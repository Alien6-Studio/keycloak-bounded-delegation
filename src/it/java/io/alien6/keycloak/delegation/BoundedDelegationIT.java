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
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
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
import org.openqa.selenium.By;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

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
            return config.dependencyCurrentProject().features(org.keycloak.common.Profile.Feature.DECLARATIVE_UI);
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

    @Test void publicSubjectCannotReusePreviouslyIssuedConfidentialInputs() throws Exception {
        String actor = rpt("actor", "read"), subject = rpt("subject", "read");
        var client = admin.realm(realm).clients().get(clients.get("subject"));
        var current = client.toRepresentation(); current.setPublicClient(true); client.update(current);
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

    @Test void administrationCreatesUpdatesWithdrawsAndAuditsExecutableGrants() throws Exception {
        consoleOwnership();
        var settings = admin.realm(realm).toRepresentation();
        settings.setAdminEventsEnabled(true);
        settings.setAdminEventsDetailsEnabled(false);
        admin.realm(realm).update(settings);
        String id = created(admin("POST", components(), consoleGrant("first", "actor", "subject")));
        AccessToken token = issued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        assertEquals(Map.of(resource, Set.of("read")), NativeAuthority.fromToken(token).permissions());
        JsonNode model = admin("GET", components() + "/" + id, null).body();
        ((com.fasterxml.jackson.databind.node.ObjectNode) model.path("config")).putArray("maxTTLSeconds").add("10");
        admin("PUT", components() + "/" + id, model);
        assertTrue(issued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of())).getExp() <= org.keycloak.common.util.Time.currentTime() + 10);
        assertEquals("configured", admin("GET", diagnostics(), null).body().path("grants").get(0).path("state").asText());
        ((com.fasterxml.jackson.databind.node.ObjectNode) model.path("config")).putArray("enabled").add("false");
        admin("PUT", components() + "/" + id, model);
        denied(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        admin("DELETE", components() + "/" + id, null);
        assertTrue(admin("GET", diagnostics(), null).body().path("grants").isEmpty());
        actorRemovalCannotFallThroughToOrdinaryExchange();
        Set<String> operations = new java.util.HashSet<>();
        for (JsonNode event : admin("GET", "/admin/realms/" + realm + "/admin-events", null).body()) {
            if (event.path("resourceType").asText().equals("COMPONENT")) operations.add(event.path("operationType").asText());
        }
        assertTrue(operations.containsAll(Set.of("CREATE", "UPDATE", "DELETE")));
        assertEquals("keycloak-admin-console", admin.realm(realm).clients().get(clients.get("actor")).toRepresentation().getAttributes().get(GrantDocument.ACTOR_ATTRIBUTE));
    }

    @Test void administrationRejectsInvalidAmbiguousAndExternallyOwnedChanges() throws Exception {
        var payload = consoleGrant("external-conflict", "actor", "subject");
        assertEquals(400, componentRequest("POST", components(), payload, admin.tokenManager().getAccessTokenString()).status());
        assertEquals(JSON.writeValueAsString(document), admin.realm(realm).clients().get(api).toRepresentation().getAttributes().get(GrantDocument.ATTRIBUTE));
        consoleOwnership();
        for (Map<String, List<String>> invalid : List.of(Map.of("maxDepth", List.of("5")), Map.of("maxTTLSeconds", List.of("601")),
                Map.of("maxDepth", List.of("1.5")), Map.of("actor", List.of("subject")), Map.of("actor", List.of("missing")),
                Map.of("scopes", List.of("admin")), Map.of("scopes", List.of("read", "read")), Map.of("resource", List.of("missing")),
                Map.of("actorId", List.of(clients.get("actor"))), Map.of("audience", List.of("actor")), Map.of("enabled", List.of("yes")))) {
            var bad = consoleGrant("invalid", "actor", "subject");
            config(bad).putAll(invalid);
            assertEquals(400, componentRequest("POST", components(), bad, admin.tokenManager().getAccessTokenString()).status());
        }
        String id = created(admin("POST", components(), consoleGrant("valid", "actor", "subject")));
        assertEquals(400, componentRequest("POST", components(), consoleGrant("duplicate", "actor", "subject"), admin.tokenManager().getAccessTokenString()).status());
        var stored = admin("GET", components() + "/" + id, null).body();
        ((com.fasterxml.jackson.databind.node.ObjectNode) stored.path("config")).putArray("subject").add("next");
        assertEquals(400, componentRequest("PUT", components() + "/" + id, stored, admin.tokenManager().getAccessTokenString()).status());
        issued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
    }

    @Test void administrationPermissionsAreRealmScopedForApiAndConsoleStorage() throws Exception {
        consoleOwnership();
        String ordinary = rawIssued(token("next", Map.of("grant_type", "client_credentials")));
        assertEquals(401, componentRequest("GET", diagnostics(), null, null).status());
        assertEquals(403, componentRequest("GET", diagnostics(), null, ordinary).status());
        assertEquals(403, componentRequest("POST", components(), consoleGrant("denied", "actor", "subject"), ordinary).status());
        grantManagementRoles("next", "view-realm");
        String viewer = rawIssued(token("next", Map.of("grant_type", "client_credentials")));
        assertEquals(200, componentRequest("GET", diagnostics(), null, viewer).status());
        assertEquals(200, componentRequest("GET", components(), null, viewer).status());
        assertEquals(403, componentRequest("POST", components(), consoleGrant("denied", "actor", "subject"), viewer).status());
        assertEquals(403, componentRequest("GET", "/admin/realms/master/bounded-delegation", null, viewer).status());
        String id = created(admin("POST", components(), consoleGrant("protected", "actor", "subject")));
        JsonNode model = admin("GET", components() + "/" + id, null).body();
        assertEquals(403, componentRequest("PUT", components() + "/" + id, model, viewer).status());
        assertEquals(403, componentRequest("DELETE", components() + "/" + id, null, viewer).status());
    }

    @Test void realmActivationRequiresExplicitSafeWithdrawal() throws Exception {
        consoleOwnership();
        var current = admin.realm(realm).toRepresentation();
        current.setAttributes(Map.of()); admin.realm(realm).update(current);
        String id = created(admin("POST", components(), Map.of("providerType", "org.keycloak.services.ui.extend.UiTabProvider", "providerId", "Bounded delegation",
                "config", Map.of("enabled", List.of("true"), "confirmExpiry", List.of("false")))));
        assertTrue(admin("GET", diagnostics(), null).body().path("enabled").asBoolean());
        String grant = created(admin("POST", components(), consoleGrant("active", "actor", "subject")));
        JsonNode entry = admin("GET", components() + "/" + id, null).body();
        ((com.fasterxml.jackson.databind.node.ObjectNode) entry.path("config")).putArray("enabled").add("false");
        ((com.fasterxml.jackson.databind.node.ObjectNode) entry.path("config")).putArray("confirmExpiry").add("true");
        assertEquals(400, componentRequest("PUT", components() + "/" + id, entry, admin.tokenManager().getAccessTokenString()).status());
        admin("DELETE", components() + "/" + grant, null);
        ((com.fasterxml.jackson.databind.node.ObjectNode) entry.path("config")).putArray("confirmExpiry").add("false");
        assertEquals(400, componentRequest("PUT", components() + "/" + id, entry, admin.tokenManager().getAccessTokenString()).status());
        ((com.fasterxml.jackson.databind.node.ObjectNode) entry.path("config")).putArray("confirmExpiry").add("true");
        admin("PUT", components() + "/" + id, entry);
        assertFalse(admin("GET", diagnostics(), null).body().path("enabled").asBoolean());
    }

    @Test void independentAdministrativeWritesPreserveBothGrantsAndRevocationEvidence() throws Exception {
        consoleOwnership();
        String bearer = admin.tokenManager().getAccessTokenString();
        try (var executor = Executors.newFixedThreadPool(2)) {
            var attempts = List.<Callable<Result>>of(
                    () -> componentRequest("POST", components(), consoleGrant("first", "actor", "subject"), bearer),
                    () -> componentRequest("POST", components(), consoleGrant("second", "subject", "next"), bearer));
            for (var response : executor.invokeAll(attempts)) assertEquals(201, response.get().status());
        }
        assertEquals(2, admin("GET", diagnostics(), null).body().path("grants").size());
        String first = rawIssued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        issued(exchange("subject", rpt("next", "read"), first, Map.of()));
        String unused = rawIssued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        for (JsonNode entry : admin("GET", components(), null).body()) {
            if (entry.path("name").asText().equals("first")) admin("DELETE", components() + "/" + entry.path("id").asText(), null);
        }
        Result revoked = exchange("subject", rpt("next", "read"), unused, Map.of());
        denied(revoked);
        assertEquals("chain_revoked", revoked.body().path("error_description").asText());
        verified(first); // Withdrawal does not claim immediate revocation of an offline JWT.
    }

    @Test void replacedNativeClientCannotInheritConsoleDelegation() throws Exception {
        consoleOwnership();
        String id = created(admin("POST", components(), consoleGrant("bound", "actor", "subject")));
        admin.realm(realm).clients().get(clients.get("actor")).remove();
        var replacement = new ClientRepresentation();
        replacement.setClientId("actor"); replacement.setEnabled(true); replacement.setPublicClient(false);
        replacement.setProtocol("openid-connect"); replacement.setServiceAccountsEnabled(true); replacement.setSecret(secret);
        replacement.setAttributes(Map.of("standard.token.exchange.enabled", "true"));
        try (var response = admin.realm(realm).clients().create(replacement)) { assertEquals(201, response.getStatus()); }
        var model = admin("GET", components() + "/" + id, null).body();
        assertEquals(400, componentRequest("PUT", components() + "/" + id, model, admin.tokenManager().getAccessTokenString()).status());
        assertEquals("invalid_configuration", admin("GET", diagnostics(), null).body().path("grants").get(0).path("state").asText());
        denied(exchange("actor", rpt("subject", "read"), rawIssued(token("actor", Map.of("grant_type", "client_credentials"))), Map.of()));
    }

    @Test void consoleCreatesEditsAndWithdrawsARealDelegation() throws Exception {
        consoleOwnership();
        var inactive = admin.realm(realm).toRepresentation(); inactive.setAttributes(Map.of()); admin.realm(realm).update(inactive);
        var user = new UserRepresentation(); user.setUsername("fixture-administrator"); user.setEnabled(true);
        user.setFirstName("Fixture"); user.setLastName("Administrator"); user.setEmail("fixture-admin@example.test"); user.setEmailVerified(true);
        var password = new CredentialRepresentation(); password.setType("password"); password.setValue(secret); password.setTemporary(false);
        user.setCredentials(List.of(password));
        try (var response = admin.realm(realm).users().create(user)) { assertEquals(201, response.getStatus()); }
        var account = admin.realm(realm).users().searchByUsername(user.getUsername(), true).getFirst();
        var management = admin.realm(realm).clients().findByClientId("realm-management").getFirst();
        admin.realm(realm).users().get(account.getId()).roles().clientLevel(management.getId()).add(List.of(
                admin.realm(realm).clients().get(management.getId()).roles().get("realm-admin").toRepresentation()));
        var options = new ChromeOptions(); options.addArguments("--headless=new", "--window-size=1440,1400", "--disable-dev-shm-usage");
        WebDriver browser = new ChromeDriver(options);
        try {
            var wait = new WebDriverWait(browser, Duration.ofSeconds(30));
            String console = urls.getBase() + "/admin/" + realm + "/console/#/" + realm;
            browser.get(console + "/realm-settings/bounded-delegation");
            wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username"))).sendKeys(user.getUsername());
            browser.findElement(By.id("password")).sendKeys(secret);
            browser.findElement(By.id("kc-login")).click();
            wait.until(ExpectedConditions.elementToBeClickable(By.cssSelector("label[for='enabled']"))).click();
            browser.findElement(By.cssSelector("button[data-testid='save']")).click();
            wait.until(d -> administrativeEnabled());
            browser.get(console + "/page-section/Bounded%20delegations/add");
            wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector("input[data-testid='name']"))).sendKeys("Console invoice access");
            selectClient(browser, wait, "Actor client", "actor");
            selectClient(browser, wait, "Subject client", "subject");
            selectClient(browser, wait, "Audience client", "invoice-api");
            browser.findElement(By.cssSelector("input[data-testid='resource']")).sendKeys("invoice");
            browser.findElement(By.cssSelector("input[aria-label='Resource scopes']")).sendKeys("read");
            browser.findElement(By.cssSelector("label[for='enabled']")).click();
            browser.findElement(By.cssSelector("button[data-testid='save']")).click();
            wait.until(d -> administrativeCount() == 1);
            String id = admin("GET", diagnostics(), null).body().path("grants").get(0).path("id").asText();
            issued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
            browser.get(console + "/page-section/Bounded%20delegations/" + id);
            var ttl = wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector("input[data-testid='maxTTLSeconds']")));
            ttl.clear(); ttl.sendKeys("10");
            browser.findElement(By.cssSelector("button[data-testid='save']")).click();
            wait.until(d -> administrativeField(id, "maxTTLSeconds").equals("10"));
            assertTrue(issued(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of())).getExp() <= org.keycloak.common.util.Time.currentTime() + 10);
            var screenshot = java.nio.file.Path.of("target", System.getProperty("bounded.keycloak.version"), "qualification", "console.png");
            java.nio.file.Files.createDirectories(screenshot.getParent());
            java.nio.file.Files.write(screenshot, ((org.openqa.selenium.TakesScreenshot) browser).getScreenshotAs(OutputType.BYTES));
            browser.findElement(By.cssSelector("label[for='enabled']")).click();
            browser.findElement(By.cssSelector("button[data-testid='save']")).click();
            wait.until(d -> administrativeField(id, "enabled").equals("false"));
            denied(exchange("actor", rpt("subject", "read"), rpt("actor", "read"), Map.of()));
        } catch (RuntimeException | AssertionError failure) {
            var screenshot = java.nio.file.Path.of("target", System.getProperty("bounded.keycloak.version"), "qualification", "console-failure.png");
            java.nio.file.Files.createDirectories(screenshot.getParent());
            java.nio.file.Files.write(screenshot, ((org.openqa.selenium.TakesScreenshot) browser).getScreenshotAs(OutputType.BYTES));
            throw failure;
        } finally { browser.quit(); }
    }

    private void selectClient(WebDriver browser, WebDriverWait wait, String label, String name) {
        if (browser.findElements(By.cssSelector("button[data-testid='select-client-button']")).isEmpty()) {
            // 26.7 uses the native typeahead; 26.8 renders a client-selection modal.
            var input = browser.findElement(By.xpath("//label[contains(.,'" + label + "')]/ancestor::div[.//input[@role='combobox']][1]//input[@role='combobox']"));
            input.click(); input.sendKeys(name);
            wait.until(ExpectedConditions.elementToBeClickable(By.xpath("//*[@role='option'][normalize-space(.)='" + name + "']"))).click();
            return;
        }
        browser.findElement(By.xpath("//label[contains(.,'" + label + "')]/ancestor::div[.//button[@data-testid='select-client-button']][1]//button[@data-testid='select-client-button']")).click();
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector("[data-testid='select-client-modal']")));
        wait.until(ExpectedConditions.elementToBeClickable(By.xpath("//*[@data-testid='select-client-modal']//tr[.//td[normalize-space(.)='" + name + "']]//input[@type='radio']"))).click();
        wait.until(ExpectedConditions.elementToBeClickable(By.cssSelector("button[data-testid='confirm']"))).click();
        wait.until(ExpectedConditions.invisibilityOfElementLocated(By.cssSelector("[data-testid='select-client-modal']")));
    }
    private int administrativeCount() {
        try { return admin("GET", diagnostics(), null).body().path("grants").size(); }
        catch (Exception ex) { throw new IllegalStateException("Cannot read synthetic grant inventory", ex); }
    }
    private boolean administrativeEnabled() {
        try { return admin("GET", diagnostics(), null).body().path("enabled").asBoolean(); }
        catch (Exception ex) { throw new IllegalStateException("Cannot read synthetic realm state", ex); }
    }
    private String administrativeField(String id, String name) {
        try { return admin("GET", components() + "/" + id, null).body().path("config").path(name).path(0).asText(); }
        catch (Exception ex) { throw new IllegalStateException("Cannot read synthetic grant configuration", ex); }
    }

    private String components() { return "/admin/realms/" + realm + "/components"; }
    private String diagnostics() { return "/admin/realms/" + realm + "/bounded-delegation"; }
    private void consoleOwnership() {
        var client = admin.realm(realm).clients().get(api);
        var current = client.toRepresentation();
        var attributes = new HashMap<>(current.getAttributes()); attributes.put(GrantDocument.ATTRIBUTE, "");
        current.setAttributes(attributes); client.update(current);
        for (String name : List.of("actor", "subject", "next")) {
            var target = admin.realm(realm).clients().get(clients.get(name));
            var representation = target.toRepresentation();
            var values = new HashMap<>(representation.getAttributes()); values.put(GrantDocument.ACTOR_ATTRIBUTE, "");
            representation.setAttributes(values); target.update(representation);
        }
    }
    private Map<String, Object> consoleGrant(String name, String actorName, String subjectName) {
        return new HashMap<>(Map.of("providerType", "org.keycloak.services.ui.extend.UiPageProvider", "providerId", "Bounded delegations",
                "config", new HashMap<>(Map.of("name", List.of(name), "actor", List.of(actorName), "subject", List.of(subjectName),
                "audience", List.of("invoice-api"), "resource", List.of("invoice"), "scopes", List.of("read"), "maxDepth", List.of("2"),
                "maxTTLSeconds", List.of("30"), "enabled", List.of("true")))));
    }
    @SuppressWarnings("unchecked") private Map<String, List<String>> config(Map<String, Object> value) { return (Map<String, List<String>>) value.get("config"); }
    private Result componentRequest(String method, String path, Object body, String bearer) throws Exception { return request(method, urls.getBase() + path, null, bearer, body); }
    private void grantManagementRoles(String clientName, String... names) {
        var management = admin.realm(realm).clients().findByClientId("realm-management").getFirst();
        var user = admin.realm(realm).clients().get(clients.get(clientName)).getServiceAccountUser();
        var roles = Arrays.stream(names).map(name -> admin.realm(realm).clients().get(management.getId()).roles().get(name).toRepresentation()).toList();
        admin.realm(realm).users().get(user.getId()).roles().clientLevel(management.getId()).add(roles);
        admin.realm(realm).clients().get(clients.get(clientName)).getScopeMappings().clientLevel(management.getId()).add(roles);
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
        assertTrue(result.status() >= 200 && result.status() < 300, "Native fixture administration failed: HTTP " + result.status()
                + " " + result.body().path("error").asText() + " " + result.body().path("errorMessage").asText());
        return result;
    }
    private String created(Result result) {
        String id = result.body().path("id").asText(result.body().path("_id").asText());
        if (id.isBlank() && result.location() != null) id = result.location().substring(result.location().lastIndexOf('/') + 1);
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
        return new Result(result.statusCode(), result.body().isBlank() ? JSON.createObjectNode() : JSON.readTree(result.body()), result.headers().firstValue("Location").orElse(null));
    }
    private record Result(int status, JsonNode body, String location) { }
}
