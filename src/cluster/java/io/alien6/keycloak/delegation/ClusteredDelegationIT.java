/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.keycloak.TokenVerifier;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real two-JVM HTTP/DB/cache tests. The Python lab owns all disposable resources. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ClusteredDelegationIT {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ACCESS = "urn:ietf:params:oauth:token-type:access_token";
    private static final String OWNER = "bounded.cluster.identity";
    private final Map<String, String> clients = new HashMap<>();
    private final Map<String, String> users = new HashMap<>();
    private final Map<String, Object> measurements = new LinkedHashMap<>();
    private final Map<String, Boolean> checks = new LinkedHashMap<>();
    private final Map<String, PublicKey> keys = new HashMap<>();
    private HttpClient http;
    private JsonNode configuration;
    private String realm, issuer, admin, resource, secret, audienceID;
    private GrantDocument document;

    @BeforeAll void nativeClusterGraph() throws Exception {
        String config = System.getenv("BOUNDED_CLUSTER_CONFIG");
        assertTrue(config != null && Files.size(Path.of(config)) < 65536, "Private cluster configuration required");
        configuration = JSON.readTree(Files.readString(Path.of(config)));
        assertTrue(configuration.path("label").asText().matches("bounded-lab-[0-9a-f]{16}"), "Unexpected lab identity");
        assertEquals(System.getProperty("bounded.keycloak.version"), configuration.path("keycloak").asText());
        for (JsonNode node : configuration.path("nodes")) assertTrue(node.asText().matches("[0-9a-f]{64}"));
        assertEquals(2, configuration.path("endpoints").size());
        for (JsonNode endpoint : configuration.path("endpoints")) assertTrue(endpoint.asText().matches("https://localhost:[0-9]{1,5}"));
        var store = KeyStore.getInstance(KeyStore.getDefaultType()); store.load(null);
        var certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Path.of(configuration.path("ca").asText()))));
        store.setCertificateEntry("lab", certificate);
        var managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); managers.init(store);
        var tls = SSLContext.getInstance("TLSv1.3"); tls.init(null, managers.getTrustManagers(), null);
        http = HttpClient.newBuilder().sslContext(tls).connectTimeout(Duration.ofSeconds(5)).build();
        admin = raw(request(0, "POST", "/realms/master/protocol/openid-connect/token", Map.of("grant_type", "password", "client_id", "admin-cli",
                "username", configuration.path("adminUser").asText(), "password", configuration.path("adminPassword").asText()), null, null));
        realm = "cluster-" + UUID.randomUUID(); secret = UUID.randomUUID().toString();
        issuer = configuration.path("issuer").asText() + "/realms/" + realm;
        admin("POST", "/admin/realms", Map.of("realm", realm, "enabled", true, "accessTokenLifespan", 300,
                "attributes", Map.of(GrantDocument.REALM_ATTRIBUTE, SoftwareProfile.ID)));
        for (String name : List.of("actor", "subject", "next", "invoice-api")) {
            admin("POST", "/admin/realms/" + realm + "/clients", Map.of("clientId", name, "enabled", true, "protocol", "openid-connect",
                    "publicClient", false, "fullScopeAllowed", false, "serviceAccountsEnabled", true, "secret", secret,
                    "authorizationServicesEnabled", name.equals("invoice-api"), "attributes", Map.of(OWNER, name,
                            "standard.token.exchange.enabled", "true", GrantDocument.ACTOR_ATTRIBUTE, "cluster-bound")));
            JsonNode values = admin("GET", "/admin/realms/" + realm + "/clients?clientId=" + name, null).body();
            assertEquals(1, values.size()); clients.put(name, values.get(0).path("id").asText());
            users.put(name, admin("GET", "/admin/realms/" + realm + "/clients/" + clients.get(name) + "/service-account-user", null).body().path("id").asText());
        }
        audienceID = clients.get("invoice-api");
        String base = "/admin/realms/" + realm + "/clients/" + audienceID + "/authz/resource-server";
        for (String route : List.of("permission", "resource", "policy")) {
            for (JsonNode value : admin("GET", base + "/" + route, null).body()) {
                admin("DELETE", base + "/" + route + "/" + value.path(route.equals("resource") ? "_id" : "id").asText(), null);
            }
        }
        List<Map<String, String>> scopes = new ArrayList<>();
        for (String name : List.of("read", "write")) {
            scopes.add(Map.of("name", name, "id", created(admin("POST", base + "/scope", Map.of("name", name)))));
        }
        resource = created(admin("POST", base + "/resource", Map.of("name", "invoice", "type", "invoice", "ownerManagedAccess", false, "scopes", scopes)));
        String policy = created(admin("POST", base + "/policy/client", Map.of("name", "software", "type", "client", "logic", "POSITIVE", "decisionStrategy", "AFFIRMATIVE",
                "clients", List.of(clients.get("actor"), clients.get("subject"), clients.get("next")))));
        admin("POST", base + "/permission/scope", Map.of("name", "invoice", "type", "scope", "logic", "POSITIVE", "decisionStrategy", "AFFIRMATIVE",
                "resources", List.of(resource), "scopes", scopes.stream().map(scope -> scope.get("id")).toList(), "policies", List.of(policy)));
        List<GrantDocument.Grant> grants = new ArrayList<>();
        for (String[] pair : List.of(new String[]{"actor", "subject"}, new String[]{"subject", "next"}, new String[]{"next", "actor"})) {
            grants.add(new GrantDocument.Grant(pair[0] + "-" + pair[1], binding(pair[0]), binding(pair[1]),
                    new Authority(Set.of(), Set.of(), Map.of(), Map.of(resource, Set.of("read"))), List.of(
                    new GrantDocument.Condition("client", clients.get(pair[0]), OWNER, pair[0]), new GrantDocument.Condition("client", clients.get(pair[1]), OWNER, pair[1])), 2, 90));
        }
        String realmID = admin("GET", "/admin/realms/" + realm, null).body().path("id").asText();
        document = new GrantDocument(1, "Committed", "cluster-owner", "cluster-revision", realmID, binding("invoice-api"), grants, List.of());
        save(document);
        for (JsonNode endpoint : configuration.path("endpoints")) {
            assertTrue(endpoint.asText().startsWith("https://"));
        }
        var jwks = JSON.treeToValue(request(0, "GET", "/realms/" + realm + "/protocol/openid-connect/certs", null, null, null).body(), JSONWebKeySet.class);
        for (var key : jwks.getKeys()) if ("RSA".equals(key.getKeyType())) keys.put(key.getKeyId(), JWKParser.create(key).toPublicKey());
        assertTrue(!keys.isEmpty(), "Native signing keys required");
        check("independent_nodes_share_native_configuration", request(1, "GET", "/admin/realms/" + realm + "/clients/" + audienceID, null, admin, null).body()
                .path("attributes").path(GrantDocument.ATTRIBUTE).asText().equals(JSON.writeValueAsString(document)));
    }

    @Test @Order(1) void sameActorAcrossNodesHasAtMostOneAcceptedIssuance() throws Exception {
        String actor = input(0, "actor"), subject = input(1, "subject");
        List<Attempt> results = parallel(32, index -> exchange(index % 2, "actor", subject, actor));
        assertEquals(1, successes(results));
        denied(exchange(0, "actor", subject, actor)); denied(exchange(1, "actor", subject, actor));
        record("replay32", results); check("cross_node_atomic_replay", true);
    }

    @Test @Order(2) void freshFanOutAttenuatesEveryGrantWithoutMergingChains() throws Exception {
        for (int count : List.of(1, 10, 100)) {
            List<String> actors = new ArrayList<>();
            for (int index = 0; index < count; index++) actors.add(input(index % 2, "actor"));
            String subject = input(1, "subject");
            List<Attempt> results = parallel(count, index -> exchange(index % 2, "actor", subject, actors.get(index)));
            assertEquals(count, successes(results)); record("fresh" + count, results);
        }
        String first = raw(exchange(0, "actor", input(1, "subject"), input(0, "actor")));
        String second = raw(exchange(1, "subject", input(0, "next"), first));
        assertEquals(2, ChainState.actorDepth(verified(second).getOtherClaims().get("act")));
        assertTrue(verified(second).getExp() <= verified(first).getExp());
        denied(exchange(0, "next", input(1, "actor"), second));
        check("cross_node_fanout_and_monotonic_depth_expiry", true);
    }

    @Test @Order(3) void committedPolicyWithdrawalIsObservedOnTheOtherNode() throws Exception {
        String issued = raw(exchange(0, "actor", input(1, "subject"), input(0, "actor")));
        GrantDocument changed = new GrantDocument(1, "Prepared", document.ownerUID(), "withdrawn-revision", document.realmID(), document.audience(), document.grants(), List.of());
        long started = System.nanoTime(); save(changed);
        await(() -> request(1, "GET", "/admin/realms/" + realm + "/clients/" + audienceID, null, admin, null).body()
                .path("attributes").path(GrantDocument.ATTRIBUTE).asText().equals(JSON.writeValueAsString(changed)), 30);
        denied(exchange(1, "subject", input(0, "next"), issued));
        denied(exchange(1, "actor", input(0, "subject"), input(1, "actor")));
        measurements.put("withdrawal_observed_ms", (System.nanoTime() - started) / 1_000_000);
        save(document); check("cross_node_withdrawal_stops_new_issuance_and_chaining", true);
    }

    @Test @Order(4) void killedNodeAndRejoinCannotForgetSpentActorEvidence() throws Exception {
        String actor = input(0, "actor"), subject = input(1, "subject");
        raw(exchange(0, "actor", subject, actor));
        String node = configuration.path("nodes").get(0).asText();
        long started = System.nanoTime();
        docker("kill", "--signal", "KILL", node);
        try { denied(exchange(1, "actor", subject, actor)); }
        finally { docker("start", node); }
        await(() -> request(0, "GET", "/realms/" + realm + "/.well-known/openid-configuration", null, null, null).status() == 200, 120);
        awaitCluster(); denied(exchange(0, "actor", subject, actor)); denied(exchange(1, "actor", subject, actor));
        raw(exchange(1, "actor", input(0, "subject"), input(1, "actor")));
        measurements.put("node_recovery_ms", (System.nanoTime() - started) / 1_000_000);
        check("node_kill_rejoin_preserves_spent_actors", true);
    }

    @Test @Order(5) void cachePartitionWithDatabaseAndHttpsStillAvailableCannotDoubleIssue() throws Exception {
        List<String> actors = new ArrayList<>();
        for (int i = 0; i < 4; i++) actors.add(input(i % 2, "actor"));
        String subject = input(0, "subject");
        String revocableActor = input(0, "actor");
        String network = configuration.path("network").asText(), node = configuration.path("nodes").get(1).asText();
        assertTrue(network.equals(configuration.path("label").asText() + "-cache"));
        long started = System.nanoTime();
        docker("network", "disconnect", network, node);
        List<Integer> accepted = new ArrayList<>();
        try {
            // HTTPS and PostgreSQL use the independent control network. Only
            // the JGroups bind network is removed from the second node.
            assertEquals(200, request(1, "GET", "/realms/" + realm + "/.well-known/openid-configuration", null, null, null).status());
            Thread.sleep(5000);
            for (String actor : actors) {
                List<Attempt> attempts = parallel(8, index -> exchange(index % 2, "actor", subject, actor));
                int count = successes(attempts); assertTrue(count <= 1, "Partition duplicated accepted issuance"); accepted.add(count);
            }
            GrantDocument withdrawn = new GrantDocument(1, "Prepared", document.ownerUID(), "partition-withdrawal", document.realmID(), document.audience(), document.grants(), List.of());
            Result update = saveResult(withdrawn);
            boolean acknowledged = update.status() >= 200 && update.status() < 300;
            measurements.put("partition_policy_write_acknowledged", acknowledged);
            Result attempt = exchange(1, "actor", subject, revocableActor);
            if (acknowledged) denied(attempt);
            else if (attempt.status() == 200) verified(raw(attempt));
            else denied(attempt);
        } finally {
            docker("network", "connect", "--ip", configuration.path("cacheAddresses").get(1).asText(), network, node);
        }
        awaitCluster();
        save(document);
        for (int index = 0; index < actors.size(); index++) {
            String actor = actors.get(index);
            List<Attempt> after = parallel(8, attempt -> exchange(attempt % 2, "actor", subject, actor));
            assertTrue(accepted.get(index) + successes(after) <= 1, "Rejoin duplicated accepted issuance");
        }
        check("cache_only_partition_and_rejoin_refuse_duplicate_issuance", true);
        measurements.put("cache_partition_recovery_ms", (System.nanoTime() - started) / 1_000_000);
    }

    @Test @Order(6) void taskApprovalAndCancellationRemainNativeAcrossNodesAndPartition() throws Exception {
        admin("POST", "/admin/realms/" + realm + "/clients", Map.of("clientId", "task-authority", "enabled", true,
                "protocol", "openid-connect", "publicClient", false, "fullScopeAllowed", false, "serviceAccountsEnabled", true,
                "secret", secret, "attributes", Map.of(OWNER, "task-authority")));
        clients.put("task-authority", admin("GET", "/admin/realms/" + realm + "/clients?clientId=task-authority", null).body().get(0).path("id").asText());
        for (String name : List.of("task-authority", "invoice-api")) {
            admin("POST", "/admin/realms/" + realm + "/clients/" + clients.get(name) + "/protocol-mappers/models",
                    Map.of("name", "task-endpoint", "protocol", "openid-connect", "protocolMapper", "oidc-audience-mapper",
                            "config", Map.of("included.custom.audience", TaskContext.ENDPOINT_AUDIENCE, "access.token.claim", "true")));
        }
        var realmState = (com.fasterxml.jackson.databind.node.ObjectNode) admin("GET", "/admin/realms/" + realm, null).body();
        var attributes = (com.fasterxml.jackson.databind.node.ObjectNode) realmState.path("attributes");
        attributes.put(TaskContext.PROFILE_ATTRIBUTE, TaskContext.PROFILE);
        attributes.put(TaskContext.ISSUER_ATTRIBUTE, JSON.writeValueAsString(binding("task-authority")));
        admin("PUT", "/admin/realms/" + realm, realmState);
        var grants = document.grants().stream().map(grant -> new GrantDocument.Grant(grant.name(), grant.actor(), grant.subject(), grant.authority(),
                grant.conditions(), 1, grant.maxTTLSeconds())).toList();
        save(new GrantDocument(2, document.phase(), document.ownerUID(), document.revision(), document.realmID(), document.audience(), grants, List.of(), TaskContext.PROFILE));
        String path = "/realms/" + realm + "/bounded-delegation/task-context";
        assertTrue(request(0, "GET", path, null, null, null).body().path("enabled").asBoolean());
        assertTrue(request(1, "GET", path, null, null, null).body().path("enabled").asBoolean());
        String actor = input(0, "actor"), subject = input(1, "subject");
        String authority = taskAccess(0, "task-authority"), recipient = taskAccess(1, "invoice-api");
        var registration = Map.of("audience", audienceID, "grant", "actor-subject", "actorJti", signed(actor).getId(), "subjectJti", signed(subject).getId(),
                "actorSubject", users.get("actor"), "subjectSubject", users.get("subject"), "permissions", Map.of(resource, Set.of("read")),
                "parametersHash", "a".repeat(64), "ttlSeconds", 90);
        Result created = request(0, "POST", path + "/contexts", null, authority, registration);
        assertEquals(201, created.status());
        String approval = created.body().path("approval").asText(), reference = created.body().path("reference").asText();
        List<Attempt> attempts = parallel(32, index -> taskExchange(index % 2, actor, subject, approval));
        List<Attempt> accepted = attempts.stream().filter(attempt -> attempt.result().status() == 200).toList();
        assertEquals(1, accepted.size(), "Approval/actor replay duplicated task-bound issuance");
        AccessToken output = signed(raw(accepted.getFirst().result()));
        assertEquals(Set.of("invoice-api"), Set.of(output.getAudience()));
        assertEquals(Map.of(resource, Set.of("read")), NativeAuthority.fromToken(output).permissions());
        assertEquals(reference, ((Map<?, ?>) output.getOtherClaims().get(TaskContext.CLAIM)).get("reference"));
        record("task_approval32", attempts); check("task_approval_is_single_use_across_nodes", true);
        Map<String, Object> query = Map.of("reference", reference, "tokenId", output.getId(), "parametersHash", "a".repeat(64), "resource", resource, "scope", "read");
        assertTrue(request(1, "POST", path + "/check", null, recipient, query).body().path("active").asBoolean());
        String network = configuration.path("network").asText(), node = configuration.path("nodes").get(1).asText();
        long started = System.nanoTime();
        docker("network", "disconnect", network, node);
        try {
            assertEquals(200, request(0, "DELETE", path + "/contexts/" + reference, null, authority, null).status());
            denied(request(1, "POST", path + "/check", null, recipient, query));
            denied(taskExchange(1, actor, subject, approval));
        } finally { docker("network", "connect", "--ip", configuration.path("cacheAddresses").get(1).asText(), network, node); }
        awaitCluster();
        denied(request(0, "POST", path + "/check", null, recipient, query));
        denied(request(1, "POST", path + "/check", null, recipient, query));
        measurements.put("task_cancellation_partition_ms", (System.nanoTime() - started) / 1_000_000);
        check("task_cancellation_survives_cache_partition_and_rejoin", true);
    }
    private String taskAccess(int node, String client) throws Exception {
        return raw(request(node, "POST", "/realms/" + realm + "/protocol/openid-connect/token",
                Map.of("grant_type", "client_credentials", "client_id", client, "client_secret", secret), null, null));
    }
    private Result taskExchange(int node, String actor, String subject, String approval) throws Exception {
        Map<String, String> form = new HashMap<>(Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "client_id", "actor", "client_secret", secret,
                "actor_token", actor, "actor_token_type", ACCESS, "subject_token", subject, "subject_token_type", ACCESS, "audience", "invoice-api"));
        form.put("task_context", approval);
        return request(node, "POST", "/realms/" + realm + "/protocol/openid-connect/token", form, null, null);
    }

    @AfterAll void privateCleanupAndBoundedMeasurements() throws Exception {
        try { if (realm != null && admin != null) admin("DELETE", "/admin/realms/" + realm, null); }
        finally {
            Path path = Path.of("target", System.getProperty("bounded.keycloak.version"), "qualification", "cluster-measurements.json");
            Files.createDirectories(path.getParent());
            Files.writeString(path, JSON.writeValueAsString(Map.of("complete", checks.size() == 8 && checks.values().stream().allMatch(Boolean::booleanValue),
                    "checks", checks, "measurements", measurements, "limits", List.of("one host; two JVMs; no throughput SLA", "JWT offline use remains bounded by expiry",
                    "policy writes can be rejected or uncertain during cache partition; immediate distributed revocation is not claimed"))) + "\n");
        }
    }

    private GrantDocument.Binding binding(String name) { return new GrantDocument.Binding(clients.get(name), OWNER, name); }
    private void check(String name, boolean value) { assertTrue(value, "Native cluster invariant failed"); checks.put(name, true); }
    private void save(GrantDocument value) throws Exception {
        Result result = saveResult(value);
        assertTrue(result.status() >= 200 && result.status() < 300, "Disposable native grant update failed");
    }
    private Result saveResult(GrantDocument value) throws Exception {
        var target = admin("GET", "/admin/realms/" + realm + "/clients/" + audienceID, null).body();
        ((com.fasterxml.jackson.databind.node.ObjectNode) target.path("attributes")).put(GrantDocument.ATTRIBUTE, JSON.writeValueAsString(value));
        return request(0, "PUT", "/admin/realms/" + realm + "/clients/" + audienceID, null, admin, target);
    }
    private Result admin(String method, String path, Object body) throws Exception {
        Result value = request(0, method, path, null, admin, body);
        assertTrue(value.status() >= 200 && value.status() < 300, "Disposable native administration failed"); return value;
    }
    private String input(int node, String client) throws Exception {
        String access = raw(request(node, "POST", "/realms/" + realm + "/protocol/openid-connect/token", Map.of("grant_type", "client_credentials", "client_id", client, "client_secret", secret), null, null));
        return raw(request(node, "POST", "/realms/" + realm + "/protocol/openid-connect/token", Map.of("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket",
                "audience", "invoice-api", "permission", "invoice#read"), access, null));
    }
    private Result exchange(int node, String client, String subject, String actor) throws Exception {
        Result result = request(node, "POST", "/realms/" + realm + "/protocol/openid-connect/token", Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id", client, "client_secret", secret, "subject_token", subject, "subject_token_type", ACCESS, "actor_token", actor,
                "actor_token_type", ACCESS, "audience", "invoice-api"), null, null);
        if (result.status() == 200) {
            AccessToken output = verified(raw(result));
            assertTrue(output.getExp() <= Math.min(signed(actor).getExp(), signed(subject).getExp()), "Input expiry bounds exceeded");
            assertTrue(output.getSubject().equals(signed(subject).getSubject()), "Subject binding changed");
            assertTrue(client.equals(output.getIssuedFor()), "Requester binding changed");
        }
        return result;
    }
    private String raw(Result result) { assertEquals(200, result.status(), "Native token issuance failed; body withheld"); assertTrue(result.body().hasNonNull("access_token")); return result.body().path("access_token").asText(); }
    private void denied(Result result) { assertTrue(result.status() >= 400, "Expected explicit denial/failure"); assertFalse(result.body().hasNonNull("access_token")); }
    private AccessToken signed(String raw) throws Exception {
        var jws = new JWSInput(raw); assertEquals("RS256", jws.getHeader().getAlgorithm().name());
        PublicKey key = keys.get(jws.getHeader().getKeyId()); assertTrue(key != null, "Unqualified signing key");
        return TokenVerifier.create(raw, AccessToken.class).withDefaultChecks().realmUrl(issuer).publicKey(key).verify().getToken();
    }
    private AccessToken verified(String raw) throws Exception {
        AccessToken token = signed(raw);
        assertTrue(Set.of(token.getAudience()).equals(Set.of("invoice-api")), "Output audience widened");
        assertTrue(NativeAuthority.fromToken(token).permissions().equals(Map.of(resource, Set.of("read"))), "Output authority widened");
        assertTrue(token.getExp() <= org.keycloak.common.util.Time.currentTime() + 90, "Output expiry widened");
        Authority authority = NativeAuthority.fromToken(token);
        assertTrue(authority.scopes().isEmpty() && authority.realmRoles().isEmpty() && authority.clientRoles().isEmpty(), "Ambient authority retained");
        assertTrue(token.getOtherClaims().keySet().equals(Set.of("act")), "Unexpected mapper/task claims retained");
        Object act = token.getOtherClaims().get("act");
        assertTrue(act instanceof Map<?, ?>, "Actor proof absent");
        Map<?, ?> current = (Map<?, ?>) act;
        assertTrue(token.getIssuedFor().equals(current.get("client_id")) && users.get(token.getIssuedFor()).equals(current.get("sub")), "Current actor differs from requester");
        return token;
    }
    private int successes(List<Attempt> attempts) throws Exception {
        int count = 0;
        for (Attempt attempt : attempts) { if (attempt.result().status() == 200) { verified(raw(attempt.result())); count++; } else denied(attempt.result()); }
        return count;
    }
    private List<Attempt> parallel(int count, Exchange action) throws Exception {
        try (var executor = Executors.newFixedThreadPool(Math.min(count, 16))) {
            CountDownLatch start = new CountDownLatch(1); List<Callable<Attempt>> calls = new ArrayList<>();
            for (int i = 0; i < count; i++) { final int index = i; calls.add(() -> { start.await(); long began = System.nanoTime(); Result result = action.run(index); return new Attempt(result, (System.nanoTime() - began) / 1_000_000.0); }); }
            var futures = calls.stream().map(executor::submit).toList(); start.countDown(); List<Attempt> result = new ArrayList<>();
            for (var future : futures) result.add(future.get()); return result;
        }
    }
    private void record(String name, List<Attempt> attempts) {
        double[] sorted = attempts.stream().mapToDouble(Attempt::milliseconds).sorted().toArray();
        measurements.put(name, Map.of("samples", sorted.length, "accepted", attempts.stream().filter(a -> a.result().status() == 200).count(),
                "p50_ms", sorted[(int) Math.ceil(sorted.length * .5) - 1], "p95_ms", sorted[(int) Math.ceil(sorted.length * .95) - 1]));
    }
    private Result request(int node, String method, String path, Map<String, String> form, String bearer, Object json) throws Exception {
        String body = form == null ? (json == null ? "" : JSON.writeValueAsString(json)) : form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(java.util.stream.Collectors.joining("&"));
        var request = HttpRequest.newBuilder(URI.create(configuration.path("endpoints").get(node).asText() + path)).timeout(Duration.ofSeconds(20));
        if (bearer != null) request.header("Authorization", "Bearer " + bearer);
        if (form != null || json != null) request.header("Content-Type", form == null ? "application/json" : "application/x-www-form-urlencoded");
        var response = http.send(request.method(method, HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(response.body().length() <= 1024 * 1024, "Native response budget exceeded");
        return new Result(response.statusCode(), response.body().isBlank() ? JSON.createObjectNode() : JSON.readTree(response.body()), response.headers().firstValue("Location").orElse(null));
    }
    private String created(Result result) { String id = result.body().path("_id").asText(result.body().path("id").asText()); return !id.isBlank() ? id : result.location().substring(result.location().lastIndexOf('/') + 1); }
    private void docker(String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of("docker")); command.addAll(Arrays.asList(arguments));
        var process = new ProcessBuilder(command).redirectErrorStream(true).start(); process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(60, java.util.concurrent.TimeUnit.SECONDS) && process.exitValue() == 0, "Owned cluster fault operation failed");
    }
    private void awaitCluster() throws Exception {
        await(() -> {
            for (JsonNode node : configuration.path("nodes")) {
                var process = new ProcessBuilder("docker", "logs", node.asText()).redirectErrorStream(true).start();
                String logs = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                String lastView = logs.lines().filter(line -> line.contains("ISPN000094:")).reduce((previous, current) -> current).orElse("");
                if (process.waitFor() != 0 || !lastView.contains("(2)")) return false;
            }
            return true;
        }, 120);
    }
    private void await(Condition condition, int seconds) throws Exception {
        long end = System.nanoTime() + Duration.ofSeconds(seconds).toNanos();
        while (System.nanoTime() < end) { try { if (condition.ready()) return; } catch (java.io.IOException ignored) { } Thread.sleep(500); }
        assertTrue(false, "Native cluster recovery deadline exceeded");
    }
    @FunctionalInterface private interface Condition { boolean ready() throws Exception; }
    @FunctionalInterface private interface Exchange { Result run(int index) throws Exception; }
    private record Result(int status, JsonNode body, String location) { }
    private record Attempt(Result result, double milliseconds) { }
}
