/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TaskContextTest {
    private static final String INPUT = """
            {"audience":"api","grant":"read","actorJti":"actor-jti","subjectJti":"subject-jti",
             "actorSubject":"actor-user","subjectSubject":"subject-user","permissions":{"invoice":["read"]},
             "parametersHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ttlSeconds":30}
            """;
    @Test void taskRegistrationRejectsAmbiguousUnboundedOrCallerExtendedInputs() {
        assertEquals(30, TaskContext.parse(INPUT, TaskContext.Registration.class).ttlSeconds());
        for (String invalid : List.of(INPUT.replace("\"ttlSeconds\":30", "\"ttlSeconds\":30,\"ttlSeconds\":600"),
                INPUT.replace("\"ttlSeconds\":30", "\"ttlSeconds\":601"), INPUT.replace("\"ttlSeconds\":30", "\"ttlSeconds\":\"30\""),
                INPUT.replace("\"grant\":\"read\"", "\"grant\":\"read\",\"taskId\":\"untrusted\""),
                INPUT.replace("\"permissions\":{\"invoice\":[\"read\"]}", "\"permissions\":{}"), INPUT + "{}")) {
            assertThrows(Bounds.Rejected.class, () -> TaskContext.parse(invalid, TaskContext.Registration.class));
        }
        assertThrows(Bounds.Rejected.class, () -> TaskContext.read(new ByteArrayInputStream("x".repeat(16385).getBytes(StandardCharsets.UTF_8)), TaskContext.Registration.class));
    }
    @Test void taskJournalCannotBeMisreadAsDefaultSoftwareOrMultiHopAuthority() {
        String header = "{\"version\":2,\"profile\":\"task-bound-software\",\"phase\":\"Committed\",\"ownerUID\":\"owner\",\"revision\":\"r\",\"realmID\":\"realm\","
                + "\"audience\":{\"id\":\"api\",\"attribute\":\"owner\",\"value\":\"api\"},\"grants\":[{";
        String grant = "\"name\":\"read\",\"actor\":{\"id\":\"a\",\"attribute\":\"owner\",\"value\":\"a\"},"
                + "\"subject\":{\"id\":\"s\",\"attribute\":\"owner\",\"value\":\"s\"},\"conditions\":[{\"kind\":\"role\",\"id\":\"r\"}],"
                + "\"authority\":{\"scopes\":[],\"realmRoles\":[],\"clientRoles\":{},\"permissions\":{\"invoice\":[\"read\"]}},\"maxDepth\":1,\"maxTTLSeconds\":30}]}";
        String valid = header + grant;
        assertEquals(TaskContext.PROFILE, GrantDocument.parse(valid).profile());
        assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse(valid.replace("\"maxDepth\":1", "\"maxDepth\":2")));
        assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse(valid.replace("\"version\":2", "\"version\":1")));
        assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse(valid.replace("\"profile\":\"task-bound-software\",", "")));
    }
}
