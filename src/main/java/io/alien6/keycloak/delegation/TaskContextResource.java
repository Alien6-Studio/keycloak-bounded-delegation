/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Map;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.Version;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AppAuthManager;

/** Confidential native task authority and online recipient decisions, outside the Admin API. */
@Produces(MediaType.APPLICATION_JSON)
public final class TaskContextResource {
    private final KeycloakSession session;
    TaskContextResource(KeycloakSession session) { this.session = session; }
    @GET public Map<String, Object> capabilities() {
        boolean enabled = false;
        try { TaskContext.issuer(session, realm()); enabled = true; } catch (Bounds.Rejected ignored) { /* bounded public discovery */ }
        return Map.of("contract", TaskContext.CONTRACT, "extensionVersion", SoftwareProfile.VERSION, "keycloakVersion", Version.VERSION,
                "enabled", enabled, "experimental", true, "stateStore", "database", "onlineRequired", true, "singleUseApproval", true,
                "maxDepth", 1, "maxTTLSeconds", 600);
    }
    @POST @Path("contexts") @Consumes(MediaType.APPLICATION_JSON)
    public Response create(InputStream body) {
        try { return response(201, TaskContext.create(session, realm(), authenticate(), TaskContext.read(body, TaskContext.Registration.class), Time.currentTime())); }
        catch (Bounds.Rejected ex) { return denied(); }
    }
    @DELETE @Path("contexts/{reference}")
    public Response cancel(@PathParam("reference") String reference) {
        try { TaskContext.cancel(session, realm(), authenticate(), reference, Time.currentTime()); return response(200, Map.of("cancelled", true)); }
        catch (Bounds.Rejected ex) { return denied(); }
    }
    @POST @Path("check") @Consumes(MediaType.APPLICATION_JSON)
    public Response check(InputStream body) {
        try { return response(200, Map.of("active", TaskContext.check(session, realm(), authenticate(), TaskContext.read(body, TaskContext.Check.class), Time.currentTime()))); }
        catch (Bounds.Rejected ex) { return denied(); }
    }
    private RealmModel realm() { return session.getContext().getRealm(); }
    private String authenticate() {
        if (!"https".equals(session.getContext().getUri().getRequestUri().getScheme())) throw new Bounds.Rejected("task_tls_required");
        TaskContext.issuer(session, realm());
        var auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null || auth.getToken().getAudience() == null || auth.getToken().getAudience().length != 1
                || !Arrays.asList(auth.getToken().getAudience()).contains(TaskContext.ENDPOINT_AUDIENCE)
                || auth.getToken().getOtherClaims().containsKey("act")) throw new Bounds.Rejected("task_authentication_required");
        var client = session.clients().getClientByClientId(realm(), auth.getToken().getIssuedFor());
        if (client == null || !client.isEnabled() || client.isPublicClient() || !client.isServiceAccountsEnabled()
                || !auth.getUser().isEnabled() || !client.getId().equals(auth.getUser().getServiceAccountClientLink())
                || !auth.getUser().equals(session.users().getServiceAccount(client))) throw new Bounds.Rejected("task_authentication_required");
        return client.getId();
    }
    private static Response denied() { return response(403, Map.of("error", "task_authorization_refused")); }
    private static Response response(int status, Object value) { return Response.status(status).header("Cache-Control", "no-store").entity(value).build(); }
}
