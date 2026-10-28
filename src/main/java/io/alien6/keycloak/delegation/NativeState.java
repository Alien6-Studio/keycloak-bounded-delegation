/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import org.keycloak.models.KeycloakSession;

/** Keep native storage failures inside the bounded refusal path; never fall back to issuance. */
final class NativeState {
    private NativeState() {}
    static boolean claim(KeycloakSession session, String key, long ttl) {
        try { return session.singleUseObjects().putIfAbsent(key, ttl); }
        catch (RuntimeException failure) {
            session.getTransactionManager().setRollbackOnly();
            throw new Bounds.Rejected("native_state_unavailable");
        }
    }
}
