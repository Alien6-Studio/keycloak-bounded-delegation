/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ExchangeFormTest {
    @Test void acceptsOnlyReviewedSoftwareParameters() {
        assertDoesNotThrow(() -> ExchangeForm.validate(Set.of("grant_type", "subject_token", "actor_token",
                "audience", "resource", "scope", "client_assertion", "client_assertion_type", "task_context")));
        for (String field : Set.of("task_assertion", "requested_subject", "requested_issuer",
                "subject_issuer", "permission", "authorization_details", "unknown")) {
            assertThrows(Bounds.Rejected.class, () -> ExchangeForm.validate(Set.of("actor_token", field)));
        }
    }

    @Test void refusesMergingIndependentDelegatedLineages() {
        ChainState left = new ChainState(1, 2, 30, Map.of("left", "policy"));
        ChainState right = new ChainState(1, 2, 30, Map.of("right", "policy"));
        assertThrows(Bounds.Rejected.class, () -> left.extend(right, null, null, null));
    }
}
