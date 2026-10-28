/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.Set;

/** Exact software-v1 request surface; caller extensions never select a weaker route. */
final class ExchangeForm {
    private static final Set<String> FIELDS = Set.of("grant_type", "client_id", "client_secret",
            "client_assertion", "client_assertion_type", "subject_token", "subject_token_type",
            "actor_token", "actor_token_type", "requested_token_type", "audience", "resource", "scope", "task_context");

    private ExchangeForm() {}

    static void validate(Set<String> fields) {
        if (!FIELDS.containsAll(fields)) throw new Bounds.Rejected("exchange_parameter_unsupported");
    }
}
