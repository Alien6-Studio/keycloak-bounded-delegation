/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SoftwareProfileTest {
    @Test void discoveryUsesPackagedVersionAndExposesNoAdministrativeState() {
        var capability = new CapabilityResource().capabilities();
        assertTrue(SoftwareProfile.VERSION.matches("[0-9]+\\.[0-9]+\\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?"));
        assertEquals(SoftwareProfile.VERSION, capability.get("extensionVersion"));
        assertEquals(false, capability.get("enabled"));
        assertEquals(Set.of("contract", "extensionVersion", "keycloakVersion", "experimental", "maxDepth", "maxTTLSeconds", "enabled"), capability.keySet());
    }
}
