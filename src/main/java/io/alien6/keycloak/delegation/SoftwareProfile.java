/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.io.IOException;
import java.util.Properties;

/** Versioned deployment policy. The generic bounds kernel does not depend on this profile. */
final class SoftwareProfile {
    static final String ID = "software-v1";
    static final String CONTRACT = "bounded-delegation/" + ID;
    static final int MAX_DEPTH = 4;
    static final int MAX_TTL_SECONDS = 600;
    static final String VERSION = version();

    private SoftwareProfile() {}

    private static String version() {
        try (var stream = SoftwareProfile.class.getResourceAsStream("/bounded-delegation.properties")) {
            if (stream == null) throw new IllegalStateException("Missing extension version metadata");
            Properties properties = new Properties();
            properties.load(stream);
            String value = properties.getProperty("version");
            if (value == null || !value.matches("[0-9]+\\.[0-9]+\\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?")) {
                throw new IllegalStateException("Invalid extension version metadata");
            }
            return value;
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot read extension version metadata", ex);
        }
    }
}
