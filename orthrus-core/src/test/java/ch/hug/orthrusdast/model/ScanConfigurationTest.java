package ch.hug.orthrusdast.model;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ScanConfigurationTest {

    @Test
    void testDefaults() {
        ScanConfiguration config = ScanConfiguration.defaults();
        
        assertNotNull(config);
        assertTrue(config.includeScanners().isEmpty());
        assertTrue(config.excludeScanners().isEmpty());
        assertEquals(10, config.concurrency());
        assertEquals(5000, config.httpConnectTimeoutMs());
        assertEquals(10000, config.httpReadTimeoutMs());
        assertFalse(config.ignoreSslErrors());
        assertEquals("json", config.reportFormat());
        assertNull(config.authScheme());
        assertNull(config.secondaryAuthScheme());
        assertEquals("en", config.language());
        assertFalse(config.includePassed());
        assertEquals(GatewayType.AUTO, config.gatewayType());
        assertNull(config.appUrl());
        assertNull(config.k8sToken());
    }

    @Test
    void testShouldRunScanner() {
        ScanConfiguration configWithIncludes = new ScanConfiguration(
                List.of("sql-injection", "xss"),
                List.of(),
                10, 5000, 10000, false, "json", null, null, "en", false, GatewayType.AUTO, null, null
        );

        assertTrue(configWithIncludes.shouldRunScanner("sql-injection"));
        assertTrue(configWithIncludes.shouldRunScanner("xss"));
        assertFalse(configWithIncludes.shouldRunScanner("csrf"));

        ScanConfiguration configWithExcludes = new ScanConfiguration(
                List.of(),
                List.of("csrf", "ssti"),
                10, 5000, 10000, false, "json", null, null, "en", false, GatewayType.AUTO, null, null
        );

        assertTrue(configWithExcludes.shouldRunScanner("sql-injection"));
        assertFalse(configWithExcludes.shouldRunScanner("csrf"));
        assertFalse(configWithExcludes.shouldRunScanner("ssti"));

        ScanConfiguration configWithBoth = new ScanConfiguration(
                List.of("sql-injection", "csrf"),
                List.of("csrf"),
                10, 5000, 10000, false, "json", null, null, "en", false, GatewayType.AUTO, null, null
        );

        // Excludes take precedence over includes
        assertFalse(configWithBoth.shouldRunScanner("csrf"));
        assertTrue(configWithBoth.shouldRunScanner("sql-injection"));
    }
}
