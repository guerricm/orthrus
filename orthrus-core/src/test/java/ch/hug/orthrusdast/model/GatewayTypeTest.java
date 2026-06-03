package ch.hug.orthrusdast.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GatewayTypeTest {

    @Test
    void testFromString_ValidInputs() {
        assertEquals(GatewayType.TRAEFIK, GatewayType.fromString("traefik"));
        assertEquals(GatewayType.TRAEFIK, GatewayType.fromString("TRAEFIK"));
        assertEquals(GatewayType.SPRING_CLOUD_GATEWAY, GatewayType.fromString("spring-cloud-gateway"));
        assertEquals(GatewayType.KONG, GatewayType.fromString("kong"));
        assertEquals(GatewayType.HAPROXY, GatewayType.fromString("haproxy"));
        assertEquals(GatewayType.K8S, GatewayType.fromString("k8s"));
        assertEquals(GatewayType.AUTO, GatewayType.fromString("auto"));
    }

    @Test
    void testFromString_EmptyOrNullReturnsAuto() {
        assertEquals(GatewayType.AUTO, GatewayType.fromString(null));
        assertEquals(GatewayType.AUTO, GatewayType.fromString(""));
        assertEquals(GatewayType.AUTO, GatewayType.fromString("   "));
    }

    @Test
    void testFromString_InvalidThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> GatewayType.fromString("nginx"));
        assertThrows(IllegalArgumentException.class, () -> GatewayType.fromString("unknown"));
    }

    @Test
    void testGetValue() {
        assertEquals("traefik", GatewayType.TRAEFIK.getValue());
        assertEquals("k8s", GatewayType.K8S.getValue());
    }
}
