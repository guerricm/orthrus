package ch.nexsol.orthrusdast.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum GatewayType {
    AUTO("auto"),
    TRAEFIK("traefik"),
    SPRING_CLOUD_GATEWAY("spring-cloud-gateway"),
    KONG("kong"),
    HAPROXY("haproxy"),
    K8S("k8s");

    private final String value;

    GatewayType(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    @JsonCreator
    public static GatewayType fromString(String value) {
        if (value == null || value.isBlank()) {
            return AUTO;
        }
        for (GatewayType type : GatewayType.values()) {
            if (type.value.equalsIgnoreCase(value.trim()) || type.name().equalsIgnoreCase(value.trim())) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown GatewayType: " + value);
    }
}
