package ch.nexsol.orthrusdast.model;

import java.util.List;

public record EndpointAttemptGroup(
        String endpoint,
        List<ScanAttempt> attempts,
        long passed,
        long failed,
        long authError,
        long error
) {}
