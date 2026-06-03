package ch.hug.orthrusdast.model;

import java.util.List;

public record EndpointAttemptGroup(
        String displayName,
        List<ScanAttempt> attempts,
        long passedCount,
        long failedCount
) {}
