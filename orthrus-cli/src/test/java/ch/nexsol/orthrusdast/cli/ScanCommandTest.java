package ch.nexsol.orthrusdast.cli;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.engine.ScanService;
import ch.nexsol.orthrusdast.report.ReportGenerator;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import reactor.core.publisher.Flux;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class ScanCommandTest {

    @Test
    void testCallWithValidParameters() throws Exception {
        ScanService scanService = Mockito.mock(ScanService.class);
        when(scanService.executeScan(anyString(), any(), any()))
                .thenReturn(reactor.core.publisher.Flux.empty());

        ReportGenerator mockGenerator = Mockito.mock(ReportGenerator.class);
        when(mockGenerator.getFormat()).thenReturn("json");
        when(mockGenerator.generateReport(any(), any(), org.mockito.ArgumentMatchers.anyBoolean())).thenReturn(reactor.core.publisher.Mono.empty());

        OAuth2TokenFetcher mockFetcher = Mockito.mock(OAuth2TokenFetcher.class);

        ScanCommand command = new ScanCommand(scanService, List.of(mockGenerator), mockFetcher);
        
        command.discovererId = "openapi";
        command.target = "http://localhost:8080/v3/api-docs";
        command.format = "json";
        
        Integer result = command.call();
        assertEquals(0, result);
    }
}
