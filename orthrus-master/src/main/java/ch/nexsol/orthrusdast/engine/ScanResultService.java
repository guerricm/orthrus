package ch.nexsol.orthrusdast.engine;

import ch.nexsol.orthrusdast.entity.ScanResultEntity;
import ch.nexsol.orthrusdast.entity.VulnerabilityEntity;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.OwaspReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.repository.ScanResultRepository;
import ch.nexsol.orthrusdast.repository.VulnerabilityRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.stream.Collectors;

@Service
public class ScanResultService {

    private final ScanResultRepository scanResultRepository;
    private final VulnerabilityRepository vulnerabilityRepository;

    public ScanResultService(ScanResultRepository scanResultRepository, VulnerabilityRepository vulnerabilityRepository) {
        this.scanResultRepository = scanResultRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    public Mono<ScanResult> save(ScanResult result) {
        ScanResultEntity entity = new ScanResultEntity(
                result.id(),
                result.targetUrl(),
                result.scanStartTime(),
                result.scanEndTime(),
                result.operationsDiscovered(),
                result.operationsScanned()
        );

        return scanResultRepository.save(entity)
                .flatMap(savedEntity -> {
                    if (result.vulnerabilities() == null || result.vulnerabilities().isEmpty()) {
                        return Mono.just(result);
                    }
                    List<VulnerabilityEntity> vulnEntities = result.vulnerabilities().stream()
                            .map(v -> mapToEntity(v, savedEntity.id()))
                            .toList();
                    return vulnerabilityRepository.saveAll(vulnEntities).then(Mono.just(result));
                });
    }

    public Mono<ScanResult> findById(String id) {
        return scanResultRepository.findById(id)
                .flatMap(entity -> vulnerabilityRepository.findByScanResultId(id)
                        .collectList()
                        .map(vulnEntities -> mapToDomain(entity, vulnEntities)));
    }

    public Flux<ScanResult> findAll() {
        return scanResultRepository.findAll()
                .flatMap(entity -> vulnerabilityRepository.findByScanResultId(entity.id())
                        .collectList()
                        .map(vulnEntities -> mapToDomain(entity, vulnEntities)));
    }

    public Flux<ScanResult> getHistory(int page, int size) {
        return scanResultRepository.findAllByOrderByScanStartTimeDesc(org.springframework.data.domain.PageRequest.of(page, size))
                .flatMap(entity -> vulnerabilityRepository.findByScanResultId(entity.id())
                        .collectList()
                        .map(vulnEntities -> mapToDomain(entity, vulnEntities)));
    }

    private VulnerabilityEntity mapToEntity(Vulnerability v, String scanResultId) {
        return new VulnerabilityEntity(
                null,
                scanResultId,
                v.name(),
                v.description(),
                v.riskLevel() != null ? v.riskLevel().name() : null,
                v.confidence() != null ? v.confidence().name() : null,
                v.scannerId(),
                v.operationUrl(),
                v.operationMethod(),
                v.cwe() != null ? String.valueOf(v.cwe().getId()) : null,
                v.cwe() != null ? v.cwe().getName() : null,
                v.capecs() != null ? String.join(",", v.capecs()) : null,
                v.cvssScore(),
                v.evidence(),
                v.remediation(),
                v.requestDetails(),
                v.responseDetails(),
                v.attackVector(),
                v.technicalImpact()
        );
    }

    private ScanResult mapToDomain(ScanResultEntity entity, List<VulnerabilityEntity> vulnEntities) {
        List<Vulnerability> vulnerabilities = vulnEntities.stream().map(ve -> {
            CWEReference cwe = null;
            if (ve.cweId() != null) {
                try {
                    int cweId = Integer.parseInt(ve.cweId());
                    for (CWEReference ref : CWEReference.values()) {
                        if (ref.getId() == cweId) {
                            cwe = ref;
                            break;
                        }
                    }
                } catch (NumberFormatException ignored) {}
            }
            return new Vulnerability(
                    java.util.UUID.randomUUID().toString(),
                    ve.vulnerabilityTitle(),
                    ve.vulnerabilityDescription(),
                    ve.riskLevel() != null ? RiskLevel.valueOf(ve.riskLevel()) : RiskLevel.INFO,
                    ve.confidence() != null ? Vulnerability.Confidence.valueOf(ve.confidence()) : Vulnerability.Confidence.LOW,
                    ve.scannerId(),
                    ve.operationUrl(),
                    ve.operationMethod(),
                    cwe,
                    Collections.emptyList(), // cves
                    ve.capecIds() != null && !ve.capecIds().isEmpty() ? List.of(ve.capecIds().split(",")) : Collections.emptyList(),
                    ve.cvssBaseScore(),
                    ve.evidence(),
                    ve.recommendation(),
                    ve.requestSummary(),
                    ve.responseSummary(),
                    ve.attackVector(),
                    ve.technicalImpact()
            );
        }).toList();

        Map<RiskLevel, Long> riskSummary = vulnerabilities.stream()
                .collect(Collectors.groupingBy(Vulnerability::riskLevel, Collectors.counting()));

        Map<String, Integer> scannerSummary = vulnerabilities.stream()
                .collect(Collectors.groupingBy(Vulnerability::scannerId, Collectors.collectingAndThen(Collectors.counting(), Long::intValue)));

        return new ScanResult(
                entity.id(),
                entity.targetUrl(),
                entity.scanStartTime(),
                entity.scanEndTime(),
                entity.operationsDiscovered(),
                entity.operationsScanned(),
                vulnerabilities,
                riskSummary,
                scannerSummary,
                null, // configuration omitted from DB for simplicity for now
                Collections.emptyList() // attempts omitted
        );
    }
}
