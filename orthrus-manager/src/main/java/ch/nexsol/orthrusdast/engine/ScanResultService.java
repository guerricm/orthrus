package ch.nexsol.orthrusdast.engine;

import ch.nexsol.orthrusdast.entity.ScanAttemptEntity;
import ch.nexsol.orthrusdast.entity.ScanResultEntity;
import ch.nexsol.orthrusdast.entity.VulnerabilityEntity;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.OwaspReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.repository.ScanAttemptRepository;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import tools.jackson.databind.ObjectMapper;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
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

	private final ScanAttemptRepository scanAttemptRepository;

	private final ScanJobRepository scanJobRepository;

	private final ObjectMapper objectMapper;

	public ScanResultService(ScanResultRepository scanResultRepository, VulnerabilityRepository vulnerabilityRepository,
			ScanAttemptRepository scanAttemptRepository, ScanJobRepository scanJobRepository,
			ObjectMapper objectMapper) {
		this.scanResultRepository = scanResultRepository;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.scanAttemptRepository = scanAttemptRepository;
		this.scanJobRepository = scanJobRepository;
		this.objectMapper = objectMapper;
	}

	public Mono<ScanResult> save(ScanResult result) {
		ScanResultEntity entity = new ScanResultEntity(result.id(), result.targetUrl(), result.scanStartTime(),
				result.scanEndTime(), result.operationsDiscovered(), result.operationsScanned());

		return scanResultRepository.save(entity).flatMap(savedEntity -> {
			if (result.vulnerabilities() == null || result.vulnerabilities().isEmpty()) {
				return Mono.just(result);
			}
			List<VulnerabilityEntity> vulnEntities = result.vulnerabilities()
				.stream()
				.map(v -> mapToEntity(v, savedEntity.id()))
				.toList();
			return vulnerabilityRepository.saveAll(vulnEntities).then(Mono.just(result));
		});
	}

	public Mono<Void> saveBatch(String resultId, List<ch.nexsol.orthrusdast.model.ScanAttempt> batch) {
		List<VulnerabilityEntity> vulnEntities = new java.util.ArrayList<>();
		List<ScanAttemptEntity> attemptEntities = new java.util.ArrayList<>();
		for (ch.nexsol.orthrusdast.model.ScanAttempt attempt : batch) {
			attemptEntities.add(new ScanAttemptEntity(null, resultId, attempt.scannerId(), attempt.scannerName(),
					attempt.operationMethod(), attempt.operationUrl(), attempt.status().name()));

			if (attempt.vulnerabilities() != null) {
				for (Vulnerability v : attempt.vulnerabilities()) {
					vulnEntities.add(mapToEntity(v, resultId));
				}
			}
		}

		Mono<Void> saveAttempts = attemptEntities.isEmpty() ? Mono.empty()
				: scanAttemptRepository.saveAll(attemptEntities).then();
		Mono<Void> saveVulns = vulnEntities.isEmpty() ? Mono.empty()
				: vulnerabilityRepository.saveAll(vulnEntities).then();

		return Mono.when(saveAttempts, saveVulns);
	}

	public Mono<Void> createPlaceholderResult(String resultId, String targetUrl, java.time.Instant startTime) {
		ScanResultEntity entity = new ScanResultEntity(resultId, targetUrl, startTime, null, 0, 0);
		// Only insert if it doesn't exist
		return scanResultRepository.findById(resultId).switchIfEmpty(scanResultRepository.save(entity)).then();
	}

	public Mono<ScanResult> finalizeJobResult(String resultId, String targetUrl, java.time.Instant startTime,
			java.time.Instant endTime, int testsCount) {
		return scanResultRepository.finalizeScanResult(resultId, endTime, testsCount)
			.defaultIfEmpty(0)
			.flatMap(rows -> {
				if (rows == 0) {
					ScanResultEntity entity = new ScanResultEntity(resultId, targetUrl, startTime, endTime, 0,
							testsCount);
					return scanResultRepository.save(entity)
						.onErrorResume(e -> Mono.empty()) // in case of race condition
															// duplicate key
						.then(findById(resultId));
				}
				return findById(resultId);
			});
	}

	public Mono<ScanResult> findById(String id) {
		return scanResultRepository.findById(id)
			.flatMap(entity -> Mono.zip(vulnerabilityRepository.findByScanResultId(id).collectList(),
					scanAttemptRepository.findByScanResultId(id).collectList(),
					scanJobRepository.findByResultId(id).map(job -> {
						try {
							return objectMapper.readValue(job.getScanConfigurationJson(), ScanConfiguration.class);
						}
						catch (Exception e) {
							return ScanConfiguration.defaults();
						}
					}).defaultIfEmpty(ScanConfiguration.defaults()))
				.map(tuple -> mapToDomain(entity, tuple.getT1(), tuple.getT2(), tuple.getT3())));
	}

	public Flux<ScanResult> findAll() {
		return scanResultRepository.findAll()
			.flatMap(entity -> Mono.zip(vulnerabilityRepository.findByScanResultId(entity.id()).collectList(),
					scanAttemptRepository.findByScanResultId(entity.id()).collectList(),
					scanJobRepository.findByResultId(entity.id()).map(job -> {
						try {
							return objectMapper.readValue(job.getScanConfigurationJson(), ScanConfiguration.class);
						}
						catch (Exception e) {
							return ScanConfiguration.defaults();
						}
					}).defaultIfEmpty(ScanConfiguration.defaults()))
				.map(tuple -> mapToDomain(entity, tuple.getT1(), tuple.getT2(), tuple.getT3())));
	}

	public Flux<ScanResult> getHistory(int page, int size) {
		return scanResultRepository
			.findAllByOrderByScanStartTimeDesc(org.springframework.data.domain.PageRequest.of(page, size))
			.flatMap(entity -> Mono.zip(vulnerabilityRepository.findByScanResultId(entity.id()).collectList(),
					scanAttemptRepository.findByScanResultId(entity.id()).collectList(),
					scanJobRepository.findByResultId(entity.id()).map(job -> {
						try {
							return objectMapper.readValue(job.getScanConfigurationJson(), ScanConfiguration.class);
						}
						catch (Exception e) {
							return ScanConfiguration.defaults();
						}
					}).defaultIfEmpty(ScanConfiguration.defaults()))
				.map(tuple -> mapToDomain(entity, tuple.getT1(), tuple.getT2(), tuple.getT3())));
	}

	private VulnerabilityEntity mapToEntity(Vulnerability v, String scanResultId) {
		return new VulnerabilityEntity(null, scanResultId, v.name(), v.description(),
				v.riskLevel() != null ? v.riskLevel().name() : null,
				v.confidence() != null ? v.confidence().name() : null, v.scannerId(), v.operationUrl(),
				v.operationMethod(), v.cwe() != null ? String.valueOf(v.cwe().getId()) : null,
				v.cwe() != null ? v.cwe().getName() : null, v.capecs() != null ? String.join(",", v.capecs()) : null,
				v.cvssScore(), v.evidence(), v.remediation(), v.requestDetails(), v.responseDetails(), v.attackVector(),
				v.technicalImpact());
	}

	private ScanResult mapToDomain(ScanResultEntity entity, List<VulnerabilityEntity> vulnEntities,
			List<ScanAttemptEntity> attemptEntities, ScanConfiguration configuration) {
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
				}
				catch (NumberFormatException ignored) {
				}
			}
			return new Vulnerability(java.util.UUID.randomUUID().toString(), ve.vulnerabilityTitle(),
					ve.vulnerabilityDescription(),
					ve.riskLevel() != null ? RiskLevel.valueOf(ve.riskLevel()) : RiskLevel.INFO,
					ve.confidence() != null ? Vulnerability.Confidence.valueOf(ve.confidence())
							: Vulnerability.Confidence.LOW,
					ve.scannerId(), ve.operationUrl(), ve.operationMethod(), cwe, Collections.emptyList(), // cves
					ve.capecIds() != null && !ve.capecIds().isEmpty() ? List.of(ve.capecIds().split(","))
							: Collections.emptyList(),
					ve.cvssBaseScore(), ve.evidence(), ve.recommendation(), ve.requestSummary(), ve.responseSummary(),
					ve.attackVector(), ve.technicalImpact());
		}).sorted(java.util.Comparator.comparing(Vulnerability::riskLevel).reversed()).toList();

		Map<RiskLevel, Long> riskSummary = vulnerabilities.stream()
			.collect(Collectors.groupingBy(Vulnerability::riskLevel, Collectors.counting()));

		Map<String, Integer> scannerSummary = vulnerabilities.stream()
			.collect(Collectors.groupingBy(Vulnerability::scannerId,
					Collectors.collectingAndThen(Collectors.counting(), Long::intValue)));

		List<ch.nexsol.orthrusdast.model.ScanAttempt> attempts = attemptEntities.stream().map(ae -> {
			List<Vulnerability> relatedVulns = vulnerabilities.stream()
				.filter(v -> v.scannerId().equals(ae.scannerId()) && v.operationMethod().equals(ae.operationMethod())
						&& v.operationUrl().equals(ae.operationUrl()))
				.toList();
			return new ch.nexsol.orthrusdast.model.ScanAttempt(ae.scannerId(), ae.scannerName(), ae.operationMethod(),
					ae.operationUrl(), ch.nexsol.orthrusdast.model.AttemptStatus.valueOf(ae.status()), relatedVulns);
		}).toList();

		return new ScanResult(entity.id(), entity.targetUrl(), entity.scanStartTime(), entity.scanEndTime(),
				entity.operationsDiscovered(), entity.operationsScanned(), vulnerabilities, riskSummary, scannerSummary,
				configuration, attempts, "UNKNOWN" // discovererId omitted from DB
		);
	}

}
