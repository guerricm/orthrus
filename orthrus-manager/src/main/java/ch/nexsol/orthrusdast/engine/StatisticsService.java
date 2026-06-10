package ch.nexsol.orthrusdast.engine;

import ch.nexsol.orthrusdast.repository.ScanResultRepository;
import ch.nexsol.orthrusdast.repository.VulnerabilityRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ch.nexsol.orthrusdast.entity.ScanResultEntity;
import ch.nexsol.orthrusdast.entity.VulnerabilityEntity;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;

@Service
public class StatisticsService {

	private final ScanResultRepository scanResultRepository;

	private final VulnerabilityRepository vulnerabilityRepository;

	public StatisticsService(ScanResultRepository scanResultRepository,
			VulnerabilityRepository vulnerabilityRepository) {
		this.scanResultRepository = scanResultRepository;
		this.vulnerabilityRepository = vulnerabilityRepository;
	}

	public Mono<Map<String, Map<String, Map<String, Long>>>> getEvolutionByTargetAndEndpoint() {
		return scanResultRepository.findAll().collectList().flatMap(scans -> {
			scans.sort((s1, s2) -> s1.scanStartTime().compareTo(s2.scanStartTime()));

			return Flux.fromIterable(scans)
				.flatMapSequential(
						scan -> vulnerabilityRepository.findByScanResultId(scan.id()).collectList().map(vulns -> {
							Map<String, Long> endpointCounts = vulns.stream()
								.filter(v -> v.operationMethod() != null && v.operationUrl() != null)
								.collect(Collectors.groupingBy(v -> v.operationMethod() + " " + v.operationUrl(),
										Collectors.counting()));
							return Map.entry(scan, endpointCounts);
						}))
				.collectList()
				.map(scanEntries -> {
					Map<String, Map<String, Map<String, Long>>> result = new HashMap<>();

					for (Map.Entry<ScanResultEntity, Map<String, Long>> scanEntry : scanEntries) {
						ScanResultEntity scan = scanEntry.getKey();
						String targetUrl = scan.targetUrl() != null ? scan.targetUrl() : "Unknown Target";
						String scanId = scan.id();
						Map<String, Long> endpoints = scanEntry.getValue();

						Map<String, Map<String, Long>> targetMap = result.computeIfAbsent(targetUrl,
								k -> new HashMap<>());

						for (Map.Entry<String, Long> endpointEntry : endpoints.entrySet()) {
							String endpoint = endpointEntry.getKey();
							Long count = endpointEntry.getValue();

							targetMap.computeIfAbsent(endpoint, k -> new LinkedHashMap<>()).put(scanId, count);
						}
					}
					return result;
				});
		});
	}

	public record GlobalScanSummary(String scanId, String targetUrl, Instant startTime, Map<String, Long> vulnsByRisk,
			Map<String, Long> vulnsByCwe, long totalVulns) {
	}

	public Mono<List<GlobalScanSummary>> getGlobalStatistics() {
		return scanResultRepository.findAll().collectList().flatMap(scans -> {
			scans.sort((s1, s2) -> s2.scanStartTime().compareTo(s1.scanStartTime()));

			return Flux.fromIterable(scans)
				.flatMapSequential(
						scan -> vulnerabilityRepository.findByScanResultId(scan.id()).collectList().map(vulns -> {
							Map<String, Long> byRisk = vulns.stream()
								.filter(v -> v.riskLevel() != null)
								.collect(Collectors.groupingBy(VulnerabilityEntity::riskLevel, Collectors.counting()));

							Map<String, Long> byCwe = vulns.stream()
								.filter(v -> v.cweId() != null)
								.collect(Collectors.groupingBy(VulnerabilityEntity::cweId, Collectors.counting()));

							return new GlobalScanSummary(scan.id(),
									scan.targetUrl() != null ? scan.targetUrl() : "Unknown Target",
									scan.scanStartTime(), byRisk, byCwe, vulns.size());
						}))
				.collectList();
		});
	}

}
