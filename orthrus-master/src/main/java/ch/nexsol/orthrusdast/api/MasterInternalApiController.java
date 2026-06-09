package ch.nexsol.orthrusdast.api;

import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

@RestController
@RequestMapping("/api/internal")
public class MasterInternalApiController {

	private final SlaveNodeRepository slaveNodeRepository;

	private final ScanJobRepository scanJobRepository;

	private final ScanResultService scanResultService;

	private final JobEventPublisher jobEventPublisher;

	public MasterInternalApiController(SlaveNodeRepository slaveNodeRepository, ScanJobRepository scanJobRepository,
			ScanResultService scanResultService, JobEventPublisher jobEventPublisher) {
		this.slaveNodeRepository = slaveNodeRepository;
		this.scanJobRepository = scanJobRepository;
		this.scanResultService = scanResultService;
		this.jobEventPublisher = jobEventPublisher;
	}

	/**
	 * Called by Slave to register its presence.
	 */
	@PostMapping("/slaves/register")
	public Mono<ResponseEntity<SlaveNodeEntity>> registerSlave(@RequestBody SlaveRegistrationRequest request) {
		SlaveNodeEntity node = new SlaveNodeEntity(request.id(), request.url(), NodeStatus.IDLE);
		return slaveNodeRepository.findById(node.getId())
			.flatMap(existing -> slaveNodeRepository
				.updateSlaveNodeUrlStatusAndLastSeenAt(node.getId(), node.getUrl(), node.getStatus().name(),
						node.getLastSeenAt())
				.then(failZombieScansForSlave(node.getId()))
				.thenReturn(ResponseEntity.ok(node)))
			.switchIfEmpty(Mono.defer(() -> slaveNodeRepository
				.insertSlaveNode(node.getId(), node.getUrl(), node.getStatus(), node.getLastSeenAt())
				.thenReturn(ResponseEntity.ok(node))));
	}

	private Mono<Void> failZombieScansForSlave(String slaveId) {
		return scanJobRepository.findByAssignedSlaveIdAndStatus(slaveId, JobStatus.RUNNING).flatMap(job -> {
			System.out.println("Failing zombie job " + job.getId() + " because slave " + slaveId + " re-registered.");
			job.setStatus(JobStatus.FAILED);
			return scanJobRepository.save(job)
				.doOnSuccess(j -> jobEventPublisher.emit(j.getId(),
						JobEvent.failed(j.getId(), j.getTarget(), "Slave node restarted")));
		}).then();
	}

	/**
	 * Called by Slave to send a heartbeat.
	 */
	@PostMapping("/slaves/{id}/heartbeat")
	public Mono<ResponseEntity<Void>> slaveHeartbeat(@PathVariable String id,
			@RequestParam(defaultValue = "IDLE") NodeStatus status) {
		return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(id, status.name(), Instant.now())
			.flatMap(rows -> {
				if (rows == 0) {
					return Mono.just(ResponseEntity.notFound().build());
				}
				return Mono.just(ResponseEntity.ok().<Void>build());
			});
	}

	/**
	 * Called by Slave to post a batch of attempts.
	 */
	@PostMapping("/jobs/{id}/attempts")
	public Mono<ResponseEntity<Void>> postJobAttemptsBatch(@PathVariable Long id,
			@RequestBody java.util.List<ch.nexsol.orthrusdast.model.ScanAttempt> batch) {
		return scanJobRepository.findById(id).flatMap(job -> {
			Mono<Void> ensureResultExists = Mono.empty();
			if (job.getResultId() == null) {
				job.setResultId(java.util.UUID.randomUUID().toString());
				ensureResultExists = scanResultService.createPlaceholderResult(job.getResultId(), job.getTarget(),
						job.getCreatedAt() != null ? job.getCreatedAt() : Instant.now());
			}

			int vulnsInBatch = 0;
			for (ch.nexsol.orthrusdast.model.ScanAttempt attempt : batch) {
				if (attempt.vulnerabilities() != null) {
					vulnsInBatch += attempt.vulnerabilities().size();
				}
			}

			job.setTestsCount((job.getTestsCount() != null ? job.getTestsCount() : 0) + batch.size());
			job.setVulnsCount((job.getVulnsCount() != null ? job.getVulnsCount() : 0) + vulnsInBatch);

			return ensureResultExists.then(scanResultService.saveBatch(job.getResultId(), batch))
				.then(scanJobRepository.save(job))
				.thenReturn(ResponseEntity.ok().<Void>build());
		}).defaultIfEmpty(ResponseEntity.notFound().build());
	}

	record CompleteJobRequest(Instant startTime, Instant endTime) {
	}

	/**
	 * Called by Slave to mark job as complete.
	 */
	@PostMapping("/jobs/{id}/complete")
	public Mono<ResponseEntity<Void>> postJobComplete(@PathVariable Long id, @RequestBody CompleteJobRequest request) {
		return scanJobRepository.findById(id).flatMap(job -> {
			job.setStatus(JobStatus.COMPLETED);
			job.setCompletedAt(request.endTime() != null ? request.endTime() : Instant.now());

			Mono<Void> ensureResultExists = Mono.empty();
			if (job.getResultId() == null) {
				job.setResultId(java.util.UUID.randomUUID().toString());
				ensureResultExists = scanResultService.createPlaceholderResult(job.getResultId(), job.getTarget(),
						request.startTime() != null ? request.startTime() : Instant.now());
			}

			int testsCount = job.getTestsCount() != null ? job.getTestsCount() : 0;

			return ensureResultExists
				.then(scanResultService.finalizeJobResult(job.getResultId(), job.getTarget(), request.startTime(),
						job.getCompletedAt(), testsCount))
				.flatMap(result -> scanJobRepository.save(job).doOnSuccess(j -> {
					long critical = result.riskSummary().getOrDefault(RiskLevel.CRITICAL, 0L);
					long high = result.riskSummary().getOrDefault(RiskLevel.HIGH, 0L);
					long medium = result.riskSummary().getOrDefault(RiskLevel.MEDIUM, 0L);
					long low = result.riskSummary().getOrDefault(RiskLevel.LOW, 0L);
					String grade = "A";
					if (critical > 0)
						grade = "F";
					else if (high > 0)
						grade = "D";
					else if (medium > 0)
						grade = "C";
					else if (low > 0)
						grade = "B";

					long info = result.riskSummary().getOrDefault(RiskLevel.INFO, 0L);

					jobEventPublisher.emit(id,
							JobEvent.completed(id, job.getTarget(), result.id(), grade, result.vulnerabilities().size(),
									critical, high, medium, low, info, result.operationsScanned()));
					jobEventPublisher.complete(id);

					if (job.getAssignedSlaveId() != null) {
						slaveNodeRepository.findById(job.getAssignedSlaveId())
							.flatMap(slave -> scanJobRepository
								.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
								.flatMap(runningCount -> {
									if (runningCount < slave.getMaxConcurrentScans()) {
										return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(slave.getId(),
												NodeStatus.IDLE.name(), slave.getLastSeenAt());
									}
									return Mono.empty();
								}))
							.subscribe();
					}
				}));
		}).map(j -> ResponseEntity.ok().<Void>build()).defaultIfEmpty(ResponseEntity.notFound().build());
	}

	record FailJobRequest(String reason) {
	}

	@PostMapping("/jobs/{id}/fail")
	public Mono<ResponseEntity<Void>> postJobFail(@PathVariable Long id, @RequestBody FailJobRequest request) {
		return scanJobRepository.findById(id).flatMap(job -> {
			job.setStatus(JobStatus.FAILED);
			return scanJobRepository.save(job).doOnSuccess(j -> {
				jobEventPublisher.emit(id, JobEvent.failed(id, job.getTarget(), request.reason()));
				jobEventPublisher.complete(id);
				if (job.getAssignedSlaveId() != null) {
					slaveNodeRepository.findById(job.getAssignedSlaveId())
						.flatMap(slave -> scanJobRepository
							.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
							.flatMap(runningCount -> {
								if (runningCount < slave.getMaxConcurrentScans()) {
									return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(slave.getId(),
											NodeStatus.IDLE.name(), slave.getLastSeenAt());
								}
								return Mono.empty();
							}))
						.subscribe();
				}
			});
		}).map(j -> ResponseEntity.ok().<Void>build()).defaultIfEmpty(ResponseEntity.notFound().build());
	}

	public record SlaveRegistrationRequest(String id, String url) {
	}

}
