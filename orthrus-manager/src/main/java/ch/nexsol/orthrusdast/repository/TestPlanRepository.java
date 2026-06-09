package ch.nexsol.orthrusdast.repository;

import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TestPlanRepository extends R2dbcRepository<TestPlanEntity, Long> {
}
