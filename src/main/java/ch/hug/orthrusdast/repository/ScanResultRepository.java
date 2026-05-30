package ch.hug.orthrusdast.repository;

import ch.hug.orthrusdast.model.ScanResult;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory repository for storing ScanResults temporarily.
 * Used primarily for the web UI to retrieve results for PDF export after scanning.
 */
@Repository
public class ScanResultRepository {

    private final ConcurrentHashMap<String, ScanResult> store = new ConcurrentHashMap<>();

    public void save(ScanResult result) {
        if (result != null && result.id() != null) {
            store.put(result.id(), result);
        }
    }

    public Optional<ScanResult> findById(String id) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(store.get(id));
    }
    
    public java.util.List<ScanResult> findAll() {
        return new java.util.ArrayList<>(store.values());
    }
    
    public void delete(String id) {
        if (id != null) {
            store.remove(id);
        }
    }
}
