package medvault.access;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory {@link CareTeam}.
 *
 * @author Martin Stoilkov
 */
public class InMemoryCareTeam implements CareTeam {
    private final Map<Long, Set<String>> members = new ConcurrentHashMap<>();

    @Override
    public Set<String> membersFor(long patientId) {
        return Collections.unmodifiableSet(members.getOrDefault(patientId, Set.of()));
    }

    @Override
    public void assign(long patientId, String username) {
        members.computeIfAbsent(patientId, id -> ConcurrentHashMap.newKeySet()).add(username);
    }
}
