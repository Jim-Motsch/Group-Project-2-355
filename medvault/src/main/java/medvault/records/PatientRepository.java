package medvault.records;

import medvault.model.Patient;
import medvault.model.Session;

import java.util.List;
import java.util.Optional;

/**
 * Reads and writes patient charts. Every method takes the caller's
 * {@link Session} and checks it through {@link medvault.access.AccessPolicy}.
 *
 * @author James Strickert
 */
public interface PatientRepository {

    /**
     * @param session caller
     * @param patient new chart (id ignored)
     * @return the saved chart with its id
     */
    Patient add(Session session, Patient patient);

    /**
     * @param session caller
     * @param id      chart id
     * @return the chart, if it exists and the caller may read it
     */
    Optional<Patient> findById(Session session, long id);

    /**
     * Searches by name.
     *
     * @param session    caller
     * @param namePrefix untrusted search text
     * @return charts the caller may read whose name starts with {@code namePrefix}
     */
    List<Patient> searchByName(Session session, String namePrefix);

    /**
     * @param session caller, must be the attending clinician
     * @param patient updated chart
     */
    void update(Session session, Patient patient);
}
