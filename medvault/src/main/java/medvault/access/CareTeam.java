package medvault.access;

import java.util.Set;

/**
 * Which clinicians are assigned to which patients. Used to decide whether a
 * user may open a given chart.
 *
 * @author Martin Stoilkov
 */
public interface CareTeam {

    /**
     * @param patientId a chart id
     * @return usernames assigned to that patient (attending doctor and nurses)
     */
    Set<String> membersFor(long patientId);

    /**
     * @param patientId a chart id
     * @param username  clinician to assign
     */
    void assign(long patientId, String username);
}
