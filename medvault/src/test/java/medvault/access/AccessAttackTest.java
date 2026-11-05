package medvault.access;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Attack tests for the access package. Each test is the target behavior for one
 * CWE. Remove {@code @Disabled} as you implement it; by integration day
 * (Nov 8) none should be disabled.
 *
 * @author Martin Stoilkov
 */
class AccessAttackTest {

    @Test
    @Disabled("TODO(Martin): CWE-306")
    void forgedSessionIsRejected() {
        // a Session object not issued by SessionManager -> AccessDeniedException
    }

    @Test
    @Disabled("TODO(Martin): CWE-639")
    void nurseCannotOpenUnassignedChart() {
        // nurse on patient 1 care team calls requireCanRead for patient 2 -> denied
    }

    @Test
    @Disabled("TODO(Martin): CWE-283")
    void onlyAttendingClinicianCanEdit() {
        // nurse on the care team calls requireCanEdit -> denied; attending doctor -> allowed
    }

    @Test
    @Disabled("TODO(Martin): CWE-1220")
    void adminCannotReadCharts() {
        // ADMIN has MANAGE_USERS but require(READ_CHART) -> denied
    }

    @Test
    @Disabled("TODO(Martin): CWE-269")
    void userCannotChangeOwnRole() {
        // nurse calls changeRole(self, ADMIN) -> denied
    }

    @Test
    @Disabled("TODO(Martin): CWE-842")
    void roleChangeIsValidatedServerSide() {
        // the team decides the rule, e.g. NURSE -> ADMIN needs a second admin
    }
}
