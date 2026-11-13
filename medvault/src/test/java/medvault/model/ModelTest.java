package medvault.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/** Checks that model objects never print sensitive data (CWE-779). */
class ModelTest {

    @Test
    void patientToStringHidesPhi() {
        Patient p = new Patient(7, "Jane Doe", LocalDate.of(1990, 1, 2), "drsmith", "diabetic");
        assertEquals("Patient[id=7]", p.toString());
    }

    @Test
    void sessionToStringHidesToken() {
        Session s = new Session("secret-token-value", new User("nurse1", Role.NURSE), Instant.EPOCH);
        assertFalse(s.toString().contains("secret-token-value"));
    }

    @Test
    void withNotesKeepsOwner() {
        Patient p = new Patient(7, "Jane Doe", LocalDate.of(1990, 1, 2), "drsmith", "a");
        Patient q = p.withNotes("b");
        assertEquals("drsmith", q.getAttendingClinician());
        assertEquals("a", p.getClinicalNotes());
    }
}
