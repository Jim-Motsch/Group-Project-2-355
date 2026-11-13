package medvault.model;

import java.time.LocalDate;
import java.util.Objects;

/**
 * A patient chart.
 *
 * <p>Immutable so a chart handed to one layer cannot be changed behind the
 * back of another. Edits go through
 * {@link medvault.records.PatientRepository#update(Session, Patient)}.</p>
 */
public final class Patient {
    private final long id;
    private final String fullName;
    private final LocalDate dateOfBirth;
    private final String attendingClinician;
    private final String clinicalNotes;

    /**
     * Creates a patient chart.
     *
     * @param id                 database id
     * @param fullName           patient name (sensitive, never logged)
     * @param dateOfBirth        date of birth (sensitive, never logged)
     * @param attendingClinician username of the clinician who owns the chart
     * @param clinicalNotes      free-text notes (sensitive, encrypted at rest)
     */
    public Patient(long id, String fullName, LocalDate dateOfBirth,
                   String attendingClinician, String clinicalNotes) {
        this.id = id;
        this.fullName = Objects.requireNonNull(fullName, "fullName");
        this.dateOfBirth = Objects.requireNonNull(dateOfBirth, "dateOfBirth");
        this.attendingClinician = Objects.requireNonNull(attendingClinician, "attendingClinician");
        this.clinicalNotes = clinicalNotes == null ? "" : clinicalNotes;
    }

    /** @return database id */
    public long getId() {
        return id;
    }

    /** @return patient name */
    public String getFullName() {
        return fullName;
    }

    /** @return date of birth */
    public LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    /** @return username of the clinician who owns this chart */
    public String getAttendingClinician() {
        return attendingClinician;
    }

    /** @return clinical notes in plaintext */
    public String getClinicalNotes() {
        return clinicalNotes;
    }

    /**
     * Returns a copy with new notes.
     *
     * @param notes the replacement notes
     * @return a new {@code Patient} with the same id and owner
     */
    public Patient withNotes(String notes) {
        return new Patient(id, fullName, dateOfBirth, attendingClinician, notes);
    }

    /** Only the id, so a chart printed to a log never leaks PHI (CWE-779). */
    @Override
    public String toString() {
        return "Patient[id=" + id + "]";
    }
}
