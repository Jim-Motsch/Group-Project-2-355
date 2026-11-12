package medvault.records;

import medvault.access.AccessPolicy;
import medvault.access.Permission;
import medvault.audit.AuditLogger;
import medvault.model.AccessDeniedException;
import medvault.model.Patient;
import medvault.model.Session;
import medvault.model.ValidationException;
import medvault.security.CryptoService;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * JDBC implementation of {@link PatientRepository}.
 *
 * <p><b>CWE-89: SQL Injection.</b> Every query is a
 * {@link java.sql.PreparedStatement} with {@code ?} placeholders, so the
 * driver sends user input as data and it can never change the shape of the
 * query. User input is never concatenated into SQL. A search for
 * {@code ' OR 1=1 --} looks for a patient literally named that and returns
 * nothing extra. In the name search, the LIKE wildcards {@code %} and
 * {@code _} (and the escape character) in the user's text are escaped, so
 * searching for {@code %} does not list every patient.</p>
 *
 * <p>Clinical notes are encrypted with {@link CryptoService} before insert
 * (AES-GCM with a fresh IV, CWE-1204) and access is checked with
 * {@link AccessPolicy} before any chart is returned or changed (CWE-306,
 * CWE-639, CWE-283). Every connection, statement and result set is closed
 * with try-with-resources (CWE-772). Database errors are rethrown with a
 * fixed message, never the SQL or the driver's text, and the audit trail
 * records patient ids only, never names, search text or notes
 * (CWE-779).</p>
 *
 * @author James Strickert
 */
public class JdbcPatientRepository implements PatientRepository {

    /** Most charts one search returns, so a one-letter search can't dump the table. */
    static final int MAX_SEARCH_RESULTS = 50;
    static final int MAX_NAME_LENGTH = 200;
    static final int MAX_ATTENDING_LENGTH = 100;

    private static final String COLUMNS = "id, full_name, date_of_birth, attending, notes_encrypted";
    private static final String INSERT =
            "INSERT INTO patient (full_name, date_of_birth, attending, notes_encrypted) VALUES (?, ?, ?, ?)";
    private static final String SELECT_BY_ID = "SELECT " + COLUMNS + " FROM patient WHERE id = ?";
    private static final String SEARCH =
            "SELECT " + COLUMNS + " FROM patient WHERE full_name LIKE ? ESCAPE '\\' ORDER BY id";
    private static final String UPDATE =
            "UPDATE patient SET full_name = ?, date_of_birth = ?, notes_encrypted = ? WHERE id = ? AND attending = ?";

    private final Database db;
    private final CryptoService crypto;
    private final AccessPolicy policy;
    private final AuditLogger audit;

    /**
     * @param db     connection source
     * @param crypto field encryption
     * @param policy access checks
     * @param audit  audit trail
     */
    public JdbcPatientRepository(Database db, CryptoService crypto, AccessPolicy policy, AuditLogger audit) {
        this.db = Objects.requireNonNull(db, "db");
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    /**
     * {@inheritDoc}
     *
     * <p>Needs {@link Permission#EDIT_CHART}, and the new chart must name the
     * caller as attending clinician, so nobody can create a chart owned by
     * someone else (CWE-283).</p>
     */
    @Override
    public Patient add(Session session, Patient patient) {
        Objects.requireNonNull(patient, "patient");
        Session live = policy.requireSession(session, Permission.EDIT_CHART);
        if (!live.getUser().getUsername().equals(patient.getAttendingClinician())) {
            audit.record(live.getUser(), "ACCESS_DENIED", "permission=EDIT_CHART reason=create_for_other");
            throw new AccessDeniedException("New charts must list you as the attending clinician.");
        }
        validate(patient);
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, patient.getFullName());
            ps.setDate(2, Date.valueOf(patient.getDateOfBirth()));
            ps.setString(3, patient.getAttendingClinician());
            ps.setString(4, crypto.encrypt(patient.getClinicalNotes()));
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (!keys.next()) {
                    throw new IllegalStateException("database did not return a chart id");
                }
                long id = keys.getLong(1);
                audit.record(live.getUser(), "CHART_CREATED", "patient=" + id);
                return new Patient(id, patient.getFullName(), patient.getDateOfBirth(),
                        patient.getAttendingClinician(), patient.getClinicalNotes());
            }
        } catch (SQLException e) {
            throw databaseError(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws AccessDeniedException if the chart exists but the caller is not on its care team
     */
    @Override
    public Optional<Patient> findById(Session session, long id) {
        // Authenticate before touching the database, so anonymous callers can't probe ids.
        Session live = policy.requireSession(session, Permission.READ_CHART);
        Optional<Patient> found = load(id);
        if (found.isPresent()) {
            policy.requireCanRead(session, found.get()); // CWE-639: must be on this patient's team
            audit.record(live.getUser(), "CHART_READ", "patient=" + id);
        }
        return found;
    }

    @Override
    public List<Patient> searchByName(Session session, String namePrefix) {
        Session live = policy.requireSession(session, Permission.READ_CHART);
        if (namePrefix == null || namePrefix.length() > MAX_NAME_LENGTH) {
            throw new ValidationException("Search text must be at most " + MAX_NAME_LENGTH + " characters.");
        }
        List<Patient> visible = new ArrayList<>();
        try (Connection c = db.connect(); PreparedStatement ps = c.prepareStatement(SEARCH)) {
            ps.setString(1, escapeLike(namePrefix) + "%");
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next() && visible.size() < MAX_SEARCH_RESULTS) {
                    Patient p = map(rs);
                    if (policy.canRead(session, p)) { // only charts the caller is assigned to
                        visible.add(p);
                    }
                }
            }
        } catch (SQLException e) {
            throw databaseError(e);
        }
        // Never log the search text: it is usually a patient's name.
        audit.record(live.getUser(), "CHART_SEARCH", "results=" + visible.size());
        return visible;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Ownership is checked against the chart <em>as stored</em>, never the
     * object the client sent, and the attending clinician cannot be changed
     * here (CWE-283).</p>
     */
    @Override
    public void update(Session session, Patient patient) {
        Objects.requireNonNull(patient, "patient");
        Session live = policy.requireSession(session, Permission.EDIT_CHART);
        Patient stored = load(patient.getId())
                .orElseThrow(() -> new ValidationException("No such chart."));
        policy.requireCanEdit(session, stored);
        if (!stored.getAttendingClinician().equals(patient.getAttendingClinician())) {
            throw new ValidationException("The attending clinician can't be changed by editing the chart.");
        }
        validate(patient);
        try (Connection c = db.connect(); PreparedStatement ps = c.prepareStatement(UPDATE)) {
            ps.setString(1, patient.getFullName());
            ps.setDate(2, Date.valueOf(patient.getDateOfBirth()));
            ps.setString(3, crypto.encrypt(patient.getClinicalNotes()));
            ps.setLong(4, stored.getId());
            ps.setString(5, stored.getAttendingClinician());
            if (ps.executeUpdate() != 1) {
                throw new ValidationException("The chart changed while you were editing it. Please reload.");
            }
        } catch (SQLException e) {
            throw databaseError(e);
        }
        audit.record(live.getUser(), "CHART_EDITED", "patient=" + stored.getId());
    }

    /** Reads one chart with no access check; callers check access first. */
    private Optional<Patient> load(long id) {
        try (Connection c = db.connect(); PreparedStatement ps = c.prepareStatement(SELECT_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(map(rs)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw databaseError(e);
        }
    }

    private Patient map(ResultSet rs) throws SQLException {
        String sealed = rs.getString("notes_encrypted");
        return new Patient(rs.getLong("id"), rs.getString("full_name"),
                rs.getDate("date_of_birth").toLocalDate(), rs.getString("attending"),
                sealed == null ? "" : crypto.decrypt(sealed));
    }

    private static void validate(Patient p) {
        if (p.getFullName().isBlank() || p.getFullName().length() > MAX_NAME_LENGTH) {
            throw new ValidationException("Patient name must be 1-" + MAX_NAME_LENGTH + " characters.");
        }
        if (p.getAttendingClinician().isBlank() || p.getAttendingClinician().length() > MAX_ATTENDING_LENGTH) {
            throw new ValidationException("Attending clinician is invalid.");
        }
    }

    /**
     * Escapes the LIKE wildcards so user text matches literally. The escape
     * character itself is escaped first.
     *
     * @param text untrusted search text
     * @return text safe to use as a LIKE prefix with {@code ESCAPE '\'}
     */
    static String escapeLike(String text) {
        return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    /** No SQL, table names or driver text in the message. */
    private static IllegalStateException databaseError(SQLException e) {
        return new IllegalStateException("database error", e);
    }
}
