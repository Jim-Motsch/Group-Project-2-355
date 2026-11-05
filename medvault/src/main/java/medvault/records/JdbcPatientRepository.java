package medvault.records;

import medvault.access.AccessPolicy;
import medvault.audit.AuditLogger;
import medvault.model.Patient;
import medvault.model.Session;
import medvault.security.CryptoService;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * JDBC implementation of {@link PatientRepository}.
 *
 * <p><b>CWE-89: SQL Injection.</b> Every query is a
 * {@link java.sql.PreparedStatement} with {@code ?} placeholders. User input
 * is never concatenated into SQL. A search for {@code ' OR 1=1 --} returns
 * nothing extra.</p>
 *
 * <p>Clinical notes are encrypted with {@link CryptoService} before insert
 * (CWE-327) and access is checked with {@link AccessPolicy} (CWE-639).</p>
 *
 * @author James Strickert
 */
public class JdbcPatientRepository implements PatientRepository {
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

    @Override
    public Patient add(Session session, Patient patient) {
        // TODO(James) CWE-89
        throw new UnsupportedOperationException("TODO(James): CWE-89");
    }

    @Override
    public Optional<Patient> findById(Session session, long id) {
        // TODO(James) CWE-89, then policy.requireCanRead(session, patient)
        throw new UnsupportedOperationException("TODO(James): CWE-89");
    }

    @Override
    public List<Patient> searchByName(Session session, String namePrefix) {
        // TODO(James) CWE-89: "SELECT ... WHERE full_name LIKE ?" with prefix + "%"
        //  (escape % and _ in the prefix), then filter by what the caller may read.
        throw new UnsupportedOperationException("TODO(James): CWE-89");
    }

    @Override
    public void update(Session session, Patient patient) {
        // TODO(James) CWE-89, after policy.requireCanEdit(session, patient)
        throw new UnsupportedOperationException("TODO(James): CWE-89");
    }
}
