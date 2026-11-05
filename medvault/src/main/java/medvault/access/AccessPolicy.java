package medvault.access;

import medvault.audit.AuditLogger;
import medvault.auth.SessionManager;
import medvault.model.AccessDeniedException;
import medvault.model.Patient;
import medvault.model.Session;

import java.util.Objects;

/**
 * The one place every service asks "may this session do this?".
 *
 * <p><b>CWE-306: Missing Authentication for Critical Function.</b> Every
 * check starts by re-validating the session token with
 * {@link SessionManager}; a forged or expired {@link Session} is refused.</p>
 *
 * <p><b>CWE-639: Authorization Bypass Through User-Controlled Key.</b> Having
 * {@link Permission#READ_CHART} is not enough. The user must also be on the
 * patient's {@link CareTeam}, so changing the patient id in a request does
 * not open someone else's chart.</p>
 *
 * <p><b>CWE-283: Unverified Ownership.</b> Editing a chart requires being its
 * attending clinician, not just a member of the care team.</p>
 *
 * @author Martin Stoilkov
 */
public class AccessPolicy {
    private final SessionManager sessions;
    private final CareTeam careTeam;
    private final AuditLogger audit;

    /**
     * @param sessions validates tokens (CWE-306)
     * @param careTeam patient assignments (CWE-639)
     * @param audit    records every denial
     */
    public AccessPolicy(SessionManager sessions, CareTeam careTeam, AuditLogger audit) {
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.careTeam = Objects.requireNonNull(careTeam, "careTeam");
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    /**
     * @param session    caller's session
     * @param permission action being attempted
     * @throws AccessDeniedException if the session is invalid or lacks the permission
     */
    public void require(Session session, Permission permission) {
        // TODO(Martin) CWE-306 / CWE-1220
        throw new UnsupportedOperationException("TODO(Martin): CWE-306, CWE-1220");
    }

    /**
     * @param session caller's session
     * @param patient chart being opened
     * @throws AccessDeniedException if the caller is not on the patient's care team
     */
    public void requireCanRead(Session session, Patient patient) {
        // TODO(Martin) CWE-639
        throw new UnsupportedOperationException("TODO(Martin): CWE-639");
    }

    /**
     * @param session caller's session
     * @param patient chart being edited
     * @throws AccessDeniedException if the caller is not the attending clinician
     */
    public void requireCanEdit(Session session, Patient patient) {
        // TODO(Martin) CWE-283
        throw new UnsupportedOperationException("TODO(Martin): CWE-283");
    }
}
