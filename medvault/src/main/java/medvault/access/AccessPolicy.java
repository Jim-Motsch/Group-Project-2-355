package medvault.access;

import medvault.audit.AuditLogger;
import medvault.auth.SessionManager;
import medvault.auth.UserRepository;
import medvault.model.AccessDeniedException;
import medvault.model.Patient;
import medvault.model.Session;
import medvault.model.User;

import java.util.Objects;
import java.util.Optional;

/**
 * The one place every service asks "may this session do this?".
 *
 * <p><b>CWE-306: Missing Authentication for Critical Function.</b> Every
 * check starts by re-validating the session token with
 * {@link SessionManager#validate(String)} and then uses the session
 * <em>returned by the server</em>, never the caller's object. A forged,
 * expired or logged-out {@link Session} is refused, and a real token wrapped
 * in a {@code Session} that claims a different user or role gets the real
 * user's rights, not the claimed ones.</p>
 *
 * <p><b>CWE-1220: Insufficient Granularity of Access Control.</b> Each
 * action needs its own {@link Permission}; see that class for the table.</p>
 *
 * <p><b>CWE-639: Authorization Bypass Through User-Controlled Key.</b> Having
 * {@link Permission#READ_CHART} is not enough. The user must also be on the
 * patient's {@link CareTeam}, so changing the patient id in a request does
 * not open someone else's chart.</p>
 *
 * <p><b>CWE-283: Unverified Ownership.</b> Editing a chart requires being its
 * attending clinician, not just a member of the care team.</p>
 *
 * <p>When built with a {@link UserRepository}, the user's <em>current</em>
 * role is read from the account store on every check, so a role change or a
 * deleted account takes effect immediately instead of when the old session
 * expires (CWE-266).</p>
 *
 * <p>Every denial is written to the audit log with ids only.</p>
 *
 * @author Martin Stoilkov
 */
public class AccessPolicy {

    /** Shown when the role lacks the permission. */
    static final String NOT_PERMITTED = "Your role is not allowed to do that.";
    /** Shown when the user is not on the patient's care team. */
    static final String NOT_ON_TEAM = "You are not on this patient's care team.";
    /** Shown when the user does not own the chart. */
    static final String NOT_ATTENDING = "Only the attending clinician can edit this chart.";

    private final SessionManager sessions;
    private final CareTeam careTeam;
    private final UserRepository users;
    private final AuditLogger audit;

    /**
     * @param sessions validates tokens (CWE-306)
     * @param careTeam patient assignments (CWE-639)
     * @param audit    records every denial
     */
    public AccessPolicy(SessionManager sessions, CareTeam careTeam, AuditLogger audit) {
        this(sessions, careTeam, null, audit);
    }

    /**
     * Same as {@link #AccessPolicy(SessionManager, CareTeam, AuditLogger)}, but
     * also re-reads each user's current role from {@code users} on every
     * check, so role changes apply to sessions that are already open.
     *
     * @param sessions validates tokens (CWE-306)
     * @param careTeam patient assignments (CWE-639)
     * @param users    account store holding the current role, or null to trust the session's role
     * @param audit    records every denial
     */
    public AccessPolicy(SessionManager sessions, CareTeam careTeam, UserRepository users, AuditLogger audit) {
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.careTeam = Objects.requireNonNull(careTeam, "careTeam");
        this.users = users;
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    /**
     * @param session    caller's session
     * @param permission action being attempted
     * @throws AccessDeniedException if the session is invalid or lacks the permission
     */
    public void require(Session session, Permission permission) {
        requireSession(session, permission);
    }

    /**
     * Same check as {@link #require(Session, Permission)}, but returns the
     * server's live session so the caller acts on the real identity (for
     * example the uploader's username) rather than on the object it was given.
     *
     * @param session    caller's session
     * @param permission action being attempted
     * @return the validated session, with the user's current role
     * @throws AccessDeniedException if the session is invalid or lacks the permission
     */
    public Session requireSession(Session session, Permission permission) {
        Objects.requireNonNull(permission, "permission");
        Session live = authenticate(session, permission);
        User user = live.getUser();
        if (!Permission.grantedTo(user.getRole()).contains(permission)) {
            audit.record(user, "ACCESS_DENIED", "permission=" + permission + " reason=role");
            throw new AccessDeniedException(NOT_PERMITTED);
        }
        return live;
    }

    /**
     * Checks a permission that applies to one patient: the role must grant it
     * and the user must be on that patient's care team.
     *
     * @param session    caller's session
     * @param permission action being attempted, for example {@link Permission#UPLOAD_LAB}
     * @param patientId  the chart the action touches
     * @return the validated session
     * @throws AccessDeniedException if the session is invalid, lacks the
     *         permission, or is not on the care team
     */
    public Session requireOnCareTeam(Session session, Permission permission, long patientId) {
        Session live = requireSession(session, permission);
        if (!careTeam.membersFor(patientId).contains(live.getUser().getUsername())) {
            audit.record(live.getUser(), "ACCESS_DENIED",
                    "permission=" + permission + " patient=" + patientId + " reason=not_on_care_team");
            throw new AccessDeniedException(NOT_ON_TEAM);
        }
        return live;
    }

    /**
     * @param session caller's session
     * @param patient chart being opened
     * @throws AccessDeniedException if the caller is not on the patient's care team
     */
    public void requireCanRead(Session session, Patient patient) {
        Objects.requireNonNull(patient, "patient");
        requireOnCareTeam(session, Permission.READ_CHART, patient.getId());
    }

    /**
     * Non-throwing read check used to filter search results, so a search does
     * not write one "denied" audit line per chart the caller can't see. The
     * session itself is still validated, and an invalid one still throws.
     *
     * @param session caller's session
     * @param patient a chart
     * @return true if the caller may read it
     * @throws AccessDeniedException if the session is invalid
     */
    public boolean canRead(Session session, Patient patient) {
        Objects.requireNonNull(patient, "patient");
        Session live = authenticate(session, Permission.READ_CHART);
        User user = live.getUser();
        return Permission.grantedTo(user.getRole()).contains(Permission.READ_CHART)
                && careTeam.membersFor(patient.getId()).contains(user.getUsername());
    }

    /**
     * @param session caller's session
     * @param patient chart being edited, as stored on the server (not as sent by the client)
     * @throws AccessDeniedException if the caller is not the attending clinician
     */
    public void requireCanEdit(Session session, Patient patient) {
        Objects.requireNonNull(patient, "patient");
        Session live = requireSession(session, Permission.EDIT_CHART);
        if (!live.getUser().getUsername().equals(patient.getAttendingClinician())) {
            audit.record(live.getUser(), "ACCESS_DENIED",
                    "permission=EDIT_CHART patient=" + patient.getId() + " reason=not_attending");
            throw new AccessDeniedException(NOT_ATTENDING);
        }
    }

    /**
     * Re-validates the token with the server and, if configured, refreshes
     * the role from the account store. The caller's {@code Session} object is
     * used only for its token.
     */
    private Session authenticate(Session session, Permission attempted) {
        Session live;
        try {
            live = sessions.validate(session == null ? null : session.getToken());
        } catch (AccessDeniedException invalid) {
            audit.record(null, "SESSION_REJECTED", "permission=" + attempted);
            throw invalid;
        }
        if (users == null) {
            return live;
        }
        Optional<User> current = users.find(live.getUser().getUsername());
        if (current.isEmpty()) {
            audit.record(live.getUser(), "SESSION_REJECTED", "permission=" + attempted + " reason=account_removed");
            throw new AccessDeniedException(NOT_PERMITTED);
        }
        return current.get().equals(live.getUser())
                ? live
                : new Session(live.getToken(), current.get(), live.getExpiresAt());
    }
}
