package medvault.auth;

import medvault.audit.AuditLogger;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;

import java.util.Objects;

/**
 * Ties the auth pieces together: policy check, salted slow hash, lockout,
 * session creation, audit trail.
 *
 * @author Ian Beebe
 */
public class DefaultAuthService implements AuthService {
    private final UserRepository users;
    private final PasswordPolicy policy;
    private final PasswordHasher hasher;
    private final LoginAttemptTracker attempts;
    private final SessionManager sessions;
    private final AuditLogger audit;

    /**
     * @param users    account storage
     * @param policy   password rules (CWE-521)
     * @param hasher   password hashing (CWE-916, CWE-759)
     * @param attempts lockout tracking (CWE-307)
     * @param sessions session lifecycle (CWE-613)
     * @param audit    audit trail
     */
    public DefaultAuthService(UserRepository users, PasswordPolicy policy, PasswordHasher hasher,
                              LoginAttemptTracker attempts, SessionManager sessions, AuditLogger audit) {
        this.users = Objects.requireNonNull(users, "users");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.hasher = Objects.requireNonNull(hasher, "hasher");
        this.attempts = Objects.requireNonNull(attempts, "attempts");
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    @Override
    public User register(String username, char[] password, Role role) {
        // TODO(Ian): policy.check -> hasher.hash -> users.save -> audit.record("USER_CREATED")
        throw new UnsupportedOperationException("TODO(Ian): register");
    }

    @Override
    public Session login(String username, char[] password) {
        // TODO(Ian): attempts.isLocked? -> verify hash -> recordFailure/recordSuccess
        //  -> sessions.create -> audit. Same error message for unknown user and bad password.
        throw new UnsupportedOperationException("TODO(Ian): login");
    }

    @Override
    public void logout(String token) {
        sessions.logout(token);
    }
}
