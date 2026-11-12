package medvault.auth;

import medvault.audit.AuditLogger;
import medvault.model.AccessDeniedException;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.model.ValidationException;

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Ties the auth pieces together: policy check, salted slow hash, lockout,
 * session creation, audit trail.
 *
 * <p>{@link #login} gives exactly the same {@link AccessDeniedException}
 * message for an unknown user, a wrong password and a locked account, and an
 * unknown user still costs one full PBKDF2 run, so neither the message nor
 * the response time tells an attacker which usernames exist (CWE-307,
 * CWE-916).</p>
 *
 * <p><b>CWE-620: Unverified Password Change.</b> If a password could be
 * changed without proving the current one, anyone who found a logged-in
 * workstation (or stole a session) could lock the real user out and keep the
 * account. {@link #changePassword} re-verifies the current password with the
 * same PBKDF2 check as login before accepting a new one. A wrong current
 * password counts as a failed login, so password change can't be used to
 * brute-force around the lockout (CWE-307), and the new password must pass
 * {@link PasswordPolicy} (CWE-521).</p>
 *
 * @author Ian Beebe
 */
public class DefaultAuthService implements AuthService {

    /** The only message a failed login ever produces. */
    static final String LOGIN_FAILED = "Invalid username or password.";

    /** Login names: letters, digits, dot, underscore, hyphen. Keeps control characters out of logs. */
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9._-]{3,64}");

    private final UserRepository users;
    private final PasswordPolicy policy;
    private final PasswordHasher hasher;
    private final LoginAttemptTracker attempts;
    private final SessionManager sessions;
    private final AuditLogger audit;
    /** Hash of a random throwaway password; verified against for unknown users to equalize timing. */
    private final String dummyHash;
    /** Makes "check the name is free, then save" atomic. */
    private final Object registerLock = new Object();

    /**
     * @param users    account storage
     * @param policy   password rules (CWE-521)
     * @param hasher   salted password hashing (CWE-916)
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
        // Not a credential: a match against it still fails, because login also requires a stored hash.
        this.dummyHash = hasher.hash("timing-equalizer-not-a-credential".toCharArray());
    }

    /**
     * {@inheritDoc}
     *
     * @throws ValidationException if the username is malformed or taken, or the
     *         password fails {@link PasswordPolicy}
     */
    @Override
    public User register(String username, char[] password, Role role) {
        if (username == null || !USERNAME.matcher(username).matches()) {
            throw new ValidationException("Username must be 3-64 letters, digits, '.', '_' or '-'.");
        }
        if (role == null) {
            throw new ValidationException("A role is required.");
        }
        try {
            policy.check(username, password);
        } catch (ValidationException weak) {
            audit.record(null, "USER_CREATE_REJECTED", "user=" + username + " reason=weak_password");
            throw weak;
        }
        String hash = hasher.hash(password);
        User user = new User(username, role);
        synchronized (registerLock) {
            if (users.find(username).isPresent()) {
                audit.record(null, "USER_CREATE_REJECTED", "user=" + username + " reason=duplicate");
                throw new ValidationException("That username is already taken.");
            }
            users.save(user, hash);
        }
        audit.record(null, "USER_CREATED", "user=" + username + " role=" + role);
        return user;
    }

    @Override
    public Session login(String username, char[] password) {
        if (username == null || username.isEmpty() || password == null) {
            audit.record(null, "LOGIN_FAILED", "reason=missing_credentials");
            throw new AccessDeniedException(LOGIN_FAILED);
        }
        if (attempts.isLocked(username)) {
            audit.record(null, "LOGIN_LOCKED", "user=" + username);
            throw new AccessDeniedException(LOGIN_FAILED);
        }
        Optional<String> stored = users.findPasswordHash(username);
        Optional<User> user = users.find(username);
        // Always run one full PBKDF2, even for unknown users, so timing reveals nothing.
        boolean passwordOk = hasher.verify(password, stored.orElse(dummyHash));
        if (!passwordOk || stored.isEmpty() || user.isEmpty()) {
            attempts.recordFailure(username);
            audit.record(null, "LOGIN_FAILED", "user=" + username);
            if (attempts.isLocked(username)) {
                audit.record(null, "ACCOUNT_LOCKED", "user=" + username);
            }
            throw new AccessDeniedException(LOGIN_FAILED);
        }
        // Re-check: parallel wrong guesses may have locked the account while we were hashing.
        if (attempts.isLocked(username)) {
            audit.record(null, "LOGIN_LOCKED", "user=" + username);
            throw new AccessDeniedException(LOGIN_FAILED);
        }
        attempts.recordSuccess(username);
        Session session = sessions.create(user.get());
        audit.record(user.get(), "LOGIN_OK", "user=" + username);
        return session;
    }

    @Override
    public void logout(String token) {
        sessions.logout(token);
    }

    @Override
    public void changePassword(String username, char[] oldPassword, char[] newPassword) {
        if (username == null || username.isEmpty() || oldPassword == null) {
            audit.record(null, "PASSWORD_CHANGE_FAILED", "reason=missing_credentials");
            throw new AccessDeniedException(LOGIN_FAILED);
        }
        if (attempts.isLocked(username)) {
            audit.record(null, "PASSWORD_CHANGE_FAILED", "user=" + username + " reason=locked");
            throw new AccessDeniedException(LOGIN_FAILED);
        }
        // CWE-620: the current password must verify before anything changes.
        Optional<String> stored = users.findPasswordHash(username);
        Optional<User> user = users.find(username);
        boolean currentOk = hasher.verify(oldPassword, stored.orElse(dummyHash));
        if (!currentOk || stored.isEmpty() || user.isEmpty()) {
            attempts.recordFailure(username); // guesses here count toward the lockout too
            audit.record(null, "PASSWORD_CHANGE_FAILED", "user=" + username + " reason=wrong_current_password");
            if (attempts.isLocked(username)) {
                audit.record(null, "ACCOUNT_LOCKED", "user=" + username);
            }
            throw new AccessDeniedException(LOGIN_FAILED);
        }
        policy.check(username, newPassword);
        String newHash = hasher.hash(newPassword);
        synchronized (registerLock) {
            // Refuse if another change landed while we were hashing.
            if (!users.findPasswordHash(username).equals(stored)) {
                throw new AccessDeniedException(LOGIN_FAILED);
            }
            users.save(user.get(), newHash);
        }
        attempts.recordSuccess(username);
        audit.record(user.get(), "PASSWORD_CHANGED", "user=" + username);
    }
}
