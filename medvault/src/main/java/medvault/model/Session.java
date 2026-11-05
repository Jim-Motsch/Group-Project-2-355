package medvault.model;

import java.time.Instant;
import java.util.Objects;

/**
 * A logged-in session. Created only by {@link medvault.auth.SessionManager};
 * every service method that touches patient data takes one (CWE-306).
 */
public final class Session {
    private final String token;
    private final User user;
    private final Instant expiresAt;

    /**
     * @param token     random, unguessable session token (CWE-338)
     * @param user      the authenticated user
     * @param expiresAt when the session stops being valid (CWE-613)
     */
    public Session(String token, User user, Instant expiresAt) {
        this.token = Objects.requireNonNull(token, "token");
        this.user = Objects.requireNonNull(user, "user");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    }

    /** @return the session token */
    public String getToken() {
        return token;
    }

    /** @return the authenticated user */
    public User getUser() {
        return user;
    }

    /** @return expiry time */
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** The token is deliberately left out so it can't end up in a log. */
    @Override
    public String toString() {
        return "Session[" + user.getUsername() + ", expires " + expiresAt + "]";
    }
}
