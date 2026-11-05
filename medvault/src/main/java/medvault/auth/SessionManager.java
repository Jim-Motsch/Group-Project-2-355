package medvault.auth;

import medvault.model.AccessDeniedException;
import medvault.model.Session;
import medvault.model.User;
import medvault.security.TokenGenerator;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Creates, validates and ends sessions.
 *
 * <p><b>CWE-613: Insufficient Session Expiration.</b> Sessions expire after
 * {@link #IDLE_TIMEOUT} of inactivity and {@link #ABSOLUTE_TIMEOUT} in total,
 * and {@link #logout(String)} invalidates the token immediately. Tokens come
 * from {@link TokenGenerator} (CWE-338).</p>
 *
 * @author Ian Beebe
 */
public class SessionManager {

    /** Inactivity limit. */
    public static final Duration IDLE_TIMEOUT = Duration.ofMinutes(15);
    /** Hard limit regardless of activity. */
    public static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(8);

    private final TokenGenerator tokens;
    private final Clock clock;

    /**
     * @param tokens source of session tokens
     * @param clock  injected so tests can move time forward
     */
    public SessionManager(TokenGenerator tokens, Clock clock) {
        this.tokens = Objects.requireNonNull(tokens, "tokens");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** @param user freshly authenticated user @return a new session */
    public Session create(User user) {
        // TODO(Ian) CWE-613
        throw new UnsupportedOperationException("TODO(Ian): CWE-613");
    }

    /**
     * @param token token presented by the caller
     * @return the live session
     * @throws AccessDeniedException if the token is unknown, expired or logged out
     */
    public Session validate(String token) {
        // TODO(Ian) CWE-613
        throw new UnsupportedOperationException("TODO(Ian): CWE-613");
    }

    /** @param token session to end now */
    public void logout(String token) {
        // TODO(Ian) CWE-613
        throw new UnsupportedOperationException("TODO(Ian): CWE-613");
    }
}
