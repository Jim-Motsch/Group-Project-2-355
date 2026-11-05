package medvault.auth;

import medvault.model.AccessDeniedException;
import medvault.model.Session;
import medvault.model.User;
import medvault.security.TokenGenerator;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Creates, validates and ends sessions.
 *
 * <p><b>CWE-613: Insufficient Session Expiration.</b> A session that never
 * expires turns a stolen token (or a shared workstation left logged in)
 * into permanent access. Sessions expire after {@link #IDLE_TIMEOUT} of
 * inactivity and {@link #ABSOLUTE_TIMEOUT} in total, and
 * {@link #logout(String)} invalidates the token immediately. Expiry is checked
 * on the server against the injected {@link Clock}, so a client can't extend
 * a session by keeping an old {@link Session} object. Tokens come from
 * {@link TokenGenerator} (CWE-338).</p>
 *
 * <p>Thread-safe: sessions live in a {@link ConcurrentHashMap}, and each
 * validate is one atomic check-and-touch, so a token that has been logged out
 * or has expired can never be accepted by a request running at the same
 * time.</p>
 *
 * @author Ian Beebe
 */
public class SessionManager {

    /** Inactivity limit. */
    public static final Duration IDLE_TIMEOUT = Duration.ofMinutes(15);
    /** Hard limit regardless of activity. */
    public static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(8);

    /** One message for unknown, expired and logged-out tokens, so none can be told apart. */
    static final String INVALID = "Your session is invalid or has expired. Please log in again.";

    /** Server-side state for one session. */
    private static final class Entry {
        final Session session;
        final Instant createdAt;
        final Instant lastSeen;

        Entry(Session session, Instant createdAt, Instant lastSeen) {
            this.session = session;
            this.createdAt = createdAt;
            this.lastSeen = lastSeen;
        }

        boolean expiredAt(Instant now) {
            return !now.isBefore(lastSeen.plus(IDLE_TIMEOUT))
                    || !now.isBefore(createdAt.plus(ABSOLUTE_TIMEOUT));
        }
    }

    private final TokenGenerator tokens;
    private final Clock clock;
    private final ConcurrentMap<String, Entry> live = new ConcurrentHashMap<>();

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
        Objects.requireNonNull(user, "user");
        Instant now = clock.instant();
        purgeExpired(now);
        while (true) {
            String token = tokens.newSessionToken();
            Session session = new Session(token, user, expiry(now, now));
            if (live.putIfAbsent(token, new Entry(session, now, now)) == null) {
                return session;
            }
            // 256-bit collision: practically impossible, but never hand out a token twice.
        }
    }

    /**
     * Checks a token and, if it is still live, resets its idle timer.
     *
     * @param token token presented by the caller
     * @return the live session, with {@link Session#getExpiresAt()} updated
     * @throws AccessDeniedException if the token is unknown, expired or logged out
     */
    public Session validate(String token) {
        if (token == null || token.isEmpty()) {
            throw new AccessDeniedException(INVALID);
        }
        Instant now = clock.instant();
        // Atomic per token: an expired entry is removed, a live one is touched.
        Entry touched = live.computeIfPresent(token, (t, e) -> e.expiredAt(now)
                ? null
                : new Entry(new Session(t, e.session.getUser(), expiry(e.createdAt, now)), e.createdAt, now));
        if (touched == null) {
            throw new AccessDeniedException(INVALID);
        }
        return touched.session;
    }

    /** @param token session to end now; unknown or null tokens are ignored */
    public void logout(String token) {
        if (token != null) {
            live.remove(token);
        }
    }

    /** Earlier of the idle deadline and the absolute deadline. */
    private static Instant expiry(Instant createdAt, Instant lastSeen) {
        Instant idle = lastSeen.plus(IDLE_TIMEOUT);
        Instant absolute = createdAt.plus(ABSOLUTE_TIMEOUT);
        return idle.isBefore(absolute) ? idle : absolute;
    }

    /** Drops sessions nobody came back for, so abandoned tokens don't pile up in memory. */
    private void purgeExpired(Instant now) {
        live.values().removeIf(e -> e.expiredAt(now));
    }
}
