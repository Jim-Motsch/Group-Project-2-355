package medvault.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Counts failed logins per account and locks it out temporarily.
 *
 * <p><b>CWE-307: Improper Restriction of Excessive Authentication
 * Attempts.</b> Without a limit an attacker can try thousands of passwords
 * against one account. After {@link #MAX_FAILURES} failures in a row the
 * account is locked for {@link #LOCKOUT}; while locked, even the correct
 * password is refused. Unknown usernames are tracked the same way, so the
 * lockout itself doesn't reveal which accounts exist. Time comes from the
 * injected {@link Clock} so tests can move it forward.</p>
 *
 * <p>Thread-safe: state lives in a {@link ConcurrentHashMap} and every update
 * is one atomic {@code compute}, so parallel guesses can't race past the
 * limit by reading the same old counter.</p>
 *
 * @author Ian Beebe
 */
public class LoginAttemptTracker {

    /** Failures allowed before lockout. */
    public static final int MAX_FAILURES = 5;
    /** How long an account stays locked. */
    public static final Duration LOCKOUT = Duration.ofMinutes(15);

    /** Immutable per-account state; replaced atomically on every change. */
    private static final class State {
        final int failures;
        final Instant lockedUntil;

        State(int failures, Instant lockedUntil) {
            this.failures = failures;
            this.lockedUntil = lockedUntil;
        }

        boolean lockedAt(Instant now) {
            return lockedUntil != null && now.isBefore(lockedUntil);
        }
    }

    private final Clock clock;
    private final ConcurrentMap<String, State> states = new ConcurrentHashMap<>();

    /** @param clock injected so tests can move time forward */
    public LoginAttemptTracker(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** @param username account name @return true if logins are currently refused */
    public boolean isLocked(String username) {
        Objects.requireNonNull(username, "username");
        State s = states.get(username);
        return s != null && s.lockedAt(clock.instant());
    }

    /** @param username account that just failed to log in */
    public void recordFailure(String username) {
        Objects.requireNonNull(username, "username");
        Instant now = clock.instant();
        states.compute(username, (u, s) -> {
            if (s != null && s.lockedAt(now)) {
                return s; // already locked; the lock does not get shorter or longer
            }
            int failures = (s == null || s.lockedUntil != null) ? 1 : s.failures + 1;
            return failures >= MAX_FAILURES
                    ? new State(0, now.plus(LOCKOUT))
                    : new State(failures, null);
        });
    }

    /** @param username account that just logged in; resets its counter */
    public void recordSuccess(String username) {
        Objects.requireNonNull(username, "username");
        states.remove(username);
    }
}
