package medvault.auth;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Counts failed logins per account and locks it out temporarily.
 *
 * <p><b>CWE-307: Improper Restriction of Excessive Authentication
 * Attempts.</b> After {@link #MAX_FAILURES} failures in a row the account is
 * locked for {@link #LOCKOUT}. Thread-safe, since logins can arrive
 * concurrently.</p>
 *
 * @author Ian Beebe
 */
public class LoginAttemptTracker {

    /** Failures allowed before lockout. */
    public static final int MAX_FAILURES = 5;
    /** How long an account stays locked. */
    public static final Duration LOCKOUT = Duration.ofMinutes(15);

    private final Clock clock;

    /** @param clock injected so tests can move time forward */
    public LoginAttemptTracker(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** @param username account name @return true if logins are currently refused */
    public boolean isLocked(String username) {
        // TODO(Ian) CWE-307
        throw new UnsupportedOperationException("TODO(Ian): CWE-307");
    }

    /** @param username account that just failed to log in */
    public void recordFailure(String username) {
        // TODO(Ian) CWE-307
        throw new UnsupportedOperationException("TODO(Ian): CWE-307");
    }

    /** @param username account that just logged in; resets its counter */
    public void recordSuccess(String username) {
        // TODO(Ian) CWE-307
        throw new UnsupportedOperationException("TODO(Ian): CWE-307");
    }
}
