package medvault.auth;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Attack tests for the auth package. Each test is the target behavior for one
 * CWE. Remove {@code @Disabled} as you implement it; by integration day
 * (Nov 8) none should be disabled.
 *
 * @author Ian Beebe
 */
class AuthAttackTest {

    @Test
    @Disabled("TODO(Ian): CWE-521")
    void rejectsShortOrCommonPassword() {
        // PasswordPolicy.check("nurse1", "password123".toCharArray()) throws ValidationException
    }

    @Test
    @Disabled("TODO(Ian): CWE-916")
    void hashUsesPbkdf2WithManyIterations() {
        // hash starts with "210000:" and verify() accepts the right password, rejects a wrong one
    }

    @Test
    @Disabled("TODO(Ian): CWE-759")
    void samePasswordGivesDifferentHashes() {
        // hash(pw) != hash(pw) because each call uses a new salt
    }

    @Test
    @Disabled("TODO(Ian): CWE-307")
    void locksAccountAfterFiveFailures() {
        // five recordFailure() calls -> isLocked() true; advance the clock 15 min -> false
    }

    @Test
    @Disabled("TODO(Ian): CWE-798")
    void refusesToStartWithoutEnvCredentials() {
        // fromEnvironment() throws IllegalStateException when the variables are unset
    }

    @Test
    @Disabled("TODO(Ian): CWE-613")
    void sessionExpiresAfterIdleTimeoutAndLogout() {
        // validate() fails after IDLE_TIMEOUT and immediately after logout()
    }
}
