package medvault.security;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Attack tests for the security package. Each test is the target behavior for one
 * CWE. Remove {@code @Disabled} as you implement it; by integration day
 * (Nov 8) none should be disabled.
 *
 * @author Jimmy Motsch
 */
class SecurityAttackTest {

    @Test
    @Disabled("TODO(Jimmy): CWE-327")
    void encryptUsesAesGcmAndDetectsTampering() {
        // decrypt(encrypt(x)) == x; flipping one byte -> SecurityException; same x twice -> different ciphertext
    }

    @Test
    @Disabled("TODO(Jimmy): CWE-321")
    void missingKeyFailsFast() {
        // loadRecordKey() throws IllegalStateException when MEDVAULT_RECORD_KEY is unset
    }

    @Test
    @Disabled("TODO(Jimmy): CWE-338")
    void tokensAreLongAndUnique() {
        // 10,000 tokens are all distinct and at least 43 characters
    }
}
