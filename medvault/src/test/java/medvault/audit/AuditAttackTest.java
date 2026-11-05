package medvault.audit;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Attack tests for the audit package. Each test is the target behavior for one
 * CWE. Remove {@code @Disabled} as you implement it; by integration day
 * (Nov 8) none should be disabled.
 *
 * @author Jimmy Motsch
 */
class AuditAttackTest {

    @Test
    @Disabled("TODO(Jimmy): CWE-117")
    void newlinesCannotForgeLogLines() {
        // clean("bob\\nINFO admin logged in") contains no \\n or \\r
    }

    @Test
    @Disabled("TODO(Jimmy): CWE-532")
    void auditLineNeverContainsSecrets() {
        // record() output never contains a password, token, patient name or notes
    }

    @Test
    @Disabled("TODO(Jimmy): CWE-209")
    void internalErrorsGetGenericMessage() {
        // toUserMessage(new SQLException("SELECT * FROM patient")) contains no SQL
    }
}
