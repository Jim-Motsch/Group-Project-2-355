package medvault.records;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Attack tests for the records package. Each test is the target behavior for one
 * CWE. Remove {@code @Disabled} as you implement it; by integration day
 * (Nov 8) none should be disabled.
 *
 * @author James Strickert
 */
class RecordsAttackTest {

    @Test
    @Disabled("TODO(James): CWE-89")
    void sqlInjectionInSearchReturnsNothingExtra() {
        // searchByName(s, "' OR 1=1 --") returns an empty list
    }

    @Test
    @Disabled("TODO(James): CWE-79")
    void exportEscapesScriptTags() {
        // notes "<script>alert(1)</script>" appear as &lt;script&gt; in toHtml()
    }

    @Test
    @Disabled("TODO(James): CWE-78")
    void printerNeverUsesAShell() {
        // ProcessBuilder command list has no "sh", "-c" or user text
    }

    @Test
    @Disabled("TODO(James): CWE-611")
    void xmlWithDoctypeIsRejected() {
        // parse() of a file with <!DOCTYPE ... SYSTEM "file:///etc/passwd"> throws ValidationException
    }

    @Test
    @Disabled("TODO(James): CWE-643")
    void xpathLookupIsParameterized() {
        // findByName(doc, "x' or '1'='1") returns no patients
    }

    @Test
    @Disabled("TODO(James): CWE-502")
    void restoreRejectsUnexpectedTypes() {
        // restore() of a stream containing a non-MedVault object throws ValidationException
    }
}
