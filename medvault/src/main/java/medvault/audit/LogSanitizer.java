package medvault.audit;

/**
 * Neutralizes user-controlled text before it is written to a log.
 *
 * <p><b>CWE-117: Improper Output Neutralization for Logs.</b> An attacker who
 * types {@code "bob\n2026-11-04 INFO admin logged in"} as a username must not
 * be able to forge a second log line. Replace CR, LF and other control
 * characters, and cap the length.</p>
 *
 * @author Jimmy Motsch
 */
public class LogSanitizer {

    /** Longest user-supplied value that will be written to a log. */
    public static final int MAX_LENGTH = 200;

    /**
     * @param input untrusted text, may be null
     * @return a single-line, length-limited, printable version of {@code input}
     */
    public String clean(String input) {
        // TODO(Jimmy) CWE-117
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-117");
    }
}
