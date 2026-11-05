package medvault.audit;

import medvault.model.User;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * Records every security-relevant action: logins, lockouts, chart reads,
 * edits, uploads, denials.
 *
 * <p><b>CWE-532: Insertion of Sensitive Information into Log File.</b> Log
 * usernames, patient <em>ids</em> and actions only. Never passwords, session
 * tokens, patient names, dates of birth, or clinical notes. All free text
 * passes through {@link LogSanitizer} first (CWE-117).</p>
 *
 * @author Jimmy Motsch
 */
public class AuditLogger {
    private static final Logger LOG = Logger.getLogger("medvault.audit");
    private final LogSanitizer sanitizer;

    /** @param sanitizer cleans untrusted text before it is logged */
    public AuditLogger(LogSanitizer sanitizer) {
        this.sanitizer = Objects.requireNonNull(sanitizer, "sanitizer");
    }

    /**
     * Writes one audit event.
     *
     * @param actor  who did it, or null for an anonymous attempt
     * @param action short fixed action name, for example {@code LOGIN_FAILED}
     * @param detail untrusted free text (will be sanitized)
     */
    public void record(User actor, String action, String detail) {
        // TODO(Jimmy) CWE-532 / CWE-117: format "actor=<name> action=<action> detail=<clean>"
        //  and LOG.info(...) it. Decide what may appear in detail.
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-532");
    }
}
