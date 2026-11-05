package medvault.audit;

import java.util.Objects;

/**
 * Turns any exception into a message that is safe to show to the user.
 *
 * <p><b>CWE-209: Generation of Error Message Containing Sensitive
 * Information.</b> Stack traces, SQL text, file paths and class names go to
 * the audit log with a reference id; the user sees only a generic message
 * and that id.</p>
 *
 * @author Jimmy Motsch
 */
public class ErrorHandler {
    private final AuditLogger audit;

    /** @param audit where full error details are recorded */
    public ErrorHandler(AuditLogger audit) {
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    /**
     * @param error any exception thrown while serving a request
     * @return a user-safe message such as {@code "Something went wrong (ref 3f9a)."}
     */
    public String toUserMessage(Exception error) {
        // TODO(Jimmy) CWE-209: AccessDeniedException / ValidationException messages are
        //  already user-safe; everything else gets a generic message + reference id.
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-209");
    }
}
