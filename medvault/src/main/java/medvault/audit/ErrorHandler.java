package medvault.audit;

import medvault.model.AccessDeniedException;
import medvault.model.ValidationException;
import medvault.security.TokenGenerator;

import java.util.HexFormat;
import java.util.Objects;

/**
 * Turns any exception into a message that is safe to show to the user.
 *
 * <p><b>CWE-209: Generation of Error Message Containing Sensitive
 * Information.</b> Raw exception messages and stack traces tell an attacker
 * the SQL being run, table names, file paths and library versions, which
 * makes the next attack easier. {@link AccessDeniedException} and
 * {@link ValidationException} are written to be user-safe, so their message is
 * shown. Every other exception becomes a generic message with a random
 * reference id; the audit log gets the same id with the exception type and the
 * code location where it was thrown, so support can find it. The exception's
 * own message is never shown or logged, because it can contain SQL text,
 * paths or patient data (CWE-532).</p>
 *
 * @author Jimmy Motsch
 */
public class ErrorHandler {
    /** Shown when an exception has no user-safe message. */
    static final String GENERIC = "Something went wrong (ref %s). Please contact support with this reference.";

    private final AuditLogger audit;
    private final TokenGenerator random;

    /**
     * @param audit where error details are recorded
     */
    public ErrorHandler(AuditLogger audit) {
        this(audit, new TokenGenerator());
    }

    /**
     * @param audit  where error details are recorded
     * @param random source of reference ids (pass the app's shared generator)
     */
    public ErrorHandler(AuditLogger audit, TokenGenerator random) {
        this.audit = Objects.requireNonNull(audit, "audit");
        this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * @param error any exception thrown while serving a request
     * @return a user-safe message such as
     *         {@code "Something went wrong (ref 3f9a1c2b). Please contact support with this reference."}
     */
    public String toUserMessage(Exception error) {
        if ((error instanceof AccessDeniedException || error instanceof ValidationException)
                && error.getMessage() != null && !error.getMessage().isBlank()) {
            return error.getMessage();
        }
        String ref = HexFormat.of().formatHex(random.randomBytes(4));
        audit.record(null, "INTERNAL_ERROR", "ref=" + ref + " type=" + describe(error));
        return String.format(GENERIC, ref);
    }

    /** Exception type plus where it was thrown; never the message text. */
    private static String describe(Throwable error) {
        if (error == null) {
            return "none";
        }
        StringBuilder sb = new StringBuilder(error.getClass().getName());
        StackTraceElement[] frames = error.getStackTrace();
        if (frames.length > 0) {
            StackTraceElement top = frames[0];
            sb.append(" at=").append(top.getClassName()).append('.').append(top.getMethodName())
                    .append(':').append(top.getLineNumber());
        }
        Throwable cause = error.getCause();
        if (cause != null && cause != error) {
            sb.append(" cause=").append(cause.getClass().getName());
        }
        return sb.toString();
    }
}
