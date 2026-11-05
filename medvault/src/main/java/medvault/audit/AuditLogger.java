package medvault.audit;

import medvault.model.User;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Records every security-relevant action: logins, lockouts, chart reads,
 * edits, uploads, denials.
 *
 * <p><b>CWE-532: Insertion of Sensitive Information into Log File.</b> Logs
 * are read by more people (and kept longer) than the database, so anything
 * secret written there leaks. Each line holds only the actor's username and
 * role, a fixed action name, and a detail string. The detail is meant for
 * usernames, patient <em>ids</em> and outcomes; as a safety net, before it is
 * written this class redacts the value of any sensitive {@code key=value}
 * field (password, token, session, secret, key, name, dob, notes, ssn) and
 * any long token-shaped string (32+ Base64/hex characters including a digit
 * or symbol, the shape of a session token, salt or key). All free text then passes through
 * {@link LogSanitizer} (CWE-117).</p>
 *
 * <p>Line format:
 * {@code actor=<username> role=<ROLE> action=<ACTION> detail="<clean detail>"}</p>
 *
 * @author Jimmy Motsch
 */
public class AuditLogger {
    private static final Logger LOG = Logger.getLogger("medvault.audit");

    /** Written in place of a removed secret. */
    static final String REDACTED = "[REDACTED]";

    /** Action names are fixed constants such as {@code LOGIN_FAILED}, never user text. */
    private static final Pattern ACTION = Pattern.compile("[A-Z][A-Z0-9_]{0,39}");

    /**
     * {@code key=value} or {@code key: value} where the key names a secret. The
     * value runs until the next {@code key=} field or the end of the text, so a
     * multi-word name or a multi-line note is removed entirely.
     */
    private static final Pattern SENSITIVE_FIELD = Pattern.compile(
            "(?i)\\b(passwords?|passwd|pwd|pass|secret|token|session(?:_?id|_?token)?|api_?key|key"
                    + "|name|full_?name|patient_?name|dob|date_?of_?birth|birth_?date|notes?"
                    + "|clinical_?notes|ssn)(\\s*[=:]\\s*)(.*?)(?=\\s+[A-Za-z_]+\\s*[=:]|$)",
            Pattern.DOTALL);

    /**
     * A run of 32+ Base64/Base64url/hex characters containing at least one digit
     * or {@code _ - + /}: looks like a token, salt, hash or key. The extra
     * requirement keeps long Java class names (letters only) readable.
     */
    private static final Pattern TOKEN_SHAPED = Pattern.compile(
            "(?<![A-Za-z0-9_\\-+/])(?=[A-Za-z]*[0-9_\\-+/])[A-Za-z0-9_\\-+/]{32,}={0,2}");

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
     *               (upper case letters, digits and underscores)
     * @param detail untrusted free text (will be redacted and sanitized); put
     *               usernames and patient ids here, never names, notes or secrets
     * @throws IllegalArgumentException if {@code action} is not a fixed action name
     */
    public void record(User actor, String action, String detail) {
        if (action == null || !ACTION.matcher(action).matches()) {
            throw new IllegalArgumentException("audit action must be an UPPER_SNAKE_CASE constant");
        }
        String who = actor == null ? "anonymous" : sanitizer.clean(actor.getUsername());
        String role = actor == null ? "-" : actor.getRole().name();
        String line = "actor=" + who
                + " role=" + role
                + " action=" + action
                + " detail=\"" + sanitizer.clean(redact(detail)) + "\"";
        LOG.log(Level.INFO, line);
    }

    /** Removes secrets from free text before it is logged. */
    static String redact(String detail) {
        if (detail == null) {
            return null;
        }
        Matcher field = SENSITIVE_FIELD.matcher(detail);
        String withoutFields = field.replaceAll(m -> Matcher.quoteReplacement(m.group(1) + m.group(2) + REDACTED));
        return TOKEN_SHAPED.matcher(withoutFields).replaceAll(Matcher.quoteReplacement(REDACTED));
    }
}
