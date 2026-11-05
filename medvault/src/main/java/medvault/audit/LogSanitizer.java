package medvault.audit;

/**
 * Neutralizes user-controlled text before it is written to a log.
 *
 * <p><b>CWE-117: Improper Output Neutralization for Logs.</b> An attacker who
 * types {@code "bob\n2026-11-04 INFO admin logged in"} as a username must not
 * be able to forge a second log line. Every character that could end a line
 * or hide text (CR, LF, other control characters, Unicode line/paragraph
 * separators, invisible format characters such as right-to-left overrides,
 * lone surrogates) is replaced by a visible escape like {@code \n} or
 * {@code ‮}. Backslash and double quote are escaped too, so the escaping
 * is unambiguous and a value cannot break out of the quotes
 * {@link AuditLogger} puts around it. The result is capped at
 * {@link #MAX_LENGTH} characters so one request cannot flood the log.</p>
 *
 * @author Jimmy Motsch
 */
public class LogSanitizer {

    /** Longest user-supplied value that will be written to a log. */
    public static final int MAX_LENGTH = 200;

    /** Appended when a value is cut short. */
    static final String TRUNCATED = "...";

    /** Written in place of a null value. */
    static final String NULL_VALUE = "-";

    /**
     * @param input untrusted text, may be null
     * @return a single-line, length-limited, printable version of {@code input},
     *         never longer than {@link #MAX_LENGTH}
     */
    public String clean(String input) {
        if (input == null) {
            return NULL_VALUE;
        }
        StringBuilder out = new StringBuilder(Math.min(input.length(), MAX_LENGTH) + 8);
        int cutAt = -1; // last length at which "..." would still fit
        int i = 0;
        while (i < input.length()) {
            int cp = input.codePointAt(i);
            String piece = escape(cp);
            if (out.length() + piece.length() > MAX_LENGTH) {
                out.setLength(cutAt);
                return out.append(TRUNCATED).toString();
            }
            if (out.length() + piece.length() <= MAX_LENGTH - TRUNCATED.length()) {
                cutAt = out.length() + piece.length();
            }
            out.append(piece);
            i += Character.charCount(cp);
        }
        return out.toString();
    }

    /** Returns {@code cp} unchanged if it is safe on one log line, otherwise a visible escape. */
    private static String escape(int cp) {
        switch (cp) {
            case '\\':
                return "\\\\";
            case '"':
                return "\\\"";
            case '\n':
                return "\\n";
            case '\r':
                return "\\r";
            case '\t':
                return "\\t";
            default:
                break;
        }
        int type = Character.getType(cp);
        boolean unsafe = Character.isISOControl(cp)
                || type == Character.FORMAT
                || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR
                || type == Character.SURROGATE
                || type == Character.UNASSIGNED;
        if (!unsafe) {
            return new String(Character.toChars(cp));
        }
        return Character.isBmpCodePoint(cp)
                ? String.format("\\u%04X", cp)
                : String.format("\\U%08X", cp);
    }
}
