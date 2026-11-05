package medvault.audit;

import medvault.model.AccessDeniedException;
import medvault.model.Role;
import medvault.model.User;
import medvault.model.ValidationException;
import medvault.security.TokenGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.UncheckedIOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack tests for the audit package. Each nested class covers one CWE: the
 * tests attempt the attack and assert it fails, and one test shows the
 * legitimate case works. Audit output is captured from the real
 * {@code medvault.audit} logger.
 *
 * @author Jimmy Motsch
 */
class AuditAttackTest {

    private final LogSanitizer sanitizer = new LogSanitizer();
    private final AuditLogger audit = new AuditLogger(sanitizer);
    private final List<String> lines = new ArrayList<>();
    private final Logger auditLog = Logger.getLogger("medvault.audit");
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            lines.add(record.getMessage());
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @BeforeEach
    void captureAuditLog() {
        auditLog.addHandler(capture);
        auditLog.setUseParentHandlers(false); // keep test output quiet
    }

    @AfterEach
    void releaseAuditLog() {
        auditLog.removeHandler(capture);
        auditLog.setUseParentHandlers(true);
    }

    private String onlyLine() {
        assertEquals(1, lines.size(), "expected exactly one audit line");
        return lines.get(0);
    }

    /** CWE-117: Improper Output Neutralization for Logs. */
    @Nested
    class Cwe117LogInjection {

        @Test
        void legitimateTextIsUnchanged() {
            assertEquals("nurse.joy viewed patient=42", sanitizer.clean("nurse.joy viewed patient=42"));
            assertEquals("José Müller", sanitizer.clean("José Müller"));
            assertEquals("-", sanitizer.clean(null));
        }

        @Test
        void newlinesCannotForgeLogLines() {
            String attack = "bob\n2026-11-04 INFO actor=admin action=LOGIN_OK\r\nmore";
            String cleaned = sanitizer.clean(attack);
            assertFalse(cleaned.contains("\n"));
            assertFalse(cleaned.contains("\r"));
            assertEquals("bob\\n2026-11-04 INFO actor=admin action=LOGIN_OK\\r\\nmore", cleaned);
        }

        @Test
        void forgedLineEndsUpInsideOneAuditRecord() {
            audit.record(null, "LOGIN_FAILED", "username=bob\n2026-11-04 INFO actor=admin action=LOGIN_OK");
            String line = onlyLine();
            assertFalse(line.contains("\n"));
            assertTrue(line.startsWith("actor=anonymous role=- action=LOGIN_FAILED detail=\""));
            assertTrue(line.endsWith("\""));
        }

        @Test
        void unicodeLineBreaksAndInvisibleCharactersAreEscaped() {
            // U+2028/2029 line/paragraph separators, NEL, vertical tab, ESC (terminal escape codes),
            // NUL, right-to-left override (makes "nimda" display as "admin"), zero-width space, lone surrogate.
            String attack = "a\u2028b\u2029c\u0085d\u000Be\u001B[31mf\u0000g\u202Enimda\u200Bh\uD800i";
            String cleaned = sanitizer.clean(attack);
            for (char c : cleaned.toCharArray()) {
                assertTrue(c >= 0x20 && c < 0x7F, "unsafe char U+" + Integer.toHexString(c) + " in " + cleaned);
            }
            assertTrue(cleaned.contains("\\u2028") && cleaned.contains("\\u202E") && cleaned.contains("\\u001B"));
        }

        @Test
        void quotesAndBackslashesCannotBreakOutOfTheDetailField() {
            audit.record(null, "LOGIN_FAILED", "x\" action=\"LOGIN_OK\\");
            String line = onlyLine();
            // Exactly two unescaped quotes: the ones AuditLogger put around the detail.
            Matcher unescapedQuote = Pattern.compile("(?<!\\\\)(?:\\\\\\\\)*\"").matcher(line);
            int count = 0;
            while (unescapedQuote.find()) {
                count++;
            }
            assertEquals(2, count, line);
            assertTrue(line.contains("detail=\"x\\\" action=\\\"LOGIN_OK\\\\\""), line);
        }

        @Test
        void hugeInputIsCapped() {
            String cleaned = sanitizer.clean("A".repeat(1_000_000));
            assertEquals(LogSanitizer.MAX_LENGTH, cleaned.length());
            assertTrue(cleaned.endsWith(LogSanitizer.TRUNCATED));
            // Escapes expand text; the cap still holds and never cuts an escape in half.
            String escaped = sanitizer.clean("\n".repeat(500));
            assertTrue(escaped.length() <= LogSanitizer.MAX_LENGTH);
            assertTrue(escaped.matches("(\\\\n)+\\.\\.\\."), escaped);
            assertEquals("A".repeat(LogSanitizer.MAX_LENGTH), sanitizer.clean("A".repeat(LogSanitizer.MAX_LENGTH)));
        }
    }

    /** CWE-532: Insertion of Sensitive Information into Log File. */
    @Nested
    class Cwe532SensitiveDataInLogs {

        @Test
        void legitimateEventIsLoggedWithUsefulDetail() {
            audit.record(new User("nurse.joy", Role.NURSE), "CHART_READ", "patient=42 result=allowed");
            assertEquals("actor=nurse.joy role=NURSE action=CHART_READ detail=\"patient=42 result=allowed\"",
                    onlyLine());
        }

        @Test
        void auditLineNeverContainsSecrets() {
            String token = new TokenGenerator().newSessionToken();
            String sampleToken = "q3V9xLr8_Tz0aKpW5mNcYb2HdJ7eUfGs4iOlRtXv1wE"; // bare token-shaped value
            audit.record(new User("dr.house", Role.DOCTOR), "CHART_EDIT",
                    "patient=42 password=Hunter2! token=" + token + " name=Jane Q. Doe dob=1984-03-12"
                            + " notes=HIV positive, started antiretrovirals\nsecond line of notes leaked=" + sampleToken);
            String line = onlyLine();
            for (String secret : List.of("Hunter2!", token, "Jane", "Doe", "1984-03-12", "HIV", "antiretrovirals",
                    "second line", sampleToken)) {
                assertFalse(line.contains(secret), "leaked '" + secret + "' in: " + line);
            }
            assertTrue(line.contains("patient=42"), "non-sensitive context should survive: " + line);
            assertTrue(line.contains("password=" + AuditLogger.REDACTED));
        }

        @Test
        void userObjectNeverExposesMoreThanUsernameAndRole() {
            audit.record(new User("nurse.joy", Role.NURSE), "LOGOUT", null);
            assertEquals("actor=nurse.joy role=NURSE action=LOGOUT detail=\"-\"", onlyLine());
        }

        @Test
        void actionMustBeAFixedConstantNotUserText() {
            // Attack: smuggle data or a fake field through the action slot.
            assertThrows(IllegalArgumentException.class,
                    () -> audit.record(null, "LOGIN_OK detail=\"admin\"", "x"));
            assertThrows(IllegalArgumentException.class, () -> audit.record(null, "login\nOK", "x"));
            assertThrows(IllegalArgumentException.class, () -> audit.record(null, null, "x"));
            assertTrue(lines.isEmpty());
        }

        @Test
        void usernameIsSanitizedToo() {
            audit.record(new User("eve\nactor=admin", Role.NURSE), "LOGIN_OK", "");
            assertFalse(onlyLine().contains("\n"));
        }
    }

    /** CWE-209: Generation of Error Message Containing Sensitive Information. */
    @Nested
    class Cwe209ErrorMessageLeaks {
        private final ErrorHandler errors = new ErrorHandler(audit, new TokenGenerator());

        @Test
        void legitimateUserSafeMessagesPassThrough() {
            assertEquals("You are not on this patient's care team.",
                    errors.toUserMessage(new AccessDeniedException("You are not on this patient's care team.")));
            assertEquals("Password must be at least 12 characters.",
                    errors.toUserMessage(new ValidationException("Password must be at least 12 characters.")));
            assertTrue(lines.isEmpty(), "user-safe errors are not internal errors");
        }

        @Test
        void internalErrorsGetGenericMessage() {
            String sql = "SELECT * FROM patient WHERE name = 'Jane Doe'";
            String msg = errors.toUserMessage(new SQLException(sql, "42000"));
            assertFalse(msg.contains("SELECT"));
            assertFalse(msg.contains("patient"));
            assertFalse(msg.contains("Jane"));
            assertFalse(msg.contains("SQLException"));
            assertTrue(msg.matches("Something went wrong \\(ref [0-9a-f]{8}\\)\\..*"), msg);
        }

        @Test
        void pathsClassNamesAndStackTracesNeverReachTheUser() {
            Exception nested = new UncheckedIOException(
                    new FileNotFoundException("C:\\medvault\\data\\labs\\42\\jane-doe.pdf"));
            String msg = errors.toUserMessage(nested);
            for (String leak : List.of("C:\\", "labs", "jane", "UncheckedIOException", "java.", "at medvault")) {
                assertFalse(msg.contains(leak), "leaked '" + leak + "' in: " + msg);
            }
        }

        @Test
        void referenceIdLinksUserMessageToAuditLogWithoutLoggingTheSecretMessage() {
            String sql = "SELECT * FROM patient WHERE name = 'Jane Doe'";
            String msg = errors.toUserMessage(new IllegalStateException(sql));
            String ref = msg.replaceAll(".*\\(ref ([0-9a-f]{8})\\).*", "$1");
            String line = onlyLine();
            assertTrue(line.contains("action=INTERNAL_ERROR"), line);
            assertTrue(line.contains("ref=" + ref), line);
            assertTrue(line.contains("java.lang.IllegalStateException"), "support needs the type: " + line);
            assertFalse(line.contains("SELECT"), "SQL must not be logged either: " + line);
            assertFalse(line.contains("Jane"), line);
        }

        @Test
        void referenceIdsAreUnique() {
            String a = errors.toUserMessage(new RuntimeException());
            String b = errors.toUserMessage(new RuntimeException());
            assertFalse(a.equals(b));
        }

        @Test
        void userSafeTypesWithoutAMessageStillGetGenericText() {
            String msg = errors.toUserMessage(new AccessDeniedException(null));
            assertTrue(msg.startsWith("Something went wrong"), msg);
            assertTrue(errors.toUserMessage(null).startsWith("Something went wrong"));
        }
    }
}
