package medvault.auth;

import medvault.model.ValidationException;

import java.util.Arrays;
import java.util.List;

/**
 * Rejects weak passwords at registration and password change.
 *
 * <p><b>CWE-521: Weak Password Requirements.</b> If the system accepts
 * {@code password1} or the account's own username, an attacker only needs a
 * short dictionary to get in. Every new password must be at least
 * {@link #MIN_LENGTH} characters, must not equal or contain the username
 * (ignoring case), must not be one repeated character, and must not be on a
 * list of the most common passwords. The check works on the {@code char[]}
 * directly and wipes its own working copies, so the password is never turned
 * into a {@code String} that lingers in memory. Error messages name the rule
 * that failed and never echo the password.</p>
 *
 * @author Ian Beebe
 */
public class PasswordPolicy {

    /** Minimum accepted password length. */
    public static final int MIN_LENGTH = 12;

    /** Longest accepted password; stops a megabyte "password" from tying up PBKDF2. */
    static final int MAX_LENGTH = 128;

    /**
     * Commonly used passwords of {@link #MIN_LENGTH}+ characters, lower case.
     * Shorter ones are already refused by the length rule.
     */
    private static final List<String> COMMON = List.of(
            "password1234", "password12345", "password123456", "password123!", "passw0rd1234",
            "123456789012", "1234567890123", "qwertyuiopas", "qwerty123456", "qwertyuiop123",
            "iloveyou1234", "letmein12345", "welcome12345", "welcome123456", "administrator",
            "changeme1234", "abc123456789", "trustno11234", "superman1234", "football1234",
            "baseball1234", "monkey123456", "dragon123456", "sunshine1234", "princess1234",
            "1q2w3e4r5t6y", "1qaz2wsx3edc", "zaq12wsxcde3", "aaaaaaaaaaaa", "medvault1234",
            "hospital1234", "nurse1234567", "doctor123456", "password2026", "summer2026!!");

    /**
     * @param username the account the password is for
     * @param password the candidate password
     * @throws ValidationException naming the rule that failed (never echoing the password)
     */
    public void check(String username, char[] password) {
        if (password == null || password.length == 0) {
            throw new ValidationException("A password is required.");
        }
        if (password.length < MIN_LENGTH) {
            throw new ValidationException("Password must be at least " + MIN_LENGTH + " characters.");
        }
        if (password.length > MAX_LENGTH) {
            throw new ValidationException("Password must be at most " + MAX_LENGTH + " characters.");
        }
        char[] lower = toLowerCase(password);
        try {
            if (username != null && !username.isBlank() && contains(lower, username.trim().toLowerCase())) {
                throw new ValidationException("Password must not contain the username.");
            }
            if (allSame(lower)) {
                throw new ValidationException("Password must not be one repeated character.");
            }
            for (String common : COMMON) {
                if (equalsChars(lower, common)) {
                    throw new ValidationException("Password is too common; choose a less predictable one.");
                }
            }
        } finally {
            Arrays.fill(lower, '\0');
        }
    }

    private static char[] toLowerCase(char[] password) {
        char[] lower = new char[password.length];
        for (int i = 0; i < password.length; i++) {
            lower[i] = Character.toLowerCase(password[i]);
        }
        return lower;
    }

    /** {@code String.contains} without turning the password into a String. */
    private static boolean contains(char[] haystack, String needle) {
        int n = needle.length();
        for (int start = 0; start + n <= haystack.length; start++) {
            int i = 0;
            while (i < n && haystack[start + i] == needle.charAt(i)) {
                i++;
            }
            if (i == n) {
                return true;
            }
        }
        return false;
    }

    private static boolean allSame(char[] chars) {
        for (char c : chars) {
            if (c != chars[0]) {
                return false;
            }
        }
        return true;
    }

    private static boolean equalsChars(char[] chars, String s) {
        if (chars.length != s.length()) {
            return false;
        }
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] != s.charAt(i)) {
                return false;
            }
        }
        return true;
    }
}
