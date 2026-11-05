package medvault.auth;

import medvault.model.ValidationException;

/**
 * Rejects weak passwords at registration and password change.
 *
 * <p><b>CWE-521: Weak Password Requirements.</b> Minimum length 12, not equal
 * to or containing the username, and not on a short list of common
 * passwords.</p>
 *
 * @author Ian Beebe
 */
public class PasswordPolicy {

    /** Minimum accepted password length. */
    public static final int MIN_LENGTH = 12;

    /**
     * @param username the account the password is for
     * @param password the candidate password
     * @throws ValidationException naming the rule that failed (never echoing the password)
     */
    public void check(String username, char[] password) {
        // TODO(Ian) CWE-521
        throw new UnsupportedOperationException("TODO(Ian): CWE-521");
    }
}
