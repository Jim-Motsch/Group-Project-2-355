package medvault.auth;

import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;

/**
 * Entry point for logging in and creating accounts.
 *
 * @author Ian Beebe
 */
public interface AuthService {

    /**
     * Creates an account. Called by the admin flow only.
     *
     * @param username new login name
     * @param password initial password, checked by {@link PasswordPolicy}
     * @param role     initial role
     * @return the new user
     */
    User register(String username, char[] password, Role role);

    /**
     * @param username login name
     * @param password candidate password
     * @return a new session
     * @throws medvault.model.AccessDeniedException on bad credentials or lockout;
     *         the message is the same for "no such user" and "wrong password"
     */
    Session login(String username, char[] password);

    /** @param token the session to end */
    void logout(String token);

    /**
     * Changes a password after re-checking the current one (CWE-620).
     *
     * @param username    account to change
     * @param oldPassword the current password, which must verify
     * @param newPassword the replacement, checked by {@link PasswordPolicy}
     * @throws medvault.model.AccessDeniedException if the current password is wrong
     *         or the account is locked (same message as a failed login)
     * @throws medvault.model.ValidationException if the new password is too weak
     */
    void changePassword(String username, char[] oldPassword, char[] newPassword);
}
