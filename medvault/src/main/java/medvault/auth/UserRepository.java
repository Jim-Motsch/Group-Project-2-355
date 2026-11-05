package medvault.auth;

import medvault.model.Role;
import medvault.model.User;

import java.util.Optional;

/**
 * Stores accounts and their password hashes.
 *
 * @author Ian Beebe
 */
public interface UserRepository {

    /**
     * @param user         the account
     * @param passwordHash value from {@link PasswordHasher#hash(char[])}
     */
    void save(User user, String passwordHash);

    /** @param username login name @return the account, if it exists */
    Optional<User> find(String username);

    /** @param username login name @return the stored hash, if the account exists */
    Optional<String> findPasswordHash(String username);

    /**
     * @param username existing account
     * @param role     its new role
     * @return the updated user
     */
    User updateRole(String username, Role role);
}
