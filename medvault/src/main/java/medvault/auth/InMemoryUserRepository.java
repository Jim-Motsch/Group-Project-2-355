package medvault.auth;

import medvault.model.Role;
import medvault.model.User;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory {@link UserRepository}. Good enough for the demo;
 * could be swapped for a JDBC version without touching callers.
 *
 * @author Ian Beebe
 */
public class InMemoryUserRepository implements UserRepository {
    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final Map<String, String> hashes = new ConcurrentHashMap<>();

    @Override
    public void save(User user, String passwordHash) {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(passwordHash, "passwordHash");
        users.put(user.getUsername(), user);
        hashes.put(user.getUsername(), passwordHash);
    }

    @Override
    public Optional<User> find(String username) {
        return Optional.ofNullable(users.get(username));
    }

    @Override
    public Optional<String> findPasswordHash(String username) {
        return Optional.ofNullable(hashes.get(username));
    }

    @Override
    public User updateRole(String username, Role role) {
        User updated = new User(username, role);
        if (users.replace(username, updated) == null) {
            throw new IllegalArgumentException("No such user");
        }
        return updated;
    }
}
