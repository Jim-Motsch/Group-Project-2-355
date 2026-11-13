package medvault.model;

import java.util.Objects;

/**
 * An account that can log in to MedVault.
 *
 * <p>Immutable: role changes produce a new {@code User} through
 * {@link medvault.access.RoleManager}, so a caller can never change its own
 * role by mutating an object it was handed.</p>
 */
public final class User {
    private final String username;
    private final Role role;

    /**
     * Creates a user.
     *
     * @param username unique login name, not null
     * @param role     the user's role, not null
     */
    public User(String username, Role role) {
        this.username = Objects.requireNonNull(username, "username");
        this.role = Objects.requireNonNull(role, "role");
    }

    /** @return the unique login name */
    public String getUsername() {
        return username;
    }

    /** @return the user's role */
    public Role getRole() {
        return role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof User)) {
            return false;
        }
        User other = (User) o;
        return username.equals(other.username) && role == other.role;
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, role);
    }

    /** Never prints anything sensitive (CWE-779). */
    @Override
    public String toString() {
        return "User[" + username + ", " + role + "]";
    }
}
