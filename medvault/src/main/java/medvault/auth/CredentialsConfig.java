package medvault.auth;

import java.util.Objects;
import java.util.function.Function;

/**
 * Bootstrap credentials (the first admin account, the database password).
 *
 * <p><b>CWE-798: Use of Hard-coded Credentials.</b> A password written in
 * source code is the same on every install, is visible to anyone with the
 * repository or the JAR, and can't be changed without a new release. Nothing
 * secret is written in this class or anywhere else in the repository. Values
 * come from the environment ({@code MEDVAULT_ADMIN_PASSWORD},
 * {@code MEDVAULT_DB_PASSWORD}); if either is missing or blank the app refuses
 * to start rather than fall back to a default.</p>
 *
 * @author Ian Beebe
 */
public final class CredentialsConfig {

    /** Environment variable holding the bootstrap admin password. */
    public static final String ADMIN_PASSWORD_ENV = "MEDVAULT_ADMIN_PASSWORD";
    /** Environment variable holding the database password. */
    public static final String DB_PASSWORD_ENV = "MEDVAULT_DB_PASSWORD";

    private final char[] adminPassword;
    private final char[] databasePassword;

    private CredentialsConfig(char[] adminPassword, char[] databasePassword) {
        this.adminPassword = adminPassword;
        this.databasePassword = databasePassword;
    }

    /**
     * Reads the credentials through a custom lookup, so tests can supply
     * values without setting real environment variables. Values are trimmed.
     *
     * @param env maps a variable name to its value, or null if unset
     * @throws IllegalStateException if a required variable is unset or blank
     */
    public CredentialsConfig(Function<String, String> env) {
        this(require(Objects.requireNonNull(env, "env"), ADMIN_PASSWORD_ENV),
                require(env, DB_PASSWORD_ENV));
    }

    /**
     * @return config read from environment variables
     * @throws IllegalStateException if a required variable is not set
     */
    public static CredentialsConfig fromEnvironment() {
        return new CredentialsConfig(System::getenv);
    }

    /** Looks up one variable; fails fast if missing. Never echoes the value. */
    private static char[] require(Function<String, String> env, String name) {
        String value = env.apply(name);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException(name + " is not set; refusing to start without it");
        }
        return value.trim().toCharArray();
    }

    /** @return a copy of the bootstrap admin password */
    public char[] adminPassword() {
        return adminPassword.clone();
    }

    /** @return a copy of the database password */
    public char[] databasePassword() {
        return databasePassword.clone();
    }

    /** Never prints the passwords, so they can't end up in a log (CWE-779). */
    @Override
    public String toString() {
        return "CredentialsConfig[***]";
    }
}
