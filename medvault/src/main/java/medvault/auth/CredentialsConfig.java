package medvault.auth;

/**
 * Bootstrap credentials (the first admin account, the database password).
 *
 * <p><b>CWE-798: Use of Hard-coded Credentials.</b> Nothing secret is
 * written in this class or anywhere else in the repository. Values come from
 * the environment ({@code MEDVAULT_ADMIN_PASSWORD}, {@code MEDVAULT_DB_PASSWORD});
 * if they are missing the app refuses to start.</p>
 *
 * @author Ian Beebe
 */
public final class CredentialsConfig {
    private final char[] adminPassword;
    private final char[] databasePassword;

    private CredentialsConfig(char[] adminPassword, char[] databasePassword) {
        this.adminPassword = adminPassword;
        this.databasePassword = databasePassword;
    }

    /**
     * @return config read from environment variables
     * @throws IllegalStateException if a required variable is not set
     */
    public static CredentialsConfig fromEnvironment() {
        // TODO(Ian) CWE-798: System.getenv(...), fail fast if null or blank.
        throw new UnsupportedOperationException("TODO(Ian): CWE-798");
    }

    /** @return a copy of the bootstrap admin password */
    public char[] adminPassword() {
        return adminPassword.clone();
    }

    /** @return a copy of the database password */
    public char[] databasePassword() {
        return databasePassword.clone();
    }
}
