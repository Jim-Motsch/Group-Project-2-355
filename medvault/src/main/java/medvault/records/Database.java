package medvault.records;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;

/**
 * Opens connections to the embedded H2 database and creates the schema.
 *
 * <p>Callers must close every {@link Connection}, {@code PreparedStatement}
 * and {@code ResultSet} with try-with-resources (CWE-772).</p>
 *
 * @author James Strickert
 */
public class Database {
    private final String url;
    private final String user;
    private final char[] password;

    /**
     * @param url      JDBC url, for example {@code jdbc:h2:mem:medvault;DB_CLOSE_DELAY=-1}
     * @param user     database user
     * @param password database password from {@link medvault.auth.CredentialsConfig} (CWE-798)
     */
    public Database(String url, String user, char[] password) {
        this.url = Objects.requireNonNull(url, "url");
        this.user = Objects.requireNonNull(user, "user");
        this.password = Objects.requireNonNull(password, "password").clone();
    }

    /** @return a new connection; the caller closes it */
    public Connection connect() throws SQLException {
        return DriverManager.getConnection(url, user, new String(password));
    }

    /** Creates the tables if they do not exist. */
    public void createSchema() throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement()) {
            s.execute("CREATE TABLE IF NOT EXISTS patient ("
                    + " id BIGINT AUTO_INCREMENT PRIMARY KEY,"
                    + " full_name VARCHAR(200) NOT NULL,"
                    + " date_of_birth DATE NOT NULL,"
                    + " attending VARCHAR(100) NOT NULL,"
                    + " notes_encrypted CLOB)");
        }
    }
}
