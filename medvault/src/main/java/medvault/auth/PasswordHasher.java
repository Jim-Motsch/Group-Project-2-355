package medvault.auth;

import medvault.security.TokenGenerator;

import java.util.Objects;

/**
 * Hashes and verifies passwords.
 *
 * <p><b>CWE-916: Use of Password Hash With Insufficient Computational
 * Effort.</b> Use PBKDF2WithHmacSHA256 with at least 210,000 iterations,
 * never a single SHA-256 or MD5.</p>
 *
 * <p><b>CWE-759: Use of a One-Way Hash without a Salt.</b> Every password
 * gets its own 16-byte random salt from {@link TokenGenerator}, stored next
 * to the hash, so two users with the same password get different hashes.</p>
 *
 * @author Ian Beebe
 */
public class PasswordHasher {

    /** PBKDF2 iteration count (OWASP 2023 guidance for HMAC-SHA256). */
    public static final int ITERATIONS = 210_000;

    private final TokenGenerator random;

    /** @param random source of salts */
    public PasswordHasher(TokenGenerator random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * @param password plaintext password; caller should wipe it afterwards
     * @return encoded {@code iterations:saltBase64:hashBase64}
     */
    public String hash(char[] password) {
        // TODO(Ian) CWE-916 / CWE-759
        throw new UnsupportedOperationException("TODO(Ian): CWE-916, CWE-759");
    }

    /**
     * @param password candidate password
     * @param stored   value produced by {@link #hash(char[])}
     * @return true if it matches; compare with {@code MessageDigest.isEqual}
     */
    public boolean verify(char[] password, String stored) {
        // TODO(Ian) CWE-916 / CWE-759
        throw new UnsupportedOperationException("TODO(Ian): CWE-916, CWE-759");
    }
}
