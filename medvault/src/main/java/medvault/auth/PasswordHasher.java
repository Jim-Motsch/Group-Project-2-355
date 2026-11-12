package medvault.auth;

import medvault.security.TokenGenerator;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Hashes and verifies passwords.
 *
 * <p><b>CWE-916: Use of Password Hash With Insufficient Computational
 * Effort.</b> A single SHA-256 or MD5 can be computed billions of times a
 * second on a GPU, so a stolen hash table falls to brute force in hours. This
 * class uses PBKDF2WithHmacSHA256 with {@link #ITERATIONS} rounds, which makes
 * every guess cost the attacker the same ~0.1&nbsp;s it costs us. Stored hashes
 * with fewer rounds are refused rather than silently accepted, so an attacker
 * who can edit the user store cannot downgrade an account to a cheap hash.</p>
 *
 * <p>Salting is part of the same defense: without a salt, equal passwords
 * give equal hashes and one precomputed (rainbow) table cracks every account
 * at once. Every password gets its own 16-byte random salt from
 * {@link TokenGenerator}, stored next to the hash as
 * {@code iterations:saltBase64:hashBase64}, so two users with the same
 * password get different hashes. Hashes are compared with
 * {@link MessageDigest#isEqual}, which takes the same time whether the first
 * or the last byte differs.</p>
 *
 * @author Ian Beebe
 */
public class PasswordHasher {

    /** PBKDF2 iteration count (OWASP 2023 guidance for HMAC-SHA256). */
    public static final int ITERATIONS = 210_000;

    /** Salt length in bytes. */
    static final int SALT_BYTES = 16;
    /** Derived hash length in bits. */
    static final int HASH_BITS = 256;
    /** Upper bound on a stored iteration count, so a tampered entry can't stall a login. */
    private static final int MAX_ITERATIONS = 10_000_000;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

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
        Objects.requireNonNull(password, "password");
        byte[] salt = random.randomBytes(SALT_BYTES);
        byte[] hash = derive(password, salt, ITERATIONS);
        try {
            Base64.Encoder b64 = Base64.getEncoder();
            return ITERATIONS + ":" + b64.encodeToString(salt) + ":" + b64.encodeToString(hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * @param password candidate password
     * @param stored   value produced by {@link #hash(char[])}
     * @return true if it matches; compare with {@code MessageDigest.isEqual}
     */
    public boolean verify(char[] password, String stored) {
        if (password == null || stored == null) {
            return false;
        }
        String[] parts = stored.split(":", -1);
        if (parts.length != 3) {
            return false;
        }
        int iterations;
        byte[] salt;
        byte[] expected;
        try {
            iterations = Integer.parseInt(parts[0]);
            salt = Base64.getDecoder().decode(parts[1]);
            expected = Base64.getDecoder().decode(parts[2]);
        } catch (IllegalArgumentException malformed) {
            return false;
        }
        if (iterations < ITERATIONS || iterations > MAX_ITERATIONS
                || salt.length != SALT_BYTES || expected.length != HASH_BITS / 8) {
            return false;
        }
        byte[] actual = derive(password, salt, iterations);
        try {
            return MessageDigest.isEqual(actual, expected);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            // PBKDF2WithHmacSHA256 is mandatory on every Java 17 runtime.
            throw new IllegalStateException("password hashing unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}
