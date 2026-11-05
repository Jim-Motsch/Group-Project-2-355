package medvault.security;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * The single source of randomness for security decisions in MedVault:
 * session tokens, password salts, and AES-GCM IVs.
 *
 * <p><b>CWE-338: Use of Cryptographically Weak PRNG.</b> Backed by one
 * {@link SecureRandom} per instance (the app creates exactly one instance and
 * injects it everywhere). {@link java.util.Random} and {@code Math.random()}
 * are linear congruential generators: after seeing a few outputs an attacker
 * can compute every past and future value, so a session token made from them
 * could be predicted and hijacked. {@code SecureRandom} is seeded from the
 * operating system's entropy source and is not predictable from its output.</p>
 *
 * @author Jimmy Motsch
 */
public class TokenGenerator {

    /** 32 bytes = 256 bits of entropy per session token. */
    static final int TOKEN_BYTES = 32;

    private static final Base64.Encoder URL_SAFE = Base64.getUrlEncoder().withoutPadding();

    private final SecureRandom random;

    /** Creates a generator backed by the platform's default {@link SecureRandom}. */
    public TokenGenerator() {
        this.random = new SecureRandom();
    }

    /**
     * Creates a new session token.
     *
     * @return a URL-safe Base64 token with 256 bits of entropy (43 characters)
     */
    public String newSessionToken() {
        return URL_SAFE.encodeToString(randomBytes(TOKEN_BYTES));
    }

    /**
     * Returns fresh random bytes.
     *
     * @param length number of random bytes, must be positive
     * @return {@code length} random bytes (used for salts and IVs)
     * @throws IllegalArgumentException if {@code length} is not positive
     */
    public byte[] randomBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
