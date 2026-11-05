package medvault.security;

/**
 * The single source of randomness for security decisions in MedVault:
 * session tokens, password salts, and AES-GCM IVs.
 *
 * <p><b>CWE-338: Use of Cryptographically Weak PRNG.</b> Back this class
 * with one shared {@link java.security.SecureRandom}. Never use
 * {@link java.util.Random} or {@code Math.random()} for anything here.</p>
 *
 * @author Jimmy Motsch
 */
public class TokenGenerator {

    /**
     * @return a URL-safe Base64 token with at least 256 bits of entropy
     */
    public String newSessionToken() {
        // TODO(Jimmy) CWE-338
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-338");
    }

    /**
     * @param length number of random bytes
     * @return {@code length} random bytes (used for salts and IVs)
     */
    public byte[] randomBytes(int length) {
        // TODO(Jimmy) CWE-338
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-338");
    }
}
