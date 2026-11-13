package medvault.security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Function;

/**
 * Supplies the AES key used to encrypt patient records at rest.
 *
 * <p>The key is never hard-coded (the same rule CWE-798 applies to
 * passwords). A key written in source code is shared by every installation
 * and readable by anyone with the repository or the compiled JAR, so it
 * protects nothing. This class contains
 * no key and no fallback: it reads the {@code MEDVAULT_RECORD_KEY} environment
 * variable (Base64, exactly 32 bytes) and throws if it is missing or malformed,
 * so the app refuses to start rather than run with a guessable key.</p>
 *
 * @author Jimmy Motsch
 */
public class KeyProvider {

    /** Name of the environment variable that holds the Base64 key. */
    public static final String KEY_ENV_VAR = "MEDVAULT_RECORD_KEY";

    /** Required key length: 32 bytes = AES-256. */
    static final int KEY_BYTES = 32;

    private final Function<String, String> env;

    /** Reads the key from the real process environment. */
    public KeyProvider() {
        this(System::getenv);
    }

    /**
     * Reads the key through a custom lookup, so tests can supply a key
     * without setting real environment variables.
     *
     * @param env maps a variable name to its value, or null if unset
     */
    public KeyProvider(Function<String, String> env) {
        this.env = Objects.requireNonNull(env, "env");
    }

    /**
     * Loads the record-encryption key.
     *
     * @return a 256-bit AES key
     * @throws IllegalStateException if no key is configured or it is not
     *         Base64 for exactly 32 bytes; the app must refuse to start
     *         rather than fall back to a built-in key
     */
    public SecretKey loadRecordKey() {
        String encoded = env.apply(KEY_ENV_VAR);
        if (encoded == null || encoded.isBlank()) {
            throw new IllegalStateException(KEY_ENV_VAR + " is not set; refusing to start without a record key");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(encoded.trim());
        } catch (IllegalArgumentException notBase64) {
            // Never echo the value: even a malformed key is secret material.
            throw new IllegalStateException(KEY_ENV_VAR + " is not valid Base64");
        }
        try {
            if (raw.length != KEY_BYTES) {
                throw new IllegalStateException(KEY_ENV_VAR + " must decode to " + KEY_BYTES
                        + " bytes (AES-256)");
            }
            return new SecretKeySpec(raw, "AES"); // SecretKeySpec keeps its own copy
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }
}
