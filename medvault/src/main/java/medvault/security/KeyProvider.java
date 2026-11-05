package medvault.security;

import javax.crypto.SecretKey;

/**
 * Supplies the AES key used to encrypt patient records at rest.
 *
 * <p><b>CWE-321: Use of Hard-coded Cryptographic Key.</b> The key must never
 * appear in source code or in the Git repository. Load it from the
 * {@code MEDVAULT_RECORD_KEY} environment variable (Base64, 32 bytes) or
 * from a Java KeyStore whose password also comes from the environment.</p>
 *
 * @author Jimmy Motsch
 */
public class KeyProvider {

    /** Name of the environment variable that holds the Base64 key. */
    public static final String KEY_ENV_VAR = "MEDVAULT_RECORD_KEY";

    /**
     * Loads the record-encryption key.
     *
     * @return a 256-bit AES key
     * @throws IllegalStateException if no key is configured; the app must
     *         refuse to start rather than fall back to a built-in key
     */
    public SecretKey loadRecordKey() {
        // TODO(Jimmy) CWE-321: read KEY_ENV_VAR, Base64-decode, check length == 32,
        //  wrap in SecretKeySpec(bytes, "AES"). No default key in code.
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-321");
    }
}
