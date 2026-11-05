package medvault.security;

import javax.crypto.SecretKey;
import java.util.Objects;

/**
 * Encrypts and decrypts sensitive fields (clinical notes) before they are
 * written to the database.
 *
 * <p><b>CWE-327: Use of a Broken or Risky Cryptographic Algorithm.</b> Use
 * {@code AES/GCM/NoPadding} with a 128-bit tag and a fresh 12-byte IV from
 * {@link TokenGenerator} for every message. Never DES, RC4, or ECB mode.</p>
 *
 * @author Jimmy Motsch
 */
public class CryptoService {
    private final SecretKey key;
    private final TokenGenerator random;

    /**
     * @param key    the record key from {@link KeyProvider}
     * @param random source of IVs
     */
    public CryptoService(SecretKey key, TokenGenerator random) {
        this.key = Objects.requireNonNull(key, "key");
        this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * Encrypts plaintext.
     *
     * @param plaintext text to protect
     * @return Base64 of {@code IV || ciphertext || tag}
     */
    public String encrypt(String plaintext) {
        // TODO(Jimmy) CWE-327: Cipher.getInstance("AES/GCM/NoPadding"), GCMParameterSpec(128, iv)
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-327");
    }

    /**
     * Decrypts a value produced by {@link #encrypt(String)}.
     *
     * @param encoded Base64 of {@code IV || ciphertext || tag}
     * @return the plaintext
     * @throws SecurityException if the tag does not verify (data was tampered with)
     */
    public String decrypt(String encoded) {
        // TODO(Jimmy) CWE-327
        throw new UnsupportedOperationException("TODO(Jimmy): CWE-327");
    }
}
