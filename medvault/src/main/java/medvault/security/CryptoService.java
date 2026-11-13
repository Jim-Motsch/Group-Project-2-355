package medvault.security;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Encrypts and decrypts sensitive fields (clinical notes) before they are
 * written to the database.
 *
 * <p><b>CWE-1204: Generation of Weak Initialization Vector (IV).</b> AES-GCM
 * is only secure if no IV is ever reused with the same key: two notes
 * encrypted under one IV leak the XOR of their plaintexts, and a repeated IV
 * also lets an attacker forge the authentication tag. A fixed, zero, counter
 * or timestamp IV fails this. {@link #encrypt} asks {@link TokenGenerator}
 * (backed by {@code SecureRandom}) for a fresh, unpredictable 12-byte IV for
 * every single message and stores it in front of the ciphertext, so the same
 * note encrypts differently every time and patterns between patients can't
 * be spotted.</p>
 *
 * <p>The cipher is {@code AES/GCM/NoPadding} with a 256-bit key and a 128-bit
 * authentication tag, so a modified ciphertext is rejected instead of
 * decrypting to altered data. The constructor refuses any key that is not a
 * 256-bit AES key.</p>
 *
 * @author Jimmy Motsch
 */
public class CryptoService {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    static final int IV_BYTES = 12;
    static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / 8;
    private static final int KEY_BYTES = 32;

    private final SecretKey key;
    private final TokenGenerator random;

    /**
     * @param key    the record key from {@link KeyProvider}; must be a 256-bit AES key
     * @param random source of IVs
     * @throws IllegalArgumentException if the key is not a 256-bit AES key
     */
    public CryptoService(SecretKey key, TokenGenerator random) {
        this.key = Objects.requireNonNull(key, "key");
        this.random = Objects.requireNonNull(random, "random");
        byte[] encoded = key.getEncoded();
        if (!"AES".equalsIgnoreCase(key.getAlgorithm()) || encoded == null || encoded.length != KEY_BYTES) {
            throw new IllegalArgumentException("record key must be a 256-bit AES key");
        }
        Arrays.fill(encoded, (byte) 0);
    }

    /**
     * Encrypts plaintext.
     *
     * @param plaintext text to protect, not null
     * @return Base64 of {@code IV || ciphertext || tag}
     */
    public String encrypt(String plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
        byte[] iv = random.randomBytes(IV_BYTES);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(
                    ByteBuffer.allocate(iv.length + sealed.length).put(iv).put(sealed).array());
        } catch (GeneralSecurityException e) {
            // AES-GCM is mandatory on every Java 17 runtime, so this means a broken JVM.
            throw new IllegalStateException("encryption unavailable", e);
        }
    }

    /**
     * Decrypts a value produced by {@link #encrypt(String)}.
     *
     * @param encoded Base64 of {@code IV || ciphertext || tag}
     * @return the plaintext
     * @throws SecurityException if the value is malformed or the tag does not
     *         verify (data was tampered with or encrypted under another key)
     */
    public String decrypt(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException notBase64) {
            throw new SecurityException("encrypted record is malformed");
        }
        if (blob.length < IV_BYTES + TAG_BYTES) {
            throw new SecurityException("encrypted record is malformed");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, blob, 0, IV_BYTES));
            byte[] plain = cipher.doFinal(blob, IV_BYTES, blob.length - IV_BYTES);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (AEADBadTagException tampered) {
            throw new SecurityException("encrypted record failed its integrity check");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("decryption unavailable", e);
        }
    }
}
