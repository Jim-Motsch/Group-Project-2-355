package medvault.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Computes integrity hashes (fingerprints) of data such as lab-report files
 * and backups, so a later copy can be checked for tampering or corruption.
 *
 * <p><b>CWE-328: Use of Weak Hash.</b> MD5 and SHA-1 are broken: attackers
 * can build two different files with the same MD5 or SHA-1 hash, so a forged
 * lab report could pass an integrity check made with them. This class uses
 * SHA-256 by default and only accepts the SHA-2 family (SHA-256, SHA-384,
 * SHA-512). Asking for MD5, SHA-1 or anything else not on that allow-list is
 * refused with an {@link IllegalArgumentException}; there is no way to get a
 * weak digest from it. Comparisons use {@link MessageDigest#isEqual}, which
 * takes the same time wherever the values differ.</p>
 *
 * <p>This is for integrity, not passwords: passwords use slow, salted
 * PBKDF2 ({@code medvault.auth.PasswordHasher}, CWE-916).</p>
 *
 * @author Jimmy Motsch
 */
public final class IntegrityHasher {

    /** The default and recommended algorithm. */
    public static final String DEFAULT_ALGORITHM = "SHA-256";

    /** The only algorithms this class will use. MD5 and SHA-1 are deliberately absent. */
    static final Set<String> ALLOWED = Set.of("SHA-256", "SHA-384", "SHA-512");

    private final String algorithm;

    /** Uses SHA-256. */
    public IntegrityHasher() {
        this(DEFAULT_ALGORITHM);
    }

    /**
     * @param algorithm one of SHA-256, SHA-384, SHA-512
     * @throws IllegalArgumentException for MD5, SHA-1 or any other algorithm
     */
    public IntegrityHasher(String algorithm) {
        String name = algorithm == null ? "" : algorithm.trim().toUpperCase(Locale.ROOT);
        if (!ALLOWED.contains(name)) {
            throw new IllegalArgumentException("integrity hashes must use SHA-256, SHA-384 or SHA-512");
        }
        this.algorithm = name;
    }

    /** @return the algorithm in use, for example {@code SHA-256} */
    public String algorithm() {
        return algorithm;
    }

    /**
     * @param data bytes to fingerprint
     * @return lower-case hex digest
     */
    public String hashHex(byte[] data) {
        Objects.requireNonNull(data, "data");
        return HexFormat.of().formatHex(digest().digest(data));
    }

    /**
     * Hashes a stream without loading it into memory. The caller closes it.
     *
     * @param in data to fingerprint
     * @return lower-case hex digest
     * @throws IOException if the stream can't be read
     */
    public String hashHex(InputStream in) throws IOException {
        Objects.requireNonNull(in, "in");
        MessageDigest md = digest();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            md.update(buf, 0, n);
        }
        return HexFormat.of().formatHex(md.digest());
    }

    /**
     * @param data        bytes to check
     * @param expectedHex a digest produced by {@link #hashHex(byte[])}
     * @return true if the data still has that fingerprint
     */
    public boolean matches(byte[] data, String expectedHex) {
        if (data == null || expectedHex == null) {
            return false;
        }
        byte[] expected;
        try {
            expected = HexFormat.of().parseHex(expectedHex.toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException notHex) {
            return false;
        }
        return MessageDigest.isEqual(digest().digest(data), expected);
    }

    private MessageDigest digest() {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256/384/512 are mandatory on every Java runtime.
            throw new IllegalStateException("hash algorithm unavailable", e);
        }
    }
}
