package medvault.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack tests for the security package. Each nested class covers one CWE:
 * the tests attempt the attack and assert it fails, and one test shows the
 * legitimate case works.
 *
 * @author Jimmy Motsch
 */
class SecurityAttackTest {

    private static SecretKey newAesKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        return gen.generateKey();
    }

    private static String base64Key(int bytes) {
        return Base64.getEncoder().encodeToString(new TokenGenerator().randomBytes(bytes));
    }

    /** CWE-327: Use of a Broken or Risky Cryptographic Algorithm. */
    @Nested
    class Cwe327BrokenCrypto {
        private final TokenGenerator random = new TokenGenerator();

        @Test
        void legitimateNoteRoundTrips() throws Exception {
            CryptoService crypto = new CryptoService(newAesKey(), random);
            String note = "Pt reports chest pain, ECG ordered. Allergy: penicillin. ünïcödé ✓";
            assertEquals(note, crypto.decrypt(crypto.encrypt(note)));
            assertEquals("", crypto.decrypt(crypto.encrypt("")));
        }

        @Test
        void ciphertextIsIvPlusCiphertextPlusTagAndHidesPlaintext() throws Exception {
            CryptoService crypto = new CryptoService(newAesKey(), random);
            String note = "HIV positive";
            byte[] blob = Base64.getDecoder().decode(crypto.encrypt(note));
            assertEquals(CryptoService.IV_BYTES + note.getBytes(StandardCharsets.UTF_8).length
                    + CryptoService.TAG_BITS / 8, blob.length);
            assertFalse(new String(blob, StandardCharsets.ISO_8859_1).contains(note));
        }

        @Test
        void sameNoteTwiceGivesDifferentCiphertext() throws Exception {
            // Attack: spot two patients with the same diagnosis by comparing ciphertext.
            CryptoService crypto = new CryptoService(newAesKey(), random);
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < 100; i++) {
                assertTrue(seen.add(crypto.encrypt("Diagnosis: diabetes type 2")));
            }
        }

        @Test
        void repeatedBlocksDoNotRepeatInCiphertext() throws Exception {
            // Attack: ECB mode turns equal 16-byte plaintext blocks into equal ciphertext blocks.
            CryptoService crypto = new CryptoService(newAesKey(), random);
            byte[] blob = Base64.getDecoder().decode(crypto.encrypt("A".repeat(16 * 8)));
            Set<String> blocks = new HashSet<>();
            for (int off = CryptoService.IV_BYTES; off + 16 <= CryptoService.IV_BYTES + 16 * 8; off += 16) {
                blocks.add(Base64.getEncoder().encodeToString(java.util.Arrays.copyOfRange(blob, off, off + 16)));
            }
            assertEquals(8, blocks.size(), "identical plaintext blocks leaked as identical ciphertext blocks");
        }

        @Test
        void flippingAnyByteIsDetected() throws Exception {
            // Attack: edit stored ciphertext (IV, body, or tag) to alter the note without the key.
            CryptoService crypto = new CryptoService(newAesKey(), random);
            byte[] blob = Base64.getDecoder().decode(crypto.encrypt("Dose: 5 mg"));
            for (int i = 0; i < blob.length; i++) {
                byte[] tampered = blob.clone();
                tampered[i] ^= 0x01;
                String forged = Base64.getEncoder().encodeToString(tampered);
                assertThrows(SecurityException.class, () -> crypto.decrypt(forged), "byte " + i);
            }
        }

        @Test
        void truncatedGarbageOrForeignKeyCiphertextIsRejected() throws Exception {
            CryptoService crypto = new CryptoService(newAesKey(), random);
            CryptoService other = new CryptoService(newAesKey(), random);
            String sealed = crypto.encrypt("note");
            assertThrows(SecurityException.class, () -> other.decrypt(sealed));
            assertThrows(SecurityException.class, () -> crypto.decrypt(sealed.substring(0, 12)));
            assertThrows(SecurityException.class, () -> crypto.decrypt("not base64 !!!"));
            assertThrows(SecurityException.class, () -> crypto.decrypt(""));
        }

        @Test
        void weakOrWrongSizeKeysAreRefused() throws Exception {
            // Attack: wire the service with a DES key or a short AES key.
            SecretKey des = KeyGenerator.getInstance("DES").generateKey();
            SecretKey aes128 = new SecretKeySpec(random.randomBytes(16), "AES");
            assertThrows(IllegalArgumentException.class, () -> new CryptoService(des, random));
            assertThrows(IllegalArgumentException.class, () -> new CryptoService(aes128, random));
        }

        @Test
        void ivComesFromTokenGenerator() throws Exception {
            List<Integer> requested = new ArrayList<>();
            TokenGenerator spy = new TokenGenerator() {
                @Override
                public byte[] randomBytes(int length) {
                    requested.add(length);
                    return super.randomBytes(length);
                }
            };
            new CryptoService(newAesKey(), spy).encrypt("x");
            assertEquals(List.of(CryptoService.IV_BYTES), requested);
        }
    }

    /** CWE-321: Use of Hard-coded Cryptographic Key. */
    @Nested
    class Cwe321HardCodedKey {

        @Test
        void legitimateKeyFromEnvironmentLoads() {
            byte[] raw = new TokenGenerator().randomBytes(32);
            String encoded = Base64.getEncoder().encodeToString(raw);
            SecretKey key = new KeyProvider(Map.of(KeyProvider.KEY_ENV_VAR, encoded)::get).loadRecordKey();
            assertEquals("AES", key.getAlgorithm());
            assertArrayEquals(raw, key.getEncoded());
        }

        @Test
        void missingKeyFailsFastInsteadOfUsingABuiltInKey() {
            KeyProvider noEnv = new KeyProvider(name -> null);
            IllegalStateException e = assertThrows(IllegalStateException.class, noEnv::loadRecordKey);
            assertTrue(e.getMessage().contains(KeyProvider.KEY_ENV_VAR));
            assertThrows(IllegalStateException.class, () -> new KeyProvider(name -> "   ").loadRecordKey());
        }

        @Test
        void differentEnvironmentsGetDifferentKeys() {
            // If there were a hidden default key, both installs would share it.
            SecretKey a = new KeyProvider(Map.of(KeyProvider.KEY_ENV_VAR, base64Key(32))::get).loadRecordKey();
            SecretKey b = new KeyProvider(Map.of(KeyProvider.KEY_ENV_VAR, base64Key(32))::get).loadRecordKey();
            assertFalse(java.util.Arrays.equals(a.getEncoded(), b.getEncoded()));
        }

        @Test
        void weakOrMalformedKeysAreRejectedWithoutEchoingThem() {
            for (String bad : List.of(base64Key(16), base64Key(31), base64Key(33), "password123!", "%%%%")) {
                KeyProvider p = new KeyProvider(Map.of(KeyProvider.KEY_ENV_VAR, bad)::get);
                IllegalStateException e = assertThrows(IllegalStateException.class, p::loadRecordKey, bad);
                assertFalse(e.getMessage().contains(bad), "error message leaked the configured value");
            }
        }

        @Test
        void sourceTreeContainsNoKeyLiteral() throws IOException {
            // Attack: read the repo/JAR and pull out an embedded AES key.
            Pattern base64Key256 = Pattern.compile("\"[A-Za-z0-9+/]{43}=\"");
            Pattern hexKey256 = Pattern.compile("\"[0-9a-fA-F]{64}\"");
            List<String> hits = new ArrayList<>();
            try (Stream<Path> files = Files.walk(Path.of("src", "main", "java"))) {
                for (Path f : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".java"))::iterator) {
                    String src = Files.readString(f);
                    Matcher m1 = base64Key256.matcher(src);
                    Matcher m2 = hexKey256.matcher(src);
                    if (m1.find() || m2.find()) {
                        hits.add(f.toString());
                    }
                }
            }
            assertTrue(hits.isEmpty(), "possible hard-coded key in " + hits);
        }
    }

    /** CWE-338: Use of Cryptographically Weak PRNG. */
    @Nested
    class Cwe338WeakPrng {
        private final TokenGenerator tokens = new TokenGenerator();

        @Test
        void legitimateTokenIsUrlSafeAnd256Bits() {
            String t = tokens.newSessionToken();
            assertTrue(t.matches("[A-Za-z0-9_-]{43}"), t);
            assertEquals(32, Base64.getUrlDecoder().decode(t).length);
            assertEquals(16, tokens.randomBytes(16).length);
        }

        @Test
        void tenThousandTokensAreLongAndUnique() {
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < 10_000; i++) {
                String t = tokens.newSessionToken();
                assertTrue(t.length() >= 43);
                assertTrue(seen.add(t), "duplicate token");
            }
        }

        @Test
        void tokensAreNotPredictableFromJavaUtilRandom() {
            // Attack: guess that tokens come from java.util.Random seeded with the clock
            // and regenerate them. Try every millisecond seed in a +/- 5 s window.
            long now = System.currentTimeMillis();
            String victim = tokens.newSessionToken();
            for (long seed = now - 5_000; seed <= now + 5_000; seed++) {
                byte[] guess = new byte[32];
                new java.util.Random(seed).nextBytes(guess);
                assertNotEquals(victim, Base64.getUrlEncoder().withoutPadding().encodeToString(guess));
            }
        }

        @Test
        void bitsAreBalanced() {
            // A weak or broken generator shows bias; 1 MB of output should be ~50% ones.
            byte[] bytes = tokens.randomBytes(1 << 20);
            long ones = 0;
            for (byte b : bytes) {
                ones += Integer.bitCount(b & 0xFF);
            }
            double ratio = ones / (bytes.length * 8.0);
            assertTrue(Math.abs(ratio - 0.5) < 0.002, "bit ratio " + ratio);
        }

        @Test
        void nonsenseLengthsAreRejected() {
            assertThrows(IllegalArgumentException.class, () -> tokens.randomBytes(0));
            assertThrows(IllegalArgumentException.class, () -> tokens.randomBytes(-1));
        }
    }
}
