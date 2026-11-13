package medvault.auth;

import medvault.audit.AuditLogger;
import medvault.audit.LogSanitizer;
import medvault.model.AccessDeniedException;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.model.ValidationException;
import medvault.security.TokenGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack tests for the auth package. Each test attempts the attack for one
 * CWE and asserts it fails; the legitimate case is tested alongside. Uses real
 * objects throughout (PBKDF2, SessionManager, in-memory user store) and
 * captures the real {@code medvault.audit} logger.
 *
 * @author Ian Beebe
 */
class AuthAttackTest {

    // ---- audit capture, so tests can check what was logged ----

    private final List<String> auditLines = Collections.synchronizedList(new ArrayList<>());
    private final Logger auditLog = Logger.getLogger("medvault.audit");
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            auditLines.add(record.getMessage());
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @BeforeEach
    void captureAudit() {
        auditLog.addHandler(capture);
        auditLog.setUseParentHandlers(false);
    }

    @AfterEach
    void releaseAudit() {
        auditLog.removeHandler(capture);
        auditLog.setUseParentHandlers(true);
    }

    private final PasswordPolicy policy = new PasswordPolicy();
    private final PasswordHasher hasher = new PasswordHasher(new TokenGenerator());

    // ---- CWE-521: Weak Password Requirements ----

    @Test
    void rejectsShortOrCommonPassword() {
        // Attack: register with passwords a dictionary attack would try first.
        List<String[]> weak = List.of(
                new String[] {"nurse1", "password123"},             // too short
                new String[] {"nurse1", "Summer26!"},               // too short
                new String[] {"nurse1", "password1234"},            // common
                new String[] {"nurse1", "QWERTY123456"},            // common, case doesn't help
                new String[] {"nurse.joy", "my-NURSE.JOY-password"}, // contains the username
                new String[] {"nurse1", "zzzzzzzzzzzzzzzz"},        // one repeated character
                new String[] {"nurse1", ""});
        for (String[] w : weak) {
            ValidationException e = assertThrows(ValidationException.class,
                    () -> policy.check(w[0], w[1].toCharArray()), w[1]);
            if (!w[1].isEmpty()) {
                assertFalse(e.getMessage().contains(w[1]), "message echoed the password");
            }
        }
        assertThrows(ValidationException.class, () -> policy.check("nurse1", null));
        assertThrows(ValidationException.class, () -> policy.check("nurse1", "x".repeat(10_000).toCharArray()));

        // Legitimate: a long passphrase passes, and the caller's array is not modified.
        char[] good = "correct horse battery staple".toCharArray();
        policy.check("nurse1", good);
        assertArrayEquals("correct horse battery staple".toCharArray(), good);
    }

    // ---- CWE-916: Password Hash With Insufficient Computational Effort ----

    @Test
    void hashUsesPbkdf2WithManyIterations() throws Exception {
        char[] pw = "correct horse battery staple".toCharArray();
        String stored = hasher.hash(pw);
        assertTrue(stored.startsWith(PasswordHasher.ITERATIONS + ":"), stored);
        assertTrue(PasswordHasher.ITERATIONS >= 210_000);
        assertTrue(hasher.verify(pw, stored), "right password must verify");
        assertFalse(hasher.verify("correct horse battery stapler".toCharArray(), stored), "wrong password");

        // The stored value really is PBKDF2-HMAC-SHA256 with that many rounds: recompute it independently.
        String[] parts = stored.split(":");
        byte[] salt = Base64.getDecoder().decode(parts[1]);
        byte[] expected = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec(pw, salt, PasswordHasher.ITERATIONS, 256)).getEncoded();
        assertArrayEquals(expected, Base64.getDecoder().decode(parts[2]));

        // Attack: someone with write access to the user store downgrades the hash to 1,000 rounds
        // (or to a plain value) so it can be cracked quickly. A correct PBKDF2 at 1,000 rounds is refused.
        byte[] cheap = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec(pw, salt, 1_000, 256)).getEncoded();
        String downgraded = "1000:" + parts[1] + ":" + Base64.getEncoder().encodeToString(cheap);
        assertFalse(hasher.verify(pw, downgraded));
        // Malformed or tampered entries fail closed instead of throwing.
        for (String bad : List.of("", "plain", "210000:abc", "210000:!!!:???", "x:y:z",
                "999999999:" + parts[1] + ":" + parts[2])) {
            assertFalse(hasher.verify(pw, bad), bad);
        }
        assertFalse(hasher.verify(pw, null));
        assertFalse(hasher.verify(null, stored));
    }

    // ---- CWE-916 (continued): every hash gets its own salt ----

    @Test
    void samePasswordGivesDifferentHashes() {
        // Attack: spot users who share a password (or use a rainbow table) by comparing hashes.
        List<Integer> saltRequests = new ArrayList<>();
        TokenGenerator spy = new TokenGenerator() {
            @Override
            public byte[] randomBytes(int length) {
                saltRequests.add(length);
                return super.randomBytes(length);
            }
        };
        PasswordHasher spied = new PasswordHasher(spy);
        char[] pw = "correct horse battery staple".toCharArray();
        String a = spied.hash(pw);
        String b = spied.hash(pw);
        assertNotEquals(a, b, "same password must not give the same hash");
        assertNotEquals(a.split(":")[1], b.split(":")[1], "each hash gets its own salt");
        assertEquals(List.of(16, 16), saltRequests, "16-byte salts come from TokenGenerator");
        assertTrue(spied.verify(pw, a) && spied.verify(pw, b), "both still verify");
    }

    // ---- CWE-307: Improper Restriction of Excessive Authentication Attempts ----

    @Test
    void locksAccountAfterFiveFailures() {
        LoginAttemptTracker tracker = new LoginAttemptTracker(clock);
        for (int i = 1; i < LoginAttemptTracker.MAX_FAILURES; i++) {
            tracker.recordFailure("nurse.joy");
            assertFalse(tracker.isLocked("nurse.joy"), "locked too early after " + i);
        }
        tracker.recordFailure("nurse.joy");
        assertTrue(tracker.isLocked("nurse.joy"), "fifth failure locks");
        assertFalse(tracker.isLocked("dr.house"), "other accounts unaffected");

        // More guesses during the lockout don't extend or end it.
        clock.advance(LoginAttemptTracker.LOCKOUT.minusMillis(1));
        tracker.recordFailure("nurse.joy");
        assertTrue(tracker.isLocked("nurse.joy"));
        clock.advance(Duration.ofMillis(1));
        assertFalse(tracker.isLocked("nurse.joy"), "lock ends after 15 minutes");

        // A success resets the counter; the next lock again needs five failures.
        tracker.recordFailure("nurse.joy");
        tracker.recordSuccess("nurse.joy");
        for (int i = 1; i < LoginAttemptTracker.MAX_FAILURES; i++) {
            tracker.recordFailure("nurse.joy");
        }
        assertFalse(tracker.isLocked("nurse.joy"));
    }

    @Test
    void parallelGuessesCannotRacePastTheLimit() throws Exception {
        // Attack: fire guesses in parallel hoping several read the same old counter.
        LoginAttemptTracker tracker = new LoginAttemptTracker(clock);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            for (int round = 0; round < 200; round++) {
                String four = "four-" + round;
                String five = "five-" + round;
                CountDownLatch go = new CountDownLatch(1);
                List<Future<?>> work = new ArrayList<>();
                for (int t = 0; t < LoginAttemptTracker.MAX_FAILURES; t++) {
                    boolean extra = t == LoginAttemptTracker.MAX_FAILURES - 1;
                    work.add(pool.submit(() -> {
                        go.await();
                        tracker.recordFailure(five);
                        if (!extra) {
                            tracker.recordFailure(four);
                        }
                        return null;
                    }));
                }
                go.countDown();
                for (Future<?> f : work) {
                    f.get(10, TimeUnit.SECONDS);
                }
                assertTrue(tracker.isLocked(five), "exactly five parallel failures must lock");
                assertFalse(tracker.isLocked(four), "four failures must not lock");
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private DefaultAuthService newAuthService(InMemoryUserRepository users) {
        AuditLogger audit = new AuditLogger(new LogSanitizer());
        return new DefaultAuthService(users, policy, hasher, new LoginAttemptTracker(clock), sessions, audit);
    }

    @Test
    void loginGivesOneMessageForUnknownUserWrongPasswordAndLockout() {
        InMemoryUserRepository users = new InMemoryUserRepository();
        DefaultAuthService auth = newAuthService(users);
        char[] real = "correct horse battery staple".toCharArray();
        auth.register("nurse.joy", real, Role.NURSE);

        String unknown = assertThrows(AccessDeniedException.class,
                () -> auth.login("nobody.here", real)).getMessage();
        String wrong = assertThrows(AccessDeniedException.class,
                () -> auth.login("nurse.joy", "wrong horse battery staple".toCharArray())).getMessage();
        assertEquals(unknown, wrong, "unknown user and wrong password must look the same");

        // Attack: brute force. After five failures even the right password is refused, with the same message.
        for (int i = 2; i <= LoginAttemptTracker.MAX_FAILURES; i++) {
            assertThrows(AccessDeniedException.class, () -> auth.login("nurse.joy", "guess-guess-guess".toCharArray()));
        }
        String locked = assertThrows(AccessDeniedException.class, () -> auth.login("nurse.joy", real)).getMessage();
        assertEquals(wrong, locked, "a locked account must not be distinguishable");

        clock.advance(LoginAttemptTracker.LOCKOUT);
        Session s = auth.login("nurse.joy", real);
        assertEquals(new User("nurse.joy", Role.NURSE), sessions.validate(s.getToken()).getUser());

        assertThrows(AccessDeniedException.class, () -> auth.login(null, real));
        assertThrows(AccessDeniedException.class, () -> auth.login("nurse.joy", null));

        // CWE-779: no password in any audit line; lockout was audited (CWE-778).
        for (String line : auditLines) {
            assertFalse(line.contains("horse"), line);
            assertFalse(line.contains("guess-guess"), line);
        }
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=ACCOUNT_LOCKED")), auditLines.toString());
    }

    // ---- CWE-620: Unverified Password Change ----

    @Test
    void passwordChangeRequiresCurrentPassword() {
        InMemoryUserRepository users = new InMemoryUserRepository();
        DefaultAuthService auth = newAuthService(users);
        char[] current = "correct horse battery staple".toCharArray();
        char[] replacement = "purple monkey dishwasher lamp".toCharArray();
        auth.register("nurse.joy", current, Role.NURSE);
        String hashBefore = users.findPasswordHash("nurse.joy").orElseThrow();

        // Attack: someone at an unlocked workstation sets a new password without knowing the old one.
        AccessDeniedException wrong = assertThrows(AccessDeniedException.class,
                () -> auth.changePassword("nurse.joy", "wrong horse battery staple".toCharArray(), replacement));
        assertEquals(DefaultAuthService.LOGIN_FAILED, wrong.getMessage(), "same message as a failed login");
        assertThrows(AccessDeniedException.class, () -> auth.changePassword("nurse.joy", null, replacement));
        assertThrows(AccessDeniedException.class, () -> auth.changePassword("no.such.user", current, replacement));
        assertEquals(hashBefore, users.findPasswordHash("nurse.joy").orElseThrow(), "password unchanged");
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=PASSWORD_CHANGE_FAILED")));

        // Wrong guesses through password change count toward the lockout, like login guesses.
        for (int i = 2; i <= LoginAttemptTracker.MAX_FAILURES; i++) {
            assertThrows(AccessDeniedException.class,
                    () -> auth.changePassword("nurse.joy", "guess-guess-guess".toCharArray(), replacement));
        }
        assertThrows(AccessDeniedException.class, () -> auth.changePassword("nurse.joy", current, replacement),
                "even the right current password is refused while locked");
        clock.advance(LoginAttemptTracker.LOCKOUT);

        // Legitimate: the right current password and a strong new one.
        assertThrows(ValidationException.class,
                () -> auth.changePassword("nurse.joy", current, "password1234".toCharArray()), "weak new password");
        auth.changePassword("nurse.joy", current, replacement);
        assertThrows(AccessDeniedException.class, () -> auth.login("nurse.joy", current), "old password is dead");
        assertEquals("nurse.joy", auth.login("nurse.joy", replacement).getUser().getUsername());
        for (String line : auditLines) {
            assertFalse(line.contains("horse") || line.contains("dishwasher"), "password in audit: " + line);
        }
    }

    @Test
    void legitimateRegisterLoginAndLogoutWork() {
        InMemoryUserRepository users = new InMemoryUserRepository();
        DefaultAuthService auth = newAuthService(users);
        User created = auth.register("dr.house", "correct horse battery staple".toCharArray(), Role.DOCTOR);
        assertEquals(new User("dr.house", Role.DOCTOR), created);
        assertTrue(users.findPasswordHash("dr.house").orElseThrow().startsWith("210000:"), "stored hashed");
        assertFalse(users.findPasswordHash("dr.house").orElseThrow().contains("horse"));

        Session s = auth.login("dr.house", "correct horse battery staple".toCharArray());
        assertEquals(created, sessions.validate(s.getToken()).getUser());
        auth.logout(s.getToken());
        assertThrows(AccessDeniedException.class, () -> sessions.validate(s.getToken()));
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=USER_CREATED")));
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=LOGIN_OK")));

        // Registration refuses weak passwords, duplicates, and usernames that could forge log lines.
        assertThrows(ValidationException.class,
                () -> auth.register("nurse.ann", "password1234".toCharArray(), Role.NURSE));
        assertThrows(ValidationException.class,
                () -> auth.register("dr.house", "another long passphrase".toCharArray(), Role.NURSE));
        assertEquals(Role.DOCTOR, users.find("dr.house").orElseThrow().getRole(), "duplicate didn't overwrite");
        assertThrows(ValidationException.class,
                () -> auth.register("eve\nactor=admin", "another long passphrase".toCharArray(), Role.NURSE));
    }

    // ---- CWE-798: Use of Hard-coded Credentials ----

    private static final String ADMIN = CredentialsConfig.ADMIN_PASSWORD_ENV;
    private static final String DB = CredentialsConfig.DB_PASSWORD_ENV;

    @Test
    void refusesToStartWithoutEnvCredentials() {
        // Attack: start the app with nothing configured, hoping it falls back to a built-in password.
        List<Map<String, String>> broken = List.of(
                Map.of(),
                Map.of(ADMIN, "Adm1n-from-env!"),
                Map.of(DB, "db-from-env-42"),
                Map.of(ADMIN, "   ", DB, "db-from-env-42"),
                Map.of(ADMIN, "Adm1n-from-env!", DB, "\t\n "));
        for (Map<String, String> env : broken) {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> new CredentialsConfig(env::get), env.keySet().toString());
            assertTrue(e.getMessage().contains(ADMIN) || e.getMessage().contains(DB), e.getMessage());
            for (String value : env.values()) {
                if (!value.isBlank()) {
                    assertFalse(e.getMessage().contains(value), "error message leaked a configured secret");
                }
            }
        }
    }

    @Test
    void credentialsComeFromEnvironmentTrimmedAndCopied() {
        CredentialsConfig creds = new CredentialsConfig(
                Map.of(ADMIN, "  Adm1n-from-env!\n", DB, "\tdb-from-env-42 ")::get);
        assertArrayEquals("Adm1n-from-env!".toCharArray(), creds.adminPassword());
        assertArrayEquals("db-from-env-42".toCharArray(), creds.databasePassword());

        // Callers get copies: wiping or changing one can't alter the stored secret.
        char[] leaked = creds.adminPassword();
        Arrays.fill(leaked, 'x');
        assertArrayEquals("Adm1n-from-env!".toCharArray(), creds.adminPassword());
        assertFalse(creds.toString().contains("Adm1n"));
        assertFalse(creds.toString().contains("db-from-env"));
    }

    @Test
    void differentEnvironmentsGetDifferentCredentials() {
        // If there were a default password, two installs would share it.
        CredentialsConfig a = new CredentialsConfig(Map.of(ADMIN, "first-install", DB, "db-one")::get);
        CredentialsConfig b = new CredentialsConfig(Map.of(ADMIN, "second-install", DB, "db-two")::get);
        assertFalse(Arrays.equals(a.adminPassword(), b.adminPassword()));
        assertFalse(Arrays.equals(a.databasePassword(), b.databasePassword()));
    }

    // ---- CWE-613: Insufficient Session Expiration ----

    /** A clock the test can move forward. */
    private static final class MutableClock extends Clock {
        private volatile Instant now = Instant.parse("2026-11-05T08:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    private final MutableClock clock = new MutableClock();
    private final SessionManager sessions = new SessionManager(new TokenGenerator(), clock);
    private final User nurse = new User("nurse.joy", Role.NURSE);

    @Test
    void sessionExpiresAfterIdleTimeoutAndLogout() {
        // Legitimate: a fresh session validates, and activity keeps it alive past 15 minutes total.
        Session s = sessions.create(nurse);
        assertEquals(clock.instant().plus(SessionManager.IDLE_TIMEOUT), s.getExpiresAt());
        assertEquals(nurse, sessions.validate(s.getToken()).getUser());
        clock.advance(Duration.ofMinutes(10));
        assertEquals(clock.instant().plus(SessionManager.IDLE_TIMEOUT),
                sessions.validate(s.getToken()).getExpiresAt(), "activity should reset the idle timer");
        clock.advance(Duration.ofMinutes(10));
        sessions.validate(s.getToken());

        // Attack: nurse walks away from a shared workstation; someone uses it 15 minutes later.
        clock.advance(SessionManager.IDLE_TIMEOUT);
        AccessDeniedException idle = assertThrows(AccessDeniedException.class, () -> sessions.validate(s.getToken()));
        // Expired stays expired, even if the clock is wrong for a moment.
        clock.advance(Duration.ofMinutes(-30));
        assertThrows(AccessDeniedException.class, () -> sessions.validate(s.getToken()));

        // Attack: reuse a token after logout (e.g. copied from browser history).
        Session t = sessions.create(nurse);
        sessions.validate(t.getToken());
        sessions.logout(t.getToken());
        AccessDeniedException loggedOut = assertThrows(AccessDeniedException.class,
                () -> sessions.validate(t.getToken()));
        assertEquals(idle.getMessage(), loggedOut.getMessage(), "expired and logged-out must look the same");
    }

    @Test
    void idleBoundaryIsExact() {
        Session s = sessions.create(nurse);
        clock.advance(SessionManager.IDLE_TIMEOUT.minusMillis(1));
        sessions.validate(s.getToken());
        clock.advance(SessionManager.IDLE_TIMEOUT);
        assertThrows(AccessDeniedException.class, () -> sessions.validate(s.getToken()));
    }

    @Test
    void sessionExpiresAtAbsoluteTimeoutEvenWhenActive() {
        // Attack: a stolen token kept alive forever by a script pinging every few minutes.
        Session s = sessions.create(nurse);
        Instant hardLimit = clock.instant().plus(SessionManager.ABSOLUTE_TIMEOUT);
        while (clock.instant().plus(Duration.ofMinutes(10)).isBefore(hardLimit)) {
            clock.advance(Duration.ofMinutes(10));
            Session live = sessions.validate(s.getToken());
            assertFalse(live.getExpiresAt().isAfter(hardLimit), "expiry must never pass the absolute limit");
        }
        clock.advance(Duration.ofMinutes(10));
        assertThrows(AccessDeniedException.class, () -> sessions.validate(s.getToken()));
    }

    @Test
    void forgedOrMissingTokensAreRejectedWithTheSameMessage() {
        Session real = sessions.create(nurse);
        String expected = assertThrows(AccessDeniedException.class,
                () -> sessions.validate(new TokenGenerator().newSessionToken())).getMessage();
        for (String forged : Arrays.asList(null, "", "admin", real.getToken().toUpperCase(),
                real.getToken() + "x", real.getToken().substring(1))) {
            if (real.getToken().equals(forged)) {
                continue;
            }
            assertEquals(expected, assertThrows(AccessDeniedException.class,
                    () -> sessions.validate(forged)).getMessage());
        }
        sessions.logout(null);
        sessions.logout("never-issued");
        assertEquals(nurse, sessions.validate(real.getToken()).getUser(), "real session unaffected");
    }

    @Test
    void sessionsAreIndependentAndUnique() {
        Session a = sessions.create(nurse);
        Session b = sessions.create(nurse);
        assertNotEquals(a.getToken(), b.getToken());
        sessions.logout(a.getToken());
        assertThrows(AccessDeniedException.class, () -> sessions.validate(a.getToken()));
        assertEquals(nurse, sessions.validate(b.getToken()).getUser(), "logging out one device keeps the other");
    }

    @Test
    void concurrentUseIsThreadSafe() throws Exception {
        int threads = 16;
        int perThread = 500;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> issued = ConcurrentHashMap.newKeySet();
        List<Future<?>> work = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                work.add(pool.submit(() -> {
                    start.await();
                    for (int j = 0; j < perThread; j++) {
                        Session s = sessions.create(nurse);
                        assertTrue(issued.add(s.getToken()), "token issued twice");
                        sessions.validate(s.getToken());
                        sessions.logout(s.getToken());
                        assertThrows(AccessDeniedException.class, () -> sessions.validate(s.getToken()));
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> f : work) {
                f.get(60, TimeUnit.SECONDS); // rethrows any assertion failure from a worker
            }

            // Race logout against validate on the same token: once logout returns, the token is dead.
            for (int round = 0; round < 200; round++) {
                Session s = sessions.create(nurse);
                CountDownLatch go = new CountDownLatch(1);
                Future<?> validator = pool.submit(() -> {
                    go.await();
                    try {
                        sessions.validate(s.getToken());
                    } catch (AccessDeniedException ignored) {
                        // losing the race is fine
                    }
                    return null;
                });
                Future<?> logout = pool.submit(() -> {
                    go.await();
                    sessions.logout(s.getToken());
                    return null;
                });
                go.countDown();
                validator.get(10, TimeUnit.SECONDS);
                logout.get(10, TimeUnit.SECONDS);
                assertThrows(AccessDeniedException.class, () -> sessions.validate(s.getToken()));
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(threads * perThread, issued.size());
    }
}
