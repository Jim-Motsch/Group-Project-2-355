package medvault.auth;

import medvault.model.AccessDeniedException;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.security.TokenGenerator;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack tests for the auth package. Each test is the target behavior for one
 * CWE. Remove {@code @Disabled} as you implement it; by integration day
 * (Nov 8) none should be disabled.
 *
 * @author Ian Beebe
 */
class AuthAttackTest {

    @Test
    @Disabled("TODO(Ian): CWE-521")
    void rejectsShortOrCommonPassword() {
        // PasswordPolicy.check("nurse1", "password123".toCharArray()) throws ValidationException
    }

    @Test
    @Disabled("TODO(Ian): CWE-916")
    void hashUsesPbkdf2WithManyIterations() {
        // hash starts with "210000:" and verify() accepts the right password, rejects a wrong one
    }

    @Test
    @Disabled("TODO(Ian): CWE-759")
    void samePasswordGivesDifferentHashes() {
        // hash(pw) != hash(pw) because each call uses a new salt
    }

    @Test
    @Disabled("TODO(Ian): CWE-307")
    void locksAccountAfterFiveFailures() {
        // five recordFailure() calls -> isLocked() true; advance the clock 15 min -> false
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
