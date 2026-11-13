package medvault.files;

import medvault.access.AccessPolicy;
import medvault.access.InMemoryCareTeam;
import medvault.audit.AuditLogger;
import medvault.audit.LogSanitizer;
import medvault.auth.SessionManager;
import medvault.model.AccessDeniedException;
import medvault.model.LabReport;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.model.ValidationException;
import medvault.security.TokenGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack tests for the files package. Each test attempts the attack for one
 * CWE and asserts it fails; {@link #legitimateUploadAndDownloadWork()} shows
 * the normal case works. Uses a real {@link SessionManager},
 * {@link InMemoryCareTeam} and {@link AccessPolicy}, with storage and staging
 * directories under {@code @TempDir}. The POSIX permission checks use
 * {@link Assumptions} and are skipped on Windows.
 *
 * @author Alex Reyes
 */
class FilesAttackTest {

    private static final long PATIENT_1 = 1;
    private static final long PATIENT_2 = 2;
    private static final byte[] PDF = "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF\n"
            .getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PNG = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R'};
    private static final byte[] EXE = {'M', 'Z', (byte) 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, (byte) 0xFF, (byte) 0xFF, 0, 0};

    @TempDir
    Path tmp;

    private final SessionManager sessions = new SessionManager(new TokenGenerator(), Clock.systemUTC());
    private final InMemoryCareTeam careTeam = new InMemoryCareTeam();
    private final AuditLogger audit = new AuditLogger(new LogSanitizer());
    private final AccessPolicy policy = new AccessPolicy(sessions, careTeam, audit);
    private final Logger auditLog = Logger.getLogger("medvault.audit");

    private Path root;
    private Path staging;
    private FileSystemLabReportStore store;
    private Session nurse;
    private Session admin;

    @BeforeEach
    void setUp() throws IOException {
        auditLog.setUseParentHandlers(false);
        root = tmp.resolve("labs");
        staging = Files.createDirectory(tmp.resolve("staging"));
        store = new FileSystemLabReportStore(root, new UploadValidator(), new UploadLimits(),
                new SecureTempFiles(staging), policy, audit, new TokenGenerator());
        nurse = sessions.create(new User("nurse.joy", Role.NURSE));
        admin = sessions.create(new User("admin", Role.ADMIN));
        careTeam.assign(PATIENT_1, "nurse.joy");
    }

    @AfterEach
    void tearDown() {
        auditLog.setUseParentHandlers(true);
    }

    private static long count(Path dir) throws IOException {
        if (Files.notExists(dir)) {
            return 0;
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.count();
        }
    }

    private void assertNothingLeftOnDisk() throws IOException {
        assertEquals(0, count(staging), "a staged temp file was left behind");
        assertEquals(0, count(root), "a rejected file was stored");
    }

    /**
     * A stream of {@code length} bytes that starts with {@code header}; generated
     * on the fly so a "1 GB" upload uses no memory. Records reads and close.
     */
    private static final class FakeUpload extends InputStream {
        private final byte[] header;
        private final long length;
        private final long failAt;
        long position;
        boolean closed;

        FakeUpload(byte[] header, long length) {
            this(header, length, -1);
        }

        FakeUpload(byte[] header, long length, long failAt) {
            this.header = header;
            this.length = length;
            this.failAt = failAt;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) == -1 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (closed) {
                throw new IOException("stream closed");
            }
            if (failAt >= 0 && position >= failAt) {
                throw new IOException("connection reset by peer");
            }
            if (position >= length) {
                return -1;
            }
            int n = (int) Math.min(len, length - position);
            for (int i = 0; i < n; i++) {
                long p = position + i;
                b[off + i] = p < header.length ? header[(int) p] : (byte) 'x';
            }
            position += n;
            return n;
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    // ---- Legitimate case ----

    @Test
    void legitimateUploadAndDownloadWork() throws IOException {
        LabReport pdf = store.upload(nurse, PATIENT_1, "Jane Doe CBC results.pdf", new ByteArrayInputStream(PDF));
        assertEquals(UploadValidator.PDF, pdf.getContentType());
        assertEquals(PDF.length, pdf.getSizeBytes());
        assertEquals("nurse.joy", pdf.getUploadedBy());
        assertEquals(PATIENT_1, pdf.getPatientId());
        assertTrue(pdf.getStoredName().matches("p1-[0-9a-f]{32}\\.pdf"), pdf.getStoredName());
        assertFalse(pdf.getStoredName().contains("Jane"), "client's file name is never used");
        try (InputStream in = store.download(nurse, pdf.getStoredName())) {
            assertArrayEquals(PDF, in.readAllBytes());
        }
        LabReport png = store.upload(nurse, PATIENT_1, "scan", new ByteArrayInputStream(PNG));
        assertEquals(UploadValidator.PNG, png.getContentType());
        assertTrue(png.getStoredName().endsWith(".png"));
        // CWE-276 (cross-platform part): files sit directly in root under server-chosen names.
        try (Stream<Path> files = Files.list(root)) {
            assertEquals(Set.of(pdf.getStoredName(), png.getStoredName()),
                    files.map(p -> p.getFileName().toString()).collect(java.util.stream.Collectors.toSet()));
        }
        assertEquals(0, count(staging), "staged temp files are moved, not copied");
    }

    // ---- CWE-22: Path Traversal ----

    @Test
    void downloadRejectsPathTraversal() throws IOException {
        Path secret = Files.writeString(tmp.resolve("secret.txt"), "TOP-SECRET");
        LabReport mine = store.upload(nurse, PATIENT_1, "r.pdf", new ByteArrayInputStream(PDF));
        List<String> attacks = new ArrayList<>(List.of(
                "../secret.txt", "../../etc/passwd", "..\\secret.txt", "..\\..\\Windows\\win.ini",
                "./../secret.txt", mine.getStoredName() + "/../../secret.txt", "../labs/../secret.txt",
                secret.toAbsolutePath().toString(), "/etc/passwd", "%2e%2e%2fsecret.txt",
                "p1-" + "0".repeat(32) + ".pdf\u0000.txt", "sub/" + mine.getStoredName(), ".", "..", "", "  "));
        attacks.add(null);
        for (String attack : attacks) {
            assertThrows(ValidationException.class, () -> store.download(nurse, attack).close(), String.valueOf(attack));
        }
        // Permission is checked before the path: a session without DOWNLOAD_LAB gets "denied", not a path hint.
        assertThrows(AccessDeniedException.class, () -> store.download(admin, "../../etc/passwd"));
        Session forged = new Session("forged", new User("nurse.joy", Role.NURSE), Instant.now().plusSeconds(600));
        assertThrows(AccessDeniedException.class, () -> store.download(forged, mine.getStoredName()));
        // A well-formed name for another patient's chart is refused by the care-team check (CWE-639).
        assertThrows(AccessDeniedException.class,
                () -> store.download(nurse, "p2-" + mine.getStoredName().substring(3)));
        assertThrows(ValidationException.class, () -> store.download(nurse, "p1-" + "0".repeat(32) + ".pdf"),
                "unknown but well-formed name");
        assertEquals("TOP-SECRET", Files.readString(secret), "secret untouched");
    }

    // ---- CWE-434: Unrestricted Upload of File with Dangerous Type ----

    @Test
    void renamedExecutableIsRejected() throws IOException {
        List<byte[]> dangerous = List.of(
                EXE,                                                                           // Windows PE
                new byte[] {0x7F, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0},                            // Linux ELF
                "<?php system($_GET['c']); ?>".getBytes(StandardCharsets.US_ASCII),            // web shell
                "<html><script>alert(1)</script></html>".getBytes(StandardCharsets.US_ASCII),  // HTML
                "junk%PDF-1.4 hidden later".getBytes(StandardCharsets.US_ASCII),               // magic not at start
                "%PDF".getBytes(StandardCharsets.US_ASCII),                                    // too short
                new byte[0]);
        for (byte[] bytes : dangerous) {
            for (String name : List.of("report.pdf", "scan.png", "report.pdf.exe")) {
                assertThrows(ValidationException.class,
                        () -> store.upload(nurse, PATIENT_1, name, new ByteArrayInputStream(bytes)), name);
            }
        }
        assertNothingLeftOnDisk();
        // The type is decided from the first bytes, so a 1 GB EXE is refused after reading only its header.
        FakeUpload hugeExe = new FakeUpload(EXE, 1L << 30);
        assertThrows(ValidationException.class, () -> store.upload(nurse, PATIENT_1, "report.pdf", hugeExe));
        assertTrue(hugeExe.position <= UploadValidator.HEADER_BYTES, "read " + hugeExe.position + " bytes");

        UploadValidator v = new UploadValidator();
        assertEquals(UploadValidator.PDF, v.detectAllowedType(Arrays.copyOf(PDF, 8)));
        assertEquals(UploadValidator.PNG, v.detectAllowedType(Arrays.copyOf(PNG, 8)));
        assertThrows(ValidationException.class, () -> v.detectAllowedType(null));
    }

    // ---- CWE-770: Allocation of Resources Without Limits or Throttling ----

    @Test
    void oversizedUploadIsRejected() throws IOException {
        // Attack: an endless (here: 1 GB) upload. Reading stops just past the 10 MB cap.
        FakeUpload huge = new FakeUpload(PDF, 1L << 30);
        assertThrows(ValidationException.class, () -> store.upload(nurse, PATIENT_1, "big.pdf", huge));
        assertTrue(huge.position <= UploadLimits.MAX_FILE_BYTES + 16 * 1024, "read " + huge.position + " bytes");
        // Exactly one byte over is refused too, and nothing is left on disk.
        assertThrows(ValidationException.class, () -> store.upload(nurse, PATIENT_1, "big.pdf",
                new FakeUpload(PDF, UploadLimits.MAX_FILE_BYTES + 1)));
        assertNothingLeftOnDisk();
        // Legitimate: exactly the limit is accepted.
        LabReport max = store.upload(nurse, PATIENT_1, "max.pdf", new FakeUpload(PDF, UploadLimits.MAX_FILE_BYTES));
        assertEquals(UploadLimits.MAX_FILE_BYTES, max.getSizeBytes());
    }

    @Test
    void perUserQuotaHoldsUnderParallelUploads() throws Exception {
        UploadLimits limits = new UploadLimits();
        long perFile = UploadLimits.MAX_FILE_BYTES;
        int fits = (int) (UploadLimits.MAX_BYTES_PER_USER / perFile);
        ExecutorService pool = Executors.newFixedThreadPool(16);
        AtomicInteger accepted = new AtomicInteger();
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> work = new ArrayList<>();
        try {
            for (int i = 0; i < fits * 3; i++) {
                work.add(pool.submit(() -> {
                    go.await();
                    try {
                        limits.reserve("nurse.joy", perFile);
                        accepted.incrementAndGet();
                    } catch (ValidationException overQuota) {
                        // expected for everything past the quota
                    }
                    return null;
                }));
            }
            go.countDown();
            for (Future<?> f : work) {
                f.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(fits, accepted.get(), "parallel uploads must not overshoot the quota");
        assertThrows(ValidationException.class, () -> limits.reserve("nurse.joy", 1));
        limits.reserve("dr.grey", perFile); // quotas are per user
        limits.release("nurse.joy", perFile);
        limits.reserve("nurse.joy", perFile); // freed space can be reused
        assertThrows(ValidationException.class, () -> limits.reserve("x", -1));
        assertThrows(ValidationException.class, () -> limits.reserve("x", perFile + 1));
    }

    // ---- CWE-378: Creation of Temporary File With Insecure Permissions ----

    @Test
    void tempFilesAreUnpredictableAndConfined() throws IOException {
        SecureTempFiles temps = new SecureTempFiles(staging);
        Set<String> names = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            Path p = temps.create(".pdf");
            assertEquals(staging, p.getParent(), "created in the configured directory");
            assertEquals(0, Files.size(p), "new and empty, never a reused file");
            String name = p.getFileName().toString();
            assertTrue(name.startsWith(SecureTempFiles.PREFIX) && name.endsWith(".pdf"), name);
            assertTrue(names.add(name));
            // The owner-only fallback (used where POSIX is missing) still leaves the owner able to use it.
            assertTrue(Files.isReadable(p) && Files.isWritable(p), "owner lost access to " + name);
        }
        // Names are not sequential: they differ in more than a trailing counter.
        List<String> sorted = new ArrayList<>(names);
        assertTrue(sorted.stream().map(n -> n.substring(SecureTempFiles.PREFIX.length(), SecureTempFiles.PREFIX.length() + 4))
                .distinct().count() > 10, "temp names look predictable: " + sorted);
        // A suffix can't smuggle in a path.
        for (String bad : List.of("/../../evil.sh", "..\\x.pdf", ".pdf/../../x", "", "pdf")) {
            assertThrows(IllegalArgumentException.class, () -> temps.create(bad), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> temps.create(null));
    }

    @Test
    void tempFileIsOwnerOnly() throws IOException {
        Assumptions.assumeTrue(Files.getFileStore(staging).supportsFileAttributeView(PosixFileAttributeView.class),
                "POSIX permissions are not supported on this file system (e.g. Windows)");
        Path p = new SecureTempFiles(staging).create(".pdf");
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(p));
        Path sys = new SecureTempFiles().create(".pdf");
        try {
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(sys));
        } finally {
            Files.deleteIfExists(sys);
        }
    }

    // ---- CWE-276: Incorrect Default Permissions ----

    @Test
    void storedFilesAreOwnerOnly() throws IOException {
        Assumptions.assumeTrue(Files.getFileStore(tmp).supportsFileAttributeView(PosixFileAttributeView.class),
                "POSIX permissions are not supported on this file system (e.g. Windows)");
        // Default: a storage directory that doesn't exist yet is created owner-only, parents included.
        Path fresh = tmp.resolve("fresh").resolve("labs");
        FileSystemLabReportStore freshStore = new FileSystemLabReportStore(fresh, new UploadValidator(),
                new UploadLimits(), new SecureTempFiles(staging), policy, audit, new TokenGenerator());
        LabReport first = freshStore.upload(nurse, PATIENT_1, "r.pdf", new ByteArrayInputStream(PDF));
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(fresh));
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(fresh.getParent()));
        assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(fresh.resolve(first.getStoredName())));

        // Attack: the directory already exists world-readable (e.g. created by a careless install script).
        Files.createDirectories(root);
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"));
        LabReport r = store.upload(nurse, PATIENT_1, "r.pdf", new ByteArrayInputStream(PDF));
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(root));
        assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(root.resolve(r.getStoredName())));
    }

    // ---- CWE-772: Missing Release of Resource after Effective Lifetime ----

    @Test
    void streamsClosedOnFailedUpload() throws IOException {
        // Each failure below would leak an open handle if the store didn't release it right away.
        // Wrong type.
        FakeUpload exe = new FakeUpload(EXE, 4096);
        assertThrows(ValidationException.class, () -> store.upload(nurse, PATIENT_1, "r.pdf", exe));
        assertTrue(exe.closed, "client stream left open after a rejected type");
        // Too big.
        FakeUpload big = new FakeUpload(PDF, UploadLimits.MAX_FILE_BYTES + 1);
        assertThrows(ValidationException.class, () -> store.upload(nurse, PATIENT_1, "r.pdf", big));
        assertTrue(big.closed);
        // Connection drops halfway through a valid PDF.
        FakeUpload dropped = new FakeUpload(PDF, 1_000_000, 300_000);
        assertThrows(UncheckedIOException.class, () -> store.upload(nurse, PATIENT_1, "r.pdf", dropped));
        assertTrue(dropped.closed);
        // Refused before reading anything: not on the care team, or no permission.
        FakeUpload otherChart = new FakeUpload(PDF, 4096);
        assertThrows(AccessDeniedException.class, () -> store.upload(nurse, PATIENT_2, "r.pdf", otherChart));
        assertTrue(otherChart.closed);
        assertEquals(0, otherChart.position, "nothing read before the access check");
        FakeUpload noPermission = new FakeUpload(PDF, 4096);
        assertThrows(AccessDeniedException.class, () -> store.upload(admin, PATIENT_1, "r.pdf", noPermission));
        assertTrue(noPermission.closed);
        // On Windows an unclosed handle would also make the temp file undeletable, so this checks that too.
        assertNothingLeftOnDisk();
        // Legitimate: a successful upload closes the stream as well.
        FakeUpload ok = new FakeUpload(PDF, 4096);
        store.upload(nurse, PATIENT_1, "r.pdf", ok);
        assertTrue(ok.closed);
    }
}
