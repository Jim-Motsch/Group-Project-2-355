package medvault.files;

import medvault.access.AccessPolicy;
import medvault.access.Permission;
import medvault.audit.AuditLogger;
import medvault.model.LabReport;
import medvault.model.Session;
import medvault.model.ValidationException;
import medvault.security.TokenGenerator;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Keeps lab reports in a directory on disk.
 *
 * <p><b>CWE-22: Path Traversal.</b> Files are saved under a random,
 * server-generated name ({@code p<patientId>-<32 hex>.pdf}); the client's
 * file name is never used for storage. On download the requested name is
 * resolved against the storage root, normalized, and rejected unless it is
 * still a file directly inside the root, so {@code ../../etc/passwd} or an
 * absolute path fails. The name must also match the server's own naming
 * pattern, and the real path (after following any symlink) must still be
 * inside the root.</p>
 *
 * <p><b>CWE-276: Incorrect Default Permissions.</b> Files and directories
 * normally get the process's default permissions (often world-readable
 * {@code rw-r--r--} / {@code rwxr-xr-x}), which would let any local account
 * read lab results. Where POSIX permissions exist, the storage directory is
 * <em>created</em> {@code rwx------} (the permission is part of the create
 * call, so it is never briefly open) and an existing directory is tightened
 * to that; each stored file is {@code rw-------}, because it starts life as
 * an owner-only temp file and is set again after the move. On Windows this is
 * skipped and the directory's inherited ACL applies.</p>
 *
 * <p><b>CWE-772: Missing Release of Resource after Effective Lifetime.</b>
 * Every stream is opened in try-with-resources, so it is closed as soon as it
 * is no longer needed, including on every error path. The upload stream is
 * always closed by {@link #upload}, and its staging temp file is always
 * deleted unless it was moved into storage. Without this, each failed upload
 * would leak a file handle until the server ran out of them.</p>
 *
 * <p>Uploads stream into a {@link SecureTempFiles} temp file (CWE-378)
 * while counting bytes, and stop as soon as the count passes
 * {@link UploadLimits#MAX_FILE_BYTES} (CWE-770). The type comes from the
 * magic bytes (CWE-434). Both directions check {@code UPLOAD_LAB} or
 * {@code DOWNLOAD_LAB} first, then care-team membership for the patient
 * (CWE-1220, CWE-639).</p>
 *
 * @author Alex Reyes
 */
public class FileSystemLabReportStore implements LabReportStore {

    /** Server naming pattern: patient id, 128 random bits as hex, server-chosen extension. */
    private static final Pattern STORED_NAME = Pattern.compile("p([0-9]{1,18})-[0-9a-f]{32}\\.(pdf|png)");
    private static final Set<PosixFilePermission> DIR_OWNER_ONLY = PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE_OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
    private static final int RANDOM_NAME_BYTES = 16;
    private static final int BUFFER_BYTES = 8192;
    private static final String BAD_NAME = "That lab report name is not valid.";
    private static final String NOT_FOUND = "That lab report does not exist.";

    private final Path root;
    private final UploadValidator validator;
    private final UploadLimits limits;
    private final SecureTempFiles tempFiles;
    private final AccessPolicy policy;
    private final AuditLogger audit;
    private final TokenGenerator random;

    /**
     * Uses its own {@link TokenGenerator} for file names; prefer the
     * constructor that takes the app's shared generator.
     *
     * @param root      storage directory
     * @param validator type checks (CWE-434)
     * @param limits    size and quota checks (CWE-770)
     * @param tempFiles staging area for uploads (CWE-378)
     * @param policy    access checks
     * @param audit     audit trail
     */
    public FileSystemLabReportStore(Path root, UploadValidator validator, UploadLimits limits,
                                    SecureTempFiles tempFiles, AccessPolicy policy, AuditLogger audit) {
        this(root, validator, limits, tempFiles, policy, audit, new TokenGenerator());
    }

    /**
     * @param root      storage directory
     * @param validator type checks (CWE-434)
     * @param limits    size and quota checks (CWE-770)
     * @param tempFiles staging area for uploads (CWE-378)
     * @param policy    access checks
     * @param audit     audit trail
     * @param random    source of stored file names (CWE-338)
     */
    public FileSystemLabReportStore(Path root, UploadValidator validator, UploadLimits limits,
                                    SecureTempFiles tempFiles, AccessPolicy policy, AuditLogger audit,
                                    TokenGenerator random) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.validator = Objects.requireNonNull(validator, "validator");
        this.limits = Objects.requireNonNull(limits, "limits");
        this.tempFiles = Objects.requireNonNull(tempFiles, "tempFiles");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code data} is always closed, whether the upload succeeds or not.</p>
     *
     * @throws ValidationException if the file is too large, over quota, or not a PDF/PNG
     */
    @Override
    public LabReport upload(Session session, long patientId, String originalName, InputStream data) {
        try (InputStream in = data) { // CWE-772: the client stream is closed on every path
            // UPLOAD_LAB first, then care team for this patient (CWE-1220, CWE-639).
            Session live = policy.requireOnCareTeam(session, Permission.UPLOAD_LAB, patientId);
            String uploader = live.getUser().getUsername();
            if (in == null) {
                throw new ValidationException("No file was sent.");
            }
            // originalName is untrusted and display-only: never used for storage, never logged.
            Path temp = tempFiles.create(".upload");
            boolean moved = false;
            long reserved = -1;
            try {
                long size;
                String type;
                try (OutputStream out = Files.newOutputStream(temp, StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING)) {
                    byte[] header = in.readNBytes(UploadValidator.HEADER_BYTES);
                    type = detect(live, patientId, header); // CWE-434: refuse before reading the rest
                    out.write(header);
                    size = header.length + copyWithLimit(in, out, live, patientId, header.length);
                }
                limits.reserve(uploader, size); // CWE-770: per-user quota
                reserved = size;
                String storedName = "p" + patientId + "-"
                        + HexFormat.of().formatHex(random.randomBytes(RANDOM_NAME_BYTES))
                        + UploadValidator.extensionFor(type);
                Path dest = ensureRoot().resolve(storedName);
                move(temp, dest);
                moved = true;
                restrict(dest, FILE_OWNER_ONLY); // CWE-276
                audit.record(live.getUser(), "LAB_UPLOADED",
                        "patient=" + patientId + " type=" + type + " bytes=" + size);
                return new LabReport(storedName, patientId, uploader, type, size, Instant.now());
            } catch (RuntimeException | IOException failure) {
                if (reserved >= 0) {
                    limits.release(uploader, reserved);
                }
                throw failure;
            } finally {
                if (!moved) {
                    Files.deleteIfExists(temp); // CWE-378/772: never leave a staged upload behind
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("lab report upload failed", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws ValidationException if the name is outside storage, malformed or unknown
     */
    @Override
    public InputStream download(Session session, String storedName) {
        Session live = policy.requireSession(session, Permission.DOWNLOAD_LAB);
        Path file = insideRoot(live, storedName); // CWE-22
        Matcher m = STORED_NAME.matcher(file.getFileName().toString());
        if (!m.matches()) {
            audit.record(live.getUser(), "LAB_DOWNLOAD_REJECTED", "reason=bad_name");
            throw new ValidationException(BAD_NAME);
        }
        long patientId = Long.parseLong(m.group(1));
        policy.requireOnCareTeam(session, Permission.DOWNLOAD_LAB, patientId); // CWE-639
        try {
            Path real = file.toRealPath();
            if (!real.startsWith(root.toRealPath()) || !Files.isRegularFile(real)) {
                audit.record(live.getUser(), "LAB_DOWNLOAD_REJECTED", "patient=" + patientId + " reason=link");
                throw new ValidationException(BAD_NAME);
            }
            InputStream in = Files.newInputStream(real); // caller closes it
            audit.record(live.getUser(), "LAB_DOWNLOADED", "patient=" + patientId);
            return in;
        } catch (NoSuchFileException missing) {
            throw new ValidationException(NOT_FOUND);
        } catch (IOException e) {
            throw new UncheckedIOException("lab report download failed", e);
        }
    }

    /** Resolves, normalizes and refuses anything that isn't a direct child of the root. */
    private Path insideRoot(Session live, String storedName) {
        Path candidate;
        try {
            candidate = storedName == null || storedName.isBlank()
                    ? null
                    : root.resolve(storedName).normalize();
        } catch (InvalidPathException bad) {
            candidate = null;
        }
        if (candidate == null || !candidate.startsWith(root) || !root.equals(candidate.getParent())) {
            // Don't log the requested path: it is attacker text and may be a real file path.
            audit.record(live.getUser(), "LAB_PATH_REJECTED", "reason=outside_storage");
            throw new ValidationException(BAD_NAME);
        }
        return candidate;
    }

    private String detect(Session live, long patientId, byte[] header) {
        try {
            return validator.detectAllowedType(header);
        } catch (ValidationException rejected) {
            audit.record(live.getUser(), "UPLOAD_REJECTED", "patient=" + patientId + " reason=type");
            throw rejected;
        }
    }

    /** Copies the rest of the stream, stopping as soon as the total passes the per-file cap. */
    private long copyWithLimit(InputStream in, OutputStream out, Session live, long patientId, long already)
            throws IOException {
        byte[] buf = new byte[BUFFER_BYTES];
        long total = already;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > UploadLimits.MAX_FILE_BYTES) {
                audit.record(live.getUser(), "UPLOAD_REJECTED", "patient=" + patientId + " reason=size");
                throw new ValidationException("Lab reports must be at most "
                        + (UploadLimits.MAX_FILE_BYTES / (1024 * 1024)) + " MB.");
            }
            out.write(buf, 0, n);
        }
        return total - already;
    }

    private static void move(Path from, Path to) throws IOException {
        try {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException otherVolume) {
            Files.move(from, to); // no REPLACE_EXISTING: never overwrite a stored report
        }
    }

    /**
     * CWE-276: creates the storage directory owner-only by default (the
     * permission is part of the create call), or tightens an existing one.
     */
    private synchronized Path ensureRoot() throws IOException {
        if (Files.notExists(root)) {
            if (supportsPosix(nearestExisting(root))) {
                Files.createDirectories(root, PosixFilePermissions.asFileAttribute(DIR_OWNER_ONLY));
            } else {
                Files.createDirectories(root);
            }
        }
        restrict(root, DIR_OWNER_ONLY);
        return root;
    }

    /** The closest ancestor that already exists, to ask its file system about POSIX support. */
    private static Path nearestExisting(Path p) {
        Path current = p;
        while (current != null && Files.notExists(current)) {
            current = current.getParent();
        }
        return current == null ? p.getRoot() : current;
    }

    private static boolean supportsPosix(Path existing) throws IOException {
        return existing != null
                && Files.getFileStore(existing).supportsFileAttributeView(PosixFileAttributeView.class);
    }

    /** Applies POSIX permissions where supported; Windows has none, so this is skipped there. */
    private static void restrict(Path p, Set<PosixFilePermission> perms) throws IOException {
        if (supportsPosix(p)) {
            Files.setPosixFilePermissions(p, perms);
        }
    }
}
