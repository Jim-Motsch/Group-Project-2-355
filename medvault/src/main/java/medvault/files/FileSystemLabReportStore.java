package medvault.files;

import medvault.access.AccessPolicy;
import medvault.audit.AuditLogger;
import medvault.model.LabReport;
import medvault.model.Session;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Keeps lab reports in a directory on disk.
 *
 * <p><b>CWE-22: Path Traversal.</b> Files are saved under a random,
 * server-generated name. On download the requested name is resolved against
 * the storage root, normalized, and rejected unless it is still inside the
 * root, so {@code ../../etc/passwd} fails.</p>
 *
 * <p><b>CWE-732: Incorrect Permission Assignment for Critical Resource.</b>
 * The storage directory is created {@code rwx------} and each file
 * {@code rw-------}.</p>
 *
 * <p><b>CWE-404: Improper Resource Shutdown or Release.</b> Every stream is
 * opened in try-with-resources, including on the error paths.</p>
 *
 * @author Alex Reyes
 */
public class FileSystemLabReportStore implements LabReportStore {
    private final Path root;
    private final UploadValidator validator;
    private final UploadLimits limits;
    private final SecureTempFiles tempFiles;
    private final AccessPolicy policy;
    private final AuditLogger audit;

    /**
     * @param root      storage directory
     * @param validator type checks (CWE-434)
     * @param limits    size and quota checks (CWE-770)
     * @param tempFiles staging area for uploads (CWE-377)
     * @param policy    access checks
     * @param audit     audit trail
     */
    public FileSystemLabReportStore(Path root, UploadValidator validator, UploadLimits limits,
                                    SecureTempFiles tempFiles, AccessPolicy policy, AuditLogger audit) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.validator = Objects.requireNonNull(validator, "validator");
        this.limits = Objects.requireNonNull(limits, "limits");
        this.tempFiles = Objects.requireNonNull(tempFiles, "tempFiles");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    @Override
    public LabReport upload(Session session, long patientId, String originalName, InputStream data) {
        // TODO(Alex): policy check -> stream into a secure temp file while counting bytes (CWE-770)
        //  -> validate header (CWE-434) -> move into root under a random name (CWE-22, CWE-732) -> audit.
        throw new UnsupportedOperationException("TODO(Alex): upload");
    }

    @Override
    public InputStream download(Session session, String storedName) {
        // TODO(Alex) CWE-22: resolve, normalize, startsWith(root) check, then policy check.
        throw new UnsupportedOperationException("TODO(Alex): CWE-22");
    }
}
