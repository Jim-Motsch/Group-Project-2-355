package medvault.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Metadata for an uploaded lab-report file. The file bytes live in
 * {@link medvault.files.LabReportStore}; this object never holds a path
 * supplied by a user.
 */
public final class LabReport {
    private final String storedName;
    private final long patientId;
    private final String uploadedBy;
    private final String contentType;
    private final long sizeBytes;
    private final Instant uploadedAt;

    /**
     * @param storedName  server-generated file name (never the client's name)
     * @param patientId   the chart this report belongs to
     * @param uploadedBy  username of the uploader
     * @param contentType detected type, for example {@code application/pdf}
     * @param sizeBytes   file size in bytes
     * @param uploadedAt  upload time
     */
    public LabReport(String storedName, long patientId, String uploadedBy,
                     String contentType, long sizeBytes, Instant uploadedAt) {
        this.storedName = Objects.requireNonNull(storedName, "storedName");
        this.patientId = patientId;
        this.uploadedBy = Objects.requireNonNull(uploadedBy, "uploadedBy");
        this.contentType = Objects.requireNonNull(contentType, "contentType");
        this.sizeBytes = sizeBytes;
        this.uploadedAt = Objects.requireNonNull(uploadedAt, "uploadedAt");
    }

    /** @return server-generated file name */
    public String getStoredName() {
        return storedName;
    }

    /** @return owning patient id */
    public long getPatientId() {
        return patientId;
    }

    /** @return uploader's username */
    public String getUploadedBy() {
        return uploadedBy;
    }

    /** @return detected content type */
    public String getContentType() {
        return contentType;
    }

    /** @return size in bytes */
    public long getSizeBytes() {
        return sizeBytes;
    }

    /** @return upload time */
    public Instant getUploadedAt() {
        return uploadedAt;
    }
}
