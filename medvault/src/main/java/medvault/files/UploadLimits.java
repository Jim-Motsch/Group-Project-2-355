package medvault.files;

/**
 * Caps how much a single user can upload.
 *
 * <p><b>CWE-770: Allocation of Resources Without Limits or Throttling.</b>
 * Each file is at most {@link #MAX_FILE_BYTES}; each user may store at most
 * {@link #MAX_BYTES_PER_USER} in total. The size is enforced while the
 * stream is being read, not by trusting a declared length.</p>
 *
 * @author Alex Reyes
 */
public class UploadLimits {

    /** Largest single upload: 10 MB. */
    public static final long MAX_FILE_BYTES = 10L * 1024 * 1024;
    /** Total storage per user: 200 MB. */
    public static final long MAX_BYTES_PER_USER = 200L * 1024 * 1024;

    /**
     * @param username uploader
     * @param bytes    size about to be added
     * @throws medvault.model.ValidationException if a limit would be exceeded
     */
    public void reserve(String username, long bytes) {
        // TODO(Alex) CWE-770: thread-safe per-user running total.
        throw new UnsupportedOperationException("TODO(Alex): CWE-770");
    }
}
