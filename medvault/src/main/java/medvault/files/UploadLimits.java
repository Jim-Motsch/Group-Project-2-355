package medvault.files;

import medvault.model.ValidationException;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Caps how much a single user can upload.
 *
 * <p><b>CWE-770: Allocation of Resources Without Limits or Throttling.</b>
 * Without limits, one account (or one stolen session) can fill the disk with
 * a few huge or endless uploads and take the clinic offline. Each file is at
 * most {@link #MAX_FILE_BYTES}; each user may store at most
 * {@link #MAX_BYTES_PER_USER} in total. The size is enforced while the
 * stream is being read (see {@link FileSystemLabReportStore}), not by trusting
 * a declared length. The per-user totals are updated with one atomic
 * {@code compute}, so parallel uploads can't both slip under the quota.</p>
 *
 * @author Alex Reyes
 */
public class UploadLimits {

    /** Largest single upload: 10 MB. */
    public static final long MAX_FILE_BYTES = 10L * 1024 * 1024;
    /** Total storage per user: 200 MB. */
    public static final long MAX_BYTES_PER_USER = 200L * 1024 * 1024;

    private final ConcurrentMap<String, Long> used = new ConcurrentHashMap<>();

    /**
     * @param username uploader
     * @param bytes    size about to be added
     * @throws medvault.model.ValidationException if a limit would be exceeded
     */
    public void reserve(String username, long bytes) {
        Objects.requireNonNull(username, "username");
        if (bytes < 0 || bytes > MAX_FILE_BYTES) {
            throw new ValidationException("Lab reports must be at most " + (MAX_FILE_BYTES / (1024 * 1024)) + " MB.");
        }
        // Throwing inside compute leaves the stored total unchanged.
        used.compute(username, (u, total) -> {
            long current = total == null ? 0 : total;
            if (current + bytes > MAX_BYTES_PER_USER) {
                throw new ValidationException("Your upload quota is used up. Please contact an administrator.");
            }
            return current + bytes;
        });
    }

    /**
     * Gives back a reservation, for example when storing the file failed.
     *
     * @param username uploader
     * @param bytes    size previously reserved
     */
    public void release(String username, long bytes) {
        Objects.requireNonNull(username, "username");
        used.computeIfPresent(username, (u, total) -> {
            long left = total - Math.max(0, bytes);
            return left <= 0 ? null : left;
        });
    }
}
