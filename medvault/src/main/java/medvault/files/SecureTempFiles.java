package medvault.files;

import java.nio.file.Path;

/**
 * Creates temporary files for uploads in progress and PDF rendering.
 *
 * <p><b>CWE-377: Insecure Temporary File.</b> Use
 * {@code Files.createTempFile} with owner-only POSIX permissions
 * ({@code rw-------}) so the name is unpredictable and other local users
 * can't read or replace the file. Never build a temp path by hand.</p>
 *
 * @author Alex Reyes
 */
public class SecureTempFiles {

    /**
     * @param suffix file suffix such as {@code .pdf}
     * @return a new, empty, owner-only temp file; caller deletes it
     */
    public Path create(String suffix) {
        // TODO(Alex) CWE-377 (fall back gracefully on Windows, where POSIX attributes aren't supported)
        throw new UnsupportedOperationException("TODO(Alex): CWE-377");
    }
}
