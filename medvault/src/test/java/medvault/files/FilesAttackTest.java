package medvault.files;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Attack tests for the files package. Each test is the target behavior for one
 * CWE. Remove {@code @Disabled} as you implement it; by integration day
 * (Nov 8) none should be disabled.
 *
 * @author Alex Reyes
 */
class FilesAttackTest {

    @Test
    @Disabled("TODO(Alex): CWE-22")
    void downloadRejectsPathTraversal() {
        // download(s, "../../etc/passwd") -> AccessDeniedException or ValidationException
    }

    @Test
    @Disabled("TODO(Alex): CWE-434")
    void renamedExecutableIsRejected() {
        // bytes starting with "MZ" named report.pdf -> ValidationException
    }

    @Test
    @Disabled("TODO(Alex): CWE-770")
    void oversizedUploadIsRejected() {
        // a stream of MAX_FILE_BYTES + 1 bytes -> ValidationException, nothing left on disk
    }

    @Test
    @Disabled("TODO(Alex): CWE-377")
    void tempFileIsOwnerOnly() {
        // Files.getPosixFilePermissions(create(".pdf")) == rw-------
    }

    @Test
    @Disabled("TODO(Alex): CWE-732")
    void storedFilesAreOwnerOnly() {
        // storage dir rwx------ and each stored file rw-------
    }

    @Test
    @Disabled("TODO(Alex): CWE-404")
    void streamsClosedOnFailedUpload() {
        // a failing upload leaves no open handle and no temp file behind
    }
}
