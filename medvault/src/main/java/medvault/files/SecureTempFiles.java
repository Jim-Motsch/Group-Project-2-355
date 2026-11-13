package medvault.files;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Creates temporary files for uploads in progress and PDF rendering.
 *
 * <p><b>CWE-378: Creation of Temporary File With Insecure Permissions.</b>
 * Uploads in progress sit in a temp directory that other local accounts can
 * list, so a temp file created with the default {@code rw-r--r--} lets anyone
 * on the machine read a patient's lab report before it is stored. Where the
 * file system supports POSIX permissions, the file is created
 * {@code rw-------} in the same {@link Files#createTempFile} call, so it is
 * never readable by others, even for a moment. Elsewhere (Windows) the file
 * is restricted right after creation with
 * {@link java.io.File#setReadable(boolean, boolean)} and
 * {@link java.io.File#setWritable(boolean, boolean)} (owner only, best
 * effort), on top of the user-private ACL of the temp directory.
 * {@code createTempFile} also picks an unpredictable name and never reuses an
 * existing file. Callers delete the file after use: the lab-report store does
 * so in a {@code finally} block, so a failed upload never leaves one
 * behind.</p>
 *
 * @author Alex Reyes
 */
public class SecureTempFiles {

    static final String PREFIX = "medvault-";
    static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
    /** Suffixes are short and plain, so a caller can't sneak a path into the name. */
    private static final Pattern SUFFIX = Pattern.compile("\\.[A-Za-z0-9]{1,10}");

    private final Path dir;

    /** Creates temp files in the system temp directory. */
    public SecureTempFiles() {
        this.dir = null;
    }

    /** @param dir directory for temp files (for example a private work directory) */
    public SecureTempFiles(Path dir) {
        this.dir = Objects.requireNonNull(dir, "dir");
    }

    /**
     * @param suffix file suffix such as {@code .pdf}
     * @return a new, empty, owner-only temp file; caller deletes it
     * @throws IllegalArgumentException if the suffix is not like {@code .pdf}
     */
    public Path create(String suffix) {
        if (suffix == null || !SUFFIX.matcher(suffix).matches()) {
            throw new IllegalArgumentException("suffix must look like .pdf");
        }
        try {
            if (supportsPosix()) {
                FileAttribute<Set<PosixFilePermission>> ownerOnly = PosixFilePermissions.asFileAttribute(OWNER_ONLY);
                return dir == null
                        ? Files.createTempFile(PREFIX, suffix, ownerOnly)
                        : Files.createTempFile(dir, PREFIX, suffix, ownerOnly);
            }
            Path temp = dir == null
                    ? Files.createTempFile(PREFIX, suffix)
                    : Files.createTempFile(dir, PREFIX, suffix);
            restrictToOwner(temp.toFile());
            return temp;
        } catch (IOException e) {
            throw new UncheckedIOException("could not create a temporary file", e);
        }
    }

    /**
     * Owner-only fallback where POSIX permissions don't exist (CWE-378): take
     * the permission away from everyone, then give it back to the owner. Best
     * effort; Windows ignores what it can't express, and the temp directory's
     * ACL is already user-private there.
     */
    static void restrictToOwner(java.io.File f) {
        f.setReadable(false, false);
        f.setReadable(true, true);
        f.setWritable(false, false);
        f.setWritable(true, true);
        f.setExecutable(false, false);
    }

    /** True if the temp location understands POSIX permissions (Linux, macOS; not Windows). */
    private boolean supportsPosix() throws IOException {
        Path where = dir != null ? dir : Path.of(System.getProperty("java.io.tmpdir"));
        return Files.getFileStore(where).supportsFileAttributeView(PosixFileAttributeView.class);
    }
}
