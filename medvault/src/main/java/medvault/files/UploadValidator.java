package medvault.files;

/**
 * Decides whether an uploaded file is an allowed type.
 *
 * <p><b>CWE-434: Unrestricted Upload of File with Dangerous Type.</b> Only
 * PDF and PNG are accepted. The type is decided from the file's first bytes
 * ({@code %PDF-} or the PNG signature), never from the client's file name
 * or Content-Type header, so {@code report.pdf.exe} or an EXE renamed to
 * {@code .pdf} is refused.</p>
 *
 * @author Alex Reyes
 */
public class UploadValidator {

    /**
     * @param header the first bytes of the upload (at least 8)
     * @return the detected MIME type, {@code application/pdf} or {@code image/png}
     * @throws medvault.model.ValidationException if the type is not allowed
     */
    public String detectAllowedType(byte[] header) {
        // TODO(Alex) CWE-434
        throw new UnsupportedOperationException("TODO(Alex): CWE-434");
    }
}
