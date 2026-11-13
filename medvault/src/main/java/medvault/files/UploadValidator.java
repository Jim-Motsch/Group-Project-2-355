package medvault.files;

import medvault.model.ValidationException;

/**
 * Decides whether an uploaded file is an allowed type.
 *
 * <p><b>CWE-434: Unrestricted Upload of File with Dangerous Type.</b> Only
 * PDF and PNG are accepted. The type is decided from the file's first bytes
 * ({@code %PDF-} or the PNG signature), never from the client's file name
 * or Content-Type header, so {@code report.pdf.exe} or an EXE renamed to
 * {@code .pdf} is refused. The stored file then gets an extension chosen by
 * the server from the detected type.</p>
 *
 * @author Alex Reyes
 */
public class UploadValidator {

    /** Bytes needed to recognize every allowed type. */
    public static final int HEADER_BYTES = 8;
    /** MIME type for PDF. */
    public static final String PDF = "application/pdf";
    /** MIME type for PNG. */
    public static final String PNG = "image/png";

    private static final byte[] PDF_MAGIC = {'%', 'P', 'D', 'F', '-'};
    private static final byte[] PNG_MAGIC = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    private static final String NOT_ALLOWED = "Only PDF and PNG lab reports can be uploaded.";

    /**
     * @param header the first bytes of the upload (at least 8)
     * @return the detected MIME type, {@code application/pdf} or {@code image/png}
     * @throws medvault.model.ValidationException if the type is not allowed
     */
    public String detectAllowedType(byte[] header) {
        if (header == null || header.length < HEADER_BYTES) {
            throw new ValidationException(NOT_ALLOWED);
        }
        if (startsWith(header, PDF_MAGIC)) {
            return PDF;
        }
        if (startsWith(header, PNG_MAGIC)) {
            return PNG;
        }
        throw new ValidationException(NOT_ALLOWED);
    }

    /**
     * @param mimeType a type returned by {@link #detectAllowedType(byte[])}
     * @return the extension the server uses for it
     */
    static String extensionFor(String mimeType) {
        return PNG.equals(mimeType) ? ".png" : ".pdf";
    }

    private static boolean startsWith(byte[] data, byte[] magic) {
        for (int i = 0; i < magic.length; i++) {
            if (data[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }
}
