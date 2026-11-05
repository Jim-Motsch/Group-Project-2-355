package medvault.files;

import medvault.model.LabReport;
import medvault.model.Session;

import java.io.InputStream;

/**
 * Stores and serves lab-report files attached to patient charts.
 *
 * @author Alex Reyes
 */
public interface LabReportStore {

    /**
     * @param session      uploader (needs UPLOAD_LAB and access to the patient)
     * @param patientId    chart to attach to
     * @param originalName client-supplied file name (untrusted, display only)
     * @param data         file contents (untrusted)
     * @return metadata for the stored file
     */
    LabReport upload(Session session, long patientId, String originalName, InputStream data);

    /**
     * @param session    downloader (needs DOWNLOAD_LAB and access to the patient)
     * @param storedName name from {@link LabReport#getStoredName()} (untrusted when it comes back from a client)
     * @return the file contents; caller closes the stream
     */
    InputStream download(Session session, String storedName);
}
