package medvault.records;

import medvault.model.Patient;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * Writes and restores chart backups.
 *
 * <p><b>CWE-502: Deserialization of Untrusted Data.</b> A backup file could be
 * swapped by an attacker, so restore never calls {@code ObjectInputStream}
 * on it without a strict {@link java.io.ObjectInputFilter} allow-list of
 * MedVault types. Simpler still: use a plain text format (CSV or JSON) and
 * parse it field by field.</p>
 *
 * @author James Strickert
 */
public class BackupService {

    /**
     * @param patients charts to back up
     * @param out      destination; caller closes it
     */
    public void backup(List<Patient> patients, OutputStream out) {
        // TODO(James) CWE-502
        throw new UnsupportedOperationException("TODO(James): CWE-502");
    }

    /**
     * @param in untrusted backup data
     * @return the restored charts
     * @throws medvault.model.ValidationException if the data contains anything unexpected
     */
    public List<Patient> restore(InputStream in) {
        // TODO(James) CWE-502
        throw new UnsupportedOperationException("TODO(James): CWE-502");
    }
}
