package medvault.records;

import medvault.model.Patient;
import medvault.model.ValidationException;
import medvault.security.CryptoService;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Writes and restores chart backups.
 *
 * <p><b>CWE-502: Deserialization of Untrusted Data.</b> A backup file could be
 * swapped by an attacker. Java's {@code ObjectInputStream} builds whatever
 * classes the stream names and runs their {@code readObject} code
 * <em>before</em> the application gets to look at the result, which is how
 * "gadget chain" attacks get remote code execution. So this class never uses
 * Java serialization at all. A backup is plain UTF-8 CSV with a fixed header,
 * and restore parses it field by field into {@link Patient} objects: each
 * value is checked (id is a number, date is ISO, lengths are bounded) and
 * anything unexpected, including a serialized Java object, is refused with a
 * {@link ValidationException}. Row count and field sizes are capped so a
 * hostile file can't exhaust memory.</p>
 *
 * <p>Built with a {@link CryptoService}, the notes column is stored as
 * AES-GCM ciphertext, so a backup file doesn't undo the encryption at rest;
 * the header records which form the notes are in.</p>
 *
 * <p>Format: line 1 {@code MEDVAULT-BACKUP,1,<notes-mode>}, line 2 the column
 * names, then one record per chart. Every field is double-quoted, with
 * {@code "} written as {@code ""}; quoted fields may span lines.</p>
 *
 * @author James Strickert
 */
public class BackupService {

    static final String MAGIC = "MEDVAULT-BACKUP";
    static final String VERSION = "1";
    static final String COLUMNS = "id,full_name,date_of_birth,attending,notes";
    static final int MAX_RECORDS = 100_000;
    static final int MAX_FIELD_CHARS = 200_000;

    private static final String PLAIN = "plain";
    private static final String ENCRYPTED = "aes-gcm";
    private static final int FIELDS = 5;
    private static final Pattern ATTENDING = Pattern.compile("[A-Za-z0-9._-]{1,100}");
    private static final String BAD_BACKUP = "The backup file is not a valid MedVault backup.";

    private final CryptoService crypto;

    /** Backups with notes in plain text (for tests and tooling; the app uses the encrypting one). */
    public BackupService() {
        this.crypto = null;
    }

    /** @param crypto encrypts the notes column in the backup file */
    public BackupService(CryptoService crypto) {
        this.crypto = Objects.requireNonNull(crypto, "crypto");
    }

    /**
     * @param patients charts to back up
     * @param out      destination; caller closes it
     */
    public void backup(List<Patient> patients, OutputStream out) {
        Objects.requireNonNull(patients, "patients");
        Objects.requireNonNull(out, "out");
        // Not try-with-resources: closing the writer would close the caller's stream.
        Writer w = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        try {
            w.write(MAGIC + "," + VERSION + "," + (crypto == null ? PLAIN : ENCRYPTED) + "\n");
            w.write(COLUMNS + "\n");
            for (Patient p : patients) {
                String notes = crypto == null ? p.getClinicalNotes() : crypto.encrypt(p.getClinicalNotes());
                w.write(quote(Long.toString(p.getId())) + "," + quote(p.getFullName()) + ","
                        + quote(p.getDateOfBirth().toString()) + "," + quote(p.getAttendingClinician()) + ","
                        + quote(notes) + "\n");
            }
            w.flush();
        } catch (IOException e) {
            throw new UncheckedIOException("backup could not be written", e);
        }
    }

    /**
     * @param in untrusted backup data; not closed by this method
     * @return the restored charts
     * @throws medvault.model.ValidationException if the data contains anything unexpected
     */
    public List<Patient> restore(InputStream in) {
        Objects.requireNonNull(in, "in");
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)));
        try {
            CsvReader csv = new CsvReader(r);
            List<String> header = csv.next();
            if (header == null || header.size() != 3 || !MAGIC.equals(header.get(0))
                    || !VERSION.equals(header.get(1))) {
                throw new ValidationException(BAD_BACKUP);
            }
            String mode = header.get(2);
            if (!PLAIN.equals(mode) && !ENCRYPTED.equals(mode)) {
                throw new ValidationException(BAD_BACKUP);
            }
            if (ENCRYPTED.equals(mode) && crypto == null) {
                throw new ValidationException("This backup is encrypted; restore it with the record key.");
            }
            List<String> columns = csv.next();
            if (columns == null || !COLUMNS.equals(String.join(",", columns))) {
                throw new ValidationException(BAD_BACKUP);
            }
            List<Patient> restored = new ArrayList<>();
            List<String> rec;
            while ((rec = csv.next()) != null) {
                if (restored.size() >= MAX_RECORDS) {
                    throw new ValidationException("The backup file has too many records.");
                }
                restored.add(toPatient(rec, ENCRYPTED.equals(mode)));
            }
            return restored;
        } catch (CharacterCodingException notText) {
            throw new ValidationException(BAD_BACKUP); // e.g. a binary Java-serialized stream
        } catch (IOException e) {
            throw new UncheckedIOException("backup could not be read", e);
        }
    }

    private Patient toPatient(List<String> f, boolean encrypted) {
        if (f.size() != FIELDS) {
            throw new ValidationException(BAD_BACKUP);
        }
        try {
            long id = Long.parseLong(f.get(0));
            String name = f.get(1);
            LocalDate dob = LocalDate.parse(f.get(2));
            String attending = f.get(3);
            if (id < 0 || name.isBlank() || name.length() > JdbcPatientRepository.MAX_NAME_LENGTH
                    || !ATTENDING.matcher(attending).matches()) {
                throw new ValidationException(BAD_BACKUP);
            }
            String notes = encrypted ? crypto.decrypt(f.get(4)) : f.get(4);
            return new Patient(id, name, dob, attending, notes);
        } catch (NumberFormatException | DateTimeParseException | SecurityException bad) {
            throw new ValidationException(BAD_BACKUP);
        }
    }

    private static String quote(String s) {
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    /**
     * Minimal RFC 4180 reader: fields may be quoted ({@code ""} is a literal
     * quote, quoted fields may contain commas and newlines) or bare. Field
     * length is capped while reading.
     */
    private static final class CsvReader {
        private final BufferedReader in;

        CsvReader(BufferedReader in) {
            this.in = in;
        }

        /** @return the next record, or null at end of input */
        List<String> next() throws IOException {
            int c = in.read();
            if (c == -1) {
                return null;
            }
            List<String> fields = new ArrayList<>(FIELDS);
            StringBuilder field = new StringBuilder();
            boolean quoted = false;
            boolean wasQuoted = false;
            while (true) {
                if (quoted) {
                    if (c == -1) {
                        throw new ValidationException(BAD_BACKUP); // unterminated quote
                    }
                    if (c == '"') {
                        in.mark(1);
                        int peek = in.read();
                        if (peek == '"') {
                            append(field, '"');
                        } else {
                            quoted = false;
                            if (peek != -1) {
                                in.reset();
                            }
                        }
                    } else {
                        append(field, (char) c);
                    }
                } else if (c == '"' && field.length() == 0 && !wasQuoted) {
                    quoted = true;
                    wasQuoted = true;
                } else if (c == ',' || c == '\n' || c == '\r' || c == -1) {
                    fields.add(field.toString());
                    if (fields.size() > FIELDS) {
                        throw new ValidationException(BAD_BACKUP);
                    }
                    if (c != ',') {
                        if (c == '\r') {
                            in.mark(1);
                            if (in.read() != '\n') {
                                in.reset();
                            }
                        }
                        return fields;
                    }
                    field.setLength(0);
                    wasQuoted = false;
                } else if (wasQuoted || c == '"') {
                    throw new ValidationException(BAD_BACKUP); // text after a closing quote, or stray quote
                } else {
                    append(field, (char) c);
                }
                c = in.read();
            }
        }

        private static void append(StringBuilder field, char c) {
            if (field.length() >= MAX_FIELD_CHARS) {
                throw new ValidationException("The backup file has a field that is too long.");
            }
            field.append(c);
        }
    }
}
