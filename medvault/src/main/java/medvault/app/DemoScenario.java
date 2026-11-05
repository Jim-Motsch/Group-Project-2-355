package medvault.app;

import medvault.security.CryptoService;
import medvault.security.KeyProvider;
import medvault.security.TokenGenerator;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * The in-class demo: one story in which an attacker tries to break into
 * MedVault and each layer stops a different attack, while a legitimate
 * nurse gets her work done. Each step prints what was attempted and what
 * happened.
 *
 * <p>Steps are filled in by each owner as their package is finished. A
 * step that isn't implemented yet prints "not implemented yet" instead of
 * crashing, so the demo can be run at any point during development.</p>
 *
 * @author MedVault team
 */
public final class DemoScenario {

    /** One step of the story. */
    @FunctionalInterface
    interface Step {
        /** @return a one-line result to print */
        String run() throws Exception;
    }

    private final MedVaultApp app;
    private final List<String> titles = new ArrayList<>();
    private final List<Step> steps = new ArrayList<>();

    /** @param app the wired application */
    public DemoScenario(MedVaultApp app) {
        this.app = Objects.requireNonNull(app, "app");
        define();
    }

    private void add(String title, Step step) {
        titles.add(title);
        steps.add(step);
    }

    private void define() {
        // Ian: CWE-521, 916, 759, 307, 613
        add("Admin creates nurse account with a weak password (CWE-521)", () -> {
            throw new UnsupportedOperationException("TODO(Ian)");
        });
        add("Attacker brute-forces the nurse's login and gets locked out (CWE-307)", () -> {
            throw new UnsupportedOperationException("TODO(Ian)");
        });
        // Martin: CWE-306, 639, 283, 269, 842, 1220
        add("Nurse logs in and changes the patient id to open another chart (CWE-639)", () -> {
            throw new UnsupportedOperationException("TODO(Martin)");
        });
        add("Nurse tries to promote herself to ADMIN (CWE-269)", () -> {
            throw new UnsupportedOperationException("TODO(Martin)");
        });
        // James: CWE-89, 79, 611, 643, 502, 78
        add("Search for \"' OR 1=1 --\" returns nothing extra (CWE-89)", () -> {
            throw new UnsupportedOperationException("TODO(James)");
        });
        add("Import an XML file with an external entity (CWE-611)", () -> {
            throw new UnsupportedOperationException("TODO(James)");
        });
        add("Export a chart whose notes contain <script> (CWE-79)", () -> {
            throw new UnsupportedOperationException("TODO(James)");
        });
        // Alex: CWE-434, 22, 770, 377, 732, 404
        add("Upload an .exe renamed to report.pdf (CWE-434)", () -> {
            throw new UnsupportedOperationException("TODO(Alex)");
        });
        add("Download ../../etc/passwd (CWE-22)", () -> {
            throw new UnsupportedOperationException("TODO(Alex)");
        });
        // Jimmy: CWE-327, 321, 338, 117, 532, 209
        add("Show notes are AES-GCM ciphertext in the database (CWE-327)", () -> {
            // Same key the app loaded at startup (MEDVAULT_RECORD_KEY, CWE-321).
            CryptoService crypto = new CryptoService(new KeyProvider().loadRecordKey(), new TokenGenerator());
            String note = "Pt reports chest pain; ECG ordered.";
            String first = crypto.encrypt(note);
            String second = crypto.encrypt(note);
            byte[] forged = Base64.getDecoder().decode(first);
            forged[forged.length - 20] ^= 0x01; // attacker flips one bit of the stored ciphertext
            String tamper;
            try {
                crypto.decrypt(Base64.getEncoder().encodeToString(forged));
                tamper = "tampered note was ACCEPTED";
            } catch (SecurityException rejected) {
                tamper = "tampered note rejected";
            }
            return "stored as " + first.substring(0, 24) + "... ; same note again -> "
                    + (first.equals(second) ? "SAME ciphertext" : "different ciphertext")
                    + " ; decrypts back " + (note.equals(crypto.decrypt(first)) ? "correctly" : "WRONG")
                    + " ; " + tamper;
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
            return (line.contains("\n") ? "FORGED a second line: " : "one line written: ") + line;
        });
    }

    /** Runs every step in order and prints the outcome of each. */
    public void run() {
        for (int i = 0; i < steps.size(); i++) {
            String result;
            try {
                result = steps.get(i).run();
            } catch (UnsupportedOperationException notYet) {
                result = "not implemented yet";
            } catch (Exception e) {
                result = app.errors().toUserMessage(e);
            }
            System.out.printf("%2d. %s%n    -> %s%n", i + 1, titles.get(i), result);
        }
    }
}
