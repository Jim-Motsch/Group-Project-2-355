package medvault.app;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * Starts MedVault and runs the demo story. Contains no logic of its own;
 * see {@link MedVaultApp} for wiring and {@link DemoScenario} for the demo.
 *
 * <p>Usage: {@code mvn compile exec:java -Dexec.args="[--no-color] [--verbose] [--pause] [storageDir]"}</p>
 * <ul>
 *   <li>{@code --no-color}: plain text, no ANSI colours</li>
 *   <li>{@code --verbose}: show audit lines under each attempt and let
 *       {@code java.util.logging} print to the console</li>
 *   <li>{@code --pause}: wait for Enter between steps</li>
 * </ul>
 *
 * @author MedVault team
 */
public final class Main {

    private static final String USAGE =
            "Usage: Main [--no-color] [--verbose] [--pause] [storageDir]  (default storageDir: data/labs)";

    private Main() {
    }

    /**
     * @param args flags (see class doc) and an optional storage directory (default {@code ./data/labs})
     */
    public static void main(String[] args) throws Exception {
        boolean color = true;
        boolean verbose = false;
        boolean pause = false;
        String storage = "data/labs";
        for (String arg : args) {
            switch (arg) {
                case "--no-color":
                    color = false;
                    break;
                case "--verbose":
                    verbose = true;
                    break;
                case "--pause":
                    pause = true;
                    break;
                case "--help":
                case "-h":
                    System.out.println(USAGE);
                    return;
                default:
                    if (arg.startsWith("-")) {
                        System.err.println("Unknown option: " + arg);
                        System.err.println(USAGE);
                        System.exit(2);
                        return;
                    }
                    storage = arg;
            }
        }
        if (!verbose) {
            silenceConsoleLogging(); // before startup, which already writes an audit line
        }
        // The demo prints plain ASCII; UTF-8 only matters if data ever contains other characters.
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);

        MedVaultApp app;
        try {
            app = MedVaultApp.create(Path.of(storage));
        } catch (IllegalStateException misconfigured) {
            // Missing or weak secrets (CWE-798, CWE-521): refuse to start, say which setting.
            System.err.println("MedVault refused to start: " + misconfigured.getMessage());
            System.exit(1);
            return;
        }
        new DemoScenario(app, new DemoScenario.Options(color, verbose, pause), out, System.in).run();
    }

    /** Removes the root logger's console handler, so java.util.logging prints nothing to the terminal. */
    private static void silenceConsoleLogging() {
        Logger root = LogManager.getLogManager().getLogger("");
        for (Handler h : root.getHandlers()) {
            if (h instanceof ConsoleHandler) {
                root.removeHandler(h);
            }
        }
    }
}
