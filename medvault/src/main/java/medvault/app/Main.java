package medvault.app;

import java.nio.file.Path;

/**
 * Starts MedVault and runs the demo story. Contains no logic of its own;
 * see {@link MedVaultApp} for wiring and {@link DemoScenario} for the demo.
 *
 * @author MedVault team
 */
public final class Main {

    private Main() {
    }

    /**
     * @param args optional storage directory (default {@code ./data/labs})
     */
    public static void main(String[] args) throws Exception {
        Path storage = Path.of(args.length > 0 ? args[0] : "data/labs");
        MedVaultApp app;
        try {
            app = MedVaultApp.create(storage);
        } catch (UnsupportedOperationException notYet) {
            System.out.println("MedVault skeleton: startup needs " + notYet.getMessage()
                    + " before the demo can run.");
            return;
        }
        new DemoScenario(app).run();
    }
}
