package medvault.model;

/**
 * Thrown when user input is rejected (bad password, bad upload, bad import).
 * The message is safe to show to the user (CWE-209).
 */
public class ValidationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** @param message a user-safe explanation */
    public ValidationException(String message) {
        super(message);
    }
}
