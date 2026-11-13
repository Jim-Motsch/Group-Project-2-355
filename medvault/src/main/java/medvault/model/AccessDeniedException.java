package medvault.model;

/**
 * Thrown when a request is refused by authentication or authorization.
 * The message is safe to show to the user; it never contains internal
 * details.
 */
public class AccessDeniedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** @param message a user-safe explanation */
    public AccessDeniedException(String message) {
        super(message);
    }
}
