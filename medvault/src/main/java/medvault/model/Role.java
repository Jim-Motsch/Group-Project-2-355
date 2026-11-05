package medvault.model;

/**
 * The roles a MedVault user can hold. Permissions for each role are defined
 * in {@link medvault.access.Permission} and enforced by the access package.
 */
public enum Role {
    /** Can read charts for assigned patients and upload lab reports. */
    NURSE,
    /** Can read and edit charts for patients they attend. */
    DOCTOR,
    /** Manages user accounts and roles; cannot read clinical data. */
    ADMIN
}
