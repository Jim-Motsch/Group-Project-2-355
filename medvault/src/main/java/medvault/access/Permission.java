package medvault.access;

import medvault.model.Role;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * Fine-grained actions a role may perform.
 *
 * <p><b>CWE-1220: Insufficient Granularity of Access Control.</b> Reading a
 * chart, editing it, uploading labs and managing users are separate
 * permissions. No single "can do anything with records" flag exists, and an
 * admin who manages accounts cannot read clinical data.</p>
 *
 * <p>The table, and why:</p>
 * <ul>
 *   <li><b>NURSE</b>: {@code READ_CHART}, {@code UPLOAD_LAB},
 *       {@code DOWNLOAD_LAB}. Nurses chart vitals and attach results but do
 *       not change diagnoses or send records out of the clinic.</li>
 *   <li><b>DOCTOR</b>: everything a nurse has plus {@code EDIT_CHART},
 *       {@code EXPORT_CHART}, {@code IMPORT_RECORDS}. Doctors own charts and
 *       exchange records with other clinics.</li>
 *   <li><b>ADMIN</b>: {@code MANAGE_USERS} only. Account management is IT
 *       work; it needs no patient data, so a compromised admin account
 *       exposes no charts.</li>
 * </ul>
 *
 * @author Martin Stoilkov
 */
public enum Permission {
    /** Open a chart (still requires care-team membership). */
    READ_CHART,
    /** Change a chart (still requires being the attending clinician). */
    EDIT_CHART,
    /** Attach a lab report to a chart. */
    UPLOAD_LAB,
    /** Read an attached lab report. */
    DOWNLOAD_LAB,
    /** Export a chart as HTML/PDF. */
    EXPORT_CHART,
    /** Import charts from another clinic. */
    IMPORT_RECORDS,
    /** Create accounts and change roles. */
    MANAGE_USERS;

    private static final Set<Permission> NURSE_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(READ_CHART, UPLOAD_LAB, DOWNLOAD_LAB));
    private static final Set<Permission> DOCTOR_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(READ_CHART, UPLOAD_LAB, DOWNLOAD_LAB,
                    EDIT_CHART, EXPORT_CHART, IMPORT_RECORDS));
    private static final Set<Permission> ADMIN_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(MANAGE_USERS));

    /**
     * @param role a role
     * @return the permissions granted to that role (unmodifiable)
     */
    public static Set<Permission> grantedTo(Role role) {
        Objects.requireNonNull(role, "role");
        switch (role) {
            case NURSE:
                return NURSE_PERMISSIONS;
            case DOCTOR:
                return DOCTOR_PERMISSIONS;
            case ADMIN:
                return ADMIN_PERMISSIONS;
            default:
                return Collections.emptySet(); // a new role gets nothing until it is added here
        }
    }
}
