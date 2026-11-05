package medvault.access;

import medvault.model.Role;

import java.util.EnumSet;
import java.util.Set;

/**
 * Fine-grained actions a role may perform.
 *
 * <p><b>CWE-1220: Insufficient Granularity of Access Control.</b> Reading a
 * chart, editing it, uploading labs and managing users are separate
 * permissions. No single "can do anything with records" flag exists, and an
 * admin who manages accounts cannot read clinical data.</p>
 *
 * @author Martin Stoilkov
 */
public enum Permission {
    READ_CHART,
    EDIT_CHART,
    UPLOAD_LAB,
    DOWNLOAD_LAB,
    EXPORT_CHART,
    IMPORT_RECORDS,
    MANAGE_USERS;

    /**
     * @param role a role
     * @return the permissions granted to that role
     */
    public static Set<Permission> grantedTo(Role role) {
        // TODO(Martin) CWE-1220: fill in the role -> permission table and justify it in the report.
        switch (role) {
            case NURSE:
            case DOCTOR:
            case ADMIN:
            default:
                return EnumSet.noneOf(Permission.class);
        }
    }
}
