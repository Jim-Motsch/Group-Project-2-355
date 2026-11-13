package medvault.access;

import medvault.audit.AuditLogger;
import medvault.auth.UserRepository;
import medvault.model.AccessDeniedException;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.model.ValidationException;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Changes a user's role.
 *
 * <p><b>CWE-266: Incorrect Privilege Assignment.</b> A role is a bundle of
 * privileges, so handing one out is a privilege assignment and must be tightly
 * controlled. Only a session holding {@link Permission#MANAGE_USERS} (an
 * admin) may grant a role; a nurse or doctor who calls this is refused. Only
 * roles on the fixed allow-list {@link #ASSIGNABLE_ROLES} can be granted, and
 * nobody may change their own role, so no account can grant itself more
 * power. The caller's identity is the one {@link AccessPolicy} gets back from
 * the server, not the user printed on the {@code Session} object it was
 * handed.</p>
 *
 * <p><b>CWE-842: Placement of User into Incorrect Group.</b> MedVault's rule:
 * <b>no account can be moved into the ADMIN group through role
 * management</b>, which is why ADMIN is not on the allow-list. The only admin
 * account is the bootstrap one created at startup from
 * {@code MEDVAULT_ADMIN_PASSWORD}. This is checked here on the server,
 * whatever the client sends, so a compromised or careless admin session
 * cannot quietly create a second admin, and a request that names
 * {@code ADMIN} is refused and audited.</p>
 *
 * @author Martin Stoilkov
 */
public class RoleManager {

    /** Shown when someone tries to change their own role. */
    static final String SELF_CHANGE = "You can't change your own role.";
    /** Shown when someone tries to put an account into the ADMIN group. */
    static final String NO_ADMIN_PROMOTION = "Accounts can't be promoted to ADMIN through role management.";
    /** Shown for any other role that is not on the allow-list. */
    static final String NOT_ASSIGNABLE = "That role can't be assigned.";

    /** CWE-266: the only roles that can ever be granted. ADMIN is deliberately absent (CWE-842). */
    static final Set<Role> ASSIGNABLE_ROLES = Collections.unmodifiableSet(EnumSet.of(Role.NURSE, Role.DOCTOR));

    private final AccessPolicy policy;
    private final UserRepository users;
    private final AuditLogger audit;

    /**
     * @param policy permission checks
     * @param users  account storage
     * @param audit  records every role change and refusal
     */
    public RoleManager(AccessPolicy policy, UserRepository users, AuditLogger audit) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.users = Objects.requireNonNull(users, "users");
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    /**
     * @param admin          the caller's session
     * @param targetUsername account to change
     * @param newRole        requested role
     * @return the updated user
     * @throws medvault.model.AccessDeniedException if the change is not allowed
     * @throws ValidationException if the target account or role is missing
     */
    public User changeRole(Session admin, String targetUsername, Role newRole) {
        // CWE-266: only an admin (MANAGE_USERS) may grant a role; we act on the server's identity.
        User caller = policy.requireSession(admin, Permission.MANAGE_USERS).getUser();
        if (targetUsername == null || targetUsername.isBlank() || newRole == null) {
            throw new ValidationException("A target account and a role are required.");
        }
        if (caller.getUsername().equals(targetUsername)) {
            audit.record(caller, "ROLE_CHANGE_DENIED", "target=" + targetUsername + " reason=self");
            throw new AccessDeniedException(SELF_CHANGE);
        }
        // CWE-266: only roles on the fixed allow-list; ADMIN is never on it (CWE-842).
        if (!ASSIGNABLE_ROLES.contains(newRole)) {
            boolean toAdmin = newRole == Role.ADMIN;
            audit.record(caller, "ROLE_CHANGE_DENIED", "target=" + targetUsername + " to=" + newRole
                    + (toAdmin ? " reason=admin_promotion" : " reason=not_assignable"));
            throw new AccessDeniedException(toAdmin ? NO_ADMIN_PROMOTION : NOT_ASSIGNABLE);
        }
        Optional<User> target = users.find(targetUsername);
        if (target.isEmpty()) {
            throw new ValidationException("No such account.");
        }
        User updated = users.updateRole(targetUsername, newRole);
        audit.record(caller, "ROLE_CHANGED",
                "target=" + targetUsername + " from=" + target.get().getRole() + " to=" + newRole);
        return updated;
    }
}
