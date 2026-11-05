package medvault.access;

import medvault.audit.AuditLogger;
import medvault.auth.UserRepository;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;

import java.util.Objects;

/**
 * Changes a user's role.
 *
 * <p><b>CWE-269: Improper Privilege Management.</b> Only a session holding
 * {@link Permission#MANAGE_USERS} may change roles, and nobody may change
 * their own role.</p>
 *
 * <p><b>CWE-842: Placement of User into Incorrect Group.</b> The new role is
 * validated server-side against what the target account is allowed to be
 * (for example, an account created as a nurse cannot be made admin without
 * a second admin's approval, or whatever rule the team decides).</p>
 *
 * @author Martin Stoilkov
 */
public class RoleManager {
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
     */
    public User changeRole(Session admin, String targetUsername, Role newRole) {
        // TODO(Martin) CWE-269 / CWE-842
        throw new UnsupportedOperationException("TODO(Martin): CWE-269, CWE-842");
    }
}
