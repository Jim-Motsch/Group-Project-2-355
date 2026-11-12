package medvault.access;

import medvault.audit.AuditLogger;
import medvault.audit.LogSanitizer;
import medvault.auth.InMemoryUserRepository;
import medvault.auth.SessionManager;
import medvault.model.AccessDeniedException;
import medvault.model.Patient;
import medvault.model.Role;
import medvault.model.Session;
import medvault.model.User;
import medvault.model.ValidationException;
import medvault.security.TokenGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack tests for the access package. Each test attempts the attack for one
 * CWE and asserts it fails; {@link #legitimateClinicalWorkIsAllowed()} shows
 * the normal case works. Uses a real {@link SessionManager},
 * {@link InMemoryCareTeam} and {@link InMemoryUserRepository}.
 *
 * @author Martin Stoilkov
 */
class AccessAttackTest {

    /** A clock the test can move forward. */
    private static final class MutableClock extends Clock {
        private volatile Instant now = Instant.parse("2026-11-05T08:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    private static final long PATIENT_1 = 1;
    private static final long PATIENT_2 = 2;

    private final MutableClock clock = new MutableClock();
    private final SessionManager sessions = new SessionManager(new TokenGenerator(), clock);
    private final InMemoryCareTeam careTeam = new InMemoryCareTeam();
    private final InMemoryUserRepository users = new InMemoryUserRepository();
    private final AuditLogger audit = new AuditLogger(new LogSanitizer());
    private final AccessPolicy policy = new AccessPolicy(sessions, careTeam, users, audit);
    private final RoleManager roles = new RoleManager(policy, users, audit);

    private final User nurseUser = new User("nurse.joy", Role.NURSE);
    private final User doctorUser = new User("dr.grey", Role.DOCTOR);
    private final User otherDoctorUser = new User("dr.house", Role.DOCTOR);
    private final User adminUser = new User("admin", Role.ADMIN);
    private final Patient patient1 = new Patient(PATIENT_1, "Alice Example", LocalDate.of(1980, 1, 31), "dr.grey", "");
    private final Patient patient2 = new Patient(PATIENT_2, "Bob Sample", LocalDate.of(1975, 6, 15), "dr.house", "");

    private Session nurse;
    private Session doctor;
    private Session otherDoctor;
    private Session admin;

    private final List<String> auditLines = Collections.synchronizedList(new ArrayList<>());
    private final Logger auditLog = Logger.getLogger("medvault.audit");
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            auditLines.add(record.getMessage());
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @BeforeEach
    void setUp() {
        auditLog.addHandler(capture);
        auditLog.setUseParentHandlers(false);
        for (User u : List.of(nurseUser, doctorUser, otherDoctorUser, adminUser)) {
            users.save(u, "unused-in-these-tests");
        }
        nurse = sessions.create(nurseUser);
        doctor = sessions.create(doctorUser);
        otherDoctor = sessions.create(otherDoctorUser);
        admin = sessions.create(adminUser);
        careTeam.assign(PATIENT_1, "dr.grey");
        careTeam.assign(PATIENT_1, "nurse.joy");
        careTeam.assign(PATIENT_1, "dr.house"); // consulting doctor: on the team, not the owner
        careTeam.assign(PATIENT_2, "dr.house");
    }

    @AfterEach
    void tearDown() {
        auditLog.removeHandler(capture);
        auditLog.setUseParentHandlers(true);
    }

    @Test
    void legitimateClinicalWorkIsAllowed() {
        assertDoesNotThrow(() -> policy.requireCanRead(nurse, patient1));
        assertDoesNotThrow(() -> policy.require(nurse, Permission.UPLOAD_LAB));
        assertDoesNotThrow(() -> policy.requireCanRead(doctor, patient1));
        assertDoesNotThrow(() -> policy.requireCanEdit(doctor, patient1));
        assertDoesNotThrow(() -> policy.require(doctor, Permission.EXPORT_CHART));
        assertDoesNotThrow(() -> policy.require(admin, Permission.MANAGE_USERS));
        assertTrue(policy.canRead(nurse, patient1));
        assertFalse(policy.canRead(nurse, patient2));
        assertEquals("nurse.joy", policy.requireOnCareTeam(nurse, Permission.DOWNLOAD_LAB, PATIENT_1)
                .getUser().getUsername());
        assertTrue(auditLines.isEmpty(), "allowed checks write no denial lines: " + auditLines);
    }

    // ---- CWE-306: Missing Authentication for Critical Function ----

    @Test
    void forgedSessionIsRejected() {
        // Attack 1: build a Session object by hand with a made-up token and an ADMIN user.
        Session forged = new Session(new TokenGenerator().newSessionToken(), adminUser, clock.instant().plusSeconds(600));
        assertThrows(AccessDeniedException.class, () -> policy.require(forged, Permission.MANAGE_USERS));
        assertThrows(AccessDeniedException.class, () -> policy.requireCanRead(forged, patient1));
        assertThrows(AccessDeniedException.class, () -> policy.require(null, Permission.READ_CHART));

        // Attack 2: a real nurse token wrapped in a Session that claims to be the attending doctor.
        Session wrapped = new Session(nurse.getToken(), doctorUser, nurse.getExpiresAt());
        assertThrows(AccessDeniedException.class, () -> policy.requireCanEdit(wrapped, patient1),
                "the server's user (the nurse) is used, not the claimed one");
        assertEquals("nurse.joy", policy.requireSession(wrapped, Permission.READ_CHART).getUser().getUsername());

        // Attack 3: keep using a session after logout or after it expired.
        sessions.logout(doctor.getToken());
        assertThrows(AccessDeniedException.class, () -> policy.requireCanRead(doctor, patient1));
        clock.advance(SessionManager.IDLE_TIMEOUT);
        assertThrows(AccessDeniedException.class, () -> policy.requireCanRead(nurse, patient1));
        assertThrows(AccessDeniedException.class, () -> policy.canRead(nurse, patient1),
                "even the non-throwing read check refuses an expired session");
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=SESSION_REJECTED")));
    }

    // ---- CWE-639: Authorization Bypass Through User-Controlled Key ----

    @Test
    void nurseCannotOpenUnassignedChart() {
        assertDoesNotThrow(() -> policy.requireCanRead(nurse, patient1));
        // Attack: same nurse, same permission, just a different patient id.
        AccessDeniedException e = assertThrows(AccessDeniedException.class,
                () -> policy.requireCanRead(nurse, patient2));
        assertEquals(AccessPolicy.NOT_ON_TEAM, e.getMessage());
        assertThrows(AccessDeniedException.class,
                () -> policy.requireOnCareTeam(nurse, Permission.UPLOAD_LAB, PATIENT_2));
        assertThrows(AccessDeniedException.class, () -> policy.requireCanRead(doctor, patient2),
                "doctors are limited to their own patients too");
        String line = auditLines.get(0);
        assertTrue(line.contains("action=ACCESS_DENIED") && line.contains("patient=2"), line);
        assertFalse(line.contains("Bob"), "audit uses ids, never names: " + line);
    }

    // ---- CWE-283: Unverified Ownership ----

    @Test
    void onlyAttendingClinicianCanEdit() {
        // Nurse is on the team but has no EDIT_CHART.
        assertThrows(AccessDeniedException.class, () -> policy.requireCanEdit(nurse, patient1));
        // Attack: a doctor on the care team (has EDIT_CHART and can read) edits a chart they don't own.
        assertDoesNotThrow(() -> policy.requireCanRead(otherDoctor, patient1));
        AccessDeniedException e = assertThrows(AccessDeniedException.class,
                () -> policy.requireCanEdit(otherDoctor, patient1));
        assertEquals(AccessPolicy.NOT_ATTENDING, e.getMessage());
        // Legitimate: the attending clinician may edit.
        assertDoesNotThrow(() -> policy.requireCanEdit(doctor, patient1));
        assertDoesNotThrow(() -> policy.requireCanEdit(otherDoctor, patient2));
    }

    // ---- CWE-1220: Insufficient Granularity of Access Control ----

    @Test
    void adminCannotReadCharts() {
        assertEquals(EnumSet.of(Permission.MANAGE_USERS), Permission.grantedTo(Role.ADMIN));
        careTeam.assign(PATIENT_1, "admin"); // even if someone adds the admin to a care team
        for (Permission clinical : EnumSet.complementOf(EnumSet.of(Permission.MANAGE_USERS))) {
            assertThrows(AccessDeniedException.class, () -> policy.require(admin, clinical), clinical.name());
        }
        assertThrows(AccessDeniedException.class, () -> policy.requireCanRead(admin, patient1));
        assertFalse(policy.canRead(admin, patient1));

        // The rest of the table: nurses can't edit, export, import or manage users; doctors can't manage users.
        Set<Permission> nursePerms = Permission.grantedTo(Role.NURSE);
        assertEquals(EnumSet.of(Permission.READ_CHART, Permission.UPLOAD_LAB, Permission.DOWNLOAD_LAB), nursePerms);
        Set<Permission> doctorPerms = Permission.grantedTo(Role.DOCTOR);
        assertTrue(doctorPerms.containsAll(nursePerms));
        assertTrue(doctorPerms.containsAll(EnumSet.of(Permission.EDIT_CHART, Permission.EXPORT_CHART,
                Permission.IMPORT_RECORDS)));
        assertFalse(doctorPerms.contains(Permission.MANAGE_USERS));
        assertThrows(AccessDeniedException.class, () -> policy.require(nurse, Permission.EXPORT_CHART));
        assertThrows(UnsupportedOperationException.class, () -> nursePerms.add(Permission.MANAGE_USERS),
                "callers can't widen a role by mutating the returned set");
    }

    // ---- CWE-266: Incorrect Privilege Assignment ----

    @Test
    void nonAdminCannotGrantARole() {
        // Attack: a doctor and a nurse (no MANAGE_USERS) try to hand out roles to other accounts.
        AccessDeniedException byDoctor = assertThrows(AccessDeniedException.class,
                () -> roles.changeRole(doctor, "nurse.joy", Role.DOCTOR));
        assertEquals(AccessPolicy.NOT_PERMITTED, byDoctor.getMessage());
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(nurse, "dr.house", Role.NURSE));
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(otherDoctor, "dr.grey", Role.NURSE));
        // A forged session claiming to be admin is no better.
        Session forged = new Session(new TokenGenerator().newSessionToken(), adminUser, admin.getExpiresAt());
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(forged, "nurse.joy", Role.DOCTOR));
        assertEquals(Role.NURSE, users.find("nurse.joy").orElseThrow().getRole(), "nothing was granted");
        assertEquals(Role.DOCTOR, users.find("dr.house").orElseThrow().getRole());
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=ACCESS_DENIED")
                && l.contains("permission=MANAGE_USERS")), auditLines.toString());
    }

    @Test
    void onlyAllowListedRolesCanBeGranted() {
        // The allow-list is fixed: the clinical roles only.
        assertEquals(EnumSet.of(Role.NURSE, Role.DOCTOR), RoleManager.ASSIGNABLE_ROLES);
        assertThrows(UnsupportedOperationException.class, () -> RoleManager.ASSIGNABLE_ROLES.add(Role.ADMIN),
                "the allow-list can't be widened at run time");
        for (Role role : Role.values()) {
            if (RoleManager.ASSIGNABLE_ROLES.contains(role)) {
                assertEquals(role, roles.changeRole(admin, "dr.house", role).getRole(), "admin may grant " + role);
            } else {
                assertThrows(AccessDeniedException.class, () -> roles.changeRole(admin, "dr.house", role),
                        role + " is not on the allow-list");
            }
        }
    }

    @Test
    void userCannotChangeOwnRole() {
        // Attack: the nurse tries to make herself ADMIN (or DOCTOR).
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(nurse, "nurse.joy", Role.ADMIN));
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(nurse, "nurse.joy", Role.DOCTOR));
        // Even an admin can't change their own role.
        AccessDeniedException self = assertThrows(AccessDeniedException.class,
                () -> roles.changeRole(admin, "admin", Role.DOCTOR));
        assertEquals(RoleManager.SELF_CHANGE, self.getMessage());
        // A real admin token wrapped in a Session claiming a different user is still "self".
        Session disguised = new Session(admin.getToken(), new User("someone.else", Role.ADMIN), admin.getExpiresAt());
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(disguised, "admin", Role.NURSE));
        assertEquals(Role.NURSE, users.find("nurse.joy").orElseThrow().getRole());
        assertEquals(Role.ADMIN, users.find("admin").orElseThrow().getRole());
    }

    @Test
    void roleChangesTakeEffectOnOpenSessions() {
        // Legitimate: an admin moves a doctor to NURSE...
        User demoted = roles.changeRole(admin, "dr.grey", Role.NURSE);
        assertEquals(Role.NURSE, demoted.getRole());
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=ROLE_CHANGED")
                && l.contains("from=DOCTOR") && l.contains("to=NURSE")));
        // ...and the doctor's already-open session loses EDIT_CHART immediately.
        assertThrows(AccessDeniedException.class, () -> policy.requireCanEdit(doctor, patient1));
        assertDoesNotThrow(() -> policy.requireCanRead(doctor, patient1));
        assertThrows(ValidationException.class, () -> roles.changeRole(admin, "no.such.user", Role.NURSE));
    }

    // ---- CWE-842: Placement of User into Incorrect Group ----

    @Test
    void roleChangeIsValidatedServerSide() {
        // Rule: no account is ever moved into ADMIN through role management, even by an admin.
        AccessDeniedException e = assertThrows(AccessDeniedException.class,
                () -> roles.changeRole(admin, "nurse.joy", Role.ADMIN));
        assertEquals(RoleManager.NO_ADMIN_PROMOTION, e.getMessage());
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(admin, "dr.grey", Role.ADMIN));
        assertEquals(Role.NURSE, users.find("nurse.joy").orElseThrow().getRole(), "nothing changed");
        assertEquals(Role.DOCTOR, users.find("dr.grey").orElseThrow().getRole());
        assertTrue(auditLines.stream().anyMatch(l -> l.contains("action=ROLE_CHANGE_DENIED")
                && l.contains("reason=admin_promotion")));
        // A doctor (no MANAGE_USERS) can't move anyone at all.
        assertThrows(AccessDeniedException.class, () -> roles.changeRole(doctor, "nurse.joy", Role.DOCTOR));
        assertThrows(ValidationException.class, () -> roles.changeRole(admin, "nurse.joy", null));
        // Legitimate: moving between clinical groups is allowed.
        assertEquals(Role.DOCTOR, roles.changeRole(admin, "nurse.joy", Role.DOCTOR).getRole());
    }
}
