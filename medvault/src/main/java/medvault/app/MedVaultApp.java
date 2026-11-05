package medvault.app;

import medvault.access.AccessPolicy;
import medvault.access.CareTeam;
import medvault.access.InMemoryCareTeam;
import medvault.access.RoleManager;
import medvault.audit.AuditLogger;
import medvault.audit.ErrorHandler;
import medvault.audit.LogSanitizer;
import medvault.auth.AuthService;
import medvault.auth.CredentialsConfig;
import medvault.auth.DefaultAuthService;
import medvault.auth.InMemoryUserRepository;
import medvault.auth.LoginAttemptTracker;
import medvault.auth.PasswordHasher;
import medvault.auth.PasswordPolicy;
import medvault.auth.SessionManager;
import medvault.auth.UserRepository;
import medvault.files.FileSystemLabReportStore;
import medvault.files.LabReportStore;
import medvault.files.SecureTempFiles;
import medvault.files.UploadLimits;
import medvault.files.UploadValidator;
import medvault.records.BackupService;
import medvault.records.Database;
import medvault.records.JdbcPatientRepository;
import medvault.records.PatientRepository;
import medvault.records.RecordExporter;
import medvault.records.ReportPrinter;
import medvault.records.XmlRecordImporter;
import medvault.security.CryptoService;
import medvault.security.KeyProvider;
import medvault.security.TokenGenerator;

import java.nio.file.Path;
import java.time.Clock;

/**
 * Builds the whole application by constructor injection. This is the only
 * class that knows how the packages fit together; no package reaches into
 * another through static state.
 *
 * @author MedVault team
 */
public final class MedVaultApp {
    private final AuthService auth;
    private final AccessPolicy access;
    private final RoleManager roles;
    private final CareTeam careTeam;
    private final PatientRepository patients;
    private final RecordExporter exporter;
    private final XmlRecordImporter importer;
    private final BackupService backups;
    private final ReportPrinter printer;
    private final LabReportStore labs;
    private final AuditLogger audit;
    private final ErrorHandler errors;

    private MedVaultApp(AuthService auth, AccessPolicy access, RoleManager roles, CareTeam careTeam,
                        PatientRepository patients, RecordExporter exporter, XmlRecordImporter importer,
                        BackupService backups, ReportPrinter printer, LabReportStore labs,
                        AuditLogger audit, ErrorHandler errors) {
        this.auth = auth;
        this.access = access;
        this.roles = roles;
        this.careTeam = careTeam;
        this.patients = patients;
        this.exporter = exporter;
        this.importer = importer;
        this.backups = backups;
        this.printer = printer;
        this.labs = labs;
        this.audit = audit;
        this.errors = errors;
    }

    /**
     * Wires every component. Secrets come from the environment
     * (CWE-798, CWE-321).
     *
     * @param storageRoot directory for lab-report files
     * @return a ready application
     */
    public static MedVaultApp create(Path storageRoot) throws Exception {
        Clock clock = Clock.systemUTC();

        // security + audit (Jimmy)
        TokenGenerator random = new TokenGenerator();
        CryptoService crypto = new CryptoService(new KeyProvider().loadRecordKey(), random);
        AuditLogger audit = new AuditLogger(new LogSanitizer());
        ErrorHandler errors = new ErrorHandler(audit);

        // auth (Ian)
        CredentialsConfig creds = CredentialsConfig.fromEnvironment();
        UserRepository users = new InMemoryUserRepository();
        SessionManager sessions = new SessionManager(random, clock);
        AuthService auth = new DefaultAuthService(users, new PasswordPolicy(),
                new PasswordHasher(random), new LoginAttemptTracker(clock), sessions, audit);

        // access (Martin)
        CareTeam careTeam = new InMemoryCareTeam();
        AccessPolicy access = new AccessPolicy(sessions, careTeam, audit);
        RoleManager roles = new RoleManager(access, users, audit);

        // records (James)
        Database db = new Database("jdbc:h2:mem:medvault;DB_CLOSE_DELAY=-1", "medvault",
                creds.databasePassword());
        db.createSchema();
        PatientRepository patients = new JdbcPatientRepository(db, crypto, access, audit);

        // files (Alex)
        LabReportStore labs = new FileSystemLabReportStore(storageRoot, new UploadValidator(),
                new UploadLimits(), new SecureTempFiles(), access, audit);

        return new MedVaultApp(auth, access, roles, careTeam, patients, new RecordExporter(),
                new XmlRecordImporter(), new BackupService(), new ReportPrinter(), labs, audit, errors);
    }

    /** @return login and account creation */
    public AuthService auth() {
        return auth;
    }

    /** @return permission checks */
    public AccessPolicy access() {
        return access;
    }

    /** @return role changes */
    public RoleManager roles() {
        return roles;
    }

    /** @return patient assignments */
    public CareTeam careTeam() {
        return careTeam;
    }

    /** @return chart storage */
    public PatientRepository patients() {
        return patients;
    }

    /** @return HTML export */
    public RecordExporter exporter() {
        return exporter;
    }

    /** @return XML import */
    public XmlRecordImporter importer() {
        return importer;
    }

    /** @return backup and restore */
    public BackupService backups() {
        return backups;
    }

    /** @return PDF conversion */
    public ReportPrinter printer() {
        return printer;
    }

    /** @return lab-report files */
    public LabReportStore labs() {
        return labs;
    }

    /** @return audit trail */
    public AuditLogger audit() {
        return audit;
    }

    /** @return user-safe error messages */
    public ErrorHandler errors() {
        return errors;
    }
}
