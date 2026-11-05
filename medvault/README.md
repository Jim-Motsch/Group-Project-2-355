# MedVault

IT 355 Group Project 2: Research on CWE. MedVault is a small clinic patient-records system. Clinicians log in, open charts, search patients, attach lab reports, and every action is audited. Each of the 30 CWEs the team chose is a real defense on a real path through the app, so one request passes through several of them.

**Team:** Ian Beebe, Jimmy Motsch, James Strickert, Alex Reyes, Martin Stoilkov

## Build and run

You need Java 17+ and Maven 3.9+.

```bash
mvn test                  # run all tests
mvn compile exec:java     # run the demo story
```

The app reads its secrets from the environment and refuses to start without them (CWE-798, CWE-321):

```bash
export MEDVAULT_ADMIN_PASSWORD='...'
export MEDVAULT_DB_PASSWORD='...'
export MEDVAULT_RECORD_KEY="$(openssl rand -base64 32)"
```

## Layout and owners

| Package | Owner | Responsibility | CWEs |
| --- | --- | --- | --- |
| `medvault.auth` | Ian | Login, passwords, sessions | 307, 521, 613, 759, 798, 916 |
| `medvault.access` | Martin | Roles, permissions, chart ownership | 269, 283, 306, 639, 842, 1220 |
| `medvault.records` | James | Patient DB, search, import/export, backup | 78, 79, 89, 502, 611, 643 |
| `medvault.files` | Alex | Lab-report upload/download and storage | 22, 377, 404, 434, 732, 770 |
| `medvault.security`, `medvault.audit` | Jimmy | Encryption, randomness, logging, errors | 117, 209, 321, 327, 338, 532 |
| `medvault.model` | shared | `User`, `Role`, `Patient`, `LabReport`, `Session` | |
| `medvault.app` | shared | `MedVaultApp` (wiring), `DemoScenario`, `Main` | |

Every stub says which CWE it covers in its JavaDoc and throws `UnsupportedOperationException("TODO(Name): CWE-xxx")` until it's built. Search for `TODO(YourName)` to find your work.

## Build order

Some packages are needed by everyone else, so they go first:

1. **Jimmy, by Fri Nov 6:** `security` (`TokenGenerator`, `KeyProvider`, `CryptoService`) and `audit` (`AuditLogger`, `LogSanitizer`, `ErrorHandler`). Every other package calls these, and the app can't start without the key loader.
2. **Ian, by Fri Nov 6:** `SessionManager` and `CredentialsConfig` first, because `AccessPolicy` and startup need them. The rest of `auth` can follow.
3. **Everyone else, by Sat Nov 7:** `access`, `records` and `files`. Until steps 1 and 2 land, you can still write code and unit tests for anything that doesn't call them.

## How a request flows

```
Main -> MedVaultApp (wires everything)
  nurse login     auth.DefaultAuthService   PasswordPolicy, PasswordHasher, LoginAttemptTracker, SessionManager
  open chart      records.JdbcPatientRepository -> access.AccessPolicy (session valid? permission? on care team?)
  notes at rest   security.CryptoService (AES-GCM, key from KeyProvider)
  attach lab PDF  files.FileSystemLabReportStore -> UploadValidator, UploadLimits, SecureTempFiles
  every step      audit.AuditLogger -> LogSanitizer;  any error -> audit.ErrorHandler
```

## Using AI on your part

Paste [`AI_CONTEXT.md`](AI_CONTEXT.md) into your AI tool first. It explains the project, the architecture and the rules, and gives you a prompt to use, so your AI writes code that fits with everyone else's.

## Rules for everyone

1. **One class per file**, in your package. No new classes in `app` without telling the team.
2. **JavaDoc on every public class and method**, and name the CWE in the class JavaDoc.
3. **Constructor injection only.** Take what you need as constructor parameters; no static mutable state and no `new`-ing another package's service inside your class. Wiring lives in `MedVaultApp`.
4. **Errors:** throw `AccessDeniedException` or `ValidationException` with a user-safe message. Never put SQL, paths, stack traces or secrets in a message.
5. **Never log** passwords, tokens, patient names, dates of birth or notes. Log usernames, patient ids and actions through `AuditLogger`.
6. **Tests:** each package has an `*AttackTest` with one disabled test per CWE describing the target behavior. Remove `@Disabled` and fill it in as you finish each one. `mvn test` must pass before you push.
7. **Demo:** add your steps to `DemoScenario` so the story runs end to end.
8. Work on a branch named after you, then open a pull request into `main`.

## Generative AI acknowledgment

Per the syllabus (Level 4), the project skeleton, including its package layout, interfaces, stubs and test outlines, was generated with Claude (Anthropic) from the team's plan. The team chose the CWEs, wrote the implementations, and wrote the report explanations. *(Update this section before submitting to describe exactly how each member used AI.)*
