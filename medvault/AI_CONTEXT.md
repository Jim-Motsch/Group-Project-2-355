# AI context for MedVault

Paste this whole file into your AI tool (ChatGPT, Claude, Copilot Chat, Gemini, ...) **first**, then attach or paste the files for your package, then use the prompt at the bottom.

## The assignment

IT 355 (Software Security) Group Project 2, "Research on CWE". Each of 5 team members picks 6 CWEs from CWE-699 that apply to Java. The team writes **one larger Java program combining all 30 CWEs to show how to avoid them** (80 of 150 report points).

Our Project 1 lost most of these points because the code was "a collection of isolated security snippets bundled into a single file" with "no unifying idea," and one giant file "breaks core software engineering standards." So this time:

- One real application with one purpose: **MedVault, a clinic patient-records system.**
- Every CWE defense sits on a real path through the app, not a standalone demo method.
- Proper structure: Maven, one package per layer, one class per file, interfaces, constructor injection, JUnit 5 tests.

## Architecture (already built; do not restructure it)

- Java 17, Maven, JUnit 5, H2 embedded database. No other dependencies without asking the team.
- `medvault.model`: shared immutable classes `User`, `Role` (NURSE, DOCTOR, ADMIN), `Patient`, `LabReport`, `Session`, plus `AccessDeniedException` and `ValidationException` (messages must be user-safe).
- `medvault.app.MedVaultApp` wires everything by constructor injection. `DemoScenario` runs the in-class demo story. `Main` just starts it.

| Package | Owner | CWEs |
| --- | --- | --- |
| `auth` (login, passwords, sessions) | Ian | 307, 521, 613, 620, 798, 916 |
| `access` (permissions, care team, roles) | Martin | 266, 283, 306, 639, 842, 1220 |
| `records` (JDBC repository, export, XML import, backup, PDF) | James | 78, 79, 89, 502, 611, 1236 |
| `files` (lab-report upload/download) | Alex | 22, 276, 378, 434, 770, 772 |
| `security` + `audit` (AES-GCM, SHA-256, SecureRandom, logging) | Jimmy | 117, 328, 338, 778, 779, 1204 |

Key cross-package calls:
- `SessionManager.validate(token)` returns the live `Session` or throws `AccessDeniedException`.
- `AccessPolicy.require(session, Permission)`, `requireCanRead(session, patient)`, `requireCanEdit(session, patient)` are called by `records` and `files` before touching data.
- `AuditLogger.record(User actor, String action, String detail)` is called for every security event.
- `TokenGenerator` is the only source of randomness (SecureRandom). `CryptoService.encrypt/decrypt` protects clinical notes.

## Rules the code must follow

1. Implement only the methods marked `TODO(<your name>)`. **Do not change public method signatures** in other people's packages; if you need a change, tell the team.
2. JavaDoc on every public class and method. Keep the CWE explanation in the class JavaDoc.
3. No static mutable state; dependencies come through the constructor.
4. Never log or put in exception messages: passwords, tokens, patient names, dates of birth, notes, SQL, file paths, stack traces.
5. try-with-resources for every stream, connection, statement and result set.
6. For each CWE, turn the matching `@Disabled` test in your `*AttackTest` class into a real JUnit test that **attempts the attack and asserts it fails**, plus one test that the legitimate case works. Remove `@Disabled`.
7. Add your steps to `DemoScenario.define()` so each prints what was attempted and what happened.
8. `mvn test` must pass before pushing. Work on a branch named after you, then open a pull request.

## Prompt to use

> I'm <NAME>, and I own the `<PACKAGE>` package of MedVault (context above). My CWEs are <LIST>. Here are my current files: <paste them>. Implement every `TODO(<NAME>)` method following the rules above, write the real attack tests in `<X>AttackTest`, and give me my `DemoScenario` steps. For each CWE, also explain in 2–3 sentences what the code does to prevent it so I understand it before I present it. Don't change other packages; if I need something from another package, tell me what to ask that teammate for.

## Academic honesty (from the syllabus)

GenAI is allowed for the code (Level 4) as long as **the team is the primary driver and the report acknowledges which tool was used and how.** Keep a note of what you used AI for. The CWE **descriptions and "why it's important" in the report must be in your own words**, so don't paste AI text into the report. Understand your code well enough to explain it live in the demo.
