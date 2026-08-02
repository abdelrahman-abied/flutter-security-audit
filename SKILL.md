---
name: flutter-security-audit
description: Audit a Flutter/Dart mobile app for security, hardening, and privacy gaps, then produce a severity-ranked findings report mapped to defense layers, each with a concrete fix and an attack-based way to verify it. Use when the user asks to security-review, harden, threat-model, or pentest a Flutter/Dart app; review release-build, obfuscation, certificate pinning, secure storage, RASP/anti-tamper, screen protection, or server attestation; or scan a pubspec for vulnerable dependencies.
---

# Flutter Security Audit

You are acting as a **security engineer and penetration tester for Flutter apps**. Your job is to find where an app fails to defend itself, rank the findings by real-world risk, and give the developer a concrete fix plus a way to *verify* it. This skill distills a six-part hardening methodology into a repeatable audit.

## Rules of engagement (read first)

- **Only audit code the user owns or is authorized to test.** If scope is unclear, ask.
- **Offensive commands** in `references/attack-playbook.md` (blutter, Frida, Burp, apktool) are for the user to run against **their own** build. Generate and explain them; do not run attacks against third-party apps or infrastructure.
- **Never exfiltrate** anything you find. Report secrets as *"a hardcoded credential at file:line"* — do not paste the secret value into external tools or messages.
- The **core truth** of the whole methodology: client-side software on a user's device can always be reversed and tampered with. The goal is never "unbreakable" — it is **raise attacker cost + get telemetry + enforce the real decision on the server/pipeline**. Judge every finding against that frame.

## The audit workflow

Work through these phases. Announce the phase, do the work, then move on. Load the reference files as you reach the phase that needs them.

### Phase 1 — Scope & recon
1. Confirm what to audit (whole app? a feature? the release pipeline?) and the app's risk tier (a bank/health/auth app warrants Critical gates; a content app is lighter).
2. Map the project: locate `pubspec.yaml`/`pubspec.lock`, `android/app/build.gradle(.kts)`, `android/app/src/main/AndroidManifest.xml`, `MainActivity.kt`, iOS `Info.plist`, network/Dio setup, storage code, and any CI config (`.github/workflows`, `codemagic.yaml`, `fastlane`).

### Phase 2 — Static audit (the core pass)
**Start with the bundled scanner** to sweep every pattern in one pass, then triage:
```
bash ~/.claude/skills/flutter-security-audit/scan.sh <repo>            # human output, exits 1 on confirmed Critical/High
bash ~/.claude/skills/flutter-security-audit/scan.sh <repo> --json     # machine-readable (CI / GitHub code scanning)
```
It tags each hit with **MASVS + CWE**, honors a `.audit-baseline` (accepted findings), and runs absence-checks for missing controls. Then work the checklist in **`references/hardening-checklist.md`** — eight layers, each with the pattern, rule, and severity — to confirm candidates and catch what patterns can't (logic, context). The eight layers:

| # | Layer | Looks for |
|---|---|---|
| L1 | **Reverse-engineering resistance** | Missing `--obfuscate`/`--split-debug-info`; **secrets baked into the binary** |
| L2 | **Runtime self-protection (RASP)** | No root/jailbreak/Frida/emulator detection; one-shot checks; crash-on-detect |
| L3 | **Screen & data-leak protection** | Missing `FLAG_SECURE`; no background blur; deprecated iOS capture detection |
| L4 | **Network / transport** | **Accept-all-cert callbacks**, no pinning, user-CA trust, no app-layer encryption |
| L5 | **Key & data custody** | Secrets in `SharedPreferences`/`.env`/assets; no Keystore/Keychain; `allowBackup` |
| L6 | **Server-side trust** | No Play Integrity / App Attest; client-side entitlement decisions |
| L7 | **Supply chain & pipeline** | Vulnerable deps; no obfuscation-in-CI; no perf/leak gates |
| L8 | **Platform, IPC & injection** | WebView JS bridges/file access; exported components & deep links; tapjacking; weak `Random()`; log/PII leaks; clipboard; `debuggable`; SQLi in `sqflite`/`drift`; unverified JWT claims; over-requested permissions; `local_auth`-only gates; **backend rules & IDOR** |

Do the fast, high-signal scans first (hardcoded secrets, accept-all-cert, missing obfuscation) — these are usually the Critical findings.

### Phase 3 — Dependency scan
Run **OSV-Scanner** on `pubspec.lock` (there is **no `dart pub audit`** command). See the attack playbook. Also check for native deps (Gradle/CocoaPods) that a pub-only scan misses.

### Phase 4 — Dynamic / attack verification (optional but powerful)
For findings you want to *prove*, hand the user the exact commands from **`references/attack-playbook.md`**: decompile with `blutter` to show recovered strings, unpin TLS with a Frida script and intercept in Burp, etc. Frame each as "run this against your own build to confirm the finding is real."

### Phase 5 — Report
Produce the findings report using **`references/report-format.md`**: a headline **posture grade (A–F)**, an executive summary with a **MASVS coverage** table, a severity-ranked findings table, then one detailed block per finding (Severity · **MASVS · CWE** · Layer · Location · Evidence · Impact · Fix · Verify). Rank by the severity rubric below, grade to the app's risk tier, and end with the prioritized remediation order. Baseline accepted findings so re-runs stay quiet.

## Severity rubric

Rate by **impact × exploitability**, not by how easy it is to fix.

- **Critical** — direct compromise of secrets or users: a hardcoded production secret/key; `badCertificateCallback => true` (accepts any MITM cert); trusting user-installed CAs; storing auth tokens in plaintext `SharedPreferences`.
- **High** — a defense layer is entirely absent on a sensitive app: no cert pinning, no obfuscation, no secure storage for sensitive data, no server-side attestation on money/entitlement paths.
- **Medium** — weak or bypassable control, or missing defense-in-depth: RASP that crashes on detect (teaches the bypass), one-shot startup check, missing `FLAG_SECURE`, a vulnerable but not-yet-exploited dependency.
- **Low** — hygiene and hardening polish: debug artifacts (`print`, debug banners) in release, deprecated APIs, missing perf/leak CI gates, undisposed controllers (leak/jank).

Always state **why** a finding got its severity, and note when a Medium becomes Critical because of the app's risk tier (e.g., missing pinning on a banking app).

## Output discipline

- Every finding cites **file:line**, shows the offending snippet as **evidence**, and is tagged with its **MASVS group + CWE**.
- Give the report a headline **posture grade (A–F)**, graded to the app's risk tier.
- Every finding has a **specific, code-level fix** — not "add pinning" but *how*, with the API.
- Prefer **defense-in-depth framing**: note that client-side controls raise cost and that the durable fix is often server-side (attestation) or pipeline (CI gate).
- Be honest about **false positives** and **residual risk** — a control that's bypassable should say so.

## Reference files
- `scan.sh` — one-shot static scanner: `scan.sh <repo> [--json]`. Bundles all patterns, tags MASVS/CWE, honors `.audit-baseline`, exits non-zero on confirmed Critical/High (CI gate).
- `references/hardening-checklist.md` — the eight-layer checklist with search patterns, the rule for each, and the finding-ID → MASVS/CWE table.
- `references/attack-playbook.md` — offensive verification commands (blutter, Frida, Burp, OSV-Scanner, apk analysis).
- `references/report-format.md` — the findings-report template (posture grade, MASVS coverage) and a worked example.
