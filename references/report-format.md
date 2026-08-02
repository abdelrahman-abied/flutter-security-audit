# Findings report format

Produce the report in this structure. Keep it skimmable at the top (summary + table) and detailed below (one block per finding).

---

## Template

```markdown
# Flutter Security Audit — <app name>

**Scope:** <what was audited>   **Risk tier:** <banking/health/auth | standard | low>
**Date:** <date>   **Method:** static audit (8-layer checklist) + <dependency scan / attack verification>

## Executive summary
**Posture grade: <A–F>** — <2–4 sentences: overall posture, the single most important thing to fix.>

| Severity | Count |   | MASVS group | Status |
|---|---|---|---|---|
| 🔴 Critical | N |   | STORAGE | ✅ / ⚠️ / ❌ |
| 🟠 High | N |   | CRYPTO | … |
| 🟡 Medium | N |   | AUTH | … |
| ⚪ Low | N |   | NETWORK · PLATFORM · CODE · RESILIENCE · PRIVACY | … |

## Findings

| # | Severity | Layer | Finding | Location |
|---|---|---|---|---|
| 1 | 🔴 Critical | L4 Network | Accepts any TLS certificate | lib/api/client.dart:42 |
| 2 | 🔴 Critical | L1 Secrets | Firebase API key hardcoded | lib/config.dart:8 |
| … | | | | |

---

### Finding 1 — Accepts any TLS certificate (🔴 Critical) · `NET-ACCEPT-ALL`
- **Layer / MASVS / CWE:** L4 Network (Article 2) · MASVS-NETWORK · CWE-295
- **Location:** `lib/api/client.dart:42`
- **Evidence:**
  ```dart
  client.badCertificateCallback = (cert, host, port) => true;
  ```
- **Impact:** Any attacker on the network (or the device owner) can MITM all
  traffic with a self-signed cert — full read/write of requests, including auth
  tokens. This defeats HTTPS entirely.
- **Fix:** Remove the callback. Pin the server's public key (SPKI SHA-256) via a
  `SecurityContext(withTrustedRoots: false)..setTrustedCertificatesBytes(...)`
  or a pinning package; ship a backup pin so renewals don't brick the app.
- **Verify:** Playbook §C — with the fix, Frida-assisted interception in Burp
  should fail to decrypt on a non-rooted device.

### Finding 2 — Firebase API key hardcoded (🔴 Critical) · `SEC-CLOUDKEY`
- **Layer / MASVS / CWE:** L1 Reverse-engineering (Article 1) · MASVS-CODE · CWE-798
- **Location:** `lib/config.dart:8`
- **Evidence:** `const firebaseKey = "AIza…";`
- **Impact:** Recoverable from `libapp.so` even with `--obfuscate` (the object
  pool holds all strings). Enables quota abuse / API impersonation.
- **Fix:** Remove from the client. Proxy the call through your backend, or (if it
  must be on-device) restrict the key by app-signing cert + package and move
  authorization server-side.
- **Verify:** Playbook §A — `grep -i "AIza" out_dir/objs.txt` should no longer
  find it after removal.

## Remediation order
1. <Critical items first, cheapest-impactful first within a tier>
2. …
3. Add CI gates (OSV scan, obfuscation, leak_tracker, perf budget) so fixes don't regress.

## Residual risk & honest notes
<What remains bypassable and why the real boundary is server-side attestation /
the CI pipeline. Note any false positives you ruled out.>
```

---

## Rules
- **Severity by impact × exploitability**, per the rubric in SKILL.md. State *why* each got its rating; note when the app's risk tier bumps it.
- Every finding: **file:line**, an **evidence snippet**, a **code-level fix** (name the API), and a **verify** step (playbook section or a test).
- Rank the table by severity, Critical first.
- Close with **residual risk** — never imply the app is now "unbreakable." The honest frame: client controls raise cost + produce signal; the enforced decision lives on the server and in CI.

## Posture grade rubric
Assign a single headline grade for the executive summary:
- **F** — any **Critical** confirmed (accept-all-cert, hardcoded prod secret, plaintext token).
- **D** — no Critical, but ≥1 **High** confirmed on a sensitive app.
- **C** — only Mediums, or Highs that are absence-checks not applicable to this app.
- **B** — Lows/hygiene only; core layers present.
- **A** — clean across all applicable layers **and** the durable controls exist: server attestation + CI gates (OSV, obfuscation, leak/perf, golden).

State the grade with a one-line justification. Grade to the app's **risk tier** — a missing-pinning "High" on a banking app is worse than on a content app.

## MASVS coverage & baseline
- Fill the **MASVS group status** column (✅ covered / ⚠️ partial / ❌ missing) so the reader sees coverage at a glance across the 8 groups.
- **Baseline:** accepted findings (e.g., an intentionally-exported launcher, a demo stub) go in a `.audit-baseline` file (one `file:line` substring per line) so `scan.sh` suppresses them on re-runs and the report doesn't cry wolf. Note in the report which findings were baselined and why.

## CI integration
Run the scanner as a PR gate (Article 6, Gate 1). The exit code is the reliable gate — `1` on any confirmed Critical/High:
```yaml
# .github/workflows/security-scan.yml
- name: Flutter security scan
  run: bash path/to/scan.sh . || { echo "::error::confirmed Critical/High finding"; exit 1; }
- name: Machine-readable findings (artifact)
  if: always()
  run: bash path/to/scan.sh . --json > flutter-audit.json
```
`--json` emits a findings array (id, severity, masvs, cwe, location, evidence). For the GitHub **Security → Code scanning** tab specifically (which ingests SARIF, not plain JSON), convert with a small `jq` mapping into SARIF 2.1.0 and upload via `github/codeql-action/upload-sarif`; otherwise the exit-code gate above already blocks the PR without SARIF.
