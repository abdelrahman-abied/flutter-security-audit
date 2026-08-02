# flutter-security-audit

A [Claude Code](https://claude.com/claude-code) skill that audits a Flutter/Dart
mobile app for security, hardening and privacy gaps, then produces a
severity-ranked report where **every finding carries a concrete fix and an
attack-based way to verify it**.

Ships with `scan.sh` — a dependency-free static scanner that bundles all the
checklist patterns into one pass, tags each hit with **OWASP MASVS + CWE**, and
exits non-zero on confirmed Critical/High so it works as a CI gate.

---

## Install

Clone into your Claude Code skills directory:

```bash
# Global (available in every project)
git clone https://github.com/abdelrahman-abied/flutter-security-audit \
  ~/.claude/skills/flutter-security-audit

# …or per-project
git clone https://github.com/abdelrahman-abied/flutter-security-audit \
  .claude/skills/flutter-security-audit
```

Then just ask Claude to audit an app — the skill activates on requests like
*"security-review this Flutter app"*, *"check my pinning setup"*, or
*"threat-model this before release"*.

## Use the scanner on its own

`scan.sh` is plain bash, grep and awk. No Dart, no Node, no install.

```bash
./scan.sh /path/to/flutter/app          # human-readable, severity-ranked
./scan.sh /path/to/flutter/app --json   # machine-readable findings
```

Exit code is `1` if any Critical/High survives the baseline, else `0`.

**It does not report comments.** A pattern that matches only a comment is prose
*about* a vulnerability, not a vulnerability — and on a real app that was 30% of
the output. Each hit is re-tested against the code part of its line, so

```dart
final token = Random();          // ← reported: weak PRNG
// never mint a token with Random()   ← not reported: it is a note
```

behave differently. Trailing comments, `/* … */` and `<!-- … -->` blocks spanning
several lines, and `//` inside a string (`'https://…'`) are all handled. The
same rule applies to the absence-checks: a dependency or a `FLAG_SECURE` call
that exists only in a commented-out line does not count as a control.

String literals *are* code, deliberately: the scanner cannot tell a hardcoded
secret from a sentence about one, so it reports both and you confirm.

**Baseline.** Accepted findings (an intentionally-exported launcher, a demo
stub) go in `<repo>/.audit-baseline`, one `file:line` substring per line, so
re-runs stay quiet and the report doesn't cry wolf.

## CI gate

```yaml
- name: Flutter security scan
  run: bash path/to/scan.sh . || { echo "::error::confirmed Critical/High finding"; exit 1; }

- name: Machine-readable findings
  if: always()
  run: bash path/to/scan.sh . --json > flutter-audit.json
```

For the GitHub **Security → Code scanning** tab, convert the JSON to SARIF 2.1.0
and upload with `github/codeql-action/upload-sarif`. The exit-code gate above
already blocks the PR without SARIF.

---

## What it checks — 8 layers

| Layer | Focus | Representative findings |
|---|---|---|
| **L1** | Reverse-engineering resistance | Missing `--obfuscate`/`--split-debug-info`; **secrets baked into the binary** |
| **L2** | Runtime self-protection (RASP) | No root/jailbreak/Frida/emulator detection; one-shot checks; crash-on-detect |
| **L3** | Screen & data-leak protection | Missing `FLAG_SECURE`; no background overlay; deprecated iOS capture API |
| **L4** | Network / transport | **Accept-all-cert callbacks**, no pinning, user-CA trust, cleartext, **iOS ATS exception domains** |
| **L5** | Key & data custody | Tokens in `SharedPreferences`; no Keystore/Keychain; `allowBackup` |
| **L6** | Server-side trust | No Play Integrity / App Attest; client-side entitlement decisions |
| **L7** | Supply chain & pipeline | Vulnerable deps; no obfuscation in CI; no perf/leak gates |
| **L8** | Platform, IPC & injection | WebView JS bridges & file access; exported components & deep links; tapjacking; weak `Random()`; log/PII leaks; clipboard; `debuggable`; SQLi; unverified JWT claims; permissions; **iOS URL schemes, Universal Links, `get-task-allow`, keychain accessibility**; **backend rules & IDOR** |

Every finding is tagged with a MASVS group (`STORAGE · CRYPTO · AUTH · NETWORK ·
PLATFORM · CODE · RESILIENCE · PRIVACY`) and a CWE id. The full
finding-ID → MASVS/CWE table is in
[`references/hardening-checklist.md`](references/hardening-checklist.md).

## Android ↔ iOS parity

Most checks are Dart-level and apply to both platforms. Where a concern is
platform-specific, both sides are covered:

| Concern | Android | iOS |
|---|---|---|
| Cleartext / transport downgrade | `usesCleartextTraffic` | `NSAllowsArbitraryLoads` **+ per-domain `NSExceptionDomains`** |
| Deep-link entry points | `android:exported`, App Links `autoVerify` | `CFBundleURLSchemes`, Associated Domains / Universal Links |
| Debuggable build | `android:debuggable` | `get-task-allow` entitlement |
| Permission over-request | `uses-permission` | `NS*UsageDescription` |
| Key storage exposure | `allowBackup` | `kSecAttrAccessible*` (native **and** Dart wrapper) |
| Screen capture | `FLAG_SECURE` | *(no iOS equivalent — detect-and-hide only)* |
| Tapjacking | `filterTouchesWhenObscured` | *(not applicable)* |

## What's in the box

| File | Purpose |
|---|---|
| `SKILL.md` | Entry point — layers, severity rubric, workflow |
| `scan.sh` | The scanner (36 checks, baseline, JSON, CI exit code) |
| `references/hardening-checklist.md` | Per-check pattern, rule, severity + the ID→MASVS/CWE table |
| `references/attack-playbook.md` | Verification steps with blutter / Frida / Burp / OSV-Scanner |
| `references/report-format.md` | Report template, posture-grade rubric, CI wiring |
| `tests/` | Fixture-based regression suite — see [`tests/README.md`](tests/README.md) |

## Tests

```bash
bash tests/test.sh
```

Two fixture apps, asserted in both directions: `vulnerable-app` must trip every
one of the 36 checks, `clean-app` must trip none. A check that never fires and a
check that always fires are both broken, and only the pair catches both. The
comment rules are asserted line by line from `EXPECT-HIT` / `EXPECT-MISS`
markers that live in the fixtures, alongside the exit-code gate, `--json`
validity and `.audit-baseline` suppression. CI runs it on Ubuntu and macOS,
because GNU and BSD grep, and mawk and the one-true-awk, are where this kind of
tool actually breaks.

---

## Honest limitations

This is a **static** scanner, and it is deliberately loud rather than clever:

- **Patterns find candidates, not findings.** Always open the hit and confirm.
  The checklist calls out expected false positives — the launcher `MainActivity`
  is *supposed* to be `exported="true"`.
- **Absence-checks are context-dependent.** "No certificate pinning" is only a
  finding if the app makes sensitive network calls. They don't fail the CI gate
  on their own.
- **Some checks are inherently one-platform.** `FLAG_SECURE`, `allowBackup` and
  `android:exported` have no iOS equivalent, and `get-task-allow` has no Android
  one. Where a real twin exists, both sides are covered — see the parity table above.
- **`get-task-allow` is scoped to non-App-Store builds.** Distribution signing
  strips the entitlement, so that check is meaningful for development, ad-hoc
  and enterprise builds — precisely the ones handed to testers and partners.
  Verify a real IPA, not just the repo.
- **It cannot see your backend**, which is frequently where the real hole is.
  A perfectly hardened client in front of `allow read, write: if true` is still
  fully exploitable. The skill prompts for this; it can't test it.

The framing throughout: **client-side controls raise cost and produce signal;
the enforced decision lives on your server and in CI.** No report from this tool
should ever imply an app is "unbreakable."

## Credits

Distilled from the *Flutter Under the Hood: Hardening & High-Speed Architecture*
article series.

## License

MIT — see [LICENSE](LICENSE).
