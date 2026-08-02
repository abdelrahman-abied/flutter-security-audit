# Flutter hardening checklist (8 layers)

Each item: **what to check**, a search **pattern** to find the anti-pattern, the **rule**, and the **default severity**. Adjust severity up for high-risk apps (banking, health, auth, wallets).

> **Fastest path:** run `scan.sh <repo>` (in the skill root) — it bundles every pattern below into one pass, tags each hit with MASVS + CWE, honors a `.audit-baseline`, and exits non-zero on confirmed Critical/High (CI gate). `scan.sh <repo> --json` emits machine-readable findings. Then triage the candidates by hand using this file.

> Patterns find *candidates*. Always open the hit and confirm it's real before reporting — note false positives honestly (e.g., the launcher `MainActivity` is *expected* to be `exported="true"`).

**Taxonomy.** Every finding is tagged with an **OWASP MASVS** control group and a **CWE** id:
`MASVS-STORAGE · CRYPTO · AUTH · NETWORK · PLATFORM · CODE · RESILIENCE · PRIVACY`. A full **finding-ID → MASVS/CWE** table is at the end of this file.

---

## L1 — Reverse-engineering resistance (Article 1)

**1.1 Release builds must be obfuscated + symbol-split.**
```bash
rg -n "flutter build (apk|appbundle|ios|ipa)" --glob '!**/build/**' \
  .github codemagic.yaml Makefile fastlane 2>/dev/null
```
Rule: every release build has `--obfuscate --split-debug-info=<dir>`. Missing → **Medium** (High if the app has meaningful client logic). Note: obfuscation is *friction*, not secret-hiding.

**1.2 No secrets baked into the binary (the big one).**
```bash
rg -nP "(?i)(api[_-]?key|secret|passwd|password|token|bearer|client[_-]?secret|private[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}" lib
rg -n "AIza[0-9A-Za-z_\-]{35}" lib            # Google / Firebase
rg -n "AKIA[0-9A-Z]{16}" lib                  # AWS access key id
rg -nP "sk_live_[0-9a-zA-Z]{24,}" lib         # Stripe live
rg -n "ghp_[0-9A-Za-z]{36}" lib               # GitHub token
rg -n "\.env" pubspec.yaml                     # .env bundled as an asset?
```
Rule: **a secret in the binary is not a secret** — `blutter` recovers the object pool (all strings) even with `--obfuscate` (verify in the attack playbook). Proxy third-party keys through your backend; derive/store device keys in Keystore/Keychain. Hardcoded **production** secret → **Critical**.

---

## L2 — Runtime self-protection / RASP (Article 1)

**2.1 Any anti-tamper at all?**
```bash
rg -ni "jailbroken|jailbreak|isRealDevice|frida|rooted|SafeDevice|developmentMode" lib
```
Rule: a sensitive app should detect root/jailbreak, emulator, debugger, and Frida. Zero hits on a sensitive app → **High**.

**2.2 Crash-on-detect anti-pattern.**
```bash
rg -n "exit\(0?\)|SystemNavigator\.pop\(\)" lib
```
Rule: don't instantly crash on a signal — it teaches the attacker exactly which check to patch. **Report before you react; degrade, don't detonate.** Instant-crash response → **Medium**.

**2.3 One-shot and Dart-only checks.**
Rule: detection only in `main()`/`initState` with no re-scan is defeated by attaching after launch — gate the *sensitive action*. Detection reachable purely through a `MethodChannel` is patchable in ~12 lines of Smali; push it into **native C++ via FFI**. Either → **Medium**.

---

## L3 — Screen & data-leak protection (Article 1)

**3.1 Android FLAG_SECURE.**
```bash
rg -n "FLAG_SECURE" android/
```
Rule: sensitive apps set `window.setFlags(FLAG_SECURE, FLAG_SECURE)` in `MainActivity`. Absent on a sensitive app → **Medium**.

**3.2 iOS capture detection uses the deprecated API.**
```bash
rg -n "isCaptured" ios/ lib/
```
Rule: `UIScreen.isCaptured` was **deprecated in iOS 18** → use `UITraitCollection.sceneCaptureState`. iOS has **no screenshot block**, only detect-and-hide + a background overlay. Deprecated API → **Low**; no background overlay on a sensitive app → **Medium**.

---

## L4 — Network / transport (Article 2)

**4.1 Accept-all-certificate callback (critical MITM hole).**
```bash
rg -nP "badCertificateCallback\s*=\s*\(?.*\)?\s*=>\s*true" lib
rg -ni "onBadCertificate|allowInvalidCertificates|allowBadCertificates" lib
```
Rule: never return `true` from `badCertificateCallback` — it accepts any proxy's cert. → **Critical**.

**4.2 Trusting user-installed CAs (Android).**
```bash
rg -n 'certificates src="user"' android/
```
Rule: since Android 7 apps don't trust user CAs by default — do not opt back in. → **Critical**.

**4.3 Cleartext traffic allowed.**
```bash
rg -n 'usesCleartextTraffic="true"' android/
rg -n "NSAllowsArbitraryLoads</key>" ios/
```
Rule: no plaintext HTTP for sensitive traffic. → **High**. Note the anchored `</key>`: a bare `NSAllowsArbitraryLoads` search also matches the narrower `…InWebContent` / `…ForMedia` keys, which are a *different* (and separately reported) finding — see **4.6**.

**4.4 Certificate pinning present and done right.**
```bash
rg -ni "setTrustedCertificatesBytes|SecurityContext\(|http_certificate_pinning|ssl_pinning|certificatePin|sha256/" lib
```
Rule: pin the **public key (SPKI SHA-256)**, not the full certificate (full-cert pinning bricks the app on renewal). Ship a backup pin. No pinning on a sensitive app → **High**; full-cert pinning → **Medium**.

**4.5 Sensitive payloads lack an application-layer envelope.**
Rule (defense-in-depth for high-risk): consider X25519→HKDF→AES-GCM inside a Dio interceptor so a stripped-TLS proxy still sees only ciphertext. Absent on a high-risk app → **Low/Medium**.

**4.6 iOS: granular ATS exceptions (the hole in an "ATS enabled" app).** `MASVS-NETWORK · CWE-319 (NET-ATS-EXCEPTION)`
```bash
rg -n "NSExceptionAllowsInsecureHTTPLoads|NSAllowsArbitraryLoadsInWebContent|NSAllowsArbitraryLoadsForMedia|NSExceptionMinimumTLSVersion|NSExceptionRequiresForwardSecrecy" ios/
```
Rule: teams that would never set the blanket `NSAllowsArbitraryLoads` routinely punch **per-domain** holes that are just as exploitable for that domain. Each key disables a specific protection: `NSExceptionAllowsInsecureHTTPLoads` permits plain HTTP; `NSExceptionMinimumTLSVersion` allows TLS 1.0/1.1; `NSExceptionRequiresForwardSecrecy` drops PFS cipher suites; `NSAllowsArbitraryLoadsInWebContent` exempts WKWebView content (pairs badly with L8.1). → **High** for an insecure-HTTP or downgraded-TLS exception on a sensitive domain; **Medium** otherwise.

**Triage nuance — do not over-rank this against Flutter traffic.** ATS governs `NSURLSession`. Flutter's `dart:io` sockets use **bundled BoringSSL** and are not constrained by ATS, exactly as Android's `network_security_config` doesn't bind them. So an ATS exception is a real finding for **plugins, WebViews and native SDKs**, but it is *not* what protects your Dio/`http` calls — pinning (4.4) is. State which traffic is actually affected instead of implying the app's API calls are downgraded.

---

## L5 — Key & data custody (Articles 1–2)

**5.1 Sensitive data in plaintext SharedPreferences.**
```bash
rg -ni "shared_preferences|SharedPreferences" lib
rg -ni "prefs?\.(setString|write).*(token|password|secret|jwt|refresh)" lib
```
Rule: tokens/keys belong in `flutter_secure_storage` (Android Keystore / iOS Keychain), not `SharedPreferences`. Token in prefs → **Critical**.

**5.2 Secure storage exists for sensitive data.**
```bash
rg -ni "flutter_secure_storage|FlutterSecureStorage" lib
```
Rule: absent on an app that stores auth tokens → **High**.

**5.3 iOS keychain accessibility too broad.**
```bash
rg -n "KeychainAccessibility\.(unlocked|always|passcode)" lib
```
Rule: prefer `first_unlock_this_device` (off iCloud, unavailable while locked). Broad accessibility → **Medium**.

**5.4 Android auto-backup of secure data.**
```bash
rg -n "allowBackup" android/app/src/main/AndroidManifest.xml
```
Rule: `allowBackup="true"` can sweep tokens into a restorable cloud backup. On a sensitive app → **Medium**.

---

## L6 — Server-side trust / attestation (Article 1)

**6.1 No remote attestation.**
```bash
rg -ni "play_?integrity|DCAppAttest|appattest|devicecheck|integrityToken|attestation" lib android ios
```
Rule: the only client control an attacker *can't* patch is a hardware-signed verdict your **server** verifies (Play Integrity / App Attest) with a server-issued nonce. Absent on money/entitlement paths → **High**.

**6.2 Client-side entitlement decisions.**
```bash
rg -ni "isPremium|isPro|hasSubscription|isEntitled|unlockedFeatures" lib
```
Rule: the client should *render* a server decision, not *make* it. A local boolean gating paid features → **High** (trivially flipped with Frida).

---

## L7 — Supply chain & pipeline (Article 6)

**7.1 Vulnerable dependencies** — run OSV-Scanner (see attack playbook). There is **no `dart pub audit`**. Any known-vuln dep → severity per the advisory.

**7.2 No obfuscation gate in CI.**
```bash
rg -n "flutter build" .github codemagic.yaml 2>/dev/null
```
Rule: CI release builds must include `--obfuscate`. Missing → **Medium**.

**7.3 No perf / leak / golden gates.**
```bash
rg -ni "integration_test|leak_tracker|matchesGoldenFile|osv-scanner|dependabot" . 2>/dev/null
```
Rule: a hardened app decays without CI gates — perf budgets, `leak_tracker`, golden tests, OSV scan. Absent → **Low/Medium**.

---

## L8 — Platform interaction, IPC & injection (Articles 7–9)

Common Flutter holes outside the "hardening" core. Each tagged with its true MASVS group.

**8.1 WebView exposes native to web content.** `MASVS-PLATFORM · CWE-749`
```bash
# -i is not optional: webview_flutter 3.x spelled it Javascript*, 4.x spells it
# JavaScript* (addJavaScriptChannel, JavaScriptMode). A case-sensitive pattern
# silently misses every app on the current plugin.
rg -ni "javascriptchannel|addjavascriptinterface|javascriptmode\.unrestricted|setjavascriptenabled\(true\)" lib
```
Rule: a channel added with `addJavaScriptChannel` — or a legacy `addJavascriptInterface` — reachable from untrusted page content is a native bridge for an attacker. Only enable JS when needed, allow-list the origins/URLs you load, never load attacker-controllable URLs into a channel-enabled WebView. → **High** (untrusted content) / **Medium**.

Note the iOS side is the same finding: `webview_flutter` is `WKWebView` there, and `addJavaScriptChannel` becomes a `WKScriptMessageHandler` callable via `window.webkit.messageHandlers.<name>.postMessage(...)`. One Dart line, two native bridges.

> **Do not accept a `NavigationDelegate` as the fix.** On Android `onNavigationRequest` **does not fire for programmatic `loadRequest()` calls** ([flutter#152168](https://github.com/flutter/flutter/issues/152168)) — verified live: a hostile `loadRequest` produces no delegate verdict at all. The delegate gates *in-page* navigation only, and never gates subresources (`<script src>`, `fetch`) on either platform. So if an external input (deep link, push payload, server response) can influence the URL, the allow-list **must run at the call site, before `loadRequest`**. A codebase that validates only inside the delegate is still vulnerable — flag it.

**8.2 WebView file / universal access.** `MASVS-PLATFORM · CWE-200`
```bash
# -i catches the setter form too: Kotlin reads settings.allowFileAccess, the
# Dart/platform-channel side setAllowFileAccess().
rg -ni "allowfileaccess|allowuniversalaccessfromfileurls" lib android
```
Rule: file access from a WebView can read local files / bypass same-origin. Disable unless required. → **Medium**.

Expect this one to fire on the fix as well as the bug: a line that explicitly sets `allowFileAccess = false` matches the same pattern. That is deliberate — below API 30 the default is `true`, so the *absence* of any mention is also a finding, and the check cannot tell the two apart. Confirm the value, then baseline the line.

**8.3 Exported components & deep links.** `MASVS-PLATFORM · CWE-926`
```bash
rg -n 'android:exported="true"' android/
```
Rule: every exported `activity`/`service`/`receiver` is an entry point. The **launcher `MainActivity` must be exported** (expected — not a finding); flag *other* exported components without permission guards, and validate deep-link / `intent` parameters. For App Links, confirm `android:autoVerify="true"` + the `assetlinks.json` so links can't be hijacked. → **Medium** (High if an exported component performs sensitive actions).

**8.4 Insecure randomness.** `MASVS-CRYPTO · CWE-330`
```bash
rg -n "[^a-zA-Z]Random\(" lib   # matches Random(), math.Random(), Random(seed); NOT Random.secure()
```
Rule: `Random()` is predictable — never use it for tokens, nonces, IVs, keys, OTPs, or session ids. Use `Random.secure()` (or the `cryptography` package). → **Medium** (High if it seeds a security token).

**8.5 Sensitive data in logs.** `MASVS-PRIVACY · CWE-532`
```bash
rg -niP "(print|debugPrint|developer\.log|Logger)[^;]*(token|password|secret|jwt|otp|pin|ssn|card)" lib
```
Rule: logs land in logcat / crash reports / analytics. Never log credentials, tokens, or PII; strip in release. → **Medium**.

Triage notes that change how you rank and word this:
- **Correct the usual overstatement.** Another app *cannot* read your logs — `READ_LOGS` has been privileged since Android 4.1. The real exfil routes are **crash/analytics SDK breadcrumbs**, `adb` with USB access, rooted devices, and user-submitted bug reports. Say that, rather than "any app can read logcat."
- **iOS gives no protection here, contrary to expectation.** `os_log`/`Logger` redact dynamic strings as `<private>` by default — but **Flutter's `print`/`debugPrint` bypass `os_log` entirely** (stdout), so the redaction never applies. Do not downgrade an iOS finding on the assumption that the platform masks it.
- `print`/`debugPrint` are **not** stripped from release builds; `dart:developer`'s `log()` **is**. Recommending `log()` plus a `kReleaseMode` guard is a concrete fix.

**8.6 Clipboard & unmasked input.** `MASVS-STORAGE · CWE-200`
```bash
rg -n "Clipboard\.setData" lib          # copying secrets to a shared clipboard
rg -n "TextField\(|TextFormField\(" lib  # then check password fields set obscureText: true
```
Rule: don't auto-copy secrets to the clipboard (other apps read it); password fields need `obscureText: true` and sensible `autofillHints`. → **Low/Medium**.

Platform reality when writing the fix:
- **Android 13+** can hide a clipboard preview via `ClipDescription.EXTRA_IS_SENSITIVE` — but **Flutter's `Clipboard.setData` cannot set it** ([flutter#105677](https://github.com/flutter/flutter/issues/105677), open since 2022, P3). So a copied password *does* render in the keyboard's clipboard preview. The fix is a platform channel, a plugin like `sensitive_clipboard`, or removing the button — not a Flutter API.
- **iOS 16+** prompts *"Allow Paste"* when an app **reads** the pasteboard programmatically (16.1 adds a per-app Ask/Deny/Allow setting), suppressed only for deliberate user paste (long-press, ⌘V, `UIPasteControl`). That constrains attackers more than Android's toast — but it protects *reads*, not what your app *writes*. Don't let it lower the severity of writing a secret to the pasteboard.

**8.7 Biometric / local_auth used as the only gate.** `MASVS-AUTH · CWE-287`
```bash
rg -n "local_auth|authenticate\(" lib
```
Rule: `local_auth` is a *local UX* check — `authenticate()` returns a `Future<bool>` computed on the attacker's device, so it's patchable and it produces **no evidence your server can verify**. Never let it be the sole authorization for sensitive actions; the server must still enforce auth (tie to L6). The real mechanism for money paths is a Keystore/Secure Enclave key created with `setUserAuthenticationRequired(true)` (iOS: `.biometryCurrentSet`) that **signs a server-issued nonce** — requires native code; no Flutter package does it end-to-end. → **High** if it gates money/data with no server check.

Also flag the **outdated API**: `local_auth` 3.0.0 removed `AuthenticationOptions` from `authenticate()` (`stickyAuth` → `persistAcrossBackgrounding`, `useErrorDialogs` dropped) and now throws `LocalAuthException` instead of `PlatformException`. Code using `options: AuthenticationOptions(...)` does not compile against current `local_auth` → **Low** (`COD-DEPRECATED`).

**8.8 The real hole is often the backend (not greppable).** `MASVS-RESILIENCE · CWE-639 (RES-BACKEND)`
Rule: a perfectly hardened client in front of **wide-open Firestore/RTDB/Storage rules** or an API with no server-side authorization is still fully exploitable. Always remind the developer to audit **backend security rules and server authz**, not just the app. Grep any rules files for `if true` and for `request.auth != null` used as if it meant *ownership* — it does not; it means "any signed-up user." Replay a real API call with `curl` and change one object id (IDOR). → context-dependent, often **Critical**.

**8.9 SQL injection in `sqflite` / `drift`.** `MASVS-CODE · CWE-89`
```bash
rg -nP '(rawQuery|rawInsert|rawUpdate|rawDelete|customSelect|customStatement|execute)\(.*\$' lib
```
Rule: never interpolate into SQL. Use `?` placeholders with an args list (`db.rawQuery('… WHERE t LIKE ?', [v])`, `db.query(..., whereArgs: [...])`, drift's `variables:`). Note placeholders bind **values, not identifiers** — a dynamic `ORDER BY $col` needs a column allow-list. → **High**.

**8.10 JWT decoded client-side and trusted.** `MASVS-AUTH · CWE-347`
```bash
rg -nP '(JwtDecoder|jwt_decoder|decodeJwt|parseJwt)' lib
```
Rule: **decoding is not verifying.** Reading `exp` to refresh proactively is fine; reading `role`/`isPremium` to unlock anything is the client-side entitlement bug (see 6.2). Server-side, the verifier must pin the algorithm — never read `alg` from the token header (`alg:none` and RS256→HS256 confusion). → **Medium** (High if a claim gates a paid or privileged feature).

**8.11 Tapjacking / touch filtering.** `MASVS-PLATFORM · CWE-1021`
```bash
rg -n "filterTouchesWhenObscured" android/
```
Rule: set `window.decorView.filterTouchesWhenObscured = true` in `MainActivity` for sensitive confirmation screens (Flutter has no Dart-side API — flutter#40422 is open). Honest severity: Android 12+ **already blocks full occlusion from other UIDs by default**, and the flag does not stop *partial* occlusion or accessibility abuse. → **Low**.

**8.12 Permission over-request.** `MASVS-PRIVACY · CWE-250`
```bash
rg -n "uses-permission" android/app/src/main/AndroidManifest.xml
aapt dump permissions app-release.apk     # the MERGED set — dependencies add their own
```
Rule: every permission must be justifiable in one sentence. Audit the **merged** manifest, since transitive dependencies inject permissions; strip unwanted ones with `tools:node="remove"`. → **Low**.

---

### iOS platform specifics — the twins of the Android checks above

**8.13 Custom URL schemes (the iOS twin of an exported component).** `MASVS-PLATFORM · CWE-939 (IPC-URLSCHEME)`
```bash
rg -n "CFBundleURLSchemes" -A3 ios/
```
Rule: **any app on the device can register the same scheme.** iOS resolves collisions unpredictably, so a `myapp://` link — and anything in its query string — can land in a malicious app. Treat every parameter as untrusted, never put a token in one, and use **Universal Links** for anything that must be ownership-verified. → **Medium** (High if the handler performs a sensitive action).

**8.14 No Universal Links / Associated Domains.** `MASVS-PLATFORM · CWE-939 (PLT-NO-APPLINKS)`
```bash
rg -n "associated-domains|applinks:" ios/
```
Rule: the iOS twin of `autoVerify` + `assetlinks.json`. Universal Links bind an HTTPS domain to your app via `apple-app-site-association` served over HTTPS from `/.well-known/`. Only relevant if the app handles deep links — but if it handles them via custom schemes *only*, that's the finding. → **Low** (absence-check).

**8.15 Debuggable iOS build.** `MASVS-RESILIENCE · CWE-489 (PLT-TASKALLOW)`
```bash
rg -n "get-task-allow" ios/
```
Rule: `get-task-allow` lets another process attach to the app's task port — a debugger, or Frida. → **Medium**. **Honest scope:** distribution signing *strips* this entitlement, so an App Store binary can't carry it; this is a finding on **development, ad-hoc and enterprise** builds, which is exactly what gets handed to testers and partners. Verify a real IPA per [MASTG-TEST-0082](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0082/), not just the repo.

**8.16 iOS permission over-request.** `MASVS-PRIVACY · CWE-250 (PRV-IOS-PERMS)`
```bash
rg -n "NS[A-Za-z]+UsageDescription" ios/Runner/Info.plist
```
Rule: every `NS*UsageDescription` is a permission you will be asked to justify — by the user at the prompt, and by App Review. Delete the ones no longer used; a stale key from a removed feature still triggers scrutiny. → **Low**.

**8.17 Keychain accessibility set in native code.** `MASVS-STORAGE · CWE-522 (STO-IOS-KEYCHAIN)`
```bash
# scan.sh anchors the second term as kSecAttrAccessibleWhenUnlocked[^T] so the
# safe …WhenUnlockedThisDeviceOnly does not report. This grep is the loud
# version: it shows both, and you read the suffix.
rg -n "kSecAttrAccessibleAlways|kSecAttrAccessibleWhenUnlocked" ios/ lib/
```
Rule: the native counterpart to **5.3**, which only sees the Dart `flutter_secure_storage` wrapper. `kSecAttrAccessibleAlways` is deprecated and readable while locked; prefer `…AfterFirstUnlockThisDeviceOnly` or `…WhenUnlockedThisDeviceOnly` — the `ThisDeviceOnly` suffix is what keeps the item out of iCloud Keychain backups. → **Medium**.

---

## Finding-ID → MASVS / CWE reference

| ID | Severity | MASVS | CWE |
|---|---|---|---|
| NET-ACCEPT-ALL | Critical | NETWORK | CWE-295 |
| NET-USER-CA | Critical | NETWORK | CWE-295 |
| NET-INVALID-OK | High | NETWORK | CWE-295 |
| NET-CLEARTEXT | High | NETWORK | CWE-319 |
| NET-ATS-EXCEPTION | High | NETWORK | CWE-319 |
| NET-NO-PINNING | High* | NETWORK | CWE-295 |
| SEC-HARDCODED | Critical | CODE | CWE-798 |
| SEC-CLOUDKEY | Critical | CODE | CWE-798 |
| STO-TOKEN-PREFS | High | STORAGE | CWE-312 |
| STO-NO-SECURE | High* | STORAGE | CWE-312 |
| STO-KEYCHAIN | Medium | STORAGE | CWE-522 |
| STO-ALLOWBACKUP | Medium | STORAGE | CWE-530 |
| STO-CLIPBOARD | Low | STORAGE | CWE-200 |
| STO-IOS-KEYCHAIN | Medium | STORAGE | CWE-522 |
| PLT-NO-FLAGSEC | Medium* | PLATFORM | CWE-200 |
| PLT-ISCAPTURED | Low | PLATFORM | CWE-1104 |
| WEB-JS-CHANNEL | Medium† | PLATFORM | CWE-749 |
| WEB-FILE-ACCESS | Medium | PLATFORM | CWE-200 |
| IPC-EXPORTED | Medium | PLATFORM | CWE-926 |
| IPC-URLSCHEME | Medium | PLATFORM | CWE-939 |
| PLT-NO-APPLINKS | Low* | PLATFORM | CWE-939 |
| PLT-DEBUGGABLE | Medium | RESILIENCE | CWE-489 |
| PLT-TASKALLOW | Medium | RESILIENCE | CWE-489 |
| PLT-TAPJACK | Low* | PLATFORM | CWE-1021 |
| CRY-WEAK-RANDOM | Medium | CRYPTO | CWE-330 |
| PRV-LOG-LEAK | Medium | PRIVACY | CWE-532 |
| PRV-PERMS | Low | PRIVACY | CWE-250 |
| PRV-IOS-PERMS | Low | PRIVACY | CWE-250 |
| COD-SQLI | High | CODE | CWE-89 |
| AUTH-JWT | Medium† | AUTH | CWE-347 |
| AUTH-BIOMETRIC | Medium† | AUTH | CWE-287 |
| RES-BACKEND | Critical‡ | RESILIENCE | CWE-639 |
| RES-NO-ATTEST | High* | RESILIENCE | CWE-353 |
| RES-CLIENT-ENT | Medium† | RESILIENCE | CWE-602 |
| RES-NO-RASP | Medium* | RESILIENCE | CWE-919 |
| COD-DEBUG-PRINT | Low | CODE | CWE-489 |
| COD-DEPRECATED | Low | CODE | CWE-477 |

\* = absence-check (a *missing* control); context-dependent, does not fail the CI gate on its own.
† = heuristic pattern; the scanner emits this **candidate** severity (Medium, won't fail the gate), but the *confirmed* severity is often **High** per the checklist prose — escalate when you verify it's a real sole-gate / client-side-decision.
‡ = **not detectable by any static scan** — `scan.sh` never emits it. It is a manual review item (backend security rules, server-side authz, IDOR). Absence from the scanner output means nothing; you must check it by hand. See 8.8.

---

## Developer guard: performance & memory (Articles 3–5)

Not "security" but the same "self-defense" mindset; report as **Low/Medium** hygiene.

**G.1 Undisposed controllers → leaks.**
```bash
rg -n "AnimationController\(|TextEditingController\(|ScrollController\(|PageController\(|Timer\.periodic\(|\.listen\(" lib
```
Rule: every controller/subscription/timer/listener needs a matching `dispose`/`cancel`/`removeListener`. Flag any `State` with one of these but no `dispose()` override. Enforce with `leak_tracker` in CI.

**G.2 Offscreen-pass / deprecated paint APIs.**
```bash
rg -n "Opacity\(|saveLayer\(|withOpacity\(|antiAliasWithSaveLayer|BackdropFilter\(" lib
```
Rule: `withOpacity` is deprecated → `withValues(alpha:)`; `Opacity`/`saveLayer`/blurs force offscreen passes (raster jank) — Impeller did **not** make these free.

**G.3 Full-resolution image decode.**
```bash
rg -n "Image\.(network|asset|file)\(" lib
```
Rule: in lists/thumbnails, pass `cacheWidth`/`memCacheWidth` — decoded RAM is `w×h×4`, independent of file size. Missing on image-heavy screens → **Medium** (OOM risk).

**G.4 Heavy work on the UI isolate.**
```bash
rg -n "jsonDecode\(|utf8\.decode\(|\.map\(.*fromJson" lib
```
Rule: large parses/CPU work belong on an isolate (`Isolate.run`/`compute`, or a worker pool); big buffers move with `TransferableTypedData`. Heavy sync parse on main → **Low/Medium** (jank).
