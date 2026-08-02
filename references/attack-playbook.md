# Attack playbook — verify findings against YOUR OWN build

> **Authorization required.** Only run these against an app you own or are explicitly authorized to test. These commands *prove* a static finding is real; they are not for use against third-party apps. Generate and explain them for the user to run — don't attack live infrastructure.

Environment: a rooted Android device or emulator, `frida` + `frida-tools`, Burp Suite or `mitmproxy`, `apktool`, and Python 3.

---

## A. Prove secrets are recoverable — `blutter` (verifies L1.2)

Flutter compiles Dart to an AOT snapshot in `libapp.so`. The object pool holds every string **even with `--obfuscate`**.

```bash
# Pull and unpack your release APK
unzip -o your_app.apk -d extracted

# Recover class names, method signatures, strings, + Frida hook templates
python3 blutter.py extracted/lib/arm64-v8a out_dir

# The reveal: every string constant, in plaintext
grep -iE "http|api|key|secret|token|password" out_dir/objs.txt
```
Quick first look without blutter:
```bash
strings extracted/lib/arm64-v8a/libapp.so | grep -iE "https?://|AIza|secret|token"
```
If your "hidden" endpoint/key appears → the L1.2 finding is confirmed.

---

## B. Inspect the manifest & config — `apktool` (verifies L3, L4.2/4.3, L5.4)

```bash
apktool d your_app.apk -o apk_src
# Then check:
grep -n "usesCleartextTraffic\|allowBackup\|android:debuggable\|android:exported" \
  apk_src/AndroidManifest.xml
cat apk_src/res/xml/network_security_config.xml 2>/dev/null   # user-CA trust?
grep -rn "FLAG_SECURE" apk_src/ || echo "FLAG_SECURE not set"
```

---

## C. Defeat pinning & intercept traffic — Frida + Burp (verifies L4.1/4.4)

Flutter uses **its own BoringSSL inside `libflutter.so`** and ignores the system proxy and trust store — so standard Android unpinning misses. Use a Flutter-specific Frida script (e.g. NVISO's `disable-flutter-tls-verification`) plus proxy redirection.

```bash
# 1. Route traffic to your proxy (Flutter ignores the system HTTP proxy):
#    use a transparent proxy (mitmproxy --mode transparent) or iptables redirect
#    to 127.0.0.1:8080 where Burp/mitmproxy listens.

# 2. Disable Flutter TLS verification at runtime:
frida -U -f com.your.package -l flutter_disable_tls.js --no-pause
```
If cleartext of your requests now appears in Burp → pinning is absent/bypassable (expected for a rooted attacker; confirms pinning is *cost*, not a wall — the real gate is server attestation, L6).

---

## C2. Prove the SQL injection actually lands (verifies L8.9)

A `rawQuery` with an interpolated variable is a *candidate*. Confirm it by typing a payload into the field that reaches it — but use one that works, because the two obvious payloads usually **fail here and produce a false "we're safe" conclusion**:

```text
Query under test:
  SELECT * FROM notes WHERE owner = '$owner' AND title LIKE '%$search%'

❌  ' OR '1'='1        AND binds tighter than OR, so this degrades to
                      (owner='amy' AND title LIKE '%') OR ('1'='1%')
                      — the right side is a string comparison that is FALSE.
                      You get the normal rows back and wrongly assume it's safe.

❌  '; DROP TABLE notes; --
                      rawQuery executes a SINGLE statement; the second is
                      never run. Nothing happens — again, a false all-clear.

✅  %' OR 1=1 --       Closes the LIKE pattern, adds an always-true disjunct,
                      comments out the tail:
                        … LIKE '%%' OR 1=1 --%'
                      → collapses to WHERE (…) OR 1=1 = the entire table.
```

**Report on what an attacker can *read*, not what they can destroy.** The destructive payload fizzling is an accident of the API, not a defence — and it is precisely why this bug survives review. Confirm the fix by re-running the same payload against the parameterized version (`'… LIKE ?', ['%$search%']`), which must return **zero** rows because the payload is bound as a literal value.

Note that placeholders bind **values, not identifiers** — a dynamic `ORDER BY $column` cannot be parameterized and needs a column allow-list.

---

## D. Scan dependencies — OSV-Scanner (verifies L7.1)

There is **no `dart pub audit`**. Use Google's OSV-Scanner over the lockfile (whole transitive tree):

```bash
# Install: https://google.github.io/osv-scanner/
osv-scanner --lockfile=pubspec.lock
# CI: uses: google/osv-scanner-action@v2  (fails the job on a known vuln)

dart pub outdated    # staleness only — NOT vulnerabilities
```

---

## E. Confirm the obfuscation ↔ crash trade-off — `flutter symbolize` (supports L1.1 / L7)

Obfuscated release crashes are unreadable without the split-debug symbols:

```bash
flutter symbolize -i obfuscated_crash.txt \
  -d build/symbols/<build-sha>/app.android-arm64.symbols
```
The symbol file **must** match the exact build. Confirms the "keep symbols as private CI artifacts" recommendation.

---

## F. Attestation is the real boundary (context for L6)

No client bypass matters if the **server** rejects the request. Play Integrity / App Attest flow: server issues a **nonce** → app requests a hardware-signed verdict binding that nonce → server verifies the signature + `requestHash` + `appRecognitionVerdict == PLAY_RECOGNIZED` + `deviceRecognitionVerdict`. A patched client can lie about its own root check; it **cannot** forge Google/Apple's signature. When testing, confirm the server actually *verifies* the token server-side (not just receives it).
