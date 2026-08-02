#!/usr/bin/env bash
# flutter-security-audit — static scanner
# Bundles the hardening-checklist patterns into one pass. Portable (uses grep).
#
# Usage:
#   scan.sh [REPO_PATH] [--json]
#   REPO_PATH defaults to "."   --json emits machine-readable findings.
#
# Baseline: lines in <repo>/.audit-baseline (substring of "file:line") are suppressed.
# Exit code: 1 if any CRITICAL/HIGH finding survives the baseline, else 0 (CI gate).
set -uo pipefail

ROOT="."
FORMAT="human"
for a in "$@"; do
  case "$a" in
    --json) FORMAT="json" ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) ROOT="$a" ;;
  esac
done
[ -d "$ROOT" ] || { echo "not a directory: $ROOT" >&2; exit 2; }

BASELINE="$ROOT/.audit-baseline"
TSV="$(mktemp)"
trap 'rm -f "$TSV"' EXIT

GBASE="-rHnEI --exclude-dir=build --exclude-dir=.dart_tool --exclude-dir=.git --exclude-dir=Pods"

rank_of() { case "$1" in CRITICAL) echo 0;; HIGH) echo 1;; MEDIUM) echo 2;; LOW) echo 3;; *) echo 4;; esac; }

suppressed() { # $1 = "file:line"
  [ -f "$BASELINE" ] || return 1
  grep -qF "$1" "$BASELINE" 2>/dev/null
}

record() { # sev id masvs cwe location snippet
  local sev="$1" id="$2" masvs="$3" cwe="$4" loc="$5" snip="$6"
  suppressed "$loc" && return 0
  snip="$(printf '%s' "$snip" | tr '\t' ' ' | sed 's/^[[:space:]]*//' | cut -c1-160)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(rank_of "$sev")" "$sev" "$id" "$masvs" "$cwe" "$loc" "$snip" >> "$TSV"
}

# present_check: a MATCH is a finding.  args: sev id masvs cwe case pattern [paths...]
present_check() {
  local sev="$1" id="$2" masvs="$3" cwe="$4" ci="$5" pat="$6"; shift 6
  local paths=("$@"); [ ${#paths[@]} -eq 0 ] && paths=("$ROOT/lib")
  local gf="$GBASE"; [ "$ci" = "i" ] && gf="$gf -i"
  # shellcheck disable=SC2086
  grep $gf "$pat" "${paths[@]}" 2>/dev/null | while IFS= read -r line; do
    local loc="${line%%:*}"; local rest="${line#*:}"; local ln="${rest%%:*}"
    record "$sev" "$id" "$masvs" "$cwe" "$loc:$ln" "${line#*:*:}"
  done
}

# absent_check: NO match is a finding (a control appears to be missing).
# args: sev id masvs cwe note case pattern [paths...]
absent_check() {
  local sev="$1" id="$2" masvs="$3" cwe="$4" note="$5" ci="$6" pat="$7"; shift 7
  local paths=("$@"); [ ${#paths[@]} -eq 0 ] && paths=("$ROOT")
  local gf="$GBASE"; [ "$ci" = "i" ] && gf="$gf -i"
  # shellcheck disable=SC2086
  if ! grep $gf -q "$pat" "${paths[@]}" 2>/dev/null; then
    record "$sev" "$id" "$masvs" "$cwe" "(project-wide)" "MISSING: $note"
  fi
}

L="$ROOT/lib"; A="$ROOT/android"; I="$ROOT/ios"

# ---- L4 Network ----
present_check CRITICAL NET-ACCEPT-ALL MASVS-NETWORK CWE-295 - 'badCertificateCallback[[:space:]]*=.*=>[[:space:]]*true' "$L"
present_check HIGH     NET-INVALID-OK  MASVS-NETWORK CWE-295 i '(allowInvalidCertificates|allowBadCertificates)' "$L"
present_check CRITICAL NET-USER-CA     MASVS-NETWORK CWE-295 - 'certificates src="user"' "$A"
present_check HIGH     NET-CLEARTEXT   MASVS-NETWORK CWE-319 - '(usesCleartextTraffic="true"|NSAllowsArbitraryLoads)' "$A" "$I"
absent_check  HIGH     NET-NO-PINNING  MASVS-NETWORK CWE-295 'no certificate/public-key pinning found (confirm the app makes HTTPS calls)' i '(setTrustedCertificatesBytes|http_certificate_pinning|ssl_pinning|certificatePin|sha256/)' "$L"

# ---- L1 Secrets / reverse engineering ----
present_check CRITICAL SEC-HARDCODED MASVS-CODE    CWE-798 i '(api[_-]?key|secret|password|passwd|bearer|client[_-]?secret|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{6,}' "$L"
present_check CRITICAL SEC-CLOUDKEY  MASVS-CODE    CWE-798 - '(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9A-Za-z]{36})' "$L"

# ---- L5 Storage / key custody ----
# setString = SharedPreferences (insecure). Deliberately NOT matching write() —
# flutter_secure_storage (the correct API) uses write(), so it would false-positive.
present_check HIGH     STO-TOKEN-PREFS MASVS-STORAGE CWE-312 i 'setString\([^;]*(token|password|secret|jwt|refresh)' "$L"
present_check MEDIUM   STO-KEYCHAIN    MASVS-STORAGE CWE-522 - 'KeychainAccessibility\.(unlocked|always)' "$L"
present_check MEDIUM   STO-ALLOWBACKUP MASVS-STORAGE CWE-530 - 'allowBackup="true"' "$A"
absent_check  HIGH     STO-NO-SECURE   MASVS-STORAGE CWE-312 'flutter_secure_storage not used (confirm the app stores tokens/keys)' i 'flutter_secure_storage' "$L" "$ROOT/pubspec.yaml"

# ---- L3 Screen / platform ----
absent_check  MEDIUM   PLT-NO-FLAGSEC  MASVS-PLATFORM CWE-200 'FLAG_SECURE not set (screenshots/recording not blocked)' - 'FLAG_SECURE' "$A"
present_check LOW      PLT-ISCAPTURED  MASVS-PLATFORM CWE-1104 - 'isCaptured' "$I" "$L"

# ---- NEW: Platform interaction, IPC & injection ----
present_check MEDIUM   WEB-JS-CHANNEL  MASVS-PLATFORM CWE-749 - '(JavascriptChannel|addJavascriptInterface|JavascriptMode\.unrestricted|setJavaScriptEnabled\(true\))' "$L"
present_check MEDIUM   WEB-FILE-ACCESS MASVS-PLATFORM CWE-200 - '(allowFileAccess|allowUniversalAccessFromFileURLs)' "$L" "$A"
present_check MEDIUM   IPC-EXPORTED    MASVS-PLATFORM CWE-926 - 'android:exported="true"' "$A"
present_check MEDIUM   PLT-DEBUGGABLE  MASVS-RESILIENCE CWE-489 - 'android:debuggable="true"' "$A"
present_check MEDIUM   CRY-WEAK-RANDOM MASVS-CRYPTO   CWE-330 - '[^a-zA-Z]Random\(' "$L"
present_check MEDIUM   PRV-LOG-LEAK    MASVS-PRIVACY  CWE-532 i '(print|debugPrint|developer\.log|Logger)[^;]*(token|password|secret|jwt|otp|pin|ssn|cardnumber)' "$L"
present_check LOW      STO-CLIPBOARD   MASVS-STORAGE  CWE-200 - 'Clipboard\.setData' "$L"
present_check MEDIUM   AUTH-BIOMETRIC  MASVS-AUTH     CWE-287 - 'local_auth|LocalAuthentication' "$L"
# Interpolated Dart string ($var or ${...}) inside a raw SQL call = injection.
present_check HIGH     COD-SQLI        MASVS-CODE     CWE-89  - '(rawQuery|rawInsert|rawUpdate|rawDelete|customSelect|customStatement|execute)\(.*\$' "$L"
# Decoding a JWT client-side; confirm no authorization decision is made from it.
present_check MEDIUM   AUTH-JWT        MASVS-AUTH     CWE-347 i '(JwtDecoder|jwt_decoder|decodeJwt|parseJwt|\.split\(.\..\)\[1\])' "$L"
# Dangerous permissions: justify each one, and check the MERGED manifest too.
present_check LOW      PRV-PERMS       MASVS-PRIVACY  CWE-250 - 'uses-permission[^>]*(READ_CONTACTS|READ_SMS|RECEIVE_SMS|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|RECORD_AUDIO|READ_CALL_LOG|QUERY_ALL_PACKAGES|READ_EXTERNAL_STORAGE)' "$A"
absent_check  LOW      PLT-TAPJACK     MASVS-PLATFORM CWE-1021 'filterTouchesWhenObscured not set (tapjacking; mostly mitigated by default on Android 12+)' - 'filterTouchesWhenObscured' "$A"

# ---- L6 Server-side trust ----
absent_check  HIGH     RES-NO-ATTEST   MASVS-RESILIENCE CWE-353 'no server attestation (Play Integrity / App Attest) found — required on money/entitlement paths' i '(play_?integrity|appattest|DCAppAttest|devicecheck|integrityToken)' "$L" "$A" "$I"
present_check MEDIUM   RES-CLIENT-ENT  MASVS-RESILIENCE CWE-602 i '(isPremium|isPro|hasSubscription|isEntitled|unlockedFeatures)' "$L"

# ---- L2 RASP ----
absent_check  MEDIUM   RES-NO-RASP     MASVS-RESILIENCE CWE-919 'no root/jailbreak/Frida/emulator detection found' i '(jailbroken|jailbreak|isRealDevice|frida|rooted|SafeDevice)' "$L"

# ---- L7 / hygiene ----
present_check LOW      COD-DEBUG-PRINT MASVS-CODE CWE-489 - '[^a-zA-Z.]print\(' "$L"
present_check LOW      COD-DEPRECATED  MASVS-CODE CWE-477 - 'withOpacity\(' "$L"

# ---- Output ----
if [ "$FORMAT" = "json" ] && command -v python3 >/dev/null 2>&1; then
  python3 - "$TSV" <<'PY'
import sys, json
rows=[]
for line in open(sys.argv[1]):
    p=line.rstrip("\n").split("\t")
    if len(p)<7: continue
    rows.append({"severity":p[1],"id":p[2],"masvs":p[3],"cwe":p[4],"location":p[5],"evidence":p[6]})
print(json.dumps({"tool":"flutter-security-audit","findings":rows,"count":len(rows)}, indent=2))
PY
else
  n=$(wc -l < "$TSV" | tr -d ' ')
  echo "flutter-security-audit — $n candidate finding(s) in $ROOT"
  echo "(candidates — confirm each before reporting; absence-checks may be N/A)"
  echo "------------------------------------------------------------------"
  if [ "$n" -gt 0 ]; then
    sort -t "$(printf '\t')" -k1,1n "$TSV" | while IFS="$(printf '\t')" read -r rank sev id masvs cwe loc snip; do
      printf '[%s] %-16s %s · %s\n    %s\n    %s\n' "$sev" "$id" "$masvs" "$cwe" "$loc" "$snip"
    done
  fi
fi

# CI gate: fail only on CONFIRMED (non-absence) CRITICAL/HIGH findings.
# Absence-checks (evidence starts "MISSING:") are context-dependent warnings.
if awk -F"$(printf '\t')" '$1<=1 && $7 !~ /^MISSING:/ {found=1} END{exit !found}' "$TSV"; then
  exit 1
fi
exit 0
