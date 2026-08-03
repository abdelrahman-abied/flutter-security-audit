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

# security-audit-*.md is the skill's own report: it quotes evidence and names
# missing controls, so it must never fire a check nor satisfy an absence-check.
GBASE="-rHnEI --exclude-dir=build --exclude-dir=.dart_tool --exclude-dir=.git --exclude-dir=Pods --exclude=security-audit-*.md"
TAB="$(printf '\t')"

rank_of() { case "$1" in CRITICAL) echo 0;; HIGH) echo 1;; MEDIUM) echo 2;; LOW) echo 3;; *) echo 4;; esac; }

# ---- comment awareness ----------------------------------------------------
# A pattern that only matches a comment is noise, not a finding: on a real app
# 30% of this scanner's hits were prose *about* the vulnerability. Rather than
# dropping any line that contains a comment (which would lose the very common
# `foo(Random());  // note`), each hit is re-tested against the CODE part of
# the line alone. awk is already required by the exit gate — no new dependency.
#
# strip_comments: stdin = grep output "file:line:content"
#                 stdout = "file<TAB>line<TAB>code-only<TAB>original"
# Lines whose code part is blank (the whole line was a comment) are dropped
# here. Comment syntax is chosen per file type, quotes are honoured so that
# "https://x" and '#tag' survive, and /* */ and <!-- --> blocks are tracked
# across lines by re-reading the source — which grep's matching-lines-only
# output cannot show. Unreadable file => fail open, the hit is kept.
strip_comments() {
  awk '
  BEGIN { SQ = sprintf("%c", 39); DQ = "\"" }
  function style(f) {
    if (f ~ /\.(xml|plist|entitlements|storyboard|xib|html|htm)$/) return "x"
    if (f ~ /\.(yaml|yml|properties|cfg|conf|sh|bash|rb|toml)$/)   return "h"
    if (f ~ /(^|\/)(Podfile|Fastfile|Gemfile|Makefile)$/)          return "h"
    return "c"
  }
  function load(f, maxln,   st, nr, l, inb, ins, esc, i, n, ch, nx, out, lead, fast) {
    DONE[f] = 1
    st = style(f); nr = 0; inb = 0
    while (nr < maxln && (getline l < f) > 0) {
      nr++
      fast = 0
      if (!inb) {
        if (st == "c")      fast = (index(l, "//") == 0 && index(l, "/*") == 0)
        else if (st == "x") fast = (index(l, "<!--") == 0)
        else                fast = (index(l, "#") == 0)
      }
      if (fast) out = l
      else {
        out = ""; ins = ""; esc = 0; n = length(l)
        for (i = 1; i <= n; i++) {
          ch = substr(l, i, 1); nx = substr(l, i + 1, 1)
          if (inb) {                                   # inside /* */ or <!-- -->
            if (st == "c") { if (ch == "*" && nx == "/")                             { inb = 0; i++ } }
            else           { if (ch == "-" && nx == "-" && substr(l, i+2, 1) == ">") { inb = 0; i += 2 } }
            continue
          }
          if (ins != "") {                             # inside a string literal
            out = out ch
            if (esc) esc = 0
            else if (ch == "\\") esc = 1
            else if (ch == ins)  ins = ""
            continue
          }
          if (st == "c") {
            if (ch == "/" && nx == "/") break
            if (ch == "/" && nx == "*") { inb = 1; i++; continue }
            if (ch == DQ || ch == SQ) ins = ch
          } else if (st == "x") {
            if (ch == "<" && substr(l, i, 4) == "<!--") { inb = 1; i += 3; continue }
          } else {
            # YAML: # starts a comment only at line start or after whitespace,
            # so http://host#frag keeps its tail.
            if (ch == "#" && (i == 1 || substr(l, i-1, 1) == " " || substr(l, i-1, 1) == "\t")) break
            if (ch == DQ || ch == SQ) ins = ch
          }
          out = out ch
        }
      }
      lead = l; sub(/^[ \t]+/, "", lead)
      if (lead ~ /^(\/\/|\/\*|\*|#|<!--)/) out = ""    # whole-line comment
      CODE[f, nr] = out
    }
    close(f)
  }
  { RAW[++N] = $0 }
  END {
    for (k = 1; k <= N; k++) {                         # pass 1: last line needed per file
      i = index(RAW[k], ":"); if (!i) continue
      f = substr(RAW[k], 1, i-1); r = substr(RAW[k], i+1)
      j = index(r, ":"); if (!j) continue
      s = substr(r, 1, j-1); if (s !~ /^[0-9]+$/) continue
      if (s + 0 > MAX[f]) MAX[f] = s + 0
    }
    for (k = 1; k <= N; k++) {
      i = index(RAW[k], ":"); if (!i) continue
      f = substr(RAW[k], 1, i-1); r = substr(RAW[k], i+1)
      j = index(r, ":"); if (!j) continue
      s = substr(r, 1, j-1); orig = substr(r, j+1)
      code = orig
      if (s ~ /^[0-9]+$/) {
        if (!(f in DONE)) load(f, MAX[f])
        if ((f SUBSEP (s+0)) in CODE) code = CODE[f, s+0]
      }
      if (code ~ /^[ \t]*$/) continue                  # the line was all comment
      gsub(/\t/, " ", code)
      print f "\t" s "\t" code "\t" orig
    }
  }'
}

# Re-test one line against the check pattern. Same ERE engine family as grep -E.
matches() { # code pattern casefold
  local rc=1
  [ "$3" = "i" ] && shopt -s nocasematch
  [[ $1 =~ $2 ]] && rc=0
  shopt -u nocasematch
  return $rc
}

# The one grep entry point: emits "file:line<TAB>original" for real code hits.
hits() { # casefold pattern paths...
  local ci="$1" pat="$2"; shift 2
  local gf="$GBASE"; [ "$ci" = "i" ] && gf="$gf -i"
  # shellcheck disable=SC2086
  grep $gf "$pat" "$@" 2>/dev/null | strip_comments |
    while IFS="$TAB" read -r f ln code orig; do
      matches "$code" "$pat" "$ci" && printf '%s:%s\t%s\n' "$f" "$ln" "$orig"
    done
}

suppressed() { # $1 = "file:line"
  [ -f "$BASELINE" ] || return 1
  grep -qF "$1" "$BASELINE" 2>/dev/null
}

record() { # sev id masvs cwe location snippet
  local sev="$1" id="$2" masvs="$3" cwe="$4" loc="$5" snip="$6"
  suppressed "$loc" && return 0
  # Bash string ops, not tr|sed|cut: four processes per finding is most of the
  # runtime on a large repo, and this runs once per hit.
  snip="${snip//$TAB/ }"                        # tabs to spaces
  snip="${snip#"${snip%%[![:space:]]*}"}"       # strip leading whitespace
  snip="${snip:0:160}"                          # keep the line one line
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(rank_of "$sev")" "$sev" "$id" "$masvs" "$cwe" "$loc" "$snip" >> "$TSV"
}

# present_check: a MATCH is a finding.  args: sev id masvs cwe case pattern [paths...]
present_check() {
  local sev="$1" id="$2" masvs="$3" cwe="$4" ci="$5" pat="$6"; shift 6
  local paths=("$@"); [ ${#paths[@]} -eq 0 ] && paths=("$ROOT/lib")
  hits "$ci" "$pat" "${paths[@]}" | while IFS="$TAB" read -r loc snip; do
    record "$sev" "$id" "$masvs" "$cwe" "$loc" "$snip"
  done
}

# absent_check: NO match is a finding (a control appears to be missing).
# A control named only in a comment does not count as present, so this uses the
# same comment filter — a commented-out dependency must not silence the check.
# args: sev id masvs cwe note case pattern [paths...]
absent_check() {
  local sev="$1" id="$2" masvs="$3" cwe="$4" note="$5" ci="$6" pat="$7"; shift 7
  local paths=("$@"); [ ${#paths[@]} -eq 0 ] && paths=("$ROOT")
  if [ -z "$(hits "$ci" "$pat" "${paths[@]}" | head -n 1)" ]; then
    record "$sev" "$id" "$masvs" "$cwe" "(project-wide)" "MISSING: $note"
  fi
}

L="$ROOT/lib"; A="$ROOT/android"; I="$ROOT/ios"

# ---- L4 Network ----
present_check CRITICAL NET-ACCEPT-ALL MASVS-NETWORK CWE-295 - 'badCertificateCallback[[:space:]]*=.*=>[[:space:]]*true' "$L"
present_check HIGH     NET-INVALID-OK  MASVS-NETWORK CWE-295 i '(allowInvalidCertificates|allowBadCertificates)' "$L"
present_check CRITICAL NET-USER-CA     MASVS-NETWORK CWE-295 - 'certificates src="user"' "$A"
# Anchor the closing tag: bare "NSAllowsArbitraryLoads" is a substring of the
# narrower InWebContent/ForMedia keys, which NET-ATS-EXCEPTION reports instead.
present_check HIGH     NET-CLEARTEXT   MASVS-NETWORK CWE-319 - '(usesCleartextTraffic="true"|NSAllowsArbitraryLoads</key>)' "$A" "$I"
absent_check  HIGH     NET-NO-PINNING  MASVS-NETWORK CWE-295 'no certificate/public-key pinning found (confirm the app makes HTTPS calls)' i '(setTrustedCertificatesBytes|http_certificate_pinning|ssl_pinning|certificatePin|sha256/)' "$L"
# iOS: granular ATS exceptions. NSAllowsArbitraryLoads is caught by NET-CLEARTEXT;
# these are the per-domain holes punched in an otherwise "ATS enabled" app.
present_check HIGH     NET-ATS-EXCEPTION MASVS-NETWORK CWE-319 - '(NSExceptionAllowsInsecureHTTPLoads|NSAllowsArbitraryLoadsInWebContent|NSAllowsArbitraryLoadsForMedia|NSExceptionMinimumTLSVersion|NSExceptionRequiresForwardSecrecy)' "$I"

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
# Case-insensitive on purpose: webview_flutter 3.x spelled it JavascriptChannel /
# JavascriptMode, 4.x spells it addJavaScriptChannel / JavaScriptMode. A
# case-sensitive pattern silently misses every app on the current plugin.
present_check MEDIUM   WEB-JS-CHANNEL  MASVS-PLATFORM CWE-749 i '(javascriptchannel|addjavascriptinterface|javascriptmode\.unrestricted|setjavascriptenabled\(true\))' "$L"
# Case-insensitive so the setter form is caught too: the Kotlin/Java side reads
# settings.allowFileAccess, the Dart and platform-channel side setAllowFileAccess().
present_check MEDIUM   WEB-FILE-ACCESS MASVS-PLATFORM CWE-200 i '(allowfileaccess|allowuniversalaccessfromfileurls)' "$L" "$A"
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

# ---- iOS platform specifics (twins of the Android checks above) ----
# Custom URL scheme = the iOS twin of an exported component. ANY app can
# register the same scheme; only Universal Links are ownership-verified.
present_check MEDIUM   IPC-URLSCHEME   MASVS-PLATFORM CWE-939 - 'CFBundleURLSchemes' "$I"
# Debuggable iOS build. NOTE: distribution signing strips this, so it is a
# finding on dev/ad-hoc/enterprise builds, not on an App Store binary.
present_check MEDIUM   PLT-TASKALLOW   MASVS-RESILIENCE CWE-489 - 'get-task-allow' "$I"
# Every usage description is a permission prompt; justify each one.
present_check LOW      PRV-IOS-PERMS   MASVS-PRIVACY  CWE-250 - 'NS[A-Za-z]+UsageDescription' "$I"
# Keychain items readable while the device is locked / synced to iCloud.
present_check MEDIUM   STO-IOS-KEYCHAIN MASVS-STORAGE CWE-522 - '(kSecAttrAccessibleAlways|kSecAttrAccessibleWhenUnlocked[^T])' "$I" "$L"
# Universal Links = the iOS twin of App Links autoVerify + assetlinks.json.
absent_check  LOW      PLT-NO-APPLINKS MASVS-PLATFORM CWE-939 'no Associated Domains / applinks entitlement (only relevant if the app handles deep links; custom schemes alone are hijackable)' - '(associated-domains|applinks:)' "$I"

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
