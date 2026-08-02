// Comment-handling regression cases.
//
// Every line below carries one of two markers (written here with angle
// brackets so this header is not itself collected as a marker):
//   EXPECT-<HIT>    this line MUST produce at least one finding
//   EXPECT-<MISS>   this line MUST NOT produce any finding
//
// tests/test.sh derives its expectations from the markers, so this file stays
// self-describing when it is edited. The markers themselves live in comments,
// which the scanner strips before matching, so they cannot skew the result.

import 'dart:math';

import 'package:flutter/foundation.dart';

// ---------------------------------------------------------------------------
// 1. A pattern named only in a comment is prose about the bug, not the bug.
// ---------------------------------------------------------------------------

// final weak = Random();                                            EXPECT-MISS
/// Never mint a token with Random(); use Random.secure().           EXPECT-MISS
//  await Clipboard.setData(ClipboardData(text: otp));               EXPECT-MISS

/*
 * The previous build called db.rawQuery('SELECT * WHERE id = $id')  EXPECT-MISS
 * and shipped a const apiKey = 'hunter2hunter2' constant.           EXPECT-MISS
 */

/* Inner lines carry no comment leader of their own, so the scanner can only
   know they are comments by tracking the block across lines:
   client.badCertificateCallback = (c, h, p) => true;                EXPECT-MISS
   'allowInvalidCertificates': true,                                 EXPECT-MISS
*/

// ---------------------------------------------------------------------------
// 2. Code with a trailing comment is still code.
// ---------------------------------------------------------------------------

final seeded = Random(42);                    // EXPECT-HIT a trailing comment must not hide the call

// ---------------------------------------------------------------------------
// 3. An inline block hides only what is inside it; scanning resumes after `*/`.
// ---------------------------------------------------------------------------

final hidden = 1 /* Random() */ + 2;          // EXPECT-MISS the only match is inside the block
final resumed = 1 /* was Random() */ + Random().nextInt(8);  // EXPECT-HIT match after the block

// ---------------------------------------------------------------------------
// 4. A match that sits only in a trailing comment is still only a comment.
// ---------------------------------------------------------------------------

bool sessionFlag = false;
bool get authed => sessionFlag;               // LocalAuthentication() said true — EXPECT-MISS

// ---------------------------------------------------------------------------
// 5. `//` inside a string is not a comment.
// ---------------------------------------------------------------------------

void audit(String token) {
  debugPrint('https://api.example.com/v1?token=$token');  // EXPECT-HIT `//` was inside the string
}

// ---------------------------------------------------------------------------
// 6. A string literal is code. The scanner is deliberately loud here: it cannot
//    tell a hardcoded secret from a sentence about one, so it reports both.
// ---------------------------------------------------------------------------

const banner = 'Do not call Random() for tokens';  // EXPECT-HIT string literals are code
