import 'dart:math';

import 'package:local_auth/local_auth.dart';
import 'package:sqflite/sqflite.dart';
import 'package:webview_flutter/webview_flutter.dart';

// A bool is not authorization.
final auth = LocalAuthentication();                  // EXPECT-HIT AUTH-BIOMETRIC

/// webview_flutter 4.x spelling — capital S in JavaScript.
WebViewController browser() {
  return WebViewController()
    ..setJavaScriptMode(JavaScriptMode.unrestricted)  // EXPECT-HIT WEB-JS-CHANNEL
    ..setAllowFileAccess(true);                       // EXPECT-HIT WEB-FILE-ACCESS
}

/// String interpolation straight into raw SQL.
Future<List<Map<String, Object?>>> notesOf(Database db, String user) {
  return db.rawQuery('SELECT * FROM notes WHERE owner = $user');  // EXPECT-HIT COD-SQLI
}

/// Client-side JWT decode. The signature is never checked here.
Map<String, dynamic> claims(String jwt) => JwtDecoder.decode(jwt);  // EXPECT-HIT AUTH-JWT

/// Predictable token source.
int weakToken() => Random().nextInt(999999);          // EXPECT-HIT CRY-WEAK-RANDOM
