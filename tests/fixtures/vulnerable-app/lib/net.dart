import 'dart:io';

import 'package:flutter/foundation.dart';

/// Trusts anything with a certificate, which is to say: anything.
HttpClient insecureClient() {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;  // EXPECT-HIT NET-ACCEPT-ALL
  return client;
}

const clientOptions = <String, Object?>{
  'allowInvalidCertificates': true,                  // EXPECT-HIT NET-INVALID-OK
};

/// The `//` in `https://` sits inside a string literal. A comment stripper that
/// cuts at the first `//` would truncate this line and lose the finding.
void trace(String token) {
  debugPrint('https://api.example.com/v1?token=$token');  // EXPECT-HIT PRV-LOG-LEAK
}
