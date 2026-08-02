// A museum of everything this app used to do wrong. None of it is live code,
// so none of it may be reported: the hardened fixture must score exactly zero.
// Every line is marked EXPECT-<MISS> and tests/test.sh asserts each one.
//
// client.badCertificateCallback = (c, h, p) => true;                EXPECT-MISS
// const apiKey = 'hunter2hunter2';                                  EXPECT-MISS
// await prefs.setString('auth_token', token);                       EXPECT-MISS
// await Clipboard.setData(ClipboardData(text: otp));                EXPECT-MISS
// final weak = Random().nextInt(999999);                            EXPECT-MISS
// debugPrint('token=$token');                                       EXPECT-MISS
// db.rawQuery('SELECT * FROM notes WHERE owner = $user');           EXPECT-MISS
// JwtDecoder.decode(token);                                         EXPECT-MISS
// final auth = LocalAuthentication();                               EXPECT-MISS
// controller.setJavaScriptMode(JavaScriptMode.unrestricted);        EXPECT-MISS
// controller.setAllowFileAccess(true);                              EXPECT-MISS
// bool isPremium = true;                                            EXPECT-MISS
// Container(color: Colors.red.withOpacity(0.4));                    EXPECT-MISS
// print('debug');                                                   EXPECT-MISS
// const keychain = KeychainAccessibility.unlocked;                  EXPECT-MISS
// bool recording(view) => view.isCaptured;                          EXPECT-MISS
