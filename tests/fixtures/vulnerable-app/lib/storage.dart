import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// SharedPreferences is a plain XML file on Android and a plist on iOS.
Future<void> persist(SharedPreferences prefs, String token, String otp) async {
  await prefs.setString('auth_token', token);        // EXPECT-HIT STO-TOKEN-PREFS
  await Clipboard.setData(ClipboardData(text: otp)); // EXPECT-HIT STO-CLIPBOARD
}

/// Readable while the device is locked.
const keychainOption = KeychainAccessibility.unlocked;  // EXPECT-HIT STO-KEYCHAIN

/// Deprecated iOS capture API.
bool screenIsRecording(dynamic view) => view.isCaptured;  // EXPECT-HIT PLT-ISCAPTURED
