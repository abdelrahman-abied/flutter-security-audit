import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

/// Signals, never gates. The client collects; the server decides, and the
/// server is the only place the decision is enforceable.
Future<Map<String, Object?>> deviceSignals(String integrityToken) async {
  final jailbroken = await FlutterJailbreakDetection.jailbroken;
  return <String, Object?>{
    'integrityToken': integrityToken,
    'jailbroken': jailbroken,
  };
}
