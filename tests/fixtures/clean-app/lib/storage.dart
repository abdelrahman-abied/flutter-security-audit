import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Not readable while the device is locked, and never restored to a new device.
const _options = IOSOptions(
  accessibility: KeychainAccessibility.first_unlock_this_device,
);

final _secure = const FlutterSecureStorage(iOptions: _options);

Future<void> persist(String token) =>
    _secure.write(key: 'auth_token', value: token);

Future<String?> restore() => _secure.read(key: 'auth_token');
