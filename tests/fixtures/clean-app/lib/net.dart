import 'dart:io';

/// SPKI pins, not certificate pins: the key survives certificate renewal.
/// A backup pin means a rotation is not an outage.
const primaryPinSha256 = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const backupPinSha256 = 'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

HttpClient pinnedClient(List<int> caBytes) {
  final context = SecurityContext(withTrustedRoots: false);
  context.setTrustedCertificatesBytes(caBytes);
  return HttpClient(context: context);
}
