import Flutter
import UIKit

@main
class AppDelegate: FlutterAppDelegate {
    // Unreadable while locked, and never restored onto a different device.
    let accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
}
