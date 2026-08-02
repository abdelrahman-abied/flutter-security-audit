package com.example.vulnerable_fixture

import io.flutter.embedding.android.FlutterActivity

class MainActivity : FlutterActivity() {
    // Both hardening lines are commented out on purpose. A control that exists
    // only in a comment is not a control, so PLT-NO-FLAGSEC and PLT-TAPJACK
    // must both still fire against this fixture.
    // window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)              EXPECT-MISS
    // window.decorView.filterTouchesWhenObscured = true                    EXPECT-MISS
}
