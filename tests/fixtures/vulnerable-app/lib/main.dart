import 'package:flutter/material.dart';

const apiKey = 'hunter2hunter2';                     // EXPECT-HIT SEC-HARDCODED

// A client-side entitlement flag: patchable, therefore not a decision.
bool isPremium = false;                              // EXPECT-HIT RES-CLIENT-ENT

void main() {
  print('booting vulnerable fixture');               // EXPECT-HIT COD-DEBUG-PRINT
  runApp(const FixtureApp());
}

class FixtureApp extends StatelessWidget {
  const FixtureApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Container(color: Colors.red.withOpacity(0.4)),  // EXPECT-HIT COD-DEPRECATED
    );
  }
}
