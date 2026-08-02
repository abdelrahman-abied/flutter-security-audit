import 'dart:math';

import 'package:flutter/material.dart';
import 'package:sqflite/sqflite.dart';

/// CSPRNG. Random() would be reproducible from its seed.
final rng = Random.secure();

/// Bound parameters, so `user` can never become SQL.
Future<List<Map<String, Object?>>> notesOf(Database db, String user) {
  return db.query('notes', where: 'owner = ?', whereArgs: [user]);
}

void main() => runApp(const CleanApp());

class CleanApp extends StatelessWidget {
  const CleanApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Container(color: Colors.red.withValues(alpha: 0.4)),
    );
  }
}
