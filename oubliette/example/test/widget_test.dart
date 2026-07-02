// Smoke test for the example app: the home screen builds and shows the
// profile list. (The old default-template test asserted a "Running on:" string
// that the current UI does not render.)

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette_example/main.dart';
import 'package:oubliette_example/profile_list_page.dart';

void main() {
  testWidgets('app builds and shows the profile list', (tester) async {
    await tester.pumpWidget(const MyApp());

    expect(find.byType(ProfileListPage), findsOneWidget);
    expect(find.widgetWithText(AppBar, 'Oubliette'), findsOneWidget);
  });
}
