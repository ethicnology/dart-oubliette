import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/oubliette.dart';

/// The `recoverable` flag is safety-critical: a caller may answer a
/// non-recoverable error with the irreversible `purge()`. This pins the truth
/// table so a future error type cannot silently get it wrong.
void main() {
  group('OublietteException.recoverable truth table', () {
    final exceptions = <OublietteException, bool>{
      const AuthenticationFailedException(key: 'k'): true,
      const AuthenticationFailedException(key: 'k', cancelled: true): true,
      const KeyInvalidatedException(keyAlias: 'a'): false,
      const KeyNotFoundException(keyAlias: 'a'): false,
      const DecryptionFailedException(key: 'k'): false,
      const PayloadCorruptException('bad'): false,
      const PayloadTamperException(
        key: 'k',
        expectedAad: 'e',
        actualAad: 'a',
        expectedAlias: 'ea',
        actualAlias: 'aa',
      ): false,
    };

    exceptions.forEach((exception, expected) {
      test('${exception.runtimeType} recoverable == $expected', () {
        expect(exception.recoverable, expected);
      });
    });

    test('AuthenticationFailedException is the ONLY recoverable type', () {
      final recoverableCount = exceptions.keys
          .where((e) => e.recoverable)
          .length;
      expect(
        recoverableCount,
        2, // both AuthenticationFailedException variants
        reason: 'only authentication failures are retry-able',
      );
      expect(
        exceptions.keys
            .where((e) => e.recoverable)
            .every((e) => e is AuthenticationFailedException),
        isTrue,
      );
    });

    test('cancelled flag is carried and surfaced in toString', () {
      const cancelled = AuthenticationFailedException(
        key: 'k',
        cancelled: true,
      );
      expect(cancelled.cancelled, isTrue);
      expect(cancelled.toString(), contains('cancelled'));
    });
  });
}
