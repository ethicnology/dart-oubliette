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
      const AuthenticationFailedException(key: 'k', lockout: true): true,
      // Linux software tier: data intact, never purge — recoverable.
      const BackendUnavailableException(): true,
      const KeyringLockedException(key: 'k'): true,
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

    test('the recoverable types are exactly the never-purge set', () {
      // Recoverable == "retry; NEVER purge in response". The data behind a
      // recoverable error is intact: an authentication gate, a locked keyring,
      // or a missing Secret Service backend. A non-recoverable error means the
      // secret is unreadable and purge()+init() is the only way forward.
      final recoverable = exceptions.keys.where((e) => e.recoverable).toSet();
      expect(
        recoverable.map((e) => e.runtimeType).toSet(),
        {
          AuthenticationFailedException,
          BackendUnavailableException,
          KeyringLockedException,
        },
        reason: 'only intact-data failures are retry-able (never purge)',
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

    test('lockout flag is carried, recoverable, and surfaced in toString', () {
      const lockout = AuthenticationFailedException(
        key: 'k',
        lockout: true,
        cause: 'RAW NATIVE LOCKOUT TEXT',
      );
      expect(lockout.lockout, isTrue);
      expect(lockout.recoverable, isTrue);
      expect(lockout.toString(), contains('locked out'));
      // The native cause stays out of toString (the key is surfaced by design
      // for this exception type — see the cancelled test above).
      expect(lockout.toString(), isNot(contains('RAW NATIVE LOCKOUT TEXT')));
    });

    test('toString does not leak the native cause or key alias (LEAK-1)', () {
      // toString() must stay free of the underlying cause (OEM/native text) and
      // the profile key alias, so logging it / a crash reporter cannot
      // exfiltrate them. The fields remain available for explicit debugging.
      const invalidated = KeyInvalidatedException(
        keyAlias: 'tenant-42-secret-alias',
        cause: 'RAW NATIVE KEYMASTER TEXT',
      );
      final s = invalidated.toString();
      expect(s, isNot(contains('tenant-42-secret-alias')));
      expect(s, isNot(contains('RAW NATIVE KEYMASTER TEXT')));
      // The field is still there for opt-in logging.
      expect(invalidated.keyAlias, 'tenant-42-secret-alias');

      const notFound = KeyNotFoundException(
        keyAlias: 'tenant-42-secret-alias',
        cause: 'RAW NATIVE TEXT',
      );
      expect(notFound.toString(), isNot(contains('tenant-42-secret-alias')));
      expect(notFound.toString(), isNot(contains('RAW NATIVE TEXT')));
    });
  });
}
