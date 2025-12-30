/// Mobi Tests - Euclidean Approach
///
/// Axiom: Mobi is a deterministic 21-digit identifier derived from a 32-byte pubkey.
/// Theorem: Same pubkey → Same mobi, formatting is consistent, parsing is reversible.
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:wallet_core/wallet_core.dart';

void main() {
  group('Mobi - Derivation', () {
    // Known test vector: the canonical NIP-06 pubkey
    const testPubkeyHex =
        '17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917';

    test('Axiom 1: Derive from hex pubkey', () {
      final mobi = Mobi.fromHex(testPubkeyHex);

      expect(mobi.full.length, equals(21));
      expect(mobi.display.length, equals(12));
    });

    test('Axiom 2: Derive from bytes', () {
      final pubkeyBytes = Uint8List.fromList(
        List.generate(32, (i) => int.parse(
          testPubkeyHex.substring(i * 2, i * 2 + 2),
          radix: 16,
        )),
      );

      final mobi = Mobi.fromBytes(pubkeyBytes);

      expect(mobi.full.length, equals(21));
    });

    test('Axiom 3: Derivation is deterministic', () {
      final mobi1 = Mobi.fromHex(testPubkeyHex);
      final mobi2 = Mobi.fromHex(testPubkeyHex);

      expect(mobi1.full, equals(mobi2.full));
      expect(mobi1.display, equals(mobi2.display));
    });

    test('Axiom 4: Invalid hex length throws', () {
      expect(
        () => Mobi.fromHex('abc123'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('Axiom 5: Invalid bytes length throws', () {
      expect(
        () => Mobi.fromBytes(Uint8List.fromList([1, 2, 3])),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('Mobi - Formats', () {
    const testPubkeyHex =
        '17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917';

    late Mobi mobi;

    setUpAll(() {
      mobi = Mobi.fromHex(testPubkeyHex);
    });

    test('Theorem 1: Full is 21 digits', () {
      expect(mobi.full.length, equals(21));
      expect(RegExp(r'^\d{21}$').hasMatch(mobi.full), isTrue);
    });

    test('Theorem 2: Display is first 12 digits of full', () {
      expect(mobi.display, equals(mobi.full.substring(0, 12)));
    });

    test('Theorem 3: Extended is first 15 digits of full', () {
      expect(mobi.extended, equals(mobi.full.substring(0, 15)));
    });

    test('Theorem 4: Long is first 18 digits of full', () {
      expect(mobi.lng, equals(mobi.full.substring(0, 18)));
    });

    test('Theorem 5: formatDisplay is XXX-XXX-XXX-XXX', () {
      final formatted = mobi.formatDisplay();
      expect(RegExp(r'^\d{3}-\d{3}-\d{3}-\d{3}$').hasMatch(formatted), isTrue);
    });

    test('Theorem 6: formatExtended is XXX-XXX-XXX-XXX-XXX', () {
      final formatted = mobi.formatExtended();
      expect(
        RegExp(r'^\d{3}-\d{3}-\d{3}-\d{3}-\d{3}$').hasMatch(formatted),
        isTrue,
      );
    });

    test('Theorem 7: formatFull is XXX-XXX-XXX-XXX-XXX-XXX-XXX', () {
      final formatted = mobi.formatFull();
      expect(
        RegExp(r'^\d{3}-\d{3}-\d{3}-\d{3}-\d{3}-\d{3}-\d{3}$').hasMatch(formatted),
        isTrue,
      );
    });

    test('Theorem 8: toString returns formatDisplay', () {
      expect(mobi.toString(), equals(mobi.formatDisplay()));
    });
  });

  group('Mobi - Parsing', () {
    test('Theorem 9: Parse from display format', () {
      final mobi = Mobi.parse('123-456-789-012');

      expect(mobi.display, equals('123456789012'));
    });

    test('Theorem 10: Parse from raw digits', () {
      final mobi = Mobi.parse('123456789012');

      expect(mobi.display, equals('123456789012'));
    });

    test('Theorem 11: Parse ignores spaces', () {
      final mobi = Mobi.parse('123 456 789 012');

      expect(mobi.display, equals('123456789012'));
    });

    test('Theorem 12: Parse ignores dots', () {
      final mobi = Mobi.parse('123.456.789.012');

      expect(mobi.display, equals('123456789012'));
    });

    test('Theorem 13: Parse ignores parentheses', () {
      final mobi = Mobi.parse('(123) 456-789-012');

      expect(mobi.display, equals('123456789012'));
    });

    test('Theorem 14: Invalid characters throw', () {
      expect(
        () => Mobi.parse('123-abc-789-012'),
        throwsA(isA<FormatException>()),
      );
    });

    test('Theorem 15: Invalid length throws', () {
      expect(
        () => Mobi.parse('12345'),
        throwsA(isA<FormatException>()),
      );
    });

    test('Theorem 16: tryParse returns null on invalid', () {
      expect(Mobi.tryParse('invalid'), isNull);
    });

    test('Theorem 17: tryParse returns Mobi on valid', () {
      final mobi = Mobi.tryParse('123-456-789-012');

      expect(mobi, isNotNull);
      expect(mobi!.display, equals('123456789012'));
    });
  });

  group('Mobi - Validation', () {
    test('Theorem 18: Validate accepts 12 digits', () {
      expect(Mobi.validate('123456789012'), isTrue);
    });

    test('Theorem 19: Validate accepts 15 digits', () {
      expect(Mobi.validate('123456789012345'), isTrue);
    });

    test('Theorem 20: Validate accepts 18 digits', () {
      expect(Mobi.validate('123456789012345678'), isTrue);
    });

    test('Theorem 21: Validate accepts 21 digits', () {
      expect(Mobi.validate('123456789012345678901'), isTrue);
    });

    test('Theorem 22: Validate accepts formatted', () {
      expect(Mobi.validate('123-456-789-012'), isTrue);
    });

    test('Theorem 23: Validate rejects invalid', () {
      expect(Mobi.validate('123'), isFalse);
      expect(Mobi.validate('abc-def-ghi-jkl'), isFalse);
    });
  });

  group('Mobi - Comparison', () {
    const testPubkeyHex =
        '17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917';

    test('Theorem 24: Equality based on full', () {
      final mobi1 = Mobi.fromHex(testPubkeyHex);
      final mobi2 = Mobi.fromHex(testPubkeyHex);

      expect(mobi1 == mobi2, isTrue);
      expect(mobi1.hashCode, equals(mobi2.hashCode));
    });

    test('Theorem 25: displayMatches compares first 12 digits', () {
      final mobi = Mobi.fromHex(testPubkeyHex);
      final display = mobi.display;

      expect(mobi.displayMatches(display), isTrue);
      expect(mobi.displayMatches('${display}000000000'), isTrue); // Extra digits ignored
    });

    test('Theorem 26: fullMatches compares all 21 digits', () {
      final mobi1 = Mobi.fromHex(testPubkeyHex);
      final mobi2 = Mobi.fromHex(testPubkeyHex);

      expect(mobi1.fullMatches(mobi2), isTrue);
    });
  });

  group('Mobi - Normalization', () {
    test('Theorem 27: Normalize strips formatting', () {
      final normalized = Mobi.normalize('123-456-789-012');

      expect(normalized, equals('123456789012'));
    });

    test('Theorem 28: Normalize returns null for invalid', () {
      expect(Mobi.normalize('abc'), isNull);
    });

    test('Theorem 29: Normalize accepts various separators', () {
      expect(Mobi.normalize('123-456-789-012'), equals('123456789012'));
      expect(Mobi.normalize('123 456 789 012'), equals('123456789012'));
      expect(Mobi.normalize('123.456.789.012'), equals('123456789012'));
      expect(Mobi.normalize('(123)456-789-012'), equals('123456789012'));
    });
  });
}
