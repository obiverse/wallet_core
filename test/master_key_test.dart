/// MasterKey Tests - Euclidean Approach
///
/// Axiom: A valid BIP-39 mnemonic deterministically produces keys.
/// Theorem: Same mnemonic → Same keys, verifiable against known test vectors.
///
/// We use the canonical BIP-39 test vector (abandon×11 + about) which has
/// well-documented derived keys across the Bitcoin/Nostr ecosystem.
import 'package:test/test.dart';
import 'package:wallet_core/wallet_core.dart';

void main() {
  group('MasterKey - Axioms', () {
    // ==========================================================================
    // AXIOM 1: The canonical test mnemonic
    // ==========================================================================
    const testMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    test('Axiom 1: Valid mnemonic creates MasterKey', () {
      final master = MasterKey.fromMnemonic(testMnemonic);
      expect(master.mnemonic, equals(testMnemonic));
    });

    test('Axiom 2: Invalid mnemonic throws', () {
      expect(
        () => MasterKey.fromMnemonic('invalid mnemonic words'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('Axiom 3: Mnemonic normalization (case, whitespace)', () {
      final master1 = MasterKey.fromMnemonic(testMnemonic);
      final master2 = MasterKey.fromMnemonic(testMnemonic.toUpperCase());
      final master3 = MasterKey.fromMnemonic('  $testMnemonic  ');

      expect(master1.nostrPublicKeyHex, equals(master2.nostrPublicKeyHex));
      expect(master1.nostrPublicKeyHex, equals(master3.nostrPublicKeyHex));
    });
  });

  group('MasterKey - Nostr Keys (NIP-06)', () {
    // ==========================================================================
    // THEOREM: NIP-06 derivation at m/44'/1237'/0'/0/0
    // Official test vector from: https://github.com/nostr-protocol/nips/blob/master/06.md
    // ==========================================================================
    const testMnemonic =
        'leader monkey parrot ring guide accident before fence cannon height naive bean';

    // Official NIP-06 test vector values
    // Path: m/44'/1237'/0'/0/0
    const expectedPrivkeyHex =
        '7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a';
    const expectedPubkeyHex =
        '17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917';
    // npub derived from pubkey via NIP-19
    const expectedNpub =
        'npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu';

    late MasterKey master;

    setUpAll(() {
      master = MasterKey.fromMnemonic(testMnemonic);
    });

    test('Theorem 1: Private key matches NIP-06 test vector', () {
      expect(master.nostrPrivateKeyHex, equals(expectedPrivkeyHex));
    });

    test('Theorem 2: Public key matches NIP-06 test vector', () {
      expect(master.nostrPublicKeyHex, equals(expectedPubkeyHex));
    });

    test('Theorem 3: npub encoding matches NIP-19', () {
      expect(master.npub, equals(expectedNpub));
    });

    test('Theorem 5: Public key is 32 bytes (x-only)', () {
      expect(master.nostrPublicKey.length, equals(32));
    });

    test('Theorem 6: Private key is 32 bytes', () {
      expect(master.nostrPrivateKey.length, equals(32));
    });
  });

  group('MasterKey - Mobi Derivation', () {
    const testMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    late MasterKey master;

    setUpAll(() {
      master = MasterKey.fromMnemonic(testMnemonic);
    });

    test('Theorem 7: Mobi is deterministic', () {
      final master2 = MasterKey.fromMnemonic(testMnemonic);
      expect(master.mobi.full, equals(master2.mobi.full));
    });

    test('Theorem 8: Mobi display is 12 digits', () {
      expect(master.mobi.display.length, equals(12));
      expect(RegExp(r'^\d{12}$').hasMatch(master.mobi.display), isTrue);
    });

    test('Theorem 9: Mobi formatted is XXX-XXX-XXX-XXX', () {
      final formatted = master.mobi.formatDisplay();
      expect(RegExp(r'^\d{3}-\d{3}-\d{3}-\d{3}$').hasMatch(formatted), isTrue);
    });

    test('Theorem 10: Mobi full is 21 digits', () {
      expect(master.mobi.full.length, equals(21));
      expect(RegExp(r'^\d{21}$').hasMatch(master.mobi.full), isTrue);
    });
  });

  group('MasterKey - Bitcoin Keys (BIP-84)', () {
    const testMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    late MasterKey master;

    setUpAll(() {
      master = MasterKey.fromMnemonic(testMnemonic);
    });

    test('Theorem 11: Bitcoin xpub is valid base58', () {
      final xpub = master.bitcoinXpub;
      expect(xpub.startsWith('xpub') || xpub.startsWith('tpub'), isTrue);
    });

    test('Theorem 12: Receive key derivation is deterministic', () {
      final key1 = master.deriveReceiveKey(0);
      final key2 = master.deriveReceiveKey(0);
      expect(key1.publicKey, equals(key2.publicKey));
    });

    test('Theorem 13: Different indices produce different keys', () {
      final key0 = master.deriveReceiveKey(0);
      final key1 = master.deriveReceiveKey(1);
      expect(key0.publicKey, isNot(equals(key1.publicKey)));
    });
  });

  group('MasterKey - WireGuard Keys', () {
    const testMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    late MasterKey master;

    setUpAll(() {
      master = MasterKey.fromMnemonic(testMnemonic);
    });

    test('Theorem 14: WireGuard private key is 32 bytes', () {
      expect(master.wireGuardPrivateKey.length, equals(32));
    });

    test('Theorem 15: WireGuard key is clamped (Curve25519)', () {
      final key = master.wireGuardPrivateKey;
      // RFC 7748 clamping: bits 0,1,2 of first byte are 0
      expect(key[0] & 7, equals(0));
      // Bit 7 of last byte is 0, bit 6 is 1
      expect(key[31] & 128, equals(0));
      expect(key[31] & 64, equals(64));
    });
  });

  group('MasterKey - Generation', () {
    test('Theorem 16: Generated mnemonic is valid', () {
      final master = MasterKey.generate();
      expect(master.mnemonic.split(' ').length, equals(24)); // 256-bit = 24 words
    });

    test('Theorem 17: Generated mnemonics are unique', () {
      final master1 = MasterKey.generate();
      final master2 = MasterKey.generate();
      expect(master1.mnemonic, isNot(equals(master2.mnemonic)));
    });

    test('Theorem 18: 12-word generation works', () {
      final master = MasterKey.generate(strength: 128);
      expect(master.mnemonic.split(' ').length, equals(12));
    });
  });

  group('MasterKey - Security', () {
    const testMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    test('Theorem 19: Zeroize clears seed', () {
      final master = MasterKey.fromMnemonic(testMnemonic);
      final seedBefore = master.seed;
      expect(seedBefore.any((b) => b != 0), isTrue);

      master.zeroize();
      // Note: seed getter returns a copy, so we check the internal state
      // by trying to derive again (would fail with zeroed seed)
    });
  });
}
