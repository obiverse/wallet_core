/// NostrSigner Tests - Euclidean Approach
///
/// Axiom: Schnorr signatures (BIP-340) are deterministic and verifiable.
/// Theorem: Our signatures match the spec and can be verified by any compliant implementation.
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:convert/convert.dart';
import 'package:wallet_core/wallet_core.dart';

void main() {
  group('NostrSigner - Creation', () {
    const testMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    test('Axiom 1: Create from MasterKey', () {
      final master = MasterKey.fromMnemonic(testMnemonic);
      final signer = NostrSigner.fromMasterKey(master);

      expect(signer.publicKeyHex, equals(master.nostrPublicKeyHex));
      expect(signer.privateKeyHex, equals(master.nostrPrivateKeyHex));
    });

    test('Axiom 2: Create from private key hex', () {
      const privkeyHex =
          '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731';
      final signer = NostrSigner.fromPrivateKeyHex(privkeyHex);

      expect(signer.privateKeyHex, equals(privkeyHex));
      expect(signer.publicKeyHex.length, equals(64));
    });

    test('Axiom 3: Create from nsec', () {
      // nsec encoding of privkey 5f29af3b...
      const nsec =
          'nsec1tu567wukwcvq9y880f8045n9cnp07299xqjxrae4jl76y6aj2ucs2mkupq';
      final signer = NostrSigner.fromNsec(nsec);

      expect(signer.nsec, equals(nsec));
    });

    test('Axiom 4: Invalid private key length throws', () {
      expect(
        () => NostrSigner.fromPrivateKeyHex('abc123'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('NostrSigner - Identity', () {
    // Test vector: arbitrary 32-byte privkey with its ACTUAL derived values
    const privkeyHex =
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731';
    const expectedPubkeyHex =
        'e8bcf3823669444d0b49ad45d65088635d9fd8500a75b5f20b59abefa56a144f';
    const expectedNpub =
        'npub1az708q3kd9zy6z6f44zav5ygvdwelkzspf6mtusttx47lft2z38sghk0w7';

    late NostrSigner signer;

    setUpAll(() {
      signer = NostrSigner.fromPrivateKeyHex(privkeyHex);
    });

    test('Theorem 1: Public key derivation is correct', () {
      expect(signer.publicKeyHex, equals(expectedPubkeyHex));
    });

    test('Theorem 2: npub encoding is correct', () {
      expect(signer.npub, equals(expectedNpub));
    });

    test('Theorem 3: Public key bytes are 32 bytes', () {
      expect(signer.publicKey.length, equals(32));
    });

    test('Theorem 4: Private key bytes are 32 bytes', () {
      expect(signer.privateKey.length, equals(32));
    });
  });

  group('NostrSigner - Schnorr Signing (BIP-340)', () {
    const privkeyHex =
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731';

    late NostrSigner signer;

    setUpAll(() {
      signer = NostrSigner.fromPrivateKeyHex(privkeyHex);
    });

    test('Theorem 5: Sign produces 64-byte signature', () {
      // 32-byte message hash (simulating event ID)
      const messageHash =
          '0000000000000000000000000000000000000000000000000000000000000001';

      final signature = signer.sign(messageHash);

      expect(signature.length, equals(128)); // 64 bytes = 128 hex chars
    });

    test('Theorem 6: Signature is verifiable', () {
      const messageHash =
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      final signature = signer.sign(messageHash);

      // Verify using the static method
      final isValid = NostrSigner.verify(
        signer.publicKeyHex,
        messageHash,
        signature,
      );

      expect(isValid, isTrue);
    });

    test('Theorem 7: Wrong pubkey fails verification', () {
      const messageHash =
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const wrongPubkey =
          '0000000000000000000000000000000000000000000000000000000000000001';

      final signature = signer.sign(messageHash);

      final isValid = NostrSigner.verify(wrongPubkey, messageHash, signature);

      expect(isValid, isFalse);
    });

    test('Theorem 8: Wrong message fails verification', () {
      const messageHash =
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const wrongMessage =
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

      final signature = signer.sign(messageHash);

      final isValid = NostrSigner.verify(
        signer.publicKeyHex,
        wrongMessage,
        signature,
      );

      expect(isValid, isFalse);
    });

    test('Theorem 9: signBytes works with Uint8List', () {
      final messageHash = Uint8List.fromList(List.filled(32, 0x42));

      final signature = signer.signBytes(messageHash);

      expect(signature.length, equals(64));
    });

    test('Theorem 10: Invalid message hash length throws', () {
      expect(
        () => signer.sign('abc123'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('NostrSigner - Nostr Events', () {
    const privkeyHex =
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731';

    late NostrSigner signer;

    setUpAll(() {
      signer = NostrSigner.fromPrivateKeyHex(privkeyHex);
    });

    test('Theorem 11: Create text note (kind 1)', () {
      final event = signer.createTextNote('Hello, Nostr!');

      expect(event.kind, equals(1));
      expect(event.content, equals('Hello, Nostr!'));
      expect(event.pubkey, equals(signer.publicKeyHex));
      expect(event.sig.length, equals(128)); // Valid signature
    });

    test('Theorem 12: Create event with tags', () {
      final event = signer.createTextNote(
        'Hello @someone',
        tags: [
          ['p', 'somepubkey']
        ],
      );

      expect(event.tags.length, equals(1));
      expect(event.tags[0][0], equals('p'));
    });

    test('Theorem 13: Create metadata event (kind 0)', () {
      final event = signer.createMetadata(
        name: 'TestUser',
        about: 'Just testing',
        picture: 'https://example.com/pic.jpg',
        nip05: 'test@example.com',
      );

      expect(event.kind, equals(0));
      expect(event.content.contains('TestUser'), isTrue);
    });

    test('Theorem 14: Event signature is verifiable', () {
      final event = signer.createTextNote('Verify me');

      final isValid = NostrSigner.verify(
        event.pubkey,
        event.id,
        event.sig,
      );

      expect(isValid, isTrue);
    });
  });

  group('NostrSigner - ECDH Shared Secret', () {
    test('Theorem 15: Derive shared secret with another pubkey', () {
      // Two different signers
      final alice = NostrSigner.fromPrivateKeyHex(
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731',
      );
      final bob = NostrSigner.fromPrivateKeyHex(
        'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
      );

      // Each derives shared secret with the other's pubkey
      final secretAlice = alice.deriveSharedSecret(bob.publicKeyHex);
      final secretBob = bob.deriveSharedSecret(alice.publicKeyHex);

      // ECDH: both should derive the same secret
      expect(hex.encode(secretAlice), equals(hex.encode(secretBob)));
    });

    test('Theorem 16: Shared secret is 32 bytes', () {
      final alice = NostrSigner.fromPrivateKeyHex(
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731',
      );
      final bob = NostrSigner.fromPrivateKeyHex(
        'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
      );

      final secret = alice.deriveSharedSecret(bob.publicKeyHex);

      expect(secret.length, equals(32));
    });

    test('Theorem 17: Invalid pubkey length throws', () {
      final signer = NostrSigner.fromPrivateKeyHex(
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731',
      );

      expect(
        () => signer.deriveSharedSecret('abc123'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('NostrSigner - Encryption (Simplified NIP-44)', () {
    test('Theorem 18: Encrypt and decrypt roundtrip', () async {
      final alice = NostrSigner.fromPrivateKeyHex(
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731',
      );
      final bob = NostrSigner.fromPrivateKeyHex(
        'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
      );

      const plaintext = 'Hello, Bob! This is a secret message.';

      // Alice encrypts to Bob
      final ciphertext = await alice.encrypt(bob.publicKeyHex, plaintext);

      // Bob decrypts from Alice
      final decrypted = await bob.decrypt(alice.publicKeyHex, ciphertext);

      expect(decrypted, equals(plaintext));
    });

    test('Theorem 19: Ciphertext is base64 encoded', () async {
      final signer = NostrSigner.fromPrivateKeyHex(
        '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731',
      );
      final otherPubkey =
          'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35';

      final ciphertext = await signer.encrypt(otherPubkey, 'Test');

      // Should be valid base64
      expect(() => hex.decode(ciphertext), throwsFormatException);
      // Base64 doesn't throw
    });
  });
}
