/// NostrSigner - Nostr key operations and NIP-44 encryption
///
/// Provides:
/// - Schnorr signing for Nostr events (NIP-01)
/// - NIP-44 encrypted direct messages
/// - Key encoding (npub, nsec, bech32)
///
/// Based on NIP-06 for key derivation from BIP-39 mnemonic.
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:convert/convert.dart';

import 'master_key.dart';

// =============================================================================
// BECH32 ENCODING
// =============================================================================

/// Bech32 character set
const String _bech32Charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/// Convert 8-bit bytes to 5-bit groups for bech32
List<int> _convertBits(List<int> data, int fromBits, int toBits, bool pad) {
  var acc = 0;
  var bits = 0;
  final result = <int>[];
  final maxv = (1 << toBits) - 1;

  for (final value in data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.add((acc >> bits) & maxv);
    }
  }

  if (pad && bits > 0) {
    result.add((acc << (toBits - bits)) & maxv);
  }

  return result;
}

/// Compute bech32 checksum
List<int> _bech32Checksum(String hrp, List<int> data) {
  final values = <int>[];
  for (var i = 0; i < hrp.length; i++) {
    values.add(hrp.codeUnitAt(i) >> 5);
  }
  values.add(0);
  for (var i = 0; i < hrp.length; i++) {
    values.add(hrp.codeUnitAt(i) & 31);
  }
  values.addAll(data);
  values.addAll([0, 0, 0, 0, 0, 0]);

  var polymod = 1;
  for (final v in values) {
    final b = polymod >> 25;
    polymod = ((polymod & 0x1ffffff) << 5) ^ v;
    if ((b & 1) != 0) polymod ^= 0x3b6a57b2;
    if ((b & 2) != 0) polymod ^= 0x26508e6d;
    if ((b & 4) != 0) polymod ^= 0x1ea119fa;
    if ((b & 8) != 0) polymod ^= 0x3d4233dd;
    if ((b & 16) != 0) polymod ^= 0x2a1462b3;
  }
  polymod ^= 1;

  final checksum = <int>[];
  for (var i = 0; i < 6; i++) {
    checksum.add((polymod >> (5 * (5 - i))) & 31);
  }
  return checksum;
}

/// Encode to bech32
String bech32Encode(String hrp, Uint8List data) {
  final converted = _convertBits(data.toList(), 8, 5, true);
  final checksum = _bech32Checksum(hrp, converted);
  final combined = [...converted, ...checksum];

  final result = StringBuffer(hrp);
  result.write('1');
  for (final c in combined) {
    result.write(_bech32Charset[c]);
  }
  return result.toString();
}

/// Decode from bech32
(String hrp, Uint8List data)? bech32Decode(String input) {
  final lower = input.toLowerCase();
  final pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) return null;

  final hrp = lower.substring(0, pos);
  final dataStr = lower.substring(pos + 1);

  final data = <int>[];
  for (var i = 0; i < dataStr.length; i++) {
    final c = _bech32Charset.indexOf(dataStr[i]);
    if (c < 0) return null;
    data.add(c);
  }

  // Verify checksum
  final values = <int>[];
  for (var i = 0; i < hrp.length; i++) {
    values.add(hrp.codeUnitAt(i) >> 5);
  }
  values.add(0);
  for (var i = 0; i < hrp.length; i++) {
    values.add(hrp.codeUnitAt(i) & 31);
  }
  values.addAll(data);

  var polymod = 1;
  for (final v in values) {
    final b = polymod >> 25;
    polymod = ((polymod & 0x1ffffff) << 5) ^ v;
    if ((b & 1) != 0) polymod ^= 0x3b6a57b2;
    if ((b & 2) != 0) polymod ^= 0x26508e6d;
    if ((b & 4) != 0) polymod ^= 0x1ea119fa;
    if ((b & 8) != 0) polymod ^= 0x3d4233dd;
    if ((b & 16) != 0) polymod ^= 0x2a1462b3;
  }
  if (polymod != 1) return null;

  // Remove checksum and convert back to 8-bit
  final payload = data.sublist(0, data.length - 6);
  final converted = _convertBits(payload, 5, 8, false);

  return (hrp, Uint8List.fromList(converted));
}

// =============================================================================
// NOSTR SIGNER
// =============================================================================

/// NostrSigner - Schnorr signing and NIP-44 encryption
///
/// Usage:
/// ```dart
/// final signer = NostrSigner.fromMasterKey(masterKey);
///
/// // Sign a Nostr event
/// final sig = await signer.signEvent(eventHash);
///
/// // Encrypt a message (NIP-44)
/// final encrypted = await signer.encrypt(recipientPubkey, message);
///
/// // Decrypt a message
/// final decrypted = await signer.decrypt(senderPubkey, encrypted);
/// ```
class NostrSigner {
  /// Private key (32 bytes)
  final Uint8List _privateKey;

  /// Public key (32 bytes, x-only)
  final Uint8List _publicKey;

  NostrSigner._({
    required Uint8List privateKey,
    required Uint8List publicKey,
  })  : _privateKey = privateKey,
        _publicKey = publicKey;

  /// Create signer from MasterKey
  factory NostrSigner.fromMasterKey(MasterKey masterKey) {
    return NostrSigner._(
      privateKey: masterKey.nostrPrivateKey,
      publicKey: masterKey.nostrPublicKey,
    );
  }

  /// Create signer from raw private key
  factory NostrSigner.fromPrivateKey(Uint8List privateKey) {
    if (privateKey.length != 32) {
      throw ArgumentError('Private key must be 32 bytes');
    }
    // Derive public key (simplified - should use secp256k1)
    // For now, we hash the private key as placeholder
    final pubkey = _derivePublicKey(privateKey);
    return NostrSigner._(privateKey: privateKey, publicKey: pubkey);
  }

  /// Create signer from nsec (bech32 encoded private key)
  factory NostrSigner.fromNsec(String nsec) {
    final decoded = bech32Decode(nsec);
    if (decoded == null || decoded.$1 != 'nsec') {
      throw ArgumentError('Invalid nsec');
    }
    return NostrSigner.fromPrivateKey(decoded.$2);
  }

  /// Public key as hex
  String get publicKeyHex => hex.encode(_publicKey);

  /// Public key as npub
  String get npub => bech32Encode('npub', _publicKey);

  /// Private key as nsec
  String get nsec => bech32Encode('nsec', _privateKey);

  // ===========================================================================
  // SIGNING (Schnorr / BIP-340)
  // ===========================================================================

  /// Sign a 32-byte event hash
  ///
  /// Returns 64-byte Schnorr signature.
  ///
  /// Note: This is a placeholder. Real implementation requires
  /// proper secp256k1 Schnorr signing (BIP-340).
  Future<Uint8List> signEvent(Uint8List eventHash) async {
    if (eventHash.length != 32) {
      throw ArgumentError('Event hash must be 32 bytes');
    }

    // Placeholder: Real Schnorr signing requires secp256k1
    // For now, use HMAC-SHA512 as a deterministic placeholder
    // TODO: Replace with actual Schnorr signing
    final hmac = Hmac(sha512, _privateKey);
    final digest = hmac.convert(eventHash);

    return Uint8List.fromList(digest.bytes.sublist(0, 64));
  }

  /// Sign a Nostr event and return hex signature
  Future<String> signEventHex(Uint8List eventHash) async {
    final sig = await signEvent(eventHash);
    return hex.encode(sig);
  }

  // ===========================================================================
  // NIP-44 ENCRYPTION
  // ===========================================================================

  /// Encrypt a message for a recipient (NIP-44)
  ///
  /// [recipientPubkey]: 32-byte x-only public key of recipient
  /// [plaintext]: Message to encrypt
  ///
  /// Returns base64-encoded ciphertext.
  Future<String> encrypt(Uint8List recipientPubkey, String plaintext) async {
    if (recipientPubkey.length != 32) {
      throw ArgumentError('Recipient public key must be 32 bytes');
    }

    // Derive shared secret using ECDH
    // Note: Real NIP-44 uses secp256k1 ECDH, this is a placeholder
    final sharedSecret = _deriveSharedSecret(_privateKey, recipientPubkey);

    // NIP-44 uses ChaCha20-Poly1305
    final algorithm = cryptography.Chacha20.poly1305Aead();

    // Derive encryption key from shared secret
    final secretKey = cryptography.SecretKey(sharedSecret);

    // Generate random nonce (12 bytes for ChaCha20)
    final nonce = Uint8List(12);
    _fillRandom(nonce);

    // Encrypt
    final secretBox = await algorithm.encrypt(
      utf8.encode(plaintext),
      secretKey: secretKey,
      nonce: nonce,
    );

    // Combine: version(1) + nonce(12) + ciphertext + mac(16)
    final result = Uint8List(1 + 12 + secretBox.cipherText.length + 16);
    result[0] = 2; // NIP-44 version 2
    result.setRange(1, 13, nonce);
    result.setRange(13, 13 + secretBox.cipherText.length, secretBox.cipherText);
    result.setRange(
        13 + secretBox.cipherText.length, result.length, secretBox.mac.bytes);

    return base64.encode(result);
  }

  /// Decrypt a message from a sender (NIP-44)
  ///
  /// [senderPubkey]: 32-byte x-only public key of sender
  /// [ciphertext]: Base64-encoded ciphertext
  ///
  /// Returns decrypted plaintext.
  Future<String> decrypt(Uint8List senderPubkey, String ciphertext) async {
    if (senderPubkey.length != 32) {
      throw ArgumentError('Sender public key must be 32 bytes');
    }

    final data = base64.decode(ciphertext);
    if (data.length < 29) {
      // 1 + 12 + 0 + 16 minimum
      throw ArgumentError('Ciphertext too short');
    }

    final version = data[0];
    if (version != 2) {
      throw ArgumentError('Unsupported NIP-44 version: $version');
    }

    final nonce = data.sublist(1, 13);
    final encryptedData = data.sublist(13, data.length - 16);
    final mac = data.sublist(data.length - 16);

    // Derive shared secret
    final sharedSecret = _deriveSharedSecret(_privateKey, senderPubkey);

    // Decrypt
    final algorithm = cryptography.Chacha20.poly1305Aead();
    final secretKey = cryptography.SecretKey(sharedSecret);

    final secretBox = cryptography.SecretBox(
      encryptedData,
      nonce: nonce,
      mac: cryptography.Mac(mac),
    );

    final plaintext = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
    );

    return utf8.decode(plaintext);
  }

  // ===========================================================================
  // INTERNAL
  // ===========================================================================

  /// Derive public key from private key
  ///
  /// Note: This is a placeholder. Real implementation needs secp256k1.
  static Uint8List _derivePublicKey(Uint8List privateKey) {
    // Placeholder: hash the private key
    // Real: secp256k1 point multiplication
    final hash = sha256.convert(privateKey);
    return Uint8List.fromList(hash.bytes);
  }

  /// Derive shared secret (ECDH)
  ///
  /// Note: This is a placeholder. Real NIP-44 uses secp256k1 ECDH.
  static Uint8List _deriveSharedSecret(
      Uint8List privateKey, Uint8List publicKey) {
    // Placeholder: HKDF of concatenated keys
    // Real: secp256k1 ECDH
    final combined = Uint8List(64);
    combined.setRange(0, 32, privateKey);
    combined.setRange(32, 64, publicKey);

    final hash = sha256.convert(combined);
    return Uint8List.fromList(hash.bytes);
  }

  /// Fill buffer with random bytes
  static void _fillRandom(Uint8List buffer) {
    // Simple PRNG for demo - use crypto.getRandomValues in production
    final now = DateTime.now().microsecondsSinceEpoch;
    var seed = now;
    for (var i = 0; i < buffer.length; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      buffer[i] = seed & 0xff;
    }
  }

  /// Securely clear key material
  void zeroize() {
    _privateKey.fillRange(0, _privateKey.length, 0);
  }
}
