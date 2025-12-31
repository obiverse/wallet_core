/// Vault Core - Pure Dart implementation
///
/// Provides the same API as vault_core_ffi.dart but using pure Dart crypto.
/// Uses the `cryptography` package for:
/// - Argon2id KDF
/// - XChaCha20-Poly1305 AEAD
/// - Secure random generation
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

// =============================================================================
// Error Codes (matching FFI version)
// =============================================================================

/// Error codes from vault_core
class VaultError {
  static const invalidInput = -1;
  static const decryptFailed = -2;
  static const kdfFailed = -3;
}

/// Exception thrown by vault operations
class VaultException implements Exception {
  final int code;
  final String message;

  VaultException(this.code, this.message);

  @override
  String toString() => 'VaultException($code): $message';

  static VaultException fromCode(int code) {
    return switch (code) {
      VaultError.invalidInput => VaultException(code, 'Invalid input'),
      VaultError.decryptFailed =>
        VaultException(code, 'Decryption failed (wrong key or corrupted data)'),
      VaultError.kdfFailed => VaultException(code, 'Key derivation failed'),
      _ => VaultException(code, 'Unknown error'),
    };
  }
}

// =============================================================================
// VaultCore - Pure Dart Implementation
// =============================================================================

/// Vault Core - Minimal cryptographic primitives (Pure Dart)
///
/// Drop-in replacement for VaultCore FFI using cryptography package.
///
/// Usage:
/// ```dart
/// final vault = VaultCore();
///
/// // Derive key from passphrase
/// final salt = vault.random(16);
/// final key = await vault.deriveKey('my passphrase', salt);
///
/// // Encrypt data
/// final sealed = await vault.seal(key, utf8.encode('secret'));
///
/// // Decrypt data
/// final plaintext = await vault.unseal(key, sealed);
///
/// // Zeroize the key when done
/// vault.zeroize(key);
/// ```
class VaultCore {
  // Argon2id with parameters matching the Rust FFI version
  // m=64MB, t=3 iterations, p=4 parallelism
  final _argon2 = Argon2id(
    memory: 65536, // 64 MB
    iterations: 3,
    parallelism: 4,
    hashLength: 32,
  );

  // XChaCha20-Poly1305 AEAD
  final _cipher = Xchacha20.poly1305Aead();

  // ===========================================================================
  // Public API
  // ===========================================================================

  /// Derive a 32-byte encryption key from passphrase using Argon2id.
  ///
  /// This is CPU-intensive (~200ms). Use async/await.
  ///
  /// - [passphrase]: User's passphrase/PIN
  /// - [salt]: 16-byte random salt (store alongside encrypted data)
  ///
  /// Returns: 32-byte key (caller should [zeroize] when done)
  Future<Uint8List> deriveKey(String passphrase, Uint8List salt) async {
    if (salt.length != 16) {
      throw ArgumentError('Salt must be exactly 16 bytes');
    }

    try {
      final secretKey = await _argon2.deriveKey(
        secretKey: SecretKey(passphrase.codeUnits),
        nonce: salt,
      );

      final keyBytes = await secretKey.extractBytes();
      return Uint8List.fromList(keyBytes);
    } catch (e) {
      throw VaultException.fromCode(VaultError.kdfFailed);
    }
  }

  /// Encrypt data using XChaCha20-Poly1305.
  ///
  /// - [key]: 32-byte key from [deriveKey]
  /// - [plaintext]: Data to encrypt
  ///
  /// Returns: Sealed data (nonce || ciphertext || tag)
  Future<Uint8List> seal(Uint8List key, Uint8List plaintext) async {
    if (key.length != 32) {
      throw ArgumentError('Key must be exactly 32 bytes');
    }

    try {
      final secretKey = SecretKey(key);
      final nonce = _cipher.newNonce(); // 24 bytes for XChaCha20

      final secretBox = await _cipher.encrypt(
        plaintext,
        secretKey: secretKey,
        nonce: nonce,
      );

      // Format: nonce (24) || ciphertext || tag (16)
      final result = Uint8List(nonce.length + secretBox.cipherText.length + secretBox.mac.bytes.length);
      var offset = 0;

      // Copy nonce
      result.setAll(offset, nonce);
      offset += nonce.length;

      // Copy ciphertext
      result.setAll(offset, secretBox.cipherText);
      offset += secretBox.cipherText.length;

      // Copy MAC/tag
      result.setAll(offset, secretBox.mac.bytes);

      return result;
    } catch (e) {
      throw VaultException(VaultError.invalidInput, 'Encryption failed: $e');
    }
  }

  /// Decrypt data encrypted with [seal].
  ///
  /// - [key]: 32-byte key from [deriveKey]
  /// - [sealed]: Sealed data from [seal]
  ///
  /// Returns: Original plaintext
  /// Throws: [VaultException] if key is wrong or data corrupted
  Future<Uint8List> unseal(Uint8List key, Uint8List sealed) async {
    if (key.length != 32) {
      throw ArgumentError('Key must be exactly 32 bytes');
    }

    // XChaCha20 nonce is 24 bytes, MAC is 16 bytes
    const nonceLen = 24;
    const macLen = 16;
    final minLen = nonceLen + macLen;

    if (sealed.length < minLen) {
      throw VaultException.fromCode(VaultError.invalidInput);
    }

    try {
      final secretKey = SecretKey(key);

      // Extract nonce (first 24 bytes)
      final nonce = sealed.sublist(0, nonceLen);

      // Extract ciphertext (middle)
      final cipherText = sealed.sublist(nonceLen, sealed.length - macLen);

      // Extract MAC (last 16 bytes)
      final mac = Mac(sealed.sublist(sealed.length - macLen));

      final secretBox = SecretBox(
        cipherText,
        nonce: nonce,
        mac: mac,
      );

      final plaintext = await _cipher.decrypt(
        secretBox,
        secretKey: secretKey,
      );

      return Uint8List.fromList(plaintext);
    } catch (e) {
      throw VaultException.fromCode(VaultError.decryptFailed);
    }
  }

  /// Zeroize a buffer in place.
  ///
  /// Call this on keys when you're done with them.
  void zeroize(Uint8List buffer) {
    buffer.fillRange(0, buffer.length, 0);
  }

  /// Generate cryptographically secure random bytes.
  ///
  /// - [length]: Number of bytes to generate
  Uint8List random(int length) {
    final random = SecretKeyData.random(length: length);
    // Extract bytes synchronously since it's already generated
    return Uint8List.fromList(random.bytes);
  }
}
