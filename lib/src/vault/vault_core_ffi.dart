/// Vault Core FFI - Dart bindings to the minimal Rust crypto library
///
/// This is the FFI bridge to Layer 0. Only 6 functions:
/// - [deriveKey] - Argon2id KDF
/// - [seal] - XChaCha20-Poly1305 encrypt
/// - [unseal] - XChaCha20-Poly1305 decrypt
/// - [free] - Secure memory free
/// - [zeroize] - Zeroize buffer in place
/// - [random] - CSPRNG bytes
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

// =============================================================================
// Native Types
// =============================================================================

/// Result buffer from native functions
final class VaultBuffer extends Struct {
  external Pointer<Uint8> data;

  @Uint32()
  external int len;

  @Int32()
  external int error;
}

// =============================================================================
// Native Function Signatures
// =============================================================================

typedef _DeriveKeyNative = VaultBuffer Function(
  Pointer<Uint8> passphrase,
  Uint32 passphraseLen,
  Pointer<Uint8> salt,
);
typedef _DeriveKeyDart = VaultBuffer Function(
  Pointer<Uint8> passphrase,
  int passphraseLen,
  Pointer<Uint8> salt,
);

typedef _SealNative = VaultBuffer Function(
  Pointer<Uint8> key,
  Pointer<Uint8> plaintext,
  Uint32 plaintextLen,
);
typedef _SealDart = VaultBuffer Function(
  Pointer<Uint8> key,
  Pointer<Uint8> plaintext,
  int plaintextLen,
);

typedef _UnsealNative = VaultBuffer Function(
  Pointer<Uint8> key,
  Pointer<Uint8> sealed,
  Uint32 sealedLen,
);
typedef _UnsealDart = VaultBuffer Function(
  Pointer<Uint8> key,
  Pointer<Uint8> sealed,
  int sealedLen,
);

typedef _FreeNative = Void Function(Pointer<Uint8> ptr, Uint32 len);
typedef _FreeDart = void Function(Pointer<Uint8> ptr, int len);

typedef _ZeroizeNative = Void Function(Pointer<Uint8> ptr, Uint32 len);
typedef _ZeroizeDart = void Function(Pointer<Uint8> ptr, int len);

typedef _RandomNative = Int32 Function(Pointer<Uint8> out, Uint32 len);
typedef _RandomDart = int Function(Pointer<Uint8> out, int len);

// =============================================================================
// Error Codes
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
      VaultError.decryptFailed => VaultException(code, 'Decryption failed (wrong key or corrupted data)'),
      VaultError.kdfFailed => VaultException(code, 'Key derivation failed'),
      _ => VaultException(code, 'Unknown error'),
    };
  }
}

// =============================================================================
// VaultCore - Main API
// =============================================================================

/// Vault Core - Minimal cryptographic primitives
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
/// final sealed = vault.seal(key, utf8.encode('secret'));
///
/// // Decrypt data
/// final plaintext = vault.unseal(key, sealed);
///
/// // Always zeroize the key when done
/// vault.zeroize(key);
/// ```
class VaultCore {
  late final DynamicLibrary _lib;
  late final _DeriveKeyDart _deriveKey;
  late final _SealDart _seal;
  late final _UnsealDart _unseal;
  late final _FreeDart _free;
  late final _ZeroizeDart _zeroize;
  late final _RandomDart _random;

  /// Create VaultCore instance
  ///
  /// Loads the native library from the appropriate location.
  VaultCore() {
    _lib = _loadLibrary();
    _deriveKey = _lib.lookupFunction<_DeriveKeyNative, _DeriveKeyDart>('vault_derive_key');
    _seal = _lib.lookupFunction<_SealNative, _SealDart>('vault_seal');
    _unseal = _lib.lookupFunction<_UnsealNative, _UnsealDart>('vault_unseal');
    _free = _lib.lookupFunction<_FreeNative, _FreeDart>('vault_free');
    _zeroize = _lib.lookupFunction<_ZeroizeNative, _ZeroizeDart>('vault_zeroize');
    _random = _lib.lookupFunction<_RandomNative, _RandomDart>('vault_random');
  }

  /// Load the native library
  static DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libvault_core.so');
    } else if (Platform.isIOS) {
      return DynamicLibrary.process(); // Statically linked
    } else if (Platform.isMacOS) {
      // Try various locations
      const paths = [
        'libvault_core.dylib',
        '../Frameworks/libvault_core.dylib',
        'vault_core.framework/vault_core',
      ];
      for (final path in paths) {
        try {
          return DynamicLibrary.open(path);
        } catch (_) {
          continue;
        }
      }
      // Fall back to executable for Flutter
      return DynamicLibrary.executable();
    } else if (Platform.isLinux) {
      return DynamicLibrary.open('libvault_core.so');
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('vault_core.dll');
    }
    throw UnsupportedError('Platform not supported: ${Platform.operatingSystem}');
  }

  // ===========================================================================
  // Public API
  // ===========================================================================

  /// Derive a 32-byte encryption key from passphrase using Argon2id.
  ///
  /// This is CPU-intensive (~200ms). Run in an isolate for UI apps.
  ///
  /// - [passphrase]: User's passphrase/PIN
  /// - [salt]: 16-byte random salt (store alongside encrypted data)
  ///
  /// Returns: 32-byte key (caller must [zeroize] when done)
  Uint8List deriveKey(String passphrase, Uint8List salt) {
    if (salt.length != 16) {
      throw ArgumentError('Salt must be exactly 16 bytes');
    }

    final passphraseBytes = Uint8List.fromList(passphrase.codeUnits);
    final passphrasePtr = _allocate(passphraseBytes);
    final saltPtr = _allocate(salt);

    try {
      final result = _deriveKey(passphrasePtr, passphraseBytes.length, saltPtr);

      if (result.error != 0) {
        throw VaultException.fromCode(result.error);
      }

      final key = _copyAndFree(result);
      return key;
    } finally {
      // Zeroize passphrase from native memory
      _zeroize(passphrasePtr, passphraseBytes.length);
      calloc.free(passphrasePtr);
      calloc.free(saltPtr);
    }
  }

  /// Encrypt data using XChaCha20-Poly1305.
  ///
  /// - [key]: 32-byte key from [deriveKey]
  /// - [plaintext]: Data to encrypt
  ///
  /// Returns: Sealed data (nonce || ciphertext || tag)
  Uint8List seal(Uint8List key, Uint8List plaintext) {
    if (key.length != 32) {
      throw ArgumentError('Key must be exactly 32 bytes');
    }

    final keyPtr = _allocate(key);
    final plaintextPtr = _allocate(plaintext);

    try {
      final result = _seal(keyPtr, plaintextPtr, plaintext.length);

      if (result.error != 0) {
        throw VaultException.fromCode(result.error);
      }

      return _copyAndFree(result);
    } finally {
      calloc.free(keyPtr);
      calloc.free(plaintextPtr);
    }
  }

  /// Decrypt data encrypted with [seal].
  ///
  /// - [key]: 32-byte key from [deriveKey]
  /// - [sealed]: Sealed data from [seal]
  ///
  /// Returns: Original plaintext
  /// Throws: [VaultException] if key is wrong or data corrupted
  Uint8List unseal(Uint8List key, Uint8List sealed) {
    if (key.length != 32) {
      throw ArgumentError('Key must be exactly 32 bytes');
    }

    final keyPtr = _allocate(key);
    final sealedPtr = _allocate(sealed);

    try {
      final result = _unseal(keyPtr, sealedPtr, sealed.length);

      if (result.error != 0) {
        throw VaultException.fromCode(result.error);
      }

      return _copyAndFree(result);
    } finally {
      calloc.free(keyPtr);
      calloc.free(sealedPtr);
    }
  }

  /// Zeroize a buffer in place.
  ///
  /// Call this on keys when you're done with them.
  void zeroize(Uint8List buffer) {
    final ptr = _allocate(buffer);
    _zeroize(ptr, buffer.length);

    // Copy zeros back to Dart buffer
    final zeros = ptr.asTypedList(buffer.length);
    buffer.setAll(0, zeros);

    calloc.free(ptr);
  }

  /// Generate cryptographically secure random bytes.
  ///
  /// - [length]: Number of bytes to generate
  Uint8List random(int length) {
    final ptr = calloc(length);

    try {
      final result = _random(ptr, length);
      if (result != 0) {
        throw VaultException.fromCode(result);
      }

      return Uint8List.fromList(ptr.asTypedList(length));
    } finally {
      calloc.free(ptr);
    }
  }

  // ===========================================================================
  // Internal Helpers
  // ===========================================================================

  /// Allocate native memory and copy data
  Pointer<Uint8> _allocate(Uint8List data) {
    final ptr = calloc(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }

  /// Copy data from native buffer and free it
  Uint8List _copyAndFree(VaultBuffer buffer) {
    final data = Uint8List.fromList(
      buffer.data.asTypedList(buffer.len),
    );
    _free(buffer.data, buffer.len);
    return data;
  }
}

// =============================================================================
// Memory Allocator
// =============================================================================

// Platform malloc/free
final DynamicLibrary _stdlib = Platform.isWindows
    ? DynamicLibrary.open('msvcrt.dll')
    : DynamicLibrary.process();

final Pointer<Void> Function(int) _nativeMalloc = _stdlib
    .lookup<NativeFunction<Pointer<Void> Function(IntPtr)>>('malloc')
    .asFunction();

final void Function(Pointer<Void>) _nativeFree = _stdlib
    .lookup<NativeFunction<Void Function(Pointer<Void>)>>('free')
    .asFunction();

/// Simple memory allocator for FFI
final calloc = _Calloc();

class _Calloc {
  /// Allocate [count] bytes of zeroed memory
  Pointer<Uint8> call(int count) {
    final ptr = _nativeMalloc(count);
    if (ptr.address == 0) {
      throw StateError('malloc failed');
    }
    // Zero initialize
    final uint8Ptr = ptr.cast<Uint8>();
    uint8Ptr.asTypedList(count).fillRange(0, count, 0);
    return uint8Ptr;
  }

  /// Free memory at [ptr]
  void free(Pointer ptr) {
    _nativeFree(ptr.cast<Void>());
  }
}
