/// VaultNamespace - Encrypted storage using Layer 0 crypto
///
/// Wraps any inner [Namespace] with transparent encryption.
/// All data is encrypted at rest using XChaCha20-Poly1305.
///
/// ## Usage
///
/// ```dart
/// // Create vault wrapping file storage
/// final inner = FileNamespace('/path/to/vault');
/// final vault = VaultNamespace(inner);
///
/// // Unlock with passphrase
/// await vault.unlock('my passphrase');
///
/// // Use like any namespace
/// await vault.writeAsync('/notes/secret', {'content': 'private data'});
/// final note = await vault.readAsync('/notes/secret');
///
/// // Lock when done
/// vault.lock();
/// ```
///
/// ## Security Model
///
/// - Passphrase → Argon2id → 32-byte key (slow, GPU-resistant)
/// - Key + plaintext → XChaCha20-Poly1305 → sealed (authenticated)
/// - Key zeroized on lock
/// - Salt stored alongside encrypted vault metadata
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:nine_s/nine_s.dart';

import 'vault_core_ffi.dart';

/// VaultNamespace - Transparent encryption layer
class VaultNamespace implements Namespace {
  final Namespace _inner;
  final VaultCore _core;

  Uint8List? _key;
  Uint8List? _salt;
  bool _closed = false;
  final List<_Watcher> _watchers = [];

  /// Create vault wrapping inner namespace
  ///
  /// - [inner]: Storage backend (FileNamespace, MemoryNamespace, etc.)
  /// - [core]: Optional VaultCore instance (creates one if not provided)
  VaultNamespace(this._inner, [VaultCore? core]) : _core = core ?? VaultCore();

  /// Check if vault is unlocked
  bool get isUnlocked => _key != null;

  /// Check if vault is initialized (has salt)
  bool get isInitialized => _salt != null;

  // ===========================================================================
  // Lifecycle
  // ===========================================================================

  /// Initialize vault with new passphrase
  ///
  /// Creates a new salt and derives encryption key.
  /// Call this once when creating a new vault.
  ///
  /// - [passphrase]: User's passphrase/PIN
  ///
  /// Runs Argon2 in isolate to avoid blocking UI.
  Future<Result<void>> init(String passphrase) async {
    if (_closed) return const Err(ClosedError());
    if (_salt != null) return const Err(InternalError('Vault already initialized'));

    // Generate random salt
    _salt = _core.random(16);

    // Derive key in isolate (Argon2 takes ~200ms)
    _key = await _deriveKeyInIsolate(passphrase, _salt!);

    // Store salt in inner namespace (unencrypted - it's public)
    final saltResult = _inner.write('/.vault/salt', {
      'salt': base64Encode(_salt!),
      'version': 1,
    });

    if (saltResult.isErr) {
      _key = null;
      _salt = null;
      return Err(saltResult.errorOrNull ?? const InternalError('Failed to store salt'));
    }

    return const Ok(null);
  }

  /// Unlock existing vault with passphrase
  ///
  /// Loads salt and derives encryption key.
  ///
  /// - [passphrase]: User's passphrase/PIN
  ///
  /// Returns error if passphrase is wrong (can't verify until first read).
  Future<Result<void>> unlock(String passphrase) async {
    if (_closed) return const Err(ClosedError());
    if (_key != null) return const Ok(null); // Already unlocked

    // Load salt
    final saltResult = _inner.read('/.vault/salt');
    if (saltResult.isErr) {
      return Err(saltResult.errorOrNull ?? const InternalError('Vault not initialized'));
    }

    final saltScroll = saltResult.value;
    if (saltScroll == null) {
      return const Err(InternalError('Vault not initialized'));
    }

    final saltBase64 = saltScroll.data['salt'] as String?;
    if (saltBase64 == null) {
      return const Err(InternalError('Invalid vault metadata'));
    }

    _salt = base64Decode(saltBase64);

    // Derive key in isolate
    _key = await _deriveKeyInIsolate(passphrase, _salt!);

    return const Ok(null);
  }

  /// Lock vault, zeroizing key
  void lock() {
    if (_key != null) {
      _core.zeroize(_key!);
      _key = null;
    }
  }

  /// Derive key in isolate to not block UI
  Future<Uint8List> _deriveKeyInIsolate(String passphrase, Uint8List salt) async {
    // For now, run synchronously
    // TODO: Use Isolate.run when we can pass VaultCore
    return _core.deriveKey(passphrase, salt);
  }

  // ===========================================================================
  // Namespace Implementation
  // ===========================================================================

  @override
  Result<Scroll?> read(String path) {
    // Sync read not supported (decryption should be async)
    return const Err(InternalError('Use readAsync for vault operations'));
  }

  /// Async read with decryption
  Future<Result<Scroll?>> readAsync(String path) async {
    if (_closed) return const Err(ClosedError());
    if (_key == null) return const Err(InternalError('Vault is locked'));

    // Skip vault metadata paths
    if (path.startsWith('/.vault/')) {
      return _inner.read(path);
    }

    // Read encrypted scroll
    final result = _inner.read(path);
    if (result.isErr) return Err(result.errorOrNull!);
    if (result.value == null) return const Ok(null);

    // Decrypt
    try {
      final sealedBase64 = result.value!.data['sealed'] as String?;
      if (sealedBase64 == null) {
        return const Err(InternalError('Invalid encrypted data'));
      }

      final sealed = base64Decode(sealedBase64);
      final plaintext = _core.unseal(_key!, sealed);
      final json = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;

      return Ok(Scroll.fromJson(json));
    } on VaultException catch (e) {
      return Err(InternalError('Decryption failed: ${e.message}'));
    } catch (e) {
      return Err(InternalError('Decryption error: $e'));
    }
  }

  @override
  Result<Scroll> write(String path, Map<String, dynamic> data) {
    // Sync write not supported
    return const Err(InternalError('Use writeAsync for vault operations'));
  }

  /// Async write with encryption
  Future<Result<Scroll>> writeAsync(String path, Map<String, dynamic> data) async {
    if (_closed) return const Err(ClosedError());
    if (_key == null) return const Err(InternalError('Vault is locked'));

    // Skip vault metadata paths
    if (path.startsWith('/.vault/')) {
      return _inner.write(path, data);
    }

    try {
      // Create scroll
      final scroll = Scroll(
        key: path,
        data: data,
        type_: 'vault/data@v1',
      );

      // Encrypt
      final plaintext = utf8.encode(jsonEncode(scroll.toJson()));
      final sealed = _core.seal(_key!, Uint8List.fromList(plaintext));

      // Store encrypted
      final result = _inner.write(path, {'sealed': base64Encode(sealed)});
      if (result.isErr) return result;

      // Notify watchers
      for (final watcher in _watchers) {
        if (_matchesPattern(path, watcher.pattern)) {
          watcher.controller.add(scroll);
        }
      }

      return Ok(scroll);
    } on VaultException catch (e) {
      return Err(InternalError('Encryption failed: ${e.message}'));
    } catch (e) {
      return Err(InternalError('Encryption error: $e'));
    }
  }

  @override
  Result<Scroll> writeScroll(Scroll scroll) {
    return const Err(InternalError('Use writeAsync'));
  }

  @override
  Result<List<String>> list(String prefix) {
    if (_closed) return const Err(ClosedError());

    // List doesn't need decryption - just returns paths
    // Filter out vault metadata
    final result = _inner.list(prefix);
    if (result.isErr) return result;

    final paths = result.value.where((p) => !p.startsWith('/.vault/')).toList();
    return Ok(paths);
  }

  @override
  Result<Stream<Scroll>> watch(String pattern) {
    if (_closed) return const Err(ClosedError());

    final controller = StreamController<Scroll>();
    _watchers.add(_Watcher(pattern: pattern, controller: controller));

    return Ok(controller.stream);
  }

  @override
  Result<void> close() {
    lock();
    _closed = true;

    for (final watcher in _watchers) {
      watcher.controller.close();
    }
    _watchers.clear();

    return const Ok(null);
  }

  // ===========================================================================
  // Helpers
  // ===========================================================================

  bool _matchesPattern(String path, String pattern) {
    // Simple glob matching
    if (pattern.endsWith('*')) {
      return path.startsWith(pattern.substring(0, pattern.length - 1));
    }
    return path == pattern;
  }
}

class _Watcher {
  final String pattern;
  final StreamController<Scroll> controller;

  _Watcher({required this.pattern, required this.controller});
}
