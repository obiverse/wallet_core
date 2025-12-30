/// IdentityNamespace - Seed-derived identity as 9S Namespace
///
/// Provides deterministic identity derivation from wallet seed:
/// - `/npub` - Nostr public key (bech32)
/// - `/hex` - Hex public key
/// - `/mobi` - Mobinumber (12-digit identifier)
/// - `/fingerprint` - Key fingerprint
///
/// All identities are derived deterministically from the seed,
/// ensuring the same seed always produces the same identities.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:nine_s/nine_s.dart';
import 'package:convert/convert.dart';

/// IdentityNamespace - Seed-derived identity
///
/// Implements the 9S Namespace interface for identity operations.
/// All data is derived on-demand from the seed - nothing stored.
class IdentityNamespace implements Namespace {
  final Uint8List _seed;
  final Map<String, Scroll> _cache = {};
  final List<_Watcher> _watchers = [];
  bool _closed = false;

  /// Derived keys (lazily computed)
  late final Uint8List _privateKey;
  late final Uint8List _publicKey;

  IdentityNamespace._(this._seed) {
    _deriveKeys();
    _computeIdentities();
  }

  /// Create from BIP-39 seed bytes
  factory IdentityNamespace.fromSeed(Uint8List seed) {
    return IdentityNamespace._(seed);
  }

  void _deriveKeys() {
    // Derive identity key at m/44'/1237'/0'/0/0 (Nostr path)
    // For simplicity, we use the first 32 bytes of seed as private key
    // In production, use proper BIP-32 derivation
    _privateKey = Uint8List.fromList(_seed.sublist(0, 32));

    // Compute public key (simplified - in production use secp256k1)
    // For now, we'll use a hash of the private key as a placeholder
    _publicKey = _hashBytes(_privateKey);
  }

  void _computeIdentities() {
    final hexPubkey = hex.encode(_publicKey);

    // npub - Nostr public key in bech32
    final npub = _toBech32('npub', _publicKey);
    _cache['/npub'] = Scroll(
      key: '/npub',
      data: {'npub': npub, 'hex': hexPubkey},
      type_: 'identity/npub@v1',
    );

    // hex - Raw hex public key
    _cache['/hex'] = Scroll(
      key: '/hex',
      data: {'hex': hexPubkey},
      type_: 'identity/hex@v1',
    );

    // mobi - 12-digit mobinumber
    final mobi = _deriveMobinumber(_publicKey);
    _cache['/mobi'] = Scroll(
      key: '/mobi',
      data: {
        'raw': mobi,
        'formatted': _formatMobi(mobi),
      },
      type_: 'identity/mobi@v1',
    );

    // fingerprint - First 8 chars of hex pubkey
    _cache['/fingerprint'] = Scroll(
      key: '/fingerprint',
      data: {'fingerprint': hexPubkey.substring(0, 8)},
      type_: 'identity/fingerprint@v1',
    );
  }

  // Simple hash function (placeholder - use proper crypto in production)
  Uint8List _hashBytes(Uint8List input) {
    var hash = 0x811c9dc5;
    for (final byte in input) {
      hash ^= byte;
      hash = (hash * 0x01000193) & 0xffffffff;
    }
    final result = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      result[i] = (hash >> (i % 4) * 8) & 0xff;
      hash = (hash * 31 + i) & 0xffffffff;
    }
    return result;
  }

  // Simplified bech32 encoding (placeholder)
  String _toBech32(String hrp, Uint8List data) {
    // In production, use proper bech32 encoding
    return '$hrp${hex.encode(data.sublist(0, 32))}';
  }

  String _deriveMobinumber(Uint8List pubkey) {
    final hash = pubkey.fold<int>(0, (prev, byte) => (prev * 31 + byte) % 1000000000000);
    return hash.toString().padLeft(12, '0');
  }

  String _formatMobi(String raw) {
    if (raw.length != 12) return raw;
    return '${raw.substring(0, 3)}-${raw.substring(3, 6)}-${raw.substring(6, 9)}-${raw.substring(9, 12)}';
  }

  // ==========================================================================
  // Namespace Implementation
  // ==========================================================================

  @override
  Result<Scroll?> read(String path) {
    if (_closed) return const Err(ClosedError());

    final scroll = _cache[path];
    return Ok(scroll);
  }

  @override
  Result<Scroll> write(String path, Map<String, dynamic> data) {
    // Identity is read-only - derived from seed
    return const Err(InternalError('Identity namespace is read-only'));
  }

  @override
  Result<Scroll> writeScroll(Scroll scroll) {
    return const Err(InternalError('Identity namespace is read-only'));
  }

  @override
  Result<List<String>> list(String prefix) {
    if (_closed) return const Err(ClosedError());

    final paths = _cache.keys
        .where((k) => isPathUnderPrefix(k, prefix))
        .toList();
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
    _closed = true;
    for (final watcher in _watchers) {
      watcher.controller.close();
    }
    _watchers.clear();
    return const Ok(null);
  }
}

class _Watcher {
  final String pattern;
  final StreamController<Scroll> controller;

  _Watcher({required this.pattern, required this.controller});
}
