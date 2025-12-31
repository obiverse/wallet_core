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
///
/// Uses battle-tested libraries:
/// - bip32: HD key derivation (NIP-06 path)
/// - bip340: Real secp256k1 public key derivation
/// - nostr: Bech32 encoding (npub)
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:nine_s/nine_s.dart';
import 'package:bip32/bip32.dart' as bip32;
import 'package:bip340/bip340.dart' as bip340;
import 'package:nostr/nostr.dart' as nostr;
import 'package:convert/convert.dart';

import 'mobi.dart';

/// NIP-06 derivation path for Nostr identity
const String _pathNip06 = "m/44'/1237'/0'/0/0";

/// IdentityNamespace - Seed-derived identity
///
/// Implements the 9S Namespace interface for identity operations.
/// All data is derived on-demand from the seed using real secp256k1.
class IdentityNamespace implements Namespace {
  final Uint8List _seed;
  final Map<String, Scroll> _cache = {};
  final List<_Watcher> _watchers = [];
  bool _closed = false;

  /// Derived keys (lazily computed)
  late final String _privateKeyHex;
  late final String _publicKeyHex;

  IdentityNamespace._(this._seed) {
    _deriveKeys();
    _computeIdentities();
  }

  /// Create from BIP-39 seed bytes (64 bytes)
  factory IdentityNamespace.fromSeed(Uint8List seed) {
    if (seed.length < 64) {
      throw ArgumentError('Seed must be at least 64 bytes (BIP-39 seed)');
    }
    return IdentityNamespace._(seed);
  }

  void _deriveKeys() {
    // Create BIP-32 root from seed
    final root = bip32.BIP32.fromSeed(_seed);

    // Derive at NIP-06 path: m/44'/1237'/0'/0/0
    final derived = root.derivePath(_pathNip06);

    // Private key as hex
    _privateKeyHex = hex.encode(derived.privateKey!);

    // Public key using REAL secp256k1 via bip340
    _publicKeyHex = bip340.getPublicKey(_privateKeyHex);
  }

  void _computeIdentities() {
    // npub - Nostr public key in bech32 (using battle-tested nostr package)
    final npub = nostr.Nip19.encodePubkey(_publicKeyHex);
    _cache['/npub'] = Scroll(
      key: '/npub',
      data: {'npub': npub, 'hex': _publicKeyHex},
      type_: 'identity/npub@v1',
    );

    // hex - Raw hex public key
    _cache['/hex'] = Scroll(
      key: '/hex',
      data: {'hex': _publicKeyHex},
      type_: 'identity/hex@v1',
    );

    // mobi - Using proper Mobi derivation from real pubkey
    final pubkeyBytes = Uint8List.fromList(hex.decode(_publicKeyHex));
    final mobi = Mobi.fromBytes(pubkeyBytes);
    _cache['/mobi'] = Scroll(
      key: '/mobi',
      data: {
        'raw': mobi.display,
        'formatted': mobi.formatDisplay(),
        'full': mobi.full,
      },
      type_: 'identity/mobi@v1',
    );

    // fingerprint - First 8 chars of hex pubkey
    _cache['/fingerprint'] = Scroll(
      key: '/fingerprint',
      data: {'fingerprint': _publicKeyHex.substring(0, 8)},
      type_: 'identity/fingerprint@v1',
    );

    // nsec - Private key in bech32 (for secure export)
    final nsec = nostr.Nip19.encodePrivkey(_privateKeyHex);
    _cache['/nsec'] = Scroll(
      key: '/nsec',
      data: {'nsec': nsec},
      type_: 'identity/nsec@v1',
    );
  }

  // ==========================================================================
  // Namespace Implementation
  // ==========================================================================

  @override
  NineResult<Scroll?> read(String path) {
    if (_closed) return const Err(ClosedError());

    final scroll = _cache[path];
    return Ok(scroll);
  }

  @override
  NineResult<Scroll> write(String path, Map<String, dynamic> data) {
    // Identity is read-only - derived from seed
    return const Err(InternalError('Identity namespace is read-only'));
  }

  @override
  NineResult<Scroll> writeScroll(Scroll scroll) {
    return const Err(InternalError('Identity namespace is read-only'));
  }

  @override
  NineResult<List<String>> list(String prefix) {
    if (_closed) return const Err(ClosedError());

    final paths = _cache.keys
        .where((k) => isPathUnderPrefix(k, prefix))
        .toList();
    return Ok(paths);
  }

  @override
  NineResult<Stream<Scroll>> watch(String pattern) {
    if (_closed) return const Err(ClosedError());

    final controller = StreamController<Scroll>();
    _watchers.add(_Watcher(pattern: pattern, controller: controller));

    return Ok(controller.stream);
  }

  @override
  NineResult<void> close() {
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
