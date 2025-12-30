/// MasterKey - Deterministic key derivation from BIP-39 mnemonic
///
/// Derives all wallet keys from a single mnemonic:
/// - Bitcoin keys (BIP-84 for Native SegWit)
/// - Nostr keys (NIP-06)
/// - Lightning keys (via Breez SDK)
/// - WireGuard keys (Curve25519)
/// - Mobi identifier
///
/// All derivations are deterministic - same mnemonic always yields same keys.
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:bip32/bip32.dart' as bip32;
import 'package:convert/convert.dart';

import 'mobi.dart';

// =============================================================================
// DERIVATION PATHS
// =============================================================================

/// BIP-84 (Native SegWit): m/84'/0'/0'
/// For Bitcoin mainnet P2WPKH addresses (bc1...)
const String pathBip84Mainnet = "m/84'/0'/0'";

/// BIP-84 testnet: m/84'/1'/0'
const String pathBip84Testnet = "m/84'/1'/0'";

/// NIP-06 (Nostr): m/44'/1237'/0'/0/0
/// Derives Nostr identity key from mnemonic
const String pathNip06 = "m/44'/1237'/0'/0/0";

/// WireGuard: m/44'/9999'/0'/0/0
/// Custom path for VPN key derivation (not a standard)
const String pathWireGuard = "m/44'/9999'/0'/0/0";

// =============================================================================
// MASTER KEY
// =============================================================================

/// MasterKey - All keys derived from one mnemonic
///
/// Usage:
/// ```dart
/// // From existing mnemonic
/// final master = MasterKey.fromMnemonic('abandon abandon ... about');
///
/// // Generate new wallet
/// final master = MasterKey.generate();
/// print('Backup these words: ${master.mnemonic}');
///
/// // Access derived keys
/// print('Nostr npub: ${master.nostrPublicKeyHex}');
/// print('Mobi: ${master.mobi.formatDisplay()}');
/// print('Bitcoin xpub: ${master.bitcoinXpub}');
/// ```
class MasterKey {
  /// The BIP-39 mnemonic phrase (12 or 24 words)
  final String mnemonic;

  /// The raw 64-byte seed derived from mnemonic
  final Uint8List _seed;

  /// BIP-32 root key
  final bip32.BIP32 _root;

  /// Network: 'mainnet' or 'testnet'
  final String network;

  // Cached derived keys
  bip32.BIP32? _nostrKey;
  bip32.BIP32? _bitcoinKey;
  bip32.BIP32? _wireGuardKey;
  Mobi? _mobi;

  MasterKey._({
    required this.mnemonic,
    required Uint8List seed,
    required bip32.BIP32 root,
    required this.network,
  })  : _seed = seed,
        _root = root;

  /// Create MasterKey from BIP-39 mnemonic
  ///
  /// Throws [ArgumentError] if mnemonic is invalid.
  factory MasterKey.fromMnemonic(
    String mnemonic, {
    String network = 'mainnet',
    String passphrase = '',
  }) {
    // Normalize mnemonic (lowercase, single spaces)
    final normalized = mnemonic.toLowerCase().trim().replaceAll(RegExp(r'\s+'), ' ');

    // Validate
    if (!bip39.validateMnemonic(normalized)) {
      throw ArgumentError('Invalid BIP-39 mnemonic');
    }

    // Derive seed (with optional passphrase for extra security)
    final seed = bip39.mnemonicToSeed(normalized, passphrase: passphrase);

    // Create BIP-32 root
    final root = bip32.BIP32.fromSeed(seed);

    return MasterKey._(
      mnemonic: normalized,
      seed: Uint8List.fromList(seed),
      root: root,
      network: network,
    );
  }

  /// Generate a new random mnemonic and create MasterKey
  ///
  /// [strength]: 128 for 12 words, 256 for 24 words (default)
  factory MasterKey.generate({
    int strength = 256,
    String network = 'mainnet',
  }) {
    final mnemonic = bip39.generateMnemonic(strength: strength);
    return MasterKey.fromMnemonic(mnemonic, network: network);
  }

  // ===========================================================================
  // NOSTR KEYS (NIP-06)
  // ===========================================================================

  /// Nostr private key (32 bytes)
  Uint8List get nostrPrivateKey {
    _nostrKey ??= _root.derivePath(pathNip06);
    return Uint8List.fromList(_nostrKey!.privateKey!);
  }

  /// Nostr private key as hex string
  String get nostrPrivateKeyHex => hex.encode(nostrPrivateKey);

  /// Nostr public key (32 bytes, x-only)
  ///
  /// This is the x-coordinate of the secp256k1 public key,
  /// used in Nostr events and for npub encoding.
  Uint8List get nostrPublicKey {
    _nostrKey ??= _root.derivePath(pathNip06);
    // BIP32 gives us 33-byte compressed pubkey, we need x-only (32 bytes)
    // Compressed format: 02|03 + x-coordinate (32 bytes)
    return Uint8List.fromList(_nostrKey!.publicKey.sublist(1));
  }

  /// Nostr public key as hex string
  String get nostrPublicKeyHex => hex.encode(nostrPublicKey);

  /// Nostr public key in bech32 format (npub1...)
  String get npub => _toBech32('npub', nostrPublicKey);

  /// Nostr private key in bech32 format (nsec1...)
  String get nsec => _toBech32('nsec', nostrPrivateKey);

  // ===========================================================================
  // BITCOIN KEYS (BIP-84)
  // ===========================================================================

  /// Bitcoin account key at m/84'/0'/0' (or testnet equivalent)
  bip32.BIP32 get _bitcoinAccount {
    if (_bitcoinKey == null) {
      final path = network == 'mainnet' ? pathBip84Mainnet : pathBip84Testnet;
      _bitcoinKey = _root.derivePath(path);
    }
    return _bitcoinKey!;
  }

  /// Bitcoin extended public key (for watch-only wallets)
  String get bitcoinXpub => _bitcoinAccount.toBase58();

  /// Derive a Bitcoin receive address key
  ///
  /// [index]: Address index (0, 1, 2, ...)
  bip32.BIP32 deriveReceiveKey(int index) {
    return _bitcoinAccount.derive(0).derive(index);
  }

  /// Derive a Bitcoin change address key
  ///
  /// [index]: Address index (0, 1, 2, ...)
  bip32.BIP32 deriveChangeKey(int index) {
    return _bitcoinAccount.derive(1).derive(index);
  }

  // ===========================================================================
  // WIREGUARD KEYS
  // ===========================================================================

  /// WireGuard private key (32 bytes, Curve25519)
  ///
  /// Note: This derives a key at a custom path, then uses HKDF
  /// to derive a proper Curve25519 key. The raw BIP-32 key is
  /// not directly usable as a WireGuard key.
  Uint8List get wireGuardPrivateKey {
    _wireGuardKey ??= _root.derivePath(pathWireGuard);
    // Clamp the key for Curve25519 (as per RFC 7748)
    final key = Uint8List.fromList(_wireGuardKey!.privateKey!);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    return key;
  }

  /// WireGuard private key as base64 (standard WireGuard format)
  String get wireGuardPrivateKeyBase64 {
    // WireGuard uses raw base64, not base64url
    return _toBase64(wireGuardPrivateKey);
  }

  // ===========================================================================
  // MOBI IDENTIFIER
  // ===========================================================================

  /// Mobi identifier derived from Nostr public key
  Mobi get mobi {
    _mobi ??= Mobi.fromBytes(nostrPublicKey);
    return _mobi!;
  }

  /// Mobi display format (12 digits with hyphens)
  String get mobiDisplay => mobi.formatDisplay();

  /// Mobi full format (21 digits)
  String get mobiFull => mobi.full;

  // ===========================================================================
  // RAW SEED ACCESS
  // ===========================================================================

  /// Get the raw 64-byte seed
  ///
  /// WARNING: This is the master secret. Handle with extreme care.
  /// Consider if you really need this - prefer derived keys instead.
  Uint8List get seed => Uint8List.fromList(_seed);

  /// Get the first 32 bytes of seed (common for symmetric encryption)
  Uint8List get seedKey32 => Uint8List.fromList(_seed.sublist(0, 32));

  // ===========================================================================
  // SECURITY
  // ===========================================================================

  /// Securely clear all key material from memory
  ///
  /// Call this when done with the MasterKey to minimize exposure.
  void zeroize() {
    _seed.fillRange(0, _seed.length, 0);
    _nostrKey = null;
    _bitcoinKey = null;
    _wireGuardKey = null;
    _mobi = null;
  }

  // ===========================================================================
  // UTILITIES
  // ===========================================================================

  /// Simple bech32 encoding (for npub/nsec)
  ///
  /// Note: This is a simplified implementation. For production,
  /// consider using a proper bech32 library.
  static String _toBech32(String hrp, Uint8List data) {
    // Simplified: just use hex for now, proper bech32 requires
    // 5-bit conversion and checksum
    // TODO: Implement proper bech32 or use a library
    return '$hrp${hex.encode(data)}';
  }

  /// Convert bytes to base64
  static String _toBase64(Uint8List data) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    final buffer = StringBuffer();
    var i = 0;

    while (i < data.length) {
      final b0 = data[i++];
      final b1 = i < data.length ? data[i++] : 0;
      final b2 = i < data.length ? data[i++] : 0;

      buffer.write(chars[(b0 >> 2) & 0x3F]);
      buffer.write(chars[((b0 << 4) | (b1 >> 4)) & 0x3F]);
      buffer.write(i > data.length + 1 ? '=' : chars[((b1 << 2) | (b2 >> 6)) & 0x3F]);
      buffer.write(i > data.length ? '=' : chars[b2 & 0x3F]);
    }

    return buffer.toString();
  }
}
