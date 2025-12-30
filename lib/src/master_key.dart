/// MasterKey - Deterministic key derivation from BIP-39 mnemonic
///
/// The universal law: One seed, all keys.
///
/// Derives all wallet keys from a single mnemonic:
/// - Bitcoin keys (BIP-84 for Native SegWit)
/// - Nostr keys (NIP-06) with real Schnorr signatures
/// - Lightning keys (via Breez SDK)
/// - WireGuard keys (Curve25519)
/// - Mobi identifier
///
/// All derivations are deterministic - same mnemonic always yields same keys.
/// Uses battle-tested libraries: bip32, bip39, bip340, nostr, bech32.
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:bip32/bip32.dart' as bip32;
import 'package:bip340/bip340.dart' as bip340;
import 'package:nostr/nostr.dart' as nostr;
import 'package:convert/convert.dart';

import 'mobi.dart';

// =============================================================================
// DERIVATION PATHS (The gravitational constants)
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
/// Custom path for VPN key derivation
const String pathWireGuard = "m/44'/9999'/0'/0/0";

// =============================================================================
// MASTER KEY - The Platonic Form of Identity
// =============================================================================

/// MasterKey - All keys derived from one mnemonic
///
/// The Form: Identity = Derive(Seed, Path)
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
/// // Access derived keys (all real, all interoperable)
/// print('Nostr npub: ${master.npub}');
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

  // Cached derived keys (lazy evaluation)
  bip32.BIP32? _nostrBip32Key;
  String? _nostrPrivateKeyHex;
  String? _nostrPublicKeyHex;
  bip32.BIP32? _bitcoinKey;
  bip32.BIP32? _wireGuardBip32Key;
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

    // Validate using battle-tested bip39
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
  // NOSTR KEYS (NIP-06) - Using bip340 for real Schnorr
  // ===========================================================================

  /// Derive Nostr key at NIP-06 path
  bip32.BIP32 get _nostrKey {
    _nostrBip32Key ??= _root.derivePath(pathNip06);
    return _nostrBip32Key!;
  }

  /// Nostr private key as hex (32 bytes = 64 chars)
  String get nostrPrivateKeyHex {
    if (_nostrPrivateKeyHex == null) {
      final privKey = _nostrKey.privateKey!;
      _nostrPrivateKeyHex = hex.encode(privKey);
    }
    return _nostrPrivateKeyHex!;
  }

  /// Nostr private key (32 bytes)
  Uint8List get nostrPrivateKey => Uint8List.fromList(hex.decode(nostrPrivateKeyHex));

  /// Nostr public key as hex (32 bytes x-only = 64 chars)
  ///
  /// Uses bip340.getPublicKey for REAL secp256k1 derivation.
  String get nostrPublicKeyHex {
    if (_nostrPublicKeyHex == null) {
      // REAL pubkey derivation using battle-tested bip340
      _nostrPublicKeyHex = bip340.getPublicKey(nostrPrivateKeyHex);
    }
    return _nostrPublicKeyHex!;
  }

  /// Nostr public key (32 bytes, x-only)
  Uint8List get nostrPublicKey => Uint8List.fromList(hex.decode(nostrPublicKeyHex));

  /// Nostr public key in bech32 format (npub1...)
  ///
  /// Uses nostr package's battle-tested Nip19 encoding.
  String get npub => nostr.Nip19.encodePubkey(nostrPublicKeyHex);

  /// Nostr private key in bech32 format (nsec1...)
  String get nsec => nostr.Nip19.encodePrivkey(nostrPrivateKeyHex);

  /// Get a Nostr Keychain for signing operations
  nostr.Keychain get nostrKeychain => nostr.Keychain(nostrPrivateKeyHex);

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
  // WIREGUARD KEYS (Curve25519)
  // ===========================================================================

  /// WireGuard private key (32 bytes, Curve25519 clamped)
  Uint8List get wireGuardPrivateKey {
    _wireGuardBip32Key ??= _root.derivePath(pathWireGuard);
    // Clamp the key for Curve25519 (RFC 7748)
    final key = Uint8List.fromList(_wireGuardBip32Key!.privateKey!);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    return key;
  }

  // ===========================================================================
  // MOBI IDENTIFIER
  // ===========================================================================

  /// Mobi identifier derived from Nostr public key
  ///
  /// Now uses REAL public key from bip340.
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
  Uint8List get seed => Uint8List.fromList(_seed);

  /// Get the first 32 bytes of seed (for symmetric encryption keys)
  Uint8List get seedKey32 => Uint8List.fromList(_seed.sublist(0, 32));

  // ===========================================================================
  // SECURITY
  // ===========================================================================

  /// Securely clear all key material from memory
  ///
  /// Call this when done with the MasterKey to minimize exposure.
  void zeroize() {
    _seed.fillRange(0, _seed.length, 0);
    _nostrBip32Key = null;
    _nostrPrivateKeyHex = null;
    _nostrPublicKeyHex = null;
    _bitcoinKey = null;
    _wireGuardBip32Key = null;
    _mobi = null;
  }
}
