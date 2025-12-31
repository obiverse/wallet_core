/// WireGuardKeys - Curve25519 key derivation for WireGuard VPN
///
/// Derives WireGuard keys deterministically from wallet seed,
/// enabling always-on encrypted connectivity without separate key management.
///
/// ## Key Derivation
///
/// 1. Derive at custom BIP-32 path: m/44'/9999'/0'/0/0
/// 2. Apply Curve25519 clamping (RFC 7748)
/// 3. Compute public key via X25519 base point multiplication
///
/// ## WireGuard Format
///
/// Keys are base64-encoded for use in WireGuard config files:
/// ```
/// [Interface]
/// PrivateKey = <base64 private key>
///
/// [Peer]
/// PublicKey = <base64 public key>
/// ```
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cryptography;

import 'master_key.dart';

// =============================================================================
// WIREGUARD KEYS
// =============================================================================

/// WireGuard key pair for VPN connectivity
///
/// Usage:
/// ```dart
/// final keys = await WireGuardKeys.fromMasterKey(masterKey);
///
/// print('Private: ${keys.privateKeyBase64}');
/// print('Public: ${keys.publicKeyBase64}');
///
/// // Generate WireGuard config
/// final config = keys.generateConfig(
///   serverPublicKey: 'server-pubkey-base64',
///   serverEndpoint: 'vpn.example.com:51820',
///   allowedIPs: '0.0.0.0/0',
/// );
/// ```
class WireGuardKeys {
  /// Private key (32 bytes, clamped for Curve25519)
  final Uint8List privateKey;

  /// Public key (32 bytes, X25519)
  final Uint8List publicKey;

  WireGuardKeys._({
    required this.privateKey,
    required this.publicKey,
  });

  /// Create WireGuard keys from MasterKey
  static Future<WireGuardKeys> fromMasterKey(MasterKey masterKey) async {
    final privateKey = masterKey.wireGuardPrivateKey;
    final publicKey = await _derivePublicKey(privateKey);

    return WireGuardKeys._(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  /// Create WireGuard keys from raw seed bytes
  ///
  /// Uses HKDF to derive a proper Curve25519 key from arbitrary seed.
  static Future<WireGuardKeys> fromSeed(Uint8List seed) async {
    // Use HKDF to derive key material
    final algorithm = cryptography.Hkdf(
      hmac: cryptography.Hmac.sha256(),
      outputLength: 32,
    );

    final secretKey = cryptography.SecretKey(seed);
    final derivedKey = await algorithm.deriveKey(
      secretKey: secretKey,
      info: utf8.encode('wireguard-key'),
      nonce: Uint8List(0),
    );

    final privateKey = Uint8List.fromList(await derivedKey.extractBytes());

    // Clamp for Curve25519 (RFC 7748)
    _clampPrivateKey(privateKey);

    final publicKey = await _derivePublicKey(privateKey);

    return WireGuardKeys._(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  /// Create from existing private key (base64)
  static Future<WireGuardKeys> fromPrivateKeyBase64(String privateKeyB64) async {
    final privateKey = Uint8List.fromList(base64.decode(privateKeyB64));
    if (privateKey.length != 32) {
      throw ArgumentError('Private key must be 32 bytes');
    }

    final publicKey = await _derivePublicKey(privateKey);

    return WireGuardKeys._(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  // ===========================================================================
  // KEY FORMATS
  // ===========================================================================

  /// Private key as base64 (WireGuard format)
  String get privateKeyBase64 => base64.encode(privateKey);

  /// Public key as base64 (WireGuard format)
  String get publicKeyBase64 => base64.encode(publicKey);

  /// Private key as hex
  String get privateKeyHex {
    return privateKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Public key as hex
  String get publicKeyHex {
    return publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  // ===========================================================================
  // CONFIG GENERATION
  // ===========================================================================

  /// Generate WireGuard [Interface] config section
  ///
  /// [address]: Client IP address (e.g., "10.0.0.2/32")
  /// [dns]: Optional DNS servers (e.g., "1.1.1.1, 8.8.8.8")
  String generateInterfaceConfig({
    String? address,
    String? dns,
    int? listenPort,
  }) {
    final lines = <String>['[Interface]'];
    lines.add('PrivateKey = $privateKeyBase64');

    if (address != null) {
      lines.add('Address = $address');
    }
    if (dns != null) {
      lines.add('DNS = $dns');
    }
    if (listenPort != null) {
      lines.add('ListenPort = $listenPort');
    }

    return lines.join('\n');
  }

  /// Generate WireGuard [Peer] config section
  ///
  /// [serverPublicKey]: Server's public key (base64)
  /// [serverEndpoint]: Server address (e.g., "vpn.example.com:51820")
  /// [allowedIPs]: Allowed IP ranges (e.g., "0.0.0.0/0" for all traffic)
  /// [persistentKeepalive]: Keepalive interval in seconds
  String generatePeerConfig({
    required String serverPublicKey,
    required String serverEndpoint,
    String allowedIPs = '0.0.0.0/0, ::/0',
    int? persistentKeepalive,
    String? presharedKey,
  }) {
    final lines = <String>['[Peer]'];
    lines.add('PublicKey = $serverPublicKey');
    lines.add('Endpoint = $serverEndpoint');
    lines.add('AllowedIPs = $allowedIPs');

    if (presharedKey != null) {
      lines.add('PresharedKey = $presharedKey');
    }
    if (persistentKeepalive != null) {
      lines.add('PersistentKeepalive = $persistentKeepalive');
    }

    return lines.join('\n');
  }

  /// Generate complete WireGuard config file
  String generateConfig({
    required String serverPublicKey,
    required String serverEndpoint,
    String? clientAddress,
    String? dns,
    String allowedIPs = '0.0.0.0/0, ::/0',
    int? persistentKeepalive,
    String? presharedKey,
  }) {
    final interfaceSection = generateInterfaceConfig(
      address: clientAddress,
      dns: dns,
    );

    final peerSection = generatePeerConfig(
      serverPublicKey: serverPublicKey,
      serverEndpoint: serverEndpoint,
      allowedIPs: allowedIPs,
      persistentKeepalive: persistentKeepalive,
      presharedKey: presharedKey,
    );

    return '$interfaceSection\n\n$peerSection';
  }

  // ===========================================================================
  // INTERNAL
  // ===========================================================================

  /// Clamp private key for Curve25519 (RFC 7748)
  ///
  /// This ensures the key is valid for X25519 operations:
  /// - Clear bits 0, 1, 2 of first byte
  /// - Clear bit 7 of last byte
  /// - Set bit 6 of last byte
  static void _clampPrivateKey(Uint8List key) {
    key[0] &= 248; // Clear bits 0, 1, 2
    key[31] &= 127; // Clear bit 7
    key[31] |= 64; // Set bit 6
  }

  /// Derive public key from private key using X25519
  static Future<Uint8List> _derivePublicKey(Uint8List privateKey) async {
    final algorithm = cryptography.X25519();

    // Create keypair from private key
    final keyPair = await algorithm.newKeyPairFromSeed(privateKey);
    final publicKey = await keyPair.extractPublicKey();

    return Uint8List.fromList(publicKey.bytes);
  }

  // ===========================================================================
  // SECURITY
  // ===========================================================================

  /// Securely clear key material from memory
  void zeroize() {
    privateKey.fillRange(0, privateKey.length, 0);
    publicKey.fillRange(0, publicKey.length, 0);
  }
}

// =============================================================================
// PRESHARED KEY GENERATION
// =============================================================================

/// Generate a random preshared key for additional WireGuard security
///
/// Preshared keys add post-quantum resistance to the handshake.
Future<String> generatePresharedKey() async {
  final algorithm = cryptography.Chacha20.poly1305Aead();
  final secretKey = await algorithm.newSecretKey();
  final bytes = await secretKey.extractBytes();
  return base64.encode(bytes);
}
