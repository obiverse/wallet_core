/// WalletCore - Orchestrates wallet namespaces
///
/// Initializes and manages all wallet-related namespaces:
/// - WalletNamespace (Bitcoin + Lightning via Breez SDK)
/// - Store (Encrypted vault from nine_s)
/// - IdentityNamespace (Seed-derived identity)
///
/// Also provides access to key derivation utilities:
/// - MasterKey for all derived keys
/// - NostrSigner for signing and encryption
/// - WireGuardKeys for VPN connectivity
/// - Mobi for human-readable identity
library;

import 'package:nine_s/nine_s.dart';

import 'wallet_namespace.dart';
import 'identity_namespace.dart';
import 'master_key.dart';
import 'nostr_signer.dart';
import 'wireguard_keys.dart';

/// WalletCore - Layer 0 for sovereign wallets
///
/// Provides pre-configured namespaces for:
/// - Bitcoin/Lightning wallet
/// - Encrypted vault storage
/// - Seed-derived identity
///
/// And key derivation utilities for:
/// - Nostr signing and encryption
/// - WireGuard VPN keys
/// - Mobi identifier
class WalletCore {
  /// The wallet namespace (Breez SDK)
  final WalletNamespace wallet;

  /// The vault namespace (encrypted Store)
  final Store vault;

  /// The identity namespace
  final IdentityNamespace identity;

  /// Master key with all derived keys
  final MasterKey master;

  /// Nostr signer for events and encryption
  final NostrSigner nostr;

  /// WireGuard keys for VPN
  final WireGuardKeys? wireGuard;

  WalletCore._({
    required this.wallet,
    required this.vault,
    required this.identity,
    required this.master,
    required this.nostr,
    this.wireGuard,
  });

  /// Initialize WalletCore with a mnemonic
  ///
  /// Creates all namespaces ready to be mounted on a Kernel.
  ///
  /// ```dart
  /// final core = await WalletCore.fromMnemonic(
  ///   mnemonic: 'abandon abandon ... about',
  ///   dataDir: '/path/to/app/data',
  ///   network: 'testnet',
  ///   breezApiKey: 'your-api-key',
  /// );
  ///
  /// kernel.mount('/wallet', core.wallet);
  /// kernel.mount('/vault', core.vault);
  /// kernel.mount('/identity', core.identity);
  ///
  /// // Access derived keys
  /// print('Mobi: ${core.master.mobiDisplay}');
  /// print('Nostr: ${core.master.npub}');
  /// ```
  static Future<WalletCore> fromMnemonic({
    required String mnemonic,
    required String dataDir,
    required String network, // 'mainnet' or 'testnet'
    String? breezApiKey,
    bool deriveWireGuard = false,
  }) async {
    // Create master key (validates mnemonic internally)
    final master = MasterKey.fromMnemonic(mnemonic, network: network);

    // Create encrypted vault
    final vault = await Store.open('$dataDir/vault', master.seedKey32);

    // Create identity namespace
    final identity = IdentityNamespace.fromSeed(master.seed);

    // Create wallet namespace
    final wallet = WalletNamespace(
      mnemonic: mnemonic,
      dataDir: '$dataDir/wallet',
      network: network,
      apiKey: breezApiKey,
    );

    // Create nostr signer
    final nostr = NostrSigner.fromMasterKey(master);

    // Optionally derive WireGuard keys
    WireGuardKeys? wireGuard;
    if (deriveWireGuard) {
      wireGuard = await WireGuardKeys.fromMasterKey(master);
    }

    return WalletCore._(
      wallet: wallet,
      vault: vault,
      identity: identity,
      master: master,
      nostr: nostr,
      wireGuard: wireGuard,
    );
  }

  /// Generate a new wallet with fresh mnemonic
  ///
  /// Returns both the WalletCore and the mnemonic (for backup).
  ///
  /// ```dart
  /// final (core, mnemonic) = await WalletCore.generate(
  ///   dataDir: '/path/to/data',
  ///   network: 'testnet',
  /// );
  ///
  /// // IMPORTANT: User must backup the mnemonic!
  /// print('Backup these words: $mnemonic');
  /// ```
  static Future<(WalletCore, String)> generate({
    required String dataDir,
    required String network,
    String? breezApiKey,
    int strength = 256, // 24 words
    bool deriveWireGuard = false,
  }) async {
    final master = MasterKey.generate(strength: strength, network: network);

    final core = await fromMnemonic(
      mnemonic: master.mnemonic,
      dataDir: dataDir,
      network: network,
      breezApiKey: breezApiKey,
      deriveWireGuard: deriveWireGuard,
    );

    return (core, master.mnemonic);
  }

  // ===========================================================================
  // CONVENIENCE ACCESSORS
  // ===========================================================================

  /// Mobi identifier in display format (XXX-XXX-XXX-XXX)
  String get mobiDisplay => master.mobiDisplay;

  /// Mobi identifier full (21 digits)
  String get mobiFull => master.mobiFull;

  /// Nostr public key in bech32 (npub1...)
  String get npub => master.npub;

  /// Nostr public key as hex
  String get nostrPubkeyHex => master.nostrPublicKeyHex;

  /// Bitcoin extended public key
  String get bitcoinXpub => master.bitcoinXpub;

  // ===========================================================================
  // LIFECYCLE
  // ===========================================================================

  /// Close all namespaces and clear sensitive data
  void close() {
    wallet.close();
    vault.close();
    identity.close();
    master.zeroize();
    nostr.zeroize();
    wireGuard?.zeroize();
  }
}
