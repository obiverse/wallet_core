/// WalletCore - Orchestrates wallet namespaces
///
/// Initializes and manages all wallet-related namespaces:
/// - WalletNamespace (Bitcoin + Lightning via Breez SDK)
/// - Store (Encrypted vault from nine_s)
/// - IdentityNamespace (Seed-derived identity)
library;

import 'dart:typed_data';

import 'package:nine_s/nine_s.dart';
import 'package:bip39/bip39.dart' as bip39;

import 'wallet_namespace.dart';
import 'identity_namespace.dart';

/// WalletCore - Layer 0 for sovereign wallets
///
/// Provides pre-configured namespaces for:
/// - Bitcoin/Lightning wallet
/// - Encrypted vault storage
/// - Seed-derived identity
class WalletCore {
  /// The wallet namespace (Breez SDK)
  final WalletNamespace wallet;

  /// The vault namespace (encrypted Store)
  final Store vault;

  /// The identity namespace
  final IdentityNamespace identity;

  /// Master key derived from mnemonic
  final Uint8List masterKey;

  WalletCore._({
    required this.wallet,
    required this.vault,
    required this.identity,
    required this.masterKey,
  });

  /// Initialize WalletCore with a mnemonic
  ///
  /// Creates all namespaces ready to be mounted on a Kernel.
  ///
  /// ```dart
  /// final core = await WalletCore.fromMnemonic(
  ///   mnemonic: 'abandon abandon ... about',
  ///   dataDir: '/path/to/app/data',
  ///   network: LiquidNetwork.testnet,
  ///   breezApiKey: 'your-api-key',
  /// );
  ///
  /// kernel.mount('/wallet', core.wallet);
  /// kernel.mount('/vault', core.vault);
  /// kernel.mount('/identity', core.identity);
  /// ```
  static Future<WalletCore> fromMnemonic({
    required String mnemonic,
    required String dataDir,
    required String network, // 'mainnet' or 'testnet'
    String? breezApiKey,
  }) async {
    // Validate mnemonic
    if (!bip39.validateMnemonic(mnemonic)) {
      throw ArgumentError('Invalid mnemonic');
    }

    // Derive master key from mnemonic
    final seed = bip39.mnemonicToSeed(mnemonic);
    final masterKey = Uint8List.fromList(seed.sublist(0, 32));

    // Create encrypted vault
    final vault = await Store.open('$dataDir/vault', masterKey);

    // Create identity namespace
    final identity = IdentityNamespace.fromSeed(seed);

    // Create wallet namespace
    final wallet = WalletNamespace(
      mnemonic: mnemonic,
      dataDir: '$dataDir/wallet',
      network: network,
      apiKey: breezApiKey,
    );

    return WalletCore._(
      wallet: wallet,
      vault: vault,
      identity: identity,
      masterKey: masterKey,
    );
  }

  /// Generate a new wallet with fresh mnemonic
  ///
  /// Returns both the WalletCore and the mnemonic (for backup).
  static Future<(WalletCore, String)> generate({
    required String dataDir,
    required String network,
    String? breezApiKey,
    int strength = 256, // 24 words
  }) async {
    final mnemonic = bip39.generateMnemonic(strength: strength);

    final core = await fromMnemonic(
      mnemonic: mnemonic,
      dataDir: dataDir,
      network: network,
      breezApiKey: breezApiKey,
    );

    return (core, mnemonic);
  }

  /// Close all namespaces
  void close() {
    wallet.close();
    vault.close();
    identity.close();
  }
}
