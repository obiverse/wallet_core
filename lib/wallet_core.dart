/// Wallet Core - Sovereign Wallet Layer 0
///
/// Provides Bitcoin + Lightning + Vault + Identity via 9S Protocol.
///
/// ## Architecture
///
/// ```
/// ┌─────────────────────────────────────────────────────────────┐
/// │ wallet_core                                                 │
/// │                                                             │
/// │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
/// │  │ nine_s      │  │ Breez SDK   │  │ cryptography        │  │
/// │  │ (re-export) │  │ (wrapped)   │  │ (vault encryption)  │  │
/// │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
/// │                                                             │
/// │  Namespaces:                                                │
/// │  ┌─────────────────────────────────────────────────────┐   │
/// │  │ /wallet/*   → WalletNamespace (Breez SDK)           │   │
/// │  │ /vault/*    → Store (encrypted, from nine_s)        │   │
/// │  │ /identity/* → IdentityNamespace (seed-derived)      │   │
/// │  └─────────────────────────────────────────────────────┘   │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// ## Usage
///
/// ```dart
/// import 'package:wallet_core/wallet_core.dart';
///
/// // Everything from nine_s is available
/// final kernel = Kernel();
///
/// // Mount wallet namespaces
/// final walletCore = await WalletCore.initialize(
///   dataDir: '/path/to/data',
///   masterKey: seed,
/// );
///
/// kernel.mount('/wallet', walletCore.wallet);
/// kernel.mount('/vault', walletCore.vault);
/// kernel.mount('/identity', walletCore.identity);
///
/// // Use via kernel
/// kernel.write('/wallet/send', {'to': 'bc1q...', 'amount': 50000});
/// kernel.read('/identity/npub');
/// kernel.write('/vault/notes/secret', {'content': 'encrypted'});
/// ```
library wallet_core;

// Re-export all of nine_s - downstream only needs to import wallet_core
export 'package:nine_s/nine_s.dart';

// Wallet Core namespaces
export 'src/wallet_namespace.dart';
export 'src/identity_namespace.dart';

// Wallet Core orchestrator
export 'src/wallet_core.dart';
