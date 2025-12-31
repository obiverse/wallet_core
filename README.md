# Wallet Core - Sovereign Wallet Layer 1

**Bitcoin + Lightning + Vault + Identity via 9S Protocol**

Wallet Core is the sovereign wallet layer that combines Bitcoin, Lightning, encrypted storage, and cryptographic identity—all unified through the 9S namespace abstraction.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ wallet_core                                                     │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ nine_s      │  │ Breez SDK   │  │ cryptography            │  │
│  │ (re-export) │  │ (wrapped)   │  │ (vault encryption)      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│                                                                 │
│  Namespaces:                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ /wallet/*   → WalletNamespace (Breez SDK)               │   │
│  │ /vault/*    → VaultNamespace (encrypted storage)        │   │
│  │ /identity/* → IdentityNamespace (seed-derived)          │   │
│  │ /onboard/*  → OnboardNamespace (state machine)          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Keys & Identity:                                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ MasterKey   → BIP-39/84/NIP-06 derivation               │   │
│  │ NostrSigner → Schnorr signing, NIP-44 encryption        │   │
│  │ WireGuard   → Curve25519 VPN keys                       │   │
│  │ Mobi        → 12-digit human-readable identifier        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

```dart
import 'package:wallet_core/wallet_core.dart';

void main() async {
  // Everything from nine_s is available
  final kernel = Kernel();

  // Create master key from mnemonic
  final master = MasterKey.fromMnemonic('abandon abandon ... about');
  print('Mobi: ${master.mobi.formatDisplay()}');
  print('Nostr: ${master.npub}');

  // Mount wallet namespaces
  final walletCore = await WalletCore.fromMnemonic(
    mnemonic: master.mnemonic,
    dataDir: '/path/to/data',
    network: 'mainnet',
  );

  kernel.mount('/wallet', walletCore.wallet);
  kernel.mount('/vault', walletCore.vault);
  kernel.mount('/identity', walletCore.identity);

  // Use via kernel
  kernel.write('/wallet/send', {'to': 'bc1q...', 'amount': 50000});
  kernel.read('/identity/npub');
  kernel.write('/vault/notes/secret', {'content': 'encrypted'});
}
```

## Namespaces

### WalletNamespace (`/wallet/*`)

Bitcoin + Lightning operations via Breez SDK.

```dart
// Balance
final balance = kernel.read('/wallet/balance');
print('Confirmed: ${balance.value?.data['confirmed']} sats');

// Send
kernel.write('/wallet/send', {
  'to': 'bc1q...',
  'amount': 50000,
  'feeRate': 5.0,
});

// Receive
final address = kernel.read('/wallet/receive');
print('Address: ${address.value?.data['address']}');
```

### VaultNamespace (`/vault/*`)

Transparent encryption layer using XChaCha20-Poly1305.

```dart
// Create vault wrapping file storage
final inner = FileNamespace('/path/to/vault');
final vault = VaultNamespace(inner);

// Initialize with passphrase
await vault.init('my passphrase');

// Use like any namespace (data encrypted at rest)
await vault.writeAsync('/notes/secret', {'content': 'private data'});
final note = await vault.readAsync('/notes/secret');

// Lock when done (zeroizes key)
vault.lock();
```

**Security Model:**
- Passphrase → Argon2id → 32-byte key (GPU-resistant)
- Key + plaintext → XChaCha20-Poly1305 → sealed
- Key zeroized on lock

### IdentityNamespace (`/identity/*`)

Deterministic identity derivation from wallet seed.

| Path | Data |
|------|------|
| `/npub` | Nostr public key (bech32) |
| `/hex` | Raw hex public key |
| `/mobi` | Mobinumber (12-digit identifier) |
| `/fingerprint` | Key fingerprint |
| `/nsec` | Private key (secure export) |

```dart
final identity = IdentityNamespace.fromSeed(seed);
final npub = identity.read('/npub');
final mobi = identity.read('/mobi');
print('Mobi: ${mobi.value?.data['formatted']}');  // 650-073-047-435
```

### OnboardNamespace (`/onboard/*`)

State machine for wallet creation/restoration flow.

```
welcome → generate → reveal → quiz → pin → confirm → sealing → identity
      └→ restore ─────────────────────┘
```

```dart
final onboard = OnboardNamespace(onSeal: (mnemonic, pin) async {
  // Create wallet with mnemonic and PIN
  return mobinumber;
});

// Generate new wallet
onboard.write('/generate', {});

// Or restore existing
onboard.write('/state', {'step': 'restore', 'isRestore': true});
onboard.write('/restore', {'words': ['abandon', 'abandon', ...]});

// Set PIN
onboard.write('/pin', {'digit': '1'});

// Watch state changes
onboard.watch('/*').value.listen((scroll) {
  print('Step: ${scroll.data['step']}');
});
```

## Key Derivation

### MasterKey

Unified key derivation from BIP-39 mnemonic.

```dart
final master = MasterKey.fromMnemonic(mnemonic);

// Bitcoin (BIP-84 Native SegWit)
final btcXprv = master.bitcoinXprv;

// Nostr (NIP-06)
final npub = master.npub;
final nsec = master.nsec;

// Mobinumber (from pubkey hash)
final mobi = master.mobi;
print(mobi.formatDisplay());  // 650-073-047-435

// WireGuard (Curve25519)
final wg = master.wireguard;
print('Private: ${wg.privateKey}');
print('Public: ${wg.publicKey}');
```

### Mobinumber

12-digit human-readable identifier derived from public key.

```dart
final mobi = Mobi.fromBytes(pubkeyBytes);
print(mobi.display);         // 650073047435
print(mobi.formatDisplay()); // 650-073-047-435
print(mobi.full);            // 650-073-047-435-XX (with checksum)
```

### NostrSigner

Schnorr signing and NIP-44 encryption.

```dart
final signer = NostrSigner.fromSeed(seed);

// Sign event
final sig = signer.sign(eventHash);

// NIP-44 encrypt
final ciphertext = signer.encrypt(plaintext, recipientPubkey);
final plaintext = signer.decrypt(ciphertext, senderPubkey);
```

## Layer Integration

Wallet Core sits between the 9S protocol (Layer 0) and application (Layer 2):

```
┌─────────────────────────────────────────┐
│ Layer 2: BeeWallet (Flutter App)        │
│   Scroll.invoke('/wallet/send', {...})  │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│ Layer 1: wallet_core                    │
│   WalletNamespace, VaultNamespace, ...  │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│ Layer 0: nine_s                         │
│   Kernel, Namespace, Scroll, Result     │
└─────────────────────────────────────────┘
```

## Testing

```bash
flutter test           # Run all 78 tests
flutter analyze        # Zero issues
```

## Dependencies

- **nine_s**: Universal data protocol (re-exported)
- **bip39/bip32**: HD wallet derivation
- **bip340**: Schnorr signatures (secp256k1)
- **nostr**: NIP encoding (bech32)
- **cryptography**: XChaCha20-Poly1305, Argon2

## License

MIT OR Apache-2.0
