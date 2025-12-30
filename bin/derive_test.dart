import 'package:wallet_core/wallet_core.dart';

void main() {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  final master = MasterKey.fromMnemonic(mnemonic);

  print('=== NIP-06 Test Vector (abandon×11 + about) ===');
  print('privkey: ${master.nostrPrivateKeyHex}');
  print('pubkey: ${master.nostrPublicKeyHex}');
  print('npub: ${master.npub}');
  print('nsec: ${master.nsec}');
  print('mobi: ${master.mobi.formatDisplay()}');
  print('mobi_full: ${master.mobi.full}');
  print('xpub: ${master.bitcoinXpub}');
}
