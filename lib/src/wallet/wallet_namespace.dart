/// WalletNamespace - Bitcoin + Lightning as 9S Namespace
///
/// Wraps Breez SDK Liquid to provide all wallet operations via 9S paths.
///
/// ## Read Paths
///
/// | Path | Description |
/// |------|-------------|
/// | `/status` | Connection status (always works) |
/// | `/balance` | Wallet balance (confirmed, pending) |
/// | `/address` | Get receive address |
/// | `/network` | Get network (testnet/mainnet) |
/// | `/transactions` | List recent transactions |
/// | `/transactions/{id}` | Get specific transaction |
/// | `/limits/lightning` | Lightning payment limits |
/// | `/limits/onchain` | On-chain payment limits |
/// | `/fiat/rates` | Fiat exchange rates |
/// | `/fees/recommended` | Recommended fee rates |
/// | `/pubkey` | Wallet public key |
///
/// ## Write Paths
///
/// | Path | Description |
/// |------|-------------|
/// | `/send` | Send to BTC address or Lightning invoice |
/// | `/invoice` | Create Lightning invoice |
/// | `/parse` | Parse any input (BOLT11, address, LNURL) |
/// | `/receive/prepare` | Prepare to receive (get fee estimate) |
/// | `/receive/execute` | Execute prepared receive |
/// | `/fee-estimate` | Estimate fee for transaction |
/// | `/sync` | Force wallet sync |
///
/// ## Philosophy
///
/// The wallet is just another namespace. All operations flow through
/// the five frozen operations: read, write, list, watch, close.
library;

import 'dart:async';

import 'package:nine_s/nine_s.dart';
import 'package:flutter_breez_liquid/flutter_breez_liquid.dart';

/// WalletNamespace - Bitcoin + Lightning via Breez SDK
class WalletNamespace implements Namespace {
  final String mnemonic;
  final String dataDir;
  final String network;
  final String? apiKey;

  BreezSdkLiquid? _sdk;
  bool _closed = false;
  bool _connecting = false;
  final List<_Watcher> _watchers = [];

  /// Cache for prepared receive responses
  final Map<String, PrepareReceiveResponse> _prepareReceiveCache = {};

  /// Dispatch table for read operations (SICP-style data-directed programming)
  late final Map<String, Future<Scroll?> Function()> _readHandlers;

  /// Dispatch table for write operations
  late final Map<String, Future<NineResult<Scroll>> Function(Map<String, dynamic>)> _writeHandlers;

  WalletNamespace({
    required this.mnemonic,
    required this.dataDir,
    required this.network,
    this.apiKey,
  }) {
    _initDispatchTables();
  }

  /// Initialize dispatch tables - SICP pattern: data-directed programming
  /// Like DNS, we lookup the handler by path prefix
  void _initDispatchTables() {
    _readHandlers = {
      '/status': () async => Scroll(
            key: '/status',
            data: {'connected': _sdk != null, 'connecting': _connecting, 'network': network},
            type_: 'wallet/status@v1',
          ),
      '/network': () async => Scroll(
            key: '/network',
            data: {'network': network},
            type_: 'wallet/network@v1',
          ),
      '/balance': _readBalance,
      '/address': _readAddress,
      '/pubkey': _readPubkey,
      '/transactions': _readTransactions,
      '/limits/lightning': _readLimitsLightning,
      '/limits/onchain': _readLimitsOnchain,
      '/fiat/rates': _readFiatRates,
      '/fees/recommended': _readRecommendedFees,
      '/refundables': _readRefundables,
    };

    _writeHandlers = {
      '/send': _handleSend,
      '/invoice': _handleInvoice,
      '/parse': _handleParse,
      '/receive/prepare': _handleReceivePrepare,
      '/receive/execute': _handleReceiveExecute,
      '/fee-estimate': _handleFeeEstimate,
      '/sync': (_) => _handleSync(),
      '/refresh': (_) => _handleRefresh(),
      '/disconnect': (_) => _handleDisconnect(),
      '/lnurl-pay': _handleLnurlPay,
      '/lnurl-pay/prepare': _handleLnurlPayPrepare,
      '/lnurl-withdraw': _handleLnurlWithdraw,
      '/lnurl-auth': _handleLnurlAuth,
      '/refund/prepare': _handleRefundPrepare,
      '/refund': _handleRefund,
      '/bolt12/offer': _handleBolt12Offer,
    };
  }

  /// Check if connected
  bool get isConnected => _sdk != null;

  /// Ensure SDK is connected
  Future<BreezSdkLiquid> _ensureConnected() async {
    if (_sdk != null) return _sdk!;
    if (_connecting) {
      while (_connecting) {
        await Future.delayed(const Duration(milliseconds: 100));
      }
      if (_sdk != null) return _sdk!;
    }

    _connecting = true;
    try {
      final liquidNetwork = network == 'mainnet'
          ? LiquidNetwork.mainnet
          : LiquidNetwork.testnet;

      final config = await defaultConfig(
        network: liquidNetwork,
        breezApiKey: apiKey,
      );

      // Create updated config with custom workingDir
      final updatedConfig = Config(
        liquidExplorer: config.liquidExplorer,
        bitcoinExplorer: config.bitcoinExplorer,
        workingDir: dataDir,
        network: config.network,
        paymentTimeoutSec: config.paymentTimeoutSec,
        syncServiceUrl: config.syncServiceUrl,
        breezApiKey: config.breezApiKey,
        zeroConfMaxAmountSat: config.zeroConfMaxAmountSat,
        useDefaultExternalInputParsers: config.useDefaultExternalInputParsers,
        externalInputParsers: config.externalInputParsers,
        onchainFeeRateLeewaySat: config.onchainFeeRateLeewaySat,
        assetMetadata: config.assetMetadata,
        sideswapApiKey: config.sideswapApiKey,
        useMagicRoutingHints: config.useMagicRoutingHints,
        onchainSyncPeriodSec: config.onchainSyncPeriodSec,
        onchainSyncRequestTimeoutSec: config.onchainSyncRequestTimeoutSec,
      );

      _sdk = await connect(
        req: ConnectRequest(
          config: updatedConfig,
          mnemonic: mnemonic,
        ),
      );

      return _sdk!;
    } finally {
      _connecting = false;
    }
  }

  // ==========================================================================
  // Namespace Implementation
  // ==========================================================================

  @override
  NineResult<Scroll?> read(String path) {
    if (_closed) return const Err(ClosedError());

    // Sync read - only status works synchronously
    switch (path) {
      case '/status':
        return Ok(Scroll(
          key: '/status',
          data: {
            'connected': _sdk != null,
            'connecting': _connecting,
            'network': network,
          },
          type_: 'wallet/status@v1',
        ));
      case '/network':
        return Ok(Scroll(
          key: '/network',
          data: {'network': network},
          type_: 'wallet/network@v1',
        ));
      default:
        // Other paths require async - return null for sync read
        return const Ok(null);
    }
  }

  /// Async read for use with invokeAsync pattern
  /// Uses dispatch table for O(1) lookup (SICP data-directed programming)
  Future<Scroll?> readAsync(String path) async {
    if (_closed) return null;

    try {
      // Direct lookup in dispatch table
      final handler = _readHandlers[path];
      if (handler != null) {
        return await handler();
      }

      // Pattern matching for parameterized paths (e.g., /transactions/{id})
      if (path.startsWith('/transactions/')) {
        return await _readTransactionById(path);
      }

      return null;
    } catch (e) {
      return Scroll(
        key: path,
        data: {'error': e.toString()},
        type_: 'error/read@v1',
      );
    }
  }

  // ===========================================================================
  // READ HANDLERS (extracted for dispatch table)
  // ===========================================================================

  Future<Scroll?> _readBalance() async {
    final sdk = await _ensureConnected();
    final info = await sdk.getInfo();
    final assets = info.walletInfo.assetBalances
        .map((a) => {
              'assetId': a.assetId,
              'name': a.name,
              'ticker': a.ticker,
              'balance': a.balanceSat.toInt(),
            })
        .toList();
    return Scroll(
      key: '/balance',
      data: {
        'confirmed': info.walletInfo.balanceSat.toInt(),
        'pending': info.walletInfo.pendingReceiveSat.toInt(),
        'pendingSend': info.walletInfo.pendingSendSat.toInt(),
        'assets': assets,
      },
      type_: 'wallet/balance@v1',
    );
  }

  Future<Scroll?> _readAddress() async {
    final sdk = await _ensureConnected();
    final prepare = await sdk.prepareReceivePayment(
      req: PrepareReceiveRequest(paymentMethod: PaymentMethod.bitcoinAddress),
    );
    final receive = await sdk.receivePayment(
      req: ReceivePaymentRequest(prepareResponse: prepare),
    );
    return Scroll(
      key: '/address',
      data: {'address': receive.destination},
      type_: 'wallet/address@v1',
    );
  }

  Future<Scroll?> _readPubkey() async {
    final sdk = await _ensureConnected();
    final info = await sdk.getInfo();
    return Scroll(
      key: '/pubkey',
      data: {'pubkey': info.walletInfo.pubkey},
      type_: 'wallet/pubkey@v1',
    );
  }

  Future<Scroll?> _readTransactions() async {
    final sdk = await _ensureConnected();
    final payments = await sdk.listPayments(req: ListPaymentsRequest());
    return Scroll(
      key: '/transactions',
      data: {
        'children': payments.map((p) => '/transactions/${p.txId ?? _getSwapId(p)}').toList(),
        'count': payments.length,
      },
      type_: 'wallet/transactions@v1',
    );
  }

  Future<Scroll?> _readTransactionById(String path) async {
    final id = path.substring('/transactions/'.length);
    final sdk = await _ensureConnected();
    final payments = await sdk.listPayments(req: ListPaymentsRequest());
    final payment = payments.where((p) => p.txId == id || _getSwapId(p) == id).firstOrNull;
    if (payment != null) {
      return Scroll(key: path, data: _paymentToMap(payment), type_: 'wallet/transaction@v1');
    }
    return null;
  }

  Future<Scroll?> _readLimitsLightning() async {
    final sdk = await _ensureConnected();
    final limits = await sdk.fetchLightningLimits();
    return Scroll(
      key: '/limits/lightning',
      data: {
        'receive': {'minSat': limits.receive.minSat.toInt(), 'maxSat': limits.receive.maxSat.toInt()},
        'send': {'minSat': limits.send.minSat.toInt(), 'maxSat': limits.send.maxSat.toInt()},
      },
      type_: 'wallet/limits@v1',
    );
  }

  Future<Scroll?> _readLimitsOnchain() async {
    final sdk = await _ensureConnected();
    final limits = await sdk.fetchOnchainLimits();
    return Scroll(
      key: '/limits/onchain',
      data: {
        'receive': {'minSat': limits.receive.minSat.toInt(), 'maxSat': limits.receive.maxSat.toInt()},
        'send': {'minSat': limits.send.minSat.toInt(), 'maxSat': limits.send.maxSat.toInt()},
      },
      type_: 'wallet/limits@v1',
    );
  }

  Future<Scroll?> _readFiatRates() async {
    final sdk = await _ensureConnected();
    final rates = await sdk.fetchFiatRates();
    return Scroll(
      key: '/fiat/rates',
      data: {'rates': rates.map((r) => {'coin': r.coin, 'value': r.value}).toList()},
      type_: 'wallet/fiat@v1',
    );
  }

  Future<Scroll?> _readRecommendedFees() async {
    final sdk = await _ensureConnected();
    final fees = await sdk.recommendedFees();
    return Scroll(
      key: '/fees/recommended',
      data: {
        'fastestFee': fees.fastestFee.toInt(),
        'halfHourFee': fees.halfHourFee.toInt(),
        'hourFee': fees.hourFee.toInt(),
        'economyFee': fees.economyFee.toInt(),
        'minimumFee': fees.minimumFee.toInt(),
      },
      type_: 'wallet/fees@v1',
    );
  }

  Future<Scroll?> _readRefundables() async {
    final sdk = await _ensureConnected();
    final refundables = await sdk.listRefundables();
    return Scroll(
      key: '/refundables',
      data: {
        'refundables': refundables
            .map((r) => {'swapAddress': r.swapAddress, 'amountSat': r.amountSat.toInt(), 'timestamp': r.timestamp})
            .toList(),
        'count': refundables.length,
      },
      type_: 'wallet/refundables@v1',
    );
  }

  /// Extract swapId from PaymentDetails (varies by type)
  String? _getSwapId(Payment payment) {
    final details = payment.details;
    return switch (details) {
      PaymentDetails_Lightning(:final swapId) => swapId,
      PaymentDetails_Bitcoin(:final swapId) => swapId,
      PaymentDetails_Liquid() => null,
    };
  }

  /// Extract description from PaymentDetails (varies by type)
  String _getDescription(Payment payment) {
    final details = payment.details;
    return switch (details) {
      PaymentDetails_Lightning(:final description) => description,
      PaymentDetails_Bitcoin(:final description) => description,
      PaymentDetails_Liquid(:final description) => description,
    };
  }

  Map<String, dynamic> _paymentToMap(Payment payment) {
    final isReceive = payment.paymentType == PaymentType.receive;
    return {
      'txid': payment.txId ?? '',
      'swapId': _getSwapId(payment) ?? '',
      'amount': payment.amountSat.toInt(),
      'fee': payment.feesSat.toInt(),
      'type': isReceive ? 'receive' : 'send',
      'status': payment.status.name,
      'timestamp': payment.timestamp,
      'description': _getDescription(payment),
    };
  }

  @override
  NineResult<Scroll> write(String path, Map<String, dynamic> data) {
    if (_closed) return const Err(ClosedError());
    return Err(InternalError('Use writeAsync for wallet operations'));
  }

  /// Async write for wallet operations
  /// Uses dispatch table for O(1) lookup (SICP data-directed programming)
  Future<NineResult<Scroll>> writeAsync(String path, Map<String, dynamic> data) async {
    if (_closed) return const Err(ClosedError());

    try {
      // Direct lookup in dispatch table
      final handler = _writeHandlers[path];
      if (handler != null) {
        return await handler(data);
      }
      return Err(NotFoundError('Unknown path: $path'));
    } catch (e) {
      return Err(InternalError(e.toString()));
    }
  }

  Future<NineResult<Scroll>> _handleSend(Map<String, dynamic> data) async {
    final to = data['to'] as String?;
    final amount = data['amount'] as int?;

    if (to == null) {
      return const Err(InternalError('Missing "to" field'));
    }

    final sdk = await _ensureConnected();

    final prepare = await sdk.prepareSendPayment(
      req: PrepareSendRequest(
        destination: to,
        amount: amount != null
            ? PayAmount_Bitcoin(receiverAmountSat: BigInt.from(amount))
            : null,
      ),
    );

    final response = await sdk.sendPayment(
      req: SendPaymentRequest(prepareResponse: prepare),
    );

    final scroll = Scroll(
      key: '/send',
      data: {
        'txid': response.payment.txId ?? '',
        'swapId': _getSwapId(response.payment) ?? '',
        'status': response.payment.status.name,
        'amount': response.payment.amountSat.toInt(),
        'fee': response.payment.feesSat.toInt(),
      },
      type_: 'wallet/send@v1',
    );

    _notifyWatchers(scroll);
    return Ok(scroll);
  }

  Future<NineResult<Scroll>> _handleInvoice(Map<String, dynamic> data) async {
    final amount = data['amount'] as int?;
    final description = data['description'] as String?;

    if (amount == null || amount <= 0) {
      return const Err(InternalError('Invalid amount'));
    }

    final sdk = await _ensureConnected();

    final prepare = await sdk.prepareReceivePayment(
      req: PrepareReceiveRequest(
        paymentMethod: PaymentMethod.bolt11Invoice,
        amount: ReceiveAmount_Bitcoin(payerAmountSat: BigInt.from(amount)),
      ),
    );

    final receive = await sdk.receivePayment(
      req: ReceivePaymentRequest(
        prepareResponse: prepare,
        description: description,
      ),
    );

    return Ok(Scroll(
      key: '/invoice',
      data: {
        'bolt11': receive.destination,
        'amount': amount,
        'fee': prepare.feesSat.toInt(),
      },
      type_: 'wallet/invoice@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleParse(Map<String, dynamic> data) async {
    final input = data['input'] as String?;

    if (input == null || input.isEmpty) {
      return const Err(InternalError('Missing "input" field'));
    }

    final sdk = await _ensureConnected();
    final parsed = await sdk.parse(input: input);

    return Ok(Scroll(
      key: '/parse',
      data: _inputTypeToMap(parsed),
      type_: 'wallet/parse@v1',
    ));
  }

  Map<String, dynamic> _inputTypeToMap(InputType input) {
    return switch (input) {
      InputType_BitcoinAddress(:final address) => {
          'type': 'bitcoinAddress',
          'address': address.address,
          'network': address.network.name,
          'amount': address.amountSat?.toInt(),
          'label': address.label,
          'message': address.message,
        },
      InputType_LiquidAddress(:final address) => {
          'type': 'liquidAddress',
          'address': address.address,
          'network': address.network.name,
          'amount': address.amountSat?.toInt(),
          'assetId': address.assetId,
        },
      InputType_Bolt11(:final invoice) => {
          'type': 'bolt11',
          'bolt11': invoice.bolt11,
          'payeePubkey': invoice.payeePubkey,
          'amountMsat': invoice.amountMsat?.toInt(),
          'description': invoice.description,
          'expiry': invoice.expiry.toInt(),
        },
      InputType_Bolt12Offer(:final offer) => {
          'type': 'bolt12Offer',
          'offer': offer.offer,
          'description': offer.description,
        },
      InputType_LnUrlPay(:final data) => {
          'type': 'lnurlPay',
          'callback': data.callback,
          'minSendable': data.minSendable.toInt(),
          'maxSendable': data.maxSendable.toInt(),
          'domain': data.domain,
        },
      InputType_LnUrlWithdraw(:final data) => {
          'type': 'lnurlWithdraw',
          'callback': data.callback,
          'minWithdrawable': data.minWithdrawable.toInt(),
          'maxWithdrawable': data.maxWithdrawable.toInt(),
        },
      InputType_LnUrlAuth(:final data) => {
          'type': 'lnurlAuth',
          'domain': data.domain,
        },
      InputType_LnUrlError(:final data) => {
          'type': 'lnurlError',
          'reason': data.reason,
        },
      InputType_NodeId(:final nodeId) => {
          'type': 'nodeId',
          'nodeId': nodeId,
        },
      InputType_Url(:final url) => {
          'type': 'url',
          'url': url,
        },
    };
  }

  Future<NineResult<Scroll>> _handleReceivePrepare(Map<String, dynamic> data) async {
    final amount = data['amount'] as int?;
    final method = data['method'] as String? ?? 'bolt11';

    final paymentMethod = switch (method) {
      'bolt11' => PaymentMethod.bolt11Invoice,
      'bitcoin' => PaymentMethod.bitcoinAddress,
      'liquid' => PaymentMethod.liquidAddress,
      _ => PaymentMethod.bolt11Invoice,
    };

    final sdk = await _ensureConnected();

    final prepare = await sdk.prepareReceivePayment(
      req: PrepareReceiveRequest(
        paymentMethod: paymentMethod,
        amount: amount != null
            ? ReceiveAmount_Bitcoin(payerAmountSat: BigInt.from(amount))
            : null,
      ),
    );

    // Generate unique ID and cache
    final prepareId = DateTime.now().millisecondsSinceEpoch.toString();
    _prepareReceiveCache[prepareId] = prepare;

    return Ok(Scroll(
      key: '/receive/prepare',
      data: {
        'prepareId': prepareId,
        'fee': prepare.feesSat.toInt(),
        'minAmount': prepare.minPayerAmountSat?.toInt(),
        'maxAmount': prepare.maxPayerAmountSat?.toInt(),
      },
      type_: 'wallet/receive/prepare@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleReceiveExecute(Map<String, dynamic> data) async {
    final prepareId = data['prepareId'] as String?;
    final description = data['description'] as String?;

    if (prepareId == null) {
      return const Err(InternalError('Missing "prepareId" field'));
    }

    final prepare = _prepareReceiveCache.remove(prepareId);
    if (prepare == null) {
      return const Err(InternalError('Invalid or expired prepareId'));
    }

    final sdk = await _ensureConnected();

    final receive = await sdk.receivePayment(
      req: ReceivePaymentRequest(
        prepareResponse: prepare,
        description: description,
      ),
    );

    return Ok(Scroll(
      key: '/receive/execute',
      data: {
        'destination': receive.destination,
      },
      type_: 'wallet/receive/execute@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleFeeEstimate(Map<String, dynamic> data) async {
    final to = data['to'] as String?;
    final amount = data['amount'] as int?;

    if (to == null) {
      return const Err(InternalError('Missing "to" field'));
    }

    final sdk = await _ensureConnected();

    final prepare = await sdk.prepareSendPayment(
      req: PrepareSendRequest(
        destination: to,
        amount: amount != null
            ? PayAmount_Bitcoin(receiverAmountSat: BigInt.from(amount))
            : null,
      ),
    );

    return Ok(Scroll(
      key: '/fee-estimate',
      data: {
        'fee': prepare.feesSat?.toInt() ?? 0,
      },
      type_: 'wallet/fee-estimate@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleSync() async {
    final sdk = await _ensureConnected();
    await sdk.sync();

    return Ok(Scroll(
      key: '/sync',
      data: {'synced': true, 'timestamp': DateTime.now().millisecondsSinceEpoch},
      type_: 'wallet/sync@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleRefresh() async {
    final sdk = await _ensureConnected();
    await sdk.sync();
    final info = await sdk.getInfo();

    return Ok(Scroll(
      key: '/refresh',
      data: {
        'balance': info.walletInfo.balanceSat.toInt(),
        'pending': info.walletInfo.pendingReceiveSat.toInt(),
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      },
      type_: 'wallet/refresh@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleDisconnect() async {
    if (_sdk != null) {
      await _sdk!.disconnect();
      _sdk = null;
    }
    return Ok(Scroll(
      key: '/disconnect',
      data: {'disconnected': true},
      type_: 'wallet/disconnect@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleLnurlPay(Map<String, dynamic> data) async {
    final lnurlData = data['data'] as Map<String, dynamic>?;
    final amount = data['amount'] as int?;
    final comment = data['comment'] as String?;

    if (lnurlData == null || amount == null) {
      return const Err(InternalError('Missing "data" or "amount" field'));
    }

    final sdk = await _ensureConnected();

    final prepare = await sdk.prepareLnurlPay(
      req: PrepareLnUrlPayRequest(
        data: LnUrlPayRequestData(
          callback: lnurlData['callback'] as String,
          minSendable: BigInt.from(lnurlData['minSendable'] as int),
          maxSendable: BigInt.from(lnurlData['maxSendable'] as int),
          metadataStr: lnurlData['metadata'] as String? ?? '',
          commentAllowed: lnurlData['commentAllowed'] as int? ?? 0,
          domain: lnurlData['domain'] as String? ?? '',
          allowsNostr: lnurlData['allowsNostr'] as bool? ?? false,
          nostrPubkey: lnurlData['nostrPubkey'] as String?,
          lnAddress: lnurlData['lnAddress'] as String?,
        ),
        amount: PayAmount_Bitcoin(receiverAmountSat: BigInt.from(amount)),
        comment: comment,
      ),
    );

    final response = await sdk.lnurlPay(req: LnUrlPayRequest(prepareResponse: prepare));

    return switch (response) {
      LnUrlPayResult_EndpointSuccess(:final data) => Ok(Scroll(
          key: '/lnurl-pay',
          data: {'type': 'success', 'successAction': data.successAction?.toString()},
          type_: 'wallet/lnurl-pay@v1',
        )),
      LnUrlPayResult_EndpointError(:final data) => Ok(Scroll(
          key: '/lnurl-pay',
          data: {'type': 'error', 'reason': data.reason},
          type_: 'error/lnurl@v1',
        )),
      LnUrlPayResult_PayError(:final data) => Ok(Scroll(
          key: '/lnurl-pay',
          data: {'type': 'payError', 'reason': data.reason},
          type_: 'error/lnurl@v1',
        )),
    };
  }

  Future<NineResult<Scroll>> _handleLnurlPayPrepare(Map<String, dynamic> data) async {
    final lnurlData = data['data'] as Map<String, dynamic>?;
    final amount = data['amount'] as int?;

    if (lnurlData == null || amount == null) {
      return const Err(InternalError('Missing "data" or "amount" field'));
    }

    final sdk = await _ensureConnected();

    final prepare = await sdk.prepareLnurlPay(
      req: PrepareLnUrlPayRequest(
        data: LnUrlPayRequestData(
          callback: lnurlData['callback'] as String,
          minSendable: BigInt.from(lnurlData['minSendable'] as int),
          maxSendable: BigInt.from(lnurlData['maxSendable'] as int),
          metadataStr: lnurlData['metadata'] as String? ?? '',
          commentAllowed: lnurlData['commentAllowed'] as int? ?? 0,
          domain: lnurlData['domain'] as String? ?? '',
          allowsNostr: lnurlData['allowsNostr'] as bool? ?? false,
          nostrPubkey: lnurlData['nostrPubkey'] as String?,
          lnAddress: lnurlData['lnAddress'] as String?,
        ),
        amount: PayAmount_Bitcoin(receiverAmountSat: BigInt.from(amount)),
      ),
    );

    return Ok(Scroll(
      key: '/lnurl-pay/prepare',
      data: {
        'fee': prepare.feesSat.toInt(),
      },
      type_: 'wallet/lnurl-pay/prepare@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleLnurlWithdraw(Map<String, dynamic> data) async {
    final lnurlData = data['data'] as Map<String, dynamic>?;
    final amount = data['amount'] as int?;
    final description = data['description'] as String?;

    if (lnurlData == null || amount == null) {
      return const Err(InternalError('Missing required fields'));
    }

    final sdk = await _ensureConnected();

    final response = await sdk.lnurlWithdraw(
      req: LnUrlWithdrawRequest(
        data: LnUrlWithdrawRequestData(
          callback: lnurlData['callback'] as String,
          k1: lnurlData['k1'] as String,
          defaultDescription: lnurlData['defaultDescription'] as String? ?? '',
          minWithdrawable: BigInt.from(lnurlData['minWithdrawable'] as int),
          maxWithdrawable: BigInt.from(lnurlData['maxWithdrawable'] as int),
        ),
        amountMsat: BigInt.from(amount * 1000),
        description: description,
      ),
    );

    return switch (response) {
      LnUrlWithdrawResult_Ok(:final data) => Ok(Scroll(
          key: '/lnurl-withdraw',
          data: {'type': 'success', 'invoice': data.invoice.bolt11},
          type_: 'wallet/lnurl-withdraw@v1',
        )),
      LnUrlWithdrawResult_Timeout(:final data) => Ok(Scroll(
          key: '/lnurl-withdraw',
          data: {'type': 'timeout', 'invoice': data.invoice.bolt11},
          type_: 'error/timeout@v1',
        )),
      LnUrlWithdrawResult_ErrorStatus(:final data) => Ok(Scroll(
          key: '/lnurl-withdraw',
          data: {'type': 'error', 'reason': data.reason},
          type_: 'error/lnurl@v1',
        )),
    };
  }

  Future<NineResult<Scroll>> _handleLnurlAuth(Map<String, dynamic> data) async {
    final lnurlData = data['data'] as Map<String, dynamic>?;

    if (lnurlData == null) {
      return const Err(InternalError('Missing "data" field'));
    }

    final sdk = await _ensureConnected();

    final response = await sdk.lnurlAuth(
      reqData: LnUrlAuthRequestData(
        k1: lnurlData['k1'] as String,
        domain: lnurlData['domain'] as String? ?? '',
        url: lnurlData['url'] as String? ?? '',
        action: lnurlData['action'] as String?,
      ),
    );

    return switch (response) {
      LnUrlCallbackStatus_Ok() => Ok(Scroll(
          key: '/lnurl-auth',
          data: {'authenticated': true},
          type_: 'wallet/lnurl-auth@v1',
        )),
      LnUrlCallbackStatus_ErrorStatus(:final data) => Ok(Scroll(
          key: '/lnurl-auth',
          data: {'authenticated': false, 'reason': data.reason},
          type_: 'error/lnurl@v1',
        )),
    };
  }

  Future<NineResult<Scroll>> _handleRefundPrepare(Map<String, dynamic> data) async {
    final swapAddress = data['swapAddress'] as String?;
    final toAddress = data['toAddress'] as String?;
    final feeRateSatPerVbyte = data['feeRate'] as int?;

    if (swapAddress == null || toAddress == null) {
      return const Err(InternalError('Missing required fields'));
    }

    final sdk = await _ensureConnected();

    final prepare = await sdk.prepareRefund(
      req: PrepareRefundRequest(
        swapAddress: swapAddress,
        refundAddress: toAddress,
        feeRateSatPerVbyte: feeRateSatPerVbyte ?? 1,
      ),
    );

    return Ok(Scroll(
      key: '/refund/prepare',
      data: {
        'txVsize': prepare.txVsize,
        'txFeeSat': prepare.txFeeSat.toInt(),
        'lastRefundTxId': prepare.lastRefundTxId,
      },
      type_: 'wallet/refund/prepare@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleRefund(Map<String, dynamic> data) async {
    final swapAddress = data['swapAddress'] as String?;
    final toAddress = data['toAddress'] as String?;
    final feeRateSatPerVbyte = data['feeRate'] as int?;

    if (swapAddress == null || toAddress == null) {
      return const Err(InternalError('Missing required fields'));
    }

    final sdk = await _ensureConnected();

    final result = await sdk.refund(
      req: RefundRequest(
        swapAddress: swapAddress,
        refundAddress: toAddress,
        feeRateSatPerVbyte: feeRateSatPerVbyte ?? 1,
      ),
    );

    return Ok(Scroll(
      key: '/refund',
      data: {'refundTxId': result.refundTxId},
      type_: 'wallet/refund@v1',
    ));
  }

  Future<NineResult<Scroll>> _handleBolt12Offer(Map<String, dynamic> data) async {
    final description = data['description'] as String?;

    final sdk = await _ensureConnected();

    final receive = await sdk.receivePayment(
      req: ReceivePaymentRequest(
        prepareResponse: await sdk.prepareReceivePayment(
          req: PrepareReceiveRequest(paymentMethod: PaymentMethod.bolt12Offer),
        ),
        description: description,
      ),
    );

    return Ok(Scroll(
      key: '/bolt12/offer',
      data: {'offer': receive.destination},
      type_: 'wallet/bolt12@v1',
    ));
  }

  @override
  NineResult<Scroll> writeScroll(Scroll scroll) {
    return write(scroll.key, scroll.data);
  }

  @override
  NineResult<List<String>> list(String prefix) {
    if (_closed) return const Err(ClosedError());

    final paths = [
      '/status',
      '/network',
      '/balance',
      '/address',
      '/pubkey',
      '/transactions',
      '/limits/lightning',
      '/limits/onchain',
      '/fiat/rates',
      '/fees/recommended',
    ];

    final matching = paths.where((p) => isPathUnderPrefix(p, prefix)).toList();
    return Ok(matching);
  }

  @override
  NineResult<Stream<Scroll>> watch(String pattern) {
    if (_closed) return const Err(ClosedError());

    final controller = StreamController<Scroll>();
    _watchers.add(_Watcher(pattern: pattern, controller: controller));

    return Ok(controller.stream);
  }

  void _notifyWatchers(Scroll scroll) {
    _watchers.removeWhere((w) => w.controller.isClosed);
    for (final watcher in _watchers) {
      if (pathMatches(scroll.key, watcher.pattern)) {
        watcher.controller.add(scroll);
      }
    }
  }

  @override
  NineResult<void> close() {
    _closed = true;
    _sdk?.disconnect();
    _sdk = null;
    _prepareReceiveCache.clear();

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
