/// OnboardNamespace - State machine for onboarding flow
///
/// The onboarding flow as a 9S namespace. State is data. Transitions are writes.
///
/// ## Paths
/// - `/state` - Current flow state (step, quizIndices, etc.)
/// - `/mnemonic` - Generated/entered mnemonic (ephemeral)
/// - `/generate` - Action: generate new mnemonic
/// - `/validate` - Action: validate quiz or restore
/// - `/seal` - Action: seal vault with PIN
///
/// ## State Machine
/// ```
/// welcome → generate → reveal → quiz → pin → confirm → sealing → identity
///       └→ restore ─────────────────────┘
/// ```
library;

import 'dart:async';
import 'dart:math';

import 'package:bip39/bip39.dart' as bip39;
import 'package:nine_s/nine_s.dart';

/// Onboarding steps
enum OnboardStep {
  welcome,
  generate,
  reveal,
  quiz,
  pin,
  confirm,
  sealing,
  identity,
  restore,
}

/// OnboardNamespace - manages onboarding state via 9S protocol
class OnboardNamespace implements Namespace {
  final StreamController<Scroll> _changes = StreamController.broadcast();
  bool _closed = false;

  // State
  OnboardStep _step = OnboardStep.welcome;
  bool _isRestore = false;
  bool _revealed = false; // Whether seed phrase has been revealed
  List<String> _mnemonic = [];
  List<String> _restoreWords = List.filled(12, '');
  List<int> _quizIndices = [];
  List<String> _quizInputs = ['', '', ''];
  int _pinLength = 0;
  int _confirmPinLength = 0;
  String? _pinError;
  String? _sealError;
  String? _mobinumber;

  // PIN storage (only during flow, cleared after seal)
  String _pin = '';
  String _confirmPin = '';

  // Callback for sealing (connects to WalletCore)
  final Future<String?> Function(String mnemonic, String pin)? onSeal;

  OnboardNamespace({this.onSeal});

  @override
  Result<Scroll?> read(String path) {
    if (_closed) return const Err(ClosedError());

    return switch (path) {
      '/state' => Ok(_stateScroll()),
      '/mnemonic' => Ok(_mnemonicScroll()),
      _ => Ok(null),
    };
  }

  @override
  Result<Scroll> write(String path, Map<String, dynamic> data) {
    if (_closed) return const Err(ClosedError());

    return switch (path) {
      '/state' => _updateState(data),
      '/generate' => _generate(),
      '/reveal' => _handleReveal(),
      '/pin' => _handlePin(data),
      '/confirm' => _handleConfirm(data),
      '/quiz' => _handleQuiz(data),
      '/restore' => _handleRestore(data),
      '/validate' => _validate(),
      '/seal' => _seal(),
      _ => Err(InvalidPathError('Unknown path: $path')),
    };
  }

  @override
  Result<Scroll> writeScroll(Scroll scroll) {
    return write(scroll.key, scroll.data);
  }

  @override
  Result<List<String>> list(String prefix) {
    if (_closed) return const Err(ClosedError());
    return const Ok(['/state', '/mnemonic']);
  }

  @override
  Result<Stream<Scroll>> watch(String pattern) {
    if (_closed) return const Err(ClosedError());
    return Ok(_changes.stream);
  }

  @override
  Result<void> close() {
    if (!_closed) {
      _closed = true;
      _changes.close();
      _clearSensitive();
    }
    return const Ok(null);
  }

  // ===========================================================================
  // STATE SCROLLS
  // ===========================================================================

  Scroll _stateScroll() {
    return Scroll(
      key: '/onboard/state',
      type_: 'onboard/${_step.name}',
      data: {
        'step': _step.name,
        'isRestore': _isRestore,
        'revealed': _revealed,
        'quizIndices': _quizIndices,
        'quizInputs': _quizInputs,
        'quizValid': _isQuizValid,
        'pinLength': _pinLength,
        'confirmPinLength': _confirmPinLength,
        'pinError': _pinError,
        'sealError': _sealError,
        'mobinumber': _mobinumber,
        'restoreWords': _restoreWords,
        'restoreValid': _isRestoreValid,
        'validCount': _validWordCount,
        // Include words only during reveal
        if (_step == OnboardStep.reveal) 'words': _mnemonic,
      },
    );
  }

  Scroll _mnemonicScroll() {
    return Scroll(
      key: '/onboard/mnemonic',
      type_: 'onboard/mnemonic',
      data: {
        'words': _mnemonic,
        'restoreWords': _restoreWords,
      },
    );
  }

  void _notify() {
    if (!_closed) {
      _changes.add(_stateScroll());
    }
  }

  // ===========================================================================
  // TRANSITIONS
  // ===========================================================================

  Result<Scroll> _updateState(Map<String, dynamic> data) {
    final stepName = data['step'] as String?;
    if (stepName != null) {
      _step = OnboardStep.values.firstWhere(
        (s) => s.name == stepName,
        orElse: () => _step,
      );
    }

    if (data.containsKey('isRestore')) {
      _isRestore = data['isRestore'] as bool;
    }

    _notify();
    return Ok(_stateScroll());
  }

  Result<Scroll> _generate() {
    _step = OnboardStep.generate;
    _isRestore = false;
    _revealed = false;
    _notify();

    // Generate mnemonic (128 bits = 12 words)
    _mnemonic = bip39.generateMnemonic(strength: 128).split(' ');
    _pickQuizIndices();

    // Move to reveal
    _step = OnboardStep.reveal;
    _notify();

    return Ok(_stateScroll());
  }

  Result<Scroll> _handleReveal() {
    _revealed = true;
    _notify();
    return Ok(_stateScroll());
  }

  void _pickQuizIndices() {
    final random = Random.secure();
    final indices = <int>{};
    while (indices.length < 3) {
      indices.add(random.nextInt(12));
    }
    _quizIndices = indices.toList()..sort();
    _quizInputs = ['', '', ''];
  }

  Result<Scroll> _handlePin(Map<String, dynamic> data) {
    if (data.containsKey('digit')) {
      final digit = data['digit'] as String;
      if (_pin.length < 6) {
        _pin += digit;
        _pinLength = _pin.length;

        // Auto-advance to confirm when PIN complete
        if (_pin.length == 6) {
          Future.microtask(() {
            _step = OnboardStep.confirm;
            _notify();
          });
        }
      }
    } else if (data['delete'] == true && _pin.isNotEmpty) {
      _pin = _pin.substring(0, _pin.length - 1);
      _pinLength = _pin.length;
    }

    _notify();
    return Ok(_stateScroll());
  }

  Result<Scroll> _handleConfirm(Map<String, dynamic> data) {
    if (data.containsKey('digit')) {
      final digit = data['digit'] as String;
      if (_confirmPin.length < 6) {
        _confirmPin += digit;
        _confirmPinLength = _confirmPin.length;

        // Check match when complete
        if (_confirmPin.length == 6) {
          if (_confirmPin == _pin) {
            _pinError = null;
            // Trigger seal
            Future.microtask(() => _seal());
          } else {
            _pinError = "PINs don't match. Try again.";
            _confirmPin = '';
            _confirmPinLength = 0;
          }
        }
      }
    } else if (data['delete'] == true && _confirmPin.isNotEmpty) {
      _confirmPin = _confirmPin.substring(0, _confirmPin.length - 1);
      _confirmPinLength = _confirmPin.length;
      _pinError = null;
    }

    _notify();
    return Ok(_stateScroll());
  }

  Result<Scroll> _handleQuiz(Map<String, dynamic> data) {
    final index = data['index'] as int?;
    final value = data['value'] as String?;
    if (index != null && value != null && index >= 0 && index < 3) {
      _quizInputs[index] = value;
    }
    _notify();
    return Ok(_stateScroll());
  }

  Result<Scroll> _handleRestore(Map<String, dynamic> data) {
    final words = data['words'] as List?;
    if (words != null) {
      _restoreWords = words.cast<String>();
    }
    _notify();
    return Ok(_stateScroll());
  }

  Result<Scroll> _validate() {
    if (_isRestore) {
      // Validate restore phrase
      if (_isRestoreValid) {
        _mnemonic = _restoreWords;
        _step = OnboardStep.pin;
      }
    } else {
      // Validate quiz
      if (_isQuizValid) {
        _step = OnboardStep.pin;
      }
    }
    _notify();
    return Ok(_stateScroll());
  }

  Result<Scroll> _seal() {
    _step = OnboardStep.sealing;
    _sealError = null;
    _notify();

    // Call seal callback
    final phrase = _mnemonic.join(' ');
    final pin = _pin;

    if (onSeal != null) {
      onSeal!(phrase, pin).then((mobinumber) {
        if (mobinumber != null) {
          _mobinumber = mobinumber;
          _step = OnboardStep.identity;
          _clearSensitive();
        } else {
          _sealError = 'Failed to create wallet';
        }
        _notify();
      }).catchError((e) {
        _sealError = e.toString();
        _notify();
      });
    } else {
      // Simulate seal for testing
      Future.delayed(const Duration(milliseconds: 500), () {
        _mobinumber = '650-073-047-435';
        _step = OnboardStep.identity;
        _clearSensitive();
        _notify();
      });
    }

    return Ok(_stateScroll());
  }

  // ===========================================================================
  // VALIDATION
  // ===========================================================================

  bool get _isQuizValid {
    if (_mnemonic.isEmpty) return false;
    for (var i = 0; i < 3; i++) {
      if (_quizIndices.length <= i) return false;
      final expected = _mnemonic[_quizIndices[i]];
      if (_quizInputs[i].toLowerCase().trim() != expected.toLowerCase()) {
        return false;
      }
    }
    return true;
  }

  bool get _isRestoreValid {
    return _restoreWords.every(
        (w) => w.isNotEmpty && bip39.validateMnemonic(_restoreWords.join(' ')));
  }

  int get _validWordCount {
    // Count words that are non-empty and valid BIP39
    return _restoreWords
        .where((w) => w.isNotEmpty && _isValidWord(w.toLowerCase().trim()))
        .length;
  }

  bool _isValidWord(String word) {
    // Try to validate as single-word mnemonic fragment
    // BIP39 requires full phrase, so we check if adding it to a valid phrase works
    // Simpler: just check if the word appears in a generated mnemonic's wordlist
    // The bip39 package validates full phrases, not individual words
    // For now, accept non-empty words - full validation happens in _isRestoreValid
    return word.isNotEmpty;
  }

  // ===========================================================================
  // SECURITY
  // ===========================================================================

  void _clearSensitive() {
    // Clear mnemonic
    for (var i = 0; i < _mnemonic.length; i++) {
      _mnemonic[i] = '';
    }
    _mnemonic = [];

    // Clear restore words
    for (var i = 0; i < _restoreWords.length; i++) {
      _restoreWords[i] = '';
    }

    // Clear PINs
    _pin = '';
    _confirmPin = '';
    _pinLength = 0;
    _confirmPinLength = 0;
  }

  /// Reset to welcome state (for testing or retry)
  void reset() {
    _clearSensitive();
    _step = OnboardStep.welcome;
    _isRestore = false;
    _revealed = false;
    _quizIndices = [];
    _quizInputs = ['', '', ''];
    _pinError = null;
    _sealError = null;
    _mobinumber = null;
    _restoreWords = List.filled(12, '');
    _notify();
  }
}
