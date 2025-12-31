/// Mobi Protocol v21.0.0 - Dart FFI Bindings
///
/// Uses the C reference implementation via FFI for derivation,
/// with pure Dart for parsing/formatting utilities.
///
/// ## Usage
///
/// ```dart
/// // Initialize the library (call once at app start)
/// await MobiBindings.initialize();
///
/// // Derive mobi from x-only pubkey
/// final mobi = Mobi.fromHex('17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917');
/// print(mobi.formatDisplay());  // "879-044-656-584"
/// ```
///
/// Copyright (c) 2024-2025 OBIVERSE LLC
/// Licensed under MIT OR Apache-2.0
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:ffi/ffi.dart';

// =============================================================================
// CONSTANTS (matching C header)
// =============================================================================

/// Version
const String mobiVersionString = '21.0.0';
const int mobiVersionMajor = 21;
const int mobiVersionMinor = 0;
const int mobiVersionPatch = 0;

/// Pubkey length - x-only secp256k1 (32 bytes)
const int mobiPubkeyLen = 32;
const int mobiPubkeyHexLen = 64;

/// Digit lengths
const int mobiFullLen = 21;
const int mobiDisplayLen = 12;
const int mobiExtendedLen = 15;
const int mobiLongLen = 18;

// =============================================================================
// FFI TYPE DEFINITIONS (matching mobi.h)
// =============================================================================

/// Error codes from C
enum MobiError {
  ok, // 0
  nullPointer, // -1
  invalidHex, // -2
  invalidLen, // -3
  invalidChar, // -4
}

/// Native mobi_t struct
final class MobiNative extends Struct {
  @Array(22)
  external Array<Uint8> full; // 21 digits + null

  @Array(13)
  external Array<Uint8> display; // 12 digits + null

  @Array(16)
  external Array<Uint8> extended; // 15 digits + null

  @Array(19)
  external Array<Uint8> lng; // 18 digits + null
}

// =============================================================================
// FFI FUNCTION SIGNATURES
// =============================================================================

typedef MobiDeriveNative = Int32 Function(
    Pointer<Utf8> pubkeyHex, Pointer<MobiNative> out);
typedef MobiDerive = int Function(
    Pointer<Utf8> pubkeyHex, Pointer<MobiNative> out);

typedef MobiDeriveBytesNative = Int32 Function(
    Pointer<Uint8> pubkey, Pointer<MobiNative> out);
typedef MobiDeriveBytes = int Function(
    Pointer<Uint8> pubkey, Pointer<MobiNative> out);

typedef MobiFormatDisplayNative = Int32 Function(
    Pointer<MobiNative> mobi, Pointer<Utf8> out);
typedef MobiFormatDisplay = int Function(
    Pointer<MobiNative> mobi, Pointer<Utf8> out);

typedef MobiNormalizeNative = Int32 Function(
    Pointer<Utf8> input, Pointer<Utf8> out, IntPtr outLen);
typedef MobiNormalize = int Function(
    Pointer<Utf8> input, Pointer<Utf8> out, int outLen);

typedef MobiValidateNative = Int32 Function(Pointer<Utf8> mobi);
typedef MobiValidate = int Function(Pointer<Utf8> mobi);

// =============================================================================
// FFI BINDINGS
// =============================================================================

/// Mobi FFI bindings to the C library
class MobiBindings {
  static DynamicLibrary? _lib;
  static MobiDerive? _derive;
  static MobiDeriveBytes? _deriveBytes;

  /// Initialize the native library
  ///
  /// Searches for libmobi in common locations:
  /// - Bundled with the app
  /// - System paths (/usr/local/lib, etc.)
  /// - Development paths (../mobi/build/)
  static void initialize([String? libraryPath]) {
    if (_lib != null) return;

    _lib = _loadLibrary(libraryPath);

    _derive = _lib!
        .lookupFunction<MobiDeriveNative, MobiDerive>('mobi_derive');
    _deriveBytes = _lib!
        .lookupFunction<MobiDeriveBytesNative, MobiDeriveBytes>('mobi_derive_bytes');
  }

  static DynamicLibrary _loadLibrary(String? libraryPath) {
    if (libraryPath != null) {
      return DynamicLibrary.open(libraryPath);
    }

    // Platform-specific library name
    final libName = Platform.isMacOS
        ? 'libmobi.dylib'
        : Platform.isWindows
            ? 'mobi.dll'
            : 'libmobi.so';

    // Search paths
    final searchPaths = [
      // Bundled with app
      libName,
      'lib/$libName',
      // System paths
      '/usr/local/lib/$libName',
      '/usr/lib/$libName',
      // Development paths
      '../mobi/build/$libName',
      '../../mobi/build/$libName',
      // Static library won't work with DynamicLibrary, need shared
    ];

    for (final path in searchPaths) {
      try {
        return DynamicLibrary.open(path);
      } catch (_) {
        continue;
      }
    }

    throw UnsupportedError(
        'Could not find libmobi. Build it with: cd mobi && make');
  }

  /// Check if native library is available
  static bool get isAvailable => _lib != null;

  /// Derive mobi from hex pubkey using native library
  static MobiNative? deriveHex(String pubkeyHex) {
    if (_derive == null) {
      throw StateError('MobiBindings not initialized. Call initialize() first.');
    }

    final pubkeyPtr = pubkeyHex.toNativeUtf8();
    final outPtr = calloc<MobiNative>();

    try {
      final result = _derive!(pubkeyPtr, outPtr);
      if (result != 0) {
        return null;
      }
      return outPtr.ref;
    } finally {
      calloc.free(pubkeyPtr);
      // Note: caller is responsible for freeing outPtr after reading values
    }
  }

  /// Derive mobi from bytes using native library
  static MobiNative? deriveBytes(Uint8List pubkey) {
    if (_deriveBytes == null) {
      throw StateError('MobiBindings not initialized. Call initialize() first.');
    }

    final pubkeyPtr = calloc<Uint8>(mobiPubkeyLen);
    for (var i = 0; i < mobiPubkeyLen; i++) {
      pubkeyPtr[i] = pubkey[i];
    }
    final outPtr = calloc<MobiNative>();

    try {
      final result = _deriveBytes!(pubkeyPtr, outPtr);
      if (result != 0) {
        calloc.free(outPtr);
        return null;
      }
      return outPtr.ref;
    } finally {
      calloc.free(pubkeyPtr);
    }
  }
}

// =============================================================================
// MOBI CLASS
// =============================================================================

/// Mobi - The complete mobi identity
///
/// Contains all representations derived from a single pubkey.
/// All fields are deterministic - same pubkey always yields same values.
class Mobi {
  /// Full 21 digits (canonical form, always unique)
  final String full;

  /// Display 12 digits
  final String display;

  /// Extended 15 digits
  final String extended;

  /// Long 18 digits
  final String lng;

  const Mobi._({
    required this.full,
    required this.display,
    required this.extended,
    required this.lng,
  });

  /// Derive mobi from 32-byte x-only public key
  ///
  /// Uses native C library for derivation.
  factory Mobi.fromBytes(Uint8List pubkey) {
    if (pubkey.length != mobiPubkeyLen) {
      throw ArgumentError(
          'Public key must be $mobiPubkeyLen bytes (x-only), got ${pubkey.length}');
    }

    // Try native library first
    if (MobiBindings.isAvailable) {
      final native = MobiBindings.deriveBytes(pubkey);
      if (native != null) {
        return _fromNative(native);
      }
    }

    // Fallback to pure Dart implementation
    return _derivePureDart(pubkey);
  }

  /// Derive mobi from 64-character hex-encoded x-only public key
  factory Mobi.fromHex(String pubkeyHex) {
    if (pubkeyHex.length != mobiPubkeyHexLen) {
      throw ArgumentError(
          'Hex public key must be $mobiPubkeyHexLen characters, got ${pubkeyHex.length}');
    }

    // Try native library first
    if (MobiBindings.isAvailable) {
      final native = MobiBindings.deriveHex(pubkeyHex);
      if (native != null) {
        return _fromNative(native);
      }
    }

    // Fallback to pure Dart
    final pubkey = _hexDecode(pubkeyHex);
    return _derivePureDart(pubkey);
  }

  /// Parse mobi from any format (with or without hyphens)
  factory Mobi.parse(String input) {
    final normalized = normalize(input);
    if (normalized == null) {
      throw FormatException('Invalid mobi format: $input');
    }

    final full = normalized.padRight(21, '0');
    return Mobi._(
      full: full,
      display: full.substring(0, mobiDisplayLen),
      extended: full.substring(0, mobiExtendedLen),
      lng: full.substring(0, mobiLongLen),
    );
  }

  /// Try to parse mobi, returns null on failure
  static Mobi? tryParse(String input) {
    try {
      return Mobi.parse(input);
    } catch (_) {
      return null;
    }
  }

  // ===========================================================================
  // FORMATTING
  // ===========================================================================

  /// Format as display: XXX-XXX-XXX-XXX
  String formatDisplay() {
    return '${display.substring(0, 3)}-${display.substring(3, 6)}-'
        '${display.substring(6, 9)}-${display.substring(9, 12)}';
  }

  /// Format as extended: XXX-XXX-XXX-XXX-XXX
  String formatExtended() {
    return '${extended.substring(0, 3)}-${extended.substring(3, 6)}-'
        '${extended.substring(6, 9)}-${extended.substring(9, 12)}-'
        '${extended.substring(12, 15)}';
  }

  /// Format as full: XXX-XXX-XXX-XXX-XXX-XXX-XXX
  String formatFull() {
    return '${full.substring(0, 3)}-${full.substring(3, 6)}-'
        '${full.substring(6, 9)}-${full.substring(9, 12)}-'
        '${full.substring(12, 15)}-${full.substring(15, 18)}-'
        '${full.substring(18, 21)}';
  }

  // ===========================================================================
  // COMPARISON
  // ===========================================================================

  /// Check if display (12-digit) matches another mobi
  bool displayMatches(String other) {
    final norm = normalize(other);
    if (norm == null || norm.length < mobiDisplayLen) return false;
    return display == norm.substring(0, mobiDisplayLen);
  }

  /// Check if full (21-digit) matches another mobi
  bool fullMatches(Mobi other) {
    return full == other.full;
  }

  @override
  String toString() => formatDisplay();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is Mobi && full == other.full;

  @override
  int get hashCode => full.hashCode;

  // ===========================================================================
  // STATIC UTILITIES
  // ===========================================================================

  /// Normalize mobi string: strip formatting, validate digits
  static String? normalize(String input) {
    final buffer = StringBuffer();

    for (var i = 0; i < input.length; i++) {
      final c = input.codeUnitAt(i);
      if (c >= 0x30 && c <= 0x39) {
        buffer.writeCharCode(c);
      } else if (c == 0x2D || c == 0x20 || c == 0x2E || c == 0x28 || c == 0x29) {
        // - space . ( )
        continue;
      } else {
        return null;
      }
    }

    final digits = buffer.toString();
    if (digits.length != 12 &&
        digits.length != 15 &&
        digits.length != 18 &&
        digits.length != 21) {
      return null;
    }

    return digits;
  }

  /// Validate mobi string
  static bool validate(String mobi) => normalize(mobi) != null;

  // ===========================================================================
  // INTERNAL
  // ===========================================================================

  /// Convert native struct to Mobi
  static Mobi _fromNative(MobiNative native) {
    String arrayToString(Array<Uint8> arr, int len) {
      final bytes = <int>[];
      for (var i = 0; i < len; i++) {
        final b = arr[i];
        if (b == 0) break;
        bytes.add(b);
      }
      return String.fromCharCodes(bytes);
    }

    return Mobi._(
      full: arrayToString(native.full, 22),
      display: arrayToString(native.display, 13),
      extended: arrayToString(native.extended, 16),
      lng: arrayToString(native.lng, 19),
    );
  }

  /// Pure Dart fallback implementation
  static Mobi _derivePureDart(Uint8List pubkey) {
    final maxValue = BigInt.parse('1000000000000000000000');
    final input = Uint8List(mobiPubkeyLen + 1);
    input.setAll(0, pubkey);

    for (var round = 0; round < 256; round++) {
      final List<int> hash;
      if (round == 0) {
        hash = crypto.sha256.convert(pubkey).bytes;
      } else {
        input[mobiPubkeyLen] = round;
        hash = crypto.sha256.convert(input.sublist(0, mobiPubkeyLen + 1)).bytes;
      }

      // Extract first 9 bytes as big-endian 72-bit integer
      var value = BigInt.zero;
      for (var i = 0; i < 9; i++) {
        value = (value << 8) | BigInt.from(hash[i]);
      }

      if (value < maxValue) {
        final full = value.toString().padLeft(21, '0');
        return Mobi._(
          full: full,
          display: full.substring(0, mobiDisplayLen),
          extended: full.substring(0, mobiExtendedLen),
          lng: full.substring(0, mobiLongLen),
        );
      }
    }

    throw StateError('Mobi derivation failed after 256 rounds');
  }

  /// Hex decode helper
  static Uint8List _hexDecode(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < result.length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }
}
