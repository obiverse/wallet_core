//! Vault Core - Minimal Cryptographic Primitives for BeeWallet
//!
//! This is Layer 0: the irreducible cryptographic foundation.
//! Everything else (protocol, domains, UI) is built in Dart on top of this.
//!
//! ## Design Principles
//!
//! 1. **Minimal surface**: Only 6 C-ABI functions exposed
//! 2. **Memory safety**: All secrets zeroized on drop
//! 3. **No allocations leak**: Caller frees all returned memory
//! 4. **Constant-time**: Crypto operations don't leak timing
//!
//! ## Functions
//!
//! | Function | Purpose |
//! |----------|---------|
//! | `vault_derive_key` | Argon2id KDF (passphrase → 32-byte key) |
//! | `vault_seal` | ChaCha20-Poly1305 encrypt |
//! | `vault_unseal` | ChaCha20-Poly1305 decrypt |
//! | `vault_free` | Secure free (zeroize + deallocate) |
//! | `vault_zeroize` | Zeroize buffer in place |
//! | `vault_random` | CSPRNG bytes |
//!
//! Copyright (c) 2024-2025 OBIVERSE LLC
//! Licensed under MIT OR Apache-2.0

use std::slice;
use std::ptr;

use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroize;

// =============================================================================
// Constants
// =============================================================================

/// Key size for XChaCha20-Poly1305 (256 bits)
const KEY_SIZE: usize = 32;

/// Nonce size for XChaCha20-Poly1305 (192 bits)
const NONCE_SIZE: usize = 24;

/// Authentication tag size (128 bits)
const TAG_SIZE: usize = 16;

/// Salt size for Argon2 (128 bits recommended)
const SALT_SIZE: usize = 16;

// Argon2id parameters (OWASP recommended for 2024)
// Target: ~200ms on modern hardware
const ARGON2_M_COST: u32 = 65536;  // 64 MiB memory
const ARGON2_T_COST: u32 = 3;      // 3 iterations
const ARGON2_P_COST: u32 = 4;      // 4 parallel lanes

// =============================================================================
// Result Structure
// =============================================================================

/// Result buffer returned by seal/unseal operations
#[repr(C)]
pub struct VaultBuffer {
    /// Pointer to data (owned by this struct)
    pub data: *mut u8,
    /// Length of data in bytes
    pub len: u32,
    /// Error code (0 = success)
    pub error: i32,
}

impl VaultBuffer {
    fn success(data: Vec<u8>) -> Self {
        let len = data.len() as u32;
        let boxed = data.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut u8;
        Self { data: ptr, len, error: 0 }
    }

    fn error(code: i32) -> Self {
        Self { data: ptr::null_mut(), len: 0, error: code }
    }
}

// Error codes
const ERR_INVALID_INPUT: i32 = -1;
const ERR_DECRYPT_FAILED: i32 = -2;
const ERR_KDF_FAILED: i32 = -3;

// =============================================================================
// Key Derivation (Argon2id)
// =============================================================================

/// Derive a 32-byte encryption key from a passphrase using Argon2id.
///
/// # Safety
///
/// - `passphrase` must be a valid UTF-8 string pointer
/// - `passphrase_len` must be the exact byte length
/// - `salt` must point to exactly 16 bytes
/// - Returned buffer must be freed with `vault_free`
///
/// # Returns
///
/// VaultBuffer containing 32-byte key, or error code
#[no_mangle]
pub unsafe extern "C" fn vault_derive_key(
    passphrase: *const u8,
    passphrase_len: u32,
    salt: *const u8,
) -> VaultBuffer {
    // Validate inputs
    if passphrase.is_null() || salt.is_null() || passphrase_len == 0 {
        return VaultBuffer::error(ERR_INVALID_INPUT);
    }

    let passphrase_slice = slice::from_raw_parts(passphrase, passphrase_len as usize);
    let salt_slice = slice::from_raw_parts(salt, SALT_SIZE);

    // Configure Argon2id
    let params = match Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE)) {
        Ok(p) => p,
        Err(_) => return VaultBuffer::error(ERR_KDF_FAILED),
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive key
    let mut key = vec![0u8; KEY_SIZE];
    match argon2.hash_password_into(passphrase_slice, salt_slice, &mut key) {
        Ok(_) => VaultBuffer::success(key),
        Err(_) => {
            key.zeroize();
            VaultBuffer::error(ERR_KDF_FAILED)
        }
    }
}

// =============================================================================
// Encryption (XChaCha20-Poly1305)
// =============================================================================

/// Encrypt data using XChaCha20-Poly1305.
///
/// # Format
///
/// Output: `nonce (24 bytes) || ciphertext || tag (16 bytes)`
///
/// # Safety
///
/// - `key` must point to exactly 32 bytes
/// - `plaintext` must be valid for `plaintext_len` bytes
/// - Returned buffer must be freed with `vault_free`
#[no_mangle]
pub unsafe extern "C" fn vault_seal(
    key: *const u8,
    plaintext: *const u8,
    plaintext_len: u32,
) -> VaultBuffer {
    // Validate inputs
    if key.is_null() || plaintext.is_null() {
        return VaultBuffer::error(ERR_INVALID_INPUT);
    }

    let key_slice = slice::from_raw_parts(key, KEY_SIZE);
    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len as usize);

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    if getrandom::getrandom(&mut nonce_bytes).is_err() {
        return VaultBuffer::error(ERR_INVALID_INPUT);
    }
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Create cipher
    let cipher = match XChaCha20Poly1305::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(_) => return VaultBuffer::error(ERR_INVALID_INPUT),
    };

    // Encrypt
    let ciphertext = match cipher.encrypt(nonce, plaintext_slice) {
        Ok(ct) => ct,
        Err(_) => return VaultBuffer::error(ERR_INVALID_INPUT),
    };

    // Output: nonce || ciphertext (includes tag)
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    VaultBuffer::success(output)
}

/// Decrypt data encrypted with `vault_seal`.
///
/// # Safety
///
/// - `key` must point to exactly 32 bytes
/// - `sealed` must contain: nonce (24) || ciphertext || tag (16)
/// - Returned buffer must be freed with `vault_free`
#[no_mangle]
pub unsafe extern "C" fn vault_unseal(
    key: *const u8,
    sealed: *const u8,
    sealed_len: u32,
) -> VaultBuffer {
    // Validate inputs
    let min_len = NONCE_SIZE + TAG_SIZE;
    if key.is_null() || sealed.is_null() || (sealed_len as usize) < min_len {
        return VaultBuffer::error(ERR_INVALID_INPUT);
    }

    let key_slice = slice::from_raw_parts(key, KEY_SIZE);
    let sealed_slice = slice::from_raw_parts(sealed, sealed_len as usize);

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = sealed_slice.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);

    // Create cipher
    let cipher = match XChaCha20Poly1305::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(_) => return VaultBuffer::error(ERR_INVALID_INPUT),
    };

    // Decrypt
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => VaultBuffer::success(plaintext),
        Err(_) => VaultBuffer::error(ERR_DECRYPT_FAILED),
    }
}

// =============================================================================
// Memory Safety
// =============================================================================

/// Free a buffer returned by vault functions, securely zeroizing first.
///
/// # Safety
///
/// - `ptr` must have been returned by a vault function
/// - `len` must match the original length
/// - Must not be called twice on the same pointer
#[no_mangle]
pub unsafe extern "C" fn vault_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }

    // Zeroize before freeing
    let slice = slice::from_raw_parts_mut(ptr, len as usize);
    slice.zeroize();

    // Reconstruct and drop the Box to free
    let _ = Box::from_raw(slice::from_raw_parts_mut(ptr, len as usize));
}

/// Zeroize a buffer in place (for Dart-allocated memory).
///
/// # Safety
///
/// - `ptr` must be valid for `len` bytes
/// - Memory must be writable
#[no_mangle]
pub unsafe extern "C" fn vault_zeroize(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }

    let slice = slice::from_raw_parts_mut(ptr, len as usize);
    slice.zeroize();
}

/// Fill a buffer with cryptographically secure random bytes.
///
/// # Safety
///
/// - `out` must be valid for `len` bytes
/// - Memory must be writable
///
/// # Returns
///
/// 0 on success, -1 on error
#[no_mangle]
pub unsafe extern "C" fn vault_random(out: *mut u8, len: u32) -> i32 {
    if out.is_null() || len == 0 {
        return ERR_INVALID_INPUT;
    }

    let slice = slice::from_raw_parts_mut(out, len as usize);
    match getrandom::getrandom(slice) {
        Ok(_) => 0,
        Err(_) => ERR_INVALID_INPUT,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let passphrase = b"test passphrase";
        let salt = [0u8; 16];

        unsafe {
            let result = vault_derive_key(
                passphrase.as_ptr(),
                passphrase.len() as u32,
                salt.as_ptr(),
            );

            assert_eq!(result.error, 0);
            assert_eq!(result.len, 32);
            assert!(!result.data.is_null());

            // Same passphrase + salt = same key (deterministic)
            let result2 = vault_derive_key(
                passphrase.as_ptr(),
                passphrase.len() as u32,
                salt.as_ptr(),
            );

            let key1 = slice::from_raw_parts(result.data, 32);
            let key2 = slice::from_raw_parts(result2.data, 32);
            assert_eq!(key1, key2);

            vault_free(result.data, result.len);
            vault_free(result2.data, result2.len);
        }
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, vault!";

        unsafe {
            // Seal
            let sealed = vault_seal(key.as_ptr(), plaintext.as_ptr(), plaintext.len() as u32);
            assert_eq!(sealed.error, 0);
            assert!(sealed.len > plaintext.len() as u32); // nonce + tag overhead

            // Unseal
            let unsealed = vault_unseal(key.as_ptr(), sealed.data, sealed.len);
            assert_eq!(unsealed.error, 0);
            assert_eq!(unsealed.len, plaintext.len() as u32);

            let result = slice::from_raw_parts(unsealed.data, unsealed.len as usize);
            assert_eq!(result, plaintext);

            vault_free(sealed.data, sealed.len);
            vault_free(unsealed.data, unsealed.len);
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32]; // Different key
        let plaintext = b"Secret data";

        unsafe {
            let sealed = vault_seal(key1.as_ptr(), plaintext.as_ptr(), plaintext.len() as u32);
            assert_eq!(sealed.error, 0);

            // Try to unseal with wrong key
            let unsealed = vault_unseal(key2.as_ptr(), sealed.data, sealed.len);
            assert_eq!(unsealed.error, ERR_DECRYPT_FAILED);

            vault_free(sealed.data, sealed.len);
        }
    }

    #[test]
    fn test_random() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        unsafe {
            assert_eq!(vault_random(buf1.as_mut_ptr(), 32), 0);
            assert_eq!(vault_random(buf2.as_mut_ptr(), 32), 0);

            // Extremely unlikely to be equal
            assert_ne!(buf1, buf2);
        }
    }
}
