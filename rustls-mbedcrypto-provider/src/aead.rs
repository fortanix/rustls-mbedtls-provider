use mbedtls::cipher::raw::{CipherId, CipherMode, CipherType};

/// All the AEADs we support use 128-bit tags.
pub(crate) const TAG_LEN: usize = 16;

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
pub(crate) static AES128_GCM: Algorithm = Algorithm {
    key_length: 128 / 8,
    cipher_type: CipherType::Aes128Gcm,
    cipher_id: CipherId::Aes,
    cipher_mode: CipherMode::GCM,
};

/// AES-256 in GCM mode with 256-bit tags and 96 bit nonces.
pub(crate) static AES256_GCM: Algorithm = Algorithm {
    key_length: 256 / 8,
    cipher_type: CipherType::Aes256Gcm,
    cipher_id: CipherId::Aes,
    cipher_mode: CipherMode::GCM,
};

/// ChaCha20-Poly1305 as described in [RFC 8439].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 8439]: https://tools.ietf.org/html/rfc8439
pub(crate) static CHACHA20_POLY1305: Algorithm = Algorithm {
    key_length: 256 / 8,
    cipher_type: CipherType::Chacha20Poly1305,
    cipher_id: CipherId::Chacha20,
    cipher_mode: CipherMode::CHACHAPOLY,
};

/// An AEAD Algorithm.
pub(crate) struct Algorithm {
    pub(crate) key_length: usize,
    pub(crate) cipher_type: CipherType,
    pub(crate) cipher_id: CipherId,
    pub(crate) cipher_mode: CipherMode,
}
