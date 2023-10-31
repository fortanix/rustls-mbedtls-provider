use mbedtls::cipher::raw::{CipherId, CipherMode, CipherType};

/// All the AEADs we support use 128-bit tags.
pub(crate) const TAG_LEN: usize = 16;

/// The maximum byte length of a tag for the algorithms in this module.
#[allow(dead_code)]
pub(crate) const MAX_TAG_LEN: usize = TAG_LEN;

pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;

pub(crate) const GCM_FIXED_IV_LEN: usize = 4;
pub(crate) const GCM_EXPLICIT_NONCE_LEN: usize = 8;
pub(crate) const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

pub(crate) static AES128_GCM: Algorithm = Algorithm {
    key_length: 128 / 8,
    cipher_type: CipherType::Aes128Gcm,
    cipher_id: CipherId::Aes,
    cipher_mode: CipherMode::GCM,
};
pub(crate) static AES256_GCM: Algorithm = Algorithm {
    key_length: 256 / 8,
    cipher_type: CipherType::Aes256Gcm,
    cipher_id: CipherId::Aes,
    cipher_mode: CipherMode::GCM,
};

pub(crate) static CHACHA20_POLY1305: Algorithm = Algorithm {
    key_length: 256 / 8,
    cipher_type: CipherType::Chacha20Poly1305,
    cipher_id: CipherId::Chacha20,
    cipher_mode: CipherMode::CHACHAPOLY,
};

pub(crate) struct Algorithm {
    pub(crate) key_length: usize,
    pub(crate) cipher_type: CipherType,
    pub(crate) cipher_id: CipherId,
    pub(crate) cipher_mode: CipherMode,
}
