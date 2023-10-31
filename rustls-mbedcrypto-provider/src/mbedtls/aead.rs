use mbedtls::cipher::raw::{CipherId, CipherMode, CipherType};

/// All the AEADs we support use 128-bit tags.
pub(crate) const TAG_LEN: usize = 16;

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
