/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use crate::error::mbedtls_err_to_rustls_error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use mbedtls::cipher::raw::{CipherId, CipherMode, CipherType};
use mbedtls::cipher::{Authenticated, Cipher, Decryption, Encryption, Fresh};
use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, BorrowedPlainMessage, Iv, KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OpaqueMessage,
    PlainMessage, Tls12AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::{CipherSuiteCommon, KeyExchangeAlgorithm};

use super::aead::{self, Algorithm, AES128_GCM, AES256_GCM};
use alloc::string::String;
use rustls::{CipherSuite, ConnectionTrafficSecrets, Error, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite};

pub(crate) const GCM_FIXED_IV_LEN: usize = 4;
pub(crate) const GCM_EXPLICIT_NONCE_LEN: usize = 8;
pub(crate) const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;
pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &super::hash::SHA256,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &ChaCha20Poly1305,
        prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
        integrity_limit: 1 << 36,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
});

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 23,
        integrity_limit: 1 << 52,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES128_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
});

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 23,
        integrity_limit: 1 << 52,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES256_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA384),
});

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 23,
        integrity_limit: 1 << 52,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES128_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
});

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 23,
        integrity_limit: 1 << 52,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES256_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA384),
});

/// The TLS1.2 ciphersuite TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 23,
        integrity_limit: 1 << 52,
    },
    kx: KeyExchangeAlgorithm::DHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES128_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
});

/// The TLS1.2 ciphersuite TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 23,
        integrity_limit: 1 << 52,
    },
    kx: KeyExchangeAlgorithm::DHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES256_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA384),
});

/// The TLS1.2 ciphersuite TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
        integrity_limit: 1 << 36,
    },
    kx: KeyExchangeAlgorithm::DHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
});

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl Tls12AeadAlgorithm for Algorithm {
    fn encrypter(&self, enc_key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let iv = gcm_iv(iv, extra);
        Box::new(GcmMessageEncrypter { enc_key, iv })
    }

    fn decrypter(&self, dec_key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut ret = GcmMessageDecrypter { dec_key, dec_salt: [0u8; GCM_FIXED_IV_LEN] };
        debug_assert_eq!(iv.len(), GCM_FIXED_IV_LEN);
        ret.dec_salt.copy_from_slice(iv);
        Box::new(ret)
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.key_length,
            fixed_iv_len: GCM_FIXED_IV_LEN,
            explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match self.cipher_type {
            CipherType::Aes128Gcm => Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv: gcm_iv(iv, explicit) }),
            CipherType::Aes256Gcm => Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv: gcm_iv(iv, explicit) }),
            _ => Err(UnsupportedOperationError),
        }
    }
}

pub(crate) struct ChaCha20Poly1305;

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn decrypter(&self, dec_key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(ChaCha20Poly1305MessageDecrypter { dec_key, dec_offset: Iv::copy(iv) })
    }

    fn encrypter(&self, enc_key: AeadKey, enc_iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(ChaCha20Poly1305MessageEncrypter { enc_key, enc_offset: Iv::copy(enc_iv) })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: 32, fixed_iv_len: 12, explicit_nonce_len: 0 }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv: Iv::new(iv[..].try_into().unwrap()) })
    }
}

/// A `MessageEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
struct GcmMessageEncrypter {
    enc_key: AeadKey,
    iv: Iv,
}

/// A `MessageDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
struct GcmMessageDecrypter {
    dec_key: AeadKey,
    dec_salt: [u8; GCM_FIXED_IV_LEN],
}

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt(&mut self, msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = msg.payload();
        if payload.len() < GCM_OVERHEAD {
            return Err(Error::DecryptError);
        }
        let nonce = {
            let mut nonce = [0u8; NONCE_LEN];
            nonce[..GCM_FIXED_IV_LEN].copy_from_slice(&self.dec_salt);
            nonce[GCM_FIXED_IV_LEN..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LEN]);
            nonce
        };
        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload.len() - GCM_OVERHEAD);

        let dec_key = self.dec_key.as_ref();
        let cipher = Cipher::<Decryption, Authenticated, Fresh>::new(CipherId::Aes, CipherMode::GCM, (dec_key.len() * 8) as _)
            .map_err(mbedtls_err_to_rustls_error)?;

        let cipher = cipher
            .set_key_iv(dec_key, &nonce)
            .map_err(mbedtls_err_to_rustls_error)?;

        let tag_offset = payload
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::General(String::from("Tag length overflow")))?;

        let tag = &payload[tag_offset..];
        let mut ciphertext = payload[GCM_EXPLICIT_NONCE_LEN..tag_offset].to_vec();
        let (plain_len, _) = cipher
            .decrypt_auth_inplace(&aad, &mut ciphertext, tag)
            .map_err(|err| match err {
                mbedtls::Error::CcmAuthFailed
                | mbedtls::Error::ChachapolyAuthFailed
                | mbedtls::Error::CipherAuthFailed
                | mbedtls::Error::GcmAuthFailed => Error::DecryptError,
                _ => mbedtls_err_to_rustls_error(err),
            })?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        ciphertext.truncate(plain_len);
        Ok(PlainMessage {
            typ: msg.typ,
            version: msg.version,
            payload: rustls::internal::msgs::base::Payload(ciphertext),
        })
    }
}

impl MessageEncrypter for GcmMessageEncrypter {
    fn encrypt(&mut self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let mut tag = [0u8; aead::TAG_LEN];
        let plain_total_len = msg.payload.len() + aead::TAG_LEN;
        let mut payload = Vec::with_capacity(GCM_EXPLICIT_NONCE_LEN + plain_total_len);
        payload.extend_from_slice(&nonce.as_ref()[GCM_FIXED_IV_LEN..]);
        payload.extend_from_slice(msg.payload);

        let enc_key = self.enc_key.as_ref();
        let cipher = Cipher::<Encryption, Authenticated, Fresh>::new(CipherId::Aes, CipherMode::GCM, (enc_key.len() * 8) as _)
            .map_err(mbedtls_err_to_rustls_error)?;
        let cipher = cipher
            .set_key_iv(enc_key, &nonce)
            .map_err(mbedtls_err_to_rustls_error)?;

        cipher
            .encrypt_auth_inplace(&aad, &mut payload[GCM_EXPLICIT_NONCE_LEN..], &mut tag)
            .map_err(|err| match err {
                mbedtls::Error::CcmAuthFailed
                | mbedtls::Error::ChachapolyAuthFailed
                | mbedtls::Error::CipherAuthFailed
                | mbedtls::Error::GcmAuthFailed => Error::EncryptError,
                _ => mbedtls_err_to_rustls_error(err),
            })?;
        payload.extend(tag);

        Ok(OpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + aead::TAG_LEN
    }
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageEncrypter`.
struct ChaCha20Poly1305MessageEncrypter {
    enc_key: AeadKey,
    enc_offset: Iv,
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageDecrypter`.
struct ChaCha20Poly1305MessageDecrypter {
    dec_key: AeadKey,
    dec_offset: Iv,
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt(&mut self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = msg.payload();

        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.dec_offset, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload.len() - CHACHAPOLY1305_OVERHEAD);

        let payload = msg.payload_mut();

        let dec_key = self.dec_key.as_ref();
        let cipher = Cipher::<Decryption, Authenticated, Fresh>::new(
            CipherId::Chacha20,
            CipherMode::CHACHAPOLY,
            (dec_key.len() * 8) as _,
        )
        .map_err(mbedtls_err_to_rustls_error)?;

        let cipher = cipher
            .set_key_iv(dec_key, &nonce)
            .map_err(mbedtls_err_to_rustls_error)?;

        let tag_offset = payload
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::DecryptError)?;

        let (ciphertext, tag) = payload.split_at_mut(tag_offset);

        let (plain_len, _) = cipher
            .decrypt_auth_inplace(&aad, ciphertext, tag)
            .map_err(|err| match err {
                mbedtls::Error::CcmAuthFailed
                | mbedtls::Error::ChachapolyAuthFailed
                | mbedtls::Error::CipherAuthFailed
                | mbedtls::Error::GcmAuthFailed => Error::DecryptError,
                _ => mbedtls_err_to_rustls_error(err),
            })?;

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for ChaCha20Poly1305MessageEncrypter {
    fn encrypt(&mut self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let nonce = Nonce::new(&self.enc_offset, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let mut tag = [0u8; aead::TAG_LEN];
        let plain_total_len = msg.payload.len() + aead::TAG_LEN;
        let mut payload = Vec::with_capacity(plain_total_len);
        payload.extend_from_slice(msg.payload);

        let enc_key = self.enc_key.as_ref();
        let cipher = Cipher::<Encryption, Authenticated, Fresh>::new(
            CipherId::Chacha20,
            CipherMode::CHACHAPOLY,
            (enc_key.len() * 8) as _,
        )
        .map_err(mbedtls_err_to_rustls_error)?;

        let cipher = cipher
            .set_key_iv(enc_key, &nonce)
            .map_err(mbedtls_err_to_rustls_error)?;

        cipher
            .encrypt_auth_inplace(&aad, &mut payload, &mut tag)
            .map_err(|err| match err {
                mbedtls::Error::CcmAuthFailed
                | mbedtls::Error::ChachapolyAuthFailed
                | mbedtls::Error::CipherAuthFailed
                | mbedtls::Error::GcmAuthFailed => Error::EncryptError,
                _ => mbedtls_err_to_rustls_error(err),
            })?;
        payload.extend(tag);

        Ok(OpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + aead::TAG_LEN
    }
}

/// Generate GCM IV based on given IV and explicit nonce.
fn gcm_iv(write_iv: &[u8], explicit_nonce: &[u8]) -> Iv {
    debug_assert_eq!(write_iv.len(), GCM_FIXED_IV_LEN);
    debug_assert_eq!(explicit_nonce.len(), GCM_EXPLICIT_NONCE_LEN);

    // The GCM nonce is constructed from a 32-bit 'salt' derived
    // from the master-secret, and a 64-bit explicit part,
    // with no specified construction.
    //
    // We use the same construction as TLS1.3/ChaCha20Poly1305:
    // a starting point extracted from the key block, XOR-ed with
    // the sequence number.
    let mut iv = [0; NONCE_LEN];
    iv[..GCM_FIXED_IV_LEN].copy_from_slice(write_iv);
    iv[GCM_FIXED_IV_LEN..].copy_from_slice(explicit_nonce);

    Iv::new(iv)
}
