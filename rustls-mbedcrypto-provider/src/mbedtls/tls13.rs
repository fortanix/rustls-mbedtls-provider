use super::aead;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use mbedtls::cipher::raw::CipherType;
use mbedtls::cipher::{Authenticated, Cipher, Decryption, Encryption, Fresh};
use rustls::cipher_suite::CipherSuiteCommon;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, BorrowedPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OpaqueMessage, PlainMessage, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::internal::msgs::codec::Codec;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    SupportedCipherSuite, Tls13CipherSuite,
};

#[cfg(feature = "logging")]
use crate::log::error;

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
    },
    hkdf_provider: &HkdfUsingHmac(&super::hmac::HMAC_SHA256),
    aead_alg: &AeadAlgorithm(&aead::CHACHA20_POLY1305),
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
        },
        hkdf_provider: &HkdfUsingHmac(&super::hmac::HMAC_SHA384),
        aead_alg: &AeadAlgorithm(&aead::AES256_GCM),
    });

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &super::hash::SHA256,
        },
        hkdf_provider: &HkdfUsingHmac(&super::hmac::HMAC_SHA256),
        aead_alg: &AeadAlgorithm(&aead::AES128_GCM),
    });

struct AeadAlgorithm(&'static aead::Algorithm);

impl Tls13AeadAlgorithm for AeadAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13MessageEncrypter {
            enc_key: key.as_ref().to_vec(),
            iv,
            aead_algorithm: self.0,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13MessageDecrypter {
            dec_key: key.as_ref().to_vec(),
            iv,
            aead_algorithm: self.0,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_length
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match self.0.cipher_type {
            CipherType::Aes128Gcm => Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv }),
            CipherType::Aes256Gcm => Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv }),
            CipherType::Chacha20Poly1305 => {
                Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
            }
            _ => Err(UnsupportedOperationError),
        }
    }
}

struct Tls13MessageEncrypter {
    enc_key: Vec<u8>,
    iv: Iv,
    aead_algorithm: &'static aead::Algorithm,
}

struct Tls13MessageDecrypter {
    dec_key: Vec<u8>,
    iv: Iv,
    aead_algorithm: &'static aead::Algorithm,
}

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let total_len = msg.payload.len() + 1 + aead::TAG_LEN;
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);
        msg.typ.encode(&mut payload);

        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let mut tag = vec![0u8; aead::TAG_LEN];

        let cipher = Cipher::<Encryption, Authenticated, Fresh>::new(
            self.aead_algorithm.cipher_id,
            self.aead_algorithm.cipher_mode,
            (self.enc_key.len() * 8) as _,
        )
        .map_err(|_err| {
            error!(
                "Failed to create TLS13 encrypt cipher, mbedtls error: {}",
                _err
            );
            Error::DecryptError
        })?;

        let cipher = cipher
            .set_key_iv(&self.enc_key, &nonce)
            .map_err(|_err| {
                error!(
                    "Failed to set key and iv for TLS13 encrypt cipher, mbedtls error: {}",
                    _err
                );
                Error::DecryptError
            })?;

        cipher
            .encrypt_auth_inplace(&aad, &mut payload, &mut tag)
            .map_err(|_err| {
                error!(
                    "Failed to encrypt with TLS13 encrypt cipher, mbedtls error: {}",
                    _err
                );
                Error::DecryptError
            })?;
        payload.extend(tag);

        Ok(OpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }
}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = msg.payload_mut();
        if payload.len() < aead::TAG_LEN {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(payload.len());

        let key_bit_len = self.dec_key.len() * 8;
        let cipher = Cipher::<Decryption, Authenticated, Fresh>::new(
            self.aead_algorithm.cipher_id,
            self.aead_algorithm.cipher_mode,
            key_bit_len as _,
        )
        .map_err(|_err| {
            error!(
                "Failed to create TLS13 decrypt cipher, mbedtls error: {}",
                _err
            );
            Error::DecryptError
        })?;

        let cipher = cipher
            .set_key_iv(&self.dec_key, &nonce)
            .map_err(|_err| {
                error!(
                    "Failed to set key and iv for TLS13 decrypt cipher, mbedtls error: {}",
                    _err
                );
                Error::DecryptError
            })?;

        let tag_offset = payload
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::DecryptError)?;

        let (ciphertext, tag) = payload.split_at_mut(tag_offset);

        let (plain_len, _) = cipher
            .decrypt_auth_inplace(&aad, ciphertext, tag)
            .map_err(|_err| {
                error!(
                    "Failed to encrypt with TLS13 decrypt cipher, mbedtls error: {}",
                    _err
                );
                Error::DecryptError
            })?;
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}
