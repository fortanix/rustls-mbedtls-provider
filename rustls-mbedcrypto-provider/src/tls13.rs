/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use super::aead;
use crate::error::mbedtls_err_to_rustls_error;
use crate::log::error;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use mbedtls::cipher::raw::CipherType;
use mbedtls::cipher::{Authenticated, Cipher, Decryption, Encryption, Fresh};
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PlainMessage, PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::hmac::Hmac;
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use rustls::crypto::CipherSuiteCommon;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion, SupportedCipherSuite, Tls13CipherSuite,
};

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &MbedHkdfUsingHmac(&super::hmac::HMAC_SHA256),
    aead_alg: &AeadAlgorithm(&aead::CHACHA20_POLY1305),
    quic: None,
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &MbedHkdfUsingHmac(&super::hmac::HMAC_SHA384),
    aead_alg: &AeadAlgorithm(&aead::AES256_GCM),
    quic: None,
});

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &MbedHkdfUsingHmac(&super::hmac::HMAC_SHA256),
    aead_alg: &AeadAlgorithm(&aead::AES128_GCM),
    quic: None,
});

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static aead::Algorithm);

impl Tls13AeadAlgorithm for AeadAlgorithm {
    fn encrypter(&self, enc_key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13MessageEncrypter { enc_key, iv, aead_algorithm: self.0 })
    }

    fn decrypter(&self, dec_key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13MessageDecrypter { dec_key, iv, aead_algorithm: self.0 })
    }

    fn key_len(&self) -> usize {
        self.0.key_length
    }

    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match self.0.cipher_type {
            CipherType::Aes128Gcm => Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv }),
            CipherType::Aes256Gcm => Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv }),
            CipherType::Chacha20Poly1305 => Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }),
            _ => Err(UnsupportedOperationError),
        }
    }
}

struct Tls13MessageEncrypter {
    enc_key: AeadKey,
    iv: Iv,
    aead_algorithm: &'static aead::Algorithm,
}

struct Tls13MessageDecrypter {
    dec_key: AeadKey,
    iv: Iv,
    aead_algorithm: &'static aead::Algorithm,
}

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&mut self, msg: OutboundPlainMessage, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        // let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let mut tag = [0u8; aead::TAG_LEN];

        let enc_key = self.enc_key.as_ref();
        let cipher = Cipher::<Encryption, Authenticated, Fresh>::new(
            self.aead_algorithm.cipher_id,
            self.aead_algorithm.cipher_mode,
            (enc_key.len() * 8) as _,
        )
        .map_err(mbedtls_err_to_rustls_error)?;

        let cipher = cipher
            .set_key_iv(enc_key, &nonce)
            .map_err(mbedtls_err_to_rustls_error)?;

        cipher
            .encrypt_auth_inplace(&aad, payload.as_mut(), &mut tag)
            .map_err(|err| match err {
                mbedtls::Error::CcmAuthFailed
                | mbedtls::Error::ChachapolyAuthFailed
                | mbedtls::Error::CipherAuthFailed
                | mbedtls::Error::GcmAuthFailed => Error::EncryptError,
                _ => mbedtls_err_to_rustls_error(err),
            })?;
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + aead::TAG_LEN
    }
}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < aead::TAG_LEN {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(payload.len());

        let dec_key = self.dec_key.as_ref();
        let cipher = Cipher::<Decryption, Authenticated, Fresh>::new(
            self.aead_algorithm.cipher_id,
            self.aead_algorithm.cipher_mode,
            (dec_key.len() * 8) as _,
        )
        .map_err(mbedtls_err_to_rustls_error)?;

        let cipher = cipher
            .set_key_iv(dec_key, &nonce)
            .map_err(mbedtls_err_to_rustls_error)?;

        let tag_offset = payload
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::General(String::from("Tag length overflow")))?;

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
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

struct MbedHkdfUsingHmac<'a>(&'a super::hmac::Hmac);

const ZERO_IKM: [u8; crate::hmac::Tag::MAX_LEN] = [0u8; crate::hmac::Tag::MAX_LEN];

impl<'a> Hkdf for MbedHkdfUsingHmac<'a> {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let md = self.0.hash_algorithm().hash_type;
        let capacity = self.0.hash_algorithm().output_len;
        let mut prf = crate::hmac::Tag::with_len(capacity);
        let prf_res = mbedtls::hash::Hkdf::hkdf_extract(md, salt, &ZERO_IKM[..capacity], prf.as_mut()).map(|_| prf);
        Box::new(MbedHkdfHmacExpander { hash_alg: self.0.hash_algorithm(), prf_res })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let md = self.0.hash_algorithm().hash_type;
        let mut prf = crate::hmac::Tag::with_len(self.0.hash_algorithm().output_len);
        let prf_res = mbedtls::hash::Hkdf::hkdf_extract(md, salt, secret, prf.as_mut()).map(|_| prf);
        Box::new(MbedHkdfHmacExpander { hash_alg: self.0.hash_algorithm(), prf_res })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        let mut prf = crate::hmac::Tag::with_len(okm.as_ref().len());
        prf.as_mut()
            .copy_from_slice(okm.as_ref());
        Box::new(MbedHkdfHmacExpander { hash_alg: self.0.hash_algorithm(), prf_res: Ok(prf) })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> rustls::crypto::hmac::Tag {
        self.0
            .with_key(key.as_ref())
            .sign(&[message])
    }
}

struct MbedHkdfHmacExpander {
    hash_alg: &'static super::hash::Algorithm,
    prf_res: Result<crate::hmac::Tag, mbedtls::Error>,
}

impl HkdfExpander for MbedHkdfHmacExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        let prf = self.prf_res.as_ref().map_err(|_err| {
            error!(
                "MbedHkdfExpander::expand_slice got mbedtls error from creation call in Hkdf trait: {:?}",
                _err
            );
            OutputLengthError
        })?;
        let info: Vec<u8> = info
            .iter()
            .flat_map(|&slice| slice)
            .cloned()
            .collect();
        mbedtls::hash::Hkdf::hkdf_expand(self.hash_alg.hash_type, prf.as_ref(), &info, output).map_err(|_err| {
            error!("MbedHkdfExpander::expand_slice got mbedtls error: {:?}", _err);
            OutputLengthError
        })
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        if let Err(_err) = self.prf_res.as_ref() {
            error!(
                "MbedHkdfExpander::expand_block got mbedtls error from creation call in Hkdf trait: {:?}",
                _err
            );
            return OkmBlock::new(&[]);
        }
        let prf = self
            .prf_res
            .as_ref()
            .expect("validated");
        let mut tag = crate::hmac::Tag::with_len(self.hash_alg.output_len);
        let info: Vec<u8> = info
            .iter()
            .flat_map(|&slice| slice)
            .cloned()
            .collect();
        let _ = mbedtls::hash::Hkdf::hkdf_expand(self.hash_alg.hash_type, prf.as_ref(), &info, tag.as_mut())
            .map_err(|_err| error!("MbedHkdfExpander::expand_block got mbedtls error: {:?}", _err));
        OkmBlock::new(tag.as_ref())
    }

    fn hash_len(&self) -> usize {
        self.hash_alg.output_len
    }
}

#[cfg(test)]
mod tests {
    use crate::aead::Algorithm;

    use super::*;
    const NONCE_LEN: usize = 12;
    const MAX_LEN: usize = 32;

    static UNSUPPORTED_ALGORITHM: Algorithm = Algorithm {
        key_length: 256 / 8,
        cipher_type: CipherType::Aes256Cbc,
        cipher_id: mbedtls::cipher::raw::CipherId::Aes,
        cipher_mode: mbedtls::cipher::raw::CipherMode::CBC,
    };

    #[test]
    fn test_extract_keys() {
        let algorithm = AeadAlgorithm(&aead::AES128_GCM);
        let key_bytes: [u8; MAX_LEN] = [1; MAX_LEN];
        let key = key_bytes.into();
        let iv_bytes: [u8; NONCE_LEN] = [2; NONCE_LEN];
        let iv = Iv::new(iv_bytes);
        let _result = algorithm.extract_keys(key, iv).unwrap();

        let algorithm = AeadAlgorithm(&aead::AES256_GCM);
        let key_bytes: [u8; MAX_LEN] = [3; MAX_LEN];
        let key = key_bytes.into();
        let iv_bytes: [u8; NONCE_LEN] = [4; NONCE_LEN];
        let iv = Iv::new(iv_bytes);
        let _result = algorithm.extract_keys(key, iv).unwrap();

        let algorithm = AeadAlgorithm(&aead::CHACHA20_POLY1305);
        let key_bytes: [u8; MAX_LEN] = [5; MAX_LEN];
        let key = key_bytes.into();
        let iv_bytes: [u8; NONCE_LEN] = [6; NONCE_LEN];
        let iv = Iv::new(iv_bytes);
        let _result = algorithm.extract_keys(key, iv).unwrap();

        let algorithm = AeadAlgorithm(&UNSUPPORTED_ALGORITHM);
        let key_bytes: [u8; MAX_LEN] = [7; MAX_LEN];
        let key = key_bytes.into();
        let iv_bytes: [u8; NONCE_LEN] = [8; NONCE_LEN];
        let iv = Iv::new(iv_bytes);
        let result = algorithm.extract_keys(key, iv).is_err();
        assert!(result);
    }

    #[test]
    fn test_expander_error() {
        let hash_alg = &crate::hash::MBED_SHA_256;
        let expander = MbedHkdfHmacExpander { hash_alg, prf_res: Err(mbedtls::Error::AesBadInputData) };
        assert!(expander
            .expand_slice(&[&[]], &mut [])
            .is_err());
        let okm_block = &OkmBlock::new(&[]);
        let expected: &[u8] = okm_block.as_ref();
        assert_eq!(expander.expand_block(&[&[]]).as_ref(), expected);
        assert_eq!(expander.hash_len(), hash_alg.output_len);
    }
}

#[cfg(bench)]
mod benchmarks {
    use rustls::crypto::tls13::{expand, Hkdf};

    use crate::hmac::HMAC_SHA256;

    struct ByteArray<const N: usize>([u8; N]);

    impl<const N: usize> From<[u8; N]> for ByteArray<N> {
        fn from(array: [u8; N]) -> Self {
            Self(array)
        }
    }

    #[bench]
    fn bench_mbedtls_hkdf(b: &mut test::Bencher) {
        bench_hkdf(b, &rustls::crypto::tls13::HkdfUsingHmac(&HMAC_SHA256));
    }

    #[bench]
    fn bench_rustls_hkdf_mbedtls_hmac(b: &mut test::Bencher) {
        bench_hkdf(b, &super::MbedHkdfUsingHmac(&HMAC_SHA256));
    }

    fn bench_hkdf(b: &mut test::Bencher, hkdf: &dyn Hkdf) {
        let ikm = &[0x0b; 22];
        let salt = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info: &[&[u8]] = &[&[0xf0, 0xf1, 0xf2], &[0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]];
        b.iter(|| {
            let output: ByteArray<42> = expand(
                hkdf.extract_from_secret(Some(salt), ikm)
                    .as_ref(),
                info,
            );
            assert_eq!(
                &output.0,
                &[
                    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
                    0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
                    0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
                ]
            );
        });
    }
}
