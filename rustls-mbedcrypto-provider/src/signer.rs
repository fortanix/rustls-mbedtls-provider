use alloc::vec;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::fmt::Debug;
use mbedtls::pk::ECDSA_MAX_LEN;
use std::sync::Mutex;
use utils::error::mbedtls_err_into_rustls_err;
use utils::hash::{buffer_for_hash_type, rustls_signature_scheme_to_mbedtls_hash_type};
use utils::pk::{rustls_signature_scheme_to_mbedtls_pk_options, rustls_signature_scheme_to_mbedtls_pk_type};

///
struct MbedTlsSigner(Arc<Mutex<mbedtls::pk::Pk>>, rustls::SignatureScheme);

impl Debug for MbedTlsSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MbedTlsSigner")
            .field(&"Arc<Mutex<mbedtls::pk::Pk>>")
            .field(&self.1)
            .finish()
    }
}

impl rustls::sign::Signer for MbedTlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let hash_type = rustls_signature_scheme_to_mbedtls_hash_type(self.1);
        let mut hash = buffer_for_hash_type(hash_type).ok_or_else(|| rustls::Error::General("unexpected hash type".into()))?;
        let hash_size = mbedtls::hash::Md::hash(hash_type, message, &mut hash).map_err(mbedtls_err_into_rustls_err)?;

        let mut pk = self
            .0
            .lock()
            .expect("poisoned PK lock!");
        if let Some(opts) = rustls_signature_scheme_to_mbedtls_pk_options(self.1) {
            pk.set_options(opts);
        }

        fn sig_len_for_pk(pk: &mbedtls::pk::Pk) -> usize {
            match pk.pk_type() {
                mbedtls::pk::Type::Eckey | mbedtls::pk::Type::EckeyDh | mbedtls::pk::Type::Ecdsa => ECDSA_MAX_LEN,
                _ => pk.len() / 8,
            }
        }
        let mut sig = vec![0; sig_len_for_pk(&pk)];
        let sig_len = pk
            .sign(
                hash_type,
                &hash[..hash_size],
                &mut sig,
                &mut crate::rng::rng_new().ok_or(rustls::Error::FailedToGetRandomBytes)?,
            )
            .map_err(mbedtls_err_into_rustls_err)?;
        sig.truncate(sig_len);
        Ok(sig)
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.1
    }
}

/// A [`SigningKey`] implemented by using [`mbedtls`]
///
/// [`SigningKey`]: rustls::sign::SigningKey
pub struct MbedTlsPkSigningKey(pub Arc<Mutex<mbedtls::pk::Pk>>);

impl Debug for MbedTlsPkSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MbedTlsPkSigningKey")
            .field(&"Arc<Mutex<mbedtls::pk::Pk>>")
            .finish()
    }
}

impl rustls::sign::SigningKey for MbedTlsPkSigningKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        for scheme in offered {
            let scheme_type = rustls_signature_scheme_to_mbedtls_pk_type(scheme);
            if let Some(scheme_type) = scheme_type {
                if scheme_type
                    == self
                        .0
                        .lock()
                        .expect("poisoned pk lock")
                        .pk_type()
                {
                    let signer = MbedTlsSigner(self.0.clone(), *scheme);
                    return Some(Box::new(signer));
                }
            }
        }
        None
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        use rustls::SignatureAlgorithm;
        match self
            .0
            .lock()
            .expect("poisoned pk lock")
            .pk_type()
        {
            mbedtls::pk::Type::Rsa => SignatureAlgorithm::RSA,
            mbedtls::pk::Type::Ecdsa => SignatureAlgorithm::ECDSA,
            mbedtls::pk::Type::RsassaPss => SignatureAlgorithm::RSA,
            mbedtls::pk::Type::Eckey => SignatureAlgorithm::ECDSA,
            mbedtls::pk::Type::RsaAlt => SignatureAlgorithm::DSA,
            mbedtls::pk::Type::EckeyDh => SignatureAlgorithm::Anonymous,
            mbedtls::pk::Type::Custom => SignatureAlgorithm::Anonymous,
            mbedtls::pk::Type::None => SignatureAlgorithm::Anonymous,
        }
    }
}
