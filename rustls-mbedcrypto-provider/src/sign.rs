use alloc::string::String;
use alloc::vec;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::fmt::Debug;
use mbedtls::pk::{EcGroupId, ECDSA_MAX_LEN};
use rustls::SignatureScheme;
use std::sync::Mutex;
use utils::error::mbedtls_err_into_rustls_err;
use utils::hash::{buffer_for_hash_type, rustls_signature_scheme_to_mbedtls_hash_type};
use utils::pk::rustls_signature_scheme_to_mbedtls_pk_options;

struct MbedTlsSigner(Arc<Mutex<mbedtls::pk::Pk>>, SignatureScheme);

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

    fn scheme(&self) -> SignatureScheme {
        self.1
    }
}

/// A [`SigningKey`] implemented by using [`mbedtls`]
///
/// [`SigningKey`]: rustls::sign::SigningKey
pub struct MbedTlsPkSigningKey {
    pk: Arc<Mutex<mbedtls::pk::Pk>>,
    pk_type: mbedtls::pk::Type,
    signature_algorithm: rustls::SignatureAlgorithm,
    ec_signature_scheme: Option<SignatureScheme>,
}

impl Debug for MbedTlsPkSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MbedTlsPkSigningKey")
            .field("pk", &"Arc<Mutex<mbedtls::pk::Pk>>")
            .field("pk_type", &self.pk_type)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("ec_signature_scheme", &self.ec_signature_scheme)
            .finish()
    }
}

impl MbedTlsPkSigningKey {
    /// Make a new `MbedTlsPkSigningKey` from a DER encoding.
    pub fn new(der: &pki_types::PrivateKeyDer<'_>) -> Result<Self, rustls::Error> {
        let pk = mbedtls::pk::Pk::from_private_key(der.secret_der(), None)
            .map_err(|err| rustls::Error::Other(rustls::OtherError(alloc::sync::Arc::new(err))))?;
        let pk_type = pk.pk_type();
        let signature_algorithm = pk_type_to_signature_algo(pk_type);
        let ec_signature_scheme = if signature_algorithm == rustls::SignatureAlgorithm::ECDSA {
            Some(
                match pk
                    .curve()
                    .map_err(|err| rustls::Error::Other(rustls::OtherError(alloc::sync::Arc::new(err))))?
                {
                    EcGroupId::SecP256R1 => SignatureScheme::ECDSA_NISTP256_SHA256,
                    EcGroupId::SecP384R1 => SignatureScheme::ECDSA_NISTP384_SHA384,
                    EcGroupId::SecP521R1 => SignatureScheme::ECDSA_NISTP521_SHA512,
                    _ => {
                        return Err(rustls::Error::General(String::from(
                            "MbedTlsPkSigningKey: unsupported ec curve",
                        )))
                    }
                },
            )
        } else {
            None
        };
        Ok(Self {
            pk: alloc::sync::Arc::new(std::sync::Mutex::new(pk)),
            pk_type,
            signature_algorithm,
            ec_signature_scheme,
        })
    }
}

const RSA_SIGNATURE_SCHEME_PREFER_LIST: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl rustls::sign::SigningKey for MbedTlsPkSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        match self.pk_type {
            mbedtls::pk::Type::Rsa | mbedtls::pk::Type::RsaAlt | mbedtls::pk::Type::RsassaPss => {
                // choose a rsa schema
                for scheme in RSA_SIGNATURE_SCHEME_PREFER_LIST {
                    if offered.contains(scheme) {
                        let signer = MbedTlsSigner(Arc::clone(&self.pk), *scheme);
                        return Some(Box::new(signer));
                    }
                }
                None
            }
            mbedtls::pk::Type::Eckey | mbedtls::pk::Type::EckeyDh | mbedtls::pk::Type::Ecdsa => {
                let scheme = self
                    .ec_signature_scheme
                    .expect("validated");
                if offered.contains(&scheme) {
                    let signer = MbedTlsSigner(Arc::clone(&self.pk), scheme);
                    return Some(Box::new(signer));
                }
                None
            }
            _ => None,
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.signature_algorithm
    }
}

fn pk_type_to_signature_algo(pk_type: mbedtls::pk::Type) -> rustls::SignatureAlgorithm {
    use rustls::SignatureAlgorithm;
    match pk_type {
        mbedtls::pk::Type::Rsa => SignatureAlgorithm::RSA,
        mbedtls::pk::Type::Ecdsa => SignatureAlgorithm::ECDSA,
        mbedtls::pk::Type::RsassaPss => SignatureAlgorithm::RSA,
        mbedtls::pk::Type::RsaAlt => SignatureAlgorithm::RSA,
        mbedtls::pk::Type::Eckey => SignatureAlgorithm::ECDSA,
        mbedtls::pk::Type::EckeyDh => SignatureAlgorithm::Unknown(255),
        mbedtls::pk::Type::Custom => SignatureAlgorithm::Unknown(255),
        mbedtls::pk::Type::None => SignatureAlgorithm::Unknown(255),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{sign::SigningKey, SignatureAlgorithm};

    #[test]
    fn test_signing_key() {
        let ec_key_pem = include_str!("../../test-ca/ecdsa/end.key");
        let der: pki_types::PrivateKeyDer<'static> =
            rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(ec_key_pem.as_bytes()))
                .next()
                .unwrap()
                .unwrap()
                .into();
        let key = MbedTlsPkSigningKey::new(&der).unwrap();
        assert_eq!("MbedTlsPkSigningKey { pk: \"Arc<Mutex<mbedtls::pk::Pk>>\", pk_type: Eckey, signature_algorithm: ECDSA, ec_signature_scheme: Some(ECDSA_NISTP256_SHA256) }", format!("{:?}", key));
        assert!(key
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA1])
            .is_none());
        let res = key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256]);
        assert!(res.is_some());
        assert_eq!(
            "Some(MbedTlsSigner(\"Arc<Mutex<mbedtls::pk::Pk>>\", ECDSA_NISTP256_SHA256))",
            format!("{:?}", res)
        );
    }

    #[test]
    fn test_pk_type_to_signature_algo() {
        assert_eq!(pk_type_to_signature_algo(mbedtls::pk::Type::Rsa), SignatureAlgorithm::RSA);
        assert_eq!(pk_type_to_signature_algo(mbedtls::pk::Type::Ecdsa), SignatureAlgorithm::ECDSA);
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::RsassaPss),
            SignatureAlgorithm::RSA
        );
        assert_eq!(pk_type_to_signature_algo(mbedtls::pk::Type::RsaAlt), SignatureAlgorithm::RSA);
        assert_eq!(pk_type_to_signature_algo(mbedtls::pk::Type::Eckey), SignatureAlgorithm::ECDSA);
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::EckeyDh),
            SignatureAlgorithm::Unknown(255)
        );
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::Custom),
            SignatureAlgorithm::Unknown(255)
        );
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::None),
            SignatureAlgorithm::Unknown(255)
        );
    }
}
