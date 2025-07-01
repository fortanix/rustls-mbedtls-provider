use alloc::string::String;
use alloc::vec;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::fmt::{self, Debug};
use mbedtls::pk::{EcGroupId, ECDSA_MAX_LEN};
use mbedtls::rng::RngCallback;
use rustls::{pki_types, SignatureScheme};
use std::sync::Mutex;
use utils::error::mbedtls_err_into_rustls_err;
use utils::hash::{buffer_for_hash_type, rustls_signature_scheme_to_mbedtls_hash_type};
use utils::pk::{get_signature_schema_from_offered, pk_type_to_signature_algo, rustls_signature_scheme_to_mbedtls_pk_options};

struct MbedTlsSigner<T: RngCallback> {
    pk: Arc<Mutex<mbedtls::pk::Pk>>,
    signature_scheme: SignatureScheme,
    rng_provider: fn() -> Option<T>,
}

impl<T: RngCallback> Debug for MbedTlsSigner<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MbedTlsSigner")
            .field(&"Arc<Mutex<mbedtls::pk::Pk>>")
            .field(&self.signature_scheme)
            .finish()
    }
}

impl<T: RngCallback> rustls::sign::Signer for MbedTlsSigner<T> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let hash_type = rustls_signature_scheme_to_mbedtls_hash_type(self.signature_scheme);
        let mut hash = buffer_for_hash_type(hash_type).ok_or_else(|| rustls::Error::General("unexpected hash type".into()))?;
        let hash_size = mbedtls::hash::Md::hash(hash_type, message, &mut hash).map_err(mbedtls_err_into_rustls_err)?;

        let mut pk = self
            .pk
            .lock()
            .expect("poisoned PK lock!");
        if let Some(opts) = rustls_signature_scheme_to_mbedtls_pk_options(self.signature_scheme) {
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
                &mut (self.rng_provider)().ok_or(rustls::Error::FailedToGetRandomBytes)?,
            )
            .map_err(mbedtls_err_into_rustls_err)?;
        sig.truncate(sig_len);
        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

struct MbedTlsPkSigningKey {
    pk: Arc<Mutex<mbedtls::pk::Pk>>,
    pk_type: mbedtls::pk::Type,
    signature_algorithm: rustls::SignatureAlgorithm,
    ec_signature_scheme: Option<SignatureScheme>,
    rsa_scheme_prefer_order_list: &'static [SignatureScheme],
}

impl Debug for MbedTlsPkSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MbedTlsPkSigningKeyWrapper")
            .field("pk", &"Arc<Mutex<mbedtls::pk::Pk>>")
            .field("pk_type", &self.pk_type)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("ec_signature_scheme", &self.ec_signature_scheme)
            .finish()
    }
}

/// A type implements [`SigningKey`] by using [`mbedtls`].
///
/// [`SigningKey`]: rustls::sign::SigningKey
pub struct MbedTlsPkSigningKeyWrapper<T: RngCallback> {
    signing_key: MbedTlsPkSigningKey,
    rng_provider: fn() -> Option<T>,
}

impl<T: RngCallback> Debug for MbedTlsPkSigningKeyWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MbedTlsPkSigningKeyWrapper")
            .field("signing_key", &self.signing_key)
            .finish()
    }
}

impl<T: RngCallback> MbedTlsPkSigningKeyWrapper<T> {
    /// Make a new [`MbedTlsPkSigningKeyWrapper`] from a DER encoding.
    pub fn new(der: &pki_types::PrivateKeyDer<'_>, rng_provider: fn() -> Option<T>) -> Result<Self, rustls::Error> {
        let pk = mbedtls::pk::Pk::from_private_key(der.secret_der(), None)
            .map_err(|err| rustls::Error::Other(rustls::OtherError(Arc::new(err))))?;
        Self::from_pk(pk, rng_provider)
    }

    /// Make a new [`MbedTlsPkSigningKeyWrapper`] from a [`mbedtls::pk::Pk`].
    pub fn from_pk(pk: mbedtls::pk::Pk, rng_provider: fn() -> Option<T>) -> Result<Self, rustls::Error> {
        let pk_type = pk.pk_type();
        let signature_algorithm = pk_type_to_signature_algo(pk_type).ok_or(rustls::Error::General(String::from(
            "MbedTlsPkSigningKeyWrapper: invalid pk type",
        )))?;
        let ec_signature_scheme = if signature_algorithm == rustls::SignatureAlgorithm::ECDSA {
            Some(
                match pk
                    .curve()
                    .map_err(|err| rustls::Error::Other(rustls::OtherError(Arc::new(err))))?
                {
                    EcGroupId::SecP256R1 => SignatureScheme::ECDSA_NISTP256_SHA256,
                    EcGroupId::SecP384R1 => SignatureScheme::ECDSA_NISTP384_SHA384,
                    EcGroupId::SecP521R1 => SignatureScheme::ECDSA_NISTP521_SHA512,
                    _ => {
                        return Err(rustls::Error::General(String::from(
                            "MbedTlsPkSigningKeyWrapper: unsupported ec curve",
                        )))
                    }
                },
            )
        } else {
            None
        };
        Ok(Self {
            signing_key: MbedTlsPkSigningKey {
                pk: Arc::new(Mutex::new(pk)),
                pk_type,
                signature_algorithm,
                ec_signature_scheme,
                rsa_scheme_prefer_order_list: DEFAULT_RSA_SIGNATURE_SCHEME_PREFER_LIST,
            },
            rng_provider,
        })
    }

    /// Change the rsa signature scheme prefer list
    pub fn set_rsa_signature_scheme_prefer_list(&mut self, prefer_order_list: &'static [SignatureScheme]) {
        self.signing_key
            .rsa_scheme_prefer_order_list = prefer_order_list
    }
}

/// An ordered list of RSA [`SignatureScheme`] used for choosing scheme in [`rustls::sign::SigningKey`]
pub const DEFAULT_RSA_SIGNATURE_SCHEME_PREFER_LIST: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl<T: RngCallback + 'static> rustls::sign::SigningKey for MbedTlsPkSigningKeyWrapper<T> {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = get_signature_schema_from_offered(
            self.signing_key.pk_type,
            offered,
            self.signing_key.ec_signature_scheme,
            self.signing_key
                .rsa_scheme_prefer_order_list,
        )?;
        let signer = MbedTlsSigner {
            pk: Arc::clone(&self.signing_key.pk),
            signature_scheme: scheme,
            rng_provider: self.rng_provider,
        };
        Some(Box::new(signer))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.signing_key.signature_algorithm
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
        let key = MbedTlsPkSigningKeyWrapper::new(&der, crate::rng::rng_new).unwrap();
        assert_eq!(format!("{key:?}"), "MbedTlsPkSigningKeyWrapper { signing_key: MbedTlsPkSigningKeyWrapper { pk: \"Arc<Mutex<mbedtls::pk::Pk>>\", pk_type: Eckey, signature_algorithm: ECDSA, ec_signature_scheme: Some(ECDSA_NISTP256_SHA256) } }");
        assert!(key
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA1])
            .is_none());
        let res = key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256]);
        assert!(res.is_some());
        assert_eq!(
            format!("{res:?}"),
            "Some(MbedTlsSigner(\"Arc<Mutex<mbedtls::pk::Pk>>\", ECDSA_NISTP256_SHA256))",
        );
    }

    #[test]
    fn test_pk_type_to_signature_algo() {
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::Rsa),
            Some(SignatureAlgorithm::RSA)
        );
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::Ecdsa),
            Some(SignatureAlgorithm::ECDSA)
        );
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::RsassaPss),
            Some(SignatureAlgorithm::RSA)
        );
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::RsaAlt),
            Some(SignatureAlgorithm::RSA)
        );
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::Eckey),
            Some(SignatureAlgorithm::ECDSA)
        );
        assert_eq!(
            pk_type_to_signature_algo(mbedtls::pk::Type::EckeyDh),
            Some(SignatureAlgorithm::ECDSA)
        );
        assert_eq!(pk_type_to_signature_algo(mbedtls::pk::Type::Custom), None);
        assert_eq!(pk_type_to_signature_algo(mbedtls::pk::Type::None), None);
    }
}
