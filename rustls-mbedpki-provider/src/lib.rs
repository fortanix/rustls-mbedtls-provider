/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! rustls-mbedpki-provider
//!
//! rustls-mbedpki-provider is a pki provider for rustls based on [mbedtls].
//!
//! [mbedtls]: https://github.com/fortanix/rust-mbedtls

// Require docs for public APIs, deny unsafe code, etc.
#![forbid(unsafe_code, unused_must_use)]
#![cfg_attr(not(bench), forbid(unstable_features))]
#![deny(
    clippy::alloc_instead_of_core,
    clippy::clone_on_ref_ptr,
    clippy::std_instead_of_core,
    clippy::use_self,
    clippy::upper_case_acronyms,
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
// Enable documentation for all features on docs.rs
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]

use chrono::NaiveDateTime;
use mbedtls::hash::Type;
use pki_types::CertificateDer;
use rustls::SignatureScheme;
use std::sync::Arc;

#[cfg(test)]
mod tests_common;

/// module for implementation of [ClientCertVerifier]
pub mod client_cert_verifier;
/// module for implementation of [ServerCertVerifier]
pub mod server_cert_verifier;

pub use client_cert_verifier::MbedTlsClientCertVerifier;
pub use server_cert_verifier::MbedTlsServerCertVerifier;

/// A config about whether to check certificate validity period
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct CertActiveCheck {
    /// Accept expired certificates
    pub ignore_expired: bool,
    /// Accept certificates that are not yet active
    pub ignore_not_active_yet: bool,
}

/// Helper function to convert a [`CertificateDer`] to [`mbedtls::x509::Certificate`]
pub fn rustls_cert_to_mbedtls_cert(cert: &CertificateDer) -> mbedtls::Result<mbedtls::alloc::Box<mbedtls::x509::Certificate>> {
    let cert = mbedtls::x509::Certificate::from_der(cert)?;
    Ok(cert)
}

/// Converts an `mbedtls::Error` into a `rustls::Error`
pub fn mbedtls_err_into_rustls_err(err: mbedtls::Error) -> rustls::Error {
    mbedtls_err_into_rustls_err_with_error_msg(err, "")
}

/// All supported signature schemas
pub const SUPPORTED_SIGNATURE_SCHEMA: [SignatureScheme; 9] = [
    rustls::SignatureScheme::RSA_PSS_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA256,
];

/// Converts an `mbedtls::Error` into a `rustls::Error`; may include the provided `msg` in the
/// returned error (e.g., if returning a `rustls::Error::General` error).
pub fn mbedtls_err_into_rustls_err_with_error_msg(err: mbedtls::Error, msg: &str) -> rustls::Error {
    match err {
        mbedtls::Error::X509InvalidSignature |
        mbedtls::Error::RsaVerifyFailed => rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature),

        mbedtls::Error::X509CertUnknownFormat |
        mbedtls::Error::X509BadInputData => rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),

        // mbedtls::Error::X509AllocFailed |
        mbedtls::Error::X509BufferTooSmall |
        mbedtls::Error::X509CertVerifyFailed |
        mbedtls::Error::X509FatalError |
        mbedtls::Error::X509FeatureUnavailable |
        // mbedtls::Error::X509FileIoError |
        mbedtls::Error::X509InvalidAlg |
        mbedtls::Error::X509InvalidDate |
        mbedtls::Error::X509InvalidExtensions |
        mbedtls::Error::X509InvalidFormat |
        mbedtls::Error::X509InvalidSerial |
        mbedtls::Error::X509InvalidVersion |
        mbedtls::Error::X509SigMismatch |
        mbedtls::Error::X509UnknownOid |
        mbedtls::Error::X509UnknownSigAlg |
        mbedtls::Error::X509UnknownVersion => rustls::Error::InvalidCertificate(rustls::CertificateError::Other(Arc::new(err))),

        mbedtls::Error::X509InvalidName => rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),

        _ => rustls::Error::General(format!("{err}{sep}{msg}", sep = if msg.is_empty() {""} else {"\n"})),
    }
}

/// Helper function to convert rustls [`SignatureScheme`] to mbedtls [`Type`]
pub fn rustls_signature_scheme_to_mbedtls_hash_type(signature_scheme: SignatureScheme) -> Type {
    match signature_scheme {
        SignatureScheme::RSA_PKCS1_SHA1 => Type::Sha1,
        SignatureScheme::ECDSA_SHA1_Legacy => Type::Sha1,
        SignatureScheme::RSA_PKCS1_SHA256 => Type::Sha256,
        SignatureScheme::ECDSA_NISTP256_SHA256 => Type::Sha256,
        SignatureScheme::RSA_PKCS1_SHA384 => Type::Sha384,
        SignatureScheme::ECDSA_NISTP384_SHA384 => Type::Sha384,
        SignatureScheme::RSA_PKCS1_SHA512 => Type::Sha512,
        SignatureScheme::ECDSA_NISTP521_SHA512 => Type::Sha512,
        SignatureScheme::RSA_PSS_SHA256 => Type::Sha256,
        SignatureScheme::RSA_PSS_SHA384 => Type::Sha384,
        SignatureScheme::RSA_PSS_SHA512 => Type::Sha512,
        SignatureScheme::ED25519 => Type::None,
        SignatureScheme::ED448 => Type::None,
        SignatureScheme::Unknown(_) => Type::None,
        _ => Type::None,
    }
}

/// Helper function to convert rustls [`SignatureScheme`] to mbedtls [`mbedtls::pk::Options`]
pub fn rustls_signature_scheme_to_mbedtls_pk_options(signature_scheme: SignatureScheme) -> Option<mbedtls::pk::Options> {
    use mbedtls::pk::Options;
    use mbedtls::pk::RsaPadding;
    // reference: https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3
    match signature_scheme {
        SignatureScheme::RSA_PKCS1_SHA1 => None,
        SignatureScheme::ECDSA_SHA1_Legacy => None,
        SignatureScheme::ECDSA_NISTP256_SHA256 => None,
        SignatureScheme::ECDSA_NISTP384_SHA384 => None,
        SignatureScheme::ECDSA_NISTP521_SHA512 => None,
        SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PKCS1_SHA384 | SignatureScheme::RSA_PKCS1_SHA512 => {
            Some(Options::Rsa { padding: RsaPadding::Pkcs1V15 })
        }
        SignatureScheme::RSA_PSS_SHA256 => Some(Options::Rsa { padding: RsaPadding::Pkcs1V21 { mgf: Type::Sha256 } }),
        SignatureScheme::RSA_PSS_SHA384 => Some(Options::Rsa { padding: RsaPadding::Pkcs1V21 { mgf: Type::Sha384 } }),
        SignatureScheme::RSA_PSS_SHA512 => Some(Options::Rsa { padding: RsaPadding::Pkcs1V21 { mgf: Type::Sha512 } }),
        SignatureScheme::ED25519 => None,
        SignatureScheme::ED448 => None,
        SignatureScheme::Unknown(_) => None,
        _ => None,
    }
}

/// Helper function to convert rustls [`SignatureScheme`] to mbedtls [`mbedtls::pk::EcGroupId`]
pub fn rustls_signature_scheme_to_mbedtls_curve_id(signature_scheme: SignatureScheme) -> mbedtls::pk::EcGroupId {
    // reference: https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3
    use mbedtls::pk::EcGroupId;
    match signature_scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => EcGroupId::SecP256R1,
        SignatureScheme::ECDSA_NISTP384_SHA384 => EcGroupId::SecP384R1,
        SignatureScheme::ECDSA_NISTP521_SHA512 => EcGroupId::SecP521R1,
        SignatureScheme::ECDSA_SHA1_Legacy => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA1 => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA256 => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA384 => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA512 => EcGroupId::None,
        SignatureScheme::RSA_PSS_SHA256 => EcGroupId::None,
        SignatureScheme::RSA_PSS_SHA384 => EcGroupId::None,
        SignatureScheme::RSA_PSS_SHA512 => EcGroupId::None,
        SignatureScheme::ED25519 => EcGroupId::None,
        SignatureScheme::ED448 => EcGroupId::None,
        SignatureScheme::Unknown(_) => EcGroupId::None,
        _ => EcGroupId::None,
    }
}

/// Returns the size of the message digest given the hash type.
fn hash_size_bytes(hash_type: Type) -> Option<usize> {
    match hash_type {
        mbedtls::hash::Type::None => None,
        mbedtls::hash::Type::Md2 => Some(16),
        mbedtls::hash::Type::Md4 => Some(16),
        mbedtls::hash::Type::Md5 => Some(16),
        mbedtls::hash::Type::Sha1 => Some(20),
        mbedtls::hash::Type::Sha224 => Some(28),
        mbedtls::hash::Type::Sha256 => Some(32),
        mbedtls::hash::Type::Sha384 => Some(48),
        mbedtls::hash::Type::Sha512 => Some(64),
        mbedtls::hash::Type::Ripemd => Some(20), // this is MD_RIPEMD160
    }
}

/// Returns the a ready to use empty [`Vec<u8>`] for the message digest with given hash type.
pub fn buffer_for_hash_type(hash_type: Type) -> Option<Vec<u8>> {
    let size = hash_size_bytes(hash_type)?;
    Some(vec![0; size])
}

/// Verifies that certificates are active, i.e., `now` is between not_before and not_after for
/// each certificate
fn verify_certificates_active<'a>(
    chain: impl IntoIterator<Item = &'a mbedtls::x509::Certificate>,
    now: NaiveDateTime,
    active_check: &CertActiveCheck,
) -> Result<(), rustls::Error> {
    if active_check.ignore_expired && active_check.ignore_not_active_yet {
        return Ok(());
    }

    fn time_err_to_err(_time_err: mbedtls::x509::InvalidTimeError) -> rustls::Error {
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
    }

    for cert in chain.into_iter() {
        if !active_check.ignore_expired {
            let not_after = cert
                .not_after()
                .map_err(mbedtls_err_into_rustls_err)?
                .try_into()
                .map_err(time_err_to_err)?;
            if now > not_after {
                return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Expired));
            }
        }
        if !active_check.ignore_not_active_yet {
            let not_before = cert
                .not_before()
                .map_err(mbedtls_err_into_rustls_err)?
                .try_into()
                .map_err(time_err_to_err)?;
            if now < not_before {
                return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet));
            }
        }
    }
    Ok(())
}

/// Verifies the tls signature, matches verify functions in rustls `ClientCertVerifier` and
/// `ServerCertVerifier`
fn verify_tls_signature(
    message: &[u8],
    cert: &CertificateDer,
    dss: &rustls::DigitallySignedStruct,
    is_tls13: bool,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    let mut cert = rustls_cert_to_mbedtls_cert(cert).map_err(mbedtls_err_into_rustls_err)?;
    let pk = cert.public_key_mut();
    let hash_type = rustls_signature_scheme_to_mbedtls_hash_type(dss.scheme);

    // for tls 1.3, we need to verify the advertised curve in signaure scheme matches the public key
    if is_tls13 {
        let signature_curve = rustls_signature_scheme_to_mbedtls_curve_id(dss.scheme);
        match signature_curve {
            mbedtls::pk::EcGroupId::None => (),
            _ => {
                let curves_match = pk
                    .curve()
                    .is_ok_and(|pk_curve| pk_curve == signature_curve);
                if !curves_match {
                    return Err(rustls::Error::PeerMisbehaved(
                        rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
                    ));
                }
            }
        }
    }

    if let Some(opts) = rustls_signature_scheme_to_mbedtls_pk_options(dss.scheme) {
        pk.set_options(opts);
    }

    let mut hash = buffer_for_hash_type(hash_type).ok_or_else(|| rustls::Error::General("unexpected hash type".into()))?;
    let hash_size = mbedtls::hash::Md::hash(hash_type, message, &mut hash).map_err(mbedtls_err_into_rustls_err)?;
    pk.verify(hash_type, &hash[..hash_size], dss.signature())
        .map_err(mbedtls_err_into_rustls_err)?;

    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
}
