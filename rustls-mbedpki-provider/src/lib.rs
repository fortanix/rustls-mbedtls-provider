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
#![cfg_attr(not(test), no_std)]

extern crate alloc;

// This `extern crate` plus the `#![no_std]` attribute changes the default prelude from
// `std::prelude` to `core::prelude`. That forces one to _explicitly_ import (`use`) everything that
// is in `std::prelude` but not in `core::prelude`. This helps maintain no-std support as even
// developers that are not interested in, or aware of, no-std support and / or that never run
// `cargo build --no-default-features` locally will get errors when they rely on `std::prelude` API.
#[cfg(not(test))]
extern crate std;

use core::fmt::Display;

use chrono::NaiveDateTime;
use mbedtls::x509::VerifyError;
use rustls::pki_types::CertificateDer;
use rustls::SignatureScheme;

#[cfg(test)]
mod tests_common;

/// module for implementation of [`ClientCertVerifier`]
///
/// [`ClientCertVerifier`]: rustls::server::danger::ClientCertVerifier
pub mod client_cert_verifier;
/// module for implementation of [`ServerCertVerifier`]
///
/// [`ServerCertVerifier`]: rustls::client::danger::ServerCertVerifier
pub mod server_cert_verifier;

pub use client_cert_verifier::MbedTlsClientCertVerifier;
pub use server_cert_verifier::MbedTlsServerCertVerifier;
use utils::error::mbedtls_err_into_rustls_err;

/// A config about whether to check certificate validity period
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct CertActiveCheck {
    /// Accept expired certificates
    pub ignore_expired: bool,
    /// Accept certificates that are not yet active
    pub ignore_not_active_yet: bool,
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

/// Helper function to convert a [`mbedtls::x509::InvalidTimeError`] to a [`rustls::Error`]
fn time_err_to_err(_time_err: mbedtls::x509::InvalidTimeError) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
}

/// Verifies that certificates are active, i.e., `now` is between not_before and not_after for
/// each certificate
fn verify_certificates_active<'a>(
    chain: impl IntoIterator<Item = &'a mbedtls::x509::Certificate>,
    now: NaiveDateTime,
    active_check: &CertActiveCheck,
) -> Result<Result<(), VerifyError>, rustls::Error> {
    if active_check.ignore_expired && active_check.ignore_not_active_yet {
        return Ok(Ok(()));
    }

    for cert in chain.into_iter() {
        if !active_check.ignore_expired {
            let not_after = cert
                .not_after()
                .map_err(mbedtls_err_into_rustls_err)?
                .try_into()
                .map_err(time_err_to_err)?;
            if now > not_after {
                return Ok(Err(VerifyError::CERT_EXPIRED));
            }
        }
        if !active_check.ignore_not_active_yet {
            let not_before = cert
                .not_before()
                .map_err(mbedtls_err_into_rustls_err)?
                .try_into()
                .map_err(time_err_to_err)?;
            if now < not_before {
                return Ok(Err(VerifyError::CERT_FUTURE));
            }
        }
    }
    Ok(Ok(()))
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
    let hash_type = utils::hash::rustls_signature_scheme_to_mbedtls_hash_type(dss.scheme);

    // for tls 1.3, we need to verify the advertised curve in signature scheme matches the public key
    if is_tls13 {
        let signature_curve = utils::pk::rustls_signature_scheme_to_mbedtls_curve_id(dss.scheme);
        if !check_ec_signature_curve_match(signature_curve, pk) {
            return Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
    }

    if let Some(opts) = utils::pk::rustls_signature_scheme_to_mbedtls_pk_options(dss.scheme) {
        pk.set_options(opts);
    }

    let mut hash =
        utils::hash::buffer_for_hash_type(hash_type).ok_or_else(|| rustls::Error::General("unexpected hash type".into()))?;
    let hash_size = mbedtls::hash::Md::hash(hash_type, message, &mut hash).map_err(mbedtls_err_into_rustls_err)?;
    pk.verify(hash_type, &hash[..hash_size], dss.signature())
        .map_err(mbedtls_err_into_rustls_err)?;

    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
}

fn check_ec_signature_curve_match(signature_curve: mbedtls::pk::EcGroupId, pk: &mbedtls::pk::Pk) -> bool {
    match signature_curve {
        mbedtls::pk::EcGroupId::None => true,
        _ => pk
            .curve()
            .is_ok_and(|pk_curve| pk_curve == signature_curve),
    }
}

/// Helper function to convert a [`CertificateDer`] to [`mbedtls::x509::Certificate`]
pub fn rustls_cert_to_mbedtls_cert(cert: &CertificateDer) -> mbedtls::Result<mbedtls::alloc::Box<mbedtls::x509::Certificate>> {
    let cert = mbedtls::x509::Certificate::from_der(cert)?;
    Ok(cert)
}

pub(crate) fn merge_verify_result(
    first: &Result<(), VerifyError>,
    second: &Result<(), VerifyError>,
) -> Result<(), VerifyError> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(second_err)) => Err(*second_err),
        (Err(first_err), Ok(())) => Err(*first_err),
        (Err(first_err), Err(second_err)) => Err(*first_err | *second_err),
    }
}

/// A wrapper on [`mbedtls::x509::VerifyError`] to impl [`std::error::Error`] for it.
#[derive(Debug)]
pub struct VerifyErrorWrapper(pub VerifyError);

impl Display for VerifyErrorWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Debug;
        self.0.fmt(f)
    }
}

impl std::error::Error for VerifyErrorWrapper {}

#[cfg(test)]
mod tests {
    use super::*;
    use mbedtls::pk::EcGroupId;
    use mbedtls::x509::InvalidTimeError;
    use rustls::{CertificateError, Error};

    #[test]
    fn test_time_err_to_err() {
        // Create a sample InvalidTimeError
        let time_err = InvalidTimeError;

        // Call the function and check the result
        let result = time_err_to_err(time_err);
        assert_eq!(result, Error::InvalidCertificate(CertificateError::BadEncoding));
    }

    #[test]
    fn verify_error_wrapper_display() {
        let verify_error = VerifyError::CERT_EXPIRED; // Replace with actual instantiation of VerifyError
        let wrapper = VerifyErrorWrapper(verify_error);
        assert_eq!(format!("{}", wrapper), format!("{:?}", verify_error));
    }

    #[test]
    fn test_check_ec_signature_curve_match() {
        let cert = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let cert = rustls_cert_to_mbedtls_cert(&cert).unwrap();
        let pk = cert.public_key();
        assert!(check_ec_signature_curve_match(EcGroupId::None, pk));
        assert!(!check_ec_signature_curve_match(EcGroupId::SecP256R1, pk));
    }
}
