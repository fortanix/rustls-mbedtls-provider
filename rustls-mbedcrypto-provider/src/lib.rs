/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! rustls-mbedcrypto-provider
//!
//! rustls-mbedcrypto-provider is a crypto provider for rustls based on [mbedtls].
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
// Relax these clippy lints:
// - ptr_arg: this triggers on references to type aliases that are Vec
//   underneath.
// - too_many_arguments: some things just need a lot of state, wrapping it
//   doesn't necessarily make it easier to follow what's going on
// - new_ret_no_self: we sometimes return `Arc<Self>`, which seems fine
// - single_component_path_imports: our top-level `use log` import causes
//   a false positive, https://github.com/rust-lang/rust-clippy/issues/5210
// - new_without_default: for internal constructors, the indirection is not
//   helpful
#![allow(
    clippy::too_many_arguments,
    clippy::new_ret_no_self,
    clippy::ptr_arg,
    clippy::single_component_path_imports,
    clippy::new_without_default
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

// log for logging (optional).
#[cfg(feature = "logging")]
use log;

#[cfg(not(feature = "logging"))]
#[allow(unused_imports)]
pub(crate) mod log {
    macro_rules! ignore_log ( ($($tt:tt)*) => {{}} );
    pub(crate) use ignore_log as trace;
    pub(crate) use ignore_log as debug;
    pub(crate) use ignore_log as warn;
    pub(crate) use ignore_log as error;
}

pub(crate) mod aead;
pub(crate) mod agreement;
pub(crate) mod error;
pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;

/// Message signing interfaces.
pub mod sign;
/// Supported signature verify algorithms
pub mod signature_verify_algo;
/// TLS1.2 ciphersuites implementation.
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
/// TLS1.3 ciphersuites implementation.
pub(crate) mod tls13;

use mbedtls::rng::Random;
use rustls::{SignatureScheme, SupportedCipherSuite, WebPkiSupportedAlgorithms};

/// RNG supported by *mbedtls*
pub mod rng {
    #[cfg(not(any(target_env = "sgx", feature = "rdrand")))]
    use mbedtls::rng::{CtrDrbg, OsEntropy};

    #[cfg(any(target_env = "sgx", feature = "rdrand"))]
    use mbedtls::rng::Rdrand;

    /// Get a RNG supported by *mbedtls*
    #[cfg(not(any(target_env = "sgx", feature = "rdrand")))]
    pub fn rng_new() -> Option<CtrDrbg> {
        let entropy = alloc::sync::Arc::new(OsEntropy::new());
        CtrDrbg::new(entropy, None).ok()
    }

    /// Get a RNG supported by *mbedtls*
    #[cfg(any(target_env = "sgx", feature = "rdrand"))]
    pub const fn rng_new() -> Option<Rdrand> {
        Some(Rdrand)
    }
}

/// A `CryptoProvider` backed by the [*mbedtls*] crate.
///
/// [*mbedtls*]: https://github.com/fortanix/rust-mbedtls
pub static MBEDTLS: &'static dyn rustls::crypto::CryptoProvider = &Mbedtls;

/// Crypto provider based on the [*mbedtls*] crate.
///
/// [*mbedtls*]: https://github.com/fortanix/rust-mbedtls
#[derive(Debug)]
struct Mbedtls;

impl rustls::crypto::CryptoProvider for Mbedtls {
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        rng::rng_new()
            .ok_or(rustls::crypto::GetRandomFailed)?
            .random(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        ALL_CIPHER_SUITES
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn rustls::crypto::SupportedKxGroup] {
        ALL_KX_GROUPS
    }

    fn load_private_key(
        &self,
        key_der: pki_types::PrivateKeyDer<'static>,
    ) -> Result<alloc::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Ok(alloc::sync::Arc::new(MbedTlsPkSigningKey::new(&key_der)?))
    }

    fn signature_verification_algorithms(&self) -> WebPkiSupportedAlgorithms {
        SUPPORTED_SIG_ALGS
    }
}

/// The cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

/// A list of all the cipher suites supported by the rustls *mbedtls* provider.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS1.2 suites
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// All defined cipher suites supported by *mbedtls* appear in this module.
pub mod cipher_suite {
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256};
}

/// A `WebPkiSupportedAlgorithms` value that reflects pki's capabilities when
/// compiled against *mbedtls*.
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        signature_verify_algo::ECDSA_P256_SHA256,
        signature_verify_algo::ECDSA_P384_SHA384,
        signature_verify_algo::RSA_PKCS1_SHA256,
        signature_verify_algo::RSA_PKCS1_SHA384,
        signature_verify_algo::RSA_PKCS1_SHA512,
        signature_verify_algo::RSA_PSS_SHA256,
        signature_verify_algo::RSA_PSS_SHA384,
        signature_verify_algo::RSA_PSS_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[signature_verify_algo::ECDSA_P384_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[signature_verify_algo::ECDSA_P256_SHA256],
        ),
        (SignatureScheme::RSA_PKCS1_SHA512, &[signature_verify_algo::RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[signature_verify_algo::RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[signature_verify_algo::RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PSS_SHA512, &[signature_verify_algo::RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[signature_verify_algo::RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[signature_verify_algo::RSA_PSS_SHA256]),
    ],
};

/// All defined key exchange groups supported by *mbedtls* appear in this module.
///
/// [`ALL_KX_GROUPS`] is provided as an array of all of these values.
pub mod kx_group {
    pub use super::kx::SECP256R1;
    pub use super::kx::SECP384R1;
    pub use super::kx::SECP521R1;
    pub use super::kx::X25519;
}

pub use kx::ALL_KX_GROUPS;
use sign::MbedTlsPkSigningKey;
