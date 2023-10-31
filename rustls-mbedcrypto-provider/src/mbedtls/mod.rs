pub(crate) mod aead;
pub(crate) mod agreement;
pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;

#[cfg(feature = "tls12")]
pub mod tls12;
pub mod tls13;

use mbedtls::rng::Random;

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
/// [*ring*]: https://github.com/fortanix/rust-mbedtls
pub static MBEDTLS: &'static dyn rustls::crypto::CryptoProvider = &Mbedtls;

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
use rustls::SupportedCipherSuite;
