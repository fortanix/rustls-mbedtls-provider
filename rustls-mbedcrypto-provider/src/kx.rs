/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::sync::Mutex;
use std::sync::OnceLock;

use super::agreement;
use crate::error::mbedtls_err_to_rustls_error;
use crate::rng::MbedRng;

use alloc::boxed::Box;
use alloc::fmt;
use alloc::format;
use alloc::vec::Vec;
use crypto::SupportedKxGroup;
use mbedtls::bignum::Mpi;
use mbedtls::rng::Random;
use mbedtls::rng::RngCallback;
use mbedtls::{
    ecp::EcPoint,
    pk::{EcGroup, Pk as PkMbed},
};
use rustls::crypto;
use rustls::crypto::ActiveKeyExchange;
use rustls::ffdhe_groups;
use rustls::ffdhe_groups::FfdheGroup;
use rustls::Error;
use rustls::NamedGroup;
/// An EC key-exchange group supported by *mbedtls*.
///
/// All possible instances of this type are provided by the library in
/// the `ALL_KX_GROUPS` array.
pub struct KxGroup<T: RngCallback> {
    /// The IANA "TLS Supported Groups" name of the group
    name: NamedGroup,

    /// The corresponding agreement algorithm
    agreement_algorithm: &'static agreement::Algorithm,

    /// Callback to produce RNGs when needed
    rng_provider: fn() -> Option<T>,
}

impl<T: RngCallback> KxGroup<T> {
    /// Create a new [`KxGroup`] with given RNG provider callback.
    pub const fn with_rng_provider<F: RngCallback>(&self, rng_provider: fn() -> Option<F>) -> KxGroup<F> {
        KxGroup { rng_provider, name: self.name, agreement_algorithm: self.agreement_algorithm }
    }
}

impl<T: RngCallback> fmt::Debug for KxGroup<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KxGroup")
            .field("name", &self.name)
            .field("agreement_algorithm", &self.agreement_algorithm.group_id)
            .finish()
    }
}

impl<T: RngCallback + 'static> SupportedKxGroup for KxGroup<T> {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut rng = (self.rng_provider)().ok_or(Error::FailedToGetRandomBytes)?;

        #[allow(unused_mut)]
        let mut priv_key = generate_ec_key(self.agreement_algorithm.group_id, &mut rng)?;

        // Only run fips check on applied NamedGroups
        #[cfg(feature = "fips")]
        match self.name {
            NamedGroup::secp256r1 | NamedGroup::secp384r1 | NamedGroup::secp521r1 => {
                crate::fips_utils::fips_ec_pct(&mut priv_key, self.agreement_algorithm.group_id, &mut rng)?;
            }
            _ => (),
        }

        Ok(Box::new(KeyExchange {
            name: self.name,
            agreement_algorithm: self.agreement_algorithm,
            priv_key,
            pub_key: OnceLock::new(),
            rng_provider: self.rng_provider,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

#[inline]
fn generate_ec_key<F: Random>(group_id: mbedtls::pk::EcGroupId, rng: &mut F) -> Result<PkMbed, Error> {
    PkMbed::generate_ec(rng, group_id)
        .map_err(|err| Error::General(format!("Got error when generating ec key, mbedtls error: {}", err)))
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: &dyn SupportedKxGroup = X25519_KX_GROUP;
/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519_KX_GROUP: &KxGroup<MbedRng> = &KxGroup {
    name: NamedGroup::X25519,
    agreement_algorithm: &agreement::X25519,
    rng_provider: crate::rng::rng_new,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: &dyn SupportedKxGroup = SECP256R1_KX_GROUP;
/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1_KX_GROUP: &KxGroup<MbedRng> = &KxGroup {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &agreement::ECDH_P256,
    rng_provider: crate::rng::rng_new,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: &dyn SupportedKxGroup = SECP384R1_KX_GROUP;
/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1_KX_GROUP: &KxGroup<MbedRng> = &KxGroup {
    name: NamedGroup::secp384r1,
    agreement_algorithm: &agreement::ECDH_P384,
    rng_provider: crate::rng::rng_new,
};

/// Ephemeral ECDH on secp521r1 (aka NIST-P521)
pub static SECP521R1: &dyn SupportedKxGroup = SECP521R1_KX_GROUP;
/// Ephemeral ECDH on secp521r1 (aka NIST-P521)
pub static SECP521R1_KX_GROUP: &KxGroup<MbedRng> = &KxGroup {
    name: NamedGroup::secp521r1,
    agreement_algorithm: &agreement::ECDH_P521,
    rng_provider: crate::rng::rng_new,
};

/// DHE group [FFDHE2048](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1)
pub static FFDHE2048: &dyn SupportedKxGroup = FFDHE2048_KX_GROUP;
/// DHE group [FFDHE2048](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1)
pub static FFDHE2048_KX_GROUP: &DheKxGroup<MbedRng> = &DheKxGroup {
    named_group: NamedGroup::FFDHE2048,
    group: ffdhe_groups::FFDHE2048,
    priv_key_len: 36,
    rng_provider: crate::rng::rng_new,
};

/// DHE group [FFDHE3072](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.2)
pub static FFDHE3072: &dyn SupportedKxGroup = FFDHE3072_KX_GROUP;
/// DHE group [FFDHE3072](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.2)
pub static FFDHE3072_KX_GROUP: &DheKxGroup<MbedRng> = &DheKxGroup {
    named_group: NamedGroup::FFDHE3072,
    group: ffdhe_groups::FFDHE3072,
    priv_key_len: 40,
    rng_provider: crate::rng::rng_new,
};

/// DHE group [FFDHE4096](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.3)
pub static FFDHE4096: &dyn SupportedKxGroup = FFDHE4096_KX_GROUP;
/// DHE group [FFDHE3072](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.2)
pub static FFDHE4096_KX_GROUP: &DheKxGroup<MbedRng> = &DheKxGroup {
    named_group: NamedGroup::FFDHE4096,
    group: ffdhe_groups::FFDHE4096,
    priv_key_len: 48,
    rng_provider: crate::rng::rng_new,
};

/// DHE group [FFDHE6144](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.4)
pub static FFDHE6144: &dyn SupportedKxGroup = FFDHE6144_KX_GROUP;
/// DHE group [FFDHE6144](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.4)
pub static FFDHE6144_KX_GROUP: &DheKxGroup<MbedRng> = &DheKxGroup {
    named_group: NamedGroup::FFDHE6144,
    group: ffdhe_groups::FFDHE6144,
    priv_key_len: 56,
    rng_provider: crate::rng::rng_new,
};

/// DHE group [FFDHE8192](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.5)
pub static FFDHE8192: &dyn SupportedKxGroup = FFDHE8192_KX_GROUP;
/// DHE group [FFDHE8192](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.5)
pub static FFDHE8192_KX_GROUP: &DheKxGroup<MbedRng> = &DheKxGroup {
    named_group: NamedGroup::FFDHE8192,
    group: ffdhe_groups::FFDHE8192,
    priv_key_len: 64,
    rng_provider: crate::rng::rng_new,
};

/// A list of all the key exchange groups supported by mbedtls.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    // ECDHE groups:
    X25519, SECP256R1, SECP384R1, SECP521R1, // fmt
    // (FF)DHE groups:
    FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192,
];

/// An in-progress ECDH key exchange.  This has the algorithm,
/// our private key, and our public key.
struct KeyExchange<T: RngCallback> {
    name: NamedGroup,
    /// The corresponding [`agreement::Algorithm`]
    agreement_algorithm: &'static agreement::Algorithm,
    /// Private key
    priv_key: PkMbed,
    /// Public key in binary format [`EcPoint`] without compression
    pub_key: OnceLock<Vec<u8>>,
    /// Callback to produce RNGs when needed
    rng_provider: fn() -> Option<T>,
}

impl<T: RngCallback> KeyExchange<T> {
    fn get_pub_key(&self) -> mbedtls::Result<Vec<u8>> {
        let group = EcGroup::new(self.agreement_algorithm.group_id)?;
        self.priv_key
            .ec_public()?
            .to_binary(&group, false)
    }
}

impl<T: RngCallback> ActiveKeyExchange for KeyExchange<T> {
    /// Completes the key exchange, given the peer's public key.
    fn complete(mut self: Box<Self>, peer_public_key: &[u8]) -> Result<crypto::SharedSecret, Error> {
        let group_id = self.agreement_algorithm.group_id;

        if peer_public_key.len() != self.agreement_algorithm.public_key_len {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }

        let peer_pk = parse_peer_public_key(group_id, peer_public_key).map_err(mbedtls_err_to_rustls_error)?;

        let mut rng = (self.rng_provider)().ok_or(crypto::GetRandomFailed)?;

        // Only run fips check on applied NamedGroups
        #[cfg(feature = "fips")]
        match self.name {
            NamedGroup::secp256r1 | NamedGroup::secp384r1 | NamedGroup::secp521r1 => {
                crate::fips_utils::fips_check_ec_pub_key(&peer_pk, &mut rng)?
            }
            _ => (),
        }

        let mut shared_key = [0u8; mbedtls::pk::ECDSA_MAX_LEN];
        let shared_key = &mut shared_key[..self
            .agreement_algorithm
            .max_signature_len];
        let len = self
            .priv_key
            .agree(&peer_pk, shared_key, &mut rng)
            .map_err(mbedtls_err_to_rustls_error)?;
        Ok(crypto::SharedSecret::from(&shared_key[..len]))
    }

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8] {
        self.pub_key
            .get_or_init(|| self.get_pub_key().unwrap_or_default())
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup {
        self.name
    }
}

/// A DHE key-exchange group supported by *mbedtls*.
///
/// All possible instances of this type are provided by the library in
/// the `ALL_KX_GROUPS` array.
pub struct DheKxGroup<T: RngCallback> {
    /// The IANA "TLS Supported Groups" name of the group
    pub(crate) named_group: NamedGroup,
    /// FFDHE Group parameters
    pub(crate) group: FfdheGroup<'static>,
    /// Private key length
    pub(crate) priv_key_len: usize,
    /// Callback to produce RNGs when needed
    rng_provider: fn() -> Option<T>,
}

impl<T: RngCallback> DheKxGroup<T> {
    /// Create a new [`DheKxGroup`] with given RNG provider callback.
    pub const fn with_rng_provider<F: RngCallback>(&self, rng_provider: fn() -> Option<F>) -> DheKxGroup<F> {
        DheKxGroup {
            rng_provider,
            named_group: self.named_group,
            group: self.group,
            priv_key_len: self.priv_key_len,
        }
    }
}

impl<T: RngCallback> fmt::Debug for DheKxGroup<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DheKxGroup")
            .field("named_group", &self.named_group)
            .field("group", &self.group)
            .field("priv_key_len", &self.priv_key_len)
            .finish()
    }
}

impl<T: RngCallback> SupportedKxGroup for DheKxGroup<T> {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let g = Mpi::from_binary(self.group.g).map_err(mbedtls_err_to_rustls_error)?;
        let p = Mpi::from_binary(self.group.p).map_err(mbedtls_err_to_rustls_error)?;

        let mut rng = (self.rng_provider)().ok_or(crypto::GetRandomFailed)?;
        let mut x = vec![0; self.priv_key_len];
        rng.random(&mut x)
            .map_err(|_| crypto::GetRandomFailed)?;
        let x = Mpi::from_binary(&x).map_err(|e| Error::General(format!("failed to make Bignum from random bytes: {}", e)))?;
        let x_pub = g
            .mod_exp(&x, &p)
            .map_err(mbedtls_err_to_rustls_error)?;

        #[cfg(feature = "fips")]
        crate::fips_utils::ffdhe_pct(self, &x, &x_pub)?;

        Ok(Box::new(DheActiveKeyExchange::new(
            self.named_group,
            self.group,
            Mutex::new(p),
            Mutex::new(x),
            x_pub
                .to_binary_padded(self.group.p.len())
                .map_err(mbedtls_err_to_rustls_error)?,
        )))
    }

    fn name(&self) -> NamedGroup {
        self.named_group
    }
}

pub(crate) struct DheActiveKeyExchange {
    named_group: NamedGroup,
    group: FfdheGroup<'static>,
    // Using Mutex just because `Mpi` is not currently `Sync`
    // TODO remove the Mutex once we switch to a version of mbedtls where `Mpi` is `Sync`
    p: Mutex<Mpi>,
    x: Mutex<Mpi>,
    x_pub: Vec<u8>,
}

impl DheActiveKeyExchange {
    pub(crate) fn new(
        named_group: NamedGroup,
        group: FfdheGroup<'static>,
        p: Mutex<Mpi>,
        x: Mutex<Mpi>,
        x_pub: Vec<u8>,
    ) -> Self {
        Self { named_group, group, p, x, x_pub }
    }
}

impl ActiveKeyExchange for DheActiveKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<crypto::SharedSecret, Error> {
        let y_pub = Mpi::from_binary(peer_pub_key).map_err(mbedtls_err_to_rustls_error)?;

        let x = self
            .x
            .into_inner()
            .expect("Mpi Mutex poisoned");
        let p = self
            .p
            .into_inner()
            .expect("Mpi Mutex poisoned");

        let one = Mpi::new(1).map_err(mbedtls_err_to_rustls_error)?;

        let mut p_minus_one = p;
        p_minus_one -= &one;

        // https://www.rfc-editor.org/rfc/rfc7919.html#section-5.1:
        // Peers MUST validate each other's public key Y [...] by ensuring that 1 < Y < p-1.
        if !(one < y_pub && y_pub < p_minus_one) {
            return Err(Error::General(
                "Invalid DHE key exchange public key received; pub key must be in range (1, p-1)".into(),
            ));
        }

        p_minus_one += &one;
        let p = p_minus_one;

        #[cfg(feature = "fips")]
        crate::fips_utils::ffdhe_pub_key_check(&self.group, self.named_group, &y_pub)?;

        let secret = y_pub
            .mod_exp(&x, &p)
            .map_err(mbedtls_err_to_rustls_error)?;

        Ok(crypto::SharedSecret::from(
            secret
                .to_binary_padded(self.group.p.len())
                .map_err(mbedtls_err_to_rustls_error)?
                .as_ref(),
        ))
    }

    fn pub_key(&self) -> &[u8] {
        &self.x_pub
    }

    fn group(&self) -> NamedGroup {
        self.named_group
    }
}

#[inline]
fn parse_peer_public_key(group_id: mbedtls::pk::EcGroupId, peer_public_key: &[u8]) -> Result<PkMbed, mbedtls::Error> {
    let ec_group = EcGroup::new(group_id)?;
    let public_point = EcPoint::from_binary_no_compress(&ec_group, peer_public_key)?;
    PkMbed::public_from_ec_components(ec_group, public_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kx_group_fmt_debug() {
        let debug_str = format!("{:?}", X25519_KX_GROUP);
        assert!(debug_str.contains("KxGroup"), "debug_str: {debug_str}");
        assert!(debug_str.contains("name: X25519"), "debug_str: {debug_str}");
        assert!(
            debug_str.contains("agreement_algorithm: Curve25519"),
            "debug_str: {debug_str}"
        );
        assert!(!debug_str.contains("rng_provider"), "debug_str: {debug_str}");
    }

    #[test]
    fn test_dhe_kx_group_fmt_debug() {
        let debug_str = format!("{:?}", FFDHE2048_KX_GROUP);
        assert!(debug_str.contains("DheKxGroup"), "debug_str: {debug_str}");
        assert!(debug_str.contains("FFDHE2048"), "debug_str: {debug_str}");
        assert!(debug_str.contains("FfdheGroup"), "debug_str: {debug_str}");
        assert!(!debug_str.contains("rng_provider"), "debug_str: {debug_str}");
    }

    #[test]
    fn test_static_with_rng_provider() {
        fn get_ftx_rng() -> Option<MbedRng> {
            None
        }
        // Test that with_rng_provider works as expected.
        assert!((X25519_KX_GROUP
            .with_rng_provider(get_ftx_rng)
            .rng_provider)()
        .is_none());
        assert!((FFDHE2048_KX_GROUP
            .with_rng_provider(get_ftx_rng)
            .rng_provider)()
        .is_none());
        // Test that with_rng_provider could use with static.
        static _X25519: &dyn SupportedKxGroup = &X25519_KX_GROUP.with_rng_provider(get_ftx_rng);
        static _FFDHE2048: &dyn SupportedKxGroup = &FFDHE2048_KX_GROUP.with_rng_provider(get_ftx_rng);
    }
}

#[cfg(bench)]
mod benchmarks {

    #[bench]
    fn bench_ecdh_p256(b: &mut test::Bencher) {
        bench_any(b, super::SECP256R1);
    }

    #[bench]
    fn bench_ecdh_p384(b: &mut test::Bencher) {
        bench_any(b, super::SECP384R1);
    }

    #[bench]
    fn bench_ecdh_p521(b: &mut test::Bencher) {
        bench_any(b, super::SECP521R1);
    }

    #[bench]
    fn bench_x25519(b: &mut test::Bencher) {
        bench_any(b, super::X25519);
    }

    fn bench_any(b: &mut test::Bencher, kxg: &dyn super::SupportedKxGroup) {
        b.iter(|| {
            let akx = kxg.start().unwrap();
            let pub_key = akx.pub_key().to_vec();
            test::black_box(akx.complete(&pub_key).unwrap());
        });
    }

    #[bench]
    fn bench_ecdh_p256_start(b: &mut test::Bencher) {
        let kxg = super::SECP256R1;
        b.iter(|| {
            test::black_box(kxg.start().unwrap());
        });
    }

    #[bench]
    fn bench_ecdh_p256_gen_private_key(b: &mut test::Bencher) {
        let mut rng = crate::rng::rng_new().unwrap();
        b.iter(|| {
            test::black_box(super::generate_ec_key(mbedtls::pk::EcGroupId::SecP256R1, &mut rng).unwrap());
        });
    }

    #[bench]
    fn bench_ecdh_p256_parse_peer_pub_key(b: &mut test::Bencher) {
        let kxg = super::SECP256R1;
        let akx = kxg.start().unwrap();
        let pub_key = akx.pub_key().to_vec();
        b.iter(|| {
            test::black_box(super::parse_peer_public_key(mbedtls::pk::EcGroupId::SecP256R1, &pub_key).unwrap());
        });
    }
}
