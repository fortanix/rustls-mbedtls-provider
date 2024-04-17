/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! This module contains functions only used with `fips` features

use core::fmt;
use std::{borrow::Cow, sync::Arc};

use rustls::{ffdhe_groups::FfdheGroup, NamedGroup, OtherError};

use core::ops::Sub;
use mbedtls::{
    bignum::Mpi,
    ecp::EcPoint,
    pk::{EcGroupId, Pk},
    rng::RngCallback,
};

mod constants;

use crate::{
    fips_utils::constants::{get_ffdhe_q, get_known_ec_key, get_known_ffdhe_key_pair},
    kx::{FfdheKxGroup, FfdheKxGroupWrapper},
    log,
};

/// Type represents errors comes from FIPS check
#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub enum FipsCheckError {
    Mbedtls(mbedtls::Error),
    General(Cow<'static, str>),
}

impl fmt::Display for FipsCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Mbedtls(_) => write!(f, "FipsCheckError::{:?}", self),
            Self::General(err_str) => write!(f, "FipsCheckError::General({})", err_str),
        }
    }
}

impl std::error::Error for FipsCheckError {}

impl From<FipsCheckError> for rustls::Error {
    fn from(value: FipsCheckError) -> Self {
        OtherError(Arc::new(value)).into()
    }
}

/// Wrap a [`mbedtls::Error`] with [`FipsCheckError`] and convert it to [`rustls::Error`].
#[inline]
fn wrap_mbedtls_error_as_fips(mbed_err: mbedtls::Error) -> rustls::Error {
    FipsCheckError::Mbedtls(mbed_err).into()
}

/// ECC Full Public-Key Validation Routine, which is defined in
/// section 5.6.2.3.3 of [NIST SP 800-56A Rev. 3]
///
/// [NIST SP 800-56A Rev. 3]:
///     https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
pub(crate) fn fips_check_ec_pub_key<F: mbedtls::rng::Random>(ec_mbed_pk: &Pk, rng: &mut F) -> Result<(), rustls::Error> {
    fips_check_ec_pub_key_mbed(ec_mbed_pk, rng).map_err(wrap_mbedtls_error_as_fips)?;
    log::debug!("ECC Full Public-Key Validation: passed");
    Ok(())
}

/// ECC Pairwise Consistency Test upon generation that mimics the shared
/// secret computation using the recent generated key pair and a known
/// key pair with the same domain parameters and comparing the shared
/// secret computation values calculated using either FFC DH or ECC CDH
/// primitives.
///
/// Learn more in:
/// - [FIPS 140-3 IG] section 10.3.A.
/// - [SP 800-56Ar3] section 5.6.2.1.4.
///
/// [FIPS 140-3 IG]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
/// [SP 800-56Ar3]: https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
pub(crate) fn fips_ec_pct<F: mbedtls::rng::Random>(
    ec_mbed_pk: &mut Pk,
    ec_group_id: EcGroupId,
    rng: &mut F,
) -> Result<(), rustls::Error> {
    // Get a static ec pub key based on given [`EcGroupId`]
    let known_ec_key_info = get_known_ec_key(&ec_group_id).expect("validated");
    let mut known_ec_key = known_ec_key_info
        .0
        .lock()
        .map_err(|_| rustls::Error::General("Failed to get known ec key: poisoned lock".to_string()))?;
    let secret_len = known_ec_key_info.1;
    fips_ec_pct_mbed(ec_mbed_pk, &mut known_ec_key, secret_len, rng).map_err(wrap_mbedtls_error_as_fips)?;
    log::debug!("ECC Pairwise Consistency Test: passed");
    Ok(())
}

#[allow(non_snake_case)]
fn fips_ec_pct_mbed<F: mbedtls::rng::Random>(
    ec_mbed_pk: &mut Pk,
    known_ec_key: &mut Pk,
    secret_len: usize,
    rng: &mut F,
) -> Result<(), mbedtls::Error> {
    // Pairwise Consistency Test upon generation that mimics the
    // shared secret computation using the recent generated key
    // pair and a known key pair with the same domain parameters
    // and comparing the shared secret computation values
    // calculated using either FFC DH or ECC CDH primitives.
    // This is based on section 10.3.A of [FIPS 140-3 IG] :
    //
    // > If at the time a PCT on a key pair is performed it is
    // > known whether the keys will be used in a key agreement
    // > scheme, digital signature algorithm or to perform a key
    // > transport, then the PCT shall be performed consistent
    // > with the intended use of the keys (i.e., TE10.35.01 for
    // > key transport, TE10.35.02 for signatures, or TE10.35.031
    // > for key agreement), even if the underlying standard does
    // > not require a PCT.
    //
    // [FIPS 140-3 IG]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
    let mut shared_1 = vec![0; secret_len];
    let mut shared_2 = vec![0; secret_len];
    let len = ec_mbed_pk.agree(known_ec_key, &mut shared_1, rng)?;
    shared_1.truncate(len);
    let len = known_ec_key.agree(ec_mbed_pk, &mut shared_2, rng)?;
    shared_2.truncate(len);
    if shared_1 != shared_2 {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    // According to section 5.6.2.1.4 of [SP 800-56Ar3]:
    //
    // > For an ECC key pair (d, Q): Use the private key, d, along
    // > with the generator G and other domain parameters
    // > associated with the key pair, to compute dG (according to
    // > the rules of elliptic-curve arithmetic). Compare the
    // > result to the public key, Q. If dG is not equal to Q,
    // > then the pair-wise consistency test fails.
    //
    // [SP 800-56Ar3]: https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
    let mut ec_group = ec_mbed_pk.ec_group()?;
    let d = ec_mbed_pk.ec_private()?;
    let Q = ec_mbed_pk.ec_public()?;
    let G = ec_group.generator()?;
    let dG = G.mul_with_rng(&mut ec_group, &d, rng)?;
    // Use cloned `dG` to ensure it has same allocation length to `Q`.
    // "Same allocation length" is required by `eq_const_time`.
    if !dG.clone().eq_const_time(&Q)? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    Ok(())
}

#[allow(non_snake_case)]
fn fips_check_ec_pub_key_mbed<F: mbedtls::rng::Random>(ec_mbed_pk: &Pk, rng: &mut F) -> Result<(), mbedtls::Error> {
    let pub_point = ec_mbed_pk.ec_public()?;
    // 1. Verify that Q is not the identity element Ø.
    if pub_point.is_zero()? {
        return Err(mbedtls::Error::EcpInvalidKey);
    };
    // 2. Verify that x_Q and y_Q are integers in the interval [0, p − 1] in the case that q is an odd prime p
    // 3. Verify that Q is on the curve. In particular, if q is an odd prime p, verify that y_Q^2 = (x_Q^3 + a*x_Q + b) mod p.
    //
    // Note:
    //   - The q of all NIST P-XXX curves is an odd prime.
    //   - Function `contains_point` will call [`mbedtls_ecp_check_pubkey`] which finally do check 2 & 3 as required.
    //
    // [`mbedtls_ecp_check_pubkey`]: https://github.com/fortanix/rust-mbedtls/blob/main/mbedtls-sys/vendor/library/ecp.c#L3090
    let mut ec_group = ec_mbed_pk.ec_group()?;
    if !ec_group.contains_point(&pub_point)? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    // 4. Compute n*Q (using elliptic curve arithmetic), and verify that n*Q = Ø.
    //    Here we compute n*Q = (n-1)*Q +Q, because `EcPoint::mul` always expects
    //    given `Mpi` < n.
    let n = ec_group.order()?;
    let n_sub_1 = n.sub(1)?;
    let n_sub_1_q = pub_point.mul_with_rng(&mut ec_group, &n_sub_1, rng)?;
    let mpi_one = Mpi::new(1)?;
    let nQ = EcPoint::muladd(&mut ec_group, &n_sub_1_q, &mpi_one, &pub_point, &mpi_one)?;
    if !nQ.is_zero()? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    Ok(())
}

/// Run the Pairwise Consistency Test described in [FIPS 140-3 IG] section 10.3.A:
///
/// > If at the time a PCT on a key pair is performed it is known
/// > whether the keys will be used in a key agreement scheme, digital
/// > signature algorithm or to perform a key transport, then the PCT
/// > shall be performed consistent with the intended use of the keys
/// > (i.e., TE10.35.01 for key transport, TE10.35.02 for signatures,
/// > or TE10.35.031 for key agreement), even if the underlying
/// > standard does not require a PCT.
///
/// [FIPS 140-3 IG]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
pub(super) fn ffdhe_pct<T: RngCallback>(dhe_group: &FfdheKxGroupWrapper<T>, y: &Mpi, y_pub: &Mpi) -> Result<(), rustls::Error> {
    let p = Mpi::from_binary(dhe_group.dhe_kx_group.group.p).map_err(wrap_mbedtls_error_as_fips)?;
    let key_pair = get_known_ffdhe_key_pair(dhe_group.dhe_kx_group.named_group)
        .expect("validated")
        .lock()
        .map_err(|_| rustls::Error::General("Failed to get ffdhe q".to_string()))?;
    let (x, x_pub) = (&key_pair.0, &key_pair.1);
    // compute shared secret with new pk and known sk
    let secret_1 = compute_shared_secret(y_pub, x, &p).map_err(wrap_mbedtls_error_as_fips)?;
    // compute shared secret with new sk and known pk
    let secret_2 = compute_shared_secret(x_pub, y, &p).map_err(wrap_mbedtls_error_as_fips)?;
    // compare two secrets
    if secret_1 != secret_2 {
        const ERR_MSG: &str = "FFDHE Pairwise Consistency Test: failed";
        crate::log::error!("{ERR_MSG}");
        return Err(FipsCheckError::General(ERR_MSG.into()).into());
    }
    crate::log::debug!("FFDHE Pairwise Consistency Test: passed");
    Ok(())
}

/// Run FFC Full Public-Key Validation Routine, which is defined in
/// section 5.6.2.3.3 of [NIST SP 800-56A Rev. 3]
///
/// [NIST SP 800-56A Rev. 3]:
///     https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
pub(super) fn ffdhe_pub_key_check(
    ffdhe_group: &FfdheGroup<'static>,
    named_group: NamedGroup,
    y_pub: &Mpi,
) -> Result<(), rustls::Error> {
    const ERR_MSG: &str = "FFDHE Full Public-Key Validity: failed";
    // 1. Verify that 2 <= y <= p − 2.
    //    Success at this stage ensures that y has the expected representation for a nonzero field
    //    element (i.e., an integer in the interval [1, p – 1]) and that y is in the proper range for
    //    a properly generated public key
    // Note: this is checked in function `ActiveKeyExchange::complete` for `DheActiveKeyExchange`.

    // 2. Verify that 1 = y^q mod p.
    //    Success at this stage ensures that y has the correct order and thus, is a non-identity
    //    element in the correct subgroup of GF(p)*.
    //
    // Note: When the FFC domain parameters correspond to a safe-prime group, 1 = y^q mod p if and only if y is a
    //       (nonzero) quadratic residue modulo p, which can be verified by computing the value of the Legendre symbol
    //       of y with respect to p
    let one = Mpi::new(1).map_err(wrap_mbedtls_error_as_fips)?;
    let p = Mpi::from_binary(ffdhe_group.p).map_err(wrap_mbedtls_error_as_fips)?;
    let q = get_ffdhe_q(named_group)
        .expect("validated")
        .lock()
        .map_err(|_| rustls::Error::General("Failed to get ffdhe q".to_string()))?;
    let lhs = y_pub
        .mod_exp(&q, &p)
        .map_err(wrap_mbedtls_error_as_fips)?;
    if lhs != one {
        crate::log::error!("{ERR_MSG}");
        return Err(FipsCheckError::General(ERR_MSG.into()).into());
    }
    Ok(())
}

#[inline]
fn compute_shared_secret(peer_pub_key: &Mpi, self_private: &Mpi, named_group_prime: &Mpi) -> Result<Mpi, mbedtls::Error> {
    peer_pub_key.mod_exp(self_private, named_group_prime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbedtls::{pk::EcGroupId, rng::Random};
    use rustls::crypto::SupportedKxGroup;

    #[test]
    fn test_fips_check_error_display() {
        let error = FipsCheckError::Mbedtls(mbedtls::Error::EcpAllocFailed);
        assert_eq!(format!("{}", error), "FipsCheckError::Mbedtls(EcpAllocFailed)");
        let error = FipsCheckError::General(Cow::Borrowed("Some other error"));
        assert_eq!(format!("{}", error), "FipsCheckError::General(Some other error)");
        let error = FipsCheckError::Mbedtls(mbedtls::Error::EcpAllocFailed);
        assert_eq!(format!("{:?}", error), "Mbedtls(EcpAllocFailed)");
        let error_other = FipsCheckError::General(Cow::Borrowed("Some other error"));
        assert_eq!(format!("{:?}", error_other), "General(\"Some other error\")");
    }

    #[test]
    fn fips_check_ec_pub_key_smoke_test() {
        let mut rng = crate::rng::rng_new().unwrap();
        for group_id in [
            EcGroupId::SecP192R1,
            EcGroupId::SecP224R1,
            EcGroupId::SecP256R1,
            EcGroupId::SecP384R1,
            EcGroupId::SecP521R1,
        ] {
            let ec_key = Pk::generate_ec(&mut rng, group_id).unwrap();
            let () = fips_check_ec_pub_key(&ec_key, &mut rng).unwrap();
        }
    }

    #[test]
    fn fips_ec_pct_smoke_test() {
        let mut rng = crate::rng::rng_new().unwrap();
        for group_id in [
            EcGroupId::SecP192R1,
            EcGroupId::SecP224R1,
            EcGroupId::SecP256R1,
            EcGroupId::SecP384R1,
            EcGroupId::SecP521R1,
        ] {
            let mut ec_key = Pk::generate_ec(&mut rng, group_id).unwrap();
            let () = fips_ec_pct(&mut ec_key, group_id, &mut rng).unwrap();
        }
    }

    #[test]
    fn fips_check_error_debug_test() {
        let rustls_test: rustls::Error = wrap_mbedtls_error_as_fips(mbedtls::Error::AesBadInputData);
        let rustls_test_fmt = format!("{rustls_test}");
        let rustls_test_dbg = format!("{rustls_test:?}");
        assert_eq!("other error: FipsCheckError::Mbedtls(AesBadInputData)", rustls_test_fmt);
        assert_eq!("Other(OtherError(Mbedtls(AesBadInputData)))", rustls_test_dbg);
    }

    fn create_ffdhe_key_pair<T: RngCallback>(dhe_group: &FfdheKxGroupWrapper<T>) -> (Mpi, Mpi) {
        let g = Mpi::from_binary(dhe_group.dhe_kx_group.group.g).unwrap();
        let p = Mpi::from_binary(dhe_group.dhe_kx_group.group.p).unwrap();
        let mut rng = crate::rng::rng_new().unwrap();
        let mut x_binary = vec![0; dhe_group.dhe_kx_group.priv_key_len];
        rng.random(&mut x_binary).unwrap();

        let x = Mpi::from_binary(&x_binary).unwrap();
        let x_pub = g.mod_exp(&x, &p).unwrap();
        let x_pub_binary = x_pub
            .to_binary_padded(dhe_group.dhe_kx_group.group.p.len())
            .unwrap();
        print_vec("public", &x_pub_binary);
        (x, x_pub)
    }

    fn print_vec(name: &str, val: &[u8]) {
        let formatted_strings: Vec<String> = val
            .iter()
            .map(|byte| format!("0x{:02x}", byte))
            .collect();

        // Join the formatted strings with commas
        let formatted_output = formatted_strings.join(",");

        // Print the output, enclosed in brackets
        println!("{}:\n[{}]", name, formatted_output);
    }

    #[test]
    fn test_ffdhe_pct() {
        for dhe_group in [
            crate::kx::FFDHE2048_KX_GROUP,
            crate::kx::FFDHE3072_KX_GROUP,
            crate::kx::FFDHE4096_KX_GROUP,
            crate::kx::FFDHE6144_KX_GROUP,
            crate::kx::FFDHE8192_KX_GROUP,
        ] {
            println!(
                "Running ffdhe pairwise consistency test smoke test on group: {:?}",
                dhe_group.name(),
            );
            let (y, y_pub) = create_ffdhe_key_pair(dhe_group);
            let result = ffdhe_pct(dhe_group, &y, &y_pub);
            assert_eq!(
                result,
                Ok(()),
                "ffdhe pairwise consistency test smoke test failed with group {:?}, res: {:?}",
                dhe_group.name(),
                result
            );
        }
    }

    #[test]
    fn test_ffdhe_pub_key_check() {
        for dhe_group in [
            crate::kx::FFDHE2048_KX_GROUP,
            crate::kx::FFDHE3072_KX_GROUP,
            crate::kx::FFDHE4096_KX_GROUP,
            crate::kx::FFDHE6144_KX_GROUP,
            crate::kx::FFDHE8192_KX_GROUP,
        ] {
            println!("Running ffdhe public key check smoke test on group: {:?}", dhe_group.name(),);
            let (_, y_pub) = create_ffdhe_key_pair(dhe_group);
            let result = ffdhe_pub_key_check(&dhe_group.dhe_kx_group.group, dhe_group.name(), &y_pub);
            assert_eq!(
                result,
                Ok(()),
                "ffdhe public key check smoke test failed with group {:?}, res: {:?}",
                dhe_group.name(),
                result
            );
        }
    }
}
