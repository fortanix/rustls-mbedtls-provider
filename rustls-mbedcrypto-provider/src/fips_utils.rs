/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! This module contains functions only used with `fips` features

use core::fmt;
use std::sync::Arc;

use mbedtls::{bignum::Mpi, ecp::EcPoint, pk::Pk};
use rustls::OtherError;

#[derive(Debug, Eq, PartialEq)]
struct FipsCheckError(mbedtls::Error);

impl fmt::Display for FipsCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for FipsCheckError {}

impl From<FipsCheckError> for rustls::Error {
    fn from(value: FipsCheckError) -> Self {
        OtherError(Arc::new(value)).into()
    }
}

/// ECC Full Public-Key Validation Routine, which is defined in
/// section 5.6.2.3.3 of [NIST SP 800-56A Rev. 3]
///
/// [NIST SP 800-56A Rev. 3]:
///     https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
pub(crate) fn fips_check_ec_pub_key(ec_mbed_pk: &Pk) -> Result<(), rustls::Error> {
    fips_check_ec_pub_key_impl(ec_mbed_pk).map_err(|mbed_err| FipsCheckError(mbed_err).into())
}

/// ECC Full Public-Key Validation Routine, which is defined in
/// section 5.6.2.3.3 of [NIST SP 800-56A Rev. 3]
///
/// [NIST SP 800-56A Rev. 3]:
///     https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
#[allow(non_snake_case)]
fn fips_check_ec_pub_key_impl(ec_mbed_pk: &Pk) -> Result<(), mbedtls::Error> {
    use core::ops::Sub;
    let pub_point = ec_mbed_pk.ec_public()?;
    // 1. Verify that Q is not the identity element Ø.
    if pub_point.is_zero()? {
        return Err(mbedtls::Error::EcpInvalidKey);
    };
    // 2. Verify that x_Q and y_Q are integers in the interval [0, p − 1] in the case that q is an odd prime p
    // Note: The q of all NIST P-XXX curves is an odd prime.
    let mut ec_group = ec_mbed_pk.ec_group()?;
    let p = ec_group.p()?;
    let x_Q = pub_point.x()?;
    let y_Q = pub_point.y()?;
    if x_Q.sign() != mbedtls::bignum::Sign::Positive || x_Q >= p {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    if y_Q.sign() != mbedtls::bignum::Sign::Positive || y_Q >= p {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    // 3. Verify that Q is on the curve. In particular,
    // If q is an odd prime p, verify that y_Q^2 = (x_Q^3 + a*x_Q + b) mod p.
    // Note:
    //   - The q of all NIST P-XXX curves is an odd prime.
    //   - `mbedtls` code called by `contains_point` will finally do check as required.
    if !ec_group.contains_point(&pub_point)? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    // 4. Compute n*Q (using elliptic curve arithmetic), and verify that n*Q = Ø.
    // Here we compute n*Q = (n-1)*Q +Q, because `EcPoint::mul` always expects
    // given `Mpi` < n.
    let n = ec_group.order()?;
    let n_sub_1 = n.sub(1)?;
    let n_sub_1_q = pub_point.mul(&mut ec_group, &n_sub_1)?;
    let mpi_one = Mpi::new(1)?;
    let nQ = EcPoint::muladd(&mut ec_group, &n_sub_1_q, &mpi_one, &pub_point, &mpi_one)?;
    if !nQ.is_zero()? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    crate::log::info!("ECC Full Public-Key Validation: passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use mbedtls::pk::EcGroupId;

    use super::*;

    #[test]
    fn fips_check_ec_pub_key_smoke_test() {
        let mut rng = crate::rng::rng_new().unwrap();
        let ec_key = Pk::generate_ec(&mut rng, EcGroupId::SecP256R1).unwrap();
        let () = fips_check_ec_pub_key(&ec_key).unwrap();
    }

    #[test]
    fn fips_check_error_debug_test() {
        let rustls_test: rustls::Error = FipsCheckError(mbedtls::Error::AesBadInputData).into();
        let rustls_test_fmt = format!("{rustls_test}");
        let rustls_test_dbg = format!("{rustls_test:?}");
        assert_eq!("other error: FipsCheckError(AesBadInputData)", rustls_test_fmt);
        assert_eq!("Other(OtherError(FipsCheckError(AesBadInputData)))", rustls_test_dbg);
    }
}
