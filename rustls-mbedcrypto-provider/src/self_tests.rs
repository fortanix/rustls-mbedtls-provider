//! This module defines self-tests. Running tests in this module (i.e., calling [`self_tests()`](self::self_tests()))
//! at runtime can help with [FIPS 140-3] compliance.
//!
//! [FIPS 140-3]: (https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf)

use rustls::crypto::{
    tls12::{Prf, PrfUsingHmac},
    tls13::{expand, Hkdf, HkdfUsingHmac},
};
use std::vec::Vec;

// test copied from rustls repo
/// TLS 1.2 SHA256 PRF test
#[cfg(feature = "tls12")]
pub fn tls12_sha256_prf_test_1() {
    let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
    let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
    let label = b"test label";
    let expect = include_bytes!("../testdata/prf-result.1.bin");
    let mut output = [0u8; 100];

    let prf = PrfUsingHmac(&super::hmac::HMAC_SHA256);
    prf.for_secret(&mut output, secret, label, seed);

    assert_eq!(expect.len(), output.len());
    assert_eq!(&expect[..], &output[..]);
}

/// TLS 1.2 SHA256 PRF test with `"extended master secret"`
#[cfg(feature = "tls12")]
pub fn tls12_sha256_prf_test_2() {
    let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
    let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
    let label = b"extended master secret";
    let expect = [
        0xd6, 0xbd, 0x1a, 0x5f, 0x96, 0x31, 0x58, 0x66, 0x73, 0x44, 0x3b, 0x93, 0x5c, 0x00, 0x39, 0x2b, 0xe8, 0x76, 0xad, 0x7d,
        0x6c, 0x5c, 0xa0, 0xc8, 0xe4, 0x3f, 0xa9, 0xf2, 0xe7, 0x8a, 0xdf, 0xf3, 0xde, 0x4c, 0xbc, 0xf5, 0x3c, 0x94, 0x81, 0x44,
        0xa4, 0xa1, 0x9c, 0xae, 0x1d, 0xbb, 0xb0, 0x8f, 0x74, 0x8b, 0xe5, 0x7a, 0xf6, 0xd1, 0x1b, 0x82, 0x5d, 0x7e, 0x89, 0x3e,
        0x8b, 0x3f, 0xab, 0xad, 0xad, 0x64, 0x4e, 0x18, 0xc1, 0x92, 0x59, 0xd7, 0xd2, 0x21, 0x38, 0x30, 0x7d, 0xca, 0x4d, 0xb4,
        0x5f, 0xb1, 0x99, 0xd1, 0x87, 0x1a, 0x76, 0x68, 0xef, 0xf5, 0x2b, 0xc3, 0x14, 0xdd, 0xaa, 0xed, 0x0c, 0xa1, 0x0a, 0x87,
    ];
    let mut output = [0u8; 100];

    let prf = PrfUsingHmac(&super::hmac::HMAC_SHA256);
    prf.for_secret(&mut output, secret, label, seed);

    assert_eq!(expect.len(), output.len());
    assert_eq!(&expect[..], &output[..]);
}

// test copied from rustls repo
/// TLS 1.2 SHA384 PRF test
#[cfg(feature = "tls12")]
pub fn tls12_sha384_prf_test() {
    let secret = b"\xb8\x0b\x73\x3d\x6c\xee\xfc\xdc\x71\x56\x6e\xa4\x8e\x55\x67\xdf";
    let seed = b"\xcd\x66\x5c\xf6\xa8\x44\x7d\xd6\xff\x8b\x27\x55\x5e\xdb\x74\x65";
    let label = b"test label";
    let expect = include_bytes!("../testdata/prf-result.3.bin");
    let mut output = [0u8; 148];

    let prf = PrfUsingHmac(&super::hmac::HMAC_SHA384);
    prf.for_secret(&mut output, secret, label, seed);

    assert_eq!(expect.len(), output.len());
    assert_eq!(&expect[..], &output[..]);
}

// test copied from rustls repo
/// TLS 1.3 KDF [test case 1](https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1).
pub fn tls13_kdf_test_case_1() {
    let hkdf = HkdfUsingHmac(&super::hmac::HMAC_SHA256);
    let ikm = &[0x0b; 22];
    let salt = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    let info: &[&[u8]] = &[&[0xf0, 0xf1, 0xf2], &[0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]];

    let output: [u8; 42] = expand(
        hkdf.extract_from_secret(Some(salt), ikm)
            .as_ref(),
        info,
    );

    assert_eq!(
        &output,
        &[
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a,
            0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8,
            0x87, 0x18, 0x58, 0x65
        ]
    );
}

// test copied from rustls repo
/// TLS 1.3 KDF [test case 2](https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.2).
pub fn tls13_kdf_test_case_2() {
    let hkdf = HkdfUsingHmac(&super::hmac::HMAC_SHA256);
    let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
    let salt: Vec<u8> = (0x60u8..=0xaf).collect();
    let info: Vec<u8> = (0xb0u8..=0xff).collect();

    let output: [u8; 82] = expand(
        hkdf.extract_from_secret(Some(&salt), &ikm)
            .as_ref(),
        &[&info],
    );

    assert_eq!(
        &output,
        &[
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34, 0x4f, 0x01, 0x2e,
            0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7,
            0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36,
            0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5,
            0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87
        ]
    );
}

// test copied from rustls repo
/// TLS 1.3 KDF [test case 3](https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.3).
pub fn tls13_kdf_test_case_3() {
    let hkdf = HkdfUsingHmac(&super::hmac::HMAC_SHA256);
    let ikm = &[0x0b; 22];
    let salt = &[];
    let info = &[];

    let output: [u8; 42] = expand(
        hkdf.extract_from_secret(Some(salt), ikm)
            .as_ref(),
        info,
    );

    assert_eq!(
        &output,
        &[
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31, 0xb8, 0xa1, 0x1f,
            0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4,
            0xb6, 0x1a, 0x96, 0xc8
        ]
    );
}

/// Run all the self_tests. If any test fails, this function will panic.
///
/// If `verbose` is true, print messages about tests that have been executed.
pub fn self_tests(verbose: bool) {
    macro_rules! print_msg {
        ($($tt: tt)*) => {
            if verbose { std::println!($($tt)*) }
        };
    }

    #[cfg(feature = "tls12")]
    {
        tls12_sha256_prf_test_1();
        print_msg!("tls12_sha256_prf_test_1 passed.");
        tls12_sha256_prf_test_2();
        print_msg!("tls12_sha256_prf_test_2 passed.");
        tls12_sha384_prf_test();
        print_msg!("tls12_sha384_prf_test passed.");
    }

    tls13_kdf_test_case_1();
    print_msg!("tls13_kdf_test_case_1 passed.");
    tls13_kdf_test_case_2();
    print_msg!("tls13_kdf_test_case_2 passed.");
    tls13_kdf_test_case_3();
    print_msg!("tls13_kdf_test_case_3 passed.");

    print_msg!("All rustls-mbedcrypto-provider self-tests passed.");
}

#[test]
fn self_tests_succeed() {
    self_tests(true)
}
