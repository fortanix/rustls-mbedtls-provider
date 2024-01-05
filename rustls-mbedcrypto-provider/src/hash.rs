/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use crate::log::error;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto::hash::{self, HashAlgorithm};
use std::sync::Mutex;

/// SHA-256
pub static SHA256: Hash = Hash(&MBED_SHA_256);
/// SHA-384
pub static SHA384: Hash = Hash(&MBED_SHA_384);

/// A hash algorithm implementing [hash::Hash].
pub struct Hash(&'static Algorithm);

/// A digest algorithm.
#[derive(Clone, Debug, PartialEq)]
pub struct Algorithm {
    pub(crate) hash_algorithm: HashAlgorithm,
    pub(crate) hash_type: mbedtls::hash::Type,
    pub(crate) output_len: usize,
}

/// SHA-256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static MBED_SHA_256: Algorithm = Algorithm {
    hash_algorithm: HashAlgorithm::SHA256,
    hash_type: mbedtls::hash::Type::Sha256,
    output_len: 256 / 8,
};

/// SHA-384 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static MBED_SHA_384: Algorithm = Algorithm {
    hash_algorithm: HashAlgorithm::SHA384,
    hash_type: mbedtls::hash::Type::Sha384,
    output_len: 384 / 8,
};

/// SHA-512 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static MBED_SHA_512: Algorithm = Algorithm {
    hash_algorithm: HashAlgorithm::SHA512,
    hash_type: mbedtls::hash::Type::Sha512,
    output_len: 512 / 8,
};

impl hash::Hash for Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(MbedHashContext::new(self.0)))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&hash(self.0, data))
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.0.hash_algorithm
    }

    fn output_len(&self) -> usize {
        self.0.output_len
    }
}

struct HashContext(MbedHashContext);

impl hash::Context for HashContext {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
}

pub(crate) struct MbedHashContext {
    pub(crate) state: Mutex<mbedtls::hash::Md>,
    pub(crate) hash_algo: &'static Algorithm,
}

impl Clone for MbedHashContext {
    fn clone(&self) -> Self {
        let state = self.state.lock().unwrap();
        Self { state: Mutex::new(state.clone()), hash_algo: self.hash_algo }
    }
}

impl MbedHashContext {
    pub(crate) fn new(hash_algo: &'static Algorithm) -> Self {
        Self {
            hash_algo,
            state: Mutex::new(mbedtls::hash::Md::new(hash_algo.hash_type).expect("input is validated")),
        }
    }

    /// Since the trait does not provider a way to return error, empty vector is returned when getting error from `mbedtls`.
    pub(crate) fn finalize(self) -> Vec<u8> {
        match self.state.into_inner() {
            Ok(ctx) => {
                let mut out = vec![0u8; self.hash_algo.output_len];
                match ctx.finish(&mut out) {
                    Ok(_) => out,
                    Err(_err) => {
                        error!("Failed to finalize hash, mbedtls error: {:?}", _err);
                        vec![]
                    }
                }
            }
            Err(_err) => {
                error!("Failed to get lock, error: {:?}", _err);
                vec![]
            }
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self.state.lock().as_mut() {
            Ok(ctx) => match ctx.update(data) {
                Ok(_) => {}
                Err(_err) => {
                    error!("Failed to update hash, mbedtls error: {:?}", _err);
                }
            },
            Err(_err) => {
                error!("Failed to get lock, error: {:?}", _err);
            }
        }
    }
}

pub(crate) fn hash(hash_algo: &'static Algorithm, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; hash_algo.output_len];
    match mbedtls::hash::Md::hash(hash_algo.hash_type, data, &mut out) {
        Ok(_) => out,
        Err(_err) => {
            error!("Failed to do hash, mbedtls error: {:?}", _err);
            vec![]
        }
    }
}

#[cfg(bench)]
mod benchmarks {

    #[bench]
    fn bench_sha_256_hash(b: &mut test::Bencher) {
        bench_hash(b, &super::SHA256);
    }

    #[bench]
    fn bench_sha_384_hash(b: &mut test::Bencher) {
        bench_hash(b, &super::SHA384);
    }

    #[bench]
    fn bench_sha_256_hash_multi_parts(b: &mut test::Bencher) {
        bench_hash_multi_parts(b, &super::SHA256);
    }

    #[bench]
    fn bench_sha_384_hash_multi_parts(b: &mut test::Bencher) {
        bench_hash_multi_parts(b, &super::SHA384);
    }

    fn bench_hash(b: &mut test::Bencher, hash: &super::Hash) {
        use super::hash::Hash;
        let input = [123u8; 1024 * 16];
        b.iter(|| {
            test::black_box(hash.hash(&input));
        });
    }

    fn bench_hash_multi_parts(b: &mut test::Bencher, hash: &super::Hash) {
        use super::hash::Hash;
        let input = [123u8; 1024 * 16];
        b.iter(|| {
            let mut ctx = hash.start();
            for i in 0..16 {
                test::black_box(ctx.update(&input[i * 1024..(i + 1) * 1024]));
            }
            test::black_box(ctx.finish())
        });
    }
}
